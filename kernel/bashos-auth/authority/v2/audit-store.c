// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/slab.h>
#include "audit-store.h"

struct ba_v2_audit_store {
	struct mutex lock;
	struct crypto_shash *hmac;
	struct shash_desc *desc;
	size_t desc_size;
	u64 epoch, sequence, backpressure;
	u32 head, used, reserved;
	struct bashos_audit_v2_record records[BA_V2_AUDIT_CAPACITY];
};
static_assert(sizeof(struct bashos_audit_v2_record) == BASHOS_AUDIT_V2_BYTES);
static_assert(offsetof(struct bashos_audit_v2_record, hmac) == 768);

static bool audit_body_valid(const struct bashos_audit_v2_record *r)
{
	u32 command = le32_to_cpu(r->command_length), cwd = le32_to_cpu(r->cwd_length);
	u32 outcome = le32_to_cpu(r->outcome), reason = le32_to_cpu(r->reason);
	return command < sizeof(r->command) && cwd < sizeof(r->cwd) && !r->reserved &&
		!memchr(r->command, 0, command) && !memchr(r->cwd, 0, cwd) &&
		!memchr_inv(r->command + command, 0, sizeof(r->command) - command) &&
		!memchr_inv(r->cwd + cwd, 0, sizeof(r->cwd) - cwd) &&
		outcome >= BASHOS_AUDIT_V2_DENIED && outcome <= BASHOS_AUDIT_V2_REJECTED &&
		reason >= BASHOS_AUDIT_V2_REASON_POLICY && reason <= BASHOS_AUDIT_V2_REASON_INTERNAL &&
		le32_to_cpu(r->cache_hit) <= 1 && le32_to_cpu(r->target_count) <= 16 &&
		le32_to_cpu(r->committed_count) <= le32_to_cpu(r->target_count);
}

struct ba_v2_audit_store *ba_v2_audit_create(void)
{
	struct ba_v2_audit_store *s = kvzalloc(sizeof(*s), GFP_KERNEL);
	u8 key[32];
	int rc;
	if (!s) return ERR_PTR(-ENOMEM);
	mutex_init(&s->lock);
	s->hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(s->hmac)) { rc = PTR_ERR(s->hmac); s->hmac = NULL; goto failed; }
	get_random_bytes(key, sizeof(key));
	rc = crypto_shash_setkey(s->hmac, key, sizeof(key));
	memzero_explicit(key, sizeof(key));
	if (rc) goto failed;
	s->desc_size = sizeof(*s->desc) + crypto_shash_descsize(s->hmac);
	s->desc = kzalloc(s->desc_size, GFP_KERNEL);
	if (!s->desc) { rc = -ENOMEM; goto failed; }
	s->desc->tfm = s->hmac;
	do { get_random_bytes(&s->epoch, sizeof(s->epoch)); } while (!s->epoch);
	return s;
failed:
	ba_v2_audit_destroy(s);
	return ERR_PTR(rc);
}

/* Caller has quiesced every context and ticket before teardown. */
void ba_v2_audit_destroy(struct ba_v2_audit_store *s)
{
	if (!s || IS_ERR(s)) return;
	if (s->desc) { memzero_explicit(s->desc, s->desc_size); kfree_sensitive(s->desc); }
	if (s->hmac) crypto_free_shash(s->hmac);
	mutex_destroy(&s->lock);
	kvfree_sensitive(s, sizeof(*s));
}

int ba_v2_audit_reserve(struct ba_v2_audit_store *s, u32 count,
		struct ba_v2_audit_ticket *ticket)
{
	int rc = 0;
	if (!s || !ticket || ticket->remaining || !count || count > BA_V2_AUDIT_CAPACITY) return -EINVAL;
	mutex_lock(&s->lock);
	if (count > BA_V2_AUDIT_CAPACITY - s->used - s->reserved ||
	    s->sequence > U64_MAX - s->reserved - count) {
		if (s->backpressure != U64_MAX) s->backpressure++;
		rc = -ENOSPC;
	} else {
		s->reserved += count;
		ticket->store = s; ticket->epoch = s->epoch; ticket->remaining = count;
	}
	mutex_unlock(&s->lock);
	return rc;
}

void ba_v2_audit_cancel(struct ba_v2_audit_ticket *ticket)
{
	struct ba_v2_audit_store *s;
	if (!ticket || !ticket->remaining || !(s = ticket->store)) return;
	mutex_lock(&s->lock);
	if (ticket->epoch == s->epoch && ticket->remaining <= s->reserved)
		s->reserved -= ticket->remaining;
	memzero_explicit(ticket, sizeof(*ticket));
	mutex_unlock(&s->lock);
}

int ba_v2_audit_commit(struct ba_v2_audit_ticket *ticket,
		const struct bashos_audit_v2_record *event, u64 *sequence)
{
	struct ba_v2_audit_store *s;
	struct bashos_audit_v2_record *record;
	u32 at;
	int rc;
	if (!ticket || !event || !(s = ticket->store) || !audit_body_valid(event)) return -EINVAL;
	mutex_lock(&s->lock);
	if (!ticket->remaining || ticket->epoch != s->epoch || !s->reserved ||
	    s->used == BA_V2_AUDIT_CAPACITY || s->sequence == U64_MAX) { rc = -ENOSPC; goto done; }
	at = (s->head + s->used) % BA_V2_AUDIT_CAPACITY;
	record = &s->records[at];
	*record = *event;
	record->size = cpu_to_le32(sizeof(*record));
	record->version = cpu_to_le32(BASHOS_AUDIT_V2_VERSION);
	record->epoch = cpu_to_le64(s->epoch);
	record->sequence = cpu_to_le64(s->sequence + 1);
	record->boottime_ns = cpu_to_le64(ktime_get_boottime_ns());
	memzero_explicit(record->hmac, sizeof(record->hmac));
	rc = crypto_shash_digest(s->desc, (const u8 *)record, offsetof(typeof(*record), hmac), record->hmac);
	if (rc) { memzero_explicit(record, sizeof(*record)); goto done; }
	s->sequence++; s->used++; s->reserved--; ticket->remaining--;
	if (sequence) *sequence = s->sequence;
done:
	mutex_unlock(&s->lock);
	return rc;
}

int ba_v2_audit_peek(struct ba_v2_audit_store *s, struct bashos_audit_v2_record *record)
{
	int rc = 0;
	if (!s || !record) return -EINVAL;
	memset(record, 0, sizeof(*record));
	mutex_lock(&s->lock);
	if (!s->used) rc = -EAGAIN;
	else *record = s->records[s->head];
	mutex_unlock(&s->lock);
	return rc;
}

int ba_v2_audit_ack(struct ba_v2_audit_store *s, u64 epoch, u64 sequence)
{
	int rc = 0;
	if (!s) return -EINVAL;
	mutex_lock(&s->lock);
	if (epoch != s->epoch || !s->used || le64_to_cpu(s->records[s->head].sequence) != sequence)
		rc = -ESTALE;
	else {
		memzero_explicit(&s->records[s->head], sizeof(s->records[s->head]));
		s->head = (s->head + 1) % BA_V2_AUDIT_CAPACITY;
		s->used--;
	}
	mutex_unlock(&s->lock);
	return rc;
}

int ba_v2_audit_verify(struct ba_v2_audit_store *s, const struct bashos_audit_v2_record *r)
{
	u8 actual[32];
	int rc;
	if (!s || !r || le32_to_cpu(r->size) != sizeof(*r) ||
	    le32_to_cpu(r->version) != BASHOS_AUDIT_V2_VERSION ||
	    !le64_to_cpu(r->sequence) || !audit_body_valid(r)) return -EINVAL;
	mutex_lock(&s->lock);
	if (le64_to_cpu(r->epoch) != s->epoch) { rc = -EKEYREJECTED; goto done; }
	rc = crypto_shash_digest(s->desc, (const u8 *)r, offsetof(typeof(*r), hmac), actual);
	if (!rc && crypto_memneq(actual, r->hmac, sizeof(actual))) rc = -EKEYREJECTED;
done:
	memzero_explicit(actual, sizeof(actual));
	mutex_unlock(&s->lock);
	return rc;
}

void ba_v2_audit_info(struct ba_v2_audit_store *s, struct ba_v2_audit_info *info)
{
	if (!s || !info) return;
	mutex_lock(&s->lock);
	info->epoch = s->epoch; info->next_sequence = s->sequence == U64_MAX ? 0 : s->sequence + 1;
	info->oldest_sequence = s->used ? le64_to_cpu(s->records[s->head].sequence) : 0;
	info->backpressure_denials = s->backpressure;
	info->available = s->used; info->reserved = s->reserved;
	mutex_unlock(&s->lock);
}
