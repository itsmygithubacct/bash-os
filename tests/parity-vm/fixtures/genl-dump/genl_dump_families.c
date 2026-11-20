// SPDX-License-Identifier: GPL-2.0-only
/* Disposable guest fixture. Enlarge the controller dump without handling
 * requests or sending traffic. The real kernel decides its packet boundaries. */
#include <linux/module.h>
#include <net/genetlink.h>

static const struct genl_multicast_group groups[] = {
	{ .name = "group0" }, { .name = "group1" },
	{ .name = "group2" }, { .name = "group3" },
	{ .name = "group4" }, { .name = "group5" },
	{ .name = "group6" }, { .name = "group7" },
};

static struct genl_family families[160];
static unsigned int registered;

static void release_families(void)
{
	while (registered)
		genl_unregister_family(&families[--registered]);
}

static int __init register_families(void)
{
	while (registered < ARRAY_SIZE(families)) {
		struct genl_family *family = &families[registered];
		int err;

		snprintf(family->name, sizeof(family->name), "qual_dump%03u", registered);
		family->version = 1;
		family->module = THIS_MODULE;
		family->mcgrps = groups;
		family->n_mcgrps = ARRAY_SIZE(groups);
		family->netnsok = true;
		err = genl_register_family(family);
		if (err) {
			release_families();
			return err;
		}
		registered++;
	}
	return 0;
}

module_init(register_families);
module_exit(release_families);
MODULE_LICENSE("GPL");
