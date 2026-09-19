/* SPDX-License-Identifier: MIT */
/* _git/proto.h — pkt-line framing, and the shape of protocol v2.
 *
 * Everything git sends over a connection is a packet: four hexadecimal
 * digits giving the length of the packet including those four digits,
 * then that many bytes less four. Three lengths carry no payload and mean
 * something on their own — 0000 ends a section, 0001 divides one, and
 * 0002 ends a response.
 *
 * Protocol v2 is a conversation in those packets: the server offers what
 * it can do, and the client asks for one thing at a time by name.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_PROTO_H
#define BASH_OS_GIT_PROTO_H

#include <stddef.h>

/* What a packet turned out to be. A packet with a payload reports how
   long it is, which is never negative. */
enum {
    BGIT_PKT_FLUSH = -1,       /* 0000, the end of a section */
    BGIT_PKT_DELIM = -2,       /* 0001, the divide inside one */
    BGIT_PKT_END   = -3,       /* 0002, the end of a response */
    BGIT_PKT_EOF   = -4,       /* nothing left to read */
    BGIT_PKT_ERROR = -5        /* the stream is not pkt-line */
};

/* A stream of packets, read from a descriptor or from bytes already in
   hand — an HTTP response body arrives whole, a pipe does not. */
typedef struct {
    int fd;                    /* -1 when the bytes are already here */
    unsigned char *buf;        /* what has been read and not yet used */
    size_t len, at, cap;
    int owns;                  /* whether buf must be freed */
} bgit_pkt_reader;

/* Read packets from FD, or from LEN bytes at DATA (which must outlive the
   reader). Release with bgit_pkt_release. */
void bgit_pkt_from_fd (bgit_pkt_reader *reader, int fd);
void bgit_pkt_from_memory (bgit_pkt_reader *reader, const unsigned char *data,
                           size_t len);
void bgit_pkt_release (bgit_pkt_reader *reader);

/* The next packet. Returns its length and points DATA at its payload,
   which stays valid until the next read, or one of the markers above.
   The payload is not copied and is not terminated. */
int bgit_pkt_read (bgit_pkt_reader *reader, const unsigned char **data);

/* The same, as a string with any trailing newline removed, in a buffer
   the caller must free. Returns the length, or a marker. */
int bgit_pkt_read_line (bgit_pkt_reader *reader, char **line);

/* Write one packet, a formatted packet, or a marker. Return 0, or -1. */
int bgit_pkt_write (int fd, const void *data, size_t len);

/* Write LEN bytes down one side-band channel — 1 for the pack itself, 2
   for progress, 3 for an error — in as many packets as it takes. */
int bgit_pkt_write_band (int fd, int channel, const void *data, size_t len);
int bgit_pkt_writef (int fd, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));
int bgit_pkt_flush (int fd);
int bgit_pkt_delim (int fd);

/* What a server said it can do: the lines of a v2 advertisement, each
   "name" or "name=value". */
typedef struct {
    char **lines;
    size_t n;
} bgit_proto_caps;

/* Read an advertisement — version, capabilities, flush — from READER.
   Returns 0, or -1 with a message for the caller to report. */
int bgit_proto_read_caps (bgit_pkt_reader *reader, bgit_proto_caps *caps);
void bgit_proto_caps_release (bgit_proto_caps *caps);

/* The value of a capability, or NULL if the server did not offer it. A
   capability offered without a value reads as "". */
const char *bgit_proto_cap (const bgit_proto_caps *caps, const char *name);

/* One ref as ls-refs reports it. */
typedef struct {
    char id[41];
    char *name;
    char *symref;              /* what HEAD points at, when asked */
    char peeled[41];           /* what a tag points at, when asked */
} bgit_proto_ref;

void bgit_proto_refs_release (bgit_proto_ref *refs, size_t n);

/* Ask for refs over a v2 connection: write the request to OUT, read the
   answer from READER. PREFIXES names what to list, empty for everything.
   Returns 0, or -1. */
int bgit_proto_ls_refs (bgit_pkt_reader *reader, int out,
                        const char *const *prefixes, size_t n_prefixes,
                        int want_symrefs, int want_peeled,
                        bgit_proto_ref **refs, size_t *n_refs);

/* Ask for everything WANTS reaches that HAVES does not, and read the
   pack that comes back: the request goes to OUT, the answer comes from
   READER. The pack is returned whole, for the caller to free; progress
   from the far end goes to stderr, and an error from it is reported the
   way git reports one. Returns 0, or -1. */
int bgit_proto_fetch (bgit_pkt_reader *reader, int out,
                      const char *const *wants, size_t n_wants,
                      const char *const *haves, size_t n_haves,
                      unsigned char **pack, size_t *pack_len);

#endif /* BASH_OS_GIT_PROTO_H */
