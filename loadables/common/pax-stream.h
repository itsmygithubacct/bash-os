/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_PAX_STREAM_H
#define BASHOS_PAX_STREAM_H
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
/* tar --transform=s/REGEX/REPLACEMENT/[FLAGS][;s/...]: GNU tar's sed-style
   rewrite of member names (flag r), symlink targets (s) and hardlink
   targets (h), applied in order. bashos_pax_xform_add reports a bad
   expression with GNU's message and returns -1. */
struct bashos_pax_xform;
int bashos_pax_xform_add(struct bashos_pax_xform **, const char *expr);
void bashos_pax_xform_free(struct bashos_pax_xform **);
struct bashos_pax_read_options {
    int extract, verbose, tar_mode, to_stdout, preserve;
    /* same_owner: chown each extracted member to the archived owner (GNU
       tar's default for root, --same-owner; pax -p o). numeric_owner: use
       the archived uid/gid even when the archived user/group names exist. */
    int same_owner, numeric_owner;
    unsigned strip;
    const char **members;
    size_t count;
    /* When set, counts members that could not be created while the rest of
       the archive was still extracted. */
    int *member_errors;
    /* --exclude=PATTERN skips matching members (as on create); with
       wildcards, member operands are fnmatch patterns (tar --wildcards). */
    const char **excludes;
    size_t nexcludes;
    int wildcards;
    /* absolute_names (tar -P): extract absolute names as they are;
       otherwise a leading '/' is removed, with GNU's warning. */
    int absolute_names;
    struct bashos_pax_xform *xforms;
    /* acls (tar --acls): restore SCHILY.acl.access/default records. */
    int acls;
    /* to_command (tar --to-command): pipe each regular member to this
       /bin/sh command with GNU's TAR_* variables; archive is TAR_ARCHIVE. */
    const char *to_command, *archive;
    /* compare (tar -d/--diff): compare each member with the file system
       instead of extracting it, printing GNU tar's "NAME: Mode differs"
       lines on stdout and counting them in *differences (a missing file
       counts too, after its warning). dereference (tar -h) compares what
       a symlink points to. */
    int compare, dereference;
    int *differences;
    /* incremental (tar -G, or -g on list/extract): a directory member's
       dumpdir (GNU 'D' members, GNU.dumpdir records) is printed by a
       listing with verbose > 1; extraction applies its renames (R/T/X)
       and deletes what the directory holds that the dumpdir does not name
       ("Deleting 'NAME'" when verbose). */
    int incremental;
    /* newer_set (tar -N/--newer-mtime on list/extract): only members whose
       modification time is not older than newer_sec.newer_nsec. */
    int newer_set;
    time_t newer_sec;
    long newer_nsec;
};
int bashos_pax_read(FILE *, const struct bashos_pax_read_options *);
/* tar --delete: copy IN to OUT without the members named in OPTIONS
   (members/count, wildcards, xforms are not applied). Returns 0, 1 when a
   member was not found (after copying the rest), or 2 on a read error. */
int bashos_pax_delete(FILE *in, FILE *out, const struct bashos_pax_read_options *);
struct bashos_pax_archived;
struct bashos_pax_hardlink;
/* Archive formats a writer can produce (tar --format, pax -x). DEFAULT is
   ustar with pax extended headers only for what ustar cannot hold (also
   tar --format=ustar|posix|pax); GNU and OLDGNU use GNU tar's magic and
   ././@LongLink records for long names; V7 has no magic, owner names or
   special files, and names of at most 99 bytes. */
enum { BASHOS_PAX_FMT_DEFAULT = 0, BASHOS_PAX_FMT_GNU, BASHOS_PAX_FMT_OLDGNU, BASHOS_PAX_FMT_V7 };
/* Zero-initialize once per output archive and clear on every exit path. */
struct bashos_pax_write_context {
    struct bashos_pax_hardlink *links;
    int no_recurse, override_mtime;
    time_t mtime;
    /* -o uid:= gid:= uname:= gname:= (tar --owner/--group/--numeric-owner) */
    int override_uid, override_gid, set_uname, set_gname;
    unsigned long uid, gid;
    char uname[33], gname[33];
    /* -o exclude:=PATTERN (tar --exclude): unanchored fnmatch on member names */
    const char **excludes;
    size_t nexcludes;
    /* -o sort:=name: directory entries in byte order */
    int sort_names;
    struct bashos_pax_xform *xforms;
    /* strip_slash (tar without -P): store names without their leading '/' */
    int strip_slash;
    /* sparse (tar -S): files with holes become GNU PAX 1.0 sparse members */
    int sparse;
    /* acls (tar --acls): store POSIX ACLs as SCHILY.acl.* records */
    int acls;
    /* update (pax -u, tar -u): skip files no newer than their archived copy */
    int update;
    /* dereference (pax -L, tar -h): archive what symlinks point to;
       dereference_operands (pax -H): only for the named operands */
    int dereference, dereference_operands;
    /* format: BASHOS_PAX_FMT_* */
    int format;
    struct bashos_pax_archived *archived;
    /* newer_set (tar -N/--newer/--newer-mtime): a non-directory whose
       modification time (or, with newer_ctime, status-change time) is
       older than newer_sec.newer_nsec is left out; directories are kept. */
    int newer_set, newer_ctime;
    time_t newer_sec;
    long newer_nsec;
    /* verbose_out (tar -v): each member's name, as archived, is printed
       there; a member -N leaves out is reported "file is unchanged; not
       dumped" on stderr. */
    FILE *verbose_out;
    /* incremental (tar -g/-G): GNU headers also carry atime and ctime. */
    int incremental;
    /* tar_words (tar): GNU tar's diagnostics ("NAME: Cannot stat: ..."). */
    int tar_words;
};
/* Position OUT (opened r+) at the end-of-archive marker for appending; with
   ctx->update also remember each member's name and time. Returns 0 or -1. */
int bashos_pax_seek_end(FILE *out, const char *archive, struct bashos_pax_write_context *ctx);
int bashos_pax_set_mtime(struct bashos_pax_write_context *, const char *seconds);
/* tar --format / pax -x NAME: BASHOS_PAX_FMT_*, or -1 for an unknown name. */
int bashos_pax_format(const char *name);
void bashos_pax_write_clear(struct bashos_pax_write_context *);
int bashos_pax_write_member_context(FILE *, const char *, struct bashos_pax_write_context *);
int bashos_pax_write_member(FILE *, const char *, int no_recurse);
/* tar -g/-G: directory PATH (ST from lstat) as a dumpdir member, DUMPDIR
   being LEN bytes of "Cname\0" records and their final NUL: a GNU 'D'
   member, or with the default (posix) format a directory with a
   GNU.dumpdir record. Returns 0, or 1 after a diagnostic. */
int bashos_pax_write_dumpdir(FILE *, const char *path, const struct stat *st,
                             const char *dumpdir, size_t len, struct bashos_pax_write_context *);
/* Whether --exclude patterns skip PATH; the member name PATH is stored
   under (transforms, leading '/' removed), malloc'd. */
int bashos_pax_excluded(const struct bashos_pax_write_context *, const char *path);
char *bashos_pax_member_name(const struct bashos_pax_write_context *, const char *path);
#endif
