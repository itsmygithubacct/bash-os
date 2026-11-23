/* SPDX-License-Identifier: MIT */
/* File mode operands for chmod, mkdir -m and install -m, written for
   bash-os from the coreutils manual ("File permissions"), POSIX chmod and
   observed GNU coreutils 9.7 behaviour.

   A MODE is either an octal number of at most 07777 or a comma-separated
   list of symbolic clauses, each [ugoa]* followed by one or more actions:
   an operator (+, - or =) and then permission letters from "rwxXst", a
   single class letter (u, g or o) whose current permissions are copied,
   or, when the clause names no class, octal digits (an "operator numeric
   mode", which must end its clause).

   Rules the manual documents and GNU follows:
   - a clause that names no class affects all classes except the bits set
     in the umask; operator numeric modes ignore the umask;
   - '=' clears the named classes (everything for an unnamed class) before
     setting; '=' with nothing after it just clears;
   - X adds or removes search/execute for directories and for files that
     have an execute bit at that point of the evaluation;
   - s is the set-user-ID bit for u and set-group-ID for g, t is the sticky
     bit for o (and for an unnamed class or a);
   - on directories the set-ID bits survive '=' clauses that do not
     mention s and plain octal modes of four digits or fewer that leave
     them clear; '=' octal modes and plain octal modes of five or more
     digits clear them. */
#ifndef BASHOS_GNU_MODE_H
#define BASHOS_GNU_MODE_H

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BOS_MODE_RWX  0777
#define BOS_MODE_BITS 07777

enum { BOS_MODE_FIXED, BOS_MODE_XCOND, BOS_MODE_COPY };

/* One action. The list ends with an entry whose op is 0. */
struct bos_mode_change
{
    char op;            /* '=', '+' or '-'; 0 ends the list */
    char kind;          /* BOS_MODE_FIXED, BOS_MODE_XCOND or BOS_MODE_COPY */
    char masked;        /* no class named: the umask filters the bits */
    unsigned char from; /* BOS_MODE_COPY: shift of the source class (6, 3, 0) */
    mode_t who;         /* bits this action may touch */
    mode_t value;       /* bits it sets or clears (already within WHO) */
    mode_t dir_keep;    /* '=' on a directory: bits that are left alone */
};

/* Octal value of the digits at *P (advanced past them), or -1 if it
   exceeds 07777. *COUNT receives the number of digits. */
static inline long
bos_mode_octal (const char **p, int *count)
{
    long v = 0;
    int n = 0;

    while (**p >= '0' && **p <= '7')
    {
        v = v * 8 + (**p - '0');
        if (v > BOS_MODE_BITS)
            return -1;
        (*p)++;
        n++;
    }
    *count = n;
    return v;
}

static inline struct bos_mode_change *
bos_mode_compile (const char *mode, int *nomem)
{
    struct bos_mode_change *list, *c;
    const char *p = mode;
    size_t room = strlen (mode) + 2;

    if (nomem)
        *nomem = 0;
    list = (struct bos_mode_change *) calloc (room, sizeof *list);
    if (list == NULL)
    {
        if (nomem)
            *nomem = 1;
        return NULL;
    }
    c = list;

    if (*p >= '0' && *p <= '7')
    {
        int digits;
        long v = bos_mode_octal (&p, &digits);

        if (v < 0 || *p != '\0')
            goto invalid;
        c->op = '=';
        c->kind = BOS_MODE_FIXED;
        c->who = BOS_MODE_BITS;
        c->value = (mode_t) v;
        /* Short octal modes leave a directory's clear set-ID bits alone. */
        c->dir_keep = digits < 5 ? (mode_t) (06000 & ~v) : 0;
        c[1].op = 0;
        return list;
    }

    for (;;)
    {
        mode_t who = 0;
        int named = 0, actions = 0;

        for (;; p++)
        {
            if (*p == 'u')
                who |= 04700;
            else if (*p == 'g')
                who |= 02070;
            else if (*p == 'o')
                who |= 01007;
            else if (*p == 'a')
                who |= BOS_MODE_BITS;
            else
                break;
            named = 1;
        }
        if (!named)
            who = BOS_MODE_BITS;

        while (*p == '=' || *p == '+' || *p == '-')
        {
            char op = *p++;

            c->op = op;
            c->who = who;
            c->masked = !named;
            c->kind = BOS_MODE_FIXED;
            c->value = 0;
            c->dir_keep = 0;
            actions++;

            if (!named && *p >= '0' && *p <= '7')
            {
                int digits;
                long v = bos_mode_octal (&p, &digits);

                if (v < 0 || (*p != ',' && *p != '\0'))
                    goto invalid;
                c->masked = 0;
                c->value = (mode_t) v;
                c++;
                break;
            }
            if (*p == 'u' || *p == 'g' || *p == 'o')
            {
                c->kind = BOS_MODE_COPY;
                c->from = *p == 'u' ? 6 : *p == 'g' ? 3 : 0;
                p++;
                if (op == '=')
                    c->dir_keep = 06000;
            }
            else
            {
                mode_t bits = 0;
                int setid = 0;

                for (;; p++)
                {
                    if (*p == 'r')
                        bits |= 0444;
                    else if (*p == 'w')
                        bits |= 0222;
                    else if (*p == 'x')
                        bits |= 0111;
                    else if (*p == 'X')
                        c->kind = BOS_MODE_XCOND;
                    else if (*p == 's')
                    {
                        bits |= 06000;
                        setid = 1;
                    }
                    else if (*p == 't')
                        bits |= 01000;
                    else
                        break;
                }
                c->value = bits & who;
                if (op == '=' && !setid)
                    c->dir_keep = 06000;
            }
            c++;
        }
        if (actions == 0)
            goto invalid;
        if (*p == '\0')
            break;
        if (*p != ',')
            goto invalid;
        p++;
    }
    c->op = 0;
    return list;

invalid:
    free (list);
    return NULL;
}

static inline mode_t
bos_mode_adjust (mode_t oldmode, int is_dir, mode_t umask_value,
                 const struct bos_mode_change *changes, mode_t *changed_bits)
{
    mode_t mode = oldmode & BOS_MODE_BITS, changed = 0;
    const struct bos_mode_change *c;

    for (c = changes; c->op; c++)
    {
        mode_t v = c->value, clear;

        if (c->kind == BOS_MODE_COPY)
        {
            mode_t t = (mode >> c->from) & 7;
            v = (t | t << 3 | t << 6) & c->who;
        }
        else if (c->kind == BOS_MODE_XCOND && (is_dir || (mode & 0111)))
            v |= 0111 & c->who;
        if (c->masked)
            v &= ~umask_value;

        switch (c->op)
        {
        case '=':
            clear = c->who & ~(is_dir ? c->dir_keep : 0);
            mode = (mode & ~clear) | v;
            changed |= clear;
            break;
        case '+':
            mode |= v;
            changed |= v;
            break;
        default:
            mode &= ~v;
            changed |= v;
            break;
        }
    }
    if (changed_bits)
        *changed_bits = changed & BOS_MODE_BITS;
    return mode;
}

/* The nine permission characters of MODE as ls shows them ("rwsr-xr-T"),
   in BUF (at least 10 bytes); returns BUF. */
static inline char *
bos_mode_string (mode_t mode, char *buf)
{
    static const char rwx[] = "rwxrwxrwx";
    int i;

    for (i = 0; i < 9; i++)
        buf[i] = (mode & (0400 >> i)) ? rwx[i] : '-';
    if (mode & 04000)
        buf[2] = (mode & 0100) ? 's' : 'S';
    if (mode & 02000)
        buf[5] = (mode & 010) ? 's' : 'S';
    if (mode & 01000)
        buf[8] = (mode & 01) ? 't' : 'T';
    buf[9] = '\0';
    return buf;
}

#endif
