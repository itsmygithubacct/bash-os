/* SPDX-License-Identifier: MIT */
/* Malformed account rows must not overflow the shell or invent identities. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "../loadables/common/bashcred_privdrop.h"

int main (void)
{
    const char *rows[] = {
        "test:x:1001:1002:Test:/tmp:/bin/sh\n",
        "test:x:1001:1002:Test:/tmp:\n",
        "test:x:1001:1002:Test:/tmp:/bin/sh:extra\n",
        "test:x:1001:1002:Test:/tmp\n",
        "test:x:invalid:1002:Test:/tmp:/bin/sh\n",
        "test:x:1001:999999999999999999999:Test:/tmp:/bin/sh\n"
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        char *line = strdup (rows[i]);
        bc_user_info user;
        int rc = bc_pd_match_row (line, strlen (line), "test", 0, 0, &user);
        assert ((rc == 0) == (i < 2));
        if (rc == 0) {
            assert (user.uid == 1001 && user.gid == 1002);
            assert (!strcmp (user.shell, i ? "/bin/bash" : "/bin/sh"));
        }
        free (line);
    }
    char groups[] = "good:x:42:other,test\nempty:x:43:\n"
                    "extra:x:44:test:extra\nshort:x:45\n"
                    "bad:x:no:test\nlarge:x:999999999999999999999:test\n"
                    "negative:x:-1:test\nalso:x:46:test\n";
    FILE *stream = fmemopen (groups, strlen (groups), "r");
    assert (stream);
    gid_t gids[2]; int count = -1;
    assert (bc_pd_groups_from_stream (stream, "test", gids, &count, 2) == 0);
    assert (count == 2 && gids[0] == 42 && gids[1] == 46);
    fclose (stream);
    puts ("privdrop-host: account parser checks passed");
    return 0;
}
