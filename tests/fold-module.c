/* SPDX-License-Identifier: MIT */
/* Register the repository source under its compiled-in name for sanitizers. */
#include "../loadables/fold.c"

struct builtin fold_struct = {
    "fold", fold_builtin, BUILTIN_ENABLED, fold_doc,
    "fold [-bcs] [-w WIDTH] [FILE...]", 0
};
