/* Optional LD_PRELOAD call-count profile of the real, dynamically linked wc.
   Compile separately through the build gate. Run through the bench gate.
   Counts include shell setup: compare with a ':' control in the same shell. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <wchar.h>
#include <wctype.h>

static unsigned long long decode_calls, width_calls, print_calls, space_calls;

size_t
mbrtowc (wchar_t *wc, const char *s, size_t n, mbstate_t *state)
{
    static size_t (*real_fn) (wchar_t *, const char *, size_t, mbstate_t *);
    if (!real_fn) real_fn = dlsym (RTLD_NEXT, "mbrtowc");
    decode_calls++;
    return real_fn (wc, s, n, state);
}

int
wcwidth (wchar_t wc)
{
    static int (*real_fn) (wchar_t);
    if (!real_fn) real_fn = dlsym (RTLD_NEXT, "wcwidth");
    width_calls++;
    return real_fn (wc);
}

int
iswprint (wint_t wc)
{
    static int (*real_fn) (wint_t);
    if (!real_fn) real_fn = dlsym (RTLD_NEXT, "iswprint");
    print_calls++;
    return real_fn (wc);
}

int
iswspace (wint_t wc)
{
    static int (*real_fn) (wint_t);
    if (!real_fn) real_fn = dlsym (RTLD_NEXT, "iswspace");
    space_calls++;
    return real_fn (wc);
}

__attribute__((destructor)) static void
report (void)
{
    fprintf (stderr, "{\"mbrtowc\":%llu,\"wcwidth\":%llu,\"iswprint\":%llu,\"iswspace\":%llu}\n",
             decode_calls, width_calls, print_calls, space_calls);
}
