/* SPDX-License-Identifier: MIT */
/* Harmless disposable-guest observer: report actual kernel credentials and
 * environment, then return the requested bounded status or a real signal. */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
extern char **environ;

static void hex(const char *p)
{
	putchar('"');
	for (; *p; p++) printf("%02x", (unsigned char)*p);
	putchar('"');
}

int main(int argc, char **argv)
{
	uid_t u[3]; gid_t g[3], groups[128]; char cwd[4096];
	struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
	struct __user_cap_data_struct caps[2] = {{0}, {0}};
	int count, wanted = 0, sig = 0;
	if (getresuid(&u[0], &u[1], &u[2]) || getresgid(&g[0], &g[1], &g[2]) ||
	    (count = getgroups(128, groups)) < 0 || !getcwd(cwd, sizeof(cwd)) || syscall(SYS_capget, &header, caps)) return 125;
	if (argc > 1 && !strncmp(argv[1], "exit-", 5)) {
		char *end; long value; errno = 0; value = strtol(argv[1] + 5, &end, 10);
		if (errno || *end || value < 0 || value > 255) return 125;
		wanted = (int)value;
	} else if (argc > 1 && !strcmp(argv[1], "signal-term")) sig = SIGTERM;
	printf("PCV2_TARGET {\"uid\":[%u,%u,%u,%u],\"gid\":[%u,%u,%u,%u],\"groups\":[",
		(unsigned)u[0],(unsigned)u[1],(unsigned)u[2],(unsigned)setfsuid((uid_t)-1),
		(unsigned)g[0],(unsigned)g[1],(unsigned)g[2],(unsigned)setfsgid((gid_t)-1));
	for (int i = 0; i < count; i++) printf("%s%u", i ? "," : "", (unsigned)groups[i]);
	printf("],\"caps\":[%u,%u,%u,%u,%u,%u],\"nnp\":%d,\"cwd_hex\":",
		caps[0].effective,caps[0].permitted,caps[0].inheritable,caps[1].effective,caps[1].permitted,caps[1].inheritable,
		prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)); hex(cwd);
	printf(",\"argv_hex\":[");
	for (int i = 0; i < argc; i++) { if (i) putchar(','); hex(argv[i]); }
	printf("],\"env_hex\":[");
	for (int i = 0; environ[i]; i++) { if (i) putchar(','); hex(environ[i]); }
	puts("]}");
	if (fflush(stdout) || ferror(stdout)) return 125;
	if (sig) { raise(sig); return 125; }
	return wanted;
}
