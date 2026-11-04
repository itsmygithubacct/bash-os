/* SPDX-License-Identifier: MIT */
/* Fixed harmless caller-side editor for attested disposable guests only. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <unistd.h>

static void hex(const char *text)
{
	putchar('"');
	for (; *text; text++) printf("%02x", (unsigned char)*text);
	putchar('"');
}

static int write_all(int fd, const char *data, size_t size)
{
	while (size) {
		ssize_t n = write(fd, data, size);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return -1;
		data += n; size -= (size_t)n;
	}
	return fsync(fd);
}

int main(int argc, char **argv)
{
	uid_t u[3]; gid_t g[3], groups[128];
	const char *behavior = getenv("SAFEEDIT_BEHAVIOR"), *wait = getenv("SAFEEDIT_WAIT");
	int count;
	if (!behavior) behavior = "write";
	if (argc < 2 || argc > 17 || getresuid(&u[0], &u[1], &u[2]) ||
	    getresgid(&g[0], &g[1], &g[2]) || (count = getgroups(128, groups)) < 0 || !u[0]) return 125;
	if (strcmp(behavior, "write") && strcmp(behavior, "replace") && strcmp(behavior, "fail") &&
	    strcmp(behavior, "symlink") && strcmp(behavior, "backup")) return 125;
	printf("PCV2_EDITOR {\"pid\":%ld,\"uid\":[%u,%u,%u,%u],\"gid\":[%u,%u,%u,%u],\"groups\":[", (long)getpid(),
		(unsigned)u[0],(unsigned)u[1],(unsigned)u[2],(unsigned)setfsuid((uid_t)-1),
		(unsigned)g[0],(unsigned)g[1],(unsigned)g[2],(unsigned)setfsgid((gid_t)-1));
	for (int i = 0; i < count; i++) printf("%s%u", i ? "," : "", (unsigned)groups[i]);
	printf("],\"paths_hex\":[");
	for (int i = 1; i < argc; i++) { if (i > 1) putchar(','); hex(argv[i]); }
	puts("]}");
	if (fflush(stdout) || ferror(stdout)) return 125;
	if (wait && !strcmp(wait, "1")) {
		char line[8];
		puts("PCV2_EDITOR_WAIT");
		if (fflush(stdout) || !fgets(line, sizeof(line), stdin) || strcmp(line, "edit\n")) return 125;
	}
	for (int i = 1; i < argc; i++) {
		char next[512], contents[32];
		const char *path = argv[i];
		struct stat st;
		int fd, length;
		if (strncmp(path, "/tmp/bashos-edit-v2.", 20) || strlen(path) >= 400) return 125;
		if (!strcmp(behavior, "symlink") && i == 1) {
			const char *outside = getenv("SAFEEDIT_ORIGINAL");
			if (!outside || *outside != '/' || unlink(path) || symlink(outside, path)) return 125;
			continue;
		}
		if (!strcmp(behavior, "replace")) {
			if (snprintf(next, sizeof(next), "%s.new", path) >= (int)sizeof(next)) return 125;
			fd = open(next, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
		} else fd = open(path, O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0) return 125;
		if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != u[0] || st.st_nlink != 1 ||
		    (st.st_mode & 0777) != 0600 || ftruncate(fd, 0)) { close(fd); return 125; }
		length = snprintf(contents, sizeof(contents), "edited-%02d\n", i - 1);
		if (length < 0 || length >= (int)sizeof(contents) || write_all(fd, contents, (size_t)length)) { close(fd); return 125; }
		if (close(fd)) return 125;
		if (!strcmp(behavior, "replace") && rename(next, path)) return 125;
		if (!strcmp(behavior, "backup")) {
			if (snprintf(next, sizeof(next), "%s.backup", path) >= (int)sizeof(next)) return 125;
			fd = open(next, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
			if (fd < 0 || write_all(fd, "private backup\n", 15)) { if (fd >= 0) close(fd); return 125; }
			if (close(fd)) return 125;
		}
	}
	puts("PCV2_EDITOR_DONE");
	if (fflush(stdout) || ferror(stdout)) return 125;
	return !strcmp(behavior, "fail") ? 17 : 0;
}
