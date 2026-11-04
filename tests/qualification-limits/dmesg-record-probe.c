/* SPDX-License-Identifier: MIT */
/* Rebuilt decoder with synthetic whole-record reads; never a live ring. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

static unsigned char record[131072];
static size_t record_size;
static unsigned stage, reads;
static int retry_errors, inject_fatal;

static ssize_t q_read(int fd, void *buf, size_t count)
{
  if (fd != 999 || ++reads > 8) { errno = EBADF; return -1; }
  int error = 0;
  if (retry_errors && stage == 0) error = EINTR;
  else if (retry_errors && stage == 1) error = EPIPE;
  else if (inject_fatal) error = EIO;
  else if (stage >= (retry_errors ? 3U : 1U)) error = EAGAIN;
  else if (count < record_size) error = EINVAL;
  stage++;
  if (error) {
    fprintf(stderr,"read count=%zu errno=%d\n",count,error);
    errno = error; return -1;
  }
  memcpy(buf,record,record_size);
  fprintf(stderr,"read count=%zu returned=%zu\n",count,record_size);
  return (ssize_t)record_size;
}

#define read q_read
#include QUAL_DMESG_SOURCE
#undef read

void builtin_error(const char *fmt, ...)
{
  va_list ap;
  fputs("diagnostic: ",stderr);
  va_start(ap,fmt); vfprintf(stderr,fmt,ap); va_end(ap);
  fputc('\n',stderr);
}

int main(int argc, char **argv)
{
  const char *header = "14,1,1000000,-;";
  char *end;
  unsigned long long emitted = 0;
  if (!getenv("BASHOS_QUALIFICATION_GUEST") ||
      strcmp(getenv("BASHOS_QUALIFICATION_GUEST"), "1")) return 125;
  if (argc != 3) return 125;
  record_size = strtoul(argv[1],&end,10);
  if (*end || record_size < strlen(header)+1 || record_size > sizeof record) return 125;
  retry_errors = !strcmp(argv[2],"retry");
  inject_fatal = !strcmp(argv[2],"fatal");
  if (!retry_errors && !inject_fatal && strcmp(argv[2],"plain")) return 125;
  unsetenv("BASHDMESG_DEV_KMSG_FILE");
  memcpy(record,header,strlen(header));
  memset(record+strlen(header),'A',record_size-strlen(header)-1);
  record[record_size-1] = '\n';
  int rc = bd_drain(999,0,0,0,0,1,0,0,0,0,0,0,&emitted,0);
  fprintf(stderr,"result=%d emitted=%llu reads=%u\n",rc,emitted,reads);
  return rc;
}
