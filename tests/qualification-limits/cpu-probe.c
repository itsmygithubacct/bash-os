/* SPDX-License-Identifier: MIT */
#include <cpuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
  unsigned a,b,c,d;
  if (!getenv("BASHOS_QUALIFICATION_GUEST") ||
      strcmp(getenv("BASHOS_QUALIFICATION_GUEST"), "1")) return 125;
  if (!__get_cpuid(1,&a,&b,&c,&d)) return 125;
  unsigned sse2 = (d >> 26) & 1, avx = (c >> 28) & 1, avx2 = 0;
  if (__get_cpuid_max(0,NULL) >= 7) { __cpuid_count(7,0,a,b,c,d); avx2 = (b >> 5) & 1; }
  /* CPUID masking alone is insufficient. A disposable child must actually
   * reject this known SSE2 instruction; do not create a guest core file. */
  struct rlimit no_core = {0,0};
  if (setrlimit(RLIMIT_CORE,&no_core)) return 125;
  pid_t child = fork();
  if (child < 0) return 125;
  if (!child) {
    signal(SIGILL,SIG_DFL);
    /* pxor %xmm0,%xmm0. Bytes avoid enabling SSE2 for the control's C code. */
    __asm__ volatile (".byte 0x66,0x0f,0xef,0xc0");
    _exit(0);
  }
  int status;
  if (waitpid(child,&status,0) != child) return 125;
  unsigned rejected = WIFSIGNALED(status) && WTERMSIG(status) == SIGILL;
  if (!rejected && !(WIFEXITED(status) && WEXITSTATUS(status) == 0)) return 125;
  printf("{\"pointer_bits\":%zu,\"sse2\":%u,\"avx\":%u,\"avx2\":%u,\"sse2_sigill\":%u}\n",
         sizeof(void *)*8,sse2,avx,avx2,rejected);
  return sizeof(void *) == 4 && !sse2 && !avx && !avx2 && rejected ? 0 : 125;
}
