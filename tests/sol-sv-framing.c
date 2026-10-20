/* SPDX-License-Identifier: MIT */
/* Exercise the production framing function without child/poll scheduling.
   Unused loadable entrypoints are discarded by --gc-sections at link time. */
#ifndef SV_SOURCE
#define SV_SOURCE "../loadables/sv.c"
#endif
#include SV_SOURCE

int main (int argc, char **argv)
{
  char buf[16384];
  int start = 1;
  if (argc != 4) return 2;
  int in = open (argv[1], O_RDONLY);
  int out = open (argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (in < 0 || out < 0) return 3;
  while (1)
    {
      ssize_t n = read (in, buf, sizeof buf);
      if (n < 0) return 4;
      if (!n) break;
      if (strcmp (argv[3], "frame") == 0)
        bsv_write_timestamped_chunk (out, buf, n, &start);
      else
        {
          ssize_t offset = 0;
          while (offset < n)
            {
              ssize_t w = write (out, buf + offset, (size_t) (n - offset));
              if (w < 0 && errno == EINTR) continue;
              if (w <= 0) return 5;
              offset += w;
            }
        }
    }
  if (close (out) != 0) return 6;
  close (in);
  return 0;
}
