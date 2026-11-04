`utf8 length-fd FD` counts grapheme clusters from a readable file descriptor.
`utf8 slice-fd FD START END` writes the selected clusters as raw bytes, including
embedded NUL, without adding a newline. Indices are zero-based and the end is
exclusive. Indices beyond the input clamp to its end.

```bash
printf 'a\0b' | utf8 length-fd 0
# 3
printf 'a\0b' | utf8 slice-fd 0 1 2 | od -An -tx1
# 00
```

Both verbs consume input through EOF and leave the descriptor open at its new
position. Input is limited to 16 MiB; detecting an oversized stream consumes at
most one additional byte. A read error, including a nonblocking read returning
EAGAIN, fails without emitting a partial result. Allocation, read, or output
errors return 1. Invalid descriptor/range syntax and unsupported arguments return
2. A producer that never reaches EOF can keep the command waiting.

The descriptor verbs operate on grapheme clusters. They do not accept `-T`, `-L`
or `-V`. Send binary slices to a file or pipe; Bash variables cannot preserve
embedded NUL. The existing `length TEXT` and `slice TEXT` interfaces retain their
text argument and output conventions.
