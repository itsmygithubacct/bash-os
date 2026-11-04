Applications can register terminal-specific escape sequences in the current
shell with `wgetch define-key NAME CODE SEQUENCE`, and remove them with
`wgetch undefine-key NAME`.

```bash
wgetch define-key vendor_short 1792 $'\e[9'
wgetch define-key vendor_long 1793 $'\e[9~'
wgetch read 0
```

An exact sequence that also prefixes a longer registered key waits for the next
byte using the existing 50 ms inter-byte slice. Silence returns the short key;
a timely valid continuation returns the longer key. The initial ESC grace and
total sequence cap retain their existing behavior.

There are at most 32 custom keys. Names contain 1–31 ASCII letters, digits or
underscores; codes are 1024–65535. Sequences contain 2–63 bytes and begin with ESC.
Names, codes and complete sequences must be unique. Built-in mappings and the
names `none`, `esc`, `char`, `backspace`, `enter` and `tab` cannot be replaced.
Invalid or duplicate definitions return 2; a full table returns 1.

Definitions apply to all screen contexts in that shell. Define keys in the shell
that will read them, since definitions made in a subshell do not update its
parent. Removing an unknown custom key returns 1. Removing a mapping preserves
already queued numeric codes; codes without a current name are printed as `char`.
