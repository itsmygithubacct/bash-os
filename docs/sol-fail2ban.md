# fail2ban ban state and server client

`fail2ban` keeps the read-only helpers `selftest`, `parse-command`,
`validate-ip`, `validate-jail`, and `format-status`. format-status never
mutates the db. Token rules are unchanged: IPv4 is four groups of one to
three digits, IPv6 is hex and colons with at least one colon, and a jail is
one to 64 characters from `[A-Za-z0-9_.-]`. A false validator returns 1.
Usage and an invalid ban token return 2.

`banip DB JAIL IP` runs `fw deny IP` and then appends one
`<ip>\t<jail>\t<epoch>` row. `unbanip DB JAIL IP` runs `fw unban IP` and then
deletes only rows with that ip and jail. Other lines stay, in order. An
invalid ip or jail prints an `invalid` diagnostic and returns 2 before any
database or `fw` call. Epoch is `time(2)` in decimal seconds.

`fail2ban -s SOCKET status` and `fail2ban -s SOCKET reload` connect to that
Unix stream socket, send `status\n` or `reload\n`, shut down the write side,
and copy the reply to stdout with no extra bytes. `reload` then runs
`fw restore` to re-apply the saved ruleset. `status` returns after the reply.
`-s` precedes the command. The socket path is the `-s` operand.

`fw` is resolved from `PATH` and exec'd by absolute path. It is the only
firewall program this builtin starts. Its stdout and stderr are discarded.
A missing `fw`, or a non-zero `fw` status, fails the ban, unban, or reload
and leaves an existing database unchanged.
