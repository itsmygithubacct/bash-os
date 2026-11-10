# sshd

`sshd run -F FILE` reads a subset of an OpenSSH server configuration. `help
sshd` lists the directives this builtin accepts. A directive it does not
accept is an error, and the server does not start.

## Subsystem

SFTP is not implicit. A client subsystem request is accepted only when a
`Subsystem` line names it:

```
Subsystem sftp internal-sftp
Subsystem sftp /usr/lib/openssh/sftp-server
```

`internal-sftp` is this build's SFTP server. Any other command is executed
directly, with the channel on its standard input, output and error, as the
authenticated user. The user's shell does not wrap that command. A request
whose name has no `Subsystem` line is refused. `Subsystem` is global; a
`Match` block cannot set it. Repeating a name replaces that name's command.
