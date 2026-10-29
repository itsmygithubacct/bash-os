# Watch interactive error evidence

For the interactive `-e` case, both builds reach the watch builtin and execute a command that exits 7, then exit 1 before showing the error prompt. The procps reference displays the message, waits for input and exits 8 after a key. These observations record failures; candidate key handling and its post-key exit are not observed.

The observations use ptrace and breakpoints, which may affect timing. The diagnostic run retains its incomplete classification. Existing nonterminal error evidence and resize observations remain part of the reviewed requirements. Migration records evidence coverage; it does not change a failure into a pass.
