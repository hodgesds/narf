# userspace/shell — shell

NARF's interactive shell. It reads keystrokes from `/dev/console` one
byte at a time, prints the `narf> ` prompt, parses each line, and
dispatches the result. External commands are looked up as
`/bin/<name>` and run via fork + execve; a set of built-ins runs
in-process instead — basic commands (`help`, `echo`, `uname`, `pid`,
`pwd`, `cd`, `whoami`, `hostname`, `clear`, `date`, `env`, `getenv`,
`true`, `false`, `exit`, `:`), filesystem commands (`cat`, `ls`, `stat`,
`head`, `wc`, `mkdir`, `rmdir`, `rm`, `mv`, `touch`), process commands
(`sleep`, `kill`, `exec`), and a set of `*test` smoke commands that
exercise kernel facilities (terminal, sockets, pipes, signals, threads,
and more).

The parser (`src/parser.rs`) is a recursive-descent parser over a `Cmd`
AST in fixed-size stack storage — no heap — supporting pipelines (`|`),
redirects (`>`, `>>`, `<`), sequences (`;`), `&&` / `||`, background
(`&`), quoting, and backslash escapes. Command substitution, parameter
and tilde expansion, glob expansion, heredocs, and multi-line input are
not implemented. The execution engine (`src/exec.rs`) drives the AST,
falling back to in-process built-in dispatch when fork fails; the
dispatch table and the smoke commands live in `src/main.rs`.
