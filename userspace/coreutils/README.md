# userspace/coreutils — coreutils

NARF's small coreutils: `no_std` user binaries that provide the basic
command-line tools the shell and the interactive bring-up expect, each
talking to the kernel through `narf-libc`.

- [`cat`](./cat/README.md) — concatenate files to stdout (stdin if no files, `-` for stdin).
- [`echo`](./echo/README.md) — print arguments space-joined, plus a newline.
- [`ls`](./ls/README.md) — list directory contents, one entry per line.
- [`ps`](./ps/README.md) — report running tasks from `/proc`.
- [`pwd`](./pwd/README.md) — print the current working directory.
