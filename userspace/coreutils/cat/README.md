# userspace/coreutils/cat — cat

Concatenates files to stdout. With no arguments it copies stdin (fd 0)
to stdout; `-` as an argument also means stdin. Each named file is
opened read-only, copied through a 4 KiB buffer, and closed; a file
that cannot be opened is reported on stderr (`cat: cannot open: <path>`)
and sets the exit status to 1 without stopping the remaining files.

There are no option flags. The whole program is `src/main.rs`, a
`no_std` binary that talks to the kernel through `narf-libc`
(`posix_open` / `posix_read` / `posix_write` / `posix_close`).
