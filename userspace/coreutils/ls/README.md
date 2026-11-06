# userspace/coreutils/ls — ls

Lists directory contents, one entry per line. With no arguments it
lists `.`; each argument is listed in turn. Entries are printed in the
kernel's enumeration order — there is no sorting.

The whole program is `src/main.rs`, a `no_std` binary built on
`narf-libc`'s `opendir` / `readdir` / `closedir`, which back onto the
`listdir` syscall. A directory that cannot be opened is reported on
stderr and sets the exit status to 1.
