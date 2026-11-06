# userspace/coreutils/pwd — pwd

Prints the current working directory followed by a newline, using
`getcwd(2)` through `narf-libc`, which routes to the kernel's per-task
cwd state. There are no `-P` / `-L` flags; a failed `getcwd` is reported
on stderr and exits 1.

The whole program is `src/main.rs`, a `no_std` binary.
