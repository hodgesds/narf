# userspace/coreutils/echo — echo

Prints its arguments separated by single spaces, followed by a newline.
There is no flag parsing and no escape interpretation: `argv[1..]` is
joined with `' '` and written to stdout as-is.

The whole program is `src/main.rs`, a `no_std` binary that writes
through `narf-libc` (`posix_write` on fd 1, looping on short writes).
