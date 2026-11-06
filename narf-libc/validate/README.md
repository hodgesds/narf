# narf-libc/validate — Smoke binary for narf-libc

`narf-libc-validate` is a `no_std`, `no_main` binary that links against
`narf-libc` and exercises it from user mode. The ELF entry point is
narf-libc's `_start` (via `ENTRY(_start)` in `validate.ld`), which bridges
through `__libc_start_main` into this binary's C-shaped `main`. The linker
script places a 16-byte TLS template (the errno slot) in `.tdata` for the
kernel's PT_TLS staging.

`main` prints a `hello from narf-libc; pid=<n>` line, then runs a probe
battery across the libc surface, printing an `ok`/`bad` line per probe: the
printf-shim's format-spec branches (width, precision, flags, `o`/`b`
conversions), the `FILE*` layer over fd 1 (`fputs`/`fwrite`/`fflush` on the
static stdout stream), string/stdlib parsing, the heap freelist (including
free-list reuse), fd/pipe/fcntl, time/math, sockets/poll/epoll, pthread,
regex, locale, `mmap`/`uname`/`sysinfo`/`dlopen`, System V IPC, and the
C-ABI file/process/memory/signal/socket/time/string/stdio/env entry points.
It returns 0; an `atexit` handler prints `atexit: ok` on the way out.

How it runs: the kernel-side test `smoke_frame_x86_64_run_narf_libc_validate`
(`verification/src/lib.rs`, x86_64 only, behind the `narf-libc-validate`
feature) loads the ELF as a user process and runs it outside the scheduler.
The pass signal is the runner's `validate round-trip succeeded` line; the
harness does not capture user stdout for grepping, so the expected probe
lines are noted in the runner for log inspection.
