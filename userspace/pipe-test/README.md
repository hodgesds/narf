# userspace/pipe-test — pipe-test

A test binary, not a user tool: the same raw-syscall assertions run on
host Linux and in NARF user mode, exercising the pipe and file-descriptor
ABI. It issues Linux syscall numbers directly (per-arch tables in the
`nr` module for x86_64 and aarch64) and checks creation, scalar and
vector I/O, capacity and lifetime, packets, full-pipe and atomicity
behaviour, page buffers, file pages and faults, pinned pages, readiness,
transfer errors, transfers, `vmsplice`, SIGPIPE, FIFOs, blocking
readers and writers, wake chains, signals and restart, pinning across
fork, and descriptor exhaustion.

Each case prints `pipe-abi RUN <name>` then `pipe-abi OK <name>`, ending
with `pipe-abi: all passed`; on NARF it also writes a pass marker to a
kernel-supplied result page. The whole program is `src/main.rs`.
