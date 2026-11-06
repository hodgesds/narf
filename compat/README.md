# compat — compatibility layers

Compatibility shims that let programs written for other systems run on
NARF's native userspace ABI, each with its own README.

- [`linux-perf-uapi`](./linux-perf-uapi/README.md) — `no_std` Rust representation of the Linux `perf_event_open(2)` wire ABI for NARF's userspace compatibility layer.
- [`relibc`](./relibc/README.md) — packaging shim letting binaries built against Redox's relibc link unchanged on NARF; it does not reimplement relibc.
- [`win`](./win/README.md) — PE32+ image loader + Win32 API thunk layer; aims to run Windows binaries the way WINE runs them on Linux.
- [`win-rt`](./win-rt/README.md) — the userspace half of the Win32 layer: the `kernel32` / `user32` / `ntdll`-shaped thunks that unmodified Windows PE binaries call.
