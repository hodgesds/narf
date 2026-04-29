# compat/win — Win32-on-NARF

PE32+ image loader + Win32 API thunk layer. Aim: run Windows binaries
on NARF the way WINE runs them on Linux — translation in userspace,
backed by NARF caps and abi rings, never an ambient-authority shim.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 4+ (depends on `userspace/` reaching Stage 4 exit).

## Milestones

- **M0 (this branch's first deliverable):** PE32+ console exe calling
  `kernel32!{GetStdHandle, WriteConsole{A,W}, ExitProcess}`. No GUI,
  no DLLs, no filesystem.
- **M1:** Real DLL loading + `kernel32` heap (`HeapAlloc`/`VirtualAlloc`)
  + file I/O thunks against `filesystem/`.
- **M2:** GUI subsystem (`user32`/`gdi32`) backed by a not-yet-existing
  NARF compositor.
- **M3:** Direct3D / DXGI via Vulkan once `drivers/gpu` is real.
