# userspace — Research

## Primary sources

- **relibc** — Redox's C library; our integration target.
  <https://gitlab.redox-os.org/redox-os/relibc>
- **ELF specification** (ABI supplements per arch — System V ABI for
  x86_64, AArch64 ELF ABI).
  <https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html>
  <https://github.com/ARM-software/abi-aa>

## Secondary sources

- **Fuchsia `starnix`** — Linux-syscall compat layer for a non-Linux
  kernel; reference for how to bolt POSIX onto something foreign.
  <https://fuchsia.dev/fuchsia-src/concepts/components/v2/starnix>
- **musl libc source** — for POSIX semantics reference.
- **Redox `relibc` + kernel interface** — closest in spirit to what NARF wants.
- **Shiva — Programmable Runtime Linker (elfmaster/shiva)** — concrete
  precedent for a custom `PT_INTERP` that installs process state beyond
  what glibc's `ld.so` does. NARF's interpreter can use the same shape
  to set up Narf-Rings, the per-task cap table, and domain bindings
  before `main`. <https://github.com/elfmaster/shiva>

## Distilled summaries

- (Defer until Stage 4 begins.)

## Fetched this round

### 2026-04-22
- No new summaries (Stage 4 deferral applies)

## Open research questions

- How far can we get with spawn-only (no fork) before POSIX compat breaks?
- Thread-local storage model under both archs with a capability-scoped process.
- Signals — do we support them at all, or use cap-based equivalents?
