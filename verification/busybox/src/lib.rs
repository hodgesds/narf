//! BusyBox demo binary, baked at build time.
//!
//! `build.rs` downloads the upstream busybox source, builds it
//! static-against-musl at NARF's PML4[1] user vaddr
//! (`-Wl,-Ttext-segment=0x8000001000`), and exports the resulting
//! ELF path via `NARF_BUSYBOX_*` env vars. `include_bytes!`
//! materialises those into `pub const` slices.
//!
//! When `musl-gcc` is absent on the host (so the build can't run)
//! the env vars fall back to `/dev/null` — the resulting slice is
//! empty and the kernel-side consumer
//! (`frame/src/bare_main.rs::MemFs::with_seeds`) skips seeding
//! `/bin/busybox`.
//!
//! ## Status
//!
//! Working applets:
//! * `busybox echo …` — uses raw `write(1, …)` syscall, no stdio
//! * `busybox true` — exit_group(0); never touches stdio
//!
//! Failing applets (stdio-bound: `pwd`, `uname`, `cat`, `ls`, …):
//! After the applet calls `ioctl(1, TIOCGWINSZ, …)` musl jumps
//! into `__overflow(FILE *f)` (`/lib/ld-musl-x86_64.so.1` symbol
//! offset `0x62b40`). The very first instruction past the prologue
//! (`mov 0x28(%rdi), %rax`) #PFs because RDI holds only the LOW
//! 32 bits of the real `FILE *stdout` pointer:
//!
//! ```text
//!   trap: vec=14 addr=0x1e7848 task=16
//!   #PF user: cr2=0x1e7848 rip=0x400000062d9a err=5
//! ```
//!
//! `cr2 ≈ 0x1e7848 == (FILE*stdout_real & 0xFFFFFFFF)`. The real
//! `stdout` lives in libc.so loaded above NARF's PML4[1] base
//! (`0x80_xxxx_xxxx_xxxx`); somewhere between
//! `R_X86_64_GLOB_DAT(stdout)` and busybox's call into `__overflow`,
//! the upper 32 bits get dropped.
//!
//! Things that have been ruled out:
//! * Busybox itself is built `CONFIG_PIE=y` + `-mcmodel=large` so
//!   every `mov` against its own statics is RIP-relative.
//! * The kernel's `apply_relocations` (`userspace/src/loader.rs`)
//!   does 64-bit `wrapping_add` end-to-end; no truncation in our
//!   reloc pass.
//! * AT_PHDR / AT_BASE / AT_ENTRY in `userspace/src/process.rs`
//!   are all built with 64-bit `wrapping_*`; no `as u32` casts in
//!   the auxv path.
//! * `sys_mmap` returns the full 64-bit `base` (verified with a
//!   temporary tracer: ld-musl received 0x408000…XX for libc.so).
//!
//! The remaining suspect is ld-musl's own reloc writer applied
//! against busybox's GOT — likely the GOT slot is being patched
//! with a 32-bit value because Arch's stock `ld-musl-x86_64.so.1`
//! itself was built `-mcmodel=small`. A custom-built large-model
//! musl would be the next thing to try.

#![no_std]

#[cfg(target_arch = "x86_64")]
pub const NARF_BUSYBOX: &[u8] = include_bytes!(env!("NARF_BUSYBOX_X86_64"));

#[cfg(target_arch = "aarch64")]
pub const NARF_BUSYBOX: &[u8] = include_bytes!(env!("NARF_BUSYBOX_AARCH64"));
