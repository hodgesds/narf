//! narf-security — KSPP-style hardening aggregator.
//!
//! Spec: `security-model/specification/`. This crate sits above the
//! per-arch and per-subsystem hardening modules (`arch/x86_64/smep`,
//! `arch/x86_64/smap`, `arch/x86_64/cet`, `arch/aarch64/pac`,
//! `arch/aarch64/mte`, `memory/wx`, `memory/kaslr`,
//! `memory/ro_after_init`, `frame/canary`) and provides:
//!
//!   * Pointer-redaction policy — kernel-VA pointers stripped from
//!     diagnostics unless the reader holds `Cap<KernelDebug>`.
//!   * Capability-leak detection — debug-only assert that a write-
//!     capable Cap doesn't survive an await boundary visible from a
//!     different DomainId.
//!   * Posture summary — a single struct the boot path fills in so
//!     `cat /proc/self/security` (one day) can report which knobs
//!     are live.
//!
//! Linux's `kernel-parameters.txt` lists ~40 hardening flags; users
//! don't know which ones their distro has set. NARF surfaces the
//! actual silicon-and-software combination once at boot and lets
//! everyone read it.
//!
//! This crate is `no_std` and stable: nothing here pulls in alloc
//! or arch-specific intrinsics. Per-arch enabling lives in `arch/`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod redact;
pub mod cap_leak;
pub mod posture;

mod tests;

pub use redact::{Redact, redact_pointer, kernel_va_cutoff};
pub use cap_leak::{assert_no_cap_leak, CapLeakError};
pub use posture::{Posture, PostureReport};
