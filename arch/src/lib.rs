//! narf-arch — hardware abstraction layer.
//!
//! Spec: `arch/specification/spec.md`. Stage 1 lands the primitives needed
//! to reach a serial `write_str` from a bare boot: `halt`, `disable_interrupts`,
//! and I/O-port / MMIO access wrappers. Each wrapper carries the
//! `compiler_fence(SeqCst)` discipline from §4 to defeat fat-LTO reorders.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as current;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as current;

/// Backend selection at the type level, per `arch/` §3 `DomainPrimitive`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DomainBackend { Pks, Mte }

#[cfg(target_arch = "x86_64")]
pub const BACKEND: DomainBackend = DomainBackend::Pks;
#[cfg(target_arch = "aarch64")]
pub const BACKEND: DomainBackend = DomainBackend::Mte;

/// Spin-halt the current CPU forever. Used on panic and end-of-boot.
#[inline(always)]
pub fn halt_forever() -> ! { current::halt_forever() }

/// End the kernel run with an exit code. Under QEMU this triggers a clean
/// VM exit; on real hardware / other VMMs it falls back to `halt_forever`.
/// `code == 0` is "normal success"; non-zero is "failure" — verification
/// harnesses map these to `cargo xtask test` pass/fail.
///
/// # Safety
/// Per-arch backend may touch a platform-specific exit device; see
/// `arch::current::exit_qemu` for the x86_64 implementation and the
/// aarch64 semihosting path.
pub unsafe fn exit_kernel(code: u32) -> ! {
    // SAFETY: backend owns the platform contract.
    unsafe { current::exit_qemu(code) }
}

/// Disable interrupts on the current CPU. Stage 1 only — proper save/restore
/// typestate comes with `frame/`'s IRQ context token.
#[inline(always)]
pub unsafe fn disable_interrupts() {
    // SAFETY: arch backend upholds the compiler_fence discipline from §4.
    unsafe { current::disable_interrupts() }
}

/// Enable interrupts on the current CPU.
#[inline(always)]
pub unsafe fn enable_interrupts() {
    // SAFETY: caller must hold the equivalent capability (Stage 3); Stage 1
    // has a single domain so the check is vacuous.
    unsafe { current::enable_interrupts() }
}
