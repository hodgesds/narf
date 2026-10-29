//! Full-register SMC Calling Convention conduit — clean-room.
//!
//! Reference: **"SMC Calling Convention"** v1.5 (Arm DEN0028E), §2.6
//! (register use), §2.5 (function identifier layout).
//!
//! [`super::psci`] only needs `x0..x3`; vendor SiP services such as the
//! Qualcomm Secure Channel Manager (SCM) pass up to six arguments
//! (`x1` carries an argument-info word, `x2..x5` the values, `x6` a
//! session/quirk word) and expect `x6` back on a retried call. This module
//! is the one place the kernel issues such calls: every argument register
//! goes in, every result register comes back, and the caller-saved
//! registers SMCCC v1.0 allows the monitor to corrupt (`x8..x17`) are
//! declared clobbered.
//!
//! Memory ordering: the asm block is *not* `nomem` (the secure side reads
//! buffers the caller wrote, e.g. a PAS metadata blob) and is bracketed by
//! `compiler_fence(SeqCst)` so fat LTO cannot move buffer stores past the
//! trap (`build/` §4, `arch/` §4).

#![cfg(target_arch = "aarch64")]

use core::sync::atomic::{compiler_fence, Ordering};

/// `x0` bit 31: fast (atomic) call. Clear = yielding (standard) call.
pub const FAST_CALL: u32 = 1 << 31;
/// `x0` bit 30: SMC64/HVC64 calling convention. Clear = SMC32.
pub const SMC64: u32 = 1 << 30;
/// Owning-entity field shift (`x0` bits 29:24).
pub const OWNER_SHIFT: u32 = 24;
/// Owning entity: CPU service.
pub const OWNER_CPU: u32 = 1;
/// Owning entity: SiP (silicon-partner) service.
pub const OWNER_SIP: u32 = 2;
/// Owning entity: standard secure service (PSCI lives here).
pub const OWNER_STANDARD: u32 = 4;

/// Compose an SMCCC function identifier (DEN0028E §2.5):
/// `fast | smc64 | owner << 24 | function`.
pub const fn call_val(fast: bool, smc64: bool, owner: u32, function: u32) -> u32 {
    (if fast { FAST_CALL } else { 0 })
        | (if smc64 { SMC64 } else { 0 })
        | ((owner & 0x3f) << OWNER_SHIFT)
        | (function & 0xffff)
}

/// Issue `smc #0` with `regs[0..8]` in `x0..x7`; on return `regs` holds
/// `x0..x7` as the secure monitor left them.
///
/// # Safety
/// EL1, and the platform's firmware conduit is SMC (a secure monitor is
/// installed). The callee may read memory the caller references through
/// the argument registers; the caller keeps such buffers alive and
/// physically addressable for the duration of the call.
#[inline]
pub unsafe fn smc_call(regs: &mut [u64; 8]) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted EL1 + SMC conduit. Clobbers follow SMCCC
    // v1.0 (x8..x17 unpredictable on return); x18+ are callee-saved.
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") regs[0],
            inout("x1") regs[1],
            inout("x2") regs[2],
            inout("x3") regs[3],
            inout("x4") regs[4],
            inout("x5") regs[5],
            inout("x6") regs[6],
            inout("x7") regs[7],
            lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _,
            lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _,
            lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// [`smc_call`] through the HVC conduit, for firmware services a
/// hypervisor forwards.
///
/// # Safety
/// As [`smc_call`], with an EL2 hypervisor that implements the service.
#[inline]
pub unsafe fn hvc_call(regs: &mut [u64; 8]) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted EL1 + HVC conduit; same clobber set.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") regs[0],
            inout("x1") regs[1],
            inout("x2") regs[2],
            inout("x3") regs[3],
            inout("x4") regs[4],
            inout("x5") regs[5],
            inout("x6") regs[6],
            inout("x7") regs[7],
            lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _,
            lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _,
            lateout("x16") _, lateout("x17") _,
            options(nostack),
        );
    }
    compiler_fence(Ordering::SeqCst);
}
