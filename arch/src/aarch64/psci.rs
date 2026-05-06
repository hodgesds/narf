//! PSCI (Power State Coordination Interface) — clean-room.
//!
//! References:
//! - **"Arm Power State Coordination Interface (PSCI)"** v1.2
//!   (free PDF, developer.arm.com — DEN0022D).
//! - **"SMC Calling Convention"** v1.5 (DEN0028E).
//!
//! PSCI is the standard SMC-based interface for waking secondary
//! CPUs, suspending the system, and powering the platform off /
//! resetting it. Every QEMU `virt` board exposes it via the SMC
//! conduit; on real silicon (Apple, NXP, Rockchip) the conduit is
//! firmware-defined and may be HVC, but the function-id surface is
//! identical.
//!
//! ## Function IDs (PSCI 1.0+ §5.2)
//!
//! | id           | name                      |
//! |--------------|---------------------------|
//! | 0x8400_0000  | PSCI_VERSION              |
//! | 0x8400_0001  | CPU_SUSPEND (32-bit)      |
//! | 0x8400_0002  | CPU_OFF                   |
//! | 0x8400_0003  | CPU_ON (32-bit)           |
//! | 0x8400_0008  | SYSTEM_OFF                |
//! | 0x8400_0009  | SYSTEM_RESET              |
//! | 0xC400_0001  | CPU_SUSPEND (64-bit)      |
//! | 0xC400_0003  | CPU_ON (64-bit)           |
//!
//! Stage cut: PSCI_VERSION + CPU_OFF + SYSTEM_OFF + SYSTEM_RESET.
//! CPU_ON / CPU_SUSPEND land when SMP bring-up is wired.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

/// PSCI function ids.
pub const PSCI_VERSION: u32 = 0x8400_0000;
pub const PSCI_CPU_OFF: u32 = 0x8400_0002;
pub const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
pub const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;

/// PSCI return codes (§5.2.2 Table 5).
pub const PSCI_SUCCESS: i32 = 0;
pub const PSCI_NOT_SUPPORTED: i32 = -1;
pub const PSCI_INVALID_PARAMS: i32 = -2;
pub const PSCI_DENIED: i32 = -3;
pub const PSCI_ALREADY_ON: i32 = -4;
pub const PSCI_ON_PENDING: i32 = -5;
pub const PSCI_INTERNAL_FAIL: i32 = -6;
pub const PSCI_NOT_PRESENT: i32 = -7;
pub const PSCI_DISABLED: i32 = -8;

/// Issue an SMC32 call per SMCCC §5. Returns the four 32-bit
/// result registers (X0..X3 truncated).
///
/// # Safety
/// CPL = 0 (EL1). Issuing SMCs has well-defined semantics on
/// every supported board.
#[inline]
pub unsafe fn smc(fn_id: u32, arg1: u64, arg2: u64, arg3: u64) -> [u64; 4] {
    let mut x0 = fn_id as u64;
    let mut x1 = arg1;
    let mut x2 = arg2;
    let mut x3 = arg3;
    // SAFETY: caller-asserted EL1; SMC conduit per SMCCC.
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") x0,
            inout("x1") x1,
            inout("x2") x2,
            inout("x3") x3,
            options(nomem, nostack),
        );
    }
    [x0, x1, x2, x3]
}

/// Issue an HVC call per SMCCC §5. Used by hypervisors that route
/// firmware calls via HVC instead of SMC. NARF defaults to SMC
/// (the QEMU virt + most real boards), but the helper is here so
/// alternate-conduit boards can opt in by calling `hvc` directly.
///
/// # Safety
/// EL1; HVC traps to EL2 (must be a valid hypervisor entrypoint
/// or fault).
#[inline]
pub unsafe fn hvc(fn_id: u32, arg1: u64, arg2: u64, arg3: u64) -> [u64; 4] {
    let mut x0 = fn_id as u64;
    let mut x1 = arg1;
    let mut x2 = arg2;
    let mut x3 = arg3;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") x0,
            inout("x1") x1,
            inout("x2") x2,
            inout("x3") x3,
            options(nomem, nostack),
        );
    }
    [x0, x1, x2, x3]
}

/// SMC conduit selector. QEMU virt + most ARM hypervisors route
/// PSCI through HVC; bare-metal silicon with a secure monitor uses
/// SMC. NARF defaults to HVC (matches QEMU virt + KVM-hosted
/// guests); a board boot path can call [`set_conduit`] to switch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Conduit {
    Hvc,
    Smc,
}

use core::sync::atomic::{AtomicU8, Ordering};

static CONDUIT: AtomicU8 = AtomicU8::new(0); // 0 = HVC, 1 = SMC.

/// Override the PSCI call conduit. `Hvc` (the default) suits QEMU
/// virt, KVM, Xen, Hyper-V; `Smc` suits bare-metal with a secure
/// monitor.
pub fn set_conduit(c: Conduit) {
    CONDUIT.store(
        match c {
            Conduit::Hvc => 0,
            Conduit::Smc => 1,
        },
        Ordering::Release,
    );
}

#[inline]
fn dispatch(fn_id: u32, a1: u64, a2: u64, a3: u64) -> [u64; 4] {
    // SAFETY: caller-asserted EL1 with valid conduit set up by
    // platform firmware / hypervisor.
    match CONDUIT.load(Ordering::Acquire) {
        1 => unsafe { smc(fn_id, a1, a2, a3) },
        _ => unsafe { hvc(fn_id, a1, a2, a3) },
    }
}

/// PSCI version: returns `(major, minor)` per §5.2.4.
pub fn version() -> (u16, u16) {
    let r = dispatch(PSCI_VERSION, 0, 0, 0);
    let v = r[0] as u32;
    ((v >> 16) as u16, (v & 0xFFFF) as u16)
}

/// Power off the system (gracefully shut down). Does not return on
/// success.
pub fn system_off() -> i32 {
    let r = dispatch(PSCI_SYSTEM_OFF, 0, 0, 0);
    r[0] as i32
}

/// Reset the system.
pub fn system_reset() -> i32 {
    let r = dispatch(PSCI_SYSTEM_RESET, 0, 0, 0);
    r[0] as i32
}

/// Power off the calling CPU. Returns only on failure.
pub fn cpu_off() -> i32 {
    let r = dispatch(PSCI_CPU_OFF, 0, 0, 0);
    r[0] as i32
}

/// `true` iff PSCI is implemented (PSCI_VERSION returns a sane
/// non-zero value).
pub fn is_present() -> bool {
    let (major, minor) = version();
    !(major == 0 && minor == 0)
}
