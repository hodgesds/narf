//! Intel UINTR — User Interrupts.
//!
//! Spec: `arch/specification/cpu-security.md` §5.
//!
//! UINTR provides a fast user-to-user IPI surface. The OS
//! installs a per-task User Posted-Interrupt Descriptor (UPID)
//! plus a UINTR handler; sender-side `senduipi` writes the
//! receiver's UPID. The receiving thread's UIF bit gates
//! delivery, controlled by `clui` / `stui` / `testui` user-mode
//! instructions. UIRET returns from a user-IRQ handler.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_UINTR_RR:           u32 = 0x985;
pub const MSR_IA32_UINTR_HANDLER:      u32 = 0x986;
pub const MSR_IA32_UINTR_STACKADJUST:  u32 = 0x987;
pub const MSR_IA32_UINTR_MISC:         u32 = 0x988;
pub const MSR_IA32_UINTR_PD:           u32 = 0x989;
pub const MSR_IA32_UINTR_TT:           u32 = 0x98A;

/// `true` iff CPUID(7, 0).EDX[5] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return false; }
    // SAFETY: leaf 7 valid.
    let (_, _, _, edx) = unsafe { cpuid(7, 0) };
    edx & (1 << 5) != 0
}

/// Install the user-interrupt handler entry point (`IA32_UINTR_HANDLER`).
///
/// # Safety
/// CPL = 0; UINTR supported; `handler_va` is a canonical user VA
/// the receiving task expects to enter on UI delivery.
pub unsafe fn install_handler(handler_va: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_UINTR_HANDLER, handler_va); }
}

/// Install the User Posted-Interrupt Descriptor table phys.
///
/// # Safety
/// CPL = 0; UINTR supported; `pd_phys` is 64-byte aligned and
/// points to a valid UPID.
pub unsafe fn install_pd(pd_phys: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_UINTR_PD, pd_phys); }
}

/// Install the user-IRQ stack adjustment.
///
/// # Safety
/// CPL = 0; UINTR supported.
pub unsafe fn install_stack_adjust(value: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_UINTR_STACKADJUST, value); }
}

/// Read `IA32_UINTR_MISC`. Bit 31 = "user-IRQ pending" hint;
/// other bits are model-specific.
///
/// # Safety
/// CPL = 0; UINTR supported.
pub unsafe fn read_misc() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_UINTR_MISC) }
}

/// Write `IA32_UINTR_MISC`.
///
/// # Safety
/// CPL = 0; UINTR supported.
pub unsafe fn write_misc(v: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_UINTR_MISC, v); }
}

/// Send a user-IPI to the UPID at index `upid_index`. Userspace
/// can call this directly (the instruction is CPL-3-legal); we
/// expose the wrapper for kernel testing.
///
/// # Safety
/// UINTR is enabled in this thread's UPID context. `upid_index`
/// is within the receiver's UPID table.
pub unsafe fn senduipi(upid_index: u32) {
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "senduipi {idx}",
            idx = in(reg) upid_index as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// `clui` — clear UIF (mask user IRQs).
///
/// # Safety
/// UINTR-aware thread context.
pub unsafe fn clui() {
    // SAFETY: caller-asserted.
    unsafe { core::arch::asm!("clui", options(nostack, preserves_flags)); }
}

/// `stui` — set UIF.
///
/// # Safety
/// Same as `clui`.
pub unsafe fn stui() {
    // SAFETY: caller-asserted.
    unsafe { core::arch::asm!("stui", options(nostack, preserves_flags)); }
}

/// `testui` — read UIF into CF.
///
/// # Safety
/// UINTR supported.
pub unsafe fn testui() -> bool {
    let cf: u8;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "testui",
            "setc {f}",
            f = out(reg_byte) cf,
            options(nostack, preserves_flags),
        );
    }
    cf != 0
}
