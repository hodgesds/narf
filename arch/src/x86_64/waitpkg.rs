//! WAITPKG — `UMONITOR` / `UMWAIT` / `TPAUSE`.
//!
//! Spec: `arch/specification/modern-cpu.md` §3.
//!
//! WAITPKG provides short user-or-kernel waits that can park
//! the core in a low-power state without raising CPL or trapping
//! to a VMM. Useful in lock-acquisition loops + idle paths.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_UMWAIT_CONTROL: u32 = 0x00E1;

/// `true` iff CPUID(7, 0).ECX[5] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return false; }
    // SAFETY: leaf 7 valid.
    let (_, _, ecx, _) = unsafe { cpuid(7, 0) };
    ecx & (1 << 5) != 0
}

/// Configure the maximum-wait deadline + C0.2 enable. `ticks` is
/// truncated to the architectural 30-bit limit; `0` means "no
/// upper limit". `allow_c02 = false` forbids the deeper C0.2
/// state — leaves C0.1 only.
///
/// # Safety
/// CPL = 0.
pub unsafe fn set_max_wait_tsc(ticks: u32, allow_c02: bool) {
    let v = ((ticks as u64) << 2 & 0xFFFF_FFFC)
          | (if allow_c02 { 0 } else { 1 });
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_UMWAIT_CONTROL, v); }
}

/// Read `IA32_UMWAIT_CONTROL`.
///
/// # Safety
/// CPL = 0.
pub unsafe fn read_control() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_UMWAIT_CONTROL) }
}

/// Arm a UMONITOR on `addr`. The next UMWAIT/TPAUSE on this CPU
/// will wake when `addr` is written. No fault on unmapped/zero
/// — the MONITOR just doesn't arm.
///
/// # Safety
/// `addr` is a valid linear address that the caller can read.
pub unsafe fn umonitor(addr: *const u8) {
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "umonitor {a}",
            a = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
}

/// Wait until either the armed monitor fires or `deadline_tsc`
/// is reached. `optimised = true` selects C0.2 (deeper, longer
/// wakeup); `false` selects C0.1.
///
/// Returns `true` if the monitor fired before the deadline,
/// `false` on timeout.
///
/// # Safety
/// `umonitor` was called recently. CPL = 0 or 3 (instruction
/// is legal at any CPL).
pub unsafe fn umwait(deadline_tsc: u64, optimised: bool) -> bool {
    let lo = deadline_tsc as u32;
    let hi = (deadline_tsc >> 32) as u32;
    let mode: u32 = if optimised { 0 } else { 1 };
    let cf: u8;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "umwait {m:e}",
            "setc {f}",
            m  = in(reg) mode,
            f  = out(reg_byte) cf,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    cf == 0  // CF = 0 → monitor fired; CF = 1 → timeout.
}

/// Pause for up to `deadline_tsc` without arming a monitor.
/// Same return semantics as `umwait`.
///
/// # Safety
/// CPL = 0 or 3.
pub unsafe fn tpause(deadline_tsc: u64, optimised: bool) -> bool {
    let lo = deadline_tsc as u32;
    let hi = (deadline_tsc >> 32) as u32;
    let mode: u32 = if optimised { 0 } else { 1 };
    let cf: u8;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "tpause {m:e}",
            "setc {f}",
            m  = in(reg) mode,
            f  = out(reg_byte) cf,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    cf == 0
}
