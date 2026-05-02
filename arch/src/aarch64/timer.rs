//! aarch64 Generic Timer calibration.
//!
//! Reference: **Arm Architecture Reference Manual for A-profile**,
//! "AArch64 Generic Timer" chapter. The architectural counter is
//! `CNTPCT_EL0`; its frequency is in the `CNTFRQ_EL0` register.
//!
//! Stage cut: read `CNTFRQ_EL0` once + cache. Replaces the 1 GHz
//! placeholder in `narf-time::wall`.

#![cfg(target_arch = "aarch64")]

use core::sync::atomic::{AtomicU64, Ordering};

/// Cached architectural timer frequency in Hz. 0 = uncalibrated.
static FREQ_HZ: AtomicU64 = AtomicU64::new(0);

/// Read `CNTFRQ_EL0`.
///
/// # Safety
/// `CNTFRQ_EL0` is readable from EL0 + EL1 unconditionally per
/// the Arm ARM. Marked unsafe only for the inline-asm boundary.
#[inline]
pub unsafe fn read_cntfrq() -> u32 {
    let v: u64;
    // SAFETY: CNTFRQ_EL0 is architecturally always readable.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack));
    }
    v as u32
}

/// Read `CNTPCT_EL0` (physical count).
///
/// # Safety
/// Architecturally always legal at EL1.
#[inline]
pub fn read_cntpct() -> u64 {
    let v: u64;
    // SAFETY: CNTPCT_EL0 is architecturally readable at EL1.
    unsafe {
        core::arch::asm!(
            "isb",
            "mrs {}, cntpct_el0",
            out(reg) v,
            options(nomem, nostack),
        );
    }
    v
}

/// Calibrate the timer frequency. Caches the result for
/// subsequent calls.
pub fn calibrate() -> u64 {
    let cur = FREQ_HZ.load(Ordering::Acquire);
    if cur != 0 { return cur; }
    // SAFETY: read of CNTFRQ_EL0 always legal.
    let hz = unsafe { read_cntfrq() } as u64;
    if hz != 0 {
        FREQ_HZ.store(hz, Ordering::Release);
    }
    hz
}

/// Cached frequency. 0 if uncalibrated.
pub fn frequency_hz() -> u64 { FREQ_HZ.load(Ordering::Acquire) }

/// Convert ticks → ns. 0 if uncalibrated.
pub fn ticks_to_nanos(ticks: u64) -> u64 {
    let hz = frequency_hz();
    if hz == 0 { return 0; }
    ((ticks as u128) * 1_000_000_000 / hz as u128) as u64
}

#[doc(hidden)]
pub fn __reset_for_test() { FREQ_HZ.store(0, Ordering::Release); }
