//! Speculative-execution mitigations: IBRS / IBPB / STIBP / SSBD.
//!
//! Reference: **Intel SDM Vol 4 §2.16** + **AMD APM Vol 2 §3.16**
//! ("Speculation Control"). The architectural surface is shared
//! across vendors:
//!
//! | MSR    | name              | bit purpose                          |
//! |--------|-------------------|--------------------------------------|
//! | 0x48   | IA32_SPEC_CTRL    | bit 0 = IBRS, 1 = STIBP, 2 = SSBD    |
//! | 0x49   | IA32_PRED_CMD     | write 1 to bit 0 = IBPB              |
//! | 0x10B  | IA32_FLUSH_CMD    | write 1 to bit 0 = L1D_FLUSH         |
//!
//! ## CPUID gates (SDM Vol 2A "CPUID instruction" + SDM Vol 4 §2.16):
//!
//! - CPUID(7, 0).EDX[26] = IBRS / IBPB supported.
//! - CPUID(7, 0).EDX[27] = STIBP supported.
//! - CPUID(7, 0).EDX[31] = SSBD supported.
//! - CPUID(7, 0).EDX[28] = L1D_FLUSH supported.
//!
//! Stage cut: feature detection + per-CPU enable for IBRS+STIBP+SSBD,
//! plus `ibpb()` and `l1d_flush()` standalone barriers. The latter
//! two are issued at context-switch points and on entry to a
//! sensitive critical section by the caller.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr_or_gp};

pub const MSR_IA32_SPEC_CTRL: u32 = 0x48;
pub const MSR_IA32_PRED_CMD: u32 = 0x49;
pub const MSR_IA32_FLUSH_CMD: u32 = 0x10B;

pub const SPEC_CTRL_IBRS: u64 = 1 << 0;
pub const SPEC_CTRL_STIBP: u64 = 1 << 1;
pub const SPEC_CTRL_SSBD: u64 = 1 << 2;

pub const PRED_CMD_IBPB: u64 = 1 << 0;
pub const FLUSH_CMD_L1D: u64 = 1 << 0;

/// Bit-flag snapshot of available speculation-control features.
#[derive(Copy, Clone, Debug, Default)]
pub struct SpecCtrlFeatures {
    pub ibrs: bool,
    pub stibp: bool,
    pub ssbd: bool,
    pub l1d_flush: bool,
}

impl SpecCtrlFeatures {
    /// Probe via CPUID.
    pub fn probe() -> Self {
        // SAFETY: leaf 7 is always defined.
        let (_, _, _, edx) = unsafe { cpuid(7, 0) };
        Self {
            ibrs: edx & (1 << 26) != 0,
            stibp: edx & (1 << 27) != 0,
            ssbd: edx & (1 << 31) != 0,
            l1d_flush: edx & (1 << 28) != 0,
        }
    }
}

static FEATURES_RAW: AtomicU8 = AtomicU8::new(0xFF);

/// Cached features. Probes on first call.
pub fn features() -> SpecCtrlFeatures {
    let cached = FEATURES_RAW.load(Ordering::Acquire);
    if cached != 0xFF {
        return SpecCtrlFeatures {
            ibrs: cached & 1 != 0,
            stibp: cached & 2 != 0,
            ssbd: cached & 4 != 0,
            l1d_flush: cached & 8 != 0,
        };
    }
    let f = SpecCtrlFeatures::probe();
    let bits = (f.ibrs as u8)
        | ((f.stibp as u8) << 1)
        | ((f.ssbd as u8) << 2)
        | ((f.l1d_flush as u8) << 3);
    FEATURES_RAW.store(bits, Ordering::Release);
    f
}

/// Read `IA32_SPEC_CTRL`. Returns 0 if the MSR isn't available.
///
/// # Safety
/// CPL = 0.
pub unsafe fn read() -> u64 {
    if !features().ibrs && !features().stibp && !features().ssbd {
        return 0;
    }
    // SAFETY: caller-asserted CPL=0; CPUID gate satisfied.
    unsafe { rdmsr(MSR_IA32_SPEC_CTRL) }
}

/// Set `IA32_SPEC_CTRL`. No-ops on hosts that don't support any
/// of the SPEC_CTRL bits.
///
/// # Safety
/// CPL = 0.
pub unsafe fn write(bits: u64) {
    if !features().ibrs && !features().stibp && !features().ssbd {
        return;
    }
    // wrmsr_or_gp: some AMD parts report the IBRS CPUID bit
    // but ship a microcode that rejects writes (paper-spec
    // bit, no microarchitectural backing). Treat as best-
    // effort — failure means the mitigation isn't actually in
    // effect, which the boot-time spec_ctrl status surface
    // already reflects via the IBRS-active probe.
    let _ = wrmsr_or_gp(MSR_IA32_SPEC_CTRL, bits);
}

/// Enable IBRS + STIBP + SSBD on this CPU (best-effort; only the
/// subset reported by `features()` is set).
///
/// # Safety
/// CPL = 0.
pub unsafe fn enable_default_mitigations() {
    let f = features();
    let mut bits = 0u64;
    if f.ibrs {
        bits |= SPEC_CTRL_IBRS;
    }
    if f.stibp {
        bits |= SPEC_CTRL_STIBP;
    }
    if f.ssbd {
        bits |= SPEC_CTRL_SSBD;
    }
    if bits != 0 {
        // SAFETY: caller-asserted.
        unsafe {
            write(bits);
        }
    }
}

/// Indirect-branch predictor barrier. Used at security
/// boundaries (e.g. entering an isolated process / driver
/// domain) to flush BTB poisoning.
///
/// No-op when CPUID doesn't advertise IBPB.
///
/// # Safety
/// CPL = 0.
pub unsafe fn ibpb() {
    if !features().ibrs {
        return;
    } // IBPB shares the IBRS CPUID bit.
      // wrmsr_or_gp: IBPB on some AMD parts is microcode-gated
      // even when CPUID advertises it. Failure means no barrier
      // is issued — best-effort.
    let _ = wrmsr_or_gp(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);
}

/// L1 data-cache flush. Used pre-VMENTER on hyperthreaded hosts
/// to mitigate L1TF.
///
/// # Safety
/// CPL = 0.
pub unsafe fn l1d_flush() {
    if !features().l1d_flush {
        return;
    }
    // wrmsr_or_gp: feature is microcode-gated even when
    // CPUID(7,0).EDX[28] is set — best-effort.
    let _ = wrmsr_or_gp(MSR_IA32_FLUSH_CMD, FLUSH_CMD_L1D);
}

#[doc(hidden)]
pub fn __reset_for_test() {
    FEATURES_RAW.store(0xFF, Ordering::Release);
}
