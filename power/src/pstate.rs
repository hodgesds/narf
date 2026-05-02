//! P-state driver — Intel HWP / SpeedStep + AMD legacy P-states.
//!
//! Spec: `power/specification/cpu-power.md` §1. Detection is
//! priority-ordered: HWP wins on Skylake+ (CPUID(6).EAX[7]),
//! SpeedStep on older Intel (CPUID(1).ECX[7] = EIST), AMD
//! legacy on AMD Family 10h+ (CPUID(0x8000_0007).EDX[7] = HwPstate).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU8, Ordering};

use narf_arch::x86_64::cpuid::cpuid;
use narf_arch::x86_64::msr::{rdmsr, wrmsr};

// ── MSR map ────────────────────────────────────────────────────────

pub const MSR_IA32_PERF_STATUS:  u32 = 0x198;
pub const MSR_IA32_PERF_CTL:     u32 = 0x199;

pub const MSR_IA32_PM_ENABLE:        u32 = 0x770;
pub const MSR_IA32_HWP_CAPABILITIES: u32 = 0x771;
pub const MSR_IA32_HWP_REQUEST:      u32 = 0x774;
pub const MSR_IA32_HWP_STATUS:       u32 = 0x777;

pub const MSR_AMD_PSTATE_LIMIT:  u32 = 0xC001_0061;
pub const MSR_AMD_PSTATE_STATUS: u32 = 0xC001_0063;
pub const MSR_AMD_PSTATE_DEF_0:  u32 = 0xC001_0064;

// ── Detection ──────────────────────────────────────────────────────

/// Selected P-state mechanism for this boot. `None` means the kernel
/// won't drive frequency scaling and leaves whatever firmware
/// programmed in place.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mechanism { Hwp, SpeedStep, AmdLegacy, None }

static MECHANISM_RAW: AtomicU8 = AtomicU8::new(0xFF);

fn vendor_intel() -> bool {
    // SAFETY: leaf 0 is always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    ebx == 0x756E_6547 && edx == 0x4965_6E69 && ecx == 0x6C65_746E
    // "Genu" "ineI" "ntel"
}

fn vendor_amd() -> bool {
    // SAFETY: same.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    ebx == 0x6874_7541 && edx == 0x6974_6E65 && ecx == 0x444D_4163
    // "Auth" "enti" "cAMD"
}

fn hwp_supported() -> bool {
    // SAFETY: leaf 6 is defined when CPUID max >= 6.
    let (max, _, _, _) = unsafe { cpuid(0, 0) };
    if max < 6 { return false; }
    let (eax, _, _, _) = unsafe { cpuid(6, 0) };
    eax & (1 << 7) != 0
}

fn eist_supported() -> bool {
    // SAFETY: leaf 1 is always defined.
    let (_, _, ecx, _) = unsafe { cpuid(1, 0) };
    ecx & (1 << 7) != 0
}

fn amd_pstate_supported() -> bool {
    // CPUID(0x8000_0007).EDX[7] = HwPstate.
    // SAFETY: extended leaves; check max via 0x8000_0000 first.
    let (max, _, _, _) = unsafe { cpuid(0x8000_0000, 0) };
    if max < 0x8000_0007 { return false; }
    let (_, _, _, edx) = unsafe { cpuid(0x8000_0007, 0) };
    edx & (1 << 7) != 0
}

/// Detect (and cache) which P-state mechanism applies. Cheap to
/// call repeatedly — the result is memoised.
pub fn detect() -> Mechanism {
    let raw = MECHANISM_RAW.load(Ordering::Acquire);
    if raw != 0xFF {
        return match raw {
            1 => Mechanism::Hwp,
            2 => Mechanism::SpeedStep,
            3 => Mechanism::AmdLegacy,
            _ => Mechanism::None,
        };
    }
    let m = if vendor_intel() {
        if hwp_supported() { Mechanism::Hwp }
        else if eist_supported() { Mechanism::SpeedStep }
        else { Mechanism::None }
    } else if vendor_amd() {
        if amd_pstate_supported() { Mechanism::AmdLegacy }
        else { Mechanism::None }
    } else {
        Mechanism::None
    };
    let bits = match m {
        Mechanism::Hwp => 1, Mechanism::SpeedStep => 2,
        Mechanism::AmdLegacy => 3, Mechanism::None => 0,
    };
    MECHANISM_RAW.store(bits, Ordering::Release);
    m
}

// ── HWP ────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug)]
pub struct HwpCaps {
    pub max_perf:        u8,
    pub guaranteed_perf: u8,
    pub efficient_perf:  u8,
    pub min_perf:        u8,
}

/// Read `IA32_HWP_CAPABILITIES`. Layout (per SDM §14.4.4):
///   bits[7:0]  = highest performance
///   bits[15:8] = guaranteed performance
///   bits[23:16] = most efficient performance
///   bits[31:24] = lowest performance
///
/// # Safety
/// CPL = 0; HWP supported.
pub unsafe fn hwp_capabilities() -> HwpCaps {
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_IA32_HWP_CAPABILITIES) };
    HwpCaps {
        max_perf:        (v & 0xFF) as u8,
        guaranteed_perf: ((v >> 8)  & 0xFF) as u8,
        efficient_perf:  ((v >> 16) & 0xFF) as u8,
        min_perf:        ((v >> 24) & 0xFF) as u8,
    }
}

/// Enable HWP on this CPU. Writes 1 to `IA32_PM_ENABLE` (sticky;
/// only effective once per boot).
///
/// # Safety
/// CPL = 0; HWP supported.
pub unsafe fn hwp_enable() {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_PM_ENABLE, 1); }
}

/// Program `IA32_HWP_REQUEST` for this CPU.
///
///   `min`     — bits[7:0]    minimum performance bound
///   `max`     — bits[15:8]   maximum performance bound
///   `desired` — bits[23:16]  0 = autonomous (HW chooses)
///   `epp`     — bits[31:24]  energy-performance preference
///                            (0 = perf, 0x80 = balanced, 0xFF = power)
///
/// # Safety
/// CPL = 0; HWP enabled.
pub unsafe fn hwp_set(min: u8, max: u8, desired: u8, epp: u8) {
    let v = (min as u64)
          | ((max as u64) << 8)
          | ((desired as u64) << 16)
          | ((epp as u64) << 24);
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_HWP_REQUEST, v); }
}

/// Read `IA32_HWP_STATUS` for diagnostics.
///
/// # Safety
/// CPL = 0; HWP enabled.
pub unsafe fn hwp_status() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_HWP_STATUS) }
}

// ── Legacy SpeedStep / AMD ─────────────────────────────────────────

/// Read `IA32_PERF_STATUS` (Intel) or `MSR_AMD_PSTATE_STATUS` (AMD).
/// Both report the currently realised P-state; vendor decoding
/// differs.
///
/// # Safety
/// CPL = 0.
pub unsafe fn current_status() -> u64 {
    match detect() {
        Mechanism::Hwp        => unsafe { rdmsr(MSR_IA32_HWP_STATUS) },
        Mechanism::SpeedStep  => unsafe { rdmsr(MSR_IA32_PERF_STATUS) },
        Mechanism::AmdLegacy  => unsafe { rdmsr(MSR_AMD_PSTATE_STATUS) },
        Mechanism::None       => 0,
    }
}

/// Set the legacy P-state target via `IA32_PERF_CTL` (Intel) or
/// `MSR_AMD_PSTATE_LIMIT` (AMD). The 16-bit `id` carries the
/// vendor-specific encoding (Intel: bus-ratio | voltage; AMD:
/// P-state index 0..7).
///
/// # Safety
/// CPL = 0; the mechanism returned by `detect()` is one of
/// `SpeedStep` / `AmdLegacy`.
pub unsafe fn legacy_set(id: u16) {
    match detect() {
        Mechanism::SpeedStep => {
            // SAFETY: caller-asserted.
            unsafe { wrmsr(MSR_IA32_PERF_CTL, id as u64); }
        }
        Mechanism::AmdLegacy => {
            // SAFETY: caller-asserted; AMD wants the low 3 bits
            // as a P-state index (0..7, 0 = P0 highest).
            unsafe { wrmsr(MSR_AMD_PSTATE_LIMIT, (id & 0x7) as u64); }
        }
        _ => {}
    }
}

/// Boot-time bring-up: detect mechanism, enable HWP if available,
/// set HWP request to `(min, max)` from capabilities (autonomous,
/// balanced EPP). On legacy paths, leave whatever firmware did.
///
/// # Safety
/// CPL = 0, boot context.
pub unsafe fn init() {
    match detect() {
        Mechanism::Hwp => {
            // SAFETY: caller-asserted.
            unsafe { hwp_enable(); }
            // SAFETY: same.
            let caps = unsafe { hwp_capabilities() };
            // SAFETY: same.
            unsafe {
                hwp_set(caps.min_perf, caps.max_perf, /*desired*/0, /*EPP*/ 0x80);
            }
        }
        _ => {}  // No-op for SpeedStep / AmdLegacy / None.
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    MECHANISM_RAW.store(0xFF, Ordering::Release);
}
