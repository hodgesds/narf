//! Memory Type Range Registers (MTRR) — clean-room.
//!
//! Reference: **Intel SDM Vol 3 §12.11** ("Memory Type Range
//! Registers (MTRRs)") + **AMD APM Vol 2 §7.7**. The two specs
//! match for every register we touch.
//!
//! ## Register set
//!
//! | MSR     | name                  | description                   |
//! |---------|-----------------------|-------------------------------|
//! | 0xFE    | IA32_MTRRCAP          | Capabilities                  |
//! | 0x2FF   | IA32_MTRR_DEF_TYPE    | Default memory type + enable  |
//! | 0x200..0x20F | IA32_MTRR_PHYSBASE0/MASK0..7 | Variable ranges  |
//! | 0x250   | IA32_MTRR_FIX64K_00000 | Fixed range, 64 KiB pages    |
//! | 0x258/0x259 | IA32_MTRR_FIX16K_*  | Fixed 16 KiB pages          |
//! | 0x268..0x26F | IA32_MTRR_FIX4K_*  | Fixed 4 KiB pages           |
//!
//! Stage cut: probe `IA32_MTRRCAP` + decode the variable-range
//! count, surface a `set_variable_range(idx, base, size, type)`
//! that respects the SDM's
//!   "disable→update→enable" sequence (§12.11.7.1):
//!   1. Disable caches (CR0.CD, CR0.NW), invalidate (WBINVD),
//!      flush TLBs.
//!   2. Disable MTRRs (`IA32_MTRR_DEF_TYPE.E = 0`).
//!   3. Update PHYSBASE / PHYSMASK.
//!   4. Re-enable MTRRs.
//!   5. Re-enable caches.
//!
//! NARF doesn't need to handle the cache-disable dance for boot-
//! time defaults left by firmware; the helper is here for
//! `set_write_combining(phys, size)` which the framebuffer / GPU
//! drivers want to claim WC for their BARs.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr_or_gp};

pub const MSR_IA32_MTRRCAP: u32 = 0xFE;
pub const MSR_IA32_MTRR_DEF_TYPE: u32 = 0x2FF;
const MSR_PHYSBASE_BASE: u32 = 0x200;
const MSR_PHYSMASK_BASE: u32 = 0x201;

/// CPUID-derived max-physical-address-width. Bits above this are
/// reserved in MTRR PHYSBASE/PHYSMASK MSR writes — real silicon
/// `#GP`s if you set them; QEMU TCG is lax. AMD APM Vol 2 §7.7.1,
/// Intel SDM Vol 3 §12.11.4 both spell this out.
///
/// Default value 36 = the architectural minimum (Intel: original
/// x86_64 required ≥ 36, AMD64 same). Real Phoenix typically
/// reports 48; the fallback exists so we never mask too loosely.
fn maxphyaddr() -> u8 {
    // CPUID.80000000h:EAX → maxleaf
    // SAFETY: leaf 0x80000000 always defined.
    let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
    if max_ext < 0x8000_0008 {
        return 36;
    }
    // CPUID.80000008h:EAX bits[7:0] = MAXPHYADDR
    // SAFETY: extended leaf 8 valid per max_ext check.
    let (eax, _, _, _) = unsafe { cpuid(0x8000_0008, 0) };
    let bits = (eax & 0xFF) as u8;
    if bits == 0 {
        36
    } else {
        bits
    }
}

/// Mask that selects "address bits available to MTRR PHYSBASE /
/// PHYSMASK" — bits 12..=MAXPHYADDR-1. Setting bits outside this
/// range #GPs on real silicon.
fn phys_addr_mask() -> u64 {
    let bits = maxphyaddr();
    if bits >= 64 {
        !0xFFFu64 // shouldn't happen, but defensive
    } else {
        let top = (1u64 << bits).wrapping_sub(1);
        top & !0xFFFu64
    }
}

/// Memory type encoding (SDM §12.11.2.1 Table 12-3 / §12.11.4.1).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemType {
    Uncacheable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
}

impl MemType {
    pub fn from_raw(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Uncacheable,
            1 => Self::WriteCombining,
            4 => Self::WriteThrough,
            5 => Self::WriteProtected,
            6 => Self::WriteBack,
            _ => return None,
        })
    }
}

/// Decoded `IA32_MTRRCAP`.
#[derive(Copy, Clone, Debug)]
pub struct MtrrCap {
    /// Number of variable-range registers (low byte).
    pub vcnt: u8,
    /// Fixed-range MTRRs supported.
    pub fix: bool,
    /// Write-combining memory type supported.
    pub wc: bool,
    /// SMRR present.
    pub smrr: bool,
}

impl MtrrCap {
    pub fn decode(raw: u64) -> Self {
        Self {
            vcnt: (raw & 0xFF) as u8,
            fix: raw & (1 << 8) != 0,
            wc: raw & (1 << 10) != 0,
            smrr: raw & (1 << 11) != 0,
        }
    }
}

/// Decoded `IA32_MTRR_DEF_TYPE`.
#[derive(Copy, Clone, Debug)]
pub struct DefType {
    pub default: MemType,
    /// Fixed-range MTRRs enabled.
    pub fe: bool,
    /// MTRRs globally enabled.
    pub e: bool,
}

impl DefType {
    pub fn decode(raw: u64) -> Self {
        Self {
            default: MemType::from_raw((raw & 0xFF) as u8).unwrap_or(MemType::Uncacheable),
            fe: raw & (1 << 10) != 0,
            e: raw & (1 << 11) != 0,
        }
    }
}

/// Read MTRR capabilities.
///
/// # Safety
/// CPL = 0. MTRR support is part of the architectural baseline
/// on every supported x86_64 CPU.
pub unsafe fn cap() -> MtrrCap {
    // SAFETY: caller-asserted.
    MtrrCap::decode(unsafe { rdmsr(MSR_IA32_MTRRCAP) })
}

/// Read default memory type + enable bits.
///
/// # Safety
/// CPL = 0.
pub unsafe fn def_type() -> DefType {
    // SAFETY: caller-asserted.
    DefType::decode(unsafe { rdmsr(MSR_IA32_MTRR_DEF_TYPE) })
}

/// Read variable range `idx` — returns `(physbase, physmask)`.
///
/// # Safety
/// CPL = 0; `idx < cap().vcnt`.
pub unsafe fn read_variable(idx: u8) -> (u64, u64) {
    // SAFETY: caller-asserted.
    let base = unsafe { rdmsr(MSR_PHYSBASE_BASE + 2 * idx as u32) };
    // SAFETY: same.
    let mask = unsafe { rdmsr(MSR_PHYSMASK_BASE + 2 * idx as u32) };
    (base, mask)
}

/// Program a variable range MTRR.
///
/// `size_bytes` must be a power of two; `phys` must be aligned to
/// it. The MTRR mask is `~(size - 1) & physmask` per the SDM,
/// where `physmask` is constrained to bits 12..=MAXPHYADDR-1 (any
/// bit above that is reserved and will be rejected by real
/// silicon with `#GP`).
///
/// Returns `Ok(())` on a successful write, `Err(())` if either
/// the PHYSBASE or PHYSMASK write was rejected (firmware-locked
/// MTRR, reserved-bit violation we didn't catch, etc.). Both
/// MSRs go through `wrmsr_or_gp` so a rejection is a typed
/// error, not a kernel-fatal #GP.
///
/// This helper does **not** perform the cache-disable / WBINVD
/// dance the SDM mandates for runtime updates to existing
/// ranges. Use it at boot, before any cacheable mapping spans
/// the affected window, or wrap the call in your own
/// `disable_caches → set_variable_range → enable_caches` sequence.
///
/// # Safety
/// CPL = 0; `idx < cap().vcnt`; the address window must be
/// reasonable (claimed by the device behind the BAR).
pub unsafe fn set_variable(
    idx: u8,
    phys: u64,
    size_bytes: u64,
    mem_type: MemType,
) -> Result<(), ()> {
    if !size_bytes.is_power_of_two() {
        return Err(());
    }
    let addr_mask = phys_addr_mask();
    let mask_bits = !(size_bytes - 1) & addr_mask;
    let physbase = (phys & addr_mask) | (mem_type as u64);
    let physmask = mask_bits | (1 << 11); // V (valid) bit 11.
    // Use the probe-armed wrappers so a firmware-locked MTRR or
    // a reserved-bit reject becomes a typed error instead of a
    // kernel-fatal #GP — early-FB-console install path treats
    // this as best-effort (no WC just means slow scroll).
    if wrmsr_or_gp(MSR_PHYSBASE_BASE + 2 * idx as u32, physbase).is_err() {
        return Err(());
    }
    if wrmsr_or_gp(MSR_PHYSMASK_BASE + 2 * idx as u32, physmask).is_err() {
        return Err(());
    }
    Ok(())
}

/// Find the first free variable MTRR slot (mask V bit clear).
///
/// # Safety
/// CPL = 0.
pub unsafe fn find_free_slot() -> Option<u8> {
    // SAFETY: caller-asserted.
    let cap = unsafe { cap() };
    for i in 0..cap.vcnt {
        // SAFETY: caller-asserted.
        let (_b, m) = unsafe { read_variable(i) };
        if m & (1 << 11) == 0 {
            return Some(i);
        }
    }
    None
}

/// Convenience: claim Write-Combining for a BAR window.
///
/// Returns the slot index that was programmed, or `None` if no
/// free slot is available.
///
/// # Safety
/// CPL = 0; `phys` is the start of an MMIO BAR claimed by the
/// caller; `size_bytes` is a power of two and the alignment is
/// respected.
pub unsafe fn set_write_combining(phys: u64, size_bytes: u64) -> Option<u8> {
    // SAFETY: caller-asserted.
    let slot = unsafe { find_free_slot() }?;
    // SAFETY: same.
    let res = unsafe { set_variable(slot, phys, size_bytes, MemType::WriteCombining) };
    res.ok().map(|_| slot)
}
