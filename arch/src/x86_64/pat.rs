//! Page Attribute Table (PAT) — per-page memory-type selection.
//!
//! Reference: **Intel SDM Vol 3 §12.12** ("Page Attribute Table").
//! AMD APM Vol 2 §7.8 matches.
//!
//! PAT supersedes MTRR for per-page cache attributes. MTRR is
//! limited to a small number of fixed phys-range registers + the
//! variable-MTRR set whose count is fixed at boot; PAT is set
//! per-PTE via three bits, giving each page its own memory type
//! from one of 8 entries in `IA32_PAT`.
//!
//! ## PTE → PAT index decoding
//!
//! The PAT entry selector for a 4 KiB PTE is a 3-bit index:
//!
//! ```text
//!   index = (PTE.PAT << 2) | (PTE.PCD << 1) | PTE.PWT
//! ```
//!
//! - `PTE.PWT` = bit 3 (Write-Through)
//! - `PTE.PCD` = bit 4 (Cache-Disable)
//! - `PTE.PAT` = bit 7 for 4 KiB pages, bit 12 for 2 MiB / 1 GiB
//!   pages (since bit 7 is `HUGE_PAGE` for big pages)
//!
//! Each `IA32_PAT` entry is a 3-bit memory-type code:
//!   0 = UC, 1 = WC, 4 = WT, 5 = WP, 6 = WB, 7 = UC-
//!
//! ## NARF layout
//!
//! We program `IA32_PAT` so the eight slots are:
//!
//! ```text
//!   PA0 = WB   (default; PWT=0, PCD=0, PAT=0)
//!   PA1 = WC   ← reprogrammed (was WT). Selected by PWT=1.
//!   PA2 = UC-  (default)
//!   PA3 = UC   (default)
//!   PA4 = WB   (default)
//!   PA5 = WC   ← reprogrammed (was WT). Selected by PAT=1, PWT=1.
//!   PA6 = UC-  (default)
//!   PA7 = UC   (default)
//! ```
//!
//! This matches Linux's `x86/mm/pat.c` layout: a "use PWT to get
//! WC" convention that doesn't break code paths that pre-PAT
//! relied on PCD alone (those still get UC- = effectively UC for
//! MMIO purposes).
//!
//! ## Detection
//!
//! PAT support: `CPUID.01h:EDX[16]`. Every x86_64 long-mode CPU
//! has it, so we assert rather than gracefully degrade.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr_or_gp};

/// MSR index for `IA32_PAT`.
pub const MSR_IA32_PAT: u32 = 0x277;

/// Memory-type codes for PAT entries (Intel SDM Vol 3 §12.12.4).
pub mod ty {
    pub const UC: u8 = 0x00;
    pub const WC: u8 = 0x01;
    pub const WT: u8 = 0x04;
    pub const WP: u8 = 0x05;
    pub const WB: u8 = 0x06;
    pub const UC_MINUS: u8 = 0x07;
}

/// `true` iff PAT is supported (per `CPUID.01h:EDX[16]`).
pub fn supported() -> bool {
    // SAFETY: leaf 1 is always defined on long-mode x86_64.
    let (_, _, _, edx) = unsafe { cpuid(1, 0) };
    edx & (1 << 16) != 0
}

/// Build the 8-byte PAT value from the eight PA entry type codes
/// (`pa[0]` = PA0 type, in the low byte). Encoded as one u64 — that's
/// exactly the `IA32_PAT` MSR layout.
pub const fn encode(pa: [u8; 8]) -> u64 {
    (pa[0] as u64)
        | (pa[1] as u64) << 8
        | (pa[2] as u64) << 16
        | (pa[3] as u64) << 24
        | (pa[4] as u64) << 32
        | (pa[5] as u64) << 40
        | (pa[6] as u64) << 48
        | (pa[7] as u64) << 56
}

/// NARF's standard PAT layout. PA1 reprogrammed to WC so PTE.PWT=1
/// gives write-combining. All other entries match the hardware
/// reset default — code that didn't know about PAT before the
/// reprogramming sees identical behaviour for PWT=0 pages.
pub const NARF_PAT: u64 = encode([
    ty::WB,       // PA0
    ty::WC,       // PA1 — reprogrammed (was WT)
    ty::UC_MINUS, // PA2
    ty::UC,       // PA3
    ty::WB,       // PA4
    ty::WC,       // PA5 — reprogrammed (was WT)
    ty::UC_MINUS, // PA6
    ty::UC,       // PA7
]);

/// Read the currently-programmed `IA32_PAT`.
pub fn read() -> u64 {
    // SAFETY: PAT is unconditional on long-mode x86_64; rdmsr is
    // always legal at CPL=0.
    unsafe { rdmsr(MSR_IA32_PAT) }
}

/// Reprogram `IA32_PAT` to the NARF standard layout. Idempotent —
/// re-applies the same value; future readers see PA1 = WC.
///
/// Per SDM Vol 3 §12.12.4 ("Programming the PAT"), the proper
/// sequence is:
///   1. Disable CR0.CD + CR0.NW.
///   2. WBINVD.
///   3. Flush TLBs (write CR3).
///   4. Write IA32_PAT.
///   5. WBINVD again.
///   6. Restore CR0.CD/NW.
///
/// NARF runs this once at boot, single-threaded, before any
/// cacheable mapping spans a region whose type we're about to
/// change (the early identity map is WB by default; we keep PA0
/// as WB so existing mappings don't change semantics). Skipping
/// the cache-disable dance is safe in that narrow window — same
/// rationale `mtrr::set_variable` uses.
///
/// # Safety
/// - CPL = 0.
/// - Must be called from a single-threaded boot context BEFORE
///   any ioremap-WC path has been used (otherwise pages that
///   transiently switched between caches between the old and new
///   PAT values would have undefined behaviour).
pub unsafe fn init_default() -> Result<(), ()> {
    if !supported() {
        return Err(());
    }
    if wrmsr_or_gp(MSR_IA32_PAT, NARF_PAT).is_err() {
        return Err(());
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pat_encode_round_trips() -> TestResult {
        let v = encode([
            ty::WB,
            ty::WC,
            ty::UC_MINUS,
            ty::UC,
            ty::WB,
            ty::WC,
            ty::UC_MINUS,
            ty::UC,
        ]);
        // Spot-check bytes.
        if (v & 0xFF) as u8 != ty::WB {
            return TestResult::Fail("PA0 wrong");
        }
        if ((v >> 8) & 0xFF) as u8 != ty::WC {
            return TestResult::Fail("PA1 (WC) wrong");
        }
        if ((v >> 56) & 0xFF) as u8 != ty::UC {
            return TestResult::Fail("PA7 wrong");
        }
        TestResult::Pass
    }

    fn smoke_pat_narf_layout_pa1_is_wc() -> TestResult {
        if ((NARF_PAT >> 8) & 0xFF) as u8 != ty::WC {
            return TestResult::Fail("NARF_PAT PA1 is not WC");
        }
        if ((NARF_PAT >> 40) & 0xFF) as u8 != ty::WC {
            return TestResult::Fail("NARF_PAT PA5 is not WC");
        }
        // PA0 should stay WB so existing mappings aren't disturbed.
        if (NARF_PAT & 0xFF) as u8 != ty::WB {
            return TestResult::Fail("NARF_PAT PA0 must stay WB");
        }
        TestResult::Pass
    }

    kernel_test_in!("arch/pat", smoke_pat_encode_round_trips);
    kernel_test_in!("arch/pat", smoke_pat_narf_layout_pa1_is_wc);
}
