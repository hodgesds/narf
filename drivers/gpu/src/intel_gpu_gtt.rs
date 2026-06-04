//! GTT / PPGTT page-table entry codec — clean-room.
//!
//! Reference: **Tiger Lake PRM Vol. 5 §"Memory Views"**.
//! Cross-checked against ADL / RPL PRMs (same Gen12 PTE layout)
//! and the Meteor Lake PRM Vol. 5 (extended cache-control bits
//! noted but the legacy PTE encoding still works for KMS-grade
//! scanout).
//!
//! ## GTT vs PPGTT
//!
//! Gen12 has two page-table machineries:
//!
//! - **Global GTT** (GGTT) — a single flat page table mapping the
//!   GPU virtual address space to host physical addresses. Used
//!   by display planes and other "always-on" engines.
//! - **Per-process GTT** (PPGTT) — a 4-level page-table walker
//!   per command-streamer context. Used by the 3D / compute /
//!   media engines.
//!
//! Both share the same **64-bit page-table-entry layout** — only
//! the placement (single flat table vs 4-level walk) differs.
//!
//! ## PTE format (Gen12, 64-bit)
//!
//! ```text
//!   bit 0     PRESENT       — entry is valid.
//!   bit 1     RW            — read/write (display planes set 0; engines may set 1).
//!   bits 2-3  PWT/PCD       — legacy x86 cache-control mirrors.
//!   bit 6     LRU age       — 0=fresh, 1=aged.
//!   bits 7-11 reserved
//!   bits 12-38 phys[38:12]  — 4 KiB-aligned physical address.
//!   bit 60    PAT[0]        — selects PAT (page-attribute table) entry.
//!   bit 61    PAT[1]        — combined: 4 PAT slots → 4 cache modes.
//!   bit 62    LRU bypass    — when set, this page bypasses LRU.
//!   bit 63    NX            — no-execute (PPGTT only; GGTT ignores).
//! ```
//!
//! Source: TGL PRM Vol. 5 §"GFX PTE Definition".
//!
//! ## Scope
//!
//! Codec only. The GGTT / PPGTT walker (and the actual page-table
//! installation) lives in the Stage-4 driver core.

// ── PTE bit definitions (TGL PRM Vol. 5 §"GFX PTE Definition") ──

/// PRESENT bit — entry maps a valid page.
pub const PTE_PRESENT: u64 = 1 << 0;
/// Read/write bit — display plane scanout sets this clear (RO);
/// 3D/compute engines may set it.
pub const PTE_RW: u64 = 1 << 1;
/// PWT — legacy x86 PAT-bit-0 mirror.
pub const PTE_PWT: u64 = 1 << 3;
/// PCD — legacy x86 PAT-bit-1 mirror.
pub const PTE_PCD: u64 = 1 << 4;
/// LRU age bit — set on PTE eviction candidates.
pub const PTE_LRU_AGE: u64 = 1 << 6;
/// PAT bit 0 (selects PAT slot, low bit).
pub const PTE_PAT0: u64 = 1 << 60;
/// PAT bit 1 (selects PAT slot, high bit).
pub const PTE_PAT1: u64 = 1 << 61;
/// LRU-bypass — page never ages.
pub const PTE_LRU_BYPASS: u64 = 1 << 62;
/// NX — PPGTT no-execute.
pub const PTE_NX: u64 = 1 << 63;

/// PRM-mandated phys mask: bits[38:12]. Higher bits are reserved
/// — the GTT physical-address space is 39 bits wide.
pub const PTE_PHYS_MASK: u64 = 0x0000_007F_FFFF_F000;

/// Page size — every Gen12 GTT entry maps a 4 KiB page.
pub const GTT_PAGE_SIZE: u64 = 0x1000;

/// Documented PAT slots on Gen12. PRM Vol. 5 §"PAT Index Encoding".
///
/// The PAT (Page Attribute Table) is a 64-byte register block
/// programmed by firmware / BIOS at boot. Each slot picks a
/// (memory-type, cache-policy) combination; the GTT PTE selects
/// one of four slots through `PAT0` + `PAT1`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum PatSlot {
    /// Slot 0 — PAT default (typically Uncached).
    Slot0 = 0,
    /// Slot 1 — usually LLC + eLLC cached, write-back.
    Slot1 = 1,
    /// Slot 2 — write-combining (the typical scanout choice).
    Slot2 = 2,
    /// Slot 3 — extended (Xe-LPG only).
    Slot3 = 3,
}

impl PatSlot {
    /// Pack into the `PAT0` + `PAT1` PTE bits.
    pub const fn encode(self) -> u64 {
        let v = self as u64;
        ((v & 1) << 60) | (((v >> 1) & 1) << 61)
    }
    pub const fn decode(pte: u64) -> Self {
        let lo = (pte >> 60) & 1;
        let hi = (pte >> 61) & 1;
        match (hi << 1) | lo {
            0 => PatSlot::Slot0,
            1 => PatSlot::Slot1,
            2 => PatSlot::Slot2,
            _ => PatSlot::Slot3,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GttError {
    /// Phys address isn't 4 KiB-aligned.
    UnalignedPhys,
    /// Phys address has bits set outside the documented 39-bit
    /// physical-address space.
    PhysOutOfRange,
}

/// Build a present, read-only PTE for a scanout page.
///
/// `phys` must be 4 KiB-aligned and fit in 39 bits. `pat` picks
/// the cache policy — `Slot2` (write-combining) is the standard
/// choice for display-plane scanout.
pub fn encode_scanout_pte(phys: u64, pat: PatSlot) -> Result<u64, GttError> {
    if phys & 0xFFF != 0 {
        return Err(GttError::UnalignedPhys);
    }
    if phys & !PTE_PHYS_MASK != 0 {
        return Err(GttError::PhysOutOfRange);
    }
    Ok(PTE_PRESENT | (phys & PTE_PHYS_MASK) | pat.encode())
}

/// Build a present, read/write PTE for a 3D / compute engine
/// (PPGTT). `pat` typically `Slot1` (LLC cached) for shader
/// surfaces, `Slot2` for staging buffers.
pub fn encode_engine_pte(phys: u64, pat: PatSlot, executable: bool) -> Result<u64, GttError> {
    if phys & 0xFFF != 0 {
        return Err(GttError::UnalignedPhys);
    }
    if phys & !PTE_PHYS_MASK != 0 {
        return Err(GttError::PhysOutOfRange);
    }
    let mut v = PTE_PRESENT | PTE_RW | (phys & PTE_PHYS_MASK) | pat.encode();
    if !executable {
        v |= PTE_NX;
    }
    Ok(v)
}

/// Decode the phys-address portion of an existing PTE.
pub fn pte_phys(pte: u64) -> u64 {
    pte & PTE_PHYS_MASK
}

/// `true` iff the PTE has `PRESENT` set.
pub fn pte_present(pte: u64) -> bool {
    pte & PTE_PRESENT != 0
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pat_slot_round_trip() -> TestResult {
        for slot in [
            PatSlot::Slot0,
            PatSlot::Slot1,
            PatSlot::Slot2,
            PatSlot::Slot3,
        ] {
            let bits = slot.encode();
            if PatSlot::decode(bits) != slot {
                return TestResult::Fail("PAT slot encode/decode round-trip");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_pat_slot_round_trip);

    fn smoke_scanout_pte_layout() -> TestResult {
        let phys = 0x0000_0001_2345_6000u64;
        let pte = match encode_scanout_pte(phys, PatSlot::Slot2) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        if !pte_present(pte) {
            return TestResult::Fail("PRESENT bit not set");
        }
        if pte_phys(pte) != phys {
            return TestResult::Fail("phys round-trip");
        }
        if PatSlot::decode(pte) != PatSlot::Slot2 {
            return TestResult::Fail("PAT slot lost in encode");
        }
        if pte & PTE_RW != 0 {
            return TestResult::Fail("scanout PTE must be RO");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_scanout_pte_layout);

    fn smoke_engine_pte_nx() -> TestResult {
        let pte = match encode_engine_pte(0x1000, PatSlot::Slot1, false) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        if pte & PTE_NX == 0 {
            return TestResult::Fail("non-executable engine PTE must set NX");
        }
        if pte & PTE_RW == 0 {
            return TestResult::Fail("engine PTE must be RW");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gtt", smoke_engine_pte_nx);

    fn smoke_pte_rejects_unaligned_phys() -> TestResult {
        match encode_scanout_pte(0x1234, PatSlot::Slot2) {
            Err(GttError::UnalignedPhys) => TestResult::Pass,
            _ => TestResult::Fail("non-4KiB phys must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gtt",
        smoke_pte_rejects_unaligned_phys
    );

    fn smoke_pte_rejects_out_of_range_phys() -> TestResult {
        // Bit 39 set — outside the documented 39-bit phys window.
        match encode_scanout_pte(1u64 << 39, PatSlot::Slot2) {
            Err(GttError::PhysOutOfRange) => TestResult::Pass,
            _ => TestResult::Fail(">39-bit phys must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gtt",
        smoke_pte_rejects_out_of_range_phys
    );
}
