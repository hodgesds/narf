//! AMD VM hub MMIO programming — write `MC_VM_CONTEXT*_PAGE_TABLE_*`
//! registers for a given (hub, vmid) pair.
//!
//! ## Why this exists
//!
//! `VmidPool::bind` (see `amdgpu_vmid.rs`) tracks who owns which
//! VMID logically. Binding a PASID's page-table root to silicon
//! requires programming three pairs of 32-bit MMIO registers per
//! VMID per hub:
//!
//! ```text
//!   regGCVM_CONTEXT<n>_PAGE_TABLE_BASE_ADDR_LO32    PT root phys lo32
//!   regGCVM_CONTEXT<n>_PAGE_TABLE_BASE_ADDR_HI32    PT root phys hi32
//!   regGCVM_CONTEXT<n>_PAGE_TABLE_START_ADDR_LO32   GART start >> 12 lo
//!   regGCVM_CONTEXT<n>_PAGE_TABLE_START_ADDR_HI32   GART start >> 12 hi
//!   regGCVM_CONTEXT<n>_PAGE_TABLE_END_ADDR_LO32     GART end >> 12 lo
//!   regGCVM_CONTEXT<n>_PAGE_TABLE_END_ADDR_HI32     GART end >> 12 hi
//! ```
//!
//! `ctx_addr_distance` per Linux `gfxhub_v3_0.c::gfxhub_v3_0_init`
//! is `regGCVM_CONTEXT1_PAGE_TABLE_BASE_ADDR_LO32 -
//! regGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32` — for GFX11 that's
//! `0x16f5 - 0x16f3 = 2`. Each VMID's base+start+end registers are
//! at the per-VMID offset of `base[0] + vmid * ctx_addr_distance`.
//!
//! ## Per-family offset table
//!
//! Phoenix (GFX11 + MMHUB v3.0) and Renoir (GFX10.3 / GCN9-ish via
//! gfxhub_v2_0 + mmhub_v2_3) use different register windows for
//! the same logical VM register set. The `VmHubRegs` table below
//! captures the per-family (GFX11 vs GFX10.3) and per-hub (GFXHUB
//! vs MMHUB) base offsets.
//!
//! ## References
//!
//! - Linux `drivers/gpu/drm/amd/amdgpu/gfxhub_v3_0.c::gfxhub_v3_0_setup_vm_pt_regs`
//!   (lines 119-131) — VMID base addr write.
//! - Linux `drivers/gpu/drm/amd/amdgpu/gfxhub_v3_0.c::gfxhub_v3_0_init_gart_aperture_regs`
//!   (lines 133-148) — START/END addr write for VMID 0 (GART).
//! - Linux `drivers/gpu/drm/amd/amdgpu/mmhub_v3_0.c::mmhub_v3_0_setup_vm_pt_regs`
//!   (lines 136-149) — MMHUB v3.0 (Phoenix) equivalent.
//! - Linux `drivers/gpu/drm/amd/include/asic_reg/gc/gc_11_0_0_offset.h`
//!   — Phoenix GC11 register offsets.
//! - Linux `drivers/gpu/drm/amd/include/asic_reg/gc/gc_10_3_0_offset.h`
//!   — Renoir GC10.3 register offsets.
//! - Linux `drivers/gpu/drm/amd/include/asic_reg/mmhub/mmhub_3_0_0_offset.h`
//!   — Phoenix MMHUB v3.0 register offsets.
//! - Linux `drivers/gpu/drm/amd/include/asic_reg/mmhub/mmhub_2_3_0_offset.h`
//!   — Renoir MMHUB v2.3 register offsets.
//!
//! GPL-2.0-or-later (matches NARF post 2026-05-20 relicense).

extern crate alloc;

use crate::amdgpu::Family;
use crate::amdgpu_vmid::VmHub;

// ── Per-family per-hub register offsets ────────────────────────────
//
// All offsets are u32 dword addresses, multiplied by 4 on MMIO write
// since the BAR5 register window is byte-addressed.

/// One hub's relevant register layout. Offsets are dword (4-byte)
/// indices — the MMIO trait below shifts left by 2 on write.
#[derive(Copy, Clone, Debug)]
pub struct VmHubRegs {
    /// Base of `*VM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32` (per-VMID
    /// the offset is `base + vmid * ctx_addr_distance`).
    pub ctx0_pt_base_lo: u32,
    /// `+1` for HI32 always (paired registers).
    pub ctx0_pt_base_hi: u32,
    /// `*VM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32`.
    pub ctx0_pt_start_lo: u32,
    pub ctx0_pt_start_hi: u32,
    /// `*VM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32`.
    pub ctx0_pt_end_lo: u32,
    pub ctx0_pt_end_hi: u32,
    /// Distance between successive VMIDs' PT_BASE / START / END
    /// register sets — per `gfxhub_v3_0.c` line 487:
    /// `regGCVM_CONTEXT1_PAGE_TABLE_BASE_ADDR_LO32 -
    /// regGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32`.
    pub ctx_addr_distance: u32,
    /// `*VM_CONTEXT0_CNTL` — context-enable register.
    pub ctx0_cntl: u32,
    /// Distance between successive CONTEXT_CNTL registers
    /// (`regGCVM_CONTEXT1_CNTL - regGCVM_CONTEXT0_CNTL`).
    pub ctx_distance: u32,
    /// `*VM_INVALIDATE_ENG0_REQ` — start of the per-engine
    /// invalidate request register block.
    pub inv_eng0_req: u32,
    /// `*VM_INVALIDATE_ENG0_ACK` — paired ack register.
    pub inv_eng0_ack: u32,
}

// ── GFX11 GFXHUB (Phoenix) ─────────────────────────────────────────
//
// regGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32                = 0x16f3
// regGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_HI32                = 0x16f4
// regGCVM_CONTEXT1_PAGE_TABLE_BASE_ADDR_LO32                = 0x16f5  → distance = 2
// regGCVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32               = 0x1713
// regGCVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32                 = 0x1733
// regGCVM_CONTEXT0_CNTL                                     = 0x1688
// regGCVM_CONTEXT1_CNTL                                     = 0x1689  → distance = 1
// regGCVM_INVALIDATE_ENG0_REQ                               = 0x16ab
// regGCVM_INVALIDATE_ENG0_ACK is at 0x16a7..; computed as REQ-4.

pub const GFXHUB_V3_0: VmHubRegs = VmHubRegs {
    ctx0_pt_base_lo: 0x16f3,
    ctx0_pt_base_hi: 0x16f4,
    ctx0_pt_start_lo: 0x1713,
    ctx0_pt_start_hi: 0x1714,
    ctx0_pt_end_lo: 0x1733,
    ctx0_pt_end_hi: 0x1734,
    ctx_addr_distance: 2,
    ctx0_cntl: 0x1688,
    ctx_distance: 1,
    inv_eng0_req: 0x16ab,
    inv_eng0_ack: 0x169f,
};

// ── MMHUB v3.0 (Phoenix) ───────────────────────────────────────────
//
// regMMVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32 = 0x07ab
// regMMVM_CONTEXT1_PAGE_TABLE_BASE_ADDR_LO32 = 0x07ad  → distance = 2
// regMMVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32 = 0x07cb
// regMMVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32 = 0x07eb
// regMMVM_CONTEXT0_CNTL = 0x0740
// regMMVM_INVALIDATE_ENG0_REQ = 0x0763

pub const MMHUB_V3_0: VmHubRegs = VmHubRegs {
    ctx0_pt_base_lo: 0x07ab,
    ctx0_pt_base_hi: 0x07ac,
    ctx0_pt_start_lo: 0x07cb,
    ctx0_pt_start_hi: 0x07cc,
    ctx0_pt_end_lo: 0x07eb,
    ctx0_pt_end_hi: 0x07ec,
    ctx_addr_distance: 2,
    ctx0_cntl: 0x0740,
    ctx_distance: 1,
    inv_eng0_req: 0x0763,
    inv_eng0_ack: 0x0757,
};

// ── GFX10.3 GFXHUB (Renoir) ───────────────────────────────────────
//
// mmGCVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32 = 0x1667
// mmGCVM_CONTEXT1_PAGE_TABLE_BASE_ADDR_LO32 = 0x1669  → distance = 2
// mmGCVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32 = 0x1687
// mmGCVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32 = 0x16a7
// mmGCVM_CONTEXT0_CNTL = 0x15fc
// mmGCVM_INVALIDATE_ENG0_REQ = 0x161f

pub const GFXHUB_V2_3: VmHubRegs = VmHubRegs {
    ctx0_pt_base_lo: 0x1667,
    ctx0_pt_base_hi: 0x1668,
    ctx0_pt_start_lo: 0x1687,
    ctx0_pt_start_hi: 0x1688,
    ctx0_pt_end_lo: 0x16a7,
    ctx0_pt_end_hi: 0x16a8,
    ctx_addr_distance: 2,
    ctx0_cntl: 0x15fc,
    ctx_distance: 1,
    inv_eng0_req: 0x161f,
    inv_eng0_ack: 0x1613,
};

// ── MMHUB v2.3 (Renoir) ───────────────────────────────────────────
//
// mmMMVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32 = 0x0940
// mmMMVM_CONTEXT0_PAGE_TABLE_START_ADDR_LO32 = 0x0942
// mmMMVM_CONTEXT0_PAGE_TABLE_END_ADDR_LO32 = 0x0944
// mmMMVM_CONTEXT0_CNTL = 0x0740
// mmMMVM_INVALIDATE_ENG0_REQ = 0x0a01
//
// Note: MMHUB v2.3 has BASE_IDX = 1 (different segment) — the
// per-BAR-offset register window expects an additional segment
// base which the driver glue applies via `apply_base_idx_segment`
// before issuing the MMIO write. For the offset table we keep
// raw dword indices; the glue layer handles segment translation.

pub const MMHUB_V2_3: VmHubRegs = VmHubRegs {
    ctx0_pt_base_lo: 0x0940,
    ctx0_pt_base_hi: 0x0941,
    ctx0_pt_start_lo: 0x0942,
    ctx0_pt_start_hi: 0x0943,
    ctx0_pt_end_lo: 0x0944,
    ctx0_pt_end_hi: 0x0945,
    ctx_addr_distance: 2,
    ctx0_cntl: 0x0740,
    ctx_distance: 1,
    inv_eng0_req: 0x0a01,
    inv_eng0_ack: 0x09f5,
};

/// Look up the per-hub register layout for `family` + `hub`.
/// Returns `None` for families whose offsets we haven't yet
/// transcribed (Vega, Navi1, Navi2 — bring-up targets are Renoir
/// and Phoenix per the project's hardware roster).
pub fn regs_for(family: Family, hub: VmHub) -> Option<VmHubRegs> {
    match (family, hub) {
        (Family::Phoenix, VmHub::Gfx) => Some(GFXHUB_V3_0),
        (Family::Phoenix, VmHub::Mm) => Some(MMHUB_V3_0),
        (Family::Renoir, VmHub::Gfx) => Some(GFXHUB_V2_3),
        (Family::Renoir, VmHub::Mm) => Some(MMHUB_V2_3),
        _ => None,
    }
}

// ── Mmio trait ─────────────────────────────────────────────────────

/// Caller's view of MMIO read/write. Same pattern as the PSP
/// mailbox in `amdgpu_psp.rs::PspMmio` — keeps the protocol
/// testable against a mock without real silicon.
///
/// Offsets are passed in *byte* address space (the trait
/// implementation already multiplied the dword index by 4).
pub trait VmHubMmio {
    fn read(&mut self, byte_off: u32) -> u32;
    fn write(&mut self, byte_off: u32, value: u32);
}

// ── Page-table register programming ────────────────────────────────

/// Bind a VMID's page-table root in one hub. Programs:
///   * `PAGE_TABLE_BASE_ADDR_LO/HI32` at `base[vmid]`.
///
/// Adapted from `gfxhub_v3_0.c::gfxhub_v3_0_setup_vm_pt_regs`
/// (Linux line 119). `regs.ctx_addr_distance * vmid` is the
/// per-VMID stride in dword address space.
pub fn write_vmid_pt_base<M: VmHubMmio>(
    mmio: &mut M,
    regs: &VmHubRegs,
    vmid: u8,
    pt_root_phys: u64,
) {
    let stride = (regs.ctx_addr_distance as u32) * (vmid as u32);
    let lo_dword = regs.ctx0_pt_base_lo + stride;
    let hi_dword = regs.ctx0_pt_base_hi + stride;
    mmio.write(lo_dword << 2, pt_root_phys as u32);
    mmio.write(hi_dword << 2, (pt_root_phys >> 32) as u32);
}

/// Set the VM aperture range (in 4 KiB pages) for VMID 0.
/// VMID 0 = kernel / GART; user VMIDs get a different
/// (typically larger) range and are configured by the OS layer.
///
/// Adapted from `gfxhub_v3_0.c::gfxhub_v3_0_init_gart_aperture_regs`
/// (Linux line 133-148). `start` + `end` are 4 KiB page numbers
/// (PFN).
pub fn write_vmid0_aperture<M: VmHubMmio>(
    mmio: &mut M,
    regs: &VmHubRegs,
    start_pfn: u64,
    end_pfn: u64,
) {
    mmio.write(regs.ctx0_pt_start_lo << 2, start_pfn as u32);
    mmio.write(regs.ctx0_pt_start_hi << 2, (start_pfn >> 32) as u32);
    mmio.write(regs.ctx0_pt_end_lo << 2, end_pfn as u32);
    mmio.write(regs.ctx0_pt_end_hi << 2, (end_pfn >> 32) as u32);
}

// ── Context-enable bits (per Linux mmhub_v3_0.c line 285-290) ──────

/// `MMVM_CONTEXT0_CNTL.ENABLE_CONTEXT` bit (per `mmhub_3_0_0_sh_mask.h`).
pub const CTX_CNTL_ENABLE_CONTEXT: u32 = 1 << 0;
/// `PAGE_TABLE_DEPTH` field shift (2 bits at bit 1).
pub const CTX_CNTL_PT_DEPTH_SHIFT: u32 = 1;
/// `RETRY_PERMISSION_OR_INVALID_PAGE_FAULT` shift.
pub const CTX_CNTL_RETRY_FAULT_SHIFT: u32 = 3;

/// Enable a VMID context. `depth` is the page-table depth (0 =
/// flat / GART, 4 = 4-level x86_64-style for user VMs).
pub fn write_vmid_cntl<M: VmHubMmio>(
    mmio: &mut M,
    regs: &VmHubRegs,
    vmid: u8,
    depth: u8,
    fault_on_invalid: bool,
) {
    let dword = regs.ctx0_cntl + (regs.ctx_distance as u32) * (vmid as u32);
    let mut val = CTX_CNTL_ENABLE_CONTEXT;
    val |= ((depth as u32) & 0x3) << CTX_CNTL_PT_DEPTH_SHIFT;
    if !fault_on_invalid {
        // RETRY=1 lets the GPU retry on a fault rather than firing
        // a VM_FAULT IH cookie — used for prefetch-friendly compute.
        val |= 1 << CTX_CNTL_RETRY_FAULT_SHIFT;
    }
    mmio.write(dword << 2, val);
}

/// Issue a TLB invalidate for `vmid` on the given hub. The hub
/// has `MAX_INVALIDATE_ENGINES` (typically 18) — engine 0 is the
/// kernel-driver-issued one. Bit field layout per
/// `gmc_v11_0.c::gmc_v11_0_flush_gpu_tlb_pasid` (and the older
/// `gmc_v9_0.c`):
///
/// | bits  | field                       |
/// |-------|-----------------------------|
/// | 0     | PER_VMID_INVALIDATE_REQ.0   |
/// | 7:4   | FLUSH_TYPE (0=range,1=ALL2) |
/// | 8     | INVALIDATE_L2_PTES          |
/// | 9     | INVALIDATE_L2_PDE0          |
/// | 10    | INVALIDATE_L2_PDE1          |
/// | 11    | INVALIDATE_L2_PDE2          |
/// | 12    | INVALIDATE_L1_PTES          |
/// | 13    | CLEAR_PROTECTION_FAULT_STATUS_ADDR |
/// | 25:16 | PER_VMID_INVALIDATE_REQ bitmask |
///
/// Polling the matching `_ACK` register tells us when the
/// invalidate is done.
pub fn write_invalidate_tlb<M: VmHubMmio>(
    mmio: &mut M,
    regs: &VmHubRegs,
    vmid: u8,
    flush_type: u8,
) -> Result<(), TlbInvalidateError> {
    if vmid >= 16 {
        return Err(TlbInvalidateError::BadVmid);
    }
    // bit field per the table above.
    let bits = ((flush_type as u32) & 0xF) << 4
        | (1 << 8)  // L2 PTE
        | (1 << 9)  // L2 PDE0
        | (1 << 10) // L2 PDE1
        | (1 << 11) // L2 PDE2
        | (1 << 12) // L1 PTE
        | (1 << 13) // clear fault status
        | ((1u32 << (vmid as u32)) << 16); // per-VMID mask
    mmio.write(regs.inv_eng0_req << 2, bits);
    // Poll the ack; budget is generous (TLB invalidate is fast
    // but real silicon can stall on outstanding accesses).
    let mut i = 0u32;
    let vmid_bit = 1u32 << (vmid as u32);
    loop {
        let ack = mmio.read(regs.inv_eng0_ack << 2);
        if ack & vmid_bit != 0 {
            break;
        }
        i += 1;
        if i >= TLB_POLL_BUDGET {
            return Err(TlbInvalidateError::Timeout);
        }
    }
    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlbInvalidateError {
    BadVmid,
    Timeout,
}

/// Poll cap — generous to allow stalls on real hardware (TLB
/// invalidate is fast at idle but can stall while engines drain).
pub const TLB_POLL_BUDGET: u32 = 1_000_000;

// ── Cross-hub broadcast ────────────────────────────────────────────

/// Issue a TLB invalidate for `vmid` across **all** hubs the family
/// has. On Renoir + Phoenix that's GFXHUB + MMHUB. Per
/// `gmc_v11_0.c::gmc_v11_0_flush_gpu_tlb`, the driver has to walk
/// every hub on a PT-change so the GPU doesn't accidentally serve
/// a stale mapping from another engine.
///
/// `mmio_gfx` and `mmio_mm` are the per-hub mmio impls; they're
/// distinct because the per-hub BAR offsets resolve to different
/// dword-shifted byte addresses inside the BAR5 window.
pub fn broadcast_invalidate_tlb<MG: VmHubMmio, MM: VmHubMmio>(
    mmio_gfx: &mut MG,
    regs_gfx: &VmHubRegs,
    mmio_mm: &mut MM,
    regs_mm: &VmHubRegs,
    vmid: u8,
    flush_type: u8,
) -> Result<(), TlbInvalidateError> {
    write_invalidate_tlb(mmio_gfx, regs_gfx, vmid, flush_type)?;
    write_invalidate_tlb(mmio_mm, regs_mm, vmid, flush_type)?;
    Ok(())
}

/// Issue a TLB invalidate on every engine of every hub. Used after
/// changing a VMID's page-table root — all in-flight translations
/// for that VMID need to drop.
///
/// In production silicon there are up to 18 invalidate engines per
/// hub (eng0 = host, eng1-17 = HW clients). For the bring-up arc
/// we issue against eng0 — the host-owned engine — which is enough
/// for the page-table-bind path. A future optimisation could issue
/// to each engine in parallel and mask their _ACK bits.
pub fn invalidate_vmid_full<MG: VmHubMmio, MM: VmHubMmio>(
    mmio_gfx: &mut MG,
    regs_gfx: &VmHubRegs,
    mmio_mm: &mut MM,
    regs_mm: &VmHubRegs,
    vmid: u8,
) -> Result<(), TlbInvalidateError> {
    // flush_type 0 = range invalidate (clears the VMID's PT entries
    // from the TLB). flush_type 2 = ALL2 — heavier-weight, used for
    // full bring-up. Linux's gmc_v11_0_flush_gpu_tlb defaults to
    // type 0 for runtime invalidates.
    broadcast_invalidate_tlb(mmio_gfx, regs_gfx, mmio_mm, regs_mm, vmid, 0)
}

// ── Test support ───────────────────────────────────────────────────

pub mod test_support {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec::Vec;

    /// Mock MMIO. Tracks all writes + stages reads-per-offset.
    #[derive(Debug, Default)]
    pub struct MockVmHubMmio {
        pub writes: Vec<(u32, u32)>,
        pub reads: VecDeque<(u32, u32)>,
        /// `Some` => after `n` polls, ack bit appears (for TLB tests).
        pub auto_ack_after: Option<(u32, u32)>,
        pub poll_count: u32,
    }

    impl MockVmHubMmio {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl VmHubMmio for MockVmHubMmio {
        fn read(&mut self, byte_off: u32) -> u32 {
            if let Some(staged) = self.reads.pop_front() {
                if staged.0 == byte_off {
                    return staged.1;
                }
                // Mismatched stage; put it back + fall through.
                self.reads.push_front(staged);
            }
            if let Some((ack_off, ack_val)) = self.auto_ack_after {
                if byte_off == ack_off {
                    self.poll_count += 1;
                    if self.poll_count > 2 {
                        return ack_val;
                    }
                }
            }
            0
        }
        fn write(&mut self, byte_off: u32, value: u32) {
            self.writes.push((byte_off, value));
        }
    }
}

// ── Smoke tests ────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::test_support::MockVmHubMmio;
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_phoenix_gfxhub_offsets_stride() -> TestResult {
        // ctx_addr_distance = 2 means VMID 1's base reg = 0x16f3 + 2 = 0x16f5.
        // That matches regGCVM_CONTEXT1_PAGE_TABLE_BASE_ADDR_LO32 verbatim.
        let r = GFXHUB_V3_0;
        if r.ctx0_pt_base_lo + r.ctx_addr_distance != 0x16f5 {
            return TestResult::Fail("VMID1 base lo stride mismatch");
        }
        if r.ctx0_cntl + r.ctx_distance != 0x1689 {
            return TestResult::Fail("VMID1 cntl stride mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_phoenix_gfxhub_offsets_stride);

    fn smoke_renoir_mmhub_offsets() -> TestResult {
        let r = MMHUB_V2_3;
        // Linux mmMMVM_CONTEXT0_PAGE_TABLE_BASE_ADDR_LO32 = 0x0940.
        if r.ctx0_pt_base_lo != 0x0940 {
            return TestResult::Fail("MMHUB v2.3 base lo wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_renoir_mmhub_offsets);

    fn smoke_regs_for_family_hub_mapping() -> TestResult {
        if regs_for(Family::Phoenix, VmHub::Gfx).is_none() {
            return TestResult::Fail("Phoenix Gfx missing");
        }
        if regs_for(Family::Phoenix, VmHub::Mm).is_none() {
            return TestResult::Fail("Phoenix Mm missing");
        }
        if regs_for(Family::Renoir, VmHub::Gfx).is_none() {
            return TestResult::Fail("Renoir Gfx missing");
        }
        if regs_for(Family::Renoir, VmHub::Mm).is_none() {
            return TestResult::Fail("Renoir Mm missing");
        }
        if regs_for(Family::Vega, VmHub::Gfx).is_some() {
            return TestResult::Fail("Vega should be unmapped");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_regs_for_family_hub_mapping);

    fn smoke_write_vmid_pt_base_writes_lo_hi_pair() -> TestResult {
        let mut m = MockVmHubMmio::new();
        // VMID 3, pt root = 0xCAFE_BABE_DEAD_0000.
        write_vmid_pt_base(&mut m, &GFXHUB_V3_0, 3, 0xCAFE_BABE_DEAD_0000);
        if m.writes.len() != 2 {
            return TestResult::Fail("expected 2 writes for base addr");
        }
        // VMID 3 stride = 3 * 2 = 6.
        // base lo offset = (0x16f3 + 6) << 2.
        let want_lo = (0x16f3u32 + 6) << 2;
        if m.writes[0].0 != want_lo {
            return TestResult::Fail("lo offset wrong");
        }
        if m.writes[0].1 != 0xDEAD_0000 {
            return TestResult::Fail("lo value wrong");
        }
        // hi offset = (0x16f4 + 6) << 2.
        let want_hi = (0x16f4u32 + 6) << 2;
        if m.writes[1].0 != want_hi {
            return TestResult::Fail("hi offset wrong");
        }
        if m.writes[1].1 != 0xCAFE_BABE {
            return TestResult::Fail("hi value wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_write_vmid_pt_base_writes_lo_hi_pair);

    fn smoke_write_vmid0_aperture_writes_4_dwords() -> TestResult {
        let mut m = MockVmHubMmio::new();
        write_vmid0_aperture(&mut m, &GFXHUB_V3_0, 0, 0x000F_FFFF);
        if m.writes.len() != 4 {
            return TestResult::Fail("expected 4 writes (start lo/hi end lo/hi)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_write_vmid0_aperture_writes_4_dwords);

    fn smoke_write_vmid_cntl_enables_context() -> TestResult {
        let mut m = MockVmHubMmio::new();
        write_vmid_cntl(&mut m, &GFXHUB_V3_0, 0, 0, true);
        if m.writes.len() != 1 {
            return TestResult::Fail("expected 1 write");
        }
        let (_, val) = m.writes[0];
        if val & CTX_CNTL_ENABLE_CONTEXT == 0 {
            return TestResult::Fail("enable bit not set");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_write_vmid_cntl_enables_context);

    fn smoke_invalidate_tlb_polls_ack() -> TestResult {
        let mut m = MockVmHubMmio::new();
        // Set up: ack reads 0 twice, then bit-for-VMID-2 appears.
        m.auto_ack_after = Some(((GFXHUB_V3_0.inv_eng0_ack << 2) as u32, 1 << 2));
        let r = write_invalidate_tlb(&mut m, &GFXHUB_V3_0, 2, 0);
        if r.is_err() {
            return TestResult::Fail("tlb invalidate failed");
        }
        // One write to REQ should have happened.
        if !m
            .writes
            .iter()
            .any(|(off, _)| *off == GFXHUB_V3_0.inv_eng0_req << 2)
        {
            return TestResult::Fail("REQ register not written");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_invalidate_tlb_polls_ack);

    fn smoke_invalidate_tlb_bad_vmid_rejected() -> TestResult {
        let mut m = MockVmHubMmio::new();
        if write_invalidate_tlb(&mut m, &GFXHUB_V3_0, 17, 0) != Err(TlbInvalidateError::BadVmid) {
            return TestResult::Fail("VMID 17 should be rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_invalidate_tlb_bad_vmid_rejected);

    fn smoke_broadcast_invalidate_writes_both_hubs() -> TestResult {
        let mut g = MockVmHubMmio::new();
        let mut m = MockVmHubMmio::new();
        g.auto_ack_after = Some(((GFXHUB_V3_0.inv_eng0_ack << 2) as u32, 1 << 5));
        m.auto_ack_after = Some(((MMHUB_V3_0.inv_eng0_ack << 2) as u32, 1 << 5));
        broadcast_invalidate_tlb(&mut g, &GFXHUB_V3_0, &mut m, &MMHUB_V3_0, 5, 0)
            .expect("broadcast");
        if !g
            .writes
            .iter()
            .any(|(off, _)| *off == GFXHUB_V3_0.inv_eng0_req << 2)
        {
            return TestResult::Fail("GFX hub not written");
        }
        if !m
            .writes
            .iter()
            .any(|(off, _)| *off == MMHUB_V3_0.inv_eng0_req << 2)
        {
            return TestResult::Fail("MM hub not written");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_broadcast_invalidate_writes_both_hubs);

    fn smoke_invalidate_vmid_full_uses_range_flush_type() -> TestResult {
        let mut g = MockVmHubMmio::new();
        let mut m = MockVmHubMmio::new();
        g.auto_ack_after = Some(((GFXHUB_V3_0.inv_eng0_ack << 2) as u32, 1 << 3));
        m.auto_ack_after = Some(((MMHUB_V3_0.inv_eng0_ack << 2) as u32, 1 << 3));
        invalidate_vmid_full(&mut g, &GFXHUB_V3_0, &mut m, &MMHUB_V3_0, 3).expect("full");
        // The REQ word's flush_type field is bits[7:4]; we passed
        // 0 for range — check the field is 0 in the first write
        // to GFX hub's REQ register.
        let req_off = GFXHUB_V3_0.inv_eng0_req << 2;
        let req_write = g.writes.iter().find(|(off, _)| *off == req_off).unwrap();
        if (req_write.1 >> 4) & 0xF != 0 {
            return TestResult::Fail("flush_type not 0 (range)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_invalidate_vmid_full_uses_range_flush_type
    );
}
