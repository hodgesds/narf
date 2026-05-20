//! AMD Interrupt Handler (IH) ring.
//!
//! The IH is the chip's interrupt aggregator. Every IP block
//! (DCN, GFX, SDMA, MES, MMHUB, ATHUB, OSS, …) routes its
//! interrupt sources into the IH, which writes 8-byte interrupt
//! cookies onto a host-visible ring buffer. The host drains
//! the ring via the IH PIC's wptr / rptr registers and the
//! per-cookie source_id tells the driver which IP to dispatch to.
//!
//! Modern AMD parts (Vega+) expose a ring per "client":
//! - **Ring 0** — main host CPU interrupts (DCN VBlank, GFX
//!   completion, SDMA fence, page faults).
//! - **Ring 1** — page-fault retry stream.
//! - **Ring 2** — for the on-die MES microcontroller.
//!
//! This module owns the ring 0 bring-up shape (the one the host
//! cares about). Cookie format + decode is shared across rings.
//!
//! ## Sequence (IH v4 — Vega / Renoir; structurally same on Navi)
//!
//! Per `drivers/gpu/drm/amd/amdgpu/vega10_ih.c::vega10_ih_irq_init`:
//!
//!   1. **Disable**. `IH_RB_CNTL = 0` so the IH stops pushing
//!      cookies while we re-program.
//!   2. **Program base**. `IH_RB_BASE = phys >> 8;
//!      IH_RB_BASE_HI = phys >> 40`.
//!   3. **Program wptr writeback**. `IH_RB_WPTR_ADDR_LO / _HI`
//!      — host buffer the IH updates as cookies are pushed.
//!   4. **Reset rptr / wptr**. `IH_RB_RPTR = 0; IH_RB_WPTR = 0`.
//!   5. **Program size + writeback enable + overflow handling**.
//!      `IH_RB_CNTL = (RB_SIZE = log2(size_dw)) << 1
//!                  | RB_GPU_TS_ENABLE (timestamp on each cookie)
//!                  | WPTR_WRITEBACK_ENABLE
//!                  | OVERFLOW_CLEAR  (so a stale overflow flag
//!                                     from prior boot doesn't latch)`.
//!   6. **Program doorbell**. `IH_DOORBELL_RPTR = (idx << 2)
//!                                              | DOORBELL_ENABLE`.
//!   7. **Enable**. `IH_RB_CNTL |= RB_ENABLE` — IH starts
//!      writing cookies into the ring.
//!
//! Linux references (post 2026-05-20 GPL relicense):
//! - `drivers/gpu/drm/amd/amdgpu/vega10_ih.c` (Vega / Renoir)
//! - `drivers/gpu/drm/amd/amdgpu/navi10_ih.c` (Navi 1–3)
//! - `drivers/gpu/drm/amd/amdgpu/ih_v6_0.c` (Phoenix)
//! - `oss/osssys_4_0_offset.h` — register defs.

extern crate alloc;

use alloc::vec::Vec;

// ── IH register offsets (dword-indexed; multiply by 4 for byte) ────
//
// Values from oss/osssys_4_0_offset.h. Relative to the IH IP-block
// base; resolved via amdgpu_discovery::HW_ID_OSSSYS.

/// `mmIH_RB_CNTL` — ring config + enable + overflow flags.
pub const IH_RB_CNTL_REL: u32 = 0x80 * 4;
/// `mmIH_RB_BASE` — phys >> 8 of the ring backing.
pub const IH_RB_BASE_REL: u32 = 0x81 * 4;
/// `mmIH_RB_BASE_HI` — phys >> 40.
pub const IH_RB_BASE_HI_REL: u32 = 0x82 * 4;
/// `mmIH_RB_RPTR` — host-written / engine-read rptr.
pub const IH_RB_RPTR_REL: u32 = 0x83 * 4;
/// `mmIH_RB_WPTR` — engine-written wptr.
pub const IH_RB_WPTR_REL: u32 = 0x84 * 4;
/// `mmIH_RB_WPTR_ADDR_LO` — wptr writeback target lo.
pub const IH_RB_WPTR_ADDR_LO_REL: u32 = 0x85 * 4;
/// `mmIH_RB_WPTR_ADDR_HI` — wptr writeback target hi.
pub const IH_RB_WPTR_ADDR_HI_REL: u32 = 0x86 * 4;
/// `mmIH_DOORBELL_RPTR` — BAR2 doorbell offset + enable.
pub const IH_DOORBELL_RPTR_REL: u32 = 0x87 * 4;

// ── Field encodings ────────────────────────────────────────────────

/// `IH_RB_CNTL` — enable the ring.
pub const IH_RB_ENABLE: u32 = 1 << 0;
/// `IH_RB_CNTL` — bits[5:1] = log2(ring size in dwords).
pub const IH_RB_SIZE_SHIFT: u32 = 1;
/// `IH_RB_CNTL` — emit GPU timestamps in each cookie (helps log
/// correlation; Linux always sets).
pub const IH_RB_GPU_TS_ENABLE: u32 = 1 << 7;
/// `IH_RB_CNTL` — enable wptr writeback to host.
pub const IH_RB_WPTR_WRITEBACK_ENABLE: u32 = 1 << 8;
/// `IH_RB_CNTL` — clear any stale overflow bit from a prior boot.
pub const IH_RB_OVERFLOW_CLEAR: u32 = 1 << 16;

/// `IH_DOORBELL_RPTR` — enable.
pub const IH_DOORBELL_ENABLE: u32 = 1 << 28;

// ── Cookie decode (8 bytes per interrupt) ───────────────────────────
//
// Each IH cookie is 8 dwords (32 bytes total — not 8 bytes; the
// per-cookie payload is several dwords). On Vega+ the cookie
// layout is:
//
//   dword 0: client_id (bits[7:0]) | source_id (bits[15:8]) | ring_id (bits[23:16])
//   dword 1: vmid (bits[3:0]) | source_data
//   dword 2: pasid
//   dword 3-7: source-specific data
//
// Caller decodes the first dword to dispatch to the right
// per-source handler.

/// One IH interrupt cookie header (dword 0).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IhCookieHeader {
    /// Which IP block raised the interrupt (DCN, GFX, SDMA, …).
    pub client_id: u8,
    /// Per-client source id (e.g. for DCN: HPD, VBlank, VLine, …).
    pub source_id: u8,
    /// Which ring on the source produced the event.
    pub ring_id: u8,
    /// Top byte of dword 0 — reserved on Vega; ASIC-version on Navi.
    pub reserved: u8,
}

impl IhCookieHeader {
    /// Decode the dword-0 field layout.
    pub fn from_dword(dw0: u32) -> Self {
        Self {
            client_id: (dw0 & 0xFF) as u8,
            source_id: ((dw0 >> 8) & 0xFF) as u8,
            ring_id: ((dw0 >> 16) & 0xFF) as u8,
            reserved: ((dw0 >> 24) & 0xFF) as u8,
        }
    }

    /// Round-trip back to dword form (smoke aid + simulator support).
    pub fn to_dword(&self) -> u32 {
        (self.client_id as u32)
            | ((self.source_id as u32) << 8)
            | ((self.ring_id as u32) << 16)
            | ((self.reserved as u32) << 24)
    }
}

// ── Source / client constants ──────────────────────────────────────
//
// Subset of soc15_ih_clientid.h + soc15_ih_sourcid.h — the ones
// the bring-up arc cares about. Phoenix adds a few new clients
// (MES, MMHUB1) but the ones below are stable across families.

/// `SOC15_IH_CLIENTID_GRBM_CP` — GFX command processor.
pub const CLIENT_ID_GFX: u8 = 0x05;
/// `SOC15_IH_CLIENTID_DCE` — Display Core Engine (DCN).
pub const CLIENT_ID_DCN: u8 = 0x06;
/// `SOC15_IH_CLIENTID_SDMA0` — first SDMA instance.
pub const CLIENT_ID_SDMA0: u8 = 0x08;
/// `SOC15_IH_CLIENTID_SDMA1` — second SDMA instance (Renoir/Vega).
pub const CLIENT_ID_SDMA1: u8 = 0x09;
/// `SOC15_IH_CLIENTID_VMC` — page faults from the memory controller.
pub const CLIENT_ID_VMC: u8 = 0x09;

/// DCN-side source id: VBlank rising-edge on a controller. Adds
/// the controller index in the source-data field.
pub const SOURCE_ID_DCN_VBLANK: u8 = 0x07;
/// DCN-side source id: HPD (hot-plug detect) on a connector.
pub const SOURCE_ID_DCN_HPD: u8 = 0x2A;

// ── Sequence shape ─────────────────────────────────────────────────

/// Errors building the IH ring-init sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IhError {
    /// `ring_size_dw` isn't a power of two between 8 and `1 << 20`.
    BadRingSize,
    /// `ring_phys` isn't 256-byte aligned. IH RB_BASE encodes
    /// `phys >> 8`.
    UnalignedRingPhys,
    /// `wptr_writeback_phys` isn't 4-byte aligned.
    UnalignedWptrWriteback,
}

/// One MMIO write in an IH ring-init sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IhWrite {
    pub addr: u32,
    pub value: u32,
}

/// Ordered list of IH register writes for one ring bring-up.
#[derive(Default, Debug)]
pub struct IhRingInitSequence {
    pub writes: Vec<IhWrite>,
}

impl IhRingInitSequence {
    pub fn len(&self) -> usize {
        self.writes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
    pub fn iter(&self) -> core::slice::Iter<'_, IhWrite> {
        self.writes.iter()
    }
    fn push(&mut self, addr: u32, value: u32) {
        self.writes.push(IhWrite { addr, value });
    }
}

/// Build the IH v4 ring-init sequence. `ih_base` is the IP-block
/// base of OSSSYS (the IH lives inside the OSSSYS block).
pub fn build_ih4_ring_init(
    ih_base: u32,
    ring_phys: u64,
    ring_size_dw: u32,
    doorbell_idx: u32,
    wptr_writeback_phys: u64,
) -> Result<IhRingInitSequence, IhError> {
    if !ring_size_dw.is_power_of_two() || ring_size_dw < 8 || ring_size_dw > (1 << 20) {
        return Err(IhError::BadRingSize);
    }
    if ring_phys & 0xFF != 0 {
        return Err(IhError::UnalignedRingPhys);
    }
    if wptr_writeback_phys & 0x3 != 0 {
        return Err(IhError::UnalignedWptrWriteback);
    }

    let mut seq = IhRingInitSequence::default();

    // Step 1: disable.
    seq.push(ih_base + IH_RB_CNTL_REL, 0);

    // Step 2: ring base.
    seq.push(ih_base + IH_RB_BASE_REL, (ring_phys >> 8) as u32);
    seq.push(ih_base + IH_RB_BASE_HI_REL, (ring_phys >> 40) as u32);

    // Step 3: wptr writeback.
    seq.push(
        ih_base + IH_RB_WPTR_ADDR_LO_REL,
        wptr_writeback_phys as u32,
    );
    seq.push(
        ih_base + IH_RB_WPTR_ADDR_HI_REL,
        (wptr_writeback_phys >> 32) as u32,
    );

    // Step 4: reset r/wptr.
    seq.push(ih_base + IH_RB_RPTR_REL, 0);
    seq.push(ih_base + IH_RB_WPTR_REL, 0);

    // Step 5: program size + writeback + clear overflow (no
    // RB_ENABLE yet — last write enables).
    let log2_size = ring_size_dw.trailing_zeros();
    let cntl_no_enable = (log2_size << IH_RB_SIZE_SHIFT)
        | IH_RB_GPU_TS_ENABLE
        | IH_RB_WPTR_WRITEBACK_ENABLE
        | IH_RB_OVERFLOW_CLEAR;
    seq.push(ih_base + IH_RB_CNTL_REL, cntl_no_enable);

    // Step 6: doorbell.
    seq.push(
        ih_base + IH_DOORBELL_RPTR_REL,
        IH_DOORBELL_ENABLE | (doorbell_idx << 2),
    );

    // Step 7: enable (LAST write).
    seq.push(
        ih_base + IH_RB_CNTL_REL,
        cntl_no_enable | IH_RB_ENABLE,
    );

    Ok(seq)
}
