//! AMDGPU GFX / compute / SDMA / VCN ring submission scaffolding — clean-room.
//!
//! Reference: AMD KGD (Kernel-mode Graphics Driver) public ring
//! protocol notes + the public PM4 packet format reference.
//!
//! ## Ring layout
//!
//! Each submission queue is a power-of-two-sized circular buffer
//! of 32-bit dwords. The host maintains a `wptr` (write pointer)
//! that advances as packets are appended; the GPU maintains an
//! independent `rptr` (read pointer) it advances as packets
//! retire. Both pointers are dword-granularity and wrap at
//! `RING_SIZE_DW`.
//!
//! ```text
//! ring buffer (RING_SIZE_DW × 4 bytes, DMA-coherent)
//! +--------+--------+--------+--------+--------+
//! | dword0 | dword1 | dword2 | ...    | dwordN |
//! +--------+--------+--------+--------+--------+
//!         ^                  ^
//!         rptr (GPU)         wptr (host)
//! ```
//!
//! Doorbell ring: write `wptr` to a per-queue doorbell offset
//! within BAR2. The doorbell hardware notifies the GPU that
//! `wptr` advanced.
//!
//! ## Pointers are free-running
//!
//! `wptr` and `rptr` count dwords ever written and ever consumed; they are
//! masked only when used as an index. That is Linux's model
//! (`ring->wptr & ring->buf_mask`) and it exists so `wptr == rptr` means EMPTY
//! and `wptr - rptr == RING_SIZE_DW` means FULL. A ring that stored the masked
//! pointers could not tell those two apart and would have to waste a dword to
//! keep them distinct.
//!
//! ## Filler is a NOP PACKET, not zero
//!
//! An unwritten ring dword must decode to something harmless, and **zero does
//! not**: a zero dword is PM4 TYPE0 with register 0 and count 0, which tells
//! the command processor to write the following dword into register 0. Linux
//! fills with `PACKET3(PACKET3_NOP, 0x3FFF)` (`gfx_v11_0.c`'s `.nop`), and so
//! does this.
//!
//! [`Ring`] takes the GPU's `rptr` as a parameter rather than reading it. That
//! is the layering, not a gap: the slot the engine reports into belongs to
//! whoever owns the writeback page, and `Ring` does not.
//! [`crate::amdgpu_gfx::GfxContext`] owns one and
//! `GfxContext::ring_rptr` reads the dword the CP writes there
//! (`gfx_v11_0_ring_get_rptr_gfx` — "gfx11 is 32bit rptr"), passing it in on
//! every submit; [`crate::amdgpu_mes::MesQueue`] does the same for the
//! scheduler's ring.
//!
//! A caller with no writeback page of its own must pass 0, which makes the
//! ring behave as write-once — `submit` starts refusing with
//! [`RingError::Full`] after a ring's worth of dwords. That is the safe
//! direction: the alternative is wrapping over commands the engine has not
//! consumed.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{alloc_coherent, DmaBuffer, DomainId, MmioRegion};

/// Doorbell BAR (BAR2 on Vega/Navi). Each per-queue doorbell is a quadword, so
/// slot N lives at byte offset `N * 8`.
///
/// Linux has TWO doorbell index spaces a dword apart in scale, and mixing them
/// is a silent factor-of-two:
///
///   * The **assignment enum** — `AMDGPU_NAVI10_DOORBELL_GFX_RING0` = 0x08B,
///     `..._MEC_RING0` = 0x003, `..._sDMA_ENGINE0` = 0x100 — is in QWORDs.
///     `amdgpu_doorbell.h` says so above `AMDGPU_DOORBELL64_ASSIGNMENT`:
///     "64bit doorbell, offset are in QWORD, occupy 2KB doorbell space". The
///     `..._DOORBELL64_VCN0_1` entry's comment, "lower 32 bits for VNC0 and
///     upper 32 bits for VNC1", is the same statement from the other side: one
///     index, two 32-bit engines.
///   * `amdgpu_ring::doorbell_index` is in DWORDs, because
///     `amdgpu_mm_wdoorbell64` indexes a `uint32_t *cpu_addr`
///     (`amdgpu_doorbell_mgr.c`) — byte address `cpu_addr + index`, i.e.
///     `index * 4`. That is why every ring setup converts:
///     `ring->doorbell_index = adev->doorbell_index.gfx_ring0 << 1`
///     (`gfx_v11_0.c:1178`, `mes_v11_0.c:1652`, `vcn_v4_0.c:222`).
///
/// [`Ring::new`]'s `queue_idx` is the **assignment-enum** space, the QWORD one,
/// so `AMDGPU_NAVI10_DOORBELL_*` values drop straight in and the byte offset
/// works out the same either way: `0x08B * 8` here against Linux's
/// `(0x08B << 1) * 4`. Do not pass a `ring->doorbell_index`; that is already
/// doubled.
pub const DOORBELL_STRIDE_BYTES: u64 = 8;

/// Which engine's doorbell protocol a ring speaks. The payload is NOT uniform
/// across AMD engines, so a ring has to know:
///
///   * GFX, compute and MES write the dword `wptr` as a quadword —
///     `WDOORBELL64(ring->doorbell_index, ring->wptr)`
///     (`gfx_v11_0.c::gfx_v11_0_ring_set_wptr_gfx` and `..._compute`,
///     `mes_v11_0.c:87`).
///   * SDMA writes the same pointer in BYTES —
///     `WDOORBELL64(ring->doorbell_index, ring->wptr << 2)`
///     (`sdma_v6_0.c::sdma_v6_0_ring_set_wptr`). A dword value here would
///     announce a pointer four times short of the truth.
///   * VCN writes only the low 32 bits, as a dword count —
///     `WDOORBELL32(ring->doorbell_index, lower_32_bits(ring->wptr))`
///     (`vcn_v4_0.c::vcn_v4_0_unified_ring_set_wptr`).
///
/// Adding an engine is adding a variant plus its arm in
/// [`Ring::doorbell_payload`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DoorbellKind {
    /// Quadword doorbell carrying a dword pointer: GFX, compute, MES.
    Gfx,
    /// Quadword doorbell carrying a byte pointer: SDMA.
    Sdma,
    /// Dword doorbell carrying a dword pointer: VCN.
    Vcn,
}

/// Ring size in dwords. 1024 is a comfortable middle-ground —
/// enough headroom for ~50 PM4 IB-submission groups before the
/// host has to wait on the GPU; small enough that one 4-KiB DMA
/// page covers the full ring.
pub const RING_SIZE_DW: usize = 1024;
const RING_BYTES: usize = RING_SIZE_DW * 4;

/// One GFX, compute, SDMA or VCN submission ring. Backed by a DMA-coherent
/// page; the GPU reads from `phys_addr()` directly.
#[derive(Debug)]
pub struct Ring {
    /// DMA-coherent backing of the ring buffer.
    backing: DmaBuffer,
    /// Host-side write pointer, in dwords ever written. Free-running: masked
    /// only when indexing. See the module header.
    wptr_dw: u64,
    /// Per-queue doorbell offset within BAR2.
    doorbell_off: u64,
    /// Which engine's doorbell protocol this ring speaks.
    kind: DoorbellKind,
    /// Queue index for diagnostics, in the assignment-enum (QWORD) space.
    pub queue_idx: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingError {
    /// Allocation of the ring backing failed.
    NoMemory,
    /// The packet is larger than the ring could ever hold.
    TooLarge,
    /// The GPU has not consumed enough for this packet to fit. The caller
    /// waits for `rptr` to advance and retries — overwriting unconsumed
    /// dwords would corrupt a command the engine is still executing.
    Full,
}

/// The value `kind`'s doorbell carries for a write pointer of `wptr_dw`
/// dwords.
///
/// Free-standing rather than a method so the conversion is testable at pointer
/// values a ring cannot be walked to, and so adding an engine is one arm here.
/// See [`DoorbellKind`] for the per-engine citations.
pub const fn doorbell_payload_for(kind: DoorbellKind, wptr_dw: u64) -> u64 {
    match kind {
        DoorbellKind::Gfx => wptr_dw,
        // `ring->wptr << 2`: SDMA's doorbell is a byte pointer.
        DoorbellKind::Sdma => wptr_dw << 2,
        // `lower_32_bits(ring->wptr)`: VCN's doorbell is 32 bits wide, so the
        // high half of a rolled-over pointer is not announced at all.
        DoorbellKind::Vcn => (wptr_dw as u32) as u64,
    }
}

/// `PACKET3(PACKET3_NOP, 0x3FFF)` — `gfx_v11_0.c`'s `.nop`.
///
/// A whole-ring filler and the padding between packets. The count field is
/// maximal because the header alone is the no-op: the command processor skips
/// `count + 1` following dwords, so one header covers the rest of the ring.
pub const NOP_DW: u32 =
    crate::amdgpu_pm4_defs::packet3(crate::amdgpu_pm4_defs::PACKET3_NOP, 0x3FFF);

impl Ring {
    /// Allocate a fresh ring + compute its doorbell offset for the given queue
    /// index.
    ///
    /// `queue_idx` is an `AMDGPU_NAVI10_DOORBELL_*` assignment value — the
    /// QWORD index space; see [`DOORBELL_STRIDE_BYTES`]. `kind` selects the
    /// doorbell payload, which differs per engine; see [`DoorbellKind`].
    pub fn new(queue_idx: u16, kind: DoorbellKind) -> Result<Self, RingError> {
        let backing =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| RingError::NoMemory)?;
        // Fill with the NOP PACKET. This used to write zeros, described as
        // "PM4 TYPE0 with count 0 = a benign 1-dword no-op" — it is not one.
        // A zero dword IS a TYPE0 header, naming register 0 with a count of 0,
        // which tells the command processor to write the NEXT dword into
        // register 0. An engine that ran off the end of the written region
        // would walk the rest of the ring writing zeros into register 0.
        // SAFETY: identity-mapped DMA-coherent page; we own it.
        unsafe {
            for i in 0..RING_SIZE_DW {
                core::ptr::write_volatile(backing.cpu_mut_ptr_at::<u32>((i * 4) as u64), NOP_DW);
            }
        }
        Ok(Self {
            backing,
            wptr_dw: 0,
            doorbell_off: queue_idx as u64 * DOORBELL_STRIDE_BYTES,
            kind,
            queue_idx,
        })
    }

    /// Phys address of the ring's first dword. Programmed into
    /// the GPU's CP_RB_BASE / SDMA_GFX_RB_BASE registers at GFX
    /// bring-up.
    pub fn phys_addr(&self) -> u64 {
        self.backing.dma_addr().raw()
    }

    /// Host write-pointer, in dwords ever written.
    pub fn wptr(&self) -> u64 {
        self.wptr_dw
    }

    /// Dwords the GPU has not yet consumed, given its `rptr`.
    pub fn used_dw(&self, rptr_dw: u64) -> u64 {
        self.wptr_dw.wrapping_sub(rptr_dw)
    }

    /// Dwords that may be written without overwriting unconsumed commands.
    pub fn free_dw(&self, rptr_dw: u64) -> u64 {
        (RING_SIZE_DW as u64).saturating_sub(self.used_dw(rptr_dw))
    }

    /// One dword at the masked index, for tests and for dumping a hung ring.
    ///
    /// # Safety
    /// The ring's backing must still be mapped.
    pub unsafe fn peek(&self, index_dw: u64) -> u32 {
        let off = (index_dw & (RING_SIZE_DW as u64 - 1)) * 4;
        // SAFETY: the index is masked into the ring, and the caller holds the
        // backing alive.
        unsafe { core::ptr::read_volatile(self.backing.cpu_ptr_at::<u32>(off)) }
    }

    /// Write one dword at the current wptr and advance it, wrapping.
    ///
    /// # Safety
    /// The caller has already checked there is room.
    unsafe fn put(&mut self, value: u32) {
        let off = (self.wptr_dw & (RING_SIZE_DW as u64 - 1)) * 4;
        // SAFETY: the offset is masked into the ring's own page.
        unsafe {
            core::ptr::write_volatile(self.backing.cpu_mut_ptr_at::<u32>(off), value);
        }
        self.wptr_dw = self.wptr_dw.wrapping_add(1);
    }

    /// Pad with `count` NOP dwords, wrapping as needed
    /// (`amdgpu_ring_insert_nop`).
    ///
    /// # Safety
    /// As [`Ring::submit`].
    pub unsafe fn insert_nop(&mut self, count: usize, rptr_dw: u64) -> Result<u64, RingError> {
        if count as u64 > self.free_dw(rptr_dw) {
            return Err(RingError::Full);
        }
        for _ in 0..count {
            // SAFETY: room checked above.
            unsafe { self.put(NOP_DW) };
        }
        Ok(self.wptr_dw)
    }

    /// Pad with NOPs until the write pointer is a multiple of `align_dw`.
    ///
    /// GFX11 wants an indirect-buffer packet aligned so the command processor
    /// fetches it in one burst; `amdgpu_ring_commit` pads to
    /// `ring->funcs->align_mask` for the same reason.
    ///
    /// # Safety
    /// As [`Ring::submit`].
    pub unsafe fn align_to(&mut self, align_dw: u64, rptr_dw: u64) -> Result<u64, RingError> {
        if align_dw <= 1 || !align_dw.is_power_of_two() {
            return Err(RingError::TooLarge);
        }
        let pad = (align_dw - (self.wptr_dw & (align_dw - 1))) & (align_dw - 1);
        // SAFETY: delegated.
        unsafe { self.insert_nop(pad as usize, rptr_dw) }
    }

    /// Doorbell BAR2 byte offset for this queue.
    pub fn doorbell_offset(&self) -> u64 {
        self.doorbell_off
    }

    /// `ring->doorbell_index` — this queue's doorbell in the **DWORD** index
    /// space, which is twice the `AMDGPU_NAVI10_DOORBELL_*` assignment value
    /// [`Ring::new`] was given. Every ring setup in Linux writes
    /// `adev->doorbell_index.<ring> << 1` into this field, and it is the value
    /// the MES legacy-queue mapping and the CP's `*_DOORBELL_CONTROL`
    /// `OFFSET` field both carry — not the assignment value. See
    /// [`DOORBELL_STRIDE_BYTES`] for why there are two spaces at all.
    pub fn doorbell_index_dw(&self) -> u32 {
        u32::from(self.queue_idx) << 1
    }

    /// Append `packet` (already-formatted dwords) to the ring.
    /// Returns the new wptr in dwords.
    ///
    /// Stage-4 cut: rejects the packet with
    /// `NotEnoughRoomBeforeWrap` rather than emitting a NOP
    /// filler when the packet would straddle the ring boundary.
    /// The Stage-5 expansion adds a `nop_to_wrap()` helper.
    ///
    /// # Safety
    /// Caller serialises ring access. Submission to a live GPU
    /// engine additionally requires the GFX firmware to be
    /// loaded; otherwise the ring sits idle.
    pub unsafe fn submit(&mut self, packet: &[u32], rptr_dw: u64) -> Result<u64, RingError> {
        if packet.len() > RING_SIZE_DW {
            return Err(RingError::TooLarge);
        }
        // The check is against what the GPU has CONSUMED, not against the end
        // of the buffer. A ring is circular: a packet may straddle the wrap
        // freely, and what it must never do is overwrite a dword the engine
        // has not read yet.
        if packet.len() as u64 > self.free_dw(rptr_dw) {
            return Err(RingError::Full);
        }
        for &w in packet {
            // SAFETY: room checked above.
            unsafe { self.put(w) };
        }
        // The dwords must be visible before the doorbell announces them.
        compiler_fence(Ordering::SeqCst);
        Ok(self.wptr_dw)
    }

    /// The value this engine's doorbell carries for the current `wptr`.
    pub fn doorbell_payload(&self) -> u64 {
        doorbell_payload_for(self.kind, self.wptr_dw)
    }

    /// Ring the per-queue doorbell. Writes the payload to BAR2 +
    /// `doorbell_off`; the GPU's doorbell hardware translates that into a
    /// "ring wptr advanced" signal to the engine.
    ///
    /// GFX and SDMA doorbells are a single quadword access
    /// (`amdgpu_mm_wdoorbell64` is an `atomic64_set`), VCN's a single dword
    /// (`WDOORBELL32`).
    ///
    /// This used to write the low half and then a literal zero to the high
    /// half, described as "only the low 32 bits carry the wptr; the upper 32
    /// are reserved". They are not reserved: the pointer is free-running and
    /// 64-bit, as this module's own header says, so zeroing the high half
    /// announces a wptr 2^32 dwords in the past once one ever rolls over. Two
    /// stores also let the engine latch a half-updated quadword, which is why
    /// Linux uses one atomic 64-bit write.
    ///
    /// LINUX-GAP: Linux also publishes the pointer to a host-memory shadow
    /// (`atomic64_set(ring->wptr_cpu_addr, ..)`) immediately before the
    /// doorbell, which is what the engine reads when doorbells are off and
    /// what MES polls. That needs the queue descriptor the firmware consumes —
    /// the same gap as `rptr` in the header above.
    ///
    /// # Safety
    /// `bar2` must map the doorbell window of the corresponding AMD GPU;
    /// caller owns the doorbell range exclusively while this queue is alive.
    pub unsafe fn ring_doorbell(&self, bar2: &MmioRegion) {
        let payload = self.doorbell_payload();
        // SAFETY: caller-asserted ownership; the offset is a multiple of
        // DOORBELL_STRIDE_BYTES and so quadword-aligned.
        unsafe {
            match self.kind {
                DoorbellKind::Gfx | DoorbellKind::Sdma => bar2.write64(self.doorbell_off, payload),
                DoorbellKind::Vcn => bar2.write32(self.doorbell_off, payload as u32),
            }
        }
    }
}
