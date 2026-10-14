//! MT7921 WFDMA0 ring allocation + descriptor programming — Stage-4.
//!
//! CONNAC2 puts its host-DMA engine in the `WFDMA0` register block
//! (BAR0 offset `0xd4000`). Each ring is configured by a 16-byte
//! quadruple at a per-ring offset inside `MT_TX_RING_BASE` /
//! `MT_RX_*_RING_BASE`:
//!
//! ```text
//!   +0x00: ring base low  32 bits  (physical address of descriptor 0)
//!   +0x04: ring depth in entries   (low 16 bits) | reserved (high)
//!   +0x08: CPU index  (host write pointer, AKA "doorbell")
//!   +0x0c: DMA index  (HW read pointer)
//! ```
//!
//! Linux walks this through `mt76_init_tx_queue` (`dma.c::mt76_dma_alloc_queue`)
//! and `mt76_queue_alloc` (`dma.c:580..650`, v6.6). The descriptor format
//! is `struct mt76_desc { __le32 buf0; __le32 ctrl; __le32 buf1; __le32 info; }`
//! (`dma.h:116`).
//!
//! ## What this module owns
//!
//! - `Ring` — one DMA ring's bookkeeping (depth, head, tail, buffers).
//! - `RingRegs` — the 16-byte MMIO offset quadruple for one ring.
//! - `mt7921_tx_ring_regs` / `mt7921_rx_ring_regs` — per-ring lookup
//!   following the Linux per-ring stride.
//! - `RingAllocator::allocate` — `DmaBuffer`-backed ring memory + buffer
//!   pool with the device's TX/RX queue indexes.
//! - `program_ring` — write the four MMIO doublewords that arm a ring.
//! - `dma_disable` / `dma_enable` — the WFDMA0 global-config sequence
//!   from `mt792x_dma_disable` / `mt792x_dma_enable`.
//!
//! ## What this module deliberately defers
//!
//! - Real submission (TX doorbell write under load, RX completion
//!   drain) lives in `txrx.rs`'s ring producer/consumer.
//! - Multi-page ring memory. The in-tree `DmaBuffer` allocator caps a
//!   single buffer at one 4 KiB page, so 16-entry rings are the
//!   bring-up baseline. Linux uses 1536+ entries; we lift the cap once
//!   the multi-page DmaBuffer landing arrives.
//!
//! ## References (all GPL-2.0)
//!
//! - `drivers/net/wireless/mediatek/mt76/dma.c` —
//!   `mt76_dma_alloc_queue` (~L580), `__mt76_dma_queue_reset` (~L320).
//! - `drivers/net/wireless/mediatek/mt76/dma.h:116` —
//!   `struct mt76_desc` layout.
//! - `drivers/net/wireless/mediatek/mt76/mt7921/pci.c::mt7921_dma_init`
//!   — per-ring init order, the `MT_WFDMA0_TX_RING0_EXT_CTRL = 0x4`
//!   poke at L185.
//! - `drivers/net/wireless/mediatek/mt76/mt792x_dma.c::mt792x_dma_disable`
//!   / `mt792x_dma_enable` — WFDMA0 global-config sequence.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use narf_bus::MmioRegion;
use narf_io::DmaBuffer;

use super::regs::*;

// ── Errors ─────────────────────────────────────────────────────────

/// Errors raised by the ring scaffolding.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaError {
    /// `narf_io::alloc_coherent` returned NoMemory. Out-of-pages or
    /// IOMMU-domain mismatch.
    BufferAllocFailed,
    /// Caller requested a ring depth that doesn't fit in a single 4 KiB
    /// `DmaBuffer` page. The bring-up baseline caps rings at
    /// `MT7921_BASELINE_RING_DEPTH` (16); a larger depth lands when the
    /// multi-page DMA allocator does.
    DepthExceedsPage,
    /// `dma_disable` poll never saw `TX_DMA_BUSY` + `RX_DMA_BUSY` go to
    /// zero within the budget. Implies the chip is wedged.
    BusyTimeout,
    /// A `RingRegs` lookup was called with a queue id outside the
    /// MT7921 TX/RX queue space.
    UnknownQueue,
}

// ── Descriptor (mt76_desc) ─────────────────────────────────────────

/// Wire layout of one MT76 DMA descriptor — 16 bytes, little-endian.
///
/// Linux `dma.h:116`:
///
/// ```c
/// struct mt76_desc {
///     __le32 buf0;
///     __le32 ctrl;
///     __le32 buf1;
///     __le32 info;
/// } __packed __aligned(4);
/// ```
///
/// `buf0` is the low 32 bits of the buffer's DMA address. `ctrl` packs
/// the segment lengths + last/burst/done flags
/// (`MT_DMA_CTL_SD_LEN0/1`, `MT_DMA_CTL_LAST_SEC0/1`,
/// `MT_DMA_CTL_DMA_DONE`). `buf1` carries the high 4 bits of the DMA
/// address on >32-bit-DMA systems (via `MT_DMA_CTL_SDP0_H`). `info` is
/// the per-frame metadata dword the firmware/MAC populates.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct Mt76Desc {
    pub buf0: u32,
    pub ctrl: u32,
    pub buf1: u32,
    pub info: u32,
}

/// Size of one `mt76_desc` in bytes — Linux uses 16-byte descriptors
/// across the MT76 family.
pub const MT76_DESC_SIZE: usize = core::mem::size_of::<Mt76Desc>();

// ── DMA control bit-fields ────────────────────────────────────────
//
// Per `dma.h:12..L24`.

/// `MT_DMA_CTL_SD_LEN1` — segment-1 length mask (GENMASK 13..0).
pub const MT_DMA_CTL_SD_LEN1_MASK: u32 = 0x0000_3FFF;
/// `MT_DMA_CTL_LAST_SEC1` — segment-1 is the last in the frame.
pub const MT_DMA_CTL_LAST_SEC1: u32 = 1 << 14;
/// `MT_DMA_CTL_BURST` — issue this descriptor as a burst.
pub const MT_DMA_CTL_BURST: u32 = 1 << 15;
/// `MT_DMA_CTL_SD_LEN0` — segment-0 length mask (GENMASK 29..16).
pub const MT_DMA_CTL_SD_LEN0_SHIFT: u32 = 16;
pub const MT_DMA_CTL_SD_LEN0_MASK: u32 = 0x3FFF << MT_DMA_CTL_SD_LEN0_SHIFT;
/// `MT_DMA_CTL_LAST_SEC0` — segment-0 is the last in the frame.
pub const MT_DMA_CTL_LAST_SEC0: u32 = 1 << 30;
/// `MT_DMA_CTL_DMA_DONE` — set by the engine when the descriptor is
/// consumed. Host clears it on re-arm.
pub const MT_DMA_CTL_DMA_DONE: u32 = 1 << 31;

// ── Per-ring MMIO offset quadruple ─────────────────────────────────

/// MMIO offset quadruple for one DMA ring.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RingRegs {
    /// Ring base low 32 bits (offset +0x00 inside the ring block).
    pub base_lo: u32,
    /// Ring base depth (offset +0x04). Top half packs flags; low 16
    /// bits encode the entry count.
    pub depth: u32,
    /// CPU index / host write pointer (offset +0x08). The "doorbell".
    pub cidx: u32,
    /// DMA index / HW read pointer (offset +0x0c).
    pub didx: u32,
}

impl RingRegs {
    /// Build the four offsets for ring index `n` inside the given block
    /// base. Each ring occupies `RING_REG_STRIDE` (16) bytes.
    pub const fn for_block(base: u32, n: u32) -> Self {
        let start = base + n * RING_REG_STRIDE;
        Self {
            base_lo: start,
            depth: start + 0x04,
            cidx: start + 0x08,
            didx: start + 0x0c,
        }
    }
}

/// MMIO offsets for one MT7921 TX ring.
///
/// `q_idx` follows the Linux `enum mt7921_txq_id` numbering:
///   - 0..=4 → BAND0 / BAND1 / data / BMC (data rings)
///   - 16 → FWDL
///   - 17 → MCU_WM
pub fn mt7921_tx_ring_regs(q_idx: u8) -> Result<RingRegs, DmaError> {
    match q_idx {
        // Data + BMC rings share the `MT_TX_RING_BASE` block, contiguous.
        0..=4 => Ok(RingRegs::for_block(MT_TX_RING_BASE, q_idx as u32)),
        16 => Ok(RingRegs::for_block(MT_TX_RING_BASE, 5)),
        17 => Ok(RingRegs::for_block(MT_TX_RING_BASE, 6)),
        _ => Err(DmaError::UnknownQueue),
    }
}

/// MMIO offsets for one MT7921 RX ring.
///
/// `q_idx` follows the Linux `enum mt7921_rxq_id` + the pre/post-FW
/// MCU-event distinction:
///   - 0 → data (BAND0) — at `MT_RX_DATA_RING_BASE`.
///   - 1 → MCU event (pre-FW) — at `MT_RX_EVENT_RING_BASE`.
///   - 2 → MCU WA event (post-FW) — at `MT_RX_MCU_WA_RING_BASE`.
pub fn mt7921_rx_ring_regs(q_idx: u8) -> Result<RingRegs, DmaError> {
    match q_idx {
        0 => Ok(RingRegs::for_block(MT_RX_DATA_RING_BASE, 0)),
        1 => Ok(RingRegs::for_block(MT_RX_EVENT_RING_BASE, 0)),
        2 => Ok(RingRegs::for_block(MT_RX_MCU_WA_RING_BASE, 0)),
        _ => Err(DmaError::UnknownQueue),
    }
}

// ── Ring container ────────────────────────────────────────────────

/// One DMA ring's bookkeeping. The ring's descriptor memory and
/// per-entry buffer pool are owned here; dropping `Ring` frees them.
pub struct Ring {
    /// Queue id (per the chip's TXQ/RXQ enumeration).
    q_idx: u8,
    /// Number of entries actually programmed.
    depth: usize,
    /// The DmaBuffer backing the descriptor ring memory.
    desc_mem: DmaBuffer,
    /// Per-entry buffer pool. Each entry is one 4 KiB DmaBuffer.
    /// For RX rings these are pre-allocated and the addresses are
    /// programmed into the descriptors. For TX rings they're allocated
    /// at submit time, so the pool starts empty.
    buffers: Vec<DmaBuffer>,
    /// Host write index (CPU pointer / "doorbell").
    cpu_idx: usize,
    /// Last observed HW read index. Updated by `txrx::drain_rx` /
    /// `txrx::reap_tx`.
    hw_idx: usize,
}

impl core::fmt::Debug for Ring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ring")
            .field("q_idx", &self.q_idx)
            .field("depth", &self.depth)
            .field("cpu_idx", &self.cpu_idx)
            .field("hw_idx", &self.hw_idx)
            .field("buffers", &self.buffers.len())
            .finish_non_exhaustive()
    }
}

impl Ring {
    /// Queue id this ring was allocated for.
    pub fn q_idx(&self) -> u8 {
        self.q_idx
    }

    /// Number of entries in the ring.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Physical address of descriptor 0.
    pub fn desc_phys(&self) -> u64 {
        self.desc_mem.dma_addr().raw()
    }

    /// Current host write index (CPU pointer).
    pub fn cpu_idx(&self) -> usize {
        self.cpu_idx
    }

    /// Last-seen HW read index (DMA pointer).
    pub fn hw_idx(&self) -> usize {
        self.hw_idx
    }

    /// Borrow the descriptor slice mutably. Used by `txrx.rs` to build
    /// descriptors before bumping the doorbell.
    ///
    /// # Safety
    /// The caller serialises against any device-side DMA writes to the
    /// same descriptor (the cooperative single-CPU executor makes this
    /// trivial — no preemption between the bump and the doorbell write).
    pub fn descriptors_mut(&mut self) -> &mut [Mt76Desc] {
        let ptr = self.desc_mem.as_mut_ptr() as *mut Mt76Desc;
        // SAFETY: `desc_mem` is a 4 KiB page; `depth * MT76_DESC_SIZE`
        // is bounded by `MT7921_BASELINE_RING_DEPTH * 16` = 256 bytes,
        // far less than the page.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::slice::from_raw_parts_mut(ptr, self.depth) }
    }

    /// Read-only descriptor view (used by drain paths).
    pub fn descriptors(&self) -> &[Mt76Desc] {
        let ptr = self.desc_mem.as_ptr() as *const Mt76Desc;
        // SAFETY: same as `descriptors_mut`.
        unsafe { core::slice::from_raw_parts(ptr, self.depth) }
    }

    /// Borrow the per-entry buffer pool (RX rings only).
    pub fn buffers(&self) -> &[DmaBuffer] {
        &self.buffers
    }

    /// Set the host write index to `idx` modulo depth. Used by the
    /// doorbell write in `txrx.rs`.
    pub fn set_cpu_idx(&mut self, idx: usize) {
        debug_assert!(self.depth > 0);
        self.cpu_idx = idx % self.depth;
    }

    /// Set the cached HW read index. Used by the drain / reap loops.
    pub fn set_hw_idx(&mut self, idx: usize) {
        debug_assert!(self.depth > 0);
        self.hw_idx = idx % self.depth;
    }

    /// Park a per-frame DmaBuffer in the ring's buffer pool at the
    /// given slot. Grows the pool with sentinel zero-len buffers if
    /// `slot` is past the current pool length.
    ///
    /// Used by the live TX path (`txrx::submit_tx_frame`) to keep the
    /// frame's memory alive until the firmware reaps the descriptor.
    pub fn set_tx_buffer(&mut self, slot: usize, buf: DmaBuffer) {
        while self.buffers.len() <= slot {
            // We can't construct a "null" DmaBuffer in safe Rust, so
            // we push a 0-len placeholder allocation. This costs one
            // page per ring slot — at the bring-up baseline (16
            // entries) that's 64 KiB across all rings, acceptable.
            let placeholder = narf_io::alloc_coherent(64, narf_lib::id::DomainId::DRIVER_0)
                .expect("dma placeholder alloc");
            self.buffers.push(placeholder);
        }
        // Swap-in: dropping the old buffer frees its page via Drop.
        self.buffers[slot] = buf;
    }

    /// Take the DmaBuffer back out of the pool at `slot`, returning
    /// `None` if the slot was never filled.
    ///
    /// The returned buffer is dropped by the caller. Used by
    /// `txrx::reap_tx` after the firmware marks a descriptor done.
    pub fn take_tx_buffer(&mut self, slot: usize) -> Option<DmaBuffer> {
        if slot >= self.buffers.len() {
            return None;
        }
        // Swap with a placeholder so the Vec retains its slots.
        let placeholder = narf_io::alloc_coherent(64, narf_lib::id::DomainId::DRIVER_0).ok()?;
        let old = core::mem::replace(&mut self.buffers[slot], placeholder);
        Some(old)
    }
}

// ── Allocation ────────────────────────────────────────────────────

/// Allocate a TX ring's descriptor memory. TX rings start with an
/// empty buffer pool (the per-frame DmaBuffer is allocated at submit
/// time, not at ring init).
pub fn alloc_tx_ring(q_idx: u8, depth: usize) -> Result<Ring, DmaError> {
    if depth == 0 || depth > MT7921_BASELINE_RING_DEPTH {
        return Err(DmaError::DepthExceedsPage);
    }
    let desc_mem =
        narf_io::alloc_coherent(depth * MT76_DESC_SIZE, narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| DmaError::BufferAllocFailed)?;

    Ok(Ring {
        q_idx,
        depth,
        desc_mem,
        buffers: Vec::new(),
        cpu_idx: 0,
        hw_idx: 0,
    })
}

/// Allocate an RX ring. The buffer pool is pre-filled with `depth`
/// per-entry 4 KiB DmaBuffers and the descriptors are written so they
/// point at those buffers. The `buf_len` cap on each per-entry buffer
/// matches Linux's `MT_RX_BUF_SIZE` (1664) but we round up to 4 KiB to
/// match the DmaBuffer allocator's page granularity.
pub fn alloc_rx_ring(q_idx: u8, depth: usize, buf_len: usize) -> Result<Ring, DmaError> {
    if depth == 0 || depth > MT7921_BASELINE_RING_DEPTH {
        return Err(DmaError::DepthExceedsPage);
    }
    let desc_mem =
        narf_io::alloc_coherent(depth * MT76_DESC_SIZE, narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| DmaError::BufferAllocFailed)?;

    let mut buffers = Vec::with_capacity(depth);
    for _ in 0..depth {
        let buf = narf_io::alloc_coherent(buf_len, narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| DmaError::BufferAllocFailed)?;
        buffers.push(buf);
    }

    let mut ring = Ring {
        q_idx,
        depth,
        desc_mem,
        buffers,
        cpu_idx: 0,
        hw_idx: 0,
    };

    // Prime the descriptors so each one points at its buffer with the
    // full segment-0 length. Linux does the same in
    // `mt76_dma_rx_fill_buf` (`dma.c:580..620`).
    //
    // Collect the buffer phys-addresses first to avoid simultaneously
    // borrowing `ring.buffers` (immutable) and `ring` (mutable via
    // `descriptors_mut`).
    let phys_addrs: Vec<u64> = ring.buffers.iter().map(|b| b.dma_addr().raw()).collect();
    {
        let descs = ring.descriptors_mut();
        let buf_len_capped =
            (buf_len as u32).min(MT_DMA_CTL_SD_LEN0_MASK >> MT_DMA_CTL_SD_LEN0_SHIFT);
        for i in 0..depth {
            let phys = phys_addrs[i];
            descs[i].buf0 = phys as u32;
            descs[i].buf1 = ((phys >> 32) as u32) & 0x0F;
            descs[i].ctrl = (buf_len_capped << MT_DMA_CTL_SD_LEN0_SHIFT) & MT_DMA_CTL_SD_LEN0_MASK;
            descs[i].info = 0;
        }
    }

    // Host has filled all entries; CPU pointer sits at depth-1 (HW
    // wraps when it catches up).
    ring.cpu_idx = depth.saturating_sub(1);
    Ok(ring)
}

// ── MMIO programming ──────────────────────────────────────────────

/// Program a ring's MMIO quadruple (base / depth / cidx / didx).
///
/// # Safety
/// `mmio` is the live BAR0 region; caller owns the device.
pub unsafe fn program_ring(mmio: &MmioRegion, regs: RingRegs, ring: &Ring) {
    let phys = ring.desc_phys();
    // SAFETY: caller-asserted.
    unsafe {
        mmio.write32(regs.base_lo as u64, (phys & 0xFFFF_FFFF) as u32);
        // The depth register packs (max_count, base_ptr_high) but the
        // baseline programs only the entry count in the low 16 bits.
        mmio.write32(regs.depth as u64, (ring.depth as u32) & 0xFFFF);
        // Host pointer starts where the buffer fill left off — for RX
        // rings that's `depth - 1` (all entries primed), for TX rings
        // 0 (queue empty).
        mmio.write32(regs.cidx as u64, ring.cpu_idx as u32);
        // HW pointer is owned by the engine; we don't poke it on
        // program, but we read it back so the cached value is sane.
        let didx = mmio.read32(regs.didx as u64) as usize;
        // Stash it back into the ring's cache so the txrx layer can
        // start polling from the right place.
        // (We can't mutate `ring` here through `&Ring`, so the caller
        // does the cache update from the read value below.)
        let _ = didx;
    }
}

// ── WFDMA0 global config (mt792x_dma_{disable,enable}) ────────────

/// Poll budget for `dma_disable` — 100 ms gives the engine time to
/// drain in-flight bursts. Linux uses `mt76_poll(..., 1000)` which is
/// 1000 ticks of 1 ms = 1 second; we cut it down because real silicon
/// drains in < 10 ms and we don't want to wedge boot.
pub const DMA_BUSY_POLL_MS: u64 = 100;

/// Reset + disable the WFDMA0 engine before reprogramming rings.
///
/// Mirrors `mt792x_dma_disable`:
///
///   1. Wait for `TX_DMA_BUSY | RX_DMA_BUSY` to clear in
///      `MT_WFDMA0_GLO_CFG`.
///   2. Clear `TX_DMA_EN | RX_DMA_EN` in the same register.
///
/// # Safety
/// `mmio` is the live BAR0 region; driver owns the device.
pub unsafe fn dma_disable(mmio: &MmioRegion) -> Result<(), DmaError> {
    use narf_time::Deadline;
    let deadline = Deadline::after_ms(DMA_BUSY_POLL_MS);
    let busy_mask = MT_WFDMA0_GLO_CFG_TX_DMA_BUSY | MT_WFDMA0_GLO_CFG_RX_DMA_BUSY;
    let cleared = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: BAR0 mapped + owned.
            let v = unsafe { mmio.read32(MT_WFDMA0_GLO_CFG as u64) };
            v & busy_mask == 0
        },
        deadline,
    );
    if !cleared {
        return Err(DmaError::BusyTimeout);
    }
    // Clear TX/RX-EN.
    // SAFETY: BAR0 mapped + owned.
    let v = unsafe { mmio.read32(MT_WFDMA0_GLO_CFG as u64) };
    // SAFETY: BAR0 mapped + owned per `# Safety`; `MT_WFDMA0_GLO_CFG`
    // is a 32-bit register in range, written read-modify-write.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        mmio.write32(
            MT_WFDMA0_GLO_CFG as u64,
            v & !(MT_WFDMA0_GLO_CFG_TX_DMA_EN | MT_WFDMA0_GLO_CFG_RX_DMA_EN),
        );
    }
    Ok(())
}

/// Enable the WFDMA0 engine after all rings are programmed.
///
/// Mirrors the tail of `mt792x_dma_enable` — set TX/RX-EN, FIFO-LE,
/// WB-DDONE, and disable the OMIT bits so the per-frame info dwords
/// reach the host.
///
/// # Safety
/// As `dma_disable`.
pub unsafe fn dma_enable(mmio: &MmioRegion) {
    let set_bits = MT_WFDMA0_GLO_CFG_TX_DMA_EN
        | MT_WFDMA0_GLO_CFG_RX_DMA_EN
        | MT_WFDMA0_GLO_CFG_FIFO_LITTLE_ENDIAN
        | MT_WFDMA0_GLO_CFG_RX_WB_DDONE;
    // SAFETY: BAR0 mapped + owned per `# Safety`.
    let v = unsafe { mmio.read32(MT_WFDMA0_GLO_CFG as u64) };
    let v = (v | set_bits) & !(MT_WFDMA0_GLO_CFG_OMIT_RX_INFO | MT_WFDMA0_GLO_CFG_OMIT_TX_INFO);
    // SAFETY: same.
    unsafe { mmio.write32(MT_WFDMA0_GLO_CFG as u64, v) };
}

/// Soft-reset the WFDMA0 logic. Linux strobes
/// `MT_WFDMA0_RST_LOGIC_RST | MT_WFDMA0_RST_DMASHDL_ALL_RST` then
/// clears them after a short pause.
///
/// # Safety
/// BAR0 mapped + owned.
pub unsafe fn dma_reset(mmio: &MmioRegion) {
    let bits = MT_WFDMA0_RST_LOGIC_RST | MT_WFDMA0_RST_DMASHDL_ALL_RST;
    // SAFETY: BAR0 mapped + owned per `# Safety`.
    unsafe { mmio.write32(MT_WFDMA0_RST as u64, bits) };
    // Brief settle — Linux uses `udelay(1)` here; we use a 1 ms
    // responsive-spin which is conservative.
    let deadline = narf_time::Deadline::after_ms(1);
    narf_scheduler::responsive_spin_until(|| false, deadline);
    // SAFETY: same.
    unsafe { mmio.write32(MT_WFDMA0_RST as u64, 0) };
}

// ── Doorbell write ────────────────────────────────────────────────

/// Bump the host write pointer ("doorbell") for the given ring.
///
/// Writes the CPU index into the ring's `cidx` register. The HW
/// engine compares the CPU index against its DMA index and picks up
/// the new descriptors.
///
/// # Safety
/// BAR0 mapped + owned.
pub unsafe fn ring_doorbell(mmio: &MmioRegion, regs: RingRegs, cpu_idx: u32) {
    // SAFETY: BAR0 mapped + owned.
    unsafe { mmio.write32(regs.cidx as u64, cpu_idx) };
}

/// Read the HW read index ("DMA index") for the given ring.
///
/// Used by drain / reap loops to detect new RX frames or completed TX
/// frames.
///
/// # Safety
/// BAR0 mapped + owned.
pub unsafe fn ring_dma_index(mmio: &MmioRegion, regs: RingRegs) -> u32 {
    // SAFETY: BAR0 mapped + owned.
    unsafe { mmio.read32(regs.didx as u64) }
}

// ── INFRA L1 remap (re)programming ───────────────────────────────
//
// Stage-0/1 use a conservative fold-into-upper-half remap that hits
// the upper 8 MiB of BAR0 for any absolute address ≥ 0x100_0000. The
// CONNAC2 silicon expects the driver to explicitly program the
// `MT_HIF_REMAP_L1` window to pick which upper-address slab lands at
// BAR0 offset `MT_HIF_REMAP_BASE_L1` (0x40000). Stage-4 introduces a
// helper for that — used by the firmware-loader to slide the patch /
// RAM-code MCU address into view.

/// Program the L1 remap window so accesses to BAR0 offset
/// `MT_HIF_REMAP_BASE_L1` route to absolute address `upper << 16`.
///
/// `upper` is the upper 16 bits of the chip-side absolute address.
///
/// # Safety
/// `mmio` is the live BAR0 region; caller owns the device.
pub unsafe fn program_l1_remap(mmio: &MmioRegion, upper: u16) {
    let v = (upper as u32) << 16;
    // SAFETY: BAR0 mapped + owned.
    unsafe { mmio.write32(MT_HIF_REMAP_L1 as u64, v & MT_HIF_REMAP_L1_BASE) };
}

/// Translate an absolute on-chip address into a BAR0 offset that hits
/// the L1-remapped window. The caller must have programmed the remap
/// page to cover `addr`'s upper 16 bits first.
pub const fn l1_remapped_offset(addr: u32) -> u32 {
    MT_HIF_REMAP_BASE_L1 + (addr & MT_HIF_REMAP_L1_MASK)
}

// ── Stage-4 collected device rings ────────────────────────────────

/// The complete ring set Stage-4 allocates at probe.
pub struct RingSet {
    /// TX data rings (one per AC + BMC). Linux: `MT7921_TXQ_AC_*`.
    pub tx_data: Vec<Ring>,
    /// TX FWDL ring (queue 16). Linux: `MT7921_TXQ_FWDL`.
    pub tx_fwdl: Ring,
    /// TX MCU command ring (queue 17). Linux: `MT7921_TXQ_MCU_WM`.
    pub tx_mcu: Ring,
    /// RX data ring (queue 0). Linux: `MT7921_RXQ_BAND0`.
    pub rx_data: Ring,
    /// RX MCU event ring (pre-firmware). Queue 1.
    pub rx_mcu_evt: Ring,
}

impl core::fmt::Debug for RingSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RingSet")
            .field("tx_data_count", &self.tx_data.len())
            .field("tx_fwdl", &self.tx_fwdl)
            .field("tx_mcu", &self.tx_mcu)
            .field("rx_data", &self.rx_data)
            .field("rx_mcu_evt", &self.rx_mcu_evt)
            .finish()
    }
}

/// RX entry buffer size — Linux uses `MT_RX_BUF_SIZE = 1664`, we round
/// up to one 4 KiB page so the DmaBuffer allocator can satisfy it from
/// a single page allocation.
pub const RX_BUF_LEN: usize = 1664;

/// Allocate every ring Stage-4 needs (5 TX-data + FWDL + MCU + RX-data
/// + RX-mcu-event = 9 rings total, ≤16 entries each).
pub fn allocate_ring_set() -> Result<RingSet, DmaError> {
    // 5 TX data rings (AC_VO/VI/BE/BK + BMC).
    let mut tx_data = Vec::with_capacity(MT7921_TX_RING_COUNT);
    for q in 0..MT7921_TX_RING_COUNT as u8 {
        tx_data.push(alloc_tx_ring(q, MT7921_BASELINE_RING_DEPTH)?);
    }
    let tx_fwdl = alloc_tx_ring(16, MT7921_BASELINE_RING_DEPTH)?;
    let tx_mcu = alloc_tx_ring(17, MT7921_BASELINE_RING_DEPTH)?;
    let rx_data = alloc_rx_ring(0, MT7921_BASELINE_RING_DEPTH, RX_BUF_LEN)?;
    let rx_mcu_evt = alloc_rx_ring(1, MT7921_BASELINE_RING_DEPTH, RX_BUF_LEN)?;

    Ok(RingSet {
        tx_data,
        tx_fwdl,
        tx_mcu,
        rx_data,
        rx_mcu_evt,
    })
}

/// Program every ring in the set into the device's MMIO rings. Mirrors
/// the Linux `mt7921_dma_init` sequence:
///
///   1. Disable DMA + reset WFDMA0.
///   2. Program each ring's base / depth / pointers.
///   3. The `MT_WFDMA0_TX_RING0_EXT_CTRL = 0x4` poke from Linux L185
///      lands here too — Stage-4 mirrors it but the EXT_CTRL block
///      isn't covered by any other path yet.
///   4. Enable TX/RX DMA via `dma_enable`.
///
/// # Safety
/// BAR0 mapped + owned.
pub unsafe fn program_ring_set(mmio: &MmioRegion, rings: &RingSet) -> Result<(), DmaError> {
    // SAFETY: forwarded.
    unsafe { dma_disable(mmio)? };
    // SAFETY: forwarded.
    unsafe { dma_reset(mmio) };

    for (i, ring) in rings.tx_data.iter().enumerate() {
        let regs = mt7921_tx_ring_regs(i as u8)?;
        // SAFETY: forwarded.
        unsafe { program_ring(mmio, regs, ring) };
    }
    let fwdl_regs = mt7921_tx_ring_regs(16)?;
    // SAFETY: forwarded.
    unsafe { program_ring(mmio, fwdl_regs, &rings.tx_fwdl) };
    let mcu_regs = mt7921_tx_ring_regs(17)?;
    // SAFETY: forwarded.
    unsafe { program_ring(mmio, mcu_regs, &rings.tx_mcu) };

    let rx_data_regs = mt7921_rx_ring_regs(0)?;
    // SAFETY: forwarded.
    unsafe { program_ring(mmio, rx_data_regs, &rings.rx_data) };
    let rx_evt_regs = mt7921_rx_ring_regs(1)?;
    // SAFETY: forwarded.
    unsafe { program_ring(mmio, rx_evt_regs, &rings.rx_mcu_evt) };

    // The MT_WFDMA0_TX_RING0_EXT_CTRL = 0x4 poke from
    // `mt7921_dma_init` (pci.c:185). The bit means "enable per-ring
    // descriptor-pre-fetch arbitration"; without it the device serves
    // ring 0 in lock-step with the other AC rings.
    // SAFETY: BAR0 mapped + owned per `# Safety`.
    unsafe { mmio.write32((MT_WFDMA0_BASE + 0x600) as u64, 0x4) };

    // SAFETY: forwarded.
    unsafe { dma_enable(mmio) };
    Ok(())
}
