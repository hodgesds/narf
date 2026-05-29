//! `brcmfmac` per-ring DMA buffer + doorbell IO.
//!
//! Each of the five common rings (and any number of TX flow-rings)
//! gets one of these wrappers around a DMA-coherent slot-array, plus
//! the per-ring write-index / read-index TCM addresses inherited from
//! the firmware's `ringinfo` table. The wrapper composes the index
//! state machine in [`super::msgbuf::Ring`] with the actual IO:
//!
//! - "Push the W cursor" → `write_ptr(devinfo, w_idx_addr, w_ptr)`.
//! - "Pull the R cursor" → `r_ptr = read_ptr(devinfo, r_idx_addr)`.
//! - "Ring the doorbell" → write `1` to `h2d_mailbox_0` (legacy)
//!   or `0xFFFF_FFFF` to `h2d_mailbox_1` (newer firmware).
//!
//! ## DMA-buffer ownership
//!
//! The slot-array backing store is one DMA-coherent host buffer of
//! `depth * item_len` bytes, plus a host-mapped pointer the producer
//! / consumer can dereference. The `Cap<DmaBuffer, _>` registered
//! with `narf-io` keeps the underlying PhysFrame alive; dropping the
//! `RingBuf` returns the cap to the registry which frees the frame.
//!
//! ## References
//!
//! - Linux `brcmfmac/pcie.c::brcmf_pcie_alloc_dma_and_ring`
//!     (~L1158..L1190) — allocator that produces a brcmf_pcie_ringbuf
//!     per ring id.
//! - `brcmf_pcie_ring_mb_*` (~L1020..L1108) — the four IO callbacks
//!     (write_wptr / write_rptr / update_wptr / update_rptr) +
//!     `ring_mb_ring_bell` doorbell.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::msgbuf::Ring;

// ── Per-ring DMA buffer ────────────────────────────────────────────

/// One DMA-backed common-ring (TX-submit, RX-post, TX-complete, etc.).
///
/// The struct holds the SPSC index state, the host-side virtual base
/// of the slot array, the DMA / TCM addresses for the device-side
/// references, and the TCM index slot addresses the host updates / the
/// device reads. The index IO is exposed via `push_w_idx` /
/// `pull_r_idx`; the doorbell IO is exposed via `ring_bell` on a
/// caller-supplied [`DoorbellSink`].
///
/// Reference: Linux `struct brcmf_pcie_ringbuf` (pcie.c ~L368..L375).
#[derive(Debug)]
pub struct RingBuf {
    /// Ring id (one of the BRCMF_*_MSGRING_* values or a flowring id).
    pub id: u8,
    /// Slot-array index dance.
    pub state: Ring,
    /// Host-side virtual base of the slot array. `null` for tests that
    /// only exercise the index state machine.
    pub host_base: *mut u8,
    /// DMA / TCM address of the slot array. Sent to the firmware via
    /// the ringmem table during ring setup.
    pub dma_base: u64,
    /// TCM (or host-RAM via DMA-indices) address of the read-index slot.
    pub r_idx_addr: u32,
    /// TCM (or host-RAM via DMA-indices) address of the write-index slot.
    pub w_idx_addr: u32,
}

// SAFETY: RingBuf is only handed across CPUs after the SPSC end-points
// are settled — the producer/consumer pattern guarantees only one
// thread holds a mutable reference at a time. The raw pointer is a
// DMA mapping that's valid for the lifetime of the underlying
// PhysFrame held in the cap registry.
unsafe impl Send for RingBuf {}
unsafe impl Sync for RingBuf {}

impl RingBuf {
    /// Construct a wrapper around a pre-allocated DMA slot array.
    pub fn new(
        id: u8,
        depth: u16,
        item_len: u16,
        host_base: *mut u8,
        dma_base: u64,
        r_idx_addr: u32,
        w_idx_addr: u32,
    ) -> Self {
        Self {
            id,
            state: Ring::new(depth, item_len),
            host_base,
            dma_base,
            r_idx_addr,
            w_idx_addr,
        }
    }

    /// Total bytes in the slot array. Used by allocators to size the
    /// DMA buffer.
    pub const fn buf_size(&self) -> u32 {
        (self.state.depth as u32) * (self.state.item_len as u32)
    }

    /// Reserve one slot for the producer. Returns the byte offset into
    /// the slot array on success; `None` if the ring is full. Caller
    /// must then write to `host_base[offset..offset+item_len]` and
    /// call [`Self::publish`] + [`DoorbellSink::ring_bell`] to flush.
    pub fn reserve_one(&mut self) -> Option<u32> {
        self.state.reserve_one()
    }

    /// Cancel the most recent `n_items` reservations. Used when the
    /// caller failed mid-build and won't commit the reserved slots.
    pub fn cancel(&mut self, n_items: u16) {
        self.state.write_cancel(n_items);
    }

    /// Snap `f_ptr` to `w_ptr` after a batch of `reserve_one`s. The
    /// next step is the index push + doorbell.
    pub fn publish(&mut self) {
        self.state.publish();
    }

    /// Number of completed items the consumer can drain.
    pub fn read_available(&self) -> u16 {
        self.state.read_available()
    }

    /// Byte offset of the next consumable item, or `None`.
    pub fn read_offset(&self) -> Option<u32> {
        self.state.read_offset()
    }

    /// Advance the read cursor after the consumer processed `n_items`.
    pub fn read_complete(&mut self, n_items: u16) {
        self.state.read_complete(n_items);
    }
}

// ── DoorbellSink ───────────────────────────────────────────────────
//
// Abstracts the actual MMIO write that signals "new entries posted"
// to the firmware. Production wires this to a `MmioRegion::write32`
// against `bar0 + h2d_mailbox_0`. Tests use a stub that records the
// writes for assertion.
//
// Reference: Linux `brcmf_pcie_ring_mb_ring_bell` (pcie.c ~L1056..L1069).

/// Sink for the H2D mailbox-data doorbell write.
///
/// `value` is whatever the firmware expects (Linux uses `1` for the
/// legacy DB0 path and `0x10000000` "HOSTRDY_DB1" bit for the v7 DB1
/// path; the sink's caller picks based on `SharedInfo::hostrdy_db1`).
pub trait DoorbellSink {
    /// Ring the doorbell. `mailbox_off` is the BAR0 offset (e.g.
    /// `BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_0`).
    fn ring_bell(&mut self, mailbox_off: u32, value: u32);
}

/// Per-ring index-IO sink. Linux's `devinfo->write_ptr` /
/// `devinfo->read_ptr` choose between TCM (`write_tcm16`,
/// `read_tcm16`) and host-DMA-indices (`write_idx`, `read_idx`); the
/// sink trait abstracts that choice.
pub trait IndexIo {
    /// Push the host-side `w_ptr` to the device-visible W-index slot.
    fn push_w_idx(&mut self, w_idx_addr: u32, w_ptr: u16);
    /// Push the host-side `r_ptr` to the device-visible R-index slot.
    fn push_r_idx(&mut self, r_idx_addr: u32, r_ptr: u16);
    /// Pull the device-side `w_ptr` from the W-index slot.
    fn pull_w_idx(&mut self, w_idx_addr: u32) -> u16;
    /// Pull the device-side `r_ptr` from the R-index slot.
    fn pull_r_idx(&mut self, r_idx_addr: u32) -> u16;
}

/// Combined "submit a posted batch" operation.
///
/// Mirrors Linux `brcmf_commonring_write_complete` (commonring.c
/// ~L181..L194). Steps:
///   1. Snap `f_ptr` to `w_ptr` (`Ring::publish`).
///   2. Push `w_ptr` to the device's W-index slot via `IndexIo`.
///   3. Ring the doorbell via `DoorbellSink`.
pub fn write_complete<I: IndexIo, D: DoorbellSink>(
    ring: &mut RingBuf,
    idx_io: &mut I,
    door: &mut D,
    mailbox_off: u32,
    doorbell_value: u32,
) {
    ring.publish();
    idx_io.push_w_idx(ring.w_idx_addr, ring.state.w_ptr);
    door.ring_bell(mailbox_off, doorbell_value);
}

// ── BAR0 register helpers ──────────────────────────────────────────
//
// The actual H2D mailbox doorbell address is published in the chip's
// reginfo table (legacy vs. v7+ register layouts have different
// offsets). For convenience the values are mirrored here.

/// Doorbell value the legacy (`reginfo_default`) path writes to
/// `h2d_mailbox_0`. Linux pcie.c:1066 "any arbitrary value will do,
/// lets use 1".
pub const DEFAULT_DOORBELL_VALUE: u32 = 1;

/// HOSTRDY-on-DB1 bit. Per `BRCMF_PCIE_SHARED_HOSTRDY_DB1` (pcie.c
/// ~L222). Used by v7+ firmware that asks the host to signal
/// "host is ready" on `h2d_mailbox_1` instead of DB0.
pub const HOSTRDY_DB1_VALUE: u32 = 0x1000_0000;

// ── Doorbell + IndexIo test stubs ──────────────────────────────────

/// Test doorbell sink — captures each `ring_bell` call into a vec.
#[derive(Debug, Default)]
pub struct RecordingDoorbell {
    pub bells: Vec<(u32, u32)>,
}

impl DoorbellSink for RecordingDoorbell {
    fn ring_bell(&mut self, mailbox_off: u32, value: u32) {
        self.bells.push((mailbox_off, value));
    }
}

/// Test index-IO sink — keeps a u16 slot map keyed by address.
#[derive(Debug, Default)]
pub struct RecordingIndexIo {
    pub slots: alloc::collections::BTreeMap<u32, u16>,
}

impl IndexIo for RecordingIndexIo {
    fn push_w_idx(&mut self, addr: u32, w: u16) {
        self.slots.insert(addr, w);
    }
    fn push_r_idx(&mut self, addr: u32, r: u16) {
        self.slots.insert(addr, r);
    }
    fn pull_w_idx(&mut self, addr: u32) -> u16 {
        *self.slots.get(&addr).unwrap_or(&0)
    }
    fn pull_r_idx(&mut self, addr: u32) -> u16 {
        *self.slots.get(&addr).unwrap_or(&0)
    }
}
