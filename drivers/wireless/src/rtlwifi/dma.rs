//! rtlwifi TX/RX DMA-ring allocator + per-queue base programming.
//!
//! The rtlwifi family exposes 9 distinct TX rings (BK/BE/VI/VO + BEACON,
//! MGMT, HIGH, plus 2 firmware command rings the host doesn't usually
//! program) plus one RX-MPDU ring.  Each ring is a contiguous block of
//! 64-byte TX descriptors (or 32-byte RX descriptors) whose physical
//! base address is written into the chip's per-queue `REG_*_DESA`
//! register and whose slot count is written into `REG_*_TXBD_NUM`.
//!
//! Minimum bring-up subset for any chip is **BE + MGT + HI** TX +
//! **RX-MPDU** RX.  All other queues map to placeholders sharing the
//! BE base (the chip's hardware scheduler accepts duplicated bases as
//! long as the TXBD-NUM tells it how many slots actually live there).
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtl8192ee/hw.c:825..875` — DMA-base programming (LO + HI halves)
//! - `rtl8192ee/hw.c:890..921` — per-queue `REG_*_TXBD_NUM` writes
//! - `rtlwifi/pci.h::RT_TXDESC_NUM` / `RT_TXDESC_NUM_BE_QUEUE`
//! - `rtlwifi/pci.h::RTL_PCI_MAX_RX_COUNT`

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

use narf_bus::MmioRegion;
use narf_io::{alloc_coherent, DmaBuffer, IoError};
use narf_lib::id::DomainId;

use super::mac::{
    bd_num_reg_for_queue, desa_reg_for_queue, REG_BCNQ_DESA, REG_BEQ_DESA, REG_BKQ_DESA,
    REG_HQ0_DESA, REG_MGQ_DESA, REG_RX_DESA, REG_VIQ_DESA, REG_VOQ_DESA,
};
use super::regs::*;

// ── Ring-size constants ──────────────────────────────────────────────────

/// Default TX-ring depth for non-BE queues.  `pci.h::RT_TXDESC_NUM`.
pub const TX_RING_DEPTH_DEFAULT: usize = 128;
/// TX-ring depth for the BE queue (primary data traffic).
/// `pci.h::RT_TXDESC_NUM_BE_QUEUE`.
pub const TX_RING_DEPTH_BE: usize = 256;
/// RX-ring depth (MPDU queue).  `pci.h::RTL_PCI_MAX_RX_COUNT`.
pub const RX_RING_DEPTH: usize = 512;

/// Per-queue segment count packed into `REG_*_TXBD_NUM[15:12]`.  Linux
/// uses 8 for 8192EE (`RTL8192EE_SEG_NUM`).
pub const TXBD_SEG_NUM: u16 = 8;

// ── Errors ───────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaError {
    OutOfMemory,
    DescriptorOverflow,
    InvalidQueue,
    PhysAddressTooHigh,
}

impl From<IoError> for DmaError {
    fn from(_e: IoError) -> Self {
        DmaError::OutOfMemory
    }
}

// ── One TX ring ──────────────────────────────────────────────────────────

/// A single TX descriptor ring (64-byte descriptors).  The ring is
/// always page-aligned (`alloc_coherent` returns one PhysFrame's worth)
/// and zero-initialized.  Hardware ownership is communicated through
/// the OWN bit in each descriptor's DW0.
pub struct TxRing {
    /// DMA-coherent backing.  Slot 0 lives at offset 0.
    pub buf: DmaBuffer,
    /// Number of descriptor slots in the ring.
    pub depth: u16,
    /// Host-side write pointer (advances on every submit, wraps at
    /// `depth`).
    pub wp: AtomicU16,
    /// Host-side completion pointer.  HW indirectly signals progress
    /// by clearing the OWN bit; the driver advances `cp` to the slot
    /// that the IRQ-side completion handler last drained.
    pub cp: AtomicU16,
    /// Which queue (BK/BE/...) this ring serves.
    pub queue: u8,
}

impl TxRing {
    /// Allocate and zero a new TX ring of `depth` descriptors.
    pub fn new(queue: usize, depth: usize) -> Result<Self, DmaError> {
        let total = depth.saturating_mul(TX_DESC_SIZE);
        let buf = alloc_coherent(total, DomainId::DRIVER_0)?;
        // `alloc_coherent` returns a zeroed page; rely on that.
        Ok(Self {
            buf,
            depth: depth as u16,
            wp: AtomicU16::new(0),
            cp: AtomicU16::new(0),
            queue: queue as u8,
        })
    }

    /// Ring base address (low + high 32 bits).
    #[inline]
    pub fn dma_base(&self) -> u64 {
        self.buf.phys_addr().raw()
    }

    /// Number of slots available for the producer.
    #[inline]
    pub fn avail(&self) -> u16 {
        let wp = self.wp.load(Ordering::Acquire);
        let cp = self.cp.load(Ordering::Acquire);
        let used = wp.wrapping_sub(cp) % self.depth;
        // Reserve one slot to distinguish "full" from "empty".
        self.depth.saturating_sub(used).saturating_sub(1)
    }

    /// Reserve one slot and return its index.  Returns `None` when full.
    pub fn reserve_one(&self) -> Option<u16> {
        let wp = self.wp.load(Ordering::Acquire);
        let cp = self.cp.load(Ordering::Acquire);
        if (wp.wrapping_add(1) % self.depth) == cp {
            return None;
        }
        self.wp.store((wp + 1) % self.depth, Ordering::Release);
        Some(wp)
    }
}

// ── RX ring ──────────────────────────────────────────────────────────────

/// A single RX descriptor ring (32-byte descriptors).
pub struct RxRing {
    pub buf: DmaBuffer,
    pub depth: u16,
    /// Last slot examined by the consumer.  HW owns slots between
    /// `next..` and the next descriptor whose OWN bit is set.
    pub next: AtomicU16,
}

impl RxRing {
    pub fn new(depth: usize) -> Result<Self, DmaError> {
        let total = depth.saturating_mul(RX_DESC_SIZE);
        let buf = alloc_coherent(total, DomainId::DRIVER_0)?;
        Ok(Self {
            buf,
            depth: depth as u16,
            next: AtomicU16::new(0),
        })
    }

    #[inline]
    pub fn dma_base(&self) -> u64 {
        self.buf.phys_addr().raw()
    }
}

// ── Program ring bases into the chip ─────────────────────────────────────

/// Program a single TX queue's descriptor-base register pair (low/high
/// 32 bits) plus its `REG_*_TXBD_NUM` slot count.  Mirrors the per-queue
/// lines in `_rtl92ee_init_mac` (`hw.c:825..921`).
///
/// `dma64` selects whether the chip should be told about the high 32
/// bits of the address (8192EE / 8821AE / 8822BE support 64-bit DMA;
/// the older chips ignore the high write).
///
/// # Safety
/// Caller must own BAR0 exclusively and the ring base must already be
/// allocated.
pub unsafe fn program_tx_ring(
    mmio: &MmioRegion,
    queue: usize,
    base: u64,
    depth: u16,
    dma64: bool,
) -> Result<(), DmaError> {
    let desa = desa_reg_for_queue(queue).ok_or(DmaError::InvalidQueue)?;
    let bdnum = bd_num_reg_for_queue(queue).ok_or(DmaError::InvalidQueue)?;

    let lo = (base & 0xFFFF_FFFF) as u32;
    let hi = (base >> 32) as u32;

    // SAFETY: caller-asserted.
    unsafe {
        mmio.write32(desa, lo);
        if dma64 {
            mmio.write32(desa + 4, hi);
        } else if hi != 0 {
            return Err(DmaError::PhysAddressTooHigh);
        }
        // Slot count + segment-num.  `hw.c:890`:
        //   TX_DESC_NUM_92E | ((SEG_NUM << 12) & 0x3000)
        mmio.write16(bdnum, depth | ((TXBD_SEG_NUM << 12) & 0x3000));
    }
    Ok(())
}

/// Program the RX MPDU ring.  Mirrors `hw.c:919..921`.  Sets bit 15 of
/// `REG_RX_RXBD_NUM` per the `0x8000` OR-on in Linux.
///
/// # Safety
/// As for [`program_tx_ring`].
pub unsafe fn program_rx_ring(
    mmio: &MmioRegion,
    base: u64,
    depth: u16,
    dma64: bool,
) -> Result<(), DmaError> {
    let lo = (base & 0xFFFF_FFFF) as u32;
    let hi = (base >> 32) as u32;

    // SAFETY: caller-asserted.
    unsafe {
        mmio.write32(REG_RX_DESA, lo);
        if dma64 {
            mmio.write32(REG_RX_DESA + 4, hi);
        } else if hi != 0 {
            return Err(DmaError::PhysAddressTooHigh);
        }
        // RX ring count + seg-num + the 0x8000 enable bit.
        mmio.write16(
            REG_RX_RXBD_NUM,
            depth | ((TXBD_SEG_NUM << 13) & 0x6000) | 0x8000,
        );
    }
    Ok(())
}

/// `REG_RX_RXBD_NUM` — `rtl8192ee/reg.h:161` — `0x0382`.
pub const REG_RX_RXBD_NUM: u64 = 0x0382;

// ── Aggregate setup: BE + MGT + HI + RX ──────────────────────────────────

/// The minimum ring set required to associate + carry data traffic.
pub struct MinRingSet {
    pub be: TxRing,
    pub mgt: TxRing,
    pub hi: TxRing,
    pub rx: RxRing,
}

impl MinRingSet {
    pub fn allocate() -> Result<Self, DmaError> {
        Ok(Self {
            be: TxRing::new(BE_QUEUE, TX_RING_DEPTH_BE)?,
            mgt: TxRing::new(MGNT_QUEUE, TX_RING_DEPTH_DEFAULT)?,
            hi: TxRing::new(HIGH_QUEUE, TX_RING_DEPTH_DEFAULT)?,
            rx: RxRing::new(RX_RING_DEPTH)?,
        })
    }

    /// Program every ring's base + depth into the chip.  Use after
    /// [`super::mac::init_mac`].
    ///
    /// # Safety
    /// Caller must own BAR0 exclusively.
    pub unsafe fn program(&self, mmio: &MmioRegion, dma64: bool) -> Result<(), DmaError> {
        // SAFETY: forwarded.
        unsafe {
            program_tx_ring(mmio, BE_QUEUE, self.be.dma_base(), self.be.depth, dma64)?;
            program_tx_ring(mmio, MGNT_QUEUE, self.mgt.dma_base(), self.mgt.depth, dma64)?;
            program_tx_ring(mmio, HIGH_QUEUE, self.hi.dma_base(), self.hi.depth, dma64)?;
            program_rx_ring(mmio, self.rx.dma_base(), self.rx.depth, dma64)?;

            // Linux also primes the BK/VI/VO/BEACON DESA registers to the
            // BE ring's address so the scheduler won't trip on
            // uninitialised pointers.  Mirrors `hw.c:847..862`.
            mmio.write32(REG_BKQ_DESA, self.be.dma_base() as u32);
            mmio.write32(REG_VIQ_DESA, self.be.dma_base() as u32);
            mmio.write32(REG_VOQ_DESA, self.be.dma_base() as u32);
            mmio.write32(REG_BCNQ_DESA, self.be.dma_base() as u32);
            if dma64 {
                let hi = (self.be.dma_base() >> 32) as u32;
                mmio.write32(REG_BKQ_DESA + 4, hi);
                mmio.write32(REG_VIQ_DESA + 4, hi);
                mmio.write32(REG_VOQ_DESA + 4, hi);
                mmio.write32(REG_BCNQ_DESA + 4, hi);
            }
            let _ = REG_MGQ_DESA;
            let _ = REG_HQ0_DESA;
        }
        Ok(())
    }
}

// ── Per-descriptor doorbell ──────────────────────────────────────────────
//
// The "doorbell" in the rtlwifi family is just the chip noticing the
// OWN bit was set; there's no explicit kick register.  We pulse the
// txdma-offset-check register (`REG_TXDMA_OFFSET_CHK`) which the chip
// polls — Linux does this in `rtl_pci_tx_polling`.

/// `REG_TXDMA_OFFSET_CHK` — `rtl8192ee/reg.h:115` — `0x020C`.
pub const REG_TXDMA_OFFSET_CHK: u64 = 0x020C;
/// Bit 30 of `REG_TXDMA_OFFSET_CHK` — TX queue 0 doorbell.
pub const TXDMA_BD_DESC_POLL: u32 = 1 << 30;

/// Notify the chip there is new TX work in `queue`.
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn ring_tx_doorbell(mmio: &MmioRegion, _queue: usize) {
    // SAFETY: caller-asserted.
    unsafe {
        let v = mmio.read32(REG_TXDMA_OFFSET_CHK);
        mmio.write32(REG_TXDMA_OFFSET_CHK, v | TXDMA_BD_DESC_POLL);
    }
}

/// Convenience: list of TX queues we actually program at probe.
pub const ACTIVE_TX_QUEUES: &[usize] = &[BE_QUEUE, MGNT_QUEUE, HIGH_QUEUE];

/// A list of (queue, register-base, register-size) triples for the
/// per-queue programming pass — useful for smoke testing the mapping.
pub fn queue_register_table() -> Vec<(usize, u64, u64)> {
    let mut v = Vec::new();
    for &q in ACTIVE_TX_QUEUES {
        if let (Some(desa), Some(bdnum)) = (desa_reg_for_queue(q), bd_num_reg_for_queue(q)) {
            v.push((q, desa, bdnum));
        }
    }
    v
}
