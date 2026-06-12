//! rtlwifi TX path — descriptor encoder + ring submit + doorbell.
//!
//! The chip-specific `TxDesc` already encodes the field positions
//! (DW0[15:0] pkt_size, DW1[12:8] queuesel, DW7[15:0] buf_size, DW8
//! buf_addr, OWN at DW0[31]).  This module is the *driver* glue that
//! takes a byte buffer + queue selector and posts a properly-formed
//! descriptor into the TX ring.
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtl8192ee/trx.c::rtl92ee_tx_fill_desc` (line ~270) — descriptor
//!   fill for 8192EE
//! - `rtlwifi/pci.c::rtl_pci_tx_polling` — kick-the-doorbell helper

#![allow(dead_code)]

use narf_bus::MmioRegion;

use super::dma::{ring_tx_doorbell, DmaError, TxRing};
use super::regs::*;
use super::rtl8188ee::TxDesc;

// ── Encode + post one MPDU into a TX ring ────────────────────────────────

/// Errors from the TX submit path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxError {
    /// Ring is full — back off and retry.
    RingFull,
    /// Frame too large for one MPDU descriptor.
    FrameTooLarge,
    /// DMA buffer programming failed.
    Dma(DmaError),
}

impl From<DmaError> for TxError {
    fn from(e: DmaError) -> Self {
        TxError::Dma(e)
    }
}

/// Maximum single-MPDU payload (~7 KiB by 802.11 spec; rtlwifi limits
/// to 2 KiB in the per-slot DMA pool).
pub const TX_MAX_MPDU: usize = 2048;

/// Build a TX descriptor for the BE queue.
///
/// `buf_phys` is the physical address of the DMA buffer holding the
/// MPDU (Linux: `pkt->skb->mapping`).  `len` is the MPDU length, ≤
/// [`TX_MAX_MPDU`].  `queuesel` is the chip's queue selector code from
/// `regs.rs` (`QSLT_BE`, `QSLT_MGNT`, etc.).
pub fn build_be_desc(buf_phys: u32, len: u16, queuesel: u8) -> TxDesc {
    let mut desc = TxDesc::default();
    desc.set_pkt_size(len);
    desc.set_single_mpdu();
    desc.set_queuesel(queuesel);
    desc.set_buf_addr(buf_phys);
    desc.set_buf_size(len);
    desc.set_own(true);
    desc
}

/// Submit an MPDU onto a TX ring + ring the chip's doorbell.
///
/// The caller has already copied the frame into a DMA-coherent buffer
/// and supplies the buffer's physical base in `buf_phys`.  The ring's
/// `TxDesc` slot at `wp` gets the descriptor; `wp` advances by 1.
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn submit_mpdu(
    mmio: &MmioRegion,
    ring: &TxRing,
    buf_phys: u32,
    len: u16,
    queuesel: u8,
) -> Result<u16, TxError> {
    if len as usize > TX_MAX_MPDU {
        return Err(TxError::FrameTooLarge);
    }
    let slot = ring.reserve_one().ok_or(TxError::RingFull)?;
    let desc = build_be_desc(buf_phys, len, queuesel);

    // Write the descriptor into slot N of the ring buffer.
    let offset = slot as usize * TX_DESC_SIZE;
    let dst_ptr = ring.buf.as_mut_ptr();
    // SAFETY: ring buffer is DMA-coherent and we own `slot` exclusively
    // via the producer's `reserve_one`.  Length is statically bounded.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        let dst = core::slice::from_raw_parts_mut(dst_ptr.add(offset).cast::<u32>(), 16);
        dst.copy_from_slice(&desc.dwords);
    }

    // SAFETY: forwarded.
    unsafe {
        ring_tx_doorbell(mmio, ring.queue as usize);
    }
    Ok(slot)
}

/// Drain completed descriptors from a TX ring.  Walks slots between
/// `cp` and `wp`, freeing every slot whose OWN bit has been cleared
/// by HW.  Advances `cp` to the first still-owned slot.
///
/// Returns the number of slots reclaimed.
pub fn reclaim_completed(ring: &TxRing) -> u16 {
    let mut reclaimed = 0u16;
    let wp = ring.wp.load(core::sync::atomic::Ordering::Acquire);
    let mut cp = ring.cp.load(core::sync::atomic::Ordering::Acquire);
    let base = ring.buf.as_ptr();
    while cp != wp {
        let offset = cp as usize * TX_DESC_SIZE;
        // SAFETY: ring is DMA-coherent and we read DW0 (OWN bit).
        let dw0 = unsafe { core::ptr::read_volatile(base.add(offset).cast::<u32>()) };
        if dw0 & (1u32 << 31) != 0 {
            break;
        }
        cp = (cp + 1) % ring.depth;
        reclaimed = reclaimed.saturating_add(1);
    }
    ring.cp.store(cp, core::sync::atomic::Ordering::Release);
    reclaimed
}
