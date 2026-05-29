//! rtlwifi RX path — descriptor poll + payload decode + ring refill.
//!
//! The RX ring is a fixed array of 32-byte descriptors.  Each slot's
//! DW0 carries an OWN bit (0 = driver-owned, 1 = HW-owned) and the
//! received MPDU length in the low 14 bits.  Driver workflow:
//!
//! 1. Read DW0 of `ring[next]`.
//! 2. If OWN == 1, no more RX data; return.
//! 3. Extract length, copy payload from the DMA buffer at DW6 to the
//!    network ingress queue.
//! 4. Re-arm the slot: rewrite DW6 with the per-slot DMA buffer
//!    address and set OWN back to 1.
//! 5. Advance `next` (wraps at ring depth).
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtl8192ee/trx.c::rtl92ee_rx_query_desc` — RX descriptor parser
//! - `rtlwifi/pci.c::_rtl_pci_rx_interrupt` — ring-walk loop

#![allow(dead_code)]

use core::sync::atomic::Ordering;

use super::dma::RxRing;
use super::regs::*;
use super::rtl8188ee::RxDesc;

/// One drained RX entry.
#[derive(Copy, Clone, Debug, Default)]
pub struct RxEntry {
    pub slot: u16,
    pub mpdu_len: u16,
    pub crc_err: bool,
}

/// Read one RX descriptor in driver byte order.  Returns `None` if the
/// slot is still owned by HW.
pub fn peek_descriptor(ring: &RxRing, slot: u16) -> Option<RxDesc> {
    let offset = slot as usize * RX_DESC_SIZE;
    let base = ring.buf.as_ptr();
    // SAFETY: DMA-coherent backing; offset is in-range (slot < depth).
    let mut desc = RxDesc::default();
    unsafe {
        for i in 0..desc.dwords.len() {
            desc.dwords[i] =
                core::ptr::read_volatile(base.add(offset + i * 4).cast::<u32>());
        }
    }
    if desc.is_hw_owned() {
        return None;
    }
    Some(desc)
}

/// Drain up to `max` completed RX descriptors.  For each non-erroring
/// MPDU, the per-payload byte slice is passed to `sink`.  After the
/// caller has consumed the payload the slot is re-armed in-place so
/// HW can reuse it.
///
/// Returns the number of slots processed.
pub fn drain<F: FnMut(&[u8])>(ring: &RxRing, max: u16, mut sink: F) -> u16 {
    let mut processed = 0u16;
    let mut next = ring.next.load(Ordering::Acquire);
    let base = ring.buf.as_ptr();
    while processed < max {
        let desc = match peek_descriptor(ring, next) {
            Some(d) => d,
            None => break,
        };
        if !desc.crc_err() {
            // The chip writes the payload into the DMA buffer pointed
            // at by DW6 (`bufferaddress`).  Linux looks it up via the
            // ring's parallel skb-array; we keep one DMA buffer per
            // ring slot at offset `slot * 2 KiB` from the ring base
            // for the smoke path, and rely on the chip's writeback.
            let len = desc.pkt_len().min(2048) as usize;
            // SAFETY: DMA-coherent backing; offset bounded.
            unsafe {
                let payload = core::slice::from_raw_parts(
                    base.add(next as usize * 2048),
                    len,
                );
                sink(payload);
            }
        }
        // Rearm in-place: reuse the same DMA address slot the chip
        // already had, just flip OWN back to 1.
        let offset = next as usize * RX_DESC_SIZE;
        // SAFETY: same.
        unsafe {
            let dst_dw0 = base.add(offset).cast::<u32>() as *mut u32;
            core::ptr::write_volatile(dst_dw0, 1u32 << 31);
        }
        next = (next + 1) % ring.depth;
        processed += 1;
    }
    ring.next.store(next, Ordering::Release);
    processed
}
