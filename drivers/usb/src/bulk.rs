//! Bulk-transfer dispatch for USB class drivers.
//!
//! Class drivers like rtl8xxxu's TX/RX path, msc's CBW/CSW, cdc-ncm's
//! NDP-encapsulated Ethernet frames all run over bulk endpoints. This
//! module wraps the [`USBDevice`] primitives so class drivers don't
//! need to track DCI math.

#![allow(dead_code)]

use crate::device::{USBDevice, UsbError};

/// Compute the Device Context Index for `ep_addr` (USB endpoint
/// descriptor's `bEndpointAddress`).
///
/// xHCI 1.2 §4.8.1: DCI = (ep_num * 2) + 1 for IN endpoints,
/// DCI = (ep_num * 2) for OUT endpoints; DCI 0 is reserved, DCI 1 is
/// the bidirectional default-control endpoint.
pub const fn dci_for(ep_addr: u8) -> u8 {
    let ep_num = ep_addr & 0x0F;
    let in_dir = (ep_addr & 0x80) != 0;
    if in_dir {
        ep_num * 2 + 1
    } else {
        ep_num * 2
    }
}

/// Issue a bulk-OUT transfer on the endpoint identified by `ep_addr`.
/// Returns the number of bytes the controller reports as transferred
/// (i.e. `data.len() - residue`).
pub async fn bulk_out(dev: &USBDevice, ep_addr: u8, data: &[u8]) -> Result<usize, UsbError> {
    dev.bulk_out(dci_for(ep_addr), data).await
}

/// Issue a bulk-IN transfer on the endpoint identified by `ep_addr`.
pub async fn bulk_in(dev: &USBDevice, ep_addr: u8, out: &mut [u8]) -> Result<usize, UsbError> {
    dev.bulk_in(dci_for(ep_addr), out).await
}

/// Split a payload into chunks of `chunk_size` and submit each as a
/// bulk-OUT transfer. Stops on first error; returns the total number
/// of bytes transferred up to that point.
pub async fn bulk_out_chunked(
    dev: &USBDevice,
    ep_addr: u8,
    data: &[u8],
    chunk_size: usize,
) -> Result<usize, UsbError> {
    let mut sent = 0usize;
    for chunk in data.chunks(chunk_size) {
        let n = bulk_out(dev, ep_addr, chunk).await?;
        sent += n;
        if n != chunk.len() {
            return Ok(sent);
        }
    }
    Ok(sent)
}
