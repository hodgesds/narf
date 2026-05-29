//! Firmware-upload helper for USB class drivers.
//!
//! Several USB chips load their runtime firmware via a bulk-OUT
//! transfer at attach time (rtl8xxxu Code A/B, btusb intel/realtek,
//! cdc-dfu). This module provides the common dance:
//!
//! 1. Fetch the blob through the kernel firmware loader (registered
//!    at `Stage::Subsys`).
//! 2. Slice it into max-packet-sized chunks.
//! 3. Send each chunk on a bulk-OUT endpoint.
//! 4. Optional: poll a vendor-specific status register over a control
//!    pipe until the chip reports "running" — class-driver supplies
//!    the polling closure since the encoding is chip-specific.

#![allow(dead_code)]

use crate::bulk;
use crate::device::{USBDevice, UsbError};

/// Result of a firmware-upload attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FirmwareError {
    /// Firmware blob not found in the firmware registry.
    NotFound,
    /// Bulk-OUT failed mid-stream.
    UploadFailed(UsbError),
    /// The class driver's post-upload status poll never reported "ready".
    Timeout,
}

/// Slice `blob` into chunks of `chunk_size` bytes and send each via
/// bulk-OUT on `ep_addr`. The last chunk may be shorter than
/// `chunk_size`; xHCI handles short packets transparently.
///
/// Returns the total number of bytes transferred. Stops on first
/// upload failure.
pub async fn upload_bulk_out(
    dev: &USBDevice,
    ep_addr: u8,
    blob: &[u8],
    chunk_size: usize,
) -> Result<usize, FirmwareError> {
    bulk::bulk_out_chunked(dev, ep_addr, blob, chunk_size)
        .await
        .map_err(FirmwareError::UploadFailed)
}

/// Convenience wrapper: choose a sensible chunk size based on the
/// endpoint's max packet size (which the caller must pass in since
/// `USBDevice` doesn't carry per-endpoint MPS without a descriptor
/// parse). 64 bytes is the legal minimum for full-speed bulk and a
/// safe default for any speed.
pub async fn upload_default(
    dev: &USBDevice,
    ep_addr: u8,
    blob: &[u8],
    max_packet: u16,
) -> Result<usize, FirmwareError> {
    let mp = (max_packet as usize).max(64);
    // Send up to 4 MaxPacket bursts per chunk to amortise the per-TRB
    // overhead while staying well inside the 64 KiB Normal TRB cap.
    let chunk = mp.saturating_mul(4).min(64 * 1024);
    upload_bulk_out(dev, ep_addr, blob, chunk).await
}
