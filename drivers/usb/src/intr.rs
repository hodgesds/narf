//! Interrupt-IN polling for USB class drivers.
//!
//! Interrupt endpoints (HID boot keyboard reports, rtl8xxxu's 56-byte
//! status notifications, CDC-ACM notifications) deliver short frames
//! at a device-driven cadence. xHCI prepots a Normal TRB on the
//! transfer ring, rings the endpoint doorbell, and the controller
//! deposits a Transfer Event when the device's bInterval-paced poll
//! returns data.
//!
//! Two patterns matter:
//!
//! 1. **Free-running poll** — arm one TRB per cycle, drain whatever
//!    completed via `poll_interrupt_in`. Used by HID boot keyboard.
//! 2. **One-shot** — arm a single TRB, await its completion. Used by
//!    cdc-acm to wait for a serial-state-change notification.

#![allow(dead_code)]

use crate::bulk::dci_for;
use crate::device::{USBDevice, UsbError};

/// Pre-post a Normal TRB on an interrupt-IN endpoint. Returns the
/// physical address of the TRB so the caller can correlate it against
/// a Transfer Event later.
pub fn arm(dev: &USBDevice, ep_addr: u8, len: u32) -> Result<u64, UsbError> {
    dev.arm_interrupt_in(dci_for(ep_addr), len)
}

/// Non-blocking drain. Returns `Ok(Some(n))` if the controller has
/// reported a completed transfer of `n` bytes into `out`; `Ok(None)`
/// if no event has been demuxed for this endpoint yet.
pub fn poll(dev: &USBDevice, ep_addr: u8, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
    dev.poll_interrupt_in(dci_for(ep_addr), out)
}

/// Free-running poll: keep one TRB armed and drain whichever completes.
/// Returns `Some(n)` on a fresh frame; arms the *next* TRB before
/// returning so the caller doesn't have to. Returns `None` when no
/// frame is ready.
pub fn pump(
    dev: &USBDevice,
    ep_addr: u8,
    expected_len: u32,
    out: &mut [u8],
) -> Result<Option<usize>, UsbError> {
    let n = poll(dev, ep_addr, out)?;
    // Re-arm regardless: if no frame was ready we still want a TRB on
    // the ring for the controller's next interval. If a frame WAS
    // ready, we just consumed its TRB and need a fresh one for the
    // following interval.
    arm(dev, ep_addr, expected_len)?;
    Ok(n)
}
