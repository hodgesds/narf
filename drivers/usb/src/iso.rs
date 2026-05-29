//! Isochronous-transfer skeleton.
//!
//! Isochronous transfers are the fixed-cadence streaming mode used by
//! UVC webcams, USB audio (UAC1/2/3), and certain DECT phone dongles.
//! xHCI implements them with a stream of Isoch TRBs on a Transfer
//! Ring, each tagged with a Frame ID (or SIA = "Start Isoch ASAP").
//!
//! NARF's UVC and UAC drivers consume the lower-level
//! [`Xhci::isoch_in`] / [`Xhci::isoch_out`] today; this module exists
//! as the eventual class-driver-facing wrapper. For now it carries
//! constant definitions and a stub helper that delegates to the
//! controller-level API.

#![allow(dead_code)]

use crate::bulk::dci_for;
use crate::device::{USBDevice, UsbError};

/// Isoch SIA bit — Start Isoch As Soon As Possible (xHCI 1.2 §6.4.1.3
/// Table 6-49). When set, the controller picks the next available
/// frame; otherwise the Frame ID field selects an explicit one.
pub const TRB_SIA: u32 = 1 << 31;

/// Issue an isochronous OUT transfer (typically UAC audio playback).
pub async fn isoch_out(dev: &USBDevice, ep_addr: u8, data: &[u8]) -> Result<usize, UsbError> {
    dev.controller()
        .isoch_out(dev.slot_id(), dci_for(ep_addr), data)
        .await
        .map_err(UsbError::from_xhci)
}

/// Issue an isochronous IN transfer (typically UVC video capture).
pub async fn isoch_in(dev: &USBDevice, ep_addr: u8, out: &mut [u8]) -> Result<usize, UsbError> {
    dev.controller()
        .isoch_in(dev.slot_id(), dci_for(ep_addr), out)
        .await
        .map_err(UsbError::from_xhci)
}
