//! Class-driver-facing [`USBDevice`] abstraction.
//!
//! `USBDevice` is the handle a USB class driver (rtl8xxxu, btusb,
//! cdc-acm, usb-mass-storage, etc.) gets after the host controller's
//! enumerator finishes Address Device + Configure Endpoint. It hides
//! the controller flavour (xHCI today; ehci/ohci/uhci tomorrow) and
//! exposes only the transfer-level primitives a class driver needs:
//! control / bulk / interrupt / isochronous.
//!
//! ## Lifetime
//!
//! A `USBDevice` is cheap (16 bytes: an `Arc<Xhci>` plus a `slot_id`).
//! Clones share the same controller handle and slot. Drop does NOT
//! tear down the slot — slot lifetime is owned by the supervisor /
//! hub teardown logic. A class driver hands its `USBDevice` back via
//! `detach()` when it has no further use for it.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::xhci::{self, EndpointConfig, EndpointKind, PortSpeed, Xhci, XhciError};

/// Errors surfaced to USB class drivers. Either a controller-level
/// fault that we want to keep distinct (so a class driver can decide
/// whether to retry or give up), or a USB-level fault (stall, NAK,
/// short-packet on unexpected endpoint).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UsbError {
    /// The slot or endpoint was not configured before the transfer.
    NotConfigured,
    /// The transfer was issued against a slot the controller doesn't
    /// know about (likely race with disconnect).
    StaleSlot,
    /// Caller-supplied buffer was too small for the descriptor / data
    /// stage residue.
    BufferTooSmall,
    /// USB device stalled (Completion Code 6 — STALL Error).
    Stall,
    /// USB device gave a Babble error.
    Babble,
    /// USB-level transaction error (CRC, retries exhausted, …).
    TransactionError,
    /// Transfer timed out waiting for a Transfer Event.
    Timeout,
    /// xHCI completion code we don't model individually.
    HardwareError(u8),
}

impl UsbError {
    /// Translate the controller-level [`XhciError`] into a class-driver
    /// friendly [`UsbError`]. Completion-code 0x06 is Stall; 0x07
    /// Babble; 0x04 USB Transaction Error; everything else falls into
    /// `HardwareError`.
    pub fn from_xhci(e: XhciError) -> Self {
        match e {
            XhciError::CmdFailed(code) => match code {
                4 => UsbError::TransactionError,
                6 => UsbError::Stall,
                7 => UsbError::Babble,
                0xFD => UsbError::StaleSlot,
                _ => UsbError::HardwareError(code),
            },
            XhciError::CmdTimeout => UsbError::Timeout,
            XhciError::PortResetTimeout => UsbError::Timeout,
            XhciError::NotReady => UsbError::HardwareError(0xFE),
            XhciError::BadPort => UsbError::StaleSlot,
            XhciError::CmdRingFull => UsbError::HardwareError(0xFC),
            XhciError::ResetTimeout => UsbError::Timeout,
            XhciError::NoMemory => UsbError::HardwareError(0xFB),
            XhciError::BarMapFailed => UsbError::HardwareError(0xFA),
            XhciError::StartFailed => UsbError::HardwareError(0xF9),
        }
    }
}

/// Class-driver-facing handle to one configured USB device.
///
/// `USBDevice` is the abstraction class drivers (rtl8xxxu / btusb /
/// cdc-acm / msc) consume. It carries a slot id and a controller
/// handle; all I/O on the device routes through the xHCI primitives
/// transparently.
///
/// Construct via [`USBDevice::new`] (the enumerator does this) or
/// [`USBDevice::attach`] (class drivers call this after a successful
/// `address_device` + descriptor fetch).
#[derive(Clone)]
pub struct USBDevice {
    controller: Arc<Xhci>,
    slot_id: u8,
    port: u8,
    speed: PortSpeed,
    /// Cached vendor ID from the 18-byte Device Descriptor (low 16
    /// bits of bcdUSB + idVendor offset 8..10). 0 if unknown.
    vendor_id: u16,
    /// Cached product ID. 0 if unknown.
    product_id: u16,
}

impl core::fmt::Debug for USBDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("USBDevice")
            .field("slot_id", &self.slot_id)
            .field("port", &self.port)
            .field("speed", &self.speed)
            .field("vendor_id", &self.vendor_id)
            .field("product_id", &self.product_id)
            .finish()
    }
}

impl USBDevice {
    /// Construct a `USBDevice` directly. Enumerator-only path; class
    /// drivers should call [`USBDevice::attach`] which fetches and
    /// caches the device descriptor.
    pub fn new(controller: Arc<Xhci>, slot_id: u8, port: u8, speed: PortSpeed) -> Self {
        Self {
            controller,
            slot_id,
            port,
            speed,
            vendor_id: 0,
            product_id: 0,
        }
    }

    /// Attach to an addressed slot. Issues `Get Device Descriptor`
    /// to cache vendor/product IDs so class drivers can match on them
    /// without re-fetching.
    pub async fn attach(
        controller: Arc<Xhci>,
        slot_id: u8,
        port: u8,
        speed: PortSpeed,
    ) -> Result<Self, UsbError> {
        let desc = controller
            .get_device_descriptor(slot_id)
            .await
            .map_err(UsbError::from_xhci)?;
        let vendor_id = u16::from_le_bytes([desc[8], desc[9]]);
        let product_id = u16::from_le_bytes([desc[10], desc[11]]);
        Ok(Self {
            controller,
            slot_id,
            port,
            speed,
            vendor_id,
            product_id,
        })
    }

    /// Override the cached `vendor_id` / `product_id`. Used by the
    /// attach dispatcher to inject the IDs already fetched via
    /// GET_DESCRIPTOR(DEVICE) without issuing a second control transfer.
    pub fn set_ids(&mut self, vendor_id: u16, product_id: u16) {
        self.vendor_id = vendor_id;
        self.product_id = product_id;
    }

    /// Slot id allocated by `Enable Slot`.
    pub fn slot_id(&self) -> u8 {
        self.slot_id
    }

    /// Root-hub port the device sits behind (or hub-internal port for
    /// downstream-hub devices).
    pub fn port(&self) -> u8 {
        self.port
    }

    /// Negotiated port speed.
    pub fn speed(&self) -> PortSpeed {
        self.speed
    }

    /// Cached idVendor from the 18-byte Device Descriptor.
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// Cached idProduct.
    pub fn product_id(&self) -> u16 {
        self.product_id
    }

    /// Underlying controller handle. Class drivers normally don't need
    /// this — prefer the [`control_in`](Self::control_in) /
    /// [`bulk_out`](Self::bulk_out) helpers — but the supervisor + hub
    /// drivers do.
    pub fn controller(&self) -> &Arc<Xhci> {
        &self.controller
    }

    // ── Transfer primitives. Each is a thin pass-through to the
    //    xHCI helpers on the controller.

    /// Issue a control IN transfer. Returns the number of bytes read.
    pub async fn control_in(
        &self,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &mut [u8],
    ) -> Result<usize, UsbError> {
        self.controller
            .control_in(self.slot_id, bm_request_type, b_request, w_value, w_index, out)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Issue a control OUT transfer. Returns the number of bytes the
    /// controller reports as transferred (caller-supplied `data.len()`
    /// on success; less on a short transfer).
    pub async fn control_out(
        &self,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
    ) -> Result<usize, UsbError> {
        self.controller
            .control_out(self.slot_id, bm_request_type, b_request, w_value, w_index, data)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Bulk-OUT transfer. `dci` is the Device Context Index of the
    /// endpoint (2 × ep_num for OUT, 2 × ep_num + 1 for IN).
    pub async fn bulk_out(&self, dci: u8, data: &[u8]) -> Result<usize, UsbError> {
        self.controller
            .bulk_out(self.slot_id, dci, data)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Bulk-IN transfer.
    pub async fn bulk_in(&self, dci: u8, out: &mut [u8]) -> Result<usize, UsbError> {
        self.controller
            .bulk_in(self.slot_id, dci, out)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Pre-post a Normal TRB on the interrupt-IN endpoint so the next
    /// device-side interrupt poll fills it. Returns the TRB pointer
    /// (used by [`poll_interrupt_in`](Self::poll_interrupt_in) to
    /// match the completion event).
    pub fn arm_interrupt_in(&self, dci: u8, len: u32) -> Result<u64, UsbError> {
        self.controller
            .arm_interrupt_in(self.slot_id, dci, len)
            .map_err(UsbError::from_xhci)
    }

    /// Poll for a completed interrupt-IN transfer. Returns the bytes
    /// actually transferred (or `None` if nothing has arrived).
    pub fn poll_interrupt_in(
        &self,
        dci: u8,
        out: &mut [u8],
    ) -> Result<Option<usize>, UsbError> {
        self.controller
            .poll_interrupt_in(self.slot_id, dci, out)
            .map_err(UsbError::from_xhci)
    }

    /// Configure one or more endpoints on this slot. Wraps the xHCI
    /// Configure Endpoint command.
    pub async fn configure_endpoints(&self, eps: &[EndpointConfig]) -> Result<(), UsbError> {
        self.controller
            .configure_endpoints(self.slot_id, eps)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Read the 18-byte Device Descriptor.
    pub async fn get_device_descriptor(&self) -> Result<[u8; 18], UsbError> {
        self.controller
            .get_device_descriptor(self.slot_id)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Read the Configuration Descriptor at `cfg_idx` (usually 0).
    /// The caller passes a buffer sized to hold the variable-length
    /// configuration block; the number of bytes actually read is
    /// returned.
    pub async fn get_config_descriptor(
        &self,
        cfg_idx: u8,
        out: &mut [u8],
    ) -> Result<usize, UsbError> {
        self.controller
            .get_config_descriptor(self.slot_id, cfg_idx, out)
            .await
            .map_err(UsbError::from_xhci)
    }
}

/// EndpointConfig builder helpers for class drivers. Keeps the
/// xhci-specific encoding out of class-driver call sites.
pub fn bulk_in_ep(ep_num: u8, max_packet: u16) -> EndpointConfig {
    EndpointConfig {
        ep_addr: ep_num | 0x80,
        max_packet,
        kind: EndpointKind::BulkIn,
    }
}

pub fn bulk_out_ep(ep_num: u8, max_packet: u16) -> EndpointConfig {
    EndpointConfig {
        ep_addr: ep_num & 0x0F,
        max_packet,
        kind: EndpointKind::BulkOut,
    }
}

pub fn interrupt_in_ep(ep_num: u8, max_packet: u16) -> EndpointConfig {
    EndpointConfig {
        ep_addr: ep_num | 0x80,
        max_packet,
        kind: EndpointKind::InterruptIn,
    }
}

pub fn interrupt_out_ep(ep_num: u8, max_packet: u16) -> EndpointConfig {
    EndpointConfig {
        ep_addr: ep_num & 0x0F,
        max_packet,
        kind: EndpointKind::InterruptOut,
    }
}

/// Find the controller, look up the slot for `port`, and wrap the
/// result in a [`USBDevice`]. Used by class drivers that walk root-hub
/// ports.
pub fn find_by_port(port: u8) -> Option<USBDevice> {
    let c = xhci::controller()?;
    let slot_id = c.slot_for_port(port)?;
    let (port, speed, _) = c.device_info(slot_id)?;
    Some(USBDevice::new(c, slot_id, port, speed))
}

/// Enumerate every currently-bound slot as a [`USBDevice`]. Used by
/// the rtl8xxxu register hook to find its dongle without going through
/// the supervisor's attach state machine.
pub fn enumerate() -> Vec<USBDevice> {
    let c = match xhci::controller() {
        Some(c) => c,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for slot_id in 1u8..=255 {
        if let Some((port, speed, _)) = c.device_info(slot_id) {
            out.push(USBDevice::new(c.clone(), slot_id, port, speed));
        }
    }
    out
}
