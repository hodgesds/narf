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
//! A `USBDevice` is a cheap handle with a retained controller and slot generation.
//! Clones share the same controller handle and slot. Drop does NOT
//! tear down the slot — slot lifetime is owned by the supervisor /
//! hub teardown logic. A class driver hands its `USBDevice` back via
//! `detach()` when it has no further use for it.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;

pub use crate::xhci::BulkToken;

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
    generation: u64,
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
        let generation = controller.device_generation(slot_id).unwrap_or(0);
        Self {
            controller,
            slot_id,
            generation,
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
        let generation = controller
            .device_generation(slot_id)
            .ok_or(UsbError::StaleSlot)?;
        let desc = controller
            .get_device_descriptor(slot_id)
            .await
            .map_err(UsbError::from_xhci)?;
        if controller.device_generation(slot_id) != Some(generation) {
            return Err(UsbError::StaleSlot);
        }
        let vendor_id = u16::from_le_bytes([desc[8], desc[9]]);
        let product_id = u16::from_le_bytes([desc[10], desc[11]]);
        Ok(Self {
            controller,
            slot_id,
            generation,
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
            .control_in_generation(
                self.slot_id,
                self.generation,
                bm_request_type,
                b_request,
                w_value,
                w_index,
                out,
            )
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
            .control_out_generation(
                self.slot_id,
                self.generation,
                bm_request_type,
                b_request,
                w_value,
                w_index,
                data,
            )
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Recover a halted endpoint end to end. Host side first:
    /// Reset Endpoint + Set TR Dequeue Pointer
    /// (`Xhci::reset_endpoint`) stops the endpoint at the canonical
    /// dequeue and discards the retained TD. Then, for non-control
    /// endpoints, CLEAR_FEATURE(ENDPOINT_HALT) (USB 2.0 §9.4.1)
    /// clears the device-side halt and resets the device's data
    /// toggle, so host and device toggles restart together. The
    /// order matters: the device-side clear runs only after the
    /// host endpoint is proven Stopped, so no in-flight TD can race
    /// the toggle reset.
    ///
    /// `endpoint` is the endpoint address as it appears in the
    /// interface descriptor (bit 7 set = IN). For EP0 the
    /// CLEAR_FEATURE step is skipped — the control pipe carries no
    /// persistent toggle state, and the host-side Reset Endpoint
    /// sequence is the whole recovery.
    pub async fn clear_endpoint_halt(&self, endpoint: u8) -> Result<(), UsbError> {
        let number = endpoint & 0x0f;
        // `dci_for` covers DCI 2..=31; EP0 is DCI 1 by definition
        // (the shared helper maps address 0 to the reserved DCI 0,
        // which no caller passes it).
        let dci = if number == 0 {
            1
        } else {
            crate::bulk::dci_for(endpoint)
        };
        self.controller
            .reset_endpoint(self.slot_id, self.generation, dci)
            .await
            .map_err(UsbError::from_xhci)?;
        if number != 0 {
            let setup = crate::control::clear_feature(
                crate::control::RT_RECIP_ENDPOINT,
                crate::control::FEATURE_ENDPOINT_HALT,
                u16::from(endpoint),
            );
            self.control_out(
                setup.bm_request_type,
                setup.b_request,
                setup.w_value,
                setup.w_index,
                &[],
            )
            .await?;
        }
        Ok(())
    }

    fn validate_bulk_token(&self, token: &BulkToken) -> Result<(), UsbError> {
        if token.slot() != self.slot_id || token.generation() != self.generation {
            return Err(UsbError::StaleSlot);
        }
        Ok(())
    }

    /// Begin a persistent receive. `dci` is 2 * endpoint_number + 1.
    /// Poll the receipt until terminal completion; dropping it preserves
    /// endpoint DMA ownership and prevents another transfer on that page.
    pub fn begin_bulk_in(&self, dci: u8, length: usize) -> Result<BulkToken, UsbError> {
        self.controller
            .begin_bulk_in(self.slot_id, dci, self.generation, length)
            .map_err(UsbError::from_xhci)
    }

    /// Stage and submit a transmit. USB completion does not imply a radio ACK.
    pub fn begin_bulk_out(&self, dci: u8, data: &[u8]) -> Result<BulkToken, UsbError> {
        self.controller
            .begin_bulk_out(self.slot_id, dci, self.generation, data)
            .map_err(UsbError::from_xhci)
    }

    pub fn poll_bulk_in(
        &self,
        token: &BulkToken,
        out: &mut [u8],
    ) -> Result<Option<usize>, UsbError> {
        self.validate_bulk_token(token)?;
        self.controller
            .poll_bulk_in(token, out)
            .map_err(UsbError::from_xhci)
    }

    pub fn poll_bulk_out(&self, token: &BulkToken) -> Result<Option<usize>, UsbError> {
        self.validate_bulk_token(token)?;
        self.controller
            .poll_bulk_out(token)
            .map_err(UsbError::from_xhci)
    }

    /// Stop/drain one retained bulk receipt before discarding or reusing its
    /// page/ring. Any error or dropped future leaves the claim terminally busy.
    pub async fn stop_bulk(&self, token: &BulkToken) -> Result<(), UsbError> {
        self.validate_bulk_token(token)?;
        self.controller
            .stop_bulk(token)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Compatibility bulk-OUT wait. Timeout/error leaves the endpoint busy;
    /// caller buffers may be released because the host owns the staged copy.
    pub async fn bulk_out(&self, dci: u8, data: &[u8]) -> Result<usize, UsbError> {
        let token = self.begin_bulk_out(dci, data)?;
        self.controller
            .wait_bulk_out(&token)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Compatibility bounded receive wait. Persistent idle receivers should
    /// use begin_bulk_in + poll_bulk_in to keep the same TD posted.
    pub async fn bulk_in(&self, dci: u8, out: &mut [u8]) -> Result<usize, UsbError> {
        let token = self.begin_bulk_in(dci, out.len())?;
        self.controller
            .wait_bulk_in(&token, out)
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
    pub fn poll_interrupt_in(&self, dci: u8, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        self.controller
            .poll_interrupt_in(self.slot_id, dci, out)
            .map_err(UsbError::from_xhci)
    }

    /// Configure one or more endpoints on this slot. Wraps the xHCI
    /// Configure Endpoint command.
    pub async fn configure_endpoints(&self, eps: &[EndpointConfig]) -> Result<(), UsbError> {
        self.controller
            .configure_endpoints_generation(self.slot_id, self.generation, eps)
            .await
            .map_err(UsbError::from_xhci)
    }

    /// Read the 18-byte Device Descriptor.
    pub async fn get_device_descriptor(&self) -> Result<[u8; 18], UsbError> {
        self.controller
            .get_device_descriptor_generation(self.slot_id, self.generation)
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
            .get_config_descriptor_generation(self.slot_id, self.generation, cfg_idx, out)
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
        interval: 0,
    }
}

pub fn bulk_out_ep(ep_num: u8, max_packet: u16) -> EndpointConfig {
    EndpointConfig {
        ep_addr: ep_num & 0x0F,
        max_packet,
        kind: EndpointKind::BulkOut,
        interval: 0,
    }
}

pub fn interrupt_in_ep(ep_num: u8, max_packet: u16) -> EndpointConfig {
    EndpointConfig {
        ep_addr: ep_num | 0x80,
        max_packet,
        kind: EndpointKind::InterruptIn,
        interval: 1,
    }
}

pub fn interrupt_out_ep(ep_num: u8, max_packet: u16) -> EndpointConfig {
    EndpointConfig {
        ep_addr: ep_num & 0x0F,
        max_packet,
        kind: EndpointKind::InterruptOut,
        interval: 1,
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
