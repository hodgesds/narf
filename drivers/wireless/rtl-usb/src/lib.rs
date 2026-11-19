// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared Realtek USB transport primitives.
//!
//! The bus-generic USB transport that both the rtl8xxxu driver and rtw88's USB
//! datapath are built on: the [`Io`]/[`ControlIo`] traits, their
//! [`UsbIo`]/[`UsbControl`] concrete USB-device wrappers, and the shared
//! [`RTL8XXXU_USB_IDS`] match table. Factored out of the rtl8xxxu driver so the
//! Realtek Wi-Fi family crate can reuse them without depending on a driver
//! crate. Chip-specific machinery (the `Owner<I>` engines, packet codecs,
//! per-chip init/radio) stays in rtl8xxxu.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use narf_drivers_usb::class_registry::UsbClassMatch;
use narf_drivers_usb::device::{BulkToken, USBDevice, UsbError};

// Realtek vendor USB control request constants (`rtl8xxxu.h`), used by
// [`UsbControl`].
/// `REALTEK_USB_READ = 0xC0`.
pub const REALTEK_USB_READ: u8 = 0xC0;
/// `REALTEK_USB_WRITE = 0x40`.
pub const REALTEK_USB_WRITE: u8 = 0x40;
/// `REALTEK_USB_CMD_REQ = 0x05`.
pub const REALTEK_USB_CMD_REQ: u8 = 0x05;

// Realtek USB VID/PIDs referenced by [`RTL8XXXU_USB_IDS`].
pub const RTL8XXXU_VENDOR: u16 = 0x0BDA;
pub const RTL8188EU_ID: u16 = 0x8179;
pub const RTL8188EU_ID_ALT: u16 = 0x0179;
pub const RTL8192EU_ID: u16 = 0x818B;
pub const RTL8192EU_ID_ALT: u16 = 0x818C;
pub const RTL8723BU_ID: u16 = 0xB720;

/// No caller/DMA alias survives a begin call: native USB stages TX bytes and
/// retains RX storage itself. Only an exact terminal receipt may copy/reuse.
#[async_trait::async_trait]
pub trait Io: Send + Sync {
    type Receipt: Send + Sync;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<Self::Receipt, UsbError>;
    fn poll_receive(
        &self,
        receipt: &Self::Receipt,
        bytes: &mut [u8],
    ) -> Result<Option<usize>, UsbError>;
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<Self::Receipt, UsbError>;
    fn poll_send(&self, receipt: &Self::Receipt) -> Result<Option<usize>, UsbError>;
    async fn stop(&self, receipt: &Self::Receipt) -> Result<(), UsbError>;
    /// Host Reset Endpoint + Set TR Dequeue, then device
    /// CLEAR_FEATURE(ENDPOINT_HALT) for `endpoint` (descriptor address).
    /// Any retained receipt on that pipe becomes stale.
    async fn clear_halt(&self, _endpoint: u8) -> Result<(), UsbError> {
        Err(UsbError::NotConfigured)
    }
}
#[derive(Clone)]
pub struct UsbIo(Arc<USBDevice>);
impl core::fmt::Debug for UsbIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euUsbIo").finish_non_exhaustive()
    }
}
impl UsbIo {
    pub fn new(device: Arc<USBDevice>) -> Self {
        Self(device)
    }
}
#[async_trait::async_trait]
impl Io for UsbIo {
    type Receipt = BulkToken;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<BulkToken, UsbError> {
        self.0.begin_bulk_in(dci, length)
    }
    fn poll_receive(
        &self,
        receipt: &BulkToken,
        bytes: &mut [u8],
    ) -> Result<Option<usize>, UsbError> {
        self.0.poll_bulk_in(receipt, bytes)
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<BulkToken, UsbError> {
        self.0.begin_bulk_out(dci, bytes)
    }
    fn poll_send(&self, receipt: &BulkToken) -> Result<Option<usize>, UsbError> {
        self.0.poll_bulk_out(receipt)
    }
    async fn stop(&self, receipt: &BulkToken) -> Result<(), UsbError> {
        self.0.stop_bulk(receipt).await
    }
    async fn clear_halt(&self, endpoint: u8) -> Result<(), UsbError> {
        self.0.clear_endpoint_halt(endpoint).await
    }
}

/// All register and firmware writes use EP0 with request 0x05, value=address,
/// index=0. The trait requires exact-count checking at the owner boundary.
#[async_trait::async_trait]
pub trait ControlIo: Send + Sync {
    #[cfg(any(test, feature = "kernel-test"))]
    fn inert_source_fixture(&self) -> bool {
        false
    }
    fn identity(&self) -> Option<(u16, u16)> {
        None
    }
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError>;
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError>;
    async fn configuration(&self, _out: &mut [u8]) -> Result<usize, UsbError> {
        Err(UsbError::NotConfigured)
    }
    async fn delay_us(&self, us: u64) {
        narf_time::sleep_cycles(narf_time::ns_to_cycles(us.saturating_mul(1000))).await;
    }
}

/// Production transport retains the enumerated USB handle for the entire
/// attempt. The owner serializes its sequence; it never nests block_on in an
/// executor poll or holds an IRQ-disabling lock across USB awaits.
#[derive(Debug)]
pub struct UsbControl {
    device: Arc<USBDevice>,
}

impl UsbControl {
    pub fn new(device: Arc<USBDevice>) -> Self {
        Self { device }
    }

    /// The retained enumerated USB handle. The packet adapter must reuse the
    /// identical generation and controller as EP0.
    pub fn device(&self) -> Arc<USBDevice> {
        self.device.clone()
    }
}

#[async_trait::async_trait]
impl ControlIo for UsbControl {
    fn identity(&self) -> Option<(u16, u16)> {
        Some((self.device.vendor_id(), self.device.product_id()))
    }
    async fn configuration(&self, out: &mut [u8]) -> Result<usize, UsbError> {
        self.device.get_config_descriptor(0, out).await
    }
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        self.device
            .control_in(REALTEK_USB_READ, REALTEK_USB_CMD_REQ, addr, 0, out)
            .await
    }

    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError> {
        self.device
            .control_out(REALTEK_USB_WRITE, REALTEK_USB_CMD_REQ, addr, 0, data)
            .await
    }
}

pub static RTL8XXXU_USB_IDS: &[narf_drivers_usb::class_registry::UsbClassMatch] = {
    &[
        // Primary Realtek-vendor IDs.
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8188EU_ID),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8188EU_ID_ALT),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8192EU_ID),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8192EU_ID_ALT),
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, RTL8723BU_ID),
        // RTL8710BU / RTL8188GU
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, 0xB711),
        // RTL8188EU rosewill ffef
        UsbClassMatch::vid_pid(RTL8XXXU_VENDOR, 0xFFEF),
        // Rebranded — TP-Link
        UsbClassMatch::vid_pid(0x2357, 0x0108),
        UsbClassMatch::vid_pid(0x2357, 0x0109),
        UsbClassMatch::vid_pid(0x2357, 0x010C),
        UsbClassMatch::vid_pid(0x2357, 0x0111),
        // Rebranded RTL8192EU (core.c dev_table `rtl8192eu_fops`).
        UsbClassMatch::vid_pid(0x2357, 0x0107),
        UsbClassMatch::vid_pid(0x2357, 0x0126),
        UsbClassMatch::vid_pid(0x2019, 0xAB33),
        UsbClassMatch::vid_pid(0x2001, 0x3312),
        UsbClassMatch::vid_pid(0x2C4E, 0x0100),
        UsbClassMatch::vid_pid(0x2C4E, 0x0104),
        // Rebranded — D-Link
        UsbClassMatch::vid_pid(0x2001, 0x3319),
        UsbClassMatch::vid_pid(0x2001, 0x3311),
        // Rebranded — Edimax
        UsbClassMatch::vid_pid(0x7392, 0xB811),
        UsbClassMatch::vid_pid(0x7392, 0xA611),
        // Rebranded — ASUS
        UsbClassMatch::vid_pid(0x0B05, 0x18F0),
        // Rebranded — Abocom
        UsbClassMatch::vid_pid(0x07B8, 0x8179),
    ]
};
