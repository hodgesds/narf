//! `narf-drivers-wireless-rtl-usb` / `narf-drivers-usb` names for the
//! module build, over the `narf_usb_*` KABI.
//!
//! Built in, rtl8xxxu drives its dongle through the shared Realtek USB
//! transport: `ControlIo` (vendor request `0x05` register reads/writes on
//! EP0) and `Io` (bulk/interrupt transfers named by xHCI DCI) over a kernel
//! `USBDevice`. Here the same traits, with the same signatures, run over the
//! module's USB device token: every transfer is a kernel-owned request
//! (`narf_usb_control` / `narf_usb_submit`) polled to its terminal status
//! (`narf_usb_poll`). Payloads are copied; module memory is never a DMA
//! target. Not carried: `clear_halt` (the KABI has no endpoint-halt
//! recovery), so a stalled bulk pipe ends the attempt instead of resetting.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

mod ffi {
    unsafe extern "C" {
        pub fn narf_usb_config_descriptor(
            dev: u64,
            buf: *mut u8,
            len: usize,
            out_len: *mut usize,
        ) -> i32;
        pub fn narf_usb_configure(
            dev: u64,
            endpoints: *const u8,
            count: usize,
            callback: usize,
            cookie: u64,
            out_urb: *mut u64,
        ) -> i32;
        pub fn narf_usb_control(
            dev: u64,
            setup: *const u8,
            data: *const u8,
            len: usize,
            callback: usize,
            cookie: u64,
            out_urb: *mut u64,
        ) -> i32;
        pub fn narf_usb_submit(
            dev: u64,
            endpoint: u8,
            data: *const u8,
            len: usize,
            callback: usize,
            cookie: u64,
            out_urb: *mut u64,
        ) -> i32;
        pub fn narf_usb_poll(
            dev: u64,
            urb: u64,
            buf: *mut u8,
            len: usize,
            out_len: *mut usize,
        ) -> i32;
        pub fn narf_usb_cancel(dev: u64, urb: u64) -> i32;
        pub fn narf_udelay(ns: u64) -> i32;
    }
}

const EAGAIN: i32 = -11;
const ENOBUFS: i32 = -105;
const ECANCELED: i32 = -125;

/// `REALTEK_USB_READ` / `REALTEK_USB_WRITE` / `REALTEK_USB_CMD_REQ`.
pub const REALTEK_USB_READ: u8 = 0xC0;
pub const REALTEK_USB_WRITE: u8 = 0x40;
pub const REALTEK_USB_CMD_REQ: u8 = 0x05;

/// `narf_drivers_usb::device::UsbError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbError {
    NotConfigured,
    StaleSlot,
    BufferTooSmall,
    Stall,
    Babble,
    TransactionError,
    Timeout,
    HardwareError(u8),
}

impl UsbError {
    /// A terminal URB status (a Linux errno) as the class driver sees it.
    fn from_status(status: i32) -> Self {
        match status {
            -32 => Self::Stall,
            -75 => Self::Babble,
            -71 | -84 => Self::TransactionError,
            -110 => Self::Timeout,
            -19 | -108 => Self::StaleSlot,
            -105 => Self::BufferTooSmall,
            other => Self::HardwareError(other.unsigned_abs().min(255) as u8),
        }
    }
}

/// The module's bound dongle: its USB token and identity.
#[derive(Debug)]
pub struct USBDevice {
    token: u64,
    vendor: u16,
    product: u16,
}

impl USBDevice {
    pub(crate) fn new(token: u64, vendor: u16, product: u16) -> Self {
        Self {
            token,
            vendor,
            product,
        }
    }
    pub fn vendor_id(&self) -> u16 {
        self.vendor
    }
    pub fn product_id(&self) -> u16 {
        self.product
    }
    pub(crate) fn token(&self) -> u64 {
        self.token
    }
}

/// Poll a request until terminal: briefly spinning in `narf_udelay` (EP0
/// and short bulk transfers finish well inside a millisecond), then on the
/// executor's 1 ms heartbeat.
async fn complete(dev: u64, urb: u64, buf: &mut [u8]) -> Result<usize, UsbError> {
    let mut spins = 0u32;
    loop {
        let mut n = 0usize;
        let (ptr, len) = if buf.is_empty() {
            (core::ptr::null_mut(), 0)
        } else {
            (buf.as_mut_ptr(), buf.len())
        };
        // SAFETY: `ptr` names `len` writable bytes (or is null with 0).
        let status = unsafe { ffi::narf_usb_poll(dev, urb, ptr, len, &mut n) };
        match status {
            EAGAIN if spins < 400 => {
                spins += 1;
                // SAFETY: argument-only call, 5 µs.
                let _ = unsafe { ffi::narf_udelay(5_000) };
            }
            EAGAIN => super::time::sleep_cycles(1_000_000).await,
            0 => return Ok(n),
            error => return Err(UsbError::from_status(error)),
        }
    }
}

/// Configure every bulk and interrupt endpoint of the probed configuration
/// (`narf_usb_configure`): the built-in USB stack configures a class
/// driver's endpoints at enumeration; a module asks for them by address.
pub(crate) async fn configure_endpoints(device: &USBDevice) -> Result<usize, UsbError> {
    let mut config = alloc::vec![0u8; 1024];
    let mut len = 0usize;
    // SAFETY: `config` names its length in writable bytes; `len` is live.
    let rc = unsafe {
        ffi::narf_usb_config_descriptor(device.token, config.as_mut_ptr(), config.len(), &mut len)
    };
    if rc != 0 {
        return Err(UsbError::from_status(rc));
    }
    config.truncate(len);
    let mut endpoints = Vec::new();
    let mut at = 0usize;
    while at + 2 <= config.len() {
        let size = usize::from(config[at]);
        if size < 2 || at + size > config.len() {
            break;
        }
        // ENDPOINT descriptor: bulk (2) or interrupt (3).
        if config[at + 1] == 5 && size >= 7 && matches!(config[at + 3] & 3, 2 | 3) {
            endpoints.push(config[at + 2]);
        }
        at += size;
    }
    if endpoints.is_empty() {
        return Err(UsbError::NotConfigured);
    }
    let mut urb = 0u64;
    // SAFETY: `endpoints` names `len` readable bytes; `urb` is live.
    let rc = unsafe {
        ffi::narf_usb_configure(
            device.token,
            endpoints.as_ptr(),
            endpoints.len(),
            0,
            0,
            &mut urb,
        )
    };
    if rc != 0 {
        return Err(UsbError::from_status(rc));
    }
    complete(device.token, urb, &mut []).await?;
    Ok(endpoints.len())
}

/// A submitted kernel request.
#[derive(Debug)]
pub struct BulkToken {
    urb: u64,
    /// Terminal status already collected (the request is consumed).
    done: AtomicBool,
}

/// `narf_drivers_wireless_rtl_usb::Io`: bulk/interrupt transfers by DCI.
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
    async fn clear_halt(&self, _endpoint: u8) -> Result<(), UsbError> {
        Err(UsbError::NotConfigured)
    }
}

/// `narf_drivers_wireless_rtl_usb::ControlIo`: EP0 vendor register access.
#[async_trait::async_trait]
pub trait ControlIo: Send + Sync {
    fn identity(&self) -> Option<(u16, u16)> {
        None
    }
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError>;
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError>;
    async fn configuration(&self, _out: &mut [u8]) -> Result<usize, UsbError> {
        Err(UsbError::NotConfigured)
    }
    async fn delay_us(&self, us: u64) {
        super::time::sleep_cycles(us.saturating_mul(1000)).await;
    }
}

/// DCI `2 * n + 1` is IN endpoint `n`, `2 * n` OUT endpoint `n`.
fn endpoint_for(dci: u8) -> u8 {
    let number = dci / 2;
    if dci & 1 == 1 {
        0x80 | number
    } else {
        number
    }
}

/// `narf_drivers_wireless_rtl_usb::UsbIo` over the KABI.
#[derive(Clone, Debug)]
pub struct UsbIo(Arc<USBDevice>);

impl UsbIo {
    pub fn new(device: Arc<USBDevice>) -> Self {
        Self(device)
    }

    fn submit(&self, endpoint: u8, data: *const u8, len: usize) -> Result<BulkToken, UsbError> {
        let mut urb = 0u64;
        // SAFETY: OUT: `data` names `len` readable bytes copied before
        // return; IN: null with the capacity. `urb` is a live local.
        let rc = unsafe { ffi::narf_usb_submit(self.0.token, endpoint, data, len, 0, 0, &mut urb) };
        if rc != 0 {
            return Err(UsbError::from_status(rc));
        }
        Ok(BulkToken {
            urb,
            done: AtomicBool::new(false),
        })
    }

    fn poll(&self, receipt: &BulkToken, bytes: &mut [u8]) -> Result<Option<usize>, UsbError> {
        if receipt.done.load(Ordering::Acquire) {
            return Err(UsbError::StaleSlot);
        }
        let mut n = 0usize;
        let (ptr, len) = if bytes.is_empty() {
            (core::ptr::null_mut(), 0)
        } else {
            (bytes.as_mut_ptr(), bytes.len())
        };
        // SAFETY: `ptr` names `len` writable bytes (or is null with 0).
        let status = unsafe { ffi::narf_usb_poll(self.0.token, receipt.urb, ptr, len, &mut n) };
        match status {
            EAGAIN => Ok(None),
            ENOBUFS => Err(UsbError::BufferTooSmall),
            status => {
                receipt.done.store(true, Ordering::Release);
                if status == 0 {
                    Ok(Some(n))
                } else {
                    Err(UsbError::from_status(status))
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Io for UsbIo {
    type Receipt = BulkToken;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<BulkToken, UsbError> {
        self.submit(endpoint_for(dci), core::ptr::null(), length)
    }
    fn poll_receive(
        &self,
        receipt: &BulkToken,
        bytes: &mut [u8],
    ) -> Result<Option<usize>, UsbError> {
        self.poll(receipt, bytes)
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<BulkToken, UsbError> {
        self.submit(endpoint_for(dci), bytes.as_ptr(), bytes.len())
    }
    fn poll_send(&self, receipt: &BulkToken) -> Result<Option<usize>, UsbError> {
        self.poll(receipt, &mut [])
    }
    async fn stop(&self, receipt: &BulkToken) -> Result<(), UsbError> {
        if receipt.done.load(Ordering::Acquire) {
            return Ok(());
        }
        // SAFETY: our own token and request.
        let _ = unsafe { ffi::narf_usb_cancel(self.0.token, receipt.urb) };
        let mut sink = alloc::vec![0u8; 16 * 1024];
        let result = complete(self.0.token, receipt.urb, &mut sink).await;
        receipt.done.store(true, Ordering::Release);
        match result {
            Ok(_) => Ok(()),
            Err(UsbError::HardwareError(code)) if i32::from(code) == -ECANCELED => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// `narf_drivers_wireless_rtl_usb::UsbControl` over the KABI.
#[derive(Debug)]
pub struct UsbControl {
    device: Arc<USBDevice>,
}

impl UsbControl {
    pub fn new(device: Arc<USBDevice>) -> Self {
        Self { device }
    }
    /// The retained dongle; the packet adapter reuses the identical token.
    pub fn device(&self) -> Arc<USBDevice> {
        self.device.clone()
    }

    async fn transfer(
        &self,
        request_type: u8,
        addr: u16,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, UsbError> {
        let input = request_type & 0x80 != 0;
        let length = if input { out.len() } else { data.len() };
        let length = u16::try_from(length).map_err(|_| UsbError::BufferTooSmall)?;
        let mut setup = [0u8; 8];
        setup[0] = request_type;
        setup[1] = REALTEK_USB_CMD_REQ;
        setup[2..4].copy_from_slice(&addr.to_le_bytes());
        setup[6..8].copy_from_slice(&length.to_le_bytes());
        let (ptr, len) = if input || data.is_empty() {
            (core::ptr::null(), 0)
        } else {
            (data.as_ptr(), data.len())
        };
        let mut urb = 0u64;
        // SAFETY: `setup` names 8 readable bytes; `ptr` names `len` readable
        // bytes copied before return (or is null with 0); `urb` is live.
        let rc = unsafe {
            ffi::narf_usb_control(self.device.token, setup.as_ptr(), ptr, len, 0, 0, &mut urb)
        };
        if rc != 0 {
            return Err(UsbError::from_status(rc));
        }
        complete(self.device.token, urb, out).await
    }
}

#[async_trait::async_trait]
impl ControlIo for UsbControl {
    fn identity(&self) -> Option<(u16, u16)> {
        Some((self.device.vendor, self.device.product))
    }
    async fn configuration(&self, out: &mut [u8]) -> Result<usize, UsbError> {
        let mut n = 0usize;
        // SAFETY: `out` names its length in writable bytes; `n` is live.
        let rc = unsafe {
            ffi::narf_usb_config_descriptor(self.device.token, out.as_mut_ptr(), out.len(), &mut n)
        };
        match rc {
            0 => Ok(n),
            ENOBUFS => Err(UsbError::BufferTooSmall),
            error => Err(UsbError::from_status(error)),
        }
    }
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        self.transfer(REALTEK_USB_READ, addr, &[], out).await
    }
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError> {
        self.transfer(REALTEK_USB_WRITE, addr, data, &mut [])
            .await?;
        Ok(data.len())
    }
}
