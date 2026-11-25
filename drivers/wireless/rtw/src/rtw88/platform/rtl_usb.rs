//! `narf_drivers_wireless_rtl_usb` for the module: the Realtek USB
//! transport traits rtw88's USB backend is written against
//! (`usb_firmware::Backend<C: ControlIo, P: Io>`), with the built-in
//! signatures. `usb_kabi.rs` implements them over `narf_usb_*`.

use alloc::boxed::Box;

use super::narf_drivers_usb::device::UsbError;

/// `REALTEK_USB_READ = 0xC0`.
pub const REALTEK_USB_READ: u8 = 0xC0;
/// `REALTEK_USB_WRITE = 0x40`.
pub const REALTEK_USB_WRITE: u8 = 0x40;
/// `REALTEK_USB_CMD_REQ = 0x05`.
pub const REALTEK_USB_CMD_REQ: u8 = 0x05;

/// Bulk pipes: non-blocking begin / poll receipts, as built in.
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

/// EP0 register and firmware access, as built in.
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
        super::narf_time::sleep_cycles(super::narf_time::ns_to_cycles(us.saturating_mul(1000)))
            .await;
    }
}
