//! Transport-agnostic Realtek chip register-programming core.
//!
//! The builtin rtw88 MAC/PHY/RF/station bring-up is a long sequence of chip
//! register reads/writes with read-modify-write updates and busy-poll loops.
//! It is written against an **async** register-I/O abstraction so the *same*
//! sequences run over every rtw88 transport (PCI MMIO and USB EP0), in both
//! the builtin driver and the loadable `.ko`: both builds compile the rtw
//! crate, whose `firmware_transport::Io` backends reach this core through
//! the `rtw88::chip_bridge` newtypes: `IoReg`, and `GatedIoReg`, which also
//! checks the native station gate before each access.
//!
//! [`RegIo`] mirrors the async RPITIT shape of the rtw `Io` trait
//! (`-> impl Future<Output = …> + Send`) so the newtypes forward each access
//! 1:1 with an error map. Only the six register widths + a delay are
//! required; the read-modify-write and poll helpers are free async functions
//! (free fns sidestep the provided-async-trait-method `Send` pitfalls).
//!
//! `#![no_std]`, `core` only, so the `module`-build `.ko` can link it. See
//! `drivers/wireless/specification/rtw88-usb-module-datapath.md`.

#![no_std]

use core::future::Future;

pub mod band5;
pub mod efuse;
pub mod mac;
pub mod phy;
pub mod phy_b22;
pub mod radio;
pub mod security_cam;
pub mod station;

/// Terminal result of a chip register operation. Register programming only
/// needs to distinguish the handful of outcomes the bring-up acts on; richer
/// driver errors stay in the consuming crates (which map to/from this).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChipError {
    /// A transfer failed on the wire / the transport refused it.
    Access,
    /// A register read returned the all-ones "device gone" pattern.
    Gone,
    /// A busy-poll did not reach its target state in time.
    Timeout,
    /// A precondition readback did not hold.
    Prerequisite,
    /// The chip / configuration is not one this core programs.
    Unsupported,
}

/// Async chip register access. The implementations are the rtw crate's
/// `chip_bridge::IoReg` and `chip_bridge::GatedIoReg`, which wrap a
/// `firmware_transport::Io` backend (PCI or USB, builtin or `.ko`). Mirrors
/// that `Io` trait's RPITIT shape so the newtypes forward each access 1:1.
pub trait RegIo {
    fn read8(&mut self, reg: u16) -> impl Future<Output = Result<u8, ChipError>> + Send;
    fn read16(&mut self, reg: u16) -> impl Future<Output = Result<u16, ChipError>> + Send;
    fn read32(&mut self, reg: u16) -> impl Future<Output = Result<u32, ChipError>> + Send;
    fn write8(&mut self, reg: u16, value: u8)
        -> impl Future<Output = Result<(), ChipError>> + Send;
    fn write16(
        &mut self,
        reg: u16,
        value: u16,
    ) -> impl Future<Output = Result<(), ChipError>> + Send;
    fn write32(
        &mut self,
        reg: u16,
        value: u32,
    ) -> impl Future<Output = Result<(), ChipError>> + Send;
    /// Busy-delay roughly `us` microseconds.
    fn delay_us(&mut self, us: u32) -> impl Future<Output = ()> + Send;
}

/// Read-modify-write: clear the `clear` bits then set the `set` bits.
pub async fn update8(io: &mut impl RegIo, reg: u16, clear: u8, set: u8) -> Result<(), ChipError> {
    let v = io.read8(reg).await?;
    io.write8(reg, v & !clear | set).await
}
pub async fn update16(
    io: &mut impl RegIo,
    reg: u16,
    clear: u16,
    set: u16,
) -> Result<(), ChipError> {
    let v = io.read16(reg).await?;
    io.write16(reg, v & !clear | set).await
}
pub async fn update32(
    io: &mut impl RegIo,
    reg: u16,
    clear: u32,
    set: u32,
) -> Result<(), ChipError> {
    let v = io.read32(reg).await?;
    if v == u32::MAX {
        return Err(ChipError::Gone);
    }
    io.write32(reg, v & !clear | set).await
}

/// Poll a 32-bit register until `value & mask == target`. Up to `attempts`
/// reads spaced by `delay_us`; `u32::MAX` means the device vanished. Mirrors
/// `firmware_transport.rs::poll`.
pub async fn poll32(
    io: &mut impl RegIo,
    reg: u16,
    mask: u32,
    target: u32,
    attempts: u32,
    delay_us: u32,
) -> Result<(), ChipError> {
    for _ in 0..attempts {
        let v = io.read32(reg).await?;
        if v == u32::MAX {
            return Err(ChipError::Gone);
        }
        if v & mask == target {
            return Ok(());
        }
        io.delay_us(delay_us).await;
    }
    Err(ChipError::Timeout)
}
