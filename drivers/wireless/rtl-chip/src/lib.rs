//! Transport-agnostic Realtek chip register-programming core.
//!
//! The builtin rtw88 MAC/PHY/RF/station bring-up is a long sequence of chip
//! register reads/writes with read-modify-write updates and busy-poll loops.
//! It is written against a register-I/O abstraction so the *same* sequences run
//! from two transports:
//!
//! - the **builtin** driver, over its native `UsbControl`/MMIO transport;
//! - the **loadable `.ko`**, over the `narf_usb_*` EP0-control C-ABI (a
//!   synchronous `RegIo` impl in `narf-drivers-wireless-rtw`'s module build).
//!
//! This crate is `#![no_std]` and depends only on `core`, so the `module`-build
//! `.ko` can link it (no kernel crate is pulled in). See
//! `drivers/wireless/specification/rtw88-usb-module-datapath.md`.
//!
//! ## Staging
//!
//! Stage 1 (here): the [`RegIo`] trait + [`ChipError`]. The MAC (`mac.rs`),
//! PHY (`phy.rs`), RF (`radio.rs`), calibration and station register
//! programming move onto `RegIo` in subsequent non-breaking slices — the
//! builtin driver re-exports them, and the `.ko` gains MAC/PHY/station without
//! reimplementation.

#![no_std]

/// Terminal result of a chip register operation. Register programming only
/// needs to distinguish the handful of outcomes the bring-up acts on; richer
/// driver errors stay in the consuming crates.
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

/// Synchronous chip register access. One implementation wraps the builtin
/// native transport; another the `.ko`'s `narf_usb_*` EP0 control path. Only
/// the three widths + a microsecond delay are required; the read-modify-write
/// and poll helpers are provided.
///
/// Every method is blocking: the bring-up is a task-context sequence of short
/// transfers, so implementations may busy-wait on their transport.
pub trait RegIo {
    /// Read an 8/16/32-bit register.
    fn read8(&mut self, reg: u16) -> Result<u8, ChipError>;
    fn read16(&mut self, reg: u16) -> Result<u16, ChipError>;
    fn read32(&mut self, reg: u16) -> Result<u32, ChipError>;
    /// Write an 8/16/32-bit register.
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), ChipError>;
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), ChipError>;
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), ChipError>;
    /// Busy-delay roughly `us` microseconds.
    fn delay_us(&mut self, us: u32);

    /// Read-modify-write: clear the `clear` bits then set the `set` bits.
    fn update8(&mut self, reg: u16, clear: u8, set: u8) -> Result<(), ChipError> {
        let v = self.read8(reg)?;
        self.write8(reg, v & !clear | set)
    }
    fn update16(&mut self, reg: u16, clear: u16, set: u16) -> Result<(), ChipError> {
        let v = self.read16(reg)?;
        self.write16(reg, v & !clear | set)
    }
    fn update32(&mut self, reg: u16, clear: u32, set: u32) -> Result<(), ChipError> {
        let v = self.read32(reg)?;
        if v == u32::MAX {
            return Err(ChipError::Gone);
        }
        self.write32(reg, v & !clear | set)
    }

    /// Poll a 32-bit register until `value & mask == target`. Up to
    /// `attempts` reads spaced by `delay_us`; `u32::MAX` means the device
    /// vanished. Mirrors `firmware_transport.rs::poll`.
    fn poll32(
        &mut self,
        reg: u16,
        mask: u32,
        target: u32,
        attempts: u32,
        delay_us: u32,
    ) -> Result<(), ChipError> {
        for _ in 0..attempts {
            let v = self.read32(reg)?;
            if v == u32::MAX {
                return Err(ChipError::Gone);
            }
            if v & mask == target {
                return Ok(());
            }
            self.delay_us(delay_us);
        }
        Err(ChipError::Timeout)
    }
}
