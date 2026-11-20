// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact AE GPIO radio-switch sample, hw.c::gpio_radio_on_off_checking.
//! Caller supplies the original measured Version/polarity. No rfkill default
//! or the unrelated EE0x6c BIT31 test can authorize this combo device.
use super::version::{Polarity, Version};
use crate::rtlwifi::{
    firmware_transport::{Error as AccessError, Io},
    prepare::Error,
};
pub fn on(io: &impl Io, version: Version) -> Result<(), Error> {
    let direction = io.read8(0x62)?;
    if direction == u8::MAX {
        return Err(Error::Access(AccessError::Gone));
    }
    io.write8(0x62, direction & !2)?;
    let pins = io.read8(0x60)?;
    if pins == u8::MAX {
        return Err(Error::Access(AccessError::Gone));
    }
    let on = match version.polarity() {
        Polarity::HighActive => pins & 2 == 0,
        Polarity::LowActive => pins & 2 != 0,
    };
    if on {
        Ok(())
    } else {
        Err(Error::RadioOff)
    }
}
