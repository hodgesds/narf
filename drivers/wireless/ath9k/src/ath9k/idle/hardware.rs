// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 D0 idle FULL_SLEEP, pinned Linux main.c::ath_ps_full_sleep and
//! hw.c::ath9k_set_power_sleep. This is not PCI D3 or system suspend.
use crate::ath9k::identity::{BringUpError, RegisterIo};

/// Original exclusive device ownership must gate every MMIO and config
/// access. Implementations observe actual PCI BME, never a cached desired bit.
pub(in crate::ath9k) trait Io: RegisterIo {
    fn bus_master(&mut self) -> Result<bool, BringUpError>;
}

fn read(io: &mut impl Io, register: u64) -> Result<u32, BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let value = io.read32(register);
    if value == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    Ok(value)
}

fn write(io: &mut impl Io, register: u64, value: u32) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(register, value);
    if read(io, register)? != value {
        return Err(BringUpError::BadState);
    }
    Ok(())
}

/// The controller must already have withdrawn the exact unassociated
/// generation and proved its terminal DMA stop. Keep its serialization and
/// original capability ownership through this complete transition. A failure
/// never supplies an asleep receipt or permission to replay old runtime state.
pub(in crate::ath9k) fn enter(io: &mut impl Io) -> Result<(), BringUpError> {
    if io.bus_master()?
        || read(io, 0x0008)? & 4 != 0 // AR_CR_RXE
        || read(io, 0x0840)? & 0x3ff != 0 // all native QCUs
        || read(io, 0x0024)? & 1 != 0 // AR_IER, not RXCFG
        || read(io, 0x402c)? != 0 // synchronous IRQ enable
        || read(io, 0x403c)? != 0 // asynchronous IRQ enable
        || read(io, 0x803c)? != 0 // native RX filter retired
        || read(io, 0x8048)? & 0x0200_0020 != 0x0200_0020
        || read(io, 0x7044)? & 15 != 2
    {
        return Err(BringUpError::BadState);
    }
    for queue in 0..10 {
        if read(io, 0x0a00 + queue * 4)? & 3 != 0 {
            return Err(BringUpError::BadState);
        }
    }
    // Actual RX state0 after RX_DIS|RX_ABORT, in addition to DMA RXE0.
    io.wait(0x806c, 0x01f0_0000, 0)?;
    let id = read(io, 0x8004)?;
    let wake = read(io, 0x704c)?;
    let rtc = read(io, 0x7040)?;
    write(io, 0x8004, id | 0x0004_0000)?;
    write(io, 0x704c, wake & !1)?;
    write(io, 0x4000, 0x101)?; // AR_RC_AHB|AR_RC_HOSTIF
    write(io, 0x7040, rtc & !1)?; // active-low RTC reset
    io.delay_us(2);
    // SHUTDOWN is1; NETWORK_SLEEP is4. Neither the request nor a zero status
    // word is a completed physical FULL_SLEEP observation.
    io.wait(0x7044, 15, 1)?;
    if io.bus_master()? {
        return Err(BringUpError::BadState);
    }
    Ok(())
}
