// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-matched RTL8188EE internal ASPM preparation. PCIe policy and
//! Link Control remain owned by the exact native PCI function adapter.
use super::firmware_transport::{Error, Io};
use core::sync::atomic::{AtomicBool, Ordering};
pub(super) trait Port: Io {
    fn write16(&self, register: u16, value: u16) -> Result<(), Error>;
}
pub(super) const CONTROL_MASK: u16 = 3 | (1 << 8);
/// Follow only an actual enabled parent policy and endpoint capabilities.
/// Common-clock configuration and the shared bridge are not modified here.
pub(super) fn policy(link_caps: u32, parent: Option<u16>, enabled: bool) -> u16 {
    if !enabled {
        return 0;
    }
    let states = ((link_caps >> 10) as u16 & 3) & parent.unwrap_or(0) & 3;
    states
        | if states != 0 && link_caps & (1 << 18) != 0 {
            1 << 8
        } else {
            0
        }
}
async fn idle(io: &impl Port) -> Result<(), Error> {
    // hw.c::_rtl88ee_enable_aspm_back_door: at most20 waits of10us.
    for attempt in 0..=20 {
        if io.read8(0x352)? == 0 {
            return Ok(());
        }
        if attempt == 20 {
            break;
        }
        io.delay_us(10).await;
    }
    Err(Error::Deadline)
}
async fn read(io: &impl Port, address: u16) -> Result<u32, Error> {
    idle(io).await?;
    io.write16(0x350, address)?;
    io.write8(0x352, 2)?;
    idle(io).await?;
    io.read32(0x34c)
}
async fn update(io: &impl Port, address: u16, bits: u32) -> Result<(), Error> {
    let before = read(io, address).await?;
    io.write32(0x348, before | bits)?;
    io.write16(0x350, 0xf000 | address)?;
    io.write8(0x352, 1)?;
    idle(io).await?;
    if read(io, address).await? != before | bits {
        return Err(Error::Gate);
    }
    Ok(())
}
/// Caller first proves endpoint ASPM/CLKREQ disabled and retains the native
/// preparation owner. Every MMIO/word write invokes its current authority.
pub(super) async fn prepare(io: &impl Port) -> Result<(), Error> {
    idle(io).await?;
    io.write16(0x354, 0x8104)?;
    io.write16(0x358, 0x0024)?;
    update(io, 0x70c, 1 << 31).await?;
    update(io, 0x718, (1 << 11) | (1 << 12)).await
}

pub(super) trait PolicyPort: Port {
    fn desired(&self, enabled: bool) -> Result<Option<u16>, Error>;
    fn control(&self, desired: u16) -> Result<(), Error>;
    fn prepared(&self) -> &AtomicBool;
}
/// Shared physical sequence; the native adapter alone supplies actual
/// configuration/parent authority. No endpoint entry precedes real DBI proof.
pub(super) async fn configure(io: &impl PolicyPort, enabled: bool) -> Result<(), Error> {
    let Some(desired) = io.desired(enabled)? else {
        return Ok(());
    };
    if desired == 0 {
        return io.control(0);
    }
    if !io.prepared().load(Ordering::Acquire) {
        io.control(0)?;
        prepare(io).await?;
        io.prepared().store(true, Ordering::Release);
    }
    let current = io.desired(enabled)?.ok_or(Error::Unsupported)?;
    io.control(current)?;
    io.delay_us(100).await;
    let current = io.desired(enabled)?.ok_or(Error::Unsupported)?;
    io.control(current)
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "aspm_tests.rs"]
pub(crate) mod tests;
