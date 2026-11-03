// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact CM3 passive sequence, independent of host/card IRQ retirement.
//! Linux7.3-rc4 chip.c::brcmf_chip_cm3_set_passive. This is not a
//! board-power-off, reset/reboot, host DMA or FIFO-quiescence substitute.
use super::core::{D11, SDIO_DEVICE, SOC_RAM, WLAN_ARM};
use crate::brcmfmac::chip::{Backplane, Chip, Core, Error};

fn unique(chip: &Chip, id: u16) -> Result<Core, Error> {
    let mut matching = chip.cores.iter().copied().filter(|core| core.id == id);
    let core = matching.next().ok_or(Error::MissingCore)?;
    if matching.next().is_some() {
        return Err(Error::MalformedErom);
    }
    Ok(core)
}
fn masked(bus: &mut impl Backplane, address: u32, mask: u32, expected: u32) -> Result<(), Error> {
    let value = bus.read32(address)?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    if value & mask != expected {
        return Err(Error::Access);
    }
    Ok(())
}

pub(super) struct Prepared {
    arm: Core,
    d11: Core,
    ram: Core,
}
/// Caller retains actual original signed host/card ownership for every
/// Backplane invocation. All discovered geometry is checked before mutation.
pub(super) fn prepare(bus: &mut impl Backplane, packet_core: u32) -> Result<Prepared, Error> {
    let chip = Chip::discover_ai(bus)?;
    if chip.id != 43439 {
        return Err(Error::UnsupportedInterconnect);
    }
    let arm = unique(&chip, WLAN_ARM)?;
    let d11 = unique(&chip, D11)?;
    let ram = unique(&chip, SOC_RAM)?;
    let sdio = unique(&chip, SDIO_DEVICE)?;
    if sdio.base != packet_core {
        return Err(Error::Access);
    }
    Ok(Prepared { arm, d11, ram })
}
pub(super) fn enter(bus: &mut impl Backplane, prepared: &Prepared) -> Result<(), Error> {
    let Prepared { arm, d11, ram } = *prepared;
    // CM3 is held in reset before resetting the MAC and internal RAM. The
    // source intentionally leaves D11/RAM reset released after passive.
    Chip::disable_core(bus, arm, 0, 0)?;
    Chip::reset_core(bus, d11, 12, 4, 4)?;
    Chip::reset_core(bus, ram, 0, 0, 0)?;
    // 43439 must not retain firmware's bank3 address remap.
    bus.write32(ram.base + 0x10, 3)?;
    bus.write32(ram.base + 0x44, 0)?;
    masked(bus, ram.base + 0x10, u32::MAX, 3)?;
    masked(bus, ram.base + 0x44, u32::MAX, 0)?;
    masked(bus, arm.wrapper + 0x800, 1, 1)?;
    masked(bus, arm.wrapper + 0x408, 3, 3)?;
    masked(bus, d11.wrapper + 0x800, 1, 0)?;
    masked(bus, d11.wrapper + 0x408, 15, 5)?;
    masked(bus, ram.wrapper + 0x800, 1, 0)?;
    masked(bus, ram.wrapper + 0x408, 3, 1)
}
