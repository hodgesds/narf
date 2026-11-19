// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Serialized AX PCIe PHY/DBI access from Linux rtw89/pci.c. These are
//! prerequisites for PCIe calibration/quirks, not DMA or radio admission.
use super::{
    mac::ChipId,
    power::{Error, Io},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    One,
    Two,
}
#[derive(Debug, Default)]
pub struct Access {
    terminal: bool,
}
impl Access {
    pub const fn terminal() -> Self {
        Self { terminal: true }
    }
    fn begin(&mut self, chip: ChipId) -> Result<(), Error> {
        if self.terminal {
            return Err(Error::Terminal);
        }
        if chip == ChipId::Rtl8922A {
            return Err(Error::Unsupported);
        }
        self.terminal = true;
        Ok(())
    }
    pub async fn read_phy(
        &mut self,
        io: &mut impl Io,
        chip: ChipId,
        generation: Generation,
        address: u8,
    ) -> Result<u16, Error> {
        if address >= 64 {
            return Err(Error::Access);
        }
        self.begin(chip)?;
        let result = read_phy(io, chip, generation, address).await;
        if result.is_ok() {
            self.terminal = false;
        }
        result
    }
    pub async fn write_phy(
        &mut self,
        io: &mut impl Io,
        chip: ChipId,
        generation: Generation,
        address: u8,
        value: u16,
    ) -> Result<(), Error> {
        if address >= 64 {
            return Err(Error::Access);
        }
        self.begin(chip)?;
        let result = write_phy(io, chip, generation, address, value).await;
        if result.is_ok() {
            self.terminal = false;
        }
        result
    }
    pub async fn modify_phy(
        &mut self,
        io: &mut impl Io,
        chip: ChipId,
        generation: Generation,
        address: u8,
        mask: u16,
        value: u16,
    ) -> Result<(), Error> {
        if address >= 64 || mask == 0 {
            return Err(Error::Access);
        }
        if (u32::from(value) << mask.trailing_zeros()) & !u32::from(mask) != 0 {
            return Err(Error::Access);
        }
        self.begin(chip)?;
        let result = async {
            let old = read_phy(io, chip, generation, address).await?;
            write_phy(
                io,
                chip,
                generation,
                address,
                (old & !mask) | ((value << mask.trailing_zeros()) & mask),
            )
            .await
        }
        .await;
        if result.is_ok() {
            self.terminal = false;
        }
        result
    }
    /// Explicit DBI fallback for a failed PCI configuration transaction. C
    /// lacks this supported fallback. The primary config owner chooses it.
    pub async fn read_dbi(
        &mut self,
        io: &mut impl Io,
        chip: ChipId,
        address: u16,
    ) -> Result<u8, Error> {
        if address >= 4096 {
            return Err(Error::Access);
        }
        if !matches!(chip, ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8851B) {
            return Err(Error::Unsupported);
        }
        self.begin(chip)?;
        let result = async {
            dbi_idle(io)?;
            io.write16(0x1090, address & 0xffc)?;
            io.write8(0x1092, 2)?;
            dbi_done(io).await?;
            io.read8(0x1098 + u32::from(address & 3))
        }
        .await;
        if result.is_ok() {
            self.terminal = false;
        }
        result
    }
    pub async fn write_dbi(
        &mut self,
        io: &mut impl Io,
        chip: ChipId,
        address: u16,
        value: u8,
    ) -> Result<(), Error> {
        if address >= 4096 {
            return Err(Error::Access);
        }
        if !matches!(chip, ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8851B) {
            return Err(Error::Unsupported);
        }
        self.begin(chip)?;
        let result = async {
            dbi_idle(io)?;
            let byte = address & 3;
            io.write8(0x1094 + u32::from(byte), value)?;
            io.write16(0x1090, (address & 0xffc) | ((1 << byte) << 12))?;
            io.write8(0x1092, 1)?;
            dbi_done(io).await
        }
        .await;
        if result.is_ok() {
            self.terminal = false;
        }
        result
    }
}
fn direct(generation: Generation, address: u8) -> u32 {
    (match generation {
        Generation::One => 0x3800,
        Generation::Two => 0x3880,
    }) + u32::from(address) * 2
}
async fn read_phy(
    io: &mut impl Io,
    chip: ChipId,
    generation: Generation,
    address: u8,
) -> Result<u16, Error> {
    if chip == ChipId::Rtl8852C {
        return io.read16(direct(generation, address));
    }
    mdio_idle(io)?;
    mdio_done(io, generation, address, 1 << 9).await?;
    io.read16(0x10a6)
}
async fn write_phy(
    io: &mut impl Io,
    chip: ChipId,
    generation: Generation,
    address: u8,
    value: u16,
) -> Result<(), Error> {
    if chip == ChipId::Rtl8852C {
        return io.write16(direct(generation, address), value);
    }
    mdio_idle(io)?;
    io.write16(0x10a4, value)?;
    mdio_done(io, generation, address, 1 << 8).await
}
fn mdio_idle(io: &mut impl Io) -> Result<(), Error> {
    let value = io.read16(0x10a0)?;
    if value == u16::MAX {
        return Err(Error::Gone);
    }
    // Never overwrite a pre-existing controller request of unknown ownership.
    if value & 0x300 != 0 {
        return Err(Error::Terminal);
    }
    Ok(())
}
fn dbi_idle(io: &mut impl Io) -> Result<(), Error> {
    let value = io.read8(0x1092)?;
    if value == u8::MAX {
        return Err(Error::Gone);
    }
    if value != 0 {
        return Err(Error::Terminal);
    }
    Ok(())
}

async fn mdio_done(
    io: &mut impl Io,
    generation: Generation,
    address: u8,
    flag: u16,
) -> Result<(), Error> {
    io.write8(0x10a0, address & 31)?;
    let old = io.read16(0x10a0)?;
    if old == u16::MAX {
        return Err(Error::Gone);
    }
    let page = u16::from(address >= 32) + if generation == Generation::Two { 2 } else { 0 };
    io.write16(0x10a0, (old & !0x3000) | (page << 12))?;
    let old = io.read16(0x10a0)?;
    if old == u16::MAX {
        return Err(Error::Gone);
    }
    io.write16(0x10a0, old | flag)?;
    let began = io.now_us();
    loop {
        let value = io.read16(0x10a0)?;
        if value == u16::MAX {
            return Err(Error::Gone);
        }
        if value & flag == 0 {
            return Ok(());
        }
        if io.now_us().saturating_sub(began) >= 2000 {
            return Err(Error::Timeout);
        }
        io.delay_us(10).await;
    }
}
async fn dbi_done(io: &mut impl Io) -> Result<(), Error> {
    let began = io.now_us();
    loop {
        let value = io.read8(0x1092)?;
        if value == u8::MAX {
            return Err(Error::Gone);
        }
        if value == 0 {
            return Ok(());
        }
        if io.now_us().saturating_sub(began) >= 200 {
            return Err(Error::Timeout);
        }
        io.delay_us(10).await;
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy_access/tests.rs"]
mod tests;
