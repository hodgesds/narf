//! AX physical EFUSE reads with one retained owner for uncertain operations.
//! Linux efuse.c: DDV uses CTRL0x30/RDY29/ADDR[26:16], bank0 on8852A,
//! PMC/isolation power-cut controls elsewhere and burst on8852B cutA.
use super::{
    mac::ChipId,
    power::{Error, Io},
};

#[derive(Debug, Default)]
pub(super) struct Ddv {
    terminal: bool,
}
impl Ddv {
    pub fn terminal() -> Self {
        Self { terminal: true }
    }
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }
    pub async fn read(
        &mut self,
        io: &mut impl Io,
        chip: ChipId,
        cut: u8,
        start: u16,
        output: &mut [u8],
    ) -> Result<(), Error> {
        if self.terminal {
            return Err(Error::Terminal);
        }
        if chip == ChipId::Rtl8922A || cut > 15 {
            return Err(Error::Unsupported);
        }
        if output.is_empty()
            || usize::from(start)
                .checked_add(output.len())
                .is_none_or(|end| end > 2048)
        {
            return Err(Error::Access);
        }
        self.terminal = true;
        open(io, chip, cut).await?;
        bytes(io, start, output).await?;
        // Isolation closure is restoration after a completed read. It is not
        // evidence that a timed-out controller operation has been aborted.
        close(io, chip, cut).await?;
        self.terminal = false;
        Ok(())
    }
}
fn set8(io: &mut impl Io, address: u32, mask: u8, value: u8) -> Result<(), Error> {
    let old = io.read8(address)?;
    io.write8(address, (old & !mask) | (value & mask))
}
fn set16(io: &mut impl Io, address: u32, mask: u16, value: u16) -> Result<(), Error> {
    let old = io.read16(address)?;
    io.write16(address, (old & !mask) | (value & mask))
}
fn set32(io: &mut impl Io, address: u32, mask: u32, value: u32) -> Result<(), Error> {
    let old = io.read32(address)?;
    io.write32(address, (old & !mask) | (value & mask))
}
async fn open(io: &mut impl Io, chip: ChipId, cut: u8) -> Result<(), Error> {
    if chip == ChipId::Rtl8852A {
        set32(io, 0x38, 3 << 8, 0)?;
        if io.read32(0x38)? & (3 << 8) != 0 {
            return Err(Error::Access);
        }
    } else {
        set8(io, 0xcc, 1 << 2, 1 << 2)?;
        set16(io, 0, 1 << 14, 1 << 14)?;
        io.delay_us(1000).await;
        set16(io, 0, 1 << 15, 1 << 15)?;
        set16(io, 0, 1 << 8, 0)?;
        if chip == ChipId::Rtl8852B && cut == 0 {
            set32(io, 0x38, 1 << 19, 1 << 19)?;
        }
    }
    Ok(())
}
async fn close(io: &mut impl Io, chip: ChipId, cut: u8) -> Result<(), Error> {
    if chip != ChipId::Rtl8852A {
        if chip == ChipId::Rtl8852B && cut == 0 {
            set32(io, 0x38, 1 << 19, 0)?;
        }
        set16(io, 0, 1 << 8, 1 << 8)?;
        set16(io, 0, 1 << 15, 0)?;
        io.delay_us(1000).await;
        set16(io, 0, 1 << 14, 0)?;
        set8(io, 0xcc, 1 << 2, 0)?;
    }
    Ok(())
}
async fn bytes(io: &mut impl Io, start: u16, output: &mut [u8]) -> Result<(), Error> {
    for (index, byte) in output.iter_mut().enumerate() {
        io.write32(0x30, (u32::from(start) + index as u32) << 16)?;
        let began = io.now_us();
        io.delay_us(1).await;
        loop {
            let value = io.read32(0x30)?;
            if value == u32::MAX {
                return Err(Error::Gone);
            }
            if value & (1 << 29) != 0 {
                *byte = value as u8;
                break;
            }
            if io.now_us().saturating_sub(began) >= 1_000_000 {
                return Err(Error::Timeout);
            }
            io.delay_us(1).await;
        }
    }
    Ok(())
}
