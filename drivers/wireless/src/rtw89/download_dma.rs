// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Shared CH12-only download DMA preparation; PCI BME stays off at this layer.
use super::{
    mac::ChipId,
    power::{Error, Io},
};
fn read(io: &mut impl Io, a: u32) -> Result<u32, Error> {
    let value = io.read32(a)?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
fn modify(io: &mut impl Io, a: u32, clear: u32, set: u32) -> Result<(), Error> {
    let value = read(io, a)?;
    io.write32(a, (value & !clear) | set)
}
/// Caller retains actual FIFO/PCIe/BDRAM/mode and empty owned CH12 ring receipts,
/// current exclusive register access and independently fenced old DMA. BME is
/// verified off outside this function. There are deliberately no RX bases and
/// no RX HCI enable: Linux's all-RX runtime activation is a separate operation.
pub(super) fn prepare(io: &mut impl Io, chip: ChipId) -> Result<(), Error> {
    let c = chip == ChipId::Rtl8852C;
    let dual = match chip {
        ChipId::Rtl8852A | ChipId::Rtl8852C => true,
        ChipId::Rtl8852B | ChipId::Rtl8851B => false,
        ChipId::Rtl8922A => return Err(Error::Unsupported),
    };
    let tx = if c { 1 << 7 } else { 1 << 11 };
    let rx = if c { 1 << 15 } else { 1 << 13 };
    let hci = if c { 0x7880 } else { 0x8380 };
    let tx_mask = if dual { 0x7ff00 } else { 0x70f00 };
    let init = read(io, 0x1000)?;
    let stop = read(io, 0x1010)?;
    if init & (tx | rx) != 0
        || stop & (tx_mask | (1 << 19)) != tx_mask | (1 << 19)
        || if c {
            init & (1 << 17) == 0
        } else {
            stop & (1 << 20) == 0
        }
    {
        return Err(Error::Access);
    }
    // Only host TX DMA is prepared. Both independent RX-enable layers remain
    // clear before the eventual current-capability PCI BME publication.
    modify(io, hci, 2, 1)?;
    modify(io, 0x1010, 1 << 18, 0)?;
    modify(io, 0x1000, rx, tx)?;
    if c {
        modify(io, 0x1000, 1 << 17, 0)?;
    } else {
        modify(io, 0x1010, 1 << 20, 0)?;
    }
    let stop = read(io, 0x1010)?;
    let init = read(io, 0x1000)?;
    if stop & (tx_mask | (1 << 19)) != ((tx_mask & !(1 << 18)) | (1 << 19))
        || init & (tx | rx) != tx
        || read(io, hci)? & 3 != 1
        || if c {
            init & (1 << 17) != 0
        } else {
            stop & (1 << 20) != 0
        }
    {
        return Err(Error::Access);
    }
    Ok(())
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "download_dma/tests.rs"]
mod tests;
