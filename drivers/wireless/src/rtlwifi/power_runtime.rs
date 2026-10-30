// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EE card-disable/enable sequencing for a retained reset owner.
//!
//! Linux rtl8188ee/hw.c::_rtl88ee_poweroff_adapter and pwrseq.h. This
//! transition is driven by the retained native recovery owner.
//! Callers must retain exclusive current PCI ownership, park bus mastering,
//! withdraw interrupts and prove the old packet DMA idle before these flows.
//! No operation here enables PCI bus mastering or releases a DMA allocation.
use super::{
    firmware_transport::{Error, Io},
    power::*,
};
use narf_time::Deadline;

async fn update(io: &impl Io, at: u16, clear: u8, set: u8) -> Result<(), Error> {
    let value = io.read8(at)?;
    io.write8(at, (value & !clear) | set)
}

async fn poll(io: &impl Io, at: u16, mask: u8, expected: u8) -> Result<(), Error> {
    let deadline = Deadline::after_ms(100);
    loop {
        if io.read8(at)? & mask == expected & mask {
            return Ok(());
        }
        if deadline.expired() {
            return Err(Error::Deadline);
        }
        io.delay_us(10).await;
    }
}

/// The existing source-backed power table, driven cooperatively. Each native
/// register operation remains inside PciIo's current capability invocation.
async fn flow(io: &impl Io, table: &[WlanPwrCfg]) -> Result<(), Error> {
    for row in table {
        if row.intf() & PWR_INTF_PCI_MSK == 0
            || row.cut_msk & PWR_CUT_ALL_MSK == 0
            || row.fab() & PWR_FAB_ALL_MSK == 0
        {
            continue;
        }
        if row.cmd() == PWR_CMD_END {
            return Ok(());
        }
        if row.base() != PWR_BASEADDR_MAC {
            return Err(Error::Unsupported);
        }
        match row.cmd() {
            PWR_CMD_READ => {
                io.read8(row.offset)?;
            }
            PWR_CMD_WRITE => {
                update(io, row.offset, row.msk, row.value & row.msk).await?;
            }
            PWR_CMD_POLLING => poll(io, row.offset, row.msk, row.value).await?,
            PWR_CMD_DELAY => {
                let us = match row.value {
                    PWRSEQ_DELAY_US => u64::from(row.offset),
                    PWRSEQ_DELAY_MS => u64::from(row.offset) * 1000,
                    _ => return Err(Error::Unsupported),
                };
                io.delay_us(us).await;
            }
            _ => return Err(Error::Unsupported),
        }
    }
    Err(Error::Unsupported)
}

/// Restore CardDisabled/CardEmu to Active before the fresh firmware download,
/// LLT, radio IQ/LC and packet-ring initialization. Uses the same qualified
/// RTL8188EE table as initial probe, including the card-enable prefix.
pub(super) async fn enable(io: &impl Io) -> Result<(), Error> {
    update(io, 0x7c, 1, 0).await?;
    update(io, 5, 0x80, 0).await?;
    io.write8(0x1c, 0)?;
    flow(io, RTL8188EE_PWR_ON).await
}

/// Stop the firmware CPU and execute ACT→LPS→CardEmu→CardDisabled after
/// the independent old-DMA retirement proof. Firmware self-reset is the
/// source's SYS_FUNC_EN+1 bit2 pulse, followed by its final disabled state.
/// A cancelled future leaves the logical owner closed and the bus parked;
/// no firmware-ready or quiescence receipt is inferred from submission.
pub(super) async fn disable(io: &impl Io, firmware_ready: bool) -> Result<(), Error> {
    update(io, 0x4ec, 2, 0).await?; // TX report timer off.
    poll(io, 0x286, 2, 2).await?; // RXDMA_IDLE, not a loop-count proof.
    io.write8(0x301, 0xff)?; // Stop host TX DMA.

    // RTL8188EE_TRANS_ACT_TO_LPS (PCI rows), in source order.
    io.write8(0x522, 0x7f)?;
    for reg in 0x5f8..=0x5fb {
        poll(io, reg, 0xff, 0).await?;
    }
    update(io, 2, 1, 0).await?;
    io.delay_us(2).await; // Native table's PWR_CMD_DELAY offset is 0x0002.
    io.write8(0x100, 0x3f)?;
    update(io, 0x101, 2, 0).await?;
    update(io, 0x553, 0, 0x20).await?;
    io.write8(0x1f, 0)?; // RF off.

    if io.read8(0x80)? & 0x80 != 0 && firmware_ready {
        let function = io.read8(3)?;
        io.write8(3, function & !4)?;
        io.write8(3, function | 4)?;
    }
    update(io, 3, 4, 0).await?;
    io.write8(0x80, 0)?;
    update(io, 0x194, 1, 0).await?;

    // NIC_DISABLE_FLOW: ACT→CardEmu, then PCI CardEmu→CardDisabled.
    io.write8(0x1f, 0)?;
    update(io, 0x23, 0, 0x10).await?;
    update(io, 5, 0, 2).await?;
    poll(io, 5, 2, 0).await?;
    update(io, 0x26, 0, 0x80).await?;

    update(io, 0x1d, 8, 0).await?;
    update(io, 0x1d, 0, 8).await?;
    io.write8(0x1c, 0x0e)?;
    io.write8(0x45, io.read8(0x44)?)?;
    io.write8(0x46, 0x7f)?;
    let gpio = io.read8(0x42)?;
    io.write8(0x42, (gpio << 4) | gpio)?;
    update(io, 0x43, 0, 0x0f).await?;
    io.write32(0x64, 0x0008_0808)?;
    Ok(())
}
