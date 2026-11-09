//! CONNAC2 probe power sequence. Linux ecd997b0189a:
//! mt7921/pci.c::mt7921_pci_probe and mt792x_dma.c::mt792x_wfsys_reset.
use super::{mac::PowerError, regs::*};

#[derive(Clone, Copy, Debug)]
pub(super) enum Stage {
    FirmwareOwn,
    DriverOwn,
    ResetAssert,
    ResetRelease,
    ResetReady,
    Ready,
}

pub(super) trait Io {
    fn stage(&mut self, _stage: Stage) {}
    fn read(&mut self, address: u32) -> Result<u32, PowerError>;
    fn write(&mut self, address: u32, value: u32) -> Result<(), PowerError>;
    fn delay(&mut self, ms: u64);
    fn poll(&mut self, address: u32, mask: u32, expected: u32, ms: u64)
        -> Result<bool, PowerError>;
}

fn read(io: &mut impl Io, address: u32) -> Result<u32, PowerError> {
    let value = io.read(address)?;
    if value == u32::MAX {
        Err(PowerError::DeviceGone)
    } else {
        Ok(value)
    }
}

fn handshake(io: &mut impl Io, firmware: bool) -> Result<(), PowerError> {
    io.stage(if firmware {
        Stage::FirmwareOwn
    } else {
        Stage::DriverOwn
    });
    let (command, expected) = if firmware {
        (PCIE_LPCR_HOST_SET_OWN, PCIE_LPCR_HOST_OWN_SYNC)
    } else {
        (PCIE_LPCR_HOST_CLR_OWN, 0)
    };
    for _ in 0..DRV_OWN_RETRY_COUNT {
        io.write(MT_CONN_ON_LPCTL, command)?;
        if read(io, MT_CONN_ON_LPCTL)? & PCIE_LPCR_HOST_OWN_SYNC == expected {
            return Ok(());
        }
        if !firmware {
            io.delay(3);
        }
        if io.poll(
            MT_CONN_ON_LPCTL,
            PCIE_LPCR_HOST_OWN_SYNC,
            expected,
            DRV_OWN_POLL_MS,
        )? {
            return Ok(());
        }
    }
    Err(PowerError::Timeout)
}

pub(super) fn take_driver(io: &mut impl Io) -> Result<(), PowerError> {
    handshake(io, false)
}

pub(super) fn give_firmware(io: &mut impl Io) -> Result<(), PowerError> {
    handshake(io, true)
}

fn ownership_cycle(io: &mut impl Io) -> Result<(), PowerError> {
    handshake(io, true)?;
    handshake(io, false)
}

fn reset(io: &mut impl Io) -> Result<(), PowerError> {
    io.stage(Stage::ResetAssert);
    let value = read(io, MT_WFSYS_SW_RST_B)?;
    io.write(MT_WFSYS_SW_RST_B, value & !1)?;
    if read(io, MT_WFSYS_SW_RST_B)? & 1 != 0 {
        return Err(PowerError::ResetRejected);
    }
    io.delay(50);
    io.stage(Stage::ResetRelease);
    let value = read(io, MT_WFSYS_SW_RST_B)?;
    io.write(MT_WFSYS_SW_RST_B, value | 1)?;
    if read(io, MT_WFSYS_SW_RST_B)? & 1 == 0 {
        return Err(PowerError::ResetRejected);
    }
    io.stage(Stage::ResetReady);
    if !io.poll(MT_WFSYS_SW_RST_B, 1 << 4, 1 << 4, 500)? {
        return Err(PowerError::ResetTimeout);
    }
    Ok(())
}

/// Caller has parked PCI bus mastering and owns the function exclusively;
/// no live transport or published DMA may exist. No bus-master enable occurs
/// here. Linux requires driver ownership before touching WFSYS reset;
/// parking host DMA does not prove that the radio's register clocks are on.
pub(super) fn initialize(io: &mut impl Io) -> Result<(), PowerError> {
    ownership_cycle(io)?;
    // Linux resets WFSYS before DMA/firmware setup even on the normal probe
    // path. Do not depend on a previous OS having unloaded firmware cleanly.
    reset(io)?;
    // WFSYS reset must not silently invalidate our HIF ownership proof.
    handshake(io, false)?;
    io.write(MT_WFDMA0_HOST_INT_ENA, 0)?;
    io.write(MT_PCIE_MAC_INT_ENABLE, 0)?;
    io.write(MT_MCU2HOST_SW_INT_ENA, 0)?;
    io.stage(Stage::Ready);
    Ok(())
}
