//! Shared parked-DMA command policy for diagnostic Realtek PCI probes.
//!
//! No current rtw88/rtw89/rtlwifi runtime owns the complete firmware/DMA/reset
//! lifecycle. Revoke inherited bus mastering before BAR/power access; never
//! turn it back on merely because identity or software ring allocation passed.
use narf_bus::{BarError, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Access,
    NotParked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Initialize,
    Bound,
    ParkExtra,
}

pub(crate) fn admission(
    bound: Option<narf_bus::BusAddr>,
    candidate: narf_bus::BusAddr,
) -> Admission {
    match bound {
        None => Admission::Initialize,
        Some(address) if address == candidate => Admission::Bound,
        Some(_) => Admission::ParkExtra,
    }
}

pub(crate) fn park_with(
    clear: impl FnOnce(u16) -> Result<u16, ()>,
    set: impl FnOnce(u16) -> Result<u16, ()>,
    read: impl FnOnce() -> Result<u16, ()>,
) -> Result<(), Error> {
    use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
    clear(BUS_MASTER).map_err(|_| Error::Access)?;
    set(MEM_SPACE | INTX_DISABLE).map_err(|_| Error::Access)?;
    let command = read().map_err(|_| Error::Access)?;
    if command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != (MEM_SPACE | INTX_DISABLE) {
        return Err(Error::NotParked);
    }
    Ok(())
}

pub(crate) fn park(device: &BusDevice, cap: &Cap<BusDeviceCap, Write>) -> Result<(), Error> {
    park_with(
        |bits| narf_bus::pci::clear_command(cap, device, bits).map_err(|_| ()),
        |bits| narf_bus::pci::set_command(cap, device, bits).map_err(|_| ()),
        || narf_bus::pci::read_command(cap, device).map_err(|_| ()),
    )
}

/// Keep the actual mapping/register operation inside the epoch-checked
/// capability invocation. A separate prior authority check is insufficient.
pub(crate) fn invoke<T>(
    cap: &Cap<BusDeviceCap, Write>,
    operation: impl FnOnce() -> T,
) -> Result<T, CapError> {
    struct Registers<F>(F);
    impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Registers<F> {
        type Output = T;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
            Ok(self.0())
        }
    }
    cap.invoke(Registers(operation))
}

/// BAR sizing writes all ones and restores the original BAR. Decode and
/// inherited DMA must both be verified off during the entire operation.
pub(super) fn map_with<T>(
    mut clear: impl FnMut(u16) -> Result<u16, ()>,
    mut set: impl FnMut(u16) -> Result<u16, ()>,
    mut read: impl FnMut() -> Result<u16, ()>,
    map: impl FnOnce() -> Result<T, BarError>,
) -> Result<T, BarError> {
    use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
    let policy = BUS_MASTER | MEM_SPACE | INTX_DISABLE;
    clear(BUS_MASTER | MEM_SPACE).map_err(|_| BarError::MappingFailed)?;
    set(INTX_DISABLE).map_err(|_| BarError::MappingFailed)?;
    if read().map_err(|_| BarError::MappingFailed)? & policy != INTX_DISABLE {
        return Err(BarError::MappingFailed);
    }
    let region = map()?;
    set(MEM_SPACE).map_err(|_| BarError::MappingFailed)?;
    if read().map_err(|_| BarError::MappingFailed)? & policy != MEM_SPACE | INTX_DISABLE {
        return Err(BarError::MappingFailed);
    }
    Ok(region)
}

pub(crate) fn map_bar_control(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    index: u8,
) -> Result<MmioRegion, BarError> {
    invoke(cap, || {
        map_with(
            |bits| narf_bus::pci::clear_command(cap, device, bits).map_err(|_| ()),
            |bits| narf_bus::pci::set_command(cap, device, bits).map_err(|_| ()),
            || narf_bus::pci::read_command(cap, device).map_err(|_| ()),
            || {
                // SAFETY: the caller owns this function exclusively; the
                // current invocation covers sizing and mapping, with command
                // readback proving MEM/BME off before every BAR sizing write.
                unsafe { narf_bus::map_bar_control(device, index) }
            },
        )
    })
    .map_err(|_| BarError::MappingFailed)?
}
