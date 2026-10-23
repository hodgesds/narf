//! Shared parked-DMA command policy for diagnostic Realtek PCI probes.
//!
//! No current rtw88/rtw89/rtlwifi runtime owns the complete firmware/DMA/reset
//! lifecycle. Revoke inherited bus mastering before BAR/power access; never
//! turn it back on merely because identity or software ring allocation passed.
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Access,
    NotParked,
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
