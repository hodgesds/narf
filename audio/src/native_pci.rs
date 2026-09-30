//! PCI power prerequisite for native audio, before enabling memory/bus mastering.
use narf_bus::{BusDevice, BusDeviceCap, BusKind, ProbeError};
use narf_capabilities::{Cap, CapError, CapOp, Write};

pub(crate) fn power_on(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<(), ProbeError> {
    cap.invoke(PowerOn(device))
        .map_err(|_| ProbeError::BadDevice)?
}

struct PowerOn<'a>(&'a BusDevice);
impl CapOp<BusDeviceCap, Write> for PowerOn<'_> {
    type Output = Result<(), ProbeError>;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
        Ok(wake(self.0))
    }
}

fn wake(device: &BusDevice) -> Result<(), ProbeError> {
    let BusKind::Pcie { cfg_phys, .. } = device.kind else {
        return Err(ProbeError::NotForThisDriver);
    };
    // SAFETY: probe owns the function; capability access is behind Cap::invoke.
    let offset = match unsafe { narf_bus::pci_cap::find_cap(device, 1) } {
        Ok(Some(offset)) => offset,
        Ok(None) | Err(narf_bus::pci_cap::CapError::NoCapList) => return Ok(()),
        Err(_) => return Err(ProbeError::BadDevice),
    };
    let pointer = narf_bus::ecam::ptr_for(cfg_phys, offset + 4)
        .ok_or(ProbeError::BadDevice)?
        .cast::<u16>();
    // SAFETY: aligned PMCSR in the claimed function's mapped PM capability.
    let current = unsafe { pointer.read_volatile() };
    if current == u16::MAX {
        return Err(ProbeError::BadDevice);
    }
    if current & 3 != 0 {
        // SAFETY: preserve other RW fields, write zero to W1C PME status.
        unsafe { pointer.write_volatile(current & !(3 | 0x8000)) };
        // PCI PM D3hot -> D0 requires 10 ms before further access. D3cold
        // platform power resources and suspend/resume are a separate contract.
        let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(10));
        // SAFETY: same owned PMCSR, after the power transition's settle time.
        if unsafe { pointer.read_volatile() } & 3 != 0 {
            return Err(ProbeError::Other("audio PCI D0 transition failed"));
        }
    }
    Ok(())
}
