// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux7.3-rc4 rtw88/pci.c DBI CLKREQ-pad transaction for C22 RFE6.
//! This component grants no suspend, device, clock or RF authority.
use super::power::{Io, PowerError};
use narf_time::Deadline;
pub(super) trait Registers: Io {
    fn write16(&mut self, address: u64, value: u16);
}
const FLAG: u64 = 0x3f0;
fn current(io: &mut impl Registers) -> Result<(), PowerError> {
    if io.permission() {
        Ok(())
    } else {
        Err(PowerError::Access)
    }
}
fn ready(io: &mut impl Registers) -> Result<(), PowerError> {
    let mut failed = None;
    let done = narf_scheduler::responsive_spin_until(
        || {
            if !io.permission() {
                failed = Some(PowerError::Access);
                return true;
            }
            match io.read8(FLAG + 2) {
                0 => true,
                255 => {
                    failed = Some(PowerError::DeviceGone);
                    true
                }
                _ => false,
            }
        },
        Deadline::after_us(200),
    );
    if let Some(error) = failed {
        return Err(error);
    }
    if !done {
        return Err(PowerError::Timeout);
    }
    current(io)
}
fn read(io: &mut impl Registers) -> Result<u8, PowerError> {
    current(io)?;
    if io.read8(FLAG + 2) != 0 {
        return Err(PowerError::StateReadback);
    }
    io.write16(FLAG, 0x718);
    io.write8(FLAG + 2, 2);
    ready(io)?;
    let value = io.read8(0x3ed);
    current(io)?;
    Ok(value)
}
/// The caller selects this only from the actual retained C22 RFE6 factory.
/// Suspend clears BIT_CLKREQ_N_PAD; resume sets it. All other bits remain.
pub(super) fn clkreq_pad(io: &mut impl Registers, suspend: bool) -> Result<(), PowerError> {
    let old = read(io)?;
    let value = if suspend { old & !1 } else { old | 1 };
    current(io)?;
    io.write8(0x3e9, value);
    io.write16(FLAG, 0x2718); // source byte1 WREN + aligned0x718
    io.write8(FLAG + 2, 1);
    ready(io)?;
    if read(io)? != value {
        return Err(PowerError::StateReadback);
    }
    Ok(())
}
#[cfg(feature = "kernel-test")]
#[path = "system_pm_wire_tests.rs"]
mod tests;
