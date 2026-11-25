//! SPD EEPROM client instantiation from SMBIOS memory devices.
//!
//! Port of Linux `i2c_register_spd` (drivers/i2c/i2c-smbus.c). Memory
//! modules carry an SPD EEPROM (DDR5: an SPD5118 hub) at SMBus address
//! `0x50 + slot`. The SMBIOS type 17 records say how many slots exist,
//! how many hold a module, and the memory type, which picks the client
//! type; the slots themselves are found by probing `0x50..0x50+slots`
//! until every populated module has answered.
//!
//! Limits, as in Linux: one memory type across all modules, at most 8
//! slots per bus, and only memory types up to (LP)DDR5.

use alloc::sync::Arc;

use narf_firmware_smbios::{SmbiosMemoryDevice, MAX_MEMORY_DEVICES};

use crate::I2cBus;

/// SPD addresses one bus can carry (`slot_count = min(slot_count, 8)`).
pub const SPD_MAX_SLOTS: usize = 8;
/// First SPD address; slot `n` answers at `0x50 + n`.
pub const SPD_BASE_ADDR: u8 = 0x50;

/// What [`plan`] decided for one adapter.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpdPlan {
    /// No populated module with a defined memory type.
    NoModules,
    /// Populated modules disagree on memory type.
    MixedTypes,
    /// A memory type Linux has no SPD client for.
    Unsupported(u8),
    /// Probe `0x50..0x50+slots` for `modules` clients of type `kind`;
    /// `instantiate` is false for DDR5 on a write-protected bus.
    Probe {
        kind: &'static str,
        slots: usize,
        modules: usize,
        instantiate: bool,
    },
}

/// The decision half of `i2c_register_spd`, over the SMBIOS type 17
/// records (every slot, populated or not).
pub fn plan(devices: &[SmbiosMemoryDevice], write_disabled: bool) -> SpdPlan {
    let mut common: u8 = 0;
    let mut modules = 0usize;
    for d in devices {
        // Skip empty slots.
        if d.size_mb == 0 {
            continue;
        }
        // Skip Invalid / Other / Unknown memory types.
        if d.memory_type <= 0x02 {
            continue;
        }
        if common == 0 {
            common = d.memory_type;
        } else if d.memory_type != common {
            return SpdPlan::MixedTypes;
        }
        modules += 1;
    }
    if modules == 0 {
        return SpdPlan::NoModules;
    }
    let slots = devices.len().min(SPD_MAX_SLOTS);
    // SMBIOS 3.6 §7.18.2, table 78.
    let (kind, instantiate) = match common {
        0x12 | 0x13 | 0x18 | 0x1B | 0x1C | 0x1D => ("spd", true),
        0x1A | 0x1E => ("ee1004", true),
        0x22 | 0x23 => ("spd5118", !write_disabled),
        other => return SpdPlan::Unsupported(other),
    };
    SpdPlan::Probe {
        kind,
        slots,
        modules,
        instantiate,
    }
}

fn log(bus: &dyn I2cBus, args: core::fmt::Arguments<'_>) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "i2c {}: {args}", bus.name());
}

/// `i2c_register_spd_write_enable`.
pub fn register_spd_write_enable(bus: &Arc<dyn I2cBus>) {
    register_spd(bus, false);
}

/// `i2c_register_spd_write_disable`: the bus write-protects SPD, so no
/// SPD5118 client (whose driver writes the hub's page register).
pub fn register_spd_write_disable(bus: &Arc<dyn I2cBus>) {
    register_spd(bus, true);
}

fn register_spd(bus: &Arc<dyn I2cBus>, write_disabled: bool) {
    let mut devices = [SmbiosMemoryDevice::ZERO; MAX_MEMORY_DEVICES];
    let n = narf_firmware_smbios::copy_memory_devices(&mut devices);
    // Called from the synchronous PCI probe. `block_on_spin` is valid in
    // every context a probe runs in; the scan is a handful of SMBus
    // transactions.
    narf_scheduler::block_on_spin(scan(bus, &devices[..n], write_disabled));
}

/// Probe and instantiate per [`plan`]. Returns how many clients were
/// created.
pub async fn scan(
    bus: &Arc<dyn I2cBus>,
    devices: &[SmbiosMemoryDevice],
    write_disabled: bool,
) -> usize {
    let (kind, slots, mut modules, instantiate) = match plan(devices, write_disabled) {
        SpdPlan::NoModules => return 0,
        SpdPlan::MixedTypes => {
            log(
                bus.as_ref(),
                format_args!("Different memory types mixed, not instantiating SPD"),
            );
            return 0;
        }
        SpdPlan::Unsupported(t) => {
            log(
                bus.as_ref(),
                format_args!("Memory type {t:#04x} not supported yet, not instantiating SPD"),
            );
            return 0;
        }
        SpdPlan::Probe {
            kind,
            slots,
            modules,
            instantiate,
        } => (kind, slots, modules, instantiate),
    };
    if !instantiate {
        return 0;
    }
    let mut created = 0;
    for n in 0..slots {
        if modules == 0 {
            break;
        }
        let addr = SPD_BASE_ADDR + n as u8;
        if crate::client::new_scanned_device(bus, kind, &[addr])
            .await
            .is_some()
        {
            log(
                bus.as_ref(),
                format_args!("Successfully instantiated SPD at {addr:#x}"),
            );
            modules -= 1;
            created += 1;
        }
    }
    created
}
