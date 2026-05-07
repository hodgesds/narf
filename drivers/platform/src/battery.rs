//! ACPI Control Method Battery driver — clean-room.
//!
//! Spec: ACPI 6.5 §10.2 (Control Method Batteries).
//!   <https://uefi.org/specs/ACPI/>
//! Uses the ACPI Embedded Controller (EC) to query battery status.

use crate::ec::with_ec;
use alloc::sync::Arc;
use narf_power::{register_source, PowerSource, PowerSourceType};

#[derive(Debug)]
pub struct AcpiBattery {
    id: u8,
}

impl AcpiBattery {
    pub fn new(id: u8) -> Self {
        Self { id }
    }
}

impl PowerSource for AcpiBattery {
    fn source_type(&self) -> PowerSourceType {
        PowerSourceType::Battery
    }

    fn capacity_percent(&self) -> u8 {
        // Implementation for Stage 5: Read from EC.
        // For Stage 4 landing, we query the EC if available or return a placeholder.
        with_ec(|ec| {
            // Placeholder: every laptop has a different EC map.
            // In a real system, we'd look up the offset in the DSDT.
            ec.read_byte(0xE0).unwrap_or(100) // Mock offset
        })
        .unwrap_or(100)
    }

    fn is_charging(&self) -> bool {
        with_ec(|ec| {
            let status = ec.read_byte(0xE1).unwrap_or(0);
            (status & 0x01) != 0
        })
        .unwrap_or(false)
    }

    fn name(&self) -> &'static str {
        "BAT0"
    }
}

pub fn init() {
    let battery = Arc::new(AcpiBattery::new(0));
    register_source(battery);
}
