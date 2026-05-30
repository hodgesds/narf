//! USB Power Delivery bridge — adapts `narf_usbpd` types for the
//! Type-C connector class.
//!
//! The actual PD state machine lives in `narf_usbpd::tcpm` and the
//! driver-level TCPM port is in `narf_drivers_usbpd::tcpm`.  This
//! file is the *seam*: it re-exports the PD types that the extcon
//! Type-C class needs and provides helpers to map PD role
//! negotiations to the `PowerRole` / `DataRole` enums in
//! `typec/mod.rs`.
//!
//! Rule: this module must NOT import `narf_drivers_usbpd` — the
//! driver crate creates a one-way dependency on us, not the other
//! way around.  We only touch `narf_usbpd` (the spec-level crate).
//!
//! Linux ref: `drivers/usb/typec/pd.c` — a thin wrapper that
//! translates PD message events into typec class calls
//! (`typec_set_pwr_role`, `typec_set_data_role`).

// Re-export the PD message types for consumers of this module.
pub use narf_usbpd::message::{DataRole as PdDataRole, PowerRole as PdPowerRole};
pub use narf_usbpd::tcpc::CcStatus;

use super::{DataRole, PowerRole};

/// Map a USB-PD power role (from the message layer) to the Type-C
/// class power role.
///
/// Linux ref: `tcpm.c::tcpm_set_pwr_role()` → `typec_set_pwr_role()`.
pub fn map_power_role(pd: PdPowerRole) -> PowerRole {
    match pd {
        PdPowerRole::Source => PowerRole::Source,
        PdPowerRole::Sink => PowerRole::Sink,
    }
}

/// Map a USB-PD data role (from the message layer) to the Type-C
/// class data role.
///
/// Linux ref: `tcpm.c::tcpm_set_data_role()` → `typec_set_data_role()`.
pub fn map_data_role(pd: PdDataRole) -> DataRole {
    match pd {
        PdDataRole::Dfp => DataRole::Host,
        PdDataRole::Ufp => DataRole::Device,
    }
}
