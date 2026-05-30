//! External Connector (extcon) framework + USB Type-C connector class.
//!
//! ## What this is
//!
//! Modern laptops have USB-C ports that can simultaneously carry USB,
//! Thunderbolt, DisplayPort, audio, and power (USB-PD).  This crate
//! gives the kernel a single place to track what is plugged in on
//! each connector and to route it correctly.
//!
//! ## Module map
//!
//! ```text
//! drivers/extcon
//!   cable    — Cable enum (USB, Headphone, DP, …)       [Linux include/linux/extcon.h]
//!   class    — ExtconDevice trait + global registry     [Linux drivers/extcon/extcon.c]
//!   typec/
//!     mod      — TypecConnector: orientation, role      [Linux drivers/usb/typec/class.c]
//!     altmode  — DP / TBT Alt Mode negotiation helpers  [Linux drivers/usb/typec/altmodes/]
//!     mux      — TypecMux trait + MuxSetting            [Linux drivers/usb/typec/mux.c]
//!     pd       — PD role mapping bridge (narf-usbpd)    [Linux drivers/usb/typec/pd.c]
//! ```
//!
//! ## Layer contract
//!
//! ```text
//! drivers/extcon  imports  narf-usbpd (spec types only)
//!                          narf-lib   (sync primitives)
//!
//! drivers/usbpd   drives   drivers/extcon (registers TypecConnectors,
//!                          calls update_cc / set_power_role /
//!                          set_alt_mode as PD events land)
//! ```
//!
//! `drivers/usbpd` drives us; we must NOT import `narf-drivers-usbpd`
//! to avoid a cycle.
//!
//! ## Linux references
//!
//! - `drivers/extcon/extcon.c` (cable registry, notifier chain)
//! - `include/linux/extcon.h` (EXTCON_* IDs)
//! - `drivers/usb/typec/class.c` (typec_port, orientation, roles)
//! - `drivers/usb/typec/altmodes/displayport.c` (DP Alt Mode)
//! - `drivers/usb/typec/altmodes/thunderbolt.c` (TBT Alt Mode)
//! - `drivers/usb/typec/mux.c` (typec_mux_dev)
//! - `drivers/usb/typec/pd.c` (PD → typec class bridge)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod cable;
pub mod class;
pub mod typec;

mod tests;
