//! Built-in platform: the kernel's own crates, re-exported unchanged.
//!
//! Driver files name kernel services as `crate::platform::<crate>::...`
//! (`time`, `lib`, `scheduler`, ...); built in each is the kernel crate
//! itself, so those paths are the kernel's items and the built-in driver is
//! exactly what it was.

pub use narf_bus::MmioRegion;
pub use narf_lib::sync::IrqSafeSpinLock;
pub use narf_scheduler::responsive_spin_until;
pub use narf_time::Deadline;

pub use narf_capabilities as capabilities;
pub use narf_console as console;
pub use narf_firmware as firmware;
pub use narf_io as io;
pub use narf_ipc as ipc;
pub use narf_lib as lib;
pub use narf_net as net;
pub use narf_scheduler as scheduler;
pub use narf_time as time;
pub use narf_wireless::reg::db as regdb;

pub use narf_drivers_wireless_core::{firmware_asset, future_heap, watchdog_work};

/// `narf_bus` names the shared driver code uses.
pub mod bus {
    pub use narf_bus::{BusAddr, MmioRegion, PcieAddr};
}

/// `narf_wireless` kernel-side names (registry events, rfkill).
pub mod wireless {
    pub use narf_wireless::{nl80211, rfkill, WirelessNetIface};
}
