//! Built-in platform: the kernel's own crates, unchanged.

/// The host regulatory database (`narf_wireless::reg::db`).
pub use narf_wireless::reg::db as regdb;
/// The netdev control trait nl80211 drives.
pub use narf_wireless::WirelessNetIface;
