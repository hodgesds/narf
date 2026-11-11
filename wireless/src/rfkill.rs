//! cfg80211's per-wiphy rfkill (`net/wireless/core.c`): every physical
//! radio is one `wlan` rfkill switch named `phyN`. A soft or hard block
//! shuts the radio's interfaces down (`cfg80211_rfkill_block_work` ->
//! `cfg80211_shutdown_all_interfaces`): a connected station disconnects
//! with a locally generated event, and nl80211 refuses new scans and
//! connections with -ERFKILL until the block is cleared.
//!
//! The rfkill core and `/dev/rfkill` are a separate subsystem; the kernel
//! links this module to it with [`install`]. Without a backend no radio is
//! registered and nothing is ever blocked.
use alloc::{format, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

/// The rfkill core's registration entry points.
#[derive(Clone, Copy, Debug)]
pub struct Backend {
    /// Register a `wlan` radio named `name`; returns its rfkill index.
    pub register: fn(name: &str) -> usize,
    /// The radio is gone (its last interface unregistered).
    pub unregister: fn(index: usize),
}

#[derive(Clone, Copy, Debug)]
struct Phy {
    wiphy: u64,
    handle: Option<usize>,
    blocked: bool,
}

static BACKEND: IrqSafeSpinLock<Option<Backend>> = IrqSafeSpinLock::new(None);
static PHYS: IrqSafeSpinLock<Vec<Phy>> = IrqSafeSpinLock::new(Vec::new());

/// Connect to the rfkill core and register every wiphy known so far.
pub fn install(backend: Backend) {
    *BACKEND.lock() = Some(backend);
    let pending: Vec<u64> = PHYS
        .lock()
        .iter()
        .filter(|phy| phy.handle.is_none())
        .map(|phy| phy.wiphy)
        .collect();
    for wiphy in pending {
        register_with(backend, wiphy);
    }
}

fn register_with(backend: Backend, wiphy: u64) {
    let name = format!(
        "phy{}",
        crate::registry::wiphy_index(wiphy).unwrap_or_default()
    );
    let handle = (backend.register)(&name);
    if let Some(phy) = PHYS.lock().iter_mut().find(|phy| phy.wiphy == wiphy) {
        phy.handle = Some(handle);
    }
}

/// A wiphy's first interface registered (`wiphy_register` ->
/// `rfkill_register`).
pub(crate) fn wiphy_added(wiphy: u64) {
    {
        let mut phys = PHYS.lock();
        if phys.iter().any(|phy| phy.wiphy == wiphy) {
            return;
        }
        phys.push(Phy {
            wiphy,
            handle: None,
            blocked: false,
        });
    }
    let backend = *BACKEND.lock();
    if let Some(backend) = backend {
        register_with(backend, wiphy);
    }
}

/// A wiphy's last interface unregistered (`wiphy_unregister`).
pub(crate) fn wiphy_removed(wiphy: u64) {
    let removed = {
        let mut phys = PHYS.lock();
        let position = phys.iter().position(|phy| phy.wiphy == wiphy);
        position.map(|index| phys.remove(index))
    };
    let backend = *BACKEND.lock();
    if let (Some(phy), Some(backend)) = (removed, backend) {
        if let Some(handle) = phy.handle {
            (backend.unregister)(handle);
        }
    }
}

/// The rfkill core's switch for radio `handle` (`cfg80211_rfkill_set_block`).
/// Blocking disconnects every interface of the wiphy; returns false for an
/// unknown radio.
pub fn set_soft_blocked(handle: usize, blocked: bool) -> bool {
    let wiphy = {
        let mut phys = PHYS.lock();
        let Some(phy) = phys.iter_mut().find(|phy| phy.handle == Some(handle)) else {
            return false;
        };
        phy.blocked = blocked;
        phy.wiphy
    };
    if blocked {
        shut_down(wiphy);
    }
    true
}

/// Whether the wiphy is rfkill-blocked.
pub fn blocked(wiphy: u64) -> bool {
    PHYS.lock()
        .iter()
        .any(|phy| phy.wiphy == wiphy && phy.blocked)
}

/// `cfg80211_shutdown_all_interfaces` for a station: disconnect each
/// connected interface of `wiphy` from its own task (the switch may run in
/// a hotkey or sysfs context that must not wait for firmware), reporting
/// the locally generated disconnect wpa_supplicant expects.
fn shut_down(wiphy: u64) {
    for iface in crate::registry::list()
        .into_iter()
        .filter(|iface| iface.wiphy_id() == wiphy && iface.connected_bssid().is_some())
    {
        narf_scheduler::spawn(async move {
            if iface.disassociate().await.is_ok() && !iface.reports_disconnect_events() {
                // WLAN_REASON_DEAUTH_LEAVING, locally generated.
                crate::nl80211::notify_disconnect(iface.name(), 3, false);
            }
        });
    }
}

#[cfg(feature = "kernel-test")]
#[doc(hidden)]
pub fn __test_reset() {
    *BACKEND.lock() = None;
    PHYS.lock().clear();
}

#[cfg(feature = "kernel-test")]
#[path = "rfkill_tests.rs"]
mod tests;
