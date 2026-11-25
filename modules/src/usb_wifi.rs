//! Kernel side of the USB Wi-Fi module exports (`kabi.rs`,
//! "USB Wi-Fi modules"): the per-device heartbeat a USB function's module
//! drives its executor from, its station interface, and the
//! regulatory-domain record.
//!
//! A PCI module's 1 ms poller and netdev live in its bus device context
//! (`narf_spawn_poller`, `narf_netif_register_with_context`). A USB
//! function's context lives in the USB stack (`narf_bus::module_usb`),
//! which has neither, so this keeps them per `(module, token)` and ties them
//! to that context's liveness, the way module disks are
//! (`module_block`): every use re-checks `context_live`, every entry into
//! module text goes through the module gate (which refuses once the module
//! is no longer Live), and the module-context-retired hook withdraws them
//! when the context goes away.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Live pollers: `(owner, token, id)`. A later spawn for the same device
/// replaces the entry, which the earlier loop notices before its next run.
static POLLERS: IrqSafeSpinLock<Vec<(u64, u64, u64)>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Most concurrent USB pollers (one per bound USB function).
const MAX_POLLERS: usize = 64;

fn current(owner: u64, token: u64, id: u64) -> bool {
    POLLERS
        .lock()
        .iter()
        .any(|&(o, t, i)| o == owner && t == token && i == id)
}

fn retire(owner: u64, token: u64, id: u64) {
    POLLERS
        .lock()
        .retain(|&(o, t, i)| !(o == owner && t == token && i == id));
}

/// `narf_usb_spawn_poller`: 0, `-ENODEV` (no live USB context for this
/// owner), or `-ENOSPC`.
pub fn spawn_poller(
    owner: u64,
    token: u64,
    callback: narf_bus::ModuleCallbackFn,
    cookie: u64,
) -> i32 {
    if !narf_bus::module_usb::context_live(owner, token) {
        return -19;
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    {
        let mut pollers = POLLERS.lock();
        pollers.retain(|&(o, t, _)| !(o == owner && t == token));
        if pollers.len() >= MAX_POLLERS {
            return -28;
        }
        pollers.push((owner, token, id));
    }
    narf_scheduler::spawn(async move {
        loop {
            if !current(owner, token, id) || !narf_bus::module_usb::context_live(owner, token) {
                retire(owner, token, id);
                return;
            }
            if narf_bus::module_usb::call_module_usb_callback(owner, callback, cookie) != 0 {
                retire(owner, token, id);
                return;
            }
            narf_time::sleep_cycles(narf_time::ns_to_cycles(1_000_000)).await;
        }
    });
    0
}

/// One USB function's station interface.
struct UsbNetif {
    owner: u64,
    token: u64,
    name: String,
    ifindex: u32,
    tx_callback: narf_bus::ModuleTxCtxFn,
}

static NETIFS: IrqSafeSpinLock<Vec<UsbNetif>> = IrqSafeSpinLock::new(Vec::new());

/// `narf_usb_netif_register_with_context`: register `wlan%d` for the USB
/// function `token` of module `owner`.
pub fn netif_register(
    owner: u64,
    token: u64,
    mac: [u8; 6],
    tx_callback: narf_bus::ModuleTxCtxFn,
) -> Result<u32, i32> {
    if !narf_bus::module_usb::context_live(owner, token) {
        return Err(-19);
    }
    if NETIFS.lock().iter().any(|n| n.token == token) {
        return Err(-16);
    }
    let name = narf_net::iface::register_with_context("wlan%d", mac, token, netif_tx_bridge);
    narf_net::iface::set_driver_info(&name, "module", None, String::new());
    let Some(ifindex) = narf_net::iface::ifindex_of(&name) else {
        let _ = narf_net::iface::unregister(&name);
        return Err(-5);
    };
    let mut netifs = NETIFS.lock();
    // The context may have gone, or a racing registration won, meanwhile.
    if !narf_bus::module_usb::context_live(owner, token) || netifs.iter().any(|n| n.token == token)
    {
        drop(netifs);
        let _ = narf_net::iface::unregister(&name);
        return Err(-16);
    }
    netifs.push(UsbNetif {
        owner,
        token,
        name,
        ifindex,
        tx_callback,
    });
    Ok(ifindex)
}

/// The stack's send hook for a USB station interface: into module text
/// only through the lifecycle/domain gate, and only while the context is
/// live.
fn netif_tx_bridge(token: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    // No offload is advertised, as for the bus netif bridge.
    if meta != narf_net::TxMeta::plain() {
        return Err(());
    }
    let (owner, callback) = NETIFS
        .lock()
        .iter()
        .find(|n| n.token == token)
        .map(|n| (n.owner, n.tx_callback))
        .ok_or(())?;
    if !narf_bus::module_usb::context_live(owner, token) {
        return Err(());
    }
    match crate::call_in_module_context(owner, || callback(token, frame.as_ptr(), frame.len())) {
        0 => Ok(()),
        _ => Err(()),
    }
}

/// `narf_usb_netif_rx`.
pub fn netif_rx(owner: u64, token: u64, ifindex: u32, frame: &mut [u8]) -> i32 {
    let Some(name) = NETIFS
        .lock()
        .iter()
        .find(|n| n.owner == owner && n.token == token)
        .map(|n| (n.ifindex, n.name.clone()))
    else {
        return -19;
    };
    if name.0 != ifindex {
        return -22;
    }
    if !narf_bus::module_usb::context_live(owner, token) {
        return -19;
    }
    narf_net::iface::on_rx_frame_from(&name.1, frame);
    0
}

/// A device context went away (the module-context-retired hook): withdraw
/// its interface and stop its poller.
pub fn retire_token(owner: u64, token: u64) {
    let gone: Vec<UsbNetif> = {
        let mut netifs = NETIFS.lock();
        let (gone, kept) = core::mem::take(&mut *netifs)
            .into_iter()
            .partition(|n| n.owner == owner && n.token == token);
        *netifs = kept;
        gone
    };
    for netif in gone {
        let _ = narf_net::iface::unregister(&netif.name);
    }
    POLLERS
        .lock()
        .retain(|&(o, t, _)| !(o == owner && t == token));
}

/// The installed regulatory domain as one NRGD v1 record (header 12 bytes,
/// then 16 bytes per rule; see `narf_wireless::reg::parse_policy`).
pub fn regdomain_record() -> Result<Vec<u8>, i32> {
    let domain = narf_wireless::reg::db::ensure_snapshot().map_err(|_| -61)?;
    if domain.rules.len() > 64 {
        return Err(-75);
    }
    let mut out = Vec::with_capacity(12 + 16 * domain.rules.len());
    out.extend_from_slice(b"NRGD");
    out.extend_from_slice(&[1, 0]);
    out.extend_from_slice(&domain.country_code);
    out.extend_from_slice(&(domain.rules.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    for rule in &domain.rules {
        let flags = rule.flags.bits();
        if flags > 0xffff {
            return Err(-75);
        }
        out.extend_from_slice(&rule.freq_start_mhz.to_le_bytes());
        out.extend_from_slice(&rule.freq_end_mhz.to_le_bytes());
        out.extend_from_slice(&rule.max_bandwidth_mhz.to_le_bytes());
        out.push(rule.max_power_dbm as u8);
        out.push(flags as u8);
        out.push((flags >> 8) as u8);
        out.push(0);
    }
    Ok(out)
}
