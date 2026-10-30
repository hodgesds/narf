//! Generation-bound raw monitor ingress. Neither the token nor this registry
//! changes userspace authority: mode controls require delegated interface
//! administration; packet socket creation requires the existing raw grant.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64};
pub(super) static HAS_MONITOR: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LinkLayer {
    #[default]
    Ethernet,
    Ieee80211Radiotap,
}

/// Serializes capture publication with mode/down/removal/namespace changes.
/// Never held across a driver callback, an await, or ordinary Ethernet RX.
pub(super) static PUBLISH: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());
static EPOCH: AtomicU64 = AtomicU64::new(1);

pub(super) fn next_epoch() -> Option<u64> {
    EPOCH
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            old.checked_add(1)
        })
        .ok()
}

/// A retained driver's capture generation, not a capability grant. Fields
/// are private so an old owner cannot retarget a new interface or namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonitorRxToken {
    ifindex: u32,
    net_ns_id: u64,
    epoch: u64,
}

/// Switch a down, carrier-free interface's link representation. The caller
/// owns live interface-control authority. A real change invalidates bound
/// packet hooks, requiring an explicit bind for the new representation.
pub fn set_link_layer(name: &str, layer: LinkLayer) -> Result<(), ()> {
    let _publish = PUBLISH.lock();
    let mut interfaces = IFACES.lock();
    let entry = interfaces
        .as_mut()
        .and_then(|all| all.iter_mut().find(|e| e.name == name))
        .ok_or(())?;
    if entry.link_up || entry.carrier || entry.name == "lo" {
        return Err(());
    }
    if entry.link_layer == layer {
        return Ok(());
    }
    let old = snapshot(entry);
    let generation = next_epoch().ok_or(())?;
    entry.link_layer = layer;
    entry.packet_generation = generation;
    if layer == LinkLayer::Ieee80211Radiotap {
        HAS_MONITOR.store(true, Ordering::Release);
    }
    entry.monitor_epoch = 0;
    drop(interfaces);
    crate::raw_sock::netdev_event(
        old.net_ns_id,
        old.ifindex,
        crate::raw_sock::NetdevEvent::Unregister,
    );
    Ok(())
}

pub(super) fn carrier(entry: &mut NetIfaceEntry, up: bool) {
    if entry.carrier != up {
        entry.carrier = up;
        entry.carrier_changes = entry.carrier_changes.saturating_add(1);
        if up {
            entry.carrier_up_count = entry.carrier_up_count.saturating_add(1);
        } else {
            entry.carrier_down_count = entry.carrier_down_count.saturating_add(1);
        }
    }
}

pub(super) fn invalidate(old: &NetIfaceSnapshot) {
    if old.link_layer == LinkLayer::Ieee80211Radiotap {
        crate::raw_sock::netdev_unregister_moved(old.net_ns_id, old);
    }
}

/// Begin only after the driver's native sniffer/configuration receipts. An
/// admin-UP monitor receives a unique epoch even across an ifindex rebind.
pub fn begin_monitor_rx(expected: &NetIfaceSnapshot) -> Option<MonitorRxToken> {
    let _publish = PUBLISH.lock();
    let mut interfaces = IFACES.lock();
    let entry = interfaces.as_mut()?.iter_mut().find(|entry| {
        entry.name == expected.name
            && entry.ifindex == expected.ifindex
            && entry.net_ns_id == expected.net_ns_id
            && entry.packet_generation == expected.packet_generation
    })?;
    if !entry.link_up
        || entry.link_layer != LinkLayer::Ieee80211Radiotap
        || entry.monitor_epoch != 0
    {
        return None;
    }
    let epoch = next_epoch()?;
    entry.monitor_epoch = epoch;
    carrier(entry, true);
    Some(MonitorRxToken {
        ifindex: entry.ifindex,
        net_ns_id: entry.net_ns_id,
        epoch,
    })
}

pub fn monitor_rx_current(token: MonitorRxToken) -> bool {
    let _publish = PUBLISH.lock();
    IFACES.lock().as_ref().is_some_and(|all| {
        all.iter()
            .any(|entry| current(entry, token) && entry.link_up && entry.carrier)
    })
}

pub fn end_monitor_rx(token: MonitorRxToken) -> bool {
    let _publish = PUBLISH.lock();
    let mut interfaces = IFACES.lock();
    let Some(entry) = interfaces
        .as_mut()
        .and_then(|all| all.iter_mut().find(|e| current(e, token)))
    else {
        return false;
    };
    entry.monitor_epoch = 0;
    entry.packet_generation = next_epoch().unwrap_or(u64::MAX);
    carrier(entry, false);
    let old = snapshot(entry);
    drop(interfaces);
    invalidate(&old);
    true
}

fn current(entry: &NetIfaceEntry, token: MonitorRxToken) -> bool {
    entry.ifindex == token.ifindex
        && entry.net_ns_id == token.net_ns_id
        && entry.monitor_epoch == token.epoch
        && entry.link_layer == LinkLayer::Ieee80211Radiotap
}

/// Publish a validated radiotap+MPDU buffer only to AF_PACKET. No Ethernet,
/// IP, XDP, or interface frame-ring callback is invoked. The publication
/// lock makes mode/down/removal atomic with hook delivery.
pub fn on_monitor_frame_from(token: MonitorRxToken, frame: &[u8]) -> bool {
    // Radiotap version, extent and at least a frame-control word. Native
    // adapters own richer metadata/802.11 validation before reaching here.
    if frame.len() < 10 || frame[0] != 0 {
        return false;
    }
    let header = usize::from(u16::from_le_bytes([frame[2], frame[3]]));
    if header < 8 || header.checked_add(2).is_none_or(|end| end > frame.len()) {
        return false;
    }
    let _publish = PUBLISH.lock();
    let dev = {
        let mut interfaces = IFACES.lock();
        let Some(entry) = interfaces.as_mut().and_then(|all| {
            all.iter_mut()
                .find(|e| current(e, token) && e.link_up && e.carrier)
        }) else {
            return false;
        };
        entry.stats.rx_packets = entry.stats.rx_packets.saturating_add(1);
        entry.stats.rx_bytes = entry.stats.rx_bytes.saturating_add(frame.len() as u64);
        snapshot(entry)
    };
    crate::raw_sock::monitor_receive(&dev, frame);
    true
}
