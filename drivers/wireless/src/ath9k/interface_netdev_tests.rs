// SPDX-License-Identifier: GPL-2.0-or-later
//! One netdev across station generations: the name, ifindex and rings stay
//! while generations attach and detach (Linux keeps the `net_device` across
//! `ath_reset`, idle and suspend), and a detached generation's late carrier,
//! TX or RX publication never reaches its successor.
use super::*;
use crate::ath9k::{
    packet::tests::Model,
    station::tests::{self, Env, Peer, AP, SSID},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::udp_ipv4;

type TestNetdev = Netdev<Arc<Model>, Arc<Env>>;
type TestDevice = Device<Arc<Model>, Arc<Env>>;
static NET: IrqSafeSpinLock<Option<Arc<TestNetdev>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let netdev = NET.lock().clone().ok_or(())?;
    netdev.generation().ok_or(())?.enqueue(bytes, meta)
}

/// One attached generation and the fixture parts its model reacts with.
struct Generation {
    device: Arc<TestDevice>,
    model: Arc<Model>,
    _peer: Arc<IrqSafeSpinLock<Peer>>,
}
fn attach(netdev: &TestNetdev, fixture: tests::Fixture) -> Result<Generation, &'static str> {
    let device = netdev
        .attach(Arc::new(Mutex::new(fixture.radio)))
        .map_err(|_| "netdev attach")?;
    device.admit_for_test();
    device.link(None);
    Ok(Generation {
        device,
        model: fixture.model,
        _peer: fixture.peer,
    })
}
fn join(netdev: &TestNetdev) -> Result<(), &'static str> {
    let found = tests::complete(netdev.scan(ScanRequest {
        ssids: vec![SSID.to_vec()],
        frequencies_mhz: vec![2412],
        channels: vec![1],
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: Some(1),
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }))
    .map_err(|_| "netdev scan through the current generation")?;
    if !found.iter().any(|bss| bss.bssid == AP) {
        return Err("netdev scan missed the AP");
    }
    tests::complete(netdev.associate(AssociateRequest {
        bssid: AP,
        ssid: SSID.to_vec(),
        frequency_mhz: 2412,
        channel: 1,
        security: SecurityConfig::Open,
        ie: Vec::new(),
    }))
    .map_err(|_| "netdev associate through the current generation")?;
    for _ in 0..16 {
        if let Some(device) = netdev.generation() {
            device.drain();
        }
    }
    if !netdev.link_up() || netdev.connected_bssid() != Some(AP) {
        return Err("netdev carrier after join");
    }
    Ok(())
}
fn carrier(name: &str) -> Option<bool> {
    narf_net::iface::lookup(name).map(|iface| iface.carrier)
}
fn generations() -> Result<(), &'static str> {
    let first = tests::fixture(false)?;
    let own = first.plan.station;
    let plan = first.plan;
    let name = narf_net::iface::reserve_name("ar9-netdev%d");
    let netdev = TestNetdev::new(name, own);
    *NET.lock() = Some(netdev.clone());
    narf_net::iface::register(name, own, send);
    narf_net::iface::set_link_state(name, true);
    let ifindex = narf_net::iface::ifindex_of(name).ok_or("netdev ifindex")?;

    let old = attach(&netdev, first)?;
    if old.device.name() != name || !core::ptr::eq(old.device.rx_ring(), netdev.rx_ring()) {
        return Err("generation does not use the netdev name and rings");
    }
    join(&netdev)?;
    if carrier(name) != Some(true) {
        return Err("first generation carrier not published");
    }

    // Generation reset/idle/suspend boundary: detach, then retire the DMA.
    if netdev.detach(&old.device.radio).is_none() {
        return Err("attached generation was not detached");
    }
    if !old.device.radio.try_lock().is_some_and(|mut r| r.retire()) {
        return Err("detached generation DMA not reclaimed");
    }
    if netdev.generation().is_some()
        || narf_net::iface::ifindex_of(name) != Some(ifindex)
        || carrier(name) != Some(false)
        || netdev.connected_bssid().is_some()
        || old.device.current()
    {
        return Err("detach did not keep the netdev with carrier down");
    }
    // A late publication of the detached generation addresses nothing.
    old.device.link(Some(AP));
    let bytes = udp_ipv4(
        AP,
        own,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"ar9-netdev-detached",
    );
    if carrier(name) != Some(false) || old.device.enqueue(&bytes, Default::default()).is_ok() {
        return Err("detached generation reached the netdev");
    }

    let next = attach(&netdev, tests::fixture(false)?)?;
    if next.device.name() != name
        || narf_net::iface::ifindex_of(name) != Some(ifindex)
        || !core::ptr::eq(next.device.rx_ring(), netdev.rx_ring())
    {
        return Err("successor generation did not keep name, ifindex and rings");
    }
    join(&netdev)?;
    // The predecessor's late carrier drop and service pass must not touch
    // the successor's association.
    old.device.link(None);
    old.device.drain();
    if carrier(name) != Some(true) || !netdev.link_up() || !next.device.current() {
        return Err("stale generation dropped the successor's carrier");
    }
    if netdev
        .generation()
        .is_none_or(|device| !Arc::ptr_eq(&device, &next.device))
    {
        return Err("netdev does not route to the successor");
    }
    if old.model.master.get() {
        return Err("detached generation still masters DMA");
    }
    netdev.unregister();
    *NET.lock() = None;
    let _ = next.device.radio.try_lock().map(|mut r| r.retire());
    if narf_net::iface::lookup(name).is_some() {
        return Err("removal left the netdev registered");
    }
    Ok(())
}
fn smoke_ath9k_netdev_name_and_ifindex_survive_generation_reset() -> TestResult {
    let result = generations();
    *NET.lock() = None;
    match result {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ath9k_netdev_name_and_ifindex_survive_generation_reset
);
