//! Raw monitor capture, bound-hook invalidation and namespace ownership.
use crate::iface::{self, LinkLayer, MonitorRxToken};
use crate::raw_sock::{self, PacketSock};
use alloc::{string::String, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fixture {
    name: String,
    socks: Vec<Arc<PacketSock>>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            name: iface::register("nmon%d", [2, 0, 0, 0, 0x6d, 1], |_, _| Ok(())),
            socks: Vec::new(),
        }
    }
    fn bind(&mut self, ns: u64, kind: u32, protocol: u16) -> Result<Arc<PacketSock>, &'static str> {
        let sock = PacketSock::create(ns, kind, 0, 212992);
        let index = iface::ifindex_of(&self.name).ok_or("monitor fixture index")?;
        sock.bind(None, index as i32, protocol.to_be())
            .map_err(|_| "bind raw monitor hook")?;
        self.socks.push(sock.clone());
        Ok(sock)
    }
    fn start(&self) -> Result<MonitorRxToken, &'static str> {
        iface::set_link_state(&self.name, true);
        iface::set_link_metadata(&self.name, true, None, None);
        iface::begin_monitor_rx(&iface::lookup(&self.name).ok_or("monitor snapshot at start")?)
            .ok_or("monitor generation admission")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for sock in &self.socks {
            sock.release();
        }
        iface::set_link_state(&self.name, false);
        iface::unregister(&self.name);
    }
}
fn capture() -> Vec<u8> {
    vec![
        0, 0, 14, 0, 0x0a, 0, 0, 0, 0, 0, 0x3c, 0x14, 0, 1, 0xd4, 0, 0, 0, 0, 1, 2, 3, 4, 5,
    ]
}
fn delivered(sock: &PacketSock) -> Result<(), &'static str> {
    let record = sock
        .recv(false)
        .map_err(|_| "monitor frame not consumable through AF_PACKET")?;
    if record.data != capture()
        || record.hatype != 803
        || record.pkttype != raw_sock::PACKET_OTHERHOST
        || record.protocol != 4
        || record.net_off != 0
        || record.halen != 0
        || record.addr != [0; 8]
        || record.vlan.is_some()
    {
        return Err("monitor radiotap/802.11 bytes or sockaddr metadata changed");
    }
    Ok(())
}
fn raw_capture() -> Result<(), &'static str> {
    let mut fixture = Fixture::new();
    let old_station = fixture.bind(0, raw_sock::SOCK_RAW, raw_sock::ETH_P_ALL)?;
    iface::set_link_layer(&fixture.name, LinkLayer::Ieee80211Radiotap)
        .map_err(|_| "down monitor type")?;
    let token = fixture.start()?;
    let raw = fixture.bind(0, raw_sock::SOCK_RAW, raw_sock::ETH_P_ALL)?;
    let cooked = fixture.bind(0, raw_sock::SOCK_DGRAM, raw_sock::ETH_P_802_2)?;
    let ip = fixture.bind(0, raw_sock::SOCK_RAW, 0x0800)?;
    if iface::set_link_layer(&fixture.name, LinkLayer::Ethernet).is_ok()
        || iface::on_monitor_frame_from(token, &[0; 9])
        || !iface::on_monitor_frame_from(token, &capture())
    {
        return Err("monitor mode/extent admission");
    }
    delivered(&raw)?;
    delivered(&cooked)?;
    if old_station.recv(false).is_ok() || ip.recv(false).is_ok() {
        return Err("station-bound or IP ethertype hook received monitor traffic");
    }
    let dev = iface::lookup(&fixture.name).ok_or("monitor netdev snapshot")?;
    if dev.hatype() != 803
        || dev.xmit(&[0; 60]).is_ok()
        || dev.xmit_direct(&[0; 60]).is_ok()
        || iface::send_on(&fixture.name, &[0; 60]).is_ok()
        || iface::send_on_ifindex(dev.ifindex, &[0; 60]).is_ok()
        || iface::for_dst([203, 0, 113, 1]).is_some_and(|egress| egress.ifindex == dev.ifindex)
    {
        return Err("monitor accepted injection or Ethernet/IP routing");
    }
    // Ordinary ingress has no radiotap fallback through the Ethernet tap.
    raw_sock::netif_receive(&dev, &[0; 60]);
    if raw.recv(false).is_ok() {
        return Err("ordinary Ethernet tap delivered monitor ingress");
    }
    Ok(())
}
fn monitor_radiotap_is_consumable_only_by_current_raw_packet_hooks() -> TestResult {
    raw_capture().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "net/monitor",
    monitor_radiotap_is_consumable_only_by_current_raw_packet_hooks
);

fn generations() -> Result<(), &'static str> {
    let mut fixture = Fixture::new();
    iface::set_link_layer(&fixture.name, LinkLayer::Ieee80211Radiotap)
        .map_err(|_| "monitor type")?;
    let first = fixture.start()?;
    let stale = fixture.bind(0, raw_sock::SOCK_RAW, raw_sock::ETH_P_ALL)?;
    iface::set_link_state(&fixture.name, false);
    let second = fixture.start()?;
    if first == second
        || iface::on_monitor_frame_from(first, &capture())
        || !iface::on_monitor_frame_from(second, &capture())
        || stale.recv(false).is_ok()
    {
        return Err("down/up reused old token or bound socket");
    }
    let index = iface::ifindex_of(&fixture.name).ok_or("monitor index after down")?;
    stale
        .bind(None, index as i32, raw_sock::ETH_P_ALL.to_be())
        .map_err(|_| "explicit monitor rebind")?;
    if !iface::on_monitor_frame_from(second, &capture()) {
        return Err("rebound monitor publication");
    }
    delivered(&stale)?;
    if !iface::end_monitor_rx(second) {
        return Err("native capture stop token");
    }
    let third = iface::begin_monitor_rx(
        &iface::lookup(&fixture.name).ok_or("monitor snapshot at generation change")?,
    )
    .ok_or("new native capture epoch")?;
    if iface::end_monitor_rx(second)
        || iface::on_monitor_frame_from(second, &capture())
        || !iface::on_monitor_frame_from(third, &capture())
        || stale.recv(false).is_ok()
    {
        return Err("native stop/restart reused old packet hook");
    }
    stale
        .bind(None, index as i32, raw_sock::ETH_P_ALL.to_be())
        .map_err(|_| "rebind after native restart")?;
    let stale_start = iface::lookup(&fixture.name).ok_or("pre-rebind start snapshot")?;
    if !iface::retire_for_rebind(&fixture.name) {
        return Err("monitor retire for driver rebind");
    }
    iface::register(&fixture.name, [2, 0, 0, 0, 0x6d, 2], |_, _| Ok(()));
    if iface::begin_monitor_rx(&stale_start).is_some() {
        return Err("old native setup admitted new driver generation by name");
    }
    let fourth = iface::begin_monitor_rx(
        &iface::lookup(&fixture.name).ok_or("monitor snapshot at generation change")?,
    )
    .ok_or("monitor rebound native epoch")?;
    if iface::ifindex_of(&fixture.name) != Some(index)
        || iface::on_monitor_frame_from(third, &capture())
        || !iface::on_monitor_frame_from(fourth, &capture())
        || stale.recv(false).is_ok()
    {
        return Err("driver rebind reused capture/socket ownership");
    }
    const NS: u64 = 0x6d6f_6e69;
    if !iface::set_net_ns(&fixture.name, NS) {
        return Err("monitor namespace move");
    }
    let in_ns = fixture.bind(NS, raw_sock::SOCK_RAW, raw_sock::ETH_P_ALL)?;
    let fifth = iface::begin_monitor_rx(
        &iface::lookup(&fixture.name).ok_or("monitor snapshot at generation change")?,
    )
    .ok_or("new namespace capture")?;
    if iface::on_monitor_frame_from(fourth, &capture())
        || !iface::on_monitor_frame_from(fifth, &capture())
    {
        return Err("monitor namespace generation");
    }
    delivered(&in_ns)?;
    if stale.recv(false).is_ok() {
        return Err("old namespace monitor socket received new traffic");
    }
    iface::set_link_state(&fixture.name, false);
    iface::set_link_metadata(&fixture.name, false, None, None);
    iface::set_link_layer(&fixture.name, LinkLayer::Ethernet)
        .map_err(|_| "monitor back to station")?;
    iface::set_link_state(&fixture.name, true);
    let mut ethernet = [0; 60];
    ethernet[12..14].copy_from_slice(&[8, 0]);
    raw_sock::netif_receive(
        &iface::lookup(&fixture.name).ok_or("station representation")?,
        &ethernet,
    );
    if in_ns.recv(false).is_ok() || iface::on_monitor_frame_from(fifth, &capture()) {
        return Err("monitor-bound socket survived representation change");
    }
    Ok(())
}
fn monitor_down_stop_rebind_namespace_and_mode_require_fresh_bound_owner() -> TestResult {
    generations().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "net/monitor",
    monitor_down_stop_rebind_namespace_and_mode_require_fresh_bound_owner
);
