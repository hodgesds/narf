// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual CR4/msgbuf controls and posted flagged RX -> original monitor
//! frontend -> AF_PACKET. Expected radiotap/MPDU bytes are independent literal
//! observations; no production encoder supplies expected metadata/receipts.
use super::*;
use crate::brcmfmac::runtime_tests::station_model::monitor_model::Profile;
use narf_capabilities::{Cap, Invoke};
use narf_net::raw_sock::{PacketSock, ETH_P_ALL, SOCK_RAW};
use narf_wireless::WirelessNetIface;
fn run<F: Future>(future: F) -> F::Output {
    narf_scheduler::block_on(future)
}
fn channel() -> narf_wireless::monitor::Channel {
    narf_wireless::monitor::Channel {
        frequency_mhz: 2437,
        width: 0,
        center1_mhz: 2437,
        center2_mhz: 0,
    }
}
fn raw(tsft: bool) -> Vec<u8> {
    let mut bytes = if tsft {
        let mut b = vec![0; 23];
        b[2..4].copy_from_slice(&23u16.to_le_bytes());
        b[4..8].copy_from_slice(&0x2fu32.to_le_bytes());
        b[8..16].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
        b[16] = 4;
        b[17] = 12;
        b[18..20].copy_from_slice(&2437u16.to_le_bytes());
        b[20..22].copy_from_slice(&0xc0u16.to_le_bytes());
        b[22] = (-47i8) as u8;
        b
    } else {
        let mut b = vec![0; 13];
        b[2..4].copy_from_slice(&13u16.to_le_bytes());
        b[4..8].copy_from_slice(&0x28u32.to_le_bytes());
        b[8..10].copy_from_slice(&2437u16.to_le_bytes());
        b[10..12].copy_from_slice(&0xc0u16.to_le_bytes());
        b[12] = (-42i8) as u8;
        b
    };
    let mut mpdu = vec![0; 24];
    mpdu[..2].copy_from_slice(&[8, 0x42]);
    mpdu[4..10].copy_from_slice(&OWN);
    mpdu[10..16].copy_from_slice(&AP);
    mpdu[16..22].copy_from_slice(&AP);
    mpdu[22..24].copy_from_slice(&0x1230u16.to_le_bytes());
    mpdu.extend_from_slice(&[0x77; 32]);
    bytes.extend(mpdu);
    bytes
}
struct Bound {
    device: Arc<ModelDevice>,
    bus: Handle,
    admin: narf_net::AdminHandle,
    socket: Arc<PacketSock>,
    database: Arc<narf_wireless::reg::db::Database>,
    name: String,
}
impl Bound {
    fn new(version: u32, prefix: u32, profile: Profile) -> Result<Self, &'static str> {
        let (adapter, bus) = if prefix == 0 {
            firmware::create(version, false)
        } else {
            firmware::create_prefixed(false, prefix)
        }
        .map_err(|_| "monitor CR4/common-ring attach")?;
        bus.enable_monitor(profile);
        let database = Arc::new(narf_wireless::reg::db::Database::new());
        database.install(firmware::domain());
        let station = run(Station::initialize_live(adapter, &[], database.clone()))
            .map_err(|_| "monitor native initialization")?;
        let name = narf_net::iface::register("wlan%d", OWN, send);
        let device = shell(name.clone(), station);
        narf_net::iface::set_link_state(&name, false);
        let cap = narf_net::registry()
            .register(&narf_net::bootstrap_authority(), Registered(device.clone()))
            .map_err(|_| "monitor registered native netdev")?;
        let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon,
        })
        .map_err(|_| "monitor original administrative owner")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = device.clone();
        narf_wireless::registry::register(iface);
        run(device.monitor_fixture_setup(database.clone()))
            .map_err(|_| "monitor actual format discovery/target binding")?;
        let socket = PacketSock::create(0, SOCK_RAW, ETH_P_ALL.to_be(), 131072);
        Ok(Self {
            device,
            bus,
            admin,
            socket,
            database,
            name,
        })
    }
    fn configure(&self) -> Result<(), &'static str> {
        self.device
            .set_iftype(6)
            .map_err(|_| "monitor original mode/layer change")?;
        self.device
            .set_monitor_channel(channel())
            .map_err(|_| "monitor selected native receive channel")?;
        self.bind()?;
        Ok(())
    }
    fn bind(&self) -> Result<(), &'static str> {
        self.socket
            .bind(
                Some(&self.name),
                narf_net::iface::lookup(&self.name).unwrap().ifindex as i32,
                ETH_P_ALL.to_be(),
            )
            .map_err(|_| "monitor AF_PACKET original representation bind")?;
        // Binding while DOWN records the ordinary socket ENETDOWN. Consume
        // that expected notification before checking actual later RX data.
        self.socket.take_error();
        Ok(())
    }
    fn up(&self) -> Result<(), &'static str> {
        self.admin
            .set_link(true)
            .map_err(|_| "monitor actual administrative UP")?;
        run(self.device.monitor_worker());
        if !self.bus.monitor_change(|p| p.mode == 3)
            || !narf_net::iface::lookup(&self.name).is_some_and(|i| i.carrier)
        {
            return Err("monitor native filter/channel receipts and original capture token");
        }
        Ok(())
    }
    fn inject(&self, bytes: Vec<u8>, flags: u16) {
        self.bus.monitor_change(|p| p.raw.push_back((bytes, flags)));
    }
    fn copies(&self) -> Result<Vec<crate::brcmfmac::monitor_scope::Received>, &'static str> {
        let mut state = self.device.state.try_lock().ok_or("monitor copy State")?;
        let State {
            station, monitor, ..
        } = &mut *state;
        monitor
            .as_mut()
            .ok_or("monitor actual native Session")?
            .step(station)
            .map_err(|_| "monitor actual native copied batch")
    }
    fn empty_eth(&self) -> bool {
        self.device
            .rx
            .lock()
            .as_mut()
            .is_some_and(|rx| matches!(rx.try_recv(), Ok(None)))
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        self.socket.release();
        self.bus.d3_ack(true);
        let _ = run(self.device.teardown());
        *ACTIVE_TEST.lock() = None;
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister(&self.name);
        narf_net::iface::unregister(&self.name);
    }
}

fn native_capture() -> Result<(), &'static str> {
    for (version, prefix) in [(5, 0), (6, 0), (7, 0), (7, 1), (7, 4)] {
        let mut profile = Profile::default();
        if version == 5 {
            profile.capabilities = b"rtap\0".to_vec();
        }
        let b = Bound::new(version, prefix, profile)?;
        b.configure()?;
        b.up()?;
        for tsft in [false, true] {
            let expected = raw(tsft);
            b.inject(expected.clone(), 2);
            b.device.monitor_drain();
            let observed = b
                .socket
                .recv(false)
                .map_err(|_| "monitor actual AF_PACKET delivery")?;
            if observed.data != expected
                || observed.hatype != 803
                || observed.pkttype != 3
                || !b.empty_eth()
            {
                return Err(
                    "monitor rewrote native radiotap/ciphertext or leaked Ethernet ingress",
                );
            }
        }
        if b.device.enqueue(&raw(false)).is_ok() || b.device.supports_control_port_tx_status() {
            return Err("monitor enabled injection or invented packet ACK");
        }
        let original = {
            let state = b.device.state.try_lock().unwrap();
            state.monitor.as_ref().unwrap().original().clone()
        };
        b.admin.set_link(false).map_err(|_| "monitor actual DOWN")?;
        if original.current().is_ok() {
            return Err("monitor DOWN retained original raw copy permission");
        }
        run(b.device.monitor_worker());
        if b.bus.monitor_change(|p| p.mode) != 0
            || narf_net::iface::lookup(&b.name).is_some_and(|i| i.carrier)
        {
            return Err("monitor native stop/readback did not close capture");
        }
        b.bind()?;
        b.up()?;
        b.inject(raw(false), 2);
        b.device.monitor_drain();
        if b.socket.recv(false).is_err() || original.current().is_ok() {
            return Err("monitor successor revived old owner or denied actual fresh raw");
        }
    }
    Ok(())
}
fn smoke_brcmf_monitor_native_flagged_radiotap_exact_bytes_prefixes_and_stop() -> TestResult {
    native_capture().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/monitor",
    smoke_brcmf_monitor_native_flagged_radiotap_exact_bytes_prefixes_and_stop
);

fn denied_profiles() -> Result<(), &'static str> {
    for caps in [
        b"monitor\0".as_slice(),
        b"monitor\0rtap\0",
        b"monitor radiotap\0",
        b"monitor rtapX\0",
    ] {
        let mut p = Profile::default();
        p.capabilities = caps.to_vec();
        let b = Bound::new(7, 0, p)?;
        if b.device.set_iftype(6).is_ok() || b.bus.monitor_change(|p| !p.writes.is_empty()) {
            return Err(
                "monitor flag/format inferred from bare, substring or unknown firmware evidence",
            );
        }
    }
    let b = Bound::new(7, 0, Profile::default())?;
    b.configure()?;
    for width in [2, 3, 5] {
        let mut wide = channel();
        wide.width = width;
        if b.device.set_monitor_channel(wide).is_ok() {
            return Err("monitor silently narrowed unknown native width");
        }
    }
    for flags in [2, 4, 8, 16, 32, 64, 128] {
        if b.device.validate_monitor_flags(flags).is_ok() {
            return Err("monitor accepted unsupported filter/injection option");
        }
    }
    if !b.bus.monitor_change(|p| p.writes.is_empty()) {
        return Err("monitor invalid geometry/flags mutated native prefix");
    }
    Ok(())
}
fn smoke_brcmf_monitor_native_format_and_atomic_channel_flags_admission() -> TestResult {
    denied_profiles().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/monitor",
    smoke_brcmf_monitor_native_format_and_atomic_channel_flags_admission
);

fn copied_retirement() -> Result<(), &'static str> {
    for policy in [false, true] {
        let b = Bound::new(7, 0, Profile::default())?;
        b.configure()?;
        b.up()?;
        b.inject(raw(false), 2);
        let copies = b.copies()?;
        if copies.len() != 1 {
            return Err("monitor native original copied record missing");
        }
        if policy {
            b.database.install(firmware::domain());
        } else {
            b.admin
                .set_mac([2, 6, 7, 8, 9, 11])
                .map_err(|_| "monitor actual MAC retirement")?;
            b.admin
                .set_mac(OWN)
                .map_err(|_| "monitor actual MAC return")?;
        }
        if b.device.monitor_deliver(copies) || b.socket.recv(false).is_ok() || !b.empty_eth() {
            return Err("monitor copied old policy/MAC owner published after retirement");
        }
        run(b.device.monitor_worker());
        if b.bus.monitor_change(|p| p.mode) != 0 {
            return Err("monitor retired native owner did not actually stop");
        }
    }
    Ok(())
}
fn smoke_brcmf_monitor_native_copies_do_not_follow_policy_or_mac_replacement() -> TestResult {
    copied_retirement().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/monitor",
    smoke_brcmf_monitor_native_copies_do_not_follow_policy_or_mac_replacement
);

fn invalid_records() -> Result<(), &'static str> {
    for fault in 0..5 {
        let b = Bound::new(7, 4, Profile::default())?;
        b.configure()?;
        b.up()?;
        let mut packet = raw(false);
        let mut flags = 2;
        match fault {
            0 => packet[0] = 1,
            1 => packet[2..4].copy_from_slice(&2047u16.to_le_bytes()),
            2 => packet[4..8].copy_from_slice(&0u32.to_le_bytes()),
            3 => packet[8..10].copy_from_slice(&5180u16.to_le_bytes()),
            _ => flags = 3,
        };
        let before = b.bus.mappings().1;
        b.inject(packet, flags);
        b.device.monitor_drain();
        if b.socket.recv(false).is_ok()
            || b.bus.dma_enabled()
            || b.bus.mappings().1 != before
            || !b.empty_eth()
        {
            return Err("monitor malformed/foreign original descriptor released uncertain owner or guessed metadata");
        }
    }
    Ok(())
}
fn smoke_brcmf_monitor_native_bad_shape_channel_or_type_preserves_dma_owner() -> TestResult {
    invalid_records().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/monitor",
    smoke_brcmf_monitor_native_bad_shape_channel_or_type_preserves_dma_owner
);

fn arming_and_cancel() -> Result<(), &'static str> {
    {
        let mut profile = Profile::default();
        profile.wrong_channel = true;
        let b = Bound::new(7, 0, profile)?;
        b.configure()?;
        b.admin
            .set_link(true)
            .map_err(|_| "monitor actual mismatched-channel UP")?;
        run(b.device.monitor_worker());
        if b.socket.recv(false).is_ok()
            || b.bus.monitor_change(|p| p.mode) != 0
            || narf_net::iface::lookup(&b.name).is_some_and(|i| i.carrier)
        {
            return Err("monitor mismatched actual native channel readback activated raw capture");
        }
    }
    {
        let mut profile = Profile::default();
        profile.early = Some(raw(false));
        let b = Bound::new(7, 1, profile)?;
        b.configure()?;
        b.up()?;
        if b.socket.recv(false).is_ok() {
            return Err("monitor SET3-drain raw bypassed actual filter/channel readback");
        }
        b.inject(raw(true), 2);
        b.device.monitor_drain();
        if b.socket.recv(false).ok().map(|r| r.data) != Some(raw(true)) {
            return Err("monitor actual Armed native record did not follow reserved drop phase");
        }
    }
    let mut profile = Profile::default();
    profile.early = Some(raw(false));
    profile.hold_readback = true;
    let b = Bound::new(7, 0, profile)?;
    b.configure()?;
    b.admin
        .set_link(true)
        .map_err(|_| "monitor actual held-start UP")?;
    let dropped = b.bus.mappings().1;
    {
        let mut future = pin!(b.device.monitor_worker());
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) || b.bus.monitor_change(|p| p.mode) != 3
            || b.socket.recv(false).is_ok()
            || narf_net::iface::lookup(&b.name).is_some_and(|i| i.carrier)
        {
            return Err("monitor missing actual GET3 reply invented activated/capture owner");
        }
    }
    run(b.device.monitor_worker());
    if b.bus.dma_enabled() || b.bus.mappings().1 != dropped || b.device.monitor_capable() {
        return Err(
            "monitor cancelled native transaction released DMA or retained advertised live owner",
        );
    }
    Ok(())
}
fn smoke_brcmf_monitor_native_reservation_is_not_activation_and_cancel_keeps_dma() -> TestResult {
    arming_and_cancel().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/monitor",
    smoke_brcmf_monitor_native_reservation_is_not_activation_and_cancel_keeps_dma
);

fn raw_progress_and_event_prefix() -> Result<(), &'static str> {
    {
        let b = Bound::new(7, 0, Profile::default())?;
        b.configure()?;
        b.up()?;
        b.bus.monitor_change(|p| {
            for _ in 0..64 {
                p.raw.push_back((raw(false), 2));
            }
        });
        // Control is genuinely idle even though the actual native RX producer
        // remains busy. A global-D2H-idle shortcut would discard this batch.
        if !b.device.monitor_drain() || b.socket.recv(false).is_err() {
            return Err("monitor continuous actual raw producer required invented global idle");
        }
    }
    let b = Bound::new(7, 0, Profile::default())?;
    b.configure()?;
    b.up()?;
    // Actual native event buffers hold a channel-owner invalidation beyond
    // one four-poll budget. They share the real common control ring.
    b.bus.monitor_control_prefix(160);
    b.inject(raw(false), 2);
    for _ in 0..16 {
        b.device.monitor_drain();
    }
    if b.socket.recv(false).is_ok() || !b.empty_eth() {
        return Err("monitor pending native channel event prefix was bypassed by raw data");
    }
    run(b.device.monitor_worker());
    if b.bus.monitor_change(|p| p.mode) != 0 {
        return Err("monitor actual channel-owner loss did not close native filter");
    }
    Ok(())
}
fn smoke_brcmf_monitor_native_control_prefix_is_distinct_from_continuous_raw_progress() -> TestResult
{
    raw_progress_and_event_prefix().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/monitor",
    smoke_brcmf_monitor_native_control_prefix_is_distinct_from_continuous_raw_progress
);

fn stop_and_pm() -> Result<(), &'static str> {
    let b = Bound::new(7, 0, Profile::default())?;
    b.configure()?;
    b.up()?;
    b.inject(raw(false), 2);
    let copies = b.copies()?;
    b.bus.d3_ack(true);
    run(Endpoint::suspend(&*b.device))
        .map_err(|_| "monitor actual native filter0 and D3 suspend")?;
    // D3 suspend retires the old capture/token authority and the carrier,
    // but retains DMA by design: Linux `brcmf_pcie_pm_enter_D3` touches
    // neither BME nor the rings (the bus only goes DOWN; the D3 ack is the
    // firmware's promise its DMA engines stopped), and NARF `brcmfmac.md`
    // "System suspend" keeps the rings retained for the hot `leave_d3`
    // resume; BME is cleared only by the confirmed stop
    // (`Runtime::quiesce`, removal/reset). The monitor arm converges on
    // the same `suspend_transport`/`enter_d3` as AP/station, and nothing
    // in `monitor_suspend` parks DMA. The station D3/D0 smoke asserts
    // the same retention (`dma.len()` unchanged, `dropped == 0`).
    if b.device.monitor_deliver(copies) {
        return Err("monitor system suspend replayed old capture");
    }
    if narf_net::iface::lookup(&b.name).is_some_and(|i| i.carrier) {
        return Err("monitor system suspend left carrier up");
    }
    if !b.bus.dma_enabled() {
        return Err("monitor system suspend freed DMA rings (D3 retains rings/BME)");
    }
    b.bus.d0_alive();
    run(Endpoint::resume(&*b.device)).map_err(|_| "monitor actual D0 hot receipt")?;
    run(b.device.monitor_worker());
    if b.bus.monitor_change(|p| p.mode) != 0 {
        return Err("monitor resume replayed old receiver/format activation without new UP");
    }
    if narf_net::iface::lookup(&b.name).is_some_and(|i| i.carrier) {
        return Err("monitor resume re-raised carrier without new UP");
    }
    if !b.bus.dma_enabled() {
        return Err("monitor hot resume lost DMA rings");
    }
    b.admin
        .set_link(false)
        .map_err(|_| "monitor fresh post-PM DOWN")?;
    b.bind()?;
    b.up()?;
    b.inject(raw(true), 2);
    b.device.monitor_drain();
    if b.socket.recv(false).ok().map(|r| r.data) != Some(raw(true)) {
        return Err("monitor fresh post-PM actual raw owner failed");
    }
    Ok(())
}
fn smoke_brcmf_monitor_native_system_pm_never_replays_old_capture() -> TestResult {
    stop_and_pm().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/monitor",
    smoke_brcmf_monitor_native_system_pm_never_replays_old_capture
);
