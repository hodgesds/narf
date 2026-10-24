//! The shared fake AP over ath11k's real CE/WMI/HTT and TCL/REO rings.
//!
//! Only the peer and firmware/device side are modelled: scan, association,
//! RSNA, key installation, frame rings, native packet descriptors, carrier
//! publication and the DHCP client are the production implementations.

use super::*;
use core::sync::atomic::AtomicBool;
use narf_wifi_fixtures::{udp_ipv4, NetworkPlan};

const NETWORK: NetworkPlan = NetworkPlan {
    station: OWN,
    bssid: BSSID,
    server_ip: [10, 77, 0, 1],
    lease_ip: [10, 77, 0, 42],
    netmask: [255, 255, 255, 0],
    lease_seconds: 3600,
};

type TxConsumer = narf_ipc::Consumer<narf_net::Frame, { narf_net::TX_RING_N }>;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static DRAIN_FAILED: AtomicBool = AtomicBool::new(false);
static TX: IrqSafeSpinLock<Option<TxConsumer>> = IrqSafeSpinLock::new(None);

pub(super) fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// The kernel-test guest has no executor TX worker for this device. Move the
/// actual TX ring consumer into the synchronous drain for the composition's
/// lifetime. Its replacement in `Up` is an unused, closed ring; no aliases or
/// pointers into a movable `Up` are needed.
struct DrainGuard;

impl DrainGuard {
    fn install(u: &mut Up) -> Self {
        let (unused, replacement) = narf_ipc::channel();
        drop(unused);
        let consumer = core::mem::replace(&mut u.tx_cons, replacement);
        let old = TX.lock().replace(consumer);
        drop(old);
        DRAIN_FAILED.store(false, Ordering::Relaxed);
        ACTIVE.store(true, Ordering::Release);
        // Install only the ordinary RX dispatch, without reinitializing the
        // global network stack, timers or netfilter tables between fixtures.
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Self
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Release);
        let consumer = TX.lock().take();
        drop(consumer);
    }
}

/// One bounded TX/runtime pass. The fake interrupt wait progresses the device
/// model, which consumes the native TCL descriptors and fills real posted RX
/// buffers. Every lock is dropped before polling a driver future or routing a
/// received packet into the stack.
fn drain() -> bool {
    if !active() {
        return false;
    }
    let Some(netdev) = TEST_DEV.lock().clone() else {
        return false;
    };
    let frame = TX
        .lock()
        .as_mut()
        .and_then(|consumer| consumer.try_recv().ok().flatten());
    let transmitted = frame.is_some();
    if let Some(frame) = frame {
        if run(netdev.tx_one(&frame)).is_err() {
            DRAIN_FAILED.store(true, Ordering::Release);
        }
    }
    let before = RX_SEEN.lock().len();
    run(netdev.shared.irq.wait(1));
    run(netdev.service_once());
    transmitted || RX_SEEN.lock().len() != before
}

fn drain_all() -> R {
    for _ in 0..32 {
        if !drain() {
            ensure!(
                !DRAIN_FAILED.load(Ordering::Acquire),
                "composition TX pump rejected a frame"
            );
            return Ok(());
        }
    }
    Err("composition drain did not become idle")
}

fn composition(secured: bool) -> R {
    let cfg = if secured {
        wpa2_cfg()
    } else {
        FwCfg {
            beacons: vec![(6, 50, beacon_sec(&BSSID, SSID, 6, None))],
            ..FwCfg::default()
        }
    };
    let mut u = up(cfg)?;
    u.dev.st.borrow_mut().dhcp = Some(DhcpServer::new(NETWORK));
    // start_pci publishes a registered, administratively-up interface with
    // carrier down; link_sink mirrors that production carrier sink below.
    ensure!(
        narf_net::iface::set_link_metadata(u.name, false, None, None),
        "composition initial carrier"
    );
    let _drain = DrainGuard::install(&mut u);

    ensure!(!u.netdev.link_up(), "carrier before association");
    ensure!(
        narf_net::iface::lookup(u.name).is_some_and(|iface| !iface.carrier),
        "registered carrier before association"
    );
    ensure!(
        narf_net::dhcp::acquire(u.name, 400).is_err(),
        "DHCP refused before association"
    );
    ensure!(
        u.dev.st.borrow().ap_data.is_empty(),
        "no pre-association data reached the AP"
    );

    let bss = scan6(&u)?;
    ensure!(
        bss.len() == 1 && bss[0].bssid == BSSID && bss[0].ssid == SSID,
        "composition scan found the AP"
    );
    let req = AssociateRequest {
        bssid: BSSID,
        ssid: SSID.to_vec(),
        frequency_mhz: 2437,
        channel: 6,
        security: if secured {
            SecurityConfig::Wpa2 { psk: PMK }
        } else {
            SecurityConfig::Open
        },
        ie: Vec::new(),
    };
    let (r, err, _, _) = latched(|| run(u.netdev.associate_kernel(req)));
    ensure!(r.is_ok() && err == 0, "composition association");
    ensure!(u.netdev.link_up(), "carrier after association");
    ensure!(
        narf_net::iface::lookup(u.name).is_some_and(|iface| iface.carrier),
        "registered carrier after association"
    );
    if secured {
        let st = u.dev.st.borrow();
        ensure!(
            st.world.ap.m2_mic_ok && st.world.ap.m2_rsn_ok && st.world.ap.m4_ok,
            "composition M2/M4 authenticated over native rings"
        );
        ensure!(
            st.wmi
                .iter()
                .filter(|cmd| cmd.cmd_id == wmi::WMI_VDEV_INSTALL_KEY_CMDID)
                .count()
                == 2,
            "composition installed pairwise and group keys"
        );
    }

    let lease = narf_net::dhcp::dhcp_acquire(u.name, 0)
        .map_err(|_| "DHCP lease did not cross native rings")?;
    ensure!(
        NETWORK.matches_lease(&lease),
        "composition DHCP lease terms"
    );
    ensure!(
        !DRAIN_FAILED.load(Ordering::Acquire),
        "DHCP TX pump failure"
    );
    {
        let st = u.dev.st.borrow();
        let seen = st.dhcp.as_ref().ok_or("shared AP missing")?.observations();
        ensure!(
            seen.discovers == 1 && seen.requests == 1,
            "AP observed DISCOVER/REQUEST through TCL"
        );
        ensure!(
            st.ap_data.len() == 2
                && st
                    .ap_data
                    .iter()
                    .all(|(_, protected)| *protected == secured),
            "DHCP data used the negotiated native TX protection"
        );
    }

    let uplink = udp_ipv4(
        BSSID,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        49152,
        7,
        b"ath11k-a2-uplink",
    );
    ensure!(
        narf_net::iface::send_on(u.name, &uplink).is_ok(),
        "post-lease uplink admission"
    );
    drain_all()?;
    ensure!(
        u.dev
            .st
            .borrow()
            .ap_data
            .iter()
            .any(|(frame, protected)| frame == &uplink && *protected == secured),
        "post-lease Ethernet bytes reached the AP through TCL"
    );

    let downlink = udp_ipv4(
        OWN,
        BSSID,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        12345,
        54321,
        b"ath11k-a2-downlink",
    );
    let rx_before = narf_net::iface::snapshot_counters()
        .into_iter()
        .find(|counters| counters.name == u.name)
        .ok_or("composition counters")?
        .rx_packets;
    u.dev.st.borrow_mut().rx_queue.push_back(downlink.clone());
    drain_all()?;
    ensure!(
        RX_SEEN.lock().contains(&downlink),
        "post-lease Ethernet bytes reached the RX sink through REO"
    );
    ensure!(
        narf_net::iface::snapshot_counters()
            .into_iter()
            .find(|counters| counters.name == u.name)
            .is_some_and(|counters| counters.rx_packets > rx_before),
        "post-lease downlink entered stack RX dispatch"
    );

    run(u.netdev.disassociate()).map_err(|_| "composition disconnect")?;
    ensure!(!u.netdev.link_up(), "carrier after disconnect");
    ensure!(
        narf_net::iface::lookup(u.name).is_some_and(|iface| !iface.carrier),
        "registered carrier after disconnect"
    );
    let captured = u.dev.st.borrow().ap_data.len();
    ensure!(
        narf_net::dhcp::acquire(u.name, 400).is_err()
            && narf_net::iface::send_on(u.name, &uplink).is_err(),
        "data admission closed after disconnect"
    );
    drain_all()?;
    ensure!(
        u.dev.st.borrow().ap_data.len() == captured,
        "no post-disconnect data reached the AP"
    );
    Ok(())
}

fn ath11k_wifi_open_association_dhcp_lease_composition() -> TestResult {
    check(|| composition(false))
}
kernel_test_in!(
    "drivers/wireless/ath11k/dhcp",
    ath11k_wifi_open_association_dhcp_lease_composition
);

fn ath11k_wifi_wpa2_association_dhcp_lease_composition() -> TestResult {
    check(|| composition(true))
}
kernel_test_in!(
    "drivers/wireless/ath11k/dhcp",
    ath11k_wifi_wpa2_association_dhcp_lease_composition
);
