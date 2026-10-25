//! Association → carrier → DHCP composition fixture (Wi-Fi program
//! Phase A1, tracker issue #706).
//!
//! Every mt76 fixture below this one stops at Ethernet delivery: the
//! fake AP proves scan → auth/assoc → 4-way → protected data, and the
//! net crate proves the DHCP client against wired interfaces, but
//! nothing composed the two. This module is that composition. It
//! drives the production station session (`Session<Model>`, the same
//! `Session` the hardware `Transport` wraps) through scan and
//! association — Open and WPA2-PSK — then registers the interface
//! with `narf_net::iface` under the same fn-pointer seam
//! `register_scan_iface` uses in production (a `SendFn` plus an RX
//! drain installed with `install_rx_drain`), raises carrier only
//! after association completes (as `Mt76Iface::associate` does), and
//! runs the production DHCP client (`narf_net::dhcp::dhcp_acquire`)
//! against a DHCP server living in the fake AP. The lease, the
//! wire-level DISCOVER/REQUEST the AP observed, and a post-lease data
//! frame in each direction are all asserted.
//!
//! Production-glue audit result: no glue was missing. The seam is
//! exactly the one production uses — association gates the send path
//! (the controlled port), `set_link_metadata` publishes carrier, and the
//! DHCP client is an ordinary `narf_net` client over the registered
//! netdev. The one substitution is forced by the fixture environment:
//! production's bridge (`Mt76Iface` + the `BOOT_OWNER` globals) is
//! bound to the concrete hardware transport, which does not exist in
//! the test guest, so the harness below mirrors its wiring shape
//! (static slot, send/drain fn pointers, routing outside the lock)
//! around the fake-backend session. Every component on the path —
//! session datapath, iface registry, TCP/UDP stack, DHCP client — is
//! the production one.
//!
//! A2 swap point: another family reuses this composition by replacing
//! the `Session<Model>` and the AP's native-packet dialect; the
//! harness (registration, carrier gating, DHCP server, assertions)
//! is driver-agnostic.

use super::*;
use alloc::{string::String, vec, vec::Vec};
use narf_wifi_fixtures::{
    dhcp_message_type, udp_ipv4 as wrap_udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan,
};

// ── Fixture network plan ───────────────────────────────────────────

/// Station MAC. Must match the identity the Model's capability reply
/// reports (`capabilities()` in the parent fixture), which is what
/// `initialize_radio` adopts.
const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
/// AP BSSID; the fake DHCP server lives on the AP, so it is also the
/// Ethernet source of every downlink frame.
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
const CHANNEL: u8 = 6;
const SSID: &[u8] = b"narf-dhcp";
const PSK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
/// The fake server's address; also the lease's gateway and DNS.
const SERVER_IP: [u8; 4] = [10, 77, 0, 1];
const LEASE_IP: [u8; 4] = [10, 77, 0, 42];
const NETMASK: [u8; 4] = [255, 255, 255, 0];
const LEASE_SECS: u32 = 3600;
const NETWORK: NetworkPlan = NetworkPlan {
    station: OWN,
    bssid: AP,
    server_ip: SERVER_IP,
    lease_ip: LEASE_IP,
    netmask: NETMASK,
    lease_seconds: LEASE_SECS,
};

// ── Harness ────────────────────────────────────────────────────────

/// The composed system under test. Mirrors production's `ACTIVE`
/// slot in `iface.rs`: a static is required because `narf_net` takes
/// plain fn pointers for the send and drain hooks.
///
/// `session` is an `Option` because scan/association are async
/// operations the test body drives directly (with the fixture `run`
/// executor); production has the same ownership split — the boot
/// owner lends the transport out across key/recovery futures. The
/// send/drain hooks treat a missing session as a closed datapath.
struct Harness {
    session: Option<Session<Model>>,
    name: String,
    /// One queued Ethernet frame awaiting the next bounded step, the
    /// harness analogue of `Mt76Iface`'s TX ring + `pending_tx`.
    pending_tx: Option<Vec<u8>>,
    /// Cursor into the backend's captured-frame log for AP reactions.
    ap_cursor: usize,
    /// Next pairwise packet number for downlink CCMP packets. The
    /// session's replay window starts at 0, so the first is 1.
    next_pn: u64,
    /// WPA2 composition: downlink data is presented as
    /// hardware-decrypted CCMP. Open composition: plaintext.
    protected_link: bool,
    /// Model-only activation of the completed receive prerequisite after
    /// legacy MLME authorizes the station; this is not HT association evidence.
    aggregate_rx: bool,
    server: DhcpServer,
    received: Vec<Vec<u8>>,
}

static HARNESS: narf_lib::sync::IrqSafeSpinLock<Option<Harness>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn take_session() -> Option<Session<Model>> {
    HARNESS.lock().as_mut()?.session.take()
}

fn put_session(session: Session<Model>) {
    if let Some(harness) = HARNESS.lock().as_mut() {
        harness.session = Some(session);
    }
}

/// `narf_net::iface::SendFn` for the composition. Admission mirrors
/// production's `Mt76Iface::enqueue`: no carrier (no associated
/// session) or a full TX slot refuses the frame — this is what keeps
/// DHCP off the air before the port is authorized.
fn harness_send(frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    let mut slot = HARNESS.lock();
    let harness = slot.as_mut().ok_or(())?;
    let associated = harness
        .session
        .as_ref()
        .is_some_and(|session| matches!(session.state, State::Associated { .. }));
    if !associated || harness.pending_tx.is_some() {
        return Err(());
    }
    harness.pending_tx = Some(frame.to_vec());
    Ok(())
}

/// `narf_net::iface` RX drain: the bounded packet step the DHCP
/// client's spin loop pumps (production pumps `Mt76Iface`'s identical
/// step via its installed drain).
fn harness_drain() -> bool {
    let (name, received, transmitted) = {
        let mut slot = HARNESS.lock();
        let Some(harness) = slot.as_mut() else {
            return false;
        };
        let Some(mut session) = harness.session.take() else {
            return false;
        };
        // The AP reacts to whatever the station has already put on
        // the air before this step collects RX, so a reply queued by
        // the reaction is delivered by the same step.
        harness.ap_service(&mut session);
        let tx = harness.pending_tx.take();
        let step = session.step_network(tx.as_deref());
        harness.session = Some(session);
        match step {
            Ok(step) => {
                harness.received.extend(step.received.iter().cloned());
                (harness.name.clone(), step.received, step.transmitted)
            }
            Err(Error::Busy) => {
                // A previous data TX is still completing; keep the
                // queued frame for the next step, as the production
                // pending-TX slot does.
                if harness.pending_tx.is_none() {
                    harness.pending_tx = tx;
                }
                return false;
            }
            Err(_) => return false,
        }
    };
    // Route outside the harness lock: the stack may synchronously
    // re-enter `harness_send` (e.g. an ARP reply), exactly the
    // re-entrancy production's `drain_network` is careful about.
    let progress = transmitted || !received.is_empty();
    for mut frame in received {
        narf_net::iface::on_rx_frame_from(&name, &mut frame);
    }
    progress
}

impl Harness {
    /// The fake AP's DHCP server: scan the backend's captured frames
    /// for station data, answer DISCOVER/REQUEST by queueing the
    /// reply as a native downlink packet for the session's RX path.
    fn ap_service(&mut self, session: &mut Session<Model>) {
        let mut replies = Vec::new();
        while self.ap_cursor < session.backend.frames.len() {
            let frame = session.backend.frames[self.ap_cursor].1.clone();
            self.ap_cursor += 1;
            if !is_station_data(&frame) {
                continue;
            }
            if let Some(reply) = self.server.receive(&frame) {
                replies.push(reply);
            }
        }
        for reply in replies {
            self.queue_downlink(session, &reply);
        }
    }

    fn queue_downlink(&mut self, session: &mut Session<Model>, eth: &[u8]) {
        if self.aggregate_rx {
            let pn = self.next_pn;
            self.next_pn += 1;
            let seq = pn as u16 & 0xfff;
            // The second MSDU is an unrelated, bounded Ethernet-II frame.
            // Both belong to one MPDU/CCMP PN; DHCP sees only its own reply.
            let second = super::amsdu_rx_tests::ethernet(0x55, 3);
            session
                .backend
                .packets
                .push_back(super::amsdu_rx_tests::packet(
                    eth,
                    self.protected_link,
                    pn,
                    3,
                    seq,
                ));
            session
                .backend
                .packets
                .push_back(super::amsdu_rx_tests::packet(
                    &second,
                    self.protected_link,
                    pn,
                    1,
                    seq,
                ));
        } else {
            let packet = self.downlink_packet(eth);
            session.backend.packets.push_back(packet);
        }
    }

    /// Wrap an Ethernet frame the AP sends to the station as a native
    /// CONNAC2 RX packet: QoS Data FromDS, LLC/SNAP, and — on the
    /// WPA2 link — marked as hardware-decrypted CCMP under the
    /// pairwise key with a fresh packet number (the same RXD dialect
    /// `ccmp_packet` in the parent fixture speaks). Addr3 carries the
    /// Ethernet source, so `to_ethernet` rebuilds the frame verbatim.
    fn downlink_packet(&mut self, eth: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(34 + eth.len());
        frame.extend_from_slice(&[0x88, if self.protected_link { 0x42 } else { 0x02 }]);
        frame.extend_from_slice(&[0, 0]); // duration
        frame.extend_from_slice(&eth[0..6]); // Addr1: station
        frame.extend_from_slice(&AP); // Addr2: BSSID
        frame.extend_from_slice(&eth[6..12]); // Addr3: Ethernet source
        frame.extend_from_slice(&[0, 0]); // sequence control
        frame.extend_from_slice(&[0, 0]); // QoS control: TID 0
        frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        frame.extend_from_slice(&eth[12..14]); // EtherType via SNAP
        frame.extend_from_slice(&eth[14..]);
        if self.protected_link {
            let pn = self.next_pn;
            self.next_pn += 1;
            let mut packet = vec![0u8; 40];
            let len = 40 + frame.len();
            packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
            packet[4..8].copy_from_slice(&((4u32 << 16) | (1 << 11)).to_le_bytes());
            packet[12..16].copy_from_slice(&(u32::from(CHANNEL) << 8).to_le_bytes());
            packet[24..30].copy_from_slice(&pn.to_le_bytes()[..6]);
            packet.extend_from_slice(&frame);
            packet
        } else {
            let mut packet = vec![0u8; 24];
            let len = 24 + frame.len();
            packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
            packet[12..16].copy_from_slice(&(u32::from(CHANNEL) << 8).to_le_bytes());
            packet.extend_from_slice(&frame);
            packet
        }
    }
}

/// True for frames the station put on the data path: the same shape
/// `Session::start_ethernet` admits and production's
/// `transmit_admitted` enforces (station source, EtherType payload,
/// never EAPOL). MCU/management frames in the backend log cannot
/// match the station-MAC-at-source-offset predicate.
fn is_station_data(frame: &[u8]) -> bool {
    frame.len() >= 14
        && frame[6..12] == OWN
        && u16::from_be_bytes([frame[12], frame[13]]) >= 0x600
        && frame[12..14] != [0x88, 0x8e]
}

/// Every data frame the AP has captured, paired with the protection
/// flag the session submitted it under, in submission order.
fn captured_data(session: &Session<Model>) -> Vec<(Vec<u8>, bool)> {
    let frames: Vec<Vec<u8>> = session
        .backend
        .frames
        .iter()
        .map(|(_, frame)| frame.clone())
        .filter(|frame| is_station_data(frame))
        .collect();
    debug_assert_eq!(frames.len(), session.backend.data_protection.len());
    frames
        .into_iter()
        .zip(session.backend.data_protection.iter().copied())
        .collect()
}

// ── Native packet adapter for the shared reactive AP ────────────────

fn push_beacon(session: &mut Session<Model>) {
    let mut frame = session
        .backend
        .access_point
        .as_ref()
        .expect("fixture AP")
        .beacon();
    if let Some(parameters) = &session.backend.wmm_reply {
        frame.extend_from_slice(parameters);
    }
    let mut packet = vec![0u8; 32 + frame.len()];
    let len = packet.len();
    packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    packet[12..16].copy_from_slice(&(u32::from(CHANNEL) << 8).to_le_bytes());
    packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    packet[32..].copy_from_slice(&frame);
    session.backend.packets.push_back(packet);
}

// ── The composition ────────────────────────────────────────────────

fn composition(wpa2: bool, aggregate_rx: bool, wmm: bool) -> TestResult {
    let mut model = Model::new();
    if wmm {
        model.wmm_reply = Some(super::wmm_tests::PARAMETERS.to_vec());
    }
    model.station_channel = CHANNEL;
    model.access_point = Some(
        if wpa2 {
            FakeAp::wpa2(NETWORK, SSID, CHANNEL, 42, PSK, ANONCE)
        } else {
            FakeAp::open(NETWORK, SSID, CHANNEL, 42)
        }
        .expect("fixture AP configuration"),
    );
    let mut session = Session::new(model, firmware(32));
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("composition radio init");
    }
    let State::RadioReady(info) = session.state else {
        return TestResult::Fail("composition radio state");
    };
    if info.capabilities.mac != OWN {
        return TestResult::Fail("composition radio identity");
    }

    // Install only the idempotent RX dispatch, without resetting another
    // family's routes, timers or netfilter hooks in the shared test guest.
    narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
    let name = narf_net::iface::register("wlan%d", OWN, harness_send);
    narf_net::iface::set_link_state(&name, true); // operator IFF_UP
    narf_net::iface::install_rx_drain(harness_drain);
    *HARNESS.lock() = Some(Harness {
        session: Some(session),
        name: name.clone(),
        pending_tx: None,
        ap_cursor: 0,
        next_pn: 1,
        protected_link: wpa2,
        aggregate_rx,
        server: DhcpServer::new(NETWORK),
        received: Vec::new(),
    });

    let result = composition_body(&name, wpa2, aggregate_rx, wmm);

    // Teardown in reverse order: session first (no drain/send can
    // fire against a half-removed interface), then carrier, then
    // the registry entry — the next composition reuses the name.
    *HARNESS.lock() = None;
    let closed = crate::iface::publish_link(&name, false)
        && narf_net::iface::lookup(&name).is_some_and(|snap| {
            snap.link_up
                && !snap.carrier
                && snap.carrier_up_count == 1
                && snap.carrier_down_count == 1
        });
    narf_net::iface::unregister(&name);
    if result == TestResult::Pass && (!closed || narf_net::ipv4::lookup_binding(&name).is_some()) {
        TestResult::Fail("composition retained carrier or IPv4 binding after teardown")
    } else {
        result
    }
}

fn composition_body(name: &str, wpa2: bool, aggregate_rx: bool, wmm: bool) -> TestResult {
    // ── Before association: no carrier, and the controlled port
    // keeps DHCP off the air entirely (audit §4.3.1 S1: "no DHCP
    // before PORT_SECURE" — here, before association completes).
    match narf_net::iface::lookup(name) {
        Some(snap) if snap.link_up && !snap.carrier => {}
        _ => return TestResult::Fail("interface must start with carrier down"),
    }
    if narf_net::dhcp::acquire(name, 400).is_ok() {
        return TestResult::Fail("DHCP acquired a lease before association");
    }
    if let Some(harness) = HARNESS.lock().as_ref() {
        let session = harness.session.as_ref().expect("session parked");
        if !captured_data(session).is_empty() {
            return TestResult::Fail("data reached the AP before association");
        }
    }

    // ── Scan (production parser) → association (production MLME +
    // shared RSNA supplicant, fake AP running a real authenticator).
    let Some(mut session) = take_session() else {
        return TestResult::Fail("harness session missing at join");
    };
    push_beacon(&mut session);
    let joined = run(session.scan_passive(&[CHANNEL]))
        .ok()
        .and_then(|report| report.bss.into_iter().next())
        .and_then(|bss| {
            if bss.bssid != AP || bss.ssid != SSID {
                return None;
            }
            let security = if wpa2 {
                crate::mt7921::association::Security::Wpa2Psk { psk: PSK }
            } else {
                crate::mt7921::association::Security::Open
            };
            run(session.associate_station(&bss, SSID, security, test_permission_for(CHANNEL), &[]))
                .ok()
                .map(|aid| (bss, aid))
        });
    let Some((_, aid)) = joined else {
        put_session(session);
        return TestResult::Fail("scan/association did not complete");
    };
    if aid != 42
        || !matches!(session.state, State::Associated { .. })
        || session.backend.access_point.as_ref().map(FakeAp::phase) != Some(ApPhase::Authorized)
        || session.wmm.is_some() != wmm
    {
        put_session(session);
        return TestResult::Fail("associated state/aid mismatch");
    }
    if aggregate_rx {
        super::amsdu_rx_tests::activate_receive(&mut session);
    }
    put_session(session);

    // ── Carrier up, exactly where `Mt76Iface::associate` raises it:
    // after the association (and 4-way) has completed.
    if !crate::iface::publish_link(name, true)
        || !narf_net::iface::lookup(name).is_some_and(|snap| snap.link_up && snap.carrier)
    {
        return TestResult::Fail("carrier did not come up after association");
    }
    narf_net::iface::set_link_state(name, false);
    if !crate::iface::publish_link(name, true)
        || !narf_net::iface::lookup(name).is_some_and(|snap| !snap.link_up && snap.carrier)
    {
        return TestResult::Fail("physical carrier overwrote operator DOWN");
    }
    narf_net::iface::set_link_state(name, true);

    // ── The lease: production DHCP client over the associated link,
    // fake AP as the server. `dhcp_acquire` also binds the address
    // on the interface (its `ipv4::bind_address` install).
    let lease = match narf_net::dhcp::dhcp_acquire(name, 0) {
        Ok(lease) => lease,
        Err(_) => return TestResult::Fail("DHCP did not complete over the associated link"),
    };
    if !NETWORK.matches_lease(&lease) {
        return TestResult::Fail("lease terms differ from the server's offer");
    }

    // ── Wire evidence at the AP: a DISCOVER and a REQUEST arrived
    // as data frames, protected iff the link is WPA2.
    if let Some(harness) = HARNESS.lock().as_ref() {
        let seen = harness.server.observations();
        if seen.discovers != 1 || seen.requests != 1 {
            return TestResult::Fail("AP did not observe the full DISCOVER/REQUEST exchange");
        }
        let session = harness.session.as_ref().expect("session parked");
        if session.backend.data_qos.len() != session.backend.data_protection.len()
            || session.backend.data_qos.iter().any(|qos| *qos != wmm)
        {
            return TestResult::Fail("DHCP link used unnegotiated QoS metadata");
        }
        let dhcp_frames = captured_data(session)
            .into_iter()
            .filter(|(frame, _)| dhcp_message_type(frame).is_some())
            .count();
        if dhcp_frames != 2 {
            return TestResult::Fail("AP captured data frames are not the DHCP pair");
        }
        for (frame, protected) in captured_data(session) {
            if dhcp_message_type(&frame).is_some() && protected != wpa2 {
                return TestResult::Fail("DHCP crossed the link with the wrong protection");
            }
        }
    }

    // ── Post-lease data, station → AP: a frame addressed from the
    // leased address crosses the registered netdev and is captured
    // by the AP byte-for-byte, under the link's protection.
    let probe = wrap_udp_ipv4(AP, OWN, LEASE_IP, SERVER_IP, 49152, 7, b"narf-a1-probe");
    if narf_net::iface::send_on(name, &probe).is_err() {
        return TestResult::Fail("post-lease transmit refused by the netdev");
    }
    while narf_net::iface::drain_pump() {}
    if let Some(harness) = HARNESS.lock().as_ref() {
        let session = harness.session.as_ref().expect("session parked");
        let found = captured_data(session)
            .into_iter()
            .any(|(frame, protected)| frame == probe && protected == wpa2);
        if !found {
            return TestResult::Fail("post-lease frame did not reach the AP intact");
        }
    }

    // ── Post-lease data, AP → station: a downlink frame addressed
    // to the leased address enters the stack's RX dispatch on this
    // interface (the same `on_rx_frame_from` the ACK already proved
    // end-to-end; here the registry's own RX counter is the witness).
    let rx_before = rx_packets(name);
    let downlink = wrap_udp_ipv4(
        OWN,
        AP,
        SERVER_IP,
        LEASE_IP,
        12345,
        54321,
        b"narf-a1-downlink",
    );
    {
        let mut slot = HARNESS.lock();
        let Some(harness) = slot.as_mut() else {
            return TestResult::Fail("harness vanished before downlink");
        };
        let mut session = harness.session.take().expect("session parked");
        harness.queue_downlink(&mut session, &downlink);
        harness.session = Some(session);
    }
    while narf_net::iface::drain_pump() {}
    if rx_packets(name) <= rx_before {
        return TestResult::Fail("post-lease downlink never entered stack RX dispatch");
    }
    if !HARNESS
        .lock()
        .as_ref()
        .is_some_and(|h| h.received.contains(&downlink))
    {
        return TestResult::Fail("post-lease native downlink changed Ethernet bytes");
    }

    TestResult::Pass
}

fn rx_packets(name: &str) -> u64 {
    narf_net::iface::snapshot_counters()
        .iter()
        .find(|counters| counters.name == name)
        .map_or(0, |counters| counters.rx_packets)
}

fn mt76_wifi_open_association_dhcp_lease_composition() -> TestResult {
    composition(false, false, false)
}
kernel_test_in!(
    "drivers/wireless/mt7921/dhcp",
    mt76_wifi_open_association_dhcp_lease_composition
);

fn mt76_wifi_wpa2_association_dhcp_lease_composition() -> TestResult {
    composition(true, false, false)
}
kernel_test_in!(
    "drivers/wireless/mt7921/dhcp",
    mt76_wifi_wpa2_association_dhcp_lease_composition
);

fn mt76_open_amsdu_receive_prerequisite_dhcp_lease_composition() -> TestResult {
    composition(false, true, false)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht_receive",
    mt76_open_amsdu_receive_prerequisite_dhcp_lease_composition
);

fn mt76_wpa2_amsdu_receive_prerequisite_dhcp_lease_composition() -> TestResult {
    composition(true, true, false)
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht_receive",
    mt76_wpa2_amsdu_receive_prerequisite_dhcp_lease_composition
);

fn mt76_open_wmm_qos_dhcp_lease_composition() -> TestResult {
    composition(false, false, true)
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_open_wmm_qos_dhcp_lease_composition
);

fn mt76_wpa2_wmm_qos_dhcp_lease_composition() -> TestResult {
    composition(true, false, true)
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wpa2_wmm_qos_dhcp_lease_composition
);
