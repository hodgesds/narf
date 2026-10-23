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
//! (the controlled port), `set_link_state` publishes carrier, and the
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
use core::sync::atomic::{AtomicBool, Ordering};

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
    saw_discover: bool,
    saw_request: bool,
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
            Ok(step) => (harness.name.clone(), step.received, step.transmitted),
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
            match dhcp_respond(&frame) {
                Some((reply, narf_net::pkt_dhcp::DHCPDISCOVER)) => {
                    self.saw_discover = true;
                    replies.push(reply);
                }
                Some((reply, narf_net::pkt_dhcp::DHCPREQUEST)) => {
                    self.saw_request = true;
                    replies.push(reply);
                }
                _ => {}
            }
        }
        for reply in replies {
            let packet = self.downlink_packet(&reply);
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

// ── Fake DHCP server ───────────────────────────────────────────────

/// Answer one station DHCP request with the server's reply Ethernet
/// frame plus the DHCP message type seen, or `None` for anything
/// that is not a well-formed DISCOVER/REQUEST for this server.
fn dhcp_respond(eth: &[u8]) -> Option<(Vec<u8>, u8)> {
    use narf_net::pkt_dhcp::{
        append_end, append_message_type, append_option, append_server_identifier, DhcpHeader,
        DHCPACK, DHCPOFFER, OPT_DNS_SERVER, OPT_LEASE_TIME, OPT_REQUESTED_IP, OPT_ROUTER,
        OPT_SERVER_IDENTIFIER, OPT_SUBNET_MASK,
    };
    if eth.len() < 42 || eth[0..6] != [0xff; 6] || eth[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &eth[14..];
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    if ihl < 20 || ip[9] != 17 || ip.len() < ihl + 8 {
        return None;
    }
    let udp = &ip[ihl..];
    if u16::from_be_bytes([udp[0], udp[1]]) != 68 || u16::from_be_bytes([udp[2], udp[3]]) != 67 {
        return None;
    }
    let payload = udp[8..].to_vec();
    let request = DhcpHeader::decode(&payload).ok()?;
    if request.op != 1 || request.chaddr[..6] != OWN {
        return None;
    }
    let mut msg_type = 0u8;
    let mut requested_ip = None;
    let mut server_id = None;
    for option in narf_net::pkt_dhcp::iter_options(&payload[240..]) {
        match option.tag {
            53 if option.data.len() == 1 => msg_type = option.data[0],
            OPT_REQUESTED_IP if option.data.len() == 4 => {
                requested_ip = Some(option.data);
            }
            OPT_SERVER_IDENTIFIER if option.data.len() == 4 => {
                server_id = Some(option.data);
            }
            _ => {}
        }
    }
    let reply_type = match msg_type {
        narf_net::pkt_dhcp::DHCPDISCOVER => DHCPOFFER,
        narf_net::pkt_dhcp::DHCPREQUEST => {
            // A REQUEST is only ACKed for the address this server
            // offered, naming this server — anything else is not
            // part of the composed conversation.
            if requested_ip != Some(&LEASE_IP[..]) || server_id != Some(&SERVER_IP[..]) {
                return None;
            }
            DHCPACK
        }
        _ => return None,
    };
    let mut dhcp = Vec::with_capacity(300);
    DhcpHeader {
        op: 2,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: request.xid,
        secs: 0,
        flags: request.flags,
        ciaddr: [0; 4],
        yiaddr: LEASE_IP,
        siaddr: SERVER_IP,
        giaddr: [0; 4],
        chaddr: request.chaddr,
    }
    .encode_into(&mut dhcp);
    append_message_type(&mut dhcp, reply_type);
    append_server_identifier(&mut dhcp, SERVER_IP);
    append_option(&mut dhcp, OPT_SUBNET_MASK, &NETMASK);
    append_option(&mut dhcp, OPT_ROUTER, &SERVER_IP);
    append_option(&mut dhcp, OPT_DNS_SERVER, &SERVER_IP);
    append_option(&mut dhcp, OPT_LEASE_TIME, &LEASE_SECS.to_be_bytes());
    append_end(&mut dhcp);
    Some((
        wrap_udp_ipv4(OWN, AP, SERVER_IP, [255; 4], 67, 68, &dhcp),
        msg_type,
    ))
}

/// Wrap a payload in UDP + IPv4 + Ethernet, the mirror of the DHCP
/// client's own `wrap_broadcast_frame` (which see in `net/src/dhcp.rs`)
/// with explicit unicast/broadcast addressing.
fn wrap_udp_ipv4(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    use narf_net::pkt::{
        set_ipv4_checksum, write_eth_header, write_ipv4_header, ETHERTYPE_IPV4, ETH_HDR_LEN,
        IPV4_HDR_LEN, IP_PROTO_UDP,
    };
    let ip_total = (IPV4_HDR_LEN + narf_net::pkt_udp::UDP_HDR_LEN + payload.len()) as u16;
    let mut frame = vec![0u8; ETH_HDR_LEN + ip_total as usize];
    write_eth_header(&mut frame, dst_mac, src_mac, ETHERTYPE_IPV4);
    {
        let ip = &mut frame[ETH_HDR_LEN..];
        let _ = write_ipv4_header(ip, ip_total, IP_PROTO_UDP, src_ip, dst_ip);
        set_ipv4_checksum(ip);
    }
    let udp = &mut frame[ETH_HDR_LEN + IPV4_HDR_LEN..];
    let _ = narf_net::pkt_udp::build_ipv4(udp, src_ip, dst_ip, src_port, dst_port, payload);
    frame
}

// ── Join choreography (mirrors the parent fixture's wire bytes) ────

fn push_beacon(session: &mut Session<Model>, wpa2: bool) {
    let mut packet = scan_beacon(CHANNEL, SSID);
    if wpa2 {
        // Same construction as `live_join_wpa2`: keep the fixed
        // header, patch capability, replace the IEs with the full
        // set including the RSN element.
        packet.truncate(68);
        packet[66..68].copy_from_slice(&0x11u16.to_le_bytes());
        let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
        let mut ies = vec![0, SSID.len() as u8];
        ies.extend_from_slice(SSID);
        ies.extend_from_slice(&[1, 3, 0x8c, 0x98, 0xb0]);
        ies.extend_from_slice(&[3, 1, CHANNEL, 48, rsn.len() as u8]);
        ies.extend_from_slice(&rsn);
        packet.extend_from_slice(&ies);
        let len = packet.len();
        packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    } else {
        packet[66..68].copy_from_slice(&1u16.to_le_bytes());
        // A real beacon always carries Supported Rates, and the join
        // plan derives the association request's rates from the
        // scanned BSS's elements. `scan_beacon`'s minimal element set
        // omits them (it was built for scan-parser tests), so append
        // the rates element the parent's own open-join fixture puts
        // in its hand-built BSS.
        packet.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
        let len = packet.len();
        packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    }
    session.backend.packets.push_back(packet);
}

fn management_packet(frame: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 32 + frame.len()];
    let len = packet.len();
    packet[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    packet[12..16].copy_from_slice(&(u32::from(CHANNEL) << 8).to_le_bytes());
    packet[28..32].copy_from_slice(&0x00007864u32.to_le_bytes());
    packet[32..].copy_from_slice(frame);
    packet
}

fn push_join_replies(session: &mut Session<Model>, wpa2: bool) {
    let mut auth_resp = vec![0u8; 30];
    auth_resp[0] = 0xb0;
    auth_resp[4..10].copy_from_slice(&OWN);
    auth_resp[10..16].copy_from_slice(&AP);
    auth_resp[16..22].copy_from_slice(&AP);
    auth_resp[24..30].copy_from_slice(&[0, 0, 2, 0, 0, 0]);
    session
        .backend
        .packets
        .push_back(management_packet(&auth_resp));

    let mut assoc_resp = vec![0u8; 30];
    assoc_resp[0] = 0x10;
    assoc_resp[4..10].copy_from_slice(&OWN);
    assoc_resp[10..16].copy_from_slice(&AP);
    assoc_resp[16..22].copy_from_slice(&AP);
    assoc_resp[24..26].copy_from_slice(&(if wpa2 { 0x31u16 } else { 1u16 }).to_le_bytes());
    assoc_resp[26..28].copy_from_slice(&0u16.to_le_bytes());
    assoc_resp[28..30].copy_from_slice(&(42u16 | 0xc000).to_le_bytes());
    session
        .backend
        .packets
        .push_back(management_packet(&assoc_resp));

    if wpa2 {
        // EAPOL-Key M1; the Model's authenticator answers the M2 the
        // session sends with a real M3 (see `submit_management`).
        let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
        m1.descriptor_type = narf_wireless::eapol::KEY_DESCRIPTOR_RSN;
        m1.key_information = narf_wireless::eapol::KI_KEY_TYPE_PAIRWISE
            | narf_wireless::eapol::KI_KEY_ACK
            | narf_wireless::eapol::KI_VERSION_HMAC_SHA1_AES;
        m1.key_length = 16;
        m1.replay_counter = 1;
        m1.key_nonce = ANONCE;
        let m1_frame = ap_eapol_frame(OWN, AP, &m1.into_eapol());
        session
            .backend
            .packets
            .push_back(management_packet(&m1_frame));
    }
}

// ── The composition ────────────────────────────────────────────────

static STACK_INIT: AtomicBool = AtomicBool::new(false);

fn composition(wpa2: bool) -> TestResult {
    let mut model = Model::new();
    model.station_channel = CHANNEL;
    if wpa2 {
        model.psk = PSK;
        model.anonce = ANONCE;
        model.ap_mac = AP;
        model.own_mac = OWN;
    }
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

    // Kernel-test guests never run the boot init that wires the
    // stack's RX handler; the virtio DHCP smoke does the same call.
    if !STACK_INIT.swap(true, Ordering::AcqRel) {
        narf_net::tcp_stack::init();
    }
    let name = narf_net::iface::register("wlan%d", OWN, harness_send);
    narf_net::iface::install_rx_drain(harness_drain);
    *HARNESS.lock() = Some(Harness {
        session: Some(session),
        name: name.clone(),
        pending_tx: None,
        ap_cursor: 0,
        next_pn: 1,
        protected_link: wpa2,
        saw_discover: false,
        saw_request: false,
    });

    let result = composition_body(&name, wpa2);

    // Teardown in reverse order: session first (no drain/send can
    // fire against a half-removed interface), then carrier, then
    // the registry entry — the next composition reuses the name.
    *HARNESS.lock() = None;
    narf_net::iface::set_link_state(&name, false);
    narf_net::iface::unregister(&name);
    result
}

fn composition_body(name: &str, wpa2: bool) -> TestResult {
    // ── Before association: no carrier, and the controlled port
    // keeps DHCP off the air entirely (audit §4.3.1 S1: "no DHCP
    // before PORT_SECURE" — here, before association completes).
    match narf_net::iface::lookup(name) {
        Some(snap) if !snap.link_up => {}
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
    push_beacon(&mut session, wpa2);
    let joined = run(session.scan_passive(&[CHANNEL]))
        .ok()
        .and_then(|report| report.bss.into_iter().next())
        .and_then(|bss| {
            if bss.bssid != AP || bss.ssid != SSID {
                return None;
            }
            push_join_replies(&mut session, wpa2);
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
    if aid != 42 || !matches!(session.state, State::Associated { .. }) {
        put_session(session);
        return TestResult::Fail("associated state/aid mismatch");
    }
    put_session(session);

    // ── Carrier up, exactly where `Mt76Iface::associate` raises it:
    // after the association (and 4-way) has completed.
    if !narf_net::iface::set_link_state(name, true)
        || !narf_net::iface::lookup(name).is_some_and(|snap| snap.link_up)
    {
        return TestResult::Fail("carrier did not come up after association");
    }

    // ── The lease: production DHCP client over the associated link,
    // fake AP as the server. `dhcp_acquire` also binds the address
    // on the interface (its `ipv4::bind_address` install).
    let lease = match narf_net::dhcp::dhcp_acquire(name, 0) {
        Ok(lease) => lease,
        Err(_) => return TestResult::Fail("DHCP did not complete over the associated link"),
    };
    if lease.addr.0 != LEASE_IP
        || lease.netmask.0 != NETMASK
        || lease.gateway.map(|gateway| gateway.0) != Some(SERVER_IP)
        || lease.dns.len() != 1
        || lease.dns[0].0 != SERVER_IP
        || lease.lease_seconds != LEASE_SECS
    {
        return TestResult::Fail("lease terms differ from the server's offer");
    }

    // ── Wire evidence at the AP: a DISCOVER and a REQUEST arrived
    // as data frames, protected iff the link is WPA2.
    if let Some(harness) = HARNESS.lock().as_ref() {
        if !harness.saw_discover || !harness.saw_request {
            return TestResult::Fail("AP did not observe the full DISCOVER/REQUEST exchange");
        }
        let session = harness.session.as_ref().expect("session parked");
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
        let packet = harness.downlink_packet(&downlink);
        let session = harness.session.as_mut().expect("session parked");
        session.backend.packets.push_back(packet);
    }
    while narf_net::iface::drain_pump() {}
    if rx_packets(name) <= rx_before {
        return TestResult::Fail("post-lease downlink never entered stack RX dispatch");
    }

    TestResult::Pass
}

/// The DHCP message type (option 53) of an Ethernet frame, if it is
/// a DHCP client→server datagram at all.
fn dhcp_message_type(eth: &[u8]) -> Option<u8> {
    if eth.len() < 42 || eth[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &eth[14..];
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    if ihl < 20 || ip[9] != 17 || ip.len() < ihl + 8 {
        return None;
    }
    let udp = &ip[ihl..];
    if u16::from_be_bytes([udp[2], udp[3]]) != 67 {
        return None;
    }
    let payload = &udp[8..];
    if payload.len() < 240 || narf_net::pkt_dhcp::DhcpHeader::decode(payload).is_err() {
        return None;
    }
    narf_net::pkt_dhcp::iter_options(&payload[240..])
        .find(|option| option.tag == 53 && option.data.len() == 1)
        .map(|option| option.data[0])
}

fn rx_packets(name: &str) -> u64 {
    narf_net::iface::snapshot_counters()
        .iter()
        .find(|counters| counters.name == name)
        .map_or(0, |counters| counters.rx_packets)
}

fn mt76_wifi_open_association_dhcp_lease_composition() -> TestResult {
    composition(false)
}
kernel_test_in!(
    "drivers/wireless/mt7921/dhcp",
    mt76_wifi_open_association_dhcp_lease_composition
);

fn mt76_wifi_wpa2_association_dhcp_lease_composition() -> TestResult {
    composition(true)
}
kernel_test_in!(
    "drivers/wireless/mt7921/dhcp",
    mt76_wifi_wpa2_association_dhcp_lease_composition
);
