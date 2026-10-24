use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::pkt_dhcp as dhcp;
use narf_wireless::eapol::{self, KeyFrame};

const PLAN: NetworkPlan = NetworkPlan {
    station: [2, 0x11, 0x22, 0x33, 0x44, 0x55],
    bssid: [2, 1, 2, 3, 4, 5],
    server_ip: [10, 77, 0, 1],
    lease_ip: [10, 77, 0, 42],
    netmask: [255, 255, 255, 0],
    lease_seconds: 3600,
};
const RSN: &[u8] = &[
    48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
];
// SHA1-PRF computed independently with Python's hashlib/hmac for PMK=55*32,
// ANonce=aa*32, SNonce=73*32 and PLAN's addresses. Do not derive expected keys
// with the production PTK routine used by the AP under test.
const PTK: [u8; 48] = [
    0x68, 0x9a, 0xfa, 0x72, 0x88, 0x8a, 0x3d, 0xfd, 0x21, 0x4b, 0x82, 0x72, 0xba, 0x65, 0xec, 0x2d,
    0x4f, 0x98, 0xbb, 0x11, 0xa7, 0xe3, 0x45, 0x89, 0x99, 0x3b, 0x76, 0xfe, 0xff, 0x19, 0x00, 0x74,
    0x4c, 0x49, 0xef, 0xc2, 0x9f, 0x27, 0x5b, 0xf5, 0x71, 0xdc, 0x8e, 0xff, 0x03, 0xa6, 0x8c, 0xce,
];

macro_rules! ensure {
    ($condition:expr, $reason:literal) => {
        if !$condition {
            return Err($reason);
        }
    };
}
macro_rules! case {
    ($kernel:ident, $body:block) => {
        fn $kernel() -> TestResult {
            let run = || -> Result<(), &'static str> { $body };
            match run() {
                Ok(()) => TestResult::Pass,
                Err(e) => TestResult::Fail(e),
            }
        }
        kernel_test_in!("verification/wifi-fixtures", $kernel);
    };
}

fn request(kind: u8, xid: u32, ip: Option<[u8; 4]>, server: Option<[u8; 4]>) -> Vec<u8> {
    let mut chaddr = [0; 16];
    chaddr[..6].copy_from_slice(&PLAN.station);
    let mut body = Vec::new();
    dhcp::DhcpHeader {
        op: 1,
        htype: 1,
        hlen: 6,
        xid,
        chaddr,
        flags: dhcp::FLAG_BROADCAST,
        ..Default::default()
    }
    .encode_into(&mut body);
    dhcp::append_message_type(&mut body, kind);
    if let Some(ip) = ip {
        dhcp::append_option(&mut body, dhcp::OPT_REQUESTED_IP, &ip);
    }
    if let Some(ip) = server {
        dhcp::append_server_identifier(&mut body, ip);
    }
    dhcp::append_end(&mut body);
    udp_ipv4([255; 6], PLAN.station, [0; 4], [255; 4], 68, 67, &body)
}

fn station_header(subtype: u8) -> Vec<u8> {
    let mut out = vec![subtype, 0, 0, 0];
    out.extend_from_slice(&PLAN.bssid);
    out.extend_from_slice(&PLAN.station);
    out.extend_from_slice(&PLAN.bssid);
    out.extend_from_slice(&[0, 0]);
    out
}

fn auth() -> Vec<u8> {
    let mut out = station_header(0xb0);
    out.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
    out
}

fn assoc(secured: bool) -> Vec<u8> {
    let mut out = station_header(0);
    out.extend_from_slice(&[if secured { 0x11 } else { 1 }, 0, 10, 0]);
    out.extend_from_slice(&[0, 4, b'n', b'a', b'r', b'f', 1, 3, 12, 24, 48]);
    if secured {
        out.extend_from_slice(RSN);
    }
    out
}

fn signed_key(m4: bool) -> Vec<u8> {
    let mut key = KeyFrame::empty(16);
    key.key_information = eapol::KI_KEY_TYPE_PAIRWISE
        | eapol::KI_KEY_MIC
        | eapol::KI_VERSION_HMAC_SHA1_AES
        | if m4 { eapol::KI_SECURE } else { 0 };
    key.replay_counter = if m4 { 2 } else { 1 };
    if !m4 {
        key.key_nonce = [0x73; 32];
        key.key_data = RSN.to_vec();
    }
    let mut pdu = key.into_eapol();
    let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&PTK[..16], &pdu);
    pdu[81..97].copy_from_slice(&mic[..16]);
    let mut frame = station_header(8);
    frame[1] = 1;
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    frame.extend_from_slice(&pdu);
    frame
}

case!(
    wifi_fixture_basic1_profile_matches_beacon_response_and_request,
    {
        for secured in [false, true] {
            let mut ap = if secured {
                FakeAp::wpa2(PLAN, b"narf", 1, 42, [0x55; 32], [0xaa; 32])
            } else {
                FakeAp::open(PLAN, b"narf", 1, 42)
            }
            .map_err(|_| "basic1 AP configuration")?
            .with_basic_1mbps()
            .map_err(|_| "basic1 fixture profile selection")?;
            ensure!(
                ap.beacon().windows(3).any(|b| b == [1, 1, 0x82]),
                "basic1 beacon rate missing"
            );
            ap.receive(&auth()).map_err(|_| "basic1 authentication")?;
            let old = assoc(secured);
            ensure!(
                ap.receive(&old) == Err(ApError::Association),
                "OFDM-only offer admitted basic1 AP"
            );
            let mut request = station_header(0);
            request.extend_from_slice(&[if secured { 0x11 } else { 1 }, 0, 10, 0]);
            request.extend_from_slice(&[0, 4, b'n', b'a', b'r', b'f', 1, 1, 0x82]);
            if secured {
                request.extend_from_slice(RSN);
            }
            let replies = ap
                .receive(&request)
                .map_err(|_| "actual basic1 offer rejected")?;
            ensure!(
                replies[0][30..] == [1, 1, 0x82],
                "basic1 response advertised other mandatory rates"
            );
            ensure!(
                ap.with_basic_1mbps().is_err(),
                "rate profile changed after authentication"
            );
        }
        Ok(())
    }
);

case!(wifi_fixture_dhcp_transaction_and_identity, {
    let mut server = DhcpServer::new(PLAN);
    let selecting = request(
        dhcp::DHCPREQUEST,
        7,
        Some(PLAN.lease_ip),
        Some(PLAN.server_ip),
    );
    ensure!(
        server.receive(&selecting).is_none(),
        "unoffered REQUEST received ACK"
    );
    let discover = request(dhcp::DHCPDISCOVER, 7, None, None);
    let offer = server.receive(&discover).ok_or("DISCOVER not offered")?;
    let bootp = dhcp::DhcpHeader::decode(&offer[42..]).map_err(|_| "OFFER header")?;
    ensure!(
        bootp.xid == 7 && bootp.yiaddr == PLAN.lease_ip,
        "OFFER identity/address"
    );
    ensure!(
        offer[..6] == PLAN.station && offer[6..12] == PLAN.bssid,
        "OFFER Ethernet addresses"
    );
    for bad in [
        request(
            dhcp::DHCPREQUEST,
            8,
            Some(PLAN.lease_ip),
            Some(PLAN.server_ip),
        ),
        request(
            dhcp::DHCPREQUEST,
            7,
            Some([10, 77, 0, 99]),
            Some(PLAN.server_ip),
        ),
        request(
            dhcp::DHCPREQUEST,
            7,
            Some(PLAN.lease_ip),
            Some([10, 77, 0, 2]),
        ),
    ] {
        ensure!(
            server.receive(&bad).is_none(),
            "foreign REQUEST received ACK"
        );
    }
    ensure!(
        server.receive(&selecting).is_some(),
        "correlated REQUEST not ACKed"
    );
    ensure!(
        server.observations()
            == DhcpObservations {
                discovers: 1,
                requests: 1
            },
        "invalid DHCP changed evidence"
    );
    Ok(())
});

case!(wifi_fixture_dhcp_rejects_truncation, {
    let frame = request(dhcp::DHCPDISCOVER, 9, None, None);
    let mut server = DhcpServer::new(PLAN);
    for n in 0..frame.len() {
        ensure!(
            server.receive(&frame[..n]).is_none(),
            "truncated DHCP was accepted"
        );
    }
    ensure!(
        server.observations() == DhcpObservations::default(),
        "truncated DHCP changed state"
    );
    ensure!(
        server.receive(&frame).is_some(),
        "full DHCP rejected after truncations"
    );
    Ok(())
});

case!(wifi_fixture_dhcp_rejects_malformed_wire, {
    let frame = request(dhcp::DHCPDISCOVER, 9, None, None);
    let mut server = DhcpServer::new(PLAN);
    let mut checksum = frame.clone();
    checksum[40] ^= 1;
    ensure!(
        server.receive(&checksum).is_none(),
        "bad UDP checksum accepted"
    );
    let mut foreign = frame.clone();
    foreign[6] ^= 2;
    ensure!(
        server.receive(&foreign).is_none(),
        "wrong Ethernet source accepted"
    );
    for (source, destination) in [([10, 77, 0, 99], [255; 4]), ([0; 4], PLAN.server_ip)] {
        let wrong_ip = udp_ipv4(
            [255; 6],
            PLAN.station,
            source,
            destination,
            68,
            67,
            &frame[42..],
        );
        ensure!(
            server.receive(&wrong_ip).is_none(),
            "unicast/non-initial DHCP IP addresses accepted"
        );
    }
    let mut fragment = frame.clone();
    fragment[20] |= 0x20;
    narf_net::pkt::set_ipv4_checksum(&mut fragment[14..]);
    ensure!(
        server.receive(&fragment).is_none(),
        "fragment accepted as complete DHCP"
    );
    let mut body = frame[42..].to_vec();
    body.pop();
    dhcp::append_message_type(&mut body, dhcp::DHCPREQUEST);
    dhcp::append_end(&mut body);
    let duplicate = udp_ipv4([255; 6], PLAN.station, [0; 4], [255; 4], 68, 67, &body);
    ensure!(
        server.receive(&duplicate).is_none(),
        "duplicate DHCP type accepted"
    );
    body.truncate(240);
    body.extend_from_slice(&[53, 1, 1, 50, 4, 1]);
    let malformed = udp_ipv4([255; 6], PLAN.station, [0; 4], [255; 4], 68, 67, &body);
    ensure!(
        server.receive(&malformed).is_none(),
        "truncated DHCP option accepted"
    );
    ensure!(
        server.observations() == DhcpObservations::default(),
        "malformed DHCP changed state"
    );
    Ok(())
});

case!(wifi_fixture_open_ap_enforces_conversation, {
    let mut ap = FakeAp::open(PLAN, b"narf", 6, 42).map_err(|_| "AP config")?;
    ensure!(
        ap.receive(&assoc(false)).is_err(),
        "association before auth"
    );
    for n in 0..auth().len() {
        ensure!(ap.receive(&auth()[..n]).is_err(), "truncated auth accepted");
    }
    let mut foreign = auth();
    foreign[10] ^= 2;
    ensure!(ap.receive(&foreign).is_err(), "foreign station accepted");
    let mut fragment = auth();
    fragment[22] = 1;
    ensure!(ap.receive(&fragment).is_err(), "fragmented auth accepted");
    ensure!(
        ap.phase() == ApPhase::Authentication,
        "bad auth changed phase"
    );
    let response = ap.receive(&auth()).map_err(|_| "auth failed")?;
    ensure!(
        response.len() == 1 && response[0][24..] == [0, 0, 2, 0, 0, 0],
        "auth response wire"
    );
    let mut wrong = assoc(false);
    wrong[30] ^= 1;
    ensure!(ap.receive(&wrong).is_err(), "wrong SSID accepted");
    ensure!(
        ap.phase() == ApPhase::Association,
        "bad association changed phase"
    );
    // Standard 8+4 split: the AP's encoded 48 basic rate is in Extended
    // Supported Rates, and must not be required to fit in the first IE.
    let mut split_rates = assoc(false);
    split_rates.truncate(34);
    split_rates.extend_from_slice(&[1, 8, 2, 4, 11, 22, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108]);
    let response = ap
        .receive(&split_rates)
        .map_err(|_| "split-rate association failed")?;
    ensure!(
        response.len() == 1 && response[0][28..30] == (42u16 | 0xc000).to_le_bytes(),
        "association AID wire"
    );
    ensure!(
        ap.phase() == ApPhase::Authorized && !ap.protected(),
        "Open port did not authorize"
    );
    Ok(())
});

case!(wifi_fixture_wpa2_ap_verifies_both_mics, {
    let mut ap =
        FakeAp::wpa2(PLAN, b"narf", 6, 42, [0x55; 32], [0xaa; 32]).map_err(|_| "AP config")?;
    ap.receive(&auth()).map_err(|_| "auth")?;
    let replies = ap.receive(&assoc(true)).map_err(|_| "association")?;
    ensure!(
        replies.len() == 2 && ap.phase() == ApPhase::Message2,
        "M1 was not gated on association"
    );
    let m1 = KeyFrame::decode(&replies[1][36..], 16).ok_or("M1 decode")?;
    ensure!(
        m1.key_nonce == [0xaa; 32] && m1.replay_counter == 1,
        "M1 nonce/replay"
    );
    let mut bad_m2 = signed_key(false);
    bad_m2[32 + 81] ^= 1;
    ensure!(
        ap.receive(&bad_m2) == Err(ApError::Mic),
        "bad M2 MIC accepted"
    );
    ensure!(ap.phase() == ApPhase::Message2, "bad M2 advanced phase");
    let replies = ap
        .receive(&signed_key(false))
        .map_err(|_| "golden-key M2 rejected")?;
    ensure!(
        replies.len() == 1 && ap.phase() == ApPhase::Message4,
        "M3 not returned"
    );
    let m3 = KeyFrame::decode(&replies[0][36..], 16).ok_or("M3 decode")?;
    let clear = narf_crypto::aes_kw::aes_unwrap(PTK[16..32].try_into().unwrap(), &m3.key_data)
        .ok_or("M3 KEK differs from golden")?;
    ensure!(
        clear.starts_with(RSN) && clear[30..46] == [0x77; 16],
        "M3 RSN/GTK contents"
    );
    let mut bad_m4 = signed_key(true);
    bad_m4[32 + 81] ^= 1;
    ensure!(
        ap.receive(&bad_m4) == Err(ApError::Mic),
        "bad M4 MIC authorized"
    );
    ensure!(ap.phase() == ApPhase::Message4, "bad M4 advanced phase");
    ensure!(
        ap.receive(&signed_key(true))
            .map_err(|_| "M4 rejected")?
            .is_empty(),
        "M4 response unexpected"
    );
    ensure!(
        ap.phase() == ApPhase::Authorized && ap.protected(),
        "WPA2 port did not authorize"
    );
    Ok(())
});

case!(wifi_fixture_wpa2_ap_rejects_replay_and_wrong_rsn, {
    let mut ap =
        FakeAp::wpa2(PLAN, b"narf", 6, 42, [0x55; 32], [0xaa; 32]).map_err(|_| "AP config")?;
    ap.receive(&auth()).map_err(|_| "auth")?;
    let mut wrong = assoc(true);
    *wrong.last_mut().unwrap() = 0x40;
    ensure!(
        ap.receive(&wrong) == Err(ApError::Association),
        "wrong RSN accepted"
    );
    ensure!(ap.phase() == ApPhase::Association, "bad RSN advanced phase");
    ap.receive(&assoc(true)).map_err(|_| "association")?;
    let mut replay = signed_key(false);
    replay[32 + 16] = 2;
    ensure!(
        ap.receive(&replay) == Err(ApError::Key),
        "wrong M2 replay accepted"
    );
    for n in 0..signed_key(false).len() {
        ensure!(
            ap.receive(&signed_key(false)[..n]).is_err(),
            "truncated EAPOL accepted"
        );
    }
    ensure!(ap.phase() == ApPhase::Message2, "rejected M2 changed state");
    ap.receive(&signed_key(false)).map_err(|_| "M2")?;
    ensure!(
        ap.receive(&signed_key(false)).is_err(),
        "old M2 accepted as M4"
    );
    ensure!(
        ap.phase() == ApPhase::Message4,
        "old replay authorized port"
    );
    Ok(())
});
