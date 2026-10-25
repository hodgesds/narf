//! Exercise the receive prerequisite at a model-only post-HT-admission seam.
//! These tests deliberately do not claim an HT MLME or firmware peer exists.
use super::*;

pub(super) const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
pub(super) const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];

pub(super) fn ht_bss() -> ScanBss {
    // Match the reactive AP's mandatory OFDM6/12/24 profile, with optional
    // OFDM9 preserving the fixture's fixed IE geometry for mutation cases.
    let mut ies = vec![0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x8c, 0x98, 0xb0, 18];
    let mut ht = [0; 26];
    ht[3] = 0xff; // AP supports MCS0..7; minimum one-stream HT profile.
    ies.extend_from_slice(&[45, 26]);
    ies.extend_from_slice(&ht);
    let mut operation = [0; 22];
    operation[0] = 6;
    operation[6] = 0xff; // All required basic MCS are in that first stream.
    ies.extend_from_slice(&[61, 22]);
    ies.extend_from_slice(&operation);
    ScanBss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 6,
        signal_dbm: Some(-45),
        capability: 1,
        beacon_interval: 100,
        information_elements: ies,
    }
}

/// The only activation seam is in the fixture, after its station is already
/// authorized. Production has no HT activation/association API yet.
pub(super) fn activate_receive(session: &mut Session<Model>) {
    let State::Associated { info, .. } = session.state else {
        panic!("fixture must authorize station before receive activation");
    };
    let mut receiver = super::super::amsdu::Receiver::prepare(info, &ht_bss()).unwrap();
    receiver.active = true;
    session.ht20_rx = Some(receiver);
}

pub(super) fn packet(eth: &[u8], protected: bool, pn: u64, marker: u8, seq: u16) -> Vec<u8> {
    let mut frame = vec![0; 28]; // Native QoS header, followed by hardware's two-byte pad.
    frame[..2].copy_from_slice(&[0x88, if protected { 0x42 } else { 2 }]);
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[22..24].copy_from_slice(&(seq << 4).to_le_bytes());
    frame[24] = 0x80;
    frame[26..28].copy_from_slice(&[0xde, 0xad]); // Never part of the MSDU.
    frame.extend_from_slice(&eth[..12]);
    frame.extend_from_slice(&((eth.len() - 14 + 8) as u16).to_be_bytes());
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend_from_slice(&eth[12..]);
    let offset = if protected { 40 } else { 24 };
    let mut packet = vec![0; offset];
    packet[..4].copy_from_slice(&((2u32 << 27) | (offset + frame.len()) as u32).to_le_bytes());
    packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    packet[16] = marker;
    if protected {
        packet[4..8].copy_from_slice(&((4u32 << 16) | (1 << 11)).to_le_bytes());
        packet[24..30].copy_from_slice(&pn.to_le_bytes()[..6]);
    }
    packet.extend_from_slice(&frame);
    packet
}

pub(super) fn ethernet(value: u8, length: usize) -> Vec<u8> {
    let mut eth = Vec::with_capacity(14 + length);
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&AP);
    eth.extend_from_slice(&[8, 0]);
    eth.resize(14 + length, value);
    eth
}

fn model(protected: bool) -> Session<Model> {
    let mut session = secure_model();
    if !protected {
        session.security = None;
    }
    activate_receive(&mut session);
    session
}

fn mt76_amsdu_native_layout_matches_original_linux_receive_oracle() -> TestResult {
    let mut bytes = include_bytes!("amsdu_oracle.bytes").as_slice();
    let mut expected = Vec::new();
    let mut session = model(false);
    for marker in 0..4 {
        let status = &bytes[..5];
        bytes = &bytes[5..];
        let normalized = &bytes[..usize::from(status[4])];
        bytes = &bytes[normalized.len()..];
        let eth = &bytes[..17];
        bytes = &bytes[17..];
        let packet = packet(&ethernet(marker, 3), false, 0, marker, 7);
        let native = super::super::scan::rx_native_with_amsdu(&packet).unwrap();
        let mut frame = native.frame[..26].to_vec();
        frame.extend_from_slice(&native.frame[if marker == 0 { 26 } else { 28 }..]);
        if status[..4]
            != [
                marker,
                u8::from(marker != 0),
                u8::from(marker == 3),
                u8::from(marker == 1),
            ]
            || native.amsdu != marker
            || frame != normalized
            || ethernet(marker, 3) != eth
        {
            return TestResult::Fail("native A-MSDU marker/padding or source Ethernet bytes");
        }
        expected.push(eth.to_vec());
    }
    if !bytes.is_empty() {
        return TestResult::Fail("source oracle record geometry");
    }
    // Original source's first/middle/last markers, with each normalized
    // Ethernet-II result checked against the genuine conversion function.
    for marker in [3u8, 2, 1] {
        session.backend.packets.push_back(packet(
            &expected[usize::from(marker)],
            false,
            0,
            marker,
            7,
        ));
    }
    for marker in [3u8, 2, 1] {
        if session.receive_ethernet() != Ok(Some(expected[usize::from(marker)].clone())) {
            return TestResult::Fail("assembled Ethernet differs from original Linux oracle");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht_receive",
    mt76_amsdu_native_layout_matches_original_linux_receive_oracle
);

fn mt76_ht_receive_preparation_has_no_activation_or_device_side_effects() -> TestResult {
    let mut session = Session::new(Model::new(), firmware(32));
    // MCU command receipts alone cannot answer authentication/association.
    // Retain the same reactive management peer used by the DHCP compositions.
    session.backend.access_point = Some(
        narf_wifi_fixtures::FakeAp::open(
            narf_wifi_fixtures::NetworkPlan {
                station: OWN,
                bssid: AP,
                server_ip: [10, 77, 0, 1],
                lease_ip: [10, 77, 0, 42],
                netmask: [255, 255, 255, 0],
                lease_seconds: 3600,
            },
            b"narf",
            6,
            42,
        )
        .unwrap(),
    );
    if run(session.run()).is_err() || run(session.initialize_radio()).is_err() {
        return TestResult::Fail("radio setup");
    }
    let State::RadioReady(info) = session.state else {
        return TestResult::Fail("radio state");
    };
    let before = session.backend.frames.len();
    let bss = ht_bss();
    let prepared = session.prepare_ht20_receive(&bss).unwrap();
    if prepared.peer != AP
        || prepared.channel != 6
        || prepared.receive_mcs != 0xff
        || prepared.max_amsdu_bytes != 3839
        || session.ht20_rx.as_ref().unwrap().active
        || session.backend.frames.len() != before
        || session.state != State::RadioReady(info)
    {
        return TestResult::Fail("receive preparation enabled a peer/carrier or wrote device");
    }
    for case in 0..11 {
        let mut bss = bss.clone();
        let mut radio = info;
        match case {
            0 => radio.capabilities.phy.ht = false,
            1 => radio.capabilities.phy.spatial_streams = 0,
            2 => bss.bssid = OWN,
            3 => bss.channel = 14,
            4 => bss.capability |= 2,
            5 => bss.beacon_interval = 0,
            6 => bss.information_elements.truncate(12),
            7 => bss.information_elements.push(45),
            8 => bss.information_elements[17] = 0, // AP first-stream MCS byte.
            9 => bss.information_elements[42] = 36, // HT operation primary channel.
            10 => bss.information_elements[49] = 1, // Basic MCS8 is not admitted.
            _ => unreachable!(),
        }
        if super::super::amsdu::Receiver::prepare(radio, &bss).is_ok() {
            return TestResult::Fail("unsupported HT receive geometry admitted");
        }
    }
    // A legacy station never inherits a prepared HT receive owner.
    let joined = run(session.associate_station(
        &bss,
        b"narf",
        crate::mt7921::association::Security::Open,
        test_permission(),
        &[],
    ));
    #[cfg(all(test, target_os = "linux"))]
    if joined != Ok(42) {
        panic!(
            "legacy fixture join={:?}, state={:?}, AP={:?}, management rates={:?}",
            joined,
            session.state,
            session
                .backend
                .access_point
                .as_ref()
                .map(narf_wifi_fixtures::FakeAp::phase),
            session.backend.management_rates
        );
    }
    if joined != Ok(42) {
        return TestResult::Fail("reactive AP did not complete the legacy association fixture");
    }
    if session.ht20_rx.is_some() {
        return TestResult::Fail("legacy association inherited HT receive preparation");
    }
    if session.prepare_ht20_receive(&bss) != Err(Error::Busy) {
        return TestResult::Fail("associated station accepted HT receive preparation");
    }
    session
        .backend
        .packets
        .push_back(packet(&ethernet(1, 3), false, 0, 3, 7));
    session
        .backend
        .packets
        .push_back(packet(&ethernet(2, 3), false, 0, 1, 7));
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("legacy station accepted aggregate RX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht_receive",
    mt76_ht_receive_preparation_has_no_activation_or_device_side_effects
);

#[cfg(all(test, target_os = "linux"))]
#[test]
fn host_ht_receive_preparation_and_legacy_association_lifecycle() {
    assert_eq!(
        mt76_ht_receive_preparation_has_no_activation_or_device_side_effects(),
        TestResult::Pass
    );
}

fn mt76_amsdu_complete_burst_releases_bytes_and_commits_one_pn() -> TestResult {
    for protected in [false, true] {
        let mut session = model(protected);
        let first = ethernet(1, 3);
        let second = ethernet(2, 5);
        let third = ethernet(3, 7);
        let head = packet(&first, protected, 1, 3, 7);
        if super::super::scan::rx_native(&head).is_some()
            || super::super::scan::rx_frame(&head).is_some()
        {
            return TestResult::Fail("aggregate escaped into legacy native parser");
        }
        session.backend.packets.push_back(head.clone());
        session
            .backend
            .packets
            .push_back(packet(&second, protected, 1, 2, 7));
        if session.receive_ethernet() != Ok(None) {
            return TestResult::Fail("partial aggregate released bytes or consumed PN");
        }
        session
            .backend
            .packets
            .push_back(packet(&third, protected, 1, 1, 7));
        if session.receive_ethernet() != Ok(Some(first.clone())) {
            return TestResult::Fail("complete aggregate conversion or PN commit");
        }
        session.backend.live = false;
        if session.receive_ethernet() != Err(Error::Authority) {
            return TestResult::Fail("queued aggregate bypassed current authority");
        }
        session.backend.live = true;
        if session.receive_ethernet() != Ok(Some(second))
            || session.receive_ethernet() != Ok(Some(third))
            || session.receive_ethernet() != Ok(None)
        {
            return TestResult::Fail("aggregate ordering or queued ownership");
        }
        if protected {
            session.backend.packets.push_back(head);
            session
                .backend
                .packets
                .push_back(packet(&first, true, 1, 1, 7));
            if session.receive_ethernet() != Ok(None) {
                return TestResult::Fail("completed aggregate replay admitted");
            }
            // Per-TID replay windows remain independent.
            for marker in [3, 1] {
                let mut next = packet(&first, true, 1, marker, 8);
                next[64] |= 1;
                session.backend.packets.push_back(next);
            }
            if session.receive_ethernet() != Ok(Some(first.clone()))
                || session.receive_ethernet() != Ok(Some(first))
            {
                return TestResult::Fail("aggregate replay windows aliased across TIDs");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht_receive",
    mt76_amsdu_complete_burst_releases_bytes_and_commits_one_pn
);

fn mt76_amsdu_malformed_middle_invalidates_entire_burst_without_pn() -> TestResult {
    let eth = ethernet(7, 5);
    for case in 0..25 {
        let mut session = model(true);
        let mut middle = packet(&eth, true, 1, 2, 7);
        match case {
            0 => {
                middle.truncate(40 + 24);
                let len = middle.len();
                middle[..4].copy_from_slice(&((2u32 << 27) | len as u32).to_le_bytes());
            }
            1 => middle[7] |= 2, // Integrity error.
            2 => middle[13] = 36,
            3 => middle[40] = 0x08, // Non-QoS frame.
            4 => middle[41] |= 4,   // Fragmentation.
            5 => middle[44] = 4,    // Receiver mismatch.
            6 => middle[50] = 4,    // Peer mismatch.
            7 => middle[56] = 3,    // Multicast source.
            8 => middle[62] = 1,    // Fragment number.
            9 => middle[63] = 1,    // Sequence mismatch.
            10 => middle[64] |= 1,  // TID mismatch.
            11 => middle[64] &= !0x80,
            12 => middle[65] = 1,
            13 => middle[68..74].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]),
            14 => middle[68] = 4, // Foreign inner destination.
            15 => middle[74] = 3, // Multicast inner source.
            16 => middle[74..80].fill(0),
            17 => middle[80..82].copy_from_slice(&u16::MAX.to_be_bytes()),
            18 => middle[82] = 0, // Invalid SNAP.
            19 => middle[88..90].copy_from_slice(&[0x88, 0x8e]), // EAPOL cannot cross data port.
            20 => middle[88..90].copy_from_slice(&[0x05, 0xff]),
            21 => middle[24] = 2,      // Packet-number mismatch.
            22 => middle[6] |= 0x20,   // Pairwise key-ID mismatch.
            23 => middle[41] &= !0x40, // Cipher/Protected inconsistency.
            24 => middle.push(0),      // Declared end ignores trailing DMA storage (valid).
            _ => unreachable!(),
        }
        session
            .backend
            .packets
            .push_back(packet(&eth, true, 1, 3, 7));
        session.backend.packets.push_back(middle);
        session
            .backend
            .packets
            .push_back(packet(&eth, true, 1, 1, 7));
        if case == 24 {
            if session.receive_ethernet() != Ok(Some(eth.clone())) {
                return TestResult::Fail("RX descriptor length did not bound DMA storage");
            }
        } else {
            if session.receive_ethernet() != Ok(None) {
                return TestResult::Fail("malformed aggregate retained pieces");
            }
            session.backend.packets.push_back(ccmp_packet(1, 0, false));
            if !matches!(session.receive_ethernet(), Ok(Some(_))) {
                return TestResult::Fail("malformed aggregate consumed PN");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht_receive",
    mt76_amsdu_malformed_middle_invalidates_entire_burst_without_pn
);

fn mt76_amsdu_bounds_timeout_and_peer_teardown_discard_partial_or_queued_data() -> TestResult {
    let eth = ethernet(4, 5);
    let mut session = model(true);
    session
        .backend
        .packets
        .push_back(packet(&eth, true, 1, 3, 7));
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("first subframe delivery");
    }
    session
        .backend
        .ticks
        .set(session.backend.ticks.get() + 100_000_000);
    session
        .backend
        .packets
        .push_back(packet(&eth, true, 1, 1, 7));
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("expired aggregate retained authority or consumed PN");
    }
    let large = ethernet(8, 1500);
    for marker in [3, 2, 1] {
        session
            .backend
            .packets
            .push_back(packet(&large, true, 1, marker, 8));
    }
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("aggregate exceeded the negotiated 3839-byte envelope");
    }
    // A normal frame separates bursts; neither an orphan tail nor a future
    // same-sequence burst can complete the abandoned head.
    session
        .backend
        .packets
        .push_back(packet(&eth, true, 1, 3, 9));
    session.backend.packets.push_back(native_data_packet(true));
    session
        .backend
        .packets
        .push_back(packet(&eth, true, 1, 1, 9));
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("normal frame spliced aggregate");
    }
    // Adversarial endless middles retain bounded work per receive call.
    for _ in 0..33 {
        session
            .backend
            .packets
            .push_back(packet(&eth, true, 1, 2, 10));
    }
    if session.receive_ethernet() != Ok(None) || session.backend.packets.len() != 17 {
        return TestResult::Fail("malformed aggregate bypassed 16-descriptor receive budget");
    }
    session.backend.packets.clear();
    for marker in [3, 1] {
        session
            .backend
            .packets
            .push_back(packet(&eth, true, 1, marker, 11));
    }
    if session.receive_ethernet() != Ok(Some(eth)) {
        return TestResult::Fail("teardown fixture burst");
    }
    session.peer_lost = true;
    if session.receive_ethernet() != Err(Error::DeviceGone) || !session.received_msdu.is_empty() {
        return TestResult::Fail("peer loss retained queued aggregate payload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht_receive",
    mt76_amsdu_bounds_timeout_and_peer_teardown_discard_partial_or_queued_data
);

fn mt76_amsdu_key_cancellation_teardown_and_reset_close_received_ownership() -> TestResult {
    let eth = ethernet(6, 3);
    let mut session = model(true);
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    session
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol())));
    for marker in [3, 1] {
        session
            .backend
            .packets
            .push_back(packet(&eth, true, 1, marker, 7));
    }
    if session.receive_ethernet() != Ok(Some(eth.clone()))
        || !session.keys_pending()
        || session.received_msdu.len() != 1
    {
        return TestResult::Fail("aggregate/key cancellation fixture");
    }
    session.backend.tx_stall = true;
    {
        let mut operation = pin!(session.service_keys());
        let mut cx = Context::from_waker(Waker::noop());
        if operation.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("key operation did not suspend");
        }
    }
    if !session.received_msdu.is_empty()
        || !matches!(session.state, State::Running(_))
        || session.receive_ethernet() != Err(Error::Busy)
    {
        return TestResult::Fail("cancelled key change retained queued aggregate authorization");
    }
    for reset in [false, true] {
        let mut session = model(true);
        for marker in [3, 1] {
            session
                .backend
                .packets
                .push_back(packet(&eth, true, 1, marker, 8));
        }
        if session.receive_ethernet() != Ok(Some(eth.clone())) || session.received_msdu.len() != 1 {
            return TestResult::Fail("aggregate teardown fixture");
        }
        let result = if reset {
            run(session.recover(OWN)).map(|_| ())
        } else {
            run(session.disassociate_station())
        };
        if result.is_err()
            || session.ht20_rx.is_some()
            || !session.received_msdu.is_empty()
            || session.receive_ethernet() != Err(Error::Busy)
        {
            return TestResult::Fail("teardown/reset retained aggregate receive owner or payload");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht_receive",
    mt76_amsdu_key_cancellation_teardown_and_reset_close_received_ownership
);
