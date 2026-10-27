//! Native production MLME/EDCA/QoS tests. Literal wire cases are independent
//! of the encoder; the reactive AP adapter appends actual received WMM IEs.
use super::*;
use crate::mt7921::association::{wmm::Parameters, JoinPlan, Security};
use narf_wifi_fixtures::{FakeAp, NetworkPlan};

const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(super) const NETWORK: NetworkPlan = NetworkPlan {
    station: OWN,
    bssid: AP,
    server_ip: [10, 78, 0, 1],
    lease_ip: [10, 78, 0, 42],
    netmask: [255, 255, 255, 0],
    lease_seconds: 3600,
};

// WMM v1 Parameter IE: U-APSD advertised by AP but never requested by STA;
// rows deliberately arrive VO, BE, VI, BK to catch ACI/LMAC permutations.
pub(super) const PARAMETERS: [u8; 26] = [
    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x81, 0, 0x62, 0x32, 47, 0, 0x03, 0xa4, 0, 0, 0x42, 0x43, 94,
    0, 0x27, 0xa4, 0, 0,
];

pub(super) fn prepared(wmm: bool, wpa2: bool) -> (Session<Model>, ScanBss) {
    prepared_with_chip(wmm, wpa2, 0)
}
pub(super) fn prepared_with_chip(wmm: bool, wpa2: bool, chip_id: u16) -> (Session<Model>, ScanBss) {
    let mut model = Model::new();
    model.chip_id = chip_id;
    let ap = if wpa2 {
        FakeAp::wpa2(NETWORK, b"narf", 6, 42, [0x55; 32], [0xaa; 32])
    } else {
        FakeAp::open(NETWORK, b"narf", 6, 42)
    }
    .unwrap();
    let beacon = ap.beacon();
    let mut bss = ScanBss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 6,
        signal_dbm: Some(-45),
        capability: u16::from_le_bytes([beacon[34], beacon[35]]),
        beacon_interval: 100,
        information_elements: beacon[36..].to_vec(),
    };
    if wmm {
        bss.information_elements.extend_from_slice(&PARAMETERS);
        model.wmm_reply = Some(PARAMETERS.to_vec());
    }
    model.access_point = Some(ap);
    let mut session = Session::new(model, firmware(32));
    run(session.run()).unwrap();
    run(session.initialize_radio()).unwrap();
    (session, bss)
}

fn security(wpa2: bool) -> Security {
    if wpa2 {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    }
}

fn command(frame: &[u8], id: u8) -> bool {
    frame.len() >= 64 && frame[36] == id && frame[37] == 0xa0
}

fn mt76_wmm_parameter_validation_and_native_edca_wire_values() -> TestResult {
    let parameters = Parameters::parse(&PARAMETERS).unwrap().unwrap();
    // mt7921_mcu_set_tx's ten-byte EDCA rows in BE/BK/VI/VO ACI order;
    // CW values are (1 << ECW)-1, TXOP remains in units of 32 us.
    let expected = [
        31, 0, 255, 3, 0, 0, 3, 0, 0, 0, 15, 0, 255, 3, 0, 0, 7, 0, 0, 0, 7, 0, 15, 0, 94, 0, 2, 0,
        0, 0, 3, 0, 7, 0, 47, 0, 2, 0, 0, 0, 0, 1, 0, 0,
    ];
    if parameters.edca() != expected
        || Parameters::parse(&crate::mt7921::association::wmm::INFORMATION) != Ok(None)
    {
        return TestResult::Fail("WMM AC order/CW conversion/EDCA fields");
    }
    for end in 1..PARAMETERS.len() {
        if Parameters::parse(&PARAMETERS[..end]).is_ok() {
            return TestResult::Fail("truncated WMM Parameter IE admitted");
        }
    }
    for (offset, value) in [
        (7, 2),
        (8, 0x10),
        (9, 1), // version / reserved QoS Info / reserved byte
        (10, 0xe2),
        (10, 0x61), // reserved ACI bit / AIFSN below 2
        (11, 0x30),
        (11, 0x23), // CWmin zero / CWmin > CWmax
        (14, 0x13),
        (22, 0x03), // BE admission control / duplicate BE, missing BK
    ] {
        let mut bad = PARAMETERS;
        bad[offset] = value;
        if Parameters::parse(&bad).is_ok() {
            return TestResult::Fail("invalid/duplicate/admission-controlled WMM accepted");
        }
    }
    let mut duplicate = PARAMETERS.to_vec();
    duplicate.extend_from_slice(&PARAMETERS);
    if Parameters::parse(&duplicate).is_ok() {
        return TestResult::Fail("duplicate AP WMM Parameter element");
    }
    // Extreme legal exponent must not wrap a u16 shift; native CW 32767.
    let mut wide = PARAMETERS;
    wide[11] = 0xff;
    if Parameters::parse(&wide).unwrap().unwrap().edca()[30..34] != [255, 127, 255, 127] {
        return TestResult::Fail("WMM maximum ECW conversion overflow");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_parameter_validation_and_native_edca_wire_values
);

fn mt76_wmm_negotiated_open_and_wpa2_program_edca_before_qos_peer() -> TestResult {
    for wpa2 in [false, true] {
        let (mut session, bss) = prepared(true, wpa2);
        let before = session.backend.frames.len();
        if run(session.associate_station(&bss, b"narf", security(wpa2), test_permission(), &[]))
            != Ok(42)
            || session.wmm.is_none()
            || session.ht20_rx.is_some()
        {
            return TestResult::Fail("WMM legacy station negotiation/authorization");
        }
        let frames = &session.backend.frames[before..];
        let assoc = frames.iter().position(|(_, frame)| {
            frame.first() == Some(&0) && frame.get(10..16) == Some(OWN.as_slice())
        });
        let edca = frames.iter().position(|(_, frame)| command(frame, 0x1d));
        let Some((assoc, edca)) = assoc.zip(edca) else {
            return TestResult::Fail("WMM association request/EDCA command missing");
        };
        if assoc >= edca
            || !frames[assoc]
                .1
                .ends_with(&[221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0])
            || frames[edca].1[64..] != Parameters::parse(&PARAMETERS).unwrap().unwrap().edca()
            || !command(&frames[edca + 1].1, 0xc0)
        {
            return TestResult::Fail("WMM negotiation/native EDCA/PSE order");
        }
        let bss_updates: Vec<_> = frames
            .iter()
            .enumerate()
            .filter(|(_, (_, frame))| {
                frame.len() == 92 && frame[34..36] == [2, 0] && frame[43] == 7
            })
            .collect();
        if bss_updates.len() != 2
            || bss_updates[0].0 >= assoc
            || bss_updates[1].0 <= edca + 1
            || bss_updates[0].1 .1[84..] != [15, 0, 8, 0, 0, 0, 0, 0]
            || bss_updates[1].1 .1[84..] != [15, 0, 8, 0, 1, 0, 0, 0]
        {
            return TestResult::Fail("WMM BSS QBSS TLV missing or enabled before EDCA receipt");
        }
        // Unified payload starts at 48. BASIC.qos is +17; nested
        // WTBL_GENERIC.qos is +93. Initial auth WCID must stay non-QoS.
        let peers: Vec<_> = frames
            .iter()
            .filter(|(_, frame)| {
                frame.len() >= 168 && frame[34..36] == [3, 0] && frame[43] == 7 && frame[49] == 1
            })
            .collect();
        if peers.len() < 3
            || peers[0].1[65] != 0
            || peers[0].1[141] != 0
            || peers[1..]
                .iter()
                .any(|(_, frame)| frame[65] != 1 || frame[141] != 1)
        {
            return TestResult::Fail("WMM STA_REC/WTBL QoS or preassociation isolation");
        }
        let mut eth = vec![0xff; 18];
        eth[6..12].copy_from_slice(&OWN);
        eth[12..14].copy_from_slice(&[8, 0]);
        if run(session.send_ethernet(&eth)).is_err()
            || session.backend.data_qos != [true]
            || session.backend.data_protection != [wpa2]
        {
            return TestResult::Fail("authorized BE/TID0 QoS data/security selection");
        }
        if run(session.disassociate_station()).is_err() {
            return TestResult::Fail("bound model deauth/native WMM cleanup did not complete");
        }
        if session.wmm.is_some()
            || session.station_permission.is_some()
            || session.security.is_some()
            || session.backend.access_point.is_some()
            || !matches!(session.state, State::ScanReady(_))
        {
            return TestResult::Fail("WMM teardown retained QoS/grant");
        }
        let closed_bss = session
            .backend
            .frames
            .iter()
            .rev()
            .find(|(_, frame)| frame.len() == 92 && frame[34..36] == [2, 0] && frame[43] == 7);
        if closed_bss.is_none_or(|(_, frame)| frame[84..] != [15, 0, 8, 0, 0, 0, 0, 0]) {
            return TestResult::Fail("WMM teardown did not retire BSS QBSS QoS");
        }
        let reset = session
            .backend
            .frames
            .iter()
            .rev()
            .find(|(_, frame)| command(frame, 0x1d));
        if reset.is_none_or(|(_, frame)| frame[105] != 0) {
            return TestResult::Fail("WMM teardown did not retire EDCA QoS");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_negotiated_open_and_wpa2_program_edca_before_qos_peer
);

fn mt76_wmm_downgrade_malformed_and_unsolicited_responses() -> TestResult {
    for case in 0..5 {
        let (mut session, mut bss) = prepared(true, false);
        match case {
            0 => session.backend.wmm_reply = None,
            1 => session.backend.wmm_reply.as_mut().unwrap()[7] = 2,
            2 => session.backend.wmm_reply.as_mut().unwrap()[22] = 3,
            3 => session.backend.wmm_reply.as_mut().unwrap()[14] |= 0x10,
            _ => bss.information_elements.extend_from_slice(&PARAMETERS),
        }
        let before = session.backend.frames.len();
        if run(session.associate_station(&bss, b"narf", Security::Open, test_permission(), &[]))
            .is_ok()
            || session.wmm.is_some()
            || matches!(session.state, State::Associated { .. })
            || session.backend.frames[before..]
                .iter()
                .any(|(_, frame)| command(frame, 0x1d))
            || case == 4 && session.backend.frames.len() != before
        {
            return TestResult::Fail("invalid/downgraded WMM published QoS or device writes");
        }
    }
    // A non-WMM scan profile never silently upgrades from unsolicited IEs.
    let (mut session, bss) = prepared(false, false);
    session.backend.wmm_reply = Some(PARAMETERS.to_vec());
    if run(session.associate_station(&bss, b"narf", Security::Open, test_permission(), &[]))
        != Ok(42)
        || session.wmm.is_some()
        || session
            .backend
            .frames
            .iter()
            .any(|(_, frame)| command(frame, 0x1d))
    {
        return TestResult::Fail("non-WMM legacy path was upgraded or blocked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_downgrade_malformed_and_unsolicited_responses
);

fn mt76_wmm_edca_cancellation_retains_owner_and_never_opens_port() -> TestResult {
    for fault in 1..=3 {
        let (mut failed, bss) = prepared(true, false);
        failed.backend.edca_progress_fault = fault;
        if run(failed.associate_station(&bss, b"narf", Security::Open, test_permission(), &[]))
            .is_ok()
            || !matches!(failed.state, State::Failed { .. })
            || failed.wmm.is_some()
            || !failed.backend.owner.published
            || failed.backend.frames.iter().any(|(_, frame)| {
                frame.len() >= 168
                    && frame[34..36] == [3, 0]
                    && frame[43] == 7
                    && frame[49] == 1
                    && frame[65] == 1
            })
        {
            return TestResult::Fail("malformed EDCA PSE progress published QoS peer or freed DMA");
        }
    }
    let (mut session, bss) = prepared(true, false);
    session.backend.stall_edca = true;
    {
        let mut future =
            pin!(session.associate_station(&bss, b"narf", Security::Open, test_permission(), &[]));
        let mut cx = Context::from_waker(Waker::noop());
        // Normal model replies complete synchronously; EDCA's outstanding
        // DMA is the first self-waking wait. Dropping this borrow retains it.
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("EDCA fixture did not suspend at device publication");
        }
    }
    if !matches!(session.state, State::Running(Stage::Associate))
        || !session.backend.owner.published
        || session.wmm.is_some()
        || session.security.is_some()
        || !session.backend.data_qos.is_empty()
        || !session
            .backend
            .frames
            .iter()
            .any(|(_, frame)| command(frame, 0x1d))
        || run(session.associate_station(&bss, b"narf", Security::Open, test_permission(), &[]))
            != Err(Error::Busy)
    {
        return TestResult::Fail("cancelled EDCA reused session or published authorized port");
    }
    let resources = session.backend.resources.clone();
    drop(session);
    if resources.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("cancelled EDCA released device-owned DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_edca_cancellation_retains_owner_and_never_opens_port
);

fn mt76_wmm_current_policy_gates_edca_and_each_data_publication() -> TestResult {
    let (mut baseline, bss) = prepared(true, false);
    let before = baseline.backend.frames.len();
    if run(baseline.associate_station(&bss, b"narf", Security::Open, test_permission(), &[]))
        != Ok(42)
    {
        return TestResult::Fail("policy baseline WMM join");
    }
    let Some(edca) = baseline
        .backend
        .frames
        .iter()
        .position(|(_, frame)| command(frame, 0x1d))
    else {
        return TestResult::Fail("policy baseline EDCA");
    };
    for limit in [before, edca, edca + 2] {
        let (mut session, bss) = prepared(true, false);
        session.backend.deny_tx_after = Some(limit);
        if run(session.associate_station(&bss, b"narf", Security::Open, test_permission(), &[]))
            != Err(Error::Authority)
            || session.wmm.is_some()
            || matches!(session.state, State::Associated { .. })
            || limit == before && session.backend.frames.len() != before
            || limit == edca
                && session
                    .backend
                    .frames
                    .iter()
                    .any(|(_, frame)| command(frame, 0x1d))
            || limit == edca + 2 && session.backend.frames.len() != limit
        {
            return TestResult::Fail("changed policy authorized preflight/EDCA/QoS peer");
        }
    }
    let mut eth = vec![0xff; 18];
    eth[6..12].copy_from_slice(&OWN);
    eth[12..14].copy_from_slice(&[8, 0]);
    baseline.backend.deny_tx_after = Some(baseline.backend.frames.len());
    let count = baseline.backend.frames.len();
    if baseline.start_ethernet(&eth) != Err(Error::Authority)
        || baseline.backend.frames.len() != count
        || !baseline.data_pending.is_empty()
    {
        return TestResult::Fail("changed policy published QoS data");
    }
    // Exercise the same ceiling/country/overlap predicate as the native
    // backend without mutating the shared signed regulatory registry.
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let mut domain = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    };
    let permission = test_permission();
    if !permission.current(&domain) {
        return TestResult::Fail("unchanged station power permission");
    }
    domain.rules[0].max_power_dbm = 16;
    if permission.current(&domain) {
        return TestResult::Fail("reduced power ceiling reused");
    }
    domain.rules[0].max_power_dbm = 18;
    domain.country_code = *b"GB";
    if permission.current(&domain) {
        return TestResult::Fail("changed station country reused");
    }
    domain.country_code = *b"US";
    domain.rules.push(RegRule {
        freq_start_mhz: 2435,
        freq_end_mhz: 2436,
        max_bandwidth_mhz: 20,
        max_power_dbm: 18,
        flags: RegFlags::NO_IR,
    });
    if permission.current(&domain) {
        return TestResult::Fail("restrictive overlapping NO_IR ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_current_policy_gates_edca_and_each_data_publication
);

fn mt76_wmm_bound_beacon_change_closes_port_and_preserves_qos_replay() -> TestResult {
    let (mut session, bss) = prepared(true, true);
    if run(session.associate_station(&bss, b"narf", security(true), test_permission(), &[]))
        != Ok(42)
    {
        return TestResult::Fail("WMM replay setup");
    }
    // Equal PN belongs to separate TIDs; replay of either cannot consume or
    // release the other's packet. Existing CCMP RX normalization is retained.
    for tid in [0u8, 3, 0, 3] {
        let mut packet = ccmp_packet(1, 0, false);
        packet[64] = tid;
        session.backend.packets.push_back(packet);
    }
    if session.receive_ethernet().ok().flatten().is_none()
        || session.receive_ethernet().ok().flatten().is_none()
        || session.receive_ethernet() != Ok(None)
    {
        return TestResult::Fail("negotiated WMM per-TID CCMP replay");
    }
    let mut beacon = session.backend.access_point.as_ref().unwrap().beacon();
    beacon.extend_from_slice(&PARAMETERS);
    let changed = beacon.len() - PARAMETERS.len() + 23;
    beacon[changed] = 0xb4; // BK CWmax changes from 1023 to 2047.
    let packet = |frame: &[u8]| {
        let mut packet = vec![0; 24];
        packet[..4].copy_from_slice(&((2u32 << 27) | (24 + frame.len()) as u32).to_le_bytes());
        packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
        packet.extend_from_slice(frame);
        packet
    };
    let mut foreign = beacon.clone();
    foreign[10] = 4;
    session.backend.packets.push_back(packet(&foreign));
    if session.receive_ethernet() != Ok(None) || session.peer_lost {
        return TestResult::Fail("foreign AP changed negotiated EDCA");
    }
    session.backend.packets.push_back(packet(&beacon));
    let mut eth = vec![0xff; 18];
    eth[6..12].copy_from_slice(&OWN);
    eth[12..14].copy_from_slice(&[8, 0]);
    let count = session.backend.frames.len();
    if session.receive_ethernet() != Err(Error::DeviceGone)
        || session.start_ethernet(&eth) != Err(Error::DeviceGone)
        || session.backend.frames.len() != count
        || run(session.disassociate_station()).is_err()
        || session.wmm.is_some()
    {
        return TestResult::Fail("changed bound AP EDCA retained port or replay authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_bound_beacon_change_closes_port_and_preserves_qos_replay
);

fn mt76_wmm_response_receipt_binds_peer_and_uses_updated_parameters() -> TestResult {
    let (_, bss) = prepared(true, false);
    let mut plan = JoinPlan::prepare(&bss, OWN, b"narf", Security::Open).unwrap();
    let reply = |subtype: u8, body: &[u8]| {
        let mut frame = vec![0; 24];
        frame[0] = subtype;
        frame[4..10].copy_from_slice(&OWN);
        frame[10..16].copy_from_slice(&AP);
        frame[16..22].copy_from_slice(&AP);
        frame.extend_from_slice(body);
        frame
    };
    plan.start_authentication().unwrap();
    let auth = reply(0xb0, &[0, 0, 2, 0, 0, 0]);
    if !plan
        .authentication_response(&auth)
        .unwrap()
        .unwrap()
        .ends_with(&[221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0])
    {
        return TestResult::Fail("driver-owned WMM information IE missing");
    }
    let mut response = reply(0x10, &[1, 0, 0, 0, 42, 0xc0, 1, 3, 0x8c, 0x98, 0xb0]);
    let mut updated = PARAMETERS;
    updated[23] = 0xb4;
    response.extend_from_slice(&updated);
    let mut foreign = response.clone();
    foreign[10] = 4;
    // A foreign reply with deliberately malformed WMM cannot cancel or
    // downgrade the still-pending bound association.
    *foreign.last_mut().unwrap() = 1;
    foreign[response.len() - PARAMETERS.len() + 7] = 2;
    if plan.association_response(&foreign) != Ok(None)
        || plan.association_response(&response) != Ok(Some(42))
        || plan.wmm() != Parameters::parse(&updated).unwrap()
    {
        return TestResult::Fail("WMM response peer binding or updated AP parameters");
    }
    let record = plan.peer_record(42, true).unwrap();
    if record[17] != 1 || record[93] != 1 || record[34] != 3 || record[40..44] != [1, 0, 16, 0] {
        return TestResult::Fail("WMM activated HT/changed legacy peer geometry");
    }
    plan.cancel();
    if plan.wmm().is_some() || plan.peer_record(42, true).is_ok() {
        return TestResult::Fail("cancelled WMM plan retained peer authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_response_receipt_binds_peer_and_uses_updated_parameters
);

fn current_policy() -> Arc<CurrentPolicy> {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let current = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: AtomicBool::new(false),
    });
    current.database.install(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    });
    current
}

fn mt76_wmm_cleared_live_policy_never_bootstraps_or_revives_old_grant() -> TestResult {
    let current = current_policy();
    // This owned pre-admission snapshot stands in for the still-staged
    // policy. Only the explicit installer below can put it back into the DB.
    let staged = current.database.snapshot().unwrap().as_ref().clone();
    let (mut session, bss) = prepared(true, true);
    session.backend.tx_policy = Some(current.clone());
    if run(session.associate_station(&bss, b"narf", security(true), test_permission(), &[]))
        != Ok(42)
    {
        return TestResult::Fail("live policy clear fixture did not negotiate WMM");
    }
    let before = session.backend.frames.len();
    let mut eth = vec![0xff; 18];
    eth[6..12].copy_from_slice(&OWN);
    eth[12..14].copy_from_slice(&[8, 0]);
    current.database.clear();
    if session.start_ethernet(&eth) != Err(Error::Authority)
        || current.database.snapshot().is_some()
        || !matches!(
            session.state,
            State::Failed {
                error: Error::Authority,
                ..
            }
        )
        || session.wmm.is_some()
        || session.station_permission.is_some()
        || session.security.is_some()
        || session.backend.frames.len() != before
        || !session.data_pending.is_empty()
        || !session.backend.owner.published
    {
        return TestResult::Fail(
            "cleared live policy was reloaded or preserved station TX authority",
        );
    }
    current.database.install(staged);
    if session.start_ethernet(&eth) != Err(Error::Busy)
        || session.backend.frames.len() != before
        || session.wmm.is_some()
        || run(session.associate_station(&bss, b"narf", security(true), test_permission(), &[]))
            != Err(Error::Busy)
    {
        return TestResult::Fail("explicit policy reinstall revived terminal station/WMM grant");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_cleared_live_policy_never_bootstraps_or_revives_old_grant
);

fn mt76_wmm_policy_loss_after_every_port_and_key_receipt_stops_next_publication() -> TestResult {
    for wpa2 in [false, true] {
        let (mut baseline, bss) = prepared(true, wpa2);
        if run(baseline.associate_station(&bss, b"narf", security(wpa2), test_permission(), &[]))
            != Ok(42)
        {
            return TestResult::Fail("post-receipt policy baseline");
        }
        let edca = baseline
            .backend
            .frames
            .iter()
            .position(|(_, frame)| command(frame, 0x1d))
            .unwrap();
        // Covers EDCA/PSE, connected QBSS, unauthorized/secure QoS peer,
        // group peer, M2/M4 and final PTK/GTK receipts. The fixture loses
        // policy as the prior command is published, before its receipt.
        for limit in edca + 2..=baseline.backend.frames.len() {
            let (mut session, bss) = prepared(true, wpa2);
            session.backend.deny_tx_after = Some(limit);
            if run(session.associate_station(&bss, b"narf", security(wpa2), test_permission(), &[]))
                != Err(Error::Authority)
                || session.backend.frames.len() != limit
                || session.wmm.is_some()
                || session.station_permission.is_some()
                || session.security.is_some()
                || !matches!(session.state, State::Failed { .. })
                || !session.backend.owner.published
            {
                return TestResult::Fail(
                    "post-await policy loss published another port/key command or readiness",
                );
            }
        }
    }
    // Also hold the connected QBSS ACK across actual future polls and
    // clear the isolated DB while waiting. Its receipt cannot authorize
    // publishing the next Open PORT_SECURE/QoS peer.
    let current = current_policy();
    current.hold_bss_ack.store(true, Ordering::SeqCst);
    let (mut session, bss) = prepared(true, false);
    session.backend.tx_policy = Some(current.clone());
    {
        let mut operation =
            pin!(session.associate_station(&bss, b"narf", Security::Open, test_permission(), &[]));
        let mut cx = Context::from_waker(Waker::noop());
        if operation.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("connected QBSS ACK did not suspend fixture");
        }
        current.database.clear();
        current.hold_bss_ack.store(false, Ordering::SeqCst);
        if operation.as_mut().poll(&mut cx) != Poll::Ready(Err(Error::Authority)) {
            return TestResult::Fail("cleared policy after held QBSS ACK was not terminal");
        }
    }
    if session.backend.frames.iter().any(|(_, frame)| {
        frame.len() >= 168
            && frame[34..36] == [3, 0]
            && frame[43] == 7
            && frame[49] == 1
            && frame[65] == 1
    }) || session.wmm.is_some()
        || session.station_permission.is_some()
    {
        return TestResult::Fail(
            "held QBSS receipt published an Open QoS secure peer after policy clear",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_policy_loss_after_every_port_and_key_receipt_stops_next_publication
);

fn mt76_wmm_rekey_reply_cannot_restore_authority_after_policy_loss() -> TestResult {
    let (mut session, bss) = prepared(true, true);
    if run(session.associate_station(&bss, b"narf", security(true), test_permission(), &[]))
        != Ok(42)
    {
        return TestResult::Fail("WMM rekey policy setup");
    }
    // The shared reactive AP covers the initial RSNA. Feed one peer-bound
    // rekey M1 through native RX, without inventing a rekey-capable AP model.
    session.backend.access_point = None;
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x56; 32];
    session
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol())));
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return TestResult::Fail("WMM native rekey M1 was not retained");
    }
    let before = session.backend.frames.len();
    session.backend.deny_tx_after = Some(before + 1);
    if run(session.service_keys()) != Err(Error::Authority)
        || session.backend.frames.len() != before + 1
        || session.security.is_some()
        || session.wmm.is_some()
        || session.station_permission.is_some()
        || !matches!(session.state, State::Failed { .. })
        || !session.backend.owner.published
    {
        return TestResult::Fail(
            "rekey M2 receipt restored old station authority after policy loss",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_rekey_reply_cannot_restore_authority_after_policy_loss
);

fn mt76_wmm_teardown_retires_host_grant_before_cancelled_or_uncertain_cleanup() -> TestResult {
    for cancel in [false, true] {
        let (mut session, bss) = prepared(true, true);
        if run(session.associate_station(&bss, b"narf", security(true), test_permission(), &[]))
            != Ok(42)
        {
            return TestResult::Fail("WMM teardown ownership fixture join");
        }
        if cancel {
            session.backend.tx_stall = true;
            {
                let mut operation = pin!(session.disassociate_station());
                if operation
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("WMM deauth did not hold device-owned completion");
                }
            }
            if !matches!(session.state, State::Running(Stage::StaRecord))
                || run(session.disassociate_station()) != Err(Error::Busy)
            {
                return TestResult::Fail("cancelled WMM teardown reopened/replayed station");
            }
        } else {
            session.backend.rx_stall = true;
            if run(session.disassociate_station()) != Err(Error::Timeout)
                || !matches!(session.state, State::Failed { .. })
            {
                return TestResult::Fail("WMM cleanup without native ACK became ready");
            }
        }
        if session.wmm.is_some()
            || session.station_permission.is_some()
            || session.security.is_some()
            || session.backend.access_point.is_some()
            || !session.backend.owner.published
            || session.start_ethernet(&[0; 14]) != Err(Error::Busy)
        {
            return TestResult::Fail("incomplete WMM teardown retained host grant or released DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_wmm_teardown_retires_host_grant_before_cancelled_or_uncertain_cleanup
);
