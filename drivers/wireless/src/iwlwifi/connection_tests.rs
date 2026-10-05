use super::super::{aggregation::Window, runtime::Packet, rx::RxPacketHeader};
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn connection() -> Connection {
    Connection {
        beacon: Beacon {
            bssid: [4; 6],
            ssid: b"test".to_vec(),
            channel: 36,
            interval: 100,
            dtim: 1,
            rsn: None,
            privacy: true,
            capabilities: 1,
            information_elements: Vec::new(),
        },
        local: [2; 6],
        management_queue: 1,
        data_queues: [None; 4],
        qos: None,
        sequence: 0,
        security: Some(security::Session::new(
            security::Akm::Wpa2Psk,
            [0; 32],
            [4; 6],
            [2; 6],
            [0; 32],
            Vec::new(),
        )),
        replay: frame_api::Replay::default(),
        authorized: true,
        last_beacon: 0,
        group_keys: [None; 4],
        pairwise_key: None,
        tx_antenna: 1,
        rates: super::super::rates::Rates::parse(&[1, 3, 0x8c, 0x98, 0xb0], 36).unwrap(),
        phy: super::super::ht_vht::Negotiated {
            mode: 1,
            center: 36,
            ..Default::default()
        },
        local_phy: super::super::ht_vht::Local::from_nvm(12, 3, 3),
        rx_ba: core::array::from_fn(|tid| {
            (tid == 0).then(|| Window::new(3, 0, 1, 100, 64, 0, 0).unwrap())
        }),
        actions: VecDeque::new(),
        mfp: narf_wireless::mfp::MfpKeyStore::new(),
        mfp_active: false,
    }
}

/// Wrap a raw 802.11 frame in the AX210 v3 MPDU envelope the RX parser
/// expects (status = RX-OK, no padding/trailer).
fn mgmt_mpdu_payload(frame: &[u8]) -> Vec<u8> {
    let mut p = alloc::vec![0u8; 64 + frame.len()];
    put16(&mut p, 0, frame.len() as u16);
    put32(&mut p, 12, 3); // status: CRC/overrun OK
    p[64..].copy_from_slice(frame);
    p
}

fn notification(cmd: u8, payload: Vec<u8>) -> Packet {
    Packet {
        header: RxPacketHeader {
            len_n_flags: payload.len() as u32 + 4,
            cmd,
            group_id: 0,
            sequence: 0x8000,
        },
        payload,
    }
}

fn data(sn: u16, nssn: u16, pn: u8) -> Packet {
    let mut p = alloc::vec![0; 108];
    put16(&mut p, 0, 44);
    put32(&mut p, 12, 0x243);
    put32(&mut p, 16, (3 << 24) | ((sn as u32) << 12) | nssn as u32);
    let f = &mut p[64..];
    f[..2].copy_from_slice(&[0x88, 0x42]);
    f[4..10].copy_from_slice(&[2; 6]);
    f[10..16].copy_from_slice(&[4; 6]);
    f[16..22].copy_from_slice(&[6; 6]);
    put16(f, 22, sn << 4);
    f[26] = pn;
    f[29] = 0x20;
    f[34..].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, sn as u8, 0]);
    notification(0xc1, p)
}

fn smoke_connection_reorders_only_authenticated_owned_frames() -> TestResult {
    let mut c = connection();
    assert!(c.receive_packet(&data(101, 100, 11)).unwrap().is_empty());
    // Neither a foreign transmitter, wrong TID nor a bad MIC may flush
    // the authenticated MPDU waiting behind sequence 100.
    for (offset, value) in [(74, 8), (88, 1), (12, 3)] {
        let mut bad = data(200, 201, 90);
        bad.payload[offset] = value;
        assert!(c.receive_packet(&bad).unwrap().is_empty());
    }
    let frames = c.receive_packet(&data(100, 102, 10)).unwrap();
    if frames.len() != 2
        || frames[0][14] != 100
        || frames[1][14] != 101
        || c.replay.pairwise[0] != 11
    {
        return TestResult::Fail("connection admission/reorder/PN ordering");
    }
    assert!(c.receive_packet(&data(103, 102, 13)).unwrap().is_empty());
    let wrong = notification(0xc2, alloc::vec![0x10, 0, 0, 0, 104, 0, 0, 3]);
    assert!(c.receive_packet(&wrong).unwrap().is_empty());
    let release = notification(0xc3, alloc::vec![3, 0, 104, 0]);
    if c.receive_packet(&release).unwrap().len() != 1 || c.replay.pairwise[0] != 13 {
        return TestResult::Fail("firmware release did not drain authenticated reorder queue");
    }
    assert!(c.receive_packet(&data(105, 104, 15)).unwrap().is_empty());
    c.discard_reorder();
    c.replay.reset_pairwise();
    let release = notification(0xc3, alloc::vec![3, 0, 106, 0]);
    if !c.receive_packet(&release).unwrap().is_empty() || c.replay.pairwise[0] != 0 {
        return TestResult::Fail("old-key reorder data survived key transition");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_connection_reorders_only_authenticated_owned_frames
);

fn smoke_connection_block_ack_actions_require_associated_ap() -> TestResult {
    let mut c = connection();
    let mut frame =
        frame_api::management(0xd0, [4; 6], [2; 6], 1, &[3, 0, 7, 2, 16, 0, 0, 0x40, 6]);
    frame[16..22].copy_from_slice(&[4; 6]);
    let mut bytes = alloc::vec![0; 64];
    put16(&mut bytes, 0, frame.len() as u16);
    put32(&mut bytes, 12, 3);
    bytes.extend_from_slice(&frame);
    let request = notification(0xc1, bytes);
    c.authorized = false;
    c.receive_packet(&request).unwrap();
    c.authorized = true;
    for (offset, value) in [(74, 8), (80, 8), (68, 8), (65, 0x40), (86, 1)] {
        let mut bad = request.clone();
        bad.payload[offset] = value;
        c.receive_packet(&bad).unwrap();
    }
    if !c.actions.is_empty() {
        return TestResult::Fail("foreign, protected or fragmented BA action admitted");
    }
    for _ in 0..20 {
        c.receive_packet(&request).unwrap();
    }
    if c.actions.len() != 16 {
        return TestResult::Fail("BA action queue not bounded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_connection_block_ack_actions_require_associated_ap
);

fn smoke_connection_stops_tx_when_ap_changes_ht_operation() -> TestResult {
    let mut c = connection();
    c.qos = Some(super::super::qos::Parameters::default());
    let mut ht = [0; 26];
    ht[..5].copy_from_slice(&[0x6e, 0, 0x13, 0xff, 0xff]);
    ht[15] = 1;
    let mut op = [0; 22];
    op[..2].copy_from_slice(&[36, 5]);
    let mut ies = alloc::vec![45, 26];
    ies.extend_from_slice(&ht);
    ies.extend_from_slice(&[61, 22]);
    ies.extend_from_slice(&op);
    c.phy =
        super::super::ht_vht::Negotiated::parse(c.local_phy, &ies, 36, true, |_, _| true).unwrap();
    let mut frame = frame_api::management(0x80, [4; 6], [4; 6], 0, &[0; 12]);
    frame[4..10].fill(0xff);
    frame.extend_from_slice(&ies);
    let mut bytes = alloc::vec![0; 64];
    put16(&mut bytes, 0, frame.len() as u16);
    put32(&mut bytes, 12, 3);
    bytes.extend_from_slice(&frame);
    let mut beacon = notification(0xc1, bytes);
    if c.receive_packet(&beacon).is_err() || !c.authorized {
        return TestResult::Fail("unchanged HT beacon closed controlled port");
    }
    beacon.payload[64 + 36 + 30 + 1] = 0; // AP switched to HT20
    if c.receive_packet(&beacon).is_ok() || c.authorized {
        return TestResult::Fail("TX remained authorized after AP narrowed HT operation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ht_vht",
    smoke_connection_stops_tx_when_ap_changes_ht_operation
);

// 802.11w: with MFP active, a group-addressed deauth is honored only when
// its BIP-CMAC MMIE verifies; a forged one is dropped (not a link teardown).
// An unprotected individually-addressed robust mgmt frame is also dropped.
fn smoke_connection_mfp_drops_forged_deauth() -> TestResult {
    let key = [0x5c; 16];
    // Build a BIP-signed broadcast deauth (A1 broadcast, A2/A3 = BSSID).
    let mut hdr = [0u8; 24];
    hdr[0] = 0xc0; // deauthentication
    hdr[4..10].copy_from_slice(&[0xff; 6]);
    hdr[10..16].copy_from_slice(&[4; 6]);
    hdr[16..22].copy_from_slice(&[4; 6]);
    let mut body = alloc::vec![3u8, 0]; // reason code 3
    let mut tx = narf_crypto::bip_cmac::Igtk::install(key, 4).unwrap();
    narf_wireless::mfp::protect_outbound(&mut tx, &hdr, &mut body).unwrap();
    let mut signed = hdr.to_vec();
    signed.extend_from_slice(&body);

    // Valid MMIE → honored (link torn down).
    let mut c = connection();
    c.mfp.install_active(key, 4).unwrap();
    c.mfp_active = true;
    let payload = mgmt_mpdu_payload(&signed);
    let mpdu = scan_api::mpdu(&payload).unwrap();
    match c.receive_frame(&mpdu) {
        Err("AP disconnected") if !c.authorized => {}
        _ => return TestResult::Fail("valid BIP-signed broadcast deauth was not honored"),
    }

    // Tampered MIC → dropped, link preserved.
    let mut c = connection();
    c.mfp.install_active(key, 4).unwrap();
    c.mfp_active = true;
    let mut forged = signed.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    let payload = mgmt_mpdu_payload(&forged);
    let mpdu = scan_api::mpdu(&payload).unwrap();
    match c.receive_frame(&mpdu) {
        Ok(None) if c.authorized => {}
        _ => return TestResult::Fail("forged broadcast deauth tore down the link"),
    }

    // Unprotected unicast deauth under MFP → dropped.
    let mut c = connection();
    c.mfp_active = true;
    let mut uni = [0u8; 26];
    uni[0] = 0xc0;
    uni[4..10].copy_from_slice(&[2; 6]); // A1 = our MAC
    uni[10..16].copy_from_slice(&[4; 6]);
    uni[16..22].copy_from_slice(&[4; 6]);
    let payload = mgmt_mpdu_payload(&uni);
    let mpdu = scan_api::mpdu(&payload).unwrap();
    match c.receive_frame(&mpdu) {
        Ok(None) if c.authorized => {}
        _ => return TestResult::Fail("unprotected unicast deauth honored under MFP"),
    }

    // Control: without MFP (WPA2), the same unicast deauth still disconnects.
    let mut c = connection();
    let payload = mgmt_mpdu_payload(&uni);
    let mpdu = scan_api::mpdu(&payload).unwrap();
    if c.receive_frame(&mpdu).is_ok() || c.authorized {
        return TestResult::Fail("non-MFP deauth should still tear down the link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/security",
    smoke_connection_mfp_drops_forged_deauth
);

// SAE anti-clogging (status 76): the STA echoes the AP-supplied token on the
// Commit retry. Cover both the H2E container element and the legacy inline form.
fn smoke_sae_anti_clogging_token_extract() -> TestResult {
    let token = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
    // H2E: ElementID 255 | len | ext 93 | token.
    let mut h2e = alloc::vec![0xff, (token.len() + 1) as u8, 93];
    h2e.extend_from_slice(&token);
    if extract_anti_clogging_token(&h2e).as_deref() != Some(&token[..]) {
        return TestResult::Fail("H2E container token not extracted");
    }
    // Legacy: the whole remaining body is the token.
    if extract_anti_clogging_token(&[1, 2, 3]).as_deref() != Some(&[1, 2, 3][..]) {
        return TestResult::Fail("legacy inline token not extracted");
    }
    if extract_anti_clogging_token(&[]).is_some() {
        return TestResult::Fail("empty body yielded a token");
    }
    // Container whose declared length overruns the buffer is rejected.
    if extract_anti_clogging_token(&[0xff, 0x40, 93, 1, 2]).is_some() {
        return TestResult::Fail("overrunning container accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/security",
    smoke_sae_anti_clogging_token_extract
);
