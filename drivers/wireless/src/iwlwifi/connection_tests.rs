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
        receive_epoch: 0,
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
    p[42] = 36;
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
        receive_epoch: Some(0),
    }
}

fn data(sn: u16, nssn: u16, pn: u8) -> Packet {
    let mut p = alloc::vec![0; 108];
    put16(&mut p, 0, 44);
    put32(&mut p, 12, 0x243);
    put32(&mut p, 16, (3 << 24) | ((sn as u32) << 12) | nssn as u32);
    p[42] = 36;
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

fn smoke_connection_original_closed_or_old_epoch_never_advances_reorder_or_pn() -> TestResult {
    let mut c = connection();
    for epoch in [None, Some(1)] {
        let mut original = data(100, 101, 10);
        original.receive_epoch = epoch;
        if !c.receive_packet(&original).unwrap().is_empty() || c.replay.pairwise[0] != 0 {
            return TestResult::Fail("closed/foreign capture altered current reorder/PN");
        }
    }
    if c.receive_packet(&data(100, 101, 10)).unwrap().len() != 1 || c.replay.pairwise[0] != 10 {
        return TestResult::Fail("old native capture consumed valid successor sequence/PN");
    }
    let old = data(102, 102, 12);
    c.receive_epoch = 2;
    c.discard_reorder();
    if !c.receive_packet(&old).unwrap().is_empty() || c.replay.pairwise[0] != 10 {
        return TestResult::Fail("saved original MPDU inherited a later key epoch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/aggregation",
    smoke_connection_original_closed_or_old_epoch_never_advances_reorder_or_pn
);

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
    bytes[42] = 36;
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
    bytes[42] = 36;
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

// 802.11w TX: protect_group_mgmt appends a BIP-CMAC-128 MMIE under the
// active IGTK; an independent key store verifies and strips it. Refused
// when MFP is inactive. (AP/mesh-side emission; station mode never calls it.)
fn smoke_connection_protect_group_mgmt_roundtrips() -> TestResult {
    let key = [0x3c; 16];
    let mut c = connection();
    c.mfp.install_active(key, 4).unwrap();
    c.mfp_active = true;
    // Group-addressed deauth we (as an AP) would emit: A1 broadcast.
    let mut hdr = [0u8; 24];
    hdr[0] = 0xc0;
    hdr[4..10].copy_from_slice(&[0xff; 6]);
    hdr[10..16].copy_from_slice(&c.local);
    hdr[16..22].copy_from_slice(&c.local);
    let mut body = alloc::vec![3u8, 0];
    let ipn = match c.protect_group_mgmt(&hdr, &mut body) {
        Ok(ipn) => ipn,
        Err(e) => return TestResult::Fail(e),
    };
    if ipn == 0 {
        return TestResult::Fail("IPN must be stamped nonzero");
    }
    let mut rx = narf_wireless::mfp::MfpKeyStore::new();
    rx.install_active(key, 4).unwrap();
    match narf_wireless::mfp::verify_inbound(&mut rx, &hdr, &body) {
        Ok(stripped) if stripped == [3u8, 0] => {}
        _ => return TestResult::Fail("protected group mgmt frame did not verify"),
    }
    // Refused without MFP active.
    let mut plain = connection();
    let mut body2 = alloc::vec![3u8, 0];
    if plain.protect_group_mgmt(&hdr, &mut body2).is_ok() {
        return TestResult::Fail("protect_group_mgmt succeeded without MFP active");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/security",
    smoke_connection_protect_group_mgmt_roundtrips
);

struct NativeBa {
    hardware: Option<super::super::runtime::Hardware>,
    firmware: super::super::runtime::model::Firmware,
    trace: super::super::runtime::model::TxTrace,
}
impl Drop for NativeBa {
    fn drop(&mut self) {
        if let Some(hw) = self.hardware.take() {
            // SAFETY: private RAM-only DMA endpoints; all test futures have ended,
            // and no physical PCI device or independent device actor is present.
            unsafe { super::super::runtime::model::destroy(hw) };
        }
    }
}
fn native_poll<T>(
    f: core::pin::Pin<&mut impl core::future::Future<Output = T>>,
) -> core::task::Poll<T> {
    let result = f.poll(&mut core::task::Context::from_waker(
        core::task::Waker::noop(),
    ));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
impl NativeBa {
    fn new() -> Self {
        let (mut hardware, firmware, trace) =
            super::super::runtime::model::station_model_for_format(
                super::super::rx_rfh::CompletionFormat::Bz,
            );
        super::super::runtime::model::versions(
            &mut hardware,
            &[0x17, 5, 3, 0, 0x16, 5, 2, 0, 2, 5, 1, 0],
        );
        Self {
            hardware: Some(hardware),
            firmware,
            trace,
        }
    }
    fn management_queue(&mut self) -> Result<(), &'static str> {
        let mut f = core::pin::pin!(self.hardware.as_mut().unwrap().allocate_tx(0, 15));
        if !native_poll(f.as_mut()).is_pending() {
            return Err("native BA management ADD missing");
        }
        self.trace.take().ok_or("management ADD trace absent")?;
        self.firmware.inject(0x17, 5, 0, &[1, 0, 0, 0, 0, 0, 0, 0]);
        if !matches!(native_poll(f.as_mut()), core::task::Poll::Ready(Ok(1))) {
            return Err("management ADD native receipt failed");
        }
        Ok(())
    }
}
fn ba_marker(cookie: u32) -> Vec<u8> {
    let mut b = alloc::vec![12, 0, 0, 0, 1, 0, 0, 0];
    b.extend_from_slice(&cookie.to_le_bytes());
    b.extend_from_slice(&3u32.to_le_bytes());
    b
}
fn smoke_connection_native_baid_remove_waits_for_marker_and_preserves_peer_loss() -> TestResult {
    let test = || -> Result<(), &'static str> {
        for (loss, foreign) in [(false, false), (true, false), (false, true)] {
            let mut t = NativeBa::new();
            let mut c = connection();
            assert!(c.receive_packet(&data(101, 100, 11))?.is_empty());
            {
                let mut remove = core::pin::pin!(c.stop_rx_ba(t.hardware.as_mut().unwrap(), 0));
                if !native_poll(remove.as_mut()).is_pending() {
                    return Err("native BAID removal skipped receipt");
                }
                let p = t.trace.take().ok_or("BAID remove trace absent")?;
                if p.bytes[7] != 0
                    || p.bytes[8..] != [2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                {
                    return Err("ML BAID v2 removal payload/header");
                }
                t.firmware.inject(0x16, 5, 0, &[255, 255, 255, 255]); // ADD-only returned ID ignored.
                if !native_poll(remove.as_mut()).is_pending() {
                    return Err("BAID REMOVE ACK freed host window before marker");
                }
                let p = t.trace.take().ok_or("BAID marker command absent")?;
                if p.bytes[8..]
                    != [
                        0, 0, 0, 0, 1, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0,
                    ]
                {
                    return Err("MLD BAID marker bytes");
                }
                if loss || foreign {
                    let mut frame =
                        frame_api::management(0xc0, [4; 6], [2; 6], 0, &3u16.to_le_bytes());
                    frame[16..22].copy_from_slice(&[4; 6]);
                    let mut payload = mgmt_mpdu_payload(&frame);
                    if foreign {
                        payload[42] = 40;
                    }
                    t.firmware.inject(0xc1, 0, 0x8000, &payload);
                }
                t.firmware.inject(2, 5, 1, &[]);
                if !native_poll(remove.as_mut()).is_pending() {
                    return Err("RX marker command ACK retired native session");
                }
                t.firmware.inject(0xff, 5, 0x8000, &ba_marker(1));
                let result = native_poll(remove.as_mut());
                if loss {
                    if !matches!(result, core::task::Poll::Ready(Err("AP disconnected"))) {
                        return Err("retirement swallowed current AP disconnect");
                    }
                } else if !matches!(result, core::task::Poll::Ready(Ok(()))) {
                    return Err("exact BAID/RX marker failed to retire host session");
                }
            }
            if c.replay.pairwise[0] != 0 || loss && c.authorized || !loss && c.rx_ba[0].is_some() {
                return Err("retired reorder prefix leaked PN/session or peer-loss authorization");
            }
        }
        Ok(())
    };
    test().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/connection",
    smoke_connection_native_baid_remove_waits_for_marker_and_preserves_peer_loss
);
fn smoke_connection_native_baid_cancelled_remove_cannot_replay_or_deliver_prefix() -> TestResult {
    let test = || -> Result<(), &'static str> {
        let mut t = NativeBa::new();
        let mut c = connection();
        assert!(c.receive_packet(&data(101, 100, 11))?.is_empty());
        {
            let mut f = core::pin::pin!(c.stop_rx_ba(t.hardware.as_mut().unwrap(), 0));
            if !native_poll(f.as_mut()).is_pending() {
                return Err("cancelled BAID removal was not published");
            }
        }
        t.trace.take().ok_or("cancelled BAID command absent")?;
        if !c.receive_packet(&data(100, 102, 10))?.is_empty() || c.replay.pairwise[0] != 0 {
            return Err("cancelled native removal released reorder/PN prefix");
        }
        {
            let mut f = core::pin::pin!(c.stop_rx_ba(t.hardware.as_mut().unwrap(), 0));
            if !matches!(native_poll(f.as_mut()), core::task::Poll::Ready(Err(_))) {
                return Err("cancelled native BAID removal replayed");
            }
        }
        if t.trace.take().is_some() {
            return Err("second native BAID removal producer");
        }
        Ok(())
    };
    test().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/connection",
    smoke_connection_native_baid_cancelled_remove_cannot_replay_or_deliver_prefix
);
fn smoke_connection_native_addba_response_completion_precedes_reorder_admission() -> TestResult {
    let test = || -> Result<(), &'static str> {
        for complete in [false, true] {
            let mut t = NativeBa::new();
            t.management_queue()?;
            let mut c = connection();
            let mut frame =
                frame_api::management(0xd0, [4; 6], [2; 6], 0, &[3, 0, 9, 0xc6, 0, 0, 0, 0x40, 6]);
            frame[16..22].copy_from_slice(&[4; 6]);
            c.receive_packet(&notification(0xc1, mgmt_mpdu_payload(&frame)))?;
            let response_pointer;
            {
                let mut f = core::pin::pin!(c.service_aggregation(t.hardware.as_mut().unwrap()));
                if !native_poll(f.as_mut()).is_pending() {
                    return Err("ADDBA skipped native BAID allocation");
                }
                let p = t.trace.take().ok_or("ADDBA allocation absent")?;
                if p.bytes[8..] != [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 100, 0, 3, 0] {
                    return Err("native ADD BAID did not bind requested TID/SSN/window");
                }
                t.firmware.inject(0x16, 5, 1, &[7, 0, 0, 0]);
                if !native_poll(f.as_mut()).is_pending() {
                    return Err("positive ADDBA did not wait actual packet completion");
                }
                let p = t
                    .trace
                    .take()
                    .ok_or("positive native ADDBA response absent")?;
                if p.bytes.get(56..) != Some(&[3, 1, 9, 0, 0, 0xc6, 0, 0, 0]) {
                    return Err("native ADDBA positive dialog/SSN/window binding");
                }
                response_pointer = p.pointer;
                if complete {
                    t.firmware.tx_complete(1, p.pointer);
                    if !matches!(native_poll(f.as_mut()), core::task::Poll::Ready(Ok(()))) {
                        return Err("positive native response failed activation");
                    }
                }
            }
            let mut packet = data(100, 101, 10);
            packet.payload[88] = 1;
            put32(&mut packet.payload, 16, 7 << 24 | 100 << 12 | 101);
            let frames = c.receive_packet(&packet)?;
            if complete {
                if frames.len() != 1 || c.replay.pairwise[1] != 10 {
                    return Err("terminal ADDBA did not activate correct native BAID/TID");
                }
            } else {
                if !frames.is_empty() || c.replay.pairwise[1] != 0 {
                    return Err("cancelled response prematurely activated receive/replay");
                }
                t.firmware.tx_complete(1, response_pointer);
                t.hardware.as_mut().unwrap().poll()?;
                if !c.receive_packet(&packet)?.is_empty() || c.replay.pairwise[1] != 0 {
                    return Err("late positive TX receipt reconstructed a lost BA response owner");
                }
                c.receive_packet(&notification(0xc1, mgmt_mpdu_payload(&frame)))?;
                let mut f = core::pin::pin!(c.service_aggregation(t.hardware.as_mut().unwrap()));
                if !matches!(native_poll(f.as_mut()), core::task::Poll::Ready(Err(_))) {
                    return Err("late duplicate dialog reconstructed unproved positive response");
                }
            }
        }
        Ok(())
    };
    test().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/connection",
    smoke_connection_native_addba_response_completion_precedes_reorder_admission
);
