use super::*;

const REMOTE: [u8; 6] = [2, 0, 0, 0, 0, 3];
const GROUP: [u8; 6] = [1, 0, 0x5e, 0, 0, 1];

fn smoke_station_amsdu_block_ack_requires_explicit_raw_current_port_and_shared_key() -> TestResult {
    let p = ptk(AN, SN);
    for tid in 0..16 {
        let mut s = established();
        let (body, expected) = plaintext(OWN);
        let frame = aggregate_policy(OWN, tid, &p.tk, 1, 0, &body, 0xe0);
        let original = frame.bytes.clone();
        if s.receive_amsdu(&frame) != Ok(None)
            || s.receive(&frame, SN) != Ok(Rx::Ignored)
            || s.receive_amsdu_block_ack(&frame) != Ok(Some(expected))
            || s.receive_amsdu_block_ack(&frame) != Ok(None)
            || frame.bytes != original
            || !s.port_open()
        {
            return TestResult::Fail(
                "BlockAck aggregate opt-in/raw header/current key/one replay owner",
            );
        }
    }
    let (body, expected) = plaintext(OWN);
    let mut frame = aggregate_policy(OWN, 3, &p.tk, 1, 0, &body, 0xe0);
    if security().receive_amsdu_block_ack(&frame) != Err(Error::State) {
        return TestResult::Fail("BlockAck aggregate opened an unestablished port");
    }
    let mut s = established();
    frame.raw = false;
    if s.receive_amsdu_block_ack(&frame) != Ok(None) {
        return TestResult::Fail("BlockAck opt-in admitted a transformed native frame");
    }
    frame.raw = true;
    let repeated = key_frame(0x13ca, 3, AN, &kde(GTK), Some(&p));
    if s.receive(&mpdu(native(&repeated, false)), SN) != Ok(Rx::ReplyReady)
        || s.receive_amsdu_block_ack(&frame) != Err(Error::State)
    {
        return TestResult::Fail("BlockAck aggregate escaped a pending native reply/key receipt");
    }
    deliver(&mut s);
    if s.receive_amsdu_block_ack(&frame) != Ok(Some(expected)) {
        return TestResult::Fail("pending/raw BlockAck rejection consumed same-PN valid aggregate");
    }
    s.fail();
    if s.receive_amsdu_block_ack(&frame) != Err(Error::State) {
        return TestResult::Fail("BlockAck aggregate escaped a failed controlled port");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_amsdu_block_ack_requires_explicit_raw_current_port_and_shared_key
);
fn plaintext(receiver: [u8; 6]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut body = Vec::new();
    let mut expected = Vec::new();
    for (i, payload) in [&[1][..], &[2, 3][..]].into_iter().enumerate() {
        body.extend_from_slice(&receiver);
        body.extend_from_slice(&REMOTE);
        body.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
        body.extend_from_slice(payload);
        let mut frame = receiver.to_vec();
        frame.extend_from_slice(&REMOTE);
        frame.extend_from_slice(&[8, 0]);
        frame.extend_from_slice(payload);
        expected.push(frame);
        if i == 0 {
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
    }
    (body, expected)
}
fn aggregate(receiver: [u8; 6], tid: u8, tk: &[u8], pn: u64, id: u8, body: &[u8]) -> Mpdu {
    aggregate_policy(receiver, tid, tk, pn, id, body, 0x80)
}
fn aggregate_policy(
    receiver: [u8; 6],
    tid: u8,
    tk: &[u8],
    pn: u64,
    id: u8,
    body: &[u8],
    policy: u8,
) -> Mpdu {
    let mut header = vec![0x88, 0x42, 0, 0];
    header.extend_from_slice(&receiver);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&REMOTE);
    header.extend_from_slice(&[0, 0, policy | tid, 0]);
    let wire = crate::ccmp::protect(
        &Ccm,
        &header,
        tk.try_into().unwrap(),
        pn,
        id,
        tid,
        false,
        &mut body.to_vec(),
    )
    .unwrap();
    header.extend_from_slice(&wire);
    mpdu(header)
}
fn smoke_station_amsdu_opt_in_preserves_pairwise_group_tid_and_default_path() -> TestResult {
    let mut s = established();
    let p = ptk(AN, SN);
    for tid in 0..16 {
        for (receiver, tk, id, pn) in [(OWN, p.tk.as_slice(), 0, 1), (GROUP, &GTK[..], 2, 6)] {
            let (body, expected) = plaintext(receiver);
            let frame = aggregate(receiver, tid, tk, pn, id, &body);
            let original = frame.bytes.clone();
            if s.receive(&frame, SN) != Ok(Rx::Ignored)
                || s.receive_amsdu(&frame) != Ok(Some(expected))
                || s.receive_amsdu(&frame) != Ok(None)
                || frame.bytes != original
                || !s.port_open()
            {
                return TestResult::Fail("opt-in aggregate split existing path/key/TID replay");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_amsdu_opt_in_preserves_pairwise_group_tid_and_default_path
);

fn smoke_station_amsdu_raw_peer_header_and_atomic_tail_denial_preserve_valid_pn() -> TestResult {
    let p = ptk(AN, SN);
    let (body, expected) = plaintext(OWN);
    for case in 0..9 {
        let mut s = established();
        let mut malformed = body.clone();
        if case == 7 {
            malformed[24 + 14] ^= 1;
        }
        if case == 8 {
            malformed[24 + 20..24 + 22].copy_from_slice(&0x888eu16.to_be_bytes());
        }
        let mut frame = aggregate(OWN, 5, &p.tk, 1, 0, &malformed);
        match case {
            0 => frame.raw = false,
            1 => frame.bytes[10] ^= 2,
            2 => frame.bytes[4] ^= 2,
            3 => frame.bytes[24] ^= 0x80,
            4 => frame.bytes[24] ^= 1,
            5 => frame.bytes[1] &= !0x40,
            6 => {
                *frame.bytes.last_mut().unwrap() ^= 1;
            }
            _ => {}
        }
        let original = frame.bytes.clone();
        if s.receive_amsdu(&frame) != Ok(None)
            || frame.bytes != original
            || !s.port_open()
            || s.receive_amsdu(&aggregate(OWN, 5, &p.tk, 1, 0, &body)) != Ok(Some(expected.clone()))
        {
            return TestResult::Fail("rejected native aggregate consumed PN or closed live port");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_amsdu_raw_peer_header_and_atomic_tail_denial_preserve_valid_pn
);

fn smoke_station_amsdu_closed_and_pending_ports_do_not_consume_key_state() -> TestResult {
    let p = ptk(AN, SN);
    let (body, expected) = plaintext(OWN);
    let frame = aggregate(OWN, 3, &p.tk, 1, 0, &body);
    if security().receive_amsdu(&frame) != Err(Error::State) {
        return TestResult::Fail("aggregate admitted before terminal M4/key installation");
    }
    let mut s = established();
    let repeated = key_frame(0x13ca, 3, AN, &kde(GTK), Some(&p));
    if s.receive(&mpdu(native(&repeated, false)), SN) != Ok(Rx::ReplyReady) {
        return TestResult::Fail("aggregate pending-port fixture did not retain exact reply");
    }
    let pending = s.pending_frame().unwrap().to_vec();
    if s.receive_amsdu(&frame) != Err(Error::State) || s.pending_frame() != Some(pending.as_slice())
    {
        return TestResult::Fail("aggregate consumed reply/key state while port closed");
    }
    deliver(&mut s);
    if s.receive_amsdu(&frame) != Ok(Some(expected)) || s.history.len() != 2 {
        return TestResult::Fail("pending aggregate denial consumed PN or reinstalled keys");
    }
    s.fail();
    if s.receive_amsdu(&frame) != Err(Error::State) {
        return TestResult::Fail("failed station admitted aggregate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_amsdu_closed_and_pending_ports_do_not_consume_key_state
);

fn smoke_station_amsdu_group_zero_and_rsc_keep_pairwise_slots_independent() -> TestResult {
    let mut s = established();
    let p = ptk(AN, SN);
    let next_gtk = [0x7d; 16];
    let mut data = kde(next_gtk);
    data[28] = 0; // Authenticated GTK KeyID0, distinct from PTK KeyID0.
    let group = key_frame(0x1382, 3, [0; 32], &data, Some(&p));
    if s.receive(&mpdu(encrypt(&native(&group, false), &p.tk, 1, 0)), SN) != Ok(Rx::ReplyReady) {
        return TestResult::Fail("aggregate group0 rekey fixture failed");
    }
    deliver(&mut s);
    let (body, expected) = plaintext(GROUP);
    if s.receive_amsdu(&aggregate(GROUP, 0, &next_gtk, 5, 0, &body)) != Ok(None)
        || s.receive_amsdu(&aggregate(GROUP, 0, &next_gtk, 6, 0, &body))
            != Ok(Some(expected.clone()))
        || s.receive_amsdu(&aggregate(GROUP, 0, &GTK, 6, 2, &body)) != Ok(Some(expected))
    {
        return TestResult::Fail("aggregate GTK0 ignored RSC or poisoned retained GTK2");
    }
    let (body, expected) = plaintext(OWN);
    if s.receive_amsdu(&aggregate(OWN, 0, &next_gtk, 1, 0, &body)) != Ok(None)
        || s.receive_amsdu(&aggregate(OWN, 0, &p.tk, 1, 0, &body)) != Ok(Some(expected))
    {
        return TestResult::Fail("GTK0 material aliased pairwise aggregate ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_amsdu_group_zero_and_rsc_keep_pairwise_slots_independent
);

fn smoke_station_amsdu_pairwise_rekey_stays_old_until_exact_m4_receipt() -> TestResult {
    let mut s = established();
    let old = ptk(AN, SN);
    let fresh = ptk([0x33; 32], [0x44; 32]);
    let (body, expected) = plaintext(OWN);
    s.receive(
        &mpdu(encrypt(
            &native(&key_frame(0x8a, 3, [0x33; 32], &[], None), false),
            &old.tk,
            1,
            0,
        )),
        [0x44; 32],
    )
    .unwrap();
    let old_packet = aggregate(OWN, 4, &old.tk, 1, 0, &body);
    if s.receive_amsdu(&old_packet) != Err(Error::State) {
        return TestResult::Fail("aggregate admitted before retained M2 receipt");
    }
    deliver(&mut s);
    if s.receive_amsdu(&old_packet) != Ok(Some(expected.clone()))
        || s.receive_amsdu(&aggregate(OWN, 4, &fresh.tk, 2, 0, &body)) != Ok(None)
    {
        return TestResult::Fail("aggregate installed new pairwise key before M3/M4");
    }
    let message3 = key_frame(0x13ca, 4, [0x33; 32], &kde([0x7d; 16]), Some(&fresh));
    s.receive(
        &mpdu(encrypt(&native(&message3, false), &old.tk, 2, 0)),
        [0x44; 32],
    )
    .unwrap();
    let new_packet = aggregate(OWN, 4, &fresh.tk, 1, 0, &body);
    if s.receive_amsdu(&new_packet) != Err(Error::State) {
        return TestResult::Fail("aggregate admitted before retained M4 receipt");
    }
    deliver(&mut s);
    if s.receive_amsdu(&aggregate(OWN, 4, &old.tk, 2, 0, &body)) != Ok(None)
        || s.receive_amsdu(&new_packet) != Ok(Some(expected))
        || s.receive_amsdu(&new_packet) != Ok(None)
        || s.history.len() != 4
    {
        return TestResult::Fail("aggregate did not bind new key epoch to terminal M4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_amsdu_pairwise_rekey_stays_old_until_exact_m4_receipt
);

fn station_frame(da: [u8; 6], protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = da.to_vec();
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&protocol.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn smoke_station_amsdu_transmit_is_port_bound_and_consumes_one_sn() -> TestResult {
    let a = station_frame(REMOTE, 0x800, &[0x45, 1, 2]);
    let b = station_frame(GROUP, 0x86dd, &[6; 40]);
    let limit = crate::amsdu::Limit::Ht3839;
    if security().transmit_amsdu_qos(&[&a, &b], 3, limit) != Err(Error::State) {
        return TestResult::Fail("A-MSDU TX escaped a closed controlled port");
    }
    let mut s = established();
    let p = ptk(AN, SN);
    for tid in [0u8, 3, 15] {
        let sequence = s.next_qos_sequence(tid).unwrap();
        let Ok(frame) = s.transmit_amsdu_qos(&[&a, &b], tid, limit) else {
            return TestResult::Fail("established station refused a valid A-MSDU");
        };
        let header = &frame[..26];
        let mut wire = frame[26..].to_vec();
        let mut replay = crate::ccmp::ReplayWindow::default();
        let plain = crate::ccmp::unprotect(
            &Ccm,
            header,
            p.tk.as_slice().try_into().unwrap(),
            tid,
            false,
            &mut replay,
            &mut wire,
        );
        let expected = crate::amsdu::encode(&[&a, &b], OWN, limit).unwrap();
        if header[..2] != [0x88, 0x41]
            || header[4..10] != AP
            || header[10..16] != OWN
            || header[16..22] != AP
            || header[22..24] != (sequence << 4).to_le_bytes()
            || header[24..] != [0x80 | tid, 0]
            || plain != Ok(expected)
            || s.next_qos_sequence(tid) != Ok((sequence + 1) & 4095)
        {
            return TestResult::Fail("A-MSDU TX header/CCMP/SN differs");
        }
    }
    let eapol = station_frame(AP, 0x888e, &[1]);
    let mut foreign = a.clone();
    foreign[6..12].copy_from_slice(&REMOTE);
    let before = s.next_qos_sequence(3).unwrap();
    if s.transmit_amsdu_qos(&[&a, &eapol], 3, limit) != Err(Error::Profile)
        || s.transmit_amsdu_qos(&[&foreign], 3, limit) != Err(Error::Profile)
        || s.transmit_amsdu_qos(&[&a], 16, limit) != Err(Error::Profile)
        || s.transmit_amsdu_qos(&[], 3, limit) != Err(Error::Profile)
        || s.next_qos_sequence(3) != Ok(before)
        || !s.port_open()
    {
        return TestResult::Fail("rejected A-MSDU TX consumed an SN or closed the port");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_amsdu_transmit_is_port_bound_and_consumes_one_sn
);

fn smoke_station_amsdu_receive_with_reports_noack_group_and_eosp() -> TestResult {
    use crate::packet_key::{AckPolicy, AmsduAdmission, AmsduReceive};
    let mut s = established();
    let (body, expected) = plaintext(GROUP);
    let frame = aggregate_policy(GROUP, 2, &GTK, 6, 2, &body, 0xa0);
    if s.receive_amsdu(&frame) != Ok(None)
        || s.receive_amsdu_with(&frame, AmsduAdmission::new().with_no_ack(true))
            != Ok(Some(AmsduReceive {
                frames: expected,
                tid: 2,
                ack_policy: AckPolicy::NoAck,
                eosp: false,
            }))
    {
        return TestResult::Fail("group No Ack aggregate not explicit or lost facts");
    }
    let p = ptk(AN, SN);
    let (body, expected) = plaintext(OWN);
    let frame = aggregate_policy(OWN, 6, &p.tk, 1, 0, &body, 0x90);
    if s.receive_amsdu(&frame) != Ok(None)
        || s.receive_amsdu_with(&frame, AmsduAdmission::new().with_no_ack(true)) != Ok(None)
        || s.receive_amsdu_with(&frame, AmsduAdmission::new().with_eosp(true))
            != Ok(Some(AmsduReceive {
                frames: expected,
                tid: 6,
                ack_policy: AckPolicy::Normal,
                eosp: true,
            }))
    {
        return TestResult::Fail("EOSP aggregate not explicit or lost its bit");
    }
    let mut closed = security();
    if closed.receive_amsdu_with(&frame, AmsduAdmission::new().with_eosp(true)) != Err(Error::State)
    {
        return TestResult::Fail("explicit admission escaped the controlled port");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_amsdu_receive_with_reports_noack_group_and_eosp
);

fn spp_rsne(capabilities: u16) -> Vec<u8> {
    let mut rsne = crate::rsn::RsnIe::wpa2_psk_ccmp();
    rsne.rsn_capabilities = capabilities;
    rsne.encode_body()
}

fn established_spp(ap_rsne: &[u8]) -> Security {
    let spp = crate::rsn::RSN_CAP_SPP_AMSDU_CAPABLE;
    let mut s = Security::new(OWN, AP, &PMK, &spp_rsne(spp), ap_rsne, None, 2).unwrap();
    let p = ptk(AN, SN);
    assert_eq!(
        s.receive(&mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false)), SN),
        Ok(Rx::ReplyReady)
    );
    deliver(&mut s);
    let mut kde = ie(48, ap_rsne).unwrap();
    kde.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, 2, 0]);
    kde.extend_from_slice(&GTK);
    assert_eq!(
        s.receive(
            &mpdu(native(&key_frame(0x13ca, 2, AN, &kde, Some(&p)), false)),
            SN
        ),
        Ok(Rx::ReplyReady)
    );
    deliver(&mut s);
    s
}

fn spp_aggregate(tid: u8, tk: &[u8], pn: u64, body: &[u8]) -> Mpdu {
    let mut header = vec![0x88, 0x42, 0, 0];
    header.extend_from_slice(&OWN);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&REMOTE);
    header.extend_from_slice(&[0, 0, 0x80 | tid, 0]);
    let wire = crate::ccmp::protect_spp_amsdu(
        &Ccm,
        &header,
        tk.try_into().unwrap(),
        pn,
        0,
        tid,
        &mut body.to_vec(),
    )
    .unwrap();
    header.extend_from_slice(&wire);
    mpdu(header)
}

fn smoke_station_spp_amsdu_negotiates_from_both_rsnes_and_binds_pairwise_aad() -> TestResult {
    use crate::rsn::{RSN_CAP_MFP_CAPABLE, RSN_CAP_SPP_AMSDU_CAPABLE, RSN_CAP_SPP_AMSDU_REQUIRED};
    let spp = RSN_CAP_SPP_AMSDU_CAPABLE;
    let new = |station: u16, ap: u16| {
        Security::new(OWN, AP, &PMK, &spp_rsne(station), &spp_rsne(ap), None, 2)
            .map(|s| s.spp_amsdu())
    };
    if new(0, 0) != Ok(false)
        || new(spp, 0) != Ok(false)
        || new(0, spp) != Ok(false)
        || new(spp, spp | RSN_CAP_SPP_AMSDU_REQUIRED) != Ok(true)
        || new(spp, spp) != Ok(true)
        || new(spp | RSN_CAP_SPP_AMSDU_REQUIRED, spp).is_ok()
        // WPA2 PMF: MFPC alone is optional PMF (not in force without the
        // AP's MFPC); MFPR without MFPC is malformed.
        || new(RSN_CAP_MFP_CAPABLE, 0) != Ok(false)
        || new(crate::rsn::RSN_CAP_MFP_REQUIRED, 0).is_ok()
    {
        return TestResult::Fail("SPP A-MSDU was not the exact two-RSNE intersection");
    }
    let p = ptk(AN, SN);
    let (body, expected) = plaintext(OWN);
    let mut s = established_spp(&spp_rsne(spp));
    let ordinary = aggregate(OWN, 1, &p.tk, 1, 0, &body);
    let protected = spp_aggregate(1, &p.tk, 1, &body);
    if !s.spp_amsdu()
        || s.receive_amsdu(&ordinary) != Ok(None)
        || s.receive_amsdu(&protected) != Ok(Some(expected.clone()))
    {
        return TestResult::Fail("negotiated SPP pairwise receive used the masked AAD");
    }
    let (group_body, group_expected) = plaintext(GROUP);
    if s.receive_amsdu(&aggregate(GROUP, 1, &GTK, 6, 2, &group_body)) != Ok(Some(group_expected)) {
        return TestResult::Fail("SPP changed group-key aggregate AAD");
    }
    let a = station_frame(REMOTE, 0x800, &[1, 2, 3]);
    let frame = s
        .transmit_amsdu_qos(&[&a], 0, crate::amsdu::Limit::Ht3839)
        .unwrap();
    let tk: &[u8; 16] = p.tk.as_slice().try_into().unwrap();
    let mut replay = crate::ccmp::ReplayWindow::default();
    if crate::ccmp::unprotect(
        &Ccm,
        &frame[..26],
        tk,
        0,
        false,
        &mut replay,
        &mut frame[26..].to_vec(),
    )
    .is_ok()
        || crate::ccmp::unprotect_spp_amsdu(
            &Ccm,
            &frame[..26],
            tk,
            0,
            &mut replay,
            &mut frame[26..].to_vec(),
        )
        .is_err()
    {
        return TestResult::Fail("SPP A-MSDU TX did not authenticate A-MSDU Present");
    }
    let mut plain = established();
    if plain.spp_amsdu() || plain.receive_amsdu(&spp_aggregate(1, &p.tk, 1, &body)) != Ok(None) {
        return TestResult::Fail("non-SPP association accepted an SPP aggregate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security/amsdu",
    smoke_station_spp_amsdu_negotiates_from_both_rsnes_and_binds_pairwise_aad
);
