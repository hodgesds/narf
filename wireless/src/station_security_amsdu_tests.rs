use super::*;

const REMOTE: [u8; 6] = [2, 0, 0, 0, 0, 3];
const GROUP: [u8; 6] = [1, 0, 0x5e, 0, 0, 1];
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
    let mut header = vec![0x88, 0x42, 0, 0];
    header.extend_from_slice(&receiver);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&REMOTE);
    header.extend_from_slice(&[0, 0, 0x80 | tid, 0]);
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
