use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];
const REMOTE: [u8; 6] = [2, 0, 0, 0, 0, 3];
const GROUP: [u8; 6] = [1, 0, 0x5e, 0, 0, 1];

fn smoke_ccmp_amsdu_block_ack_is_explicit_original_header_and_one_replay_owner() -> TestResult {
    let tk = [0x55; 16];
    for tid in 0..16 {
        let mut h = header(LOCAL, tid);
        h[24] |= 0x60;
        let original_header = h.clone();
        let (body, expected) = plaintext(LOCAL);
        let wire = seal(&h, &body, &tk, 6, 0);
        let original = wire.clone();
        let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 5).unwrap();
        if key.unprotect_amsdu(&h, &wire) != Err(Error::Header)
            || key.unprotect(&h, &mut wire.clone()) != Err(Error::Header)
            || key.receive[usize::from(tid)].last_seen_pn != 5
            || key.unprotect_amsdu_block_ack(&h, &wire) != Ok(expected)
            || h != original_header
            || wire != original
            || key.receive[usize::from(tid)].last_seen_pn != 6
        {
            return TestResult::Fail(
                "BlockAck aggregate default opt-in/header/ciphertext/atomic PN",
            );
        }
        let normal = header(LOCAL, tid);
        if key.unprotect_amsdu(&normal, &seal(&normal, &body, &tk, 6, 0))
            != Err(Error::Crypto(CcmpError::Replay))
            || key.unprotect_amsdu_block_ack(&h, &wire) != Err(Error::Crypto(CcmpError::Replay))
        {
            return TestResult::Fail(
                "normal/BlockAck aggregate methods split the same key/TID replay owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/amsdu",
    smoke_ccmp_amsdu_block_ack_is_explicit_original_header_and_one_replay_owner
);

fn smoke_ccmp_amsdu_block_ack_invalid_policy_group_and_tail_keep_pn() -> TestResult {
    let tk = [0x55; 16];
    let (body, expected) = plaintext(LOCAL);
    for policy in [0x60, 0x90, 0xa0, 0xc0, 0xf0] {
        let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 5).unwrap();
        let mut h = header(LOCAL, 3);
        h[24] = policy | 3;
        let wire = seal(&h, &body, &tk, MAX_PN, 0);
        if key.unprotect_amsdu_block_ack(&h, &wire) != Err(Error::Header)
            || key.receive.iter().any(|tracker| tracker.last_seen_pn != 5)
        {
            return TestResult::Fail(
                "BlockAck opt-in admitted EOSP/NoAck/NoExplicitAck/no aggregate",
            );
        }
    }
    let mut h = header(LOCAL, 3);
    h[24] |= 0x60;
    for mic_failure in [false, true] {
        let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 5).unwrap();
        let mut bad = body.clone();
        if !mic_failure {
            bad.pop();
        }
        let mut wire = seal(&h, &bad, &tk, MAX_PN, 0);
        if mic_failure {
            *wire.last_mut().unwrap() ^= 1;
        }
        let original = wire.clone();
        if key.unprotect_amsdu_block_ack(&h, &wire).is_ok()
            || wire != original
            || key.receive.iter().any(|tracker| tracker.last_seen_pn != 5)
            || key.unprotect_amsdu_block_ack(&h, &seal(&h, &body, &tk, 6, 0))
                != Ok(expected.clone())
        {
            return TestResult::Fail(
                "bad BlockAck aggregate MIC/tail consumed replay or exposed a prefix",
            );
        }
    }
    let mut key = Key::new(&tk, 2, Role::Group, LOCAL, PEER, 5).unwrap();
    let mut h = header(GROUP, 3);
    h[24] |= 0x60;
    let (body, expected) = plaintext(GROUP);
    if key.unprotect_amsdu_block_ack(&h, &seal(&h, &body, &tk, 6, 2)) != Err(Error::Header) {
        return TestResult::Fail("unicast BlockAck opt-in invented group-addressed BA");
    }
    let normal = header(GROUP, 3);
    if key.unprotect_amsdu(&normal, &seal(&normal, &body, &tk, 6, 2)) != Ok(expected) {
        return TestResult::Fail("multicast BlockAck rejection consumed current GTK PN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/amsdu",
    smoke_ccmp_amsdu_block_ack_invalid_policy_group_and_tail_keep_pn
);
fn header(receiver: [u8; 6], tid: u8) -> Vec<u8> {
    let mut header = vec![0x88, 0x42, 0, 0];
    header.extend_from_slice(&receiver);
    header.extend_from_slice(&PEER);
    header.extend_from_slice(&REMOTE);
    header.extend_from_slice(&[0, 0, 0x80 | tid, 0]);
    header
}
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
fn seal(header: &[u8], body: &[u8], tk: &[u8; 16], pn: u64, id: u8) -> Vec<u8> {
    ccmp::protect(
        &Ccm,
        header,
        tk,
        pn,
        id,
        header[24] & 15,
        false,
        &mut body.to_vec(),
    )
    .unwrap()
}
fn smoke_ccmp_amsdu_pairwise_group_all_tids_and_replay_are_atomic() -> TestResult {
    let tk = [0x55; 16];
    for (role, id, receiver) in [
        (Role::Pairwise, 0, LOCAL),
        (Role::Group, 0, GROUP),
        (Role::Group, 2, GROUP),
    ] {
        let mut key = Key::new(&tk, id, role, LOCAL, PEER, 5).unwrap();
        for tid in 0..16 {
            let header = header(receiver, tid);
            let (body, expected) = plaintext(receiver);
            let wire = seal(&header, &body, &tk, 6, id);
            let saved = wire.clone();
            if key.unprotect_amsdu(&header, &wire) != Ok(expected)
                || key.receive[usize::from(tid)].last_seen_pn != 6
                || key.unprotect_amsdu(&header, &wire) != Err(Error::Crypto(CcmpError::Replay))
                || wire != saved
            {
                return TestResult::Fail("A-MSDU key/TID/group replay or immutable ciphertext");
            }
        }
        if key.receive[16].last_seen_pn != 5 {
            return TestResult::Fail("QoS aggregate changed non-QoS replay floor");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/amsdu",
    smoke_ccmp_amsdu_pairwise_group_all_tids_and_replay_are_atomic
);

fn smoke_ccmp_amsdu_authenticated_bad_tail_cannot_commit_any_replay() -> TestResult {
    let tk = [0x55; 16];
    let h = header(LOCAL, 3);
    let (body, expected) = plaintext(LOCAL);
    for case in 0..7 {
        let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 5).unwrap();
        let mut malformed = body.clone();
        match case {
            0 => {
                malformed.pop();
            }
            1 => malformed[24 + 12..24 + 14].copy_from_slice(&0xffffu16.to_be_bytes()),
            2 => malformed[24 + 14] ^= 1,
            3 => malformed[24 + 6] |= 1,
            4 => malformed[24..24 + 6].fill(0),
            5 => malformed[24 + 20..24 + 22].copy_from_slice(&0x888eu16.to_be_bytes()),
            _ => malformed.push(0),
        }
        let wire = seal(&h, &malformed, &tk, MAX_PN, 0);
        let original = wire.clone();
        if !matches!(key.unprotect_amsdu(&h, &wire), Err(Error::Aggregate(_)))
            || key.receive.iter().any(|r| r.last_seen_pn != 5)
            || wire != original
            || key.unprotect_amsdu(&h, &seal(&h, &body, &tk, 6, 0)) != Ok(expected.clone())
        {
            return TestResult::Fail("authenticated malformed aggregate committed prefix/PN");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/amsdu",
    smoke_ccmp_amsdu_authenticated_bad_tail_cannot_commit_any_replay
);

fn smoke_ccmp_amsdu_forged_header_mic_key_and_extents_keep_replay_unchanged() -> TestResult {
    let tk = [0x55; 16];
    let h = header(LOCAL, 3);
    let (body, expected) = plaintext(LOCAL);
    let wire = seal(&h, &body, &tk, MAX_PN, 0);
    for (offset, mask) in [
        (0, 4),
        (1, 4),
        (1, 0x80),
        (1, 1),
        (4, 2),
        (10, 2),
        (22, 1),
        (24, 1),
        (24, 0x80),
        (25, 1),
    ] {
        let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 5).unwrap();
        let mut bad = h.clone();
        bad[offset] ^= mask;
        if key.unprotect_amsdu(&bad, &wire).is_ok()
            || key.receive.iter().any(|r| r.last_seen_pn != 5)
        {
            return TestResult::Fail("forged aggregate header/TID changed any replay tracker");
        }
    }
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 5).unwrap();
    for (offset, mask) in [(2, 1), (3, 1), (3, 0x20), (3, 0x40), (wire.len() - 1, 1)] {
        let mut bad = wire.clone();
        bad[offset] ^= mask;
        let original = bad.clone();
        if key.unprotect_amsdu(&h, &bad).is_ok()
            || key.receive[3].last_seen_pn != 5
            || bad != original
        {
            return TestResult::Fail("bad aggregate CCMP header/MIC changed wire or replay");
        }
    }
    if key.unprotect_amsdu(&h, &vec![0; crate::amsdu::MAX_BYTES + 17]) != Err(Error::Length)
        || key.unprotect_amsdu(&h[..25], &wire) != Err(Error::Header)
        || key.unprotect_amsdu(&h, &seal(&h, &body, &tk, 6, 0)) != Ok(expected)
    {
        return TestResult::Fail("bad aggregate extents poisoned valid later CCMP");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/amsdu",
    smoke_ccmp_amsdu_forged_header_mic_key_and_extents_keep_replay_unchanged
);

fn smoke_ccmp_amsdu_present_bit_injection_is_rejected_before_pn_commit() -> TestResult {
    let tk = [0x55; 16];
    let h = header(LOCAL, 0);
    let mut standalone = h.clone();
    standalone[24] &= !0x80;
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 2, 3, 4, 5, 0, 9];
    body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 0x45]);
    let wire = seal(&standalone, &body, &tk, 1, 0);
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    if ccmp::build_aad(&h) != ccmp::build_aad(&standalone)
        || key.unprotect_amsdu(&h, &wire) != Err(Error::Aggregate(crate::amsdu::Error::Injection))
        || key.receive[0].last_seen_pn != 0
    {
        return TestResult::Fail(
            "unauthenticated A-MSDU-present flip reinterpreted standalone MSDU",
        );
    }
    let (body, expected) = plaintext(LOCAL);
    let valid = seal(&h, &body, &tk, 1, 0);
    if key.unprotect_amsdu(&standalone, &valid) != Err(Error::Header)
        || key.unprotect_amsdu(&h, &valid) != Ok(expected)
    {
        return TestResult::Fail("aggregate flag rejection consumed genuine same-PN packet");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/amsdu",
    smoke_ccmp_amsdu_present_bit_injection_is_rejected_before_pn_commit
);

fn smoke_ccmp_amsdu_and_single_mpdu_share_tid_replay_across_reinstall() -> TestResult {
    let tk = [0x55; 16];
    let mut key = Key::new(&tk, 0, Role::Pairwise, LOCAL, PEER, 0).unwrap();
    let h = header(LOCAL, 3);
    let (body, expected) = plaintext(LOCAL);
    let mut single = h.clone();
    single[24] &= !0x80;
    if key.unprotect_amsdu(&h, &seal(&h, &body, &tk, 4, 0)) != Ok(expected.clone())
        || key.unprotect(&single, &mut seal(&single, &[1; 8], &tk, 4, 0))
            != Err(Error::Crypto(CcmpError::Replay))
        || key.unprotect(&single, &mut seal(&single, &[1; 8], &tk, 5, 0)) != Ok(vec![1; 8])
        || key.unprotect_amsdu(&h, &seal(&h, &body, &tk, 5, 0))
            != Err(Error::Crypto(CcmpError::Replay))
        || key.reinstall(&tk, 0) != Ok(false)
        || key.unprotect_amsdu(&h, &seal(&h, &body, &tk, 5, 0))
            != Err(Error::Crypto(CcmpError::Replay))
    {
        return TestResult::Fail("aggregate/single or same-key reinstall split replay ownership");
    }
    let changed = [0x56; 16];
    if key.reinstall(&changed, 8) != Ok(true)
        || key.unprotect_amsdu(&h, &seal(&h, &body, &changed, 8, 0))
            != Err(Error::Crypto(CcmpError::Replay))
        || key.unprotect_amsdu(&h, &seal(&h, &body, &tk, 9, 0))
            != Err(Error::Crypto(CcmpError::AuthFailed))
        || key.unprotect_amsdu(&h, &seal(&h, &body, &changed, 9, 0)) != Ok(expected)
    {
        return TestResult::Fail("aggregate rekey ignored native RSC or old material");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ccmp/amsdu",
    smoke_ccmp_amsdu_and_single_mpdu_share_tid_replay_across_reinstall
);
