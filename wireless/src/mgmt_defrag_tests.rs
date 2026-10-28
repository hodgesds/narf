use super::*;
use crate::association::{Bss, JoinPlan, Phase, SecurityMode};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 3];

fn fragment(
    subtype: u8,
    ta: [u8; 6],
    sequence: u16,
    number: u8,
    more: bool,
    body: &[u8],
) -> Vec<u8> {
    let mut frame = vec![subtype, if more { 4 } else { 0 }, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&ta);
    frame.extend_from_slice(&ta);
    frame.extend_from_slice(&(sequence << 4 | u16::from(number)).to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

fn split(subtype: u8, sequence: u16, body: &[u8], pieces: usize) -> Vec<Vec<u8>> {
    let size = body.len().div_ceil(pieces);
    let chunks: Vec<&[u8]> = body.chunks(size).collect();
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| fragment(subtype, AP, sequence, i as u8, i + 1 != chunks.len(), chunk))
        .collect()
}

fn smoke_mgmt_defrag_reassembles_consecutive_fragments_with_first_header() -> TestResult {
    let mut r = Reassembler::new(OWN).unwrap();
    let body: Vec<u8> = (0..900u32).map(|i| i as u8).collect();
    let whole = fragment(0x10, AP, 7, 0, false, &body);
    if r.push(&whole, 0) != Ok(Some(whole.clone())) || r.pending() != 0 {
        return TestResult::Fail("unfragmented MMPDU was not passed through unchanged");
    }
    for pieces in [2, 3, 16] {
        let frags = split(0x10, 9, &body, pieces);
        for (i, frag) in frags.iter().enumerate() {
            let result = r.push(frag, 1_000 * i as u64);
            if i + 1 < frags.len() {
                if result != Ok(None) || r.pending() != 1 {
                    return TestResult::Fail("partial sequence published or not retained");
                }
            } else {
                let mut expected = fragment(0x10, AP, 9, 0, false, &body);
                expected[1] = 0;
                if result != Ok(Some(expected)) || r.pending() != 0 {
                    return TestResult::Fail(
                        "reassembled MMPDU differs from first header + bodies",
                    );
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/mgmt_defrag",
    smoke_mgmt_defrag_reassembles_consecutive_fragments_with_first_header
);

fn smoke_mgmt_defrag_drops_gaps_duplicates_and_foreign_fragments() -> TestResult {
    let mut r = Reassembler::new(OWN).unwrap();
    let frags = split(0x10, 5, &[0x55; 300], 3);
    r.push(&frags[0], 0).unwrap();
    // Gap, wrong sequence, wrong TA, different subtype: all dropped while
    // the partial sequence stays intact.
    let mut wrong_type = frags[1].clone();
    wrong_type[0] = 0x30;
    let wrong_seq = fragment(0x10, AP, 6, 1, true, &[0x55; 100]);
    let wrong_ta = fragment(0x10, OTHER, 5, 1, true, &[0x55; 100]);
    for bad in [&frags[2], &wrong_seq, &wrong_ta, &wrong_type] {
        if r.push(bad, 1) != Err(Error::Sequence) || r.pending() != 1 {
            return TestResult::Fail("unexpected fragment changed the partial sequence");
        }
    }
    if r.push(&frags[1], 2) != Ok(None) || r.push(&frags[1], 3) != Err(Error::Sequence) {
        return TestResult::Fail("duplicate fragment was appended twice");
    }
    let Ok(Some(done)) = r.push(&frags[2], 4) else {
        return TestResult::Fail("sequence did not complete after a dropped duplicate");
    };
    if done.len() != 24 + 300 {
        return TestResult::Fail("dropped fragments leaked into the result");
    }
    // A continuation without its first fragment never starts a sequence.
    if r.push(&frags[1], 5) != Err(Error::Sequence) || r.pending() != 0 {
        return TestResult::Fail("orphan continuation started a sequence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/mgmt_defrag",
    smoke_mgmt_defrag_drops_gaps_duplicates_and_foreign_fragments
);

fn smoke_mgmt_defrag_lifetime_slots_bounds_and_admission() -> TestResult {
    let mut r = Reassembler::new(OWN).unwrap();
    let frags = split(0x10, 1, &[1; 200], 2);
    r.push(&frags[0], 0).unwrap();
    if r.push(&frags[1], LIFETIME_NS + 1) != Err(Error::Sequence) || r.pending() != 0 {
        return TestResult::Fail("expired partial sequence completed");
    }
    // Four sequences from distinct TAs; a fifth replaces the oldest slot.
    for (i, ta) in [
        [2, 0, 0, 0, 1, 1],
        [2, 0, 0, 0, 1, 2],
        [2, 0, 0, 0, 1, 3],
        [2, 0, 0, 0, 1, 4],
    ]
    .into_iter()
    .enumerate()
    {
        r.push(&fragment(0x10, ta, i as u16, 0, true, &[1]), 0)
            .unwrap();
    }
    r.push(&fragment(0x10, [2, 0, 0, 0, 1, 5], 9, 0, true, &[1]), 0)
        .unwrap();
    if r.pending() != ENTRIES
        || r.push(&fragment(0x10, [2, 0, 0, 0, 1, 1], 0, 1, false, &[1]), 0) != Err(Error::Sequence)
        || r.push(&fragment(0x10, [2, 0, 0, 0, 1, 2], 1, 1, false, &[1]), 0)
            .map(|f| f.map(|f| f.len()))
            != Ok(Some(26))
    {
        return TestResult::Fail("fragment cache did not replace round-robin");
    }
    // A new first fragment from the same TA supersedes its old sequence.
    r.clear();
    r.push(&fragment(0x10, AP, 1, 0, true, &[1]), 0).unwrap();
    r.push(&fragment(0x10, AP, 2, 0, true, &[2]), 0).unwrap();
    if r.pending() != 1 || r.push(&fragment(0x10, AP, 1, 1, false, &[1]), 0) != Err(Error::Sequence)
    {
        return TestResult::Fail("superseded sequence still accepted fragments");
    }
    // Size bound drops the sequence.
    r.clear();
    r.push(&fragment(0x10, AP, 3, 0, true, &[0; 2000]), 0)
        .unwrap();
    r.push(&fragment(0x10, AP, 3, 1, true, &[0; 2000]), 0)
        .unwrap();
    if r.push(&fragment(0x10, AP, 3, 2, false, &[0; 100]), 0) != Err(Error::Length)
        || r.pending() != 0
    {
        return TestResult::Fail("oversized reassembly was retained");
    }
    // Header/address admission.
    let mut protected = fragment(0x10, AP, 4, 0, true, &[1]);
    protected[1] |= 0x40;
    let mut data = fragment(0x08, AP, 4, 0, true, &[1]);
    data[1] |= 0x01;
    let mut group = fragment(0x10, AP, 4, 0, true, &[1]);
    group[4] = 0xff;
    let mut multicast_ta = fragment(0x10, AP, 4, 0, true, &[1]);
    multicast_ta[10] = 1;
    if r.push(&protected, 0) != Err(Error::Header)
        || r.push(&data, 0) != Err(Error::Header)
        || r.push(&group, 0) != Err(Error::Address)
        || r.push(&multicast_ta, 0) != Err(Error::Address)
        || r.push(&[0x10; 23], 0) != Err(Error::Header)
        || Reassembler::new([1, 0, 0, 0, 0, 1]).is_ok()
        || r.pending() != 0
    {
        return TestResult::Fail("refused MPDU class was admitted");
    }
    // Sixteen fragments are the most a sequence may use.
    for n in 0..16 {
        let result = r.push(&fragment(0x10, AP, 8, n, true, &[n]), 0);
        if n < 15 && result != Ok(None) || n == 15 && result != Err(Error::Sequence) {
            return TestResult::Fail("a seventeenth fragment was awaited");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/mgmt_defrag",
    smoke_mgmt_defrag_lifetime_slots_bounds_and_admission
);

fn smoke_mgmt_defrag_fragmented_association_response_is_admitted() -> TestResult {
    let ap = Bss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 1,
        band: None,
        signal_dbm: None,
        capability: 1,
        beacon_interval: 100,
        information_elements: vec![0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96],
    };
    let mut plan = JoinPlan::prepare(&ap, OWN, b"narf", SecurityMode::Open).unwrap();
    let mut r = Reassembler::new(OWN).unwrap();
    plan.start_authentication().unwrap();
    // Authentication: algorithm 0, transaction 2, success, in two fragments.
    let auth = split(0xb0, 3, &[0, 0, 2, 0, 0, 0], 2);
    if plan.authentication_response(&auth[0]) != Ok(None) {
        return TestResult::Fail("raw first fragment advanced authentication");
    }
    let mut whole = None;
    for frag in &auth {
        whole = r.push(frag, 0).unwrap();
    }
    let whole = whole.unwrap();
    if plan.authentication_response(&whole).map(|f| f.is_some()) != Ok(true) {
        return TestResult::Fail("reassembled authentication was not admitted");
    }
    // Association response with a vendor element padding it to 3 fragments.
    let mut body = vec![1, 0, 0, 0, 42, 0xc0, 1, 4, 0x82, 0x84, 0x8b, 0x96];
    body.extend_from_slice(&[221, 200]);
    body.extend_from_slice(&[0x50, 0x6f, 0x9a, 0xff]);
    body.extend_from_slice(&[0; 196]);
    let frags = split(0x10, 4, &body, 3);
    for frag in &frags[..2] {
        if plan.association_response(frag) != Ok(None) || r.push(frag, 0) != Ok(None) {
            return TestResult::Fail("partial association response advanced the plan");
        }
    }
    let whole = r.push(&frags[2], 0).unwrap().unwrap();
    if plan.association_response(&whole) != Ok(Some(42))
        || plan.phase() != (Phase::Associated { aid: 42 })
    {
        return TestResult::Fail("reassembled association response was not admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/mgmt_defrag",
    smoke_mgmt_defrag_fragmented_association_response_is_admitted
);
