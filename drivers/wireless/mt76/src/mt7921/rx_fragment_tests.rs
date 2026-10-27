//! Native station RX defragmentation (Linux `ieee80211_rx_h_defragment`).
use super::*;
use fragment::{Cache, MAX_AGE_NS, MAX_MSDU};

const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
const SA: [u8; 6] = [2, 6, 7, 8, 9, 10];

/// Native QoS-data fragment MPDU (TID `tid`), FromDS, CCMP IV/MIC stripped.
fn fragment_frame(
    seq: u16,
    number: u8,
    more: bool,
    protected: bool,
    tid: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut frame = vec![0u8; 26];
    frame[0] = 0x88;
    frame[1] = 0x02 | if more { 0x04 } else { 0 } | if protected { 0x40 } else { 0 };
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&SA);
    frame[22..24].copy_from_slice(&((seq << 4) | u16::from(number)).to_le_bytes());
    frame[24] = tid;
    frame.extend_from_slice(body);
    frame
}

/// CONNAC2 normal RX descriptor around `frame`, with `MT_RXD2_NORMAL_FRAG`
/// and, for CCMP, the RX group 1 PN.
fn fragment_packet(frame: &[u8], pn: Option<u64>, frag_marker: bool, ampdu: bool) -> Vec<u8> {
    let descriptor = if pn.is_some() { 40 } else { 24 };
    let mut packet = vec![0u8; descriptor];
    packet[..4].copy_from_slice(&((2u32 << 27) | (descriptor + frame.len()) as u32).to_le_bytes());
    let r2 = if ampdu { 0 } else { 1u32 << 30 } | if frag_marker { 1 << 27 } else { 0 };
    packet[8..12].copy_from_slice(&r2.to_le_bytes());
    packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    if let Some(pn) = pn {
        packet[4..8].copy_from_slice(&((4u32 << 16) | (1 << 11)).to_le_bytes());
        packet[24..30].copy_from_slice(&pn.to_le_bytes()[..6]);
    }
    packet.extend_from_slice(frame);
    packet
}

const MSDU: [u8; 14] = [0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00, 1, 2, 3, 4, 5, 6];

fn expected_ethernet() -> Vec<u8> {
    let mut eth = OWN.to_vec();
    eth.extend_from_slice(&SA);
    eth.extend_from_slice(&[0x08, 0x00, 1, 2, 3, 4, 5, 6]);
    eth
}

fn mt76_rx_fragment_cache_follows_mac80211_reassembly_rules() -> TestResult {
    let parts = [&MSDU[..5], &MSDU[5..9], &MSDU[9..]];
    let feed = |cache: &mut Cache, seq: u16, order: &[usize], pns: &[Option<u64>], now: u64| {
        let mut out = None;
        for (&index, &pn) in order.iter().zip(pns) {
            let frame = fragment_frame(seq, index as u8, index != 2, pn.is_some(), 0, parts[index]);
            out = cache.insert(&frame, pn, now);
        }
        out
    };
    // In-order plaintext reassembly normalizes the first header.
    let mut cache = Cache::default();
    let Some(done) = feed(&mut cache, 7, &[0, 1, 2], &[None; 3], 0) else {
        return TestResult::Fail("plaintext reassembly");
    };
    let mut normalized = fragment_frame(7, 0, false, false, 0, &MSDU);
    normalized[22] &= 0xf0;
    if done.frame != normalized || done.queue != 0 || done.pn.is_some() || cache.pending() != 0 {
        return TestResult::Fail("reassembled MSDU layout");
    }
    // Protected: sequential PNs complete, recording the PN range.
    let pns = [Some(40), Some(41), Some(42)];
    if feed(&mut cache, 8, &[0, 1, 2], &pns, 0).map(|d| d.pn) != Some(Some((40, 42))) {
        return TestResult::Fail("protected reassembly");
    }
    // Non-sequential PN, a skipped fragment, a repeated fragment and mixed
    // protection never complete.
    for (order, pns) in [
        (&[0, 1, 2][..], [Some(40), Some(42), Some(43)]),
        (&[0, 2][..], [Some(40), Some(41), None]),
        (&[0, 1, 1][..], [Some(40), Some(41), Some(42)]),
        (&[0, 1, 2][..], [Some(40), None, Some(42)]),
        (&[0, 1, 2][..], [None, Some(41), Some(42)]),
    ] {
        let mut cache = Cache::default();
        if feed(&mut cache, 9, order, &pns, 0).is_some() {
            return TestResult::Fail("invalid continuation completed");
        }
    }
    // A different sequence, TID or transmitter does not match the entry.
    let mut cache = Cache::default();
    cache.insert(&fragment_frame(10, 0, true, false, 0, parts[0]), None, 0);
    let mut foreign = fragment_frame(10, 1, false, false, 0, parts[1]);
    foreign[10] ^= 2;
    if cache
        .insert(&fragment_frame(11, 1, false, false, 0, parts[1]), None, 0)
        .is_some()
        || cache
            .insert(&fragment_frame(10, 1, false, false, 5, parts[1]), None, 0)
            .is_some()
        || cache.insert(&foreign, None, 0).is_some()
    {
        return TestResult::Fail("mismatched continuation accepted");
    }
    // Two-second age limit purges the entry on lookup.
    let mut cache = Cache::default();
    cache.insert(&fragment_frame(12, 0, true, false, 0, parts[0]), None, 0);
    if cache
        .insert(
            &fragment_frame(12, 1, false, false, 0, parts[1]),
            None,
            MAX_AGE_NS + 1,
        )
        .is_some()
        || cache.pending() != 0
    {
        return TestResult::Fail("expired fragment entry");
    }
    // Four entries; a fifth first fragment evicts the oldest.
    let mut cache = Cache::default();
    for seq in 0..5 {
        cache.insert(&fragment_frame(seq, 0, true, false, 0, parts[0]), None, 0);
    }
    if cache.pending() != 4
        || cache
            .insert(&fragment_frame(0, 1, false, false, 0, parts[1]), None, 0)
            .is_some()
        || cache
            .insert(&fragment_frame(4, 1, false, false, 0, parts[1]), None, 0)
            .is_none()
    {
        return TestResult::Fail("four-entry replacement");
    }
    // Multicast, A-MSDU, ToDS, HT-control, unfragmented and PN/protection
    // disagreement are not station fragments.
    let base = fragment_frame(13, 0, true, false, 0, parts[0]);
    for (offset, value) in [
        (4, 0xff),
        (24, 0x80),
        (1, 0x05),
        (1, 0x86),
        (1, 0x02),
        (1, 0x46),
    ] {
        let mut bad = base.clone();
        bad[offset] = value;
        if Cache::parse(&bad, None).is_some() {
            return TestResult::Fail("non-fragment layout parsed");
        }
    }
    if Cache::parse(&base, Some(1)).is_some() {
        return TestResult::Fail("PN without Protected parsed");
    }
    // The reassembled MSDU is bounded.
    let mut cache = Cache::default();
    let half = vec![0u8; MAX_MSDU / 2 + 1];
    cache.insert(&fragment_frame(14, 0, true, false, 0, &half), None, 0);
    if cache
        .insert(&fragment_frame(14, 1, false, false, 0, &half), None, 0)
        .is_some()
        || cache.pending() != 0
    {
        return TestResult::Fail("oversized MSDU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_rx_fragment_cache_follows_mac80211_reassembly_rules
);

fn push_fragments(session: &mut Session<Model>, seq: u16, pns: [u64; 3]) {
    let parts = [&MSDU[..5], &MSDU[5..9], &MSDU[9..]];
    for (index, part) in parts.into_iter().enumerate() {
        let frame = fragment_frame(seq, index as u8, index != 2, true, 0, part);
        session
            .backend
            .packets
            .push_back(fragment_packet(&frame, Some(pns[index]), true, false));
    }
}

fn mt76_protected_rx_defragments_with_sequential_pn_and_replay() -> TestResult {
    let mut session = super::secure_model();
    push_fragments(&mut session, 20, [10, 11, 12]);
    if session.receive_ethernet() != Ok(Some(expected_ethernet())) {
        return TestResult::Fail("protected fragmented MSDU not delivered");
    }
    // The completed MSDU advanced the TID0 counter to its last PN.
    session.backend.packets.push_back(ccmp_packet(12, 0, false));
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("PN of a delivered fragment replayed");
    }
    session.backend.packets.push_back(ccmp_packet(13, 0, false));
    if !matches!(session.receive_ethernet(), Ok(Some(_))) {
        return TestResult::Fail("next PN after reassembly");
    }
    // Replayed, non-sequential and stale-PN bursts deliver nothing and do
    // not advance the counter.
    push_fragments(&mut session, 20, [10, 11, 12]);
    push_fragments(&mut session, 21, [20, 22, 23]);
    push_fragments(&mut session, 22, [13, 14, 15]);
    if session.receive_ethernet() != Ok(None) || !session.backend.packets.is_empty() {
        return TestResult::Fail("invalid fragment burst delivered");
    }
    session.backend.packets.push_back(ccmp_packet(14, 0, false));
    if !matches!(session.receive_ethernet(), Ok(Some(_))) {
        return TestResult::Fail("rejected burst advanced the counter");
    }
    // An A-MPDU-flagged fragment, a missing RXD FRAG marker, a group-key
    // fragment and a plaintext fragment on a secure link are all dropped.
    let parts = [&MSDU[..5], &MSDU[5..]];
    for case in 0..4 {
        for (index, part) in parts.into_iter().enumerate() {
            let protected = case != 3;
            let mut frame = fragment_frame(30 + case, index as u8, index == 0, protected, 0, part);
            if case == 2 {
                frame[4..10].fill(0xff);
            }
            let pn = protected.then_some(100 + u64::from(case) * 2 + index as u64);
            session
                .backend
                .packets
                .push_back(fragment_packet(&frame, pn, case != 1, case == 0));
        }
    }
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("invalid fragment metadata delivered");
    }
    // A receive-epoch renewal (every rekey path) discards partial MSDUs.
    let frame = fragment_frame(40, 0, true, true, 0, &MSDU[..5]);
    session
        .backend
        .packets
        .push_back(fragment_packet(&frame, Some(200), true, false));
    if session.receive_ethernet() != Ok(None) || session.rx_fragments.pending() != 1 {
        return TestResult::Fail("first fragment not retained");
    }
    session.renew_receive_epoch().unwrap();
    if session.rx_fragments.pending() != 0 {
        return TestResult::Fail("epoch renewal kept a partial MSDU");
    }
    let frame = fragment_frame(40, 1, false, true, 0, &MSDU[5..]);
    session
        .backend
        .packets
        .push_back(fragment_packet(&frame, Some(201), true, false));
    if session.receive_ethernet() != Ok(None) {
        return TestResult::Fail("continuation completed across epoch renewal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_protected_rx_defragments_with_sequential_pn_and_replay
);

/// The scan/auth/EAPOL parsers never admit an RXD FRAG packet.
fn mt76_fragment_descriptors_stay_out_of_management_paths() -> TestResult {
    let frame = fragment_frame(1, 0, true, false, 0, &MSDU);
    let packet = fragment_packet(&frame, None, true, false);
    if rx_frame(&packet).is_some() || scan::rx_native(&packet).is_some() {
        return TestResult::Fail("fragment reached a management parser");
    }
    match scan::rx_native_with_amsdu(&packet) {
        Some(native) if native.fragment => {}
        _ => return TestResult::Fail("station parser lost the fragment marker"),
    }
    let mut amsdu = packet.clone();
    amsdu[16] |= 1; // RXD4 A-MSDU marker on a fragment.
    if scan::rx_native_with_amsdu(&amsdu).is_some() {
        return TestResult::Fail("fragmented hardware A-MSDU accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mt76_fragment_descriptors_stay_out_of_management_paths
);
