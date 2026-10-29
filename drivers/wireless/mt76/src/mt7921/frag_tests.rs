//! TX fragmentation under the wiphy threshold: mac80211
//! `ieee80211_fragment` MPDUs and the mt76 `MT_TXD2_FRAG` descriptors.
use super::*;
use crate::mt7921::association::Security;

const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];

fn ethernet(len: usize) -> Vec<u8> {
    let mut frame: Vec<u8> = (0..len).map(|i| i as u8).collect();
    frame[..6].copy_from_slice(&AP);
    frame[6..12].copy_from_slice(&OWN);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    frame[15] = 0; // DSCP 0: BE / TID 0.
    frame
}

fn joined(wmm: bool, wpa2: bool) -> Session<Model> {
    let (mut session, bss) = wmm_tests::prepared(wmm, wpa2);
    let security = if wpa2 {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    };
    assert_eq!(
        run(session.associate_station(&bss, b"narf", security, test_permission(), &[])),
        Ok(42)
    );
    session
}

/// Drive completions until the fragment queue and data tokens drain.
fn drain(session: &mut Session<Model>) -> Result<(), Error> {
    for _ in 0..16 {
        if session.poll_data_tx()? && session.data_pending.is_empty() {
            return Ok(());
        }
    }
    Err(Error::Timeout)
}

fn fragments(session: &Session<Model>, before: usize) -> Vec<Vec<u8>> {
    session.backend.frames[before..]
        .iter()
        .filter(|(_, f)| matches!(f.first(), Some(0x08 | 0x88)) && f[1] & 1 != 0)
        .map(|(_, f)| f.clone())
        .collect()
}

fn check(wmm: bool, wpa2: bool) -> Result<(), &'static str> {
    let mut session = joined(wmm, wpa2);
    session.frag_threshold = 256;
    let frame = ethernet(1000);
    let before = session.backend.frames.len();
    let data_before = session.backend.data_protection.len();
    session.start_ethernet(&frame).map_err(|_| "start")?;
    if session.start_ethernet(&frame) != Err(Error::Busy) {
        return Err("a second MSDU overtook queued fragments");
    }
    drain(&mut session).map_err(|_| "drain")?;
    let header = if wmm { 26 } else { 24 };
    let per = 256 - header - 4;
    let mut msdu = vec![0xaa, 0xaa, 3, 0, 0, 0];
    msdu.extend_from_slice(&frame[12..]);
    let sent = fragments(&session, before);
    if sent.len() != msdu.len().div_ceil(per)
        || session.backend.data_protection.len() != data_before
    {
        return Err("fragment count / 802.3 path used");
    }
    let mut body = Vec::new();
    for (number, mpdu) in sent.iter().enumerate() {
        let last = number + 1 == sent.len();
        let fc1 = 0x01 | if wpa2 { 0x40 } else { 0 } | if last { 0 } else { 0x04 };
        if mpdu[0] != if wmm { 0x88 } else { 0x08 }
            || mpdu[1] != fc1
            || mpdu[4..10] != AP
            || mpdu[10..16] != OWN
            || mpdu[16..22] != AP
            || mpdu[22..24] != [number as u8, 0]
            || wmm && mpdu[24..26] != [0, 0]
            || !last && mpdu.len() != 256 - 4
        {
            return Err("fragment header/length");
        }
        let txd = crate::mt7921::packet_tx::fragment(mpdu, 0x1000, 1, 1).map_err(|_| "txd")?;
        let word = |i: usize| u32::from_le_bytes(txd[i * 4..i * 4 + 4].try_into().unwrap());
        let position = if number == 0 {
            1
        } else if last {
            3
        } else {
            2
        };
        if (word(2) >> 14) & 3 != position
            || word(2) & (1 << 31) != 0
            || (word(1) >> 16) & 3 != 2
            || (word(1) >> 11) & 31 != header as u32 / 2
            || (word(3) >> 1) & 1 != u32::from(wpa2)
            || word(3) & (1 << 28) != 0
        {
            return Err("MT_TXD2_FRAG / header format / protect bits");
        }
        body.extend_from_slice(&mpdu[header..]);
    }
    if body != msdu {
        return Err("fragments do not reassemble the MSDU");
    }
    // At or below the threshold, and with fragmentation off, the 802.3
    // offload path is used unchanged.
    for (threshold, len) in [(256, 256 - header - 4 - 8 + 14), (u32::MAX, 1500)] {
        session.frag_threshold = threshold;
        let before = session.backend.frames.len();
        session
            .start_ethernet(&ethernet(len))
            .map_err(|_| "unfragmented start")?;
        drain(&mut session).map_err(|_| "unfragmented drain")?;
        if !fragments(&session, before).is_empty()
            || session.backend.data_protection.len()
                != data_before + 1 + usize::from(threshold == u32::MAX)
        {
            return Err("unfragmented MSDU took the fragment path");
        }
    }
    Ok(())
}

fn mt76_tx_fragmentation_open_wpa2_qos_matches_ieee80211_fragment() -> TestResult {
    for (wmm, wpa2) in [(false, false), (false, true), (true, false), (true, true)] {
        if let Err(error) = check(wmm, wpa2) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/frag",
    mt76_tx_fragmentation_open_wpa2_qos_matches_ieee80211_fragment
);

fn mt76_tx_fragment_failure_and_teardown_drop_the_remaining_fragments() -> TestResult {
    // A rejected fragment fails the data owner and drops the rest.
    let mut session = joined(false, true);
    session.frag_threshold = 256;
    session.start_ethernet(&ethernet(1000)).unwrap();
    session.backend.completion_status = 1;
    if session.poll_data_tx().is_ok()
        || !session.tx_fragments.is_empty()
        || session.security.is_some()
    {
        return TestResult::Fail("rejected fragment kept the remaining fragments");
    }
    // Teardown with fragments queued drains only the one in flight.
    let mut session = joined(false, true);
    session.frag_threshold = 256;
    session.start_ethernet(&ethernet(1000)).unwrap();
    let before = session.backend.frames.len();
    if run(session.disassociate_station()).is_err()
        || !session.tx_fragments.is_empty()
        || !fragments(&session, before).is_empty()
    {
        return TestResult::Fail("teardown transmitted queued fragments");
    }
    // Encoder refusals: management, multicast receiver, no MoreFrags on
    // fragment zero, Order bit, unknown token.
    let mut good = vec![0u8; 40];
    good[0] = 0x08;
    good[1] = 0x05;
    good[4..10].copy_from_slice(&AP);
    if crate::mt7921::packet_tx::fragment(&good, 0x1000, 1, 1).is_err() {
        return TestResult::Fail("valid fragment refused");
    }
    for (offset, value) in [(0, 0xd0), (4, 0x03), (1, 0x01), (1, 0x85)] {
        let mut bad = good.clone();
        bad[offset] = value;
        if crate::mt7921::packet_tx::fragment(&bad, 0x1000, 1, 1).is_ok() {
            return TestResult::Fail("invalid fragment encoded");
        }
    }
    if crate::mt7921::packet_tx::fragment(&good, 0x1000, 0, 1).is_ok() {
        return TestResult::Fail("token zero encoded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/frag",
    mt76_tx_fragment_failure_and_teardown_drop_the_remaining_fragments
);
