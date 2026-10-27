//! Source-qualified CONNAC2 HT greenfield over the real retained station owner.
use super::tx_nss_tests::{associated, join, prepared, Mode};
use super::*;

fn greenfield(ies: &mut [u8], enabled: bool) {
    let mut offset = 0;
    while offset < ies.len() {
        if ies[offset] == 45 {
            ies[offset + 2] = (ies[offset + 2] & !16) | (u8::from(enabled) << 4);
        }
        offset += 2 + usize::from(ies[offset + 1]);
    }
}
fn packet(secure: bool, channel: u8, width: u8, mcs: u8, nsts: u8, pn: u64, extra: u32) -> Vec<u8> {
    let mut packet = vht_tests::data(secure, width, mcs, nsts, pn);
    packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    let offset = if secure { 40 } else { 24 };
    packet[offset..offset + 4].copy_from_slice(
        &((3u32 << 24)
            | (u32::from(width) << 12)
            | (u32::from(nsts - 1) << 7)
            | u32::from(mcs)
            | extra)
            .to_le_bytes(),
    );
    packet
}
fn mt76_greenfield_actual_ht_offer_native_peer_and_directional_response() -> TestResult {
    for mode in [Mode::Ht20, Mode::Ht40, Mode::Vht(2), Mode::Vht(3)] {
        for secure in [false, true] {
            for scan in [false, true] {
                for response in [false, true] {
                    let (mut s, mut b, p) = prepared(mode, 2, secure);
                    greenfield(&mut b.information_elements, scan);
                    greenfield(s.backend.ht_reply.as_mut().unwrap(), response);
                    if join(&mut s, &b, p, secure) != Ok(42) {
                        return TestResult::Fail("greenfield bound native association");
                    }
                    let peer = associated(&s);
                    if vht_tests::record(peer, 9)
                        .is_none_or(|ht| (ht[4] & 16 != 0) != (scan && response))
                    {
                        return TestResult::Fail(
                            "native STA_REC_HT greenfield escaped original/local/response bounds",
                        );
                    }
                    let request = s
                        .backend
                        .frames
                        .iter()
                        .find(|(_, f)| f.first() == Some(&0))
                        .unwrap();
                    if !request
                        .1
                        .windows(28)
                        .any(|ie| ie[..2] == [45, 26] && ie[2] & 16 != 0)
                        || !s.ht20_profile.unwrap().receive_greenfield()
                    {
                        return TestResult::Fail(
                            "actual greenfield decoder promise lost from association request",
                        );
                    }
                    // AP's RX promise bounds our TX, independently of whether
                    // its TX can send greenfield into our qualified decoder.
                    s.backend
                        .packets
                        .push_back(packet(secure, b.channel, 0, 7, 1, 9, 0));
                    if s.receive_ethernet().ok().flatten().is_none() {
                        return TestResult::Fail(
                            "valid native greenfield PPDU rejected by peer RX capability",
                        );
                    }
                    run(s.disassociate_station()).unwrap();
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/greenfield",
    mt76_greenfield_actual_ht_offer_native_peer_and_directional_response
);

fn mt76_greenfield_native_mcs_nsts_width_coding_and_pn_bounds() -> TestResult {
    for secure in [false, true] {
        for nss in [1, 2] {
            let (mut s, b, p) = prepared(Mode::Vht(2), nss, secure);
            if join(&mut s, &b, p, secure) != Ok(42) {
                return TestResult::Fail("greenfield native metadata fixture");
            }
            let mut pn = 9;
            for width in [0, 1] {
                for streams in 1..=nss {
                    for mcs in [8 * (streams - 1), 8 * streams - 1] {
                        s.backend.packets.push_back(packet(
                            secure,
                            b.channel,
                            width,
                            mcs,
                            streams,
                            pn,
                            1 << 15,
                        ));
                        if s.receive_ethernet().ok().flatten().is_none() {
                            return TestResult::Fail("native HT greenfield MCS/NSTS/20-40 bounds");
                        }
                        pn += 1;
                    }
                }
            }
            for (width, mcs, streams, extra) in [
                (2, 7, 1, 0),
                (0, 16, 2, 0),
                (0, 7, 2, 0),
                (0, 8, 1, 0),
                (0, 7, 1, 3 << 15),
                (0, 7, 3, 0),
                (0, 15, 2, 1 << 22),
            ] {
                s.backend
                    .packets
                    .push_back(packet(secure, b.channel, width, mcs, streams, pn, extra));
                if s.receive_ethernet() != Ok(None) {
                    return TestResult::Fail("invalid greenfield metadata published data");
                }
                s.backend
                    .packets
                    .push_back(packet(secure, b.channel, 0, 7, 1, pn, 0));
                if s.receive_ethernet().ok().flatten().is_none() {
                    return TestResult::Fail("invalid greenfield consumed ordinary per-TID PN");
                }
                pn += 1;
            }
            run(s.disassociate_station()).unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/greenfield",
    mt76_greenfield_native_mcs_nsts_width_coding_and_pn_bounds
);

fn mt76_greenfield_native_optional_coding_requires_actual_nic_facts() -> TestResult {
    for coding in [false, true] {
        let (mut s, b, p) = prepared(Mode::Ht40, 2, true);
        let State::RadioReady(mut info) = s.state else {
            return TestResult::Fail("greenfield NIC query");
        };
        info.capabilities.phy.rx_ldpc = coding;
        info.capabilities.phy.rx_stbc = coding;
        s.state = State::RadioReady(info);
        if join(&mut s, &b, p, true) != Ok(42) {
            return TestResult::Fail("greenfield coding fixture");
        }
        let mut pn = 9;
        for (nsts, extra) in [(1, 1 << 11), (2, 1 << 22)] {
            s.backend
                .packets
                .push_back(packet(true, b.channel, 1, 7, nsts, pn, extra));
            if s.receive_ethernet().ok().flatten().is_some() != coding {
                return TestResult::Fail("greenfield inferred LDPC/STBC decoder from HT support");
            }
            if coding {
                pn += 1;
            }
            s.backend
                .packets
                .push_back(packet(true, b.channel, 0, 7, 1, pn, 0));
            if s.receive_ethernet().ok().flatten().is_none() {
                return TestResult::Fail("coding rejection consumed PN");
            }
            pn += 1;
        }
        run(s.disassociate_station()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/greenfield",
    mt76_greenfield_native_optional_coding_requires_actual_nic_facts
);
