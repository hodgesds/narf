//! Occupied-channel permission and complete non-BA HT40 native station path.
use super::*;
use crate::mt7921::association::{Security, TxPermission};

fn domain(channel: u8) -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: if channel <= 11 { 2402 } else { 5170 },
            freq_end_mhz: if channel <= 11 { 2472 } else { 5895 },
            max_bandwidth_mhz: 40,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}
pub(super) fn permission40(channel: u8, secondary: u8) -> TxPermission {
    TxPermission::from_domain40(&domain(channel), channel, secondary).unwrap()
}
fn prepared(primary: u8, secondary: u8, secured: bool) -> (Session<Model>, ScanBss) {
    let (mut session, mut bss) = super::ht20_tests::prepared(primary, secured);
    let operation = if secondary > primary { 5 } else { 7 };
    session.backend.ht_reply.as_mut().unwrap()[31] = operation;
    let mut offset = 0;
    while offset < bss.information_elements.len() {
        if bss.information_elements[offset] == 61 {
            bss.information_elements[offset + 3] = operation;
        }
        offset += 2 + usize::from(bss.information_elements[offset + 1]);
    }
    (session, bss)
}
fn security(secured: bool) -> Security {
    if secured {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    }
}

fn mt76_ht40_occupied_policy_overlap_power_and_legacy_fallback() -> TestResult {
    use narf_wireless::reg::{RegFlags, RegRule};
    for (primary, secondary) in [(6, 10), (10, 6), (36, 40), (40, 36)] {
        let mut db = domain(primary);
        let grant = TxPermission::from_domain40(&db, primary, secondary).unwrap();
        let payload = grant.rate_limits();
        if grant.native_width() != 1
            || payload.len() != 368
            || payload[4] != 2
            || payload[44] != primary
            || payload[206] != secondary
            || payload[45..206] != [34; 161]
            || payload[207..] != [34; 161]
        {
            return TestResult::Fail("HT40 native two-channel power inventory");
        }
        let center = crate::mt7921::channel::frequency(secondary).unwrap();
        let boundary = if secondary > primary {
            center - 9
        } else {
            center + 1
        };
        db.rules.push(RegRule {
            freq_start_mhz: boundary,
            freq_end_mhz: boundary + 8,
            max_bandwidth_mhz: 40,
            max_power_dbm: 12,
            flags: RegFlags::empty(),
        });
        if TxPermission::from_domain40(&db, primary, secondary).is_none_or(|p| p.power_dbm != 12)
            || grant.current(&db)
        {
            return TestResult::Fail("secondary-only lower ceiling retained old40MHz grant");
        }
        for flags in [
            RegFlags::DFS,
            RegFlags::NO_IR,
            RegFlags::INDOOR_ONLY,
            RegFlags::from_bits_retain(16),
        ] {
            db.rules[1].flags = flags;
            if TxPermission::from_domain40(&db, primary, secondary).is_some()
                || TxPermission::from_domain(&db, primary).is_none()
                || grant.current(&db)
            {
                return TestResult::Fail(
                    "secondary restriction erased or disjoint20MHz fallback denied",
                );
            }
        }
        db.rules[1].flags = RegFlags::empty();
        db.rules[1].max_bandwidth_mhz = 20;
        if TxPermission::from_domain40(&db, primary, secondary).is_some() {
            return TestResult::Fail("narrow overlapping rule widened to40MHz");
        }
    }
    for (primary, secondary) in [(36, 44), (40, 44), (11, 15), (1, 36)] {
        if TxPermission::from_domain40(&domain(primary), primary, secondary).is_some() {
            return TestResult::Fail("invalid40MHz geometry granted");
        }
    }
    let (session, bss) = prepared(6, 10, false);
    let State::RadioReady(info) = session.state else {
        return TestResult::Fail("HT40 radio fixture");
    };
    let mut db = domain(6);
    if TxPermission::from_ap(&db, info, &bss).and_then(|p| p.secondary_channel()) != Some(10) {
        return TestResult::Fail("actual AP/NIC40MHz preference not selected");
    }
    db.rules[0].max_bandwidth_mhz = 20;
    if TxPermission::from_ap(&db, info, &bss).is_none_or(|p| p.secondary_channel().is_some()) {
        return TestResult::Fail("20MHz policy fallback lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht40",
    mt76_ht40_occupied_policy_overlap_power_and_legacy_fallback
);

fn mt76_ht40_native_domain_channel_rlm_peer_and_response_geometry() -> TestResult {
    for (primary, secondary) in [(6, 10), (10, 6), (36, 40), (40, 36)] {
        for secured in [false, true] {
            let (mut session, bss) = prepared(primary, secondary, secured);
            if run(session.associate_station(
                &bss,
                b"narf",
                security(secured),
                permission40(primary, secondary),
                &[],
            )) != Ok(42)
                || session.ht20_profile.and_then(|p| p.negotiated_secondary()) != Some(secondary)
                || session.ht20_profile.is_none_or(|p| !p.short_gi())
            {
                return TestResult::Fail(
                    "HT40 native association did not activate negotiated width/SGI40",
                );
            }
            let frames = &session.backend.frames;
            let center = ((u16::from(primary) + u16::from(secondary)) / 2) as u8;
            let band = u8::from(primary > 14);
            let switch = frames
                .iter()
                .find(|(_, f)| f.len() >= 76 && f[36] == 0xed && f[41] == 8);
            if switch.is_none_or(|(_, f)| f[64..69] != [primary, center, 1, 1, 2] || f[74] != band)
            {
                return TestResult::Fail("native40MHz switch width/center/actual RX count");
            }
            let rlm = frames
                .iter()
                .find(|(_, f)| f.len() == 68 && f[34..36] == [2, 0] && f[52..56] == [2, 0, 16, 0]);
            if rlm.is_none_or(|(_, f)| {
                f[56..]
                    != [
                        primary,
                        center,
                        0,
                        1,
                        2,
                        3,
                        1,
                        4,
                        if secondary > primary { 1 } else { 3 },
                        band,
                        0,
                        0,
                    ]
            }) {
                return TestResult::Fail("native40MHz RLM HT-operation/SCO geometry");
            }
            let peer = frames
                .iter()
                .find(|(_, f)| f.len() >= 196 && f[34..36] == [3, 0] && f[43] == 7 && f[65] == 1);
            if peer.is_none_or(|(_, f)| f[188..196] != [9, 0, 8, 0, 103, 0, 0, 0] || f[184] != 1) {
                return TestResult::Fail("HT40/SGI40 native peer or independent SMPS");
            }
            let domain = frames.iter().find(|(_, f)| f.len() == 92 && f[36] == 15);
            if domain.is_none_or(|(_, f)| {
                f[68 + usize::from(band)] != 0
                    || f[72 + usize::from(band)] != 2
                    || f[76] != primary
                    || f[84] != secondary
            }) {
                return TestResult::Fail("native40MHz domain did not admit both occupied channels");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht40",
    mt76_ht40_native_domain_channel_rlm_peer_and_response_geometry
);

fn mt76_ht40_response_narrows_native_geometry_and_failed_receipts_keep_rx_closed() -> TestResult {
    let (mut baseline, bss) = prepared(6, 10, false);
    if run(baseline.associate_station(&bss, b"narf", Security::Open, permission40(6, 10), &[]))
        .is_err()
    {
        return TestResult::Fail("HT40 baseline");
    }
    let rlm = baseline
        .backend
        .frames
        .iter()
        .position(|(_, f)| f.len() == 68 && f[34..36] == [2, 0] && f[52..56] == [2, 0, 16, 0])
        .unwrap();
    for case in 0..3 {
        let (mut session, bss) = prepared(6, 10, false);
        if case == 0 {
            session.backend.ht_reply.as_mut().unwrap()[31] = 0;
            if run(session.associate_station(
                &bss,
                b"narf",
                Security::Open,
                permission40(6, 10),
                &[],
            )) != Ok(42)
                || session
                    .ht20_profile
                    .is_none_or(|p| p.negotiated_secondary().is_some())
                || !session.backend.frames.iter().any(|(_, f)| {
                    f.len() >= 140 && f[36] == 0xed && f[41] == 8 && f[64..69] == [6, 6, 0, 2, 2]
                })
                || !session.backend.frames.iter().any(|(_, f)| {
                    f.len() == 68
                        && f[34..36] == [2, 0]
                        && f[52..56] == [2, 0, 16, 0]
                        && f[56..62] == [6, 6, 0, 0, 2, 3]
                })
            {
                return TestResult::Fail("AP20MHz downgrade inherited40MHz state");
            }
            if run(session.disassociate_station()).is_err() {
                return TestResult::Fail("actual response20 native teardown");
            }
            continue;
        } else if case == 1 {
            session.backend.deny_tx_after = Some(rlm + 1);
            if run(session.associate_station(
                &bss,
                b"narf",
                Security::Open,
                permission40(6, 10),
                &[],
            )) != Err(Error::Authority)
            {
                return TestResult::Fail("HT40 RLM receipt bypassed current authority");
            }
        } else {
            session.backend.tx_stall_after = Some(rlm + 1);
            let mut future = pin!(session.associate_station(
                &bss,
                b"narf",
                Security::Open,
                permission40(6, 10),
                &[]
            ));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("native HT40 cancellation did not suspend");
            }
        }
        if session.ht20_profile.is_some()
            || session.ht20_rx.as_ref().is_some_and(|rx| rx.active)
            || matches!(session.state, State::Associated { .. })
            || !session.backend.owner.published
        {
            return TestResult::Fail("failed/cancelled HT40 retained active peer or released DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht40",
    mt76_ht40_response_narrows_native_geometry_and_failed_receipts_keep_rx_closed
);
