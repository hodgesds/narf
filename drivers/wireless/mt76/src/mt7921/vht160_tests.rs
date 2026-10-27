//! Actual-chip contiguous160 native records, occupied power and packet path.
use super::*;
use crate::mt7921::association::TxPermission;
pub(super) fn domain() -> narf_wireless::reg::RegulatoryDomain {
    let mut domain = super::vht_tests::domain();
    domain.rules[0].max_bandwidth_mhz = 160;
    domain
}
pub(super) fn elements(primary: u8, center: u8, revised: bool) -> (Vec<u8>, Vec<u8>) {
    let (ht, mut vht) = super::vht_tests::full_elements(2, primary);
    vht[2] |= 4 | 64; // Actual AP160/SGI160, not an extended-NSS encoding.
    let index = usize::from((primary - (center - 14)) / 4);
    vht[16] = if revised { 1 } else { 2 };
    vht[17] = if revised {
        if index < 4 {
            center - 8
        } else {
            center + 8
        }
    } else {
        center
    };
    vht[18] = if revised { center } else { 0 };
    (ht, vht)
}
fn prepared(
    primary: u8,
    center: u8,
    revised: bool,
    secure: bool,
    chip: u16,
) -> (Session<Model>, ScanBss, TxPermission) {
    let (mut session, mut bss) = super::wmm_tests::prepared_with_chip(true, secure, chip);
    session.backend.station_channel = primary;
    bss.channel = primary;
    let (ht, vht) = elements(primary, center, revised);
    session.backend.ht_reply = Some(ht.clone());
    session.backend.vht_reply = Some(vht.clone());
    let mut offset = 0;
    while offset < bss.information_elements.len() {
        if bss.information_elements[offset] == 3 {
            bss.information_elements[offset + 2] = primary;
        }
        offset += 2 + usize::from(bss.information_elements[offset + 1]);
    }
    bss.information_elements.extend_from_slice(&ht);
    bss.information_elements.extend_from_slice(&vht);
    let State::RadioReady(info) = session.state else {
        panic!("native160 capability initialization");
    };
    assert_eq!(info.chip_id, chip);
    let permission = TxPermission::from_ap(&domain(), info, &bss).unwrap();
    (session, bss, permission)
}
fn native() -> Result<(), &'static str> {
    for secure in [false, true] {
        for revised in [false, true] {
            for (primary, center) in [
                (36, 50),
                (64, 50),
                (100, 114),
                (128, 114),
                (149, 163),
                (177, 163),
            ] {
                let (mut session, bss, permission) =
                    prepared(primary, center, revised, secure, 0x7922);
                if permission.native_width() != 3
                    || permission.channels().len() != 8
                    || super::vht_tests::join(&mut session, &bss, permission, secure) != Ok(42)
                    || session
                        .vht_profile
                        .is_none_or(|profile| profile.width() != 3 || profile.center() != center)
                {
                    return Err("actual MT7922 full native160 association");
                }
                let frames = &session.backend.frames;
                if !frames.iter().any(|(_, f)| {
                    f.get(36) == Some(&0xed)
                        && f.get(41) == Some(&8)
                        && f.get(64..69) == Some(&[primary, center, 3, 1, 2][..])
                }) {
                    return Err("literal160 channel switch/count namespace");
                }
                let expected = [10, 0, 16, 0, 100, 0, 0, 1, 250, 255, 250, 255, 0, 0, 0, 0];
                if frames
                    .iter()
                    .find_map(|(_, frame)| super::vht_tests::record(frame, 10))
                    != Some(expected.as_slice())
                {
                    return Err("native160 STA width/GI/directional maps");
                }
                let request = frames
                    .iter()
                    .find(|(_, frame)| frame.first() == Some(&0))
                    .ok_or("native160 local association request")?;
                if !request
                    .1
                    .windows(14)
                    .any(|ie| ie == [191, 12, 116, 1, 0, 0, 250, 255, 0, 0, 250, 255, 0, 0])
                {
                    return Err("local actual-chip160 capability encoding");
                }
                let sku = frames
                    .iter()
                    .find(|(_, f)| f.get(36) == Some(&0x5d) && f.len() == 1404)
                    .ok_or("all eight native SKU channel rows")?;
                for (index, channel) in permission.channels().into_iter().enumerate() {
                    if sku.1[108 + index * 162] != channel
                        || sku.1[109 + index * 162..108 + (index + 1) * 162]
                            .iter()
                            .any(|&value| value != 28)
                    {
                        return Err("160 occupied-channel power row/ceiling");
                    }
                }
                // Native RXV applies to the actual PPDU width, including a
                // narrower20MHz MCS8 packet on the160MHz link.
                for width in 0..=3 {
                    let mut packet = super::vht_tests::data(
                        secure,
                        width,
                        if width == 0 { 8 } else { 9 },
                        2,
                        9 + u64::from(width),
                    );
                    packet[12..16].copy_from_slice(&(u32::from(primary) << 8).to_le_bytes());
                    session.backend.packets.push_back(packet);
                    if session.receive_ethernet().ok().flatten().is_none() {
                        return Err("native RX2/MCS8/9 actual160/narrower PPDU packet");
                    }
                }
                run(session.disassociate_station()).map_err(|_| "native160 key/peer retirement")?;
            }
        }
    }
    Ok(())
}
fn mt76_mt7922_native160_legacy_revised_records_eight_power_rows_and_rx2_packets() -> TestResult {
    native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht160",
    mt76_mt7922_native160_legacy_revised_records_eight_power_rows_and_rx2_packets
);

fn gates_and_narrowing() -> Result<(), &'static str> {
    for chip in [0, 0x7961, 0x7920, 0x0616] {
        let (mut session, bss, permission) = prepared(36, 50, true, false, chip);
        if permission.native_width() != 2
            || super::vht_tests::join(&mut session, &bss, permission, false) != Ok(42)
            || session
                .vht_profile
                .is_none_or(|profile| profile.width() != 2 || profile.center() != 42)
            || session.backend.frames.iter().any(|(_, f)| {
                f.get(36) == Some(&0xed) && f.get(41) == Some(&8) && f.get(66) == Some(&3)
            })
        {
            return Err("NIC max_bw or PCI alias promoted a non-MT7922 to160");
        }
    }
    let (mut session, bss, _) = prepared(36, 50, true, true, 0x7922);
    let State::RadioReady(info) = session.state else {
        return Err("160 policy fallback state");
    };
    let mut policy = domain();
    policy.rules[0].max_bandwidth_mhz = 80;
    let permission =
        TxPermission::from_ap(&policy, info, &bss).ok_or("160-to80 policy permission")?;
    if permission.native_width() != 2
        || super::vht_tests::join(&mut session, &bss, permission, true) != Ok(42)
        || session
            .vht_profile
            .is_none_or(|profile| profile.width() != 2)
    {
        return Err("160 radio could not select primary80 under current narrow policy");
    }
    let (mut session, bss, permission) = prepared(36, 50, true, true, 0x7922);
    let (ht, vht) = super::vht_tests::full_elements(2, 36);
    session.backend.ht_reply = Some(ht);
    session.backend.vht_reply = Some(vht);
    if super::vht_tests::join(&mut session, &bss, permission, true) != Ok(42)
        || session
            .station_permission
            .is_none_or(|permission| permission.native_width() != 2)
    {
        return Err("bound response160-to80 did not replace the occupied grant");
    }
    let switches: Vec<_> = session
        .backend
        .frames
        .iter()
        .enumerate()
        .filter(|(_, (_, f))| f.get(36) == Some(&0xed) && f.get(41) == Some(&8))
        .collect();
    let peer = session
        .backend
        .frames
        .iter()
        .position(|(_, f)| super::vht_tests::record(f, 10).is_some())
        .ok_or("narrowed160 peer record")?;
    if switches.len() != 2
        || switches[0].1 .1[66] != 3
        || switches[1].1 .1[66] != 2
        || switches[1].0 >= peer
    {
        return Err("native160 response retune did not precede peer/key/port");
    }
    Ok(())
}
fn mt76_mt7922_160_actual_chip_policy_primary80_fallback_and_response_retune() -> TestResult {
    gates_and_narrowing().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht160",
    mt76_mt7922_160_actual_chip_policy_primary80_fallback_and_response_retune
);

fn occupied_policy() -> Result<(), &'static str> {
    use narf_wireless::reg::{RegFlags, RegRule};
    for center in [50, 114, 163] {
        let expected: Vec<_> = (0..8).map(|index| center - 14 + 4 * index).collect();
        for primary in expected.iter().copied() {
            let mut policy = domain();
            let grant = TxPermission::from_domain160(&policy, primary, center)
                .ok_or("canonical160 occupied grant")?;
            let sku = grant.rate_limits();
            if grant.channels() != expected
                || grant.native_width() != 3
                || grant.domain_width() != 3
                || sku.len() != 1340
                || sku[4..7] != [8, 2, 1]
                || !grant.current(&policy)
            {
                return Err("160 literal eight-channel occupied namespace");
            }
            for width in 0..=3 {
                let new_center = match width {
                    0 => primary,
                    1 => {
                        if ((primary - expected[0]) / 4) & 1 == 0 {
                            primary + 2
                        } else {
                            primary - 2
                        }
                    }
                    2 => {
                        if primary < center {
                            center - 8
                        } else {
                            center + 8
                        }
                    }
                    _ => center,
                };
                if grant.narrow(width, new_center).is_none_or(|p| {
                    p.native_width() != width
                        || p.channels().iter().any(|ch| !expected.contains(ch))
                }) {
                    return Err("160 response subset lost the exact primary/HT pair");
                }
            }
            let edge = 5000 + 5 * u32::from(expected[7]) + 1;
            policy.rules.push(RegRule {
                freq_start_mhz: edge,
                freq_end_mhz: edge + 8,
                max_bandwidth_mhz: 160,
                max_power_dbm: 12,
                flags: RegFlags::empty(),
            });
            if grant.current(&policy)
                || TxPermission::from_domain160(&policy, primary, center)
                    .is_none_or(|p| p.power_dbm != 12 || p.rate_limits()[45] != 24)
            {
                return Err("outermost160 constituent failed to lower every power row");
            }
            for flags in [
                RegFlags::DFS,
                RegFlags::NO_IR,
                RegFlags::INDOOR_ONLY,
                RegFlags::from_bits_retain(16),
            ] {
                policy.rules[1].flags = flags;
                if grant.current(&policy)
                    || TxPermission::from_domain160(&policy, primary, center).is_some()
                {
                    return Err("160 erased an outer-only current restriction");
                }
            }
            policy.rules.truncate(1);
            policy.rules[0].freq_end_mhz = 5000 + 5 * u32::from(center) + 79;
            if grant.current(&policy)
                || TxPermission::from_domain160(&policy, primary, center).is_some()
            {
                return Err("160 accepted an incomplete occupied extent");
            }
        }
    }
    for (primary, center) in [(36, 42), (36, 82), (132, 146), (144, 163), (177, 171)] {
        if TxPermission::from_domain160(&domain(), primary, center).is_some() {
            return Err("noncanonical/discontinuous160 occupied grant");
        }
    }
    Ok(())
}
fn mt76_mt7922_160_all_primaries_power_overlap_extent_and_narrow_subsets() -> TestResult {
    occupied_policy().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht160",
    mt76_mt7922_160_all_primaries_power_overlap_extent_and_narrow_subsets
);

fn retirement_and_rx() -> Result<(), &'static str> {
    for (width, rate, nss) in [(4, 9, 1), (0, 9, 1), (0, 9, 2), (3, 9, 3), (3, 10, 1)] {
        let (mut session, bss, permission) = prepared(36, 50, true, true, 0x7922);
        if super::vht_tests::join(&mut session, &bss, permission, true) != Ok(42) {
            return Err("160 invalid-RXV reference join");
        }
        session
            .backend
            .packets
            .push_back(super::vht_tests::data(true, width, rate, nss, 9));
        if session.receive_ethernet() != Ok(None) {
            return Err("invalid actual160 PPDU admitted");
        }
        session
            .backend
            .packets
            .push_back(super::vht_tests::data(true, 3, 9, 2, 9));
        if session.receive_ethernet().ok().flatten().is_none() {
            return Err("invalid160 RXV consumed PN before a valid same-PN RX2 packet");
        }
        run(session.disassociate_station()).map_err(|_| "160 invalid-RXV retirement")?;
    }
    let (mut reference, bss, permission) = prepared(36, 50, true, true, 0x7922);
    if super::vht_tests::join(&mut reference, &bss, permission, true) != Ok(42) {
        return Err("160 cancellation reference join");
    }
    let first = reference
        .backend
        .frames
        .iter()
        .position(|(_, frame)| super::vht_tests::record(frame, 10).is_some())
        .ok_or("160 reference peer record")?;
    for cancel in [false, true] {
        let (mut session, bss, permission) = prepared(36, 50, true, true, 0x7922);
        if cancel {
            session.backend.tx_stall_after = Some(first + 1);
            {
                let mut future = pin!(session.associate_station(
                    &bss,
                    b"narf",
                    crate::mt7921::association::Security::Wpa2Psk { psk: [0x55; 32] },
                    permission,
                    &[]
                ));
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return Err("160 held native receipt did not suspend");
                }
            }
        } else {
            session.backend.ba_error_tag = Some(10);
            if super::vht_tests::join(&mut session, &bss, permission, true).is_ok() {
                return Err("rejected160 peer record accepted");
            }
        }
        if session.vht_profile.is_some()
            || session.ht20_rx.as_ref().is_some_and(|r| r.active)
            || matches!(session.state, State::Associated { .. })
            || !session.backend.owner.published
        {
            return Err("160 failure/cancellation reopened admission or freed uncertain DMA");
        }
    }
    for stage in [first, first + 1] {
        let (mut session, bss, permission) = prepared(36, 50, true, false, 0x7922);
        session.backend.deny_tx_after = Some(stage);
        if super::vht_tests::join(&mut session, &bss, permission, false) != Err(Error::Authority)
            || session.vht_profile.is_some()
            || session.station_permission.is_some()
        {
            return Err("160 native publication crossed current policy authority");
        }
    }
    Ok(())
}
fn mt76_mt7922_160_native_rejection_cancel_policy_and_invalid_rxv_before_pn() -> TestResult {
    retirement_and_rx().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/vht160",
    mt76_mt7922_160_native_rejection_cancel_policy_and_invalid_rxv_before_pn
);
