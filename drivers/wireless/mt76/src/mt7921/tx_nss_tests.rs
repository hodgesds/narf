//! Native firmware NSS facts, response-bounded maps and actual two-path setup.
use super::*;
use crate::mt7921::association::{Security, TxPermission};

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Ht20,
    Ht40,
    Vht(u8),
}
const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(super) fn prepared(
    mode: Mode,
    nss: u8,
    secure: bool,
) -> (Session<Model>, ScanBss, TxPermission) {
    let chip = if matches!(mode, Mode::Vht(3)) {
        0x7922
    } else {
        0
    };
    let phy = [1, 1, 1, 2, nss, 0, 1, 1, 1, 1, 3, 1];
    let (mut s, mut b) = wmm_tests::prepared_with_phy(true, secure, chip, Some(phy));
    b.channel = if matches!(mode, Mode::Vht(_)) { 36 } else { 6 };
    s.backend.station_channel = b.channel;
    let mut offset = 0;
    while offset < b.information_elements.len() {
        if b.information_elements[offset] == 3 {
            b.information_elements[offset + 2] = b.channel;
        }
        offset += 2 + usize::from(b.information_elements[offset + 1]);
    }
    let (ht, vht, domain) = match mode {
        Mode::Ht20 | Mode::Ht40 => (
            ht20_tests::elements(6),
            Vec::new(),
            narf_wireless::reg::RegulatoryDomain {
                country_code: *b"US",
                rules: vec![narf_wireless::reg::RegRule {
                    freq_start_mhz: 2402,
                    freq_end_mhz: 2472,
                    max_bandwidth_mhz: if matches!(mode, Mode::Ht40) { 40 } else { 20 },
                    max_power_dbm: 17,
                    flags: narf_wireless::reg::RegFlags::empty(),
                }],
            },
        ),
        Mode::Vht(3) => {
            let (h, v) = vht160_tests::elements(36, 50, true);
            (h, v, vht160_tests::domain())
        }
        Mode::Vht(w) => {
            let (h, v) = vht_tests::full_elements(w, 36);
            (h, v, vht_tests::domain())
        }
    };
    s.backend.ht_reply = Some(ht.clone());
    b.information_elements.extend_from_slice(&ht);
    if !vht.is_empty() {
        s.backend.vht_reply = Some(vht.clone());
        b.information_elements.extend_from_slice(&vht);
    }
    let State::RadioReady(info) = s.state else {
        panic!("native NSS radio")
    };
    let p = TxPermission::from_ap(&domain, info, &b).unwrap();
    (s, b, p)
}
pub(super) fn join(
    s: &mut Session<Model>,
    b: &ScanBss,
    p: TxPermission,
    secure: bool,
) -> Result<u16, Error> {
    run(s.associate_station(
        b,
        b"narf",
        if secure {
            Security::Wpa2Psk { psk: [0x55; 32] }
        } else {
            Security::Open
        },
        p,
        &[],
    ))
}
fn switch(f: &[u8]) -> bool {
    f.len() >= 140 && f[36] == 0xed && f[41] == 8
}
fn command(f: &[u8], id: u8) -> bool {
    f.len() >= 64 && f[36] == id && f[37] == 0xa0
}
pub(super) fn associated(s: &Session<Model>) -> &[u8] {
    &s.backend
        .frames
        .iter()
        .rev()
        .find(|(_, f)| {
            f.len() >= 196
                && f[34..36] == [3, 0]
                && f[49] == 1
                && f[52] == 1
                && vht_tests::record(f, 0)
                    .is_some_and(|b| b.len() == 20 && b[10..12] == 42u16.to_le_bytes())
        })
        .unwrap()
        .1
}
fn rlm(s: &Session<Model>) -> &[u8] {
    &s.backend
        .frames
        .iter()
        .rev()
        .find(|(_, f)| f.len() == 68 && f[34..36] == [2, 0] && f[52..56] == [2, 0, 16, 0])
        .unwrap()
        .1
}
fn ether() -> Vec<u8> {
    let mut f = vec![0; 60];
    f[..6].copy_from_slice(&AP);
    f[6..12].copy_from_slice(&OWN);
    f[12..14].copy_from_slice(&[8, 0]);
    f
}
fn mcsmask(b: &mut [u8], second: u8) {
    let mut o = 0;
    while o < b.len() {
        if b[o] == 45 {
            b[o + 6] = second;
        }
        o += 2 + usize::from(b[o + 1]);
    }
}
fn vhtmap(b: &mut [u8], map: u16) {
    let mut o = 0;
    while o < b.len() {
        if b[o] == 191 {
            b[o + 6..o + 8].copy_from_slice(&map.to_le_bytes());
        }
        o += 2 + usize::from(b[o + 1]);
    }
}
fn smps(b: &mut [u8], bits: u8) {
    let mut o = 0;
    while o < b.len() {
        if b[o] == 45 {
            b[o + 2] = (b[o + 2] & !12) | bits;
        }
        o += 2 + usize::from(b[o + 1]);
    }
}

fn mt76_tx_nss2_native_chain_sku_peer_maps_and_controlled_data() -> TestResult {
    for mode in [
        Mode::Ht20,
        Mode::Ht40,
        Mode::Vht(0),
        Mode::Vht(1),
        Mode::Vht(2),
        Mode::Vht(3),
    ] {
        for secure in [false, true] {
            let (mut s, b, p) = prepared(mode, 2, secure);
            if join(&mut s, &b, p, secure) != Ok(42) {
                return TestResult::Fail("real NSS2 native association");
            }
            let switches = s
                .backend
                .frames
                .iter()
                .filter(|(_, f)| switch(f))
                .map(|(_, f)| f)
                .collect::<Vec<_>>();
            let last = switches.last().unwrap();
            if switches.len() < 2
                || switches[0][67] != 1
                || last[67..69] != [2, 2]
                || rlm(&s)[60..62] != [2, 3]
                || s.ht20_profile.unwrap().transmit_streams() != 2
            {
                return TestResult::Fail(
                    "NSS2 radio count, RX count/mask or actual post-response switch",
                );
            }
            let peer = associated(&s);
            if vht_tests::record(peer, 1).unwrap()[6..16] != [255, 255, 0, 0, 0, 0, 0, 0, 0, 0] {
                return TestResult::Fail("native STA_REC_RA did not retain MCS8..15");
            }
            if let Mode::Vht(width) = mode {
                let expected = if width == 0 { 0xfff5u16 } else { 0xfffa };
                if vht_tests::record(peer, 10).unwrap()[8..10] != expected.to_le_bytes()
                    || vht_tests::record(peer, 7).unwrap()[9] != width | 16
                {
                    return TestResult::Fail("native VHT width-valid TX2 map/peer NSS");
                }
            }
            let mut power = 0;
            for (_, f) in &s.backend.frames {
                if command(f, 0x5d) {
                    power += 1;
                    for row in f[108..].chunks_exact(162) {
                        if row[1..].iter().any(|v| *v != 28) {
                            return TestResult::Fail("two-path host headroom absent from SKU");
                        }
                    }
                }
            }
            if power < 2
                || run(s.send_ethernet(&ether())).is_err()
                || s.backend.data_protection.last() != Some(&secure)
            {
                return TestResult::Fail("NSS2 original native DATA/key ownership");
            }
            run(s.disassociate_station()).unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_tx_nss2_native_chain_sku_peer_maps_and_controlled_data
);

fn mt76_tx_nss1_hardware_never_promotes_from_ap_two_stream_offer() -> TestResult {
    for mode in [Mode::Ht20, Mode::Ht40, Mode::Vht(2), Mode::Vht(3)] {
        let (mut s, b, p) = prepared(mode, 1, true);
        if join(&mut s, &b, p, true) != Ok(42) {
            return TestResult::Fail("native single-chain association");
        }
        if s.backend
            .frames
            .iter()
            .filter(|(_, f)| switch(f))
            .any(|(_, f)| f[67] != 1 || f[68] != 1)
            || rlm(&s)[60..62] != [1, 1]
            || vht_tests::record(associated(&s), 1).unwrap()[7..16] != [0; 9]
            || s.backend
                .frames
                .iter()
                .filter(|(_, f)| command(f, 0x5d))
                .any(|(_, f)| f[109..270].iter().any(|v| *v != 34))
        {
            return TestResult::Fail(
                "AP/PCI alias promoted actual NIC NSS1 or lowered its single-path table",
            );
        }
        run(s.disassociate_station()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_tx_nss1_hardware_never_promotes_from_ap_two_stream_offer
);

fn mt76_tx_nss2_scan_and_response_bounds_preserve_single_stream_selection() -> TestResult {
    for scan_only in [false, true] {
        let (mut s, mut b, p) = prepared(Mode::Vht(2), 2, true);
        if scan_only {
            mcsmask(&mut b.information_elements, 0);
            vhtmap(&mut b.information_elements, 0xfffe);
        } else {
            mcsmask(s.backend.ht_reply.as_mut().unwrap(), 0);
            vhtmap(s.backend.vht_reply.as_mut().unwrap(), 0xfffe);
        }
        if join(&mut s, &b, p, true) != Ok(42)
            || rlm(&s)[60] != 1
            || s.backend
                .frames
                .iter()
                .filter(|(_, f)| switch(f))
                .any(|(_, f)| f[67] != 1)
            || vht_tests::record(associated(&s), 1).unwrap()[7..16] != [0; 9]
            || vht_tests::record(associated(&s), 10).unwrap()[8..10] != 0xfffeu16.to_le_bytes()
        {
            return TestResult::Fail(
                "response enabled omitted TX NSS or failed actual peer RX1 fallback",
            );
        }
        run(s.disassociate_station()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_tx_nss2_scan_and_response_bounds_preserve_single_stream_selection
);

fn mt76_tx_nss2_static_smps_is_single_dynamic_and_disabled_are_native() -> TestResult {
    for bits in [0, 4, 12] {
        let (mut s, mut b, p) = prepared(Mode::Vht(2), 2, false);
        smps(&mut b.information_elements, bits);
        smps(s.backend.ht_reply.as_mut().unwrap(), bits);
        let expected = if bits == 0 { 1 } else { 2 };
        if join(&mut s, &b, p, false) != Ok(42)
            || rlm(&s)[60] != expected
            || s.ht20_profile.unwrap().transmit_streams() != expected
            || vht_tests::record(associated(&s), 7).unwrap()[9] != 2 | ((expected - 1) << 4)
        {
            return TestResult::Fail(
                "native SMPS or peer NSS allowed unsupported spatial transmission",
            );
        }
        run(s.disassociate_station()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_tx_nss2_static_smps_is_single_dynamic_and_disabled_are_native
);

fn mt76_tx_nss2_power_headroom_occupied_rows_and_native_lower_bound() -> TestResult {
    let mut domain = vht160_tests::domain();
    domain.rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 5310,
        freq_end_mhz: 5330,
        max_bandwidth_mhz: 160,
        max_power_dbm: 13,
        flags: narf_wireless::reg::RegFlags::empty(),
    });
    let p = TxPermission::from_domain160(&domain, 36, 50).unwrap();
    let b = p.rate_limits_for_paths(2).unwrap();
    if b[4] != 8
        || b[44..]
            .chunks_exact(162)
            .zip([36, 40, 44, 48, 52, 56, 60, 64])
            .any(|(r, c)| r[0] != c || r[1..].iter().any(|v| *v != 20))
    {
        return TestResult::Fail(
            "remote constituent's lowest EIRP/headroom not applied to all native rows",
        );
    }
    for (dbm, expected) in [
        (-61, Some(128u8)),
        (-62, None),
        (0, Some(250)),
        (63, Some(120)),
    ] {
        domain.rules.truncate(1);
        domain.rules[0].max_power_dbm = dbm;
        let p = TxPermission::from_domain160(&domain, 36, 50).unwrap();
        let native = p.rate_limits_for_paths(2);
        if native.as_ref().map(|v| v[45]) != expected
            || p.rate_limits_for_paths(0).is_some()
            || p.rate_limits_for_paths(3).is_some()
        {
            return TestResult::Fail(
                "native signed two-path ceiling wrapped or invented an RF path",
            );
        }
    }
    let (mut s, b, mut p) = prepared(Mode::Ht20, 2, false);
    p.power_dbm = -62;
    let before = s.backend.frames.len();
    if join(&mut s, &b, p, false) != Err(Error::Bounds) || s.backend.frames.len() != before {
        return TestResult::Fail("unrepresentable NSS2 power reached native setup/publication");
    }
    let mut domain = vht_tests::domain();
    domain.rules[0].max_power_dbm = -62;
    let (mut s, _) = wmm_tests::prepared(true, false);
    let before = s.backend.frames.len();
    if !matches!(
        run(s.scan_active_with_policy(&[36], &[b"narf".to_vec()], || Ok(domain.clone()))),
        Err(Error::Bounds)
    ) || s.backend.frames.len() != before
        || !matches!(s.state, State::RadioReady(_))
    {
        return TestResult::Fail("unrepresentable NSS2 scan ceiling reached native scan setup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_tx_nss2_power_headroom_occupied_rows_and_native_lower_bound
);

fn mt76_tx_nss2_native_switch_cancellation_and_each_enable_policy_fence() -> TestResult {
    let (mut baseline, b, p) = prepared(Mode::Vht(2), 2, true);
    join(&mut baseline, &b, p, true).unwrap();
    let at = baseline
        .backend
        .frames
        .iter()
        .position(|(_, f)| switch(f) && f[67] == 2)
        .unwrap();
    for limit in [at, at + 1, at + 2] {
        let (mut s, b, p) = prepared(Mode::Vht(2), 2, true);
        s.backend.deny_tx_after = Some(limit);
        if join(&mut s, &b, p, true) != Err(Error::Authority)
            || matches!(s.state, State::Associated { .. })
            || s.receive_current(s.receive_epoch) != Ok(false)
            || !s.backend.data_qos.is_empty()
            || limit == at
                && s.backend
                    .frames
                    .iter()
                    .any(|(_, f)| switch(f) && f[67] == 2)
        {
            return TestResult::Fail(
                "NSS2 native enable lost current permission or published an authorized port",
            );
        }
    }
    let (mut s, b, p) = prepared(Mode::Vht(2), 2, true);
    s.backend.tx_stall_after = Some(at + 1);
    {
        let mut future =
            pin!(s.associate_station(&b, b"narf", Security::Wpa2Psk { psk: [0x55; 32] }, p, &[]));
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("NSS2 switch did not reach native held DMA");
        }
    }
    if s.state != State::Running(Stage::Associate)
        || s.receive_current(s.receive_epoch) != Ok(false)
        || s.start_ethernet(&ether()) != Err(Error::Busy)
        || !s.backend.owner.published
    {
        return TestResult::Fail(
            "cancelled NSS2 configuration reopened DATA or freed native ownership",
        );
    }
    let resources = s.backend.resources.clone();
    drop(s);
    if resources.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("cancelled NSS2 setup released published DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_tx_nss2_native_switch_cancellation_and_each_enable_policy_fence
);

fn mt76_tx_nss2_ht_basic_mcs8_receiver_and_legacy_fallback_are_distinct() -> TestResult {
    for nss in [1, 2] {
        let (mut s, mut b, p) = prepared(Mode::Ht20, nss, true);
        // Basic-MCS8 is an actual required receive rate, independently of
        // the peer TX map and its SMPS constraint on our transmitter.
        for ies in [
            b.information_elements.as_mut_slice(),
            s.backend.ht_reply.as_mut().unwrap().as_mut_slice(),
        ] {
            let mut offset = 0;
            while offset < ies.len() {
                if ies[offset] == 61 {
                    ies[offset + 9] = 1;
                }
                offset += 2 + usize::from(ies[offset + 1]);
            }
        }
        let result = join(&mut s, &b, p, true);
        if nss == 1 {
            if result.is_ok() || matches!(s.state, State::Associated { .. }) {
                return TestResult::Fail("one-path NIC admitted mandatory HT MCS8");
            }
        } else if result != Ok(42) || s.ht20_rx.as_ref().is_none_or(|r| !r.active) {
            return TestResult::Fail(
                "qualified HT RX2/basic-MCS8 failed native receiver activation",
            );
        }
    }
    let (mut s, b) = wmm_tests::prepared(true, false);
    if join(&mut s, &b, test_permission_for(b.channel), false) != Ok(42)
        || s.ht20_profile.is_some()
        || s.backend
            .frames
            .iter()
            .any(|(_, f)| switch(f) && f[67] != 1)
    {
        return TestResult::Fail("legacy peer acquired HT or two native transmit paths");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_tx_nss2_ht_basic_mcs8_receiver_and_legacy_fallback_are_distinct
);

fn mt76_typed_ht_native_cck_band_and_metadata_bounds_precede_ccmp_pn() -> TestResult {
    for channel in [6, 36] {
        let (mut s, b) = ht20_tests::prepared(channel, true);
        if join(&mut s, &b, test_permission_for(channel), true) != Ok(42) {
            return TestResult::Fail("typed HT legacy-rate station setup");
        }
        let mut pn = 9;
        for (rate, nsts, width, extra) in [
            (0, 1, 0u8, 0),
            (1, 1, 0, 0),
            (2, 1, 0, 0),
            (3, 1, 0, 0),
            (4, 1, 0, 0),
            (5, 1, 0, 0),
            (6, 1, 0, 0),
            (7, 1, 0, 0),
            (8, 1, 0, 0),
            (0, 2, 0, 0),
            (0, 1, 1, 0),
            (0, 1, 0, 1 << 11),
            (0, 1, 0, 1 << 15),
            (0, 1, 0, 1 << 22),
        ] {
            let mut packet = vht_tests::data(true, 0, rate, nsts, pn);
            packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
            let rxv =
                u32::from(rate) | (u32::from(nsts - 1) << 7) | (u32::from(width) << 12) | extra;
            packet[40..44].copy_from_slice(&rxv.to_le_bytes());
            s.backend.packets.push_back(packet);
            let admitted = channel == 6 && rate < 8 && nsts == 1 && width == 0 && extra == 0;
            if s.receive_ethernet().ok().flatten().is_some() != admitted {
                return TestResult::Fail(
                    "typed HT admitted wrong-band/invalid CCK or refused native legacy RX",
                );
            }
            if admitted {
                pn += 1;
            }
            // A valid HT packet with the next unconsumed PN proves rejected
            // native metadata cannot poison the current per-TID replay floor.
            let mut retry = vht_tests::data(true, 0, 7, 1, pn);
            retry[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
            retry[40..44].copy_from_slice(&((2u32 << 24) | (1 << 15) | 7).to_le_bytes());
            s.backend.packets.push_back(retry);
            if s.receive_ethernet().ok().flatten().is_none() {
                return TestResult::Fail("invalid legacy PHY consumed PN or damaged typed HT RX");
            }
            pn += 1;
        }
        run(s.disassociate_station()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_typed_ht_native_cck_band_and_metadata_bounds_precede_ccmp_pn
);

/// Set the AP's HT RX STBC (bits 8..9) and VHT RXSTBC (bits 8..10) to one
/// stream in every capability element.
fn peer_rx_stbc(b: &mut [u8]) {
    let mut o = 0;
    while o + 4 <= b.len() {
        if matches!(b[o], 45 | 191) {
            b[o + 3] = (b[o + 3] & !7) | 1;
        }
        o += 2 + usize::from(b[o + 1]);
    }
}

fn mt76_tx_stbc_follows_stream_count_and_peer_rx_stbc_into_sta_records() -> TestResult {
    for nss in [1, 2] {
        for mode in [Mode::Ht20, Mode::Vht(2)] {
            for peer in [false, true] {
                let (mut s, mut b, p) = prepared(mode, nss, false);
                let State::RadioReady(info) = s.state else {
                    unreachable!()
                };
                // mt76_init_stream_cap: TX_STBC (HT bit7) / TXSTBC (VHT bit7)
                // exactly when more than one TX stream exists.
                let local_ht = crate::mt7921::vht::ht_capability(info);
                if (local_ht[0] & 0x80 != 0) != (nss == 2)
                    || crate::mt7921::vht::capability(info)
                        .is_some_and(|vht| (vht[0] & 0x80 != 0) != (nss == 2))
                {
                    return TestResult::Fail("local TX STBC advertisement ignores TX streams");
                }
                if peer {
                    peer_rx_stbc(&mut b.information_elements);
                    if let Some(reply) = s.backend.ht_reply.as_mut() {
                        peer_rx_stbc(reply);
                    }
                    if let Some(reply) = s.backend.vht_reply.as_mut() {
                        peer_rx_stbc(reply);
                    }
                }
                if join(&mut s, &b, p, false) != Ok(42) {
                    return TestResult::Fail("TX STBC fixture association");
                }
                let record = associated(&s);
                let expected = nss == 2 && peer;
                let ht = vht_tests::record(record, 9).unwrap();
                if (u16::from_le_bytes([ht[4], ht[5]]) & 0x0300 == 0x0100) != expected
                    || u16::from_le_bytes([ht[4], ht[5]]) & 0x0300 & !0x0100 != 0
                    || s.ht20_profile.unwrap().transmit_stbc() != expected
                {
                    return TestResult::Fail("STA_REC_HT RX STBC not masked by local TX STBC");
                }
                if matches!(mode, Mode::Vht(_)) {
                    let vht = vht_tests::record(record, 10).unwrap();
                    let cap = u32::from_le_bytes(vht[4..8].try_into().unwrap());
                    if (cap & 0x0700 == 0x0100) != expected || cap & 0x0700 & !0x0100 != 0 {
                        return TestResult::Fail("STA_REC_VHT RXSTBC not masked by local TXSTBC");
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/nss",
    mt76_tx_stbc_follows_stream_count_and_peer_rx_stbc_into_sta_records
);
