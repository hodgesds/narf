// SPDX-License-Identifier: GPL-2.0-or-later
//! Noninitial 2.4GHz/20MHz channel programs and signed-record admission.
use super::radio_tests::RadioIo;
use super::Io;
use crate::rtw88::{
    channel_policy::{self, Record},
    qualification::PAYLOAD,
    radio, radio8821c,
};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};

fn payload(channel: u8, c22: bool) -> [u8; PAYLOAD] {
    let mut p = [0; PAYLOAD];
    p[0] = channel;
    p[1] = 20;
    for (at, v) in [(2, 4i16), (4, 76), (6, 40), (8, 40), (10, 44)] {
        p[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    if c22 {
        p[12..14].copy_from_slice(&[36, 32]);
    } else {
        p[14..26].copy_from_slice(&[30, 30, 30, 30, 28, 28, 28, 28, 26, 26, 26, 26]);
    }
    p
}

fn domain(start: u32, end: u32, dbm: i8, flags: RegFlags) -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: 40,
            max_power_dbm: dbm,
            flags,
        }],
    }
}

fn smoke_rtw88_channel_policy_linux_groups_bb_rf_and_probe_ds() -> TestResult {
    // phy.c::rtw_get_channel_group and ieee80211 2.4GHz frequencies.
    let groups: [usize; 13] = [0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4];
    for (i, g) in groups.iter().enumerate() {
        let ch = i as u8 + 1;
        if channel_policy::group(ch) != Some(*g)
            || channel_policy::frequency(ch) != Some(2407 + 5 * u16::from(ch))
        {
            return TestResult::Fail("channel group/frequency differs from Linux");
        }
    }
    if channel_policy::group(14).is_some() || channel_policy::group(0).is_some() {
        return TestResult::Fail("channel 14 or 0 admitted");
    }
    // rtw8822c_set_channel_bb SCOTRK and TXDFIR0 per primary.
    for (ch, sco, dfir) in [(1, 0x9aa, 1), (6, 0x9aa, 1), (11, 0x96a, 1), (12, 0x96a, 1)]
        .into_iter()
        .chain([(13, 0x969, 3)])
    {
        if channel_policy::scotrk(ch) != sco || channel_policy::txdfir(ch) != dfir {
            return TestResult::Fail("SCOTRK/TXDFIR table differs from rtw8822c_set_channel_bb");
        }
        let mut io = RadioIo::reference();
        if narf_scheduler::block_on(radio::channel_to(&mut io, ch)).is_err() {
            return TestResult::Fail("channel program rejected an admitted primary");
        }
        let ok = (|| -> Result<bool, crate::rtw88::firmware_transport::Error> {
            Ok(radio::read(&mut io, 0xc30)? & 0xfff == sco
                && (radio::read(&mut io, 0x808)? >> 4) & 7 == dfir
                && radio::rf_read(&mut io, 1, 0x18)? & 0x733ff == 0x3000 | u32::from(ch))
        })();
        if ok != Ok(true) {
            return TestResult::Fail("BB/RF readback is not the requested primary");
        }
    }
    for ch in [0, 14, 36] {
        let mut io = RadioIo::reference();
        if narf_scheduler::block_on(radio::channel_to(&mut io, ch)).is_ok() {
            return TestResult::Fail("unadmitted primary programmed");
        }
    }
    let probe = crate::rtw88::scan::probe([2, 4, 6, 8, 10, 12], b"lab", &[]).unwrap();
    let tuned = channel_policy::probe_for(&probe, 6).unwrap();
    let ds = tuned.windows(3).position(|w| w == [3, 1, 6]);
    if ds.is_none()
        || tuned.len() != probe.len()
        || tuned.iter().zip(&probe).filter(|(a, b)| a != b).count() != 1
        || channel_policy::probe_for(&probe, 14).is_some()
    {
        return TestResult::Fail("probe DS parameter not rewritten to the scanned primary");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_channel_policy_linux_groups_bb_rf_and_probe_ds
);

fn smoke_rtw88_channel_record_admission_and_regulatory_span() -> TestResult {
    let c22 = payload(6, true);
    let c21 = payload(6, false);
    let Some(r22) = Record::decode(0xc822, &c22) else {
        return TestResult::Fail("valid C22 record refused");
    };
    if Record::decode(0xc821, &c22).is_some()
        || Record::decode(0xc822, &c21).is_some()
        || Record::decode(0xc821, &c21).map(|r| r.indices[0]) != Some(30)
    {
        return TestResult::Fail("chip-specific TX power fields not enforced");
    }
    let mut bad = c22;
    bad[0] = 1;
    let mut wide = c22;
    wide[1] = 40;
    let mut tail = c22;
    tail[40] = 1;
    let mut fourteen = c22;
    fourteen[0] = 14;
    if [bad, wide, tail, fourteen]
        .iter()
        .any(|p| Record::decode(0xc822, p).is_some())
    {
        return TestResult::Fail("record with base/other width/nonzero tail/ch14 admitted");
    }
    // Each kind admits only its own primary.
    let six = channel_policy::kind(6).unwrap();
    let seven = channel_policy::kind(7).unwrap();
    if !(six.admit)(0xc822, &c22)
        || (seven.admit)(0xc822, &c22)
        || six.tag != b'O'
        || six.stem != "channel06"
        || channel_policy::kind(1).is_some()
        || channel_policy::kind(14).is_some()
    {
        return TestResult::Fail("per-channel kind identity/admission is not exact");
    }
    // US-like 2402..2472: channel 6 and 11 covered, 12/13 spans exceed it.
    let us = domain(2402, 2472, 30, RegFlags::empty());
    if channel_policy::policy(&r22, &us) != Ok(76) {
        return TestResult::Fail("covered primary not admitted at the record ceiling");
    }
    for ch in [11, 12, 13] {
        let r = Record { channel: ch, ..r22 };
        if channel_policy::policy(&r, &us).is_ok() != (ch == 11) {
            return TestResult::Fail("occupied span not checked against the rule");
        }
    }
    let low = domain(2402, 2472, 10, RegFlags::empty());
    let flagged = domain(2402, 2472, 30, RegFlags::NO_IR);
    if channel_policy::policy(&r22, &low).is_ok() || channel_policy::policy(&r22, &flagged).is_ok()
    {
        return TestResult::Fail("peaks over the ceiling or a restricted rule admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_channel_record_admission_and_regulatory_span
);

fn smoke_rtw8821ce_retune_txagc_and_rf18_readback() -> TestResult {
    let indices = [30, 30, 30, 30, 28, 28, 28, 28, 26, 26, 26, 26];
    let mut io = RadioIo::new();
    let setup = (|| {
        io.write32(0x2860, 0xc06)?;
        io.write32(0x440, 0x1f)?;
        io.write32(0x1bf0, 0)?;
        radio8821c::write_txagc(&mut io, indices)
    })();
    if setup.is_err() {
        return TestResult::Fail("C21 TXAGC write rejected");
    }
    if radio8821c::verify_retune(&mut io, 6, indices).is_err() {
        return TestResult::Fail("C21 retune readback refused the programmed primary");
    }
    let mut other = indices;
    other[0] = 31;
    if radio8821c::verify_retune(&mut io, 7, indices).is_ok()
        || radio8821c::verify_retune(&mut io, 6, other).is_ok()
    {
        return TestResult::Fail("C21 retune readback accepted another channel or power");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8821ce_retune_txagc_and_rf18_readback
);

fn smoke_rtw8821ce_operating_readback_rf18_tracks_primary() -> TestResult {
    // rtw8821c_set_channel_rf: band | RFSI | BW | channel under 0x70fff.
    if radio8821c::rf18_for(1, 20) != 0xc01
        || radio8821c::rf18_for(6, 20) != 0xc06
        || radio8821c::rf18_for(6, 40) != 0x806
        || radio8821c::rf18_for(36, 20) != 0x10d24
        || radio8821c::rf18_for(100, 20) != 0x30d64
        || radio8821c::rf18_for(149, 20) != 0x50d95
        || radio8821c::rf18_for(42, 80) != 0x1052a
    {
        return TestResult::Fail("C21 RF18 encoding differs from rtw8821c_set_channel_rf");
    }
    let indices = [30, 30, 30, 30, 28, 28, 28, 28, 26, 26, 26, 26];
    let mcs = [24; 8];
    let mut io = RadioIo::new();
    let setup = (|| {
        io.write32(0x2860, 0xc06)?;
        radio8821c::write_txagc(&mut io, indices)?;
        io.write32(0x1d0c, u32::from_le_bytes([24; 4]))?;
        io.write32(0x1d10, u32::from_le_bytes([24; 4]))
    })();
    if setup.is_err() {
        return TestResult::Fail("C21 operating fixture rejected");
    }
    let mut read = |r: u16| io.read32(r);
    if radio8821c::operating_readback_ht(&mut read, indices, mcs, 6).is_err() {
        return TestResult::Fail("C21 HT20 readback refused the committed noninitial primary");
    }
    if radio8821c::operating_readback_ht(&mut read, indices, mcs, 1).is_ok() {
        return TestResult::Fail("C21 HT20 readback accepted channel 1 RF18 on channel 6");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8821ce_operating_readback_rf18_tracks_primary
);

fn smoke_rtw88_channel_scoped_filenames_and_group_ht_ceilings() -> TestResult {
    // Channel-scoped continuation records never share a channel-1 name.
    let base = "rtw88/rtw8822ce-ht20-v1-001122334455.bin";
    if channel_policy::scoped_filename(base, 1) != base
        || channel_policy::scoped_filename(base, 6)
            != "rtw88/rtw8822ce-ch06-ht20-v1-001122334455.bin"
        || channel_policy::scoped_filename("rtw88/rtw8821ce-legacy-wmm-v1-00.bin", 13)
            != "rtw88/rtw8821ce-ch13-legacy-wmm-v1-00.bin"
    {
        return TestResult::Fail("channel-scoped filename is not distinct per primary");
    }
    // phy.c::rtw_phy_get_2g_tx_power_index HT20 1S/2S: bw40_base[group]
    // (bytes 6..11) plus the signed differences at bytes 11/12.
    let mut p = [0u8; 13];
    p[6..11].copy_from_slice(&[40, 42, 44, 46, 48]);
    p[11] = 0xe0; // HT20 1S diff -2 (high nibble), OFDM diff 0
    p[12] = 0x0f; // HT20 2S diff -1 (low nibble)
    use crate::rtw88::ht;
    for group in 0..5 {
        let base = 40 + 2 * group as i16;
        if ht::factory_limit_group(&p, group, 2, 127) != Some((base - 4) as u8)
            || ht::factory_limit_group(&p, group, 1, 63) != Some((base - 2) as u8)
            || ht::factory_limit_2ss_group(&p, group) != Some((base - 6) as u8)
        {
            return TestResult::Fail("HT20 factory ceiling not taken from the channel's group");
        }
    }
    if ht::factory_limit(&p, 2, 127) != ht::factory_limit_group(&p, 0, 2, 127)
        || ht::factory_limit_group(&p, 5, 2, 127).is_some()
        || ht::factory_limit_2ss_group(&p, 5).is_some()
    {
        return TestResult::Fail("group0 alias or out-of-range group differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_channel_scoped_filenames_and_group_ht_ceilings
);

fn smoke_rtw88_channel_switch_announcement_parse() -> TestResult {
    use channel_policy::{switch_ie, SwitchIe};
    // SSID, DS(1), CSA mode1 -> 6 count3.
    let csa = [0, 3, b'l', b'a', b'b', 3, 1, 1, 37, 3, 1, 6, 3];
    // ECSA (class 81 -> 11, count 0) takes precedence over CSA.
    let both = [37, 3, 0, 6, 5, 60, 4, 0, 81, 11, 0];
    // ECSA in a 40MHz class (83) cannot be followed at 20MHz.
    let wide = [60, 4, 1, 83, 6, 2];
    if switch_ie(&csa)
        != Some(SwitchIe {
            block: true,
            channel: Some(6),
            count: 3,
        })
        || switch_ie(&both)
            != Some(SwitchIe {
                block: false,
                channel: Some(11),
                count: 0,
            })
        || switch_ie(&wide).map(|s| s.channel) != Some(None)
        || switch_ie(&[0, 3, b'l', b'a', b'b', 3, 1, 1]).is_some()
        || switch_ie(&[37, 2, 1, 6]).is_some()
    {
        return TestResult::Fail(
            "CSA/ECSA element parse differs from ieee80211_parse_ch_switch_ie",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_channel_switch_announcement_parse
);
