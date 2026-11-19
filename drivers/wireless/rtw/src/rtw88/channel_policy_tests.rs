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
            Ok(
                crate::rtw88::firmware_transport::now(radio::read(&mut io, 0xc30))? & 0xfff == sco
                    && (crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x808))? >> 4)
                        & 7
                        == dfir
                    && crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 1, 0x18))?
                        & 0x733ff
                        == 0x3000 | u32::from(ch),
            )
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
    let setup = crate::rtw88::firmware_transport::now(async {
        io.write32(0x2860, 0xc06).await?;
        io.write32(0x440, 0x1f).await?;
        io.write32(0x1bf0, 0).await?;
        radio8821c::write_txagc(&mut io, indices).await
    });
    if setup.is_err() {
        return TestResult::Fail("C21 TXAGC write rejected");
    }
    if crate::rtw88::firmware_transport::now(radio8821c::verify_retune(&mut io, 6, indices))
        .is_err()
    {
        return TestResult::Fail("C21 retune readback refused the programmed primary");
    }
    let mut other = indices;
    other[0] = 31;
    if crate::rtw88::firmware_transport::now(radio8821c::verify_retune(&mut io, 7, indices)).is_ok()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_retune(&mut io, 6, other))
            .is_ok()
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
    let setup = crate::rtw88::firmware_transport::now(async {
        io.write32(0x2860, 0xc06).await?;
        radio8821c::write_txagc(&mut io, indices).await?;
        io.write32(0x1d0c, u32::from_le_bytes([24; 4])).await?;
        io.write32(0x1d10, u32::from_le_bytes([24; 4])).await?;
        // The rest of the committed operating state operating_readback_rf18
        // requires clear (0x2820, 0x1bf0, 0x100 bit9, 0x680); the pattern
        // model otherwise leaves nonzero bytes there.
        for reg in [0x2820, 0x1bf0, 0x100, 0x680] {
            io.write32(reg, 0).await?;
        }
        Ok::<(), crate::rtw88::firmware_transport::Error>(())
    });
    if setup.is_err() {
        return TestResult::Fail("C21 operating fixture rejected");
    }
    let mut read = crate::rtw88::firmware_transport::IoRead32(&mut io);
    if crate::rtw88::firmware_transport::now(radio8821c::operating_readback_ht(
        &mut read, indices, mcs, 6,
    ))
    .is_err()
    {
        return TestResult::Fail("C21 HT20 readback refused the committed noninitial primary");
    }
    if crate::rtw88::firmware_transport::now(radio8821c::operating_readback_ht(
        &mut read, indices, mcs, 1,
    ))
    .is_ok()
    {
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

fn smoke_rtw88_band5_linux_groups_and_factory_power() -> TestResult {
    use crate::rtw88::band5::{self, Power5g};
    // main.h IS_CH_5G_BAND_* and phy.c rtw_get_channel_group.
    for (ch, b, g) in [
        (36, 1, 0),
        (48, 1, 1),
        (52, 2, 2),
        (64, 2, 3),
        (100, 3, 4),
        (144, 3, 9),
        (149, 4, 10),
        (161, 4, 11),
        (165, 4, 12),
        (177, 4, 13),
    ] {
        if band5::band(ch) != Some(b)
            || band5::group(ch) != Some(g)
            || !band5::primary(ch)
            || band5::frequency(ch) != Some(5000 + 5 * u16::from(ch))
        {
            return TestResult::Fail("5GHz band/group/frequency differs from Linux");
        }
    }
    if [1, 13, 14, 34, 38, 50, 68, 96, 147, 151, 181]
        .into_iter()
        .any(band5::primary)
    {
        return TestResult::Fail("non-primary 5GHz number accepted as a 20MHz primary");
    }
    // rtw8822c_set_channel_bb / rtw8821c_set_channel_bb 5GHz tables.
    for (ch, agc, sco, scale, clk) in [
        (36, 1, 0x494, 1, 0x494),
        (52, 1, 0x493, 1, 0x453),
        (100, 2, 0x453, 2, 0x452),
        (116, 2, 0x452, 2, 0x452),
        (120, 2, 0x412, 2, 0x412),
        (149, 3, 0x412, 3, 0x412),
        (177, 3, 0x411, 3, 0x412),
    ] {
        if band5::rxagc_ofdm8822c(ch) != Some(agc)
            || band5::scotrk8822c(ch) != Some(sco)
            || band5::txscale8821c(ch) != Some(scale)
            || band5::clktrk8821c(ch) != Some(clk)
        {
            return TestResult::Fail("5GHz BB table differs from Linux");
        }
    }
    // rtw_5g_txpwr_idx at bytes 18..42 of one path record.
    let mut path = [0u8; 42];
    path[18..32].copy_from_slice(&[40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 30, 0xff]);
    path[32] = 0x2e; // ht_1s: ofdm -2, bw20 +2
    path[33] = 0xf1; // ht_2s: bw20 +1, bw40 -1
    path[38] = 0x30; // vht_1s: bw80 +3
    path[39] = 0xe0; // vht_2s: bw80 -2
    let Some(p) = Power5g::parse(&path) else {
        return TestResult::Fail("5GHz factory record not parsed");
    };
    if p.ofdm(0, 1) != Some(38)
        || p.bw20(1, false, 1) != Some(44)
        || p.bw20(1, true, 2) != Some(48)
        || p.bw40(2, false, 1) != Some(44)
        || p.bw40(2, true, 1) != Some(43)
        || p.bw80(0, false, 1) != Some(44)
        || p.bw80(0, true, 1) != Some(42)
        || p.ofdm(13, 1).is_some()
        || p.bw80(12, false, 1).is_some()
    {
        return TestResult::Fail("5GHz factory index differs from rtw_phy_get_5g_tx_power_index");
    }
    // C22 5GHz HT keeps the N2xO OFDM selection: per-rate path minimum.
    let mut r = crate::rtw88::channel_policy::Record {
        channel: 36,
        antenna: 0,
        ceiling: 0,
        peaks: [0; 3],
        gains: [0; 2],
        indices: [0; 12],
        indices_b: [0; 12],
        ofdm: [40, 38],
        // 6M +2, 9M -1, 12M 0, 18M +63; 24M -30, 36..54M 0.
        diffs: [0x3f00_7f02, 0x0000_0062],
    };
    if r.ofdm5_indices() != Some([40, 37, 38, 101, 8, 38, 38, 38]) {
        return TestResult::Fail("5GHz OFDM selection is not the per-rate path minimum");
    }
    r.ofdm = [127, 127];
    if r.ofdm5_indices().is_some() {
        return TestResult::Fail("5GHz OFDM selection above index 127 accepted");
    }
    r.channel = 6;
    r.ofdm = [40, 38];
    if r.ofdm5_indices().is_some() {
        return TestResult::Fail("2.4GHz record produced a 5GHz OFDM selection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_band5_linux_groups_and_factory_power
);

fn smoke_rtw8822ce_channel5_bb_mac_rf_program() -> TestResult {
    for (ch, rf18) in [(36, 0x13124), (100, 0x33164), (149, 0x53195)] {
        if radio::rf18_8822c(ch, 20) != rf18 {
            return TestResult::Fail("C22 RF18 differs from rtw8822c_set_channel_rf");
        }
        let mut io = RadioIo::reference();
        if narf_scheduler::block_on(radio::channel5_to(&mut io, ch)).is_err()
            || crate::rtw88::firmware_transport::now(radio::verify_channel5(&mut io, ch)).is_err()
        {
            return TestResult::Fail("C22 5GHz program or readback failed");
        }
        let check = (|| -> Result<bool, crate::rtw88::firmware_transport::Error> {
            Ok(
                crate::rtw88::firmware_transport::now(io.read8(0x454))? & 0x80 != 0
                    && crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 0, 0x18))?
                        & 0x733ff
                        == rf18
                    && crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 1, 0x18))?
                        & 0x733ff
                        == rf18,
            )
        })();
        if check != Ok(true)
            || crate::rtw88::firmware_transport::now(radio::verify_channel5(&mut io, ch + 4))
                .is_ok()
        {
            return TestResult::Fail("C22 5GHz readback accepted another primary");
        }
        // Back to 2.4GHz rewrites every 5GHz field.
        if narf_scheduler::block_on(radio::channel_to(&mut io, 6)).is_err() {
            return TestResult::Fail("C22 2.4GHz program after 5GHz failed");
        }
        let back = (|| -> Result<bool, crate::rtw88::firmware_transport::Error> {
            Ok(
                crate::rtw88::firmware_transport::now(io.read8(0x454))? & 0x80 == 0
                    && crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x1c80))?
                        & 0x3f000000
                        == 15 << 24
                    && crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x1a80))?
                        & (1 << 18)
                        == 0
                    && crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x1a14))? & 0x300
                        == 0
                    && crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 0, 0x18))?
                        & 0x733ff
                        == 0x3006,
            )
        })();
        if back != Ok(true) {
            return TestResult::Fail("C22 2.4GHz program left 5GHz state");
        }
    }
    for ch in [6, 38, 34, 181] {
        let mut io = RadioIo::reference();
        if narf_scheduler::block_on(radio::channel5_to(&mut io, ch)).is_ok() {
            return TestResult::Fail("C22 5GHz program accepted a non-primary");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_channel5_bb_mac_rf_program
);

fn smoke_rtw8821ce_channel20_cross_band_readback() -> TestResult {
    let facts = radio8821c::BandFacts {
        filters: [0, 0, 0],
        btg: false,
        swing_2g: 0,
        swing_5g: 4,
    };
    if facts.swing(36) != Ok(0x16a)
        || facts.swing(1) != Ok(0x200)
        || (radio8821c::BandFacts {
            swing_5g: 0xff,
            ..facts
        })
        .swing(36)
        .is_ok()
    {
        return TestResult::Fail("C21 swing differs from rtw8821c_get_bb_swing or erased accepted");
    }
    let mut io = RadioIo::new();
    let setup = crate::rtw88::firmware_transport::now(async {
        io.write32(0x2800 + 0x18 * 4, radio8821c::rf18_for(36, 20))
            .await?;
        io.write32(0x2800 + 0xdf * 4, 0).await?;
        io.write32(0xc1c, 0x16a << 21 | 1 << 8).await?;
        io.write32(0x860, 0x494 << 17).await?;
        io.write32(0xa80, 1 << 18).await?;
        io.write32(0x808, 0).await?;
        io.write8(0x454, 0x80).await?;
        io.write32(0x8ac, 0x10010000).await?;
        io.write32(0xcb8, 0xd00000).await
    });
    if setup.is_err()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_channel20(&mut io, 36, &facts))
            .is_err()
    {
        return TestResult::Fail("C21 5GHz readback refused the programmed primary");
    }
    if crate::rtw88::firmware_transport::now(radio8821c::verify_channel20(&mut io, 40, &facts))
        .is_ok()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_channel20(&mut io, 6, &facts))
            .is_ok()
    {
        return TestResult::Fail("C21 5GHz readback accepted another channel or band");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8821ce_channel20_cross_band_readback
);

fn smoke_rtw88_plain_rule_auto_bw_and_no_160mhz() -> TestResult {
    // cfg80211 reg_get_max_bandwidth: AUTO_BW widens a rule to its adjacent
    // run, NO_160MHZ caps at 80; both are bandwidth shaping, not restrictions.
    let r22 = match Record::decode(0xc822, &payload(6, true)) {
        Some(r) => r,
        None => return TestResult::Fail("valid C22 record refused"),
    };
    let mut split = domain(2402, 2412, 30, RegFlags::AUTO_BW);
    split.rules[0].max_bandwidth_mhz = 10;
    split.rules.push(RegRule {
        freq_start_mhz: 2412,
        freq_end_mhz: 2472,
        max_bandwidth_mhz: 10,
        max_power_dbm: 30,
        flags: RegFlags::AUTO_BW | RegFlags::NO_160MHZ,
    });
    if !channel_policy::plain_rule(&split, 1, 40) || channel_policy::policy(&r22, &split) != Ok(76)
    {
        return TestResult::Fail("AUTO_BW/NO_160MHZ rule not admitted at its run bandwidth");
    }
    let mut narrow = split.clone();
    narrow.rules[0].flags = RegFlags::empty();
    narrow.rules[1].flags = RegFlags::empty();
    if channel_policy::plain_rule(&narrow, 1, 20) || channel_policy::policy(&r22, &narrow).is_ok() {
        return TestResult::Fail("rule maximum below 20MHz admitted without AUTO_BW");
    }
    let mut unknown = split.clone();
    unknown.rules[1].flags |= RegFlags::DFS;
    if channel_policy::plain_rule(&unknown, 1, 20)
        || channel_policy::plain_rule(&split, 5, 20)
        || channel_policy::policy(&r22, &unknown).is_ok()
    {
        return TestResult::Fail("DFS rule or bad index admitted as plain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_plain_rule_auto_bw_and_no_160mhz
);

fn smoke_rtw88_channel5_record_ofdm_selection_and_kinds() -> TestResult {
    // 5GHz N2xO payload: C22 per-path OFDM reference + 0x3a04/0x3a08
    // difference words; C21 OFDM TXAGC with CCK zero.
    let mut c22 = payload(36, true);
    c22[12..14].copy_from_slice(&[0, 0]);
    c22[26..28].copy_from_slice(&[40, 38]);
    // 6M +2, 9M -1 (0x7f), 12M 0, 18M -3 (0x7d); 24..54M -4 (0x7c).
    c22[28..32].copy_from_slice(&[0x02, 0x7f, 0x00, 0x7d]);
    c22[32..36].copy_from_slice(&[0x7c; 4]);
    let Some(r) = Record::decode(0xc822, &c22) else {
        return TestResult::Fail("valid C22 5GHz record refused");
    };
    if !r.band5()
        || r.frequency() != Some(5180)
        || [r.diff(0), r.diff(1), r.diff(2), r.diff(3), r.diff(7)] != [2, -1, 0, -3, -4]
    {
        return TestResult::Fail("C22 5GHz OFDM differences or frequency misdecoded");
    }
    let mut cck = c22;
    cck[12] = 30;
    let mut sign = c22;
    sign[29] = 0x80;
    let mut odd = c22;
    odd[0] = 38;
    let mut tail = c22;
    tail[36] = 1;
    let mut stale = payload(6, true);
    stale[26] = 1;
    if [cck, sign, odd, tail]
        .iter()
        .any(|p| Record::decode(0xc822, p).is_some())
        || Record::decode(0xc822, &stale).is_some()
    {
        return TestResult::Fail(
            "5GHz CCK, bad diff byte, non-primary, tail or 2.4GHz OFDM admitted",
        );
    }
    let mut c21 = payload(149, false);
    c21[14..18].copy_from_slice(&[0; 4]);
    if Record::decode(0xc821, &c21).map(|r| r.indices[4]) != Some(28)
        || Record::decode(0xc821, &payload(149, false)).is_some()
    {
        return TestResult::Fail("C21 5GHz record must carry OFDM only");
    }
    let (Some(k36), Some(k177)) = (channel_policy::kind(36), channel_policy::kind(177)) else {
        return TestResult::Fail("5GHz primary without a static kind");
    };
    if k36.stem != "channel36"
        || k177.stem != "channel177"
        || !(k36.admit)(0xc822, &c22)
        || (k177.admit)(0xc822, &c22)
        || channel_policy::kind(38).is_some()
        || channel_policy::kind(14).is_some()
    {
        return TestResult::Fail("5GHz kind identity/admission is not exact");
    }
    // Regulatory span 5170..5190 under a plain UNII-1 rule. Since the
    // reg::witness passive primaries, a DFS rule admits the span as
    // passive-only (`passive_rule`); INDOOR_ONLY and an uncovered span refuse.
    let unii1 = domain(5170, 5250, 23, RegFlags::empty());
    let dfs = domain(5170, 5250, 23, RegFlags::DFS);
    let indoor = domain(5170, 5250, 23, RegFlags::INDOOR_ONLY);
    let short = domain(5175, 5250, 23, RegFlags::empty());
    if channel_policy::admission(&r, &unii1) != Ok((76, false))
        || channel_policy::admission(&r, &dfs) != Ok((76, true))
        || channel_policy::policy(&r, &indoor).is_ok()
        || channel_policy::policy(&r, &short).is_ok()
    {
        return TestResult::Fail("5GHz record regulatory span not checked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_channel5_record_ofdm_selection_and_kinds
);

fn smoke_rtw88_band5_base_rate_rrsr_and_ofdm_reference() -> TestResult {
    use crate::rtw88::packet_format::{transmit_profile, DataProfile};
    // tx.c rtw_tx_pkt_info_update_rate: 5GHz RTW_RATEID_G at DESC_RATE6M;
    // get_rate_id WIRELESS_OFDM = RTW_RATEID_G; RRSR_INIT_5G & mask(6M).
    let five = DataProfile::LEGACY5;
    if !five.valid()
        || five.rate_id() != 7
        || five.rate() != 4
        || five.response_mask() != 0x10
        || DataProfile::LEGACY.response_mask() != 0x1f
        || (DataProfile {
            rates: 0x11,
            ..five
        })
        .valid()
    {
        return TestResult::Fail("5GHz profile rate id, rate or RRSR differs from Linux");
    }
    let own = [2, 1, 2, 3, 4, 5];
    let mut frame = vec![0x59; 40];
    frame[..2].copy_from_slice(&[0xb0, 0]);
    frame[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[10..16].copy_from_slice(&own);
    frame[22..24].copy_from_slice(&[0xc0, 0xab]);
    let word = |d: &[u8], at: usize| u32::from_le_bytes(d[at..at + 4].try_into().unwrap());
    let (Ok((m5, _)), Ok((m2, _))) = (
        transmit_profile(&frame, own, 0, None, five),
        transmit_profile(&frame, own, 0, None, DataProfile::LEGACY),
    ) else {
        return TestResult::Fail("management frame refused");
    };
    if (word(&m5, 4) >> 16) & 31 != 7
        || word(&m5, 16) & 0x7f != 4
        || (word(&m2, 4) >> 16) & 31 != 8
        || word(&m2, 16) & 0x7f != 0
    {
        return TestResult::Fail("management rate id/rate not band-aware");
    }
    // rtw8822c_set_write_tx_power_ref / _set_tx_power_diff on 5GHz.
    let mut io = RadioIo::reference();
    let (ofdm, diffs) = ([40, 38], [0x7d00_7f02, 0x7c7c_7c7c]);
    if crate::rtw88::firmware_transport::now(radio::ofdm5(&mut io, ofdm, diffs)).is_err()
        || crate::rtw88::firmware_transport::now(radio::verify_ofdm5(&mut io, ofdm, diffs)).is_err()
        || crate::rtw88::firmware_transport::now(radio::verify_ofdm5(&mut io, [40, 37], diffs))
            .is_ok()
        || crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x440)) != Ok(0x10)
    {
        return TestResult::Fail("C22 5GHz OFDM reference/difference program not read back");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_band5_base_rate_rrsr_and_ofdm_reference
);

fn smoke_rtw8821ce_channel5_ofdm_txagc_and_rrsr() -> TestResult {
    // C21 5GHz retune tail: OFDM TXAGC with CCK zero, RRSR_INIT_5G & mask(6M).
    let indices = [0, 0, 0, 0, 28, 28, 28, 28, 26, 26, 26, 26];
    let mut io = RadioIo::new();
    let run = crate::rtw88::firmware_transport::now(async {
        radio8821c::write_txagc(&mut io, indices).await?;
        io.write32(0x440, radio::RRSR_OFDM6_5G).await?;
        io.write32(0x1bf0, 0).await
    });
    if radio::RRSR_OFDM6_5G != 0x10
        || run.is_err()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_txagc(&mut io, indices, 0x10))
            .is_err()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_txagc(&mut io, indices, 0x1f))
            .is_ok()
    {
        return TestResult::Fail("C21 5GHz TXAGC/RRSR readback differs");
    }
    let mut other = indices;
    other[4] = 27;
    if crate::rtw88::firmware_transport::now(radio8821c::verify_txagc(&mut io, other, 0x10)).is_ok()
    {
        return TestResult::Fail("C21 TXAGC readback accepted another selection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8821ce_channel5_ofdm_txagc_and_rrsr
);

fn smoke_rtw88_band5_station_scan_csa_and_probe() -> TestResult {
    // ieee80211_put_preq_ies_band: 5GHz OFDM rates, no ESR, no DS element.
    let mut probe = vec![0x40, 0, 0, 0];
    probe.extend_from_slice(&[255; 6]);
    probe.extend_from_slice(&[2, 1, 2, 3, 4, 5]);
    probe.extend_from_slice(&[255; 6]);
    probe.extend_from_slice(&[
        0, 0, 0, 1, b'x', 1, 2, 0x02, 0x04, 50, 1, 0x6c, 3, 1, 1, 221, 3, 1, 2, 3,
    ]);
    let five = channel_policy::probe_for(&probe, 36);
    let mut expect = probe[..27].to_vec();
    expect.extend_from_slice(&[
        1, 8, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c, 221, 3, 1, 2, 3,
    ]);
    if five.as_deref() != Some(&expect[..])
        || channel_policy::probe_for(&probe, 6).map(|p| p[p.len() - 6]) != Some(6)
        || channel_policy::probe_for(&probe, 38).is_some()
    {
        return TestResult::Fail("5GHz preq not rebuilt for the band");
    }
    // ECSA 20MHz classes 81/115/118/121/124/125 (Annex E Table E-4).
    for (class, ch, ok) in [
        (81, 6, true),
        (115, 44, true),
        (124, 161, true),
        (125, 177, true),
        (124, 165, false),
        (115, 52, false),
        (118, 52, true),
        (118, 48, false),
        (121, 100, true),
        (121, 144, true),
        (121, 102, false),
        (121, 149, false),
    ] {
        let ie = channel_policy::switch_ie(&[60, 4, 1, class, ch, 5]);
        if ie.map(|i| i.channel) != Some(ok.then_some(ch)) {
            return TestResult::Fail("ECSA operating class mapping differs");
        }
    }
    if channel_policy::any_frequency(149) != Some(5745)
        || channel_policy::any_frequency(14).is_some()
        || !channel_policy::base_rate_ok(36, 0x150)
        || channel_policy::base_rate_ok(36, 0x151)
        || channel_policy::base_rate_ok(36, 0x140)
        || !channel_policy::base_rate_ok(1, 0x0f)
    {
        return TestResult::Fail("band-aware frequency/base-rate admission differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_band5_station_scan_csa_and_probe
);

fn smoke_rtw88_dfs_passive_rule_and_record_admission() -> TestResult {
    // cfg80211 IEEE80211_CHAN_RADAR / NO_IR: a 5GHz DFS or NO_IR span is
    // admitted passive-only; 2.4GHz and indoor/unknown bits still refuse.
    let mut c22 = payload(52, true);
    c22[12..14].copy_from_slice(&[0, 0]);
    c22[26..28].copy_from_slice(&[40, 38]);
    let Some(r52) = Record::decode(0xc822, &c22) else {
        return TestResult::Fail("valid C22 channel52 record refused");
    };
    let Some(r6) = Record::decode(0xc822, &payload(6, true)) else {
        return TestResult::Fail("valid C22 channel6 record refused");
    };
    let dfs = domain(5250, 5330, 23, RegFlags::DFS | RegFlags::AUTO_BW);
    let no_ir = domain(5250, 5330, 23, RegFlags::NO_IR);
    let plain = domain(5250, 5330, 23, RegFlags::empty());
    if channel_policy::passive_rule(&dfs, 0, 20) != Some(true)
        || channel_policy::passive_rule(&plain, 0, 20) != Some(false)
        || channel_policy::passive_rule(&dfs, 1, 20).is_some()
        || channel_policy::plain_rule(&dfs, 0, 20)
    {
        return TestResult::Fail("passive_rule classification differs");
    }
    if channel_policy::admission(&r52, &dfs) != Ok((76, true))
        || channel_policy::admission(&r52, &no_ir) != Ok((76, true))
        || channel_policy::admission(&r52, &plain) != Ok((76, false))
        || channel_policy::policy(&r52, &dfs) != Ok(76)
    {
        return TestResult::Fail("5GHz DFS/NO_IR span not admitted passive-only");
    }
    let indoor = domain(5250, 5330, 23, RegFlags::DFS | RegFlags::INDOOR_ONLY);
    let low = domain(2402, 2482, 30, RegFlags::DFS);
    let low_no_ir = domain(2402, 2482, 30, RegFlags::NO_IR);
    if channel_policy::admission(&r52, &indoor).is_ok()
        || channel_policy::admission(&r6, &low).is_ok()
        || channel_policy::admission(&r6, &low_no_ir).is_ok()
    {
        return TestResult::Fail("indoor 5GHz or DFS/NO_IR 2.4GHz span admitted");
    }
    // Station scan/join classification: probes are dropped and a witness is
    // required only on a 5GHz RADAR / NO_IR primary under a policy.
    let dfs = alloc::sync::Arc::new(dfs);
    let low = alloc::sync::Arc::new(low);
    if !crate::rtw88::station::passive_only(Some(&dfs), 52)
        || !crate::rtw88::station::passive_only(Some(&dfs), 64)
        || crate::rtw88::station::passive_only(Some(&dfs), 48)
        || crate::rtw88::station::passive_only(None, 52)
        || crate::rtw88::station::passive_only(Some(&low), 6)
    {
        return TestResult::Fail("station passive-only classification differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_dfs_passive_rule_and_record_admission
);
