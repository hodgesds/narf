// SPDX-License-Identifier: GPL-2.0-or-later
//! N2xB 2.4GHz HT40: record admission, regulatory 40MHz span, Linux BW40
//! BB/MAC/RF programs, and the descriptor/RA/PHY-status 40MHz fields.
use super::radio_tests::RadioIo;
use super::Io;
use crate::rtw88::{
    ht::{factory_limit_bw40, factory_limit_bw40_2ss},
    ht40::{self, Record},
    packet_format::{self, DataProfile},
    packet_phy,
    qualification::PAYLOAD,
    radio, radio8821c,
};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};

fn payload(primary: u8, secondary: u8, c22: bool) -> [u8; PAYLOAD] {
    let mut p = [0; PAYLOAD];
    p[0] = primary;
    p[1] = secondary;
    p[2] = 40;
    p[3] = 1;
    for (at, v) in [(4, 4i16), (6, 76), (8, 44), (10, 40), (12, 40)] {
        p[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    p[14..16].copy_from_slice(&0xffu16.to_le_bytes());
    p[16..24].copy_from_slice(if c22 {
        &[40, 40, 40, 40, 38, 38, 36, 36]
    } else {
        &[30, 30, 30, 30, 28, 28, 26, 26]
    });
    p
}

fn domain(start: u32, end: u32, bw: u32, flags: RegFlags) -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: bw,
            max_power_dbm: 30,
            flags,
        }],
    }
}

fn smoke_rtw88_ht40_record_pair_factory_and_regulatory_span() -> TestResult {
    let Some(r) = Record::decode(0xc822, &payload(6, 2, true)) else {
        return TestResult::Fail("valid C22 HT40 lower-secondary record refused");
    };
    // rtw_update_channel: primary above the center is RTW_SC_20_UPPER (1).
    if r.center() != 4 || r.sc() != 1 || !r.sgi || r.mcs != 0xff {
        return TestResult::Fail("center/sub-channel index differs from rtw_update_channel");
    }
    let up = Record::decode(0xc821, &payload(1, 5, false));
    if up.map(|r| (r.center(), r.sc())) != Some((3, 2)) {
        return TestResult::Fail("C21 upper-secondary pair not admitted as SC_20_LOWER");
    }
    let mut bad = vec![
        payload(6, 3, true),
        payload(11, 15, true),
        payload(12, 16, true),
        payload(14, 10, true),
    ];
    let mut twenty = payload(6, 2, true);
    twenty[2] = 20;
    let mut tail = payload(6, 2, true);
    tail[40] = 1;
    let mut stray = payload(6, 2, true);
    stray[30] = 9; // index outside the MCS mask
    let mut two_c21 = payload(6, 2, false);
    two_c21[15] = 0xff;
    let mut no_ref = payload(6, 2, true);
    no_ref[14] = 0x7f; // C22 needs the MCS7 reference
    bad.extend([twenty, tail, stray, no_ref]);
    if bad.iter().any(|p| Record::decode(0xc822, p).is_some())
        || Record::decode(0xc821, &two_c21).is_some()
    {
        return TestResult::Fail("malformed HT40 pair/width/tail/index admitted");
    }
    if !(ht40::KIND.admit)(0xc822, &payload(6, 2, true)) || ht40::KIND.tag != b'B' {
        return TestResult::Fail("N2xB kind identity/admission is not exact");
    }
    // phy.c BW40: bw40_base[group]; 2S adds ht_2s_diff.bw40 (high nibble).
    let mut power = [0u8; 14];
    power[6..11].copy_from_slice(&[40, 41, 42, 43, 44]);
    power[12] = 0xe2; // bw40 -2, bw20 +2
    if factory_limit_bw40(&power, 1, 127) != Some(41)
        || factory_limit_bw40(&power, 5, 127).is_some()
        || factory_limit_bw40(&power, 1, 40).is_some()
        || factory_limit_bw40_2ss(&power, 2, 2) != Some(38)
    {
        return TestResult::Fail("HT40 factory base differs from rtw_phy_get_2g_tx_power_index");
    }
    // The 40MHz span of center 4 is 2417..2457MHz.
    let us = domain(2402, 2472, 40, RegFlags::empty());
    if ht40::policy(&r, &us) != Ok(76) {
        return TestResult::Fail("covered 40MHz span not admitted at the record ceiling");
    }
    let narrow = domain(2402, 2472, 20, RegFlags::empty());
    let short = domain(2420, 2472, 40, RegFlags::empty());
    let flagged = domain(2402, 2472, 40, RegFlags::NO_IR);
    if [narrow, short, flagged]
        .iter()
        .any(|d| ht40::policy(&r, d).is_ok())
    {
        return TestResult::Fail("20MHz-only, partial or restricted rule admitted HT40");
    }
    if ht40::hardware_allows(1) || !ht40::hardware_allows(6) || !ht40::hardware_allows(0) {
        return TestResult::Fail("hw_cap.bw decoding differs from hw_bw_cap_to_bitamp");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_ht40_record_pair_factory_and_regulatory_span
);

fn smoke_rtw88_ht40_operation_element_and_phy_status_width() -> TestResult {
    let mut ies = vec![0, 3, b'l', b'a', b'b', 61, 22, 6, 7];
    ies.extend_from_slice(&[0; 20]);
    if ht40::ht_operation(&ies) != Some((6, Some(2))) {
        return TestResult::Fail("SCO below with STA width not parsed");
    }
    ies[8] = 5; // SCO above + width
    if ht40::ht_operation(&ies) != Some((6, Some(10))) {
        return TestResult::Fail("SCO above with STA width not parsed");
    }
    ies[8] = 1; // SCO without STA channel width
    if ht40::ht_operation(&ies) != Some((6, None)) {
        return TestResult::Fail("SCO without channel width taken as 40MHz");
    }
    // query_phy_status_page1: C22 RXSC 0 is the current band width.
    let mut p = [0u8; 32];
    p[0] = 1;
    p[6] = 6; // channel
    let at20 = packet_phy::parse_at(packet_phy::Chip::C22, 20, &p, 0).ok();
    let at40 = packet_phy::parse_at(packet_phy::Chip::C22, 20, &p, 1).ok();
    if at20.map(|e| e.bandwidth) != Some(0)
        || at40.map(|e| e.bandwidth) != Some(1)
        || !at40.is_some_and(|e| e.on_operating(6, 1))
        || at40.is_some_and(|e| e.on_operating(6, 0) || e.on_channel(6))
    {
        return TestResult::Fail("RXSC0 not mapped to the committed width");
    }
    p[5] = 9 << 4; // HT RXSC 9: 40MHz PPDU
    if packet_phy::parse_at(packet_phy::Chip::C22, 20, &p, 0).is_ok_and(|e| e.on_operating(6, 0)) {
        return TestResult::Fail("40MHz PPDU admitted at 20MHz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_ht40_operation_element_and_phy_status_width
);

fn smoke_rtw88_ht40_descriptor_rate_id_and_profile() -> TestResult {
    let p = DataProfile {
        rates: 0xfff,
        qos: true,
        mcs: 0xff,
        rx_mcs: 0xff,
        sgi: true,
        bw40: true,
        ..DataProfile::LEGACY
    };
    // get_rate_id: BGN_40M_1SS 1 / 2SS 0; GN independent of bandwidth.
    if p.rate_id() != 1
        || (DataProfile {
            mcs: 0xffff,
            rx_mcs: 0xffff,
            ..p
        })
        .rate_id()
            != 0
        || (DataProfile { rates: 0xff0, ..p }).rate_id() != 5
        || (DataProfile { bw40: false, ..p }).rate_id() != 3
        || !p.valid()
        || (DataProfile {
            mcs: 0,
            rx_mcs: 0,
            sgi: false,
            ..p
        })
        .valid()
    {
        return TestResult::Fail("BW40 rate id/validity differs from get_rate_id");
    }
    let own = crate::rtw88::ht_tests::OWN;
    let mut frame = vec![0x88, 1, 0, 0];
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x10, 0, 0, 0]);
    frame.extend_from_slice(&[0; 32]);
    let Ok((d, _)) = packet_format::transmit_profile(&frame, own, 0, None, p) else {
        return TestResult::Fail("BW40 QoS DATA descriptor refused");
    };
    // W5_DATA_SHORT bit4 + W5_DATA_BW bits6:5 = 1; W1 RATE_ID 1.
    if u32::from_le_bytes([d[20], d[21], d[22], d[23]]) != (1 << 4 | 1 << 5)
        || (u32::from_le_bytes([d[4], d[5], d[6], d[7]]) >> 16) & 31 != 1
    {
        return TestResult::Fail("descriptor BW/SGI/rate id not at BW40");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_ht40_descriptor_rate_id_and_profile
);

fn smoke_rtw88_ht40_linux_bw40_bb_mac_rf_programs() -> TestResult {
    // rtw8822c_set_channel(center 4, BW40, SC_20_UPPER) for primary 6.
    let mut io = RadioIo::reference();
    if narf_scheduler::block_on(radio::width40(&mut io, 4, 1)).is_err()
        || radio::gains(&mut io, [36, 32]).is_err()
        || io.write32(0x440, 0x1f).is_err()
    {
        return TestResult::Fail("C22 BW40 program rejected an admitted pair");
    }
    let ok = (|| -> Result<bool, crate::rtw88::firmware_transport::Error> {
        Ok(radio::rf_read(&mut io, 0, 0x18)? & 0x733ff == 0x2004
            && radio::rf_read(&mut io, 1, 0x18)? & 0x733ff == 0x2004
            && radio::read(&mut io, 0x9b0)? & 0xffcf == 0x1105
            && radio::read(&mut io, 0x18ac)? & 0xf1f0 == 0x4000
            && io.read8(0x483)? == 1
            && radio::read(&mut io, 0x668)? & 0x180 == 0x80)
    })();
    if ok != Ok(true) || radio::verify_width40(&mut io, 4, 1, [36, 32]).is_err() {
        return TestResult::Fail("C22 BW40 BB/MAC/RF readback differs from Linux");
    }
    if radio::verify_width40(&mut io, 4, 2, [36, 32]).is_ok()
        || radio::verify_width40(&mut io, 5, 1, [36, 32]).is_ok()
    {
        return TestResult::Fail("C22 BW40 readback accepted another sideband/center");
    }
    // The 20MHz program restores every BW40 field it owns.
    if narf_scheduler::block_on(radio::channel_to(&mut io, 6)).is_err()
        || radio::rf_read(&mut io, 0, 0x18).map(|v| v & 0x733ff) != Ok(0x3006)
        || io.read8(0x483) != Ok(0)
        || radio::read(&mut io, 0x668).map(|v| v & 0x180) != Ok(0)
    {
        return TestResult::Fail("BW20 retune left BW40 state behind");
    }
    for (center, sc) in [(2, 1), (12, 2), (4, 0), (4, 3)] {
        let mut io = RadioIo::reference();
        if narf_scheduler::block_on(radio::width40(&mut io, center, sc)).is_ok() {
            return TestResult::Fail("unadmitted BW40 center/sub-channel programmed");
        }
    }
    // rtw8821c_set_channel(center 8, BW40, SC_20_LOWER) for primary 6: the
    // retained state its readback requires (RF18 via the 0x2860 window).
    let mut io = RadioIo::new();
    let setup = (|| {
        for (reg, value) in [
            (0x2860, 0x808),
            (0xa00, 0),
            (0x8ac, 0x2002_0009),
            (0x8c4, 1 << 30),
            (0x668, 0x80),
            (0x948, 2 << 28),
            (0x94c, 2 << 28),
            (0xc20, 0),
            (0x8f0, 0),
            (0x440, 0x1f),
            (0x1bf0, 0),
        ] {
            io.write32(reg, value)?;
        }
        io.write8(0x483, 2)
    })();
    if setup.is_err() || radio8821c::verify_width40(&mut io, 8, 2).is_err() {
        return TestResult::Fail("C21 BW40 readback refused the rtw8821c_set_channel state");
    }
    if radio8821c::verify_width40(&mut io, 8, 1).is_ok()
        || radio8821c::verify_width40(&mut io, 4, 2).is_ok()
    {
        return TestResult::Fail("C21 BW40 readback accepted another sideband/center");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_ht40_linux_bw40_bb_mac_rf_programs
);

fn smoke_rtw88_ht40_5ghz_pairs_programs_and_passive_span() -> TestResult {
    use crate::rtw88::band5::{self, Width};
    // IEEE 802.11 Annex E 40MHz blocks 36/40 .. 157/161 only.
    for (p, s, c) in [
        (36, 40, 38),
        (40, 36, 38),
        (44, 48, 46),
        (64, 60, 62),
        (140, 144, 142),
        (149, 153, 151),
        (161, 157, 159),
    ] {
        if band5::center40(p, s) != Some(c) || ht40::center(p, s) != Some(c) {
            return TestResult::Fail("admitted 5GHz 40MHz pair has the wrong center");
        }
    }
    for (p, s) in [
        (40, 44),
        (48, 52),
        (64, 100),
        (165, 169),
        (36, 32),
        (38, 42),
    ] {
        if ht40::center(p, s).is_some() {
            return TestResult::Fail("non-Annex-E 5GHz pair admitted");
        }
    }
    let Some(r) = Record::decode(0xc822, &payload(36, 40, true)) else {
        return TestResult::Fail("valid C22 5GHz HT40 record refused");
    };
    if r.center() != 38 || r.sc() != 2 || !r.band5() {
        return TestResult::Fail("5GHz sub-channel index differs from rtw_update_channel");
    }
    let upper = Record::decode(0xc821, &payload(48, 44, false));
    if upper.map(|r| (r.center(), r.sc())) != Some((46, 1)) {
        return TestResult::Fail("C21 5GHz upper primary not SC_20_UPPER");
    }
    // One kind per band: a 2.4GHz record never admits as 5GHz and back.
    if (ht40::KIND.admit)(0xc822, &payload(36, 40, true))
        || !(ht40::KIND5.admit)(0xc822, &payload(36, 40, true))
        || (ht40::KIND5.admit)(0xc822, &payload(6, 2, true))
        || !core::ptr::eq(ht40::kind(36), &ht40::KIND5)
        || !core::ptr::eq(ht40::kind(6), &ht40::KIND)
        || ht40::KIND.source == ht40::KIND5.source
    {
        return TestResult::Fail("N2xB band kinds are not disjoint");
    }
    // 40MHz span of center 38 is 5170..5210MHz; 52/56 (center 54) 5250..5290.
    if ht40::admission(&r, &domain(5170, 5250, 80, RegFlags::empty())) != Ok((76, false)) {
        return TestResult::Fail("plain 5GHz 40MHz span not admitted");
    }
    let Some(dfs) = Record::decode(0xc822, &payload(52, 56, true)) else {
        return TestResult::Fail("valid DFS-band pair refused");
    };
    if ht40::admission(&dfs, &domain(5250, 5330, 80, RegFlags::DFS)) != Ok((76, true))
        || ht40::admission(&dfs, &domain(5250, 5330, 80, RegFlags::NO_IR)) != Ok((76, true))
    {
        return TestResult::Fail("DFS/NO_IR 40MHz span not admitted as passive-only");
    }
    if ht40::admission(&dfs, &domain(5250, 5330, 20, RegFlags::DFS)).is_ok()
        || ht40::admission(&dfs, &domain(5250, 5330, 80, RegFlags::INDOOR_ONLY)).is_ok()
        || ht40::admission(&dfs, &domain(5260, 5330, 80, RegFlags::DFS)).is_ok()
    {
        return TestResult::Fail("narrow, indoor or partial 5GHz span admitted");
    }
    // rtw8822c_set_channel(38, BW40, SC_20_LOWER): 5GHz head of the center.
    let mut io = RadioIo::reference();
    if narf_scheduler::block_on(radio::wide5_to(&mut io, 38, Width::Forty(2))).is_err() {
        return TestResult::Fail("C22 5GHz BW40 program rejected an admitted center");
    }
    let rf18 = 1 << 16 | 1 << 8 | 2 << 12 | 38;
    if radio::rf_read(&mut io, 0, 0x18).map(|v| v & 0x733ff) != Ok(rf18)
        || radio::rf_read(&mut io, 1, 0x18).map(|v| v & 0x733ff) != Ok(rf18)
        || radio::read(&mut io, 0x9b0).map(|v| v & 0xffcf) != Ok(0x2205)
        || radio::read(&mut io, 0x18ac).map(|v| v & 0x1f0) != Ok(0x10)
        || io.read8(0x483) != Ok(2)
        || io.read8(0x454).map(|v| v & 0x80) != Ok(0x80)
        || radio::verify_wide5(&mut io, 38, Width::Forty(2)).is_err()
    {
        return TestResult::Fail("C22 5GHz BW40 BB/MAC/RF differs from Linux");
    }
    if radio::verify_wide5(&mut io, 38, Width::Forty(1)).is_ok()
        || radio::verify_wide5(&mut io, 46, Width::Forty(2)).is_ok()
        || radio::verify_channel5(&mut io, 36).is_ok()
    {
        return TestResult::Fail("C22 5GHz BW40 readback accepted another state");
    }
    for (center, width) in [
        (40, Width::Forty(1)),
        (38, Width::Forty(3)),
        (4, Width::Forty(1)),
    ] {
        let mut io = RadioIo::reference();
        if narf_scheduler::block_on(radio::wide5_to(&mut io, center, width)).is_ok() {
            return TestResult::Fail("unadmitted 5GHz BW40 center/sub-channel programmed");
        }
    }
    // rtw8821c_set_channel(46, BW40, SC_20_UPPER) readback state.
    let facts = radio8821c::BandFacts {
        filters: [0; 3],
        btg: false,
        swing_2g: 0,
        swing_5g: 4,
    };
    let mut io = RadioIo::new();
    let setup = (|| {
        for (reg, value) in [
            (0x2860, radio8821c::rf18_for(46, 40)),
            (0x2800 + 0xdf * 4, 0),
            (0xc1c, 0x16a << 21 | 1 << 8),
            (0x860, 0x494 << 17),
            (0xa80, 1 << 18),
            (0x808, 0),
            (0x8ac, 0x2002_0005),
            (0x8c4, 1 << 30),
            (0x668, 0x80),
            (0xcb8, 0xd0_0000),
            (0xa00, 1 << 4),
            (0x948, 2 << 28),
            (0x94c, 2 << 28),
            (0xc20, 0),
            (0x8f0, 0),
        ] {
            io.write32(reg, value)?;
        }
        io.write8(0x454, 0x80)?;
        io.write8(0x483, 1)
    })();
    if setup.is_err() || radio8821c::verify_wide5(&mut io, 46, Width::Forty(1), &facts).is_err() {
        return TestResult::Fail("C21 5GHz BW40 readback refused the rtw8821c_set_channel state");
    }
    if radio8821c::verify_wide5(&mut io, 46, Width::Forty(2), &facts).is_ok()
        || radio8821c::verify_wide5(&mut io, 38, Width::Forty(1), &facts).is_ok()
    {
        return TestResult::Fail("C21 5GHz BW40 readback accepted another sideband/center");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_ht40_5ghz_pairs_programs_and_passive_span
);
