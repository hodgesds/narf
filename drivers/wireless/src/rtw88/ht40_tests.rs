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
        || crate::rtw88::firmware_transport::now(radio::gains(&mut io, [36, 32])).is_err()
        || crate::rtw88::firmware_transport::now(io.write32(0x440, 0x1f)).is_err()
    {
        return TestResult::Fail("C22 BW40 program rejected an admitted pair");
    }
    let ok = (|| -> Result<bool, crate::rtw88::firmware_transport::Error> {
        Ok(
            crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 0, 0x18))? & 0x733ff
                == 0x2004
                && crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 1, 0x18))?
                    & 0x733ff
                    == 0x2004
                && crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x9b0))? & 0xffcf
                    == 0x1105
                && crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x18ac))? & 0xf1f0
                    == 0x4000
                && crate::rtw88::firmware_transport::now(io.read8(0x483))? == 1
                && crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x668))? & 0x180
                    == 0x80,
        )
    })();
    if ok != Ok(true)
        || crate::rtw88::firmware_transport::now(radio::verify_width40(&mut io, 4, 1, [36, 32]))
            .is_err()
    {
        return TestResult::Fail("C22 BW40 BB/MAC/RF readback differs from Linux");
    }
    if crate::rtw88::firmware_transport::now(radio::verify_width40(&mut io, 4, 2, [36, 32])).is_ok()
        || crate::rtw88::firmware_transport::now(radio::verify_width40(&mut io, 5, 1, [36, 32]))
            .is_ok()
    {
        return TestResult::Fail("C22 BW40 readback accepted another sideband/center");
    }
    // The 20MHz program restores every BW40 field it owns.
    if narf_scheduler::block_on(radio::channel_to(&mut io, 6)).is_err()
        || crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 0, 0x18))
            .map(|v| v & 0x733ff)
            != Ok(0x3006)
        || crate::rtw88::firmware_transport::now(io.read8(0x483)) != Ok(0)
        || crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x668)).map(|v| v & 0x180)
            != Ok(0)
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
    let setup = crate::rtw88::firmware_transport::now(async {
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
            io.write32(reg, value).await?;
        }
        io.write8(0x483, 2).await
    });
    if setup.is_err()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_width40(&mut io, 8, 2)).is_err()
    {
        return TestResult::Fail("C21 BW40 readback refused the rtw8821c_set_channel state");
    }
    if crate::rtw88::firmware_transport::now(radio8821c::verify_width40(&mut io, 8, 1)).is_ok()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_width40(&mut io, 4, 2)).is_ok()
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
    if crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 0, 0x18)).map(|v| v & 0x733ff)
        != Ok(rf18)
        || crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 1, 0x18))
            .map(|v| v & 0x733ff)
            != Ok(rf18)
        || crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x9b0)).map(|v| v & 0xffcf)
            != Ok(0x2205)
        || crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x18ac)).map(|v| v & 0x1f0)
            != Ok(0x10)
        || crate::rtw88::firmware_transport::now(io.read8(0x483)) != Ok(2)
        || crate::rtw88::firmware_transport::now(io.read8(0x454)).map(|v| v & 0x80) != Ok(0x80)
        || crate::rtw88::firmware_transport::now(radio::verify_wide5(&mut io, 38, Width::Forty(2)))
            .is_err()
    {
        return TestResult::Fail("C22 5GHz BW40 BB/MAC/RF differs from Linux");
    }
    if crate::rtw88::firmware_transport::now(radio::verify_wide5(&mut io, 38, Width::Forty(1)))
        .is_ok()
        || crate::rtw88::firmware_transport::now(radio::verify_wide5(&mut io, 46, Width::Forty(2)))
            .is_ok()
        || crate::rtw88::firmware_transport::now(radio::verify_channel5(&mut io, 36)).is_ok()
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
    let setup = crate::rtw88::firmware_transport::now(async {
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
            io.write32(reg, value).await?;
        }
        io.write8(0x454, 0x80).await?;
        io.write8(0x483, 1).await
    });
    if setup.is_err()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_wide5(
            &mut io,
            46,
            Width::Forty(1),
            &facts,
        ))
        .is_err()
    {
        return TestResult::Fail("C21 5GHz BW40 readback refused the rtw8821c_set_channel state");
    }
    if crate::rtw88::firmware_transport::now(radio8821c::verify_wide5(
        &mut io,
        46,
        Width::Forty(2),
        &facts,
    ))
    .is_ok()
        || crate::rtw88::firmware_transport::now(radio8821c::verify_wide5(
            &mut io,
            38,
            Width::Forty(1),
            &facts,
        ))
        .is_ok()
    {
        return TestResult::Fail("C21 5GHz BW40 readback accepted another sideband/center");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_ht40_5ghz_pairs_programs_and_passive_span
);

fn vht_payload(primary: u8, center: u8, streams: u8) -> [u8; PAYLOAD] {
    let mut p = [0; PAYLOAD];
    p[..4].copy_from_slice(&[primary, center, 80, 1]);
    for (at, v) in [(4, 4i16), (6, 76), (8, 44), (10, 40), (12, 40)] {
        p[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    p[14] = streams;
    p[15] = 9;
    p[16..26].copy_from_slice(&[40, 40, 40, 40, 38, 38, 36, 36, 34, 34]);
    if streams == 2 {
        p[26..36].copy_from_slice(&[38; 10]);
    }
    p
}

fn smoke_rtw88_vht80_record_span_and_bw80_program() -> TestResult {
    use crate::rtw88::{
        band5::{self, Width},
        vht,
    };
    // rtw_update_channel 80MHz sub-channel indices for block 36..48 (42).
    if [36, 40, 44, 48].map(|p| band5::sc80(p, 42)) != [4, 2, 1, 3]
        || band5::center80(157) != Some(155)
        || band5::center80(165).is_some()
        || band5::constituents80(58) != [52, 56, 60, 64]
    {
        return TestResult::Fail("80MHz block/sub-channel differs from rtw_update_channel");
    }
    let Some(r) = vht::Record::decode(0xc822, &vht_payload(44, 42, 2)) else {
        return TestResult::Fail("valid C22 VHT80 record refused");
    };
    if r.sc() != 1 || r.width() != Width::Eighty(1) || !r.sgi {
        return TestResult::Fail("VHT80 record width/sub-channel wrong");
    }
    let mut stray = vht_payload(44, 42, 1);
    stray[30] = 1; // 2SS index on a one-stream record
    let mut tail = vht_payload(44, 42, 1);
    tail[50] = 1;
    if vht::Record::decode(0xc822, &vht_payload(44, 46, 1)).is_some()
        || vht::Record::decode(0xc821, &vht_payload(44, 42, 2)).is_some()
        || vht::Record::decode(0xc822, &stray).is_some()
        || vht::Record::decode(0xc822, &tail).is_some()
        || vht::Record::decode(0xc821, &vht_payload(44, 42, 1)).is_none()
    {
        return TestResult::Fail("malformed VHT80 record admitted");
    }
    if vht::hardware_allows(6) || !vht::hardware_allows(7) {
        return TestResult::Fail("hw_cap.bw 80MHz decoding differs from hw_bw_cap_to_bitamp");
    }
    // 80MHz span of center 58 is 5250..5330MHz: all four halves DFS.
    let Some(dfs) = vht::Record::decode(0xc822, &vht_payload(52, 58, 1)) else {
        return TestResult::Fail("valid DFS-band VHT80 record refused");
    };
    if vht::admission(&dfs, &domain(5250, 5330, 80, RegFlags::DFS)) != Ok((76, true))
        || vht::admission(&r, &domain(5170, 5250, 80, RegFlags::empty())) != Ok((76, false))
        || vht::admission(&r, &domain(5170, 5250, 40, RegFlags::empty())).is_ok()
        || vht::admission(&dfs, &domain(5250, 5320, 80, RegFlags::DFS)).is_ok()
    {
        return TestResult::Fail("VHT80 regulatory span admission wrong");
    }
    // rtw8822c_set_channel(42, BW80, SC_20_UPPER).
    let mut io = RadioIo::reference();
    if narf_scheduler::block_on(radio::wide5_to(&mut io, 42, Width::Eighty(1))).is_err()
        || crate::rtw88::firmware_transport::now(radio::rf_read(&mut io, 0, 0x18))
            .map(|v| v & 0x733ff)
            != Ok(1 << 16 | 1 << 8 | 1 << 12 | 42)
        || crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x9b0)).map(|v| v & 0xffcf)
            != Ok(0x110a)
        || crate::rtw88::firmware_transport::now(io.read8(0x483)) != Ok(1 | 9 << 4)
        || crate::rtw88::firmware_transport::now(radio::read(&mut io, 0x668)).map(|v| v & 0x180)
            != Ok(0x100)
        || crate::rtw88::firmware_transport::now(radio::verify_wide5(&mut io, 42, Width::Eighty(1)))
            .is_err()
        || crate::rtw88::firmware_transport::now(radio::verify_wide5(&mut io, 42, Width::Eighty(4)))
            .is_ok()
    {
        return TestResult::Fail("C22 BW80 BB/MAC/RF differs from Linux");
    }
    if narf_scheduler::block_on(radio::wide5_to(&mut io, 46, Width::Eighty(1))).is_ok()
        || narf_scheduler::block_on(radio::wide5_to(&mut io, 42, Width::Eighty(5))).is_ok()
    {
        return TestResult::Fail("non-80MHz center or sub-channel programmed");
    }
    // VHT TX power words (0x3a2c.. relative to the VHT1SS MCS7 reference).
    let ofdm = [40, 40, 40, 40, 38, 38, 36, 36];
    let mut regs = alloc::collections::BTreeMap::new();
    let mut cio = RadioIo::reference();
    if crate::rtw88::firmware_transport::now(vht::write_power(&mut cio, 0xc822, &r, Some(ofdm)))
        .is_err()
    {
        return TestResult::Fail("C22 VHT80 power write failed");
    }
    for reg in (0x3a00u16..0x3a40).step_by(4).chain([0x18e8, 0x41e8]) {
        regs.insert(
            reg,
            crate::rtw88::firmware_transport::now(radio::read(&mut cio, reg)).unwrap_or(0),
        );
    }
    let mut read =
        crate::rtw88::firmware_transport::Sampled(|r: u16| Ok(regs.get(&r).copied().unwrap_or(0)));
    if crate::rtw88::firmware_transport::now(vht::check_power(&mut read, 0xc822, &r, Some(ofdm)))
        .is_err()
        || regs.get(&0x3a2c) != Some(&0x0404_0404)
        || regs.get(&0x3a3c) != Some(&0x0202_0202)
        || crate::rtw88::firmware_transport::now(vht::check_power(
            &mut read,
            0xc822,
            &r,
            Some([0; 8]),
        ))
        .is_ok()
    {
        return TestResult::Fail(
            "C22 VHT80 difference words differ from rtw8822c_set_tx_power_diff",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_vht80_record_span_and_bw80_program
);

fn smoke_rtw88_vht80_station_profile_descriptor_rx_and_readback() -> TestResult {
    use crate::rtw88::{packet_format::VhtRates, vht};
    // VHT Operation (192): channel width 1, CCFS0 42, CCFS1 0.
    let ies = [0, 1, b'x', 192, 5, 1, 42, 0, 0xfc, 0xff];
    if vht::vht_operation(&ies) != Some((1, 42, 0)) || vht::vht_operation(&ies[..9]).is_some() {
        return TestResult::Fail("VHT Operation element not parsed");
    }
    let (Some(two), Some(one)) = (
        vht::Record::decode(0xc822, &vht_payload(44, 42, 2)),
        vht::Record::decode(0xc821, &vht_payload(44, 42, 1)),
    ) else {
        return TestResult::Fail("valid VHT80 records refused");
    };
    // rtw_init_vht_cap maps narrowed to the record; get_vht_ra_mask.
    if two.tx_mask() != 0xfffff
        || two.tx_map() != 0xfffa
        || one.tx_mask() != 0x3ff
        || one.tx_map() != 0xfffe
        || vht::rx_map(2) != 0xfffa
        || VhtRates::from_map(0xfff4) != (0xff | 0x1ff << 10)
        || VhtRates::from_map(0xfffe) != 0x3ff
    {
        return TestResult::Fail("VHT MCS map / ra mask differs from get_vht_ra_mask");
    }
    let Some(local) = vht::local(0xc822, 2, &two) else {
        return TestResult::Fail("VHT80 local capability refused");
    };
    let cap = local.capability_body();
    let info = u32::from_le_bytes([cap[0], cap[1], cap[2], cap[3]]);
    // SHORT_GI_80 bit5, RXSTBC_1 bit8, RXLDPC bit4 per chip, MPDU 3895,
    // SU beamformee bit12 with BEAMFORMEE_STS 3 (`bfee_sts_cap`) and MU
    // beamformee bit20; no TX STBC, SU beamformer or MU beamformer.
    if info & (1 << 5 | 1 << 8 | 1 << 20) != (1 << 5 | 1 << 8 | 1 << 20)
        || info & 3 != 0
        || info & (1 << 7 | 1 << 11 | 1 << 19) != 0
        || info & (1 << 12 | 7 << 13) != (1 << 12 | 3 << 13)
        || cap[4..6] != [0xfa, 0xff]
        || cap[8..10] != [0xfa, 0xff]
    {
        return TestResult::Fail("VHT capability differs from rtw_init_vht_cap");
    }
    let p = DataProfile {
        rates: 0xff0,
        qos: true,
        mcs: 0xffff,
        rx_mcs: 0xffff,
        sgi: true,
        band5: true,
        vht: Some(VhtRates {
            tx: 0xfffff,
            rx: 0xfffff,
        }),
        ..DataProfile::LEGACY
    };
    let one_ss = DataProfile {
        vht: Some(VhtRates {
            tx: 0x1ff,
            rx: 0xfffff,
        }),
        ..p
    };
    // get_rate_id ARFR0_AC_2SS 9 / ARFR1_AC_1SS 10; get_highest_vht_tx_rate;
    // RA mask RA_MASK_VHT_RATES | RA_MASK_OFDM_IN_VHT; bw_mode 80.
    if !p.valid()
        || p.rate_id() != 9
        || one_ss.rate_id() != 10
        || p.rate() != 0x3f
        || one_ss.rate() != 0x34
        || p.bw_mode() != 2
        || p.ra_mask() != (0xff0 | 0xfffff << 12)
        || DataProfile::vht_rx_for(0xff) != 0x3ff
        || (DataProfile { band5: false, ..p }).valid()
        || (DataProfile { bw40: true, ..p }).valid()
        || (DataProfile {
            vht: Some(VhtRates {
                tx: 0x7f,
                rx: 0x3ff,
            }),
            ..p
        })
        .valid()
        || (DataProfile {
            vht: Some(VhtRates {
                tx: 0xfffff,
                rx: 0x3ff,
            }),
            ..p
        })
        .valid()
    {
        return TestResult::Fail("VHT80 profile rate id/mask/validity wrong");
    }
    let own = crate::rtw88::ht_tests::OWN;
    let mut frame = vec![0x88, 1, 0, 0];
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x10, 0, 0, 0]);
    frame.extend_from_slice(&[0; 32]);
    let Ok((d, _)) = packet_format::transmit_profile(&frame, own, 0, None, p) else {
        return TestResult::Fail("VHT80 QoS DATA descriptor refused");
    };
    let w = |at: usize| u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]);
    // W5 SHORT bit4 + DATA_BW 2; W1 RATE_ID 9; W4 DATARATE VHT2SS MCS9.
    if w(20) != (1 << 4 | 2 << 5) || (w(4) >> 16) & 31 != 9 || w(16) & 127 != 0x3f {
        return TestResult::Fail("descriptor BW/SGI/rate not at VHT80");
    }
    // RX admission of the advertised VHT set and the 3895-byte VHT MPDU.
    let rx = |rate: u8, length: u32, vht: u32| {
        let mut d = [0u8; packet_format::RX_DESC];
        d[..4].copy_from_slice(&(length | 4 << 16 | 1 << 26).to_le_bytes());
        d[12] = rate;
        packet_format::receive_rates(&d, 0xff, vht).is_ok()
    };
    if !rx(0x35, 100, 0x3ff)
        || rx(0x36, 100, 0x3ff)
        || rx(0x2c, 100, 0)
        || !rx(0x2c, 3895, 0x3ff)
        || rx(0x2c, 3896, 0x3ff)
        || rx(0x0c, 3890, 0)
        || rx(0x1c, 100, 0xfffff)
    {
        return TestResult::Fail("VHT RX rate/length admission wrong");
    }
    // query_phy_status_page1: RXSC 13 is an 80MHz PPDU; RXSC 0 at the
    // committed 80MHz width.
    let mut s = [0u8; 32];
    s[0] = 1;
    s[6] = 44;
    s[5] = 13 << 4;
    let e = packet_phy::parse_at(packet_phy::Chip::C22, 0x2d, &s, 2).ok();
    s[5] = 0;
    let z = packet_phy::parse_at(packet_phy::Chip::C22, 0x2d, &s, 2).ok();
    if !e.is_some_and(|e| e.bandwidth == 2 && e.on_operating(44, 2) && !e.on_operating(44, 1))
        || z.is_none_or(|e| e.bandwidth != 2)
    {
        return TestResult::Fail("80MHz PHY status not admitted at the committed width");
    }
    // C21 readback at 80MHz: HT words unchanged, VHT words from the record,
    // RF18 BW80 on the center.
    let legacy = [30; 12];
    let mcs = [28; 8];
    let mut vwords = [0u8; 12];
    vwords[..10].copy_from_slice(&one.indices[..10]);
    let mut regs = alloc::collections::BTreeMap::new();
    for reg in [0x1d00u16, 0x1d04, 0x1d08] {
        regs.insert(reg, u32::from_le_bytes([30; 4]));
    }
    regs.insert(0x1d0c, u32::from_le_bytes([28; 4]));
    regs.insert(0x1d10, u32::from_le_bytes([28; 4]));
    for (i, reg) in [0x1d2cu16, 0x1d30, 0x1d34].into_iter().enumerate() {
        regs.insert(
            reg,
            u32::from_le_bytes(vwords[i * 4..i * 4 + 4].try_into().unwrap()),
        );
    }
    regs.insert(0x2860, radio8821c::rf18_for(42, 80));
    let read =
        crate::rtw88::firmware_transport::Sampled(|r: u16| Ok(regs.get(&r).copied().unwrap_or(0)));
    if crate::rtw88::firmware_transport::now(radio8821c::operating_readback_vht(
        read, legacy, mcs, vwords, 42,
    ))
    .is_err()
        || crate::rtw88::firmware_transport::now(radio8821c::operating_readback_wide(
            read, legacy, mcs, 42,
        ))
        .is_ok()
        || crate::rtw88::firmware_transport::now(radio8821c::operating_readback_vht(
            read, legacy, mcs, [0; 12], 42,
        ))
        .is_ok()
    {
        return TestResult::Fail("C21 VHT80 readback differs from the 80MHz program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_vht80_station_profile_descriptor_rx_and_readback
);
