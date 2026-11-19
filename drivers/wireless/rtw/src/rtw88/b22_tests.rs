// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822BE ("B22") identity, firmware header and factory-map cases.
//! Written; not yet executed natively.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

include!("firmware/rtl8822b_metadata.rs");

fn smoke_rtw8822be_raw_source_header_and_exact_profile_binding() -> TestResult {
    let bytes = match narf_wifi_fixtures::firmware::sparse_image(
        SOURCE_8822B_LENGTH,
        &[(0, SOURCE_8822B_HEADER)],
    ) {
        Ok(bytes) => bytes,
        Err(_) => return TestResult::Fail("8822B source metadata replay geometry"),
    };
    if SOURCE_8822B_SHA256 != "a72da690597bfa99d8eb6fc2ab090d18d8ad92ac2befd35db1c9e3662d8d8418"
        || filename(0xb822) != Ok("rtw88/rtw8822b_fw.bin")
        // The shared 0x8822 signature never lets the C22 IMEM@0x30000 profile
        // admit the B22 IMEM@0x0 image, nor the C21 signature check pass.
        || parse(0xc822, &bytes).is_ok()
        || parse(0xc821, &bytes).is_ok()
    {
        return TestResult::Fail("8822B source identity or sibling separation");
    }
    let image = match parse(0xb822, &bytes) {
        Ok(image) => image,
        Err(_) => return TestResult::Fail("8822B original firmware section header rejected"),
    };
    if image.info
        != (Info {
            version: 30,
            subversion: 20,
            subindex: 0,
            features: 0,
            h2c: 14,
            sections: 2,
        })
    {
        return TestResult::Fail("8822B original firmware version/H2C facts");
    }
    let expected = [Some((0x200000, 0x2bc8 + 8)), Some((0x0, 0x249c0 + 8)), None];
    for (part, expected) in image.sections.iter().zip(expected) {
        if part.as_ref().map(|p| (p.address, p.bytes.len())) != expected {
            return TestResult::Fail("8822B original section/checksum boundaries");
        }
    }
    // A C22-layout image (IMEM at 0x30000) is not a B22 image.
    let mut relocated = bytes.clone();
    relocated[0x3c..0x40].copy_from_slice(&0x8003_0000u32.to_le_bytes());
    if parse(0xb822, &relocated).is_ok() {
        return TestResult::Fail("8822B accepted a relocated IMEM base");
    }
    let mut truncated = bytes;
    truncated.pop();
    if parse(0xb822, &truncated).is_ok() {
        return TestResult::Fail("8822B accepted truncated section geometry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_raw_source_header_and_exact_profile_binding
);

fn smoke_rtw8822be_factory_map_follows_rtw8822b_efuse_layout() -> TestResult {
    use super::super::efuse8822b::Factory8822b;
    let mut map = [0xffu8; 768];
    map[0xd0..0xd6].copy_from_slice(&[0x00, 0xe0, 0x4c, 0x22, 0xb8, 0x01]);
    map[0x06] = 0x80;
    map[0xb8] = 0x7f;
    map[0xb9] = 0x2a;
    map[0xba] = 0x1c;
    map[0xbc] = 0x05;
    map[0xbd] = 0x11;
    map[0xbf] = 0x22;
    map[0xc1] = 0x31;
    map[0xca] = 0x25; // whole-byte RFE on 8822B, not 8821C's 5-bit field
    map[0xcb..0xcd].copy_from_slice(b"US");
    map[0x10] = 0x2d;
    map[0x10 + 3 * 42] = 0x33;
    let factory = match Factory8822b::for_test(map) {
        Ok(factory) => factory,
        Err(_) => return TestResult::Fail("8822B valid factory map rejected"),
    };
    if factory.mac() != [0x00, 0xe0, 0x4c, 0x22, 0xb8, 0x01]
        || factory.rfe() != 0x25
        || factory.regd() != 1
        || factory.board_option() != 0x31
        || !factory.usb_mode_switch()
        || factory.crystal() != 0x2a
        || factory.thermal() != 0x1c
        || factory.pa_type() != 0x05
        || factory.lna_2g() != 0x11
        || factory.lna_5g() != 0x22
        || factory.channel_plan() != 0x7f
        || factory.country() != *b"US"
        || factory.power_path(0).map(|p| (p.len(), p[0])) != Some((42, 0x2d))
        || factory.power_path(3).map(|p| p[0]) != Some(0x33)
        || factory.power_path(4).is_some()
        // erased power fields are retained raw, not defaulted
        || factory.power_path(1).is_none_or(|p| p.iter().any(|b| *b != 0xff))
    {
        return TestResult::Fail("8822B factory fields differ from rtw8822b_efuse");
    }
    let mut multicast = map;
    multicast[0xd0] = 0x01;
    let mut erased = map;
    erased[0xd0..0xd6].fill(0);
    if Factory8822b::for_test(multicast).is_ok() || Factory8822b::for_test(erased).is_ok() {
        return TestResult::Fail("8822B invalid factory MAC admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_factory_map_follows_rtw8822b_efuse_layout
);

fn smoke_rtw8822be_inactive_mac_follows_rtw8822b_mac_init_and_fifo_pages() -> TestResult {
    for (seed, cut) in [(0u8, 0u8), (1, 3)] {
        let mut io = super::mac_tests::Model::new(seed, cut);
        let info = match narf_scheduler::block_on(crate::rtw88::mac::prepare_for(&mut io, 0xb822)) {
            Ok(info) => info,
            Err(_) => return TestResult::Fail("8822B inactive MAC did not complete"),
        };
        // rtw_set_trx_fifo_info: 2048 pages, csi 0, drv 8 -> 1996/2036/2044.
        if info
            != (crate::rtw88::mac::Info {
                cut,
                reserved_boundary: 1996,
                h2c_page: 2036,
                firmware_tx_page: 2044,
            })
        {
            return TestResult::Fail("8822B FIFO reserved-page layout differs from Linux");
        }
        let writes = |reg: u16| {
            io.trace
                .iter()
                .filter(|op| op.0 == 1 && op.2 == reg)
                .count()
        };
        let first_write = |reg: u16| io.trace.iter().position(|op| op.0 == 1 && op.2 == reg);
        // 8822B-only BIT_PRE_TX_CMD clear precedes AMPDU_MAX_TIME; the
        // 8821C PRECNT/INIRTS/ACKTO_CCK/TRXPTCL_H writes and C22 0x3fc quirk
        // never appear.
        if io.regs[0x4bc] & (1 << 6) != 0
            || first_write(0x4bc).is_none()
            || first_write(0x4bc) > first_write(0x455)
            || [0x4e5, 0x480, 0x639, 0x66c, 0x3fc]
                .into_iter()
                .any(|r| writes(r) != 0)
            || io.regs[0x522] != 255
            || io.regs[0x100] & 0xcf != 0
            || io.regs[0x718] & (1 << 6) == 0
        {
            return TestResult::Fail("8822B chip MAC sequence differs from rtw8822b_mac_init");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_inactive_mac_follows_rtw8822b_mac_init_and_fifo_pages
);

fn b22_factory(rfe: u8, crystal: u8) -> super::super::efuse8822b::Factory8822b {
    let mut map = [0xffu8; 768];
    map[0xd0..0xd6].copy_from_slice(&[0x00, 0xe0, 0x4c, 0x22, 0xb8, 0x02]);
    map[0xca] = rfe;
    map[0xb9] = crystal;
    map[0xc1] = 0x01;
    super::super::efuse8822b::Factory8822b::for_test(map).unwrap()
}
fn b22_features(antennas: u8) -> super::super::hardware::Features {
    super::super::hardware::Features {
        raw: [0; 13],
        hci: 1,
        bandwidth: 2,
        streams: 1,
        antennas,
        protocol: 2,
    }
}

fn smoke_rtw8822be_phy_tables_follow_rtw8822b_phy_set_param_order() -> TestResult {
    use super::super::phy8822b::{prepare, Info};
    // rtw8822b_rfe_defs has only 2/3/5; erased crystal/board and a non-2T2R
    // report are refused rather than defaulted.
    for (rfe, crystal, antennas) in [(0, 0x20, 2), (4, 0x20, 2), (2, 0xff, 2), (2, 0x20, 1)] {
        if Info::from_factory(&b22_factory(rfe, crystal), 0, b22_features(antennas)).is_ok() {
            return TestResult::Fail("8822B PHY admitted an unsupported factory/hardware facet");
        }
    }
    for (cut, rfe) in [(0u8, 2u8), (1, 3), (2, 5)] {
        let info = match Info::from_factory(&b22_factory(rfe, 0xa5), cut, b22_features(2)) {
            Ok(info) => info,
            Err(_) => return TestResult::Fail("8822B PHY rejected a supported RFE"),
        };
        if info.crystal != 0x25 {
            return TestResult::Fail("8822B crystal cap is not efuse crystal_cap & 0x3f");
        }
        let mut io = super::mac_tests::Model::new(cut, cut);
        io.sipi8822b = true;
        let info = match narf_scheduler::block_on(prepare(&mut io, info)) {
            Ok(info) => info,
            Err(_) => return TestResult::Fail("8822B PHY table stage did not complete"),
        };
        let rows = |kind| super::super::phy8822b::tables_for_test(cut, rfe, kind).unwrap();
        let w8 = io.trace.iter().filter(|op| op.0 == 1 && op.1 == 8).count();
        let sipi = |reg: u16| {
            io.trace
                .iter()
                .filter(|op| op.0 == 1 && op.1 == 32 && op.2 == reg)
                .count()
        };
        let rf_rows = |kind| {
            rows(kind)
                .iter()
                .filter(|(a, _)| !matches!(a, 0xffe | 0xfe))
                .count()
        };
        // Two power-on byte RMWs (SYS_FUNC_EN, RF_CTRL) precede the MAC rows;
        // rtw_bf_phy_init adds its two byte writes. config_trx_mode adds one
        // LUT poll (2 path-A SIPI words) and the six RF-mode LUT words.
        if w8 != rows(0).len() + 4
            || sipi(0xc90) != rf_rows(3) + 8
            || sipi(0xe90) != rf_rows(4)
            || u32::from_le_bytes(io.regs[0x808..0x80c].try_into().unwrap()) & (3 << 28) != 3 << 28
            || (u32::from_le_bytes(io.regs[0x24..0x28].try_into().unwrap()) >> 25) & 0x3f != 0x25
            || (u32::from_le_bytes(io.regs[0x28..0x2c].try_into().unwrap()) >> 1) & 0x3f != 0x25
        {
            return TestResult::Fail("8822B PHY table writes differ from rtw_phy_load_tables");
        }
        let first = io.trace.iter().position(|op| op.0 == 1).unwrap();
        if io.trace[first].2 != 0x02 {
            return TestResult::Fail("8822B BB/RF domain power-on is not first");
        }
        let r32 = |reg: usize| u32::from_le_bytes(io.regs[reg..reg + 4].try_into().unwrap());
        // config_trx_mode(AB, AB): RX/TX path select 0x33, MRC on, AGC 0x3231;
        // phy_bf_init grouping bitmap; rfe_init chip-top mux.
        if r32(0x808) & 0xff != 0x33
            || r32(0x80c) & 0xff != 0x33
            || r32(0xc08) & 0xffff != 0x3231
            || r32(0xe08) & 0xffff != 0x3231
            || r32(0x850) & (1 << 23) == 0
            || r32(0x1c94) != 0xafffafff
            || (r32(0x64) >> 28) & 3 != 3
            || r32(0x8a4) & 0xffff != 0x7f7f
            || u32::from(info.igi) != r32(0xc50) & 0x7f
            || usize::from(info.default_ofdm_index) > 36
        {
            return TestResult::Fail("8822B phy_set_param tail differs from rtw8822b.c");
        }
        // channel 0 (no rtw_set_channel yet) is IS_CH_2G_BAND (`<= 14`), so
        // both the EFEM and IFEM RFE programs take their 2.4 GHz 2TX/2RX
        // TRSW 0xa501 (rtw8822b_set_channel_rfe_{efem,ifem}).
        let trsw = 0xa501;
        if r32(0xca0) & 0xffff != trsw || r32(0xea0) & 0xffff != trsw {
            return TestResult::Fail("8822B config_trx_mode RFE TRSW differs");
        }
    }
    if super::super::phy8822b::tables_for_test(0, 4, 0).is_some()
        || super::super::phy8822b::tables_for_test(0, 2, 5).is_some()
    {
        return TestResult::Fail("8822B table selector admitted an undefined RFE/kind");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_phy_tables_follow_rtw8822b_phy_set_param_order
);

fn smoke_rtw8822be_set_channel_follows_rtw8822b_set_channel() -> TestResult {
    use super::super::{band5::Width, phy8822b::Info, radio8822b};
    // RF18 band/channel/RFSI/BW and the RF 0xbe band table.
    if radio8822b::rf18(0, 1, Width::Twenty) != 0x0c01
        || radio8822b::rf18(0, 36, Width::Twenty) != 0x10d24
        || radio8822b::rf18(0, 106, Width::Eighty(1)) != 0x3056a
        || radio8822b::rf18(0, 153, Width::Forty(1)) != 0x50999
        || radio8822b::rf_be(42) != Some(0x5)
        || radio8822b::rf_be(114) != Some(0xff)
        || radio8822b::rf_be(30).is_some()
        || radio8822b::valid_channel(15)
        || radio8822b::valid_channel(37)
    {
        return TestResult::Fail("8822B RF18/RFBE encoding differs from set_channel_rf");
    }
    let info = match Info::from_factory(&b22_factory(3, 0x20), 2, b22_features(2)) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("8822B RFE3 factory rejected"),
    };
    let mut io = super::mac_tests::Model::new(3, 2);
    io.sipi8822b = true;
    let set = |io: &mut super::mac_tests::Model, ch, width| {
        narf_scheduler::block_on(radio8822b::set_channel(io, info, ch, width))
    };
    if set(&mut io, 114, Width::Twenty).is_ok()
        || set(&mut io, 1, Width::Eighty(1)).is_ok()
        || set(&mut io, 36, Width::Forty(3)).is_ok()
    {
        return TestResult::Fail("8822B set_channel admitted an invalid centre/width");
    }
    if set(&mut io, 42, Width::Eighty(2)).is_err() {
        return TestResult::Fail("8822B set_channel 42/80 failed");
    }
    let r32 = |io: &super::mac_tests::Model, reg: usize| {
        u32::from_le_bytes(io.regs[reg..reg + 4].try_into().unwrap())
    };
    // 5 GHz BB, 80MHz ADCCLK, RF18 on both paths, ifem_ext CCA, ifem TRSW.
    if r32(&io, 0x808) & (1 << 28) != 0
        || (r32(&io, 0x958) & 0x1f) != 1
        || (r32(&io, 0x860) >> 17) & 0xfff != 0x494
        || r32(&io, 0x8ac) & 0xff != (2 << 2 | 2)
        || io.regs[0x483] != (2 | 10 << 4)
        || r32(&io, 0x2800 + 0x18 * 4) & 0x70fff != 0x1052a
        || r32(&io, 0x2c00 + 0x18 * 4) & 0x70fff != 0x1052a
        || r32(&io, 0x82c) != 0x75da8010
        || r32(&io, 0x838) != 0x86666361
        || r32(&io, 0xca0) & 0xffff != 0xa5a5
        || io.regs[0x454] & 0x80 == 0
    {
        return TestResult::Fail("8822B 42/80 program differs from rtw8822b_set_channel");
    }
    if set(&mut io, 6, Width::Forty(1)).is_err() {
        return TestResult::Fail("8822B set_channel 6/40 failed");
    }
    if r32(&io, 0x808) & (1 << 28) == 0
        || r32(&io, 0xa24) != 0x384f6577
        || r32(&io, 0xa00) & (1 << 4) == 0
        || r32(&io, 0x8ac) & 0xff != (1 << 2 | 1)
        || r32(&io, 0x2800 + 0x18 * 4) & 0x70fff != 0x0806
        || r32(&io, 0xca0) & 0xffff != 0xa501
        || r32(&io, 0x82c) != 0x75da8010
        || io.regs[0x454] & 0x80 != 0
    {
        return TestResult::Fail("8822B 6/40 program differs from rtw8822b_set_channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_set_channel_follows_rtw8822b_set_channel
);

fn b22_board_factory(rfe: u8, thermal: u8) -> super::super::efuse8822b::Factory8822b {
    let mut map = *b22_factory(rfe, 0x20).logical();
    map[0xba] = thermal;
    super::super::efuse8822b::Factory8822b::for_test(map).unwrap()
}
fn b22_record(request: &super::super::calibration8822b::Request) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec![0; 128];
    bytes[..4].copy_from_slice(b"N2BQ");
    for (at, value) in [(4, 1u16), (6, 128), (12, 0x10ec), (14, 0xb822)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[8..12].copy_from_slice(&128u32.to_le_bytes());
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    bytes[54] = 1;
    bytes[55] = 20;
    for (at, value) in [(56, 4i16), (58, 76), (60, 40)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[62] = 20;
    bytes[63] = 30;
    bytes[64..66].copy_from_slice(b"US");
    bytes
}

fn smoke_rtw8822be_n2bq_envelope_binds_board_and_refuses_unprovisioned() -> TestResult {
    use super::super::calibration8822b::{Board, Error as E, Source};
    use super::super::{mac, phy8822b::Info};
    use narf_capabilities::Cap;
    let mac = mac::Info {
        cut: 1,
        reserved_boundary: 1996,
        h2c_page: 2036,
        firmware_tx_page: 2044,
    };
    let board = |rfe, thermal, mac: mac::Info| {
        let factory = b22_board_factory(rfe, thermal);
        let phy = Info::from_factory(&factory, 1, b22_features(2)).unwrap();
        Board::new(
            &factory,
            phy,
            mac,
            b22_features(2),
            [9; 32],
            crate::rtw88::phy8821c::Host::PCI_B22,
        )
    };
    // An erased thermal meter or a non-B22 FIFO geometry never qualifies.
    if board(3, 0xff, mac) != Err(E::Factory)
        || board(
            3,
            25,
            mac::Info {
                h2c_page: 500,
                ..mac
            },
        ) != Err(E::Identity)
    {
        return TestResult::Fail("8822B calibration board admitted an erased/foreign facet");
    }
    let (b3, b5) = match (board(3, 25, mac), board(5, 25, mac)) {
        (Ok(b3), Ok(b5)) => (b3, b5),
        _ => return TestResult::Fail("8822B calibration board rejected a provisioned map"),
    };
    let request = b3.request();
    if request.identity == b5.request().identity
        || request.filename != "rtw88/rtw8822be-iqk-v1-00e04c22b802.bin"
    {
        return TestResult::Fail("8822B N2BQ request does not bind RFE/identity/filename");
    }
    let load = |bytes, signer, board| {
        Source::Verified {
            bytes,
            signer,
            cap: Cap::bootstrap(),
        }
        .load(board)
    };
    let good = b22_record(&request);
    let mut c21 = good.clone();
    c21[..4].copy_from_slice(b"N21Q");
    let mut hot = good.clone();
    hot[63] = 24; // board thermal 25 outside the measured window
    if load(good.clone(), None, b3).err() != Some(E::Unsigned)
        || load(c21, Some([7; 32]), b3).err() != Some(E::Format)
        || load(hot, Some([7; 32]), b3).err() != Some(E::Format)
        || load(good.clone(), Some([7; 32]), b5).err() != Some(E::Identity)
    {
        return TestResult::Fail("8822B N2BQ decode admitted a foreign/unsigned record");
    }
    let envelope = match load(good, Some([7; 32]), b3) {
        Ok(envelope) => envelope,
        Err(_) => return TestResult::Fail("8822B N2BQ rejected its exact signed record"),
    };
    let us = narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: alloc::vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 20,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    };
    let mut other = us.clone();
    other.country_code = *b"DE";
    if envelope.validate(&us).is_err()
        || envelope.validate(&other).is_ok()
        || !envelope.matches(b3)
        || envelope.matches(b5)
        || envelope.temperature(31).is_ok()
    {
        return TestResult::Fail("8822B N2BQ policy/thermal/board checks differ");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_n2bq_envelope_binds_board_and_refuses_unprovisioned
);

fn smoke_rtw8822be_iqk_commands_and_txagc_follow_linux() -> TestResult {
    use super::super::{command, phy8822b::Info, radio8822b};
    let info = Info::from_factory(&b22_factory(5, 0x20), 3, b22_features(2)).unwrap();
    let packet = match command::phydm8822b(info, 1) {
        Ok(packet) => packet,
        Err(_) => return TestResult::Fail("8822B phydm H2C rejected RFE5"),
    };
    // H2C_PKT_PHYDM_INFO: rfe_option, FW_RF_2T2R, cut, BB_PATH_AB/AB.
    if packet[8..12] != [5, 2, 3, 0x33] || command::iqk8821c(2)[8] != 0 {
        return TestResult::Fail("8822B phydm/IQK H2C fields differ from fw.c");
    }
    let mut io = super::mac_tests::Model::new(1, 1);
    let mut indices = [0u8; 64];
    for (i, v) in indices.iter_mut().enumerate() {
        *v = i as u8 & 0x3f;
    }
    if narf_scheduler::block_on(radio8822b::write_txagc(&mut io, 1, &indices)).is_err()
        || narf_scheduler::block_on(radio8822b::write_txagc(&mut io, 0, &[0x40; 64])).is_ok()
    {
        return TestResult::Fail("8822B TXAGC index bound differs");
    }
    let words: alloc::vec::Vec<_> = io
        .trace
        .iter()
        .filter(|op| op.0 == 1 && op.1 == 32)
        .map(|op| (op.2, op.3))
        .collect();
    // 12 words per path: CCK..HT2S (0x00..0x1b) and VHT1S/VHT2S (0x2c..0x3f).
    if words.len() != 12
        || words[0] != (0x1d80, 0x03020100)
        || words[6] != (0x1d98, 0x1b1a1918)
        || words[7] != (0x1dac, 0x2f2e2d2c)
        || words[11] != (0x1dbc, 0x3f3e3d3c)
    {
        return TestResult::Fail("8822B TXAGC words differ from set_tx_power_index_by_rate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_iqk_commands_and_txagc_follow_linux
);

fn b22_power_record(request: &super::super::operating8822b::Request) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec![0; 192];
    bytes[..4].copy_from_slice(b"N2BP");
    for (at, value) in [(4, 1u16), (6, 192), (12, 0x10ec), (14, 0xb822)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[8..12].copy_from_slice(&192u32.to_le_bytes());
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    bytes[54] = 1;
    bytes[55] = 20;
    for (at, value) in [(56, 4i16), (58, 76), (60, 60), (62, 40)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[64] = 20;
    bytes[65] = 30;
    bytes[66..68].copy_from_slice(b"US");
    for i in 0..12 {
        bytes[68 + i] = if i < 4 { 30 } else { 28 }; // path A
        bytes[80 + i] = if i < 4 { 29 } else { 27 }; // path B
        bytes[92 + 2 * i..94 + 2 * i].copy_from_slice(&50i16.to_le_bytes());
    }
    bytes
}

/// `N2BP`/`N2BS` decode keyed by the B22 PCI identity and the retained N2BQ
/// board; factory channel-group-0 bases bound every coded index.
fn smoke_rtw8822be_n2bp_n2bs_records_bind_board_and_factory_limits() -> TestResult {
    use super::super::operating8822b::{
        factory_limits, request, station_request, Info, Source, StationSource,
    };
    use super::super::{calibration8822b, mac, phy8822b, radio8822b};
    use narf_capabilities::Cap;
    let mut map = *b22_board_factory(3, 25).logical();
    // txpwr_idx_table[0]/[1]: cck_base[0], bw40_base[0], ofdm_diff nibble.
    for (path, cck, bw40, diff) in [(0usize, 32u8, 30u8, 0x02u8), (1, 31, 29, 0x0f)] {
        let at = 0x10 + path * 42;
        map[at] = cck;
        map[at + 6] = bw40;
        map[at + 11] = diff;
    }
    let factory = super::super::efuse8822b::Factory8822b::for_test(map).unwrap();
    if factory_limits(factory.power_path(0).unwrap()) != Ok([32, 32])
        || factory_limits(factory.power_path(1).unwrap()) != Ok([31, 28])
        || factory_limits(&[0xff; 42]).is_ok()
    {
        return TestResult::Fail(
            "8822B factory TXAGC base differs from rtw_phy_get_2g_tx_power_index",
        );
    }
    let info = mac::Info {
        cut: 1,
        reserved_boundary: 1996,
        h2c_page: 2036,
        firmware_tx_page: 2044,
    };
    let phy = phy8822b::Info::from_factory(&factory, 1, b22_features(2)).unwrap();
    let board = calibration8822b::Board::new(
        &factory,
        phy,
        info,
        b22_features(2),
        [9; 32],
        crate::rtw88::phy8821c::Host::PCI_B22,
    )
    .unwrap();
    let calibration = match (calibration8822b::Source::Verified {
        bytes: b22_record(&board.request()),
        signer: Some([7; 32]),
        cap: Cap::bootstrap(),
    })
    .load(board)
    {
        Ok(envelope) => alloc::sync::Arc::new(envelope),
        Err(_) => return TestResult::Fail("8822B N2BQ fixture rejected"),
    };
    let receipt = radio8822b::Calibration {
        channel: 1,
        bandwidth_mhz: 20,
        thermal_before: 25,
        thermal_after: 25,
        iqk_status: 0,
    };
    let req = request(board.request(), receipt);
    if req.filename != "rtw88/rtw8822be-power-v1-00e04c22b802.bin"
        || req.identity == board.request().identity
    {
        return TestResult::Fail("8822B N2BP request filename/identity differs");
    }
    let load = |bytes| {
        Source::Verified {
            bytes,
            signer: Some([7; 32]),
            cap: Cap::bootstrap(),
        }
        .load(req.clone(), &factory, calibration.clone())
    };
    let good = b22_power_record(&req);
    let mut c21 = good.clone();
    c21[..4].copy_from_slice(b"N21P");
    let mut over = good.clone();
    over[80 + 4] = 29; // path-B OFDM above its factory base 28
    let mut foreign = good.clone();
    foreign[14..16].copy_from_slice(&0xc821u16.to_le_bytes());
    if load(c21).is_ok() || load(over).is_ok() || load(foreign).is_ok() {
        return TestResult::Fail("8822B N2BP admitted a foreign/over-limit record");
    }
    let envelope = match load(good) {
        Ok(envelope) => alloc::sync::Arc::new(envelope),
        Err(_) => return TestResult::Fail("8822B N2BP rejected its exact signed record"),
    };
    let table = envelope.txagc(1);
    if table[..4] != [29; 4] || table[4..12] != [27; 8] || table[12..].iter().any(|&v| v != 0) {
        return TestResult::Fail("8822B N2BP TXAGC table differs");
    }
    let us = narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: alloc::vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 20,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    };
    if envelope.invoke(&|| Ok(us.clone()), || Ok(())).is_err()
        || envelope.temperature(31).is_ok()
        || envelope.temperature(25).is_err()
    {
        return TestResult::Fail("8822B N2BP policy/thermal checks differ");
    }
    let power = Info {
        indices: envelope.indices(),
        thermal: 25,
        response_rates: 0x15f,
        identity: req.identity,
        host: req.host,
    };
    let sreq = station_request(power, factory.mac());
    if sreq.filename != "rtw88/rtw8822be-station-v1-00e04c22b802.bin" {
        return TestResult::Fail("8822B N2BS filename differs");
    }
    let mut station = alloc::vec![0u8; 128];
    station[..4].copy_from_slice(b"N2BS");
    for (at, value) in [(4, 1u16), (6, 128), (12, 0x10ec), (14, 0xb822)] {
        station[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    station[8..12].copy_from_slice(&128u32.to_le_bytes());
    station[16..48].copy_from_slice(&sreq.identity);
    station[48..54].copy_from_slice(&sreq.mac);
    station[54] = 1;
    station[55] = 20;
    for (at, value) in [(56, 4i16), (58, 76), (60, 50), (62, 40), (64, 60)] {
        station[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    station[66] = 0;
    station[67] = 63;
    station[68..70].copy_from_slice(b"US");
    let sload = |bytes| {
        StationSource::Verified {
            bytes,
            signer: Some([7; 32]),
            cap: Cap::bootstrap(),
        }
        .load(sreq.clone(), envelope.clone())
    };
    let mut narrow = station.clone();
    narrow[67] = 40; // static awake profile must cover every meter value
    if sload(narrow).is_ok() {
        return TestResult::Fail("8822B N2BS admitted a narrow thermal window");
    }
    match sload(station) {
        Ok(grant)
            if grant.matches(&sreq) && grant.invoke(&|| Ok(us.clone()), || Ok(())).is_ok() =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("8822B N2BS rejected its exact signed record"),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_n2bp_n2bs_records_bind_board_and_factory_limits
);

/// `rtw8822b_txagc_swing_offset` arithmetic over `default_ofdm_index`.
fn smoke_rtw8822be_pwr_track_swing_offset_follows_linux() -> TestResult {
    use super::super::tracking8822b::{swing_offset, Tracker};
    let cases = [
        ((3i8, 10u8, 24u8), (3u8, 24u8)),
        ((12, 5, 24), (5, 31)),
        ((20, 0x20, 24), (15, 29)), // max_tx_pwr_idx_offset 0xf
        ((30, 2, 24), (2, 34)),     // swing_upper_bound default + 10
        ((-5, 10, 24), (0, 19)),
        ((-30, 10, 24), (0, 0)), // swing_lower_bound 0
        ((5, 0, 36), (0, 36)),   // RTW_TXSCALE_SIZE - 1
    ];
    for ((delta, offset, default), expected) in cases {
        if swing_offset(delta, offset, default) != expected {
            return TestResult::Fail(
                "8822B txagc/swing offset differs from rtw8822b_txagc_swing_offset",
            );
        }
    }
    if Tracker::new(25, 24).delta_power() != [0, 0] {
        return TestResult::Fail("8822B power tracker initial delta differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_pwr_track_swing_offset_follows_linux
);

/// The admitted B22 station chain fixture: factory, PHY facts, the `N2BS`
/// grant over `N2BP` + `N2BQ`, and the US rule they are qualified under.
type B22Station = (
    super::super::efuse8822b::Factory8822b,
    super::super::phy8822b::Info,
    alloc::sync::Arc<super::super::operating8822b::Grant>,
    narf_wireless::reg::RegulatoryDomain,
);
fn b22_station_fixture() -> Option<B22Station> {
    b22_station_fixture_for(b22_features(2))
}
/// [`b22_station_fixture`] over an explicit firmware hardware report.
fn b22_station_fixture_for(features: super::super::hardware::Features) -> Option<B22Station> {
    use super::super::operating8822b::{request, station_request, Info, Source, StationSource};
    use super::super::{calibration8822b, mac, phy8822b, radio8822b};
    use narf_capabilities::Cap;
    let mut map = *b22_board_factory(3, 25).logical();
    for (path, cck, bw40, diff) in [(0usize, 32u8, 30u8, 0x02u8), (1, 31, 29, 0x0f)] {
        let at = 0x10 + path * 42;
        // Group 0 carries the N2BP facts; groups 1..4 (the `N2BO` cases)
        // step the base down by one index per group.
        for group in 0..5 {
            map[at + group] = cck - group as u8;
            map[at + 6 + group] = bw40 - group as u8;
        }
        map[at + 11] = diff;
        // HT1S bw20 +0 (high nibble of `diff`), HT2S bw20 -1.
        map[at + 12] = 0x0f;
    }
    let factory = super::super::efuse8822b::Factory8822b::for_test(map).ok()?;
    let info = mac::Info {
        cut: 1,
        reserved_boundary: 1996,
        h2c_page: 2036,
        firmware_tx_page: 2044,
    };
    let phy = phy8822b::Info::from_factory(&factory, 1, features).ok()?;
    let board = calibration8822b::Board::new(
        &factory,
        phy,
        info,
        features,
        [9; 32],
        crate::rtw88::phy8821c::Host::PCI_B22,
    )
    .ok()?;
    let calibration = alloc::sync::Arc::new(
        calibration8822b::Source::Verified {
            bytes: b22_record(&board.request()),
            signer: Some([7; 32]),
            cap: Cap::bootstrap(),
        }
        .load(board)
        .ok()?,
    );
    let receipt = radio8822b::Calibration {
        channel: 1,
        bandwidth_mhz: 20,
        thermal_before: 25,
        thermal_after: 25,
        iqk_status: 0,
    };
    let req = request(board.request(), receipt);
    let envelope = alloc::sync::Arc::new(
        Source::Verified {
            bytes: b22_power_record(&req),
            signer: Some([7; 32]),
            cap: Cap::bootstrap(),
        }
        .load(req.clone(), &factory, calibration)
        .ok()?,
    );
    let power = Info {
        indices: envelope.indices(),
        thermal: 25,
        response_rates: 0x15f,
        identity: req.identity,
        host: req.host,
    };
    let sreq = station_request(power, factory.mac());
    let mut station = alloc::vec![0u8; 128];
    station[..4].copy_from_slice(b"N2BS");
    for (at, value) in [(4, 1u16), (6, 128), (12, 0x10ec), (14, 0xb822)] {
        station[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    station[8..12].copy_from_slice(&128u32.to_le_bytes());
    station[16..48].copy_from_slice(&sreq.identity);
    station[48..54].copy_from_slice(&sreq.mac);
    station[54] = 1;
    station[55] = 20;
    for (at, value) in [(56, 4i16), (58, 76), (60, 50), (62, 40), (64, 60)] {
        station[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    station[67] = 63;
    station[68..70].copy_from_slice(b"US");
    let grant = StationSource::Verified {
        bytes: station,
        signer: Some([7; 32]),
        cap: Cap::bootstrap(),
    }
    .load(sreq, envelope)
    .ok()?;
    let us = narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: alloc::vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 20,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    };
    Some((factory, phy, grant, us))
}

/// The B22 base packet gate is keyed by `10ec:b822`, binds the `N2BS` MAC and
/// exposes no C21/C22 continuation family; the awake-station program refuses
/// before any register access when the transport has no B22 station arm.
fn smoke_rtw8822be_station_gate_and_program_refuse_without_station_arm() -> TestResult {
    use super::super::{phy8821c::Host, power_policy::Gate, radio8822b};
    let Some((factory, phy, grant, us)) = b22_station_fixture() else {
        return TestResult::Fail("8822B station fixture rejected");
    };
    let gate = Gate::b22(grant.clone(), phy);
    if gate.did() != 0xb822
        || gate.host() != Host::PCI_B22
        || Host::PCI_B22.family() != "rtw8822be"
        || gate.own() != factory.mac()
        || gate.extension_base().is_none()
        || gate.calibrated_base().is_some()
        || gate.base_request().is_none()
        // N2BH (rtw_phy_get_2g_tx_power_index HT20 ceilings) exposes B22 HT
        // facts over the base; no HT continuation is bound (base_only).
        || gate.ht_facts().is_none()
        || gate.c21_indices().is_some()
        || !gate.base_only()
        || gate.current_with_policy_for_test(&us).is_err()
    {
        return TestResult::Fail("8822B station gate differs from its N2BS base");
    }
    let mut io = super::mac_tests::Model::new(1, 1);
    let result = narf_scheduler::block_on(radio8822b::prepare_station(
        &mut io,
        &factory,
        phy,
        grant,
        move || Ok(us.clone()),
    ));
    if result.is_ok() || !io.trace.is_empty() {
        return TestResult::Fail("8822B station program touched hardware without a station arm");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_station_gate_and_program_refuse_without_station_arm
);

/// One signed 128-byte `N2BO` channel record for `channel` over `gate`.
fn b22_channel_record(
    gate: &super::super::power_policy::Gate,
    channel: u8,
    a: [u8; 12],
    b: [u8; 12],
) -> Option<alloc::vec::Vec<u8>> {
    let kind = super::super::channel_policy::kind(channel)?;
    let req = super::super::qualification::request(kind, gate).ok()?;
    let mut r = alloc::vec![0u8; 128];
    r[..4].copy_from_slice(b"N2BO");
    r[4..8].copy_from_slice(&[1, 0, 128, 0]);
    r[8..12].copy_from_slice(&128u32.to_le_bytes());
    r[12..16].copy_from_slice(&req.host.header());
    r[16..48].copy_from_slice(&req.identity);
    r[48..54].copy_from_slice(&req.mac);
    r[54..56].copy_from_slice(&[b'O', 1]);
    r[56] = channel;
    r[57] = 20;
    for (at, value) in [(58, 4i16), (60, 76), (62, 50), (64, 40), (66, 60)] {
        r[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    r[70..82].copy_from_slice(&a);
    r[92..104].copy_from_slice(&b);
    Some(r)
}

/// `N2BO` binds the exact `N2BS` base with the B22 channel contract, carries
/// both paths' indices bounded by that primary's own factory group, scopes
/// continuation identities per channel, and the retune program replays
/// `rtw8822b_set_channel` + both paths' TXAGC with readback. Written; not
/// yet executed natively.
fn smoke_rtw8822be_n2bo_channel_record_binds_base_and_retunes() -> TestResult {
    use super::super::{channel_policy, power_policy::Gate, qualification};
    use narf_capabilities::Cap;
    let Some((factory, phy, grant, _)) = b22_station_fixture() else {
        return TestResult::Fail("8822B station fixture rejected");
    };
    let base = Gate::b22(grant, phy);
    let Some(request) = base.base_request() else {
        return TestResult::Fail("8822B base request missing for N2BO");
    };
    let m = factory.mac();
    if request.filename
        != alloc::format!(
            "rtw88/rtw8822be-station-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5]
        )
    {
        return TestResult::Fail("8822B N2BO base is not the exact N2BS request");
    }
    let Some(six) = channel_policy::kind(6) else {
        return TestResult::Fail("channel 6 kind missing");
    };
    match qualification::request(six, &base) {
        Ok(req) if req.filename.starts_with("rtw88/rtw8822be-channel06-v1-") => {}
        _ => return TestResult::Fail("8822B N2BO request/filename differs"),
    }
    // Group 2 (channel 6) factory: A CCK 30 / OFDM 28+2, B CCK 29 / OFDM 27-1.
    let a = [30, 30, 30, 30, 30, 30, 30, 30, 29, 29, 28, 28];
    let b = [29, 29, 29, 29, 26, 26, 26, 26, 26, 25, 25, 24];
    let load = |bytes| {
        qualification::Source::Verified {
            bytes,
            signer: Some([7; 32]),
            cap: Cap::bootstrap(),
        }
        .load(six, &base)
    };
    let (Some(good), Some(over)) = (
        b22_channel_record(&base, 6, a, b),
        // Over the path-B group-2 OFDM ceiling (26) by one.
        b22_channel_record(
            &base,
            6,
            a,
            [29, 29, 29, 29, 27, 26, 26, 26, 26, 25, 25, 24],
        ),
    ) else {
        return TestResult::Fail("8822B N2BO fixture");
    };
    let mut tail = good.clone();
    tail[56 + 48] = 1;
    let mut magic = good.clone();
    magic[2] = b'2';
    if load(tail).is_ok() || load(magic).is_ok() {
        return TestResult::Fail("8822B N2BO admitted a nonzero tail or C22 magic");
    }
    narf_wireless::reg::db::set_domain(narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: alloc::vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 20,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    });
    let result = (|| {
        if load(over).is_ok_and(|g| base.with_channel(g).is_ok()) {
            return TestResult::Fail("8822B N2BO admitted an index over its group ceiling");
        }
        let Ok(g) = load(good) else {
            return TestResult::Fail("8822B N2BO record rejected");
        };
        let Ok(gate) = base.with_channel(g) else {
            return TestResult::Fail("8822B N2BO did not bind over the base");
        };
        if gate.channel() != 6
            || gate.b22_indices() != Some([a, b])
            || gate.extension_request().is_none_or(|r| {
                // Continuations bind the channel-scoped N2BL request.
                !r.filename
                    .starts_with("rtw88/rtw8822be-ch06-legacy-wmm-v1-")
                    || r.identity == request.identity
            })
            || gate.without_channel().b22_indices() == Some([a, b])
            || gate.current().is_err()
        {
            return TestResult::Fail("8822B N2BO gate facts differ");
        }
        let mut io = super::mac_tests::Model::new(3, 2);
        io.sipi8822b = true;
        if narf_scheduler::block_on(channel_policy::program(&mut io, &gate, false)).is_err() {
            return TestResult::Fail("8822B N2BO retune program failed");
        }
        let r32 = |reg: usize| u32::from_le_bytes(io.regs[reg..reg + 4].try_into().unwrap());
        if r32(0x2800 + 0x18 * 4) & 0x70fff != 0x0c06
            || r32(0x2c00 + 0x18 * 4) & 0x70fff != 0x0c06
            || r32(0x1d00) != u32::from_le_bytes([30; 4])
            || r32(0x1d88) != u32::from_le_bytes([26, 25, 25, 24])
            || r32(0x1d0c) != 0
            || r32(0x440) != 0x1f
        {
            return TestResult::Fail("8822B N2BO retune differs from rtw8822b_set_channel + TXAGC");
        }
        TestResult::Pass
    })();
    narf_wireless::reg::db::clear_domain();
    result
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_n2bo_channel_record_binds_base_and_retunes
);

/// `N2BD` admits only the 8822B mechanisms (DIG over 0xc50/0xe50, RA), uses
/// the 8822B PHY-status PWDB layout and binds the B22 dm contract over the
/// `N2BS` base. Written; not yet executed natively.
fn smoke_rtw8822be_n2bd_dm_admission_and_phy_status() -> TestResult {
    use super::super::{dm, power_policy::Gate, qualification};
    let Some((factory, phy, grant, _)) = b22_station_fixture() else {
        return TestResult::Fail("8822B station fixture rejected");
    };
    let payload = |enabled: u16| {
        let mut p = [0u8; qualification::PAYLOAD];
        p[..2].copy_from_slice(&enabled.to_le_bytes());
        p[2] = 0x40;
        p[8] = 63;
        p
    };
    if dm::bounds(0xb822, &payload(dm::DIG | dm::RA)).is_none()
        || dm::bounds(0xb822, &payload(dm::DIG | dm::CCK_PD)).is_some()
        || dm::bounds(0xb822, &payload(dm::PWR_TRACK)).is_none()
        || dm::bounds(0xb822, &payload(dm::EDCCA)).is_none()
        || dm::bounds(0xb822, &payload(dm::PATH_DIV)).is_some()
    {
        return TestResult::Fail("8822B N2BD mechanism set differs from rtw8822b ops");
    }
    let facts = dm::Facts {
        did: 0xb822,
        rfe: phy.rfe,
        crystal: phy.crystal,
        thermal: [factory.thermal(), 0xff],
        power_track_type: 0,
        cck_gi: [0, 0],
    };
    let mut status = [0u8; 32];
    status[1] = 70; // PWDB / PWDB_A: -40 dBm
    status[2] = 60; // PWDB_B (page 1 only): -50 dBm
    let (Some(cck), Some(ofdm)) = (
        dm::sample(&facts, 0, &status),
        dm::sample(&facts, 4, &{
            let mut s = status;
            s[0] = 1;
            s
        }),
    ) else {
        return TestResult::Fail("8822B PHY status page refused");
    };
    if cck.rssi != dm::rf_power_2_rssi(&[-40])
        || ofdm.rssi != dm::rf_power_2_rssi(&[-40, -50])
        || ofdm.rssi == cck.rssi
    {
        return TestResult::Fail("8822B PHY status RSSI differs from query_phy_status");
    }
    let gate = Gate::b22(grant, phy);
    match qualification::request(&dm::KIND, &gate) {
        Ok(r) if r.filename.starts_with("rtw88/rtw8822be-dm-v1-") => TestResult::Pass,
        _ => TestResult::Fail("8822B N2BD request/filename differs"),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_n2bd_dm_admission_and_phy_status
);

/// `rtw8822b_pwr_track` under the dm authority: trigger pass, then the
/// sampled pass writes `rtw8822b_pwrtrack_set_pwr` per path from the 2.4 GHz
/// OFDM tables and the programmed index; out-of-window samples and swing
/// deltas beyond the `N2BD` power bounds refuse before any write; threshold 8
/// reports `rtw_phy_pwrtrack_need_iqk`. The `N2BW` kind binds only its exact
/// `N2BD`. Written; not yet executed natively.
fn smoke_rtw8822be_n2bw_power_tracking_and_iqk_admission() -> TestResult {
    use super::super::dm::Authority;
    use super::super::firmware_transport::Error;
    use super::super::tracking8822b::{Limits, Pass, Tracker, KIND};
    use super::super::{qualification, radio8822b};
    struct Open;
    impl Authority for Open {
        fn run<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
            op()
        }
        fn b22_channel(&self) -> Option<u8> {
            Some(1)
        }
    }
    let mut payload = [0u8; qualification::PAYLOAD];
    payload[..32].copy_from_slice(&[5; 32]);
    payload[32] = 10;
    payload[33] = 50;
    let admit = |did: u16, p: &[u8; qualification::PAYLOAD]| (KIND.admit)(did, p);
    let mut tail = payload;
    tail[40] = 1;
    let mut unbound = payload;
    unbound[..32].copy_from_slice(&[0; 32]);
    if !admit(0xb822, &payload)
        || admit(0xc821, &payload)
        || admit(0xb822, &tail)
        || admit(0xb822, &unbound)
    {
        return TestResult::Fail("8822B N2BW payload admission differs");
    }
    let mut io = super::mac_tests::Model::new(3, 2);
    io.sipi8822b = true;
    let at = |reg: usize| reg..reg + 4;
    io.regs[at(0xc1c)].copy_from_slice(&(radio8822b::TXSCALE[24] << 21).to_le_bytes());
    io.regs[at(0xe1c)].copy_from_slice(&(radio8822b::TXSCALE[24] << 21).to_le_bytes());
    let meter = |io: &mut super::mac_tests::Model, t: u32| {
        io.regs[0x2800 + 0x42 * 4..0x2800 + 0x42 * 4 + 4].copy_from_slice(&(t << 10).to_le_bytes())
    };
    let limits = Limits {
        thermal: [10, 50],
        up: 10,
        down: 10,
    };
    let indices = ([[0x20; super::super::tracking8822b::RATES]; 2], 12);
    let mut tracker = Tracker::new(25, 24);
    let pass = |io: &mut super::mac_tests::Model, t: &mut Tracker, limits: Limits| {
        narf_scheduler::block_on(t.pass(io, &Open, indices, |_| Ok(()), limits, 4))
    };
    // A rate the committed program never wrote (VHT1SS MCS0 over a
    // legacy12 table) skips without touching RF42.
    let rf42 = io.regs[0x2800 + 0x42 * 4..0x2800 + 0x42 * 4 + 4].to_vec();
    if narf_scheduler::block_on(tracker.pass(&mut io, &Open, indices, |_| Ok(()), limits, 0x2c))
        != Ok(Pass::Skipped)
        || io.regs[0x2800 + 0x42 * 4..0x2800 + 0x42 * 4 + 4] != rf42[..]
    {
        return TestResult::Fail("8822B power tracking failed or wrote on an unwritten rate");
    }
    if pass(&mut io, &mut tracker, limits) != Ok(Pass::Triggered) {
        return TestResult::Fail("8822B power tracking did not trigger RF42 first");
    }
    meter(&mut io, 30);
    if pass(&mut io, &mut tracker, limits)
        != Ok(Pass::Tracked {
            thermal: 30,
            iqk: false,
        })
    {
        return TestResult::Fail("8822B power tracking sample differs");
    }
    let r32 = |io: &super::mac_tests::Model, reg: usize| {
        u32::from_le_bytes(io.regs[at(reg)].try_into().unwrap())
    };
    // delta 5: _2ga_p[5] = 3, _2gb_p[5] = 2; offset min(0x3f - 0x20, 0xf).
    if (r32(&io, 0xc94) >> 25) & 0x1f != 3
        || (r32(&io, 0xe94) >> 25) & 0x1f != 2
        || r32(&io, 0xc1c) >> 21 != radio8822b::TXSCALE[24]
        || tracker.delta_power() != [3, 2]
    {
        return TestResult::Fail("8822B pwrtrack_set_pwr differs from rtw8822b_pwrtrack_set");
    }
    let mut hot = Tracker::new(25, 24);
    meter(&mut io, 55);
    let _ = pass(&mut io, &mut hot, limits);
    if pass(&mut io, &mut hot, limits) != Err(Error::Prerequisite) {
        return TestResult::Fail("8822B power tracking admitted a sample outside N2BD");
    }
    let mut tight = Tracker::new(25, 24);
    meter(&mut io, 45);
    let _ = pass(&mut io, &mut tight, Limits { up: 2, ..limits });
    if pass(&mut io, &mut tight, Limits { up: 2, ..limits }) != Err(Error::Prerequisite) {
        return TestResult::Fail("8822B power tracking exceeded the N2BD power bound");
    }
    let mut drift = Tracker::new(25, 24);
    meter(&mut io, 34);
    let _ = pass(&mut io, &mut drift, limits);
    if pass(&mut io, &mut drift, limits)
        != Ok(Pass::Tracked {
            thermal: 34,
            iqk: true,
        })
    {
        return TestResult::Fail("8822B need_iqk threshold 8 differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_n2bw_power_tracking_and_iqk_admission
);

/// `rtw8822b_adaptivity` thresholds: `rtw_phy_adaptivity_set_mode` with the
/// 8822B `l2h_th_ini_{cs,ad}` (60/36) and the normal/adaptivity formulas.
/// Written; not yet executed natively.
fn smoke_rtw8822be_edcca_adaptivity_follows_rtw8822b() -> TestResult {
    use super::super::dm::{edcca_mode, edcca_mode8822b, EdccaMode, Tracker};
    if edcca_mode8822b(*b"DE") != EdccaMode::Adaptivity(36)
        || edcca_mode8822b(*b"JP") != EdccaMode::Adaptivity(60)
        || edcca_mode8822b(*b"US") != EdccaMode::Normal
        || edcca_mode(*b"DE") != EdccaMode::Adaptivity(45)
    {
        return TestResult::Fail("8822B EDCCA mode differs from rtw_phy_adaptivity_set_mode");
    }
    let cases = [
        ((0x20u8, EdccaMode::Normal), (48u8, 40u8)),
        ((0x40, EdccaMode::Normal), (0x48, 0x40)),
        ((0x20, EdccaMode::Adaptivity(36)), (0x20, 0x19)),
        ((0x30, EdccaMode::Adaptivity(36)), (36, 29)),
        ((0x40, EdccaMode::Adaptivity(60)), (60, 53)),
    ];
    for ((igi, mode), expected) in cases {
        if Tracker::edcca8822b(igi, mode) != expected {
            return TestResult::Fail("8822B EDCCA thresholds differ from rtw8822b_adaptivity");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_edcca_adaptivity_follows_rtw8822b
);

/// One signed 128-byte `N2BL` legacy12/WMM record (`station_profile` layout).
fn b22_legacy_record(
    r: &super::super::station_profile::Request,
    rates: u16,
    wmm: bool,
) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0u8; 128];
    b[..4].copy_from_slice(b"N2BL");
    b[4..8].copy_from_slice(&[1, 0, 128, 0]);
    b[8..12].copy_from_slice(&128u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x22, 0xb8]);
    b[16..48].copy_from_slice(&r.identity);
    b[48..54].copy_from_slice(&r.mac);
    b[54..56].copy_from_slice(&[1, 20]);
    for (at, v) in [(56, 4i16), (58, 76), (60, 48), (62, 48)] {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    for i in 0..12 {
        b[64 + i * 2..66 + i * 2].copy_from_slice(&(40i16 + i as i16).to_le_bytes());
    }
    b[88..90].copy_from_slice(&rates.to_le_bytes());
    b[90] = u8::from(wmm);
    b
}

/// `N2BL` binds the exact `N2BS` grant (identity hashes its record digest
/// and both paths' `N2BP` indices) under the B22 magic/header; C21/C22
/// magics, a foreign identity or MAC refuse, and a bound record admits
/// exactly its legacy12/WMM DATA profile; the legacy-only retune program
/// refuses the bound gate. Written; not yet executed natively.
fn smoke_rtw8822be_n2bl_legacy_wmm_binds_n2bs() -> TestResult {
    use super::super::{packet_format::DataProfile, power_policy::Gate, station_profile::Source};
    use narf_capabilities::Cap;
    let Some((factory, phy, grant, us)) = b22_station_fixture() else {
        return TestResult::Fail("8822B station fixture rejected");
    };
    let gate = Gate::b22(grant, phy);
    let Some(base) = gate.extension_base() else {
        return TestResult::Fail("8822B gate exposes no N2xL base");
    };
    let r = base.request();
    if base.did() != 0xb822
        || r.mac != factory.mac()
        || !r.filename.starts_with("rtw88/rtw8822be-legacy-wmm-v1-")
        || gate.extension_request().as_ref() != Some(&r)
    {
        return TestResult::Fail("8822B N2BL request is not the N2BS-scoped one");
    }
    let db = alloc::sync::Arc::new(narf_wireless::reg::db::Database::new());
    db.install(us);
    let load = |bytes| {
        Source::Verified {
            bytes,
            signer: Some([7; 32]),
            cap: Cap::bootstrap(),
            policy: db.clone(),
        }
        .load(gate.clone())
    };
    for fault in 0..5 {
        let mut b = b22_legacy_record(&r, 0xfff, true);
        match fault {
            0 => b[..4].copy_from_slice(b"N22L"),
            1 => b[..4].copy_from_slice(b"N21L"),
            2 => b[14] = 0x21,
            3 => b[16] ^= 1,
            _ => b[48] ^= 1,
        }
        if load(b).is_ok() {
            return TestResult::Fail("8822B N2BL accepted a foreign record");
        }
    }
    let Ok(l) = load(b22_legacy_record(&r, 0xfff, true)) else {
        return TestResult::Fail("8822B N2BL rejected its exact record");
    };
    let Ok(bound) = gate.with_extension(l) else {
        return TestResult::Fail("8822B N2BL did not bind over N2BS");
    };
    if bound.extension_base().is_some()
        || bound.ht_base().is_none()
        || !bound.allows_profile(DataProfile::LEGACY)
    {
        return TestResult::Fail("8822B N2BL binding differs from the C21/C22 family");
    }
    // program8822b writes legacy-only tables: refused over a bound extension.
    let mut io = super::mac_tests::Model::new(3, 2);
    io.sipi8822b = true;
    if !matches!(
        narf_scheduler::block_on(super::super::channel_policy::program(
            &mut io, &bound, false
        )),
        Err(super::super::firmware_transport::Error::State)
    ) {
        return TestResult::Fail("8822B retune program ran over a bound N2BL");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_n2bl_legacy_wmm_binds_n2bs
);

/// One signed 256-byte B22 `N2BH` v2 record: path-A MCS0..15 at 70..86,
/// path-B MCS8..15 at 174..182 (`ht::Grant::decode`).
fn b22_ht_record(r: &super::super::ht::Request, a: [u8; 16], b: [u8; 8]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; 256];
    v[..4].copy_from_slice(b"N2BH");
    v[4..8].copy_from_slice(&[2, 0, 0, 1]);
    v[8..12].copy_from_slice(&256u32.to_le_bytes());
    v[12..16].copy_from_slice(&[0xec, 0x10, 0x22, 0xb8]);
    v[16..48].copy_from_slice(&r.identity);
    v[48..54].copy_from_slice(&r.mac);
    v[54..56].copy_from_slice(&[1, 20]);
    for (at, x) in [(56, 4i16), (58, 76), (60, 60), (62, 40)] {
        v[at..at + 2].copy_from_slice(&x.to_le_bytes());
    }
    v[64..66].copy_from_slice(&[0, 63]);
    v[66..68].copy_from_slice(&0xffffu16.to_le_bytes());
    v[68] = 1;
    v[69] = 2;
    v[70..86].copy_from_slice(&a);
    for i in 0..44 {
        v[86 + i * 2..88 + i * 2].copy_from_slice(&40i16.to_le_bytes());
    }
    v[174..182].copy_from_slice(&b);
    v
}

/// `N2BH` binds the exact `N2BL` grant on a 2T2R VHT-protocol report: the
/// v1 proposal carries a B22 two-stream child, MCS indices are bounded by
/// both paths' `rtw_phy_get_2g_tx_power_index` HT20 ceilings (txgi 1), foreign
/// magics / over-ceiling path-B indices / a dirty tail refuse, and the bound
/// grant's tracking table is legacy12 + MCS0..15 per path (path-B HT1S takes
/// path A's index); an `N2BR` recipient-BA record binds over it while
/// C21/C22 magics refuse. Written; not yet executed natively.
fn smoke_rtw8822be_n2bh_ht20_2ss_binds_n2bl() -> TestResult {
    use super::super::{ht, power_policy::Gate, station_profile};
    use narf_capabilities::Cap;
    let features = super::super::hardware::Features {
        raw: [0; 13],
        hci: 1,
        bandwidth: 2,
        streams: 2,
        antennas: 2,
        protocol: 3,
    };
    let Some((_, phy, grant, us)) = b22_station_fixture_for(features) else {
        return TestResult::Fail("8822B 2T2R station fixture rejected");
    };
    let legacy = grant.power().indices();
    let gate = Gate::b22(grant, phy);
    let Some(f) = gate.ht_facts() else {
        return TestResult::Fail("8822B gate exposes no HT facts");
    };
    // Path A 30/29, path B 29/28 (fixture bytes 6, 11, 12): intersected.
    if f.maximum != 29 || f.maximum_2ss != Some(28) || f.legacy != legacy[0] || f.local().is_none()
    {
        return TestResult::Fail(
            "8822B HT20 factory facts differ from rtw_phy_get_2g_tx_power_index",
        );
    }
    let db = alloc::sync::Arc::new(narf_wireless::reg::db::Database::new());
    db.install(us);
    let Some(lr) = gate.extension_request() else {
        return TestResult::Fail("8822B N2BL request missing");
    };
    let Ok(l) = (station_profile::Source::Verified {
        bytes: b22_legacy_record(&lr, 0xfff, true),
        signer: Some([7; 32]),
        cap: Cap::bootstrap(),
        policy: db,
    })
    .load(gate.clone()) else {
        return TestResult::Fail("8822B N2BL rejected");
    };
    let Ok(gate) = gate.with_extension(l.clone()) else {
        return TestResult::Fail("8822B N2BL did not bind");
    };
    let Ok(r) = ht::request(&l) else {
        return TestResult::Fail("8822B HT request refused over N2BL");
    };
    let Some(r2) = r.two_streams.clone() else {
        return TestResult::Fail("8822B 2T2R HT request has no two-stream child");
    };
    if !r.filename.starts_with("rtw88/rtw8822be-ht20-v1-")
        || !r2.filename.starts_with("rtw88/rtw8822be-ht20-2ss-v2-")
        || r2.identity == r.identity
    {
        return TestResult::Fail("8822B HT request naming/identity differs");
    }
    let a: [u8; 16] = core::array::from_fn(|i| {
        if i < 8 {
            29 - i as u8
        } else {
            28 - (i as u8 - 8)
        }
    });
    let b: [u8; 8] = core::array::from_fn(|i| 27 - i as u8);
    let load = |bytes| {
        ht::Source::Verified {
            bytes,
            signer: Some([7; 32]),
            cap: Cap::bootstrap(),
        }
        .load(l.clone())
    };
    for fault in 0..4 {
        let mut v = b22_ht_record(&r2, a, b);
        match fault {
            0 => v[..4].copy_from_slice(b"N22H"),
            1 => v[174] = 29,
            2 => v[182] = 1,
            _ => v[70] = 30,
        }
        if load(v).is_ok() {
            return TestResult::Fail("8822B N2BH accepted a foreign or over-ceiling record");
        }
    }
    let Ok(h) = load(b22_ht_record(&r2, a, b)) else {
        return TestResult::Fail("8822B N2BH rejected its exact record");
    };
    if h.mcs() != 0xffff || !h.sgi() {
        return TestResult::Fail("8822B N2BH selection differs from its record");
    }
    let Ok(gate) = gate.with_ht(h.clone()) else {
        return TestResult::Fail("8822B N2BH did not bind over N2BL");
    };
    let Some((rates, count)) = gate.b22_rate_indices() else {
        return TestResult::Fail("8822B HT tracking table missing");
    };
    for path in 0..2 {
        let mut want = [0u8; super::super::tracking8822b::RATES];
        want[..12].copy_from_slice(&legacy[path]);
        want[12..20].copy_from_slice(&a[..8]);
        want[20..28].copy_from_slice(if path == 0 { &a[8..] } else { &b });
        if rates[path] != want {
            return TestResult::Fail("8822B HT tracking table differs from the programmed words");
        }
    }
    if count != 28 {
        return TestResult::Fail("8822B 2SS tracking table does not cover MCS0..15");
    }
    // N2BR over the exact N2BH: B22 magic only, its own identity.
    let Ok(rr) = super::super::rx_ba_power::request(&h) else {
        return TestResult::Fail("8822B N2BR request refused over N2BH");
    };
    let rx_ba = |magic: &[u8; 4]| {
        let mut b = alloc::vec![0u8; 128];
        b[..4].copy_from_slice(magic);
        b[4..8].copy_from_slice(&[1, 0, 128, 0]);
        b[8..12].copy_from_slice(&128u32.to_le_bytes());
        b[12..16].copy_from_slice(&[0xec, 0x10, 0x22, 0xb8]);
        b[16..48].copy_from_slice(&rr.identity);
        b[48..54].copy_from_slice(&rr.mac);
        b[54..56].copy_from_slice(&[1, 20]);
        for (at, v) in [(56, 4i16), (58, 76), (60, 60), (62, 40), (64, 40)] {
            b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
        b[66..68].copy_from_slice(&[0, 63]);
        b[68] = 64;
        b[69] = 1;
        super::super::rx_ba_power::Source::Verified {
            bytes: b,
            signer: Some([7; 32]),
            cap: Cap::bootstrap(),
        }
        .load(h.clone())
    };
    if !rr.filename.starts_with("rtw88/rtw8822be-rx-ba-v1-")
        || rx_ba(b"N22R").is_ok()
        || rx_ba(b"N21R").is_ok()
        || rx_ba(b"N2BR").is_err()
        || super::super::tx_ba_power::magic(0xb822, b'X') != Some(*b"N2BX")
        || super::super::tx_ba_power::magic(0x8822, b'T').is_some()
    {
        return TestResult::Fail("8822B N2BR/N2xT/N2xX magic or binding differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_n2bh_ht20_2ss_binds_n2bl
);

/// B22 `N2BB`/`N2BV` wide records: the decoders admit the B22 layouts
/// (path-B HT40 MCS8..15 at payload 32..40, path-B VHT80 2SS at 36..46)
/// and refuse dirty tails / foreign-chip shapes, `Gate::ht40_limits` is
/// both paths' `bw40_base[group]` (+ `ht_2s_diff.bw40`) at txgi 1, the
/// HT40/VHT80 TXAGC tables follow `rtw8822b_set_tx_power_index_by_rate`
/// (path-B 1SS zero), and `rtw8822b_set_channel` at BW40 reads back with
/// BIT_RFMOD_40M while another sideband/width refuses. Written; not yet
/// executed natively.
fn smoke_rtw8822be_n2bb_n2bv_wide_records_limits_and_bw40_readback() -> TestResult {
    use super::super::{
        band5::Width, ht40, power_policy::Gate, qualification::PAYLOAD, radio8822b, vht,
    };
    let Some((_, phy, grant, _)) = b22_station_fixture() else {
        return TestResult::Fail("8822B station fixture rejected");
    };
    let legacy = grant.power().indices();
    let gate = Gate::b22(grant, phy);
    // Center 3 = group 1: path A bw40 29, path B 28; ht_2s_diff.bw40 +0.
    if gate.ht40_limits(3) != Some((28, Some(28))) {
        return TestResult::Fail(
            "8822B HT40 ceilings differ from rtw_phy_get_2g_tx_power_index BW40",
        );
    }
    let mut p = [0u8; PAYLOAD];
    p[0] = 1;
    p[1] = 5;
    p[2] = 40;
    p[3] = 1;
    for (at, v) in [(4, 4i16), (6, 76), (8, 44), (10, 40), (12, 40)] {
        p[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    p[14..16].copy_from_slice(&0xffffu16.to_le_bytes());
    let a: [u8; 16] = core::array::from_fn(|i| 28 - (i as u8 & 7));
    p[16..32].copy_from_slice(&a);
    p[32..40].copy_from_slice(&[27; 8]);
    let Some(r) = ht40::Record::decode(0xb822, &p) else {
        return TestResult::Fail("8822B N2BB payload rejected");
    };
    let mut over = p;
    over[32] = 29;
    let mut tail = p;
    tail[40] = 1;
    let mut c22 = p;
    c22[32..40].fill(0);
    c22[32] = 1;
    if r.indices_b != [27; 8]
        || r.center() != 3
        || r.sc() != 2
        || !ht40::within_factory(&gate, &r)
        || ht40::Record::decode(0xb822, &over).is_some_and(|o| ht40::within_factory(&gate, &o))
        || ht40::Record::decode(0xb822, &tail).is_some()
        || ht40::Record::decode(0xc822, &c22).is_some()
    {
        return TestResult::Fail("8822B N2BB decode/ceiling admission differs");
    }
    let words = ht40::b22_words(legacy, &r);
    for path in 0..2 {
        let mut want = [0u8; 28];
        want[..12].copy_from_slice(&legacy[path]);
        if path == 0 {
            want[12..].copy_from_slice(&a);
        } else {
            want[20..].copy_from_slice(&[27; 8]);
        }
        for (w, v) in words[path].iter().enumerate() {
            if v.to_le_bytes() != want[w * 4..w * 4 + 4] {
                return TestResult::Fail("8822B HT40 words differ from set_tx_power_index_by_rate");
            }
        }
    }
    // N2BV: two streams, MCS0..9, path-B 2SS at 36..46.
    let mut v = [0u8; PAYLOAD];
    v[0] = 36;
    v[1] = 42;
    v[2] = 80;
    for (at, x) in [(4, 4i16), (6, 76), (8, 44), (10, 40), (12, 40)] {
        v[at..at + 2].copy_from_slice(&x.to_le_bytes());
    }
    v[14] = 2;
    v[15] = 9;
    v[16..36].fill(20);
    v[36..46].fill(19);
    let Some(vr) = vht::Record::decode(0xb822, &v) else {
        return TestResult::Fail("8822B N2BV payload rejected");
    };
    let mut one = v;
    one[14] = 1;
    one[26..36].fill(0);
    let mut vtail = v;
    vtail[46] = 1;
    if vr.indices_b != [19; 10]
        || vht::Record::decode(0xb822, &one).is_some()
        || vht::Record::decode(0xb822, &vtail).is_some()
        || vht::Record::decode(0xc821, &v).is_some()
    {
        return TestResult::Fail("8822B N2BV decode differs");
    }
    let tables = vht::b22_tables([[0; 12]; 2], &vr);
    if tables[0][0x2c..] != [20; 20]
        || tables[1][0x2c..0x36] != [0; 10]
        || tables[1][0x36..] != [19; 10]
        || tables.iter().any(|t| t[12..0x2c] != [0; 32])
    {
        return TestResult::Fail("8822B VHT80 tables differ from set_tx_power_index_by_rate");
    }
    // rtw8822b_set_channel(3, BW40, SC_20_LOWER) and its readback.
    let mut io = super::mac_tests::Model::new(3, 2);
    io.sipi8822b = true;
    if narf_scheduler::block_on(radio8822b::set_channel(&mut io, phy, 3, Width::Forty(2))).is_err()
    {
        return TestResult::Fail("8822B set_channel 3/40 failed");
    }
    let r668 = u32::from_le_bytes(io.regs[0x668..0x66c].try_into().unwrap());
    if r668 & 0x180 != 0x80
        || io.regs[0x483] != 2
        || narf_scheduler::block_on(radio8822b::verify_channel(&mut io, 3, Width::Forty(2)))
            .is_err()
        || narf_scheduler::block_on(radio8822b::verify_channel(&mut io, 3, Width::Forty(1))).is_ok()
        || narf_scheduler::block_on(radio8822b::verify_channel(&mut io, 3, Width::Twenty)).is_ok()
    {
        return TestResult::Fail("8822B BW40 MAC/BB/RF readback differs from rtw8822b_set_channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8822b",
    smoke_rtw8822be_n2bb_n2bv_wide_records_limits_and_bw40_readback
);
