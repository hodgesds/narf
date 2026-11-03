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
