//! Linux 7.3-rc4 `cam.c`/`wow.c` layouts for the RTL8852B WoW security
//! CAM. Unexecuted until the native validation run.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn snapshot() -> (SuspendKeys, SuspendFloors) {
    (
        SuspendKeys {
            pairwise: Zeroizing::new([0x11; 16]),
            groups: vec![(1, Zeroizing::new([0x22; 16]))],
        },
        SuspendFloors {
            pairwise_tx: 0x0102_0304_0506,
            pairwise_rx: 0x0a0b,
            groups: vec![(1, 0x0c0d)],
        },
    )
}

fn smoke_rtw89_wow_security_cam_entries_and_addr_cam() -> TestResult {
    let open = match plan(None, None) {
        Ok(k) => k,
        Err(_) => return TestResult::Fail("open BSS refused"),
    };
    if open.secured() || !open.entries.is_empty() || open.key_info != KeyInfo::default() {
        return TestResult::Fail("open BSS wrote keys");
    }
    let (keys, floors) = snapshot();
    if plan(Some(&keys), None).is_ok() {
        return TestResult::Fail("keys without floors accepted");
    }
    let k = match plan(Some(&keys), Some(&floors)) {
        Ok(k) => k,
        Err(_) => return TestResult::Fail("PTK+GTK refused"),
    };
    if k.entries.len() != 2
        || k.entries[0].index != 0
        || k.entries[1].index != 1
        || *k.entries[0].key != [0x11; 16]
        || k.pairwise != Alg::Ccmp
        || k.group != Alg::Ccmp
    {
        return TestResult::Fail("rtw89_cam_sec_key_install order");
    }
    let body = k.entries[1].body();
    if body[0..4] != [1, 0, 20, 0] || body[4] != 6 || body[8..24] != [0x22; 16] {
        return TestResult::Fail("H2C_SEC_CAM body");
    }
    if k.entries[1].cleared()[8..24] != [0; 16] {
        return TestResult::Fail("resume overwrite keeps key bytes");
    }
    let ki = k.key_info;
    if ki.ptk_tx_iv != [0x06, 0x05, 0, 0x20, 0x04, 0x03, 0x02, 0x01]
        || ki.ptk_rx_iv != [0x0b, 0x0a, 0, 0x20, 0, 0, 0, 0]
        || ki.gtk_rx_iv[1] != [0x0d, 0x0c, 0, 0x60, 0, 0, 0, 0]
        || ki.gtk_rx_iv[0] != [0; 8]
        || ki.gtk_keyidx != 1
        || ki.valid_check != 0xdd
        || ki.symbol_check_en != 3
    {
        return TestResult::Fail("rtw89_wow_construct_key_info");
    }
    let mut base = [0u8; 60];
    base[36..40].copy_from_slice(&(2u32 << 16 | 5).to_le_bytes());
    let cam = wow_cam(&base, &k, true, true);
    let w9 = u32::from_le_bytes([cam[36], cam[37], cam[38], cam[39]]);
    let w10 = u32::from_le_bytes([cam[40], cam[41], cam[42], cam[43]]);
    let w11 = u32::from_le_bytes([cam[44], cam[45], cam[46], cam[47]]);
    // AID 5, WOL_PATTERN, WOL_MAGIC, SEC_NORMAL, slot0 keyid 0, slot2 keyid 1.
    if w9 != (5 | 1 << 12 | 1 << 14 | 2 << 16 | 1 << 22) || w10 != (0b101 | 1 << 24) || w11 != 0 {
        return TestResult::Fail("rtw89_cam_fill_addr_cam_info W9..W11");
    }
    if wow_cam(&base, &open, false, true)[36..48] != [5, 0x40, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
        return TestResult::Fail("open WoW CAM");
    }
    let (mut bad, floors) = snapshot();
    bad.groups.push((1, Zeroizing::new([0x33; 16])));
    if plan(Some(&bad), Some(&floors)).is_ok() {
        return TestResult::Fail("duplicate/mismatched group set accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wow_security_cam_entries_and_addr_cam
);
