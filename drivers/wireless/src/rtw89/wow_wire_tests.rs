//! Literal Linux 7.3-rc4 layouts for the RTL8852B WoW codecs. Unexecuted
//! until the native validation run.
use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];

fn pattern(da: [u8; 6], mask: Vec<u8>) -> WowlanPattern {
    let mut bytes = vec![0u8; 20];
    bytes[..6].copy_from_slice(&da);
    bytes[6..12].copy_from_slice(&[0xaa; 6]);
    bytes[12..15].copy_from_slice(&[0x08, 0x00, 0x45]);
    WowlanPattern {
        mask,
        pattern: bytes,
        offset: 0,
    }
}

fn smoke_rtw89_wow_support_patterns_and_cam() -> TestResult {
    let s = support();
    if !s.disconnect
        || !s.magic_packet
        || s.gtk_rekey
        || s.gtk_rekey_failure
        || s.max_patterns != 18
        || s.min_pattern_len != 1
        || s.max_pattern_len != 128
        || s.net_detect_max_match_sets != 0
    {
        return TestResult::Fail("rtw_wowlan_stub_8852b differs");
    }
    if crc16(b"123456789") != 0x7609 || crc16(&[]) != 0 || crc16(&[0x08, 0x00, 0x45]) != 0xe5a8 {
        return TestResult::Fail("rtw89_calc_crc vectors");
    }
    let bc = match generate(&pattern([0xff; 6], vec![0x3f, 0x70, 0]), OWN) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("broadcast pattern rejected"),
    };
    if bc.mask != [0x0000_01c0, 0, 0, 0] || bc.crc != 0xe5a8 || !bc.bc || bc.mc || bc.uc {
        return TestResult::Fail("six-bit LLC mask shift / CRC / broadcast type");
    }
    let uc = generate(&pattern(OWN, vec![0x3f, 0, 0]), OWN);
    let mc = generate(&pattern([1, 0, 0x5e, 0, 0, 1], vec![0x3f, 0, 0]), OWN);
    let wild = generate(&pattern([9; 6], vec![0, 0x70, 0]), OWN);
    if !uc.is_ok_and(|p| p.uc && !p.mc && !p.bc)
        || !mc.is_ok_and(|p| p.mc && !p.uc && !p.bc)
        || !wild.is_ok_and(|p| !p.uc && !p.mc && !p.bc)
    {
        return TestResult::Fail("DA classification");
    }
    // Own address under a partial DA mask and another unicast DA are -EPERM.
    if generate(&pattern(OWN, vec![0x1f, 0, 0]), OWN) != Err(Error::Invalid)
        || generate(&pattern([4; 6], vec![0x3f, 0, 0]), OWN) != Err(Error::Invalid)
    {
        return TestResult::Fail("invalid DA admitted");
    }
    let mut config = WowlanConfig {
        magic_packet: true,
        ..WowlanConfig::default()
    };
    if validate(&config, OWN).map(|p| p.len()) != Ok(0) {
        return TestResult::Fail("magic-only config");
    }
    config.patterns = vec![pattern([0xff; 6], vec![0x3f, 0x70, 0]); 19];
    if validate(&config, OWN) != Err(Error::Invalid) {
        return TestResult::Fail("19 patterns admitted");
    }
    config.patterns.truncate(1);
    config.patterns[0].mask.pop();
    if validate(&config, OWN) != Err(Error::Invalid) {
        return TestResult::Fail("short mask admitted");
    }
    config.patterns.clear();
    config.gtk_rekey_failure = true;
    if validate(&config, OWN) != Err(Error::Unsupported) {
        return TestResult::Fail("GTK-rekey wake admitted without the stub flag");
    }
    if validate(&WowlanConfig::default(), OWN) != Err(Error::Invalid) {
        return TestResult::Fail("empty trigger set admitted");
    }
    let write = cam_update(3, Some(&bc)).unwrap();
    let mut expect = [0u8; 24];
    expect[0] = 0x07;
    expect[4..8].copy_from_slice(&0x1c0u32.to_le_bytes());
    expect[20..24].copy_from_slice(&(0xe5a8u32 | 1 << 23 | 1 << 26 | 1 << 31).to_le_bytes());
    if write != expect {
        return TestResult::Fail("rtw89_h2c_wow_cam_update write");
    }
    let mut clear = [0u8; 24];
    clear[0] = 0x07;
    if cam_update(3, None) != Some(clear) || cam_update(18, None).is_some() {
        return TestResult::Fail("pattern CAM clear / bounds");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wow_support_patterns_and_cam
);

fn smoke_rtw89_wow_h2c_bodies_reason_and_aoac() -> TestResult {
    if keep_alive(true, 7, 0) != [1, 7, 5, 0] || keep_alive(false, 7, 0) != [0, 0, 5, 0] {
        return TestResult::Fail("keep alive");
    }
    if disconnect_detect(true, true, 0) != [1, 0, 100, 5, 0, 0, 0, 0]
        || disconnect_detect(false, true, 0) != [4, 0, 100, 5, 0, 0, 0, 0]
        || disconnect_detect(true, false, 0) != [0; 8]
    {
        return TestResult::Fail("disconnect detect");
    }
    if wakeup_ctrl(true, true, true, true, 0) != [0x13, 0, 0, 0]
        || wakeup_ctrl(true, false, true, false, 2) != [0x02, 0, 0, 2]
        || wakeup_ctrl(false, true, true, true, 2) != [0, 0, 0, 2]
    {
        return TestResult::Fail("wakeup ctrl");
    }
    if ccmp_iv(0x0605_0403_0201, 1) != [1, 2, 0, 0x60, 3, 4, 5, 6]
        || ccmp_pn(&[1, 2, 0, 0x60, 3, 4, 5, 6]) != 0x0605_0403_0201
    {
        return TestResult::Fail("CCMP PN/IV");
    }
    let keys = KeyInfo {
        ptk_tx_iv: [1; 8],
        valid_check: VALID_CHECK,
        symbol_check_en: SYMBOL_CHECK_PTK_GTK,
        gtk_keyidx: 1,
        ptk_rx_iv: [2; 8],
        gtk_rx_iv: [[3; 8], [4; 8], [5; 8], [6; 8]],
    };
    let global = wow_global(true, 0, Alg::Ccmp, Alg::Ccmp, &keys);
    if global[0..4] != [1, 0, 6, 6]
        || global[4..12] != [1; 8]
        || global[12..15] != [0xdd, 3, 1]
        || global[15..20] != [0; 5]
        || global[20..28] != [2; 8]
        || global[28..36] != [3; 8]
        || global[52..60] != [6; 8]
    {
        return TestResult::Fail("wow global / key info layout");
    }
    let open = wow_global(false, 0, Alg::None, Alg::None, &KeyInfo::default());
    if open != [0; 60] || aoac_request() != [0; 4] {
        return TestResult::Fail("disable / AOAC request");
    }
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let cam = sec_cam_ccmp(2, &key);
    if cam[0..8] != [2, 0, 20, 0, 6, 0, 0, 0] || cam[8..24] != key {
        return TestResult::Fail("security CAM key body");
    }
    let mut body = vec![0u8; 148];
    body[..5].copy_from_slice(&[1, 6, 1, 4, 0]);
    body[8..16].copy_from_slice(&[9; 8]);
    body[56..64].copy_from_slice(&[7; 8]);
    body[72..80].copy_from_slice(&[8; 8]);
    let aoac = match decode_aoac(&body) {
        Some(a) => a,
        None => return TestResult::Fail("AOAC decode"),
    };
    if aoac.pattern_idx != 4
        || aoac.ptk_tx_iv != [9; 8]
        || aoac.ptk_rx_iv != [7; 8]
        || aoac.gtk_rx_iv[1] != [8; 8]
        || decode_aoac(&body[..147]).is_some()
    {
        return TestResult::Fail("AOAC offsets / truncation");
    }
    let pattern = decode_reason(0x23, Some(&aoac));
    let deauth = decode_reason(0x08, None);
    let unknown = decode_reason(0x77, None);
    if pattern.pattern_index != Some(4)
        || !keeps_link(&pattern)
        || !decode_reason(0x21, None).magic_packet
        || !decode_reason(0x04, None).disconnect
        || !deauth.disconnect
        || keeps_link(&deauth)
        || unknown.unknown != Some(0x77)
        || keeps_link(&unknown)
    {
        return TestResult::Fail("rtw89_wow_show_wakeup_reason decode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wow_h2c_bodies_reason_and_aoac
);
