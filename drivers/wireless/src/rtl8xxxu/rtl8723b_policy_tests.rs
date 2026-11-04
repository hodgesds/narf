//! N8BP parser/permission regressions. Every bound here is a synthetic
//! dimensional value for arithmetic checks only, never a qualified board
//! curve, and is never registered for real hardware.
use super::*;
use crate::rtl8xxxu::rtl8192e_init::Queues;
use crate::rtl8xxxu::rtl8192e_policy::tests::domain;
use crate::rtl8xxxu::rtl8723b_init::{parse_efuse, parse_identity};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const VID: u16 = 0x0bda;
const PID: u16 = 0xb720;

pub(in crate::rtl8xxxu) fn factory() -> Factory {
    let multi = (1 << 2) | (1 << 18);
    let id = parse_identity(0x0004_2000, multi, 0, Queues::from_sie(0x0111)).unwrap();
    parse_efuse(id, &crate::rtl8xxxu::rtl8723b_tests::logical_map()).unwrap()
}

fn row(factory: &Factory, channel: u8, code: u8, bound: i16) -> [u8; ROW] {
    let mut raw = [0; ROW];
    raw[0] = channel;
    raw[1] = code;
    raw[4..7].copy_from_slice(&programmed(factory, channel, row_width(code).unwrap()));
    for i in 0..3 {
        raw[8 + i * 2..10 + i * 2].copy_from_slice(&bound.to_le_bytes());
    }
    raw
}

/// Synthetic record: `rows` of (channel, width code, per-class bound).
pub(in crate::rtl8xxxu) fn record(
    factory: &Factory,
    admitted: u32,
    rows: &[(u8, u8, i16)],
) -> Vec<u8> {
    let total = HEADER + rows.len() * ROW;
    let mut bytes = vec![0; HEADER];
    bytes[..4].copy_from_slice(&MAGIC);
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&(HEADER as u16).to_le_bytes());
    bytes[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    bytes[12..76].copy_from_slice(&factory_bytes(factory, VID, PID));
    bytes[76..84].copy_from_slice(&efuse_tail(factory));
    bytes[84] = 1;
    bytes[86..88].copy_from_slice(&8i16.to_le_bytes()); // +2 dBi
    bytes[88..90].copy_from_slice(&80i16.to_le_bytes()); // 20 dBm EIRP
    bytes[90..92].copy_from_slice(&(rows.len() as u16).to_le_bytes());
    bytes[94..98].copy_from_slice(&admitted.to_le_bytes());
    for &(channel, code, bound) in rows {
        bytes.extend_from_slice(&row(factory, channel, code, bound));
    }
    bytes
}

pub(in crate::rtl8xxxu) fn parse(bytes: &[u8], factory: &Factory) -> Result<Calibration, Error> {
    Calibration::from_verified(bytes, Some([0x55; 32]), [0x77; 32], factory, VID, PID)
}

fn smoke_rtl8723bu_record_format() -> TestResult {
    let f = factory();
    let good = record(&f, 0x000f_ffff, &[(1, 0, 60), (6, 1, 60)]);
    let cal = match parse(&good, &f) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("8723bu valid record rejected"),
    };
    if cal.admitted() != 0x000f_ffff {
        return TestResult::Fail("8723bu admitted mask");
    }
    if Calibration::from_verified(&good, None, [0; 32], &f, VID, PID).err() != Some(Error::Unsigned)
    {
        return TestResult::Fail("8723bu unsigned record accepted");
    }
    let mut n92p = good.clone();
    n92p[..4].copy_from_slice(b"N92P");
    let mut other_pid = good.clone();
    other_pid[14] ^= 1;
    let mut tail = good.clone();
    tail[81] ^= 1; // bt_setting
    let mut index = good.clone();
    index[HEADER + 4] ^= 1; // programmed CCK index
    let two_ss = record(&f, 0x0010_0fff, &[(1, 0, 60)]);
    let mut bad_bound = good.clone();
    bad_bound[HEADER + 8..HEADER + 10].copy_from_slice(&300i16.to_le_bytes());
    let unordered = record(&f, 0x0fff, &[(6, 0, 60), (1, 0, 60)]);
    let bad_geometry = record(&f, 0x0fff, &[(11, 1, 60)]);
    if parse(&n92p, &f).err() != Some(Error::Format)
        || parse(&other_pid, &f).err() != Some(Error::Identity)
        || parse(&tail, &f).err() != Some(Error::Identity)
        || parse(&index, &f).err() != Some(Error::Format)
        || parse(&two_ss, &f).err() != Some(Error::Format)
        || parse(&bad_bound, &f).err() != Some(Error::Format)
        || parse(&unordered, &f).err() != Some(Error::Format)
        || parse(&bad_geometry, &f).err() != Some(Error::Format)
    {
        return TestResult::Fail("8723bu record validation");
    }
    if Calibration::asset_name(&f) != "rtl8xxxu/rtl8723bu-cal-v1-00e04c8723b0" {
        return TestResult::Fail("8723bu asset name");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_record_format
);

fn smoke_rtl8723bu_record_permission() -> TestResult {
    let f = factory();
    // 15 dBm conducted + 2 dBi <= 20 dBm EIRP.
    let cal = parse(&record(&f, 0x000f_ffff, &[(1, 0, 60), (6, 1, 60)]), &f).unwrap();
    let p = match cal.permission(&domain(20, 40), 1, Width::Ht20) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("8723bu ch1 HT20 refused"),
    };
    if p.check(&f, VID, PID, 1, Width::Ht20) != Ok(0x000f_ffff)
        || p.check(&f, VID, 0xa611, 1, Width::Ht20).is_ok()
        || p.check(&f, VID, PID, 6, Width::Ht20).is_ok()
    {
        return TestResult::Fail("8723bu permission check");
    }
    if cal.permission(&domain(20, 40), 6, Width::Ht40Above).is_err()
        || cal.permission(&domain(20, 20), 6, Width::Ht40Above).err() != Some(Error::Policy)
        || cal.permission(&domain(20, 40), 2, Width::Ht20).err() != Some(Error::NoMeasuredGain)
        // 15 dBm + 2 dBi > 16 dBm ceiling: refused, never narrowed.
        || cal.permission(&domain(16, 40), 1, Width::Ht20).err() != Some(Error::NoMeasuredGain)
    {
        return TestResult::Fail("8723bu permission policy");
    }
    let unknown = parse(&record(&f, 0x0fff, &[(1, 0, UNKNOWN)]), &f).unwrap();
    if unknown.permission(&domain(20, 40), 1, Width::Ht20).err() != Some(Error::NoMeasuredGain) {
        return TestResult::Fail("8723bu unknown bound admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_record_permission
);
