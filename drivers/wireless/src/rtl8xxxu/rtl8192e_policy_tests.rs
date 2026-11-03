//! N92P parser/permission regressions. Every bound here is a synthetic
//! dimensional value for arithmetic checks only, never a qualified board
//! curve, and is never registered for real hardware.
use super::*;
use crate::rtl8xxxu::rtl8192e_init::{parse_efuse, parse_identity, Queues};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const VID: u16 = 0x0bda;
const PID: u16 = 0x818b;

pub(in crate::rtl8xxxu) fn factory(two_t: bool) -> Factory {
    let hpon = if two_t { 0 } else { 1 << 22 };
    let id = parse_identity(0, hpon, 0, Queues::from_sie(0x0111)).unwrap();
    parse_efuse(id, &crate::rtl8xxxu::rtl8192e_tests::logical_map()).unwrap()
}

fn row(factory: &Factory, channel: u8, code: u8, bound: i16) -> [u8; ROW] {
    let mut raw = [0; ROW];
    raw[0] = channel;
    raw[1] = code;
    let width = row_width(code).unwrap();
    for p in 0..2 {
        let at = 4 + p * 12;
        raw[at..at + 3].copy_from_slice(&programmed(factory, channel, width, p));
        let b = if p == 1 && factory.identity.tx_paths == 1 {
            UNKNOWN
        } else {
            bound
        };
        for i in 0..3 {
            raw[at + 4 + i * 2..at + 6 + i * 2].copy_from_slice(&b.to_le_bytes());
        }
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
    bytes[12..82].copy_from_slice(&factory_bytes(factory, VID, PID));
    bytes[82] = 1;
    bytes[84..86].copy_from_slice(&8i16.to_le_bytes()); // +2 dBi
    bytes[86..88].copy_from_slice(&80i16.to_le_bytes()); // 20 dBm EIRP
    bytes[88..90].copy_from_slice(&(rows.len() as u16).to_le_bytes());
    bytes[92..96].copy_from_slice(&admitted.to_le_bytes());
    for &(channel, code, bound) in rows {
        bytes.extend_from_slice(&row(factory, channel, code, bound));
    }
    bytes
}

pub(in crate::rtl8xxxu) fn parse(bytes: &[u8], factory: &Factory) -> Result<Calibration, Error> {
    Calibration::from_verified(bytes, Some([0x55; 32]), [0x77; 32], factory, VID, PID)
}

pub(in crate::rtl8xxxu) fn domain(
    power: i8,
    bandwidth: u32,
) -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: power,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}

const BGN_2SS: u32 = 0x0fff_ffff;
const BGN_1SS: u32 = 0x000f_ffff;

fn smoke_rtl8192eu_signed_record_identity_and_format() -> TestResult {
    let f = factory(true);
    let bytes = record(&f, BGN_2SS, &[(1, 0, 40), (1, 1, 40)]);
    if Calibration::from_verified(&bytes, None, [0; 32], &f, VID, PID).err()
        != Some(Error::Unsigned)
    {
        return TestResult::Fail("8192eu unsigned record admitted");
    }
    let Ok(cal) = parse(&bytes, &f) else {
        return TestResult::Fail("8192eu valid record rejected");
    };
    if cal.admitted() != BGN_2SS {
        return TestResult::Fail("8192eu admitted mask not retained");
    }
    let mut other = f;
    other.mac[5] ^= 1;
    if parse(&bytes, &other).err() != Some(Error::Identity) {
        return TestResult::Fail("8192eu record reused on another MAC");
    }
    let mut other = f;
    other.power[1].ht40_diff[1] = 2;
    if parse(&bytes, &other).err() != Some(Error::Identity) {
        return TestResult::Fail("8192eu record reused with different EFUSE power");
    }
    if Calibration::from_verified(&bytes, Some([0; 32]), [0; 32], &f, VID, 0x818c).err()
        != Some(Error::Identity)
    {
        return TestResult::Fail("8192eu record reused on another PID");
    }
    let mut bad = bytes.clone();
    bad[..4].copy_from_slice(b"N8PC");
    if parse(&bad, &f).err() != Some(Error::Format) {
        return TestResult::Fail("8192eu accepted the 8188EU magic");
    }
    let mut bad = bytes.clone();
    bad[HEADER + 4] ^= 1; // path-A CCK index differs from what is programmed
    if parse(&bad, &f).err() != Some(Error::Format) {
        return TestResult::Fail("8192eu record for other indices accepted");
    }
    let unsorted = record(&f, BGN_2SS, &[(1, 1, 40), (1, 0, 40)]);
    if parse(&unsorted, &f).err() != Some(Error::Format) {
        return TestResult::Fail("8192eu unsorted rows accepted");
    }
    let geometry = record(&f, BGN_2SS, &[(11, 1, 40)]);
    if parse(&geometry, &f).err() != Some(Error::Format) {
        return TestResult::Fail("8192eu out-of-band HT40 row accepted");
    }
    let f1 = factory(false);
    if f1.identity.tx_paths != 1 {
        return TestResult::Fail("8191eu fixture bonding");
    }
    if parse(&record(&f1, BGN_2SS, &[(1, 0, 40)]), &f1).err() != Some(Error::Format) {
        return TestResult::Fail("8191eu record admitted 2SS MCS");
    }
    if parse(&record(&f1, BGN_1SS, &[(1, 0, 40)]), &f1).is_err() {
        return TestResult::Fail("8191eu 1SS record rejected");
    }
    let mut pathb = record(&f1, BGN_1SS, &[(1, 0, 40)]);
    pathb[HEADER + 20..HEADER + 22].copy_from_slice(&40i16.to_le_bytes());
    if parse(&pathb, &f1).err() != Some(Error::Format) {
        return TestResult::Fail("8191eu path-B bound accepted");
    }
    if parse(&record(&f, 0, &[(1, 0, 40)]), &f).err() != Some(Error::Format)
        || parse(&record(&f, 1 << 28, &[(1, 0, 40)]), &f).err() != Some(Error::Format)
    {
        return TestResult::Fail("8192eu empty/oversized admitted mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_signed_record_identity_and_format
);

fn smoke_rtl8192eu_signed_record_permission_refuses_never_narrows() -> TestResult {
    let f = factory(true);
    // Per-chain 15 dBm conducted (60 qdBm); 2 chains + 13 + 8 dBi-q = 81.
    let cal = parse(
        &record(&f, BGN_2SS, &[(1, 0, 59), (6, 0, 60), (6, 2, 40)]),
        &f,
    )
    .unwrap();
    let Ok(p) = cal.permission(&domain(30, 40), 1, Width::Ht20) else {
        return TestResult::Fail("8192eu qualified HT20 refused");
    };
    if p.admitted() != BGN_2SS
        || p.eirp_limit_qdbm() != 80
        || p.check(&f, VID, PID, 1, Width::Ht20) != Ok(BGN_2SS)
        || p.check(&f, VID, PID, 1, Width::Ht40Above).is_ok()
    {
        return TestResult::Fail("8192eu permission binding");
    }
    if cal.permission(&domain(30, 40), 6, Width::Ht20).err() != Some(Error::NoMeasuredGain) {
        return TestResult::Fail("8192eu two-chain sum rounded down");
    }
    if cal.permission(&domain(30, 40), 1, Width::NoHt20).is_err() {
        return TestResult::Fail("8192eu non-HT shares the HT20 row");
    }
    if cal
        .permission(&domain(30, 40), 6, Width::Ht40Below)
        .is_err()
    {
        return TestResult::Fail("8192eu qualified HT40- refused");
    }
    if cal.permission(&domain(30, 20), 6, Width::Ht40Below).err() != Some(Error::Policy) {
        return TestResult::Fail("8192eu HT40 under a 20 MHz rule");
    }
    if cal.permission(&domain(30, 40), 1, Width::Ht40Above).err() != Some(Error::NoMeasuredGain) {
        return TestResult::Fail("8192eu unrecorded HT40 row");
    }
    if cal.permission(&domain(14, 40), 1, Width::Ht20).err() != Some(Error::NoMeasuredGain) {
        return TestResult::Fail("8192eu regulatory ceiling ignored");
    }
    // An admitted class with an unknown bound refuses the channel.
    let mut partial = record(&f, BGN_2SS, &[(1, 0, 40)]);
    let mcs_b = HEADER + 4 + 12 + 4 + 4;
    partial[mcs_b..mcs_b + 2].copy_from_slice(&UNKNOWN.to_le_bytes());
    let cal = parse(&partial, &f).unwrap();
    if cal.permission(&domain(30, 40), 1, Width::Ht20).err() != Some(Error::NoMeasuredGain) {
        return TestResult::Fail("8192eu narrowed past an unknown MCS bound");
    }
    let legacy = record(&f, CCK | OFDM, &[(1, 0, 40)]);
    let mut legacy = legacy;
    legacy[mcs_b..mcs_b + 2].copy_from_slice(&UNKNOWN.to_le_bytes());
    if parse(&legacy, &f)
        .and_then(|c| c.permission(&domain(30, 40), 1, Width::Ht20))
        .is_err()
    {
        return TestResult::Fail("8192eu legacy-only record refused");
    }
    let mut odd = domain(30, 40);
    odd.rules[0].freq_end_mhz = 2440;
    if parse(&record(&f, BGN_2SS, &[(6, 1, 40)]), &f)
        .unwrap()
        .permission(&odd, 6, Width::Ht40Above)
        .err()
        != Some(Error::Policy)
    {
        return TestResult::Fail("8192eu HT40 span outside a partial rule");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_signed_record_permission_refuses_never_narrows
);
