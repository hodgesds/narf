//! Literal native CNM/release-feature regressions for the next role batch.
//! Not registered until the runtime source graph is wired coherently.
use crate::mt7921::{
    firmware_transport::Error,
    fw_features,
    p2p_cnm::Cnm,
    p2p_wire::{Kind, Request},
};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
fn grant(token: u8, band: u8, channel: u8, interval: u32) -> Vec<u8> {
    let mut out = vec![0; 24];
    out[6..8].copy_from_slice(&20u16.to_le_bytes());
    out[9] = token;
    out[11] = channel;
    out[13] = band;
    out[15] = channel;
    out[17] = 1;
    out[18] = 0xff;
    out[20..24].copy_from_slice(&interval.to_le_bytes());
    out
}
fn mt76_cnm_roc_literal_acquire_abort_and_exact_grant_identity() -> TestResult {
    let r = Request::new(0, 9, 2437, 500, Kind::Remain).unwrap();
    if r.acquire()
        != [
            0, 0, 0, 0, 0, 0, 24, 0, 0, 9, 6, 0, 1, 0, 6, 0, 0, 6, 0, 1, 244, 1, 0, 0, 255, 0, 0, 0,
        ]
        || r.abort() != [0, 0, 0, 0, 1, 0, 12, 0, 0, 9, 255, 0, 0, 0, 0, 0]
        || r.grant(&grant(9, 1, 6, 400)) != Ok(400)
    {
        return TestResult::Fail("native CNM literal acquire/abort/grant source layout");
    }
    for offset in [4, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18] {
        let mut invalid = grant(9, 1, 6, 400);
        invalid[offset] ^= 0x40;
        if r.grant(&invalid).is_ok() {
            return TestResult::Fail("foreign CNM grant identity/geometry admitted");
        }
    }
    if r.grant(&grant(9, 1, 6, 0)).is_ok()
        || r.grant(&grant(9, 1, 6, 501)).is_ok()
        || r.grant(&grant(9, 1, 6, 400)[..23]).is_ok()
        || Request::new(0, 0, 2437, 500, Kind::Remain).is_ok()
        || Request::new(0, 1, 2437, 5001, Kind::Remain).is_ok()
    {
        return TestResult::Fail("CNM malformed duration/token/extent admitted");
    }
    let two = Request::new(0, 10, 2412, 500, Kind::Remain).unwrap();
    let six = Request::new(0, 10, 5955, 500, Kind::Remain).unwrap();
    if two.acquire()[10] != six.acquire()[10]
        || two.acquire()[12] != 1
        || six.acquire()[12] != 3
        || six.grant(&grant(10, 1, 1, 400)).is_ok()
        || six.grant(&grant(10, 3, 1, 400)) != Ok(400)
    {
        return TestResult::Fail("CNM6GHz reused ambiguous2GHz channel identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_cnm_roc_literal_acquire_abort_and_exact_grant_identity
);
fn mt76_cnm_grant_timer_abort_and_no_token_wrap_before_verified_reset() -> TestResult {
    let mut cnm = Cnm::default();
    for i in 1..=255 {
        let request = cnm
            .reserve(0, u64::from(i), 2437, 500, Kind::Remain)
            .unwrap();
        if request.token() != i
            || cnm.current(u64::from(i), 2437, 0)
            || cnm.reserve(0, 999, 2437, 500, Kind::Remain) != Err(Error::Busy)
        {
            return TestResult::Fail("CNM queued acquire fabricated a current lease");
        }
        if cnm.grant(&grant(i, 1, 6, 400), 1_000_000) != Ok(400)
            || cnm.grant(&grant(i, 1, 6, 400), 1_000_000).is_ok()
            || !cnm.current(u64::from(i), 2437, 400_999_999)
            || cnm.current(u64::from(i), 2437, 401_000_000)
            || cnm.release_expired_after_packets(400_999_999).is_ok()
            || cnm.release_expired_after_packets(401_000_000).is_err()
        {
            return TestResult::Fail("CNM grant identity/timer changed its finite receipt");
        }
    }
    if cnm.reserve(0, 256, 2437, 500, Kind::Remain) != Err(Error::Busy) {
        return TestResult::Fail("CNM late old grant can match a silently wrapped token");
    }
    cnm.reset_after_verified_mac();
    let r = cnm.reserve(0, 257, 2437, 500, Kind::Remain).unwrap();
    if r.token() != 1
        || cnm.abort(257) != Ok(r)
        || cnm.current(257, 2437, 0)
        || !cnm.pending()
        || cnm.release_expired_after_packets(u64::MAX).is_ok()
        || cnm.grant(&grant(1, 1, 6, 400), 0).is_ok()
    {
        return TestResult::Fail("unconfirmed abort released or resurrected a native CNM owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_cnm_grant_timer_abort_and_no_token_wrap_before_verified_reset
);
fn wm_features(bits: u8) -> Vec<u8> {
    let payload = 32usize;
    let mut ram = vec![
        0;
        payload
            + 16
            + 4
            + 20
            + crate::mt7921::fwdl::FW_REGION_SIZE
            + crate::mt7921::fwdl::FW_TRAILER_SIZE
    ];
    let release = payload + 16;
    ram[release..release + 2].copy_from_slice(&20u16.to_le_bytes());
    ram[release + 4..release + 6].copy_from_slice(&16u16.to_le_bytes());
    ram[release + 7] = 4;
    ram[release + 9] = bits;
    let table =
        ram.len() - crate::mt7921::fwdl::FW_TRAILER_SIZE - crate::mt7921::fwdl::FW_REGION_SIZE;
    ram[table + 20..table + 24].copy_from_slice(&(payload as u32).to_le_bytes());
    let trailer = ram.len() - crate::mt7921::fwdl::FW_TRAILER_SIZE;
    ram[trailer + 2] = 1;
    ram
}
fn mt76_wm_release_cnm_feature_requires_exact_bounded_native_artifact() -> TestResult {
    let positive = wm_features(0x80);
    let base = super::firmware(32);
    let prepared =
        crate::mt7921::firmware_transport::Firmware::prepare(&base.patch, &positive).unwrap();
    if prepared.cnm_capability() != Ok(true) || base.cnm_capability() != Ok(false) {
        return TestResult::Fail(
            "immutable prepared WM artifact did not own its actual CNM feature",
        );
    }
    let feature = fw_features::parse(&positive).unwrap().unwrap();
    if !feature.cnm()
        || feature.nan()
        || fw_features::parse(&wm_features(0)).unwrap().unwrap().cnm()
    {
        return TestResult::Fail("WM release source feature bits do not gate CNM");
    }
    let mut short = positive.clone();
    short[32 + 16] = 21;
    if fw_features::parse(&short) != Err(fw_features::Error::Extent) {
        return TestResult::Fail(
            "WM feature outer record escaped its actual region-table boundary",
        );
    }
    let mut bad = positive.clone();
    bad[32 + 16 + 4] = 15;
    if fw_features::parse(&bad) != Err(fw_features::Error::Extent) {
        return TestResult::Fail("WM truncated feature body became a capability");
    }
    let mut absent = positive[..32].to_vec();
    absent.extend_from_slice(&positive[positive.len() - 76..]);
    if fw_features::parse(&absent) != Ok(None) {
        return TestResult::Fail("absent release metadata confused with native CNM receipt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_wm_release_cnm_feature_requires_exact_bounded_native_artifact
);
