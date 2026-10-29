use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// 2560x1440 at 143.994 Hz (h_total 2720, v_total 1497).
pub(crate) fn qhd144() -> Timing {
    Timing {
        pixel_clock_khz: 586_322,
        h_active: 2560,
        h_total: 2720,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 1440,
        v_total: 1497,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    }
}

fn range_descriptor(offsets: u8, min: u8, max: u8, flags: u8) -> [u8; 18] {
    let mut d = [0u8; 18];
    d[3] = 0xfd;
    d[4] = offsets;
    d[5] = min;
    d[6] = max;
    d[7] = 30;
    d[8] = 230;
    d[9] = 60;
    d[10] = flags;
    d
}

/// An EDID 1.`revision` base block with continuous frequency (or not) and
/// `slot` 0-3 holding `d`.
pub(crate) fn edid(revision: u8, continuous: bool, slot: usize, d: [u8; 18]) -> Vec<u8> {
    let mut b = alloc::vec![0u8; 128];
    b[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    b[0x12] = 1;
    b[0x13] = revision;
    b[0x18] = if continuous { 1 } else { 0 };
    b[54 + 18 * slot..72 + 18 * slot].copy_from_slice(&d);
    b
}

/// A 48-144 Hz "range limits only" EDID 1.4 base block.
pub(crate) fn edid_48_144() -> Vec<u8> {
    edid(4, true, 3, range_descriptor(0, 48, 144, 1))
}

fn freesync_edid_monitor_range_follows_drm_get_monitor_range() -> TestResult {
    let r = |min, max| {
        Some(MonitorRange {
            min_vfreq: min,
            max_vfreq: max,
        })
    };
    if monitor_range(&edid_48_144()) != r(48, 144) {
        return TestResult::Fail("base range");
    }
    // EDID 1.3, no continuous frequency, another range variant (GTF 0x00,
    // CVT 0x04), a non-descriptor or a short buffer: no range.
    for (e, why) in [
        (edid(3, true, 3, range_descriptor(0, 48, 144, 1)), "1.3"),
        (
            edid(4, false, 3, range_descriptor(0, 48, 144, 1)),
            "discrete",
        ),
        (edid(4, true, 3, range_descriptor(0, 48, 144, 0)), "GTF"),
        (edid(4, true, 3, range_descriptor(0, 48, 144, 4)), "CVT"),
    ] {
        if monitor_range(&e).is_some() {
            return TestResult::Fail(why);
        }
    }
    let mut padded = range_descriptor(0, 48, 144, 1);
    padded[2] = 1; // pad1 must be zero
    if monitor_range(&edid(4, true, 1, padded)).is_some() || monitor_range(&[0; 64]).is_some() {
        return TestResult::Fail("not a display descriptor");
    }
    // EDID 1.4 +255 offsets apply to either bound.
    if monitor_range(&edid(4, true, 0, range_descriptor(2, 48, 5, 1))) != r(48, 260)
        || monitor_range(&edid(4, true, 0, range_descriptor(3, 1, 5, 1))) != r(256, 260)
        || monitor_range(&edid(4, true, 0, range_descriptor(4, 48, 144, 1))) != r(48, 144)
    {
        return TestResult::Fail("offsets");
    }
    // A CTA-861 extension's DTD area is searched; the last descriptor wins.
    let mut e = edid_48_144();
    e[0x7e] = 1;
    let mut cta = alloc::vec![0u8; 128];
    cta[0] = 0x02;
    cta[1] = 3;
    cta[2] = 4 + 18; // one 18-byte gap, then the DTD area
    cta[4 + 18 + 18..4 + 18 + 36].copy_from_slice(&range_descriptor(0, 40, 165, 1));
    e.extend_from_slice(&cta);
    if monitor_range(&e) != r(40, 165) {
        return TestResult::Fail("CTA DTD area");
    }
    // An undeclared extension block, or a CTA offset outside 4..=127, is not.
    e[0x7e] = 0;
    if monitor_range(&e) != r(48, 144) {
        return TestResult::Fail("undeclared extension");
    }
    e[0x7e] = 1;
    e[128 + 2] = 2;
    if monitor_range(&e) != r(48, 144) {
        return TestResult::Fail("CTA offset");
    }
    // A VTB (version 1) extension's descriptors follow its five-byte header.
    let mut v = edid_48_144();
    v[0x7e] = 1;
    let mut vtb = alloc::vec![0u8; 128];
    vtb[0] = 0x10;
    vtb[1] = 1;
    vtb[2] = 2;
    vtb[5 + 18..5 + 36].copy_from_slice(&range_descriptor(0, 30, 120, 1));
    v.extend_from_slice(&vtb);
    if monitor_range(&v) != r(30, 120) {
        return TestResult::Fail("VTB");
    }
    v[128 + 1] = 2;
    if monitor_range(&v) != r(48, 144) {
        return TestResult::Fail("unknown VTB version");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_edid_monitor_range_follows_drm_get_monitor_range
);

fn freesync_dp_sst_caps_follow_amdgpu_dm_update_freesync_caps() -> TestResult {
    let mut dpcd = [0u8; 16];
    if dp_sst_caps(&edid_48_144(), &dpcd).is_some() {
        return TestResult::Fail("MSA_TIMING_PAR_IGNORED clear");
    }
    dpcd[7] = 0x41;
    let caps = dp_sst_caps(&edid_48_144(), &dpcd);
    if caps
        != Some(VrrRange {
            min_hz: 48,
            max_hz: 144,
        })
    {
        return TestResult::Fail("capable sink");
    }
    // The range must be more than 10 Hz wide.
    let e = |min, max| edid(4, true, 2, range_descriptor(0, min, max, 1));
    if dp_sst_caps(&e(50, 60), &dpcd).is_some()
        || dp_sst_caps(&e(50, 61), &dpcd)
            != Some(VrrRange {
                min_hz: 50,
                max_hz: 61,
            })
        || dp_sst_caps(&e(60, 50), &dpcd).is_some()
    {
        return TestResult::Fail("range width");
    }
    if dp_sst_caps(&edid(3, true, 3, range_descriptor(0, 48, 144, 1)), &dpcd).is_some() {
        return TestResult::Fail("no monitor range");
    }
    // vrr_supported: drm_mode_vrefresh within [min, max].
    let r = caps.unwrap();
    let t = qhd144();
    if vrefresh(&t) != 144 || !r.supports(&t) {
        return TestResult::Fail("144 Hz mode");
    }
    let hd60 = Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_front_porch: 88,
        h_sync_width: 44,
        v_active: 1080,
        v_total: 1125,
        v_front_porch: 4,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    let narrow = VrrRange {
        min_hz: 61,
        max_hz: 144,
    };
    if !r.supports(&hd60)
        || narrow.supports(&hd60)
        || !(VrrRange {
            min_hz: 48,
            max_hz: 60,
        })
        .supports(&hd60)
    {
        return TestResult::Fail("range bounds");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_dp_sst_caps_follow_amdgpu_dm_update_freesync_caps
);

fn freesync_vtotals_match_mod_freesync_build_vrr_params() -> TestResult {
    let t = qhd144();
    // Hand-computed from Linux's integer code: nominal 143994361 uHz, so the
    // maximum is capped there and v_total_min rounds up to the nominal
    // 1497; the 48 Hz minimum (above the 6.58 Hz hardware floor) rounds
    // 4490.39 lines up to 4491.
    let range = VrrRange {
        min_hz: 48,
        max_hz: 144,
    };
    if drr(&t, range)
        != Some(Drr {
            v_total_min: 1497,
            v_total_max: 4491,
        })
    {
        return TestResult::Fail("48-144 Hz");
    }
    // A sink declaring exactly 2x its minimum, at the rounded nominal rate:
    // the minimum becomes half the nominal (71997180 uHz, 2993.6 -> 2994).
    if drr(
        &t,
        VrrRange {
            min_hz: 72,
            max_hz: 144,
        },
    ) != Some(Drr {
        v_total_min: 1497,
        v_total_max: 2994,
    }) {
        return TestResult::Fail("exact 2x");
    }
    // 1080p60 in a 40-75 Hz range: capped at the nominal 60 Hz.
    let mut hd = t;
    (hd.pixel_clock_khz, hd.h_total, hd.v_total, hd.v_front_porch) = (148_500, 2200, 1125, 4);
    if drr(
        &hd,
        VrrRange {
            min_hz: 40,
            max_hz: 75,
        },
    ) != Some(Drr {
        v_total_min: 1125,
        v_total_max: 1688,
    }) {
        return TestResult::Fail("capped at nominal");
    }
    // Under 10 Hz left after capping: fixed refresh. Out of range: none.
    if drr(
        &hd,
        VrrRange {
            min_hz: 51,
            max_hz: 75,
        },
    )
    .is_some()
        || drr(
            &hd,
            VrrRange {
                min_hz: 50,
                max_hz: 75,
            },
        )
        .is_none()
        || drr(
            &t,
            VrrRange {
                min_hz: 48,
                max_hz: 120,
            },
        )
        .is_some()
    {
        return TestResult::Fail("range checks");
    }
    // A minimum the 15-bit total cannot reach is limited by the hardware
    // floor: pix * 1e8 / (h_total * (32767 - (vfp + 1))).
    let mut slow = hd;
    (slow.pixel_clock_khz, slow.h_total) = (148_500, 220);
    slow.v_total = 11250; // 60 Hz with a tiny line time
    let d = drr(
        &slow,
        VrrRange {
            min_hz: 1,
            max_hz: 60,
        },
    )
    .unwrap();
    if d.v_total_min != 11250 || d.v_total_max > MAX_V_TOTAL || d.v_total_max < 32_000 {
        return TestResult::Fail("hardware floor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_vtotals_match_mod_freesync_build_vrr_params
);

fn freesync_calc_v_total_rounding_branches() -> TestResult {
    let t = qhd144();
    // 101 Hz is 2134.25 lines: down at/below the stream minimum, nearest
    // strictly inside, up at/above the stream maximum.
    let r = 101_000_000;
    if calc_v_total_from_refresh(&t, r, r, 200_000_000) != Some(2134)
        || calc_v_total_from_refresh(&t, r, 50_000_000, 200_000_000) != Some(2134)
        || calc_v_total_from_refresh(&t, r, 50_000_000, r) != Some(2135)
        || calc_v_total_from_refresh(&t, r, 0, 0) != Some(2135)
    {
        return TestResult::Fail("rounding");
    }
    // Zero refresh is the nominal total; never below it.
    if calc_v_total_from_refresh(&t, 0, 0, 0) != Some(1497)
        || calc_v_total_from_refresh(&t, 300_000_000, 0, 0) != Some(1497)
    {
        return TestResult::Fail("nominal floor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_calc_v_total_rounding_branches
);

fn freesync_displayid_fallback_and_hdmi_vsdb_policy() -> TestResult {
    let mut edid = alloc::vec![0; 256];
    edid[126] = 1;
    edid[128] = 0x70;
    let j = 114; // Last full range accepted by Linux's >13 byte guard.
    edid[128 + j] = 0x25;
    edid[128 + j + 1] = 1;
    edid[128 + j + 2] = 9;
    edid[128 + j + 9] = 48;
    edid[128 + j + 10] = 104;
    edid[128 + j + 11] = 1;
    let mut dpcd = [0; 16];
    dpcd[7] = DPCD_MSA_TIMING_PAR_IGNORED;
    assert_eq!(
        dp_sst_caps(&edid, &dpcd),
        Some(VrrRange {
            min_hz: 48,
            max_hz: 360
        })
    );
    edid[128 + j + 1] = 0;
    assert_eq!(
        dp_sst_caps(&edid, &dpcd),
        Some(VrrRange {
            min_hz: 48,
            max_hz: 104
        })
    );
    edid[128 + j + 1] = 2;
    assert_eq!(dp_sst_caps(&edid, &dpcd), None);
    assert_eq!(dp_sst_caps(&edid[..255], &dpcd), None);
    edid[126] = 0;
    assert_eq!(dp_sst_caps(&edid, &dpcd), None);
    let vsdb = AmdVsdb {
        version: 3,
        min_hz: 48,
        max_hz: 144,
        vcp_code: 0,
    };
    assert_eq!(
        vsdb.range(),
        Some(VrrRange {
            min_hz: 48,
            max_hz: 144
        })
    );
    assert_eq!(
        AmdVsdb {
            vcp_code: 0xe0,
            ..vsdb
        }
        .range(),
        None
    );
    assert_eq!(AmdVsdb { max_hz: 58, ..vsdb }.range(), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_displayid_fallback_and_hdmi_vsdb_policy
);
fn freesync_spd_packets_follow_linux_headers_data_and_checksum() -> TestResult {
    let timing = qhd144();
    let range = VrrRange {
        min_hz: 48,
        max_hz: 144,
    };
    for hdmi in [false, true] {
        for active in [false, true] {
            let p = info_packet(&timing, range, hdmi, active).unwrap();
            assert!(p.valid);
            assert_eq!(
                p.hb,
                if hdmi {
                    [0x83, 1, 8, 0]
                } else {
                    [0, 0x83, 0x1b, 4]
                }
            );
            assert_eq!(
                &p.sb[1..9],
                &[
                    0x1a,
                    0,
                    0,
                    0,
                    0,
                    if active { 7 } else { 3 },
                    if active { 48 } else { 144 },
                    144
                ]
            );
            assert_eq!(
                p.hb.iter()
                    .chain(&p.sb)
                    .fold(0u8, |a, b| a.wrapping_add(*b)),
                0
            );
            assert!(p.sb[9..].iter().all(|v| *v == 0));
        }
    }
    assert!(info_packet(
        &timing,
        VrrRange {
            min_hz: 30,
            max_hz: 60
        },
        true,
        true
    )
    .is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_spd_packets_follow_linux_headers_data_and_checksum
);

fn freesync_replays_primary_spd_packets() -> TestResult {
    let range = VrrRange {
        min_hz: 48,
        max_hz: 144,
    };
    for line in include_str!("../tests/dcn401_freesync/vectors.txt").lines() {
        let mut fields = line.split_whitespace();
        let hdmi = fields.next().unwrap() == "1";
        let active = fields.next().unwrap() == "1";
        let bytes: Vec<u8> = fields.map(|s| u8::from_str_radix(s, 16).unwrap()).collect();
        assert_eq!(
            info_packet(&qhd144(), range, hdmi, active)
                .unwrap()
                .bytes()
                .as_slice(),
            bytes.as_slice()
        );
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/freesync", freesync_replays_primary_spd_packets);

fn freesync_hdmi_versioned_spd_distinguishes_disabled_inactive_and_active() -> TestResult {
    let t = qhd144();
    let range = VrrRange {
        min_hz: 40,
        max_hz: 144,
    };
    for (version, length) in [(1, 8), (2, 9), (3, 16)] {
        for (state, flags) in [
            (HdmiState::Disabled, 1),
            (HdmiState::Inactive, 3),
            (HdmiState::Variable, 7),
        ] {
            let Some(p) = hdmi_info_packet(&t, range, version, state) else {
                return TestResult::Fail("versioned HDMI SPD");
            };
            if p.hb != [0x83, version as u8, length, 0]
                || p.sb[1..4] != [0x1a, 0, 0]
                || p.sb[6] != flags
                || p.hb
                    .iter()
                    .chain(&p.sb[..=length as usize])
                    .fold(0u8, |sum, b| sum.wrapping_add(*b))
                    != 0
                || p.sb[7]
                    != if state == HdmiState::Variable
                        || version == 3 && state == HdmiState::Inactive
                    {
                        40
                    } else {
                        144
                    }
            {
                return TestResult::Fail("SPD header, state/range flags or checksum");
            }
        }
    }
    let mut fast = t;
    fast.pixel_clock_khz *= 3;
    let range = VrrRange {
        min_hz: 40,
        max_hz: 432,
    };
    if hdmi_info_packet(&fast, range, 1, HdmiState::Variable).is_some()
        || hdmi_info_packet(&fast, range, 2, HdmiState::Variable).is_some()
        || hdmi_info_packet(&fast, range, 3, HdmiState::Variable)
            .is_none_or(|p| p.sb[8] != 176 || p.sb[12] != 1)
        || hdmi_info_packet(&t, range, 0, HdmiState::Variable).is_some()
    {
        return TestResult::Fail("SPD truncated an unrepresentable refresh rate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/freesync",
    freesync_hdmi_versioned_spd_distinguishes_disabled_inactive_and_active
);
