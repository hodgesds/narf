//! DCN3.0 MST arithmetic: PBN, time slots and the VC rate as Linux derives
//! them for an 8-bpc RGB stream on an 8b/10b link.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn dcn30_mst_budget_like_drm_and_dc() -> TestResult {
    // HBR2 x4: 17.28 Gbps, PBN divider 40 per slot.
    let kbps = link_kbps(0x14, 4, false);
    if kbps != 17_280_000 || link_kbps(0x14, 4, true) != 16_761_600 {
        return TestResult::Fail("dc_link_bandwidth_kbps");
    }
    let Some((pbn, slots, (x, y))) = budget(148_500, kbps) else {
        return TestResult::Fail("1080p60 does not fit HBR2 x4");
    };
    // drm_dp_calc_pbn_mode(148500, 24 bpp) and 40 PBN per slot.
    if pbn != 532 || slots != 14 || x != 13 || y == 0 {
        return TestResult::Fail("PBN/slots/VC rate");
    }
    // 4K60 at 594 MHz needs more than 63 slots at HBR (code 0x0a) x 2.
    if budget(594_000, link_kbps(0x0a, 2, false)).is_some() {
        return TestResult::Fail("over-link stream admitted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn30-mst", dcn30_mst_budget_like_drm_and_dc);
