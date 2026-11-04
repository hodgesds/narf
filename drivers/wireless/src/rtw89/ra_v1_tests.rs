// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixture tests for the BE RA v1 builder. Expected words are computed
//! in the test from the Linux `fw.h` bit positions, never by calling
//! the builder under test.

use super::ra_v1::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_be_ra_v1_build() -> TestResult {
    let info = RaV1Info {
        is_dis: true,
        mode: 0x1F,
        bw_cap: 0x3,
        mac_id: 0xAB,
        dcm: true,
        er: true,
        init_rate_lv: 0x3,
        upd_all: true,
        sgi: true,
        ldpc: true,
        stbc: true,
        ss_num: 0x7,
        giltf: 0x7,
        upd_bw_nss: true,
        upd: true,
        ramask_lo32: 0x1234_5678,
        ramask_hi31: 0x7FFF_FFFF,
        bfee_csi_ctl: true,
        band_num: 0x5A,
        ra_csi_rate_en: true,
        fixed_csi_rate_en: true,
        cr_tbl_sel: true,
        fix_giltf_en: true,
        fix_giltf: 0x7,
        partial_bw_su_er: true,
        fixed_csi_rate_l: 0xFF,
        is_noisy: true,
        psra_en: true,
        macid_msb: 0x3,
        band: 0x3,
        new_dbgreg: true,
        mode_eht: 0x7F,
        bw_eht: 0x7,
        ramask_uhl16: 0xBEEF,
        ramask_uhh16: 0xCAFE,
    };
    let w = build_ra_v1(&info);
    // W0: every field at its fw.h position; all-ones in the small fields.
    let want_w0: u32 = 1
        | (0x1F << 1)
        | (0x3 << 6)
        | (0xAB << 8)
        | (1 << 16)
        | (1 << 17)
        | (0x3 << 18)
        | (1 << 20)
        | (1 << 21)
        | (1 << 22)
        | (1 << 23)
        | (0x7 << 24)
        | (0x7 << 27)
        | (1 << 30)
        | (1 << 31);
    if w[0] != want_w0 {
        return TestResult::Fail("BE RA v1 w0 wrong");
    }
    if w[1] != 0x1234_5678 || w[2] != 0xFFFF_FFFF {
        return TestResult::Fail("BE RA v1 w1/w2 wrong");
    }
    // W3 upper bits use the _V1 names: a builder using the v0 names
    // (FIXED_CSI_BW at 31..29 for `band`, FIXED_CSI_GI_LTF at 28..26
    // for `macid_msb`) would place `band`/`macid_msb` differently and
    // fail this all-ones comparison.
    let want_w3: u32 = 0x5A
        | (1 << 8)
        | (1 << 9)
        | (1 << 10)
        | (1 << 11)
        | (0x7 << 12)
        | (1 << 15)
        | (0xFF << 16)
        | (1 << 24)
        | (1 << 25)
        | (0x3 << 27)
        | (0x3 << 29)
        | (1 << 31);
    if w[3] != want_w3 {
        return TestResult::Fail("BE RA v1 w3 _V1 fields wrong");
    }
    let want_w4: u32 = 0x7F | (0x7 << 8) | (0xBEEF << 16);
    if w[4] != want_w4 || w[5] != 0xCAFE {
        return TestResult::Fail("BE RA v1 w4/w5 EHT fields wrong");
    }
    // Zero input must produce zero words (no hidden defaults).
    let zero = build_ra_v1(&RaV1Info::default());
    if zero != [0; 6] {
        return TestResult::Fail("BE RA v1 zero input must give zero words");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_ra_v1_build);
