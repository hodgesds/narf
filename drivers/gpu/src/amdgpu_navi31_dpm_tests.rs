use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn navi31_dpm_requests_encode_clk_and_freq_as_linux() -> TestResult {
    // (ppclk << 16) | (mhz & 0xffff), as smu_v13_0_set_soft_freq_limited_range.
    assert_eq!(
        Request::set_soft_min(Clock::Gfxclk, 1200),
        Request {
            msg: 0x19,
            arg: 1200
        }
    );
    assert_eq!(
        Request::set_soft_max(Clock::Uclk, 2000),
        Request {
            msg: 0x1a,
            arg: (2 << 16) | 2000
        }
    );
    assert_eq!(
        Request::set_soft_max_auto(Clock::Sclk),
        Request {
            msg: 0x1a,
            arg: 0xffff
        }
    );
    assert_eq!(
        Request::set_hard_min(Clock::Fclk, 1940),
        Request {
            msg: 0x1b,
            arg: (3 << 16) | 1940
        }
    );
    assert_eq!(
        Request::set_hard_max(Clock::Socclk, 1300),
        Request {
            msg: 0x1c,
            arg: (1 << 16) | 1300
        }
    );
    assert_eq!(
        Request::get_min_dpm_freq(Clock::Dclk),
        Request {
            msg: 0x1d,
            arg: 4 << 16
        }
    );
    assert_eq!(
        Request::get_max_dpm_freq(Clock::Vclk1),
        Request {
            msg: 0x1e,
            arg: 7 << 16
        }
    );
    assert_eq!(
        Request::get_dpm_freq_by_index(Clock::Uclk, 0xff),
        Request {
            msg: 0x1f,
            arg: (2 << 16) | 0xff
        }
    );
    // The CLK_MAP aliases: MCLK is UCLK, DCEFCLK is DCFCLK, SCLK is GFXCLK.
    assert_eq!(Clock::Mclk.ppclk(), Clock::Uclk.ppclk());
    assert_eq!(Clock::Dcefclk.ppclk(), PPCLK_DCFCLK as u32);
    assert_eq!(Clock::Sclk.ppclk(), Clock::Gfxclk.ppclk());
    assert_eq!(Clock::Dclk1.ppclk(), PPCLK_DCLK_1 as u32);
    assert_eq!(
        Request::set_workload_mask(workload::FULL_SCREEN_3D | workload::COMPUTE),
        Request {
            msg: 0x24,
            arg: (1 << 1) | (1 << 5)
        }
    );
    assert_eq!(Request::allow_gfx_off(), Request { msg: 0x28, arg: 0 });
    assert_eq!(Request::disallow_gfx_off(), Request { msg: 0x29, arg: 0 });
    assert_eq!(
        Request::set_ppt_limit(300),
        Request {
            msg: 0x32,
            arg: 300
        }
    );
    assert_eq!(Request::get_ppt_limit(), Request { msg: 0x33, arg: 0 });
    assert_eq!(
        Request::reenable_ac_dc_interrupt(),
        Request { msg: 0x34, arg: 0 }
    );
    assert_eq!(
        Request::set_temperature_input_select(0x1),
        Request {
            msg: 0x38,
            arg: 0x1
        }
    );
    assert_eq!(
        Request::set_fan_boost_limit_rpm(3300),
        Request {
            msg: 0x3c,
            arg: 3300
        }
    );
    assert_eq!(MSG_COUNT, 0x52);
    // Responses: a frequency decodes, zero and out-of-range values do not
    // (the top bit is a DPM-mode flag the decoder masks off).
    assert_eq!(freq_from_response(2400), Some(2400));
    assert_eq!(freq_from_response(0x8000_0960), Some(2400));
    assert_eq!(freq_from_response(0), None);
    assert_eq!(freq_from_response(0x1_0000), None);
    assert_eq!(count_from_response(4), Some(4));
    assert_eq!(count_from_response(0), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_dpm_requests_encode_clk_and_freq_as_linux
);

fn table() -> [u8; DPM_TABLE_BYTES] {
    let mut b = [0u8; DPM_TABLE_BYTES];
    let put = |b: &mut [u8], at: usize, v: u16| {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    };
    for (i, mhz) in [500u16, 1200, 1800, 2400, 2800].iter().enumerate() {
        put(&mut b, 2 * i, *mhz);
    }
    put(&mut b, 32, 1200); // FreqTableVclk[0]
    put(&mut b, 48, 1100); // FreqTableDclk[0]
    put(&mut b, 64, 1000); // FreqTableSocclk[0]
    put(&mut b, 80, 2000); // FreqTableUclk[0]
    put(&mut b, 88, 1300); // FreqTableDispclk[0]
    put(&mut b, 104, 900); // FreqTableDppClk[0]
    put(&mut b, 120, 600); // FreqTableDprefclk[0]
    put(&mut b, 136, 1400); // FreqTableDcfclk[0]
    put(&mut b, 152, 700); // FreqTableDtbclk[0]
    put(&mut b, 168, 1940); // FreqTableFclk[0]
    put(&mut b, 184, 2800); // DcModeMaxFreq[GFXCLK]
    put(&mut b, 184 + 2 * 11, 1400); // DcModeMaxFreq[DCFCLK]
    b
}

fn navi31_dpm_tables_decode_driver_info_table() -> TestResult {
    let t = DpmTables::decode(&table()).unwrap();
    assert_eq!(t.gfx[..5], [500, 1200, 1800, 2400, 2800]);
    assert_eq!(t.vclk[0], 1200);
    assert_eq!(t.dclk[0], 1100);
    assert_eq!(t.socclk[0], 1000);
    assert_eq!(t.uclk[0], 2000);
    assert_eq!(t.dispclk[0], 1300);
    assert_eq!(t.dppclk[0], 900);
    assert_eq!(t.dprefclk[0], 600);
    assert_eq!(t.dcfclk[0], 1400);
    assert_eq!(t.dtbclk[0], 700);
    assert_eq!(t.fclk[0], 1940);
    assert_eq!(t.dc_mode_max(PPCLK_GFXCLK), Some(2800));
    assert_eq!(t.dc_mode_max(PPCLK_DCFCLK), Some(1400));
    assert_eq!(t.dc_mode_max(PPCLK_COUNT), None);
    // Both VCLK/DCLK instances share one table each.
    assert_eq!(t.freq_table(PPCLK_VCLK_0), t.freq_table(PPCLK_VCLK_1));
    assert_eq!(t.freq_table(PPCLK_DCLK_0), t.freq_table(PPCLK_DCLK_1));
    assert_eq!(t.freq_table(PPCLK_GFXCLK).unwrap().len(), 16);
    assert_eq!(t.freq_table(PPCLK_UCLK).unwrap().len(), 4);
    assert_eq!(t.freq_table(PPCLK_COUNT), None);
    assert!(DpmTables::decode(&table()[..DPM_TABLE_BYTES - 1]).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_dpm_tables_decode_driver_info_table
);
