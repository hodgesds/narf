//! DCN3.0 DSC: the policy needs FEC, an ODM half compresses half the line
//! with half the slices, and the engine's register image is
//! `dsc_write_to_registers`' for DCN2.0's layout.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn dcn303_dsc_power_avoids_removed_registers() -> TestResult {
    use crate::amdgpu_navi22_modeset_model::{d2, Bench};
    let bench = Bench::new();
    bench.model.0.lock().forbidden.push(d2(0x80)..=d2(0xb5));
    let regs = Regs {
        window: crate::amdgpu_reg_window::Window::new(bench.gpu.regs),
        authority: narf_capabilities::Cap::bootstrap(),
    };
    let mut dsc = Dsc::new(regs, u64::from(d2(0)) * 4)
        .for_profile(crate::amdgpu_dcn_profile::Profile::Dcn303);
    for index in 0..2 {
        for on in [true, false] {
            if narf_scheduler::block_on_spin(dsc.power(index, on)) != Ok(true) {
                return TestResult::Fail("DCN303 DSC power operation");
            }
        }
    }
    if narf_scheduler::block_on_spin(dsc.power(2, true)) != Err(Error::Invalid)
        || dsc.stop(2) != Err(Error::Invalid)
        || dsc.optc(2, None) != Err(Error::Invalid)
        || dsc.encoder(2, None) != Err(Error::Invalid)
        || !bench.log().is_empty()
    {
        return TestResult::Fail("DCN303 DSC capacity or removed power registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-dsc",
    dcn303_dsc_power_avoids_removed_registers
);

fn uhd() -> Timing {
    Timing {
        pixel_clock_khz: 533_250,
        h_active: 3840,
        h_total: 4000,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 2160,
        v_total: 2222,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
fn caps() -> [u8; 16] {
    [
        1, 0x21, 0, 0x0f, 0x0b, 4, 1, 0x80, 0x01, 1, 2, 0x0c, 0x10, 0, 0, 0,
    ]
}

fn dcn30_dsc_policy_needs_fec_and_compresses_to_the_link() -> TestResult {
    // HBR2 x2 less FEC: 8.38 Gbps for a 12.8 Gbps stream.
    let kbps = 20 * 27_000 * 8 * 2 * 97 / 100;
    if select(&uhd(), &caps(), 0, kbps).is_some() {
        return TestResult::Fail("DSC without FEC");
    }
    let Some(cfg) = select(&uhd(), &caps(), 1, kbps) else {
        return TestResult::Fail("no DSC for an over-link stream");
    };
    if cfg.bpp_x16 < 8 * 16
        || u64::from(cfg.bpp_x16) * 533_250 / 16 > u64::from(kbps)
        || 3840 % cfg.slices_h != 0
    {
        return TestResult::Fail("compressed rate exceeds the link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-dsc",
    dcn30_dsc_policy_needs_fec_and_compresses_to_the_link
);

fn dcn30_dsc_odm_halves_and_register_image() -> TestResult {
    let cfg = DscConfig {
        slices_h: 4,
        slices_v: 20,
        bpp_x16: 192,
        block_pred: true,
        linebuf_depth: 13,
        version_minor: 2,
        ycbcr422_simple: false,
        frl: None,
    };
    let (Ok(whole), Ok(odm)) = (plan(&uhd(), &cfg, false), plan(&uhd(), &cfg, true)) else {
        return TestResult::Fail("plans refused");
    };
    // Half the picture, half the slices, ICH reset at every line end; one
    // slice width and byte rate for the OPTC and encoder either way.
    if odm.engine.pps.pic_width != 1920
        || odm.engine.slices_h != 2
        || odm.engine.ich_reset_at_eol != 0xf
        || odm.picture.slice_width != whole.picture.slice_width
        || odm.engine.bytes_per_pixel != whole.picture.bytes_per_pixel
    {
        return TestResult::Fail("ODM halves");
    }
    // Five slices per engine are past DCN2.0's four.
    if plan(&uhd(), &DscConfig { slices_h: 5, ..cfg }, false).is_ok() {
        return TestResult::Fail("five slices admitted");
    }
    let v = engine_values(&whole.engine);
    let at = |reg: u64| v.iter().find(|(r, _)| *r == reg).map(|(_, x)| *x);
    // DSCCIF_CONFIG1 carries the picture, DSCC_CONFIG0 the slices, the PPS
    // starts at 0xe and ends at 0x24.
    if at(CIF_CONFIG1) != Some(3840 | 2160 << 16)
        || at(CONFIG0).map(|x| (x >> 4) & 3) != Some(3)
        || at(PPS_CONFIG0 + 2) != Some(3840 | 2160 << 16)
        || at(PPS_CONFIG0 + 22).is_none()
        || v.iter().any(|(r, _)| *r > PPS_CONFIG0 + 22)
    {
        return TestResult::Fail("register image");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-dsc",
    dcn30_dsc_odm_halves_and_register_image
);
