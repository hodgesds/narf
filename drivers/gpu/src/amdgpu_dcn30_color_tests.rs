//! amdgpu_dm's mapping of the CRTC blobs on DCN 3.0.
use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// amdgpu_dm's mapping of the CRTC blobs: legacy 256-entry gamma always
/// regammas on an sRGB-linearized input unless an explicit degamma
/// replaces it; a linear 4096-entry LUT, like none, bypasses; a
/// non-linear 4096-entry DEGAMMA_LUT becomes the GAMCOR distributed
/// points; any CTM remaps; other sizes are refused.
fn dcn30_color_maps_crtc_blobs_like_amdgpu_dm() -> TestResult {
    let lut = |n: usize, f: &dyn Fn(usize) -> u16| -> Vec<u8> {
        (0..n)
            .flat_map(|i| {
                let v = f(i);
                [v, v, v, 0].into_iter().flat_map(u16::to_le_bytes)
            })
            .collect()
    };
    let linear4096 = lut(4096, &|i| (i * 0xffff / 4095) as u16);
    let inverse4096 = lut(4096, &|i| (0xffff - i * 0xffff / 4095) as u16);
    // A non-linear increasing curve (gamma 2.2), the shape a degamma LUT
    // takes: the GAMCOR's distributed points stay non-decreasing.
    let gamma4096 = lut(4096, &|i| {
        let x = i as u64;
        let d = 4095u64;
        ((x * x * 0xffff) / (d * d)) as u16
    });
    let linear256 = lut(256, &|i| (i * 0xffff / 255) as u16);
    let mut identity = [0u8; 72];
    for k in [0, 4, 8] {
        identity[k * 8..k * 8 + 8].copy_from_slice(&(1u64 << 32).to_le_bytes());
    }
    if ColorProgram::from_crtc(None, None, None) != Some(ColorProgram::default())
        || ColorProgram::from_crtc(None, Some(&linear4096), None) != Some(ColorProgram::default())
        || ColorProgram::from_crtc(None, None, Some(&linear4096)) != Some(ColorProgram::default())
    {
        return TestResult::Fail("bypass");
    }
    let Some(atomic) = ColorProgram::from_crtc(None, None, Some(&inverse4096)) else {
        return TestResult::Fail("atomic regamma");
    };
    let Some(legacy) = ColorProgram::from_crtc(None, None, Some(&linear256)) else {
        return TestResult::Fail("legacy regamma");
    };
    if atomic.pre_degam_srgb
        || atomic.degamma.is_some()
        || atomic.gamut.is_some()
        || atomic.ogam.as_ref().is_none_or(|o| o.lut[0].len() != 195)
        || !legacy.pre_degam_srgb
        || legacy.degamma.is_some()
        || legacy.ogam.as_ref().is_none_or(|o| o.lut[0].len() != 195)
    {
        return TestResult::Fail("regamma mapping");
    }
    // The DEGAMMA_LUT is the 9-region GAMCOR PWL (256 hardware points),
    // not the 13-region OGAM one.
    let Some(degamma) = ColorProgram::from_crtc(None, Some(&gamma4096), None) else {
        return TestResult::Fail("degamma");
    };
    if degamma.pre_degam_srgb
        || degamma.ogam.is_some()
        || degamma.gamut.is_some()
        || degamma
            .degamma
            .as_ref()
            .is_none_or(|o| o.lut[0].len() != 256)
    {
        return TestResult::Fail("degamma mapping");
    }
    // An explicit degamma replaces the implicit sRGB ROM: legacy gamma
    // still regammas, but its input is the GAMCOR, not the ROM.
    let Some(both) = ColorProgram::from_crtc(None, Some(&gamma4096), Some(&linear256)) else {
        return TestResult::Fail("degamma with legacy gamma");
    };
    if both.pre_degam_srgb || both.degamma.is_none() || both.ogam.is_none() {
        return TestResult::Fail("explicit degamma must replace the ROM");
    }
    // A linear DEGAMMA_LUT is identity: the GAMCOR stays bypassed and
    // legacy gamma keeps its ROM.
    let Some(linear_degamma) = ColorProgram::from_crtc(None, Some(&linear4096), Some(&linear256))
    else {
        return TestResult::Fail("linear degamma with legacy gamma");
    };
    if !linear_degamma.pre_degam_srgb || linear_degamma.degamma.is_some() {
        return TestResult::Fail("linear degamma must not replace the ROM");
    }
    // The identity CTM is still a remap: unity S2.13 on the diagonal.
    let Some(ctm) = ColorProgram::from_crtc(Some(&identity), None, None) else {
        return TestResult::Fail("CTM");
    };
    if ctm.gamut
        != Some(GamutProgram {
            coef: [0x2000, 0, 0x2000 << 16, 0, 0, 0x2000],
            s3_12: false,
        })
        || ctm.ogam.is_some()
        || ctm.degamma.is_some()
    {
        return TestResult::Fail("identity CTM");
    }
    if ColorProgram::from_crtc(Some(&identity[..64]), None, None).is_some()
        || ColorProgram::from_crtc(None, Some(&linear256), None).is_some()
        || ColorProgram::from_crtc(None, None, Some(&linear4096[..1024 * 8])).is_some()
        || ColorProgram::from_crtc(None, None, Some(&linear4096[..7])).is_some()
        || ColorProgram::from_crtc(None, Some(&linear4096[..1024 * 8]), None).is_some()
    {
        return TestResult::Fail("bad sizes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-color",
    dcn30_color_maps_crtc_blobs_like_amdgpu_dm
);

/// `same_program`: identity by pointer or by value, never across
/// different programs or the bypass boundary.
fn dcn30_color_same_program() -> TestResult {
    let a = Arc::new(ColorProgram {
        pre_degam_srgb: true,
        ..Default::default()
    });
    let b = Arc::new(ColorProgram {
        pre_degam_srgb: true,
        ..Default::default()
    });
    let c = Arc::new(ColorProgram::default());
    if !same_program(&None, &None)
        || !same_program(&Some(a.clone()), &Some(a.clone()))
        || !same_program(&Some(a.clone()), &Some(b))
        || same_program(&Some(a), &Some(c.clone()))
        || same_program(&Some(c), &None)
    {
        return TestResult::Fail("same_program");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn30-color", dcn30_color_same_program);

/// The PRE_DEGAM ROM words dpp3_set_pre_degam writes.
fn dcn30_color_pre_degam_words() -> TestResult {
    if PreDegam::Bypass.word() != 0 || PreDegam::Srgb.word() != 1 {
        return TestResult::Fail("pre_degam words");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn30-color", dcn30_color_pre_degam_words);
