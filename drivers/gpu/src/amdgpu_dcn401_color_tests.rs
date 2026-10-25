//! Register-level model tests of the DCN401 CRTC color programming.
use super::*;
use crate::amdgpu_dcn401_otg::tests::{engine, run, Fake};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const BASE: u64 = 0x10000;
const MPC_BASE: u64 = 0x30000;
fn dpp(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x16b) * 4
}
fn mpcc(p: u8, r: u64) -> u64 {
    MPC_BASE + (r + u64::from(p) * 0x15) * 4
}
fn ogam(p: u8, r: u64) -> u64 {
    MPC_BASE + (r + u64::from(p) * 0x5e) * 4
}
fn mcm(p: u8, r: u64) -> u64 {
    MPC_BASE + (r + u64::from(p) * 0xb0) * 4
}

/// A PWL whose words name their own register so misplaced writes show.
fn pwl(equal: bool) -> OgamProgram {
    let lut = |c: u32| -> Vec<u32> {
        (0..195u32)
            .map(|i| i << 4 | if equal { 0 } else { c })
            .collect()
    };
    OgamProgram {
        start: [0x1_0001, 0x1_0002, 0x1_0003],
        start_slope: [0x2_0001, 0x2_0002, 0x2_0003],
        end_base: [0x3_0001, 0x3_0002, 0x3_0003],
        end: [0x4_0001, 0x4_0002, 0x4_0003],
        regions: core::array::from_fn(|i| 0x5_0000 | i as u32),
        lut: [lut(1), lut(2), lut(3)],
    }
}

/// Every write `e` made at `at`, in order.
fn writes_at(e: &Engine<Fake>, at: u64) -> Vec<u32> {
    e.io.writes
        .iter()
        .filter(|&&(a, _)| a == at)
        .map(|&(_, v)| v)
        .collect()
}

/// The written position of the first write to `at`.
fn first(e: &Engine<Fake>, at: u64) -> Option<usize> {
    e.io.writes.iter().position(|&(a, _)| a == at)
}

/// mpc3_set_output_gamma: RAM A from bypass, B while A is current, A while
/// B is current; the bank's own registers in cm_helper_program_gamcor_xfer_func
/// order, then the LUT and finally SELECT.
fn dcn401_color_ogam_ping_pongs_banks_like_mpc3() -> TestResult {
    for p in 0..4u8 {
        let program = pwl(true);
        for (current, next, ram) in [
            (0u32, 0u32, 0x82u64),
            (2 << 7, 1, 0xa5),
            (2 << 7 | 1 << 9, 0, 0x82),
            (1 << 7 | 1 << 9, 0, 0x82), // ROM/other mode: not RAM, so A
        ] {
            let mut e = engine();
            e.io.regs.insert(ogam(p, 0x7e), current);
            let Ok(Some(bank)) = run(e.program_ogam(p, Some(&program))) else {
                return TestResult::Fail("ogam programming");
            };
            if u32::from(bank) != next {
                return TestResult::Fail("bank choice");
            }
            // MODE = RAM, then the next bank's selection at the end.
            let control = writes_at(&e, ogam(p, 0x7e));
            if control.first().map(|v| v & 0xf) != Some(2)
                || control.last().map(|v| v & 0xf) != Some(2 | next << 2)
            {
                return TestResult::Fail("OGAM_CONTROL");
            }
            // mpc3_power_on_ogam_lut, then all channels to the host bank.
            if e.io.regs.get(&mpcc(p, 0xd)).copied().unwrap_or(0) & 4 == 0
                || writes_at(&e, ogam(p, 0x81)).first().map(|v| v & 0x47) != Some(7 | next << 6)
            {
                return TestResult::Fail("LUT power/host select");
            }
            let order: Vec<u64> = (0..3)
                .chain(3..6)
                .chain([9, 0xb, 0xd])
                .chain([0xa, 0xc, 0xe])
                .chain(0x12..0x23)
                .map(|r| ram + r)
                .collect();
            let mut at = 0;
            for (i, &r) in order.iter().enumerate() {
                let want = match i {
                    0..=2 => program.start[i],
                    3..=5 => program.start_slope[i - 3],
                    6..=8 => program.end_base[i - 6],
                    9..=11 => program.end[i - 9],
                    _ => program.regions[i - 12],
                };
                let Some(pos) = first(&e, ogam(p, r)) else {
                    return TestResult::Fail("bank register missing");
                };
                if pos < at || writes_at(&e, ogam(p, r)) != [want] {
                    return TestResult::Fail("bank register order/value");
                }
                at = pos;
            }
            // The other bank is untouched.
            let other = if ram == 0x82 { 0xa5 } else { 0x82 };
            if (other..other + 0x23).any(|r| first(&e, ogam(p, r)).is_some()) {
                return TestResult::Fail("other bank written");
            }
            // Equal channels: one pass of hw_points_num words.
            if writes_at(&e, ogam(p, 0x80)) != program.lut[0] {
                return TestResult::Fail("LUT data");
            }
            if first(&e, ogam(p, 0x80)) < Some(at) {
                return TestResult::Fail("LUT before the bank registers");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-color",
    dcn401_color_ogam_ping_pongs_banks_like_mpc3
);

/// mpc3_program_ogam_pwl with differing channels: red, green, blue under
/// write masks 4, 2, 1, the index reset before green and blue.
fn dcn401_color_ogam_writes_channels_separately() -> TestResult {
    let program = pwl(false);
    let mut e = engine();
    if run(e.program_ogam(2, Some(&program))) != Ok(Some(0)) {
        return TestResult::Fail("program");
    }
    let (data, index, control) = (ogam(2, 0x80), ogam(2, 0x7f), ogam(2, 0x81));
    let mut events = Vec::new();
    for &(at, v) in &e.io.writes {
        if at == control {
            events.push(("mask", v & 7));
        } else if at == index {
            events.push(("index", v));
        }
    }
    if events
        != [
            ("mask", 7),
            ("index", 0),
            ("mask", 4),
            ("index", 0),
            ("mask", 2),
            ("index", 0),
            ("mask", 1),
        ]
    {
        return TestResult::Fail("mask/index sequence");
    }
    let words = writes_at(&e, data);
    let n = program.lut[0].len();
    if words.len() != 3 * n
        || words[..n] != program.lut[0][..]
        || words[n..2 * n] != program.lut[1][..]
        || words[2 * n..] != program.lut[2][..]
    {
        return TestResult::Fail("per-channel data");
    }
    // Each channel's words follow its own mask write.
    let masks: Vec<usize> =
        e.io.writes
            .iter()
            .enumerate()
            .filter(|(_, &(at, _))| at == control)
            .map(|(i, _)| i)
            .collect();
    let first_word = |c: usize| {
        e.io.writes
            .iter()
            .position(|&w| w == (data, program.lut[c][0]))
            .unwrap_or(0)
    };
    if masks.len() != 4 || (0..3).any(|c| first_word(c) < masks[c + 1]) {
        return TestResult::Fail("channel before its mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-color",
    dcn401_color_ogam_writes_channels_separately
);

/// mpc401_set_gamut_remap: set A unless A is current; coefficients, mode,
/// then format; both MCM remaps bypassed; bypass is mode 0.
fn dcn401_color_gamut_remap_alternates_sets() -> TestResult {
    let gamut = GamutProgram {
        coef: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        s3_12: true,
    };
    for (current, set, base) in [(0u32, 1u8, 0xcau64), (1 << 7, 2, 0xd0), (2 << 7, 1, 0xca)] {
        let mut e = engine();
        e.io.regs.insert(ogam(1, 0xc9), current);
        e.io.regs.insert(mcm(1, 0x4de), 1);
        if e.program_gamut(1, Some(&gamut)) != Ok(Some((set, true))) {
            return TestResult::Fail("gamut set");
        }
        for (i, &c) in gamut.coef.iter().enumerate() {
            if writes_at(&e, ogam(1, base + i as u64)) != [c] {
                return TestResult::Fail("coefficients");
            }
        }
        let other = if base == 0xca { 0xd0 } else { 0xca };
        if (other..other + 6).any(|r| first(&e, ogam(1, r)).is_some()) {
            return TestResult::Fail("other set written");
        }
        if e.io.regs[&ogam(1, 0xc9)] & 3 != u32::from(set)
            || e.io.regs[&ogam(1, 0xc8)] & 1 != 1
            || first(&e, ogam(1, 0xc9)) > first(&e, ogam(1, 0xc8))
            || first(&e, ogam(1, base)) > first(&e, ogam(1, 0xc9))
            || e.io.regs[&mcm(1, 0x4de)] & 3 != 0
            || e.io.regs[&mcm(1, 0x4ec)] & 3 != 0
        {
            return TestResult::Fail("mode/format order");
        }
    }
    let mut e = engine();
    e.io.regs.insert(ogam(3, 0xc9), 1 | 1 << 7);
    if e.program_gamut(3, None) != Ok(None) || e.io.regs[&ogam(3, 0xc9)] & 3 != 0 {
        return TestResult::Fail("bypass");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-color",
    dcn401_color_gamut_remap_alternates_sets
);

/// dpp3_set_pre_degam's sRGB ROM for an RGB plane under legacy gamma
/// (mode 1, select 0) or bypass, the GAMCOR bypassed; the BT.709 points of
/// an NV12 plane bypass the ROM and select the GAMCOR RAM they were loaded
/// into (B from bypass); CM enabled throughout.
fn dcn401_color_input_tf_selects_the_srgb_rom() -> TestResult {
    for (tf, word, gamcor, bank) in [
        (InputTf::Srgb, 1, 0, None),
        (InputTf::Bypass, 0, 0, None),
        (InputTf::Bt709, 0, 2 | 4, Some(1)),
    ] {
        let mut e = engine();
        e.io.regs.insert(dpp(0, 0xced), 0x52);
        e.io.regs.insert(dpp(0, 0xd77), 0xa);
        e.io.regs.insert(dpp(0, 0xd67), 1);
        if e.program_input_tf(0, tf) != Ok(bank)
            || e.io.regs[&dpp(0, 0xced)] & 0x73 != word
            || e.io.regs[&dpp(0, 0xd77)] & 0xf != gamcor
            || e.io.regs[&dpp(0, 0xd67)] & 1 != 0
        {
            return TestResult::Fail("input transfer function");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-color",
    dcn401_color_input_tf_selects_the_srgb_rom
);

/// tests/dcn401_yuv/gamcor_vectors.txt: every register write Linux's
/// dcn32_set_input_transfer_func makes for each format under legacy gamma
/// (map_crtc_degamma_to_dc_plane through mod_color_calculate_degamma_params,
/// dpp3_set_pre_degam, cm3_helper_translate_curve_to_degamma_hw_format and
/// dpp3_program_gamcor_lut), from a DPP whose GAMCOR is bypassed, on RAM A
/// or on RAM B, in order and with its values (CM_GAMCOR_CONTROL's read-only
/// MODE/SELECT_CURRENT left out).
fn dcn401_color_input_tf_matches_linux_gamcor_vectors() -> TestResult {
    use core::fmt::Write;
    const VECTORS: &str = include_str!("../tests/dcn401_yuv/gamcor_vectors.txt");
    let mut n = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let (input, want) = line.split_once(" = ").unwrap();
        let (code, control) = input.split_once(' ').unwrap();
        let code = code.as_bytes();
        let fourcc = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        let control = u32::from_str_radix(control, 16).unwrap();
        let format = SurfaceFormat::from_fourcc(fourcc).unwrap();
        let mut e = engine();
        e.io.regs.insert(dpp(0, 0xd77), control);
        if e.program_input_tf(0, InputTf::implicit(format)).is_err() {
            return TestResult::Fail("input transfer function refused");
        }
        let mut got = alloc::string::String::new();
        let _ = write!(got, "{}", e.io.writes.len());
        for &(at, value) in &e.io.writes {
            let reg = (at - BASE) / 4;
            let value = if reg == 0xd77 { value & !0x70 } else { value };
            let _ = write!(got, " {reg:x}:{value:x}");
        }
        if got != want {
            let _ = writeln!(
                narf_console::Writer,
                "dcn401_yuv gamcor: {input}: got {}, want {}",
                &got[..got.len().min(160)],
                &want[..want.len().min(160)]
            );
            return TestResult::Fail("input transfer function differs from Linux");
        }
        n += 1;
    }
    if n != 27 {
        return TestResult::Fail("vector count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-color",
    dcn401_color_input_tf_matches_linux_gamcor_vectors
);

/// A dark display only records its color; the record drives programming
/// at its next start, and the per-pipe record what verifiers expect.
fn dcn401_color_records_without_live_scanout() -> TestResult {
    let mut e = engine();
    let program = Arc::new(ColorProgram {
        pre_degam_srgb: true,
        gamut: None,
        ogam: Some(pwl(true)),
    });
    if run(e.set_color(1, Some(program.clone()))).is_err()
        || !e.io.writes.is_empty()
        || !e.displays.color[1]
            .as_ref()
            .is_some_and(|c| Arc::ptr_eq(c, &program))
        || e.status.state != State::Ready
    {
        return TestResult::Fail("dark display");
    }
    // The verifier reads what the record says.
    e.status.colors[1] = PipeColor {
        pre_degam: PreDegam::Srgb,
        gamcor: None,
        gamut: Some((2, false)),
        ogam: Some(1),
    };
    e.io.regs.insert(dpp(1, 0xced), 1);
    e.io.regs.insert(ogam(1, 0x7e), 2 | 4);
    e.io.regs.insert(ogam(1, 0xc9), 2);
    if e.verify_color(1).is_err() {
        return TestResult::Fail("verify programmed");
    }
    e.io.regs.insert(ogam(1, 0x7e), 2);
    if e.verify_color(1).is_ok() {
        return TestResult::Fail("wrong bank accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-color",
    dcn401_color_records_without_live_scanout
);

/// amdgpu_dm's mapping of the CRTC blobs: legacy 256-entry gamma always
/// regammas on an sRGB-linearized input; a linear 4096-entry LUT, like none,
/// bypasses; any CTM remaps; other sizes are refused.
fn dcn401_color_maps_crtc_blobs_like_amdgpu_dm() -> TestResult {
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
    let linear256 = lut(256, &|i| (i * 0xffff / 255) as u16);
    let mut identity = [0u8; 72];
    for k in [0, 4, 8] {
        identity[k * 8..k * 8 + 8].copy_from_slice(&(1u64 << 32).to_le_bytes());
    }
    if ColorProgram::from_crtc(None, None) != Some(ColorProgram::default())
        || ColorProgram::from_crtc(None, Some(&linear4096)) != Some(ColorProgram::default())
    {
        return TestResult::Fail("bypass");
    }
    let Some(atomic) = ColorProgram::from_crtc(None, Some(&inverse4096)) else {
        return TestResult::Fail("atomic regamma");
    };
    let Some(legacy) = ColorProgram::from_crtc(None, Some(&linear256)) else {
        return TestResult::Fail("legacy regamma");
    };
    if atomic.pre_degam_srgb
        || atomic.gamut.is_some()
        || atomic.ogam.as_ref().is_none_or(|o| o.lut[0].len() != 195)
        || !legacy.pre_degam_srgb
        || legacy.ogam.as_ref().is_none_or(|o| o.lut[0].len() != 195)
    {
        return TestResult::Fail("regamma mapping");
    }
    // The identity CTM is still a remap: unity S2.13 on the diagonal.
    let Some(ctm) = ColorProgram::from_crtc(Some(&identity), None) else {
        return TestResult::Fail("CTM");
    };
    if ctm.gamut
        != Some(GamutProgram {
            coef: [0x2000, 0, 0x2000 << 16, 0, 0, 0x2000],
            s3_12: false,
        })
        || ctm.ogam.is_some()
    {
        return TestResult::Fail("identity CTM");
    }
    if ColorProgram::from_crtc(Some(&identity[..64]), None).is_some()
        || ColorProgram::from_crtc(None, Some(&linear4096[..1024 * 8])).is_some()
        || ColorProgram::from_crtc(None, Some(&linear4096[..7])).is_some()
    {
        return TestResult::Fail("bad sizes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-color",
    dcn401_color_maps_crtc_blobs_like_amdgpu_dm
);

/// amdgpu_dm_update_plane_color_mgmt on DCN 4.0.1 (no plane color
/// property): a plane's input transfer function is bypassed unless the
/// CRTC's legacy gamma asks for map_crtc_degamma_to_dc_plane's implicit
/// degamma, which is BT.709 for an NV12 plane (VIDEO_420_YCrCb) and sRGB
/// for an RGB or P010 (VIDEO_420_10bpc_YCrCb) one; each HUBP/DPP takes the
/// one of the plane it fetches, ODM segments included.
fn dcn401_color_input_tf_follows_the_planes_format() -> TestResult {
    use crate::amdgpu_dcn401_otg::{SplitPipes, SurfaceRequest};
    let plane = |pipe: u8, odm: SplitPipes, format: SurfaceFormat| {
        let request = SurfaceRequest {
            pipe,
            width: 64,
            height: 32,
            format,
            odm,
            mpc: SplitPipes::NONE,
            plane: None,
            surface: Default::default(),
        };
        let b = request.bytes();
        SurfaceApplied::staged(request, 0x8_0000_0000, b.pitch_bytes, b.bytes)
    };
    for (format, want) in [
        (SurfaceFormat::Nv12, InputTf::Bt709),
        (SurfaceFormat::P010, InputTf::Srgb),
        (SurfaceFormat::Xrgb8888, InputTf::Srgb),
        (SurfaceFormat::Abgr16161616f, InputTf::Srgb),
    ] {
        for legacy in [false, true] {
            let mut e = engine();
            e.status.surfaces[0] = Some(plane(0, SplitPipes::one(1), format));
            e.status.surfaces[2] = Some(plane(2, SplitPipes::NONE, SurfaceFormat::Nv12));
            e.displays.color[0] = Some(Arc::new(ColorProgram {
                pre_degam_srgb: legacy,
                ..Default::default()
            }));
            let want = if legacy { want } else { InputTf::Bypass };
            if e.input_tf(0, 0) != want || e.input_tf(0, 1) != want {
                return TestResult::Fail("plane's implicit degamma");
            }
            let overlay = if legacy {
                InputTf::Bt709
            } else {
                InputTf::Bypass
            };
            if e.input_tf(0, 2) != overlay {
                return TestResult::Fail("overlay's implicit degamma");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-color",
    dcn401_color_input_tf_follows_the_planes_format
);
