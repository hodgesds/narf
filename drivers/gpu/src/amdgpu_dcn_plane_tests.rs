use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    values: Vec<u32>,
    writes: Vec<(u64, u32)>,
}
impl Fake {
    fn new(size: u32) -> Self {
        Self {
            values: vec![0; size as usize + 1],
            writes: Vec::new(),
        }
    }
}
impl Io for Fake {
    fn read(&mut self, reg: u64) -> u32 {
        self.values[reg as usize]
    }
    fn write(&mut self, reg: u64, value: u32) {
        self.writes.push((reg, value));
        self.values[reg as usize] = value;
    }
}
fn block(instance: u8, size: u32) -> Block<Fake> {
    Block {
        io: Fake::new(size),
        authority: Cap::bootstrap(),
        instance,
        profile: Profile::Dcn314,
    }
}
fn plane_navi22_routes_sixth_dpp_and_opp() -> TestResult {
    let mut mpc = block(5, 0x0680);
    mpc.profile = Profile::Navi22;
    mpc.mpc_mux_plane(5, 5).unwrap();
    if mpc.io.values[0xa0] & 0xf != 5
        || mpc.io.values[0xa1] & 0xf != 15
        || mpc.io.values[0xa2] & 0xf != 5
        || mpc.io.values[0x594] & 0xf != 5
    {
        return TestResult::Fail("DCN30 sixth plane mux");
    }
    let count = mpc.io.writes.len();
    if mpc.mpc_mux_plane(6, 0) != Err(Error::Invalid)
        || mpc.mpc_mux_plane(0, 6) != Err(Error::Invalid)
        || mpc.io.writes.len() != count
    {
        return TestResult::Fail("DCN30 instance limit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_navi22_routes_sixth_dpp_and_opp
);

fn plane_dpp_bypasses_the_scaler_for_an_unscaled_plane() -> TestResult {
    // Drive the same register writes the public Dpp performs, on instance 1.
    let mut dpp = block(1, DPP_LAST_REG);
    let at = |reg: u64| reg + DPP_STRIDE;
    let (width, height) = (1920u32, 1080u32);
    // Inherited scaler mode 6, `DSCL_MODE_DSCL_BYPASS` — the highest value
    // `enum dscl_mode_sel` defines. A two-bit mask would leave 4 behind.
    dpp.io.values[at(SCL_MODE) as usize] = 6;
    if dpp.dpp_program(Format::Rgb32, width, height).is_err() {
        return TestResult::Fail("DPP programming rejected");
    }
    // The DPP clock has to be running before it processes anything.
    if dpp.io.values[at(DPP_CONTROL) as usize] & 1 << 4 == 0 {
        return TestResult::Fail("DPP clock left gated");
    }
    // ARGB8888 is code 8 in the converter too, not its bit depth.
    if dpp.io.values[at(CNVC_SURFACE_PIXEL_FORMAT) as usize] & 0x7f != 8 {
        return TestResult::Fail("converter pixel format");
    }
    // Bypass, not unity taps. `DSCL0_SCL_MODE__DSCL_MODE_MASK` is 0x00000007 —
    // three bits, because the enum runs to 6.
    if dpp.io.values[at(SCL_MODE) as usize] & 0x0000_0007 != SCALER_BYPASS {
        return TestResult::Fail("scaler not bypassed");
    }
    // The recout and combiner size both match the active area for a 1:1 plane.
    if dpp.io.values[at(RECOUT_SIZE) as usize] != 1920 | 1080 << 16
        || dpp.io.values[at(MPC_SIZE) as usize] != 1920 | 1080 << 16
        || dpp.io.values[at(RECOUT_START) as usize] != 0
    {
        return TestResult::Fail("recout geometry");
    }
    if cnvc_format(Format::Rgb16) != 3 || cnvc_format(Format::Rgb64) != 26 {
        return TestResult::Fail("converter format codes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_dpp_bypasses_the_scaler_for_an_unscaled_plane
);

fn plane_dpp_normalizes_inherited_conversion_and_color() -> TestResult {
    for profile in [Profile::Navi22, Profile::Dcn314] {
        for format in [Format::Rgb16, Format::Rgb32, Format::Rgb64] {
            // The same fields/offsets exist in both Linux register headers.
            let mut dpp = block(2, (0x0d21 + 3 * DPP_STRIDE) as u32);
            dpp.profile = profile;
            let at = |reg: u64| (reg + 2 * DPP_STRIDE) as usize;
            dpp.io.values[at(CNVC_SURFACE_PIXEL_FORMAT)] = 0x8000_0100;
            dpp.io.values[at(0x0cd0)] = 0xbf03_3111; // FORMAT_CONTROL
            dpp.io.values[at(0x0cde)] = 0x8000_0011; // PRE_DEALPHA
            dpp.io.values[at(0x0ced)] = 0x8000_0073; // PRE_DEGAM
            dpp.io.values[at(0x0cee)] = 0x8000_0011; // PRE_REALPHA
            dpp.io.values[at(0x0d20)] = 0x8000_0000; // CM_CONTROL: LUTs active
            dpp.io.values[at(0x0d0c)] = 0x8000_3303; // DSCL_AUTOCAL
            dpp.io.values[at(0x0cfd)] = 0x8000_0001; // DSCL_CONTROL
            dpp.io.values[at(0x0d14)] = 0x8000_0011; // LB_DATA_FORMAT
            dpp.io.values[at(0x0d15)] = 0x0000_0003; // 4:2:0 LB banks
            if dpp.dpp_program(format, 3840, 2160).is_err() {
                return TestResult::Fail("DPP conversion setup rejected");
            }
            let alpha = u32::from(format != Format::Rgb16) << 8;
            if dpp.io.values[at(CNVC_SURFACE_PIXEL_FORMAT)] != 0x8000_0000 | cnvc_format(format)
                || dpp.io.values[at(0x0cd0)] != 0xa400_0001 | alpha
            {
                return TestResult::Fail("inherited CNVC conversion/crossbar/alpha survived");
            }
            if dpp.io.values[at(0x0cde)] != 0x8000_0000
                || dpp.io.values[at(0x0ced)] != 0x8000_0000
                || dpp.io.values[at(0x0cee)] != 0x8000_0000
                || dpp.io.values[at(0x0d20)] != 0x8000_0001
            {
                return TestResult::Fail("inherited alpha processing or color LUT survived");
            }
            if dpp.io.values[at(0x0d0c)] != 0x8000_0000
                || dpp.io.values[at(0x0cfd)] != 0x8000_0000
                || dpp.io.values[at(0x0d14)] != 0x8000_0000
                || dpp.io.values[at(0x0d15)] != 0x3f00
            {
                return TestResult::Fail("inherited scaler/line-buffer state survived");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_dpp_normalizes_inherited_conversion_and_color
);

fn plane_navi22_bypasses_inherited_gamut_and_rmus() -> TestResult {
    let mut mpc = block(2, 0x680);
    mpc.profile = Profile::Navi22;
    mpc.io.values[0x24b] = 0x8000_0002;
    // RMUs 0 and 2 were attached to our MPCC; RMU 1 belongs to MPCC 3.
    // Each byte contains a requested mux and its read-only status nibble.
    let inherited = 0x8000_0000 | 0x22 | (0x33 << 8) | (0x22 << 16);
    mpc.io.values[0x680] = inherited;
    if mpc.mpc_mux_plane(2, 2).is_err() {
        return TestResult::Fail("MPC passthrough initialization");
    }
    if mpc.io.values[0x24b] != 0x8000_0000 {
        return TestResult::Fail("inherited MPC gamut matrix survived");
    }
    let writable = 0x000f_000f;
    if mpc.io.values[0x680] != (inherited & !writable) | writable {
        return TestResult::Fail("owned remap units retained, or another stream's remap changed");
    }
    TestResult::Pass
}
fn plane_rmu_release_respects_each_rdna2_physical_capacity() -> TestResult {
    for (profile, mask) in [
        (Profile::Navi22, 0x000f_0f0f),
        (Profile::Dcn302, 0x0000_0f0f),
        (Profile::Dcn303, 0x0000_000f),
    ] {
        let mut mpc = block(0, 0x680);
        mpc.profile = profile;
        mpc.io.values[0x680] = 0x8000_0000;
        if mpc.mpc_mux_plane(0, 0).is_err() || mpc.io.values[0x680] != 0x8000_0000 | mask {
            return TestResult::Fail("absent remap mux was programmed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_rmu_release_respects_each_rdna2_physical_capacity
);
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_navi22_bypasses_inherited_gamut_and_rmus
);

fn plane_mpc_binds_one_pipe_with_nothing_beneath_it() -> TestResult {
    let mut mpc = block(2, MPC_LAST_REG);
    mpc.io.values[(0x0100 + 2 * 0x80) as usize] = 0x8000_0002;
    // Seed MPCC_CONTROL's reserved bits 3:2 and an inherited FMT-style
    // subsampling value so an over-wide mask shows up as a cleared bit.
    mpc.io.values[(MPCC_CONTROL + 2 * MPCC_STRIDE) as usize] = 0x0000_000C;
    let at = |reg: u64| reg + 2 * MPCC_STRIDE;
    // Leave a stale bottom select behind to prove it gets cleared.
    mpc.io.values[at(MPCC_BOT_SEL) as usize] = 1;
    let (dpp, opp) = (3u32, 1u8);
    let mux = MPC_OUT_MUX + opp as u64 * MPC_OUT_STRIDE;
    if mpc.mpc_mux_plane(dpp as u8, opp).is_err() {
        return TestResult::Fail("MPC programming rejected");
    }
    if mpc.io.values[(0x0100 + 2 * 0x80) as usize] != 0x8000_0000 {
        return TestResult::Fail("inherited output gamma LUT survived");
    }
    if mpc.io.values[at(MPCC_TOP_SEL) as usize] & 0xf != 3 {
        return TestResult::Fail("top select");
    }
    // Nothing below the plane; a stale bottom would blend another pipe in.
    if mpc.io.values[at(MPCC_BOT_SEL) as usize] & 0xf != MPCC_UNSET {
        return TestResult::Fail("stale bottom select retained");
    }
    if mpc.io.values[at(MPCC_OPP_ID) as usize] & 0xf != 1 {
        return TestResult::Fail("OPP binding");
    }
    // `mpc1_mux_plane` with no bottom layer writes `MPCC_MODE` =
    // `MPCC_BLEND_MODE_TOP_LAYER_ONLY` = 2. BYPASS (0) is a different mode and
    // Linux's MPC never writes it: a bypassed MPCC puts nothing on the OPP.
    let control = mpc.io.values[at(MPCC_CONTROL) as usize];
    if control & 0x0000_0003 != 2 {
        return TestResult::Fail("MPCC_MODE must be TOP_LAYER_ONLY, not BYPASS");
    }
    // The opaque blend configuration from `dcn20_hwseq.c:2960-2990`:
    // MPCC_ALPHA_BLND_MODE 0x30 = 2 (global alpha), MPCC_GLOBAL_ALPHA
    // 0x00FF0000 = 0xff, MPCC_BG_BPC 0x700 = 4, with
    // MPCC_ALPHA_MULTIPLIED_MODE 0x40 and MPCC_BLND_ACTIVE_OVERLAP_ONLY 0x80
    // both clear.
    if (control & 0x0000_0030) >> 4 != 2 {
        return TestResult::Fail("alpha blend mode");
    }
    if (control & 0x00FF_0000) >> 16 != 0xff {
        return TestResult::Fail("global alpha must be fully opaque");
    }
    if (control & 0x0000_0700) >> 8 != 4 {
        return TestResult::Fail("background colour bpc");
    }
    if control & (0x0000_0040 | 0x0000_0080) != 0 {
        return TestResult::Fail("pre-multiplied or overlap-only alpha");
    }
    // Reserved bits 3:2 are not ours: the old mask was 0xf, two bits too wide.
    if control & 0x0000_000C != 0x0000_000C {
        return TestResult::Fail("MPCC_CONTROL's reserved bits 3:2 were cleared");
    }
    // The OPP's own output mux must point at this combiner.
    if mpc.io.values[mux as usize] & 0xf != 2 {
        return TestResult::Fail("output mux");
    }
    // Releasing must leave neither the DPP nor the OPP routed.
    if mpc.mpc_release(opp).is_err() {
        return TestResult::Fail("release rejected");
    }
    if mpc.io.values[mux as usize] & 0xf != MPCC_UNSET
        || mpc.io.values[at(MPCC_TOP_SEL) as usize] & 0xf != MPCC_UNSET
        || mpc.io.values[at(MPCC_OPP_ID) as usize] & 0xf != MPCC_UNSET
    {
        return TestResult::Fail("released combiner still routed");
    }
    if mpc.mpc_mux_plane(INSTANCES, 0).is_ok() || mpc.mpc_mux_plane(0, INSTANCES).is_ok() {
        return TestResult::Fail("out-of-range pipe or OPP accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_mpc_binds_one_pipe_with_nothing_beneath_it
);

fn plane_opp_formatter_passes_depth_through() -> TestResult {
    let mut opp = block(0, OPP_LAST_REG);
    // Leave truncation and dithering enabled to prove they get cleared.
    opp.io.values[FMT_BIT_DEPTH_CONTROL as usize] = 1 | 1 << 8 | 1 << 13;
    // And an inherited 4:2:2 formatter state: FMT_SUBSAMPLING_MODE 0x000C0000
    // = 2 plus FMT_CBCR_BIT_REDUCTION_BYPASS 0x00200000. Both must go.
    opp.io.values[FMT_CONTROL as usize] = 0x0008_0000 | 0x0020_0000;
    if opp.opp_program(Encoding::Rgb, 1920, 1080).is_err() {
        return TestResult::Fail("OPP programming rejected");
    }
    if opp.io.values[OPP_PIPE_CONTROL as usize] & 1 == 0 {
        return TestResult::Fail("OPP clock left gated");
    }
    // `opp1_program_fmt`'s RGB arm clears FMT_PIXEL_ENCODING 0x00030000,
    // FMT_SUBSAMPLING_MODE 0x000C0000 and FMT_CBCR_BIT_REDUCTION_BYPASS
    // 0x00200000 — all three, not the one-and-a-half a `0x7 << 16` mask reaches.
    let fmt = opp.io.values[FMT_CONTROL as usize];
    if fmt & (0x0003_0000 | 0x000C_0000 | 0x0020_0000) != 0 {
        return TestResult::Fail("pixel encoding, subsampling or CbCr bypass retained");
    }
    // Truncation and dithering must be off so the plane's depth survives.
    if opp.io.values[FMT_BIT_DEPTH_CONTROL as usize] != 0 {
        return TestResult::Fail("formatter still truncating or dithering");
    }
    // The pattern generator's dimensions put height in the low half.
    if opp.io.values[DPG_DIMENSIONS as usize] != 1080 | 1920 << 16 {
        return TestResult::Fail("pattern generator dimensions");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_opp_formatter_passes_depth_through
);

fn plane_opp_blanks_with_the_pattern_generator() -> TestResult {
    let mut opp = block(3, OPP_LAST_REG);
    let at = |reg: u64| reg + 3 * OPP_STRIDE;
    // Blanking paints black over the whole active area.
    if opp.opp_set_blank(true).is_err() {
        return TestResult::Fail("blank rejected");
    }
    let control = opp.io.values[at(DPG_CONTROL) as usize];
    if control & 1 == 0 {
        return TestResult::Fail("pattern generator not enabled for blank");
    }
    if control >> 4 & 0x7 != DPG_MODE_SOLID {
        return TestResult::Fail("blank pattern mode");
    }
    if opp.io.values[at(DPG_COLOUR_R_CR) as usize] != 0
        || opp.io.values[at(DPG_COLOUR_G_Y) as usize] != 0
        || opp.io.values[at(DPG_COLOUR_B_CB) as usize] != 0
    {
        return TestResult::Fail("blank colour not black");
    }
    // Unblanking disables the generator outright rather than selecting a
    // passthrough pattern, which is how DCN2 onwards returns to video.
    if opp.opp_set_blank(false).is_err() {
        return TestResult::Fail("unblank rejected");
    }
    if opp.io.values[at(DPG_CONTROL) as usize] != 0 {
        return TestResult::Fail("pattern generator still driving the stream");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_opp_blanks_with_the_pattern_generator
);

/// `resource_build_scaling_params`' DCN3.0 result for `src` shown at `dst`
/// on a 1080p stream.
fn scaler(src: (i32, i32, i32, i32), dst: (i32, i32, i32, i32)) -> ScalerData {
    use crate::amdgpu_dcn30_scl::{build, Rect};
    build(
        1920,
        1080,
        (0, 1),
        Rect::new(src.0, src.1, src.2, src.3),
        Rect::new(dst.0, dst.1, dst.2, dst.3),
    )
    .expect("a placement DC accepts")
}

fn plane_dcn30_dscl_scales_like_dpp1_dscl_set_scaler_manual_scale() -> TestResult {
    let mut dpp = block(1, DPP_LAST_REG);
    dpp.profile = Profile::Navi22;
    let at = |reg: u64| (reg + DPP_STRIDE) as usize;
    let mut cache = DsclCache::default();
    // Inherited state the update must replace: autocal on, a stale
    // boundary mode and the coefficient RAM currently on bank 1.
    dpp.io.values[at(DSCL_AUTOCAL)] = 0x3303;
    dpp.io.values[at(DSCL_CONTROL)] = 1;
    dpp.io.values[at(SCL_MODE)] = SCL_COEF_RAM_SELECT_CURRENT | SCL_COEF_RAM_SELECT;
    // 2x up: 960x540 shown on the whole 1080p screen, 4 taps each way,
    // ratio 0.5, initial phase 2.75.
    let up = scaler((0, 0, 960, 540), (0, 0, 1920, 1080));
    if dpp.dscl_set_scaler(&up, &mut cache).is_err() {
        return TestResult::Fail("scaled plane refused");
    }
    let v = |dpp: &Block<Fake>, reg: u64| dpp.io.values[at(reg)];
    // Ratio 0.5 is U3.19 0x40000, shifted into the field's top: 0x800000.
    // Phase 2.75: 0.75 x 2^19 << 5 = 0xc00000 with 2 in the integer field.
    if v(&dpp, DSCL_AUTOCAL) != 0
        || v(&dpp, DSCL_CONTROL) != 0
        || v(&dpp, RECOUT_START) != 0
        || v(&dpp, RECOUT_SIZE) != 1920 | 1080 << 16
        || v(&dpp, MPC_SIZE) != 1920 | 1080 << 16
        || v(&dpp, SCL_MODE) & DSCL_MODE != SCALER_RGB
        || v(&dpp, LB_MEMORY_CTRL) != 0x3f00
        || v(&dpp, LB_DATA_FORMAT) != 0
        || v(&dpp, SCL_HORZ_FILTER_SCALE_RATIO) != 0x80_0000
        || v(&dpp, SCL_VERT_FILTER_SCALE_RATIO_C) != 0x80_0000
        || v(&dpp, SCL_HORZ_FILTER_INIT) != 0x0200_0000 | 0xc0_0000
        || v(&dpp, SCL_VERT_FILTER_INIT_C) != 0x0200_0000 | 0xc0_0000
        || v(&dpp, SCL_TAP_CONTROL) != 0x3333
        || v(&dpp, DSCL_2TAP_CONTROL) & DSCL_2TAP_FIELDS != 0
    {
        return TestResult::Fail("2x upscale registers");
    }
    // Both 4-tap upscale filters went to the RAM, horizontal (type 1) then
    // vertical (type 0): 33 phases x 2 tap pairs each, then the select
    // flipped from the current bank 1 to bank 0.
    let data = DPP_STRIDE + SCL_COEF_RAM_TAP_DATA;
    let select = DPP_STRIDE + SCL_COEF_RAM_TAP_SELECT;
    let selects: Vec<u32> = dpp
        .io
        .writes
        .iter()
        .filter(|(r, _)| *r == select)
        .map(|(_, v)| *v)
        .collect();
    let words: Vec<u32> = dpp
        .io
        .writes
        .iter()
        .filter(|(r, _)| *r == data)
        .map(|(_, v)| *v)
        .collect();
    let table = &crate::amdgpu_dcn401_spl_filters::FILTER_4TAP_64P_UPSCALE;
    let first = u32::from(table[0]) | 1 << 15 | u32::from(table[1]) << 16 | 1 << 31;
    let last = u32::from(table[130]) | 1 << 15 | u32::from(table[131]) << 16 | 1 << 31;
    if selects != vec![1 << 16, 0]
        || words.len() != 2 * 33 * 2
        || words[0] != first
        || words[65] != last
        || words[66] != first
        || v(&dpp, SCL_MODE) & SCL_COEF_RAM_SELECT != 0
        || v(&dpp, SCL_MODE) & SCL_CHROMA_COEF_MODE != 0
    {
        return TestResult::Fail("4-tap upscale coefficients");
    }
    // The same data again writes nothing (the scl_data memcmp).
    let count = dpp.io.writes.len();
    if dpp.dscl_set_scaler(&up, &mut cache).is_err() || dpp.io.writes.len() != count {
        return TestResult::Fail("unchanged scaler reprogrammed");
    }
    // Moved but the same ratio and taps: geometry only, no coefficients.
    let moved = scaler((0, 0, 960, 540), (-100, 0, 1920, 1080));
    if dpp.dscl_set_scaler(&moved, &mut cache).is_err()
        || v(&dpp, RECOUT_SIZE) != 1820 | 1080 << 16
        || v(&dpp, SCL_HORZ_FILTER_INIT) != 0x0400_0000 | 0xc0_0000
        || dpp.io.writes[count..].iter().any(|(r, _)| *r == data)
    {
        return TestResult::Fail("moved plane");
    }
    // 2:1 down picks the 1.83 set (ratio 2 >= 5/3) for both directions.
    let down = scaler((0, 0, 3840, 2160), (0, 0, 1920, 1080));
    let count = dpp.io.writes.len();
    if dpp.dscl_set_scaler(&down, &mut cache).is_err() {
        return TestResult::Fail("downscale refused");
    }
    let table = &crate::amdgpu_dcn401_spl_filters::FILTER_4TAP_64P_183;
    let first = u32::from(table[0]) | 1 << 15 | u32::from(table[1]) << 16 | 1 << 31;
    let words: Vec<u32> = dpp.io.writes[count..]
        .iter()
        .filter(|(r, _)| *r == data)
        .map(|(_, v)| *v)
        .collect();
    if words.len() != 132 || words[0] != first || v(&dpp, SCL_HORZ_FILTER_SCALE_RATIO) != 0x200_0000
    {
        return TestResult::Fail("2:1 downscale coefficients");
    }
    // A positioned, unscaled plane: bypass, the recout at its place, and
    // no ratio or coefficient writes.
    let placed = scaler((0, 0, 55, 55), (912, 513, 55, 55));
    let count = dpp.io.writes.len();
    if dpp.dscl_set_scaler(&placed, &mut cache).is_err()
        || v(&dpp, SCL_MODE) & DSCL_MODE != SCALER_BYPASS
        || v(&dpp, RECOUT_START) != 912 | 513 << 16
        || v(&dpp, RECOUT_SIZE) != 55 | 55 << 16
        || v(&dpp, MPC_SIZE) != 1920 | 1080 << 16
        || dpp.io.writes[count..]
            .iter()
            .any(|(r, _)| *r == data || *r == DPP_STRIDE + SCL_TAP_CONTROL)
    {
        return TestResult::Fail("positioned bypass");
    }
    // DCN3.1.4's DSCL block is not this one.
    let mut other = block(1, DPP_LAST_REG);
    if other.dscl_set_scaler(&up, &mut DsclCache::default()) != Err(Error::Unsupported) {
        return TestResult::Fail("DCN3.1.4 scaler");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_dcn30_dscl_scales_like_dpp1_dscl_set_scaler_manual_scale
);

fn plane_dcn30_mpcc_background_is_black() -> TestResult {
    let mut mpc = block(3, 0x0680);
    mpc.profile = Profile::Navi22;
    // A firmware owner's grey background.
    for reg in [MPCC_BG_R_CR, MPCC_BG_G_Y, MPCC_BG_B_CB] {
        mpc.io.values[(reg + 3 * MPCC_STRIDE) as usize] = 0x800;
    }
    if mpc.mpc_set_bg_color([0; 3]).is_err() {
        return TestResult::Fail("background refused");
    }
    if [MPCC_BG_R_CR, MPCC_BG_G_Y, MPCC_BG_B_CB]
        .iter()
        .any(|reg| mpc.io.values[(reg + 3 * MPCC_STRIDE) as usize] != 0)
    {
        return TestResult::Fail("background not black");
    }
    // 10-bit tg_color into the 12-bit MPC fields.
    if mpc.mpc_set_bg_color([0x3ff, 0x200, 1]).is_err()
        || mpc.io.values[(MPCC_BG_R_CR + 3 * MPCC_STRIDE) as usize] != 0xffc
        || mpc.io.values[(MPCC_BG_G_Y + 3 * MPCC_STRIDE) as usize] != 0x800
        || mpc.io.values[(MPCC_BG_B_CB + 3 * MPCC_STRIDE) as usize] != 4
    {
        return TestResult::Fail("12-bit background");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_dcn30_mpcc_background_is_black
);

/// The overlay tree: the primary muxed alone, the slave MPCC inserted above
/// it (`mpc1_insert_plane` with `insert_above_mpcc` the primary), then
/// removed (`mpc1_remove_mpcc` from the top).
fn plane_mpc_inserts_overlay_above_primary_and_removes_it() -> TestResult {
    let mut mpc = block(0, 0x0680);
    mpc.profile = Profile::Navi22;
    if mpc.mpc_mux_plane(0, 0).is_err() {
        return TestResult::Fail("primary mux refused");
    }
    // The slave MPCC is instance 5; one Fake file holds the whole tree.
    mpc.instance = 5;
    if mpc
        .mpc_insert_plane(5, 0, Some(0), &BlendConfig::opaque())
        .is_err()
    {
        return TestResult::Fail("overlay insert refused");
    }
    let at = |reg: u64| (reg + 5 * MPCC_STRIDE) as usize;
    if mpc.io.values[at(MPCC_TOP_SEL)] & 0xf != 5
        || mpc.io.values[at(MPCC_BOT_SEL)] & 0xf != 0
        || mpc.io.values[at(MPCC_OPP_ID)] & 0xf != 0
        || mpc.io.values[at(MPCC_UPDATE_LOCK_SEL)] & 0xf != 0
    {
        return TestResult::Fail("overlay mux wrong");
    }
    // Blending over the primary: mode 3, global-alpha blend, opaque gains.
    let control = mpc.io.values[at(MPCC_CONTROL)];
    if control & MPCC_MODE != MPCC_BLEND_MODE_TOP_BOT_BLENDING
        || control & MPCC_ALPHA_BLND_MODE != 2 << 4
        || control & MPCC_GLOBAL_ALPHA != 0xff << 16
        || control & MPCC_GLOBAL_GAIN != 0xff << 24
        || control & MPCC_BG_BPC != 4 << 8
        || control & MPCC_BOT_GAIN_MODE != 0
        || mpc.io.values[at(MPCC_TOP_GAIN)] != 0x1f000
        || mpc.io.values[at(MPCC_BOT_GAIN_INSIDE)] != 0x1f000
        || mpc.io.values[at(MPCC_BOT_GAIN_OUTSIDE)] != 0x1f000
    {
        return TestResult::Fail("overlay blend wrong");
    }
    // The mux names the slave; the primary keeps its own top-only mode.
    if mpc.io.values[MPC_OUT_MUX as usize] & 0xf != 5
        || mpc.io.values[MPCC_CONTROL as usize] & MPCC_MODE != MPCC_BLEND_MODE_TOP_LAYER_ONLY
        || mpc.io.values[MPCC_BOT_SEL as usize] & 0xf != 0xf
    {
        return TestResult::Fail("primary disturbed by the insert");
    }
    if mpc.mpc_tree_head(0) != Ok(5) {
        return TestResult::Fail("tree head is not the overlay");
    }
    if mpc.mpc_remove_plane(0).is_err() {
        return TestResult::Fail("overlay remove refused");
    }
    if mpc.io.values[MPC_OUT_MUX as usize] & 0xf != 0
        || mpc.io.values[at(MPCC_TOP_SEL)] & 0xf != 0xf
        || mpc.io.values[at(MPCC_BOT_SEL)] & 0xf != 0xf
        || mpc.io.values[at(MPCC_OPP_ID)] & 0xf != 0xf
        || mpc.io.values[at(MPCC_UPDATE_LOCK_SEL)] & 0xf != 0xf
        || mpc.io.values[MPCC_CONTROL as usize] & MPCC_MODE != MPCC_BLEND_MODE_TOP_LAYER_ONLY
    {
        return TestResult::Fail("overlay remove left the tree wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_mpc_inserts_overlay_above_primary_and_removes_it
);

/// Appending at the bottom (`insert_above_mpcc` NULL): the old bottom
/// starts blending, and removing the bottom leaves it passing through.
fn plane_mpc_appends_below_and_removes_bottom() -> TestResult {
    let mut mpc = block(0, 0x0680);
    mpc.profile = Profile::Navi22;
    if mpc.mpc_mux_plane(0, 0).is_err() {
        return TestResult::Fail("primary mux refused");
    }
    mpc.instance = 5;
    if mpc
        .mpc_insert_plane(5, 0, None, &BlendConfig::opaque())
        .is_err()
    {
        return TestResult::Fail("bottom insert refused");
    }
    let at = |reg: u64| (reg + 5 * MPCC_STRIDE) as usize;
    if mpc.io.values[at(MPCC_BOT_SEL)] & 0xf != 0xf
        || mpc.io.values[at(MPCC_CONTROL)] & MPCC_MODE != MPCC_BLEND_MODE_TOP_LAYER_ONLY
        || mpc.io.values[MPCC_CONTROL as usize] & MPCC_MODE != MPCC_BLEND_MODE_TOP_BOT_BLENDING
        || mpc.io.values[MPC_OUT_MUX as usize] & 0xf != 0
    {
        return TestResult::Fail("bottom append linked wrong");
    }
    if mpc.mpc_remove_plane(0).is_err() {
        return TestResult::Fail("bottom remove refused");
    }
    if mpc.io.values[MPCC_BOT_SEL as usize] & 0xf != 0xf
        || mpc.io.values[MPCC_CONTROL as usize] & MPCC_MODE != MPCC_BLEND_MODE_TOP_LAYER_PASSTHROUGH
        || mpc.io.values[MPC_OUT_MUX as usize] & 0xf != 0
    {
        return TestResult::Fail("bottom remove left the primary blending");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_mpc_appends_below_and_removes_bottom
);

/// A link that cannot be made fails before any register is written: above
/// an MPCC that is not in the tree, above itself, or on an out-of-range
/// pipe.
fn plane_mpc_insert_above_unknown_mpcc_fails_without_writes() -> TestResult {
    let mut mpc = block(0, 0x0680);
    mpc.profile = Profile::Navi22;
    if mpc.mpc_mux_plane(0, 0).is_err() {
        return TestResult::Fail("primary mux refused");
    }
    mpc.instance = 5;
    let count = mpc.io.writes.len();
    if mpc.mpc_insert_plane(5, 0, Some(3), &BlendConfig::opaque()) != Err(Error::Invalid)
        || mpc.mpc_insert_plane(5, 0, Some(5), &BlendConfig::opaque()) != Err(Error::Invalid)
        || mpc.mpc_insert_plane(6, 0, None, &BlendConfig::opaque()) != Err(Error::Invalid)
        || mpc.mpc_insert_plane(5, 6, None, &BlendConfig::opaque()) != Err(Error::Invalid)
        || mpc.io.writes.len() != count
    {
        return TestResult::Fail("bad insert wrote registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-plane",
    plane_mpc_insert_above_unknown_mpcc_fails_without_writes
);

/// `mpc2_update_blending`'s field composition for the three alpha modes.
fn plane_mpc_blend_modes() -> TestResult {
    let mut mpc = block(0, 0x0680);
    mpc.profile = Profile::Navi22;
    // Opaque: global-alpha mode, opaque alpha and gain, bpc 4.
    if mpc.mpc_set_blend(0, &BlendConfig::opaque()).is_err()
        || mpc.io.values[MPCC_CONTROL as usize] != 0xffff_0420
        || mpc.io.values[MPCC_TOP_GAIN as usize] != 0x1f000
    {
        return TestResult::Fail("opaque blend wrong");
    }
    // Per-pixel alpha, pre-multiplied: mode 0, multiplied bit set.
    if mpc
        .mpc_set_blend(0, &BlendConfig::per_pixel_alpha(true))
        .is_err()
        || mpc.io.values[MPCC_CONTROL as usize] != 0xffff_0440
    {
        return TestResult::Fail("per-pixel blend wrong");
    }
    // Per-pixel alpha with a plane alpha: combined mode, gain in both fields.
    if mpc
        .mpc_set_blend(0, &BlendConfig::per_pixel_alpha_with_gain(false, 0x80))
        .is_err()
        || mpc.io.values[MPCC_CONTROL as usize] != 0x8080_0410
    {
        return TestResult::Fail("combined-gain blend wrong");
    }
    // Out-of-field values are refused, not truncated.
    let bad_bpc = BlendConfig {
        background_color_bpc: 8,
        ..BlendConfig::opaque()
    };
    let bad_gain = BlendConfig {
        bottom_gain_mode: 2,
        ..BlendConfig::opaque()
    };
    if mpc.mpc_set_blend(0, &bad_bpc) != Err(Error::Invalid)
        || mpc.mpc_set_blend(0, &bad_gain) != Err(Error::Invalid)
        || mpc.mpc_set_blend(6, &BlendConfig::opaque()) != Err(Error::Invalid)
    {
        return TestResult::Fail("bad blend accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn-plane", plane_mpc_blend_modes);
