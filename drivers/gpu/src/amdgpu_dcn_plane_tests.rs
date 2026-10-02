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
    }
}

fn plane_dpp_bypasses_the_scaler_for_an_unscaled_plane() -> TestResult {
    // Drive the same register writes the public Dpp performs, on instance 1.
    let mut dpp = block(1, DPP_LAST_REG);
    let at = |reg: u64| reg + DPP_STRIDE;
    let (width, height) = (1920u32, 1080u32);
    if dpp.update(at(DPP_CONTROL), 1 << 4, 1 << 4).is_err()
        || dpp
            .update(
                at(CNVC_SURFACE_PIXEL_FORMAT),
                0x7f,
                cnvc_format(Format::Rgb32),
            )
            .is_err()
        || dpp.update(at(SCL_MODE), 0x3, SCALER_BYPASS).is_err()
        || dpp.set(at(RECOUT_START), 0).is_err()
        || dpp.set(at(RECOUT_SIZE), width | height << 16).is_err()
        || dpp.set(at(MPC_SIZE), width | height << 16).is_err()
    {
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
    // Bypass, not unity taps.
    if dpp.io.values[at(SCL_MODE) as usize] & 3 != SCALER_BYPASS {
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

fn plane_mpc_binds_one_pipe_with_nothing_beneath_it() -> TestResult {
    let mut mpc = block(2, MPC_LAST_REG);
    let at = |reg: u64| reg + 2 * MPCC_STRIDE;
    // Leave a stale bottom select behind to prove it gets cleared.
    mpc.io.values[at(MPCC_BOT_SEL) as usize] = 1;
    let (dpp, opp) = (3u32, 1u8);
    let mux = MPC_OUT_MUX + opp as u64 * MPC_OUT_STRIDE;
    if mpc.mpc_mux_plane(dpp as u8, opp).is_err() {
        return TestResult::Fail("MPC programming rejected");
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
    // Opaque passthrough: no blend mode, no alpha, no background depth.
    if mpc.io.values[at(MPCC_CONTROL) as usize] & (0xf | 0x3 << 4 | 0x3 << 8) != 0 {
        return TestResult::Fail("blend mode");
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
    if opp.opp_program(Encoding::Rgb, 1920, 1080).is_err() {
        return TestResult::Fail("OPP programming rejected");
    }
    if opp.io.values[OPP_PIPE_CONTROL as usize] & 1 == 0 {
        return TestResult::Fail("OPP clock left gated");
    }
    if opp.io.values[FMT_CONTROL as usize] >> 16 & 0x7 != 0 {
        return TestResult::Fail("pixel encoding");
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
