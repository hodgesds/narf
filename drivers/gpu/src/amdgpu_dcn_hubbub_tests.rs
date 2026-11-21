use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// A DCN register file. DETn_SIZE_CURRENT follows DETn_SIZE on write unless
/// `stuck_det`, COMPBUF_SIZE_CURRENT follows COMPBUF_SIZE, and CONFIG_ERROR
/// is raised on demand.
struct Fake {
    values: Vec<u32>,
    writes: Vec<(u64, u32)>,
    profile: Profile,
    stuck_det: bool,
    config_error: bool,
}
impl Fake {
    fn new(profile: Profile) -> Self {
        Self {
            values: vec![0; LAST_REG as usize + 1],
            writes: Vec::new(),
            profile,
            stuck_det: false,
            config_error: false,
        }
    }
    fn shift(&self) -> u64 {
        if self.profile == Profile::Dcn315 {
            DCN315_CRB_SHIFT
        } else {
            0
        }
    }
}
impl Io for Fake {
    fn wait_poll_limit(&self) -> Option<u32> {
        Some(16)
    }
    fn read(&mut self, reg: u64) -> u32 {
        self.values[reg as usize]
    }
    fn write(&mut self, reg: u64, value: u32) {
        self.writes.push((reg, value));
        let det = DET0_CTRL + self.shift();
        let compbuf = COMPBUF_CTRL + self.shift();
        let mut value = value;
        if (det..det + 4).contains(&reg) && !self.stuck_det {
            value = value & !DET_SIZE_CURRENT | (value & DET_SIZE) << 8;
        }
        if reg == compbuf {
            value = value & !COMPBUF_SIZE_CURRENT | (value & COMPBUF_SIZE) << 8;
            if self.config_error {
                value |= CONFIG_ERROR;
            }
        }
        self.values[reg as usize] = value;
    }
}
fn engine(profile: Profile) -> Engine<Fake> {
    Engine {
        io: Fake::new(profile),
        authority: Cap::bootstrap(),
        profile,
    }
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

/// `populate_dml_pipes_from_context` on both DCNs: alone, a surface up to
/// 5120 wide gets 192 KB and unbounded requesting (DCN 3.1.5 also needs the
/// pixel clock below DPM DISPCLK / 1.0038); beside live pipes, DCN 3.1.4 gives
/// 384 KB and DCN 3.1.5 an even split of 896 KB capped at 384. The compressed
/// buffer is what the DETs leave of the CRB (1792 / 1024 KB), shrunk to
/// 64 KB first on DCN 3.1.5.
fn hubbub_det_plan_follows_the_populate_policy() -> TestResult {
    let cases = [
        // (profile, live others' DET segments, width, pixel kHz, expected)
        (
            Profile::Dcn314,
            &[][..],
            1920,
            148_500,
            Some((192, 1600, 1600, true)),
        ),
        (
            Profile::Dcn315,
            &[][..],
            1920,
            148_500,
            Some((192, 832, 64, true)),
        ),
        (
            Profile::Dcn314,
            &[][..],
            6000,
            148_500,
            Some((384, 1408, 1408, false)),
        ),
        (
            Profile::Dcn315,
            &[][..],
            6000,
            148_500,
            Some((384, 640, 64, false)),
        ),
        // At the non-ODM ceiling (1.2 GHz / 1.0038) DCN 3.1.5 stays bounded.
        (
            Profile::Dcn315,
            &[][..],
            1920,
            1_196_000,
            Some((384, 640, 64, false)),
        ),
        (
            Profile::Dcn315,
            &[][..],
            1920,
            1_195_000,
            Some((192, 832, 64, true)),
        ),
        // Beside a live boot pipe holding 384 KB.
        (
            Profile::Dcn314,
            &[6][..],
            1920,
            148_500,
            Some((384, 1024, 1024, false)),
        ),
        (
            Profile::Dcn315,
            &[6][..],
            1920,
            148_500,
            Some((384, 256, 64, false)),
        ),
        // Three live 384 KB pipes leave DCN 3.1.5 no room: refused.
        (Profile::Dcn315, &[6, 6, 6][..], 1920, 148_500, None),
    ];
    for (profile, others, width, pixel, want) in cases {
        let got = plan(profile, others, width, pixel, 1_200_000)
            .ok()
            .map(|p| {
                (
                    p.det_kbytes,
                    p.compbuf_kbytes,
                    p.prepare_compbuf_kbytes,
                    p.unbounded,
                )
            });
        if got != want {
            return TestResult::Fail("DET plan is not populate_dml_pipes_from_context's");
        }
    }
    if plan(Profile::Navi22, &[], 1920, 148_500, 1_200_000) != Err(Error::Unsupported) {
        return TestResult::Fail("DCN30 has no CRB");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-hubbub",
    hubbub_det_plan_follows_the_populate_policy
);

/// `dcn31_program_det_size` / `wait_for_det_apply` / `program_compbuf_size`:
/// DET0..3 and COMPBUF at 0x4bb/0x4ba (DCN 3.1.4) and 0x4cc/0x4cb (DCN 3.1.5,
/// `dcn_3_1_5_offset.h`), in 64 KB segments. A split that overflows the CRB
/// is refused, growing the compressed buffer waits for every DET, shrinking
/// is the only change allowed before that, and CONFIG_ERROR is an error.
fn hubbub_det_and_compbuf_keep_the_crb_consistent() -> TestResult {
    for (profile, det0, compbuf, crb) in [
        (Profile::Dcn314, 0x4bb_u64, 0x4ba_u64, 28u32),
        (Profile::Dcn315, 0x4cc, 0x4cb, 16),
    ] {
        let mut hub = engine(profile);
        // Boot state: compbuf holds everything.
        hub.io.write(compbuf, crb);
        if hub.program_det_size(1, 192) != Err(Error::Invalid) {
            return TestResult::Fail("DET taken from a full compressed buffer");
        }
        // Shrinking is allowed before the DETs change; growing is not.
        if run(hub.program_compbuf_size(64 * (crb - 3), false)).is_err()
            || hub.io.values[compbuf as usize] & COMPBUF_SIZE != crb - 3
        {
            return TestResult::Fail("compressed buffer did not shrink");
        }
        if run(hub.program_compbuf_size(64 * crb, false)).is_err()
            || hub.io.values[compbuf as usize] & COMPBUF_SIZE != crb - 3
        {
            return TestResult::Fail("compressed buffer grew before it was safe");
        }
        if hub.program_det_size(1, 192).is_err()
            || hub.io.values[(det0 + 1) as usize] & DET_SIZE != 3
            || run(hub.wait_for_det_apply(1)).is_err()
        {
            return TestResult::Fail("DET1 to three segments");
        }
        // Growing back past the DET is refused; up to it is allowed.
        if run(hub.program_compbuf_size(64 * crb, true)) != Err(Error::Invalid)
            || run(hub.program_compbuf_size(64 * (crb - 3), true)).is_err()
        {
            return TestResult::Fail("compressed buffer growth against the CRB");
        }
        // A DET that never applies is a timeout, and blocks growth.
        hub.io.stuck_det = true;
        hub.program_det_size(1, 128).unwrap();
        if run(hub.wait_for_det_apply(1)) != Err(Error::Timeout) {
            return TestResult::Fail("unapplied DET reported as applied");
        }
        hub.io.stuck_det = false;
        hub.io.write(det0 + 1, 2);
        // CONFIG_ERROR after the write is a refused split.
        hub.io.config_error = true;
        if run(hub.program_compbuf_size(64 * (crb - 4), false)) != Err(Error::Invalid) {
            return TestResult::Fail("CONFIG_ERROR ignored");
        }
        if hub.program_det_size(4, 64) != Err(Error::Invalid)
            || hub.program_det_size(0, 8 * 64) != Err(Error::Invalid)
        {
            return TestResult::Fail("DET beyond the pipes or its field");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-hubbub",
    hubbub_det_and_compbuf_keep_the_crb_consistent
);

fn watermarks() -> Watermarks {
    Watermarks {
        urgent_ns: 5_000,
        urgent_latency_ns: 4_000,
        sr_exit_ns: 12_000,
        sr_enter_plus_exit_ns: 15_000,
        sr_exit_z8_ns: 50_000,
        sr_enter_plus_exit_z8_ns: 60_000,
        pstate_change_ns: 135_000,
        frac_urg_bw_nom: 300,
        frac_urg_bw_flip: 0,
    }
}

/// `hubbub31_program_watermarks` at a 100 MHz DCHUB reference: every value
/// is `ns * refclk_mhz / 1000` cycles, written to all four sets (A at 0x4fd..,
/// B 0x506.., D 0x518..). Raise keeps a larger value the hardware already
/// holds; Exact writes the computed one and allows self-refresh. A value its
/// field cannot hold refuses the whole set before any write.
fn hubbub_watermarks_raise_or_set_all_four_sets() -> TestResult {
    let mut hub = engine(Profile::Dcn314);
    // The boot firmware left a larger urgency watermark in set C and forced
    // self-refresh off.
    hub.io.values[(URGENCY + 2 * SET_STRIDE) as usize] = 900;
    hub.io.values[DRAM_STATE_CNTL as usize] = 0x2;
    if hub
        .program_watermarks(&watermarks(), 100, Mode::Raise)
        .is_err()
    {
        return TestResult::Fail("raise rejected");
    }
    let want = [
        (URGENCY, 500u32),
        (TRIP_TO_MEMORY, 400),
        (SR_ENTER, 1_500),
        (SR_EXIT, 1_200),
        (SR_ENTER_Z8, 6_000),
        (SR_EXIT_Z8, 5_000),
        (DRAM_CLK_CHANGE, 13_500),
        (FRAC_URG_BW_NOM, 300),
        (FRAC_URG_BW_FLIP, 0),
    ];
    for set in 0..SETS {
        for (reg, value) in want {
            let expected = if reg == URGENCY && set == 2 {
                900
            } else {
                value
            };
            if hub.io.values[(reg + set * SET_STRIDE) as usize] != expected {
                return TestResult::Fail("raised watermark set");
            }
        }
    }
    if hub.io.values[DRAM_STATE_CNTL as usize] != 0x2 {
        return TestResult::Fail("raise touched self-refresh control");
    }
    if (URGENCY + 3 * SET_STRIDE, FRAC_URG_BW_NOM + 3 * SET_STRIDE) != (0x518, 0x51f) {
        return TestResult::Fail("set D offsets");
    }
    // Exact lowers set C to the computed value and allows self-refresh.
    if hub
        .program_watermarks(&watermarks(), 100, Mode::Exact)
        .is_err()
        || hub.io.values[(URGENCY + 2 * SET_STRIDE) as usize] != 500
        || hub.io.values[DRAM_STATE_CNTL as usize] & SELF_REFRESH_FORCE != 0
    {
        return TestResult::Fail("exact watermarks");
    }
    // 0x3fff cycles is the urgency field's limit: 164 us at 100 MHz is not.
    hub.io.writes.clear();
    let too_long = Watermarks {
        urgent_ns: 164_000,
        ..watermarks()
    };
    if hub.program_watermarks(&too_long, 100, Mode::Exact) != Err(Error::Invalid)
        || !hub.io.writes.is_empty()
    {
        return TestResult::Fail("an overflowing watermark was written or clamped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-hubbub",
    hubbub_watermarks_raise_or_set_all_four_sets
);

/// Live pipes are those whose OTG master enable is set (0x1b41 + n * 0x80),
/// with the DET segments they currently hold; and the mode math's microseconds
/// become Linux's truncated nanoseconds, with DCN 3.1.4's Z8 enter watermark
/// at its 2100 us minimum residency.
fn hubbub_finds_live_pipes_and_converts_the_mode_math() -> TestResult {
    let mut hub = engine(Profile::Dcn315);
    hub.io.values[(OTG_CONTROL + 2 * OTG_STRIDE) as usize] = OTG_MASTER_EN;
    hub.io.write(DET0_CTRL + DCN315_CRB_SHIFT + 2, 6);
    match hub.live_others(1) {
        Ok(others) if others == [6] => {}
        _ => return TestResult::Fail("live pipe 2 with six segments"),
    }
    if hub.live_others(2).map(|o| o.is_empty()) != Ok(true) {
        return TestResult::Fail("a pipe is not its own neighbour");
    }
    use crate::amdgpu_dml::Fx;
    let dml = crate::amdgpu_dml::Watermarks {
        urgent_us: Fx::ratio(48_765, 10_000),
        pstate_change_us: Fx::ratio(1_338_765, 10_000),
        stutter_exit_us: Fx::ratio(123, 10),
        stutter_enter_plus_exit_us: Fx::ratio(153, 10),
        z8_stutter_exit_us: Fx::int(51),
        z8_stutter_enter_plus_exit_us: Fx::int(52),
        urgent_latency_us: Fx::int(4),
        extra_latency_us: Fx::ZERO,
        return_bandwidth_bytes_per_us: Fx::int(1),
        pstate_latency_us: Fx::ZERO,
        sr_exit_us: Fx::ZERO,
        sr_enter_plus_exit_us: Fx::ZERO,
    };
    let raphael = Watermarks::from_dml(Profile::Dcn315, &dml, 321);
    if (
        raphael.urgent_ns,
        raphael.pstate_change_ns,
        raphael.urgent_latency_ns,
    ) != (4_876, 133_876, 4_000)
        || raphael.sr_enter_plus_exit_z8_ns != 52_000
        || (raphael.frac_urg_bw_nom, raphael.frac_urg_bw_flip) != (321, 0)
    {
        return TestResult::Fail("DML to nanoseconds");
    }
    if Watermarks::from_dml(Profile::Dcn314, &dml, 0).sr_enter_plus_exit_z8_ns != 2_100_000 {
        return TestResult::Fail("DCN 3.1.4 Z8 minimum residency");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn-hubbub",
    hubbub_finds_live_pipes_and_converts_the_mode_math
);
