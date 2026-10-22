use super::*;
#[path = "amdgpu_dcn401_mpc_tests.rs"]
mod mpc;

fn d(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x16b) * 4
}
// Golden native unity RGB register values; offsets/masks are independently
// asserted against AMD's headers by tests/dcn401_dpp.c.
const RGB: [(u64, u32); 31] = [
    (0xcd0, 0x24000101),
    (0xccf, 8),
    (0xcd7, 0),
    (0xcde, 0),
    (0xcee, 0),
    (0xced, 0),
    (0xcd1, 0),
    (0xcd2, 0),
    (0xcd3, 0),
    (0xcd4, 0x1f000),
    (0xcd5, 0x1f000),
    (0xcd6, 0x1f000),
    (0xd67, 0),
    (0xd68, 0),
    (0xd77, 0),
    (0xdc5, 0),
    (0xd75, 0),
    (0xd76, 0),
    (0xdc1, 0x1f000),
    (0xcf6, 0),
    (0xd19, 0),
    (0xd0a, 0),
    (0xd1e, 0),
    (0xd1f, 0x30041),
    (0xd20, 0x30041),
    (0xd08, 0),
    (0xd21, 0),
    (0xd22, 0x3f01),
    (0xd28, 0),
    (0xd29, 0),
    (0xd55, 0),
];
struct DppIo {
    memory: MemoryIo,
    pipe: u8,
    waking: u8,
    delay: [u8; 2],
    stall: u8,
}
impl Engine<DppIo> {
    fn fake(&mut self) -> &mut Fake {
        self.io.fake()
    }
}
impl DppIo {
    fn fake(&mut self) -> &mut Fake {
        &mut self.memory.surface.inner
    }
    fn accessible(&self, at: u64) {
        for p in 0..4 {
            if (d(p, 0xcc5)..d(p, 0xcc5 + 0x16b)).contains(&at) {
                assert_eq!(
                    self.memory.surface.inner.forbidden_hubps & (1 << p),
                    0,
                    "access to an unrelated powered-off pipe"
                );
            }
        }
    }
}
impl Io for DppIo {
    fn wait_poll_limit(&self) -> Option<u32> {
        // Acknowledgements advance on reads, not elapsed time. Retain the
        // delayed success, stuck acknowledgement and cancellation cases
        // without letting host scheduling turn fault injection into timeout.
        Some(8)
    }
    fn read(&mut self, at: u64) -> u32 {
        self.accessible(at);
        for (index, (r, mask)) in [(0xd25, 3), (0xd62, 0x30)].into_iter().enumerate() {
            if at == d(self.pipe, r)
                && self.waking & (1 << index) != 0
                && self.stall & (1 << index) == 0
            {
                if self.delay[index] == 0 {
                    *self.fake().regs.entry(at).or_default() &= !mask;
                    self.waking &= !(1 << index);
                } else {
                    self.delay[index] -= 1;
                }
            }
        }
        self.memory.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.accessible(at);
        let p = self.pipe;
        if at != d(p, 0xcc5) {
            assert_eq!(self.fake().regs[&d(p, 0xcc5)] & 0x10, 0x10);
        }
        assert_eq!(self.fake().regs[&h(p, 0x5f4)] & 0x1007, 3);
        assert_eq!(self.fake().regs[&h(p, 0x5f5)] & 1, 0);
        self.memory.write(at, value);
        let f = self.fake();
        if f.reject == Some(f.writes.len()) {
            return;
        }
        if at == d(p, 0xd24) {
            self.waking |= 1;
            *self.fake().regs.entry(d(p, 0xd25)).or_default() |= 3;
        }
        if at == d(p, 0xd62) {
            self.waking |= 2;
            *self.fake().regs.entry(d(p, 0xd62)).or_default() |= 0x30;
        }
        // Stopped timing does not latch CNVC/scaler/CM double buffers.
        for (written, pending, mask) in [
            (0xcd0, 0xcd0, 0x100000),
            (0xd1f, 0xd18, 1),
            (0xd67, 0xd67, 0x100),
        ] {
            if at == d(p, written) {
                *self.fake().regs.entry(d(p, pending)).or_default() |= mask;
            }
        }
    }
}
fn ready(p: u8) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    ready_depth(p, ColorDepth::Bpc8)
}
/// The small default plane mode: a 65x3 surface on a 65x3-active timing.
fn small(p: u8) -> Mode {
    let mut t = request(p);
    t.timing.h_active = 65;
    t.timing.v_active = 3;
    Mode {
        surface: req(p),
        bytes: 8192,
        timing: t,
        clock: clock(t),
    }
}
fn ready_depth(
    p: u8,
    depth: ColorDepth,
) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    ready_with(p, depth, small(p))
}
fn ready_with(
    p: u8,
    depth: ColorDepth,
    mode: Mode,
) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    ready_range(p, depth, mode, false)
}
/// `ready_with` for a full- or limited-range blank request.
fn ready_range(
    p: u8,
    depth: ColorDepth,
    mode: Mode,
    limited: bool,
) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    ready_range_pipes(p, 0, depth, mode, limited)
}
/// A powered, stopped DPP's inherited state, every field off its target.
fn seed_dpp(f: &mut Fake, p: u8) {
    for (r, value) in RGB {
        f.regs.insert(d(p, r), 0x80000000 | (value ^ 1));
    }
    f.regs.insert(d(p, 0xcc5), 0x80050100);
    f.regs.insert(d(p, 0xd24), 3);
    f.regs.insert(d(p, 0xd62), 3);
}
/// `ready_range`, the pipes in `extra` ready for overlay planes too.
fn ready_range_pipes(
    p: u8,
    extra: u8,
    depth: ColorDepth,
    mode: Mode,
    limited: bool,
) -> (Vec<u32>, Pool, Engine<DppIo>, Surfaces, dccg::Applied) {
    let (backing, pool, mut e, mut surfaces) = staged_pipes(p, extra, mode.surface, mode.bytes);
    run(surfaces.prepare_memory(&mut e, p, || Ok(config()))).unwrap();
    let (t, clock) = (mode.timing, mode.clock);
    run(e.prepare(t, clock)).unwrap();
    run(e.prepare_blank(
        BlankRequest {
            pipe: p,
            depth,
            limited,
            encoding: mode.timing.encoding,
            colorspace: crate::amdgpu_dcn401_otg::BlankRequest::default_colorspace(
                limited,
                mode.timing.encoding.is_420(),
            ),
        },
        clock,
    ))
    .unwrap();
    for q in (0..4u8).filter(|&q| q == p || extra & 1 << q != 0) {
        seed_dpp(&mut e.io.surface.inner, q);
    }
    e.io.surface.inner.writes.clear();
    let engine = Engine {
        io: DppIo {
            memory: e.io,
            pipe: p,
            waking: 0,
            delay: [1, 2],
            stall: 0,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    (backing, pool, engine, surfaces, clock)
}
fn dcn401_dpp_stages_native_rgb_and_unity_scaling_on_all_pipes() -> TestResult {
    for p in 0..4 {
        let (_backing, pool, mut e, mut surfaces, clock) = ready(p);
        let mut checks = 0;
        let a = run(surfaces.prepare_dpp(&mut e, p, || {
            checks += 1;
            Ok((clock, config()))
        }))
        .unwrap();
        assert_eq!(checks, 2);
        assert_eq!(a.pending, 7);
        assert_eq!(a.line_buffer_config, 1);
        assert_eq!(e.status.dpps[p as usize], Some(a));
        assert_eq!(e.status.state, State::DppPrepared);
        assert_eq!(e.fake().regs[&d(p, 0xcc5)], 0x80050100);
        for (r, value) in RGB {
            let pending = match r {
                0xcd0 => 0x100000,
                0xd67 => 0x100,
                _ => 0,
            };
            assert_eq!(
                e.fake().regs[&d(p, r)],
                (if r == 0xd76 { 0 } else { 0x80000000 }) | value | pending
            );
        }
        // The CNVC/CM, DSCL and coefficient writes, and hwseq's cursor
        // matrix bypass after dpp_setup.
        assert_eq!(e.fake().writes.len(), 36);
        assert_eq!(e.fake().regs[&d(p, 0xcf6)] & 0x13, 0);
        assert_eq!(e.fake().regs[&h(p, 0x613)] & 0x100, 0x100);
        assert_eq!(
            e.fake().regs[&(MPC_BASE + (0x2f2 + u64::from(p) * 4) * 4)] & 0xf,
            0xf
        );
        assert_eq!(
            run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))),
            Err(Error::Busy)
        );
        drop(surfaces);
        assert_eq!(pool.available(), 4096);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_stages_native_rgb_and_unity_scaling_on_all_pipes
);

/// dpp401_dpp_setup's CNVC format and ALPHA_EN, and the line buffer's
/// alpha (lb_params.alpha_en = per_pixel_alpha), for every format; the
/// rest of the unity RGB state is the same for all of them.
fn dcn401_dpp_programs_every_format_as_linux() -> TestResult {
    for (format, _, _, _, _, cnvc, alpha_en, alpha) in LINUX_FORMATS {
        let p = 2;
        let mode = Mode {
            surface: SurfaceRequest { format, ..req(p) },
            ..small(p)
        };
        let (_backing, pool, mut e, mut surfaces, clock) = ready_with(p, ColorDepth::Bpc8, mode);
        let a = run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))).unwrap();
        assert_eq!(a.line_buffer_config, 1);
        for (r, value) in RGB {
            let value = match r {
                0xcd0 => 0x24000001 | alpha_en << 8 | 0x100000,
                0xccf => cnvc,
                0xd21 => u32::from(alpha) << 4,
                0xd67 => value | 0x100,
                _ => value,
            };
            assert_eq!(
                e.fake().regs[&d(p, r)],
                (if r == 0xd76 { 0 } else { 0x80000000 }) | value
            );
        }
        drop(surfaces);
        assert_eq!(pool.available(), 4096);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_programs_every_format_as_linux
);

fn dcn401_dpp_preflight_rejects_stale_owners_geometry_and_pending_updates() -> TestResult {
    let (_backing, _pool, mut e, mut surfaces, clock) = ready(0);
    for p in [1, 4, 255] {
        assert_eq!(
            run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))),
            Err(Error::Invalid)
        );
    }
    for (c, memory) in [
        (
            dccg::Applied {
                dpp_phase: clock.dpp_phase ^ 1,
                ..clock
            },
            config(),
        ),
        (
            clock,
            DisplayContext {
                root: config().root + 4096,
                ..config()
            },
        ),
    ] {
        assert_eq!(
            run(surfaces.prepare_dpp(&mut e, 0, || Ok((c, memory)))),
            Err(Error::Invalid)
        );
    }
    let saved = e.status.blanks[0].unwrap();
    let mut mismatched = saved;
    mismatched.timing.request.timing.h_active += 1;
    e.status.blanks[0] = Some(mismatched);
    e.status.pipes[0] = Some(mismatched.timing);
    assert_eq!(
        run(surfaces.prepare_dpp(&mut e, 0, || Ok((clock, config())))),
        Err(Error::Invalid)
    );
    e.status.blanks[0] = Some(saved);
    e.status.pipes[0] = Some(saved.timing);
    for (at, value) in [
        (d(0, 0xcd0), 0x100000),
        (d(0, 0xd18), 1),
        (d(0, 0xd67), 0x100),
        (d(0, 0xcc5), 0x10),
        (d(0, 0xcc5), 0x10000000),
        (d(0, 0xcc6), 0x1111),
        (d(0, 0xcf1), 1),
        (d(0, 0xcf1), 0x10000),
        (d(0, 0xd24), 0x30),
        (d(0, 0xd24), 0x10000000),
        (h(0, 0x60a), 0),
        (h(0, 0x5f4), 1),
        (BASE + 0x477 * 4, 0),
        (BASE + 0x1b2a * 4, 0),
        (BASE + 0x1840 * 4, 0x100),
        (MPC_BASE + 0x2f2 * 4, 0),
    ] {
        let old = e.fake().regs.insert(at, value);
        assert!(run(surfaces.prepare_dpp(&mut e, 0, || Ok((clock, config())))).is_err());
        e.fake().regs.insert(at, old.unwrap_or(0));
    }
    assert!(e.fake().writes.is_empty());
    assert_eq!(e.status.state, State::BlankPrepared);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_preflight_rejects_stale_owners_geometry_and_pending_updates
);

fn dcn401_dpp_lost_writes_revocation_and_device_loss_quarantine() -> TestResult {
    for mode in 0..3 {
        for n in 1..=36 {
            let (_backing, pool, mut e, mut surfaces, clock) = ready(2);
            let authority = e.authority;
            match mode {
                0 => e.fake().reject = Some(n),
                1 => e.fake().revoke = Some((n, authority)),
                _ => e.fake().gone = Some(n),
            }
            let error = run(surfaces.prepare_dpp(&mut e, 2, || Ok((clock, config())))).unwrap_err();
            assert_eq!(e.status.state, State::Failed(error));
            assert!(matches!(
                error,
                Error::Readback(_) | Error::Revoked | Error::DeviceGone
            ));
            assert_eq!(e.status.dpps, [None; 4]);
            let count = e.fake().writes.len();
            assert_eq!(
                run(surfaces.prepare_dpp(&mut e, 2, || Ok((clock, config())))),
                Err(Error::Busy)
            );
            assert_eq!(e.fake().writes.len(), count);
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_lost_writes_revocation_and_device_loss_quarantine
);

fn dcn401_dpp_ram_wake_timeout_cancellation_and_late_changes_fail_closed() -> TestResult {
    for stage in 0..2 {
        for cancel in [false, true] {
            let (_backing, pool, mut e, mut surfaces, clock) = ready(1);
            e.io.stall = 1 << stage;
            e.io.delay = [0; 2];
            if cancel {
                let mut f =
                    core::pin::pin!(surfaces.prepare_dpp(&mut e, 1, || Ok((clock, config()))));
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            } else {
                let at = d(1, if stage == 0 { 0xd25 } else { 0xd62 });
                assert_eq!(
                    run(surfaces.prepare_dpp(&mut e, 1, || Ok((clock, config())))),
                    Err(Error::Timeout(at))
                );
            }
            assert!(matches!(
                e.status.state,
                State::PreparingDpp(1) | State::Failed(Error::Timeout(_))
            ));
            assert_eq!(e.status.dpps, [None; 4]);
            // The scaler LUT wakes first; the iSHARP LUT inside the DSCL
            // programming, after the 20 CNVC/CM (the cursor matrix's
            // included) and 11 DSCL writes.
            assert_eq!(e.fake().writes.len(), [2, 33][stage]);
            assert_eq!(e.fake().regs[&d(1, 0xcc5)] & 0x10, 0x10); // no speculative rollback
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    for (n, at, value) in [
        (2, BASE + 0x1b43 * 4, 1),
        (3, d(0, 0xcc6), 1),
        (35, d(0, 0xcd4), 0),
        (35, h(0, 0x60a), 0),
        (35, BASE + 0x477 * 4, 0),
    ] {
        let (_backing, _pool, mut e, mut surfaces, clock) = ready(0);
        e.fake().after_write = Some((n, at, value));
        assert!(run(surfaces.prepare_dpp(&mut e, 0, || Ok((clock, config())))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.status.dpps, [None; 4]);
    }
    let (_backing, _pool, mut e, mut surfaces, clock) = ready(3);
    let mut checks = 0;
    assert_eq!(
        run(surfaces.prepare_dpp(&mut e, 3, || {
            checks += 1;
            if checks == 1 {
                Ok((clock, config()))
            } else {
                Err(Error::PipeClocks(dccg::Error::Revoked))
            }
        })),
        Err(Error::PipeClocks(dccg::Error::Revoked))
    );
    assert_eq!(e.status.dpps, [None; 4]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_ram_wake_timeout_cancellation_and_late_changes_fail_closed
);

/// tests/dcn401_yuv/vectors.txt: Linux's fill_plane_color_attributes,
/// dpp401_dpp_setup and hubp2_program_pixel_format for every scanned format
/// and COLOR_ENCODING / COLOR_RANGE pair; the post CSC words of a YCbCr
/// plane are its dpp_input_csc_matrix entry as
/// cm_helper_program_color_matrices packs it.
fn dcn401_dpp_input_conversion_matches_linux_vectors() -> TestResult {
    use crate::amdgpu_dcn401_otg::YuvColor;
    use core::fmt::Write;
    const VECTORS: &str = include_str!("../tests/dcn401_yuv/vectors.txt");
    let mut n = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let (input, want) = line.split_once(" = ").unwrap();
        let mut f = input.split_whitespace();
        let code = f.next().unwrap().as_bytes();
        let fourcc = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        let enc: u8 = f.next().unwrap().parse().unwrap();
        let range: u8 = f.next().unwrap().parse().unwrap();
        let Some(format) = SurfaceFormat::from_fourcc(fourcc) else {
            // Linux advertises RA24 but fill_dc_plane_info_and_addr rejects
            // it. The native list likewise must not promise this format.
            if fourcc != u32::from_le_bytes(*b"RA24") || want != "-" {
                return TestResult::Fail("unsupported plane differs from Linux");
            }
            n += 1;
            continue;
        };
        // fill_plane_color_attributes ignores the properties for RGB.
        let color = if format.is_video() {
            YuvColor::from_props(enc, range)
        } else {
            Some(YuvColor::default())
        };
        let mut got = alloc::string::String::new();
        match color {
            None => got.push('-'),
            Some(color) => {
                let crossbar = format.crossbar();
                let csc = crate::amdgpu_dcn401_otg::fetch::post_csc_words(format, color);
                let _ = write!(
                    got,
                    "{} {} {} {} {} {}",
                    format.hubp_pixel_format(),
                    crossbar >> 20 & 3,
                    crossbar >> 22 & 3,
                    format.cnvc_pixel_format(),
                    u32::from(format.cnvc_alpha()),
                    u32::from(csc.is_some()),
                );
                for w in csc.into_iter().flatten() {
                    let _ = write!(got, " {w:x}");
                }
            }
        }
        if got != want {
            let _ = writeln!(
                narf_console::Writer,
                "dcn401_yuv: {input}: got {got}, want {want}"
            );
            return TestResult::Fail("input conversion differs from Linux");
        }
        n += 1;
    }
    if n != 160 {
        return TestResult::Fail("vector count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_input_conversion_matches_linux_vectors
);

/// tests/dcn401_yuv/color_vectors.txt: Linux's input transfer function for
/// every scanned format with and without the CRTC's legacy gamma
/// (map_crtc_degamma_to_dc_plane through dcn32_set_input_transfer_func: the
/// sRGB ROM for RGB and P010, the BT.709 GAMCOR points with the ROM
/// bypassed for NV12; its PRE_DEGAM and GAMCOR fields and the FNV-1a of
/// its writes from a bypassed GAMCOR), dpp3_program_post_csc's
/// coefficient set against each CM_POST_CSC_MODE_CURRENT (the one not in
/// use), dpp401_set_cursor_matrix's bypass and
/// dpp401_set_cursor_attributes' CUR0_ROM_EN (amdgpu_dm's
/// ENABLE_CURSOR_DEGAMMA under legacy gamma).
fn dcn401_dpp_color_input_matches_linux_vectors() -> TestResult {
    use crate::amdgpu_dcn401_otg::{InputTf, YuvColor};
    use core::fmt::Write;
    const VECTORS: &str = include_str!("../tests/dcn401_yuv/color_vectors.txt");
    // CM_GAMCOR_MODE, CM_GAMCOR_SELECT and the FNV-1a 32 of each input
    // transfer function's writes (dword offset, then value, as LE bytes;
    // CM_GAMCOR_CONTROL's read-only current fields left out).
    let trace = |tf: InputTf| -> (u32, u32, u32) {
        let mut e = engine();
        let _ = e.program_input_tf(0, tf);
        let mut h: u32 = 0x811c_9dc5;
        for &(at, value) in &e.io.writes {
            let reg = ((at - BASE) / 4) as u32;
            let value = if reg == 0xd77 { value & !0x70 } else { value };
            for b in reg.to_le_bytes().into_iter().chain(value.to_le_bytes()) {
                h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
            }
        }
        let control = e.io.regs.get(&d(0, 0xd77)).copied().unwrap_or(0);
        (control & 3, (control >> 2) & 1, h)
    };
    let traces = [
        trace(InputTf::Bypass),
        trace(InputTf::Srgb),
        trace(InputTf::Bt709),
    ];
    let mut n = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let (input, want) = line.split_once(" = ").unwrap();
        let mut f = input.split_whitespace();
        let code = f.next().unwrap().as_bytes();
        let fourcc = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
        let mut num = || f.next().unwrap().parse::<u32>().unwrap();
        let (legacy, current, enc, range) = (num() != 0, num(), num(), num());
        let format = SurfaceFormat::from_fourcc(fourcc).unwrap();
        let refused = format.is_video() && YuvColor::from_props(enc as u8, range as u8).is_none();
        let got = if refused {
            alloc::string::String::from("-")
        } else {
            let tf = if legacy {
                InputTf::implicit(format)
            } else {
                InputTf::Bypass
            };
            let degam = tf.pre_degam().word();
            let (gamcor_mode, gamcor_select, hash) = traces[tf as usize];
            let (mode, set) = match format.is_video() {
                false => (0, "-"),
                true if crate::amdgpu_dcn401_otg::fetch::post_csc_set_b(current) => (2, "B"),
                true => (1, "A"),
            };
            // The cursor's ROM follows the CRTC's legacy gamma, as
            // ColorProgram records it (cm_is_degamma_srgb).
            let program = crate::amdgpu_dcn401_otg::ColorProgram {
                pre_degam_srgb: legacy,
                ..Default::default()
            };
            let mut out = alloc::string::String::new();
            let _ = write!(
                out,
                "{} {} {mode} {set} {} {} {gamcor_mode} {gamcor_select} {hash:08x}",
                degam & 3,
                degam >> 4 & 7,
                crate::amdgpu_dcn401_otg::fetch::CURSOR_MATRIX_WORD,
                u32::from(program.pre_degam_srgb),
            );
            out
        };
        if got != want {
            let _ = writeln!(
                narf_console::Writer,
                "dcn401_yuv color: {input}: got {got}, want {want}"
            );
            return TestResult::Fail("plane color input differs from Linux");
        }
        n += 1;
    }
    if n != 684 {
        return TestResult::Fail("vector count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_color_input_matches_linux_vectors
);

/// dpp3_program_post_csc double-buffers the input CSC: on a DPP whose
/// CM_POST_CSC_MODE_CURRENT reads set A (ICSC) an NV12 plane's matrix goes
/// into set B (CM_POST_CSC_B_*) and COMA is selected, leaving A's words as
/// they were; the record says B, which staging's verifier checked. The cursor
/// matrix is bypassed by the same setup (dpp401_set_cursor_matrix).
fn dcn401_dpp_input_csc_takes_the_set_not_in_use() -> TestResult {
    use crate::amdgpu_dcn401_otg::{PlaneSurface, YuvColor};
    let p = 1;
    let mut mode = small(p);
    mode.timing.timing.h_active = 64;
    mode.timing.timing.v_active = 16;
    mode.clock = clock(mode.timing);
    mode.surface = SurfaceRequest {
        width: 64,
        height: 16,
        format: SurfaceFormat::Nv12,
        surface: PlaneSurface {
            color: YuvColor::Bt709,
            ..PlaneSurface::LINEAR
        },
        ..req(p)
    };
    let (_backing, _pool, mut e, mut surfaces, clock) = ready_with(p, ColorDepth::Bpc8, mode);
    // Set A in use, holding stale words; the cursor matrix left on set A.
    e.fake().regs.insert(d(p, 0xd68), 1 | 1 << 2);
    e.fake().regs.insert(d(p, 0xd69), 0xdead_beef);
    e.fake().regs.insert(d(p, 0xcf6), 1);
    let Ok(applied) = run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))) else {
        return TestResult::Fail("NV12 DPP staging");
    };
    let reg = |e: &mut Engine<DppIo>, r: u64| e.fake().regs[&d(p, r)] & !0x8000_0000;
    let words =
        crate::amdgpu_dcn401_otg::fetch::post_csc_words(SurfaceFormat::Nv12, YuvColor::Bt709)
            .unwrap();
    if !applied.post_csc_b.b(0)
        || reg(&mut e, 0xd68) & 3 != 2
        || reg(&mut e, 0xd69) != 0xdead_beef & !0x8000_0000
        || (0..6).any(|i| reg(&mut e, 0xd6f + i) != words[i as usize] & !0x8000_0000)
        || reg(&mut e, 0xcf6) & 0x13 != 0
    {
        return TestResult::Fail("input CSC not double-buffered into set B");
    }
    // prepare_dpp's own verify_dpp read the set B record back.
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_input_csc_takes_the_set_not_in_use
);

/// dpp3_program_post_csc runs on each segment's own DPP and reads that
/// DPP's CM_POST_CSC_MODE_CURRENT: an ODM-split NV12 plane whose first DPP
/// uses set A and whose second uses set B loads B on the first and A on the
/// second; an RGB plane takes A everywhere.
fn dcn401_dpp_input_csc_set_is_chosen_per_dpp() -> TestResult {
    use crate::amdgpu_dcn401_otg::SplitPipes;
    let mut e = crate::amdgpu_dcn401_otg::tests::engine();
    let request = |format| SurfaceRequest {
        pipe: 0,
        width: 64,
        height: 32,
        format,
        odm: SplitPipes::one(1),
        mpc: SplitPipes::NONE,
        plane: None,
        surface: Default::default(),
    };
    // CM_POST_CSC_MODE_CURRENT: ICSC (A) on DPP 0, COMA (B) on DPP 1.
    e.io.regs.insert(d(0, 0xd68), 1 << 2);
    e.io.regs.insert(d(1, 0xd68), 2 << 2);
    let Ok(sets) = e.post_csc_choice(request(SurfaceFormat::Nv12)) else {
        return TestResult::Fail("NV12 choice");
    };
    if !sets.b(0) || sets.b(1) {
        return TestResult::Fail("NV12 segments share the first DPP's set");
    }
    let Ok(sets) = e.post_csc_choice(request(SurfaceFormat::Xrgb8888)) else {
        return TestResult::Fail("RGB choice");
    };
    if sets.b(0) || sets.b(1) {
        return TestResult::Fail("RGB loads set B");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_input_csc_set_is_chosen_per_dpp
);

/// An NV12 plane stages dpp401_dpp_setup's VIDEO_420 CNVC format and the
/// post CSC of its color space (set A, CM_POST_CSC_MODE 1).
fn dcn401_dpp_stages_nv12_input_csc() -> TestResult {
    use crate::amdgpu_dcn401_otg::{PlaneSurface, YuvColor};
    let p = 1;
    let mut mode = small(p);
    mode.timing.timing.h_active = 64;
    mode.timing.timing.v_active = 16;
    mode.clock = clock(mode.timing);
    mode.surface = SurfaceRequest {
        width: 64,
        height: 16,
        format: SurfaceFormat::Nv12,
        surface: PlaneSurface {
            color: YuvColor::Bt601,
            ..PlaneSurface::LINEAR
        },
        ..req(p)
    };
    let (_backing, _pool, mut e, mut surfaces, clock) = ready_with(p, ColorDepth::Bpc8, mode);
    if run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))).is_err() {
        return TestResult::Fail("NV12 DPP staging");
    }
    let reg = |e: &mut Engine<DppIo>, r: u64| e.fake().regs[&d(p, r)] & !0x8000_0000;
    if reg(&mut e, 0xccf) & 0x17f != 64 || reg(&mut e, 0xd68) & 3 != 1 {
        return TestResult::Fail("CNVC format / post CSC mode");
    }
    let want = [
        0x2000_2cdd,
        0xe991_0000,
        0x2000_e926,
        0x10ef_f4fd,
        0x2000_0000,
        0xe3a6_38b4,
    ];
    for (i, w) in want.into_iter().enumerate() {
        if reg(&mut e, 0xd69 + i as u64) != w & !0x8000_0000 {
            return TestResult::Fail("post CSC coefficients");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-dpp", dcn401_dpp_stages_nv12_input_csc);
