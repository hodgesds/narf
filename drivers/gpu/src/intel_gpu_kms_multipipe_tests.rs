//! Display-14 Pipe-A KMS services while an external output is lit on Pipe B:
//! the multi-pipe layout the Pipe B–D owner programs and publishes. Flips,
//! the cursor and color prove Pipe A's share of that layout and never touch
//! the external pipe or the global resources; a diverged or foreign layout
//! still refuses. x86_64 only: the KMS present path needs WC GEM objects.
use super::*;
use crate::intel_gpu_xelpg_pipes::{publish_layout_for_test, reset_published_layout, Layout};
use crate::intel_gpu_xelpg_resources as res;
use crate::intel_gpu_xelpg_wm::{Latency, Tiling};

/// The external's scanout surface, outside the KMS GEM arena.
pub(super) const EXT_SURFACE: u32 = 0x0200_0000;

/// A 1280x720 external on Pipe B (DP HBR2, combo PHY B).
pub(super) fn external() -> res::PipeRequest {
    let mut planes = [None; res::PLANES];
    planes[0] = Some(res::PlaneRequest {
        width: 1280,
        height: 720,
        cpp: 4,
        tiling: Tiling::Linear,
    });
    res::PipeRequest {
        pixel_rate_khz: 74_250,
        hdisplay: 1280,
        htotal: 1650,
        vdisplay: 720,
        vtotal: 750,
        planes,
        cursor_visible: false,
        port_clock_khz: 270_000,
        combo_phy: Some(1),
        dsc: None,
        src_w: None,
        src_h: None,
        scaler: None,
        bigjoiner_slave: None,
    }
}

pub(super) fn mode_of(timing: crate::intel_gpu_dsb::Timing) -> crate::intel_gpu_modeset::Mode {
    crate::intel_gpu_modeset::Mode {
        pixel_clock_khz: timing.clock,
        h_active: timing.width,
        h_total: timing.htotal,
        v_active: timing.height,
        v_total: timing.vtotal,
        ..crate::intel_gpu_modeset::Mode::VESA_1024X768_60
    }
}

/// The owned panel with the external lit on Pipe B, as the Pipe B–D owner
/// leaves them: the two-pipe state committed (here from all-off), both
/// transcoders and primaries on, and the layout published.
pub(super) fn beside_external(
    platform: &MockPlatform,
) -> (crate::intel_gpu_dsb::Timing, res::State) {
    reset_published_layout();
    let timing = platform.cursor_resources();
    platform.set(0x70008, 0);
    platform.set(0x70180, 0);
    let mut request =
        crate::intel_gpu_display_resources::request(&mode_of(timing), Tiling::Linear, 307_200);
    request.pipes[1] = Some(external());
    let state = res::compute(&request, &Latency::read(platform).unwrap()).unwrap();
    res::commit(platform, &state).unwrap();
    for (r, v) in [
        (0x70008, 3 << 30),
        (0x70180, 0x8400_0000),
        (0x71008, 3 << 30),
        (0x71180, 0x8400_0000),
        (0x7119c, EXT_SURFACE),
    ] {
        platform.set(r, v);
    }
    publish_layout_for_test(Some(Layout {
        state,
        surfaces: [None, Some(EXT_SURFACE), None, None],
    }));
    (timing, state)
}

/// A register the panel's KMS services must never write while the external
/// is lit: Pipes and transcoders B–D, and the global display resources the
/// Pipe B–D owner partitions (PM demand, CDCLK, DBUF slices, MBUS).
pub(super) fn external_or_global(r: u64) -> bool {
    (0x71000..0x74000).contains(&r)
        || (0x61000..0x64000).contains(&r)
        || [
            0x45230, 0x45234, 0x46000, 0x46008, 0x46070, 0x45008, 0x44fe8, 0x44300, 0x44304,
            0x4438c,
        ]
        .contains(&r)
}

pub(super) fn drive<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..1024 {
        if let Poll::Ready(result) = once(future.as_mut()) {
            return result;
        }
    }
    panic!("multi-pipe KMS conversation did not finish");
}

const IDENTITY: [u64; 9] = [1 << 32, 0, 0, 0, 1 << 32, 0, 0, 0, 1 << 32];

fn smoke_kms_mtl_panel_flip_cursor_and_color_beside_lit_external() -> TestResult {
    {
        let platform = MockPlatform::new();
        let (timing, state) = beside_external(&platform);
        let device = platform.meteor();
        let start = platform.all_writes().len();
        // A panel flip.
        {
            let mut session = complete(device.session()).unwrap();
            complete(session.present(object(true).unwrap(), geometry())).unwrap();
        }
        assert_ne!(platform.read32(LIVE), CONSOLE);
        // Tile4 admission proves the layout's Tile4 image fits Pipe A.
        crate::intel_gpu_kms::tile4_profile(&platform, geometry(), timing).unwrap();
        // The cursor takes Pipe A's multi-pipe cursor DDB and watermarks.
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(16384, |_, _| Ok(())).unwrap();
        {
            let mut session = complete(device.session()).unwrap();
            drive(session.cursor(
                Some(gem.object(handle).unwrap()),
                true,
                Some((3, 4)),
                timing,
            ))
            .unwrap();
        }
        assert_ne!(platform.read32(0x700ac), 0);
        let share = &state.dbuf.pipes[0];
        assert!(share.cursor.end <= 2048, "Pipe A holds half the DBUF");
        assert_eq!(platform.read32(res::cursor_buf_cfg(0)), share.cursor.reg());
        for (r, v) in res::cursor_wm_image(0, &share.cursor_wm).unwrap() {
            assert_eq!(platform.read32(r), v, "cursor WM {r:#x}");
        }
        // Color (CSC).
        {
            let mut session = complete(device.session()).unwrap();
            complete(session.set_ctm(Some(IDENTITY))).unwrap();
        }
        // The external pipe and the global partition were never touched.
        let writes = &platform.all_writes()[start..];
        assert!(writes.iter().all(|&(r, _)| !external_or_global(r)));
        for (r, v) in state.pipe_registers(1, false).unwrap() {
            assert_eq!(platform.read32(r), v, "external image {r:#x}");
        }
        assert_eq!(platform.read32(0x71008), 3 << 30);
        assert_eq!(platform.read32(0x7119c), EXT_SURFACE);
        reset_published_layout();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_mtl_panel_flip_cursor_and_color_beside_lit_external
);

fn smoke_kms_mtl_cursor_refuses_diverged_multi_pipe_layout() -> TestResult {
    {
        let platform = MockPlatform::new();
        let (timing, _) = beside_external(&platform);
        let device = platform.meteor();
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(16384, |_, _| Ok(())).unwrap();
        // Each divergence refuses before any cursor, DSB or WM write.
        let diverge: [(u64, u32); 4] = [
            // Pipe B's DDB moved under Pipe A's feet.
            (res::plane_buf_cfg(1, 0), 0x07ff_0000),
            // A foreign pipe lit outside the layout.
            (0x72008, 3 << 30),
            // Pipe A's primary DDB grown back to the single-pipe layout.
            (res::plane_buf_cfg(0, 0), 0x0fff_0000),
            // MBUS selecting a pipe the layout does not run.
            (0x4438c, 3 << 26),
        ];
        for (r, value) in diverge {
            let held = platform.read32(r);
            platform.set(r, value);
            let start = platform.all_writes().len();
            {
                let mut session = complete(device.session()).unwrap();
                let refused = drive(session.cursor(
                    Some(gem.object(handle).unwrap()),
                    true,
                    Some((3, 4)),
                    timing,
                ));
                assert_eq!(refused, Err(FsError::Unsupported), "divergence {r:#x}");
            }
            assert!(platform.all_writes()[start..]
                .iter()
                .all(
                    |&(w, _)| !(0x70080..0x70180).contains(&w) && !(0x70b00..0x70c00).contains(&w)
                ));
            platform.set(r, held);
        }
        // Without the published layout the two-pipe hardware is foreign too.
        reset_published_layout();
        {
            let mut session = complete(device.session()).unwrap();
            assert_eq!(
                drive(session.cursor(
                    Some(gem.object(handle).unwrap()),
                    true,
                    Some((3, 4)),
                    timing,
                )),
                Err(FsError::Unsupported)
            );
        }
        assert_eq!(platform.read32(0x70080), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_mtl_cursor_refuses_diverged_multi_pipe_layout
);

// ── The external pass around a repartition (PSR, FBC, DSB) ──────────────

const DPFC_CONTROL: u64 = 0x43208;
const DPFC_CB_BASE: u64 = 0x43200;
const DSB0_CTRL: u64 = 0x70b08;

/// The owned single-pipe state and the two-pipe state with the external
/// on Pipe B, both at the fixture's 307.2 MHz CDCLK floor.
fn layouts(
    platform: &MockPlatform,
    timing: crate::intel_gpu_dsb::Timing,
) -> (res::State, res::State) {
    let latency = Latency::read(platform).unwrap();
    let mut request =
        crate::intel_gpu_display_resources::request(&mode_of(timing), Tiling::Linear, 307_200);
    let single = res::compute(&request, &latency).unwrap();
    request.pipes[1] = Some(external());
    (single, res::compute(&request, &latency).unwrap())
}

/// What the route does inside the pass to add the external beside the
/// lit panel: the Pipe B–D owner's live pre-plane repartition, its
/// published layout, then the lit pipe and primary.
fn add_external(platform: &MockPlatform, single: &res::State, multi: &res::State) {
    crate::intel_gpu_xelpg_live::commit_live(platform, single, multi, 1).unwrap();
    publish_layout_for_test(Some(Layout {
        state: *multi,
        surfaces: [None, Some(EXT_SURFACE), None, None],
    }));
    for (r, v) in [
        (0x71008, 3 << 30),
        (0x71180, 0x8400_0000),
        (0x7119c, EXT_SURFACE),
    ] {
        platform.set(r, v);
    }
}

/// And to remove it: the pipe goes dark (the route's stop), then the
/// post-plane repartition gives Pipe A its whole profile back.
fn remove_external(platform: &MockPlatform, multi: &res::State, single: &res::State) {
    for r in [0x71008, 0x71180] {
        platform.set(r, 0);
    }
    crate::intel_gpu_xelpg_live::commit_live(platform, multi, single, 1).unwrap();
    reset_published_layout();
}

/// The first and last write of the repartition in `writes`.
fn repartition_span(writes: &[(u64, u32)]) -> (usize, usize) {
    let touched = |r: u64| external_or_global(r) || (0x70140..0x70380).contains(&r);
    (
        writes.iter().position(|&(r, _)| touched(r)).unwrap(),
        writes.iter().rposition(|&(r, _)| touched(r)).unwrap(),
    )
}

fn smoke_kms_mtl_psr_enables_beside_external_and_brackets_repartitions() -> TestResult {
    use super::psr::{attach, present_once, psr, sink_writes, ARMED, EN_CFG, EXITED, PSR_CTL};
    {
        let previous = crate::intel_gpu_psr::register_wm_level_disabled(None);
        crate::intel_gpu_xelpg_wm::register_psr_provider();
        crate::intel_gpu_xelpg_wm::publish_pipe_a(None);
        let platform = MockPlatform::new();
        let (timing, multi) = beside_external(&platform);
        let (single, _) = layouts(&platform, timing);
        attach(&platform, timing, None);
        platform.0.lock().psr_wm_provider = true;
        let device = platform.meteor();
        // PSR enables on the first latch with the external lit: the
        // qualification proves Pipe A's share of the two-pipe layout and
        // reads its wm_level_disabled from that proof.
        present_once(&device, object(true).unwrap());
        assert_eq!(
            crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled(),
            Some(false)
        );
        assert!(psr(&device).is_some());
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        assert_eq!(
            sink_writes(&platform.all_writes())[..2],
            [(EN_CFG, 0x04), (EN_CFG, 0x05)]
        );
        // Each repartition runs inside the pass's bracket: PSR exits and
        // idles before the first write that touches Pipe A's resources and
        // re-arms from idle only after the latch, when the pass ends.
        platform.step_on_read(Some(FRAME));
        for add in [false, true] {
            let start = platform.all_writes().len();
            {
                let mut pass = device.external_pass().unwrap();
                pass.pre_update();
                assert_eq!(platform.read32(PSR_CTL), EXITED);
                if add {
                    add_external(&platform, &single, &multi);
                } else {
                    remove_external(&platform, &multi, &single);
                }
                pass.post_update();
                assert_eq!(platform.read32(PSR_CTL), EXITED, "re-armed inside the pass");
            }
            assert_eq!(platform.read32(PSR_CTL), ARMED);
            let writes = &platform.all_writes()[start..];
            let exit = writes.iter().position(|&w| w == (PSR_CTL, EXITED)).unwrap();
            let (first, last) = repartition_span(writes);
            let rearm = writes.iter().rposition(|&w| w == (PSR_CTL, ARMED)).unwrap();
            assert!(exit < first && last < rearm, "add {add}");
            assert!(psr(&device).unwrap().active());
            // The post-update re-proved Pipe A in the new layout.
            assert_eq!(
                crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled(),
                Some(false)
            );
        }
        platform.step_on_read(None);
        // A flip with the external lit again keeps PSR enabled.
        present_once(&device, object(true).unwrap());
        assert_eq!(platform.read32(PSR_CTL), ARMED);
        assert_eq!(platform.read32(0x7119c), EXT_SURFACE);
        reset_published_layout();
        crate::intel_gpu_psr::register_wm_level_disabled(previous);
        crate::intel_gpu_xelpg_wm::publish_pipe_a(None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_mtl_psr_enables_beside_external_and_brackets_repartitions
);

fn smoke_kms_mtl_external_pass_deactivates_and_reevaluates_fbc() -> TestResult {
    use super::psr::present_once;
    {
        reset_published_layout();
        let platform = MockPlatform::new();
        let timing = platform.cursor_resources();
        let (single, multi) = layouts(&platform, timing);
        // The panel mode is known; no PSR VBT, so FBC runs.
        platform.0.lock().psr_timing = Some(timing);
        platform.0.lock().fbc_offset = Some(0x10_0000);
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        assert_ne!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
        let cfb = platform.read32(DPFC_CB_BASE);
        let carves = platform.0.lock().fbc_carve_polls;
        // An active FBC is what the live transaction refuses (the former
        // Busy of the external route), before any write.
        let start = platform.all_writes().len();
        assert_eq!(
            crate::intel_gpu_xelpg_live::commit_live(&platform, &single, &multi, 1),
            Err(res::ResourceError::Busy)
        );
        assert_eq!(platform.all_writes().len(), start);
        platform.step_on_read(Some(FRAME));
        for add in [true, false] {
            let start = platform.all_writes().len();
            {
                let mut pass = device.external_pass().unwrap();
                pass.pre_update();
                // intel_fbc_pre_update: deactivated, then one vblank (WA
                // #1198) before any plane update.
                assert_eq!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
                if add {
                    add_external(&platform, &single, &multi);
                } else {
                    remove_external(&platform, &multi, &single);
                }
                pass.post_update();
                // intel_fbc_post_update on the proved layout.
                assert_ne!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
            }
            let writes = &platform.all_writes()[start..];
            let off = writes
                .iter()
                .position(|&(r, v)| r == DPFC_CONTROL && v & (1 << 31) == 0)
                .unwrap();
            let (first, last) = repartition_span(writes);
            let on = writes
                .iter()
                .rposition(|&(r, v)| r == DPFC_CONTROL && v & (1 << 31) != 0)
                .unwrap();
            assert!(off < first && last < on, "add {add}");
            // The CFB carve stays valid: same base, no new carve.
            assert_eq!(platform.read32(DPFC_CB_BASE), cfb);
            assert_eq!(platform.0.lock().fbc_carve_polls, carves);
        }
        // Never on stale DDB/WM: a layout that does not prove after the
        // event keeps FBC off (until the next latch re-evaluates it).
        let held = platform.read32(res::plane_buf_cfg(0, 0));
        {
            let mut pass = device.external_pass().unwrap();
            pass.pre_update();
            platform.set(res::plane_buf_cfg(0, 0), held - 1);
            pass.post_update();
        }
        platform.step_on_read(None);
        assert_eq!(platform.read32(DPFC_CONTROL) & (1 << 31), 0);
        platform.set(res::plane_buf_cfg(0, 0), held);
        reset_published_layout();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_mtl_external_pass_deactivates_and_reevaluates_fbc
);

fn smoke_kms_mtl_external_pass_idles_in_flight_dsb_before_repartition() -> TestResult {
    use super::psr::present_once;
    {
        reset_published_layout();
        let platform = MockPlatform::new();
        let timing = platform.cursor_resources();
        let (single, multi) = layouts(&platform, timing);
        let device = platform.meteor();
        present_once(&device, object(true).unwrap());
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(16384, |_, _| Ok(())).unwrap();
        // A cursor update armed on DSB0 whose future is dropped before the
        // stream ran: the stream is in flight on the panel.
        {
            let mut session = complete(device.session()).unwrap();
            let mut update = Box::pin(session.cursor(
                Some(gem.object(handle).unwrap()),
                true,
                Some((3, 4)),
                timing,
            ));
            for _ in 0..64 {
                if platform.read32(DSB0_CTRL) & (1 << 31) != 0 {
                    break;
                }
                assert!(once(update.as_mut()).is_pending());
            }
        }
        assert_ne!(platform.read32(DSB0_CTRL) & ((1 << 31) | 1), 0);
        // The live transaction refuses an in-flight DSB.
        assert_eq!(
            crate::intel_gpu_xelpg_live::check_pipes(&platform, 1),
            Err(res::ResourceError::Busy)
        );
        // The pass waits for the stream (its engine ticks on each control
        // read here) and only then may repartition.
        platform.step_on_read(Some(DSB0_CTRL));
        let mut pass = device.external_pass().unwrap();
        assert_eq!(platform.read32(DSB0_CTRL) & ((1 << 31) | 1), 0);
        assert_eq!(
            crate::intel_gpu_xelpg_live::check_pipes(&platform, 1),
            Ok(())
        );
        platform.step_on_read(Some(FRAME));
        pass.pre_update();
        add_external(&platform, &single, &multi);
        pass.post_update();
        drop(pass);
        platform.step_on_read(None);
        // The owner completes the dropped cursor update on its next call,
        // and moves the cursor beside the lit external.
        {
            let mut session = complete(device.session()).unwrap();
            drive(session.cursor(None, false, Some((5, 6)), timing)).unwrap();
        }
        assert_eq!(platform.read32(0x70088), 5 | (6 << 16));
        assert_eq!(
            platform.read32(res::cursor_buf_cfg(0)),
            multi.dbuf.pipes[0].cursor.reg()
        );
        reset_published_layout();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_mtl_external_pass_idles_in_flight_dsb_before_repartition
);

/// The runtime actor's MTL external pass (`service_mtl_external_for_bar`,
/// whose body is [`crate::intel_gpu::mtl_runtime_pass`]) leaves the panel's
/// KMS owner open: after a pass whose hotplug poll found nothing and one that
/// handled an event, a session still opens and the cursor still updates.
/// The pass used to take the owner through `legacy_drain`, which set
/// `blocked` for good on the first runtime iteration, so every later session
/// failed with NoDevice, with or without a monitor.
fn smoke_kms_mtl_runtime_pass_leaves_the_panel_owner_open() -> TestResult {
    {
        let platform = MockPlatform::new();
        let (timing, _) = beside_external(&platform);
        let device = platform.meteor();
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(16384, |_, _| Ok(())).unwrap();
        // The post-update waits for a Pipe-A frame boundary.
        platform.step_on_read(Some(FRAME));
        let mut events = 0;
        let idle = crate::intel_gpu::mtl_runtime_pass(Some(&device), |_, _| false);
        let handled = crate::intel_gpu::mtl_runtime_pass(Some(&device), |before, after| {
            before();
            after();
            events += 1;
            true
        });
        platform.step_on_read(None);
        if idle || !handled || events != 1 {
            reset_published_layout();
            return TestResult::Fail("both runtime passes must run with the owner held");
        }
        for _ in 0..2 {
            let Ok(mut session) = complete(device.session()) else {
                reset_published_layout();
                return TestResult::Fail("the runtime pass left the panel's KMS owner blocked");
            };
            let cursor = drive(session.cursor(
                Some(gem.object(handle).unwrap()),
                true,
                Some((3, 4)),
                timing,
            ));
            if cursor.is_err() {
                reset_published_layout();
                return TestResult::Fail("the panel cursor must update after the runtime pass");
            }
        }
        reset_published_layout();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_mtl_runtime_pass_leaves_the_panel_owner_open
);
