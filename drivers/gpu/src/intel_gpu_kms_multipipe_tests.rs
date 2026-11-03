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
