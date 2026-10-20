use super::*;
use crate::amdgpu_dcn401_otg::tests::{engine, run};
use narf_kernel_test::{kernel_test_in, TestResult};

fn dcn401_flip_requires_live_scanout_and_consistent_reports() -> TestResult {
    let mut e = engine();
    let mut surfaces = Surfaces::new();
    let mut called = false;
    if run(surfaces.flip(&mut e, 0, 100_000, || {
        called = true;
        Err(Error::Busy)
    })) != Err(Error::Invalid)
        || called
        || e.status.state != State::Ready
    {
        return TestResult::Fail("flip without scanout");
    }
    if !matches!(surfaces.back_framebuffer(0), Err(Error::Invalid)) {
        return TestResult::Fail("back buffer without surface");
    }
    // Retargeting never invents reports: missing ones refuse the swap.
    let surface = SurfaceApplied {
        request: SurfaceRequest {
            surface: Default::default(),
            pipe: 0,
            width: 1920,
            height: 1080,
            format: SurfaceFormat::Xrgb8888,
            odm: None,
            plane: None,
        },
        address: 0x8_0000_0000,
        pitch_bytes: 7680,
        bytes: 7680 * 1080,
    };
    e.status.surfaces[0] = Some(surface);
    if e.retarget(0, surface, 0x8_0100_0000) != Err(Error::Invalid)
        || e.status.surfaces[0] != Some(surface)
    {
        return TestResult::Fail("partial retarget");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-flip",
    dcn401_flip_requires_live_scanout_and_consistent_reports
);
