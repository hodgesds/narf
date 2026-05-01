//! Per-crate smoke tests for `narf-drivers-gpu`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"drivers/gpu"`. Probe-dependent tests
//! emit `TestResult::Skip` when the underlying device isn't present
//! so this file is safe to link on every build.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_drivers_gpu_mode_and_family() -> TestResult {
    use crate::{GpuFamily, Mode, ModeList, SubmitKind};

    // Known modes carry sensible sizes.
    if Mode::FHD_60.width != 1920 || Mode::FHD_60.height != 1080 {
        return TestResult::Fail("FHD_60 mode fields wrong");
    }
    if Mode::XGA_60.refresh_hz != 60 {
        return TestResult::Fail("XGA_60 refresh_hz wrong");
    }

    let mut list = ModeList::default();
    list.modes.push(Mode::FHD_60);
    list.modes.push(Mode::XGA_60);
    if list.modes.len() != 2 { return TestResult::Fail("mode list len"); }

    // Family + submit kind discriminants distinct.
    if GpuFamily::VirtioGpu == GpuFamily::IntelI915 {
        return TestResult::Fail("GpuFamily variants collapsed");
    }
    if SubmitKind::Gfx == SubmitKind::Compute {
        return TestResult::Fail("SubmitKind variants collapsed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_drivers_gpu_mode_and_family);

fn smoke_bochs_display_probed_at_boot() -> TestResult {
    use narf_graphics_driver::bochs;
    if bochs::is_probed() {
        TestResult::Pass
    } else {
        TestResult::Skip("bochs-display not present in this QEMU config")
    }
}
kernel_test_in!("drivers/gpu", smoke_bochs_display_probed_at_boot);

fn smoke_virtio_gpu_probed_at_boot() -> TestResult {
    use narf_drivers_virtio::gpu_pci;
    if gpu_pci::is_probed() {
        TestResult::Pass
    } else {
        TestResult::Skip("virtio-gpu-pci not present in this QEMU config")
    }
}
kernel_test_in!("drivers/gpu", smoke_virtio_gpu_probed_at_boot);

fn smoke_virtio_gpu_scanout_initialised() -> TestResult {
    // After boot's splash blit, the virtio-gpu controller should be
    // marked `ready` (init_scanout completed: GET_DISPLAY_INFO,
    // RESOURCE_CREATE_2D, ATTACH_BACKING, SET_SCANOUT all OK).
    use narf_drivers_virtio::gpu_pci;
    if !gpu_pci::is_probed() {
        return TestResult::Skip("virtio-gpu-pci not present");
    }
    match gpu_pci::with_controller(|d| d.ready) {
        Some(true)  => TestResult::Pass,
        Some(false) => TestResult::Fail("virtio-gpu probed but scanout not ready"),
        None        => TestResult::Skip("virtio-gpu-pci controller missing"),
    }
}
kernel_test_in!("drivers/gpu", smoke_virtio_gpu_scanout_initialised);
