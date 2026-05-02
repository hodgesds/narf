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

fn smoke_amdgpu_pci_matches_registered() -> TestResult {
    // Structural: register the amdgpu driver and assert every
    // explicit AMD VID/DID match plus the class-match backstop
    // are in the bus's table. Doesn't require live silicon.
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    use crate::amdgpu;
    __reset_for_test();
    amdgpu::register_pci_driver();
    let regs = registered_pci_drivers();
    let want: &[(u16, u16)] = &[
        (amdgpu::AMD_VENDOR, amdgpu::PHOENIX_HAWKPOINT1),
        (amdgpu::AMD_VENDOR, amdgpu::PHOENIX_DISCRETE),
        (amdgpu::AMD_VENDOR, amdgpu::STRIX_POINT),
        (amdgpu::AMD_VENDOR, amdgpu::RAPHAEL),
        (amdgpu::AMD_VENDOR, amdgpu::CEZANNE),
        (amdgpu::AMD_VENDOR, amdgpu::RENOIR),
        (amdgpu::AMD_VENDOR, amdgpu::NAVI22),
        (amdgpu::AMD_VENDOR, amdgpu::NAVI31),
    ];
    for (v, d) in want.iter().copied() {
        let found = regs.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == v && device == d));
        if !found {
            return TestResult::Fail("missing amdgpu VID/DID match");
        }
    }
    let class_match = regs.iter().any(|m|
        matches!(m.kind, MatchKind::Class {
            class: 0x03, mask: 0xFF,
        }));
    if !class_match {
        return TestResult::Fail("amdgpu class-match backstop missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_pci_matches_registered);

fn smoke_amdgpu_family_table_documented_offsets() -> TestResult {
    // Family::mp0_base() is documented for Vega + Navi1; the
    // Stage-2 spec leaves Phoenix/Strix/Renoir/Navi2 marked TBD
    // pending datasheet sourcing. Lock this in so accidentally
    // shipping a placeholder offset for an undocumented family
    // surfaces as a test failure.
    use crate::amdgpu::Family;
    if Family::Vega.mp0_base()  != Some(0x000B_0000) {
        return TestResult::Fail("Vega MP0 base wrong");
    }
    if Family::Navi1.mp0_base() != Some(0x000B_0000) {
        return TestResult::Fail("Navi1 MP0 base wrong");
    }
    if Family::Navi2.mp0_base().is_some() {
        return TestResult::Fail("Navi2 should be TBD");
    }
    if Family::Navi3.mp0_base().is_some() {
        return TestResult::Fail("Navi3 should be TBD");
    }
    if Family::Renoir.mp0_base().is_some() {
        return TestResult::Fail("Renoir should be TBD");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_amdgpu_family_table_documented_offsets);

// `smoke_amdgpu_scanout_picker_idle` lives in `fb/src/tests.rs`
// to avoid a `narf-drivers-gpu` ↔ `narf-fb` Cargo cycle (fb
// already depends on drivers/gpu for the picker).
