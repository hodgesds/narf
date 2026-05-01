//! Per-driver smoke tests for `narf-audio::hda`. Tests register
//! via `narf_kernel_test::kernel_test_in!` so the runner groups
//! output under `audio/hda`.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_hda_match_amd_phoenix_ids() -> TestResult {
    // Register the HDA driver and verify both supported PCI ids
    // (AMD Ryzen Phoenix HDA + Radeon HD Audio) appear in the bus
    // match table. No live silicon required.
    use crate::hda;
    use narf_bus::{registered_pci_drivers, MatchKind};
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    bus_reset();
    hda::register_pci_driver();
    let regs = registered_pci_drivers();
    let mut saw_phoenix = false;
    let mut saw_radeon  = false;
    for m in regs.iter() {
        if let MatchKind::VendorDevice { vendor, device } = m.kind {
            if vendor == hda::HDA_AMD_PHOENIX_VENDOR
                && device == hda::HDA_AMD_PHOENIX_DEVICE
            {
                saw_phoenix = true;
            }
            if vendor == hda::HDA_AMD_RADEON_VENDOR
                && device == hda::HDA_AMD_RADEON_DEVICE
            {
                saw_radeon = true;
            }
        }
    }
    if !saw_phoenix {
        return TestResult::Fail("AMD Phoenix 1022:15e3 not in match table");
    }
    if !saw_radeon {
        return TestResult::Fail("AMD Radeon 1002:1640 not in match table");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", smoke_hda_match_amd_phoenix_ids);

fn smoke_hda_corb_size_layout() -> TestResult {
    // HDA spec rev 1.0a §3.3.18 / §3.3.25: CORB and RIRB rings must
    // be 128-byte aligned. The driver allocates 4 KiB pages from
    // alloc_coherent which trivially satisfy that. This smoke
    // round-trips the alignment invariant so a future allocator
    // change can't silently regress it.
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let corb = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b)  => b,
        Err(_) => return TestResult::Fail("alloc_coherent CORB"),
    };
    let rirb = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b)  => b,
        Err(_) => return TestResult::Fail("alloc_coherent RIRB"),
    };
    let corb_phys = corb.phys_addr().raw();
    let rirb_phys = rirb.phys_addr().raw();
    if corb_phys & 0x7F != 0 {
        return TestResult::Fail("CORB phys not 128-byte aligned");
    }
    if rirb_phys & 0x7F != 0 {
        return TestResult::Fail("RIRB phys not 128-byte aligned");
    }
    if (corb_phys & 0xFFF) + 1024 > 4096 {
        return TestResult::Fail("CORB 1024-byte ring spans a page");
    }
    if (rirb_phys & 0xFFF) + 2048 > 4096 {
        return TestResult::Fail("RIRB 2048-byte ring spans a page");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", smoke_hda_corb_size_layout);

fn smoke_hda_period_load_silence() -> TestResult {
    // Round-trip the period-buffer math against the bound
    // controller. Skips when no HDA silicon is bound.
    use crate::hda;
    if !hda::is_probed() { return TestResult::Skip("hda not probed"); }
    let n = hda::with_controller(|c| {
        let _ = c.load_period(&[]);
        c.period_samples()
    });
    match n {
        Some(2048) => TestResult::Pass,
        Some(_)    => TestResult::Fail("period_samples != 2048"),
        None       => TestResult::Skip("hda controller missing"),
    }
}
kernel_test_in!("audio/hda", smoke_hda_period_load_silence);
