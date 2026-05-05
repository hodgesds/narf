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
    let mut saw_ich9 = false;
    for m in regs.iter() {
        if let MatchKind::VendorDevice { vendor, device } = m.kind {
            if vendor == hda::HDA_INTEL_ICH9_VENDOR
                && device == hda::HDA_INTEL_ICH9_DEVICE
            {
                saw_ich9 = true;
            }
        }
    }
    if !saw_ich9 {
        return TestResult::Fail("Intel ICH9 0x8086:0x293E not in match table");
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

fn smoke_acp6_pci_match_registered() -> TestResult {
    // Structural: register the ACP6 driver and assert the
    // AMD Phoenix ACP6.0 (1022:15E2) match is in the bus's table.
    use crate::acp6;
    use narf_bus::{registered_pci_drivers, MatchKind};
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    bus_reset();
    acp6::register_pci_driver();
    let regs = registered_pci_drivers();
    let matched = regs.iter().any(|m|
        m.name == "acp6"
        && matches!(m.kind, MatchKind::VendorDevice {
            vendor: acp6::ACP_VENDOR,
            device: acp6::ACP_PHOENIX,
        }));
    if !matched {
        return TestResult::Fail("acp6 PCI match table entry missing");
    }
    TestResult::Pass
}
kernel_test_in!("audio/acp6", smoke_acp6_pci_match_registered);

#[cfg(target_arch = "x86_64")]
fn smoke_hda_writer_submit_round_trip() -> TestResult {
    // End-to-end PCM submit through AudioWriter → hda. Probes
    // the device, opens an AudioWriter at the default playback
    // format (S16LE / 48 kHz / stereo), and submits 1024 bytes.
    use crate::{
        bootstrap_writer, AudioFormat, AudioWriter, hda,
    };
    use narf_bus::{bootstrap_registry_authority, devices, BusKind, probe_all_pci};
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;

    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d|
        matches!(&d.kind, BusKind::Pcie { .. })
        && d.id.vendor == hda::HDA_INTEL_ICH9_VENDOR
        && d.id.device == hda::HDA_INTEL_ICH9_DEVICE);
    if !has { return TestResult::Skip("no intel-hda (ICH9)"); }

    hda::__reset_for_test();
    bus_reset();
    hda::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }

    let cap = bootstrap_writer();
    let writer = match AudioWriter::open(cap, AudioFormat::default_playback()) {
        Ok(w)  => w,
        Err(_) => return TestResult::Fail("AudioWriter::open"),
    };

    // 1024 bytes = 256 stereo S16 frames = ~5.3 ms @ 48 kHz.
    let silence = [0u8; 1024];
    let frames = match writer.submit(&silence) {
        Ok(f)  => f,
        Err(_) => return TestResult::Fail("submit returned error"),
    };
    if frames != 256 {
        return TestResult::Fail("submit returned wrong frame count");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("audio/hda", smoke_hda_writer_submit_round_trip);
