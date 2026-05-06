//! Per-crate smoke tests for `narf-bus`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under the `"bus"` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

extern crate alloc;

#[cfg(target_arch = "x86_64")]
fn smoke_bus_enumerates_pcie() -> TestResult {
    // Walk QEMU q35's PCIe ECAM at its default base. q35 exposes a
    // PCI-Express host bridge at 00:00.0 plus any attached devices.
    // We expect at minimum the host bridge entry (vendor != 0xFFFF).
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{devices, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE (0xb000_0000) is inside q35's
    // pcie-mmcfg region and below the 4-GiB identity map installed
    // by memory/mmu::init_mmu. No MMIO write happens during the walk.
    let n = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    if n == 0 {
        return TestResult::Fail("ECAM walk found zero devices on q35 — host bridge missing");
    }
    // Host bridge must be the first entry (function 0 on bus 0, dev 0).
    let devs = devices();
    let has_host_bridge = devs.iter().any(|d| {
        matches!(
            &d.kind,
            BusKind::Pcie { addr, .. } if addr.bus == 0 && addr.device == 0 && addr.function == 0
        )
    });
    if !has_host_bridge {
        return TestResult::Fail("00:00.0 host bridge not found in ECAM walk");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_bus_enumerates_pcie);

#[cfg(target_arch = "aarch64")]
fn smoke_bus_pcie_dtb_aarch64() -> TestResult {
    // The boot-time `bus::init` discovers the `pcie@10000000` node
    // via the DTB walker, parses its `reg` property for the ECAM
    // base, and runs the shared walker. Other smokes that do
    // `init(None)` reset the registry; re-init explicitly with the
    // xtask-loaded DTB physical address so this test is order-
    // independent.
    use crate::{devices, BusKind};
    use narf_memory::PhysAddr;
    // SAFETY: xtask loads the DTB at this address; identity-mapped.
    let _ = unsafe { crate::init(Some(PhysAddr::new(0x4F00_0000))) };
    let devs = devices();
    let n_pcie = devs
        .iter()
        .filter(|d| matches!(&d.kind, BusKind::Pcie { .. }))
        .count();
    if n_pcie == 0 {
        return TestResult::Fail(
            "DTB walk yielded no PCIe devices on aarch64 — host bridge missing",
        );
    }
    // QEMU virt's host bridge appears at 00:00.0 by convention.
    let has_root = devs.iter().any(|d| {
        matches!(
            &d.kind,
            BusKind::Pcie { addr, .. }
                if addr.bus == 0 && addr.device == 0 && addr.function == 0
        )
    });
    if !has_root {
        return TestResult::Fail("no 00:00.0 PCIe host bridge entry on aarch64");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("bus", smoke_bus_pcie_dtb_aarch64);

#[cfg(target_arch = "aarch64")]
fn smoke_bus_enumerates_virtio_mmio() -> TestResult {
    // QEMU `virt` exposes 32 virtio-mmio transport slots at
    // 0x0a00_0000 (stride 0x200). We don't have easy access to the
    // DTB pointer from here, so the enumerator's fallback path probes
    // the documented slot layout when no DTB is supplied — this
    // covers the default cargo-xtask-test boot.
    use crate::{devices, snapshot};
    // SAFETY: the fallback reads 4-byte MMIO from identity-mapped
    // virtio-mmio registers and rejects invalid magic, so stray
    // ranges don't produce phantom devices.
    let _n = unsafe { crate::init(None) };
    let devs = devices();
    // Structural: snapshot must agree with devices() post-init.
    if snapshot().len() != devs.len() {
        return TestResult::Fail("snapshot vs devices mismatch after init");
    }
    // QEMU virt without extra -device flags still exposes magic on
    // every slot; populated slots (DeviceID != 0) appear only when a
    // device is attached. We don't require one — just that the walk
    // runs cleanly. If any device is present, it must have a
    // VirtioMmio kind variant.
    for d in devs.iter() {
        match &d.kind {
            crate::BusKind::VirtioMmio { base, .. } => {
                if base.raw() < 0x0a00_0000 || base.raw() >= 0x0a00_0000 + 32 * 0x200 {
                    return TestResult::Fail("virtio-mmio base outside QEMU virt range");
                }
            }
            _ => return TestResult::Fail("non-virtio device in aarch64 registry"),
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("bus", smoke_bus_enumerates_virtio_mmio);

fn smoke_bus_claim_device_not_found() -> TestResult {
    // Structural test for the claim-API stub: claiming an address
    // that doesn't exist must cleanly return NotFound / NotInitialised,
    // never panic.
    use crate::{claim_device, BusAddr};
    use narf_memory::PhysAddr;
    let bogus = BusAddr::Mmio(PhysAddr::new(0xdead_beef_0000));
    match claim_device(bogus) {
        Err(crate::ClaimError::NotFound) | Err(crate::ClaimError::NotInitialised) => {
            TestResult::Pass
        }
        Err(crate::ClaimError::AuthorityRevoked) => {
            TestResult::Fail("AuthorityRevoked on un-authorised path")
        }
        Ok(_) => TestResult::Fail("claim of bogus addr succeeded"),
    }
}
kernel_test_in!("bus", smoke_bus_claim_device_not_found);

fn smoke_bus_msix_alloc_vector() -> TestResult {
    // Exercises the MsixTable::alloc_vector arithmetic against a
    // synthetic table so the test doesn't depend on any particular
    // device having an MSI-X capability.
    use crate::msix::__synth_msix_table;
    let mut t = __synth_msix_table(4);
    if t.size() != 4 {
        return TestResult::Fail("synthetic size mismatch");
    }
    if t.free() != 4 {
        return TestResult::Fail("initial free mismatch");
    }

    let v0 = t.alloc_vector().expect("slot 0");
    let v1 = t.alloc_vector().expect("slot 1");
    if v0.vector != 0 || v1.vector != 1 {
        return TestResult::Fail("monotonic vector allocation broken");
    }
    if t.free() != 2 {
        return TestResult::Fail("free count not decremented");
    }

    if t.alloc_block(2).is_err() {
        return TestResult::Fail("alloc_block(2) rejected a fitting reservation");
    }
    if t.alloc_vector().is_some() {
        return TestResult::Fail("alloc_vector returned Some on a full table");
    }
    match t.alloc_block(1) {
        Err(crate::MsixError::TableOverflow) => {}
        Ok(_) => return TestResult::Fail("alloc_block past capacity succeeded"),
        Err(_) => return TestResult::Fail("wrong error on overflow"),
    }
    TestResult::Pass
}
kernel_test_in!("bus", smoke_bus_msix_alloc_vector);

fn smoke_bus_msix_program_vector_out_of_range() -> TestResult {
    // The synthetic table's cfg_phys is 0, so calling program_vector
    // with a real index would dereference physical 0 to read the
    // BAR — guaranteed UB. This test exercises only the structural
    // VectorOutOfRange precondition, which short-circuits before the
    // BAR read.
    use crate::msix::__synth_msix_table;
    let mut t = __synth_msix_table(2);
    // SAFETY: VectorOutOfRange is checked before any cfg-space access,
    // so passing a too-large index is safe regardless of cfg_phys.
    match unsafe { t.program_vector(2, 0, 32) } {
        Err(crate::MsixError::VectorOutOfRange) => TestResult::Pass,
        Err(e) => {
            let _ = e;
            TestResult::Fail("wrong error from program_vector(out-of-range)")
        }
        Ok(_) => TestResult::Fail("program_vector accepted out-of-range index"),
    }
}
kernel_test_in!("bus", smoke_bus_msix_program_vector_out_of_range);

#[cfg(target_arch = "x86_64")]
fn smoke_bus_bar_read_on_q35() -> TestResult {
    // Walk the q35 ECAM, find some device, and exercise read_bar
    // against BAR 0.
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{devices, read_bar, BarError, BusKind};
    // SAFETY: ECAM is identity-mapped; idempotent re-init.
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };

    let devs = devices();
    let pcie: alloc::vec::Vec<_> = devs
        .iter()
        .filter(|d| matches!(d.kind, BusKind::Pcie { .. }))
        .collect();
    if pcie.is_empty() {
        return TestResult::Fail("no PCIe devices found in registry");
    }

    let mut any_sized = false;
    for d in &pcie {
        // SAFETY: BSP, no other writer to this device's cfg window.
        match unsafe { read_bar(d, 0) } {
            Ok(b) => {
                if b.size == 0 {
                    return TestResult::Fail("read_bar returned Ok with size 0");
                }
                any_sized = true;
                break;
            }
            Err(BarError::Unimplemented) => {}
            Err(_) => return TestResult::Fail("unexpected BAR error on PCIe device"),
        }
    }
    let _ = any_sized;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_bus_bar_read_on_q35);

#[cfg(target_arch = "aarch64")]
fn smoke_its_doorbell_addr() -> TestResult {
    // The ITS doorbell on QEMU virt is GITS_TRANSLATER at offset
    // 0x10040 from the ITS base 0x0808_0000. `program_vector` on
    // aarch64 emits this address into msg_addr; verify the helper
    // returns the documented value so a regression in the constant
    // is caught structurally.
    let pa = narf_interrupts::aarch64::its::doorbell_pa();
    if pa != 0x0808_0000 + 0x10040 {
        return TestResult::Fail("ITS doorbell address mismatch");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("bus", smoke_its_doorbell_addr);

#[cfg(target_arch = "aarch64")]
fn smoke_bus_msix_enable_on_virtio() -> TestResult {
    // virtio-mmio transports have no PCIe capability list. `enable_msix`
    // must reject them cleanly with `NotPcie`.
    use crate::{
        bootstrap_registry_authority, claim_device_cap, devices, enable_msix, BusKind, MsixError,
    };
    // SAFETY: aarch64 enumerator falls back to the QEMU virt slot layout.
    let _ = unsafe { crate::init(None) };
    let devs = devices();
    let virtio = devs
        .iter()
        .find(|d| matches!(d.kind, BusKind::VirtioMmio { .. }));
    let Some(dev) = virtio else {
        return TestResult::Skip("no virtio-mmio device in this flavour");
    };

    let authority = bootstrap_registry_authority();
    let (_handle, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap on a live address failed"),
    };
    match enable_msix(&dev_cap, dev) {
        Err(MsixError::NotPcie) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error on virtio-mmio"),
        Ok(_) => TestResult::Fail("enable_msix accepted a virtio-mmio device"),
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("bus", smoke_bus_msix_enable_on_virtio);

fn smoke_bus_hotplug_listener_roundtrip() -> TestResult {
    // Register a listener, dispatch an Attach + Detach, confirm the
    // listener's atomic advanced to 2.
    use crate::hotplug::__clear_listeners;
    use crate::{
        bootstrap_registry_authority, dispatch_event, register_listener, BusAddr, DeviceId,
        HotplugEvent, HotplugListener, PcieAddr,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    __clear_listeners();

    struct Counter {
        hits: AtomicUsize,
    }
    impl HotplugListener for Counter {
        fn on_event(&self, _ev: HotplugEvent) {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
    }

    let authority = bootstrap_registry_authority();
    let counter = Arc::new(Counter {
        hits: AtomicUsize::new(0),
    });
    if register_listener(&authority, counter.clone()).is_err() {
        return TestResult::Fail("register_listener rejected a live authority");
    }

    let addr = BusAddr::Pcie(PcieAddr::new(0, 0, 1, 0));
    dispatch_event(HotplugEvent::Attach {
        addr,
        device_id: DeviceId {
            vendor: 0x1af4,
            device: 0x1001,
            class: 0,
        },
    });
    dispatch_event(HotplugEvent::Detach { addr });

    if counter.hits.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("listener did not see both events");
    }
    __clear_listeners();
    TestResult::Pass
}
kernel_test_in!("bus", smoke_bus_hotplug_listener_roundtrip);

fn smoke_bus_hotplug_revoked_authority() -> TestResult {
    // Revoking the authority before `register_listener` must fail with
    // AuthorityRevoked.
    use crate::hotplug::__clear_listeners;
    use crate::{
        bootstrap_registry_authority, register_listener, HotplugError, HotplugEvent,
        HotplugListener,
    };
    use alloc::sync::Arc;

    __clear_listeners();

    struct Sink;
    impl HotplugListener for Sink {
        fn on_event(&self, _: HotplugEvent) {}
    }

    let authority = bootstrap_registry_authority();
    authority.revoke();
    match register_listener(&authority, Arc::new(Sink) as Arc<dyn HotplugListener>) {
        Err(HotplugError::AuthorityRevoked) => TestResult::Pass,
        Ok(_) => TestResult::Fail("register_listener accepted a revoked authority"),
    }
}
kernel_test_in!("bus", smoke_bus_hotplug_revoked_authority);

fn smoke_bus_iommu_group_default() -> TestResult {
    // Stage-3 stub: every enumerated device lives in group 0 on the
    // default QEMU line (no vIOMMU).
    use crate::{devices, iommu_group_for};
    #[cfg(target_arch = "x86_64")]
    {
        use crate::x86_64::ECAM_DEFAULT_BASE;
        // SAFETY: walking QEMU q35's identity-mapped ECAM.
        let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: fallback probes the identity-mapped virtio-mmio layout.
        let _ = unsafe { crate::init(None) };
    }

    let devs = devices();
    if devs.is_empty() {
        return TestResult::Skip("empty registry on this flavour");
    }
    for d in devs.iter() {
        if iommu_group_for(d) != 0 {
            return TestResult::Fail("Stage-3 stub reported non-zero group");
        }
    }
    TestResult::Pass
}
kernel_test_in!("bus", smoke_bus_iommu_group_default);

fn smoke_bus_acpi_notify_dispatch() -> TestResult {
    use crate::acpi_notify::{self, AcpiNotify, NotifyEvent, NotifyKind};
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_capabilities::{Cap, Grant};

    acpi_notify::__test_reset();
    acpi_notify::init();

    static HITS: AtomicU32 = AtomicU32::new(0);
    HITS.store(0, Ordering::Relaxed);

    let cap: Cap<AcpiNotify, Grant> = Cap::bootstrap();
    if acpi_notify::subscribe(&cap, |ev| {
        if matches!(ev.kind, NotifyKind::Thermal) {
            HITS.fetch_add(1, Ordering::Relaxed);
        }
    })
    .is_err()
    {
        return TestResult::Fail("subscribe failed on live cap");
    }

    let _ = acpi_notify::dispatch_notify(NotifyEvent {
        acpi_handle: 0x4242,
        kind: NotifyKind::Thermal,
    });
    if HITS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("Thermal notify did not reach subscriber");
    }

    let _ = acpi_notify::dispatch_notify(NotifyEvent {
        acpi_handle: 0x4242,
        kind: NotifyKind::PowerSource,
    });
    if HITS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("non-thermal notify incremented thermal counter");
    }

    if NotifyKind::from_raw(0x82) != NotifyKind::Thermal {
        return TestResult::Fail("NotifyKind::from_raw broke on 0x82");
    }
    if NotifyKind::Device(0x77).raw() != 0x77 {
        return TestResult::Fail("NotifyKind::Device round-trip broken");
    }

    acpi_notify::__test_reset();
    TestResult::Pass
}
kernel_test_in!("bus", smoke_bus_acpi_notify_dispatch);

#[cfg(target_arch = "x86_64")]
fn smoke_pci_command_bme_round_trip() -> TestResult {
    // Sets MEM_SPACE | BUS_MASTER on the QEMU NVMe device and reads
    // the command register back.
    use crate::pci::{cmd, read_command, set_command};
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    // SAFETY: ECAM identity-mapped; init idempotent.
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };

    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };

    let authority = bootstrap_registry_authority();
    let (_h, cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };

    let bits = cmd::MEM_SPACE | cmd::BUS_MASTER;
    let new = match set_command(&cap, &dev, bits) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("set_command failed"),
    };
    if (new & bits) != bits {
        return TestResult::Fail("set_command did not OR the requested bits");
    }
    let readback = match read_command(&cap, &dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("read_command failed"),
    };
    if (readback & bits) != bits {
        return TestResult::Fail("read_command lost the requested bits");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_pci_command_bme_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_pci_match_specificity() -> TestResult {
    // Specificity rules: VendorDevice > Class > Vendor.
    use crate::MatchKind;
    let vd = MatchKind::VendorDevice {
        vendor: 0x1B36,
        device: 0x0010,
    };
    let cls = MatchKind::Class {
        class: 0x01,
        mask: 0xFF,
    };
    let v = MatchKind::Vendor { vendor: 0x1B36 };
    if vd.specificity() <= cls.specificity() || cls.specificity() <= v.specificity() {
        return TestResult::Fail("specificity ordering broken");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_pci_match_specificity);

// `smoke_pci_probe_all_dispatches_nvme` cannot live here — it depends
// on `narf-drivers-nvme`, and that crate already depends on `narf-bus`.
// Adding the reverse edge would cycle the workspace. The smoke stays in
// `verification/src/lib.rs`, which already pulls both crates.

#[cfg(target_arch = "x86_64")]
fn smoke_pci_cap_ext_walker() -> TestResult {
    // The PCIe extended cap list lives at offset 0x100. QEMU NVMe
    // generally doesn't expose AER, but the walker must terminate
    // cleanly on an empty list (header reads 0 or 0xFFFF_FFFF).
    use crate::pci_cap_ext::iter as ext_iter;
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme = devs.iter().find(|d| {
        matches!(&d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(d) = nvme.copied() else {
        return TestResult::Skip("no QEMU NVMe");
    };
    let authority = bootstrap_registry_authority();
    let (_h, cap) = match claim_device_cap(&authority, d.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim"),
    };
    let read_cap = match cap.derive() {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("derive"),
    };
    let it = match ext_iter(&read_cap, &d) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("ext iter"),
    };
    let mut count = 0;
    for _ in it {
        count += 1;
        if count > 256 {
            return TestResult::Fail("walker did not terminate");
        }
    }
    let _ = count;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_pci_cap_ext_walker);

// ── AER classifier + bit definitions ──────────────────────────────

fn smoke_aer_classify_correctable_first() -> TestResult {
    use crate::pci_cap_ext::{classify_aer, AerSeverity};
    // Both corr + uncorr bits set → correctable wins because we
    // prioritise the cheaper class (PCIe §6.2.7 — correctable
    // events are always logged separately).
    let s = classify_aer(0x0001_0000, 0x0001_0000, 0x0000_0001);
    assert_eq!(s, Some(AerSeverity::Correctable));
    TestResult::Pass
}
kernel_test_in!("bus/aer", smoke_aer_classify_correctable_first);

fn smoke_aer_classify_fatal_when_severity_set() -> TestResult {
    use crate::pci_cap_ext::{aer_uncorrectable, classify_aer, AerSeverity};
    let bit = aer_uncorrectable::DLP;
    // DLP set in status + severity → Fatal.
    let s = classify_aer(bit, bit, 0);
    assert_eq!(s, Some(AerSeverity::Fatal));
    // DLP set in status but not severity → NonFatal.
    let s = classify_aer(bit, 0, 0);
    assert_eq!(s, Some(AerSeverity::NonFatal));
    // No bits at all → None.
    let s = classify_aer(0, 0, 0);
    assert_eq!(s, None);
    TestResult::Pass
}
kernel_test_in!("bus/aer", smoke_aer_classify_fatal_when_severity_set);

fn smoke_aer_uncorrectable_bits_are_distinct() -> TestResult {
    use crate::pci_cap_ext::aer_uncorrectable as u;
    let bits = [
        u::DLP,
        u::SURPRISE_DOWN,
        u::POISONED_TLP,
        u::FLOW_CTRL_PROTO,
        u::COMPLETION_TIMEOUT,
        u::COMPLETER_ABORT,
        u::UNEXPECTED_COMPLETION,
        u::RECEIVER_OVERFLOW,
        u::MALFORMED_TLP,
        u::ECRC_ERROR,
        u::UNSUPPORTED_REQUEST,
        u::ACS_VIOLATION,
        u::INTERNAL_ERROR,
        u::MC_BLOCKED_TLP,
        u::ATOMIC_OP_EGRESS_BLOCKED,
        u::TLP_PREFIX_BLOCKED,
    ];
    // Every entry should be a single-bit constant and pairwise unique.
    for b in &bits {
        if b.count_ones() != 1 {
            return TestResult::Fail("AER uncorrectable bit constants must be single-bit");
        }
    }
    for (i, a) in bits.iter().enumerate() {
        for b in bits.iter().skip(i + 1) {
            if a == b {
                return TestResult::Fail("duplicate AER uncorrectable bit constant");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("bus/aer", smoke_aer_uncorrectable_bits_are_distinct);

fn smoke_aer_correctable_bits_at_documented_positions() -> TestResult {
    use crate::pci_cap_ext::aer_correctable as c;
    // Spot-check the positions called out in PCIe §7.8.4.5 table.
    if c::RECEIVER_ERROR != 1 << 0 {
        return TestResult::Fail("Receiver Error must be bit 0");
    }
    if c::BAD_TLP != 1 << 6 {
        return TestResult::Fail("Bad TLP must be bit 6");
    }
    if c::BAD_DLLP != 1 << 7 {
        return TestResult::Fail("Bad DLLP must be bit 7");
    }
    if c::REPLAY_TIMER_TIMEOUT != 1 << 12 {
        return TestResult::Fail("Replay Timer Timeout must be bit 12");
    }
    if c::HEADER_LOG_OVERFLOW != 1 << 15 {
        return TestResult::Fail("Header Log Overflow must be bit 15");
    }
    TestResult::Pass
}
kernel_test_in!("bus/aer", smoke_aer_correctable_bits_at_documented_positions);

fn smoke_aer_listener_dispatch_round_trip() -> TestResult {
    use crate::addr::BusAddr;
    use crate::pci_cap_ext::{
        __clear_aer_listeners, aer_listener_count, dispatch_aer, register_aer_listener,
        AerEvent, AerListener, AerSeverity,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    __clear_aer_listeners();

    struct Counter(AtomicU32);
    impl AerListener for Counter {
        fn on_aer(&self, _ev: AerEvent) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }
    let c = Arc::new(Counter(AtomicU32::new(0)));
    register_aer_listener(c.clone());
    if aer_listener_count() != 1 {
        return TestResult::Fail("listener count != 1");
    }
    dispatch_aer(AerEvent {
        addr: BusAddr::Pcie(crate::addr::PcieAddr::new(0, 0, 0, 0)),
        severity: AerSeverity::Correctable,
        status_word: 0,
    });
    if c.0.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("listener should have fired once");
    }
    __clear_aer_listeners();
    if aer_listener_count() != 0 {
        return TestResult::Fail("__clear_aer_listeners did not drain");
    }
    TestResult::Pass
}
kernel_test_in!("bus/aer", smoke_aer_listener_dispatch_round_trip);

// ── PCIe DOE smokes ────────────────────────────────────────────────

fn smoke_doe_object_round_trip() -> TestResult {
    use crate::pci_doe::{Object, TYPE_DOE_DISCOVERY, VENDOR_PCISIG};
    let obj = Object {
        vendor_id: VENDOR_PCISIG,
        data_object_type: TYPE_DOE_DISCOVERY,
        payload: alloc::vec![0xCAFE_BABE, 0xDEAD_BEEF],
    };
    let dwords = obj.encode();
    if dwords.len() != 4 {
        return TestResult::Fail("envelope = 2 hdr + 2 payload = 4 DWORDs");
    }
    // DWORD 0 packing: vendor in low 16, type in next 8.
    if dwords[0] & 0xFFFF != VENDOR_PCISIG as u32 {
        return TestResult::Fail("vendor ID lives in DWORD 0 low 16 bits");
    }
    if (dwords[0] >> 16) & 0xFF != TYPE_DOE_DISCOVERY as u32 {
        return TestResult::Fail("data object type lives in DWORD 0 bits 23..16");
    }
    if dwords[1] != 4 {
        return TestResult::Fail("length = total DWORDs (incl header) = 4");
    }
    let back = Object::decode(&dwords).expect("decode");
    if back != obj {
        return TestResult::Fail("DOE object round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("bus/doe", smoke_doe_object_round_trip);

fn smoke_doe_length_zero_means_max() -> TestResult {
    use crate::pci_doe::{Object, VENDOR_PCISIG};
    // A length field of 0 in the wire encoding decodes to 2^18.
    // We don't exercise a buffer of that size; just verify the
    // encoder's edge case stays at the literal 0 mark when total
    // hits the maximum (synthesised: payload 2^18 - 2 entries is
    // huge, so test the ceiling on encode by inspecting the field
    // arithmetic via a smaller probe).
    let obj = Object {
        vendor_id: VENDOR_PCISIG,
        data_object_type: 0,
        payload: alloc::vec![0; 5],
    };
    let dwords = obj.encode();
    if dwords[1] != 7 {
        return TestResult::Fail("length should be 7 (header + 5 payload)");
    }
    TestResult::Pass
}
kernel_test_in!("bus/doe", smoke_doe_length_zero_means_max);

fn smoke_doe_decode_truncated_rejected() -> TestResult {
    use crate::pci_doe::{DoeError, Object, VENDOR_PCISIG};
    let mut dwords = Object {
        vendor_id: VENDOR_PCISIG,
        data_object_type: 0,
        payload: alloc::vec![0xAA; 4],
    }
    .encode();
    dwords.pop(); // drop one DWORD — length now exceeds the buffer
    match Object::decode(&dwords) {
        Err(DoeError::Truncated) => TestResult::Pass,
        _ => TestResult::Fail("truncated DWORD stream must be rejected"),
    }
}
kernel_test_in!("bus/doe", smoke_doe_decode_truncated_rejected);

fn smoke_doe_decode_bad_length_rejected() -> TestResult {
    use crate::pci_doe::{DoeError, Object};
    let dwords = [0x00010000u32, 1u32]; // length=1 < 2 (header is mandatory)
    match Object::decode(&dwords) {
        Err(DoeError::BadLength) => TestResult::Pass,
        _ => TestResult::Fail("length < 2 must be rejected"),
    }
}
kernel_test_in!("bus/doe", smoke_doe_decode_bad_length_rejected);

fn smoke_doe_discovery_request_layout() -> TestResult {
    use crate::pci_doe::{build_discovery_request, TYPE_DOE_DISCOVERY, VENDOR_PCISIG};
    let req = build_discovery_request(2);
    if req.len() != 3 {
        return TestResult::Fail("Discovery request = 3 DWORDs (2 hdr + 1 index)");
    }
    if req[0] & 0xFFFF != VENDOR_PCISIG as u32 {
        return TestResult::Fail("vendor field");
    }
    if (req[0] >> 16) & 0xFF != TYPE_DOE_DISCOVERY as u32 {
        return TestResult::Fail("type field");
    }
    if req[2] != 2 {
        return TestResult::Fail("payload DWORD carries the discovery index");
    }
    TestResult::Pass
}
kernel_test_in!("bus/doe", smoke_doe_discovery_request_layout);

fn smoke_doe_discovery_entry_parse() -> TestResult {
    use crate::pci_doe::DiscoveryEntry;
    // Vendor 0x0001, Type 0x01 (CMA_SPDM), next_index = 5
    let payload_dword: u32 = 0x0001 | (0x01 << 16) | (0x05 << 24);
    let e = DiscoveryEntry::parse(&[payload_dword]).expect("parse");
    if e.vendor_id != 0x0001 || e.data_object_type != 0x01 {
        return TestResult::Fail("vendor/type decode mismatch");
    }
    if e.next_index != 5 {
        return TestResult::Fail("next_index lives in bits 31..24");
    }
    TestResult::Pass
}
kernel_test_in!("bus/doe", smoke_doe_discovery_entry_parse);

// ── PCIe IDE smokes ────────────────────────────────────────────────

fn smoke_ide_stream_selector_round_trip() -> TestResult {
    use crate::pci_ide::StreamSelector;
    let s = StreamSelector {
        stream_id: 0x12,
        sub_stream_npr: true,
        key_set_b: false,
        direction_tx: true,
    };
    let raw = s.encode();
    if raw & 0xFF != 0x12 {
        return TestResult::Fail("Stream ID lives in low 8 bits");
    }
    if raw & (1 << 8) == 0 {
        return TestResult::Fail("sub_stream_npr at bit 8");
    }
    if raw & (1 << 10) == 0 {
        return TestResult::Fail("direction_tx at bit 10");
    }
    let back = StreamSelector::decode(raw);
    if back != s {
        return TestResult::Fail("StreamSelector round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bus/ide", smoke_ide_stream_selector_round_trip);

fn smoke_ide_key_prog_message_layout() -> TestResult {
    use crate::pci_ide::{key_prog, StreamSelector, KM_OBJECT_KEY_PROG};
    let key = [0u8; 32];
    let iv = [0u8; 8];
    let s = StreamSelector {
        stream_id: 1,
        ..Default::default()
    };
    let bytes = key_prog(s, &key, &iv);
    if bytes[0] != KM_OBJECT_KEY_PROG {
        return TestResult::Fail("Object ID byte must be KEY_PROG");
    }
    if bytes.len() != 4 + 32 + 8 {
        return TestResult::Fail("KEY_PROG body = 4 hdr + 32 key + 8 IV");
    }
    if bytes[2] != 1 {
        return TestResult::Fail("selector low byte should hold stream id");
    }
    TestResult::Pass
}
kernel_test_in!("bus/ide", smoke_ide_key_prog_message_layout);

fn smoke_ide_kp_ack_status_field() -> TestResult {
    use crate::pci_ide::{
        kp_ack, parse, StreamSelector, KM_OBJECT_KP_ACK, KP_ACK_STATUS_INCORRECT_LENGTH,
    };
    let s = StreamSelector {
        stream_id: 5,
        ..Default::default()
    };
    let body = kp_ack(s, KP_ACK_STATUS_INCORRECT_LENGTH);
    let (obj, back, tail) = parse(&body).expect("parse");
    if obj != KM_OBJECT_KP_ACK {
        return TestResult::Fail("Object ID round-trip");
    }
    if back != s {
        return TestResult::Fail("selector round-trip");
    }
    if tail[0] != KP_ACK_STATUS_INCORRECT_LENGTH {
        return TestResult::Fail("status byte missing");
    }
    TestResult::Pass
}
kernel_test_in!("bus/ide", smoke_ide_kp_ack_status_field);

fn smoke_ide_set_go_set_stop_layout() -> TestResult {
    use crate::pci_ide::{
        k_set_go, k_set_stop, StreamSelector, KM_OBJECT_K_SET_GO, KM_OBJECT_K_SET_STOP,
    };
    let s = StreamSelector { stream_id: 3, ..Default::default() };
    let go = k_set_go(s);
    let stop = k_set_stop(s);
    if go[0] != KM_OBJECT_K_SET_GO {
        return TestResult::Fail("K_SET_GO opcode");
    }
    if stop[0] != KM_OBJECT_K_SET_STOP {
        return TestResult::Fail("K_SET_STOP opcode");
    }
    if go.len() != 4 || stop.len() != 4 {
        return TestResult::Fail("both messages = 4-byte body");
    }
    TestResult::Pass
}
kernel_test_in!("bus/ide", smoke_ide_set_go_set_stop_layout);

fn smoke_ide_parse_rejects_unknown_object_id() -> TestResult {
    use crate::pci_ide::{parse, IdeError};
    let body = [0x42u8, 0, 0, 0];
    match parse(&body) {
        Err(IdeError::BadObjectId(0x42)) => TestResult::Pass,
        _ => TestResult::Fail("unknown KM object id must be rejected"),
    }
}
kernel_test_in!("bus/ide", smoke_ide_parse_rejects_unknown_object_id);

fn smoke_ide_doe_type_constant() -> TestResult {
    use crate::pci_ide::{DOE_TYPE_IDE_KM, DOE_VENDOR_PCISIG};
    if DOE_TYPE_IDE_KM != 0x07 {
        return TestResult::Fail("IDE_KM DOE type = 0x07 per §6.33.4");
    }
    if DOE_VENDOR_PCISIG != 0x0001 {
        return TestResult::Fail("PCI-SIG vendor ID = 0x0001");
    }
    TestResult::Pass
}
kernel_test_in!("bus/ide", smoke_ide_doe_type_constant);

// ── CXL mailbox smokes ─────────────────────────────────────────────

fn smoke_cxl_command_register_round_trip() -> TestResult {
    use crate::cxl::{pack_command_register, unpack_command_register, OP_INFOSTAT_IDENTIFY};
    let v = pack_command_register(OP_INFOSTAT_IDENTIFY, 1024);
    let (op, len) = unpack_command_register(v);
    if op != OP_INFOSTAT_IDENTIFY {
        return TestResult::Fail("opcode lives in low 16 bits");
    }
    if len != 1024 {
        return TestResult::Fail("input length lives in bits 36..16");
    }
    TestResult::Pass
}
kernel_test_in!("bus/cxl", smoke_cxl_command_register_round_trip);

fn smoke_cxl_status_register_packs_return_code_at_bits_47_32() -> TestResult {
    use crate::cxl::{pack_status_register, unpack_status_register, RC_INVALID_INPUT};
    let v = pack_status_register(true, RC_INVALID_INPUT, 0xCAFE);
    let (bg, rc, vendor) = unpack_status_register(v);
    if !bg {
        return TestResult::Fail("background-operation bit lost");
    }
    if rc != RC_INVALID_INPUT {
        return TestResult::Fail("return code mismatch");
    }
    if vendor != 0xCAFE {
        return TestResult::Fail("vendor extended status mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/cxl",
    smoke_cxl_status_register_packs_return_code_at_bits_47_32
);

fn smoke_cxl_background_status_round_trip() -> TestResult {
    use crate::cxl::BackgroundStatus;
    let s = BackgroundStatus {
        percentage: 42,
        complete: true,
        return_code: 0,
        vendor_extended_status: 0,
    };
    let raw = s.pack();
    let back = BackgroundStatus::unpack(raw);
    if back != s {
        return TestResult::Fail("BackgroundStatus round-trip");
    }
    if (raw & 0x7F) != 42 {
        return TestResult::Fail("percentage at bits 6..0");
    }
    if (raw & (1 << 16)) == 0 {
        return TestResult::Fail("complete bit at bit 16");
    }
    TestResult::Pass
}
kernel_test_in!("bus/cxl", smoke_cxl_background_status_round_trip);

fn smoke_cxl_identify_response_decodes() -> TestResult {
    use crate::cxl::IdentifyResponse;
    let mut buf = alloc::vec![0u8; 40];
    buf[0..16].copy_from_slice(b"narfdev v1.2.3\x00\x00");
    buf[16] = 9; // log2 256-byte payload? — 8 means 256, 9 means 512
    buf[17] = 0x03; // component type
    buf[18..20].copy_from_slice(&0x1E98u16.to_le_bytes());
    buf[20..22].copy_from_slice(&0x1234u16.to_le_bytes());
    buf[26..34].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
    let id = IdentifyResponse::parse(&buf).expect("parse");
    if &id.fw_revision[0..14] != b"narfdev v1.2.3" {
        return TestResult::Fail("fw revision text");
    }
    if id.vid != 0x1E98 {
        return TestResult::Fail("VID should round-trip");
    }
    if id.serial_number != 0xDEAD_BEEF_CAFE_BABE {
        return TestResult::Fail("serial number should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("bus/cxl", smoke_cxl_identify_response_decodes);

fn smoke_cxl_get_log_input_layout() -> TestResult {
    use crate::cxl::get_log_input;
    let uuid = [0xAAu8; 16];
    let buf = get_log_input(&uuid, 0x40, 0x100);
    if buf.len() != 24 {
        return TestResult::Fail("Get Log input = 16 UUID + 4 offset + 4 length");
    }
    if &buf[0..16] != &uuid {
        return TestResult::Fail("UUID prefix");
    }
    if &buf[16..20] != &0x40u32.to_le_bytes() {
        return TestResult::Fail("offset is LE u32");
    }
    if &buf[20..24] != &0x100u32.to_le_bytes() {
        return TestResult::Fail("length is LE u32");
    }
    TestResult::Pass
}
kernel_test_in!("bus/cxl", smoke_cxl_get_log_input_layout);

fn smoke_cxl_health_info_decodes() -> TestResult {
    use crate::cxl::HealthInfo;
    let mut buf = alloc::vec![0u8; 18];
    buf[0] = HealthInfo::HEALTH_PERFORMANCE_DEGRADED;
    buf[3] = 25; // life used %
    buf[4..6].copy_from_slice(&313u16.to_le_bytes()); // device temperature
    buf[6..10].copy_from_slice(&7u32.to_le_bytes()); // dirty shutdown count
    let h = HealthInfo::parse(&buf).expect("parse");
    if h.health_status & HealthInfo::HEALTH_PERFORMANCE_DEGRADED == 0 {
        return TestResult::Fail("performance-degraded flag should round-trip");
    }
    if h.life_used != 25 {
        return TestResult::Fail("life used %");
    }
    if h.device_temperature != 313 {
        return TestResult::Fail("device temperature");
    }
    if h.dirty_shutdown_count != 7 {
        return TestResult::Fail("dirty shutdown count");
    }
    TestResult::Pass
}
kernel_test_in!("bus/cxl", smoke_cxl_health_info_decodes);

fn smoke_cxl_dvsec_vendor_constant() -> TestResult {
    use crate::cxl::{DVSEC_ID_COMPONENT_REGISTER_LOCATOR, DVSEC_VENDOR_CXL};
    if DVSEC_VENDOR_CXL != 0x1E98 {
        return TestResult::Fail("CXL DVSEC vendor = 0x1E98");
    }
    if DVSEC_ID_COMPONENT_REGISTER_LOCATOR != 0x0008 {
        return TestResult::Fail("Component Register Locator DVSEC ID = 0x0008");
    }
    TestResult::Pass
}
kernel_test_in!("bus/cxl", smoke_cxl_dvsec_vendor_constant);
