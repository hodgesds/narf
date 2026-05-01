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
    use crate::{devices, BusKind};
    use crate::x86_64::ECAM_DEFAULT_BASE;
    // SAFETY: ECAM_DEFAULT_BASE (0xb000_0000) is inside q35's
    // pcie-mmcfg region and below the 4-GiB identity map installed
    // by memory/mmu::init_mmu. No MMIO write happens during the walk.
    let n = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    if n == 0 {
        return TestResult::Fail("ECAM walk found zero devices on q35 — host bridge missing");
    }
    // Host bridge must be the first entry (function 0 on bus 0, dev 0).
    let devs = devices();
    let has_host_bridge = devs.iter().any(|d| matches!(
        &d.kind,
        BusKind::Pcie { addr, .. } if addr.bus == 0 && addr.device == 0 && addr.function == 0
    ));
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
    let _ = unsafe {
        crate::init(Some(PhysAddr::new(0x4F00_0000)))
    };
    let devs = devices();
    let n_pcie = devs.iter()
        .filter(|d| matches!(&d.kind, BusKind::Pcie { .. }))
        .count();
    if n_pcie == 0 {
        return TestResult::Fail(
            "DTB walk yielded no PCIe devices on aarch64 — host bridge missing");
    }
    // QEMU virt's host bridge appears at 00:00.0 by convention.
    let has_root = devs.iter().any(|d| matches!(
        &d.kind,
        BusKind::Pcie { addr, .. }
            if addr.bus == 0 && addr.device == 0 && addr.function == 0
    ));
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
        Err(crate::ClaimError::NotFound)
        | Err(crate::ClaimError::NotInitialised) => TestResult::Pass,
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
    if t.size() != 4 { return TestResult::Fail("synthetic size mismatch"); }
    if t.free() != 4 { return TestResult::Fail("initial free mismatch"); }

    let v0 = t.alloc_vector().expect("slot 0");
    let v1 = t.alloc_vector().expect("slot 1");
    if v0.vector != 0 || v1.vector != 1 {
        return TestResult::Fail("monotonic vector allocation broken");
    }
    if t.free() != 2 { return TestResult::Fail("free count not decremented"); }

    if t.alloc_block(2).is_err() {
        return TestResult::Fail("alloc_block(2) rejected a fitting reservation");
    }
    if t.alloc_vector().is_some() {
        return TestResult::Fail("alloc_vector returned Some on a full table");
    }
    match t.alloc_block(1) {
        Err(crate::MsixError::TableOverflow) => {}
        Ok(_)  => return TestResult::Fail("alloc_block past capacity succeeded"),
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
        Ok(_)  => TestResult::Fail("program_vector accepted out-of-range index"),
    }
}
kernel_test_in!("bus", smoke_bus_msix_program_vector_out_of_range);

#[cfg(target_arch = "x86_64")]
fn smoke_bus_bar_read_on_q35() -> TestResult {
    // Walk the q35 ECAM, find some device, and exercise read_bar
    // against BAR 0.
    use crate::{devices, read_bar, BarError, BusKind};
    use crate::x86_64::ECAM_DEFAULT_BASE;
    // SAFETY: ECAM is identity-mapped; idempotent re-init.
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };

    let devs = devices();
    let pcie: alloc::vec::Vec<_> = devs.iter()
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
        bootstrap_registry_authority, claim_device_cap, devices, enable_msix,
        BusKind, MsixError,
    };
    // SAFETY: aarch64 enumerator falls back to the QEMU virt slot layout.
    let _ = unsafe { crate::init(None) };
    let devs = devices();
    let virtio = devs.iter().find(|d| matches!(d.kind, BusKind::VirtioMmio { .. }));
    let Some(dev) = virtio else {
        return TestResult::Skip("no virtio-mmio device in this flavour");
    };

    let authority = bootstrap_registry_authority();
    let (_handle, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok)  => ok,
        Err(_)  => return TestResult::Fail("claim_device_cap on a live address failed"),
    };
    match enable_msix(&dev_cap, dev) {
        Err(MsixError::NotPcie) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error on virtio-mmio"),
        Ok(_)  => TestResult::Fail("enable_msix accepted a virtio-mmio device"),
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("bus", smoke_bus_msix_enable_on_virtio);

fn smoke_bus_hotplug_listener_roundtrip() -> TestResult {
    // Register a listener, dispatch an Attach + Detach, confirm the
    // listener's atomic advanced to 2.
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use crate::hotplug::__clear_listeners;
    use crate::{
        bootstrap_registry_authority, dispatch_event, register_listener, BusAddr, DeviceId,
        HotplugEvent, HotplugListener, PcieAddr,
    };

    __clear_listeners();

    struct Counter { hits: AtomicUsize }
    impl HotplugListener for Counter {
        fn on_event(&self, _ev: HotplugEvent) {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
    }

    let authority = bootstrap_registry_authority();
    let counter = Arc::new(Counter { hits: AtomicUsize::new(0) });
    if register_listener(&authority, counter.clone()).is_err() {
        return TestResult::Fail("register_listener rejected a live authority");
    }

    let addr = BusAddr::Pcie(PcieAddr::new(0, 0, 1, 0));
    dispatch_event(HotplugEvent::Attach {
        addr,
        device_id: DeviceId { vendor: 0x1af4, device: 0x1001, class: 0 },
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
    use alloc::sync::Arc;
    use crate::hotplug::__clear_listeners;
    use crate::{
        bootstrap_registry_authority, register_listener, HotplugError, HotplugEvent,
        HotplugListener,
    };

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
    use core::sync::atomic::{AtomicU32, Ordering};
    use crate::acpi_notify::{
        self, AcpiNotify, NotifyEvent, NotifyKind,
    };
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
    }).is_err() {
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
    use crate::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use crate::pci::{cmd, read_command, set_command};
    use crate::x86_64::ECAM_DEFAULT_BASE;
    // SAFETY: ECAM identity-mapped; init idempotent.
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };

    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. })
            && d.id.vendor == 0x1B36
            && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };

    let authority = bootstrap_registry_authority();
    let (_h, cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok)  => ok,
        Err(_)  => return TestResult::Fail("claim_device_cap failed"),
    };

    let bits = cmd::MEM_SPACE | cmd::BUS_MASTER;
    let new = match set_command(&cap, &dev, bits) {
        Ok(v)  => v,
        Err(_) => return TestResult::Fail("set_command failed"),
    };
    if (new & bits) != bits {
        return TestResult::Fail("set_command did not OR the requested bits");
    }
    let readback = match read_command(&cap, &dev) {
        Ok(v)  => v,
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
    let vd = MatchKind::VendorDevice { vendor: 0x1B36, device: 0x0010 };
    let cls = MatchKind::Class { class: 0x01, mask: 0xFF };
    let v   = MatchKind::Vendor { vendor: 0x1B36 };
    if vd.specificity() <= cls.specificity()
        || cls.specificity() <= v.specificity() {
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
    use crate::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use crate::pci_cap_ext::iter as ext_iter;
    use crate::x86_64::ECAM_DEFAULT_BASE;
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme = devs.iter().find(|d|
        matches!(&d.kind, BusKind::Pcie { .. })
        && d.id.vendor == 0x1B36 && d.id.device == 0x0010);
    let Some(d) = nvme.copied() else { return TestResult::Skip("no QEMU NVMe"); };
    let authority = bootstrap_registry_authority();
    let (_h, cap) = match claim_device_cap(&authority, d.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim"),
    };
    let read_cap = match cap.derive() {
        Ok(c)  => c,
        Err(_) => return TestResult::Fail("derive"),
    };
    let it = match ext_iter(&read_cap, &d) {
        Ok(i)  => i,
        Err(_) => return TestResult::Fail("ext iter"),
    };
    let mut count = 0;
    for _ in it { count += 1; if count > 256 { return TestResult::Fail("walker did not terminate"); } }
    let _ = count;
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_pci_cap_ext_walker);
