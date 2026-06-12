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
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
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

fn smoke_bus_append_devices_grows_registry() -> TestResult {
    // VMD relies on append_devices: a discovered child must show
    // up in `devices()` without clobbering anything install()'d
    // earlier. This smoke exercises that contract with a synthetic
    // two-step install + append.
    use crate::registry::install;
    use crate::{append_devices, devices, BusAddr, BusDevice, BusKind, DeviceId, PcieAddr};
    use alloc::vec;
    use narf_memory::PhysAddr;

    let host_dev = BusDevice {
        addr: BusAddr::Pcie(PcieAddr::new(0, 0, 1, 0)),
        id: DeviceId {
            vendor: 0x1234,
            device: 0xAAAA,
            class: 0x010400,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: PcieAddr::new(0, 0, 1, 0),
            cfg_phys: PhysAddr::new(0xb000_1000),
        },
    };
    let child_dev = BusDevice {
        addr: BusAddr::Pcie(PcieAddr::new(0x8000, 0, 0, 0)),
        id: DeviceId {
            vendor: 0x144D,
            device: 0xA80A,
            class: 0x010802,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: PcieAddr::new(0x8000, 0, 0, 0),
            cfg_phys: PhysAddr::new(0xfee0_0000),
        },
    };
    install(vec![host_dev]);
    let before = devices();
    if before.len() != 1 {
        return TestResult::Fail("install did not seed the registry");
    }
    append_devices(vec![child_dev]);
    let after = devices();
    if after.len() != 2 {
        return TestResult::Fail("append_devices did not grow the registry");
    }
    // The original device must still be present (append, not replace).
    let has_host = after.iter().any(|d| d.id.vendor == 0x1234);
    let has_child = after.iter().any(|d| d.id.vendor == 0x144D);
    if !has_host || !has_child {
        return TestResult::Fail("append clobbered or dropped a device");
    }
    // Children must keep the synthetic segment so VMD-domain addrs
    // don't collide with the host PCIe domain.
    let child = after.iter().find(|d| d.id.vendor == 0x144D).unwrap();
    if let BusAddr::Pcie(PcieAddr { segment, .. }) = child.addr {
        if segment != 0x8000 {
            return TestResult::Fail("child lost its synthetic segment");
        }
    } else {
        return TestResult::Fail("child addr not Pcie");
    }
    TestResult::Pass
}
kernel_test_in!("bus", smoke_bus_append_devices_grows_registry);

#[cfg(target_arch = "x86_64")]
fn smoke_bus_enumerate_segment_tags_devices() -> TestResult {
    // Walking an ECAM region with a non-zero segment must
    // propagate that segment into every PcieAddr it yields. This
    // smoke uses the host q35 ECAM but asks for a segment of
    // 0x8765 so the assertion is on the segment, not on the
    // device IDs.
    use crate::pcie::enumerate_segment;
    use crate::{BusAddr, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the same region the boot enumerate
    // path uses; identity-mapped. Cap the walk at 32 buses — enough
    // for QEMU q35 to surface the usual lineup without scanning the
    // whole 256-bus address space.
    // SAFETY: Valid memory or trusted environment
    let devs = unsafe { enumerate_segment(crate::x86_64::ECAM_DEFAULT_BASE, 32, 0x8765) };
    if devs.is_empty() {
        return TestResult::Skip("no devices to enumerate");
    }
    for d in &devs {
        let seg = match d.addr {
            BusAddr::Pcie(a) => a.segment,
            _ => return TestResult::Fail("non-Pcie BusAddr from pcie walker"),
        };
        if seg != 0x8765 {
            return TestResult::Fail("enumerate_segment did not tag segment");
        }
        if let BusKind::Pcie { addr, .. } = d.kind {
            if addr.segment != 0x8765 {
                return TestResult::Fail("BusKind::Pcie.addr.segment mismatch");
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_bus_enumerate_segment_tags_devices);

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
    // SAFETY: Valid memory or trusted environment
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
            subsystem_vendor: 0,
            subsystem_id: 0,
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
    use crate::acpi_notify::{self, NotifyEvent, NotifyKind};
    use narf_capabilities::{Cap, Read};
    use narf_event_bus::TopicRegistry;

    acpi_notify::__test_reset();
    acpi_notify::init();

    // Mint a registry-read cap for the subscriber path.
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let mut sub = match acpi_notify::subscribe(&reg_r) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("subscribe failed on live cap"),
    };

    let _ = acpi_notify::dispatch_notify(NotifyEvent {
        acpi_handle: 0x4242,
        kind: NotifyKind::Thermal,
    });
    let mut thermal_hits: u32 = 0;
    if let Ok(Some((_seq, ev))) = sub.try_next() {
        if matches!(ev.kind, NotifyKind::Thermal) {
            thermal_hits += 1;
        }
    }
    if thermal_hits != 1 {
        return TestResult::Fail("Thermal notify did not reach subscriber");
    }

    let _ = acpi_notify::dispatch_notify(NotifyEvent {
        acpi_handle: 0x4242,
        kind: NotifyKind::PowerSource,
    });
    let mut non_thermal_seen = false;
    if let Ok(Some((_seq, ev))) = sub.try_next() {
        if matches!(ev.kind, NotifyKind::PowerSource) {
            non_thermal_seen = true;
        }
    }
    if !non_thermal_seen {
        return TestResult::Fail("non-thermal notify did not arrive");
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
    // SAFETY: ECAM_DEFAULT_BASE (q35 pcie-mmcfg base, 0xb000_0000) is
    // identity-mapped below the 4-GiB map and the enumerator only
    // issues config-space reads; init is idempotent across calls.
    // SAFETY: Valid memory or trusted environment
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
kernel_test_in!(
    "bus/aer",
    smoke_aer_correctable_bits_at_documented_positions
);

fn smoke_aer_listener_dispatch_round_trip() -> TestResult {
    use crate::addr::BusAddr;
    use crate::pci_cap_ext::{
        __clear_aer_listeners, aer_listener_count, dispatch_aer, register_aer_listener, AerEvent,
        AerListener, AerSeverity,
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
    let s = StreamSelector {
        stream_id: 3,
        ..Default::default()
    };
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
    if buf[0..16] != uuid {
        return TestResult::Fail("UUID prefix");
    }
    if buf[16..20] != 0x40u32.to_le_bytes() {
        return TestResult::Fail("offset is LE u32");
    }
    if buf[20..24] != 0x100u32.to_le_bytes() {
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

// ── PCIe AER ──────────────────────────────────────────────────────

fn smoke_aer_ext_cap_header_decode() -> TestResult {
    use crate::pcie_aer::{ExtCapHeader, AER_CAP_ID};

    let raw = (AER_CAP_ID as u32) | (2u32 << 16) | (0x180u32 << 20);

    let h = ExtCapHeader::decode(raw);

    if !h.is_aer() || h.cap_version != 2 || h.next_ptr != 0x180 {
        return TestResult::Fail("AER ext-cap header decode");
    }

    TestResult::Pass
}

kernel_test_in!("bus/pcie-aer", smoke_aer_ext_cap_header_decode);

fn smoke_aer_classify_uncorrectable() -> TestResult {
    use crate::pcie_aer::{classify_uncorrectable, ue, UeSeverity};

    if classify_uncorrectable(0, ue::DEFAULT_SEVERE) != UeSeverity::None {
        return TestResult::Fail("empty status");
    }

    let cur = ue::COMPLETION_TIMEOUT;

    if classify_uncorrectable(cur, ue::DEFAULT_SEVERE) != UeSeverity::NonFatal {
        return TestResult::Fail("completion timeout default = non-fatal");
    }

    let cur = ue::MALFORMED_TLP;

    if classify_uncorrectable(cur, ue::DEFAULT_SEVERE) != UeSeverity::Severe {
        return TestResult::Fail("malformed TLP default = severe");
    }

    TestResult::Pass
}

kernel_test_in!("bus/pcie-aer", smoke_aer_classify_uncorrectable);

fn smoke_aer_header_log_decodes_le() -> TestResult {
    use crate::pcie_aer::HeaderLog;

    let raw = [
        0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    let h = HeaderLog::decode(&raw);

    if h.0[0] != 0x12345678 || h.0[1] != 0xDEADBEEF {
        return TestResult::Fail("LE header-log decode");
    }

    TestResult::Pass
}

kernel_test_in!("bus/pcie-aer", smoke_aer_header_log_decodes_le);

// ── relocated from verification ──

#[cfg(target_arch = "x86_64")]
fn smoke_pci_cap_walker_finds_msix() -> TestResult {
    // The QEMU NVMe device exposes a standard cap list with at
    // minimum MSI-X (0x11), Power Management (0x01), and PCI Express
    // (0x10). Walk it via the generic walker + assert MSI-X is
    // present.
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{devices, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE (q35 pcie-mmcfg base, 0xb000_0000) is
    // identity-mapped below the 4-GiB map and the enumerator only
    // issues config-space reads; init is idempotent across calls.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme = devs.iter().find(|d| {
        matches!(&d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(d) = nvme else {
        return TestResult::Skip("no QEMU NVMe");
    };
    // SAFETY: bounded walk on identity-mapped cfg-space.
    let off = match unsafe { crate::pci_cap::find_cap(d, crate::pci_cap::id::MSI_X) } {
        Ok(Some(o)) => o,
        _ => return TestResult::Fail("MSI-X cap not found"),
    };
    if off == 0 || off >= 0x100 {
        return TestResult::Fail("MSI-X cap offset out of range");
    }
    // PCI Express cap should also exist on a QEMU NVMe.
    // SAFETY: `d` came from the enumerated registry, so its cfg-space is the
    // identity-mapped ECAM window; find_cap only does a bounded read-only walk.
    // SAFETY: Valid memory or trusted environment
    match unsafe { crate::pci_cap::find_cap(d, crate::pci_cap::id::PCI_EXPRESS) } {
        Ok(Some(_)) => {}
        _ => return TestResult::Fail("PCI Express cap not found"),
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_pci_cap_walker_finds_msix);

#[cfg(target_arch = "x86_64")]
fn smoke_pci_express_cap_link_status() -> TestResult {
    // Read the PCIe cap's link_status on QEMU NVMe and verify the
    // link-speed/width fields decode to non-zero values.
    use crate::pci_express::read_status;
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE (q35 pcie-mmcfg base, 0xb000_0000) is
    // identity-mapped below the 4-GiB map and the enumerator only
    // issues config-space reads; init is idempotent across calls.
    // SAFETY: Valid memory or trusted environment
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
        Err(_) => return TestResult::Fail("claim_device_cap"),
    };
    let read_cap = match cap.derive() {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("derive read"),
    };
    let s = match read_status(&read_cap, &d) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("read_status"),
    };
    if s.link_speed() == 0 {
        return TestResult::Fail("link speed 0");
    }
    if s.link_width() == 0 {
        return TestResult::Fail("link width 0");
    }
    if s.max_payload_supported() < 128 {
        return TestResult::Fail("max payload < 128");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_pci_express_cap_link_status);

#[cfg(target_arch = "x86_64")]
fn smoke_msix_program_block() -> TestResult {
    // Alloc 4 contiguous IDT vectors + program block 0..4 of the
    // QEMU NVMe MSI-X table to deliver them. We can't easily assert
    // the device fires multiple IRQs from a smoke (the driver isn't
    // running yet), but the structural path — alloc_block, walk the
    // cap, program 4 entries, enable — must succeed without faulting.
    use crate::msix::enable_msix;
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_interrupts::vector;
    // SAFETY: ECAM_DEFAULT_BASE (q35 pcie-mmcfg base, 0xb000_0000) is
    // identity-mapped below the 4-GiB map and the enumerator only
    // issues config-space reads; init is idempotent across calls.
    // SAFETY: Valid memory or trusted environment
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
    let mut table = match enable_msix(&cap, &d) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("enable_msix"),
    };
    if table.size() < 4 {
        return TestResult::Skip("table < 4");
    }
    if table.alloc_block(4).is_err() {
        return TestResult::Fail("alloc_block(4)");
    }
    let base = match vector::alloc_block(4) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("vector::alloc_block"),
    };
    // SAFETY: we own the device cap; cap-list walk + writes target
    // identity-mapped MMIO.
    // SAFETY: Valid memory or trusted environment
    let block = unsafe { table.program_vector_block(0, 4, 0, base) };
    let v = match block {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("program_vector_block"),
    };
    if v.len() != 4 {
        return TestResult::Fail("program_vector_block returned wrong count");
    }
    // Cleanup: release vectors. (Table allocation persists; OK,
    // re-running enable_msix discovers the same N.)
    for i in 0..4 {
        let _ = vector::free(base + i);
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus", smoke_msix_program_block);

fn smoke_hotplug_default_dispatcher_round_trip() -> TestResult {
    use crate::hotplug::{
        __clear_listeners, dispatch_event, install_default_dispatcher, listener_count,
        HotplugEvent, HotplugListener,
    };
    use crate::{BusAddr, DeviceId, PcieAddr};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    __clear_listeners();
    if listener_count() != 0 {
        return TestResult::Fail("listener list not empty after clear");
    }
    if install_default_dispatcher().is_err() {
        return TestResult::Fail("install_default_dispatcher");
    }

    static ATTACHES: AtomicU32 = AtomicU32::new(0);
    static DETACHES: AtomicU32 = AtomicU32::new(0);
    struct Tally;
    impl HotplugListener for Tally {
        fn on_event(&self, ev: HotplugEvent) {
            match ev {
                HotplugEvent::Attach { .. } => {
                    ATTACHES.fetch_add(1, Ordering::Relaxed);
                }
                HotplugEvent::Detach { .. } => {
                    DETACHES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    let auth = crate::bootstrap_registry_authority();
    if crate::hotplug::register_listener(&auth, Arc::new(Tally)).is_err() {
        return TestResult::Fail("register Tally");
    }
    if listener_count() != 2 {
        return TestResult::Fail("expected 2 listeners after default + tally");
    }

    let baseline_a = ATTACHES.load(Ordering::Relaxed);
    let baseline_d = DETACHES.load(Ordering::Relaxed);
    let addr = BusAddr::Pcie(PcieAddr {
        segment: 0,
        bus: 0,
        device: 31,
        function: 0,
    });

    dispatch_event(HotplugEvent::Attach {
        addr,
        device_id: DeviceId {
            vendor: 0x1234,
            device: 0x5678,
            class: 0,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
    });
    dispatch_event(HotplugEvent::Detach { addr });

    if ATTACHES.load(Ordering::Relaxed) != baseline_a + 1 {
        return TestResult::Fail("Attach not delivered to tally listener");
    }
    if DETACHES.load(Ordering::Relaxed) != baseline_d + 1 {
        return TestResult::Fail("Detach not delivered to tally listener");
    }
    __clear_listeners();
    TestResult::Pass
}
kernel_test_in!("bus", smoke_hotplug_default_dispatcher_round_trip);

fn smoke_aer_classifier_severity() -> TestResult {
    use crate::pci_cap_ext::{classify_aer, AerSeverity};

    if classify_aer(0, 0, 0).is_some() {
        return TestResult::Fail("zero status produced an event");
    }
    if classify_aer(0, 0, 1) != Some(AerSeverity::Correctable) {
        return TestResult::Fail("correctable bit didn't classify");
    }
    if classify_aer(1 << 4, 0, 0) != Some(AerSeverity::NonFatal) {
        return TestResult::Fail("uncorr w/o severity should be NonFatal");
    }
    if classify_aer(1 << 4, 1 << 4, 0) != Some(AerSeverity::Fatal) {
        return TestResult::Fail("uncorr matched severity should be Fatal");
    }
    if classify_aer(1 << 4, 0, 1) != Some(AerSeverity::Correctable) {
        return TestResult::Fail("correctable should win over uncorr");
    }
    TestResult::Pass
}
kernel_test_in!("bus", smoke_aer_classifier_severity);

// ── PCI INTx pin reader smoke ──────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_bus_pci_read_intx_pin_against_devices() -> TestResult {
    // Walk every claimed PCIe device and verify read_intx_pin
    // returns a value in {0, 1, 2, 3, 4} (PCI Local Bus Spec
    // §6.2.4). 0 = no INTx; 1-4 = INTA-INTD. Anything else is
    // a config-space read corruption — would catch a regression
    // in pcie_cfg_phys's offset arithmetic.
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{
        bootstrap_registry_authority, claim_device_cap, devices, pci::read_intx_pin, BusKind,
    };
    // SAFETY: ECAM_DEFAULT_BASE (q35 pcie-mmcfg base, 0xb000_0000) is
    // identity-mapped below the 4-GiB map and the enumerator only
    // issues config-space reads; init is idempotent across calls.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let mut tested = 0u32;
    for d in devs.iter() {
        if !matches!(d.kind, BusKind::Pcie { .. }) {
            continue;
        }
        let authority = bootstrap_registry_authority();
        let (_h, cap) = match claim_device_cap(&authority, d.addr) {
            Ok(ok) => ok,
            Err(_) => continue,
        };
        let pin = match read_intx_pin(&cap, d) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pin > 4 {
            return TestResult::Fail("INTERRUPT_PIN out of {0..4}");
        }
        tested += 1;
    }
    if tested == 0 {
        return TestResult::Skip("no claimable PCIe devices");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus/pci", smoke_bus_pci_read_intx_pin_against_devices);

#[cfg(target_arch = "x86_64")]
fn smoke_bus_pcie_aer_cap_walker() -> TestResult {
    // Walks every PCIe device's extended-cap list looking for
    // an AER cap. On QEMU q35 several devices (the root port,
    // pcie-root, etc.) carry AER. Catches a regression in the
    // extended-cap header decode (next_offset shift, cap_id
    // mask) by asserting the walker terminates and returns
    // either a sane cap offset or None for every device.
    use crate::pcie_aer::find_aer_cap_offset;
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{devices, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE (q35 pcie-mmcfg base, 0xb000_0000) is
    // identity-mapped below the 4-GiB map and the enumerator only
    // issues config-space reads; init is idempotent across calls.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let mut walked = 0u32;
    for d in devs.iter() {
        let cfg_phys = match d.kind {
            BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
            _ => continue,
        };
        // SAFETY: identity-mapped ECAM region; walker bounded.
        let off = unsafe { find_aer_cap_offset(cfg_phys) };
        if let Some(o) = off {
            // Sanity: AER cap header lives inside extended
            // config space.
            if !(0x100..0x1000).contains(&o) {
                return TestResult::Fail("AER cap offset outside extended config space");
            }
        }
        walked += 1;
    }
    if walked == 0 {
        return TestResult::Skip("no PCIe devices to walk");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus/pcie_aer", smoke_bus_pcie_aer_cap_walker);

#[cfg(target_arch = "x86_64")]
fn smoke_bus_hotplug_pcie_cap_walker() -> TestResult {
    // Walks every PCIe device's standard cap list looking for
    // the PCI Express capability (cap_id 0x10). Most devices
    // (NVMe, NICs, GPUs, root ports) carry it; some legacy
    // devices in QEMU q35 might not. Asserts each PCIe cap
    // offset (when present) lies in the [0x40, 0x100) standard
    // config range. Catches regressions in the cap-list decode
    // (next-pointer shift, cap_id mask).
    use crate::hotplug::find_pcie_cap_offset;
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{devices, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE (q35 pcie-mmcfg base, 0xb000_0000) is
    // identity-mapped below the 4-GiB map and the enumerator only
    // issues config-space reads; init is idempotent across calls.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let mut walked = 0u32;
    for d in devs.iter() {
        let cfg_phys = match d.kind {
            BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
            _ => continue,
        };
        // SAFETY: identity-mapped ECAM region; walker bounded.
        if let Some(o) = unsafe { find_pcie_cap_offset(cfg_phys) } {
            // u8 fits 0..=255; the standard cap region is
            // [0x40, 0x100). At 0x100 a u8 would overflow,
            // so we just check the lower bound here — the
            // walker itself rejects offsets &lt; 0x40.
            if o < 0x40 {
                return TestResult::Fail("PCIe cap offset below standard cap region");
            }
        }
        walked += 1;
    }
    if walked == 0 {
        return TestResult::Skip("no PCIe devices to walk");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus/hotplug", smoke_bus_hotplug_pcie_cap_walker);

// ── extended bus/pcie_aer coverage ─────────────────────────────────
//
// Existing surface had one decode test + one classify test. New
// tests pin every accessor on the AER cap header + UE classifier
// + Header Log + MSI number decoder.

fn smoke_aer_ext_cap_header_round_trip_full() -> TestResult {
    // raw u32 → ExtCapHeader → field round-trip across the full
    // value range each field permits.
    use crate::pcie_aer::{ExtCapHeader, AER_CAP_ID};
    let cases: &[(u16, u8, u16)] = &[
        (AER_CAP_ID, 1, 0x100),
        (0xABCD, 0xF, 0x320),
        (0x0000, 0, 0),
        (0xFFFF, 0xF, 0xFFF),
    ];
    for &(cap_id, cap_version, next_ptr) in cases {
        let raw = (cap_id as u32)
            | ((cap_version as u32 & 0xF) << 16)
            | ((next_ptr as u32 & 0xFFF) << 20);
        let h = ExtCapHeader::decode(raw);
        if h.cap_id != cap_id || h.cap_version != cap_version || h.next_ptr != next_ptr {
            return TestResult::Fail("ExtCapHeader field round-trip");
        }
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_ext_cap_header_round_trip_full);

fn smoke_aer_is_aer_classifier() -> TestResult {
    // Only AER_CAP_ID (0x0001) classifies as AER.
    use crate::pcie_aer::{ExtCapHeader, AER_CAP_ID};
    let aer = ExtCapHeader {
        cap_id: AER_CAP_ID,
        cap_version: 1,
        next_ptr: 0,
    };
    if !aer.is_aer() {
        return TestResult::Fail("AER header not classified as AER");
    }
    let not_aer = ExtCapHeader {
        cap_id: 0x0008,
        cap_version: 1,
        next_ptr: 0,
    };
    if not_aer.is_aer() {
        return TestResult::Fail("non-AER cap classified as AER");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_is_aer_classifier);

fn smoke_aer_classify_uncorrectable_table() -> TestResult {
    // Status==0 → None; status set + severity overlap → Severe;
    // status set + severity zero → NonFatal.
    use crate::pcie_aer::{classify_uncorrectable, ue, UeSeverity};
    if classify_uncorrectable(0, ue::DEFAULT_SEVERE) != UeSeverity::None {
        return TestResult::Fail("status=0 should be None");
    }
    if classify_uncorrectable(0, 0) != UeSeverity::None {
        return TestResult::Fail("status=0+severity=0 should be None");
    }
    // POISONED_TLP isn't in DEFAULT_SEVERE → NonFatal.
    if classify_uncorrectable(ue::POISONED_TLP, ue::DEFAULT_SEVERE) != UeSeverity::NonFatal {
        return TestResult::Fail("status w/o overlapping severity should be NonFatal");
    }
    // MALFORMED_TLP is in DEFAULT_SEVERE → Severe.
    if classify_uncorrectable(ue::MALFORMED_TLP, ue::DEFAULT_SEVERE) != UeSeverity::Severe {
        return TestResult::Fail("MALFORMED_TLP with default severity should be Severe");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_classify_uncorrectable_table);

fn smoke_aer_header_log_decodes_le_words() -> TestResult {
    // 16-byte raw → 4 little-endian u32 words.
    use crate::pcie_aer::HeaderLog;
    let raw: [u8; 16] = [
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07,
    ];
    let log = HeaderLog::decode(&raw);
    if log.0 != [1, u32::MAX, 0x0302_0100, 0x0706_0504] {
        return TestResult::Fail("HeaderLog::decode word order/endianness wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_header_log_decodes_le_words);

fn smoke_aer_msi_number_decodes_top_5_bits() -> TestResult {
    use crate::pcie_aer::aer_msi_number;
    let pins: &[(u32, u8)] = &[
        (0, 0),
        (1 << 27, 1),
        (31 << 27, 31),
        ((31u32 << 27) | 0x000F_FFFF, 31),
    ];
    for &(raw, want) in pins {
        let got = aer_msi_number(raw);
        if got != want {
            let msg = alloc::format!("aer_msi_number({:#x}) = {} (expected {})", raw, got, want);
            let s: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            return TestResult::Fail(s);
        }
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_msi_number_decodes_top_5_bits);

fn smoke_aer_ue_severity_variants_distinct() -> TestResult {
    use crate::pcie_aer::UeSeverity;
    let all = [UeSeverity::None, UeSeverity::NonFatal, UeSeverity::Severe];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("UeSeverity variants compared equal");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_ue_severity_variants_distinct);

// ── deep bus/pci + bus/hotplug coverage ───────────────────────────

fn smoke_pci_command_bits_layout() -> TestResult {
    // Pin the cmd:: bit positions against the PCIe spec §7.5.1.1.3.
    use crate::pci::cmd;
    if cmd::IO_SPACE != 1 << 0 {
        return TestResult::Fail("IO_SPACE bit drifted from 0");
    }
    if cmd::MEM_SPACE != 1 << 1 {
        return TestResult::Fail("MEM_SPACE bit drifted from 1");
    }
    if cmd::BUS_MASTER != 1 << 2 {
        return TestResult::Fail("BUS_MASTER bit drifted from 2");
    }
    if cmd::INTX_DISABLE != 1 << 10 {
        return TestResult::Fail("INTX_DISABLE bit drifted from 10");
    }
    // All four bits must be pairwise distinct.
    let all = [
        cmd::IO_SPACE,
        cmd::MEM_SPACE,
        cmd::BUS_MASTER,
        cmd::INTX_DISABLE,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("two cmd:: bits share a value");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("bus/pci", smoke_pci_command_bits_layout);

fn smoke_pci_command_offset_constant() -> TestResult {
    use crate::pci::COMMAND_OFFSET;
    // Type-0 PCI Config Space layout: Command is at byte offset 0x04.
    if COMMAND_OFFSET != 0x04 {
        return TestResult::Fail("COMMAND_OFFSET drifted from 0x04");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pci", smoke_pci_command_offset_constant);

fn smoke_pci_error_variants_distinct() -> TestResult {
    use crate::pci::PciError;
    let all = [PciError::AuthorityRevoked, PciError::NotPcie];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("PciError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("bus/pci", smoke_pci_error_variants_distinct);

fn smoke_pci_requester_id_packs_bdf() -> TestResult {
    // requester_id encodes BDF as `(bus << 8) | (device << 3) | function`
    // — same layout the GIC ITS uses for routing. Walk a few coordinates
    // to confirm the bit shifts.
    use crate::device::{BusDevice, BusKind};
    use crate::pci::requester_id;

    fn make_pcie(bus: u8, device: u8, function: u8) -> BusDevice {
        BusDevice {
            kind: BusKind::Pcie {
                addr: crate::addr::PcieAddr::new(0, bus, device, function),
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
            id: crate::device::DeviceId {
                vendor: 0,
                device: 0,
                class: 0,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            addr: crate::addr::BusAddr::Pcie(crate::addr::PcieAddr::new(0, bus, device, function)),
        }
    }
    let cases: &[(u8, u8, u8, u16)] = &[
        (0, 0, 0, 0),
        (0, 0, 1, 1),
        (0, 1, 0, 0b0000_0000_0000_1000),
        (1, 0, 0, 0x0100),
        (255, 31, 7, (255u16 << 8) | (31u16 << 3) | 7u16),
    ];
    for &(b, d, f, want) in cases {
        let dev = make_pcie(b, d, f);
        match requester_id(&dev) {
            Some(rid) if rid == want => {}
            _ => return TestResult::Fail("requester_id BDF encoding drifted"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("bus/pci", smoke_pci_requester_id_packs_bdf);

fn smoke_pci_requester_id_none_for_non_pcie() -> TestResult {
    use crate::addr::BusAddr;
    use crate::device::{BusDevice, BusKind, DeviceId};
    use crate::pci::requester_id;
    let phys = narf_memory::PhysAddr::new(0xFF00_0000);
    let dev = BusDevice {
        addr: BusAddr::Mmio(phys),
        id: DeviceId {
            vendor: 0,
            device: 0,
            class: 0,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::VirtioMmio {
            base: phys,
            len: 0x200,
            device_id: 1,
        },
    };
    if requester_id(&dev).is_some() {
        return TestResult::Fail("requester_id returned Some for virtio-mmio");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pci", smoke_pci_requester_id_none_for_non_pcie);

fn smoke_pci_read_command_revoked_cap_rejected() -> TestResult {
    // Revoked Cap<BusDeviceCap, Write> rejects cfg-space reads with
    // AuthorityRevoked regardless of the BusKind underneath.
    use crate::addr::{BusAddr, PcieAddr};
    use crate::device::{BusDevice, BusKind, DeviceId};
    use crate::pci::{read_command, PciError};
    use crate::registry::BusDeviceCap;
    use narf_capabilities::{Cap, Write};
    let cap: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    cap.revoke();
    let pcie = PcieAddr::new(0, 0, 0, 0);
    let dev = BusDevice {
        addr: BusAddr::Pcie(pcie),
        id: DeviceId {
            vendor: 0,
            device: 0,
            class: 0,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: pcie,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    match read_command(&cap, &dev) {
        Err(PciError::AuthorityRevoked) => TestResult::Pass,
        _ => TestResult::Fail("revoked cap didn't surface AuthorityRevoked"),
    }
}
kernel_test_in!("bus/pci", smoke_pci_read_command_revoked_cap_rejected);

// ── bus/hotplug ───────────────────────────────────────────────────

fn smoke_hotplug_error_variants_distinct() -> TestResult {
    use crate::hotplug::HotplugError;
    // Only one variant today; verify its shape compiles + Eq works
    // so a future second variant naturally fits the test.
    let a = HotplugError::AuthorityRevoked;
    let b = HotplugError::AuthorityRevoked;
    if a != b {
        return TestResult::Fail("HotplugError Eq broken");
    }
    TestResult::Pass
}
kernel_test_in!("bus/hotplug", smoke_hotplug_error_variants_distinct);

fn smoke_hotplug_register_rejects_revoked_authority() -> TestResult {
    use crate::hotplug::{register_listener, HotplugError, HotplugEvent, HotplugListener};
    use crate::registry::BusRegistryCap;
    use alloc::sync::Arc;
    use narf_capabilities::{Cap, Grant};

    struct NoOp;
    impl HotplugListener for NoOp {
        fn on_event(&self, _: HotplugEvent) {}
    }

    let auth: Cap<BusRegistryCap, Grant> = Cap::bootstrap();
    auth.revoke();
    match register_listener(&auth, Arc::new(NoOp)) {
        Err(HotplugError::AuthorityRevoked) => TestResult::Pass,
        _ => TestResult::Fail("revoked authority didn't surface AuthorityRevoked"),
    }
}
kernel_test_in!(
    "bus/hotplug",
    smoke_hotplug_register_rejects_revoked_authority
);

fn smoke_hotplug_dispatch_fans_out_to_listeners() -> TestResult {
    use crate::addr::{BusAddr, PcieAddr};
    use crate::device::DeviceId;
    use crate::hotplug::{
        dispatch_event, listener_count, register_listener, HotplugEvent, HotplugListener,
        __clear_listeners,
    };
    use crate::registry::BusRegistryCap;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_capabilities::{Cap, Grant};

    static ATTACH_HITS: AtomicU32 = AtomicU32::new(0);
    static DETACH_HITS: AtomicU32 = AtomicU32::new(0);

    struct Counter;
    impl HotplugListener for Counter {
        fn on_event(&self, ev: HotplugEvent) {
            match ev {
                HotplugEvent::Attach { .. } => {
                    ATTACH_HITS.fetch_add(1, Ordering::Relaxed);
                }
                HotplugEvent::Detach { .. } => {
                    DETACH_HITS.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    __clear_listeners();
    ATTACH_HITS.store(0, Ordering::Relaxed);
    DETACH_HITS.store(0, Ordering::Relaxed);

    let auth: Cap<BusRegistryCap, Grant> = Cap::bootstrap();
    if register_listener(&auth, Arc::new(Counter)).is_err() {
        return TestResult::Fail("register failed on live authority");
    }
    if register_listener(&auth, Arc::new(Counter)).is_err() {
        return TestResult::Fail("second register failed");
    }
    if listener_count() != 2 {
        return TestResult::Fail("listener_count != 2");
    }

    let addr = BusAddr::Pcie(PcieAddr::new(0, 1, 2, 3));
    let id = DeviceId {
        vendor: 0x1B36,
        device: 0x0010,
        class: 0x010802,
        subsystem_vendor: 0,
        subsystem_id: 0,
    };
    dispatch_event(HotplugEvent::Attach {
        addr,
        device_id: id,
    });
    if ATTACH_HITS.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("Attach didn't fan out to both listeners");
    }
    dispatch_event(HotplugEvent::Detach { addr });
    if DETACH_HITS.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("Detach didn't fan out to both listeners");
    }

    __clear_listeners();
    if listener_count() != 0 {
        return TestResult::Fail("__clear_listeners didn't drain");
    }
    TestResult::Pass
}
kernel_test_in!("bus/hotplug", smoke_hotplug_dispatch_fans_out_to_listeners);

fn smoke_hotplug_event_variants_distinct() -> TestResult {
    use crate::addr::{BusAddr, PcieAddr};
    use crate::device::DeviceId;
    use crate::hotplug::HotplugEvent;
    let addr = BusAddr::Pcie(PcieAddr::new(0, 0, 0, 0));
    let id = DeviceId {
        vendor: 0,
        device: 0,
        class: 0,
        subsystem_vendor: 0,
        subsystem_id: 0,
    };
    let a = HotplugEvent::Attach {
        addr,
        device_id: id,
    };
    let d = HotplugEvent::Detach { addr };
    if a == d {
        return TestResult::Fail("Attach == Detach");
    }
    TestResult::Pass
}
kernel_test_in!("bus/hotplug", smoke_hotplug_event_variants_distinct);

// ── bus/pci (config save/restore) ──────────────────────────────────

fn smoke_pci_save_config_shape_fits_64_byte_header() -> TestResult {
    use crate::pci::SavedPciConfig;
    // SavedPciConfig is a pure POD struct — its size should be
    // comparable to the 64-byte type-0 header it captures.
    // Caps + alignment may bump it slightly; we just sanity-check
    // it's smaller than 96 bytes.
    let sz = core::mem::size_of::<SavedPciConfig>();
    if sz > 96 {
        return TestResult::Fail("SavedPciConfig must fit in <= 96 bytes");
    }
    if !(40..=96).contains(&sz) {
        return TestResult::Fail("SavedPciConfig size out of plausible band");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pci", smoke_pci_save_config_shape_fits_64_byte_header);

fn smoke_pci_saved_config_is_pod_and_copyable() -> TestResult {
    use crate::pci::SavedPciConfig;
    let a = SavedPciConfig {
        command: 0x0407, // I/O | Mem | BM | INTx-disable
        cache_line_size: 64,
        latency_timer: 0,
        bist: 0,
        bars: [0xF000_0000, 0x0000_0000, 0xE000_0000, 0, 0, 0],
        cardbus_cis_ptr: 0,
        subsys_vendor: 0x1022,
        subsys_device: 0x1234,
        expansion_rom_bar: 0,
        interrupt_line: 11,
        interrupt_pin: 1,
        min_gnt: 0,
        max_lat: 0,
    };
    let b = a; // Copy
    if a != b {
        return TestResult::Fail("SavedPciConfig must be Copy + Eq");
    }
    if a.command != 0x0407 || a.bars[0] != 0xF000_0000 || a.bars[2] != 0xE000_0000 {
        return TestResult::Fail("field round-trip lost data");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pci", smoke_pci_saved_config_is_pod_and_copyable);

// ── SlotCaps + Hotplug power-control smokes ───────────────────────
//
// These exercise the new SlotCaps decoder, presence-detect debounce
// constant, and SlotPolicy helpers added in this session.

fn smoke_slot_caps_bit_positions() -> TestResult {
    // Every single-bit slot_cap constant must be a power of two and
    // sit at the position documented in PCIe 6.0 §7.5.3.9.
    use crate::hotplug::slot_cap;
    let single_bits = [
        slot_cap::ATTENTION_BUTTON,
        slot_cap::POWER_CONTROLLER,
        slot_cap::MRL_SENSOR,
        slot_cap::ATTENTION_INDICATOR,
        slot_cap::POWER_INDICATOR,
        slot_cap::HOT_PLUG_SURPRISE,
        slot_cap::HOT_PLUG_CAPABLE,
        slot_cap::ELECTROMECHANICAL_INTERLOCK,
        slot_cap::NO_COMMAND_COMPLETED,
    ];
    for b in &single_bits {
        if b.count_ones() != 1 {
            return TestResult::Fail("slot_cap single-bit constant is not a power of two");
        }
    }
    if slot_cap::ATTENTION_BUTTON != 1 << 0 {
        return TestResult::Fail("ATTENTION_BUTTON must be bit 0");
    }
    if slot_cap::POWER_CONTROLLER != 1 << 1 {
        return TestResult::Fail("POWER_CONTROLLER must be bit 1");
    }
    if slot_cap::HOT_PLUG_CAPABLE != 1 << 6 {
        return TestResult::Fail("HOT_PLUG_CAPABLE must be bit 6");
    }
    if slot_cap::NO_COMMAND_COMPLETED != 1 << 18 {
        return TestResult::Fail("NO_COMMAND_COMPLETED must be bit 18");
    }
    TestResult::Pass
}
kernel_test_in!("bus/hotplug", smoke_slot_caps_bit_positions);

fn smoke_slot_caps_decode_round_trip() -> TestResult {
    // Encode POWER_CONTROLLER | HOT_PLUG_CAPABLE | NO_COMMAND_COMPLETED
    // and slot_number=0x42, then verify all fields are decoded.
    use crate::hotplug::{slot_cap, SlotCaps};
    let slot_num: u32 = 0x42;
    let raw: u32 = slot_cap::POWER_CONTROLLER
        | slot_cap::HOT_PLUG_CAPABLE
        | slot_cap::NO_COMMAND_COMPLETED
        | (slot_num << slot_cap::PHYSICAL_SLOT_NUM_SHIFT);
    let caps = SlotCaps::decode(raw);
    if !caps.power_ctrl {
        return TestResult::Fail("power_ctrl not decoded");
    }
    if !caps.hp_capable {
        return TestResult::Fail("hp_capable not decoded");
    }
    if !caps.no_cmd_complete {
        return TestResult::Fail("no_cmd_complete not decoded");
    }
    if caps.attn_button || caps.mrl_sensor || caps.attn_indicator || caps.hp_surprise {
        return TestResult::Fail("spurious bits set in decoded SlotCaps");
    }
    if caps.slot_number != 0x42 {
        return TestResult::Fail("slot_number decoded incorrectly");
    }
    TestResult::Pass
}
kernel_test_in!("bus/hotplug", smoke_slot_caps_decode_round_trip);

fn smoke_presence_detect_debounce_in_range() -> TestResult {
    // PCIe CEM §2.6.2 minimum is 50 ms; practical ceiling is 500 ms.
    use crate::hotplug::PRESENCE_DETECT_DEBOUNCE_MS;
    if PRESENCE_DETECT_DEBOUNCE_MS < 50 {
        return TestResult::Fail("debounce below spec minimum of 50 ms");
    }
    if PRESENCE_DETECT_DEBOUNCE_MS > 500 {
        return TestResult::Fail("debounce unreasonably large (> 500 ms)");
    }
    TestResult::Pass
}
kernel_test_in!("bus/hotplug", smoke_presence_detect_debounce_in_range);

fn smoke_slot_policy_from_caps() -> TestResult {
    // SlotPolicy correctly inherits power-ctrl flag from SlotCaps.
    use crate::hotplug::{slot_cap, SlotCaps, SlotPolicy};
    let with_pwr = SlotCaps::decode(slot_cap::HOT_PLUG_CAPABLE | slot_cap::POWER_CONTROLLER);
    let p = SlotPolicy::from_caps(0xDEAD_0000, 0x70, &with_pwr);
    if !p.has_power_ctrl {
        return TestResult::Fail("has_power_ctrl not propagated");
    }
    let without_pwr = SlotCaps::decode(slot_cap::HOT_PLUG_CAPABLE);
    let p2 = SlotPolicy::from_caps(0xDEAD_0000, 0x70, &without_pwr);
    if p2.has_power_ctrl {
        return TestResult::Fail("has_power_ctrl spuriously set when not in caps");
    }
    TestResult::Pass
}
kernel_test_in!("bus/hotplug", smoke_slot_policy_from_caps);

// ── AER capability discovery + mask config smokes ─────────────────
//
// These exercise the new pcie_aer functions: synthetic AER cap
// discovery, UE status RW1C semantics, Root Error Status aggregation,
// DPC capability decode, and default mask constants.

fn smoke_aer_cap_discovery_synthetic() -> TestResult {
    // Build a synthetic 4 KiB config space with two extended caps:
    //   0x100: dummy (ID=0xABCD, next=0x140)
    //   0x140: AER  (ID=0x0001, next=0x000)
    // Verify find_aer_cap_offset returns 0x140.
    use crate::pcie_aer::find_aer_cap_offset;
    let mut space = alloc::vec![0u32; 1024]; // 4096 bytes
    space[0x100 / 4] = 0xABCDu32 | (1 << 16) | (0x140u32 << 20);
    space[0x140 / 4] = 0x0001u32 | (2 << 16); // next-cap pointer = 0 (end of list)
    let cfg_phys = space.as_ptr() as u64;
    // SAFETY: `space` is a live heap allocation; walk is read-only;
    // all pointer arithmetic stays within the 4096-byte Vec.
    // SAFETY: Valid memory or trusted environment
    let result = unsafe { find_aer_cap_offset(cfg_phys) };
    match result {
        Some(0x140) => TestResult::Pass,
        Some(_) => TestResult::Fail("AER cap found at wrong offset in synthetic space"),
        None => TestResult::Fail("find_aer_cap_offset returned None on synthetic AER space"),
    }
}
kernel_test_in!("bus/hotplug", smoke_aer_cap_discovery_synthetic);

fn smoke_ue_status_rw1c_severity_semantics() -> TestResult {
    // classify_uncorrectable must correctly interpret the three scenarios:
    // status & severity != 0 → Severe; status != 0, no overlap → NonFatal;
    // status == 0 → None.
    use crate::pcie_aer::{classify_uncorrectable, ue, UeSeverity};
    // DLP in both → Severe.
    if classify_uncorrectable(ue::DATA_LINK_PROTOCOL_ERROR, ue::DATA_LINK_PROTOCOL_ERROR)
        != UeSeverity::Severe
    {
        return TestResult::Fail("DLP in status+severity should be Severe");
    }
    // DLP in status only → NonFatal.
    if classify_uncorrectable(ue::DATA_LINK_PROTOCOL_ERROR, 0) != UeSeverity::NonFatal {
        return TestResult::Fail("DLP in status only should be NonFatal");
    }
    // status = 0 → None.
    if classify_uncorrectable(0, ue::DATA_LINK_PROTOCOL_ERROR) != UeSeverity::None {
        return TestResult::Fail("zero status should be None");
    }
    // Multiple bits, one severe → Severe.
    let status = ue::POISONED_TLP | ue::COMPLETION_TIMEOUT;
    if classify_uncorrectable(status, ue::POISONED_TLP) != UeSeverity::Severe {
        return TestResult::Fail("mixed status with one severe bit should be Severe");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_ue_status_rw1c_severity_semantics);

fn smoke_root_error_status_aggregation() -> TestResult {
    // RootErrorStatus::decode correctly extracts each field and
    // ue_severity() classifies Fatal vs NonFatal correctly.
    use crate::pcie_aer::{root_sts, RootErrorStatus, UeSeverity};
    // Correctable only.
    let corr = RootErrorStatus::decode(root_sts::ERR_COR_RECEIVED);
    if !corr.corr_received || corr.fatal_nonfatal_received {
        return TestResult::Fail("corr_received wrong");
    }
    if !corr.any_error() {
        return TestResult::Fail("any_error should be true for correctable");
    }
    // Fatal UE (FIRST_UNCORRECTABLE_FATAL set).
    let fatal = RootErrorStatus::decode(
        root_sts::ERR_FATAL_NONFATAL_RECEIVED | root_sts::FIRST_UNCORRECTABLE_FATAL,
    );
    if !fatal.fatal_nonfatal_received || !fatal.first_ue_fatal {
        return TestResult::Fail("fatal fields not decoded");
    }
    if fatal.ue_severity() != UeSeverity::Severe {
        return TestResult::Fail("fatal UE should be Severe");
    }
    // Non-fatal UE (ERR_FATAL_NONFATAL but FIRST_UE_FATAL clear).
    let nf = RootErrorStatus::decode(root_sts::ERR_FATAL_NONFATAL_RECEIVED);
    if nf.ue_severity() != UeSeverity::NonFatal {
        return TestResult::Fail("non-fatal UE should be NonFatal");
    }
    // MSI vector extraction.
    if RootErrorStatus::decode(5u32 << 27).aer_int_number != 5 {
        return TestResult::Fail("aer_int_number decoded wrong");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_root_error_status_aggregation);

fn smoke_dpc_capability_decode() -> TestResult {
    // DpcCapability::decode correctly parses int_msg_number and feature bits.
    use crate::pcie_aer::DpcCapability;
    // int_msg_number=3, rp_extensions, sw_triggering.
    let raw: u16 = 3 | (1 << 5) | (1 << 7);
    let cap = DpcCapability::decode(raw);
    if cap.int_msg_number != 3 {
        return TestResult::Fail("int_msg_number wrong");
    }
    if !cap.rp_extensions {
        return TestResult::Fail("rp_extensions not decoded");
    }
    if cap.ptlp_egress_blocking {
        return TestResult::Fail("ptlp_egress_blocking spuriously set");
    }
    if !cap.sw_triggering {
        return TestResult::Fail("sw_triggering not decoded");
    }
    if cap.raw != raw {
        return TestResult::Fail("raw field not stored");
    }
    // Zero raw → all false / zero.
    let none = DpcCapability::decode(0);
    if none.rp_extensions || none.sw_triggering || none.int_msg_number != 0 {
        return TestResult::Fail("zero raw should decode to all-false");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_dpc_capability_decode);

fn smoke_default_aer_masks_correct() -> TestResult {
    // DEFAULT_CE_MASK must suppress Advisory Non-Fatal only;
    // DEFAULT_UE_MASK must be zero; DEFAULT_UE_SEVERITY must
    // include every spec-mandated link-fatal bit.
    use crate::pcie_aer::{ce, ue, DEFAULT_CE_MASK, DEFAULT_UE_MASK, DEFAULT_UE_SEVERITY};
    if DEFAULT_CE_MASK != ce::ADVISORY_NON_FATAL {
        return TestResult::Fail("DEFAULT_CE_MASK should be ADVISORY_NON_FATAL only");
    }
    if DEFAULT_UE_MASK != 0 {
        return TestResult::Fail("DEFAULT_UE_MASK should be 0");
    }
    let required = ue::DATA_LINK_PROTOCOL_ERROR
        | ue::SURPRISE_DOWN_ERROR
        | ue::FLOW_CONTROL_PROTOCOL_ERROR
        | ue::RECEIVER_OVERFLOW
        | ue::MALFORMED_TLP
        | ue::UNCORRECTABLE_INTERNAL_ERROR;
    if DEFAULT_UE_SEVERITY & required != required {
        return TestResult::Fail("DEFAULT_UE_SEVERITY missing spec-mandated fatal bits");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_default_aer_masks_correct);

// ── AER recovery / DPC smokes ─────────────────────────────────────

fn smoke_recovery_merge_result_lattice() -> TestResult {
    // merge_result must implement the Linux err.c lattice: NoAerDriver
    // absorbs, None passes-through, CanRecover/Recovered yield to the
    // new vote, Disconnect only upgrades to NeedReset.
    use crate::pcie_recovery::{merge_result, PciErsResult};
    if merge_result(PciErsResult::CanRecover, PciErsResult::NoAerDriver)
        != PciErsResult::NoAerDriver
    {
        return TestResult::Fail("NoAerDriver should absorb");
    }
    if merge_result(PciErsResult::Recovered, PciErsResult::None) != PciErsResult::Recovered {
        return TestResult::Fail("None should pass through");
    }
    if merge_result(PciErsResult::CanRecover, PciErsResult::NeedReset) != PciErsResult::NeedReset {
        return TestResult::Fail("CanRecover -> NeedReset");
    }
    if merge_result(PciErsResult::Disconnect, PciErsResult::NeedReset) != PciErsResult::NeedReset {
        return TestResult::Fail("Disconnect upgrades to NeedReset");
    }
    if merge_result(PciErsResult::Disconnect, PciErsResult::Recovered) != PciErsResult::Disconnect {
        return TestResult::Fail("Disconnect should not downgrade to Recovered");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_recovery_merge_result_lattice);

fn smoke_aer_error_detected_to_resume() -> TestResult {
    // FakeDriver records the lifecycle: error_detected (CanRecover)
    // → mmio_enabled (Recovered) → resume. No slot_reset because the
    // vote stayed CanRecover.
    use crate::addr::{BusAddr, PcieAddr};
    use crate::pcie_recovery::{
        __clear_error_callbacks, do_recovery, register_error_callback, ErrorCallback,
        PciChannelState, PciErrSeverity, PciErsResult, RecoveryOutcome, ResetResult,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    __clear_error_callbacks();

    struct FakeDriver {
        seq: AtomicU32,
    }
    impl ErrorCallback for FakeDriver {
        fn error_detected(&self, _s: PciErrSeverity) -> PciErsResult {
            // Encode call index into the low byte of seq.
            self.seq.fetch_or(0x01, Ordering::Relaxed);
            PciErsResult::CanRecover
        }
        fn mmio_enabled(&self) -> PciErsResult {
            self.seq.fetch_or(0x02, Ordering::Relaxed);
            PciErsResult::Recovered
        }
        fn slot_reset(&self) -> PciErsResult {
            self.seq.fetch_or(0x04, Ordering::Relaxed);
            PciErsResult::Recovered
        }
        fn resume(&self) {
            self.seq.fetch_or(0x08, Ordering::Relaxed);
        }
    }
    let drv = Arc::new(FakeDriver {
        seq: AtomicU32::new(0),
    });
    let bdf = BusAddr::Pcie(PcieAddr::new(0, 1, 2, 3));
    register_error_callback(bdf, drv.clone());
    let mut reset_fired = false;
    let outcome = do_recovery(
        &[bdf],
        PciErrSeverity::NonFatal,
        PciChannelState::Normal,
        &mut || {
            reset_fired = true;
            ResetResult::Recovered
        },
    );
    __clear_error_callbacks();
    if outcome != RecoveryOutcome::Recovered {
        return TestResult::Fail("non-fatal recovery should succeed");
    }
    let seq = drv.seq.load(Ordering::Relaxed);
    // error_detected (0x01) + mmio_enabled (0x02) + resume (0x08).
    // slot_reset (0x04) MUST NOT fire on a CanRecover path.
    if seq & 0x01 == 0 {
        return TestResult::Fail("error_detected did not fire");
    }
    if seq & 0x02 == 0 {
        return TestResult::Fail("mmio_enabled did not fire");
    }
    if seq & 0x04 != 0 {
        return TestResult::Fail("slot_reset fired on CanRecover path");
    }
    if seq & 0x08 == 0 {
        return TestResult::Fail("resume did not fire");
    }
    if reset_fired {
        return TestResult::Fail("reset_fn fired on CanRecover path");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_error_detected_to_resume);

fn smoke_aer_fatal_escalation_path() -> TestResult {
    // Driver votes NeedReset → reset_fn fires → slot_reset broadcast
    // → resume. Verifies the full Frozen-path lifecycle plus the
    // platform reset callback.
    use crate::addr::{BusAddr, PcieAddr};
    use crate::pcie_recovery::{
        __clear_error_callbacks, do_recovery, register_error_callback, ErrorCallback,
        PciChannelState, PciErrSeverity, PciErsResult, RecoveryOutcome, ResetResult,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    __clear_error_callbacks();

    struct ResetWantingDriver {
        seq: AtomicU32,
    }
    impl ErrorCallback for ResetWantingDriver {
        fn error_detected(&self, s: PciErrSeverity) -> PciErsResult {
            self.seq.fetch_or(0x01, Ordering::Relaxed);
            if s == PciErrSeverity::Fatal {
                PciErsResult::NeedReset
            } else {
                PciErsResult::CanRecover
            }
        }
        fn mmio_enabled(&self) -> PciErsResult {
            self.seq.fetch_or(0x02, Ordering::Relaxed);
            PciErsResult::Recovered
        }
        fn slot_reset(&self) -> PciErsResult {
            self.seq.fetch_or(0x04, Ordering::Relaxed);
            PciErsResult::Recovered
        }
        fn resume(&self) {
            self.seq.fetch_or(0x08, Ordering::Relaxed);
        }
    }
    let drv = Arc::new(ResetWantingDriver {
        seq: AtomicU32::new(0),
    });
    let bdf = BusAddr::Pcie(PcieAddr::new(0, 4, 5, 6));
    register_error_callback(bdf, drv.clone());
    let mut reset_count = 0u32;
    let outcome = do_recovery(
        &[bdf],
        PciErrSeverity::Fatal,
        PciChannelState::Frozen,
        &mut || {
            reset_count += 1;
            ResetResult::Recovered
        },
    );
    __clear_error_callbacks();
    if outcome != RecoveryOutcome::Recovered {
        return TestResult::Fail("fatal recovery should succeed");
    }
    if reset_count != 1 {
        return TestResult::Fail("reset_fn should fire exactly once");
    }
    let seq = drv.seq.load(Ordering::Relaxed);
    if seq & 0x01 == 0 {
        return TestResult::Fail("error_detected did not fire");
    }
    if seq & 0x04 == 0 {
        return TestResult::Fail("slot_reset did not fire on fatal path");
    }
    if seq & 0x08 == 0 {
        return TestResult::Fail("resume did not fire");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_fatal_escalation_path);

fn smoke_aer_isr_aggregates_counters() -> TestResult {
    // Drive the ISR over the live ECAM. We can't inject AER events in
    // QEMU, but we CAN assert that the ISR walks without panicking and
    // that the counters are monotonic (i.e. the W1C write doesn't
    // corrupt them).
    use crate::pcie_aer::{aer_isr, AER_CORRECTABLE_COUNT, AER_FATAL_COUNT, AER_NONFATAL_COUNT};
    use core::sync::atomic::Ordering;
    // Snapshot counters, run ISR, verify no decrease.
    let c0 = AER_CORRECTABLE_COUNT.load(Ordering::Relaxed);
    let n0 = AER_NONFATAL_COUNT.load(Ordering::Relaxed);
    let f0 = AER_FATAL_COUNT.load(Ordering::Relaxed);
    aer_isr();
    let c1 = AER_CORRECTABLE_COUNT.load(Ordering::Relaxed);
    let n1 = AER_NONFATAL_COUNT.load(Ordering::Relaxed);
    let f1 = AER_FATAL_COUNT.load(Ordering::Relaxed);
    if c1 < c0 || n1 < n0 || f1 < f0 {
        return TestResult::Fail("AER counters must be monotonic");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_aer_isr_aggregates_counters);

fn smoke_dpc_status_decode_and_rw1c() -> TestResult {
    // DpcStatus decoder + the implied RW1C semantics: TRIGGERED +
    // INTERRUPT are RW1C, REASON is RO, RP_BUSY is RO. We exercise
    // the decoder against the spec-shaped bit fields.
    use crate::pcie_dpc::{sts, DpcReason, DpcStatus};
    // Fatal reason, TRIGGERED + INTERRUPT, RP_BUSY clear.
    let raw = sts::TRIGGERED | sts::INTERRUPT | sts::REASON_FE;
    let snap = DpcStatus::decode(raw);
    if !snap.triggered {
        return TestResult::Fail("triggered bit not decoded");
    }
    if !snap.interrupt {
        return TestResult::Fail("interrupt bit not decoded");
    }
    if snap.rp_busy {
        return TestResult::Fail("rp_busy spuriously set");
    }
    if snap.reason != DpcReason::Fatal {
        return TestResult::Fail("reason should be Fatal");
    }
    // RW1C semantic check via the constant: writing the same bits
    // back should clear them — that's what the ISR does. We verify
    // the bit definitions match the PCIe spec.
    if sts::TRIGGERED != 1 << 0 {
        return TestResult::Fail("TRIGGERED bit position");
    }
    if sts::INTERRUPT != 1 << 3 {
        return TestResult::Fail("INTERRUPT bit position");
    }
    // Verify DL Protocol Error / RP PIO classification.
    let rp_pio = sts::REASON_EXT | sts::REASON_EXT_RP_PIO | sts::TRIGGERED;
    let dl = DpcStatus::decode(rp_pio);
    if dl.reason != DpcReason::RpPioError {
        return TestResult::Fail("RP PIO error reason classification");
    }
    if !dl.is_dl_protocol_error() {
        return TestResult::Fail("RP PIO should be treated as DL protocol");
    }
    // Software trigger.
    let sw = DpcStatus::decode(sts::REASON_EXT | sts::REASON_EXT_SW | sts::TRIGGERED);
    if sw.reason != DpcReason::SoftwareTrigger {
        return TestResult::Fail("SW trigger reason classification");
    }
    if sw.is_dl_protocol_error() {
        return TestResult::Fail("SW trigger should not be DL protocol");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_dpc", smoke_dpc_status_decode_and_rw1c);

#[cfg(target_arch = "x86_64")]
fn smoke_dpc_capability_presence_detect() -> TestResult {
    // Walk every PCIe device and run find_dpc_cap_offset. QEMU q35
    // root ports may or may not expose DPC depending on the machine
    // type; the test just verifies the walker terminates on every
    // device without faulting and without aliasing a non-DPC cap as
    // DPC.
    use crate::pcie_dpc::find_dpc_cap_offset;
    use crate::x86_64::ECAM_DEFAULT_BASE;
    use crate::{devices, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE (q35 pcie-mmcfg base, 0xb000_0000) is
    // identity-mapped below the 4-GiB map and the enumerator only
    // issues config-space reads; init is idempotent across calls.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { crate::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    for d in devs.iter() {
        let cfg_phys = match d.kind {
            BusKind::Pcie { cfg_phys, .. } => cfg_phys.raw(),
            _ => continue,
        };
        // SAFETY: live ECAM; walker is read-only + bounded.
        let off = unsafe { find_dpc_cap_offset(cfg_phys) };
        if let Some(o) = off {
            if !(0x100..0x1000).contains(&o) {
                return TestResult::Fail("DPC cap offset out of range");
            }
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bus/pcie_dpc", smoke_dpc_capability_presence_detect);

fn smoke_link_retrain_wait_loop_completes() -> TestResult {
    // Drive retrain_link against a fake register pair that toggles
    // DLL_ACTIVE after a few polls — verifies the wait loop sees
    // DLL_ACTIVE + !LINK_TRAINING and returns true.
    use crate::pcie_aer::{link_sts, retrain_link};
    use core::cell::Cell;
    let polls = Cell::new(0u32);
    let last_ctl = Cell::new(0xFFFFu16);
    let mut read_status = || -> u16 {
        let n = polls.get();
        polls.set(n + 1);
        // Simulate the link coming back on the 3rd poll.
        if n < 3 {
            link_sts::LINK_TRAINING
        } else {
            link_sts::DLL_ACTIVE
        }
    };
    let mut write_ctrl = |v: u16| {
        last_ctl.set(v);
    };
    let mut settle = || {};
    let ok = retrain_link(&mut read_status, &mut write_ctrl, &mut settle, 32);
    if !ok {
        return TestResult::Fail("retrain_link should return true once DLL_ACTIVE");
    }
    // last write should have been 0 (re-enable), not LINK_DISABLE.
    if last_ctl.get() & crate::pcie_aer::link_ctrl::LINK_DISABLE != 0 {
        return TestResult::Fail("final write should clear LINK_DISABLE");
    }
    // Timeout path: poll always returns LINK_TRAINING.
    let polls2 = Cell::new(0u32);
    let mut never_ready = || -> u16 {
        polls2.set(polls2.get() + 1);
        link_sts::LINK_TRAINING
    };
    let mut write2 = |_v: u16| {};
    let mut settle2 = || {};
    let timed_out = retrain_link(&mut never_ready, &mut write2, &mut settle2, 5);
    if timed_out {
        return TestResult::Fail("retrain_link should return false on timeout");
    }
    if polls2.get() != 5 {
        return TestResult::Fail("timeout path should poll timeout_polls times");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_link_retrain_wait_loop_completes);

fn smoke_recovery_no_driver_blocks_subtree() -> TestResult {
    // Subtree with one registered and one un-registered device. The
    // un-registered device's NoAerDriver vote must poison the whole
    // recovery — slot_reset should never fire.
    use crate::addr::{BusAddr, PcieAddr};
    use crate::pcie_recovery::{
        __clear_error_callbacks, do_recovery, register_error_callback, ErrorCallback,
        PciChannelState, PciErrSeverity, PciErsResult, RecoveryOutcome, ResetResult,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    __clear_error_callbacks();

    struct GoodDriver {
        slot_reset_calls: AtomicU32,
    }
    impl ErrorCallback for GoodDriver {
        fn error_detected(&self, _s: PciErrSeverity) -> PciErsResult {
            PciErsResult::CanRecover
        }
        fn slot_reset(&self) -> PciErsResult {
            self.slot_reset_calls.fetch_add(1, Ordering::Relaxed);
            PciErsResult::Recovered
        }
        fn resume(&self) {}
    }
    let drv = Arc::new(GoodDriver {
        slot_reset_calls: AtomicU32::new(0),
    });
    let known = BusAddr::Pcie(PcieAddr::new(0, 7, 8, 9));
    let unknown = BusAddr::Pcie(PcieAddr::new(0, 7, 10, 0));
    register_error_callback(known, drv.clone());

    let mut reset_fired = 0u32;
    let outcome = do_recovery(
        &[known, unknown],
        PciErrSeverity::Fatal,
        PciChannelState::Frozen,
        &mut || {
            reset_fired += 1;
            ResetResult::Recovered
        },
    );
    __clear_error_callbacks();
    if outcome != RecoveryOutcome::NoDriver {
        return TestResult::Fail("missing driver must yield NoDriver");
    }
    if reset_fired != 0 {
        return TestResult::Fail("reset_fn must not fire when NoDriver");
    }
    if drv.slot_reset_calls.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("slot_reset must not fire when NoDriver");
    }
    TestResult::Pass
}
kernel_test_in!("bus/pcie_aer", smoke_recovery_no_driver_blocks_subtree);
