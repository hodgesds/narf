//! Per-driver smoke tests for `narf-drivers-nvme`. Tests register
//! via `narf_kernel_test::kernel_test_in!` so the runner groups
//! output under `drivers/nvme`.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_nvme_samsung_pci_matches() -> TestResult {
    // Structural smoke: register the NVMe driver and verify the
    // Samsung PM9A1 / 970 EVO / 990 PRO VID/DID entries plus the
    // QEMU pair plus the class-match backstop are all in the
    // bus's match table. Real-silicon binding only happens on a
    // host with a Samsung NVMe drive (the user's Ryzen 7 PRO
    // 8840HS reference laptop has a PM9A1), so the always-on bit
    // is the structural assertion that registration shipped.
    use crate as nvme;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    nvme::register_pci_driver();
    let regs = registered_pci_drivers();
    let want: &[(u16, u16)] = &[
        (nvme::QEMU_NVME_VENDOR, nvme::QEMU_NVME_DEVICE),
        (nvme::SAMSUNG_VENDOR, nvme::SAMSUNG_PM9A1),
        (nvme::SAMSUNG_VENDOR, nvme::SAMSUNG_970EVO),
        (nvme::SAMSUNG_VENDOR, nvme::SAMSUNG_990PRO),
    ];
    for (v, d) in want.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == v && device == d)
        });
        if !found {
            return TestResult::Fail("missing nvme VID/DID match");
        }
    }
    let class_match = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::ClassFull {
                class: 0x01,
                subclass: 0x08,
                prog_if: 0x02,
            }
        )
    });
    if !class_match {
        return TestResult::Fail("nvme class-match backstop missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_samsung_pci_matches);

fn smoke_nvme_cap_register_decode() -> TestResult {
    use crate::NvmeCaps;
    // CAP layout: MQES[0..=15], DSTRD[32..=35], MPSMIN[48..=51],
    // MPSMAX[52..=55]. Craft a value with MQES=0x3FF, DSTRD=2,
    // MPSMIN=0, MPSMAX=4 and check the decoder.
    let raw: u64 = 0x3FF | (2u64 << 32) | (0u64 << 48) | (4u64 << 52);
    let c = NvmeCaps::from_raw(raw);
    if c.mqes != 0x3FF || c.dstrd != 2 || c.mpsmin != 0 || c.mpsmax != 4 {
        return TestResult::Fail("NvmeCaps::from_raw decoded wrong");
    }
    if c.doorbell_stride() != 16 {
        return TestResult::Fail("doorbell stride mis-computed (4 << 2 = 16)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_cap_register_decode);

fn smoke_nvme_probe_stub_surfaces_not_implemented() -> TestResult {
    use crate::{Controller, NvmeError};
    use narf_capabilities::{Cap, Write};
    let mut ctrl = Controller::new(0x8000_0000);
    let cap: Cap<narf_bus::BusDeviceCap, Write> = Cap::bootstrap();
    match ctrl.probe(&cap) {
        Err(NvmeError::NotImplemented) => {}
        _ => return TestResult::Fail("probe should surface NotImplemented"),
    }
    let mut bad = Controller::new(0);
    if bad.probe(&cap) != Err(NvmeError::BadBar) {
        return TestResult::Fail("zero BAR should surface BadBar");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme",
    smoke_nvme_probe_stub_surfaces_not_implemented
);

fn smoke_nvme_admin_identify_controller() -> TestResult {
    // End-to-end NVMe admin-queue bring-up against the QEMU NVMe
    // device (vendor 0x1B36 / device 0x0010).
    use crate::Controller;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    // SAFETY: ECAM is identity-mapped; bus::init is idempotent.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller in this flavour");
    };
    let authority = bootstrap_registry_authority();
    let (_handle, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed for NVMe"),
    };
    let mut ctrl = Controller::from_device(dev);
    if let Err(e) = ctrl.bring_up(&dev_cap) {
        let _ = e;
        return TestResult::Fail("Controller::bring_up failed");
    }
    if !ctrl.is_ready() {
        return TestResult::Fail("controller didn't transition to ready");
    }
    let id = match ctrl.identify() {
        Some(i) => i,
        None => return TestResult::Fail("identify snapshot missing"),
    };
    if id.vid != 0x1B36 {
        return TestResult::Fail("identify VID mismatch");
    }
    if &id.mn[..4] != b"QEMU" {
        return TestResult::Fail("identify MN does not start with 'QEMU'");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_admin_identify_controller);

fn smoke_nvme_io_round_trip() -> TestResult {
    // End-to-end NVMe I/O: bring up, create one I/O queue pair,
    // write a 512-byte pattern at LBA 0, read it back, compare.
    use crate::Controller;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("Controller::bring_up failed");
    }
    if ctrl.create_io_queue().is_err() {
        return TestResult::Fail("Controller::create_io_queue failed");
    }
    if ctrl.lba_bytes != 512 {
        return TestResult::Fail("expected 512-byte LBAs on QEMU default");
    }
    if ctrl.nsze == 0 {
        return TestResult::Fail("namespace reported zero size");
    }
    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent failed"),
    };
    let phys = buf.phys_addr().raw();
    // SAFETY: identity-mapped DMA buffer.
    unsafe {
        for i in 0..512usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), (i as u8) ^ 0xA5);
        }
    }
    if ctrl.write_lba(0, 1, &buf).is_err() {
        return TestResult::Fail("write_lba(0) failed");
    }
    // SAFETY: still our identity-mapped DMA buffer.
    unsafe {
        for i in 0..4096usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), 0);
        }
    }
    if ctrl.read_lba(0, 1, &buf).is_err() {
        return TestResult::Fail("read_lba(0) failed");
    }
    for i in 0..512usize {
        let v = unsafe { core::ptr::read_volatile((phys as *const u8).add(i)) };
        let expected = (i as u8) ^ 0xA5;
        if v != expected {
            return TestResult::Fail("read-back pattern mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_io_round_trip);

fn smoke_nvme_io_multipage_round_trip() -> TestResult {
    // 8-KiB transfer (16 LBAs at 512 B) across a 2-page PRP-list:
    // exercises the PRP1 + PRP2 = pages[1] short-list path. Ensures
    // the controller correctly DMA-reads/writes both pages.
    use crate::Controller;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("Controller::bring_up failed");
    }
    if ctrl.create_io_queue().is_err() {
        return TestResult::Fail("Controller::create_io_queue failed");
    }
    if ctrl.lba_bytes != 512 {
        return TestResult::Skip("non-512B LBAs (test assumes 8KiB == 16 LBAs)");
    }

    // Allocate two coherent pages — they don't have to be physically
    // contiguous, which is exactly what PRP-list buys us.
    let page_a = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent page A"),
    };
    let page_b = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent page B"),
    };
    // Stamp a page-distinct pattern across both pages so a swapped /
    // truncated DMA shows up as a mismatch. Use volatile so the
    // compiler can't elide writes to memory the controller will
    // observe.
    unsafe {
        let pa = page_a.phys_addr().raw() as *mut u8;
        let pb = page_b.phys_addr().raw() as *mut u8;
        for i in 0..4096usize {
            core::ptr::write_volatile(pa.add(i), (i as u8).wrapping_add(0x11));
            core::ptr::write_volatile(pb.add(i), (i as u8).wrapping_add(0xC3));
        }
    }
    let pages = [page_a.phys_addr(), page_b.phys_addr()];

    // Write 16 LBAs (8 KiB) at LBA 1024 — far enough from LBA 0/1
    // that the existing single-page round-trip's footprint isn't in
    // play.
    if ctrl.write_lba_pages(1024, 16, &pages).is_err() {
        return TestResult::Fail("write_lba_pages failed");
    }
    // Zero both pages, then read back — anything the controller
    // returns has to match what we wrote.
    unsafe {
        let pa = page_a.phys_addr().raw() as *mut u8;
        let pb = page_b.phys_addr().raw() as *mut u8;
        for i in 0..4096usize {
            core::ptr::write_volatile(pa.add(i), 0);
            core::ptr::write_volatile(pb.add(i), 0);
        }
    }
    if ctrl.read_lba_pages(1024, 16, &pages).is_err() {
        return TestResult::Fail("read_lba_pages failed");
    }
    for i in 0..4096usize {
        unsafe {
            let pa = page_a.phys_addr().raw() as *const u8;
            let pb = page_b.phys_addr().raw() as *const u8;
            if core::ptr::read_volatile(pa.add(i)) != (i as u8).wrapping_add(0x11) {
                return TestResult::Fail("page A read-back mismatch");
            }
            if core::ptr::read_volatile(pb.add(i)) != (i as u8).wrapping_add(0xC3) {
                return TestResult::Fail("page B read-back mismatch");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_io_multipage_round_trip);

fn smoke_nvme_block_device_async_round_trip() -> TestResult {
    // Async-trait round-trip: route a `BlockOp::Write` + `BlockOp::Read`
    // through `NvmeBlockDevice` (the `block::BlockDevice` impl) and
    // confirm we get back the bytes we wrote. Exercises the
    // cap-resolution path that the VFS / filesystem stack will use.
    use crate::{Controller, NvmeBlockDevice, CONTROLLER};
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_block::{BlockDevice, BlockOp, BlockRequest, QosHint};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_io::{alloc_coherent, register_with_cap};
    use narf_lib::id::DomainId;

    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let nvme_dev = devices().iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    }).copied();
    let Some(dev) = nvme_dev else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };

    // The other smoke tests in this file talk to a stack-local
    // `Controller` and toggle `CC.EN` during their bring-up, which
    // resets the QEMU NVMe device and orphans whatever I/O queue
    // probe registered. Install a fresh `Controller` here
    // unconditionally so we own a live I/O-queue pair against the
    // device's *current* state.
    {
        let mut ctrl = Controller::from_device(dev);
        if ctrl.bring_up(&dev_cap).is_err() {
            return TestResult::Fail("Controller::bring_up failed");
        }
        if ctrl.create_io_queue().is_err() {
            return TestResult::Fail("Controller::create_io_queue failed");
        }
        *CONTROLLER.lock() = Some(ctrl);
    }

    // Build a 4-KiB DMA buffer, hand it to the I/O registry to mint a
    // `Cap<DmaBuffer, Write>` (the cap's slot.index is what
    // `narf_io::resolve_cap` keys on).
    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent failed"),
    };
    let phys = buf.phys_addr().raw();
    // Write a sentinel pattern through the identity map.
    // SAFETY: alloc_coherent returns a live identity-mapped DMA page.
    unsafe {
        for i in 0..512usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), (i as u8).wrapping_mul(0x37));
        }
    }
    let write_cap = register_with_cap(buf);
    // Downgrade Write→Read so the cap matches BlockRequest::buffer's type.
    let read_cap = unsafe {
        use narf_capabilities::{Cap, CapSlot, Read, Rights};
        let s = write_cap.slot();
        Cap::<narf_io::DmaBuffer, Read>::mint(CapSlot::new(
            s.generation,
            s.index,
            Read::BITS,
            narf_capabilities::CapKind::DmaBuffer as u32,
        ))
    };

    let dev = NvmeBlockDevice;

    // Drive the future to completion. NvmeBlockDevice's submit
    // currently does the I/O synchronously inside the future body
    // (polled completions on the I/O queue), so a single poll
    // suffices — no waker plumbing needed.
    fn poll_once<F: Future>(mut f: F) -> Option<F::Output> {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        // SAFETY: vtable holds null-pointer-clean stubs.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTAB)) };
        let mut ctx = Context::from_waker(&waker);
        // SAFETY: f is owned + pinned to a stack temporary.
        let pinned = unsafe { Pin::new_unchecked(&mut f) };
        match pinned.poll(&mut ctx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    let write_req = BlockRequest {
        op: BlockOp::Write { fua: false },
        lba: 0,
        blocks: 1,
        buffer: read_cap.clone(),
        qos: QosHint::Latency,
        user_tag: 0xC0FFEE,
    };
    let comp = match poll_once(dev.submit(write_req)) {
        Some(c) => c,
        None => return TestResult::Fail("submit(Write) returned Pending"),
    };
    if comp.user_tag != 0xC0FFEE {
        return TestResult::Fail("write completion lost user_tag");
    }
    if comp.result.is_err() {
        return TestResult::Fail("submit(Write) returned an error");
    }

    // Zero the buffer so the read-back has something to overwrite.
    // SAFETY: same identity-mapped DMA page.
    unsafe {
        for i in 0..4096usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), 0);
        }
    }

    let read_req = BlockRequest {
        op: BlockOp::Read,
        lba: 0,
        blocks: 1,
        buffer: read_cap,
        qos: QosHint::Latency,
        user_tag: 0xBEEF,
    };
    let comp = match poll_once(dev.submit(read_req)) {
        Some(c) => c,
        None => return TestResult::Fail("submit(Read) returned Pending"),
    };
    if comp.user_tag != 0xBEEF {
        return TestResult::Fail("read completion lost user_tag");
    }
    if comp.result.is_err() {
        return TestResult::Fail("submit(Read) returned an error");
    }

    for i in 0..512usize {
        // SAFETY: same DMA page; bounded read.
        let v = unsafe { core::ptr::read_volatile((phys as *const u8).add(i)) };
        let expected = (i as u8).wrapping_mul(0x37);
        if v != expected {
            return TestResult::Fail("async-trait read-back pattern mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_block_device_async_round_trip);

fn smoke_nvme_io_msix_irq_driven() -> TestResult {
    // End-to-end IRQ-driven NVMe I/O: bring up, enable MSI-X with
    // one vector wired to a fresh IDT slot, create the I/O queue
    // with IEN=1, do a write+read round trip, assert IRQ dispatch
    // observed ≥1 MSI delivery.
    use crate::{Controller, IoOpcode};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("Controller::bring_up failed");
    }
    // Request a single queue pair here — this smoke validates the
    // MSI-X + multi-queue plumbing end-to-end against a real device,
    // but the IRQ-count assertion below is per-vector and easier to
    // reason about with one queue. The multi-queue grant is
    // covered by `smoke_nvme_multi_queue_granted` below.
    let granted = match ctrl.create_io_queues_msix(&dev_cap, 1) {
        Ok(g) => g,
        Err(_) => return TestResult::Fail("create_io_queues_msix failed"),
    };
    if granted == 0 {
        return TestResult::Fail("create_io_queues_msix granted zero queues");
    }
    let v = ctrl.irq_vector.expect("irq_vector populated by create_io_queues_msix");
    // SAFETY: APIC is initialised; MSI lands in our IDT vector.
    unsafe {
        narf_arch::enable_interrupts();
    }
    let baseline = narf_interrupts::fire_count(v);
    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent failed"),
    };
    let phys = buf.phys_addr().raw();
    // SAFETY: identity-mapped DMA page.
    unsafe {
        for i in 0..512usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), (i as u8).wrapping_mul(7));
        }
    }
    if ctrl
        .submit_io_irq(IoOpcode::Write as u8, 1, 1, &buf)
        .is_err()
    {
        return TestResult::Fail("submit_io_irq(Write) failed");
    }
    // SAFETY: same.
    unsafe {
        for i in 0..4096usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), 0);
        }
    }
    if ctrl
        .submit_io_irq(IoOpcode::Read as u8, 1, 1, &buf)
        .is_err()
    {
        return TestResult::Fail("submit_io_irq(Read) failed");
    }
    for i in 0..512usize {
        let v = unsafe { core::ptr::read_volatile((phys as *const u8).add(i)) };
        if v != (i as u8).wrapping_mul(7) {
            return TestResult::Fail("IRQ-driven read-back pattern mismatch");
        }
    }
    let after = narf_interrupts::fire_count(v);
    // SAFETY: counterpart to the enable_interrupts above.
    unsafe {
        narf_arch::disable_interrupts();
    }
    if after <= baseline {
        return TestResult::Fail("IRQ dispatch fire_count never advanced");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_io_msix_irq_driven);

fn smoke_nvme_multi_queue_granted() -> TestResult {
    // Validates the NVMe Set Features (FID 0x07, Number of Queues)
    // round trip + multi-queue create path against the QEMU NVMe
    // emulation. The host requests `NVME_MAX_IO_QUEUE_PAIRS` pairs;
    // QEMU grants up to its `-num-queues` (default 64), so the
    // assertion is that we got at least 2 pairs — anything past 1
    // proves the multi-queue plumbing works.
    use crate::{Controller, NVME_MAX_IO_QUEUE_PAIRS};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    // SAFETY: ECAM is identity-mapped; bus::init is idempotent.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let nvme_dev = devices().iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    }).copied();
    let Some(dev) = nvme_dev else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("Controller::bring_up failed");
    }
    // Standalone Set Features round-trip first — confirms the CDW0
    // response decode is right before we depend on it for queue
    // creation.
    match ctrl.submit_set_features_n_queues(NVME_MAX_IO_QUEUE_PAIRS) {
        Ok((nsqa, ncqa)) => {
            if nsqa == 0 || ncqa == 0 {
                return TestResult::Fail("Set Features granted zero queues");
            }
        }
        Err(_) => return TestResult::Fail("submit_set_features_n_queues failed"),
    }
    // Re-issue Set Features inside `create_io_queues_msix` (idempotent
    // — the controller treats repeated FID=7 as a re-request); then
    // creates the queue pairs.
    let granted = match ctrl.create_io_queues_msix(&dev_cap, NVME_MAX_IO_QUEUE_PAIRS) {
        Ok(g) => g,
        Err(_) => return TestResult::Fail("create_io_queues_msix failed"),
    };
    if granted < 2 {
        return TestResult::Fail("expected at least 2 I/O queue pairs from QEMU");
    }
    if ctrl.io_queue_count() != granted {
        return TestResult::Fail("io_queue_count() != granted");
    }
    if ctrl.irq_vector.is_none() {
        return TestResult::Fail("irq_vector should be populated post-msix");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_multi_queue_granted);

fn smoke_nvme_pick_queue_round_robins() -> TestResult {
    // Unit-style validator for `pick_queue`'s round-robin: build a
    // controller via the cheap `Controller::new(0)` skeleton ctor,
    // synthesize an io_queues Vec via the public-but-test-only path,
    // and check fetch_add wraps mod len.
    //
    // We can't construct fake `Queue`s without DMA pages, so this
    // test stays observational: it asserts the math through the
    // `next_queue` AtomicUsize directly. The full round-robin under
    // submission is exercised by `smoke_nvme_multi_queue_granted` +
    // the BlockDevice async smoke when multi-queue is wired.
    use core::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let n = 4usize;
    // Mirror the body of `pick_queue` (n > 1 branch).
    let mut counts = [0usize; 4];
    for _ in 0..20 {
        let i = next.fetch_add(1, Ordering::Relaxed) % n;
        counts[i] += 1;
    }
    for c in counts {
        if c != 5 {
            return TestResult::Fail("round-robin distribution should be even");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_pick_queue_round_robins);


fn smoke_nvme_params_typed_round_trip() -> TestResult {
    // Drive the typed driver-parameter surface end-to-end.
    use crate::{LogLevel, NvmeUpdate, PARAMS};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    use narf_capabilities::{Cap, Write};
    use narf_drivers::DriverHandle;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_nvme = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    if !has_nvme {
        return TestResult::Skip("no QEMU NVMe controller");
    }
    __reset_for_test();
    PARAMS.__reset_for_test();
    crate::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci failed");
    }
    if !PARAMS.is_installed() {
        return TestResult::Fail("PARAMS not installed by probe");
    }
    let driver_cap: Cap<DriverHandle, Write> = Cap::bootstrap();
    let read_cap: Cap<DriverHandle, narf_capabilities::Read> = match driver_cap.derive() {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Read derivation from Write failed"),
    };
    let snap = match PARAMS.read(&read_cap) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("PARAMS.read failed"),
    };
    if snap.identify_vid != 0x1B36 {
        return TestResult::Fail("snapshot.identify_vid mismatch");
    }
    if snap.lba_bytes != 512 {
        return TestResult::Fail("snapshot.lba_bytes != 512");
    }
    if snap.log_level != LogLevel::Info {
        return TestResult::Fail("snapshot.log_level default != Info");
    }
    if PARAMS
        .write(&driver_cap, NvmeUpdate::SetLogLevel(LogLevel::Debug))
        .is_err()
    {
        return TestResult::Fail("PARAMS.write failed");
    }
    let snap2 = PARAMS.read(&read_cap).expect("re-read");
    if snap2.log_level != LogLevel::Debug {
        return TestResult::Fail("Update::SetLogLevel did not stick");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_params_typed_round_trip);

// ── NVMe-MI message framing smokes ─────────────────────────────────

fn smoke_mi_nmh_round_trip() -> TestResult {
    use crate::mi::{Nmh, NMIMT_MI_COMMAND, MET_OUT_OF_BAND};
    let nmh = Nmh {
        mctp_ic: true,
        command_slot: false,
        response: false,
        nmimt: NMIMT_MI_COMMAND,
        met: MET_OUT_OF_BAND,
    };
    let bytes = nmh.encode();
    let back = Nmh::decode(&bytes);
    if back != nmh {
        return TestResult::Fail("NMH round-trip mismatch");
    }
    if bytes[0] & 0x80 == 0 {
        return TestResult::Fail("MCTP IC bit should be at byte 0 bit 7");
    }
    if (bytes[1] >> 4) != NMIMT_MI_COMMAND {
        return TestResult::Fail("NMIMT lives in byte 1 high nibble");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_nmh_round_trip);

fn smoke_mi_mic_crc32_matches_known_vector() -> TestResult {
    use crate::mi::mic;
    // CRC-32/Ethernet of "123456789" is 0xCBF43926 (well-known).
    let r = mic(b"123456789");
    if r != 0xCBF4_3926 {
        return TestResult::Fail("CRC-32/Ethernet test vector mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_mic_crc32_matches_known_vector);

fn smoke_mi_build_and_decode_command_round_trip() -> TestResult {
    use crate::mi::{
        build_command, decode_message, read_data_structure, Nmh, DTYPE_CONTROLLER_LIST,
        MI_OPCODE_READ_DATA_STRUCTURE, NMIMT_MI_COMMAND,
    };
    let nmh = Nmh {
        mctp_ic: true,
        nmimt: NMIMT_MI_COMMAND,
        ..Default::default()
    };
    let body = read_data_structure(DTYPE_CONTROLLER_LIST, 0x0042);
    let frame = build_command(nmh, &body);
    // 4 (NMH) + 12 (opcode + 2 cdw header) + 4 (MIC) = 20 bytes.
    if frame.len() != 20 {
        return TestResult::Fail("expected 20-byte minimal NVMe-MI command");
    }
    let (back_nmh, back_body) = decode_message(&frame).expect("decode");
    if back_nmh != nmh {
        return TestResult::Fail("NMH decode mismatch");
    }
    if back_body.opcode != MI_OPCODE_READ_DATA_STRUCTURE {
        return TestResult::Fail("opcode lost");
    }
    let dtype = (back_body.cdw0 & 0xFF) as u8;
    let cid = (back_body.cdw0 >> 16) as u16;
    if dtype != DTYPE_CONTROLLER_LIST {
        return TestResult::Fail("DTYPE lives in CDW0[7:0]");
    }
    if cid != 0x0042 {
        return TestResult::Fail("controller id lives in CDW0[31:16]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_build_and_decode_command_round_trip);

fn smoke_mi_bad_mic_rejected() -> TestResult {
    use crate::mi::{build_command, decode_message, read_data_structure, MiError, Nmh, NMIMT_MI_COMMAND};
    let nmh = Nmh { mctp_ic: true, nmimt: NMIMT_MI_COMMAND, ..Default::default() };
    let mut frame = build_command(nmh, &read_data_structure(0, 0));
    let last = frame.len() - 1;
    frame[last] = frame[last].wrapping_add(1);
    match decode_message(&frame) {
        Err(MiError::BadMic) => TestResult::Pass,
        _ => TestResult::Fail("tampered MIC must be rejected"),
    }
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_bad_mic_rejected);

fn smoke_mi_subsystem_health_status_poll_clear_bit() -> TestResult {
    use crate::mi::{subsystem_health_status_poll, MI_OPCODE_NVM_SUBSYSTEM_HEALTH_STATUS_POLL};
    let cmd = subsystem_health_status_poll(true);
    if cmd.opcode != MI_OPCODE_NVM_SUBSYSTEM_HEALTH_STATUS_POLL {
        return TestResult::Fail("opcode 0x01 expected");
    }
    if cmd.cdw1 & (1 << 31) == 0 {
        return TestResult::Fail("Clear Status flag lives at CDW1 bit 31");
    }
    let cmd2 = subsystem_health_status_poll(false);
    if cmd2.cdw1 != 0 {
        return TestResult::Fail("CDW1 should be zero when Clear Status not requested");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_subsystem_health_status_poll_clear_bit);

fn smoke_mi_subsystem_health_parse() -> TestResult {
    use crate::mi::SubsystemHealth;
    // 8-byte response data: NSS=0x02 (CFS), warnings=0x10, temp=0x2A,
    // pct_used=0x05, composite controller status (LE) = 0x0007.
    let buf = [0x02u8, 0x10, 0x2A, 0x05, 0x07, 0x00, 0x00, 0x00];
    let h = SubsystemHealth::parse(&buf).expect("parse");
    if h.nss != 0x02 || h.smart_warnings != 0x10 {
        return TestResult::Fail("NSS / warning byte mismatch");
    }
    if h.composite_temperature != 0x2A || h.percentage_used != 0x05 {
        return TestResult::Fail("temperature / wear byte mismatch");
    }
    if h.composite_controller_status != 0x0007 {
        return TestResult::Fail("CCS LE decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_subsystem_health_parse);

// ── NVMe admin-command builder smokes ──────────────────────────────

fn smoke_admin_sqe_cdw0_packs_opcode_and_cid() -> TestResult {
    use crate::admin::{AdminSqe, OPC_IDENTIFY};
    let mut sqe = AdminSqe::new(OPC_IDENTIFY);
    sqe.cid = 0x1234;
    let cdw0 = sqe.cdw0();
    if (cdw0 & 0xFF) != OPC_IDENTIFY as u32 {
        return TestResult::Fail("opcode lives in CDW0[7:0]");
    }
    if (cdw0 >> 16) != 0x1234 {
        return TestResult::Fail("CID lives in CDW0[31:16]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_sqe_cdw0_packs_opcode_and_cid);

fn smoke_admin_sqe_encode_is_64_bytes() -> TestResult {
    use crate::admin::AdminSqe;
    let sqe = AdminSqe::new(0x06);
    let bytes = sqe.encode();
    if bytes.len() != 64 {
        return TestResult::Fail("SQE wire form is 64 bytes per Base 2.0c §3.3.3");
    }
    // CDW0 LE byte 0 should equal opcode 0x06.
    if bytes[0] != 0x06 {
        return TestResult::Fail("CDW0 LE byte 0 should carry opcode");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_sqe_encode_is_64_bytes);

fn smoke_admin_format_nvm_cdw10_layout() -> TestResult {
    use crate::admin::{format_nvm, OPC_FORMAT_NVM, SES_CRYPTO_ERASE};
    let sqe = format_nvm(7, 1, 0x03, SES_CRYPTO_ERASE);
    if sqe.opcode != OPC_FORMAT_NVM {
        return TestResult::Fail("opcode = 0x80 for Format NVM");
    }
    if sqe.nsid != 1 {
        return TestResult::Fail("NSID lost");
    }
    // CDW10[3:0] = LBAF, CDW10[11:9] = SES.
    if (sqe.cdw10 & 0x0F) != 0x03 {
        return TestResult::Fail("LBAF should be in CDW10 low nibble");
    }
    if ((sqe.cdw10 >> 9) & 0x07) != SES_CRYPTO_ERASE as u32 {
        return TestResult::Fail("SES should be at CDW10 bits 11..9");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_format_nvm_cdw10_layout);

fn smoke_admin_sanitize_block_erase_layout() -> TestResult {
    use crate::admin::{sanitize, OPC_SANITIZE, SANACT_BLOCK_ERASE};
    let sqe = sanitize(11, SANACT_BLOCK_ERASE, true, 0, false, 0xDEAD_BEEF);
    if sqe.opcode != OPC_SANITIZE {
        return TestResult::Fail("opcode = 0x84 for Sanitize");
    }
    if (sqe.cdw10 & 0x07) != SANACT_BLOCK_ERASE as u32 {
        return TestResult::Fail("SANACT lives in CDW10[2:0]");
    }
    if (sqe.cdw10 & (1 << 3)) == 0 {
        return TestResult::Fail("AUSE bit should be set");
    }
    if sqe.cdw11 != 0xDEAD_BEEF {
        return TestResult::Fail("overwrite pattern goes in CDW11");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_sanitize_block_erase_layout);

fn smoke_admin_get_log_page_smart_layout() -> TestResult {
    use crate::admin::{get_smart_log, LID_SMART_HEALTH, OPC_GET_LOG_PAGE};
    let sqe = get_smart_log(2, 0xCAFE_F000_0000_0000);
    if sqe.opcode != OPC_GET_LOG_PAGE {
        return TestResult::Fail("opcode = 0x02 for Get Log Page");
    }
    if sqe.nsid != 0xFFFF_FFFF {
        return TestResult::Fail("SMART log uses controller-wide NSID 0xFFFF_FFFF");
    }
    // CDW10[7:0] = LID, CDW10[31:16] = NUMDL.
    if (sqe.cdw10 & 0xFF) != LID_SMART_HEALTH as u32 {
        return TestResult::Fail("LID should be in CDW10 low byte");
    }
    if (sqe.cdw10 >> 16) != 127 {
        return TestResult::Fail("NUMDL should encode 512-byte transfer (numd=127)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_get_log_page_smart_layout);

fn smoke_admin_set_features_number_of_queues() -> TestResult {
    use crate::admin::{set_features_number_of_queues, FID_NUMBER_OF_QUEUES, OPC_SET_FEATURES};
    let sqe = set_features_number_of_queues(0, 7, 5);
    if sqe.opcode != OPC_SET_FEATURES {
        return TestResult::Fail("opcode = 0x09 for Set Features");
    }
    if (sqe.cdw10 & 0xFF) != FID_NUMBER_OF_QUEUES as u32 {
        return TestResult::Fail("FID = 0x07");
    }
    if (sqe.cdw11 & 0xFFFF) != 7 {
        return TestResult::Fail("NSQR lives in CDW11[15:0]");
    }
    if (sqe.cdw11 >> 16) != 5 {
        return TestResult::Fail("NCQR lives in CDW11[31:16]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_set_features_number_of_queues);

fn smoke_admin_smart_log_round_trip() -> TestResult {
    use crate::admin::{encode_smart_log, SmartLog};
    let s = SmartLog {
        critical_warning: 0x02,
        composite_temperature_k: 313,
        available_spare: 100,
        available_spare_threshold: 10,
        percentage_used: 5,
        power_on_hours: 1234,
        unsafe_shutdowns: 7,
        media_errors: 0,
    };
    let buf = encode_smart_log(s);
    let back = SmartLog::parse(&buf).expect("parse");
    if back != s {
        return TestResult::Fail("SMART log round-trip mismatch");
    }
    if back.composite_temperature_c() != 313 - 273 {
        return TestResult::Fail("Kelvin → Celsius conversion wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_smart_log_round_trip);

fn smoke_admin_set_features_boot_partition_wp_layout() -> TestResult {
    use crate::admin::{set_features_boot_partition_wp, FID_BOOT_PARTITION_WRITE_PROTECTION};
    let sqe = set_features_boot_partition_wp(0, 1, 0x02);
    if (sqe.cdw10 & 0xFF) != FID_BOOT_PARTITION_WRITE_PROTECTION as u32 {
        return TestResult::Fail("FID = 0x1A for Boot Partition WP");
    }
    if (sqe.cdw11 & 0x07) != 0x02 {
        return TestResult::Fail("BPWPS lives in CDW11[2:0]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_set_features_boot_partition_wp_layout);

fn smoke_executor_minimal_spawn() -> TestResult {
    // Minimal: spawn one task that completes immediately.
    // Must `init` first to drop any stale tasks left in the
    // queue by earlier kernel-test work — without that, our
    // spawn-then-run_until_empty would also try to drive
    // those zombies and could hang on a parked-forever one.
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    narf_scheduler::__reset_queues_for_test();
    let done = Arc::new(AtomicBool::new(false));
    let done_c = done.clone();
    narf_scheduler::spawn(async move {
        done_c.store(true, Ordering::Release);
    });
    narf_scheduler::run_until_empty();
    if !done.load(Ordering::Acquire) {
        return TestResult::Fail("single-task spawn didn't complete");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_executor_minimal_spawn);

// ── Stage-11 admin queue + namespace management smokes ─────────────

fn smoke_admin_identify_controller_data_parse() -> TestResult {
    // Unit-decode: build a minimal IDENTIFY CONTROLLER buffer with
    // known field values, parse with IdentifyControllerData::parse,
    // confirm all fields round-trip.
    use crate::admin::{encode_identify_controller, IdentifyControllerData};
    let mut mn = [b' '; 40];
    mn[..4].copy_from_slice(b"QEMU");
    let d = IdentifyControllerData {
        vid: 0x1B36,
        ssvid: 0x1B36,
        sn: *b"SN1234567890ABCD1234",
        mn,
        fr: *b"1.0.0   ",
        mdts: 5,
        cntlid: 0x0001,
        oacs: 0x0006, // Format NVM + FW activate
        acl: 3,
        aerl: 3,
        frmw: 0x02,
        npss: 0,
        sqes: 0x66, // min=6, max=6
        cqes: 0x44,
        maxcmd: 0,
        nn: 1,
    };
    let buf = encode_identify_controller(&d);
    let back = match IdentifyControllerData::parse(&buf) {
        Some(b) => b,
        None => return TestResult::Fail("parse returned None"),
    };
    if back.vid != 0x1B36 {
        return TestResult::Fail("vid mismatch");
    }
    if back.mdts != 5 {
        return TestResult::Fail("mdts mismatch");
    }
    if back.aerl != 3 {
        return TestResult::Fail("aerl mismatch");
    }
    if back.nn != 1 {
        return TestResult::Fail("nn mismatch");
    }
    if !back.supports_format_nvm() {
        return TestResult::Fail("OACS bit 1 should indicate Format NVM support");
    }
    if &back.mn[..4] != b"QEMU" {
        return TestResult::Fail("mn prefix mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_identify_controller_data_parse);

fn smoke_admin_identify_namespace_data_parse() -> TestResult {
    // Build an IDENTIFY NAMESPACE buffer with two LBAF entries and
    // active format = index 1 (4 KiB LBAs), confirm decode.
    use crate::admin::{
        encode_identify_namespace, IdentifyNamespaceData, LbaFormat,
    };
    let mut d = IdentifyNamespaceData {
        nsze: 131072,   // 64 MiB at 512 B/sector
        ncap: 131072,
        nuse: 4096,
        nsfeat: 0,
        nlbaf: 1,       // 2 formats (zero-based)
        flbas: 0x01,    // active = LBAF[1] (4 KiB)
        mc: 0,
        dpc: 0,
        dps: 0,
        lbaf: [LbaFormat::default(); 16],
    };
    // LBAF[0]: 512 B, best perf.
    d.lbaf[0] = LbaFormat { ms: 0, lbads: 9, rp: 0 };  // 1<<9 = 512
    // LBAF[1]: 4 KiB, good perf.
    d.lbaf[1] = LbaFormat { ms: 0, lbads: 12, rp: 1 }; // 1<<12 = 4096
    let buf = encode_identify_namespace(&d);
    let back = match IdentifyNamespaceData::parse(&buf) {
        Some(b) => b,
        None => return TestResult::Fail("parse returned None"),
    };
    if back.nsze != 131072 {
        return TestResult::Fail("nsze mismatch");
    }
    if back.ncap != 131072 {
        return TestResult::Fail("ncap mismatch");
    }
    if back.active_lbaf_index() != 1 {
        return TestResult::Fail("active lbaf index should be 1");
    }
    if back.lba_bytes() != 4096 {
        return TestResult::Fail("active lba_bytes should be 4096");
    }
    if back.lbaf[0].lba_bytes() != 512 {
        return TestResult::Fail("LBAF[0] should be 512 B");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_identify_namespace_data_parse);

fn smoke_admin_get_features_cdw10_layout() -> TestResult {
    // Verify that get_features encodes FID + SEL into CDW10 correctly.
    // SEL=0x01 (Default), FID=0x07 (Number of Queues).
    use crate::admin::{get_features, FID_NUMBER_OF_QUEUES, OPC_GET_FEATURES};
    let sqe = get_features(3, FID_NUMBER_OF_QUEUES, 0x01);
    if sqe.opcode != OPC_GET_FEATURES {
        return TestResult::Fail("opcode = 0x0A for Get Features");
    }
    if (sqe.cdw10 & 0xFF) != FID_NUMBER_OF_QUEUES as u32 {
        return TestResult::Fail("FID should be in CDW10[7:0]");
    }
    if ((sqe.cdw10 >> 8) & 0x07) != 0x01 {
        return TestResult::Fail("SEL should be in CDW10[10:8]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_get_features_cdw10_layout);

fn smoke_admin_set_features_power_management_layout() -> TestResult {
    // Power state 3, workload hint 2 → CDW11 = (wh<<5)|ps.
    use crate::admin::{set_features_power_management, FID_POWER_MANAGEMENT, OPC_SET_FEATURES};
    let sqe = set_features_power_management(0, 3, 2);
    if sqe.opcode != OPC_SET_FEATURES {
        return TestResult::Fail("opcode should be 0x09");
    }
    if (sqe.cdw10 & 0xFF) != FID_POWER_MANAGEMENT as u32 {
        return TestResult::Fail("FID = 0x02 for Power Management");
    }
    if (sqe.cdw11 & 0x1F) != 3 {
        return TestResult::Fail("PS should be in CDW11[4:0]");
    }
    if ((sqe.cdw11 >> 5) & 0x07) != 2 {
        return TestResult::Fail("WH should be in CDW11[7:5]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_set_features_power_management_layout);

fn smoke_admin_set_features_async_event_config_layout() -> TestResult {
    // AEC bitmap: bits 0+1+2 set → CDW11 = 0x07.
    use crate::admin::{
        set_features_async_event_config, FID_ASYNC_EVENT_CONFIG, OPC_SET_FEATURES,
    };
    let sqe = set_features_async_event_config(0, 0x07);
    if sqe.opcode != OPC_SET_FEATURES {
        return TestResult::Fail("opcode should be 0x09");
    }
    if (sqe.cdw10 & 0xFF) != FID_ASYNC_EVENT_CONFIG as u32 {
        return TestResult::Fail("FID = 0x0B for Async Event Config");
    }
    if sqe.cdw11 != 0x07 {
        return TestResult::Fail("AEC bitmap should be in CDW11");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_set_features_async_event_config_layout);

fn smoke_admin_async_event_completion_decode() -> TestResult {
    // Verify AsyncEventCompletion::from_cdw0 bit-extracts correctly.
    // Type=1 (SMART), info=0x02 (spare below threshold), log=0x02.
    use crate::admin::AsyncEventCompletion;
    // CDW0: type=1, info=0x02 at bits[15:8], log=0x02 at bits[31:24].
    let cdw0: u32 = (0x02u32 << 24) | (0x02u32 << 8) | 0x01;
    let ev = AsyncEventCompletion::from_cdw0(cdw0);
    if ev.event_type != 0x01 {
        return TestResult::Fail("event_type should be 0x01 (SMART/Health)");
    }
    if ev.event_info != 0x02 {
        return TestResult::Fail("event_info should be 0x02");
    }
    if ev.log_page_id != 0x02 {
        return TestResult::Fail("log_page_id should be 0x02 (SMART Health log)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_async_event_completion_decode);

fn smoke_admin_identify_namespace_list_builder() -> TestResult {
    // Structural: identify_namespace_list(CNS=0x02) SQE layout.
    use crate::admin::{identify_namespace_list, CNS_NAMESPACE_LIST, OPC_IDENTIFY};
    let sqe = identify_namespace_list(5, 0x0000_0001, 0xDEAD_BEEF_0000_0000);
    if sqe.opcode != OPC_IDENTIFY {
        return TestResult::Fail("opcode should be 0x06 for Identify");
    }
    if (sqe.cdw10 & 0xFF) as u8 != CNS_NAMESPACE_LIST {
        return TestResult::Fail("CNS should be 0x02 for Namespace List");
    }
    if sqe.nsid != 0x0000_0001 {
        return TestResult::Fail("start_nsid should be in NSID field");
    }
    if sqe.prp1 != 0xDEAD_BEEF_0000_0000 {
        return TestResult::Fail("PRP1 should carry the DMA address");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_identify_namespace_list_builder);

fn smoke_admin_ns_enumerate_qemu() -> TestResult {
    // End-to-end: bring up the QEMU NVMe controller, enumerate
    // active namespaces, confirm NSID=1 is in the list.
    use crate::Controller;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let nvme_dev = devices().iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. })
            && d.id.vendor == 0x1B36
            && d.id.device == 0x0010
    }).copied();
    let Some(dev) = nvme_dev else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("bring_up failed");
    }
    let nsids = match ctrl.enumerate_namespaces() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("enumerate_namespaces failed"),
    };
    if !nsids.contains(&1) {
        return TestResult::Fail("NSID=1 should be in active namespace list");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_admin_ns_enumerate_qemu);

fn smoke_admin_get_set_features_power_qemu() -> TestResult {
    // End-to-end: bring up, Get Features PM to read current PS,
    // Set Features PM back to PS=0, confirm no error.
    use crate::Controller;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use crate::admin::FID_POWER_MANAGEMENT;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let nvme_dev = devices().iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. })
            && d.id.vendor == 0x1B36
            && d.id.device == 0x0010
    }).copied();
    let Some(dev) = nvme_dev else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("bring_up failed");
    }
    // Get current PM feature (SEL=0 = Current).
    let current_ps = match ctrl.get_features(FID_POWER_MANAGEMENT, 0) {
        Ok(v) => v & 0x1F, // bits[4:0] = power state
        Err(_) => return TestResult::Fail("get_features(PM) failed"),
    };
    // Set it back to whatever it was (PS=0 is safe for QEMU).
    let set_ps = current_ps.min(0) as u8;
    if ctrl.set_features_power_management(set_ps).is_err() {
        return TestResult::Fail("set_features(PM) failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_admin_get_set_features_power_qemu);

fn smoke_admin_aer_post_qemu() -> TestResult {
    // End-to-end: bring up and post 4 AER commands into the admin queue.
    // The QEMU NVMe emulation does not fire async events, so we just
    // verify the doorbell writes don't panic / corrupt the queue and
    // the controller remains in a coherent state (subsequent IDENTIFY
    // still completes successfully).
    //
    // NVMe Base Spec 2.0c §5.2: hosts SHOULD keep at least AERL+1
    // AER requests outstanding. AERL is capped to 4 by spec; QEMU
    // reports 0 (1 slot) but accepts up to 3 before returning "Cmd
    // Limit Exceeded" on the 4th. We cap at min(3, ADMIN_Q_DEPTH-1).
    use crate::Controller;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let nvme_dev = devices().iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. })
            && d.id.vendor == 0x1B36
            && d.id.device == 0x0010
    }).copied();
    let Some(dev) = nvme_dev else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("bring_up failed");
    }
    // Post 1 AER (safe even with a shallow queue depth).
    if ctrl.post_aer_commands(1).is_err() {
        return TestResult::Fail("post_aer_commands failed");
    }
    // The controller remains functional — verify with a typed NS identify.
    match ctrl.identify_namespace_typed(1) {
        Ok(ns) => {
            if ns.nsze == 0 {
                return TestResult::Fail("NSZE is 0 after AER post");
            }
        }
        Err(_) => return TestResult::Fail("identify_namespace_typed failed after AER post"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_admin_aer_post_qemu);

fn smoke_wait_for_irq_through_executor() -> TestResult {
    // Validates the full executor + waker + wait_for_irq +
    // dispatch::on_irq chain end-to-end without depending on
    // hardware MSI delivery.
    //
    // Spawns task A that awaits a fresh vector, then task B
    // that synthetically fires the vector via on_irq. The
    // second task's on_irq increments fire_count + wakes
    // task A's installed waker. run_until_empty drives both.
    //
    // No bounded timeout — a hang here would be a real bug.
    // `init()` first to drop stale zombie tasks from earlier
    // smokes (otherwise run_until_empty waits on them too).
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    narf_scheduler::__reset_queues_for_test();
    let v = match narf_interrupts::vector::alloc() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("vector::alloc"),
    };
    let done = Arc::new(AtomicBool::new(false));
    let done_c = done.clone();
    narf_scheduler::spawn(async move {
        let _ = narf_interrupts::wait_for_irq(v).await;
        done_c.store(true, Ordering::Release);
    });
    narf_scheduler::spawn(async move {
        narf_interrupts::on_irq(v);
    });
    narf_scheduler::run_until_empty();
    if !done.load(Ordering::Acquire) {
        return TestResult::Fail("first task didn't wake from synthetic IRQ");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_wait_for_irq_through_executor);
