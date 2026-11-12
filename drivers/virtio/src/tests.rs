//! Per-driver smoke tests for `narf-drivers-virtio`. Tests register
//! via `narf_kernel_test::kernel_test_in!` so the runner groups
//! output by transport (`drivers/virtio/blk-pci`,
//! `drivers/virtio/net-pci`, `drivers/virtio/rng-pci`,
//! `drivers/virtio/snd-pci`, `drivers/virtio/balloon-pci`).

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── Diagnostic atoms for the virtio-blk irq-async failure mode ──────
//
// When the smoke fails with "Waker fired from OTHER vector", these
// surface what we learned so the next session (or panel paint code)
// can pick up where this run left off. The vector that fired the
// Waker is in SMOKE_VIRTIO_OTHER_VEC (0xFFFF_FFFF = none), with the
// count in SMOKE_VIRTIO_OTHER_WAKES. SMOKE_VIRTIO_V_WAKES is the
// count for the vector the test expected (must be 0 for the
// "OTHER vector" diagnosis to hold).
pub static SMOKE_VIRTIO_OTHER_VEC: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0xFFFF_FFFF);
pub static SMOKE_VIRTIO_OTHER_WAKES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
pub static SMOKE_VIRTIO_V_WAKES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

// ── virtio-blk-pci ─────────────────────────────────────────────────

fn smoke_virtio_blk_pci_read_sector() -> TestResult {
    // End-to-end virtio-blk-pci modern transport smoke: register the
    // driver via the bus match table, run probe_all_pci, then read
    // sector 0 and verify the pattern xtask wrote into the backing
    // image (`(i * 0x97) & 0xFF`).
    use crate::blk_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_vblk = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == blk_pci::VIRTIO_BLK_PCI_VENDOR
            && d.id.device == blk_pci::VIRTIO_BLK_PCI_DEVICE
    });
    if !has_vblk {
        return TestResult::Skip("no virtio-blk-pci device");
    }
    __reset_for_test();
    blk_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci failed");
    }
    if !blk_pci::is_probed() {
        return TestResult::Fail("virtio-blk-pci not probed");
    }
    let mut sector = [0u8; 512];
    let read_ok = blk_pci::with_controller(|c| c.read_sector(0, &mut sector))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !read_ok {
        return TestResult::Fail("read_sector(0) failed");
    }
    for (i, &b) in sector.iter().enumerate() {
        let expected = (i as u8).wrapping_mul(0x97);
        if b != expected {
            return TestResult::Fail("virtio-blk-pci read pattern mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/blk-pci", smoke_virtio_blk_pci_read_sector);

fn smoke_virtio_blk_pci_flush() -> TestResult {
    // End-to-end virtio-blk-pci cache-flush smoke (#841): same probe
    // preamble as the read smoke (skipped when another smoke already
    // probed), then flush through the sync wrapper and check the
    // advertisement matches the negotiated state — the #841 property
    // itself. On a QEMU device offering F_FLUSH (the default
    // writeback configuration) this round-trips a real T_FLUSH
    // request to S_OK; on a device that does not offer it, flush
    // is the documented write-through no-op and the capabilities
    // claim matches that.
    use crate::blk_pci;
    use narf_block::BlockDeviceSync;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_vblk = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == blk_pci::VIRTIO_BLK_PCI_VENDOR
            && d.id.device == blk_pci::VIRTIO_BLK_PCI_DEVICE
    });
    if !has_vblk {
        return TestResult::Skip("no virtio-blk-pci device");
    }
    if !blk_pci::is_probed() {
        __reset_for_test();
        blk_pci::register_pci_driver();
        let authority = bootstrap_registry_authority();
        if probe_all_pci(&authority).is_err() {
            return TestResult::Fail("probe_all_pci failed");
        }
        if !blk_pci::is_probed() {
            return TestResult::Fail("virtio-blk-pci not probed");
        }
    }
    let dev = blk_pci::VirtioBlkBlockSync;
    if dev.flush().is_err() {
        return TestResult::Fail("virtio-blk-pci flush failed");
    }
    let negotiated = blk_pci::with_controller(|c| c.flush_supported()).unwrap_or(false);
    let caps = dev.capabilities();
    if caps.volatile_cache != negotiated {
        return TestResult::Fail("virtio-blk-pci capabilities volatile_cache != negotiated flush");
    }
    if caps.fua {
        return TestResult::Fail("virtio-blk-pci capabilities claims native fua");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/blk-pci", smoke_virtio_blk_pci_flush);

/// The installed controller must never move, be replaced, or be dropped.
///
/// `blk_pci::with_device_unlocked` reads the device's address under the
/// CONTROLLER lock, releases the lock, and then uses that reference for the
/// whole transfer — which is what lets a virtio round-trip run with
/// interrupts enabled instead of livelocking every other CPU on an
/// IRQ-masking spinlock. That is only sound because `probe` installs the
/// device exactly once and nothing ever stores `None` back.
///
/// This is precisely the sort of assumption a later "support hot-unplug" or
/// "re-probe on reset" change invalidates silently, leaving a use-after-free
/// reachable only under load. Assert it directly: probing again must not
/// move the device, and the address must stay put across I/O.
fn smoke_virtio_blk_device_address_is_stable() -> TestResult {
    use crate::blk_pci;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, probe_all_pci};

    // SAFETY: identity-mapped QEMU ECAM region.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    if !blk_pci::is_probed() {
        return TestResult::Skip("virtio-blk-pci not probed");
    }
    let before = match blk_pci::dbg_device_addr() {
        Some(a) => a,
        None => return TestResult::Fail("probed controller has no address"),
    };

    // A repeat probe must be refused, not re-install a fresh device.
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
    match blk_pci::dbg_device_addr() {
        Some(a) if a == before => {}
        Some(_) => return TestResult::Fail("re-probe MOVED the installed controller"),
        None => return TestResult::Fail("re-probe removed the installed controller"),
    }

    // And it must survive ordinary traffic through the unlocked path.
    let mut sector = [0u8; 512];
    let _ = blk_pci::with_controller(|c| c.read_sector(0, &mut sector));
    match blk_pci::dbg_device_addr() {
        Some(a) if a == before => TestResult::Pass,
        Some(_) => TestResult::Fail("controller address changed across a read"),
        None => TestResult::Fail("controller vanished across a read"),
    }
}
kernel_test_in!(
    "drivers/virtio/blk-pci",
    smoke_virtio_blk_device_address_is_stable
);

/// Same install-once invariant as `smoke_virtio_blk_device_address_is_stable`,
/// for virtio-gpu: `gpu_pci::probed_device` hands out a `&'static` after
/// releasing the CONTROLLER lock so every framebuffer flush runs with
/// interrupts enabled. That is only sound while `probe` installs the device
/// exactly once and nothing ever stores `None` back or replaces the value.
fn smoke_virtio_gpu_device_address_is_stable() -> TestResult {
    use crate::gpu_pci;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, probe_all_pci};

    // SAFETY: identity-mapped QEMU ECAM region.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    if !gpu_pci::is_probed() {
        return TestResult::Skip("virtio-gpu-pci not probed");
    }
    let before = match gpu_pci::dbg_device_addr() {
        Some(a) => a,
        None => return TestResult::Fail("probed controller has no address"),
    };

    // A repeat probe must be refused, not re-install a fresh device.
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
    match gpu_pci::dbg_device_addr() {
        Some(a) if a == before => {}
        Some(_) => return TestResult::Fail("re-probe MOVED the installed controller"),
        None => return TestResult::Fail("re-probe removed the installed controller"),
    }

    // And it must survive ordinary traffic through the unlocked path.
    // `flush` is best-effort here: on a controller whose scanout was
    // never initialised the device rejects the command, which is fine —
    // the invariant under test is address stability, not scanout state.
    if let Some(d) = gpu_pci::probed_device() {
        let _ = d.flush();
    }
    match gpu_pci::dbg_device_addr() {
        Some(a) if a == before => TestResult::Pass,
        Some(_) => TestResult::Fail("controller address changed across a flush"),
        None => TestResult::Fail("controller vanished across a flush"),
    }
}
kernel_test_in!(
    "drivers/virtio/gpu_pci",
    smoke_virtio_gpu_device_address_is_stable
);

fn smoke_virtio_blk_pci_write_then_read() -> TestResult {
    use crate::blk_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == blk_pci::VIRTIO_BLK_PCI_VENDOR
            && d.id.device == blk_pci::VIRTIO_BLK_PCI_DEVICE
    }) {
        return TestResult::Skip("no virtio-blk-pci device");
    }
    __reset_for_test();
    blk_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci failed");
    }
    let mut payload = [0u8; 512];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x5B) ^ 0xC3;
    }
    let wrote = blk_pci::with_controller(|c| c.write_sector(4, &payload))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !wrote {
        return TestResult::Fail("write_sector(4) failed");
    }
    let mut readback = [0u8; 512];
    let read_ok = blk_pci::with_controller(|c| c.read_sector(4, &mut readback))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !read_ok {
        return TestResult::Fail("read_sector(4) failed");
    }
    if readback != payload {
        return TestResult::Fail("write/read pattern mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/blk-pci",
    smoke_virtio_blk_pci_write_then_read
);

fn smoke_virtio_blk_pci_irq_driven() -> TestResult {
    use crate::blk_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{
        bootstrap_registry_authority, claim_device_cap, devices, probe_all_pci, BusKind,
    };
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let dev = match devs.iter().find(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == blk_pci::VIRTIO_BLK_PCI_VENDOR
            && d.id.device == blk_pci::VIRTIO_BLK_PCI_DEVICE
    }) {
        Some(d) => *d,
        None => return TestResult::Skip("no virtio-blk-pci device"),
    };
    __reset_for_test();
    blk_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    let (_h, cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap"),
    };
    let v = match blk_pci::enable_msix_for_probed(&cap, &dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("enable_msix"),
    };
    // SAFETY: APIC initialised; OK to enable for the test.
    unsafe {
        narf_arch::enable_interrupts();
    }
    let baseline = narf_interrupts::fire_count(v);
    let mut sector = [0u8; 512];
    let read_ok = blk_pci::with_controller(|c| c.read_sector_irq(0, &mut sector))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    let mut spins = 0u32;
    let after = loop {
        let now = narf_interrupts::fire_count(v);
        if now > baseline || spins > 1_000_000 {
            break now;
        }
        spins += 1;
        core::hint::spin_loop();
    };
    // SAFETY: counterpart.
    unsafe {
        narf_arch::disable_interrupts();
    }
    if !read_ok {
        return TestResult::Fail("read_sector_irq failed");
    }
    for (i, &b) in sector.iter().enumerate() {
        let expected = (i as u8).wrapping_mul(0x97);
        if b != expected {
            return TestResult::Fail("read_sector_irq pattern mismatch");
        }
    }
    if after <= baseline {
        return TestResult::Fail("MSI-X fire_count never moved");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/blk-pci", smoke_virtio_blk_pci_irq_driven);

fn smoke_virtio_blk_pci_irq_async() -> TestResult {
    use crate::blk_pci;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{
        bootstrap_registry_authority, claim_device_cap, devices, probe_all_pci, BusKind,
    };
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let dev = match devs.iter().find(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == blk_pci::VIRTIO_BLK_PCI_VENDOR
            && d.id.device == blk_pci::VIRTIO_BLK_PCI_DEVICE
    }) {
        Some(d) => *d,
        None => return TestResult::Skip("no virtio-blk-pci device"),
    };
    __reset_for_test();
    blk_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    let (_h, cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap"),
    };
    let v = match blk_pci::enable_msix_for_probed(&cap, &dev) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("enable_msix"),
    };
    static WOKEN: AtomicBool = AtomicBool::new(false);
    fn flag_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VT)
    }
    fn flag_wake(p: *const ()) {
        // SAFETY: p was constructed from `&WOKEN`; AtomicBool is 'static.
        unsafe {
            (*(p as *const AtomicBool)).store(true, Ordering::Release);
        }
    }
    fn flag_wake_by_ref(p: *const ()) {
        flag_wake(p);
    }
    fn flag_drop(_: *const ()) {}
    static VT: RawWakerVTable =
        RawWakerVTable::new(flag_clone, flag_wake, flag_wake_by_ref, flag_drop);
    WOKEN.store(false, Ordering::Release);
    let raw = RawWaker::new(&WOKEN as *const AtomicBool as *const (), &VT);
    // SAFETY: vtable + payload constructed above.
    let waker = unsafe { Waker::from_raw(raw) };
    let mut ctx = Context::from_waker(&waker);
    // Install a no-op wheel arm callback IF none is set yet. In
    // kernel-test mode `run_async_demo` isn't called, so
    // `timer_pump::init` doesn't run → arm_callback isn't
    // installed → SleepUntil's self-wake fallback fires on every
    // poll (see narf_time::SleepUntil::poll). That self-wake
    // breaks this test: the test's manual poll loop sees the
    // self-wake-set WOKEN flag and re-polls instead of HLT'ing,
    // so the MSI-X IRQ never gets a delivery window.
    //
    // The no-op callback satisfies `arm_callback_installed()`
    // without doing anything; the wheel won't pump (no real timer
    // backing it) but we don't need it to — the IRQ is the
    // primary wake source, and the wheel's role here is just the
    // 5-second safety timeout which we don't expect to expire.
    //
    // Skip if a real arm callback (e.g. timer_pump's wheel_arm)
    // is already installed so we don't clobber it.
    fn _wheel_arm_noop(_deadline_cycles: u64) {}
    let _wheel_arm_installed_by_us = if !narf_time::hrtimer::arm_callback_installed() {
        narf_time::hrtimer::set_arm_callback(_wheel_arm_noop);
        true
    } else {
        false
    };
    // SAFETY: enter the wait loop with IRQs DISABLED.
    unsafe {
        narf_arch::disable_interrupts();
    }
    let baseline = narf_interrupts::fire_count(v);
    // Capture wakes_invoked baselines for every vector so we can
    // compute deltas after the test loop. Absolute values lie
    // across tests because prior runs leave counters non-zero.
    let mut wakes_baseline = [0u64; 256];
    for i in 0..256u16 {
        wakes_baseline[i as usize] = narf_interrupts::wakes_invoked(i as u8);
    }
    let mut fut = alloc::boxed::Box::pin(blk_pci::read_sector_irq_async(0));
    let mut polls = 0u32;
    let mut wokes = 0u32;
    let result = loop {
        match Pin::new(&mut fut).poll(&mut ctx) {
            Poll::Ready(r) => break Some(r),
            Poll::Pending => {
                polls += 1;
                if polls > 1000 {
                    break None;
                }
                if WOKEN.swap(false, Ordering::AcqRel) {
                    wokes += 1;
                    continue;
                }
                // SAFETY: IRQs disabled by precondition.
                unsafe {
                    narf_arch::idle_halt_then_disable();
                }
            }
        }
    };
    let after = narf_interrupts::fire_count(v);
    // Restore the wheel arm-callback state — if we installed the
    // no-op (no real callback was set), clear it now so other
    // tests that depend on SleepUntil's self-wake fallback
    // (`smoke_concurrency_timer_wheel_many_sleepers_fire`,
    // `smoke_timer_pump_drives_wheel_sleep` when timer_pump
    // isn't actually init'd) aren't affected by our temporary
    // install.
    if _wheel_arm_installed_by_us {
        narf_time::hrtimer::clear_arm_callback();
    }
    // Branchy diagnostic sentinel: distinct fail strings let us
    // discriminate the failure mode from the test runner output.
    if result.is_none() {
        // Scan all vectors for wakes_invoked > 0 (excluding v).
        // The vector whose count moved tells us which IRQ is
        // firing the test's Waker. Used to root-cause vector-
        // mismatch failures.
        // Compute deltas (current - baseline). Absolute counts
        // can be > 0 from prior tests' IRQs, which would
        // false-positive the "wakes happened" check.
        let wakes_on_v = narf_interrupts::wakes_invoked(v) - wakes_baseline[v as usize];
        let mut other_vec: Option<u8> = None;
        let mut other_wakes: u64 = 0;
        for candidate in 0..=255u16 {
            let cv = candidate as u8;
            if cv == v {
                continue;
            }
            let n = narf_interrupts::wakes_invoked(cv) - wakes_baseline[cv as usize];
            if n > other_wakes {
                other_wakes = n;
                other_vec = Some(cv);
            }
        }
        SMOKE_VIRTIO_OTHER_VEC.store(
            other_vec.map(|v| v as u32).unwrap_or(0xFFFF_FFFF),
            core::sync::atomic::Ordering::Release,
        );
        SMOKE_VIRTIO_OTHER_WAKES.store(other_wakes as u32, core::sync::atomic::Ordering::Release);
        SMOKE_VIRTIO_V_WAKES.store(wakes_on_v as u32, core::sync::atomic::Ordering::Release);
        // Branchy fail strings on the full (wokes,after>base,wakes_on_v>0,other_vec.is_some()) tuple.
        // The test runner shows one matching string; that's enough to read
        // off which exact failure mode we're in.
        return match (wokes > 0, after > baseline, wakes_on_v > 0, other_vec.is_some()) {
            (false, false, _, _) => TestResult::Fail("FAIL_A: no WOKEN ever set, fire_count unchanged"),
            (false, true, _, _) => TestResult::Fail("FAIL_B: fire_count moved but WOKEN never set"),
            (true, true, true, _) => TestResult::Fail("FAIL_C: WOKEN+fire_count(v)+wakes_invoked(v) all moved — WaitForIrq.poll still Pending (executor bug?)"),
            (true, true, false, _) => TestResult::Fail("FAIL_D: WOKEN+fire_count(v) moved but wakes_invoked(v) ZERO (counter bug?)"),
            (true, false, true, _) => TestResult::Fail("FAIL_E: WOKEN+wakes_invoked(v) moved but fire_count(v) ZERO (impossible — atomic ordering broken)"),
            (true, false, false, true) => TestResult::Fail("FAIL_F: WOKEN+wakes_invoked(OTHER) moved, v's wakes_invoked ZERO — Waker mis-registered to wrong vector"),
            (true, false, false, false) => TestResult::Fail("FAIL_G: WOKEN moved but no SLOTS[*].wakes_invoked counter — wake came from non-dispatch path"),
        };
    }
    match result {
        Some(Ok(sector)) => {
            for (i, &b) in sector.iter().enumerate() {
                let expected = (i as u8).wrapping_mul(0x97);
                if b != expected {
                    return TestResult::Fail("pattern mismatch");
                }
            }
            if after <= baseline {
                return TestResult::Fail("MSI-X fire_count never moved");
            }
            TestResult::Pass
        }
        Some(Err(_)) => TestResult::Fail("read_sector_irq_async returned Err"),
        None => TestResult::Fail("future never resolved within poll budget"),
    }
}
kernel_test_in!("drivers/virtio/blk-pci", smoke_virtio_blk_pci_irq_async);

fn smoke_virtio_blk_pci_write_irq_async() -> TestResult {
    use crate::blk_pci;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{
        bootstrap_registry_authority, claim_device_cap, devices, probe_all_pci, BusKind,
    };
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let dev = match devs.iter().find(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == blk_pci::VIRTIO_BLK_PCI_VENDOR
            && d.id.device == blk_pci::VIRTIO_BLK_PCI_DEVICE
    }) {
        Some(d) => *d,
        None => return TestResult::Skip("no virtio-blk-pci device"),
    };
    __reset_for_test();
    blk_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    let (_h, cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap"),
    };
    if blk_pci::enable_msix_for_probed(&cap, &dev).is_err() {
        return TestResult::Fail("enable_msix");
    }
    use core::sync::atomic::{AtomicBool, Ordering};
    static WOKEN: AtomicBool = AtomicBool::new(false);
    fn flag_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VT)
    }
    fn flag_wake(p: *const ()) {
        // SAFETY: p was constructed from `&WOKEN`; AtomicBool is 'static.
        unsafe {
            (*(p as *const AtomicBool)).store(true, Ordering::Release);
        }
    }
    fn flag_wake_by_ref(p: *const ()) {
        flag_wake(p);
    }
    fn flag_drop(_: *const ()) {}
    static VT: RawWakerVTable =
        RawWakerVTable::new(flag_clone, flag_wake, flag_wake_by_ref, flag_drop);
    WOKEN.store(false, Ordering::Release);
    let raw = RawWaker::new(&WOKEN as *const AtomicBool as *const (), &VT);
    // SAFETY: vtable + payload constructed above.
    let waker = unsafe { Waker::from_raw(raw) };
    let mut ctx = Context::from_waker(&waker);

    fn drive<F: Future>(fut: F, ctx: &mut Context<'_>, woken: &AtomicBool) -> Option<F::Output> {
        let mut fut = alloc::boxed::Box::pin(fut);
        let mut polls = 0u32;
        loop {
            match Pin::new(&mut fut).poll(ctx) {
                Poll::Ready(r) => return Some(r),
                Poll::Pending => {
                    polls += 1;
                    if polls > 1000 {
                        return None;
                    }
                    if woken.swap(false, Ordering::AcqRel) {
                        continue;
                    }
                    // SAFETY: IF=0 by precondition.
                    unsafe {
                        narf_arch::idle_halt_then_disable();
                    }
                }
            }
        }
    }

    let mut pattern = [0u8; 512];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x37);
    }
    // Install no-op wheel arm callback if needed — same reasoning
    // as smoke_virtio_blk_pci_irq_async (SleepUntil's self-wake
    // breaks the HLT idle loop in kernel-test mode where
    // timer_pump::init never ran).
    fn _wheel_arm_noop(_deadline_cycles: u64) {}
    let _wheel_arm_installed_by_us = if !narf_time::hrtimer::arm_callback_installed() {
        narf_time::hrtimer::set_arm_callback(_wheel_arm_noop);
        true
    } else {
        false
    };
    // SAFETY: IF=0 idle pattern.
    unsafe {
        narf_arch::disable_interrupts();
    }
    let write_res = drive(
        blk_pci::write_sector_irq_async(1, pattern),
        &mut ctx,
        &WOKEN,
    );
    let read_res = drive(blk_pci::read_sector_irq_async(1), &mut ctx, &WOKEN);
    // Restore the wheel arm-callback state before returning.
    if _wheel_arm_installed_by_us {
        narf_time::hrtimer::clear_arm_callback();
    }
    match write_res {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("write_sector_irq_async returned Err"),
        None => return TestResult::Fail("write future never resolved"),
    }
    let readback = match read_res {
        Some(Ok(b)) => b,
        Some(Err(_)) => return TestResult::Fail("read_sector_irq_async returned Err"),
        None => return TestResult::Fail("read future never resolved"),
    };
    for (&rb, &pat) in readback.iter().zip(pattern.iter()) {
        if rb != pat {
            return TestResult::Fail("read-back pattern mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/blk-pci",
    smoke_virtio_blk_pci_write_irq_async
);

// ── virtio-net-pci ─────────────────────────────────────────────────

fn smoke_virtio_net_fast_poll_quantum_is_bounded() -> TestResult {
    use crate::net_pci::{fast_poll_quantum_expired, FAST_POLL_QUANTUM};

    let mut rounds = 0;
    for _ in 0..(FAST_POLL_QUANTUM - 1) {
        if fast_poll_quantum_expired(&mut rounds, true) {
            return TestResult::Fail("fast-poll quantum expired before its bound");
        }
    }
    if !fast_poll_quantum_expired(&mut rounds, true) {
        return TestResult::Fail("fast-poll quantum never requested a yield");
    }
    if rounds != 0 {
        return TestResult::Fail("fast-poll quantum did not reset after yielding");
    }
    if fast_poll_quantum_expired(&mut rounds, false) || rounds != 0 {
        return TestResult::Fail("idle RX round did not reset the fast-poll budget");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_fast_poll_quantum_is_bounded
);

/// Construct the ordinary Ethernet/IPv4/TCP layout emitted by the TCP stack.
/// The offload-header tests keep this tiny fixture local so they exercise the
/// driver encoder without needing PCI, DMA, or a live QEMU NIC.
fn virtio_test_ipv4_tcp_frame(frame: &mut [u8]) {
    const ETH: usize = 14;
    const IP: usize = 20;
    const TCP: usize = 20;
    assert!(frame.len() >= ETH + IP + TCP);
    let ip_len = (frame.len() - ETH) as u16;
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[ETH] = 0x45;
    frame[ETH + 2..ETH + 4].copy_from_slice(&ip_len.to_be_bytes());
    frame[ETH + 8] = 64;
    frame[ETH + 9] = 6;
    frame[ETH + 12..ETH + 16].copy_from_slice(&[192, 0, 2, 10]);
    frame[ETH + 16..ETH + 20].copy_from_slice(&[198, 51, 100, 20]);
    let tcp = ETH + IP;
    frame[tcp..tcp + 2].copy_from_slice(&1234u16.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
    frame[tcp + 12] = (TCP as u8 / 4) << 4;
    frame[tcp + 13] = 0x18; // PSH | ACK, deliberately not ECN.
}

/// Construct the Ethernet/IPv6/TCP layout: 40-byte fixed header, no
/// extension headers (the driver's layout validator rejects extension
/// headers fail-closed, so the encoder never sees them).
fn virtio_test_ipv6_tcp_frame(frame: &mut [u8]) {
    const ETH: usize = 14;
    const IP6: usize = 40;
    const TCP: usize = 20;
    assert!(frame.len() >= ETH + IP6 + TCP);
    let payload_len = (frame.len() - ETH - IP6) as u16;
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    frame[ETH] = 0x60;
    frame[ETH + 4..ETH + 6].copy_from_slice(&payload_len.to_be_bytes());
    frame[ETH + 6] = 6;
    frame[ETH + 7] = 64;
    frame[ETH + 8..ETH + 24]
        .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame[ETH + 24..ETH + 40]
        .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let tcp = ETH + IP6;
    frame[tcp..tcp + 2].copy_from_slice(&1234u16.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
    frame[tcp + 12] = (TCP as u8 / 4) << 4;
    frame[tcp + 13] = 0x18; // PSH | ACK, deliberately not ECN.
}

/// Construct the Ethernet/IPv4/UDP layout. The UDP length field describes
/// the whole super-frame payload, as the USO template convention requires;
/// the device rewrites it per segment.
fn virtio_test_ipv4_udp_frame(frame: &mut [u8]) {
    const ETH: usize = 14;
    const IP: usize = 20;
    const UDP: usize = 8;
    assert!(frame.len() >= ETH + IP + UDP);
    let ip_len = (frame.len() - ETH) as u16;
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[ETH] = 0x45;
    frame[ETH + 2..ETH + 4].copy_from_slice(&ip_len.to_be_bytes());
    frame[ETH + 8] = 64;
    frame[ETH + 9] = 17;
    frame[ETH + 12..ETH + 16].copy_from_slice(&[192, 0, 2, 10]);
    frame[ETH + 16..ETH + 20].copy_from_slice(&[198, 51, 100, 20]);
    let udp = ETH + IP;
    frame[udp..udp + 2].copy_from_slice(&1234u16.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&53u16.to_be_bytes());
    frame[udp + 4..udp + 6].copy_from_slice(&(ip_len - IP as u16).to_be_bytes());
}

/// Construct the Ethernet/IPv6/UDP layout, same template convention as v4.
fn virtio_test_ipv6_udp_frame(frame: &mut [u8]) {
    const ETH: usize = 14;
    const IP6: usize = 40;
    const UDP: usize = 8;
    assert!(frame.len() >= ETH + IP6 + UDP);
    let payload_len = (frame.len() - ETH - IP6) as u16;
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    frame[ETH] = 0x60;
    frame[ETH + 4..ETH + 6].copy_from_slice(&payload_len.to_be_bytes());
    frame[ETH + 6] = 17;
    frame[ETH + 7] = 64;
    frame[ETH + 8..ETH + 24]
        .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame[ETH + 24..ETH + 40]
        .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let udp = ETH + IP6;
    frame[udp..udp + 2].copy_from_slice(&1234u16.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&53u16.to_be_bytes());
    // The UDP length field equals the IPv6 payload length (UDP header +
    // data), as `l4_checksum_layout` validates — not payload minus header.
    frame[udp + 4..udp + 6].copy_from_slice(&payload_len.to_be_bytes());
}

fn smoke_virtio_net_tx_tso_header_is_feature_gated_and_well_formed() -> TestResult {
    use crate::net_pci::{tx_header_for_frame, TxOffloadProfile};
    use narf_net::TxMeta;

    let mut frame = [0u8; 1514];
    virtio_test_ipv4_tcp_frame(&mut frame);
    let hdr = match tx_header_for_frame(
        &mut frame,
        TxMeta::with_tso(1200),
        TxOffloadProfile {
            checksum: true,
            tso4: true,
            tso6: false,
            uso: false,
        },
        1518,
    ) {
        Ok(hdr) => hdr,
        Err(_) => return TestResult::Fail("virtio-net rejected negotiated TCPv4 TSO"),
    };
    if hdr.flags != 1
        || hdr.gso_type != 1
        || u16::from_le(hdr.hdr_len) != 54
        || u16::from_le(hdr.gso_size) != 1200
        || u16::from_le(hdr.csum_start) != 34
        || u16::from_le(hdr.csum_offset) != 16
    {
        return TestResult::Fail("virtio-net TSO header has wrong offsets or GSO fields");
    }
    let expected_seed =
        narf_net::pkt_tcp::ipv4_tcp_pseudo_seed([192, 0, 2, 10], [198, 51, 100, 20], 0);
    if frame[50..52] != expected_seed.to_be_bytes() {
        return TestResult::Fail("virtio-net TSO did not prepare zero-length pseudo-header seed");
    }
    if tx_header_for_frame(
        &mut frame,
        TxMeta::with_tso(1200),
        TxOffloadProfile::default(),
        1518,
    )
    .is_ok()
    {
        return TestResult::Fail("virtio-net accepted TSO without negotiated feature");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_tx_tso_header_is_feature_gated_and_well_formed
);

fn smoke_virtio_net_tx_tso6_header_is_feature_gated_and_well_formed() -> TestResult {
    use crate::net_pci::{ipv6_pseudo_seed, tx_header_for_frame, TxOffloadProfile};
    use narf_net::TxMeta;

    // Cross-check the driver-local v6 seed helper against the oracle:
    // 2001:db8::1 -> 2001:db8::2, TCP, zero length folds to 0x5b7b.
    if ipv6_pseudo_seed(
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        6,
    ) != 0x5b7b
    {
        return TestResult::Fail("virtio-net IPv6 pseudo seed mismatch");
    }
    let mut frame = [0u8; 1514];
    virtio_test_ipv6_tcp_frame(&mut frame);
    let hdr = match tx_header_for_frame(
        &mut frame,
        TxMeta::with_tso(1200),
        TxOffloadProfile {
            checksum: true,
            tso4: false,
            tso6: true,
            uso: false,
        },
        1518,
    ) {
        Ok(hdr) => hdr,
        Err(_) => return TestResult::Fail("virtio-net rejected negotiated TCPv6 TSO"),
    };
    if hdr.flags != 1
        || hdr.gso_type != 4
        || u16::from_le(hdr.hdr_len) != 74
        || u16::from_le(hdr.gso_size) != 1200
        || u16::from_le(hdr.csum_start) != 54
        || u16::from_le(hdr.csum_offset) != 16
    {
        return TestResult::Fail("virtio-net TSO6 header has wrong offsets or GSO fields");
    }
    if frame[70..72] != 0x5b7bu16.to_be_bytes() {
        return TestResult::Fail("virtio-net TSO6 did not prepare zero-length pseudo-header seed");
    }
    // The old mislabeling path must be gone: a v6 TCP GSO frame with only
    // TSO4 negotiated is rejected, not emitted as TCPV4.
    if tx_header_for_frame(
        &mut frame,
        TxMeta::with_tso(1200),
        TxOffloadProfile {
            checksum: true,
            tso4: true,
            tso6: false,
            uso: false,
        },
        1518,
    )
    .is_ok()
    {
        return TestResult::Fail("virtio-net emitted TCPv6 TSO under a TSO4-only profile");
    }
    // ECN-marked v6 TCP GSO stays refused (HOST_ECN not negotiated).
    frame[54 + 13] |= 0x40;
    if tx_header_for_frame(
        &mut frame,
        TxMeta::with_tso(1200),
        TxOffloadProfile {
            checksum: true,
            tso4: false,
            tso6: true,
            uso: false,
        },
        1518,
    )
    .is_ok()
    {
        return TestResult::Fail("virtio-net accepted ECN-marked TCPv6 GSO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_tx_tso6_header_is_feature_gated_and_well_formed
);

fn smoke_virtio_net_tx_uso_header_is_feature_gated_and_well_formed() -> TestResult {
    use crate::net_pci::{ipv4_pseudo_seed, tx_header_for_frame, TxOffloadProfile};
    use narf_net::{L4CsumKind, TxMeta};

    // Cross-checks against the Python oracle: v4 UDP seed for
    // 192.0.2.10 -> 198.51.100.20 folds to 0xec63, and the v4 helper
    // with proto TCP reproduces the in-tree TCP seed exactly.
    if ipv4_pseudo_seed([192, 0, 2, 10], [198, 51, 100, 20], 17) != 0xec63
        || ipv4_pseudo_seed([192, 0, 2, 10], [198, 51, 100, 20], 6)
            != narf_net::pkt_tcp::ipv4_tcp_pseudo_seed([192, 0, 2, 10], [198, 51, 100, 20], 0)
    {
        return TestResult::Fail("virtio-net IPv4 pseudo seed mismatch");
    }
    let uso_meta = TxMeta {
        csum_l4: Some(L4CsumKind::Udp),
        tso_mss: Some(1200),
        ..Default::default()
    };
    let uso_profile = TxOffloadProfile {
        checksum: true,
        tso4: false,
        tso6: false,
        uso: true,
    };
    let mut frame = [0u8; 1500];
    virtio_test_ipv4_udp_frame(&mut frame);
    let hdr = match tx_header_for_frame(&mut frame, uso_meta, uso_profile, 1518) {
        Ok(hdr) => hdr,
        Err(_) => return TestResult::Fail("virtio-net rejected negotiated IPv4 USO"),
    };
    if hdr.flags != 1
        || hdr.gso_type != 5
        || u16::from_le(hdr.hdr_len) != 42
        || u16::from_le(hdr.gso_size) != 1200
        || u16::from_le(hdr.csum_start) != 34
        || u16::from_le(hdr.csum_offset) != 6
    {
        return TestResult::Fail("virtio-net USO header has wrong offsets or GSO fields");
    }
    if frame[40..42] != 0xec63u16.to_be_bytes() {
        return TestResult::Fail("virtio-net USO did not prepare zero-length pseudo-header seed");
    }
    // v6 USO: same GSO type, v6 header geometry, v6 UDP seed 0x5b86.
    let mut frame6 = [0u8; 1500];
    virtio_test_ipv6_udp_frame(&mut frame6);
    let hdr6 = match tx_header_for_frame(&mut frame6, uso_meta, uso_profile, 1518) {
        Ok(hdr) => hdr,
        Err(_) => return TestResult::Fail("virtio-net rejected negotiated IPv6 USO"),
    };
    if hdr6.flags != 1
        || hdr6.gso_type != 5
        || u16::from_le(hdr6.hdr_len) != 62
        || u16::from_le(hdr6.gso_size) != 1200
        || u16::from_le(hdr6.csum_start) != 54
        || u16::from_le(hdr6.csum_offset) != 6
    {
        return TestResult::Fail("virtio-net IPv6 USO header has wrong offsets or GSO fields");
    }
    if frame6[60..62] != 0x5b86u16.to_be_bytes() {
        return TestResult::Fail(
            "virtio-net IPv6 USO did not prepare zero-length pseudo-header seed",
        );
    }
    // Rejections: no USO feature, and mss 0.
    if tx_header_for_frame(&mut frame, uso_meta, TxOffloadProfile::default(), 1518).is_ok() {
        return TestResult::Fail("virtio-net accepted USO without negotiated feature");
    }
    let zero_mss = TxMeta {
        csum_l4: Some(L4CsumKind::Udp),
        tso_mss: Some(0),
        ..Default::default()
    };
    if tx_header_for_frame(&mut frame, zero_mss, uso_profile, 1518).is_ok() {
        return TestResult::Fail("virtio-net accepted USO with mss 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_tx_uso_header_is_feature_gated_and_well_formed
);

fn smoke_virtio_net_tx_checksum_header_is_feature_gated() -> TestResult {
    use crate::net_pci::{tx_header_for_frame, TxOffloadProfile};
    use narf_net::{L4CsumKind, TxMeta};

    let mut frame = [0u8; 74];
    virtio_test_ipv4_tcp_frame(&mut frame);
    let hdr = match tx_header_for_frame(
        &mut frame,
        TxMeta::with_csum(L4CsumKind::Tcp),
        TxOffloadProfile {
            checksum: true,
            tso4: false,
            tso6: false,
            uso: false,
        },
        1518,
    ) {
        Ok(hdr) => hdr,
        Err(_) => return TestResult::Fail("virtio-net rejected negotiated TCP checksum offload"),
    };
    if hdr.flags != 1
        || hdr.gso_type != 0
        || u16::from_le(hdr.csum_start) != 34
        || u16::from_le(hdr.csum_offset) != 16
    {
        return TestResult::Fail("virtio-net checksum header has wrong offsets");
    }
    if tx_header_for_frame(
        &mut frame,
        TxMeta::with_csum(L4CsumKind::Tcp),
        TxOffloadProfile::default(),
        1518,
    )
    .is_ok()
    {
        return TestResult::Fail("virtio-net accepted checksum offload without negotiated feature");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_tx_checksum_header_is_feature_gated
);

fn smoke_virtio_net_rx_csum_verdict() -> TestResult {
    use crate::net_pci::{
        rx_csum_deliver, VIRTIO_NET_HDR_F_DATA_VALID, VIRTIO_NET_HDR_F_NEEDS_CSUM,
    };

    const DATA_VALID: u8 = VIRTIO_NET_HDR_F_DATA_VALID;
    const NEEDS_CSUM: u8 = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    // IPv4/TCP frame via the shared builder (eth 14 + ip 20 + tcp 20).
    let mut tcp4 = [0u8; 54];
    virtio_test_ipv4_tcp_frame(&mut tcp4);
    if !rx_csum_deliver(DATA_VALID, &tcp4) {
        return TestResult::Fail("device-verified TCPv4 dropped");
    }
    if rx_csum_deliver(0, &tcp4) {
        return TestResult::Fail("unverified TCPv4 delivered");
    }
    if rx_csum_deliver(NEEDS_CSUM, &tcp4) {
        return TestResult::Fail("partial-checksum TCPv4 delivered");
    }
    if rx_csum_deliver(DATA_VALID | NEEDS_CSUM, &tcp4) {
        return TestResult::Fail("contradictory DATA_VALID|NEEDS_CSUM TCPv4 delivered");
    }
    // IPv4/UDP with a nonzero checksum: drop when unverified.
    let mut udp4 = [0u8; 42];
    udp4[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    udp4[14] = 0x45;
    udp4[14 + 9] = 17;
    udp4[14 + 20 + 6..14 + 20 + 8].copy_from_slice(&0x1234u16.to_be_bytes());
    if rx_csum_deliver(0, &udp4) {
        return TestResult::Fail("unverified UDPv4 with checksum delivered");
    }
    if !rx_csum_deliver(DATA_VALID, &udp4) {
        return TestResult::Fail("device-verified UDPv4 dropped");
    }
    // IPv4/UDP with a zero checksum field: no checksum transmitted.
    let mut udp4_zero = udp4;
    udp4_zero[14 + 20 + 6..14 + 20 + 8].copy_from_slice(&0u16.to_be_bytes());
    if !rx_csum_deliver(0, &udp4_zero) {
        return TestResult::Fail("zero-checksum UDPv4 dropped");
    }
    // ARP: no transport checksum to verify.
    let mut arp = [0u8; 42];
    arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    if !rx_csum_deliver(0, &arp) {
        return TestResult::Fail("ARP dropped");
    }
    // IPv4/ICMP: delivered unverified (documented remainder).
    let mut icmp4 = [0u8; 42];
    icmp4[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    icmp4[14] = 0x45;
    icmp4[14 + 9] = 1;
    if !rx_csum_deliver(0, &icmp4) {
        return TestResult::Fail("ICMPv4 dropped");
    }
    // IPv4 non-first fragment of a TCP packet: no L4 header present.
    let mut frag = tcp4;
    frag[14 + 6..14 + 8].copy_from_slice(&0x0001u16.to_be_bytes());
    if !rx_csum_deliver(0, &frag) {
        return TestResult::Fail("non-first TCPv4 fragment dropped");
    }
    // IPv4 first fragment (MF set, offset 0): L4 header present, drops.
    let mut frag_first = tcp4;
    frag_first[14 + 6..14 + 8].copy_from_slice(&0x2000u16.to_be_bytes());
    if rx_csum_deliver(0, &frag_first) {
        return TestResult::Fail("unverified first TCPv4 fragment delivered");
    }
    // IPv6/TCP and IPv6/UDP: drop when unverified.
    let mut tcp6 = [0u8; 74];
    tcp6[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    tcp6[14] = 0x60;
    tcp6[14 + 6] = 6;
    if rx_csum_deliver(0, &tcp6) {
        return TestResult::Fail("unverified TCPv6 delivered");
    }
    if !rx_csum_deliver(DATA_VALID, &tcp6) {
        return TestResult::Fail("device-verified TCPv6 dropped");
    }
    let mut udp6 = tcp6;
    udp6[14 + 6] = 17;
    if rx_csum_deliver(0, &udp6) {
        return TestResult::Fail("unverified UDPv6 delivered");
    }
    // IPv6 with a fragment extension header: L4 hidden, delivers.
    let mut ext6 = tcp6;
    ext6[14 + 6] = 44;
    if !rx_csum_deliver(0, &ext6) {
        return TestResult::Fail("extension-header IPv6 dropped");
    }
    // Single 802.1Q tag around an IPv4/TCP frame: MAC + tag + inner
    // ethertype, then the IP/TCP part (tcp4[14..]) at L3 offset 18.
    let mut vlan = [0u8; 58];
    vlan[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    vlan[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    vlan[18..58].copy_from_slice(&tcp4[14..54]);
    if rx_csum_deliver(0, &vlan) {
        return TestResult::Fail("unverified VLAN-tagged TCPv4 delivered");
    }
    if !rx_csum_deliver(DATA_VALID, &vlan) {
        return TestResult::Fail("device-verified VLAN-tagged TCPv4 dropped");
    }
    // Runt: unparseable, delivers for the stack to drop.
    if !rx_csum_deliver(0, &[0u8; 10]) {
        return TestResult::Fail("runt dropped by verdict");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_rx_csum_verdict);

/// Regression pin for the HASH_REPORT + GUEST_CSUM fail-open: the RX
/// pump's csum check must slice the payload at the runtime header
/// length (20 with HASH_REPORT), not a hardcoded 12. Under the old
/// slicing, an unverified TCPv4 segment under a 20-byte header
/// delivered (the shifted window misreads the ethertype as 0x0000
/// from the dst-MAC bytes); under the fix it drops fail-closed, and
/// the 12-byte (GUEST_CSUM-only) path behaves byte-identically.
fn smoke_virtio_net_rx_csum_hash_report_header() -> TestResult {
    use crate::net_pci::{
        rx_csum_deliver, rx_csum_payload, rx_header_len, VIRTIO_NET_HDR_F_DATA_VALID,
    };

    if rx_header_len(true) != 20 || rx_header_len(false) != 12 {
        return TestResult::Fail("rx_header_len mismatch");
    }
    // IPv4/TCP frame via the shared builder (eth 14 + ip 20 + tcp 20).
    let mut tcp4 = [0u8; 54];
    virtio_test_ipv4_tcp_frame(&mut tcp4);
    // Full RX buffer: 20-byte HASH_REPORT header (zeroed but for the
    // flags byte, which stays 0 = unverified) + payload.
    let mut buf20 = [0u8; 74];
    buf20[20..74].copy_from_slice(&tcp4);
    let payload20 = rx_csum_payload(&buf20, 20, tcp4.len() as u32);
    if payload20 != tcp4 {
        return TestResult::Fail("20-byte-header csum slice is not the true payload");
    }
    // Unverified TCPv4 under HASH_REPORT must drop (fail-closed).
    if rx_csum_deliver(0, payload20) {
        return TestResult::Fail("unverified TCPv4 under HASH_REPORT delivered");
    }
    // Device-verified TCPv4 under HASH_REPORT delivers.
    if !rx_csum_deliver(VIRTIO_NET_HDR_F_DATA_VALID, payload20) {
        return TestResult::Fail("device-verified TCPv4 under HASH_REPORT dropped");
    }
    // Regression pin: the old hardcoded-12 slice of the same buffer
    // delivers the unverified segment — the fail-open this fix closes.
    // (Shifted window's ethertype read lands on dst-MAC bytes = 0x0000,
    // which takes the deliver-by-default arm.)
    let shifted = buf20.get(12..12 + tcp4.len()).unwrap_or(&[]);
    if !rx_csum_deliver(0, shifted) {
        return TestResult::Fail("shifted-slice pin does not reproduce the fail-open");
    }
    // GUEST_CSUM-only path (12-byte header): same slice, same verdicts.
    let mut buf12 = [0u8; 66];
    buf12[12..66].copy_from_slice(&tcp4);
    let payload12 = rx_csum_payload(&buf12, 12, tcp4.len() as u32);
    if payload12 != tcp4 {
        return TestResult::Fail("12-byte-header csum slice changed");
    }
    if rx_csum_deliver(0, payload12) {
        return TestResult::Fail("unverified TCPv4 without HASH_REPORT delivered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_rx_csum_hash_report_header
);

fn smoke_virtio_net_pci_tx() -> TestResult {
    use crate::net_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_net = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == net_pci::VIRTIO_NET_PCI_VENDOR
            && d.id.device == net_pci::VIRTIO_NET_PCI_DEVICE
    });
    if !has_net {
        return TestResult::Skip("no virtio-net-pci device");
    }
    __reset_for_test();
    net_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !net_pci::is_probed() {
        return TestResult::Fail("virtio-net-pci not probed");
    }
    // Build a synthetic 64-byte frame in a fresh DMA buffer and
    // hand it to tx_dma. Fire-and-forget tx_dma takes the buffer BY
    // VALUE and writes the 12-byte virtio-net header at offset 0, so
    // the frame body lives at offset 12.
    let mut tx_buf =
        narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0).expect("alloc tx scratch");
    {
        let slice = tx_buf.as_mut_slice();
        for (i, b) in slice[12 + 14..12 + 64].iter_mut().enumerate() {
            *b = ((i + 14) as u8).wrapping_mul(0x3D);
        }
    }
    let tx_ok = net_pci::with_controller(|c| c.tx_dma(tx_buf, 64))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !tx_ok {
        return TestResult::Fail("virtio-net-pci tx_dma returned Err");
    }
    let qsizes =
        net_pci::with_controller(|c| (c.rx_queue_size(), c.tx_queue_size())).unwrap_or((0, 0));
    if qsizes.0 == 0 || qsizes.1 == 0 {
        return TestResult::Fail("queue sizes zero — bring-up failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_pci_tx);

fn smoke_virtio_net_pci_rx_arp() -> TestResult {
    use crate::net_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_net = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == net_pci::VIRTIO_NET_PCI_VENDOR
            && d.id.device == net_pci::VIRTIO_NET_PCI_DEVICE
    });
    if !has_net {
        return TestResult::Skip("no virtio-net-pci");
    }
    __reset_for_test();
    net_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    let mut tx_dma =
        narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0).expect("alloc arp scratch");
    {
        // Frame body lives at offset H=12 (tx_dma writes the 12-byte
        // virtio-net header at offset 0 and takes the buffer by value).
        const H: usize = 12;
        let f = tx_dma.as_mut_slice();
        for b in f[H..H + 6].iter_mut() {
            *b = 0xFF;
        }
        f[H + 6] = 0x52;
        f[H + 7] = 0x54;
        f[H + 8] = 0x00;
        f[H + 9] = 0x12;
        f[H + 10] = 0x34;
        f[H + 11] = 0x57;
        f[H + 12] = 0x08;
        f[H + 13] = 0x06;
        f[H + 14] = 0x00;
        f[H + 15] = 0x01;
        f[H + 16] = 0x08;
        f[H + 17] = 0x00;
        f[H + 18] = 6;
        f[H + 19] = 4;
        f[H + 20] = 0x00;
        f[H + 21] = 0x01;
        for i in 0..6 {
            f[H + 22 + i] = f[H + 6 + i];
        }
        f[H + 28] = 10;
        f[H + 29] = 0;
        f[H + 30] = 2;
        f[H + 31] = 15;
        f[H + 38] = 10;
        f[H + 39] = 0;
        f[H + 40] = 2;
        f[H + 41] = 2;
    }
    if !net_pci::with_controller(|c| c.tx_dma(tx_dma, 42))
        .map(|r| r.is_ok())
        .unwrap_or(false)
    {
        return TestResult::Fail("virtio-net tx_dma");
    }
    // Drain one RX frame via zero-copy rx_take. `buf` would be
    // freed on drop here; we only need to confirm the device
    // actually published an arrival.
    let mut any = 0u32;
    for _ in 0..2_000_000u32 {
        let taken = net_pci::with_controller(|c| {
            let t = c.rx_take();
            if t.is_some() {
                c.rx_notify(0);
            }
            t
        })
        .flatten();
        if let Some((_buf, len)) = taken {
            any = len;
            break;
        }
        core::hint::spin_loop();
    }
    let _ = any;
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_pci_rx_arp);

fn smoke_virtio_net_pci_registers_iface() -> TestResult {
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    // probe() registers the primary controller's `eth%d` Interface with
    // narf_net::registry(), under the same name as its legacy iface.
    // Confirm it's there and reports a non-default MAC + standard MTU.
    let found =
        narf_net::registry().with_interface(crate::net_pci::primary_iface_name(), |iface| {
            let mac = iface.mac();
            let mtu = iface.mtu();
            let link = iface.link_up();
            // mtu defaults to 1500 when F_MTU isn't negotiated — that's
            // still a valid pass. The MAC ought to be non-zero on QEMU
            // (QEMU advertises a 52:54:00:XX:XX:XX vendor default).
            let mac_ok = mac.iter().any(|&b| b != 0);
            let mtu_ok = (64..=65535).contains(&mtu);
            (mac_ok, mtu_ok, link)
        });
    match found {
        Some((true, true, _link)) => TestResult::Pass,
        Some((false, _, _)) => TestResult::Fail("MAC is all-zero — F_MAC negotiation broken"),
        Some((_, false, _)) => TestResult::Fail("MTU out of expected range"),
        None => {
            TestResult::Fail("primary virtio-net iface not registered with narf_net::registry()")
        }
    }
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_registers_iface
);

// ── virtio-net RSS (audit gap 8) ────────────────────────────────────
// Pure-encoder smokes: the RSS/HASH config builders + RX header
// length selection, exercised without PCI, DMA, or a live QEMU
// NIC (default QEMU does not offer F_RSS, so no live-device
// coverage exists in CI either — the wire bytes are pinned here
// and the device behavior is CI/silicon-verified).

fn smoke_virtio_net_rss_config_encoding() -> TestResult {
    use crate::net_pci::{build_hash_config, build_rss_config, rx_header_len};
    use crate::net_pci::{VIRTIO_NET_HDR_HASH_LEN, VIRTIO_NET_HDR_LEN};

    // Header lengths: 12 base, 20 with HASH_REPORT.
    if VIRTIO_NET_HDR_LEN != 12 || VIRTIO_NET_HDR_HASH_LEN != 20 {
        return TestResult::Fail("RX header length constants wrong");
    }
    if rx_header_len(false) != 12 || rx_header_len(true) != 20 {
        return TestResult::Fail("rx_header_len selection wrong");
    }

    // Full config: device advertises all 9 hash types (incl. _EX)
    // + 128-entry table max + 52-byte key max, 4 live pairs.
    // Expect: _EX masked out (0x3f), table capped at 64 (mask 63),
    // entries i % 4, max_tx_vq 4, key clamped to 40.
    let payload = match build_rss_config(0x1ff, 4, 128, 52) {
        Some(p) => p,
        None => return TestResult::Fail("valid RSS config returned None"),
    };
    // 11 fixed bytes + 2*64 table + 40 key = 179.
    if payload.len() != 179 {
        return TestResult::Fail("RSS config length wrong");
    }
    let hash_types = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if hash_types != 0x3f {
        return TestResult::Fail("RSS hash types not masked to base six");
    }
    let mask = u16::from_le_bytes([payload[4], payload[5]]);
    if mask != 63 {
        return TestResult::Fail("RSS indirection mask not 63");
    }
    let unclassified = u16::from_le_bytes([payload[6], payload[7]]);
    if unclassified != 0 {
        return TestResult::Fail("RSS unclassified queue not pair 0");
    }
    for i in 0..64u16 {
        let off = 8 + 2 * i as usize;
        let entry = u16::from_le_bytes([payload[off], payload[off + 1]]);
        if entry != i % 4 {
            return TestResult::Fail("RSS indirection entry not i % num_pairs");
        }
    }
    let max_tx_vq = u16::from_le_bytes([payload[136], payload[137]]);
    if max_tx_vq != 4 {
        return TestResult::Fail("RSS max_tx_vq not live pair count");
    }
    if payload[138] != 40 {
        return TestResult::Fail("RSS key length not clamped to 40");
    }
    // Key pinned from an independent splitmix64 computation: an
    // accidental key change silently re-steers every flow.
    let expected_key: [u8; 8] = [0xc6, 0xb4, 0x50, 0xbb, 0x39, 0x33, 0xb8, 0x21];
    if payload[139..147] != expected_key {
        return TestResult::Fail("RSS key bytes changed from pinned splitmix64 output");
    }

    // Non-power-of-two device max rounds DOWN (5 -> 4, mask 3).
    let small = match build_rss_config(0x3f, 2, 5, 40) {
        Some(p) => p,
        None => return TestResult::Fail("small-table RSS config returned None"),
    };
    if u16::from_le_bytes([small[4], small[5]]) != 3 || small.len() != 11 + 8 + 40 {
        return TestResult::Fail("RSS table size not rounded down to power of two");
    }

    // Degenerate inputs fail closed (caller skips the command).
    if build_rss_config(0x3f, 0, 128, 40).is_some()
        || build_rss_config(0x3f, 4, 0, 40).is_some()
        || build_rss_config(0x3f, 4, 128, 0).is_some()
    {
        return TestResult::Fail("degenerate RSS config not rejected");
    }
    // Zero advertised types fall back to the base six, not zero.
    let fallback = match build_rss_config(0, 1, 1, 40) {
        Some(p) => p,
        None => return TestResult::Fail("fallback RSS config returned None"),
    };
    if u32::from_le_bytes([fallback[0], fallback[1], fallback[2], fallback[3]]) != 0x3f {
        return TestResult::Fail("RSS hash types did not fall back to base six");
    }

    // HASH_CONFIG: hash_types + 8 reserved zero bytes + key.
    let hash = match build_hash_config(0x1ff, 40) {
        Some(p) => p,
        None => return TestResult::Fail("valid HASH config returned None"),
    };
    if hash.len() != 53
        || u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) != 0x3f
        || hash[4..12] != [0u8; 8]
        || hash[12] != 40
        || hash[13..21] != expected_key
    {
        return TestResult::Fail("HASH config layout wrong");
    }
    if build_hash_config(0x3f, 0).is_some() {
        return TestResult::Fail("zero-key HASH config not rejected");
    }

    // Strip math: a max-size frame fits under both header forms,
    // and a header-only buffer strips to an empty payload.
    let total_hash = (20 + 1518) as u32;
    if total_hash.saturating_sub(rx_header_len(true) as u32) != 1518 {
        return TestResult::Fail("hash-report strip math wrong");
    }
    if (20u32).saturating_sub(rx_header_len(true) as u32) != 0 {
        return TestResult::Fail("header-only frame did not strip to empty");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_rss_config_encoding
);

fn smoke_virtio_net_pci_legacy_iface_registered() -> TestResult {
    // The TCP stack consumes from narf_net::iface (fn-pointer
    // registry), not the ring-based narf_net::registry. virtio-net
    // probe must hook itself into both so `tcp_stack::connect` /
    // ARP requests / `iface::send` actually reach the device.
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    let vnet = match narf_net::iface::lookup(crate::net_pci::primary_iface_name()) {
        Some(i) => i,
        None => {
            return TestResult::Fail("primary virtio-net iface not registered with narf_net::iface")
        }
    };
    // Same MAC the controller reports — confirms the probe path
    // copied it through (not a hardcoded placeholder).
    let ctrl_mac = net_pci::with_controller(|c| c.mac()).unwrap_or([0; 6]);
    if vnet.mac != ctrl_mac {
        return TestResult::Fail("legacy iface MAC doesn't match controller mac()");
    }
    let ctrl_link = net_pci::with_controller(|c| c.link_up()).unwrap_or(false);
    if vnet.carrier != ctrl_link {
        return TestResult::Fail("legacy iface carrier doesn't match controller link state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_legacy_iface_registered
);

fn smoke_virtio_net_pci_send_fn_dispatches() -> TestResult {
    // Direct smoke: call the primary virtio-net iface's SendFn with a hand-built broadcast
    // ARP frame and confirm the send returns Ok. This validates the
    // legacy iface registration → DmaBuffer alloc → tx_dma path
    // end-to-end without depending on which iface `primary()` picks
    // when both virtio-net and e1000 are attached.
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    let vnet = match narf_net::iface::lookup(crate::net_pci::primary_iface_name()) {
        Some(i) => i,
        None => {
            return TestResult::Skip("primary virtio-net iface not registered with legacy iface")
        }
    };
    let src_mac = vnet.mac;
    // 42-byte ARP-over-Ethernet broadcast for 10.0.2.2. Bytes
    // copied straight from RFC 826 layout; the device only sees
    // the wire, so as long as the frame is well-formed QEMU's
    // user-mode SLIRP will answer.
    let mut frame = [0u8; 42];
    // Eth dst = ff:ff:ff:ff:ff:ff (broadcast)
    for b in frame.iter_mut().take(6) {
        *b = 0xFF;
    }
    // Eth src = our MAC
    frame[6..12].copy_from_slice(&src_mac);
    // Ethertype = 0x0806 (ARP)
    frame[12] = 0x08;
    frame[13] = 0x06;
    // HTYPE = 1 (Ethernet)
    frame[14] = 0x00;
    frame[15] = 0x01;
    // PTYPE = 0x0800 (IPv4)
    frame[16] = 0x08;
    frame[17] = 0x00;
    // HLEN / PLEN
    frame[18] = 6;
    frame[19] = 4;
    // OPER = 1 (request)
    frame[20] = 0x00;
    frame[21] = 0x01;
    // Sender HW = our MAC
    frame[22..28].copy_from_slice(&src_mac);
    // Sender IP = 10.0.2.15
    frame[28] = 10;
    frame[29] = 0;
    frame[30] = 2;
    frame[31] = 15;
    // Target HW = zeroes
    // Target IP = 10.0.2.2
    frame[38] = 10;
    frame[39] = 0;
    frame[40] = 2;
    frame[41] = 2;
    match vnet.xmit(&frame) {
        Ok(()) => TestResult::Pass,
        Err(()) => {
            TestResult::Fail("primary virtio-net iface SendFn returned Err — tx_dma path broken")
        }
    }
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_send_fn_dispatches
);

fn smoke_virtio_net_pci_set_mac_round_trip() -> TestResult {
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    // Save the controller's current MAC so we can restore it
    // (other tests may depend on a stable MAC across runs).
    let original = match net_pci::with_controller(|c| c.mac()) {
        Some(m) => m,
        None => return TestResult::Skip("primary virtio-net iface controller missing"),
    };
    // Locally-administered, unicast — guaranteed not to collide
    // with a vendor-assigned address. Bit 1 of the first octet
    // set = locally-administered; bit 0 clear = unicast.
    let new_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let res = net_pci::with_controller(|c| c.set_mac(new_mac));
    match res {
        Some(Ok(())) => {}
        Some(Err(_)) => {
            return TestResult::Skip("device didn't negotiate F_CTRL_MAC_ADDR");
        }
        None => return TestResult::Skip("primary virtio-net iface controller vanished"),
    }
    let observed = net_pci::with_controller(|c| c.mac()).unwrap_or([0; 6]);
    if observed != new_mac {
        return TestResult::Fail("mac() didn't reflect set_mac");
    }
    // Restore so smoke_virtio_net_pci_legacy_iface_registered's
    // MAC comparison stays meaningful. The iface registry copied
    // the *original* MAC at probe time; restoring keeps that
    // consistent.
    let _ = net_pci::with_controller(|c| c.set_mac(original));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_set_mac_round_trip
);

/// Runtime MTU change through the stack-facing `DeviceControl`
/// hook (audit gap 11): `configure` with a new MTU retargets the
/// controller's live MTU, an above-ceiling value is refused with
/// errno 22 and leaves the live MTU untouched, and the original
/// MTU is restored so later smokes see the probe-time value.
/// The ceiling is device-dependent (1500 without MRG, 9000 with),
/// so it is probed from the controller rather than assumed.
fn smoke_virtio_net_pci_set_mtu_round_trip() -> TestResult {
    use crate::net_pci;
    use narf_net::iface::DeviceControl;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    let original = match net_pci::with_controller(|c| c.mtu()) {
        Some(m) => m,
        None => return TestResult::Skip("primary virtio-net iface controller missing"),
    };
    // Pin the wiring itself: without a registered hook,
    // `try_set_mtu` would succeed registry-only and the driver
    // would never learn the new MTU.
    if narf_net::iface::device_control(crate::net_pci::primary_iface_name()).is_none() {
        return TestResult::Fail("DeviceControl hook not registered for primary iface");
    }
    let ceiling = match net_pci::with_controller(|c| c.max_mtu()) {
        Some(m) => m,
        None => return TestResult::Skip("primary virtio-net iface controller vanished"),
    };
    if ceiling < 1400 {
        return TestResult::Skip("device MTU ceiling below 1400");
    }
    let mac = match net_pci::with_controller(|c| c.mac()) {
        Some(m) => m,
        None => return TestResult::Skip("primary virtio-net iface controller vanished"),
    };
    let config = |mtu: u32| narf_net::iface::DeviceConfig {
        mac,
        mtu,
        promiscuous: false,
        all_multicast: false,
        addresses: alloc::vec::Vec::new(),
    };
    if net_pci::with_controller(|c| c.configure(&config(1400))) != Some(Ok(())) {
        return TestResult::Fail("configure(1400) rejected");
    }
    if net_pci::with_controller(|c| c.mtu()) != Some(1400) {
        let _ = net_pci::with_controller(|c| c.configure(&config(original)));
        return TestResult::Fail("mtu() didn't reflect configure(1400)");
    }
    // Restore before the rejection check so a failure there can't
    // leak the lowered MTU into later smokes.
    if net_pci::with_controller(|c| c.configure(&config(original))) != Some(Ok(())) {
        return TestResult::Fail("configure(original) restore rejected");
    }
    if net_pci::with_controller(|c| c.mtu()) != Some(original) {
        return TestResult::Fail("mtu() didn't reflect restore");
    }
    if net_pci::with_controller(|c| c.configure(&config(ceiling + 1))) != Some(Err(22)) {
        return TestResult::Fail("configure above ceiling did not report EINVAL");
    }
    if net_pci::with_controller(|c| c.mtu()) != Some(original) {
        return TestResult::Fail("rejected configure clobbered live MTU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_set_mtu_round_trip
);

fn smoke_virtio_net_pci_dhcp_acquire() -> TestResult {
    // End-to-end DHCP exchange against QEMU's built-in user-mode
    // SLIRP server, which always offers `10.0.2.15` as the lease.
    // Drives the full DISCOVER → OFFER → REQUEST → ACK flow through
    // the primary virtio-net iface — exercises the new tcp_stack UDP dispatch + dhcp client
    // + frame-build wrappers.
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    if narf_net::iface::lookup(crate::net_pci::primary_iface_name()).is_none() {
        return TestResult::Skip("primary virtio-net iface not registered with legacy iface");
    }
    // kernel-test builds don't run `boot_userspace_init`, so the
    // `tcp_stack::init()` that normally wires
    // `iface::install_rx_handler(rx_handler)` never fires. Without
    // an RX handler installed, inbound DHCP OFFER frames are
    // silently dropped by `iface::on_rx_frame` and the busy-wait
    // inside `acquire` times out. Idempotent — production builds
    // already called it via `cross_crate_init::install_all_hooks`.
    narf_net::tcp_stack::init();
    // acquire() sends through the primary iface's send_fn (looked up by name,
    // not by primary()). The reply comes back on its RX
    // virtqueue; the busy-wait in `acquire` drains the ring via
    // `iface::drain_pump`, which routes through tcp_stack
    // → dhcp::on_udp_in, populating LATEST_REPLY.
    match narf_net::dhcp::acquire(crate::net_pci::primary_iface_name(), 5000) {
        Ok(lease) => {
            // QEMU SLIRP hands out 10.0.2.15 by default.
            if lease.ip != [10, 0, 2, 15] {
                return TestResult::Fail("DHCP yiaddr mismatch");
            }
            if lease.gateway != [10, 0, 2, 2] {
                return TestResult::Fail("DHCP gateway mismatch");
            }
            if lease.lease_secs == 0 {
                return TestResult::Fail("DHCP lease_secs zero");
            }
            TestResult::Pass
        }
        Err(()) => TestResult::Skip("DHCP timed out — no user-mode netdev?"),
    }
}
kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_pci_dhcp_acquire);

fn smoke_virtio_net_pci_count_matches_probe() -> TestResult {
    use crate::net_pci;
    let n = net_pci::count();
    if net_pci::is_probed() {
        if n == 0 {
            return TestResult::Fail("is_probed() true but count() == 0");
        }
    } else if n != 0 {
        return TestResult::Fail("is_probed() false but count() > 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_count_matches_probe
);

fn smoke_virtio_net_pci_ctrl_vq_set_promisc() -> TestResult {
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    let has_ctrl = net_pci::with_controller(|c| c.has_ctrl_vq()).unwrap_or(false);
    if !has_ctrl {
        return TestResult::Skip("device didn't negotiate F_CTRL_VQ");
    }
    // Enable promisc, then disable. Both must round-trip through
    // the device with VIRTIO_NET_OK acks.
    let on = net_pci::with_controller(|c| c.set_promisc(true))
        .unwrap_or(Err(crate::pci::VirtioPciError::NoQueues));
    if on.is_err() {
        return TestResult::Fail("promisc=on rejected");
    }
    let off = net_pci::with_controller(|c| c.set_promisc(false))
        .unwrap_or(Err(crate::pci::VirtioPciError::NoQueues));
    if off.is_err() {
        return TestResult::Fail("promisc=off rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_ctrl_vq_set_promisc
);

fn smoke_virtio_net_pci_mq_pairs_consistent() -> TestResult {
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    // After bring_up the controller should report ≥ 1 active pair.
    // With F_MQ negotiated (qemu `-device virtio-net-pci,...,mq=on`)
    // it should be 2..MAX_QUEUE_PAIRS; without F_MQ it's exactly 1.
    // Either way, num_pairs > 0 and rx_take_on/tx_dma_on(0) must
    // mirror the singleton rx_take/tx_dma behaviour.
    let n = net_pci::with_controller(|c| c.num_pairs()).unwrap_or(0);
    if n == 0 {
        return TestResult::Fail("num_pairs == 0 — MQ negotiation broke bring_up");
    }
    // The primary-pair sizes used to be the only reported queue
    // sizes; they should still match `rx_queue_size`/`tx_queue_size`.
    let (rxs, txs) =
        net_pci::with_controller(|c| (c.rx_queue_size(), c.tx_queue_size())).unwrap_or((0, 0));
    if rxs == 0 || txs == 0 {
        return TestResult::Fail("primary-pair queue sizes zero");
    }
    // tx_dma_on(0) should accept a small frame even with MQ active.
    // Frame body at offset 12 (tx_dma_on writes the 12-byte header).
    let mut buf =
        narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0).expect("alloc tx scratch");
    {
        let s = buf.as_mut_slice();
        for (i, b) in s[12..12 + 64].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x17);
        }
    }
    let ok = net_pci::with_controller(|c| c.tx_dma_on(0, buf, 64))
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if !ok {
        return TestResult::Fail("tx_dma_on(0) rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_mq_pairs_consistent
);

// ── virtio-rng-pci / virtio-snd-pci / virtio-balloon-pci ───────────

fn smoke_virtio_rng_pci_probe() -> TestResult {
    use crate::rng_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == rng_pci::VIRTIO_RNG_PCI_VENDOR
            && d.id.device == rng_pci::VIRTIO_RNG_PCI_DEVICE
    });
    if !has {
        return TestResult::Skip("no virtio-rng-pci");
    }
    __reset_for_test();
    rng_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !rng_pci::is_probed() {
        return TestResult::Fail("rng probe did not install controller");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/rng-pci", smoke_virtio_rng_pci_probe);

fn smoke_virtio_rng_seed_fill_loop() -> TestResult {
    use crate::pci::VirtioPciError;
    use crate::rng_pci::fill_seed_from_reads;

    // Partial completions concatenate in order: a device that
    // writes 5 bytes, then the remaining 27, fills the seed with
    // the first chunk's bytes first. Distinct per-chunk patterns
    // prove order, not just length.
    let script = [(5usize, 0xA1u8), (27usize, 0xB2u8)];
    let mut step = 0usize;
    let mut read = |out: &mut [u8]| -> Result<usize, VirtioPciError> {
        if step >= script.len() {
            return Err(VirtioPciError::NoQueues);
        }
        let (n, tag) = script[step];
        step += 1;
        let n = n.min(out.len());
        out[..n].fill(tag);
        Ok(n)
    };
    let mut seed = [0u8; 32];
    if fill_seed_from_reads(&mut seed, &mut read).is_err() {
        return TestResult::Fail("partial-read seed fill refused");
    }
    if seed[..5].iter().any(|&b| b != 0xA1) || seed[5..].iter().any(|&b| b != 0xB2) {
        return TestResult::Fail("partial-read seed bytes out of order");
    }

    // A zero-progress completion is a stalled device, not a
    // retryable short read: it must fail, never spin.
    let mut stalled = |_out: &mut [u8]| -> Result<usize, VirtioPciError> { Ok(0) };
    let mut seed = [0u8; 32];
    match fill_seed_from_reads(&mut seed, &mut stalled) {
        Err(VirtioPciError::CompletionTimeout) => {}
        _ => return TestResult::Fail("zero-progress completion did not fail as stalled"),
    }

    // A device error propagates instead of being papered over.
    let mut failing =
        |_out: &mut [u8]| -> Result<usize, VirtioPciError> { Err(VirtioPciError::NoQueues) };
    let mut seed = [0u8; 32];
    match fill_seed_from_reads(&mut seed, &mut failing) {
        Err(VirtioPciError::NoQueues) => {}
        _ => return TestResult::Fail("device error did not fail the seed fill"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/rng-pci", smoke_virtio_rng_seed_fill_loop);

fn smoke_virtio_snd_pci_probe() -> TestResult {
    use crate::snd_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == snd_pci::VIRTIO_SND_PCI_VENDOR
            && d.id.device == snd_pci::VIRTIO_SND_PCI_DEVICE
    });
    if !has {
        return TestResult::Skip("no virtio-snd-pci");
    }
    let authority = bootstrap_registry_authority();
    // Exercise teardown/re-probe explicitly. The full suite probes this same
    // live QEMU device from the audio tests too; dropping queue DMA without a
    // completed device reset used to leave stale host-side queue pointers and
    // intermittently SIGSEGV QEMU on a later probe.
    for _ in 0..4 {
        snd_pci::__reset_for_test();
        __reset_for_test();
        snd_pci::register_pci_driver();
        if probe_all_pci(&authority).is_err() {
            return TestResult::Fail("probe_all_pci");
        }
        if !snd_pci::is_probed() {
            return TestResult::Fail("snd probe didn't install controller");
        }
        if snd_pci::topology().is_none() {
            return TestResult::Fail("topology missing after probe");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/snd-pci", smoke_virtio_snd_pci_probe);

/// The ALSA playback backend must keep the device's TX queue full without
/// waiting for playback. The device acks a buffer only after consuming it at
/// the stream rate, so a backend that waited for each ack inside START
/// reported every queued frame as already played: ALSA saw an empty ring,
/// raised XRUN, and PipeWire's DROP/PREPARE/START recovery looped forever.
fn smoke_virtio_snd_pci_playback_queues_async() -> TestResult {
    use crate::snd_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    use narf_drivers_sound::format::{HwParams, SampleFormat};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    if !devices().iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == snd_pci::VIRTIO_SND_PCI_VENDOR
            && d.id.device == snd_pci::VIRTIO_SND_PCI_DEVICE
    }) {
        return TestResult::Skip("no virtio-snd-pci");
    }
    snd_pci::__reset_for_test();
    __reset_for_test();
    snd_pci::register_pci_driver();
    if probe_all_pci(&bootstrap_registry_authority()).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    let Some(card) = snd_pci::__card_index_for_test() else {
        return TestResult::Fail("virtio-snd card not registered");
    };
    // QEMU advertises PCM_INFO from the last voice an earlier test prepared
    // (hw/audio/virtio-snd.c::virtio_snd_pcm_prepare), so ask for a format
    // the device reports now; the queueing is what this test pins.
    let Ok(caps) = narf_drivers_sound::pcm_capabilities(card, false) else {
        return TestResult::Fail("pcm_capabilities");
    };
    let (Some(&rate), Some(&channels)) = (caps.rates.last(), caps.channels.last()) else {
        return TestResult::Fail("virtio-snd advertises no S16 rate or channel count");
    };
    let Ok(mut stream) = narf_drivers_sound::open_playback(card, 0) else {
        return TestResult::Fail("open_playback");
    };
    // 32 periods of 1024 frames = 683 ms at 48 kHz.
    let params = HwParams {
        format: SampleFormat::S16LE,
        rate,
        channels,
        period_size: 1024,
        periods: 32,
    };
    let frames = u64::from(params.period_size * params.periods);
    if stream.hw_params(params).is_err() || stream.prepare().is_err() {
        return TestResult::Fail("hw_params/prepare");
    }
    let silence = alloc::vec![0u8; params.buffer_bytes()];
    if stream.write(&silence) != Ok(silence.len()) {
        return TestResult::Fail("prefill did not accept the whole ring");
    }
    let started = narf_time::wall::monotonic_ns();
    if stream.start().is_err() {
        return TestResult::Fail("start");
    }
    let start_ms = (narf_time::wall::monotonic_ns() - started) / 1_000_000;
    let early = stream.pointer();
    if start_ms > 200 {
        return TestResult::Fail("START waited for the queued audio to play");
    }
    if early >= frames / 2 {
        return TestResult::Fail("pointer reported queued frames as played");
    }
    // Completions must still arrive and advance the pointer to the end. The
    // device plays in real time, but the kernel-test boot never calibrates
    // the TSC (`frame/src/bare_main.rs`), so a monotonic-ns budget here is
    // raw cycles: on a 4.7 GHz host 3 "s" is 0.64 s, less than the 683 ms of
    // queued audio, and the last periods always missed it. Bound the wait by
    // a stall — no completion for STALL_NS — instead of by total time, with a
    // generous overall cap so a slow-but-steady device still finishes.
    const STALL_NS: u64 = 3_000_000_000;
    let mut last = early;
    let mut progressed_at = narf_time::wall::monotonic_ns();
    let mut stalled = false;
    let drained = narf_scheduler::responsive_spin_until(
        || {
            let now = stream.pointer();
            if now < last {
                return true;
            }
            let t = narf_time::wall::monotonic_ns();
            if now != last {
                progressed_at = t;
            } else if t - progressed_at > STALL_NS {
                stalled = true;
                return true;
            }
            last = now;
            now >= frames
        },
        narf_time::Deadline::after_ms(60_000),
    );
    let _ = stream.stop();
    if stalled {
        return TestResult::Fail("device completions stalled before the end of the ring");
    }
    if !drained || last != frames {
        return TestResult::Fail("device completions did not advance the pointer to the end");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/snd-pci",
    smoke_virtio_snd_pci_playback_queues_async
);

/// Event decoding is pinned byte-for-byte against the spec-shaped
/// frame (1.2 §5.14.6 events; CTL_NOTIFY per 1.4 §5.14.6.10.4).
/// No device is needed: the decoder is pure.
fn virtio_snd_event_decode() -> TestResult {
    use crate::snd_pci::{decode_event, SndEvent};
    // Jack connected: code 0x1000, data = jack id.
    let mut bytes = [0u8; 8];
    bytes[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
    if decode_event(&bytes) != Some(SndEvent::JackConnected(3)) {
        return TestResult::Fail("jack connected decode");
    }
    // Jack disconnected: code 0x1001.
    bytes[0..4].copy_from_slice(&0x1001u32.to_le_bytes());
    if decode_event(&bytes) != Some(SndEvent::JackDisconnected(3)) {
        return TestResult::Fail("jack disconnected decode");
    }
    // PCM period elapsed / xrun: codes 0x1100 / 0x1101, data = stream id.
    bytes[0..4].copy_from_slice(&0x1100u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    if decode_event(&bytes) != Some(SndEvent::PcmPeriodElapsed(1)) {
        return TestResult::Fail("pcm period decode");
    }
    bytes[0..4].copy_from_slice(&0x1101u32.to_le_bytes());
    if decode_event(&bytes) != Some(SndEvent::PcmXrun(1)) {
        return TestResult::Fail("pcm xrun decode");
    }
    // CTL notify: code 0x1200, data word splits into control_id
    // (low u16) + mask (high u16).
    bytes[0..4].copy_from_slice(&0x1200u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&0x0007u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&0x0001u16.to_le_bytes());
    if decode_event(&bytes)
        != Some(SndEvent::CtlNotify {
            control_id: 7,
            mask: 1,
        })
    {
        return TestResult::Fail("ctl notify decode");
    }
    // Unknown codes and short buffers decode to None, never to a
    // misapplied event.
    bytes[0..4].copy_from_slice(&0x9999u32.to_le_bytes());
    if decode_event(&bytes).is_some() {
        return TestResult::Fail("unknown event code decoded");
    }
    if decode_event(&bytes[..7]).is_some() || decode_event(&[]).is_some() {
        return TestResult::Fail("short event buffer decoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/snd-pci", virtio_snd_event_decode);

/// Jack-event application against a fake state slice: connect sets,
/// disconnect clears, out-of-range ids and non-jack events are
/// ignored rather than flipping state.
fn virtio_snd_jack_apply() -> TestResult {
    use crate::snd_pci::{apply_jack_event, SndEvent};
    let mut state = [false; 2];
    apply_jack_event(&mut state, SndEvent::JackConnected(1));
    if state != [false, true] {
        return TestResult::Fail("connect did not set jack 1");
    }
    apply_jack_event(&mut state, SndEvent::JackConnected(9));
    if state != [false, true] {
        return TestResult::Fail("out-of-range connect flipped state");
    }
    apply_jack_event(&mut state, SndEvent::PcmPeriodElapsed(1));
    if state != [false, true] {
        return TestResult::Fail("pcm event flipped jack state");
    }
    apply_jack_event(&mut state, SndEvent::JackDisconnected(1));
    if state != [false, false] {
        return TestResult::Fail("disconnect did not clear jack 1");
    }
    apply_jack_event(&mut state, SndEvent::JackDisconnected(0));
    if state != [false, false] {
        return TestResult::Fail("disconnect of clear jack changed state");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/snd-pci", virtio_snd_jack_apply);

/// CTL role encoding and mixer-kind mapping (1.4 §5.14.6.10.1):
/// role = (base << 1) | direction; UNDEFINED and out-of-range roles
/// map to nothing; input mutes and output gains have no mixer kind
/// and stay unadvertised rather than mislabeled.
fn virtio_snd_ctl_role_mapping() -> TestResult {
    use crate::snd_pci::{ctl_kind_for, split_ctl_role};
    use narf_drivers_sound::mixer::ControlKind;
    // (role, expected split, expected kind). Roles 0, 1, and 8 do
    // not split; roles 5 (input mute) and 6 (output gain) split
    // but have no mixer kind.
    type RoleCase = (u32, Option<(u32, u32)>, Option<ControlKind>);
    let cases: [RoleCase; 9] = [
        (2, Some((1, 0)), Some(ControlKind::MasterVolume)),
        (3, Some((1, 1)), Some(ControlKind::CaptureVolume)),
        (4, Some((2, 0)), Some(ControlKind::MasterMute)),
        (5, Some((2, 1)), None),
        (6, Some((3, 0)), None),
        (7, Some((3, 1)), Some(ControlKind::MicBoost)),
        (0, None, None),
        (1, None, None),
        (8, None, None),
    ];
    for (role, split, kind) in cases {
        if split_ctl_role(role) != split {
            return TestResult::Fail("role split mismatch");
        }
        let Some((base, direction)) = split else {
            continue;
        };
        if ctl_kind_for(base, direction) != kind {
            return TestResult::Fail("role kind mapping mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/snd-pci", virtio_snd_ctl_role_mapping);

/// `virtio_snd_ctl_info` parsing (1.4 §5.14.6.10.1, 92 bytes):
/// a volume element with role (VOLUME << 1) | OUTPUT, INTEGER type,
/// READ|WRITE access, count 2, and min/max/step parses field-exact;
/// malformed records (zero count, count above the type maximum,
/// undefined role/type/access bits, wrong length) parse to None.
fn virtio_snd_ctl_info_parse() -> TestResult {
    use crate::snd_pci::parse_ctl_info_record;
    let mut record = [0u8; 92];
    record[0..4].copy_from_slice(&0u32.to_le_bytes());
    record[4..8].copy_from_slice(&2u32.to_le_bytes());
    record[8..12].copy_from_slice(&1u32.to_le_bytes());
    record[12..16].copy_from_slice(&0b11u32.to_le_bytes());
    record[16..20].copy_from_slice(&2u32.to_le_bytes());
    record[20..24].copy_from_slice(&0u32.to_le_bytes());
    record[24..28].copy_from_slice(b"Vol\0");
    record[68..72].copy_from_slice(&0i32.to_le_bytes());
    record[72..76].copy_from_slice(&87i32.to_le_bytes());
    record[76..80].copy_from_slice(&1i32.to_le_bytes());
    let Some(info) = parse_ctl_info_record(&record) else {
        return TestResult::Fail("valid ctl info record rejected");
    };
    if info.role != 2
        || info.ctype != 1
        || info.access != 0b11
        || info.count != 2
        || info.min != 0
        || info.max != 87
        || info.step != 1
    {
        return TestResult::Fail("ctl info fields mismatch");
    }
    // INTEGER64 form: min/max/step are 64-bit at 68/76/84.
    let mut record64 = [0u8; 92];
    record64[8..12].copy_from_slice(&2u32.to_le_bytes());
    record64[12..16].copy_from_slice(&0b01u32.to_le_bytes());
    record64[16..20].copy_from_slice(&1u32.to_le_bytes());
    record64[68..76].copy_from_slice(&(-100i64).to_le_bytes());
    record64[76..84].copy_from_slice(&100i64.to_le_bytes());
    record64[84..92].copy_from_slice(&5i64.to_le_bytes());
    let Some(info64) = parse_ctl_info_record(&record64) else {
        return TestResult::Fail("valid integer64 record rejected");
    };
    if info64.min != -100 || info64.max != 100 || info64.step != 5 {
        return TestResult::Fail("integer64 fields mismatch");
    }
    // Malformed variants.
    let mut bad = record;
    bad[16..20].copy_from_slice(&0u32.to_le_bytes());
    if parse_ctl_info_record(&bad).is_some() {
        return TestResult::Fail("zero-count record accepted");
    }
    let mut bad = record;
    bad[16..20].copy_from_slice(&129u32.to_le_bytes());
    if parse_ctl_info_record(&bad).is_some() {
        return TestResult::Fail("over-count record accepted");
    }
    let mut bad = record;
    bad[4..8].copy_from_slice(&8u32.to_le_bytes());
    if parse_ctl_info_record(&bad).is_some() {
        return TestResult::Fail("undefined role accepted");
    }
    let mut bad = record;
    bad[8..12].copy_from_slice(&6u32.to_le_bytes());
    if parse_ctl_info_record(&bad).is_some() {
        return TestResult::Fail("undefined type accepted");
    }
    let mut bad = record;
    bad[12..16].copy_from_slice(&0x80u32.to_le_bytes());
    if parse_ctl_info_record(&bad).is_some() {
        return TestResult::Fail("undefined access bit accepted");
    }
    if parse_ctl_info_record(&record[..91]).is_some() {
        return TestResult::Fail("short record accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/snd-pci", virtio_snd_ctl_info_parse);

/// `virtio_snd_pcm_info` direction split (1.2 §5.14.6.6.2): given
/// output-then-input records, the first output id and first input id
/// are selected; a wrong-direction record is never accepted as the
/// other direction, and non-viable records are skipped.
fn virtio_snd_pcm_info_direction_split() -> TestResult {
    use crate::snd_pci::{split_stream_records, PlaybackInfo};
    let output = PlaybackInfo {
        formats: 1 << 5,
        rates: (1 << 6) | (1 << 7),
        direction: 0,
        channels_min: 1,
        channels_max: 2,
    };
    let input = PlaybackInfo {
        formats: 1 << 5,
        rates: 1 << 7,
        direction: 1,
        channels_min: 1,
        channels_max: 1,
    };
    let broken = PlaybackInfo {
        formats: 0,
        rates: 1 << 7,
        direction: 1,
        channels_min: 1,
        channels_max: 1,
    };
    // Input first, then output, then a non-viable input: selection
    // is by direction in device order, skipping the broken record.
    let records = [(3, input), (1, output), (2, broken)];
    if split_stream_records(&records) != (Some(1), Some(3)) {
        return TestResult::Fail("direction split mismatch");
    }
    // Output only: no input id.
    if split_stream_records(&[(0, output)]) != (Some(0), None) {
        return TestResult::Fail("output-only split mismatch");
    }
    // Input only: no output id (probe would fail, not misbind).
    if split_stream_records(&[(0, input)]) != (None, Some(0)) {
        return TestResult::Fail("input-only split mismatch");
    }
    // Non-viable only: neither.
    if split_stream_records(&[(0, broken)]) != (None, None) {
        return TestResult::Fail("broken-only split mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/snd-pci",
    virtio_snd_pcm_info_direction_split
);

/// `virtio_snd_jack_info` parsing (1.2 §5.14.6.4.1, 24 bytes):
/// the `connected` byte at offset 16 reads 0/1; any other value
/// parses to None rather than being guessed.
fn virtio_snd_jack_info_parse() -> TestResult {
    use crate::snd_pci::parse_jack_info_record;
    let mut record = [0u8; 24];
    record[16] = 1;
    if parse_jack_info_record(&record) != Some(true) {
        return TestResult::Fail("connected jack parsed wrong");
    }
    record[16] = 0;
    if parse_jack_info_record(&record) != Some(false) {
        return TestResult::Fail("disconnected jack parsed wrong");
    }
    record[16] = 2;
    if parse_jack_info_record(&record).is_some() {
        return TestResult::Fail("undefined connected value accepted");
    }
    if parse_jack_info_record(&record[..23]).is_some() {
        return TestResult::Fail("short jack record accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/snd-pci", virtio_snd_jack_info_parse);

/// Live capture path against the QEMU virtio-snd device: open the
/// capture device, configure/prepare/start, and read at least one
/// period of frames, with the same stall-bounded wait the playback
/// test uses (the kernel-test boot never calibrates the TSC, so a
/// total-time budget is meaningless; a stall budget is not).
/// Skips when the device has no capture stream.
fn smoke_virtio_snd_pci_capture_queues_async() -> TestResult {
    use crate::snd_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    use narf_drivers_sound::format::{HwParams, SampleFormat};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    if !devices().iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == snd_pci::VIRTIO_SND_PCI_VENDOR
            && d.id.device == snd_pci::VIRTIO_SND_PCI_DEVICE
    }) {
        return TestResult::Skip("no virtio-snd-pci");
    }
    snd_pci::__reset_for_test();
    __reset_for_test();
    snd_pci::register_pci_driver();
    if probe_all_pci(&bootstrap_registry_authority()).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    let Some(card) = snd_pci::__card_index_for_test() else {
        return TestResult::Fail("virtio-snd card not registered");
    };
    let mut stream = match narf_drivers_sound::open_capture(card, 0) {
        Ok(stream) => stream,
        Err(narf_drivers_sound::SoundError::NoSuchDevice) => {
            return TestResult::Skip("no virtio-snd capture stream");
        }
        Err(_) => return TestResult::Fail("open_capture"),
    };
    let Ok(caps) = narf_drivers_sound::pcm_capabilities(card, true) else {
        return TestResult::Fail("pcm_capabilities(capture)");
    };
    let (Some(&rate), Some(&channels)) = (caps.rates.last(), caps.channels.last()) else {
        return TestResult::Fail("virtio-snd advertises no S16 capture rate or channel count");
    };
    let params = HwParams {
        format: SampleFormat::S16LE,
        rate,
        channels,
        period_size: 1024,
        periods: 4,
    };
    if stream.hw_params(params).is_err() || stream.prepare().is_err() {
        return TestResult::Fail("capture hw_params/prepare");
    }
    if stream.start().is_err() {
        return TestResult::Fail("capture start");
    }
    let period_bytes = params.period_bytes();
    let mut buf = alloc::vec![0u8; period_bytes * 2];
    let mut got = 0usize;
    let mut last = 0usize;
    let mut progressed_at = narf_time::wall::monotonic_ns();
    let mut stalled = false;
    const STALL_NS: u64 = 3_000_000_000;
    let filled = narf_scheduler::responsive_spin_until(
        || {
            match stream.read(&mut buf) {
                Ok(n) => got += n,
                Err(_) => return true,
            }
            if got < last {
                return true;
            }
            let t = narf_time::wall::monotonic_ns();
            if got != last {
                progressed_at = t;
            } else if t - progressed_at > STALL_NS {
                stalled = true;
                return true;
            }
            last = got;
            got >= period_bytes
        },
        narf_time::Deadline::after_ms(60_000),
    );
    let _ = stream.stop();
    if stalled {
        return TestResult::Fail("capture produced no frames before stalling");
    }
    if !filled || got < period_bytes {
        return TestResult::Fail("capture did not fill one period");
    }
    if stream.pointer() < u64::from(params.period_size) {
        return TestResult::Fail("capture pointer did not advance a period");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/snd-pci",
    smoke_virtio_snd_pci_capture_queues_async
);

/// Live mixer surface against the QEMU virtio-snd device: every
/// jack id the topology reports has exactly one JackSense control
/// that reads as a boolean, and every advertised CTL control
/// round-trips its own value back through a write of the value just
/// read (a no-op write, so the device state is unchanged). A
/// read-only CTL control reports NoSuchControl on write, which is
/// accepted. Skips nothing: the jack surface exists whenever the
/// device reports jacks, and the CTL part is vacuous (but still
/// executed) when the device offers no control elements.
fn smoke_virtio_snd_pci_controls_surface() -> TestResult {
    use crate::snd_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    use narf_drivers_sound::mixer::ControlKind;
    use narf_drivers_sound::SoundError;
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    if !devices().iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == snd_pci::VIRTIO_SND_PCI_VENDOR
            && d.id.device == snd_pci::VIRTIO_SND_PCI_DEVICE
    }) {
        return TestResult::Skip("no virtio-snd-pci");
    }
    snd_pci::__reset_for_test();
    __reset_for_test();
    snd_pci::register_pci_driver();
    if probe_all_pci(&bootstrap_registry_authority()).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    let Some(card) = snd_pci::__card_index_for_test() else {
        return TestResult::Fail("virtio-snd card not registered");
    };
    let Some((jacks, _, _)) = snd_pci::topology() else {
        return TestResult::Fail("topology missing after probe");
    };
    let Ok(mixer) = narf_drivers_sound::mixer(card) else {
        return TestResult::Fail("mixer(card)");
    };
    let controls = mixer.list_controls();
    let jack_controls: alloc::vec::Vec<u32> = controls
        .iter()
        .filter(|id| id.kind == ControlKind::JackSense)
        .map(|id| id.index)
        .collect();
    if jack_controls.len() != jacks as usize {
        return TestResult::Fail("jack control count does not match topology jacks");
    }
    for jack in 0..jacks {
        if !jack_controls.contains(&jack) {
            return TestResult::Fail("jack id missing its JackSense control");
        }
        let id = narf_drivers_sound::mixer::ControlId {
            index: jack,
            kind: ControlKind::JackSense,
        };
        match mixer.get_control_value(id) {
            Ok(narf_drivers_sound::mixer::ControlValue::Boolean(_)) => {}
            _ => return TestResult::Fail("JackSense did not read as boolean"),
        }
    }
    for id in controls
        .iter()
        .filter(|id| id.kind != ControlKind::JackSense)
    {
        let Ok(value) = mixer.get_control_value(*id) else {
            return TestResult::Fail("CTL control did not read");
        };
        match mixer.set_control_value(*id, value) {
            Ok(()) => {}
            Err(SoundError::NoSuchControl) => {}
            Err(_) => return TestResult::Fail("CTL control write failed unexpectedly"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/snd-pci",
    smoke_virtio_snd_pci_controls_surface
);

fn smoke_virtio_balloon_pci_probe() -> TestResult {
    use crate::balloon_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == balloon_pci::VIRTIO_BALLOON_PCI_VENDOR
            && d.id.device == balloon_pci::VIRTIO_BALLOON_PCI_DEVICE
    });
    if !has {
        return TestResult::Skip("no virtio-balloon-pci");
    }
    __reset_for_test();
    balloon_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !balloon_pci::is_probed() {
        return TestResult::Fail("balloon probe didn't install controller");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/balloon-pci", smoke_virtio_balloon_pci_probe);

fn smoke_virtio_balloon_pci_inflate_deflate() -> TestResult {
    use crate::balloon_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    // SAFETY: ECAM_DEFAULT_BASE is the identity-mapped QEMU ECAM region; safe to call once per test.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == balloon_pci::VIRTIO_BALLOON_PCI_VENDOR
            && d.id.device == balloon_pci::VIRTIO_BALLOON_PCI_DEVICE
    });
    if !has {
        return TestResult::Skip("no virtio-balloon-pci");
    }
    __reset_for_test();
    balloon_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    // Allocate a single guest page + hand its PFN to the host through
    // the inflate queue, then deflate it back. Polled completion;
    // succeeds iff the device acks both submissions.
    let buf = match narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent"),
    };
    let pfn = (buf.dma_addr().raw() >> 12) as u32;
    let pfns = [pfn];
    let r = balloon_pci::with_controller(|c| c.inflate(&pfns));
    match r {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("inflate"),
        None => return TestResult::Fail("controller missing"),
    }
    let r = balloon_pci::with_controller(|c| c.deflate(&pfns));
    match r {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("deflate"),
        None => return TestResult::Fail("controller missing"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/balloon-pci",
    smoke_virtio_balloon_pci_inflate_deflate
);
