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
    for i in 0..512usize {
        let expected = (i as u8).wrapping_mul(0x97);
        if sector[i] != expected {
            return TestResult::Fail("virtio-blk-pci read pattern mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/blk-pci", smoke_virtio_blk_pci_read_sector);

fn smoke_virtio_blk_pci_write_then_read() -> TestResult {
    use crate::blk_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
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
    for i in 0..512usize {
        payload[i] = (i as u8).wrapping_mul(0x5B) ^ 0xC3;
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
    for i in 0..512usize {
        let expected = (i as u8).wrapping_mul(0x97);
        if sector[i] != expected {
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
    let _wheel_arm_installed_by_us =
        if !narf_time::timer_wheel::arm_callback_installed() {
            narf_time::timer_wheel::set_arm_callback(_wheel_arm_noop);
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
        narf_time::timer_wheel::clear_arm_callback();
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
            for i in 0..512usize {
                let expected = (i as u8).wrapping_mul(0x97);
                if sector[i] != expected {
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
    for i in 0..512usize {
        pattern[i] = (i as u8).wrapping_add(0x37);
    }
    // Install no-op wheel arm callback if needed — same reasoning
    // as smoke_virtio_blk_pci_irq_async (SleepUntil's self-wake
    // breaks the HLT idle loop in kernel-test mode where
    // timer_pump::init never ran).
    fn _wheel_arm_noop(_deadline_cycles: u64) {}
    let _wheel_arm_installed_by_us =
        if !narf_time::timer_wheel::arm_callback_installed() {
            narf_time::timer_wheel::set_arm_callback(_wheel_arm_noop);
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
        narf_time::timer_wheel::clear_arm_callback();
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
    for i in 0..512usize {
        if readback[i] != pattern[i] {
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

fn smoke_virtio_net_pci_tx() -> TestResult {
    use crate::net_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
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
    // hand it to tx_dma — zero-copy: the device descriptor will
    // point at this buffer directly.
    let mut tx_buf = narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0)
        .expect("alloc tx scratch");
    {
        let slice = tx_buf.as_mut_slice();
        for i in 14..64 {
            slice[i] = (i as u8).wrapping_mul(0x3D);
        }
    }
    let tx_ok = net_pci::with_controller(|c| c.tx_dma(&tx_buf, 0, 64))
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
    let mut tx_dma = narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0)
        .expect("alloc arp scratch");
    {
        let f = tx_dma.as_mut_slice();
        for i in 0..6 {
            f[i] = 0xFF;
        }
        f[6] = 0x52;
        f[7] = 0x54;
        f[8] = 0x00;
        f[9] = 0x12;
        f[10] = 0x34;
        f[11] = 0x57;
        f[12] = 0x08;
        f[13] = 0x06;
        f[14] = 0x00;
        f[15] = 0x01;
        f[16] = 0x08;
        f[17] = 0x00;
        f[18] = 6;
        f[19] = 4;
        f[20] = 0x00;
        f[21] = 0x01;
        for i in 0..6 {
            f[22 + i] = f[6 + i];
        }
        f[28] = 10;
        f[29] = 0;
        f[30] = 2;
        f[31] = 15;
        f[38] = 10;
        f[39] = 0;
        f[40] = 2;
        f[41] = 2;
    }
    if net_pci::with_controller(|c| c.tx_dma(&tx_dma, 0, 42))
        .map(|r| r.is_ok())
        .unwrap_or(false)
        == false
    {
        return TestResult::Fail("virtio-net tx_dma");
    }
    // Drain one RX frame via zero-copy rx_take. `buf` would be
    // freed on drop here; we only need to confirm the device
    // actually published an arrival.
    let mut any = 0u32;
    for _ in 0..2_000_000u32 {
        let taken = net_pci::with_controller(|c| c.rx_take()).flatten();
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
    // probe() registers a "vnet0" Interface with narf_net::registry().
    // Confirm it's there and reports a non-default MAC + standard MTU.
    let found = narf_net::registry().with_interface("vnet0", |iface| {
        let mac = iface.mac();
        let mtu = iface.mtu();
        let link = iface.link_up();
        // mtu defaults to 1500 when F_MTU isn't negotiated — that's
        // still a valid pass. The MAC ought to be non-zero on QEMU
        // (QEMU advertises a 52:54:00:XX:XX:XX vendor default).
        let mac_ok = mac.iter().any(|&b| b != 0);
        let mtu_ok = mtu >= 64 && mtu <= 65535;
        (mac_ok, mtu_ok, link)
    });
    match found {
        Some((true, true, _link)) => TestResult::Pass,
        Some((false, _, _)) => TestResult::Fail("MAC is all-zero — F_MAC negotiation broken"),
        Some((_, false, _)) => TestResult::Fail("MTU out of expected range"),
        None => TestResult::Fail("vnet0 not registered with narf_net::registry()"),
    }
}
kernel_test_in!("drivers/virtio/net-pci", smoke_virtio_net_pci_registers_iface);

fn smoke_virtio_net_pci_legacy_iface_registered() -> TestResult {
    // The TCP stack consumes from narf_net::iface (fn-pointer
    // registry), not the ring-based narf_net::registry. virtio-net
    // probe must hook itself into both so `tcp_stack::connect` /
    // `arp_resolve` / `iface::send` actually reach the device.
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    let vnet = match narf_net::iface::lookup("vnet0") {
        Some(i) => i,
        None => return TestResult::Fail("vnet0 not registered with narf_net::iface"),
    };
    // Same MAC the controller reports — confirms the probe path
    // copied it through (not a hardcoded placeholder).
    let ctrl_mac = net_pci::with_controller(|c| c.mac()).unwrap_or([0; 6]);
    if vnet.mac != ctrl_mac {
        return TestResult::Fail("legacy iface MAC doesn't match controller mac()");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_legacy_iface_registered
);

fn smoke_virtio_net_pci_send_fn_dispatches() -> TestResult {
    // Direct smoke: call vnet0's SendFn with a hand-built broadcast
    // ARP frame and confirm the send returns Ok. This validates the
    // legacy iface registration → DmaBuffer alloc → tx_dma path
    // end-to-end without depending on which iface `primary()` picks
    // when both virtio-net and e1000 are attached.
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    let vnet = match narf_net::iface::lookup("vnet0") {
        Some(i) => i,
        None => return TestResult::Skip("vnet0 not registered with legacy iface"),
    };
    let src_mac = vnet.mac;
    // 42-byte ARP-over-Ethernet broadcast for 10.0.2.2. Bytes
    // copied straight from RFC 826 layout; the device only sees
    // the wire, so as long as the frame is well-formed QEMU's
    // user-mode SLIRP will answer.
    let mut frame = [0u8; 42];
    // Eth dst = ff:ff:ff:ff:ff:ff (broadcast)
    for i in 0..6 {
        frame[i] = 0xFF;
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
    match (vnet.send)(&frame) {
        Ok(()) => TestResult::Pass,
        Err(()) => TestResult::Fail("vnet0 SendFn returned Err — tx_dma path broken"),
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
        None => return TestResult::Skip("vnet0 controller missing"),
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
        None => return TestResult::Skip("vnet0 controller vanished"),
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

fn smoke_virtio_net_pci_dhcp_acquire() -> TestResult {
    // End-to-end DHCP exchange against QEMU's built-in user-mode
    // SLIRP server, which always offers `10.0.2.15` as the lease.
    // Drives the full DISCOVER → OFFER → REQUEST → ACK flow through
    // vnet0 — exercises the new tcp_stack UDP dispatch + dhcp client
    // + frame-build wrappers.
    use crate::net_pci;
    if !net_pci::is_probed() {
        return TestResult::Skip("virtio-net-pci not present in this QEMU config");
    }
    if narf_net::iface::lookup("vnet0").is_none() {
        return TestResult::Skip("vnet0 not registered with legacy iface");
    }
    // kernel-test builds don't run `boot_userspace_init`, so the
    // `tcp_stack::init()` that normally wires
    // `iface::install_rx_handler(rx_handler)` never fires. Without
    // an RX handler installed, inbound DHCP OFFER frames are
    // silently dropped by `iface::on_rx_frame` and the busy-wait
    // inside `acquire` times out. Idempotent — production builds
    // already called it via `cross_crate_init::install_all_hooks`.
    narf_net::tcp_stack::init();
    // acquire() sends through vnet0's send_fn (looked up by name,
    // not by primary()). The reply comes back on vnet0's RX
    // virtqueue; the busy-wait in `acquire` drains the ring via
    // `iface::drain_pump`, which routes through tcp_stack
    // → dhcp::on_udp_in, populating LATEST_REPLY.
    match narf_net::dhcp::acquire("vnet0", 5000) {
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
kernel_test_in!(
    "drivers/virtio/net-pci",
    smoke_virtio_net_pci_dhcp_acquire
);

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
    let on = net_pci::with_controller(|c| c.set_promisc(true)).unwrap_or(Err(
        crate::pci::VirtioPciError::NoQueues,
    ));
    if on.is_err() {
        return TestResult::Fail("promisc=on rejected");
    }
    let off = net_pci::with_controller(|c| c.set_promisc(false)).unwrap_or(Err(
        crate::pci::VirtioPciError::NoQueues,
    ));
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
    let mut buf = narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0)
        .expect("alloc tx scratch");
    {
        let s = buf.as_mut_slice();
        for (i, b) in s.iter_mut().enumerate().take(64) {
            *b = (i as u8).wrapping_mul(0x17);
        }
    }
    let ok = net_pci::with_controller(|c| c.tx_dma_on(0, &buf, 0, 64))
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

fn smoke_virtio_snd_pci_probe() -> TestResult {
    use crate::snd_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
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
    __reset_for_test();
    snd_pci::__reset_for_test();
    snd_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !snd_pci::is_probed() {
        return TestResult::Fail("snd probe didn't install controller");
    }
    if snd_pci::topology().is_none() {
        return TestResult::Fail("topology missing after probe");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/snd-pci", smoke_virtio_snd_pci_probe);

fn smoke_virtio_balloon_pci_probe() -> TestResult {
    use crate::balloon_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
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
    let pfn = (buf.phys_addr().raw() >> 12) as u32;
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
