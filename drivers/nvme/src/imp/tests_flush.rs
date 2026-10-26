//! Flush / FUA / clean-shutdown smokes: the shutdown register protocol and
//! quiesce ordering against a model controller, then the real Flush, FUA
//! write and CC.SHN shutdown on QEMU's controllers.

use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::shutdown::{self, CtrlRegs, ShutdownOutcome};

/// Model controller: records every event (flushes and CC writes) in one
/// log, and reports SHST complete `delay` CSTS reads after SHN was set.
struct ModelCtrl<'a> {
    log: &'a IrqSafeSpinLock<Vec<&'static str>>,
    cc: Cell<u32>,
    shn_reads: Cell<u32>,
    delay: u32,
    gone: bool,
}

impl CtrlRegs for ModelCtrl<'_> {
    fn read_cc(&self) -> u32 {
        self.cc.get()
    }
    fn write_cc(&self, v: u32) {
        if v & shutdown::CC_SHN_MASK == shutdown::CC_SHN_NORMAL {
            self.log.lock().push("shn");
        }
        self.cc.set(v);
    }
    fn read_csts(&self) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        if self.cc.get() & shutdown::CC_SHN_MASK == 0 {
            return 1; // RDY
        }
        let n = self.shn_reads.get() + 1;
        self.shn_reads.set(n);
        if n > self.delay {
            self.log.lock().push("shst-complete");
            1 | shutdown::CSTS_SHST_CMPLT
        } else {
            1 | (1 << 2) // shutdown processing occurring
        }
    }
}

/// `spin` model: poll up to `ms` times (one poll per "millisecond").
fn model_spin(cond: &mut dyn FnMut() -> bool, ms: u64) -> bool {
    (0..ms).any(|_| cond())
}

fn model<'a>(log: &'a IrqSafeSpinLock<Vec<&'static str>>, delay: u32) -> ModelCtrl<'a> {
    ModelCtrl {
        log,
        cc: Cell::new(shutdown::CC_EN),
        shn_reads: Cell::new(0),
        delay,
        gone: false,
    }
}

/// Every namespace is flushed — each flush completing before the next
/// step — before CC.SHN is written; SHN is then held until CSTS.SHST
/// reports complete; no flush is sent without a VWC; the budget, a vanished
/// function and a disabled controller are all bounded.
fn smoke_nvme_shutdown_model() -> TestResult {
    let log = IrqSafeSpinLock::new(Vec::new());
    let regs = model(&log, 3);
    let report = shutdown::quiesce(
        &[1, 4],
        shutdown::VWC_PRESENT,
        &mut |nsid| -> Result<(), ()> {
            log.lock().push(if nsid == 1 { "flush1" } else { "flush4" });
            Ok(())
        },
        &regs,
        5_000,
        &mut model_spin,
    );
    if report.shutdown != ShutdownOutcome::Complete
        || report.flushes != vec![(1, Ok(())), (4, Ok(()))]
    {
        return TestResult::Fail("quiesce did not flush both namespaces and complete SHN");
    }
    if *log.lock() != ["flush1", "flush4", "shn", "shst-complete"] {
        return TestResult::Fail("flush must complete before SHN, and SHN wait for SHST");
    }
    if regs.cc.get() & shutdown::CC_SHN_MASK != shutdown::CC_SHN_NORMAL
        || regs.cc.get() & shutdown::CC_EN == 0
    {
        return TestResult::Fail("CC must carry SHN=normal with EN kept");
    }
    // No VWC: no flush, SHN still sent. A failing flush still gets SHN.
    let log2 = IrqSafeSpinLock::new(Vec::new());
    let r2 = shutdown::quiesce(
        &[1],
        0,
        &mut |_| -> Result<(), ()> { Err(()) },
        &model(&log2, 0),
        5_000,
        &mut model_spin,
    );
    if !r2.flushes.is_empty() || *log2.lock() != ["shn", "shst-complete"] {
        return TestResult::Fail("a write-through controller must not be flushed");
    }
    let log3 = IrqSafeSpinLock::new(Vec::new());
    let r3 = shutdown::quiesce(
        &[1],
        shutdown::VWC_PRESENT,
        &mut |_| -> Result<(), ()> { Err(()) },
        &model(&log3, 0),
        5_000,
        &mut model_spin,
    );
    if r3.shutdown != ShutdownOutcome::Complete || r3.flushes != vec![(1, Err(()))] {
        return TestResult::Fail("a failed flush must not skip the shutdown");
    }
    // Bounded: SHST never completes inside the budget.
    let log4 = IrqSafeSpinLock::new(Vec::new());
    if shutdown::normal_shutdown(&model(&log4, 1_000), 100, &mut model_spin)
        != ShutdownOutcome::TimedOut
    {
        return TestResult::Fail("SHST wait not bounded by the timeout");
    }
    let log5 = IrqSafeSpinLock::new(Vec::new());
    let mut gone = model(&log5, 0);
    gone.gone = true;
    if shutdown::normal_shutdown(&gone, 100, &mut model_spin) != ShutdownOutcome::Gone {
        return TestResult::Fail("all-ones CSTS must report the function gone");
    }
    let log6 = IrqSafeSpinLock::new(Vec::new());
    let off = model(&log6, 0);
    off.cc.set(0);
    if shutdown::normal_shutdown(&off, 100, &mut model_spin) != ShutdownOutcome::NotEnabled
        || !log6.lock().is_empty()
    {
        return TestResult::Fail("a disabled controller must not be sent SHN");
    }
    // Linux shutdown_timeout: clamp(RTD3E s, 5, 60), 5 s when unreported.
    if shutdown::shutdown_timeout_ms(0) != 5_000
        || shutdown::shutdown_timeout_ms(2_000_000) != 5_000
        || shutdown::shutdown_timeout_ms(8_000_000) != 8_000
        || shutdown::shutdown_timeout_ms(200_000_000) != 60_000
    {
        return TestResult::Fail("shutdown timeout differs from Linux's RTD3E clamp");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/flush", smoke_nvme_shutdown_model);

/// On QEMU's controllers: a Flush is sent and completes when VWC is set
/// (QEMU reports one), the registry's `flush` / `write_fua` / caps reach
/// the controller, and a FUA write reads back.
fn smoke_nvme_flush_qemu() -> TestResult {
    if super::controller_count() < 2 {
        return TestResult::Skip("needs the kernel-test NVMe controllers");
    }
    let Some(dev) = narf_block::find_block_device("nvme1n1") else {
        return TestResult::Fail("nvme1n1 not registered");
    };
    let vwc = super::with_controller_at(1, |c| c.has_volatile_write_cache()).unwrap_or(false);
    if dev.capabilities().volatile_cache != vwc || !dev.capabilities().fua {
        return TestResult::Fail("capabilities do not report the controller's VWC / FUA");
    }
    let before = super::with_controller_at(1, |c| c.flushes_completed()).unwrap_or(0);
    let lba = 60u64;
    let mut saved = [0u8; 512];
    if dev.read(lba, 1, &mut saved).is_err() {
        return TestResult::Fail("read failed");
    }
    let mut block = [0u8; 512];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i as u8) ^ 0x6D;
    }
    if dev.write_fua(lba, 1, &block).is_err() {
        return TestResult::Fail("FUA write failed");
    }
    if dev.flush().is_err() {
        return TestResult::Fail("flush failed");
    }
    let after = super::with_controller_at(1, |c| c.flushes_completed()).unwrap_or(0);
    if vwc && after != before + 1 {
        return TestResult::Fail("VWC controller: flush did not issue and complete a Flush");
    }
    if !vwc && after != before {
        return TestResult::Fail("write-through controller: flush must not send a command");
    }
    let mut back = [0u8; 512];
    let ok = dev.read(lba, 1, &mut back).is_ok() && back == block;
    let _ = dev.write(lba, 1, &saved);
    if !ok {
        return TestResult::Fail("FUA write did not read back");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/flush", smoke_nvme_flush_qemu);

/// Real CC.SHN on nvme1: shutdown completes (CSTS.SHST = complete), the
/// controller then refuses I/O, and a fresh bring-up restores it.
fn smoke_nvme_shutdown_qemu() -> TestResult {
    use narf_bus::{bootstrap_registry_authority, claim_device_cap};
    if super::controller_count() < 2 {
        return TestResult::Skip("needs the kernel-test NVMe controllers");
    }
    let Some(Some(dev)) = super::with_controller_at(1, |c| c.bus_device()) else {
        return TestResult::Fail("nvme1 has no bus device");
    };
    let authority = bootstrap_registry_authority();
    let Ok((_h, cap)) = claim_device_cap(&authority, dev.addr) else {
        return TestResult::Fail("claim_device_cap failed");
    };
    let mut ctrl = super::Controller::from_device(dev);
    if ctrl.bring_up(&cap).is_err() || ctrl.create_io_queue().is_err() {
        return TestResult::Fail("bring-up failed");
    }
    let vwc = ctrl.has_volatile_write_cache();
    let report = ctrl.shutdown();
    let mut buf_ok = true;
    if let Ok(buf) = narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0) {
        buf_ok = ctrl.read_lba(0, 1, &buf) == Err(super::NvmeError::ControllerDead);
        // Keep the page: the controller is shut down, but never hand DMA
        // memory back on a path that did not disable the controller.
        core::mem::forget(buf);
    }
    let result = match report {
        Some(r) if r.shutdown == ShutdownOutcome::Complete => {
            if vwc && (r.flushes.is_empty() || r.flushes.iter().any(|(_, x)| x.is_err())) {
                TestResult::Fail("shutdown did not flush the namespaces first")
            } else if !buf_ok {
                TestResult::Fail("a shut-down controller accepted I/O")
            } else {
                TestResult::Pass
            }
        }
        Some(_) => TestResult::Fail("CSTS.SHST never reported shutdown complete"),
        None => TestResult::Fail("shutdown on a brought-up controller returned None"),
    };
    // The live slot still points at its own (now reset) queues: reinstall.
    let mut fresh = super::Controller::from_device(dev);
    if fresh.bring_up(&cap).is_err() || fresh.create_io_queue().is_err() {
        return TestResult::Fail("re-bring-up after shutdown failed");
    }
    super::install_controller(fresh);
    // Leak the shut-down stack controller: its queues stay valid forever.
    core::mem::forget(ctrl);
    result
}
kernel_test_in!("drivers/nvme/flush", smoke_nvme_shutdown_qemu);

/// Bring `nvme1` back after a test shut it down: a fresh controller,
/// installed in place (the old slot is leaked, as `install_controller` does).
fn reinstall_nvme1() -> Result<(), &'static str> {
    use narf_bus::{bootstrap_registry_authority, claim_device_cap};
    let Some(Some(dev)) = super::with_controller_at(1, |c| c.bus_device()) else {
        return Err("nvme1 has no bus device");
    };
    let authority = bootstrap_registry_authority();
    let Ok((_h, cap)) = claim_device_cap(&authority, dev.addr) else {
        return Err("claim_device_cap failed");
    };
    let mut fresh = super::Controller::from_device(dev);
    if fresh.bring_up(&cap).is_err() || fresh.create_io_queue().is_err() {
        return Err("re-bring-up after shutdown failed");
    }
    super::install_controller(fresh);
    Ok(())
}

/// The final shutdown WAITS for the in-flight command: with nvme1's request
/// gate held (a command mid-flight), shutdown keeps polling, and once the
/// holder releases it the controller is flushed and sent CC.SHN normally —
/// not skipped, as the old 2-second "busy, shutdown skipped" path did.
fn smoke_nvme_shutdown_waits_for_in_flight_io() -> TestResult {
    if super::controller_count() < 2 {
        return TestResult::Skip("needs the kernel-test NVMe controllers");
    }
    let Some(slot) = super::slot_of(1) else {
        return TestResult::Fail("nvme1 slot missing");
    };
    let vwc = super::with_controller_at(1, |c| c.has_volatile_write_cache()).unwrap_or(false);
    // "In flight": hold the gate the way an I/O path does.
    core::mem::forget(super::acquire(slot));
    let mut polls = 0u32;
    let outcome = super::shutdown_slot(
        slot,
        super::SHUTDOWN_DRAIN_TIMEOUT_MS,
        &mut |cond, _budget| {
            loop {
                if cond() {
                    return true;
                }
                polls += 1;
                // The command completes after a few polls.
                if polls == 3 {
                    slot.req_gate
                        .store(false, core::sync::atomic::Ordering::Release);
                }
                if polls > 100 {
                    return false;
                }
            }
        },
    );
    let result = match &outcome {
        super::SlotShutdown::Normal(r) if r.shutdown == ShutdownOutcome::Complete => {
            if vwc && (r.flushes.is_empty() || r.flushes.iter().any(|(_, x)| x.is_err())) {
                TestResult::Fail("drained shutdown did not flush every namespace")
            } else if polls < 3 {
                TestResult::Fail("shutdown did not wait for the gate holder")
            } else {
                TestResult::Pass
            }
        }
        _ => TestResult::Fail("drained shutdown must be a normal Flush + CC.SHN"),
    };
    if let Err(e) = reinstall_nvme1() {
        return TestResult::Fail(e);
    }
    result
}
kernel_test_in!(
    "drivers/nvme/flush",
    smoke_nvme_shutdown_waits_for_in_flight_io
);

/// A command that never completes within the drain budget does not make the
/// shutdown skip the controller: CC.SHN is still written (no Flush can be
/// queued while the gate is held) and the outcome says so.
fn smoke_nvme_shutdown_forces_shn_when_never_drained() -> TestResult {
    if super::controller_count() < 2 {
        return TestResult::Skip("needs the kernel-test NVMe controllers");
    }
    let Some(slot) = super::slot_of(1) else {
        return TestResult::Fail("nvme1 slot missing");
    };
    let guard = super::acquire(slot);
    let outcome = super::shutdown_slot(slot, 50, &mut |cond, ms| (0..ms).any(|_| cond()));
    drop(guard);
    let result = match outcome {
        super::SlotShutdown::Forced(ShutdownOutcome::Complete) => TestResult::Pass,
        super::SlotShutdown::Forced(_) => TestResult::Fail("forced CC.SHN did not complete"),
        _ => TestResult::Fail("a never-drained controller must get the forced CC.SHN"),
    };
    if let Err(e) = reinstall_nvme1() {
        return TestResult::Fail(e);
    }
    result
}
kernel_test_in!(
    "drivers/nvme/flush",
    smoke_nvme_shutdown_forces_shn_when_never_drained
);

/// An `NvmePm` for nvme1 carrying a freshly claimed device cap — the
/// shape `probe` registers at boot (instance + the function's
/// `BusDeviceCap`), rebuilt here because the boot registration lives in
/// the device-PM registry, not in a handle the smokes can reach.
fn nvme1_pm() -> Option<super::NvmePm> {
    use narf_bus::{bootstrap_registry_authority, claim_device_cap};
    let dev = super::with_controller_at(1, |c| c.bus_device())??;
    let authority = bootstrap_registry_authority();
    let (_h, cap) = claim_device_cap(&authority, dev.addr).ok()?;
    Some(super::NvmePm { instance: 1, cap })
}

/// System suspend/resume round-trip on QEMU's nvme1 (#926, replacing
/// `smoke_nvme_suspend_is_refused`): suspend quiesces and tears the
/// controller down — I/O is refused while it is down, not served by
/// stale queues — resume re-initialises it, and the first command
/// afterwards lands: the block written and flushed before suspend
/// reads back intact on the rebuilt queues, and the datapath (write +
/// Flush) is fully alive again. A rollback resume is a no-op, and a
/// second full cycle works.
fn smoke_nvme_suspend_resume_qemu() -> TestResult {
    use narf_power::device_pm::DevicePmOps;
    if super::controller_count() < 2 {
        return TestResult::Skip("needs the kernel-test NVMe controllers");
    }
    let Some(pm) = nvme1_pm() else {
        return TestResult::Fail("could not claim nvme1's device cap");
    };
    let Some(dev) = narf_block::find_block_device("nvme1n1") else {
        return TestResult::Fail("nvme1n1 not registered");
    };
    // Seed a known block and flush it durable before suspending.
    let lba = 60u64;
    let mut saved = [0u8; 512];
    if dev.read(lba, 1, &mut saved).is_err() {
        return TestResult::Fail("pre-suspend read failed");
    }
    let mut block = [0u8; 512];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xA5;
    }
    if dev.write(lba, 1, &block).is_err() || dev.flush().is_err() {
        return TestResult::Fail("pre-suspend write/flush failed");
    }
    if pm.suspend().is_err() {
        return TestResult::Fail("NVMe suspend failed on a healthy controller");
    }
    // While suspended: the state is marked, and I/O is refused.
    let marked = super::with_controller_at(1, |c| c.is_suspended() && c.is_dead());
    let mut probe = [0u8; 512];
    let refused = dev.read(lba, 1, &mut probe).is_err();
    let resume = pm.resume();
    if marked != Some(true) {
        let _ = dev.write(lba, 1, &saved);
        return TestResult::Fail("controller not marked suspended after suspend");
    }
    if !refused {
        let _ = dev.write(lba, 1, &saved);
        return TestResult::Fail("a suspended controller served I/O");
    }
    if resume.is_err() {
        return TestResult::Fail("NVMe resume failed");
    }
    // The first post-resume command lands: the pre-suspend block reads
    // back intact on the rebuilt queues.
    let mut back = [0u8; 512];
    let landed = dev.read(lba, 1, &mut back).is_ok() && back == block;
    // And the datapath is fully alive again: write + flush + read back.
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i as u8) ^ 0x3C;
    }
    let alive = dev.write(lba, 1, &block).is_ok()
        && dev.flush().is_ok()
        && dev.read(lba, 1, &mut back).is_ok()
        && back == block;
    let _ = dev.write(lba, 1, &saved);
    if !landed {
        return TestResult::Fail("first post-resume read did not return the pre-suspend block");
    }
    if !alive {
        return TestResult::Fail("datapath did not come back after resume");
    }
    // A rollback resume (not suspended) is a no-op success, and
    // suspend is not a one-shot: a second full cycle works.
    if pm.resume().is_err() {
        return TestResult::Fail("resume while not suspended must be a no-op");
    }
    if pm.suspend().is_err() || pm.resume().is_err() {
        return TestResult::Fail("second suspend/resume cycle failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/flush", smoke_nvme_suspend_resume_qemu);

/// Suspend drains the in-flight command before quiescing: with nvme1's
/// request gate held (a command mid-flight), a wait that never sees
/// the gate free reports Busy and touches nothing; a wait that sees it
/// released after a few polls suspends normally (Flush + CC.SHN), and
/// resume rebuilds the controller.
fn smoke_nvme_suspend_drains_in_flight_io() -> TestResult {
    if super::controller_count() < 2 {
        return TestResult::Skip("needs the kernel-test NVMe controllers");
    }
    let Some(pm) = nvme1_pm() else {
        return TestResult::Fail("could not claim nvme1's device cap");
    };
    let Some(slot) = super::slot_of(1) else {
        return TestResult::Fail("nvme1 slot missing");
    };
    let vwc = super::with_controller_at(1, |c| c.has_volatile_write_cache()).unwrap_or(false);
    let flushes_before = super::with_controller_at(1, |c| c.flushes_completed()).unwrap_or(0);
    // "In flight": hold the gate the way an I/O path does.
    core::mem::forget(super::acquire(slot));
    // A wait that never observes the gate free: Busy, nothing touched.
    let busy = super::suspend_slot(slot, &pm.cap, 50, &mut |cond, ms| (0..ms).any(|_| cond()));
    if busy != super::SlotSuspend::Busy {
        slot.req_gate
            .store(false, core::sync::atomic::Ordering::Release);
        return TestResult::Fail("a never-drained suspend must report Busy");
    }
    // Inspect the controller directly, NOT through
    // `with_controller_at`: that helper acquires the gate by spinning
    // on it, and this fixture is itself the gate holder (the forgotten
    // `acquire` above) — the helper would spin forever on a hold this
    // fixture only releases in its failure arms or in the second
    // suspend's model wait, wedging the run.
    // SAFETY: `req_gate` is held by this fixture (the forgotten
    // `acquire` guard), so no other reference into the cell can exist
    // — the same argument `ControllerGuard::deref` makes.
    let untouched = {
        let c = unsafe { &*slot.ctrl.get() };
        c.is_ready() && !c.is_suspended()
    };
    if !untouched {
        slot.req_gate
            .store(false, core::sync::atomic::Ordering::Release);
        return TestResult::Fail("a Busy suspend touched the controller");
    }
    // A wait whose holder releases after a few polls: suspend proceeds.
    let mut polls = 0u32;
    let outcome = super::suspend_slot(
        slot,
        &pm.cap,
        super::SHUTDOWN_DRAIN_TIMEOUT_MS,
        &mut |cond, _budget| {
            loop {
                if cond() {
                    return true;
                }
                polls += 1;
                // The command completes after a few polls.
                if polls == 3 {
                    slot.req_gate
                        .store(false, core::sync::atomic::Ordering::Release);
                }
                if polls > 100 {
                    return false;
                }
            }
        },
    );
    let result = match &outcome {
        super::SlotSuspend::Suspended(ShutdownOutcome::Complete) => {
            let flushes_after =
                super::with_controller_at(1, |c| c.flushes_completed()).unwrap_or(0);
            if polls < 3 {
                TestResult::Fail("suspend did not wait for the gate holder")
            } else if vwc && flushes_after <= flushes_before {
                TestResult::Fail("drained suspend did not flush")
            } else {
                TestResult::Pass
            }
        }
        _ => TestResult::Fail("drained suspend must quiesce with Flush + CC.SHN"),
    };
    // Whatever the outcome the slot is suspended now: resume it and
    // require the controller back before any later smoke runs.
    let resumed = super::resume_slot(
        slot,
        &pm.cap,
        super::SHUTDOWN_DRAIN_TIMEOUT_MS,
        &mut |cond, ms| (0..ms).any(|_| cond()),
    );
    if resumed != super::SlotResume::Resumed {
        return TestResult::Fail("resume after drained suspend failed");
    }
    result
}
kernel_test_in!("drivers/nvme/flush", smoke_nvme_suspend_drains_in_flight_io);

/// The resume identity re-check, model side: the rebuilt controller
/// must be the one that was suspended. A serial, model or
/// namespace-count change — or any change to the registered namespace
/// set — fails the match; a firmware-revision change alone does not
/// (it names no data).
fn smoke_nvme_suspend_identity_match() -> TestResult {
    let mut sn = [b' '; 20];
    sn[..12].copy_from_slice(b"SN1234567890");
    let mut mn = [b' '; 40];
    mn[..7].copy_from_slice(b"Model X");
    let mut fr = [b' '; 8];
    fr[..3].copy_from_slice(b"1.0");
    let id = super::IdentifyController {
        vid: 0x15B7,
        ssvid: 0,
        sn,
        mn,
        fr,
        mdts: 0,
        ver: 0x0001_0400,
        nn: 1,
        rtd3e: 0,
        vwc: 1,
    };
    let ns = super::ns::NamespaceInfo {
        nsid: 1,
        lba_bytes: 512,
        nsze: 1_000_000,
        usable: true,
        ids: super::ns::NsIds {
            eui64: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            nguid: None,
            uuid: None,
        },
    };
    let snap = super::SuspendSnapshot {
        identify: id,
        namespaces: alloc::vec![ns],
    };
    if !super::suspend_identity_matches(&snap, &id, &[ns]) {
        return TestResult::Fail("the identical controller must match its snapshot");
    }
    let mut other = id;
    other.sn[0] = b'X';
    if super::suspend_identity_matches(&snap, &other, &[ns]) {
        return TestResult::Fail("a serial change must fail the identity check");
    }
    let mut other = id;
    other.nn = 2;
    if super::suspend_identity_matches(&snap, &other, &[ns]) {
        return TestResult::Fail("a namespace-count change must fail the identity check");
    }
    let mut resized = ns;
    resized.nsze += 1;
    if super::suspend_identity_matches(&snap, &id, &[resized]) {
        return TestResult::Fail("a namespace size change must fail the identity check");
    }
    if super::suspend_identity_matches(&snap, &id, &[]) {
        return TestResult::Fail("a shrunk namespace set must fail the identity check");
    }
    let mut updated = id;
    updated.fr[0] = b'2';
    if !super::suspend_identity_matches(&snap, &updated, &[ns]) {
        return TestResult::Fail("a firmware-revision change alone must still match");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/flush", smoke_nvme_suspend_identity_match);

/// `NVME_IOCTL_IO_CMD` / `NVME_IOCTL_IO64_CMD` are refused (EOPNOTSUPP at
/// the syscall layer) without reading the command or touching the
/// controller: they used to be run on the ADMIN queue, where an I/O opcode
/// names a different command (Write 0x01 = Create I/O SQ).
fn smoke_nvme_io_passthrough_refused() -> TestResult {
    use narf_filesystem::{FileOps, FsError, IoctlContext};
    struct CountCtx {
        reads: core::sync::atomic::AtomicUsize,
    }
    impl IoctlContext for CountCtx {
        fn read(&self, _address: u64, destination: &mut [u8]) -> Result<(), FsError> {
            self.reads
                .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            destination.fill(0);
            Ok(())
        }
        fn write(&self, _address: u64, _source: &[u8]) -> Result<(), FsError> {
            Ok(())
        }
        fn nonblocking(&self) -> bool {
            false
        }
    }
    let ctx = CountCtx {
        reads: core::sync::atomic::AtomicUsize::new(0),
    };
    let dev = super::chardev::NvmeCharDev::new(1);
    for cmd in [
        super::chardev::NVME_IOCTL_IO_CMD,
        super::chardev::NVME_IOCTL_IO64_CMD,
    ] {
        let mut fut = dev.ioctl_user(cmd, 0x1000, &ctx);
        let r = poll_ready(fut.as_mut());
        if !matches!(r, Some(Err(FsError::Unsupported))) {
            return TestResult::Fail("I/O passthrough must be refused");
        }
    }
    if ctx.reads.load(core::sync::atomic::Ordering::Acquire) != 0 {
        return TestResult::Fail("a refused I/O passthrough must not read the command");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/flush", smoke_nvme_io_passthrough_refused);

fn poll_ready<F: core::future::Future + ?Sized>(
    mut fut: core::pin::Pin<&mut F>,
) -> Option<F::Output> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        unsafe fn noop(_: *const ()) {}
        const VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        RawWaker::new(core::ptr::null(), &VT)
    }
    // SAFETY: every vtable entry is a no-op that never reads the data pointer.
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    for _ in 0..16 {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}
