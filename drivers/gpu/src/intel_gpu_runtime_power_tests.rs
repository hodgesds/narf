use super::*;
use alloc::boxed::Box;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU8},
    task::{Context, Waker},
};
use narf_bus::pci::{PciError, PciPowerState};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_power::{
    runtime_pm::{ManualEnv, RpmFuture, RuntimePmOps},
    runtime_pm_pci::{register_with_io, PciPmIo, PciRuntimeNode, PciTarget},
};

const OK: u8 = 0;
const BUSY: u8 = 1;
const FAIL: u8 = 2;
const PENDING: u8 = 3;
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
struct Pci {
    power: IrqSafeSpinLock<PciPowerState>,
    lost: AtomicBool,
    reads: AtomicU32,
    writes: AtomicU32,
    saves: AtomicU32,
    restores: AtomicU32,
    env: Arc<ManualEnv>,
}
impl PciPmIo for Pci {
    fn power_state(&self) -> Result<Option<PciPowerState>, PciError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok((!self.lost.load(Ordering::Acquire)).then(|| *self.power.lock()))
    }
    fn set_power_state(&self, state: PciPowerState) -> Result<(), PciError> {
        if self.lost.load(Ordering::Acquire) {
            return Err(PciError::AuthorityRevoked);
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        *self.power.lock() = state;
        Ok(())
    }
    fn save_state(&self) -> Result<(), PciError> {
        if self.lost.load(Ordering::Acquire) {
            return Err(PciError::AuthorityRevoked);
        }
        self.saves.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn restore_state(&self) -> Result<(), PciError> {
        if self.lost.load(Ordering::Acquire) {
            return Err(PciError::AuthorityRevoked);
        }
        self.restores.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn delay_ms(&self, ms: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.env.advance_ms(ms);
        })
    }
}
struct Driver {
    suspend: AtomicU8,
    resume: AtomicU8,
    live_vram: AtomicBool,
    env: Arc<ManualEnv>,
    cost: AtomicU32,
    dropped: AtomicU32,
}
struct Callback<'a>(&'a AtomicU32);
impl Drop for Callback<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}
impl Driver {
    async fn callback(&self, mode: &AtomicU8) -> Result<(), RpmError> {
        let _callback = Callback(&self.dropped);
        self.env
            .advance_ms(u64::from(self.cost.load(Ordering::Relaxed)));
        match mode.load(Ordering::Acquire) {
            BUSY => Err(RpmError::Busy),
            FAIL => Err(RpmError::Failed),
            PENDING => core::future::pending().await,
            _ => Ok(()),
        }
    }
}
impl RuntimePmOps for Driver {
    fn runtime_suspend(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            if self.live_vram.load(Ordering::Acquire) {
                return Err(RpmError::Busy);
            }
            self.callback(&self.suspend).await
        })
    }
    fn runtime_resume(&self) -> RpmFuture<'_> {
        Box::pin(self.callback(&self.resume))
    }
}
struct Fixture {
    env: Arc<ManualEnv>,
    pci: Arc<Pci>,
    driver: Arc<Driver>,
    node: PciRuntimeNode,
    epoch: Arc<AtomicU64>,
    control: Arc<Control>,
    power: Arc<Kobject>,
}
impl Fixture {
    fn new(auto: bool) -> Self {
        let env = ManualEnv::new();
        let pci = Arc::new(Pci {
            power: IrqSafeSpinLock::new(PciPowerState::D0),
            lost: AtomicBool::new(false),
            reads: AtomicU32::new(0),
            writes: AtomicU32::new(0),
            saves: AtomicU32::new(0),
            restores: AtomicU32::new(0),
            env: env.clone(),
        });
        let driver = Arc::new(Driver {
            suspend: AtomicU8::new(OK),
            resume: AtomicU8::new(OK),
            live_vram: AtomicBool::new(false),
            env: env.clone(),
            cost: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
        });
        let node = register_with_io(
            "intel-pm-policy-fixture",
            pci.clone(),
            driver.clone(),
            None,
            None,
            env.clone(),
        )
        .unwrap();
        let epoch = Arc::new(AtomicU64::new(7));
        let control = Control::register(u32::MAX - 4, node.device.clone(), epoch.clone(), auto);
        control.activate(7);
        if auto {
            run(node.device.set_autosuspend_delay(1000));
            run(node.device.use_autosuspend(true));
            node.device.mark_last_busy();
            node.device.allow();
            node.device.put_autosuspend().unwrap();
            control.autosuspend_ready();
        }
        let parent = Kobject::new_root("intel-pci-function");
        let power = get_or_create_child(&parent, "power");
        let resolved = control.clone();
        populate(&power, move || Some(resolved.clone()));
        Self {
            env,
            pci,
            driver,
            node,
            epoch,
            control,
            power,
        }
    }
    fn current(&self) -> bool {
        self.pci.power_state().is_ok_and(|state| state.is_some())
    }
    fn service(&self) {
        run(self.control.service(|| self.current()));
    }
    fn drain(&self) {
        run(self.env.run_pending());
    }
    fn park(&self) {
        self.env.advance_ms(1000);
        self.drain();
        assert_eq!(self.node.pci.current(), PciTarget::D3Hot);
        assert_eq!(self.node.device.status(), RpmStatus::Suspended);
    }
    fn show(&self, name: &str) -> String {
        self.power.attr_show(name).unwrap()
    }
    fn store(&self, name: &str, value: &[u8]) -> Result<(), FsError> {
        self.power.attr_store(name, value).unwrap()
    }
}
struct Admin(Option<fn(u32) -> bool>);
impl Admin {
    fn new(allow: bool) -> Self {
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            if allow { |cap| cap == 21 } else { |_| false },
        )))
    }
}
impl Drop for Admin {
    fn drop(&mut self) {
        narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}

fn smoke_runtime_power_sysfs_force_on_resumes_and_auto_reparks_real_pci() -> TestResult {
    let _admin = Admin::new(true);
    let f = Fixture::new(true);
    f.park();
    assert_eq!(f.pci.saves.load(Ordering::Relaxed), 1);
    f.env.advance_ms(250);
    let accesses = f.pci.reads.load(Ordering::Relaxed);
    assert_eq!(f.show("runtime_status"), "suspended\n");
    assert_eq!(f.show("runtime_active_time"), "1010\n");
    assert_eq!(f.show("runtime_suspended_time"), "250\n");
    assert_eq!(
        f.pci.reads.load(Ordering::Relaxed),
        accesses,
        "show read PCI/woke GPU"
    );
    let writes = f.pci.writes.load(Ordering::Relaxed);
    f.store("control", b"on\n").unwrap();
    assert_eq!(f.show("runtime_control_status"), "queued 1\n");
    assert_eq!(
        f.show("control"),
        "auto\n",
        "queue pretended policy was applied"
    );
    assert_eq!(f.pci.writes.load(Ordering::Relaxed), writes);
    f.service();
    assert_eq!(f.show("control"), "on\n");
    assert_eq!(f.show("runtime_control_status"), "applied 1\n");
    assert_eq!(f.show("runtime_status"), "active\n");
    assert_eq!(f.show("runtime_active_time"), "1020\n");
    assert_eq!(f.show("runtime_suspended_time"), "250\n");
    assert_eq!(f.node.device.state().usage_count, 1);
    assert_eq!(f.node.pci.current(), PciTarget::D0);
    assert_eq!(f.pci.restores.load(Ordering::Relaxed), 1);
    f.store("control", b"on").unwrap();
    f.service();
    assert_eq!(
        f.node.device.state().usage_count,
        1,
        "duplicate on leaked a PM reference"
    );
    f.env.advance_ms(2000);
    f.drain();
    assert_eq!(f.node.pci.current(), PciTarget::D0);
    f.store("control", b"auto").unwrap();
    f.service();
    f.drain();
    assert_eq!(f.show("control"), "auto\n");
    assert_eq!(f.node.device.state().usage_count, 0);
    assert_eq!(f.node.pci.current(), PciTarget::D3Hot);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_sysfs_force_on_resumes_and_auto_reparks_real_pci
);

fn smoke_runtime_power_signed_delay_reference_and_exact_bounds() -> TestResult {
    let _admin = Admin::new(true);
    let f = Fixture::new(true);
    f.store("autosuspend_delay_ms", b"-1").unwrap();
    f.service();
    assert_eq!(f.show("autosuspend_delay_ms"), "-1\n");
    assert_eq!(f.node.device.state().usage_count, 1);
    f.env.advance_ms(5000);
    f.drain();
    assert_eq!(f.node.pci.current(), PciTarget::D0);
    f.store("autosuspend_delay_ms", b"-2147483648").unwrap();
    f.service();
    assert_eq!(f.node.device.state().usage_count, 1);
    f.store("autosuspend_delay_ms", b"0").unwrap();
    f.service();
    assert_eq!(f.node.device.state().usage_count, 0);
    assert_eq!(f.node.pci.current(), PciTarget::D3Hot);
    f.store("autosuspend_delay_ms", b"2147483647").unwrap();
    f.service();
    assert_eq!(f.show("autosuspend_delay_ms"), "2147483647\n");
    for invalid in [
        &b"2147483648"[..],
        &b"-2147483649"[..],
        &b"1 0"[..],
        &b"nan"[..],
        &b"1\0"[..],
        &b""[..],
        &b"111111111111111111111111111111111"[..],
    ] {
        assert_eq!(
            f.store("autosuspend_delay_ms", invalid),
            Err(FsError::InvalidData)
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_signed_delay_reference_and_exact_bounds
);

fn smoke_runtime_power_current_admin_epoch_and_bounded_mailbox_no_replay() -> TestResult {
    let f = Fixture::new(true);
    let _admin = Admin::new(true);
    {
        let _denied = Admin::new(false);
        assert_eq!(
            f.store("control", b"on"),
            Err(FsError::OperationNotPermitted)
        );
    }
    for invalid in [b"off".as_slice(), b"autoon", b"on\0"] {
        assert_eq!(f.store("control", invalid), Err(FsError::InvalidData));
    }
    f.store("control", b"on").unwrap();
    assert_eq!(f.store("autosuspend_delay_ms", b"0"), Err(FsError::Busy));
    let writes = f.pci.writes.load(Ordering::Relaxed);
    f.epoch.store(0, Ordering::Release);
    assert_eq!(f.store("control", b"on"), Err(FsError::NoDevice));
    assert!(f.show("control").is_empty());
    f.service();
    f.control.activate(8);
    f.epoch.store(8, Ordering::Release);
    f.service();
    assert_eq!(f.show("control"), "auto\n");
    assert_eq!(f.pci.writes.load(Ordering::Relaxed), writes);
    assert_eq!(
        f.node.device.state().usage_count,
        0,
        "old on request replayed"
    );
    f.store("control", b"on").unwrap();
    f.control.activate(9);
    f.epoch.store(9, Ordering::Release);
    f.service();
    assert_eq!(f.show("control"), "auto\n");
    assert_eq!(f.show("runtime_control_status"), "ready\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_current_admin_epoch_and_bounded_mailbox_no_replay
);

fn smoke_runtime_power_loss_closes_pending_and_fresh_epoch_reopens() -> TestResult {
    let _admin = Admin::new(true);
    let f = Fixture::new(true);
    f.park();
    f.store("control", b"on").unwrap();
    let writes = f.pci.writes.load(Ordering::Relaxed);
    f.pci.lost.store(true, Ordering::Release);
    f.service();
    assert_eq!(f.pci.writes.load(Ordering::Relaxed), writes);
    assert!(f.show("runtime_status").is_empty());
    assert_eq!(f.store("control", b"on"), Err(FsError::NoDevice));
    f.pci.lost.store(false, Ordering::Release);
    f.service();
    assert!(
        f.show("control").is_empty(),
        "same epoch reopened known-loss admission"
    );
    f.epoch.store(8, Ordering::Release);
    f.control.activate(8);
    f.store("control", b"on").unwrap();
    f.service();
    assert_eq!(f.show("runtime_status"), "active\n");
    assert_eq!(f.show("control"), "on\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_loss_closes_pending_and_fresh_epoch_reopens
);

fn smoke_runtime_power_panel_refusal_and_live_vram_busy_are_truthful() -> TestResult {
    let _admin = Admin::new(true);
    let panel = Fixture::new(false);
    assert_eq!(panel.store("control", b"auto"), Err(FsError::Unsupported));
    assert_eq!(
        panel.store("autosuspend_delay_ms", b"0"),
        Err(FsError::Unsupported)
    );
    assert!(panel.show("autosuspend_delay_ms").is_empty());
    panel.store("control", b"on").unwrap();
    panel.service();
    assert_eq!(panel.show("runtime_status"), "active\n");
    assert_eq!(panel.node.device.state().usage_count, 2);
    let f = Fixture::new(true);
    f.driver.live_vram.store(true, Ordering::Release);
    f.env.advance_ms(1000);
    f.drain();
    assert_eq!(f.show("control"), "auto\n");
    assert_eq!(f.show("runtime_status"), "active\n");
    assert_eq!(f.node.pci.current(), PciTarget::D0);
    assert_eq!(f.pci.writes.load(Ordering::Relaxed), 0);
    assert!(f.node.device.state().runtime_error.is_none());
    f.driver.live_vram.store(false, Ordering::Release);
    f.store("autosuspend_delay_ms", b"0").unwrap();
    f.service();
    assert_eq!(f.show("runtime_status"), "suspended\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_panel_refusal_and_live_vram_busy_are_truthful
);

fn smoke_runtime_power_failed_and_cancelled_resume_retains_force_on() -> TestResult {
    let _admin = Admin::new(true);
    for mode in [FAIL, PENDING] {
        let f = Fixture::new(true);
        f.park();
        f.driver.resume.store(mode, Ordering::Release);
        f.store("control", b"on").unwrap();
        if mode == FAIL {
            f.service();
            assert_eq!(f.show("runtime_control_status"), "failed 1 Failed\n");
        } else {
            let mut operation = Box::pin(f.control.service(|| f.current()));
            assert!(operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            assert_eq!(f.show("runtime_status"), "resuming\n");
            assert_eq!(f.show("runtime_control_status"), "applying 1\n");
            drop(operation);
            assert_eq!(f.show("runtime_control_status"), "failed 1 Cancelled\n");
        }
        assert_eq!(f.show("runtime_status"), "error\n");
        assert_eq!(f.show("control"), "on\n");
        assert_eq!(
            f.node.device.state().usage_count,
            1,
            "failed resume released forbid hold"
        );
        assert_eq!(f.node.device.state().resumes, 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_failed_and_cancelled_resume_retains_force_on
);

fn smoke_runtime_power_existing_generic_projection_owner_is_preserved() -> TestResult {
    let f = Fixture::new(true);
    let existing = Kobject::new_root("generic-power");
    kobject_add_attr(&existing, "control", || String::from("generic-owner\n"));
    let control = f.control.clone();
    populate(&existing, move || Some(control.clone()));
    assert_eq!(existing.attr_show("control").unwrap(), "generic-owner\n");
    assert!(!existing.has_attr("runtime_control_status"));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_existing_generic_projection_owner_is_preserved
);

fn smoke_runtime_power_accounting_transition_failures_disable_and_reset() -> TestResult {
    let f = Fixture::new(true);
    f.env.advance_ms(100);
    assert_eq!(f.node.device.state().active_time_ns, 100_000_000);
    run(f.node.device.disable());
    f.env.advance_ms(500);
    f.node.device.set_suspended().unwrap();
    let disabled = f.node.device.state();
    assert_eq!(
        (disabled.active_time_ns, disabled.suspended_time_ns),
        (100_000_000, 0)
    );
    f.node.device.enable();
    f.env.advance_ms(50);
    assert_eq!(f.node.device.state().suspended_time_ns, 50_000_000);
    f.driver.cost.store(7, Ordering::Relaxed);
    f.driver.resume.store(FAIL, Ordering::Release);
    assert_eq!(run(f.node.device.forbid()), Err(RpmError::Failed));
    assert_eq!(f.node.device.state().active_time_ns, 107_000_000);
    f.env.advance_ms(20);
    assert_eq!(f.node.device.state().suspended_time_ns, 70_000_000);
    run(f.node.device.disable());
    f.env.advance_ms(30);
    f.node.device.set_active().unwrap();
    f.node.device.enable();
    assert!(f.node.device.state().runtime_error.is_none());
    f.env.advance_ms(10);
    let recovered = f.node.device.state();
    assert_eq!(
        (recovered.active_time_ns, recovered.suspended_time_ns),
        (117_000_000, 70_000_000)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_accounting_transition_failures_disable_and_reset
);

fn smoke_runtime_power_cancel_disable_drops_callback_and_stale_work_cannot_resume() -> TestResult {
    let _admin = Admin::new(true);
    let f = Fixture::new(true);
    f.park();
    f.driver.resume.store(PENDING, Ordering::Release);
    f.store("control", b"on").unwrap();
    let dropped = f.driver.dropped.load(Ordering::Acquire);
    let mut operation = Box::pin(f.control.service(|| f.current()));
    assert!(operation
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    f.env.advance_ms(25);
    drop(operation);
    assert_eq!(f.driver.dropped.load(Ordering::Acquire), dropped + 1);
    assert_eq!(
        f.node.device.state().runtime_error,
        Some(RpmError::Cancelled)
    );
    assert_eq!(f.node.device.state().active_time_ns, 1_045_000_000);
    // A cancelled transition no longer has any pollable callback. Disabling
    // its accounting/admission must complete instead of spinning forever.
    run(f.node.device.disable());
    assert_eq!(f.node.device.state().disable_depth, 1);
    f.env.advance_ms(100);
    let frozen = f.node.device.state();
    assert_eq!(frozen.active_time_ns, 1_045_000_000);
    f.driver.resume.store(OK, Ordering::Release);
    // The model's driver is gone and PCI D0 is explicitly verified before
    // restoring core status; disable alone supplies no hardware-state proof.
    assert_eq!(f.pci.power_state(), Ok(Some(PciPowerState::D0)));
    f.node.device.set_active().unwrap();
    f.epoch.store(8, Ordering::Release);
    f.control.activate(8);
    f.node.device.enable();
    let resumes = f.node.device.state().resumes;
    f.drain(); // Old autosuspend timers/work cannot revive the dropped callback.
    assert_eq!(f.node.device.state().resumes, resumes);
    assert_eq!(f.node.device.status(), RpmStatus::Active);
    assert_eq!(f.show("runtime_control_status"), "ready\n");
    assert_eq!(f.show("runtime_status"), "active\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_runtime_power_cancel_disable_drops_callback_and_stale_work_cannot_resume
);
