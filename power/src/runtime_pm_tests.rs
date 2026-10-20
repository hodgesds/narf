//! Runtime-PM core and PCI-layer kernel tests (`power/runtime`). Time is a
//! fake clock ([`ManualEnv`]); nothing waits on wall-clock deadlines.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};

use narf_bus::pci::{PciError, PciPowerState};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::runtime_pm::{
    ManualEnv, RpmEnv, RpmError, RpmFuture, RpmOk, RpmStatus, RuntimePmDevice, RuntimePmOps,
};
use crate::runtime_pm_pci::{register_with_io, PciPlatformPm, PciPmIo, PciTarget};

fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

type Log = Arc<IrqSafeSpinLock<Vec<String>>>;
fn new_log() -> Log {
    Arc::new(IrqSafeSpinLock::new(Vec::new()))
}
fn log(l: &Log, s: &str) {
    l.lock().push(String::from(s));
}
fn taken(l: &Log) -> Vec<String> {
    core::mem::take(&mut *l.lock())
}

const OK: u8 = 0;
const BUSY: u8 = 1;
const FAIL: u8 = 2;
const PEND: u8 = 3;
fn outcome(mode: &AtomicU8) -> Result<(), RpmError> {
    match mode.load(Ordering::Acquire) {
        BUSY => Err(RpmError::Busy),
        FAIL => Err(RpmError::Failed),
        _ => Ok(()),
    }
}

/// Never ready: models a callback whose hardware wait never completes.
struct Forever;
impl Future for Forever {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

struct Ops {
    name: &'static str,
    log: Log,
    suspend: AtomicU8,
    resume: AtomicU8,
    idle: AtomicU8,
}
impl Ops {
    fn new(name: &'static str, log: &Log) -> Arc<Self> {
        Arc::new(Self {
            name,
            log: log.clone(),
            suspend: AtomicU8::new(OK),
            resume: AtomicU8::new(OK),
            idle: AtomicU8::new(OK),
        })
    }
    fn event(&self, what: &str) {
        let mut s = String::from(self.name);
        s.push(':');
        s.push_str(what);
        self.log.lock().push(s);
    }
}
impl RuntimePmOps for Ops {
    fn runtime_suspend(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            self.event("suspend");
            if self.suspend.load(Ordering::Acquire) == PEND {
                Forever.await;
            }
            outcome(&self.suspend)
        })
    }
    fn runtime_resume(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            self.event("resume");
            outcome(&self.resume)
        })
    }
    fn runtime_idle(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            self.event("idle");
            outcome(&self.idle)
        })
    }
}

/// An active, enabled device with the probe reference dropped and runtime
/// PM allowed (no autosuspend unless the test sets it).
fn device(
    name: &'static str,
    log: &Log,
    parent: Option<Arc<RuntimePmDevice>>,
    env: &Arc<ManualEnv>,
) -> (Arc<RuntimePmDevice>, Arc<Ops>) {
    let ops = Ops::new(name, log);
    let env: Arc<dyn RpmEnv> = env.clone();
    let dev = RuntimePmDevice::new(name, Some(ops.clone()), parent, env);
    dev.set_active().unwrap();
    dev.enable();
    (dev, ops)
}

fn runtime_pm_autosuspend_follows_last_busy() -> TestResult {
    let env = ManualEnv::new();
    let l = new_log();
    let (dev, _ops) = device("gpu", &l, None, &env);
    // Configure under a reference (amdgpu's probe holds one), then drop it.
    dev.get_noresume();
    run(dev.set_autosuspend_delay(5000));
    run(dev.use_autosuspend(true));
    if dev.put_autosuspend() != Ok(RpmOk::Queued) {
        return TestResult::Fail("put_autosuspend did not arm the timer");
    }
    run(env.run_pending());
    if dev.status() != RpmStatus::Active || dev.state().timer_expires_ns != 5_000_000_000 {
        return TestResult::Fail("autosuspend did not arm at last_busy + delay");
    }
    // An access at 4.9 s: get_sync on an active device, put_autosuspend.
    env.advance_ms(4900);
    if run(dev.get_sync()) != Ok(RpmOk::Already) || dev.put_autosuspend() != Ok(RpmOk::Queued) {
        return TestResult::Fail("get_sync/put_autosuspend on an active device");
    }
    env.advance_ms(100); // 5.0 s: the first timer fires and re-arms for 9.9 s.
    run(env.run_pending());
    if dev.status() != RpmStatus::Active || dev.state().timer_expires_ns != 9_900_000_000 {
        return TestResult::Fail("mark_last_busy did not postpone the autosuspend");
    }
    env.advance_ms(4899);
    run(env.run_pending());
    if dev.status() != RpmStatus::Active {
        return TestResult::Fail("suspended before the delay expired");
    }
    env.advance_ms(1);
    run(env.run_pending());
    let st = dev.state();
    if st.status != RpmStatus::Suspended || st.suspends != 1 || taken(&l) != ["gpu:suspend"] {
        return TestResult::Fail("did not autosuspend exactly once at the expiry");
    }
    TestResult::Pass
}
kernel_test_in!("power/runtime", runtime_pm_autosuspend_follows_last_busy);

fn runtime_pm_resume_on_access_and_usage_counts() -> TestResult {
    let env = ManualEnv::new();
    let l = new_log();
    let (dev, _ops) = device("gpu", &l, None, &env);
    if run(dev.suspend()) != Ok(RpmOk::Done) || dev.status() != RpmStatus::Suspended {
        return TestResult::Fail("synchronous suspend of an idle device");
    }
    // Two users: the device stays up until both have put.
    if run(dev.get_sync()) != Ok(RpmOk::Done) || run(dev.get_sync()) != Ok(RpmOk::Already) {
        return TestResult::Fail("get_sync did not resume exactly once");
    }
    if dev.put() != Ok(RpmOk::Done) {
        return TestResult::Fail("first put");
    }
    run(env.run_pending());
    if dev.status() != RpmStatus::Active || dev.state().usage_count != 1 {
        return TestResult::Fail("suspended while a user held a reference");
    }
    if run(dev.suspend()) != Err(RpmError::Again) {
        return TestResult::Fail("suspend with a usage reference must be EAGAIN");
    }
    let _ = dev.put();
    run(env.run_pending());
    if dev.status() != RpmStatus::Suspended {
        return TestResult::Fail("last put did not idle-suspend");
    }
    if dev.put() != Err(RpmError::Invalid) || dev.state().usage_count != 0 {
        return TestResult::Fail("usage-count underflow accepted");
    }
    if taken(&l) != ["gpu:suspend", "gpu:resume", "gpu:idle", "gpu:suspend"] {
        return TestResult::Fail("callback order");
    }
    // pm_runtime_get_if_active never wakes.
    if dev.get_if_active() != Ok(false) {
        return TestResult::Fail("get_if_active took a reference on a suspended device");
    }
    // pm_runtime_get: reference plus an asynchronous resume.
    if dev.get() != Ok(RpmOk::Queued) || dev.status() != RpmStatus::Suspended {
        return TestResult::Fail("pm_runtime_get resumed synchronously");
    }
    run(env.run_pending());
    if dev.status() != RpmStatus::Active || dev.get_if_active() != Ok(true) {
        return TestResult::Fail("queued resume did not run");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/runtime",
    runtime_pm_resume_on_access_and_usage_counts
);

fn runtime_pm_parent_child_ordering() -> TestResult {
    let env = ManualEnv::new();
    let l = new_log();
    let (bridge, _) = device("bridge", &l, None, &env);
    let (gpu, _) = device("gpu", &l, Some(bridge.clone()), &env);
    if bridge.state().child_count != 1 {
        return TestResult::Fail("an active child is not counted");
    }
    if run(bridge.suspend()) != Err(RpmError::Busy) {
        return TestResult::Fail("parent suspended under an active child");
    }
    // The child's suspend queues the parent's idle check.
    let _ = run(gpu.suspend());
    run(env.run_pending());
    if gpu.status() != RpmStatus::Suspended || bridge.status() != RpmStatus::Suspended {
        return TestResult::Fail("parent did not follow its last child down");
    }
    // Resuming the child resumes the parent first.
    let _ = run(gpu.get_sync());
    if bridge.status() != RpmStatus::Active || bridge.state().child_count != 1 {
        return TestResult::Fail("parent not active and counting after child resume");
    }
    if taken(&l)
        != [
            "gpu:suspend",
            "bridge:idle",
            "bridge:suspend",
            "bridge:resume",
            "gpu:resume",
        ]
    {
        return TestResult::Fail("child suspends before parent; parent resumes before child");
    }
    // A child that cannot resume its parent fails with EBUSY.
    let _ = gpu.put();
    run(env.run_pending());
    let (bridge2, bops) = device("b2", &l, None, &env);
    let (gpu2, _) = device("g2", &l, Some(bridge2.clone()), &env);
    let _ = run(gpu2.suspend());
    run(env.run_pending());
    bops.resume.store(BUSY, Ordering::Release);
    if run(gpu2.get_sync()) != Err(RpmError::Busy) || gpu2.status() != RpmStatus::Suspended {
        return TestResult::Fail("child resumed under a suspended parent");
    }
    if bridge2.state().usage_count != 0 {
        return TestResult::Fail("failed child resume leaked the parent reference");
    }
    TestResult::Pass
}
kernel_test_in!("power/runtime", runtime_pm_parent_child_ordering);

fn runtime_pm_callback_failures() -> TestResult {
    let env = ManualEnv::new();
    let l = new_log();
    let (dev, ops) = device("gpu", &l, None, &env);
    // runtime_idle refusing: no suspend.
    ops.idle.store(BUSY, Ordering::Release);
    if run(dev.idle()) != Err(RpmError::Busy) || dev.status() != RpmStatus::Active {
        return TestResult::Fail("refusing runtime_idle still suspended");
    }
    ops.idle.store(OK, Ordering::Release);
    // A transient suspend refusal keeps runtime PM usable.
    ops.suspend.store(BUSY, Ordering::Release);
    if run(dev.suspend()) != Err(RpmError::Busy)
        || dev.status() != RpmStatus::Active
        || dev.state().runtime_error.is_some()
    {
        return TestResult::Fail("EBUSY from runtime_suspend must be transient");
    }
    // A hard failure is sticky until the state is re-established.
    ops.suspend.store(FAIL, Ordering::Release);
    if run(dev.suspend()) != Err(RpmError::Failed)
        || dev.state().runtime_error != Some(RpmError::Failed)
        || run(dev.get_sync()) != Err(RpmError::Invalid)
    {
        return TestResult::Fail("hard suspend failure not sticky");
    }
    let _ = dev.put();
    run(dev.disable());
    if dev.set_active().is_err() || dev.state().runtime_error.is_some() {
        return TestResult::Fail("set_active while disabled did not clear the error");
    }
    if run(dev.suspend()) != Err(RpmError::Access) {
        return TestResult::Fail("disabled device suspended");
    }
    dev.enable();
    ops.suspend.store(OK, Ordering::Release);
    let _ = run(dev.suspend());
    // Resume failure: stays suspended with the error recorded.
    ops.resume.store(FAIL, Ordering::Release);
    if run(dev.get_sync()) != Err(RpmError::Failed)
        || dev.status() != RpmStatus::Suspended
        || run(dev.resume()) != Err(RpmError::Invalid)
    {
        return TestResult::Fail("resume failure");
    }
    TestResult::Pass
}
kernel_test_in!("power/runtime", runtime_pm_callback_failures);

fn runtime_pm_forbid_allow_and_cancellation() -> TestResult {
    let env = ManualEnv::new();
    let l = new_log();
    let (dev, ops) = device("gpu", &l, None, &env);
    let _ = run(dev.forbid());
    if run(dev.suspend()) != Err(RpmError::Again) {
        return TestResult::Fail("forbidden device suspended");
    }
    dev.allow();
    run(env.run_pending());
    if dev.status() != RpmStatus::Suspended {
        return TestResult::Fail("allow did not idle-suspend");
    }
    let _ = run(dev.forbid());
    if dev.status() != RpmStatus::Active {
        return TestResult::Fail("forbid did not resume");
    }
    // Cancel a suspend whose callback never completes. allow() queues an
    // idle check that this test never runs.
    dev.allow();
    ops.suspend.store(PEND, Ordering::Release);
    {
        let mut f = core::pin::pin!(dev.suspend());
        if f.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("pending callback completed");
        }
    }
    let st = dev.state();
    if st.runtime_error != Some(RpmError::Cancelled) || st.status != RpmStatus::Suspending {
        return TestResult::Fail("cancelled transition not recorded");
    }
    if run(dev.get_sync()) != Err(RpmError::Invalid) {
        return TestResult::Fail("transition after cancellation must fail");
    }
    TestResult::Pass
}
kernel_test_in!("power/runtime", runtime_pm_forbid_allow_and_cancellation);

/// PCI function model: PMCSR, saved state and the order of operations.
struct PciModel {
    log: Log,
    state: IrqSafeSpinLock<Option<PciPowerState>>,
    gone_after_suspend: AtomicBool,
    fail_save: AtomicBool,
}
impl PciPmIo for PciModel {
    fn power_state(&self) -> Result<Option<PciPowerState>, PciError> {
        Ok(*self.state.lock())
    }
    fn set_power_state(&self, state: PciPowerState) -> Result<(), PciError> {
        log(
            &self.log,
            if state == PciPowerState::D0 {
                "pci:D0"
            } else {
                "pci:D3hot"
            },
        );
        *self.state.lock() =
            if state != PciPowerState::D0 && self.gone_after_suspend.load(Ordering::Acquire) {
                None
            } else {
                Some(state)
            };
        Ok(())
    }
    fn save_state(&self) -> Result<(), PciError> {
        if self.fail_save.load(Ordering::Acquire) {
            return Err(PciError::BadOffset);
        }
        log(&self.log, "pci:save");
        Ok(())
    }
    fn restore_state(&self) -> Result<(), PciError> {
        log(&self.log, "pci:restore");
        Ok(())
    }
    fn delay_ms(&self, ms: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        log(
            &self.log,
            if ms == 10 {
                "pci:delay10"
            } else {
                "pci:delay?"
            },
        );
        Box::pin(async {})
    }
}
struct Platform(Log);
impl PciPlatformPm for Platform {
    fn d3cold_supported(&self) -> bool {
        true
    }
    fn power_off(&self) -> Pin<Box<dyn Future<Output = Result<(), PciError>> + Send + '_>> {
        log(&self.0, "plat:off");
        Box::pin(async { Ok(()) })
    }
    fn power_on(&self) -> Pin<Box<dyn Future<Output = Result<(), PciError>> + Send + '_>> {
        log(&self.0, "plat:on");
        Box::pin(async { Ok(()) })
    }
}

fn runtime_pm_pci_d3_and_state_save() -> TestResult {
    for d3cold in [false, true] {
        let env = ManualEnv::new();
        let l = new_log();
        let model = Arc::new(PciModel {
            log: l.clone(),
            state: IrqSafeSpinLock::new(Some(PciPowerState::D0)),
            gone_after_suspend: AtomicBool::new(false),
            fail_save: AtomicBool::new(false),
        });
        let driver = Ops::new("drv", &l);
        let platform: Option<Arc<dyn PciPlatformPm>> =
            d3cold.then(|| Arc::new(Platform(l.clone())) as Arc<dyn PciPlatformPm>);
        let env_dyn: Arc<dyn RpmEnv> = env.clone();
        let node = register_with_io(
            "gpu",
            model.clone(),
            driver.clone(),
            platform,
            None,
            env_dyn,
        )
        .unwrap();
        // amdgpu probe: allow + put_autosuspend after configuring autosuspend.
        run(node.device.use_autosuspend(true));
        run(node.device.set_autosuspend_delay(5000));
        node.device.allow();
        let _ = node.device.put_autosuspend();
        env.advance_ms(5000);
        run(env.run_pending());
        let want_down: &[&str] = if d3cold {
            &[
                "drv:suspend",
                "pci:save",
                "pci:D3hot",
                "pci:delay10",
                "plat:off",
            ]
        } else {
            &["drv:suspend", "pci:save", "pci:D3hot", "pci:delay10"]
        };
        let target = if d3cold {
            PciTarget::D3Cold
        } else {
            PciTarget::D3Hot
        };
        if taken(&l) != want_down || node.pci.current() != target {
            return TestResult::Fail("pci_pm_runtime_suspend order or target state");
        }
        let _ = run(node.device.get_sync());
        let want_up: &[&str] = if d3cold {
            &[
                "plat:on",
                "pci:D0",
                "pci:delay10",
                "pci:restore",
                "drv:resume",
            ]
        } else {
            &["pci:D0", "pci:delay10", "pci:restore", "drv:resume"]
        };
        if taken(&l) != want_up || node.pci.current() != PciTarget::D0 {
            return TestResult::Fail("pci_pm_runtime_resume order");
        }
    }
    TestResult::Pass
}
kernel_test_in!("power/runtime", runtime_pm_pci_d3_and_state_save);

fn runtime_pm_pci_failures() -> TestResult {
    let env = ManualEnv::new();
    let l = new_log();
    let model = Arc::new(PciModel {
        log: l.clone(),
        state: IrqSafeSpinLock::new(Some(PciPowerState::D0)),
        gone_after_suspend: AtomicBool::new(false),
        fail_save: AtomicBool::new(false),
    });
    let driver = Ops::new("drv", &l);
    let env_dyn: Arc<dyn RpmEnv> = env.clone();
    let node = register_with_io("gpu", model.clone(), driver.clone(), None, None, env_dyn).unwrap();
    node.device.allow();
    node.device.put_noidle();
    // Driver refusal: no state save, no D3.
    driver.suspend.store(BUSY, Ordering::Release);
    if run(node.device.suspend()) != Err(RpmError::Busy)
        || taken(&l) != ["drv:suspend"]
        || node.pci.current() != PciTarget::D0
    {
        return TestResult::Fail("refused driver suspend touched PCI state");
    }
    driver.suspend.store(OK, Ordering::Release);
    // The function vanishing while suspended fails the resume (the
    // device-gone check of amdgpu_pmops_runtime_resume).
    model.gone_after_suspend.store(true, Ordering::Release);
    let _ = run(node.device.suspend());
    let _ = taken(&l);
    if run(node.device.get_sync()) != Err(RpmError::Failed)
        || node.device.status() != RpmStatus::Suspended
        || taken(&l).iter().any(|e| e == "drv:resume")
    {
        return TestResult::Fail("resume of a vanished function reached the driver");
    }
    TestResult::Pass
}
kernel_test_in!("power/runtime", runtime_pm_pci_failures);
