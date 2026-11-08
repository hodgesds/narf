//! Navi22 runtime-PM policy over the generic core with a fake clock: mode
//! selection (amdgpu_device_detect_runtime_pm_mode), autosuspend timing,
//! resume on ioctl, the display/console refusals and failures during each
//! transition. Card and PCI function are models. There is no audio gate:
//! GFXOFF is GC-scoped and the HDMI/DP audio function is not in the GC
//! power domain.

use super::*;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU8;
use narf_bus::pci::{PciError, PciPowerState};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_power::runtime_pm::{ManualEnv, RpmOk, RpmStatus};
use narf_power::runtime_pm_pci::{register_with_io, PciPmIo};

fn run<T>(f: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
type Log = Arc<IrqSafeSpinLock<Vec<String>>>;
fn push(log: &Log, s: &str) {
    log.lock().push(String::from(s));
}
fn taken(log: &Log) -> Vec<String> {
    core::mem::take(&mut *log.lock())
}

const OK: u8 = 0;
const BUSY: u8 = 1;
const FAIL: u8 = 2;
fn result(mode: &AtomicU8) -> Result<(), crate::amdgpu_navi22_boot::Error> {
    match mode.load(Ordering::Acquire) {
        BUSY => Err(crate::amdgpu_navi22_boot::Error::Busy),
        FAIL => Err(crate::amdgpu_navi22_boot::Error::Invalid),
        _ => Ok(()),
    }
}

struct Card {
    log: Log,
    suspend: AtomicU8,
    resume: AtomicU8,
    native: AtomicBool,
    scan: IrqSafeSpinLock<Option<bool>>,
}
struct Model(Arc<Card>);
impl Backend for Model {
    fn native_display_running(&self) -> bool {
        self.0.native.load(Ordering::Acquire)
    }
    fn scan_connected(&self) -> BoxFuture<'_, Option<bool>> {
        push(&self.0.log, "scan");
        let scan = *self.0.scan.lock();
        Box::pin(async move { scan })
    }
    fn suspend(&self) -> BoxFuture<'_, Result<(), crate::amdgpu_navi22_boot::Error>> {
        push(&self.0.log, "card:suspend gfxoff");
        let r = result(&self.0.suspend);
        Box::pin(async move { r })
    }
    fn resume(&self) -> BoxFuture<'_, Result<(), crate::amdgpu_navi22_boot::Error>> {
        push(&self.0.log, "card:resume");
        let r = result(&self.0.resume);
        Box::pin(async move { r })
    }
}

struct Function {
    log: Log,
    state: IrqSafeSpinLock<Option<PciPowerState>>,
    vanish: AtomicBool,
}
impl PciPmIo for Function {
    fn power_state(&self) -> Result<Option<PciPowerState>, PciError> {
        Ok(*self.state.lock())
    }
    fn set_power_state(&self, state: PciPowerState) -> Result<(), PciError> {
        push(
            &self.log,
            if state == PciPowerState::D0 {
                "pci:D0"
            } else {
                "pci:D3hot"
            },
        );
        *self.state.lock() = if state != PciPowerState::D0 && self.vanish.load(Ordering::Acquire) {
            None
        } else {
            Some(state)
        };
        Ok(())
    }
    fn save_state(&self) -> Result<(), PciError> {
        push(&self.log, "pci:save");
        Ok(())
    }
    fn restore_state(&self) -> Result<(), PciError> {
        push(&self.log, "pci:restore");
        Ok(())
    }
    fn delay_ms(
        &self,
        _: u64,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

struct Fixture {
    env: Arc<ManualEnv>,
    device: Arc<RuntimePmDevice>,
    ops: Arc<Navi22Pm>,
    card: Arc<Card>,
    function: Arc<Function>,
    log: Log,
}
/// A registered, configured Navi22 (probe reference dropped, autosuspend
/// armed at 5 s) with no display published.
fn fixture(runpm: i32, mode: Mode, console_on_gpu: bool) -> Fixture {
    __reset_displays_for_test();
    let env = ManualEnv::new();
    let log: Log = Arc::new(IrqSafeSpinLock::new(Vec::new()));
    let card = Arc::new(Card {
        log: log.clone(),
        suspend: AtomicU8::new(OK),
        resume: AtomicU8::new(OK),
        native: AtomicBool::new(true),
        scan: IrqSafeSpinLock::new(None),
    });
    let function = Arc::new(Function {
        log: log.clone(),
        state: IrqSafeSpinLock::new(Some(PciPowerState::D0)),
        vanish: AtomicBool::new(false),
    });
    let ops = Navi22Pm::new(runpm, mode, Box::new(Model(card.clone())));
    let env_dyn: Arc<dyn RpmEnv> = env.clone();
    let node =
        register_with_io("navi22", function.clone(), ops.clone(), None, None, env_dyn).unwrap();
    ops.attach(&node.device);
    run(configure(&node.device, console_on_gpu));
    Fixture {
        env,
        device: node.device,
        ops,
        card,
        function,
        log,
    }
}
impl Fixture {
    fn advance(&self, ms: u64) {
        self.env.advance_ms(ms);
        run(self.env.run_pending());
    }
}

fn navi22_runpm_mode_selection_matches_linux() -> TestResult {
    let none = Platform {
        external: false,
        passthrough: false,
    };
    let with = |f: fn(&mut Platform)| {
        let mut p = none;
        f(&mut p);
        p
    };
    for (runpm, gfxoff, platform, want) in [
        (-1, false, none, Mode::None),
        (-1, true, none, Mode::GfxOff),
        (-2, true, none, Mode::GfxOff),
        (0, true, none, Mode::None),
        (1, true, none, Mode::GfxOff),
        (1, false, none, Mode::None),
        (2, true, none, Mode::GfxOff),
        (2, false, none, Mode::None),
        (3, true, none, Mode::None),
        (-3, true, none, Mode::None),
        (-1, true, with(|p| p.external = true), Mode::None),
        (2, true, with(|p| p.external = true), Mode::None),
        (-1, true, with(|p| p.passthrough = true), Mode::None),
        (1, true, with(|p| p.passthrough = true), Mode::GfxOff),
    ] {
        if detect_mode(runpm, gfxoff, platform) != want {
            return TestResult::Fail("amdgpu_device_detect_runtime_pm_mode table");
        }
    }
    if describe(-1, true, Mode::GfxOff, none) != "Using GFXOFF for runtime pm"
        || describe(1, true, Mode::GfxOff, none) != "Forcing GFXOFF for runtime pm"
        || describe(0, true, Mode::None, none) != "runtime pm is manually disabled"
    {
        return TestResult::Fail("runtime PM dev_info text");
    }
    if parse_runpm(None) != -1
        || parse_runpm(Some("2")) != 2
        || parse_runpm(Some(" -2 ")) != -2
        || parse_runpm(Some("auto")) != -1
    {
        return TestResult::Fail("amdgpu.runpm parsing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-runtime-pm",
    navi22_runpm_mode_selection_matches_linux
);

fn navi22_runtime_autosuspend_and_resume_on_ioctl() -> TestResult {
    let f = fixture(-1, Mode::GfxOff, false);
    f.advance(AUTOSUSPEND_MS as u64 - 1);
    if f.device.status() != RpmStatus::Active || !taken(&f.log).is_empty() {
        return TestResult::Fail("suspended before the 5 s autosuspend delay");
    }
    f.advance(1);
    if f.device.status() != RpmStatus::Suspended
        || taken(&f.log) != ["card:suspend gfxoff", "pci:save", "pci:D3hot"]
    {
        return TestResult::Fail("autosuspend: GFXOFF entry, then PCI save and D3hot");
    }
    // An ioctl: amdgpu_drm_ioctl's get_sync resumes; the guard keeps it up.
    let (guard, resumed) = run(narf_power::runtime_pm::active_auto(&f.device));
    if resumed != Ok(RpmOk::Done) || taken(&f.log) != ["pci:D0", "pci:restore", "card:resume"] {
        return TestResult::Fail("resume on ioctl: D0, config restore, then GFXOFF exit");
    }
    f.advance(60_000);
    if f.device.status() != RpmStatus::Active {
        return TestResult::Fail("suspended under an ioctl reference");
    }
    // Leaving the ioctl marks the device busy: 5 s from now, not before.
    drop(guard);
    f.advance(AUTOSUSPEND_MS as u64 - 1);
    if f.device.status() != RpmStatus::Active {
        return TestResult::Fail("put_autosuspend did not restart the delay");
    }
    f.advance(1);
    let st = f.device.state();
    if st.status != RpmStatus::Suspended || st.suspends != 2 || st.resumes != 1 {
        return TestResult::Fail("second autosuspend");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-runtime-pm",
    navi22_runtime_autosuspend_and_resume_on_ioctl
);

fn navi22_runtime_refuses_lit_displays_connectors_and_console() -> TestResult {
    // A lit CRTC holds a reference (amdgpu_dm's commit tail): never idle.
    let f = fixture(-1, Mode::GfxOff, false);
    apply_refs(&f.device, displays_changed(0b10, true));
    f.advance(60_000);
    if f.device.status() != RpmStatus::Active || run(f.ops.runtime_idle()) != Err(RpmError::Busy) {
        return TestResult::Fail("suspended with a lit display");
    }
    // Display off but still connected: refused unless amdgpu.runpm=-2.
    apply_refs(&f.device, displays_changed(0, true));
    f.advance(60_000);
    if f.device.status() != RpmStatus::Active
        || f.device.state().runtime_error.is_some()
        || taken(&f.log).iter().any(|e| e.starts_with("card:suspend"))
    {
        return TestResult::Fail("suspended with a connected display (runpm=-1)");
    }
    apply_refs(&f.device, displays_changed(0, false));
    f.advance(AUTOSUSPEND_MS as u64);
    if f.device.status() != RpmStatus::Suspended {
        return TestResult::Fail("no suspend once the display was unplugged");
    }
    let f = fixture(-2, Mode::GfxOff, false);
    apply_refs(&f.device, displays_changed(0, true));
    f.advance(AUTOSUSPEND_MS as u64);
    if f.device.status() != RpmStatus::Suspended {
        return TestResult::Fail("runpm=-2 must suspend with displays connected but off");
    }
    // Without a native display stack, suspend scans the board sinks.
    let f = fixture(-1, Mode::GfxOff, false);
    f.card.native.store(false, Ordering::Release);
    *f.card.scan.lock() = Some(true);
    f.advance(AUTOSUSPEND_MS as u64);
    if f.device.status() != RpmStatus::Active || taken(&f.log) != ["scan"] {
        return TestResult::Fail("scanned sink did not refuse suspend");
    }
    // The scan is repeated at the next attempt, not cached.
    *f.card.scan.lock() = Some(true);
    let (guard, _) = run(narf_power::runtime_pm::active_auto(&f.device));
    drop(guard);
    f.advance(AUTOSUSPEND_MS as u64);
    if taken(&f.log) != ["scan"] {
        return TestResult::Fail("connector state was not rescanned");
    }
    *f.card.scan.lock() = Some(false);
    let (guard, _) = run(narf_power::runtime_pm::active_auto(&f.device));
    drop(guard);
    f.advance(AUTOSUSPEND_MS as u64);
    if f.device.status() != RpmStatus::Suspended {
        return TestResult::Fail("no sink found but no suspend");
    }
    // A kernel console in this GPU's VRAM holds it for good (fbcon).
    let f = fixture(-1, Mode::GfxOff, true);
    f.advance(3_600_000);
    if f.device.status() != RpmStatus::Active || f.device.state().usage_count != 1 {
        return TestResult::Fail("console on the GPU did not hold it active");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-runtime-pm",
    navi22_runtime_refuses_lit_displays_connectors_and_console
);

fn navi22_runtime_failure_during_each_transition() -> TestResult {
    // Suspend refused (ring drain timeout): transient, running.
    let f = fixture(-1, Mode::GfxOff, false);
    f.card.suspend.store(BUSY, Ordering::Release);
    f.advance(AUTOSUSPEND_MS as u64);
    if f.device.status() != RpmStatus::Active
        || f.device.state().runtime_error.is_some()
        || f.function.state.lock().as_ref() != Some(&PciPowerState::D0)
    {
        return TestResult::Fail("refused suspend must leave the card running in D0");
    }
    // The next access retries after its own delay.
    f.card.suspend.store(OK, Ordering::Release);
    let (guard, _) = run(narf_power::runtime_pm::active_auto(&f.device));
    drop(guard);
    f.advance(AUTOSUSPEND_MS as u64);
    if f.device.status() != RpmStatus::Suspended {
        return TestResult::Fail("suspend not retried after an access");
    }
    // A hard suspend failure (GFXOFF entry refused, card restarted) is sticky.
    let f = fixture(-1, Mode::GfxOff, false);
    f.card.suspend.store(FAIL, Ordering::Release);
    f.advance(AUTOSUSPEND_MS as u64);
    let (guard, r) = run(narf_power::runtime_pm::active_auto(&f.device));
    if f.device.status() != RpmStatus::Active || r.map_err(ioctl_error) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("hard suspend failure");
    }
    drop(guard);
    // A failed resume (owner rebuild) loses the device.
    let f = fixture(-1, Mode::GfxOff, false);
    f.advance(AUTOSUSPEND_MS as u64);
    f.card.resume.store(FAIL, Ordering::Release);
    let (guard, r) = run(narf_power::runtime_pm::active_auto(&f.device));
    if r.map_err(ioctl_error) != Err(FsError::NoDevice) || f.device.status() != RpmStatus::Suspended
    {
        return TestResult::Fail("failed resume must fail the ioctl");
    }
    drop(guard);
    let (_, r) = run(narf_power::runtime_pm::active_auto(&f.device));
    if r != Err(RpmError::Invalid) {
        return TestResult::Fail("lost device resumed again");
    }
    // A function that vanished in D3 never reaches the card resume.
    let f = fixture(-1, Mode::GfxOff, false);
    f.function.vanish.store(true, Ordering::Release);
    f.advance(AUTOSUSPEND_MS as u64);
    let _ = taken(&f.log);
    let (_, r) = run(narf_power::runtime_pm::active_auto(&f.device));
    if r != Err(RpmError::Failed) || taken(&f.log).iter().any(|e| e == "card:resume") {
        return TestResult::Fail("vanished function reached the card resume");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-runtime-pm",
    navi22_runtime_failure_during_each_transition
);
