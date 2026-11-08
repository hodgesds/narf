//! Navi22 runtime power management: Linux `amdgpu_drv.c`
//! `amdgpu_pmops_runtime_{idle,suspend,resume}` with
//! `amdgpu_device_detect_runtime_pm_mode` (`amdgpu.runpm`), on the generic
//! `narf_power::runtime_pm` core and its PCI layer.
//!
//! The mechanism is GFXOFF + clock gating, not BACO: Navi22 in NARF has no
//! BACO/BAMACO path, so there is no chip-off state to enter. The dGPU
//! registers as amdgpu's probe leaves it: autosuspend after 5000 ms,
//! runtime PM allowed, the probe reference dropped. Every DRM ioctl holds
//! a reference (`amdgpu_drm_ioctl`'s `pm_runtime_get_sync` …
//! `pm_runtime_put_autosuspend`), an open requests a resume, every enabled
//! CRTC holds one (amdgpu_dm's commit tail), and a kernel console drawing
//! into this GPU's VRAM holds one for good (the lit fbcon display that
//! keeps Linux's dGPU awake). With all of them gone the runtime-idle
//! check refuses while any display is lit or, unless `amdgpu.runpm=-2`,
//! any connector is connected; otherwise the card drains its rings,
//! quiesces like S3 (engines withdrawn, IH disabled) and the PCI layer
//! saves config state and moves it to D3hot. The next access resumes it:
//! D0, then the owner is rebuilt (mode1, as recovery does) and the display
//! relit — IH disable is one-way (`amdgpu_ih_navi22::Ih::disable` leaves
//! the ring quarantined), so there is no lighter resume until an
//! `Ih::enable` lands.
//!
//! GFXOFF is armed by the boot power-saving application, not here: the
//! first application is the only one that can start the GFXOFF controller
//! (a stopped controller stays stopped for the boot), so the fb handoff
//! applies the boot opt-in augmented with GFXOFF when this module's mode
//! is `GfxOff`, and [`register`] only verifies the arming before it
//! registers the PCI device. `amdgpu.rdna2_pg=none` therefore also
//! disables runtime PM: no arming, no device.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::runtime_pm::{
    RpmActiveRef, RpmEnv, RpmError, RpmFuture, RuntimePmDevice, RuntimePmOps, SchedulerEnv,
};

use crate::amdgpu_navi22_platform as platform;

/// `enum amdgpu_runpm_mode`, Navi22 subset: no PX (ATPX), no BOCO
/// (`_PR3`), no BACO/BAMACO — NARF executes no AML and Navi22 in NARF
/// has no BACO path. GFXOFF is the only runtime power state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    None,
    /// GC powered off while the rest of the chip stays in D0.
    GfxOff,
}

/// What `amdgpu_device_detect_runtime_pm_mode` sees of the platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    /// `pci_is_thunderbolt_attached || dev_is_removable`.
    pub external: bool,
    /// `amdgpu_passthrough`.
    pub passthrough: bool,
}

impl Platform {
    /// The platform NARF sees: no removable/Thunderbolt detection, no
    /// passthrough detection, and no AML, so no `_PR3` (BOCO) and no
    /// ATPX (PX).
    pub const fn current() -> Self {
        Self {
            external: false,
            passthrough: false,
        }
    }
}

/// Linux `amdgpu_device_detect_runtime_pm_mode` for a CHIP_IP_DISCOVERY
/// dGPU, Navi22 subset. `gfxoff` is PMFW's running feature mask carrying
/// `FEATURE_GFXOFF` (`platform::gfxoff_available`). `runpm` 1 forces
/// GFXOFF and 2 (Linux's "force BAMACO") forces GFXOFF too: Navi22 has
/// no BAMACO to fall back to.
pub fn detect_mode(runpm: i32, gfxoff: bool, platform: Platform) -> Mode {
    if platform.external {
        return Mode::None;
    }
    match runpm {
        1 | 2 if gfxoff => Mode::GfxOff,
        -1 | -2 if platform.passthrough => Mode::None,
        -1 | -2 if gfxoff => Mode::GfxOff,
        _ => Mode::None,
    }
}

/// The `dev_info` line Linux prints for the decision.
pub fn describe(runpm: i32, gfxoff: bool, mode: Mode, platform: Platform) -> &'static str {
    match (mode, runpm) {
        (Mode::None, _) if platform.external => {
            "Runtime PM disabled for externally attached device"
        }
        (Mode::None, 0) => "runtime pm is manually disabled",
        (Mode::None, _) => "Runtime PM not available",
        (Mode::GfxOff, 1) | (Mode::GfxOff, 2) if gfxoff => "Forcing GFXOFF for runtime pm",
        (Mode::GfxOff, _) => "Using GFXOFF for runtime pm",
    }
}

/// `amdgpu.runpm` (int, default -1).
pub fn parse_runpm(value: Option<&str>) -> i32 {
    value
        .and_then(|v| v.trim().parse::<i32>().ok())
        .unwrap_or(-1)
}

/// `amdgpu_runtime_idle_check_display` (DC enabled, CRTCs present): with
/// `runpm != -2`, any connected connector is busy (the XXX workaround for
/// hotplug while suspended); any active CRTC is busy.
pub fn check_display(runpm: i32, lit: u8, connected: bool) -> Result<(), RpmError> {
    if runpm != -2 && connected {
        return Err(RpmError::Busy);
    }
    if lit != 0 {
        return Err(RpmError::Busy);
    }
    Ok(())
}

/// Linux's errno for a failed `pm_runtime_get_sync` in an ioctl.
pub fn ioctl_error(error: RpmError) -> FsError {
    match error {
        RpmError::Access => FsError::PermissionDenied,
        RpmError::Again => FsError::WouldBlock,
        RpmError::Busy | RpmError::InProgress => FsError::Busy,
        RpmError::Invalid => FsError::InvalidData,
        RpmError::NotPermitted => FsError::OperationNotPermitted,
        RpmError::Failed | RpmError::Cancelled => FsError::NoDevice,
    }
}

/// CRTCs holding a runtime-PM reference, and whether a sink is connected.
static LIT: AtomicU8 = AtomicU8::new(0);
static CONNECTED: AtomicBool = AtomicBool::new(false);

pub(crate) type BoxFuture<'a, T> =
    core::pin::Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;

/// The card operations runtime PM drives: the platform owner on hardware,
/// models in tests.
pub(crate) trait Backend: Send + Sync {
    /// The native display stack is up (so `CONNECTED` is published state).
    fn native_display_running(&self) -> bool;
    /// Discover board sinks (`None`: no display information).
    fn scan_connected(&self) -> BoxFuture<'_, Option<bool>>;
    fn suspend(&self) -> BoxFuture<'_, Result<(), crate::amdgpu_navi22_boot::Error>>;
    fn resume(&self) -> BoxFuture<'_, Result<(), crate::amdgpu_navi22_boot::Error>>;
}

/// Backend over the Navi22 platform. Unlike the Navi48 backend, this
/// holds no PCI pair: GFXOFF is GC-scoped, so there is no audio sibling
/// to gate, and the PCI device/authority live in `register()` where the
/// runtime-PM layer takes them.
struct Hardware;
impl Backend for Hardware {
    fn native_display_running(&self) -> bool {
        platform::native_display_running()
    }
    fn scan_connected(&self) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async { platform::scan_connected().await })
    }
    fn suspend(&self) -> BoxFuture<'_, Result<(), crate::amdgpu_navi22_boot::Error>> {
        // SAFETY: runtime PM proved no display is lit and holds a usage
        // reference for any console on this GPU; registration accepted the
        // S3 contract for every other user.
        Box::pin(async move { unsafe { platform::runtime_suspend() }.await })
    }
    fn resume(&self) -> BoxFuture<'_, Result<(), crate::amdgpu_navi22_boot::Error>> {
        // SAFETY: the card was parked by runtime_suspend.
        Box::pin(async { unsafe { platform::runtime_resume() }.await.map(|_| ()) })
    }
}

/// One registered card: its mode, backend and runtime-PM device.
pub(crate) struct Navi22Pm {
    runpm: i32,
    mode: Mode,
    backend: Box<dyn Backend>,
    device: IrqSafeSpinLock<Option<alloc::sync::Weak<RuntimePmDevice>>>,
}
impl core::fmt::Debug for Navi22Pm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Navi22Pm")
            .field("runpm", &self.runpm)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}
impl Navi22Pm {
    pub(crate) fn new(runpm: i32, mode: Mode, backend: Box<dyn Backend>) -> Arc<Self> {
        Arc::new(Self {
            runpm,
            mode,
            backend,
            device: IrqSafeSpinLock::new(None),
        })
    }
    pub(crate) fn attach(&self, device: &Arc<RuntimePmDevice>) {
        *self.device.lock() = Some(Arc::downgrade(device));
    }
    fn device(&self) -> Option<Arc<RuntimePmDevice>> {
        self.device
            .lock()
            .as_ref()
            .and_then(alloc::sync::Weak::upgrade)
    }
    /// amdgpu_pmops_runtime_checks: RUNPM_NONE refuses;
    /// `amdgpu_runtime_idle_check_display` against the published outputs;
    /// `amdgpu_runtime_idle_check_userq` has nothing to check (no user
    /// queues).
    fn checks(&self) -> Result<(), RpmError> {
        if self.mode == Mode::None {
            return Err(RpmError::Busy);
        }
        // Without the native display stack nothing publishes connector
        // state; runtime_suspend scans the board sinks instead.
        let connected = self.backend.native_display_running() && CONNECTED.load(Ordering::Acquire);
        check_display(self.runpm, LIT.load(Ordering::Acquire), connected)
    }
}
impl RuntimePmOps for Navi22Pm {
    /// amdgpu_pmops_runtime_idle: checks, then pm_runtime_autosuspend.
    fn runtime_idle(&self) -> RpmFuture<'_> {
        Box::pin(async {
            let checks = self.checks();
            if let Some(device) = self.device() {
                let _ = device.autosuspend().await;
            }
            checks
        })
    }
    /// amdgpu_pmops_runtime_suspend (GFXOFF + D3hot via the PCI layer).
    fn runtime_suspend(&self) -> RpmFuture<'_> {
        Box::pin(async {
            self.checks()?;
            if self.runpm != -2 && !self.backend.native_display_running() {
                // No display stack publishes connector state: discover the
                // board sinks now, as amdgpu_dm would have.
                if self.backend.scan_connected().await == Some(true) {
                    return Err(RpmError::Busy);
                }
            }
            match self.backend.suspend().await {
                Ok(()) => Ok(()),
                Err(crate::amdgpu_navi22_boot::Error::Busy) => Err(RpmError::Busy),
                Err(_) => Err(RpmError::Failed),
            }
        })
    }
    /// amdgpu_pmops_runtime_resume (GFXOFF + D3hot); the PCI layer already
    /// restored D0 and the config header and refused a vanished function.
    fn runtime_resume(&self) -> RpmFuture<'_> {
        Box::pin(async { self.backend.resume().await.map_err(|_| RpmError::Failed) })
    }
}

#[derive(Debug)]
struct Registered {
    device: Arc<RuntimePmDevice>,
    card: Option<u32>,
    mode: Mode,
}
static REGISTERED: IrqSafeSpinLock<Option<Arc<Registered>>> = IrqSafeSpinLock::new(None);

fn registered() -> Option<Arc<Registered>> {
    REGISTERED.lock().clone()
}
/// The runtime-PM device, once registered.
pub fn device() -> Option<Arc<RuntimePmDevice>> {
    registered().map(|r| r.device.clone())
}
/// The selected `AMDGPU_RUNPM_*` mode (None before registration).
pub fn mode() -> Option<Mode> {
    registered().map(|r| r.mode)
}

/// The delta [`displays_changed`] computed: references to take and drop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayDelta {
    pub get: u32,
    pub put: u32,
}
/// Record the lit CRTC mask and connector presence the native display path
/// just published; called in publication order.
///
/// No KMS commit hook calls this yet: the native display stack lights
/// pipes without publishing lit/connected state, so `LIT`/`CONNECTED`
/// stay 0/false and the scan fallback in [`RuntimePmOps::runtime_suspend`]
/// is the operative check until that wiring lands.
pub fn displays_changed(lit: u8, connected: bool) -> DisplayDelta {
    CONNECTED.store(connected, Ordering::Release);
    let old = LIT.swap(lit, Ordering::AcqRel);
    DisplayDelta {
        get: (lit & !old).count_ones(),
        put: (old & !lit).count_ones(),
    }
}
/// Take `pm_runtime_get_noresume` for newly enabled CRTCs and
/// `pm_runtime_put_autosuspend` for disabled ones (no lock held).
pub fn apply_display_refs(delta: DisplayDelta) {
    if let Some(device) = device() {
        apply_refs(&device, delta);
    }
}
pub(crate) fn apply_refs(device: &Arc<RuntimePmDevice>, delta: DisplayDelta) {
    for _ in 0..delta.get {
        device.get_noresume();
    }
    for _ in 0..delta.put {
        let _ = device.put_autosuspend();
    }
    if delta.get == 0 && delta.put == 0 {
        // A connector change alone (no CRTC enabled or disabled): queue an
        // autosuspend so an unplug lets an idle card power down.
        let _ = device.request_autosuspend();
    }
}

/// amdgpu probe's runtime-PM configuration of a registered device: hold
/// the console's reference when a kernel console draws into this GPU's
/// VRAM and one per lit CRTC, then `use_autosuspend`, a 5000 ms delay,
/// `pm_runtime_allow` and `pm_runtime_put_autosuspend` (dropping the probe
/// reference).
pub(crate) async fn configure(device: &Arc<RuntimePmDevice>, console_on_gpu: bool) {
    if console_on_gpu {
        // fbcon keeps its display lit, so Linux's runtime-idle check never
        // passes: hold the device active for the console's lifetime.
        device.get_noresume();
    }
    for _ in 0..LIT.load(Ordering::Acquire).count_ones() {
        device.get_noresume();
    }
    device.use_autosuspend(true).await;
    device.set_autosuspend_delay(AUTOSUSPEND_MS).await;
    device.allow();
    let _ = device.put_autosuspend();
}
/// amdgpu_pci_probe's pm_runtime_set_autosuspend_delay.
pub const AUTOSUSPEND_MS: i32 = 5000;

/// amdgpu probe's runtime-PM setup for the running Navi22: decide the mode
/// (`amdgpu.runpm`), verify the fb handoff armed GFXOFF through the boot
/// power-saving application, register the PCI function's runtime-PM device
/// and [`configure`] it.
///
/// # Safety
/// The caller accepts `platform::prepare_suspend`'s contract for every user
/// (as `register_system_pm`), and `console_on_gpu` is true whenever any
/// kernel CPU writer can draw into this GPU's VRAM.
pub async unsafe fn register(runpm: i32, console_on_gpu: bool) -> Option<Mode> {
    if registered().is_some() {
        return mode();
    }
    let (pci, authority) = platform::pci_function().await?;
    let gfxoff = platform::gfxoff_available().await;
    let platform_caps = Platform::current();
    let mode = detect_mode(runpm, gfxoff, platform_caps);
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 {} (runpm {runpm}, gfxoff {gfxoff})",
            describe(runpm, gfxoff, mode, platform_caps)
        );
    }
    if mode != Mode::GfxOff {
        return Some(mode);
    }
    if !platform::gfxoff_armed().await {
        // The boot application did not admit GFXOFF (admission refused, or
        // `amdgpu.rdna2_pg=none`): there is nothing to gate, so runtime PM
        // stays off rather than parking a card it cannot power down.
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 runtime PM unavailable: GFXOFF was not armed by the boot power-saving application"
        );
        return Some(Mode::None);
    }
    let ops = Navi22Pm::new(runpm, mode, Box::new(Hardware));
    let env: Arc<dyn RpmEnv> = Arc::new(SchedulerEnv);
    let node = narf_power::runtime_pm_pci::register_pci_device(
        "amdgpu-navi22",
        authority,
        pci,
        ops.clone(),
        None,
        env,
    )
    .ok()?;
    ops.attach(&node.device);
    *REGISTERED.lock() = Some(Arc::new(Registered {
        device: node.device.clone(),
        card: crate::amdgpu_navi22_cs::drm_card(),
        mode,
    }));
    configure(&node.device, console_on_gpu).await;
    Some(mode)
}

/// `amdgpu_drm_ioctl`'s `pm_runtime_get_sync`: the returned guard puts with
/// autosuspend when the ioctl finishes. `Ok(None)` for other cards.
pub async fn ioctl_enter(card: u32) -> Result<Option<RpmActiveRef>, FsError> {
    let Some(r) = registered().filter(|r| r.card == Some(card)) else {
        return Ok(None);
    };
    let (guard, result) = narf_power::runtime_pm::active_auto(&r.device).await;
    match result {
        Ok(_) => Ok(Some(guard)),
        // The guard's drop is the `out:` put of amdgpu_drm_ioctl.
        Err(error) => Err(ioctl_error(error)),
    }
}

/// `amdgpu_driver_open_kms`'s resume for a synchronous devfs open: queue
/// the resume and let autosuspend follow (the first ioctl waits for it).
pub fn on_open(card: u32) {
    if let Some(r) = registered().filter(|r| r.card == Some(card)) {
        let _ = r.device.get();
        let _ = r.device.put_autosuspend();
    }
}

/// device_prepare for S3: hold a reference and resume a runtime-suspended
/// card before the system-PM prepare.
pub async fn system_prepare() {
    if let Some(device) = device() {
        let _ = device.get_sync().await;
    }
}
/// device_complete: drop the S3 reference.
pub fn system_complete() {
    if let Some(device) = device() {
        let _ = device.put_autosuspend();
    }
}

/// `amdgpu_pm_get_access` for a power-management write (hwmon power cap,
/// performance level): resume for the access; the guard autosuspends.
pub async fn access() -> Result<Option<RpmActiveRef>, crate::amdgpu_navi22_boot::Error> {
    let Some(device) = device() else {
        return Ok(None);
    };
    let (guard, result) = narf_power::runtime_pm::active_auto(&device).await;
    match result {
        Ok(_) => Ok(Some(guard)),
        Err(_) => Err(crate::amdgpu_navi22_boot::Error::Busy),
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_runtime_pm_tests.rs"]
mod tests;

#[cfg(feature = "kernel-test")]
pub(crate) fn __reset_displays_for_test() {
    LIT.store(0, Ordering::Release);
    CONNECTED.store(false, Ordering::Release);
}
