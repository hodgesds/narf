//! Navi48 runtime power management: Linux `amdgpu_drv.c`
//! `amdgpu_pmops_runtime_{idle,suspend,resume}` with
//! `amdgpu_device_detect_runtime_pm_mode` (`amdgpu.runpm`), on the generic
//! `narf_power::runtime_pm` core and its PCI layer.
//!
//! The dGPU registers as amdgpu's probe leaves it: autosuspend after
//! 5000 ms, runtime PM allowed, the probe reference dropped. Every DRM
//! ioctl holds a reference (`amdgpu_drm_ioctl`'s `pm_runtime_get_sync` …
//! `pm_runtime_put_autosuspend`), an open requests a resume, every enabled
//! CRTC holds one (amdgpu_dm's commit tail), and a kernel console drawing
//! into this GPU's VRAM holds one for good (the lit fbcon display that
//! keeps Linux's dGPU awake). With all of them gone the runtime-idle
//! check refuses while any display is lit or, unless `amdgpu.runpm=-2`,
//! any connector is connected; otherwise the card drains its rings,
//! evicts client VRAM, quiesces like S3 and enters BACO (or BAMACO), and
//! the PCI layer saves config state and moves it to D3hot. The next access
//! resumes it: D0, BACO exit, resume post and a fresh owner.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::runtime_pm::{
    RpmActiveRef, RpmEnv, RpmError, RpmFuture, RuntimePmDevice, RuntimePmOps, SchedulerEnv,
};

use crate::amdgpu_navi48_platform as platform;
use crate::amdgpu_smu_navi48::{BACO_SUPPORT, MACO_SUPPORT};

/// `enum amdgpu_runpm_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    None,
    /// ATPX (PowerXpress) dGPU power control.
    Px,
    /// Bus Off, Chip Off through ACPI power resources (`_PR3`).
    Boco,
    /// Bus Active, Chip Off.
    Baco,
    /// BACO with memory also powered off (MACO).
    Bamaco,
}

/// What `amdgpu_device_detect_runtime_pm_mode` sees of the platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    /// `pci_is_thunderbolt_attached || dev_is_removable`.
    pub external: bool,
    /// `amdgpu_device_supports_px`.
    pub px: bool,
    /// `amdgpu_device_supports_boco` (`adev->has_pr3`).
    pub boco: bool,
    /// `amdgpu_passthrough`.
    pub passthrough: bool,
}

/// Linux `amdgpu_device_detect_runtime_pm_mode` for a CHIP_IP_DISCOVERY
/// dGPU (no Vega10/20/Arcturus special cases apply). `support` is
/// `amdgpu_device_supports_baco` (`BACO_SUPPORT | MACO_SUPPORT`).
pub fn detect_mode(runpm: i32, support: u8, platform: Platform) -> Mode {
    if platform.external {
        return Mode::None;
    }
    match runpm {
        2 if support & MACO_SUPPORT != 0 => Mode::Bamaco,
        2 if support == BACO_SUPPORT => Mode::Baco,
        1 if support & BACO_SUPPORT != 0 => Mode::Baco,
        -1 | -2 if platform.px => Mode::Px,
        -1 | -2 if platform.boco => Mode::Boco,
        -1 | -2 if support == 0 || platform.passthrough => Mode::None,
        -1 | -2 if support & MACO_SUPPORT != 0 => Mode::Bamaco,
        -1 | -2 => Mode::Baco,
        _ => Mode::None,
    }
}

/// The `dev_info` line Linux prints for the decision.
pub fn describe(runpm: i32, support: u8, mode: Mode, platform: Platform) -> &'static str {
    match (mode, runpm) {
        (Mode::None, _) if platform.external => {
            "Runtime PM disabled for externally attached device"
        }
        (Mode::None, 0) => "runtime pm is manually disabled",
        (Mode::None, _) => "Runtime PM not available",
        (Mode::Bamaco, 2) => "Forcing BAMACO for runtime pm",
        (Mode::Baco, 2) if support == BACO_SUPPORT => {
            "Requested mode BAMACO not available,fallback to use BACO"
        }
        (Mode::Baco, 1) => "Forcing BACO for runtime pm",
        (Mode::Px, _) => "Using ATPX for runtime pm",
        (Mode::Boco, _) => "Using BOCO for runtime pm",
        (Mode::Bamaco, _) => "Using BAMACO for runtime pm",
        (Mode::Baco, _) => "Using BACO for runtime pm",
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

/// smu_v14_0_2_baco_enter's path for runtime PM: ArmD3 when
/// `smu_cmn_is_audio_func_enabled` (an audio function with its driver
/// enabled, or none at all), else EnterBaco.
pub fn baco_path(mode: Mode, audio_present: bool, audio_bound: bool) -> platform::Baco {
    platform::Baco {
        bamaco: mode == Mode::Bamaco,
        armd3: !audio_present || audio_bound,
    }
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
static WARNED_AUDIO: AtomicBool = AtomicBool::new(false);

/// The HDMI/DP audio function (PCI function 1) as
/// `smu_cmn_is_audio_func_enabled` and PMFW's D-state tracking see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audio {
    Absent,
    /// Present with no driver bound (`!pci_is_enabled`).
    Unbound,
    /// A driver is bound; whether the function is in D3hot now.
    Bound {
        d3: bool,
    },
}

pub(crate) type BoxFuture<'a, T> =
    core::pin::Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;

/// The card operations runtime PM drives: the platform owner on hardware,
/// models in tests.
pub(crate) trait Backend: Send + Sync {
    /// The native display monitor publishes connector state.
    fn native_display_running(&self) -> bool;
    /// Discover board sinks (`None`: no display information).
    fn scan_connected(&self) -> BoxFuture<'_, Option<bool>>;
    fn audio(&self) -> Audio;
    fn suspend(
        &self,
        baco: platform::Baco,
    ) -> BoxFuture<'_, Result<(), crate::amdgpu_navi48_boot::Error>>;
    fn resume(&self) -> BoxFuture<'_, Result<(), crate::amdgpu_navi48_boot::Error>>;
}

struct Hardware {
    pci: narf_bus::BusDevice,
    authority: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
}
impl Backend for Hardware {
    fn native_display_running(&self) -> bool {
        platform::native_display_running()
    }
    fn scan_connected(&self) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async {
            let ports = platform::scan_display().await.ok()?;
            Some(ports.iter().any(|p| p.sink.is_ok()))
        })
    }
    fn audio(&self) -> Audio {
        let Some(audio) = narf_bus::pci::sibling_function(&self.pci, 1) else {
            return Audio::Absent;
        };
        let bound = narf_drivers::bound::snapshot().iter().any(|b| {
            b.kind == narf_drivers::bound::BoundKind::Audio
                && b.pci_vid == Some(audio.id.vendor)
                && b.pci_did == Some(audio.id.device)
        });
        if !bound {
            return Audio::Unbound;
        }
        let d3 = matches!(
            narf_bus::pci::power_state(&self.authority, &audio),
            Ok(Some(narf_bus::pci::PciPowerState::D3Hot))
        );
        Audio::Bound { d3 }
    }
    fn suspend(
        &self,
        baco: platform::Baco,
    ) -> BoxFuture<'_, Result<(), crate::amdgpu_navi48_boot::Error>> {
        // SAFETY: runtime PM proved no display is lit and holds a usage
        // reference for any console on this GPU; registration accepted the
        // S3 contract for every other user.
        Box::pin(async move { unsafe { platform::runtime_suspend(baco) }.await })
    }
    fn resume(&self) -> BoxFuture<'_, Result<(), crate::amdgpu_navi48_boot::Error>> {
        // SAFETY: the card was parked by runtime_suspend.
        Box::pin(async { unsafe { platform::runtime_resume() }.await.map(|_| ()) })
    }
}

/// One registered card: its mode, backend and runtime-PM device.
pub(crate) struct Navi48Pm {
    runpm: i32,
    mode: Mode,
    backend: Box<dyn Backend>,
    device: IrqSafeSpinLock<Option<alloc::sync::Weak<RuntimePmDevice>>>,
}
impl core::fmt::Debug for Navi48Pm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Navi48Pm")
            .field("runpm", &self.runpm)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}
impl Navi48Pm {
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
        // Without the native display monitor nothing publishes connector
        // state; runtime_suspend scans the board sinks instead.
        let connected = self.backend.native_display_running() && CONNECTED.load(Ordering::Acquire);
        check_display(self.runpm, LIT.load(Ordering::Acquire), connected)
    }
}
impl RuntimePmOps for Navi48Pm {
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
    /// amdgpu_pmops_runtime_suspend (BACO/BAMACO).
    fn runtime_suspend(&self) -> RpmFuture<'_> {
        Box::pin(async {
            self.checks()?;
            if self.runpm != -2 && !self.backend.native_display_running() {
                // No display monitor publishes connector state: discover the
                // board sinks now, as amdgpu_dm would have.
                if self.backend.scan_connected().await == Some(true) {
                    return Err(RpmError::Busy);
                }
            }
            let audio = self.backend.audio();
            let baco = baco_path(
                self.mode,
                audio != Audio::Absent,
                matches!(audio, Audio::Bound { .. }),
            );
            if audio == (Audio::Bound { d3: false }) {
                // PMFW enters an ArmD3-armed BACO only once both functions
                // are in D3, and NARF's HD-audio driver keeps its function in
                // D0: the card would never power off, and its resume would
                // need a reset. Refuse instead.
                if !WARNED_AUDIO.swap(true, Ordering::AcqRel) {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi48 runtime suspend waits for the HDMI audio function to reach D3"
                    );
                }
                return Err(RpmError::Busy);
            }
            match self.backend.suspend(baco).await {
                Ok(()) => Ok(()),
                Err(crate::amdgpu_navi48_boot::Error::Busy) => Err(RpmError::Busy),
                Err(_) => Err(RpmError::Failed),
            }
        })
    }
    /// amdgpu_pmops_runtime_resume (BACO/BAMACO); the PCI layer already
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

/// amdgpu probe's runtime-PM setup for the running Navi48: decide the mode
/// (`amdgpu.runpm`), register the PCI function's runtime-PM device and
/// [`configure`] it.
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
    let support = platform::bamaco_support().await;
    // NARF executes no AML, so no _PR3 (BOCO) and no ATPX (PX); no
    // removable/Thunderbolt detection and no passthrough detection.
    let platform_caps = Platform {
        external: false,
        px: false,
        boco: false,
        passthrough: false,
    };
    let mode = detect_mode(runpm, support, platform_caps);
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi48 {} (runpm {runpm}, baco support {support:#x})",
            describe(runpm, support, mode, platform_caps)
        );
    }
    if !matches!(mode, Mode::Baco | Mode::Bamaco) {
        return Some(mode);
    }
    let ops = Navi48Pm::new(runpm, mode, Box::new(Hardware { pci, authority }));
    let env: Arc<dyn RpmEnv> = Arc::new(SchedulerEnv);
    let node = narf_power::runtime_pm_pci::register_pci_device(
        "amdgpu-navi48",
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
        card: crate::amdgpu_navi48_boot::ColdBoot::drm_card(),
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
pub async fn access() -> Result<Option<RpmActiveRef>, crate::amdgpu_navi48_boot::Error> {
    let Some(device) = device() else {
        return Ok(None);
    };
    let (guard, result) = narf_power::runtime_pm::active_auto(&device).await;
    match result {
        Ok(_) => Ok(Some(guard)),
        Err(_) => Err(crate::amdgpu_navi48_boot::Error::Busy),
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_runtime_pm_tests.rs"]
mod tests;

#[cfg(feature = "kernel-test")]
pub(crate) fn __reset_displays_for_test() {
    LIT.store(0, Ordering::Release);
    CONNECTED.store(false, Ordering::Release);
}
