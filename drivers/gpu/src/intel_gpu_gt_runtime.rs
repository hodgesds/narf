//! Per-PCI-function GT startup and scheduling service. No singleton GT BAR or
//! ambient firmware bytes: every instance retains its card, PCI authority,
//! runtime-PM hold, GGTT arena and complete GuCGt graph through stop/reset.

use crate::{
    drm_devfs_bridge::IntelGpuCard,
    intel_gpu_aux::MmioWindow,
    intel_gpu_fence::CompletionFence,
    intel_gpu_gt::GtPlatform,
    intel_gpu_gt_hw::AuthorizedWindow,
    intel_gpu_guc_boot::BootConfig,
    intel_gpu_guc_firmware::GuCFirmware,
    intel_gpu_guc_gt::{GtError, GtState, GuCGt},
    intel_gpu_rcs::{GgttArena, SharedArena},
};
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Read, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_power::runtime_pm::{RpmError, RpmFuture, RuntimePmOps, SchedulerEnv};

type ProductionGt = GuCGt<AuthorizedWindow, SharedArena>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RuntimeError {
    Device,
    Authority,
    Firmware(crate::intel_gpu_guc_firmware::FirmwareError),
    State,
    Configuration,
    Gt(GtError),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Cold,
    Powering,
    Booting,
    Discovering,
    Reloading,
    Ct,
    Probe,
    Defaults,
    PpgttProbe,
    /// Fresh GT is ready; display retirement runs outside the GT mutex.
    DisplayRecovery,
    Running,
    /// Runtime-suspended after a verified idle stop; D3hot is owned by the
    /// PCI runtime-PM layer. Resume restarts from Cold under the same epoch.
    Parked,
    Stopped,
    Failed,
    Cleaning,
}

struct State {
    irq: Option<crate::intel_gpu_gt_irq::GtIrq>,
    irq_tried: bool,
    gt: Option<ProductionGt>,
    firmware: Option<GuCFirmware>,
    probe: Option<Arc<CompletionFence>>,
    probe_result: Option<crate::intel_gpu_exec::PpgttProbeResult>,
    probe_engine: crate::intel_gpu_engine::Engine,
    phase: Phase,
    saved: Option<narf_bus::pci::SavedPciConfig>,
    power_ready: u64,
    recover_after_stop: bool,
    /// User epoch to continue after a runtime resume (clean idle stop only).
    parked_epoch: Option<(u64, crate::intel_gpu_engine::EngineSet, (u8, u8))>,
    /// The SLPC outcome of this GT incarnation has been logged.
    slpc_reported: bool,
    /// Immutable boot choice initially; changed only by a client-free reset
    /// transaction. Clean runtime resume preserves this exact owner policy.
    ccs_mode: Result<u8, RuntimeError>,
}

struct Pending {
    index: u32,
    card: Arc<IntelGpuCard>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: narf_bus::bar::MmioRegion,
    mode: Option<crate::intel_gpu_modeset::Mode>,
}

struct Owner {
    pending: Pending,
    pm: narf_power::runtime_pm_pci::PciRuntimeNode,
    /// Autosuspend has been configured and runtime PM allowed.
    autosuspend: AtomicBool,
    state: Mutex<State>,
    suspended: AtomicBool,
    user_epoch: Arc<AtomicU64>,
    user_version: Arc<AtomicU32>,
    user_engines: Arc<core::sync::atomic::AtomicU8>,
    user_facts: Arc<IrqSafeSpinLock<Option<crate::intel_gpu_user::DeviceFacts>>>,
    power_controls: Arc<crate::intel_gpu_power_controls::PowerControls>,
    hwmon: Option<Arc<crate::intel_gpu_hwmon::Monitor>>,
    ccs_control: Option<Arc<crate::intel_gpu_ccs_control::Control>>,
}

#[derive(Debug)]
struct Backend {
    owner: Weak<Owner>,
    epoch: Arc<AtomicU64>,
    version: Arc<AtomicU32>,
    engines: Arc<core::sync::atomic::AtomicU8>,
    platform: GtPlatform,
    facts: Arc<IrqSafeSpinLock<Option<crate::intel_gpu_user::DeviceFacts>>>,
    power_controls: Arc<crate::intel_gpu_power_controls::PowerControls>,
    ccs_control: Option<Arc<crate::intel_gpu_ccs_control::Control>>,
}

impl crate::intel_gpu_user::UserBackend for Backend {
    fn ccs_control(&self) -> Option<Arc<crate::intel_gpu_ccs_control::Control>> {
        self.ccs_control.clone()
    }
    fn guc_log_snapshot(
        &self,
        buffer: crate::intel_gpu_guc_log::CaptureBuffer,
    ) -> narf_filesystem::FsFuture<'_, crate::intel_gpu_guc_log::Snapshot> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            if buffer.index() != owner.pending.index {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            // Passive diagnostics never resume/reboot an idle or lost GT.
            // This reset/power mutex excludes park/S3 throughout the bounded
            // synchronous copy; each chunk rechecks current D0 and wake.
            let state = owner.state.lock().await;
            let epoch = owner.user_epoch.load(Ordering::Acquire);
            if state.phase != Phase::Running
                || epoch == 0
                || owner.suspended.load(Ordering::Acquire)
            {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            let digest = state
                .firmware
                .as_ref()
                .ok_or(narf_filesystem::FsError::NoDevice)?
                .digest;
            state
                .gt
                .as_ref()
                .ok_or(narf_filesystem::FsError::NoDevice)?
                .snapshot_guc_log(buffer, epoch, narf_time::monotonic_ns(), digest, || {
                    narf_bus::pci::power_state(&owner.pending.cap, &owner.pending.device)
                        == Ok(Some(narf_bus::pci::PciPowerState::D0))
                })
        })
    }
    fn power_controls(&self) -> Option<Arc<crate::intel_gpu_power_controls::PowerControls>> {
        Some(self.power_controls.clone())
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        *self.facts.lock()
    }
    fn engine_cycles(
        &self,
        engine: crate::intel_gpu_engine::Engine,
        clock: i32,
    ) -> narf_filesystem::FsFuture<'_, crate::intel_gpu_timestamp::EngineCycles> {
        Box::pin(async move {
            let owner = self
                .owner
                .upgrade()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let _awake = Awake::take(&owner).await?;
            let mut state = owner.lock_running().await;
            if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
                return Err(narf_filesystem::FsError::NoDevice);
            }
            let gt = state
                .gt
                .as_mut()
                .ok_or(narf_filesystem::FsError::NoDevice)?;
            let result = gt.engine_cycles(engine, clock);
            if gt.state() == GtState::Lost {
                owner.close_controls();
                owner.user_epoch.store(0, Ordering::Release);
            }
            result.map_err(|error| match error {
                GtError::Busy => narf_filesystem::FsError::WouldBlock,
                GtError::State => narf_filesystem::FsError::NoDevice,
                _ => crate::intel_gpu_user::io_error(),
            })
        })
    }
    fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        let epoch = self.epoch.load(Ordering::Acquire);
        let version = self.version.load(Ordering::Relaxed);
        (epoch != 0).then_some(crate::intel_gpu_user::UserStatus {
            epoch,
            platform: self.platform,
            submission_version: ((version >> 16) as u8, (version >> 8) as u8, version as u8),
            engines: crate::intel_gpu_engine::EngineSet::from_bits(
                self.engines.load(Ordering::Acquire),
            ),
        })
    }
    fn submit<'a>(
        &'a self,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
    ) -> narf_filesystem::FsFuture<'a, Arc<CompletionFence>> {
        Box::pin(async move {
            self.submit_request(context, batch, None)
                .await
                .map_err(|error| match error {
                    crate::intel_gpu_user::OutputError::Io(error) => error,
                    crate::intel_gpu_user::OutputError::Install(_) => {
                        crate::intel_gpu_user::io_error()
                    }
                })
        })
    }

    fn submit_with_output<'a>(
        &'a self,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: crate::intel_gpu_user::UserOutput<'a>,
    ) -> crate::intel_gpu_user::OutputFuture<'a> {
        Box::pin(async move { self.submit_request(context, batch, Some(&output)).await })
    }
}

impl Backend {
    async fn submit_request(
        &self,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: Option<&crate::intel_gpu_user::UserOutput<'_>>,
    ) -> Result<Arc<CompletionFence>, crate::intel_gpu_user::OutputError> {
        use crate::intel_gpu_user::OutputError;
        let owner = self
            .owner
            .upgrade()
            .ok_or(narf_filesystem::FsError::NoDevice)?;
        let awake = Awake::take(&owner).await?;
        let mut state = owner.lock_running().await;
        if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
            return Err(narf_filesystem::FsError::NoDevice.into());
        }
        let gt = state
            .gt
            .as_mut()
            .ok_or(narf_filesystem::FsError::NoDevice)?;
        let epoch = gt.user_epoch().ok_or(narf_filesystem::FsError::NoDevice)?;
        context.check_epoch(epoch)?;
        let result = match output {
            Some(output) => {
                gt.submit_user_batch_with_output(narf_time::monotonic_ns(), context, batch, output)
            }
            None => gt.submit_user_batch(narf_time::monotonic_ns(), context, batch),
        };
        if gt.state() == GtState::Lost {
            owner.close_controls();
            owner.user_epoch.store(0, Ordering::Release);
        }
        if let Ok((_, fence)) = &result {
            awake.until(fence.clone());
        }
        result.map(|(_, fence)| fence).map_err(|error| match error {
            GtError::Scheduling(crate::intel_gpu_guc_sched::SchedulingError::Residency(error)) => {
                OutputError::Io(error)
            }
            GtError::Scheduling(crate::intel_gpu_guc_sched::SchedulingError::Output(error)) => {
                OutputError::Install(error)
            }
            GtError::Scheduling(
                crate::intel_gpu_guc_sched::SchedulingError::Busy
                | crate::intel_gpu_guc_sched::SchedulingError::Full,
            ) => OutputError::Io(narf_filesystem::FsError::WouldBlock),
            _ => OutputError::Io(crate::intel_gpu_user::io_error()),
        })
    }
}

/// Runtime-PM callbacks, bound to the owner once it exists. Until then (and
/// after the owner is gone) suspension is refused and resume is a no-op.
struct PmOps(IrqSafeSpinLock<Weak<Owner>>);
impl RuntimePmOps for PmOps {
    fn runtime_suspend(&self) -> RpmFuture<'_> {
        let owner = self.0.lock().upgrade();
        Box::pin(async move {
            match owner {
                Some(owner) => owner.park().await,
                None => Err(RpmError::Busy),
            }
        })
    }
    fn runtime_resume(&self) -> RpmFuture<'_> {
        let owner = self.0.lock().upgrade();
        Box::pin(async move {
            if let Some(owner) = owner {
                owner.unpark().await;
            }
            Ok(())
        })
    }
}

/// Linux xe's default autosuspend delay.
const AUTOSUSPEND_MS: i32 = 1000;

/// A runtime-PM usage reference: the function stays in D0 until it drops.
struct Awake(Arc<narf_power::runtime_pm::RuntimePmDevice>);
impl Awake {
    async fn take(owner: &Owner) -> Result<Self, narf_filesystem::FsError> {
        let device = owner.pm.device.clone();
        if device.resume_and_get().await.is_err() {
            let _ = device.put_autosuspend();
            return Err(narf_filesystem::FsError::NoDevice);
        }
        Ok(Self(device))
    }
    /// Release when `fence` reaches a terminal state, not at ioctl return.
    fn until(self, fence: Arc<CompletionFence>) {
        narf_scheduler::spawn(async move {
            let _ = fence.wait().await;
            drop(self);
        });
    }
}
impl Drop for Awake {
    fn drop(&mut self) {
        self.0.mark_last_busy();
        let _ = self.0.put_autosuspend();
    }
}

static PENDING: IrqSafeSpinLock<Vec<Pending>> = IrqSafeSpinLock::new(Vec::new());
static OWNERS: IrqSafeSpinLock<Vec<Arc<Owner>>> = IrqSafeSpinLock::new(Vec::new());

/// Probe installs only identity and authority. Late spawns survive executor
/// startup; firmware scanning completes before these tasks start polling.
pub(crate) fn install(
    index: u32,
    card: Arc<IntelGpuCard>,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    bar: narf_bus::bar::MmioRegion,
    mode: Option<crate::intel_gpu_modeset::Mode>,
) {
    if GtPlatform::from_pci(device.id.vendor, device.id.device)
        .and_then(GtPlatform::guc)
        .is_none()
    {
        return;
    }
    PENDING.lock().push(Pending {
        index,
        card,
        device,
        cap,
        bar,
        mode,
    });
}

pub(crate) fn start_pending() {
    let pending = core::mem::take(&mut *PENDING.lock());
    for p in pending {
        let name = alloc::format!("intel-gt-{}", p.index);
        let ops = Arc::new(PmOps(IrqSafeSpinLock::new(Weak::new())));
        // The probe and forbid references keep the function in D0 until a
        // running, eligible GT explicitly allows autosuspend.
        let pm = match narf_power::runtime_pm_pci::register_pci_device(
            &name,
            p.cap,
            p.device,
            ops.clone(),
            None,
            Arc::new(SchedulerEnv),
        ) {
            Ok(node) => node,
            Err(_) => {
                log(p.index, "runtime-PM registration failed; GT not started");
                continue;
            }
        };
        let hwmon = crate::intel_gpu_hwmon::Monitor::register(
            p.index,
            GtPlatform::from_pci(p.device.id.vendor, p.device.id.device)
                .expect("admitted platform"),
        );
        let ccs_control = crate::intel_gpu_ccs_control::Control::new(p.index);
        let owner = Arc::new(Owner {
            pending: p,
            pm,
            autosuspend: AtomicBool::new(false),
            state: Mutex::new(State {
                irq: None,
                irq_tried: false,
                gt: None,
                firmware: None,
                probe: None,
                probe_result: None,
                probe_engine: crate::intel_gpu_engine::Engine::Rcs0,
                phase: Phase::Cold,
                saved: None,
                power_ready: 0,
                recover_after_stop: false,
                parked_epoch: None,
                slpc_reported: false,
                ccs_mode: ccs_boot_mode(narf_boot::args()),
            }),
            suspended: AtomicBool::new(false),
            user_epoch: Arc::new(AtomicU64::new(0)),
            user_version: Arc::new(AtomicU32::new(0)),
            user_engines: Arc::new(core::sync::atomic::AtomicU8::new(0)),
            user_facts: Arc::new(IrqSafeSpinLock::new(None)),
            power_controls: Arc::new(crate::intel_gpu_power_controls::PowerControls::new()),
            hwmon,
            ccs_control,
        });
        *ops.0.lock() = Arc::downgrade(&owner);
        let backend = Arc::new(Backend {
            owner: Arc::downgrade(&owner),
            epoch: owner.user_epoch.clone(),
            version: owner.user_version.clone(),
            engines: owner.user_engines.clone(),
            platform: GtPlatform::from_pci(
                owner.pending.device.id.vendor,
                owner.pending.device.id.device,
            )
            .expect("admitted platform"),
            facts: owner.user_facts.clone(),
            power_controls: owner.power_controls.clone(),
            ccs_control: owner.ccs_control.clone(),
        });
        if owner.pending.card.install_user_backend(backend).is_err() {
            log(
                owner.pending.index,
                "duplicate userspace backend; GT not started",
            );
            continue;
        }
        OWNERS.lock().push(owner.clone());
        narf_power::device_pm::register_device_pm_ops(&name, owner.clone());
        narf_power::system_pm::register_async_system_pm(&name, owner.clone());
        narf_scheduler::spawn(async move { owner.run().await });
    }
}

fn log(index: u32, text: &str) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "intel-gt card{index}: {text}");
}

fn validate_pci(p: &Pending, mmio: &impl MmioWindow) -> Result<u8, RuntimeError> {
    let read = |off| {
        narf_bus::pci::read_config32(&p.cap, &p.device, off).map_err(|_| RuntimeError::Authority)
    };
    let revision = pci_identity(read, p.device.id.vendor, p.device.id.device)?;
    let vf = mmio.read32(0x1901f8);
    if vf == u32::MAX || vf & 1 != 0 || p.bar.len < 16 * 1024 * 1024 {
        return Err(RuntimeError::Device);
    }
    if GtPlatform::from_pci(p.device.id.vendor, p.device.id.device)
        .is_some_and(GtPlatform::is_discrete)
    {
        // GT-only Arc binding must not replace GGTT mappings underneath an
        // inherited firmware scanout. Display takeover remains a separate owner.
        for pipe in 0..4 {
            for plane in 0..7 {
                let ctl = mmio.read32(0x70180 + pipe * 0x1000 + plane * 0x100);
                if ctl == u32::MAX || ctl & (1 << 31) != 0 {
                    return Err(RuntimeError::Device);
                }
            }
        }
    }
    if narf_bus::pci::power_state(&p.cap, &p.device).ok().flatten()
        != Some(narf_bus::pci::PciPowerState::D0)
    {
        return Err(RuntimeError::Device);
    }
    Ok(revision)
}

fn pci_identity(
    mut read: impl FnMut(u16) -> Result<u32, RuntimeError>,
    vendor: u16,
    device: u16,
) -> Result<u8, RuntimeError> {
    if read(0)? != (u32::from(device) << 16 | u32::from(vendor)) {
        return Err(RuntimeError::Device);
    }
    let revision = read(8)?;
    if revision == u32::MAX {
        return Err(RuntimeError::Device);
    }
    let mut off = 0x100u16;
    let mut seen = [0u16; 64];
    for count in 0..64 {
        if seen[..count].contains(&off) {
            return Err(RuntimeError::Device);
        }
        seen[count] = off;
        let header = read(off)?;
        if header == u32::MAX {
            return Err(RuntimeError::Device);
        }
        if header == 0 {
            return Ok(revision as u8);
        }
        if header as u16 == 0x10 && (off > 0xff4 || read(off + 8)? & 1 != 0) {
            return Err(RuntimeError::Device);
        }
        let next = (header >> 20) as u16;
        if next == 0 {
            return Ok(revision as u8);
        }
        if !(0x100..=0xffc).contains(&next) || next % 4 != 0 {
            return Err(RuntimeError::Device);
        }
        off = next;
    }
    Err(RuntimeError::Device)
}

/// A single unambiguous boot selection is immutable for each physical owner.
/// Invalid explicit settings refuse scheduling; tokens after `--` are init args.
fn ccs_boot_mode(command_line: narf_boot::args::KernelCmdline<'_>) -> Result<u8, RuntimeError> {
    let mut selection = None;
    for token in command_line.tokens().take_while(|token| *token != "--") {
        let value = if token == "narf.intel.ccs_mode" {
            return Err(RuntimeError::Configuration);
        } else if let Some(value) = token.strip_prefix("narf.intel.ccs_mode=") {
            value
        } else {
            continue;
        };
        if selection.is_some() {
            return Err(RuntimeError::Configuration);
        }
        selection = Some(match value {
            "1" => 1,
            "2" => 2,
            "3" => 3,
            "4" => 4,
            _ => return Err(RuntimeError::Configuration),
        });
    }
    Ok(selection.unwrap_or(1))
}

/// Every advertised physical engine must retire and verify its own private
/// PPGTT store before publication. The order comes from the frozen EngineSet.
fn next_probe_engine(
    engines: crate::intel_gpu_engine::EngineSet,
    completed: crate::intel_gpu_engine::Engine,
) -> Result<Option<crate::intel_gpu_engine::Engine>, RuntimeError> {
    let at = engines
        .iter()
        .position(|engine| engine == completed)
        .ok_or(RuntimeError::State)?;
    Ok(engines.iter().nth(at + 1))
}

impl Owner {
    fn close_controls(&self) {
        self.power_controls.close();
        if let Some(hwmon) = &self.hwmon {
            hwmon.close();
        }
    }

    fn cold_start(&self, state: &mut State) -> Result<(), RuntimeError> {
        let mode = state.ccs_mode?;
        let platform =
            GtPlatform::from_pci(self.pending.device.id.vendor, self.pending.device.id.device)
                .ok_or(RuntimeError::Device)?;
        if mode != 1 && !platform.is_discrete() {
            return Err(RuntimeError::Configuration);
        }
        state.irq.take();
        state.irq_tried = false;
        state.recover_after_stop = false;
        if state
            .gt
            .as_ref()
            .is_some_and(|gt| !matches!(gt.state(), GtState::Staged | GtState::Stopped))
        {
            return Err(RuntimeError::State);
        }
        state.gt.take(); // only verified stopped owners can be replaced
        let p = &self.pending;
        let mmio = AuthorizedWindow::new(p.bar, p.cap);
        let revision = validate_pci(p, &mmio)?;
        let platform = GtPlatform::from_pci(p.device.id.vendor, p.device.id.device)
            .ok_or(RuntimeError::Device)?;
        // Each verified restart needs a fresh policy proof. Reusing an arena
        // after S3 would publish new PTEs using the pre-suspend PAT/MOCS state
        // before hardware initialization has re-established that state.
        let arena = SharedArena::new(GgttArena::for_gt(p.bar, p.cap, platform));
        if state.firmware.is_none() {
            let authority: Cap<narf_firmware::FirmwareRegistry, Read> =
                narf_firmware::trusted_loader_authority()
                    .ok_or(RuntimeError::Authority)?
                    .derive()
                    .map_err(|_| RuntimeError::Authority)?;
            state.firmware = Some(
                GuCFirmware::open_for_platform(platform, &authority)
                    .map_err(RuntimeError::Firmware)?,
            );
        }
        state.gt = Some(
            GuCGt::stage_hardware(
                mmio,
                arena,
                state.firmware.as_ref().expect("prepared image"),
                BootConfig {
                    device_id: p.device.id.device,
                    revision,
                    huc_upload_bytes: 0,
                    uncached_mocs: (platform == GtPlatform::Battlemage).then_some(3),
                },
            )
            .map_err(RuntimeError::Gt)?,
        );
        state
            .gt
            .as_mut()
            .expect("retained GT")
            .begin(narf_time::monotonic_ns())
            .map_err(RuntimeError::Gt)?;
        state.phase = Phase::Booting;
        Ok(())
    }

    fn step(&self, state: &mut State, reconfiguration_power: bool) -> Result<(), RuntimeError> {
        if state.phase == Phase::Cold {
            let current = narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                .map_err(|_| RuntimeError::Authority)?
                .ok_or(RuntimeError::Device)?;
            if current != narf_bus::pci::PciPowerState::D0 {
                narf_bus::pci::set_power_state(
                    &self.pending.cap,
                    &self.pending.device,
                    narf_bus::pci::PciPowerState::D0,
                )
                .map_err(|_| RuntimeError::Authority)?;
                state.power_ready = narf_time::monotonic_ns()
                    .checked_add(10_000_000)
                    .ok_or(RuntimeError::State)?;
                state.phase = Phase::Powering;
                return Ok(());
            }
            return self.cold_start(state);
        }
        if state.phase == Phase::Powering {
            if narf_time::monotonic_ns() < state.power_ready {
                return Ok(());
            }
            return self.cold_start(state);
        }
        if matches!(state.phase, Phase::Failed | Phase::Stopped | Phase::Parked) {
            return Ok(());
        }
        let now = narf_time::monotonic_ns();
        let gt = state.gt.as_mut().ok_or(RuntimeError::State)?;
        let polled = gt.poll(now);
        if let Some(report) = gt.take_error_report() {
            crate::intel_gpu_error::record(self.pending.index, report);
        }
        let current = match polled {
            core::task::Poll::Pending => return Ok(()),
            core::task::Poll::Ready(result) => result.map_err(RuntimeError::Gt)?,
        };
        match (state.phase, current) {
            (Phase::Booting, GtState::Ready) => {
                gt.begin_hwconfig(now).map_err(RuntimeError::Gt)?;
                state.phase = Phase::Discovering;
            }
            (Phase::Discovering, GtState::Ready) => {
                match self.pending.card.publish_gt_hwconfig(gt) {
                    Ok(()) | Err(GtError::Busy) => {}
                    Err(e) => return Err(RuntimeError::Gt(e)),
                }
                self.pending
                    .card
                    .publish_gt_topology(gt)
                    .map_err(RuntimeError::Gt)?;
                gt.begin_scheduling_with_ccs_mode(now, state.ccs_mode?)
                    .map_err(RuntimeError::Gt)?;
                state.phase = Phase::Reloading;
            }
            (Phase::Reloading, GtState::Ready) => {
                gt.begin_ct(now).map_err(RuntimeError::Gt)?;
                state.phase = Phase::Ct;
            }
            (Phase::Ct, GtState::SchedulingReady) => {
                // Optional GuC frequency/RC6 management, as xe_guc_pc_start.
                state.slpc_reported = gt.begin_slpc(now).is_err();
                if state.slpc_reported {
                    log(
                        self.pending.index,
                        "GuC SLPC not started; retaining current GT frequency policy",
                    );
                }
                let (_, completion) = gt.submit_kernel_probe(now).map_err(RuntimeError::Gt)?;
                state.probe = Some(completion);
                state.phase = Phase::Probe;
            }
            (Phase::Probe, GtState::SchedulingReady) => {
                if let Some(result) = state.probe.as_ref().expect("owned probe").result() {
                    result.map_err(|_| RuntimeError::State)?;
                    state.probe = Some(gt.begin_context_defaults(now).map_err(RuntimeError::Gt)?);
                    state.phase = Phase::Defaults;
                }
            }
            (Phase::Defaults, GtState::SchedulingReady) => {
                if let Some(result) = state.probe.as_ref().expect("owned defaults fence").result() {
                    result.map_err(|_| RuntimeError::State)?;
                    if !gt.context_defaults_ready() {
                        return Err(RuntimeError::State);
                    }
                    let probe = gt.submit_ppgtt_probe(now).map_err(RuntimeError::Gt)?;
                    state.probe_engine = crate::intel_gpu_engine::Engine::Rcs0;
                    state.probe = Some(probe.completion);
                    state.probe_result = Some(probe.result);
                    state.phase = Phase::PpgttProbe;
                }
            }
            (Phase::PpgttProbe, GtState::SchedulingReady) => {
                if let Some(result) = state.probe.as_ref().expect("owned PPGTT probe").result() {
                    result.map_err(|_| RuntimeError::State)?;
                    state
                        .probe_result
                        .as_ref()
                        .expect("owned result")
                        .verify()
                        .map_err(|_| RuntimeError::State)?;
                    state.probe_result = None;
                    let engines = gt.engines().ok_or(RuntimeError::State)?;
                    if let Some(next) = next_probe_engine(engines, state.probe_engine)? {
                        let probe = gt
                            .submit_ppgtt_probe_on(now, next)
                            .map_err(RuntimeError::Gt)?;
                        state.probe = Some(probe.completion);
                        state.probe_result = Some(probe.result);
                        state.probe_engine = next;
                        return Ok(());
                    }
                    if let Some((epoch, previous, compute)) = state.parked_epoch {
                        if previous != engines || gt.compute_configuration() != Some(compute) {
                            return Err(RuntimeError::State);
                        }
                        gt.adopt_user_epoch(epoch).map_err(RuntimeError::Gt)?;
                    }
                    *self.user_facts.lock() = Some(gt.device_facts().map_err(RuntimeError::Gt)?);
                    // Before the epoch: discovery sees VRAM with the engines.
                    self.pending.card.publish_gt_vram(gt);
                    state.phase = Phase::DisplayRecovery;
                    let (major, minor, patch) = gt.submission_version();
                    self.user_version.store(
                        u32::from(major) << 16 | u32::from(minor) << 8 | u32::from(patch),
                        Ordering::Relaxed,
                    );
                    self.user_engines.store(
                        gt.engines().ok_or(RuntimeError::State)?.bits(),
                        Ordering::Release,
                    );
                    // Epoch publication follows an independent console
                    // recovery attempt, outside this GT mutex. A display
                    // waiter may itself still depend on our failed fences.
                    log(
                        self.pending.index,
                        "GuC ready; every published engine's defaults, private PPGTT store and retirement verified",
                    );
                }
            }
            (Phase::Running, GtState::SchedulingReady) => {
                if reconfiguration_power {
                    if let Some(control) = &self.ccs_control {
                        let epoch = self.user_epoch.load(Ordering::Acquire);
                        if control
                            .begin(gt, epoch, now, |mode| {
                                self.close_controls();
                                self.user_epoch.store(0, Ordering::Release);
                                state.irq.take();
                                state.irq_tried = false;
                                crate::intel_gpu_kms::quarantine_for_gt_reset(&self.pending.bar);
                                state.parked_epoch = None;
                                state.ccs_mode = Ok(mode);
                                state.recover_after_stop = true;
                            })
                            .map_err(RuntimeError::Gt)?
                            .is_some()
                        {
                            state.phase = Phase::Cleaning;
                            return Ok(());
                        }
                    }
                }
                use crate::intel_gpu_guc_sched::SlpcState;
                match gt.slpc() {
                    SlpcState::Running if !state.slpc_reported => {
                        state.slpc_reported = true;
                        log(self.pending.index, "GuC SLPC running; GuC controls RC6");
                    }
                    SlpcState::Unavailable if !state.slpc_reported => {
                        state.slpc_reported = true;
                        log(
                            self.pending.index,
                            "GuC SLPC controls unavailable; retaining current firmware policy",
                        );
                    }
                    _ => {}
                }
            }
            (Phase::Cleaning, GtState::Stopped) => {
                state.phase = if state.recover_after_stop {
                    state.recover_after_stop = false;
                    Phase::Cold
                } else {
                    Phase::Failed
                };
            }
            _ => return Err(RuntimeError::State),
        }
        Ok(())
    }

    async fn run(self: Arc<Self>) {
        let mut reconfiguration_power = None;
        loop {
            let mut reconfiguration_power_failed = false;
            // Runtime resume can acquire this same GT mutex. Never request
            // power while holding it, and retain the usage reference across
            // verified stop, all new probes and epoch publication.
            if self
                .ccs_control
                .as_ref()
                .is_some_and(|control| control.needs_power())
                && !self.suspended.load(Ordering::Acquire)
            {
                if reconfiguration_power.is_none() {
                    match Awake::take(&self).await {
                        Ok(awake) => reconfiguration_power = Some(awake),
                        Err(_) => {
                            reconfiguration_power_failed = true;
                            if let Some(control) = &self.ccs_control {
                                control.close();
                            }
                        }
                    }
                }
            } else {
                drop(reconfiguration_power.take());
            }
            let mut wait = None;
            let mut delay_us = 500;
            if !self.suspended.load(Ordering::Acquire) {
                let mut state = self.state.lock().await;
                // Snapshot the IRQ epoch before servicing any status. The
                // waiter observes an edge even before its first poll.
                if let Some(irq) = state.irq.as_ref().filter(|_| !reconfiguration_power_failed) {
                    wait = Some(narf_interrupts::wait_for_irq(irq.vector()));
                    match irq.service(narf_time::monotonic_ns()) {
                        Ok(pending) => delay_us = if pending { 10 } else { 10_000 },
                        Err(_) => {
                            drop(wait.take());
                            state.irq.take();
                            log(
                                self.pending.index,
                                "IRQ delivery closed; using timer completion",
                            );
                        }
                    }
                }
                let stepped = if reconfiguration_power_failed {
                    Err(RuntimeError::Authority)
                } else {
                    self.step(&mut state, reconfiguration_power.is_some())
                };
                if let Err(error) = stepped {
                    drop(wait.take());
                    state.irq.take(); // stop delivery before resetting the GT
                    delay_us = 500;
                    if let Some(gt) = state.gt.as_ref() {
                        use crate::intel_gpu_error::Reason;
                        let reason = match error {
                            RuntimeError::Gt(GtError::WakeLost | GtError::WakeTimeout) => {
                                Reason::WakeLost
                            }
                            RuntimeError::Gt(GtError::Unavailable) => Reason::Unavailable,
                            RuntimeError::Gt(GtError::Scheduling(
                                crate::intel_gpu_guc_sched::SchedulingError::Timeout,
                            )) => Reason::Timeout,
                            RuntimeError::Gt(GtError::Scheduling(
                                crate::intel_gpu_guc_sched::SchedulingError::Protocol,
                            )) => Reason::Protocol,
                            RuntimeError::Gt(
                                GtError::Scheduling(
                                    crate::intel_gpu_guc_sched::SchedulingError::Transport(_),
                                )
                                | GtError::Transport(_),
                            ) => Reason::Transport,
                            RuntimeError::Gt(GtError::Boot(_)) | RuntimeError::Firmware(_) => {
                                Reason::Boot
                            }
                            RuntimeError::Gt(_) => Reason::Recovery,
                            _ => Reason::State,
                        };
                        let window = AuthorizedWindow::new(self.pending.bar, self.pending.cap);
                        let report = gt.error_report(
                            reason,
                            self.user_epoch.load(Ordering::Acquire),
                            narf_time::monotonic_ns(),
                            || {
                                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
                            },
                            |offset| {
                                if narf_bus::pci::power_state(
                                    &self.pending.cap,
                                    &self.pending.device,
                                ) != Ok(Some(narf_bus::pci::PciPowerState::D0))
                                {
                                    return None;
                                }
                                let value = window.read32(offset);
                                (value != u32::MAX).then_some(value)
                            },
                        );
                        crate::intel_gpu_error::record(self.pending.index, report);
                    }
                    self.close_controls();
                    if let Some(control) = &self.ccs_control {
                        control.close();
                    }
                    self.user_epoch.store(0, Ordering::Release);
                    // A display waiter can depend on one of our fences.
                    // Poison its proofs synchronously before reset; never
                    // await the KMS mutex while holding this GT reset mutex.
                    crate::intel_gpu_kms::quarantine_for_gt_reset(&self.pending.bar);
                    state.parked_epoch = None; // a failed resume is a real loss
                    state.recover_after_stop |= state.phase == Phase::Running;
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "intel-gt card{}: closed after {:?}",
                        self.pending.index,
                        error
                    );
                    let cleanup_failed = state.phase == Phase::Cleaning;
                    state.phase = Phase::Failed;
                    if let Some(gt) = &mut state.gt {
                        if !matches!(gt.state(), GtState::Staged | GtState::Stopped)
                            && !cleanup_failed
                            && gt.begin_stop(narf_time::monotonic_ns()).is_ok()
                        {
                            state.phase = Phase::Cleaning;
                        }
                    }
                }
                if state.phase == Phase::DisplayRecovery {
                    drop(state);
                    if crate::intel_gpu_kms::recover_after_gt_reset(&self.pending.bar)
                        .await
                        .is_err()
                    {
                        log(
                            self.pending.index,
                            "display recovery failed; retained scanout remains quarantined",
                        );
                    }
                    state = self.state.lock().await;
                    if state.phase == Phase::DisplayRecovery
                        && !self.suspended.load(Ordering::Acquire)
                    {
                        if let Some(epoch) = state.gt.as_ref().and_then(GuCGt::user_epoch) {
                            let configuration =
                                state.gt.as_ref().and_then(GuCGt::compute_configuration);
                            let mut publish = || {
                                self.power_controls.activate(epoch);
                                if let Some(hwmon) = &self.hwmon {
                                    hwmon.activate(epoch);
                                }
                                self.user_epoch.store(epoch, Ordering::Release);
                                state.parked_epoch = None;
                                state.phase = Phase::Running;
                            };
                            let configured = match (&self.ccs_control, configuration) {
                                (Some(control), Some(configuration)) => {
                                    control.publish_with(epoch, configuration, publish)
                                }
                                (Some(_), None) => Err(narf_filesystem::FsError::NoDevice),
                                (None, _) => {
                                    publish();
                                    Ok(())
                                }
                            };
                            if configured.is_err() {
                                // DisplayRecovery is not a polling phase:
                                // the next step returns State and takes the
                                // common fatal/reset path before admission.
                                self.close_controls();
                                self.user_epoch.store(0, Ordering::Release);
                                if let Some(control) = &self.ccs_control {
                                    control.close();
                                }
                                drop(state);
                                narf_scheduler::yield_now().await;
                                continue;
                            }
                        }
                    }
                }
                if state.phase == Phase::Running {
                    if let Some(gt) = state.gt.as_mut() {
                        self.power_controls.service(
                            gt,
                            self.user_epoch.load(Ordering::Acquire),
                            narf_time::monotonic_ns(),
                        );
                    }
                }
                if state.phase == Phase::Running {
                    if let Some(hwmon) = &self.hwmon {
                        let mmio = AuthorizedWindow::new(self.pending.bar, self.pending.cap);
                        hwmon.service_mmio(
                            self.user_epoch.load(Ordering::Acquire),
                            narf_time::monotonic_ns(),
                            &mmio,
                            || {
                                narf_bus::pci::power_state(&self.pending.cap, &self.pending.device)
                                    == Ok(Some(narf_bus::pci::PciPowerState::D0))
                            },
                        );
                    }
                }
                if state.phase == Phase::Running && !state.irq_tried {
                    state.irq_tried = true;
                    let engines = state
                        .gt
                        .as_ref()
                        .and_then(GuCGt::engines)
                        .unwrap_or_default();
                    state.irq = crate::intel_gpu_gt_irq::GtIrq::for_device(
                        AuthorizedWindow::new(self.pending.bar, self.pending.cap),
                        self.pending.cap,
                        self.pending.device,
                        engines,
                    )
                    .ok();
                    if state.irq.is_some() {
                        log(self.pending.index, "MSI completion delivery installed");
                        delay_us = 10; // first drain before opening tile master
                    } else {
                        log(
                            self.pending.index,
                            "MSI unavailable; using timer completion",
                        );
                    }
                }
            }
            self.arm_autosuspend().await;
            narf_scheduler::yield_now().await;
            let deadline = narf_time::Deadline::after_us(delay_us);
            if let Some(wait) = wait {
                let _ = narf_time::timeout(deadline, wait).await;
            } else {
                narf_time::SleepUntil::new(deadline.as_instant()).await;
            }
        }
    }
}

impl Owner {
    /// Discrete functions without a bound display may autosuspend. An iGPU
    /// scanout keeps its function in D0, as Linux's display wakeref does.
    fn autosuspend_eligible(&self) -> bool {
        let platform =
            GtPlatform::from_pci(self.pending.device.id.vendor, self.pending.device.id.device);
        platform.is_some_and(GtPlatform::is_discrete) && self.pending.mode.is_none()
    }

    /// Once the first bring-up publishes users: configure autosuspend, allow
    /// runtime PM and drop the probe reference. Never holds the state lock,
    /// because allowing may immediately invoke `park`.
    async fn arm_autosuspend(&self) {
        if self.autosuspend.load(Ordering::Acquire)
            || !self.autosuspend_eligible()
            || self.user_epoch.load(Ordering::Acquire) == 0
        {
            return;
        }
        self.autosuspend.store(true, Ordering::Release);
        let device = &self.pm.device;
        device.set_autosuspend_delay(AUTOSUSPEND_MS).await;
        device.use_autosuspend(true).await;
        device.mark_last_busy();
        device.allow();
        let _ = device.put_autosuspend();
    }

    /// Runtime suspend: refuse unless the GT is running and provably idle,
    /// no VRAM object exists (CPU BAR mappings cannot be revoked) and no
    /// system sleep owns the function. Then stop the GT exactly as for
    /// reset, keeping the user epoch published for the resume.
    async fn park(&self) -> Result<(), RpmError> {
        let mut state = self.state.lock().await;
        if self.suspended.load(Ordering::Acquire)
            || state.phase != Phase::Running
            || !self.autosuspend_eligible()
            || self
                .pending
                .card
                .intel_vram_used()
                .is_some_and(|used| used != 0)
        {
            return Err(RpmError::Busy);
        }
        let epoch = self.user_epoch.load(Ordering::Acquire);
        if epoch == 0 || !state.gt.as_ref().is_some_and(GuCGt::idle) {
            return Err(RpmError::Busy);
        }
        let engines = state
            .gt
            .as_ref()
            .and_then(GuCGt::engines)
            .ok_or(RpmError::Failed)?;
        let compute = state
            .gt
            .as_ref()
            .and_then(GuCGt::compute_configuration)
            .ok_or(RpmError::Failed)?;
        state.irq.take(); // mask and synchronize while still in D0
        self.close_controls();
        state.irq_tried = false;
        let gt = state.gt.as_mut().expect("running GT");
        let stopped = gt.begin_stop(narf_time::monotonic_ns()).is_ok()
            && gt.wait().await == Ok(GtState::Stopped);
        if !stopped {
            // Uncertain hardware: close admission; the worker owns recovery.
            self.user_epoch.store(0, Ordering::Release);
            state.phase = Phase::Failed;
            return Err(RpmError::Failed);
        }
        // Verified stopped: reclaim its GGTT owners before D3hot.
        state.gt.take();
        state.parked_epoch = Some((epoch, engines, compute));
        state.phase = Phase::Parked;
        log(self.pending.index, "runtime suspended (idle)");
        Ok(())
    }

    /// Runtime resume: the PCI layer restored D0 and config space; restart
    /// the verified bring-up, which adopts the parked epoch at publication.
    async fn unpark(&self) {
        let mut state = self.state.lock().await;
        if state.phase == Phase::Parked {
            state.phase = Phase::Cold;
            state.probe = None;
            state.probe_result = None;
        }
    }

    /// Whether a non-running GT is resuming under a still-valid epoch, so a
    /// caller should wait rather than see a lost device.
    fn resuming(&self, state: &State) -> bool {
        state.parked_epoch.is_some()
            && !matches!(
                state.phase,
                Phase::Failed | Phase::Cleaning | Phase::Stopped
            )
            && !self.suspended.load(Ordering::Acquire)
    }

    /// The state, once any runtime-resume bring-up has finished or failed.
    /// The lock is released between polls so the worker can progress.
    async fn lock_running(&self) -> narf_lib::mutex::MutexGuard<'_, State> {
        loop {
            let state = self.state.lock().await;
            if !self.resuming(&state) {
                return state;
            }
            drop(state);
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
}

impl narf_power::device_pm::DevicePmOps for Owner {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
        use narf_power::device_pm::DeviceSuspendError as E;
        let state = self.state.try_lock().ok_or(E::Busy)?;
        // Legacy synchronous suspend has not run the async GT preparation.
        // Refuse before power loss; never bridge a wait inside an executor poll.
        if !self.suspended.load(Ordering::Acquire)
            || state.phase != Phase::Stopped
            || state.saved.is_none()
        {
            return Err(E::Busy);
        }
        Ok(())
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
        // Keep admission closed until the paired asynchronous D0 settle,
        // PCI/display restore and fresh-policy restart can run with IRQs usable.
        Ok(())
    }
}

impl narf_power::system_pm::AsyncSystemPm for Owner {
    fn prepare_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        Box::pin(async move {
            use narf_power::device_pm::DeviceSuspendError as E;
            // Retire display GEM fetch before closing the backend or taking
            // its reset mutex. KMS holds this same display mutex while a
            // transaction is armed, so suspend cannot overtake its latch.
            crate::intel_gpu_kms::quiesce_for_legacy(&self.pending.bar)
                .await
                .map_err(|_| E::Busy)?;
            // Serialize closing admission with the worker's ready-epoch
            // activation. Display quiescence remains outside this lock.
            let mut state = self.state.lock().await;
            self.close_controls();
            if let Some(control) = &self.ccs_control {
                control.close();
            }
            self.suspended.store(true, Ordering::Release);
            self.user_epoch.store(0, Ordering::Release);
            state.irq.take(); // mask/synchronize while the function is in D0
            state.saved = None;
            // System sleep loses context state: no runtime epoch survives it.
            state.parked_epoch = None;
            let result = async {
                if let Some(gt) = &mut state.gt {
                    if !matches!(gt.state(), GtState::Staged | GtState::Stopped) {
                        gt.begin_stop(narf_time::monotonic_ns())
                            .map_err(|_| E::DriverError)?;
                        if gt.wait().await != Ok(GtState::Stopped) {
                            return Err(E::DriverError);
                        }
                    }
                }
                state.saved = Some(
                    narf_bus::pci::save_config(&self.pending.cap, &self.pending.device)
                        .map_err(|_| E::DriverError)?,
                );
                // Reclaim verified stopped/unpublished mappings while this
                // function is still in D0, before platform firmware can alter
                // the GGTT across S3. Resume constructs a fresh GT owner.
                state.gt.take();
                state.phase = Phase::Stopped;
                Ok(())
            }
            .await;
            if result.is_err() {
                // The coordinator does not resume its failing prepare hook.
                // Restart only a provably stopped/unpublished graph; retain
                // uncertain hardware as failed and let the system abort S3.
                state.phase = if state
                    .gt
                    .as_ref()
                    .is_none_or(|gt| matches!(gt.state(), GtState::Staged | GtState::Stopped))
                {
                    Phase::Cold
                } else {
                    Phase::Failed
                };
                self.suspended.store(false, Ordering::Release);
            }
            result
        })
    }

    fn resume_from_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        Box::pin(async move {
            use narf_power::device_pm::DeviceSuspendError as E;
            let mut state = self.state.lock().await;
            if !self.suspended.load(Ordering::Acquire) {
                return Ok(());
            }
            if let Some(saved) = state.saved.as_ref() {
                narf_bus::pci::set_power_state(
                    &self.pending.cap,
                    &self.pending.device,
                    narf_bus::pci::PciPowerState::D0,
                )
                .map_err(|_| E::DriverError)?;
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
                narf_bus::pci::restore_config(&self.pending.cap, &self.pending.device, saved)
                    .map_err(|_| E::DriverError)?;
            }
            if let Some(mode) = self.pending.mode {
                crate::intel_gpu::relight_display(&mode).ok_or(E::DriverError)?;
            }
            state.phase = Phase::Cold;
            state.probe = None;
            state.probe_result = None;
            state.saved = None;
            self.suspended.store(false, Ordering::Release);
            Ok(())
        })
    }
}

/// Queue another owned kernel context probe on the actual registered function.
/// The per-card worker owns CT progression; cancelling the returned waiter
/// never removes the context or releases DMA memory.
pub async fn kernel_probe(index: u32) -> Result<Arc<CompletionFence>, RuntimeError> {
    let owner = OWNERS
        .lock()
        .iter()
        .find(|o| o.pending.index == index)
        .cloned()
        .ok_or(RuntimeError::Device)?;
    let mut state = owner.state.lock().await;
    if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
        return Err(RuntimeError::State);
    }
    state
        .gt
        .as_mut()
        .ok_or(RuntimeError::State)?
        .submit_kernel_probe(narf_time::monotonic_ns())
        .map(|(_, completion)| completion)
        .map_err(RuntimeError::Gt)
}

/// Queue the fixed private-address-space store probe on this PCI function.
/// Wait for completion before checking `result.verify()`. Cancelling the
/// waiter or dropping the result retains the scheduler's complete residency.
pub async fn kernel_ppgtt_probe(
    index: u32,
) -> Result<crate::intel_gpu_exec::PpgttProbeSubmission, RuntimeError> {
    let owner = OWNERS
        .lock()
        .iter()
        .find(|o| o.pending.index == index)
        .cloned()
        .ok_or(RuntimeError::Device)?;
    let mut state = owner.state.lock().await;
    if state.phase != Phase::Running || owner.suspended.load(Ordering::Acquire) {
        return Err(RuntimeError::State);
    }
    state
        .gt
        .as_mut()
        .ok_or(RuntimeError::State)?
        .submit_ppgtt_probe(narf_time::monotonic_ns())
        .map_err(RuntimeError::Gt)
}

/// Arc cards bind to a GT-only device; no display or local-memory region is
/// invented. BAR0 and authority remain with the per-function startup service.
pub(crate) fn probe_discrete(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    let platform = GtPlatform::from_pci(device.id.vendor, device.id.device)
        .ok_or(narf_bus::ProbeError::NotForThisDriver)?;
    if !platform.is_discrete() {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if PENDING.lock().iter().any(|p| p.device.addr == device.addr)
        || OWNERS
            .lock()
            .iter()
            .any(|o| o.pending.device.addr == device.addr)
    {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: the PCI probe grants exclusive ownership of this function's BAR0.
    let bar = unsafe { narf_bus::bar::map_bar(&device, 0) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // LMEM BAR: write-combining for the prefetchable window. A failed or
    // conflicting mapping leaves VRAM unpublished rather than refusing the GT.
    // SAFETY: the same exclusive probe ownership covers BAR2.
    let lmem = unsafe { narf_bus::bar::map_bar(&device, 2) }.ok();
    let index = crate::drm_registry::count() as u32;
    let card = Arc::new(IntelGpuCard::new(
        alloc::format!("card{index}"),
        device.id.vendor,
        device.id.device,
        device.id.subsystem_vendor,
        device.id.subsystem_id,
    ));
    if let Some(lmem) = lmem {
        // SAFETY: this card's own BAR2, owned exclusively by this probe.
        unsafe { card.install_lmem_bar(lmem) };
    }
    let assigned = crate::drm_registry::register_drm_card(card.clone());
    install(assigned, card, device, cap, bar, None);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-gpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_gt_compute_boot_selection_is_unambiguous_and_immutable() -> TestResult {
        use narf_boot::args::KernelCmdline;
        for (raw, expected) in [
            ("", 1),
            ("quiet", 1),
            ("narf.intel.ccs_mode=1", 1),
            ("narf.intel.ccs_mode=2", 2),
            ("narf.intel.ccs_mode=3", 3),
            ("narf.intel.ccs_mode=4", 4),
            ("-- narf.intel.ccs_mode=4", 1),
        ] {
            assert_eq!(ccs_boot_mode(KernelCmdline::new(raw)), Ok(expected));
        }
        for raw in [
            "narf.intel.ccs_mode",
            "narf.intel.ccs_mode=",
            "narf.intel.ccs_mode=0",
            "narf.intel.ccs_mode=5",
            "narf.intel.ccs_mode=-1",
            "narf.intel.ccs_mode=02",
            "narf.intel.ccs_mode=2 narf.intel.ccs_mode=2",
            "narf.intel.ccs_mode=1 narf.intel.ccs_mode=2",
            "narf.intel.ccs_mode=1 narf.intel.ccs_mode",
        ] {
            assert_eq!(
                ccs_boot_mode(KernelCmdline::new(raw)),
                Err(RuntimeError::Configuration)
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_compute_boot_selection_is_unambiguous_and_immutable
    );

    fn smoke_gt_private_startup_probes_cover_every_sparse_physical_engine() -> TestResult {
        use crate::intel_gpu_engine::{Engine, EngineSet};
        let engines = EngineSet::of(&[
            Engine::Rcs0,
            Engine::Bcs0,
            Engine::Bcs8,
            Engine::Ccs1,
            Engine::Ccs3,
        ]);
        let mut current = Engine::Rcs0;
        let mut visited = alloc::vec![current];
        while let Some(next) = next_probe_engine(engines, current).unwrap() {
            visited.push(next);
            current = next;
        }
        assert_eq!(
            visited,
            [
                Engine::Rcs0,
                Engine::Bcs0,
                Engine::Bcs8,
                Engine::Ccs1,
                Engine::Ccs3
            ]
        );
        assert_eq!(
            next_probe_engine(engines, Engine::Ccs0),
            Err(RuntimeError::State)
        );
        assert_eq!(
            next_probe_engine(EngineSet::default(), Engine::Rcs0),
            Err(RuntimeError::State)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_private_startup_probes_cover_every_sparse_physical_engine
    );

    fn smoke_gt_pci_identity_and_virtualization_admission() -> TestResult {
        // PCIe extended-capability headers: ID[15:0], version[19:16],
        // next[31:20]. SR-IOV Control.VF Enable is bit0 at capability+8.
        let mut cfg: BTreeMap<u16, u32> = [(0, 0x7d558086), (8, 3)].into_iter().collect();
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Ok(3)
        );
        for unreadable in [8, 0x100] {
            assert_eq!(
                pci_identity(
                    |off| Ok(if off == unreadable {
                        u32::MAX
                    } else {
                        *cfg.get(&off).unwrap_or(&0)
                    }),
                    0x8086,
                    0x7d55
                ),
                Err(RuntimeError::Device)
            );
        }
        cfg.insert(0x100, 0x20010001);
        cfg.insert(0x200, 0x18010010);
        cfg.insert(0x180, 0x0001000f);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Ok(3)
        );
        cfg.insert(0x208, 1);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.insert(0x208, 0);
        cfg.insert(0x180, 0x2001000f);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.insert(0x180, 0x1811000f);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.insert(0x180, 0x0801000f);
        assert_eq!(
            pci_identity(|off| Ok(*cfg.get(&off).unwrap_or(&0)), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        cfg.clear();
        cfg.insert(0, 0x7d558086);
        cfg.insert(8, 3);
        for i in 0..65u16 {
            cfg.insert(0x100 + i * 16, (u32::from(0x110 + i * 16) << 20) | 0x10001);
        }
        let mut count = 0;
        assert_eq!(
            pci_identity(
                |off| {
                    count += 1;
                    Ok(*cfg.get(&off).unwrap_or(&0))
                },
                0x8086,
                0x7d55
            ),
            Err(RuntimeError::Device)
        );
        assert_eq!(count, 66); // identity + revision + at most64 capability reads
        assert_eq!(
            pci_identity(|_| Err(RuntimeError::Authority), 0x8086, 0x7d55),
            Err(RuntimeError::Authority)
        );
        assert_eq!(
            pci_identity(|_| Ok(0xffffffff), 0x8086, 0x7d55),
            Err(RuntimeError::Device)
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_pci_identity_and_virtualization_admission
    );
}
