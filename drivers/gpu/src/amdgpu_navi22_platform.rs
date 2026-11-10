//! One retained Navi22 firmware owner, entered by the framebuffer boot handoff.
//! Preparation is read-only; the caller stops CPU writers before entering it.
use crate::{amdgpu, amdgpu_navi22_boot as boot, amdgpu_vram_boot as vram};
use core::ops::Range;
use narf_capabilities::{Cap, Read};
use narf_graphics_driver::generic::GenericFb;
use narf_lib::mutex::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Clock,
    Authority,
    InvalidFramebuffer,
    Firmware(boot::Error),
    Memory(vram::Error),
}

static OWNER: Mutex<Option<boot::ColdBoot>> = Mutex::new(None);
static RECOVERY: Mutex<crate::amdgpu_navi22_recovery::Recovery> =
    Mutex::new(crate::amdgpu_navi22_recovery::Recovery::new());

/// Firmware progress only, never an acceleration-ready indication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "diagnostic snapshots must remain allocation-free"
)]
pub enum Status {
    Absent,
    Running,
    Retained(Diagnostics),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diagnostics {
    pub state: boot::State,
    pub training: Option<crate::amdgpu_gddr6::State>,
    pub gfx: Option<crate::amdgpu_psp_ring::GfxBootStatus>,
    pub dmub: Option<crate::amdgpu_dmub_navi22::MailboxState>,
    pub power: Option<crate::amdgpu_navi22_power::Snapshot>,
    pub thermal: crate::amdgpu_navi22_thermal::Status,
    pub tdr: crate::amdgpu_navi22_tdr::Status,
    /// None while a recovery runs.
    pub recovery: Option<crate::amdgpu_navi22_recovery::State>,
}
pub fn status() -> Status {
    match OWNER.try_lock() {
        None => Status::Running,
        Some(owner) => owner.as_ref().map_or(Status::Absent, |boot| {
            Status::Retained(Diagnostics {
                state: boot.state(),
                training: boot.training_state(),
                gfx: boot.gfx_boot_status(),
                dmub: boot.dmub_mailbox_state(),
                power: crate::amdgpu_navi22_power::snapshot(),
                thermal: crate::amdgpu_navi22_thermal::status(),
                tdr: crate::amdgpu_navi22_tdr::status(),
                recovery: RECOVERY.try_lock().map(|r| r.state()),
            })
        }),
    }
}

// A secondary GPU must not reserve another device's GOP address. Partial
// overlap is an invalid handoff, not evidence that the framebuffer is absent.
fn framebuffer_range(
    aperture: Range<u64>,
    framebuffer: Option<GenericFb>,
) -> Result<Option<Range<u64>>, Error> {
    if aperture.start >= aperture.end {
        return Err(Error::InvalidFramebuffer);
    }
    let Some(fb) = framebuffer else {
        return Ok(None);
    };
    let bytes = u64::from(fb.pitch) * u64::from(fb.height);
    let end = fb
        .addr
        .checked_add(bytes)
        .ok_or(Error::InvalidFramebuffer)?;
    if bytes == 0
        || fb.width == 0
        || fb.bpp == 0
        || u64::from(fb.width) * u64::from(fb.bpp).div_ceil(8) > u64::from(fb.pitch)
    {
        return Err(Error::InvalidFramebuffer);
    }
    if end <= aperture.start || fb.addr >= aperture.end {
        return Ok(None);
    }
    if fb.addr < aperture.start || end > aperture.end {
        return Err(Error::InvalidFramebuffer);
    }
    Ok(Some(fb.addr..end))
}

fn training_clients(protected: &[vram::Protected]) -> Result<(), Error> {
    // Long training temporarily overwrites this entire prefix, regardless of
    // allocator exclusions. Display/cursor readers can show transient pixels.
    // Inherited DMUB windows are tolerated as Linux does: psp_v11_0's long
    // training backs up/restores the prefix whatever DCN maps there, and the
    // DMCUB is stopped and reset (DmubQuiesce, dm_dmub_hw_init) before its
    // firmware is reloaded. Other firmware writers there cannot be preserved
    // by racing a CPU backup/restore. No caller-supplied OtherClient ranges
    // exist here: Plan produces those only from inherited display surfaces.
    if protected.iter().any(|region| {
        // linux: n/a (NARF policy: protected 32 MiB VRAM prefix)
        region.range.start < 32 * 1024 * 1024
            && !matches!(
                region.owner,
                vram::Owner::BootFramebuffer | vram::Owner::OtherClient | vram::Owner::Dmub
            )
    }) {
        return Err(Error::Memory(vram::Error::Busy));
    }
    Ok(())
}

/// Prepare all firmware and VRAM exclusions, then reserve exclusive MMIO
/// ownership. `Ok(None)` means no Navi22. `Ok(Some(affected))` means the owner
/// is retained and reports whether the boot framebuffer belongs to this GPU.
/// Errors perform no device writes and leave framebuffer/controller access live.
///
/// # Safety
/// Call once during single-CPU boot, before executor polling or userspace,
/// with no NARF GPU allocations, active queues, reset or PM transitions.
/// `framebuffer` is the original bus-physical GOP geometry, not its remapped VA.
/// Probe's mappings and PCI ownership must be permanent. Firmware must have
/// posted this physical GPU; this is neither VF initialization nor recovery.
/// Other than inventoried firmware/display clients, VRAM is exclusively free.
/// CPU framebuffer writers and sleep pumps must already be stopped and remain
/// stopped until run succeeds (or until a preparation error returns).
pub unsafe fn prepare(framebuffer: Option<GenericFb>) -> Result<Option<bool>, Error> {
    if !amdgpu::is_navi22() {
        return Ok(None);
    }
    // No hardware writes or retained ownership before the timing preflight.
    // Firmware delays must use wall time even though the BSP's timer IRQ
    // setup runs after this Late initcall.
    if !amdgpu::boot_clock_ready() {
        return Err(Error::Clock);
    }
    let mut owner = OWNER.try_lock().ok_or(Error::Busy)?;
    if owner.is_some() {
        return Err(Error::Busy);
    }
    let authority = amdgpu::pci_authority().ok_or(Error::Authority)?;
    let device = amdgpu::pci_device().ok_or(Error::Authority)?;
    // pdev->revision (cfg 0x08), the amdgpu.ids key with the device id.
    if let Ok(class_rev) = narf_bus::pci::read_config32(&authority, &device, 0x08) {
        crate::amdgpu_info::publish_navi22_pci_revision(class_rev as u8);
    }
    let identity = crate::amdgpu_power_navi22::Identity::read(&device, &authority)
        .map_err(|error| Error::Firmware(boot::Error::Power(error)))?;
    let registry: Cap<narf_firmware::FirmwareRegistry, Read> =
        narf_firmware::trusted_loader_authority()
            .ok_or(Error::Authority)?
            .derive()
            .map_err(|_| Error::Authority)?;
    amdgpu::claim_navi22(|gpu| {
        // Validate/copy every file before inspecting hardware or claiming VRAM.
        let mut firmware = boot::Firmware::open_rdna2(gpu, &registry).map_err(Error::Firmware)?;
        crate::amdgpu_info::sample_rdna2_board(gpu, &authority, &device);
        // amdgpu_discovery_harvest_ip: VCN instances absent from the harvest
        // table get firmware and an owner. An unreadable table disables
        // media only; display and queue bring-up do not depend on it.
        // SAFETY: single-CPU boot under the exclusive claim, same mappings
        // and index latch probe used for the discovery read.
        match unsafe { crate::amdgpu_vcn_navi22::Harvest::read(gpu, &authority, identity.revision) }
        {
            Ok(harvest) => {
                crate::amdgpu_info::publish_navi22_vcn_harvest(harvest.0);
                firmware.harvest_vcn(harvest.0)
            }
            Err(error) => {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 media disabled: harvest {error:?}"
                );
                firmware.harvest_vcn(3);
            }
        }
        firmware
            .prepare_power(gpu, identity)
            .map_err(Error::Firmware)?;
        firmware.prepare_dmub(gpu).map_err(Error::Firmware)?;
        // Display routing is diagnostic for firmware bring-up: a board whose
        // connector table cannot be read still runs the firmware sequence.
        let display = firmware.prepare_display(gpu);
        let end = gpu
            .vram
            .base
            .checked_add(gpu.vram.visible_size)
            .ok_or(Error::InvalidFramebuffer)?;
        let range = framebuffer_range(gpu.vram.base..end, framebuffer)?;
        let affected = range.is_some();
        // SAFETY: caller's boot ownership, no active NARF clients. Plan refuses
        // live VM contexts and accounts for firmware, all pipes and cursors.
        let plan = unsafe { vram::Plan::read_rdna2(gpu, &authority, range, &[]) }
            .map_err(Error::Memory)?;
        let training = plan.training();
        let secure_dmub = plan.secure_dmub();
        if training.is_some() {
            training_clients(plan.protected())?;
        }
        // SAFETY: the immutable inventory covers every inherited client, and
        // successful preparation excludes every later legacy MMIO accessor.
        let unmapped = unsafe { plan.unmapped_pool() }.map_err(Error::Memory)?;
        // SAFETY: same complete inventory/exclusive ownership; the visible
        // prefix is disjoint from the above-BAR pool just retained.
        let pool = unsafe { plan.into_pool() }.map_err(Error::Memory)?;
        // Constructors allocate host state/reservations only. The framebuffer
        // handoff has already stopped CPU writers before entering prepare().
        let mut prepared = match training {
            Some(exchange) => {
                // SAFETY: exclusive GPU/pool as above; run's caller stops CPU
                // VRAM clients before accessing the training hardware.
                unsafe {
                    boot::ColdBoot::new_with_training(gpu, authority, &pool, firmware, exchange)
                }
            }
            None => {
                // SAFETY: posted VRAM, no firmware two-stage training request;
                // permanent exclusive GPU/pool ownership as above.
                unsafe { boot::ColdBoot::new_rdna2(gpu, authority, &pool, firmware) }
            }
        }
        .map_err(Error::Firmware)?;
        prepared.set_unmapped(unmapped);
        prepared
            .set_secure_dmub(secure_dmub)
            .map_err(Error::Firmware)?;
        // Linux resets every posted discrete Navi before loading firmware.
        // SAFETY: probe's PCI function for this GPU; its config space is
        // claimed along with the exclusive MMIO ownership transferred below.
        unsafe { prepared.prepare_reset(device) }.map_err(Error::Firmware)?;
        prepared.prepare_memory_hubs().map_err(Error::Firmware)?;
        prepared.prepare_sdma().map_err(Error::Firmware)?;
        prepared
            .prepare_interrupts(device)
            .map_err(Error::Firmware)?;
        prepared.prepare_dmub().map_err(Error::Firmware)?;
        if let Err(error) = display.and_then(|()| prepared.prepare_display()) {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 display routes: {error:?}"
            );
        }
        // Kernel queues are optional for the firmware/display path: without
        // a usable BAR2 doorbell page the queue stages are skipped, visibly.
        // SAFETY: boot-time exclusive PCI ownership; BAR2 is otherwise unused.
        match unsafe { crate::amdgpu_cp_navi22::Doorbells::map_rdna2(&device) } {
            Ok(doorbells) => {
                prepared
                    .prepare_queues(doorbells)
                    .map_err(Error::Firmware)?;
                if let Err(error) = prepared.prepare_media(doorbells) {
                    use core::fmt::Write;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi22 media disabled: {error:?}"
                    );
                }
            }
            Err(error) => {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 kernel queues disabled: doorbells {error:?}"
                );
            }
        }
        *owner = Some(prepared);
        Ok(Some(affected))
    })
    .ok_or(Error::Busy)?
}

/// Run the prepared owner once. The static retains training preimage, pool,
/// PSP/TMR and diagnostic state through success, failure and cancellation.
///
/// # Safety
/// All CPU framebuffer writers/pumps and other VRAM clients must be stopped
/// before polling, and stay stopped after failure or cancellation until reset.
/// Continue to satisfy `prepare`'s exclusive hardware ownership contract.
pub async unsafe fn run() -> Result<boot::Report, boot::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(boot::Error::Invalid)?;
    let report = boot.run().await?;
    // AMDGPU_INFO_FW_VERSION and DPM clocks describe what actually loaded.
    if let Some(firmware) = boot.uapi_versions() {
        crate::amdgpu_info::publish_navi22_boot(crate::amdgpu_info_navi22::Boot {
            firmware,
            smc: report.smu.firmware,
            gfx_mhz: report.power_status.map(|p| (p.gfx_min_mhz, p.gfx_max_mhz)),
            queues_verified: report.queues.is_some(),
            sdma_rings: report.queues.map_or(0, |q| {
                q.sdma
                    .ring
                    .iter()
                    .enumerate()
                    .fold(0u8, |mask, (i, ready)| mask | (u8::from(*ready) << i))
            }),
        });
    }
    start_services(boot).await;
    Ok(report)
}

/// Serialised access to the retained owner for client submission
/// (`amdgpu_navi22_cs`). Never held across a fence wait.
pub(crate) async fn owner() -> narf_lib::mutex::MutexGuard<'static, Option<boot::ColdBoot>> {
    OWNER.lock().await
}

/// Controller before OWNER, with an activation/epoch recheck under OWNER.
/// A transition cannot power GC down while the returned owner is held.
pub(crate) async fn gc_owner() -> Result<
    (
        crate::amdgpu_navi22_gfxoff::Reference,
        narf_lib::mutex::MutexGuard<'static, Option<boot::ColdBoot>>,
    ),
    narf_filesystem::FsError,
> {
    loop {
        let power = crate::amdgpu_navi22_gfxoff::Reference::acquire()
            .await
            .map_err(|_| narf_filesystem::FsError::NoDevice)?;
        let owner = OWNER.lock().await;
        if power.covers_access() {
            return Ok((power, owner));
        }
        drop(owner);
        drop(power);
    }
}

/// Runtime services of a completed (or recovered) owner: PMFW telemetry and
/// hwmon, then the SMU11 thermal interrupts. They run as executor tasks that
/// take the owner lock per refresh. Failures are reported, never fatal.
async fn start_services(boot: &mut boot::ColdBoot) {
    use core::fmt::Write;
    crate::amdgpu_info::publish_rdna2_memory_clocks(boot.memory_clock_range().await.ok());
    // Clients' command submissions and VRAM buffers (generic CS/GEM path).
    if boot.queues_verified()
        && crate::amdgpu_info_navi22::submission() == crate::amdgpu_info_navi22::Submission::Wired
    {
        crate::amdgpu_navi22_cs::register(boot).await;
    }
    start_hotplug(boot);
    crate::amdgpu_vcn_navi22::idle::start();
    if boot.queues_verified() {
        crate::amdgpu_navi22_tdr::start();
    }
    let Some(limits) = boot.power_limits() else {
        return;
    };
    crate::amdgpu_navi22_power::start(Some(limits));
    let Some(ih) = boot.interrupts() else {
        return;
    };
    // Subscribe first so the alert enable cannot raise an unrouted IV.
    let subscriptions = match crate::amdgpu_navi22_thermal::subscribe(&ih) {
        Ok(subscriptions) => subscriptions,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 thermal interrupts unavailable: {error:?}"
            );
            return;
        }
    };
    match boot.enable_thermal_alert().await {
        Ok((alert, ack)) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 thermal alert {alert:?}"
            );
            crate::amdgpu_navi22_thermal::spawn(subscriptions, alert, ack, Some(limits));
        }
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 thermal alert failed: {error:?}"
            );
        }
    }
}

/// HPD over the IH ring (amdgpu_navi22_display::serve_hpd): each vector is
/// acknowledged under the owner lock, then wakes the hotplug pollers and the
/// display monitor. Without an IH ring or display owner, polling alone runs.
fn start_hotplug(boot: &mut boot::ColdBoot) {
    use core::fmt::Write;
    if !display_engines_requested() {
        return;
    }
    match boot.arm_display_hpd() {
        Ok(subscription) => {
            narf_scheduler::spawn(crate::amdgpu_navi22_display::serve_hpd(
                subscription,
                |hpd| async move {
                    if let Some(boot) = OWNER.lock().await.as_mut() {
                        let _ = boot.display_hpd(hpd);
                    }
                    note_hpd_pulse(hpd);
                    crate::amdgpu_navi22_kms::wake();
                },
            ));
        }
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 HPD interrupts unavailable ({error:?}); polling"
            );
        }
    }
}

/// Display-engine opt-in (`amdgpu.native_display` / `amdgpu.display_probe`,
/// set by fb before `run`). Arming HPD programs the HPD/AUX/DDC engines, so
/// a firmware-only boot (the default) leaves them as the GOP left them.
static DISPLAY_ENGINES: AtomicBool = AtomicBool::new(false);
pub fn set_display_engines(enabled: bool) {
    DISPLAY_ENGINES.store(enabled, Ordering::Release);
}
pub(crate) fn display_engines_requested() -> bool {
    DISPLAY_ENGINES.load(Ordering::Acquire)
}

/// TDR sample of every verified kernel queue, serialized with the owner.
pub(crate) async fn queue_progress(
) -> Result<alloc::vec::Vec<crate::amdgpu_navi22_tdr::Progress>, boot::Error> {
    // The sample reads only fence writeback memory and HDP_READ_CACHE_INVALIDATE
    // (`amdgpu_cp_navi22::progress`); HDP is outside GC. Like Linux's fence /
    // drm_sched timeout path it takes no GFXOFF reference, so an idle GPU is
    // not cycled through Disallow/AllowGfxOff every PERIOD_MS. The timeout
    // snapshot, which does read GC, keeps its lease (`gfx_hang_snapshot`).
    let mut owner = OWNER.lock().await;
    owner.as_mut().ok_or(boot::Error::Invalid)?.queue_progress()
}

/// Sample only after a graphics timeout. Unlike queue progress this reads GC
/// registers, so it holds a GFXOFF reference with the owner. The caller
/// prints after both guards drop.
pub(crate) async fn gfx_hang_snapshot(
) -> Result<crate::amdgpu_cp_navi22::GfxHangSnapshot, boot::Error> {
    let (_gc, mut owner) = gc_owner().await.map_err(|_| boot::Error::Invalid)?;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .gfx_hang_snapshot()
}

/// Recovery effects on the retained owner (see amdgpu_navi22_recovery).
struct Recovering<'a> {
    owner: &'a mut Option<boot::ColdBoot>,
    device: narf_bus::BusDevice,
    /// Every IH endpoint created so far: the old ring and, once built, the
    /// new owner's. Device loss closes all of them.
    interrupts: alloc::vec::Vec<crate::amdgpu_ih_navi22::Handle>,
}
impl crate::amdgpu_navi22_recovery::Backend for Recovering<'_> {
    fn check(&mut self) -> Result<(), crate::amdgpu_navi22_recovery::Error> {
        use crate::amdgpu_navi22_recovery::Error;
        match self.owner.as_ref() {
            Some(boot) if boot.recoverable() => Ok(()),
            Some(boot) if matches!(boot.state(), boot::State::FirmwareReady(_)) => {
                Err(Error::Unsupported)
            }
            _ => Err(Error::Busy),
        }
    }
    async fn quiesce(&mut self) -> Result<(), boot::Error> {
        // Recovery::run has accepted this owner. Rejection must leave client
        // admission, CPU console writers and power controls intact.
        crate::amdgpu_navi22_cs::unregister();
        console(true);
        crate::amdgpu_rdna2_power_controls::withdraw();
        crate::amdgpu_vcn_navi22::idle::stop();
        crate::amdgpu_navi22_tdr::stop();
        crate::amdgpu_navi22_thermal::stop();
        crate::amdgpu_navi22_power::stop(None);
        let boot = self.owner.as_mut().ok_or(boot::Error::Invalid)?;
        withdraw_for_reset(boot).await;
        if let Some(ih) = boot.interrupts() {
            self.interrupts.push(ih);
        }
        // SAFETY: recover()'s caller accepted the whole-device contract.
        unsafe { boot.quiesce_for_reset() }.await?;
        crate::amdgpu_fence_navi22::abandon_all();
        Ok(())
    }
    async fn reinitialize(&mut self) -> Result<boot::Report, boot::Error> {
        let old = self.owner.take().ok_or(boot::Error::Invalid)?;
        // SAFETY: quiesce completed; probe's PCI function for this GPU.
        let new = unsafe { old.into_recovery(self.device) }?;
        if let Some(ih) = new.interrupts() {
            self.interrupts.push(ih);
        }
        // Retained before running, so cancellation keeps the new owner.
        let boot = self.owner.insert(new);
        boot.run().await
    }
    async fn restart(&mut self) {
        if let Some(boot) = self.owner.as_mut() {
            start_services(boot).await;
        }
        relight_after_recovery();
    }
    fn lose(&mut self) {
        crate::amdgpu_vcn_navi22::idle::stop();
        crate::amdgpu_navi22_gfxoff::device_lost();
        crate::amdgpu_navi22_cs::abandon(narf_filesystem::FsError::NoDevice);
        crate::amdgpu_navi22_tdr::stop();
        crate::amdgpu_navi22_thermal::stop();
        crate::amdgpu_navi22_power::stop(Some(crate::amdgpu_smu_navi22::Error::DeviceGone));
        crate::amdgpu_fence_navi22::abandon_all();
        for ih in &self.interrupts {
            ih.close(crate::amdgpu_ih_navi22::Closed::DeviceLost);
        }
    }
}

/// Pauses (`true`) and resumes (`false`) every kernel CPU writer of the boot
/// framebuffer; installed by the fb owner.
type ConsoleHook = fn(bool);
static CONSOLE_HOOK: narf_lib::sync::IrqSafeSpinLock<Option<ConsoleHook>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
/// Install the hook [`recover`] uses to keep kernel CPU writers off this
/// card's framebuffer while it resets.
pub fn set_recovery_console_hook(hook: ConsoleHook) {
    *CONSOLE_HOOK.lock() = Some(hook);
}
fn console(pause: bool) {
    let hook = *CONSOLE_HOOK.lock();
    if let Some(hook) = hook {
        hook(pause);
    }
}

/// Device recovery (Linux `amdgpu_device_gpu_recover`, mode1), triggered by
/// the hang detector when `amdgpu_navi22_tdr::set_automatic_recovery` is on
/// (the RX 6000 default; `amdgpu.gpu_recovery=0` turns it off). Quiesces the services and IH, abandons every fence wait,
/// mode1-resets the ASIC and re-runs the complete cold-boot bring-up on a
/// fresh owner (DMUB restarted as on cold boot), then restarts telemetry,
/// thermal and TDR. The native display is withdrawn and stopped first and,
/// once `recoveries()` increments, relit by the display monitor. Failure or cancellation
/// reports the device lost to every waiter. Not hardware-validated.
///
/// # Safety
/// All in-flight kernel-queue work is abandoned; no CPU writer or reader of
/// this card's VRAM or framebuffer may run until this returns; no other
/// owner of the PCI function, its MSI-X table or config space may exist; and
/// each successful recovery leaks the old owners' quarantined VRAM.
pub async unsafe fn recover() -> Result<boot::Report, crate::amdgpu_navi22_recovery::Error> {
    use crate::amdgpu_navi22_recovery::Error;
    let mut recovery = RECOVERY.try_lock().ok_or(Error::Busy)?;
    let device = amdgpu::pci_device().ok_or(Error::Busy)?;
    let result = {
        let mut owner = OWNER.lock().await;
        let mut backend = Recovering {
            owner: &mut owner,
            device,
            interrupts: alloc::vec::Vec::new(),
        };
        recovery.run(&mut backend).await
    };
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 GPU recovery {result:?}"
    );
    if result.is_ok() {
        // The fresh owner runs without the previous power-saving opt-in and
        // at automatic GFXCLK limits; publish what it really runs.
        *REQUESTED.lock() = crate::amdgpu_navi22_power_policy::OptIn::NONE;
        crate::amdgpu_rdna2_power_controls::publish().await;
        console(false);
    }
    // A lost device keeps the console quarantined, as a failed boot does.
    result
}

// ── Suspend / resume (#1760) ────────────────────────────────────────────
//
// Runtime suspend keeps the retained owner: the rings drain, the services
// withdraw and the display stops, the GFXOFF controller (armed by the boot
// power-saving application) powers GC down, and the PCI layer moves the
// function to D3hot. Resume re-enables GC for the resume work, restarts
// the services and relights the display. IH is never disabled on this
// path — `Ih::disable` leaves the ring quarantined with no re-arm — so
// there is no owner rebuild to pay for.
//
// System (S3) suspend goes through the recovery shape instead: the
// console pauses and IH is disabled, and resume rebuilds the owner with
// `into_recovery`, as recovery does. That rebuild needs a recoverable
// owner; a trained GDDR6 owner is one once its trainer finished, because
// `into_recovery` retains the trainer and replays its cache
// (`PSP_MEM_TRAIN_RESUME`) before SOS loads, so S3 no longer refuses on
// trained hardware. An owner whose trainer never finished, failed, or was
// cancelled mid-replay still refuses rather than suspending into a lost
// device. Runtime suspend has no such gate: the retained owner is all it
// needs.
//
// D3hot may reset engine registers (IH ring pointers, queue doorbells)
// that only a fresh owner re-initializes; if the hardware run shows lost
// interrupts or stalled rings after a runtime resume, the resume must
// rebuild the owner — which needs GDDR6 retention first.

/// How long suspend waits for submitted jobs (the GFX job timeout).
const RING_DRAIN_MS: u64 = 10_000;

/// Whether every ring's submitted jobs completed within `ms`, polling the
/// fence progress each millisecond. True without queues; false when the
/// owner is gone or not firmware-ready (suspend refuses).
async fn rings_idle(ms: u64) -> bool {
    let deadline = narf_time::Deadline::after_ms(ms);
    loop {
        match queue_progress().await {
            Ok(samples) => {
                if samples
                    .iter()
                    .all(|p| crate::amdgpu_fence_navi22::signaled(p.signaled, p.emitted))
                {
                    return true;
                }
            }
            Err(_) => return false,
        }
        if deadline.expired() {
            return false;
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
    }
}

/// A withdrawn owner between quiesce and resume.
struct Suspended {
    /// IH endpoints collected at quiesce; closed with DeviceLost if the
    /// resume fails (the ring is quarantined on success, as in recovery).
    interrupts: alloc::vec::Vec<crate::amdgpu_ih_navi22::Handle>,
    /// Runtime (GFXOFF + D3hot, retained owner) vs system (S3, rebuilt owner).
    runtime: bool,
}
static SUSPENDED: narf_lib::sync::IrqSafeSpinLock<Option<Suspended>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The running owner's PCI function and device authority.
pub(crate) async fn pci_function() -> Option<(
    narf_bus::BusDevice,
    narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
)> {
    OWNER.lock().await.as_ref()?.pci_function()
}

/// Whether PMFW's running feature mask carries `FEATURE_GFXOFF`: the
/// chip/PMFW can gate GC, as `EnableAllSmuFeatures` enables it at SMU
/// init. The capability signal for `amdgpu_navi22_runtime_pm::detect_mode`.
pub async fn gfxoff_available() -> bool {
    running_features()
        .await
        .is_ok_and(|mask| mask & crate::amdgpu_navi22_power_policy::SMU_GFXOFF != 0)
}

/// Whether the boot power-saving application admitted GFXOFF: the SMU bit
/// is enabled and the GFXOFF controller runs. Checked by
/// `amdgpu_navi22_runtime_pm::register` before it registers the PCI device.
pub async fn gfxoff_armed() -> bool {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .and_then(|boot| boot.power_saving())
        .is_some_and(|applied| applied.plan.policy.gfxoff())
}

/// Whether the native display stack is up (so the runtime-PM `CONNECTED`
/// state is published rather than scanned): display engines were
/// requested and a modeset state is retained.
pub fn native_display_running() -> bool {
    display_engines_requested() && modeset_state().is_some()
}

/// Discover board sinks for runtime suspend (`None`: no display information).
pub(crate) async fn scan_connected() -> Option<bool> {
    let reports = detect_displays().await.ok()?;
    Some(reports.iter().any(|r| {
        matches!(
            r.detection,
            crate::amdgpu_navi22_display::Detection::Connected(_)
        )
    }))
}

/// The S3 and runtime suspend shared by [`prepare_suspend`] and
/// [`runtime_suspend`]; `runtime` selects the retained-owner form.
/// Cancellation rolls the card back through [`resume_gated`], as
/// `amdgpu_navi48_platform::suspend_device` does.
///
/// # Safety
/// As [`prepare_suspend`].
async unsafe fn suspend_device(
    runtime: bool,
    reference: Option<SystemPmReference>,
) -> Result<(), boot::Error> {
    let cancelled = alloc::sync::Arc::new(AtomicBool::new(false));
    let observe = cancelled.clone();
    let operation = async move {
        let _transition = RECOVERY.lock().await;
        if observe.load(Ordering::Acquire) {
            return Err(boot::Error::Busy);
        }
        // SAFETY: the caller transfers its exclusions to the retained
        // operation; cancellation requests rollback without cancelling MMIO.
        let result = unsafe { suspend_gated(runtime) }.await;
        if result.is_ok() {
            if observe.load(Ordering::Acquire) {
                // Resume now owns the parked device. Do not let this guard's
                // later Drop clear a newer transition's state after resume
                // has restored the card.
                if let Some(reference) = reference {
                    reference.park();
                }
                // SAFETY: this operation parked the device; the system has
                // not entered S3/D3.
                let _ = unsafe { resume_gated(runtime) }.await;
            } else if let Some(reference) = reference {
                reference.park();
            }
        }
        result
    };
    crate::suspend_transition::Retained::new(operation, cancelled, |cleanup| {
        narf_scheduler::spawn(cleanup);
    })
    .await
}

/// `suspend_device` with the rings drained and the services withdrawn.
///
/// # Safety
/// As [`prepare_suspend`].
async unsafe fn suspend_gated(runtime: bool) -> Result<(), boot::Error> {
    if SUSPENDED.lock().is_some() {
        return Err(boot::Error::Busy);
    }
    if !runtime {
        // Refuse before touching hardware state: an owner whose trainer
        // never finished, failed, or was cancelled mid-replay cannot be
        // rebuilt (see `ColdBoot::recoverable`), so an S3 resume could not
        // restore it.
        let owner = OWNER.lock().await;
        if owner.as_ref().is_none_or(|boot| !boot.recoverable()) {
            return Err(boot::Error::Busy);
        }
    }
    // New submissions must stop before the drain means anything; the drain
    // samples fences, so a job submitted after it would be cancelled by
    // the unregister instead of awaited. The window is one poll period.
    if !rings_idle(RING_DRAIN_MS).await {
        return Err(boot::Error::Busy);
    }
    if !runtime {
        console(true);
    }
    crate::amdgpu_navi22_cs::unregister();
    crate::amdgpu_rdna2_power_controls::withdraw();
    crate::amdgpu_vcn_navi22::idle::stop();
    crate::amdgpu_navi22_tdr::stop();
    crate::amdgpu_navi22_thermal::stop();
    crate::amdgpu_navi22_power::stop(None);
    let interrupts = {
        let mut owner = OWNER.lock().await;
        let boot = owner.as_mut().ok_or(boot::Error::Invalid)?;
        withdraw_for_reset(boot).await;
        let mut interrupts = alloc::vec::Vec::new();
        if let Some(ih) = boot.interrupts() {
            interrupts.push(ih);
        }
        if !runtime {
            // SAFETY: the caller accepted the whole-device contract; S3
            // discards PMFW's GFXOFF state, as a reset does.
            unsafe { boot.quiesce_for_reset() }.await?;
        }
        interrupts
    };
    // Jobs submitted between the drain sample and the unregister above are
    // cancelled rather than hung: the submitter is gone and nothing will
    // signal their fences.
    crate::amdgpu_fence_navi22::abandon_all();
    *SUSPENDED.lock() = Some(Suspended {
        interrupts,
        runtime,
    });
    Ok(())
}

/// Linux `amdgpu_pmops_runtime_suspend` for GFXOFF after the runtime-PM
/// checks: drain the rings (amdgpu_fence_wait_empty, bounded here), then
/// quiesce the services and withdraw the display without pausing the
/// console, and park. The GFXOFF controller — armed by the boot
/// power-saving application — powers GC down once its references drain;
/// the PCI layer then saves config state and moves the function to D3hot.
/// A drain timeout is `Busy` with the device running. After success only
/// [`runtime_resume`] may touch the card.
///
/// # Safety
/// As [`prepare_suspend`]. The caller (runtime PM) proved no display is lit
/// and holds no console writer on this GPU's VRAM.
pub async unsafe fn runtime_suspend() -> Result<(), boot::Error> {
    // SAFETY: forwarded contract.
    unsafe { suspend_device(true, None) }.await
}

/// S3 through the async system-PM phase: drain, quiesce and park (see
/// [`runtime_suspend`]), pausing the console and disabling IH as recovery
/// does. Refuses when the owner is not recoverable — including a trained
/// owner whose trainer never finished (see `ColdBoot::recoverable`). A
/// finished trainer is retained across the rebuild and replayed
/// (`PSP_MEM_TRAIN_RESUME`) before SOS loads, so S3 no longer refuses on
/// trained hardware.
///
/// # Safety
/// As [`recover`]: no external CPU mapping user, PCI or firmware owner may
/// touch the card until resume. Runs from the async system-PM prepare phase.
/// After cancellation the same exclusions persist while executor cleanup
/// completes; a failed resume retains the device's quarantine.
pub async unsafe fn prepare_suspend() -> Result<(), boot::Error> {
    // SAFETY: forwarded contract.
    unsafe { suspend_device(false, None) }.await
}

/// Rebuild or restart the parked owner. Runtime resume keeps the retained
/// owner (IH was never disabled); system resume rebuilds it, as recovery
/// does. A failure is terminal, as a failed recovery.
///
/// # Safety
/// As [`prepare_suspend`]; the parked suspend came from [`suspend_device`].
pub async unsafe fn resume_from_suspend() -> Result<(), boot::Error> {
    // SAFETY: forwarded contract.
    unsafe { resume_device(false) }.await
}

/// Linux `amdgpu_pmops_runtime_resume` for GFXOFF, after the PCI layer
/// restored D0 and the config header: restart the services and relight
/// the display on the retained owner.
///
/// # Safety
/// As [`resume_from_suspend`]; the parked suspend came from
/// [`runtime_suspend`].
pub async unsafe fn runtime_resume() -> Result<(), boot::Error> {
    // SAFETY: forwarded contract.
    unsafe { resume_device(true) }.await
}

async unsafe fn resume_device(runtime: bool) -> Result<(), boot::Error> {
    let operation = async move {
        let _transition = RECOVERY.lock().await;
        // SAFETY: resume's caller transfers its exclusions to the retained
        // operation, so dropping the wait cannot drop the hardware owner.
        unsafe { resume_gated(runtime) }.await
    };
    crate::suspend_transition::Retained::new(
        operation,
        alloc::sync::Arc::new(AtomicBool::new(false)),
        |cleanup| {
            narf_scheduler::spawn(cleanup);
        },
    )
    .await
}

/// Resume while the retained operation holds RECOVERY.
async unsafe fn resume_gated(runtime: bool) -> Result<(), boot::Error> {
    let mut suspended = {
        let mut parked = SUSPENDED.lock();
        if parked.as_ref().is_none_or(|s| s.runtime != runtime) {
            return Err(boot::Error::Busy);
        }
        parked.take().unwrap()
    };
    // SAFETY: parked by `suspend_device` with the matching flavor.
    let result = if runtime {
        // SAFETY: the parked state was written by `runtime_suspend`
        // (matching flavor checked above); the retained operation holds
        // RECOVERY for the whole resume.
        unsafe { resume_retained() }.await
    } else {
        // SAFETY: the parked state was written by `prepare_suspend`
        // (matching flavor checked above); the retained operation holds
        // RECOVERY for the whole resume.
        unsafe { resume_rebuilt(&mut suspended) }.await
    };
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 {}resume {:?}",
        if runtime { "runtime " } else { "" },
        result.as_ref().map(|_| ())
    );
    if result.is_err() {
        lose_suspended(&mut suspended);
    } else if !runtime {
        // A lost device keeps the console quarantined, as a failed recovery does.
        console(false);
    }
    result
}

/// Restart the retained owner: GC stays powered for the resume work, then
/// gates again when idle; the reference is inert while GFXOFF is off.
///
/// # Safety
/// Parked by [`runtime_suspend`].
async unsafe fn resume_retained() -> Result<(), boot::Error> {
    // Must not be awaited while holding the platform owner lock.
    let _gc = crate::amdgpu_navi22_gfxoff::Reference::acquire().await.ok();
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(boot::Error::Invalid)?;
    start_services(boot).await;
    relight_after_recovery();
    // The boot power-saving application was never removed (suspend does
    // not undo it), so nothing is re-applied here: a remove would stop
    // the GFXOFF controller for the rest of the boot.
    Ok(())
}

/// Rebuild the owner, as recovery does: mode1 reset, fresh owner, full
/// bring-up, then services and the display. VRAM contents are lost, as in
/// recovery (user mappings are not revoked).
///
/// # Safety
/// Parked by [`prepare_suspend`].
async unsafe fn resume_rebuilt(suspended: &mut Suspended) -> Result<(), boot::Error> {
    let device = amdgpu::pci_device().ok_or(boot::Error::Busy)?;
    let mut owner = OWNER.lock().await;
    let old = owner.take().ok_or(boot::Error::Invalid)?;
    // SAFETY: quiesce completed; probe's PCI function for this GPU.
    let new = match unsafe { old.into_recovery(device) } {
        Ok(new) => new,
        Err(error) => return Err(error),
    };
    if let Some(ih) = new.interrupts() {
        suspended.interrupts.push(ih);
    }
    // Retained before running, so cancellation keeps the new owner.
    let boot = owner.insert(new);
    boot.run().await?;
    start_services(boot).await;
    relight_after_recovery();
    drop(owner);
    // Best effort, as in `resume_retained`.
    // SAFETY: `boot.run()` succeeded above, so the boot published these
    // controls; `start_services` started the GC MMIO clients (CS/TDR),
    // which take a GFXOFF reference; the OWNER lock was dropped just
    // above and this task holds no lock the platform takes.
    if let Err(error) = unsafe { replace_power_saving(requested_power_saving()) }.await {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 resume: power saving not re-applied: {error:?}"
        );
    }
    Ok(())
}

/// A failed resume loses the device, as a failed recovery does.
fn lose_suspended(suspended: &mut Suspended) {
    crate::amdgpu_vcn_navi22::idle::stop();
    crate::amdgpu_navi22_gfxoff::device_lost();
    crate::amdgpu_navi22_cs::abandon(narf_filesystem::FsError::NoDevice);
    crate::amdgpu_navi22_tdr::stop();
    crate::amdgpu_navi22_thermal::stop();
    crate::amdgpu_navi22_power::stop(Some(crate::amdgpu_smu_navi22::Error::DeviceGone));
    crate::amdgpu_fence_navi22::abandon_all();
    for ih in &suspended.interrupts {
        ih.close(crate::amdgpu_ih_navi22::Closed::DeviceLost);
    }
    suspended.interrupts.clear();
}

/// device_prepare's reference follows its retained suspend through a
/// cancellation rollback. Only an accepted suspend hands it to resume.
struct SystemPmReference {
    held: bool,
}
impl SystemPmReference {
    fn park(mut self) {
        self.held = false;
    }
}
impl Drop for SystemPmReference {
    fn drop(&mut self) {
        if self.held {
            crate::amdgpu_navi22_runtime_pm::system_complete();
        }
    }
}

struct SystemPm;
impl narf_power::system_pm::AsyncSystemPm for SystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            // device_prepare: a runtime-PM reference for the transition,
            // resuming a runtime-suspended card first (pci_pm_prepare).
            let reference = SystemPmReference { held: true };
            crate::amdgpu_navi22_runtime_pm::system_prepare().await;
            // SAFETY: register_system_pm's caller accepted the contract.
            unsafe { suspend_device(false, Some(reference)) }
                .await
                .map_err(|_| narf_power::device_pm::DeviceSuspendError::Busy)
        })
    }
    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        alloc::boxed::Box::pin(async {
            let reference = SystemPmReference { held: true };
            // SAFETY: as above.
            // Retain device_complete together with resume: cancellation
            // cannot release its reference before the hardware is restored.
            let operation = async move {
                let _reference = reference;
                // SAFETY: register_system_pm accepted resume's exclusions;
                // the retained operation keeps them through cancellation.
                unsafe { resume_from_suspend() }
                    .await
                    .map_err(|_| narf_power::device_pm::DeviceSuspendError::DriverError)
            };
            crate::suspend_transition::Retained::new(
                operation,
                alloc::sync::Arc::new(AtomicBool::new(false)),
                |cleanup| {
                    narf_scheduler::spawn(cleanup);
                },
            )
            .await
        })
    }
}

/// Register Navi22 S3 with the async system-PM phase.
///
/// # Safety
/// The caller accepts [`prepare_suspend`]'s contract for every user, as
/// [`set_automatic_recovery`] does for recovery.
pub unsafe fn register_system_pm() {
    narf_power::system_pm::register_async_system_pm(
        "amdgpu-navi22",
        alloc::sync::Arc::new(SystemPm),
    );
}

/// ReenableAcDcInterrupt through the retained SMU owner.
pub(crate) async fn reenable_acdc() -> Result<(), crate::amdgpu_smu_navi22::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_smu_navi22::Error::Busy)?;
    boot.reenable_acdc().await.map_err(|error| match error {
        boot::Error::Smu(error) => error,
        _ => crate::amdgpu_smu_navi22::Error::Busy,
    })
}

/// One PMFW telemetry refresh, serialized with every retained owner user.
pub(crate) async fn power_sample() -> Result<crate::amdgpu_navi22_power::Sample, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .power_sample()
        .await
}

/// Faults logged before the service only counts them (Linux rate-limits
/// `gmc_v10_0_process_interrupt`'s report the same way).
const FAULT_LOG_LIMIT: u64 = 16; // linux: n/a (NARF policy)
static FAULTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Faults delivered to the service since boot.
pub fn fault_count() -> u64 {
    FAULTS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Start VM fault delivery after a completed boot: subscribe to the VMC and
/// UTCL2 sources, then unmask the GMC fault interrupts, and attribute every
/// entry through `Gmc::handle_fault` (`gmc_v10_0_process_interrupt`). Until
/// this runs, faults stay masked and only redirect to the default page.
pub async fn start_fault_service() -> Result<(), boot::Error> {
    use crate::amdgpu_ih_navi22::source;
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(boot::Error::Invalid)?;
    let ih = boot.interrupts().ok_or(boot::Error::Invalid)?;
    let mut subscriptions = alloc::vec::Vec::new();
    // Subscribe first so no fault raised after unmasking goes unclaimed.
    for from in [source::VMC_FAULT, source::UTCL2_FAULT] {
        subscriptions.push(ih.subscribe(from).map_err(boot::Error::Interrupts)?);
    }
    boot.memory()?
        .set_fault_interrupts(true)
        .map_err(boot::Error::MemoryHubs)?;
    drop(owner);
    for mut subscription in subscriptions {
        narf_scheduler::spawn(async move {
            while let Ok(iv) = subscription.wait().await {
                let Some(fault) = crate::amdgpu_gmc_navi22::Fault::from_iv(&iv) else {
                    continue;
                };
                let result = {
                    let mut owner = OWNER.lock().await;
                    owner
                        .as_mut()
                        .ok_or(boot::Error::Invalid)
                        .and_then(|boot| boot.memory())
                        .and_then(|gmc| gmc.handle_fault(fault).map_err(boot::Error::MemoryHubs))
                };
                let seen = FAULTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if seen < FAULT_LOG_LIMIT {
                    use core::fmt::Write;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi22 GPU page fault {fault:?} -> {result:?}"
                    );
                    // gfxhub_v2_1_print_l2_protection_fault_status.
                    let status = crate::amdgpu_vmid::fault(fault.pasid).status;
                    const CLIENTS: [&str; 18] = [
                        "CB/DB",
                        "Reserved",
                        "GE1",
                        "GE2",
                        "CPF",
                        "CPC",
                        "CPG",
                        "RLC",
                        "TCP",
                        "SQC (inst)",
                        "SQC (data)",
                        "SQG",
                        "Reserved",
                        "SDMA0",
                        "SDMA1",
                        "GCR",
                        "SDMA2",
                        "SDMA3",
                    ];
                    let cid = (status >> 9) & 0x1ff;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi22 GPU page fault status={status:#x} client={} walker={} permission={:#x} mapping={} rw={}",
                        CLIENTS.get(cid as usize).copied().unwrap_or("?"),
                        (status >> 1) & 7,
                        (status >> 4) & 0xf,
                        (status >> 8) & 1,
                        (status >> 18) & 1,
                    );
                }
            }
        });
    }
    Ok(())
}

/// IH dispatch endpoint of the retained owner (see amdgpu_ih_navi22).
pub async fn interrupts() -> Option<crate::amdgpu_ih_navi22::Handle> {
    OWNER.lock().await.as_ref()?.interrupts()
}

/// Detect every board connector over the native DCN3.0 AUX/DDC/HPD path.
/// Requires the completed, retained cold boot; reads sinks only.
pub async fn detect_displays(
) -> Result<alloc::vec::Vec<crate::amdgpu_navi22_display::Report>, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .detect_displays()
        .await
}

/// The retained native modeset's state, for diagnostics.
pub fn modeset_state() -> Option<crate::amdgpu_navi22_modeset::State> {
    OWNER.try_lock()?.as_ref()?.modeset_state()
}

/// Best effort: a busy owner skips the flush and buffered writes drain later.
fn flush_scanout() {
    if let Some(mut owner) = OWNER.try_lock() {
        if let Some(boot) = owner.as_mut() {
            let _ = boot.flush_display_scanout();
        }
    }
}

/// Opt-in native HDMI scanout (`amdgpu.native_display`): light the first
/// connected HDMI sink with a test pattern and publish it as the external
/// scanout, which moves the console there. The pipeline is retained.
///
/// # Safety
/// Boot-time, after a successful `run`; no other display client, and no CPU
/// writer of the new scanout except through the published framebuffer.
pub async unsafe fn modeset_hdmi() -> Result<crate::amdgpu_navi22_modeset::Output, boot::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(boot::Error::Invalid)?;
    // SAFETY: forwarded unchanged; serialized by the owner mutex.
    let output = unsafe { boot.modeset_hdmi().await }?;
    crate::amdgpu_dcn_display::publish_external(Some(output.scanout), Some(flush_scanout));
    Ok(output)
}

/// Serialized DMUB HPD query, refused unless DMUB AUX was explicitly allowed.
pub async fn dmub_hpd(instance: u8) -> Result<bool, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .dmub_hpd(instance)
        .await
}
/// Serialized DMUB AUX/I2C-over-AUX transaction, at most 16 bytes. Refused
/// unless DMUB AUX was explicitly allowed; native AUX is the default.
pub async fn dmub_aux(
    instance: u8,
    action: u8,
    address: u32,
    data: &mut [u8],
) -> Result<(), boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .dmub_aux(instance, action, address, data)
        .await
}
pub async fn dmub_notification() -> Result<Option<[u8; 64]>, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .dmub_notification()
}

// ── Native display: publication, flips, cursor and KMS ──────────────────
//
// The lit pipe's front buffer is the console's external scanout (CPU writes
// plus the HDP flush hook) and the KMS CRTC's primary plane. DRM frames are
// copied into the back buffer and flipped at VUPDATE; the console follows the
// front. Every teardown first withdraws the publication and waits for the
// retired CPU views (`scanout_access`), then stops presentation, then the
// pipeline. The display monitor converges the hardware to `amdgpu_navi22_kms`.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
type ScanError = crate::amdgpu_dcn_clk::Error;
use crate::amdgpu_navi22_scanout::ArmedKind;

/// Hardware cursor opt-in (`amdgpu.navi22_hw_cursor`): DML30 here does not
/// budget a cursor yet (Linux always budgets a 256-wide ARGB cursor), so the
/// default stays the software sprite.
static HW_CURSOR: AtomicBool = AtomicBool::new(false);
pub fn set_hw_cursor(enabled: bool) {
    HW_CURSOR.store(enabled, Ordering::Release);
}

/// Cursor hook published with the scanout: upload once, then move; hide with
/// an off-screen move. Never waits for the owner. False (software sprite)
/// while the hardware cursor is not enabled or nothing is lit.
fn scanout_cursor(image: (u32, u32, &[u32]), position: Option<(i32, i32)>) -> bool {
    // DRM's cursor plane owns the hardware cursor while a client drives it.
    if DRM_CURSOR_OWNED.load(Ordering::Acquire) {
        return true;
    }
    if !HW_CURSOR.load(Ordering::Acquire) {
        return false;
    }
    let Some(mut owner) = OWNER.try_lock() else {
        return true;
    };
    let Some(boot) = owner.as_mut() else {
        return false;
    };
    let (w, h, _) = image;
    let Ok(scanout) = boot.display_scanout() else {
        return false;
    };
    let shown = scanout
        .cursor()
        .is_some_and(|c| (c.width, c.height) == (w, h));
    // A failure leaves the cursor hidden; the pointer just stops.
    let _ = match (shown, position) {
        (false, None) => return true,
        (true, at) => scanout.move_cursor(at.unwrap_or((-(w as i32), -(h as i32)))),
        (false, Some(at)) => boot.set_display_cursor(image, at),
    };
    true
}

// ── DRM cursor plane (amdgpu_dm_crtc_init's DRM_PLANE_TYPE_CURSOR) ────

/// CRTC 0's DRM cursor plane as last committed: the image to show (None:
/// off) at CRTC_X/Y, and a GEM framebuffer whose rows are read once its
/// writes land. Kept apart from OWNER so a commit or move is recorded at
/// once and never dropped; the cursor task applies the latest state when it
/// next holds OWNER (amdgpu_dm_commit_cursors programs the cursor without
/// waiting for a vblank).
struct DrmCursor {
    image: Option<alloc::sync::Arc<crate::amdgpu_navi48_platform::CursorImage>>,
    pending: Option<crate::amdgpu_navi48_platform::GemCursor>,
    position: (i32, i32),
    dirty: bool,
    running: bool,
}
static DRM_CURSOR: narf_lib::sync::IrqSafeSpinLock<DrmCursor> =
    narf_lib::sync::IrqSafeSpinLock::new(DrmCursor {
        image: None,
        pending: None,
        position: (0, 0),
        dirty: false,
        running: false,
    });
/// A DRM client drives the hardware cursor (the console's pointer stays off
/// it until lastclose).
static DRM_CURSOR_OWNED: AtomicBool = AtomicBool::new(false);

/// Record a DRM cursor plane commit on display `display` and have the
/// cursor task program it. Navi22 presents on display 0 only.
pub(crate) fn request_display_cursor(
    display: u8,
    content: Option<crate::amdgpu_navi48_platform::CursorContent>,
    position: (i32, i32),
) -> bool {
    if display != 0 {
        return false;
    }
    let spawn = {
        let mut c = DRM_CURSOR.lock();
        DRM_CURSOR_OWNED.store(true, Ordering::Release);
        record_cursor(&mut c, content, position);
        !core::mem::replace(&mut c.running, true)
    };
    if spawn {
        narf_scheduler::spawn(drm_cursor_task());
    }
    true
}

/// The new cursor state of a commit: a dumb buffer's image as is, a GEM
/// framebuffer's once read, off, and the position in every case.
fn record_cursor(
    c: &mut DrmCursor,
    content: Option<crate::amdgpu_navi48_platform::CursorContent>,
    position: (i32, i32),
) {
    use crate::amdgpu_navi48_platform::CursorContent;
    match content {
        Some(CursorContent::Gem(gem)) => c.pending = Some(gem),
        Some(CursorContent::Image(image)) => {
            c.pending = None;
            if c.image.as_deref() != Some(&image) {
                c.image = Some(alloc::sync::Arc::new(image));
            }
        }
        None => {
            c.pending = None;
            c.image = None;
        }
    }
    c.position = position;
    c.dirty = true;
}

async fn drm_cursor_task() {
    loop {
        let pending = {
            let mut c = DRM_CURSOR.lock();
            if !c.dirty {
                c.running = false;
                return;
            }
            c.dirty = false;
            c.pending.clone()
        };
        // A GEM cursor: its writes land first (the commit's fence wait),
        // then its rows become the image, unless a newer commit replaced it.
        if let Some(gem) = pending {
            let deadline =
                narf_time::Deadline::after_ms(crate::amdgpu_navi48_platform::CURSOR_FENCE_WAIT_MS);
            let resv = &gem.pin.object().dma_buf().resv;
            while !resv
                .fences(narf_filesystem::dma_buf::DmaResvUsage::Write)
                .is_empty()
                && !deadline.expired()
            {
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
            }
            let image = gem.read();
            let mut c = DRM_CURSOR.lock();
            if c.pending.as_ref().is_some_and(|p| p.same(&gem)) {
                c.pending = None;
                c.image = image.map(alloc::sync::Arc::new);
            }
        }
        let mut owner = OWNER.lock().await;
        if let Some(boot) = owner.as_mut() {
            apply_drm_cursor(boot);
        }
    }
}

/// Program the lit pipe's DCN30 cursor with the DRM cursor state: the image
/// (uploaded when it changed) at its position, or off.
fn apply_drm_cursor(boot: &mut boot::ColdBoot) {
    if !DRM_CURSOR_OWNED.load(Ordering::Acquire) {
        return;
    }
    let (image, position) = {
        let c = DRM_CURSOR.lock();
        (c.image.clone(), c.position)
    };
    match image {
        Some(i) => {
            let _ = boot.set_display_cursor((i.width, i.height, &i.pixels), position);
        }
        None => {
            if let Ok(scanout) = boot.display_scanout() {
                let _ = scanout.hide_cursor();
            }
        }
    }
}

/// Lastclose: the cursor plane's client is gone; the console's pointer
/// may use the hardware cursor again.
fn release_drm_cursor() {
    let mut c = DRM_CURSOR.lock();
    c.image = None;
    c.pending = None;
    c.dirty = true;
    DRM_CURSOR_OWNED.store(false, Ordering::Release);
}

/// Put the console on the lit pipe's front buffer, or withdraw it.
fn publish_console(boot: &boot::ColdBoot) {
    match boot.display_scanout_ref().map(|s| s.front().fb) {
        Some(fb) => {
            crate::amdgpu_dcn_display::publish_external(Some(fb), Some(flush_scanout));
            crate::amdgpu_dcn_display::publish_external_cursor(Some(scanout_cursor));
        }
        None => crate::amdgpu_dcn_display::publish_external(None, None),
    }
}

/// Stop presenting on the lit pipe: no more native frames, the console off
/// its buffers, and every retired CPU view drained.
async fn withdraw(boot: &boot::ColdBoot) {
    PRESENT.native.store(false, Ordering::Release);
    PRESENT.damage.lock().forget();
    *PRESENT.geometry.lock() = None;
    *PLANE_BASIS.lock() = None;
    if let Some(s) = boot.display_scanout_ref() {
        let ours = |addr| {
            [Some(s.front()), s.back()]
                .iter()
                .flatten()
                .any(|b| b.fb.addr == addr)
        };
        if crate::amdgpu_dcn_display::active_scanout().is_some_and(|fb| ours(fb.addr)) {
            crate::amdgpu_dcn_display::publish_external(None, None);
        }
    }
    crate::scanout_access::wait_retired().await;
}

/// Recompute every detected sink's offers and the KMS inventory: the
/// DCN30-admitted EDID timings (once admission inputs exist), a DP sink's
/// bounded by its verified link or, until verified, its receiver caps.
/// Dark and disabled connectors keep their EDID and modes, as Linux keeps
/// a connected connector's modes whatever its CRTC does.
fn reconcile_displays(boot: &mut boot::ColdBoot, reports: &[crate::amdgpu_navi22_display::Report]) {
    use crate::amdgpu_navi22_display::Detection;
    use crate::amdgpu_navi22_modeset::offered_on;
    let soc = boot
        .display_admitted()
        .map(|a| (a.soc, a.soc.dentist_vco_khz));
    let links: alloc::vec::Vec<_> = reports
        .iter()
        .enumerate()
        .map(|(i, r)| match &r.detection {
            Detection::Connected(sink) => boot.display_link_cap(i, sink.dpcd),
            _ => None,
        })
        .collect();
    crate::amdgpu_navi22_kms::KMS
        .lock()
        .reconcile_sinks(reports, |port, sink| {
            let i = reports.iter().position(|r| r.connector == *port)?;
            soc.map(|(soc, vco)| offered_on(sink, &soc, vco, links[i]))
        });
    {
        let mut kms = crate::amdgpu_navi22_kms::KMS.lock();
        for (index, connector) in kms.connectors.iter_mut().enumerate() {
            connector.hdmi_limits = boot.display_hdmi_limits(&connector.port);
            connector.vrr = boot.hdmi_vrr_caps(index);
            // A DP sink's FreeSync range from its EDID and the DPCD caps
            // detection read (`dp_sst_caps`); HDMI sinks keep `vrr`.
            connector.dp_vrr = match reports.get(index).map(|r| &r.detection) {
                Some(Detection::Connected(sink)) => sink
                    .dpcd
                    .and_then(|dpcd| crate::amdgpu_freesync::dp_sst_caps(&sink.edid, &dpcd)),
                _ => None,
            };
        }
    }
    // What the sinks' HPD looked like at this detection.
    let senses = boot.display_hpd_senses();
    let mut last = SENSES.lock();
    for (slot, sense) in last
        .iter_mut()
        .zip(senses.iter().chain(core::iter::repeat(&None)))
    {
        *slot = *sense;
    }
}

/// Detect, route and light the CRTC per `amdgpu_navi22_kms`, filling rows
/// with `draw` before fetch, then present: back buffer, vblank, console, KMS.
/// # Safety
/// As for `modeset_displays`.
async unsafe fn light(
    boot: &mut boot::ColdBoot,
    draw: impl Fn(u32, &mut [u32]),
) -> Result<crate::amdgpu_navi22_modeset::Output, boot::Error> {
    use crate::amdgpu_navi22_display::Detection;
    use crate::amdgpu_navi22_kms::{Action, KMS};
    use crate::amdgpu_navi22_modeset::Error as M;
    let reports = boot.detect_displays().await?;
    reconcile_displays(boot, &reports);
    let action = {
        let mut kms = KMS.lock();
        kms.assign_route();
        let action = kms.next(None);
        if let Action::Light { route, want } = action {
            kms.attempted = Some((route, want));
        }
        action
    };
    let Action::Light { route, want } = action else {
        crate::amdgpu_navi22_kms::publish();
        return Err(boot::Error::Modeset(M::NoSink));
    };
    let (connector, sink) = match reports.get(route).map(|r| (&r.connector, &r.detection)) {
        Some((c, Detection::Connected(sink))) => (*c, sink.clone()),
        _ => return Err(boot::Error::Modeset(M::NoSink)),
    };
    let output_settings = KMS.lock().connectors[route].output;
    // SAFETY: the caller's obligations.
    let result =
        unsafe { boot.modeset_display(connector, &sink, want, output_settings, draw) }.await;
    // Admission inputs (and a DP sink's verified link) exist now, lit or
    // not: offer what they admit.
    reconcile_displays(boot, &reports);
    {
        let mut kms = KMS.lock();
        kms.crtc.shown = None;
        *LIT_SINK.lock() = result.is_ok().then(|| (route, sink.clone()));
        if let Ok(output) = result.as_ref() {
            kms.connectors[route].shown_output = output_settings;
            kms.connectors[route].color_relight = false;
            let edid = sink
                .edid
                .get(..128)
                .and_then(|e| <[u8; 128]>::try_from(e).ok());
            if let Some(edid) = edid {
                let offered = kms.connectors[route].modes.clone();
                kms.crtc.shown = Some((edid, output.timing, offered));
            }
        }
    }
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            crate::amdgpu_navi22_kms::publish();
            return Err(error);
        }
    };
    // Without a back buffer (allocation failed) DRM frames fall back to
    // copies onto the visible front.
    let back = boot.prepare_display_back_buffer().await;
    PRESENT.damage.lock().forget();
    // The new pipeline fetches its owned activation surface.
    let released = PRESENT.shown.lock().latched_owned();
    // Unpinned outside the IRQ-safe lock.
    drop(released);
    *PRESENT.geometry.lock() = boot.display_scanout_ref().map(|s| s.front().fb);
    *PLANE_BASIS.lock() = boot.display_plane_basis();
    PRESENT.native.store(back.is_ok(), Ordering::Release);
    restart_vblank();
    publish_console(boot);
    crate::amdgpu_navi22_kms::publish();
    let delta = crate::amdgpu_navi22_runtime_pm::displays_changed(1 << (route & 7), true);
    crate::amdgpu_navi22_runtime_pm::apply_display_refs(delta);
    if back.is_ok() {
        present_committed_again();
    }
    // A relit pipe starts without a cursor.
    apply_drm_cursor(boot);
    Ok(output)
}

/// Withdraw and tear the lit pipe down.
/// # Safety
/// As for `modeset_displays`.
async unsafe fn unlight(boot: &mut boot::ColdBoot) -> Result<(), boot::Error> {
    withdraw(boot).await;
    // SAFETY: the publication is withdrawn and every CPU view retired.
    let result = unsafe { boot.stop_display() }.await;
    if result.is_ok() {
        // The stopped HUBP fetches nothing.
        let released = PRESENT.shown.lock().latched_owned();
        // Unpinned outside the IRQ-safe lock.
        drop(released);
    }
    crate::amdgpu_navi22_kms::KMS.lock().crtc.shown = None;
    crate::amdgpu_navi22_kms::publish();
    let delta = crate::amdgpu_navi22_runtime_pm::displays_changed(0, false);
    crate::amdgpu_navi22_runtime_pm::apply_display_refs(delta);
    result
}

/// Light the board's HDMI sink per KMS (preferred mode, automatic route on
/// first use), filling rows with `draw` before fetch starts, and publish it:
/// the console on its front buffer, KMS on the amdgpu card.
///
/// # Safety
/// Boot-time or monitor context after a successful `run`; no other display
/// client, and no CPU writer of the scanout except through the publication.
pub async unsafe fn modeset_displays(
    draw: impl Fn(u32, &mut [u32]),
) -> Result<crate::amdgpu_navi22_modeset::Output, boot::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(boot::Error::Invalid)?;
    // SAFETY: forwarded; serialized by the owner mutex.
    unsafe { light(boot, draw) }.await
}

/// Poll period of the display monitor; DRM requests and recoveries wake it
/// within `MONITOR_STEP_MS`.
const MONITOR_MS: u64 = 1000; // linux: n/a (NARF policy)
const MONITOR_STEP_MS: u64 = 50; // linux: n/a (NARF policy)
static MONITOR: AtomicBool = AtomicBool::new(false);
/// Recoveries the display was last lit after.
static RELIT: AtomicU64 = AtomicU64::new(0);

/// HPD blocks whose long pulse (plug/unplug edge) the IH service saw
/// since the monitor's last pass; short pulses (HPD-RX) only wake it, as
/// each pass checks the lit DP link anyway.
static LONG_PULSES: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
/// Each board connector's debounced HPD at the last detection or pass.
static SENSES: narf_lib::sync::IrqSafeSpinLock<[Option<bool>; 6]> =
    narf_lib::sync::IrqSafeSpinLock::new([None; 6]);
static HDMI_LINKS: narf_lib::sync::IrqSafeSpinLock<[crate::amdgpu_dcn30_hdmi::LinkMonitor; 6]> =
    narf_lib::sync::IrqSafeSpinLock::new([crate::amdgpu_dcn30_hdmi::LinkMonitor::new(); 6]);
/// The route and sink the lit pipe was lit for, for the long-pulse
/// `same_edid` check.
static LIT_SINK: narf_lib::sync::IrqSafeSpinLock<
    Option<(usize, crate::amdgpu_navi22_display::Sink)>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// `detect_link_and_local_sink`'s `same_edid`: after a long pulse with HPD
/// still high, a sink whose EDID (and, for DP, receiver capabilities) reads
/// back unchanged is the same sink, and the lit stream is kept
/// (`link_disconnect_remap(prev_sink)`). Anything else — a different EDID or
/// DPCD, a disconnect, a sink that cannot be read — is a new sink.
pub(crate) fn long_pulse_keeps_stream(
    lit: &crate::amdgpu_navi22_display::Sink,
    now: &crate::amdgpu_navi22_display::Detection,
) -> bool {
    match now {
        crate::amdgpu_navi22_display::Detection::Connected(sink) => {
            sink.edid == lit.edid && sink.dpcd == lit.dpcd
        }
        _ => false,
    }
}

fn note_hpd_pulse(hpd: crate::amdgpu_ih_navi22::Hpd) {
    if !hpd.rx && hpd.instance < 8 {
        LONG_PULSES.fetch_or(1 << hpd.instance, Ordering::AcqRel);
    }
}

/// What a monitor pass did, for its console line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorStep {
    /// One automatic relight per connection; subsequent sustained failures
    /// are reported without resetting healthy streams in the same context.
    HdmiLinkState(
        usize,
        crate::amdgpu_dcn30_hdmi::LinkAction,
        crate::amdgpu_dcn30_hdmi::LinkHealth,
    ),
    /// The lit sink's HPD fell: withdrawn and torn down without AUX/DDC.
    Unplugged(usize),
    /// A connector's sink appeared, left or was replaced: detected again.
    Reprobed(usize),
    /// The lit DP link lost lock and trained again (same setting).
    Retrained(crate::amdgpu_navi22_modeset::DpLink),
    /// Retraining failed: the display was stopped, to be lit again from a
    /// fresh verification (rate/lane fallback).
    RetrainFailed,
    /// The sink asked for an automated test (acknowledged, not run).
    AutomatedTest,
}

/// Apply live VRR controls under the same owner used for flips. No KMS
/// guard survives an await. Failure takes the existing safe relight path.
async fn converge_hdmi_vrr(boot: &mut boot::ColdBoot) {
    use crate::amdgpu_navi22_kms::{KMS, MAX_CRTCS};
    let updates: alloc::vec::Vec<_> = {
        let kms = KMS.lock();
        (0..MAX_CRTCS)
            .filter_map(|d| {
                let crtc = kms.crtc_at(d)?;
                let shown = crtc.shown.as_ref()?;
                let n = crtc.route?;
                let c = kms.connectors.get(n)?;
                (crtc.active
                    && crtc.requested.is_none_or(|t| t == shown.1)
                    && c.port.signal == crate::amdgpu_navi22_display::Signal::Hdmi
                    && !c.color_relight
                    && !c.output.needs_modeset(c.shown_output))
                .then_some((d, n, c.port, c.vrr, crtc.vrr_enabled))
            })
            .collect()
    };
    for (d, n, port, caps, enabled) in updates {
        let group = GROUP_CRTCS.lock().iter().position(|&crtc| crtc == d);
        if group.is_none() && d != 0 {
            continue;
        }
        if boot.configure_hdmi_vrr(group, caps, enabled).await.is_err() {
            let mut kms = KMS.lock();
            if let Some(c) = kms.connectors.get_mut(n).filter(|c| c.port == port) {
                c.color_relight = true;
                kms.attempted = None;
                kms.attempted_group = None;
            }
        }
    }
    let variable = boot.display_scanout_ref().is_some_and(|s| s.vrr_active());
    if let Some(clock) = VBLANK.lock().as_mut() {
        if clock.variable != variable {
            clock.raw = None;
            clock.variable = variable;
        }
    }
}

/// Apply live DP VRR controls under the same owner used for flips. No KMS
/// guard survives an await. Failure takes the existing safe relight path.
async fn converge_dp_vrr(boot: &mut boot::ColdBoot) {
    use crate::amdgpu_navi22_kms::{KMS, MAX_CRTCS};
    let updates: alloc::vec::Vec<_> = {
        let kms = KMS.lock();
        (0..MAX_CRTCS)
            .filter_map(|d| {
                let crtc = kms.crtc_at(d)?;
                let shown = crtc.shown.as_ref()?;
                let n = crtc.route?;
                let c = kms.connectors.get(n)?;
                (crtc.active
                    && crtc.requested.is_none_or(|t| t == shown.1)
                    && c.port.signal == crate::amdgpu_navi22_display::Signal::DisplayPort
                    && !c.color_relight
                    && !c.output.needs_modeset(c.shown_output))
                .then_some((d, n, c.port, c.dp_vrr, crtc.vrr_enabled))
            })
            .collect()
    };
    for (d, n, port, range, enabled) in updates {
        let group = GROUP_CRTCS.lock().iter().position(|&crtc| crtc == d);
        if group.is_none() && d != 0 {
            continue;
        }
        if boot.configure_dp_vrr(group, range, enabled).await.is_err() {
            let mut kms = KMS.lock();
            if let Some(c) = kms.connectors.get_mut(n).filter(|c| c.port == port) {
                c.color_relight = true;
                kms.attempted = None;
                kms.attempted_group = None;
            }
        }
    }
}

/// Metadata updates are serialized with the display owner. A newer request
/// arriving during the await remains pending: mark only the captured state
/// applied. A failed packet update requests the usual bounded relight.
async fn update_hdmi_metadata(boot: &mut boot::ColdBoot) {
    use crate::amdgpu_navi22_kms::{KMS, MAX_CRTCS};
    let updates: alloc::vec::Vec<_> = {
        let kms = KMS.lock();
        (0..MAX_CRTCS)
            .filter_map(|d| {
                let crtc = kms.crtc_at(d)?;
                crtc.shown.as_ref()?;
                let n = crtc.route?;
                let c = kms.connectors.get(n)?;
                // HDMI's DRM InfoFrame or DP's HDR metadata SDP, in place.
                (!c.color_relight
                    && c.output != c.shown_output
                    && !c.output.needs_modeset(c.shown_output))
                .then_some((d, n, c.port, c.output))
            })
            .collect()
    };
    for (d, n, port, settings) in updates {
        let group_stream = GROUP_CRTCS.lock().iter().position(|&crtc| crtc == d);
        if group_stream.is_none() && d != 0 {
            continue;
        }
        let result = boot.update_hdmi_metadata(group_stream, settings).await;
        let mut kms = KMS.lock();
        if let Some(c) = kms.connectors.get_mut(n).filter(|c| c.port == port) {
            if result.is_ok() {
                c.shown_output = settings;
            } else {
                c.color_relight = true;
                kms.attempted = None;
                kms.attempted_group = None;
            }
        }
    }
}

/// Converge each lit CRTC's committed color onto its running stream: the
/// display monitor programs what DRM asked for when it differs from what
/// the pipe last programmed (a fresh light starts in bypass and converges
/// here, within one monitor step). A newer request arriving during the
/// await remains pending: the pipe records only the captured program, so
/// the next pass converges the newer one. A failed program requests the
/// usual bounded relight.
async fn converge_crtc_color(boot: &mut boot::ColdBoot) {
    use crate::amdgpu_dcn30_color::same_program;
    use crate::amdgpu_navi22_kms::{KMS, MAX_CRTCS};
    let updates: alloc::vec::Vec<_> = {
        let kms = KMS.lock();
        (0..MAX_CRTCS)
            .filter_map(|d| {
                let crtc = kms.crtc_at(d)?;
                crtc.shown.as_ref()?;
                let n = crtc.route?;
                let c = kms.connectors.get(n)?;
                (crtc.active && !c.color_relight).then_some((d, n, c.port, crtc.color.clone()))
            })
            .collect()
    };
    for (d, n, port, want) in updates {
        let group_stream = GROUP_CRTCS.lock().iter().position(|&crtc| crtc == d);
        if group_stream.is_none() && d != 0 {
            continue;
        }
        if same_program(&boot.display_color(group_stream), &want) {
            continue;
        }
        if boot.set_display_color(group_stream, want).await.is_err() {
            let mut kms = KMS.lock();
            if let Some(c) = kms.connectors.get_mut(n).filter(|c| c.port == port) {
                c.color_relight = true;
                kms.attempted = None;
                kms.attempted_group = None;
            }
        }
    }
}

/// Linux's long-pulse path (`handle_hpd_irq` → `dc_link_detect` → a
/// zero-stream commit) and short-pulse path (`handle_hpd_rx_irq` →
/// `dp_handle_link_loss`) for the single lit pipe, before KMS convergence.
/// Returns the step taken; a teardown ends the pass.
/// # Safety
/// As for `modeset_displays`, with OWNER held.
async unsafe fn monitor_hotplug(
    boot: &mut boot::ColdBoot,
    running: Option<(usize, crate::amdgpu_dml::Timing)>,
) -> Option<Result<MonitorStep, boot::Error>> {
    use crate::amdgpu_navi22_display::Signal;
    use crate::amdgpu_navi22_kms::KMS;
    use crate::amdgpu_navi22_modeset::RxEvent;
    let long = LONG_PULSES.swap(0, Ordering::AcqRel);
    let senses = boot.display_hpd_senses();
    let ports: alloc::vec::Vec<_> = boot
        .display_connectors()
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    // 1. The lit sink left: no AUX/DDC to it, surfaces released, the
    //    connector disconnected (its EDID and modes gone).
    if let Some((route, _)) = running {
        if senses.get(route) == Some(&Some(false)) {
            HDMI_LINKS.lock()[route] = crate::amdgpu_dcn30_hdmi::LinkMonitor::new();
            withdraw(boot).await;
            // SAFETY: withdrawn and drained; serialized by OWNER.
            let result = unsafe { boot.stop_unplugged_display() }.await;
            {
                let mut kms = KMS.lock();
                kms.crtc.shown = None;
                if let Some(c) = kms.connectors.get_mut(route) {
                    c.present = false;
                    c.edid.clear();
                    c.modes.clear();
                    c.unadmitted = false;
                }
                kms.attempted = None;
                kms.assign_route();
            }
            SENSES.lock()[route] = Some(false);
            crate::amdgpu_navi22_kms::publish();
            crate::amdgpu_navi22_kms::wake();
            return Some(result.map(|()| MonitorStep::Unplugged(route)));
        }
    }
    // 2. A sink appeared, left or pulsed (replaced): detect every connector
    //    again (EDID inventory for dark connectors too). A pulsed lit sink
    //    that is still present is a new sink: stop it so the next pass
    //    lights it from a fresh detection and link verification.
    let last = *SENSES.lock();
    let mut changed: alloc::vec::Vec<usize> = (0..senses.len().min(6))
        .filter(|&i| {
            let pulsed = ports
                .get(i)
                .and_then(|c| c.hpd)
                .is_some_and(|h| long & 1 << h != 0);
            senses[i].is_some() && (senses[i] != last[i] || pulsed)
        })
        .collect();
    // A long pulse on the lit connector with HPD still high (a sink's own
    // re-assert, or one queued while `light` trained the link) is first
    // checked as dc_link_detect does: an unchanged EDID/DPCD keeps the
    // stream instead of tearing it down.
    if let Some((route, _)) = running {
        let lit = LIT_SINK.lock().clone().filter(|(r, _)| *r == route);
        if let Some((_, lit)) = lit {
            if changed.contains(&route)
                && senses.get(route) == Some(&Some(true))
                && last[route] == Some(true)
            {
                if let Ok(now) = boot.detect_display(route).await {
                    if long_pulse_keeps_stream(&lit, &now) {
                        changed.retain(|&i| i != route);
                    }
                }
            }
        }
    }
    if let Some(&first) = changed.first() {
        for &i in &changed {
            HDMI_LINKS.lock()[i] = crate::amdgpu_dcn30_hdmi::LinkMonitor::new();
            boot.forget_display_link(i);
        }
        if running.is_some_and(|(route, _)| changed.contains(&route)) {
            // SAFETY: as above.
            let stopped = unsafe { unlight(boot) }.await;
            KMS.lock().attempted = None;
            crate::amdgpu_navi22_kms::wake();
            if let Err(error) = stopped {
                return Some(Err(error));
            }
        }
        return Some(match boot.detect_displays().await {
            Ok(reports) => {
                reconcile_displays(boot, &reports);
                {
                    let mut kms = KMS.lock();
                    kms.attempted = None;
                    kms.assign_route();
                }
                crate::amdgpu_navi22_kms::publish();
                crate::amdgpu_navi22_kms::wake();
                Ok(MonitorStep::Reprobed(first))
            }
            Err(error) => Err(error),
        });
    }
    // 3. The lit DP link (HPD-RX or the periodic poll): link loss retrains.
    let (route, _) = running?;
    if ports.get(route).map(|c| c.signal) == Some(Signal::Hdmi) {
        use crate::amdgpu_dcn30_hdmi::LinkAction;
        let now = narf_time::wall::monotonic_ns() / 1_000_000;
        if !HDMI_LINKS.lock().get_mut(route)?.poll_due(now) {
            return None;
        }
        let health = boot.check_display_hdmi_link().await.ok()?;
        let action = HDMI_LINKS.lock().get_mut(route)?.observe(health);
        if action == LinkAction::None {
            return None;
        }
        if action != LinkAction::Relight {
            return Some(Ok(MonitorStep::HdmiLinkState(route, action, health)));
        }
        // SAFETY: same withdrawal and CPU-view retirement as other relights.
        let result = unsafe { unlight(boot) }.await;
        if action == LinkAction::Relight && result.is_ok() {
            KMS.lock().attempted = None;
            crate::amdgpu_navi22_kms::wake();
        }
        return Some(result.map(|()| MonitorStep::HdmiLinkState(route, action, health)));
    }
    if ports.get(route).map(|c| c.signal) != Some(Signal::DisplayPort) {
        return None;
    }
    match boot.check_display_link().await {
        Ok(RxEvent::None) => None,
        Ok(RxEvent::AutomatedTest) => Some(Ok(MonitorStep::AutomatedTest)),
        Ok(RxEvent::LinkLoss(_)) => {
            // SAFETY: the surfaces stay published; OWNER serializes.
            match unsafe { boot.retrain_display() }.await {
                Ok(link) => Some(Ok(MonitorStep::Retrained(link))),
                Err(error) => {
                    use core::fmt::Write;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi22 DP retrain failed ({error:?}); relighting"
                    );
                    // SAFETY: as above.
                    let stopped = unsafe { unlight(boot) }.await;
                    KMS.lock().attempted = None;
                    crate::amdgpu_navi22_kms::wake();
                    Some(stopped.map(|()| MonitorStep::RetrainFailed))
                }
            }
        }
        // An AUX failure while HPD is high: the next pass sees an unplug,
        // or checks again.
        Err(_) => None,
    }
}

/// One monitor pass: after a recovery, light the new owner; then hot-plug
/// and link maintenance (`monitor_hotplug`); otherwise apply the next KMS
/// convergence step (tear down, then light on the next pass).
/// # Safety
/// As for `modeset_displays`.
async unsafe fn monitor_pass() {
    use crate::amdgpu_navi22_kms::{Action, KMS};
    use core::fmt::Write;
    let recoveries = crate::amdgpu_navi22_recovery::recoveries();
    let mut owner = OWNER.lock().await;
    let Some(boot) = owner.as_mut() else {
        return;
    };
    if RELIT.swap(recoveries, Ordering::AcqRel) != recoveries {
        // The recovered owner has a fresh DCN (and restarted DMUB): nothing
        // shows, and the last attempt does not apply.
        let mut kms = KMS.lock();
        kms.crtc.shown = None;
        kms.attempted = None;
        HDMI_LINKS
            .lock()
            .fill(crate::amdgpu_dcn30_hdmi::LinkMonitor::new());
    }
    let running = boot.display_output().and_then(|o| {
        boot.display_scanout_ref()?;
        let kms = KMS.lock();
        let route = kms.connectors.iter().position(|c| c.port == o.connector)?;
        Some((route, o.timing))
    });
    // SAFETY: the caller's obligations, with OWNER held.
    if let Some(step) = unsafe { monitor_hotplug(boot, running) }.await {
        let _ = writeln!(narf_console::Writer, "amdgpu: navi22 display {step:?}");
        return;
    }
    update_hdmi_metadata(boot).await;
    converge_hdmi_vrr(boot).await;
    converge_crtc_color(boot).await;
    converge_dp_vrr(boot).await;
    // The monitor pass is the per-VUPDATE BTR service on Navi22 (50 ms
    // steps): a missed VUPDATE only resets the BTR cycle, it never
    // shortens the wrong frame.
    boot.display_lfc_progress();
    // SAFETY: as below; a lit or wanted multi-stream context owns the pass.
    if unsafe { converge_group(boot, running) }.await {
        return;
    }
    let action = KMS.lock().next(running);
    let result = match action {
        Action::Nothing => return,
        // SAFETY: serialized by the owner lock; the monitor is the only
        // display client after boot.
        Action::Unlight => unsafe { unlight(boot) }.await.map(|()| None),
        // SAFETY: as above.
        Action::Light { .. } => unsafe { light(boot, |_, row| row.fill(0)) }.await.map(Some),
    };
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 display {action:?}: {:?}",
        result.map(|o| o.map(|o| (o.timing.h_active, o.timing.v_active)))
    );
    // A teardown is followed at once by any relight it was for.
    if action == Action::Unlight {
        crate::amdgpu_navi22_kms::wake();
    }
}

// ── Multi-stream contexts (KMS CRTCs 1..) ───────────────────────────────

/// The lit context as KMS sees it: (CRTC, connector, timing) per stream,
/// CRTC k showing stream k.
fn group_running(
    boot: &boot::ColdBoot,
) -> Option<alloc::vec::Vec<(usize, usize, crate::amdgpu_dml::Timing)>> {
    let outputs = boot.group_outputs()?;
    let crtcs = GROUP_CRTCS.lock();
    let kms = crate::amdgpu_navi22_kms::KMS.lock();
    outputs
        .iter()
        .zip(crtcs.iter())
        .map(|(o, &d)| {
            let n = kms.connectors.iter().position(|c| c.port == o.connector)?;
            Some((d, n, o.timing))
        })
        .collect()
}
/// The CRTC each stream of the lit context shows.
static GROUP_CRTCS: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<usize>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// One monitor step for the multi-stream context, ahead of the single-pipe
/// owner's: while a CRTC other than 0 wants a sink, CRTC 0's single pipe is
/// torn down and every wanted CRTC lights together (`dc_commit_state` of
/// the whole context: `ColdBoot::modeset_group`); any change relights the
/// whole context. True while the context owns the display (lit, or this
/// pass worked on it); false hands the pass to the single-pipe owner, also
/// after a context failed to light (CRTC 0 then lights alone).
/// # Safety
/// As `modeset_displays`, with OWNER held.
async unsafe fn converge_group(
    boot: &mut boot::ColdBoot,
    single: Option<(usize, crate::amdgpu_dml::Timing)>,
) -> bool {
    use crate::amdgpu_navi22_display::Detection;
    use crate::amdgpu_navi22_kms::{GroupAction, KMS};
    use core::fmt::Write;
    let running = group_running(boot);
    if running.is_some() {
        use crate::amdgpu_dcn30_hdmi::LinkAction;
        let now = narf_time::wall::monotonic_ns() / 1_000_000;
        let due = HDMI_LINKS
            .lock()
            .iter_mut()
            .enumerate()
            .fold(0u8, |mask, (i, m)| mask | (u8::from(m.poll_due(now)) << i));
        for (route, health) in boot.check_group_hdmi_links(due).await.unwrap_or_default() {
            let action = HDMI_LINKS
                .lock()
                .get_mut(route)
                .map_or(LinkAction::None, |m| m.observe(health));
            if action == LinkAction::None {
                continue;
            }
            if action != LinkAction::Relight {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 HDMI {route} {health:?} {action:?}; link context retained"
                );
                continue;
            }
            // SAFETY: OWNER excludes presentation; all group CPU views are
            // retired by the same normal group-withdraw path before teardown.
            let result = unsafe { unlight_group(boot) }.await;
            if action == LinkAction::Relight && result.is_ok() {
                KMS.lock().attempted_group = None;
                crate::amdgpu_navi22_kms::wake();
            }
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 HDMI {route} {health:?} {action:?}: {result:?}"
            );
            return true;
        }
    }
    let action = {
        let mut kms = KMS.lock();
        kms.assign_route();
        kms.next_group(running.as_deref())
    };
    let targets = match action {
        GroupAction::Nothing => return running.is_some(),
        GroupAction::Unlight => {
            // SAFETY: the caller's obligations.
            let r = unsafe { unlight_group(boot) }.await;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 displays Unlight: {r:?}"
            );
            crate::amdgpu_navi22_kms::wake();
            return true;
        }
        GroupAction::Light(targets) => targets,
    };
    if single.is_some() || boot.display_output().is_some() {
        // SAFETY: the caller's obligations; the next pass lights the group.
        let r = unsafe { unlight(boot) }.await;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 display Unlight for group: {r:?}"
        );
        crate::amdgpu_navi22_kms::wake();
        return true;
    }
    let reports = match boot.detect_displays().await {
        Ok(reports) => reports,
        Err(_) => return false,
    };
    reconcile_displays(boot, &reports);
    let board: alloc::vec::Vec<_> = boot
        .display_connectors()
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    let mut requests = alloc::vec::Vec::new();
    for &(_, n, want) in &targets {
        let Some(report) = reports.get(n) else {
            return false;
        };
        let Detection::Connected(sink) = &report.detection else {
            return false;
        };
        let Some(link) = board.iter().position(|c| *c == report.connector) else {
            return false;
        };
        requests.push(crate::amdgpu_navi22_modeset::Request {
            link,
            connector: report.connector,
            sink: sink.clone(),
            want,
            mst: None,
            hdmi_settings: KMS.lock().connectors[n].output,
        });
    }
    KMS.lock().attempted_group = Some(targets.iter().map(|t| (t.1, t.2)).collect());
    // SAFETY: the caller's obligations; the single pipe is dark.
    let result = unsafe { boot.modeset_group(&requests, |_, _, row| row.fill(0)) }.await;
    reconcile_displays(boot, &reports);
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 displays Light x{}: {:?}",
        requests.len(),
        result.as_ref().map(alloc::vec::Vec::len)
    );
    let outputs = match result {
        Ok(outputs) => outputs,
        Err(_) => {
            // CRTC 0 may light alone again.
            KMS.lock().attempted = None;
            crate::amdgpu_navi22_kms::publish();
            crate::amdgpu_navi22_kms::wake();
            return false;
        }
    };
    *GROUP_CRTCS.lock() = targets.iter().map(|t| t.0).collect();
    {
        let mut kms = KMS.lock();
        for (&(d, n, _), (o, r)) in targets.iter().zip(outputs.iter().zip(&requests)) {
            let edid = r
                .sink
                .edid
                .get(..128)
                .and_then(|e| <[u8; 128]>::try_from(e).ok());
            let offered = kms
                .connectors
                .get(n)
                .map(|c| c.modes.clone())
                .unwrap_or_default();
            kms.connectors[n].shown_output = r.hdmi_settings;
            kms.connectors[n].color_relight = false;
            if let Some(c) = kms.crtc_at_mut(d) {
                c.shown = edid.map(|e| (e, o.timing, offered));
            }
        }
    }
    // The console follows the first stream (CRTC 0's); the other scanouts
    // are static.
    if let Some(o) = outputs.first() {
        crate::amdgpu_dcn_display::publish_external(Some(o.scanout), Some(flush_group));
    }
    crate::amdgpu_navi22_kms::publish();
    true
}

/// Best effort, as `flush_scanout`, for the context's console scanout.
fn flush_group() {
    if let Some(mut owner) = OWNER.try_lock() {
        if let Some(boot) = owner.as_mut() {
            let _ = boot.flush_group_scanout();
        }
    }
}

/// Withdraw the console from the context's scanouts and stop it.
/// # Safety
/// As `modeset_displays`, with OWNER held.
async unsafe fn unlight_group(boot: &mut boot::ColdBoot) -> Result<(), boot::Error> {
    let Some(outputs) = boot.group_outputs() else {
        return Ok(());
    };
    if crate::amdgpu_dcn_display::active_scanout()
        .is_some_and(|fb| outputs.iter().any(|o| o.scanout.addr == fb.addr))
    {
        crate::amdgpu_dcn_display::publish_external(None, None);
    }
    crate::scanout_access::wait_retired().await;
    // SAFETY: withdrawn and retired above.
    let result = unsafe { boot.stop_group() }.await;
    GROUP_CRTCS.lock().clear();
    {
        let mut kms = crate::amdgpu_navi22_kms::KMS.lock();
        for d in 0..crate::amdgpu_navi22_kms::MAX_CRTCS {
            if let Some(c) = kms.crtc_at_mut(d) {
                c.shown = None;
            }
        }
    }
    crate::amdgpu_navi22_kms::publish();
    result
}

/// The lit context's admission: its lowest supporting state's plan for
/// every stream (each member holds the same joint clocks and floors).
fn group_admission(
    boot: &boot::ColdBoot,
) -> Option<crate::amdgpu_navi22_power_policy::DisplayAdmission> {
    let group = boot.group()?;
    let streams = u8::try_from(boot.group_outputs()?.len()).ok()?;
    let admitted = group.members().first()?.admitted()?;
    Some(crate::amdgpu_navi22_kms::display_admission(
        admitted, streams,
    ))
}

/// Start the display monitor (once): it converges DRM's requests, relights
/// after a GPU recovery, and runs until the owner disappears.
/// # Safety
/// As for `modeset_displays`; from here on only the monitor and the
/// published hooks drive the display.
pub unsafe fn spawn_display_monitor() {
    if MONITOR.swap(true, Ordering::AcqRel) {
        return;
    }
    RELIT.store(
        crate::amdgpu_navi22_recovery::recoveries(),
        Ordering::Release,
    );
    narf_scheduler::spawn(async {
        loop {
            let mut waited = 0;
            while waited < MONITOR_MS
                && !crate::amdgpu_navi22_kms::take_pending()
                && RELIT.load(Ordering::Acquire) == crate::amdgpu_navi22_recovery::recoveries()
            {
                narf_time::SleepUntil::new(
                    narf_time::Deadline::after_ms(MONITOR_STEP_MS).as_instant(),
                )
                .await;
                waited += MONITOR_STEP_MS;
            }
            // SAFETY: the monitor's contract, accepted at spawn.
            unsafe { monitor_pass() }.await;
        }
    });
}

/// Called by the recovery path once the new owner runs: the monitor relights
/// the display (DMUB was restarted by the recovered sequence) as soon as
/// `amdgpu_navi22_recovery::recoveries()` has incremented.
pub fn relight_after_recovery() {
    crate::amdgpu_navi22_kms::wake();
}

/// Before a reset: withdraw the scanout from every CPU writer and stop the
/// pipe (best effort; the reset clears DCN either way), as amdgpu_dm commits
/// zero streams in `dm_suspend` during GPU reset.
async fn withdraw_for_reset(boot: &mut boot::ColdBoot) {
    // SAFETY: recovery excludes every other display client.
    let _ = unsafe { unlight_group(boot) }.await;
    withdraw(boot).await;
    if boot.display_output().is_some() {
        // SAFETY: withdrawn and drained above; recovery excludes others.
        let _ = unsafe { boot.stop_display() }.await;
    }
    crate::amdgpu_navi22_kms::KMS.lock().crtc.shown = None;
    crate::amdgpu_navi22_kms::publish();
}

/// The DCN30 admission of the lit configuration for the power policy
/// (`amdgpu_navi22_power_policy`); None while busy or nothing is lit.
pub fn display_admission() -> Option<crate::amdgpu_navi22_power_policy::DisplayAdmission> {
    let owner = OWNER.try_lock()?;
    let boot = owner.as_ref()?;
    if let Some(a) = group_admission(boot) {
        return Some(a);
    }
    let streams = u8::from(boot.display_output().is_some());
    // The plan the pipe runs under now: a placed primary's own.
    let mut admitted = boot.display_admitted()?.clone();
    if let Some(plan) = boot.display_plane_plan() {
        admitted.plan = plan;
    }
    Some(crate::amdgpu_navi22_kms::display_admission(
        &admitted, streams,
    ))
}

/// Show a premultiplied ARGB8888 cursor (at most 256x256) on the lit pipe.
pub async fn set_display_cursor(
    image: (u32, u32, &[u32]),
    at: (i32, i32),
) -> Result<crate::amdgpu_dcn30_cursor::Shown, ScanError> {
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ScanError::Busy)?;
    boot.set_display_cursor(image, at)
}

/// Flip the lit pipe to its back buffer; a console on the old front follows.
/// # Safety
/// The back buffer holds the complete next frame and no CPU writer touches
/// it until the next flip.
pub async unsafe fn flip_display() -> Result<crate::amdgpu_navi22_scanout::FlipDone, ScanError> {
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ScanError::Busy)?;
    let before = boot.display_scanout()?.front().fb;
    let done = boot.flip_display().await?;
    // An owned surface is shown: a client framebuffer it left is unfetched.
    let released = PRESENT.shown.lock().latched_owned();
    drop(released);
    follow_flip(before, boot.display_scanout()?.front().fb).await;
    Ok(done)
}

/// Follow a flip while still holding OWNER: retired CPU views must finish
/// before the former front is overwritten as the back buffer.
async fn follow_flip(before: GenericFb, after: GenericFb) {
    if crate::amdgpu_dcn_display::active_scanout().is_some_and(|fb| fb.addr == before.addr) {
        crate::amdgpu_dcn_display::publish_external(Some(after), Some(flush_scanout));
        crate::amdgpu_dcn_display::publish_external_cursor(Some(scanout_cursor));
    }
    crate::scanout_access::wait_retired().await;
}

// ── Vblank clock (DRM's 64-bit count from the 24-bit OTG frame count) ──

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VblankClock {
    raw: Option<u32>,
    time: crate::drm::card::VblankTime,
    read_ns: u64,
    variable: bool,
}
static VBLANK: narf_lib::sync::IrqSafeSpinLock<Option<VblankClock>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Fold a reading into the clock: the wrapped 24-bit difference advances
/// the 64-bit count; the first reading after a relight counts one past the
/// last known vblank (amdgpu_navi48_platform's clock, same OTG semantics).
fn extend_vblank(
    clock: Option<VblankClock>,
    phase: crate::amdgpu_dcn401_otg::VblankPhase,
    read_ns: u64,
) -> VblankClock {
    let mask = crate::amdgpu_dcn30_flip::FRAME_MASK;
    let count = match clock {
        Some(VblankClock {
            raw: Some(raw),
            time,
            ..
        }) => time.count + u64::from(phase.count.wrapping_sub(raw) & mask),
        Some(VblankClock {
            raw: None, time, ..
        }) => time.count + 1,
        None => u64::from(phase.count),
    };
    let at = |offset: i64| read_ns.saturating_add_signed(offset);
    VblankClock {
        raw: Some(phase.count),
        time: crate::drm::card::VblankTime {
            count,
            start_ns: at(phase.start_ns),
            ns: at(phase.end_ns),
            period_ns: phase.period_ns,
        },
        read_ns,
        variable: false,
    }
}
/// A recent reading carried forward whole periods while the owner is busy.
fn extrapolate_vblank(clock: VblankClock, now: u64) -> Option<crate::drm::card::VblankTime> {
    let t = clock.time;
    // Variable refresh has no predictable next period. Carry the last real
    // counter, including while the owner is busy; never invent vblanks.
    if clock.variable {
        return Some(t);
    }
    if now.saturating_sub(clock.read_ns) > 1_000_000_000 || t.period_ns == 0 {
        return None;
    }
    let periods = now.saturating_sub(t.start_ns) / t.period_ns;
    Some(crate::drm::card::VblankTime {
        count: t.count + periods,
        start_ns: t.start_ns + periods * t.period_ns,
        ns: t.ns + periods * t.period_ns,
        period_ns: t.period_ns,
    })
}
fn read_vblank(boot: &mut boot::ColdBoot) -> Option<crate::drm::card::VblankTime> {
    let scanout = boot.display_scanout().ok()?;
    let phase = scanout.vblank_phase().ok()?;
    let variable = scanout.vrr_active();
    let read_ns = narf_time::wall::monotonic_ns();
    let mut clock = VBLANK.lock();
    let mut next = extend_vblank(*clock, phase, read_ns);
    next.variable = variable;
    *clock = Some(next);
    Some(next.time)
}
fn restart_vblank() {
    if let Some(clock) = VBLANK.lock().as_mut() {
        clock.raw = None;
    }
}
/// The hardware vblank clock of the lit pipe, read now or carried forward.
pub fn vblank_time() -> Option<crate::drm::card::VblankTime> {
    if let Some(mut owner) = OWNER.try_lock() {
        return read_vblank(owner.as_mut()?);
    }
    let clock = (*VBLANK.lock())?;
    extrapolate_vblank(clock, narf_time::wall::monotonic_ns())
}
/// `drm::card::VblankSource` for the native CRTC.
pub fn crtc_vblank(crtc_id: u32) -> Option<crate::drm::card::VblankTime> {
    crate::amdgpu_navi22_kms::crtc_display(crtc_id).filter(|&d| d == 0)?;
    vblank_time()
}

// ── DRM presentation (mailbox of one frame, copied then flipped) ────────

struct PresentSlot {
    native: AtomicBool,
    presenting: AtomicBool,
    next: narf_lib::sync::IrqSafeSpinLock<Option<Frame>>,
    /// What the scanout buffers hold, for damaged (DIRTYFB) frames.
    damage: narf_lib::sync::IrqSafeSpinLock<crate::amdgpu_present_damage::Damage>,
    /// The lit pipe's owned front (pitch and size the HUBP was programmed
    /// with), for choosing in-place scanout before taking OWNER.
    geometry: narf_lib::sync::IrqSafeSpinLock<Option<GenericFb>>,
    /// The client framebuffer the pipe may still fetch.
    shown: narf_lib::sync::IrqSafeSpinLock<frame_copy::ShownPin>,
    /// The primary DRM last committed (its ticket and damage cleared), shown
    /// again on the new pipe after a relight: amdgpu_dm's modeset commit
    /// programs its new stream with the committed plane, and a compositor
    /// does not repaint an unchanged frame. Dropped at lastclose.
    committed: narf_lib::sync::IrqSafeSpinLock<Option<Frame>>,
    /// Trace counters: frames scanned out in place, frames copied, and
    /// their summed present time.
    direct: AtomicU64,
    copied: AtomicU64,
    present_ns: AtomicU64,
    /// Ineligibility reasons already logged (bit per `Ineligible`).
    logged: AtomicU64,
}
static PRESENT: PresentSlot = PresentSlot {
    native: AtomicBool::new(false),
    presenting: AtomicBool::new(false),
    next: narf_lib::sync::IrqSafeSpinLock::new(None),
    damage: narf_lib::sync::IrqSafeSpinLock::new(crate::amdgpu_present_damage::Damage::new()),
    geometry: narf_lib::sync::IrqSafeSpinLock::new(None),
    shown: narf_lib::sync::IrqSafeSpinLock::new(frame_copy::ShownPin::new()),
    committed: narf_lib::sync::IrqSafeSpinLock::new(None),
    direct: AtomicU64::new(0),
    copied: AtomicU64::new(0),
    present_ns: AtomicU64::new(0),
    logged: AtomicU64::new(0),
};

/// Low-volume hardware trace of the present path: the first in-place
/// scanout, the first copy per reason, and totals every 512 presents.
fn trace_present(direct: Option<u64>, reason: Option<frame_copy::Ineligible>, pitch: u32, ns: u64) {
    use core::fmt::Write;
    let total_ns = PRESENT.present_ns.fetch_add(ns, Ordering::Relaxed) + ns;
    let (d, c) = match direct {
        Some(_) => (
            PRESENT.direct.fetch_add(1, Ordering::Relaxed) + 1,
            PRESENT.copied.load(Ordering::Relaxed),
        ),
        None => (
            PRESENT.direct.load(Ordering::Relaxed),
            PRESENT.copied.fetch_add(1, Ordering::Relaxed) + 1,
        ),
    };
    if let (Some(address), 1) = (direct, d) {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 present: direct addr={address:#x} pitch={pitch} (frame #{})",
            d + c
        );
    }
    if let Some(reason) = reason {
        let bit = 1u64
            << frame_copy::Ineligible::ALL
                .iter()
                .position(|r| *r == reason)
                .unwrap_or(0);
        if PRESENT.logged.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 present: copy (reason={reason:?})"
            );
        }
    }
    let n = d + c;
    if n % 512 == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 present: {n} frames, direct {d}, copied {c}, avg {} us",
            total_ns / n / 1000
        );
    }
}

/// The lit stream placements are validated against without OWNER (the
/// atomic check), set with the presentation geometry at each relight.
static PLANE_BASIS: narf_lib::sync::IrqSafeSpinLock<Option<crate::amdgpu_navi22_plane::Basis>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// `dc_validate_global_state` for a positioned or scaled primary of `fb`
/// (pitch in bytes, width, height) on a CRTC of `mode`: what the presenter
/// would plan for it in place on the lit stream. A mode other than the lit
/// one (a modeset in the same commit) or no lit stream is validated by the
/// modeset that lights it.
pub(crate) fn placement_admitted(
    fb: (u32, u32, u32),
    mode: (u32, u32),
    src: (u32, u32, u32, u32),
    dst: (i32, i32, u32, u32),
) -> bool {
    let Some(basis) = *PLANE_BASIS.lock() else {
        return true;
    };
    if (basis.timing.h_active, basis.timing.v_active) != mode {
        return true;
    }
    let request = crate::amdgpu_navi22_plane::Request {
        pitch: fb.0 / 4,
        width: fb.1,
        height: fb.2,
        src,
        dst,
    };
    basis.plan(&request).is_ok()
}

/// The plane update `request` needs on the lit pipe: None when the pipe
/// already shows that placement (an address-only flip).
fn plane_update(
    boot: &boot::ColdBoot,
    request: &crate::amdgpu_navi22_plane::Request,
) -> Result<Option<crate::amdgpu_navi22_plane::Update>, crate::amdgpu_navi22_plane::Refusal> {
    if boot.display_plane_request() == Some(*request) {
        return Ok(None);
    }
    boot.plan_display_plane(request).map(Some)
}

/// A frame whose placement the lit pipe cannot show is dropped (its event
/// completes without a latch); logged once per kind.
fn trace_refusal(refusal: crate::amdgpu_navi22_plane::Refusal) {
    use core::fmt::Write;
    static LOGGED: AtomicU64 = AtomicU64::new(0);
    let bit = 1u64
        << match refusal {
            crate::amdgpu_navi22_plane::Refusal::Invalid => 0,
            crate::amdgpu_navi22_plane::Refusal::Geometry(_) => 1,
            crate::amdgpu_navi22_plane::Refusal::Mode(_) => 2,
            crate::amdgpu_navi22_plane::Refusal::Clock => 3,
            // Only produced when a slave overlay is live and the
            // single-plane plan is attempted; the two-plane path
            // (plan_two) is the one that admits it.
            crate::amdgpu_navi22_plane::Refusal::Overlay => 5,
            crate::amdgpu_navi22_plane::Refusal::Odm => 4,
        };
    if LOGGED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 present: placement dropped ({refusal:?})"
        );
    }
}

/// Take the lit pipe off a client framebuffer and back onto its owned
/// front, then release the client's pin (Navi48's `release_client_scanout`,
/// amdgpu_dm's restore commit on lastclose). The console comes back on the
/// owned front when no client owns the framebuffer. False when the pipe
/// could not let go (the pin is then kept).
/// # Safety
/// The caller holds OWNER and excludes other display writers.
async unsafe fn release_client_scanout(boot: &mut boot::ColdBoot) -> bool {
    let external = boot
        .display_scanout_ref()
        .is_some_and(|s| s.external_front().is_some());
    // A placed copy on the owned surface is undone too.
    if external || !boot.display_plane_is_owned() {
        let Ok(Some(_)) = boot.return_display_to_owned().await else {
            return false;
        };
    }
    let released = PRESENT.shown.lock().latched_owned();
    // Unpinned outside the IRQ-safe lock.
    drop(released);
    if crate::amdgpu_dcn_display::active_scanout().is_none() && !narf_console::fb_user_owned() {
        publish_console(boot);
    }
    true
}

/// drm_fb_helper's restore on lastclose: take the pipe off the closed
/// client's framebuffer (its pin goes after that flip latches).
pub fn release_client_scanout_async() {
    // The closed client's frame is not shown again by a later relight.
    let dropped = PRESENT.committed.lock().take();
    drop(dropped);
    release_drm_cursor();
    narf_scheduler::spawn(async {
        // A present may hold an armed flip (OWNER released while it
        // latches); returning to the owned surface is refused until it
        // completes. Retry for up to ~1 s rather than leaving the pipe on
        // the closed client's last frame.
        for _ in 0..50 {
            if !PRESENT.presenting.load(Ordering::Acquire) {
                let mut owner = OWNER.lock().await;
                let Some(boot) = owner.as_mut() else {
                    return;
                };
                // SAFETY: OWNER serializes display writers.
                if unsafe { release_client_scanout(boot) }.await {
                    return;
                }
            }
            narf_time::sleep_ms(20).await;
        }
        use core::fmt::Write;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 lastclose could not return to the owned scanout"
        );
    });
}
#[derive(Clone, Debug)]
struct Frame {
    phys: u64,
    pitch: u32,
    width: u32,
    height: u32,
    offset: u64,
    bo: Option<alloc::sync::Arc<crate::amdgpu_gem::ScanoutPin>>,
    ticket: Option<u64>,
    /// The rows that changed since the source's previous frame (DIRTYFB);
    /// None: all of them.
    damage: Option<core::ops::Range<u32>>,
    /// A positioned or scaled primary's SRC and CRTC rectangles.
    placement: Option<crate::drm::card::Placement>,
}

#[path = "amdgpu_navi22_frame_copy.rs"]
mod frame_copy;

/// Whether `present_frame` would present through a hardware flip now.
pub fn native_present_ready(display: u8) -> bool {
    // Only CRTC 0 presents (the secondary CRTCs show static scanouts).
    display == 0 && PRESENT.native.load(Ordering::Acquire)
}

/// Complete flip-complete events up to `ticket`: in the vblank the flip
/// latched in, or now in the last known vblank when it did not flip.
fn complete_flip(display: u8, ticket: Option<u64>, latched: Option<crate::drm::card::VblankTime>) {
    use crate::drm::card::{flips, FlipStamp};
    let Some(ticket) = ticket else {
        return;
    };
    let mut log = flips(display).lock();
    match latched {
        Some(t) => log.complete(
            ticket,
            FlipStamp {
                ns: t.ns,
                sequence: t.count as u32,
            },
        ),
        None => {
            let sequence = log.last().map_or(0, |s| s.sequence);
            let ns = narf_time::wall::monotonic_ns();
            log.complete(ticket, FlipStamp { ns, sequence });
        }
    }
}

/// Queue a DRM client's XRGB8888 frame (a kernel-mapped dumb buffer) for
/// tear-free presentation: the presenter copies it into the back buffer and
/// flips at the next VUPDATE. A newer frame replaces a waiting one; its
/// `ticket` completes when the flip latches, or at once when the frame is
/// replaced, refused or fails. False when native presentation is not
/// available (the caller then copies onto the visible front).
pub fn present_frame(
    display: u8,
    phys: u64,
    pitch: u32,
    width: u32,
    height: u32,
    ticket: Option<u64>,
) -> bool {
    present_plane(
        display,
        Some(crate::amdgpu_navi48_platform::PlaneFrame::linear(
            phys,
            pitch,
            width,
            height,
            0x3432_5258,
        )),
        ticket,
    )
}

/// One linear 8888 primary, including a pinned GEM framebuffer. The pin
/// remains live while queued, during any readback, and through the flip.
pub(crate) fn present_plane(
    display: u8,
    plane: Option<crate::amdgpu_navi48_platform::PlaneFrame>,
    ticket: Option<u64>,
) -> bool {
    present_damaged(display, plane, ticket, None)
}

/// As [`present_plane`], for a dumb-buffer frame whose rows outside
/// `damage` are unchanged since that buffer's previous frame (DIRTYFB).
/// Only those rows, and what the back buffer missed, are copied.
pub(crate) fn present_damaged(
    display: u8,
    plane: Option<crate::amdgpu_navi48_platform::PlaneFrame>,
    ticket: Option<u64>,
    damage: Option<core::ops::Range<u32>>,
) -> bool {
    let Some(plane) = plane else {
        complete_flip(display, ticket, None);
        return true;
    };
    let Some(mut frame) =
        Frame::from_plane(plane, ticket).filter(|_| native_present_ready(display))
    else {
        complete_flip(display, ticket, None);
        return false;
    };
    frame.damage = damage;
    *PRESENT.committed.lock() = Some(committed_copy(&frame));
    {
        let mut next = PRESENT.next.lock();
        frame.ticket = ticket.max(next.as_ref().and_then(|f| f.ticket));
        if let Some(old) = next.as_ref() {
            frame_copy::coalesce(old, &mut frame);
        }
        *next = Some(frame);
    }
    if !PRESENT.presenting.swap(true, Ordering::AcqRel) {
        narf_scheduler::spawn(presenter());
    }
    true
}

/// `frame` as the committed state a relight shows again: no event to
/// complete, every row to copy.
fn committed_copy(frame: &Frame) -> Frame {
    Frame {
        ticket: None,
        damage: None,
        ..frame.clone()
    }
}

/// After a relight lit the pipe on its cleared owned surface, queue the
/// committed primary again unless a newer frame is already waiting.
fn present_committed_again() {
    let Some(frame) = PRESENT.committed.lock().clone() else {
        return;
    };
    {
        let mut next = PRESENT.next.lock();
        if next.is_some() {
            return;
        }
        *next = Some(frame);
    }
    if !PRESENT.presenting.swap(true, Ordering::AcqRel) {
        narf_scheduler::spawn(presenter());
    }
}

async fn presenter() {
    use core::fmt::Write;
    loop {
        let Some(frame) = PRESENT.next.lock().take() else {
            PRESENT.presenting.store(false, Ordering::Release);
            if PRESENT.next.lock().is_some() && !PRESENT.presenting.swap(true, Ordering::AcqRel) {
                continue;
            }
            return;
        };
        if !PRESENT.native.load(Ordering::Acquire) {
            complete_flip(0, frame.ticket, None);
            continue;
        }
        let started = narf_time::monotonic_ns();
        // In place when the pinned client framebuffer can be fetched at its
        // own pitch, size and placement (amdgpu_dm never copies a client
        // framebuffer).
        let plan = frame_copy::direct(&frame);
        let result = async {
            if let (Ok(_), Some(pin)) = (plan, frame.bo.as_ref()) {
                // Rendering must finish before the HUBP fetches it; wait
                // without OWNER (the producer may need it).
                frame_copy::wait_rendered(pin).await?;
                if let Direct::Shown(latched) = present_direct(&frame, pin).await? {
                    return Ok::<_, ScanError>(latched);
                }
            }
            // A client framebuffer the HUBP cannot fetch as programmed is
            // copied by the GPU into the owned back surface (amdgpu_dm never
            // reads a client framebuffer with the CPU).
            if let Some(pin) = frame.bo.as_ref() {
                match present_blit(&frame, pin).await? {
                    Blitted::Flipped(latched) => return Ok(latched),
                    Blitted::Dropped => return Ok(None),
                    Blitted::Unavailable => {}
                }
            }
            // Wait on rendering and perform hidden-VRAM SDMA readback
            // before taking OWNER: the producer/transfer also needs it.
            let source = frame_copy::source(&frame).await?;
            let mut owner = OWNER.lock().await;
            let boot = owner.as_mut().ok_or(ScanError::Busy)?;
            // The copy shows with the frame's placement: its SRC at the
            // owned surface's origin, in its CRTC rectangle.
            let back = boot.display_scanout()?.back().ok_or(ScanError::Invalid)?;
            let Some(update) = frame_copy::copied_request(&frame, &back.fb)
                .ok_or(crate::amdgpu_navi22_plane::Refusal::Invalid)
                .and_then(|r| plane_update(boot, &r))
                .map_err(trace_refusal)
                .ok()
            else {
                return Ok(None);
            };
            // Taken for the present: a failed copy or flip leaves both
            // buffers unknown, so it is only put back after the latch.
            let mut damage = core::mem::take(&mut *PRESENT.damage.lock());
            // SAFETY: OWNER serializes display/reset; the frame retains its
            // GEM pin or the trusted DRM dumb backing, and source readback
            // completed outside this lock.
            let copied =
                unsafe { present_native(boot, &frame, source.as_deref(), &mut damage) }.await?;
            match flip_unlocked(owner, ArmedKind::Back, 0, update).await? {
                Latch::Done {
                    before,
                    after,
                    latched,
                } => {
                    damage.presented(
                        copied.tracked,
                        frame.damage.as_ref(),
                        Some(copied.address),
                        0,
                    );
                    *PRESENT.damage.lock() = damage;
                    // An owned surface is shown: the client framebuffer
                    // the pipe left is unfetched.
                    let released = PRESENT.shown.lock().latched_owned();
                    // Unpinned outside the IRQ-safe lock.
                    drop(released);
                    follow_flip(before, after).await;
                    Ok(latched)
                }
                Latch::Dropped => Ok(None),
            }
        }
        .await;
        if result.is_ok() {
            trace_present(
                plan.ok(),
                plan.err(),
                frame.pitch,
                narf_time::monotonic_ns().saturating_sub(started),
            );
        }
        match result {
            Ok(latched) => complete_flip(0, frame.ticket, latched),
            Err(e) => {
                complete_flip(0, frame.ticket, None);
                // A failed flip quarantines presentation; later frames use
                // the fallback copy.
                PRESENT.native.store(false, Ordering::Release);
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 native present disabled: {e:?}"
                );
            }
        }
    }
}

/// What [`flip_unlocked`] observed.
enum Latch {
    /// The flip latched: the owned fronts before and after, and the latch.
    Done {
        before: GenericFb,
        after: GenericFb,
        latched: Option<crate::drm::card::VblankTime>,
    },
    /// The pipe was relit, recovered or stopped while the flip was armed:
    /// nothing completed and the frame is dropped.
    Dropped,
}

/// Arm a flip under `owner`, release OWNER, then poll the latch every
/// `POLL_US`, retaking OWNER only for each non-blocking check (amdgpu_dm's
/// commit worker waits for flip_done holding no display lock). Cursor,
/// console and SDMA work can take OWNER meanwhile.
async fn flip_unlocked(
    mut owner: narf_lib::mutex::MutexGuard<'static, Option<boot::ColdBoot>>,
    kind: ArmedKind,
    external: u64,
    update: Option<crate::amdgpu_navi22_plane::Update>,
) -> Result<Latch, ScanError> {
    let boot = owner.as_mut().ok_or(ScanError::Busy)?;
    let before = boot.display_scanout()?.front().fb;
    // A placement other than the one shown is a plane update latched with
    // the address (commit_planes_for_stream); otherwise only the address.
    let armed = match update {
        Some(u) => boot.arm_display_plane(kind, external, &u).await?,
        None => boot.arm_display_flip(kind, external)?,
    };
    drop(owner);
    loop {
        narf_time::sleep_us(crate::amdgpu_dcn30_flip::POLL_US).await;
        let mut owner = OWNER.lock().await;
        let Some(boot) = owner.as_mut() else {
            return Ok(Latch::Dropped);
        };
        match latch_step(boot.poll_display_flip(&armed))? {
            LatchStep::Latched => {
                // optimize_bandwidth: what the update lowered follows now.
                if update.is_some() {
                    if let Err(e) = boot.optimize_display_plane() {
                        use core::fmt::Write;
                        let _ = writeln!(
                            narf_console::Writer,
                            "amdgpu: navi22 plane watermarks not lowered: {e:?}"
                        );
                    }
                }
                let after = boot.display_scanout()?.front().fb;
                let latched = read_vblank(boot);
                return Ok(Latch::Done {
                    before,
                    after,
                    latched,
                });
            }
            LatchStep::Pending => {}
            LatchStep::Dropped => return Ok(Latch::Dropped),
        }
    }
}

/// One poll's verdict in [`flip_unlocked`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LatchStep {
    Latched,
    Pending,
    /// The pipe was relit, recovered, stopped or withdrawn while armed.
    Dropped,
}
/// Timeout and device loss fail the present (quarantine, as a failed
/// `flip` does); any other refusal means the armed pipe is gone, so the
/// frame is dropped and its event completed without a latch.
fn latch_step(
    poll: Result<Option<crate::amdgpu_navi22_scanout::FlipDone>, ScanError>,
) -> Result<LatchStep, ScanError> {
    match poll {
        Ok(Some(_)) => Ok(LatchStep::Latched),
        Ok(None) => Ok(LatchStep::Pending),
        Err(e @ (ScanError::Timeout | ScanError::DeviceGone)) => Err(e),
        Err(_) => Ok(LatchStep::Dropped),
    }
}

#[cfg(feature = "kernel-test")]
fn navi22_flip_latch_wait_outcomes() -> narf_kernel_test::TestResult {
    use crate::amdgpu_navi22_scanout::FlipDone;
    use narf_kernel_test::TestResult;
    let done = FlipDone {
        front: 0x100,
        back: 0x200,
        frame: 7,
    };
    if latch_step(Ok(Some(done))) != Ok(LatchStep::Latched)
        || latch_step(Ok(None)) != Ok(LatchStep::Pending)
    {
        return TestResult::Fail("latched/pending flip misread");
    }
    // A withdraw/relight during the unlocked wait leaves the armed pipe
    // gone (`poll_armed` → Busy): drop the frame, never complete a flip.
    for gone in [ScanError::Busy, ScanError::Invalid, ScanError::Revoked] {
        if latch_step(Err(gone)) != Ok(LatchStep::Dropped) {
            return TestResult::Fail("replaced pipe did not drop the armed frame");
        }
    }
    for fatal in [ScanError::Timeout, ScanError::DeviceGone] {
        if latch_step(Err(fatal)) != Err(fatal) {
            return TestResult::Fail("timeout/device loss did not fail the present");
        }
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("drivers/gpu/amdgpu/navi22", navi22_flip_latch_wait_outcomes);

/// What [`present_direct`] did with a frame.
enum Direct {
    /// Flipped (or dropped because its pipe changed while armed): the latch.
    Shown(Option<crate::drm::card::VblankTime>),
    /// The lit pipe cannot fetch its placement in place (an ODM stream,
    /// say): the frame takes the copy path instead.
    Refused,
}

/// Flip the lit pipe to `frame`'s pinned client framebuffer in place, with
/// its pitch, size and placement, and keep that pin until a later flip
/// latches. A frame whose pipe changed while armed is dropped.
async fn present_direct(
    frame: &Frame,
    pin: &alloc::sync::Arc<crate::amdgpu_gem::ScanoutPin>,
) -> Result<Direct, ScanError> {
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ScanError::Busy)?;
    // A cancelled presenter may have left the old front's views draining.
    crate::scanout_access::wait_retired().await;
    let front = boot.display_scanout()?.front().fb;
    let Ok(address) = frame_copy::direct(frame) else {
        return Ok(Direct::Refused);
    };
    // The frame's pitch, size and placement on the mode lit now (it can
    // change between choosing and taking OWNER).
    let request = frame_copy::direct_request(frame, (front.width, front.height));
    let Ok(update) = plane_update(boot, &request) else {
        return Ok(Direct::Refused);
    };
    // No HDP step: display fetch reads VRAM through the MMHUB, not the
    // HDP read path the CPU copy samples (amdgpu_dm programs the address
    // after the fence wait alone). Requiring verified queues here would
    // disable native present during recovery for no reason.
    match flip_unlocked(owner, ArmedKind::External, address, update).await {
        Ok(Latch::Done {
            before, latched, ..
        }) => {
            // The previous client framebuffer (if any) is no longer fetched.
            let released = PRESENT.shown.lock().latched_external(pin.clone());
            // Unpinned outside the IRQ-safe lock.
            drop(released);
            // Owned surfaces are both stale now; DIRTYFB damage restarts.
            PRESENT.damage.lock().forget();
            follow_external(before).await;
            Ok(Direct::Shown(latched))
        }
        Ok(Latch::Dropped) => Ok(Direct::Shown(None)),
        Err(e) => {
            // The HUBP may still fetch either client buffer after a failed
            // flip: keep this one alive (the previous stays in `shown`).
            core::mem::forget(pin.clone());
            Err(e)
        }
    }
}

/// Outcome of the SDMA fallback for a client framebuffer.
enum Blitted {
    /// Copied and flipped; the latch time.
    Flipped(Option<crate::drm::card::VblankTime>),
    /// The lit surface changed under the frame: dropped, event completed.
    Dropped,
    /// No kernel SDMA queue (or nothing to copy): use the CPU copy.
    Unavailable,
}

/// Copy a pinned client framebuffer into the owned back surface with the
/// kernel SDMA queue, then flip to it. OWNER is held only to read the back
/// surface and to flip, never across the copy (the queue's worker takes it).
async fn present_blit(
    frame: &Frame,
    pin: &alloc::sync::Arc<crate::amdgpu_gem::ScanoutPin>,
) -> Result<Blitted, ScanError> {
    frame_copy::wait_rendered(pin).await?;
    let back = {
        let mut owner = OWNER.lock().await;
        let boot = owner.as_mut().ok_or(ScanError::Busy)?;
        // CPU views of the surface this copy overwrites must be retired.
        crate::scanout_access::wait_retired().await;
        boot.display_scanout()?.back().ok_or(ScanError::Invalid)?
    };
    // The SRC rectangle (an unplaced frame: what fits of its full screen)
    // goes unscaled to the back surface's origin.
    let (x, y, width, rows) = match frame.placement {
        Some(p) => p.src,
        None => (
            0,
            0,
            frame.width.min(back.fb.width),
            frame.height.min(back.fb.height),
        ),
    };
    if width > back.fb.width || rows > back.fb.height {
        trace_refusal(crate::amdgpu_navi22_plane::Refusal::Invalid);
        return Ok(Blitted::Dropped);
    }
    let source = pin
        .address()
        .checked_add(frame.offset)
        .and_then(|a| a.checked_add(u64::from(y) * u64::from(frame.pitch)))
        .and_then(|a| a.checked_add(u64::from(x) * 4))
        .ok_or(ScanError::Invalid)?;
    let ops = crate::amdgpu_rdna2_vram::blit_ops(
        source,
        u64::from(frame.pitch),
        back.address,
        u64::from(back.fb.pitch),
        u64::from(width) * 4,
        u64::from(rows),
    );
    if ops.is_empty() {
        return Ok(Blitted::Unavailable);
    }
    let held: alloc::sync::Arc<dyn Send + Sync> = pin.clone();
    match crate::amdgpu_rdna2_vram::blit(&ops, held).await {
        Ok(()) => {}
        Err(narf_filesystem::FsError::NoDevice | narf_filesystem::FsError::Unsupported) => {
            return Ok(Blitted::Unavailable)
        }
        Err(narf_filesystem::FsError::TimedOut) => return Err(ScanError::Timeout),
        Err(_) => return Err(ScanError::DeviceGone),
    }
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ScanError::Busy)?;
    // A relight or recovery between the copy and here replaced the surfaces.
    if boot.display_scanout()?.back().map(|b| b.address) != Some(back.address) {
        return Ok(Blitted::Dropped);
    }
    let Some(update) = frame_copy::copied_request(frame, &back.fb)
        .ok_or(crate::amdgpu_navi22_plane::Refusal::Invalid)
        .and_then(|r| plane_update(boot, &r))
        .map_err(trace_refusal)
        .ok()
    else {
        return Ok(Blitted::Dropped);
    };
    let (before, after, latched) = match flip_unlocked(owner, ArmedKind::Back, 0, update).await? {
        Latch::Done {
            before,
            after,
            latched,
        } => (before, after, latched),
        Latch::Dropped => return Ok(Blitted::Dropped),
    };
    // An owned surface is shown: the client framebuffer the pipe left is
    // unfetched, and DIRTYFB damage no longer describes either surface.
    let released = PRESENT.shown.lock().latched_owned();
    drop(released);
    PRESENT.damage.lock().forget();
    static TRACED: AtomicBool = AtomicBool::new(false);
    if !TRACED.swap(true, Ordering::Relaxed) {
        use core::fmt::Write;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 present: sdma blit {} op(s), pitch {} -> {}",
            ops.len(),
            frame.pitch,
            back.fb.pitch
        );
    }
    follow_flip(before, after).await;
    Ok(Blitted::Flipped(latched))
}

/// The pipe now fetches a client framebuffer: withdraw a console published
/// on the owned front (Navi48's `follow_flip(None)`), and let retired CPU
/// views of the owned surfaces drain before either is written again.
async fn follow_external(before: GenericFb) {
    if crate::amdgpu_dcn_display::active_scanout().is_some_and(|fb| fb.addr == before.addr) {
        crate::amdgpu_dcn_display::publish_external(None, None);
    }
    crate::scanout_access::wait_retired().await;
}

/// Where [`present_native`] copied a frame, for its damage bookkeeping
/// once the flip latches.
struct Copied {
    tracked: Option<crate::amdgpu_present_damage::Source>,
    address: u64,
}

/// Copy `frame` into the back buffer (the caller flips to it).
/// # Safety
/// The caller holds the owner lock; `frame` names a mapped dumb buffer or
/// a CPU-readable source.
async unsafe fn present_native(
    boot: &mut boot::ColdBoot,
    frame: &Frame,
    source: Option<&crate::amdgpu_gem::GemPlacement>,
    damage: &mut crate::amdgpu_present_damage::Damage,
) -> Result<Copied, ScanError> {
    // A cancelled presenter may have left the old front's views draining.
    crate::scanout_access::wait_retired().await;
    if frame.bo.is_some() {
        // Reuse the queue reader's checked HDP read-cache invalidation
        // before sampling client GPU writes through the CPU BAR window.
        boot.client_fence_reader()
            .ok_or(ScanError::Busy)?
            .completed(0)
            .map_err(|_| ScanError::DeviceGone)?;
    }
    let scanout = boot.display_scanout()?;
    let surface = scanout.back().ok_or(ScanError::Invalid)?;
    let back = surface.fb;
    // Navi22 reallocates no buffer behind the presenter (a relight forgets
    // them), so one epoch serves.
    if let Some(placement) = frame.placement {
        // The SRC rectangle, unscaled, to the back surface's origin; the
        // pipe scales and positions it (no damage tracking).
        damage.forget();
        let (sx, sy, sw, sh) = placement.src;
        if sw > back.width || sh > back.height {
            return Err(ScanError::Invalid);
        }
        let mut pixels = alloc::vec::Vec::new();
        pixels
            .try_reserve_exact((sx + sw) as usize)
            .map_err(|_| ScanError::Allocation)?;
        pixels.resize((sx + sw) as usize, 0u32);
        for row in 0..sh {
            boot.access_vram(|| {
                frame_copy::row(frame, source, sy + row, &mut pixels)
                    .map_err(|_| narf_filesystem::FsError::InvalidData)
            })
            .map_err(|_| ScanError::DeviceGone)?;
            boot.display_scanout()?
                .upload_back(0, row, &pixels[sx as usize..])?;
            if row % 64 == 63 {
                narf_scheduler::yield_now().await;
            }
        }
        return Ok(Copied {
            tracked: None,
            address: surface.address,
        });
    }
    let tracked = frame_copy::damage_source(frame);
    let rows = match tracked {
        Some(_) => damage.plan(tracked, frame.damage.as_ref(), surface.address, 0),
        None => 0..frame.height,
    };
    let width = frame.width.min(back.width);
    let mut pixels = alloc::vec::Vec::new();
    pixels
        .try_reserve_exact(width as usize)
        .map_err(|_| ScanError::Allocation)?;
    pixels.resize(width as usize, 0u32);
    for y in rows.start..rows.end.min(back.height) {
        // OWNER excludes reset while CPU reads a visible VRAM source.
        boot.access_vram(|| {
            frame_copy::row(frame, source, y, &mut pixels)
                .map_err(|_| narf_filesystem::FsError::InvalidData)
        })
        .map_err(|_| ScanError::DeviceGone)?;
        boot.display_scanout()?.upload_back(0, y, &pixels)?;
        if y % 64 == 63 {
            narf_scheduler::yield_now().await;
        }
    }
    Ok(Copied {
        tracked,
        address: surface.address,
    })
}

// ── Opt-in power saving (`amdgpu.navi22_pg`) ────────────────────────────

/// Apply the features named by the `amdgpu.rdna2_pg=` value (or the default
/// list) that the power policy admits (amdgpu_navi22_power_saving), then
/// start GFXOFF if it was admitted. Each refusal is reported on the console.
///
/// # Safety
/// After a successful `run`; every GC MMIO client (TDR, uapi/CS) takes a
/// GFXOFF reference, and the caller holds neither lock.
pub async unsafe fn power_saving(
    value: &str,
) -> Result<crate::amdgpu_navi22_power_saving::Applied, boot::Error> {
    use core::fmt::Write;
    let optin = crate::amdgpu_navi22_power_policy::OptIn::parse(Some(value));
    if optin.is_empty() {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 power saving: unrecognised amdgpu.rdna2_pg={value}; nothing enabled"
        );
        return Err(boot::Error::Invalid);
    }
    // SAFETY: forwarded caller contract.
    unsafe { apply_optin(optin) }.await
}

/// Apply the power-saving opt-in (see [`power_saving`]) without parsing
/// a `amdgpu.rdna2_pg=` value: the fb handoff's single application, which
/// the runtime-PM mode decision augments with GFXOFF before the first
/// application (a stopped GFXOFF controller never restarts, so the
/// arming cannot be a later re-application).
///
/// # Safety
/// As [`power_saving`].
pub async unsafe fn power_saving_optin(
    optin: crate::amdgpu_navi22_power_policy::OptIn,
) -> Result<crate::amdgpu_navi22_power_saving::Applied, boot::Error> {
    if optin.is_empty() {
        return Err(boot::Error::Invalid);
    }
    // SAFETY: forwarded caller contract.
    unsafe { apply_optin(optin) }.await
}

/// The opt-in last requested at boot or through `pp_features`.
static REQUESTED: narf_lib::sync::IrqSafeSpinLock<crate::amdgpu_navi22_power_policy::OptIn> =
    narf_lib::sync::IrqSafeSpinLock::new(crate::amdgpu_navi22_power_policy::OptIn::NONE);
/// The opt-in currently requested (for `pp_features` re-planning).
pub fn requested_power_saving() -> crate::amdgpu_navi22_power_policy::OptIn {
    *REQUESTED.lock()
}

/// Remove whatever power saving is applied, then apply `optin` (if not
/// empty) through the same admission gates as the boot path.
///
/// # Safety
/// As [`power_saving`].
pub async unsafe fn replace_power_saving(
    optin: crate::amdgpu_navi22_power_policy::OptIn,
) -> Result<Option<crate::amdgpu_navi22_power_saving::Applied>, boot::Error> {
    let applied = {
        let owner = OWNER.lock().await;
        owner.as_ref().ok_or(boot::Error::Invalid)?.power_saving()
    };
    if applied.is_some() {
        // SAFETY: forwarded caller contract.
        unsafe { remove_power_saving() }.await?;
    }
    *REQUESTED.lock() = optin;
    if optin.is_empty() {
        return Ok(None);
    }
    // SAFETY: forwarded caller contract; GFXOFF is stopped by the removal.
    unsafe { apply_optin(optin) }.await.map(Some)
}

/// `power_dpm_force_performance_level` on GFXCLK.
pub async fn set_gfx_level(level: crate::amdgpu_smu_navi22::GfxLevel) -> Result<(), boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .set_gfx_level(level)
        .await
}

/// The PMFW running feature mask (`pp_features`).
pub async fn running_features() -> Result<u64, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .running_features()
        .await
}

/// # Safety
/// As [`power_saving`].
async unsafe fn apply_optin(
    optin: crate::amdgpu_navi22_power_policy::OptIn,
) -> Result<crate::amdgpu_navi22_power_saving::Applied, boot::Error> {
    use core::fmt::Write;
    *REQUESTED.lock() = optin;
    let result = {
        let mut owner = OWNER.lock().await;
        let boot = owner.as_mut().ok_or(boot::Error::Invalid)?;
        // SAFETY: owner lock held, GFXOFF not started (it starts below).
        let result = unsafe { boot.apply_power_saving(optin) }.await;
        crate::amdgpu_info::publish_rdna2_memory_clocks(boot.memory_clock_range().await.ok());
        result
    };
    let applied = match result {
        Ok(applied) => applied,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 power saving failed: {error:?}"
            );
            return Err(error);
        }
    };
    for (feature, refusal) in crate::amdgpu_navi22_power_policy::FEATURES
        .iter()
        .zip(applied.plan.refusals)
    {
        if let Some(refusal) = refusal
            .filter(|r| !matches!(r, crate::amdgpu_navi22_power_policy::Refusal::NotOptedIn(_)))
        {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 power saving: {feature:?} refused: {refusal:?}"
            );
        }
    }
    if applied.plan.policy.gfxoff() {
        if let Err(error) = crate::amdgpu_navi22_gfxoff::start().await {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 GFXOFF start: {error:?}"
            );
        }
    }
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 power saving (unvalidated opt-in): cg {:?}, smu {:#x}, wm {}, uclk {:?}, fclk {:?}, gfxoff {}",
        applied.blocks,
        applied.smu_bits,
        applied.watermarks,
        applied.uclk_floor_mhz,
        applied.fclk_floor_mhz,
        applied.plan.policy.gfxoff()
    );
    Ok(applied)
}

/// Undo `power_saving`: stop GFXOFF (GC powered on return), then floors,
/// PMFW bits and clock gating in reverse.
///
/// # Safety
/// As `power_saving`.
pub async unsafe fn remove_power_saving() -> Result<(), boot::Error> {
    let stopped = crate::amdgpu_navi22_gfxoff::stop().await;
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(boot::Error::Invalid)?;
    // A failed stop leaves GC power unknown: do not touch GC clock gating.
    stopped.map_err(|e| {
        boot::Error::PowerSaving(crate::amdgpu_navi22_power_saving::Error::GfxOff(e))
    })?;
    // SAFETY: owner lock held, GFXOFF stopped above.
    let result = unsafe { boot.remove_power_saving() }.await;
    crate::amdgpu_info::publish_rdna2_memory_clocks(boot.memory_clock_range().await.ok());
    result
}

/// The GFXOFF controller's PMFW transport (`smu_v11_0_gfx_off_control`).
pub(crate) async fn gfx_off_control(allow: bool) -> Result<(), boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .gfx_off_control(allow)
        .await
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi22_recovery_preflight_preserves_registered_clients() -> TestResult {
        use crate::amdgpu_cs::{Submission, Submitter};
        use alloc::{boxed::Box, sync::Arc};
        use core::{future::Future, pin::Pin};
        use narf_filesystem::FsError;

        // This fixture exercises rejection by the real platform entry, never
        // a reset. It must not run against a physical GPU/retained owner.
        if amdgpu::pci_device().is_some()
            || narf_scheduler::block_on_spin(async { OWNER.lock().await.is_some() })
        {
            return TestResult::Skip("physical GPU owner present");
        }
        struct Client;
        impl Submitter for Client {
            fn submit<'a>(
                &'a self,
                _: &'a crate::amdgpu_vm::VmState,
                _: &'a Submission,
                _: &'a Arc<crate::amdgpu_ctx::Health>,
            ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
                Box::pin(async { Err(FsError::NoDevice) })
            }
            fn signalled(&self, _: u64) -> bool {
                false
            }
            fn ring_for(&self, _: u32, _: u32, _: u32) -> Option<u32> {
                None
            }
            fn wait(
                &self,
                _: u64,
                _: u64,
            ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
                Box::pin(async { Ok(false) })
            }
        }
        let card = crate::amdgpu_navi22_cs::drm_card().unwrap_or_else(|| {
            crate::drm_registry::register_drm_card(Arc::new(
                crate::drm_devfs_bridge::AmdgpuCard::new(
                    "recovery-preflight".into(),
                    0x1002,
                    0x73df,
                    0,
                    0,
                    None,
                ),
            ))
        });
        if crate::amdgpu_gem::vram_heap_usage(card).is_some() {
            return TestResult::Skip("existing native heap belongs to another fixture");
        }
        let previous = crate::amdgpu_cs::submitter(card);
        let client: Arc<dyn Submitter> = Arc::new(Client);
        crate::amdgpu_cs::register_submitter(card, client.clone());
        // SAFETY: the preconditions above establish that no physical GPU or
        // boot owner exists; preflight must reject before any teardown/I/O.
        let result = narf_scheduler::block_on_spin(unsafe { recover() });
        let retained =
            crate::amdgpu_cs::submitter(card).is_some_and(|current| Arc::ptr_eq(&current, &client));
        crate::amdgpu_cs::unregister_submitter(card);
        if let Some(previous) = previous {
            crate::amdgpu_cs::register_submitter(card, previous);
        }
        if result != Err(crate::amdgpu_navi22_recovery::Error::Busy) || !retained {
            return TestResult::Fail("rejected platform recovery withdrew registered clients");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi22-recovery-preflight",
        navi22_recovery_preflight_preserves_registered_clients
    );

    fn navi22_handoff_distinguishes_primary_and_secondary_apertures() -> TestResult {
        let fb = GenericFb::new(0x1100, 16, 4, 64, 32);
        if framebuffer_range(0x1000..0x2000, Some(fb)) != Ok(Some(0x1100..0x1200))
            || framebuffer_range(0x2000..0x3000, Some(fb)) != Ok(None)
            || framebuffer_range(0x1000..0x2000, None) != Ok(None)
        {
            return TestResult::Fail("boot framebuffer classification");
        }
        for fb in [
            GenericFb { addr: 0x1f80, ..fb },
            GenericFb { addr: 0xf80, ..fb },
            GenericFb {
                addr: u64::MAX - 4,
                ..fb
            },
            GenericFb { pitch: 32, ..fb },
            GenericFb { height: 0, ..fb },
        ] {
            if framebuffer_range(0x1000..0x2000, Some(fb)) != Err(Error::InvalidFramebuffer) {
                return TestResult::Fail("invalid/partial framebuffer admitted");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_handoff_distinguishes_primary_and_secondary_apertures
    );

    fn navi22_training_refuses_live_firmware_in_overwritten_prefix() -> TestResult {
        let mut region = vram::Protected {
            owner: vram::Owner::OtherClient,
            range: 4096..8192,
        };
        if training_clients(core::slice::from_ref(&region)).is_err() {
            return TestResult::Fail("inventoried display reader refused");
        }
        // A GOP-era DMUB window in the prefix: Linux trains regardless.
        region.owner = vram::Owner::Dmub;
        if training_clients(core::slice::from_ref(&region)).is_err() {
            return TestResult::Fail("inherited DMUB window blocked cold training");
        }
        for owner in [
            vram::Owner::FirmwareUsage,
            vram::Owner::DriverUsage,
            vram::Owner::FirmwareTail,
            vram::Owner::FirmwareRuntime,
        ] {
            region.owner = owner;
            if training_clients(core::slice::from_ref(&region))
                != Err(Error::Memory(vram::Error::Busy))
            {
                return TestResult::Fail("training would overwrite live firmware");
            }
        }
        region.range = (32 << 20)..(33 << 20);
        if training_clients(core::slice::from_ref(&region)).is_err() {
            return TestResult::Fail("nonoverlapping firmware refused");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_training_refuses_live_firmware_in_overwritten_prefix
    );

    /// A long HPD pulse whose sink reads back the same EDID (and DPCD) keeps
    /// the lit stream, as `detect_link_and_local_sink`'s `same_edid` does;
    /// every pulse used to tear the display down and relight it.
    fn navi22_long_pulse_same_edid_keeps_the_stream() -> TestResult {
        use crate::amdgpu_navi22_display::{Detection, Error as D, Sink};
        let lit = Sink {
            edid: alloc::vec![0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 1, 2],
            preferred: None,
            hdmi: true,
            dpcd: None,
        };
        let dp = Sink {
            dpcd: Some([0x12; 16]),
            ..lit.clone()
        };
        let mut other_edid = lit.clone();
        other_edid.edid[9] = 3;
        let mut other_dpcd = dp.clone();
        other_dpcd.dpcd = Some([0x14; 16]);
        if !long_pulse_keeps_stream(&lit, &Detection::Connected(lit.clone()))
            || !long_pulse_keeps_stream(&dp, &Detection::Connected(dp.clone()))
        {
            return TestResult::Fail("unchanged sink after a long pulse was torn down");
        }
        if long_pulse_keeps_stream(&lit, &Detection::Connected(other_edid))
            || long_pulse_keeps_stream(&dp, &Detection::Connected(other_dpcd))
            || long_pulse_keeps_stream(&lit, &Detection::Disconnected)
            || long_pulse_keeps_stream(&lit, &Detection::Failed(D::Invalid))
        {
            return TestResult::Fail("a changed or unreadable sink kept the old stream");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_long_pulse_same_edid_keeps_the_stream
    );
    fn navi22_variable_refresh_never_extrapolates_hardware_vblanks() -> TestResult {
        let phase = crate::amdgpu_dcn401_otg::VblankPhase {
            count: 7,
            start_ns: -2_000_000,
            end_ns: 0,
            period_ns: 16_666_666,
        };
        let mut clock = extend_vblank(None, phase, 100_000_000);
        clock.variable = true;
        if extrapolate_vblank(clock, 150_000_000) != Some(clock.time)
            || extrapolate_vblank(clock, 2_000_000_000) != Some(clock.time)
        {
            return TestResult::Fail(
                "variable refresh invented unobserved vblanks while owner busy",
            );
        }
        clock.variable = false;
        if extrapolate_vblank(clock, 150_000_000).is_none_or(|t| t.count <= clock.time.count) {
            return TestResult::Fail("fixed-rate fallback stopped extrapolating");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_variable_refresh_never_extrapolates_hardware_vblanks
    );
}
