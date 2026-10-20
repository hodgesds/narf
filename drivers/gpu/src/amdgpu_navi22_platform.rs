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
    // The sample reads CP registers: hold GC powered (no-op without GFXOFF).
    let _gc = crate::amdgpu_navi22_gfxoff::Reference::acquire()
        .await
        .map_err(|_| boot::Error::Busy)?;
    let mut owner = OWNER.lock().await;
    owner.as_mut().ok_or(boot::Error::Invalid)?.queue_progress()
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
    crate::amdgpu_navi22_cs::unregister();
    let device = amdgpu::pci_device().ok_or(Error::Busy)?;
    // Kernel CPU writers stay off the framebuffer for the whole reset; the
    // runtime power controls refer to the old owner's PMFW state.
    console(true);
    crate::amdgpu_rdna2_power_controls::withdraw();
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
    // SAFETY: the caller's obligations.
    let result = unsafe { boot.modeset_display(connector, &sink, want, draw) }.await;
    // Admission inputs (and a DP sink's verified link) exist now, lit or
    // not: offer what they admit.
    reconcile_displays(boot, &reports);
    {
        let mut kms = KMS.lock();
        kms.crtc.shown = None;
        *LIT_SINK.lock() = result.is_ok().then(|| (route, sink.clone()));
        if let Ok(output) = result.as_ref() {
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
    PRESENT.native.store(back.is_ok(), Ordering::Release);
    restart_vblank();
    publish_console(boot);
    crate::amdgpu_navi22_kms::publish();
    Ok(output)
}

/// Withdraw and tear the lit pipe down.
/// # Safety
/// As for `modeset_displays`.
async unsafe fn unlight(boot: &mut boot::ColdBoot) -> Result<(), boot::Error> {
    withdraw(boot).await;
    // SAFETY: the publication is withdrawn and every CPU view retired.
    let result = unsafe { boot.stop_display() }.await;
    crate::amdgpu_navi22_kms::KMS.lock().crtc.shown = None;
    crate::amdgpu_navi22_kms::publish();
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
    Some(crate::amdgpu_navi22_kms::display_admission(
        boot.display_admitted()?,
        streams,
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
    }
}
/// A recent reading carried forward whole periods while the owner is busy.
fn extrapolate_vblank(clock: VblankClock, now: u64) -> Option<crate::drm::card::VblankTime> {
    let t = clock.time;
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
    let timing = scanout.timing();
    let position = scanout.position().ok()?;
    let read_ns = narf_time::wall::monotonic_ns();
    let phase = crate::amdgpu_navi22_scanout::vblank_phase(position, &timing)?;
    let mut clock = VBLANK.lock();
    let next = extend_vblank(*clock, phase, read_ns);
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
}
static PRESENT: PresentSlot = PresentSlot {
    native: AtomicBool::new(false),
    presenting: AtomicBool::new(false),
    next: narf_lib::sync::IrqSafeSpinLock::new(None),
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    phys: u64,
    pitch: u32,
    width: u32,
    height: u32,
    ticket: Option<u64>,
}

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
    if !native_present_ready(display)
        || width == 0
        || height == 0
        || pitch < width.saturating_mul(4)
    {
        complete_flip(display, ticket, None);
        return false;
    }
    {
        let mut next = PRESENT.next.lock();
        let ticket = ticket.max(next.and_then(|f| f.ticket));
        *next = Some(Frame {
            phys,
            pitch,
            width,
            height,
            ticket,
        });
    }
    if !PRESENT.presenting.swap(true, Ordering::AcqRel) {
        narf_scheduler::spawn(presenter());
    }
    true
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
        let result = {
            let mut owner = OWNER.lock().await;
            match owner.as_mut() {
                // SAFETY: the owner lock serializes display writers; the
                // dumb buffer stays valid under DRM's buffer rules.
                Some(boot) => match unsafe { present_native(boot, frame) }.await {
                    Ok((before, after)) => {
                        let latched = read_vblank(boot);
                        follow_flip(before, after).await;
                        Ok(latched)
                    }
                    Err(e) => Err(e),
                },
                None => Err(ScanError::Busy),
            }
        };
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

/// Copy `frame` into the back buffer, then flip to it. Returns the front
/// before and after.
/// # Safety
/// The caller holds the owner lock; `frame` names a mapped dumb buffer.
async unsafe fn present_native(
    boot: &mut boot::ColdBoot,
    frame: Frame,
) -> Result<(GenericFb, GenericFb), ScanError> {
    // A cancelled presenter may have left the old front's views draining.
    crate::scanout_access::wait_retired().await;
    let scanout = boot.display_scanout()?;
    let back = scanout.back().ok_or(ScanError::Invalid)?.fb;
    let width = frame.width.min(back.width);
    for y in 0..frame.height.min(back.height) {
        let at = frame.phys + u64::from(y) * u64::from(frame.pitch);
        // SAFETY: a kernel-mapped dumb buffer row of at least `width`
        // pixels (pitch >= 4 * width was checked when queued).
        let row = unsafe {
            core::slice::from_raw_parts(
                narf_memory::PhysAddr::new(at).kernel_ptr::<u32>(),
                width as usize,
            )
        };
        boot.display_scanout()?.upload_back(0, y, row)?;
        if y % 64 == 63 {
            narf_scheduler::yield_now().await;
        }
    }
    let before = boot.display_scanout()?.front().fb;
    boot.flip_display().await?;
    Ok((before, boot.display_scanout()?.front().fb))
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
}
