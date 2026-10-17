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
    // allocator exclusions. Display/cursor readers can show transient pixels,
    // but live DMUB code/data or another firmware writer cannot be preserved
    // by racing a CPU backup/restore. No caller-supplied OtherClient ranges
    // exist here: Plan produces those only from inherited display surfaces.
    if protected.iter().any(|region| {
        region.range.start < 32 * 1024 * 1024
            && !matches!(
                region.owner,
                vram::Owner::BootFramebuffer | vram::Owner::OtherClient
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
        let mut firmware = boot::Firmware::open(gpu, &registry).map_err(Error::Firmware)?;
        // amdgpu_discovery_harvest_ip: VCN instances absent from the harvest
        // table get firmware and an owner. An unreadable table disables
        // media only; display and queue bring-up do not depend on it.
        // SAFETY: single-CPU boot under the exclusive claim, same mappings
        // and index latch probe used for the discovery read.
        match unsafe { crate::amdgpu_vcn_navi22::Harvest::read(gpu, &authority, identity.revision) }
        {
            Ok(harvest) => firmware.harvest_vcn(harvest.0),
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
        let plan = unsafe { vram::Plan::read_navi22(gpu, &authority, range, &[]) }
            .map_err(Error::Memory)?;
        let training = plan.training();
        if training.is_some() {
            training_clients(plan.protected())?;
        }
        // SAFETY: the immutable inventory covers every inherited client, and
        // successful preparation excludes every later legacy MMIO accessor.
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
                unsafe { boot::ColdBoot::new(gpu, authority, &pool, firmware) }
            }
        }
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
        match unsafe { crate::amdgpu_cp_navi22::Doorbells::map_navi22(&device) } {
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
        });
    }
    start_services(boot).await;
    Ok(report)
}

/// Runtime services of a completed (or recovered) owner: PMFW telemetry and
/// hwmon, then the SMU11 thermal interrupts. They run as executor tasks that
/// take the owner lock per refresh. Failures are reported, never fatal.
async fn start_services(boot: &mut boot::ColdBoot) {
    use core::fmt::Write;
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

/// TDR sample of every verified kernel queue, serialized with the owner.
pub(crate) async fn queue_progress(
) -> Result<alloc::vec::Vec<crate::amdgpu_navi22_tdr::Progress>, boot::Error> {
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

/// Opt-in device recovery (Linux `amdgpu_device_gpu_recover`, mode1): not
/// triggered automatically unless `amdgpu_navi22_tdr::set_automatic_recovery`
/// was enabled. Quiesces the services and IH, abandons every fence wait,
/// mode1-resets the ASIC and re-runs the complete cold-boot bring-up on a
/// fresh owner, then restarts telemetry, thermal and TDR. The display stays
/// dark until its owner restarts DMUB and modesets. Failure or cancellation
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
    let mut owner = OWNER.lock().await;
    let mut backend = Recovering {
        owner: &mut owner,
        device,
        interrupts: alloc::vec::Vec::new(),
    };
    let result = recovery.run(&mut backend).await;
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 GPU recovery {result:?}"
    );
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
const FAULT_LOG_LIMIT: u64 = 16;
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
        for owner in [
            vram::Owner::Dmub,
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
}
