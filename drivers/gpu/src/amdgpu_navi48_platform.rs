//! One retained Navi48 firmware owner, entered by the framebuffer boot handoff.
//! Preparation is read-only; the caller stops CPU writers before entering it.
use crate::amdgpu_navi48_display as display;
use crate::{amdgpu, amdgpu_navi48_boot as boot, amdgpu_vram_boot as vram};
use alloc::sync::Arc;
use alloc::vec::Vec;
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

static SHADER_PROOF: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Boot opt-in for shader execution evidence, independent of Mesa readiness.
pub fn set_shader_proof(enabled: bool) {
    SHADER_PROOF.store(enabled, core::sync::atomic::Ordering::Release);
}

static OWNER: Mutex<Option<alloc::boxed::Box<boot::ColdBoot>>> = Mutex::new(None);
// The lock spans each synchronous hardware-fence read. Advancing generation
// drains old readers before reset; their retained readers never touch BARs again.
static READ_GENERATION: narf_lib::sync::IrqSafeSpinLock<u64> =
    narf_lib::sync::IrqSafeSpinLock::new(0);
static SUBMITTER: narf_lib::sync::IrqSafeSpinLock<Option<Arc<Submitter>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
#[allow(
    clippy::vec_box,
    reason = "retain large owners without moving them onto the kernel stack"
)]
static QUARANTINED: narf_lib::sync::IrqSafeSpinLock<Vec<alloc::boxed::Box<boot::ColdBoot>>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());
static RECOVERY_STATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static RECOVERIES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub fn recoveries() -> u64 {
    RECOVERIES.load(core::sync::atomic::Ordering::Acquire)
}

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
    pub report: Option<boot::Report>,
    pub display: Result<display::State, display::Error>,
    pub interrupts: Option<crate::amdgpu_navi48_interrupts::Status>,
    pub queue_state: Option<crate::amdgpu_gfx12_queue::State>,
    pub queue_interrupts:
        Option<Result<crate::amdgpu_gfx12_queue::InterruptProof, crate::amdgpu_gfx12_queue::Error>>,
    pub shaders:
        Option<Result<crate::amdgpu_gfx12_shader::Proof, crate::amdgpu_gfx12_queue::Error>>,
    pub sdma_state: Option<crate::amdgpu_sdma_navi48::State>,
    pub sdma_interrupts:
        Option<Result<crate::amdgpu_sdma_navi48::InterruptProof, crate::amdgpu_sdma_navi48::Error>>,
    pub display_clocks: Result<crate::amdgpu_dcn401_clk::Status, crate::amdgpu_dcn401_clk::Error>,
    pub display_pipe_clocks:
        Result<crate::amdgpu_dcn401_dccg::Status, crate::amdgpu_dcn401_dccg::Error>,
    pub display_timing: Result<crate::amdgpu_dcn401_otg::Status, crate::amdgpu_dcn401_otg::Error>,
    pub power: Option<crate::amdgpu_navi48_power::Snapshot>,
}
pub fn status() -> Status {
    match OWNER.try_lock() {
        None => Status::Running,
        Some(owner) => owner.as_ref().map_or(Status::Absent, |boot| {
            Status::Retained(Diagnostics {
                state: boot.state(),
                report: boot.report(),
                display: boot.display_state(),
                interrupts: crate::amdgpu_navi48_interrupts::status(),
                queue_state: boot.queue_state(),
                queue_interrupts: boot.queue_interrupts(),
                shaders: boot.shader_result(),
                sdma_state: boot.sdma_state(),
                sdma_interrupts: boot.sdma_interrupts(),
                display_clocks: boot.display_clock_status(),
                display_pipe_clocks: boot.display_pipe_clock_status(),
                display_timing: boot.display_timing_status(),
                power: crate::amdgpu_navi48_power::snapshot(),
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
/// ownership. `Ok(None)` means no Navi48. `Ok(Some(affected))` means the owner
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
    if !amdgpu::is_navi48() {
        return Ok(None);
    }
    let mut owner = OWNER.try_lock().ok_or(Error::Busy)?;
    if owner.is_some() {
        return Err(Error::Busy);
    }
    let authority = amdgpu::pci_authority().ok_or(Error::Authority)?;
    let pci = amdgpu::pci_device().ok_or(Error::Authority)?;
    let registry: Cap<narf_firmware::FirmwareRegistry, Read> =
        narf_firmware::trusted_loader_authority()
            .ok_or(Error::Authority)?
            .derive()
            .map_err(|_| Error::Authority)?;
    amdgpu::claim_navi48(|gpu| {
        // Validate/copy every file before inspecting hardware or claiming VRAM.
        let firmware = boot::Firmware::open(
            gpu,
            &registry,
            crate::amdgpu_navi48_firmware::MesMode::Unified,
        )
        .map_err(Error::Firmware)?;
        // What AMDGPU_INFO_FW_VERSION reports for the CP firmware.
        {
            use crate::amdgpu_navi48_firmware::Source;
            use crate::amdgpu_uapi as u;
            let images = firmware.images().map_err(Error::Firmware)?;
            let cp = |source, fw_type| {
                images
                    .iter()
                    .find(|i| i.source() == source)
                    .map(|i| (fw_type, i.version(), i.feature()))
            };
            if let (Some(me), Some(pfp), Some(mec)) = (
                cp(Source::Me, u::AMDGPU_INFO_FW_GFX_ME),
                cp(Source::Pfp, u::AMDGPU_INFO_FW_GFX_PFP),
                cp(Source::Mec, u::AMDGPU_INFO_FW_GFX_MEC),
            ) {
                crate::amdgpu_info::publish_navi48_firmware([me, pfp, mec]);
            }
        }
        let end = gpu
            .vram
            .base
            .checked_add(gpu.vram.visible_size)
            .ok_or(Error::InvalidFramebuffer)?;
        let range = framebuffer_range(gpu.vram.base..end, framebuffer)?;
        let affected = range.is_some();
        // SAFETY: caller's boot ownership, no active NARF clients. Plan refuses
        // live VM contexts and accounts for firmware, all pipes and cursors.
        let plan = unsafe { vram::Plan::read_navi48(gpu, &authority, range, &[]) }
            .map_err(Error::Memory)?;
        let training = plan.training();
        if training.is_some() {
            training_clients(plan.protected())?;
        }
        // SAFETY: the immutable inventory covers every inherited client, and
        // successful preparation excludes every later legacy MMIO accessor.
        // Nothing the driver allocates lies past the BAR: every owner takes
        // CPU-visible memory from `pool`, so that range is all clients'.
        let (unmapped, pool) = unsafe { (plan.unmapped_pool(), plan.into_pool()) };
        let (unmapped, pool) = (
            unmapped.map_err(Error::Memory)?,
            pool.map_err(Error::Memory)?,
        );
        // SAFETY: inventory covers every inherited client and CPU framebuffer
        // writers are paused. Construction performs bounded reads, never writes.
        let prepared = unsafe {
            boot::ColdBoot::new(gpu, pci, authority, &pool, unmapped, firmware, training)
        }
        .map_err(Error::Firmware)?;
        *owner = Some(alloc::boxed::Box::new(prepared));
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
    let mut report = boot.run().await?;
    // SAFETY: final boot handoff has CPU IRQ/executor initialization and keeps
    // all device reset/PM access excluded. The service owns IH independently.
    unsafe { boot.start_interrupt_service() }?;
    if let Some(live) = crate::amdgpu_navi48_interrupts::status().and_then(|s| s.report) {
        report.interrupts = live;
    }
    // Boot's block_on_spin may have IF=0. Defer the CPU-delivery proof to the
    // executor; the IRQ service keeps running independently of OWNER.
    narf_scheduler::spawn(prove_queue_interrupts());
    if let Some((limits, level)) = boot.power_info() {
        crate::amdgpu_navi48_power::start(limits, level);
    }
    register_submitter(
        boot,
        [const { crate::amdgpu_ring_watch::RingWatch::new() }; RINGS],
    );
    // Clients' VRAM buffers; without it they fall back to system memory.
    {
        use core::fmt::Write as _;
        let _ = match boot.publish_client_vram() {
            Ok(bytes) => writeln!(
                narf_console::Writer,
                "amdgpu: navi48 client VRAM heap {} MiB",
                bytes >> 20
            ),
            Err(e) => writeln!(
                narf_console::Writer,
                "amdgpu: navi48 no client VRAM heap: {e:?}"
            ),
        };
    }
    Ok(report)
}

fn register_submitter(
    boot: &boot::ColdBoot,
    watches: [crate::amdgpu_ring_watch::RingWatch; RINGS],
) {
    if let (Some(card), Some(fence)) = (boot::ColdBoot::drm_card(), boot.client_fence_reader()) {
        let submitter = Arc::new(Submitter {
            card,
            generation: *READ_GENERATION.lock(),
            fence,
            sdma_fence: boot.client_sdma_fence_reader(),
            contexts: narf_lib::sync::IrqSafeSpinLock::new([(0, 0); RINGS]),
            vmids: narf_lib::sync::IrqSafeSpinLock::new(crate::amdgpu_vmid::VmidManager::new(
                CLIENT_VMIDS.0,
                CLIENT_VMIDS.1,
            )),
            watch: narf_lib::sync::IrqSafeSpinLock::new(watches),
        });
        *SUBMITTER.lock() = Some(submitter.clone());
        crate::amdgpu_cs::register_submitter(card, submitter.clone());
        narf_scheduler::spawn(watchdog(submitter));
    }
}

/// Retains whichever owner recovery reached if its future is canceled.
struct RecoveryOwner {
    boot: Option<alloc::boxed::Box<boot::ColdBoot>>,
    armed: bool,
}
impl Drop for RecoveryOwner {
    fn drop(&mut self) {
        if self.armed {
            RECOVERY_STATE.store(3, Ordering::Release);
            crate::amdgpu_info::withdraw_navi48_clock();
            crate::amdgpu_navi48_interrupts::lose();
        }
        if let Some(boot) = self.boot.take() {
            QUARANTINED.lock().push(boot);
        }
    }
}
/// Explicit whole-device recovery after a failed ring reset. SMU14 mode1
/// loses VRAM contents. Old firmware/display allocations remain quarantined;
/// client allocations keep their addresses but their contexts report reset.
/// Restarts firmware, IH, queues and their interrupt proofs before publishing
/// a new submitter. The display monitor relights the fresh display owner.
/// Failure or cancellation is terminal and cannot be retried.
///
/// # Safety
/// Stop ALL CPU access to this GPU's VRAM, including userspace mmap and GOP
/// writers, and exclude other PCI/config/firmware owners until successful
/// return. Keep these exclusions after failure or cancellation. Clients
/// must handle lost VRAM contents. This cannot safely run from the watchdog
/// without an external mechanism providing those exclusions. Hardware unvalidated.
pub async unsafe fn recover() -> Result<boot::Report, boot::Error> {
    let mut owner = OWNER.lock().await;
    if RECOVERY_STATE.load(Ordering::Acquire) & 1 != 0 {
        return Err(boot::Error::Busy);
    }
    owner.as_mut().ok_or(boot::Error::Busy)?.prepare_reset()?;
    RECOVERY_STATE.store(1, Ordering::Release);
    let mut retained = RecoveryOwner {
        boot: owner.take(),
        armed: true,
    };
    let old_submitter = SUBMITTER.lock().take();
    if let Some(s) = &old_submitter {
        for w in s.watch.lock().iter_mut() {
            w.stop();
        }
    }
    if let Some(card) = boot::ColdBoot::drm_card() {
        crate::amdgpu_cs::unregister_submitter(card);
        crate::amdgpu_gem::unregister_vram_heap(card);
    }
    *READ_GENERATION.lock() += 1;
    let restart_display = DISPLAY_GENERATION.load(Ordering::Acquire) != 0;
    if restart_display {
        DISPLAY_GENERATION.fetch_add(1, Ordering::AcqRel);
    }
    crate::amdgpu_navi48_power::stop();
    *CLEARER.lock() = None;
    crate::amdgpu_info::withdraw_navi48_clock();
    for pipe in 0..4 {
        present_slot(pipe).native.store(false, Ordering::Release);
    }
    crate::amdgpu_dcn_display::publish_external(None, None);
    crate::scanout_access::wait_retired().await;
    crate::amdgpu_navi48_interrupts::stop_for_reset().await;
    let old = retained.boot.as_mut().unwrap();
    // SAFETY: OWNER excludes async access; readers, IH and publication were
    // withdrawn. The caller excludes all external CPU mappings and PCI users.
    unsafe { old.run_reset().await }?;
    // SAFETY: full reset and ASIC_Init proved old hardware no longer executes.
    let new = alloc::boxed::Box::new(unsafe { old.after_reset() }?);
    QUARANTINED.lock().push(retained.boot.replace(new).unwrap());
    let boot = retained.boot.as_mut().unwrap();
    let report = boot.run().await?;
    crate::amdgpu_navi48_dispatch::TABLE.lock().restart();
    // SAFETY: new retained IH/queues on the same exclusively owned GPU.
    unsafe { boot.start_interrupt_service() }?;
    // SAFETY: OWNER retains the new queues/GMC and the independent IH service.
    unsafe { boot.prove_queue_interrupts().await }.map_err(boot::Error::Queues)?;
    // SAFETY: GC12 proof drained; SDMA exclusively owns the same GMC test pages.
    unsafe { boot.prove_sdma_interrupts().await }.map_err(boot::Error::Sdma)?;
    if SHADER_PROOF.load(Ordering::Acquire) {
        // SAFETY: new queues are drained and all test-page users stay under OWNER.
        unsafe { boot.prove_shaders().await }.map_err(boot::Error::Queues)?;
    }
    let mut watches = old_submitter.as_ref().map_or_else(
        || [const { crate::amdgpu_ring_watch::RingWatch::new() }; RINGS],
        |s| {
            let old = s.watch.lock();
            core::array::from_fn(|i| old[i].successor())
        },
    );
    let done = core::array::from_fn(|i| watches[i].progress(0, 0));
    RECOVERIES.fetch_add(1, Ordering::AcqRel);
    boot.republish_client_vram();
    publish_clearer(boot);
    register_submitter(boot, watches);
    if let Some(card) = boot::ColdBoot::drm_card() {
        // Reset stopped every old job. Late deferred registrations are also
        // covered by the successor ledger's completed logical sequences.
        crate::amdgpu_cs::retire(card, &|t| job_done(done, t));
    }
    *owner = retained.boot.take();
    retained.armed = false;
    RECOVERY_STATE.store(2, Ordering::Release);
    if let Some((limits, level)) = owner.as_ref().and_then(|b| b.power_info()) {
        crate::amdgpu_navi48_power::restart(limits, level);
    }
    if restart_display {
        // SAFETY: caller's external writer exclusions and the existing native
        // display monitor contract persist. Only fresh modeset witnesses run.
        unsafe {
            spawn_display_monitor(boot::Configuration {
                displays: Vec::new(),
                failed: None,
            })
        };
    }
    Ok(report)
}

/// The Navi48 kernel queues behind AMDGPU_CS: up to eight IBs per
/// submission, all for one ring — graphics, compute or SDMA0 — run
/// in the open's address space on a GFX hub VMID from 1–7 (8–15 are KFD's,
/// as gmc_v12_0 sets first_kfd_vmid), granted by `amdgpu_vmid::VmidManager`
/// as amdgpu_vmid_grab does: a space keeps reusing its VMID without a
/// flush until it removes a mapping, and a submission that finds no idle
/// VMID waits for one.
///
/// A job's ticket is its pipe in the high 32 bits and its ring sequence in
/// the low. `amdgpu_cs` records each job on its address space, so the
/// buffers and page tables it may reach are freed only once its fence
/// passes; every fence read here retires what completed jobs held.
///
/// A job maps its VMID to its open's PASID in the IH LUT whenever the
/// VMID last mapped another (or that write may not have run yet), so its
/// faults carry the client's PASID and reach that open's GPUVM_FAULT query.
///
/// A watchdog (`watchdog`) times out a ring's front job after
/// `amdgpu_ring_watch::JOB_TIMEOUT_NS`: it ends with ETIME and retirement
/// freezes. Healthy contexts' queued jobs replay under their original tickets;
/// other jobs from the guilty context end with ECANCELED. The graphics ring is then reset through MES, the
/// compute ring by MMIO and remapped, SDMA0's ring by MMIO and reprogrammed,
/// and tested (`ColdBoot::recover_client_ring`, `recover_client_sdma`);
/// after replay is published it takes jobs again. A test fence never retires
/// an innocent job's memory.
///
/// AMDGPU_INFO keeps reporting acceleration unavailable, so Mesa does not
/// submit here.
struct Submitter {
    card: u32,
    generation: u64,
    fence: crate::amdgpu_gfx12_queue::FenceReader,
    /// SDMA0's job fence (no DMA ring without SDMA0). Its jobs are refused
    /// as busy until both SDMA proofs pass, as the GC12 queues' are.
    sdma_fence: Option<crate::amdgpu_sdma_navi48::FenceReader>,
    /// Touched only under OWNER, beside the submission it grants.
    vmids: narf_lib::sync::IrqSafeSpinLock<crate::amdgpu_vmid::VmidManager>,
    /// Each ring's last job's context, `(VmState::owner, ctx_id)`: the
    /// scheduler entity Linux compares for AMDGPU_HAVE_CTX_SWITCH. Touched
    /// only under OWNER.
    contexts: narf_lib::sync::IrqSafeSpinLock<[(u64, u32); RINGS]>,
    /// Each ring's jobs in flight and whether it hung.
    watch: narf_lib::sync::IrqSafeSpinLock<[crate::amdgpu_ring_watch::RingWatch; RINGS]>,
}
/// Why a ring's reset failed.
#[derive(Debug)]
#[allow(dead_code, reason = "read through Debug in the reset log")]
enum RingError {
    Queue(crate::amdgpu_gfx12_queue::Error),
    Sdma(crate::amdgpu_sdma_navi48::Error),
}
/// Client VMIDs on the GFX hub: 1 up to first_kfd_vmid (8) exclusive.
const CLIENT_VMIDS: (u8, u8) = (1, 7);
/// The rings by ticket index: the two GC12 queues, then SDMA0 (index 2).
const PIPES: [crate::amdgpu_gfx12_queue::Pipe; 2] = [
    crate::amdgpu_gfx12_queue::Pipe::Graphics,
    crate::amdgpu_gfx12_queue::Pipe::Compute,
];
const SDMA_RING: u32 = 2;
const RINGS: usize = 3;
/// Whether `ticket` is complete, given each ring's completed sequence
/// (32-bit sequences wrap).
fn job_done(completed: [u32; RINGS], ticket: u64) -> bool {
    let pipe = (ticket >> 32) as usize;
    completed
        .get(pipe)
        .is_some_and(|&c| c.wrapping_sub(ticket as u32) as i32 >= 0)
}
impl Submitter {
    /// Every ring's completed sequence, retiring what completed jobs held.
    /// None when the device stopped answering.
    fn progress(&self) -> Option<[u32; RINGS]> {
        let generation = READ_GENERATION.lock();
        if *generation != self.generation {
            return None;
        }
        let mut completed = [0; RINGS];
        for (c, pipe) in completed.iter_mut().zip(PIPES) {
            *c = self.fence.completed(pipe).ok()?;
        }
        if let Some(sdma) = &self.sdma_fence {
            completed[SDMA_RING as usize] = sdma.completed().ok()?;
        }
        // Lock after reading hardware: reset keeps each affected ledger frozen
        // until every replay fence is assigned. Old samples cannot complete a
        // new replay whose hardware sequence is strictly later.
        let now = narf_time::monotonic_ns();
        {
            let mut watches = self.watch.lock();
            for (watch, done) in watches.iter_mut().zip(&mut completed) {
                *done = watch.progress(*done, now);
            }
        }
        drop(generation);
        crate::amdgpu_cs::retire(self.card, &|t| job_done(completed, t));
        Some(completed)
    }
    /// Time out the front job of every ring that has held it too long,
    /// and recover the rings that can be.
    async fn watch(&self) {
        use core::fmt::Write as _;
        if !self.watch.lock().iter().any(|w| w.busy()) {
            return;
        }
        let Some(completed) = self.progress() else {
            return;
        };
        let now = narf_time::monotonic_ns();
        for (ring, &done) in completed.iter().enumerate() {
            let hung = self.watch.lock()[ring].check(now);
            let Some((seq, vmid)) = hung else {
                continue;
            };
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi48 ring {ring} timeout, signaled seq={}, job {seq} hung",
                done
            );
            let recovered = {
                let mut owner = OWNER.lock().await;
                if *READ_GENERATION.lock() != self.generation {
                    return;
                }
                let reset = match (owner.as_mut(), PIPES.get(ring)) {
                    // SAFETY: OWNER serializes the queues, SDMA0 and MES;
                    // every job on the ring holds its memory until its
                    // fence, which only the ring test's proves passed.
                    (Some(boot), Some(&pipe)) => unsafe { boot.recover_client_ring(pipe, vmid) }
                        .await
                        .map_err(RingError::Queue),
                    // SAFETY: as above.
                    (Some(boot), None) => unsafe { boot.recover_client_sdma(requeue_clears) }
                        .await
                        .map_err(RingError::Sdma),
                    (None, _) => Err(RingError::Queue(
                        crate::amdgpu_gfx12_queue::Error::DeviceGone,
                    )),
                };
                match (reset, owner.as_mut()) {
                    (Ok(test), Some(boot)) => {
                        let jobs = self.watch.lock()[ring].replay();
                        let mut result = Ok(test);
                        for (ticket, job) in jobs {
                            // SAFETY: OWNER stays held across reset and replay;
                            // the frozen ledger retains all buffers and VMIDs.
                            let submitted = match PIPES.get(ring) {
                                // SAFETY: frozen ledger and OWNER retain the job's VMID and memory.
                                Some(&pipe) => unsafe { boot.submit_client_job(pipe, job) }
                                    .map_err(RingError::Queue),
                                // SAFETY: same retained memory and exclusive SDMA owner.
                                None => unsafe { boot.submit_client_sdma_job(job) }
                                    .map_err(RingError::Sdma),
                            };
                            match submitted {
                                Ok(seq) => self.watch.lock()[ring].replayed(ticket, seq),
                                Err(e) => {
                                    result = Err(e);
                                    break;
                                }
                            }
                        }
                        if result.is_ok() {
                            // Next normal submission must establish its context.
                            self.contexts.lock()[ring] = (0, 0);
                            self.watch.lock()[ring].recovered(narf_time::monotonic_ns());
                        }
                        result
                    }
                    (Err(e), _) => Err(e),
                    (Ok(_), None) => unreachable!(),
                }
            };
            match recovered {
                Ok(test) => {
                    let _ = self.progress();
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi48 ring {ring} reset succeeded (test fence {test})"
                    );
                }
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi48 ring {ring} reset failed ({e:?}); ring stopped"
                    );
                }
            }
        }
    }
    /// How job `ticket` ended if not by completing (see `RingWatch`).
    fn job_error(&self, ticket: u64) -> Option<narf_filesystem::FsError> {
        let ring = (ticket >> 32) as usize;
        let error = self.watch.lock().get(ring)?.error(ticket as u32);
        error.or_else(|| {
            (*READ_GENERATION.lock() != self.generation)
                .then_some(narf_filesystem::FsError::NoDevice)
        })
    }
}

/// Check the card's rings for timed-out jobs every 100 ms while `submitter`
/// stays the card's registered one.
async fn watchdog(submitter: Arc<Submitter>) {
    loop {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(100_000).as_instant()).await;
        let current = crate::amdgpu_cs::submitter(submitter.card);
        let ours: Arc<dyn crate::amdgpu_cs::Submitter> = submitter.clone();
        if !current.is_some_and(|c| Arc::ptr_eq(&c, &ours)) {
            return;
        }
        submitter.watch().await;
    }
}
impl crate::amdgpu_cs::Submitter for Submitter {
    fn ring_for(&self, ip_type: u32, ip_instance: u32, ring: u32) -> Option<u32> {
        match (ip_type, ip_instance, ring) {
            (crate::amdgpu_uapi::AMDGPU_HW_IP_GFX, 0, 0) => Some(0),
            (crate::amdgpu_uapi::AMDGPU_HW_IP_COMPUTE, 0, 0) => Some(1),
            (crate::amdgpu_uapi::AMDGPU_HW_IP_DMA, 0, 0) if self.sdma_fence.is_some() => {
                Some(SDMA_RING)
            }
            _ => None,
        }
    }
    fn max_ibs(&self, _ring: u32) -> u32 {
        crate::amdgpu_gfx12_queue::MAX_JOB_IBS as u32
    }
    fn signalled(&self, ticket: u64) -> bool {
        // A revoked or vanished device makes no more progress; report done
        // so waiters cannot wedge.
        self.progress()
            .is_none_or(|completed| job_done(completed, ticket) || self.job_error(ticket).is_some())
    }
    fn error(&self, ticket: u64) -> Option<narf_filesystem::FsError> {
        self.job_error(ticket)
    }
    fn submit<'a>(
        &'a self,
        vm: &'a crate::amdgpu_vm::VmState,
        submission: &'a crate::amdgpu_cs::Submission,
        health: &'a Arc<crate::amdgpu_ctx::Health>,
    ) -> core::pin::Pin<
        alloc::boxed::Box<
            dyn core::future::Future<Output = Result<u64, narf_filesystem::FsError>> + Send + 'a,
        >,
    > {
        alloc::boxed::Box::pin(async move {
            use narf_filesystem::FsError;
            let first = submission.ibs.first().ok_or(FsError::InvalidData)?;
            let ring = self
                .ring_for(first.ip_type, first.ip_instance, first.ring)
                .ok_or(FsError::Unsupported)?;
            if submission.ibs.len() > crate::amdgpu_gfx12_queue::MAX_JOB_IBS
                || submission
                    .ibs
                    .iter()
                    .any(|ib| self.ring_for(ib.ip_type, ib.ip_instance, ib.ring) != Some(ring))
            {
                return Err(FsError::Unsupported);
            }
            let ibs: alloc::vec::Vec<(u64, u32)> = submission
                .ibs
                .iter()
                .map(|ib| (ib.va_start, ib.length_dw))
                .collect();
            if vm.geometry() != crate::amdgpu_vm::Geometry::GMC12 {
                return Err(FsError::InvalidData);
            }
            let pd_addr = vm.root_pde().ok_or(FsError::InvalidData)?;
            let pasid = vm.pasid().ok_or(FsError::NoSpace)?;
            let request = crate::amdgpu_vmid::GrabRequest {
                owner: vm.owner(),
                pd_addr,
                tlb_seq: vm.tlb_seq(),
                pasid,
                ring,
            };
            let mut job = crate::amdgpu_gfx12_queue::Job::new(0, pasid, pd_addr, &ibs)
                .ok_or(FsError::InvalidData)?;
            // amdgpu_ib_schedule asks the first IB.
            job.mem_sync = first.flags & crate::amdgpu_uapi::AMDGPU_IB_FLAG_EMIT_MEM_SYNC != 0;
            let entity = (request.owner, submission.ctx_id);
            let result = loop {
                let mut owner = OWNER.lock().await;
                let boot = owner.as_mut().ok_or(FsError::NoDevice)?;
                if health.reset_epoch() != crate::amdgpu_ctx::recoveries() {
                    health.mark_canceled();
                    break Err(FsError::Canceled);
                }
                if let Some(error) = health.error() {
                    break Err(error);
                }
                // A hung ring takes no more jobs until it is recovered.
                if let Some(error) = self.watch.lock()[ring as usize].refusing() {
                    break Err(error);
                }
                let completed = self.progress().ok_or(FsError::NoDevice)?;
                let done = |t| job_done(completed, t);
                let grant = self.vmids.lock().grab(request, &done);
                let Some(grant) = grant else {
                    // amdgpu_vmid_grab_idle: wait for a VMID to go idle.
                    drop(owner);
                    narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant())
                        .await;
                    continue;
                };
                job.vmid = grant.vmid;
                job.flush = grant.needs_flush;
                job.map_pasid = grant.map_pasid;
                job.ctx_switch = self.contexts.lock()[ring as usize] != entity;
                let result = match PIPES.get(ring as usize) {
                    // SAFETY: the platform serializes every queue user under
                    // OWNER; `amdgpu_cs` holds the job's memory until its
                    // fence, and the grant keeps another space off this VMID
                    // until then.
                    Some(&pipe) => unsafe { boot.submit_client_job(pipe, job) }.map_err(|e| {
                        use crate::amdgpu_gfx12_queue::Error;
                        match e {
                            Error::Busy => FsError::Busy,
                            Error::Invalid => FsError::InvalidData,
                            _ => FsError::NoDevice,
                        }
                    }),
                    // SAFETY: as above.
                    None => unsafe { boot.submit_client_sdma_job(job) }.map_err(|e| {
                        use crate::amdgpu_sdma_navi48::Error;
                        match e {
                            Error::Busy => FsError::Busy,
                            Error::Invalid => FsError::InvalidData,
                            _ => FsError::NoDevice,
                        }
                    }),
                };
                break result.map(|physical| {
                    let seq = self.watch.lock()[ring as usize].submitted(
                        physical,
                        job,
                        health.clone(),
                        narf_time::monotonic_ns(),
                    );
                    let ticket = u64::from(ring) << 32 | u64::from(seq);
                    self.vmids.lock().commit(request, grant, ticket);
                    self.contexts.lock()[ring as usize] = entity;
                    seq
                });
            };
            let _ = self.progress();
            result.map(|seq| u64::from(ring) << 32 | u64::from(seq))
        })
    }
    fn wait(
        &self,
        ticket: u64,
        deadline_ns: u64,
    ) -> core::pin::Pin<
        alloc::boxed::Box<
            dyn core::future::Future<Output = Result<bool, narf_filesystem::FsError>> + Send + '_,
        >,
    > {
        alloc::boxed::Box::pin(async move {
            use narf_filesystem::FsError;
            if (ticket >> 32) as usize >= RINGS {
                return Err(FsError::InvalidData);
            }
            loop {
                let completed = self.progress().ok_or(FsError::NoDevice)?;
                if job_done(completed, ticket) || self.job_error(ticket).is_some() {
                    return Ok(true);
                }
                if narf_time::monotonic_ns() >= deadline_ns {
                    return Ok(false);
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
            }
        })
    }
}

/// One PMFW telemetry refresh, serialized with every retained owner user.
pub(crate) async fn power_sample() -> Result<crate::amdgpu_navi48_power::Sample, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .power_sample()
        .await
}
/// Linux `power_dpm_force_performance_level` restricted to GFXCLK soft
/// limits. Display, memory and fabric clocks stay pinned by their owner.
pub async fn set_gfx_level(level: crate::amdgpu_smu_navi48::GfxLevel) -> Result<(), boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .set_gfx_level(level)
        .await
}

async fn prove_queue_interrupts() {
    let mut owner = OWNER.lock().await;
    if let Some(boot) = owner.as_mut() {
        // SAFETY: the platform retains matching owners and excludes reset/PM.
        // The proof checks CPU IRQ state before submitting any command. Its
        // result/cancellation state remains visible in the retained queues.
        if unsafe { boot.prove_queue_interrupts().await }.is_ok() {
            // SAFETY: GC12 has drained; the same exclusive owner serializes
            // SDMA against all other users of the retained GMC test pages.
            let proved = unsafe { boot.prove_sdma_interrupts().await };
            // SDMA0 now runs jobs, so it can clear VRAM past the BAR.
            if proved.is_ok() {
                if SHADER_PROOF.load(Ordering::Acquire) {
                    // SAFETY: both interrupt proofs drained; OWNER retains every
                    // queue and test page before client/clear work can acquire it.
                    let result = unsafe { boot.prove_shaders().await };
                    use core::fmt::Write;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi48 shader proof {result:?}"
                    );
                    if result.is_err() {
                        return;
                    }
                }
                publish_clearer(boot);
            }
        }
    }
}
fn publish_clearer(boot: &mut boot::ColdBoot) {
    if let Some(reader) = boot.client_sdma_fence_reader() {
        use core::fmt::Write as _;
        let generation = *READ_GENERATION.lock();
        let progress: SdmaProgress = Arc::new(move || {
            let current = READ_GENERATION.lock();
            if *current != generation {
                return None;
            }
            reader.completed().ok()
        });
        let clearer = VramClearer::new(progress);
        *CLEARER.lock() = Some(clearer.clone());
        let _ = match boot.publish_unmapped_vram(Arc::new(clearer)) {
            Ok(bytes) => writeln!(
                narf_console::Writer,
                "amdgpu: navi48 client VRAM past the BAR {} MiB",
                bytes >> 20
            ),
            Err(boot::Error::Busy) => Ok(()),
            Err(e) => writeln!(
                narf_console::Writer,
                "amdgpu: navi48 no client VRAM past the BAR: {e:?}"
            ),
        };
    }
}

/// Clears of client VRAM past the BAR on SDMA0 (`amdgpu_gem::VramClear`).
/// Requests queue in order; one drain task at a time takes them under OWNER,
/// batching as many as one kernel job holds, so they run — and complete —
/// in the order they were queued. Each fence is its job's sequence on
/// SDMA0's fence — the hardware's word alone, never a timeout's verdict, as
/// the clear is what keeps stale VRAM from the next owner.
#[derive(Debug, Clone)]
struct VramClearer(Arc<ClearQueue>);
struct ClearQueue {
    progress: SdmaProgress,
    state: narf_lib::sync::IrqSafeSpinLock<ClearState>,
}
/// The clears waiting for SDMA0 and those on its ring.
#[derive(Debug, Default)]
struct ClearState {
    /// Waiting to go on the ring, oldest first.
    queued: alloc::collections::VecDeque<Clear>,
    /// On the ring and not yet seen complete, oldest first.
    inflight: alloc::collections::VecDeque<Clear>,
    /// A drain task is running.
    draining: bool,
}
impl ClearState {
    /// Forget the clears on the ring that SDMA0 completed by `completed`.
    fn retire(&mut self, completed: u32) {
        use core::sync::atomic::Ordering;
        while self.inflight.front().is_some_and(|c| {
            completed.wrapping_sub(c.fence.seq.load(Ordering::Acquire) as u32) as i32 >= 0
        }) {
            self.inflight.pop_front();
        }
    }
    /// SDMA0's ring was reset at `completed`, skipping what it held past
    /// that: those clears never ran, so they go back to the front of the
    /// queue, in order and unsignalled, to run on the recovered ring.
    /// Returns whether a drain task must start.
    fn requeue(&mut self, completed: u32) -> bool {
        use core::sync::atomic::Ordering;
        self.retire(completed);
        while let Some(c) = self.inflight.pop_back() {
            c.fence.seq.store(u64::MAX, Ordering::Release);
            self.queued.push_front(c);
        }
        !self.queued.is_empty() && !core::mem::replace(&mut self.draining, true)
    }
}
/// The platform's VRAM clearer, which an SDMA0 reset hands its skipped
/// clears back to.
static CLEARER: narf_lib::sync::IrqSafeSpinLock<Option<VramClearer>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
/// After SDMA0's ring was reset at `completed`, run its skipped clears
/// again (`ClearState::requeue`).
fn requeue_clears(completed: u32) {
    let Some(clearer) = CLEARER.lock().clone() else {
        return;
    };
    if clearer.0.state.lock().requeue(completed) {
        narf_scheduler::spawn(clearer.drain());
    }
}
#[derive(Debug, Clone)]
struct Clear {
    address: u64,
    bytes: u64,
    fence: Arc<ClearFence>,
}
/// Fill packets one clear job carries at most: 5 dwords each, well inside
/// a 256-dword SDMA job slot with its fence.
const CLEAR_PACKETS: u64 = 32;
/// How many of the queued clears of `bytes` each one job takes: the front
/// ones whose fill packets fit, at least one.
fn clear_batch(bytes: impl Iterator<Item = u64>) -> usize {
    let mut packets = 0;
    bytes
        .take_while(|b| {
            packets += b.div_ceil(crate::amdgpu_sdma_navi48::MAX_PACKET_BYTES);
            packets <= CLEAR_PACKETS
        })
        .count()
        .max(1)
}
/// Whether one job can fill `bytes` at `address`: dword aligned, whole
/// dwords, and no more packets than a job takes.
fn clear_fits(address: u64, bytes: u64) -> bool {
    bytes != 0
        && bytes % 4 == 0
        && address % 4 == 0
        && bytes.div_ceil(crate::amdgpu_sdma_navi48::MAX_PACKET_BYTES) <= CLEAR_PACKETS
}
/// SDMA0's last completed job sequence, or None once the device stopped
/// answering.
type SdmaProgress = Arc<dyn Fn() -> Option<u32> + Send + Sync>;
/// One queued clear's completion.
struct ClearFence {
    progress: SdmaProgress,
    /// The kernel job's SDMA0 sequence once queued; `u64::MAX` before.
    seq: core::sync::atomic::AtomicU64,
    /// The device refused the job for good: nothing runs on it any more.
    gone: core::sync::atomic::AtomicBool,
}
impl core::fmt::Debug for ClearFence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClearFence")
            .field("seq", &self.seq)
            .field("gone", &self.gone)
            .finish()
    }
}
impl ClearFence {
    fn new(progress: SdmaProgress) -> Self {
        Self {
            progress,
            seq: core::sync::atomic::AtomicU64::new(u64::MAX),
            gone: core::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl narf_filesystem::DrmFence for ClearFence {
    fn is_signalled(&self) -> bool {
        use core::sync::atomic::Ordering;
        if self.gone.load(Ordering::Acquire) {
            return true;
        }
        let seq = self.seq.load(Ordering::Acquire);
        // A device that stopped answering runs nothing any more.
        seq != u64::MAX
            && (self.progress)().is_none_or(|done| done.wrapping_sub(seq as u32) as i32 >= 0)
    }
    fn wait(&self, timeout_ms: u64) -> bool {
        let deadline =
            narf_time::monotonic_ns().saturating_add(timeout_ms.saturating_mul(1_000_000));
        while !self.is_signalled() {
            if narf_time::monotonic_ns() >= deadline {
                return false;
            }
            narf_scheduler::block_on_spin(narf_time::SleepUntil::new(
                narf_time::Deadline::after_us(50).as_instant(),
            ));
        }
        true
    }
    fn driver_name(&self) -> &str {
        "amdgpu"
    }
}
impl core::fmt::Debug for ClearQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClearQueue")
            .field("queued", &self.state.lock().queued.len())
            .finish()
    }
}
impl VramClearer {
    fn new(progress: SdmaProgress) -> Self {
        Self(Arc::new(ClearQueue {
            progress,
            state: narf_lib::sync::IrqSafeSpinLock::new(ClearState::default()),
        }))
    }
    /// Run queued clears until none is left.
    async fn drain(self) {
        use crate::amdgpu_sdma_navi48::KernelOp;
        use core::sync::atomic::Ordering;
        loop {
            // The batch is taken and queued under OWNER, as an SDMA0 reset
            // requeues skipped clears at the queue's front under it too.
            let mut owner = OWNER.lock().await;
            // The front clears that fit one job, left queued until they are
            // in the ring so a later request cannot overtake them.
            let batch: Vec<Clear> = {
                let mut state = self.0.state.lock();
                if state.queued.is_empty() {
                    state.draining = false;
                    return;
                }
                let n = clear_batch(state.queued.iter().map(|c| c.bytes));
                state.queued.iter().take(n).cloned().collect()
            };
            let ops: Vec<KernelOp> = batch
                .iter()
                .map(|c| KernelOp::Fill {
                    dst: c.address,
                    bytes: c.bytes,
                    value: 0,
                })
                .collect();
            let result = match owner.as_mut() {
                // SAFETY: OWNER serializes SDMA0's ring; each range is a
                // client reservation the GEM layer holds no job can reach
                // before this job's fence (its KERNEL fence).
                Some(boot) if (self.0.progress)().is_some() => unsafe {
                    boot.submit_client_sdma_kernel(&ops)
                },
                _ => Err(crate::amdgpu_sdma_navi48::Error::DeviceGone),
            };
            match result {
                // The ring is full: let jobs retire.
                Err(crate::amdgpu_sdma_navi48::Error::Busy) => {
                    drop(owner);
                    narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant())
                        .await;
                    continue;
                }
                Ok(seq) => {
                    for c in &batch {
                        c.fence.seq.store(u64::from(seq), Ordering::Release);
                    }
                    let completed = (self.0.progress)();
                    let mut state = self.0.state.lock();
                    let ran: Vec<Clear> = state.queued.drain(..batch.len()).collect();
                    state.inflight.extend(ran);
                    if let Some(completed) = completed {
                        state.retire(completed);
                    }
                }
                // `clear` validated every request, so the device is gone.
                Err(_) => {
                    for c in &batch {
                        c.fence.gone.store(true, Ordering::Release);
                    }
                    self.0.state.lock().queued.drain(..batch.len());
                }
            }
        }
    }
}
impl crate::amdgpu_gem::VramClear for VramClearer {
    fn clear(
        &self,
        address: u64,
        bytes: u64,
    ) -> Result<Arc<dyn narf_filesystem::DrmFence>, narf_filesystem::FsError> {
        if !clear_fits(address, bytes) {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        if (self.0.progress)().is_none() {
            return Err(narf_filesystem::FsError::NoDevice);
        }
        let fence = Arc::new(ClearFence::new(self.0.progress.clone()));
        let start = {
            let mut state = self.0.state.lock();
            state
                .queued
                .try_reserve(1)
                .map_err(|_| narf_filesystem::FsError::NoSpace)?;
            state.queued.push_back(Clear {
                address,
                bytes,
                fence: fence.clone(),
            });
            !core::mem::replace(&mut state.draining, true)
        };
        if start {
            narf_scheduler::spawn(self.clone().drain());
        }
        Ok(fence)
    }
}

/// Serialized native HPD query. Requires the completed, retained cold boot.
pub async fn dmub_hpd(instance: u8) -> Result<bool, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .dmub()?
        .hpd(instance)
        .await
        .map_err(boot::Error::Dmub)
}
/// Serialized native AUX/I2C-over-AUX transaction, at most 16 bytes.
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
        .dmub()?
        .aux(instance, action, address, data)
        .await
        .map_err(boot::Error::Dmub)
}
pub async fn dmub_notification() -> Result<Option<[u8; 64]>, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .dmub()?
        .poll_notification()
        .map_err(boot::Error::Dmub)
}

/// Board routing copied before exclusive controller handoff. No device I/O.
pub async fn display_paths() -> Result<Vec<crate::amdgpu_dcn_inventory::Path>, boot::Error> {
    let owner = OWNER.lock().await;
    let paths = owner
        .as_ref()
        .ok_or(boot::Error::Invalid)?
        .display_paths()
        .map_err(boot::Error::Display)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(paths.len())
        .map_err(|_| boot::Error::Allocation)?;
    result.extend_from_slice(paths);
    Ok(result)
}
/// Serialized DPCD/EDID discovery on board-routed native DP/eDP/HDMI ports.
/// Includes per-port failures; fatal transport failures stop the scan.
pub async fn scan_display() -> Result<Vec<display::Port>, boot::Error> {
    let mut owner = OWNER.lock().await;
    owner
        .as_mut()
        .ok_or(boot::Error::Invalid)?
        .scan_display()
        .await
}

/// Establish native DCN4 clock floors with all display consumers retired.
/// Serializes both MP1 mailboxes against every other retained hardware owner.
pub async fn prepare_display_clocks(
    request: crate::amdgpu_dcn401_clk::Request,
) -> Result<crate::amdgpu_dcn401_clk::Applied, crate::amdgpu_dcn401_clk::Error> {
    OWNER
        .lock()
        .await
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_clk::Error::Busy)?
        .prepare_display_clocks(request)
        .await
}

/// Divide native per-pipe clocks while holding the retained display/PM owner.
pub async fn prepare_display_pipe_clocks(
    request: crate::amdgpu_dcn401_dccg::Request,
) -> Result<crate::amdgpu_dcn401_dccg::Applied, crate::amdgpu_dcn401_dccg::Error> {
    OWNER
        .lock()
        .await
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_dccg::Error::Busy)?
        .prepare_display_pipe_clocks(request)
        .await
}

/// Connect a prepared native pixel clock to a retired HPO DP or FRL stream.
pub async fn route_display_stream_clock(
    route: crate::amdgpu_dcn401_dccg::StreamRoute,
) -> Result<(), crate::amdgpu_dcn401_dccg::Error> {
    OWNER
        .lock()
        .await
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_dccg::Error::Busy)?
        .route_display_stream_clock(route)
}

/// Prepare disabled native timing against current, matching pipe clocks.
pub async fn prepare_display_timing(
    request: crate::amdgpu_dcn401_otg::Request,
) -> Result<crate::amdgpu_dcn401_otg::Applied, crate::amdgpu_dcn401_otg::Error> {
    OWNER
        .lock()
        .await
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?
        .prepare_display_timing(request)
        .await
}

/// Stage native OPP RGB formatting and black pattern; timing remains disabled.
pub async fn prepare_display_blank(
    request: crate::amdgpu_dcn401_otg::BlankRequest,
) -> Result<crate::amdgpu_dcn401_otg::BlankApplied, crate::amdgpu_dcn401_otg::Error> {
    OWNER
        .lock()
        .await
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?
        .prepare_display_blank(request)
        .await
}

/// Start internal black timing while fetchers and external streams stay stopped.
/// # Safety
/// Stop CPU scanout writers, exclude other fetcher/cursor/metadata writers and
/// retain all associated surfaces, page tables, HUBP and OPP resources. Success
/// does not permit freeing resources or enabling a plane/link.
pub async unsafe fn start_display_blank(
    pipe: u8,
) -> Result<crate::amdgpu_dcn401_otg::BlankRunning, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: owner serializes display/PM; caller retains memory and excludes writers.
    unsafe { boot.start_display_blank(pipe).await }
}

/// # Safety
/// Stop scanout CPU writers and retain every associated surface, page table,
/// HUBP and OPP resource. Completion proves timing retirement only.
pub async unsafe fn retire_display_timing(pipe: u8) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained owner serializes display/PM; caller retains scanout memory.
    unsafe { boot.retire_display_timing(pipe).await }
}

/// Disconnect all native MPC planes and stop drained HUBP fetch clocks.
/// # Safety
/// Stop CPU scanout writers and exclude all surface/cursor/metadata/LUT, MPC,
/// firmware/FAMS and power writers. Retain all associated allocations and
/// translations; completion does not permit freeing or reusing them.
pub async unsafe fn retire_display_planes(
) -> Result<crate::amdgpu_dcn401_otg::PlanesRetired, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller excludes writers and retains memory.
    unsafe { boot.retire_display_planes().await }
}

/// Power a disconnected HUBP on to blank readiness, or gate a drained HUBP.
/// # Safety
/// Stop CPU scanout writers, exclude firmware/FAMS and concurrent display,
/// auxiliary fetcher, clock and power writers, and retain every allocation and
/// translation on every outcome. Completion never permits memory reuse.
pub async unsafe fn set_display_hubp_power(
    pipe: u8,
    powered: bool,
) -> Result<crate::amdgpu_dcn401_otg::HubpPower, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller excludes writers and retains memory.
    unsafe { boot.set_display_hubp_power(pipe, powered).await }
}

/// Stage an owned linear framebuffer while pixel fetch stays disabled.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/HDP/clock/power writers;
/// retain the owner and inherited resources on every outcome.
pub async unsafe fn prepare_display_surface(
    request: crate::amdgpu_dcn401_otg::SurfaceRequest,
) -> Result<crate::amdgpu_dcn401_otg::SurfaceApplied, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller excludes external writers.
    unsafe { boot.prepare_display_surface(request).await }
}

/// Upload a visible row segment of a staged, stopped framebuffer.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/HDP/clock/power writers;
/// retain the owner and inherited resources on every outcome.
pub async unsafe fn upload_display_surface(
    pipe: u8,
    x: u32,
    y: u32,
    pixels: &[u32],
) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; upload checks bounds and live state.
    unsafe { boot.upload_display_surface(pipe, x, y, pixels) }
}

/// Prepare DCN framebuffer translation for an owned, staged surface.
/// # Safety
/// Exclude firmware/FAMS and concurrent hub/VM/display/clock/reset/power writers;
/// retain the owner and all inherited resources on every outcome.
pub async unsafe fn prepare_display_memory(
    pipe: u8,
) -> Result<crate::amdgpu_dcn401_otg::MemoryApplied, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.prepare_display_memory(pipe).await }
}

/// Stage native RGB processing for the retained full-frame surface.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/hub/VM/clock/reset/power writers;
/// retain the owner and all inherited resources on every outcome.
pub async unsafe fn prepare_display_dpp(
    pipe: u8,
) -> Result<crate::amdgpu_dcn401_otg::DppApplied, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.prepare_display_dpp(pipe).await }
}

/// Stage opaque RGB composition for the retained full-frame surface.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/hub/VM/clock/reset/power writers;
/// retain the owner and all inherited resources on every outcome.
pub async unsafe fn prepare_display_mpc(
    pipe: u8,
) -> Result<crate::amdgpu_dcn401_otg::MpcApplied, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.prepare_display_mpc(pipe) }
}

/// Stage bounded requests and the native default single-pipe display buffers.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/hub/VM/IRQ/clock/reset/power writers;
/// retain the owner and every resource on success, error and cancellation.
pub async unsafe fn prepare_display_requestor(
    pipe: u8,
) -> Result<crate::amdgpu_dcn401_otg::RequestorApplied, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.prepare_display_requestor(pipe).await }
}

/// Admit one single-pipe scanout mode against the live board. Read-only.
pub async fn display_admission(
    mode: crate::amdgpu_dcn401_dml::Mode,
) -> Result<crate::amdgpu_dcn401_dml::Plan, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    boot.display_admission(&mode)
}

/// Program an admitted plan's deadlines and watermarks for the staged pipe.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/hub/VM/IRQ/clock/reset/power writers;
/// retain the owner and every resource on success, error and cancellation.
pub async unsafe fn prepare_display_deadlines(
    pipe: u8,
    plan: crate::amdgpu_dcn401_dml::Plan,
) -> Result<crate::amdgpu_dcn401_otg::DeadlinesApplied, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.prepare_display_deadlines(pipe, &plan).await }
}

/// Flush hook published with the live scanout. Never waits: if the owner is
/// busy the HDP write buffer still drains by itself, only later.
fn flush_scanout() {
    if let Some(mut owner) = OWNER.try_lock() {
        if let Some(boot) = owner.as_mut() {
            let _ = boot.flush_display_scanout();
        }
    }
}

/// Retire the legacy DP SST output the firmware left running.
/// # Safety
/// Stop CPU writers of the inherited scanout role and exclude firmware/FAMS
/// and concurrent display/audio/link/clock/power writers.
pub async unsafe fn retire_inherited_display(
) -> Result<crate::amdgpu_navi48_boot::InheritedRetired, crate::amdgpu_navi48_boot::ModesetError> {
    use crate::amdgpu_navi48_boot::{Error as BootError, ModesetError};
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ModesetError::Boot(BootError::Busy))?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.retire_inherited_display().await }
}

// ── Native displays ──────────────────────────────────────────────────
//
// Connectors: every lightable board port (DisplayPort or HDMI) in board
// order and, while a DP port's MST branch is in use, that branch's four
// end-device slots (the root's own connector then reports nothing, as
// amdgpu_dm's MST root). Display k is pipe k, its owner slot and CRTC k.
// Each CRTC is routed to at most one connector: as DRM set it (SETCRTC's
// connector, an atomic connector CRTC_ID), else automatically to plugged
// connectors in connector order. The console runs on the first lit
// display; DRM clients present per display.

type Timing = crate::amdgpu_dml::Timing;
type Modeset = crate::amdgpu_navi48_boot::Modeset;
type ModesetError = crate::amdgpu_navi48_boot::ModesetError;
type ConnectorType = crate::drm::card::ConnectorType;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Pipe of the console's display, for the cursor hook.
static CURSOR_PIPE: AtomicU8 = AtomicU8::new(0);
static DISPLAY_GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The pipe (display) the console runs on.
pub fn console_pipe() -> u8 {
    CURSOR_PIPE.load(Ordering::Acquire)
}

/// What a connector drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    /// A board DP or HDMI port (display-path index).
    Board(usize),
    /// End device `slot` (`MstLink::outputs`) behind board DP port `port`.
    Mst(usize, u8),
}

/// KMS index of an MST end device's connector: past any board port.
const MST_INDEX: usize = 32;

/// One connector and its sink as last discovered.
#[derive(Debug)]
struct ConnectorState {
    target: Target,
    kind: ConnectorType,
    /// KMS object index: board ordinal, or `MST_INDEX` + slot.
    index: usize,
    present: bool,
    /// DRM detached it from its CRTC: automatic routing leaves it dark.
    parked: bool,
    edid: Vec<u8>,
    /// Admitted timings for routing it to a CRTC that does not show it.
    modes: Vec<Timing>,
    mst_id: Option<boot::MstOutputId>,
    last_hpd: Option<bool>,
}
impl ConnectorState {
    fn new(target: Target, kind: ConnectorType, index: usize) -> Self {
        Self {
            target,
            kind,
            index,
            present: false,
            parked: false,
            edid: Vec::new(),
            modes: Vec::new(),
            mst_id: None,
            last_hpd: None,
        }
    }
    /// A board sink's discovery; true when its EDID changed.
    fn reconcile_sst(&mut self, output: Option<&boot::SstOutput>) -> bool {
        self.present = output.is_some();
        self.modes.clear();
        let Some(output) = output else {
            return false;
        };
        let changed = self.edid != output.edid;
        if changed {
            self.edid.clone_from(&output.edid);
        }
        self.modes.clone_from(&output.modes);
        changed
    }
    fn observe_sst_hpd(&mut self, present: bool) -> bool {
        let reprobe = present && !self.last_hpd.unwrap_or(self.present);
        self.last_hpd = Some(present);
        if !present {
            self.reconcile_sst(None);
        }
        reprobe
    }
    /// An end device's discovery: (another device took the slot, its EDID
    /// changed). A new device starts unparked.
    fn reconcile_mst(&mut self, output: Option<&boot::MstOutput>) -> (bool, bool) {
        let id = output.map(|o| o.id);
        let reset = self.mst_id != id;
        if reset {
            *self = Self::new(self.target, self.kind, self.index);
            self.mst_id = id;
        }
        self.present = output.is_some_and(|o| o.sink.is_some());
        self.modes.clear();
        let mut changed = false;
        // Never advertise the old monitor's modes after a different or
        // unreadable EDID appears.
        if let Some(output) = output.filter(|_| self.present) {
            self.modes.clone_from(&output.modes);
            if self.edid != output.edid {
                changed = true;
                self.edid.clone_from(&output.edid);
            }
        }
        (reset, changed)
    }
}

/// What DRM asked of one CRTC and what it shows: a CRTC switched off keeps
/// its connector published (connected), as Linux keeps a disabled
/// connector's modes.
#[derive(Debug)]
struct CrtcState {
    /// DRM wants the CRTC on (SETCRTC with a framebuffer, atomic ACTIVE=1).
    active: bool,
    /// A recorded teardown stays inactive even if DRM requests on meanwhile.
    retiring: bool,
    /// The mode DRM last set, or None for the sink's preferred mode.
    requested: Option<Timing>,
    /// The lit sink: EDID, running timing and every offered timing.
    shown: Option<([u8; 128], Timing, Vec<Timing>)>,
    /// The connector this CRTC drives.
    route: Option<Target>,
    /// DRM chose `route` (including none): automatic routing leaves it.
    explicit: bool,
}
impl CrtcState {
    const fn new() -> Self {
        Self {
            active: true,
            retiring: false,
            requested: None,
            shown: None,
            route: None,
            explicit: false,
        }
    }
    fn retrained(&mut self, edid: [u8; 128], timing: Timing, offered: Vec<Timing>) {
        // A lower trained link can invalidate alternatives and queued requests.
        // Keep the actual running timing and update KMS without re-adopting VRAM.
        self.requested = self.requested.filter(|t| offered.contains(t));
        self.shown = Some((edid, timing, offered));
    }
    fn published_active(&self) -> bool {
        self.active && !self.retiring
    }
}

/// The connectors and CRTCs, under one lock.
#[derive(Debug)]
struct Outputs {
    connectors: Vec<ConnectorState>,
    crtcs: [CrtcState; 4],
}
impl Outputs {
    const fn new() -> Self {
        Self {
            connectors: Vec::new(),
            crtcs: [const { CrtcState::new() }; 4],
        }
    }
    fn connector(&self, target: Target) -> Option<&ConnectorState> {
        self.connectors.iter().find(|c| c.target == target)
    }
    fn connector_mut(&mut self, target: Target) -> Option<&mut ConnectorState> {
        self.connectors.iter_mut().find(|c| c.target == target)
    }
    fn routed(&self, k: usize) -> Option<&ConnectorState> {
        self.crtcs[k].route.and_then(|t| self.connector(t))
    }
    /// The CRTC routed to `target`.
    fn crtc_of(&self, target: Target) -> Option<usize> {
        self.crtcs.iter().position(|c| c.route == Some(target))
    }
    /// Replace the connector set, keeping the discovery of every connector
    /// that remains. Routes to vanished connectors are dropped.
    fn reshape(&mut self, shape: &[(Target, ConnectorType, usize)]) {
        let old = core::mem::take(&mut self.connectors);
        self.connectors = shape
            .iter()
            .map(|&(target, kind, index)| {
                old.iter()
                    .position(|c| c.target == target)
                    .map(|i| &old[i])
                    .map_or_else(
                        || ConnectorState::new(target, kind, index),
                        |c| ConnectorState {
                            target,
                            kind,
                            index,
                            present: c.present,
                            parked: c.parked,
                            edid: c.edid.clone(),
                            modes: c.modes.clone(),
                            mst_id: c.mst_id,
                            last_hpd: c.last_hpd,
                        },
                    )
            })
            .collect();
        for k in 0..4 {
            if self.crtcs[k]
                .route
                .is_some_and(|t| self.connector(t).is_none())
            {
                self.drop_route(k);
            }
        }
    }
    fn drop_route(&mut self, k: usize) {
        let c = &mut self.crtcs[k];
        c.route = None;
        c.explicit = false;
        c.requested = None;
        c.shown = None;
    }
    /// A connector's sink changed: requests for the old one are void; a
    /// new device in an MST slot also forgets the CRTC's off request.
    fn invalidate(&mut self, target: Target, reset: bool) {
        if let Some(k) = self.crtc_of(target) {
            let c = &mut self.crtcs[k];
            c.requested = None;
            c.shown = None;
            if reset {
                c.active = true;
            }
        }
    }
    /// Automatic routing: a CRTC DRM did not route drops a connector whose
    /// sink left; each plugged, unparked connector without a CRTC takes the
    /// first such free CRTC. Running displays keep their CRTCs.
    fn assign_routes(&mut self) {
        for k in 0..4 {
            let c = &self.crtcs[k];
            if c.explicit {
                continue;
            }
            if c.route
                .is_some_and(|t| !self.connector(t).is_some_and(|x| x.present))
            {
                self.drop_route(k);
            }
        }
        for n in 0..self.connectors.len() {
            let x = &self.connectors[n];
            if !x.present || x.parked || self.crtc_of(x.target).is_some() {
                continue;
            }
            let target = x.target;
            if let Some(c) = self
                .crtcs
                .iter_mut()
                .find(|c| c.route.is_none() && !c.explicit)
            {
                c.route = Some(target);
            }
        }
    }
    /// DRM routed CRTC k to `target` (None: no connector). Another CRTC
    /// driving that connector loses it; a connector left without a CRTC is
    /// parked so automatic routing does not light it elsewhere.
    fn route(&mut self, k: usize, target: Option<Target>) {
        let old = self.crtcs[k].route;
        if let Some(t) = target {
            if let Some(j) = self.crtc_of(t).filter(|&j| j != k) {
                self.drop_route(j);
                self.crtcs[j].explicit = true;
            }
            if let Some(x) = self.connector_mut(t) {
                x.parked = false;
            }
        }
        if old != target {
            if let Some(x) = old.and_then(|t| self.connector_mut(t)) {
                x.parked = true;
            }
            let c = &mut self.crtcs[k];
            c.route = target;
            c.requested = None;
            c.shown = None;
        }
        self.crtcs[k].explicit = true;
    }
    /// The sink CRTC k shows to DRM: while on and its connector has a sink.
    fn published(&self, k: usize) -> Option<&([u8; 128], Timing, Vec<Timing>)> {
        let c = &self.crtcs[k];
        (c.active && self.routed(k).is_some_and(|x| x.present))
            .then_some(c.shown.as_ref())
            .flatten()
    }
    /// Timings a CRTC can switch `target` (default: its route) to.
    fn offered(&self, k: usize, target: Option<Target>) -> &[Timing] {
        let target = target.or(self.crtcs[k].route);
        let Some(x) = target.and_then(|t| self.connector(t)).filter(|x| x.present) else {
            return &[];
        };
        match &self.crtcs[k].shown {
            Some((_, _, offered)) if self.crtcs[k].route == Some(x.target) => offered,
            _ => &x.modes,
        }
    }
    fn find_mode(
        &self,
        k: usize,
        target: Option<Target>,
        mode: &crate::drm::ioctl::DrmModeModeInfo,
    ) -> Option<Timing> {
        let geometry = |w: &crate::drm::ioctl::DrmModeModeInfo| {
            (
                w.clock,
                [w.hdisplay, w.hsync_start, w.hsync_end, w.htotal],
                [w.vdisplay, w.vsync_start, w.vsync_end, w.vtotal],
            )
        };
        self.offered(k, target)
            .iter()
            .copied()
            .find(|t| geometry(&crate::amdgpu_navi48_kms::timing_wire(t)) == geometry(mode))
    }
    /// The connector behind a KMS connector id.
    fn target_of_id(&self, connector_id: u32) -> Option<Target> {
        let n = crate::amdgpu_navi48_kms::connector_index(connector_id)?;
        self.connectors
            .iter()
            .find(|c| c.index == n)
            .map(|c| c.target)
    }
    /// The MST root port, while its branch's connectors exist.
    fn mst_port(&self) -> Option<usize> {
        self.connectors.iter().find_map(|c| match c.target {
            Target::Mst(port, _) => Some(port),
            Target::Board(_) => None,
        })
    }
}
static OUTPUTS: narf_lib::sync::IrqSafeSpinLock<Outputs> =
    narf_lib::sync::IrqSafeSpinLock::new(Outputs::new());

/// The connector set: every lightable board port, then `mst`'s four
/// end-device slots.
fn connector_shape(
    boot: &boot::ColdBoot,
    mst: Option<usize>,
) -> Vec<(Target, ConnectorType, usize)> {
    use crate::amdgpu_dcn_inventory::Connector;
    let Ok(paths) = boot.display_paths() else {
        return Vec::new();
    };
    let mut shape: Vec<_> = paths
        .iter()
        .enumerate()
        .filter_map(|(port, p)| match p.connector {
            Connector::DisplayPort => Some((port, ConnectorType::DisplayPort)),
            Connector::HdmiTypeA => Some((port, ConnectorType::HdmiA)),
            _ => None,
        })
        .enumerate()
        .map(|(n, (port, kind))| (Target::Board(port), kind, n))
        .collect();
    if let Some(port) = mst {
        for slot in 0..crate::amdgpu_navi48_kms::MAX_OUTPUTS as u8 {
            shape.push((
                Target::Mst(port, slot),
                ConnectorType::DisplayPort,
                MST_INDEX + usize::from(slot),
            ));
        }
    }
    shape
}

/// The board DP/HDMI ports.
fn board_ports(boot: &boot::ColdBoot) -> Vec<usize> {
    connector_shape(boot, None)
        .into_iter()
        .filter_map(|(t, _, _)| match t {
            Target::Board(port) => Some(port),
            Target::Mst(..) => None,
        })
        .collect()
}

/// Publish every connector and CRTC on the amdgpu card's KMS state; a
/// shown sink whose CRTC DRM switched off stays connected with its CRTC off.
fn publish_outputs() {
    let outputs = OUTPUTS.lock();
    let crtcs: Vec<Option<crate::amdgpu_navi48_kms::Sink>> = (0..4)
        .map(|k| {
            outputs
                .published(k)
                .map(|(edid, timing, offered)| crate::amdgpu_navi48_kms::Sink {
                    edid,
                    timing,
                    offered,
                })
        })
        .collect();
    let connectors: Vec<crate::amdgpu_navi48_kms::RoutedConnector> = outputs
        .connectors
        .iter()
        .map(|c| crate::amdgpu_navi48_kms::RoutedConnector {
            index: c.index,
            kind: c.kind,
            edid: c
                .present
                .then(|| c.edid.get(..128).and_then(|e| e.try_into().ok()))
                .flatten(),
            offered: if c.present { &c.modes } else { &[] },
            crtc: outputs.crtc_of(c.target),
            possible_crtcs: 0xf,
        })
        .collect();
    crate::amdgpu_navi48_kms::publish_routed(&crtcs, &connectors);
    for (k, sink) in crtcs.iter().enumerate() {
        if sink.is_some() && !outputs.crtcs[k].published_active() {
            crate::amdgpu_navi48_kms::set_active(k, false);
        }
    }
}

/// Cursor hook published with the console's scanout: upload once, then
/// move; hide with an off-screen move. Never waits for the owner.
fn scanout_cursor(image: (u32, u32, &[u32]), position: Option<(i32, i32)>) -> bool {
    let pipe = CURSOR_PIPE.load(Ordering::Acquire);
    let Some(mut owner) = OWNER.try_lock() else {
        return true;
    };
    let Some(boot) = owner.as_mut() else {
        return true;
    };
    let (w, h, _) = image;
    let shown = boot
        .display_status(pipe)
        .ok()
        .flatten()
        .and_then(|s| s.cursor)
        .is_some_and(|c| c.pipe == pipe && (c.width, c.height) == (w, h));
    // A failure quarantines the pipe in the owner; the pointer just stops.
    let _ = match (shown, position) {
        (false, None) => return true, // never shown: nothing to hide
        // SAFETY: serialized retained owner; the platform excludes writers.
        (true, at) => unsafe {
            boot.move_display_cursor(pipe, at.unwrap_or((-(w as i32), -(h as i32))))
        },
        // SAFETY: as above.
        (false, Some(at)) => unsafe { boot.set_display_cursor(pipe, image, at) },
    };
    true
}

/// Put the console on `pipe`'s live scanout, or withdraw it.
fn publish_console(boot: &boot::ColdBoot, pipe: Option<u8>) {
    match pipe.and_then(|p| boot.display_scanout_framebuffer(p).ok().map(|fb| (p, fb))) {
        Some((p, fb)) => {
            CURSOR_PIPE.store(p, Ordering::Release);
            crate::amdgpu_dcn_display::publish_external(Some(fb), Some(flush_scanout));
            crate::amdgpu_dcn_display::publish_external_cursor(Some(scanout_cursor));
        }
        None => crate::amdgpu_dcn_display::publish_external(None, None),
    }
}

/// Make `m` presentable: its back buffer (reused across relights of the
/// same geometry) for tear-free DRM frames, its vblank count continued, its
/// sink published as shown.
/// # Safety
/// As for `modeset_displays`.
async unsafe fn adopt(boot: &mut boot::ColdBoot, m: &Modeset) {
    let pipe = m.pipe;
    // Without a back buffer (allocation failed) DRM frames fall back to
    // copies onto the visible front.
    // SAFETY: the caller's obligations; touches only owned VRAM and HDP.
    let _ = unsafe { boot.prepare_display_back_buffer(pipe).await };
    present_slot(pipe).native.store(
        boot.display_back_framebuffer(pipe).is_ok(),
        Ordering::Release,
    );
    // Its timing generator restarted: the vblank count continues.
    restart_vblank(pipe);
    let s = &m.selection;
    let offered: Vec<Timing> = m.modes.iter().flatten().copied().collect();
    if let Some(c) = OUTPUTS.lock().crtcs.get_mut(usize::from(pipe)) {
        c.shown = Some((s.edid, s.timing, offered));
        c.retiring = false;
    }
}

/// Stop presenting on `pipe` and, when it carried the console, move the
/// console to another lit display (or withdraw it).
async fn withdraw(boot: &boot::ColdBoot, pipe: u8, lit: &[Option<Modeset>; 4]) {
    present_slot(pipe).native.store(false, Ordering::Release);
    if CURSOR_PIPE.load(Ordering::Acquire) == pipe {
        let next = lit
            .iter()
            .flatten()
            .map(|m| m.pipe)
            .find(|&p| p != pipe && boot.display_teardown_status(p).is_none());
        publish_console(boot, next);
    }
    crate::scanout_access::wait_retired().await;
}

/// Light every plugged sink whose CRTC DRM has not switched off, as one
/// configuration (output k on pipe k), filling rows with `fill(pipe, y,
/// row)` before each fetch starts, then publish them: the console on the
/// first display, every output on KMS. Every display must be stopped.
/// # Safety
/// Inherited display consumers must be retired; withdraw and drain any CPU
/// views of retained surfaces before entry. Exclude firmware/FAMS and
/// concurrent display/hub/VM/IRQ/clock/reset/power/link writers.
pub async unsafe fn modeset_displays(
    fill: impl FnMut(u8, u32, &mut [u32]),
) -> Result<crate::amdgpu_navi48_boot::Configuration, ModesetError> {
    use crate::amdgpu_navi48_boot::Error as BootError;
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ModesetError::Boot(BootError::Busy))?;
    // SAFETY: the caller's obligations.
    unsafe { light_displays(boot, fill) }.await
}

/// `modeset_displays` with the owner held.
/// # Safety
/// As for `modeset_displays`.
async unsafe fn light_displays(
    boot: &mut boot::ColdBoot,
    fill: impl FnMut(u8, u32, &mut [u32]),
) -> Result<crate::amdgpu_navi48_boot::Configuration, ModesetError> {
    if pending_display_work(boot) {
        return Err(crate::amdgpu_dcn401_otg::Error::Busy.into());
    }
    // The first plugged DP port whose sink is an MST branch adds its end
    // devices' connectors; every other board port stays a connector too.
    let mut mst = None;
    for port in board_ports(boot) {
        if boot
            .display_paths()
            .ok()
            .and_then(|p| p.get(port))
            .is_none_or(|p| p.connector != crate::amdgpu_dcn_inventory::Connector::DisplayPort)
        {
            continue;
        }
        // HPD may still be disabled on cold boot; sense refuses such a
        // block. Route the board pin before using sense to choose MST.
        // SAFETY: the board-routed pin has no concurrent GPIO user.
        match unsafe { boot.enable_display_hpd(port) } {
            Ok(()) => {}
            Err(crate::amdgpu_dcn401_otg::Error::Unsupported) => continue,
            Err(e) => return Err(e.into()),
        }
        if boot.display_hpd(port) == Ok(true)
            && (boot.display_mst(port).is_some() || boot.display_mst_capable(port).await)
        {
            mst = Some(port);
            break;
        }
    }
    let shape = connector_shape(boot, mst);
    OUTPUTS.lock().reshape(&shape);
    if let Some(port) = mst {
        boot.start_display_mst(port).await?;
        reconcile_mst_outputs(boot, port);
        // Clear old CRTC/framebuffer bindings for removed/reassigned monitors
        // before a newly lit sink can inherit the slot's DRM framebuffer.
        publish_outputs();
    }
    // Routes and requests as this lighting sees them.
    let (routes, wants) = {
        let mut outputs = OUTPUTS.lock();
        if let Some(port) = mst {
            // The MST root's own connector carries no sink meanwhile.
            if let Some(root) = outputs.connector_mut(Target::Board(port)) {
                root.reconcile_sst(None);
            }
        }
        outputs.assign_routes();
        // What this lighting lights is shown afresh; a CRTC DRM switched
        // off keeps its connector published.
        for c in outputs.crtcs.iter_mut().filter(|c| c.active) {
            c.shown = None;
        }
        let routes: [Option<Target>; 4] = core::array::from_fn(|k| {
            let c = &outputs.crtcs[k];
            c.route.filter(|_| c.active)
        });
        let wants: [Option<Timing>; 4] = core::array::from_fn(|k| outputs.crtcs[k].requested);
        (routes, wants)
    };
    let crtc_of = |t: Target| routes.iter().position(|r| *r == Some(t));
    let pipe = |port: usize| crtc_of(Target::Board(port)).map(|k| k as u8);
    let want = |port: usize| crtc_of(Target::Board(port)).and_then(|k| wants[k]);
    let mst_pipes: Vec<Option<u8>> = (0..crate::amdgpu_navi48_kms::MAX_OUTPUTS as u8)
        .map(|slot| {
            mst.and_then(|port| crtc_of(Target::Mst(port, slot)))
                .map(|k| k as u8)
        })
        .collect();
    let mst_want = |slot: usize| {
        mst.and_then(|port| crtc_of(Target::Mst(port, slot as u8)))
            .and_then(|k| wants[k])
    };
    let route = mst.map(|port| boot::MstRoute {
        port,
        // End device k stays on its connector, including gaps for disabled
        // or unreadable devices: compacting would move another monitor.
        pipes: &mst_pipes,
        want: &mst_want,
    });
    // SAFETY: the caller's obligations.
    let result = unsafe { boot.modeset_routed(fill, want, pipe, route) }.await;
    {
        let mut outputs = OUTPUTS.lock();
        for c in &mut outputs.crtcs {
            c.retiring = false;
        }
        let ports = board_ports(boot);
        for port in ports {
            let hpd = boot.display_hpd(port).ok();
            let sst = boot.display_sst_outputs().iter().find(|o| o.port == port);
            let Some(x) = outputs.connector_mut(Target::Board(port)) else {
                continue;
            };
            let changed = if Some(port) == mst {
                x.reconcile_sst(None)
            } else {
                x.reconcile_sst(sst)
            };
            x.last_hpd = hpd;
            if changed {
                outputs.invalidate(Target::Board(port), false);
            }
        }
    }
    if let Some(port) = mst {
        reconcile_mst_outputs(boot, port);
    }
    // Even a failed preferred-mode activation leaves a valid connector
    // inventory. It must not publish the former monitor's modes.
    publish_outputs();
    let config = result?;
    for m in &config.displays {
        // SAFETY: as above.
        unsafe { adopt(boot, m) }.await;
    }
    publish_console(boot, config.displays.first().map(|m| m.pipe));
    publish_outputs();
    Ok(config)
}

/// Bring the branch's end-device connectors up to date.
fn reconcile_mst_outputs(boot: &boot::ColdBoot, port: usize) {
    let Some(link) = boot.display_mst(port) else {
        return;
    };
    let mut outputs = OUTPUTS.lock();
    for (slot, output) in link.outputs.iter().enumerate() {
        let target = Target::Mst(port, slot as u8);
        let Some(x) = outputs.connector_mut(target) else {
            continue;
        };
        let (reset, changed) = x.reconcile_mst(output.as_ref());
        if reset || changed {
            outputs.invalidate(target, reset);
        }
    }
}

/// The connector a running modeset drives.
fn target_of(boot: &boot::ColdBoot, m: &Modeset) -> Option<Target> {
    let port = m.selection.port;
    let Some(stream) = m.selection.mst else {
        return Some(Target::Board(port));
    };
    let link = boot.display_mst(port)?;
    let slot = link
        .outputs
        .iter()
        .position(|o| o.as_ref().is_some_and(|o| o.sink == Some(stream.sink)))?;
    Some(Target::Mst(port, slot as u8))
}

/// Allocate the back buffer of a staged or live pipe and return its CPU view.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/HDP writers.
pub async unsafe fn prepare_display_back_buffer(
    pipe: u8,
) -> Result<GenericFb, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    crate::scanout_access::wait_retired().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller excludes external writers.
    unsafe { boot.prepare_display_back_buffer(pipe).await }?;
    boot.display_back_framebuffer(pipe)
}

/// Flip a live scanout to its back buffer. If the console had adopted the old
/// front, it follows the new one, so it keeps drawing to the visible buffer.
/// # Safety
/// The back buffer must hold the complete next frame with no CPU writer until
/// the next flip. Exclude firmware/FAMS and concurrent display writers.
pub async unsafe fn flip_display(
    pipe: u8,
) -> Result<crate::amdgpu_dcn401_otg::FlipDone, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    let before = boot.display_scanout_framebuffer(pipe)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    let done = unsafe { boot.flip_display(pipe).await }?;
    follow_flip(before, boot.display_scanout_framebuffer(pipe)?).await;
    Ok(done)
}

/// Follow a flip while still holding OWNER. Retired CPU views must finish
/// before another presenter can overwrite the former front as its back buffer.
async fn follow_flip(before: GenericFb, after: GenericFb) {
    if crate::amdgpu_dcn_display::active_scanout().is_some_and(|fb| fb.addr == before.addr) {
        crate::amdgpu_dcn_display::publish_external(Some(after), Some(flush_scanout));
        crate::amdgpu_dcn_display::publish_external_cursor(Some(scanout_cursor));
    }
    crate::scanout_access::wait_retired().await;
}

/// One display's DRM presentation: whether frames go through its back
/// buffer and a latched flip, whether a presenter task drains it, and the
/// newest frame not yet copied (a newer one replaces it: mailbox).
struct PresentSlot {
    native: AtomicBool,
    presenting: AtomicBool,
    next: narf_lib::sync::IrqSafeSpinLock<Option<Frame>>,
}
impl PresentSlot {
    const fn new() -> Self {
        Self {
            native: AtomicBool::new(false),
            presenting: AtomicBool::new(false),
            next: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
}
static PRESENT: [PresentSlot; 4] = [const { PresentSlot::new() }; 4];
fn present_slot(display: u8) -> &'static PresentSlot {
    &PRESENT[usize::from(display).min(PRESENT.len() - 1)]
}

/// A DRM client's XRGB8888 frame in a kernel-mapped dumb buffer, and the
/// flip-complete ticket (see `drm::card::FlipLog`) its flip completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    phys: u64,
    pitch: u32,
    width: u32,
    height: u32,
    ticket: Option<u64>,
}

/// Whether `present_frame` on `display` would present through a hardware
/// flip now, so a DRM flip-complete event should wait for that flip.
pub fn native_present_ready(display: u8) -> bool {
    usize::from(display) < PRESENT.len() && present_slot(display).native.load(Ordering::Acquire)
}

/// One display's hardware vblank clock: the last reading (24-bit cooked
/// count, its extension to DRM's 64-bit count, the clock then) and when it
/// was read. After a relight the count continues from the last one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VblankClock {
    raw: Option<u32>,
    time: crate::drm::card::VblankTime,
    read_ns: u64,
}

static VBLANK_CLOCKS: [narf_lib::sync::IrqSafeSpinLock<Option<VblankClock>>; 4] = [
    narf_lib::sync::IrqSafeSpinLock::new(None),
    narf_lib::sync::IrqSafeSpinLock::new(None),
    narf_lib::sync::IrqSafeSpinLock::new(None),
    narf_lib::sync::IrqSafeSpinLock::new(None),
];

/// Fold a reading into the clock: the 24-bit count advances the 64-bit
/// one by its wrapped difference; the first reading after a (re)light
/// counts one past the last known vblank.
fn extend_vblank(
    clock: Option<VblankClock>,
    phase: crate::amdgpu_dcn401_otg::VblankPhase,
    read_ns: u64,
) -> VblankClock {
    const FRAME_MASK: u32 = 0xff_ffff;
    let count = match clock {
        Some(VblankClock {
            raw: Some(raw),
            time,
            ..
        }) => time.count + u64::from(phase.count.wrapping_sub(raw) & FRAME_MASK),
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

/// A clock reading carried forward whole periods to `now`, while the
/// owner is busy; none once the reading is a second old.
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

/// Read display `display`'s vblank clock from the hardware (display k
/// scans out on pipe k). None while its timing does not run.
fn read_vblank(boot: &mut boot::ColdBoot, display: u8) -> Option<crate::drm::card::VblankTime> {
    let slot = VBLANK_CLOCKS.get(usize::from(display))?;
    let position = boot.display_scanout_position(display).ok()?;
    let read_ns = narf_time::wall::monotonic_ns();
    let phase = position.phase()?;
    let mut clock = slot.lock();
    let next = extend_vblank(*clock, phase, read_ns);
    *clock = Some(next);
    Some(next.time)
}

/// Start display `display`'s count again from its last vblank: its timing
/// generator was relit and its frame count restarted.
fn restart_vblank(display: u8) {
    if let Some(slot) = VBLANK_CLOCKS.get(usize::from(display)) {
        if let Some(clock) = slot.lock().as_mut() {
            clock.raw = None;
        }
    }
}

/// The hardware vblank clock of display `display`, read now, or carried
/// forward from a recent reading while the display owner is busy.
pub fn vblank_time(display: u8) -> Option<crate::drm::card::VblankTime> {
    if let Some(mut owner) = OWNER.try_lock() {
        let boot = owner.as_mut()?;
        return read_vblank(boot, display);
    }
    let clock = (*VBLANK_CLOCKS.get(usize::from(display))?.lock())?;
    extrapolate_vblank(clock, narf_time::wall::monotonic_ns())
}

/// `drm::card::VblankSource` for the native CRTC.
pub fn crtc_vblank(crtc_id: u32) -> Option<crate::drm::card::VblankTime> {
    let display = crate::amdgpu_navi48_kms::crtc_display(crtc_id)?;
    vblank_time(display)
}

/// Complete display `display`'s flip-complete events up to `ticket`: at
/// the latched flip, in the vblank it latched in, or now in the last known
/// vblank when the frame will not be flipped.
fn complete_flip(display: u8, ticket: Option<u64>, latched: Option<crate::drm::card::VblankTime>) {
    use crate::drm::card::{flips, FlipStamp};
    let Some(ticket) = ticket else {
        return;
    };
    let ns = narf_time::wall::monotonic_ns();
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
            log.complete(ticket, FlipStamp { ns, sequence });
        }
    }
}

/// Queue a DRM client's frame for tear-free presentation on display
/// `display`'s scanout: its presenter copies it into the back buffer (which
/// no fetch reads) and flips at the next VUPDATE, so scanout never shows a
/// partly copied frame. Frames arriving while a copy or flip is in progress
/// replace any frame still waiting (mailbox); the latest always shows.
/// Returns false when native presentation is not available there, and the
/// caller then copies onto the visible front as before.
///
/// `ticket` (of the display's flip log) completes when the frame's flip
/// latches, or when the frame is replaced, refused or fails to present: no
/// event waits forever.
///
/// DRM's buffer rules make the deferred read safe: a client leaves a
/// submitted framebuffer untouched until its flip-complete event, which
/// is not sent before the copy is done.
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
    let slot = present_slot(display);
    {
        let mut next = slot.next.lock();
        // A replaced frame's event completes with the frame replacing it.
        let ticket = ticket.max(next.and_then(|f| f.ticket));
        *next = Some(Frame {
            phys,
            pitch,
            width,
            height,
            ticket,
        });
    }
    if !slot.presenting.swap(true, Ordering::AcqRel) {
        narf_scheduler::spawn(presenter(display));
    }
    true
}

async fn presenter(display: u8) {
    use core::fmt::Write;
    let slot = present_slot(display);
    loop {
        let Some(frame) = slot.next.lock().take() else {
            slot.presenting.store(false, Ordering::Release);
            // A frame queued between the take and the store found the flag
            // still set and spawned nothing: keep draining.
            if slot.next.lock().is_some() && !slot.presenting.swap(true, Ordering::AcqRel) {
                continue;
            }
            return;
        };
        if !slot.native.load(Ordering::Acquire) {
            complete_flip(display, frame.ticket, None);
            continue;
        }
        let result = {
            let mut owner = OWNER.lock().await;
            match owner.as_mut() {
                // SAFETY: the owner lock serializes display writers; the
                // frame's dumb buffer stays valid under DRM's buffer rules.
                Some(boot) => match unsafe { present_native(boot, display, frame).await } {
                    // The vblank the flip latched in, as DRM counts it.
                    Ok((before, after, _)) => {
                        let latched = read_vblank(boot, display);
                        follow_flip(before, after).await;
                        Ok(latched)
                    }
                    Err(e) => Err(e),
                },
                None => Err(crate::amdgpu_dcn401_otg::Error::Busy),
            }
        };
        match result {
            Ok(latched) => complete_flip(display, frame.ticket, latched),
            Err(e) => {
                complete_flip(display, frame.ticket, None);
                // A failed flip quarantines the pipe; later frames use the
                // fallback copy, which a stopped pipe simply does not show.
                slot.native.store(false, Ordering::Release);
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi48 native present on display {display} disabled: {e:?}"
                );
            }
        }
    }
}

/// Copy `frame` into the back buffer of the live pipe, then flip to it.
/// Returns the published front before and after, and the flip.
/// # Safety
/// The caller holds the owner lock; `frame` names a mapped dumb buffer.
async unsafe fn present_native(
    boot: &mut boot::ColdBoot,
    pipe: u8,
    frame: Frame,
) -> Result<
    (GenericFb, GenericFb, crate::amdgpu_dcn401_otg::FlipDone),
    crate::amdgpu_dcn401_otg::Error,
> {
    // A previous presenter may have been cancelled while draining the old
    // front after a successful flip. Finish that barrier before reusing it.
    crate::scanout_access::wait_retired().await;
    let back = boot.display_back_framebuffer(pipe)?;
    let width = frame.width.min(back.width);
    for y in 0..frame.height.min(back.height) {
        let at = frame.phys + u64::from(y) * u64::from(frame.pitch);
        // SAFETY: a kernel-mapped dumb buffer row of at least `width` pixels
        // (pitch >= 4 * width was checked when queued).
        let row = unsafe {
            core::slice::from_raw_parts(
                narf_memory::PhysAddr::new(at).kernel_ptr::<u32>(),
                width as usize,
            )
        };
        // SAFETY: serialized retained owner; caller excludes writers.
        unsafe { boot.upload_display_back(pipe, 0, y, row) }?;
        if y % 64 == 63 {
            narf_scheduler::yield_now().await;
        }
    }
    let before = boot.display_scanout_framebuffer(pipe)?;
    // SAFETY: the back buffer holds the complete frame; no other writer
    // touches it until the next flip (the owner lock is held).
    let done = unsafe { boot.flip_display(pipe).await }?;
    Ok((before, boot.display_scanout_framebuffer(pipe)?, done))
}

/// Show a premultiplied ARGB8888 cursor (at most 64x64) on a live pipe.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/HDP writers.
pub async unsafe fn set_display_cursor(
    pipe: u8,
    image: (u32, u32, &[u32]),
    position: (i32, i32),
) -> Result<crate::amdgpu_dcn401_otg::CursorApplied, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller excludes external writers.
    unsafe { boot.set_display_cursor(pipe, image, position) }
}

/// Move the live cursor without waiting: a pointer pump must never block on
/// a modeset or flip in progress, so a busy owner simply skips this move.
/// # Safety
/// As for `set_display_cursor`.
pub unsafe fn try_move_display_cursor(
    pipe: u8,
    position: (i32, i32),
) -> Option<Result<crate::amdgpu_dcn401_otg::CursorApplied, crate::amdgpu_dcn401_otg::Error>> {
    let mut owner = OWNER.try_lock()?;
    let boot = owner.as_mut()?;
    // SAFETY: serialized retained owner; caller excludes external writers.
    Some(unsafe { boot.move_display_cursor(pipe, position) })
}

/// Highest HDMI output depth native modesets may pick (8, 10 or 12 bpc;
/// default 8 as DRM's max_requested_bpc). Other values are ignored.
pub fn set_max_bpc(bpc: u8) {
    crate::amdgpu_navi48_boot::set_max_bpc(bpc);
}

/// Let native modesets drive HDMI FRL when TMDS cannot carry a mode
/// (Linux's dcfeaturemask DC_FRL_MASK; off by default).
pub fn set_frl(enabled: bool) {
    crate::amdgpu_navi48_boot::set_frl(enabled);
}

/// Poll period of the native display monitor. DCN HPD/HPD-RX vectors (and
/// lost IH vectors) wake it early through the interrupt dispatcher: the
/// monitor arms each lightable port's HPD interrupt and acknowledges raised
/// ones on wake; the period remains the fallback.
const MONITOR_MS: u64 = 1000;
const FRL_MONITOR_MS: u64 = 200;

/// What one native display monitor pass did to an output (pipe).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorStep {
    /// The DP link lost lock and was retrained; scanout resumed.
    Retrained(u8),
    /// HPD fell: the display's scanout was withdrawn and its modeset torn
    /// down; the others run on.
    Unplugged(u8),
    /// A DRM client switched the CRTC off: the display was torn down, its
    /// connector staying connected.
    Disabled(u8),
    /// The configuration was lit again (a new sink, a CRTC switched back on,
    /// another mode or output range): this many displays now run.
    Relit(u8),
}

/// Record DRM's CRTC on/off request for display `display`. Level-triggered:
/// the display monitor converges the hardware to it on its next pass, so a
/// quick off/on pair does nothing.
pub fn request_display_active(display: u8, active: bool) {
    if let Some(c) = OUTPUTS.lock().crtcs.get_mut(usize::from(display)) {
        c.active = active;
    }
}

/// Record DRM's routing of CRTC `display` to the connector with KMS id
/// `connector` (None: no connector), as SETCRTC's connector list or an
/// atomic connector CRTC_ID sets it. Any encoder may drive any CRTC; a
/// connector moved here leaves its old CRTC. The monitor relights when a
/// running display's connector changes. False for an unknown connector.
pub fn request_display_route(display: u8, connector: Option<u32>) -> bool {
    let mut outputs = OUTPUTS.lock();
    let k = usize::from(display);
    if k >= 4 {
        return false;
    }
    let target = match connector {
        Some(id) => match outputs.target_of_id(id) {
            Some(t) => Some(t),
            None => return false,
        },
        None => None,
    };
    if outputs.crtcs[k].route != target || !outputs.crtcs[k].explicit {
        outputs.route(k, target);
    }
    true
}

/// Record DRM's routing of the connector with KMS id `connector` to CRTC
/// `display` (None: detached from every CRTC).
pub fn request_connector_crtc(connector: u32, display: Option<u8>) -> bool {
    match display {
        Some(display) => request_display_route(display, Some(connector)),
        None => {
            let mut outputs = OUTPUTS.lock();
            let Some(target) = outputs.target_of_id(connector) else {
                return false;
            };
            if let Some(k) = outputs.crtc_of(target) {
                outputs.route(k, None);
            }
            true
        }
    }
}

/// Record a DRM "Broadcast RGB" value (0 Automatic, 1 Full, 2 Limited
/// 16:235) for the native displays. Like a mode request, the display
/// monitor relights running displays whose output range no longer matches.
pub fn request_broadcast_rgb(value: u8) {
    crate::amdgpu_navi48_boot::set_broadcast_rgb(value);
}

/// Whether display `display` offers `mode` on its routed connector, or on
/// `connector` (a KMS id) when the same request routes it there.
pub fn display_offers(
    display: u8,
    connector: Option<u32>,
    mode: &crate::drm::ioctl::DrmModeModeInfo,
) -> bool {
    let outputs = OUTPUTS.lock();
    let k = usize::from(display);
    if k >= 4 {
        return false;
    }
    let target = match connector {
        Some(id) => match outputs.target_of_id(id) {
            Some(t) => Some(t),
            None => return false,
        },
        None => None,
    };
    outputs.find_mode(k, target, mode).is_some()
}

/// Record the mode a DRM client set on display `display` (SETCRTC or an
/// atomic MODE_ID), which must be one of its connector's offered timings;
/// `None` returns it to its preferred mode. Returns false for a mode the
/// display does not offer. Route first when the same request routes it.
pub fn request_display_mode(
    display: u8,
    mode: Option<&crate::drm::ioctl::DrmModeModeInfo>,
) -> bool {
    let mut outputs = OUTPUTS.lock();
    let k = usize::from(display);
    if k >= 4 {
        return false;
    }
    let Some(m) = mode else {
        outputs.crtcs[k].requested = None;
        return true;
    };
    match outputs.find_mode(k, None, m) {
        Some(t) => {
            outputs.crtcs[k].requested = Some(t);
            true
        }
        None => false,
    }
}

/// Every display back to the console's defaults (on, preferred mode,
/// automatic routing), as drm_fb_helper restores the console on lastclose.
pub fn restore_displays() {
    let mut outputs = OUTPUTS.lock();
    for c in outputs.crtcs.iter_mut() {
        c.active = true;
        c.requested = None;
        c.explicit = false;
    }
    for x in outputs.connectors.iter_mut() {
        x.parked = false;
    }
}

/// The monitor's view of the configuration: each pipe's running modeset,
/// and the outputs whose plugged sinks the last lighting already considered
/// (lit or left dark), so only a new sink or a returned CRTC relights.
#[derive(Debug)]
pub struct Displays {
    generation: u64,
    epoch: u64,
    lit: [Option<Modeset>; 4],
    considered: u8,
}

/// Whether the configuration must be lit again: a running display asked
/// for another mode or output range (`changed`), or a plugged sink on an
/// output DRM has not switched off (`wanted`) that is neither lit nor was
/// considered by the last lighting (which may have left it dark: it did
/// not fit). A sink that left (lit or not), or whose CRTC DRM switched off,
/// is new again when it returns.
fn needs_relight(changed: bool, wanted: u8, lit: u8, considered: &mut u8) -> bool {
    *considered &= wanted | lit;
    changed || wanted & !*considered & !lit != 0
}

fn monitor_order(pending: u8) -> impl Iterator<Item = u8> {
    (0..4u8)
        .filter(move |p| pending & (1 << p) != 0)
        .chain((0..4u8).filter(move |p| pending & (1 << p) == 0))
}

fn pending_display_work(boot: &boot::ColdBoot) -> bool {
    boot.display_modesets().iter().any(Option::is_some)
        || (0..4).any(|p| {
            boot.display_teardown_status(p)
                .is_some_and(|s| s.next != boot::TeardownStep::Complete)
        })
}

/// Whether CRTC k's routed connector has a sink: board sinks by HPD, end
/// devices by the retained downstream snapshot (physical HPD describes the
/// root only), including when no stream is running.
fn routed_present(boot: &mut boot::ColdBoot, outputs: &Outputs, k: usize) -> bool {
    match outputs.crtcs[k].route {
        Some(Target::Board(port)) => {
            boot.display_hpd(port) == Ok(true) && outputs.mst_port() != Some(port)
        }
        Some(Target::Mst(port, slot)) => {
            boot.display_hpd(port) == Ok(true)
                && boot.display_mst(port).is_some_and(|l| {
                    l.outputs
                        .get(usize::from(slot))
                        .and_then(Option::as_ref)
                        .is_some_and(|o| o.sink.is_some())
                })
        }
        None => false,
    }
}

/// CRTCs DRM wants on whose connectors have sinks.
fn wanted_mask(boot: &mut boot::ColdBoot) -> u8 {
    let outputs = OUTPUTS.lock();
    (0..4)
        .filter(|&k| outputs.crtcs[k].active && routed_present(boot, &outputs, k))
        .fold(0, |acc, k| acc | 1 << k)
}

/// Record before the CPU drain, then finish native retirement and release.
/// The caller's Displays retains the Modeset across cancellation and errors.
/// # Safety
/// As for monitor_displays, with OWNER held.
async unsafe fn retire_monitored_display(
    boot: &mut boot::ColdBoot,
    displays: &mut Displays,
    pipe: u8,
    unplugged: bool,
) -> Result<(), ModesetError> {
    let m = displays.lit[usize::from(pipe)].ok_or(crate::amdgpu_dcn401_otg::Error::Invalid)?;
    // Before teardown can change the branch's payload records.
    let target = target_of(boot, &m);
    boot.begin_modeset_teardown(&m, unplugged)?;
    OUTPUTS.lock().crtcs[usize::from(pipe)].retiring = true;
    publish_outputs();
    withdraw(boot, pipe, &displays.lit).await;
    // SAFETY: CPU views drained and OWNER excludes native producers. The
    // retained journal skips successes; the unfinished native step checks itself.
    unsafe {
        if unplugged {
            boot.unplug_modeset(&m).await?;
        } else {
            boot.stop_modeset(&m).await?;
        }
        boot.release_display_surfaces(pipe)?;
    }
    displays.lit[usize::from(pipe)] = None;
    // A request to reactivate during withdrawal is a new lighting attempt.
    displays.considered &= !(1 << pipe);
    {
        let mut outputs = OUTPUTS.lock();
        outputs.crtcs[usize::from(pipe)].shown = None;
        // A disable need not relight siblings. Retain the modes already
        // admitted beside them, without a CRTC mode; the next configuration
        // or reprobe recomputes independent admission.
        if let Some(x) = target.and_then(|t| outputs.connector_mut(t)) {
            if unplugged {
                // An end device's presence follows the branch snapshot.
                if matches!(x.target, Target::Board(_)) {
                    x.present = false;
                }
                x.modes.clear();
            } else {
                x.modes = m.modes.iter().flatten().copied().collect();
            }
        }
    }
    publish_outputs();
    Ok(())
}

/// One monitor pass over every output: tear down displays DRM switched
/// off or whose sink left, retrain lost links, and relight the whole
/// configuration when a sink appears (or a CRTC returns) or a running
/// display's requested mode or output range changed.
/// # Safety
/// As for `modeset_displays`.
pub async unsafe fn monitor_displays(
    displays: &mut Displays,
) -> Result<Vec<MonitorStep>, ModesetError> {
    use crate::amdgpu_navi48_boot::{Error as BootError, Health};
    let mut steps = Vec::new();
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ModesetError::Boot(BootError::Busy))?;
    if displays.generation != DISPLAY_GENERATION.load(Ordering::Acquire) {
        return Ok(steps);
    }
    if displays.epoch != recoveries() {
        displays.epoch = recoveries();
        displays.lit = [None; 4];
        displays.considered = 0;
        for c in &mut OUTPUTS.lock().crtcs {
            c.shown = None;
            c.retiring = false;
        }
    }
    // Cancellation may have lost the caller's configuration during a later
    // pipe startup or asynchronous adoption. Restore actual completed witnesses
    // and retire them through the usual CPU withdrawal and native journal.
    let recovered = boot.restore_modesets(&mut displays.lit)?;
    for pipe in (0..4u8).filter(|p| recovered & (1 << p) != 0) {
        let m = displays.lit[usize::from(pipe)].unwrap();
        let unplugged = boot.display_hpd(m.selection.port) == Ok(false);
        boot.begin_modeset_teardown(&m, unplugged)?;
    }
    // Failed activations have no Modeset in Displays. Finish their recorded
    // abort before topology service or selecting an already-lit sibling.
    for pipe in 0..4 {
        if boot
            .display_teardown_status(pipe)
            .is_some_and(|s| s.activation)
        {
            if displays.lit[usize::from(pipe)].is_some() {
                return Err(crate::amdgpu_dcn401_otg::Error::Busy.into());
            }
            // SAFETY: this activation never published a CPU scanout; OWNER
            // and the caller's exclusions retain every native resource.
            unsafe { boot.abort_modeset_activation(pipe) }.await?;
            displays.considered &= !(1 << pipe);
        }
    }
    // Keep a connected branch's connectors and DRM requests even when its
    // CRTCs are off. Only the root's physical removal drops them, once no
    // stream on that branch remains.
    let mst_port = OUTPUTS.lock().mst_port();
    if let Some(port) = mst_port.filter(|&p| boot.display_hpd(p) == Ok(false)) {
        let streaming = displays
            .lit
            .iter()
            .flatten()
            .any(|m| m.selection.port == port && m.selection.mst.is_some());
        if !streaming {
            boot.forget_unplugged_display_mst(port)?;
            let shape = connector_shape(boot, None);
            OUTPUTS.lock().reshape(&shape);
            displays.considered = 0;
            publish_outputs();
        }
    }
    let mst_port = OUTPUTS.lock().mst_port();
    let wants: [(bool, Option<Timing>); 4] = {
        let outputs = OUTPUTS.lock();
        core::array::from_fn(|k| (outputs.crtcs[k].active, outputs.crtcs[k].requested))
    };
    let limited =
        crate::amdgpu_navi48_boot::limited_range(crate::amdgpu_navi48_boot::broadcast_rgb());
    let pending_mask = (0..4u8)
        .filter(|&p| {
            displays.lit[usize::from(p)].is_some() && boot.display_teardown_status(p).is_some()
        })
        .fold(0u8, |mask, p| mask | (1 << p));
    let mut relight = false;
    for port in board_ports(boot) {
        if Some(port) == mst_port {
            continue;
        }
        if let Ok(present) = boot.display_hpd(port) {
            let mut outputs = OUTPUTS.lock();
            // A disabled port still needs a new EDID/admission snapshot
            // when HPD rises. Physical removal needs no AUX transaction.
            if let Some(x) = outputs.connector_mut(Target::Board(port)) {
                relight |= x.observe_sst_hpd(present);
            }
        }
    }
    publish_outputs();
    if let Some(port) = mst_port {
        if pending_mask == 0
            && boot.display_hpd(port) == Ok(true)
            && boot.display_mst(port).is_some()
        {
            relight |= boot.service_display_mst(port).await?;
        }
    }
    for k in monitor_order(pending_mask) {
        let Some(m) = displays.lit[usize::from(k)] else {
            continue;
        };
        let pending = boot.display_teardown_status(k);
        let unplugged =
            boot.display_hpd(m.selection.port) == Ok(false) || pending.is_some_and(|p| p.unplugged);
        if unplugged || !wants[usize::from(k)].0 || pending.is_some() {
            // Finish a recorded teardown even when DRM has since requested on.
            // SAFETY: OWNER and the caller's exclusions cover the whole resume.
            unsafe { retire_monitored_display(boot, displays, k, unplugged) }.await?;
            steps.push(if unplugged {
                MonitorStep::Unplugged(k)
            } else {
                MonitorStep::Disabled(k)
            });
            continue;
        }
        let preferred = m.modes.iter().flatten().next().copied();
        let desired = wants[usize::from(k)].1.or(preferred);
        // DRM moved this CRTC to another connector (or another connector
        // here): a configuration change like a mode request.
        let rerouted = target_of(boot, &m) != OUTPUTS.lock().crtcs[usize::from(k)].route;
        if rerouted
            || desired.is_some_and(|d| d != m.selection.timing)
            || limited != m.selection.limited
        {
            relight = true;
            continue;
        }
        // SAFETY: serialized retained owners; writers stay excluded.
        match unsafe { boot.check_modeset(&m) }.await? {
            Health::Running(_) => {}
            Health::FrlRetrain => {
                // Full retirement quiesces writers/fetch before SCDC cleanup
                // and fresh admission/training (including rate fallback).
                relight = true;
            }
            Health::LinkLost(_) => {
                if m.selection.mst.is_some() {
                    // Retraining affects every stream on the shared link.
                    // Stop them all before the next configuration trains it.
                    relight = true;
                    continue;
                }
                // The surface stays allocated and published: writes during
                // the retrain land in it and show once scanout resumes.
                let mut m = m;
                // SAFETY: as above.
                if let Err(e) = unsafe { boot.retrain_modeset(&mut m) }.await {
                    // A refused retrain whose link stopped again is ordinary
                    // teardown from timing on: retire it (writers, planes,
                    // surfaces) and light again, against the verified link.
                    let handed_over = boot
                        .display_teardown_status(k)
                        .is_some_and(|s| !s.in_flight && s.next == boot::TeardownStep::Timing);
                    if !handed_over {
                        return Err(e);
                    }
                    let _ = core::fmt::Write::write_fmt(
                        &mut narf_console::Writer,
                        format_args!("amdgpu: navi48 display {k} retrain failed: {e:?}\n"),
                    );
                    // SAFETY: as above; the journal resumes after the link.
                    unsafe { retire_monitored_display(boot, displays, k, false) }.await?;
                    steps.push(MonitorStep::Disabled(k));
                    relight = true;
                    continue;
                }
                displays.lit[usize::from(k)] = Some(m);
                {
                    let offered: Vec<Timing> = m.modes.into_iter().flatten().collect();
                    let mut outputs = OUTPUTS.lock();
                    if let Some(x) = target_of(boot, &m).and_then(|t| outputs.connector_mut(t)) {
                        x.modes.clone_from(&offered);
                    }
                    outputs.crtcs[usize::from(k)].retrained(
                        m.selection.edid,
                        m.selection.timing,
                        offered,
                    );
                }
                steps.push(MonitorStep::Retrained(k));
            }
            Health::Unplugged => {
                // SAFETY: as above; the helper records intent before withdrawing.
                unsafe { retire_monitored_display(boot, displays, k, true) }.await?;
                steps.push(MonitorStep::Unplugged(k));
            }
        }
    }
    // Sinks to light: a plugged connector, routed (automatically for a new
    // sink) to a CRTC DRM has not switched off.
    OUTPUTS.lock().assign_routes();
    let wanted = wanted_mask(boot);
    let lit_mask = displays
        .lit
        .iter()
        .enumerate()
        .filter(|(_, m)| m.is_some())
        .fold(0u8, |acc, (k, _)| acc | 1 << k);
    if needs_relight(relight, wanted, lit_mask, &mut displays.considered) {
        // Withdraw every writer, stop every display, light them again.
        for k in (0..4u8).rev() {
            let Some(m) = displays.lit[usize::from(k)] else {
                continue;
            };
            let unplugged = boot.display_hpd(m.selection.port) == Ok(false);
            // SAFETY: the caller's exclusions and OWNER cover withdrawal/retirement.
            unsafe { retire_monitored_display(boot, displays, k, unplugged) }.await?;
        }
        let fill = |_: u8, _: u32, row: &mut [u32]| row.fill(0);
        // SAFETY: as above; every display is stopped.
        let lit = match unsafe { light_displays(boot, fill) }.await {
            Err(e @ (ModesetError::NoSink | ModesetError::Link | ModesetError::LinkReduced))
                if !pending_display_work(boot) =>
            {
                let _ = core::fmt::Write::write_fmt(
                    &mut narf_console::Writer,
                    format_args!("amdgpu: navi48 displays not lit: {e:?}\n"),
                );
                None
            }
            Err(e) if wants.iter().any(|w| w.1.is_some()) && !pending_display_work(boot) => {
                // A requested mode did not light: go back to the preferred
                // modes rather than leave the sinks dark.
                let _ = core::fmt::Write::write_fmt(
                    &mut narf_console::Writer,
                    format_args!("amdgpu: navi48 mode switch failed: {e:?}\n"),
                );
                for c in OUTPUTS.lock().crtcs.iter_mut() {
                    c.requested = None;
                }
                // SAFETY: as above.
                Some(unsafe { light_displays(boot, fill) }.await?)
            }
            Err(e) => return Err(e),
            Ok(config) => Some(config),
        };
        let mut count = 0;
        // A later display whose link verified below its caps lights at the
        // next pass, selected (and DSC-admitted) against that link.
        let reduced = lit
            .as_ref()
            .is_some_and(|c| c.failed == Some(ModesetError::LinkReduced));
        if let Some(config) = lit {
            if let Some(e) = config.failed {
                let _ = core::fmt::Write::write_fmt(
                    &mut narf_console::Writer,
                    format_args!("amdgpu: navi48 display failed to light: {e:?}\n"),
                );
            }
            for m in config.displays {
                displays.lit[usize::from(m.pipe)] = Some(m);
                count += 1;
            }
        }
        // Every wanted CRTC the lighting saw, lit or left dark.
        displays.considered = wanted_mask(boot);
        if reduced {
            displays.considered = displays
                .lit
                .iter()
                .enumerate()
                .filter(|(_, m)| m.is_some())
                .fold(0, |acc, (k, _)| acc | 1 << k);
        }
        steps.push(MonitorStep::Relit(count));
    }
    if !steps.is_empty() {
        publish_outputs();
    }
    Ok(steps)
}

/// Watch the lit configuration for hot-plug, link loss and DRM requests
/// until the owner fails. HPD is enabled on every routed DP and HDMI port so
/// a sink on another port is seen.
/// # Safety
/// As for `modeset_displays`, for the lifetime of the spawned task.
pub unsafe fn spawn_display_monitor(config: crate::amdgpu_navi48_boot::Configuration) {
    let generation = DISPLAY_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    narf_scheduler::spawn(async move {
        use core::fmt::Write;
        let mut displays = Displays {
            generation,
            // Empty configuration after reset must relight even if the old
            // connector inventory still reports every sink present.
            epoch: recoveries().wrapping_sub(u64::from(config.displays.is_empty())),
            lit: [None; 4],
            considered: 0,
        };
        for m in config.displays {
            if let Some(slot) = displays.lit.get_mut(usize::from(m.pipe)) {
                displays.considered |= 1 << m.pipe;
                *slot = Some(m);
            }
        }
        {
            let mut owner = OWNER.lock().await;
            if generation != DISPLAY_GENERATION.load(Ordering::Acquire) {
                return;
            }
            if let Some(boot) = owner.as_mut() {
                // Every board port, whatever the connectors are now.
                let ports = board_ports(boot);
                for port in ports {
                    // SAFETY: board-routed selectors; no GPIO user of HPD pins.
                    if unsafe { boot.enable_display_hpd(port) }.is_ok() {
                        // SAFETY: the interrupt worker routes DCN vectors to
                        // the dispatcher this monitor waits on.
                        let _ = unsafe { boot.enable_display_hpd_irq(port) };
                    }
                }
                // Bits are CRTCs, whose connectors can be MST devices.
                displays.considered |= wanted_mask(boot);
            }
        }
        let mut hotplug = None;
        loop {
            if generation != DISPLAY_GENERATION.load(Ordering::Acquire) {
                return;
            }
            let interval = if displays
                .lit
                .iter()
                .flatten()
                .any(|m| m.selection.frl.is_some())
            {
                FRL_MONITOR_MS
            } else {
                MONITOR_MS
            };
            if crate::amdgpu_navi48_dispatch::wait_hotplug(&mut hotplug, interval).await {
                // Acknowledge (and re-arm the opposite edge of) every port's
                // raised HPD/HPD-RX before the pass reads the sense.
                let mut owner = OWNER.lock().await;
                if generation != DISPLAY_GENERATION.load(Ordering::Acquire) {
                    return;
                }
                if let Some(boot) = owner.as_mut() {
                    let ports = boot.display_paths().map_or(0, <[_]>::len);
                    for port in 0..ports {
                        let _ = boot.ack_display_hpd(port);
                    }
                }
            }
            // SAFETY: the spawner's obligations hold for the task's lifetime.
            match unsafe { monitor_displays(&mut displays) }.await {
                Ok(steps) => {
                    for step in steps {
                        let _ = writeln!(narf_console::Writer, "amdgpu: navi48 display {step:?}");
                    }
                }
                Err(e) => {
                    // The failed owner stays quarantined where it stopped.
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: navi48 display monitor stopped: {e:?}"
                    );
                    return;
                }
            }
        }
    });
}

/// Make the staged surface the visible source of the pipe's running black video.
/// # Safety
/// The surface must stay allocated until a successful stop. Exclude firmware/FAMS
/// and concurrent display/hub/VM/IRQ/clock/reset/power writers.
pub async unsafe fn start_display_scanout(
    pipe: u8,
) -> Result<crate::amdgpu_dcn401_otg::ScanoutRunning, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.start_display_scanout(pipe).await }
}

/// Re-verify a live scanout; an underflow returns the pipe to black.
/// # Safety
/// As for `start_display_scanout`.
pub async unsafe fn check_display_scanout(
    pipe: u8,
) -> Result<u32, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.check_display_scanout(pipe).await }
}

/// Return a live pipe to black video with fetch drained and clocks gated.
/// # Safety
/// As for `start_display_scanout`.
pub async unsafe fn stop_display_scanout(pipe: u8) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.stop_display_scanout(pipe).await }
}

/// Blank one legacy or HPO DisplayPort video stream, retaining timing/link clocks.
/// # Safety
/// Stop CPU scanout writers and exclude firmware/FAMS and concurrent display,
/// audio/packet/link/clock/power writers. Retain every allocation and translation;
/// this does not retire the PHY, sink, timing, MST topology or memory.
pub async unsafe fn blank_display_dp_stream(
    stream: crate::amdgpu_dcn401_otg::DpStream,
) -> Result<crate::amdgpu_dcn401_otg::DpBlanked, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller excludes writers and retains memory.
    unsafe { boot.blank_display_dp_stream(stream).await }
}

/// Retire one blank DP stream encoder and acknowledge its frontend clocks off.
/// # Safety
/// Exclude CPU/firmware/FAMS and concurrent display/audio/link/power writers;
/// retain every allocation and translation. Independently retire sink/MST and
/// audio/metadata producers. Success does not retire PHYs, timing or memory.
pub async unsafe fn retire_display_dp_encoder(
    stream: crate::amdgpu_dcn401_otg::DpStream,
) -> Result<crate::amdgpu_dcn401_otg::DpEncoderRetired, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller excludes writers and retains memory.
    unsafe { boot.retire_display_dp_encoder(stream).await }
}

/// Enable an untrained external legacy DP PHY after display clock preparation.
/// # Safety
/// Fulfil `Otg::enable_dp_phy` board/sink/cable limits, direct-port, producer and
/// writer-exclusion obligations. Retain memory/translations. No training/scanout.
pub async unsafe fn enable_display_dp_phy(
    port: usize,
    settings: crate::amdgpu_dcn401_otg::DpPhySettings,
) -> Result<crate::amdgpu_dcn401_otg::DpPhyReady, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils the documented obligations.
    unsafe { boot.enable_display_dp_phy(port, settings).await }
}

/// Disable only the retained owner's matching, still-untrained DP PHY.
/// # Safety
/// Fulfil the same direct-port, producer/writer exclusion and retention
/// obligations as `enable_display_dp_phy`. No analog power or memory release.
pub async unsafe fn disable_display_dp_phy(
    port: usize,
) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils the documented obligations.
    unsafe { boot.disable_display_dp_phy(port).await }
}

/// Train the retained legacy DP PHY at its current lane count and rate.
/// # Safety
/// Fulfil `Otg::train_dp_link` direct-port, board SSC, producer/writer exclusion
/// and memory-retention obligations. No scanout or automatic rate fallback.
pub async unsafe fn train_display_dp_link(
    port: usize,
    downspread: bool,
) -> Result<crate::amdgpu_dcn401_otg::DpLinkTrained, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils documented obligations.
    unsafe { boot.train_display_dp_link(port, downspread).await }
}
/// Request sink D3 and stop the matching trained, streamless legacy DP PHY.
/// # Safety
/// Fulfil `Otg::stop_dp_link` direct-port and writer/resource obligations.
pub async unsafe fn stop_display_dp_link(
    port: usize,
) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils documented obligations.
    unsafe { boot.stop_display_dp_link(port).await }
}
/// Prepare a native legacy DP frontend for matching staged RGB black timing.
/// # Safety
/// Fulfil `Otg::prepare_dp_frontend` direct-port, exclusive writer/clock/timing
/// and resource-retention obligations. Video and scanout remain stopped.
pub async unsafe fn prepare_display_dp_frontend(
    port: usize,
    request: crate::amdgpu_dcn401_otg::DpFrontendRequest,
) -> Result<crate::amdgpu_dcn401_otg::DpFrontendReady, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils documented obligations.
    unsafe { boot.prepare_display_dp_frontend(port, request).await }
}
/// Start native legacy SST RGB black video from the retained frontend/timing.
/// # Safety
/// Fulfil `Otg::start_dp_video` writer-exclusion and resource-lifetime contract
/// throughout the running lifetime. No memory fetcher is enabled.
pub async unsafe fn start_display_dp_video(
    port: usize,
) -> Result<crate::amdgpu_dcn401_otg::DpVideoRunning, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils lifetime obligations.
    unsafe { boot.start_display_dp_video(port).await }
}
/// Blank the owned video and stop timing, retaining the prepared frontend.
/// # Safety
/// Fulfil `Otg::stop_dp_video` writer/resource lifetime obligations.
pub async unsafe fn stop_display_dp_video(
    port: usize,
) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils lifetime obligations.
    unsafe { boot.stop_display_dp_video(port).await }
}
/// Stop the matching blank frontend while retaining its trained DP PHY.
/// # Safety
/// Fulfil `Otg::stop_dp_frontend` writer/resource and stopped-video obligations.
pub async unsafe fn stop_display_dp_frontend(
    port: usize,
) -> Result<(), crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils documented obligations.
    unsafe { boot.stop_display_dp_frontend(port).await }
}
/// Disable the direct FRL PHY after frontend and digital-link retirement.
/// # Safety
/// Fulfil `Otg::disable_frl` direct-port, sink/SCDC/retimer, producer and
/// writer-exclusion obligations. Retain all allocations/translations;
/// forced input clocks, timing and analog power remain owned.
pub async unsafe fn disable_display_frl(
    port: usize,
) -> Result<crate::amdgpu_dcn401_otg::FrlDisabled, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained serialized owner; caller fulfils the documented obligations.
    unsafe { boot.disable_display_frl(port).await }
}

/// Retire the board-routed FRL digital link, retaining its PHY/root clocks.
/// # Safety
/// Fulfil `Otg::retire_frl_link` frontend, sink/SCDC/retimer, audio/metadata/
/// HDCP and writer-exclusion obligations. Retain all allocations/translations;
/// success is not PHY, root-clock or memory retirement.
pub async unsafe fn retire_display_frl_link(
    port: usize,
) -> Result<crate::amdgpu_dcn401_otg::FrlLinkRetired, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained serialized owner; caller fulfils the documented obligations.
    unsafe { boot.retire_display_frl_link(port).await }
}

/// Retire the native FRL frontend, preserving link/PHY and timing clocks.
/// # Safety
/// Fulfil `Otg::retire_hdmi_frl_encoder` sink/SCDC/retimer, audio/ACR/metadata/
/// HDCP and writer-exclusion obligations. Retain all memory/translations;
/// success is not link or memory retirement.
pub async unsafe fn retire_display_hdmi_frl_encoder(
) -> Result<crate::amdgpu_dcn401_otg::FrlEncoderRetired, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained serialized owner; caller fulfils the documented obligations.
    unsafe { boot.retire_display_hdmi_frl_encoder().await }
}

/// Disable a direct TMDS HDMI transmitter after frontend/timing retirement.
/// # Safety
/// Fulfil `Otg::disable_tmds` direct-port, sink/SCDC/retimer, producer and
/// writer-exclusion obligations. Retain all allocations and translations;
/// completion proves backend/lane/TX-clock stop, not analog power gating.
pub async unsafe fn disable_display_tmds(
    port: usize,
) -> Result<crate::amdgpu_dcn401_otg::TmdsDisabled, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained serialized owner; caller fulfils the documented obligations.
    unsafe { boot.disable_display_tmds(port).await }
}

/// Retire one OTG and its clocks while retaining TMDS transmitters.
/// # Safety
/// Fulfil `Otg::retire_tmds_timing` frontend/audio/metadata/HDCP retirement
/// and writer-exclusion obligations. Retain all memory and translations;
/// future PHY shutdown needs fresh checks of every timing and clock user.
pub async unsafe fn retire_display_tmds_timing(
    pipe: u8,
) -> Result<crate::amdgpu_dcn401_otg::TmdsTimingRetired, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained serialized owner; caller fulfils the documented obligations.
    unsafe { boot.retire_display_tmds_timing(pipe).await }
}

/// Retire a native TMDS HDMI frontend while retaining backend/PHY/OTG clocks.
/// # Safety
/// Fulfil `Otg::retire_hdmi_tmds_encoder` sink/SCDC/retimer, audio/metadata/HDCP
/// and writer-exclusion obligations; retain every allocation and translation.
/// Success never proves link or memory retirement.
pub async unsafe fn retire_display_hdmi_tmds_encoder(
    stream: u8,
) -> Result<crate::amdgpu_dcn401_otg::HdmiTmdsRetired, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained serialized owner; caller fulfils the documented obligations.
    unsafe { boot.retire_display_hdmi_tmds_encoder(stream).await }
}

/// Disable a board-routed legacy DP SST transmitter before retiring its frontend.
/// # Safety
/// Select a direct external DP port without USB-C/ACPI PHY interlocks or SSC
/// workarounds. Stop sink/audio/metadata/HDCP/FEC producers; exclude CPU, firmware,
/// FAMS and concurrent display/link/clock/power writers. Retain all resources;
/// success proves backend-off, never analog power gating or memory retirement.
pub async unsafe fn disable_display_dp_sst(
    port: usize,
) -> Result<crate::amdgpu_dcn401_otg::DpSstDisabled, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained serialized owners; caller fulfils the platform obligations.
    unsafe { boot.disable_display_dp_sst(port).await }
}

/// Drain native HPO timeslots and retire the board-routed digital link.
/// # Safety
/// Retire sink/MST bookkeeping, audio/metadata/HDCP producers and associated
/// streams. Exclude CPU/firmware/FAMS and concurrent display/link/clock/power
/// writers; retain all memory/translations. PHY output and clocks stay owned.
pub async unsafe fn retire_display_hpo_link(
    port: usize,
) -> Result<crate::amdgpu_dcn401_otg::HpoLinkRetired, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: serialized retained owner; caller fulfils the shutdown obligations.
    unsafe { boot.retire_display_hpo_link(port).await }
}

/// Disable an HPO PHY after digital-link retirement, then park its root route.
/// # Safety
/// Signal matches the inherited link. Direct external DP only, without USB-C/
/// ACPI PHY interlocks or SSC workarounds. Retire sink/MST bookkeeping, audio/
/// metadata/HDCP producers and associated streams/link. Exclude CPU/firmware/FAMS
/// and concurrent display/link/clock/power/reset writers; retain memory/translations.
/// Success does not prove analog power gating or permit memory reuse.
pub async unsafe fn disable_display_hpo_dp(
    port: usize,
    signal: crate::amdgpu_dmub_navi48::DpSignal,
) -> Result<crate::amdgpu_dcn401_otg::HpoDpDisabled, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
    let boot = owner
        .as_mut()
        .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
    // SAFETY: retained serialized owner; caller fulfils the shutdown obligations.
    unsafe { boot.disable_display_hpo_dp(port, signal).await }
}

/// Consume bounded diagnostic history from the independent IH service.
/// Hardware draining and CPU interrupt waits never hold the display-owner lock.
pub async fn poll_interrupts() -> Result<crate::amdgpu_ih7::Batch, boot::Error> {
    crate::amdgpu_navi48_interrupts::poll()
        .await
        .map_err(boot::Error::Interrupts)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn hd() -> Timing {
        Timing {
            pixel_clock_khz: 148500,
            h_active: 1920,
            h_total: 2200,
            h_front_porch: 88,
            h_sync_width: 44,
            v_active: 1080,
            v_total: 1125,
            v_front_porch: 4,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }
    fn board(n: usize) -> (Target, ConnectorType, usize) {
        (Target::Board(n), ConnectorType::DisplayPort, n)
    }

    fn navi48_dark_sst_connector_preserves_disable_and_invalidates_replacement() -> TestResult {
        let timing = hd();
        let target = Target::Board(2);
        let mut output = boot::SstOutput {
            port: 2,
            edid: alloc::vec![0; 256],
            modes: alloc::vec![timing],
        };
        let mut o = Outputs::new();
        o.reshape(&[(target, ConnectorType::DisplayPort, 0)]);
        o.crtcs[0].active = false;
        assert!(o
            .connector_mut(target)
            .unwrap()
            .reconcile_sst(Some(&output)));
        o.assign_routes();
        assert_eq!(o.crtcs[0].route, Some(target));
        assert!(o.connector(target).unwrap().present && o.published(0).is_none());
        assert!(!o.crtcs[0].published_active());
        let wire = crate::amdgpu_navi48_kms::timing_wire(&timing);
        assert_eq!(o.find_mode(0, None, &wire), Some(timing));
        o.crtcs[0].requested = Some(timing);
        let x = o.connector_mut(target).unwrap();
        assert!(!x.observe_sst_hpd(true));
        assert!(!x.observe_sst_hpd(false));
        assert!(!o.connector(target).unwrap().present && o.offered(0, None).is_empty());
        assert_eq!(o.crtcs[0].requested, Some(timing));
        let x = o.connector_mut(target).unwrap();
        assert!(x.observe_sst_hpd(true));
        assert!(!x.observe_sst_hpd(true));
        assert!(!x.reconcile_sst(Some(&output)));
        assert!(!o.crtcs[0].active && o.published(0).is_none());
        assert_eq!(o.crtcs[0].requested, Some(timing));
        assert_eq!(o.find_mode(0, None, &wire), Some(timing));
        // Extension changes invalidate requests even with an identical base.
        output.edid[128] = 1;
        output.modes.clear();
        assert!(o
            .connector_mut(target)
            .unwrap()
            .reconcile_sst(Some(&output)));
        o.invalidate(target, false);
        assert!(o.connector(target).unwrap().present && !o.crtcs[0].active);
        assert!(o.crtcs[0].requested.is_none() && o.offered(0, None).is_empty());
        let mut initially_absent = ConnectorState::new(target, ConnectorType::DisplayPort, 0);
        assert!(initially_absent.observe_sst_hpd(true));
        assert!(!initially_absent.observe_sst_hpd(true));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-kms",
        navi48_dark_sst_connector_preserves_disable_and_invalidates_replacement
    );

    fn navi48_retraining_refreshes_published_modes_and_drops_invalid_requests() -> TestResult {
        let timing = hd();
        let faster = Timing {
            pixel_clock_khz: 594000,
            ..timing
        };
        let mut o = Outputs::new();
        o.reshape(&[board(0)]);
        o.connectors[0].present = true;
        o.assign_routes();
        let c = &mut o.crtcs[0];
        c.shown = Some(([1; 128], timing, alloc::vec![timing, faster]));
        c.requested = Some(faster);
        c.retrained([1; 128], timing, alloc::vec![timing]);
        assert_eq!(o.offered(0, None), &[timing]);
        assert!(o.crtcs[0].requested.is_none() && o.crtcs[0].published_active());
        assert_eq!(o.published(0).unwrap().1, timing);
        o.crtcs[0].requested = Some(timing);
        o.crtcs[0].retrained([1; 128], timing, alloc::vec![timing]);
        assert_eq!(o.crtcs[0].requested, Some(timing));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-kms",
        navi48_retraining_refreshes_published_modes_and_drops_invalid_requests
    );

    fn navi48_mst_disabled_connector_survives_hotplug() -> TestResult {
        let id = boot::MstOutputId {
            root: [1; 16],
            branch: [2; 16],
            lct: 2,
            rad: [0; 8],
            port: 3,
        };
        let mut output = boot::MstOutput {
            id,
            sink: Some(crate::dp_mst_mgr::Sink { branch: 1, port: 3 }),
            edid: alloc::vec![0; 256],
            modes: Vec::new(),
        };
        let timing = hd();
        let target = Target::Mst(0, 1);
        let mut o = Outputs::new();
        o.reshape(&[(target, ConnectorType::DisplayPort, MST_INDEX + 1)]);
        output.modes.push(timing);
        let reconcile = |o: &mut Outputs, output: &boot::MstOutput| {
            let (reset, changed) = o.connector_mut(target).unwrap().reconcile_mst(Some(output));
            if reset || changed {
                o.invalidate(target, reset);
            }
        };
        reconcile(&mut o, &output);
        o.assign_routes();
        o.crtcs[0].shown = Some(([0; 128], timing, alloc::vec![timing]));
        o.crtcs[0].requested = Some(timing);
        o.crtcs[0].active = false;
        let mut considered = 0;
        // Downstream disconnect drives a reprobe even with no wanted CRTC.
        assert!(needs_relight(true, 0, 0, &mut considered));
        output.sink = None;
        output.edid.clear();
        reconcile(&mut o, &output);
        assert!(o.published(0).is_none());
        assert!(o.offered(0, None).is_empty());
        assert!(!o.crtcs[0].active);
        assert_eq!(o.crtcs[0].requested, Some(timing));
        // DRM's explicit routing survives the device leaving.
        o.route(0, Some(target));
        o.assign_routes();
        assert_eq!(o.crtcs[0].route, Some(target));
        // The same connector and EDID return with a different branch index.
        output.sink = Some(crate::dp_mst_mgr::Sink { branch: 2, port: 3 });
        output.edid.resize(256, 0);
        reconcile(&mut o, &output);
        assert!(o.published(0).is_none());
        o.crtcs[0].shown = None;
        assert_eq!(o.offered(0, None), &[timing]);
        let wire = crate::amdgpu_navi48_kms::timing_wire(&timing);
        assert_eq!(o.find_mode(0, None, &wire), Some(timing));
        assert!(!o.crtcs[0].active);
        o.crtcs[0].requested = Some(timing);
        assert!(!needs_relight(false, 0, 0, &mut considered));
        o.crtcs[0].active = true;
        assert!(needs_relight(false, 1, 0, &mut considered));
        // A different monitor on this connector retains disabled state but
        // loses stale modes. Reassigning the slot resets old DRM requests.
        o.crtcs[0].active = false;
        output.edid[128] = 1; // same base block, changed extension modes
        output.modes.clear(); // a reprobe invalidates admission too
        reconcile(&mut o, &output);
        assert!(!o.crtcs[0].active && o.crtcs[0].shown.is_none());
        assert!(o.crtcs[0].requested.is_none());
        assert!(o.find_mode(0, None, &wire).is_none());
        output.id.branch = [3; 16];
        reconcile(&mut o, &output);
        assert!(o.crtcs[0].active && o.crtcs[0].requested.is_none());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48",
        navi48_mst_disabled_connector_survives_hotplug
    );

    /// Linux-style routing: connectors (board ports beside an MST branch's
    /// end devices) take CRTCs automatically in connector order and keep
    /// them while plugged; DRM routes any connector to any CRTC, moving it
    /// off its old CRTC and parking a displaced one; reshaping drops routes
    /// to vanished connectors; restore returns to automatic routing.
    fn navi48_outputs_route_connectors_to_any_crtc() -> TestResult {
        let shape = [
            board(0),
            (Target::Board(1), ConnectorType::HdmiA, 1),
            (Target::Mst(0, 0), ConnectorType::DisplayPort, MST_INDEX),
            (Target::Mst(0, 1), ConnectorType::DisplayPort, MST_INDEX + 1),
            (Target::Mst(0, 2), ConnectorType::DisplayPort, MST_INDEX + 2),
        ];
        let mut o = Outputs::new();
        o.reshape(&shape);
        for t in [Target::Board(1), Target::Mst(0, 0), Target::Mst(0, 2)] {
            o.connector_mut(t).unwrap().present = true;
        }
        o.assign_routes();
        let routes = |o: &Outputs| o.crtcs.iter().map(|c| c.route).collect::<Vec<_>>();
        assert_eq!(
            routes(&o),
            [
                Some(Target::Board(1)),
                Some(Target::Mst(0, 0)),
                Some(Target::Mst(0, 2)),
                None
            ]
        );
        // A new end device takes the free CRTC; running ones keep theirs.
        o.connector_mut(Target::Mst(0, 1)).unwrap().present = true;
        o.assign_routes();
        assert_eq!(o.crtcs[3].route, Some(Target::Mst(0, 1)));
        // KMS ids: board ordinals, MST slots past them.
        let id = crate::amdgpu_navi48_kms::connector_id;
        assert_eq!(o.target_of_id(id(1)), Some(Target::Board(1)));
        assert_eq!(o.target_of_id(id(MST_INDEX + 2)), Some(Target::Mst(0, 2)));
        assert_eq!(o.target_of_id(id(7)), None);
        // DRM moves the HDMI sink to CRTC 3: CRTC 0 is left explicitly
        // empty and CRTC 3's end device parked, so neither is refilled.
        o.crtcs[3].requested = Some(hd());
        o.route(3, Some(Target::Board(1)));
        o.assign_routes();
        assert_eq!(
            routes(&o),
            [
                None,
                Some(Target::Mst(0, 0)),
                Some(Target::Mst(0, 2)),
                Some(Target::Board(1))
            ]
        );
        assert!(o.crtcs[0].explicit && o.crtcs[3].explicit);
        assert!(o.crtcs[3].requested.is_none(), "old connector's mode kept");
        assert!(o.connector(Target::Mst(0, 1)).unwrap().parked);
        // A timing is validated on the connector the request routes to.
        let wire = crate::amdgpu_navi48_kms::timing_wire(&hd());
        o.connector_mut(Target::Mst(0, 1)).unwrap().modes = alloc::vec![hd()];
        assert!(o.find_mode(3, None, &wire).is_none());
        assert_eq!(o.find_mode(3, Some(Target::Mst(0, 1)), &wire), Some(hd()));
        // An unplugged automatic route is dropped; an explicit one stays.
        o.connector_mut(Target::Mst(0, 0)).unwrap().present = false;
        o.connector_mut(Target::Board(1)).unwrap().present = false;
        o.assign_routes();
        assert_eq!(o.crtcs[1].route, None);
        assert_eq!(o.crtcs[3].route, Some(Target::Board(1)));
        // The branch leaves: its connectors and routes go.
        o.reshape(&shape[..2]);
        assert!(o
            .crtcs
            .iter()
            .all(|c| !matches!(c.route, Some(Target::Mst(..)))));
        assert_eq!(o.mst_port(), None);
        // Console restore: automatic routing again.
        for c in o.crtcs.iter_mut() {
            c.explicit = false;
        }
        o.connector_mut(Target::Board(1)).unwrap().present = true;
        o.crtcs[3].route = None;
        o.assign_routes();
        assert_eq!(o.crtcs[0].route, Some(Target::Board(1)));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-kms",
        navi48_outputs_route_connectors_to_any_crtc
    );

    /// A frame the native display cannot take still completes its
    /// flip-complete event, and the 24-bit OTG frame count extends across
    /// its wrap and a relight into DRM's vblank count.
    fn navi48_present_completes_refused_flip_and_extends_vblanks() -> TestResult {
        use crate::drm::card::flips;
        // On every display: its own flip log, its own refusal.
        for display in 0..4 {
            let ticket = flips(display).lock().reserve();
            if native_present_ready(display) {
                return TestResult::Fail("test kernel unexpectedly presents natively");
            }
            if present_frame(display, 0x1000, 64, 16, 16, Some(ticket)) {
                return TestResult::Fail("frame taken without a native display");
            }
            if flips(display).lock().stamp(ticket).is_none() {
                return TestResult::Fail("refused frame left its event waiting");
            }
        }
        if native_present_ready(4) || present_frame(9, 0x1000, 64, 16, 16, None) {
            return TestResult::Fail("display out of range presents");
        }
        use crate::amdgpu_dcn401_otg::VblankPhase;
        let phase = |count| VblankPhase {
            count,
            start_ns: -1_000,
            end_ns: 500_000,
            period_ns: 16_000_000,
        };
        let first = extend_vblank(None, phase(0xff_fff0), 10_000_000);
        let wrapped = extend_vblank(Some(first), phase(0x10), 20_000_000);
        if first.time.count != 0xff_fff0
            || wrapped.time.count - first.time.count != 0x20
            || wrapped.time.start_ns != 20_000_000 - 1_000
            || wrapped.time.ns != 20_500_000
        {
            return TestResult::Fail("frame count wrap not extended");
        }
        // A relit display's restarted frame count continues the count.
        let relit = extend_vblank(
            Some(VblankClock {
                raw: None,
                ..wrapped
            }),
            phase(3),
            30_000_000,
        );
        if relit.time.count != wrapped.time.count + 1 {
            return TestResult::Fail("relight did not continue the count");
        }
        // Carried forward while the owner is busy, a second at most.
        let t = extrapolate_vblank(relit, 30_000_000 + 2 * 16_000_000);
        if t.map(|t| t.count) != Some(relit.time.count + 2)
            || extrapolate_vblank(relit, 30_000_000 + 1_100_000_000).is_some()
        {
            return TestResult::Fail("extrapolation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48",
        navi48_present_completes_refused_flip_and_extends_vblanks
    );

    /// The monitor relights for a new sink, a returning sink or CRTC, or a
    /// requested change, and never again for a sink the last lighting left
    /// dark (it did not fit).
    fn navi48_monitor_relights_only_for_new_sinks_and_changes() -> TestResult {
        // Boot lit outputs 0 and 2; output 1 was plugged but did not fit.
        let mut considered = 0b111;
        // (requested change, plugged and wanted, lit, relight expected).
        let steps: [(bool, u8, u8, bool); 8] = [
            // Nothing changed: outputs 0, 2 run, 1 stays dark.
            (false, 0b111, 0b101, false),
            // Output 2's sink left (and was torn down): no relight.
            (false, 0b011, 0b001, false),
            // It returns: new again.
            (false, 0b111, 0b001, true),
            // Lit again with 0 and 2; DRM switches output 0 off (torn down).
            (false, 0b110, 0b100, false),
            // DRM switches it back on.
            (false, 0b111, 0b100, true),
            // Relit; nothing changes.
            (false, 0b111, 0b101, false),
            // A requested mode on a running display.
            (true, 0b111, 0b101, true),
            // A fourth sink appears.
            (false, 0b1111, 0b101, true),
        ];
        for (changed, wanted, lit, want) in steps {
            if needs_relight(changed, wanted, lit, &mut considered) != want {
                return TestResult::Fail("relight decision");
            }
            if want {
                // The relighting considers every wanted sink.
                considered = wanted;
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48",
        navi48_monitor_relights_only_for_new_sinks_and_changes
    );

    /// After an SDMA0 reset, the clears the ring held past where it
    /// stopped go back to the queue's front, in order and unsignalled;
    /// those it completed are forgotten, and a drain starts only if none
    /// runs.
    fn navi48_sdma_reset_requeues_skipped_clears() -> TestResult {
        use core::sync::atomic::Ordering;
        let progress: SdmaProgress = Arc::new(|| Some(0));
        let clear = |address, seq: u64| {
            let fence = Arc::new(ClearFence::new(progress.clone()));
            fence.seq.store(seq, Ordering::Release);
            Clear {
                address,
                bytes: 4096,
                fence,
            }
        };
        let mut state = ClearState::default();
        state
            .inflight
            .extend([clear(0x1000, 4), clear(0x2000, 5), clear(0x3000, 5)]);
        state.queued.push_back(clear(0x4000, u64::MAX));
        state.retire(3);
        if state.inflight.len() != 3 {
            return TestResult::Fail("retired clears not yet done");
        }
        if !state.requeue(4) || state.requeue(4) {
            return TestResult::Fail("drain start");
        }
        let queued: Vec<(u64, u64)> = state
            .queued
            .iter()
            .map(|c| (c.address, c.fence.seq.load(Ordering::Acquire)))
            .collect();
        if !state.inflight.is_empty()
            || queued != [(0x2000, u64::MAX), (0x3000, u64::MAX), (0x4000, u64::MAX)]
            || state
                .queued
                .iter()
                .any(|c| narf_filesystem::DrmFence::is_signalled(&*c.fence))
        {
            return TestResult::Fail("requeued clears");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48",
        navi48_sdma_reset_requeues_skipped_clears
    );

    fn navi48_monitor_finishes_retirement_before_reactivation() -> TestResult {
        let mut output = CrtcState::new();
        output.active = false;
        output.retiring = true;
        // DRM asks to reactivate while CPU withdrawal or native stop waits.
        output.active = true;
        assert!(!output.published_active());
        // Finishing retirement removes the old pipe and makes it newly wanted.
        let mut considered = 0b1111 & !(1 << 3);
        assert!(needs_relight(false, 0b1111, 0b0111, &mut considered));
        // Adoption after a successful relight restores publication.
        output.retiring = false;
        assert!(output.published_active());
        // Resume a higher-numbered interrupted pipe before health checks can
        // select another owner or a shared-link notification can start a relight.
        assert_eq!(monitor_order(0b1000).collect::<Vec<_>>(), [3, 0, 1, 2]);
        assert_eq!(monitor_order(0b1010).collect::<Vec<_>>(), [1, 3, 0, 2]);
        assert_eq!(monitor_order(0).collect::<Vec<_>>(), [0, 1, 2, 3]);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48",
        navi48_monitor_finishes_retirement_before_reactivation
    );

    /// Clears batch front-first into jobs of at most 32 fill packets, and
    /// a clear's fence waits for SDMA0 to reach its job, unless the device
    /// is gone.
    fn navi48_vram_clears_batch_in_order() -> TestResult {
        use narf_filesystem::DrmFence;
        const GIB: u64 = 1 << 30;
        if clear_batch([4096u64; 40].into_iter()) != 32
            || clear_batch([31 * GIB, GIB, 4096].into_iter()) != 2
            || clear_batch([GIB + 4, 31 * GIB].into_iter()) != 1
            || clear_batch([4096, 32 * GIB].into_iter()) != 1
            || clear_batch(core::iter::empty()) != 1
        {
            return TestResult::Fail("clear batching");
        }
        if !clear_fits(0x10, 32 * GIB)
            || clear_fits(0x10, 32 * GIB + 4)
            || clear_fits(0x12, 4)
            || clear_fits(0x10, 6)
            || clear_fits(0x10, 0)
        {
            return TestResult::Fail("clear validation");
        }
        // A fence follows SDMA0's own completed sequence (wrapping), and
        // a vanished or refusing device signals it.
        let done = Arc::new(core::sync::atomic::AtomicU64::new(u64::from(u32::MAX - 1)));
        let seen = done.clone();
        let fence = ClearFence::new(Arc::new(move || {
            let d = seen.load(Ordering::Acquire);
            (d != u64::MAX).then_some(d as u32)
        }));
        if fence.is_signalled() {
            return TestResult::Fail("unqueued clear signalled");
        }
        fence.seq.store(1, Ordering::Release);
        let early = fence.is_signalled();
        done.store(0, Ordering::Release);
        let before = fence.is_signalled();
        done.store(1, Ordering::Release);
        let reached = fence.is_signalled();
        done.store(u64::MAX, Ordering::Release);
        let vanished = fence.is_signalled();
        let refused = ClearFence::new(Arc::new(|| Some(0)));
        refused.gone.store(true, Ordering::Release);
        if early || before || !reached || !vanished || !refused.is_signalled() {
            return TestResult::Fail("clear fence against SDMA0's sequence");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48",
        navi48_vram_clears_batch_in_order
    );

    fn navi48_handoff_distinguishes_primary_and_secondary_apertures() -> TestResult {
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
        "drivers/gpu/amdgpu/navi48",
        navi48_handoff_distinguishes_primary_and_secondary_apertures
    );

    fn navi48_training_refuses_live_firmware_in_overwritten_prefix() -> TestResult {
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
        "drivers/gpu/amdgpu/navi48",
        navi48_training_refuses_live_firmware_in_overwritten_prefix
    );
}
