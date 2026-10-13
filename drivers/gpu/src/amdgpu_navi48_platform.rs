//! One retained Navi48 firmware owner, entered by the framebuffer boot handoff.
//! Preparation is read-only; the caller stops CPU writers before entering it.
use crate::amdgpu_navi48_display as display;
use crate::{amdgpu, amdgpu_navi48_boot as boot, amdgpu_vram_boot as vram};
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

static OWNER: Mutex<Option<boot::ColdBoot>> = Mutex::new(None);

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
    pub sdma_state: Option<crate::amdgpu_sdma_navi48::State>,
    pub sdma_interrupts:
        Option<Result<crate::amdgpu_sdma_navi48::InterruptProof, crate::amdgpu_sdma_navi48::Error>>,
    pub display_clocks: Result<crate::amdgpu_dcn401_clk::Status, crate::amdgpu_dcn401_clk::Error>,
    pub display_pipe_clocks:
        Result<crate::amdgpu_dcn401_dccg::Status, crate::amdgpu_dcn401_dccg::Error>,
    pub display_timing: Result<crate::amdgpu_dcn401_otg::Status, crate::amdgpu_dcn401_otg::Error>,
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
                sdma_state: boot.sdma_state(),
                sdma_interrupts: boot.sdma_interrupts(),
                display_clocks: boot.display_clock_status(),
                display_pipe_clocks: boot.display_pipe_clock_status(),
                display_timing: boot.display_timing_status(),
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
        let pool = unsafe { plan.into_pool() }.map_err(Error::Memory)?;
        // SAFETY: inventory covers every inherited client and CPU framebuffer
        // writers are paused. Construction performs bounded reads, never writes.
        let prepared =
            unsafe { boot::ColdBoot::new(gpu, pci, authority, &pool, firmware, training) }
                .map_err(Error::Firmware)?;
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
    Ok(report)
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
            let _ = unsafe { boot.prove_sdma_interrupts().await };
        }
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

/// Pipe of the published scanout, for the cursor hook.
static CURSOR_PIPE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Cursor hook published with the live scanout: upload once, then move;
/// hide with an off-screen move. Never waits for the owner.
fn scanout_cursor(image: (u32, u32, &[u32]), position: Option<(i32, i32)>) -> bool {
    let pipe = CURSOR_PIPE.load(core::sync::atomic::Ordering::Acquire);
    let Some(mut owner) = OWNER.try_lock() else {
        return true;
    };
    let Some(boot) = owner.as_mut() else {
        return true;
    };
    let (w, h, _) = image;
    let shown = boot
        .display_timing_status()
        .ok()
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

/// Light the first answering DP SST sink at its preferred mode on `pipe`,
/// filling each visible row with `fill(y, row)` before fetch starts, then
/// publish the live surface as the active external scanout.
/// # Safety
/// Inherited display consumers must be retired. Exclude firmware/FAMS and
/// concurrent display/hub/VM/IRQ/clock/reset/power/link writers.
pub async unsafe fn modeset_display(
    pipe: u8,
    fill: impl FnMut(u32, &mut [u32]),
) -> Result<crate::amdgpu_navi48_boot::Modeset, crate::amdgpu_navi48_boot::ModesetError> {
    use crate::amdgpu_navi48_boot::{Error as BootError, ModesetError};
    let (modeset, fb) = {
        let mut owner = OWNER.lock().await;
        let boot = owner.as_mut().ok_or(ModesetError::Boot(BootError::Busy))?;
        // SAFETY: serialized retained owners; caller excludes external writers.
        let modeset = unsafe { boot.modeset_display(pipe, fill).await }?;
        (modeset, boot.display_scanout_framebuffer(pipe)?)
    };
    // Outside the owner lock: the observer may move the console here at once.
    CURSOR_PIPE.store(pipe, core::sync::atomic::Ordering::Release);
    crate::amdgpu_dcn_display::publish_external(Some(fb), Some(flush_scanout));
    crate::amdgpu_dcn_display::publish_external_cursor(Some(scanout_cursor));
    let s = &modeset.selection;
    crate::amdgpu_navi48_kms::publish(Some((&s.edid, &s.timing)));
    Ok(modeset)
}

/// Allocate the back buffer of a staged or live pipe and return its CPU view.
/// # Safety
/// Exclude firmware/FAMS and concurrent display/HDP writers.
pub async unsafe fn prepare_display_back_buffer(
    pipe: u8,
) -> Result<GenericFb, crate::amdgpu_dcn401_otg::Error> {
    let mut owner = OWNER.lock().await;
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
    let (done, before, after) = {
        let mut owner = OWNER.lock().await;
        let boot = owner
            .as_mut()
            .ok_or(crate::amdgpu_dcn401_otg::Error::Busy)?;
        let before = boot.display_scanout_framebuffer(pipe)?;
        // SAFETY: serialized retained owners; caller excludes external writers.
        let done = unsafe { boot.flip_display(pipe).await }?;
        (done, before, boot.display_scanout_framebuffer(pipe)?)
    };
    if crate::amdgpu_dcn_display::active_scanout().is_some_and(|fb| fb.addr == before.addr) {
        crate::amdgpu_dcn_display::publish_external(Some(after), Some(flush_scanout));
        crate::amdgpu_dcn_display::publish_external_cursor(Some(scanout_cursor));
    }
    Ok(done)
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

/// Withdraw the published scanout, then reverse a successful modeset to a
/// disabled PHY with timing and planes retired. The surface stays allocated,
/// so a console write already in flight lands in retained memory.
/// # Safety
/// As for `modeset_display`.
pub async unsafe fn stop_modeset(
    modeset: &crate::amdgpu_navi48_boot::Modeset,
) -> Result<(), crate::amdgpu_navi48_boot::ModesetError> {
    use crate::amdgpu_navi48_boot::{Error as BootError, ModesetError};
    crate::amdgpu_dcn_display::publish_external(None, None);
    crate::amdgpu_navi48_kms::publish(None);
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ModesetError::Boot(BootError::Busy))?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    unsafe { boot.stop_modeset(modeset).await }
}

/// Poll period of the native display monitor. HPD interrupts are not yet
/// dispatched to the display owner, so hot-plug and link loss are polled.
const MONITOR_MS: u64 = 1000;

/// What one native display monitor pass did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorStep {
    /// Sink present, link locked, scanout fetching; the fresh frame count.
    Running(u32),
    /// The link lost lock and was retrained; scanout resumed.
    Retrained,
    /// HPD fell: the scanout was withdrawn and the modeset torn down.
    Unplugged,
    /// A sink appeared with no modeset running, and was lit.
    Replugged,
    /// No modeset and no sink.
    Waiting,
}

/// One monitor pass: check a running modeset and retrain or tear it down,
/// or light a newly plugged sink when none runs.
/// # Safety
/// As for `modeset_display`.
pub async unsafe fn monitor_display(
    current: &mut Option<crate::amdgpu_navi48_boot::Modeset>,
    pipe: u8,
) -> Result<MonitorStep, crate::amdgpu_navi48_boot::ModesetError> {
    use crate::amdgpu_navi48_boot::{Error as BootError, Health, ModesetError};
    let Some(m) = current.as_mut() else {
        let plugged = {
            let mut owner = OWNER.lock().await;
            let boot = owner.as_mut().ok_or(ModesetError::Boot(BootError::Busy))?;
            let ports = boot.display_paths().map_or(0, <[_]>::len);
            (0..ports).any(|port| boot.display_hpd(port) == Ok(true))
        };
        if !plugged {
            return Ok(MonitorStep::Waiting);
        }
        // SAFETY: the caller's obligations.
        *current = Some(unsafe { modeset_display(pipe, |_, row| row.fill(0)) }.await?);
        return Ok(MonitorStep::Replugged);
    };
    let mut owner = OWNER.lock().await;
    let boot = owner.as_mut().ok_or(ModesetError::Boot(BootError::Busy))?;
    // SAFETY: serialized retained owners; caller excludes external writers.
    match unsafe { boot.check_modeset(m).await }? {
        Health::Running(frame) => Ok(MonitorStep::Running(frame)),
        Health::LinkLost(_) => {
            // The surface stays allocated and published: console writes
            // during the retrain land in it and show once scanout resumes.
            // SAFETY: as above.
            unsafe { boot.retrain_modeset(m).await }?;
            // The fallback may have changed the link, never the timing.
            Ok(MonitorStep::Retrained)
        }
        Health::Unplugged => {
            crate::amdgpu_dcn_display::publish_external(None, None);
            crate::amdgpu_navi48_kms::publish(None);
            // SAFETY: as above; the scanout is withdrawn first.
            unsafe { boot.unplug_modeset(m).await }?;
            *current = None;
            Ok(MonitorStep::Unplugged)
        }
    }
}

/// Poll a lit modeset for hot-plug and link loss until the owner fails.
/// HPD is enabled on every routed port so a sink on another port is seen.
/// # Safety
/// As for `modeset_display`, for the lifetime of the spawned task.
pub unsafe fn spawn_display_monitor(modeset: crate::amdgpu_navi48_boot::Modeset) {
    narf_scheduler::spawn(async move {
        use core::fmt::Write;
        let pipe = modeset.pipe;
        let mut current = Some(modeset);
        {
            let mut owner = OWNER.lock().await;
            if let Some(boot) = owner.as_mut() {
                let ports = boot.display_paths().map_or(0, <[_]>::len);
                for port in 0..ports {
                    let dp = boot.display_paths().is_ok_and(|p| {
                        p[port].connector == crate::amdgpu_dcn_inventory::Connector::DisplayPort
                    });
                    if dp {
                        // SAFETY: board-routed selectors; no GPIO user of HPD pins.
                        let _ = unsafe { boot.enable_display_hpd(port) };
                    }
                }
            }
        }
        loop {
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(MONITOR_MS).as_instant())
                .await;
            // SAFETY: the spawner's obligations hold for the task's lifetime.
            match unsafe { monitor_display(&mut current, pipe) }.await {
                Ok(MonitorStep::Running(_) | MonitorStep::Waiting) => {}
                Ok(step) => {
                    let _ = writeln!(narf_console::Writer, "amdgpu: navi48 display {step:?}");
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
