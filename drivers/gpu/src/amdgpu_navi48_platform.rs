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
    if let Some((limits, level)) = boot.power_info() {
        crate::amdgpu_navi48_power::start(limits, level);
    }
    Ok(report)
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

// ── Native displays ──────────────────────────────────────────────────
//
// Output k is the k-th lightable board port (DisplayPort or HDMI, the
// first four); it is always lit on pipe k, which is also its display slot
// in the owner and its CRTC in KMS. The console runs on the first display
// of the configuration (DP before HDMI); DRM clients present per display.

type Timing = crate::amdgpu_dml::Timing;
type Modeset = crate::amdgpu_navi48_boot::Modeset;
type ModesetError = crate::amdgpu_navi48_boot::ModesetError;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Pipe of the console's display, for the cursor hook.
static CURSOR_PIPE: AtomicU8 = AtomicU8::new(0);

/// The pipe (display) the console runs on.
pub fn console_pipe() -> u8 {
    CURSOR_PIPE.load(Ordering::Acquire)
}

/// The outputs in order: (display-path index, connector type). The
/// lightable board ports; while a DP port's MST branch is lit, its end
/// devices instead, `MAX_OUTPUTS` outputs on that port.
static OUTPUTS: narf_lib::sync::IrqSafeSpinLock<Vec<(usize, crate::drm::card::ConnectorType)>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

/// The initial MST configuration dedicates all four outputs to one branch.
fn mst_output_port(outputs: &[(usize, crate::drm::card::ConnectorType)]) -> Option<usize> {
    let first = *outputs.first()?;
    (outputs.len() == crate::amdgpu_navi48_kms::MAX_OUTPUTS
        && first.1 == crate::drm::card::ConnectorType::DisplayPort
        && outputs.iter().all(|o| *o == first))
    .then_some(first.0)
}

fn lightable_outputs(boot: &boot::ColdBoot) -> Vec<(usize, crate::drm::card::ConnectorType)> {
    use crate::amdgpu_dcn_inventory::Connector;
    use crate::drm::card::ConnectorType;
    let Ok(paths) = boot.display_paths() else {
        return Vec::new();
    };
    paths
        .iter()
        .enumerate()
        .filter_map(|(port, p)| match p.connector {
            Connector::DisplayPort => Some((port, ConnectorType::DisplayPort)),
            Connector::HdmiTypeA => Some((port, ConnectorType::HdmiA)),
            _ => None,
        })
        .take(crate::amdgpu_navi48_kms::MAX_OUTPUTS)
        .collect()
}

/// The pipe (output) of board port `port`.
fn pipe_of(port: usize) -> Option<u8> {
    OUTPUTS
        .lock()
        .iter()
        .position(|&(p, _)| p == port)
        .map(|k| k as u8)
}

/// What DRM asked of one output and what it shows: a CRTC switched off
/// keeps its sink published (connected), as Linux keeps a disabled
/// connector's modes.
struct OutputState {
    /// DRM wants the CRTC on (SETCRTC with a framebuffer, atomic ACTIVE=1).
    active: bool,
    /// A recorded teardown stays inactive even if DRM requests on meanwhile.
    retiring: bool,
    /// The mode DRM last set, or None for the sink's preferred mode.
    requested: Option<Timing>,
    /// The lit sink: EDID, running timing and every offered timing.
    shown: Option<([u8; 128], Timing, Vec<Timing>)>,
    mst_id: Option<boot::MstOutputId>,
    mst_present: bool,
    mst_edid: Vec<u8>,
    mst_modes: Vec<Timing>,
    sst_present: bool,
    sst_edid: Vec<u8>,
    sst_modes: Vec<Timing>,
    last_hpd: Option<bool>,
}
impl OutputState {
    const fn new() -> Self {
        Self {
            active: true,
            retiring: false,
            requested: None,
            shown: None,
            mst_id: None,
            mst_present: false,
            mst_edid: Vec::new(),
            mst_modes: Vec::new(),
            sst_present: false,
            sst_edid: Vec::new(),
            sst_modes: Vec::new(),
            last_hpd: None,
        }
    }

    fn reconcile_sst(&mut self, output: Option<&boot::SstOutput>) {
        self.sst_present = output.is_some();
        self.sst_modes.clear();
        if !self.active {
            self.shown = None;
        }
        if let Some(output) = output {
            if self.sst_edid != output.edid {
                self.shown = None;
                self.requested = None;
                self.sst_edid.clone_from(&output.edid);
            }
            self.sst_modes.clone_from(&output.modes);
        } else {
            self.shown = None;
        }
    }

    fn observe_sst_hpd(&mut self, present: bool) -> bool {
        let reprobe = present && !self.last_hpd.unwrap_or(self.sst_present);
        self.last_hpd = Some(present);
        if !present {
            self.reconcile_sst(None);
        }
        reprobe
    }

    fn reconcile_mst(&mut self, output: Option<&boot::MstOutput>) {
        let id = output.map(|o| o.id);
        if self.mst_id != id {
            *self = Self::new();
            self.mst_id = id;
        }
        self.mst_present = output.is_some_and(|o| o.sink.is_some());
        self.mst_modes.clear();
        if !self.active {
            self.shown = None;
        }
        // Preserve disabled requests at this connector, but never advertise
        // the old monitor's modes after a different/unreadable EDID appears.
        if let Some(output) = output.filter(|_| self.mst_present) {
            self.mst_modes.clone_from(&output.modes);
            if self.mst_edid != output.edid {
                self.shown = None;
                self.requested = None;
                self.mst_edid.clone_from(&output.edid);
            }
        }
    }

    fn published(&self) -> Option<&([u8; 128], Timing, Vec<Timing>)> {
        if self.mst_id.is_some() && (!self.mst_present || !self.active) {
            None
        } else {
            self.shown.as_ref()
        }
    }
    fn published_active(&self) -> bool {
        self.active && !self.retiring
    }
    fn offered(&self) -> &[Timing] {
        if let Some((_, _, offered)) = self
            .shown
            .as_ref()
            .filter(|_| self.mst_id.is_none() || self.mst_present)
        {
            offered
        } else if self.mst_present {
            &self.mst_modes
        } else if self.sst_present {
            &self.sst_modes
        } else {
            &[]
        }
    }
    fn find_mode(&self, mode: &crate::drm::ioctl::DrmModeModeInfo) -> Option<Timing> {
        let geometry = |w: &crate::drm::ioctl::DrmModeModeInfo| {
            (
                w.clock,
                [w.hdisplay, w.hsync_start, w.hsync_end, w.htotal],
                [w.vdisplay, w.vsync_start, w.vsync_end, w.vtotal],
            )
        };
        self.offered()
            .iter()
            .copied()
            .find(|t| geometry(&crate::amdgpu_navi48_kms::timing_wire(t)) == geometry(mode))
    }
}
static OUTPUT_STATE: narf_lib::sync::IrqSafeSpinLock<[OutputState; 4]> =
    narf_lib::sync::IrqSafeSpinLock::new([const { OutputState::new() }; 4]);

/// Publish every output on the amdgpu card's KMS state; a shown sink whose
/// CRTC DRM switched off stays connected with its CRTC off.
fn publish_outputs() {
    let outputs = OUTPUTS.lock().clone();
    let state = OUTPUT_STATE.lock();
    let sinks: Vec<_> = outputs
        .iter()
        .enumerate()
        .map(|(k, &(_, kind))| (kind, state[k].published(), state[k].published_active()))
        .collect();
    let kms: Vec<crate::amdgpu_navi48_kms::Output> = sinks
        .iter()
        .enumerate()
        .map(|(k, &(kind, shown, _))| crate::amdgpu_navi48_kms::Output {
            kind,
            offered: state[k].offered(),
            edid: if state[k].mst_present {
                state[k].mst_edid.get(..128).and_then(|e| e.try_into().ok())
            } else if state[k].sst_present {
                state[k].sst_edid.get(..128).and_then(|e| e.try_into().ok())
            } else {
                None
            },
            sink: shown.map(|(edid, timing, offered)| crate::amdgpu_navi48_kms::Sink {
                edid,
                timing,
                offered,
            }),
        })
        .collect();
    crate::amdgpu_navi48_kms::publish(&kms);
    for (k, &(_, shown, active)) in sinks.iter().enumerate() {
        if shown.is_some() && !active {
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
    if let Some(o) = OUTPUT_STATE.lock().get_mut(usize::from(pipe)) {
        o.shown = Some((s.edid, s.timing, offered));
        o.retiring = false;
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
    use crate::drm::card::ConnectorType;
    if pending_display_work(boot) {
        return Err(crate::amdgpu_dcn401_otg::Error::Busy.into());
    }
    // The first plugged DP port whose sink is an MST branch lights its end
    // devices, one output each; the other ports stay dark meanwhile.
    let board = lightable_outputs(boot);
    let mut mst = None;
    for &(port, kind) in &board {
        if kind != ConnectorType::DisplayPort {
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
    let shape = match mst {
        Some(port) => {
            alloc::vec![(port, ConnectorType::DisplayPort); crate::amdgpu_navi48_kms::MAX_OUTPUTS]
        }
        None => board,
    };
    let reshaped = {
        let mut outputs = OUTPUTS.lock();
        let reshaped = *outputs != shape;
        *outputs = shape;
        reshaped
    };
    if reshaped {
        // Other outputs: DRM's requests were the old ones'.
        for o in OUTPUT_STATE.lock().iter_mut() {
            *o = OutputState::new();
        }
    }
    if let Some(port) = mst {
        boot.start_display_mst(port).await?;
        let link = boot.display_mst(port).ok_or(boot::MstFailure::Invalid)?;
        for (state, output) in OUTPUT_STATE.lock().iter_mut().zip(&link.outputs) {
            state.reconcile_mst(output.as_ref());
        }
        // Clear old CRTC/framebuffer bindings for removed/reassigned monitors
        // before a newly lit sink can inherit the slot's DRM framebuffer.
        publish_outputs();
    }
    let wants: Vec<(bool, Option<Timing>)> = {
        let mut state = OUTPUT_STATE.lock();
        // What this lighting lights is shown afresh; an output DRM switched
        // off keeps its sink published.
        for o in state.iter_mut().filter(|o| o.active) {
            o.shown = None;
        }
        state.iter().map(|o| (o.active, o.requested)).collect()
    };
    let want = |port: usize| pipe_of(port).and_then(|k| wants[usize::from(k)].1);
    let pipe = |port: usize| pipe_of(port).filter(|&k| wants[usize::from(k)].0);
    let result = if let Some(port) = mst {
        // End device k stays on output k, including gaps for disabled or
        // unreadable devices. Compacting would move another monitor here.
        let pipes: Vec<Option<u8>> = (0..4u8)
            .map(|k| wants[usize::from(k)].0.then_some(k))
            .collect();
        let want = |k: usize| wants[k].1;
        // SAFETY: the caller's obligations.
        unsafe { boot.modeset_mst_displays(port, fill, want, &pipes) }.await
    } else {
        // SAFETY: the caller's obligations.
        unsafe { boot.modeset_displays(fill, want, pipe) }.await
    };
    if mst.is_none() {
        let outputs = OUTPUTS.lock().clone();
        for (k, &(port, _)) in outputs.iter().enumerate() {
            let hpd = boot.display_hpd(port).ok();
            let mut state = OUTPUT_STATE.lock();
            state[k].reconcile_sst(boot.display_sst_outputs().iter().find(|o| o.port == port));
            state[k].last_hpd = hpd;
        }
        // Even a failed preferred-mode activation leaves a valid connector
        // inventory. It must not publish the former monitor's modes.
        publish_outputs();
    }
    let config = result?;
    if let Some(link) = mst.and_then(|port| boot.display_mst(port)) {
        for (state, output) in OUTPUT_STATE.lock().iter_mut().zip(&link.outputs) {
            state.reconcile_mst(output.as_ref());
        }
    }
    for m in &config.displays {
        // SAFETY: as above.
        unsafe { adopt(boot, m) }.await;
    }
    publish_console(boot, config.displays.first().map(|m| m.pipe));
    publish_outputs();
    Ok(config)
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
    if let Some(o) = OUTPUT_STATE.lock().get_mut(usize::from(display)) {
        o.active = active;
    }
}

/// Record a DRM "Broadcast RGB" value (0 Automatic, 1 Full, 2 Limited
/// 16:235) for the native displays. Like a mode request, the display
/// monitor relights running displays whose output range no longer matches.
pub fn request_broadcast_rgb(value: u8) {
    crate::amdgpu_navi48_boot::set_broadcast_rgb(value);
}

/// Whether display `display` offers `mode` (one of its published timings).
pub fn display_offers(display: u8, mode: &crate::drm::ioctl::DrmModeModeInfo) -> bool {
    OUTPUT_STATE
        .lock()
        .get(usize::from(display))
        .is_some_and(|o| o.find_mode(mode).is_some())
}

/// Record the mode a DRM client set on display `display` (SETCRTC or an
/// atomic MODE_ID), which must be one of that display's offered timings;
/// `None` returns it to its preferred mode. Returns false for a mode the
/// display does not offer.
pub fn request_display_mode(
    display: u8,
    mode: Option<&crate::drm::ioctl::DrmModeModeInfo>,
) -> bool {
    let mut state = OUTPUT_STATE.lock();
    let Some(o) = state.get_mut(usize::from(display)) else {
        return false;
    };
    let Some(m) = mode else {
        o.requested = None;
        return true;
    };
    let found = o.find_mode(m);
    match found {
        Some(t) => {
            o.requested = Some(t);
            true
        }
        None => false,
    }
}

/// Every display back to the console's defaults (on, preferred mode), as
/// drm_fb_helper restores the console on lastclose.
pub fn restore_displays() {
    for o in OUTPUT_STATE.lock().iter_mut() {
        o.active = true;
        o.requested = None;
    }
}

/// The monitor's view of the configuration: each pipe's running modeset,
/// and the outputs whose plugged sinks the last lighting already considered
/// (lit or left dark), so only a new sink or a returned CRTC relights.
#[derive(Debug)]
pub struct Displays {
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

/// Physical HPD describes the root only. MST output presence comes from the
/// retained downstream snapshot, including when no stream is running.
fn output_present(boot: &mut boot::ColdBoot, port: usize, slot: usize, mst: bool) -> bool {
    boot.display_hpd(port) == Ok(true)
        && (!mst
            || boot.display_mst(port).is_some_and(|l| {
                l.outputs
                    .get(slot)
                    .and_then(Option::as_ref)
                    .is_some_and(|o| o.sink.is_some())
            }))
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
    boot.begin_modeset_teardown(&m, unplugged)?;
    OUTPUT_STATE.lock()[usize::from(pipe)].retiring = true;
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
        let mut state = OUTPUT_STATE.lock();
        let output = &mut state[usize::from(pipe)];
        if m.selection.mst.is_some() {
            // A disable need not relight surviving streams. Retain the modes
            // already admitted beside them, without retaining a CRTC mode.
            // The next configuration/reprobe recomputes independent admission.
            output.mst_modes = if unplugged {
                Vec::new()
            } else {
                m.modes.iter().flatten().copied().collect()
            };
            output.shown = None;
        } else {
            output.sst_modes = if unplugged {
                output.sst_present = false;
                Vec::new()
            } else {
                m.modes.iter().flatten().copied().collect()
            };
            output.shown = None;
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
    // Keep a connected branch's output identities and DRM requests even
    // when every CRTC is off. Only its physical removal restores board ports.
    let mst_port = mst_output_port(&OUTPUTS.lock());
    if displays.lit.iter().all(Option::is_none)
        && mst_port.is_some_and(|p| boot.display_hpd(p) == Ok(false))
    {
        boot.forget_unplugged_display_mst(mst_port.unwrap())?;
        let board = lightable_outputs(boot);
        let mut outputs = OUTPUTS.lock();
        if *outputs != board {
            *outputs = board;
            drop(outputs);
            for o in OUTPUT_STATE.lock().iter_mut() {
                *o = OutputState::new();
            }
            displays.considered = 0;
            publish_outputs();
        }
    }
    let outputs = OUTPUTS.lock().clone();
    let wants: Vec<(bool, Option<Timing>)> = OUTPUT_STATE
        .lock()
        .iter()
        .map(|o| (o.active, o.requested))
        .collect();
    let limited =
        crate::amdgpu_navi48_boot::limited_range(crate::amdgpu_navi48_boot::broadcast_rgb());
    let pending_mask = (0..4u8)
        .filter(|&p| {
            displays.lit[usize::from(p)].is_some() && boot.display_teardown_status(p).is_some()
        })
        .fold(0u8, |mask, p| mask | (1 << p));
    let mut relight = false;
    if mst_port.is_none() {
        for (k, &(port, _)) in outputs.iter().enumerate() {
            if let Ok(present) = boot.display_hpd(port) {
                let mut state = OUTPUT_STATE.lock();
                let o = &mut state[k];
                // A disabled port still needs a new EDID/admission snapshot
                // when HPD rises. Physical removal needs no AUX transaction.
                relight |= o.observe_sst_hpd(present);
            }
        }
        publish_outputs();
    }
    if let Some(port) = mst_port {
        if pending_mask == 0
            && boot.display_hpd(port) == Ok(true)
            && boot.display_mst(port).is_some()
        {
            relight = boot.service_display_mst(port).await?;
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
        if desired.is_some_and(|d| d != m.selection.timing) || limited != m.selection.limited {
            relight = true;
            continue;
        }
        // SAFETY: serialized retained owners; writers stay excluded.
        match unsafe { boot.check_modeset(&m) }.await? {
            Health::Running(_) => {}
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
                unsafe { boot.retrain_modeset(&mut m) }.await?;
                displays.lit[usize::from(k)] = Some(m);
                steps.push(MonitorStep::Retrained(k));
            }
            Health::Unplugged => {
                // SAFETY: as above; the helper records intent before withdrawing.
                unsafe { retire_monitored_display(boot, displays, k, true) }.await?;
                steps.push(MonitorStep::Unplugged(k));
            }
        }
    }
    // Sinks to light: plugged on an output DRM has not switched off.
    let mut wanted = 0u8;
    for (k, &(port, _)) in outputs.iter().enumerate() {
        if wants[k].0 && output_present(boot, port, k, mst_output_port(&outputs).is_some()) {
            wanted |= 1 << k;
        }
    }
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
            Err(e @ (ModesetError::NoSink | ModesetError::Link)) if !pending_display_work(boot) => {
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
                for o in OUTPUT_STATE.lock().iter_mut() {
                    o.requested = None;
                }
                // SAFETY: as above.
                Some(unsafe { light_displays(boot, fill) }.await?)
            }
            Err(e) => return Err(e),
            Ok(config) => Some(config),
        };
        let mut count = 0;
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
        // Every plugged output the lighting saw, on its outputs (an MST
        // branch's replace the board's).
        let outputs = OUTPUTS.lock().clone();
        let state = OUTPUT_STATE.lock();
        displays.considered = outputs
            .iter()
            .enumerate()
            .filter(|&(k, &(port, _))| {
                state[k].active
                    && output_present(boot, port, k, mst_output_port(&outputs).is_some())
            })
            .fold(0, |acc, (k, _)| acc | 1 << k);
        drop(state);
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
    narf_scheduler::spawn(async move {
        use core::fmt::Write;
        let mut displays = Displays {
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
            if let Some(boot) = owner.as_mut() {
                // Every board port, whatever the outputs are now.
                let ports: Vec<usize> = lightable_outputs(boot).iter().map(|&(p, _)| p).collect();
                for port in ports {
                    // SAFETY: board-routed selectors; no GPIO user of HPD pins.
                    if unsafe { boot.enable_display_hpd(port) }.is_ok() {
                        // SAFETY: the interrupt worker routes DCN vectors to
                        // the dispatcher this monitor waits on.
                        let _ = unsafe { boot.enable_display_hpd_irq(port) };
                    }
                }
                // Bits describe current outputs, which can be MST devices
                // rather than board-port ordinals.
                let outputs = OUTPUTS.lock().clone();
                for (k, &(port, _)) in outputs.iter().enumerate() {
                    if output_present(boot, port, k, mst_output_port(&outputs).is_some()) {
                        displays.considered |= 1 << k;
                    }
                }
            }
        }
        let mut hotplug = None;
        loop {
            if crate::amdgpu_navi48_dispatch::wait_hotplug(&mut hotplug, MONITOR_MS).await {
                // Acknowledge (and re-arm the opposite edge of) every port's
                // raised HPD/HPD-RX before the pass reads the sense.
                let mut owner = OWNER.lock().await;
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

    fn navi48_dark_sst_connector_preserves_disable_and_invalidates_replacement() -> TestResult {
        let timing = Timing {
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
        };
        let mut output = boot::SstOutput {
            port: 2,
            edid: alloc::vec![0; 256],
            modes: alloc::vec![timing],
        };
        let mut state = OutputState::new();
        state.active = false;
        state.reconcile_sst(Some(&output));
        assert!(state.sst_present && state.published().is_none());
        assert!(!state.published_active());
        let wire = crate::amdgpu_navi48_kms::timing_wire(&timing);
        assert_eq!(state.find_mode(&wire), Some(timing));
        state.requested = Some(timing);
        assert!(!state.observe_sst_hpd(true));
        assert!(!state.observe_sst_hpd(false));
        assert!(!state.sst_present && state.offered().is_empty());
        assert_eq!(state.requested, Some(timing));
        assert!(state.observe_sst_hpd(true));
        assert!(!state.observe_sst_hpd(true));
        state.reconcile_sst(Some(&output));
        assert!(!state.active && state.published().is_none());
        assert_eq!(state.requested, Some(timing));
        assert_eq!(state.find_mode(&wire), Some(timing));
        // Extension changes invalidate requests even with an identical base.
        output.edid[128] = 1;
        output.modes.clear();
        state.reconcile_sst(Some(&output));
        assert!(state.sst_present && !state.active);
        assert!(state.requested.is_none() && state.offered().is_empty());
        let mut initially_absent = OutputState::new();
        initially_absent.active = false;
        assert!(initially_absent.observe_sst_hpd(true));
        assert!(!initially_absent.observe_sst_hpd(true));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-kms",
        navi48_dark_sst_connector_preserves_disable_and_invalidates_replacement
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
        let timing = Timing {
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
        };
        let mut state = OutputState::new();
        output.modes.push(timing);
        state.reconcile_mst(Some(&output));
        state.shown = Some(([0; 128], timing, alloc::vec![timing]));
        state.requested = Some(timing);
        state.active = false;
        let mut considered = 0;
        // Downstream disconnect drives a reprobe even with no wanted CRTC.
        assert!(needs_relight(true, 0, 0, &mut considered));
        output.sink = None;
        output.edid.clear();
        state.reconcile_mst(Some(&output));
        assert!(state.published().is_none());
        assert!(state.offered().is_empty());
        assert!(!state.active);
        assert_eq!(state.requested, Some(timing));
        // The same connector and EDID return with a different branch index.
        output.sink = Some(crate::dp_mst_mgr::Sink { branch: 2, port: 3 });
        output.edid.resize(256, 0);
        state.reconcile_mst(Some(&output));
        assert!(state.published().is_none());
        assert_eq!(state.offered(), &[timing]);
        let wire = crate::amdgpu_navi48_kms::timing_wire(&timing);
        assert_eq!(state.find_mode(&wire), Some(timing));
        assert!(!state.active);
        assert_eq!(state.requested, Some(timing));
        assert!(!needs_relight(false, 0, 0, &mut considered));
        state.active = true;
        assert_eq!(state.find_mode(&wire), Some(timing));
        assert!(needs_relight(false, 1, 0, &mut considered));
        // A different monitor on this connector retains disabled state but
        // loses stale modes. Reassigning the slot resets old DRM requests.
        state.active = false;
        output.edid[128] = 1; // same base block, changed extension modes
        output.modes.clear(); // a reprobe invalidates admission too
        state.reconcile_mst(Some(&output));
        assert!(!state.active && state.shown.is_none() && state.requested.is_none());
        assert!(state.find_mode(&wire).is_none());
        output.id.branch = [3; 16];
        state.reconcile_mst(Some(&output));
        assert!(state.active && state.shown.is_none() && state.requested.is_none());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48",
        navi48_mst_disabled_connector_survives_hotplug
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

    fn navi48_monitor_finishes_retirement_before_reactivation() -> TestResult {
        let mut output = OutputState::new();
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
