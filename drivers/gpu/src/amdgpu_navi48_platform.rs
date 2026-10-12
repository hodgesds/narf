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
