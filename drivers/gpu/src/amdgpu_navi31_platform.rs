//! One retained Navi31 (RDNA3) identity owner, entered by the framebuffer
//! boot handoff. Navi31 executes ordered bring-up stages through the
//! retained [`crate::amdgpu_navi31_boot::ColdBoot`]; Navi32/33 keep the
//! identity skeleton (their bring-up is a follow-up lane, not a silent
//! extension), so their boot behavior is unchanged: no device writes,
//! no firmware loads, the inherited display left alone.
//!
//! The stages are the programme's lane order (tracker #2455); each
//! parked owner fails closed in `run` until its lane lands. Until the
//! first real stage exists, `run` returns the skeleton report and the
//! inherited display is left alone — a Navi31 card boots exactly as it
//! did before this module existed (GOP framebuffer), except the dispatch
//! now reaches here instead of stopping inert after probe.
//!
//! Preparation is read-only for Navi32/33; for Navi31 it validates and
//! copies every firmware blob and builds the VRAM inventory before
//! claiming the card. The caller stops CPU writers before entering it.
use crate::{
    amdgpu, amdgpu_navi31_boot as boot,
    amdgpu_rdna3::{self, Rdna3Chip},
    amdgpu_vram_boot as vram,
};
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
    /// The bound GPU stopped identifying as RDNA3 under its own claim.
    DeviceGone,
    /// `run` was called before a successful `prepare`.
    NotPrepared,
    Firmware(boot::Error),
    Memory(vram::Error),
}

/// The bring-up stages, in the order the programme lands them. A stage
/// names its tracker lane: PSP/SMU is lane 2, GMC lane 3, IH lane 4,
/// DCN/DMUB lane 5, CP/RLC/MES lane 6, SDMA lane 7, submitter lane 8,
/// VCN/JPEG lane 9, thermal/DPM lane 10. Memory training (GDDR6, as on
/// Navi48's ColdBoot) runs first once lane 2's firmware exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    MemoryTraining,
    Psp,
    Smu,
    Gmc,
    Ih,
    Dcn,
    Cp,
    Sdma,
    Submitter,
    Vcn,
    Thermal,
}
pub(crate) const STAGES: [Stage; 11] = [
    Stage::MemoryTraining,
    Stage::Psp,
    Stage::Smu,
    Stage::Gmc,
    Stage::Ih,
    Stage::Dcn,
    Stage::Cp,
    Stage::Sdma,
    Stage::Submitter,
    Stage::Vcn,
    Stage::Thermal,
];

/// What `run` reports. While the skeleton stands, `stages_completed` is 0
/// and `next_stage` is the first stage a later lane must implement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub chip: Rdna3Chip,
    pub stages_completed: u8,
    pub next_stage: Option<Stage>,
}
impl Report {
    pub fn skeleton(chip: Rdna3Chip) -> Self {
        Self {
            chip,
            stages_completed: 0,
            next_stage: STAGES.first().copied(),
        }
    }
}

/// The retained identity: the discovered die, its IP versions, and whether
/// the boot framebuffer belongs to this GPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Skeleton {
    pub chip: Rdna3Chip,
    pub gc_version: (u8, u8, u8),
    pub mp0: Option<(u8, u8, u8)>,
    pub mp1: Option<(u8, u8, u8)>,
    pub affected: bool,
}

/// Bring-up progress only, never an acceleration-ready indication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Absent,
    Running,
    Retained(Diagnostics),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diagnostics {
    pub chip: Rdna3Chip,
    pub gc_version: (u8, u8, u8),
    pub mp0: Option<(u8, u8, u8)>,
    pub mp1: Option<(u8, u8, u8)>,
    pub stages_completed: u8,
    pub next_stage: Option<Stage>,
    pub affected: bool,
}

/// The retained owner: a Navi31 cold boot, or the identity skeleton
/// for Navi32/33 (whose bring-up is a follow-up lane).
#[derive(Debug)]
enum Owner {
    Skeleton(Skeleton),
    ColdBoot(alloc::boxed::Box<boot::ColdBoot>),
}

static OWNER: Mutex<Option<Owner>> = Mutex::new(None);

pub fn status() -> Status {
    match OWNER.try_lock() {
        None => Status::Running,
        Some(owner) => owner.as_ref().map_or(Status::Absent, |owner| {
            let (skeleton, stages_completed, next_stage) = match owner {
                Owner::Skeleton(skeleton) => (*skeleton, 0, STAGES.first().copied()),
                Owner::ColdBoot(boot) => {
                    let (completed, next) = boot.progress();
                    (boot.skeleton(), completed, next)
                }
            };
            Status::Retained(Diagnostics {
                chip: skeleton.chip,
                gc_version: skeleton.gc_version,
                mp0: skeleton.mp0,
                mp1: skeleton.mp1,
                stages_completed,
                next_stage,
                affected: skeleton.affected,
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

/// Claim the bound RDNA3 card and retain its discovered identity.
/// `Ok(None)` means no Navi31/32/33. `Ok(Some(affected))` means the owner
/// is retained and reports whether the boot framebuffer belongs to this GPU.
/// For Navi31 this also opens and validates every firmware blob, builds
/// the VRAM inventory, and retains the prepared ColdBoot; errors before
/// the claim leave framebuffer/controller access live.
///
/// # Safety
/// Call once during single-CPU boot, before executor polling or userspace,
/// with no NARF GPU allocations, active queues, reset or PM transitions.
/// `framebuffer` is the original bus-physical GOP geometry, not its remapped VA.
/// Probe's mappings and PCI ownership must be permanent. CPU framebuffer
/// writers and sleep pumps must already be stopped and remain stopped until
/// run succeeds (or until a preparation error returns).
pub unsafe fn prepare(framebuffer: Option<GenericFb>) -> Result<Option<bool>, Error> {
    if !amdgpu::is_navi31() {
        return Ok(None);
    }
    // No hardware writes or retained ownership before the timing preflight.
    if !amdgpu::boot_clock_ready() {
        return Err(Error::Clock);
    }
    let mut owner = OWNER.try_lock().ok_or(Error::Busy)?;
    if owner.is_some() {
        return Err(Error::Busy);
    }
    amdgpu::claim_navi31(|gpu| {
        // claim_navi31 matched this GPU on the same predicate under the
        // same controller lock; discovery cannot change underneath it.
        let chip = Rdna3Chip::of(gpu).ok_or(Error::DeviceGone)?;
        let (mp0, mp1) = amdgpu_rdna3::mp_versions(&gpu.ip_blocks);
        let end = gpu
            .vram
            .base
            .checked_add(gpu.vram.visible_size)
            .ok_or(Error::InvalidFramebuffer)?;
        let range = framebuffer_range(gpu.vram.base..end, framebuffer)?;
        let affected = range.is_some();
        amdgpu_rdna3::publish(Some(chip));
        let skeleton = Skeleton {
            chip,
            gc_version: chip.gc_version(),
            mp0,
            mp1,
            affected,
        };
        if chip != Rdna3Chip::Navi31 {
            // Navi32/33 keep the identity skeleton: no device writes,
            // no firmware loads, the inherited display left alone.
            *owner = Some(Owner::Skeleton(skeleton));
            return Ok(Some(affected));
        }
        let authority = amdgpu::pci_authority().ok_or(Error::Authority)?;
        let pci = amdgpu::pci_device().ok_or(Error::Authority)?;
        let registry: Cap<narf_firmware::FirmwareRegistry, Read> =
            narf_firmware::trusted_loader_authority()
                .ok_or(Error::Authority)?
                .derive()
                .map_err(|_| Error::Authority)?;
        // Validate/copy every file before inspecting hardware or claiming VRAM.
        let firmware = boot::Firmware::open(gpu, &registry).map_err(Error::Firmware)?;
        // SAFETY: caller's boot ownership, no active NARF clients. Plan refuses
        // live VM contexts and accounts for firmware, all pipes and cursors.
        let plan = unsafe { vram::Plan::read_navi31(gpu, &authority, range, &[]) }
            .map_err(Error::Memory)?;
        let training = plan.training();
        if training.is_some() {
            training_clients(plan.protected())?;
        }
        // SAFETY: the immutable inventory covers every inherited client, and
        // successful preparation excludes every later legacy MMIO accessor.
        // Nothing the driver allocates lies past the BAR: every owner takes
        // CPU-visible memory from `pool`, so that range is all clients'.
        // The VRAM past the BAR has no owner yet: `ColdBoot` takes only the
        // CPU-visible `pool`. The parked Mes/Ih lanes re-add the unmapped
        // retention when they land (Navi48's `pin_vram` pattern).
        let pool = unsafe { plan.into_pool() }.map_err(Error::Memory)?;
        // SAFETY: inventory covers every inherited client and CPU framebuffer
        // writers are paused. Construction performs bounded reads, never writes.
        let prepared = unsafe {
            boot::ColdBoot::new(gpu, pci, authority, &pool, firmware, training, skeleton)
        }
        .map_err(Error::Firmware)?;
        *owner = Some(Owner::ColdBoot(alloc::boxed::Box::new(prepared)));
        Ok(Some(affected))
    })
    .ok_or(Error::Busy)?
}

/// Run the prepared owner once. The skeleton reports the retained identity
/// with zero stages complete and leaves the inherited display untouched.
/// The ColdBoot drives its stages in order and fails closed at the first
/// stage whose owner does not exist yet; the framebuffer handoff then
/// quarantines the boot console.
///
/// # Safety
/// All CPU framebuffer writers/pumps and other VRAM clients must be stopped
/// before polling, and stay stopped after failure or cancellation until reset.
/// Continue to satisfy `prepare`'s exclusive hardware ownership contract.
pub async unsafe fn run() -> Result<Report, Error> {
    let mut owner = OWNER.lock().await;
    match owner.as_mut().ok_or(Error::NotPrepared)? {
        Owner::Skeleton(skeleton) => Ok(Report::skeleton(skeleton.chip)),
        Owner::ColdBoot(boot) => {
            let report = boot.run().await.map_err(Error::Firmware)?;
            Ok(Report {
                chip: report.chip,
                stages_completed: report.stages_completed,
                next_stage: report.next_stage,
            })
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi31_platform_tests.rs"]
mod tests;
