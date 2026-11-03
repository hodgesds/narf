//! Meteor Lake / Arrow Lake standalone media GT (Xe_LPM+, media IP 13.00).
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! - xe_pci.c::{read_gmdid,handle_gmdid,alloc_media_gt} and `media_ips`: on
//!   GMD_ID platforms the media IP is a separate GT1 whose GMD_ID is read at
//!   `GMD_ID + MEDIA_GT_GSI_OFFSET`; version 0 means fused off / not present.
//!   `mtl_desc` (shared by Arrow Lake) pairs Xe_LPG/Xe_LPG+ 12.70/12.71/12.74
//!   graphics with `media_xelpmp` (VCS0-7, VECS0-3, GSCCS0).
//! - xe_gt.c::xe_gt_mmio_init + xe_mmio.h::xe_mmio_adjusted_addr: media-GT
//!   offsets below `MEDIA_GT_GSI_LENGTH` translate by `MEDIA_GT_GSI_OFFSET`;
//!   everything else (engine bases, GSC HECI) is absolute.
//! - xe_force_wake.c::{xe_force_wake_init_gt,xe_force_wake_init_engines}: GT
//!   domain FORCEWAKE_GT / FORCEWAKE_ACK_GT_MTL (graphics >= 12.70), no render
//!   domain on a media GT, one VDBOX/VEBOX domain per present engine, 50 ms
//!   acknowledgement bound and an all-ones ack treated as lost MMIO.
//! - xe_hw_engine.c::read_media_fuses: GT_VEBOX_VDBOX_DISABLE with positive
//!   (present) polarity at graphics >= 12.50. check_gsc_availability drops
//!   GSCCS0 without loaded GSC firmware, which this owner never loads.
//! - Probe resets only the GuC: xe_uc.c::xe_uc_sanitize_reset (from
//!   xe_uc_init_post_hwconfig/xe_uc_load_hw) -> xe_guc.c::xe_guc_reset
//!   (GRDOM_GUC, 5 ms, GS_MIA_IN_RESET). xe_gt.c::do_gt_reset (GRDOM_FULL,
//!   5 ms, bracketed by xe_gsc.c::xe_gsc_wa_14015076503, MEDIA_VERSION(1300))
//!   runs only from gt_reset_worker and xe_gt_shutdown; here only a recovery
//!   owner (`MediaGt::for_recovery`) performs it.
//! - xe_pat.c `xelpg_pat_table` through `xelpg_pat_ops.program_media`
//!   (program_pat_mcr), xe_gt_mcr.c::{mcr_lock,mcr_unlock,
//!   xe_gt_mcr_multicast_write} with STEER_SEMAPHORE / MTL_MCR_SELECTOR.
//! - xe_mocs.c `mtl_mocs_desc`, unused index 1, HAS_GLOBAL_MOCS|HAS_LNCF_MOCS
//!   and `regs_are_mcr` (plain writes for media < 20).
//! - xe_wa.c gt_was "Xe_LPM+" (16021867713 per VDBOX, 22016670082) with
//!   xe_rtp.c's standalone-media split: graphics rules never match GT1 and
//!   media rules never match GT0. xe_tuning.c has no media 13.00 entry.
//!
//! This owner establishes the media GT's identity, inventory, wake, cache,
//! workaround and GuC-sanitize state for one GT0 incarnation and then releases
//! every wake request it made. The whole media GT path is default-off behind
//! `narf.intel.media_gt=1` (`requested`). `MediaGuc` below runs the media GuC
//! and its polled CT; no media engine or UAPI GT is published here.

use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_engine::{Engine, EngineSet};
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_gt_hw::{MTL_GLOBAL_MOCS, MTL_L3CC};
use core::task::Poll;

/// Default-off opt-in for the whole MTL/Arrow media GT path (lifecycle owner,
/// media GuC, CT and second-TLB registration), with the shared pre-`--`
/// grammar of `narf.intel.huc=1` and `narf.intel.bmg_smallbar=1`.
pub(crate) fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, "narf.intel.media_gt")
}

/// Runtime admission: an MTL-classified device and the explicit opt-in.
/// Absent the option, GT0's runtime never constructs a media owner.
pub(crate) fn admitted(
    platform: Option<GtPlatform>,
    args: narf_boot::args::KernelCmdline<'_>,
) -> bool {
    platform.is_some_and(profile_eligible) && requested(args)
}

/// regs/xe_gt_regs.h MEDIA_GT_GSI_OFFSET / MEDIA_GT_GSI_LENGTH.
pub(crate) const GSI_OFFSET: u64 = 0x380000;
pub(crate) const GSI_LENGTH: u64 = 0x40000;

const GMD_ID: u64 = 0xd8c;
const FORCEWAKE_GT: u64 = 0xa188;
const FORCEWAKE_ACK_GT_MTL: u64 = 0xdfc;
const VEBOX_VDBOX_FUSE: u64 = 0x9140;
const GDRST: u64 = 0x941c;
const GRDOM_FULL: u32 = 1 << 0;
const GRDOM_GUC: u32 = 1 << 3;
const GUC_STATUS: u64 = 0xc000;
const GS_MIA_IN_RESET: u32 = 1 << 0;
const STEER_SEMAPHORE: u64 = 0xfd0;
const MTL_MCR_SELECTOR: u64 = 0xfd4;
const MCR_MULTICAST: u32 = 1 << 31;
const PAT_INDEX: u64 = 0x4800;
const GLOBAL_MOCS: u64 = 0x4000;
const LNCFCMOCS: u64 = 0xb020;
const XELPMP_SQCNT1: u64 = 0x8718;
const ENFORCE_RAR: u32 = 1 << 23;
const VDBOX_CGCTL3F1C: u64 = 0x3f1c;
const MFXPIPE_CLKGATE_DIS: u32 = 1 << 3;
// regs/xe_gsc_regs.h: MTL_GSC_HECI1_BASE 0x116000, MTL_GSC_HECI2_BASE 0x117000.
const HECI1_FWSTS1: u64 = 0x116000 + 0xc40;
const HECI1_FWSTS1_INIT_COMPLETE: u32 = 1 << 9;
const HECI2_H_GS1: u64 = 0x117000 + 0xc4c;
const HECI_H_GS1_ER_PREP: u32 = 1 << 0;
const HECI2_H_CSR: u64 = 0x117000 + 0x4;
const HECI_H_CSR_IG: u32 = 1 << 2;
const HECI_H_CSR_RST: u32 = 1 << 4;
/// FORCEWAKE_MT_MASK(FORCEWAKE_KERNEL) | FORCEWAKE_MT(FORCEWAKE_KERNEL).
const KERNEL_WAKE: u32 = 0x0001_0001;
const KERNEL_SLEEP: u32 = 0x0001_0000;
const WAKE_NS: u64 = 50_000_000;
const RESET_NS: u64 = 5_000_000;
const GSC_PREPARE_NS: u64 = 200_000_000;

/// `xelpg_pat_table`: WB, WT, UC, WB 1-way coherent, WB 2-way coherent.
pub(crate) const XELPG_PAT: [u32; 5] = [0x0, 0x4, 0xc, 0x2, 0x3];
/// xe_mmio.h::xe_mmio_adjusted_addr for a media GT's `adj_limit/adj_offset`.
pub(crate) const fn gsi(offset: u64) -> u64 {
    if offset < GSI_LENGTH {
        offset + GSI_OFFSET
    } else {
        offset
    }
}

/// The media GT's register view of the device BAR. It owns no authority:
/// every access still goes through the wrapped window's current checks.
pub(crate) struct MediaWindow<'a, M: MmioWindow + ?Sized>(&'a M);

impl<'a, M: MmioWindow + ?Sized> MediaWindow<'a, M> {
    pub(crate) fn new(bar: &'a M) -> Self {
        Self(bar)
    }
}

impl<M: MmioWindow + ?Sized> MmioWindow for MediaWindow<'_, M> {
    fn display_access_ok(&self) -> bool {
        false
    }
    fn read32(&self, offset: u64) -> u32 {
        self.0.read32(gsi(offset))
    }
    fn write32(&self, offset: u64, value: u32) {
        self.0.write32(gsi(offset), value)
    }
}

/// Owned media-GT register view for the long-lived media GuC and CT owners.
/// This type is the role proof: `GuCBoot::stage_media` accepts only it, so
/// GuC registers are GSI-translated while the absolute media mailbox,
/// engine and interrupt registers pass through unchanged.
#[derive(Clone, Debug)]
pub(crate) struct MediaGsi<M>(M);

impl<M: MmioWindow> MediaGsi<M> {
    pub(crate) fn new(bar: M) -> Self {
        Self(bar)
    }
}

impl<M: MmioWindow> MmioWindow for MediaGsi<M> {
    fn display_access_ok(&self) -> bool {
        false
    }
    fn read32(&self, offset: u64) -> u32 {
        self.0.read32(gsi(offset))
    }
    fn write32(&self, offset: u64, value: u32) {
        self.0.write32(gsi(offset), value)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaError {
    /// GMD_ID reports no media IP (fused off). Nothing was written.
    Absent,
    /// Not the exact MTL/Arrow Xe_LPG + Xe_LPM+ 13.00 profile.
    Unsupported,
    /// Current access was lost or a register read all-ones.
    Unavailable,
    /// Two identity samples disagreed.
    Unstable,
    /// Another agent holds a wake request or a reset is already in flight.
    Busy,
    Timeout,
    WakeLost,
    /// Fuses publish neither a VDBOX nor a VEBOX.
    NoEngines,
    /// The media GuC did not report its MIA core held in reset.
    Reset,
    State,
}

/// Media IP observed through the GSI-translated GMD_ID.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MediaIp {
    pub gmd: u32,
    pub version: u16,
    /// xe_step.c::xe_step_gmdid_get: STEP_A0 + GMD_ID revid.
    pub step: u8,
}

impl MediaIp {
    /// GMD_ID_ARCH_MASK 31:22, GMD_ID_RELEASE_MASK 21:14, GMD_ID_REVID 5:0.
    pub(crate) const fn decode(gmd: u32) -> Self {
        Self {
            gmd,
            version: ((gmd >> 22) * 100 + ((gmd >> 14) & 0xff)) as u16,
            step: (gmd & 0x3f) as u8,
        }
    }
}

/// Facts this owner established for one GT0 incarnation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MediaFacts {
    pub ip: MediaIp,
    /// Raw GT_VEBOX_VDBOX_DISABLE sampled under media GT wake.
    pub fuse: u32,
    /// Present physical VCS/VECS engines of GT1.
    pub engines: EngineSet,
}

/// Only Generation::MeteorLake (which includes Arrow Lake) has this profile.
pub(crate) const fn profile_eligible(platform: GtPlatform) -> bool {
    matches!(platform, GtPlatform::Integrated(Generation::MeteorLake))
}

/// xe_pci.c `graphics_ips` entries that `mtl_desc` can pair with Xe_LPM+.
pub(crate) const fn graphics_qualified(version: u16) -> bool {
    matches!(version, 1270 | 1271 | 1274)
}

/// Exact identity qualification. Version 0 is the source "media fused off".
pub(crate) fn qualify(
    platform: GtPlatform,
    graphics: u16,
    gmd: u32,
) -> Result<MediaIp, MediaError> {
    if !profile_eligible(platform) || !graphics_qualified(graphics) {
        return Err(MediaError::Unsupported);
    }
    if gmd == u32::MAX {
        return Err(MediaError::Unavailable);
    }
    if gmd == 0 {
        return Err(MediaError::Absent);
    }
    let ip = MediaIp::decode(gmd);
    if ip.version != 1300 {
        return Err(MediaError::Unsupported);
    }
    Ok(ip)
}

/// xe_hw_engine.c::read_media_fuses with present polarity, limited to the
/// media_xelpmp VCS/VECS mask. GSCCS0 is never a scheduled engine here.
pub(crate) fn inventory(fuse: u32) -> EngineSet {
    let vdbox = fuse & 0xff; // GT_VDBOX_DISABLE_MASK 7:0
    let vebox = (fuse >> 16) & 0xf; // GT_VEBOX_DISABLE_MASK 19:16
    let mut bits = 0;
    for engine in Engine::ALL.into_iter().filter(|engine| engine.is_media()) {
        let mask = if engine.is_decode() { vdbox } else { vebox };
        if mask >> engine.physical_instance() & 1 != 0 {
            bits |= 1 << engine.index();
        }
    }
    EngineSet::from_bits(bits)
}

/// Forcewake domain bitmap: bit0 GT, bits1-8 VDBOX0-7, bits9-12 VEBOX0-3.
pub(crate) fn engine_domains(engines: EngineSet) -> u16 {
    engines.iter().fold(0, |domains, engine| {
        let first = if engine.is_decode() { 1 } else { 9 };
        domains | 1 << (first + engine.physical_instance())
    })
}

/// FORCEWAKE request and acknowledgement registers (pre-GSI) of a domain.
pub(crate) const fn domain_registers(domain: u32) -> (u64, u64) {
    match domain {
        0 => (FORCEWAKE_GT, FORCEWAKE_ACK_GT_MTL),
        1..=8 => (
            0xa540 + (domain as u64 - 1) * 4,
            0xd50 + (domain as u64 - 1) * 4,
        ),
        _ => (
            0xa560 + (domain as u64 - 9) * 4,
            0xd70 + (domain as u64 - 9) * 4,
        ),
    }
}

fn domains(mask: u16) -> impl Iterator<Item = u32> {
    (0..13).filter(move |domain| mask & 1 << domain != 0)
}

fn domains_rev(mask: u16) -> impl Iterator<Item = u32> {
    (0..13).rev().filter(move |domain| mask & 1 << domain != 0)
}

fn read(mmio: &impl MmioWindow, reg: u64) -> Result<u32, MediaError> {
    let value = mmio.read32(reg);
    if value == u32::MAX {
        Err(MediaError::Unavailable)
    } else {
        Ok(value)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    /// Nothing has been read or written.
    Identify,
    /// A previous incarnation's GT sleep acknowledgement is still settling.
    SettleGt,
    WakeGt,
    ResetGuc,
    /// Wa_14015076503: loaded GSC firmware was alerted; wait 200 ms.
    GscPrepare,
    ResetFull,
    SettleEngines,
    WakeEngines,
    Program,
    Release,
    Failing(MediaError),
    Initialized,
    Failed(MediaError),
    Stopped,
}

/// Exclusive per-incarnation owner of the media GT wake/reset/cache state.
/// It never touches a GT0 register: every write is GSI-translated, a media
/// engine register or the media GT's own GSC HECI2 workaround register.
#[derive(Debug)]
pub(crate) struct MediaGt {
    platform: GtPlatform,
    graphics: u16,
    phase: Phase,
    deadline: u64,
    ip: Option<MediaIp>,
    fuse: u32,
    engines: EngineSet,
    /// Domains whose kernel wake request this owner wrote and not released.
    requested: u16,
    gsc_prepared: bool,
    /// A GT reset/recovery owner (gt_reset_worker), not a probe owner.
    recovery: bool,
}

impl MediaGt {
    /// Probe-time owner: identity, fuses, wells, PAT/WA/MOCS and the GuC
    /// sanitize reset, as Linux media-GT probe does. No GT reset.
    pub(crate) fn new(platform: GtPlatform, graphics: u16) -> Self {
        Self {
            platform,
            graphics,
            phase: Phase::Identify,
            deadline: 0,
            ip: None,
            fuse: 0,
            engines: EngineSet::default(),
            requested: 0,
            gsc_prepared: false,
            recovery: false,
        }
    }

    /// Media-GT reset/recovery owner after its GuC was stopped, following
    /// xe_gt.c::gt_reset_worker: do_gt_reset (Wa_14015076503 around
    /// GRDOM_FULL) and then do_gt_restart's reprogramming and GuC sanitize.
    pub(crate) fn for_recovery(platform: GtPlatform, graphics: u16) -> Self {
        Self {
            recovery: true,
            ..Self::new(platform, graphics)
        }
    }

    /// Established facts once the media GT is initialized and released.
    pub(crate) fn facts(&self) -> Option<MediaFacts> {
        (self.phase == Phase::Initialized).then(|| MediaFacts {
            ip: self.ip.expect("initialized identity"),
            fuse: self.fuse,
            engines: self.engines,
        })
    }

    /// Native-test fixture for owners layered above this lifecycle: an
    /// initialized, released media GT with the given identity and fuses.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn initialized_for_test(platform: GtPlatform, gmd: u32, fuse: u32) -> Self {
        let mut owner = Self::new(platform, 1274);
        owner.ip = Some(MediaIp::decode(gmd));
        owner.fuse = fuse;
        owner.engines = inventory(fuse);
        owner.phase = Phase::Initialized;
        owner
    }

    /// Wake requests this owner still has outstanding.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn outstanding_wake(&self) -> u16 {
        self.requested
    }

    /// Drive startup one bounded step. `bar` is the device BAR0 window; the
    /// owner applies the GSI translation itself. `current` must prove PCI/D0
    /// authority before any further register access.
    pub(crate) fn poll<M: MmioWindow + ?Sized>(
        &mut self,
        bar: &M,
        now: u64,
        mut current: impl FnMut() -> bool,
    ) -> Poll<Result<MediaFacts, MediaError>> {
        match self.phase {
            Phase::Initialized => return Poll::Ready(Ok(self.facts().expect("initialized"))),
            Phase::Failed(error) => return Poll::Ready(Err(error)),
            Phase::Stopped => return Poll::Ready(Err(MediaError::State)),
            _ => {}
        }
        let media = MediaWindow::new(bar);
        if !current() {
            return self.fail(&media, MediaError::Unavailable, now);
        }
        match self.step(&media, now) {
            Ok(true) => self.poll_terminal(),
            Ok(false) => Poll::Pending,
            Err(error) => self.fail(&media, error, now),
        }
    }

    fn poll_terminal(&self) -> Poll<Result<MediaFacts, MediaError>> {
        match self.phase {
            Phase::Initialized => Poll::Ready(Ok(self.facts().expect("initialized"))),
            Phase::Failed(error) => Poll::Ready(Err(error)),
            _ => Poll::Pending,
        }
    }

    /// One step. `Ok(true)` reports a terminal phase.
    fn step(&mut self, media: &impl MmioWindow, now: u64) -> Result<bool, MediaError> {
        match self.phase {
            Phase::Identify => {
                // Exact profile before the first MMIO access.
                if !profile_eligible(self.platform) || !graphics_qualified(self.graphics) {
                    return Err(MediaError::Unsupported);
                }
                // xe_pci.c::read_gmdid reads media GMD_ID without forcewake.
                let a = read(media, GMD_ID)?;
                if read(media, GMD_ID)? != a {
                    return Err(MediaError::Unstable);
                }
                let ip = match qualify(self.platform, self.graphics, a) {
                    Err(MediaError::Absent) => {
                        self.phase = Phase::Failed(MediaError::Absent);
                        return Ok(true);
                    }
                    other => other?,
                };
                self.ip = Some(ip);
                self.deadline = now.checked_add(WAKE_NS).ok_or(MediaError::Timeout)?;
                self.phase = Phase::SettleGt;
                self.request(media, 1, Phase::SettleGt, Phase::WakeGt)
            }
            Phase::SettleGt => {
                if !self.settled(media, 1, now)? {
                    return Ok(false);
                }
                self.request(media, 1, Phase::SettleGt, Phase::WakeGt)
            }
            Phase::WakeGt => {
                if !self.acked(media, 1, now)? {
                    return Ok(false);
                }
                self.gt_awake(media)?;
                let ip = self.ip.ok_or(MediaError::State)?;
                // gt_init_with_gt_forcewake re-reads GMD_ID under GT wake.
                let a = read(media, GMD_ID)?;
                if a != ip.gmd || read(media, GMD_ID)? != ip.gmd {
                    return Err(MediaError::Unstable);
                }
                self.fuse = read(media, VEBOX_VDBOX_FUSE)?;
                self.engines = inventory(self.fuse);
                if self.engines.iter().next().is_none() {
                    return Err(MediaError::NoEngines);
                }
                if !self.recovery {
                    // Probe: no GT reset (xe_gt.c::do_gt_reset runs only from
                    // gt_reset_worker and xe_gt_shutdown). The GuC sanitize
                    // reset follows hardware programming below.
                    return self.begin_wells(media, now);
                }
                // Recovery: xe_gt.c::gt_reset_worker -> do_gt_reset.
                if read(media, GDRST)? != 0 {
                    return Err(MediaError::Busy);
                }
                // xe_gsc.c::xe_gsc_wa_14015076503(gt, true).
                if read(media, HECI1_FWSTS1)? & HECI1_FWSTS1_INIT_COMPLETE != 0 {
                    let gs1 = read(media, HECI2_H_GS1)?;
                    media.write32(HECI2_H_GS1, gs1 | HECI_H_GS1_ER_PREP);
                    self.gsc_prepared = true;
                    let csr = read(media, HECI2_H_CSR)?;
                    media.write32(HECI2_H_CSR, (csr & !HECI_H_CSR_RST) | HECI_H_CSR_IG);
                    self.deadline = now.checked_add(GSC_PREPARE_NS).ok_or(MediaError::Timeout)?;
                    self.phase = Phase::GscPrepare;
                    return Ok(false);
                }
                self.begin_full_reset(media, now)
            }
            Phase::GscPrepare => {
                if now < self.deadline {
                    return Ok(false);
                }
                self.gt_awake(media)?;
                self.begin_full_reset(media, now)
            }
            Phase::ResetFull => {
                if read(media, GDRST)? & GRDOM_FULL != 0 {
                    return if now >= self.deadline {
                        Err(MediaError::Timeout)
                    } else {
                        Ok(false)
                    };
                }
                // xe_gsc_wa_14015076503(gt, false) clears the notification.
                self.clear_gsc_prepare(media)?;
                // GT wake survives the GT reset only if the hardware says so.
                self.gt_awake(media)?;
                // do_gt_restart then reprograms the GT as at probe.
                self.begin_wells(media, now)
            }
            Phase::SettleEngines => {
                let wells = engine_domains(self.engines);
                if !self.settled(media, wells, now)? {
                    return Ok(false);
                }
                self.request(media, wells, Phase::SettleEngines, Phase::WakeEngines)
            }
            Phase::WakeEngines => {
                if !self.acked(media, engine_domains(self.engines), now)? {
                    return Ok(false);
                }
                self.gt_awake(media)?;
                self.deadline = now.checked_add(WAKE_NS).ok_or(MediaError::Timeout)?;
                self.phase = Phase::Program;
                self.program(media, now)
            }
            Phase::Program => self.program(media, now),
            Phase::ResetGuc => {
                self.wells_awake(media)?;
                if read(media, GDRST)? & GRDOM_GUC != 0 {
                    return if now >= self.deadline {
                        Err(MediaError::Timeout)
                    } else {
                        Ok(false)
                    };
                }
                if read(media, GUC_STATUS)? & GS_MIA_IN_RESET == 0 {
                    return Err(MediaError::Reset);
                }
                self.begin_release(media, now)?;
                self.phase = Phase::Release;
                Ok(false)
            }
            Phase::Release => {
                if !self.released(media, now)? {
                    return Ok(false);
                }
                self.phase = Phase::Initialized;
                Ok(true)
            }
            Phase::Failing(error) => match self.released(media, now) {
                Ok(false) => Ok(false),
                // The original refusal remains the reported outcome.
                Ok(true) | Err(_) => {
                    self.phase = Phase::Failed(error);
                    Ok(true)
                }
            },
            Phase::Initialized | Phase::Failed(_) | Phase::Stopped => Ok(true),
        }
    }

    fn begin_wells(&mut self, media: &impl MmioWindow, now: u64) -> Result<bool, MediaError> {
        self.deadline = now.checked_add(WAKE_NS).ok_or(MediaError::Timeout)?;
        let wells = engine_domains(self.engines);
        self.phase = Phase::SettleEngines;
        self.request(media, wells, Phase::SettleEngines, Phase::WakeEngines)
    }

    fn begin_full_reset(&mut self, media: &impl MmioWindow, now: u64) -> Result<bool, MediaError> {
        media.write32(GDRST, GRDOM_FULL);
        self.deadline = now.checked_add(RESET_NS).ok_or(MediaError::Timeout)?;
        self.phase = Phase::ResetFull;
        Ok(false)
    }

    fn clear_gsc_prepare(&mut self, media: &impl MmioWindow) -> Result<(), MediaError> {
        if self.gsc_prepared {
            let gs1 = read(media, HECI2_H_GS1)?;
            media.write32(HECI2_H_GS1, gs1 & !HECI_H_GS1_ER_PREP);
            self.gsc_prepared = false;
        }
        Ok(())
    }

    /// Refuse an inherited request; wait for a settling sleep ACK; then write
    /// the kernel wake request of every domain in `mask` at once.
    fn request(
        &mut self,
        media: &impl MmioWindow,
        mask: u16,
        settle: Phase,
        wake: Phase,
    ) -> Result<bool, MediaError> {
        for domain in domains(mask) {
            let (request, ack) = domain_registers(domain);
            if read(media, request)? & 1 != 0 {
                return Err(MediaError::Busy);
            }
            if read(media, ack)? & 1 != 0 {
                self.phase = settle;
                return Ok(false);
            }
        }
        for domain in domains(mask) {
            let (request, _) = domain_registers(domain);
            media.write32(request, KERNEL_WAKE);
            self.requested |= 1 << domain;
        }
        for domain in domains(mask) {
            let _ = media.read32(domain_registers(domain).0); // posting read
        }
        self.phase = wake;
        Ok(false)
    }

    /// Every acknowledgement in `mask` reads asleep; `false` while a sleep
    /// from an earlier incarnation is still settling inside the bound.
    fn settled(&self, media: &impl MmioWindow, mask: u16, now: u64) -> Result<bool, MediaError> {
        for domain in domains(mask) {
            if read(media, domain_registers(domain).1)? & 1 != 0 {
                return if now >= self.deadline {
                    Err(MediaError::Timeout)
                } else {
                    Ok(false)
                };
            }
        }
        Ok(true)
    }

    /// Every domain in `mask` acknowledged its wake within the bound.
    fn acked(&self, media: &impl MmioWindow, mask: u16, now: u64) -> Result<bool, MediaError> {
        for domain in domains(mask) {
            if read(media, domain_registers(domain).1)? & 1 == 0 {
                return if now >= self.deadline {
                    Err(MediaError::Timeout)
                } else {
                    Ok(false)
                };
            }
        }
        Ok(true)
    }

    /// Both the retained GT request and its acknowledgement are still set.
    fn gt_awake(&self, media: &impl MmioWindow) -> Result<(), MediaError> {
        if self.requested & 1 == 0
            || read(media, FORCEWAKE_GT)? & 1 == 0
            || read(media, FORCEWAKE_ACK_GT_MTL)? & 1 == 0
        {
            return Err(MediaError::WakeLost);
        }
        Ok(())
    }

    fn wells_awake(&self, media: &impl MmioWindow) -> Result<(), MediaError> {
        self.gt_awake(media)?;
        for domain in domains(engine_domains(self.engines)) {
            let (request, ack) = domain_registers(domain);
            if self.requested & 1 << domain == 0
                || read(media, request)? & 1 == 0
                || read(media, ack)? & 1 == 0
            {
                return Err(MediaError::WakeLost);
            }
        }
        Ok(())
    }

    /// PAT under the media steering semaphore, then the media 13.00 GT WAs
    /// and MOCS under all-domain wake. Never returns holding the semaphore.
    fn program(&mut self, media: &impl MmioWindow, now: u64) -> Result<bool, MediaError> {
        self.wells_awake(media)?;
        // xe_gt_mcr.c::mcr_lock: a read of 1 grants the hardware semaphore.
        // Linux warns and proceeds after 10 us; this owner refuses instead.
        if read(media, STEER_SEMAPHORE)? & 1 == 0 {
            return if now >= self.deadline {
                Err(MediaError::Timeout)
            } else {
                Ok(false)
            };
        }
        let old = media.read32(MTL_MCR_SELECTOR);
        if old == u32::MAX {
            media.write32(STEER_SEMAPHORE, 1);
            return Err(MediaError::Unavailable);
        }
        media.write32(MTL_MCR_SELECTOR, old | MCR_MULTICAST);
        for (index, value) in XELPG_PAT.into_iter().enumerate() {
            media.write32(PAT_INDEX + index as u64 * 4, value);
        }
        let posted = media.read32(MTL_MCR_SELECTOR);
        media.write32(MTL_MCR_SELECTOR, old);
        media.write32(STEER_SEMAPHORE, 1); // mcr_unlock
        if posted == u32::MAX {
            return Err(MediaError::Unavailable);
        }
        // Wa_22016670082: SET(XELPMP_SQCNT1, ENFORCE_RAR), plain RMW.
        let sqcnt = read(media, XELPMP_SQCNT1)?;
        media.write32(XELPMP_SQCNT1, sqcnt | ENFORCE_RAR);
        // Wa_16021867713: FOREACH_ENGINE VIDEO_DECODE, engine-relative.
        for engine in self.engines.iter().filter(|engine| engine.is_decode()) {
            let reg = u64::from(engine.base()) + VDBOX_CGCTL3F1C;
            let value = read(media, reg)?;
            media.write32(reg, value | MFXPIPE_CLKGATE_DIS);
        }
        // xe_mocs.c::__init_mocs_table / init_l3cc_table, non-MCR on media13.
        for (index, value) in MTL_GLOBAL_MOCS.into_iter().enumerate() {
            media.write32(GLOBAL_MOCS + index as u64 * 4, value);
        }
        for (index, pair) in MTL_L3CC.chunks_exact(2).enumerate() {
            media.write32(
                LNCFCMOCS + index as u64 * 4,
                u32::from(pair[0]) | u32::from(pair[1]) << 16,
            );
        }
        self.wells_awake(media)?;
        // xe_uc.c::xe_uc_sanitize_reset -> xe_guc.c::xe_guc_reset, the only
        // reset on the probe path: GRDOM_GUC, 5 ms, then GS_MIA_IN_RESET.
        if read(media, GDRST)? != 0 {
            return Err(MediaError::Busy);
        }
        media.write32(GDRST, GRDOM_GUC);
        self.deadline = now.checked_add(RESET_NS).ok_or(MediaError::Timeout)?;
        self.phase = Phase::ResetGuc;
        Ok(false)
    }

    fn begin_release(&mut self, media: &impl MmioWindow, now: u64) -> Result<(), MediaError> {
        // Engine wells first, then the GT domain they depend on.
        for domain in domains_rev(self.requested) {
            media.write32(domain_registers(domain).0, KERNEL_SLEEP);
        }
        self.deadline = now.checked_add(WAKE_NS).ok_or(MediaError::Timeout)?;
        Ok(())
    }

    /// Every released domain's acknowledgement cleared within the bound.
    fn released(&mut self, media: &impl MmioWindow, now: u64) -> Result<bool, MediaError> {
        for domain in domains(self.requested) {
            if read(media, domain_registers(domain).1)? & 1 != 0 {
                return if now >= self.deadline {
                    Err(MediaError::Timeout)
                } else {
                    Ok(false)
                };
            }
        }
        self.requested = 0;
        Ok(true)
    }

    /// Record `error`, clear the GSC notification and release every wake this
    /// owner requested. GT0 state is never part of this path.
    fn fail(
        &mut self,
        media: &impl MmioWindow,
        error: MediaError,
        now: u64,
    ) -> Poll<Result<MediaFacts, MediaError>> {
        let error = match self.phase {
            Phase::Failing(original) => original,
            _ => error,
        };
        if self.gsc_prepared {
            let gs1 = media.read32(HECI2_H_GS1);
            if gs1 != u32::MAX {
                media.write32(HECI2_H_GS1, gs1 & !HECI_H_GS1_ER_PREP);
                self.gsc_prepared = false;
            }
        }
        if self.requested == 0 || matches!(self.phase, Phase::Failing(_)) {
            self.phase = Phase::Failed(error);
            return Poll::Ready(Err(error));
        }
        if self.begin_release(media, now).is_err() {
            self.phase = Phase::Failed(error);
            return Poll::Ready(Err(error));
        }
        self.phase = Phase::Failing(error);
        Poll::Pending
    }

    /// Synchronous teardown for a GT0 stop, park or suspend: write release
    /// for every outstanding request without waiting. A later incarnation
    /// waits for these acknowledgements to settle before requesting again.
    pub(crate) fn abandon<M: MmioWindow + ?Sized>(&mut self, bar: &M) {
        let media = MediaWindow::new(bar);
        if self.gsc_prepared {
            let gs1 = media.read32(HECI2_H_GS1);
            if gs1 != u32::MAX {
                media.write32(HECI2_H_GS1, gs1 & !HECI_H_GS1_ER_PREP);
            }
            self.gsc_prepared = false;
        }
        for domain in domains_rev(self.requested) {
            media.write32(domain_registers(domain).0, KERNEL_SLEEP);
        }
        self.requested = 0;
        self.phase = Phase::Stopped;
    }
}

/// xe_pat.c `xe->pat.idx[XE_CACHE_WB]` for METEORLAKE. GT0's MTL cache
/// policy publishes the same GGTT index (`intel_gpu_gt_hw`).
const XELPG_WB_INDEX: u8 = 3;
/// regs/xe_irq_regs.h GUC_SG_INTR_MASK; xe_guc.c::guc_enable_irq puts the
/// media GuC's GUC_INTR_GUC2HOST (bit 15) in the ENGINE0 half.
const GUC_SG_INTR_MASK: u64 = 0x1900e8;
const MEDIA_GUC2HOST: u32 = 1 << 15;

impl MediaGt {
    /// The cache proof for this incarnation: the xelpg PAT this owner wrote
    /// gives the shared GGTT write-back index the same meaning on GT1.
    pub(crate) fn cache_policy(&self) -> Option<crate::intel_gpu_gt_hw::CachePolicy> {
        (self.phase == Phase::Initialized).then_some(crate::intel_gpu_gt_hw::CachePolicy {
            platform: self.platform,
            ggtt_pat: XELPG_WB_INDEX,
            media: None,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaGucError {
    Gt(crate::intel_gpu_guc_gt::GtError),
    /// The shared GGTT refused the second-TLB registration.
    Ggtt(crate::intel_gpu_guc_boot::BootError),
    Unavailable,
    /// The idle media GuC sent an unsolicited CT message.
    Protocol,
    /// Stop could not be proven; firmware memory and the TLB hook stay held.
    Retained,
    State,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaGucState {
    Starting,
    /// Firmware authenticated and CT enabled through the media mailbox.
    Running,
    Stopping,
    /// GuC reset proven, CT/ADS/log memory freed, wake released.
    Stopped,
    Retained,
}

/// The standalone media GuC of one GT0 incarnation, run through the shared
/// bare `GuCGt` owner over the media GSI window and shared GGTT arena.
/// It registers as the arena's second GGTT TLB before firmware DMA and keeps
/// its GuC-to-host interrupt half masked: its CT is polled. No engine,
/// context, SLPC or HuC is admitted and no userspace GT is published.
pub(crate) struct MediaGuc<
    M: MmioWindow + Clone,
    A: crate::intel_gpu_guc_boot::BootAllocator + Clone,
> {
    gt: crate::intel_gpu_guc_gt::GuCGt<MediaGsi<M>, A>,
    allocator: A,
    registered: bool,
    state: MediaGucState,
    error: Option<MediaGucError>,
}

impl<M: MmioWindow + Clone, A: crate::intel_gpu_guc_boot::BootAllocator + Clone> core::fmt::Debug
    for MediaGuc<M, A>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MediaGuc")
            .field("state", &self.state)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<M: MmioWindow + Clone, A: crate::intel_gpu_guc_boot::BootAllocator + Clone> MediaGuc<M, A> {
    /// Stage and begin after `MediaGt` initialized this incarnation and
    /// released its own wake. `firmware` is GT0's MTL GuC image (xe_uc_fw.c
    /// GT_TYPE_ANY). On error nothing has been published: the staged owner
    /// is dropped and the arena hook is withdrawn.
    pub(crate) fn start(
        bar: M,
        allocator: A,
        firmware: &crate::intel_gpu_guc_firmware::GuCFirmware,
        config: crate::intel_gpu_guc_boot::BootConfig,
        media: &MediaGt,
        now: u64,
    ) -> Result<Self, MediaGucError> {
        let (Some(facts), Some(policy)) = (media.facts(), media.cache_policy()) else {
            return Err(MediaGucError::State);
        };
        let mut gt = crate::intel_gpu_guc_gt::GuCGt::stage_media(
            MediaGsi::new(bar.clone()),
            allocator.clone(),
            firmware,
            config,
            facts.ip,
            policy,
        )
        .map_err(MediaGucError::Gt)?;
        let mask = bar.read32(GUC_SG_INTR_MASK);
        if mask == u32::MAX {
            return Err(MediaGucError::Unavailable);
        }
        bar.write32(GUC_SG_INTR_MASK, mask | MEDIA_GUC2HOST);
        if bar.read32(GUC_SG_INTR_MASK) & MEDIA_GUC2HOST == 0 {
            return Err(MediaGucError::Unavailable);
        }
        let mut hook = allocator;
        hook.register_media_guc_tlb(true)
            .map_err(MediaGucError::Ggtt)?;
        if let Err(error) = gt.begin(now) {
            // Still Staged: no wake request or firmware address was written.
            let _ = hook.register_media_guc_tlb(false);
            return Err(MediaGucError::Gt(error));
        }
        Ok(Self {
            gt,
            allocator: hook,
            registered: true,
            state: MediaGucState::Starting,
            error: None,
        })
    }

    pub(crate) fn state(&self) -> MediaGucState {
        self.state
    }

    /// The first refusal of this owner, if any.
    pub(crate) fn error(&self) -> Option<MediaGucError> {
        self.error
    }

    /// Advance start, the idle CT drain or stop by one bounded step.
    pub(crate) fn poll(
        &mut self,
        now: u64,
        current: impl FnMut() -> bool,
    ) -> Poll<Result<MediaGucState, MediaGucError>> {
        use crate::intel_gpu_guc_gt::GtState;
        match self.state {
            MediaGucState::Stopped | MediaGucState::Retained => {
                return Poll::Ready(Ok(self.state));
            }
            _ => {}
        }
        let polled = self.gt.poll_with_access(now, current);
        let result = match (self.state, polled) {
            (_, Poll::Pending) => return Poll::Pending,
            (MediaGucState::Stopping, Poll::Ready(Ok(GtState::Stopped))) => {
                if self.allocator.register_media_guc_tlb(false).is_err() {
                    self.state = MediaGucState::Retained;
                    return Poll::Ready(Err(MediaGucError::Retained));
                }
                self.registered = false;
                self.state = MediaGucState::Stopped;
                return Poll::Ready(Ok(self.state));
            }
            (MediaGucState::Stopping, Poll::Ready(Ok(_))) => return Poll::Pending,
            (MediaGucState::Stopping, Poll::Ready(Err(_))) => {
                self.state = MediaGucState::Retained;
                return Poll::Ready(Err(MediaGucError::Retained));
            }
            (MediaGucState::Starting, Poll::Ready(Ok(GtState::Ready))) => {
                // xe_guc_hwconfig_init skips non-GT0 GuCs: enable CT directly.
                self.gt.begin_ct(now).map_err(MediaGucError::Gt)
            }
            (MediaGucState::Starting, Poll::Ready(Ok(GtState::CtReady)))
            | (MediaGucState::Running, Poll::Ready(Ok(GtState::CtReady))) => {
                self.state = MediaGucState::Running;
                match self.gt.receive() {
                    Ok(None) => return Poll::Ready(Ok(self.state)),
                    Ok(Some(_)) => Err(MediaGucError::Protocol),
                    Err(error) => Err(MediaGucError::Gt(error)),
                }
            }
            (MediaGucState::Starting, Poll::Ready(Ok(_))) => return Poll::Pending,
            (_, Poll::Ready(Ok(_))) => Err(MediaGucError::State),
            (_, Poll::Ready(Err(error))) => Err(MediaGucError::Gt(error)),
        };
        match result {
            Ok(()) => Poll::Pending,
            Err(error) => {
                self.error.get_or_insert(error);
                self.begin_stop(now);
                Poll::Ready(Err(error))
            }
        }
    }

    /// Begin a verified stop: GuC reset, DMA idle, CT/ADS/log release and
    /// media wake release, as the shared GuCGt stop path proves for GT0.
    pub(crate) fn begin_stop(&mut self, now: u64) {
        if matches!(
            self.state,
            MediaGucState::Stopping | MediaGucState::Stopped | MediaGucState::Retained
        ) {
            return;
        }
        if self.gt.state() == crate::intel_gpu_guc_gt::GtState::Stopped {
            self.state = MediaGucState::Stopping;
            return;
        }
        self.state = match self.gt.begin_stop(now) {
            Ok(()) => MediaGucState::Stopping,
            Err(error) => {
                self.error.get_or_insert(MediaGucError::Gt(error));
                MediaGucState::Retained
            }
        };
    }

    /// Stop and wait without holding any IRQ lock. Cancellation leaves the
    /// owner, its memory and its TLB registration retained.
    pub(crate) async fn stop(&mut self, mut current: impl FnMut() -> bool) -> MediaGucState {
        self.begin_stop(narf_time::monotonic_ns());
        loop {
            match self.poll(narf_time::monotonic_ns(), &mut current) {
                Poll::Ready(_) if self.state != MediaGucState::Stopping => return self.state,
                _ => {}
            }
            narf_scheduler::yield_now().await;
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
        }
    }

    /// Whether this owner may be dropped: only after a proven stop, or before
    /// any wake/firmware publication (`start` never returns such an owner).
    pub(crate) fn reclaimable(&self) -> bool {
        self.state == MediaGucState::Stopped && !self.registered
    }
}

/// Outcome of retiring the media owners before a GT0 transition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Retire {
    Done,
    Pending,
    /// The media GuC's stop is unproven; its shared-GGTT memory stays held.
    Retained,
}

/// Abandon the media GT owner (releasing its own wake requests) and advance
/// a verified media GuC stop. With no media owner, as when
/// `narf.intel.media_gt=1` is absent, this is `Done` with no MMIO access.
pub(crate) fn retire<B, M, A>(
    media: &mut Option<MediaGt>,
    guc: &mut Option<MediaGuc<M, A>>,
    bar: &B,
    now: u64,
    current: impl FnMut() -> bool,
) -> Retire
where
    B: MmioWindow + ?Sized,
    M: MmioWindow + Clone,
    A: crate::intel_gpu_guc_boot::BootAllocator + Clone,
{
    if let Some(mut owner) = media.take() {
        owner.abandon(bar);
    }
    let Some(owner) = guc.as_mut() else {
        return Retire::Done;
    };
    owner.begin_stop(now);
    let _ = owner.poll(now, current);
    match owner.state() {
        MediaGucState::Stopped if owner.reclaimable() => {
            *guc = None;
            Retire::Done
        }
        MediaGucState::Retained => Retire::Retained,
        _ => Retire::Pending,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_media_gt_tests.rs"]
mod tests;
