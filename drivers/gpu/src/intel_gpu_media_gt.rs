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
//!   GSCCS0 without available GSC firmware; with `narf.intel.gsc=1` and an
//!   available image `MediaGuc::schedule_gsccs` adds it to the scheduler.
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
//! and its polled CT and schedules the fused VCS/VECS engines:
//! - xe_hw_engine.c builds GT1's engine list from the media fuses; HWCONFIG is
//!   GT0-only (xe_guc_hwconfig_init), so the ADS comes from that list
//!   (xe_guc_ads.c mapping/enable masks, golden LRCs, hwe->reg_sr saves).
//! - Engine setup holds every VDBOX/VEBOX well: oam_mmio_trg_vcs/vecs
//!   NONPRIV grants (xe_reg_whitelist.c), xe_hw_engine_enable_ring.
//! - Default LRCs follow xe_gt_record_default_lrcs with the empty media
//!   13.00 WA job; video rings follow __emit_job_gen12_video with AUX_INV at
//!   the media GSI offset (emit_aux_table_inv adds gt->mmio.adj_offset).
//! - Once submission is enabled the shared GGTT invalidates GT1's TLB
//!   through the media CT (xe_guc_tlb_inval.c::send_tlb_inval_ggtt).
//! - Every engine executes and retires a private PPGTT job before
//!   `MediaGuc::publication` exposes GT1.
//! - Power follows Linux per GT: xe_gt_idle_enable_pg (`powergate_enable`)
//!   and xe_guc_pc_start on the media GuC (GT1's MTL_MEDIAP_STATE_CAP /
//!   MTL_MPE_FREQUENCY limits, bounds, GUCRC firmware control, strategy,
//!   profile) before publication. Every stop first runs
//!   xe_guc_pc_gucrc_disable, xe_gt_idle_disable_c6 and
//!   xe_gt_idle_disable_pg through GT1's window.
//! - xe_gt_topology.c::xe_gt_topology_init also runs on GT1, so probe reads
//!   GT1's own GSI-translated fuse mirrors (`MediaTopology`) for
//!   xe_query.c::query_gt_topology; query_engine_cycles samples a published
//!   VCS/VECS RING_TIMESTAMP at its absolute engine base under GT1's wake
//!   (`MediaGuc::engine_cycles`).

use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_engine::{Engine, EngineSet};
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_gt_hw::{MTL_GLOBAL_MOCS, MTL_L3CC};
use crate::intel_gpu_topology::{xelpg_l3_bank_mask, MIRROR_FUSE3, XEHP_FUSE4};
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

/// regs/xe_gt_regs.h RC_CONTROL, RC_STATE and POWERGATE_ENABLE. All lie below
/// MEDIA_GT_GSI_LENGTH, so GT1's copies are at its GSI base (`gsi`).
pub(crate) const RC_CONTROL: u64 = 0xa090;
pub(crate) const RC_STATE: u64 = 0xa094;
pub(crate) const POWERGATE_ENABLE: u64 = 0xa210;
const MEDIA_POWERGATE_ENABLE: u32 = 1 << 1;

/// xe_gt_idle.c::xe_gt_idle_enable_pg for this GT1 profile (media 13.00):
/// MEDIA_POWERGATE_ENABLE with any VCS/VECS, plus VDN_HCP_POWERGATE_ENABLE(n)
/// (bit 3 + 2n) and VDN_MFXVDENC_POWERGATE_ENABLE(n) (bit 4 + 2n) for each
/// present VCSn. A media GT gets no RENDER_POWERGATE_ENABLE
/// (xe_gt_is_main_type), media 13.00 is outside the 11.00..12.55 sampler
/// range, and Wa_14020316580 is MEDIA_VERSION(1301) only.
pub(crate) fn powergate_enable(engines: EngineSet) -> u32 {
    const VCS: [Engine; 8] = [
        Engine::Vcs0,
        Engine::Vcs1,
        Engine::Vcs2,
        Engine::Vcs3,
        Engine::Vcs4,
        Engine::Vcs5,
        Engine::Vcs6,
        Engine::Vcs7,
    ];
    let mut value = 0;
    if engines.iter().any(Engine::is_media) {
        value |= MEDIA_POWERGATE_ENABLE;
    }
    for (n, engine) in VCS.into_iter().enumerate() {
        if engines.contains(engine) {
            value |= 0b11 << (3 + 2 * n);
        }
    }
    value
}

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

/// The media GT's own topology fuses, as xe_gt_topology.c::
/// xe_gt_topology_init reads them through GT1's GSI-adjusted MMIO under GT
/// forcewake (gt_init_with_gt_forcewake runs it for the media GT too). At
/// graphics 12.70-12.74 get_num_dss_regs selects one geometry and one compute
/// register, and load_eu_mask reads XELP_EU_ENABLE without inversion as SIMD8
/// (one fuse bit is two EUs). load_l3_bank_mask runs too, and
/// xe_gt_topology_report_l3 reports a media GT's L3 bank mask before media
/// version 30. Linux keeps whatever GT1 reports, including empty masks;
/// nothing here is inferred from GT0.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct MediaTopology {
    /// XELP_GT_GEOMETRY_DSS_ENABLE (0x913c + GSI).
    pub geometry: u32,
    /// XEHP_GT_COMPUTE_DSS_ENABLE (0x9144 + GSI).
    pub compute: u32,
    /// SIMD8 EU mask per DSS expanded from XELP_EU_ENABLE (0x9134 + GSI).
    pub eu_per_dss: u16,
    /// xe_l3_bank_mask_t (XE_MAX_L3_BANK_MASK_BITS = 64) from MIRROR_FUSE3
    /// (0x9118 + GSI) and XEHP_FUSE4 (0x9114 + GSI), by the graphics 12.70
    /// rule GT0 also uses (`intel_gpu_topology::xelpg_l3_bank_mask`).
    pub l3_bank: u64,
}

/// regs/xe_gt_regs.h topology fuse mirrors (pre-GSI offsets).
const GEOMETRY_DSS_ENABLE: u64 = 0x913c;
const COMPUTE_DSS_ENABLE: u64 = 0x9144;
const EU_ENABLE: u64 = 0x9134;
/// regs/xe_gt_regs.h `MTL_MIRROR_TARGET_WP1` (`0x0c60`, GSI-translated to
/// `0x380c60` on GT1); bits [8:0] (`MTL_CAGF_MASK`) carry CAGF in 16.67 MHz units.
pub(crate) const MTL_MIRROR_TARGET_WP1: u64 = 0x0c60;
/// regs/xe_gt_regs.h `MTL_MEDIA_MC6` (`0x138048`, above `MEDIA_GT_GSI_LENGTH`
/// in the PCU mirror range); 32-bit residency counter in 1.28 us (1280 ns) units.
pub(crate) const MTL_MEDIA_MC6: u64 = 0x138048;

impl MediaTopology {
    /// Two identical samples of GT1's fuse mirrors under GT1 wake. As for
    /// GT0 (`GtTopology::read`), a fully populated DSS mask may read all
    /// ones, so the EU register's reserved bits 31:8 (XELP_EU_MASK is 7:0)
    /// identify unavailable MMIO instead.
    pub(crate) fn read(media: &impl MmioWindow) -> Result<Self, MediaError> {
        let sample = || {
            (
                media.read32(GEOMETRY_DSS_ENABLE),
                media.read32(COMPUTE_DSS_ENABLE),
                media.read32(EU_ENABLE),
                media.read32(MIRROR_FUSE3),
                media.read32(XEHP_FUSE4),
            )
        };
        let first = sample();
        if first != sample() {
            return Err(MediaError::Unstable);
        }
        let (geometry, compute, raw_eu, fuse3, fuse4) = first;
        if raw_eu & !0xff != 0 {
            return Err(MediaError::Unavailable);
        }
        let eu_per_dss = (0..8)
            .filter(|bit| raw_eu & 1 << bit != 0)
            .fold(0u16, |mask, bit| mask | 3 << (bit * 2));
        Ok(Self {
            geometry,
            compute,
            eu_per_dss,
            l3_bank: xelpg_l3_bank_mask(fuse3, fuse4),
        })
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
    /// GT1's own topology fuses (DRM_XE_DEVICE_QUERY_GT_TOPOLOGY gt_id 1).
    pub topology: MediaTopology,
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
/// media_xelpmp VCS/VECS mask. GSCCS0 is not part of this published
/// inventory; the media GuC schedules it separately (`schedule_gsccs`).
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

/// Forcewake domain bitmap: bit0 GT, bits1-8 VDBOX0-7, bits9-12 VEBOX0-3,
/// bit13 GSC. Linux numbers these XE_FW_DOMAIN_ID_GT, _MEDIA_VDBOX0..7,
/// _MEDIA_VEBOX0..3 and _GSC (enum value 15: the media GT has no RENDER or
/// MEDIA domain, so this bitmap packs them); xe_force_wake_init_engines
/// gives GSCCS0 its own FORCEWAKE_GSC / FORCEWAKE_ACK_GSC domain.
pub(crate) fn engine_domains(engines: EngineSet) -> u16 {
    engines.iter().fold(0, |domains, engine| {
        if engine.is_gsc() {
            return domains | 1 << GSC_DOMAIN;
        }
        let first = if engine.is_decode() { 1 } else { 9 };
        domains | 1 << (first + engine.physical_instance())
    })
}

/// The GSC forcewake domain's bit in `engine_domains`.
pub(crate) const GSC_DOMAIN: u32 = 13;

/// xe_gsc.c::xe_gsc_wa_14015076503 applies only while GSC firmware reports
/// HECI1_FWSTS1_INIT_COMPLETE. The HECI1 block is absolute (above the GSI
/// range), so either a BAR or a media GSI window reads the same register.
pub(crate) fn gsc_firmware_loaded(
    mmio: &impl MmioWindow,
) -> Result<bool, crate::intel_gpu_guc_gt::GtError> {
    let status = mmio.read32(HECI1_FWSTS1);
    if status == u32::MAX {
        return Err(crate::intel_gpu_guc_gt::GtError::Unavailable);
    }
    Ok(status & HECI1_FWSTS1_INIT_COMPLETE != 0)
}

/// FORCEWAKE request and acknowledgement registers (pre-GSI) of a domain.
pub(crate) const fn domain_registers(domain: u32) -> (u64, u64) {
    match domain {
        0 => (FORCEWAKE_GT, FORCEWAKE_ACK_GT_MTL),
        // regs/xe_gt_regs.h FORCEWAKE_GSC / FORCEWAKE_ACK_GSC.
        GSC_DOMAIN => (0xa618, 0xdf8),
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
    (0..=GSC_DOMAIN).filter(move |domain| mask & 1 << domain != 0)
}

fn domains_rev(mask: u16) -> impl Iterator<Item = u32> {
    (0..=GSC_DOMAIN)
        .rev()
        .filter(move |domain| mask & 1 << domain != 0)
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
    topology: MediaTopology,
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
            topology: MediaTopology::default(),
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
            topology: self.topology,
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

    /// The same fixture with GT1 topology fuses already observed.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn with_topology_for_test(mut self, topology: MediaTopology) -> Self {
        self.topology = topology;
        self
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
                // gt_init_with_gt_forcewake -> xe_gt_topology_init on GT1.
                self.topology = MediaTopology::read(media)?;
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
    /// The shared GGTT refused the second-TLB registration or its mode.
    Ggtt(crate::intel_gpu_guc_boot::BootError),
    /// A VDBOX/VEBOX forcewake domain could not be taken for scheduling.
    Wells(MediaError),
    /// A default-LRC capture or private PPGTT probe did not retire cleanly.
    Probe,
    /// The media GuC's SLPC did not reach RUNNING with acknowledged bounds.
    /// xe_uc.c::xe_uc_load_hw fails the uC load on a xe_guc_pc_start error,
    /// so GT1 stops instead of publishing without power management.
    Slpc,
    Unavailable,
    /// Stop could not be proven; firmware memory and the TLB hook stay held.
    Retained,
    State,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaGucState {
    Starting,
    /// Every published VCS/VECS executed and retired a private PPGTT job;
    /// GT1 may be exposed to userspace.
    Running,
    Stopping,
    /// GuC reset and (with a scheduler) media GRDOM_FULL proven, CT/ADS/
    /// log/LRC memory freed, GT and engine wake released.
    Stopped,
    Retained,
}

/// Startup progress of the media GuC beneath `MediaGucState::Starting`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Step {
    /// First firmware boot with the minimal ADS.
    Boot,
    /// An earlier owner's VDBOX/VEBOX sleep acknowledgement is settling.
    SettleWells,
    /// Engine wells requested; waiting for every acknowledgement.
    WakeWells,
    /// Engine policy, ring enable, populated-ADS reload and CT enable.
    Scheduling,
    /// Default LRC capture on every engine.
    Priming,
    /// One private PPGTT job per engine.
    Probing,
    /// Powergating enabled; the media GuC's SLPC start must reach RUNNING.
    Power,
    /// A staged HuC reaches RUNNING or unavailable before publication.
    Huc,
    Published,
}

/// What the media GuC publishes once every engine executed (UAPI gt_id 1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct MediaPublication {
    pub(crate) epoch: u64,
    pub(crate) engines: EngineSet,
    pub(crate) gmd: u32,
    pub(crate) reference_clock: u32,
    pub(crate) topology: MediaTopology,
}

/// The standalone media GuC of one GT0 incarnation, run through the shared
/// `GuCGt` owner over the media GSI window and shared GGTT arena. It
/// registers as the arena's second GGTT TLB before firmware DMA, keeps its
/// GuC-to-host interrupt half masked (its CT is polled), then schedules the
/// fused VCS/VECS engines. After the default LRCs and engine probes it enables
/// GT1 powergating and starts the media GuC's SLPC, which hands media C6 to
/// firmware; GT1 publishes only once SLPC is RUNNING, since xe_uc_load_hw
/// fails on a xe_guc_pc_start error. With a staged HuC it then authenticates
/// the HuC, as xe_uc_load_hw does after xe_guc_pc_start; a HuC failure never
/// fails GT1.
pub(crate) struct MediaGuc<
    M: MmioWindow + Clone,
    A: crate::intel_gpu_guc_boot::BootAllocator + Clone,
> {
    gt: crate::intel_gpu_guc_gt::GuCGt<MediaGsi<M>, A>,
    media: MediaGsi<M>,
    allocator: A,
    registered: bool,
    /// GGTT invalidation runs through the media CT (submission enabled).
    submission: bool,
    state: MediaGucState,
    step: Step,
    error: Option<MediaGucError>,
    /// Published VCS/VECS (never GSCCS0).
    engines: EngineSet,
    /// GSCCS0 is scheduled beside them (`schedule_gsccs`).
    gsc: bool,
    /// The GSC kernel queue's newest job (`GscQueue`).
    gsc_job: Option<alloc::sync::Arc<crate::intel_gpu_fence::CompletionFence>>,
    gmd: u32,
    topology: MediaTopology,
    /// VDBOX/VEBOX domains whose kernel wake request this owner wrote.
    wells: u16,
    deadline: u64,
    defaults: Option<alloc::sync::Arc<crate::intel_gpu_fence::CompletionFence>>,
    probes: alloc::vec::Vec<crate::intel_gpu_exec::PpgttProbeSubmission>,
    published: Option<MediaPublication>,
}

impl<M: MmioWindow + Clone, A: crate::intel_gpu_guc_boot::BootAllocator + Clone> core::fmt::Debug
    for MediaGuc<M, A>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MediaGuc")
            .field("state", &self.state)
            .field("step", &self.step)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<M: MmioWindow + Clone, A: crate::intel_gpu_guc_boot::BootAllocator + Clone> MediaGuc<M, A> {
    /// Stage and begin after `MediaGt` initialized this incarnation and
    /// released its own wake. `firmware` is GT0's MTL GuC image (xe_uc_fw.c
    /// GT_TYPE_ANY). `huc` is the media GT's HuC image and whether this
    /// owner may adopt an authentication that survived an earlier one
    /// (`intel_gpu_huc::Upload::adopt`). On error nothing has been published:
    /// the staged owner is dropped and the arena hook is withdrawn.
    pub(crate) fn start(
        bar: M,
        allocator: A,
        firmware: &crate::intel_gpu_guc_firmware::GuCFirmware,
        huc: Option<(&crate::intel_gpu_huc::Firmware, bool)>,
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
            huc,
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
            media: MediaGsi::new(bar),
            allocator: hook,
            registered: true,
            submission: false,
            state: MediaGucState::Starting,
            step: Step::Boot,
            error: None,
            engines: facts.engines,
            gsc: false,
            gsc_job: None,
            gmd: facts.ip.gmd,
            topology: facts.topology,
            wells: 0,
            deadline: 0,
            defaults: None,
            probes: alloc::vec::Vec::new(),
            published: None,
        })
    }

    pub(crate) fn state(&self) -> MediaGucState {
        self.state
    }

    /// `narf.intel.gsc=1`: bracket the stop's media GRDOM_FULL with
    /// Wa_14015076503 while GSC firmware reports loaded, and schedule beside
    /// it (`GuCGt::honour_gsc_reset_workaround`). Call before scheduling.
    pub(crate) fn honour_gsc_reset_workaround(&mut self) -> Result<(), MediaGucError> {
        self.gt
            .honour_gsc_reset_workaround()
            .map_err(MediaGucError::Gt)
    }

    /// `narf.intel.gsc=1` with available GSC firmware: schedule GSCCS0 beside
    /// the published VCS/VECS, before any engine well is requested.
    /// xe_hw_engine.c::check_gsc_availability keeps GSCCS0 in GT1's engine
    /// mask only then; it takes the XE_FW_GSC domain (xe_force_wake_init_engines),
    /// joins the ADS, records its default LRC, and stays out of every
    /// publication, query and placement (xe_hw_engine_is_reserved).
    pub(crate) fn schedule_gsccs(&mut self) -> Result<(), MediaGucError> {
        if self.state != MediaGucState::Starting || self.step != Step::Boot {
            return Err(MediaGucError::State);
        }
        self.gsc = true;
        Ok(())
    }

    /// GSCCS0 is part of this owner's scheduler.
    pub(crate) fn gsccs_scheduled(&self) -> bool {
        self.gsc
    }

    /// Every engine the media GuC schedules: the published VCS/VECS, plus
    /// GSCCS0 when `schedule_gsccs` admitted it.
    fn scheduled(&self) -> EngineSet {
        if self.gsc {
            EngineSet::from_bits(self.engines.bits() | EngineSet::of(&[Engine::Gsccs0]).bits())
        } else {
            self.engines
        }
    }

    /// One GSC kernel job on GSCCS0 while GT1 runs (`gsc->q`). The worker
    /// polls its fence; it retires only after deregistration, as every NARF
    /// kernel job does.
    pub(crate) fn submit_gsc(
        &mut self,
        now: u64,
        commands: &[u32],
    ) -> Result<
        alloc::sync::Arc<crate::intel_gpu_fence::CompletionFence>,
        crate::intel_gpu_guc_gt::GtError,
    > {
        if !self.gsc || self.state != MediaGucState::Running {
            return Err(crate::intel_gpu_guc_gt::GtError::State);
        }
        let result = self.gt.submit_gsc(now, commands);
        if self.gt.state() == crate::intel_gpu_guc_gt::GtState::Lost {
            self.error.get_or_insert(MediaGucError::Gt(
                result
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(crate::intel_gpu_guc_gt::GtError::State),
            ));
            self.begin_stop(now);
        }
        result.map(|(_, fence)| fence)
    }

    /// The media HuC object (`huc->fw.bo`) for GSC authentication.
    pub(crate) fn huc_object(&self) -> Option<(u64, u32)> {
        self.gt.huc_object()
    }

    /// The GSC rejected the HuC the media GuC authenticated: huc->fw becomes
    /// LOAD_FAIL (xe_huc_auth), so query7 type1 answers ENODEV.
    pub(crate) fn huc_gsc_failed(&mut self) {
        self.gt.invalidate_huc();
    }

    /// A handle to the shared GGTT arena this media GuC lives in.
    pub(crate) fn allocator(&self) -> A {
        self.allocator.clone()
    }

    /// The first refusal of this owner, if any.
    pub(crate) fn error(&self) -> Option<MediaGucError> {
        self.error
    }

    /// GT1 as userspace may see it: only while Running, after every engine
    /// executed and retired its private PPGTT job.
    pub(crate) fn publication(&self) -> Option<MediaPublication> {
        (self.state == MediaGucState::Running)
            .then_some(self.published)
            .flatten()
    }

    /// The running HuC release (versions.found[XE_UC_FW_VER_RELEASE]) while
    /// GT1 is published, read under GT1's epoch, current access and wake
    /// with a current HUC_KERNEL_LOAD_INFO success bit. Passive: it never
    /// loads, authenticates or wakes anything.
    pub(crate) fn huc_version(&self, current: impl FnMut() -> bool) -> Option<(u8, u8, u8)> {
        let publication = self.publication()?;
        self.gt.huc_version(publication.epoch, current)
    }

    /// The staged HuC's terminal outcome without MMIO: `Some(true)` RUNNING,
    /// `Some(false)` unavailable, `None` while pending or without a HuC.
    pub(crate) fn huc_outcome(&self) -> Option<bool> {
        self.gt.huc_outcome()
    }

    /// GT1's confirmed SLPC limits, frequency range and power profile while
    /// published, without MMIO. Absent during an update or after a later
    /// SLPC failure, which, as on GT0, leaves the published engines running.
    pub(crate) fn slpc_status(&self) -> Option<crate::intel_gpu_slpc::Status> {
        self.publication()?;
        self.gt.slpc_status()
    }

    /// GT1's accumulated MC6 residency in milliseconds (`MTL_MEDIA_MC6`,
    /// `0x138048`, 1.28 us units) while GT1 is published.
    pub(crate) fn mc6_residency_ms(&self) -> Option<u64> {
        self.publication()?;
        let raw = self.media.read32(MTL_MEDIA_MC6);
        (raw != u32::MAX).then_some((u64::from(raw) * 1280) / 1_000_000)
    }

    /// GT1's actual CAGF operating frequency in MHz (`MTL_MIRROR_TARGET_WP1`,
    /// `0x0c60` + GSI = `0x380c60`, bits [8:0] in 16.67 MHz units) while GT1
    /// is published.
    pub(crate) fn act_freq_mhz(&self) -> Option<u32> {
        self.publication()?;
        let raw = self.media.read32(MTL_MIRROR_TARGET_WP1);
        (raw != u32::MAX).then_some(crate::intel_gpu_slpc::decode(raw & 0x1ff))
    }

    /// Advance start, scheduling or stop by one bounded step.
    pub(crate) fn poll(
        &mut self,
        now: u64,
        mut current: impl FnMut() -> bool,
    ) -> Poll<Result<MediaGucState, MediaGucError>> {
        use crate::intel_gpu_guc_gt::GtState;
        match self.state {
            MediaGucState::Stopped | MediaGucState::Retained => {
                return Poll::Ready(Ok(self.state));
            }
            MediaGucState::Stopping => {
                return match self.gt.poll_with_access(now, &mut current) {
                    Poll::Pending | Poll::Ready(Ok(_)) if self.gt.state() != GtState::Stopped => {
                        Poll::Pending
                    }
                    Poll::Ready(Err(_)) => {
                        self.state = MediaGucState::Retained;
                        Poll::Ready(Err(MediaGucError::Retained))
                    }
                    _ => self.finish_stop(),
                };
            }
            MediaGucState::Starting | MediaGucState::Running => {}
        }
        match self.advance(now, &mut current) {
            Ok(true) => Poll::Ready(Ok(self.state)),
            Ok(false) => Poll::Pending,
            Err(error) => {
                self.error.get_or_insert(error);
                self.begin_stop(now);
                Poll::Ready(Err(error))
            }
        }
    }

    /// GuCGt proved its stop and released GT wake: release the engine wells
    /// (a later owner settles their acknowledgements), then the arena hook.
    fn finish_stop(&mut self) -> Poll<Result<MediaGucState, MediaGucError>> {
        for domain in domains_rev(self.wells) {
            self.media.write32(domain_registers(domain).0, KERNEL_SLEEP);
        }
        self.wells = 0;
        if self.allocator.register_media_guc_tlb(false).is_err() {
            self.state = MediaGucState::Retained;
            return Poll::Ready(Err(MediaGucError::Retained));
        }
        self.registered = false;
        self.submission = false;
        self.state = MediaGucState::Stopped;
        Poll::Ready(Ok(self.state))
    }

    fn advance(
        &mut self,
        now: u64,
        current: &mut impl FnMut() -> bool,
    ) -> Result<bool, MediaGucError> {
        use crate::intel_gpu_guc_gt::GtState;
        let polled = match self.gt.poll_with_access(now, &mut *current) {
            Poll::Pending => return Ok(false),
            Poll::Ready(result) => result.map_err(MediaGucError::Gt)?,
        };
        match (self.step, polled) {
            (Step::Boot, GtState::Ready) => {
                // xe_guc_hwconfig_init skips non-GT0 GuCs: no HWCONFIG.
                self.deadline = now.checked_add(WAKE_NS).ok_or(MediaGucError::State)?;
                self.step = Step::SettleWells;
                self.request_wells(now)
            }
            (Step::SettleWells, GtState::Ready) => self.request_wells(now),
            (Step::WakeWells, GtState::Ready) => {
                let scheduled = self.scheduled();
                let mask = engine_domains(scheduled);
                for domain in domains(mask) {
                    if read(&self.media, domain_registers(domain).1)
                        .map_err(MediaGucError::Wells)?
                        & 1
                        == 0
                    {
                        return if now >= self.deadline {
                            Err(MediaGucError::Wells(MediaError::Timeout))
                        } else {
                            Ok(false)
                        };
                    }
                }
                self.gt
                    .begin_media_scheduling(scheduled, mask)
                    .map_err(MediaGucError::Gt)?;
                self.step = Step::Scheduling;
                Ok(false)
            }
            (Step::Scheduling, GtState::Ready) => {
                self.gt.begin_ct(now).map_err(MediaGucError::Gt)?;
                Ok(false)
            }
            (Step::Scheduling, GtState::SchedulingReady) => {
                // Submission is enabled: GGTT invalidation now runs through
                // this CT (xe_guc_tlb_inval.c::send_tlb_inval_ggtt).
                self.allocator
                    .media_guc_submission(true)
                    .map_err(MediaGucError::Ggtt)?;
                self.submission = true;
                self.defaults = Some(
                    self.gt
                        .begin_media_context_defaults(now)
                        .map_err(MediaGucError::Gt)?,
                );
                self.step = Step::Priming;
                Ok(false)
            }
            (Step::Priming, GtState::SchedulingReady) => {
                match self.defaults.as_ref().and_then(|fence| fence.result()) {
                    None => return Ok(false),
                    Some(Ok(())) => {}
                    Some(Err(_)) => return Err(MediaGucError::Probe),
                }
                self.defaults = None;
                for engine in self.engines.iter() {
                    let probe = self
                        .gt
                        .submit_ppgtt_probe_on(now, engine)
                        .map_err(MediaGucError::Gt)?;
                    self.probes.push(probe);
                }
                self.step = Step::Probing;
                Ok(false)
            }
            (Step::Probing, GtState::SchedulingReady) => {
                for probe in &self.probes {
                    match probe.completion.result() {
                        None => return Ok(false),
                        Some(Ok(())) => {}
                        Some(Err(_)) => return Err(MediaGucError::Probe),
                    }
                }
                // Every fence signals only after deregistration and the final
                // TLB acknowledgement: each job fully retired. Its private
                // store must also have landed through its own PPGTT.
                if self
                    .probes
                    .iter()
                    .any(|probe| probe.result.verify().is_err())
                    || !self.gt.idle()
                {
                    return Err(MediaGucError::Probe);
                }
                self.probes.clear();
                // xe_uc_load_hw: xe_guc_pc_start follows the default LRCs.
                self.gt.begin_media_power(now).map_err(MediaGucError::Gt)?;
                self.step = Step::Power;
                Ok(false)
            }
            (Step::Power, GtState::SchedulingReady) => {
                use crate::intel_gpu_slpc::SlpcState;
                match self.gt.slpc() {
                    SlpcState::Running => {
                        self.step = Step::Huc;
                        self.huc_then_publish(now)
                    }
                    SlpcState::Off | SlpcState::Unavailable => Err(MediaGucError::Slpc),
                    SlpcState::Resetting { .. } | SlpcState::Updating => Ok(false),
                }
            }
            (Step::Huc, GtState::SchedulingReady) => self.huc_then_publish(now),
            (Step::Published, GtState::SchedulingReady) => Ok(true),
            (
                Step::Boot | Step::SettleWells | Step::WakeWells | Step::Scheduling,
                GtState::Waking
                | GtState::Booting
                | GtState::PreparingScheduling
                | GtState::StartingScheduling
                | GtState::EnablingCt,
            ) => Ok(false),
            _ => Err(MediaGucError::State),
        }
    }

    /// xe_uc.c::xe_uc_load_hw: xe_huc_auth(XE_HUC_AUTH_VIA_GUC) follows the
    /// default LRCs, and "We don't fail the driver load if HuC fails to
    /// auth": rejection or a status timeout leaves the HuC unavailable and
    /// GT1 publishes anyway. Without a staged HuC this publishes at once.
    fn huc_then_publish(&mut self, now: u64) -> Result<bool, MediaGucError> {
        if !self.gt.prepare_huc(now).map_err(MediaGucError::Gt)? {
            return Ok(false);
        }
        let epoch = self.gt.user_epoch().ok_or(MediaGucError::State)?;
        let reference_clock = self.gt.media_reference_clock().map_err(MediaGucError::Gt)?;
        self.published = Some(MediaPublication {
            epoch,
            engines: self.engines,
            gmd: self.gmd,
            reference_clock,
            topology: self.topology,
        });
        self.step = Step::Published;
        self.state = MediaGucState::Running;
        Ok(true)
    }

    /// Take every present engine's VDBOX/VEBOX domain, after any sleep
    /// acknowledgement of an earlier owner settled (xe_force_wake.c bounds).
    fn request_wells(&mut self, now: u64) -> Result<bool, MediaGucError> {
        let mask = engine_domains(self.scheduled());
        for domain in domains(mask) {
            let (request, ack) = domain_registers(domain);
            if read(&self.media, request).map_err(MediaGucError::Wells)? & 1 != 0 {
                return Err(MediaGucError::Wells(MediaError::Busy));
            }
            if read(&self.media, ack).map_err(MediaGucError::Wells)? & 1 != 0 {
                return if now >= self.deadline {
                    Err(MediaGucError::Wells(MediaError::Timeout))
                } else {
                    Ok(false)
                };
            }
        }
        for domain in domains(mask) {
            self.media.write32(domain_registers(domain).0, KERNEL_WAKE);
            self.wells |= 1 << domain;
        }
        for domain in domains(mask) {
            let _ = self.media.read32(domain_registers(domain).0); // posting read
        }
        self.deadline = now.checked_add(WAKE_NS).ok_or(MediaGucError::State)?;
        self.step = Step::WakeWells;
        Ok(false)
    }

    /// Queue an untrusted user batch on a published VCS/VECS. The context's
    /// epoch is GT1's; GT0's epoch never admits it.
    pub(crate) fn submit_user(
        &mut self,
        now: u64,
        context: alloc::sync::Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: Option<&crate::intel_gpu_user::UserOutput<'_>>,
    ) -> Result<
        (
            u16,
            alloc::sync::Arc<crate::intel_gpu_fence::CompletionFence>,
        ),
        crate::intel_gpu_guc_gt::GtError,
    > {
        let publication = self
            .publication()
            .ok_or(crate::intel_gpu_guc_gt::GtError::State)?;
        if !context
            .placements()
            .iter()
            .all(|engine| publication.engines.contains(engine))
        {
            return Err(crate::intel_gpu_guc_gt::GtError::State);
        }
        let result = match output {
            Some(output) => self
                .gt
                .submit_user_batch_with_output(now, context, batch, output),
            None => self.gt.submit_user_batch(now, context, batch),
        };
        if self.gt.state() == crate::intel_gpu_guc_gt::GtState::Lost {
            self.error.get_or_insert(MediaGucError::Gt(
                result
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(crate::intel_gpu_guc_gt::GtError::State),
            ));
            self.begin_stop(now);
        }
        result
    }

    /// DRM_XE_DEVICE_QUERY_ENGINE_CYCLES for a published GT1 engine
    /// (xe_query.c::query_engine_cycles -> hwe_read_timestamp). The sample
    /// reads the engine's own RING_TIMESTAMP(_UDW) through GT1's MMIO: engine
    /// bases are above MEDIA_GT_GSI_LENGTH, so xe_mmio_adjusted_addr leaves
    /// them absolute. GuCGt rechecks GT1's GT wake and every held VDBOX/VEBOX
    /// well (Linux holds XE_FORCEWAKE_ALL on the media GT), and the width is
    /// 36 bits (GRAPHICS_VER < 20). A lost wake loses this GuC, as on GT0.
    pub(crate) fn engine_cycles(
        &mut self,
        now: u64,
        engine: Engine,
        clock: i32,
    ) -> Result<crate::intel_gpu_timestamp::EngineCycles, crate::intel_gpu_guc_gt::GtError> {
        let publication = self
            .publication()
            .ok_or(crate::intel_gpu_guc_gt::GtError::State)?;
        if !publication.engines.contains(engine) {
            return Err(crate::intel_gpu_guc_gt::GtError::State);
        }
        let result = self.gt.engine_cycles(engine, clock);
        if self.gt.state() == crate::intel_gpu_guc_gt::GtState::Lost {
            self.error.get_or_insert(MediaGucError::Gt(
                result
                    .as_ref()
                    .err()
                    .copied()
                    .unwrap_or(crate::intel_gpu_guc_gt::GtError::State),
            ));
            self.begin_stop(now);
        }
        result
    }

    /// Begin a verified stop: unpublish, return GGTT invalidation to MMIO,
    /// then GuC reset, media GRDOM_FULL with a scheduler, DMA idle, CT/ADS/
    /// log/LRC release and GT wake release, as the shared GuCGt proves for
    /// GT0. Engine wells are released after that proof.
    pub(crate) fn begin_stop(&mut self, now: u64) {
        if matches!(
            self.state,
            MediaGucState::Stopping | MediaGucState::Stopped | MediaGucState::Retained
        ) {
            return;
        }
        self.published = None;
        self.defaults = None;
        self.gsc_job = None;
        if self.submission {
            // Linux's GGTT invalidation reverts to MMIO once submission stops.
            if self.allocator.media_guc_submission(false).is_ok() {
                self.submission = false;
            }
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

/// The production `gsc::load::Gsccs`: the GSC worker's kernel jobs on the
/// media GuC's GSCCS0 (`gsc->q`), one outstanding at a time.
pub(crate) struct GscQueue<
    'a,
    M: MmioWindow + Clone,
    A: crate::intel_gpu_guc_boot::BootAllocator + Clone,
> {
    guc: &'a mut MediaGuc<M, A>,
    now: u64,
}

impl<'a, M: MmioWindow + Clone, A: crate::intel_gpu_guc_boot::BootAllocator + Clone>
    GscQueue<'a, M, A>
{
    pub(crate) fn new(guc: &'a mut MediaGuc<M, A>, now: u64) -> Self {
        Self { guc, now }
    }
}

impl<M: MmioWindow + Clone, A: crate::intel_gpu_guc_boot::BootAllocator + Clone> gsc::load::Gsccs
    for GscQueue<'_, M, A>
{
    fn submit(&mut self, commands: &[u32]) -> Result<(), gsc::load::LoadError> {
        use crate::intel_gpu_guc_gt::GtError;
        use crate::intel_gpu_guc_sched::SchedulingError;
        use gsc::load::LoadError;
        if self
            .guc
            .gsc_job
            .as_ref()
            .is_some_and(|job| job.result().is_none())
        {
            return Err(LoadError::Queue);
        }
        match self.guc.submit_gsc(self.now, commands) {
            Ok(fence) => {
                self.guc.gsc_job = Some(fence);
                Ok(())
            }
            // No running GT1 or no GSCCS0: xe_gsc_init_post_hwconfig's ENODEV.
            Err(GtError::State) => Err(LoadError::NoDevice),
            Err(GtError::Scheduling(SchedulingError::Full | SchedulingError::Busy)) => {
                Err(LoadError::Queue)
            }
            Err(GtError::Scheduling(SchedulingError::Allocation(_))) => Err(LoadError::NoMemory),
            // Not one of the two GSC instruction shapes the queue admits.
            Err(GtError::Scheduling(SchedulingError::Address)) => Err(LoadError::Invalid),
            Err(_) => Err(LoadError::Io),
        }
    }

    /// NARF: a job that retired with an error (reset, cancellation) fails
    /// the step with EIO; dma_fence_wait_timeout ignores the fence error.
    fn finished(&mut self) -> Option<Result<(), gsc::load::LoadError>> {
        match self.guc.gsc_job.as_ref()?.result()? {
            Ok(()) => Some(Ok(())),
            Err(_) => Some(Err(gsc::load::LoadError::Io)),
        }
    }

    fn holds_wake(&self) -> bool {
        self.guc.gsc && self.guc.wells & 1 << GSC_DOMAIN != 0
    }
}

/// xe_query.c::query_uc_fw_version for XE_QUERY_UC_TYPE_HUC. With
/// MEDIA_VER >= 13 (this MTL/Arrow profile) the HuC is the first tile's media
/// GT's: no published media GT, or a HuC that is not RUNNING, is ENODEV
/// (`None`), and GT0 never answers. Older media reports the primary GT's HuC
/// through `primary`.
pub(crate) fn query_huc<M, A>(
    platform: GtPlatform,
    media: Option<&MediaGuc<M, A>>,
    current: impl FnMut() -> bool,
    primary: impl FnOnce() -> Option<(u8, u8, u8)>,
) -> Option<(u8, u8, u8)>
where
    M: MmioWindow + Clone,
    A: crate::intel_gpu_guc_boot::BootAllocator + Clone,
{
    if profile_eligible(platform) {
        media?.huc_version(current)
    } else {
        primary()
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

/// GSC firmware, GSC-headered HuC images and the GSC HECI protocol of this
/// media GT. The media GuC loads the HuC through it; with `narf.intel.gsc=1`
/// its `owner` loads the GSC over GSCCS0.
#[path = "intel_gpu_gsc.rs"]
pub(crate) mod gsc;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_media_gt_tests.rs"]
mod tests;
