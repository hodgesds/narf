//! GuC-scheduled graphics-GT engines and the copy engine's literal codecs.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_pci.c engine
//! masks (BCS0 is never fused on Xe-LPG, Xe-HPG or Xe2-HPG; read_copy_fuses
//! applies only to PVC and Xe3+), xe_hw_engine.c, xe_lrc.c
//! {gen12_xcs,xe2_bcs}_offsets, xe_ring_ops.c::__emit_job_gen12_simple,
//! xe_gt.c::emit_wa_job, xe_hw_engine_setup_default_lrc_state and
//! regs/xe_engine_regs.h. CCS0–3 follow xe_gt_ccs_mode.c's immutable boot
//! partition (default one engine), dense logical mapping and physical fuses. BMG's architecture-present BCS8 is ordinary COPY1 while
//! USM is absent. A future USM owner must reserve/revoke that user engine.
//! Gen12 media engines share this main GuC, with immutable physical fuses.
//! Other platforms retain their existing graphics-only inventory.

use crate::{intel_gpu_gt::GtPlatform, intel_gpu_rcs::GpuBacking};
use alloc::vec::Vec;

/// Engine-state page offset of the register state within every LRC image.
pub(crate) const REGS: u64 = 4096;

/// OACTXCONTROL register offset from the engine base (Linux
/// `i915_perf_oa_regs.h` `GEN12_OACTXCONTROL(base)`: `(base) + 0x360`;
/// pre-Gen12 fixed `GEN8_OACTXCONTROL` 0x2360). Single authority for the
/// offset: the OA live job and the LRC image hook both use this.
pub(crate) const OACTXCONTROL_OFF: u32 = 0x360;
/// Driver-defined PPHWSP breadcrumb and job-start stamp.
pub(crate) const BREADCRUMB: u64 = 0x800;
const START: u64 = BREADCRUMB + 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Engine {
    Rcs0,
    Bcs0,
    Bcs8,
    Ccs0,
    Ccs1,
    Ccs2,
    Ccs3,
    Vcs0,
    Vcs1,
    Vcs2,
    Vcs3,
    Vcs4,
    Vcs5,
    Vcs6,
    Vcs7,
    Vecs0,
    Vecs1,
    Vecs2,
    Vecs3,
    /// The MTL/Arrow media GT's GSC command streamer (xe_hw_engine.c
    /// XE_HW_ENGINE_GSCCS0: class OTHER, OTHER_GSC_INSTANCE). Kernel-only:
    /// xe_hw_engine_is_reserved holds for class OTHER, so no UAPI class,
    /// query or placement ever names it.
    Gsccs0,
}

/// DRM_XE_ENGINE_CLASS has no OTHER member (xe_query.c skips reserved
/// engines and user_to_xe_engine_class maps none to OTHER). GSCCS0 reports
/// this value, which no UAPI lookup accepts (`EngineSet::from_class_instance`
/// skips reserved engines as well).
pub(crate) const RESERVED_CLASS: u16 = u16::MAX;

/// The engines a GT publishes, decided from fuses before scheduling starts.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct EngineSet(u32);

impl EngineSet {
    pub const fn of(engines: &[Engine]) -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < engines.len() {
            bits |= 1 << engines[i] as u8;
            i += 1;
        }
        Self(bits)
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & ((1 << Engine::COUNT) - 1))
    }
    pub fn contains(self, engine: Engine) -> bool {
        self.0 & 1 << engine as u8 != 0
    }
    /// Present engines in stable NARF slot order (the first seven predate media).
    pub fn iter(self) -> impl Iterator<Item = Engine> {
        Engine::ALL.into_iter().filter(move |e| self.contains(*e))
    }
    pub fn compute(self) -> impl Iterator<Item = Engine> {
        self.iter().filter(|engine| engine.is_compute())
    }
    /// Dense UAPI/GuC logical numbering is defined by this published set,
    /// including when lower physical compute instances are fused off.
    pub fn logical_instance(self, engine: Engine) -> Option<u16> {
        self.iter()
            .filter(|candidate| candidate.xe_class() == engine.xe_class())
            .position(|candidate| candidate == engine)
            .map(|index| index as u16)
    }
    pub fn from_class_instance(self, class: u16, logical: u16) -> Option<Engine> {
        self.iter()
            .filter(|engine| !engine.reserved() && engine.xe_class() == class)
            .nth(usize::from(logical))
    }
    /// GuC submits a width-one virtual context to this dense logical mask.
    /// Every placement must belong to one advertised class of this GT.
    pub(crate) fn logical_mask(self, placements: Self) -> Option<u32> {
        let first = placements.iter().next()?;
        placements.iter().try_fold(0, |mask, engine| {
            (!engine.reserved() && engine.xe_class() == first.xe_class())
                .then(|| self.logical_instance(engine))
                .flatten()
                .map(|logical| mask | 1 << logical)
        })
    }
    /// The REGISTER_CONTEXT logical mask of an already admitted context. For
    /// advertised engines this is [`Self::logical_mask`]. A kernel-only
    /// (reserved) engine context, which no UAPI placement can name, maps to
    /// its own logical instance, as Linux creates the kernel GSC queue with
    /// `BIT(hwe->logical_instance)` (xe_gsc.c::xe_gsc_init_post_hwconfig).
    pub(crate) fn registration_mask(self, placements: Self) -> Option<u32> {
        let first = placements.iter().next()?;
        placements.iter().try_fold(0, |mask, engine| {
            (engine.reserved() == first.reserved() && engine.xe_class() == first.xe_class())
                .then(|| self.logical_instance(engine))
                .flatten()
                .map(|logical| mask | 1 << logical)
        })
    }
    /// ENGINE_ID uses hardware class/physical instance, not GuC or UAPI
    /// numbering (xe_engine_regs.h + xe_lrc.c::get_ctx_timestamp).
    pub(crate) fn decode_hardware_id(self, word: u32) -> Option<Engine> {
        self.iter().find(|engine| {
            word & 7 == engine.hw_class() && (word >> 4) & 63 == engine.physical_instance()
        })
    }
}

/// Physically present compute instances (bit n = CCSn), from
/// xe_hw_engine.c::read_compute_fuses. Xe-LPG has exactly one CCS; Xe-HPG
/// infers CCSn from DSS in quadrant n; Xe2 reads XEHP_FUSE4 CCS_EN.
pub(crate) fn compute_instances(platform: GtPlatform, dss: u128, fuse4: u32) -> u8 {
    match platform {
        _ if platform.is_xe2() => ((fuse4 >> 16) & 0xf) as u8,
        GtPlatform::Gen12(_) => 0,
        GtPlatform::Integrated(_) => 1,
        GtPlatform::Alchemist => {
            // get_num_dss_regs: one geometry and one compute register, so
            // each quadrant is 8 DSS of the geometry|compute union.
            (0..4)
                .filter(|q| dss >> (q * 8) & 0xff != 0)
                .fold(0, |m, q| m | 1 << q)
        }
        GtPlatform::Battlemage => ((fuse4 >> 16) & 0xf) as u8,
    }
}

/// Boot-only compute partition. Xe requires an equal integral slice share.
/// Default mode1 permits a GT with no compute engine at all.
pub(crate) fn compute_selection(instances: u8, requested: u8) -> Option<EngineSet> {
    let count = instances.count_ones() as u8;
    if instances & !15 != 0
        || requested == 0
        || requested > 4
        || (count == 0 && requested != 1)
        || (count != 0 && (requested > count || count % requested != 0))
    {
        return None;
    }
    Some(EngineSet::from_bits(
        Engine::ALL
            .into_iter()
            .filter(|e| e.is_compute())
            .filter(|e| instances & (1 << e.physical_instance()) != 0)
            .take(usize::from(requested))
            .fold(0, |bits, e| bits | (1 << e.index())),
    ))
}

/// xe_gt_ccs_mode.c::__xe_gt_apply_ccs_mode: present slices are assigned
/// round-robin to the first requested physical engines; absent slices stay disabled.
/// `None` when at most one CCS exists (CCS mode is not enabled).
pub(crate) fn ccs_mode(instances: u8, engines: u8) -> Option<u32> {
    let count = instances.count_ones();
    if count <= 1 || compute_selection(instances, engines).is_none() {
        return None;
    }
    let mut owners = [0u32; 4];
    for (n, physical) in (0..4)
        .filter(|i| instances & (1 << i) != 0)
        .take(usize::from(engines))
        .enumerate()
    {
        owners[n] = physical;
    }
    let mut mode = 0xfff; // CCS_MODE_CSLICE_0_3_MASK: all disabled
    let mut next = 0;
    for slice in 0..4 {
        if instances & 1 << slice != 0 {
            mode &= !(7 << (slice * 3));
            mode |= owners[next % usize::from(engines)] << (slice * 3);
            next += 1;
        }
    }
    Some(mode | 0xfff << 16)
}

impl Engine {
    pub const COUNT: usize = 20;
    /// Stable original graphics slots; Gen12 media appends without renumbering.
    pub const GRAPHICS: [Engine; 7] = [
        Self::Rcs0,
        Self::Bcs0,
        Self::Bcs8,
        Self::Ccs0,
        Self::Ccs1,
        Self::Ccs2,
        Self::Ccs3,
    ];
    pub const ALL: [Engine; Self::COUNT] = [
        Engine::Rcs0,
        Engine::Bcs0,
        Engine::Bcs8,
        Engine::Ccs0,
        Engine::Ccs1,
        Engine::Ccs2,
        Engine::Ccs3,
        Engine::Vcs0,
        Engine::Vcs1,
        Engine::Vcs2,
        Engine::Vcs3,
        Engine::Vcs4,
        Engine::Vcs5,
        Engine::Vcs6,
        Engine::Vcs7,
        Engine::Vecs0,
        Engine::Vecs1,
        Engine::Vecs2,
        Engine::Vecs3,
        Engine::Gsccs0,
    ];

    pub(crate) fn index(self) -> usize {
        self as usize
    }
    pub(crate) fn base(self) -> u32 {
        match self {
            Engine::Rcs0 => 0x2000,
            Engine::Bcs0 => 0x22000,
            Engine::Bcs8 => 0x3ee000,
            Engine::Ccs0 => 0x1a000,
            Engine::Ccs1 => 0x1c000,
            Engine::Ccs2 => 0x1e000,
            Engine::Ccs3 => 0x26000,
            Self::Vcs0 => 0x1c0000,
            Self::Vcs1 => 0x1c4000,
            Self::Vcs2 => 0x1d0000,
            Self::Vcs3 => 0x1d4000,
            Self::Vcs4 => 0x1e0000,
            Self::Vcs5 => 0x1e4000,
            Self::Vcs6 => 0x1f0000,
            Self::Vcs7 => 0x1f4000,
            Self::Vecs0 => 0x1c8000,
            Self::Vecs1 => 0x1d8000,
            Self::Vecs2 => 0x1e8000,
            Self::Vecs3 => 0x1f8000,
            // regs/xe_engine_regs.h GSCCS_RING_BASE.
            Self::Gsccs0 => 0x11a000,
        }
    }
    /// GUC_RENDER_CLASS / GUC_BLITTER_CLASS / GUC_COMPUTE_CLASS, and
    /// GUC_GSC_OTHER_CLASS for class OTHER (xe_guc.h
    /// xe_engine_class_to_guc_class, abi/guc_scheduler_abi.h).
    pub(crate) fn guc_class(self) -> u32 {
        match self {
            Engine::Rcs0 => 0,
            Engine::Bcs0 | Engine::Bcs8 => 3,
            Engine::Ccs0 | Engine::Ccs1 | Engine::Ccs2 | Engine::Ccs3 => 4,
            Self::Vcs0
            | Self::Vcs1
            | Self::Vcs2
            | Self::Vcs3
            | Self::Vcs4
            | Self::Vcs5
            | Self::Vcs6
            | Self::Vcs7 => 1,
            Self::Vecs0 | Self::Vecs1 | Self::Vecs2 | Self::Vecs3 => 2,
            Self::Gsccs0 => 5,
        }
    }
    /// The hardware class of RING ENGINE_ID and interrupt identities
    /// (`enum xe_engine_class`): RENDER 0, VIDEO_DECODE 1, VIDEO_ENHANCE 2,
    /// COPY 3, OTHER 4, COMPUTE 5.
    pub(crate) fn hw_class(self) -> u32 {
        match self.guc_class() {
            4 => 5,
            5 => 4,
            class => class,
        }
    }
    /// DRM_XE_ENGINE_CLASS_RENDER / _COPY / _COMPUTE (also i915 UABI).
    pub fn xe_class(self) -> u16 {
        match self {
            Engine::Rcs0 => 0,
            Engine::Bcs0 | Engine::Bcs8 => 1,
            Engine::Ccs0 | Engine::Ccs1 | Engine::Ccs2 | Engine::Ccs3 => 4,
            Self::Vcs0
            | Self::Vcs1
            | Self::Vcs2
            | Self::Vcs3
            | Self::Vcs4
            | Self::Vcs5
            | Self::Vcs6
            | Self::Vcs7 => 2,
            Self::Vecs0 | Self::Vecs1 | Self::Vecs2 | Self::Vecs3 => 3,
            Self::Gsccs0 => RESERVED_CLASS,
        }
    }
    pub(crate) fn physical_instance(self) -> u32 {
        match self {
            Self::Bcs8 => 8,
            Self::Ccs1 | Self::Vcs1 | Self::Vecs1 => 1,
            Self::Ccs2 | Self::Vcs2 | Self::Vecs2 => 2,
            Self::Ccs3 | Self::Vcs3 | Self::Vecs3 => 3,
            Self::Vcs4 => 4,
            Self::Vcs5 => 5,
            Self::Vcs6 => 6,
            Self::Vcs7 => 7,
            // regs/xe_irq_regs.h OTHER_GSC_INSTANCE.
            Self::Gsccs0 => 6,
            _ => 0,
        }
    }
    pub(crate) fn is_copy(self) -> bool {
        matches!(self, Self::Bcs0 | Self::Bcs8)
    }
    pub(crate) fn is_media(self) -> bool {
        matches!(self.xe_class(), 2 | 3)
    }
    pub(crate) fn is_decode(self) -> bool {
        self.xe_class() == 2
    }
    /// xe_ring_ops.c ring_ops_gen12_gsc: emit_job_gen12_gsc runs
    /// __emit_job_gen12_simple, as COPY does; VCS/VECS add AUX invalidation.
    pub(crate) fn simple_ring(self) -> bool {
        self.is_copy() || self.is_media() || self.is_gsc()
    }
    /// GSCCS0 (class OTHER).
    pub(crate) fn is_gsc(self) -> bool {
        self == Self::Gsccs0
    }
    /// xe_hw_engine.c::xe_hw_engine_is_reserved for class OTHER: kernel
    /// use only, never in a query, placement or published engine set.
    pub(crate) fn reserved(self) -> bool {
        self.is_gsc()
    }
    pub fn is_compute(self) -> bool {
        matches!(self, Self::Ccs0 | Self::Ccs1 | Self::Ccs2 | Self::Ccs3)
    }
    /// xe_gt_lrc_size: PPHWSP plus the class's engine context image.
    pub(crate) fn lrc_pages(self, platform: GtPlatform) -> u32 {
        match (self, platform) {
            (Engine::Rcs0, _) if platform.is_xe2() => 4,
            (Engine::Rcs0, _) => 14,
            (Engine::Bcs0 | Engine::Bcs8, _) => 2,
            (Engine::Ccs0 | Engine::Ccs1 | Engine::Ccs2 | Engine::Ccs3, _) if platform.is_xe2() => {
                3
            }
            (Engine::Ccs0 | Engine::Ccs1 | Engine::Ccs2 | Engine::Ccs3, _) => 14,
            _ => 2,
        }
    }
    /// First MI_LOAD_REGISTER_IMM header of the hardware-saved image.
    pub(crate) fn first_lri(self, platform: GtPlatform) -> u32 {
        if platform.is_gen12() || self.is_copy() && !platform.is_xe2() {
            0x11081019 // gen12_xcs_offsets: 13 registers, no PRT_BB_STATE
        } else {
            0x1108101d
        }
    }
}

/// xe_hw_engine_enable_ring for the GuC-owned engine. GT/render wake and
/// each present Gen12 media wake are retained by the same hardware owner;
/// MOCS defaults follow RING_CMD_CCTL.
pub(crate) fn enable_ring(
    mmio: &impl crate::intel_gpu_aux::MmioWindow,
    engine: Engine,
    platform: GtPlatform,
    hwsp: u32,
) {
    let base = u64::from(engine.base());
    if engine.is_gsc() {
        // hwe->reg_sr "MTL GSCCS IDLE MSG enable" (MEDIA_VERSION(1300),
        // ENGINE_CLASS(OTHER)), which hw_engine_init applies before
        // xe_hw_engine_enable_ring: masked CLR of RING_PSMI_CTL
        // IDLE_MSG_DISABLE, then RING_PWRCTX_MAXCNT IDLE_WAIT_TIME = 0xA (5 us
        // hysteresis) read-modify-written as xe_reg_sr_apply_mmio does.
        mmio.write32(base + 0x50, 0x0001_0000);
        let maxcnt = mmio.read32(base + 0x54);
        mmio.write32(base + 0x54, (maxcnt & !0x000f_ffff) | 0xa);
    }
    let uc = uncached_mocs(platform);
    // hw_engine_setup_default_state: discrete Xe2 compute reads use WB.
    let read = if engine.is_compute() && platform == GtPlatform::Battlemage {
        4
    } else {
        uc
    };
    if engine.is_compute() {
        mmio.write32(0x14800, 0x00010001); // RCU_MODE_CCS_ENABLE
    }
    mmio.write32(base + 0xc4, 0x3f7e0000 | uc << 8 | read << 1);
    mmio.write32(base + 0xa8, u32::MAX); // runtime owner enables IRQs after startup probes
    mmio.write32(base + 0x98, u32::MAX);
    mmio.write32(base + 0x80, hwsp);
    mmio.write32(base + 0x29c, 0x00080008);
    mmio.write32(base + 0x9c, 0x01000000);
    let _ = mmio.read32(base + 0x9c);
}

pub(crate) fn uncached_mocs(platform: GtPlatform) -> u32 {
    match platform {
        _ if platform.is_headless_integrated() => 3,
        GtPlatform::Gen12(_) => 3,
        GtPlatform::Integrated(_) => 9,
        GtPlatform::Alchemist => 1,
        GtPlatform::Battlemage => 3,
    }
}

/// Default BCS LRC state: emit_wa_job's non-MCR read-modify-write of
/// BLIT_CCTL, pointing MOCS-less blitter commands at the uncached index.
pub(crate) fn copy_seed(engine: Engine, platform: GtPlatform) -> Vec<u32> {
    let uc = uncached_mocs(platform);
    let reg = engine.base() + 0x204;
    let mut words = if platform.is_gen12() {
        gen12_nonrender_seed()
    } else {
        Vec::new()
    };
    words.extend_from_slice(&[
        0x15080001,
        reg,
        0x600,
        0x11080003,
        0x608,
        0x7e7e,
        0x610,
        uc << 9 | uc << 1,
        0x0d000007,
        0x08008000,
        0x48008401,
        0x10200000,
        0x18000031,
        0x08008000,
        0x08008402,
        0x10300000,
        0x18000031,
        0x15040001,
        0x600,
        reg,
        0x11080005,
        0x600,
        0,
        0x608,
        0,
        0x610,
        0,
    ]);
    words
}

/// Default CCS LRC state: xe_hw_engine_setup_default_lrc_state's only
/// compute entry on these platforms, the Xe2 WMTP-disabled preemption level
/// (CS_CHICKEN1 PREEMPT_GPGPU_THREAD_GROUP_LEVEL, masked). No 3D state.
pub(crate) fn compute_seed(engine: Engine, platform: GtPlatform, disable_wmtp: bool) -> Vec<u32> {
    if platform.is_xe2() && disable_wmtp {
        alloc::vec![0x11000001, engine.base() + 0x580, 0x00060002]
    } else {
        Vec::new()
    }
}

/// Source graphics1200 lrc_was shared by nonrender engines. Media has no
/// BLIT_CCTL or render FF_MODE2/3D initialization.
pub(crate) fn gen12_nonrender_seed() -> Vec<u32> {
    alloc::vec![
        0, 0x11000007, 0x2580, 0x00060002, 0x7018, 0x20002000, 0x7300, 0x00400040, 0x7304,
        0x02000200
    ]
}

/// xe_ring_ops::__emit_job_gen12_video. AUX invalidation is class-specific
/// and precedes the start-stamp TLB flush while preparser is disabled.
pub(crate) fn media_ring(
    engine: Engine,
    batch: Option<u64>,
    user_fence: Option<(u64, u64)>,
    image: u32,
    seq: u32,
) -> Vec<u32> {
    media_ring_at(engine, 0, batch, user_fence, image, seq)
}

/// `media_ring` for a GT whose MMIO is adjusted by `adj_offset`:
/// xe_ring_ops.c::emit_aux_table_inv writes `reg.addr + gt->mmio.adj_offset`,
/// so the MTL/Arrow standalone media GT invalidates VD0/VE0_AUX_INV at the
/// media GSI base. has_aux_ccs holds there: mtl_desc has no flat CCS and
/// graphics is below 20.
pub(crate) fn media_ring_at(
    engine: Engine,
    adj_offset: u32,
    batch: Option<u64>,
    user_fence: Option<(u64, u64)>,
    image: u32,
    seq: u32,
) -> Vec<u32> {
    let mut words = copy_ring(batch, user_fence, image, seq);
    words.splice(
        2..2,
        [
            0x11020001, // MMIO_REMAP_EN bit17; ADD_CS_MMIO_START bit19 is absent.
            adj_offset + if engine.is_decode() { 0x4218 } else { 0x4238 },
            1,
            0,
        ],
    );
    words
}

/// Default media LRC seed (xe_gt.c::emit_wa_job over hwe->reg_lrc). Gen12's
/// single GT matches graphics1200 lrc_was on its media engines. On the
/// MTL/Arrow standalone media GT no lrc_was, lrc_tunings or default LRC state
/// entry matches VCS/VECS (xe_rtp.c: graphics rules never match a media GT,
/// and no media 13.00 LRC rule exists), so the WA job is empty.
pub(crate) fn media_seed(platform: GtPlatform) -> Vec<u32> {
    if platform.is_gen12() {
        gen12_nonrender_seed()
    } else {
        Vec::new()
    }
}

/// Inverted pre-XeHP fuse polarity: bits0..7 VDBOX,16..19 VEBOX.
pub(crate) fn gen12_media(fuse: u32) -> EngineSet {
    let mut bits = 0;
    for engine in Engine::ALL.into_iter().filter(|engine| engine.is_media()) {
        let bit = engine.physical_instance() + if engine.is_decode() { 0 } else { 16 };
        if fuse & (1 << bit) == 0 {
            bits |= 1 << engine.index();
        }
    }
    EngineSet::from_bits(bits)
}

/// The only GSC instructions the kernel GSC queue admits
/// (instructions/xe_gsc_commands.h): xe_gsc_pkt_submit_kernel's 8-dword
/// GSC_HECI_CMD_PKT, both buffers carrying at least a GSC header, or
/// emit_gsc_upload's GSC_FW_LOAD with GSC_FW_LOAD_LIMIT_VALID. Every GGTT
/// address fits the 4 GiB GGTT, so the upper dwords are zero.
pub(crate) fn gsc_job_valid(words: &[u32]) -> bool {
    use crate::intel_gpu_gt::media::gsc::{GSC_FW_LOAD, GSC_HECI_CMD_PKT, HEADER};
    match *words {
        [GSC_HECI_CMD_PKT, _, 0, input, _, 0, output, 0] => {
            input >= HEADER as u32 && output >= HEADER as u32
        }
        [GSC_FW_LOAD, _, 0, limit] => limit & 1 << 31 != 0 && limit & !(1 << 31) != 0,
        _ => false,
    }
}

/// MI_FLUSH_DW post-sync GGTT store, then MI_USER_INTERRUPT. Tails stay
/// qword aligned.
pub(crate) fn copy_completion(image: u32, seq: u32, words: &mut Vec<u32>) {
    words.extend_from_slice(&[
        0x13004002,
        (image + BREADCRUMB as u32) | 4,
        0,
        seq,
        0x01000000,
        0x04000001,
        0x02800000,
    ]);
    if words.len() % 2 != 0 {
        words.push(0);
    }
}

/// __emit_job_gen12_simple with the TLB-invalidating start stamp. A user
/// fence follows a plain MI_FLUSH_DW and precedes the owned breadcrumb.
pub(crate) fn copy_ring(
    batch: Option<u64>,
    user_fence: Option<(u64, u64)>,
    image: u32,
    seq: u32,
) -> Vec<u32> {
    let mut words = alloc::vec![
        0x04000001,
        0x02800101,
        0x13044002,
        (image + START as u32) | 4,
        0,
        seq,
        0x02800100,
    ];
    if let Some(batch) = batch {
        words.extend_from_slice(&[0x18800101, batch as u32, (batch >> 32) as u32]);
    }
    words.push(0x04000000);
    if let Some((address, value)) = user_fence {
        words.extend_from_slice(&[
            0x13000002,
            0,
            0,
            0,
            0x10200003,
            address as u32,
            (address >> 32) as u32,
            value as u32,
            (value >> 32) as u32,
        ]);
    }
    copy_completion(image, seq, &mut words);
    words
}

/// Inhibited initial BCS image from the class's Linux offset table.
#[cfg(feature = "kernel-test")]
pub(crate) fn copy_image(image: &impl GpuBacking, platform: GtPlatform, ring: u32) {
    xcs_image(Engine::Bcs0, image, platform, ring)
}

/// Inhibited initial non-render image (reg_offsets for COPY/COMPUTE):
/// BCS uses gen12_xcs before Xe2 and xe2_bcs on BMG; CCS uses dg2_xcs
/// (graphics >= 12.55) and xe2_xcs. Only xe2_bcs has a third LRI group.
pub(crate) fn xcs_image(engine: Engine, image: &impl GpuBacking, platform: GtPlatform, ring: u32) {
    let base = engine.base();
    let xe2 = platform.is_xe2();
    let mut first: Vec<u32> = alloc::vec![
        0x244, 0x034, 0x030, 0x038, 0x03c, 0x168, 0x140, 0x110, 0x1c0, 0x1c4, 0x1c8, 0x180, 0x2b4,
    ];
    // dg2_xcs_offsets (graphics >= 12.55) also serves VCS/VECS and GSCCS on
    // the MTL media GT: xe_lrc.c::reg_offsets keys on the device graphics IP.
    if xe2
        || engine.is_compute()
        || ((engine.is_media() || engine.is_gsc()) && !platform.is_gen12())
    {
        first.extend_from_slice(&[0x120, 0x124]);
    }
    // OACTXCONTROL (engine base + 0x360) in the render image only, last in
    // the group, value default 0 (the disabled value). The OA image hook
    // programs this slot at stream enable (see
    // `oactxcontrol_value_slot`); the default is load-bearing — adding the
    // register without the hook would restore 0 over the live programming
    // on the next context switch (Linux i915_perf.c
    // `gen12_configure_oar_context` writes the image slot, never the
    // template). The group only takes the register while it still ends
    // before the second group at dword 0x21: Gen12 render has 13
    // registers, so it fits; Xe2/compute/media images already carry 15
    // and have no room, so they keep the live-only path (their image hook
    // is a follow-up, as is OAC on compute).
    if engine == Engine::Rcs0 && first.len() < 15 {
        first.push(OACTXCONTROL_OFF);
    }
    let second: &[u32] = if xe2 {
        &[
            0x3a8, 0x3ac, 0x108, 0x284, 0x280, 0x27c, 0x278, 0x274, 0x270,
        ]
    } else {
        &[
            0x3a8, 0x28c, 0x288, 0x284, 0x280, 0x27c, 0x278, 0x274, 0x270,
        ]
    };
    let mut groups: Vec<(u64, &[u32])> = alloc::vec![(1, first.as_slice()), (0x21, second)];
    if xe2 && engine.is_copy() {
        groups.push((0x41, &[0x200, 0x204]));
    }
    let mut end = 0;
    for (start, group) in groups {
        image.write32(REGS + start * 4, 0x11081000 | (group.len() as u32 * 2 - 1));
        for (i, offset) in group.iter().enumerate() {
            image.write32(REGS + (start + 1 + i as u64 * 2) * 4, base + offset);
        }
        end = start + 1 + group.len() as u64 * 2;
    }
    image.write32(REGS + end * 4, 0x05000001);
    image.write32(REGS + 3 * 4, 0x00090009); // inhibit restore and synchronous switch
    image.write32(REGS + 9 * 4, ring);
    image.write32(REGS + 11 * 4, 0x1001); // 8 KiB ring
    image.write32(
        REGS + if platform.is_gen12() { 0x61 } else { 0x71 } * 4,
        0x01000000,
    );
}

/// Scan an LRC image's register-state page for the OACTXCONTROL slot and
/// return the byte offset (relative to the REGS page) of its value dword.
///
/// Layout-independent: it walks the image's MI_LOAD_REGISTER_IMM groups
/// (Linux `i915_perf.c` `oa_context_image_offset` does the same scan on
/// Gen12, caching the offset; NARF re-scans per apply — the image is a
/// few KiB and the apply is once per stream enable). A value dword is
/// the word immediately following its register dword; the LRI header is
/// `0x11000000 | (2 * nregs - 1)`, one register dword plus one value
/// dword per register. Returns `None` when the image has no OACTXCONTROL slot (an
/// engine whose template does not carry it) — callers fail closed.
pub(crate) fn oactxcontrol_value_slot<B: GpuBacking>(image: &B, base: u32) -> Option<u64> {
    const MI_LRI_HEADER: u32 = 0x11000000;
    const MI_BATCH_BUFFER_END: u32 = 0x05000001;
    const MAX_DWORDS: u64 = 1024;
    let mut dw: u64 = 0;
    while dw < MAX_DWORDS {
        let word = image.read32(REGS + dw * 4);
        if word == MI_BATCH_BUFFER_END {
            return None;
        }
        if word == 0 {
            // MI_NOOP; skip one dword.
            dw += 1;
            continue;
        }
        if word & 0xFF000000 == MI_LRI_HEADER {
            // The header's low field is (2 * nregs - 1): each register
            // contributes a register dword and a value dword. Dword
            // indices are u64 throughout (the image cursor is u64).
            let nregs = (word & 0x3FF).div_ceil(2) as u64;
            for i in 0..nregs {
                let reg_dw = dw + 1 + i * 2;
                let val_dw = reg_dw + 1;
                if val_dw >= MAX_DWORDS {
                    return None;
                }
                if image.read32(REGS + reg_dw * 4) == base + OACTXCONTROL_OFF {
                    return Some(val_dw * 4);
                }
            }
            dw += 1 + nregs * 2;
            continue;
        }
        // Unknown dword: skip it; a malformed image terminates at the
        // batch-buffer end or the dword bound.
        dw += 1;
    }
    None
}

/// Write `value` into the image's OACTXCONTROL slot, if it has one.
/// Returns false (no write) when the image carries no slot.
pub(crate) fn apply_oa_oactxcontrol<B: GpuBacking>(image: &B, base: u32, value: u32) -> bool {
    match oactxcontrol_value_slot(image, base) {
        Some(slot) => {
            image.write32(REGS + slot, value);
            true
        }
        None => false,
    }
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    pub(crate) struct Image(pub RefCell<Vec<u32>>);
    impl GpuBacking for Image {
        fn ggtt_offset(&self) -> u32 {
            0x0100_0000
        }
        fn size_pages(&self) -> u32 {
            2
        }
        fn write32(&self, offset: u64, value: u32) {
            self.0.borrow_mut()[offset as usize / 4] = value;
        }
        fn read32(&self, offset: u64) -> u32 {
            self.0.borrow()[offset as usize / 4]
        }
        fn zero_fill(&self) {
            self.0.borrow_mut().fill(0);
        }
    }

    fn smoke_engine_identity_table() -> TestResult {
        assert_eq!(
            Engine::GRAPHICS.map(|e| (e.base(), e.guc_class(), e.xe_class())),
            [
                (0x2000, 0, 0),
                (0x22000, 3, 1),
                (0x3ee000, 3, 1),
                (0x1a000, 4, 4),
                (0x1c000, 4, 4),
                (0x1e000, 4, 4),
                (0x26000, 4, 4)
            ]
        );
        assert_eq!(Engine::Ccs0.lrc_pages(GtPlatform::Battlemage), 3);
        assert_eq!(Engine::Ccs0.lrc_pages(GtPlatform::Alchemist), 14);
        assert_eq!(Engine::Ccs0.first_lri(GtPlatform::Alchemist), 0x1108101d);
        let set = EngineSet::of(&[Engine::Rcs0, Engine::Ccs0]);
        assert!(set.contains(Engine::Ccs0) && !set.contains(Engine::Bcs0));
        assert_eq!(set.iter().collect::<Vec<_>>(), [Engine::Rcs0, Engine::Ccs0]);
        let mtl = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
        assert_eq!(compute_instances(mtl, 0, 0), 1);
        assert_eq!(
            compute_instances(GtPlatform::Alchemist, 0x0100_0001, 0),
            0b1001
        );
        assert_eq!(compute_instances(GtPlatform::Alchemist, 0x100, 0), 0b10);
        // Xe2: XEHP_FUSE4 CCS_EN (19:16), independent of DSS.
        assert_eq!(
            compute_instances(GtPlatform::Battlemage, 1, 0xa << 16 | 0x10),
            0b1010
        );
        // __xe_gt_apply_ccs_mode with ccs_mode 1: present slices -> CCS0.
        assert_eq!(ccs_mode(1, 1), None);
        assert_eq!(ccs_mode(0xf, 1), Some(0x0fff_0000));
        assert_eq!(ccs_mode(0b1010, 1), Some(0x0fff_0000 | 0b001_111_001_111));
        assert_eq!(
            EngineSet::of(&Engine::GRAPHICS).from_class_instance(1, 0),
            Some(Engine::Bcs0)
        );
        assert_eq!(
            EngineSet::of(&Engine::GRAPHICS).from_class_instance(4, 0),
            Some(Engine::Ccs0)
        );
        assert_eq!(
            EngineSet::of(&Engine::GRAPHICS).from_class_instance(2, 0),
            None
        );
        assert_eq!(
            EngineSet::of(&Engine::GRAPHICS).from_class_instance(1, 1),
            Some(Engine::Bcs8)
        );
        assert_eq!(
            EngineSet::of(&Engine::GRAPHICS).from_class_instance(1, 8),
            None
        );
        assert_eq!(
            (
                Engine::Bcs8.physical_instance(),
                EngineSet::of(&Engine::GRAPHICS)
                    .logical_instance(Engine::Bcs8)
                    .unwrap(),
                1u32 << EngineSet::of(&Engine::GRAPHICS)
                    .logical_instance(Engine::Bcs8)
                    .unwrap()
            ),
            (8, 1, 2)
        );
        assert_eq!(EngineSet::from_bits(0x7f), EngineSet::of(&Engine::GRAPHICS));
        for platform in [
            GtPlatform::Alchemist,
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
        ] {
            assert_eq!(Engine::Rcs0.lrc_pages(platform), 14);
            assert_eq!(Engine::Bcs0.lrc_pages(platform), 2);
            assert_eq!(Engine::Bcs0.first_lri(platform), 0x11081019);
        }
        assert_eq!(Engine::Rcs0.lrc_pages(GtPlatform::Battlemage), 4);
        assert_eq!(Engine::Bcs0.first_lri(GtPlatform::Battlemage), 0x1108101d);
        assert_eq!(Engine::Bcs8.lrc_pages(GtPlatform::Battlemage), 2);
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_engine", smoke_engine_identity_table);

    // Literal LRC slots from Linux's u8 tables (REG16/REG offsets + BCS base).
    fn smoke_copy_lrc_layout_vectors() -> TestResult {
        let gen12 = Image(RefCell::new(alloc::vec![0; 2048]));
        copy_image(&gen12, GtPlatform::Alchemist, 0x0123_4000);
        let w = gen12.0.borrow();
        let r = &w[1024..];
        assert_eq!(&r[..6], &[0, 0x11081019, 0x22244, 0x00090009, 0x22034, 0]);
        assert_eq!(
            (r[8], r[9], r[10], r[11]),
            (0x22038, 0x0123_4000, 0x2203c, 0x1001)
        );
        assert_eq!(r[26], 0x222b4);
        assert!(r[28..0x21].iter().all(|w| *w == 0)); // NOP(5)
        assert_eq!((r[0x21], r[0x22], r[0x24]), (0x11081011, 0x223a8, 0x2228c));
        assert_eq!((r[0x30], r[0x32], r[0x34]), (0x22274, 0x22270, 0x05000001));
        assert_eq!(r[0x71], 0x01000000);
        assert!(w[..1024].iter().all(|w| *w == 0));
        drop(w);

        let xe2 = Image(RefCell::new(alloc::vec![0; 2048]));
        copy_image(&xe2, GtPlatform::Battlemage, 0x0123_4000);
        let w = xe2.0.borrow();
        let r = &w[1024..];
        assert_eq!(r[1], 0x1108101d);
        assert_eq!((r[0x1c], r[0x1e], r[0x20]), (0x22120, 0x22124, 0));
        assert_eq!((r[0x22], r[0x24], r[0x26]), (0x223a8, 0x223ac, 0x22108));
        assert!(r[0x34..0x41].iter().all(|w| *w == 0)); // NOP(4 + 8 + 1)
        assert_eq!(
            &r[0x41..0x47],
            &[0x11081003, 0x22200, 0, 0x22204, 0, 0x05000001]
        );
        drop(w);
        let copy8 = Image(RefCell::new(alloc::vec![0; 2048]));
        xcs_image(Engine::Bcs8, &copy8, GtPlatform::Battlemage, 0x0123_4000);
        let w = copy8.0.borrow();
        let r = &w[1024..];
        assert_eq!(&r[..6], &[0, 0x1108101d, 0x3ee244, 0x00090009, 0x3ee034, 0]);
        assert_eq!(
            &r[0x41..0x47],
            &[0x11081003, 0x3ee200, 0, 0x3ee204, 0, 0x05000001]
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_engine",
        smoke_copy_lrc_layout_vectors
    );

    // MI_FLUSH_DW | OP_STOREDW | IMM_DW (| INVALIDATE_TLB), USE_GTT address.
    fn smoke_copy_ring_vectors() -> TestResult {
        let image = 0x0100_0000;
        assert_eq!(
            copy_ring(Some(0x1234_0000_0000), None, image, 7),
            [
                0x04000001,
                0x02800101,
                0x13044002,
                image + 0x80c,
                0,
                7,
                0x02800100,
                0x18800101,
                0,
                0x1234,
                0x04000000,
                0x13004002,
                image + 0x804,
                0,
                7,
                0x01000000,
                0x04000001,
                0x02800000,
            ]
        );
        let fenced = copy_ring(None, Some((0x2000_0008, 0x1_0000_0002)), image, 9);
        assert_eq!(
            &fenced[7..18],
            &[
                0x04000000,
                0x13000002,
                0,
                0,
                0,
                0x10200003,
                0x2000_0008,
                0,
                2,
                1,
                0x13004002
            ]
        );
        assert_eq!(fenced.len() % 2, 0);
        let seed = copy_seed(Engine::Bcs0, GtPlatform::Battlemage);
        assert_eq!(&seed[..3], &[0x15080001, 0x22204, 0x600]);
        assert_eq!(seed[7], 3 << 9 | 3 << 1);
        assert_eq!(&seed[17..20], &[0x15040001, 0x600, 0x22204]);
        assert_eq!(
            copy_seed(Engine::Bcs0, GtPlatform::Alchemist)[7],
            1 << 9 | 1 << 1
        );
        let copy8 = copy_seed(Engine::Bcs8, GtPlatform::Battlemage);
        assert_eq!((copy8[1], copy8[19], copy8[7]), (0x3ee204, 0x3ee204, 0x606));
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_engine", smoke_copy_ring_vectors);
    fn smoke_gen12_media_literal_identity_fuses_and_context() -> TestResult {
        let platform = GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake);
        let physical = [
            (Engine::Vcs0, 0x1c0000, 1, 2, 0),
            (Engine::Vcs1, 0x1c4000, 1, 2, 1),
            (Engine::Vcs2, 0x1d0000, 1, 2, 2),
            (Engine::Vcs3, 0x1d4000, 1, 2, 3),
            (Engine::Vcs4, 0x1e0000, 1, 2, 4),
            (Engine::Vcs5, 0x1e4000, 1, 2, 5),
            (Engine::Vcs6, 0x1f0000, 1, 2, 6),
            (Engine::Vcs7, 0x1f4000, 1, 2, 7),
            (Engine::Vecs0, 0x1c8000, 2, 3, 0),
            (Engine::Vecs1, 0x1d8000, 2, 3, 1),
            (Engine::Vecs2, 0x1e8000, 2, 3, 2),
            (Engine::Vecs3, 0x1f8000, 2, 3, 3),
        ];
        assert_eq!(EngineSet::of(&Engine::GRAPHICS).bits(), 0x7f);
        assert_eq!(EngineSet::from_bits(u32::MAX).iter().count(), 20);
        assert_eq!(gen12_media(0x000f00ff).bits(), 0);
        assert_eq!(gen12_media(0).iter().count(), 12);
        for (index, (engine, base, guc, uapi, instance)) in physical.into_iter().enumerate() {
            assert_eq!(
                (
                    engine.index(),
                    engine.base(),
                    engine.guc_class(),
                    engine.xe_class(),
                    engine.physical_instance()
                ),
                (7 + index, base, guc, uapi, instance)
            );
            assert_eq!(engine.lrc_pages(platform), 2);
            let fuse = 0x000f00ff & !(1 << (instance + if guc == 1 { 0 } else { 16 }));
            let set = gen12_media(fuse);
            assert_eq!(set.iter().collect::<Vec<_>>(), [engine]);
            assert_eq!(set.from_class_instance(uapi, 0), Some(engine));
            assert_eq!(set.from_class_instance(uapi, 1), None);
            let image = Image(RefCell::new(alloc::vec![0;2048]));
            xcs_image(engine, &image, platform, 0x1200000);
            let words = image.0.borrow();
            let r = &words[1024..];
            assert_eq!(
                &r[..12],
                &[
                    0,
                    0x11081019,
                    base + 0x244,
                    0x00090009,
                    base + 0x34,
                    0,
                    base + 0x30,
                    0,
                    base + 0x38,
                    0x1200000,
                    base + 0x3c,
                    0x1001
                ]
            );
            assert_eq!(
                (r[0x21], r[0x22], r[0x24], r[0x34], r[0x61]),
                (
                    0x11081011,
                    base + 0x3a8,
                    base + 0x28c,
                    0x05000001,
                    0x01000000
                )
            );
        }
        let sparse = gen12_media(0x000f00ff & !0x00050082);
        assert_eq!(
            sparse.iter().collect::<Vec<_>>(),
            [Engine::Vcs1, Engine::Vcs7, Engine::Vecs0, Engine::Vecs2]
        );
        assert_eq!(sparse.from_class_instance(2, 1), Some(Engine::Vcs7));
        assert_eq!(sparse.from_class_instance(3, 1), Some(Engine::Vecs2));
        assert_eq!(sparse.decode_hardware_id(0x71), Some(Engine::Vcs7));
        assert_eq!(sparse.decode_hardware_id(0x22), Some(Engine::Vecs2));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12",
        smoke_gen12_media_literal_identity_fuses_and_context
    );

    fn smoke_gen12_nonrender_lrc_workarounds_and_video_ring_literals() -> TestResult {
        let platform = GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::AlderLakeS);
        let generic = [
            0, 0x11000007, 0x2580, 0x00060002, 0x7018, 0x20002000, 0x7300, 0x00400040, 0x7304,
            0x02000200,
        ];
        assert_eq!(gen12_nonrender_seed(), generic);
        let bcs = copy_seed(Engine::Bcs0, platform);
        assert_eq!(&bcs[..10], &generic);
        assert_eq!(&bcs[10..13], &[0x15080001, 0x22204, 0x600]);
        assert_eq!(bcs[17], 0x606);
        assert!(!bcs.contains(&0x6604)); // RCS-only FF_MODE2 never reaches nonrender.
        for (engine, aux) in [(Engine::Vcs7, 0x4218), (Engine::Vecs3, 0x4238)] {
            let words = media_ring(
                engine,
                Some(0x1234_0000_0000),
                Some((0x2345_0000_0090, 0x1122334455667788)),
                0x1000000,
                7,
            );
            assert_eq!(
                &words[..15],
                &[
                    0x04000001, 0x02800101, 0x11020001, aux, 1, 0, 0x13044002, 0x100080c, 0, 7,
                    0x02800100, 0x18800101, 0, 0x1234, 0x04000000
                ]
            );
            assert_eq!(
                &words[15..24],
                &[0x13000002, 0, 0, 0, 0x10200003, 0x90, 0x2345, 0x55667788, 0x11223344]
            );
            assert_eq!(
                &words[24..31],
                &[0x13004002, 0x1000804, 0, 7, 0x01000000, 0x04000001, 0x02800000]
            );
            assert_ne!(words[2] & (1 << 17), 0);
            assert_eq!(words[2] & (1 << 19), 0);
            assert_eq!(words.len(), 32);
            assert!(!words.contains(&0x7a000004));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12",
        smoke_gen12_nonrender_lrc_workarounds_and_video_ring_literals
    );
}
