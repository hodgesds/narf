//! GuC-scheduled graphics-GT engines and the copy engine's literal codecs.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_pci.c engine
//! masks (BCS0 is never fused on Xe-LPG, Xe-HPG or Xe2-HPG; read_copy_fuses
//! applies only to PVC and Xe3+), xe_hw_engine.c, xe_lrc.c
//! {gen12_xcs,xe2_bcs}_offsets, xe_ring_ops.c::__emit_job_gen12_simple,
//! xe_gt.c::emit_wa_job, xe_hw_engine_setup_default_lrc_state and
//! regs/xe_engine_regs.h. CCS0 follows xe_gt_ccs_mode.c's default ccs_mode 1
//! (all compute slices on CCS0; CCS1-3 never exposed) and xe_hw_engine.c's
//! compute fuses. BMG's architecture-present BCS8 is ordinary COPY1 while
//! USM is absent. A future USM owner must reserve/revoke that user engine.
//! Media engines remain unadmitted.

use crate::{intel_gpu_gt::GtPlatform, intel_gpu_rcs::GpuBacking};
use alloc::vec::Vec;

/// Engine-state page offset of the register state within every LRC image.
pub(crate) const REGS: u64 = 4096;
/// Driver-defined PPHWSP breadcrumb and job-start stamp.
pub(crate) const BREADCRUMB: u64 = 0x800;
const START: u64 = BREADCRUMB + 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Engine {
    Rcs0,
    Bcs0,
    Bcs8,
    Ccs0,
}

/// The engines a GT publishes, decided from fuses before scheduling starts.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct EngineSet(u8);

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
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & ((1 << Engine::COUNT) - 1))
    }
    pub fn contains(self, engine: Engine) -> bool {
        self.0 & 1 << engine as u8 != 0
    }
    /// Present engines in `Engine::ALL` (xe_hw_engine id) order.
    pub fn iter(self) -> impl Iterator<Item = Engine> {
        Engine::ALL.into_iter().filter(move |e| self.contains(*e))
    }
}

/// Physically present compute instances (bit n = CCSn), from
/// xe_hw_engine.c::read_compute_fuses. Xe-LPG has exactly one CCS; Xe-HPG
/// infers CCSn from DSS in quadrant n; Xe2 reads XEHP_FUSE4 CCS_EN.
pub(crate) fn compute_instances(platform: GtPlatform, dss: u32, fuse4: u32) -> u8 {
    match platform {
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

/// xe_gt_ccs_mode.c::__xe_gt_apply_ccs_mode with one exposed engine: every
/// present compute slice is assigned to CCS0, absent slices stay disabled.
/// `None` when at most one CCS exists (CCS mode is not enabled).
pub(crate) fn ccs_mode(instances: u8) -> Option<u32> {
    if instances.count_ones() <= 1 {
        return None;
    }
    let mut mode = 0xfff; // CCS_MODE_CSLICE_0_3_MASK: all disabled
    for slice in 0..4 {
        if instances & 1 << slice != 0 {
            mode &= !(7 << (slice * 3)); // CCS0
        }
    }
    Some(mode | 0xfff << 16)
}

impl Engine {
    pub const COUNT: usize = 4;
    pub const ALL: [Engine; Self::COUNT] = [Engine::Rcs0, Engine::Bcs0, Engine::Bcs8, Engine::Ccs0];

    pub(crate) fn index(self) -> usize {
        self as usize
    }
    pub(crate) fn base(self) -> u32 {
        match self {
            Engine::Rcs0 => 0x2000,
            Engine::Bcs0 => 0x22000,
            Engine::Bcs8 => 0x3ee000,
            Engine::Ccs0 => 0x1a000,
        }
    }
    /// GUC_RENDER_CLASS / GUC_BLITTER_CLASS / GUC_COMPUTE_CLASS.
    pub(crate) fn guc_class(self) -> u32 {
        match self {
            Engine::Rcs0 => 0,
            Engine::Bcs0 | Engine::Bcs8 => 3,
            Engine::Ccs0 => 4,
        }
    }
    /// DRM_XE_ENGINE_CLASS_RENDER / _COPY / _COMPUTE (also i915 UABI).
    pub fn xe_class(self) -> u16 {
        match self {
            Engine::Rcs0 => 0,
            Engine::Bcs0 | Engine::Bcs8 => 1,
            Engine::Ccs0 => 4,
        }
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn from_xe_class(class: u16) -> Option<Self> {
        Self::from_class_instance(class, 0)
    }
    /// Public logical instances are dense within a class; GuC ADS maps
    /// COPY1 to hardware BCS8 (xe_hw_engine_setup_logical_mapping).
    pub fn logical_instance(self) -> u16 {
        if self == Self::Bcs8 {
            1
        } else {
            0
        }
    }
    pub(crate) fn physical_instance(self) -> u32 {
        if self == Self::Bcs8 {
            8
        } else {
            0
        }
    }
    pub(crate) fn submit_mask(self) -> u32 {
        1 << self.logical_instance()
    }
    pub(crate) fn is_copy(self) -> bool {
        matches!(self, Self::Bcs0 | Self::Bcs8)
    }
    pub(crate) fn from_class_instance(class: u16, instance: u16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|e| e.xe_class() == class && e.logical_instance() == instance)
    }
    /// xe_gt_lrc_size: PPHWSP plus the class's engine context image.
    pub(crate) fn lrc_pages(self, platform: GtPlatform) -> u32 {
        match (self, platform) {
            (Engine::Rcs0, GtPlatform::Battlemage) => 4,
            (Engine::Rcs0, _) => 14,
            (Engine::Bcs0 | Engine::Bcs8, _) => 2,
            (Engine::Ccs0, GtPlatform::Battlemage) => 3,
            (Engine::Ccs0, _) => 14,
        }
    }
    /// First MI_LOAD_REGISTER_IMM header of the hardware-saved image.
    pub(crate) fn first_lri(self, platform: GtPlatform) -> u32 {
        if self.is_copy() && platform != GtPlatform::Battlemage {
            0x11081019 // gen12_xcs_offsets: 13 registers, no PRT_BB_STATE
        } else {
            0x1108101d
        }
    }
}

/// xe_hw_engine_enable_ring for the GuC-owned engine. Render-well and GT
/// wake are held by the owner; MOCS defaults follow RING_CMD_CCTL.
pub(crate) fn enable_ring(
    mmio: &impl crate::intel_gpu_aux::MmioWindow,
    engine: Engine,
    platform: GtPlatform,
    hwsp: u32,
) {
    let base = u64::from(engine.base());
    let uc = uncached_mocs(platform);
    // hw_engine_setup_default_state: discrete Xe2 compute reads use WB.
    let read = if engine == Engine::Ccs0 && platform == GtPlatform::Battlemage {
        4
    } else {
        uc
    };
    if engine == Engine::Ccs0 {
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
    alloc::vec![
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
    ]
}

/// Default CCS LRC state: xe_hw_engine_setup_default_lrc_state's only
/// compute entry on these platforms, the Xe2 WMTP-disabled preemption level
/// (CS_CHICKEN1 PREEMPT_GPGPU_THREAD_GROUP_LEVEL, masked). No 3D state.
pub(crate) fn compute_seed(platform: GtPlatform, disable_wmtp: bool) -> Vec<u32> {
    if platform == GtPlatform::Battlemage && disable_wmtp {
        alloc::vec![0x11000001, Engine::Ccs0.base() + 0x580, 0x00060002]
    } else {
        Vec::new()
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
    let xe2 = platform == GtPlatform::Battlemage;
    let mut first: Vec<u32> = alloc::vec![
        0x244, 0x034, 0x030, 0x038, 0x03c, 0x168, 0x140, 0x110, 0x1c0, 0x1c4, 0x1c8, 0x180, 0x2b4,
    ];
    if xe2 || engine == Engine::Ccs0 {
        first.extend_from_slice(&[0x120, 0x124]);
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
    image.write32(REGS + 0x71 * 4, 0x01000000); // reset_stop_ring, IP >= 12.50
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
            Engine::ALL.map(|e| (e.base(), e.guc_class(), e.xe_class())),
            [
                (0x2000, 0, 0),
                (0x22000, 3, 1),
                (0x3ee000, 3, 1),
                (0x1a000, 4, 4)
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
        assert_eq!(ccs_mode(1), None);
        assert_eq!(ccs_mode(0xf), Some(0x0fff_0000));
        assert_eq!(ccs_mode(0b1010), Some(0x0fff_0000 | 0b111_000_111));
        assert_eq!(Engine::from_xe_class(1), Some(Engine::Bcs0));
        assert_eq!(Engine::from_xe_class(4), Some(Engine::Ccs0));
        assert_eq!(Engine::from_xe_class(2), None);
        assert_eq!(Engine::from_class_instance(1, 1), Some(Engine::Bcs8));
        assert_eq!(Engine::from_class_instance(1, 8), None);
        assert_eq!(
            (
                Engine::Bcs8.physical_instance(),
                Engine::Bcs8.logical_instance(),
                Engine::Bcs8.submit_mask()
            ),
            (8, 1, 2)
        );
        assert_eq!(EngineSet::from_bits(0xff), EngineSet::of(&Engine::ALL));
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
}
