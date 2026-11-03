//! Live graphics-GT DSS/EU/L3-bank fuses, independent of HWCONFIG maxima.
//!
//! Reference: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! xe_gt_topology.c::{get_num_dss_regs,load_eu_mask,load_l3_bank_mask,
//! gen_l3_mask_from_pattern}, intel_sseu.c's xehp_sseu_info_init and
//! include/uapi/drm/i915_drm.h topology layout.

use crate::{intel_gpu::Generation, intel_gpu_aux::MmioWindow, intel_gpu_gt::GtPlatform};
use alloc::vec::Vec;

/// regs/xe_gt_regs.h fuse mirrors read by load_l3_bank_mask, as offsets in
/// one GT's window (the media GT adds its GSI offset).
pub(crate) const XEHP_FUSE4: u64 = 0x9114;
pub(crate) const MIRROR_FUSE3: u64 = 0x9118;
pub(crate) const MIRROR_L3BANK_ENABLE: u64 = 0x9130;

/// The xe_gt_topology.c::load_l3_bank_mask branch for each admitted device.
/// The branch keys on the device's graphics IP, not on the GT, so the MTL
/// standalone media GT takes its device's `XeLpg` branch too.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum L3Rule {
    /// The final branch (Xe_LP 12.00: TGL, ADL-S/P/N and their RPL IDs):
    /// MIRROR_FUSE3 XELP_GT_L3_MODE_MASK (7:0) inverted, one bit per bank.
    XeLp,
    /// XE_DG2 (Xe_HPG 12.55): eight banks for each MEML3_EN_MASK (3:0) node.
    Dg2,
    /// GRAPHICS_VERx100 >= 1270 below 20 (MTL/Arrow 12.70/12.71/12.74); see
    /// `xelpg_l3_bank_mask`.
    XeLpg,
    /// GRAPHICS_VER 20 (BMG 20.01/20.02, LNL 20.04): the XE2_GT_L3_MODE_MASK
    /// (MIRROR_FUSE3 7:4) banks for each XE2_NODE_ENABLE_MASK (31:16) node.
    Xe2,
    /// GRAPHICS_VER 30 (PTL 30.00/30.01): all 32 XE3_L3BANK_ENABLE bits of
    /// MIRROR_L3BANK_ENABLE for each XE2_NODE_ENABLE_MASK node.
    Xe3,
}

impl L3Rule {
    /// Every GuC-admitted profile has a branch; anything else has none.
    pub(crate) const fn for_platform(platform: GtPlatform) -> Option<Self> {
        Some(match platform {
            GtPlatform::Gen12(_) => Self::XeLp,
            GtPlatform::Alchemist => Self::Dg2,
            GtPlatform::Integrated(Generation::MeteorLake) => Self::XeLpg,
            GtPlatform::Battlemage | GtPlatform::Integrated(Generation::LunarLake) => Self::Xe2,
            GtPlatform::Integrated(Generation::PantherLake) => Self::Xe3,
            GtPlatform::Integrated(_) => return None,
        })
    }

    /// The register load_l3_bank_mask reads after MIRROR_FUSE3, if any.
    pub(crate) const fn second(self) -> Option<u64> {
        match self {
            Self::XeLpg => Some(XEHP_FUSE4),
            Self::Xe3 => Some(MIRROR_L3BANK_ENABLE),
            Self::XeLp | Self::Dg2 | Self::Xe2 => None,
        }
    }

    /// xe_l3_bank_mask_t (XE_MAX_L3_BANK_MASK_BITS = 64) from MIRROR_FUSE3 and
    /// the `second` register (ignored by rules that read none). None only
    /// where Linux defines no result: an Xe3 node above 1 shifts its 32-bit
    /// pattern by 64 or more. gen_l3_mask_from_pattern's xe_assert forbids
    /// that, and bitmap_shift_left's one-word `*src << shift` is then
    /// undefined C. query_gt_topology prefers omitting L3 to bogus data.
    pub(crate) fn mask(self, fuse3: u32, second: u32) -> Option<u64> {
        let nodes = fuse3 >> 16;
        Some(match self {
            Self::XeLp => u64::from(!fuse3 & 0xff),
            Self::Dg2 => replicate(0xff, 8, fuse3 & 0xf),
            Self::XeLpg => xelpg_l3_bank_mask(fuse3, second),
            Self::Xe2 => replicate(u64::from((fuse3 >> 4) & 0xf), 4, nodes),
            Self::Xe3 if nodes > 0b11 => return None,
            Self::Xe3 => replicate(u64::from(second), 32, nodes),
        })
    }
}

/// load_l3_bank_mask for GRAPHICS_VERx100 >= 1270 below graphics 20, shared
/// by every MTL/Arrow GT (GT0 and the standalone media GT): each
/// GT_L3_EXC_MASK (XEHP_FUSE4 6:4) bit sets a two-bank pair of the node
/// pattern, and the pattern repeats every four bits for each MEML3_EN_MASK
/// (MIRROR_FUSE3 3:0) node. Pair 2 reaches into the next node's bits; that
/// breaks the source's xe_assert but stays defined, and is ORed as there.
pub(crate) fn xelpg_l3_bank_mask(fuse3: u32, fuse4: u32) -> u64 {
    let per_node = replicate(0x3, 2, (fuse4 >> 4) & 0x7);
    replicate(per_node, 4, fuse3 & 0xf)
}

/// gen_l3_mask_from_pattern on one 64-bit word: OR `pattern` shifted left by
/// `bit * bits` for each set `mask` bit. Callers keep every shift below 64.
fn replicate(pattern: u64, bits: u32, mask: u32) -> u64 {
    (0..32)
        .filter(|bit| (mask >> bit) & 1 != 0)
        .fold(0, |dst, bit| dst | (pattern << (bit * bits)))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TopologyError {
    Unsupported,
    Unavailable,
    Unstable,
    Empty,
    NoRender,
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_gen12_fuse_inversion_real_slice_and_legacy_topology() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        for family in [
            Gen12Platform::TigerLake,
            Gen12Platform::AlderLakeP,
            Gen12Platform::AlderLakeS,
            Gen12Platform::AlderLakeN,
        ] {
            let platform = GtPlatform::Gen12(family);
            let window = Fuses::new([0x25, u32::MAX, 0xfa]);
            let topology = GtTopology::read(&window, platform).unwrap();
            // Geometry, EU disable and MIRROR_FUSE3, sampled twice.
            assert_eq!(window.reads(), 6);
            assert_eq!(
                (
                    topology.geometry_dss(),
                    topology.compute_dss(),
                    topology.eu_mask_per_dss(),
                    topology.eu_count()
                ),
                (0x25, 0, 0x33, 12)
            );
            let mut expected = [0u8; 30];
            expected[..18]
                .copy_from_slice(&[0, 0, 1, 0, 6, 0, 16, 0, 1, 0, 1, 0, 2, 0, 2, 0, 1, 0x25]);
            for i in [18, 22, 28] {
                expected[i] = 0x33;
            }
            assert_eq!(topology.i915_bytes(false), expected);
            assert_eq!(topology.i915_bytes(true), expected);
            for values in [[0x40, 0, 0], [1, 0, 0x100]] {
                assert_eq!(
                    GtTopology::read(&Fuses::new(values), platform),
                    Err(TopologyError::Unavailable)
                );
            }
            assert_eq!(
                GtTopology::read(&Fuses::new([1, 0, 0xff]), platform),
                Err(TopologyError::Empty)
            );
            let mut changed = Fuses::new([1, 0, 0]);
            changed.flip = Some(0x913c);
            assert_eq!(
                GtTopology::read(&changed, platform),
                Err(TopologyError::Unstable)
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_topology",
        smoke_gen12_fuse_inversion_real_slice_and_legacy_topology
    );

    struct Fuses {
        /// Geometry DSS, compute DSS and EU fuses.
        values: [u32; 3],
        /// MIRROR_FUSE3, XEHP_FUSE4 and MIRROR_L3BANK_ENABLE.
        l3: [u32; 3],
        log: RefCell<Vec<u64>>,
        /// This register's low bit differs on every read after its first,
        /// as if the fuse changed between the two samples.
        flip: Option<u64>,
    }
    impl Fuses {
        fn new(values: [u32; 3]) -> Self {
            Self::with_l3(values, [0; 3])
        }
        fn with_l3(values: [u32; 3], l3: [u32; 3]) -> Self {
            Self {
                values,
                l3,
                log: RefCell::new(Vec::new()),
                flip: None,
            }
        }
        fn reads(&self) -> usize {
            self.log.borrow().len()
        }
    }
    impl MmioWindow for Fuses {
        fn read32(&self, offset: u64) -> u32 {
            let again = self.log.borrow().contains(&offset);
            self.log.borrow_mut().push(offset);
            let value = match offset {
                0x913c => self.values[0],
                0x9144 => self.values[1],
                0x9134 => self.values[2],
                // PTL's second and third geometry/compute DSS words.
                0x9148 | 0x914c | 0x9150 | 0x9154 => 0,
                MIRROR_FUSE3 => self.l3[0],
                XEHP_FUSE4 => self.l3[1],
                MIRROR_L3BANK_ENABLE => self.l3[2],
                _ => panic!("unexpected topology register {offset:x}"),
            };
            value ^ u32::from(again && self.flip == Some(offset))
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("fuse discovery wrote MMIO");
        }
    }

    fn smoke_fuse_topology_platform_vectors() -> TestResult {
        for platform in [
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            GtPlatform::Alchemist,
            GtPlatform::Battlemage,
        ] {
            let window = Fuses::new([5, 6, 5]);
            let topology = GtTopology::read(&window, platform).unwrap();
            // Two samples of geometry, compute, EU and MIRROR_FUSE3, plus
            // XEHP_FUSE4 for the graphics 12.70 L3 rule.
            let mtl = platform == GtPlatform::Integrated(Generation::MeteorLake);
            assert_eq!(window.reads(), if mtl { 10 } else { 8 });
            assert_eq!((topology.geometry_dss(), topology.compute_dss()), (5, 6));
            assert_eq!(topology.dss_count(), 3); // shared DSS counted only once
            if platform.is_xe2() {
                assert_eq!(topology.eu_type(), EuType::Simd16);
                assert_eq!(topology.eu_mask_per_dss(), 5);
                assert_eq!(topology.eu_count(), 6);
            } else {
                assert_eq!(topology.eu_type(), EuType::Simd8);
                assert_eq!(topology.eu_mask_per_dss(), 0x33);
                assert_eq!(topology.eu_count(), 12);
            }
            let full = GtTopology::read(&Fuses::new([0xffffffff, 0, 0xff]), platform).unwrap();
            assert_eq!(full.dss_count(), 32);
            assert_eq!(full.eu_count(), if platform.is_xe2() { 256 } else { 512 });
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_topology",
        smoke_fuse_topology_platform_vectors
    );

    fn smoke_fuse_topology_refusal_and_stability() -> TestResult {
        for (values, error) in [
            ([0, 0, 1], TopologyError::Empty),
            ([1, 0, 0], TopologyError::Empty),
            ([1, 0, 0xffffffff], TopologyError::Unavailable),
            ([1, 0, 0x100], TopologyError::Unavailable),
        ] {
            assert_eq!(
                GtTopology::read(&Fuses::new(values), GtPlatform::Alchemist),
                Err(error)
            );
        }
        let mut window = Fuses::new([1, 0, 1]);
        window.flip = Some(0x913c);
        assert_eq!(
            GtTopology::read(&window, GtPlatform::Battlemage),
            Err(TopologyError::Unstable)
        );
        let window = Fuses::new([1, 0, 1]);
        assert_eq!(
            GtTopology::read(
                &window,
                GtPlatform::Integrated(crate::intel_gpu::Generation::TigerLake)
            ),
            Err(TopologyError::Unsupported)
        );
        assert_eq!(window.reads(), 0);
        let compute = GtTopology::read(&window, GtPlatform::Alchemist).unwrap();
        assert!(compute.has_render());
        let compute =
            GtTopology::read(&Fuses::new([0, 0x80000000, 1]), GtPlatform::Alchemist).unwrap();
        assert!(!compute.has_render());
        assert_eq!(compute.eu_count(), 2);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_topology",
        smoke_fuse_topology_refusal_and_stability
    );

    fn smoke_i915_topology_literal_layouts() -> TestResult {
        // Linux topology header, one software slice, 32 DSS, paired EU mask.
        let topology = GtTopology::read(&Fuses::new([5, 6, 5]), GtPlatform::Alchemist).unwrap();
        let mut expected = [0u8; 85];
        expected[..16].copy_from_slice(&[0, 0, 1, 0, 32, 0, 16, 0, 1, 0, 4, 0, 5, 0, 2, 0]);
        expected[16..21].copy_from_slice(&[1, 7, 0, 0, 0]);
        expected[21..27].copy_from_slice(&[0x33, 0, 0x33, 0, 0x33, 0]);
        assert_eq!(topology.i915_bytes(false), expected);
        expected[17] = 5;
        expected[23..25].fill(0);
        assert_eq!(topology.i915_bytes(true), expected);

        let bmg =
            GtTopology::read(&Fuses::new([0x80000000, 1, 0x81]), GtPlatform::Battlemage).unwrap();
        let mut expected = [0u8; 53];
        expected[..16].copy_from_slice(&[0, 0, 1, 0, 32, 0, 8, 0, 1, 0, 4, 0, 5, 0, 1, 0]);
        expected[16..21].copy_from_slice(&[1, 1, 0, 0, 0x80]);
        expected[21] = 0x81;
        expected[52] = 0x81;
        assert_eq!(bmg.i915_bytes(false), expected);
        expected[17] = 0;
        expected[21] = 0;
        assert_eq!(bmg.i915_bytes(true), expected);
        // drm_i915_query_topology_info has no L3 bank field, so different
        // L3 fuses leave the i915 bytes identical.
        let other_l3 = GtTopology::read(
            &Fuses::with_l3([0x80000000, 1, 0x81], [0x000f_00f0, 0, 0]),
            GtPlatform::Battlemage,
        )
        .unwrap();
        assert_ne!(other_l3.l3_bank_mask(), bmg.l3_bank_mask());
        assert_eq!(other_l3.i915_bytes(false), bmg.i915_bytes(false));
        assert_eq!(other_l3.i915_bytes(true), bmg.i915_bytes(true));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_topology",
        smoke_i915_topology_literal_layouts
    );

    const TGL: GtPlatform = GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake);
    const MTL: GtPlatform = GtPlatform::Integrated(Generation::MeteorLake);
    const LNL: GtPlatform = GtPlatform::Integrated(Generation::LunarLake);
    const PTL: GtPlatform = GtPlatform::Integrated(Generation::PantherLake);

    /// xe_gt_topology.c::load_l3_bank_mask's branches through
    /// gen_l3_mask_from_pattern into the 64-bit xe_l3_bank_mask_t, selected
    /// by the device's graphics IP (xe_pci.c).
    fn smoke_l3_bank_rules_follow_load_l3_bank_mask() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        for (platform, rule) in [
            (TGL, L3Rule::XeLp),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeP), L3Rule::XeLp),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeS), L3Rule::XeLp),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeN), L3Rule::XeLp),
            (GtPlatform::Alchemist, L3Rule::Dg2),
            (MTL, L3Rule::XeLpg),
            (GtPlatform::Battlemage, L3Rule::Xe2),
            (LNL, L3Rule::Xe2),
            (PTL, L3Rule::Xe3),
        ] {
            assert!(platform.guc().is_some());
            assert_eq!(L3Rule::for_platform(platform), Some(rule));
        }
        // Profiles without a GuC have neither a topology nor a branch.
        for generation in [Generation::TigerLake, Generation::AlderLake] {
            let platform = GtPlatform::Integrated(generation);
            assert!(platform.guc().is_none());
            assert_eq!(L3Rule::for_platform(platform), None);
        }
        assert_eq!(
            [
                L3Rule::XeLp,
                L3Rule::Dg2,
                L3Rule::XeLpg,
                L3Rule::Xe2,
                L3Rule::Xe3
            ]
            .map(L3Rule::second),
            [None, None, Some(0x9114), None, Some(0x9130)]
        );
        for (rule, fuse3, second, mask) in [
            // XELP_GT_L3_MODE_MASK of ~MIRROR_FUSE3, one bit per bank.
            (L3Rule::XeLp, 0, 0, Some(0xff)),
            (L3Rule::XeLp, 0x0c, 0, Some(0xf3)), // banks 2 and 3 fused off
            (L3Rule::XeLp, 0xffff_ff00, u32::MAX, Some(0xff)),
            (L3Rule::XeLp, u32::MAX, 0, Some(0)),
            // DG2: eight banks per MEML3_EN_MASK node.
            (L3Rule::Dg2, 0xf, 0, Some(0xffff_ffff)),
            (L3Rule::Dg2, 0b1011, 0, Some(0xff00_ffff)), // node 2 fused off
            (L3Rule::Dg2, 0xffff_fff0, u32::MAX, Some(0)),
            // 12.70: GT_L3_EXC_MASK pairs per MEML3_EN_MASK node.
            (L3Rule::XeLpg, 0b0101, 0b011 << 4, Some(0x0f0f)),
            // Pair 0 fused off; pair 2 reaches into the next node.
            (L3Rule::XeLpg, 0b0011, 0b110 << 4, Some(0x03fc)),
            (L3Rule::XeLpg, 0xf, 0, Some(0)),
            // Xe2: XE2_GT_L3_MODE_MASK per XE2_NODE_ENABLE_MASK node.
            (L3Rule::Xe2, 0x00ff_00f0, 0, Some(0xffff_ffff)),
            (L3Rule::Xe2, 0x0005_00b0, 0, Some(0x0b0b)), // bank 2 fused off
            (L3Rule::Xe2, 0xffff_00f0, 0, Some(u64::MAX)), // all 64 bits
            (L3Rule::Xe2, 0x0001_000f, u32::MAX, Some(0)),
            // Xe3: XE3_L3BANK_ENABLE per XE2_NODE_ENABLE_MASK node.
            (L3Rule::Xe3, 0x0001_0000, u32::MAX, Some(0xffff_ffff)),
            (L3Rule::Xe3, 0x0003_0000, 0xfd, Some(0x0000_00fd_0000_00fd)),
            (L3Rule::Xe3, 0x0002_ffff, 0xf, Some(0x0000_000f_0000_0000)),
            (L3Rule::Xe3, 0x0000_ffff, 0xff, Some(0)),
            // A node above 1 would shift past bit 63: no defined mask.
            (L3Rule::Xe3, 0x0004_0000, 0xff, None),
            (L3Rule::Xe3, 0x8003_0000, 0xff, None),
        ] {
            assert_eq!(rule.mask(fuse3, second), mask, "{rule:?} {fuse3:x}");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_topology",
        smoke_l3_bank_rules_follow_load_l3_bank_mask
    );

    /// load_l3_bank_mask follows load_eu_mask: MIRROR_FUSE3, then XEHP_FUSE4
    /// (12.70) or MIRROR_L3BANK_ENABLE (Xe3). Both samples include them.
    fn smoke_gt_topology_samples_l3_fuses_after_eu_fuses() -> TestResult {
        // MIRROR_FUSE3: Xe2 nodes 0-1, Xe2 L3 mode 0xb, MEML3_EN nodes 0 and 2,
        // XeLP mode 0xb5; XEHP_FUSE4 exclusion pairs 0-1; Xe3 banks 0xfd.
        let l3 = [0x0003_00b5, 0x30, 0xfd];
        let xelp: &[u64] = &[0x913c, 0x9134, 0x9118];
        let xehp: &[u64] = &[0x913c, 0x9144, 0x9134, 0x9118];
        let xelpg: &[u64] = &[0x913c, 0x9144, 0x9134, 0x9118, 0x9114];
        let xe3: &[u64] = &[
            0x913c, 0x9144, 0x9150, 0x9154, 0x9148, 0x914c, 0x9134, 0x9118, 0x9130,
        ];
        for (platform, order, mask) in [
            (TGL, xelp, Some(0x4a)),
            (GtPlatform::Alchemist, xehp, Some(0x00ff_00ff)),
            (MTL, xelpg, Some(0x0f0f)),
            (GtPlatform::Battlemage, xehp, Some(0xbb)),
            (LNL, xehp, Some(0xbb)),
            (PTL, xe3, Some(0x0000_00fd_0000_00fd)),
        ] {
            let window = Fuses::with_l3([5, 6, 5], l3);
            let topology = GtTopology::read(&window, platform).unwrap();
            assert_eq!(topology.l3_bank_mask(), mask);
            assert_eq!(*window.log.borrow(), [order, order].concat());
            for reg in [MIRROR_FUSE3, XEHP_FUSE4, MIRROR_L3BANK_ENABLE] {
                let mut changed = Fuses::with_l3([5, 6, 5], l3);
                changed.flip = Some(reg);
                assert_eq!(
                    GtTopology::read(&changed, platform),
                    if order.contains(&reg) {
                        Err(TopologyError::Unstable)
                    } else {
                        Ok(topology.clone())
                    }
                );
            }
        }
        // An undefined Xe3 mask keeps the topology and omits only L3.
        let window = Fuses::with_l3([5, 6, 5], [0x0007_0000, 0, 0xfd]);
        let topology = GtTopology::read(&window, PTL).unwrap();
        assert_eq!(topology.l3_bank_mask(), None);
        assert_eq!((topology.geometry_dss(), topology.compute_dss()), (5, 6));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_topology",
        smoke_gt_topology_samples_l3_fuses_after_eu_fuses
    );

    /// DRM_XE_DEVICE_QUERY_GT_TOPOLOGY for `topology` alone: size query, an
    /// off-by-one size (EINVAL), then the exact copy.
    fn xe_gt0_topology_query(topology: GtTopology) -> Vec<u8> {
        use crate::intel_gpu_render::{tests::User, DeviceInfo};
        let info = DeviceInfo {
            device_id: 0,
            platform: topology.platform(),
            memory_bytes: 0,
            hwconfig: None,
            topology: Some(alloc::sync::Arc::new(topology)),
            vram: None,
            backend: None,
        };
        let user = User::new();
        let mut wire = [0u8; 40];
        wire[8..12].copy_from_slice(&5u32.to_le_bytes());
        user.store(64, &wire);
        crate::intel_gpu_xe_query::query(&info, 64, &user).unwrap();
        let size = u32::from_le_bytes(user.load(76, 4).try_into().unwrap());
        wire[12..16].copy_from_slice(&(size - 1).to_le_bytes());
        wire[16..24].copy_from_slice(&4096u64.to_le_bytes());
        user.store(64, &wire);
        assert_eq!(
            crate::intel_gpu_xe_query::query(&info, 64, &user),
            Err(narf_filesystem::FsError::InvalidData)
        );
        wire[12..16].copy_from_slice(&size.to_le_bytes());
        user.store(64, &wire);
        crate::intel_gpu_xe_query::query(&info, 64, &user).unwrap();
        user.load(4096, size as usize)
    }

    /// xe_query.c::query_gt_topology reports the primary GT's L3 bank mask
    /// (xe_gt_topology_report_l3 is true for it) as xe_l3_bank_mask_t's 8
    /// bytes between the compute DSS and EU entries.
    fn smoke_xe_gt_topology_query_reports_gt0_l3_bank_entry() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        const SIMD8: [u8; 10] = [0, 0, 4, 0, 2, 0, 0, 0, 0x33, 0];
        const SIMD16: [u8; 10] = [0, 0, 5, 0, 2, 0, 0, 0, 5, 0];
        let dss = |geometry: u8, compute: u8| {
            let mut bytes = alloc::vec![0, 0, 1, 0, 4, 0, 0, 0, geometry, 0, 0, 0];
            bytes.extend([0, 0, 2, 0, 4, 0, 0, 0, compute, 0, 0, 0]);
            bytes
        };
        // TGL/ADL: MIRROR_FUSE3 0x0c disables banks 2 and 3.
        let mut gen12 = dss(0x25, 0);
        gen12.extend([0, 0, 3, 0, 8, 0, 0, 0, 0xf3, 0, 0, 0, 0, 0, 0, 0]);
        gen12.extend(SIMD8);
        for family in [
            Gen12Platform::TigerLake,
            Gen12Platform::AlderLakeP,
            Gen12Platform::AlderLakeS,
            Gen12Platform::AlderLakeN,
        ] {
            let window = Fuses::with_l3([0x25, u32::MAX, 0xfa], [0x0c, 0, 0]);
            let topology = GtTopology::read(&window, GtPlatform::Gen12(family)).unwrap();
            assert_eq!(xe_gt0_topology_query(topology), gen12);
        }
        for (platform, l3, entry, eu) in [
            // DG2: mslice 2 fused off.
            (
                GtPlatform::Alchemist,
                [0b1011, 0, 0],
                [0xff, 0xff, 0, 0xff, 0, 0, 0, 0],
                SIMD8,
            ),
            // MTL/Arrow: bank pair 0 fused off on nodes 0 and 1.
            (
                MTL,
                [0b0011, 0b110 << 4, 0],
                [0xfc, 0x03, 0, 0, 0, 0, 0, 0],
                SIMD8,
            ),
            // BMG: bank 2 fused off on nodes 0 and 2.
            (
                GtPlatform::Battlemage,
                [0x0005_00b0, 0, 0],
                [0x0b, 0x0b, 0, 0, 0, 0, 0, 0],
                SIMD16,
            ),
            // LNL: all sixteen nodes and banks.
            (LNL, [0xffff_00f0, 0, 0], [0xff; 8], SIMD16),
        ] {
            let topology = GtTopology::read(&Fuses::with_l3([5, 6, 5], l3), platform).unwrap();
            let mut expected = dss(5, 6);
            expected.extend([0, 0, 3, 0, 8, 0, 0, 0]);
            expected.extend(entry);
            expected.extend(eu);
            assert_eq!(xe_gt0_topology_query(topology), expected, "{platform:?}");
        }
        // PTL: 12-byte DSS masks; bank 1 fused off on nodes 0 and 1.
        let mut ptl = alloc::vec![0, 0, 1, 0, 12, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ptl.extend([0, 0, 2, 0, 12, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let without_l3 = [ptl.clone(), SIMD16.to_vec()].concat();
        ptl.extend([0, 0, 3, 0, 8, 0, 0, 0, 0xfd, 0, 0, 0, 0xfd, 0, 0, 0]);
        ptl.extend(SIMD16);
        let window = Fuses::with_l3([5, 6, 5], [0x0003_0000, 0, 0xfd]);
        assert_eq!(
            xe_gt0_topology_query(GtTopology::read(&window, PTL).unwrap()),
            ptl
        );
        // A third node has no defined mask: the L3 entry alone is omitted.
        let window = Fuses::with_l3([5, 6, 5], [0x0007_0000, 0, 0xfd]);
        assert_eq!(
            xe_gt0_topology_query(GtTopology::read(&window, PTL).unwrap()),
            without_l3
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_topology",
        smoke_xe_gt_topology_query_reports_gt0_l3_bank_entry
    );
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EuType {
    Simd8,
    Simd16,
}

/// Immutable observed main-GT fuses:32 DSS on existing profiles,96 on
/// exact PTL graphics30.00/30.01, plus the main GT's L3 bank mask. The media
/// GT's fuses live in `intel_gpu_gt::media::MediaTopology`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GtTopology {
    platform: GtPlatform,
    geometry: u128,
    compute: u128,
    eu_mask: u16,
    eu_type: EuType,
    l3_bank: Option<u64>,
}

impl GtTopology {
    /// Caller holds this physical function's GT/render wake and serializes
    /// reset. GuCGt checks current wake again before accepting the snapshot.
    pub(crate) fn read(
        mmio: &impl MmioWindow,
        platform: GtPlatform,
    ) -> Result<Self, TopologyError> {
        platform.guc().ok_or(TopologyError::Unsupported)?;
        let l3 = L3Rule::for_platform(platform);
        // xe_gt_topology.c::get_num_dss_regs: graphics>20 has three
        // words per mask. Preserve holes across all96 source fuse bits.
        let sample = || {
            let mut geometry = u128::from(mmio.read32(0x913c));
            let mut compute = if platform.is_gen12() {
                0
            } else {
                u128::from(mmio.read32(0x9144))
            };
            if platform.is_ptl() {
                geometry |= u128::from(mmio.read32(0x9150)) << 32;
                geometry |= u128::from(mmio.read32(0x9154)) << 64;
                compute |= u128::from(mmio.read32(0x9148)) << 32;
                compute |= u128::from(mmio.read32(0x914c)) << 64;
            }
            let eu = mmio.read32(0x9134);
            // xe_gt_topology_init runs load_l3_bank_mask after load_eu_mask:
            // MIRROR_FUSE3, then the branch's second register, if any.
            let l3_fuses = l3.map(|rule| {
                let fuse3 = mmio.read32(MIRROR_FUSE3);
                (fuse3, rule.second().map_or(0, |reg| mmio.read32(reg)))
            });
            (geometry, compute, eu, l3_fuses)
        };
        let first = sample();
        if first != sample() {
            return Err(TopologyError::Unstable);
        }
        let (geometry, compute, mut raw_eu, l3_fuses) = first;
        // A fully populated 32-DSS mask legitimately reads all ones. The EU
        // register's reserved bits distinguish an unavailable BAR instead.
        if raw_eu & !0xff != 0 {
            return Err(TopologyError::Unavailable);
        }
        if platform.is_gen12() {
            if geometry & !0x3f != 0 {
                return Err(TopologyError::Unavailable);
            }
            raw_eu = !raw_eu & 0xff;
        }
        if geometry | compute == 0 || raw_eu == 0 {
            return Err(TopologyError::Empty);
        }
        let (eu_type, eu_mask) = if platform.is_xe2() {
            (EuType::Simd16, raw_eu as u16)
        } else {
            let mut pairs = 0;
            for bit in 0..8 {
                if raw_eu & (1 << bit) != 0 {
                    pairs |= 3 << (bit * 2);
                }
            }
            (EuType::Simd8, pairs)
        };
        // xe_gt_topology_report_l3 always holds for the primary GT. Linux
        // checks no L3 fuse value; unavailable MMIO is already refused
        // through the EU fuse sampled alongside.
        let l3_bank = l3
            .zip(l3_fuses)
            .and_then(|(rule, (fuse3, second))| rule.mask(fuse3, second));
        Ok(Self {
            platform,
            geometry,
            compute,
            eu_mask,
            eu_type,
            l3_bank,
        })
    }

    pub fn platform(&self) -> GtPlatform {
        self.platform
    }
    pub fn geometry_dss(&self) -> u128 {
        self.geometry
    }
    pub fn compute_dss(&self) -> u128 {
        self.compute
    }
    pub fn eu_mask_per_dss(&self) -> u16 {
        self.eu_mask
    }
    pub fn eu_type(&self) -> EuType {
        self.eu_type
    }
    /// DRM_XE_TOPO_L3_BANK's xe_l3_bank_mask_t; None omits the entry.
    pub fn l3_bank_mask(&self) -> Option<u64> {
        self.l3_bank
    }
    pub fn dss_count(&self) -> u32 {
        (self.geometry | self.compute).count_ones()
    }
    pub fn eu_count(&self) -> u32 {
        self.dss_count() * self.eu_mask.count_ones()
    }
    pub fn has_render(&self) -> bool {
        self.geometry != 0
    }

    /// i915's single software slice contains 32 DSS bits, preserving holes.
    /// This metadata grants no userspace execution or engine authority.
    pub(crate) fn i915_bytes(&self, geometry_only: bool) -> Vec<u8> {
        let mask = if geometry_only {
            self.geometry
        } else {
            self.geometry | self.compute
        };
        let width = if self.eu_type == EuType::Simd16 {
            8u16
        } else {
            16
        };
        let stride = usize::from(width / 8);
        // i915 gen12_sseu_info_init: one real slice, six dual-subslices.
        // The XeHP single software slice uses the full32-bit DSS register.
        let (dss_count, subslice_stride) = if self.platform.is_gen12() {
            (6usize, 1usize)
        } else if self.platform.is_ptl() {
            (96, 12)
        } else {
            (32, 4)
        };
        let eu_start = 17 + subslice_stride;
        let mut bytes = alloc::vec![0; eu_start + dss_count * stride];
        for (index, value) in [
            0u16,
            1,
            dss_count as u16,
            width,
            1,
            subslice_stride as u16,
            (1 + subslice_stride) as u16,
            stride as u16,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[16] = u8::from(mask != 0);
        bytes[17..eu_start].copy_from_slice(&mask.to_le_bytes()[..subslice_stride]);
        for dss in 0..dss_count {
            if mask & (1 << dss) != 0 {
                let start = eu_start + dss * stride;
                bytes[start..start + stride].copy_from_slice(&self.eu_mask.to_le_bytes()[..stride]);
            }
        }
        bytes
    }
}
