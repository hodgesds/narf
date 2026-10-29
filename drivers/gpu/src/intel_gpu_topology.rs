//! Live graphics-GT DSS/EU fuses, independent of HWCONFIG capability maxima.
//!
//! Reference: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! xe_gt_topology.c::{get_num_dss_regs,load_eu_mask}, intel_sseu.c's
//! xehp_sseu_info_init and include/uapi/drm/i915_drm.h topology layout.

use crate::{intel_gpu_aux::MmioWindow, intel_gpu_gt::GtPlatform};
use alloc::vec::Vec;

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
    use core::cell::Cell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Fuses {
        values: [u32; 3],
        reads: Cell<u32>,
        change: bool,
    }
    impl Fuses {
        fn new(values: [u32; 3]) -> Self {
            Self {
                values,
                reads: Cell::new(0),
                change: false,
            }
        }
    }
    impl MmioWindow for Fuses {
        fn read32(&self, offset: u64) -> u32 {
            let count = self.reads.get();
            self.reads.set(count + 1);
            match offset {
                0x913c if self.change && count >= 3 => self.values[0] ^ 1,
                0x913c => self.values[0],
                0x9144 => self.values[1],
                0x9134 => self.values[2],
                _ => panic!("unexpected topology register {offset:x}"),
            }
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
            assert_eq!(window.reads.get(), 6);
            assert_eq!((topology.geometry_dss(), topology.compute_dss()), (5, 6));
            assert_eq!(topology.dss_count(), 3); // shared DSS counted only once
            if platform == GtPlatform::Battlemage {
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
            assert_eq!(
                full.eu_count(),
                if platform == GtPlatform::Battlemage {
                    256
                } else {
                    512
                }
            );
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
        window.change = true;
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
        assert_eq!(window.reads.get(), 0);
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
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_topology",
        smoke_i915_topology_literal_layouts
    );
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EuType {
    Simd8,
    Simd16,
}

/// Immutable observed fuses for the main graphics GT. Media GTs and future
/// multi-register DSS formats require their own discovery profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GtTopology {
    platform: GtPlatform,
    geometry: u32,
    compute: u32,
    eu_mask: u16,
    eu_type: EuType,
}

impl GtTopology {
    /// Caller holds this physical function's GT/render wake and serializes
    /// reset. GuCGt checks current wake again before accepting the snapshot.
    pub(crate) fn read(
        mmio: &impl MmioWindow,
        platform: GtPlatform,
    ) -> Result<Self, TopologyError> {
        platform.guc().ok_or(TopologyError::Unsupported)?;
        // All three admitted profiles use one geometry and one compute fuse
        // register. Xe2 version 20 does NOT use Xe3's three-register format.
        let sample = || {
            [
                mmio.read32(0x913c),
                mmio.read32(0x9144),
                mmio.read32(0x9134),
            ]
        };
        let first = sample();
        if first != sample() {
            return Err(TopologyError::Unstable);
        }
        let [geometry, compute, raw_eu] = first;
        // A fully populated 32-DSS mask legitimately reads all ones. The EU
        // register's reserved bits distinguish an unavailable BAR instead.
        if raw_eu & !0xff != 0 {
            return Err(TopologyError::Unavailable);
        }
        if geometry | compute == 0 || raw_eu == 0 {
            return Err(TopologyError::Empty);
        }
        let (eu_type, eu_mask) = if platform == GtPlatform::Battlemage {
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
        Ok(Self {
            platform,
            geometry,
            compute,
            eu_mask,
            eu_type,
        })
    }

    pub fn platform(&self) -> GtPlatform {
        self.platform
    }
    pub fn geometry_dss(&self) -> u32 {
        self.geometry
    }
    pub fn compute_dss(&self) -> u32 {
        self.compute
    }
    pub fn eu_mask_per_dss(&self) -> u16 {
        self.eu_mask
    }
    pub fn eu_type(&self) -> EuType {
        self.eu_type
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
        let mut bytes = alloc::vec![0; 21 + 32 * stride];
        for (index, value) in [0u16, 1, 32, width, 1, 4, 5, stride as u16]
            .into_iter()
            .enumerate()
        {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[16] = u8::from(mask != 0);
        bytes[17..21].copy_from_slice(&mask.to_le_bytes());
        for dss in 0..32 {
            if mask & (1 << dss) != 0 {
                let start = 21 + dss * stride;
                bytes[start..start + stride].copy_from_slice(&self.eu_mask.to_le_bytes()[..stride]);
            }
        }
        bytes
    }
}
