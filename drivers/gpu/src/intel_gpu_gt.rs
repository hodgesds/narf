//! GT identity is separate from display admission. Reference checkout:
//! ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! include/drm/intel/pciids.h and drivers/gpu/drm/xe/xe_uc_fw.c (MIT).

use crate::intel_gpu::Generation;

// GuC addresses below WOPCM bypass the GGTT. Reserve the largest WOPCM
// accepted from already-locked firmware layouts (xe_wopcm.c: MAX_WOPCM_SIZE).
pub(crate) const GUC_GGTT_MIN: u32 = 8 * 1024 * 1024;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GtPlatform {
    Integrated(Generation),
    Alchemist,
    Battlemage,
}

// Exact source IDs, including mobile/embedded variants; no range matches.
const DG2_IDS: &[u16] = &[
    0x56a0, 0x56a1, 0x56a2, 0x56be, 0x56bf, 0x5690, 0x5691, 0x5692, 0x56a5, 0x56a6, 0x56b0, 0x56b1,
    0x56ba, 0x56bb, 0x56bc, 0x56bd, 0x5693, 0x5694, 0x5695, 0x56a3, 0x56a4, 0x56b2, 0x56b3, 0x5696,
    0x5697,
];
const BMG_IDS: &[u16] = &[
    0xe202, 0xe209, 0xe20b, 0xe20c, 0xe20d, 0xe210, 0xe211, 0xe212, 0xe216, 0xe220, 0xe221, 0xe222,
    0xe223,
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GuCProfile {
    pub platform: GtPlatform,
    pub firmware: &'static str,
    pub minimum_version: (u8, u8, u8),
}

impl GtPlatform {
    pub fn from_pci(vendor: u16, device: u16) -> Option<Self> {
        if vendor != 0x8086 {
            return None;
        }
        if let Some(entry) = crate::intel_gpu::DEVICE_TABLE
            .iter()
            .find(|entry| entry.did == device)
        {
            return Some(Self::Integrated(entry.generation));
        }
        if DG2_IDS.contains(&device) {
            Some(Self::Alchemist)
        } else if BMG_IDS.contains(&device) {
            Some(Self::Battlemage)
        } else {
            None
        }
    }

    pub const fn is_discrete(self) -> bool {
        matches!(self, Self::Alchemist | Self::Battlemage)
    }

    /// Supported GuC boot ABI, not permission to publish a display or engine.
    pub const fn guc(self) -> Option<GuCProfile> {
        let (firmware, minimum_version) = match self {
            Self::Integrated(Generation::MeteorLake) => ("i915/mtl_guc_70.bin", (70, 53, 0)),
            Self::Alchemist => ("i915/dg2_guc_70.bin", (70, 53, 0)),
            Self::Battlemage => ("xe/bmg_guc_70.bin", (70, 54, 0)),
            _ => return None,
        };
        Some(GuCProfile {
            platform: self,
            firmware,
            minimum_version,
        })
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_gt_identity_and_firmware_profiles() -> TestResult {
        for (device, platform, name, version) in [
            (
                0x7d55,
                GtPlatform::Integrated(Generation::MeteorLake),
                "i915/mtl_guc_70.bin",
                (70, 53, 0),
            ),
            (
                0x7d51,
                GtPlatform::Integrated(Generation::MeteorLake),
                "i915/mtl_guc_70.bin",
                (70, 53, 0),
            ),
            (
                0x56a0,
                GtPlatform::Alchemist,
                "i915/dg2_guc_70.bin",
                (70, 53, 0),
            ),
            (
                0x5697,
                GtPlatform::Alchemist,
                "i915/dg2_guc_70.bin",
                (70, 53, 0),
            ),
            (
                0xe20b,
                GtPlatform::Battlemage,
                "xe/bmg_guc_70.bin",
                (70, 54, 0),
            ),
            (
                0xe223,
                GtPlatform::Battlemage,
                "xe/bmg_guc_70.bin",
                (70, 54, 0),
            ),
        ] {
            if GtPlatform::from_pci(0x8086, device) != Some(platform)
                || platform.guc().map(|p| (p.firmware, p.minimum_version)) != Some((name, version))
            {
                return TestResult::Fail("source-defined GT/firmware profile");
            }
        }
        if GtPlatform::from_pci(0x1002, 0x56a0).is_some()
            || GtPlatform::from_pci(0x8086, 0x56a7).is_some()
            || GtPlatform::Integrated(Generation::PantherLake)
                .guc()
                .is_some()
            || DG2_IDS.len() != 25
            || BMG_IDS.len() != 13
        {
            return TestResult::Fail("unsupported GT or approximate PCI range admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_identity_and_firmware_profiles
    );
}
