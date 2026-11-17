//! GT identity is separate from display admission. Reference checkout:
//! ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! include/drm/intel/pciids.h and drivers/gpu/drm/xe/{xe_uc_fw.c,
//! xe_force_wake.c,regs/xe_gt_regs.h} (MIT).

use crate::intel_gpu::Generation;

#[path = "intel_gpu_gen12_gt.rs"]
pub(crate) mod gen12;

#[path = "intel_gpu_gt_ownership.rs"]
pub(crate) mod ownership;

#[path = "intel_gpu_lnl_takeover.rs"]
pub(crate) mod lnl;

#[path = "intel_gpu_bmg_smallbar.rs"]
pub(crate) mod smallbar;

#[path = "intel_gpu_media_gt.rs"]
pub(crate) mod media;

/// The MTL/Arrow GSC proxy's CSME end (`i915_gsc_proxy_component_ops`): a
/// MEI GSC proxy client binds here (gsc_proxy_component_bind/unbind).
pub use media::gsc::load::{register_csme_proxy, unregister_csme_proxy, CsmeProxy};

/// The default-off pre-separator Intel opt-in grammar shared by
/// `narf.intel.huc`, `narf.intel.bmg_smallbar` and `narf.intel.media_gt`:
/// exactly one `name=1` before the first `--`. A bare, malformed or
/// duplicate occurrence refuses the option; post-separator init arguments
/// neither enable nor negate it.
pub(crate) fn boot_opt_in(args: narf_boot::args::KernelCmdline<'_>, name: &str) -> bool {
    let mut enabled = false;
    for token in args.tokens().take_while(|token| *token != "--") {
        let Some(rest) = token.strip_prefix(name) else {
            continue;
        };
        if rest.is_empty() {
            return false;
        }
        if let Some(value) = rest.strip_prefix('=') {
            if enabled || value != "1" {
                return false;
            }
            enabled = true;
        }
    }
    enabled
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GraphicsError {
    Unsupported,
    Unavailable,
    Unstable,
}

/// A matched graphics-GT IP, sampled with current forcewake by its owner.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct GraphicsIp {
    pub version: u16,
    pub step: u8,
}

impl GraphicsIp {
    pub(crate) fn read(
        mmio: &impl crate::intel_gpu_aux::MmioWindow,
        platform: GtPlatform,
    ) -> Result<Self, GraphicsError> {
        platform.guc().ok_or(GraphicsError::Unsupported)?;
        if platform.is_gen12() {
            // xe_pci.c's pre-GMD descriptor; these GTs have no GMD_ID.
            return Ok(Self {
                version: if platform == GtPlatform::Gen12(Gen12Platform::Dg1) {
                    1210
                } else {
                    1200
                },
                step: 0,
            });
        }
        if platform.is_dg2() {
            return Ok(Self {
                version: 1255,
                step: 0,
            });
        }
        let a = mmio.read32(0xd8c);
        let b = mmio.read32(0xd8c);
        if a == u32::MAX || b == u32::MAX {
            return Err(GraphicsError::Unavailable);
        }
        if a != b {
            return Err(GraphicsError::Unstable);
        }
        let version = (a >> 22) * 100 + ((a >> 14) & 255);
        let supported = match platform {
            GtPlatform::Battlemage => matches!(version, 2001 | 2002),
            GtPlatform::WildcatLake => matches!(version, 3003..=3005),
            GtPlatform::NovaLakeS => matches!(version, 3003..=3005),
            GtPlatform::Integrated(Generation::LunarLake) => version == 2004,
            GtPlatform::Integrated(Generation::PantherLake) => matches!(version, 3000 | 3001),
            _ => matches!(version, 1270 | 1271 | 1274),
        };
        if !supported {
            return Err(GraphicsError::Unsupported);
        }
        Ok(Self {
            version: version as u16,
            step: (a & 63) as u8,
        })
    }
}

// GuC addresses below WOPCM bypass the GGTT. Reserve the largest WOPCM
// accepted from already-locked firmware layouts (xe_wopcm.c: MAX_WOPCM_SIZE).
pub(crate) const GUC_GGTT_MIN: u32 = 8 * 1024 * 1024;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GtPlatform {
    Integrated(Generation),
    Gen12(Gen12Platform),
    /// Wildcat Lake: PTL device descriptor/firmware, distinct 30.02 media
    /// and 30.03-30.05 graphics GMD contract.
    WildcatLake,
    /// Nova Lake-S: distinct 70.55.4 GuC with display/media 35.00 and the
    /// source Xe3-LPG graphics 30.03-30.05 live-GMD set.
    NovaLakeS,
    /// Arctic Sound-M: display-less DG2 accelerator identity. NARF owns only
    /// the physical function with SR-IOV disabled; VF lifecycle stays refused.
    ArcticSoundM,
    Alchemist,
    Battlemage,
}

/// Exact pre-GMD firmware families (xe_pci.c + xe_uc_fw.c). Raptor Lake
/// inherits the corresponding ADL P/S descriptor, not a guessed firmware.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Gen12Platform {
    TigerLake,
    RocketLake,
    /// DG1 — discrete Xe-LP+ graphics 12.10, not a DG2 alias.
    Dg1,
    AlderLakeP,
    AlderLakeS,
    AlderLakeN,
}

// Exact source IDs, including mobile/embedded variants; no range matches.
pub(crate) const PTL_IDS: &[u16] = &[
    0xb080, 0xb081, 0xb082, 0xb083, 0xb084, 0xb085, 0xb086, 0xb087, 0xb08f, 0xb090, 0xb0a0, 0xb0b0,
];
pub(crate) const WCL_IDS: &[u16] = &[0xfd80, 0xfd81];
pub(crate) const NVLS_IDS: &[u16] = &[0xd740, 0xd741, 0xd742, 0xd743, 0xd744, 0xd745];
pub(crate) const DG2_IDS: &[u16] = &[
    0x56a0, 0x56a1, 0x56a2, 0x56be, 0x56bf, 0x5690, 0x5691, 0x5692, 0x56a5, 0x56a6, 0x56b0, 0x56b1,
    0x56ba, 0x56bb, 0x56bc, 0x56bd, 0x5693, 0x5694, 0x5695, 0x56a3, 0x56a4, 0x56b2, 0x56b3, 0x5696,
    0x5697,
];
pub(crate) const DG1_IDS: &[u16] = &[0x4905, 0x4906, 0x4907, 0x4908, 0x4909];
pub(crate) const BMG_IDS: &[u16] = &[
    0xe202, 0xe209, 0xe20b, 0xe20c, 0xe20d, 0xe210, 0xe211, 0xe212, 0xe216, 0xe220, 0xe221, 0xe222,
    0xe223,
];

/// Linux `dg2_g10_ids`: DG2 G10 plus ATS-M150.
pub(crate) const fn is_dg2_g10(device: u16) -> bool {
    matches!(
        device,
        0x56a0 | 0x56a1 | 0x56a2 | 0x56be | 0x56bf | 0x5690 | 0x5691 | 0x5692 | 0x56c0 | 0x56c2
    )
}

/// Linux `dg2_g11_ids`: DG2 G11 plus ATS-M75.
pub(crate) const fn is_dg2_g11(device: u16) -> bool {
    matches!(
        device,
        0x56a5
            | 0x56a6
            | 0x56b0
            | 0x56b1
            | 0x56ba
            | 0x56bb
            | 0x56bc
            | 0x56bd
            | 0x5693
            | 0x5694
            | 0x5695
            | 0x56c1
    )
}

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
            if entry.generation == Generation::PantherLake
                && !PTL_IDS.contains(&device)
                && !WCL_IDS.contains(&device)
                && !NVLS_IDS.contains(&device)
            {
                return None;
            }
            let family = match entry.asic {
                "tigerlake" => Some(Gen12Platform::TigerLake),
                "rocketlake" => Some(Gen12Platform::RocketLake),
                "alderlake-p" | "alderlake-m" | "raptorlake-p" => Some(Gen12Platform::AlderLakeP),
                "alderlake-s" | "raptorlake-s" => Some(Gen12Platform::AlderLakeS),
                "alderlake-n" => Some(Gen12Platform::AlderLakeN),
                _ => None,
            };
            if entry.asic == "wildcatlake" {
                return Some(Self::WildcatLake);
            }
            if entry.asic == "novalake-s" {
                return Some(Self::NovaLakeS);
            }
            return Some(family.map_or(Self::Integrated(entry.generation), Self::Gen12));
        }
        if DG1_IDS.contains(&device) {
            Some(Self::Gen12(Gen12Platform::Dg1))
        } else if crate::intel_gpu::ATSM_IDS.contains(&device) {
            Some(Self::ArcticSoundM)
        } else if DG2_IDS.contains(&device) {
            Some(Self::Alchemist)
        } else if BMG_IDS.contains(&device) {
            Some(Self::Battlemage)
        } else {
            None
        }
    }

    pub const fn is_discrete(self) -> bool {
        matches!(
            self,
            Self::Gen12(Gen12Platform::Dg1)
                | Self::ArcticSoundM
                | Self::Alchemist
                | Self::Battlemage
        )
    }

    /// Physical display-engine presence from the source device descriptor.
    /// This is distinct from whether NARF has admitted a KMS route.
    pub const fn has_display(self) -> bool {
        !matches!(self, Self::ArcticSoundM)
    }

    /// Source descriptor fan-control capability. ATS-M shares DG2 graphics
    /// mechanics but deliberately omits retail Arc's fan-control feature.
    pub const fn has_fan_control(self) -> bool {
        matches!(self, Self::Alchemist | Self::Battlemage)
    }

    /// Source `xe_device_desc.has_sriov`. NARF implements no VF lifecycle, so
    /// these families retain a current PF-only proof for every GT/GGTT access.
    pub const fn has_sriov(self) -> bool {
        matches!(
            self,
            Self::Gen12(Gen12Platform::TigerLake)
                | Self::Gen12(Gen12Platform::AlderLakeP)
                | Self::Gen12(Gen12Platform::AlderLakeS)
                | Self::Gen12(Gen12Platform::AlderLakeN)
                | Self::Integrated(Generation::PantherLake)
                | Self::WildcatLake
                | Self::ArcticSoundM
                | Self::Battlemage
        )
    }

    pub const fn is_gen12(self) -> bool {
        matches!(self, Self::Gen12(_))
    }

    /// Shared Xe-HPG 12.55 mechanics. ATS-M remains a distinct policy
    /// identity even though Linux assigns it the DG2 platform architecture.
    pub const fn is_dg2(self) -> bool {
        matches!(self, Self::ArcticSoundM | Self::Alchemist)
    }

    /// Architecture properties are independent of discrete-memory ownership.
    pub const fn is_lnl(self) -> bool {
        matches!(self, Self::Integrated(Generation::LunarLake))
    }
    pub const fn is_ptl(self) -> bool {
        matches!(
            self,
            Self::Integrated(Generation::PantherLake) | Self::WildcatLake
        )
    }
    /// Xe3-LPG graphics 30.xx topology/register family. NVL-S shares these
    /// mechanics but not policy keyed specifically to XE_PANTHERLAKE.
    pub const fn is_xe3_lpg(self) -> bool {
        self.is_ptl() || matches!(self, Self::NovaLakeS)
    }
    /// PCI families eligible for the display-30 route. Nova Lake-S shares
    /// Xe3 GT machinery but its display is 35.00 and must never pass this gate.
    pub const fn has_ptl_display_route(self) -> bool {
        matches!(
            self,
            Self::Integrated(Generation::PantherLake) | Self::WildcatLake
        )
    }
    /// Integrated GT-only profiles with retained full-device takeover.
    pub const fn is_headless_integrated(self) -> bool {
        self.is_lnl() || self.is_xe3_lpg()
    }
    /// xe_pci.c graphics_xe2 descriptor, shared by qualified Xe2 and Xe3-LPG.
    pub const fn is_xe2(self) -> bool {
        self.is_headless_integrated() || matches!(self, Self::Battlemage)
    }
    pub const fn multiple_ccs(self) -> bool {
        self.is_dg2() || matches!(self, Self::Battlemage) || self.is_headless_integrated()
    }
    /// DG1 introduced the tile-master interrupt register even though its
    /// graphics IP remains in the pre-GMD Gen12 family.
    pub(crate) const fn has_tile_irq(self) -> bool {
        !self.is_gen12() || matches!(self, Self::Gen12(Gen12Platform::Dg1))
    }
    pub(crate) const fn ppgtt_root_level(self) -> u8 {
        if self.is_headless_integrated() {
            4
        } else {
            3
        }
    }
    pub(crate) const fn pte_format(self) -> crate::intel_gpu_gtt::PteFormat {
        if self.is_headless_integrated() {
            crate::intel_gpu_gtt::PteFormat::Xe2
        } else if self.is_gen12() || self.is_dg2() {
            crate::intel_gpu_gtt::PteFormat::Gen12
        } else {
            crate::intel_gpu_gtt::PteFormat::XeLpg
        }
    }

    pub(crate) const fn physical_bits(self) -> u32 {
        match self {
            Self::Gen12(_) => 39,
            // Current Linux xe descriptors give every admitted post-Gen12
            // platform a 46-bit DMA mask. PTE address capacity is a separate
            // contract and must not widen DMA admission (notably DG2/BMG).
            Self::Integrated(
                Generation::MeteorLake | Generation::LunarLake | Generation::PantherLake,
            )
            | Self::WildcatLake
            | Self::NovaLakeS
            | Self::ArcticSoundM
            | Self::Alchemist
            | Self::Battlemage => 46,
            Self::Integrated(
                Generation::TigerLake | Generation::RocketLake | Generation::AlderLake,
            ) => 39,
        }
    }

    /// xe_guc_hwconfig.c: only ADL-P among pre-XeHP families supplies a
    /// HWCONFIG table. Absence is a platform property, never a guessed table.
    pub const fn has_hwconfig(self) -> bool {
        !matches!(self, Self::Gen12(family) if !matches!(family, Gen12Platform::AlderLakeP))
    }

    /// Graphics-GT forcewake ACK (xe_force_wake_init_gt / xe_gt_regs.h).
    /// Gfx 12.70+ moved the GT ACK; DG2 retains the earlier address.
    pub const fn guc_forcewake_ack(self) -> Option<u64> {
        match self {
            Self::Integrated(
                Generation::MeteorLake | Generation::LunarLake | Generation::PantherLake,
            )
            | Self::WildcatLake
            | Self::NovaLakeS
            | Self::Battlemage => Some(0xdfc),
            Self::ArcticSoundM | Self::Alchemist | Self::Gen12(_) => Some(0x130044),
            _ => None,
        }
    }

    /// Supported GuC boot ABI, not permission to publish a display or engine.
    pub const fn guc(self) -> Option<GuCProfile> {
        let (firmware, minimum_version) = match self {
            Self::Gen12(Gen12Platform::Dg1) => ("i915/dg1_guc_70.bin", (70, 44, 1)),
            Self::Gen12(Gen12Platform::AlderLakeP) => ("i915/adlp_guc_70.bin", (70, 44, 1)),
            Self::Gen12(_) => ("i915/tgl_guc_70.bin", (70, 44, 1)),
            Self::Integrated(Generation::MeteorLake) => ("i915/mtl_guc_70.bin", (70, 53, 0)),
            Self::ArcticSoundM | Self::Alchemist => ("i915/dg2_guc_70.bin", (70, 53, 0)),
            Self::Battlemage => ("xe/bmg_guc_70.bin", (70, 54, 0)),
            Self::Integrated(Generation::LunarLake) => ("xe/lnl_guc_70.bin", (70, 53, 0)),
            Self::Integrated(Generation::PantherLake) => ("xe/ptl_guc_70.bin", (70, 54, 0)),
            Self::WildcatLake => ("xe/ptl_guc_70.bin", (70, 54, 0)),
            Self::NovaLakeS => ("xe/nvl_guc_70.bin", (70, 55, 4)),
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
                0x9a49,
                GtPlatform::Gen12(Gen12Platform::TigerLake),
                "i915/tgl_guc_70.bin",
                (70, 44, 1),
            ),
            (
                0x4c80,
                GtPlatform::Gen12(Gen12Platform::RocketLake),
                "i915/tgl_guc_70.bin",
                (70, 44, 1),
            ),
            (
                0x4905,
                GtPlatform::Gen12(Gen12Platform::Dg1),
                "i915/dg1_guc_70.bin",
                (70, 44, 1),
            ),
            (
                0x46a6,
                GtPlatform::Gen12(Gen12Platform::AlderLakeP),
                "i915/adlp_guc_70.bin",
                (70, 44, 1),
            ),
            (
                0x4680,
                GtPlatform::Gen12(Gen12Platform::AlderLakeS),
                "i915/tgl_guc_70.bin",
                (70, 44, 1),
            ),
            (
                0x46d0,
                GtPlatform::Gen12(Gen12Platform::AlderLakeN),
                "i915/tgl_guc_70.bin",
                (70, 44, 1),
            ),
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
                0x56c0,
                GtPlatform::ArcticSoundM,
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
            (
                0xfd80,
                GtPlatform::WildcatLake,
                "xe/ptl_guc_70.bin",
                (70, 54, 0),
            ),
            (
                0xd740,
                GtPlatform::NovaLakeS,
                "xe/nvl_guc_70.bin",
                (70, 55, 4),
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
            || GtPlatform::from_pci(0x8086, 0x4904).is_some()
            || GtPlatform::from_pci(0x8086, 0x490a).is_some()
            || GtPlatform::Integrated(Generation::PantherLake)
                .guc()
                .is_none()
            || DG2_IDS.len() != 25
            || DG1_IDS.len() != 5
            || BMG_IDS.len() != 13
            || PTL_IDS.len() != 12
            || WCL_IDS.len() != 2
            || NVLS_IDS.len() != 6
        {
            return TestResult::Fail("unsupported GT or approximate PCI range admitted");
        }
        let dg1 = GtPlatform::Gen12(Gen12Platform::Dg1);
        if !dg1.is_discrete()
            || dg1.multiple_ccs()
            || dg1.physical_bits() != 39
            || dg1.ppgtt_root_level() != 3
            || !dg1.has_tile_irq()
            || GtPlatform::Gen12(Gen12Platform::TigerLake).has_tile_irq()
            || GraphicsIp::read(&NoMmio, dg1)
                != Ok(GraphicsIp {
                    version: 1210,
                    step: 0,
                })
        {
            return TestResult::Fail("DG1 Xe-LP+ architecture profile");
        }
        if GraphicsIp::read(&NoMmio, GtPlatform::ArcticSoundM)
            != Ok(GraphicsIp {
                version: 1255,
                step: 0,
            })
            || !GtPlatform::ArcticSoundM.is_discrete()
            || GtPlatform::ArcticSoundM.has_display()
            || !GtPlatform::Alchemist.has_display()
        {
            return TestResult::Fail("ATS-M pre-GMD headless graphics identity");
        }
        for (platform, sriov) in [
            (GtPlatform::Gen12(Gen12Platform::TigerLake), true),
            (GtPlatform::Gen12(Gen12Platform::RocketLake), false),
            (GtPlatform::Gen12(Gen12Platform::Dg1), false),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeP), true),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeS), true),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeN), true),
            (GtPlatform::Integrated(Generation::MeteorLake), false),
            (GtPlatform::Integrated(Generation::LunarLake), false),
            (GtPlatform::Integrated(Generation::PantherLake), true),
            (GtPlatform::WildcatLake, true),
            (GtPlatform::NovaLakeS, false),
            (GtPlatform::ArcticSoundM, true),
            (GtPlatform::Alchemist, false),
            (GtPlatform::Battlemage, true),
        ] {
            if platform.has_sriov() != sriov {
                return TestResult::Fail("Linux xe descriptor SR-IOV capability");
            }
        }
        for (platform, bits) in [
            (GtPlatform::Gen12(Gen12Platform::TigerLake), 39),
            (GtPlatform::Gen12(Gen12Platform::Dg1), 39),
            (GtPlatform::Integrated(Generation::MeteorLake), 46),
            (GtPlatform::ArcticSoundM, 46),
            (GtPlatform::Alchemist, 46),
            (GtPlatform::Battlemage, 46),
            (GtPlatform::Integrated(Generation::LunarLake), 46),
            (GtPlatform::Integrated(Generation::PantherLake), 46),
            (GtPlatform::WildcatLake, 46),
            (GtPlatform::NovaLakeS, 46),
        ] {
            if platform.physical_bits() != bits {
                return TestResult::Fail("Linux xe descriptor DMA width");
            }
        }
        if !is_dg2_g10(0x56c0)
            || !is_dg2_g10(0x56c2)
            || is_dg2_g10(0x56c1)
            || !is_dg2_g11(0x56c1)
            || is_dg2_g11(0x56c0)
        {
            return TestResult::Fail("ATS-M DG2 subplatform identity");
        }
        for version in [3003, 3004, 3005] {
            let raw = (version / 100) << 22 | (version % 100) << 14 | 2;
            if GraphicsIp::read(&FixedMmio(raw), GtPlatform::WildcatLake)
                != Ok(GraphicsIp {
                    version: version as u16,
                    step: 2,
                })
            {
                return TestResult::Fail("WCL graphics GMD profile");
            }
        }
        for version in [3002, 3006] {
            let raw = (version / 100) << 22 | (version % 100) << 14;
            if GraphicsIp::read(&FixedMmio(raw), GtPlatform::WildcatLake)
                != Err(GraphicsError::Unsupported)
            {
                return TestResult::Fail("WCL graphics GMD boundary");
            }
        }
        for version in [3003, 3004, 3005] {
            let raw = (version / 100) << 22 | (version % 100) << 14 | 3;
            if GraphicsIp::read(&FixedMmio(raw), GtPlatform::NovaLakeS)
                != Ok(GraphicsIp {
                    version: version as u16,
                    step: 3,
                })
            {
                return TestResult::Fail("NVL-S graphics GMD profile");
            }
        }
        for version in [3002, 3511] {
            let raw = (version / 100) << 22 | (version % 100) << 14;
            if GraphicsIp::read(&FixedMmio(raw), GtPlatform::NovaLakeS)
                != Err(GraphicsError::Unsupported)
            {
                return TestResult::Fail("NVL-S graphics GMD boundary");
            }
        }
        let nvl = GtPlatform::NovaLakeS;
        if nvl.is_ptl()
            || !nvl.is_xe3_lpg()
            || !nvl.is_headless_integrated()
            || nvl.has_ptl_display_route()
            || !GtPlatform::WildcatLake.is_ptl()
        {
            return TestResult::Fail("NVL-S Xe3 mechanics leaked PTL-only policy");
        }
        TestResult::Pass
    }

    struct NoMmio;
    impl crate::intel_gpu_aux::MmioWindow for NoMmio {
        fn read32(&self, _: u64) -> u32 {
            panic!("pre-GMD identity read MMIO")
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("pre-GMD identity wrote MMIO")
        }
    }
    struct FixedMmio(u32);
    impl crate::intel_gpu_aux::MmioWindow for FixedMmio {
        fn read32(&self, _: u64) -> u32 {
            self.0
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("identity probe wrote MMIO")
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_gt_identity_and_firmware_profiles
    );
}
