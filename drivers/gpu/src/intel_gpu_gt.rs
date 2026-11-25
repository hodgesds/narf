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
        if platform.is_gen11() {
            // Pre-GMD, like Gen12: ICL/EHL/JSL are graphics 11
            // (`i915_pci.c` GEN11_FEATURES carries GEN(11)), so
            // there is no GMD_ID to sample and the version is the
            // generation itself (11.00) with no step.
            return Ok(Self {
                version: 1100,
                step: 0,
            });
        }
        if platform.is_gen9() {
            // Pre-GMD, like Gen11: SKL/KBL/CFL/WHL/CML are
            // graphics 9 (`i915_pci.c` GEN9_FEATURES carries
            // GEN(9)), so there is no GMD_ID to sample and the
            // version is the generation itself (9.00) with no
            // step. Without this arm the fall-through below would
            // sample 0xD8C on a part that has no such register.
            return Ok(Self {
                version: 900,
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
    /// Gen11 — Ice Lake / Elkhart Lake / Jasper Lake, pre-GMD.
    /// Distinct from `Integrated(Generation::IceLake)`: the GuC
    /// firmware family differs by product (see `Gen11Platform`),
    /// and only the sub-platform selects the right blob.
    Gen11(Gen11Platform),
    /// Gen9 — Skylake / Kaby Lake / Coffee Lake / Whiskey Lake /
    /// Comet Lake, pre-GMD. Distinct from
    /// `Integrated(Generation::Skylake)` for the same reason as
    /// Gen11: the GuC firmware family differs by product (see
    /// `Gen9Platform`), and only the sub-platform selects the
    /// right blob. Lane 1 admits identity + probe only;
    /// display and GT execution stay gated for later lanes.
    Gen9(Gen9Platform),
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

/// Gen11 sub-platforms. The GT/register surface is shared across
/// Ice Lake, Elkhart Lake and Jasper Lake (one `Generation::IceLake`),
/// but the GuC firmware family is not: Ice Lake takes the `icl_guc`
/// blob, Elkhart/Jasper Lake the `ehl_guc` blob
/// (`gt/uc/intel_uc_fw.c`, Linux 7.4-rc2 `INTEL_GUC_FIRMWARE_DEFS`).
/// The sub-platform is what selects the file, so it lives here —
/// the same reason `Gen12Platform` exists for the Gen12 family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Gen11Platform {
    IceLake,
    ElkhartLake,
    JasperLake,
}

/// Gen9 sub-platforms. The GT/register surface is shared across
/// Skylake, Kaby Lake, Coffee Lake, Whiskey Lake and Comet Lake
/// (one `Generation::Skylake`), but the GuC firmware family is
/// not: Skylake takes the `skl_guc` blob, Kaby Lake / Coffee Lake /
/// Whiskey Lake take the `kbl_guc` blob, Comet Lake takes the
/// `kbl_guc` blob at rev < 5 and the `cml_guc` blob at rev >= 5
/// (`gt/uc/intel_uc_fw.c`, Linux 7.4-rc2
/// `INTEL_GUC_FIRMWARE_DEFS`). The sub-platform is what selects
/// the file, so it lives here — the same reason `Gen11Platform`
/// exists for the Gen11 family. The Comet Lake revision split is
/// not a sub-platform: it is the PCI revision ID, which
/// [`GtPlatform::guc_for_revision`] and
/// `intel_gpu_huc::firmware_name_for_revision` take, as Linux's
/// firmware tables key on `INTEL_REVID`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Gen9Platform {
    Skylake,
    KabyLake,
    CometLake,
    /// Broxton / Apollo Lake (`IS_BROXTON`, Gen9 LP).
    Broxton,
    /// Gemini Lake (`IS_GEMINILAKE`, Gen9 LP).
    GeminiLake,
}

impl Gen9Platform {
    /// `IS_GEN9_LP`: no LLC, one slice, the CHV-style PPAT and the
    /// Broxton MOCS table. No Gen9 big-core display path applies.
    pub const fn is_lp(self) -> bool {
        matches!(self, Self::Broxton | Self::GeminiLake)
    }
}

/// The first Comet Lake PCI revision that takes the `cml_*` GuC and HuC
/// blobs; earlier revisions take Kaby Lake's (`gt/uc/intel_uc_fw.c`
/// `INTEL_GUC_FIRMWARE_DEFS` / `INTEL_HUC_FIRMWARE_DEFS`).
pub const CML_FIRMWARE_REVISION: u8 = 5;

pub(crate) use crate::intel_gpu::{BMG_IDS, DG1_IDS, DG2_IDS};

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum GuCRsaTransfer {
    ScratchRegisters,
    GgttPointer,
}

impl GuCProfile {
    /// How the GuC ROM receives this image's RSA signature. Linux
    /// `gt/uc/intel_guc_fw.c::guc_xfer_rsa` selects purely on size, with
    /// no generation gate: a 256-byte (2048-bit) signature goes through
    /// the 64 scratch registers (`guc_xfer_rsa_mmio`), and only a larger
    /// signature (`intel_uc_fw.c`: `rsa_size > 256` sets `rsa_data`)
    /// goes through the GGTT pointer (`guc_xfer_rsa_vma`). Gen9 takes
    /// the same 256-byte scratch path as Gen11/Gen12 (Gen9 Lane 7):
    /// the 70.1.1 blobs are RSA-2048 signed, so without this arm every
    /// Gen9 GuC load failed at validation and staging with
    /// `FirmwareLayout` / `BootError::Device` even though the profile
    /// itself was admitted.
    pub(crate) fn rsa_transfer(self, bytes: usize) -> Option<GuCRsaTransfer> {
        match (bytes, self.platform) {
            (256, GtPlatform::Gen9(_) | GtPlatform::Gen11(_) | GtPlatform::Gen12(_)) => {
                Some(GuCRsaTransfer::ScratchRegisters)
            }
            (384, _) => Some(GuCRsaTransfer::GgttPointer),
            _ => None,
        }
    }
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
            if entry.generation == Generation::PantherLake {
                // All three products share the broad display generation. The
                // exact PCI table entry determines which GT and GuC to use.
                return match entry.asic {
                    "pantherlake" => Some(Self::Integrated(Generation::PantherLake)),
                    "wildcatlake" => Some(Self::WildcatLake),
                    "novalake-s" => Some(Self::NovaLakeS),
                    _ => None,
                };
            }
            let family = match entry.asic {
                "tigerlake" => Some(Gen12Platform::TigerLake),
                "rocketlake" => Some(Gen12Platform::RocketLake),
                "alderlake-p" | "alderlake-m" | "raptorlake-p" | "raptorlake-u" => {
                    Some(Gen12Platform::AlderLakeP)
                }
                "alderlake-s" | "raptorlake-s" => Some(Gen12Platform::AlderLakeS),
                "alderlake-n" => Some(Gen12Platform::AlderLakeN),
                _ => None,
            };
            if let Some(family) = family {
                return Some(Self::Gen12(family));
            }
            let gen11 = match entry.asic {
                "icelake" => Some(Gen11Platform::IceLake),
                "elkhartlake" => Some(Gen11Platform::ElkhartLake),
                "jasperlake" => Some(Gen11Platform::JasperLake),
                _ => None,
            };
            if let Some(gen11) = gen11 {
                return Some(Self::Gen11(gen11));
            }
            // Gen9 (Lane 1): Coffee Lake and Whiskey Lake ride
            // the Kaby Lake firmware family (`kbl_guc_70.1.1`,
            // `gt/uc/intel_uc_fw.c`).
            let gen9 = match entry.asic {
                "skylake" => Some(Gen9Platform::Skylake),
                "kabylake" | "coffeelake" | "whiskeylake" => Some(Gen9Platform::KabyLake),
                "cometlake" => Some(Gen9Platform::CometLake),
                "broxton" => Some(Gen9Platform::Broxton),
                "geminilake" => Some(Gen9Platform::GeminiLake),
                _ => None,
            };
            return Some(gen9.map_or(Self::Integrated(entry.generation), Self::Gen9));
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

    /// Pre-GMD Gen11 (Ice Lake / Elkhart Lake / Jasper Lake).
    pub const fn is_gen11(self) -> bool {
        matches!(self, Self::Gen11(_))
    }

    /// Pre-GMD Gen9 (Skylake / Kaby Lake / Coffee Lake /
    /// Whiskey Lake / Comet Lake).
    pub const fn is_gen9(self) -> bool {
        matches!(self, Self::Gen9(_))
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
    /// graphics IP remains in the pre-GMD Gen12 family. Gen9 has no
    /// tile-master block: its IRQ routing is the pre-tile master-IRQ
    /// model (Lane 8 grounds it against `intel_display_irq.c` /
    /// `gt/intel_gt_irq.c`), so it takes the MASTER-only path
    /// (`tiled = false`), which degrades to timer completion when
    /// the install refuses.
    pub(crate) const fn has_tile_irq(self) -> bool {
        (!self.is_gen12() && !matches!(self, Self::Gen9(_)))
            || matches!(self, Self::Gen12(Gen12Platform::Dg1))
    }
    /// `vm->total` for a full PPGTT: `BIT_ULL(RUNTIME_INFO->ppgtt_size)`.
    /// Elkhart Lake and Jasper Lake are 36-bit (`ehl_info`/`jsl_info` in
    /// `i915_pci.c`), still a four-level walk (`i915_vm_is_4lvl` is
    /// `total > 4 GiB`); every other platform here is 48-bit.
    pub const fn ppgtt_va_size(self) -> u64 {
        match self {
            Self::Gen11(Gen11Platform::ElkhartLake | Gen11Platform::JasperLake) => 1 << 36,
            _ => 1 << 48,
        }
    }

    pub(crate) const fn ppgtt_root_level(self) -> u8 {
        if self.is_headless_integrated() || matches!(self, Self::Battlemage) {
            4
        } else {
            3
        }
    }
    pub(crate) const fn pte_format(self) -> crate::intel_gpu_gtt::PteFormat {
        if self.is_headless_integrated() || matches!(self, Self::Battlemage) {
            crate::intel_gpu_gtt::PteFormat::Xe2
        } else if self.is_gen12() || self.is_dg2() {
            crate::intel_gpu_gtt::PteFormat::Gen12
        } else if matches!(self, Self::Gen11(_) | Self::Gen9(_)) {
            crate::intel_gpu_gtt::PteFormat::Gen8
        } else {
            crate::intel_gpu_gtt::PteFormat::XeLpg
        }
    }

    pub(crate) const fn physical_bits(self) -> u32 {
        match self {
            Self::Gen12(_) => 39,
            // Gen11: 39-bit DMA mask (`i915_pci.c` GEN11_FEATURES
            // inherits GEN9/GEN8's `.dma_mask_size = 39`).
            Self::Gen11(_) => 39,
            // Gen9: 39-bit DMA mask (`i915_pci.c` GEN9_FEATURES
            // `.dma_mask_size = 39` — the value Gen11 inherits
            // above).
            Self::Gen9(_) => 39,
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
                Generation::TigerLake
                | Generation::RocketLake
                | Generation::AlderLake
                | Generation::IceLake
                | Generation::Skylake
                | Generation::Broxton,
            ) => 39,
        }
    }

    /// xe_guc_hwconfig.c: only ADL-P among pre-XeHP families supplies a
    /// HWCONFIG table. Absence is a platform property, never a guessed table.
    /// Gen11 has none either: i915's `intel_guc_hwconfig.c::has_table`
    /// requires graphics 12.55+, and Gen11 is graphics 11. Gen9 has
    /// none for the same reason (graphics 9).
    pub const fn has_hwconfig(self) -> bool {
        if matches!(self, Self::Gen11(_) | Self::Gen9(_)) {
            return false;
        }
        !matches!(self, Self::Gen12(family) if !matches!(family, Gen12Platform::AlderLakeP))
    }

    /// Graphics-GT forcewake ACK (xe_force_wake_init_gt / xe_gt_regs.h).
    /// Gfx 12.70+ moved the GT ACK; DG2 retains the earlier address.
    /// Gen11 keeps the earlier address too: i915's
    /// `FORCEWAKE_ACK_GT_GEN9` is 0x130044 (`intel_gt_regs.h`).
    pub const fn guc_forcewake_ack(self) -> Option<u64> {
        match self {
            Self::Integrated(
                Generation::MeteorLake | Generation::LunarLake | Generation::PantherLake,
            )
            | Self::WildcatLake
            | Self::NovaLakeS
            | Self::Battlemage => Some(0xdfc),
            Self::ArcticSoundM
            | Self::Alchemist
            | Self::Gen12(_)
            | Self::Gen11(_)
            | Self::Gen9(_) => Some(0x130044),
            _ => None,
        }
    }

    /// [`Self::guc`] for a device whose PCI revision ID is `revision`.
    /// Only Comet Lake's firmware depends on it: Linux's
    /// `INTEL_GUC_FIRMWARE_DEFS` lists `fw_def(COMETLAKE, 5, guc_mmp(cml,
    /// 70, 1, 1))` before `fw_def(COMETLAKE, 0, guc_mmp(kbl, 70, 1, 1))`,
    /// and `__uc_fw_auto_select` takes the first row whose revision the
    /// device's `INTEL_REVID` reaches (`gt/uc/intel_uc_fw.c`).
    pub const fn guc_for_revision(self, revision: u8) -> Option<GuCProfile> {
        if matches!(self, Self::Gen9(Gen9Platform::CometLake)) && revision >= CML_FIRMWARE_REVISION
        {
            return Some(GuCProfile {
                platform: self,
                firmware: "i915/cml_guc_70.1.1.bin",
                minimum_version: (70, 1, 1),
            });
        }
        self.guc()
    }

    /// Supported GuC boot ABI, not permission to publish a display or engine.
    /// Comet Lake gets its revision-0 row here; see [`Self::guc_for_revision`].
    pub const fn guc(self) -> Option<GuCProfile> {
        let (firmware, minimum_version) = match self {
            Self::Gen12(Gen12Platform::Dg1) => ("i915/dg1_guc_70.bin", (70, 44, 1)),
            Self::Gen12(Gen12Platform::AlderLakeP) => ("i915/adlp_guc_70.bin", (70, 44, 1)),
            Self::Gen12(_) => ("i915/tgl_guc_70.bin", (70, 44, 1)),
            // Gen11 GuC is old-format: the blob filename carries its
            // full version and the embedded CSS version is that same
            // 70.1.1 (`gt/uc/intel_uc_fw.c` INTEL_GUC_FIRMWARE_DEFS:
            // ICL `guc_mmp(icl, 70, 1, 1)`, EHL/JSL
            // `guc_mmp(ehl, 70, 1, 1)`). The minimum is the blob's
            // own version — the same rule the TGL (70, 44, 1) pin
            // follows for its major-only blob. GuC submission stays
            // optional on Gen11 (execlists works without it); this
            // profile only admits the firmware family for Lane 7.
            Self::Gen11(Gen11Platform::IceLake) => ("i915/icl_guc_70.1.1.bin", (70, 1, 1)),
            Self::Gen11(Gen11Platform::ElkhartLake | Gen11Platform::JasperLake) => {
                ("i915/ehl_guc_70.1.1.bin", (70, 1, 1))
            }
            // Gen9 GuC is old-format like Gen11's: the blob filename
            // carries its full version and the embedded CSS version
            // is that same 70.1.1 (`gt/uc/intel_uc_fw.c`
            // `INTEL_GUC_FIRMWARE_DEFS`: SKL `guc_mmp(skl, 70, 1,
            // 1)`, KBL/CFL `guc_mmp(kbl, 70, 1, 1)`, CML rev>=5
            // `guc_mmp(cml, 70, 1, 1)` / rev<5 `guc_mmp(kbl, 70, 1,
            // 1)`). The minimum is the blob's own version — the
            // same rule the Gen11 (70, 1, 1) pin follows. These
            // arms exist in Lane 1 because the device-table census
            // fixture requires a qualified GT/GuC profile for every
            // census DID; GuC submission stays optional on Gen9
            // (execlists works without it) and the load itself is
            // Lane 7's. This arm is CML below revision 5; the
            // rev>=5 blob is `guc_for_revision`'s.
            Self::Gen9(Gen9Platform::Skylake) => ("i915/skl_guc_70.1.1.bin", (70, 1, 1)),
            // `fw_def(BROXTON, 0, guc_mmp(bxt, 70, 1, 1))`, likewise GLK.
            Self::Gen9(Gen9Platform::Broxton) => ("i915/bxt_guc_70.1.1.bin", (70, 1, 1)),
            Self::Gen9(Gen9Platform::GeminiLake) => ("i915/glk_guc_70.1.1.bin", (70, 1, 1)),
            Self::Gen9(Gen9Platform::KabyLake | Gen9Platform::CometLake) => {
                ("i915/kbl_guc_70.1.1.bin", (70, 1, 1))
            }
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
                0x8a50,
                GtPlatform::Gen11(Gen11Platform::IceLake),
                "i915/icl_guc_70.1.1.bin",
                (70, 1, 1),
            ),
            (
                0x8a71,
                GtPlatform::Gen11(Gen11Platform::IceLake),
                "i915/icl_guc_70.1.1.bin",
                (70, 1, 1),
            ),
            (
                0x4571,
                GtPlatform::Gen11(Gen11Platform::ElkhartLake),
                "i915/ehl_guc_70.1.1.bin",
                (70, 1, 1),
            ),
            (
                0x4e51,
                GtPlatform::Gen11(Gen11Platform::JasperLake),
                "i915/ehl_guc_70.1.1.bin",
                (70, 1, 1),
            ),
            (
                0x1912,
                GtPlatform::Gen9(Gen9Platform::Skylake),
                "i915/skl_guc_70.1.1.bin",
                (70, 1, 1),
            ),
            (
                0x5912,
                GtPlatform::Gen9(Gen9Platform::KabyLake),
                "i915/kbl_guc_70.1.1.bin",
                (70, 1, 1),
            ),
            (
                0x9b41,
                GtPlatform::Gen9(Gen9Platform::CometLake),
                "i915/kbl_guc_70.1.1.bin",
                (70, 1, 1),
            ),
            (
                0x5a85,
                GtPlatform::Gen9(Gen9Platform::Broxton),
                "i915/bxt_guc_70.1.1.bin",
                (70, 1, 1),
            ),
            (
                0x3185,
                GtPlatform::Gen9(Gen9Platform::GeminiLake),
                "i915/glk_guc_70.1.1.bin",
                (70, 1, 1),
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
        if GtPlatform::Battlemage.ppgtt_root_level() != 4
            || GtPlatform::Battlemage.pte_format() != crate::intel_gpu_gtt::PteFormat::Xe2
            || GtPlatform::Alchemist.ppgtt_root_level() != 3
            || GtPlatform::Alchemist.pte_format() != crate::intel_gpu_gtt::PteFormat::Gen12
        {
            return TestResult::Fail("BMG source five-level Xe2 PPGTT profile");
        }
        // Gen9 and Gen11 (all sub-platforms) take the legacy Gen8 PPAT
        // format on a four-level walk; Gen12 keeps its own format.
        for platform in [
            GtPlatform::Gen9(Gen9Platform::Skylake),
            GtPlatform::Gen9(Gen9Platform::KabyLake),
            GtPlatform::Gen9(Gen9Platform::CometLake),
            GtPlatform::Gen9(Gen9Platform::Broxton),
            GtPlatform::Gen9(Gen9Platform::GeminiLake),
            GtPlatform::Gen11(Gen11Platform::IceLake),
            GtPlatform::Gen11(Gen11Platform::ElkhartLake),
            GtPlatform::Gen11(Gen11Platform::JasperLake),
        ] {
            if platform.ppgtt_root_level() != 3
                || platform.pte_format() != crate::intel_gpu_gtt::PteFormat::Gen8
            {
                return TestResult::Fail("Gen9/Gen11 must select the Gen8 PTE format");
            }
        }
        if GtPlatform::Gen12(Gen12Platform::TigerLake).pte_format()
            != crate::intel_gpu_gtt::PteFormat::Gen12
        {
            return TestResult::Fail("Gen12 must keep its PTE format");
        }
        for (platform, sriov) in [
            (GtPlatform::Gen12(Gen12Platform::TigerLake), true),
            (GtPlatform::Gen12(Gen12Platform::RocketLake), false),
            (GtPlatform::Gen12(Gen12Platform::Dg1), false),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeP), true),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeS), true),
            (GtPlatform::Gen12(Gen12Platform::AlderLakeN), true),
            (GtPlatform::Gen11(Gen11Platform::IceLake), false),
            (GtPlatform::Gen11(Gen11Platform::ElkhartLake), false),
            (GtPlatform::Gen11(Gen11Platform::JasperLake), false),
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
            (GtPlatform::Gen11(Gen11Platform::IceLake), 39),
            (GtPlatform::Gen11(Gen11Platform::ElkhartLake), 39),
            (GtPlatform::Gen11(Gen11Platform::JasperLake), 39),
            (GtPlatform::Gen9(Gen9Platform::Skylake), 39),
            (GtPlatform::Gen9(Gen9Platform::KabyLake), 39),
            (GtPlatform::Gen9(Gen9Platform::CometLake), 39),
            // GEN9_LP_FEATURES `.dma_mask_size = 39`.
            (GtPlatform::Gen9(Gen9Platform::Broxton), 39),
            (GtPlatform::Gen9(Gen9Platform::GeminiLake), 39),
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
        // Gen11: no HWCONFIG table (i915 requires graphics 12.55+)
        // and the GT forcewake ACK is the Gen9 address 0x130044 —
        // never the MTL 0xdfc. The pre-GMD identity read must not
        // touch MMIO: Gen11 has no GMD_ID to sample.
        for platform in [
            GtPlatform::Gen11(Gen11Platform::IceLake),
            GtPlatform::Gen11(Gen11Platform::ElkhartLake),
            GtPlatform::Gen11(Gen11Platform::JasperLake),
        ] {
            if platform.has_hwconfig()
                || platform.guc_forcewake_ack() != Some(0x130044)
                || platform.is_gen12()
                || platform.is_headless_integrated()
                || platform.ppgtt_root_level() != 3
                || GraphicsIp::read(&NoMmio, platform)
                    != Ok(GraphicsIp {
                        version: 1100,
                        step: 0,
                    })
            {
                return TestResult::Fail("Gen11 GT profile");
            }
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

    /// Q6: Comet Lake's GuC and HuC follow the PCI revision ID, as
    /// Linux's `INTEL_REVID` rows do; no other platform's do.
    fn smoke_cml_firmware_follows_revision() -> TestResult {
        let cml = GtPlatform::Gen9(Gen9Platform::CometLake);
        for (revision, guc, huc) in [
            (0, "i915/kbl_guc_70.1.1.bin", "i915/kbl_huc_4.0.0.bin"),
            (4, "i915/kbl_guc_70.1.1.bin", "i915/kbl_huc_4.0.0.bin"),
            (5, "i915/cml_guc_70.1.1.bin", "i915/cml_huc_4.0.0.bin"),
            (6, "i915/cml_guc_70.1.1.bin", "i915/cml_huc_4.0.0.bin"),
        ] {
            let Some(profile) = cml.guc_for_revision(revision) else {
                return TestResult::Fail("CML lost its GuC profile");
            };
            if profile.firmware != guc
                || profile.minimum_version != (70, 1, 1)
                || profile.platform != cml
            {
                return TestResult::Fail("CML GuC blob does not follow the revision");
            }
            if crate::intel_gpu_huc::firmware_name_for_revision(cml, revision) != Some(huc) {
                return TestResult::Fail("CML HuC blob does not follow the revision");
            }
        }
        // The revision-less entry points are revision 0.
        if cml.guc() != cml.guc_for_revision(0)
            || crate::intel_gpu_huc::firmware_name(cml)
                != crate::intel_gpu_huc::firmware_name_for_revision(cml, 0)
        {
            return TestResult::Fail("revision-less CML lookup is not revision 0");
        }
        // Kaby Lake (and the CFL/WHL that ride it) and Skylake ignore it.
        for platform in [
            GtPlatform::Gen9(Gen9Platform::KabyLake),
            GtPlatform::Gen9(Gen9Platform::Skylake),
            GtPlatform::Gen11(Gen11Platform::IceLake),
            GtPlatform::Gen12(Gen12Platform::TigerLake),
        ] {
            if platform.guc_for_revision(9) != platform.guc()
                || crate::intel_gpu_huc::firmware_name_for_revision(platform, 9)
                    != crate::intel_gpu_huc::firmware_name(platform)
            {
                return TestResult::Fail("a non-CML blob moved with the revision");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_cml_firmware_follows_revision
    );

    /// Q8: EHL/JSL VMs are 36-bit (`ppgtt_size = 36`), still four-level;
    /// Ice Lake and the rest stay 48-bit.
    fn smoke_ehl_jsl_ppgtt_ceiling() -> TestResult {
        for (platform, size) in [
            (GtPlatform::Gen11(Gen11Platform::ElkhartLake), 1u64 << 36),
            (GtPlatform::Gen11(Gen11Platform::JasperLake), 1 << 36),
            (GtPlatform::Gen11(Gen11Platform::IceLake), 1 << 48),
            (GtPlatform::Gen9(Gen9Platform::KabyLake), 1 << 48),
            (GtPlatform::Gen12(Gen12Platform::TigerLake), 1 << 48),
        ] {
            if platform.ppgtt_va_size() != size {
                return TestResult::Fail("ppgtt_va_size does not follow i915_pci.c");
            }
            // Above 4 GiB the walk is four-level (`i915_vm_is_4lvl`).
            if platform.ppgtt_root_level() != 3 {
                return TestResult::Fail("a 36-bit VM still walks four levels");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gt", smoke_ehl_jsl_ppgtt_ceiling);
}
