//! Intel PCI identities shared by built-in and loadable registration.

/// Intel Corporation (PCI Special Interest Group ID).
pub const INTEL_VENDOR: u16 = 0x8086;

// Ice Lake (Gen11). Linux `include/drm/intel/pciids.h`
// INTEL_ICL_IDS (15): PORT_F 8A50/8A52–8A54/8A56–8A5C/8A70/8A71
// plus 8A51 and 8A5D.
pub const ICL_8A50: u16 = 0x8A50;
pub const ICL_8A51: u16 = 0x8A51;
pub const ICL_8A52: u16 = 0x8A52;
pub const ICL_8A53: u16 = 0x8A53;
pub const ICL_8A54: u16 = 0x8A54;
pub const ICL_8A56: u16 = 0x8A56;
pub const ICL_8A57: u16 = 0x8A57;
pub const ICL_8A58: u16 = 0x8A58;
pub const ICL_8A59: u16 = 0x8A59;
pub const ICL_8A5A: u16 = 0x8A5A;
pub const ICL_8A5B: u16 = 0x8A5B;
pub const ICL_8A5C: u16 = 0x8A5C;
pub const ICL_8A5D: u16 = 0x8A5D;
pub const ICL_8A70: u16 = 0x8A70;
pub const ICL_8A71: u16 = 0x8A71;

// Elkhart Lake (Gen11). Linux INTEL_EHL_IDS (6).
pub const EHL_4541: u16 = 0x4541;
pub const EHL_4551: u16 = 0x4551;
pub const EHL_4555: u16 = 0x4555;
pub const EHL_4557: u16 = 0x4557;
pub const EHL_4570: u16 = 0x4570;
pub const EHL_4571: u16 = 0x4571;

// Jasper Lake (Gen11). Linux INTEL_JSL_IDS (5).
pub const JSL_4E51: u16 = 0x4E51;
pub const JSL_4E55: u16 = 0x4E55;
pub const JSL_4E57: u16 = 0x4E57;
pub const JSL_4E61: u16 = 0x4E61;
pub const JSL_4E71: u16 = 0x4E71;

// Tiger Lake (Gen12 Xe-LP) — public `pci.ids` Intel rows.
// GT split per Linux `INTEL_TGL_GT1_IDS` / `INTEL_TGL_GT2_IDS`
// (`include/drm/intel/pciids.h`, Linux 7.4-rc2): GT1 = 9A60, 9A68,
// 9A70; GT2 = 9A40, 9A49, 9A59, 9A78, 9AC0, 9AC9, 9AD9, 9AF8.
pub const TGL_GT2_9A40: u16 = 0x9A40;
pub const TGL_U_GT2_9A49: u16 = 0x9A49;
pub const TGL_U_GT2_9A59: u16 = 0x9A59;
pub const TGL_H_GT1_9A60: u16 = 0x9A60;
pub const TGL_H_GT1_9A68: u16 = 0x9A68;
pub const TGL_H_GT1_9A70: u16 = 0x9A70;
pub const TGL_GT2_9A78: u16 = 0x9A78;
pub const TGL_GT2_9AC0: u16 = 0x9AC0;
pub const TGL_GT2_9AC9: u16 = 0x9AC9;
pub const TGL_GT2_9AD9: u16 = 0x9AD9;
pub const TGL_GT2_9AF8: u16 = 0x9AF8;

// Rocket Lake (Gen12 Xe-LP, desktop). The GT shares the TGL GuC profile;
// display clocks/ports are a distinct source family and remain gated.
pub const RKL_4C80: u16 = 0x4C80;
pub const RKL_4C8A: u16 = 0x4C8A;
pub const RKL_4C8B: u16 = 0x4C8B;
pub const RKL_4C8C: u16 = 0x4C8C;
pub const RKL_4C90: u16 = 0x4C90;
pub const RKL_4C9A: u16 = 0x4C9A;

// Alder Lake-P (Gen12, mobile).
pub const ADL_P_4626: u16 = 0x4626;
pub const ADL_P_4628: u16 = 0x4628;
pub const ADL_P_462A: u16 = 0x462A;
pub const ADL_P_4636: u16 = 0x4636;
pub const ADL_P_4638: u16 = 0x4638;
pub const ADL_P_463A: u16 = 0x463A;
pub const ADL_P_46A0: u16 = 0x46A0;
pub const ADL_P_46A1: u16 = 0x46A1;
pub const ADL_P_46A2: u16 = 0x46A2;
pub const ADL_P_46A3: u16 = 0x46A3;
pub const ADL_P_46A6: u16 = 0x46A6;
pub const ADL_P_46A8: u16 = 0x46A8;
pub const ADL_P_46AA: u16 = 0x46AA;
pub const ADL_P_46B6: u16 = 0x46B6;
pub const ADL_P_46B8: u16 = 0x46B8;
pub const ADL_P_46BA: u16 = 0x46BA;
pub const ADL_P_46B0: u16 = 0x46B0;
pub const ADL_P_46B1: u16 = 0x46B1;
pub const ADL_P_46B2: u16 = 0x46B2;
pub const ADL_P_46B3: u16 = 0x46B3;
// Alder Lake-M (Gen12, mobile).
pub const ADL_M_46C0: u16 = 0x46C0;
pub const ADL_M_46C1: u16 = 0x46C1;
pub const ADL_M_46C2: u16 = 0x46C2;
pub const ADL_M_46C3: u16 = 0x46C3;
// Alder Lake-N (Gen12, low-power mobile/desktop).
pub const ADL_N_46D0: u16 = 0x46D0;
pub const ADL_N_46D1: u16 = 0x46D1;
pub const ADL_N_46D2: u16 = 0x46D2;
pub const ADL_N_46D3: u16 = 0x46D3;
pub const ADL_N_46D4: u16 = 0x46D4;

// Alder Lake-S / Raptor Lake-S (Gen12, desktop).
pub const ADL_S_4680: u16 = 0x4680;
pub const ADL_S_4682: u16 = 0x4682;
pub const ADL_S_4688: u16 = 0x4688;
pub const ADL_S_468A: u16 = 0x468A;
pub const ADL_S_468B: u16 = 0x468B;
pub const ADL_S_4690: u16 = 0x4690;
pub const ADL_S_4692: u16 = 0x4692;
pub const ADL_S_4693: u16 = 0x4693;
pub const RPL_S_A780: u16 = 0xA780;
pub const RPL_S_A781: u16 = 0xA781;
pub const RPL_S_A782: u16 = 0xA782;
pub const RPL_S_A783: u16 = 0xA783;
pub const RPL_S_A788: u16 = 0xA788;
pub const RPL_S_A789: u16 = 0xA789;
pub const RPL_S_A78A: u16 = 0xA78A;
pub const RPL_S_A78B: u16 = 0xA78B;
// Raptor Lake-P / -U (Gen12, mobile).
pub const RPL_P_A720: u16 = 0xA720;
pub const RPL_U_A721: u16 = 0xA721;
pub const RPL_P_A7A0: u16 = 0xA7A0;
pub const RPL_U_A7A1: u16 = 0xA7A1;
pub const RPL_P_A7A8: u16 = 0xA7A8;
pub const RPL_U_A7A9: u16 = 0xA7A9;
pub const RPL_P_A7AA: u16 = 0xA7AA;
pub const RPL_P_A7AB: u16 = 0xA7AB;
pub const RPL_U_A7AC: u16 = 0xA7AC;
pub const RPL_U_A7AD: u16 = 0xA7AD;

// Compatibility for users of the original PCI constant names.
pub use self::ADL_P_46B0 as RPL_P_46B0;
pub use self::ADL_P_46B1 as RPL_P_46B1;
pub use self::ADL_P_46B2 as RPL_P_46B2;
pub use self::ADL_P_46B3 as RPL_P_46B3;
pub use self::RPL_U_A721 as RPL_P_A721;
pub use self::RPL_U_A7A1 as RPL_P_A7A1;
pub use self::RPL_U_A7A9 as RPL_P_A7A9;
pub use self::RPL_U_A7AC as RPL_P_A7AC;
pub use self::RPL_U_A7AD as RPL_P_A7AD;

// Meteor Lake (Xe-LPG, mobile).
pub const MTL_7D40: u16 = 0x7D40;
pub const MTL_7D45: u16 = 0x7D45;
pub const MTL_7D55: u16 = 0x7D55;
pub const MTL_7D60: u16 = 0x7D60;
pub const MTL_7DD5: u16 = 0x7DD5;

// Arrow Lake (Xe-LPG silicon under a new product name — see the
// DEVICE_TABLE note). Linux `include/drm/intel/pciids.h`
// INTEL_ARL_*_IDS: H = 7D51/7DD1, U = 7D41, S = 7D67/B640.
// pci.ids lists the same five as Arrow Lake (it labels B640
// Arrow Lake-H; i915 files B640 under its ARL-S macro — the
// segment letter differs between the two sources, the Arrow
// Lake attribution and the MTL binding agree).
pub const ARL_7D41: u16 = 0x7D41;
pub const ARL_7D51: u16 = 0x7D51;
pub const ARL_7D67: u16 = 0x7D67;
pub const ARL_7DD1: u16 = 0x7DD1;
pub const ARL_B640: u16 = 0xB640;

// Panther Lake (Xe3-LPG / "Xe3", Core Ultra Series 3 mobile).
pub const PTL_B080: u16 = 0xB080;
pub const PTL_B081: u16 = 0xB081;
pub const PTL_B082: u16 = 0xB082;
pub const PTL_B083: u16 = 0xB083;
pub const PTL_B084: u16 = 0xB084;
pub const PTL_B085: u16 = 0xB085;
pub const PTL_B086: u16 = 0xB086;
pub const PTL_B087: u16 = 0xB087;
pub const PTL_B08F: u16 = 0xB08F;
pub const PTL_B090: u16 = 0xB090;
/// Panther Lake-H — the SKU on the Minisforum MS-03 (Core Ultra 5 336H).
pub const PTL_B0A0: u16 = 0xB0A0;
pub const PTL_B0A1: u16 = 0xB0A1;
pub const PTL_B0B0: u16 = 0xB0B0;

// Wildcat Lake (Xe3-LPG). Linux binds both IDs to the Panther Lake GT
// descriptor; display 30.02 remains separately gated in intel_gpu_xe3lpd.
pub const WCL_FD80: u16 = 0xFD80;
pub const WCL_FD81: u16 = 0xFD81;

// Nova Lake-S. Linux gives this family a distinct descriptor and GuC image;
// display 35.00 remains on the headless route until its modeset is qualified.
pub const NVLS_D740: u16 = 0xD740;
pub const NVLS_D741: u16 = 0xD741;
pub const NVLS_D742: u16 = 0xD742;
pub const NVLS_D743: u16 = 0xD743;
/// Retained from Linux 7.0-rc7's INTEL_NVLS_IDS.
pub const NVLS_D744: u16 = 0xD744;
pub const NVLS_D745: u16 = 0xD745;
pub const NVLS_D74A: u16 = 0xD74A;
pub const NVLS_D74B: u16 = 0xD74B;

// Crescent Island is source-known but execution remains gated: the current
// Linux xe firmware manifest has no CRESCENTISLAND GuC entry.
pub const CRI_674C: u16 = 0x674C;
pub(crate) const CRI_IDS: &[u16] = &[CRI_674C, 0x674d, 0x674e, 0x674f, 0x6750];
// Linux 7.4-rc1 INTEL_NVLP_IDS uses a distinct force-probe descriptor.
// xe_uc_fw.c does not supply a GuC profile for NOVALAKE_P.
pub(crate) const NVLP_IDS: &[u16] = &[
    0xd750, 0xd751, 0xd752, 0xd753, 0xd754, 0xd755, 0xd756, 0xd757, 0xd75f,
];

// Arctic Sound-M. Linux `INTEL_ATS_M_IDS`: M150 = 56C0/56C2, M75 = 56C1.
// These use the DG2 platform machinery but are display-less, SR-IOV-capable
// accelerator profiles. NARF binds only a PF with VF Enable and NumVFs zero.
pub const ATSM_56C0: u16 = 0x56C0;
pub const ATSM_56C1: u16 = 0x56C1;
pub const ATSM_56C2: u16 = 0x56C2;
pub(crate) const ATSM_IDS: &[u16] = &[ATSM_56C0, ATSM_56C1, ATSM_56C2];

// ── Generation classifier ────────────────────────────────────────

/// Gen12 sub-architecture identifier. Tiger Lake / Alder Lake /
/// Raptor Lake all share the Xe-LP register surface; Meteor Lake
/// uses Xe-LPG (different DDI / DPLL programming).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Generation {
    /// Ice Lake / Elkhart Lake / Jasper Lake — Gen11. One
    /// variant for the whole Gen11 family, following the
    /// Raptor-Lake-under-AlderLake pattern: the GT/register
    /// surface is shared and `asic` carries the product name
    /// ("icelake" / "elkhartlake" / "jasperlake"). The GuC
    /// firmware family is NOT shared (ICL takes `icl_guc`,
    /// EHL/JSL take `ehl_guc`), so `GtPlatform` keeps a
    /// distinct `Gen11` sub-platform per product (see
    /// `intel_gpu_gt::Gen11Platform`).
    IceLake,
    /// Tiger Lake — Gen12 Xe-LP. Conservative reference target.
    TigerLake,
    /// Rocket Lake — Gen12 Xe-LP GT with a distinct display-12 clock/port
    /// topology. GT execution is admitted; display programming is gated.
    RocketLake,
    /// Alder Lake / Raptor Lake — Gen12 Xe-LP carry-forward.
    AlderLake,
    /// Meteor Lake — Xe-LPG (re-architected DDI + display power).
    /// Arrow Lake classifies here too: its GT is Xe-LPG and its
    /// display is Xe-LPD, and both Linux drivers bind the ARL IDs
    /// to the Meteor Lake device info / display descriptor
    /// (i915 `INTEL_ARL_IDS(..., &mtl_info)`, xe `&mtl_desc`),
    /// distinguishing Arrow Lake only as a subplatform. The
    /// table follows the silicon, as it already does for Raptor
    /// Lake under `AlderLake`; `asic` carries the product name.
    MeteorLake,
    /// Lunar Lake — Xe2-LPG graphics; display 20 (Xe2_LPD) is
    /// driven only through the opted-in per-device route
    /// (`intel_gpu_xe2lpd`), never the shared probe path.
    LunarLake,
    /// Panther Lake / Wildcat Lake — Xe3-LPG. Display is Xe3_LPD: the DDI block
    /// moved again relative to Xe-LPG and the C10/C20 PHYs replace
    /// the combo-PHY + DPLL pair Gen12 used.
    PantherLake,
}

/// One row of the canonical Intel device table. PCI registration
/// and `chip_info_for_pci_id` both derive from this single list,
/// so the two can no longer drift apart (before lane 1 they were
/// a hand-duplicated classifier match + a 36-entry registration
/// list with zero fixtures pinning either).
#[derive(Copy, Clone, Debug)]
pub struct DeviceEntry {
    /// PCI registration name (`narf_bus::PciMatch::name`).
    pub name: &'static str,
    pub did: u16,
    pub generation: Generation,
    pub asic: &'static str,
}

/// The canonical integrated device table. Contents are pinned against
/// spec §5 by the census fixture in this module's tests. Current families
/// are transcribed from Linux `include/drm/intel/pciids.h`; the six retained
/// public-`pci.ids` ADL-P rows are called out in the spec. Every row requires
/// an already-qualified matching generation profile.
pub const DEVICE_TABLE: &[DeviceEntry] = &[
    // MIT Linux include/drm/intel/pciids.h: INTEL_LNL_IDS (exactly three).
    DeviceEntry {
        name: "intel-gpu-lnl-6420",
        did: 0x6420,
        generation: Generation::LunarLake,
        asic: "lunarlake",
    },
    DeviceEntry {
        name: "intel-gpu-lnl-64A0",
        did: 0x64a0,
        generation: Generation::LunarLake,
        asic: "lunarlake",
    },
    DeviceEntry {
        name: "intel-gpu-lnl-64B0",
        did: 0x64b0,
        generation: Generation::LunarLake,
        asic: "lunarlake",
    },
    // Ice Lake (Gen11). Linux INTEL_ICL_IDS, in macro order.
    DeviceEntry {
        name: "intel-gpu-icl-8A50",
        did: ICL_8A50,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A51",
        did: ICL_8A51,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A52",
        did: ICL_8A52,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A53",
        did: ICL_8A53,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A54",
        did: ICL_8A54,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A56",
        did: ICL_8A56,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A57",
        did: ICL_8A57,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A58",
        did: ICL_8A58,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A59",
        did: ICL_8A59,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A5A",
        did: ICL_8A5A,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A5B",
        did: ICL_8A5B,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A5C",
        did: ICL_8A5C,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A5D",
        did: ICL_8A5D,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A70",
        did: ICL_8A70,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    DeviceEntry {
        name: "intel-gpu-icl-8A71",
        did: ICL_8A71,
        generation: Generation::IceLake,
        asic: "icelake",
    },
    // Elkhart Lake (Gen11). Linux INTEL_EHL_IDS.
    DeviceEntry {
        name: "intel-gpu-ehl-4541",
        did: EHL_4541,
        generation: Generation::IceLake,
        asic: "elkhartlake",
    },
    DeviceEntry {
        name: "intel-gpu-ehl-4551",
        did: EHL_4551,
        generation: Generation::IceLake,
        asic: "elkhartlake",
    },
    DeviceEntry {
        name: "intel-gpu-ehl-4555",
        did: EHL_4555,
        generation: Generation::IceLake,
        asic: "elkhartlake",
    },
    DeviceEntry {
        name: "intel-gpu-ehl-4557",
        did: EHL_4557,
        generation: Generation::IceLake,
        asic: "elkhartlake",
    },
    DeviceEntry {
        name: "intel-gpu-ehl-4570",
        did: EHL_4570,
        generation: Generation::IceLake,
        asic: "elkhartlake",
    },
    DeviceEntry {
        name: "intel-gpu-ehl-4571",
        did: EHL_4571,
        generation: Generation::IceLake,
        asic: "elkhartlake",
    },
    // Jasper Lake (Gen11). Linux INTEL_JSL_IDS.
    DeviceEntry {
        name: "intel-gpu-jsl-4E51",
        did: JSL_4E51,
        generation: Generation::IceLake,
        asic: "jasperlake",
    },
    DeviceEntry {
        name: "intel-gpu-jsl-4E55",
        did: JSL_4E55,
        generation: Generation::IceLake,
        asic: "jasperlake",
    },
    DeviceEntry {
        name: "intel-gpu-jsl-4E57",
        did: JSL_4E57,
        generation: Generation::IceLake,
        asic: "jasperlake",
    },
    DeviceEntry {
        name: "intel-gpu-jsl-4E61",
        did: JSL_4E61,
        generation: Generation::IceLake,
        asic: "jasperlake",
    },
    DeviceEntry {
        name: "intel-gpu-jsl-4E71",
        did: JSL_4E71,
        generation: Generation::IceLake,
        asic: "jasperlake",
    },
    // Tiger Lake (Gen12 Xe-LP).
    DeviceEntry {
        name: "intel-gpu-tgl-9A40",
        did: TGL_GT2_9A40,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A49",
        did: TGL_U_GT2_9A49,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A59",
        did: TGL_U_GT2_9A59,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A60",
        did: TGL_H_GT1_9A60,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A68",
        did: TGL_H_GT1_9A68,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A70",
        did: TGL_H_GT1_9A70,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A78",
        did: TGL_GT2_9A78,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9AC0",
        did: TGL_GT2_9AC0,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9AC9",
        did: TGL_GT2_9AC9,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9AD9",
        did: TGL_GT2_9AD9,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9AF8",
        did: TGL_GT2_9AF8,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    // Rocket Lake (Gen12 Xe-LP GT; display remains separately gated).
    DeviceEntry {
        name: "intel-gpu-rkl-4C80",
        did: RKL_4C80,
        generation: Generation::RocketLake,
        asic: "rocketlake",
    },
    DeviceEntry {
        name: "intel-gpu-rkl-4C8A",
        did: RKL_4C8A,
        generation: Generation::RocketLake,
        asic: "rocketlake",
    },
    DeviceEntry {
        name: "intel-gpu-rkl-4C8B",
        did: RKL_4C8B,
        generation: Generation::RocketLake,
        asic: "rocketlake",
    },
    DeviceEntry {
        name: "intel-gpu-rkl-4C8C",
        did: RKL_4C8C,
        generation: Generation::RocketLake,
        asic: "rocketlake",
    },
    DeviceEntry {
        name: "intel-gpu-rkl-4C90",
        did: RKL_4C90,
        generation: Generation::RocketLake,
        asic: "rocketlake",
    },
    DeviceEntry {
        name: "intel-gpu-rkl-4C9A",
        did: RKL_4C9A,
        generation: Generation::RocketLake,
        asic: "rocketlake",
    },
    // Alder Lake-P.
    DeviceEntry {
        name: "intel-gpu-adl-4626",
        did: ADL_P_4626,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-4628",
        did: ADL_P_4628,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-462A",
        did: ADL_P_462A,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-4636",
        did: ADL_P_4636,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-4638",
        did: ADL_P_4638,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-463A",
        did: ADL_P_463A,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46A0",
        did: ADL_P_46A0,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46A1",
        did: ADL_P_46A1,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46A2",
        did: ADL_P_46A2,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46A3",
        did: ADL_P_46A3,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46A6",
        did: ADL_P_46A6,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46A8",
        did: ADL_P_46A8,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46AA",
        did: ADL_P_46AA,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46B6",
        did: ADL_P_46B6,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46B8",
        did: ADL_P_46B8,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46BA",
        did: ADL_P_46BA,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    // Keep the registered bus names for these Alder Lake-P devices.
    DeviceEntry {
        name: "intel-gpu-rpl-46B0",
        did: ADL_P_46B0,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-46B1",
        did: ADL_P_46B1,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-46B2",
        did: ADL_P_46B2,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-46B3",
        did: ADL_P_46B3,
        generation: Generation::AlderLake,
        asic: "alderlake-p",
    },
    // Alder Lake-M.
    DeviceEntry {
        name: "intel-gpu-adl-46C0",
        did: ADL_M_46C0,
        generation: Generation::AlderLake,
        asic: "alderlake-m",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46C1",
        did: ADL_M_46C1,
        generation: Generation::AlderLake,
        asic: "alderlake-m",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46C2",
        did: ADL_M_46C2,
        generation: Generation::AlderLake,
        asic: "alderlake-m",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46C3",
        did: ADL_M_46C3,
        generation: Generation::AlderLake,
        asic: "alderlake-m",
    },
    // Alder Lake-N.
    DeviceEntry {
        name: "intel-gpu-adl-46D0",
        did: ADL_N_46D0,
        generation: Generation::AlderLake,
        asic: "alderlake-n",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46D1",
        did: ADL_N_46D1,
        generation: Generation::AlderLake,
        asic: "alderlake-n",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46D2",
        did: ADL_N_46D2,
        generation: Generation::AlderLake,
        asic: "alderlake-n",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46D3",
        did: ADL_N_46D3,
        generation: Generation::AlderLake,
        asic: "alderlake-n",
    },
    DeviceEntry {
        name: "intel-gpu-adl-46D4",
        did: ADL_N_46D4,
        generation: Generation::AlderLake,
        asic: "alderlake-n",
    },
    // Alder Lake-S.
    DeviceEntry {
        name: "intel-gpu-adl-4680",
        did: ADL_S_4680,
        generation: Generation::AlderLake,
        asic: "alderlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-adl-4682",
        did: ADL_S_4682,
        generation: Generation::AlderLake,
        asic: "alderlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-adl-4688",
        did: ADL_S_4688,
        generation: Generation::AlderLake,
        asic: "alderlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-adl-468A",
        did: ADL_S_468A,
        generation: Generation::AlderLake,
        asic: "alderlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-adl-468B",
        did: ADL_S_468B,
        generation: Generation::AlderLake,
        asic: "alderlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-adl-4690",
        did: ADL_S_4690,
        generation: Generation::AlderLake,
        asic: "alderlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-adl-4692",
        did: ADL_S_4692,
        generation: Generation::AlderLake,
        asic: "alderlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-adl-4693",
        did: ADL_S_4693,
        generation: Generation::AlderLake,
        asic: "alderlake-s",
    },
    // Raptor Lake-S.
    DeviceEntry {
        name: "intel-gpu-rpl-A780",
        did: RPL_S_A780,
        generation: Generation::AlderLake,
        asic: "raptorlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A781",
        did: RPL_S_A781,
        generation: Generation::AlderLake,
        asic: "raptorlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A782",
        did: RPL_S_A782,
        generation: Generation::AlderLake,
        asic: "raptorlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A783",
        did: RPL_S_A783,
        generation: Generation::AlderLake,
        asic: "raptorlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A788",
        did: RPL_S_A788,
        generation: Generation::AlderLake,
        asic: "raptorlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A789",
        did: RPL_S_A789,
        generation: Generation::AlderLake,
        asic: "raptorlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A78A",
        did: RPL_S_A78A,
        generation: Generation::AlderLake,
        asic: "raptorlake-s",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A78B",
        did: RPL_S_A78B,
        generation: Generation::AlderLake,
        asic: "raptorlake-s",
    },
    // Raptor Lake-P / -U.
    DeviceEntry {
        name: "intel-gpu-rpl-A720",
        did: RPL_P_A720,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A721",
        did: RPL_U_A721,
        generation: Generation::AlderLake,
        asic: "raptorlake-u",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7A0",
        did: RPL_P_A7A0,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7A1",
        did: RPL_U_A7A1,
        generation: Generation::AlderLake,
        asic: "raptorlake-u",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7A8",
        did: RPL_P_A7A8,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7A9",
        did: RPL_U_A7A9,
        generation: Generation::AlderLake,
        asic: "raptorlake-u",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7AA",
        did: RPL_P_A7AA,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7AB",
        did: RPL_P_A7AB,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7AC",
        did: RPL_U_A7AC,
        generation: Generation::AlderLake,
        asic: "raptorlake-u",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7AD",
        did: RPL_U_A7AD,
        generation: Generation::AlderLake,
        asic: "raptorlake-u",
    },
    // Meteor Lake (Xe-LPG) — identify + announce only in this lane.
    DeviceEntry {
        name: "intel-gpu-mtl-7D40",
        did: MTL_7D40,
        generation: Generation::MeteorLake,
        asic: "meteorlake",
    },
    DeviceEntry {
        name: "intel-gpu-mtl-7D45",
        did: MTL_7D45,
        generation: Generation::MeteorLake,
        asic: "meteorlake",
    },
    DeviceEntry {
        name: "intel-gpu-mtl-7D55",
        did: MTL_7D55,
        generation: Generation::MeteorLake,
        asic: "meteorlake",
    },
    DeviceEntry {
        name: "intel-gpu-mtl-7D60",
        did: MTL_7D60,
        generation: Generation::MeteorLake,
        asic: "meteorlake",
    },
    DeviceEntry {
        name: "intel-gpu-mtl-7DD5",
        did: MTL_7DD5,
        generation: Generation::MeteorLake,
        asic: "meteorlake",
    },
    // Arrow Lake (Xe-LPG) — classified Generation::MeteorLake
    // (the silicon and both Linux drivers' binding), announced
    // under its own name. Display disposition is exactly the
    // Meteor Lake rows' above (Xe-LPG display, #1016).
    DeviceEntry {
        name: "intel-gpu-arl-7D41",
        did: ARL_7D41,
        generation: Generation::MeteorLake,
        asic: "arrowlake",
    },
    DeviceEntry {
        name: "intel-gpu-arl-7D51",
        did: ARL_7D51,
        generation: Generation::MeteorLake,
        asic: "arrowlake",
    },
    DeviceEntry {
        name: "intel-gpu-arl-7D67",
        did: ARL_7D67,
        generation: Generation::MeteorLake,
        asic: "arrowlake",
    },
    DeviceEntry {
        name: "intel-gpu-arl-7DD1",
        did: ARL_7DD1,
        generation: Generation::MeteorLake,
        asic: "arrowlake",
    },
    DeviceEntry {
        name: "intel-gpu-arl-B640",
        did: ARL_B640,
        generation: Generation::MeteorLake,
        asic: "arrowlake",
    },
    // Panther Lake (Xe3-LPG) — identify + announce only in this lane.
    DeviceEntry {
        name: "intel-gpu-ptl-B080",
        did: PTL_B080,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B081",
        did: PTL_B081,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B082",
        did: PTL_B082,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B083",
        did: PTL_B083,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B084",
        did: PTL_B084,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B085",
        did: PTL_B085,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B086",
        did: PTL_B086,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B087",
        did: PTL_B087,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B08F",
        did: PTL_B08F,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B090",
        did: PTL_B090,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B0A0",
        did: PTL_B0A0,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B0A1",
        did: PTL_B0A1,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    DeviceEntry {
        name: "intel-gpu-ptl-B0B0",
        did: PTL_B0B0,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
    // Wildcat Lake uses Linux's ptl_desc GT profile and its own display 30.02 route.
    DeviceEntry {
        name: "intel-gpu-wcl-FD80",
        did: WCL_FD80,
        generation: Generation::PantherLake,
        asic: "wildcatlake",
    },
    DeviceEntry {
        name: "intel-gpu-wcl-FD81",
        did: WCL_FD81,
        generation: Generation::PantherLake,
        asic: "wildcatlake",
    },
    // Nova Lake-S retains the broad post-Xe2 display-generation gate here;
    // GtPlatform carries its distinct GT, firmware and live-GMD identity.
    DeviceEntry {
        name: "intel-gpu-nvls-D740",
        did: NVLS_D740,
        generation: Generation::PantherLake,
        asic: "novalake-s",
    },
    DeviceEntry {
        name: "intel-gpu-nvls-D741",
        did: NVLS_D741,
        generation: Generation::PantherLake,
        asic: "novalake-s",
    },
    DeviceEntry {
        name: "intel-gpu-nvls-D742",
        did: NVLS_D742,
        generation: Generation::PantherLake,
        asic: "novalake-s",
    },
    DeviceEntry {
        name: "intel-gpu-nvls-D743",
        did: NVLS_D743,
        generation: Generation::PantherLake,
        asic: "novalake-s",
    },
    DeviceEntry {
        name: "intel-gpu-nvls-D744",
        did: NVLS_D744,
        generation: Generation::PantherLake,
        asic: "novalake-s",
    },
    DeviceEntry {
        name: "intel-gpu-nvls-D745",
        did: NVLS_D745,
        generation: Generation::PantherLake,
        asic: "novalake-s",
    },
    DeviceEntry {
        name: "intel-gpu-nvls-D74A",
        did: NVLS_D74A,
        generation: Generation::PantherLake,
        asic: "novalake-s",
    },
    DeviceEntry {
        name: "intel-gpu-nvls-D74B",
        did: NVLS_D74B,
        generation: Generation::PantherLake,
        asic: "novalake-s",
    },
];

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

/// Exact PCI matches in the same order for the resident and loadable drivers.
pub(crate) fn pci_matches() -> impl Iterator<Item = (&'static str, u16)> {
    [
        ("intel-gpu-dg1", DG1_IDS),
        ("intel-gpu-dg2", DG2_IDS),
        ("intel-gpu-bmg", BMG_IDS),
        ("intel-gpu-atsm", ATSM_IDS),
        ("intel-gpu-cri-gated", CRI_IDS),
        ("intel-gpu-nvlp-gated", NVLP_IDS),
    ]
    .into_iter()
    .flat_map(|(name, ids)| ids.iter().map(move |&id| (name, id)))
    .chain(DEVICE_TABLE.iter().map(|entry| (entry.name, entry.did)))
}
