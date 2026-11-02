//! Intel integrated graphics (Gen12 Xe-LP / Xe-LPG) — clean-room driver.
//!
//! Spec: `drivers/gpu/specification/intel_gpu.md`.
//!
//! ## References
//!
//! - **Intel "Linux Graphics Programmer's Reference Manual" hub** —
//!   per-generation public PDFs.
//!   <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/overview.html>
//! - **Tiger Lake PRM** (the conservative reference target):
//!   - **Vol. 12** — Display DDIs / Plane Programming.
//!   - **Vol. 14** — Display Engine (pipes + transcoders).
//!   - **Vol. 11** — Display Engine Registers (clocks).
//!   - **Vol.  5** — Memory Views (GTT / PPGTT).
//! - **Alder Lake PRM** — same Gen12 register surface; useful
//!   cross-check for ADL-S/-P iGPUs.
//! - **Meteor Lake display PRM** — Xe-LPG display engine.
//! - **Public `pci.ids` database** — every Intel iGPU device ID
//!   the upstream snapshot lists for Gen12 and later. This is the
//!   authority for the device table below (lane 1, #1010: IDs the
//!   summary research could not find in pci.ids v2.2 — 9A59 /
//!   9AC9 / 9AC0 / 46B2 / 46A2 — do not exist and are not listed).
//!
//! **No GPL Linux `i915` / `xe` source consulted for the driver
//! logic.** Register *values* in sibling modules are cross-checked
//! against public PRM volumes; where a PRM volume was not directly
//! readable, the module doc says so.
//!
//! ## Stage progression
//!
//! - **Stage 1** — PCI claim, BAR0 (GTTMMADR) mapping, presence
//!   test against `GMD_ID`, bound-driver record.
//! - **Stage 2** — Codec layer: GMBUS, DPLL, pipes, DDI, GTT
//!   register-codecs in sibling `crate::intel_gpu_*` modules.
//! - **Stage 3** — Modeset orchestrator takes over the firmware
//!   display (see `intel_gpu_modeset`).
//! - **Lane 1 (#1010)** — identification is a single canonical
//!   device table (registration and classification both derive
//!   from it, pinned by a census fixture); probe is panic-free
//!   and owns its scanout allocation; display programming is
//!   gated to Gen12 — Meteor Lake / Panther Lake identify and
//!   announce, but skip modeset (their display engines are
//!   #1016's lane).

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

use crate::intel_gpu_regions::{self, Region, RegionGeneration, RegionKind};

// ── Vendor + device ids ───────────────────────────────────────────

/// Intel Corporation (PCI Special Interest Group ID).
pub const INTEL_VENDOR: u16 = 0x8086;

/// PCI class triple for a VGA-compatible display controller. The
/// class-match backstop catches all VGA cards; `probe` filters by
/// vendor so non-Intel cards fall through to their own drivers.
const PCI_CLASS_DISPLAY: u8 = 0x03;

// Tiger Lake (Gen12 Xe-LP) — public `pci.ids` Intel rows.
pub const TGL_9A40: u16 = 0x9A40;
pub const TGL_U_GT2_9A49: u16 = 0x9A49;
pub const TGL_H_GT1_9A60: u16 = 0x9A60;
pub const TGL_H_GT2_9A68: u16 = 0x9A68;
pub const TGL_H_GT2_9A70: u16 = 0x9A70;
pub const TGL_GT2_9A78: u16 = 0x9A78;

// Alder Lake-P / Raptor Lake-P (Gen12, mobile).
pub const ADL_P_4626: u16 = 0x4626;
pub const ADL_P_4628: u16 = 0x4628;
pub const ADL_P_462A: u16 = 0x462A;
pub const ADL_P_4636: u16 = 0x4636;
pub const ADL_P_4638: u16 = 0x4638;
pub const ADL_P_463A: u16 = 0x463A;
pub const ADL_P_46A0: u16 = 0x46A0;
pub const ADL_P_46A1: u16 = 0x46A1;
pub const ADL_P_46A3: u16 = 0x46A3;
pub const ADL_P_46A6: u16 = 0x46A6;
pub const ADL_P_46A8: u16 = 0x46A8;
pub const ADL_P_46AA: u16 = 0x46AA;
pub const ADL_P_46B6: u16 = 0x46B6;
pub const ADL_P_46B8: u16 = 0x46B8;
pub const ADL_P_46BA: u16 = 0x46BA;
pub const RPL_P_46B0: u16 = 0x46B0;
pub const RPL_P_46B1: u16 = 0x46B1;
pub const RPL_P_46B3: u16 = 0x46B3;
// Alder Lake-M (Gen12, mobile).
pub const ADL_M_46C0: u16 = 0x46C0;
pub const ADL_M_46C1: u16 = 0x46C1;
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
pub const RPL_P_A721: u16 = 0xA721;
pub const RPL_P_A7A0: u16 = 0xA7A0;
pub const RPL_P_A7A1: u16 = 0xA7A1;
pub const RPL_P_A7A8: u16 = 0xA7A8;
pub const RPL_P_A7A9: u16 = 0xA7A9;
pub const RPL_P_A7AA: u16 = 0xA7AA;
pub const RPL_P_A7AB: u16 = 0xA7AB;
pub const RPL_P_A7AC: u16 = 0xA7AC;
pub const RPL_P_A7AD: u16 = 0xA7AD;

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
pub const PTL_B0B0: u16 = 0xB0B0;

// ── Generation classifier ────────────────────────────────────────

/// Gen12 sub-architecture identifier. Tiger Lake / Alder Lake /
/// Raptor Lake all share the Xe-LP register surface; Meteor Lake
/// uses Xe-LPG (different DDI / DPLL programming).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Generation {
    /// Tiger Lake — Gen12 Xe-LP. Conservative reference target.
    TigerLake,
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
    /// Panther Lake — Xe3-LPG. Display is Xe3_LPD: the DDI block
    /// moved again relative to Xe-LPG and the C10/C20 PHYs replace
    /// the combo-PHY + DPLL pair Gen12 used.
    PantherLake,
}

impl Generation {
    /// Map the sub-architecture to the BAR0 region-enumeration
    /// generation. TGL / ADL / RPL share the Xe-LP MMIO map
    /// (`RegionGeneration::Gen12`); Meteor Lake maps to the
    /// Xe-LPG region table (#1016); Panther Lake's Xe3-LPD map
    /// is not modelled yet.
    pub const fn region_generation(self) -> Option<RegionGeneration> {
        match self {
            Generation::TigerLake | Generation::AlderLake => Some(RegionGeneration::Gen12),
            Generation::MeteorLake => Some(RegionGeneration::XeLpg),
            Generation::PantherLake => None,
        }
    }

    /// Whether this lane programs the display engine for the
    /// generation. Gen12 (TGL/ADL/RPL) and Meteor Lake (Xe-LPG,
    /// #1016) have validated register sequences. Panther Lake
    /// stays gated off: Xe3-LPD is a different display IP
    /// generation from Xe-LPG (its own PHY arrangement, PLL
    /// tables, and widened clock-select fields), so claiming it
    /// from the MTL sequence would claim support that cannot be
    /// driven — the exact failure this gate exists to prevent.
    pub const fn display_supported(self) -> bool {
        matches!(
            self,
            Generation::TigerLake | Generation::AlderLake | Generation::MeteorLake
        )
    }

    /// The external sessions and HPD block currently implement Gen12 only.
    /// Xe-LPG's internal-panel sequence does not validate these registers.
    pub const fn external_display_supported(self) -> bool {
        matches!(self, Generation::TigerLake | Generation::AlderLake)
    }

    /// Whether the backlight PWM install is valid for the
    /// generation. The install programs the Gen12 BXT-style PWM
    /// block; MTL's backlight path is owned by the backlight
    /// composition lane (PR #1037, #947/#949/#951), which flips
    /// this predicate when the MTL registers land. Keeping it
    /// separate from `display_supported` lets the MTL modeset
    /// ship without claiming a backlight it cannot drive.
    pub const fn backlight_supported(self) -> bool {
        matches!(self, Generation::TigerLake | Generation::AlderLake)
    }
}

/// What Stage-1 knows about a probed Intel iGPU.
#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    pub vid: u16,
    pub did: u16,
    pub generation: Generation,
    /// Short ASIC name for diagnostics.
    pub asic: &'static str,
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

/// The canonical device table. Contents are pinned against
/// spec §5 by the census fixture in this module's tests; the IDs
/// themselves are transcribed from the public `pci.ids` database
/// (v2.2) Intel graphics rows.
pub const DEVICE_TABLE: &[DeviceEntry] = &[
    // Tiger Lake (Gen12 Xe-LP).
    DeviceEntry {
        name: "intel-gpu-tgl-9A40",
        did: TGL_9A40,
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
        name: "intel-gpu-tgl-9A60",
        did: TGL_H_GT1_9A60,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A68",
        did: TGL_H_GT2_9A68,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A70",
        did: TGL_H_GT2_9A70,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    },
    DeviceEntry {
        name: "intel-gpu-tgl-9A78",
        did: TGL_GT2_9A78,
        generation: Generation::TigerLake,
        asic: "tigerlake",
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
    // Raptor Lake-P (IDs the tree has always classified here).
    DeviceEntry {
        name: "intel-gpu-rpl-46B0",
        did: RPL_P_46B0,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-46B1",
        did: RPL_P_46B1,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-46B3",
        did: RPL_P_46B3,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
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
        did: RPL_P_A721,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7A0",
        did: RPL_P_A7A0,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7A1",
        did: RPL_P_A7A1,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7A8",
        did: RPL_P_A7A8,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7A9",
        did: RPL_P_A7A9,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
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
        did: RPL_P_A7AC,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
    },
    DeviceEntry {
        name: "intel-gpu-rpl-A7AD",
        did: RPL_P_A7AD,
        generation: Generation::AlderLake,
        asic: "raptorlake-p",
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
        name: "intel-gpu-ptl-B0B0",
        did: PTL_B0B0,
        generation: Generation::PantherLake,
        asic: "pantherlake",
    },
];

fn chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != INTEL_VENDOR {
        return None;
    }
    DEVICE_TABLE
        .iter()
        .find(|e| e.did == did)
        .map(|e| ChipInfo {
            vid,
            did,
            generation: e.generation,
            asic: e.asic,
        })
}

/// Scanout stride for a 32-bpp linear surface of `width` pixels,
/// padded up to the display engine's 64-byte stride alignment
/// (TGL PRM Vol. 14, `PLANE_STRIDE`). Before lane 1 the probe
/// used the unpadded `width * 4`, which `build_primary_plane`
/// rejects for widths like 1366 — and the probe `.expect()`ed
/// the result, panicking during Stage::Device probe on a common
/// laptop panel size.
pub const fn padded_stride_bytes(width: u32) -> u32 {
    let raw = width * 4;
    (raw + 63) & !63
}

/// Total scanout allocation size for `width`x`height` at the
/// padded stride.
pub const fn scanout_size_bytes(width: u32, height: u32) -> u64 {
    padded_stride_bytes(width) as u64 * height as u64
}

// ── BAR layout (TGL PRM Vol. 12 §"Memory Map and Configuration") ─

/// `GTTMMADR` — Graphics Translation Table + Memory-Mapped
/// register window. BAR0 on every Gen12 iGPU; the low half is
/// MMIO registers, the high half is the GTT entry array.
const BAR_GTTMMADR: u8 = 0;
/// `GMADR` — Graphics Memory aperture (stolen-memory frame
/// buffer). BAR2 on iGPUs.
const BAR_GMADR: u8 = 2;

// ── Identification register ──────────────────────────────────────

/// `GMD_ID` — Graphics Media Device Identifier (TGL PRM Vol. 12
/// §"Device Identification"). MMIO offset `0x000D8C`.
const GMD_ID: u64 = 0x0000_0D8C;

/// `MTCFG_TRBLK` cookie (TGL PRM Vol. 12 §"Identifier").
const MTCFG_TRBLK: u64 = 0x0000_0FF8;

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IntelGpuError {
    BarMapFailed,
    /// Vendor is Intel but the device id isn't in the table.
    UnknownAsic,
    /// MMIO presence test read garbage (all-ones).
    DeviceGone,
}

// ── Driver state ─────────────────────────────────────────────────

/// The scanout allocation owned by the probed device. Before
/// lane 1 the probe dropped the `Vec<PhysFrame>` returned by the
/// allocator at the end of probe — `PhysFrame` has no `Drop`
/// impl (freeing is explicit), so the frames leaked permanently
/// and the driver held no handle to its own scanout.
#[derive(Copy, Clone, Debug)]
pub struct ScanoutAllocation {
    pub gtt_offset: u32,
    /// Host-physical base of the contiguous surface.
    pub phys_base: u64,
    /// Buddy order of the backing block.
    pub order: u8,
    pub size_bytes: u64,
}

/// One probed Intel iGPU.
pub struct IntelGpu {
    pub gtt_mmadr: MmioRegion,
    pub gmadr: MmioRegion,
    pub chip: ChipInfo,
    /// `GMD_ID` value captured at probe time.
    pub gmd_id: u32,
    display_device: BusDevice,
    display_cap: Cap<BusDeviceCap, Write>,
    pub active_scanout: narf_lib::sync::IrqSafeSpinLock<Option<ActiveScanout>>,
    /// Owned scanout backing, set by probe when the allocation
    /// and plane programming succeed. `None` on PTL (display
    /// gated off) or when allocation failed (logged at probe).
    pub scanout: Option<ScanoutAllocation>,
    /// The same card instance installed in the DRM registry. A future PCI GT
    /// owner publishes discovery here instead of through a global device-ID map.
    pub drm_card: Option<alloc::sync::Arc<crate::drm_devfs_bridge::IntelGpuCard>>,
}

#[derive(Clone, Debug)]
pub struct ActiveScanout {
    pub width: u32,
    pub height: u32,
    pub stride_bytes: u32,
    pub gtt_offset: u32,
    /// Host-physical base of the surface (contiguous allocation),
    /// for framebuffer-console publication.
    pub phys_base: u64,
}

impl core::fmt::Debug for IntelGpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelGpu")
            .field("chip", &self.chip)
            .field("gmd_id", &self.gmd_id)
            .finish_non_exhaustive()
    }
}

impl IntelGpu {
    /// Map BAR0 (GTTMMADR) and BAR2 (GMADR), identify the chip,
    /// run a presence test against `GMD_ID`.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR2 exclusively for the duration of probe.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, IntelGpuError> {
        let chip = chip_info_for_pci_id(device.id.vendor, device.id.device)
            .ok_or(IntelGpuError::UnknownAsic)?;

        let gtt_mmadr =
            // SAFETY: `bring_up`'s contract gives us exclusive ownership of
            // BAR0 (`GTTMMADR`); `map_bar` maps the PCI BAR `device` advertises.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { map_bar(device, BAR_GTTMMADR) }.map_err(|_| IntelGpuError::BarMapFailed)?;
        let gmadr =
            // SAFETY: same contract grants exclusive ownership of BAR2 (`GMADR`);
            // `map_bar` maps the PCI BAR `device` advertises.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe { map_bar(device, BAR_GMADR) }.map_err(|_| IntelGpuError::BarMapFailed)?;

        // Presence smoke test: read `GMD_ID`. All-ones means the
        // BAR is mapped but the device isn't responding.
        // SAFETY: identity-mapped MMIO.
        let gmd_id = unsafe { gtt_mmadr.read32(GMD_ID) };
        if gmd_id == 0xFFFF_FFFF {
            return Err(IntelGpuError::DeviceGone);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        let trblk = unsafe { gtt_mmadr.read32(MTCFG_TRBLK) };
        if trblk == 0xFFFF_FFFF {
            return Err(IntelGpuError::DeviceGone);
        }

        Ok(Self {
            gtt_mmadr,
            gmadr,
            chip,
            gmd_id,
            display_device: *device,
            display_cap: *cap,
            active_scanout: narf_lib::sync::IrqSafeSpinLock::new(None),
            scanout: None,
            drm_card: None,
        })
    }

    pub(crate) fn mode_window(&self) -> ModeWindow {
        ModeWindow::new(self.gtt_mmadr, self.display_device, self.display_cap)
    }
    pub fn current_mode(&self) -> Option<ActiveScanout> {
        self.active_scanout.lock().clone()
    }

    pub fn chip_info(&self) -> ChipInfo {
        self.chip
    }

    pub fn gmd_id(&self) -> u32 {
        self.gmd_id
    }

    /// Enumerated BAR0 register-block table for this chip's
    /// generation, or an empty slice for generations the Stage-0
    /// region map doesn't cover.
    pub fn regions(&self) -> &'static [Region] {
        match self.chip.generation.region_generation() {
            Some(gen) => intel_gpu_regions::regions_for(gen),
            None => &[],
        }
    }

    /// Look up the region that contains `bar0_offset`, if any.
    pub fn region_at(&self, bar0_offset: u64) -> Option<&'static Region> {
        self.chip
            .generation
            .region_generation()
            .and_then(|gen| intel_gpu_regions::region_at(gen, bar0_offset))
    }

    /// Look up the region of a given kind.
    pub fn region_of(&self, kind: RegionKind) -> Option<&'static Region> {
        self.chip
            .generation
            .region_generation()
            .and_then(|gen| intel_gpu_regions::region_of(gen, kind))
    }
}

// ── Driver-match registration ────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<IntelGpu>> = IrqSafeSpinLock::new(None);

// KMS owns the display while its primary plane names a GEM surface. The
// console's own allocation is retained throughout, never republished as GEM.
static KMS_CONSOLE_PAUSED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static KMS_SAVED_CONSOLE: IrqSafeSpinLock<Option<narf_graphics::FbConsole>> =
    IrqSafeSpinLock::new(None);

/// Also checked inside the framebuffer view epoch: an old cached writer
/// cannot pass its admission check before pause and capture pixels after it.
pub fn kms_console_paused() -> bool {
    KMS_CONSOLE_PAUSED.load(Ordering::Acquire)
}

/// Caller holds the KMS display session, outside CONTROLLER. Pause new
/// kernel framebuffer access, drain the synchronous log writer, then wait
/// for every earlier cursor/status/draw view (including its WC fence).
/// Cancellation leaves the console paused until verified console restoration.
pub(crate) async fn kms_pause_console() {
    crate::scanout_access::replace(|| {
        if !KMS_CONSOLE_PAUSED.swap(true, Ordering::AcqRel) {
            *KMS_SAVED_CONSOLE.lock() = narf_graphics::console::GLOBAL_FB_CONSOLE.lock().take();
        }
    });
    crate::scanout_access::wait_retired().await;
}

/// Caller holds the KMS display session and has proved the original owned
/// console surface latched (or that GEM fetch never started). Failed stop
/// paths deliberately retain the paused state and saved console.
pub(crate) fn kms_resume_console() {
    crate::scanout_access::replace(|| {
        if KMS_CONSOLE_PAUSED.load(Ordering::Acquire) {
            *narf_graphics::console::GLOBAL_FB_CONSOLE.lock() = KMS_SAVED_CONSOLE.lock().take();
            KMS_CONSOLE_PAUSED.store(false, Ordering::Release);
        }
    });
}

fn log_probe(msg: &str, device: &BusDevice) {
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "intel-gpu: {} (PCI {:04x}:{:04x})",
        msg,
        device.id.vendor,
        device.id.device,
    );
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device)
        .is_some_and(crate::intel_gpu_gt::GtPlatform::is_discrete)
    {
        return crate::intel_gpu_gt_runtime::probe_discrete(device, cap);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    if device.id.vendor != INTEL_VENDOR {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let mut dev = match unsafe { IntelGpu::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(IntelGpuError::UnknownAsic) => {
            // Announced, not silent: an Intel DID outside the
            // table is a coverage gap, not broken silicon.
            log_probe(
                "unsupported Intel ASIC — device id not in the driver table",
                &device,
            );
            return Err(narf_bus::ProbeError::NotForThisDriver);
        }
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu: bring-up failed: {:?} (PCI {:04x}:{:04x})",
                e,
                device.id.vendor,
                device.id.device,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    // Stage-0 announce.
    {
        use core::fmt::Write as _;
        let bar0_phys = dev.gtt_mmadr.phys.raw();
        let region_count = dev.regions().len();
        let _ = writeln!(
            narf_console::Writer,
            "intel-gpu: detected {} (PCI {:04x}:{:04x}, gen={:?}, GMD_ID={:#010x}) BAR0={:#018x} regions={}",
            dev.chip.asic,
            dev.chip.vid,
            dev.chip.did,
            dev.chip.generation,
            dev.gmd_id,
            bar0_phys,
            region_count,
        );
    }

    let mut panel_mode: Option<crate::intel_gpu_modeset::Mode> = None;
    if dev.chip.generation.display_supported() {
        // eDP panel power sequencing (#1020): the panel must be
        // sequenced on before any AUX traffic (the EDID read
        // inside takeover), modeset, or backlight enable. A
        // panel that fails its sequence is left powered-down:
        // no backlight install, no takeover, no scanout move.
        let window = crate::intel_gpu_edp::BarWindow(&dev.gtt_mmadr);
        let mut pps = crate::intel_gpu_edp::PanelPowerSequencer::new(&window);
        pps.init_registers();
        crate::intel_gpu_edp::runtime_install_panel(
            pps.delays(),
            crate::intel_gpu_edp::PsrLayout::from_generation(dev.chip.generation),
        );
        let panel_on = match pps.power_on() {
            Ok(()) => true,
            Err(e) => {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: eDP panel power sequence failed: {:?} — panel left powered down, display skipped",
                    e,
                );
                false
            }
        };

        // Take over the firmware display. The takeover modeset
        // programs the plane at the GOP surface; probe then moves
        // scanout to the owned allocation below — the second
        // plane programming is deliberate (dropping it would
        // leave `active_scanout` naming a buffer the plane is
        // not scanning), but it no longer panics and it logs
        // each failing step instead of collapsing to silence.
        let mode_opt = if panel_on {
            // Activate backlight PWM where the generation's PWM
            // block is modelled (Gen12 today; MTL's install is
            // gated on the backlight composition lane, PR #1037).
            if dev.chip.generation.backlight_supported() {
                narf_drivers_backlight::intel_bl::install(dev.gtt_mmadr);
            }
            let mode = crate::intel_gpu_modeset::takeover_display(&dev);
            if mode.is_some() {
                // The PPS backlight gate opens only with live
                // video; T8 runs from the power-on stamp inside
                // the sequencer.
                let _ = pps.backlight_on();
            }
            mode
        } else {
            None
        };
        panel_mode = mode_opt;

        // The internal display owns Pipe A from here on
        // (#1017): external sessions arbitrate the remaining
        // pipes through `intel_gpu_multipipe` instead of
        // silently sharing this one. Claimed only when a
        // firmware pipeline was actually taken over — with no
        // internal display live, Pipe A stays free for the
        // first external session, as before multi-pipe support.
        if mode_opt.is_some() {
            let _ = crate::intel_gpu_multipipe::claim_pipe(
                crate::intel_gpu_pipes::Pipe::A,
                crate::intel_gpu_multipipe::PipeOwner {
                    ddi: crate::intel_gpu_ddi::Ddi::A,
                    used_for: crate::intel_gpu_multipipe::PipeUse::InternalPanel,
                },
            );
        }

        // A powered panel alone does not establish a scanning pipeline.
        // Allocate and publish only after takeover returned an actual mode.
        if let Some(mode) = mode_opt {
            let width = u32::from(mode.h_active);
            let height = u32::from(mode.v_active);
            let stride_bytes = padded_stride_bytes(width);
            let size_bytes = scanout_size_bytes(width, height);

            match crate::intel_gpu_gtt::alloc_contiguous_scanout(&dev.gtt_mmadr, size_bytes) {
                Ok(alloc) => {
                    let phys_base = alloc.phys_base();
                    dev.scanout = Some(ScanoutAllocation {
                        gtt_offset: alloc.gtt_offset,
                        phys_base,
                        order: alloc.order,
                        size_bytes: alloc.size_bytes,
                    });
                    match crate::intel_gpu_pipes::build_primary_plane(
                        width as u16,
                        height as u16,
                        stride_bytes,
                        alloc.gtt_offset,
                        crate::intel_gpu_pipes::PixelFormat::Argb8888,
                    ) {
                        Ok(prog) => {
                            let plane_base = crate::intel_gpu_pipes::Pipe::A.base()
                                + crate::intel_gpu_pipes::PLANE_PRIMARY_OFFSET;
                            // SAFETY: `dev.gtt_mmadr` is the BAR0 region mapped in
                            // `bring_up`, and we own the device. `plane_base` is
                            // Pipe A's primary plane block; every offset is a
                            // known in-range plane register.
                            // SAFETY: Valid MMIO bounds or trusted driver environment
                            unsafe {
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_STRIDE_OFFSET,
                                    prog.plane_stride,
                                );
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_SIZE_OFFSET,
                                    prog.plane_size,
                                );
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_OFFSET_OFFSET,
                                    prog.plane_offset,
                                );
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_CTL_OFFSET,
                                    prog.plane_ctl,
                                );
                                dev.gtt_mmadr.write32(
                                    plane_base + crate::intel_gpu_pipes::PLANE_SURF_OFFSET,
                                    prog.plane_surf,
                                );
                            }
                            compiler_fence(Ordering::SeqCst);
                            *dev.active_scanout.lock() = Some(ActiveScanout {
                                width,
                                height,
                                stride_bytes,
                                gtt_offset: alloc.gtt_offset,
                                phys_base,
                            });
                        }
                        Err(e) => {
                            use core::fmt::Write as _;
                            let _ = writeln!(
                            narf_console::Writer,
                            "intel-gpu: primary-plane build failed: {:?} ({}x{} stride {}) — scanout allocated but plane not reprogrammed",
                            e, width, height, stride_bytes,
                        );
                        }
                    }
                }
                Err(e) => {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: scanout allocation failed: {:?} ({}x{} padded stride {}, {} bytes) — display left on firmware surface",
                    e, width, height, stride_bytes, size_bytes,
                );
                }
            }
        }
    } else {
        // PTL: identification is real, but Xe3-LPD is a
        // different display IP generation from both Gen12 and
        // Xe-LPG — no validated sequence exists for it yet.
        log_probe(
            "display programming skipped — Xe3-LPD display engine is not modelled (Panther Lake gated off in #1016)",
            &device,
        );
    }

    // The qualified full-AUX MTL owner is installed only after actual mode,
    // retained scanout and the internal Pipe-A claim exist. Other profiles
    // keep their existing backlight mechanism; no MTL PWM gate is widened.
    crate::intel_dpcd_bl::install_mtl(&dev, device, cap);

    // PSR bring-up (#1020): only for an eDP panel that powered
    // on and produced a real mode. Every failure path inside
    // leaves the panel running plain eDP.
    if let Some(mode) = panel_mode {
        crate::intel_gpu_edp::enable_psr_for_panel(&dev, &mode);
    }

    // Media-engine inventory (#1022): announce exactly the
    // execlists media engines the submission path can drive
    // on this part — the same list `intel_gpu_media` attaches
    // lazily on first submit.
    if let Some(rg) = dev.chip_info().generation.region_generation() {
        let engines = crate::intel_gpu_media::media_engines_for(rg);
        if !engines.is_empty() {
            let mut names = alloc::string::String::new();
            for (i, spec) in engines.iter().enumerate() {
                if i > 0 {
                    names.push(' ');
                }
                names.push_str(spec.name);
            }
            log_probe(&alloc::format!("media engines present: {}", names), &device);
        }
    }

    let scanout_mode = dev.current_mode();
    let kms_console = scanout_mode.clone();
    let kms_generation = dev.chip.generation;
    // Power management (Q9, #1015) covers the Gen12 register
    // map only. Xe-LPG now has a region map and a display
    // engine (#1016); its separate GT owner handles system PM below.
    // The legacy forcewake/RC6/DMC PM owner remains Gen12-only.
    let pm_supported = matches!(
        dev.chip.generation.region_generation(),
        Some(RegionGeneration::Gen12)
    );
    // Register with drm_registry. With a live scanout the card
    // carries real KMS mode state (CRTC 1 + mode, encoder 2,
    // eDP connector 3 — the virtio/bochs pattern in lib.rs) and
    // the scanout is published to the framebuffer console;
    // without one (PTL gate, allocation failure) the card
    // stays identity-only, as before lane 1.
    let drm_count = crate::drm_registry::count() as u32;
    let card_name = alloc::format!("card{}", drm_count);
    let intel_card = alloc::sync::Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
        card_name,
        device.id.vendor,
        device.id.device,
        device.id.subsystem_vendor,
        device.id.subsystem_id,
    ));
    dev.drm_card = Some(intel_card.clone());
    let gt_card = intel_card.clone();
    let gt_bar = dev.gtt_mmadr;
    *CONTROLLER.lock() = Some(dev);
    let owns_scanout = scanout_mode.is_some();
    let card_index = match scanout_mode {
        Some(mode) => {
            use crate::drm::card::{
                Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType,
            };
            let kms_mode = crate::Mode {
                width: mode.width,
                height: mode.height,
                refresh_hz: 60,
                bpp: 32,
            };
            let mut kms = Card::new("intel-gpu", "NARF Intel iGPU driver", (1, 0, 0));
            kms.crtcs.push(Crtc {
                id: 1,
                mode: Some(kms_mode),
                enabled: true,
                primary_fb: None,
                x: 0,
                y: 0,
            });
            kms.encoders.push(Encoder {
                id: 2,
                // i915 reports DP encoders as TMDS to userspace.
                encoder_type: EncoderType::Tmds,
                possible_crtcs: 0x1,
                possible_clones: 0,
                crtc_id: Some(1),
            });
            kms.connectors.push(Connector {
                id: 3,
                connector_type: ConnectorType::Edp,
                connector_type_id: 1,
                status: ConnectorStatus::Connected,
                encoder_id: Some(2),
                modes: alloc::vec![kms_mode],
            });
            let index = crate::drm_registry::register_drm_card_with_state(intel_card, kms);
            publish_scanout(Some(narf_graphics_driver::generic::GenericFb::new(
                mode.phys_base,
                mode.width,
                mode.height,
                mode.stride_bytes,
                32,
            )));
            index
        }
        None => crate::drm_registry::register_drm_card(intel_card),
    };
    if let Some(console) = kms_console {
        crate::intel_gpu_kms::install(card_index, kms_generation, gt_bar, device, cap, console);
    }
    // A retained firmware scanout has not granted us its GGTT reservation.
    // Start automatically only after this driver owns the integrated scanout.
    if owns_scanout {
        crate::intel_gpu_gt_runtime::install(card_index, gt_card, device, cap, gt_bar, panel_mode);
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-gpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });

    // External DP (lane Q4, #1092): program the combo-DDI HPD
    // interrupt enables and pick up a sink that was already
    // attached at boot. The session connect path re-checks the
    // generation's display support itself.
    with_controller(|gpu| {
        let window = DpBarWindow(&gpu.gtt_mmadr);
        enable_external_hpd(&window, gpu.chip.generation);
    });
    poll_dp_hpd_events();

    // Power management (Q9, #1015): retain the PCI authority,
    // note the takeover mode for resume re-light, and register
    // the device-PM + suspend-hook pair. Last, so a failed
    // probe never leaves a registration behind.
    if pm_supported {
        crate::intel_gpu_pm::register_pm(device, cap, panel_mode);
    }
    Ok(())
}

/// Re-establish the display after a D3 excursion (Q9, #1015):
/// allocate a fresh scanout at `mode`'s dimensions and run
/// the real modeset at it. The GGTT PTEs behind the
/// pre-suspend surface do not survive D3, so — exactly as
/// probe does — the surface is re-allocated and the plane
/// reprogrammed, never restored in place. On success the
/// controller's scanout state and the fb-console publication
/// follow the new surface. Returns the new active scanout.
pub fn relight_display(mode: &crate::intel_gpu_modeset::Mode) -> Option<ActiveScanout> {
    let display =
        with_controller(|gpu| crate::intel_gpu_kms::display_for_bar(&gpu.gtt_mmadr)).flatten();
    let mut ownership = match display.as_ref() {
        Some(display) => Some(display.legacy().ok()?),
        None => None,
    };
    if let Some(guard) = ownership.as_mut() {
        guard.suspend();
    }
    let console = relight_display_locked(mode)?;
    if let Some(guard) = ownership.as_mut() {
        guard.console_replaced(&console);
    }
    Some(console)
}

/// The caller already holds the display's LegacyGuard. Used by the PM core
/// so its outer power-transition exclusion is retained through publication.
pub(crate) fn relight_display_locked(
    mode: &crate::intel_gpu_modeset::Mode,
) -> Option<ActiveScanout> {
    let display = with_display_info(|display| *display)?;
    if !display.chip.generation.display_supported() {
        return None;
    }
    let aux_backlight = crate::intel_dpcd_bl::installed(&display.gtt_mmadr);
    if aux_backlight {
        crate::intel_dpcd_bl::prepare_relight_for_bar(&display.gtt_mmadr).ok()?;
    }
    let width = u32::from(mode.h_active);
    let height = u32::from(mode.v_active);
    let stride_bytes = padded_stride_bytes(width);
    let size_bytes = scanout_size_bytes(width, height);
    let alloc =
        crate::intel_gpu_gtt::alloc_contiguous_scanout(&display.gtt_mmadr, size_bytes).ok()?;
    let fb = crate::intel_gpu_modeset::Framebuffer {
        phys_addr: u64::from(alloc.gtt_offset),
        stride_bytes,
        format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
    };
    let window = ModeWindow::new(display.gtt_mmadr, display.device, display.cap);
    let applied = crate::intel_gpu_modeset::modeset_display(
        &window,
        display.chip.generation,
        &fb,
        Some(mode),
    )
    .ok()?;
    let scanout = ActiveScanout {
        width: u32::from(applied.h_active),
        height: u32::from(applied.v_active),
        stride_bytes,
        gtt_offset: alloc.gtt_offset,
        phys_base: alloc.phys_base(),
    };
    let mut guard = CONTROLLER.lock();
    let dev = guard.as_mut()?;
    if dev.gtt_mmadr.phys != display.gtt_mmadr.phys {
        return None;
    }
    dev.scanout = Some(ScanoutAllocation {
        gtt_offset: alloc.gtt_offset,
        phys_base: alloc.phys_base(),
        order: alloc.order,
        size_bytes: alloc.size_bytes,
    });
    *dev.active_scanout.lock() = Some(scanout.clone());
    let phys_base = scanout.phys_base;
    let (w, h) = (scanout.width, scanout.height);
    drop(guard);
    publish_scanout(Some(narf_graphics_driver::generic::GenericFb::new(
        phys_base,
        w,
        h,
        stride_bytes,
        32,
    )));
    if aux_backlight {
        crate::intel_dpcd_bl::resume_for_bar(&display.gtt_mmadr).ok()?;
    }
    Some(scanout)
}

/// Register one exact-match PCI driver per row of the canonical
/// device table, plus the class-match backstop.
pub fn register_pci_driver() {
    for (name, ids) in [
        ("intel-gpu-dg2", crate::intel_gpu_gt::DG2_IDS),
        ("intel-gpu-bmg", crate::intel_gpu_gt::BMG_IDS),
    ] {
        for &device in ids {
            narf_bus::register_pci_driver(narf_bus::PciMatch {
                name,
                kind: narf_bus::MatchKind::VendorDevice {
                    vendor: INTEL_VENDOR,
                    device,
                },
                probe,
            });
        }
    }
    for entry in DEVICE_TABLE.iter() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: entry.name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: INTEL_VENDOR,
                device: entry.did,
            },
            probe,
        });
    }
    // Class-match backstop. The probe body filters non-Intel
    // vendors so AMD / NVIDIA / virtio-gpu cards aren't claimed,
    // and announces unknown Intel DIDs instead of failing silently.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "intel-gpu-class",
        kind: narf_bus::MatchKind::Class {
            class: PCI_CLASS_DISPLAY,
            mask: 0xFF,
        },
        probe,
    });
}

// ── Framebuffer-console publication (lane 1, #1010 item 4) ──────
//
// Mirrors the AMD publication protocol in `amdgpu_dcn_display`:
// an ACTIVE slot plus a single observer fn pointer, so the fb
// crate (which depends on this crate, not the reverse) can
// follow the Intel scanout exactly the way it follows AMD's.
// Publishing records ACTIVE first; an observer installed late
// is told the current value immediately, so install order
// between probe (Stage::Device) and the fb initcall
// (Stage::Late) does not matter.

/// Told when the active Intel scanout appears or goes away.
pub type ScanoutObserver = fn(Option<narf_graphics_driver::generic::GenericFb>);
static ACTIVE_GENERIC: IrqSafeSpinLock<Option<narf_graphics_driver::generic::GenericFb>> =
    IrqSafeSpinLock::new(None);
static SCANOUT_OBSERVER: IrqSafeSpinLock<Option<ScanoutObserver>> = IrqSafeSpinLock::new(None);

/// The Intel scanout currently published to the fb console.
pub fn active_scanout_generic() -> Option<narf_graphics_driver::generic::GenericFb> {
    *ACTIVE_GENERIC.lock()
}

/// Install the fb-console observer. Called once during
/// Stage::Late; a scanout that already exists is replayed
/// immediately so the edge cannot be missed.
pub fn register_scanout_observer(observer: ScanoutObserver) {
    *SCANOUT_OBSERVER.lock() = Some(observer);
    let current = *ACTIVE_GENERIC.lock();
    if current.is_some() {
        observer(current);
    }
}

/// Publish (or withdraw) the Intel scanout. Locks are released
/// before the observer runs, so an observer that reads
/// `active_scanout_generic` cannot deadlock against this.
fn publish_scanout(scanout: Option<narf_graphics_driver::generic::GenericFb>) {
    *ACTIVE_GENERIC.lock() = scanout;
    let observer = *SCANOUT_OBSERVER.lock();
    if let Some(observer) = observer {
        observer(scanout);
    }
    // #1020: a scanout publish is a full-frame update, which is
    // what exits PSR — notify the eDP runtime. No-op when no
    // PSR session is active; called with no locks held, like
    // the observer above.
    if scanout.is_some() {
        crate::intel_gpu_edp::on_scanout_published();
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&IntelGpu) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Permanent probe-mapped display identity. Slow AUX/modeset operations use
/// this snapshot under a LegacyGuard rather than retaining CONTROLLER while
/// responsive waits run framebuffer pumps which also query the controller.
#[derive(Copy, Clone, Debug)]
pub(crate) struct DisplayInfo {
    pub gtt_mmadr: MmioRegion,
    pub chip: ChipInfo,
    pub gmd_id: u32,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
}

/// Current PCI authority and D0 checked window for owned modesets. Slow
/// register programming never holds CONTROLLER or uses a prior grant alone.
#[derive(Debug)]
pub(crate) struct ModeWindow {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    io: crate::intel_gpu_gt_hw::AuthorizedWindow,
}
impl ModeWindow {
    fn new(bar: MmioRegion, device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Self {
        Self {
            device,
            cap,
            io: crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap),
        }
    }
    fn powered(&self) -> bool {
        narf_bus::pci::power_state(&self.cap, &self.device)
            == Ok(Some(narf_bus::pci::PciPowerState::D0))
    }
}
impl crate::intel_gpu_aux::MmioWindow for ModeWindow {
    fn read32(&self, reg: u64) -> u32 {
        if self.powered() {
            self.io.read32(reg)
        } else {
            u32::MAX
        }
    }
    fn write32(&self, reg: u64, value: u32) {
        if self.powered() {
            self.io.write32(reg, value)
        }
    }
}
pub(crate) fn with_display_info<R>(f: impl FnOnce(&DisplayInfo) -> R) -> Option<R> {
    let display = CONTROLLER.lock().as_ref().map(|gpu| DisplayInfo {
        gtt_mmadr: gpu.gtt_mmadr,
        chip: gpu.chip,
        gmd_id: gpu.gmd_id,
        device: gpu.display_device,
        cap: gpu.display_cap,
    })?;
    Some(f(&display))
}

// ── External DisplayPort session (lane Q4, #1092) ──────────────
//
// The HPD-driven external-DP path: `intel_gpu_dp` owns the
// session logic (caps, negotiation, training, ELD publication);
// this glue owns the parts that need the probed controller —
// the BAR window, the scanout allocation (same allocator and
// lifetime as probe's own scanout: the GTT allocator has no
// free path, so a session allocation is retained and reused
// across reconnects while it fits), and scanout publication
// through the same ACTIVE + observer protocol as the takeover
// path. Since #1017 a session claims its pipe from
// `intel_gpu_multipipe` and allocates in that pipe's GGTT
// window, so an internal panel and external sessions scan out
// concurrently; the fb-console publication slot is still
// single, so the last HPD event wins it.

/// `MmioWindow` over the controller's BAR0 mapping (same
/// adapter shape as the DP Alt-Mode bridge).
struct DpBarWindow<'a>(&'a MmioRegion);

impl crate::intel_gpu_aux::MmioWindow for DpBarWindow<'_> {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: BAR0 is mapped for the lifetime of `IntelGpu`;
        // `off` is a display register offset from the DP
        // session code, and a 32-bit register read has no
        // unwanted side effect.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.0.read32(off) }
    }
    fn write32(&self, off: u64, val: u32) {
        // SAFETY: same BAR ownership as `read32`; `off` is a
        // programmable display register.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.0.write32(off, val) }
    }
}

/// Live external-DP session state: the connection, the
/// framebuffer it scans out, and its retained allocation.
struct DpSessionState {
    conn: crate::intel_gpu_dp::DpConnection,
    fb: crate::intel_gpu_modeset::Framebuffer,
    alloc: ScanoutAllocation,
}

static DP_SESSION: IrqSafeSpinLock<Option<DpSessionState>> = IrqSafeSpinLock::new(None);

/// Live external-HDMI session state; same shape and
/// discipline as [`DpSessionState`]. A connector is either
/// DP or HDMI at a time — whichever probe answers owns the
/// DDI's session slot.
struct HdmiSessionState {
    conn: crate::intel_gpu_hdmi::HdmiConnection,
    fb: crate::intel_gpu_modeset::Framebuffer,
    alloc: ScanoutAllocation,
}

static HDMI_SESSION: IrqSafeSpinLock<Option<HdmiSessionState>> = IrqSafeSpinLock::new(None);

/// Drain pending combo-DDI hotplug events and act on them.
/// Called once at the end of probe (a sink already attached at
/// boot is picked up there); a future periodic-polled caller
/// can invoke it the same way.
pub fn poll_dp_hpd_events() {
    let display =
        with_controller(|gpu| crate::intel_gpu_kms::display_for_bar(&gpu.gtt_mmadr)).flatten();
    let mut ownership = match display.as_ref() {
        Some(display) => match display.legacy() {
            Ok(guard) => Some(guard),
            Err(_) => return,
        },
        None => None,
    };
    loop {
        let event = with_display_info(|gpu| {
            let window = DpBarWindow(&gpu.gtt_mmadr);
            poll_external_hpd(&window, gpu.chip.generation)
        });
        match event {
            Some(Some(event)) => {
                if let Some(guard) = ownership.as_mut() {
                    // External programming may change pipe ownership or
                    // shared watermarks. Re-admit fixed internal flips only
                    // after an explicit owned-console re-establishment.
                    guard.suspend();
                }
                handle_dp_hpd_event(event);
            }
            _ => return,
        }
    }
}

fn enable_external_hpd<M: crate::intel_gpu_aux::MmioWindow>(mmio: &M, generation: Generation) {
    if generation.external_display_supported() {
        crate::intel_gpu_dp::enable_hpd_interrupts(mmio);
    }
}

fn poll_external_hpd<M: crate::intel_gpu_aux::MmioWindow>(
    mmio: &M,
    generation: Generation,
) -> Option<crate::intel_gpu_dp::HpdEvent> {
    if !generation.external_display_supported() {
        return None;
    }
    crate::intel_gpu_dp::poll_hpd_event(mmio)
}

fn handle_dp_hpd_event(event: crate::intel_gpu_dp::HpdEvent) {
    use crate::intel_gpu_dp::HpdEvent;
    match event {
        HpdEvent::Connected(ddi) => {
            // An MST branch device (hub / dock / daisy-chain
            // monitor) gets the MST session (#1017): if the
            // device advertises MST and a stream comes up, the
            // SST path never runs for this connector. Anything
            // else — an SST sink, or an MST attempt that found
            // no usable sink — falls through to the SST connect.
            if mst_session_ddi() == Some(ddi) {
                // MST session already live on this connector; a
                // repeat connect event changes nothing.
                return;
            }
            if mst_connect(ddi) {
                let stored = {
                    let session = MST_SESSION.lock();
                    session.as_ref().and_then(|s| {
                        s.streams
                            .first()
                            .map(|g| (g.alloc, g.fb, g.mode.h_active, g.mode.v_active))
                    })
                };
                if let Some((alloc, fb, width, height)) = stored {
                    publish_scanout(Some(narf_graphics_driver::generic::GenericFb::new(
                        alloc.phys_base,
                        width as u32,
                        height as u32,
                        fb.stride_bytes,
                        32,
                    )));
                }
                return;
            }
            if let Some(conn) = dp_connect(ddi) {
                // Publish from the stored session state (the
                // retained allocation + framebuffer the session
                // actually scans out).
                let stored = {
                    let session = DP_SESSION.lock();
                    session.as_ref().map(|s| (s.alloc, s.fb))
                };
                if let Some((alloc, fb)) = stored {
                    publish_scanout(Some(narf_graphics_driver::generic::GenericFb::new(
                        alloc.phys_base,
                        conn.mode.h_active as u32,
                        conn.mode.v_active as u32,
                        fb.stride_bytes,
                        32,
                    )));
                }
            } else if let Some(conn) = hdmi_connect(ddi) {
                // The DP probe did not answer; the HDMI one
                // did. Publish from the HDMI session state the
                // same way.
                let stored = {
                    let session = HDMI_SESSION.lock();
                    session.as_ref().map(|s| (s.alloc, s.fb))
                };
                if let Some((alloc, fb)) = stored {
                    publish_scanout(Some(narf_graphics_driver::generic::GenericFb::new(
                        alloc.phys_base,
                        conn.mode.h_active as u32,
                        conn.mode.v_active as u32,
                        fb.stride_bytes,
                        32,
                    )));
                }
            }
        }
        HpdEvent::Disconnected(ddi) => {
            if mst_session_ddi() == Some(ddi) {
                mst_disconnect(ddi);
                publish_scanout(None);
                return;
            }
            let session = DP_SESSION.lock().take();
            if let Some(state) = session {
                if state.conn.ddi == ddi {
                    with_display_info(|gpu| {
                        let window = DpBarWindow(&gpu.gtt_mmadr);
                        crate::intel_gpu_dp::disconnect(&window, &state.conn);
                        // Hand the pipe back and re-split the
                        // DBUF pool across the survivors.
                        crate::intel_gpu_multipipe::release_pipe(state.conn.pipe, ddi);
                        crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
                    });
                    publish_scanout(None);
                    return;
                }
                *DP_SESSION.lock() = Some(state);
            }
            let session = HDMI_SESSION.lock().take();
            if let Some(state) = session {
                if state.conn.ddi == ddi {
                    with_display_info(|gpu| {
                        let window = DpBarWindow(&gpu.gtt_mmadr);
                        crate::intel_gpu_hdmi::disconnect(&window, &state.conn);
                    });
                    publish_scanout(None);
                } else {
                    *HDMI_SESSION.lock() = Some(state);
                }
            }
        }
        HpdEvent::RetrainRequired(ddi) => {
            if mst_session_ddi() == Some(ddi) {
                // MST links don't revalidate per-lane status the
                // SST way; branch notifications are the change
                // channel. Drain them (they're also how a sink
                // disappearing mid-session first surfaces).
                mst_poll_notifications(ddi);
                return;
            }
            // Snapshot under the session lock, retrain against
            // the controller, then store back — never hold
            // DP_SESSION across `with_controller` (the connect
            // path takes the locks in the opposite order).
            let current = {
                let session = DP_SESSION.lock();
                session
                    .as_ref()
                    .filter(|state| state.conn.ddi == ddi)
                    .map(|state| (state.conn.clone(), state.fb))
            };
            if let Some((conn, fb)) = current {
                let updated = with_display_info(|gpu| {
                    let window = DpBarWindow(&gpu.gtt_mmadr);
                    let out = crate::intel_gpu_dp::retrain(&window, &conn, &fb).ok();
                    if out.is_some() {
                        // The retrained modeset wrote the
                        // single-pipe watermark shape; restore
                        // the multi-pipe DBUF split.
                        crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
                    }
                    out
                });
                if let Some(Some(new_conn)) = updated {
                    let mut session = DP_SESSION.lock();
                    if let Some(state) = session.as_mut() {
                        if state.conn.ddi == ddi {
                            state.conn = new_conn;
                        }
                    }
                }
            }
        }
    }
}

/// Run one external-DP connect against the probed controller:
/// probe the sink over AUX, claim a pipe, allocate its scanout
/// in the pipe's GGTT window, activate on that pipe. On
/// success the session state is stored for disconnect /
/// retrain handling. The claim is re-entrant per DDI, so a
/// repeat connect event for a live session reuses its pipe.
fn dp_connect(ddi: crate::intel_gpu_ddi::Ddi) -> Option<crate::intel_gpu_dp::DpConnection> {
    with_display_info(|gpu| {
        if !gpu.chip.generation.external_display_supported() {
            return None;
        }
        let window = DpBarWindow(&gpu.gtt_mmadr);
        let probe = crate::intel_gpu_dp::probe_sink(&window, ddi).ok()?;
        let pipe =
            crate::intel_gpu_multipipe::claim_pipe_for(crate::intel_gpu_multipipe::PipeOwner {
                ddi,
                used_for: crate::intel_gpu_multipipe::PipeUse::ExternalSst,
            })?;
        // When this claim lights a second (or third) pipe, the
        // session modesets with its DBUF share and the pipes
        // already live are reprogrammed to theirs afterwards.
        let share = {
            let active = crate::intel_gpu_multipipe::active_pipes();
            if active.len() >= 2 {
                crate::intel_gpu_multipipe::share_for(&active, pipe)
            } else {
                None
            }
        };
        let width = probe.mode.h_active as u32;
        let height = probe.mode.v_active as u32;
        let stride_bytes = padded_stride_bytes(width);
        let size_bytes = scanout_size_bytes(width, height);
        let alloc = match crate::intel_gpu_gtt::alloc_contiguous_scanout_at(
            &gpu.gtt_mmadr,
            crate::intel_gpu_multipipe::scanout_gtt_offset(pipe),
            size_bytes,
        ) {
            Ok(alloc) => alloc,
            Err(_) => {
                crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                return None;
            }
        };
        let alloc = ScanoutAllocation {
            gtt_offset: alloc.gtt_offset,
            phys_base: alloc.phys_base(),
            order: alloc.order,
            size_bytes: alloc.size_bytes,
        };
        let fb = crate::intel_gpu_modeset::Framebuffer {
            phys_addr: alloc.gtt_offset as u64,
            stride_bytes,
            format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
        };
        let conn = match crate::intel_gpu_dp::activate_on_pipe(&window, &probe, &fb, pipe, share) {
            Ok(conn) => conn,
            Err(_) => {
                crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                return None;
            }
        };
        crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
        *DP_SESSION.lock() = Some(DpSessionState {
            conn: conn.clone(),
            fb,
            alloc,
        });
        Some(conn)
    })
    .flatten()
}

/// HDMI twin of [`dp_connect`]: DDC probe over GMBUS,
/// scanout allocation, HDMI activate (SCDC where the rate
/// demands it, WRPLL modeset, AVI DIP, ELD publication).
/// The HPD handler tries this only after the DP probe did
/// not answer — an HDMI sink never answers AUX.
fn hdmi_connect(ddi: crate::intel_gpu_ddi::Ddi) -> Option<crate::intel_gpu_hdmi::HdmiConnection> {
    with_display_info(|gpu| {
        if !gpu.chip.generation.external_display_supported() {
            return None;
        }
        let window = DpBarWindow(&gpu.gtt_mmadr);
        let probe = crate::intel_gpu_hdmi::probe_sink(&window, ddi).ok()?;
        let width = probe.mode.h_active as u32;
        let height = probe.mode.v_active as u32;
        let stride_bytes = padded_stride_bytes(width);
        let size_bytes = scanout_size_bytes(width, height);
        let alloc =
            crate::intel_gpu_gtt::alloc_contiguous_scanout(&gpu.gtt_mmadr, size_bytes).ok()?;
        let alloc = ScanoutAllocation {
            gtt_offset: alloc.gtt_offset,
            phys_base: alloc.phys_base(),
            order: alloc.order,
            size_bytes: alloc.size_bytes,
        };
        let fb = crate::intel_gpu_modeset::Framebuffer {
            phys_addr: alloc.gtt_offset as u64,
            stride_bytes,
            format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
        };
        let conn = crate::intel_gpu_hdmi::activate(&window, &probe, &fb).ok()?;
        *HDMI_SESSION.lock() = Some(HdmiSessionState {
            conn: conn.clone(),
            fb,
            alloc,
        });
        Some(conn)
    })
    .flatten()
}

// ── DP MST session (lane Q11, #1017) ─────────────────────────
//
// The MST counterpart of the SST glue above: `intel_gpu_mst`
// owns the session logic (topology, payload allocation,
// per-stream modesets); this glue owns the controller-bound
// parts — pipe claims, per-pipe scanout windows and
// allocations, DBUF reprogramming as the active set changes,
// and fb-console publication of the first stream (the
// publication slot is single; see the SST section's note).

/// Per-stream glue state: the retained allocation and
/// framebuffer for one live MST stream.
struct MstStreamGlue {
    sink: crate::dp_mst_mgr::Sink,
    mode: crate::intel_gpu_modeset::Mode,
    fb: crate::intel_gpu_modeset::Framebuffer,
    alloc: ScanoutAllocation,
}

/// Live MST session state for one DDI.
struct MstSessionState {
    link: crate::intel_gpu_mst::MstLink,
    streams: alloc::vec::Vec<MstStreamGlue>,
}

static MST_SESSION: IrqSafeSpinLock<Option<MstSessionState>> = IrqSafeSpinLock::new(None);

/// The DDI the live MST session sits on, if any.
fn mst_session_ddi() -> Option<crate::intel_gpu_ddi::Ddi> {
    MST_SESSION.lock().as_ref().map(|s| s.link.ddi())
}

/// Try to bring an MST session up on `ddi`. Returns `false`
/// (leaving no trace — MST is stopped again, no pipe claimed)
/// when the device doesn't advertise MST, the topology probe
/// fails, or no sink stream could be lit; the caller then
/// falls back to the SST connect.
fn mst_connect(ddi: crate::intel_gpu_ddi::Ddi) -> bool {
    use crate::dp_aux::AuxChannel as _;
    let state = with_display_info(|gpu| {
        if !gpu.chip.generation.external_display_supported() {
            return None;
        }
        let window = DpBarWindow(&gpu.gtt_mmadr);
        // Capability gate: DP 1.2+ and MSTM_CAP set. Anything
        // less is an SST device and not this path's business.
        let mut aux = crate::intel_gpu_aux::IntelAux::new(&window, ddi);
        let caps = crate::dp_link_training::read_caps(&mut aux).ok()?;
        let mut raw_caps = [0u8; 16];
        aux.dpcd_read(0, &mut raw_caps).ok()?;
        let mut mstm_cap = [0u8; 1];
        aux.dpcd_read(crate::dp_mst_mgr::MSTM_CAP, &mut mstm_cap)
            .ok()?;
        if caps.dpcd_rev < 0x12 || mstm_cap[0] & 1 == 0 {
            return None;
        }

        let mut maux = crate::intel_gpu_mst::IntelMstAux::new(&window, ddi);
        let mut link = crate::intel_gpu_mst::MstLink::new(ddi);
        if link.connect(&mut maux, caps, &raw_caps).is_err() {
            return None;
        }
        if link.probe_topology(&mut maux).is_err() {
            link.disconnect(&mut maux);
            return None;
        }
        let sinks = link.topology().map(|t| t.sinks()).unwrap_or_default();
        let mut streams: alloc::vec::Vec<MstStreamGlue> = alloc::vec::Vec::new();
        for sink in sinks {
            let Some(pipe) =
                crate::intel_gpu_multipipe::claim_any_pipe(crate::intel_gpu_multipipe::PipeOwner {
                    ddi,
                    used_for: crate::intel_gpu_multipipe::PipeUse::ExternalMst,
                })
            else {
                break;
            };
            let mode = match link.sink_mode(&mut maux, sink) {
                Ok(mode) => mode,
                Err(_) => {
                    crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                    continue;
                }
            };
            let width = mode.h_active as u32;
            let height = mode.v_active as u32;
            let stride_bytes = padded_stride_bytes(width);
            let size_bytes = scanout_size_bytes(width, height);
            let alloc = match crate::intel_gpu_gtt::alloc_contiguous_scanout_at(
                &gpu.gtt_mmadr,
                crate::intel_gpu_multipipe::scanout_gtt_offset(pipe),
                size_bytes,
            ) {
                Ok(alloc) => ScanoutAllocation {
                    gtt_offset: alloc.gtt_offset,
                    phys_base: alloc.phys_base(),
                    order: alloc.order,
                    size_bytes: alloc.size_bytes,
                },
                Err(_) => {
                    crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                    continue;
                }
            };
            let fb = crate::intel_gpu_modeset::Framebuffer {
                phys_addr: alloc.gtt_offset as u64,
                stride_bytes,
                format: crate::intel_gpu_modeset::PixelFormat::Xrgb8888,
            };
            let share = {
                let active = crate::intel_gpu_multipipe::active_pipes();
                if active.len() >= 2 {
                    crate::intel_gpu_multipipe::share_for(&active, pipe)
                } else {
                    None
                }
            };
            match link.add_stream(&window, &mut maux, sink, mode, pipe, &fb, share) {
                Ok(_) => {
                    streams.push(MstStreamGlue {
                        sink,
                        mode,
                        fb,
                        alloc,
                    });
                    crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
                }
                Err(_) => {
                    crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
                }
            }
        }
        if streams.is_empty() {
            // Nothing lit: not an MST session. Stop MST so the
            // branch presents as an SST device to the fallback.
            link.disconnect(&mut maux);
            return None;
        }
        Some(MstSessionState { link, streams })
    })
    .flatten();
    match state {
        Some(state) => {
            *MST_SESSION.lock() = Some(state);
            true
        }
        None => false,
    }
}

/// Tear the MST session on `ddi` down: streams in reverse
/// bring-up order (payloads deallocated, pipes torn down),
/// MST off, pipes released.
fn mst_disconnect(ddi: crate::intel_gpu_ddi::Ddi) {
    let state = {
        let mut session = MST_SESSION.lock();
        match session.as_ref() {
            Some(s) if s.link.ddi() == ddi => session.take(),
            _ => None,
        }
    };
    let Some(mut state) = state else { return };
    let pipes: alloc::vec::Vec<crate::intel_gpu_pipes::Pipe> =
        state.link.streams().iter().map(|s| s.pipe).collect();
    let sinks: alloc::vec::Vec<crate::dp_mst_mgr::Sink> =
        state.streams.iter().map(|g| g.sink).collect();
    with_display_info(|gpu| {
        let window = DpBarWindow(&gpu.gtt_mmadr);
        let mut maux = crate::intel_gpu_mst::IntelMstAux::new(&window, ddi);
        for sink in sinks.iter().rev() {
            let _ = state.link.remove_stream(&window, &mut maux, *sink);
        }
        state.link.disconnect(&mut maux);
        for pipe in pipes {
            crate::intel_gpu_multipipe::release_pipe(pipe, ddi);
        }
        crate::intel_gpu_multipipe::reprogram_active_dbuf_shares(&window);
    });
}

/// Drain branch notifications for the MST session on `ddi`
/// (the RetrainRequired route). Events are logged; acting on
/// a vanished sink beyond the log is the session layer's next
/// step, not this glue's.
fn mst_poll_notifications(ddi: crate::intel_gpu_ddi::Ddi) {
    use core::fmt::Write as _;
    let state = {
        let mut session = MST_SESSION.lock();
        match session.as_ref() {
            Some(s) if s.link.ddi() == ddi => session.take(),
            _ => None,
        }
    };
    let Some(mut state) = state else { return };
    with_display_info(|gpu| {
        let window = DpBarWindow(&gpu.gtt_mmadr);
        let mut maux = crate::intel_gpu_mst::IntelMstAux::new(&window, ddi);
        if let Ok(events) = state.link.poll_notifications(&mut maux) {
            for event in events {
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: MST event on DDI {:?}: {:?}",
                    ddi,
                    event,
                );
            }
        }
    });
    // Restore the session (teardown races are the HPD
    // sequencer's problem, exactly as in the SST retrain path:
    // the store-back is unconditional).
    let mut session = MST_SESSION.lock();
    if session.is_none() {
        *session = Some(state);
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Cross-crate native fixture hook: exercises the real CPU-view gate,
    /// without constructing a PCI display or pretending any GEM DMA retired.
    pub async fn kms_pause_console_for_test() {
        super::kms_pause_console().await;
    }

    /// The calling fixture owns its synthetic CPU scanout and proves it
    /// never armed GEM fetch before reopening the real writer gate.
    pub fn kms_resume_console_for_test() {
        super::kms_resume_console();
    }

    fn smoke_kms_console_pause_drains_views_and_survives_cancel() -> TestResult {
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        if kms_console_paused() {
            return TestResult::Skip("a production KMS session owns the console");
        }
        let installed = narf_graphics::console::GLOBAL_FB_CONSOLE.lock().is_some();
        // SAFETY: only a scalar is captured; no mapping access escapes.
        let old = unsafe { crate::scanout_access::snapshot(|| 7) };
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut pause = core::pin::pin!(kms_pause_console());
            assert_eq!(pause.as_mut().poll(&mut cx), Poll::Pending);
            assert!(kms_console_paused());
            assert!(narf_graphics::console::GLOBAL_FB_CONSOLE.lock().is_none());
        }
        // Cancellation does not reopen writers while a previous CPU view
        // can still write. A later waiter must observe that same old view.
        assert!(kms_console_paused());
        let mut pause = core::pin::pin!(kms_pause_console());
        assert_eq!(pause.as_mut().poll(&mut cx), Poll::Pending);
        // A post-pause view sees the gate under the same epoch lock and
        // must not delay retirement of the prior display's writers.
        // SAFETY: only the admission boolean is captured, with no raw mapping.
        let current = unsafe { crate::scanout_access::snapshot(kms_console_paused) };
        assert!(*current);
        drop(old);
        assert_eq!(pause.as_mut().poll(&mut cx), Poll::Ready(()));
        drop(current);
        kms_resume_console();
        assert!(!kms_console_paused());
        assert_eq!(
            narf_graphics::console::GLOBAL_FB_CONSOLE.lock().is_some(),
            installed
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_kms",
        smoke_kms_console_pause_drains_views_and_survives_cancel
    );

    /// Census: the canonical table must contain exactly the DID
    /// set transcribed from spec §5 / pci.ids v2.2, every row
    /// must classify back to its own (generation, asic), and no
    /// DID or registration name may repeat. If a SKU is added or
    /// dropped, this fixture and spec §5 must move together.
    fn smoke_device_table_census() -> TestResult {
        // (did, asic) — transcribed from drivers/gpu/specification/intel_gpu.md §5.
        const EXPECTED: &[(u16, &str)] = &[
            (0x9A40, "tigerlake"),
            (0x9A49, "tigerlake"),
            (0x9A60, "tigerlake"),
            (0x9A68, "tigerlake"),
            (0x9A70, "tigerlake"),
            (0x9A78, "tigerlake"),
            (0x4626, "alderlake-p"),
            (0x4628, "alderlake-p"),
            (0x462A, "alderlake-p"),
            (0x4636, "alderlake-p"),
            (0x4638, "alderlake-p"),
            (0x463A, "alderlake-p"),
            (0x46A0, "alderlake-p"),
            (0x46A1, "alderlake-p"),
            (0x46A3, "alderlake-p"),
            (0x46A6, "alderlake-p"),
            (0x46A8, "alderlake-p"),
            (0x46AA, "alderlake-p"),
            (0x46B6, "alderlake-p"),
            (0x46B8, "alderlake-p"),
            (0x46BA, "alderlake-p"),
            (0x46B0, "raptorlake-p"),
            (0x46B1, "raptorlake-p"),
            (0x46B3, "raptorlake-p"),
            (0x46C0, "alderlake-m"),
            (0x46C1, "alderlake-m"),
            (0x46C3, "alderlake-m"),
            (0x46D0, "alderlake-n"),
            (0x46D1, "alderlake-n"),
            (0x46D2, "alderlake-n"),
            (0x46D3, "alderlake-n"),
            (0x46D4, "alderlake-n"),
            (0x4680, "alderlake-s"),
            (0x4682, "alderlake-s"),
            (0x4688, "alderlake-s"),
            (0x468A, "alderlake-s"),
            (0x468B, "alderlake-s"),
            (0x4690, "alderlake-s"),
            (0x4692, "alderlake-s"),
            (0x4693, "alderlake-s"),
            (0xA780, "raptorlake-s"),
            (0xA781, "raptorlake-s"),
            (0xA782, "raptorlake-s"),
            (0xA783, "raptorlake-s"),
            (0xA788, "raptorlake-s"),
            (0xA789, "raptorlake-s"),
            (0xA78A, "raptorlake-s"),
            (0xA78B, "raptorlake-s"),
            (0xA720, "raptorlake-p"),
            (0xA721, "raptorlake-p"),
            (0xA7A0, "raptorlake-p"),
            (0xA7A1, "raptorlake-p"),
            (0xA7A8, "raptorlake-p"),
            (0xA7A9, "raptorlake-p"),
            (0xA7AA, "raptorlake-p"),
            (0xA7AB, "raptorlake-p"),
            (0xA7AC, "raptorlake-p"),
            (0xA7AD, "raptorlake-p"),
            (0x7D40, "meteorlake"),
            (0x7D45, "meteorlake"),
            (0x7D55, "meteorlake"),
            (0x7D60, "meteorlake"),
            (0x7DD5, "meteorlake"),
            (0x7D41, "arrowlake"),
            (0x7D51, "arrowlake"),
            (0x7D67, "arrowlake"),
            (0x7DD1, "arrowlake"),
            (0xB640, "arrowlake"),
            (0xB080, "pantherlake"),
            (0xB081, "pantherlake"),
            (0xB082, "pantherlake"),
            (0xB083, "pantherlake"),
            (0xB084, "pantherlake"),
            (0xB085, "pantherlake"),
            (0xB086, "pantherlake"),
            (0xB087, "pantherlake"),
            (0xB08F, "pantherlake"),
            (0xB090, "pantherlake"),
            (0xB0A0, "pantherlake"),
            (0xB0B0, "pantherlake"),
        ];
        if DEVICE_TABLE.len() != EXPECTED.len() {
            return TestResult::Fail("device table size drifted from the spec §5 census");
        }
        for (did, asic) in EXPECTED {
            let info = match chip_info_for_pci_id(INTEL_VENDOR, *did) {
                Some(i) => i,
                None => return TestResult::Fail("census DID does not classify"),
            };
            if info.asic != *asic || info.did != *did {
                return TestResult::Fail("census DID classifies to the wrong ASIC");
            }
        }
        // No duplicate DIDs or registration names.
        for (i, a) in DEVICE_TABLE.iter().enumerate() {
            for b in DEVICE_TABLE.iter().skip(i + 1) {
                if a.did == b.did {
                    return TestResult::Fail("duplicate DID in device table");
                }
                if a.name == b.name {
                    return TestResult::Fail("duplicate registration name in device table");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_device_table_census);

    fn smoke_unknown_ids_do_not_classify() -> TestResult {
        if chip_info_for_pci_id(INTEL_VENDOR, 0x1234).is_some() {
            return TestResult::Fail("unknown Intel DID must not classify");
        }
        if chip_info_for_pci_id(0x10DE, TGL_U_GT2_9A49).is_some() {
            return TestResult::Fail("non-Intel vendor must not classify");
        }
        // The phantom IDs from the earlier coverage pass do not
        // exist in pci.ids and must stay absent.
        for did in [0x9A59u16, 0x9AC9, 0x9AC0, 0x46B2, 0x46A2] {
            if chip_info_for_pci_id(INTEL_VENDOR, did).is_some() {
                return TestResult::Fail("phantom DID present in table");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_unknown_ids_do_not_classify);

    /// Regression for the 1366-wide panel panic: the unpadded
    /// stride (5464) is not 64-byte aligned and the plane builder
    /// rejects it; the padded stride (5504) must be accepted and
    /// the allocation sized by it.
    fn smoke_probe_stride_1366_regression() -> TestResult {
        if padded_stride_bytes(1366) != 5504 {
            return TestResult::Fail("1366-wide stride must pad to 5504");
        }
        if padded_stride_bytes(1920) != 7680 {
            return TestResult::Fail("1920-wide stride is already aligned");
        }
        if scanout_size_bytes(1366, 768) != 5504 * 768 {
            return TestResult::Fail("scanout size must use the padded stride");
        }
        match crate::intel_gpu_pipes::build_primary_plane(
            1366,
            768,
            1366 * 4,
            0x10_0000,
            crate::intel_gpu_pipes::PixelFormat::Argb8888,
        ) {
            Err(crate::intel_gpu_pipes::PipeError::BadStride) => {}
            _ => return TestResult::Fail("unpadded 1366 stride must be rejected"),
        }
        if crate::intel_gpu_pipes::build_primary_plane(
            1366,
            768,
            padded_stride_bytes(1366),
            0x10_0000,
            crate::intel_gpu_pipes::PixelFormat::Argb8888,
        )
        .is_err()
        {
            return TestResult::Fail("padded 1366 stride must build a plane");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_probe_stride_1366_regression);

    fn smoke_display_generation_gates() -> TestResult {
        if !Generation::TigerLake.display_supported() || !Generation::AlderLake.display_supported()
        {
            return TestResult::Fail("Gen12 generations must allow display programming");
        }
        // #1016: Meteor Lake's Xe-LPG sequence is implemented, so
        // the gate opens for MTL. Panther Lake (Xe3-LPD, a
        // different display IP) must stay gated off.
        if !Generation::MeteorLake.display_supported() {
            return TestResult::Fail("MTL must allow display programming (#1016)");
        }
        if Generation::PantherLake.display_supported() {
            return TestResult::Fail("PTL must skip display programming (Xe3-LPD not modelled)");
        }
        if !Generation::TigerLake.external_display_supported()
            || !Generation::AlderLake.external_display_supported()
            || Generation::MeteorLake.external_display_supported()
            || Generation::PantherLake.external_display_supported()
        {
            return TestResult::Fail("external display sequences must remain Gen12-only");
        }
        // Backlight stays Gen12-only until the composition lane
        // (PR #1037) lands the MTL PWM path.
        if !Generation::TigerLake.backlight_supported()
            || !Generation::AlderLake.backlight_supported()
            || Generation::MeteorLake.backlight_supported()
            || Generation::PantherLake.backlight_supported()
        {
            return TestResult::Fail("backlight gate must be Gen12-only pending #1037");
        }
        // Region generations follow the same split.
        if Generation::MeteorLake.region_generation() != Some(RegionGeneration::XeLpg)
            || Generation::PantherLake.region_generation().is_some()
        {
            return TestResult::Fail("region generation map wrong for MTL/PTL");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_display_generation_gates);

    fn smoke_unsupported_external_hpd_never_touches_mmio() -> TestResult {
        struct NoAccess;
        impl crate::intel_gpu_aux::MmioWindow for NoAccess {
            fn read32(&self, _: u64) -> u32 {
                panic!("unsupported HPD generation read MMIO")
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("unsupported HPD generation wrote MMIO")
            }
        }
        for generation in [Generation::MeteorLake, Generation::PantherLake] {
            enable_external_hpd(&NoAccess, generation);
            if poll_external_hpd(&NoAccess, generation).is_some() {
                return TestResult::Fail("unsupported HPD generation must report no events");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu",
        smoke_unsupported_external_hpd_never_touches_mmio
    );

    /// Arrow Lake classification (#1023): the product name says
    /// "new generation", the silicon says Xe-LPG. Linux binds
    /// every ARL ID to the Meteor Lake device info / display
    /// descriptor (i915 `INTEL_ARL_IDS(..., &mtl_info)`, xe and
    /// display `&mtl_desc`), so the rows classify
    /// `Generation::MeteorLake` under `asic: "arrowlake"` — the
    /// Raptor-Lake-under-AlderLake pattern. This fixture pins
    /// the whole set (including B640, which the pci.ids v2.2
    /// extract lane 1 worked from did not carry, though the
    /// i915 ID macros and current pci.ids do) so a future
    /// "helpful" reclassification to a distinct generation — or
    /// worse, to Gen12, which would arm the Gen12 modeset
    /// against Xe-LPG silicon — fails here first.
    fn smoke_arrowlake_classification() -> TestResult {
        const ARL_DIDS: &[u16] = &[ARL_7D41, ARL_7D51, ARL_7D67, ARL_7DD1, ARL_B640];
        for did in ARL_DIDS {
            let info = match chip_info_for_pci_id(INTEL_VENDOR, *did) {
                Some(i) => i,
                None => return TestResult::Fail("Arrow Lake DID does not classify"),
            };
            if info.asic != "arrowlake" {
                return TestResult::Fail("Arrow Lake DID classifies to the wrong ASIC");
            }
            if info.generation != Generation::MeteorLake {
                return TestResult::Fail("Arrow Lake must classify as MeteorLake (Xe-LPG)");
            }
            // Disposition follows the Meteor Lake rows exactly:
            // since #1016 that is the Xe-LPG display sequence and
            // region map — never the Gen12 one.
            if !info.generation.display_supported() {
                return TestResult::Fail("Arrow Lake must arm the Xe-LPG display (#1016)");
            }
            if info.generation.region_generation() != Some(RegionGeneration::XeLpg) {
                return TestResult::Fail("Arrow Lake must claim the Xe-LPG region map");
            }
        }
        // No bleed across the shared 0x7Dxx space: the sibling
        // Meteor Lake IDs keep their own ASIC name.
        for did in [MTL_7D40, MTL_7D45, MTL_7D55, MTL_7D60, MTL_7DD5] {
            match chip_info_for_pci_id(INTEL_VENDOR, did) {
                Some(i) if i.asic == "meteorlake" && i.generation == Generation::MeteorLake => {}
                _ => return TestResult::Fail("Meteor Lake DID misclassified next to Arrow Lake"),
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu", smoke_arrowlake_classification);
}
