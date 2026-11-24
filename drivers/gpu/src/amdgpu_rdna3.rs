//! RDNA3 (GC 11.0.x) chip identity: which die is bound, and the per-die IP
//! versions Linux amdgpu discovers for it.
//!
//! Linux binds every RDNA3 board through the generic
//! `{ PCI_DEVICE(0x1002, PCI_ANY_ID), .class = PCI_CLASS_DISPLAY_* }`
//! entries in `amdgpu_drv.c` (`CHIP_IP_DISCOVERY`) and decides everything
//! after that from the discovery blob: `soc21.c` switches on the GC version,
//! `psp_v13_0.c` and `smu_v13_0.c` on MP0/MP1, DC on the DCI version. This
//! module is that switch. [`Rdna3Chip::of`] keys on discovered GC (and the
//! AMD vendor plus the `Navi3` family the probe assigns) — never on the PCI
//! device id, which only names the board.
//!
//! | GC     | die    | MP0/MP1 | SDMA  | DCN   | VCN   | GFX target |
//! |--------|--------|---------|-------|-------|-------|------------|
//! | 11.0.0 | Navi31 | 13.0.0  | 6.0.0 | 3.2.0 | 4.0.0 | gfx1100    |
//! | 11.0.3 | Navi32 | 13.0.10 | 6.0.3 | 3.2.0 | 4.0.0 | gfx1101    |
//! | 11.0.2 | Navi33 | 13.0.7  | 6.0.2 | 3.2.1 | 4.0.4 | gfx1102    |
//!
//! The die↔GC pairing is the one the firmware sets pin down, and it is NOT
//! the order the early (pre-launch, July 2022) patch tables guessed: those
//! had Navi32 at GC 11.0.2 and Navi33 at 11.0.3. Two independent post-launch
//! sources say the opposite, and they agree with each other:
//!
//! * The linux-firmware sets arrive as one group per die. Ubuntu LP#2034103
//!   ("Missing firmware for AMD GPU GC 11.0.3") is filed for **Navi32**
//!   hardware and lists the GC 11.0.3 set: `gc_11_0_3` + `psp_13_0_10` +
//!   `sdma_6_0_3` + `smu_13_0_10` + `vcn_4_0_0`. The GC 11.0.2 set
//!   (`gc_11_0_2` + `psp_13_0_7` + `sdma_6_0_2` + `smu_13_0_7`) is the
//!   other discrete set, which leaves Navi33 on it by elimination.
//! * The Gentoo AMDGPU firmware table lists per chipset: NAVI31
//!   `gc_11_0_0`/`psp_13_0_0`/`smu_13_0_0`/`dcn_3_2_0_dmcub`/`sdma_6_0_0`/
//!   `vcn_4_0_0`; NAVI32 `gc_11_0_3`/`psp_13_0_10`/`smu_13_0_10`/
//!   `dcn_3_2_0_dmcub`/`sdma_6_0_3`/`vcn_4_0_0`; NAVI33 `gc_11_0_2`/
//!   `psp_13_0_7`/`smu_13_0_7`/`dcn_3_2_1_dmcub`/`sdma_6_0_2`/`vcn_4_0_4`.
//! * Cross-check: Mesa's drm-shim `navi33` entry (device 0x7480) reports
//!   `external_rev = 0x10`, which is `soc21_common_early_init`'s GC 11.0.2
//!   assignment (`rev_id + 0x10`); GC 11.0.3 assigns `rev_id + 0x20` and
//!   GC 11.0.0 assigns `rev_id + 0x1`.
//!
//! No extracted Linux file names the dies — the ref tree (Linux 7.4-rc2)
//! contains no `navi31`/`navi32`/`navi33` string at all — so the pairing
//! rests on the firmware sets above, not on a kernel switch. If a later lane
//! finds a kernel source that names a die, this table is where it lands.
//!
//! Version groups the ref tree does confirm directly:
//! * GC firmware groups `gc_11_0_0`/`gc_11_0_1`/`gc_11_0_2`/`gc_11_0_3`
//!   (`gfx_v11_0.c` `MODULE_FIRMWARE`, `mes_v11_0.c`); GC 11.0.1 is the
//!   Phoenix APU, not a discrete die, and is refused here by the family
//!   guard in [`Rdna3Chip::of`].
//! * MP0/MP1 13.0.0/13.0.7/13.0.10 share one driver: `psp_v13_0.c`
//!   (`IP_VERSION(13, 0, 0|7|10)` → `psp_v13_0_ip_block`, with a 13.0.10
//!   fatal-error quirk) and `smu_v13_0.c` (the same three in the
//!   `smu_v13_0_gfx_off_control` switch and the MP1 13.0.7/13.0.0/13.0.10
//!   group). `smu_13_0_0.bin` and `smu_13_0_7.bin` are named in
//!   `smu_v13_0.c` `MODULE_FIRMWARE`.
//! * VCN 4.0.0/4.0.2/4.0.4 all take the `vcn_v4_0` block
//!   (`amdgpu_discovery.c` VCN switch); 4.0.3 takes the separate
//!   `vcn_v4_0_3` block and belongs to no RDNA3 discrete die. That is why
//!   the #2453 Navi3 → `V4_0_2` map holds for all three dies.
//! * DCN 3.2.0 and 3.2.1 both exist (`amdgpu_discovery.c` DCI switch;
//!   `dcn_3_2_0_dmcub.bin` / `dcn_3_2_1_dmcub.bin` in `amdgpu_dm_dmub.h`);
//!   `dcn32_resource.c` and `dcn321_resource.c` both cap
//!   `num_timing_generator = 4`.
//!
//! Navi33's VCN 4.0.4 comes from the Gentoo firmware table alone (its row
//! also lists Raphael blobs, so the row is visibly a merge of two entries);
//! lane 10 (VCN/JPEG owner) re-checks it against `vcn_v4_0.c` before
//! relying on it.
use crate::{
    amdgpu::{AmdGpu, Family, AMD_VENDOR},
    amdgpu_discovery::{self as ip, IpBlock},
};
use core::sync::atomic::{AtomicU8, Ordering};

/// The three RDNA3 discrete dies Linux supports (`soc21_common_early_init`'s
/// GC cases, minus the 11.0.1 Phoenix APU case and the 11.0.4 Dragon Range
/// case, which are not `Family::Navi3`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rdna3Chip {
    /// GC 11.0.0: RX 7900 XTX/XT/GRE, Radeon Pro W7900/W7800.
    Navi31,
    /// GC 11.0.3: RX 7800 XT / 7700 XT, Radeon Pro W7700/V710.
    Navi32,
    /// GC 11.0.2: RX 7600/7600 XT, Radeon Pro W7500.
    Navi33,
}

/// Every GC version `gfx_v11_0`, `gmc_v11_0`, `mes_v11_0` and `soc21`
/// handle with one case, restricted to the discrete dies. GC 11.0.1
/// (Phoenix) and 11.0.4 (Dragon Range) are APUs, not `Family::Navi3`.
pub const GC_VERSIONS: &[(u8, u8, u8)] = &[(11, 0, 0), (11, 0, 2), (11, 0, 3)];
/// MP0 / MP1 versions `psp_v13_0` and `smu_v13_0` share
/// (`amdgpu_discovery.c` adds the same IP block for all three).
pub const MP_VERSIONS: &[(u8, u8, u8)] = &[(13, 0, 0), (13, 0, 7), (13, 0, 10)];

/// One die's discovered IP versions, as the firmware sets group them (see
/// the module docs). MP0 (PSP) and MP1 (SMU) share the 13.0.x revision:
/// Linux selects both from the same `psp_v13_0` / `smu_v13_0` driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpVersions {
    pub gc: (u8, u8, u8),
    pub mp: (u8, u8, u8),
    pub sdma: (u8, u8, u8),
    pub dcn: (u8, u8, u8),
    pub vcn: (u8, u8, u8),
}

/// A board whose PCI id `pci.ids` names. The probe does not need this list —
/// an unlisted RDNA3 id is admitted by the class match plus discovery — but
/// listed ids also get an exact bus match, log a marketing name, and let a
/// test pin the identity. This is the only RDNA3 PCI id list in the driver.
/// Names are `pci.ids` v2026.11.22 verbatim; lane 0 registers these ids in
/// the probe table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownDevice {
    pub did: u16,
    pub chip: Rdna3Chip,
    /// `pci.ids`' device name.
    pub name: &'static str,
}
pub const KNOWN_DEVICES: &[KnownDevice] = &[
    KnownDevice {
        did: 0x7446,
        chip: Rdna3Chip::Navi31,
        name: "Navi 31 USB",
    },
    KnownDevice {
        did: 0x7448,
        chip: Rdna3Chip::Navi31,
        name: "Navi 31 [Radeon Pro W7900]",
    },
    KnownDevice {
        did: 0x7449,
        chip: Rdna3Chip::Navi31,
        name: "Navi 31 [Radeon Pro W7800 48GB]",
    },
    KnownDevice {
        did: 0x744A,
        chip: Rdna3Chip::Navi31,
        name: "Navi 31 [Radeon Pro W7900 Dual Slot]",
    },
    KnownDevice {
        did: 0x744B,
        chip: Rdna3Chip::Navi31,
        name: "Navi 31 [Radeon Pro W7900D]",
    },
    KnownDevice {
        did: 0x744C,
        chip: Rdna3Chip::Navi31,
        name: "Navi 31 [Radeon RX 7900 XT/7900 XTX/7900 GRE/7900M]",
    },
    KnownDevice {
        did: 0x745E,
        chip: Rdna3Chip::Navi31,
        name: "Navi 31 [Radeon Pro W7800]",
    },
    KnownDevice {
        did: 0x7460,
        chip: Rdna3Chip::Navi32,
        name: "Navi 32 GL-XL [AMD Radeon PRO V710]",
    },
    KnownDevice {
        did: 0x7461,
        chip: Rdna3Chip::Navi32,
        name: "Navi 32 [AMD Radeon PRO V710]",
    },
    KnownDevice {
        did: 0x7470,
        chip: Rdna3Chip::Navi32,
        name: "Navi 32 [Radeon PRO W7700]",
    },
    KnownDevice {
        did: 0x747E,
        chip: Rdna3Chip::Navi32,
        name: "Navi 32 [Radeon RX 7700 XT / 7800 XT]",
    },
    KnownDevice {
        did: 0x73F0,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon RX 7600M XT]",
    },
    KnownDevice {
        did: 0x7480,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon RX 7600/7600 XT/7600M XT/7600S/7700S / PRO W7600]",
    },
    KnownDevice {
        did: 0x7481,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon Graphics]",
    },
    KnownDevice {
        did: 0x7483,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon RX 7600M/7600M XT]",
    },
    KnownDevice {
        did: 0x7487,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon Graphics]",
    },
    KnownDevice {
        did: 0x7489,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon Pro W7500]",
    },
    KnownDevice {
        did: 0x748B,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon Graphics]",
    },
    KnownDevice {
        did: 0x7499,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon RX 7400/7300/Pro W7400]",
    },
    KnownDevice {
        did: 0x749F,
        chip: Rdna3Chip::Navi33,
        name: "Navi 33 [Radeon RX 7500]",
    },
];
pub fn known_device(did: u16) -> Option<&'static KnownDevice> {
    KNOWN_DEVICES.iter().find(|d| d.did == did)
}

impl Rdna3Chip {
    pub const ALL: [Self; 3] = [Self::Navi31, Self::Navi32, Self::Navi33];

    pub const fn from_gc(version: (u8, u8, u8)) -> Option<Self> {
        match version {
            (11, 0, 0) => Some(Self::Navi31),
            (11, 0, 3) => Some(Self::Navi32),
            (11, 0, 2) => Some(Self::Navi33),
            _ => None,
        }
    }
    /// The die discovery describes: exactly one GC instance 0, of a GC
    /// 11.0.x version Linux supports. Duplicate or absent GC fails closed.
    pub fn from_ip_blocks(blocks: &[IpBlock]) -> Option<Self> {
        let mut gc = blocks
            .iter()
            .filter(|b| b.hw_id == ip::HW_ID_GC && b.instance == 0);
        let first = gc.next()?;
        if gc.next().is_some() {
            return None;
        }
        Self::from_gc((first.major, first.minor, first.revision))
    }
    /// The RDNA3 die this probed AMD GPU is, or `None` for every other part.
    /// A device id the PCI table assigns to another family is refused even
    /// with RDNA3 discovery: the identity would be self-contradictory. A
    /// device id the table does not know is admitted by discovery alone, as
    /// for RDNA4.
    pub fn of(gpu: &AmdGpu) -> Option<Self> {
        if gpu.chip.vid != AMD_VENDOR
            || gpu.chip.family != Family::Navi3
            || crate::amdgpu::family_for_pci_id(gpu.chip.vid, gpu.chip.did)
                .is_some_and(|f| f != Family::Navi3)
        {
            return None;
        }
        Self::from_ip_blocks(&gpu.ip_blocks)
    }
    pub const fn gc_version(self) -> (u8, u8, u8) {
        match self {
            Self::Navi31 => (11, 0, 0),
            Self::Navi32 => (11, 0, 3),
            Self::Navi33 => (11, 0, 2),
        }
    }
    /// Linux `amdgpu_asic_name`-style short name, also the boot log's.
    pub const fn asic(self) -> &'static str {
        match self {
            Self::Navi31 => "navi31",
            Self::Navi32 => "navi32",
            Self::Navi33 => "navi33",
        }
    }
    /// This die's discovered IP versions (module docs for the grounding).
    pub const fn ip_versions(self) -> IpVersions {
        match self {
            Self::Navi31 => IpVersions {
                gc: (11, 0, 0),
                mp: (13, 0, 0),
                sdma: (6, 0, 0),
                dcn: (3, 2, 0),
                vcn: (4, 0, 0),
            },
            Self::Navi32 => IpVersions {
                gc: (11, 0, 3),
                mp: (13, 0, 10),
                sdma: (6, 0, 3),
                dcn: (3, 2, 0),
                vcn: (4, 0, 0),
            },
            Self::Navi33 => IpVersions {
                gc: (11, 0, 2),
                mp: (13, 0, 7),
                sdma: (6, 0, 2),
                dcn: (3, 2, 1),
                // Gentoo-table value only; lane 10 re-checks it against
                // `vcn_v4_0.c` before relying on it.
                vcn: (4, 0, 4),
            },
        }
    }
    /// `soc21_common_early_init`: `external_rev_id = rev_id + 0x1` for GC
    /// 11.0.0, `+ 0x20` for GC 11.0.3 and `+ 0x10` for GC 11.0.2.
    /// `AMDGPU_INFO_DEV_INFO` reports it and Mesa picks the GFX target
    /// from it.
    pub const fn external_rev(self, rev_id: u8) -> u32 {
        rev_id as u32
            + match self {
                Self::Navi31 => 0x01,
                Self::Navi32 => 0x20,
                Self::Navi33 => 0x10,
            }
    }
    /// `kfd_device.c` `gfx_target_version` (gfx1100 / gfx1101 / gfx1102),
    /// on the same encoding as RDNA4's gfx1200/gfx1201.
    pub const fn gfx_target_version(self) -> u32 {
        match self {
            Self::Navi31 => 110_000,
            Self::Navi32 => 110_001,
            Self::Navi33 => 110_002,
        }
    }
}

/// One discovered IP block version: (major, minor, revision).
pub type IpVersion = (u8, u8, u8);

/// Discovered MP0 (PSP) / MP1 (SMU) versions: (MP0, MP1), instance 0 of
/// each. Absent blocks stay `None`.
pub type MpVersions = (Option<IpVersion>, Option<IpVersion>);

/// Discovered MP0 (PSP) / MP1 (SMU) versions, instance 0 of each, for
/// diagnostics. Absent blocks stay `None`: the PSP/SMU lane (tracker lane 2)
/// is what makes them load-bearing, not this identity module.
pub fn mp_versions(blocks: &[IpBlock]) -> MpVersions {
    let one = |hw: u16| {
        blocks
            .iter()
            .find(|b| b.hw_id == hw && b.instance == 0)
            .map(|b| (b.major, b.minor, b.revision))
    };
    (one(ip::HW_ID_MP0), one(ip::HW_ID_MP1))
}

/// The bound RDNA3 die, if any. Published by the Navi31 platform's
/// `prepare` so later stages and diagnostics can read the identity without
/// re-running discovery; `NONE` is the unbound state.
const NONE: u8 = 0;
static BOUND: AtomicU8 = AtomicU8::new(NONE);
pub(crate) fn publish(chip: Option<Rdna3Chip>) {
    let code = match chip {
        None => NONE,
        Some(Rdna3Chip::Navi31) => 1,
        Some(Rdna3Chip::Navi32) => 2,
        Some(Rdna3Chip::Navi33) => 3,
    };
    BOUND.store(code, Ordering::Release);
}
/// The bound RDNA3 die, if any.
pub fn bound() -> Option<Rdna3Chip> {
    match BOUND.load(Ordering::Acquire) {
        1 => Some(Rdna3Chip::Navi31),
        2 => Some(Rdna3Chip::Navi32),
        3 => Some(Rdna3Chip::Navi33),
        _ => None,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_rdna3_tests.rs"]
pub(crate) mod tests;
