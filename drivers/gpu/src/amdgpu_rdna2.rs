//! Discrete RX 6000 ASIC identity and firmware inventory.
//!
//! PCI IDs follow Linux amdgpu_drv.c::pciidlist. These include professional
//! and mobile variants of the same ASIC; an ID does not establish board
//! topology, memory size, connector routing, or native-startup compatibility.
//! Firmware names follow Linux MODULE_FIRMWARE declarations in psp_v11_0.c,
//! gfx_v10_0.c, sdma_v5_2.c and the SMU11 power-management backends.
//! This inventory is not a firmware load sequence.

#[path = "amdgpu_rdna2_golden.rs"]
pub mod golden;
#[path = "amdgpu_rdna2_metadata.rs"]
pub mod metadata;
#[path = "amdgpu_rdna2_options.rs"]
pub mod options;

// gc_10_1_0_offset.h; BASE_IDX 0 for every entry.
pub const READ_MMR_GC: &[u32] = &[
    0x0da4, 0x0da2, 0x0da5, 0x0da6, 0x0dae, 0x0daf, 0x0f40, 0x0f3d, 0x0f3e, 0x0f3c, 0x0e28, 0x0e29,
    0x0e27, 0x0e25, 0x0e26, 0x0e24, 0x13de,
];

/// Serialized PowerPlay SKU and board boundaries. Beige Goby's original
/// fbe8115c6ab7 interface remains in shipping firmware alongside the newer ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerTableLayout {
    pub format_revision: u8,
    pub format_id: u16,
    pub smc_bytes: usize,
    pub board_start: usize,
    pub board_end: usize,
}
impl Profile {
    /// gmc_v10_0_sw_init: MALL size for the discrete GC 10.3 revisions.
    pub const fn mall_bytes(&self) -> u64 {
        let mib = match self.gc_version {
            (10, 3, 0) => 128,
            (10, 3, 2) => 96,
            (10, 3, 4) => 32,
            (10, 3, 5) => 16,
            _ => 0,
        };
        mib * 1024 * 1024
    }
    /// Bare-metal `nv_common_early_init` clock-gating flags. Media applies
    /// its own flags; Navi24 has no JPEG clock-gating capability flag.
    pub const fn clock_gating_flags(&self) -> u64 {
        let common = (1 << 0)
            | (1 << 2)
            | (1 << 3)
            | (1 << 8)
            | (1 << 9)
            | (1 << 15)
            | (1 << 16)
            | (1 << 20)
            | (1 << 24)
            | (1 << 27);
        match self.gc_version {
            (10, 3, 0 | 2 | 4) => common | (1 << 30),
            (10, 3, 5) => common,
            _ => 0,
        }
    }
    /// Bare-metal `nv_common_early_init` power-gating capability flags.
    pub const fn power_gating_flags(&self) -> u32 {
        let common = (1 << 13) | (1 << 14) | (1 << 15) | (1 << 16);
        match self.gc_version {
            (10, 3, 0 | 2 | 4) => common | (1 << 17),
            (10, 3, 5) => common,
            _ => 0,
        }
    }
    /// `sienna_cichlid_set_smc_driver_if_version` (diagnostic comparison).
    pub const fn smu_driver_interface(&self) -> u32 {
        match self.psp_version {
            (11, 0, 7) => 0x40,
            (11, 0, 11) => 0xe,
            (11, 0, 12) => 0xf,
            (11, 0, 13) => 0xd,
            _ => 0,
        }
    }
    pub fn power_table_layout(&self, smc_bytes: usize) -> Option<PowerTableLayout> {
        let (format_revision, format_id, board_start, board_end) = match (self.asic, smc_bytes) {
            ("navi21", 1668) => (15, 0x80, 1344, 1636),
            ("navi22", 1668) => (16, 0x81, 1344, 1636),
            ("navi23", 1668) => (18, 0x83, 1344, 1636),
            ("navi24", 1700) => (19, 0x84, 1376, 1668),
            ("navi24", 1888) => (19, 0x84, 1564, 1856),
            _ => return None,
        };
        Some(PowerTableLayout {
            format_revision,
            format_id,
            smc_bytes,
            board_start,
            board_end,
        })
    }
}

/// Compatible navi10_ih backends; discovery remains authoritative per board.
pub const IH_OSSSYS_VERSIONS: &[(u8, u8, u8)] = &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3)];

/// Linux's SMUIO11 ROM callback selection. The newer callback forces ROM
/// clocks on when ROM_MGCG is absent; the older callback performs no I/O.
pub const fn smuio_rom_forced_on(version: (u8, u8, u8)) -> Option<bool> {
    match version {
        (11, 0, 6 | 10 | 11) => Some(true),
        (11, 0, 0 | 2 | 3 | 4 | 7 | 8) => Some(false),
        _ => None,
    }
}

/// One discrete RDNA2 ASIC, independently of its marketed board name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub asic: &'static str,
    pub pci_ids: &'static [u16],
    pub firmware: Firmware,
    /// GC identity used by Linux's legacy firmware decoder.
    pub gc_version: (u8, u8, u8),
    /// MP0 identity used by psp_v11_0 and its shared mailbox layout.
    pub psp_version: (u8, u8, u8),
    pub sdma_version: (u8, u8, u8),
    pub dcn_version: (u8, u8, u8),
    pub vcn_versions: &'static [(u8, u8, u8)],
}

/// Chip-specific containers. Availability does not imply an implemented loader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Firmware {
    pub sos: &'static str,
    pub smc: &'static str,
    pub sdma: &'static str,
    pub ce: &'static str,
    pub pfp: &'static str,
    pub me: &'static str,
    pub mec: &'static str,
    pub mec2: &'static str,
    pub rlc: &'static str,
    pub vcn: &'static str,
    pub dmcub: &'static str,
}

macro_rules! firmware {
    ($prefix:literal) => {
        Firmware {
            sos: concat!("amdgpu/", $prefix, "_sos.bin"),
            smc: concat!("amdgpu/", $prefix, "_smc.bin"),
            sdma: concat!("amdgpu/", $prefix, "_sdma.bin"),
            ce: concat!("amdgpu/", $prefix, "_ce.bin"),
            pfp: concat!("amdgpu/", $prefix, "_pfp.bin"),
            me: concat!("amdgpu/", $prefix, "_me.bin"),
            mec: concat!("amdgpu/", $prefix, "_mec.bin"),
            mec2: concat!("amdgpu/", $prefix, "_mec2.bin"),
            rlc: concat!("amdgpu/", $prefix, "_rlc.bin"),
            vcn: concat!("amdgpu/", $prefix, "_vcn.bin"),
            dmcub: concat!("amdgpu/", $prefix, "_dmcub.bin"),
        }
    };
}

pub const NAVI21: Profile = Profile {
    asic: "navi21",
    pci_ids: &[
        0x73a0, 0x73a1, 0x73a2, 0x73a3, 0x73a5, 0x73a8, 0x73a9, 0x73ab, 0x73ac, 0x73ad, 0x73ae,
        0x73af, 0x73bf,
    ],
    firmware: firmware!("sienna_cichlid"),
    gc_version: (10, 3, 0),
    psp_version: (11, 0, 7),
    sdma_version: (5, 2, 0),
    dcn_version: (3, 0, 0),
    vcn_versions: &[(3, 0, 0), (3, 0, 64), (3, 0, 192)],
};

pub const NAVI22: Profile = Profile {
    asic: "navi22",
    pci_ids: &[
        0x73c0, 0x73c1, 0x73c3, 0x73da, 0x73db, 0x73dc, 0x73dd, 0x73de, 0x73df,
    ],
    firmware: firmware!("navy_flounder"),
    gc_version: (10, 3, 2),
    psp_version: (11, 0, 11),
    sdma_version: (5, 2, 2),
    dcn_version: (3, 0, 0),
    vcn_versions: &[(3, 0, 0), (3, 0, 64), (3, 0, 192)],
};

pub const NAVI23: Profile = Profile {
    asic: "navi23",
    pci_ids: &[
        0x73e0, 0x73e1, 0x73e2, 0x73e3, 0x73e8, 0x73e9, 0x73ea, 0x73eb, 0x73ec, 0x73ed, 0x73ef,
        0x73ff,
    ],
    firmware: firmware!("dimgrey_cavefish"),
    gc_version: (10, 3, 4),
    psp_version: (11, 0, 12),
    sdma_version: (5, 2, 4),
    dcn_version: (3, 0, 2),
    vcn_versions: &[(3, 0, 16)],
};

pub const NAVI24: Profile = Profile {
    asic: "navi24",
    pci_ids: &[0x7420, 0x7421, 0x7422, 0x7423, 0x7424, 0x743f],
    firmware: firmware!("beige_goby"),
    gc_version: (10, 3, 5),
    psp_version: (11, 0, 13),
    sdma_version: (5, 2, 5),
    dcn_version: (3, 0, 3),
    vcn_versions: &[(3, 0, 33)],
};

/// Shared GC10.3 register layout used by gfxhub_v2_1 and GFX10 autoload.
/// Offsets are dwords; each is relative to its discovery base index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PspGcRegisters {
    pub fb_base: u32,
    pub fb_top: u32,
    pub fb_offset: u32,
    pub cp_status: u32,
    pub rlc_status: u32,
    pub gc_base_index: usize,
    pub rlc_base_index: usize,
}

pub(crate) const PSP_GC_REGISTERS: PspGcRegisters = PspGcRegisters {
    fb_base: 0x16fc,
    fb_top: 0x16fd,
    fb_offset: 0x16e7,
    cp_status: 0x0f40,
    rlc_status: 0x4e8d,
    gc_base_index: 0,
    rlc_base_index: 1,
};

/// MMHUB revisions sharing Linux mmhub_v2_0's register and VM programming
/// backend. Selection is by discovered layout, not inferred from a board SKU.
pub const GMC_MMHUB_VERSIONS: &[(u8, u8, u8)] = &[(2, 1, 0), (2, 1, 1), (2, 1, 2)];

pub const PROFILES: &[Profile] = &[NAVI21, NAVI22, NAVI23, NAVI24];

/// Exact vendor/device lookup: never infer an ASIC from a PCI-ID range.
pub fn for_pci_id(vendor: u16, device: u16) -> Option<&'static Profile> {
    if vendor != 0x1002 {
        return None;
    }
    PROFILES.iter().find(|p| p.pci_ids.contains(&device))
}

/// Exact PCI identities with a native RDNA2 startup implementation. Runtime
/// constructors additionally validate discovered IPs and board firmware.
pub fn native_start_available(vendor: u16, device: u16) -> bool {
    for_pci_id(vendor, device).is_some()
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "amdgpu_rdna2_contract_tests.rs"]
mod contract_tests;

#[cfg(test)]
mod tests {
    extern crate std;

    use self::std::{collections::BTreeSet, format};
    use super::*;

    #[test]
    fn exact_ids_are_unique_and_resolve() {
        let mut seen = BTreeSet::new();
        for profile in PROFILES {
            for &did in profile.pci_ids {
                assert!(seen.insert(did), "duplicate {did:04x}");
                assert_eq!(for_pci_id(0x1002, did), Some(profile));
                assert_eq!(for_pci_id(0x10de, did), None);
                assert!(native_start_available(0x1002, did));
            }
        }
        assert_eq!(seen.len(), 40);
    }

    #[test]
    fn holes_apus_and_other_generations_are_not_discrete_rdna2() {
        for did in [
            0, 0xffff, 0x73a4, 0x73c2, 0x73ee, 0x743e, 0x1681, 0x164e, 0x1636, 0x744c, 0x7550,
        ] {
            assert_eq!(for_pci_id(0x1002, did), None);
            assert!(!native_start_available(0x1002, did));
        }
        assert!(!native_start_available(0x10de, 0x73df));
    }

    #[test]
    fn firmware_names_are_asic_specific() {
        for (profile, prefix) in PROFILES.iter().zip([
            "sienna_cichlid",
            "navy_flounder",
            "dimgrey_cavefish",
            "beige_goby",
        ]) {
            let f = profile.firmware;
            for (name, kind) in [
                (f.sos, "sos"),
                (f.smc, "smc"),
                (f.sdma, "sdma"),
                (f.ce, "ce"),
                (f.pfp, "pfp"),
                (f.me, "me"),
                (f.mec, "mec"),
                (f.mec2, "mec2"),
                (f.rlc, "rlc"),
                (f.vcn, "vcn"),
                (f.dmcub, "dmcub"),
            ] {
                assert_eq!(name, format!("amdgpu/{prefix}_{kind}.bin"));
            }
        }
    }
}
