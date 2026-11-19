//! Exact initial Bz-b0 core103 profile; independent of Sc and API89.
//! Linux iwl-drv.c, cfg/bz.c, pcie/drv.c and fw/api contracts.
use super::transport::IwlMmio;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    revision: u32,
    radio: u32,
    pub prefix: &'static str,
    pub integrated: bool,
}
impl Profile {
    pub fn read(did: u16, io: &mut impl IwlMmio) -> Result<Self, &'static str> {
        let revision = io.read(super::regs::CSR_HW_REV);
        let radio = io.read(0x9c);
        if revision == u32::MAX || radio == u32::MAX {
            return Err("Bz native MAC/RF identity unavailable");
        }
        let mac = (revision >> 4) & 0xfff;
        let step = revision & 15;
        if !matches!(mac, 0x46 | 0x4b) || step != 1 || radio & (1 << 28) != 0 {
            return Err("initial Bz station requires actual B0 non-CDB MAC");
        }
        let prefix = match ((radio >> 12) & 0xfff, (radio >> 8) & 15) {
            (0x112, 2) => "iwlwifi-bz-b0-fm-c0",
            (0x113, 1) => "iwlwifi-bz-b0-wh-b0",
            _ => return Err("initial Bz station RF/step unavailable"),
        };
        let integrated = match did {
            0x272b => false,
            0x7740 | 0x4d40 | 0xa840 => true,
            _ => return Err("Bz PCI/MAC/RF combination unsupported"),
        };
        Ok(Self {
            revision,
            radio,
            prefix,
            integrated,
        })
    }
    pub fn check(&self, did: u16, io: &mut impl IwlMmio) -> Result<(), &'static str> {
        if Self::read(did, io)? != *self {
            return Err("Bz native identity changed after source selection");
        }
        Ok(())
    }
    pub fn validate(&self, parsed: &super::ParsedUcode<'_>) -> Result<(), &'static str> {
        if super::gen2_profile::firmware_api(parsed) != 103
            || !parsed.api.has_capability(110)
            || parsed.api.has_capability(40)
        {
            return Err("Bz exact core103 non-CDB station firmware unavailable");
        }
        for (group, command, expected) in [
            (3, 8, 3),
            (3, 9, 8),
            (3, 10, 2),
            (1, 8, 6),
            (5, 8, 3),
            (1, 0x98, 1),
            (1, 0x9b, 6),
            (2, 1, 2),
            (1, 0x77, 7),
            (1, 0xc, 5),
            (1, 0xd, 18),
            (1, 0x9f, 10),
            (5, 0x17, 3),
            (5, 0x18, 1),
            (5, 0xf, 6),
            (1, 0x1c, 11),
            (5, 0xd, 2),
        ] {
            if parsed.api.command_version(group, command) != Some(expected) {
                return Err("Bz exact station producer command profile differs");
            }
        }
        for (group, command, expected) in [
            (0, 1, 7),
            (0xc, 2, 4),
            (0, 0xc1, 8),
            (1, 0xc8, 8),
            (1, 0x1c, 9),
            (5, 0xf7, 4),
            (0, 0xc5, 7),
        ] {
            if parsed.api.versions(group, command).map(|v| v.1) != Some(expected) {
                return Err("Bz exact station notification profile differs");
            }
        }
        // MLD sends its fixed sync0 record independently of a version
        // table. RSS uses the source fixed payload1; both actual c103
        // inventories omit the corresponding command records.
        if !matches!(parsed.api.command_version(5, 2), None | Some(0 | 99))
            || !matches!(parsed.api.command_version(1, 0xb3), None | Some(1 | 99))
        {
            return Err("Bz incompatible fixed native control profile");
        }
        Ok(())
    }
}
