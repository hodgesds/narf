//! API89 MVM/MLD-style station facts, separate from descriptor geometry.
//! Used only after exact native PCI/MAC/RF and executable admission.
//! Linux cfg/ax210.c, pcie/drv.c, iwl-drv.c and mvm/{mld-mac,link,mld-sta}.c.
use super::transport::IwlMmio;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    revision: u32,
    radio: u32,
    pub prefix: &'static str,
    pub integrated: bool,
    pub low_latency: bool,
    pub imr_debug: bool,
    pub xtal_latency_us: u32,
    pub ltr_delay_us: u32,
    pub cdb: bool,
}
impl Profile {
    pub fn read(did: u16, io: &mut impl IwlMmio) -> Result<Self, &'static str> {
        Self::select(did, io.read(super::regs::CSR_HW_REV), io.read(0x9c))
    }
    fn select(did: u16, revision: u32, radio: u32) -> Result<Self, &'static str> {
        if revision == u32::MAX || radio == u32::MAX {
            return Err("API89 native MAC/RF identity unavailable");
        }
        let mac = (revision >> 4) & 0xfff;
        let cdb = radio & (1 << 28) != 0;
        // Linux always uses A0 firmware for Ty/So, independent of MAC step.
        // GF's firmware step is likewise fixed to A. CDB is the separate
        // actual RF-ID bit, not a guessed GF4 type or installed-file order.
        if (radio >> 12) & 0xfff != 0x10d {
            return Err("API89 initial station requires actual GF RF profile");
        }
        let (prefix, integrated, low_latency, imr_debug, xtal, ltr) = match did {
            0x2725 if mac == 0x42 && !cdb => ("iwlwifi-ty-a0-gf-a0", false, false, false, 500, 0),
            0x51f0 | 0x51f1 | 0x54f0 | 0x7a70 | 0x7af0 | 0x7f70 if matches!(mac, 0x37 | 0x43) => {
                let prefix = if cdb {
                    "iwlwifi-so-a0-gf4-a0"
                } else {
                    "iwlwifi-so-a0-gf-a0"
                };
                let imr = matches!(did, 0x51f1 | 0x7a70);
                let low_latency = matches!(did, 0x51f0 | 0x51f1 | 0x54f0 | 0x7a70);
                (
                    prefix,
                    true,
                    low_latency,
                    imr,
                    if low_latency { 12000 } else { 500 },
                    if low_latency { 2500 } else { 200 },
                )
            }
            0x2729 | 0x7e40 if mac == 0x44 && matches!(revision & 15, 0 | 1) => {
                let prefix = match (revision & 15, cdb) {
                    (0, false) => "iwlwifi-ma-a0-gf-a0",
                    (0, true) => "iwlwifi-ma-a0-gf4-a0",
                    (1, false) => "iwlwifi-ma-b0-gf-a0",
                    (1, true) => "iwlwifi-ma-b0-gf4-a0",
                    _ => unreachable!(),
                };
                (prefix, true, false, false, 0, 0)
            }
            _ => return Err("API89 PCI/MAC/RF combination unsupported"),
        };
        Ok(Self {
            revision,
            radio,
            prefix,
            integrated,
            low_latency,
            imr_debug,
            xtal_latency_us: xtal,
            ltr_delay_us: ltr,
            cdb,
        })
    }
    pub fn check(&self, did: u16, io: &mut impl IwlMmio) -> Result<(), &'static str> {
        if Self::read(did, io)? != *self {
            return Err("API89 native identity changed after source selection");
        }
        Ok(())
    }
    pub fn validate(&self, parsed: &super::ParsedUcode<'_>) -> Result<Abi, &'static str> {
        if super::gen2_profile::firmware_api(parsed) != 89 || !parsed.api.has_capability(110) {
            return Err("API89 exact MVM/MLD station firmware unavailable");
        }
        let api = &parsed.api;
        if api.has_capability(40) != self.cdb {
            return Err("API89 CDB firmware differs from native RF identity");
        }
        for (group, cmd, expected) in [
            (3, 8, 2),
            (3, 9, 2),
            (1, 8, 4),
            (5, 8, 2),
            (1, 0x98, 1),
            (1, 0x9b, 6),
            (2, 1, 2),
            (1, 0x77, 7),
            (1, 0xc, 5),
            (1, 0xd, 17),
            (1, 0x9f, 8),
            (5, 0x17, 3),
            (5, 0x18, 1),
            (5, 0xf, 4),
            (1, 0x1c, 10),
        ] {
            if api.command_version(group, cmd) != Some(expected) {
                return Err("API89 exact station producer command profile differs");
            }
        }
        for (group, cmd, expected) in [
            (0, 1, 6),
            (0xc, 2, 4),
            (0, 0xc1, 5),
            (1, 0xc8, 6),
            (1, 0x1c, 7),
            (5, 0xf7, 3),
            (0, 0xc5, 5),
        ] {
            if api.versions(group, cmd).map(|v| v.1) != Some(expected) {
                return Err("API89 exact station notification profile differs");
            }
        }
        // The actual images omit STA_CONFIG. Linux's sender uses the v1
        // extent unless reported version >1, including a missing record.
        let station = match api.command_version(3, 0xa) {
            None | Some(0 | 1 | 99) => 1,
            Some(2) => 2,
            _ => return Err("API89 incompatible station command version"),
        };
        // Fixed MVM sync-v1 and the Linux capability-backed RSS default
        // remain unversioned. Absence is not an unsupported command.
        for (group, cmd) in [(5, 2), (1, 0xb3)] {
            if !matches!(api.command_version(group, cmd), None | Some(1 | 99)) {
                return Err("API89 incompatible fixed native control profile");
            }
        }
        Ok(Abi { station })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Abi {
    pub station: u8,
}
impl Abi {
    pub fn station_extent(self) -> usize {
        if self.station == 1 {
            96
        } else {
            104
        }
    }
}
