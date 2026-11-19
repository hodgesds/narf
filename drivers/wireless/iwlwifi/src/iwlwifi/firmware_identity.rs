//! Sc firmware names bind actual CSR MAC/RF/step, never installed-file order.
//! Linux iwl-csr.h, iwl-config.h and iwl-drv.c::iwl_drv_get_fwname_pre.
use super::{transport::IwlMmio, ChipConfig, MacFamily};
use alloc::{string::String, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Sc {
    revision: u32,
    radio: u32,
}
impl Sc {
    pub(super) fn read(io: &mut impl IwlMmio) -> Result<Self, &'static str> {
        let identity = Self {
            revision: io.read(super::regs::CSR_HW_REV),
            radio: io.read(0x9c), // CSR_HW_RF_ID.
        };
        identity.rf()?;
        Ok(identity)
    }
    fn rf(self) -> Result<&'static str, &'static str> {
        if self.revision == u32::MAX || self.radio == u32::MAX {
            return Err("Sc firmware identity unavailable");
        }
        // 8000+ CSR MAC stepping is the complete low nibble (trans.c).
        // Only the configured Sc A0 pairings have an initial native profile.
        if (self.revision >> 4) & 0xfff != 0x48 || self.revision & 15 != 0 {
            return Err("unsupported Sc firmware MAC/step");
        }
        let kind = (self.radio >> 12) & 0xfff;
        let step = (self.radio >> 8) & 15;
        let cdb = self.radio & (1 << 28) != 0;
        match (kind, step, cdb) {
            (0x113, 1, false) => Ok("wh-b0"),
            (0x112, 1, false) => Ok("fm-b0"),
            (0x112, 2, false) => Ok("fm-c0"),
            // Linux fixes the GF firmware step to A irrespective of RF step.
            (0x10d, _, false) => Ok("gf-a0"),
            _ => Err("unsupported Sc firmware RF/step/CDB"),
        }
    }
    pub(super) fn ladder(self, chip: &ChipConfig) -> Result<Vec<String>, &'static str> {
        if chip.mac != MacFamily::ScA0 {
            return Err("Sc firmware identity on another MAC profile");
        }
        let rf = self.rf()?;
        let mut names = Vec::new();
        for api in (chip.api_min..=chip.api_max).rev() {
            names.push(alloc::format!(
                "iwlwifi/iwlwifi-sc-a0-{rf}-{}{api}.ucode",
                chip.api_prefix
            ));
        }
        Ok(names)
    }
    pub(super) fn check(self, io: &mut impl IwlMmio) -> Result<(), &'static str> {
        if Self::read(io)? != self {
            return Err("Sc firmware identity changed after selection");
        }
        Ok(())
    }
}
