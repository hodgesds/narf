//! Exact Bz core103 source admission; the common MLD station owns DMA.
use super::super::bz_profile::Profile;
use super::*;
impl Hardware {
    pub(super) fn prepare_bz_profile(
        &mut self,
        parsed: &ParsedUcode<'_>,
    ) -> Result<bool, &'static str> {
        if !matches!(self.device.id.device, 0x272b | 0x7740 | 0x4d40 | 0xa840) {
            if self.bz.is_some() {
                return Err("Bz restart changed its native PCI profile");
            }
            return Ok(false);
        }
        if self.format != rx_rfh::CompletionFormat::Bz || self.api89.is_some() {
            return Err("Bz source bound to another native protocol owner");
        }
        let assets = self.source_assets()?;
        let pci = self.authority(false);
        let profile = assets
            .invoke(|| pci.invoke(|| Profile::read(self.device.id.device, &mut self.mmio)))?;
        profile.validate(parsed)?;
        if self.bz.is_some_and(|old| old != profile) {
            return Err("Bz restart changed its native identity/profile");
        }
        self.bz = Some(profile);
        self.mld_station = true;
        Ok(true)
    }
    pub(super) fn bz_runtime(
        &self,
        profile: Profile,
    ) -> super::super::station_api::RuntimeConfiguration {
        let mut runtime = super::super::station_api::RuntimeConfiguration {
            coexistence: [1, 0, 0, 0, 17, 0, 0, 0],
            soc: [0; 8],
            power: [0; 4],
        };
        // Linux cfg/bz.c: GL/discrete has no integrated LTR delay; the
        // integrated Bz PCI configs use LTR2500. Both use low-latency XTAL.
        let flags = if profile.integrated { 2 | 8 } else { 1 | 2 };
        boot_context::put32(&mut runtime.soc, 0, flags);
        boot_context::put32(&mut runtime.soc, 4, 12000);
        runtime
    }
}
