//! Exact API89 protocol admission; RX completion geometry is independent.
use super::super::gen3_profile::Profile;
use super::*;
impl Hardware {
    pub(in crate::iwlwifi) fn prepare_station_profile(
        &mut self,
        parsed: &ParsedUcode<'_>,
    ) -> Result<(), &'static str> {
        if super::super::gen2_profile::firmware_api(parsed) != 89 {
            if self.api89.is_some() {
                return Err("API89 restart changed its executable protocol");
            }
            return Ok(());
        }
        let assets = self.source_assets()?;
        let pci = self.authority(false);
        let profile = assets
            .invoke(|| pci.invoke(|| Profile::read(self.device.id.device, &mut self.mmio)))?;
        let abi = profile.validate(parsed)?;
        if self.api89.is_some_and(|old| old != (profile, abi)) {
            return Err("API89 restart changed its native identity/profile");
        }
        if !self.armed {
            let scratch = self
                .resources
                .boot
                .scratch
                .as_ref()
                .ok_or("API89 context scratch absent")?;
            let mut flags = u32::from_le_bytes(scratch.as_slice()[8..12].try_into().unwrap());
            if profile.imr_debug {
                flags |= 1 << 1;
            } else {
                flags &= !(1 << 1);
            }
            write_dma(scratch, 8, &flags.to_le_bytes());
        }
        self.api89 = Some((profile, abi));
        Ok(())
    }
    pub(in crate::iwlwifi) fn is_mvm89(&self) -> bool {
        self.api89.is_some()
    }
    pub(in crate::iwlwifi) async fn station_peer(
        &mut self,
        peer: &[u8; 104],
    ) -> Result<(), &'static str> {
        let length = self.api89.map_or(104, |(_, abi)| abi.station_extent());
        self.command(3, 0xa, &peer[..length]).await?;
        Ok(())
    }
    pub(in crate::iwlwifi) async fn station_tlc(
        &mut self,
        canonical: &[u8; 44],
    ) -> Result<(), &'static str> {
        if self.api89.is_some() {
            let body = super::super::gen3_wire::tlc_v4(canonical)?;
            self.command(5, 0xf, &body).await?;
        } else {
            self.command(5, 0xf, canonical).await?;
        }
        Ok(())
    }
    pub(in crate::iwlwifi) async fn station_phy(
        &mut self,
        canonical: &[u8; 32],
        channel: u8,
    ) -> Result<(), &'static str> {
        let mut body = *canonical;
        if let Some((profile, _)) = self.api89 {
            boot_context::put32(&mut body, 16, u32::from(profile.cdb && channel > 14));
            body[20..24].fill(0); // PHYv4 reserves the old RX-chain field.
        }
        self.command(1, 8, &body).await?;
        Ok(())
    }
    pub(super) fn compressed_ba_supported(&self) -> bool {
        matches!(self.version(0, 0xc5).map(|v| v.1), Some(4 | 6 | 7))
            || self.is_mvm89() && self.version(0, 0xc5).map(|v| v.1) == Some(5)
    }
    pub(in crate::iwlwifi) fn station_link(&self, body: &mut [u8; 208]) {
        if self.api89.is_some() {
            super::super::gen3_wire::he_link_mask(body);
        }
    }
    pub(in crate::iwlwifi) async fn station_receive_chains(
        &mut self,
        rx_chains: u32,
    ) -> Result<(), &'static str> {
        if self.api89.is_some() {
            if rx_chains == 0 || rx_chains & !3 != 0 {
                return Err("API89 invalid native RX chains");
            }
            let count = rx_chains.count_ones();
            let mut body = [0; 32];
            boot_context::put32(
                &mut body,
                4,
                (rx_chains << 1) | (count << 10) | (count << 12),
            );
            let receipt = self.command_with_header_version(5, 8, &body, 2).await?;
            if !receipt.payload.is_empty() {
                return Err("API89 RLC native receipt extent");
            }
        }
        Ok(())
    }
    pub(super) fn api89_runtime(
        &self,
        profile: Profile,
    ) -> super::super::station_api::RuntimeConfiguration {
        let flags = u32::from(!profile.integrated)
            | u32::from(profile.low_latency) << 1
            | match profile.ltr_delay_us {
                200 => 4,
                2500 => 8,
                _ => 0,
            };
        let mut runtime = super::super::station_api::RuntimeConfiguration {
            coexistence: [1, 0, 0, 0, 17, 0, 0, 0],
            soc: [0; 8],
            power: [0; 4],
        };
        boot_context::put32(&mut runtime.soc, 0, flags);
        boot_context::put32(&mut runtime.soc, 4, profile.xtal_latency_us);
        runtime
    }
}
