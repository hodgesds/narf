//! Exact API89 protocol admission; RX completion geometry is independent.
use super::super::gen3_profile::Profile;
use super::*;
impl Hardware {
    /// Called only after actual ALIVE and required PNVM initialization.
    /// The post-ready RAM fixture exercises the identical parsed-source seam.
    pub(super) fn retain_eht_boot(
        &mut self,
        parsed: &ParsedUcode<'_>,
        alive: &[u8],
    ) -> Result<(), &'static str> {
        self.eht_source = if self.uses_mld_station_protocol()
            && super::super::sc_he::native_supported(self)
            && super::super::sc_he::rates_version(self) == Some(3)
        {
            super::super::sc_eht::Source::boot(
                self.device.id.device,
                self.device.id.subsystem_id,
                self.mmio.read(super::super::regs::CSR_HW_REV),
                self.mmio.read(0x9c),
                parsed,
                alive,
            )?
        } else {
            None
        };
        Ok(())
    }
    pub(in crate::iwlwifi) fn eht_supported(&mut self) -> bool {
        self.eht_source.is_some_and(|source| {
            source.matches(
                self.device.id.device,
                self.device.id.subsystem_id,
                self.mmio.read(super::super::regs::CSR_HW_REV),
                self.mmio.read(0x9c),
            )
        }) && self.uses_mld_station_protocol()
            && super::super::sc_he::rates_version(self) == Some(3)
    }
    pub(in crate::iwlwifi) fn eht_320_supported(&mut self) -> bool {
        self.eht_supported()
            && self
                .eht_source
                .is_some_and(|source| source.bandwidth_limit >= 320 && !source.reduced)
    }
    pub(in crate::iwlwifi) fn prepare_station_profile(
        &mut self,
        parsed: &ParsedUcode<'_>,
    ) -> Result<(), &'static str> {
        if self.prepare_bz_profile(parsed)? {
            return Ok(());
        }
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
    /// The runtime consumer is selected by the retained native profile,
    /// independently of command metadata and RX descriptor geometry.
    pub(in crate::iwlwifi) fn uses_mld_station_protocol(&self) -> bool {
        self.mld_station
    }
    /// MLD directly consumes mac_phy_band; MVM requires the actual
    /// IWL_UCODE_TLV_API_BAND_IN_RX_DATA (59), not a command-version guess.
    pub(in crate::iwlwifi) fn band_in_rx_supported(&self) -> bool {
        self.mld_station || self.band_in_rx
    }
    pub(in crate::iwlwifi) fn scan_fixed_antenna_supported(&self) -> bool {
        self.mld_station || self.scan_fixed_antenna
    }
    pub(in crate::iwlwifi) fn scan_hidden_six_supported(&self) -> bool {
        self.mld_station || self.scan_six_capabilities & 1 != 0
    }
    pub(in crate::iwlwifi) fn scan_tpc_supported(&self) -> bool {
        self.mld_station || self.scan_six_capabilities & 2 != 0
    }
    pub(in crate::iwlwifi) fn install_six_tx_profile(
        &mut self,
        profile: alloc::sync::Arc<super::super::six_ghz_station::Profile>,
    ) -> Result<(), &'static str> {
        profile.check_pending(self)?;
        self.six_tx_profile = Some(profile);
        Ok(())
    }
    pub(in crate::iwlwifi) fn check_six_tx_publication(&mut self) -> Result<(), &'static str> {
        let result = self
            .mld_link
            .as_ref()
            .map_or(Ok(()), |mld| mld.check_pending(self))
            .and_then(|()| {
                self.six_tx_profile
                    .as_ref()
                    .map_or(Ok(()), |profile| profile.check_pending(self))
            });
        if result
            .as_ref()
            .is_err_and(|&reason| reason != super::super::six_ghz_station::UPDATE_REQUIRED)
        {
            self.fail();
        }
        result
    }
    pub(in crate::iwlwifi) async fn service_six_power(&mut self) -> Result<(), &'static str> {
        if let Some(profile) = self.six_tx_profile.clone() {
            profile.apply_pending(self).await?;
        }
        Ok(())
    }
    pub(in crate::iwlwifi) fn install_mld_link(
        &mut self,
        link: alloc::sync::Arc<super::super::sc_mlo::Binding>,
    ) -> Result<(), &'static str> {
        link.check_pending(self)?;
        self.mld_link = Some(link);
        Ok(())
    }
    pub(in crate::iwlwifi) async fn station_peer(
        &mut self,
        peer: &[u8; 104],
    ) -> Result<(), &'static str> {
        let length = self.api89.map_or(104, |(_, abi)| abi.station_extent());
        self.command(3, 0xa, &peer[..length]).await?;
        Ok(())
    }
    pub(in crate::iwlwifi) fn install_ap_owner(
        &mut self,
        owner: alloc::sync::Arc<super::super::ap_owner::Owner>,
    ) -> Result<(), &'static str> {
        owner.check()?;
        // A fresh AP/GO START cannot inherit a predecessor's native NoA.
        // Caller still owes actual new receive-prefix and role receipts.
        self.p2p_go = None;
        self.ap_owner = Some(owner);
        Ok(())
    }
    pub(in crate::iwlwifi) async fn ap_tlc(
        &mut self,
        body: &[u8; 44],
        station: u8,
    ) -> Result<(), &'static str> {
        let response = if self.is_mvm89() || self.ap_gen2.is_some() {
            let wire = super::super::gen3_wire::ap_tlc_v4(body, station)?;
            self.command(5, 0xf, &wire).await?
        } else {
            self.command(5, 0xf, body).await?
        };
        if !response.payload.is_empty() {
            return Err("AP native TLC receipt payload unexpected");
        }
        Ok(())
    }
    pub(in crate::iwlwifi) async fn ap_peer(
        &mut self,
        peer: &[u8; 104],
    ) -> Result<(), &'static str> {
        if let Some(adapter) = &self.ap_gen2 {
            let (id, body) = adapter.peer(peer)?;
            let receipt = self.command(1, 0x18, &body).await?;
            return self.ap_gen2.as_mut().unwrap().added(id, &receipt.payload);
        }
        let length = self.api89.map_or(104, |(_, abi)| abi.station_extent());
        if !self
            .command(3, 0xa, &peer[..length])
            .await?
            .payload
            .is_empty()
        {
            return Err("AP native peer receipt payload unexpected");
        }
        Ok(())
    }
    pub(in crate::iwlwifi) async fn ap_phy(
        &mut self,
        canonical: &[u8; 32],
    ) -> Result<(), &'static str> {
        if let Some(adapter) = &self.ap_gen2 {
            let (body, rlc) = adapter.phy(canonical)?;
            if !self.command(1, 8, &body).await?.payload.is_empty() {
                return Err("API77 AP PHY native receipt unexpected");
            }
            if let Some(rlc) = rlc {
                if !self
                    .command_with_header_version(5, 8, &rlc, 2)
                    .await?
                    .payload
                    .is_empty()
                {
                    return Err("API77 AP RLC native receipt unexpected");
                }
            }
            return Ok(());
        }
        let mut body = *canonical;
        if let Some((profile, _)) = self.api89 {
            let high_band = body[12] != 1;
            boot_context::put32(&mut body, 16, u32::from(profile.cdb && high_band));
            body[20..24].fill(0);
        }
        if !self.command(1, 8, &body).await?.payload.is_empty() {
            return Err("AP native PHY receipt payload unexpected");
        }
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
        _channel: u8,
    ) -> Result<(), &'static str> {
        let mut body = *canonical;
        if let Some((profile, _)) = self.api89 {
            let high_band = body[12] != 1;
            boot_context::put32(&mut body, 16, u32::from(profile.cdb && high_band));
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
