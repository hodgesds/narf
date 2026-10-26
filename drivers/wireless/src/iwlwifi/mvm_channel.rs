// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained API77 PHY ownership for the inactive MLD link. This preparation
//! never activates a link, allocates a packet queue or authorizes transmission.
use super::super::{boot_context::put32, firmware_api::FirmwareApi, station_api::Nvm};
use super::{Owner, Phase};
use alloc::vec::Vec;
use narf_wireless::reg::RegulatoryDomain;

pub(super) struct ChannelContext {
    version: u8,
    rlc_version: u8,
    ultra_channels: bool,
    pub(super) current: Option<u8>,
}
impl ChannelContext {
    pub(super) fn new(api: &FirmwareApi<'_>) -> Self {
        // Linux fw/img.c defaults absent/UNKNOWN PHY_CONTEXT to v1. The
        // actual CC/Qu API77 command tables omit this command entirely.
        let version = match api.versions(1, 8).map(|v| v.0) {
            None | Some(99) => 1,
            Some(version) => version,
        };
        Self {
            version,
            rlc_version: api
                .versions(5, 8)
                .map(|v| v.0)
                .filter(|v| *v != 99)
                .unwrap_or(0),
            ultra_channels: api.has_capability(48),
            current: None,
        }
    }
    fn rlc_command(&self, nvm: &Nvm) -> Option<[u8; 32]> {
        if self.rlc_version != 2 {
            // Linux mvm/phy-ctxt.c sends only v2. Earlier versions keep RX
            // chains in PHY; v3+ explicitly offloads RLC to firmware.
            return None;
        }
        let mut body = [0; 32];
        put32(&mut body, 4, receive_chains(nvm));
        Some(body)
    }
    fn command(&self, action: u32, channel: u8, nvm: &Nvm) -> Result<Vec<u8>, &'static str> {
        if !matches!(self.version, 1 | 2)
            || !matches!(action, 1 | 3)
            || !nvm.channels.contains(&channel)
            || !matches!(nvm.rx_chains, 1..=3)
            || !matches!(nvm.tx_chains, 1..=3)
        {
            return Err("unsupported MVM inactive PHY profile/channel");
        }
        // Linux mvm/phy-ctxt.c uses the old 16-byte prefix and a
        // capability-sized channel field followed immediately by its tail.
        // The Gen3 32-byte PHY_CONTEXT command has a different prefix.
        let tail = if self.ultra_channels { 24 } else { 20 };
        let mut body = alloc::vec![0; tail + 16];
        put32(&mut body, 4, action);
        if self.ultra_channels {
            put32(&mut body, 16, u32::from(channel));
            body[20] = u8::from(channel <= 14);
        } else {
            body[16] = u8::from(channel <= 14);
            body[17] = channel;
        }
        put32(&mut body, tail, nvm.tx_chains);
        put32(&mut body, tail + 4, receive_chains(nvm));
        Ok(body)
    }
}

fn receive_chains(nvm: &Nvm) -> u32 {
    let count = nvm.rx_chains.count_ones();
    (nvm.rx_chains << 1) | (count << 10) | (count << 12)
}

fn inactive_binding(local: [u8; 6], bound: bool) -> [u8; 208] {
    let mut body = [0; 208];
    put32(&mut body, 0, 2); // MODIFY link0 of MAC0
    put32(&mut body, 12, if bound { 0 } else { u32::MAX });
    body[16..22].copy_from_slice(&local);
    // modify_mask=0 is the Linux inactive PHY-binding operation. Setting
    // MODIFY_ACTIVE here would combine binding with a different operation.
    body
}

impl Owner {
    /// Prepare a 20MHz receive channel context attached to the existing
    /// inactive link0. This is an ownership prerequisite, not RX/TX service.
    /// A prepared channel must be released before another scan/preparation.
    pub async fn prepare_inactive_channel(&mut self, channel: u8) -> Result<(), &'static str> {
        let domain = narf_wireless::reg::db::get_domain()
            .ok_or("missing authenticated MVM regulatory policy")?;
        self.prepare_channel_in_domain(channel, &domain).await
    }
    pub(super) async fn prepare_channel_in_domain(
        &mut self,
        channel: u8,
        domain: &RegulatoryDomain,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::Configured || self.hardware.is_failed() {
            return Err("MVM owner is not ready for inactive PHY");
        }
        if !super::scan::passive_permitted(domain, channel) {
            return Err("MVM inactive PHY channel prohibited by receive policy");
        }
        let local = self.mac.ok_or("missing MVM PHY identity")?;
        let phy = self.channel.command(
            1,
            channel,
            self.nvm.as_ref().ok_or("missing retained MVM NVM")?,
        )?;
        let rlc = self
            .channel
            .rlc_command(self.nvm.as_ref().ok_or("missing retained MVM NVM")?);
        // Reuse the scan entry's full profile preflight, without borrowing a
        // scan slot or publishing SCAN_REQ. Both operations need this same
        // real idle MAC/link, optional DQA, and current MCC receipt.
        self.validate_scan_profile()?;
        self.phase = Phase::PreparingChannel;
        let result = self
            .prepare_channel_inner(channel, local, &phy, rlc.as_ref())
            .await;
        match result {
            Ok(()) => {
                self.channel.current = Some(channel);
                self.phase = Phase::ChannelPrepared;
                Ok(())
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }
    async fn prepare_channel_inner(
        &mut self,
        channel: u8,
        local: [u8; 6],
        phy: &[u8],
        rlc: Option<&[u8; 32]>,
    ) -> Result<(), &'static str> {
        self.prepare_scan().await?;
        if let Some(permissions) = &self.scan.permissions {
            let index = super::super::station_api::channel_index(channel)
                .ok_or("invalid MVM PHY band/channel")?;
            if permissions.get(index).is_none_or(|flags| flags & 1 == 0) {
                return Err("MVM inactive PHY absent from current MCC");
            }
        }
        self.hardware.command(1, 8, phy).await?;
        if let Some(rlc) = rlc {
            self.hardware.command(5, 8, rlc).await?;
        }
        self.hardware
            .command(3, 9, &inactive_binding(local, true))
            .await?;
        Ok(())
    }
    /// Retire the binding before removing the context. Only both exact ACKs
    /// reopen scan/channel admission; failure or cancellation stays closed.
    pub async fn release_inactive_channel(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::ChannelPrepared || self.hardware.is_failed() {
            return Err("MVM owner has no prepared inactive PHY");
        }
        let channel = self
            .channel
            .current
            .ok_or("missing retained MVM PHY channel")?;
        let local = self.mac.ok_or("missing MVM PHY identity")?;
        let remove = self.channel.command(
            3,
            channel,
            self.nvm.as_ref().ok_or("missing retained MVM NVM")?,
        )?;
        self.phase = Phase::ReleasingChannel;
        let result = self.release_channel_inner(local, &remove).await;
        match result {
            Ok(()) => {
                self.channel.current = None;
                self.phase = Phase::Configured;
                Ok(())
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }
    async fn release_channel_inner(
        &mut self,
        local: [u8; 6],
        remove: &[u8],
    ) -> Result<(), &'static str> {
        self.hardware
            .command(3, 9, &inactive_binding(local, false))
            .await?;
        self.hardware.command(1, 8, remove).await?;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_channel_tests.rs"]
mod tests;
