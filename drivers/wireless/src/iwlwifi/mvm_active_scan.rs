// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Qualified API77 UMAC probe emission from the unassociated owner. The
//! firmware's scan engine is fenced by global device power and per-chain
//! SAR before SCAN_REQ_UMAC; a link/peer power command is insufficient here.
use super::{
    power::{self, Emission, ScanFence},
    Owner, Phase,
};
use crate::firmware_asset::Asset;
use alloc::vec::Vec;
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};
use narf_wireless::{reg::RegulatoryDomain, BssInfo};

async fn checked<T>(
    fence: &ScanFence,
    policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    future: impl Future<Output = Result<T, &'static str>>,
) -> Result<T, &'static str> {
    let mut future = pin!(future);
    poll_fn(|cx| {
        match policy().and_then(|domain| fence.invoke(&domain, || Ok(future.as_mut().poll(cx)))) {
            Ok(poll) => poll,
            Err(error) => Poll::Ready(Err(error)),
        }
    })
    .await
}

impl Owner {
    fn active_scan_mask(
        &self,
        channels: &[u8],
        domain: &RegulatoryDomain,
    ) -> Result<Vec<bool>, &'static str> {
        let (permissions, ibss) = match &self.scan.permissions {
            Some(current) => (current, false),
            None => (
                self.power
                    .nvm_permissions
                    .as_ref()
                    .ok_or("MVM active scan lacks retained NVM permissions")?,
                true,
            ),
        };
        // Actual 22000 NVM flags: VALID|ACTIVE|20MHZ and, without LAR,
        // IBSS (Linux maps absence of that legacy flag to NO_IR).
        let required = 1 | (1 << 3) | (1 << 8) | if ibss { 1 << 1 } else { 0 };
        Ok(channels
            .iter()
            .map(|&channel| {
                // The common 2.4GHz template includes OFDM rates; channel14
                // remains passive rather than inventing a CCK-only profile.
                channel != 14
                    && super::super::station_api::channel_index(channel)
                        .and_then(|index| permissions.get(index))
                        .is_some_and(|flags| flags & required == required && flags & (1 << 4) == 0)
                    && super::super::connection::host_channel_power(domain, channel, true).is_some()
            })
            .collect())
    }

    pub(in crate::iwlwifi) async fn active_scan_using(
        &mut self,
        channels: &[u8],
        ssids: &[Vec<u8>],
        source: Asset,
        binding: [u8; 32],
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<Vec<BssInfo>, &'static str> {
        if self.phase != Phase::Configured || self.hardware.is_failed() || !self.scan_power_api() {
            return Err("MVM owner is not ready for qualified active scan");
        }
        let nvm = self.nvm.as_ref().ok_or("MVM active scan lacks NVM")?;
        let domain = policy()?;
        if channels.is_empty()
            || channels.len() > 51
            || channels.iter().enumerate().any(|(i, channel)| {
                !nvm.channels.contains(channel)
                    || channels[..i].contains(channel)
                    || !super::scan::passive_permitted(&domain, *channel)
            })
        {
            return Err("invalid MVM active-scan channels");
        }
        let version = self.validate_scan_profile()?;
        let local = self.mac.ok_or("MVM active scan lacks MAC")?;
        let prepared = power::parse_for(source, binding, local, channels[0], Emission::ActiveScan)?;
        let initial = self.active_scan_mask(channels, &domain)?;
        let fence = prepared.scan_fence(channels, &initial, &domain)?;
        // Validate caller SSIDs before any native preparation command.
        super::super::scan_api::active(version, 0, channels, &initial, local, ssids)?;
        self.phase = Phase::Scanning;
        let result = async {
            self.hardware.poll()?;
            self.hardware.notifications.clear();
            checked(&fence, &mut policy, self.prepare_scan()).await?;
            let domain = policy()?;
            let active = self.active_scan_mask(channels, &domain)?;
            let fence = prepared.scan_fence(channels, &active, &domain)?;
            let request =
                super::super::scan_api::active(version, 0, channels, &active, local, ssids)?;
            let chains = prepared.scan_chain_command();
            let reply =
                checked(&fence, &mut policy, self.hardware.command(1, 0x9f, &chains)).await?;
            if !reply.payload.is_empty() {
                return Err("MVM active-scan SAR receipt is malformed");
            }
            let device = fence.device_command();
            let reply =
                checked(&fence, &mut policy, self.hardware.command(1, 0x9f, &device)).await?;
            if !reply.payload.is_empty() {
                return Err("MVM active-scan device power receipt is malformed");
            }
            // Retire stale slot0 events received while preparing power.
            self.hardware.poll()?;
            self.hardware.notifications.clear();
            checked(&fence, &mut policy, self.hardware.command(1, 0xd, &request)).await?;
            let results = checked(&fence, &mut policy, self.scan_results_inner(channels)).await?;
            fence.invoke(&policy()?, || Ok(()))?;
            Ok(results)
        }
        .await;
        match result {
            Ok((beacons, results)) => {
                self.beacons = beacons;
                self.phase = Phase::Configured;
                Ok(results)
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                // A firmware scan is autonomous after SCAN_REQ. Retire the
                // radio/transport through the existing DMA-stop + SW-reset
                // path rather than letting a failed host waiter leave it
                // emitting. An ambiguous stop retains every allocation.
                let _ = self.suspend_transport().await;
                Err(error)
            }
        }
    }
}
