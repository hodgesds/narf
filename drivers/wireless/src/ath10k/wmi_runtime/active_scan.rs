// SPDX-License-Identifier: GPL-2.0-or-later
//! Policy-bounded unassociated probes over the retained mission transport.
use super::*;
use crate::ath10k::{regulatory::Permission, wmi_boot::Capabilities};
use core::{future::Future, pin::pin, task::Poll};
use narf_wireless::reg::RegulatoryDomain;

fn permission(
    caps: &Capabilities,
    domain: &RegulatoryDomain,
    frequency: u16,
) -> Result<Permission, Error> {
    let permission = Permission::from_domain(caps, domain, frequency)?;
    // No trusted indoor-location input exists in this station profile.
    let center = u32::from(frequency);
    if domain.rules.iter().any(|r| {
        r.freq_start_mhz < center + 10
            && center - 10 < r.freq_end_mhz
            && r.flags.contains(narf_wireless::reg::RegFlags::INDOOR_ONLY)
    }) {
        return Err(Error::Unsupported);
    }
    Ok(permission)
}

pub(in crate::ath10k) struct Plan {
    channels: Vec<u16>,
    ssids: Vec<Vec<u8>>,
    extra_ies: Vec<u8>,
    permissions: Vec<Permission>,
    setup: Vec<Vec<u8>>,
    restore: Vec<u8>,
}
impl Plan {
    /// Own and validate all probe content before reserving an ID or touching HIF.
    pub(in crate::ath10k) fn with_extra_ies(mut self, bytes: &[u8]) -> Result<Self, Error> {
        wire::validate_probe_ies(bytes)?;
        self.extra_ies = wire::owned(bytes)?;
        Ok(self)
    }
    fn validate(&self, caps: &Capabilities, domain: &RegulatoryDomain) -> Result<(), Error> {
        for previous in &self.permissions {
            let current = permission(caps, domain, previous.frequency)?;
            if current.factory != previous.factory
                || current.country != previous.country
                || current.half_dbm < previous.half_dbm
            {
                return Err(Error::Unsupported);
            }
        }
        Ok(())
    }
}

// A credit wait can yield inside send_wmi. Recheck policy on every poll,
// including Ready, rather than checking only before constructing the future.
pub(super) async fn checked<O>(
    future: impl Future<Output = Result<O, Error>>,
    validate: &impl Fn() -> Result<(), Error>,
) -> Result<O, Error> {
    let mut future = pin!(future);
    core::future::poll_fn(|cx| {
        if let Err(error) = validate() {
            return Poll::Ready(Err(error));
        }
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(validate().and(result)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn active_frequency_allowed(
        &self,
        domain: &RegulatoryDomain,
        frequency: u16,
    ) -> bool {
        self.channels.contains(&frequency)
            && self
                .htt
                .wmi
                .caps
                .as_ref()
                .is_some_and(|caps| permission(caps, domain, frequency).is_ok())
    }
    /// Preflight performs no transport access and reserves no scan ID.
    pub(in crate::ath10k) fn prepare_active_scan(
        &self,
        channels: &[u16],
        ssids: &[Vec<u8>],
        domain: &RegulatoryDomain,
    ) -> Result<Plan, Error> {
        if self.failed || self.ready.is_none() || self.peer.is_some() {
            return Err(Error::Failed);
        }
        wire::validate_channels(channels)?;
        wire::validate_ssids(ssids)?;
        if channels.iter().any(|f| !self.channels.contains(f)) {
            return Err(Error::Unsupported);
        }
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        let mut permissions = Vec::new();
        permissions
            .try_reserve_exact(channels.len())
            .map_err(|_| Error::NoMemory)?;
        for &frequency in channels {
            permissions.push(permission(caps, domain, frequency)?);
        }
        let mut global = *permissions.first().ok_or(Error::Unsupported)?;
        global.half_dbm = permissions
            .iter()
            .map(|p| p.half_dbm)
            .min()
            .ok_or(Error::Unsupported)?;
        let mut setup = Vec::new();
        setup.try_reserve_exact(3).map_err(|_| Error::NoMemory)?;
        setup.push(self.wire.domain(global)?);
        setup.push(self.wire.power(global)?);
        setup.push(self.wire.active_channels(&permissions)?);
        let restore = self.wire.channels(&self.channels)?;
        let mut names = Vec::new();
        names
            .try_reserve_exact(ssids.len())
            .map_err(|_| Error::NoMemory)?;
        for ssid in ssids {
            names.push(wire::owned(ssid)?);
        }
        let mut frequencies = Vec::new();
        frequencies
            .try_reserve_exact(channels.len())
            .map_err(|_| Error::NoMemory)?;
        frequencies.extend_from_slice(channels);
        Ok(Plan {
            channels: frequencies,
            ssids: names,
            extra_ies: Vec::new(),
            permissions,
            setup,
            restore,
        })
    }

    /// Keep the physical owner closed across every command/receive suspension.
    /// Failure/cancellation retains DMA and requires an owned full reset. STOP
    /// submission is best effort; it is not a firmware-idle acknowledgment.
    pub(in crate::ath10k) async fn active_scan(
        &mut self,
        plan: Plan,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<ScanReport, Error> {
        // Plans carry requested geometry, not authority for another physical
        // owner. Bind every check to this owner's actual SERVICE_READY facts.
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?.clone();
        plan.validate(&caps, &current()?)?;
        let before = self.sequence;
        let result = self
            .scan_run(
                &plan.channels,
                (&plan.ssids, &plan.extra_ies),
                &plan.setup,
                Some(&plan.restore),
                || plan.validate(&caps, &current()?),
            )
            .await;
        if result.is_err() && self.sequence != before {
            // Only the freshly reserved ID can be stopped. A denied preflight
            // does not send STOP or configure channels behind the caller's back.
            if let Ok(stop) = self.wire.stop_scan(self.sequence) {
                if self.htt.wmi.htc.send_wmi(&stop).await.is_ok() {
                    let _ = self.htt.wmi.htc.send_wmi(&plan.restore).await;
                }
            }
            self.failed = true;
        }
        result
    }
}
