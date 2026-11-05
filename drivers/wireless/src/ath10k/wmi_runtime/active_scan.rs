// SPDX-License-Identifier: GPL-2.0-or-later
//! Policy-bounded unassociated probes over the retained mission transport.
use super::*;
use crate::ath10k::{regulatory::Permission, wmi_boot::Capabilities};
use alloc::sync::Arc;
use core::{future::Future, pin::pin, task::Poll};
use narf_wireless::reg::RegulatoryDomain;

fn permission(
    caps: &Capabilities,
    domain: &RegulatoryDomain,
    frequency: u16,
    hint: Option<Arc<beacon_hints::Receipt>>,
) -> Result<Permission, Error> {
    Permission::occupied_width_with_hint(caps, domain, frequency, None, false, hint)
}

#[derive(Clone, Debug)]
pub(in crate::ath10k) struct Plan {
    pub(super) channels: Vec<u16>,
    pub(super) ssids: Vec<Vec<u8>>,
    pub(super) extra_ies: Vec<u8>,
    pub(super) permissions: Vec<Permission>,
    pub(super) setup: Vec<Vec<u8>>,
    pub(super) restore: Vec<Vec<u8>>,
    pub(super) station: Option<associated_scan::Binding>,
    /// Run on the P2P_DEVICE vdev (`Radio::p2p_device_scan`), not vdev0.
    pub(super) p2p_device: Option<u8>,
}
impl Plan {
    /// Own and validate all probe content before reserving an ID or touching HIF.
    pub(in crate::ath10k) fn with_extra_ies(mut self, bytes: &[u8]) -> Result<Self, Error> {
        wire::validate_probe_ies(bytes)?;
        self.extra_ies = wire::owned(bytes)?;
        Ok(self)
    }
    pub(in crate::ath10k) fn validate(
        &self,
        caps: &Capabilities,
        domain: &RegulatoryDomain,
    ) -> Result<(), Error> {
        associated_scan::receive_permission(domain, &self.channels)?;
        if let Some(station) = &self.station {
            station.check(domain)?;
        }
        for previous in &self.permissions {
            let current = permission(caps, domain, previous.frequency, previous.hint.clone())?;
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
pub(in crate::ath10k) async fn checked<O>(
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
            && self.htt.wmi.caps.as_ref().is_some_and(|caps| {
                permission(caps, domain, frequency, self.beacon_hints.receipt(domain)).is_ok()
            })
    }
    /// Preflight performs no transport access and reserves no scan ID.
    pub(in crate::ath10k) fn prepare_active_scan(
        &self,
        channels: &[u16],
        ssids: &[Vec<u8>],
        domain: &RegulatoryDomain,
    ) -> Result<Plan, Error> {
        if self.failed || self.ready.is_none() || self.scan_pending.is_some() {
            return Err(Error::Failed);
        }
        let station = self.scan_binding()?;
        if let Some(station) = &station {
            station.check(domain)?;
        }
        wire::validate_channels(channels)?;
        wire::validate_ssids(ssids)?;
        if channels.iter().any(|f| !self.channels.contains(f)) {
            return Err(Error::Unsupported);
        }
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        let hint = self.beacon_hints.receipt(domain);
        let mut permissions = Vec::new();
        permissions
            .try_reserve_exact(channels.len())
            .map_err(|_| Error::NoMemory)?;
        for &frequency in channels {
            permissions.push(permission(caps, domain, frequency, hint.clone())?);
        }
        let global = station
            .as_ref()
            .map(|s| &s.permission)
            .or_else(|| permissions.first())
            .ok_or(Error::Unsupported)?;
        let mut setup = Vec::new();
        setup.try_reserve_exact(4).map_err(|_| Error::NoMemory)?;
        setup.push(self.wire.domain(global)?);
        // Both native per-band limits precede a mixed-band active request.
        // A low-power2GHz channel cannot accidentally program only2G while
        // probes on5GHz inherit an unrelated firmware default.
        for two_ghz in [true, false] {
            if let Some(permission) = permissions
                .iter()
                .chain(station.as_ref().map(|s| &s.permission))
                .filter(|p| (p.frequency < 3000) == two_ghz)
                .min_by_key(|p| p.half_dbm)
            {
                setup.push(self.wire.power(permission)?);
            }
        }
        setup.push(if station.is_some() {
            self.scan_inventory(&permissions, station.as_ref())?
        } else {
            self.wire.active_channels(&permissions)?
        });
        let restore = self.scan_restore(station.as_ref())?;
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
            station,
            p2p_device: None,
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
        // Raw PCI diagnostics keep their original exclusive unassociated
        // owner. Registered associated scans use retained stepwise dwell,
        // except a P2P-device scan: it runs on the P2P_DEVICE vdev with
        // firmware dwell while the managed station stays associated, so
        // its station binding is carried for setup/restore only. A failed
        // P2P scan while associated still fails the radio (station
        // retirement), exactly as a failed managed associated scan does;
        // scan-failure isolation is a separate item.
        if plan.p2p_device.is_none() && (plan.station.is_some() || self.station.peer.is_some()) {
            return Err(Error::Failed);
        }
        // Plans carry requested geometry, not authority for another physical
        // owner. Bind every check to this owner's actual SERVICE_READY facts.
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?.clone();
        plan.validate(&caps, &current()?)?;
        self.check_scan_binding(plan.station.as_ref())?;
        let before = self.sequence;
        let result = self
            .scan_run_on(
                plan.p2p_device,
                &plan.channels,
                (&plan.ssids, &plan.extra_ies),
                &plan.setup,
                &plan.restore,
                || plan.validate(&caps, &current()?),
            )
            .await;
        if result.is_err() && self.sequence != before {
            // Only the freshly reserved ID can be stopped. A denied preflight
            // does not send STOP or configure channels behind the caller's back.
            if !self.htt.wmi.htc.transport.nonblocking_wmi() {
                if let Ok(stop) = self.wire.stop_scan(self.sequence) {
                    if self.htt.wmi.htc.send_wmi(&stop).await.is_ok() && plan.station.is_none() {
                        for packet in &plan.restore {
                            let _ = self.htt.wmi.htc.send_wmi(packet).await;
                        }
                    }
                }
            }
            self.failed = true;
        }
        result
    }
}
