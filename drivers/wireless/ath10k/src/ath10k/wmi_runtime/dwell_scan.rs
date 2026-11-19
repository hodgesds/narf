// SPDX-License-Identifier: GPL-2.0-or-later
//! An associated scan has a retained receipt owner, not a long-lived borrow of
//! Radio. Normal native RX/TX can run between scan steps. Firmware performs
//! home/off-channel PS and dwell (Linux ath10k_hw_scan on the station vdev).
use super::*;
use active_scan::Plan;
use alloc::sync::Arc;
use narf_wireless::reg::RegulatoryDomain;

#[derive(Debug)]
pub(super) struct Work {
    policy: Arc<ScanPolicy>,
    report: ScanReport,
    complete: bool,
}

/// Immutable native scan program carried through final copied RX admission,
/// after the Radio lock has been released for the stack callback.
#[derive(Debug)]
pub(in crate::ath10k) struct ScanPolicy {
    plan: Plan,
    caps: wmi_boot::Capabilities,
    deadline: narf_time::Deadline,
}
impl ScanPolicy {
    pub fn check(&self, domain: &RegulatoryDomain) -> Result<(), Error> {
        self.plan.validate(&self.caps, domain)?;
        if self.deadline.expired() {
            return Err(Error::Timeout);
        }
        Ok(())
    }
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(super) async fn send_scan_command(
        &mut self,
        packet: &[u8],
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        checked_policy(
            async {
                self.htt
                    .wmi
                    .htc
                    .send_wmi_retained(packet)
                    .await
                    .map_err(htt::Error::from)?;
                Ok(())
            },
            validate,
        )
        .await
    }
    pub(in crate::ath10k) fn scan_in_progress(&self) -> bool {
        self.scan_pending.is_some()
    }

    /// Peer is removed only after the exact DELETE/UNMAP/VDEV_STOPPED chain.
    /// Retained packet state distinguishes that receipt from an unused radio.
    pub(in crate::ath10k) fn station_retired(&self) -> bool {
        self.failed && self.station.peer.is_none() && self.station.data.is_some()
    }
    pub(in crate::ath10k) fn failed_station_pending(&self) -> bool {
        self.failed && self.station.peer.is_some()
    }

    pub(in crate::ath10k) fn prepare_associated_passive_scan(
        &self,
        channels: &[u16],
        domain: &RegulatoryDomain,
    ) -> Result<Plan, Error> {
        if self.failed || self.ready.is_none() || self.scan_pending.is_some() {
            return Err(Error::Failed);
        }
        wire::validate_channels(channels)?;
        if channels.iter().any(|f| !self.channels.contains(f)) {
            return Err(Error::Unsupported);
        }
        let station = self.scan_binding()?.ok_or(Error::Unsupported)?;
        station.check(domain)?;
        associated_scan::receive_permission(domain, channels)?;
        let restore = self.scan_restore(Some(&station))?;
        let mut frequencies = Vec::new();
        frequencies
            .try_reserve_exact(channels.len())
            .map_err(|_| Error::NoMemory)?;
        frequencies.extend_from_slice(channels);
        Ok(Plan {
            channels: frequencies,
            ssids: Vec::new(),
            extra_ies: Vec::new(),
            permissions: Vec::new(),
            setup: restore.clone(),
            restore,
            station: Some(station),
            p2p_device: None,
        })
    }

    /// Setup is bounded by native command/credit waits. After publication the
    /// caller releases Radio; the usual data worker consumes scan events too.
    /// Cancellation during setup leaves failed + scan_pending for cleanup.
    pub(in crate::ath10k) async fn begin_associated_scan(
        &mut self,
        plan: Plan,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<(), Error> {
        if self.failed
            || self.ready.is_none()
            || self.scan_pending.is_some()
            || plan.station.is_none()
        {
            return Err(Error::Failed);
        }
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?.clone();
        let validate = || plan.validate(&caps, &current()?);
        validate()?;
        self.check_scan_binding(plan.station.as_ref())?;
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n <= 4095)
            .ok_or(Error::Exhausted)?;
        let command = if plan.ssids.is_empty() {
            self.wire.scan(sequence, &plan.channels)?
        } else {
            self.wire
                .active_scan(sequence, &plan.channels, &plan.ssids, &plan.extra_ies)?
        };
        let mut report = ScanReport {
            bss: Vec::new(),
            received: 0,
            ignored: 0,
            truncated: false,
        };
        report
            .bss
            .try_reserve_exact(64)
            .map_err(|_| Error::NoMemory)?;
        self.sequence = sequence;
        self.scan_pending = Some(sequence);
        self.scan_vdev = u32::from(self.primary.id());
        self.begin_beacon_hint_scan(sequence, &plan.channels);
        self.scan_terminal = None;
        self.failed = true;
        for packet in plan
            .setup
            .iter()
            .map(Vec::as_slice)
            .chain(core::iter::once(command.as_slice()))
        {
            self.send_scan_command(packet, &validate).await?;
        }
        validate()?;
        self.check_scan_binding(plan.station.as_ref())?;
        self.scan_dwell = Some(Work {
            policy: Arc::new(ScanPolicy {
                plan,
                caps,
                deadline: narf_time::Deadline::after_ms(25_000),
            }),
            report,
            complete: false,
        });
        self.failed = false;
        Ok(())
    }

    /// This also runs before ordinary DATA/reply publication while a scan is
    /// active: a tightened probe grant must stop autonomous scan emissions.
    pub(super) fn check_dwell_scan(&self, domain: &RegulatoryDomain) -> Result<(), Error> {
        let Some(work) = &self.scan_dwell else {
            return Ok(());
        };
        work.policy.check(domain)?;
        self.check_scan_binding(work.policy.plan.station.as_ref())
    }

    pub(in crate::ath10k) fn scan_policy(&self) -> Option<Arc<ScanPolicy>> {
        self.scan_dwell.as_ref().map(|work| work.policy.clone())
    }

    pub(in crate::ath10k) fn associated_scan_complete(
        &self,
        domain: &RegulatoryDomain,
    ) -> Result<bool, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        self.check_data_policy(domain)?;
        Ok(self.scan_dwell.as_ref().ok_or(Error::Failed)?.complete)
    }

    /// Observe before station_event forwards the same management/data event
    /// to its existing peer/key/BA owner. No callback or alternate key parser.
    pub(super) fn observe_dwell_scan(&mut self, event: &htt::Event) -> Result<(), Error> {
        let Some(work) = &mut self.scan_dwell else {
            return Ok(());
        };
        let htt::Event::Wmi(bytes) = event else {
            return Ok(());
        };
        let id = wire::word(bytes, 0)? & 0xffffff;
        if id == self.wire.scan_event {
            let event = self.wire.scan_event(&bytes[4..])?;
            if Some(event.sequence) != self.scan_pending.map(|id| 0xa000 | u32::from(id))
                || event.request != 0xa001
                || event.vdev != u32::from(self.primary.id())
            {
                work.report.ignored = work.report.ignored.saturating_add(1);
                return Ok(());
            }
            match event.kind {
                2 if event.reason == 0 => {
                    self.scan_terminal = self.scan_pending;
                    work.complete = true;
                }
                2 | 64 => {
                    self.scan_terminal = self.scan_pending;
                    return Err(Error::Firmware(event.reason));
                }
                _ => {}
            }
        } else if id == self.wire.management_event {
            let management = self.wire.management(&bytes[4..], self.features)?;
            work.report.received = work.report.received.saturating_add(1);
            if let Some(bss) = beacon(&management, &work.policy.plan.channels)? {
                if let Some(previous) = work
                    .report
                    .bss
                    .iter_mut()
                    .find(|b| b.bssid == bss.bssid && b.frequency == bss.frequency)
                {
                    *previous = bss;
                } else if work.report.bss.len() < 64 {
                    work.report.bss.push(bss);
                } else {
                    work.report.truncated = true;
                }
            } else {
                work.report.ignored = work.report.ignored.saturating_add(1);
            }
        }
        Ok(())
    }

    pub(in crate::ath10k) async fn finish_associated_scan(
        &mut self,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<ScanReport, Error> {
        if !self.associated_scan_complete(&current()?)? {
            return Err(Error::Failed);
        }
        // Keep the plan locally while Radio is exclusively borrowed. A drop
        // at any restore wait preserves scan_pending + failed for the worker.
        let work = self.scan_dwell.take().ok_or(Error::Failed)?;
        let validate = || work.policy.check(&current()?);
        self.failed = true;
        for packet in &work.policy.plan.restore {
            self.send_scan_command(packet, &validate).await?;
        }
        validate()?;
        self.check_scan_binding(work.policy.plan.station.as_ref())?;
        self.cache_scan_results(&work.report, work.policy.plan.station.as_ref())?;
        self.scan_pending = None;
        self.failed = false;
        Ok(work.report)
    }
}
