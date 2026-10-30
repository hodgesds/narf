// SPDX-License-Identifier: GPL-2.0-or-later
//! Associated scan inventory over the retained vdev. Firmware's normal scan
//! scheduler owns home/off-channel dwell; host station/key/BA ownership stays
//! on this exact peer. Linux mac.c::ath10k_hw_scan/update_channel_list.
use super::*;
use crate::ath10k::regulatory::Permission;
use narf_wireless::reg::RegulatoryDomain;

pub(in crate::ath10k) fn receive_permission(
    domain: &RegulatoryDomain,
    frequencies: &[u16],
) -> Result<(), Error> {
    if !domain.country_code.iter().all(u8::is_ascii_uppercase)
        || frequencies.iter().any(|frequency| {
            if *frequency < 10 {
                return true;
            }
            let low = u32::from(*frequency) - 10;
            let high = u32::from(*frequency) + 10;
            let mut covering = false;
            for rule in &domain.rules {
                if rule.freq_end_mhz <= low || high <= rule.freq_start_mhz {
                    continue;
                }
                if rule.freq_start_mhz >= rule.freq_end_mhz || rule.max_bandwidth_mhz < 20 {
                    return true;
                }
                covering |= rule.freq_start_mhz <= low && high <= rule.freq_end_mhz;
            }
            !covering
        })
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    bssid: [u8; 6],
    pub permission: Permission,
    ht: bool,
    vht: bool,
}
impl Binding {
    pub fn check(&self, domain: &RegulatoryDomain) -> Result<(), Error> {
        self.permission.check(domain)
    }
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) async fn passive_scan_current(
        &mut self,
        channels: &[u16],
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<ScanReport, Error> {
        if self.peer.is_some() {
            return Err(Error::Failed);
        }
        let validate = || {
            let domain = current()?;
            receive_permission(&domain, channels)?;
            Ok(())
        };
        validate()?;
        self.scan_run(channels, (&[], &[]), &[], None, validate)
            .await
    }

    pub(in crate::ath10k) fn failed_scan_pending(&self) -> bool {
        self.failed && self.scan_pending.is_some()
    }

    /// Retained worker continuation after the caller dropped its scan future.
    /// STOP transmission is not a receipt: wait for this exact scan's terminal
    /// before the existing peer/vdev teardown. Policy loss may forbid DATA,
    /// but current transport authority still permits commands that silence it.
    pub(in crate::ath10k) async fn abort_failed_scan(
        &mut self,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.failed {
            return Err(Error::Failed);
        }
        let Some(sequence) = self.scan_pending else {
            return Ok(());
        };
        let mut stopped = self.scan_terminal == Some(sequence);
        if !stopped {
            let stop = self.wire.stop_scan(sequence)?;
            self.send_scan_command(&stop, validate).await?;
        } else {
            active_scan::checked(
                async {
                    self.htt
                        .wmi
                        .htc
                        .wait_wmi_source()
                        .await
                        .map_err(htt::Error::from)?;
                    Ok(())
                },
                validate,
            )
            .await?;
        }
        let deadline = narf_time::Deadline::after_ms(1500);
        for _ in 0..4096 {
            if stopped {
                break;
            }
            validate()?;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = active_scan::checked(
                async { self.htt.poll().await.map_err(Error::from) },
                validate,
            )
            .await?;
            if let htt::Event::Wmi(bytes) = event {
                if wire::word(&bytes, 0)? & 0xffffff == self.wire.scan_event {
                    let event = self.wire.scan_event(&bytes[4..])?;
                    if event.sequence == 0xa000 | u32::from(sequence)
                        && event.request == 0xa001
                        && event.vdev == 0
                        && matches!(event.kind, 2 | 64)
                    {
                        stopped = true;
                        break;
                    }
                }
            }
            narf_scheduler::yield_now().await;
        }
        if !stopped {
            return Err(Error::Timeout);
        }
        self.scan_pending = None;
        self.scan_dwell = None;
        if self.peer.is_some() {
            active_scan::checked(self.disconnect_after_failed_scan(), validate).await?;
        }
        // Failed remains set even with a confirmed STOP; only a separately
        // owned full reset may replace this physical/key/DMA generation.
        Ok(())
    }
    /// Preflight only. A partially prepared peer or an initially closed
    /// controlled port is not an associated scan owner.
    pub(super) fn scan_binding(&self) -> Result<Option<Binding>, Error> {
        let Some(peer) = &self.peer else {
            return Ok(None);
        };
        if self.station_link().is_none() || self.data.is_none() {
            return Err(Error::Failed);
        }
        Ok(Some(Binding {
            bssid: peer.bssid,
            permission: peer.permission,
            ht: peer.ht.is_some(),
            vht: peer.ht.is_some_and(|ht| ht.vht.is_some()),
        }))
    }

    /// Scan poisoning intentionally keeps public DATA entry points closed
    /// across awaits. Internal station progression may complete a rekey, so
    /// do not require a continuously open controlled port here.
    pub(super) fn check_scan_binding(&self, expected: Option<Binding>) -> Result<(), Error> {
        match (expected, self.peer.as_ref()) {
            (None, None) => Ok(()),
            (Some(expected), Some(peer))
                if peer.bssid == expected.bssid
                    && peer.permission == expected.permission
                    && peer.associated.is_some()
                    && self.data.is_some() =>
            {
                Ok(())
            }
            _ => Err(Error::Failed),
        }
    }

    /// Begin from the complete passive inventory. Probe permissions replace
    /// only their selected rows; the station's real occupied rows take final
    /// precedence, preserving HT40/VHT80 and home-channel autonomous traffic.
    pub(super) fn scan_inventory(
        &self,
        probes: &[Permission],
        station: Option<Binding>,
    ) -> Result<Vec<u8>, Error> {
        let mut frequencies = Vec::new();
        frequencies
            .try_reserve_exact(self.channels.len() + 4)
            .map_err(|_| Error::NoMemory)?;
        frequencies.extend_from_slice(&self.channels);
        // A deliberately small discovery inventory may omit the HT partner
        // or other VHT segment rows already covered by the station's actual
        // occupied permission. Keep those real home rows in the scan table.
        if let Some(station) = station {
            let p = station.permission;
            let occupied = if p.width80 {
                [p.center - 30, p.center - 10, p.center + 10, p.center + 30]
            } else {
                [
                    p.frequency,
                    p.secondary.unwrap_or(p.frequency),
                    p.frequency,
                    p.frequency,
                ]
            };
            for frequency in occupied {
                if !frequencies.contains(&frequency) {
                    frequencies.push(frequency);
                }
            }
        }
        let mut inventory = self.wire.channels(&frequencies)?;
        let tlv = self.wire.dialect == Dialect::Tlv;
        if !probes.is_empty() {
            let active = self.wire.active_channels(probes)?;
            merge_inventory(&mut inventory, &active, tlv)?;
        }
        if let Some(station) = station {
            let permission = station.permission;
            let occupied = if permission.secondary.is_some() {
                self.wire.station_ht40_channels(permission, station.vht)?
            } else {
                let mut row = self.wire.active_channels(&[permission])?;
                let at = if tlv { 20 } else { 8 };
                wire::put(
                    &mut row,
                    at + 12,
                    u32::from(permission.frequency < 3000)
                        | u32::from(station.ht) << 11
                        | u32::from(station.vht) << 12,
                );
                row
            };
            merge_inventory(&mut inventory, &occupied, tlv)?;
        }
        Ok(inventory)
    }

    pub(super) fn scan_restore(&self, station: Option<Binding>) -> Result<Vec<Vec<u8>>, Error> {
        let mut restore = Vec::new();
        restore.try_reserve_exact(3).map_err(|_| Error::NoMemory)?;
        if let Some(station) = station {
            restore.push(self.wire.domain(station.permission)?);
            restore.push(self.wire.power(station.permission)?);
        }
        restore.push(self.scan_inventory(&[], station)?);
        Ok(restore)
    }

    pub(super) fn cache_scan_results(
        &mut self,
        report: &ScanReport,
        station: Option<Binding>,
    ) -> Result<(), Error> {
        let mut cache = Vec::new();
        cache.try_reserve_exact(64).map_err(|_| Error::NoMemory)?;
        for bss in &report.bss {
            cache.push(bss.copy_owned()?);
        }
        if let Some(station) = station {
            let is_home = |b: &ScanBss| {
                b.bssid == station.bssid && b.frequency == station.permission.frequency
            };
            if !cache.iter().any(is_home) {
                if let Some(home) = self.scan_cache.iter().find(|b| is_home(b)) {
                    // A requested off-channel scan may never observe home.
                    // Keep its bound beacon identity so normal station RX can
                    // continue refreshing liveness and checking HT/WMM facts.
                    if cache.len() == 64 {
                        cache.pop();
                    }
                    cache.push(home.copy_owned()?);
                }
            }
        }
        self.scan_cache = cache;
        Ok(())
    }
}

/// Both inputs are native channel-list commands. Preserve the target's full
/// inventory and TLV framing; replace only complete24-byte wmi_channel bodies.
fn merge_inventory(target: &mut [u8], selected: &[u8], tlv: bool) -> Result<(), Error> {
    fn geometry(bytes: &[u8], tlv: bool) -> Result<(usize, usize, usize), Error> {
        let count = wire::word(bytes, if tlv { 8 } else { 4 })? as usize;
        let (prefix, first, stride) = if tlv { (16, 20, 28) } else { (8, 8, 24) };
        if count == 0 || count > 64 || bytes.len() != prefix + count * stride {
            return Err(Error::Malformed);
        }
        Ok((count, first, stride))
    }
    let (count, first, stride) = geometry(target, tlv)?;
    let (selected_count, selected_first, selected_stride) = geometry(selected, tlv)?;
    for index in 0..selected_count {
        let source = selected_first + index * selected_stride;
        let frequency = wire::word(selected, source)?;
        let slot = (0..count)
            .find(|index| wire::word(target, first + index * stride) == Ok(frequency))
            .ok_or(Error::Unsupported)?;
        let destination = first + slot * stride;
        target[destination..destination + 24].copy_from_slice(&selected[source..source + 24]);
    }
    Ok(())
}
