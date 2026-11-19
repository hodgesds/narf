// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! API77 idle periodic-scan transport. The physical boot owner retains
//! native UID/command receipts; no host timer synthesizes scan iterations.
use super::super::scheduled_wire as wire;
use super::{
    power::{self, Emission, ScanFence},
    Owner, Phase,
};
use crate::firmware_asset::Asset;
use alloc::{sync::Arc, vec::Vec};
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};
use narf_wireless::{reg::RegulatoryDomain, SchedScanRequest};

pub(in crate::iwlwifi) struct Scheduled {
    channels: Vec<u8>,
    request: SchedScanRequest,
    qualification: Option<Arc<ScanFence>>,
    results: Vec<(narf_wireless::BssInfo, Vec<u8>, u64)>,
}
#[derive(Clone)]
pub(in crate::iwlwifi) struct Fence {
    channels: Vec<u8>,
    qualification: Option<Arc<ScanFence>>,
}
pub(in crate::iwlwifi) struct Report {
    pub results: Option<Vec<(narf_wireless::BssInfo, Vec<u8>)>>,
    pub stopped: bool,
    pub oldest: Option<u64>,
}
async fn checked<T>(
    schedule: &Scheduled,
    policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    future: impl Future<Output = Result<T, &'static str>>,
) -> Result<T, &'static str> {
    let mut future = pin!(future);
    poll_fn(|cx| {
        let current =
            policy().and_then(|domain| schedule.invoke(&domain, || Ok(future.as_mut().poll(cx))));
        match current {
            Ok(poll) => poll,
            Err(error) => Poll::Ready(Err(error)),
        }
    })
    .await
}
impl Scheduled {
    pub fn fence(&self) -> Fence {
        Fence {
            channels: self.channels.clone(),
            qualification: self.qualification.clone(),
        }
    }
    pub fn invoke<T>(
        &self,
        domain: &RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        invoke(
            &self.channels,
            self.qualification.as_deref(),
            domain,
            operation,
        )
    }
}
impl Fence {
    pub fn invoke<T>(
        &self,
        domain: &RegulatoryDomain,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        invoke(
            &self.channels,
            self.qualification.as_deref(),
            domain,
            operation,
        )
    }
}
fn invoke<T>(
    channels: &[u8],
    qualification: Option<&ScanFence>,
    domain: &RegulatoryDomain,
    operation: impl FnOnce() -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    if channels
        .iter()
        .any(|&channel| !super::scan::passive_permitted(domain, channel))
    {
        return Err("MVM scheduled receive policy retired");
    }
    match qualification {
        Some(fence) => fence.invoke(domain, operation),
        None => operation(),
    }
}
impl Owner {
    fn scheduled_mcc_current(&mut self) -> Result<(), &'static str> {
        self.hardware.poll()?;
        if self
            .hardware
            .notifications
            .iter()
            .any(|p| p.header.group_id == 0 && p.header.cmd == 0xc9)
        {
            return Err("MVM scheduled native MCC changed before scanner publication");
        }
        Ok(())
    }
    pub(in crate::iwlwifi) fn scheduled_profile(&self) -> Result<(usize, bool), &'static str> {
        let parsed = super::super::parse_ucode(&self.firmware)
            .map_err(|_| "MVM scheduled executable metadata invalid")?;
        let version = parsed.api.command_version(0, 0x6e).filter(|v| *v != 99);
        Ok((
            if version.is_some_and(|v| v >= 3) {
                8
            } else {
                11
            },
            parsed.api.flags & (1 << 7) != 0,
        ))
    }
    pub(in crate::iwlwifi) async fn scheduled_start_using(
        &mut self,
        channels: &[u8],
        request: SchedScanRequest,
        source: Option<(Asset, [u8; 32])>,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<Scheduled, &'static str> {
        if self.phase != Phase::Configured || self.hardware.is_failed() {
            return Err("MVM scheduled scan requires idle configured owner");
        }
        let nvm = self.nvm.as_ref().ok_or("MVM scheduled NVM absent")?;
        let domain = policy()?;
        if channels.is_empty()
            || channels.len() > 51
            || channels.iter().enumerate().any(|(i, ch)| {
                !nvm.channels.contains(ch)
                    || channels[..i].contains(ch)
                    || !super::scan::passive_permitted(&domain, *ch)
            })
        {
            return Err("MVM scheduled channels invalid");
        }
        let version = self.validate_scan_profile()?;
        let local = self.mac.ok_or("MVM scheduled MAC absent")?;
        let (maximum, short) = self.scheduled_profile()?;
        let profile = wire::profiles_with_limits(&request.matches, maximum, short)?;
        let probe_mac = if let Some(random) = &request.random_mac {
            let mut bytes = [0; 6];
            narf_crypto::try_fill_random_bytes(&mut bytes)
                .map_err(|_| "MVM scheduled random MAC entropy unavailable")?;
            bytes[0] = (bytes[0] | 2) & !1;
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = (*byte & !random.mask[i]) | (random.addr[i] & random.mask[i]);
            }
            if bytes[0] & 1 != 0 || bytes == [0; 6] {
                return Err("MVM scheduled invalid random source");
            }
            bytes
        } else {
            local
        };
        let phy = super::super::ht_vht::Local::from_nvm(0, 1, 1);
        wire::request(
            version,
            channels,
            &alloc::vec![false;channels.len()],
            probe_mac,
            phy,
            &request,
        )?;
        let prepared = match source {
            Some((source, binding)) => Some(power::parse_for(
                source,
                binding,
                local,
                channels[0],
                Emission::ActiveScan,
            )?),
            None => None,
        };
        if !request.probe_ssids.is_empty() && prepared.is_none() {
            return Err("MVM scheduled probes lack exact current qualification");
        }
        let mut schedule = Scheduled {
            channels: channels.to_vec(),
            request,
            qualification: None,
            results: Vec::new(),
        };
        self.phase = Phase::Scanning;
        let result = async {
            checked(&schedule, &mut policy, self.prepare_scan()).await?;
            self.scheduled_mcc_current()?;
            let permitted = if schedule.request.probe_ssids.is_empty() {
                alloc::vec![false;channels.len()]
            } else {
                self.active_scan_mask(channels, &policy()?)?
            };
            if permitted.iter().any(|&allowed| allowed) {
                let prepared = prepared
                    .as_ref()
                    .ok_or("MVM scheduled qualification lost")?;
                schedule.qualification = Some(Arc::new(prepared.scan_fence(
                    channels,
                    &permitted,
                    &policy()?,
                )?));
                let chains = prepared.scan_chain_command();
                let reply = checked(
                    &schedule,
                    &mut policy,
                    self.hardware.command(1, 0x9f, &chains),
                )
                .await?;
                if !reply.payload.is_empty() {
                    return Err("MVM scheduled SAR reply malformed");
                }
                self.scheduled_mcc_current()?;
                let device = schedule.qualification.as_ref().unwrap().device_command();
                let reply = checked(
                    &schedule,
                    &mut policy,
                    self.hardware.command(1, 0x9f, &device),
                )
                .await?;
                if !reply.payload.is_empty() {
                    return Err("MVM scheduled device power reply malformed");
                }
                self.scheduled_mcc_current()?;
            }
            let body = wire::request(
                version,
                channels,
                &permitted,
                probe_mac,
                phy,
                &schedule.request,
            )?;
            self.scheduled_mcc_current()?;
            self.hardware.notifications.clear();
            checked(
                &schedule,
                &mut policy,
                self.hardware.command(0, 0x6e, &profile),
            )
            .await?;
            self.scheduled_mcc_current()?;
            self.hardware.notifications.clear();
            self.hardware.watch_scan_mcc(true);
            checked(&schedule, &mut policy, self.hardware.command(1, 0xd, &body)).await?;
            self.scheduled_mcc_current()?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.beacons.clear();
                Ok(schedule)
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                let _ = self.suspend_transport().await;
                Err(error)
            }
        }
    }

    pub(in crate::iwlwifi) fn scheduled_poll(
        &mut self,
        schedule: &mut Scheduled,
        domain: &RegulatoryDomain,
        copied_after: u64,
    ) -> Result<Report, &'static str> {
        schedule.invoke(domain, || self.hardware.poll())?;
        let maximum_age = narf_time::wall::ns_to_cycles(10_000_000_000);
        schedule
            .results
            .retain(|(_, _, seen)| copied_after.wrapping_sub(*seen) <= maximum_age);
        let mut results = false;
        let mut stopped = false;
        for _ in 0..64 {
            let Some(packet) = self.hardware.notifications.pop_front() else {
                break;
            };
            if packet.header.group_id != 0 {
                continue;
            }
            match packet.header.cmd {
                0xc9 => return Err("MVM scheduled native MCC map retired"),
                0xf => {
                    if wire::complete(&packet.payload)?.is_some() {
                        stopped = true;
                    }
                }
                0xb5 => {
                    if packet.payload.len() < 16 {
                        return Err("MVM scheduled iteration extent");
                    }
                    if packet.payload[..4] == wire::UID.to_le_bytes()
                        && schedule
                            .request
                            .matches
                            .first()
                            .is_none_or(|m| m.ssid.is_empty())
                    {
                        results = true;
                    }
                }
                0xd9 => results = true,
                0xc1 if packet.receive_queue == 0 => {
                    if let Some((beacon, bss)) =
                        wire::copied_bss(&packet, true, &schedule.channels, &schedule.request)
                    {
                        if let Some(old) = self
                            .beacons
                            .iter_mut()
                            .find(|old| old.bssid == beacon.bssid)
                        {
                            *old = beacon.clone();
                        } else if self.beacons.len() < 256 {
                            self.beacons.push(beacon.clone());
                        }
                        let entry = (bss, beacon.information_elements, copied_after);
                        if let Some(old) = schedule
                            .results
                            .iter_mut()
                            .find(|old| old.0.bssid == entry.0.bssid)
                        {
                            *old = entry;
                        } else if schedule.results.len() < 256 {
                            schedule.results.push(entry);
                        }
                    }
                }
                _ => {}
            }
        }
        if stopped {
            self.hardware.watch_scan_mcc(false);
            self.phase = Phase::Configured;
        }
        self.beacons.retain(|beacon| {
            schedule
                .results
                .iter()
                .any(|(bss, _, _)| bss.bssid == beacon.bssid)
        });
        let oldest = schedule
            .results
            .iter()
            .max_by_key(|(_, _, seen)| copied_after.wrapping_sub(*seen))
            .map(|(_, _, seen)| *seen);
        Ok(Report {
            results: (results && !schedule.results.is_empty()).then(|| {
                schedule
                    .results
                    .iter()
                    .map(|(bss, ies, _)| (bss.clone(), ies.clone()))
                    .collect()
            }),
            stopped,
            oldest,
        })
    }
    pub(in crate::iwlwifi) async fn scheduled_stop(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::Scanning || self.hardware.is_failed() {
            self.station_fail();
            let _ = self.suspend_transport().await;
            return Err("MVM scheduled stop has uncertain transport");
        }
        let result = async {
            let mut body = [0; 8];
            body[..4].copy_from_slice(&wire::UID.to_le_bytes());
            let response = self.hardware.command(1, 0xe, &body).await?;
            if !wire::aborted_reply(&response.payload)? {
                let deadline = narf_time::Deadline::after_ms(2000);
                loop {
                    let activity = self.hardware.activity();
                    self.hardware.poll()?;
                    if let Some(at) = self.hardware.notifications.iter().position(|p| {
                        p.header.group_id == 0
                            && p.header.cmd == 0xf
                            && p.payload.get(..4) == Some(wire::UID.to_le_bytes().as_slice())
                    }) {
                        wire::complete(&self.hardware.notifications.remove(at).unwrap().payload)?;
                        break;
                    }
                    if deadline.expired() {
                        return Err("MVM scheduled stop terminal UID timed out");
                    }
                    activity.await;
                }
            }
            self.hardware.notifications.retain(|p| {
                !(p.header.group_id == 0 && matches!(p.header.cmd, 0xf | 0xc1 | 0xb2 | 0xb5 | 0xd9))
            });
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.hardware.watch_scan_mcc(false);
                self.phase = Phase::Configured;
                Ok(())
            }
            Err(error) => {
                self.station_fail();
                let _ = self.suspend_transport().await;
                Err(error)
            }
        }
    }
}
