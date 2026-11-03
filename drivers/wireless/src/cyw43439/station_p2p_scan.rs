// SPDX-License-Identifier: GPL-2.0-or-later
//! P2P escan of the primary station (Linux 7.3-rc4 `cfg80211.c`
//! `brcmf_cfg80211_scan` with `p2p.c` `brcmf_p2p_scan_prep`,
//! `brcmf_p2p_run_escan` and `brcmf_p2p_escan`).
//!
//! A scan request carrying the `DIRECT-` wildcard SSID is a P2P scan: the
//! discovery bsscfg (`brcmfmac::p2p::Device`) is enabled, the request's
//! vendor IEs become its probe-request `vndr_ie` set, and the scan runs as
//! bsscfg `p2p_scan` 'E' on that bsscfg with the SEARCH state for the three
//! social channels (or an existing GO) and the SCAN state with the
//! `DIRECT-` SSID otherwise. Channels whose current policy forbids TX
//! (Linux: `IEEE80211_CHAN_RADAR | IEEE80211_CHAN_NO_IR`) are left out;
//! Linux leaves zero holes in its chanspec list for them, NARF compacts.
//! Results (`BRCMF_E_ESCAN_RESULT` with the P2P `sync_id`) are taken from
//! the primary and the discovery bsscfg queues; they are not SSID-filtered,
//! as the Linux escan handler reports every BSS to cfg80211.
use super::{channel, channel_power, events, le32, parse_scan_result, wait, Station};
use crate::brcmfmac::{p2p::Device, p2p_wire, vif_owner::Owner};
use crate::cyw43439::{fullmac::Fullmac, runtime::Error};
use alloc::vec::Vec;
use narf_wireless::{BssInfo, ScanRequest};

impl<R: Fullmac> Station<R> {
    /// `brcmf_p2p_scan_is_p2p_request`.
    pub fn is_p2p_scan(request: &ScanRequest) -> bool {
        p2p_wire::is_p2p_request(&request.ssids)
    }

    /// One P2P escan (see the module documentation). `go` is a live P2P GO
    /// connection bsscfg (`brcmf_p2p_run_escan` "Already a GO").
    pub async fn p2p_scan(
        &mut self,
        owner: &mut Owner,
        device: &mut Device,
        go: bool,
        request: ScanRequest,
    ) -> Result<Vec<BssInfo>, Error> {
        if self.operation {
            self.runtime.fail();
            return Err(Error::Failed);
        }
        self.operation = true;
        let result = self.p2p_scan_inner(owner, device, go, request).await;
        self.operation = false;
        result
    }

    async fn p2p_scan_inner(
        &mut self,
        owner: &mut Owner,
        device: &mut Device,
        go: bool,
        request: ScanRequest,
    ) -> Result<Vec<BssInfo>, Error> {
        // The station scan loop consumes the primary event queue, so it
        // never runs while associated (as `scan`); Linux's connected
        // `active = -1` dwell is therefore not reachable here.
        if self.bssid.is_some() {
            return Err(Error::Busy);
        }
        if !Self::is_p2p_scan(&request)
            || request.random_mac.is_some()
            || request.colocated_6ghz
            || request.duration_tu.is_some()
            || request.duration_mandatory
        {
            return Err(Error::Unsupported);
        }
        let mut requested = Vec::new();
        if request.frequencies_mhz.is_empty() {
            // cfg80211 fills every supported channel when none is given.
            requested.extend_from_slice(&self.channels);
        } else {
            for &frequency in &request.frequencies_mhz {
                requested.push(channel::from_frequency(frequency).ok_or(Error::Unsupported)?);
            }
        }
        let mut channels = Vec::new();
        for channel in requested {
            if !self.channels.contains(&channel) {
                return Err(Error::Malformed);
            }
            // No P2P scanning on passive or DFS channels.
            if channel_power(&self.domain, channel).is_none() || channels.contains(&channel) {
                continue;
            }
            channels.push(channel);
        }
        if channels.is_empty() {
            return Err(Error::Unsupported);
        }
        let state = p2p_wire::search_state(&channels, go);
        let chanspecs = channels
            .iter()
            .map(|&channel| channel::encode20(channel).ok_or(Error::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        self.check_receive_policy(&channels)?;
        // Every P2P escan is active: each channel must permit TX, and the
        // shared TX power is the lowest of their ceilings (as `scan`).
        let mut power: Option<u8> = None;
        let mut grants = Vec::new();
        for &channel in &channels {
            let ceiling = channel_power(&self.domain, channel).ok_or(Error::Unsupported)?;
            power = Some(power.map_or(ceiling, |old| old.min(ceiling)));
        }
        let power = power.ok_or(Error::Unsupported)?;
        for &channel in &channels {
            grants.push(self.grant(channel, power)?);
        }
        self.check_grants(&grants)?;
        self.checked_var(
            &grants,
            &channels,
            "qtxpower",
            &(u32::from(power) * 4).to_le_bytes(),
        )
        .await?;
        self.runtime.poll()?;
        while self.runtime.pop_event().is_some() {}
        device
            .scan_prep(&mut self.runtime, &request.extra_ies)
            .await?;
        self.check_receive_policy(&channels)?;
        self.check_grants(&grants)?;
        self.cache.clear();
        device
            .run_escan(&mut self.runtime, state, &chanspecs)
            .await?;
        let deadline = narf_time::Deadline::after_ms(15000);
        let mut diverted = Vec::new();
        let outcome = async {
            loop {
                self.check_receive_policy(&channels)?;
                self.check_grants(&grants)?;
                self.runtime.poll()?;
                device
                    .service_escan(&mut self.runtime, owner, &mut diverted)
                    .await?;
                while let Some(event) = self.runtime.pop_event() {
                    diverted.push(event);
                }
                for event in diverted.drain(..) {
                    if event.header.event_type != events::WLC_E_ESCAN_RESULT {
                        continue;
                    }
                    if event.header.status == 8 {
                        // BRCMF_E_STATUS_PARTIAL.
                        let (event_id, bss) = parse_scan_result(&event.payload)?;
                        if event_id != p2p_wire::ESCAN_SYNC_ID
                            || !channels.contains(&(bss.info.channel as u8))
                        {
                            continue;
                        }
                        if let Some(old) = self
                            .cache
                            .iter_mut()
                            .find(|b| b.info.bssid == bss.info.bssid)
                        {
                            *old = bss;
                        } else if self.cache.len() < 64 {
                            self.cache.push(bss);
                        }
                        continue;
                    }
                    if !event.payload.is_empty() {
                        let length = le32(&event.payload, 0)? as usize;
                        if length < 12 || length > event.payload.len() {
                            return Err(Error::Malformed);
                        }
                        let event_id = u16::from_le_bytes([event.payload[8], event.payload[9]]);
                        if event_id != p2p_wire::ESCAN_SYNC_ID {
                            continue;
                        }
                    }
                    if event.header.status == 0 {
                        self.check_receive_policy(&channels)?;
                        self.check_grants(&grants)?;
                        return Ok(self.cache.iter().map(|b| b.info.clone()).collect());
                    }
                    return Err(Error::Firmware(event.header.status));
                }
                if deadline.expired() {
                    self.runtime.fail();
                    return Err(Error::Timeout);
                }
                wait().await;
            }
        }
        .await;
        // As `scan`: an accepted escan that ends in error or malformed
        // input needs a reset before another operation can reuse the bus.
        if outcome.is_err() {
            self.runtime.fail();
        }
        outcome
    }
}
