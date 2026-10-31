// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-channel software dwell over retained physical owners. The display
//! cache owns metadata only; joining always consumes the current RX owner.
use super::*;
const MAX_BSS: usize = 32;
const CACHE_MS: u64 = 10_000;
pub(super) struct Observation {
    pub(super) candidate: station::Candidate,
    seen: u64,
}
impl Observation {
    fn current(&self, now: u64) -> bool {
        now >= self.seen && now - self.seen < CACHE_MS
    }
    fn info(&self) -> BssInfo {
        let candidate = &self.candidate;
        BssInfo {
            bssid: candidate.bss.bssid,
            ssid: candidate.bss.ssid.clone(),
            channel: u32::from(candidate.bss.channel),
            frequency_mhz: 2407 + u32::from(candidate.bss.channel) * 5,
            rssi: i8::MIN,
            security: if candidate.rsne.is_some() {
                narf_wireless::scan::BssSecurity::Wpa2
            } else if candidate.bss.capability & 16 != 0 {
                narf_wireless::scan::BssSecurity::Wep
            } else {
                narf_wireless::scan::BssSecurity::Open
            },
        }
    }
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Device<I, M, E> {
    pub(super) fn scan_ies(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.scan_cache
            .lock()
            .iter()
            .find(|entry| {
                entry.current(self.environment.now_ms()) && entry.candidate.bss.bssid == bssid
            })
            .map(|entry| entry.candidate.bss.information_elements.clone())
    }
    pub(super) fn available_channels(&self) -> Vec<u32> {
        (1..=11)
            .filter(|&channel| {
                self.environment
                    .allow_channel(&self.factory, channel)
                    .is_ok()
            })
            .map(u32::from)
            .collect()
    }
    async fn select_scan_channel(&self, channel: u8) -> Result<(), WirelessError> {
        self.lifecycle
            .activity_ms
            .store(self.environment.now_ms(), Ordering::Release);
        if channel != self.lifecycle.channel.load(Ordering::Acquire) {
            self.environment
                .change_channel(channel)
                .ok_or(WirelessError::NotSupported)?
                .await
                .map_err(error)?;
        } else if self.admission.closed.load(Ordering::Acquire) {
            self.environment
                .recovery()
                .ok_or(WirelessError::HardwareError)?
                .await
                .map_err(error)?;
        }
        Ok(())
    }
    pub(super) async fn scan_channels(
        &self,
        request: ScanRequest,
    ) -> Result<Vec<BssInfo>, WirelessError> {
        let dwell = scan_dwell(&request)?;
        let mut channels = requested_channels(&request)?;
        if channels.is_empty() {
            channels = self
                .available_channels()
                .into_iter()
                .map(|ch| ch as u8)
                .collect();
        }
        if channels.is_empty() {
            return Err(WirelessError::NotSupported);
        }
        // Reject the entire explicit plan before the first retune or probe.
        for &channel in &channels {
            self.environment
                .allow_channel(&self.factory, channel)
                .map_err(error)?;
        }
        let _scan = self.scan_request.lock().await;
        self.scan_cache.lock().clear();
        let home = self.lifecycle.channel.load(Ordering::Acquire);
        let multiple = channels.len() > 1;
        let mut observations: Vec<Observation> = Vec::new();
        for channel in channels {
            for candidate in self.scan_one(&request, channel, dwell).await? {
                let entry = Observation {
                    candidate,
                    seen: self.environment.now_ms(),
                };
                if let Some(old) = observations
                    .iter_mut()
                    .find(|old| old.candidate.bss.bssid == entry.candidate.bss.bssid)
                {
                    *old = entry;
                } else {
                    if observations.len() == MAX_BSS {
                        observations.remove(0);
                    }
                    observations.push(entry);
                }
            }
        }
        // A scan over several channels restores its original operating
        // channel. No old cache is injected into the fresh station owner.
        if multiple {
            self.select_scan_channel(home).await?;
        }
        let now = self.environment.now_ms();
        observations.retain(|entry| entry.current(now));
        let result = observations.iter().map(Observation::info).collect();
        *self.scan_cache.lock() = observations;
        Ok(result)
    }
    async fn scan_one(
        &self,
        request: &ScanRequest,
        channel: u8,
        dwell: u64,
    ) -> Result<Vec<station::Candidate>, WirelessError> {
        self.select_scan_channel(channel).await?;
        let _control = self.lifecycle.control.lock().await;
        if self.lifecycle.channel.load(Ordering::Acquire) != channel {
            return Err(WirelessError::Busy);
        }
        if self.admission.closed.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        let mut storage = self.prepared.lock().await;
        let owner = storage
            .as_mut()
            .ok_or(if self.environment.preparation_failed() {
                WirelessError::HardwareError
            } else {
                WirelessError::Busy
            })?;
        self.ready(owner).await.map_err(error)?;
        if owner.station_phase() != station::Phase::Passive {
            return Err(WirelessError::Busy);
        }
        let mut attempt = Attempt {
            device: self,
            owner: Some(owner.station_cancellation()),
            generation: self.lifecycle.generation(),
            armed: true,
        };
        let result = async {
            if request.active {
                if request.ssids.is_empty() {
                    owner.probe_station(&[], &self.environment).await?;
                }
                for ssid in &request.ssids {
                    owner.probe_station(ssid, &self.environment).await?;
                }
            }
            let deadline = self.environment.now_ms().saturating_add(dwell);
            loop {
                owner.progress_station(&self.environment)?;
                if self.environment.now_ms() >= deadline {
                    break;
                }
                self.environment.pause().await;
            }
            Ok::<_, Error>(
                owner
                    .station_candidates(self.environment.now_ms())
                    .into_iter()
                    .filter(|candidate| {
                        candidate.bss.channel == channel
                            && (request.ssids.is_empty()
                                || request
                                    .ssids
                                    .iter()
                                    .any(|ssid| ssid.is_empty() || *ssid == candidate.bss.ssid))
                    })
                    .collect(),
            )
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            owner.abort_station();
            self.close();
        }
        result.map_err(error)
    }
    /// Called under the ordinary async control and native-owner mutexes.
    /// Display metadata never replaces fresh physical beacon/probe reception.
    pub(super) async fn observe_join_target(
        &self,
        owner: &mut Prepared<I, M>,
        request: &AssociateRequest,
    ) -> Result<(), Error> {
        let matching = |owner: &Prepared<I, M>| {
            owner
                .station_candidates(self.environment.now_ms())
                .iter()
                .any(|candidate| {
                    candidate.bss.bssid == request.bssid
                        && candidate.bss.ssid == request.ssid
                        && u32::from(candidate.bss.channel) == request.channel
                })
        };
        if matching(owner) {
            return Ok(());
        }
        owner
            .probe_station(&request.ssid, &self.environment)
            .await?;
        let deadline = self.environment.now_ms().saturating_add(200);
        loop {
            owner.progress_station(&self.environment)?;
            if matching(owner) {
                return Ok(());
            }
            if self.environment.now_ms() >= deadline {
                return Err(Error::Timeout);
            }
            self.environment.pause().await;
        }
    }
    pub(super) async fn select_join_channel(
        &self,
        request: &AssociateRequest,
    ) -> Result<(), WirelessError> {
        let channel = u8::try_from(request.channel).map_err(|_| WirelessError::NotSupported)?;
        if !(1..=11).contains(&channel)
            || request.frequency_mhz != 2407 + u32::from(channel) * 5
            || request.ssid.len() > 32
        {
            return Err(WirelessError::NotSupported);
        }
        self.environment
            .allow_channel(&self.factory, channel)
            .map_err(error)?;
        self.select_scan_channel(channel).await
    }
}
fn requested_channels(request: &ScanRequest) -> Result<Vec<u8>, WirelessError> {
    let mut frequencies = Vec::new();
    for &frequency in &request.frequencies_mhz {
        if !(2412..=2462).contains(&frequency) || (frequency - 2407) % 5 != 0 {
            return Err(WirelessError::NotSupported);
        }
        let channel = ((frequency - 2407) / 5) as u8;
        if !frequencies.contains(&channel) {
            frequencies.push(channel);
        }
    }
    let mut channels = Vec::new();
    for &raw in &request.channels {
        let channel = u8::try_from(raw).map_err(|_| WirelessError::NotSupported)?;
        if !(1..=11).contains(&channel) {
            return Err(WirelessError::NotSupported);
        }
        if !channels.contains(&channel) {
            channels.push(channel);
        }
    }
    if !frequencies.is_empty() {
        if !channels.is_empty()
            && (channels.len() != frequencies.len()
                || channels
                    .iter()
                    .any(|channel| !frequencies.contains(channel)))
        {
            return Err(WirelessError::InvalidArgs);
        }
        Ok(frequencies)
    } else {
        Ok(channels)
    }
}
