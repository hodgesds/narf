// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-channel software dwell over retained physical owners. The display
//! cache owns metadata only; joining always consumes the current RX owner.
use super::*;
const MAX_BSS: usize = 32;
const CACHE_MS: u64 = 10_000;

/// One scan may replace the physical owner at each channel. Cancellation
/// closes only the last exact full-coexistence owner this scan captured.
struct CoexScanAttempt<
    'a,
    I: Port<Buffer = M> + 'static,
    M: Memory + 'static,
    E: Environment + 'static,
> {
    device: &'a Device<I, M, E>,
    owner: Option<Arc<AtomicBool>>,
    park: Option<super::super::prepare::packet::TerminalPark>,
    generation: u64,
    armed: bool,
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static>
    CoexScanAttempt<'_, I, M, E>
{
    fn capture(&mut self, owner: &Prepared<I, M>) {
        if owner.station_full_coex() {
            self.owner = Some(owner.station_cancellation());
            self.park = owner.ae_coex_terminal_park();
            self.generation = self.device.lifecycle.generation();
            self.armed = true;
        }
    }
}
impl<I: Port<Buffer = M> + 'static, M: Memory + 'static, E: Environment + 'static> Drop
    for CoexScanAttempt<'_, I, M, E>
{
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(owner) = &self.owner {
            owner.store(true, Ordering::Release);
        }
        // Generation advancement uses this same gate. A stale callback
        // must never park physical PCI after a new owner has been admitted.
        let publication = self.device.admission.publication.lock();
        if self.device.lifecycle.generation() == self.generation {
            self.device.admission.abort.store(true, Ordering::Release);
            self.device.admission.closed.store(true, Ordering::Release);
            if let Some(park) = &self.park {
                let _ = park.park();
            }
            self.device.commit_close(publication);
        }
    }
}

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
            frequency_mhz: crate::rtlwifi::rtl8821ae::envelope::station_frequency_mhz(
                candidate.bss.channel,
            )
            .unwrap_or(0),
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
    /// 2.4 GHz 1-11, then the RTL8821AE 5 GHz plan; each channel is listed
    /// only when the profile's `allow_channel` admits it (88EE refuses every
    /// 5 GHz channel; DFS/NO_IR rules refuse the `NAPC` permission, so such
    /// channels are neither listed nor scanned).
    pub(super) fn available_channels(&self) -> Vec<u32> {
        let coex_channel = self.coex_channel.load(Ordering::Acquire);
        (1..=11)
            .chain(crate::rtlwifi::rtl8821ae::envelope::CHANNELS_5G)
            .filter(|&channel| {
                (coex_channel == 0 || channel == coex_channel)
                    && self
                        .environment
                        .allow_channel(&self.factory, channel)
                        .is_ok()
            })
            .map(u32::from)
            .collect()
    }
    async fn select_scan_channel(&self, channel: u8) -> Result<(), WirelessError> {
        let coex_channel = self.coex_channel.load(Ordering::Acquire);
        if coex_channel != 0 && channel != coex_channel {
            return Err(WirelessError::NotSupported);
        }
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
    async fn select_coex_scan_channel(
        &self,
        channel: u8,
        attempt: &mut CoexScanAttempt<'_, I, M, E>,
    ) -> Result<(), WirelessError> {
        self.select_scan_channel(channel).await?;
        if !attempt.armed {
            return Ok(());
        }
        // A completed driver-owned transition has released its owner lock.
        // Capture before the next await, including the wait for control.
        let storage = self.prepared.try_lock().ok_or(WirelessError::Busy)?;
        if self.lifecycle.rebuilding.load(Ordering::Acquire)
            || self.lifecycle.channel.load(Ordering::Acquire) != channel
        {
            return Err(WirelessError::Busy);
        }
        if let Some(owner) = storage.as_ref() {
            attempt.capture(owner);
        }
        Ok(())
    }
    pub(super) async fn scan_channels(
        &self,
        request: ScanRequest,
    ) -> Result<Vec<BssInfo>, WirelessError> {
        let dwell = scan_dwell(&request)?;
        let mut channels = requested_channels(&request)?;
        let explicit = !channels.is_empty();
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
        let coex_channel = self.coex_channel.load(Ordering::Acquire);
        if coex_channel != 0 && channels.iter().any(|&channel| channel != coex_channel) {
            return Err(WirelessError::NotSupported);
        }
        // Reject the entire explicit plan before the first retune or probe.
        for &channel in &channels {
            self.environment
                .allow_channel(&self.factory, channel)
                .map_err(error)?;
        }
        let _scan = self.scan_request.lock().await;
        let mut attempt = CoexScanAttempt {
            device: self,
            owner: None,
            park: None,
            generation: self.lifecycle.generation(),
            armed: false,
        };
        // Initial ready may discover the first full N21C program. Resolve
        // its fixed operating point before declaring scan-start, so the
        // default NAPC channel list cannot trigger an unqualified retune.
        {
            let mut storage = self.prepared.lock().await;
            if let Some(owner) = storage
                .as_mut()
                .filter(|owner| owner.chip() == super::super::prepare::Chip::Rtl8821ae)
            {
                self.ready(owner).await.map_err(error)?;
            }
        }
        let coex_channel = self.coex_channel.load(Ordering::Acquire);
        if coex_channel != 0 {
            if explicit && channels.iter().any(|&channel| channel != coex_channel) {
                return Err(WirelessError::NotSupported);
            }
            channels.retain(|&channel| channel == coex_channel);
        }
        self.scan_cache.lock().clear();
        // `btc_scan_notify(1)` (`core.c::rtl_op_sw_scan_start`): the scan
        // runs on the live owner, so the coexistence algorithm can yield
        // the antenna. The (0) notify runs at the successful end below; a
        // failed scan aborts and closes the owner, leaving no live coex
        // owner to notify.
        self.coex_scan_notify(true, &mut attempt)
            .await
            .map_err(error)?;
        let home = self.lifecycle.channel.load(Ordering::Acquire);
        let multiple = channels.len() > 1;
        let mut observations: Vec<Observation> = Vec::new();
        for channel in channels {
            for candidate in self
                .scan_one(&request, channel, dwell, &mut attempt)
                .await?
            {
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
            self.select_coex_scan_channel(home, &mut attempt).await?;
        }
        let now = self.environment.now_ms();
        observations.retain(|entry| entry.current(now));
        let result = observations.iter().map(Observation::info).collect();
        *self.scan_cache.lock() = observations;
        self.coex_scan_notify(false, &mut attempt)
            .await
            .map_err(error)?;
        attempt.armed = false;
        Ok(result)
    }
    /// `btc_scan_notify` for the RTL8723BE owner, if one is live
    /// (`ready()` is the scan's own admission step, already run per channel
    /// by `scan_one`; running it here too is a no-op on a live owner). Any
    /// other chip, or no owner, is a no-op.
    async fn coex_scan_notify(
        &self,
        start: bool,
        attempt: &mut CoexScanAttempt<'_, I, M, E>,
    ) -> Result<(), Error> {
        let mut storage = self.prepared.lock().await;
        let Some(owner) = storage.as_mut() else {
            return Ok(());
        };
        if !matches!(
            owner.chip(),
            super::super::prepare::Chip::Rtl8723be | super::super::prepare::Chip::Rtl8821ae
        ) {
            return Ok(());
        }
        self.ready(owner).await?;
        if owner.station_full_coex() {
            attempt.capture(owner);
            if !start {
                let now = self.environment.now_ms();
                let count = {
                    self.scan_cache
                        .lock()
                        .iter()
                        .filter(|entry| entry.current(now))
                        .count()
                        .min(255) as u8
                };
                owner.station_8821_scan_count(count)?;
            }
            owner
                .station_8821_notify(
                    super::super::rtl8821ae::coex_runtime::Notify::Scan(start),
                    &self.environment,
                )
                .await
        } else if owner.chip() == super::super::prepare::Chip::Rtl8723be {
            owner
                .be_tracking_notify(station::BeTrackingNotice::Scan(start), &self.environment)
                .await
        } else {
            Ok(())
        }
    }
    async fn scan_one(
        &self,
        request: &ScanRequest,
        channel: u8,
        dwell: u64,
        scan: &mut CoexScanAttempt<'_, I, M, E>,
    ) -> Result<Vec<station::Candidate>, WirelessError> {
        self.select_coex_scan_channel(channel, scan).await?;
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
        scan.capture(owner);
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
            if owner.station_full_coex() && !owner.station_8821_scanning() {
                owner
                    .station_8821_notify(
                        super::super::rtl8821ae::coex_runtime::Notify::Scan(true),
                        &self.environment,
                    )
                    .await?;
            }
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
                owner.station_coex_service(&self.environment).await?;
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
        let coex_channel = self.coex_channel.load(Ordering::Acquire);
        if coex_channel != 0 && channel != coex_channel {
            return Err(WirelessError::NotSupported);
        }
        if crate::rtlwifi::rtl8821ae::envelope::station_frequency_mhz(channel)
            != Some(request.frequency_mhz)
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
        let channel = crate::rtlwifi::rtl8821ae::envelope::station_channel_at(frequency)
            .ok_or(WirelessError::NotSupported)?;
        if !frequencies.contains(&channel) {
            frequencies.push(channel);
        }
    }
    let mut channels = Vec::new();
    for &raw in &request.channels {
        let channel = u8::try_from(raw).map_err(|_| WirelessError::NotSupported)?;
        if !crate::rtlwifi::rtl8821ae::envelope::station_channel(channel) {
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
