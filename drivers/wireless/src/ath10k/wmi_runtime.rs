// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained ath10k WMI vdev/passive-scan owner over the real HTC/HTT runtime.
//! Creating a scan vdev does not authorize station traffic or a controlled port.
use crate::ath10k::{
    control::Hif,
    htt_runtime::{self as htt, HttMemory},
    wmi_boot::{self, Dialect, HostMemory},
};
use alloc::{collections::VecDeque, vec::Vec};
#[path = "wmi_runtime/management.rs"]
pub(super) mod management;
#[path = "wmi_runtime/wire.rs"]
mod wire;
pub use management::{
    Completion as ManagementCompletion, Receipt as ManagementReceipt, Token as ManagementToken,
};
mod active_scan;
mod data;
mod mlme;
pub use data::Link as StationLink;
pub use mlme::Associated as StationAssociated;
pub use station::Disconnected as StationDisconnected;
pub(in crate::ath10k) use wire::validate_probe_ies;
pub(crate) use wire::{MAX_SCAN_IE_LEN, MAX_SCAN_SSIDS};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Htt(htt::Error),
    Wmi(wmi_boot::Error),
    Malformed,
    Failed,
    NoMemory,
    Unsupported,
    Timeout,
    Exhausted,
    Firmware(u32),
}
impl From<htt::Error> for Error {
    fn from(e: htt::Error) -> Self {
        Self::Htt(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ScanEvent {
    kind: u32,
    reason: u32,
    frequency: u32,
    request: u32,
    sequence: u32,
    vdev: u32,
}
#[derive(Debug)]
pub(super) struct Management {
    pub channel: u32,
    pub snr: u32,
    pub status: u32,
    pub frame: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct ScanBss {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub frequency: u16,
    pub snr: u32,
    pub capability: u16,
    pub beacon_interval: u16,
    pub information_elements: Vec<u8>,
}
#[derive(Debug)]
pub struct ScanReport {
    pub bss: Vec<ScanBss>,
    pub received: u32,
    pub ignored: u32,
    pub truncated: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanReady {
    pub mac: [u8; 6],
    pub channels: u8,
}
#[derive(Debug)]
pub(super) struct Radio<T> {
    scan_cache: Vec<ScanBss>,
    management_done: VecDeque<ManagementCompletion>,
    peer: Option<station::Peer>,
    data: Option<data::State>,
    pub htt: htt::Runtime<T>,
    wire: wire::Wire,
    features: u64,
    pub ready: Option<ScanReady>,
    channels: Vec<u16>,
    sequence: u16,
    pending: VecDeque<htt::Event>,
    failed: bool,
}
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub fn information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.scan_cache
            .iter()
            .find(|b| b.bssid == bssid)
            .map(|b| b.information_elements.clone())
    }
    pub fn new(htt: htt::Runtime<T>, dialect: Dialect, features: u64) -> Self {
        Self {
            htt,
            wire: wire::Wire::new(dialect),
            features,
            ready: None,
            scan_cache: Vec::new(),
            management_done: VecDeque::new(),
            peer: None,
            data: None,
            channels: Vec::new(),
            sequence: 0,
            pending: VecDeque::new(),
            failed: false,
        }
    }
    /// No country policy is inferred here: these are receive-only IEEE
    /// channels intersected with the target's actual SERVICE_READY limits.
    pub async fn start_from_hardware(&mut self) -> Result<ScanReady, Error> {
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        let mut channels = Vec::new();
        channels
            .try_reserve_exact(64)
            .map_err(|_| Error::NoMemory)?;
        for frequency in (2412..=2472)
            .step_by(5)
            .chain(core::iter::once(2484))
            .chain((5180..=5320).step_by(20))
            .chain((5500..=5720).step_by(20))
            .chain((5745..=5825).step_by(20))
        {
            if wire::supported(caps, frequency) {
                channels.push(frequency);
            }
        }
        self.start(&channels).await
    }
    pub async fn start(&mut self, channels: &[u16]) -> Result<ScanReady, Error> {
        if self.failed || self.ready.is_some() || self.htt.ready.is_none() {
            return Err(Error::Failed);
        }
        wire::validate_channels(channels)?;
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        if channels.iter().any(|f| !wire::supported(caps, *f)) {
            return Err(Error::Unsupported);
        }
        let mac = self.htt.wmi.ready.ok_or(Error::Failed)?.mac;
        let create = self.wire.create(mac)?;
        let configured = self.wire.channels(channels)?;
        self.channels
            .try_reserve_exact(channels.len())
            .map_err(|_| Error::NoMemory)?;
        // No await can expose a reusable vdev/command owner after an
        // ambiguous publication. DMA remains in the nested mission owner.
        self.failed = true;
        self.htt
            .wmi
            .htc
            .send_wmi(&create)
            .await
            .map_err(htt::Error::from)?;
        self.htt
            .wmi
            .htc
            .send_wmi(&configured)
            .await
            .map_err(htt::Error::from)?;
        self.channels.extend_from_slice(channels);
        let ready = ScanReady {
            mac,
            channels: channels.len() as u8,
        };
        self.ready = Some(ready);
        self.failed = false;
        Ok(ready)
    }
    /// Scan IDs never wrap within this firmware owner's lifetime. A timeout,
    /// failed scan or dropped future leaves the owner closed until reset.
    pub async fn passive_scan(&mut self, channels: &[u16]) -> Result<ScanReport, Error> {
        self.scan_run(channels, (&[], &[]), &[], None, || Ok(()))
            .await
    }
    async fn scan_run(
        &mut self,
        channels: &[u16],
        probes: (&[Vec<u8>], &[u8]),
        setup: &[Vec<u8>],
        restore: Option<&[u8]>,
        validate: impl Fn() -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        if self.failed || self.ready.is_none() || self.peer.is_some() {
            return Err(Error::Failed);
        }
        wire::validate_channels(channels)?;
        if channels.iter().any(|f| !self.channels.contains(f)) {
            return Err(Error::Unsupported);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n <= 4095)
            .ok_or(Error::Exhausted)?;
        let (ssids, extra_ies) = probes;
        let command = if ssids.is_empty() {
            self.wire.scan(sequence, channels)?
        } else {
            self.wire
                .active_scan(sequence, channels, ssids, extra_ies)?
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
        self.failed = true;
        for packet in setup
            .iter()
            .map(Vec::as_slice)
            .chain(core::iter::once(command.as_slice()))
        {
            active_scan::checked(
                async {
                    self.htt
                        .wmi
                        .htc
                        .send_wmi(packet)
                        .await
                        .map_err(htt::Error::from)
                        .map_err(Error::from)
                },
                &validate,
            )
            .await?;
        }
        let deadline = narf_time::Deadline::after_ms(25_000);
        for _ in 0..65_536 {
            narf_scheduler::yield_now().await;
            validate()?;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            match active_scan::checked(
                async { self.htt.poll().await.map_err(Error::from) },
                &validate,
            )
            .await?
            {
                htt::Event::Wmi(bytes) => {
                    let id = wire::word(&bytes, 0)? & 0xffffff;
                    if id == self.wire.scan_event {
                        let event = self.wire.scan_event(&bytes[4..])?;
                        if event.sequence != 0xa000 | u32::from(sequence)
                            || event.request != 0xa001
                            || event.vdev != 0
                        {
                            report.ignored = report.ignored.saturating_add(1);
                            continue;
                        }
                        match event.kind {
                            2 if event.reason == 0 => {
                                if let Some(packet) = restore {
                                    active_scan::checked(
                                        async {
                                            self.htt
                                                .wmi
                                                .htc
                                                .send_wmi(packet)
                                                .await
                                                .map_err(htt::Error::from)
                                                .map_err(Error::from)
                                        },
                                        &validate,
                                    )
                                    .await?;
                                }
                                validate()?;
                                let mut cache = Vec::new();
                                cache
                                    .try_reserve_exact(report.bss.len())
                                    .map_err(|_| Error::NoMemory)?;
                                for bss in &report.bss {
                                    cache.push(bss.copy_owned()?);
                                }
                                self.scan_cache = cache;
                                self.failed = false;
                                return Ok(report);
                            }
                            2 | 64 => return Err(Error::Firmware(event.reason)),
                            _ => {}
                        }
                    } else if id == self.wire.management_event {
                        let management = self.wire.management(&bytes[4..], self.features)?;
                        report.received = report.received.saturating_add(1);
                        if let Some(bss) = beacon(&management, channels)? {
                            if let Some(previous) = report
                                .bss
                                .iter_mut()
                                .find(|b| b.bssid == bss.bssid && b.frequency == bss.frequency)
                            {
                                *previous = bss;
                            } else if report.bss.len() < 64 {
                                report.bss.push(bss);
                            } else {
                                report.truncated = true;
                            }
                        } else {
                            report.ignored = report.ignored.saturating_add(1);
                        }
                    } else {
                        self.queue(htt::Event::Wmi(bytes))?;
                    }
                }
                htt::Event::Idle | htt::Event::Progress => narf_scheduler::yield_now().await,
                // Keep peer/BA/packet events for the future station worker.
                // No event can raise a link or open the controlled port here.
                event => self.queue(event)?,
            }
        }
        Err(Error::Timeout)
    }
    fn queue(&mut self, event: htt::Event) -> Result<(), Error> {
        if self.pending.len() == 64 {
            return Err(Error::Malformed);
        }
        self.pending.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.pending.push_back(event);
        Ok(())
    }
    pub fn take_event(&mut self) -> Option<htt::Event> {
        self.pending.pop_front()
    }
}
fn beacon(event: &Management, channels: &[u16]) -> Result<Option<ScanBss>, Error> {
    if event.status & !0x40 != 0 {
        return Ok(None);
    }
    let Some(frequency) = wire::channel_to_frequency(event.channel) else {
        return Ok(None);
    };
    if !channels.contains(&frequency) {
        return Ok(None);
    }
    let frame = &event.frame;
    let Some(fixed) = frame.get(..36) else {
        return Ok(None);
    };
    let fc = u16::from_le_bytes([fixed[0], fixed[1]]);
    if !matches!(fc & 0x00ff, 0x0080 | 0x0050)
        || fc & 0xc700 != 0
        || fixed[22] & 15 != 0
        || fixed[16] & 1 != 0
        || fixed[16..22] == [0; 6]
        || fixed[10..16] != fixed[16..22]
    {
        return Ok(None);
    }
    let capability = u16::from_le_bytes([fixed[34], fixed[35]]);
    if capability & 3 != 1 {
        return Ok(None);
    }
    let mut ssid = None;
    let mut ds = None;
    let mut ht = None;
    let mut ies = &frame[36..];
    while !ies.is_empty() {
        let Some(header) = ies.get(..2) else {
            return Ok(None);
        };
        let length = usize::from(header[1]);
        let Some(body) = ies.get(2..2 + length) else {
            return Ok(None);
        };
        match header[0] {
            0 => {
                if length > 32 || ssid.replace(body).is_some() {
                    return Ok(None);
                }
            }
            3 => {
                if length != 1 || ds.replace(body[0]).is_some() {
                    return Ok(None);
                }
            }
            61 => {
                if length != 22 || ht.replace(body[0]).is_some() {
                    return Ok(None);
                }
            }
            _ => {}
        }
        ies = &ies[2 + length..];
    }
    if ds.is_some_and(|c| u32::from(c) != event.channel)
        || ht.is_some_and(|c| u32::from(c) != event.channel)
    {
        return Ok(None);
    }
    let Some(ssid) = ssid else {
        return Ok(None);
    };
    Ok(Some(ScanBss {
        bssid: fixed[16..22].try_into().unwrap(),
        ssid: wire::owned(ssid)?,
        frequency,
        snr: event.snr,
        capability,
        beacon_interval: u16::from_le_bytes([fixed[32], fixed[33]]),
        information_elements: wire::owned(&frame[36..])?,
    }))
}

impl ScanBss {
    fn copy_owned(&self) -> Result<Self, Error> {
        Ok(Self {
            bssid: self.bssid,
            ssid: wire::owned(&self.ssid)?,
            frequency: self.frequency,
            snr: self.snr,
            capability: self.capability,
            beacon_interval: self.beacon_interval,
            information_elements: wire::owned(&self.information_elements)?,
        })
    }
}
#[path = "wmi_runtime/station.rs"]
mod station;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerPrepared {
    pub bssid: [u8; 6],
    pub frequency: u16,
    /// Sparse firmware ID, not an index bounded by resource peer count.
    pub peer_id: u16,
    pub maximum_power_dbm: u8,
}
