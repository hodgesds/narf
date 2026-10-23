// SPDX-License-Identifier: GPL-2.0-or-later
//! FullMAC single-station commands over the live F2 runtime.
//! References: Linux brcmfmac/{common,cfg80211}.c and fwil_types.h.

use super::{
    events,
    ioctl::{self, Direction},
    runtime::{Error, Runtime},
    PacketTransport,
};
use alloc::{vec, vec::Vec};
use narf_wireless::{AssociateRequest, BssInfo, ScanRequest, SecurityConfig};

#[derive(Debug, Clone)]
pub struct Bss {
    pub info: BssInfo,
    pub ies: Vec<u8>,
}

pub struct Station<T: PacketTransport> {
    pub runtime: Runtime<T>,
    pub mac: [u8; 6],
    pub channels: Vec<u8>,
    domain: narf_wireless::reg::RegulatoryDomain,
    pub bssid: Option<[u8; 6]>,
    pub cache: Vec<Bss>,
    scan_id: u16,
    pub supplicant: bool,
    operation: bool,
}
impl<T: PacketTransport> core::fmt::Debug for Station<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CywStation")
            .field("mac", &self.mac)
            .field("bssid", &self.bssid)
            .finish_non_exhaustive()
    }
}

impl<T: PacketTransport> Station<T> {
    /// Initialize firmware IOCTLs, CLM, regulatory policy and event delivery.
    /// The caller supplies a completed firmware-loader transport and an
    /// authenticated host policy; no interface may be published before success.
    pub async fn initialize(
        mut runtime: Runtime<T>,
        clm: &[u8],
        domain: narf_wireless::reg::RegulatoryDomain,
    ) -> Result<Self, Error> {
        if clm.is_empty()
            || clm.len() > 1024 * 1024
            || !domain.country_code.iter().all(u8::is_ascii_uppercase)
        {
            return Err(Error::Malformed);
        }
        let version = runtime
            .command(Direction::Get, ioctl::WLC_GET_VERSION, &[], 4)
            .await?;
        if version.as_slice() != 2u32.to_le_bytes() {
            return Err(Error::Unsupported);
        }
        for (i, chunk) in clm.chunks(1024).enumerate() {
            let mut payload = vec![0; 12 + chunk.len()];
            let flags = 0x1000u16
                | if i == 0 { 2 } else { 0 }
                | if (i + 1) * 1024 >= clm.len() { 4 } else { 0 };
            payload[..2].copy_from_slice(&flags.to_le_bytes());
            payload[2..4].copy_from_slice(&2u16.to_le_bytes());
            payload[4..8].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
            payload[12..].copy_from_slice(chunk);
            set_var(&mut runtime, "clmload", &payload).await?;
        }
        if get_var(&mut runtime, "clmload_status", 4).await?.as_slice() != [0; 4] {
            return Err(Error::Firmware(1));
        }
        let mut country = [0; 12];
        country[..2].copy_from_slice(&domain.country_code);
        country[8..10].copy_from_slice(&domain.country_code);
        set_var(&mut runtime, "country", &country).await?;
        set_var(&mut runtime, "bus:txglom", &0u32.to_le_bytes()).await?;
        // A single-packet host adapter never consumes an unnegotiated superframe.
        set_var(&mut runtime, "bus:rxglom", &0u32.to_le_bytes()).await?;
        set_int(&mut runtime, 86, 0).await?; // WLC_SET_PM: continuously awake.
        set_int(&mut runtime, 20, 1).await?; // Infrastructure station.
        set_int(&mut runtime, 22, 0).await?; // Open-system 802.11 authentication.
                                             // This profile pins the selected BSSID and does not consume ROAM
                                             // events. Firmware must not silently move the authorized peer.
        set_var(&mut runtime, "roam_off", &1u32.to_le_bytes()).await?;
        let address = get_var(&mut runtime, "cur_etheraddr", 6).await?;
        let mac: [u8; 6] = address.try_into().map_err(|_| Error::Malformed)?;
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(Error::Malformed);
        }
        let mut mask = [0; 16];
        for event in [0, 3, 5, 6, 7, 11, 12, 16, 46, 69] {
            mask[event / 8] |= 1 << (event % 8);
        }
        set_var(&mut runtime, "event_msgs", &mask).await?;
        let supplicant = match get_var(&mut runtime, "sup_wpa", 4).await {
            Ok(bytes) => bytes.len() == 4,
            Err(Error::Firmware(code)) if code as i32 == -23 => false,
            Err(error) => return Err(error),
        };
        set_int(&mut runtime, ioctl::WLC_UP, 0).await?;
        let reply = runtime
            .command(Direction::Get, 217, &64u32.to_le_bytes(), 260)
            .await?;
        let count = le32(&reply, 0)? as usize;
        if count > 64 || reply.len() < 4 + count * 4 {
            return Err(Error::Malformed);
        }
        let mut channels = Vec::new();
        for index in 0..count {
            let channel = le32(&reply, 4 + index * 4)?;
            if (1..=14).contains(&channel)
                && channel_power(&domain, channel as u8).is_some()
                && !channels.contains(&(channel as u8))
            {
                channels.push(channel as u8);
            }
        }
        if channels.is_empty() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            runtime,
            mac,
            channels,
            domain,
            bssid: None,
            cache: Vec::new(),
            scan_id: 0,
            supplicant,
            operation: false,
        })
    }

    pub async fn scan(&mut self, request: ScanRequest) -> Result<Vec<BssInfo>, Error> {
        if self.operation {
            self.runtime.fail();
            return Err(Error::Failed);
        }
        self.operation = true;
        let result = self.scan_inner(request).await;
        self.operation = false;
        result
    }

    async fn scan_inner(&mut self, request: ScanRequest) -> Result<Vec<BssInfo>, Error> {
        if self.bssid.is_some() {
            return Err(Error::Busy);
        }
        if request.random_mac.is_some()
            || request.colocated_6ghz
            || request.duration_tu.is_some()
            || request.duration_mandatory
            || !request.extra_ies.is_empty()
        {
            return Err(Error::Unsupported);
        }
        let mut channels = Vec::new();
        for channel in if !request.frequencies_mhz.is_empty() {
            let mut selected = Vec::new();
            for &frequency in &request.frequencies_mhz {
                let channel = match frequency {
                    2484 => 14,
                    2412..=2472 if (frequency - 2407) % 5 == 0 => (frequency - 2407) / 5,
                    _ => return Err(Error::Unsupported),
                };
                if !request.channels.is_empty() && !request.channels.contains(&channel) {
                    return Err(Error::Malformed);
                }
                selected.push(channel);
            }
            selected
        } else if request.channels.is_empty() {
            self.channels.iter().map(|&ch| u32::from(ch)).collect()
        } else {
            request.channels.clone()
        } {
            let channel = u8::try_from(channel).map_err(|_| Error::Malformed)?;
            if !self.channels.contains(&channel) {
                return Err(Error::Malformed);
            }
            if !channels.contains(&channel) {
                channels.push(channel);
            }
        }
        self.scan_id = self.scan_id.wrapping_add(1);
        let id = self.scan_id;
        let command = scan_command(id, &channels, &request.ssids, request.active)?;
        self.runtime.poll()?;
        while self.runtime.pop_event().is_some() {}
        if request.active {
            let power = channels
                .iter()
                .filter_map(|&ch| channel_power(&self.domain, ch))
                .min()
                .ok_or(Error::Unsupported)?;
            set_var(
                &mut self.runtime,
                "qtxpower",
                &(u32::from(power) * 4).to_le_bytes(),
            )
            .await?;
        }
        self.cache.clear();
        set_var(&mut self.runtime, "escan", &command).await?;
        let deadline = narf_time::Deadline::after_ms(15000);
        let outcome = async {
            loop {
                self.runtime.poll()?;
                while let Some(event) = self.runtime.pop_event() {
                    if event.header.event_type != events::WLC_E_ESCAN_RESULT {
                        continue;
                    }
                    if event.header.status == 8 {
                        // BRCMF_E_STATUS_PARTIAL.
                        let (event_id, bss) = parse_scan_result(&event.payload)?;
                        if event_id != id {
                            continue;
                        }
                        if self.channels.contains(&(bss.info.channel as u8))
                            && (request.ssids.is_empty()
                                || request
                                    .ssids
                                    .iter()
                                    .any(|s| s.is_empty() || *s == bss.info.ssid))
                        {
                            if let Some(old) = self
                                .cache
                                .iter_mut()
                                .find(|b| b.info.bssid == bss.info.bssid)
                            {
                                *old = bss;
                            } else if self.cache.len() < 64 {
                                self.cache.push(bss);
                            }
                        }
                    } else {
                        // Some firmware sends a headerless terminal event, as
                        // Linux's escan handler permits. When it supplies the
                        // escan header, a stale sync ID cannot complete this scan.
                        if !event.payload.is_empty() {
                            let length = le32(&event.payload, 0)? as usize;
                            if length < 12 || length > event.payload.len() {
                                return Err(Error::Malformed);
                            }
                            let event_id = u16::from_le_bytes(
                                event
                                    .payload
                                    .get(8..10)
                                    .ok_or(Error::Malformed)?
                                    .try_into()
                                    .unwrap(),
                            );
                            if event_id != id {
                                continue;
                            }
                        }
                        if event.header.status == 0 {
                            return Ok(self.cache.iter().map(|b| b.info.clone()).collect());
                        }
                        return Err(Error::Firmware(event.header.status));
                    }
                }
                if deadline.expired() {
                    self.runtime.fail();
                    return Err(Error::Timeout);
                }
                wait().await;
            }
        }
        .await;
        // Once firmware accepted escan, any malformed/error outcome needs
        // reset or a confirmed abort. Never let its late completion finish
        // another operation. Cancellation is caught by `operation` on poll.
        if outcome.is_err() {
            self.runtime.fail();
        }
        outcome
    }

    pub async fn associate(&mut self, request: AssociateRequest) -> Result<(), Error> {
        if self.operation {
            self.runtime.fail();
            return Err(Error::Failed);
        }
        self.operation = true;
        let result = self.associate_inner(request).await;
        self.operation = false;
        result
    }

    async fn associate_inner(&mut self, request: AssociateRequest) -> Result<(), Error> {
        if self.bssid.is_some() {
            return Err(Error::Busy);
        }
        if request.ssid.is_empty()
            || request.ssid.len() > 32
            || request.bssid == [0; 6]
            || request.bssid[0] & 1 != 0
        {
            return Err(Error::Malformed);
        }
        let bss = self
            .cache
            .iter()
            .find(|b| {
                b.info.bssid == request.bssid
                    && b.info.ssid == request.ssid
                    && b.info.channel == request.channel
                    && b.info.frequency_mhz == request.frequency_mhz
            })
            .ok_or(Error::Malformed)?
            .clone();
        let power =
            channel_power(&self.domain, bss.info.channel as u8).ok_or(Error::Unsupported)?;
        let secure = match &request.security {
            SecurityConfig::Open
                if matches!(bss.info.security, narf_wireless::scan::BssSecurity::Open) =>
            {
                false
            }
            SecurityConfig::Wpa2 { .. } if self.supplicant => {
                let rsn = rsn(&bss.ies).ok_or(Error::Unsupported)?;
                use narf_wireless::rsn::*;
                let ccmp = Suite::standard(CIPHER_CCMP_128);
                if rsn.group_cipher != ccmp
                    || !rsn.pairwise_ciphers.contains(&ccmp)
                    || !rsn.akms.contains(&Suite::standard(AKM_PSK))
                    || rsn.rsn_capabilities & RSN_CAP_MFP_REQUIRED != 0
                {
                    return Err(Error::Unsupported);
                }
                true
            }
            _ => return Err(Error::Unsupported),
        };
        validate_association_ies(&request.ie, secure)?;
        set_var(
            &mut self.runtime,
            "qtxpower",
            &(u32::from(power) * 4).to_le_bytes(),
        )
        .await?;
        self.runtime.poll()?;
        while self.runtime.pop_event().is_some() {}
        let result = async {
            set_int(&mut self.runtime, 22, 0).await?;
            // Linux configures (and clears for Open) the association RSNE
            // before joining. Pin the firmware offload to this driver's
            // single PSK/CCMP, no-PMF profile even on a mixed-mode AP.
            let mut wpa_ie = Vec::new();
            if secure {
                let body = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
                wpa_ie.extend_from_slice(&[48, body.len() as u8]);
                wpa_ie.extend_from_slice(&body);
            }
            set_var(&mut self.runtime, "wpaie", &wpa_ie).await?;
            set_var(
                &mut self.runtime,
                "wpa_auth",
                &if secure { 128u32 } else { 0 }.to_le_bytes(),
            )
            .await?;
            set_int(&mut self.runtime, 134, if secure { 4 } else { 0 }).await?;
            if self.supplicant {
                set_var(
                    &mut self.runtime,
                    "sup_wpa",
                    &u32::from(secure).to_le_bytes(),
                )
                .await?;
            }
            if let SecurityConfig::Wpa2 { psk } = &request.security {
                // CYW legacy wsec_pmk: length/flags + 64-byte key buffer.
                let mut pmk = zeroize::Zeroizing::new([0; 68]);
                pmk[..2].copy_from_slice(&32u16.to_le_bytes());
                pmk[4..36].copy_from_slice(psk);
                self.runtime
                    .command(Direction::Set, 268, &pmk[..], MAX_REPLY)
                    .await?;
            }
            let mut join = [0; 50];
            join[..4].copy_from_slice(&(request.ssid.len() as u32).to_le_bytes());
            join[4..4 + request.ssid.len()].copy_from_slice(&request.ssid);
            join[36..42].copy_from_slice(&request.bssid);
            join[44..48].copy_from_slice(&1u32.to_le_bytes());
            join[48..50].copy_from_slice(&(0x1000 | request.channel as u16).to_le_bytes());
            self.runtime
                .command(Direction::Set, 26, &join, MAX_REPLY)
                .await?;
            let deadline = narf_time::Deadline::after_ms(15000);
            let (mut associated, mut keys) = (false, !secure);
            loop {
                self.runtime.poll()?;
                while let Some(event) = self.runtime.pop_event() {
                    if event.header.source_mac != request.bssid {
                        continue;
                    }
                    match event.header.event_type {
                        events::WLC_E_LINK => {
                            if event.header.flags & 1 == 0 || event.header.status != 0 {
                                return Err(Error::Firmware(event.header.reason));
                            }
                        }
                        events::WLC_E_PSK_SUP => {
                            if event.header.status != 6 {
                                return Err(Error::Firmware(event.header.status));
                            }
                            keys = true; // BRCMF_E_STATUS_FWSUP_COMPLETED.
                        }
                        events::WLC_E_DEAUTH
                        | events::WLC_E_DEAUTH_IND
                        | events::WLC_E_DISASSOC
                        | events::WLC_E_DISASSOC_IND => {
                            return Err(Error::Firmware(event.header.reason))
                        }
                        events::WLC_E_SET_SSID => {
                            if event.header.status != 0 {
                                return Err(Error::Firmware(event.header.status));
                            }
                            associated = true;
                        }
                        _ => {}
                    }
                }
                if associated && keys {
                    self.bssid = Some(request.bssid);
                    // No packets captured before authorization reach the stack.
                    while self.runtime.pop_data().is_some() {}
                    return Ok(());
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                wait().await;
            }
        }
        .await;
        if result.is_err() {
            self.bssid = None;
            // SET_SSID/PSK events carry no join transaction ID. An ACK to
            // DISASSOC does not prove that old authorization events are
            // drained. Until recovery confirms a fresh firmware lifecycle,
            // a failed join may never be retried against the same BSSID.
            self.runtime.fail();
        }
        result
    }

    pub async fn disconnect(&mut self) -> Result<(), Error> {
        if self.operation {
            self.runtime.fail();
            return Err(Error::Failed);
        }
        self.operation = true;
        let result = self.disconnect_inner().await;
        if result.is_err() {
            // A rejected DISASSOC does not establish firmware link-down.
            // Do not reuse old SET_SSID/PSK events for a later attempt.
            self.runtime.fail();
        }
        self.operation = false;
        result
    }

    async fn disconnect_inner(&mut self) -> Result<(), Error> {
        let peer = self.bssid.take();
        self.runtime
            .command(Direction::Set, 52, &[], MAX_REPLY)
            .await?;
        if let Some(peer) = peer {
            let deadline = narf_time::Deadline::after_ms(2000);
            'complete: loop {
                self.runtime.poll()?;
                while let Some(event) = self.runtime.pop_event() {
                    if event.header.source_mac == peer
                        && (matches!(event.header.event_type, 5 | 6 | 11 | 12)
                            || event.header.event_type == 16 && event.header.flags & 1 == 0)
                    {
                        break 'complete;
                    }
                }
                if deadline.expired() {
                    self.runtime.fail();
                    return Err(Error::Timeout);
                }
                wait().await;
            }
        }
        while self.runtime.pop_data().is_some() {}
        Ok(())
    }

    pub fn poll(&mut self) -> Result<(), Error> {
        // Control operations hold the device mutex. Observing this flag in
        // the worker means cancellation happened between completed IOCTLs.
        if self.operation {
            self.runtime.fail();
            self.bssid = None;
            return Err(Error::Failed);
        }
        if let Err(error) = self.runtime.poll() {
            self.bssid = None;
            return Err(error);
        }
        while let Some(event) = self.runtime.pop_event() {
            if let Some(peer) = self.bssid {
                if event.header.source_mac == peer
                    && (matches!(event.header.event_type, 5 | 6 | 11 | 12)
                        || event.header.event_type == 16 && event.header.flags & 1 == 0
                        || event.header.event_type == 46 && event.header.status != 6)
                {
                    self.bssid = None;
                }
            }
        }
        Ok(())
    }
}

const MAX_REPLY: usize = 1502;

/// The firmware offload builds its own association elements. Match the
/// nl80211 PSK-offload contract: validate the requested RSNE, consume a
/// bounded well-formed IE list, and leave firmware-generated capabilities
/// and RSNXE to the firmware. External-key profiles remain unsupported.
fn validate_association_ies(mut ies: &[u8], secure: bool) -> Result<(), Error> {
    use narf_wireless::rsn::*;
    if ies.len() > 2048 {
        return Err(Error::Malformed);
    }
    let mut seen_rsn = false;
    while !ies.is_empty() {
        let header = ies.get(..2).ok_or(Error::Malformed)?;
        let end = 2 + usize::from(header[1]);
        let body = ies.get(2..end).ok_or(Error::Malformed)?;
        if header[0] == 48 {
            if !secure || seen_rsn {
                return Err(Error::Unsupported);
            }
            let rsn = RsnIe::decode_body(body).ok_or(Error::Malformed)?;
            let ccmp = Suite::standard(CIPHER_CCMP_128);
            if rsn.group_cipher != ccmp
                || rsn.pairwise_ciphers != [ccmp]
                || rsn.akms != [Suite::standard(AKM_PSK)]
                || rsn.rsn_capabilities & RSN_CAP_MFP_REQUIRED != 0
                || !rsn.pmkids.is_empty()
            {
                return Err(Error::Unsupported);
            }
            seen_rsn = true;
        } else if header[0] == 244 && !secure {
            return Err(Error::Unsupported);
        }
        ies = &ies[end..];
    }
    Ok(())
}
async fn wait() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
}
async fn set_int<T: PacketTransport>(
    runtime: &mut Runtime<T>,
    command: u32,
    value: u32,
) -> Result<(), Error> {
    runtime
        .command(Direction::Set, command, &value.to_le_bytes(), MAX_REPLY)
        .await
        .map(|_| ())
}
pub(super) async fn set_var<T: PacketTransport>(
    runtime: &mut Runtime<T>,
    name: &str,
    value: &[u8],
) -> Result<(), Error> {
    let mut payload = name.as_bytes().to_vec();
    payload.push(0);
    payload.extend_from_slice(value);
    runtime
        .command(Direction::Set, 263, &payload, MAX_REPLY)
        .await
        .map(|_| ())
}
async fn get_var<T: PacketTransport>(
    runtime: &mut Runtime<T>,
    name: &str,
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut payload = name.as_bytes().to_vec();
    payload.push(0);
    runtime.command(Direction::Get, 262, &payload, length).await
}
fn le32(bytes: &[u8], index: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(index..index + 4)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn channel_power(domain: &narf_wireless::reg::RegulatoryDomain, channel: u8) -> Option<u8> {
    if !(1..=14).contains(&channel) {
        return None;
    }
    let frequency = if channel == 14 {
        2484
    } else {
        2407 + 5 * u32::from(channel)
    };
    domain
        .rules
        .iter()
        .filter(|r| {
            r.freq_start_mhz <= frequency - 10
                && r.freq_end_mhz >= frequency + 10
                && r.max_bandwidth_mhz >= 20
                && !r.flags.contains(narf_wireless::reg::RegFlags::DFS)
        })
        .map(|r| r.max_power_dbm)
        .min()
        .and_then(|power| u8::try_from(power).ok())
}
fn rsn(ies: &[u8]) -> Option<narf_wireless::rsn::RsnIe> {
    let mut rest = ies;
    while rest.len() >= 2 {
        let len = usize::from(rest[1]);
        let body = rest.get(2..2 + len)?;
        if rest[0] == 48 {
            return narf_wireless::rsn::RsnIe::decode_body(body);
        }
        rest = &rest[2 + len..];
    }
    None
}

fn scan_command(
    id: u16,
    channels: &[u8],
    ssids: &[Vec<u8>],
    active: bool,
) -> Result<Vec<u8>, Error> {
    if channels.is_empty()
        || channels.len() > 14
        || ssids.len() > 16
        || ssids.iter().any(|s| s.len() > 32)
    {
        return Err(Error::Malformed);
    }
    let ssid_start = (72 + channels.len() * 2).next_multiple_of(4);
    let mut out = vec![0; ssid_start + ssids.len() * 36];
    out[..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&id.to_le_bytes());
    out[44..50].fill(0xff);
    out[50] = 2; // DOT11_BSSTYPE_ANY.
    out[51] = u8::from(!active);
    out[52..68].fill(0xff); // firmware default dwell/probe values.
    out[68..72]
        .copy_from_slice(&((ssids.len() as u32) << 16 | channels.len() as u32).to_le_bytes());
    for (i, &ch) in channels.iter().enumerate() {
        if !(1..=14).contains(&ch) {
            return Err(Error::Malformed);
        }
        out[72 + i * 2..74 + i * 2].copy_from_slice(&(0x1000u16 | u16::from(ch)).to_le_bytes());
    }
    for (i, ssid) in ssids.iter().enumerate() {
        let index = ssid_start + i * 36;
        out[index..index + 4].copy_from_slice(&(ssid.len() as u32).to_le_bytes());
        out[index + 4..index + 4 + ssid.len()].copy_from_slice(ssid);
    }
    Ok(out)
}

fn parse_scan_result(bytes: &[u8]) -> Result<(u16, Bss), Error> {
    if bytes.len() < 12 + 128
        || le32(bytes, 0)? as usize > bytes.len()
        || u16::from_le_bytes(bytes[10..12].try_into().unwrap()) != 1
    {
        return Err(Error::Malformed);
    }
    let id = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let b = &bytes[12..];
    let length = le32(b, 4)? as usize;
    if le32(b, 0)? != 109 || length < 128 || length > b.len() {
        return Err(Error::Malformed);
    }
    let b = &b[..length];
    let ssid_len = usize::from(b[18]);
    let offset = usize::from(u16::from_le_bytes(b[116..118].try_into().unwrap()));
    let ie_len = le32(b, 120)? as usize;
    if ssid_len > 32 || offset < 128 || ie_len > 2048 || b[8] & 1 != 0 || b[8..14] == [0; 6] {
        return Err(Error::Malformed);
    }
    let ies = b
        .get(offset..offset.checked_add(ie_len).ok_or(Error::Malformed)?)
        .ok_or(Error::Malformed)?;
    // Verify every IE before preserving an AP's original bytes.
    let mut rest = ies;
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1).ok_or(Error::Malformed)?);
        rest = rest.get(2 + len..).ok_or(Error::Malformed)?;
    }
    let chanspec = u16::from_le_bytes(b[72..74].try_into().unwrap());
    // Legacy APs can leave ctl_ch zero. Never use a wide center as primary.
    let channel = if b[88] != 0 {
        b[88]
    } else if chanspec & 0xff00 == 0x1000 {
        chanspec as u8
    } else {
        return Err(Error::Unsupported);
    };
    if !(1..=14).contains(&channel) {
        return Err(Error::Unsupported);
    }
    let capability = u16::from_le_bytes(b[16..18].try_into().unwrap());
    let security = if rsn(ies).is_some() {
        narf_wireless::scan::BssSecurity::Wpa2
    } else if capability & 16 != 0 {
        narf_wireless::scan::BssSecurity::Wep
    } else {
        narf_wireless::scan::BssSecurity::Open
    };
    Ok((
        id,
        Bss {
            info: BssInfo {
                bssid: b[8..14].try_into().unwrap(),
                ssid: b[19..19 + ssid_len].to_vec(),
                frequency_mhz: if channel == 14 {
                    2484
                } else {
                    2407 + 5 * u32::from(channel)
                },
                channel: u32::from(channel),
                rssi: i16::from_le_bytes(b[78..80].try_into().unwrap()).clamp(-128, 0) as i8,
                security,
            },
            ies: ies.to_vec(),
        },
    ))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_tests.rs"]
pub(in crate::cyw43439) mod tests;
