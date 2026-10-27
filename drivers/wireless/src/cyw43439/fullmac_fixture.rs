// SPDX-License-Identifier: GPL-2.0-or-later
//! Scripted native FullMAC firmware for common `Station` feature smokes.
//!
//! It implements the `Fullmac` seam directly, so the production common
//! station (shared by SDIO/BCDC and PCIe/msgbuf) runs unchanged while each
//! smoke answers exact Linux brcmfmac IOCTL/iovar/event literals. Transport
//! framing is covered by the SDPCM/msgbuf fixtures; this fixture models the
//! firmware command/event contract only and claims no RF behaviour.
use super::{
    events::EventHeader,
    fullmac::{Family, FirmwareVendor, Fullmac},
    ioctl::Direction,
    runtime::{Error, Event},
    station::{Bss, Station},
};
use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

pub(crate) const OWN: [u8; 6] = [2, 6, 7, 8, 9, 10];
pub(crate) const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(crate) const AP2: [u8; 6] = [2, 1, 2, 3, 4, 6];

/// One recorded host command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Command {
    pub direction: Direction,
    pub command: u32,
    pub body: Vec<u8>,
}
impl Command {
    /// Iovar name for 262/263, else `None`.
    pub fn iovar(&self) -> Option<&[u8]> {
        if !matches!(self.command, 262 | 263) {
            return None;
        }
        let end = self.body.iter().position(|&b| b == 0)?;
        Some(&self.body[..end])
    }
    /// Iovar value bytes after the NUL-terminated name.
    pub fn value(&self) -> &[u8] {
        match self.iovar() {
            Some(name) => &self.body[name.len() + 1..],
            None => &self.body,
        }
    }
}

/// Per-command test hook: `Some(result)` overrides the default reply.
pub(crate) type Hook =
    Box<dyn FnMut(&mut Firmware, &Command) -> Option<Result<Vec<u8>, Error>> + Send>;

pub(crate) struct Firmware {
    pub log: Vec<Command>,
    pub events: VecDeque<Event>,
    pub data: VecDeque<Vec<u8>>,
    /// Records the next `poll` reports as consumed.
    pub pending: usize,
    pub sent: Vec<(Vec<u8>, u8)>,
    pub caps: Vec<u8>,
    pub supplicant: bool,
    pub mfp_supported: bool,
    pub mfp_mode: u32,
    pub vendor: FirmwareVendor,
    pub link: Option<[u8; 6]>,
    pub failed: bool,
    pub channels: Vec<u32>,
    pub bssid: [u8; 6],
    /// Peer the scripted join completes against (`SET_SSID`).
    pub join_events: bool,
    pub assoc_req_ies: Vec<u8>,
    pub assoc_resp_ies: Vec<u8>,
    pub hook: Option<Hook>,
}
impl Firmware {
    pub fn new() -> Self {
        Self {
            log: Vec::new(),
            events: VecDeque::new(),
            data: VecDeque::new(),
            pending: 0,
            sent: Vec::new(),
            caps: b"ap sta wme 802.11d 802.11h rm cqa cac dualband ampdu ampdu_tx ampdu_rx amsdurx mfp"
                .to_vec(),
            supplicant: true,
            mfp_supported: true,
            mfp_mode: 0,
            vendor: FirmwareVendor::Wcc,
            link: None,
            failed: false,
            channels: vec![1, 6, 11],
            bssid: AP,
            join_events: true,
            assoc_req_ies: Vec::new(),
            assoc_resp_ies: Vec::new(),
            hook: None,
        }
    }
    pub fn event(&mut self, kind: u32, status: u32, flags: u16, source: [u8; 6], payload: &[u8]) {
        self.events.push_back(Event {
            header: EventHeader {
                version: 2,
                flags,
                event_type: kind,
                status,
                reason: 0,
                auth_type: 0,
                datalen: payload.len() as u32,
                source_mac: source,
                if_name: [0; 16],
                if_idx: 0,
                bsscfg_idx: 0,
            },
            payload: payload.to_vec(),
        });
        self.pending += 1;
    }
    /// Commands carrying `name` as an iovar, in order.
    pub fn iovars(&self, direction: Direction, name: &[u8]) -> Vec<Vec<u8>> {
        self.log
            .iter()
            .filter(|c| c.direction == direction && c.iovar() == Some(name))
            .map(|c| c.value().to_vec())
            .collect()
    }
    pub fn commands(&self, command: u32) -> Vec<Vec<u8>> {
        self.log
            .iter()
            .filter(|c| c.command == command && c.direction == Direction::Set)
            .map(|c| c.body.clone())
            .collect()
    }
    fn default_reply(&mut self, command: &Command, maximum: usize) -> Result<Vec<u8>, Error> {
        let unsupported = Err(Error::Firmware((-23i32) as u32));
        match (command.direction, command.command) {
            (Direction::Get, 1) => Ok(2u32.to_le_bytes().to_vec()),
            (Direction::Get, 23) => Ok(self.bssid.to_vec()),
            (Direction::Get, 217) => {
                let mut out = (self.channels.len() as u32).to_le_bytes().to_vec();
                for channel in &self.channels {
                    out.extend_from_slice(&channel.to_le_bytes());
                }
                Ok(out)
            }
            (Direction::Get, 262) => match command.iovar().unwrap_or_default() {
                b"cur_etheraddr" => Ok(OWN.to_vec()),
                b"sup_wpa" if self.supplicant => Ok(1u32.to_le_bytes().to_vec()),
                b"sup_wpa" => unsupported,
                b"mfp" if self.mfp_supported => Ok(self.mfp_mode.to_le_bytes().to_vec()),
                b"mfp" => unsupported,
                b"cap" => {
                    let mut caps = self.caps.clone();
                    caps.resize(maximum, 0);
                    Ok(caps)
                }
                b"nmode" | b"vhtmode" | b"rxchain" => unsupported,
                b"wme_ac_sta" => unsupported,
                b"assoc_info" => {
                    let mut out = (self.assoc_req_ies.len() as u32).to_le_bytes().to_vec();
                    out.extend_from_slice(&(self.assoc_resp_ies.len() as u32).to_le_bytes());
                    Ok(out)
                }
                b"assoc_req_ies" => Ok(self.assoc_req_ies.clone()),
                b"assoc_resp_ies" => Ok(self.assoc_resp_ies.clone()),
                _ => Ok(vec![0; maximum.min(4)]),
            },
            (Direction::Set, 263) => {
                if command.iovar() == Some(b"mfp") {
                    self.mfp_mode = u32::from_le_bytes(
                        command
                            .value()
                            .get(..4)
                            .ok_or(Error::Malformed)?
                            .try_into()
                            .unwrap(),
                    );
                }
                Ok(Vec::new())
            }
            (Direction::Set, 26) if self.join_events => {
                let peer = self.bssid;
                self.event(16, 0, 1, peer, &[]);
                self.event(0, 0, 0, peer, &[]);
                if self.log.iter().any(|c| {
                    c.direction == Direction::Set
                        && c.iovar() == Some(b"sup_wpa")
                        && c.value() == 1u32.to_le_bytes()
                }) {
                    self.event(46, 6, 0, peer, &[]);
                }
                Ok(Vec::new())
            }
            (Direction::Set, 52) => {
                if let Some(peer) = self.link {
                    self.event(16, 0, 0, peer, &[]);
                }
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }
}

/// `Fullmac` adapter; `PCIE` selects the family constant only.
pub(crate) struct Mock<const PCIE: bool> {
    pub fw: Firmware,
}
impl<const PCIE: bool> Mock<PCIE> {
    pub fn new(fw: Firmware) -> Self {
        Self { fw }
    }
}
impl<const PCIE: bool> Fullmac for Mock<PCIE> {
    const FAMILY: Family = if PCIE { Family::Pcie } else { Family::Sdio };
    const EXTERNAL_CLM: bool = !PCIE;
    fn command<'a>(
        &'a mut self,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        let record = Command {
            direction,
            command,
            body: input.to_vec(),
        };
        let fw = &mut self.fw;
        let result = if fw.failed {
            Err(Error::Failed)
        } else {
            fw.log.push(record.clone());
            let hooked = fw.hook.take().map(|mut hook| {
                let out = hook(fw, &record);
                if fw.hook.is_none() {
                    fw.hook = Some(hook);
                }
                out
            });
            match hooked.flatten() {
                Some(result) => result,
                None => fw.default_reply(&record, maximum),
            }
        };
        let result = result.map(|mut reply| {
            if direction == Direction::Set {
                reply.clear();
            } else {
                reply.truncate(maximum);
            }
            reply
        });
        core::future::ready(result)
    }
    async fn configure_bus(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn poll(&mut self) -> Result<usize, Error> {
        if self.fw.failed {
            return Err(Error::Failed);
        }
        Ok(core::mem::take(&mut self.fw.pending))
    }
    fn fail(&mut self) {
        self.fw.failed = true;
        self.fw.link = None;
    }
    fn pop_event(&mut self) -> Option<Event> {
        self.fw.events.pop_front()
    }
    fn pop_data(&mut self) -> Option<Vec<u8>> {
        self.fw.link?;
        self.fw.data.pop_front()
    }
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error> {
        if self.fw.failed || self.fw.link.is_none() {
            return Err(Error::Failed);
        }
        self.fw.sent.push((frame.to_vec(), priority));
        Ok(())
    }
    fn set_link(&mut self, peer: Option<[u8; 6]>) {
        self.fw.link = peer;
    }
    fn firmware_vendor(&self) -> FirmwareVendor {
        self.fw.vendor
    }
}

pub(crate) fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(out) => Some(out),
        Poll::Pending => None,
    }
}

pub(crate) fn domain() -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}

/// Initialize the production common station over the scripted firmware.
pub(crate) fn init_station<const PCIE: bool>(
    fw: Firmware,
) -> Result<Station<Mock<PCIE>>, &'static str> {
    let clm: &[u8] = if PCIE { &[] } else { &[0x5a; 16] };
    ready(Station::initialize(Mock::new(fw), clm, domain()))
        .ok_or("station initialization pended")?
        .map_err(|_| "station initialization failed")
}

/// RSNE: CCMP group/pairwise, one `akm` suite, `caps`, BIP-CMAC when MFPC.
pub(crate) fn rsne(akm: u8, caps: u16) -> Vec<u8> {
    let mut body = vec![
        1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, akm,
    ];
    body.extend_from_slice(&caps.to_le_bytes());
    if caps & 0x80 != 0 {
        body.extend_from_slice(&[0, 0, 0, 15, 172, 6]);
    }
    let mut ie = vec![48, body.len() as u8];
    ie.extend_from_slice(&body);
    ie
}

/// Install one scanned BSS in the station cache (as `scan` would).
pub(crate) fn cache<R: Fullmac>(
    station: &mut Station<R>,
    bssid: [u8; 6],
    channel: u8,
    security: narf_wireless::scan::BssSecurity,
    rsn: &[u8],
) {
    let mut ies = vec![0, 4, b't', b'e', b's', b't'];
    ies.extend_from_slice(rsn);
    station.cache.push(Bss {
        info: narf_wireless::BssInfo {
            bssid,
            ssid: b"test".to_vec(),
            channel: u32::from(channel),
            frequency_mhz: 2407 + 5 * u32::from(channel),
            rssi: -42,
            security,
        },
        ies,
    });
}

pub(crate) fn request(
    bssid: [u8; 6],
    channel: u8,
    security: narf_wireless::SecurityConfig,
    ie: Vec<u8>,
) -> narf_wireless::AssociateRequest {
    narf_wireless::AssociateRequest {
        bssid,
        ssid: b"test".to_vec(),
        frequency_mhz: 2407 + 5 * u32::from(channel),
        channel: u32::from(channel),
        security,
        ie,
    }
}
