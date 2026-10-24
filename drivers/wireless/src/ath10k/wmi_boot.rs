// SPDX-License-Identifier: GPL-2.0-or-later
//! Owned service-ready/host-memory/INIT/READY orchestration for PCI WMI
//! MAIN,10.1,10.2,10.2.4,TLV and10.4. Linux ath10k/wmi{,-tlv}.{c,h}.
//! No station or HTT packet admission follows this initialization.
use super::{
    control::{self, Hif, Session},
    hw::HwRev,
};
use alloc::{collections::VecDeque, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Control(control::Error),
    Malformed,
    Unsupported,
    Abi,
    Firmware(u32),
    NoMemory,
    Memory,
    Failed,
    Timeout,
}
impl From<control::Error> for Error {
    fn from(e: control::Error) -> Self {
        Self::Control(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Dialect {
    Main,
    TenOne,
    TenTwo,
    TenTwoFour,
    Tlv,
    TenFour,
}
impl Dialect {
    pub fn from_version(version: u32) -> Result<Self, Error> {
        Ok(match version {
            1 => Self::Main,
            2 => Self::TenOne,
            3 => Self::TenTwo,
            4 => Self::Tlv,
            5 => Self::TenTwoFour,
            6 => Self::TenFour,
            _ => return Err(Error::Unsupported),
        })
    }
    fn service_event(self) -> u32 {
        if matches!(self, Self::Main | Self::Tlv) {
            1
        } else {
            0x8000
        }
    }
    fn ready_event(self) -> u32 {
        self.service_event() + 1
    }
    fn init_command(self) -> u32 {
        if matches!(self, Self::Main | Self::Tlv) {
            1
        } else {
            0xa000
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MemoryPlan {
    pub id: u32,
    pub bytes: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MemoryChunk {
    pub id: u32,
    pub address: u32,
    pub bytes: u32,
}
/// Returned addresses must already be retained in the physical transport's
/// stop-protected DMA owner; an INIT encoder must never own temporary DMA.
pub(super) trait HostMemory {
    fn retain_wmi_memory(&mut self, plans: &[MemoryPlan]) -> Result<Vec<MemoryChunk>, Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryRequest {
    id: u32,
    unit_size: u32,
    flags: u32,
    units: u32,
}
#[derive(Clone, Debug)]
pub struct Capabilities {
    pub rf_chains: u32,
    pub ht: u32,
    pub vht: u32,
    pub vht_mcs: u32,
    pub eeprom_domain: u32,
    pub low_2ghz: u32,
    pub high_2ghz: u32,
    pub low_5ghz: u32,
    pub high_5ghz: u32,
    pub min_tx_power: i32,
    pub max_tx_power: i32,
    bitmap: Vec<u8>,
}
impl Capabilities {
    /// Firmware uses four low bits per32-bit word for the original map.
    /// Extended TLV services use32 bits; extended legacy services use the
    /// remaining28 bits. Length is bytes, matching Linux's SVCMAP macros.
    pub(super) fn service(&self, dialect: Dialect, id: usize) -> bool {
        let length = self.bitmap.len();
        let (index, bit) = if id < length {
            (id / 4, id % 4)
        } else if dialect == Dialect::Tlv {
            if id >= 256 {
                return false;
            }
            ((id - length) / 32, (id - length) % 32)
        } else {
            ((id - length) / 28, (id - length) % 28 + 4)
        };
        word(&self.bitmap, index * 4).is_ok_and(|v| v & (1 << bit) != 0)
    }
}
#[derive(Debug)]
struct ServiceReady {
    caps: Capabilities,
    requests: Vec<MemoryRequest>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ready {
    pub mac: [u8; 6],
    pub software: u32,
    pub abi: u32,
}
#[derive(Debug)]
struct Resources {
    words: Vec<u32>,
    vdevs: u32,
    peers: u32,
    active_peers: u32,
}
fn owned(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| Error::NoMemory)?;
    v.extend_from_slice(bytes);
    Ok(v)
}
fn word(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn words(values: &[u32]) -> Result<Vec<u32>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(values.len())
        .map_err(|_| Error::NoMemory)?;
    v.extend_from_slice(values);
    Ok(v)
}
/// Iteration uses each advertised extent, with no unchecked cast or
/// speculative fixed-layout read. All load-bearing duplicates are rejected.
fn tlvs<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(u16, &'a [u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        let header = word(bytes, 0)?;
        let len = (header & 0xffff) as usize;
        let end = 4usize.checked_add(len).ok_or(Error::Malformed)?;
        let value = bytes.get(4..end).ok_or(Error::Malformed)?;
        visit((header >> 16) as u16, value)?;
        bytes = bytes.get(end..).ok_or(Error::Malformed)?;
    }
    Ok(())
}
fn request(bytes: &[u8]) -> Result<MemoryRequest, Error> {
    let r = MemoryRequest {
        id: word(bytes, 0)?,
        unit_size: word(bytes, 4)?,
        flags: word(bytes, 8)?,
        units: word(bytes, 12)?,
    };
    if r.flags & !7 != 0 {
        return Err(Error::Unsupported);
    }
    Ok(r)
}
fn unique<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
const ABI: [u32; 6] = [0x01000000, 53, 0x5f414351, 0x4c4d, 0, 0];
fn abi(bytes: &[u8]) -> Result<(), Error> {
    for (i, value) in ABI.iter().enumerate() {
        // Linux deliberately permits a differing minor/build ABI1 value.
        if i != 1 && word(bytes, i * 4)? != *value {
            return Err(Error::Abi);
        }
    }
    Ok(())
}
fn service_ready(dialect: Dialect, body: &[u8]) -> Result<ServiceReady, Error> {
    let (ev, reg, bitmap, mem, rf, ht, min_power, count) = if dialect == Dialect::Tlv {
        let (mut ev, mut reg, mut map, mut mem) = (None, None, None, None);
        tlvs(body, |tag, value| {
            match tag {
                32 => unique(&mut ev, value)?,
                33 => unique(&mut reg, value)?,
                16 if map.is_none() => map = Some(value), // Later UINT32 array is DBS modes.
                18 => unique(&mut mem, value)?,
                _ => {}
            };
            Ok(())
        })?;
        let ev = ev.ok_or(Error::Malformed)?;
        if ev.len() < 104 {
            return Err(Error::Malformed);
        }
        abi(&ev[4..28])?;
        (
            ev,
            reg.ok_or(Error::Malformed)?,
            map.ok_or(Error::Malformed)?,
            mem.ok_or(Error::Malformed)?,
            36,
            40,
            52,
            72,
        )
    } else {
        let main_layout = matches!(dialect, Dialect::Main | Dialect::TenFour);
        let (fixed, rf, reg, count, bitmap) = if main_layout {
            (160, 84, 108, 156, 20)
        } else {
            (152, 80, 104, 148, 16)
        };
        if body.len() < fixed {
            return Err(Error::Malformed);
        }
        (
            body,
            &body[reg..reg + 36],
            &body[bitmap..bitmap + 64],
            &body[fixed..],
            rf,
            rf + 4,
            rf + 16,
            count,
        )
    };
    if reg.len() < 36 || bitmap.is_empty() || bitmap.len() & 3 != 0 || bitmap.len() > 1024 {
        return Err(Error::Malformed);
    }
    let n = word(ev, count)? as usize;
    if n > 16 {
        return Err(Error::Memory);
    }
    let mut requests = Vec::new();
    requests.try_reserve_exact(n).map_err(|_| Error::NoMemory)?;
    if dialect == Dialect::Tlv {
        tlvs(mem, |tag, bytes| {
            if tag != 34 || requests.len() == n {
                return Err(Error::Malformed);
            }
            requests.push(request(bytes)?);
            Ok(())
        })?;
        if requests.len() != n {
            return Err(Error::Malformed);
        }
    } else {
        if mem.len() < n * 16 {
            return Err(Error::Malformed);
        }
        for bytes in mem[..n * 16].chunks_exact(16) {
            requests.push(request(bytes)?);
        }
    }
    for (i, req) in requests.iter().enumerate() {
        if requests[..i].iter().any(|r| r.id == req.id) {
            return Err(Error::Malformed);
        }
    }
    let caps = Capabilities {
        rf_chains: word(ev, rf)?,
        ht: word(ev, ht)?,
        vht: word(ev, ht + 4)?,
        vht_mcs: word(ev, ht + 8)?,
        min_tx_power: word(ev, min_power)? as i32,
        max_tx_power: word(ev, min_power + 4)? as i32,
        eeprom_domain: word(reg, 0)?,
        low_2ghz: word(reg, 20)?,
        high_2ghz: word(reg, 24)?,
        low_5ghz: word(reg, 28)?,
        high_5ghz: word(reg, 32)?,
        bitmap: owned(bitmap)?,
    };
    if !(1..=4).contains(&caps.rf_chains) || caps.min_tx_power > caps.max_tx_power {
        return Err(Error::Malformed);
    }
    Ok(ServiceReady { caps, requests })
}
fn ready(dialect: Dialect, body: &[u8]) -> Result<Ready, Error> {
    let (bytes, offset) = if dialect == Dialect::Tlv {
        let mut value = None;
        tlvs(body, |tag, bytes| {
            if tag == 35 {
                unique(&mut value, bytes)?;
            }
            Ok(())
        })?;
        let bytes = value.ok_or(Error::Malformed)?;
        if bytes.len() < 36 {
            return Err(Error::Malformed);
        }
        (bytes, 24)
    } else {
        if body.len() < 20 {
            return Err(Error::Malformed);
        }
        (body, 8)
    };
    let status = word(bytes, offset + 8)?;
    if status != 0 {
        return Err(Error::Firmware(status));
    }
    let mac: [u8; 6] = bytes[offset..offset + 6].try_into().unwrap();
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err(Error::Malformed);
    }
    Ok(Ready {
        mac,
        software: word(bytes, 0)?,
        abi: word(bytes, 4)?,
    })
}
fn resources(
    d: Dialect,
    hw: HwRev,
    caps: &Capabilities,
    features: u64,
) -> Result<Resources, Error> {
    let (mut values, vdevs, peers, active_peers) = match d {
        Dialect::Main => (
            words(&[
                8, 24, 0, 0, 2, 48, 16, 7, 7, 100, 100, 100, 40, 1, 4, 3, 3, 8, 0, 0, 0, 1024, 32,
                0, 0, 0, 0, 3, 1424, 0,
            ])?,
            8,
            24,
            0,
        ),
        Dialect::Tlv => {
            let off = if caps.service(d, 65) { 4 } else { 0 };
            // host_capab remains0: no bundled-management/TX-ACK-RSSI promise.
            (
                words(&[
                    4, 33, off, off, 2, 66, 16, 7, 7, 100, 100, 100, 40, 1, 4, 4, 4, 8, 0, 0, 0,
                    1024, 32, 0, 0, 0, 0, 2, 1056, 2, 1, 32, 2, 5, 22, 6, 0, 1, 1, 0, 0, 0, 0, 0,
                ])?,
                4,
                33,
                0,
            )
        }
        Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour => {
            let mut values = words(&[
                16, 144, 2, 256, 128, 7, 7, 100, 100, 100, 40, 1, 4, 2, 2, 8, 0, 0, 0, 1024, 32, 0,
                0, 1, 0, 1424, 0,
            ])?;
            if d != Dialect::TenOne {
                values.try_reserve_exact(7).map_err(|_| Error::NoMemory)?;
                // Default RX batching, plus channel-info64 only if advertised.
                let feature = 1 | if caps.service(d, 25) { 1 << 6 } else { 0 };
                values.extend_from_slice(&[0, 0, 0, 0, 0, 0, feature]);
            }
            (values, 16, 144, 0)
        }
        Dialect::TenFour => {
            let pfc = features & (1 << 13) != 0;
            let cache = caps.service(d, 37);
            let (peers, active, tids) = if cache {
                let active = if pfc { 51 } else { 66 };
                (528, active, active * 2)
            } else {
                (48, 0, 96)
            };
            let chains = if matches!(hw, HwRev::Qca99x0 | HwRev::Qca9984) {
                15
            } else {
                3
            };
            (
                words(&[
                    16,
                    peers,
                    active,
                    0,
                    0,
                    2,
                    tids,
                    32,
                    chains,
                    chains,
                    100,
                    100,
                    100,
                    40,
                    1,
                    4,
                    3,
                    3,
                    8,
                    0,
                    0,
                    0,
                    1024,
                    32,
                    1,
                    0,
                    1,
                    0,
                    3,
                    if pfc { 2500 } else { 1424 },
                    2,
                    16,
                    0,
                    0,
                    0,
                    0,
                    0,
                    1,
                    0,
                    0,
                    1,
                    0,
                ])?,
                16,
                peers,
                active,
            )
        }
    };
    if features & (1 << 10) != 0 {
        // Linux core.c::ath10k_core_init_firmware_features selects RAW for
        // software crypto only with RAW_MODE_SUPPORT. These are the packed
        // resource_config{,_10x,_10_4}/TLV rx_decap_mode word offsets.
        let index = match d {
            Dialect::Main | Dialect::Tlv => 13,
            Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour => 11,
            Dialect::TenFour => 14,
        };
        values[index] = 0; // ATH10K_HW_TXRX_RAW
    }
    Ok(Resources {
        words: values,
        vdevs,
        peers,
        active_peers,
    })
}
fn memory_plans(reqs: &[MemoryRequest], cfg: &Resources) -> Result<Vec<MemoryPlan>, Error> {
    let mut plans = Vec::new();
    plans
        .try_reserve_exact(reqs.len())
        .map_err(|_| Error::NoMemory)?;
    for req in reqs {
        let units = if req.flags & 4 != 0 {
            (if cfg.active_peers != 0 {
                cfg.active_peers
            } else {
                cfg.peers
            }) + 1
        } else if req.flags & 2 != 0 {
            cfg.peers + 1
        } else if req.flags & 1 != 0 {
            cfg.vdevs + 1
        } else {
            req.units
        };
        let size = req.unit_size.checked_add(3).ok_or(Error::Memory)? & !3;
        let bytes = size.checked_mul(units).ok_or(Error::Memory)?;
        if units != 0 && size == 0 {
            return Err(Error::Memory);
        }
        if bytes != 0 {
            plans.push(MemoryPlan { id: req.id, bytes });
        }
    }
    Ok(plans)
}
fn put(v: &mut Vec<u8>, value: u32) {
    v.extend_from_slice(&value.to_le_bytes());
}
fn tlv(v: &mut Vec<u8>, tag: u16, length: usize) {
    put(v, (u32::from(tag) << 16) | length as u32);
}
fn init(d: Dialect, cfg: &Resources, chunks: &[MemoryChunk]) -> Result<Vec<u8>, Error> {
    if chunks.len() > 16 {
        return Err(Error::Memory);
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(1024).map_err(|_| Error::NoMemory)?;
    put(&mut bytes, d.init_command());
    if d == Dialect::Tlv {
        tlv(&mut bytes, 74, 28);
        for value in ABI {
            put(&mut bytes, value);
        }
        put(&mut bytes, chunks.len() as u32);
        tlv(&mut bytes, 75, cfg.words.len() * 4);
    }
    for &value in &cfg.words {
        put(&mut bytes, value);
    }
    if d == Dialect::Tlv {
        tlv(&mut bytes, 18, chunks.len() * 20);
    } else {
        put(&mut bytes, chunks.len() as u32);
    }
    for chunk in chunks {
        if d == Dialect::Tlv {
            tlv(&mut bytes, 76, 16);
        }
        put(&mut bytes, chunk.id);
        put(&mut bytes, chunk.address);
        put(&mut bytes, chunk.bytes);
        if d == Dialect::Tlv {
            put(&mut bytes, 0);
        }
    }
    // Linux retains a fixed union item in non-TLV wmi_host_mem_chunks even
    // when count0; struct_size additionally reserves the advertised items.
    if d != Dialect::Tlv {
        bytes.extend_from_slice(&[0; 12]);
    }
    Ok(bytes)
}
#[derive(Debug)]
pub(super) struct Runtime<T> {
    pub htc: Session<T>,
    dialect: Dialect,
    hardware: HwRev,
    features: u64,
    pub caps: Option<Capabilities>,
    pub ready: Option<Ready>,
    early_htt: VecDeque<Vec<u8>>,
    failed: bool,
}
impl<T: Hif + HostMemory> Runtime<T> {
    pub fn raw_mode(&self) -> bool {
        self.ready.is_some() && self.features & (1 << 10) != 0
    }
    pub fn new(htc: Session<T>, dialect: Dialect, hardware: HwRev, features: u64) -> Self {
        Self {
            htc,
            dialect,
            hardware,
            features,
            caps: None,
            ready: None,
            early_htt: VecDeque::new(),
            failed: false,
        }
    }
    async fn event(&mut self, expected: u32) -> Result<Vec<u8>, Error> {
        let deadline = narf_time::Deadline::after_ms(5000);
        for _ in 0..512 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let (endpoint, bytes) = self.htc.receive().await?;
            if endpoint == self.htc.htt {
                if self.early_htt.len() == 32 {
                    return Err(Error::Malformed);
                }
                self.early_htt.try_reserve(1).map_err(|_| Error::NoMemory)?;
                self.early_htt.push_back(bytes);
                continue;
            }
            if endpoint != self.htc.wmi {
                return Err(Error::Malformed);
            }
            let id = word(&bytes, 0)? & 0xffffff;
            if id == expected {
                return owned(&bytes[4..]);
            }
            if id == self.dialect.service_event() || id == self.dialect.ready_event() {
                return Err(Error::Malformed);
            }
            // Before any vdev exists, unrelated firmware diagnostics/events
            // cannot authorize a channel, association or controlled port.
        }
        Err(Error::Timeout)
    }
    pub fn take_early_htt(&mut self) -> Option<Vec<u8>> {
        self.early_htt.pop_front()
    }
    pub async fn start(&mut self) -> Result<Ready, Error> {
        if self.failed || self.ready.is_some() {
            return Err(Error::Failed);
        }
        self.failed = true; // Dropping this future cannot replay memory/INIT.
        let body = self.event(self.dialect.service_event()).await?;
        let service = service_ready(self.dialect, &body)?;
        let config = resources(self.dialect, self.hardware, &service.caps, self.features)?;
        let plans = memory_plans(&service.requests, &config)?;
        let chunks = self.htc.transport.retain_wmi_memory(&plans)?;
        if chunks.len() != plans.len()
            || chunks.iter().zip(&plans).any(|(c, p)| {
                c.id != p.id
                    || c.bytes != p.bytes
                    || c.address == 0
                    || c.address & 3 != 0
                    || u64::from(c.address) + u64::from(c.bytes) > 1 << 32
            })
        {
            return Err(Error::Memory);
        }
        self.caps = Some(service.caps);
        let command = init(self.dialect, &config, &chunks)?;
        self.htc.send_wmi(&command).await?;
        let ready = ready(self.dialect, &self.event(self.dialect.ready_event()).await?)?;
        self.ready = Some(ready);
        self.failed = false;
        Ok(ready)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "wmi_boot/tests.rs"]
mod tests;
