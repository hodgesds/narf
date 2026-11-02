// SPDX-License-Identifier: GPL-2.0-or-later
//! Owned native PCI HTT setup. No station is admitted by this stage.
use crate::ath10k::{
    control::{self, Hif},
    hw::HwRev,
    wmi_boot::{self, HostMemory},
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
#[path = "htt_runtime/pfc.rs"]
pub(super) mod pfc;
#[path = "htt_runtime/rx.rs"]
pub(super) mod rx;
#[path = "htt_runtime/storage.rs"]
pub(super) mod storage;
#[path = "htt_runtime/tx.rs"]
pub(super) mod tx;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Control(control::Error),
    Wmi(wmi_boot::Error),
    Malformed,
    Unsupported,
    Failed,
    NoMemory,
    Memory,
    Timeout,
    Busy,
}
impl From<control::Error> for Error {
    fn from(v: control::Error) -> Self {
        Self::Control(v)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Config {
    pub continuous: bool,
    pub pfc: bool,
    pub pending: u16,
    pub dialect: u32,
    pub major: u8,
}
impl Config {
    pub fn new(hw: HwRev, wmi: u32, htt: u32, features: u64) -> Result<Self, Error> {
        if !(1..=4).contains(&htt) {
            return Err(Error::Unsupported);
        }
        let continuous = matches!(hw, HwRev::Qca99x0 | HwRev::Qca9888 | HwRev::Qca9984);
        let pfc = features & (1 << 13) != 0;
        if pfc && (!continuous || wmi != 6 || htt != 4) {
            return Err(Error::Unsupported);
        }
        let pending = match wmi {
            1 | 2 | 3 | 5 => 1424,
            4 => 1056,
            6 => {
                if pfc {
                    2500
                } else {
                    1424
                }
            }
            _ => return Err(Error::Unsupported),
        };
        Ok(Self {
            continuous,
            pfc,
            pending,
            dialect: htt,
            major: 0,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DmaConfig {
    pub ring: u32,
    pub producer: u32,
    pub initial: u16,
    pub fragments: u32,
    pub qstate: u32,
}
/// Returned addresses must already be retained by the physical transport's
/// mission-mode DMA owner; cancelled setup never returns them to an allocator.
pub(super) trait HttMemory {
    /// Real coherent qstate ownership; absence keeps RAW/PFC diagnostic-only.
    fn supports_htt_pfc(&self) -> bool {
        false
    }
    fn publish_htt_queue_state(&mut self, _bytes: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn pending_htt_tx(&self) -> Result<usize, Error> {
        Err(Error::Unsupported)
    }
    fn prepare_wmi_management(&mut self, _bytes: &[u8]) -> Result<(u32, u64), Error> {
        Err(Error::Unsupported)
    }
    fn complete_wmi_management(&mut self, _ids: &[u32]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn retain_htt_memory(&mut self, config: Config) -> Result<DmaConfig, Error>;
    fn prepare_htt_tx(
        &mut self,
        config: Config,
        parameters: tx::Parameters,
        bytes: &[u8],
    ) -> Result<(u16, Vec<u8>), Error>;
    fn complete_htt_tx(&mut self, ids: &[u16], management: bool) -> Result<(), Error>;
    fn pop_htt_amsdu(&mut self) -> Result<Vec<rx::Msdu>, Error>;
    fn pop_htt_in_order(&mut self, indication: &rx::InOrder) -> Result<Vec<rx::Msdu>, Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ready {
    pub major: u8,
    pub minor: u8,
}
fn append(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn dma_config(c: Config, d: DmaConfig) -> Result<(), Error> {
    if d.ring == 0
        || d.producer == 0
        || (d.ring | d.producer | d.fragments | d.qstate) & 3 != 0
        || u64::from(d.ring) + 8192 > 1 << 32
        || u64::from(d.producer) + 4 > 1 << 32
        || d.initial != 1023
        || c.continuous != (d.fragments != 0)
        || c.pfc != (d.qstate != 0)
    {
        return Err(Error::Memory);
    }
    if c.continuous && u64::from(d.fragments) + u64::from(c.pending) * 64 > 1 << 32 {
        return Err(Error::Memory);
    }
    if c.pfc && u64::from(d.qstate) + 4772 > 1 << 32 {
        return Err(Error::Memory);
    }
    Ok(())
}
fn rx_config(d: DmaConfig) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(40).map_err(|_| Error::NoMemory)?;
    bytes.extend_from_slice(&[2, 1, 0, 0]);
    append(&mut bytes, d.producer);
    append(&mut bytes, d.ring);
    // All matched PCI devices use htt_rx_desc_v1. Independent C sizeof/offsetof
    // oracle:300 bytes; hdr236/payload300/PPDU84,124/MPDU12,80/MSDU24,40/att4/frag8.
    for value in [
        2048, 2048, 0xffff, d.initial, 59, 75, 21, 31, 3, 20, 6, 10, 1, 2,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    Ok(bytes)
}
fn fragment_config(c: Config, d: DmaConfig) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(48).map_err(|_| Error::NoMemory)?;
    bytes.extend_from_slice(&[6, if c.pfc { 8 } else { 0 }, 1, 64]);
    for value in [d.fragments, 0, 0, 0] {
        append(&mut bytes, value);
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(c.pending - 1).to_le_bytes());
    bytes.extend_from_slice(&[0; 12]);
    append(&mut bytes, d.qstate);
    bytes.extend_from_slice(&(if c.pfc { 528u16 } else { 0 }).to_le_bytes());
    bytes.extend_from_slice(&(if c.pfc { 8u16 } else { 0 }).to_le_bytes());
    bytes.extend_from_slice(&[1, 0, 0, 0]);
    Ok(bytes)
}
#[derive(Debug)]
pub(super) enum Event {
    /// Empty nonblocking HIF poll, after all retained payloads were drained.
    Idle,
    /// A credit-only or internally consumed event; input may still be queued.
    Progress,
    Tx(u8),
    Rx(RxBatch),
    InOrder(rx::InOrder, Vec<rx::Msdu>),
    Wmi(Vec<u8>),
    Message(Vec<u8>),
}
#[derive(Debug)]
pub(super) struct RxBatch {
    pub peer: u16,
    pub tid: u8,
    pub frames: Vec<(u8, rx::Msdu)>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TxReceipt {
    pub id: u16,
    pub status: u8,
}
#[derive(Debug)]
pub(super) struct Runtime<T> {
    pub wmi: wmi_boot::Runtime<T>,
    config: Config,
    pub ready: Option<Ready>,
    pub early_htt: VecDeque<Vec<u8>>,
    pub wmi_events: VecDeque<Vec<u8>>,
    tx_receipts: VecDeque<TxReceipt>,
    pfc: Option<Box<pfc::Owner>>,
    failed: bool,
}
impl<T: Hif + HostMemory + HttMemory> Runtime<T> {
    pub fn new(wmi: wmi_boot::Runtime<T>, config: Config) -> Self {
        Self {
            wmi,
            config,
            ready: None,
            early_htt: VecDeque::new(),
            wmi_events: VecDeque::new(),
            tx_receipts: VecDeque::new(),
            pfc: config
                .pfc
                .then(|| Box::new(pfc::Owner::new(config.pending))),
            failed: false,
        }
    }
    fn queue(queue: &mut VecDeque<Vec<u8>>, bytes: Vec<u8>) -> Result<(), Error> {
        if queue.len() == 64 {
            return Err(Error::Malformed);
        }
        queue.try_reserve(1).map_err(|_| Error::NoMemory)?;
        queue.push_back(bytes);
        Ok(())
    }
    pub async fn poll(&mut self) -> Result<Event, Error> {
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        let (progressed, packet) = if let Some(bytes) = self.early_htt.pop_front() {
            (true, Some((self.wmi.htc.htt, bytes)))
        } else if let Some(bytes) = self.wmi_events.pop_front() {
            (true, Some((self.wmi.htc.wmi, bytes)))
        } else {
            self.wmi.htc.poll_with_progress().await?
        };
        self.failed = false;
        self.dispatch(progressed, packet)
    }
    fn dispatch(
        &mut self,
        progressed: bool,
        packet: Option<(u8, Vec<u8>)>,
    ) -> Result<Event, Error> {
        let Some((endpoint, bytes)) = packet else {
            return Ok(if progressed {
                Event::Progress
            } else {
                Event::Idle
            });
        };
        if endpoint == self.wmi.htc.wmi {
            return Ok(Event::Wmi(bytes));
        }
        if endpoint != self.wmi.htc.htt {
            self.failed = true;
            return Err(Error::Malformed);
        }
        if let Some(owner) = &mut self.pfc {
            self.failed = true;
            let consumed = owner.observe(&bytes)?;
            if consumed {
                self.publish_pfc_state()?;
                self.failed = false;
                return Ok(Event::Progress);
            }
            self.failed = false;
        }
        match bytes.first().copied() {
            Some(7) => self.complete_tx(&bytes).map(Event::Tx),
            Some(message) if message == if self.config.dialect == 2 { 0x13 } else { 0xe } => {
                self.complete_management(&bytes).map(Event::Tx)
            }
            Some(1) => self.receive_legacy(&bytes).map(Event::Rx),
            Some(0x12) if self.config.dialect == 3 => self
                .receive_in_order(&bytes)
                .map(|(i, f)| Event::InOrder(i, f)),
            Some(_) => Ok(Event::Message(bytes)),
            None => {
                self.failed = true;
                Err(Error::Malformed)
            }
        }
    }
    pub fn source_ready(&mut self) -> Result<bool, Error> {
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.wmi.htc.htt_source_ready().map_err(Error::from)
    }
    fn publish_pfc_state(&mut self) -> Result<(), Error> {
        let bytes = self.pfc.as_mut().ok_or(Error::Failed)?.state()?;
        self.wmi.htc.transport.publish_htt_queue_state(&bytes)
    }
    pub(super) fn pfc_queued(&self) -> bool {
        self.pfc.as_ref().is_some_and(|owner| owner.pending() != 0)
    }
    pub(super) fn pfc_active(&self) -> bool {
        self.pfc.is_some()
    }
    fn queue_pfc(&mut self, parameters: tx::Parameters, bytes: &[u8]) -> Result<u16, Error> {
        self.failed = true;
        if !self.wmi.htc.transport.supports_htt_pfc()
            || parameters.vdev != 0
            || bytes.len() < 24
            || !matches!(bytes[0], 8 | 0x88)
            || bytes[1] & 3 != 1
            || bytes[4] & 1 != 0
        {
            return Err(Error::Unsupported);
        }
        // mac80211's non-QoS TXQ is host queue0; native ext-TID16 remains
        // unchanged in TX_FRM. Do not alias management ext-TID17 to data.
        let tid = if bytes[0] == 8 && parameters.tid == 16 {
            0
        } else if bytes[0] == 0x88
            && bytes.len() >= 26
            && parameters.tid < 8
            && bytes[24] & 15 == parameters.tid
        {
            parameters.tid
        } else {
            return Err(Error::Malformed);
        };
        let mac = bytes[4..10].try_into().unwrap();
        let key = self
            .pfc
            .as_ref()
            .ok_or(Error::Failed)?
            .key(parameters.vdev, mac, tid)?;
        let (id, body) = self
            .wmi
            .htc
            .transport
            .prepare_htt_tx(self.config, parameters, bytes)?;
        self.pfc
            .as_mut()
            .ok_or(Error::Failed)?
            .enqueue(key, id, bytes.len(), body)?;
        self.publish_pfc_state()?;
        self.failed = false;
        Ok(id)
    }
    /// Only the live station packet path calls this after its current
    /// association/policy/key/timeout checks. Generic scan/management polling
    /// never publishes a retained data entry for a retired controlled port.
    pub(super) fn service_pfc(&mut self, mac: [u8; 6], ids: &[u64; 32]) -> Result<bool, Error> {
        if self.pfc.is_none() {
            return Ok(false);
        }
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        let mut progress = false;
        for _ in 0..32 {
            if !self.wmi.htc.htt_source_ready()? {
                break;
            }
            // The pool also contains management and prepared host IDs. Count
            // all actual native work, excluding only this owner's host queues.
            let owner = self.pfc.as_mut().ok_or(Error::Failed)?;
            let native = self
                .wmi
                .htc
                .transport
                .pending_htt_tx()?
                .checked_sub(owner.pending())
                .ok_or(Error::Failed)?;
            let Some(work) = owner.next(mac, ids, native)? else {
                break;
            };
            self.wmi.htc.begin_htt(work.bytes())?;
            self.pfc.as_mut().ok_or(Error::Failed)?.published(work)?;
            self.publish_pfc_state()?;
            progress = true;
        }
        self.failed = false;
        Ok(progress)
    }
    pub fn begin_transmit(
        &mut self,
        parameters: tx::Parameters,
        bytes: &[u8],
    ) -> Result<u16, Error> {
        if !self.source_ready()? {
            return Err(Error::Busy);
        }
        if self.config.pfc && parameters.kind == tx::Kind::Raw {
            return self.queue_pfc(parameters, bytes);
        }
        let (id, body) = self
            .wmi
            .htc
            .transport
            .prepare_htt_tx(self.config, parameters, bytes)?;
        self.failed = true;
        self.wmi.htc.begin_htt(&body)?;
        self.failed = false;
        Ok(id)
    }
    pub fn poll_now(&mut self) -> Result<Event, Error> {
        // Buffered real HTC/HTT events must never inherit an earlier physical
        // PM defer. Only this call's actual HIF result may deny fresh idle.
        self.wmi.htc.take_idle_deferred();
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        let (progressed, packet) = if let Some(bytes) = self.early_htt.pop_front() {
            (true, Some((self.wmi.htc.htt, bytes)))
        } else if let Some(bytes) = self.wmi_events.pop_front() {
            (true, Some((self.wmi.htc.wmi, bytes)))
        } else {
            self.wmi.htc.poll_now()?
        };
        self.failed = false;
        self.dispatch(progressed, packet)
    }
    pub(super) fn take_idle_deferred(&mut self) -> bool {
        self.wmi.htc.take_idle_deferred()
    }
    pub async fn transmit(
        &mut self,
        parameters: tx::Parameters,
        bytes: &[u8],
    ) -> Result<u16, Error> {
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        if self.config.pfc && parameters.kind == tx::Kind::Raw {
            return self.queue_pfc(parameters, bytes);
        }
        let (id, body) = self
            .wmi
            .htc
            .transport
            .prepare_htt_tx(self.config, parameters, bytes)?;
        self.failed = true;
        self.wmi.htc.send_htt(&body).await?;
        self.failed = false;
        Ok(id)
    }
    pub fn receive_in_order(
        &mut self,
        bytes: &[u8],
    ) -> Result<(rx::InOrder, Vec<rx::Msdu>), Error> {
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        if self.config.dialect != 3 {
            return Err(Error::Unsupported);
        }
        let indication = rx::in_order(bytes)?;
        let frames = self.wmi.htc.transport.pop_htt_in_order(&indication)?;
        self.failed = false;
        Ok((indication, frames))
    }
    pub fn receive_legacy(&mut self, bytes: &[u8]) -> Result<RxBatch, Error> {
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        let indication = rx::indication(bytes)?;
        let count: usize = indication.ranges.iter().map(|r| usize::from(r.count)).sum();
        if count > 1023 {
            return Err(Error::Malformed);
        }
        let mut frames = Vec::new();
        frames.try_reserve(count).map_err(|_| Error::NoMemory)?;
        for range in indication.ranges {
            for _ in 0..range.count {
                let msdus = self.wmi.htc.transport.pop_htt_amsdu()?;
                frames
                    .try_reserve(msdus.len())
                    .map_err(|_| Error::NoMemory)?;
                frames.extend(msdus.into_iter().map(|frame| (range.status, frame)));
            }
        }
        self.failed = false;
        Ok(RxBatch {
            peer: indication.peer,
            tid: indication.tid,
            frames,
        })
    }
    pub fn complete_management(&mut self, bytes: &[u8]) -> Result<u8, Error> {
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        let message = if self.config.dialect == 2 { 0x13 } else { 0xe };
        if bytes.len() < 20 || bytes[0] != message {
            return Err(Error::Malformed);
        }
        let id = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let status = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if id > u32::from(u16::MAX) || status > 2 {
            return Err(Error::Malformed);
        }
        if self.tx_receipts.len() >= usize::from(self.config.pending) {
            return Err(Error::Busy);
        }
        if let Some(owner) = &self.pfc {
            owner.validate_receipts(&[id as u16])?;
        }
        self.tx_receipts
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        self.wmi.htc.transport.complete_htt_tx(&[id as u16], true)?;
        if let Some(owner) = &mut self.pfc {
            owner.complete(&[id as u16]);
        }
        let status = match status {
            0 => 0,
            1 => 2,
            _ => 1,
        };
        self.tx_receipts.push_back(TxReceipt {
            id: id as u16,
            status,
        });
        self.failed = false;
        Ok(status)
    }
    pub fn complete_tx(&mut self, bytes: &[u8]) -> Result<u8, Error> {
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        let (status, ids) = tx::completion(bytes)?;
        if let Some(owner) = &self.pfc {
            owner.validate_receipts(&ids)?;
        }
        if self.tx_receipts.len() + ids.len() > usize::from(self.config.pending) {
            return Err(Error::Busy);
        }
        self.tx_receipts
            .try_reserve(ids.len())
            .map_err(|_| Error::NoMemory)?;
        self.wmi.htc.transport.complete_htt_tx(&ids, false)?;
        if let Some(owner) = &mut self.pfc {
            owner.complete(&ids);
        }
        self.tx_receipts
            .extend(ids.into_iter().map(|id| TxReceipt { id, status }));
        self.failed = false;
        Ok(status)
    }
    pub fn take_tx_receipt(&mut self) -> Option<TxReceipt> {
        self.tx_receipts.pop_front()
    }
    pub fn take_tx_receipt_for(&mut self, id: u16) -> Option<TxReceipt> {
        let at = self.tx_receipts.iter().position(|r| r.id == id)?;
        self.tx_receipts.remove(at)
    }
    // mac.c::ath10k_mac_tx_frm_has_freq: the actual negotiated version and
    // TLV HTT dialect qualify this field, never PCI identity alone.
    pub fn offchannel_frequency_field(&self) -> bool {
        self.config.dialect == 3 && self.ready.is_some_and(|r| r.major >= 3 && r.minor >= 4)
    }
    pub fn prepare_offchannel(
        &mut self,
        parameters: tx::Parameters,
        bytes: &[u8],
        frequency: u16,
    ) -> Result<(u16, Vec<u8>), Error> {
        if self.failed
            || self.ready.is_none()
            || parameters.kind != tx::Kind::Management
            || frequency == 0
        {
            return Err(Error::Failed);
        }
        let (id, mut body) =
            self.wmi
                .htc
                .transport
                .prepare_htt_tx(self.config, parameters, bytes)?;
        if self.offchannel_frequency_field() {
            // v3 TX_FRM peerid/freq union; old MGMT_TX has no frequency field.
            if self.config.major < 3 || body.len() < 16 {
                return Err(Error::Malformed);
            }
            body[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
            body[14..16].copy_from_slice(&frequency.to_le_bytes());
        }
        Ok((id, body))
    }
    pub async fn submit_prepared(&mut self, body: &[u8]) -> Result<(), Error> {
        if self.failed || self.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        self.wmi.htc.send_htt(body).await?;
        self.failed = false;
        Ok(())
    }
    /// The AP owner uses the actual negotiated legacy RAW descriptor path.
    /// A continuous/PFC profile needs separate AP ownership and stays refused.
    pub(in crate::ath10k) fn ap_protocol(&self) -> bool {
        !self.failed
            && self.config.dialect == 3
            && !self.config.continuous
            && !self.config.pfc
            && self.ready.is_some_and(|ready| ready.major >= 3)
            && self.data_profile()
    }
    pub fn data_profile(&self) -> bool {
        self.wmi.raw_mode() && (!self.config.pfc || self.wmi.htc.transport.supports_htt_pfc())
    }
    pub async fn start(&mut self) -> Result<Ready, Error> {
        if self.failed || self.ready.is_some() || self.wmi.ready.is_none() {
            return Err(Error::Failed);
        }
        self.failed = true;
        self.wmi.htc.send_htt(&[0, 0, 0, 0]).await?;
        let deadline = narf_time::Deadline::after_ms(3000);
        let version = loop {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let bytes = if let Some(bytes) = self.wmi.take_early_htt() {
                bytes
            } else {
                let (endpoint, bytes) = self.wmi.htc.receive().await?;
                if endpoint == self.wmi.htc.wmi {
                    Self::queue(&mut self.wmi_events, bytes)?;
                    continue;
                }
                if endpoint != self.wmi.htc.htt {
                    return Err(Error::Malformed);
                }
                bytes
            };
            if bytes.first().copied() != Some(0) {
                Self::queue(&mut self.early_htt, bytes)?;
                continue;
            }
            if bytes.len() < 4 {
                return Err(Error::Malformed);
            }
            if bytes[2] != 2 && bytes[2] != 3 {
                return Err(Error::Unsupported);
            }
            break Ready {
                major: bytes[2],
                minor: bytes[1],
            };
        };
        let dma = self.wmi.htc.transport.retain_htt_memory(self.config)?;
        dma_config(self.config, dma)?;
        if self.config.continuous {
            self.wmi
                .htc
                .send_htt(&fragment_config(self.config, dma)?)
                .await?;
        }
        self.wmi.htc.send_htt(&rx_config(dma)?).await?;
        // Firmware offloads TX aggregation. This retained RAW packet owner
        // submits one MPDU at a time and must configure that native bound,
        // independently of RX BA/reorder. RAW transmit A-MSDU stays disabled
        // for Linux's firmware-format workaround (htt_tx.c::aggr_cfg_msg).
        let (ampdu, amsdu) = if self.wmi.raw_mode() { (1, 1) } else { (64, 3) };
        self.wmi.htc.send_htt(&[5, ampdu, amsdu]).await?;
        self.config.major = version.major;
        self.ready = Some(version);
        self.failed = false;
        Ok(version)
    }
}
