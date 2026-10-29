//! GLINK over SMEM: the RPMSG-style channel transport between the
//! application processor and a Q6 (WCSS on IPQ8074/IPQ6018/IPQ5018,
//! WPSS on SC7280/WCN6750). ath11k AHB's WLFW QMI rides QRTR over the
//! `IPCRTR` channel of the `rtr`/`wpss` edge.
//!
//! Two layers, split as Linux does:
//!
//! - [`GlinkSmem`] — `drivers/rpmsg/qcom_glink_smem.c`: a pair of
//!   byte FIFOs in SMEM. Item 478 (`SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR`,
//!   32 bytes) holds `tx tail, tx head, rx tail, rx head` (`__le32`
//!   each, from the host's point of view); item 479 is the host's
//!   16 KiB TX FIFO, item 480 the RX FIFO the remote allocates (looked
//!   up lazily, as `glink_smem_rx_avail` does). Writes keep `head`
//!   8-byte aligned and publish it after the data (`wmb()`), and
//!   `tx_avail` holds back `FIFO_FULL_RESERVE + TX_BLOCKED_CMD_RESERVE`
//!   so a `READ_NOTIF` always fits.
//! - [`Glink`] — `drivers/rpmsg/qcom_glink_native.c` (Linux v7.2): version/feature
//!   negotiation, channel open/close with local (`lcid`) and remote
//!   (`rcid`) ids, receive intents (both directions), fragmented
//!   `TX_DATA`/`TX_DATA_CONT`, `RX_DONE[_W_REUSE]`, intent requests,
//!   `READ_NOTIF` back-pressure and `SIGNALS`.
//!
//! Linux blocks in `qcom_glink_tx` / `qcom_glink_request_intent`; here
//! [`Glink`] is a non-blocking state machine. Outgoing commands go
//! through one ordered queue flushed whenever the FIFO has room, and
//! payloads wait per channel for a fitting remote intent. The owner
//! calls [`Glink::process_rx`] on every edge interrupt
//! (`qcom_glink_smem_intr` → `qcom_glink_native_rx`) and drains
//! [`GlinkEvent`]s. Linux defers `VERSION`, `OPEN`, `CLOSE`, … to a
//! worker but processes them in FIFO order; here they run inline in
//! that same order.
//!
//! Remote-initiated channels (the `IPCRTR` case) follow the rpmsg
//! probe path: `qcom_glink_rx_open` records the remote's `rcid`; when
//! a driver has claimed the name ([`Glink::accept`]),
//! `qcom_glink_create_remote` sends `OPEN_ACK` then our own `OPEN`,
//! and once the remote's `OPEN_ACK` arrives `qcom_glink_announce_create`
//! advertises the base intents (DT `qcom,intents`, default 5 × 1 KiB).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

use crate::hwlock::HwSpinlock;
use crate::io::{read_bytes, write_bytes, RegIo};
use crate::ipc::Kick;
use crate::smem::{Smem, SmemError};

pub const GLINK_VERSION_1: u16 = 1;
pub const GLINK_NAME_SIZE: usize = 32;
pub const GLINK_CMD_VERSION: u16 = 0;
pub const GLINK_CMD_VERSION_ACK: u16 = 1;
pub const GLINK_CMD_OPEN: u16 = 2;
pub const GLINK_CMD_CLOSE: u16 = 3;
pub const GLINK_CMD_OPEN_ACK: u16 = 4;
pub const GLINK_CMD_INTENT: u16 = 5;
pub const GLINK_CMD_RX_DONE: u16 = 6;
pub const GLINK_CMD_RX_INTENT_REQ: u16 = 7;
pub const GLINK_CMD_RX_INTENT_REQ_ACK: u16 = 8;
pub const GLINK_CMD_TX_DATA: u16 = 9;
pub const GLINK_CMD_CLOSE_ACK: u16 = 11;
pub const GLINK_CMD_TX_DATA_CONT: u16 = 12;
pub const GLINK_CMD_READ_NOTIF: u16 = 13;
pub const GLINK_CMD_RX_DONE_W_REUSE: u16 = 14;
pub const GLINK_CMD_SIGNALS: u16 = 15;
/// `GLINK_FEATURE_INTENT_REUSE` (`include/linux/rpmsg/qcom_glink.h`).
pub const GLINK_FEATURE_INTENT_REUSE: u32 = 1 << 0;
pub const GLINK_FEATURE_INTENTLESS: u32 = 1 << 1;
pub const NATIVE_DSR_SIG: u32 = 1 << 31;
pub const NATIVE_CTS_SIG: u32 = 1 << 30;
/// `RPM_GLINK_CID_MIN` / `_MAX` (lcid allocation range).
pub const GLINK_CID_MIN: u32 = 1;
pub const GLINK_CID_MAX: u32 = 65536;
/// `struct glink_msg` header size.
pub const GLINK_MSG_SIZE: usize = 8;
/// `TX_DATA` header: `glink_msg` + `chunk_size` + `left_size`.
pub const GLINK_DATA_HDR_SIZE: usize = 16;
/// `__qcom_glink_send` splits payloads into ≤ 8 KiB chunks.
pub const GLINK_TX_CHUNK: usize = 8 * 1024;
/// `qcom_glink_announce_create` default: 5 intents of 1 KiB.
pub const GLINK_DEFAULT_INTENTS: [(u32, u32); 1] = [(1024, 5)];

pub const SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR: u32 = 478;
pub const SMEM_GLINK_NATIVE_XPRT_FIFO_0: u32 = 479;
pub const SMEM_GLINK_NATIVE_XPRT_FIFO_1: u32 = 480;
pub const GLINK_SMEM_DESC_SIZE: u32 = 32;
pub const GLINK_SMEM_TX_FIFO_SIZE: u32 = 16 * 1024;
pub const FIFO_FULL_RESERVE: usize = 8;
pub const TX_BLOCKED_CMD_RESERVE: usize = 8;

const fn align8(v: usize) -> usize {
    (v + 7) & !7
}

/// GLINK failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GlinkError {
    Smem(SmemError),
    /// Descriptor item is not 32 bytes (`-EINVAL` in Linux).
    BadDescriptor(u32),
    /// Unknown local channel id.
    NoChannel(u32),
    /// Channel exists but the open handshake has not completed.
    NotOpen(u32),
    /// Payload cannot fit the TX FIFO in one chunk, or is empty.
    TooBig(usize),
    /// A name longer than `GLINK_NAME_SIZE - 1`.
    BadName,
    /// Local channel ids exhausted.
    NoCid,
}

impl From<SmemError> for GlinkError {
    fn from(e: SmemError) -> Self {
        GlinkError::Smem(e)
    }
}

/// `struct qcom_glink_pipe`: one direction's FIFO operations.
pub trait GlinkPipe {
    /// `rx_pipe->avail` (bytes waiting).
    fn rx_avail(&mut self) -> usize;
    /// `rx_pipe->peek`: copy `buf.len()` bytes starting `offset` past tail.
    fn rx_peek(&self, buf: &mut [u8], offset: usize);
    /// `rx_pipe->advance`.
    fn rx_advance(&mut self, count: usize);
    /// `tx_pipe->avail` (after the reserves).
    fn tx_avail(&self) -> usize;
    /// `tx_pipe->length`.
    fn tx_len(&self) -> usize;
    /// `tx_pipe->write`: `hdr` then `data`, head realigned to 8.
    fn tx_write(&mut self, hdr: &[u8], data: &[u8]);
    /// `tx_pipe->kick`: raise the remote's interrupt.
    fn kick(&self);
}

/// `struct qcom_glink_smem` + its two `glink_smem_pipe`s.
#[derive(Debug)]
pub struct GlinkSmem<M: RegIo, K: Kick> {
    smem: Smem<M>,
    remote_pid: u16,
    desc: u32,
    tx_fifo: u32,
    tx_len: u32,
    rx: Option<(u32, u32)>,
    kick: K,
}

impl<M: RegIo, K: Kick> GlinkSmem<M, K> {
    /// `qcom_glink_smem_register` (resource half): allocate (or reuse)
    /// the descriptor and TX FIFO in the `remote_pid` partition, reset
    /// our RX tail and TX head. The RX FIFO is looked up on first use.
    pub async fn register<L: HwSpinlock>(
        smem: Smem<M>,
        lock: &L,
        remote_pid: u16,
        kick: K,
    ) -> Result<Self, GlinkError> {
        match smem
            .alloc(
                lock,
                remote_pid,
                SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR,
                GLINK_SMEM_DESC_SIZE,
            )
            .await
        {
            Ok(()) | Err(SmemError::Exists) => {}
            Err(e) => return Err(e.into()),
        }
        let d = smem.get(remote_pid, SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR)?;
        if d.len != GLINK_SMEM_DESC_SIZE {
            return Err(GlinkError::BadDescriptor(d.len));
        }
        match smem
            .alloc(
                lock,
                remote_pid,
                SMEM_GLINK_NATIVE_XPRT_FIFO_0,
                GLINK_SMEM_TX_FIFO_SIZE,
            )
            .await
        {
            Ok(()) | Err(SmemError::Exists) => {}
            Err(e) => return Err(e.into()),
        }
        let t = smem.get(remote_pid, SMEM_GLINK_NATIVE_XPRT_FIFO_0)?;
        let s = Self {
            remote_pid,
            desc: d.offset,
            tx_fifo: t.offset,
            tx_len: t.len,
            rx: None,
            kick,
            smem,
        };
        // `*rx_pipe->tail = 0; *tx_pipe->head = 0;`
        s.smem.mem().write32(s.desc + 8, 0);
        s.smem.mem().write32(s.desc + 4, 0);
        Ok(s)
    }

    pub fn smem(&self) -> &Smem<M> {
        &self.smem
    }
    pub fn remote_pid(&self) -> u16 {
        self.remote_pid
    }
    /// Byte offset of the descriptor item in the SMEM region.
    pub fn descriptor(&self) -> u32 {
        self.desc
    }
    /// (offset, length) of the TX FIFO.
    pub fn tx_fifo(&self) -> (u32, u32) {
        (self.tx_fifo, self.tx_len)
    }
    /// (offset, length) of the RX FIFO once the remote has allocated it.
    pub fn rx_fifo(&self) -> Option<(u32, u32)> {
        self.rx
    }

    fn rd(&self, word: u32) -> u32 {
        self.smem.mem().read32(self.desc + word * 4)
    }
    fn wr(&self, word: u32, v: u32) {
        self.smem.mem().write32(self.desc + word * 4, v)
    }

    fn write_one(&self, head: u32, data: &[u8]) -> u32 {
        let len = self.tx_len as usize;
        let first = data.len().min(len - head as usize);
        if first > 0 {
            write_bytes(self.smem.mem(), self.tx_fifo + head, &data[..first]);
        }
        if first != data.len() {
            write_bytes(self.smem.mem(), self.tx_fifo, &data[first..]);
        }
        let mut h = head as usize + data.len();
        if h >= len {
            h -= len;
        }
        h as u32
    }
}

impl<M: RegIo, K: Kick> GlinkPipe for GlinkSmem<M, K> {
    fn rx_avail(&mut self) -> usize {
        let (_, len) = match self.rx {
            Some(r) => r,
            None => match self
                .smem
                .get(self.remote_pid, SMEM_GLINK_NATIVE_XPRT_FIFO_1)
            {
                Ok(it) if it.len > 0 => {
                    self.rx = Some((it.offset, it.len));
                    (it.offset, it.len)
                }
                _ => return 0,
            },
        };
        let head = self.rd(3);
        let tail = self.rd(2);
        if head >= len || tail >= len {
            // A corrupt index would make peek read outside the FIFO.
            return 0;
        }
        if head < tail {
            (len - tail + head) as usize
        } else {
            (head - tail) as usize
        }
    }

    fn rx_peek(&self, buf: &mut [u8], offset: usize) {
        let Some((fifo, len)) = self.rx else {
            buf.fill(0);
            return;
        };
        let len = len as usize;
        let mut tail = self.rd(2) as usize + offset;
        if tail >= len {
            tail -= len;
        }
        let first = buf.len().min(len - tail);
        let (a, b) = buf.split_at_mut(first);
        if !a.is_empty() {
            read_bytes(self.smem.mem(), fifo + tail as u32, a);
        }
        if !b.is_empty() {
            read_bytes(self.smem.mem(), fifo, b);
        }
    }

    fn rx_advance(&mut self, count: usize) {
        let Some((_, len)) = self.rx else { return };
        let mut tail = self.rd(2) as usize + count;
        if tail >= len as usize {
            tail -= len as usize;
        }
        self.wr(2, tail as u32);
    }

    fn tx_avail(&self) -> usize {
        let head = self.rd(1) as usize;
        let tail = self.rd(0) as usize;
        let len = self.tx_len as usize;
        let avail = if tail <= head {
            len - head + tail
        } else {
            tail - head
        };
        avail.saturating_sub(FIFO_FULL_RESERVE + TX_BLOCKED_CMD_RESERVE)
    }

    fn tx_len(&self) -> usize {
        self.tx_len as usize
    }

    fn tx_write(&mut self, hdr: &[u8], data: &[u8]) {
        let mut head = self.rd(1);
        head = self.write_one(head, hdr);
        head = self.write_one(head, data);
        let mut h = align8(head as usize);
        if h >= self.tx_len as usize {
            h -= self.tx_len as usize;
        }
        // `wmb()`: FIFO contents before the head index.
        fence(Ordering::SeqCst);
        self.wr(1, h as u32);
    }

    fn kick(&self) {
        self.kick.kick();
    }
}

/// What the edge reported to its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GlinkEvent {
    /// Version negotiation finished with these features.
    Negotiated { features: u32 },
    /// The channel finished its open handshake and its intents are out.
    Open { lcid: u32, name: String },
    /// The remote announced a channel nobody has accepted yet.
    RemoteOpen { name: String },
    /// One complete message (`ept.cb`).
    Data { lcid: u32, data: Vec<u8> },
    /// The remote closed the channel (`qcom_glink_rx_close`).
    Closed { lcid: u32, name: String },
    /// The remote refused an intent request; the queued message was
    /// dropped (`__qcom_glink_send` → `-EAGAIN`).
    SendFailed { lcid: u32, len: usize },
    /// `GLINK_CMD_SIGNALS` (flow control: `true` = remote ready).
    Flow { lcid: u32, enable: bool },
}

/// Counters for protocol anomalies Linux logs with `dev_err`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GlinkStats {
    pub unknown_cmd: u32,
    pub unknown_channel: u32,
    pub no_intent: u32,
    pub intent_overflow: u32,
    pub read_notify_sent: u32,
    pub tx_blocked: u32,
}

#[derive(Clone, Debug)]
struct LocalIntent {
    id: u32,
    size: u32,
    reuse: bool,
    data: Vec<u8>,
}

#[derive(Copy, Clone, Debug)]
struct RemoteIntent {
    id: u32,
    size: u32,
    in_use: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum IntentReq {
    Idle,
    /// `RX_INTENT_REQ` sent; `granted` once the ack said yes.
    Pending {
        granted: bool,
    },
}

#[derive(Clone, Debug)]
struct Channel {
    name: String,
    lcid: u32,
    rcid: u32,
    /// Remote `OPEN_ACK` for our `OPEN`.
    open_ack: bool,
    /// Remote `OPEN` seen (`open_req` completion).
    open_req: bool,
    /// Claimed by a local user (rpmsg driver bound / `open` called).
    claimed: bool,
    /// Locally initiated (`qcom_glink_create_local`).
    local: bool,
    /// Our `OPEN_ACK` has gone out.
    acked: bool,
    /// Base intents advertised and `Open` reported.
    announced: bool,
    base_intents: Vec<(u32, u32)>,
    liids: Vec<LocalIntent>,
    next_liid: u32,
    /// Message being reassembled: (liid, bytes so far).
    rx_partial: Option<(u32, usize)>,
    riids: Vec<RemoteIntent>,
    txq: VecDeque<Vec<u8>>,
    intent_req: IntentReq,
}

impl Channel {
    fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            lcid: 0,
            rcid: 0,
            open_ack: false,
            open_req: false,
            claimed: false,
            local: false,
            acked: false,
            announced: false,
            base_intents: Vec::new(),
            liids: Vec::new(),
            next_liid: 1,
            rx_partial: None,
            riids: Vec::new(),
            txq: VecDeque::new(),
            intent_req: IntentReq::Idle,
        }
    }
    fn is_open(&self) -> bool {
        self.announced
    }
}

/// `struct qcom_glink`: one edge.
#[derive(Debug)]
pub struct Glink<P: GlinkPipe> {
    pipe: P,
    features: u32,
    negotiated: bool,
    channels: Vec<Channel>,
    next_lcid: u32,
    /// Commands in FIFO order: (header, payload).
    txq: VecDeque<(Vec<u8>, Vec<u8>)>,
    sent_read_notify: bool,
    accepts: Vec<(String, Vec<(u32, u32)>)>,
    events: VecDeque<GlinkEvent>,
    pub stats: GlinkStats,
}

fn msg(cmd: u16, p1: u16, p2: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(GLINK_MSG_SIZE);
    v.extend_from_slice(&cmd.to_le_bytes());
    v.extend_from_slice(&p1.to_le_bytes());
    v.extend_from_slice(&p2.to_le_bytes());
    v
}

impl<P: GlinkPipe> Glink<P> {
    /// `qcom_glink_native_probe`: queue `VERSION` (version 1, `features`)
    /// and flush it. `GlinkSmem` edges pass `GLINK_FEATURE_INTENT_REUSE`.
    pub fn new(pipe: P, features: u32) -> Self {
        let mut g = Self {
            pipe,
            features,
            negotiated: false,
            channels: Vec::new(),
            next_lcid: GLINK_CID_MIN,
            txq: VecDeque::new(),
            sent_read_notify: false,
            accepts: Vec::new(),
            events: VecDeque::new(),
            stats: GlinkStats::default(),
        };
        g.send_version(GLINK_CMD_VERSION);
        g.flush_tx();
        g
    }

    pub fn pipe(&self) -> &P {
        &self.pipe
    }
    pub fn pipe_mut(&mut self) -> &mut P {
        &mut self.pipe
    }
    pub fn features(&self) -> u32 {
        self.features
    }
    pub fn negotiated(&self) -> bool {
        self.negotiated
    }
    pub fn take_event(&mut self) -> Option<GlinkEvent> {
        self.events.pop_front()
    }
    /// Commands waiting for FIFO room.
    pub fn tx_backlog(&self) -> usize {
        self.txq.len()
    }
    /// Local channel id of an open channel called `name`.
    pub fn lcid_of(&self, name: &str) -> Option<u32> {
        self.channels
            .iter()
            .find(|c| c.name == name && c.is_open())
            .map(|c| c.lcid)
    }
    pub fn is_open(&self, lcid: u32) -> bool {
        self.channels.iter().any(|c| c.lcid == lcid && c.is_open())
    }
    /// Remote intents currently free on `lcid` (size, id).
    pub fn remote_intents(&self, lcid: u32) -> Vec<(u32, u32)> {
        self.channels
            .iter()
            .find(|c| c.lcid == lcid)
            .map(|c| {
                c.riids
                    .iter()
                    .filter(|i| !i.in_use)
                    .map(|i| (i.size, i.id))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn send_version(&mut self, cmd: u16) {
        self.txq
            .push_back((msg(cmd, GLINK_VERSION_1, self.features), Vec::new()));
    }

    fn alloc_lcid(&mut self) -> Result<u32, GlinkError> {
        // `idr_alloc_cyclic(&lcids, .., RPM_GLINK_CID_MIN, RPM_GLINK_CID_MAX)`
        for _ in 0..(GLINK_CID_MAX - GLINK_CID_MIN) {
            let c = self.next_lcid;
            self.next_lcid = if c + 1 >= GLINK_CID_MAX {
                GLINK_CID_MIN
            } else {
                c + 1
            };
            if !self.channels.iter().any(|ch| ch.lcid == c) {
                return Ok(c);
            }
        }
        Err(GlinkError::NoCid)
    }

    /// `qcom_glink_send_open_req`.
    fn send_open(&mut self, idx: usize) -> Result<(), GlinkError> {
        let lcid = self.alloc_lcid()?;
        let ch = &mut self.channels[idx];
        ch.lcid = lcid;
        let name_len = ch.name.len() + 1;
        let mut m = msg(GLINK_CMD_OPEN, lcid as u16, name_len as u32);
        m.extend_from_slice(ch.name.as_bytes());
        m.push(0);
        m.resize(align8(m.len()), 0);
        self.txq.push_back((m, Vec::new()));
        Ok(())
    }

    fn send_open_ack(&mut self, idx: usize) {
        let ch = &mut self.channels[idx];
        ch.acked = true;
        let m = msg(GLINK_CMD_OPEN_ACK, ch.rcid as u16, 0);
        self.txq.push_back((m, Vec::new()));
    }

    /// `qcom_glink_alloc_intent` + `qcom_glink_advertise_intent`.
    fn advertise(&mut self, idx: usize, size: u32, reuse: bool) -> u32 {
        let ch = &mut self.channels[idx];
        // `idr_alloc_cyclic(&liids, intent, 1, -1)`
        let mut id = ch.next_liid;
        while ch.liids.iter().any(|i| i.id == id) {
            id = id.wrapping_add(1).max(1);
        }
        ch.next_liid = id.wrapping_add(1).max(1);
        ch.liids.push(LocalIntent {
            id,
            size,
            reuse,
            data: Vec::new(),
        });
        let mut m = msg(GLINK_CMD_INTENT, ch.lcid as u16, 1);
        m.extend_from_slice(&size.to_le_bytes());
        m.extend_from_slice(&id.to_le_bytes());
        self.txq.push_back((m, Vec::new()));
        id
    }

    /// Drive a channel's open handshake as far as the state allows.
    fn progress(&mut self, idx: usize) {
        let ch = &self.channels[idx];
        if !ch.claimed || ch.announced {
            return;
        }
        if ch.local {
            // `qcom_glink_create_local`: OPEN → (OPEN_ACK, remote OPEN) → OPEN_ACK.
            if ch.open_ack && ch.open_req && !ch.acked {
                self.send_open_ack(idx);
            }
        } else if ch.open_req && ch.lcid == 0 {
            // `qcom_glink_create_remote`: OPEN_ACK then our OPEN.
            self.send_open_ack(idx);
            if self.send_open(idx).is_err() {
                return;
            }
        }
        let ch = &self.channels[idx];
        if ch.open_ack && ch.open_req && ch.acked && !ch.announced {
            // `qcom_glink_announce_create`.
            let base = ch.base_intents.clone();
            for (size, count) in base {
                for _ in 0..count {
                    self.advertise(idx, size, true);
                }
            }
            let ch = &mut self.channels[idx];
            ch.announced = true;
            let ev = GlinkEvent::Open {
                lcid: ch.lcid,
                name: ch.name.clone(),
            };
            self.events.push_back(ev);
        }
    }

    /// Claim remote-initiated channel `name` (an rpmsg driver's id
    /// table), advertising `intents` as (size, count) groups once open.
    pub fn accept(&mut self, name: &str, intents: &[(u32, u32)]) -> Result<(), GlinkError> {
        if name.len() >= GLINK_NAME_SIZE {
            return Err(GlinkError::BadName);
        }
        self.accepts.retain(|(n, _)| n != name);
        self.accepts.push((String::from(name), intents.to_vec()));
        if let Some(idx) = self
            .channels
            .iter()
            .position(|c| c.name == name && !c.claimed)
        {
            self.channels[idx].claimed = true;
            self.channels[idx].base_intents = intents.to_vec();
            self.progress(idx);
            self.flush_tx();
        }
        Ok(())
    }

    /// `qcom_glink_create_local`: open channel `name` from this side.
    /// Returns the lcid; [`GlinkEvent::Open`] reports completion.
    pub fn open(&mut self, name: &str, intents: &[(u32, u32)]) -> Result<u32, GlinkError> {
        if name.len() >= GLINK_NAME_SIZE {
            return Err(GlinkError::BadName);
        }
        let mut ch = Channel::new(name);
        ch.claimed = true;
        ch.local = true;
        ch.base_intents = intents.to_vec();
        self.channels.push(ch);
        let idx = self.channels.len() - 1;
        if let Err(e) = self.send_open(idx) {
            self.channels.pop();
            return Err(e);
        }
        let lcid = self.channels[idx].lcid;
        self.flush_tx();
        Ok(lcid)
    }

    /// `qcom_glink_destroy_ept`: send `CLOSE` for `lcid`.
    pub fn close(&mut self, lcid: u32) -> Result<(), GlinkError> {
        let ch = self
            .channels
            .iter_mut()
            .find(|c| c.lcid == lcid)
            .ok_or(GlinkError::NoChannel(lcid))?;
        ch.claimed = false;
        ch.announced = false;
        ch.txq.clear();
        self.txq
            .push_back((msg(GLINK_CMD_CLOSE, lcid as u16, 0), Vec::new()));
        self.flush_tx();
        Ok(())
    }

    /// `rpmsg_send`: queue one message; it goes out once a remote intent
    /// fits (requesting one if needed) and the FIFO has room.
    pub fn send(&mut self, lcid: u32, data: &[u8]) -> Result<(), GlinkError> {
        if data.is_empty() {
            return Err(GlinkError::TooBig(0));
        }
        let max = self.pipe.tx_len();
        let chunk = data.len().min(GLINK_TX_CHUNK);
        if chunk + GLINK_DATA_HDR_SIZE >= max {
            return Err(GlinkError::TooBig(data.len()));
        }
        let ch = self
            .channels
            .iter_mut()
            .find(|c| c.lcid == lcid)
            .ok_or(GlinkError::NoChannel(lcid))?;
        if !ch.is_open() {
            return Err(GlinkError::NotOpen(lcid));
        }
        ch.txq.push_back(data.to_vec());
        self.service_tx();
        Ok(())
    }

    /// Move queued payloads onto intents and flush the command queue.
    pub fn service_tx(&mut self) {
        for idx in 0..self.channels.len() {
            loop {
                let ch = &mut self.channels[idx];
                let Some(len) = ch.txq.front().map(|d| d.len()) else {
                    break;
                };
                // `__qcom_glink_send`: smallest free intent that fits.
                let mut best: Option<usize> = None;
                for (i, it) in ch.riids.iter().enumerate() {
                    if it.in_use || (it.size as usize) < len {
                        continue;
                    }
                    match best {
                        Some(b) if ch.riids[b].size <= it.size => {}
                        _ => best = Some(i),
                    }
                }
                let Some(b) = best else {
                    if ch.intent_req == IntentReq::Idle {
                        // `qcom_glink_request_intent`.
                        ch.intent_req = IntentReq::Pending { granted: false };
                        let m = msg(GLINK_CMD_RX_INTENT_REQ, ch.lcid as u16, len as u32);
                        self.txq.push_back((m, Vec::new()));
                    }
                    break;
                };
                ch.riids[b].in_use = true;
                ch.intent_req = IntentReq::Idle;
                let iid = ch.riids[b].id;
                let lcid = ch.lcid;
                let data = ch.txq.pop_front().unwrap_or_default();
                let mut off = 0usize;
                while off < data.len() {
                    let n = (data.len() - off).min(GLINK_TX_CHUNK);
                    let cmd = if off == 0 {
                        GLINK_CMD_TX_DATA
                    } else {
                        GLINK_CMD_TX_DATA_CONT
                    };
                    let mut h = msg(cmd, lcid as u16, iid);
                    h.extend_from_slice(&(n as u32).to_le_bytes());
                    h.extend_from_slice(&((data.len() - off - n) as u32).to_le_bytes());
                    self.txq.push_back((h, data[off..off + n].to_vec()));
                    off += n;
                }
            }
        }
        self.flush_tx();
    }

    /// `qcom_glink_tx` without the sleep: write what fits, in order; on
    /// a full FIFO send `READ_NOTIF` once so the remote interrupts us
    /// when it drains.
    fn flush_tx(&mut self) {
        let mut wrote = false;
        while let Some((h, d)) = self.txq.front() {
            let tlen = h.len() + d.len();
            if self.pipe.tx_avail() < tlen {
                self.stats.tx_blocked += 1;
                if !self.sent_read_notify {
                    self.sent_read_notify = true;
                    self.stats.read_notify_sent += 1;
                    let m = msg(GLINK_CMD_READ_NOTIF, 0, 0);
                    self.pipe.tx_write(&m, &[]);
                    wrote = true;
                }
                break;
            }
            self.sent_read_notify = false;
            let (h, d) = self.txq.pop_front().unwrap_or_default();
            self.pipe.tx_write(&h, &d);
            wrote = true;
        }
        if wrote {
            self.pipe.kick();
        }
    }

    fn by_rcid(&self, rcid: u32) -> Option<usize> {
        self.channels
            .iter()
            .position(|c| c.rcid == rcid && c.rcid != 0)
    }
    fn by_lcid(&self, lcid: u32) -> Option<usize> {
        self.channels
            .iter()
            .position(|c| c.lcid == lcid && c.lcid != 0)
    }

    /// `qcom_glink_native_rx`: consume every complete command in the RX
    /// FIFO, then flush whatever the commands queued. Call on each edge
    /// interrupt.
    pub fn process_rx(&mut self) {
        loop {
            let avail = self.pipe.rx_avail();
            if avail < GLINK_MSG_SIZE {
                break;
            }
            let mut hdr = [0u8; GLINK_MSG_SIZE];
            self.pipe.rx_peek(&mut hdr, 0);
            let cmd = u16::from_le_bytes([hdr[0], hdr[1]]);
            let p1 = u16::from_le_bytes([hdr[2], hdr[3]]) as u32;
            let p2 = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            let more = match cmd {
                GLINK_CMD_VERSION => {
                    self.adv(GLINK_MSG_SIZE);
                    self.rx_version(p1, p2);
                    true
                }
                GLINK_CMD_VERSION_ACK => {
                    self.adv(GLINK_MSG_SIZE);
                    self.rx_version_ack(p1, p2);
                    true
                }
                // Upper 16 bits of param2 are the channel priority (Linux v7.2).
                GLINK_CMD_OPEN => self.rx_open(avail, p1, (p2 & 0xffff) as usize),
                GLINK_CMD_OPEN_ACK => {
                    self.adv(GLINK_MSG_SIZE);
                    match self.by_lcid(p1) {
                        Some(i) => {
                            self.channels[i].open_ack = true;
                            self.progress(i);
                        }
                        None => self.stats.unknown_channel += 1,
                    }
                    true
                }
                GLINK_CMD_CLOSE => {
                    self.adv(GLINK_MSG_SIZE);
                    self.rx_close(p1);
                    true
                }
                GLINK_CMD_CLOSE_ACK => {
                    self.adv(GLINK_MSG_SIZE);
                    match self.by_lcid(p1) {
                        Some(i) => {
                            let ch = &mut self.channels[i];
                            ch.lcid = 0;
                            if ch.rcid == 0 {
                                self.channels.remove(i);
                            }
                        }
                        None => self.stats.unknown_channel += 1,
                    }
                    true
                }
                GLINK_CMD_INTENT => self.rx_intent(avail, p1, p2 as usize),
                GLINK_CMD_RX_DONE | GLINK_CMD_RX_DONE_W_REUSE => {
                    self.adv(GLINK_MSG_SIZE);
                    self.rx_done(p1, p2, cmd == GLINK_CMD_RX_DONE_W_REUSE);
                    true
                }
                GLINK_CMD_RX_INTENT_REQ => {
                    self.adv(GLINK_MSG_SIZE);
                    self.rx_intent_req(p1, p2);
                    true
                }
                GLINK_CMD_RX_INTENT_REQ_ACK => {
                    self.adv(GLINK_MSG_SIZE);
                    self.rx_intent_req_ack(p1, p2 != 0);
                    true
                }
                GLINK_CMD_TX_DATA | GLINK_CMD_TX_DATA_CONT => self.rx_data(avail, p1, p2),
                GLINK_CMD_READ_NOTIF => {
                    // `qcom_glink_rx_read_notif`: just kick back.
                    self.adv(GLINK_MSG_SIZE);
                    self.pipe.kick();
                    true
                }
                GLINK_CMD_SIGNALS => {
                    self.adv(GLINK_MSG_SIZE);
                    match self.by_rcid(p1) {
                        Some(i) => {
                            let lcid = self.channels[i].lcid;
                            let enable = p2 & (NATIVE_DSR_SIG | NATIVE_CTS_SIG) != 0;
                            self.events.push_back(GlinkEvent::Flow { lcid, enable });
                        }
                        None => self.stats.unknown_channel += 1,
                    }
                    true
                }
                _ => {
                    // `unhandled rx cmd` → `-EINVAL` stops the loop.
                    self.stats.unknown_cmd += 1;
                    false
                }
            };
            if !more {
                break;
            }
        }
        // `wake_up_all(&glink->tx_avail_notify)`: retry blocked writers.
        self.service_tx();
    }

    fn adv(&mut self, n: usize) {
        self.pipe.rx_advance(align8(n));
    }

    fn rx_version(&mut self, version: u32, features: u32) {
        match version {
            0 => {}
            v => {
                if v == GLINK_VERSION_1 as u32 {
                    self.features &= features;
                }
                self.send_version(GLINK_CMD_VERSION_ACK);
                if !self.negotiated {
                    self.negotiated = true;
                    self.events.push_back(GlinkEvent::Negotiated {
                        features: self.features,
                    });
                }
            }
        }
    }

    fn rx_version_ack(&mut self, version: u32, features: u32) {
        match version {
            0 => {}
            v if v == GLINK_VERSION_1 as u32 && features == self.features => {
                if !self.negotiated {
                    self.negotiated = true;
                    self.events.push_back(GlinkEvent::Negotiated {
                        features: self.features,
                    });
                }
            }
            v => {
                if v == GLINK_VERSION_1 as u32 {
                    self.features &= features;
                }
                self.send_version(GLINK_CMD_VERSION);
            }
        }
    }

    /// `qcom_glink_rx_defer(glink, param2)` + `qcom_glink_rx_open`.
    fn rx_open(&mut self, avail: usize, rcid: u32, name_len: usize) -> bool {
        let total = GLINK_MSG_SIZE + align8(name_len);
        if avail < total {
            return false;
        }
        let mut buf = vec![0u8; name_len];
        self.pipe.rx_peek(&mut buf, GLINK_MSG_SIZE);
        self.pipe.rx_advance(total);
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..end]).into_owned();
        if self.by_rcid(rcid).is_some() {
            // `idr_alloc(&rcids, .., rcid, rcid + 1)` fails.
            self.stats.unknown_channel += 1;
            return true;
        }
        let idx = match self
            .channels
            .iter()
            .position(|c| c.name == name && c.lcid != 0 && c.rcid == 0)
        {
            Some(i) => i,
            None => {
                let mut ch = Channel::new(&name);
                if let Some((_, intents)) = self.accepts.iter().find(|(n, _)| *n == name) {
                    ch.claimed = true;
                    ch.base_intents = intents.clone();
                } else {
                    self.events
                        .push_back(GlinkEvent::RemoteOpen { name: name.clone() });
                }
                self.channels.push(ch);
                self.channels.len() - 1
            }
        };
        self.channels[idx].rcid = rcid;
        self.channels[idx].open_req = true;
        self.progress(idx);
        true
    }

    /// `qcom_glink_rx_close`: ack and forget the remote side; our own
    /// `CLOSE` follows (`rpmsg_unregister_device` → `destroy_ept`).
    fn rx_close(&mut self, rcid: u32) {
        let Some(i) = self.by_rcid(rcid) else {
            self.stats.unknown_channel += 1;
            return;
        };
        self.txq
            .push_back((msg(GLINK_CMD_CLOSE_ACK, rcid as u16, 0), Vec::new()));
        let ch = &mut self.channels[i];
        let was_open = ch.announced;
        let lcid = ch.lcid;
        let name = ch.name.clone();
        ch.rcid = 0;
        ch.open_req = false;
        ch.announced = false;
        ch.acked = false;
        ch.open_ack = false;
        ch.riids.clear();
        ch.liids.clear();
        ch.txq.clear();
        ch.rx_partial = None;
        ch.intent_req = IntentReq::Idle;
        if lcid != 0 {
            self.txq
                .push_back((msg(GLINK_CMD_CLOSE, lcid as u16, 0), Vec::new()));
        } else {
            self.channels.remove(i);
        }
        if was_open {
            self.events.push_back(GlinkEvent::Closed { lcid, name });
        }
    }

    /// `qcom_glink_handle_intent`.
    fn rx_intent(&mut self, avail: usize, rcid: u32, count: usize) -> bool {
        let len = GLINK_MSG_SIZE + count * 8;
        if avail < len {
            return false;
        }
        let mut buf = vec![0u8; count * 8];
        self.pipe.rx_peek(&mut buf, GLINK_MSG_SIZE);
        self.adv(len);
        let Some(i) = self.by_rcid(rcid) else {
            self.stats.unknown_channel += 1;
            return true;
        };
        let ch = &mut self.channels[i];
        for p in buf.chunks_exact(8) {
            let size = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
            let id = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
            if ch.riids.iter().any(|r| r.id == id) {
                // `idr_alloc(&riids, .., iid, iid + 1)` fails.
                continue;
            }
            ch.riids.push(RemoteIntent {
                id,
                size,
                in_use: false,
            });
        }
        true
    }

    /// `qcom_glink_handle_rx_done`.
    fn rx_done(&mut self, rcid: u32, iid: u32, reuse: bool) {
        let Some(i) = self.by_rcid(rcid) else {
            self.stats.unknown_channel += 1;
            return;
        };
        let ch = &mut self.channels[i];
        let Some(k) = ch.riids.iter().position(|r| r.id == iid) else {
            self.stats.no_intent += 1;
            return;
        };
        ch.riids[k].in_use = false;
        if !reuse {
            ch.riids.remove(k);
        }
    }

    /// `qcom_glink_handle_intent_req`: grant with a one-shot intent.
    fn rx_intent_req(&mut self, rcid: u32, size: u32) {
        let Some(i) = self.by_rcid(rcid) else {
            self.stats.unknown_channel += 1;
            return;
        };
        self.advertise(i, size, false);
        let lcid = self.channels[i].lcid;
        self.txq
            .push_back((msg(GLINK_CMD_RX_INTENT_REQ_ACK, lcid as u16, 1), Vec::new()));
    }

    /// `qcom_glink_handle_intent_req_ack`.
    fn rx_intent_req_ack(&mut self, rcid: u32, granted: bool) {
        let Some(i) = self.by_rcid(rcid) else {
            self.stats.unknown_channel += 1;
            return;
        };
        let ch = &mut self.channels[i];
        if granted {
            ch.intent_req = IntentReq::Pending { granted: true };
            // The INTENT that precedes the ack is already stored;
            // `service_tx` (end of `process_rx`) uses it. If none fits,
            // ask again on the next pass.
            let len = ch.txq.front().map(|d| d.len()).unwrap_or(0);
            if !ch.riids.iter().any(|r| !r.in_use && r.size as usize >= len) {
                ch.intent_req = IntentReq::Idle;
            }
        } else {
            ch.intent_req = IntentReq::Idle;
            let lcid = ch.lcid;
            if let Some(d) = ch.txq.pop_front() {
                self.events
                    .push_back(GlinkEvent::SendFailed { lcid, len: d.len() });
            }
        }
    }

    /// `qcom_glink_rx_data` (intent mode).
    fn rx_data(&mut self, avail: usize, rcid: u32, liid: u32) -> bool {
        if avail < GLINK_DATA_HDR_SIZE {
            return false;
        }
        let mut h = [0u8; 8];
        self.pipe.rx_peek(&mut h, GLINK_MSG_SIZE);
        let chunk = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let left = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
        if avail < GLINK_DATA_HDR_SIZE + chunk {
            return false;
        }
        let total = GLINK_DATA_HDR_SIZE + chunk;
        let Some(i) = self.by_rcid(rcid) else {
            self.stats.unknown_channel += 1;
            self.adv(total);
            return true;
        };
        let Some(k) = self.channels[i].liids.iter().position(|l| l.id == liid) else {
            self.stats.no_intent += 1;
            self.adv(total);
            return true;
        };
        let it = &self.channels[i].liids[k];
        if it.size as usize - it.data.len() < chunk {
            // "The packet header lied, drop payload".
            self.stats.intent_overflow += 1;
            self.adv(total);
            return true;
        }
        let mut buf = vec![0u8; chunk];
        self.pipe.rx_peek(&mut buf, GLINK_DATA_HDR_SIZE);
        self.adv(total);
        let ch = &mut self.channels[i];
        ch.liids[k].data.extend_from_slice(&buf);
        ch.rx_partial = Some((liid, ch.liids[k].data.len()));
        if left == 0 {
            ch.rx_partial = None;
            let data = core::mem::take(&mut ch.liids[k].data);
            let lcid = ch.lcid;
            let reuse = ch.liids[k].reuse;
            if !reuse {
                ch.liids.remove(k);
            }
            if ch.announced {
                self.events.push_back(GlinkEvent::Data { lcid, data });
            }
            // `qcom_glink_rx_done_work`.
            let cmd = if reuse {
                GLINK_CMD_RX_DONE_W_REUSE
            } else {
                GLINK_CMD_RX_DONE
            };
            self.txq
                .push_back((msg(cmd, lcid as u16, liid), Vec::new()));
        }
        true
    }
}
