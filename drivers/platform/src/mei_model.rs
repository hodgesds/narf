//! Register-level model of a CSME HECI function, for the MEI smokes.
//!
//! It implements [`HeciRegs`] the way the hardware behaves from the
//! host's side, so the production protocol code in `crate::mei` runs
//! against it unchanged:
//!
//! - `H_CB_WW` stores push into the host buffer and advance `H_CBWP`;
//!   the `H_IG` doorbell makes "firmware" consume every complete
//!   packet in it (`H_CBRP` catches up) and then refill its own buffer.
//! - `ME_CB_RW` loads pop the firmware buffer and advance `ME_CBRP`;
//!   firmware only refills it on the next doorbell, which the host
//!   rings after each read, as `mei_me_read_slots` does.
//! - `H_RST` empties both buffers, drops every connection and
//!   re-asserts `ME_RDY`.
//!
//! The firmware side answers the HBM handshake, the properties walk,
//! connect / disconnect and flow control, and runs a per-client reply
//! policy (echo, fixed bytes or silence) gated on the host's credits.
//! Replies larger than the firmware buffer are split into packets with
//! `msg_complete` on the last one only. Fault hooks cover device loss,
//! firmware dropping ready, a stalled host buffer, ignored requests and
//! raw packet injection. Everything happens synchronously inside the
//! register access, so the smokes are deterministic.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::mei::{
    data_to_slots, HeciRegs, MeiClientProperties, MeiMsgHdr, MeiUuid, CLIENT_CONNECT_REQ_CMD,
    CLIENT_CONNECT_RES_CMD, CLIENT_DISCONNECT_REQ_CMD, CLIENT_DISCONNECT_RES_CMD,
    HBM_MAJOR_VERSION, HBM_MINOR_VERSION, HOST_CLIENT_PROPERTIES_REQ_CMD,
    HOST_CLIENT_PROPERTIES_RES_CMD, HOST_ENUM_REQ_CMD, HOST_ENUM_RES_CMD, HOST_START_REQ_CMD,
    HOST_START_RES_CMD, HOST_STOP_REQ_CMD, HOST_STOP_RES_CMD, H_D0I3C_IE, H_IE, H_IG, H_RDY, H_RST,
    MEI_CLIENT_PROPERTIES_LEN, MEI_FLOW_CONTROL_CMD, MEI_HBMS_CLIENT_NOT_FOUND, MEI_HBMS_SUCCESS,
    MEI_MSG_MAX_PAYLOAD, ME_RDY_HRA, REG_H_CB_WW, REG_H_CSR, REG_ME_CB_RW, REG_ME_CSR_HA,
};

/// How a firmware client answers a complete host message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// No answer.
    Silent,
    /// The message itself.
    Echo,
    /// These bytes.
    Bytes(Vec<u8>),
}

/// One firmware client.
#[derive(Clone, Debug)]
pub struct ModelClient {
    pub addr: u8,
    pub props: MeiClientProperties,
    /// Status of the properties response for this address.
    pub props_status: u8,
    /// Status of the connect response.
    pub connect_status: u8,
    /// Grant the host one TX credit right after connecting.
    pub grant_on_connect: bool,
    /// Grant the host one TX credit after each complete message.
    pub grant_after_message: bool,
    pub reply: Reply,
}

impl ModelClient {
    /// A dynamic, single-connection client that echoes and keeps the
    /// host supplied with credits.
    pub fn new(addr: u8, uuid: MeiUuid, mtu: u32) -> Self {
        Self {
            addr,
            props: MeiClientProperties {
                protocol_name: uuid,
                protocol_version: 1,
                max_number_of_connections: 1,
                fixed_address: 0,
                single_recv_buf: false,
                vt_supported: false,
                max_msg_length: mtu,
            },
            props_status: MEI_HBMS_SUCCESS,
            connect_status: MEI_HBMS_SUCCESS,
            grant_on_connect: true,
            grant_after_message: true,
            reply: Reply::Echo,
        }
    }
}

/// A packet the host wrote, as firmware consumed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPacket {
    pub hdr: MeiMsgHdr,
    pub data: Vec<u8>,
}

#[derive(Debug)]
struct Conn {
    me: u8,
    host: u8,
    /// Credits the host granted firmware (host RX).
    credits: u32,
    partial: Vec<u8>,
    replies: VecDeque<Vec<u8>>,
}

#[derive(Debug)]
struct State {
    hbuf_depth: u8,
    me_depth: u8,
    h_bits: u32,
    h_wp: u8,
    h_rp: u8,
    hbuf: Vec<u32>,
    me_wp: u8,
    me_rp: u8,
    mebuf: VecDeque<u32>,
    me_ready: bool,
    gone: bool,
    stall: bool,
    ignore_connect: bool,
    ignore_disconnect: bool,
    props_addr_skew: u8,
    clients: Vec<ModelClient>,
    enum_only: Vec<u8>,
    conns: Vec<Conn>,
    outq: VecDeque<Vec<u32>>,
    packets: Vec<HostPacket>,
    delivered: Vec<(u8, u8, Vec<u8>)>,
    resets: u32,
}

fn make_packet(me: u8, host: u8, data: &[u8], complete: bool) -> Vec<u32> {
    let hdr = MeiMsgHdr {
        me_addr: me,
        host_addr: host,
        length: data.len() as u16,
        extended: false,
        dma_ring: false,
        internal: false,
        msg_complete: complete,
    };
    let mut words = vec![hdr.to_u32()];
    for chunk in data.chunks(4) {
        let mut w = [0u8; 4];
        w[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_le_bytes(w));
    }
    words
}

impl State {
    fn client(&self, addr: u8) -> Option<&ModelClient> {
        self.clients.iter().find(|c| c.addr == addr)
    }

    fn conn(&self, me: u8, host: u8) -> Option<usize> {
        self.conns.iter().position(|c| c.me == me && c.host == host)
    }

    fn push_hbm(&mut self, bytes: &[u8]) {
        self.outq.push_back(make_packet(0, 0, bytes, true));
    }

    fn push_fc(&mut self, me: u8, host: u8) {
        self.push_hbm(&[MEI_FLOW_CONTROL_CMD, me, host, 0, 0, 0, 0, 0]);
    }

    fn reset(&mut self) {
        self.resets += 1;
        self.h_bits = H_RST;
        self.hbuf.clear();
        self.h_wp = 0;
        self.h_rp = 0;
        self.mebuf.clear();
        self.me_wp = 0;
        self.me_rp = 0;
        self.outq.clear();
        self.conns.clear();
        self.me_ready = true;
    }

    fn refill(&mut self) {
        loop {
            let Some(len) = self.outq.front().map(Vec::len) else {
                return;
            };
            let filled = self.me_wp.wrapping_sub(self.me_rp);
            let free = self.me_depth.saturating_sub(filled) as usize;
            if len > free {
                return;
            }
            let Some(packet) = self.outq.pop_front() else {
                return;
            };
            for w in packet {
                self.mebuf.push_back(w);
                self.me_wp = self.me_wp.wrapping_add(1);
            }
        }
    }

    fn doorbell(&mut self) {
        if !self.stall && self.h_bits & H_RDY != 0 && !self.hbuf.is_empty() {
            let words = core::mem::take(&mut self.hbuf);
            self.h_rp = self.h_wp;
            let mut i = 0;
            while i < words.len() {
                let hdr = MeiMsgHdr::from_u32(words[i]);
                i += 1;
                let end = (i + data_to_slots(hdr.length as usize) as usize).min(words.len());
                let mut data = Vec::new();
                for w in &words[i..end] {
                    data.extend_from_slice(&w.to_le_bytes());
                }
                data.truncate(hdr.length as usize);
                i = end;
                self.packets.push(HostPacket {
                    hdr,
                    data: data.clone(),
                });
                if hdr.is_hbm() {
                    self.hbm(&data);
                } else {
                    self.client_msg(hdr, data);
                }
            }
        }
        self.refill();
    }

    fn hbm(&mut self, b: &[u8]) {
        let arg = |k: usize| b.get(k).copied().unwrap_or(0);
        match arg(0) {
            HOST_START_REQ_CMD => {
                self.push_hbm(&[HOST_START_RES_CMD, 1, HBM_MINOR_VERSION, HBM_MAJOR_VERSION]);
            }
            HOST_ENUM_REQ_CMD => {
                let mut r = vec![HOST_ENUM_RES_CMD, 0, 0, 0];
                let mut map = [0u8; 32];
                for a in self
                    .clients
                    .iter()
                    .map(|c| c.addr)
                    .chain(self.enum_only.iter().copied())
                {
                    map[(a / 8) as usize] |= 1 << (a % 8);
                }
                r.extend_from_slice(&map);
                self.push_hbm(&r);
            }
            HOST_CLIENT_PROPERTIES_REQ_CMD => {
                let addr = arg(1);
                let mut r = vec![
                    HOST_CLIENT_PROPERTIES_RES_CMD,
                    addr.wrapping_add(self.props_addr_skew),
                    MEI_HBMS_CLIENT_NOT_FOUND,
                    0,
                ];
                match self.client(addr) {
                    Some(c) => {
                        r[2] = c.props_status;
                        r.extend_from_slice(&c.props.to_bytes());
                    }
                    None => r.extend_from_slice(&[0u8; MEI_CLIENT_PROPERTIES_LEN]),
                }
                self.push_hbm(&r);
            }
            CLIENT_CONNECT_REQ_CMD => {
                if self.ignore_connect {
                    return;
                }
                let (me, host) = (arg(1), arg(2));
                let (status, grant) = match self.client(me) {
                    Some(c) => (c.connect_status, c.grant_on_connect),
                    None => (MEI_HBMS_CLIENT_NOT_FOUND, false),
                };
                self.push_hbm(&[CLIENT_CONNECT_RES_CMD, me, host, status]);
                if status == MEI_HBMS_SUCCESS {
                    self.conns.push(Conn {
                        me,
                        host,
                        credits: 0,
                        partial: Vec::new(),
                        replies: VecDeque::new(),
                    });
                    if grant {
                        self.push_fc(me, host);
                    }
                }
            }
            CLIENT_DISCONNECT_REQ_CMD => {
                if self.ignore_disconnect {
                    return;
                }
                let (me, host) = (arg(1), arg(2));
                self.conns.retain(|c| c.me != me || c.host != host);
                self.push_hbm(&[CLIENT_DISCONNECT_RES_CMD, me, host, MEI_HBMS_SUCCESS]);
            }
            CLIENT_DISCONNECT_RES_CMD => {
                let (me, host) = (arg(1), arg(2));
                self.conns.retain(|c| c.me != me || c.host != host);
            }
            MEI_FLOW_CONTROL_CMD => {
                let (me, host) = (arg(1), arg(2));
                if let Some(ci) = self.conn(me, host) {
                    self.conns[ci].credits += 1;
                }
                self.deliver(me, host);
            }
            HOST_STOP_REQ_CMD => self.push_hbm(&[HOST_STOP_RES_CMD, 0, 0, 0]),
            _ => {}
        }
    }

    fn client_msg(&mut self, hdr: MeiMsgHdr, data: Vec<u8>) {
        let (me, host) = (hdr.me_addr, hdr.host_addr);
        let Some(ci) = self.conn(me, host) else {
            return;
        };
        self.conns[ci].partial.extend_from_slice(&data);
        if !hdr.msg_complete {
            return;
        }
        let msg = core::mem::take(&mut self.conns[ci].partial);
        self.delivered.push((me, host, msg.clone()));
        let (reply, grant) = match self.client(me) {
            Some(c) => (
                match &c.reply {
                    Reply::Silent => None,
                    Reply::Echo => Some(msg),
                    Reply::Bytes(b) => Some(b.clone()),
                },
                c.grant_after_message,
            ),
            None => (None, false),
        };
        if let Some(r) = reply {
            self.conns[ci].replies.push_back(r);
        }
        if grant {
            self.push_fc(me, host);
        }
        self.deliver(me, host);
    }

    /// Send queued replies while the host has granted credits, split
    /// to what the firmware buffer holds.
    fn deliver(&mut self, me: u8, host: u8) {
        let max = (usize::from(self.me_depth) * 4)
            .saturating_sub(4)
            .min(MEI_MSG_MAX_PAYLOAD);
        while let Some(ci) = self.conn(me, host) {
            if self.conns[ci].credits == 0 {
                return;
            }
            let Some(r) = self.conns[ci].replies.pop_front() else {
                return;
            };
            self.conns[ci].credits -= 1;
            if r.is_empty() {
                self.outq.push_back(make_packet(me, host, &[], true));
                continue;
            }
            let n = r.chunks(max).count();
            for (k, chunk) in r.chunks(max).enumerate() {
                self.outq
                    .push_back(make_packet(me, host, chunk, k + 1 == n));
            }
        }
    }
}

/// The model. Share it as `Arc<HeciModel>`; hand [`ModelRegs`] to the
/// driver.
#[derive(Debug)]
pub struct HeciModel {
    st: IrqSafeSpinLock<State>,
}

/// The driver's view of a [`HeciModel`].
#[derive(Clone, Debug)]
pub struct ModelRegs(pub Arc<HeciModel>);

impl HeciRegs for ModelRegs {
    fn read32(&self, reg: u64) -> u32 {
        self.0.read32(reg)
    }

    fn write32(&self, reg: u64, value: u32) {
        self.0.write32(reg, value)
    }
}

impl HeciModel {
    /// A ready device with the given buffer depths and clients.
    pub fn new(hbuf_depth: u8, me_depth: u8, clients: Vec<ModelClient>) -> Arc<Self> {
        Arc::new(Self {
            st: IrqSafeSpinLock::new(State {
                hbuf_depth,
                me_depth,
                h_bits: 0,
                h_wp: 0,
                h_rp: 0,
                hbuf: Vec::new(),
                me_wp: 0,
                me_rp: 0,
                mebuf: VecDeque::new(),
                me_ready: true,
                gone: false,
                stall: false,
                ignore_connect: false,
                ignore_disconnect: false,
                props_addr_skew: 0,
                clients,
                enum_only: Vec::new(),
                conns: Vec::new(),
                outq: VecDeque::new(),
                packets: Vec::new(),
                delivered: Vec::new(),
                resets: 0,
            }),
        })
    }

    /// Driver-side register handle.
    pub fn regs(self: &Arc<Self>) -> ModelRegs {
        ModelRegs(self.clone())
    }

    fn read32(&self, reg: u64) -> u32 {
        let mut s = self.st.lock();
        if s.gone {
            return u32::MAX;
        }
        match reg {
            REG_H_CSR => {
                (u32::from(s.hbuf_depth) << 24)
                    | (u32::from(s.h_wp) << 16)
                    | (u32::from(s.h_rp) << 8)
                    | s.h_bits
            }
            REG_ME_CSR_HA => {
                (u32::from(s.me_depth) << 24)
                    | (u32::from(s.me_wp) << 16)
                    | (u32::from(s.me_rp) << 8)
                    | if s.me_ready { ME_RDY_HRA } else { 0 }
            }
            REG_ME_CB_RW => match s.mebuf.pop_front() {
                Some(w) => {
                    s.me_rp = s.me_rp.wrapping_add(1);
                    w
                }
                None => 0,
            },
            _ => 0,
        }
    }

    fn write32(&self, reg: u64, value: u32) {
        let mut s = self.st.lock();
        if s.gone {
            return;
        }
        match reg {
            REG_H_CB_WW => {
                if s.h_wp.wrapping_sub(s.h_rp) < s.hbuf_depth {
                    s.hbuf.push(value);
                    s.h_wp = s.h_wp.wrapping_add(1);
                }
            }
            REG_H_CSR => {
                if value & H_RST != 0 {
                    s.reset();
                } else {
                    s.h_bits = value & (H_RDY | H_IE | H_D0I3C_IE);
                    if value & H_IG != 0 {
                        s.doorbell();
                    }
                }
            }
            _ => {}
        }
    }

    // ── Fault hooks and inspection ──────────────────────────────────

    /// Every register reads all-ones and writes are dropped.
    pub fn set_gone(&self, on: bool) {
        self.st.lock().gone = on;
    }

    /// Firmware drops (or raises) `ME_RDY`.
    pub fn set_me_ready(&self, on: bool) {
        self.st.lock().me_ready = on;
    }

    /// Firmware stops consuming the host buffer.
    pub fn set_stall(&self, on: bool) {
        self.st.lock().stall = on;
    }

    /// Firmware ignores connect requests.
    pub fn set_ignore_connect(&self, on: bool) {
        self.st.lock().ignore_connect = on;
    }

    /// Firmware ignores disconnect requests.
    pub fn set_ignore_disconnect(&self, on: bool) {
        self.st.lock().ignore_disconnect = on;
    }

    /// Properties responses report `addr + skew` instead of `addr`.
    pub fn set_props_addr_skew(&self, skew: u8) {
        self.st.lock().props_addr_skew = skew;
    }

    /// Set `addr` in the enumeration bitmap without a client behind it
    /// (its properties answer `MEI_HBMS_CLIENT_NOT_FOUND`).
    pub fn add_enum_only(&self, addr: u8) {
        self.st.lock().enum_only.push(addr);
    }

    /// Change a client's reply policy.
    pub fn set_reply(&self, me: u8, reply: Reply) {
        if let Some(c) = self.st.lock().clients.iter_mut().find(|c| c.addr == me) {
            c.reply = reply;
        }
    }

    /// Queue a reply from client `me` to host client `host`; it goes
    /// out once the host has a credit outstanding.
    pub fn queue_reply(&self, me: u8, host: u8, data: &[u8]) {
        let mut s = self.st.lock();
        if let Some(ci) = s.conn(me, host) {
            s.conns[ci].replies.push_back(data.to_vec());
        }
        s.deliver(me, host);
        s.refill();
    }

    /// Grant the host one TX credit for `(me, host)`; `host == 0` is a
    /// single-receive-buffer credit.
    pub fn grant(&self, me: u8, host: u8) {
        let mut s = self.st.lock();
        s.push_fc(me, host);
        s.refill();
    }

    /// Queue a bus message from firmware.
    pub fn inject_hbm(&self, bytes: &[u8]) {
        let mut s = self.st.lock();
        s.push_hbm(bytes);
        s.refill();
    }

    /// Queue raw words (header included) from firmware.
    pub fn inject_raw(&self, words: &[u32]) {
        let mut s = self.st.lock();
        s.outq.push_back(words.to_vec());
        s.refill();
    }

    /// Every packet the host wrote since the last clear.
    pub fn packets(&self) -> Vec<HostPacket> {
        self.st.lock().packets.clone()
    }

    pub fn clear_packets(&self) {
        self.st.lock().packets.clear();
    }

    /// Complete client messages firmware received: `(me, host, bytes)`.
    pub fn delivered(&self) -> Vec<(u8, u8, Vec<u8>)> {
        self.st.lock().delivered.clone()
    }

    /// Live connections.
    pub fn conn_count(&self) -> usize {
        self.st.lock().conns.len()
    }

    /// How many times the host asserted `H_RST`.
    pub fn resets(&self) -> u32 {
        self.st.lock().resets
    }

    /// The host-written `H_CSR` control bits.
    pub fn host_bits(&self) -> u32 {
        self.st.lock().h_bits
    }
}
