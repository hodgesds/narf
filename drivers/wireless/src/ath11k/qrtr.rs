//! QRTR (Qualcomm IPC Router) framing over the MHI `IPCR` channels
//! (20 = host→device UL, 21 = device→host DL).
//!
//! Each MHI transfer carries exactly one QRTR packet:
//!
//! ```text
//! struct qrtr_hdr_v1 (32 bytes, every field __le32)
//!   version(=1) type src_node src_port confirm_rx size dst_node dst_port
//! payload[size], zero-padded to a multiple of 4
//! ```
//!
//! Control packets (`HELLO`, `NEW_SERVER`, …) are addressed to
//! `QRTR_PORT_CTRL` and carry a 20-byte `struct qrtr_ctrl_pkt`; QMI
//! messages ride in `DATA` packets between two ports.
//!
//! The host side of Linux splits this across `af_qrtr.c` (framing,
//! node-id assignment, flow control), `ns.c` (the name service that
//! answers `HELLO` and tracks remote servers) and `qmi_interface.c`
//! (the lookup client). NARF has no QRTR socket layer, so
//! [`QrtrLink`] folds the parts that matter for one MHI endpoint
//! into a pure frame-in / frame-out state machine: it answers the
//! remote's `HELLO`, learns the servers the remote announces, matches
//! them against registered lookups (WLFW: service `0x45`), and frames
//! QMI payloads as DATA with Linux's flow-control `confirm_rx` rule.
//!
//! Linux references (GPL-2.0, citation + adaptation permitted):
//! - `include/uapi/linux/qrtr.h` — `QRTR_NODE_BCAST`,
//!   `QRTR_PORT_CTRL`, `enum qrtr_pkt_type`, `struct qrtr_ctrl_pkt`.
//! - `net/qrtr/af_qrtr.c` — `struct qrtr_hdr_v1/v2`,
//!   `qrtr_endpoint_post` (receive validation), `qrtr_node_enqueue`
//!   (transmit framing), `qrtr_tx_wait` / `qrtr_tx_resume` (flow
//!   control), `qrtr_send_resume_tx`, `qrtr_node_assign`.
//! - `net/qrtr/ns.c` — `ctrl_cmd_hello`, `ctrl_cmd_bye`,
//!   `ctrl_cmd_new_server`, `ctrl_cmd_del_server`,
//!   `ctrl_cmd_del_client`, `ctrl_cmd_new_lookup`, `server_match`.
//! - `net/qrtr/mhi.c` — one packet per MHI buffer, `MHI_EOT`.
//! - `drivers/soc/qcom/qmi_interface.c` — `qmi_send_new_lookup`
//!   (`instance = version | instance << 8`), `qmi_recv_new_server`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Constants ──────────────────────────────────────────────────────

/// `QRTR_PROTO_VER_1` — the only version Linux transmits.
pub const QRTR_PROTO_VER_1: u8 = 1;
/// `QRTR_PROTO_VER_2` (accepted on receive).
pub const QRTR_PROTO_VER_2: u8 = 3;

/// `QRTR_NODE_BCAST`.
pub const QRTR_NODE_BCAST: u32 = 0xffff_ffff;
/// `QRTR_PORT_CTRL`.
pub const QRTR_PORT_CTRL: u32 = 0xffff_fffe;
/// `QRTR_PORT_CTRL_LEGACY` — rewritten to `QRTR_PORT_CTRL` on receive.
pub const QRTR_PORT_CTRL_LEGACY: u32 = 0xffff;
/// `QRTR_EP_NID_AUTO` (`(-1)` as unsigned) — endpoint node id before
/// the first received packet names it.
pub const QRTR_EP_NID_AUTO: u32 = 0xffff_ffff;
/// Linux's default `qrtr_local_nid`.
pub const QRTR_DEFAULT_LOCAL_NODE: u32 = 1;
/// Ephemeral (auto-bind) port range, `QRTR_MIN/MAX_EPH_SOCKET`.
pub const QRTR_MIN_EPH_SOCKET: u32 = 0x4000;
pub const QRTR_MAX_EPH_SOCKET: u32 = 0x7fff;

pub const QRTR_TYPE_DATA: u32 = 1;
pub const QRTR_TYPE_HELLO: u32 = 2;
pub const QRTR_TYPE_BYE: u32 = 3;
pub const QRTR_TYPE_NEW_SERVER: u32 = 4;
pub const QRTR_TYPE_DEL_SERVER: u32 = 5;
pub const QRTR_TYPE_DEL_CLIENT: u32 = 6;
pub const QRTR_TYPE_RESUME_TX: u32 = 7;
pub const QRTR_TYPE_EXIT: u32 = 8;
pub const QRTR_TYPE_PING: u32 = 9;
pub const QRTR_TYPE_NEW_LOOKUP: u32 = 10;
pub const QRTR_TYPE_DEL_LOOKUP: u32 = 11;

/// `sizeof(struct qrtr_hdr_v1)`.
pub const QRTR_HDR_V1_SIZE: usize = 32;
/// `sizeof(struct qrtr_hdr_v2)` (before `optlen` bytes).
pub const QRTR_HDR_V2_SIZE: usize = 16;
/// `sizeof(struct qrtr_ctrl_pkt)` — `cmd` + the 16-byte union.
pub const QRTR_CTRL_PKT_SIZE: usize = 20;
/// `QRTR_FLAGS_CONFIRM_RX` (v2 `flags`).
pub const QRTR_FLAGS_CONFIRM_RX: u8 = 1 << 0;
/// `qrtr_sendmsg` refuses payloads above this (`-EMSGSIZE`).
pub const QRTR_MAX_PAYLOAD: usize = 65535;

/// `QRTR_TX_FLOW_HIGH` — senders block at this many unacknowledged
/// DATA packets per destination.
pub const QRTR_TX_FLOW_HIGH: u32 = 10;
/// `QRTR_TX_FLOW_LOW` — the packet that brings the count to this
/// carries `confirm_rx`.
pub const QRTR_TX_FLOW_LOW: u32 = 5;

const fn align4(n: u64) -> u64 {
    (n + 3) & !3
}

// ── Errors ─────────────────────────────────────────────────────────

/// Why a frame was refused. Receive-side variants are the
/// `goto err` (`-EINVAL`) branches of `qrtr_endpoint_post`, in its
/// check order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QrtrError {
    /// `len == 0 || len & 3`.
    BadLength,
    /// First byte is neither 1 nor 3 ("qrtr: Invalid version").
    BadVersion(u8),
    /// Shorter than the version's fixed header.
    ShortHeader,
    /// `!size || len != ALIGN(size, 4) + hdrlen`.
    SizeMismatch,
    /// `NEW_SERVER` / `RESUME_TX` with `size < sizeof(qrtr_ctrl_pkt)`.
    ShortControl,
    /// Neither DATA nor RESUME_TX, yet not addressed to the control
    /// port.
    NotToControlPort,
    /// Control payload shorter than 20 bytes
    /// (`qmi_recv_ctrl_pkt` "ignoring short control packet").
    ShortControlPayload,
    /// Transmit payload over 65535 bytes (`qrtr_sendmsg` `-EMSGSIZE`).
    PayloadTooLarge,
    /// Transmit would exceed `QRTR_TX_FLOW_HIGH` unacknowledged
    /// packets — Linux sleeps in `qrtr_tx_wait` until RESUME_TX.
    FlowBlocked,
}

// ── Packet framing ─────────────────────────────────────────────────

/// A received packet, as `qrtr_endpoint_post` fills `struct qrtr_cb`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QrtrPacket<'a> {
    pub version: u8,
    pub pkt_type: u32,
    pub src_node: u32,
    pub src_port: u32,
    pub dst_node: u32,
    pub dst_port: u32,
    pub confirm_rx: bool,
    /// Exactly `size` bytes (padding stripped).
    pub payload: &'a [u8],
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// Validate and parse one received buffer — `qrtr_endpoint_post`
/// minus the socket delivery.
pub fn decode_packet(data: &[u8]) -> Result<QrtrPacket<'_>, QrtrError> {
    let len = data.len();
    if len == 0 || len & 3 != 0 {
        return Err(QrtrError::BadLength);
    }
    // v1's version is a __le32 but Linux, like this, looks only at
    // the first byte.
    let ver = data[0];
    let (mut pkt, hdrlen, size) = match ver {
        QRTR_PROTO_VER_1 => {
            if len < QRTR_HDR_V1_SIZE {
                return Err(QrtrError::ShortHeader);
            }
            (
                QrtrPacket {
                    version: ver,
                    pkt_type: le32(data, 4),
                    src_node: le32(data, 8),
                    src_port: le32(data, 12),
                    confirm_rx: le32(data, 16) != 0,
                    dst_node: le32(data, 24),
                    dst_port: le32(data, 28),
                    payload: &[],
                },
                QRTR_HDR_V1_SIZE,
                le32(data, 20),
            )
        }
        QRTR_PROTO_VER_2 => {
            if len < QRTR_HDR_V2_SIZE {
                return Err(QrtrError::ShortHeader);
            }
            let mut src_port = le16(data, 10) as u32;
            let mut dst_port = le16(data, 14) as u32;
            if src_port == QRTR_PORT_CTRL & 0xffff {
                src_port = QRTR_PORT_CTRL;
            }
            if dst_port == QRTR_PORT_CTRL & 0xffff {
                dst_port = QRTR_PORT_CTRL;
            }
            (
                QrtrPacket {
                    version: ver,
                    pkt_type: data[1] as u32,
                    confirm_rx: data[2] & QRTR_FLAGS_CONFIRM_RX != 0,
                    src_node: le16(data, 8) as u32,
                    src_port,
                    dst_node: le16(data, 12) as u32,
                    dst_port,
                    payload: &[],
                },
                QRTR_HDR_V2_SIZE + data[3] as usize,
                le32(data, 4),
            )
        }
        other => return Err(QrtrError::BadVersion(other)),
    };

    if pkt.dst_port == QRTR_PORT_CTRL_LEGACY {
        pkt.dst_port = QRTR_PORT_CTRL;
    }

    if size == 0 || len as u64 != align4(size as u64) + hdrlen as u64 {
        return Err(QrtrError::SizeMismatch);
    }

    if (pkt.pkt_type == QRTR_TYPE_NEW_SERVER || pkt.pkt_type == QRTR_TYPE_RESUME_TX)
        && (size as usize) < QRTR_CTRL_PKT_SIZE
    {
        return Err(QrtrError::ShortControl);
    }

    if pkt.dst_port != QRTR_PORT_CTRL
        && pkt.pkt_type != QRTR_TYPE_DATA
        && pkt.pkt_type != QRTR_TYPE_RESUME_TX
    {
        return Err(QrtrError::NotToControlPort);
    }

    pkt.payload = &data[hdrlen..hdrlen + size as usize];
    Ok(pkt)
}

/// Addressing for one transmitted packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QrtrAddr {
    pub node: u32,
    pub port: u32,
}

/// Frame `payload` as a v1 packet — `qrtr_node_enqueue`: header,
/// `size = payload.len()`, zero padding to a 4-byte multiple
/// (`skb_put_padto`). `confirm_rx` goes on the wire as 0 or 1.
pub fn encode_packet(
    pkt_type: u32,
    src: QrtrAddr,
    dst: QrtrAddr,
    confirm_rx: bool,
    payload: &[u8],
) -> Result<Vec<u8>, QrtrError> {
    if payload.len() > QRTR_MAX_PAYLOAD {
        return Err(QrtrError::PayloadTooLarge);
    }
    let padded = align4(payload.len() as u64) as usize;
    let mut out = Vec::with_capacity(QRTR_HDR_V1_SIZE + padded);
    for w in [
        QRTR_PROTO_VER_1 as u32,
        pkt_type,
        src.node,
        src.port,
        confirm_rx as u32,
        payload.len() as u32,
        dst.node,
        dst.port,
    ] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(payload);
    out.resize(QRTR_HDR_V1_SIZE + padded, 0);
    Ok(out)
}

// ── Control packets ────────────────────────────────────────────────

/// `struct qrtr_ctrl_pkt`, by `cmd`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CtrlPkt {
    Hello,
    /// `client.node` = the departing node.
    Bye {
        node: u32,
    },
    NewServer {
        service: u32,
        instance: u32,
        node: u32,
        port: u32,
    },
    DelServer {
        service: u32,
        instance: u32,
        node: u32,
        port: u32,
    },
    DelClient {
        node: u32,
        port: u32,
    },
    ResumeTx {
        node: u32,
        port: u32,
    },
    Exit,
    Ping,
    /// `server.service`, `server.instance`; node/port zero.
    NewLookup {
        service: u32,
        instance: u32,
    },
    DelLookup {
        service: u32,
        instance: u32,
    },
    /// Any other `cmd` (ignored by the name service).
    Other {
        cmd: u32,
    },
}

impl CtrlPkt {
    pub fn cmd(&self) -> u32 {
        match *self {
            CtrlPkt::Hello => QRTR_TYPE_HELLO,
            CtrlPkt::Bye { .. } => QRTR_TYPE_BYE,
            CtrlPkt::NewServer { .. } => QRTR_TYPE_NEW_SERVER,
            CtrlPkt::DelServer { .. } => QRTR_TYPE_DEL_SERVER,
            CtrlPkt::DelClient { .. } => QRTR_TYPE_DEL_CLIENT,
            CtrlPkt::ResumeTx { .. } => QRTR_TYPE_RESUME_TX,
            CtrlPkt::Exit => QRTR_TYPE_EXIT,
            CtrlPkt::Ping => QRTR_TYPE_PING,
            CtrlPkt::NewLookup { .. } => QRTR_TYPE_NEW_LOOKUP,
            CtrlPkt::DelLookup { .. } => QRTR_TYPE_DEL_LOOKUP,
            CtrlPkt::Other { cmd } => cmd,
        }
    }

    /// The 20 wire bytes; unused union words are zero (every Linux
    /// sender `memset`s the packet first).
    pub fn to_bytes(&self) -> [u8; QRTR_CTRL_PKT_SIZE] {
        let words: [u32; 5] = match *self {
            CtrlPkt::NewServer {
                service,
                instance,
                node,
                port,
            }
            | CtrlPkt::DelServer {
                service,
                instance,
                node,
                port,
            } => [self.cmd(), service, instance, node, port],
            CtrlPkt::NewLookup { service, instance } | CtrlPkt::DelLookup { service, instance } => {
                [self.cmd(), service, instance, 0, 0]
            }
            CtrlPkt::Bye { node } => [self.cmd(), node, 0, 0, 0],
            CtrlPkt::DelClient { node, port } | CtrlPkt::ResumeTx { node, port } => {
                [self.cmd(), node, port, 0, 0]
            }
            _ => [self.cmd(), 0, 0, 0, 0],
        };
        let mut out = [0u8; QRTR_CTRL_PKT_SIZE];
        for (i, w) in words.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Parse a control payload. Under 20 bytes is refused, as
    /// `qmi_recv_ctrl_pkt` does; extra bytes are ignored.
    pub fn parse(b: &[u8]) -> Result<Self, QrtrError> {
        if b.len() < QRTR_CTRL_PKT_SIZE {
            return Err(QrtrError::ShortControlPayload);
        }
        let w = |i: usize| le32(b, i * 4);
        Ok(match w(0) {
            QRTR_TYPE_HELLO => CtrlPkt::Hello,
            QRTR_TYPE_BYE => CtrlPkt::Bye { node: w(1) },
            QRTR_TYPE_NEW_SERVER => CtrlPkt::NewServer {
                service: w(1),
                instance: w(2),
                node: w(3),
                port: w(4),
            },
            QRTR_TYPE_DEL_SERVER => CtrlPkt::DelServer {
                service: w(1),
                instance: w(2),
                node: w(3),
                port: w(4),
            },
            QRTR_TYPE_DEL_CLIENT => CtrlPkt::DelClient {
                node: w(1),
                port: w(2),
            },
            QRTR_TYPE_RESUME_TX => CtrlPkt::ResumeTx {
                node: w(1),
                port: w(2),
            },
            QRTR_TYPE_EXIT => CtrlPkt::Exit,
            QRTR_TYPE_PING => CtrlPkt::Ping,
            QRTR_TYPE_NEW_LOOKUP => CtrlPkt::NewLookup {
                service: w(1),
                instance: w(2),
            },
            QRTR_TYPE_DEL_LOOKUP => CtrlPkt::DelLookup {
                service: w(1),
                instance: w(2),
            },
            cmd => CtrlPkt::Other { cmd },
        })
    }
}

/// QMI's packing of a service version + instance into the QRTR
/// `instance` word (`qmi_send_new_lookup`): `version | instance << 8`.
pub const fn qmi_instance(version: u32, instance: u32) -> u32 {
    version | (instance << 8)
}

// ── Link state machine ─────────────────────────────────────────────

/// A server the remote announced (`struct qrtr_server` in `ns.c`).
/// `instance` is the raw QRTR word; [`Self::qmi_version`] /
/// [`Self::qmi_instance`] split it as `qmi_recv_new_server` does.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QrtrServer {
    pub service: u32,
    pub instance: u32,
    pub node: u32,
    pub port: u32,
}

impl QrtrServer {
    pub fn qmi_version(&self) -> u32 {
        self.instance & 0xff
    }

    pub fn qmi_instance(&self) -> u32 {
        self.instance >> 8
    }

    pub fn addr(&self) -> QrtrAddr {
        QrtrAddr {
            node: self.node,
            port: self.port,
        }
    }
}

/// A registered lookup (`struct qrtr_lookup`); zero fields are
/// wildcards.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QrtrLookup {
    pub service: u32,
    pub instance: u32,
}

impl QrtrLookup {
    /// `ns.c::server_match` with the filter `ctrl_cmd_new_lookup`
    /// builds (also the test `ctrl_cmd_new_server` applies).
    pub fn matches(&self, srv: &QrtrServer) -> bool {
        if self.service != 0 && srv.service != self.service {
            return false;
        }
        let ifilter = if self.instance != 0 { !0u32 } else { 0 };
        (srv.instance & ifilter) == self.instance
    }
}

/// What a received frame meant for the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrtrEvent {
    /// A server matching a registered lookup appeared
    /// (`lookup_notify(.., true)` → `qmi_recv_new_server`).
    NewServer(QrtrServer),
    /// A server matching a registered lookup went away (DEL_SERVER,
    /// or the remote's BYE / DEL_CLIENT).
    DelServer(QrtrServer),
    /// A DATA packet — for WLFW, one QMI message.
    Data {
        src: QrtrAddr,
        dst_port: u32,
        payload: Vec<u8>,
    },
    /// RESUME_TX: the flow toward `(node, port)` was reset.
    ResumeTx { node: u32, port: u32 },
}

/// Result of [`QrtrLink::receive`]: frames to queue on the UL
/// channel, then events for the host, both in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QrtrRx {
    pub tx: Vec<Vec<u8>>,
    pub events: Vec<QrtrEvent>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct TxFlow {
    dst: QrtrAddr,
    pending: u32,
}

/// Host-side QRTR state for one MHI endpoint: the local node, the
/// remote node id once learned, the remote's servers, the host's
/// lookups, and per-destination TX flow counters.
#[derive(Clone, Debug)]
pub struct QrtrLink {
    local_node: u32,
    remote_node: u32,
    hello_seen: bool,
    servers: Vec<QrtrServer>,
    lookups: Vec<QrtrLookup>,
    flows: Vec<TxFlow>,
}

impl QrtrLink {
    /// `local_node` is Linux's `qrtr_local_nid` (default
    /// [`QRTR_DEFAULT_LOCAL_NODE`]).
    pub fn new(local_node: u32) -> Self {
        Self {
            local_node,
            remote_node: QRTR_EP_NID_AUTO,
            hello_seen: false,
            servers: Vec::new(),
            lookups: Vec::new(),
            flows: Vec::new(),
        }
    }

    pub fn local_node(&self) -> u32 {
        self.local_node
    }

    /// The endpoint's node id: `QRTR_EP_NID_AUTO` until the first
    /// valid received packet (`qrtr_node_assign`).
    pub fn remote_node(&self) -> u32 {
        self.remote_node
    }

    /// Whether the remote's HELLO has arrived (and been answered).
    pub fn hello_seen(&self) -> bool {
        self.hello_seen
    }

    pub fn servers(&self) -> &[QrtrServer] {
        &self.servers
    }

    fn ctrl_src(&self) -> QrtrAddr {
        QrtrAddr {
            node: self.local_node,
            port: QRTR_PORT_CTRL,
        }
    }

    /// A control packet from the local name service to the endpoint.
    /// `qrtr_node_enqueue` rewrites a control destination to
    /// `(node->nid, QRTR_PORT_CTRL)`, whatever node was asked for.
    fn ctrl_frame(&self, pkt: CtrlPkt) -> Vec<u8> {
        let dst = QrtrAddr {
            node: self.remote_node,
            port: QRTR_PORT_CTRL,
        };
        // A 20-byte payload can never exceed the size limit.
        encode_packet(pkt.cmd(), self.ctrl_src(), dst, false, &pkt.to_bytes()).unwrap_or_default()
    }

    /// The HELLO the local name service broadcasts on start
    /// (`qrtr_ns_init` → `say_hello(&bcast_sq)`); before the remote
    /// has spoken its destination node is `QRTR_EP_NID_AUTO`.
    pub fn hello_frame(&self) -> Vec<u8> {
        self.ctrl_frame(CtrlPkt::Hello)
    }

    /// Register a lookup (`qmi_add_lookup` → local NEW_LOOKUP →
    /// `ctrl_cmd_new_lookup`). Local only: nothing goes on the wire.
    /// Returns a [`QrtrEvent::NewServer`] for each already-known
    /// matching server (the end-of-listing empty notification Linux
    /// sends is dropped by `qmi_recv_new_server` and not modelled).
    pub fn add_lookup(&mut self, service: u32, instance: u32) -> Vec<QrtrEvent> {
        let l = QrtrLookup { service, instance };
        self.lookups.push(l);
        self.servers
            .iter()
            .filter(|s| l.matches(s))
            .map(|s| QrtrEvent::NewServer(*s))
            .collect()
    }

    /// The NEW_LOOKUP control payload `qmi_send_new_lookup` builds for
    /// a QMI service — for reference/tests; the packet goes to the
    /// *local* name service, not over MHI.
    pub fn new_lookup_payload(
        service: u32,
        version: u32,
        instance: u32,
    ) -> [u8; QRTR_CTRL_PKT_SIZE] {
        CtrlPkt::NewLookup {
            service,
            instance: qmi_instance(version, instance),
        }
        .to_bytes()
    }

    fn notify(&self, srv: &QrtrServer, new: bool, events: &mut Vec<QrtrEvent>) {
        // `lookup_notify` fires once per matching lookup.
        for l in &self.lookups {
            if l.service != 0 && l.service != srv.service {
                continue;
            }
            if l.instance != 0 && l.instance != srv.instance {
                continue;
            }
            events.push(if new {
                QrtrEvent::NewServer(*srv)
            } else {
                QrtrEvent::DelServer(*srv)
            });
        }
    }

    fn server_del(&mut self, node: u32, port: u32, events: &mut Vec<QrtrEvent>) {
        if let Some(i) = self
            .servers
            .iter()
            .position(|s| s.node == node && s.port == port)
        {
            let srv = self.servers.remove(i);
            self.notify(&srv, false, events);
        }
    }

    /// A control payload as `qrtr_ns_worker` reads it: it switches on
    /// `cmd` alone, and HELLO / BYE / EXIT / PING use no other field,
    /// so those are honoured from just the 4-byte `cmd`. Any command
    /// that reads the union needs the full 20 bytes (Linux would read
    /// stale buffer contents).
    fn parse_ns_ctrl(payload: &[u8]) -> Result<CtrlPkt, QrtrError> {
        if payload.len() >= QRTR_CTRL_PKT_SIZE {
            return CtrlPkt::parse(payload);
        }
        if payload.len() < 4 {
            return Err(QrtrError::ShortControlPayload);
        }
        match le32(payload, 0) {
            cmd @ (QRTR_TYPE_HELLO | QRTR_TYPE_BYE | QRTR_TYPE_EXIT | QRTR_TYPE_PING) => {
                let mut full = [0u8; QRTR_CTRL_PKT_SIZE];
                full[..4].copy_from_slice(&cmd.to_le_bytes());
                CtrlPkt::parse(&full)
            }
            _ => Err(QrtrError::ShortControlPayload),
        }
    }

    /// Handle one DL buffer. A frame `qrtr_endpoint_post` would refuse
    /// is returned as `Err` with no state change; a control packet
    /// the name service would refuse (spoofed DEL_CLIENT, NEW_SERVER
    /// with service or port 0, remote lookups) is accepted and
    /// ignored, as Linux logs and continues.
    pub fn receive(&mut self, frame: &[u8]) -> Result<QrtrRx, QrtrError> {
        let pkt = decode_packet(frame)?;
        let ctrl = if pkt.dst_port == QRTR_PORT_CTRL || pkt.pkt_type == QRTR_TYPE_RESUME_TX {
            Some(Self::parse_ns_ctrl(pkt.payload)?)
        } else {
            None
        };

        let mut rx = QrtrRx::default();
        // qrtr_node_assign(node, cb->src_node): only the first id sticks.
        if self.remote_node == QRTR_EP_NID_AUTO && pkt.src_node != QRTR_EP_NID_AUTO {
            self.remote_node = pkt.src_node;
        }

        if pkt.pkt_type == QRTR_TYPE_RESUME_TX {
            // qrtr_tx_resume: key on the ctrl packet's client node/port.
            if let Some(CtrlPkt::ResumeTx { node, port }) = ctrl {
                if let Some(f) = self
                    .flows
                    .iter_mut()
                    .find(|f| f.dst.node == node && f.dst.port == port)
                {
                    f.pending = 0;
                }
                rx.events.push(QrtrEvent::ResumeTx { node, port });
            }
            return Ok(rx);
        }

        let Some(ctrl) = ctrl else {
            // DATA (or another type) to a client port. qrtr_recvmsg
            // answers confirm_rx with RESUME_TX from the receiving
            // port back to the sender.
            if pkt.confirm_rx {
                let resume = CtrlPkt::ResumeTx {
                    node: pkt.dst_node,
                    port: pkt.dst_port,
                };
                let local = QrtrAddr {
                    node: pkt.dst_node,
                    port: pkt.dst_port,
                };
                let remote = QrtrAddr {
                    node: pkt.src_node,
                    port: pkt.src_port,
                };
                let dst = if remote.port == QRTR_PORT_CTRL {
                    QrtrAddr {
                        node: self.remote_node,
                        port: QRTR_PORT_CTRL,
                    }
                } else {
                    remote
                };
                if let Ok(f) =
                    encode_packet(QRTR_TYPE_RESUME_TX, local, dst, false, &resume.to_bytes())
                {
                    rx.tx.push(f);
                }
            }
            rx.events.push(QrtrEvent::Data {
                src: QrtrAddr {
                    node: pkt.src_node,
                    port: pkt.src_port,
                },
                dst_port: pkt.dst_port,
                payload: pkt.payload.to_vec(),
            });
            return Ok(rx);
        };

        // Control packet for the local name service; `from` is the
        // packet's source address (`qrtr_ns_worker`'s `sq`).
        let from_node = pkt.src_node;
        match ctrl {
            CtrlPkt::Hello => {
                // ctrl_cmd_hello: say_hello(sq), then announce local
                // servers (NARF hosts none).
                self.hello_seen = true;
                rx.tx.push(self.ctrl_frame(CtrlPkt::Hello));
            }
            CtrlPkt::Bye { .. } => {
                // ctrl_cmd_bye: drop every server of the sending node.
                let gone: Vec<QrtrServer> = self
                    .servers
                    .iter()
                    .filter(|s| s.node == from_node)
                    .copied()
                    .collect();
                for s in gone {
                    self.server_del(s.node, s.port, &mut rx.events);
                }
            }
            CtrlPkt::NewServer {
                service,
                instance,
                node,
                port,
            } => {
                // ctrl_cmd_new_server → server_add: service and port
                // must be non-zero; a server on the same (node, port)
                // is replaced.
                if self.remote_node == QRTR_EP_NID_AUTO && node != QRTR_EP_NID_AUTO {
                    // The NEW_SERVER branch of qrtr_endpoint_post also
                    // assigns server.node to the endpoint.
                    self.remote_node = node;
                }
                if service != 0 && port != 0 {
                    let srv = QrtrServer {
                        service,
                        instance,
                        node,
                        port,
                    };
                    if let Some(old) = self
                        .servers
                        .iter_mut()
                        .find(|s| s.node == node && s.port == port)
                    {
                        *old = srv;
                    } else {
                        self.servers.push(srv);
                    }
                    self.notify(&srv, true, &mut rx.events);
                }
            }
            CtrlPkt::DelServer { node, port, .. } => {
                self.server_del(node, port, &mut rx.events);
            }
            CtrlPkt::DelClient { node, port } => {
                // ctrl_cmd_del_client: refuse spoofed packets, else drop
                // the server on that port (no broadcast).
                if from_node == node {
                    self.server_del(node, port, &mut rx.events);
                }
            }
            // EXIT / PING / RESUME_TX-to-ctrl need nothing; the name
            // service only accepts lookups from local observers.
            CtrlPkt::ResumeTx { .. }
            | CtrlPkt::Exit
            | CtrlPkt::Ping
            | CtrlPkt::NewLookup { .. }
            | CtrlPkt::DelLookup { .. }
            | CtrlPkt::Other { .. } => {}
        }
        Ok(rx)
    }

    /// Frame a QMI message as DATA from local `src_port` to `dst` —
    /// `qrtr_sendmsg` → `qrtr_tx_wait` → `qrtr_node_enqueue`. The
    /// packet that brings the destination's pending count to
    /// `QRTR_TX_FLOW_LOW` carries `confirm_rx`; at
    /// `QRTR_TX_FLOW_HIGH` pending, `FlowBlocked` until the remote's
    /// RESUME_TX (Linux sleeps there).
    pub fn data_frame(
        &mut self,
        src_port: u32,
        dst: QrtrAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, QrtrError> {
        if payload.len() > QRTR_MAX_PAYLOAD {
            return Err(QrtrError::PayloadTooLarge);
        }
        let idx = match self.flows.iter().position(|f| f.dst == dst) {
            Some(i) => i,
            None => {
                self.flows.push(TxFlow { dst, pending: 0 });
                self.flows.len() - 1
            }
        };
        if self.flows[idx].pending >= QRTR_TX_FLOW_HIGH {
            return Err(QrtrError::FlowBlocked);
        }
        self.flows[idx].pending += 1;
        let confirm_rx = self.flows[idx].pending == QRTR_TX_FLOW_LOW;
        let src = QrtrAddr {
            node: self.local_node,
            port: src_port,
        };
        let wire_dst = if dst.port == QRTR_PORT_CTRL {
            QrtrAddr {
                node: self.remote_node,
                port: QRTR_PORT_CTRL,
            }
        } else {
            dst
        };
        encode_packet(QRTR_TYPE_DATA, src, wire_dst, confirm_rx, payload)
    }

    /// Unacknowledged DATA packets toward `dst`.
    pub fn pending(&self, dst: QrtrAddr) -> u32 {
        self.flows
            .iter()
            .find(|f| f.dst == dst)
            .map_or(0, |f| f.pending)
    }
}
