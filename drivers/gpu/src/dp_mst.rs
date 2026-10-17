//! DisplayPort MST sideband messaging and bandwidth math, ported from
//! Linux's drm_dp_mst_topology.c / drm_dp_helper.c and checked against
//! them byte for byte (`tests/dp_mst/check.sh` builds Linux's functions on
//! the host and writes the reference vectors this module's test replays).
//!
//! - `Header` is drm_dp_sideband_msg_hdr with its CRC-4 encode/decode;
//! - `Request::encode` is drm_dp_encode_sideband_req;
//! - `chunks` is process_single_tx_qlock: a message body split into the
//!   48-byte sideband messages written at DP_SIDEBAND_MSG_DOWN_REQ_BASE;
//! - `Rx` reassembles received sideband messages
//!   (drm_dp_sideband_msg_set_header / drm_dp_sideband_append_payload);
//! - `Reply::parse` and `UpRequest::parse` are drm_dp_sideband_parse_reply
//!   and drm_dp_sideband_parse_req;
//! - `calc_pbn_mode`, `pbn_div` and `time_slots` are drm_dp_calc_pbn_mode,
//!   amdgpu's dm_mst_get_pbn_divider and drm_dp_atomic_find_time_slots.
use alloc::vec::Vec;

pub const LINK_ADDRESS: u8 = 0x01;
pub const CONNECTION_STATUS_NOTIFY: u8 = 0x02;
pub const ENUM_PATH_RESOURCES: u8 = 0x10;
pub const ALLOCATE_PAYLOAD: u8 = 0x11;
pub const QUERY_PAYLOAD: u8 = 0x12;
pub const RESOURCE_STATUS_NOTIFY: u8 = 0x13;
pub const CLEAR_PAYLOAD_ID_TABLE: u8 = 0x14;
pub const REMOTE_DPCD_READ: u8 = 0x20;
pub const REMOTE_DPCD_WRITE: u8 = 0x21;
pub const REMOTE_I2C_READ: u8 = 0x22;
pub const REMOTE_I2C_WRITE: u8 = 0x23;
pub const POWER_UP_PHY: u8 = 0x24;
pub const POWER_DOWN_PHY: u8 = 0x25;
/// DP_SIDEBAND_MSG_{DOWN_REQ,UP_REP,DOWN_REP,UP_REQ}_BASE.
pub const DOWN_REQ_BASE: u32 = 0x1000;
pub const UP_REP_BASE: u32 = 0x1200;
pub const DOWN_REP_BASE: u32 = 0x1400;
pub const UP_REQ_BASE: u32 = 0x1600;
/// Peer device types (DP_PEER_DEVICE_*).
pub const PEER_MST_BRANCHING: u8 = 2;
pub const PEER_SST_SINK: u8 = 3;
pub const PEER_DP_LEGACY_CONV: u8 = 4;

/// drm_dp_msg_header_crc4 over `nibbles` leading nibbles.
pub fn header_crc4(data: &[u8], nibbles: usize) -> u8 {
    let mut remainder: u8 = 0;
    for bit in 0..nibbles * 4 {
        remainder = remainder << 1 | (data[bit / 8] >> (7 - bit % 8)) & 1;
        if remainder & 0x10 != 0 {
            remainder ^= 0x13;
        }
    }
    for _ in 0..4 {
        remainder <<= 1;
        if remainder & 0x10 != 0 {
            remainder ^= 0x13;
        }
    }
    remainder
}

/// drm_dp_msg_data_crc4 (a CRC-8 despite its name).
pub fn data_crc(data: &[u8]) -> u8 {
    let mut remainder: u16 = 0;
    for bit in 0..data.len() * 8 {
        remainder = remainder << 1 | u16::from((data[bit / 8] >> (7 - bit % 8)) & 1);
        if remainder & 0x100 != 0 {
            remainder ^= 0xd5;
        }
    }
    for _ in 0..8 {
        remainder <<= 1;
        if remainder & 0x100 != 0 {
            remainder ^= 0xd5;
        }
    }
    remainder as u8
}

/// A sideband message header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Link count total and remaining.
    pub lct: u8,
    pub lcr: u8,
    /// Relative address, a nibble per hop.
    pub rad: [u8; 8],
    pub broadcast: bool,
    pub path_msg: bool,
    /// Body bytes in this message, its CRC included.
    pub msg_len: u8,
    pub somt: bool,
    pub eomt: bool,
    pub seqno: bool,
}
impl Header {
    /// drm_dp_encode_sideband_msg_hdr.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(11);
        buf.push((self.lct & 0xf) << 4 | (self.lcr & 0xf));
        buf.extend_from_slice(&self.rad[..usize::from(self.lct / 2)]);
        buf.push(
            u8::from(self.broadcast) << 7 | u8::from(self.path_msg) << 6 | (self.msg_len & 0x3f),
        );
        buf.push(u8::from(self.somt) << 7 | u8::from(self.eomt) << 6 | u8::from(self.seqno) << 4);
        let crc = header_crc4(&buf, buf.len() * 2 - 1);
        *buf.last_mut().unwrap() |= crc & 0xf;
        buf
    }
    /// drm_dp_decode_sideband_msg_hdr: the header and its length.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.first().copied().unwrap_or(0) == 0 {
            return None;
        }
        let len = 3 + usize::from(buf[0] >> 4) / 2;
        if len > buf.len() || header_crc4(buf, len * 2 - 1) & 0xf != buf[len - 1] & 0xf {
            return None;
        }
        let lct = buf[0] >> 4;
        let mut rad = [0; 8];
        let n = usize::from(lct / 2);
        rad[..n].copy_from_slice(&buf[1..1 + n]);
        let b = buf[1 + n];
        let msg_len = b & 0x3f;
        if msg_len < 1 {
            return None;
        }
        let s = buf[2 + n];
        Some((
            Self {
                lct,
                lcr: buf[0] & 0xf,
                rad,
                broadcast: b >> 7 & 1 != 0,
                path_msg: b >> 6 & 1 != 0,
                msg_len,
                somt: s >> 7 & 1 != 0,
                eomt: s >> 6 & 1 != 0,
                seqno: s >> 4 & 1 != 0,
            },
            3 + n,
        ))
    }
}

/// One I2C write transaction ahead of a REMOTE_I2C_READ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I2cWrite {
    pub device: u8,
    pub bytes: Vec<u8>,
    pub no_stop: bool,
    pub delay: u8,
}

/// A down request body (drm_dp_sideband_msg_req_body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    LinkAddress,
    EnumPathResources {
        port: u8,
    },
    PowerUpPhy {
        port: u8,
    },
    PowerDownPhy {
        port: u8,
    },
    AllocatePayload {
        port: u8,
        vcpi: u8,
        pbn: u16,
        sdp_stream_sinks: Vec<u8>,
    },
    QueryPayload {
        port: u8,
        vcpi: u8,
    },
    RemoteDpcdRead {
        port: u8,
        address: u32,
        len: u8,
    },
    RemoteDpcdWrite {
        port: u8,
        address: u32,
        bytes: Vec<u8>,
    },
    RemoteI2cRead {
        port: u8,
        writes: Vec<I2cWrite>,
        device: u8,
        len: u8,
    },
    RemoteI2cWrite {
        port: u8,
        device: u8,
        bytes: Vec<u8>,
    },
    ClearPayloadIdTable,
}
impl Request {
    pub fn kind(&self) -> u8 {
        match self {
            Self::LinkAddress => LINK_ADDRESS,
            Self::EnumPathResources { .. } => ENUM_PATH_RESOURCES,
            Self::PowerUpPhy { .. } => POWER_UP_PHY,
            Self::PowerDownPhy { .. } => POWER_DOWN_PHY,
            Self::AllocatePayload { .. } => ALLOCATE_PAYLOAD,
            Self::QueryPayload { .. } => QUERY_PAYLOAD,
            Self::RemoteDpcdRead { .. } => REMOTE_DPCD_READ,
            Self::RemoteDpcdWrite { .. } => REMOTE_DPCD_WRITE,
            Self::RemoteI2cRead { .. } => REMOTE_I2C_READ,
            Self::RemoteI2cWrite { .. } => REMOTE_I2C_WRITE,
            Self::ClearPayloadIdTable => CLEAR_PAYLOAD_ID_TABLE,
        }
    }
    /// drm_dp_encode_sideband_req.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = alloc::vec![self.kind() & 0x7f];
        match self {
            Self::LinkAddress | Self::ClearPayloadIdTable => {}
            Self::EnumPathResources { port }
            | Self::PowerUpPhy { port }
            | Self::PowerDownPhy { port } => b.push((port & 0xf) << 4),
            Self::AllocatePayload {
                port,
                vcpi,
                pbn,
                sdp_stream_sinks: s,
            } => {
                b.push((port & 0xf) << 4 | (s.len() as u8 & 0xf));
                b.push(vcpi & 0x7f);
                b.extend_from_slice(&pbn.to_be_bytes());
                for pair in s.chunks(2) {
                    b.push((pair[0] & 0xf) << 4 | pair.get(1).map_or(0, |x| x & 0xf));
                }
            }
            Self::QueryPayload { port, vcpi } => {
                b.push((port & 0xf) << 4);
                b.push(vcpi & 0x7f);
            }
            Self::RemoteDpcdRead { port, address, len } => {
                b.push((port & 0xf) << 4 | (address >> 16 & 0xf) as u8);
                b.extend_from_slice(&(*address as u16).to_be_bytes());
                b.push(*len);
            }
            Self::RemoteDpcdWrite {
                port,
                address,
                bytes,
            } => {
                b.push((port & 0xf) << 4 | (address >> 16 & 0xf) as u8);
                b.extend_from_slice(&(*address as u16).to_be_bytes());
                b.push(bytes.len() as u8);
                b.extend_from_slice(bytes);
            }
            Self::RemoteI2cRead {
                port,
                writes,
                device,
                len,
            } => {
                b.push((port & 0xf) << 4 | (writes.len() as u8 & 3));
                for w in writes.iter().take(3) {
                    b.push(w.device & 0x7f);
                    b.push(w.bytes.len() as u8);
                    b.extend_from_slice(&w.bytes);
                    b.push(u8::from(w.no_stop) << 4 | (w.delay & 0xf));
                }
                b.push(device & 0x7f);
                b.push(*len);
            }
            Self::RemoteI2cWrite {
                port,
                device,
                bytes,
            } => {
                b.push((port & 0xf) << 4);
                b.push(device & 0x7f);
                b.push(bytes.len() as u8);
                b.extend_from_slice(bytes);
            }
        }
        b
    }
}

/// process_single_tx_qlock until the message is sent: `body` to the branch
/// at (`lct`, `rad`) as sideband messages of at most 48 bytes, each its
/// header, a body piece and that piece's CRC. Broadcast types go to every
/// branch (LCT 1, LCR 6). Linux leaves the header's sequence number 0.
pub fn chunks(lct: u8, rad: &[u8; 8], path_msg: bool, body: &[u8]) -> Vec<Vec<u8>> {
    let kind = body.first().copied().unwrap_or(0) & 0x7f;
    let broadcast = matches!(
        kind,
        CONNECTION_STATUS_NOTIFY | RESOURCE_STATUS_NOTIFY | CLEAR_PAYLOAD_ID_TABLE
    );
    let (lct, lcr) = if broadcast {
        (1, 6)
    } else {
        (lct, lct.wrapping_sub(1))
    };
    let mut hdr = Header {
        lct,
        lcr,
        broadcast,
        path_msg,
        ..Header::default()
    };
    let n = usize::from(lct / 2);
    hdr.rad[..n].copy_from_slice(&rad[..n]);
    let space = 48 - 1 - (3 + n);
    let mut out = Vec::new();
    let mut offset = 0;
    loop {
        let len = body.len() - offset;
        let send = len.min(space);
        hdr.somt = offset == 0;
        hdr.eomt = space >= len;
        hdr.msg_len = send as u8 + 1;
        let mut chunk = hdr.encode();
        let piece = &body[offset..offset + send];
        chunk.extend_from_slice(piece);
        chunk.push(data_crc(piece));
        out.push(chunk);
        offset += send;
        if offset == body.len() {
            return out;
        }
    }
}

/// A received message being reassembled (drm_dp_sideband_msg_rx).
#[derive(Clone, Debug)]
pub struct Rx {
    chunk: [u8; 48],
    pub msg: [u8; 256],
    chunk_len: u8,
    chunk_idx: u8,
    /// Body bytes so far (u8, as Linux keeps it).
    pub len: u8,
    pub have_somt: bool,
    pub have_eomt: bool,
    pub initial: Header,
}
impl Default for Rx {
    fn default() -> Self {
        Self {
            chunk: [0; 48],
            msg: [0; 256],
            chunk_len: 0,
            chunk_idx: 0,
            len: 0,
            have_somt: false,
            have_eomt: false,
            initial: Header::default(),
        }
    }
}
impl Rx {
    /// drm_dp_sideband_msg_set_header.
    fn set_header(&mut self, hdr: &Header) -> bool {
        if !hdr.somt && !self.have_somt {
            return false;
        }
        self.chunk_idx = 0;
        self.chunk_len = hdr.msg_len;
        if hdr.somt && self.have_somt {
            return false;
        }
        if hdr.somt {
            self.initial = *hdr;
            self.have_somt = true;
        }
        if hdr.eomt {
            self.have_eomt = true;
        }
        true
    }
    /// drm_dp_sideband_append_payload. A CRC mismatch is only logged by
    /// Linux; the data is kept.
    fn append(&mut self, data: &[u8]) -> bool {
        let (len, idx) = (usize::from(self.chunk_len), usize::from(self.chunk_idx));
        if len == 0 || len > 48 || idx + data.len() > 48 {
            return false;
        }
        self.chunk[idx..idx + data.len()].copy_from_slice(data);
        self.chunk_idx = (idx + data.len()) as u8;
        if usize::from(self.chunk_idx) >= len {
            let total = usize::from(self.len);
            if total + len - 1 > 256 {
                return false;
            }
            self.msg[total..total + len - 1].copy_from_slice(&self.chunk[..len - 1]);
            self.len = (total + len - 1) as u8;
        }
        true
    }
    /// One sideband message as read: header, then its body piece.
    pub fn add(&mut self, raw: &[u8]) -> bool {
        let Some((hdr, hdrlen)) = Header::decode(raw) else {
            return false;
        };
        self.set_header(&hdr) && self.append(&raw[hdrlen..])
    }
    /// The whole message has arrived.
    pub fn complete(&self) -> bool {
        self.have_somt && self.have_eomt
    }
}

/// A port of a LINK_ADDRESS reply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkPort {
    pub input: bool,
    pub peer_device_type: u8,
    pub port: u8,
    pub mcs: bool,
    pub ddps: bool,
    pub legacy_plug: bool,
    pub dpcd_revision: u8,
    pub peer_guid: [u8; 16],
    pub sdp_streams: u8,
    pub sdp_stream_sinks: u8,
}

/// A parsed reply (drm_dp_sideband_msg_reply_body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Nak {
        kind: u8,
        guid: [u8; 16],
        reason: u8,
        data: u8,
    },
    LinkAddress {
        guid: [u8; 16],
        ports: Vec<LinkPort>,
    },
    EnumPathResources {
        port: u8,
        fec: bool,
        full_pbn: u16,
        available_pbn: u16,
    },
    AllocatePayload {
        port: u8,
        vcpi: u8,
        pbn: u16,
    },
    QueryPayload {
        port: u8,
        pbn: u16,
    },
    RemoteDpcdRead {
        port: u8,
        bytes: Vec<u8>,
    },
    RemoteDpcdWrite {
        port: u8,
    },
    RemoteI2cRead {
        port: u8,
        bytes: Vec<u8>,
    },
    RemoteI2cWrite,
    PowerUpDownPhy {
        kind: u8,
        port: u8,
    },
    ClearPayloadIdTable,
}
fn guid(m: &[u8; 256], at: usize) -> [u8; 16] {
    m[at..at + 16].try_into().unwrap()
}
impl Reply {
    /// drm_dp_sideband_parse_reply: None for a malformed or unknown ACK;
    /// a NAK parses (Linux reports it as a failure with its reason).
    pub fn parse(rx: &Rx) -> Option<Self> {
        let m = &rx.msg;
        let len = usize::from(rx.len);
        let kind = m[0] & 0x7f;
        if m[0] & 0x80 != 0 {
            return Some(Self::Nak {
                kind,
                guid: guid(m, 1),
                reason: m[17],
                data: m[18],
            });
        }
        let short = |idx: usize| idx > len;
        Some(match kind {
            LINK_ADDRESS => {
                let g = guid(m, 1);
                let nports = m[17] & 0xf;
                let mut idx = 18;
                if short(idx) {
                    return None;
                }
                let mut ports = Vec::new();
                for _ in 0..nports {
                    let mut p = LinkPort {
                        input: m[idx] & 0x80 != 0,
                        peer_device_type: m[idx] >> 4 & 7,
                        port: m[idx] & 0xf,
                        ..LinkPort::default()
                    };
                    idx += 1;
                    if short(idx) {
                        return None;
                    }
                    p.mcs = m[idx] >> 7 & 1 != 0;
                    p.ddps = m[idx] >> 6 & 1 != 0;
                    if !p.input {
                        p.legacy_plug = m[idx] >> 5 & 1 != 0;
                    }
                    idx += 1;
                    if short(idx) {
                        return None;
                    }
                    if !p.input {
                        p.dpcd_revision = m[idx];
                        idx += 1;
                        if short(idx) {
                            return None;
                        }
                        p.peer_guid = guid(m, idx);
                        idx += 16;
                        if short(idx) {
                            return None;
                        }
                        p.sdp_streams = m[idx] >> 4;
                        p.sdp_stream_sinks = m[idx] & 0xf;
                        idx += 1;
                    }
                    if short(idx) {
                        return None;
                    }
                    ports.push(p);
                }
                Self::LinkAddress { guid: g, ports }
            }
            QUERY_PAYLOAD => {
                if short(4) {
                    return None;
                }
                Self::QueryPayload {
                    port: m[1] >> 4,
                    pbn: u16::from_be_bytes([m[2], m[3]]),
                }
            }
            REMOTE_DPCD_READ | REMOTE_I2C_READ => {
                if short(2) {
                    return None;
                }
                let n = usize::from(m[2]);
                if 3 + n > len {
                    return None;
                }
                let (port, bytes) = (m[1] & 0xf, m[3..3 + n].to_vec());
                if kind == REMOTE_DPCD_READ {
                    Self::RemoteDpcdRead { port, bytes }
                } else {
                    Self::RemoteI2cRead { port, bytes }
                }
            }
            REMOTE_DPCD_WRITE => {
                if short(2) {
                    return None;
                }
                Self::RemoteDpcdWrite { port: m[1] & 0xf }
            }
            REMOTE_I2C_WRITE => Self::RemoteI2cWrite,
            ENUM_PATH_RESOURCES => {
                if 2 + 2 > len || 4 + 2 > len {
                    return None;
                }
                Self::EnumPathResources {
                    port: m[1] >> 4,
                    fec: m[1] & 1 != 0,
                    full_pbn: u16::from_be_bytes([m[2], m[3]]),
                    available_pbn: u16::from_be_bytes([m[4], m[5]]),
                }
            }
            ALLOCATE_PAYLOAD => {
                if short(2) || 3 + 2 > len {
                    return None;
                }
                Self::AllocatePayload {
                    port: m[1] >> 4,
                    vcpi: m[2],
                    pbn: u16::from_be_bytes([m[3], m[4]]),
                }
            }
            POWER_UP_PHY | POWER_DOWN_PHY => {
                if short(2) {
                    return None;
                }
                Self::PowerUpDownPhy {
                    kind,
                    port: m[1] >> 4,
                }
            }
            CLEAR_PAYLOAD_ID_TABLE => Self::ClearPayloadIdTable,
            _ => return None,
        })
    }
}

/// A parsed up request (drm_dp_sideband_parse_req).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpRequest {
    ConnectionStatus {
        port: u8,
        guid: [u8; 16],
        legacy_plug: bool,
        dp_plug: bool,
        message_capable: bool,
        input: bool,
        peer_device_type: u8,
    },
    ResourceStatus {
        port: u8,
        guid: [u8; 16],
        available_pbn: u16,
    },
}
impl UpRequest {
    pub fn parse(rx: &Rx) -> Option<Self> {
        let m = &rx.msg;
        let len = usize::from(rx.len);
        let port = (m[1] & 0xf0) >> 4;
        let kind = m[0] & 0x7f;
        if !matches!(kind, CONNECTION_STATUS_NOTIFY | RESOURCE_STATUS_NOTIFY) || 2 > len || 18 > len
        {
            return None;
        }
        let g = guid(m, 2);
        Some(if kind == CONNECTION_STATUS_NOTIFY {
            Self::ConnectionStatus {
                port,
                guid: g,
                legacy_plug: m[18] >> 6 & 1 != 0,
                dp_plug: m[18] >> 5 & 1 != 0,
                message_capable: m[18] >> 4 & 1 != 0,
                input: m[18] >> 3 & 1 != 0,
                peer_device_type: m[18] & 7,
            }
        } else {
            Self::ResourceStatus {
                port,
                guid: g,
                available_pbn: u16::from_be_bytes([m[18], m[19]]),
            }
        })
    }
    /// drm_dp_encode_up_ack_reply: the ACK body for an up request type.
    pub fn ack(kind: u8) -> [u8; 1] {
        [kind & 0x7f]
    }
}

/// drm_dp_calc_pbn_mode: the PBN of a `clock_khz` stream at `bpp_x16`
/// (1/16 bpp), with Linux's MST and SSC/ref-clock overhead for four lanes
/// and 4096 active pixels.
pub fn calc_pbn_mode(clock_khz: u32, bpp_x16: u32) -> u32 {
    // drm_dp_bw_overhead(4, 4096, 0, bpp, MST | SSC_REF_CLK).
    let overhead: u64 = 1_000_000 + 6000;
    let cycles = (4096 * u64::from(bpp_x16)).div_ceil(16 * 8 * 4);
    let factor = (cycles * 8 * 4 * (overhead * 16)).div_ceil(4096 * u64::from(bpp_x16));
    let num = u64::from(clock_khz.wrapping_mul(bpp_x16)) * ((64 * factor) >> 4);
    num.div_ceil(1_000_000 * 8 * 54 * 1000) as u32
}

/// dm_mst_get_pbn_divider: PBN per time slot as 20.12 fixed point, from
/// the link's bandwidth (dc_link_bandwidth_kbps of its verified caps).
pub fn pbn_div(link_kbps: u32) -> u32 {
    let x100 = (u64::from(link_kbps) * 100 / (8 * 1000 * 54)) as u32;
    (x100 << 12) / 100
}

/// drm_dp_atomic_find_time_slots: MTP time slots for `pbn`.
pub fn time_slots(pbn: u32, pbn_div: u32) -> u32 {
    (pbn << 12).div_ceil(pbn_div)
}

#[cfg(feature = "kernel-test")]
#[path = "dp_mst_tests.rs"]
mod tests;
