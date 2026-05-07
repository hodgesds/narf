//! DHCPv6 message codec — clean-room.
//!
//! References (public-only):
//! - RFC 8415 — Dynamic Host Configuration Protocol for IPv6
//!   (T. Mrugalski et al, Nov 2018). §8 Message Formats. §9
//!   Messages between Clients and Servers (4-byte client/server
//!   header). §9.1 Relay Agent Messages (34-byte Relay-forw / Relay-
//!   repl header). §21 Options.
//!   <https://datatracker.ietf.org/doc/html/rfc8415>
//! - RFC 3315 — DHCPv6 (kept for the original IA_NA / IA_TA layouts
//!   that 8415 inherits unchanged).
//!   <https://datatracker.ietf.org/doc/html/rfc3315>
//!
//! No GPL Linux source consulted.
//!
//! ## Client/Server message header (RFC 8415 §8)
//!
//! ```text
//!   byte 0       msg-type
//!   bytes 1..3   transaction-id (24-bit BE — random per request)
//!   bytes 4..N   options (TLV: 16-bit type + 16-bit length + body)
//! ```
//!
//! ## Relay header (RFC 8415 §9.1)
//!
//! ```text
//!   byte 0       msg-type (12 = Relay-forw, 13 = Relay-repl)
//!   byte 1       hop-count
//!   bytes 2..17  link-address (relay's IPv6 address on the network
//!                                where the client lives)
//!   bytes 18..33 peer-address (client's IPv6 link-local address)
//!   bytes 34..N  options (must include OPT_RELAY_MSG)
//! ```

extern crate alloc;

use alloc::vec::Vec;

/// Standard UDP ports.
pub const CLIENT_PORT: u16 = 546;
pub const SERVER_PORT: u16 = 547;

/// Multicast addresses (RFC 8415 §7.1).
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: [u8; 16] = [
    0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02, 0, 0,
];
pub const ALL_DHCP_SERVERS: [u8; 16] = [
    0xFF, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x03, 0, 0,
];

// ── Message types (RFC 8415 §7.3) ──────────────────────────────────

pub const MT_SOLICIT: u8 = 1;
pub const MT_ADVERTISE: u8 = 2;
pub const MT_REQUEST: u8 = 3;
pub const MT_CONFIRM: u8 = 4;
pub const MT_RENEW: u8 = 5;
pub const MT_REBIND: u8 = 6;
pub const MT_REPLY: u8 = 7;
pub const MT_RELEASE: u8 = 8;
pub const MT_DECLINE: u8 = 9;
pub const MT_RECONFIGURE: u8 = 10;
pub const MT_INFORMATION_REQUEST: u8 = 11;
pub const MT_RELAY_FORW: u8 = 12;
pub const MT_RELAY_REPL: u8 = 13;

// ── Option codes (RFC 8415 §21 / IANA registry, selected) ──────────

pub const OPT_CLIENTID: u16 = 1;
pub const OPT_SERVERID: u16 = 2;
pub const OPT_IA_NA: u16 = 3;
pub const OPT_IA_TA: u16 = 4;
pub const OPT_IAADDR: u16 = 5;
pub const OPT_ORO: u16 = 6;
pub const OPT_PREFERENCE: u16 = 7;
pub const OPT_ELAPSED_TIME: u16 = 8;
pub const OPT_RELAY_MSG: u16 = 9;
pub const OPT_AUTH: u16 = 11;
pub const OPT_UNICAST: u16 = 12;
pub const OPT_STATUS_CODE: u16 = 13;
pub const OPT_RAPID_COMMIT: u16 = 14;
pub const OPT_USER_CLASS: u16 = 15;
pub const OPT_VENDOR_CLASS: u16 = 16;
pub const OPT_VENDOR_OPTS: u16 = 17;
pub const OPT_INTERFACE_ID: u16 = 18;
pub const OPT_RECONF_MSG: u16 = 19;
pub const OPT_RECONF_ACCEPT: u16 = 20;
pub const OPT_DNS_SERVERS: u16 = 23;
pub const OPT_DOMAIN_LIST: u16 = 24;
pub const OPT_IA_PD: u16 = 25;
pub const OPT_IAPREFIX: u16 = 26;
pub const OPT_FQDN: u16 = 39;
pub const OPT_SOL_MAX_RT: u16 = 82;

// ── Status codes (RFC 8415 §21.13) ────────────────────────────────

pub const STATUS_SUCCESS: u16 = 0;
pub const STATUS_UNSPEC_FAIL: u16 = 1;
pub const STATUS_NO_ADDRS_AVAIL: u16 = 2;
pub const STATUS_NO_BINDING: u16 = 3;
pub const STATUS_NOT_ON_LINK: u16 = 4;
pub const STATUS_USE_MULTICAST: u16 = 5;
pub const STATUS_NO_PREFIX_AVAIL: u16 = 6;

// ── DUID type values (RFC 8415 §11) ───────────────────────────────

pub const DUID_TYPE_LLT: u16 = 1; // Link-layer + time
pub const DUID_TYPE_EN: u16 = 2;  // Enterprise number
pub const DUID_TYPE_LL: u16 = 3;  // Link-layer
pub const DUID_TYPE_UUID: u16 = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DhcpV6Error {
    Short,
    Truncated,
}

// ── Header ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DhcpV6Header {
    pub msg_type: u8,
    /// 24-bit transaction id (top 8 bits unused).
    pub transaction_id: u32,
}

impl DhcpV6Header {
    pub fn encode(self) -> [u8; 4] {
        [
            self.msg_type,
            ((self.transaction_id >> 16) & 0xFF) as u8,
            ((self.transaction_id >> 8) & 0xFF) as u8,
            (self.transaction_id & 0xFF) as u8,
        ]
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DhcpV6Error> {
        if buf.len() < 4 {
            return Err(DhcpV6Error::Short);
        }
        let xid = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32);
        Ok(Self {
            msg_type: buf[0],
            transaction_id: xid,
        })
    }
}

// ── Relay header ───────────────────────────────────────────────────

pub const RELAY_HDR_LEN: usize = 34;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayHeader {
    pub msg_type: u8,
    pub hop_count: u8,
    pub link_address: [u8; 16],
    pub peer_address: [u8; 16],
}

impl RelayHeader {
    pub fn encode(&self) -> [u8; RELAY_HDR_LEN] {
        let mut out = [0u8; RELAY_HDR_LEN];
        out[0] = self.msg_type;
        out[1] = self.hop_count;
        out[2..18].copy_from_slice(&self.link_address);
        out[18..34].copy_from_slice(&self.peer_address);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DhcpV6Error> {
        if buf.len() < RELAY_HDR_LEN {
            return Err(DhcpV6Error::Short);
        }
        let mut link = [0u8; 16];
        let mut peer = [0u8; 16];
        link.copy_from_slice(&buf[2..18]);
        peer.copy_from_slice(&buf[18..34]);
        Ok(Self {
            msg_type: buf[0],
            hop_count: buf[1],
            link_address: link,
            peer_address: peer,
        })
    }
}

// ── Option iterator + builder ──────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpV6Option<'a> {
    pub code: u16,
    pub data: &'a [u8],
}

/// Walk options (TLVs of `code(u16 BE) + length(u16 BE) + data`).
pub fn iter_options(mut buf: &[u8]) -> impl Iterator<Item = Result<DhcpV6Option<'_>, DhcpV6Error>> {
    core::iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }
        if buf.len() < 4 {
            buf = &[];
            return Some(Err(DhcpV6Error::Short));
        }
        let code = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if 4 + len > buf.len() {
            buf = &[];
            return Some(Err(DhcpV6Error::Truncated));
        }
        let data = &buf[4..4 + len];
        buf = &buf[4 + len..];
        Some(Ok(DhcpV6Option { code, data }))
    })
}

/// Append a single option (code BE + length BE + body).
pub fn append_option(out: &mut Vec<u8>, code: u16, data: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Build an Elapsed Time option (8). Value is in 1/100 second units;
/// 0xFFFF = "saturated" (RFC 8415 §21.9).
pub fn append_elapsed_time(out: &mut Vec<u8>, hundredths: u16) {
    append_option(out, OPT_ELAPSED_TIME, &hundredths.to_be_bytes());
}

/// Build a Client DUID option from a DUID_LL (link-layer) value:
/// `[type=3 BE | hardware-type BE | link-layer-address]`.
pub fn append_clientid_duid_ll(out: &mut Vec<u8>, hardware_type: u16, link_layer_addr: &[u8]) {
    let mut body = Vec::with_capacity(4 + link_layer_addr.len());
    body.extend_from_slice(&DUID_TYPE_LL.to_be_bytes());
    body.extend_from_slice(&hardware_type.to_be_bytes());
    body.extend_from_slice(link_layer_addr);
    append_option(out, OPT_CLIENTID, &body);
}

/// Append an Option Request Option (ORO, code 6) — list of 16-bit
/// option codes the client wants the server to include.
pub fn append_oro(out: &mut Vec<u8>, codes: &[u16]) {
    let mut body = Vec::with_capacity(codes.len() * 2);
    for c in codes {
        body.extend_from_slice(&c.to_be_bytes());
    }
    append_option(out, OPT_ORO, &body);
}

/// Append a Rapid Commit option (14, RFC 8415 §21.14 — body is empty).
pub fn append_rapid_commit(out: &mut Vec<u8>) {
    append_option(out, OPT_RAPID_COMMIT, &[]);
}

// ── Convenience builder ────────────────────────────────────────────

/// Build a SOLICIT message body (header + Client ID + Elapsed Time
/// + ORO).
pub fn build_solicit(transaction_id: u32, mac: [u8; 6], oro: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    let header = DhcpV6Header {
        msg_type: MT_SOLICIT,
        transaction_id: transaction_id & 0x00FF_FFFF,
    };
    out.extend_from_slice(&header.encode());
    append_clientid_duid_ll(&mut out, 1, &mac); // hardware-type 1 = Ethernet
    append_elapsed_time(&mut out, 0);
    append_oro(&mut out, oro);
    out
}
