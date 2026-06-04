//! DHCPv4 client packet codec — clean-room.
//!
//! References (public-only):
//! - RFC 2131 — Dynamic Host Configuration Protocol (R. Droms, Mar
//!   1997). §2 (BOOTP-derived header layout: op/htype/hlen/hops/xid/
//!   secs/flags/ciaddr/yiaddr/siaddr/giaddr/chaddr/sname/file).
//!   §3.1 protocol summary, §4.1 client/server message types.
//!   <https://datatracker.ietf.org/doc/html/rfc2131>
//! - RFC 2132 — DHCP Options and BOOTP Vendor Extensions
//!   (S. Alexander & R. Droms, Mar 1997). All numbered options.
//!   <https://datatracker.ietf.org/doc/html/rfc2132>
//! - RFC 951 — BOOTP base (the 236-byte fixed payload + 64-byte
//!   sname + 128-byte file → total 240 bytes before options).
//!   <https://datatracker.ietf.org/doc/html/rfc951>
//! - RFC 1497 — magic cookie 0x63 0x82 0x53 0x63 prefixing the
//!   options area.
//!   <https://datatracker.ietf.org/doc/html/rfc1497>
//!
//! No GPL Linux source consulted.
//!
//! ## Header layout (RFC 2131 §2, table 1)
//!
//! 240 bytes ahead of the options blob:
//!
//! ```text
//!   byte 0      op       (1 = BOOTREQUEST, 2 = BOOTREPLY)
//!   byte 1      htype    (1 = Ethernet)
//!   byte 2      hlen     (6 for Ethernet)
//!   byte 3      hops
//!   bytes 4..7  xid      (transaction id)
//!   bytes 8..9  secs     (seconds since client started)
//!   bytes 10..11 flags   (bit 15 = BROADCAST)
//!   bytes 12..15 ciaddr  (client IP — only set when in BOUND/RENEW)
//!   bytes 16..19 yiaddr  (your-IP — server fills in for the client)
//!   bytes 20..23 siaddr
//!   bytes 24..27 giaddr  (relay agent)
//!   bytes 28..43 chaddr  (client hardware address; 16 bytes, hlen significant)
//!   bytes 44..107 sname  (64-byte server hostname, NUL-terminated)
//!   bytes 108..235 file  (128-byte boot file name, NUL-terminated)
//!   bytes 236..239 magic cookie 0x63 0x82 0x53 0x63
//! ```
//!
//! Options follow as TLVs: 1-byte tag, 1-byte length, length-byte
//! payload. Tag 0xFF (END) terminates; tag 0x00 (PAD) is filler.

extern crate alloc;

use alloc::vec::Vec;

/// Header byte count + magic cookie.
pub const DHCP_HDR_LEN: usize = 240;

pub const OP_BOOT_REQUEST: u8 = 1;
pub const OP_BOOT_REPLY: u8 = 2;

pub const HTYPE_ETHERNET: u8 = 1;

pub const FLAG_BROADCAST: u16 = 1 << 15;

pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

// ── DHCP option tags (RFC 2132) ────────────────────────────────────

pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_TIME_OFFSET: u8 = 2;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS_SERVER: u8 = 6;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_DOMAIN_NAME: u8 = 15;
/// RFC 2132 §5.1 — interface MTU in bytes (2-byte big-endian value).
pub const OPT_INTERFACE_MTU: u8 = 26;
pub const OPT_BROADCAST_ADDRESS: u8 = 28;
pub const OPT_NTP_SERVERS: u8 = 42;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_OPTION_OVERLOAD: u8 = 52;
pub const OPT_DHCP_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_IDENTIFIER: u8 = 54;
pub const OPT_PARAMETER_REQUEST_LIST: u8 = 55;
pub const OPT_MESSAGE: u8 = 56;
pub const OPT_MAX_MESSAGE_SIZE: u8 = 57;
pub const OPT_RENEWAL_TIME_T1: u8 = 58;
pub const OPT_REBINDING_TIME_T2: u8 = 59;
pub const OPT_VENDOR_CLASS_ID: u8 = 60;
pub const OPT_CLIENT_IDENTIFIER: u8 = 61;
pub const OPT_TFTP_SERVER_NAME: u8 = 66;
pub const OPT_BOOTFILE_NAME: u8 = 67;
pub const OPT_USER_CLASS: u8 = 77;
pub const OPT_CLIENT_FQDN: u8 = 81;
pub const OPT_DOMAIN_SEARCH: u8 = 119;
pub const OPT_END: u8 = 0xFF;

// ── DHCP message types (option 53 values; RFC 2132 §9.6) ───────────

pub const DHCPDISCOVER: u8 = 1;
pub const DHCPOFFER: u8 = 2;
pub const DHCPREQUEST: u8 = 3;
pub const DHCPDECLINE: u8 = 4;
pub const DHCPACK: u8 = 5;
pub const DHCPNAK: u8 = 6;
pub const DHCPRELEASE: u8 = 7;
pub const DHCPINFORM: u8 = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DhcpError {
    Short,
    /// Magic cookie at offset 236 didn't match RFC 1497.
    BadMagic,
    /// Option's length byte exceeds the buffer.
    BadOption,
}

// ── Header ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DhcpHeader {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
}

impl DhcpHeader {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.op);
        out.push(self.htype);
        out.push(self.hlen);
        out.push(self.hops);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.ciaddr);
        out.extend_from_slice(&self.yiaddr);
        out.extend_from_slice(&self.siaddr);
        out.extend_from_slice(&self.giaddr);
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&[0u8; 64]); // sname
        out.extend_from_slice(&[0u8; 128]); // file
        out.extend_from_slice(&MAGIC_COOKIE);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DhcpError> {
        if buf.len() < DHCP_HDR_LEN {
            return Err(DhcpError::Short);
        }
        if buf[236..240] != MAGIC_COOKIE {
            return Err(DhcpError::BadMagic);
        }
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&buf[28..44]);
        let mut ciaddr = [0u8; 4];
        ciaddr.copy_from_slice(&buf[12..16]);
        let mut yiaddr = [0u8; 4];
        yiaddr.copy_from_slice(&buf[16..20]);
        let mut siaddr = [0u8; 4];
        siaddr.copy_from_slice(&buf[20..24]);
        let mut giaddr = [0u8; 4];
        giaddr.copy_from_slice(&buf[24..28]);
        Ok(Self {
            op: buf[0],
            htype: buf[1],
            hlen: buf[2],
            hops: buf[3],
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            secs: u16::from_be_bytes([buf[8], buf[9]]),
            flags: u16::from_be_bytes([buf[10], buf[11]]),
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
        })
    }
}

// ── Option iterator + builder ──────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DhcpOption<'a> {
    pub tag: u8,
    pub data: &'a [u8],
}

/// Walk the options blob (i.e. `&buf[240..]`). Stops at OPT_END
/// (0xFF) or end of buffer; skips OPT_PAD (0x00) bytes.
pub fn iter_options(mut buf: &[u8]) -> impl Iterator<Item = DhcpOption<'_>> {
    core::iter::from_fn(move || {
        loop {
            let head = *buf.first()?;
            match head {
                OPT_END => return None,
                OPT_PAD => {
                    buf = &buf[1..];
                    continue;
                }
                _ => break,
            }
        }
        if buf.len() < 2 {
            return None;
        }
        let tag = buf[0];
        let len = buf[1] as usize;
        if buf.len() < 2 + len {
            return None;
        }
        let data = &buf[2..2 + len];
        buf = &buf[2 + len..];
        Some(DhcpOption { tag, data })
    })
}

/// Append a single option (tag + length + payload) to `out`.
pub fn append_option(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

/// Append the DHCP Message Type option (53).
pub fn append_message_type(out: &mut Vec<u8>, msg_type: u8) {
    append_option(out, OPT_DHCP_MESSAGE_TYPE, &[msg_type]);
}

/// Append the Parameter Request List option (55).
pub fn append_parameter_request_list(out: &mut Vec<u8>, tags: &[u8]) {
    append_option(out, OPT_PARAMETER_REQUEST_LIST, tags);
}

/// Append the Client Identifier option (61) for an Ethernet MAC: the
/// 1-byte hardware-type prefix is 1 (htype Ethernet), followed by the
/// 6-byte MAC.
pub fn append_client_identifier_eth(out: &mut Vec<u8>, mac: &[u8; 6]) {
    let mut buf = [0u8; 7];
    buf[0] = HTYPE_ETHERNET;
    buf[1..7].copy_from_slice(mac);
    append_option(out, OPT_CLIENT_IDENTIFIER, &buf);
}

/// Append the Requested IP Address option (50).
pub fn append_requested_ip(out: &mut Vec<u8>, ip: [u8; 4]) {
    append_option(out, OPT_REQUESTED_IP, &ip);
}

/// Append the Server Identifier option (54).
pub fn append_server_identifier(out: &mut Vec<u8>, ip: [u8; 4]) {
    append_option(out, OPT_SERVER_IDENTIFIER, &ip);
}

/// Mark the end of the options blob (option 255).
pub fn append_end(out: &mut Vec<u8>) {
    out.push(OPT_END);
}

// ── Convenience builders ───────────────────────────────────────────

/// Build a DHCPDISCOVER request. The caller chooses the xid and
/// supplies the client MAC.
pub fn build_discover(xid: u32, mac: [u8; 6]) -> Vec<u8> {
    let mut out = Vec::with_capacity(300);
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);
    let header = DhcpHeader {
        op: OP_BOOT_REQUEST,
        htype: HTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: FLAG_BROADCAST,
        ciaddr: [0; 4],
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
    };
    header.encode_into(&mut out);
    append_message_type(&mut out, DHCPDISCOVER);
    append_client_identifier_eth(&mut out, &mac);
    append_parameter_request_list(
        &mut out,
        &[
            OPT_SUBNET_MASK,
            OPT_ROUTER,
            OPT_DNS_SERVER,
            OPT_DOMAIN_NAME,
            OPT_LEASE_TIME,
            OPT_INTERFACE_MTU,
            OPT_BROADCAST_ADDRESS,
            OPT_RENEWAL_TIME_T1,
            OPT_REBINDING_TIME_T2,
        ],
    );
    append_end(&mut out);
    out
}

/// Build a DHCPREQUEST for lease renewal/rebinding (RENEWING/REBINDING).
///
/// RFC 2131 §4.3.2: in RENEWING the client unicasts to the server; in
/// REBINDING it broadcasts. `ciaddr` is set to the currently-bound
/// address. No Requested-IP or Server-Identifier options are included
/// in renewal REQUESTs per RFC 2131 §4.3.2.
pub fn build_request_renew(xid: u32, mac: [u8; 6], ciaddr: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(300);
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);
    let header = DhcpHeader {
        op: OP_BOOT_REQUEST,
        htype: HTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: 0,
        ciaddr,
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
    };
    header.encode_into(&mut out);
    append_message_type(&mut out, DHCPREQUEST);
    append_client_identifier_eth(&mut out, &mac);
    append_parameter_request_list(
        &mut out,
        &[
            OPT_SUBNET_MASK,
            OPT_ROUTER,
            OPT_DNS_SERVER,
            OPT_LEASE_TIME,
            OPT_RENEWAL_TIME_T1,
            OPT_REBINDING_TIME_T2,
        ],
    );
    append_end(&mut out);
    out
}

/// Build a DHCPDECLINE for an offered address that failed ARP probe.
///
/// RFC 2131 §4.4.1: sent when the client detects the offered address is
/// already in use. Contains Requested-IP-Address + Server-Identifier.
pub fn build_decline(xid: u32, mac: [u8; 6], declined_ip: [u8; 4], server_id: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(300);
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);
    let header = DhcpHeader {
        op: OP_BOOT_REQUEST,
        htype: HTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: FLAG_BROADCAST,
        ciaddr: [0; 4],
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
    };
    header.encode_into(&mut out);
    append_message_type(&mut out, DHCPDECLINE);
    append_requested_ip(&mut out, declined_ip);
    append_server_identifier(&mut out, server_id);
    append_client_identifier_eth(&mut out, &mac);
    append_end(&mut out);
    out
}

/// Build a DHCPRELEASE for clean shutdown (RFC 2131 §4.4.6).
/// `ciaddr` is the currently-bound address. Sent unicast to server.
pub fn build_release(xid: u32, mac: [u8; 6], ciaddr: [u8; 4], server_id: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(300);
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);
    let header = DhcpHeader {
        op: OP_BOOT_REQUEST,
        htype: HTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: 0,
        ciaddr,
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
    };
    header.encode_into(&mut out);
    append_message_type(&mut out, DHCPRELEASE);
    append_server_identifier(&mut out, server_id);
    append_client_identifier_eth(&mut out, &mac);
    append_end(&mut out);
    out
}

/// Build a DHCPINFORM for stateless configuration (RFC 2131 §4.4.3).
/// `ciaddr` is the externally-configured address. Requests options
/// but does not include lease-time options.
pub fn build_inform(xid: u32, mac: [u8; 6], ciaddr: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(300);
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);
    let header = DhcpHeader {
        op: OP_BOOT_REQUEST,
        htype: HTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: FLAG_BROADCAST,
        ciaddr,
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
    };
    header.encode_into(&mut out);
    append_message_type(&mut out, DHCPINFORM);
    append_client_identifier_eth(&mut out, &mac);
    append_parameter_request_list(
        &mut out,
        &[
            OPT_SUBNET_MASK,
            OPT_ROUTER,
            OPT_DNS_SERVER,
            OPT_DOMAIN_NAME,
            OPT_INTERFACE_MTU,
            OPT_BROADCAST_ADDRESS,
        ],
    );
    append_end(&mut out);
    out
}

/// Build a DHCPREQUEST that selects an offer. Carries Server
/// Identifier + Requested IP Address per RFC 2131 §4.3.2.
pub fn build_request(xid: u32, mac: [u8; 6], requested_ip: [u8; 4], server_id: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(300);
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);
    let header = DhcpHeader {
        op: OP_BOOT_REQUEST,
        htype: HTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: FLAG_BROADCAST,
        ciaddr: [0; 4],
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
    };
    header.encode_into(&mut out);
    append_message_type(&mut out, DHCPREQUEST);
    append_requested_ip(&mut out, requested_ip);
    append_server_identifier(&mut out, server_id);
    append_client_identifier_eth(&mut out, &mac);
    append_parameter_request_list(
        &mut out,
        &[
            OPT_SUBNET_MASK,
            OPT_ROUTER,
            OPT_DNS_SERVER,
            OPT_LEASE_TIME,
            OPT_RENEWAL_TIME_T1,
            OPT_REBINDING_TIME_T2,
        ],
    );
    append_end(&mut out);
    out
}
