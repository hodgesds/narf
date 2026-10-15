//! UDP datagram codec — clean-room.
//!
//! References (public-only):
//! - RFC 768 — User Datagram Protocol (J. Postel, Aug 1980).
//!   <https://datatracker.ietf.org/doc/html/rfc768>
//! - RFC 1071 — Computing the Internet Checksum (mechanism reused
//!   here against the UDP pseudo-header). Public IETF documents.
//!   <https://datatracker.ietf.org/doc/html/rfc1071>
//!
//! No GPL Linux source consulted.
//!
//! ## Header (RFC 768)
//!
//! ```text
//!   bytes 0..1   Source Port (BE)
//!   bytes 2..3   Destination Port (BE)
//!   bytes 4..5   Length (BE, header + data, ≥ 8)
//!   bytes 6..7   Checksum (BE; 0 ⇒ unset on IPv4, mandatory on IPv6)
//! ```
//!
//! ## Pseudo-header (IPv4)
//!
//! For checksum computation the host conceptually prepends a
//! 12-byte pseudo-header in front of the UDP datagram:
//!
//! ```text
//!   bytes 0..3   Source IP
//!   bytes 4..7   Destination IP
//!   byte  8     Zero
//!   byte  9     Protocol (= 17 = IP_PROTO_UDP)
//!   bytes 10..11 UDP length
//! ```

use crate::pkt::{ones_complement_add, ones_complement_sum};

/// UDP header size in bytes.
pub const UDP_HDR_LEN: usize = 8;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn encode(self) -> [u8; UDP_HDR_LEN] {
        let mut out = [0u8; UDP_HDR_LEN];
        out[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&self.length.to_be_bytes());
        out[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < UDP_HDR_LEN {
            return None;
        }
        Some(Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            length: u16::from_be_bytes([buf[4], buf[5]]),
            checksum: u16::from_be_bytes([buf[6], buf[7]]),
        })
    }
}

/// Compute the UDP checksum over the IPv4 pseudo-header + UDP
/// header (with the on-wire checksum field zeroed) + payload. Returns
/// the value to place in the UDP `checksum` field; per RFC 768 a
/// computed value of 0 is transmitted as 0xFFFF so receivers can
/// distinguish "checksum disabled" from "all zero".
pub fn ipv4_pseudo_checksum(src: [u8; 4], dst: [u8; 4], udp: &[u8]) -> u16 {
    // Sum the 12-byte pseudo-header and the datagram in place (no scratch
    // copy of the datagram); the even-length header keeps word alignment.
    let length = udp.len() as u16;
    let ph = [
        src[0],
        src[1],
        src[2],
        src[3],
        dst[0],
        dst[1],
        dst[2],
        dst[3],
        0, // zero
        crate::pkt::IP_PROTO_UDP,
        (length >> 8) as u8,
        length as u8,
    ];
    let sum = !ones_complement_add(ones_complement_sum(&ph), ones_complement_sum(udp));
    if sum == 0 {
        0xFFFF
    } else {
        sum
    }
}

extern crate alloc;

/// Build a complete UDP datagram (header + payload) with checksum
/// pre-installed against the IPv4 pseudo-header. Returns the byte
/// length written.
pub fn build_ipv4(
    out: &mut [u8],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<usize> {
    let total = UDP_HDR_LEN + payload.len();
    if out.len() < total {
        return None;
    }
    let header = UdpHeader {
        src_port,
        dst_port,
        length: total as u16,
        checksum: 0,
    };
    out[..UDP_HDR_LEN].copy_from_slice(&header.encode());
    out[UDP_HDR_LEN..total].copy_from_slice(payload);
    let cs = ipv4_pseudo_checksum(src_ip, dst_ip, &out[..total]);
    out[6..8].copy_from_slice(&cs.to_be_bytes());
    Some(total)
}

/// Verify the UDP checksum of a datagram against an IPv4 pseudo-header.
/// Returns `Ok(())` when the receiver's running ones-complement sum
/// of pseudo-header + datagram is zero (or when the sender disabled
/// the checksum by leaving it at 0).
pub fn verify_ipv4(src_ip: [u8; 4], dst_ip: [u8; 4], datagram: &[u8]) -> Result<(), UdpError> {
    if datagram.len() < UDP_HDR_LEN {
        return Err(UdpError::Short);
    }
    let on_wire = u16::from_be_bytes([datagram[6], datagram[7]]);
    if on_wire == 0 {
        // RFC 768: checksum 0 = disabled (IPv4 only).
        return Ok(());
    }
    // Recompute with the field zeroed.
    let mut probe: alloc::vec::Vec<u8> = datagram.to_vec();
    probe[6] = 0;
    probe[7] = 0;
    let calc = ipv4_pseudo_checksum(src_ip, dst_ip, &probe);
    let calc = if calc == 0xFFFF { 0xFFFF } else { calc };
    if calc != on_wire {
        return Err(UdpError::BadChecksum);
    }
    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UdpError {
    Short,
    BadChecksum,
}
