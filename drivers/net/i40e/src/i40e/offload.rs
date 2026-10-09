//! i40e checksum and TSO offload.
//!
//! Offload on this part is driven entirely from descriptor fields:
//! there is no per-queue "enable checksums" switch. The transmit
//! descriptor's `CMD` field says *what* the headers are, and its
//! `OFFSET` field says *where* they end, and the device computes
//! checksums from that. TSO additionally needs a context descriptor
//! placed immediately ahead of the data descriptor.
//!
//! The part that bites is the units. The three header lengths packed
//! into `OFFSET` are not bytes and not the same scale as each other:
//!
//! | Field  | Unit         | Width  |
//! |--------|--------------|--------|
//! | MACLEN | 2-byte words | 7 bits |
//! | IPLEN  | 4-byte dwords| 7 bits |
//! | L4LEN  | 4-byte dwords| 4 bits |
//!
//! A byte count written straight into any of them is silently wrong
//! by a factor of two or four, and because the field is narrow it
//! also wraps: a 20-byte IP header written as 20 instead of 5 still
//! fits, so the device simply computes the checksum over the wrong
//! span and emits a corrupt frame rather than failing.
//!
//! The encoders below take byte counts and do the conversion, and
//! reject a length that is not a whole number of units or does not
//! fit its field.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `i40e_type.h` — `i40e_tx_desc_cmd_bits`,
//!   `i40e_tx_desc_length_fields`, `i40e_tx_context_desc`,
//!   `I40E_TXD_CTX_QW1_*`, `i40e_rx_desc_status_bits`,
//!   `i40e_rx_desc_error_bits`.
//! - `i40e_txrx.c` — `i40e_tx_enable_csum` (the unit conversions),
//!   `i40e_tso`, `i40e_rx_checksum`.

#![allow(dead_code)]

// ── Transmit CMD bits ───────────────────────────────────────────────
//
// These are values within the 12-bit CMD field, which itself sits at
// bit 4 of the descriptor's second qword.

/// `IIPT` — no IP header; leave the L3 checksum alone.
pub const TX_CMD_IIPT_NONIP: u64 = 0x0000;
/// `IIPT` — IPv6. There is no IPv6 header checksum, so this only
/// tells the device where L4 begins.
pub const TX_CMD_IIPT_IPV6: u64 = 0x0020;
/// `IIPT` — IPv4, header checksum already correct.
pub const TX_CMD_IIPT_IPV4: u64 = 0x0040;
/// `IIPT` — IPv4, and compute the header checksum.
pub const TX_CMD_IIPT_IPV4_CSUM: u64 = 0x0060;

/// `L4T` — unknown L4; no transport checksum.
pub const TX_CMD_L4T_UNKNOWN: u64 = 0x0000;
/// `L4T` — TCP.
pub const TX_CMD_L4T_TCP: u64 = 0x0100;
/// `L4T` — SCTP.
pub const TX_CMD_L4T_SCTP: u64 = 0x0200;
/// `L4T` — UDP.
pub const TX_CMD_L4T_UDP: u64 = 0x0300;

// ── OFFSET sub-fields ───────────────────────────────────────────────

/// MACLEN — L2 header length, in 2-byte words, at bit 0 of `OFFSET`.
pub const TX_OFFSET_MACLEN_SHIFT: u32 = 0;
/// MACLEN is seven bits wide.
pub const TX_OFFSET_MACLEN_MASK: u64 = 0x7F;
/// IPLEN — L3 header length, in dwords, at bit 7 of `OFFSET`.
pub const TX_OFFSET_IPLEN_SHIFT: u32 = 7;
/// IPLEN is seven bits wide.
pub const TX_OFFSET_IPLEN_MASK: u64 = 0x7F;
/// L4LEN — L4 header length, in dwords, at bit 14 of `OFFSET`.
pub const TX_OFFSET_L4LEN_SHIFT: u32 = 14;
/// L4LEN is four bits wide.
pub const TX_OFFSET_L4LEN_MASK: u64 = 0xF;

/// Largest L2 header the MACLEN field can describe, in bytes.
pub const MAX_MACLEN_BYTES: u16 = (TX_OFFSET_MACLEN_MASK as u16) * 2;
/// Largest L3 header the IPLEN field can describe, in bytes.
pub const MAX_IPLEN_BYTES: u16 = (TX_OFFSET_IPLEN_MASK as u16) * 4;
/// Largest L4 header the L4LEN field can describe, in bytes.
pub const MAX_L4LEN_BYTES: u16 = (TX_OFFSET_L4LEN_MASK as u16) * 4;

/// Why an offload descriptor could not be built.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OffloadError {
    /// A header length is not a whole number of the field's units,
    /// so it cannot be represented at all.
    NotAWholeUnit {
        /// Which header: "maclen", "iplen" or "l4len".
        field: &'static str,
        /// The byte length that does not divide.
        bytes: u16,
    },
    /// A header length does not fit its field.
    TooLong {
        /// Which header.
        field: &'static str,
        /// The byte length that does not fit.
        bytes: u16,
    },
    /// The segment size is zero or wider than the MSS field.
    BadMss(u16),
    /// The payload to segment does not fit the TSO length field.
    TsoLengthTooLarge(u32),
}

/// Header boundaries of a frame being transmitted, in bytes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderLens {
    /// Bytes of L2 header, i.e. where the IP header starts.
    pub mac: u16,
    /// Bytes of L3 header.
    pub ip: u16,
    /// Bytes of L4 header.
    pub l4: u16,
}

/// Encode header lengths into the descriptor's `OFFSET` field.
///
/// Takes byte counts and converts; a length that is not a whole
/// number of units is rejected rather than truncated, because a
/// truncated length still produces a valid-looking descriptor that
/// checksums the wrong span.
pub const fn tx_offset_field(lens: HeaderLens) -> Result<u64, OffloadError> {
    if lens.mac % 2 != 0 {
        return Err(OffloadError::NotAWholeUnit {
            field: "maclen",
            bytes: lens.mac,
        });
    }
    if lens.ip % 4 != 0 {
        return Err(OffloadError::NotAWholeUnit {
            field: "iplen",
            bytes: lens.ip,
        });
    }
    if lens.l4 % 4 != 0 {
        return Err(OffloadError::NotAWholeUnit {
            field: "l4len",
            bytes: lens.l4,
        });
    }
    if lens.mac > MAX_MACLEN_BYTES {
        return Err(OffloadError::TooLong {
            field: "maclen",
            bytes: lens.mac,
        });
    }
    if lens.ip > MAX_IPLEN_BYTES {
        return Err(OffloadError::TooLong {
            field: "iplen",
            bytes: lens.ip,
        });
    }
    if lens.l4 > MAX_L4LEN_BYTES {
        return Err(OffloadError::TooLong {
            field: "l4len",
            bytes: lens.l4,
        });
    }
    Ok((((lens.mac / 2) as u64) << TX_OFFSET_MACLEN_SHIFT)
        | (((lens.ip / 4) as u64) << TX_OFFSET_IPLEN_SHIFT)
        | (((lens.l4 / 4) as u64) << TX_OFFSET_L4LEN_SHIFT))
}

/// What the device should checksum on transmit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxCsum {
    /// Leave both checksums alone.
    None,
    /// IPv4, compute the header checksum and the transport checksum.
    Ipv4 {
        /// Transport-layer protocol.
        l4: L4Proto,
    },
    /// IPv6; there is no header checksum to compute.
    Ipv6 {
        /// Transport-layer protocol.
        l4: L4Proto,
    },
}

/// Transport protocols the device can checksum.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum L4Proto {
    /// No transport checksum.
    None,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// SCTP.
    Sctp,
}

impl L4Proto {
    /// The `L4T` bits for this protocol.
    pub const fn cmd_bits(self) -> u64 {
        match self {
            L4Proto::None => TX_CMD_L4T_UNKNOWN,
            L4Proto::Tcp => TX_CMD_L4T_TCP,
            L4Proto::Udp => TX_CMD_L4T_UDP,
            L4Proto::Sctp => TX_CMD_L4T_SCTP,
        }
    }
}

impl TxCsum {
    /// The `CMD` bits describing this combination.
    ///
    /// `tso` selects `IPV4_CSUM` over `IPV4`: segmentation rewrites
    /// the length and identification fields of every segment, so the
    /// header checksum the host computed is wrong for all but the
    /// first and the device has to recompute it.
    pub const fn cmd_bits(self, tso: bool) -> u64 {
        match self {
            TxCsum::None => TX_CMD_IIPT_NONIP,
            TxCsum::Ipv4 { l4 } => {
                let iipt = if tso {
                    TX_CMD_IIPT_IPV4_CSUM
                } else {
                    TX_CMD_IIPT_IPV4
                };
                iipt | l4.cmd_bits()
            }
            TxCsum::Ipv6 { l4 } => TX_CMD_IIPT_IPV6 | l4.cmd_bits(),
        }
    }
}

// ── TSO context descriptor ──────────────────────────────────────────

/// `I40E_TX_DESC_DTYPE_CONTEXT`.
pub const TX_DESC_DTYPE_CONTEXT: u64 = 0x1;
/// `I40E_TX_CTX_DESC_TSO` — the context command bit for segmentation.
pub const TX_CTX_DESC_TSO: u64 = 0x01;
/// Context `CMD` field shift.
pub const TXD_CTX_QW1_CMD_SHIFT: u32 = 4;
/// Payload length to segment, 20 bits at 30.
pub const TXD_CTX_QW1_TSO_LEN_SHIFT: u32 = 30;
/// Mask for the TSO length field.
pub const TXD_CTX_QW1_TSO_LEN_MASK: u64 = 0xF_FFFF;
/// Maximum segment size, 14 bits at 50.
pub const TXD_CTX_QW1_MSS_SHIFT: u32 = 50;
/// Mask for the MSS field.
pub const TXD_CTX_QW1_MSS_MASK: u64 = 0x3FFF;

/// Build the two qwords of an `i40e_tx_context_desc` for TSO.
///
/// `payload_len` is the data to be segmented — the frame length
/// *minus* the headers, not the whole frame. Passing the whole frame
/// makes the device emit one segment too many.
pub const fn tso_context_desc(payload_len: u32, mss: u16) -> Result<(u64, u64), OffloadError> {
    if mss == 0 || mss as u64 > TXD_CTX_QW1_MSS_MASK {
        return Err(OffloadError::BadMss(mss));
    }
    if payload_len as u64 > TXD_CTX_QW1_TSO_LEN_MASK {
        return Err(OffloadError::TsoLengthTooLarge(payload_len));
    }
    // qword0 carries tunnelling parameters and L2TAG2, neither of
    // which this path uses.
    let qw0 = 0u64;
    let qw1 = TX_DESC_DTYPE_CONTEXT
        | (TX_CTX_DESC_TSO << TXD_CTX_QW1_CMD_SHIFT)
        | ((payload_len as u64) << TXD_CTX_QW1_TSO_LEN_SHIFT)
        | ((mss as u64) << TXD_CTX_QW1_MSS_SHIFT);
    Ok((qw0, qw1))
}

// ── Receive checksum ────────────────────────────────────────────────

/// `I40E_RX_DESC_STATUS_L3L4P_SHIFT` — the device examined L3/L4.
pub const RX_STATUS_L3L4P_SHIFT: u32 = 3;
/// `I40E_RX_DESC_ERROR_IPE_SHIFT` — IP header checksum was wrong.
pub const RX_ERROR_IPE_SHIFT: u32 = 3;
/// `I40E_RX_DESC_ERROR_L4E_SHIFT` — transport checksum was wrong.
pub const RX_ERROR_L4E_SHIFT: u32 = 4;
/// `I40E_RX_DESC_ERROR_EIPE_SHIFT` — outer IP checksum was wrong.
pub const RX_ERROR_EIPE_SHIFT: u32 = 5;

/// What the device concluded about a received frame's checksums.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsum {
    /// The device did not examine L3/L4, so the host must verify.
    NotChecked,
    /// Checked and correct.
    Good,
    /// Checked and wrong.
    Bad {
        /// The IP header checksum failed.
        ip: bool,
        /// The transport checksum failed.
        l4: bool,
        /// The outer IP checksum failed, on a tunnelled frame.
        outer_ip: bool,
    },
}

/// Decode the checksum verdict from a receive descriptor.
///
/// `status` and `error` are the fields already extracted from the
/// descriptor's second qword. A frame the device did not examine is
/// reported as [`RxCsum::NotChecked`] rather than as good: treating
/// "not checked" as "correct" is how a corrupt frame gets accepted.
pub const fn rx_checksum(status: u64, error: u8) -> RxCsum {
    if status & (1 << RX_STATUS_L3L4P_SHIFT) == 0 {
        return RxCsum::NotChecked;
    }
    let ip = error & (1 << RX_ERROR_IPE_SHIFT) != 0;
    let l4 = error & (1 << RX_ERROR_L4E_SHIFT) != 0;
    let outer_ip = error & (1 << RX_ERROR_EIPE_SHIFT) != 0;
    if ip || l4 || outer_ip {
        RxCsum::Bad { ip, l4, outer_ip }
    } else {
        RxCsum::Good
    }
}

/// The runtime accepts a bounded, non-tunnelled offload profile. The limit
/// includes Ethernet headers and fits in seventeen 4-KiB data descriptors.
pub const MAX_TSO_BYTES: usize = 65_535;

/// Validated descriptor fields and checksum preparation offsets.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TxPlan {
    pub command: u64,
    pub offset: u64,
    pub context: Option<(u64, u64)>,
    ip: usize,
    checksum: usize,
    ipv4: bool,
    seed: u16,
}

fn be16(packet: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

fn sum_words(bytes: &[u8]) -> u32 {
    bytes
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as u32)
        .sum()
}

impl TxPlan {
    pub fn parse(packet: &[u8], meta: narf_net::TxMeta) -> Result<Self, super::I40eError> {
        use narf_net::L4CsumKind;
        let bad = super::I40eError::InvalidOffload;
        if meta.vlan_tag.is_some() {
            return Err(bad);
        }
        if packet.len() < 14 || packet.len() > MAX_TSO_BYTES {
            return Err(super::I40eError::FrameTooLong);
        }
        let mut plan = Self {
            command: 0,
            offset: 0,
            context: None,
            ip: 0,
            checksum: 0,
            ipv4: false,
            seed: 0,
        };
        let mut ip = 14;
        let mut ether = be16(packet, 12);
        // In-band VLAN headers stay in the packet. Limit parsing to QinQ.
        for _ in 0..2 {
            if ether != 0x8100 && ether != 0x88a8 {
                break;
            }
            if packet.len() < ip + 4 {
                return Err(bad);
            }
            ether = be16(packet, ip + 2);
            ip += 4;
        }
        if meta.tso_mss.is_none() && packet.len() > ip + 1500 {
            return Err(super::I40eError::FrameTooLong);
        }
        if meta.csum_l4.is_none() && meta.tso_mss.is_none() {
            return Ok(plan);
        }
        let (ip_len, protocol, l4_len, mut sum) = match ether {
            0x0800 => {
                if packet.len() < ip + 20 || packet[ip] >> 4 != 4 {
                    return Err(bad);
                }
                let ihl = (packet[ip] as usize & 15) * 4;
                let total = be16(packet, ip + 2) as usize;
                if ihl < 20
                    || total < ihl
                    || ip + total != packet.len()
                    || be16(packet, ip + 6) & 0x3fff != 0
                {
                    return Err(bad);
                }
                (
                    ihl,
                    packet[ip + 9],
                    total - ihl,
                    sum_words(&packet[ip + 12..ip + 20]),
                )
            }
            0x86dd => {
                if packet.len() < ip + 40 || packet[ip] >> 4 != 6 {
                    return Err(bad);
                }
                let len = be16(packet, ip + 4) as usize;
                if len == 0 || ip + 40 + len != packet.len() {
                    return Err(bad);
                }
                // Extension headers (including fragments), tunnels and jumbograms
                // are left to software; never guess the checksum start.
                (40, packet[ip + 6], len, sum_words(&packet[ip + 8..ip + 40]))
            }
            _ => return Err(bad),
        };
        let transport = ip + ip_len;
        let (l4, header_len, checksum) = match protocol {
            6 => {
                if meta.csum_l4 == Some(L4CsumKind::Udp) || l4_len < 20 {
                    return Err(bad);
                }
                let len = (packet[transport + 12] >> 4) as usize * 4;
                if len < 20 || len > l4_len {
                    return Err(bad);
                }
                (L4Proto::Tcp, len, transport + 16)
            }
            17 => {
                if meta.csum_l4 != Some(L4CsumKind::Udp)
                    || meta.tso_mss.is_some()
                    || l4_len < 8
                    || be16(packet, transport + 4) as usize != l4_len
                {
                    return Err(bad);
                }
                (L4Proto::Udp, 8, transport + 6)
            }
            _ => return Err(bad),
        };
        if let Some(mss) = meta.tso_mss {
            // i40e's minimum MSS is 64. Every emitted IP packet fits the MTU.
            if mss < 64
                || ip_len + header_len + mss as usize > 1500
                || l4_len <= header_len
                || packet[transport + 13] & (0x02 | 0x04 | 0x20) != 0
            {
                return Err(bad);
            }
            plan.context =
                Some(tso_context_desc((l4_len - header_len) as u32, mss).map_err(|_| bad)?);
        } else {
            sum += l4_len as u32;
        }
        sum += protocol as u32;
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        plan.ipv4 = ether == 0x0800;
        plan.command = if plan.ipv4 {
            TxCsum::Ipv4 { l4 }
        } else {
            TxCsum::Ipv6 { l4 }
        }
        .cmd_bits(true);
        plan.offset = tx_offset_field(HeaderLens {
            mac: ip as u16,
            ip: ip_len as u16,
            l4: header_len as u16,
        })
        .map_err(|_| bad)?;
        plan.ip = ip;
        plan.checksum = checksum;
        plan.seed = sum as u16;
        Ok(plan)
    }

    /// The device consumes the uncomplemented pseudoheader sum. For TSO it
    /// supplies each segment's transport length; ordinary checksum adds it here.
    pub fn prepare(&self, packet: &mut [u8]) {
        if self.command == 0 {
            return;
        }
        packet[self.checksum..self.checksum + 2].copy_from_slice(&self.seed.to_be_bytes());
        if self.ipv4 {
            packet[self.ip + 10..self.ip + 12].fill(0);
        }
        if self.context.is_some() {
            let offset = if self.ipv4 { self.ip + 2 } else { self.ip + 4 };
            packet[offset..offset + 2].fill(0);
        }
    }
}

/// Only non-tunnelled, non-fragmented TCP/UDP packet types receive checksum
/// credit. IPv6 extension parsing and PPRS (parser/speed failure) force software
/// verification. PTYPE values follow libie/rx.c's 8-bit legacy table.
pub fn rx_metadata(qword: u64) -> narf_net::RxMeta {
    let ptype = ((qword >> 30) & 0xff) as u8;
    let errors = ((qword >> 19) & 0xff) as u8;
    let ipv4 = matches!(ptype, 24 | 26);
    let ipv6 = matches!(ptype, 90 | 92);
    let good = (ipv4 || ipv6)
        && matches!(rx_checksum(qword, errors), RxCsum::Good)
        && errors & (1 << 7) == 0
        && (!ipv6 || qword & (1 << 15) == 0);
    narf_net::RxMeta {
        csum_l3: good && ipv4,
        csum_l4: good,
        ..Default::default()
    }
}
