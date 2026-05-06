//! `QUERY_HCA_CAP` response decoders — Stage 5.
//!
//! Stage 4 returns the raw 4-KiB capability payload for any group.
//! Stage 5 lays a typed view over it for the GENERAL_DEVICE group
//! (the most useful subset for bring-up planning) and the
//! ETHERNET_OFFLOAD group (NIC fast-path scoping).
//!
//! Reference: public Mellanox PRM §15.2 ("HCA Capabilities").
//!
//! ## What this stage commits to
//!
//! A focused subset of byte-aligned fields the PRM documents at
//! consistent offsets across ConnectX-4..6:
//!
//! | offset | field                  | width |
//! |--------|------------------------|-------|
//! | 0x10   | vhca_id                | u16 BE |
//! | 0x40   | log_max_srq_sz         | u8     |
//! | 0x41   | log_max_qp_sz          | u8     |
//! | 0x53   | log_max_cq_sz          | u8     |
//! | 0x5B   | log_max_eq_sz          | u8     |
//! | 0x60   | log_max_mkey           | u8     |
//! | 0x68   | log_max_pd             | u8     |
//!
//! Bit-packed sub-fields (e.g. log_max_qp at the low 5 bits of byte
//! 0x47) decode in a later stage where we'll add a `bit_field!`
//! helper rather than inlining the masks here.
//!
//! Anything not surfaced via a named accessor is reachable through
//! `raw()` so consumers can decode opportunistically without forking
//! the decoder.

extern crate alloc;
use alloc::vec::Vec;

use super::bit_field::read_bits_be;

/// Decoded-payload length for QUERY_HCA_CAP. Firmware returns a
/// 4-KiB structure regardless of which subgroup of fields is
/// populated.
pub const HCA_CAP_OUT_LEN: usize = 0x1000;

// ── Field offsets ──────────────────────────────────────────────────

pub const HCA_CAP_OFF_VHCA_ID: usize = 0x10;
pub const HCA_CAP_OFF_LOG_MAX_SRQ_SZ: usize = 0x40;
pub const HCA_CAP_OFF_LOG_MAX_QP_SZ: usize = 0x41;
pub const HCA_CAP_OFF_LOG_MAX_CQ_SZ: usize = 0x53;
pub const HCA_CAP_OFF_LOG_MAX_EQ_SZ: usize = 0x5B;
pub const HCA_CAP_OFF_LOG_MAX_MKEY: usize = 0x60;
pub const HCA_CAP_OFF_LOG_MAX_PD: usize = 0x68;

// Bit-packed fields (see Stage 6 — `bit_field.rs` does the math).
//
// Per PRM mlx5_ifc layout, log_max_qp lives at the low 5 bits of
// the 32-bit BE word at byte offset 0x44 — i.e. bit positions
// 0x44*8 + 27 .. 0x44*8 + 31. log_max_eq lives at low 4 bits of
// byte 0x47.
pub const HCA_CAP_BIT_LOG_MAX_QP: usize = 0x44 * 8 + 27;
pub const HCA_CAP_BIT_LOG_MAX_QP_W: usize = 5;
pub const HCA_CAP_BIT_LOG_MAX_EQ: usize = 0x47 * 8 + 28;
pub const HCA_CAP_BIT_LOG_MAX_EQ_W: usize = 4;

// Ethernet-offload field offsets (relative to start of the cap
// payload — the same 4-KiB structure shape, just different
// well-known fields).
pub const ETH_OFF_TX_CSUM: usize = 0x10;
pub const ETH_OFF_RX_CSUM: usize = 0x11;
pub const ETH_OFF_LSO: usize = 0x12;
pub const ETH_OFF_LRO: usize = 0x13;
pub const ETH_OFF_MAX_LSO_SIZE: usize = 0x14;
pub const ETH_OFF_RSS_IND_TBL: usize = 0x18;
pub const ETH_OFF_VLAN_INSERT: usize = 0x19;
pub const ETH_OFF_VLAN_STRIP: usize = 0x1A;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CapsDecodeError {
    /// Bytes shorter than the smallest valid HCA_CAP payload.
    Truncated,
}

// ── GENERAL_DEVICE caps ────────────────────────────────────────────

/// Decoded view over a `QUERY_HCA_CAP(GENERAL_DEVICE)` response.
/// Holds the raw 4-KiB payload + offers typed accessors for the
/// fields we've committed to. Other fields are reachable via
/// `raw()`.
#[derive(Debug)]
pub struct HcaGeneralCaps {
    bytes: Vec<u8>,
}

impl HcaGeneralCaps {
    /// Wrap a `query_hca_cap(GeneralDevice, _)` result. Returns
    /// `Truncated` if the buffer is shorter than the highest field
    /// offset we expose.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CapsDecodeError> {
        if bytes.len() <= HCA_CAP_OFF_LOG_MAX_PD {
            return Err(CapsDecodeError::Truncated);
        }
        Ok(Self { bytes })
    }

    /// Virtual-HCA identifier — assigned by FW per VF / per-host
    /// instance.
    pub fn vhca_id(&self) -> u16 {
        u16::from_be_bytes([
            self.bytes[HCA_CAP_OFF_VHCA_ID],
            self.bytes[HCA_CAP_OFF_VHCA_ID + 1],
        ])
    }

    /// Max SRQ size as 2^N entries.
    pub fn log_max_srq_sz(&self) -> u8 {
        self.bytes[HCA_CAP_OFF_LOG_MAX_SRQ_SZ]
    }
    /// Max QP size as 2^N WQEs.
    pub fn log_max_qp_sz(&self) -> u8 {
        self.bytes[HCA_CAP_OFF_LOG_MAX_QP_SZ]
    }
    /// Max CQ size as 2^N CQEs.
    pub fn log_max_cq_sz(&self) -> u8 {
        self.bytes[HCA_CAP_OFF_LOG_MAX_CQ_SZ]
    }
    /// Max EQ size as 2^N entries.
    pub fn log_max_eq_sz(&self) -> u8 {
        self.bytes[HCA_CAP_OFF_LOG_MAX_EQ_SZ]
    }
    /// Max number of memory keys, 2^N.
    pub fn log_max_mkey(&self) -> u8 {
        self.bytes[HCA_CAP_OFF_LOG_MAX_MKEY]
    }
    /// Max number of protection domains, 2^N.
    pub fn log_max_pd(&self) -> u8 {
        self.bytes[HCA_CAP_OFF_LOG_MAX_PD]
    }

    /// Max number of QPs, 2^N. Bit-packed at the low 5 bits of byte
    /// 0x47 (within the 32-bit BE word starting at 0x44).
    pub fn log_max_qp(&self) -> u8 {
        read_bits_be(
            &self.bytes,
            HCA_CAP_BIT_LOG_MAX_QP,
            HCA_CAP_BIT_LOG_MAX_QP_W,
        ) as u8
    }

    /// Max number of EQs, 2^N. Bit-packed at the low 4 bits of byte
    /// 0x47 (within the 32-bit BE word starting at 0x44).
    pub fn log_max_eq(&self) -> u8 {
        read_bits_be(
            &self.bytes,
            HCA_CAP_BIT_LOG_MAX_EQ,
            HCA_CAP_BIT_LOG_MAX_EQ_W,
        ) as u8
    }

    /// Raw bytes — full 4-KiB payload. Stable so callers decoding
    /// fields beyond Stage-5's committed subset don't have to fork
    /// the decoder.
    pub fn raw(&self) -> &[u8] {
        &self.bytes
    }
}

// ── ETHERNET_OFFLOAD caps ──────────────────────────────────────────

/// Decoded view over `QUERY_HCA_CAP(ETHERNET_OFFLOAD)`. Surfaces the
/// per-byte offload flags + `max_lso_size`. NIC fast-path planners
/// use this to decide which features to negotiate.
#[derive(Debug)]
pub struct EthernetOffloadCaps {
    bytes: Vec<u8>,
}

impl EthernetOffloadCaps {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CapsDecodeError> {
        if bytes.len() <= ETH_OFF_VLAN_STRIP {
            return Err(CapsDecodeError::Truncated);
        }
        Ok(Self { bytes })
    }

    pub fn supports_tx_csum(&self) -> bool {
        self.bytes[ETH_OFF_TX_CSUM] != 0
    }
    pub fn supports_rx_csum(&self) -> bool {
        self.bytes[ETH_OFF_RX_CSUM] != 0
    }
    pub fn supports_lso(&self) -> bool {
        self.bytes[ETH_OFF_LSO] != 0
    }
    pub fn supports_lro(&self) -> bool {
        self.bytes[ETH_OFF_LRO] != 0
    }
    pub fn supports_rss(&self) -> bool {
        self.bytes[ETH_OFF_RSS_IND_TBL] != 0
    }
    pub fn supports_vlan_insert(&self) -> bool {
        self.bytes[ETH_OFF_VLAN_INSERT] != 0
    }
    pub fn supports_vlan_strip(&self) -> bool {
        self.bytes[ETH_OFF_VLAN_STRIP] != 0
    }

    /// Max LSO/TSO segment payload size, BE u32.
    pub fn max_lso_size(&self) -> u32 {
        u32::from_be_bytes([
            self.bytes[ETH_OFF_MAX_LSO_SIZE],
            self.bytes[ETH_OFF_MAX_LSO_SIZE + 1],
            self.bytes[ETH_OFF_MAX_LSO_SIZE + 2],
            self.bytes[ETH_OFF_MAX_LSO_SIZE + 3],
        ])
    }

    pub fn raw(&self) -> &[u8] {
        &self.bytes
    }
}
