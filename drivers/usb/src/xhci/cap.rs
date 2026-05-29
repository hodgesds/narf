//! xHCI 1.2 Capability Register definitions (§5.3).
//!
//! Capability registers sit at BAR0 + 0 and describe the controller's
//! immutable parameters: `CAPLENGTH` (offset to operational regs),
//! `HCIVERSION`, `HCSPARAMS1/2/3`, `HCCPARAMS1/2`, `DBOFF` (offset to
//! doorbell array), `RTSOFF` (offset to runtime registers).
//!
//! The numeric constants are co-located with the implementation in
//! `super` (xhci/mod.rs) because the bring-up code reads these via
//! `MmioRegion::read32`. This file factors out the *decode* helpers
//! so anyone reading the spec can find the field layouts in one
//! place — see [`decode_hcsparams1`], [`decode_hccparams1`] and the
//! re-exported [`XhciCaps`] struct.

#![allow(dead_code)]

pub use super::XhciCaps;

/// Capability-register byte offsets (relative to BAR0 + 0). xHCI §5.3.
pub const CAP_CAPLENGTH: u64 = 0x00;
pub const CAP_HCIVERSION: u64 = 0x02;
pub const CAP_HCSPARAMS1: u64 = 0x04;
pub const CAP_HCSPARAMS2: u64 = 0x08;
pub const CAP_HCSPARAMS3: u64 = 0x0C;
pub const CAP_HCCPARAMS1: u64 = 0x10;
pub const CAP_DBOFF: u64 = 0x14;
pub const CAP_RTSOFF: u64 = 0x18;
pub const CAP_HCCPARAMS2: u64 = 0x1C;

/// Decoded HCSPARAMS1 (§5.3.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HcsParams1 {
    pub max_slots: u8,
    pub max_intrs: u16,
    pub max_ports: u8,
}

impl HcsParams1 {
    /// Decode the raw 32-bit register value into the three fields.
    /// `MaxSlots` is bits[7:0]; `MaxIntrs` is bits[18:8] (11 bits);
    /// `MaxPorts` is bits[31:24].
    pub const fn decode(v: u32) -> Self {
        Self {
            max_slots: (v & 0xFF) as u8,
            max_intrs: ((v >> 8) & 0x7FF) as u16,
            max_ports: ((v >> 24) & 0xFF) as u8,
        }
    }
}

/// Decoded HCSPARAMS2 (§5.3.4). MAXSCRATCHPAD_BUFS combines high bits
/// (bits[25:21]) and low bits (bits[31:27]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HcsParams2 {
    /// Isochronous Scheduling Threshold.
    pub ist: u8,
    /// Event Ring Segment Table Max — log2 of the maximum number of
    /// segments an interrupter can use.
    pub erst_max: u8,
    /// Number of scratchpad-buffer pointer pages the controller wants
    /// the OS to allocate. Reassembled from the high/low halves.
    pub max_scratchpad_bufs: u32,
}

impl HcsParams2 {
    pub const fn decode(v: u32) -> Self {
        let lo = (v >> 27) & 0x1F;
        let hi = (v >> 21) & 0x1F;
        let bufs = (hi << 5) | lo;
        Self {
            ist: (v & 0xF) as u8,
            erst_max: ((v >> 4) & 0xF) as u8,
            max_scratchpad_bufs: bufs,
        }
    }
}

/// Decoded HCSPARAMS3 (§5.3.5). Latency advertisements for U1/U2.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HcsParams3 {
    /// U1 Device Exit Latency, microseconds.
    pub u1_exit_latency_us: u8,
    /// U2 Device Exit Latency, microseconds.
    pub u2_exit_latency_us: u16,
}

impl HcsParams3 {
    pub const fn decode(v: u32) -> Self {
        Self {
            u1_exit_latency_us: (v & 0xFF) as u8,
            u2_exit_latency_us: ((v >> 16) & 0xFFFF) as u16,
        }
    }
}

/// Decoded HCCPARAMS1 (§5.3.6). The fields the bring-up path reads.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HccParams1 {
    /// AC64 — 64-bit DMA addressing supported.
    pub ac64: bool,
    /// BNC — Bandwidth Negotiation Capability.
    pub bnc: bool,
    /// CSZ — Context Size: 0 = 32 byte, 1 = 64 byte.
    pub csz_64byte: bool,
    /// PPC — Port Power Control.
    pub ppc: bool,
    /// PIND — Port Indicators.
    pub pind: bool,
    /// LHRC — Light Host Controller Reset Capability.
    pub lhrc: bool,
    /// LTC — Latency Tolerance Messaging Capability.
    pub ltc: bool,
    /// NSS — No Secondary SID Support.
    pub nss: bool,
    /// xECP — Extended Capabilities Pointer (DWORD units from MMIO base).
    pub xecp_dwords: u16,
    /// MaxPSASize — Max Primary Stream Array Size encode.
    pub max_psa_size: u8,
}

impl HccParams1 {
    pub const fn decode(v: u32) -> Self {
        Self {
            ac64: (v & 0x1) != 0,
            bnc: (v & (1 << 1)) != 0,
            csz_64byte: (v & (1 << 2)) != 0,
            ppc: (v & (1 << 3)) != 0,
            pind: (v & (1 << 4)) != 0,
            lhrc: (v & (1 << 5)) != 0,
            ltc: (v & (1 << 6)) != 0,
            nss: (v & (1 << 7)) != 0,
            max_psa_size: ((v >> 12) & 0xF) as u8,
            xecp_dwords: ((v >> 16) & 0xFFFF) as u16,
        }
    }
}

/// Convenience: decode HCSPARAMS1 directly.
pub fn decode_hcsparams1(v: u32) -> HcsParams1 {
    HcsParams1::decode(v)
}

/// Convenience: decode HCCPARAMS1 directly.
pub fn decode_hccparams1(v: u32) -> HccParams1 {
    HccParams1::decode(v)
}
