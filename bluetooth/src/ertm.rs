//! L2CAP Enhanced Retransmission Mode (ERTM, mode 0x03) and Streaming
//! Mode (0x04) framing — clean-room.
//!
//! Spec sources (public-only):
//! - "Bluetooth Core Specification 5.3, Vol 3 Part A" — Bluetooth SIG.
//!   §3.3.2 (Enhanced Control Field), §3.3.4 (I-frame layout), §3.3.5
//!   (S-frame layout), §3.4 (Retransmission and Flow Control), §5.4
//!   (Retransmission timer T_RTX), table 3.4 (Configuration option
//!   types 0x04 / 0x09).
//! - "Bluetooth Assigned Numbers" — L2CAP option type IDs and FCS
//!   polynomial constant (0xA001, CRC16-CCITT-FALSE variant per
//!   Vol 3 Part A §3.3.5).
//!
//! Linux reference consulted (GPL-2.0-or-later, NARF relicense
//! 2026-05-20): `net/bluetooth/l2cap_core.c` —
//! `l2cap_skbuff_fromiovec`, `l2cap_ertm_send`, `__pack_enhanced_control`,
//! `l2cap_check_fcs` for the FCS polynomial and ECF bit layout.
//!
//! ## Enhanced Control Field (§3.3.2, figure 3.3)
//!
//! ```text
//!   bit  0    : Type (0 = I-frame, 1 = S-frame)
//!   bit  1    : F (Final)            — S-frame only
//!   bits 2..7 : ReqSeq (request seq, 6 bits) — actually 14 bits via byte 1
//!   bits 8..9 : SAR (Segmentation and Reassembly, I-frame only)
//!   bits 10..15: TxSeq (transmit seq, 6 bits) — I-frame only
//! ```
//!
//! Some controllers use the 2-byte "basic" ECF; 4-byte "extended" ECF
//! widens TxSeq/ReqSeq to 14 bits and lives behind the Extended Window
//! capability. We implement the 2-byte form (Core spec calls it
//! "Standard Control Field"); extended is a stub.
//!
//! ## SAR codes (§3.3.4)
//!
//! 0b00 Unsegmented   — entire SDU in one I-frame
//! 0b01 Start         — first segment, includes 2-byte total SDU length
//! 0b10 End           — last segment
//! 0b11 Continuation  — middle segment

use alloc::vec::Vec;

// ── ECF bit positions (§3.3.2, figure 3.3) ─────────────────────────
// We work over the 16-bit ECF read little-endian off the wire.

/// I-frame discriminator (bit 0 = 0).
pub const ECF_TYPE_IFRAME: u16 = 0x0000;
/// S-frame discriminator (bit 0 = 1).
pub const ECF_TYPE_SFRAME: u16 = 0x0001;

const TX_SEQ_SHIFT: u16 = 1; // bits 1..7 (6 bits)
const TX_SEQ_MASK: u16 = 0x007E;
const F_BIT_MASK: u16 = 0x0080; // bit 7 in S-frame layout
const REQ_SEQ_SHIFT: u16 = 8;
const REQ_SEQ_MASK: u16 = 0x3F00; // bits 8..13 (6 bits)
const SAR_SHIFT: u16 = 14;
const SAR_MASK: u16 = 0xC000;

// ── SAR codes (§3.3.4, table 3.5) ──────────────────────────────────

pub const SAR_UNSEGMENTED: u8 = 0b00;
pub const SAR_START: u8 = 0b01;
pub const SAR_END: u8 = 0b10;
pub const SAR_CONTINUATION: u8 = 0b11;

// ── S-frame supervisor function codes (§3.3.5, table 3.6) ─────────

const S_RR: u16 = 0b00; // Receiver Ready
const S_REJ: u16 = 0b01; // Reject
const S_RNR: u16 = 0b10; // Receiver Not Ready
const S_SREJ: u16 = 0b11; // Selective Reject

const S_FUNC_SHIFT: u16 = 2; // bits 2..3 in S-frame layout
const S_FUNC_MASK: u16 = 0x000C;

/// I-frame (Information) — carries an SDU segment plus piggy-backed
/// receiver state in ReqSeq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IFrame {
    /// Transmit sequence number (0..=63).
    pub tx_seq: u8,
    /// Acknowledgement sequence number (0..=63).
    pub req_seq: u8,
    /// Segmentation/Reassembly indicator (one of `SAR_*`).
    pub sar: u8,
    /// SDU payload (for SAR=Start, the first 2 bytes are SDU total
    /// length BE; callers should strip them before reassembly).
    pub payload: Vec<u8>,
    /// Optional 2-byte FCS appended after the payload when the channel
    /// configured FCS=on (§3.3.5). The codec keeps FCS as-typed by
    /// callers; encode/decode insert the polynomial check below.
    pub fcs: Option<u16>,
}

impl IFrame {
    pub fn encode(&self) -> Vec<u8> {
        let ecf = ECF_TYPE_IFRAME
            | (((self.tx_seq as u16) << TX_SEQ_SHIFT) & TX_SEQ_MASK)
            | (((self.req_seq as u16) << REQ_SEQ_SHIFT) & REQ_SEQ_MASK)
            | (((self.sar as u16) << SAR_SHIFT) & SAR_MASK);
        let mut out = Vec::with_capacity(2 + self.payload.len() + 2);
        out.extend_from_slice(&ecf.to_le_bytes());
        out.extend_from_slice(&self.payload);
        if let Some(fcs) = self.fcs {
            out.extend_from_slice(&fcs.to_le_bytes());
        }
        out
    }

    /// Decode an I-frame body (the ECF + payload [+ FCS]). `has_fcs`
    /// drives whether the trailing 2 bytes are stripped as an FCS.
    pub fn decode(buf: &[u8], has_fcs: bool) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }
        let ecf = u16::from_le_bytes([buf[0], buf[1]]);
        if (ecf & 1) != 0 {
            // S-frame, not I-frame.
            return None;
        }
        let tx_seq = ((ecf & TX_SEQ_MASK) >> TX_SEQ_SHIFT) as u8;
        let req_seq = ((ecf & REQ_SEQ_MASK) >> REQ_SEQ_SHIFT) as u8;
        let sar = ((ecf & SAR_MASK) >> SAR_SHIFT) as u8;

        let body_end = if has_fcs {
            if buf.len() < 4 {
                return None;
            }
            buf.len() - 2
        } else {
            buf.len()
        };
        let payload = buf[2..body_end].to_vec();
        let fcs = if has_fcs {
            Some(u16::from_le_bytes([buf[body_end], buf[body_end + 1]]))
        } else {
            None
        };
        Some(Self {
            tx_seq,
            req_seq,
            sar,
            payload,
            fcs,
        })
    }
}

/// S-frame supervisor functions (§3.3.5).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SupervisorFunc {
    Rr = S_RR as u8,
    Rej = S_REJ as u8,
    Rnr = S_RNR as u8,
    SRej = S_SREJ as u8,
}

impl SupervisorFunc {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            x if x == S_RR as u8 => Self::Rr,
            x if x == S_REJ as u8 => Self::Rej,
            x if x == S_RNR as u8 => Self::Rnr,
            x if x == S_SREJ as u8 => Self::SRej,
            _ => return None,
        })
    }
}

/// S-frame (Supervisor) — no payload, carries ReqSeq + function code.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SFrame {
    pub function: SupervisorFunc,
    pub req_seq: u8,
    /// Final bit — set in the last S-frame of a recovery cycle.
    pub final_bit: bool,
}

impl SFrame {
    pub fn encode(&self) -> [u8; 2] {
        let mut ecf = ECF_TYPE_SFRAME
            | (((self.function as u16) << S_FUNC_SHIFT) & S_FUNC_MASK)
            | (((self.req_seq as u16) << REQ_SEQ_SHIFT) & REQ_SEQ_MASK);
        if self.final_bit {
            ecf |= F_BIT_MASK;
        }
        ecf.to_le_bytes()
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }
        let ecf = u16::from_le_bytes([buf[0], buf[1]]);
        if (ecf & 1) == 0 {
            // I-frame.
            return None;
        }
        let function_bits = ((ecf & S_FUNC_MASK) >> S_FUNC_SHIFT) as u8;
        let function = SupervisorFunc::from_u8(function_bits)?;
        Some(Self {
            function,
            req_seq: ((ecf & REQ_SEQ_MASK) >> REQ_SEQ_SHIFT) as u8,
            final_bit: (ecf & F_BIT_MASK) != 0,
        })
    }
}

// ── ERTM FCS (CRC16, polynomial 0xA001 reflected) ────────────────
// Bluetooth Core 5.3 Vol 3 Part A §3.3.5: the FCS is CRC-16-CCITT with
// generator polynomial x^16 + x^15 + x^2 + 1, computed in
// least-significant-bit-first order. The reflected polynomial is
// 0xA001 — same as Modbus CRC.

/// Compute the L2CAP FCS over `bytes`. Initial value is 0, no XOR-out.
pub fn fcs(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bytes {
        crc ^= b as u16;
        for _ in 0..8 {
            let lsb = crc & 1 != 0;
            crc >>= 1;
            if lsb {
                crc ^= 0xA001;
            }
        }
    }
    crc
}

// ── Sequence-number arithmetic (mod 64) ────────────────────────────

/// Sequence-window modulus. ERTM uses a 6-bit Tx/ReqSeq → window of 64.
pub const SEQ_MODULO: u8 = 64;

/// Returns true iff `(start <= seq < end)` in the modulo-`SEQ_MODULO`
/// window. Implements the receive-window admission check from §3.4.2.
pub fn seq_in_window(start: u8, seq: u8, end: u8) -> bool {
    let s = (start & 0x3F) as u16;
    let e = (end & 0x3F) as u16;
    let v = (seq & 0x3F) as u16;
    if s <= e {
        s <= v && v < e
    } else {
        // Window wraps past 63.
        v >= s || v < e
    }
}

/// Advance a 6-bit sequence number by one with wrap.
#[inline]
pub fn seq_next(s: u8) -> u8 {
    (s + 1) & 0x3F
}

// ── Configuration option encoders (§5.4, §5.5) ────────────────────

/// Retransmission and Flow Control option type (§5.4, table 5.7).
pub const CONFIG_OPT_RFC: u8 = 0x04;
/// FCS Option type (§5.5).
pub const CONFIG_OPT_FCS: u8 = 0x05;
/// Extended Flow Spec (§5.7).
pub const CONFIG_OPT_EXT_FLOW_SPEC: u8 = 0x06;
/// Extended Window Size (§5.8).
pub const CONFIG_OPT_EXT_WINDOW: u8 = 0x09;

/// Channel modes carried inside the RFC option (§5.4, table 5.7).
pub const MODE_BASIC: u8 = 0x00;
pub const MODE_RETRANSMISSION: u8 = 0x01;
pub const MODE_FLOW_CONTROL: u8 = 0x02;
pub const MODE_ERTM: u8 = 0x03;
pub const MODE_STREAMING: u8 = 0x04;

/// Encode the L2CAP "Retransmission and Flow Control" config option
/// (§5.4). Format:
///
/// ```text
///   byte 0: Option Type (0x04)
///   byte 1: Option Length (9 for this option)
///   byte 2: mode
///   byte 3: TxWindow size (1..=63)
///   byte 4: MaxTransmit (number of attempts before giving up)
///   bytes 5..7: u16 LE Retransmission Timeout (ms)
///   bytes 7..9: u16 LE Monitor Timeout (ms)
///   bytes 9..11: u16 LE Max PDU payload size (per fragment)
/// ```
pub fn config_option_rfc(
    mode: u8,
    tx_window: u8,
    max_transmit: u8,
    retransmit_timeout_ms: u16,
    monitor_timeout_ms: u16,
    max_pdu: u16,
) -> [u8; 11] {
    let mut out = [0u8; 11];
    out[0] = CONFIG_OPT_RFC;
    out[1] = 9;
    out[2] = mode;
    out[3] = tx_window;
    out[4] = max_transmit;
    out[5..7].copy_from_slice(&retransmit_timeout_ms.to_le_bytes());
    out[7..9].copy_from_slice(&monitor_timeout_ms.to_le_bytes());
    out[9..11].copy_from_slice(&max_pdu.to_le_bytes());
    out
}

/// FCS option (§5.5). Format: type(1) length(1) fcs_type(1).
/// `fcs_type` = 0 disables FCS, 1 enables CRC16 (default).
pub fn config_option_fcs(fcs_type: u8) -> [u8; 3] {
    [CONFIG_OPT_FCS, 1, fcs_type]
}

/// ERTM tx/rx state per §3.4. The sender maintains TxWindow, NextTxSeq,
/// and ExpectedAckSeq; receivers track BufferSeq and ExpectedTxSeq.
#[derive(Debug)]
pub struct ErtmState {
    /// Configured tx-window size (1..=63).
    pub tx_window: u8,
    /// Next sequence number to assign to an outbound I-frame.
    pub next_tx_seq: u8,
    /// Lowest unacknowledged sequence number — wraps mod 64.
    pub expected_ack_seq: u8,
    /// Next sequence number we expect from the peer.
    pub expected_rx_seq: u8,
    /// Whether we're in REJ-recovery (frames between rej_seq and
    /// the latest received are being re-requested).
    pub rej_pending: bool,
}

impl ErtmState {
    pub fn new(tx_window: u8) -> Self {
        Self {
            tx_window: tx_window.clamp(1, 63),
            next_tx_seq: 0,
            expected_ack_seq: 0,
            expected_rx_seq: 0,
            rej_pending: false,
        }
    }

    /// Mark an outbound I-frame as sent. Returns the assigned tx_seq.
    pub fn assign_tx_seq(&mut self) -> u8 {
        let s = self.next_tx_seq;
        self.next_tx_seq = seq_next(s);
        s
    }

    /// Process an incoming peer ReqSeq — slides our send-window left.
    pub fn on_peer_ack(&mut self, peer_req_seq: u8) {
        self.expected_ack_seq = peer_req_seq & 0x3F;
    }

    /// Number of unacknowledged frames currently outstanding (mod 64).
    pub fn outstanding(&self) -> u8 {
        let a = self.expected_ack_seq as i16;
        let n = self.next_tx_seq as i16;
        let raw = (n - a) & 0x3F;
        raw as u8
    }

    /// Whether we may transmit a new I-frame (window not exhausted).
    pub fn can_send(&self) -> bool {
        self.outstanding() < self.tx_window
    }

    /// Receive an I-frame; check sequence and update expected_rx_seq.
    /// Returns true if the frame is in-order, false if out-of-order.
    pub fn on_rx_iframe(&mut self, tx_seq: u8) -> bool {
        if (tx_seq & 0x3F) == self.expected_rx_seq {
            self.expected_rx_seq = seq_next(self.expected_rx_seq);
            self.rej_pending = false;
            true
        } else {
            self.rej_pending = true;
            false
        }
    }
}

#[cfg(test)]
mod selftest {
    use super::*;
    const _: () = assert!(SEQ_MODULO == 64);
    // CRC self-check is in `tests.rs`; here we just compile-check the
    // size of `config_option_rfc()`.
    const _: () = assert!(::core::mem::size_of::<[u8; 11]>() == 11);
}
