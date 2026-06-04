//! T=1 block-protocol APDU framing for USB CCID.
//!
//! ## References
//!
//! - **ISO/IEC 7816-3:2006** §11 — T=1 half-duplex asynchronous block
//!   transmission protocol.
//!   - §11.3.1 — Block structure: NAD(1) PCB(1) LEN(1) INF(0..254) EDC(1–2).
//!   - §11.3.2 — PCB byte encoding for I/R/S blocks.
//!   - §11.3.3 — Error detection: LRC (XOR) or CRC-16 selected by ATR TA3.
//!   - §11.6   — I-block sequencing (sequence numbers 0/1, alternating).
//!   - §11.6.2 — R-block: ACK (parity/other error bit clear) or NAK.
//!   - §11.6.3 — S-block request/response pairs: IFS, ABORT, WTX, RESYNCH.
//! - **USB CCID spec rev 1.1 §6.2** — XfrBlock carries T=1 blocks in
//!   INF payload; CCID reader handles physical layer (NAD is typically 0x00).
//! - **pcsc-lite / libccid** `src/T1/t1.c` — reference implementation;
//!   block structuring mirrors this file's approach adapted to no_std Rust.
//!
//! ## What is NOT here
//!
//! - CRC-16 checksum mode (TA3 = 0x02 in ATR) — only LRC is implemented;
//!   CRC is deferred (ATR negotiation is pcsc-lite territory for now).
//! - Multiblock chaining (IFSC > 254, wLevelParameter ≠ 0 in XfrBlock)
//!   — deferred; single-block exchange covers the vast majority of cards.
//! - T=15 / global-interface parameter negotiation — deferred per task scope.
//! - PPS (Protocol and Parameters Selection) — deferred.

extern crate alloc;

use super::CcidError;
use alloc::vec::Vec;

// ── PCB block-type masks (ISO 7816-3 §11.3.2 Table 16) ───────────────

/// PCB[7:6] = 00 → I-block (information). Bit 6 always 0 for I-blocks.
pub const PCB_IBLOCK_MASK: u8 = 0x00;
/// PCB[7:6] = 10 → R-block (receive-ready / error). Bit 6 always 1.
pub const PCB_RBLOCK_BASE: u8 = 0x80;
/// PCB[7:6] = 11 → S-block (supervisory). Bits 7 and 6 both set.
pub const PCB_SBLOCK_BASE: u8 = 0xC0;

// ── I-block PCB bits ───────────────────────────────────────────────────

/// I-block PCB bit 6: sequence number N(S). 0 or 1 (alternating).
pub const PCB_IBLOCK_NS_BIT: u8 = 0x40;
/// I-block PCB bit 5: more-data (M) — set when more blocks follow in a
/// chained sequence (ISO 7816-3 §11.6.1.2). We never set this (no chaining).
pub const PCB_IBLOCK_MORE: u8 = 0x20;

// ── R-block PCB bits ───────────────────────────────────────────────────

/// R-block PCB bit 4: sequence number N(R). 0 or 1.
pub const PCB_RBLOCK_NR_BIT: u8 = 0x10;
/// R-block error bit 1 (bit 0): parity error or other error detected
/// (NAK condition). When both error bits are 0 → ACK (no error detected).
pub const PCB_RBLOCK_ERR1: u8 = 0x01;
/// R-block error bit 2 (bit 1): "other error" (e.g. CRC/EDC failure).
pub const PCB_RBLOCK_ERR2: u8 = 0x02;

// ── S-block PCB values (ISO 7816-3 §11.3.2 Table 16) ─────────────────

/// S(IFS request): reader requests an interface-device frame size change.
pub const PCB_SBLOCK_IFS_REQ: u8 = 0xC1;
/// S(IFS response): card acknowledges the IFS change.
pub const PCB_SBLOCK_IFS_RESP: u8 = 0xE1;
/// S(ABORT request): reader requests protocol abort.
pub const PCB_SBLOCK_ABORT_REQ: u8 = 0xC2;
/// S(ABORT response): card acknowledges the abort.
pub const PCB_SBLOCK_ABORT_RESP: u8 = 0xE2;
/// S(WTX request): card requests a waiting-time extension.
pub const PCB_SBLOCK_WTX_REQ: u8 = 0xC3;
/// S(WTX response): reader grants the waiting-time extension.
pub const PCB_SBLOCK_WTX_RESP: u8 = 0xE3;
/// S(RESYNCH request): reader requests link re-synchronisation.
pub const PCB_SBLOCK_RESYNCH_REQ: u8 = 0xC0;
/// S(RESYNCH response): card acknowledges re-synchronisation.
pub const PCB_SBLOCK_RESYNCH_RESP: u8 = 0xE0;

// ── NAD default ───────────────────────────────────────────────────────

/// Default NAD (Node ADdress) byte: 0x00 means reader→card, no
/// intra-card routing (ISO 7816-3 §11.3.1.1). CCID readers always
/// use 0x00 per USB CCID spec §6.2.
pub const NAD_DEFAULT: u8 = 0x00;

// ── T1Block ───────────────────────────────────────────────────────────

/// A single T=1 block as defined by ISO 7816-3 §11.3.1.
///
/// NAD(1) + PCB(1) + LEN(1) + INF(LEN) + EDC(1–2, LRC here).
#[derive(Debug, Clone)]
pub struct T1Block {
    /// NAD byte. Always 0x00 for CCID.
    pub nad: u8,
    /// PCB byte: encodes block type + sequence number + flags.
    pub pcb: u8,
    /// INF field (the block information payload, 0–254 bytes).
    pub inf: Vec<u8>,
}

impl T1Block {
    // ── Constructors ────────────────────────────────────────────────

    /// Build an I-block carrying `apdu_chunk` (ISO 7816-3 §11.6.1).
    ///
    /// `ns` is the sender's sequence number (0 or 1). The PCB has
    /// bit 7 = 0, bit 6 = N(S), bit 5 = 0 (no chaining).
    pub fn i_block(ns: u8, apdu_chunk: &[u8]) -> Self {
        let pcb = PCB_IBLOCK_MASK | if ns & 1 != 0 { PCB_IBLOCK_NS_BIT } else { 0 };
        Self {
            nad: NAD_DEFAULT,
            pcb,
            inf: apdu_chunk.to_vec(),
        }
    }

    /// Build an R-block ACK (no error): N(R) = `nr` (ISO 7816-3 §11.6.2.2).
    ///
    /// Used to acknowledge a correctly-received I-block or as a resend request.
    pub fn r_block_ack(nr: u8) -> Self {
        let pcb = PCB_RBLOCK_BASE | if nr & 1 != 0 { PCB_RBLOCK_NR_BIT } else { 0 };
        Self {
            nad: NAD_DEFAULT,
            pcb,
            inf: Vec::new(),
        }
    }

    /// Build an R-block NAK (parity or other error detected, ISO §11.6.2.2).
    ///
    /// `nr` is the sequence number of the expected next I-block.
    /// Error bit 1 is set per §11.3.2 Table 16 footnote.
    pub fn r_block_nak(nr: u8) -> Self {
        let pcb =
            PCB_RBLOCK_BASE | if nr & 1 != 0 { PCB_RBLOCK_NR_BIT } else { 0 } | PCB_RBLOCK_ERR1;
        Self {
            nad: NAD_DEFAULT,
            pcb,
            inf: Vec::new(),
        }
    }

    /// Build an S(IFS request) block: ask the card to accept frame size `ifsd`
    /// (ISO 7816-3 §11.6.3.1). `ifsd` must be in 1..=254.
    pub fn s_ifs_request(ifsd: u8) -> Self {
        Self {
            nad: NAD_DEFAULT,
            pcb: PCB_SBLOCK_IFS_REQ,
            inf: alloc::vec![ifsd],
        }
    }

    /// Build an S(IFS response) block: confirm the IFS change (§11.6.3.1).
    pub fn s_ifs_response(ifsd: u8) -> Self {
        Self {
            nad: NAD_DEFAULT,
            pcb: PCB_SBLOCK_IFS_RESP,
            inf: alloc::vec![ifsd],
        }
    }

    /// Build an S(ABORT request) block (ISO 7816-3 §11.6.3.3).
    pub fn s_abort_request() -> Self {
        Self {
            nad: NAD_DEFAULT,
            pcb: PCB_SBLOCK_ABORT_REQ,
            inf: Vec::new(),
        }
    }

    /// Build an S(WTX response) block: reader acknowledges a waiting-time
    /// extension request from the card (ISO 7816-3 §11.6.3.2).
    /// `multiplier` is echoed from the card's WTX request INF byte.
    pub fn s_wtx_response(multiplier: u8) -> Self {
        Self {
            nad: NAD_DEFAULT,
            pcb: PCB_SBLOCK_WTX_RESP,
            inf: alloc::vec![multiplier],
        }
    }

    /// Build an S(RESYNCH request) block (ISO 7816-3 §11.6.3.4).
    pub fn s_resynch_request() -> Self {
        Self {
            nad: NAD_DEFAULT,
            pcb: PCB_SBLOCK_RESYNCH_REQ,
            inf: Vec::new(),
        }
    }

    // ── Encoding ────────────────────────────────────────────────────

    /// Serialize the block to wire format: NAD + PCB + LEN + INF + LRC.
    ///
    /// LRC is computed per ISO 7816-3 §11.3.3 (Table 18): XOR of every
    /// byte in NAD + PCB + LEN + INF. The LRC byte is appended so the
    /// XOR of the whole block (including LRC) equals 0x00.
    ///
    /// Returns `CcidError::ResponseTooLong` if `inf` exceeds 254 bytes
    /// (ISO 7816-3 §11.3.1.1 — LEN field is 8 bits, but 255 is reserved
    /// for future extended-length use).
    pub fn encode(&self) -> Result<Vec<u8>, CcidError> {
        if self.inf.len() > 254 {
            return Err(CcidError::ResponseTooLong);
        }
        let len = self.inf.len() as u8;
        let mut out = Vec::with_capacity(4 + self.inf.len());
        out.push(self.nad);
        out.push(self.pcb);
        out.push(len);
        out.extend_from_slice(&self.inf);
        let lrc = lrc_compute(&out);
        out.push(lrc);
        Ok(out)
    }

    // ── Decoding ────────────────────────────────────────────────────

    /// Decode a T=1 block from wire bytes (ISO 7816-3 §11.3.1).
    ///
    /// Validates:
    /// - At least 4 bytes present (NAD + PCB + LEN + LRC; empty INF is valid).
    /// - LRC: XOR of all bytes in the received block must be 0x00.
    ///
    /// Returns `CcidError::BadResponse` on structural errors, or
    /// `CcidError::CommandError(lrc_actual)` on checksum failure.
    pub fn decode(wire: &[u8]) -> Result<Self, CcidError> {
        // Minimum: NAD(1) + PCB(1) + LEN(1) + LRC(1) = 4 bytes.
        if wire.len() < 4 {
            return Err(CcidError::BadResponse);
        }
        let nad = wire[0];
        let pcb = wire[1];
        let len = wire[2] as usize;
        // Total expected = 3 + len + 1 (LRC).
        if wire.len() < 3 + len + 1 {
            return Err(CcidError::BadResponse);
        }
        let inf = wire[3..3 + len].to_vec();
        // LRC check: XOR of all bytes in the block including the trailing
        // LRC must equal 0x00 (ISO 7816-3 §11.3.3 Table 18).
        let check_data = &wire[..3 + len + 1];
        let lrc_check = lrc_check(check_data);
        if lrc_check != 0x00 {
            return Err(CcidError::CommandError(lrc_check));
        }
        Ok(Self { nad, pcb, inf })
    }

    // ── Block-type queries ──────────────────────────────────────────

    /// Returns `true` if this is an I-block (PCB[7] = 0, ISO §11.3.2).
    pub fn is_iblock(&self) -> bool {
        self.pcb & 0x80 == 0
    }

    /// Returns `true` if this is an R-block (PCB[7:6] = 10, ISO §11.3.2).
    pub fn is_rblock(&self) -> bool {
        self.pcb & 0xC0 == PCB_RBLOCK_BASE
    }

    /// Returns `true` if this is an S-block (PCB[7:6] = 11, ISO §11.3.2).
    pub fn is_sblock(&self) -> bool {
        self.pcb & 0xC0 == PCB_SBLOCK_BASE
    }

    /// For I-blocks: returns N(S) (bit 6 of PCB) as 0 or 1.
    pub fn ns(&self) -> u8 {
        if self.pcb & PCB_IBLOCK_NS_BIT != 0 {
            1
        } else {
            0
        }
    }

    /// For R-blocks: returns N(R) (bit 4 of PCB) as 0 or 1.
    pub fn nr(&self) -> u8 {
        if self.pcb & PCB_RBLOCK_NR_BIT != 0 {
            1
        } else {
            0
        }
    }

    /// For R-blocks: returns `true` if an error is indicated
    /// (PCB[1:0] ≠ 00, ISO §11.3.2 Table 16).
    pub fn r_error(&self) -> bool {
        self.pcb & (PCB_RBLOCK_ERR1 | PCB_RBLOCK_ERR2) != 0
    }
}

// ── LRC helpers (ISO 7816-3 §11.3.3) ─────────────────────────────────

/// Compute LRC for the bytes that form the block header + INF.
/// The LRC byte is the XOR of all provided bytes, producing the
/// checksum byte that makes the XOR of (header + INF + LRC) = 0x00.
pub fn lrc_compute(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// Verify LRC: XOR of all bytes in the block (including the trailing LRC
/// byte) must equal 0x00. Returns the XOR result (0x00 = valid).
pub fn lrc_check(block_with_lrc: &[u8]) -> u8 {
    block_with_lrc.iter().fold(0u8, |acc, &b| acc ^ b)
}

// ── T=1 sequence-number state ─────────────────────────────────────────

/// Per-slot T=1 sequence-number state.
///
/// Tracks N(S) (sender sequence, toggles after each I-block sent) and
/// N(R) (receiver expected sequence, toggles after each I-block received)
/// per ISO 7816-3 §11.6.1.
#[derive(Debug, Clone, Copy, Default)]
pub struct T1SeqState {
    /// N(S): sender sequence number, 0 or 1 (alternating).
    ns: u8,
    /// N(R): expected receiver sequence number, 0 or 1.
    nr: u8,
}

impl T1SeqState {
    /// Return the current N(S) and advance it for the next send.
    pub fn next_ns(&mut self) -> u8 {
        let n = self.ns;
        self.ns ^= 1;
        n
    }

    /// Return the current N(R) (expected from the card).
    pub fn current_nr(&self) -> u8 {
        self.nr
    }

    /// Advance N(R) after a correctly-received I-block.
    pub fn advance_nr(&mut self) {
        self.nr ^= 1;
    }

    /// Reset both sequence numbers to 0 (post-RESYNCH, ISO §11.6.3.4).
    pub fn reset(&mut self) {
        self.ns = 0;
        self.nr = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── LRC computation ───────────────────────────────────────────────

    #[test]
    fn t1_lrc_compute_and_check() {
        // ISO 7816-3 §11.3.3 Table 18: LRC = XOR of NAD+PCB+LEN+INF.
        // Round-trip: encode then verify XOR(whole block) = 0x00.
        let block = T1Block::i_block(0, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let wire = block.encode().unwrap();
        // LRC check over the whole wire buffer must yield 0x00.
        assert_eq!(lrc_check(&wire), 0x00, "LRC of full block must be 0x00");
        // The LRC byte itself is the XOR of the prefix bytes.
        let prefix_lrc = lrc_compute(&wire[..wire.len() - 1]);
        assert_eq!(prefix_lrc, *wire.last().unwrap(), "LRC byte mismatch");
    }

    // ── I-block encode + sequence number ──────────────────────────────

    #[test]
    fn t1_iblock_encode_ns0() {
        // I-block with N(S)=0: PCB[7:6]=00, PCB[6]=0 (NS=0), PCB[5]=0 (no more).
        let block = T1Block::i_block(0, &[0xAA, 0xBB]);
        let wire = block.encode().unwrap();
        // NAD = 0x00
        assert_eq!(wire[0], 0x00, "NAD must be 0x00");
        // PCB: bits 7=0 (I-block), 6=0 (NS=0), 5=0 (no M) → 0x00.
        assert_eq!(wire[1], 0x00, "PCB for I(NS=0) must be 0x00");
        // LEN = 2.
        assert_eq!(wire[2], 2, "LEN must be 2");
        // INF.
        assert_eq!(wire[3], 0xAA);
        assert_eq!(wire[4], 0xBB);
        // LRC check.
        assert_eq!(lrc_check(&wire), 0x00);
    }

    #[test]
    fn t1_iblock_encode_ns1() {
        // I-block with N(S)=1: PCB = PCB_IBLOCK_NS_BIT = 0x40.
        let block = T1Block::i_block(1, &[0x01]);
        let wire = block.encode().unwrap();
        assert_eq!(wire[1], 0x40, "PCB for I(NS=1) must be 0x40");
        assert_eq!(lrc_check(&wire), 0x00);
    }

    // ── I-block sequence-number wrap (0 → 1 → 0) ────────────────────

    #[test]
    fn t1_iblock_sequence_wrap() {
        // ISO 7816-3 §11.6.1: N(S) toggles 0 → 1 → 0 … per I-block sent.
        let mut state = T1SeqState::default();
        assert_eq!(state.next_ns(), 0);
        assert_eq!(state.next_ns(), 1);
        assert_eq!(state.next_ns(), 0); // wraps
        assert_eq!(state.next_ns(), 1);
        // N(R) advances independently on receive.
        state.advance_nr();
        assert_eq!(state.current_nr(), 1);
        state.advance_nr();
        assert_eq!(state.current_nr(), 0); // wraps
    }

    // ── R-block ACK/NAK encoding ──────────────────────────────────────

    #[test]
    fn t1_rblock_ack_nr0() {
        // ISO 7816-3 §11.6.2.2: R-block ACK N(R)=0: PCB = 0x80.
        let block = T1Block::r_block_ack(0);
        assert!(block.is_rblock());
        assert!(!block.r_error());
        assert_eq!(block.nr(), 0);
        let wire = block.encode().unwrap();
        // R(ACK, NR=0): PCB_RBLOCK_BASE | 0 | 0 = 0x80.
        assert_eq!(wire[1], 0x80, "PCB for R(ACK,NR=0) = 0x80");
        assert_eq!(lrc_check(&wire), 0x00);
    }

    #[test]
    fn t1_rblock_nak_nr1() {
        // ISO 7816-3 §11.6.2.2: R-block NAK N(R)=1: error bit 1 set.
        // PCB = PCB_RBLOCK_BASE | PCB_RBLOCK_NR_BIT | PCB_RBLOCK_ERR1
        //     = 0x80 | 0x10 | 0x01 = 0x91.
        let block = T1Block::r_block_nak(1);
        assert!(block.is_rblock());
        assert!(block.r_error());
        assert_eq!(block.nr(), 1);
        let wire = block.encode().unwrap();
        assert_eq!(wire[1], 0x91, "PCB for R(NAK,NR=1) = 0x91");
        assert_eq!(lrc_check(&wire), 0x00);
    }

    // ── S-block IFS request ───────────────────────────────────────────

    #[test]
    fn t1_sblock_ifs_request() {
        // ISO 7816-3 §11.6.3.1: S(IFS request) PCB = 0xC1, INF = [ifsd].
        let block = T1Block::s_ifs_request(0xFE); // IFSD = 254
        assert!(block.is_sblock());
        assert_eq!(block.pcb, PCB_SBLOCK_IFS_REQ);
        assert_eq!(block.inf, &[0xFE]);
        let wire = block.encode().unwrap();
        assert_eq!(wire[1], 0xC1, "S(IFS req) PCB = 0xC1");
        assert_eq!(wire[2], 1, "LEN = 1");
        assert_eq!(wire[3], 0xFE, "INF = IFSD value");
        assert_eq!(lrc_check(&wire), 0x00);
    }

    // ── S-block WTX response ──────────────────────────────────────────

    #[test]
    fn t1_sblock_wtx_response() {
        // ISO 7816-3 §11.6.3.2: S(WTX response) PCB = 0xE3.
        let block = T1Block::s_wtx_response(0x01);
        assert!(block.is_sblock());
        assert_eq!(block.pcb, PCB_SBLOCK_WTX_RESP);
        let wire = block.encode().unwrap();
        assert_eq!(wire[1], 0xE3, "S(WTX resp) PCB = 0xE3");
        assert_eq!(lrc_check(&wire), 0x00);
    }

    // ── Decode round-trip ─────────────────────────────────────────────

    #[test]
    fn t1_decode_iblock_roundtrip() {
        // Encode then decode an I-block and verify all fields survive.
        let orig = T1Block::i_block(1, &[0x10, 0x20, 0x30]);
        let wire = orig.encode().unwrap();
        let decoded = T1Block::decode(&wire).expect("decode must succeed");
        assert_eq!(decoded.nad, 0x00);
        assert!(decoded.is_iblock());
        assert_eq!(decoded.ns(), 1);
        assert_eq!(decoded.inf, &[0x10, 0x20, 0x30]);
    }

    #[test]
    fn t1_decode_rejects_bad_lrc() {
        // Corrupt the LRC byte and verify decode returns an error.
        let block = T1Block::i_block(0, &[0xAA]);
        let mut wire = block.encode().unwrap();
        *wire.last_mut().unwrap() ^= 0xFF; // flip all bits in LRC
        let r = T1Block::decode(&wire);
        assert!(r.is_err(), "corrupted LRC must be rejected");
    }

    #[test]
    fn t1_decode_too_short() {
        // 3 bytes is below the minimum NAD+PCB+LEN+LRC = 4.
        let r = T1Block::decode(&[0x00, 0x00, 0x00]);
        assert!(r.is_err());
    }
}
