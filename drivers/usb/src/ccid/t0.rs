//! T=0 character-protocol APDU framing for USB CCID.
//!
//! ## References
//!
//! - **ISO/IEC 7816-3:2006** §10 — T=0 transmission protocol.
//!   APDU command structure: CLA(1) INS(1) P1(1) P2(1) [Lc(1) DATA] [Le(1)].
//!   Card response: [DATA] SW1(1) SW2(1).
//! - **ISO/IEC 7816-4:2013** §5.3 — Four APDU command cases:
//!   Case 1 (no body), Case 2 (Le only), Case 3 (Lc + data), Case 4
//!   (Lc + data + Le).
//! - **USB CCID spec rev 1.1 §6.2** — XfrBlock wLevelParameter = 0 for
//!   a single-block T=0 exchange; the CCID reader passes the bare APDU
//!   to the ICC, returns SW1:SW2 in the RDR_to_PC_DataBlock payload.
//! - **pcsc-lite / libccid** `src/commands.c` — GET_RESPONSE chaining:
//!   on SW1=0x61 the reader issues `CLA 0xC0 0x00 0x00 Le=XX` where
//!   XX = SW2. Used here verbatim.
//!
//! ## What is NOT here
//!
//! - T=15 / global-interface parameters and PPS negotiation — both
//!   default-good for CCID; deferred per task scope.
//! - Extended APDU (Lc/Le > 255) — T=0 is a byte-at-a-time protocol
//!   that predates extended APDUs; only short APDUs are in scope.

extern crate alloc;

use super::CcidError;
use alloc::vec::Vec;

// ── SW1 constants ─────────────────────────────────────────────────────

/// SW1 = 0x61: card has XX bytes of additional response data available.
/// Caller should issue GET_RESPONSE with Le = SW2 (ISO 7816-3 §10.3.3).
pub const SW1_GET_RESPONSE: u8 = 0x61;

/// GET_RESPONSE INS byte (ISO 7816-4 §7.6.1). Used for T=0 chaining.
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// Maximum GET_RESPONSE iterations to prevent infinite chaining loops.
pub const MAX_GET_RESPONSE_ITERS: usize = 16;

// ── T0Apdu ────────────────────────────────────────────────────────────

/// A T=0 command APDU (ISO 7816-4 §5.3). The four ISO 7816-4 cases
/// correspond to the `build_case*` constructors below.
///
/// - Case 1: CLA INS P1 P2                  (no body, no expected response data)
/// - Case 2: CLA INS P1 P2 Le               (no body, Le bytes expected)
/// - Case 3: CLA INS P1 P2 Lc DATA          (Lc data bytes, no response data)
/// - Case 4: CLA INS P1 P2 Lc DATA Le       (Lc data bytes + Le expected)
#[derive(Debug, Clone)]
pub struct T0Apdu {
    /// Raw APDU bytes ready to pass to `PC_to_RDR_XfrBlock`.
    bytes: Vec<u8>,
    /// Class byte — preserved so GET_RESPONSE can echo the original CLA.
    cla: u8,
}

impl T0Apdu {
    /// Case 1 — no command data, no response data expected (ISO 7816-4 §5.3.1).
    ///
    /// Wire format: CLA INS P1 P2 (4 bytes).
    pub fn build_case1(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            bytes: alloc::vec![cla, ins, p1, p2],
            cla,
        }
    }

    /// Case 2 — no command data, Le response bytes expected (ISO 7816-4 §5.3.2).
    ///
    /// Wire format: CLA INS P1 P2 Le (5 bytes). `le=0` means 256 bytes
    /// per ISO 7816-3 §10.3.2.
    pub fn build_case2(cla: u8, ins: u8, p1: u8, p2: u8, le: u8) -> Self {
        Self {
            bytes: alloc::vec![cla, ins, p1, p2, le],
            cla,
        }
    }

    /// Case 3 — command data only, no response data expected (ISO 7816-4 §5.3.3).
    ///
    /// Wire format: CLA INS P1 P2 Lc DATA (5 + Lc bytes).
    /// Returns `CcidError::BadResponse` if `data` exceeds 255 bytes
    /// (T=0 short APDU limit, ISO 7816-3 §10.3.2).
    pub fn build_case3(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Self, CcidError> {
        if data.len() > 255 {
            return Err(CcidError::ResponseTooLong);
        }
        let lc = data.len() as u8;
        let mut bytes = Vec::with_capacity(5 + data.len());
        bytes.extend_from_slice(&[cla, ins, p1, p2, lc]);
        bytes.extend_from_slice(data);
        Ok(Self { bytes, cla })
    }

    /// Case 4 — command data + response data expected (ISO 7816-4 §5.3.4).
    ///
    /// Wire format: CLA INS P1 P2 Lc DATA Le (6 + Lc bytes).
    /// Returns `CcidError::BadResponse` if `data` exceeds 255 bytes.
    pub fn build_case4(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: u8,
    ) -> Result<Self, CcidError> {
        if data.len() > 255 {
            return Err(CcidError::ResponseTooLong);
        }
        let lc = data.len() as u8;
        let mut bytes = Vec::with_capacity(6 + data.len());
        bytes.extend_from_slice(&[cla, ins, p1, p2, lc]);
        bytes.extend_from_slice(data);
        bytes.push(le);
        Ok(Self { bytes, cla })
    }

    /// Return a reference to the raw APDU bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// CLA byte of the APDU. Used when constructing GET_RESPONSE commands
    /// during chaining (ISO 7816-3 §10.3.3 — CLA must match the original).
    pub fn cla(&self) -> u8 {
        self.cla
    }
}

// ── GET_RESPONSE chaining ─────────────────────────────────────────────

/// Build a T=0 GET_RESPONSE APDU (ISO 7816-4 §7.6.1).
///
/// CLA is echoed from the original command (ISO 7816-3 §10.3.3).
/// INS = 0xC0, P1 = 0x00, P2 = 0x00, Le = `available_bytes` (SW2).
///
/// `le=0` is legal; it means "return all 256 available bytes" per T=0
/// short-APDU convention (ISO 7816-3 §10.3.2).
pub fn build_get_response(cla: u8, available_bytes: u8) -> T0Apdu {
    T0Apdu::build_case2(cla, INS_GET_RESPONSE, 0x00, 0x00, available_bytes)
}

/// Decode a T=0 card response. Returns `(data, sw1, sw2)` where `data`
/// is everything before the 2-byte status word, and sw1/sw2 are the
/// ISO 7816-3 status bytes (§10.3.3 Table 12).
///
/// Returns `CcidError::BadResponse` if the response is shorter than 2
/// bytes (minimum = SW1 + SW2 only).
pub fn decode_response(resp: &[u8]) -> Result<(&[u8], u8, u8), CcidError> {
    if resp.len() < 2 {
        return Err(CcidError::BadResponse);
    }
    let sw1 = resp[resp.len() - 2];
    let sw2 = resp[resp.len() - 1];
    let data = &resp[..resp.len() - 2];
    Ok((data, sw1, sw2))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── T=0 APDU Case encoders ─────────────────────────────────────────

    #[test]
    fn t0_case1_encode() {
        // ISO 7816-4 §5.3.1 — Case 1: CLA INS P1 P2 only.
        let apdu = T0Apdu::build_case1(0x00, 0xA4, 0x04, 0x00);
        assert_eq!(apdu.as_bytes(), &[0x00, 0xA4, 0x04, 0x00]);
        assert_eq!(apdu.cla(), 0x00);
    }

    #[test]
    fn t0_case2_encode() {
        // ISO 7816-4 §5.3.2 — Case 2: CLA INS P1 P2 Le.
        let apdu = T0Apdu::build_case2(0x00, 0xCA, 0x00, 0x6E, 0x00);
        assert_eq!(apdu.as_bytes(), &[0x00, 0xCA, 0x00, 0x6E, 0x00]);
    }

    #[test]
    fn t0_case3_encode() {
        // ISO 7816-4 §5.3.3 — Case 3: CLA INS P1 P2 Lc DATA.
        let data = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
        let apdu = T0Apdu::build_case3(0x00, 0xA4, 0x04, 0x00, &data).unwrap();
        let want: &[u8] = &[
            0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
        ];
        assert_eq!(apdu.as_bytes(), want);
    }

    #[test]
    fn t0_case4_encode() {
        // ISO 7816-4 §5.3.4 — Case 4: CLA INS P1 P2 Lc DATA Le.
        let data = [0x01, 0x02];
        let apdu = T0Apdu::build_case4(0x80, 0xE0, 0x00, 0x00, &data, 0x08).unwrap();
        let want: &[u8] = &[0x80, 0xE0, 0x00, 0x00, 0x02, 0x01, 0x02, 0x08];
        assert_eq!(apdu.as_bytes(), want);
        assert_eq!(apdu.cla(), 0x80);
    }

    #[test]
    fn t0_case3_rejects_oversized_data() {
        // ISO 7816-3 §10.3.2 — T=0 short APDU Lc ≤ 255.
        let big = alloc::vec![0u8; 256];
        let r = T0Apdu::build_case3(0x00, 0xA4, 0x04, 0x00, &big);
        assert!(r.is_err(), "should reject Lc > 255");
    }

    #[test]
    fn t0_get_response_chaining() {
        // ISO 7816-3 §10.3.3 — SW1=0x61 triggers GET_RESPONSE with Le=SW2.
        // Simulate card returning SW1=0x61, SW2=0x08.
        let card_resp = [0x61u8, 0x08];
        let (data, sw1, sw2) = decode_response(&card_resp).unwrap();
        assert_eq!(data, &[]);
        assert_eq!(sw1, SW1_GET_RESPONSE);
        assert_eq!(sw2, 0x08);
        // Build the chained GET_RESPONSE using the original CLA.
        let get_resp = build_get_response(0x00, sw2);
        assert_eq!(get_resp.as_bytes(), &[0x00, 0xC0, 0x00, 0x00, 0x08]);
    }

    #[test]
    fn t0_decode_response_too_short() {
        // Must have at least SW1 + SW2 = 2 bytes.
        let r = decode_response(&[0x90]);
        assert!(r.is_err());
        let r2 = decode_response(&[]);
        assert!(r2.is_err());
    }
}
