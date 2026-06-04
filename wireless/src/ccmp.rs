//! AES-CCMP — CTR-with-CBC-MAC frame encryption (clean-room).
//!
//! Spec: IEEE Std 802.11-2020 §12.5.3 (CCMP). Public IEEE document.
//!   <https://standards.ieee.org/ieee/802.11/7028/>
//! No GPL Linux source consulted.
//!
//! CCMP is the WPA2 (and WPA3-Personal-Compatibility) data-frame
//! cipher. Each MPDU carries an 8-byte CCMP header in front of the
//! frame body and an 8-byte MIC at the tail. The cipher's block
//! primitive is AES-128 in CCM mode (RFC 3610) with the 802.11-
//! specific nonce + AAD construction this module owns.
//!   <https://datatracker.ietf.org/doc/html/rfc3610>
//!
//! ## CCMP header layout (§12.5.3.2)
//!
//! ```text
//!   0..1: PN0, PN1               (low 16 bits of packet number, LE)
//!   2:    Reserved                0
//!   3:    KeyID octet            (bits 0..4 reserved, 5 ExtIV=1, 6..7 KeyID)
//!   4..7: PN2, PN3, PN4, PN5     (high 32 bits of packet number, LE)
//! ```
//!
//! ## Nonce (§12.5.3.3.4)
//!
//! ```text
//!   0:    Nonce Flags
//!           bit 0..3: priority (TID, 0 for non-QoS)
//!           bit 4:    Management (1 if mgmt frame)
//!           bits 5..7: Reserved
//!   1..7: A2 — transmitter MAC address (6 bytes)
//!   7..13: PN — packet number, BIG-ENDIAN per §12.5.3.3.4
//! ```
//!
//! Total nonce = 13 bytes.
//!
//! ## AAD (§12.5.3.3.3)
//!
//! Build from the MPDU header — masking out the muted fields per
//! the spec table:
//! - FC[Subtype 4..7] zeroed
//! - FC[Retry, PowerMgmt, MoreData] cleared
//! - Duration set to 0
//! - SeqCtrl[FragNum] preserved, [SeqNum] cleared
//! - QoS Control field's TID (4 bits) preserved, rest cleared
//!
//! AAD length is either 22 (no Address4 / no QoS), 24 (with QoS),
//! 28 (with Address4), or 30 (with both).

use alloc::vec::Vec;

/// CCMP header byte length.
pub const CCMP_HDR_LEN: usize = 8;
/// CCMP MIC byte length.
pub const CCMP_MIC_LEN: usize = 8;
/// Nonce length per §12.5.3.3.4.
pub const CCMP_NONCE_LEN: usize = 13;

/// Errors from the CCMP path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CcmpError {
    /// Frame body was too short to carry a CCMP header + MIC.
    TooShort,
    /// CCMP header had ExtIV=0 (= TKIP / unencrypted, not CCMP).
    NotEncrypted,
    /// AES-CCM decryption rejected the MIC.
    AuthFailed,
    /// Packet number didn't strictly increase — replay attack
    /// suspected (§12.5.3.4.4).
    Replay,
}

/// AES-CCM primitive — caller plugs in the actual AES-128-CCM
/// implementation (production wires through `narf-crypto`; test
/// stubs return deterministic blocks).
pub trait AesCcm {
    /// AES-128-CCM encrypt-and-tag.
    /// `nonce` is exactly `CCMP_NONCE_LEN` bytes; `tag` returned
    /// is `CCMP_MIC_LEN` bytes.
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; CCMP_NONCE_LEN],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> [u8; CCMP_MIC_LEN];

    /// AES-128-CCM decrypt-and-verify. Returns `Ok` if the tag
    /// matches; the ciphertext slice is mutated to plaintext on
    /// success and left as-is on failure.
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; CCMP_NONCE_LEN],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; CCMP_MIC_LEN],
    ) -> Result<(), CcmpError>;
}

/// Build a CCMP header for `(packet_number, key_id)`.
pub fn build_ccmp_header(pn: u64, key_id: u8) -> [u8; CCMP_HDR_LEN] {
    let mut hdr = [0u8; CCMP_HDR_LEN];
    let pn = pn & 0x0000_FFFF_FFFF_FFFF; // 48-bit
    hdr[0] = (pn & 0xFF) as u8;
    hdr[1] = ((pn >> 8) & 0xFF) as u8;
    hdr[2] = 0; // Reserved
    hdr[3] = (1 << 5) | ((key_id & 0x3) << 6); // ExtIV=1
    hdr[4] = ((pn >> 16) & 0xFF) as u8;
    hdr[5] = ((pn >> 24) & 0xFF) as u8;
    hdr[6] = ((pn >> 32) & 0xFF) as u8;
    hdr[7] = ((pn >> 40) & 0xFF) as u8;
    hdr
}

/// Decode a CCMP header. Returns `(packet_number, key_id)`. Fails
/// if ExtIV bit is clear (means the frame isn't CCMP-encrypted).
pub fn decode_ccmp_header(hdr: &[u8; CCMP_HDR_LEN]) -> Result<(u64, u8), CcmpError> {
    if hdr[3] & (1 << 5) == 0 {
        return Err(CcmpError::NotEncrypted);
    }
    let pn = (hdr[0] as u64)
        | ((hdr[1] as u64) << 8)
        | ((hdr[4] as u64) << 16)
        | ((hdr[5] as u64) << 24)
        | ((hdr[6] as u64) << 32)
        | ((hdr[7] as u64) << 40);
    let key_id = (hdr[3] >> 6) & 0x3;
    Ok((pn, key_id))
}

/// Build the CCMP nonce per §12.5.3.3.4.
///
/// `priority` is the QoS TID (or 0 for non-QoS). `mgmt` is `true`
/// for management frames. `a2` is the transmitter MAC.
pub fn build_nonce(priority: u8, mgmt: bool, a2: &[u8; 6], pn: u64) -> [u8; CCMP_NONCE_LEN] {
    let mut nonce = [0u8; CCMP_NONCE_LEN];
    nonce[0] = (priority & 0x0F) | ((mgmt as u8) << 4);
    nonce[1..7].copy_from_slice(a2);
    // PN is big-endian within the nonce per the spec.
    let pn = pn & 0x0000_FFFF_FFFF_FFFF;
    nonce[7] = ((pn >> 40) & 0xFF) as u8;
    nonce[8] = ((pn >> 32) & 0xFF) as u8;
    nonce[9] = ((pn >> 24) & 0xFF) as u8;
    nonce[10] = ((pn >> 16) & 0xFF) as u8;
    nonce[11] = ((pn >> 8) & 0xFF) as u8;
    nonce[12] = (pn & 0xFF) as u8;
    nonce
}

/// Build the AAD for an MPDU header per §12.5.3.3.3. Masks the
/// muted bits in Frame Control + Duration + SeqCtrl per the spec.
///
/// `mac_header` must be the contiguous 802.11 header (before the
/// CCMP header / frame body). Returns the AAD (length 22..=30
/// depending on Address4 / QoS presence).
pub fn build_aad(mac_header: &[u8]) -> Vec<u8> {
    if mac_header.len() < 24 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(mac_header.len());

    // Frame Control with muted bits zeroed (§12.5.3.3.3).
    let fc_lo = mac_header[0];
    let fc_hi = mac_header[1];
    // Mute Subtype bits 4..7 of FC[0]: we keep them as-is per Note 1
    // (subtype is part of AAD); FC[1] mute Retry(11), PwrMgmt(12),
    // MoreData(13) — bits 3, 4, 5 in the high byte.
    let fc_hi_masked = fc_hi & !(0x38);
    out.push(fc_lo);
    out.push(fc_hi_masked);
    // Per IEEE 802.11-2020 §12.5.3.3.3, AAD construction skips
    // the Duration/ID field — it goes straight from FC to A1.
    // (Earlier versions of this driver inserted two zero bytes
    // for Duration; that produced a 24-byte AAD that wouldn't
    // round-trip with any conformant peer.)
    // Address1, 2, 3 — copied as-is.
    out.extend_from_slice(&mac_header[4..22]);
    // SeqCtrl: keep FragNum (low 4 bits of byte 22), zero SeqNum (rest).
    out.push(mac_header[22] & 0x0F);
    out.push(0);

    // If a 4th address is present (ToDS=FromDS=1), include 6 bytes.
    let to_ds = (fc_hi & 0x01) != 0;
    let from_ds = (fc_hi & 0x02) != 0;
    let has_addr4 = to_ds && from_ds;
    let header_offset = if has_addr4 { 30 } else { 24 };
    if has_addr4 && mac_header.len() >= 30 {
        out.extend_from_slice(&mac_header[24..30]);
    }

    // QoS frames (subtype with bit 3 set in the data-frame range)
    // append the 2-byte QoS Control field with all bits zeroed
    // except the TID nibble (bits 0..4).
    // Type=Data (FC[0] bits 2..4 == 0b10) and bit 7 of FC[0] is the
    // QoS-data subtype indicator (subtype 0x8..=0xF for QoS data).
    let frame_type = (fc_lo >> 2) & 0x3;
    let subtype = (fc_lo >> 4) & 0xF;
    let qos = frame_type == 2 && subtype & 0x8 != 0;
    if qos && mac_header.len() >= header_offset + 2 {
        let qos_lo = mac_header[header_offset] & 0x0F; // TID
        out.push(qos_lo);
        out.push(0);
    }

    out
}

// ── Replay tracker (§12.5.3.4.4) ──────────────────────────────────

/// Per-key replay window. Production should track a window of 16
/// PNs to allow out-of-order delivery; today we enforce strict
/// monotonic-increase, which is conservative + simpler.
#[derive(Copy, Clone, Debug, Default)]
pub struct ReplayWindow {
    pub last_seen_pn: u64,
}

impl ReplayWindow {
    /// Validate `pn`. Returns `Err(CcmpError::Replay)` if `pn` is
    /// not strictly greater than the last accepted.
    pub fn check(&mut self, pn: u64) -> Result<(), CcmpError> {
        if pn <= self.last_seen_pn {
            return Err(CcmpError::Replay);
        }
        self.last_seen_pn = pn;
        Ok(())
    }
}

// ── End-to-end protect / unprotect ────────────────────────────────

/// Encrypt + tag a frame body in place. Caller hands in:
/// - `mac_header`: the unencrypted 802.11 MAC header (24..=30 bytes).
/// - `key`: the 16-byte temporal key (TK from PTK).
/// - `pn`: the packet number to use (caller increments per frame).
/// - `key_id`: 0..=3.
/// - `priority` / `mgmt`: nonce inputs.
/// - `body`: the plaintext frame body, mutated in-place to ciphertext.
///
/// Returns the on-the-wire layout: `[ccmp_header || ciphertext || mic]`.
pub fn protect(
    aes: &dyn AesCcm,
    mac_header: &[u8],
    key: &[u8; 16],
    pn: u64,
    key_id: u8,
    priority: u8,
    mgmt: bool,
    body: &mut [u8],
) -> Vec<u8> {
    let hdr = build_ccmp_header(pn, key_id);
    let nonce = build_nonce(priority, mgmt, mac_header_a2(mac_header), pn);
    let aad = build_aad(mac_header);
    let mic = aes.encrypt(key, &nonce, &aad, body);
    let mut out = Vec::with_capacity(CCMP_HDR_LEN + body.len() + CCMP_MIC_LEN);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(body);
    out.extend_from_slice(&mic);
    out
}

/// Decrypt + verify an on-the-wire CCMP frame body. `protected` is
/// `[ccmp_header || ciphertext || mic]`. On success the mutated
/// plaintext is returned (the input is consumed).
pub fn unprotect(
    aes: &dyn AesCcm,
    mac_header: &[u8],
    key: &[u8; 16],
    priority: u8,
    mgmt: bool,
    replay: &mut ReplayWindow,
    protected: &mut [u8],
) -> Result<Vec<u8>, CcmpError> {
    if protected.len() < CCMP_HDR_LEN + CCMP_MIC_LEN {
        return Err(CcmpError::TooShort);
    }
    let hdr_bytes: [u8; CCMP_HDR_LEN] = protected[..CCMP_HDR_LEN]
        .try_into()
        .map_err(|_| CcmpError::TooShort)?;
    let (pn, _key_id) = decode_ccmp_header(&hdr_bytes)?;
    replay.check(pn)?;

    let nonce = build_nonce(priority, mgmt, mac_header_a2(mac_header), pn);
    let aad = build_aad(mac_header);
    let body_len = protected.len() - CCMP_HDR_LEN - CCMP_MIC_LEN;
    let mut tag = [0u8; CCMP_MIC_LEN];
    tag.copy_from_slice(&protected[CCMP_HDR_LEN + body_len..]);
    let body = &mut protected[CCMP_HDR_LEN..CCMP_HDR_LEN + body_len];
    aes.decrypt(key, &nonce, &aad, body, &tag)?;
    Ok(body.to_vec())
}

fn mac_header_a2(mac_header: &[u8]) -> &[u8; 6] {
    // §9.2.4: Address2 (TA) is at offset 10..16.
    let arr: &[u8; 6] = mac_header[10..16]
        .try_into()
        .expect("mac header < 16 bytes");
    arr
}
