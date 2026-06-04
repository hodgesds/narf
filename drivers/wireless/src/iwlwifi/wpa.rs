//! iwlwifi WPA2/RSN — HMAC-SHA1 primitive + 4-way handshake glue.
//!
//! Stage 4: provides the `HmacSha1` adapter that fulfils the
//! `narf_wireless::eapol::HmacPrimitive` contract, then re-exports
//! the supplicant-side 4-way handshake types from `narf_wireless`.
//!
//! ## HMAC-SHA1
//!
//! WPA2-Personal (AKM-1 / AKM-2) uses HMAC-SHA1-160 as the PRF
//! primitive (802.11-2020 §12.7.1.2). The output is 20 bytes per
//! round; the PTK PRF needs 64 bytes total (2×16-byte KCK+KEK +
//! 16-byte TK for CCMP-128), so it takes 4 rounds and truncates.
//!
//! narf-crypto carries HMAC-SHA256 (`narf_crypto::hkdf::hmac_sha256`)
//! but not HMAC-SHA1. This module supplies a compact clean-room SHA-1
//! implementation sufficient for the MIC/PRF path.
//!
//! ### SHA-1 reference
//! FIPS PUB 180-4 §6.1 — SHA-1 message schedule and round function.
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
//!
//! ### HMAC-SHA1 reference
//! RFC 2104 §2 — HMAC construction.
//! <https://datatracker.ietf.org/doc/html/rfc2104>
//!
//! ### PRF-X / 4-way handshake
//! IEEE 802.11-2020 §12.7.1.2 (PRF) + §12.7.6 (4-way handshake).
//! <https://standards.ieee.org/ieee/802.11/7028/>

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use narf_wireless::eapol::{derive_ptk, HmacPrimitive, KeyFrame, Ptk, Supplicant};

// ── SHA-1 (FIPS 180-4 §6.1) ─────────────────────────────────────────

/// SHA-1 context. State is 5×u32 big-endian words; input is buffered
/// and processed in 64-byte (512-bit) blocks.
struct Sha1 {
    state: [u32; 5],
    count: u64, // total bits processed
    buf: [u8; 64],
    buf_len: usize,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            // Initial hash values from FIPS 180-4 §5.3.1.
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            count: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut off = 0;
        while off < data.len() {
            let take = (64 - self.buf_len).min(data.len() - off);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[off..off + take]);
            self.buf_len += take;
            off += take;
            self.count += (take as u64) * 8;
            if self.buf_len == 64 {
                let block: [u8; 64] = self.buf;
                self.process_block(&block);
                self.buf_len = 0;
            }
        }
    }

    fn finalize(mut self) -> [u8; 20] {
        // Padding: 0x80 + zeros + 64-bit big-endian bit-count.
        let bit_len = self.count;
        self.update(&[0x80]);
        let zeros_needed = if self.buf_len <= 56 {
            56 - self.buf_len
        } else {
            64 + 56 - self.buf_len
        };
        let pad = [0u8; 64];
        self.update(&pad[..zeros_needed]);
        self.update(&bit_len.to_be_bytes());

        let mut out = [0u8; 20];
        for (i, &w) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        // Message schedule W[0..80].
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // Round constants (FIPS 180-4 §4.2.1).
        const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), K[0]),
                20..=39 => (b ^ c ^ d, K[1]),
                40..=59 => ((b & c) | (b & d) | (c & d), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

// ── HMAC-SHA1 (RFC 2104 §2) ─────────────────────────────────────────

/// HMAC-SHA1. Returns the 20-byte MAC.
///
/// Key longer than 64 bytes is pre-hashed per RFC 2104 §2.
/// Used both by the 4-way handshake PRF and by the group-rekey
/// MIC validation path (`rekey::group_rekey_handle_m1`).
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    // Key normalisation.
    let mut k = [0u8; 64];
    if key.len() > 64 {
        // Hash the key per RFC 2104 §2.
        let mut hs = Sha1::new();
        hs.update(key);
        let hk = hs.finalize();
        k[..20].copy_from_slice(&hk);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ── HmacPrimitive adapter ────────────────────────────────────────────

/// `HmacPrimitive` adapter that uses HMAC-SHA1.
///
/// Pass this to `narf_wireless::eapol::derive_ptk` and `prf` to
/// implement the WPA2-Personal (AKM-1 / AKM-2) key derivation.
pub struct HmacSha1;

impl HmacPrimitive for HmacSha1 {
    fn out_len(&self) -> usize {
        20
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac_sha1(key, data).to_vec()
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Derive the Pairwise Transient Key (PTK) from the given inputs.
///
/// `pmk` is the 32-byte PSK from PBKDF2-SHA1 (or a pre-agreed PMK).
/// `aa` is the AP BSSID; `sa` is the station MAC address.
/// `anonce` and `snonce` are the 32-byte nonces from M1 and M2.
/// `tk_len` is 16 for CCMP-128.
///
/// Reference: 802.11-2020 §12.7.1.3 (PTK derivation) +
/// §12.7.6 (4-way handshake message flow).
pub fn derive_ptk_sha1(
    pmk: &[u8],
    aa: &[u8; 6],
    sa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    tk_len: usize,
) -> Ptk {
    derive_ptk(&HmacSha1, pmk, aa, sa, anonce, snonce, tk_len)
}

/// Result of a completed 4-way handshake on the supplicant side.
pub struct HandshakeResult {
    pub ptk: Ptk,
}

// ── AssocResponse stub ───────────────────────────────────────────────

/// Minimal fields from a parsed 802.11 Association Response body
/// (§9.3.3.7): status code + Association ID. The iwlwifi driver
/// validates these before advancing to the 4-way phase.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AssocResponse {
    /// 802.11 status code (0 = success). Non-zero values map to
    /// `WirelessError::AssocDenied`.
    pub status_code: u16,
    /// Association ID (AID) assigned by the AP, bits[13:0].
    pub aid: u16,
}

impl AssocResponse {
    /// Decode from the fixed-field bytes of an Assoc Response body
    /// (capability[2] + status[2] + AID[2]).
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 6 {
            return None;
        }
        // Capability Info at [0..2] is skipped for now.
        let status_code = u16::from_le_bytes([buf[2], buf[3]]);
        let aid = u16::from_le_bytes([buf[4], buf[5]]) & 0x3FFF;
        Some(Self { status_code, aid })
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_wireless::eapol::{
        FourWayState, KeyFrame, Supplicant, KEY_DESCRIPTOR_RSN, KI_KEY_ACK, KI_KEY_MIC,
        KI_KEY_TYPE_PAIRWISE, KI_SECURE, KI_VERSION_HMAC_SHA1_AES,
    };

    // ── FIPS 180-4 SHA-1 known-answer ─────────────────────────────
    // SHA-1("abc") = A9993E364706816ABA3E25717850C26C9CD0D89D
    fn smoke_wpa_sha1_abc_vector() -> TestResult {
        let mut h = Sha1::new();
        h.update(b"abc");
        let d = h.finalize();
        let expected: [u8; 20] = [
            0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50,
            0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
        ];
        if d != expected {
            return TestResult::Fail("SHA-1(abc) FIPS vector mismatch");
        }
        TestResult::Pass
    }

    // ── RFC 2104 HMAC-SHA1 test vector (from §Test Cases) ─────────
    // HMAC-SHA1 key = 0x0b * 20, data = "Hi There"
    // Expected: B617318655057264E28BC0B6FB378C8EF146BE00
    fn smoke_wpa_hmac_sha1_rfc2104_vector() -> TestResult {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha1(&key, data);
        let expected: [u8; 20] = [
            0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xE2, 0x8B, 0xC0, 0xB6, 0xFB, 0x37,
            0x8C, 0x8E, 0xF1, 0x46, 0xBE, 0x00,
        ];
        if mac != expected {
            return TestResult::Fail("HMAC-SHA1 RFC 2104 vector mismatch");
        }
        TestResult::Pass
    }

    // ── EAPOL-Key frame layout: Key Info bits ──────────────────────
    // Verify that M1 flag encoding is correct per 802.11-2020 §12.7.2.
    fn smoke_wpa_eapol_key_info_m1_bits() -> TestResult {
        // M1: Key ACK=1, MIC=0, Pairwise=1, Install=0.
        let mut m1 = KeyFrame::empty(16);
        m1.descriptor_type = KEY_DESCRIPTOR_RSN;
        m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK;
        m1.replay_counter = 1;
        m1.key_nonce = [0xAAu8; 32];

        if !m1.key_ack() {
            return TestResult::Fail("M1 key_ack should be set");
        }
        if m1.has_mic() {
            return TestResult::Fail("M1 should not have MIC");
        }
        if !m1.pairwise() {
            return TestResult::Fail("M1 should be pairwise");
        }
        if m1.install() {
            return TestResult::Fail("M1 should not have Install");
        }
        TestResult::Pass
    }

    // ── EAPOL-Key frame encode / decode round-trip ─────────────────
    fn smoke_wpa_eapol_key_frame_encode_decode() -> TestResult {
        let mut frame = KeyFrame::empty(16);
        frame.descriptor_type = KEY_DESCRIPTOR_RSN;
        frame.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_VERSION_HMAC_SHA1_AES;
        frame.replay_counter = 0x0102_0304_0506_0708;
        frame.key_nonce = [0x55u8; 32];
        frame.key_data = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];

        let wire = frame.encode();
        let decoded = KeyFrame::decode(&wire, 16);
        let decoded = match decoded {
            Some(d) => d,
            None => return TestResult::Fail("KeyFrame::decode returned None"),
        };

        if decoded.descriptor_type != KEY_DESCRIPTOR_RSN {
            return TestResult::Fail("descriptor_type wrong after encode/decode");
        }
        if decoded.replay_counter != frame.replay_counter {
            return TestResult::Fail("replay_counter wrong after encode/decode");
        }
        if decoded.key_nonce != frame.key_nonce {
            return TestResult::Fail("key_nonce wrong after encode/decode");
        }
        if decoded.key_data != frame.key_data {
            return TestResult::Fail("key_data wrong after encode/decode");
        }
        TestResult::Pass
    }

    // ── 4-Way Handshake state machine: M1 → M2 ────────────────────
    fn smoke_wpa_4way_m1_m2_transition() -> TestResult {
        let aa = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let snonce = [0x11u8; 32];
        let pmk = [0x22u8; 32];

        let mut sup = Supplicant::new(aa, sa, snonce);

        // Craft a minimal M1.
        let mut m1 = KeyFrame::empty(16);
        m1.descriptor_type = KEY_DESCRIPTOR_RSN;
        m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK;
        m1.replay_counter = 1;
        m1.key_nonce = [0xAAu8; 32];

        let result = sup.handle(&HmacSha1, &pmk, 16, &m1);
        match result {
            Ok(Some(m2)) => {
                if sup.state != FourWayState::WaitM3 {
                    return TestResult::Fail("state should be WaitM3 after M1");
                }
                if !m2.pairwise() {
                    return TestResult::Fail("M2 should have pairwise bit");
                }
                if !m2.has_mic() {
                    return TestResult::Fail("M2 should have MIC bit");
                }
                if m2.replay_counter != 1 {
                    return TestResult::Fail("M2 replay counter should mirror M1");
                }
                if m2.key_nonce != snonce {
                    return TestResult::Fail("M2 key_nonce should be SNonce");
                }
            }
            Ok(None) => return TestResult::Fail("expected M2 response"),
            Err(_) => return TestResult::Fail("handle_m1 returned error"),
        }
        TestResult::Pass
    }

    // ── PTK derivation produces non-zero KCK/KEK/TK ───────────────
    // Full vector test requires PBKDF2-SHA1 to produce the PMK from
    // a passphrase; since narf-crypto doesn't carry SHA-1/PBKDF2-SHA1,
    // we use a raw PMK constant and verify the PRF output is non-zero
    // and deterministic.
    fn smoke_wpa_ptk_deriv_nonzero_and_deterministic() -> TestResult {
        let pmk = [0x42u8; 32];
        let aa = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let anonce = [0x11u8; 32];
        let snonce = [0x22u8; 32];

        let ptk1 = derive_ptk_sha1(&pmk, &aa, &sa, &anonce, &snonce, 16);
        let ptk2 = derive_ptk_sha1(&pmk, &aa, &sa, &anonce, &snonce, 16);

        if ptk1.kck != ptk2.kck {
            return TestResult::Fail("PTK derivation not deterministic (KCK)");
        }
        if ptk1.kck.iter().all(|&b| b == 0) {
            return TestResult::Fail("KCK is all-zeros");
        }
        if ptk1.kek.iter().all(|&b| b == 0) {
            return TestResult::Fail("KEK is all-zeros");
        }
        if ptk1.tk.len() != 16 {
            return TestResult::Fail("TK length wrong (expected 16 for CCMP-128)");
        }
        TestResult::Pass
    }

    // ── AssocResponse decode ───────────────────────────────────────
    fn smoke_wpa_assoc_response_decode() -> TestResult {
        // cap=0x0431, status=0 (success), AID=1.
        let buf: &[u8] = &[0x31, 0x04, 0x00, 0x00, 0x01, 0xC0];
        let resp = match AssocResponse::decode(buf) {
            Some(r) => r,
            None => return TestResult::Fail("AssocResponse::decode returned None"),
        };
        if resp.status_code != 0 {
            return TestResult::Fail("status_code wrong");
        }
        // AID = 0xC001 & 0x3FFF = 1.
        if resp.aid != 1 {
            return TestResult::Fail("AID wrong");
        }
        TestResult::Pass
    }

    kernel_test_in!("drivers/wireless/iwlwifi/wpa", smoke_wpa_sha1_abc_vector);
    kernel_test_in!(
        "drivers/wireless/iwlwifi/wpa",
        smoke_wpa_hmac_sha1_rfc2104_vector
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/wpa",
        smoke_wpa_eapol_key_info_m1_bits
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/wpa",
        smoke_wpa_eapol_key_frame_encode_decode
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/wpa",
        smoke_wpa_4way_m1_m2_transition
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/wpa",
        smoke_wpa_ptk_deriv_nonzero_and_deterministic
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/wpa",
        smoke_wpa_assoc_response_decode
    );
}
