//! WPA3 SAE-PK (Public Key) — the station-side verification framing.
//!
//! SAE-PK layers a public-key authentication onto the SAE (Dragonfly)
//! handshake so a password-based network resists evil-twin / offline-dictionary
//! attacks: the password encodes a truncated fingerprint of the AP's ECDSA
//! public key, and the AP proves possession of the matching private key by
//! signing the Confirm transcript (KeyAuth). A station authenticates the AP by
//!
//!   1. recovering the Modifier `M` from the SAE-PK element (AES-SIV under the
//!      SAE KEK),
//!   2. checking `Hash(SSID || M || K_AP)` reproduces the password fingerprint
//!      (with the required leading zero octets), and
//!   3. verifying the ECDSA KeyAuth signature over the exchange transcript with
//!      the AP public key `K_AP`.
//!
//! References: Wi-Fi Alliance WPA3 Specification v3.x (SAE-PK), hostap
//! `src/common/sae_pk.c`. Element IDs, the SAE-PK status code and the FILS
//! element extension IDs are validated against `/usr/src/linux`
//! `include/linux/ieee80211.h`. SAE-PK's wire format is a WFA specification and
//! is not present in the kernel tree, so the password/fingerprint layout and
//! the KeyAuth transcript follow the hostap reference. Only P-256 / SHA-256
//! (SAE group 19) is implemented here.

extern crate alloc;

use alloc::vec::Vec;
use narf_crypto::p256::ecdsa::verify_p256;
use narf_crypto::sha256::Sha256;

/// Authentication status indicating the AP used SAE-PK (IEEE 802.11
/// `WLAN_STATUS_SAE_PK`, validated vs /usr/src/linux ieee80211.h).
pub const WLAN_STATUS_SAE_PK: u16 = 127;

/// Element IDs used by the SAE-PK Confirm carriage (validated vs the kernel
/// `enum ieee80211_eid` / `ieee80211_eid_ext`).
const WLAN_EID_VENDOR_SPECIFIC: u8 = 221;
const WLAN_EID_EXTENSION: u8 = 255;
const WLAN_EID_EXT_FILS_KEY_CONFIRM: u8 = 3;
const WLAN_EID_EXT_FILS_PUBLIC_KEY: u8 = 12;
/// Wi-Fi Alliance OUI (50:6F:9A) prefixing the SAE-PK vendor-specific element.
const WFA_OUI: [u8; 3] = [0x50, 0x6f, 0x9a];

/// SAE-PK Modifier length (hostap `SAE_PK_M_LEN`).
pub const SAE_PK_M_LEN: usize = 16;

/// Fixed DER `SubjectPublicKeyInfo` prefix for an uncompressed NIST P-256
/// (prime256v1) ECDSA public key: SEQUENCE { AlgorithmIdentifier {
/// id-ecPublicKey, prime256v1 }, BIT STRING (unused=0) }. The 65-byte
/// uncompressed point (`0x04 || X || Y`) follows.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// RFC 4648 base32 alphabet, lowercase (hostap `sae_pk_base32_table`).
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

// ── Base32 password / fingerprint ─────────────────────────────────

fn base32_value(c: u8) -> Option<u8> {
    BASE32.iter().position(|&a| a == c).map(|p| p as u8)
}

/// Decode a SAE-PK password (hyphen-separated groups of four base32 chars) into
/// the raw bit buffer, packed MSB-first, plus the base32 character count.
fn base32_decode(password: &str) -> Option<(Vec<u8>, usize)> {
    let mut acc = 0u16;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    let mut nchars = 0usize;
    for &c in password.as_bytes() {
        if c == b'-' {
            continue;
        }
        let v = base32_value(c)? as u16;
        acc = (acc << 5) | v;
        nbits += 5;
        nchars += 1;
        while nbits >= 8 {
            nbits -= 8;
            out.push(((acc >> nbits) & 0xff) as u8);
        }
    }
    if nbits > 0 {
        // Left-justify the remaining bits into a final octet.
        out.push(((acc << (8 - nbits)) & 0xff) as u8);
    }
    Some((out, nchars))
}

/// Read `n` (<=57) bits MSB-first from a packed bit buffer, starting at bit
/// `start`. Returns 0 for bits past the end of the buffer.
fn read_bit(buf: &[u8], bit: usize) -> u8 {
    buf.get(bit / 8)
        .map(|byte| (byte >> (7 - (bit % 8))) & 1)
        .unwrap_or(0)
}

/// Decode the `Sec` parameter and the embedded fingerprint bits from a SAE-PK
/// password. Returns `(sec, fingerprint_bits_packed, fingerprint_bit_len)`,
/// where `sec` is the number of required leading zero octets (3 or 5) and the
/// packed bits are MSB-first. The password-format rules match hostap
/// `sae_pk_valid_password` (minimum length, 4-char groups, hyphen placement);
/// the trailing checksum character is typo protection only and is not verified
/// here.
fn password_fingerprint(password: &str) -> Option<(usize, Vec<u8>, usize)> {
    let len = password.len();
    if len < 14 || len % 5 != 4 {
        return None;
    }
    for (i, &c) in password.as_bytes().iter().enumerate() {
        if i % 5 == 4 {
            if c != b'-' {
                return None;
            }
        } else if base32_value(c).is_none() {
            return None;
        }
    }
    let (buf, nchars) = base32_decode(password)?;
    if nchars % 4 != 0 || buf.is_empty() {
        return None;
    }
    let groups = nchars / 4;
    // The very first decoded bit (Sec_1b) selects Sec: set -> 3, clear -> 5.
    let sec = if buf[0] & 0x80 != 0 { 3 } else { 5 };
    // Each 20-bit group starts with a Sec_1b marker bit; the remaining 19 bits
    // are fingerprint. The final base32 character (5 bits) is the checksum.
    let total_tail = 19 * groups;
    if total_tail < 5 {
        return None;
    }
    let fp_len = total_tail - 5;
    let mut packed = alloc::vec![0u8; fp_len.div_ceil(8)];
    let mut out_bit = 0usize;
    'outer: for g in 0..groups {
        let base = g * 20 + 1; // skip the group's Sec_1b bit
        for i in 0..19 {
            if out_bit == fp_len {
                break 'outer;
            }
            if read_bit(&buf, base + i) != 0 {
                packed[out_bit / 8] |= 1 << (7 - (out_bit % 8));
            }
            out_bit += 1;
        }
    }
    Some((sec, packed, fp_len))
}

/// Compare the password fingerprint against `Hash(SSID || M || K_AP)`: the
/// hash must begin with `sec` zero octets, and the next `fp_bits` bits must
/// equal the embedded fingerprint.
fn fingerprint_matches(hash: &[u8], sec: usize, fingerprint: &[u8], fp_bits: usize) -> bool {
    if hash.len() < sec || 8 * sec + fp_bits > 8 * hash.len() {
        return false;
    }
    if hash[..sec].iter().any(|&b| b != 0) {
        return false;
    }
    (0..fp_bits).all(|i| read_bit(hash, 8 * sec + i) == read_bit(fingerprint, i))
}

/// Validate that `password` is the SAE-PK fingerprint of the AP public key
/// `spki_der` under the given `ssid` and recovered `modifier`.
pub fn validate_fingerprint(
    ssid: &[u8],
    modifier: &[u8; SAE_PK_M_LEN],
    spki_der: &[u8],
    password: &str,
) -> bool {
    let Some((sec, fingerprint, fp_bits)) = password_fingerprint(password) else {
        return false;
    };
    let mut hasher = Sha256::new();
    hasher.update(ssid);
    hasher.update(modifier);
    hasher.update(spki_der);
    let hash = hasher.finalize();
    fingerprint_matches(&hash, sec, &fingerprint, fp_bits)
}

// ── DER parsing (P-256 SubjectPublicKeyInfo + ECDSA signature) ─────

/// Extract the 65-byte uncompressed point (`0x04 || X || Y`) from a DER-encoded
/// P-256 `SubjectPublicKeyInfo`.
fn spki_point(der: &[u8]) -> Option<[u8; 65]> {
    if der.len() != 91 || der[..26] != P256_SPKI_PREFIX || der[26] != 0x04 {
        return None;
    }
    let mut point = [0u8; 65];
    point.copy_from_slice(&der[26..91]);
    Some(point)
}

/// Decode a DER `INTEGER` field (short-form length) into a 32-byte big-endian
/// scalar, stripping an optional leading sign octet and left-padding. Returns
/// `(scalar, bytes_consumed_after_the_0x02_tag_and_length)`.
fn der_integer_32(der: &[u8], mut off: usize) -> Option<([u8; 32], usize)> {
    if *der.get(off)? != 0x02 {
        return None;
    }
    off += 1;
    let len = *der.get(off)? as usize;
    if len == 0 || len > 0x7f {
        return None;
    }
    off += 1;
    let bytes = der.get(off..off + len)?;
    // Strip a single leading 0x00 (ASN.1 sign octet) if present.
    let trimmed = if bytes[0] == 0x00 { &bytes[1..] } else { bytes };
    if trimmed.len() > 32 {
        return None;
    }
    let mut scalar = [0u8; 32];
    scalar[32 - trimmed.len()..].copy_from_slice(trimmed);
    Some((scalar, off + len))
}

/// Decode a DER `SEQUENCE { INTEGER r, INTEGER s }` ECDSA signature into
/// P1363-form `(r, s)` 32-byte big-endian components.
fn der_ecdsa_rs(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if sig.len() < 8 || sig[0] != 0x30 {
        return None;
    }
    let seq_len = sig[1] as usize;
    if seq_len > 0x7f || 2 + seq_len != sig.len() {
        return None;
    }
    let (r, off) = der_integer_32(sig, 2)?;
    let (s, end) = der_integer_32(sig, off)?;
    if end != sig.len() {
        return None;
    }
    Some((r, s))
}

// ── KeyAuth signature ─────────────────────────────────────────────

/// Build the SAE-PK KeyAuth transcript signed by the AP (hostap
/// `sae_pk_hash_sig_data`): `eleAP || eleSTA || scaAP || scaSTA || M || K_AP ||
/// AP-BSSID || STA-MAC`. The commit elements are the 64-byte `X || Y` encodings
/// of the EC points and the scalars are 32 bytes each (SAE group 19).
#[allow(clippy::too_many_arguments)]
pub fn keyauth_sig_data(
    ele_ap: &[u8; 64],
    ele_sta: &[u8; 64],
    sca_ap: &[u8; 32],
    sca_sta: &[u8; 32],
    modifier: &[u8; SAE_PK_M_LEN],
    spki_der: &[u8],
    ap_bssid: &[u8; 6],
    sta_mac: &[u8; 6],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(64 + 64 + 32 + 32 + SAE_PK_M_LEN + spki_der.len() + 12);
    data.extend_from_slice(ele_ap);
    data.extend_from_slice(ele_sta);
    data.extend_from_slice(sca_ap);
    data.extend_from_slice(sca_sta);
    data.extend_from_slice(modifier);
    data.extend_from_slice(spki_der);
    data.extend_from_slice(ap_bssid);
    data.extend_from_slice(sta_mac);
    data
}

/// Verify an ECDSA KeyAuth `signature` (DER `SEQUENCE { r, s }`) over
/// `SHA-256(sig_data)` with the AP public key `spki_der` (DER SPKI).
pub fn verify_keyauth(spki_der: &[u8], signature: &[u8], sig_data: &[u8]) -> bool {
    let Some(point) = spki_point(spki_der) else {
        return false;
    };
    let Some((r, s)) = der_ecdsa_rs(signature) else {
        return false;
    };
    let mut hasher = Sha256::new();
    hasher.update(sig_data);
    let digest = hasher.finalize();
    verify_p256(&point, &digest, &r, &s)
}

// ── Confirm-message elements + modifier recovery ──────────────────

/// The SAE-PK material carried in the AP's SAE Confirm frame.
#[derive(Debug, Default)]
pub struct SaePkElements {
    /// DER `SubjectPublicKeyInfo` of the AP public key (FILS Public Key elem).
    pub public_key_der: Vec<u8>,
    /// DER ECDSA KeyAuth signature (FILS Key Confirmation element).
    pub key_auth: Vec<u8>,
    /// AES-SIV-encrypted Modifier (SAE-PK vendor-specific element).
    pub encrypted_modifier: Vec<u8>,
}

/// Parse the FILS Public Key, FILS Key Confirmation and SAE-PK vendor elements
/// out of an SAE Confirm information-element stream. Returns `None` when any of
/// the three is missing or malformed.
pub fn parse_elements(ies: &[u8]) -> Option<SaePkElements> {
    let mut out = SaePkElements::default();
    let mut off = 0;
    while off + 2 <= ies.len() {
        let id = ies[off];
        let len = ies[off + 1] as usize;
        let body = ies.get(off + 2..off + 2 + len)?;
        off += 2 + len;
        match id {
            WLAN_EID_EXTENSION if !body.is_empty() => match body[0] {
                // ext-id || key-type || DER public key
                WLAN_EID_EXT_FILS_PUBLIC_KEY if body.len() > 2 => {
                    out.public_key_der = body[2..].to_vec();
                }
                // ext-id || DER ECDSA signature
                WLAN_EID_EXT_FILS_KEY_CONFIRM if body.len() > 1 => {
                    out.key_auth = body[1..].to_vec();
                }
                _ => {}
            },
            // WFA-OUI vendor type || encrypted Modifier (V || ciphertext)
            WLAN_EID_VENDOR_SPECIFIC if body.len() > 4 && body[..3] == WFA_OUI => {
                out.encrypted_modifier = body[4..].to_vec();
            }
            _ => {}
        }
    }
    if out.public_key_der.is_empty() || out.key_auth.is_empty() || out.encrypted_modifier.is_empty()
    {
        return None;
    }
    Some(out)
}

/// Recover the Modifier `M` from the SAE-PK element's encrypted Modifier using
/// AES-SIV under the SAE KEK (no associated data). Returns `None` on an
/// authentication failure or wrong length.
pub fn recover_modifier(kek: &[u8; 32], encrypted_modifier: &[u8]) -> Option<[u8; SAE_PK_M_LEN]> {
    let plaintext = narf_crypto::aes_siv::decrypt(kek, &[], encrypted_modifier)?;
    plaintext.as_slice().try_into().ok()
}

/// Everything a station needs to decide whether an AP is SAE-PK-authentic.
pub struct ApVerification<'a> {
    pub ssid: &'a [u8],
    pub password: &'a str,
    pub modifier: &'a [u8; SAE_PK_M_LEN],
    pub public_key_der: &'a [u8],
    pub key_auth: &'a [u8],
    pub ele_ap: &'a [u8; 64],
    pub ele_sta: &'a [u8; 64],
    pub sca_ap: &'a [u8; 32],
    pub sca_sta: &'a [u8; 32],
    pub ap_bssid: &'a [u8; 6],
    pub sta_mac: &'a [u8; 6],
}

/// The station's SAE-PK AP-authentication decision: the password must match the
/// public-key fingerprint, and the KeyAuth signature over the exchange
/// transcript must verify with that public key.
pub fn authenticate_ap(v: &ApVerification<'_>) -> bool {
    if !validate_fingerprint(v.ssid, v.modifier, v.public_key_der, v.password) {
        return false;
    }
    let sig_data = keyauth_sig_data(
        v.ele_ap,
        v.ele_sta,
        v.sca_ap,
        v.sca_sta,
        v.modifier,
        v.public_key_der,
        v.ap_bssid,
        v.sta_mac,
    );
    verify_keyauth(v.public_key_der, v.key_auth, &sig_data)
}

/// AP-side WPA3 SAE-PK generation: password/Modifier derivation (proof-of-work
/// over the public-key fingerprint), the base-32 encoding with the Damm
/// checksum, KeyAuth signing and the SAE Confirm element assembly. Ported from
/// the Wi-Fi Alliance reference (hostap `src/common/sae_pk.c` +
/// `hostapd/sae_pk_gen.c`); the quasigroup tables are copied verbatim so
/// generated passwords validate under hostapd. Gated behind the `sae-pk-ap`
/// feature — NARF is primarily a station, so an AP build opts in.
#[cfg(feature = "sae-pk-ap")]
pub mod gen {
    use super::*;
    use alloc::string::String;
    use narf_crypto::p256::ecdsa::sign_p256;
    use narf_crypto::p256::point::{scalar_mul_base, AffinePoint};
    use narf_crypto::p256::scalar::Scalar;

    // Base-32 Damm quasigroup tables (hostap sae_pk.c, verbatim).
    #[rustfmt::skip]
    const D_MULT_TABLE: [u8; 1024] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16,
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1,
        18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17,
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18,
        4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5,
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21,
        7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6,
        23, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22,
        8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7,
        24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23,
        9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
        14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        31, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
        0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18,
        1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2,
        18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19,
        2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3,
        19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20,
        3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4,
        20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21,
        4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
        21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22,
        5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6,
        22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, 23,
        6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7,
        23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24,
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25,
        8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9,
        25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26,
        9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10,
        26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27,
        10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11,
        27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28,
        11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12,
        28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29,
        12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13,
        29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30,
        13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14,
        30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 31,
        14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15,
        31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    ];
    const D_PERM_TABLE: [u8; 32] = [
        7, 2, 1, 30, 16, 20, 27, 11, 31, 6, 8, 13, 29, 5, 10, 21, 22, 3, 24, 0, 23, 25, 12, 9, 28,
        14, 4, 15, 17, 18, 19, 26,
    ];

    fn d_permute(mut val: u8, iter: u32) -> u8 {
        for _ in 0..iter {
            val = D_PERM_TABLE[val as usize];
        }
        val
    }

    fn d_invert(val: u8) -> u8 {
        if val > 0 && val < 16 {
            16 - val
        } else {
            val
        }
    }

    /// Damm checksum character over a (possibly hyphenated) base-32 string;
    /// hyphens are skipped, as in hostap `d_check_char`.
    fn d_check_char(s: &[u8]) -> u8 {
        let mut val = 0u8;
        let mut iter = 1u32;
        for &ch in s.iter().rev() {
            let Some(c) = base32_value(ch) else {
                continue;
            };
            let p = d_permute(c, iter);
            iter += 1;
            val = D_MULT_TABLE[val as usize * 32 + p as usize];
        }
        BASE32[d_invert(val) as usize]
    }

    /// Validate a SAE-PK password's trailing Damm checksum character (the typo
    /// guard skipped by the station-side decoder).
    pub fn validate_checksum(password: &str) -> bool {
        let b = password.as_bytes();
        b.len() >= 2 && b[b.len() - 1] == d_check_char(&b[..b.len() - 1])
    }

    // Read the top 19 bits big-endian; shift a buffer left by 19 bits with
    // zero fill (hostap sae_pk_get_be19 / sae_pk_buf_shift_left_19).
    fn get_be19(buf: &[u8]) -> u32 {
        let b0 = *buf.first().unwrap_or(&0) as u32;
        let b1 = *buf.get(1).unwrap_or(&0) as u32;
        let b2 = *buf.get(2).unwrap_or(&0) as u32;
        (b0 << 11) | (b1 << 3) | (b2 >> 5)
    }
    fn shift_left_19(buf: &mut [u8]) {
        let len = buf.len();
        if len < 3 {
            buf.iter_mut().for_each(|b| *b = 0);
            return;
        }
        let mut dst = 0usize;
        let mut src = 2usize;
        while src + 1 < len {
            buf[dst] = (buf[src] << 3) | (buf[src + 1] >> 5);
            dst += 1;
            src += 1;
        }
        buf[dst] = buf[src] << 3;
        dst += 1;
        while dst < len {
            buf[dst] = 0;
            dst += 1;
        }
    }

    /// Build the "PasswordBase" bit buffer: skip the `sec` leading zero octets
    /// of the hash, then pack 20-bit groups of [Sec_1b | 19 fingerprint bits]
    /// MSB-first (hostap sae_pk_gen.c).
    fn password_base_bin(hash: &[u8], sec: usize) -> Vec<u8> {
        let sec_1b: u32 = (sec == 3) as u32;
        let ngroups = 8 * hash.len() / 20;
        let mut work = hash[sec..].to_vec();
        let mut bits: Vec<u8> = Vec::with_capacity(ngroups * 20);
        for _ in 0..ngroups {
            let val20 = (sec_1b << 19) | get_be19(&work);
            shift_left_19(&mut work);
            for b in (0..20).rev() {
                bits.push(((val20 >> b) & 1) as u8);
            }
        }
        let mut out = alloc::vec![0u8; bits.len().div_ceil(8)];
        for (i, &b) in bits.iter().enumerate() {
            if b != 0 {
                out[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        out
    }

    fn add_char(out: &mut Vec<u8>, idx: u8, left: &mut usize) {
        if *left == 0 {
            return;
        }
        *left = left.saturating_sub(5);
        if out.len() % 5 == 4 {
            out.push(b'-');
        }
        out.push(BASE32[idx as usize]);
    }

    /// Base-32 encode `len_bits` of `src` into a hyphen-grouped password with a
    /// trailing Damm checksum character (hostap sae_pk_base32_encode).
    fn base32_encode(src: &[u8], len_bits: usize) -> String {
        let len = len_bits.div_ceil(8);
        let extra_pad = (5 - len % 5) % 5;
        let mut out: Vec<u8> = Vec::new();
        let mut left = len_bits;
        let mut block: u64 = 0;
        #[allow(clippy::needless_range_loop)]
        for i in 0..(len + extra_pad) {
            let val = if i < len { src[i] as u64 } else { 0 };
            block = (block << 8) | val;
            if i % 5 == 4 {
                for j in (0..8).rev() {
                    add_char(&mut out, ((block >> (j * 5)) & 0x1f) as u8, &mut left);
                }
                block = 0;
            }
        }
        let chk = d_check_char(&out);
        out.push(chk);
        // All bytes are from BASE32 or '-', so this is valid ASCII/UTF-8.
        String::from_utf8(out).unwrap_or_default()
    }

    /// Big-endian increment of the Modifier (hostap inc_byte_array).
    fn inc_be(m: &mut [u8; SAE_PK_M_LEN]) {
        for byte in m.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// Proof-of-work search for a Modifier M such that
    /// `SHA-256(SSID || M || K_AP)` begins with `leading_zero_octets` zero
    /// bytes (Sec). Scans from the given `start` Modifier for up to `max_iters`
    /// candidates; `None` if none is found within the bound. A real Sec=3
    /// search averages 2^24 iterations, so callers pass a large bound.
    pub fn find_modifier(
        ssid: &[u8],
        spki_der: &[u8],
        leading_zero_octets: usize,
        start: [u8; SAE_PK_M_LEN],
        max_iters: u64,
    ) -> Option<[u8; SAE_PK_M_LEN]> {
        let mut m = start;
        for _ in 0..max_iters {
            let mut hasher = Sha256::new();
            hasher.update(ssid);
            hasher.update(&m);
            hasher.update(spki_der);
            let hash = hasher.finalize();
            if hash[..leading_zero_octets].iter().all(|&b| b == 0) {
                return Some(m);
            }
            inc_be(&mut m);
        }
        None
    }

    /// Generate the SAE-PK password of `groups` four-character groups
    /// (`groups >= 3`) for a Modifier already known to satisfy the Sec
    /// proof-of-work. Returns `None` for an out-of-range Sec/groups value.
    pub fn generate_password(
        ssid: &[u8],
        spki_der: &[u8],
        modifier: &[u8; SAE_PK_M_LEN],
        sec: usize,
        groups: usize,
    ) -> Option<String> {
        if (sec != 3 && sec != 5) || groups < 3 {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(ssid);
        hasher.update(modifier);
        hasher.update(spki_der);
        let hash = hasher.finalize();
        if hash[..sec].iter().any(|&b| b != 0) {
            return None; // Modifier does not satisfy the Sec proof-of-work.
        }
        let base = password_base_bin(&hash, sec);
        Some(base32_encode(&base, 20 * groups - 5))
    }

    fn der_len_byte(v: &[u8; 32]) -> (u8, bool) {
        // ASN.1 INTEGER: prepend 0x00 when the high bit is set.
        if v[0] & 0x80 != 0 {
            (33, true)
        } else {
            (32, false)
        }
    }

    fn der_encode_sig(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::with_capacity(72);
        for v in [r, s] {
            let (len, pad) = der_len_byte(v);
            body.push(0x02);
            body.push(len);
            if pad {
                body.push(0x00);
            }
            body.extend_from_slice(v);
        }
        let mut sig = alloc::vec![0x30, body.len() as u8];
        sig.extend_from_slice(&body);
        sig
    }

    /// Sign a KeyAuth transcript (from [`keyauth_sig_data`]) with the AP's
    /// ECDSA private key, returning the DER `SEQUENCE { r, s }` signature.
    pub fn sign_keyauth(private_key: &[u8; 32], sig_data: &[u8]) -> Option<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(sig_data);
        let digest = hasher.finalize();
        let (r, s) = sign_p256(private_key, &digest)?;
        Some(der_encode_sig(&r, &s))
    }

    /// Derive the DER `SubjectPublicKeyInfo` for the AP public key `d * G` from
    /// the private scalar.
    pub fn public_key_spki(private_key: &[u8; 32]) -> Option<Vec<u8>> {
        let d = Scalar::from_bytes_be(private_key).filter(|d| !d.is_zero())?;
        let q: AffinePoint = scalar_mul_base(&d);
        let encoded = q.to_encoded()?; // 64-byte X || Y
        let mut der = P256_SPKI_PREFIX.to_vec();
        der.push(0x04);
        der.extend_from_slice(&encoded);
        Some(der)
    }

    /// AES-SIV-encrypt the Modifier under the SAE KEK (no associated data) for
    /// the SAE-PK element.
    pub fn encrypt_modifier(kek: &[u8; 32], modifier: &[u8; SAE_PK_M_LEN]) -> Vec<u8> {
        narf_crypto::aes_siv::encrypt(kek, &[], modifier)
    }

    fn push_element(out: &mut Vec<u8>, id: u8, body: &[u8]) {
        out.push(id);
        out.push(body.len() as u8);
        out.extend_from_slice(body);
    }

    /// Assemble the SAE Confirm information elements carrying the SAE-PK
    /// material: FILS Public Key (ext 12, key-type ECDSA), FILS Key
    /// Confirmation (ext 3, the KeyAuth signature) and the SAE-PK
    /// vendor-specific element (WFA OUI + encrypted Modifier).
    pub fn build_confirm_elements(
        spki_der: &[u8],
        key_auth: &[u8],
        encrypted_modifier: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        // FILS Public Key: ext-id(12) || key-type(0x02 = ECDSA) || DER.
        let mut pk = alloc::vec![WLAN_EID_EXT_FILS_PUBLIC_KEY, 0x02];
        pk.extend_from_slice(spki_der);
        push_element(&mut out, WLAN_EID_EXTENSION, &pk);
        // FILS Key Confirmation: ext-id(3) || DER ECDSA signature.
        let mut kc = alloc::vec![WLAN_EID_EXT_FILS_KEY_CONFIRM];
        kc.extend_from_slice(key_auth);
        push_element(&mut out, WLAN_EID_EXTENSION, &kc);
        // SAE-PK vendor element: WFA OUI || type || encrypted Modifier.
        let mut ve = WFA_OUI.to_vec();
        ve.push(0x1f);
        ve.extend_from_slice(encrypted_modifier);
        push_element(&mut out, WLAN_EID_VENDOR_SPECIFIC, &ve);
        out
    }

    #[cfg(any(test, feature = "kernel-test"))]
    mod gen_tests {
        use super::*;
        use narf_kernel_test::{kernel_test_in, TestResult};

        // A fixed test private key (< n) for deterministic generation.
        const TEST_D: [u8; 32] = [
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1,
            0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b,
            0x12, 0x0f, 0x67, 0x21,
        ];

        // Password encode -> station decode round-trip over a synthetic hash
        // with Sec=3 leading zero octets (no proof-of-work needed): the
        // generated password's checksum validates, its Sec_1b decodes to 3,
        // and its fingerprint matches the hash.
        fn smoke_sae_pk_gen_password_roundtrip() -> TestResult {
            let mut hash = [0u8; 32];
            hash[0] = 0;
            hash[1] = 0;
            hash[2] = 0;
            for (i, b) in hash[3..].iter_mut().enumerate() {
                *b = (0x11 * (i as u32 + 1)) as u8;
            }
            let base = password_base_bin(&hash, 3);
            let pw = base32_encode(&base, 20 * 3 - 5);
            if pw.len() != 14 || !validate_checksum(&pw) {
                return TestResult::Fail("generated password malformed or bad checksum");
            }
            let (sec, fp, bits) = match password_fingerprint(&pw) {
                Some(v) => v,
                None => return TestResult::Fail("generated password failed station decode"),
            };
            if sec != 3 || !fingerprint_matches(&hash, sec, &fp, bits) {
                return TestResult::Fail("generated fingerprint did not match the hash");
            }
            // A single-character mutation breaks the checksum.
            let mut bad = pw.into_bytes();
            bad[0] = if bad[0] == b'a' { b'b' } else { b'a' };
            if validate_checksum(&String::from_utf8(bad).unwrap()) {
                return TestResult::Fail("checksum accepted a mutated password");
            }
            TestResult::Pass
        }
        kernel_test_in!("wireless/sae_pk", smoke_sae_pk_gen_password_roundtrip);

        // Proof-of-work search finds a 2-leading-zero-octet Modifier cheaply,
        // and generate_password refuses a Modifier that fails its Sec.
        fn smoke_sae_pk_gen_modifier_search() -> TestResult {
            let spki = match public_key_spki(&TEST_D) {
                Some(s) => s,
                None => return TestResult::Fail("public_key_spki failed"),
            };
            let ssid = b"narf-pk";
            let m = find_modifier(ssid, &spki, 2, [0u8; SAE_PK_M_LEN], 5_000_000);
            let m = match m {
                Some(m) => m,
                None => return TestResult::Fail("no 2-zero-octet modifier found in budget"),
            };
            let mut h = Sha256::new();
            h.update(ssid);
            h.update(&m);
            h.update(&spki);
            let hash = h.finalize();
            if hash[0] != 0 || hash[1] != 0 {
                return TestResult::Fail("found modifier does not satisfy the target");
            }
            // generate_password demands the real Sec-3 leading zeros; a 2-octet
            // modifier must be refused for Sec=3.
            if generate_password(ssid, &spki, &m, 3, 3).is_some() && hash[2] != 0 {
                return TestResult::Fail("generate_password accepted a sub-Sec modifier");
            }
            TestResult::Pass
        }
        kernel_test_in!("wireless/sae_pk", smoke_sae_pk_gen_modifier_search);

        // KeyAuth sign -> verify round trip, and the full Confirm element set
        // parses back to the same material with the Modifier recoverable.
        fn smoke_sae_pk_gen_keyauth_and_elements() -> TestResult {
            let spki = match public_key_spki(&TEST_D) {
                Some(s) => s,
                None => return TestResult::Fail("public_key_spki failed"),
            };
            let ele_ap = [0x21u8; 64];
            let ele_sta = [0x22u8; 64];
            let sca_ap = [0x23u8; 32];
            let sca_sta = [0x24u8; 32];
            let modifier = [0x5au8; SAE_PK_M_LEN];
            let ap_bssid = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
            let sta_mac = [0x02, 0x66, 0x77, 0x88, 0x99, 0xaa];
            let sig_data = keyauth_sig_data(
                &ele_ap, &ele_sta, &sca_ap, &sca_sta, &modifier, &spki, &ap_bssid, &sta_mac,
            );
            let key_auth = match sign_keyauth(&TEST_D, &sig_data) {
                Some(sig) => sig,
                None => return TestResult::Fail("sign_keyauth failed"),
            };
            if !verify_keyauth(&spki, &key_auth, &sig_data) {
                return TestResult::Fail("KeyAuth signature did not verify");
            }
            // Tampering the transcript must break verification.
            let mut bad = sig_data.clone();
            bad[0] ^= 0x01;
            if verify_keyauth(&spki, &key_auth, &bad) {
                return TestResult::Fail("KeyAuth verified a tampered transcript");
            }
            // Confirm elements assemble and parse back; AES-SIV Modifier round-trips.
            let kek = [0x33u8; 32];
            let encr = encrypt_modifier(&kek, &modifier);
            let ies = build_confirm_elements(&spki, &key_auth, &encr);
            let parsed = match parse_elements(&ies) {
                Some(p) => p,
                None => return TestResult::Fail("assembled Confirm elements did not parse"),
            };
            if parsed.public_key_der != spki
                || parsed.key_auth != key_auth
                || parsed.encrypted_modifier != encr
            {
                return TestResult::Fail("round-tripped Confirm elements differ");
            }
            match recover_modifier(&kek, &parsed.encrypted_modifier) {
                Some(m) if m == modifier => TestResult::Pass,
                _ => TestResult::Fail("Modifier not recovered from assembled element"),
            }
        }
        kernel_test_in!("wireless/sae_pk", smoke_sae_pk_gen_keyauth_and_elements);
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod pk_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // NIST P-256 ECDSA vector (Linux crypto/testmgr.h p1363_ecdsa_nist_p256),
    // reused to exercise the SPKI + DER-signature parsing against a real key.
    const PUBKEY: [u8; 65] = [
        0x04, 0xf1, 0xea, 0xc4, 0x53, 0xf3, 0xb9, 0x0e, 0x9f, 0x7e, 0xad, 0xe3, 0xea, 0xd7, 0x0e,
        0x0f, 0xd6, 0x98, 0x9a, 0xca, 0x92, 0x4d, 0x0a, 0x80, 0xdb, 0x2d, 0x45, 0xc7, 0xec, 0x4b,
        0x97, 0x00, 0x2f, 0xe9, 0x42, 0x6c, 0x29, 0xdc, 0x55, 0x0e, 0x0b, 0x53, 0x12, 0x9b, 0x2b,
        0xad, 0x2c, 0xe9, 0x80, 0xe6, 0xc5, 0x43, 0xc2, 0x1d, 0x5e, 0xbb, 0x65, 0x21, 0x50, 0xb6,
        0x37, 0xb0, 0x03, 0x8e, 0xb8,
    ];
    const R: [u8; 32] = [
        0x08, 0x31, 0xfa, 0x74, 0x0d, 0x1d, 0x21, 0x5d, 0x09, 0xdc, 0x29, 0x63, 0xa8, 0x1a, 0xad,
        0xfc, 0xac, 0x44, 0xc3, 0xe8, 0x24, 0x11, 0x2d, 0xa4, 0x91, 0xdc, 0x02, 0x67, 0xdc, 0x0c,
        0xd0, 0x82,
    ];
    const S: [u8; 32] = [
        0xbd, 0xff, 0xce, 0xee, 0x42, 0xc3, 0x97, 0xff, 0xf9, 0xa9, 0x81, 0xac, 0x4a, 0x50, 0xd0,
        0x91, 0x0a, 0x6e, 0x1b, 0xc4, 0xaf, 0xe1, 0x83, 0xc3, 0x4f, 0x2a, 0x65, 0x35, 0x23, 0xe3,
        0x1d, 0xfa,
    ];

    fn spki_of(pubkey: &[u8; 65]) -> Vec<u8> {
        let mut der = P256_SPKI_PREFIX.to_vec();
        der.extend_from_slice(pubkey);
        der
    }

    /// DER-encode P1363 (r, s) as SEQUENCE { INTEGER r, INTEGER s }, inserting
    /// the ASN.1 sign octet when the high bit is set.
    fn der_sig(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        fn int(v: &[u8; 32], out: &mut Vec<u8>) {
            out.push(0x02);
            if v[0] & 0x80 != 0 {
                out.push(33);
                out.push(0x00);
            } else {
                out.push(32);
            }
            out.extend_from_slice(v);
        }
        let mut body = Vec::new();
        int(r, &mut body);
        int(s, &mut body);
        let mut sig = alloc::vec![0x30, body.len() as u8];
        sig.extend_from_slice(&body);
        sig
    }

    fn smoke_sae_pk_password_fingerprint() -> TestResult {
        // All-'a' password: Sec_1b clear -> Sec 5, 3 groups -> 52 fingerprint
        // bits, all zero.
        match password_fingerprint("aaaa-aaaa-aaaa") {
            Some((5, fp, 52)) if fp.iter().all(|&b| b == 0) => {}
            _ => return TestResult::Fail("Sec-5 all-zero password misparsed"),
        }
        // 'q' = 16 sets the top (Sec_1b) bit -> Sec 3.
        match password_fingerprint("qaaa-aaaa-aaaa") {
            Some((3, _, _)) => {}
            _ => return TestResult::Fail("Sec-3 password not recognised"),
        }
        // Format rules: too short, bad length class, missing hyphen.
        if password_fingerprint("aaaa-aaaa").is_some()
            || password_fingerprint("aaaaa-aaaa-aaaa").is_some()
            || password_fingerprint("aaaa_aaaa-aaaa").is_some()
            || password_fingerprint("aaaa-aaaa-aaa!").is_some()
        {
            return TestResult::Fail("malformed SAE-PK password accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae_pk", smoke_sae_pk_password_fingerprint);

    fn smoke_sae_pk_fingerprint_matches() -> TestResult {
        // Hash with 3 leading zero octets then 0xAB: an 8-bit 0xAB fingerprint
        // matches, a non-zero leading octet or wrong bits do not.
        let mut hash = [0u8; 32];
        hash[3] = 0xab;
        if !fingerprint_matches(&hash, 3, &[0xab], 8) {
            return TestResult::Fail("valid fingerprint rejected");
        }
        if fingerprint_matches(&hash, 3, &[0xaa], 8) {
            return TestResult::Fail("wrong fingerprint accepted");
        }
        let mut leading = hash;
        leading[0] = 1;
        if fingerprint_matches(&leading, 3, &[0xab], 8) {
            return TestResult::Fail("non-zero leading octet accepted");
        }
        // The all-zero Sec-5 password matches an all-zero hash prefix.
        let (sec, fp, bits) = password_fingerprint("aaaa-aaaa-aaaa").unwrap();
        if !fingerprint_matches(&[0u8; 32], sec, &fp, bits) {
            return TestResult::Fail("all-zero fingerprint path failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae_pk", smoke_sae_pk_fingerprint_matches);

    fn smoke_sae_pk_der_and_keyauth() -> TestResult {
        let spki = spki_of(&PUBKEY);
        match spki_point(&spki) {
            Some(p) if p == PUBKEY => {}
            _ => return TestResult::Fail("SPKI point extraction failed"),
        }
        if spki_point(&spki[..90]).is_some() {
            return TestResult::Fail("short SPKI accepted");
        }
        let sig = der_sig(&R, &S);
        match der_ecdsa_rs(&sig) {
            Some((r, s)) if r == R && s == S => {}
            _ => return TestResult::Fail("DER ECDSA signature misparsed"),
        }
        // The extracted key + signature verify the vector digest directly.
        let digest = [
            0x8f, 0x43, 0x43, 0x46, 0x64, 0x8f, 0x6b, 0x96, 0xdf, 0x89, 0xdd, 0xa9, 0x01, 0xc5,
            0x17, 0x6b, 0x10, 0xa6, 0xd8, 0x39, 0x61, 0xdd, 0x3c, 0x1a, 0xc8, 0x8b, 0x59, 0xb2,
            0xdc, 0x32, 0x7a, 0xa4,
        ];
        if !verify_p256(&spki_point(&spki).unwrap(), &digest, &R, &S) {
            return TestResult::Fail("parsed key/signature did not verify the vector");
        }
        // verify_keyauth hashes the transcript, so an arbitrary transcript must
        // not verify against this signature.
        if verify_keyauth(&spki, &sig, b"not the signed transcript") {
            return TestResult::Fail("KeyAuth accepted an unrelated transcript");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae_pk", smoke_sae_pk_der_and_keyauth);

    fn smoke_sae_pk_sig_data_layout() -> TestResult {
        let ele_ap = [1u8; 64];
        let ele_sta = [2u8; 64];
        let sca_ap = [3u8; 32];
        let sca_sta = [4u8; 32];
        let modifier = [5u8; SAE_PK_M_LEN];
        let spki = [6u8; 10];
        let ap_bssid = [7u8; 6];
        let sta_mac = [8u8; 6];
        let data = keyauth_sig_data(
            &ele_ap, &ele_sta, &sca_ap, &sca_sta, &modifier, &spki, &ap_bssid, &sta_mac,
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(&ele_ap);
        expected.extend_from_slice(&ele_sta);
        expected.extend_from_slice(&sca_ap);
        expected.extend_from_slice(&sca_sta);
        expected.extend_from_slice(&modifier);
        expected.extend_from_slice(&spki);
        expected.extend_from_slice(&ap_bssid);
        expected.extend_from_slice(&sta_mac);
        if data != expected {
            return TestResult::Fail("KeyAuth sig-data concatenation order wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae_pk", smoke_sae_pk_sig_data_layout);

    fn smoke_sae_pk_elements_and_modifier() -> TestResult {
        let pubkey_der = [0xaau8; 8];
        let key_auth = [0xbbu8; 9];
        // Encrypt a real modifier so recover_modifier is exercised end-to-end.
        let kek = [0x11u8; 32];
        let modifier = [0x5au8; SAE_PK_M_LEN];
        let encr = narf_crypto::aes_siv::encrypt(&kek, &[], &modifier);

        // FILS Public Key element: 255, len, ext=12, key-type=2, DER.
        let mut ies = alloc::vec![
            WLAN_EID_EXTENSION,
            (2 + pubkey_der.len()) as u8,
            WLAN_EID_EXT_FILS_PUBLIC_KEY,
            0x02,
        ];
        ies.extend_from_slice(&pubkey_der);
        // FILS Key Confirmation element: 255, len, ext=3, signature.
        ies.push(WLAN_EID_EXTENSION);
        ies.push((1 + key_auth.len()) as u8);
        ies.push(WLAN_EID_EXT_FILS_KEY_CONFIRM);
        ies.extend_from_slice(&key_auth);
        // SAE-PK vendor element: 221, len, WFA-OUI, type, encrypted modifier.
        ies.push(WLAN_EID_VENDOR_SPECIFIC);
        ies.push((4 + encr.len()) as u8);
        ies.extend_from_slice(&WFA_OUI);
        ies.push(0x1f);
        ies.extend_from_slice(&encr);

        let parsed = match parse_elements(&ies) {
            Some(p) => p,
            None => return TestResult::Fail("SAE-PK elements not parsed"),
        };
        if parsed.public_key_der != pubkey_der
            || parsed.key_auth != key_auth
            || parsed.encrypted_modifier != encr
        {
            return TestResult::Fail("SAE-PK element fields extracted incorrectly");
        }
        match recover_modifier(&kek, &parsed.encrypted_modifier) {
            Some(m) if m == modifier => {}
            _ => return TestResult::Fail("Modifier recovery failed"),
        }
        if recover_modifier(&[0x22u8; 32], &parsed.encrypted_modifier).is_some() {
            return TestResult::Fail("Modifier recovered under the wrong KEK");
        }
        // A stream missing the vendor element is rejected.
        let short = &ies[..4 + pubkey_der.len() + 3 + key_auth.len()];
        if parse_elements(short).is_some() {
            return TestResult::Fail("incomplete SAE-PK element set accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae_pk", smoke_sae_pk_elements_and_modifier);
}
