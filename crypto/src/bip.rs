//! The BIP management-frame integrity variants implemented by mac80211.
//!
//! IEEE 802.11 makes AES-CMAC-128 mandatory, but ath11k advertises the
//! complete CMAC-128/CMAC-256/GMAC-128/GMAC-256 set.  The firmware leaves
//! these keys to the host, so this module owns the common MMIE layout,
//! replay-number encoding, and their CMAC / GMAC constructions.
//!
//! References: IEEE 802.11-2020 §12.5.4 and NIST SP 800-38B/-38D.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, Key as GcmKey, Nonce,
};

use crate::{bip_cmac, cmac_aes128, cmac_aes256};

/// The host-protected BIP suite selected by an IGTK.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cipher {
    Cmac128,
    Cmac256,
    Gmac128,
    Gmac256,
}

impl Cipher {
    /// Required IGTK size for this BIP construction.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Cmac128 | Self::Gmac128 => 16,
            Self::Cmac256 | Self::Gmac256 => 32,
        }
    }

    /// MMIE MIC size.  CMAC-128 truncates the full CMAC to 64 bits; all
    /// other BIP suites retain 128 bits.
    pub const fn mic_len(self) -> usize {
        match self {
            Self::Cmac128 => 8,
            Self::Cmac256 | Self::Gmac128 | Self::Gmac256 => 16,
        }
    }

    /// Complete MMIE size including Element ID and Length.
    pub const fn mmie_len(self) -> usize {
        2 + 2 + bip_cmac::BIP_IPN_LEN + self.mic_len()
    }
}

/// A decoded Management MIC Element.  `mic` is left-aligned and only the
/// first `mic_len` octets are meaningful.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mmie {
    pub key_id: u16,
    pub ipn: u64,
    pub mic: [u8; 16],
    pub mic_len: usize,
}

/// Failure returned by BIP encode/verify helpers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    BadKey,
    BadKeyId,
    BadFrame,
    BadMmie,
    MicFailed,
    CryptoFailed,
    IpnExhausted,
}

fn valid_key(cipher: Cipher, key: &[u8]) -> bool {
    key.len() == cipher.key_len()
}

fn valid_key_id(key_id: u16) -> bool {
    (bip_cmac::IGTK_KEY_INDEX_MIN..=bip_cmac::IGTK_KEY_INDEX_MAX).contains(&key_id)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&a, &b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn gmac_nonce(aad: &[u8; 20], ipn: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    // A2 || IPN in big-endian order (§12.5.4.3).  `build_bip_aad` places
    // A2 at bytes 8..14 and wire IPNs are little-endian.
    nonce[..6].copy_from_slice(&aad[8..14]);
    nonce[6..].copy_from_slice(&ipn.to_be_bytes()[2..]);
    nonce
}

fn compute_mic(
    cipher: Cipher,
    key: &[u8],
    aad: &[u8; 20],
    ipn: u64,
    body: &[u8],
) -> Result<[u8; 16], Error> {
    if !valid_key(cipher, key) {
        return Err(Error::BadKey);
    }
    let mut out = [0u8; 16];
    match cipher {
        Cipher::Cmac128 => {
            let key: [u8; 16] = key.try_into().map_err(|_| Error::BadKey)?;
            let input = bip_cmac::authenticated_bytes(aad, body);
            out[..8].copy_from_slice(&cmac_aes128::cmac_aes128(&key, &input)[..8]);
        }
        Cipher::Cmac256 => {
            let key: [u8; 32] = key.try_into().map_err(|_| Error::BadKey)?;
            let input = bip_cmac::authenticated_bytes(aad, body);
            out.copy_from_slice(&cmac_aes256::cmac_aes256(&key, &input));
        }
        Cipher::Gmac128 => {
            let key: [u8; 16] = key.try_into().map_err(|_| Error::BadKey)?;
            let cipher = Aes128Gcm::new(GcmKey::<Aes128Gcm>::from_slice(&key));
            let nonce = gmac_nonce(aad, ipn);
            let mut empty = Vec::new();
            let tag = cipher
                .encrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    &bip_cmac::authenticated_bytes(aad, body),
                    &mut empty,
                )
                .map_err(|_| Error::CryptoFailed)?;
            out.copy_from_slice(tag.as_slice());
        }
        Cipher::Gmac256 => {
            let key: [u8; 32] = key.try_into().map_err(|_| Error::BadKey)?;
            let cipher = Aes256Gcm::new(GcmKey::<Aes256Gcm>::from_slice(&key));
            let nonce = gmac_nonce(aad, ipn);
            let mut empty = Vec::new();
            let tag = cipher
                .encrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    &bip_cmac::authenticated_bytes(aad, body),
                    &mut empty,
                )
                .map_err(|_| Error::CryptoFailed)?;
            out.copy_from_slice(tag.as_slice());
        }
    }
    Ok(out)
}

/// Decode the trailing MMIE in a management-frame body.  Both 18-byte and
/// 26-byte MMIEs are accepted; key-suite matching is performed by
/// [`verify_mmie`].
pub fn parse_mmie(body: &[u8]) -> Result<Mmie, Error> {
    // Prefer the longer form: its trailing 18 octets can otherwise happen to
    // resemble a short MMIE if attacker-controlled key/IPN bytes align so.
    for (total_len, mic_len) in [(26usize, 16usize), (18, 8)] {
        if body.len() < total_len {
            continue;
        }
        let start = body.len() - total_len;
        let mmie = &body[start..];
        if mmie[0] != bip_cmac::ELEMENT_ID_MMIE || mmie[1] as usize != total_len - 2 {
            continue;
        }
        let mut mic = [0u8; 16];
        mic[..mic_len].copy_from_slice(&mmie[10..10 + mic_len]);
        return Ok(Mmie {
            key_id: u16::from_le_bytes([mmie[2], mmie[3]]),
            ipn: bip_cmac::decode_ipn(&mmie[4..10]),
            mic,
            mic_len,
        });
    }
    Err(Error::BadMmie)
}

/// Append and authenticate an MMIE, advancing the caller-owned transmit IPN.
/// `body` is the management payload only; `hdr` is its 24-byte 802.11 header.
pub fn protect_mmie(
    cipher: Cipher,
    key: &[u8],
    key_id: u16,
    tx_ipn: &mut u64,
    hdr: &[u8],
    body: &mut Vec<u8>,
) -> Result<u64, Error> {
    if hdr.len() < 24 || !valid_key(cipher, key) {
        return Err(if hdr.len() < 24 {
            Error::BadFrame
        } else {
            Error::BadKey
        });
    }
    if !valid_key_id(key_id) {
        return Err(Error::BadKeyId);
    }
    // IPN is a 48-bit counter on the wire.  Reuse after exhaustion would
    // undermine replay protection, so the caller must rekey instead.
    if *tx_ipn >= (1u64 << 48) - 1 {
        return Err(Error::IpnExhausted);
    }
    *tx_ipn += 1;
    let ipn = *tx_ipn;
    let mic_len = cipher.mic_len();
    body.push(bip_cmac::ELEMENT_ID_MMIE);
    body.push((8 + mic_len) as u8);
    body.extend_from_slice(&key_id.to_le_bytes());
    body.extend_from_slice(&bip_cmac::encode_ipn(ipn));
    body.extend(core::iter::repeat_n(0u8, mic_len));
    let aad = bip_cmac::build_bip_aad(hdr).map_err(|_| Error::BadFrame)?;
    let mic = compute_mic(cipher, key, &aad, ipn, body)?;
    let end = body.len();
    body[end - mic_len..].copy_from_slice(&mic[..mic_len]);
    Ok(ipn)
}

/// Authenticate the trailing MMIE against `cipher` and `key`.  This does not
/// update a replay window; callers must compare and commit `Mmie::ipn` only
/// after this operation succeeds.
pub fn verify_mmie(cipher: Cipher, key: &[u8], hdr: &[u8], body: &[u8]) -> Result<Mmie, Error> {
    if hdr.len() < 24 || !valid_key(cipher, key) {
        return Err(if hdr.len() < 24 {
            Error::BadFrame
        } else {
            Error::BadKey
        });
    }
    let mmie = parse_mmie(body)?;
    if !valid_key_id(mmie.key_id) {
        return Err(Error::BadKeyId);
    }
    if mmie.mic_len != cipher.mic_len() {
        return Err(Error::BadMmie);
    }
    let mut authenticated = body.to_vec();
    let end = authenticated.len();
    authenticated[end - mmie.mic_len..].fill(0);
    let aad = bip_cmac::build_bip_aad(hdr).map_err(|_| Error::BadFrame)?;
    let expected = compute_mic(cipher, key, &aad, mmie.ipn, &authenticated)?;
    if !constant_time_eq(&expected[..mmie.mic_len], &mmie.mic[..mmie.mic_len]) {
        return Err(Error::MicFailed);
    }
    Ok(mmie)
}

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn round_trip(cipher: Cipher, key: &[u8]) -> bool {
        let mut hdr = [0u8; 24];
        hdr[0] = 0xd0; // Action management frame.
        hdr[4..10].copy_from_slice(&[0xff; 6]);
        hdr[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        hdr[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        let mut body = alloc::vec![8, 0, 0x12, 0x34];
        if protect_mmie(cipher, key, 4, &mut 7, &hdr, &mut body) != Ok(8) {
            return false;
        }
        let Ok(mmie) = verify_mmie(cipher, key, &hdr, &body) else {
            return false;
        };
        if mmie.key_id != 4 || mmie.ipn != 8 || mmie.mic_len != cipher.mic_len() {
            return false;
        }
        body[3] ^= 1;
        matches!(verify_mmie(cipher, key, &hdr, &body), Err(Error::MicFailed))
    }

    fn smoke_bip_all_advertised_suites_round_trip() -> TestResult {
        let key128 = [0x42; 16];
        let key256 = [0x24; 32];
        if !round_trip(Cipher::Cmac128, &key128)
            || !round_trip(Cipher::Cmac256, &key256)
            || !round_trip(Cipher::Gmac128, &key128)
            || !round_trip(Cipher::Gmac256, &key256)
        {
            return TestResult::Fail("BIP suite round-trip or MIC rejection failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/bip", smoke_bip_all_advertised_suites_round_trip);

    fn smoke_bip_beacon_timestamp_is_not_authenticated() -> TestResult {
        let mut hdr = [0u8; 24];
        hdr[0] = 0x80; // Beacon.
        hdr[4..10].copy_from_slice(&[0xff; 6]);
        hdr[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        hdr[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        let mut first = alloc::vec![0; 12];
        let mut second = first.clone();
        second[..8].copy_from_slice(&0xfeed_face_cafe_beefu64.to_le_bytes());
        let key = [0x53; 16];
        if protect_mmie(Cipher::Cmac128, &key, 4, &mut 0, &hdr, &mut first).is_err() {
            return TestResult::Fail("first beacon protect failed");
        }
        if protect_mmie(Cipher::Cmac128, &key, 4, &mut 0, &hdr, &mut second).is_err() {
            return TestResult::Fail("second beacon protect failed");
        }
        if first[first.len() - 8..] != second[second.len() - 8..] {
            return TestResult::Fail("Beacon timestamp changed BIP-CMAC");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "crypto/bip",
        smoke_bip_beacon_timestamp_is_not_authenticated
    );

    fn smoke_bip_refuses_bad_key_id_and_ipn_wrap() -> TestResult {
        let hdr = [0u8; 24];
        let key = [0x77; 16];
        let mut body = alloc::vec![];
        if protect_mmie(Cipher::Cmac128, &key, 3, &mut 0, &hdr, &mut body) != Err(Error::BadKeyId) {
            return TestResult::Fail("BIP accepted non-IGTK key index");
        }
        let mut body = alloc::vec![];
        let mut ipn = (1u64 << 48) - 1;
        if protect_mmie(Cipher::Cmac128, &key, 4, &mut ipn, &hdr, &mut body)
            != Err(Error::IpnExhausted)
        {
            return TestResult::Fail("BIP reused an exhausted IPN");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/bip", smoke_bip_refuses_bad_key_id_and_ipn_wrap);
}
