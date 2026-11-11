//! Every BIP suite (IEEE 802.11-2020 12.5.4): BIP-CMAC-128 (8-octet MIC),
//! BIP-CMAC-256, BIP-GMAC-128 and BIP-GMAC-256 (16-octet MIC). The AAD and
//! the authenticated body are the CMAC-128 ones (`build_bip_aad`,
//! `authenticated_bytes`); BIP-GMAC's nonce is A2 || IPN (big endian).
//! mac80211 `ieee80211_crypto_aes_{cmac,cmac_256,gmac}_{encrypt,decrypt}`.
use super::MfpError;
use crate::rsn;
use alloc::vec::Vec;
use narf_crypto::bip_cmac::{authenticated_bytes, build_bip_aad, decode_ipn, encode_ipn};
use zeroize::Zeroizing;

const MMIE: u8 = 76;

/// One IGTK and its replay state.
pub struct BipKey {
    cipher: u8,
    key: Zeroizing<Vec<u8>>,
    pub key_id: u16,
    /// The last accepted IPN.
    pub rx_ipn: u64,
    /// The last IPN this key protected a frame with.
    pub tx_ipn: u64,
}
impl core::fmt::Debug for BipKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BipKey")
            .field("cipher", &self.cipher)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}
impl BipKey {
    /// `cipher` is a standard BIP suite type; the key length must be its
    /// own and the key ID 4 or 5 (IGTK) or 6 or 7 (BIGTK).
    pub fn new(cipher: u8, key: &[u8], key_id: u16, rx_ipn: u64) -> Result<Self, MfpError> {
        if rsn::mgmt_cipher_key_len(cipher) != Some(key.len()) {
            return Err(MfpError::NoMmie);
        }
        if !(4..=7).contains(&key_id) {
            return Err(MfpError::BadKeyIndex);
        }
        Ok(Self {
            cipher,
            key: Zeroizing::new(key.to_vec()),
            key_id,
            rx_ipn,
            tx_ipn: 0,
        })
    }
    pub fn cipher(&self) -> u8 {
        self.cipher
    }
    /// The MIC length: 8 for BIP-CMAC-128, else 16.
    pub fn mic_len(&self) -> usize {
        if self.cipher == rsn::CIPHER_BIP_CMAC_128 {
            8
        } else {
            16
        }
    }
    /// The MIC over `hdr_24` and `body`, whose MMIE MIC field is zero.
    fn mic(&self, hdr_24: &[u8], body: &[u8], ipn: u64) -> Result<Vec<u8>, MfpError> {
        let aad = build_bip_aad(hdr_24).map_err(MfpError::from)?;
        let data = Zeroizing::new(authenticated_bytes(&aad, body));
        Ok(match self.cipher {
            rsn::CIPHER_BIP_CMAC_128 => {
                let key: &[u8; 16] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| MfpError::NoMmie)?;
                narf_crypto::cmac_aes128::cmac_aes128(key, &data[..])[..8].to_vec()
            }
            rsn::CIPHER_BIP_CMAC_256 => {
                let key: &[u8; 32] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| MfpError::NoMmie)?;
                narf_crypto::cmac_aes256::cmac_aes256(key, &data[..]).to_vec()
            }
            _ => {
                // The AAD is the leading 20 octets of `data`; GMAC
                // authenticates AAD || body as one string.
                let mut nonce = [0; narf_crypto::gcm::NONCE_LEN];
                nonce[..6].copy_from_slice(&hdr_24[10..16]);
                let mut ipn_be = encode_ipn(ipn);
                ipn_be.reverse();
                nonce[6..].copy_from_slice(&ipn_be);
                narf_crypto::gcm::gmac(&self.key, &nonce, &data[..])
                    .map_err(|_| MfpError::NoMmie)?
                    .to_vec()
            }
        })
    }
}

/// The active IGTK and the one it replaced.
#[derive(Debug, Default)]
pub struct BipKeyStore {
    pub active: Option<BipKey>,
    pub next: Option<BipKey>,
}
impl BipKeyStore {
    pub const fn new() -> Self {
        Self {
            active: None,
            next: None,
        }
    }
    /// Install `key` as active; a different active key moves to `next`.
    pub fn install_active(&mut self, key: BipKey) {
        if let Some(previous) = self.active.take() {
            if previous.key_id != key.key_id {
                self.next = Some(previous);
            }
        }
        self.active = Some(key);
    }
    fn find_mut(&mut self, key_id: u16) -> Option<&mut BipKey> {
        [self.active.as_mut(), self.next.as_mut()]
            .into_iter()
            .flatten()
            .find(|key| key.key_id == key_id)
    }
}

/// Append an MMIE protecting `body` under `key` (the next IPN).
pub fn bip_protect(key: &mut BipKey, hdr_24: &[u8], body: &mut Vec<u8>) -> Result<u64, MfpError> {
    if hdr_24.len() < 24 {
        return Err(MfpError::Truncated);
    }
    let ipn = key
        .tx_ipn
        .checked_add(1)
        .filter(|ipn| *ipn < 1 << 48)
        .ok_or(MfpError::Replay)?;
    let mic_len = key.mic_len();
    let start = body.len();
    body.extend_from_slice(&[MMIE, (8 + mic_len) as u8]);
    body.extend_from_slice(&key.key_id.to_le_bytes());
    body.extend_from_slice(&encode_ipn(ipn));
    body.extend(core::iter::repeat_n(0, mic_len));
    let mic = key.mic(hdr_24, body, ipn)?;
    body[start + 10..].copy_from_slice(&mic);
    key.tx_ipn = ipn;
    Ok(ipn)
}

/// Verify the trailing MMIE of `body` under the stored key it names and
/// commit its IPN; returns the body without the MMIE.
pub fn bip_verify<'a>(
    store: &mut BipKeyStore,
    hdr_24: &[u8],
    body: &'a [u8],
) -> Result<&'a [u8], MfpError> {
    if hdr_24.len() < 24 {
        return Err(MfpError::Truncated);
    }
    let cipher = store.active.as_ref().ok_or(MfpError::NoMmie)?.cipher;
    let mic_len = if cipher == rsn::CIPHER_BIP_CMAC_128 {
        8
    } else {
        16
    };
    let total = 2 + 8 + mic_len;
    let split = body.len().checked_sub(total).ok_or(MfpError::Truncated)?;
    let mmie = &body[split..];
    if mmie[0] != MMIE || usize::from(mmie[1]) != 8 + mic_len {
        return Err(MfpError::NoMmie);
    }
    let key_id = u16::from_le_bytes([mmie[2], mmie[3]]);
    let ipn = decode_ipn(&mmie[4..10]);
    let mut probe = body[..split + 10].to_vec();
    probe.extend(core::iter::repeat_n(0, mic_len));
    let key = store.find_mut(key_id).ok_or(MfpError::NoMmie)?;
    if key.mic_len() != mic_len {
        return Err(MfpError::NoMmie);
    }
    let expected = key.mic(hdr_24, &probe, ipn)?;
    // Constant-time comparison: every octet is examined.
    let difference = expected
        .iter()
        .zip(&mmie[10..])
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if core::hint::black_box(difference) != 0 {
        return Err(MfpError::MicFailed);
    }
    if ipn <= key.rx_ipn {
        return Err(MfpError::Replay);
    }
    key.rx_ipn = ipn;
    Ok(&body[..split])
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mfp_bip_tests.rs"]
mod tests;
