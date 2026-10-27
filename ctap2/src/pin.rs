//! `authenticatorClientPIN` and PIN/UV auth protocol **one**
//! (FIDO2 CTAP2 specification §6.5).
//!
//! ## Protocol one, as the spec defines it
//!
//! - Key agreement is ECDH on P-256; the shared secret is
//!   `SHA-256(x-coordinate)` (the protocol's `kdf`).
//! - The authenticator's ephemeral public key is long-lived per
//!   power cycle: one `getKeyAgreement` result serves every
//!   subsequent clientPIN call *and* the `hmac-secret` extension
//!   inputs until the key is replaced, so this session object is
//!   shared by both flows on purpose (see [`crate::client`]).
//! - `getPINToken`: platform sends `pinHashEnc` =
//!   AES-256-CBC(shared, zero IV) of `LEFT(SHA-256(pin), 16)`;
//!   authenticator replies `pinUvAuthToken` encrypted the same
//!   way (32 bytes for protocol one).
//! - `setPIN`: `newPinEnc` = AES-CBC of the new PIN zero-padded
//!   to a 64-byte minimum (PINs are 4..=63 bytes, so the encoding
//!   is exactly 64 bytes when the PIN is shorter than 64).
//! - `changePIN`: additionally `pinHashEnc` as above and
//!   `pinUvAuthParam = HMAC-SHA-256(shared, newPinEnc)` (the
//!   *full* 32-byte MAC here — clientPIN authenticates with the
//!   shared secret, unlike makeCredential/getAssertion, which use
//!   the first 16 bytes of HMAC(token, clientDataHash)).
//!
//! CTAP2 command byte for clientPIN is 0x06; request map keys:
//! 1 pinUvAuthProtocol, 2 subCommand, 3 keyAgreement,
//! 4 pinUvAuthParam, 5 newPinEnc, 6 pinHashEnc. Response keys:
//! 1 keyAgreement, 2 pinUvAuthToken (encrypted), 3 pinRetries.

extern crate alloc;

use alloc::vec::Vec;

use crate::cbor::{self, Value};
use crate::cose;
use crate::crypto::{self, KeyPair};
use crate::ctaphid::Channel;
use crate::ctaphid::HidPipe;
use crate::{Error, RandomSource};

/// CTAP2 command byte: authenticatorClientPIN.
pub const CMD_CLIENT_PIN: u8 = 0x06;

/// Sub-command codes (CTAP2 §6.5.2).
pub const SUB_GET_PIN_RETRIES: u64 = 1;
pub const SUB_GET_KEY_AGREEMENT: u64 = 2;
pub const SUB_SET_PIN: u64 = 3;
pub const SUB_CHANGE_PIN: u64 = 4;
pub const SUB_GET_PIN_TOKEN: u64 = 5;

/// PIN length limits from the spec (bytes of UTF-8).
pub const PIN_MIN_LEN: usize = 4;
pub const PIN_MAX_LEN: usize = 63;

/// An established key-agreement session with one authenticator:
/// our ephemeral pair plus the derived shared secret. Clone-free
/// on purpose — the secret must not spray copies around the
/// client.
pub struct PinSession {
    key_agreement: KeyPair,
    shared_secret: [u8; 32],
}

impl PinSession {
    /// Establish a session: `clientPIN/getKeyAgreement`, parse
    /// the authenticator's COSE key (must be EC2/P-256/alg -25),
    /// generate our ephemeral, derive the shared secret.
    pub fn establish<P: HidPipe, R: RandomSource>(
        channel: &mut Channel<P>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let req = Value::Map(alloc::vec![
            (Value::int(1), Value::UInt(1)),
            (Value::int(2), Value::UInt(SUB_GET_KEY_AGREEMENT)),
        ]);
        let mut bytes = alloc::vec![CMD_CLIENT_PIN];
        bytes.extend_from_slice(&cbor::encode(&req));
        let resp = channel.exchange_cbor(&bytes)?;
        let map = cbor::decode(&resp)?;
        let cose_val = map
            .get_int(1)
            .ok_or(Error::Protocol("clientPIN: no keyAgreement in response"))?;
        let (peer, alg) = cose::parse_ec2_key(cose_val)?;
        if alg != cose::ALG_ECDH_ES_HKDF_256 {
            return Err(Error::Protocol(
                "clientPIN: keyAgreement alg is not ECDH-ES",
            ));
        }
        let key_agreement = KeyPair::generate(rng)?;
        let shared_secret = key_agreement.shared_secret(&peer)?;
        Ok(Self {
            key_agreement,
            shared_secret,
        })
    }

    /// Build from a caller-supplied ephemeral (fixture pinning).
    pub fn from_keypair_and_peer(key_agreement: KeyPair, peer: &[u8; 64]) -> Result<Self, Error> {
        let shared_secret = key_agreement.shared_secret(peer)?;
        Ok(Self {
            key_agreement,
            shared_secret,
        })
    }

    /// The shared secret (`SHA-256(ECDH x)`) — used by the
    /// hmac-secret extension to encrypt/decrypt salts and outputs.
    pub fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }

    /// Our key-agreement public key as a COSE_Key value (goes
    /// into clientPIN requests and hmac-secret inputs).
    pub fn key_agreement_cose(&self) -> Value {
        cose::ec2_key_value(
            &self.key_agreement.public_encoded,
            cose::ALG_ECDH_ES_HKDF_256,
        )
    }

    /// AES-256-CBC/zero-IV encrypt under the shared secret.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        crypto::aes256_cbc_encrypt(&self.shared_secret, plaintext)
    }

    /// AES-256-CBC/zero-IV decrypt under the shared secret.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        crypto::aes256_cbc_decrypt(&self.shared_secret, ciphertext)
    }

    fn base_request(&self, sub_command: u64) -> Vec<(Value, Value)> {
        alloc::vec![
            (Value::int(1), Value::UInt(1)),
            (Value::int(2), Value::UInt(sub_command)),
            (Value::int(3), self.key_agreement_cose()),
        ]
    }

    fn send<P: HidPipe>(
        &self,
        channel: &mut Channel<P>,
        params: Vec<(Value, Value)>,
    ) -> Result<Value, Error> {
        let mut bytes = alloc::vec![CMD_CLIENT_PIN];
        bytes.extend_from_slice(&cbor::encode(&Value::Map(params)));
        let resp = channel.exchange_cbor(&bytes)?;
        if resp.is_empty() {
            return Ok(Value::Map(alloc::vec![]));
        }
        Ok(cbor::decode(&resp)?)
    }

    /// `getPINToken`: exchange the PIN for a pinUvAuthToken.
    /// A wrong PIN surfaces as [`Error::Ctap`]
    /// `CTAP2_ERR_PIN_INVALID` (0x31) from the authenticator.
    pub fn get_pin_token<P: HidPipe>(
        &self,
        channel: &mut Channel<P>,
        pin: &[u8],
    ) -> Result<[u8; 32], Error> {
        check_pin_len(pin)?;
        let pin_hash = crypto::sha256(pin);
        let pin_hash_enc = self.encrypt(&pin_hash[..16])?;
        let mut params = self.base_request(SUB_GET_PIN_TOKEN);
        params.push((Value::int(6), Value::Bytes(pin_hash_enc)));
        let resp = self.send(channel, params)?;
        let enc = resp
            .get_int_key_bytes(2)
            .ok_or(Error::Protocol("clientPIN: no pinUvAuthToken"))?;
        let token = self.decrypt(enc)?;
        if token.len() != 32 {
            return Err(Error::Protocol("clientPIN: pinUvAuthToken length"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&token);
        Ok(out)
    }

    /// `setPIN`: set the PIN on a token that has none. No
    /// pinUvAuthParam — the shared-secret encryption is the only
    /// protection, per spec.
    pub fn set_pin<P: HidPipe>(
        &self,
        channel: &mut Channel<P>,
        new_pin: &[u8],
    ) -> Result<(), Error> {
        check_pin_len(new_pin)?;
        let new_pin_enc = self.encrypt(&pad_pin(new_pin))?;
        let mut params = self.base_request(SUB_SET_PIN);
        params.push((Value::int(5), Value::Bytes(new_pin_enc)));
        self.send(channel, params)?;
        Ok(())
    }

    /// `changePIN`: replace the PIN, proving knowledge of the
    /// current one. `pinUvAuthParam` here is the full
    /// HMAC-SHA-256(sharedSecret, newPinEnc).
    pub fn change_pin<P: HidPipe>(
        &self,
        channel: &mut Channel<P>,
        current_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<(), Error> {
        check_pin_len(current_pin)?;
        check_pin_len(new_pin)?;
        let new_pin_enc = self.encrypt(&pad_pin(new_pin))?;
        let pin_hash = crypto::sha256(current_pin);
        let pin_hash_enc = self.encrypt(&pin_hash[..16])?;
        let auth_param = crypto::hmac_sha256(&self.shared_secret, &new_pin_enc);
        let mut params = self.base_request(SUB_CHANGE_PIN);
        params.push((Value::int(4), Value::Bytes(auth_param.to_vec())));
        params.push((Value::int(5), Value::Bytes(new_pin_enc)));
        params.push((Value::int(6), Value::Bytes(pin_hash_enc)));
        self.send(channel, params)?;
        Ok(())
    }
}

/// `getPINRetries` — needs no key agreement, so it stands alone.
/// Returns the remaining PIN retries before the token blocks.
pub fn get_pin_retries<P: HidPipe>(channel: &mut Channel<P>) -> Result<u64, Error> {
    let req = Value::Map(alloc::vec![
        (Value::int(1), Value::UInt(1)),
        (Value::int(2), Value::UInt(SUB_GET_PIN_RETRIES)),
    ]);
    let mut bytes = alloc::vec![CMD_CLIENT_PIN];
    bytes.extend_from_slice(&cbor::encode(&req));
    let resp = channel.exchange_cbor(&bytes)?;
    let map = cbor::decode(&resp)?;
    map.get_int(3)
        .and_then(|v| v.as_uint())
        .ok_or(Error::Protocol("clientPIN: no pinRetries in response"))
}

/// The pinUvAuthParam for makeCredential/getAssertion under
/// protocol one: first 16 bytes of HMAC-SHA-256(pinUvAuthToken,
/// clientDataHash).
pub fn pin_uv_auth_param(pin_uv_auth_token: &[u8], client_data_hash: &[u8; 32]) -> [u8; 16] {
    let mac = crypto::hmac_sha256(pin_uv_auth_token, client_data_hash);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

fn check_pin_len(pin: &[u8]) -> Result<(), Error> {
    if pin.len() < PIN_MIN_LEN || pin.len() > PIN_MAX_LEN {
        return Err(Error::Protocol("pin: length outside 4..=63"));
    }
    Ok(())
}

/// PIN encoding for setPIN/changePIN: the PIN bytes followed by
/// zero bytes to at least 64 bytes total.
fn pad_pin(pin: &[u8]) -> Vec<u8> {
    let mut out = pin.to_vec();
    while out.len() < 64 {
        out.push(0);
    }
    out
}
