//! The CTAP2 client: `authenticatorGetInfo`,
//! `authenticatorMakeCredential`, `authenticatorGetAssertion`
//! (with the `hmac-secret` extension), `authenticatorGetNextAssertion`.
//!
//! Command bytes and parameter/response map keys are FIDO2 CTAP2
//! §6.1–§6.4. Parameter maps use integer keys; response maps are
//! decoded with the strict CBOR reader and every field the
//! suspend flows rely on is extracted by key — a missing or
//! mistyped field is a [`Error::Protocol`], never a default.
//!
//! PIN handling, per the decided touch+PIN default: when the
//! caller supplies a PIN, the client establishes one key-agreement
//! session (PIN protocol one), obtains a pinUvAuthToken, and
//! presents `pinUvAuthParam = LEFT(HMAC(token, clientDataHash),
//! 16)` with `pinUvAuthProtocol = 1`. The same session encrypts
//! hmac-secret salts — the authenticator keeps one ephemeral key
//! per power cycle, so a second `getKeyAgreement` between the
//! token fetch and the extension would invalidate the first.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::cbor::{self, Value};
use crate::cose;
use crate::crypto;
use crate::ctaphid::{Channel, HidPipe};
use crate::pin::{pin_uv_auth_param, PinSession};
use crate::{Error, RandomSource};

/// CTAP2 command bytes (spec §6).
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;

/// Authenticator data flags (spec §6.1/6.2 authData layout).
pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

/// `authenticatorGetInfo` output (response keys 0x01..0x15; the
/// fields the suspend flows branch on are extracted, the raw map
/// is retained for fields like firmwareVersion/algorithm lists
/// that callers may want later).
#[derive(Clone, Debug)]
pub struct AuthenticatorInfo {
    /// 0x01 versions, e.g. ["FIDO_2_0", "FIDO_2_1"].
    pub versions: Vec<String>,
    /// 0x02 supported extension identifiers.
    pub extensions: Vec<String>,
    /// 0x03 AAGUID.
    pub aaguid: [u8; 16],
    /// 0x04 options map (text key → bool): "rk", "up", "uv",
    /// "clientPin", "plat", …
    pub options: Vec<(String, bool)>,
    /// 0x05 max message size, when advertised.
    pub max_msg_size: Option<u64>,
    /// 0x06 supported PIN/UV auth protocol versions.
    pub pin_protocols: Vec<u64>,
    /// The untouched response map.
    pub raw: Value,
}

impl AuthenticatorInfo {
    pub fn option(&self, name: &str) -> Option<bool> {
        self.options
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
    }

    pub fn supports_extension(&self, name: &str) -> bool {
        self.extensions.iter().any(|e| e == name)
    }

    /// The token has a usable PIN story: option "clientPin" is
    /// present (true = PIN set, false = supported but unset);
    /// absent means the authenticator has no clientPIN at all.
    pub fn client_pin_state(&self) -> Option<bool> {
        self.option("clientPin")
    }
}

/// A parsed authenticator-data blob (makeCredential and
/// getAssertion share the prefix layout).
#[derive(Clone, Debug)]
pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    /// Present when the AT flag is set (makeCredential).
    pub attested: Option<AttestedCredential>,
    /// Extension outputs decoded when the ED flag is set.
    pub extensions: Option<Value>,
    pub raw: Vec<u8>,
}

impl AuthData {
    pub fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }
    pub fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 37 {
            return Err(Error::Protocol("authData: shorter than 37-byte prefix"));
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&bytes[..32]);
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
        let mut rest = &bytes[37..];
        let mut attested = None;
        if flags & FLAG_AT != 0 {
            // aaguid(16) | credIdLen(2, BE) | credId | COSE key (CBOR).
            if rest.len() < 18 {
                return Err(Error::Protocol("authData: attested data truncated"));
            }
            let mut aaguid = [0u8; 16];
            aaguid.copy_from_slice(&rest[..16]);
            let cred_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
            rest = &rest[18..];
            if rest.len() < cred_len {
                return Err(Error::Protocol("authData: credential id truncated"));
            }
            let credential_id = rest[..cred_len].to_vec();
            rest = &rest[cred_len..];
            let (cose_val, used) = cbor::decode_prefix(rest)?;
            rest = &rest[used..];
            let (public_key, alg) = cose::parse_ec2_key(&cose_val)?;
            if alg != cose::ALG_ES256 {
                return Err(Error::Protocol("authData: credential key alg is not ES256"));
            }
            attested = Some(AttestedCredential {
                aaguid,
                credential_id,
                public_key,
            });
        }
        let extensions = if flags & FLAG_ED != 0 {
            if rest.is_empty() {
                return Err(Error::Protocol("authData: ED set but no extension CBOR"));
            }
            let (val, _used) = cbor::decode_prefix(rest)?;
            Some(val)
        } else {
            None
        };
        Ok(Self {
            rp_id_hash,
            flags,
            sign_count,
            attested,
            extensions,
            raw: bytes.to_vec(),
        })
    }
}

/// The attested credential data inside a makeCredential authData.
#[derive(Clone, Debug)]
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    /// Credential public key, X || Y.
    pub public_key: [u8; 64],
}

/// A reference to a credential (allow/exclude lists, responses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRef {
    pub id: Vec<u8>,
    /// Transports (response hint only; never sent by this client).
    pub transports: Vec<String>,
}

impl CredentialRef {
    pub fn new(id: Vec<u8>) -> Self {
        Self {
            id,
            transports: Vec::new(),
        }
    }

    fn to_value(&self) -> Value {
        Value::Map(alloc::vec![
            (Value::Text("id".into()), Value::Bytes(self.id.clone())),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let id = v
            .get_text_key_bytes("id")
            .ok_or(Error::Protocol("credential descriptor: no id"))?
            .to_vec();
        let mut transports = Vec::new();
        if let Some(Value::Array(list)) = v.get_text("transports") {
            for t in list {
                if let Value::Text(s) = t {
                    transports.push(s.clone());
                }
            }
        }
        Ok(Self { id, transports })
    }
}

/// User-verification requirement for one call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserVerification {
    /// Do not request UV (touch-only credential or call).
    Discouraged,
    /// Request UV when the credential/token supports it — the
    /// client drives the PIN flow only when a PIN is supplied.
    Preferred,
    /// UV is mandatory: the client refuses to proceed without a
    /// PIN to drive it on a clientPin-capable token.
    Required,
}

/// Inputs for `make_credential`. `client_data_hash` is the
/// caller's — the suspend service defines its content (the client
/// never invents what an assertion is *about*).
pub struct MakeCredentialParams<'a> {
    pub client_data_hash: [u8; 32],
    pub rp_id: &'a str,
    pub rp_name: Option<&'a str>,
    pub user_id: &'a [u8],
    pub user_name: Option<&'a str>,
    pub user_display_name: Option<&'a str>,
    pub exclude: &'a [CredentialRef],
    pub resident_key: bool,
    pub user_verification: UserVerification,
    /// PIN for the token, when using the PIN flow. `None` =
    /// touch-only enrollment (only honored when the caller asked
    /// for [`UserVerification::Discouraged`]).
    pub pin: Option<&'a [u8]>,
}

/// Result of `make_credential`.
#[derive(Clone, Debug)]
pub struct MakeCredentialResult {
    /// Attestation format identifier (e.g. "packed", "none").
    pub fmt: String,
    pub auth_data: AuthData,
    /// The attestation statement map, untouched. Attestation
    /// *verification* is out of scope for this client (the token
    /// is physically present and enrolled by the owner); the raw
    /// statement is carried so a caller can pin it if desired.
    pub attestation_statement: Value,
}

/// Inputs for one hmac-secret derivation inside `get_assertion`.
pub struct HmacSecretParams {
    pub salt1: [u8; 32],
    pub salt2: Option<[u8; 32]>,
}

/// hmac-secret extension output: 32 bytes for one salt, 64 (two
/// independent outputs) when salt2 was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HmacSecretOutput {
    pub first: [u8; 32],
    pub second: Option<[u8; 32]>,
}

/// Inputs for `get_assertion`.
pub struct GetAssertionParams<'a> {
    pub rp_id: &'a str,
    pub client_data_hash: [u8; 32],
    /// Empty = discoverable-credential lookup (first matching
    /// credential wins; more arrive via getNextAssertion).
    pub allow: &'a [CredentialRef],
    pub user_verification: UserVerification,
    pub hmac_secret: Option<HmacSecretParams>,
    pub pin: Option<&'a [u8]>,
}

/// One assertion (also the shape of getNextAssertion results).
#[derive(Clone, Debug)]
pub struct Assertion {
    pub credential: Option<CredentialRef>,
    pub auth_data: AuthData,
    pub signature: Vec<u8>,
    pub user_id: Option<Vec<u8>>,
    pub user_name: Option<String>,
    /// Total credentials for the RP when the authenticator
    /// reported it (first assertion only).
    pub number_of_credentials: Option<u64>,
    pub hmac_secret: Option<HmacSecretOutput>,
}

/// The CTAP2 client over one CTAPHID channel.
pub struct Client<P: HidPipe, R: RandomSource> {
    channel: Channel<P>,
    rng: R,
    info: Option<AuthenticatorInfo>,
}

impl<P: HidPipe, R: RandomSource> Client<P, R> {
    /// Connect: CTAPHID INIT, capability check, then getInfo.
    pub fn connect(pipe: P, mut rng: R) -> Result<Self, Error> {
        let (channel, init) = Channel::init(pipe, &mut rng)?;
        if init.protocol_version != 2 {
            return Err(Error::Unsupported("ctaphid protocol version is not 2"));
        }
        if init.capabilities & crate::ctaphid::CAP_CBOR == 0 {
            return Err(Error::Unsupported(
                "authenticator does not offer CTAPHID_CBOR",
            ));
        }
        let mut client = Self {
            channel,
            rng,
            info: None,
        };
        client.get_info()?;
        Ok(client)
    }

    /// Build over an already-initialized channel (tests/fixtures).
    pub fn from_channel(channel: Channel<P>, rng: R) -> Self {
        Self {
            channel,
            rng,
            info: None,
        }
    }

    pub fn channel(&mut self) -> &mut Channel<P> {
        &mut self.channel
    }

    pub fn rng_mut(&mut self) -> &mut R {
        &mut self.rng
    }

    /// `authenticatorGetInfo` (cached after the first fetch;
    /// PIN-state changes are picked up by [`Client::refresh_info`]).
    pub fn get_info(&mut self) -> Result<AuthenticatorInfo, Error> {
        if let Some(info) = &self.info {
            return Ok(info.clone());
        }
        let info = self.fetch_info()?;
        self.info = Some(info.clone());
        Ok(info)
    }

    /// Force a fresh getInfo (after setPIN the cached options map
    /// is stale — clientPin flips false→true).
    pub fn refresh_info(&mut self) -> Result<AuthenticatorInfo, Error> {
        self.info = None;
        self.get_info()
    }

    fn fetch_info(&mut self) -> Result<AuthenticatorInfo, Error> {
        let resp = self.channel.exchange_cbor(&[CMD_GET_INFO])?;
        let map = cbor::decode(&resp)?;
        let mut versions = Vec::new();
        if let Some(Value::Array(items)) = map.get_int(1) {
            for v in items {
                if let Value::Text(s) = v {
                    versions.push(s.clone());
                }
            }
        }
        let mut extensions = Vec::new();
        if let Some(Value::Array(items)) = map.get_int(2) {
            for v in items {
                if let Value::Text(s) = v {
                    extensions.push(s.clone());
                }
            }
        }
        let aaguid_bytes = map
            .get_int_key_bytes(3)
            .ok_or(Error::Protocol("getInfo: no aaguid"))?;
        if aaguid_bytes.len() != 16 {
            return Err(Error::Protocol("getInfo: aaguid length"));
        }
        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(aaguid_bytes);
        let mut options = Vec::new();
        if let Some(Value::Map(entries)) = map.get_int(4) {
            for (k, v) in entries {
                if let (Value::Text(name), Value::Bool(b)) = (k, v) {
                    options.push((name.clone(), *b));
                }
            }
        }
        let max_msg_size = map.get_int(5).and_then(|v| v.as_uint());
        let mut pin_protocols = Vec::new();
        if let Some(Value::Array(items)) = map.get_int(6) {
            for v in items {
                if let Some(n) = v.as_uint() {
                    pin_protocols.push(n);
                }
            }
        }
        Ok(AuthenticatorInfo {
            versions,
            extensions,
            aaguid,
            options,
            max_msg_size,
            pin_protocols,
            raw: map,
        })
    }

    /// Open a PIN-protocol-one session with the authenticator.
    pub fn pin_session(&mut self) -> Result<PinSession, Error> {
        PinSession::establish(&mut self.channel, &mut self.rng)
    }

    /// Remaining PIN retries (no session needed).
    pub fn pin_retries(&mut self) -> Result<u64, Error> {
        crate::pin::get_pin_retries(&mut self.channel)
    }

    /// `authenticatorMakeCredential` (§6.2).
    pub fn make_credential(
        &mut self,
        params: &MakeCredentialParams<'_>,
    ) -> Result<MakeCredentialResult, Error> {
        if params.user_verification == UserVerification::Required && params.pin.is_none() {
            return Err(Error::Unsupported("uv required but no PIN supplied"));
        }
        let mut rp_map = alloc::vec![(Value::Text("id".into()), Value::Text(params.rp_id.into()))];
        if let Some(name) = params.rp_name {
            rp_map.push((Value::Text("name".into()), Value::Text(name.into())));
        }
        let mut user_map = alloc::vec![(
            Value::Text("id".into()),
            Value::Bytes(params.user_id.to_vec())
        )];
        if let Some(name) = params.user_name {
            user_map.push((Value::Text("name".into()), Value::Text(name.into())));
        }
        if let Some(dn) = params.user_display_name {
            user_map.push((Value::Text("displayName".into()), Value::Text(dn.into())));
        }
        let cred_params = Value::Array(alloc::vec![Value::Map(alloc::vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (Value::Text("alg".into()), Value::int(cose::ALG_ES256)),
        ])]);

        let mut map: Vec<(Value, Value)> = alloc::vec![
            (
                Value::int(1),
                Value::Bytes(params.client_data_hash.to_vec())
            ),
            (Value::int(2), Value::Map(rp_map)),
            (Value::int(3), Value::Map(user_map)),
            (Value::int(4), cred_params),
        ];
        if !params.exclude.is_empty() {
            map.push((
                Value::int(5),
                Value::Array(params.exclude.iter().map(|c| c.to_value()).collect()),
            ));
        }
        // Extensions request (key 6): hmac-secret enrollment is
        // the entire point of this client — always requested on
        // makeCredential so enrollment can verify it was granted.
        map.push((
            Value::int(6),
            Value::Map(alloc::vec![(
                Value::Text("hmac-secret".into()),
                Value::Bool(true),
            )]),
        ));
        let mut options: Vec<(Value, Value)> = alloc::vec![];
        if params.resident_key {
            options.push((Value::Text("rk".into()), Value::Bool(true)));
        }
        if params.user_verification != UserVerification::Discouraged {
            options.push((Value::Text("uv".into()), Value::Bool(true)));
        }
        if !options.is_empty() {
            map.push((Value::int(7), Value::Map(options)));
        }
        if let Some(pin) = params.pin {
            let session = self.pin_session()?;
            let token = session.get_pin_token(&mut self.channel, pin)?;
            let auth_param = pin_uv_auth_param(&token, &params.client_data_hash);
            map.push((Value::int(8), Value::Bytes(auth_param.to_vec())));
            map.push((Value::int(9), Value::UInt(1)));
        }

        let mut bytes = alloc::vec![CMD_MAKE_CREDENTIAL];
        bytes.extend_from_slice(&cbor::encode(&Value::Map(map)));
        let resp = self.channel.exchange_cbor(&bytes)?;
        let resp_map = cbor::decode(&resp)?;
        let fmt = resp_map
            .get_int(1)
            .and_then(|v| v.as_text().map(|s| s.to_string()))
            .ok_or(Error::Protocol("makeCredential: no fmt"))?;
        let auth_bytes = resp_map
            .get_int_key_bytes(2)
            .ok_or(Error::Protocol("makeCredential: no authData"))?
            .to_vec();
        let auth_data = AuthData::parse(&auth_bytes)?;
        if auth_data.attested.is_none() {
            return Err(Error::Protocol(
                "makeCredential: authData has no attested credential",
            ));
        }
        // RP binding: the returned rpIdHash must be SHA-256(rpId).
        if auth_data.rp_id_hash != crypto::sha256(params.rp_id.as_bytes()) {
            return Err(Error::Protocol("makeCredential: rpIdHash mismatch"));
        }
        let att_stmt = resp_map
            .get_int(3)
            .cloned()
            .ok_or(Error::Protocol("makeCredential: no attStmt"))?;
        Ok(MakeCredentialResult {
            fmt,
            auth_data,
            attestation_statement: att_stmt,
        })
    }

    /// `authenticatorGetAssertion` (§6.3) with the hmac-secret
    /// extension (§6.4) when requested.
    pub fn get_assertion(&mut self, params: &GetAssertionParams<'_>) -> Result<Assertion, Error> {
        if params.user_verification == UserVerification::Required && params.pin.is_none() {
            return Err(Error::Unsupported("uv required but no PIN supplied"));
        }
        // One key-agreement session serves the pin token AND the
        // hmac-secret salt encryption (the authenticator's
        // ephemeral persists; re-keying mid-call would orphan
        // whichever went first).
        let needs_session = params.pin.is_some() || params.hmac_secret.is_some();
        let session = if needs_session {
            Some(self.pin_session()?)
        } else {
            None
        };

        let mut map: Vec<(Value, Value)> = alloc::vec![
            (Value::int(1), Value::Text(params.rp_id.into())),
            (
                Value::int(2),
                Value::Bytes(params.client_data_hash.to_vec())
            ),
        ];
        if !params.allow.is_empty() {
            map.push((
                Value::int(3),
                Value::Array(params.allow.iter().map(|c| c.to_value()).collect()),
            ));
        }
        if let Some(hs) = &params.hmac_secret {
            let session = session.as_ref().expect("session established above");
            let mut salts = hs.salt1.to_vec();
            if let Some(s2) = &hs.salt2 {
                salts.extend_from_slice(s2);
            }
            let salt_enc = session.encrypt(&salts)?;
            let salt_auth = crypto::hmac_sha256(session.shared_secret(), &salt_enc);
            let ext = Value::Map(alloc::vec![(
                Value::Text("hmac-secret".into()),
                Value::Map(alloc::vec![
                    (Value::int(1), session.key_agreement_cose()),
                    (Value::int(2), Value::Bytes(salt_enc)),
                    (Value::int(3), Value::Bytes(salt_auth.to_vec())),
                    (Value::int(4), Value::UInt(1)),
                ]),
            )]);
            map.push((Value::int(4), ext));
        }
        let mut options: Vec<(Value, Value)> = alloc::vec![];
        if params.user_verification != UserVerification::Discouraged {
            options.push((Value::Text("uv".into()), Value::Bool(true)));
        }
        if !options.is_empty() {
            map.push((Value::int(5), Value::Map(options)));
        }
        if let Some(pin) = params.pin {
            let session = session.as_ref().expect("session established above");
            let token = session.get_pin_token(&mut self.channel, pin)?;
            let auth_param = pin_uv_auth_param(&token, &params.client_data_hash);
            map.push((Value::int(6), Value::Bytes(auth_param.to_vec())));
            map.push((Value::int(7), Value::UInt(1)));
        }

        let mut bytes = alloc::vec![CMD_GET_ASSERTION];
        bytes.extend_from_slice(&cbor::encode(&Value::Map(map)));
        let resp = self.channel.exchange_cbor(&bytes)?;
        let resp_map = cbor::decode(&resp)?;
        self.parse_assertion(&resp_map, params.rp_id, session.as_ref())
    }

    /// `authenticatorGetNextAssertion` (§6.4 shape) — call after
    /// an assertion whose `number_of_credentials` > 1.
    pub fn get_next_assertion(&mut self, rp_id: &str) -> Result<Assertion, Error> {
        let resp = self.channel.exchange_cbor(&[CMD_GET_NEXT_ASSERTION])?;
        let resp_map = cbor::decode(&resp)?;
        self.parse_assertion(&resp_map, rp_id, None)
    }

    fn parse_assertion(
        &self,
        resp_map: &Value,
        rp_id: &str,
        session: Option<&PinSession>,
    ) -> Result<Assertion, Error> {
        let credential = match resp_map.get_int(1) {
            Some(v) => Some(CredentialRef::from_value(v)?),
            None => None,
        };
        let auth_bytes = resp_map
            .get_int_key_bytes(2)
            .ok_or(Error::Protocol("getAssertion: no authData"))?
            .to_vec();
        let auth_data = AuthData::parse(&auth_bytes)?;
        if auth_data.rp_id_hash != crypto::sha256(rp_id.as_bytes()) {
            return Err(Error::Protocol("getAssertion: rpIdHash mismatch"));
        }
        let signature = resp_map
            .get_int_key_bytes(3)
            .ok_or(Error::Protocol("getAssertion: no signature"))?
            .to_vec();
        let (user_id, user_name) = match resp_map.get_int(4) {
            Some(user) => (
                user.get_text_key_bytes("id").map(|b| b.to_vec()),
                user.get_text("name")
                    .and_then(|v| v.as_text().map(|s| s.to_string())),
            ),
            None => (None, None),
        };
        let number_of_credentials = resp_map.get_int(5).and_then(|v| v.as_uint());

        // hmac-secret output lives in the authData extensions.
        let mut hmac_out = None;
        if let Some(ext) = &auth_data.extensions {
            if let Some(enc) = ext.get_text_key_bytes("hmac-secret") {
                let session = session.ok_or(Error::Protocol(
                    "getAssertion: hmac-secret output without a session",
                ))?;
                let plain = session.decrypt(enc)?;
                if plain.len() == 32 {
                    let mut first = [0u8; 32];
                    first.copy_from_slice(&plain);
                    hmac_out = Some(HmacSecretOutput {
                        first,
                        second: None,
                    });
                } else if plain.len() == 64 {
                    let mut first = [0u8; 32];
                    let mut second = [0u8; 32];
                    first.copy_from_slice(&plain[..32]);
                    second.copy_from_slice(&plain[32..]);
                    hmac_out = Some(HmacSecretOutput {
                        first,
                        second: Some(second),
                    });
                } else {
                    return Err(Error::Protocol("getAssertion: hmac-secret output length"));
                }
            }
        }

        Ok(Assertion {
            credential,
            auth_data,
            signature,
            user_id,
            user_name,
            number_of_credentials,
            hmac_secret: hmac_out,
        })
    }
}
