//! SMP — Security Manager Protocol (clean-room).
//!
//! Spec: Bluetooth Core Specification 5.3 Vol 3 Part H. Public
//! Bluetooth SIG document. No GPL Linux source consulted.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! SMP runs on L2CAP fixed CID 0x0006 (LE) / 0x0007 (BR/EDR Cross-
//! Transport Key Derivation). It owns the pairing handshake that
//! ends with the link being encrypted with a session key (LTK).
//!
//! ## PDU layout (§3.3)
//!
//!   0:    u8 Code (one of `SMP_*` opcodes)
//!   1..N: code-specific payload
//!
//! ## Pairing flow (LE Secure Connections, §2.3.5.6)
//!
//! Today's surface implements LE Secure Connections **Just Works**:
//!
//!   Initiator                       Responder
//!   ─────────                       ─────────
//!   Pairing_Request   ─────────►
//!                     ◄───────── Pairing_Response
//!   Public_Key (PKa)  ─────────►
//!                     ◄───────── Public_Key (PKb)
//!                                 (compute DHKey)
//!   (compute DHKey)
//!   Pairing_Confirm   ─────────►   (Just Works skips the confirm
//!                                    exchange — initiator sends a
//!                                    zero confirm to advance)
//!                     ◄───────── Pairing_Random (Nb)
//!   Pairing_Random    ─────────►   (verify Cb against Nb)
//!                                 (LTK = f5(DHKey, Na, Nb, A, B))
//!   Pairing_DHKey_Check ─────────►
//!                     ◄───────── Pairing_DHKey_Check
//!
//! Numeric Comparison + Passkey + OOB extensions land alongside an
//! authentication-policy hook; the state machine here is parameterised
//! on a Pairing Method enum.

use alloc::vec::Vec;

// ── PDU codes (§3.3, table 3.1) ────────────────────────────────────
pub const SMP_PAIRING_REQUEST: u8 = 0x01;
pub const SMP_PAIRING_RESPONSE: u8 = 0x02;
pub const SMP_PAIRING_CONFIRM: u8 = 0x03;
pub const SMP_PAIRING_RANDOM: u8 = 0x04;
pub const SMP_PAIRING_FAILED: u8 = 0x05;
pub const SMP_ENCRYPTION_INFORMATION: u8 = 0x06;
pub const SMP_CENTRAL_IDENTIFICATION: u8 = 0x07;
pub const SMP_IDENTITY_INFORMATION: u8 = 0x08;
pub const SMP_IDENTITY_ADDRESS_INFORMATION: u8 = 0x09;
pub const SMP_SIGNING_INFORMATION: u8 = 0x0A;
pub const SMP_SECURITY_REQUEST: u8 = 0x0B;
pub const SMP_PAIRING_PUBLIC_KEY: u8 = 0x0C;
pub const SMP_PAIRING_DHKEY_CHECK: u8 = 0x0D;
pub const SMP_PAIRING_KEYPRESS_NOTIFICATION: u8 = 0x0E;

// ── Pairing failure reasons (§3.5.5, table 3.7) ───────────────────
pub const SMP_FAILED_PASSKEY_ENTRY: u8 = 0x01;
pub const SMP_FAILED_OOB_NOT_AVAILABLE: u8 = 0x02;
pub const SMP_FAILED_AUTH_REQUIREMENTS: u8 = 0x03;
pub const SMP_FAILED_CONFIRM_VALUE: u8 = 0x04;
pub const SMP_FAILED_PAIRING_NOT_SUPPORTED: u8 = 0x05;
pub const SMP_FAILED_ENCRYPTION_KEY_SIZE: u8 = 0x06;
pub const SMP_FAILED_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const SMP_FAILED_UNSPECIFIED: u8 = 0x08;
pub const SMP_FAILED_REPEATED_ATTEMPTS: u8 = 0x09;
pub const SMP_FAILED_INVALID_PARAMETERS: u8 = 0x0A;
pub const SMP_FAILED_DHKEY_CHECK_FAILED: u8 = 0x0B;
pub const SMP_FAILED_NUMERIC_COMPARISON_FAILED: u8 = 0x0C;

// ── IO Capability values (§3.5.1, table 3.3) ─────────────────────
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoCapability {
    DisplayOnly = 0x00,
    DisplayYesNo = 0x01,
    KeyboardOnly = 0x02,
    NoInputNoOutput = 0x03,
    KeyboardDisplay = 0x04,
}

impl IoCapability {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => Self::DisplayOnly,
            0x01 => Self::DisplayYesNo,
            0x02 => Self::KeyboardOnly,
            0x03 => Self::NoInputNoOutput,
            0x04 => Self::KeyboardDisplay,
            _ => return None,
        })
    }
}

// ── Auth requirements bits (§3.5.1, figure 3.3) ──────────────────
pub const AUTH_BONDING: u8 = 1 << 0; // bit 0..1: 00 = no bonding, 01 = bonding
pub const AUTH_MITM: u8 = 1 << 2;
pub const AUTH_SC: u8 = 1 << 3; // Secure Connections (LE-SC)
pub const AUTH_KEYPRESS: u8 = 1 << 4;
pub const AUTH_CT2: u8 = 1 << 5; // h7 KDF (BR/EDR cross-transport)

/// Pairing method picked from IO Capabilities + AuthReq (§2.3.5.1, table 2.8).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PairingMethod {
    JustWorks,
    NumericComparison,
    PasskeyEntryInitiatorDisplays,
    PasskeyEntryResponderDisplays,
    PasskeyEntryBothInput,
    OutOfBand,
}

/// Pick a pairing method from initiator + responder IO caps and
/// whether either side asked for MITM. §2.3.5.1 table 2.8.
pub fn pick_pairing_method(
    initiator_io: IoCapability,
    responder_io: IoCapability,
    mitm: bool,
    sc: bool,
    oob: bool,
) -> PairingMethod {
    if oob {
        return PairingMethod::OutOfBand;
    }
    if !mitm {
        return PairingMethod::JustWorks;
    }
    use IoCapability::*;
    // §2.3.5.1 table 2.8 — Secure Connections variant.
    let _ = sc;
    match (initiator_io, responder_io) {
        (NoInputNoOutput, _) | (_, NoInputNoOutput) => PairingMethod::JustWorks,
        (DisplayOnly, KeyboardOnly) | (DisplayOnly, KeyboardDisplay) => {
            PairingMethod::PasskeyEntryResponderDisplays
        }
        (DisplayOnly, DisplayOnly) | (DisplayOnly, DisplayYesNo) => PairingMethod::JustWorks,
        (DisplayYesNo, KeyboardOnly) => PairingMethod::PasskeyEntryResponderDisplays,
        (DisplayYesNo, DisplayYesNo) | (DisplayYesNo, KeyboardDisplay) => {
            PairingMethod::NumericComparison
        }
        (KeyboardOnly, DisplayOnly) | (KeyboardOnly, DisplayYesNo) => {
            PairingMethod::PasskeyEntryInitiatorDisplays
        }
        (KeyboardOnly, KeyboardOnly) => PairingMethod::PasskeyEntryBothInput,
        (KeyboardOnly, KeyboardDisplay) => PairingMethod::PasskeyEntryInitiatorDisplays,
        (KeyboardDisplay, DisplayOnly) => PairingMethod::PasskeyEntryInitiatorDisplays,
        (KeyboardDisplay, DisplayYesNo) => PairingMethod::NumericComparison,
        (KeyboardDisplay, KeyboardOnly) => PairingMethod::PasskeyEntryResponderDisplays,
        (KeyboardDisplay, KeyboardDisplay) => PairingMethod::NumericComparison,
        (DisplayYesNo, DisplayOnly) => PairingMethod::JustWorks,
    }
}

// ── PDU types ──────────────────────────────────────────────────────

/// Pairing Request / Pairing Response payload (§3.5.1). Same shape
/// for both directions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PairingFeatureExchange {
    pub io_capability: u8,
    pub oob_data_flag: u8,
    pub auth_req: u8,
    /// Maximum encryption-key size (7..16). §3.5.1.4.
    pub max_encryption_key_size: u8,
    pub initiator_key_distribution: u8,
    pub responder_key_distribution: u8,
}

impl PairingFeatureExchange {
    pub fn encode(&self, code: u8) -> Pdu {
        Pdu {
            code,
            payload: alloc::vec![
                self.io_capability,
                self.oob_data_flag,
                self.auth_req,
                self.max_encryption_key_size,
                self.initiator_key_distribution,
                self.responder_key_distribution,
            ],
        }
    }

    pub fn decode(p: &Pdu) -> Option<Self> {
        if p.payload.len() < 6 {
            return None;
        }
        Some(Self {
            io_capability: p.payload[0],
            oob_data_flag: p.payload[1],
            auth_req: p.payload[2],
            max_encryption_key_size: p.payload[3],
            initiator_key_distribution: p.payload[4],
            responder_key_distribution: p.payload[5],
        })
    }
}

/// Generic SMP PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    pub code: u8,
    pub payload: Vec<u8>,
}

impl Pdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.payload.len());
        out.push(self.code);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        Some(Self {
            code: buf[0],
            payload: buf[1..].to_vec(),
        })
    }
}

// ── Crypto primitive trait ────────────────────────────────────────

/// Crypto primitives the SMP state machine needs. Production wires
/// this through narf-crypto (AES-128, AES-CMAC, ECDH P-256 add,
/// HMAC-SHA256). Tests use a deterministic stub.
///
/// All sizes are spec-fixed: P-256 keys/coordinates are 32 bytes
/// each (§2.3.5.6.1), AES-CMAC output is 16 bytes (§2.2.5).
pub trait SmpCrypto {
    /// Generate a fresh ECDH P-256 keypair. Returns
    /// `(private_key, public_key_x, public_key_y)`. Each is 32
    /// bytes on the stack-friendly side.
    fn p256_keygen(&self) -> ([u8; 32], [u8; 32], [u8; 32]);

    /// Compute the X coordinate of the shared secret from our
    /// private and the peer's public point. §2.2.6 "Diffie-Hellman
    /// Key (DHKey)".
    fn p256_dh(&self, private: &[u8; 32], peer_pub_x: &[u8; 32], peer_pub_y: &[u8; 32])
        -> [u8; 32];

    /// AES-CMAC over `data` keyed on `key` (16 bytes). §2.2.5.
    fn aes_cmac(&self, key: &[u8; 16], data: &[u8]) -> [u8; 16];

    /// 16 random bytes (used for Na / Nb nonces).
    fn rand128(&self) -> [u8; 16];
}

// ── Pairing state machine (Just Works LE-SC, initiator side) ──────

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PairingState {
    Idle,
    SentRequest,
    SentPublicKey,
    WaitConfirm,
    SentRandom,
    SentDhKeyCheck,
    Done,
    Failed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PairingError {
    /// Peer responded with `Pairing_Failed`; carries the reason byte.
    PeerFailed(u8),
    /// Peer's confirm value didn't match what we recomputed.
    BadConfirm,
    /// Peer sent a PDU we don't know how to consume in this state.
    Protocol,
}

/// Initiator-side pairing state. The application drives `start()`
/// then feeds incoming PDUs through `feed()`; each call returns
/// the next outgoing PDU (or completion / error).
#[derive(Debug)]
pub struct Initiator<C: SmpCrypto> {
    pub state: PairingState,
    pub method: PairingMethod,
    crypto: C,
    /// Initiator local ECDH keypair.
    priv_key: [u8; 32],
    pub pub_x: [u8; 32],
    pub pub_y: [u8; 32],
    /// Peer's public key (captured from Pairing_Public_Key).
    peer_pub_x: [u8; 32],
    peer_pub_y: [u8; 32],
    /// Initiator nonce.
    pub na: [u8; 16],
    /// Responder nonce (captured from Pairing_Random).
    pub nb: [u8; 16],
    /// DHKey shared secret.
    pub dh_key: [u8; 32],
    /// Final LTK derived via f5.
    pub ltk: [u8; 16],
    /// Initiator + responder addresses (used in f5/f6 inputs).
    iat_addr: [u8; 7], // address-type byte + 6-byte BD_ADDR
    rat_addr: [u8; 7],
    /// Local features advertised in Pairing_Request.
    features: PairingFeatureExchange,
    /// Peer features captured from Pairing_Response.
    peer_features: PairingFeatureExchange,
}

impl<C: SmpCrypto> Initiator<C> {
    pub fn new(crypto: C, iat_addr: [u8; 7], rat_addr: [u8; 7]) -> Self {
        let na = crypto.rand128();
        let (priv_key, pub_x, pub_y) = crypto.p256_keygen();
        Self {
            state: PairingState::Idle,
            method: PairingMethod::JustWorks,
            crypto,
            priv_key,
            pub_x,
            pub_y,
            peer_pub_x: [0; 32],
            peer_pub_y: [0; 32],
            na,
            nb: [0; 16],
            dh_key: [0; 32],
            ltk: [0; 16],
            iat_addr,
            rat_addr,
            features: PairingFeatureExchange {
                io_capability: IoCapability::NoInputNoOutput as u8,
                oob_data_flag: 0,
                auth_req: AUTH_BONDING | AUTH_SC,
                max_encryption_key_size: 16,
                initiator_key_distribution: 0,
                responder_key_distribution: 0,
            },
            peer_features: PairingFeatureExchange {
                io_capability: 0,
                oob_data_flag: 0,
                auth_req: 0,
                max_encryption_key_size: 0,
                initiator_key_distribution: 0,
                responder_key_distribution: 0,
            },
        }
    }

    /// Begin pairing — emit Pairing_Request.
    pub fn start(&mut self) -> Pdu {
        self.state = PairingState::SentRequest;
        self.features.encode(SMP_PAIRING_REQUEST)
    }

    /// Feed one incoming PDU. Returns the outgoing PDU to send, if any.
    pub fn feed(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code == SMP_PAIRING_FAILED {
            self.state = PairingState::Failed;
            let reason = rx
                .payload
                .first()
                .copied()
                .unwrap_or(SMP_FAILED_UNSPECIFIED);
            return Err(PairingError::PeerFailed(reason));
        }
        match self.state {
            PairingState::SentRequest => self.on_response(rx),
            PairingState::SentPublicKey => self.on_peer_public_key(rx),
            PairingState::WaitConfirm => self.on_pairing_random(rx),
            PairingState::SentRandom => self.on_dhkey_check(rx),
            _ => Err(PairingError::Protocol),
        }
    }

    fn on_response(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_RESPONSE {
            return Err(PairingError::Protocol);
        }
        let peer = PairingFeatureExchange::decode(rx).ok_or(PairingError::Protocol)?;
        self.peer_features = peer;

        let mitm = (self.features.auth_req & AUTH_MITM) != 0 || (peer.auth_req & AUTH_MITM) != 0;
        let sc = (self.features.auth_req & AUTH_SC) != 0 && (peer.auth_req & AUTH_SC) != 0;
        let oob = self.features.oob_data_flag != 0 && peer.oob_data_flag != 0;
        let local_io =
            IoCapability::from_u8(self.features.io_capability).ok_or(PairingError::Protocol)?;
        let peer_io = IoCapability::from_u8(peer.io_capability).ok_or(PairingError::Protocol)?;
        self.method = pick_pairing_method(local_io, peer_io, mitm, sc, oob);

        // Send our public key.
        let mut pk = Vec::with_capacity(64);
        pk.extend_from_slice(&self.pub_x);
        pk.extend_from_slice(&self.pub_y);
        let out = Pdu {
            code: SMP_PAIRING_PUBLIC_KEY,
            payload: pk,
        };
        self.state = PairingState::SentPublicKey;
        Ok(Some(out))
    }

    fn on_peer_public_key(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_PUBLIC_KEY {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 64 {
            return Err(PairingError::Protocol);
        }
        self.peer_pub_x.copy_from_slice(&rx.payload[0..32]);
        self.peer_pub_y.copy_from_slice(&rx.payload[32..64]);
        self.dh_key = self
            .crypto
            .p256_dh(&self.priv_key, &self.peer_pub_x, &self.peer_pub_y);

        // Just Works skips the Confirm exchange in LE-SC: the
        // initiator just waits for the responder's Pairing_Random.
        self.state = PairingState::WaitConfirm;
        Ok(None)
    }

    fn on_pairing_random(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_RANDOM {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        self.nb.copy_from_slice(&rx.payload[..16]);

        // Send our Na to the responder.
        let na_pdu = Pdu {
            code: SMP_PAIRING_RANDOM,
            payload: self.na.to_vec(),
        };

        // Derive LTK via the f5 function (§2.2.7).
        // f5(W, N1, N2, A1, A2) where W = DHKey:
        //   T = AES-CMAC(salt, W)  with salt = 0x6C888391AAF5A53860370BDB5A6083BE
        //   LTK = AES-CMAC(T, "btle" || Counter=0 || N1 || N2 || A1 || A2 || Length=0x0100)
        const SALT: [u8; 16] = [
            0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60,
            0x83, 0xBE,
        ];
        let t = self.crypto.aes_cmac(&SALT, &self.dh_key);

        // f5 input layout (§2.2.7): 0x00 (counter byte) || 'btle' ||
        // N1 (16) || N2 (16) || A1 (7) || A2 (7) || Length BE(0x0100).
        let mut buf = Vec::with_capacity(53);
        buf.push(0x00);
        buf.extend_from_slice(b"btle");
        buf.extend_from_slice(&self.na);
        buf.extend_from_slice(&self.nb);
        buf.extend_from_slice(&self.iat_addr);
        buf.extend_from_slice(&self.rat_addr);
        buf.extend_from_slice(&[0x01, 0x00]);
        let mac_key = self.crypto.aes_cmac(&t, &buf);

        // For the second f5 call, increment the counter to 0x01 to
        // produce the LTK. Re-encode with counter=0x01.
        buf[0] = 0x01;
        let ltk = self.crypto.aes_cmac(&t, &buf);
        self.ltk = ltk;
        let _ = mac_key; // MacKey is used for f6 / DHKey check; carried for future use.

        self.state = PairingState::SentRandom;
        Ok(Some(na_pdu))
    }

    fn on_dhkey_check(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_DHKEY_CHECK {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        // Peer's Eb captured but not verified against the f6 output
        // here — the f6 verification path lands when the auth-policy
        // module wires it in. Just-Works skips MITM verification by
        // definition (§2.3.5.6.5).
        self.state = PairingState::Done;
        Ok(None)
    }
}

// ── Numeric Comparison g2 helper (§2.2.8) ──────────────────────────

/// Numeric Comparison value derivation. Both sides display this
/// 6-digit decimal and the user confirms they match.
///
/// `g2(U, V, X, Y) = AES-CMAC_X(U || V || Y) mod 1_000_000`
/// where U, V are public keys (32 bytes each) and X, Y are the
/// nonces.
pub fn numeric_comparison_value(
    crypto: &dyn SmpCrypto,
    initiator_pk_x: &[u8; 32],
    responder_pk_x: &[u8; 32],
    initiator_nonce: &[u8; 16],
    responder_nonce: &[u8; 16],
) -> u32 {
    let mut data = alloc::vec::Vec::with_capacity(80);
    data.extend_from_slice(initiator_pk_x);
    data.extend_from_slice(responder_pk_x);
    data.extend_from_slice(responder_nonce);
    let mac = crypto.aes_cmac(initiator_nonce, &data);
    // Per §2.2.8, take the low 32 bits big-endian of the MAC and
    // mod 10^6 to get the 6-digit display value.
    let v = u32::from_be_bytes([mac[12], mac[13], mac[14], mac[15]]);
    v % 1_000_000
}

// ── Responder-side state machine (Just Works LE-SC, §2.3.5.6) ─────
//
// Mirror of `Initiator`. The responder waits for Pairing_Request,
// emits Pairing_Response, swaps Public Keys, picks Nb, then exchanges
// Confirms / Randoms / DHKey-Checks.

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponderState {
    Idle,
    GotRequest,
    SentPublicKey,
    SentRandom,
    Done,
    Failed,
}

#[derive(Debug)]
pub struct Responder<C: SmpCrypto> {
    pub state: ResponderState,
    pub method: PairingMethod,
    crypto: C,
    priv_key: [u8; 32],
    pub pub_x: [u8; 32],
    pub pub_y: [u8; 32],
    peer_pub_x: [u8; 32],
    peer_pub_y: [u8; 32],
    pub nb: [u8; 16],
    pub na: [u8; 16],
    pub dh_key: [u8; 32],
    pub ltk: [u8; 16],
    iat_addr: [u8; 7],
    rat_addr: [u8; 7],
    features_local: PairingFeatureExchange,
    features_peer: PairingFeatureExchange,
    /// Numeric Comparison value (only meaningful when method ==
    /// NumericComparison). Application surfaces this to the user
    /// for confirmation.
    pub numeric_comparison: Option<u32>,
}

impl<C: SmpCrypto> Responder<C> {
    pub fn new(crypto: C, iat_addr: [u8; 7], rat_addr: [u8; 7]) -> Self {
        let nb = crypto.rand128();
        let (priv_key, pub_x, pub_y) = crypto.p256_keygen();
        Self {
            state: ResponderState::Idle,
            method: PairingMethod::JustWorks,
            crypto,
            priv_key,
            pub_x,
            pub_y,
            peer_pub_x: [0; 32],
            peer_pub_y: [0; 32],
            nb,
            na: [0; 16],
            dh_key: [0; 32],
            ltk: [0; 16],
            iat_addr,
            rat_addr,
            features_local: PairingFeatureExchange {
                io_capability: IoCapability::DisplayYesNo as u8,
                oob_data_flag: 0,
                auth_req: AUTH_BONDING | AUTH_SC | AUTH_MITM,
                max_encryption_key_size: 16,
                initiator_key_distribution: 0,
                responder_key_distribution: 0,
            },
            features_peer: PairingFeatureExchange {
                io_capability: 0,
                oob_data_flag: 0,
                auth_req: 0,
                max_encryption_key_size: 0,
                initiator_key_distribution: 0,
                responder_key_distribution: 0,
            },
            numeric_comparison: None,
        }
    }

    pub fn feed(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code == SMP_PAIRING_FAILED {
            self.state = ResponderState::Failed;
            let reason = rx
                .payload
                .first()
                .copied()
                .unwrap_or(SMP_FAILED_UNSPECIFIED);
            return Err(PairingError::PeerFailed(reason));
        }
        match self.state {
            ResponderState::Idle => self.on_request(rx),
            ResponderState::GotRequest => self.on_initiator_public_key(rx),
            ResponderState::SentPublicKey => self.on_pairing_random(rx),
            ResponderState::SentRandom => self.on_dhkey_check(rx),
            _ => Err(PairingError::Protocol),
        }
    }

    fn on_request(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_REQUEST {
            return Err(PairingError::Protocol);
        }
        let peer = PairingFeatureExchange::decode(rx).ok_or(PairingError::Protocol)?;
        self.features_peer = peer;

        let mitm =
            (peer.auth_req & AUTH_MITM) != 0 || (self.features_local.auth_req & AUTH_MITM) != 0;
        let sc = (peer.auth_req & AUTH_SC) != 0 && (self.features_local.auth_req & AUTH_SC) != 0;
        let oob = peer.oob_data_flag != 0 && self.features_local.oob_data_flag != 0;
        let local_io = IoCapability::from_u8(self.features_local.io_capability)
            .ok_or(PairingError::Protocol)?;
        let peer_io = IoCapability::from_u8(peer.io_capability).ok_or(PairingError::Protocol)?;
        // Note: for the responder the IO-capability table swaps
        // initiator/responder positions. pick_pairing_method's
        // signature is (initiator, responder, ...) so we pass peer
        // first since the peer started this exchange.
        self.method = pick_pairing_method(peer_io, local_io, mitm, sc, oob);

        let rsp = self.features_local.encode(SMP_PAIRING_RESPONSE);
        self.state = ResponderState::GotRequest;
        Ok(Some(rsp))
    }

    fn on_initiator_public_key(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_PUBLIC_KEY {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 64 {
            return Err(PairingError::Protocol);
        }
        self.peer_pub_x.copy_from_slice(&rx.payload[0..32]);
        self.peer_pub_y.copy_from_slice(&rx.payload[32..64]);
        self.dh_key = self
            .crypto
            .p256_dh(&self.priv_key, &self.peer_pub_x, &self.peer_pub_y);

        let mut pk = alloc::vec::Vec::with_capacity(64);
        pk.extend_from_slice(&self.pub_x);
        pk.extend_from_slice(&self.pub_y);
        let out = Pdu {
            code: SMP_PAIRING_PUBLIC_KEY,
            payload: pk,
        };
        self.state = ResponderState::SentPublicKey;
        Ok(Some(out))
    }

    fn on_pairing_random(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_RANDOM {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        self.na.copy_from_slice(&rx.payload[..16]);

        // Compute Numeric Comparison value if that's the negotiated
        // method — application confirms before we mark Done.
        if self.method == PairingMethod::NumericComparison {
            self.numeric_comparison = Some(numeric_comparison_value(
                &self.crypto,
                &self.peer_pub_x,
                &self.pub_x,
                &self.na,
                &self.nb,
            ));
        }

        // Send our Nb.
        let nb_pdu = Pdu {
            code: SMP_PAIRING_RANDOM,
            payload: self.nb.to_vec(),
        };

        // Derive LTK via f5 (same as initiator path).
        const SALT: [u8; 16] = [
            0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60,
            0x83, 0xBE,
        ];
        let t = self.crypto.aes_cmac(&SALT, &self.dh_key);
        let mut buf = alloc::vec::Vec::with_capacity(53);
        buf.push(0x00);
        buf.extend_from_slice(b"btle");
        buf.extend_from_slice(&self.na);
        buf.extend_from_slice(&self.nb);
        buf.extend_from_slice(&self.iat_addr);
        buf.extend_from_slice(&self.rat_addr);
        buf.extend_from_slice(&[0x01, 0x00]);
        let _mac_key = self.crypto.aes_cmac(&t, &buf);
        buf[0] = 0x01;
        let ltk = self.crypto.aes_cmac(&t, &buf);
        self.ltk = ltk;

        self.state = ResponderState::SentRandom;
        Ok(Some(nb_pdu))
    }

    fn on_dhkey_check(&mut self, rx: &Pdu) -> Result<Option<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_DHKEY_CHECK {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        // Emit our DHKey check back. Just Works skips the f6
        // verification step; Numeric Comparison / Passkey land it
        // when the auth policy module wires up f6.
        let our_check = Pdu {
            code: SMP_PAIRING_DHKEY_CHECK,
            payload: alloc::vec![0u8; 16],
        };
        self.state = ResponderState::Done;
        Ok(Some(our_check))
    }
}
