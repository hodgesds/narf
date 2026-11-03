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
//! Today's surface implements LE Secure Connections **Just Works**
//! (the §2.3.5.6.2 commitment sequence is shared with Numeric
//! Comparison; only the user-confirmation step differs):
//!
//!   Initiator                       Responder
//!   ─────────                       ─────────
//!   Pairing_Request   ─────────►
//!                     ◄───────── Pairing_Response
//!   Public_Key (PKa)  ─────────►
//!                     ◄───────── Public_Key (PKb)
//!   (DHKey; Ca = f4(PKa, PKb, Na, 0))
//!   Pairing_Confirm   ─────────►   (store Ca)
//!                     ◄───────── Pairing_Confirm (Cb = f4(PKb, PKa, Nb, 0))
//!                     ◄───────── Pairing_Random (Nb)
//!   (verify Cb; MacKey‖LTK = f5(DHKey, Na, Nb, A, B);
//!    Ea = f6(MacKey, Na, Nb, 0, IOcapA, A, B))
//!   Pairing_Random    ─────────►   (verify Ca)
//!   Pairing_DHKey_Check (Ea) ────► (verify Ea;
//!                                   Eb = f6(MacKey, Nb, Na, 0, IOcapB, B, A))
//!                     ◄───────── Pairing_DHKey_Check (Eb)
//!   (verify Eb)
//!
//! A confirm mismatch aborts with Pairing Failed reason 0x04
//! (Confirm Value Failed); a DHKey Check mismatch with 0x0B
//! (DHKey Check Failed) — §3.5.5 table 3.7.
//!
//! Passkey + OOB extensions land alongside an authentication-policy
//! hook; the state machine here is parameterised on a Pairing
//! Method enum.

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

/// Key-distribution field bits (Part H §3.6.1, Figure 3.11).
/// The octet layout is a bitmask: bit 0 EncKey, bit 1 IdKey,
/// bit 2 Sign, bit 3 LinkKey. This lane only ever negotiates the
/// IdKey and Sign bits — EncKey is ignored for LE Secure
/// Connections (§3.6.1: "the EncKey field shall be ignored. EDIV
/// and Rand shall be set to zero and shall not be distributed"),
/// and LinkKey (BR/EDR cross-transport) is out of scope.
pub const DIST_ENCKEY: u8 = 0x01;
pub const DIST_IDKEY: u8 = 0x02;
pub const DIST_SIGN: u8 = 0x04;
pub const DIST_LINKKEY: u8 = 0x08;

/// Distribution bits this lane negotiates (IdKey | Sign).
pub const DIST_SUPPORTED: u8 = DIST_IDKEY | DIST_SIGN;

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
    /// private and the peer's public point — the DHKey of
    /// §2.3.5.6.1.
    fn p256_dh(&self, private: &[u8; 32], peer_pub_x: &[u8; 32], peer_pub_y: &[u8; 32])
        -> [u8; 32];

    /// AES-CMAC over `data` keyed on `key` (16 bytes). §2.2.5.
    fn aes_cmac(&self, key: &[u8; 16], data: &[u8]) -> [u8; 16];

    /// 16 random bytes (used for Na / Nb nonces).
    fn rand128(&self) -> [u8; 16];
}

// ── f4 / f5 / f6 derivation helpers (§2.2.6 – §2.2.8) ─────────────

/// IOcap input to f6 (§2.2.8): the 24-bit value whose most
/// significant octet is the AuthReq parameter, middle octet the
/// OOB data flag, and least significant octet the IO capability —
/// the reverse of the Pairing Request/Response payload order.
pub fn iocap_bytes(features: &PairingFeatureExchange) -> [u8; 3] {
    [
        features.auth_req,
        features.oob_data_flag,
        features.io_capability,
    ]
}

/// f4 confirm value (§2.2.6): `AES-CMAC_X(U ‖ V ‖ Z)` where X is
/// the computing device's own nonce. Per table 2.1 each device
/// passes its **own** public-key X coordinate as U and the peer's
/// as V — the initiator computes `Ca = f4(PKax, PKbx, Na, 0)` and
/// the responder `Cb = f4(PKbx, PKax, Nb, 0)`. `z` is 0 for Just
/// Works and Numeric Comparison.
pub fn confirm_value(
    crypto: &dyn SmpCrypto,
    own_pk_x: &[u8; 32],
    peer_pk_x: &[u8; 32],
    own_nonce: &[u8; 16],
    z: u8,
) -> [u8; 16] {
    let mut data = Vec::with_capacity(65);
    data.extend_from_slice(own_pk_x);
    data.extend_from_slice(peer_pk_x);
    data.push(z);
    crypto.aes_cmac(own_nonce, &data)
}

/// f5 key derivation (§2.2.7): returns `(MacKey, LTK)`, the
/// counter-0 and counter-1 halves of `f5(W, N1, N2, A1, A2)` with
/// `T = AES-CMAC_SALT(W)` and W = DHKey. A1/A2 are the initiator /
/// responder addresses (type byte + BD_ADDR).
pub fn derive_mac_key_and_ltk(
    crypto: &dyn SmpCrypto,
    dh_key: &[u8; 32],
    na: &[u8; 16],
    nb: &[u8; 16],
    iat_addr: &[u8; 7],
    rat_addr: &[u8; 7],
) -> ([u8; 16], [u8; 16]) {
    const SALT: [u8; 16] = [
        0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83,
        0xBE,
    ];
    let t = crypto.aes_cmac(&SALT, dh_key);
    // Layout (§2.2.7): counter (1) ‖ keyID "btle" ‖ N1 ‖ N2 ‖
    // A1 ‖ A2 ‖ Length (256 as two octets, 0x01 0x00).
    let mut buf = Vec::with_capacity(53);
    buf.push(0x00);
    buf.extend_from_slice(b"btle");
    buf.extend_from_slice(na);
    buf.extend_from_slice(nb);
    buf.extend_from_slice(iat_addr);
    buf.extend_from_slice(rat_addr);
    buf.extend_from_slice(&[0x01, 0x00]);
    let mac_key = crypto.aes_cmac(&t, &buf);
    // Counter 0x01 produces the LTK half.
    buf[0] = 0x01;
    let ltk = crypto.aes_cmac(&t, &buf);
    (mac_key, ltk)
}

/// The §2.2.8 f6 message inputs, in formula order. Bundled so
/// [`dhkey_check_value`] takes the MacKey plus this one
/// spec-shaped block instead of six loose slices: the caller
/// picks the initiator or the table-2.2 responder ordering by
/// which values it places in `n1`/`n2` and `a1`/`a2`.
#[derive(Debug)]
pub struct DhKeyCheckInputs<'a> {
    /// First nonce (Na for Ea, Nb for Eb).
    pub n1: &'a [u8; 16],
    /// Second nonce (Nb for Ea, Na for Eb).
    pub n2: &'a [u8; 16],
    /// The 128-bit random (zero for Just Works / Numeric
    /// Comparison).
    pub r: &'a [u8; 16],
    /// IO capabilities, from [`iocap_bytes`].
    pub iocap: &'a [u8; 3],
    /// First address (A for Ea, B for Eb): type byte + BD_ADDR.
    pub a1: &'a [u8; 7],
    /// Second address (B for Ea, A for Eb).
    pub a2: &'a [u8; 7],
}

/// f6 DHKey check value (§2.2.8):
/// `AES-CMAC_W(N1 ‖ N2 ‖ R ‖ IOcap ‖ A1 ‖ A2)` keyed on the f5
/// MacKey. Per table 2.2, for Just Works / Numeric Comparison the
/// initiator's check is `Ea = f6(MacKey, Na, Nb, 0, IOcapA, A, B)`
/// and the responder's is `Eb = f6(MacKey, Nb, Na, 0, IOcapB, B, A)`
/// — the responder's form swaps both the nonce order and the
/// address order. `inputs` carries the message block in formula
/// order; see [`DhKeyCheckInputs`].
pub fn dhkey_check_value(
    crypto: &dyn SmpCrypto,
    mac_key: &[u8; 16],
    inputs: &DhKeyCheckInputs<'_>,
) -> [u8; 16] {
    let mut data = Vec::with_capacity(65);
    data.extend_from_slice(inputs.n1);
    data.extend_from_slice(inputs.n2);
    data.extend_from_slice(inputs.r);
    data.extend_from_slice(inputs.iocap);
    data.extend_from_slice(inputs.a1);
    data.extend_from_slice(inputs.a2);
    crypto.aes_cmac(mac_key, &data)
}

// ── Pairing state machine (Just Works LE-SC, initiator side) ──────

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PairingState {
    Idle,
    SentRequest,
    SentPublicKey,
    WaitConfirm,
    WaitRandom,
    SentDhKeyCheck,
    /// Authentication (Phase 2) completed and keys are negotiated
    /// for distribution, but the link is not yet encrypted. Phase 3
    /// distribution PDUs are only legal on an encrypted link (Part H
    /// §3.6.4–§3.6.6), so the session parks here until the pump
    /// reports encryption; the pump then calls
    /// [`Initiator::begin_distribution`].
    AuthComplete,
    /// Our side's distribution PDUs (if any) are sent and the
    /// peer's are still arriving. [`Initiator::on_distribution`]
    /// consumes them in §3.6.1 order.
    WaitDistribution,
    Done,
    Failed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PairingError {
    /// Peer responded with `Pairing_Failed`; carries the reason byte.
    PeerFailed(u8),
    /// Peer's confirm value didn't match what we recomputed.
    BadConfirm,
    /// Peer's DHKey Check value didn't match what we recomputed.
    BadDhKeyCheck,
    /// Peer sent a PDU we don't know how to consume in this state.
    Protocol,
}

/// Phase 3 key-distribution helpers (Part H §3.6.1, §3.6.4–§3.6.6).
///
/// Distribution order for LE Secure Connections is fixed: the
/// Peripheral distributes first (IRK, then BD_ADDR, then CSRK),
/// then the Central distributes in the same order. Within one
/// side's distribution, Identity Information (IRK) is always
/// followed by Identity Address Information — the two are one
/// IdKey unit, not independent keys.

/// Build this side's Phase 3 PDUs for the negotiated `dist_send`
/// set, in §3.6.1 order: Identity Information, Identity Address
/// Information, Signing Information. The IRK and CSRK are fresh
/// randoms per pairing — a stable device IRK (so a peer's stored
/// bond can resolve our RPA across pairings) is future work; a
/// fresh IRK per pairing is conformant, it only forfeits RPA
/// resolution by previously-bonded peers.
fn own_distribution_pdus(crypto: &dyn SmpCrypto, dist_send: u8, own_addr: &[u8; 7]) -> Vec<Pdu> {
    let mut out = Vec::new();
    if dist_send & DIST_IDKEY != 0 {
        out.push(Pdu {
            code: SMP_IDENTITY_INFORMATION,
            payload: crypto.rand128().to_vec(),
        });
        let mut addr = Vec::with_capacity(7);
        addr.extend_from_slice(own_addr);
        out.push(Pdu {
            code: SMP_IDENTITY_ADDRESS_INFORMATION,
            payload: addr,
        });
    }
    if dist_send & DIST_SIGN != 0 {
        out.push(Pdu {
            code: SMP_SIGNING_INFORMATION,
            payload: crypto.rand128().to_vec(),
        });
    }
    out
}

/// Consume one peer Phase 3 PDU in §3.6.1 order. Returns true
/// when the peer's distribution is complete (no keys remain
/// expected). Strict: a PDU out of order, of the wrong code, or
/// arriving when nothing is expected is a Protocol error — the
/// caller fails the pairing rather than storing a half-parsed
/// key set.
#[allow(clippy::too_many_arguments)]
fn consume_distribution_pdu(
    dist_expect: &mut u8,
    got_identity: &mut bool,
    peer_irk: &mut Option<[u8; 16]>,
    peer_identity_addr: &mut Option<[u8; 7]>,
    peer_csrk: &mut Option<[u8; 16]>,
    rx: &Pdu,
) -> Result<bool, PairingError> {
    if *dist_expect & DIST_IDKEY != 0 && !*got_identity {
        if rx.code != SMP_IDENTITY_INFORMATION || rx.payload.len() != 16 {
            return Err(PairingError::Protocol);
        }
        let mut irk = [0u8; 16];
        irk.copy_from_slice(&rx.payload);
        *peer_irk = Some(irk);
        *got_identity = true;
    } else if *got_identity {
        if rx.code != SMP_IDENTITY_ADDRESS_INFORMATION || rx.payload.len() != 7 {
            return Err(PairingError::Protocol);
        }
        let mut addr = [0u8; 7];
        addr.copy_from_slice(&rx.payload);
        *peer_identity_addr = Some(addr);
        *got_identity = false;
        *dist_expect &= !DIST_IDKEY;
    } else if *dist_expect & DIST_SIGN != 0 {
        if rx.code != SMP_SIGNING_INFORMATION || rx.payload.len() != 16 {
            return Err(PairingError::Protocol);
        }
        let mut csrk = [0u8; 16];
        csrk.copy_from_slice(&rx.payload);
        *peer_csrk = Some(csrk);
        *dist_expect &= !DIST_SIGN;
    } else {
        return Err(PairingError::Protocol);
    }
    Ok(*dist_expect == 0)
}

/// Initiator-side pairing state. The application drives `start()`
/// then feeds incoming PDUs through `feed()`; each call returns
/// the outgoing PDUs to send (or completion / error).
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
    /// MacKey half of f5 — keys the f6 DHKey checks.
    pub mac_key: [u8; 16],
    /// Peer's confirm value Cb (captured from Pairing_Confirm).
    peer_confirm: [u8; 16],
    /// Initiator + responder addresses (used in f5/f6 inputs).
    iat_addr: [u8; 7], // address-type byte + 6-byte BD_ADDR
    rat_addr: [u8; 7],
    /// Local features advertised in Pairing_Request.
    features: PairingFeatureExchange,
    /// Peer features captured from Pairing_Response.
    peer_features: PairingFeatureExchange,
    /// True when both sides negotiated bonding (both Bonding_Flags
    /// == 01). The pump stores a bond only when this is set; a
    /// non-bonded pairing's LTK lives for the connection only.
    pub bonded: bool,
    /// Keys this side sends in Phase 3, negotiated as (own byte) ∩
    /// (peer byte) masked to [`DIST_SUPPORTED`]. Zero when not
    /// bonding or when nothing was negotiated.
    dist_send: u8,
    /// Keys the peer sends in Phase 3, same negotiation.
    dist_expect: u8,
    /// True after Identity Information arrived while expecting
    /// IdKey — the next PDU must be Identity Address Information.
    got_identity: bool,
    /// Peer's distributed keys, filled as Phase 3 PDUs arrive.
    pub peer_irk: Option<[u8; 16]>,
    pub peer_identity_addr: Option<[u8; 7]>,
    pub peer_csrk: Option<[u8; 16]>,
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
            mac_key: [0; 16],
            peer_confirm: [0; 16],
            iat_addr,
            rat_addr,
            features: PairingFeatureExchange {
                io_capability: IoCapability::NoInputNoOutput as u8,
                oob_data_flag: 0,
                auth_req: AUTH_BONDING | AUTH_SC,
                max_encryption_key_size: 16,
                // Offer IdKey + Sign and request the same. The
                // negotiated set is the intersection (§3.6.1: "The
                // Peripheral shall not set to one any flag in the
                // Response that the Central has set to zero in the
                // Request"), so offering both never over-promises.
                initiator_key_distribution: DIST_SUPPORTED,
                responder_key_distribution: DIST_SUPPORTED,
            },
            peer_features: PairingFeatureExchange {
                io_capability: 0,
                oob_data_flag: 0,
                auth_req: 0,
                max_encryption_key_size: 0,
                initiator_key_distribution: 0,
                responder_key_distribution: 0,
            },
            bonded: false,
            dist_send: 0,
            dist_expect: 0,
            got_identity: false,
            peer_irk: None,
            peer_identity_addr: None,
            peer_csrk: None,
        }
    }

    /// Begin pairing — emit Pairing_Request.
    pub fn start(&mut self) -> Pdu {
        self.state = PairingState::SentRequest;
        self.features.encode(SMP_PAIRING_REQUEST)
    }

    /// Feed one incoming PDU. Returns the outgoing PDUs to send
    /// (one step emits two: Pairing_Random and the DHKey Check
    /// leave together once Nb has been verified).
    pub fn feed(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
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
            PairingState::WaitConfirm => self.on_pairing_confirm(rx),
            PairingState::WaitRandom => self.on_pairing_random(rx),
            PairingState::SentDhKeyCheck => self.on_dhkey_check(rx),
            PairingState::WaitDistribution => self.on_distribution(rx),
            // AuthComplete parks the session until the pump
            // reports encryption. A distribution PDU here is
            // nonconformant (Phase 3 needs an encrypted link) —
            // fail, do not buffer it.
            _ => Err(PairingError::Protocol),
        }
    }

    /// Start Phase 3 after the pump reports the link encrypted.
    /// The responder (Peripheral) distributes first (§3.6.1), so
    /// the initiator sends nothing yet when it still expects peer
    /// keys; when nothing is expected it sends its own PDUs and
    /// completes immediately. Only valid from AuthComplete.
    pub fn begin_distribution(&mut self) -> Vec<Pdu> {
        if self.state != PairingState::AuthComplete {
            return Vec::new();
        }
        if self.dist_expect == 0 {
            self.state = PairingState::Done;
            return own_distribution_pdus(&self.crypto, self.dist_send, &self.iat_addr);
        }
        self.state = PairingState::WaitDistribution;
        Vec::new()
    }

    fn on_distribution(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
        let complete = consume_distribution_pdu(
            &mut self.dist_expect,
            &mut self.got_identity,
            &mut self.peer_irk,
            &mut self.peer_identity_addr,
            &mut self.peer_csrk,
            rx,
        )?;
        if !complete {
            return Ok(Vec::new());
        }
        self.state = PairingState::Done;
        Ok(own_distribution_pdus(
            &self.crypto,
            self.dist_send,
            &self.iat_addr,
        ))
    }

    fn on_response(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
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

        // Negotiate bonding and Phase 3 distribution (§3.6.1).
        // Bonding requires both sides' Bonding_Flags == 01 (the
        // low two auth_req bits). Each distributed key is sent
        // only when BOTH sides set its bit: the initiator's send
        // set is its own initiator byte ∩ the peer's initiator
        // byte, its expect set its own responder byte ∩ the peer's
        // responder byte — each masked to the bits this lane
        // implements (EncKey ignored for SC, LinkKey out of scope).
        // Without bonding the distribution bytes are ignored and
        // the pairing completes at authentication, as before.
        self.bonded = (self.features.auth_req & 0x03) == 0x01 && (peer.auth_req & 0x03) == 0x01;
        if self.bonded {
            self.dist_send = self.features.initiator_key_distribution
                & peer.initiator_key_distribution
                & DIST_SUPPORTED;
            self.dist_expect = self.features.responder_key_distribution
                & peer.responder_key_distribution
                & DIST_SUPPORTED;
        }

        // Send our public key.
        let mut pk = Vec::with_capacity(64);
        pk.extend_from_slice(&self.pub_x);
        pk.extend_from_slice(&self.pub_y);
        let out = Pdu {
            code: SMP_PAIRING_PUBLIC_KEY,
            payload: pk,
        };
        self.state = PairingState::SentPublicKey;
        Ok(alloc::vec![out])
    }

    fn on_peer_public_key(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
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

        // Authentication stage 1 (§2.3.5.6.2): commit to both
        // public keys and our nonce with Ca (§2.2.6 table 2.1)
        // before Na is revealed to the responder.
        let ca = confirm_value(&self.crypto, &self.pub_x, &self.peer_pub_x, &self.na, 0);
        self.state = PairingState::WaitConfirm;
        Ok(alloc::vec![Pdu {
            code: SMP_PAIRING_CONFIRM,
            payload: ca.to_vec(),
        }])
    }

    fn on_pairing_confirm(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_CONFIRM {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        // Cb cannot be checked yet — it commits the responder to
        // Nb, which is only revealed by the next PDU.
        self.peer_confirm.copy_from_slice(&rx.payload[..16]);
        self.state = PairingState::WaitRandom;
        Ok(Vec::new())
    }

    fn on_pairing_random(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_RANDOM {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        self.nb.copy_from_slice(&rx.payload[..16]);

        // Verify Cb now that Nb is revealed (§2.2.6 table 2.1:
        // the responder's confirm takes the responder's key
        // first). A mismatch aborts the pairing — the caller
        // maps BadConfirm to Pairing Failed 0x04.
        let want_cb = confirm_value(&self.crypto, &self.peer_pub_x, &self.pub_x, &self.nb, 0);
        if self.peer_confirm != want_cb {
            self.state = PairingState::Failed;
            return Err(PairingError::BadConfirm);
        }

        // Derive MacKey + LTK via f5 (§2.2.7).
        let (mac_key, ltk) = derive_mac_key_and_ltk(
            &self.crypto,
            &self.dh_key,
            &self.na,
            &self.nb,
            &self.iat_addr,
            &self.rat_addr,
        );
        self.mac_key = mac_key;
        self.ltk = ltk;

        // Authentication stage 2 (§2.3.5.6.5): our DHKey Check
        // Ea leaves with Na. Ea = f6(MacKey, Na, Nb, 0, IOcapA,
        // A, B) per §2.2.8 table 2.2.
        let ea = dhkey_check_value(
            &self.crypto,
            &self.mac_key,
            &DhKeyCheckInputs {
                n1: &self.na,
                n2: &self.nb,
                r: &[0u8; 16],
                iocap: &iocap_bytes(&self.features),
                a1: &self.iat_addr,
                a2: &self.rat_addr,
            },
        );
        self.state = PairingState::SentDhKeyCheck;
        Ok(alloc::vec![
            Pdu {
                code: SMP_PAIRING_RANDOM,
                payload: self.na.to_vec(),
            },
            Pdu {
                code: SMP_PAIRING_DHKEY_CHECK,
                payload: ea.to_vec(),
            },
        ])
    }

    fn on_dhkey_check(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_DHKEY_CHECK {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        // Verify Eb = f6(MacKey, Nb, Na, 0, IOcapB, B, A)
        // (§2.2.8 table 2.2) — the responder's form swaps both
        // the nonce order and the address order. A mismatch
        // aborts the pairing (Pairing Failed 0x0B at the caller).
        let want_eb = dhkey_check_value(
            &self.crypto,
            &self.mac_key,
            &DhKeyCheckInputs {
                n1: &self.nb,
                n2: &self.na,
                r: &[0u8; 16],
                iocap: &iocap_bytes(&self.peer_features),
                a1: &self.rat_addr,
                a2: &self.iat_addr,
            },
        );
        if rx.payload[..16] != want_eb[..] {
            self.state = PairingState::Failed;
            return Err(PairingError::BadDhKeyCheck);
        }
        // Authentication is complete. With negotiated distribution
        // keys the session parks at AuthComplete until the pump
        // reports encryption (Phase 3 needs an encrypted link);
        // otherwise pairing completes here, as before.
        if self.bonded && (self.dist_send != 0 || self.dist_expect != 0) {
            self.state = PairingState::AuthComplete;
        } else {
            self.state = PairingState::Done;
        }
        Ok(Vec::new())
    }
}

// ── Numeric Comparison g2 helper (§2.2.9) ──────────────────────────

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
    // Per §2.2.9, take the low 32 bits big-endian of the MAC and
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
    WaitDhKeyCheck,
    /// Authentication (Phase 2) completed and keys are negotiated
    /// for distribution, but the link is not yet encrypted. Same
    /// parking state as [`PairingState::AuthComplete`]: the pump
    /// calls [`Responder::begin_distribution`] once encryption is
    /// reported. A responder at AuthComplete whose LTK Request
    /// arrives first is answered from the session itself (the bond
    /// is stored only when distribution finishes).
    AuthComplete,
    /// Our side's distribution PDUs (if any) are sent and the
    /// peer's are still arriving. [`Responder::on_distribution`]
    /// consumes them in §3.6.1 order.
    WaitDistribution,
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
    /// MacKey half of f5 — keys the f6 DHKey checks.
    pub mac_key: [u8; 16],
    /// Peer's confirm value Ca (captured from Pairing_Confirm).
    peer_confirm: [u8; 16],
    iat_addr: [u8; 7],
    rat_addr: [u8; 7],
    features_local: PairingFeatureExchange,
    features_peer: PairingFeatureExchange,
    /// Numeric Comparison value (only meaningful when method ==
    /// NumericComparison). Application surfaces this to the user
    /// for confirmation.
    pub numeric_comparison: Option<u32>,
    /// True when both sides negotiated bonding (both Bonding_Flags
    /// == 01). Same rule as [`Initiator::bonded`].
    pub bonded: bool,
    /// Keys this side sends in Phase 3, negotiated as (own byte) ∩
    /// (peer byte) masked to [`DIST_SUPPORTED`].
    dist_send: u8,
    /// Keys the peer sends in Phase 3, same negotiation.
    dist_expect: u8,
    /// True after Identity Information arrived while expecting
    /// IdKey — the next PDU must be Identity Address Information.
    got_identity: bool,
    /// Peer's distributed keys, filled as Phase 3 PDUs arrive.
    pub peer_irk: Option<[u8; 16]>,
    pub peer_identity_addr: Option<[u8; 7]>,
    pub peer_csrk: Option<[u8; 16]>,
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
            mac_key: [0; 16],
            peer_confirm: [0; 16],
            iat_addr,
            rat_addr,
            features_local: PairingFeatureExchange {
                io_capability: IoCapability::DisplayYesNo as u8,
                oob_data_flag: 0,
                auth_req: AUTH_BONDING | AUTH_SC | AUTH_MITM,
                max_encryption_key_size: 16,
                // Same offer as the initiator: IdKey + Sign, both
                // directions. The negotiated set is the
                // intersection, so this never over-promises.
                initiator_key_distribution: DIST_SUPPORTED,
                responder_key_distribution: DIST_SUPPORTED,
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
            bonded: false,
            dist_send: 0,
            dist_expect: 0,
            got_identity: false,
            peer_irk: None,
            peer_identity_addr: None,
            peer_csrk: None,
        }
    }

    pub fn feed(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
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
            ResponderState::SentPublicKey => self.on_pairing_confirm(rx),
            ResponderState::SentRandom => self.on_pairing_random(rx),
            ResponderState::WaitDhKeyCheck => self.on_dhkey_check(rx),
            ResponderState::WaitDistribution => self.on_distribution(rx),
            // AuthComplete parks the session until the pump
            // reports encryption; a distribution PDU here is
            // nonconformant — fail, do not buffer it.
            _ => Err(PairingError::Protocol),
        }
    }

    /// Start Phase 3 after the pump reports the link encrypted.
    /// The responder (Peripheral) distributes first (§3.6.1), so
    /// its own PDUs always leave here; when nothing is expected
    /// back the pairing completes immediately, otherwise it parks
    /// in WaitDistribution for the initiator's PDUs. Only valid
    /// from AuthComplete.
    pub fn begin_distribution(&mut self) -> Vec<Pdu> {
        if self.state != ResponderState::AuthComplete {
            return Vec::new();
        }
        let out = own_distribution_pdus(&self.crypto, self.dist_send, &self.rat_addr);
        if self.dist_expect == 0 {
            self.state = ResponderState::Done;
        } else {
            self.state = ResponderState::WaitDistribution;
        }
        out
    }

    fn on_distribution(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
        let complete = consume_distribution_pdu(
            &mut self.dist_expect,
            &mut self.got_identity,
            &mut self.peer_irk,
            &mut self.peer_identity_addr,
            &mut self.peer_csrk,
            rx,
        )?;
        if !complete {
            return Ok(Vec::new());
        }
        self.state = ResponderState::Done;
        Ok(Vec::new())
    }

    fn on_request(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
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

        // Negotiate bonding and Phase 3 distribution (§3.6.1),
        // mirrored from the initiator side: the responder's send
        // set is its own responder byte ∩ the peer's responder
        // byte, its expect set its own initiator byte ∩ the peer's
        // initiator byte — each masked to DIST_SUPPORTED. Without
        // bonding the distribution bytes are ignored.
        self.bonded =
            (peer.auth_req & 0x03) == 0x01 && (self.features_local.auth_req & 0x03) == 0x01;
        if self.bonded {
            self.dist_send = self.features_local.responder_key_distribution
                & peer.responder_key_distribution
                & DIST_SUPPORTED;
            self.dist_expect = self.features_local.initiator_key_distribution
                & peer.initiator_key_distribution
                & DIST_SUPPORTED;
        }

        let rsp = self.features_local.encode(SMP_PAIRING_RESPONSE);
        self.state = ResponderState::GotRequest;
        Ok(alloc::vec![rsp])
    }

    fn on_initiator_public_key(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
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
        Ok(alloc::vec![out])
    }

    fn on_pairing_confirm(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_CONFIRM {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        self.peer_confirm.copy_from_slice(&rx.payload[..16]);

        // Commit Cb and reveal Nb together (§2.3.5.6.2). Our
        // confirm takes our own key first (§2.2.6 table 2.1).
        // Ca itself is verified when Na arrives — a commitment
        // cannot be checked before its nonce is revealed.
        let cb = confirm_value(&self.crypto, &self.pub_x, &self.peer_pub_x, &self.nb, 0);
        self.state = ResponderState::SentRandom;
        Ok(alloc::vec![
            Pdu {
                code: SMP_PAIRING_CONFIRM,
                payload: cb.to_vec(),
            },
            Pdu {
                code: SMP_PAIRING_RANDOM,
                payload: self.nb.to_vec(),
            },
        ])
    }

    fn on_pairing_random(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_RANDOM {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        self.na.copy_from_slice(&rx.payload[..16]);

        // Verify the initiator's commitment Ca now that Na is
        // revealed (§2.2.6 table 2.1: Ca takes the initiator's
        // key first). A mismatch aborts the pairing — the caller
        // maps BadConfirm to Pairing Failed 0x04.
        let want_ca = confirm_value(&self.crypto, &self.peer_pub_x, &self.pub_x, &self.na, 0);
        if self.peer_confirm != want_ca {
            self.state = ResponderState::Failed;
            return Err(PairingError::BadConfirm);
        }

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

        // Derive MacKey + LTK via f5 (§2.2.7).
        let (mac_key, ltk) = derive_mac_key_and_ltk(
            &self.crypto,
            &self.dh_key,
            &self.na,
            &self.nb,
            &self.iat_addr,
            &self.rat_addr,
        );
        self.mac_key = mac_key;
        self.ltk = ltk;

        self.state = ResponderState::WaitDhKeyCheck;
        Ok(Vec::new())
    }

    fn on_dhkey_check(&mut self, rx: &Pdu) -> Result<Vec<Pdu>, PairingError> {
        if rx.code != SMP_PAIRING_DHKEY_CHECK {
            return Err(PairingError::Protocol);
        }
        if rx.payload.len() < 16 {
            return Err(PairingError::Protocol);
        }
        // Verify Ea = f6(MacKey, Na, Nb, 0, IOcapA, A, B)
        // (§2.2.8 table 2.2). A mismatch aborts the pairing
        // (Pairing Failed 0x0B at the caller).
        let want_ea = dhkey_check_value(
            &self.crypto,
            &self.mac_key,
            &DhKeyCheckInputs {
                n1: &self.na,
                n2: &self.nb,
                r: &[0u8; 16],
                iocap: &iocap_bytes(&self.features_peer),
                a1: &self.iat_addr,
                a2: &self.rat_addr,
            },
        );
        if rx.payload[..16] != want_ea[..] {
            self.state = ResponderState::Failed;
            return Err(PairingError::BadDhKeyCheck);
        }
        // Answer with Eb — the swapped form (§2.2.8 table 2.2).
        let eb = dhkey_check_value(
            &self.crypto,
            &self.mac_key,
            &DhKeyCheckInputs {
                n1: &self.nb,
                n2: &self.na,
                r: &[0u8; 16],
                iocap: &iocap_bytes(&self.features_local),
                a1: &self.rat_addr,
                a2: &self.iat_addr,
            },
        );
        // Authentication is complete. With negotiated distribution
        // keys the session parks at AuthComplete until the pump
        // reports encryption; otherwise pairing completes here.
        if self.bonded && (self.dist_send != 0 || self.dist_expect != 0) {
            self.state = ResponderState::AuthComplete;
        } else {
            self.state = ResponderState::Done;
        }
        Ok(alloc::vec![Pdu {
            code: SMP_PAIRING_DHKEY_CHECK,
            payload: eb.to_vec(),
        }])
    }
}
