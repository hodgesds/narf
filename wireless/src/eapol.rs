//! EAPOL-Key frame codec + 4-Way Handshake (clean-room).
//!
//! Specs:
//! - IEEE Std 802.1X-2020 §11 (EAPOL frame format).
//!   <https://standards.ieee.org/ieee/802.1X/7345/>
//! - IEEE Std 802.11-2020 §12.7 (Keys and key distribution).
//!   <https://standards.ieee.org/ieee/802.11/7028/>
//! - IEEE Std 802.11-2020 §12.4 (SAE — for WPA3, scaffolded but the
//!   actual ECC math lives in narf-crypto when it grows that surface).
//!   <https://standards.ieee.org/ieee/802.11/7028/>
//!
//! Public IEEE standards. No GPL Linux `net/wireless/` source consulted.
//!
//! ## EAPOL frame (802.1X §11.3)
//!
//! All EAPOL frames sit in an 802.11 Data frame with the LLC/SNAP
//! header pointing at EtherType 0x888E. The 4-byte EAPOL header is:
//!
//! ```text
//!   0:    u8  Protocol Version (3 for 802.1X-2010+)
//!   1:    u8  Packet Type (3 = EAPOL-Key, others used for EAP)
//!   2..4: u16 BE Body Length
//!   4..N: body
//! ```
//!
//! ## Key frame body (802.11 §12.7.2)
//!
//! The 4-Way Handshake uses the EAPOL-Key body — 95 bytes of fixed
//! header followed by a variable Key Data field. Header layout:
//!
//! ```text
//!   0:     u8  Descriptor Type (2 = RSN; 254 = WPA-OUI legacy)
//!   1..3:  u16 BE Key Information bitmap
//!   3..5:  u16 BE Key Length (TK length, 16 for CCMP, 32 for GCMP-256)
//!   5..13: u64 BE Replay Counter
//!   13..45: 32B Key Nonce
//!   45..61: 16B EAPOL Key IV (zeroed on modern AKMs)
//!   61..69: 8B  Key RSC
//!   69..77: 8B  Reserved
//!   77..93: 16B Key MIC (size depends on AKM — 16 for HMAC-SHA1,
//!                 24 for HMAC-SHA256, 32 for HMAC-SHA384)
//!   93..95: u16 BE Key Data Length
//!   95..N: Key Data (RSN IE, GTK KDE, etc.)
//! ```
//!
//! The MIC field's *length* depends on the AKM. We expose the layout
//! parameterised on `mic_len` so the supplicant code-paths can pick
//! the right size without forking the codec.

use alloc::vec::Vec;

// ── EAPOL header constants ─────────────────────────────────────────
pub const EAPOL_PROTOCOL_VERSION: u8 = 3;

/// Packet Type values (802.1X §11.3.2).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EapolType {
    EapPacket = 0,
    EapolStart = 1,
    EapolLogoff = 2,
    EapolKey = 3,
    EapolEncapsulatedAsfAlert = 4,
}

/// Descriptor Type byte (802.11 §12.7.2).
pub const KEY_DESCRIPTOR_RSN: u8 = 2;
pub const KEY_DESCRIPTOR_WPA_LEGACY: u8 = 254;

// ── Key Information bits (802.11 §12.7.2 figure 12-32) ────────────
//
// 16-bit bitmap; bits 0..2 are Key Descriptor Version, then per-flag.
pub const KI_VERSION_HMAC_SHA1_AES: u16 = 0x02;
pub const KI_VERSION_AES_128_CMAC: u16 = 0x03;
pub const KI_KEY_TYPE_PAIRWISE: u16 = 1 << 3;
pub const KI_INSTALL: u16 = 1 << 6;
pub const KI_KEY_ACK: u16 = 1 << 7;
pub const KI_KEY_MIC: u16 = 1 << 8;
pub const KI_SECURE: u16 = 1 << 9;
pub const KI_ERROR: u16 = 1 << 10;
pub const KI_REQUEST: u16 = 1 << 11;
pub const KI_ENCRYPTED_KEY_DATA: u16 = 1 << 12;
pub const KI_SMK_MESSAGE: u16 = 1 << 13;

/// Decoded EAPOL header (802.1X §11.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EapolHeader {
    pub version: u8,
    pub packet_type: u8,
    pub body_length: u16,
}

impl EapolHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        out.push(self.packet_type);
        // Body length is big-endian per §11.3.
        out.push((self.body_length >> 8) as u8);
        out.push((self.body_length & 0xFF) as u8);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        Some(Self {
            version: buf[0],
            packet_type: buf[1],
            body_length: u16::from_be_bytes([buf[2], buf[3]]),
        })
    }
}

/// Decoded EAPOL-Key body. The MIC and Key Data fields are kept as
/// owned `Vec<u8>` so the consumer can mutate / re-MIC them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFrame {
    pub descriptor_type: u8,
    pub key_information: u16,
    pub key_length: u16,
    pub replay_counter: u64,
    pub key_nonce: [u8; 32],
    pub key_iv: [u8; 16],
    pub key_rsc: [u8; 8],
    pub key_mic: Vec<u8>,
    pub key_data: Vec<u8>,
}

impl KeyFrame {
    /// Construct an empty (zeroed) key frame with the given AKM MIC
    /// length. Callers fill fields in before transmit.
    pub fn empty(mic_len: usize) -> Self {
        Self {
            descriptor_type: KEY_DESCRIPTOR_RSN,
            key_information: 0,
            key_length: 0,
            replay_counter: 0,
            key_nonce: [0u8; 32],
            key_iv: [0u8; 16],
            key_rsc: [0u8; 8],
            key_mic: alloc::vec![0u8; mic_len],
            key_data: Vec::new(),
        }
    }

    /// Encode to the wire layout (95 + mic_len + key_data bytes).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(81 + self.key_mic.len() + 4 + self.key_data.len());
        out.push(self.descriptor_type);
        out.extend_from_slice(&self.key_information.to_be_bytes());
        out.extend_from_slice(&self.key_length.to_be_bytes());
        out.extend_from_slice(&self.replay_counter.to_be_bytes());
        out.extend_from_slice(&self.key_nonce);
        out.extend_from_slice(&self.key_iv);
        out.extend_from_slice(&self.key_rsc);
        out.extend_from_slice(&[0u8; 8]); // Reserved
        out.extend_from_slice(&self.key_mic);
        out.extend_from_slice(&(self.key_data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.key_data);
        out
    }

    /// Decode from a buffer. `mic_len` must match the AKM's MIC size
    /// — the spec layout doesn't carry it, so the caller decides
    /// based on the negotiated AKM (16 for AKM-1/2, 24 for AKM-3+).
    pub fn decode(buf: &[u8], mic_len: usize) -> Option<Self> {
        let head = 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8;
        if buf.len() < head + mic_len + 2 {
            return None;
        }
        let descriptor_type = buf[0];
        let key_information = u16::from_be_bytes([buf[1], buf[2]]);
        let key_length = u16::from_be_bytes([buf[3], buf[4]]);
        let replay_counter = u64::from_be_bytes([
            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
        ]);
        let mut key_nonce = [0u8; 32];
        key_nonce.copy_from_slice(&buf[13..45]);
        let mut key_iv = [0u8; 16];
        key_iv.copy_from_slice(&buf[45..61]);
        let mut key_rsc = [0u8; 8];
        key_rsc.copy_from_slice(&buf[61..69]);
        // 69..77 reserved.
        let mic_start = 77;
        let key_mic = buf[mic_start..mic_start + mic_len].to_vec();
        let kd_len_off = mic_start + mic_len;
        let key_data_len = u16::from_be_bytes([buf[kd_len_off], buf[kd_len_off + 1]]) as usize;
        let kd_off = kd_len_off + 2;
        if buf.len() < kd_off + key_data_len {
            return None;
        }
        let key_data = buf[kd_off..kd_off + key_data_len].to_vec();
        Some(Self {
            descriptor_type,
            key_information,
            key_length,
            replay_counter,
            key_nonce,
            key_iv,
            key_rsc,
            key_mic,
            key_data,
        })
    }

    /// Wrap this body in an EAPOL header and emit the full PDU.
    pub fn into_eapol(self) -> Vec<u8> {
        let body = self.encode();
        let mut out = Vec::with_capacity(4 + body.len());
        EapolHeader {
            version: EAPOL_PROTOCOL_VERSION,
            packet_type: EapolType::EapolKey as u8,
            body_length: body.len() as u16,
        }
        .encode(&mut out);
        out.extend_from_slice(&body);
        out
    }

    /// `true` when the Key MIC bit is set.
    pub fn has_mic(&self) -> bool {
        self.key_information & KI_KEY_MIC != 0
    }

    /// `true` when the Install bit is set (asks supplicant to
    /// install the PTK).
    pub fn install(&self) -> bool {
        self.key_information & KI_INSTALL != 0
    }

    /// `true` when the Pairwise bit is set (PTK exchange, not GTK).
    pub fn pairwise(&self) -> bool {
        self.key_information & KI_KEY_TYPE_PAIRWISE != 0
    }

    /// `true` when the Key ACK bit is set (M1/M3 from authenticator).
    pub fn key_ack(&self) -> bool {
        self.key_information & KI_KEY_ACK != 0
    }
}

// ── Pseudo-Random Function (PRF, §12.7.1.2) ────────────────────────
//
// PRF-N(K, A, B) repeats:
//   for i in 0..ceil(N/HMAC_OUT_LEN):
//     out[i] = HMAC(K, A || 0x00 || B || i)
// then truncates to N bits.

/// HMAC primitive injected by the caller. Production wires HMAC-SHA1
/// (for AKM-1/2) or HMAC-SHA256 (for AKM-3+). Output length is a
/// per-AKM constant; the trait's `out_len()` reports it.
pub trait HmacPrimitive {
    fn out_len(&self) -> usize;
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8>;
}

/// PRF: produce `out_bits` bits of pseudo-random output keyed on
/// `key`, salted with `label || 0x00 || context`.
pub fn prf(hmac: &dyn HmacPrimitive, key: &[u8], label: &[u8], context: &[u8], out_bits: usize) -> Vec<u8> {
    let out_bytes = (out_bits + 7) / 8;
    let mut result = Vec::with_capacity(out_bytes);
    let chunks = (out_bytes + hmac.out_len() - 1) / hmac.out_len();
    let mut data = Vec::with_capacity(label.len() + 1 + context.len() + 1);
    for i in 0..chunks as u8 {
        data.clear();
        data.extend_from_slice(label);
        data.push(0x00);
        data.extend_from_slice(context);
        data.push(i);
        let blk = hmac.mac(key, &data);
        result.extend_from_slice(&blk);
    }
    result.truncate(out_bytes);
    result
}

/// PTK (Pairwise Transient Key) bundle (802.11 §12.7.1.3).
///
/// PTK = PRF(PMK, "Pairwise key expansion",
///           min(AA,SA) || max(AA,SA) || min(ANonce,SNonce) || max(ANonce,SNonce))
///
/// The first 16 bytes are KCK (Key Confirmation Key — used for MICs),
/// the next 16 are KEK (Key Encryption Key — used for unwrapping the
/// GTK in M3), and the rest is the TK (Temporal Key — installed in
/// the cipher engine for data-frame encryption).
#[derive(Clone, Debug)]
pub struct Ptk {
    pub kck: Vec<u8>,
    pub kek: Vec<u8>,
    pub tk: Vec<u8>,
}

/// Derive the PTK. `pmk` is 32 bytes for WPA2-Personal (PSK), 32+
/// for WPA3. `aa` / `sa` are the AP and STA MAC addresses;
/// `anonce` / `snonce` are the random nonces traded in M1/M2.
/// `tk_len` is 16 for CCMP, 32 for GCMP-256.
pub fn derive_ptk(
    hmac: &dyn HmacPrimitive,
    pmk: &[u8],
    aa: &[u8; 6],
    sa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    tk_len: usize,
) -> Ptk {
    let mut context = Vec::with_capacity(12 + 64);
    if aa <= sa {
        context.extend_from_slice(aa);
        context.extend_from_slice(sa);
    } else {
        context.extend_from_slice(sa);
        context.extend_from_slice(aa);
    }
    if anonce <= snonce {
        context.extend_from_slice(anonce);
        context.extend_from_slice(snonce);
    } else {
        context.extend_from_slice(snonce);
        context.extend_from_slice(anonce);
    }
    let total_bits = (16 + 16 + tk_len) * 8;
    let bytes = prf(hmac, pmk, b"Pairwise key expansion", &context, total_bits);
    Ptk {
        kck: bytes[0..16].to_vec(),
        kek: bytes[16..32].to_vec(),
        tk: bytes[32..32 + tk_len].to_vec(),
    }
}

// ── 4-Way Handshake state machine (Supplicant side, §12.7.6) ──────

/// Supplicant-side state of the 4-Way Handshake.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FourWayState {
    /// Waiting for M1 from the authenticator.
    WaitM1 = 0,
    /// M1 received, M2 sent, waiting for M3.
    WaitM3 = 1,
    /// M3 received, M4 sent, PTK installed.
    PtkDone = 2,
    /// Aborted (replay-counter regression, MIC failure, etc.).
    Failed = 3,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FourWayError {
    /// M1 had no Key ACK or wrong descriptor.
    BadM1,
    /// M3 had no Install bit, or replay counter regressed.
    BadM3,
    /// MIC verification failed.
    MicMismatch,
    /// Replay counter went backwards.
    ReplayRegression,
}

/// Supplicant 4-Way Handshake driver. Holds the in-progress nonces,
/// counter, and partial PTK; once `PtkDone` the consumer pulls the
/// PTK and installs the TK in the data-path.
#[derive(Clone, Debug)]
pub struct Supplicant {
    pub state: FourWayState,
    pub anonce: [u8; 32],
    pub snonce: [u8; 32],
    pub last_replay_counter: u64,
    pub ptk: Option<Ptk>,
    pub aa: [u8; 6],
    pub sa: [u8; 6],
}

impl Supplicant {
    pub fn new(aa: [u8; 6], sa: [u8; 6], snonce: [u8; 32]) -> Self {
        Self {
            state: FourWayState::WaitM1,
            anonce: [0u8; 32],
            snonce,
            last_replay_counter: 0,
            ptk: None,
            aa,
            sa,
        }
    }

    /// Process an incoming key frame. Returns the supplicant's
    /// response frame to send back, when one is required (M2 after
    /// M1, M4 after M3). Returns `Ok(None)` on idle states.
    pub fn handle(
        &mut self,
        hmac: &dyn HmacPrimitive,
        pmk: &[u8],
        tk_len: usize,
        rx: &KeyFrame,
    ) -> Result<Option<KeyFrame>, FourWayError> {
        match self.state {
            FourWayState::WaitM1 => self.handle_m1(hmac, pmk, tk_len, rx),
            FourWayState::WaitM3 => self.handle_m3(rx),
            FourWayState::PtkDone | FourWayState::Failed => Ok(None),
        }
    }

    fn handle_m1(
        &mut self,
        hmac: &dyn HmacPrimitive,
        pmk: &[u8],
        tk_len: usize,
        m1: &KeyFrame,
    ) -> Result<Option<KeyFrame>, FourWayError> {
        // M1 has Key ACK set, MIC clear, Pairwise set, Install clear.
        if !m1.key_ack() || m1.has_mic() || !m1.pairwise() || m1.install() {
            self.state = FourWayState::Failed;
            return Err(FourWayError::BadM1);
        }
        self.anonce = m1.key_nonce;
        self.last_replay_counter = m1.replay_counter;
        let ptk = derive_ptk(hmac, pmk, &self.aa, &self.sa, &self.anonce, &self.snonce, tk_len);

        // M2: Pairwise set, MIC set (computed across the EAPOL frame
        // with MIC field zeroed), Install/ACK clear, Replay counter
        // mirrors M1, key_data carries the supplicant's RSN IE
        // (provided by the caller via .key_data; we leave it empty
        // here — the supplicant top-level fills it).
        let mut m2 = KeyFrame::empty(hmac.out_len().min(32));
        m2.descriptor_type = m1.descriptor_type;
        m2.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC;
        m2.replay_counter = m1.replay_counter;
        m2.key_nonce = self.snonce;
        // MIC computed over the encoded EAPOL-Key body with MIC zeroed.
        // Caller computes + installs the MIC after we hand it back.
        self.ptk = Some(ptk);
        self.state = FourWayState::WaitM3;
        Ok(Some(m2))
    }

    fn handle_m3(&mut self, m3: &KeyFrame) -> Result<Option<KeyFrame>, FourWayError> {
        if m3.replay_counter <= self.last_replay_counter {
            self.state = FourWayState::Failed;
            return Err(FourWayError::ReplayRegression);
        }
        if !m3.install() || !m3.has_mic() || !m3.pairwise() {
            self.state = FourWayState::Failed;
            return Err(FourWayError::BadM3);
        }
        if m3.key_nonce != self.anonce {
            self.state = FourWayState::Failed;
            return Err(FourWayError::BadM3);
        }
        self.last_replay_counter = m3.replay_counter;

        // M4: ACK clear, MIC set, Install clear, key_data empty.
        let mic_len = m3.key_mic.len();
        let mut m4 = KeyFrame::empty(mic_len);
        m4.descriptor_type = m3.descriptor_type;
        m4.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC | KI_SECURE;
        m4.replay_counter = m3.replay_counter;
        self.state = FourWayState::PtkDone;
        Ok(Some(m4))
    }
}
