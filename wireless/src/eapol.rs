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

mod rsna;
pub use rsna::{
    key_ver_allowed, wpa_eapol_key_mic, wpa_pmk_to_ptk, EapolRx, EapolRxError, KeyMgmt,
    PairwiseFail, PairwiseM1, PairwiseM3, RsnaParams, KI_VERSION_AKM_DEFINED,
    WLAN_REASON_IE_IN_4WAY_DIFFERS,
};

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
/// Key Information bits 2:0 — Key Descriptor Version.
pub const KI_VERSION_MASK: u16 = 0x0007;
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
pub fn prf(
    hmac: &dyn HmacPrimitive,
    key: &[u8],
    label: &[u8],
    context: &[u8],
    out_bits: usize,
) -> Vec<u8> {
    let out_bytes = out_bits.div_ceil(8);
    let mut result = Vec::with_capacity(out_bytes);
    let chunks = out_bytes.div_ceil(hmac.out_len());
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
    /// `sm->rx_replay_counter_set`: a MIC-verified frame set
    /// [`Supplicant::last_replay_counter`].
    pub rx_replay_counter_set: bool,
    /// The GTK / IGTK in use (`sm->gtk` / `sm->igtk`), for the
    /// key-reinstallation check.
    pub gtk: Option<Vec<u8>>,
    pub igtk: Option<Vec<u8>>,
    /// The negotiated AKM (`sm->key_mgmt`); PSK unless [`Self::with_rsna`].
    pub key_mgmt: KeyMgmt,
    /// The association's RSN parameters ([`Self::with_rsna`]).
    pub rsna: Option<RsnaParams>,
    /// `sm->tptk`: the PTK derived from the last message 1/4, until a
    /// message 3/4 MIC verifies with it.
    pub tptk: Option<Ptk>,
    /// `sm->renew_snonce`.
    pub renew_snonce: bool,
    /// `sm->ptk.installed`.
    pub ptk_installed: bool,
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
            rx_replay_counter_set: false,
            gtk: None,
            igtk: None,
            key_mgmt: KeyMgmt::Psk,
            rsna: None,
            tptk: None,
            renew_snonce: false,
            ptk_installed: false,
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
        let ptk = derive_ptk(
            hmac,
            pmk,
            &self.aa,
            &self.sa,
            &self.anonce,
            &self.snonce,
            tk_len,
        );

        // M2: Pairwise set, MIC set (computed across the EAPOL frame
        // with MIC field zeroed), Install/ACK clear, Replay counter
        // mirrors M1, key_data carries the supplicant's RSN IE
        // (provided by the caller via .key_data; we leave it empty
        // here — the supplicant top-level fills it).
        //
        // The Key MIC field length is the AKM's (IEEE 802.11-2020
        // Table 12-11: 16 for AKM 1/2, HMAC-SHA1-128 truncated), not
        // the HMAC output length (20 for SHA-1). The caller decoded M1
        // with that length, so mirror it — wpa_supplicant uses
        // `wpa_mic_len(akmp)` the same way. The Key Descriptor Version
        // (Key Information bits 2:0) is echoed from M1, as
        // `wpa_supplicant_send_2_of_4` does via `ver`.
        let mut m2 = KeyFrame::empty(m1.key_mic.len());
        m2.descriptor_type = m1.descriptor_type;
        m2.key_information =
            (m1.key_information & KI_VERSION_MASK) | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC;
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
        // The caller verified M3's MIC (wpa_supplicant_verify_eapol_key_mic
        // records the counter).
        self.last_replay_counter = m3.replay_counter;
        self.rx_replay_counter_set = true;

        // M4: ACK clear, MIC set, Install clear, key_data empty.
        let mic_len = m3.key_mic.len();
        let mut m4 = KeyFrame::empty(mic_len);
        m4.descriptor_type = m3.descriptor_type;
        m4.key_information =
            (m3.key_information & KI_VERSION_MASK) | KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC | KI_SECURE;
        m4.replay_counter = m3.replay_counter;
        self.state = FourWayState::PtkDone;
        Ok(Some(m4))
    }
}

// ── Group Key Handshake (Supplicant side, IEEE 802.11-2020 §12.7.7) ──
//
// The supplicant half of wpa_supplicant's `wpa_sm_rx_eapol` for a
// group-key frame after the 4-Way Handshake, then
// `wpa_supplicant_process_1_of_2` / `wpa_supplicant_rsn_process_1_of_2`
// and `wpa_supplicant_send_2_of_2` (hostap `src/rsn_supp/wpa.c`), with
// the Key Data parsed by the rules of `wpa_parse_kde_ies`
// (`src/common/wpa_common.c`). RSN only (no WPA1, no FILS / AEAD AKMs,
// no OCV, no MLO).

/// `wpa_eapol_key_mic` for the Key Descriptor Versions a PSK / 802.1X
/// AKM uses: HMAC-SHA1-128 (version 2) and AES-128-CMAC (version 3),
/// truncated to `mic_len`. `None` for any other version or a KCK of the
/// wrong length.
pub fn eapol_key_mic(ver: u16, kck: &[u8], pdu: &[u8], mic_len: usize) -> Option<Vec<u8>> {
    match ver {
        KI_VERSION_HMAC_SHA1_AES if mic_len <= 20 => {
            Some(narf_crypto::pbkdf2_sha1::hmac_sha1(kck, pdu)[..mic_len].to_vec())
        }
        KI_VERSION_AES_128_CMAC if mic_len <= 16 => {
            let k: &[u8; 16] = kck.try_into().ok()?;
            Some(narf_crypto::cmac_aes128::cmac_aes128_truncated(
                k, pdu, mic_len,
            ))
        }
        _ => None,
    }
}

/// Key Information bits 5:4 — Key Index (`WPA_KEY_INFO_KEY_INDEX_MASK`).
pub const KI_KEY_INDEX_MASK: u16 = 0x0030;
/// `WPA_KEY_INFO_TYPE_HMAC_MD5_RC4`.
pub const KI_VERSION_HMAC_MD5_RC4: u16 = 0x01;
/// wpa_supplicant's `DEFAULT_EAPOL_VERSION` (the 802.1X version of the
/// frames it sends).
pub const WPAS_EAPOL_VERSION: u8 = 1;
/// `WPA_GTK_MAX_LEN`.
pub const WPA_GTK_MAX_LEN: usize = 32;
/// `WPA_IGTK_KDE_PREFIX_LEN` (Key ID 2 + IPN 6).
pub const WPA_IGTK_KDE_PREFIX_LEN: usize = 8;
/// `RSN_KEY_DATA_GROUPKEY` / `RSN_KEY_DATA_IGTK` (00-0F-AC:1 / :9).
const KDE_GROUPKEY: [u8; 4] = [0x00, 0x0F, 0xAC, 1];
const KDE_IGTK: [u8; 4] = [0x00, 0x0F, 0xAC, 9];

/// Why a frame was dropped without an answer (wpa_supplicant `goto out`
/// in `wpa_sm_rx_eapol`; the association stays).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GroupKeyDrop {
    /// Shorter than an EAPOL-Key frame.
    TooShort,
    /// Not an EAPOL-Key frame.
    NotKey,
    /// Body length larger than the frame or smaller than the key header.
    BadLength,
    /// Descriptor Type is not RSN.
    BadDescriptor,
    /// Key Data Length past the body.
    KeyDataOverflow,
    /// "EAPOL-Key Replay Counter did not increase".
    Replay,
    /// SMK bit.
    Smk,
    /// No Key Ack.
    NoAck,
    /// Request bit.
    Request,
    /// Key Descriptor Version not 2 (or the CCMP interop version 3).
    BadVersion,
    /// A pairwise frame (PTK rekey: not handled here).
    Pairwise,
    /// "EAPOL-Key (Group) without Mic/Encr bit".
    NoMic,
    /// "Invalid EAPOL-Key MIC" / no PTK to verify it with.
    BadMic,
    /// Encrypted Key Data without the MIC bit.
    EncryptedUnauthenticated,
    /// "Unsupported AES-WRAP len" / "AES unwrap failed".
    Decrypt,
    /// "Discard unencrypted EAPOL-Key msg 1/4 when TK is set and PMF is
    /// enabled".
    Unencrypted,
    /// "Discard EAPOL-Key msg 1/4 with invalid IEs/KDEs".
    KeyData,
}

/// Why `process_1_of_2` failed: wpa_supplicant then deauthenticates
/// with `WLAN_REASON_UNSPECIFIED` (`wpa_sm_deauthenticate`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GroupKeyFail {
    /// "Group Key Handshake started prior to completion of 4-way".
    Before4Way,
    /// Key Data underflow (`wpa_parse_kde_ies` returned -1).
    KeyData,
    /// "GTK KDE in unencrypted key data".
    GtkUnencrypted,
    /// "No GTK KDE in Group Key msg 1/2".
    NoGtk,
    /// "Invalid GTK KDE length".
    GtkKdeLength,
    /// `wpa_supplicant_check_group_cipher`: key length ≠ the cipher's.
    GtkCipherLength,
}

/// A group-key frame was not processed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GroupKeyError {
    Drop(GroupKeyDrop),
    Fail(GroupKeyFail),
}

/// A GTK to install (`struct wpa_gtk_data` + the RSC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gtk {
    pub key_id: u8,
    /// The KDE's Tx bit after `wpa_supplicant_gtk_tx_bit_workaround`
    /// (always false with a pairwise key).
    pub tx: bool,
    pub key: Vec<u8>,
    /// Key RSC of the message (`key_rsc_len` = 6 for CCMP / GCMP).
    pub rsc: [u8; 8],
}

/// An IGTK to install (`struct wpa_igtk_kde`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igtk {
    pub key_id: u16,
    pub ipn: [u8; 6],
    pub key: Vec<u8>,
}

/// A processed Group Key message 1/2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyM1 {
    /// The GTK to install; `None` when it is the GTK already in use
    /// ("Not reinstalling already in-use GTK").
    pub gtk: Option<Gtk>,
    /// The IGTK (PMF only): `Some(Ok(None))` = already in use,
    /// `Some(Err(()))` = invalid KDE ("Failed to configure IGTK", not
    /// fatal), `None` = none sent / PMF off.
    pub igtk: Option<Result<Option<Igtk>, ()>>,
    /// The Group Key message 2/2 PDU (802.1X header + body, MIC set).
    pub reply: Vec<u8>,
}

/// `(GTK KDE data, IGTK KDE data)`.
type GroupKdes<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

/// `wpa_parse_kde_ies`'s GTK / IGTK (the data after the KDE selector).
fn parse_group_kdes(buf: &[u8]) -> Result<GroupKdes<'_>, ()> {
    let (mut gtk, mut igtk) = (None, None);
    let mut pos = 0usize;
    while buf.len() - pos > 1 {
        if buf[pos] == 0xdd && (pos == buf.len() - 1 || buf[pos + 1] == 0) {
            break; // padding
        }
        let dlen = 2 + buf[pos + 1] as usize;
        if dlen > buf.len() - pos {
            return Err(()); // "EAPOL-Key Key Data underflow"
        }
        if buf[pos] == 0xdd && buf[pos + 1] as usize >= 4 {
            let sel = &buf[pos + 2..pos + 6];
            let left = &buf[pos + 6..pos + dlen];
            if left.len() > 2 && sel == KDE_GROUPKEY {
                gtk = Some(left);
            } else if left.len() > 2 && sel == KDE_IGTK {
                igtk = Some(left);
            }
        }
        pos += dlen;
    }
    Ok((gtk, igtk))
}

impl Supplicant {
    /// wpa_supplicant's `wpa_sm_rx_eapol` for a group-key EAPOL-Key frame
    /// (`pdu` = 802.1X header + body) after the 4-Way Handshake, then
    /// `wpa_supplicant_process_1_of_2` and `wpa_supplicant_send_2_of_2`.
    ///
    /// `mic_len` is the AKM's (16 for PSK), `group_key_len` the group
    /// cipher's key length (16 for CCMP-128), `mgmt_group_key_len` the
    /// IGTK length when PMF is negotiated (`None` = no PMF: an IGTK KDE
    /// is ignored, as `ieee80211w_set_keys`).
    ///
    /// MICs are [`eapol_key_mic`]; Key Data is unwrapped with
    /// `narf_crypto::aes_kw::aes_unwrap` (KEK of the PTK).
    ///
    /// On success the replay counter has advanced; the caller installs
    /// [`GroupKeyM1::gtk`] (and the IGTK), then calls
    /// [`Supplicant::group_keys_installed`] and transmits
    /// [`GroupKeyM1::reply`]. If the install fails, wpa_supplicant
    /// deauthenticates (`WLAN_REASON_UNSPECIFIED`), as for
    /// [`GroupKeyError::Fail`].
    pub fn process_group_m1(
        &mut self,
        pdu: &[u8],
        _mic_len: usize,
        group_key_len: usize,
        mgmt_group_key_len: Option<usize>,
    ) -> Result<GroupKeyM1, GroupKeyError> {
        let f = self.front(pdu).map_err(GroupKeyError::Drop)?;
        if f.key_info & KI_KEY_TYPE_PAIRWISE != 0 {
            return Err(GroupKeyError::Drop(GroupKeyDrop::Pairwise));
        }
        if f.key_info & KI_KEY_MIC == 0 {
            return Err(GroupKeyError::Drop(GroupKeyDrop::NoMic));
        }
        self.process_1_of_2(&f, group_key_len, mgmt_group_key_len)
    }

    /// `wpa_supplicant_process_1_of_2` + `wpa_supplicant_send_2_of_2` on a
    /// frame that passed [`Self::front`] (MIC verified, Key Data decrypted).
    fn process_1_of_2(
        &mut self,
        f: &rsna::Front,
        group_key_len: usize,
        mgmt_group_key_len: Option<usize>,
    ) -> Result<GroupKeyM1, GroupKeyError> {
        use GroupKeyDrop as D;
        use GroupKeyError::{Drop, Fail};
        let (tmp, key_info, ver, replay_counter) = (&f.tmp, f.key_info, f.ver, f.replay_counter);
        let key_data = &f.key_data[..];
        let body = 4;
        let mic_len = self.key_mgmt.mic_len();
        // wpa_supplicant_process_1_of_2
        if self.state != FourWayState::PtkDone {
            return Err(Fail(GroupKeyFail::Before4Way));
        }
        let (gtk, igtk) = parse_group_kdes(key_data).map_err(|_| Fail(GroupKeyFail::KeyData))?;
        if gtk.is_some() && key_info & KI_ENCRYPTED_KEY_DATA == 0 {
            return Err(Fail(GroupKeyFail::GtkUnencrypted));
        }
        let Some(gtk) = gtk else {
            return Err(Fail(GroupKeyFail::NoGtk));
        };
        if gtk.len() < 2 || gtk.len() - 2 > WPA_GTK_MAX_LEN {
            return Err(Fail(GroupKeyFail::GtkKdeLength));
        }
        if gtk.len() - 2 != group_key_len {
            return Err(Fail(GroupKeyFail::GtkCipherLength));
        }
        let mut rsc = [0u8; 8];
        rsc.copy_from_slice(&tmp[body + 61..body + 69]);
        let new_gtk = Gtk {
            key_id: gtk[0] & 0x3,
            // wpa_supplicant_gtk_tx_bit_workaround: a pairwise key is in use.
            tx: false,
            key: gtk[2..].to_vec(),
            rsc,
        };
        // ieee80211w_set_keys
        let igtk = match (mgmt_group_key_len, igtk) {
            (Some(klen), Some(i)) => Some(if i.len() != WPA_IGTK_KDE_PREFIX_LEN + klen {
                Err(())
            } else {
                let key_id = u16::from_le_bytes([i[0], i[1]]);
                let key = i[8..].to_vec();
                if self.igtk.as_deref() == Some(&key[..]) {
                    Ok(None)
                } else if key_id > 4095 {
                    Err(())
                } else {
                    let mut ipn = [0u8; 6];
                    ipn.copy_from_slice(&i[2..8]);
                    Ok(Some(Igtk { key_id, ipn, key }))
                }
            }),
            _ => None,
        };
        // wpa_supplicant_install_gtk: "Detect possible key reinstallation".
        let gtk = (self.gtk.as_deref() != Some(&new_gtk.key[..])).then_some(new_gtk);

        // wpa_supplicant_send_2_of_2
        let mut reply = KeyFrame::empty(mic_len);
        reply.descriptor_type = KEY_DESCRIPTOR_RSN;
        reply.key_information = (key_info & KI_KEY_INDEX_MASK) | ver | KI_SECURE | KI_KEY_MIC;
        reply.key_length = 0;
        reply.replay_counter = replay_counter;
        let body_bytes = reply.encode();
        let mut out = Vec::with_capacity(4 + body_bytes.len());
        EapolHeader {
            version: WPAS_EAPOL_VERSION,
            packet_type: EapolType::EapolKey as u8,
            body_length: body_bytes.len() as u16,
        }
        .encode(&mut out);
        out.extend_from_slice(&body_bytes);
        let kck = &self.ptk.as_ref().expect("PTK verified above").kck;
        let m = wpa_eapol_key_mic(self.key_mgmt, ver, kck, &out).ok_or(Drop(D::BadVersion))?;
        out[4 + 77..4 + 77 + mic_len].copy_from_slice(&m);
        Ok(GroupKeyM1 {
            gtk,
            igtk,
            reply: out,
        })
    }

    /// Record the keys the driver accepted (`sm->gtk` / `sm->igtk`), for
    /// the key-reinstallation check of the next Group Key message.
    pub fn group_keys_installed(&mut self, gtk: Option<&[u8]>, igtk: Option<&[u8]>) {
        if let Some(g) = gtk {
            self.gtk = Some(g.to_vec());
        }
        if let Some(i) = igtk {
            self.igtk = Some(i.to_vec());
        }
    }
}

// ── Tests (Group Key Handshake) ─────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod group_tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Sha1;
    impl HmacPrimitive for Sha1 {
        fn out_len(&self) -> usize {
            20
        }
        fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
            narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
        }
    }

    const AA: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const SA: [u8; 6] = [0x00, 0x03, 0x7F, 0x12, 0x34, 0x56];
    const OLD_GTK: [u8; 16] = [0x7C; 16];
    const NEW_GTK: [u8; 16] = [0x3D; 16];
    const RSC: [u8; 8] = [0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00];

    fn ptk() -> Ptk {
        derive_ptk(&Sha1, &[0x5A; 32], &AA, &SA, &[0x11; 32], &[0x22; 32], 16)
    }

    /// A supplicant right after a 4-way handshake whose M3 had replay
    /// counter 2 and carried `OLD_GTK`.
    fn done() -> Supplicant {
        let mut s = Supplicant::new(AA, SA, [0x22; 32]);
        s.state = FourWayState::PtkDone;
        s.ptk = Some(ptk());
        s.last_replay_counter = 2;
        s.rx_replay_counter_set = true;
        s.group_keys_installed(Some(&OLD_GTK), None);
        s
    }

    /// `GTK KDE`: dd len 00-0f-ac:1 | KeyID/Tx | reserved | GTK.
    fn gtk_kde(key_id: u8, gtk: &[u8]) -> Vec<u8> {
        let mut v = vec![
            0xDD,
            (6 + gtk.len()) as u8,
            0x00,
            0x0F,
            0xAC,
            0x01,
            key_id,
            0x00,
        ];
        v.extend_from_slice(gtk);
        v
    }

    /// The authenticator's Group Key message 1/2 (hostapd field order):
    /// Key Info `ki`, replay counter `rc`, Key RSC, `kd` (wrapped with
    /// the KEK when `ki` has Encrypted Key Data; padded with `dd 00…`
    /// to 8 bytes first), MIC with the KCK when `ki` has Key MIC.
    fn gm1(ki: u16, rc: u64, kd: &[u8]) -> Vec<u8> {
        let p = ptk();
        let mut k = KeyFrame::empty(16);
        k.key_information = ki;
        k.key_length = 0;
        k.replay_counter = rc;
        k.key_rsc = RSC;
        k.key_data = if ki & KI_ENCRYPTED_KEY_DATA != 0 {
            let mut d = kd.to_vec();
            if d.len() % 8 != 0 || d.len() < 16 {
                d.push(0xDD);
                while d.len() % 8 != 0 || d.len() < 16 {
                    d.push(0);
                }
            }
            let kek: [u8; 16] = p.kek.as_slice().try_into().unwrap();
            narf_crypto::aes_kw::aes_wrap(&kek, &d).unwrap()
        } else {
            kd.to_vec()
        };
        let mut b = k.into_eapol();
        if ki & KI_KEY_MIC != 0 {
            let ver = ki & KI_VERSION_MASK;
            // RC4 (version 1) has no MIC primitive here: any bytes do.
            let m = eapol_key_mic(ver, &p.kck, &b, 16).unwrap_or_else(|| vec![0; 16]);
            b[81..97].copy_from_slice(&m);
        }
        b
    }

    /// ver 2 | Key MIC | Secure | Key Ack | Encrypted Key Data, group.
    const GM1_KI: u16 = 0x1382;

    fn smoke_eapol_group_rekey_2_of_2_golden() -> TestResult {
        let mut s = done();
        let f = gm1(GM1_KI, 3, &gtk_kde(2, &NEW_GTK));
        let r = match s.process_group_m1(&f, 16, 16, None) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("GM1 rejected"),
        };
        let want_gtk = Gtk {
            key_id: 2,
            tx: false,
            key: NEW_GTK.to_vec(),
            rsc: RSC,
        };
        if r.gtk != Some(want_gtk) || r.igtk.is_some() {
            return TestResult::Fail("GTK idx 2 + RSC from the frame, no IGTK");
        }
        // wpa_supplicant_send_2_of_2 (RSN, PSK, ver 2): 802.1X version 1
        // (DEFAULT_EAPOL_VERSION), type 3, length 95; descriptor 2; Key
        // Info = rx key index (0) | ver 2 | Secure | Key MIC = 0x0302;
        // Key Length 0; replay counter copied (3); nonce / IV / RSC /
        // reserved zero; MIC; Key Data Length 0.
        let mut g = vec![0x01, 0x03, 0x00, 0x5F, 0x02, 0x03, 0x02, 0x00, 0x00];
        g.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 3]);
        g.extend_from_slice(&[0u8; 32 + 16 + 8 + 8]);
        g.extend_from_slice(&[0u8; 16]);
        g.extend_from_slice(&[0x00, 0x00]);
        let p = ptk();
        let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&p.kck, &g);
        g[81..97].copy_from_slice(&mic[..16]);
        if r.reply != g {
            return TestResult::Fail("2/2 golden");
        }
        if s.last_replay_counter != 3 {
            return TestResult::Fail("replay counter advanced to 3");
        }
        s.group_keys_installed(Some(&NEW_GTK), None);
        if s.gtk.as_deref() != Some(&NEW_GTK[..]) {
            return TestResult::Fail("installed GTK recorded");
        }
        // The same GTK again (retransmitted with a new counter): not
        // reinstalled, still answered.
        let f = gm1(GM1_KI, 4, &gtk_kde(2, &NEW_GTK));
        match s.process_group_m1(&f, 16, 16, None) {
            Ok(r) if r.gtk.is_none() && r.reply[16] == 4 => {}
            _ => return TestResult::Fail("reinstall suppressed, 2/2 sent"),
        }
        // AES-128-CMAC descriptor version 3 (interop workaround).
        let mut s = done();
        let f = gm1(0x1383, 3, &gtk_kde(1, &NEW_GTK));
        match s.process_group_m1(&f, 16, 16, None) {
            Ok(r) => {
                let mut z = r.reply.clone();
                z[81..97].fill(0);
                let k: [u8; 16] = ptk().kck.as_slice().try_into().unwrap();
                let m = narf_crypto::cmac_aes128::cmac_aes128(&k, &z);
                if r.reply[6] != 0x03 || r.reply[81..97] != m {
                    return TestResult::Fail("ver 3: 0x0303 + CMAC MIC");
                }
            }
            Err(_) => return TestResult::Fail("ver 3 GM1 rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_group_rekey_2_of_2_golden);

    fn smoke_eapol_group_rekey_drops() -> TestResult {
        use GroupKeyDrop as D;
        let kd = gtk_kde(2, &NEW_GTK);
        let mut bad_mic = gm1(GM1_KI, 3, &kd);
        bad_mic[90] ^= 1;
        // Corrupt the wrapped key data, then re-MIC so only the unwrap
        // fails.
        let mut bad_wrap = gm1(GM1_KI, 3, &kd);
        bad_wrap[100] ^= 1;
        bad_wrap[81..97].fill(0);
        let m = eapol_key_mic(2, &ptk().kck, &bad_wrap, 16).unwrap();
        bad_wrap[81..97].copy_from_slice(&m);
        let short = gm1(GM1_KI, 3, &kd)[..98].to_vec();
        let mut not_key = gm1(GM1_KI, 3, &kd);
        not_key[1] = 0;
        let mut long_len = gm1(GM1_KI, 3, &kd);
        long_len[2..4].copy_from_slice(&0x0400u16.to_be_bytes());
        let mut wpa1 = gm1(GM1_KI, 3, &kd);
        wpa1[4] = KEY_DESCRIPTOR_WPA_LEGACY;
        let mut other_desc = gm1(GM1_KI, 3, &kd);
        other_desc[4] = 7;
        let mut kd_over = gm1(GM1_KI, 3, &kd);
        kd_over[97..99].copy_from_slice(&0x0100u16.to_be_bytes());
        let cases: Vec<(Vec<u8>, D, &'static str)> = vec![
            (short, D::TooShort, "too short"),
            (not_key, D::NotKey, "EAP packet is not a key frame"),
            (long_len, D::BadLength, "body length past the frame"),
            (other_desc, D::BadDescriptor, "unknown descriptor"),
            (kd_over, D::KeyDataOverflow, "key data overflow"),
            (
                gm1(GM1_KI, 2, &kd),
                D::Replay,
                "replay counter not increased",
            ),
            (gm1(GM1_KI, 1, &kd), D::Replay, "replay counter went back"),
            (gm1(GM1_KI | KI_SMK_MESSAGE, 3, &kd), D::Smk, "SMK bit"),
            (gm1(GM1_KI & !KI_KEY_ACK, 3, &kd), D::NoAck, "no Key Ack"),
            (gm1(GM1_KI | KI_REQUEST, 3, &kd), D::Request, "Request bit"),
            (wpa1, D::BadDescriptor, "WPA1 descriptor"),
            (
                gm1(
                    (GM1_KI & !KI_VERSION_MASK) | KI_VERSION_HMAC_MD5_RC4,
                    3,
                    &kd,
                ),
                D::BadVersion,
                "RC4 descriptor version without TKIP",
            ),
            (
                gm1(GM1_KI | KI_KEY_TYPE_PAIRWISE, 3, &kd),
                D::Pairwise,
                "pairwise frame",
            ),
            (bad_mic, D::BadMic, "MIC mismatch"),
            (
                gm1(GM1_KI & !KI_KEY_MIC, 3, &kd),
                D::EncryptedUnauthenticated,
                "encrypted Key Data without MIC",
            ),
            (bad_wrap, D::Decrypt, "AES unwrap integrity failure"),
            (
                gm1(KI_VERSION_HMAC_SHA1_AES | KI_SECURE | KI_KEY_ACK, 3, &kd),
                D::NoMic,
                "group frame without MIC / Encr",
            ),
        ];
        for (f, d, what) in cases {
            let mut s = done();
            let r = s.process_group_m1(&f, 16, 16, None);
            if r != Err(GroupKeyError::Drop(d)) {
                return TestResult::Fail(what);
            }
            // Nothing is installed; a MIC-verified frame that failed
            // its unwrap, or a MIC-verified pairwise frame (which
            // wpa_sm_rx_eapol verifies before dispatching to the 4-way),
            // still advanced the counter, as wpa_supplicant.
            let rc = if d == D::Decrypt || d == D::Pairwise {
                3
            } else {
                2
            };
            if s.last_replay_counter != rc || s.gtk.as_deref() != Some(&OLD_GTK[..]) {
                return TestResult::Fail("dropped frame: supplicant state");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_group_rekey_drops);

    fn smoke_eapol_group_rekey_failures_and_igtk() -> TestResult {
        use GroupKeyFail as F;
        // process_1_of_2 failures → wpa_sm_deauthenticate. The MIC was
        // good, so the counter has advanced (wpa_supplicant order).
        let fail = |s: &mut Supplicant, f: &[u8], want: F| {
            s.process_group_m1(f, 16, 16, None) == Err(GroupKeyError::Fail(want))
                && s.last_replay_counter == 3
        };
        let mut s = done();
        s.state = FourWayState::WaitM3;
        if !fail(
            &mut s,
            &gm1(GM1_KI, 3, &gtk_kde(1, &NEW_GTK)),
            F::Before4Way,
        ) {
            return TestResult::Fail("before the 4-way completed");
        }
        // Only an RSN element in the key data (no GTK KDE).
        let rsn = [0x30, 0x02, 0x01, 0x00];
        if !fail(&mut done(), &gm1(GM1_KI, 3, &rsn), F::NoGtk) {
            return TestResult::Fail("no GTK KDE");
        }
        // A KDE claiming more bytes than present (underflow).
        let mut under = gtk_kde(1, &NEW_GTK);
        under[1] = 40;
        if !fail(&mut done(), &gm1(GM1_KI, 3, &under), F::KeyData) {
            return TestResult::Fail("key data underflow");
        }
        // A 32-byte GTK for a CCMP-128 group cipher.
        let long = gm1(GM1_KI, 3, &gtk_kde(1, &[0x44; 32]));
        if !fail(&mut done(), &long, F::GtkCipherLength) {
            return TestResult::Fail("GTK length != cipher");
        }
        // A GTK KDE with only the KeyID byte + 1.
        let tiny = [0xDD, 0x07, 0x00, 0x0F, 0xAC, 0x01, 0x01, 0x00, 0x55];
        if !fail(&mut done(), &gm1(GM1_KI, 3, &tiny), F::GtkCipherLength) {
            return TestResult::Fail("1-byte GTK");
        }
        // GTK KDE in clear Key Data.
        let clear = gm1(GM1_KI & !KI_ENCRYPTED_KEY_DATA, 3, &gtk_kde(1, &NEW_GTK));
        if !fail(&mut done(), &clear, F::GtkUnencrypted) {
            return TestResult::Fail("GTK in unencrypted key data");
        }

        // IGTK KDE: dd 1c 00-0f-ac:9 | KeyID 4 (LE) | IPN | IGTK.
        let mut kd = gtk_kde(1, &NEW_GTK);
        let ipn = [1, 2, 3, 4, 5, 6];
        let igtk = [0x9E; 16];
        kd.extend_from_slice(&[0xDD, 28, 0x00, 0x0F, 0xAC, 0x09, 0x04, 0x00]);
        kd.extend_from_slice(&ipn);
        kd.extend_from_slice(&igtk);
        let f = gm1(GM1_KI, 3, &kd);
        let want = Igtk {
            key_id: 4,
            ipn,
            key: igtk.to_vec(),
        };
        match done().process_group_m1(&f, 16, 16, Some(16)) {
            Ok(r) if r.igtk == Some(Ok(Some(want))) && r.gtk.is_some() => {}
            _ => return TestResult::Fail("IGTK with PMF"),
        }
        match done().process_group_m1(&f, 16, 16, None) {
            Ok(r) if r.igtk.is_none() => {}
            _ => return TestResult::Fail("IGTK ignored without PMF"),
        }
        // A 32-byte IGTK cipher negotiated: the 16-byte KDE is invalid,
        // which is not fatal ("Failed to configure IGTK").
        match done().process_group_m1(&f, 16, 16, Some(32)) {
            Ok(r) if r.igtk == Some(Err(())) && r.gtk.is_some() => {}
            _ => return TestResult::Fail("bad IGTK KDE length is not fatal"),
        }
        let mut s = done();
        s.group_keys_installed(None, Some(&igtk));
        match s.process_group_m1(&f, 16, 16, Some(16)) {
            Ok(r) if r.igtk == Some(Ok(None)) => {}
            _ => return TestResult::Fail("IGTK reinstall suppressed"),
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/eapol", smoke_eapol_group_rekey_failures_and_igtk);
}
