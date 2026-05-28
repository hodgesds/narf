//! HDCP 2.x key exchange (over SEC2).
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/dispnv50/disp.c`**
//!   `nv50_disp_hdcp_*` — Nouveau's HDCP integration on Maxwell+.
//! - **HDCP 2.3 specification** (DCP LLC) — the authentication +
//!   key exchange protocol the driver implements over the AUX
//!   sideband.
//! - **`/home/daniel/git/linux/drivers/gpu/drm/display/drm_hdcp_helper.c`** —
//!   shared DRM HDCP state machine. We mirror the message-id
//!   constants from `<drm/display/drm_hdcp.h>`.
//! - **`nvkm/engine/sec2/*.c`** — SEC2 cmdq interface that signs
//!   the messages.
//!
//! ## Overview
//!
//! HDCP 2.x authentication is a 4-pass key exchange:
//!
//! 1. **AKE_Init** — host sends rtx (random nonce) + tx capability.
//! 2. **AKE_Send_Cert** — sink replies with its certificate +
//!    rrx (sink nonce) + RxCaps.
//! 3. **AKE_No_Stored_km** — host wraps km (master key) with the
//!    sink's certificate public key, sends.
//! 4. **AKE_Send_H_prime** — sink computes H' = HMAC-SHA256 over
//!    (rtx || RxCaps || TxCaps) keyed by kd; host verifies.
//! 5. **AKE_Send_Pairing_Info** — sink shares Ekh(km) for future
//!    fast-restart.
//!
//! Then locality-check + session-key exchange:
//!
//! 6. **LC_Init** — host sends rn (round nonce).
//! 7. **LC_Send_L_prime** — sink replies with L' = HMAC-SHA256(
//!    rn) keyed by kd. Must arrive within 7 ms (locality test).
//! 8. **SKE_Send_Eks** — host sends Eks (session key, AES-wrapped).
//!
//! NARF's SEC2 Falcon signs the host-side blobs; this module
//! encodes the on-the-wire layout + state machine.

#![allow(dead_code)]

// ── Message-id constants (per HDCP 2.x §2.2) ─────────────────────

pub const HDCP_MSG_AKE_INIT: u8 = 2;
pub const HDCP_MSG_AKE_SEND_CERT: u8 = 3;
pub const HDCP_MSG_AKE_NO_STORED_KM: u8 = 4;
pub const HDCP_MSG_AKE_STORED_KM: u8 = 5;
pub const HDCP_MSG_AKE_SEND_H_PRIME: u8 = 7;
pub const HDCP_MSG_AKE_SEND_PAIRING_INFO: u8 = 8;
pub const HDCP_MSG_LC_INIT: u8 = 9;
pub const HDCP_MSG_LC_SEND_L_PRIME: u8 = 10;
pub const HDCP_MSG_SKE_SEND_EKS: u8 = 11;
pub const HDCP_MSG_REPEATER_RECV_ID_LIST: u8 = 12;
pub const HDCP_MSG_RTT_READY: u8 = 13;
pub const HDCP_MSG_RTT_CHALLENGE: u8 = 14;

// ── Field sizes (HDCP 2.x §2.3) ──────────────────────────────────

pub const HDCP_RTX_LEN: usize = 8;
pub const HDCP_RRX_LEN: usize = 8;
pub const HDCP_KM_LEN: usize = 16;
pub const HDCP_H_PRIME_LEN: usize = 32;
pub const HDCP_L_PRIME_LEN: usize = 32;
pub const HDCP_KS_LEN: usize = 16;
pub const HDCP_RN_LEN: usize = 8;
pub const HDCP_EDKEY_KS_LEN: usize = 16;
pub const HDCP_RIV_LEN: usize = 8;
pub const HDCP_CERT_LEN: usize = 522;
pub const HDCP_E_KH_KM_LEN: usize = 16;

// ── Auth state machine ──────────────────────────────────────────

/// HDCP authentication state. The driver advances through these
/// states as messages are signed by SEC2 and posted via AUX/HDCP.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdcpState {
    /// No auth yet.
    Idle,
    /// AKE_Init sent; waiting for AKE_Send_Cert.
    AkeInitSent,
    /// AKE_Send_Cert received; sink certificate validated by SEC2.
    /// Building AKE_No_Stored_km (or AKE_Stored_km if pairing info
    /// is cached).
    AkeCertValidated,
    /// AKE_No_Stored_km sent; waiting for AKE_Send_H_prime.
    AkeNoStoredKmSent,
    /// H' received and verified; the host expects AKE_Send_Pairing_Info
    /// next (if no stored km).
    AkeHPrimeVerified,
    /// LC_Init sent; waiting for LC_Send_L_prime (must arrive ≤ 7 ms).
    LcInitSent,
    /// L' verified; SKE_Send_Eks queued.
    LcLPrimeVerified,
    /// SKE_Send_Eks sent; link is authenticated.
    Authenticated,
    /// Auth failed at some step. Caller should drop the link or
    /// fall back to HDCP 1.x (out of scope here).
    Failed,
}

/// Per-link HDCP context — minimum state to drive the auth machine.
#[derive(Clone, Debug)]
pub struct HdcpContext {
    pub state: HdcpState,
    /// rtx — host nonce. Random per session.
    pub rtx: [u8; HDCP_RTX_LEN],
    /// rrx — sink nonce. Received in AKE_Send_Cert.
    pub rrx: [u8; HDCP_RRX_LEN],
    /// rn — locality-check nonce. Random per round.
    pub rn: [u8; HDCP_RN_LEN],
    /// km — master key. Random per session, sent encrypted.
    pub km: [u8; HDCP_KM_LEN],
    /// Tx capabilities byte. HDCP 2.3 spec §2.2.1 — 3-byte field;
    /// we keep the canonical 0x02 / 0x00 / 0x00 default.
    pub tx_caps: [u8; 3],
    /// Rx capabilities byte (received).
    pub rx_caps: [u8; 3],
    /// Whether we should send `AKE_Stored_km` (true) or
    /// `AKE_No_Stored_km` (false). Determined by whether the host
    /// has cached pairing info (Ekh(km)) for this sink.
    pub use_stored_km: bool,
}

impl HdcpContext {
    pub fn new() -> Self {
        Self {
            state: HdcpState::Idle,
            rtx: [0; HDCP_RTX_LEN],
            rrx: [0; HDCP_RRX_LEN],
            rn: [0; HDCP_RN_LEN],
            km: [0; HDCP_KM_LEN],
            tx_caps: [0x02, 0, 0],
            rx_caps: [0; 3],
            use_stored_km: false,
        }
    }

    /// Drive the state machine forward by one event. Returns the
    /// next outbound message id (if any) the caller should
    /// build + sign via SEC2.
    pub fn step(&mut self, event: HdcpEvent) -> Option<u8> {
        match (self.state, event) {
            (HdcpState::Idle, HdcpEvent::Start) => {
                self.state = HdcpState::AkeInitSent;
                Some(HDCP_MSG_AKE_INIT)
            }
            (HdcpState::AkeInitSent, HdcpEvent::ReceivedCert(rx_caps, rrx)) => {
                self.rx_caps = rx_caps;
                self.rrx = rrx;
                self.state = HdcpState::AkeCertValidated;
                if self.use_stored_km {
                    Some(HDCP_MSG_AKE_STORED_KM)
                } else {
                    Some(HDCP_MSG_AKE_NO_STORED_KM)
                }
            }
            (HdcpState::AkeCertValidated, HdcpEvent::SentKm) => {
                self.state = HdcpState::AkeNoStoredKmSent;
                None
            }
            (HdcpState::AkeNoStoredKmSent, HdcpEvent::HPrimeVerified) => {
                self.state = HdcpState::AkeHPrimeVerified;
                Some(HDCP_MSG_LC_INIT)
            }
            (HdcpState::AkeHPrimeVerified, HdcpEvent::SentLcInit) => {
                self.state = HdcpState::LcInitSent;
                None
            }
            (HdcpState::LcInitSent, HdcpEvent::LPrimeVerified) => {
                self.state = HdcpState::LcLPrimeVerified;
                Some(HDCP_MSG_SKE_SEND_EKS)
            }
            (HdcpState::LcLPrimeVerified, HdcpEvent::SentEks) => {
                self.state = HdcpState::Authenticated;
                None
            }
            (_, HdcpEvent::Failure) => {
                self.state = HdcpState::Failed;
                None
            }
            _ => None,
        }
    }
}

impl Default for HdcpContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Events that drive the HDCP state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdcpEvent {
    /// Caller asks to start authentication.
    Start,
    /// Sink replied with AKE_Send_Cert; we cache rx_caps + rrx.
    ReceivedCert([u8; 3], [u8; HDCP_RRX_LEN]),
    /// AKE_*_km message posted on the wire.
    SentKm,
    /// SEC2 verified the received H' is correct.
    HPrimeVerified,
    /// LC_Init posted.
    SentLcInit,
    /// SEC2 verified L' came back in time + correct.
    LPrimeVerified,
    /// SKE_Send_Eks posted.
    SentEks,
    /// Any failure — abort.
    Failure,
}

// ── SEC2 command-id integration ──────────────────────────────────
//
// `sec2.rs::Sec2Cmd::HdcpKx` is the umbrella command; the actual
// HDCP sub-command + per-step opcode are passed in MAILBOX1.

/// HDCP sub-commands posted to SEC2's HdcpKx command. Cite
/// `nvkm/engine/sec2/gp102.c` for the same dispatch table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdcpSec2SubCmd {
    /// Generate rtx + sign AKE_Init.
    GenAkeInit = 0x01,
    /// Verify sink certificate + decode rrx + RxCaps.
    VerifyCert = 0x02,
    /// Build AKE_No_Stored_km (encrypt km with cert pubkey).
    EncryptKm = 0x03,
    /// Verify H' from sink.
    VerifyHPrime = 0x04,
    /// Generate LC_Init.
    GenLcInit = 0x05,
    /// Verify L' from sink (and 7 ms timing).
    VerifyLPrime = 0x06,
    /// Build SKE_Send_Eks (AES-wrap ks).
    EncryptKs = 0x07,
}

impl HdcpSec2SubCmd {
    pub const fn code(self) -> u32 {
        self as u32
    }
}
