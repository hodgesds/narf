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

// ── In-kernel HDCP crypto path ───────────────────────────────────────
//
// Prior agents wired the `Sec2Cmd::HdcpKx` dispatch table and called
// out that the actual AES / SHA / HMAC / RSA crypto was missing
// because we don't want to depend on signed SEC2 firmware just to
// authenticate a display on the open driver path. NARF's crypto crate
// now ships the primitives (`narf_crypto::hdcp`, `narf_crypto::aes_ctr`,
// `narf_crypto::rsaes_oaep`); this section wires them into the per-link
// state.
//
// The sub-commands above remain a useful abstraction for *signed*
// HDCP paths (where the host still wants firmware to sign on its
// behalf for HDCP-2.3 robustness rules). We expose a *parallel*
// in-kernel handler so the driver can pick which to use per chip-gen
// — and so the SEC2 dispatch can call back into the in-kernel routines
// when the firmware blob is unavailable.

use narf_crypto::hdcp as nc_hdcp;
use narf_crypto::rsaes_oaep;

/// Per-link derived material that lives next to `HdcpContext` once
/// AKE_Send_Cert has been received. Computed in-kernel by
/// `compute_kd_for_link` — feeds the H' / L' verify paths.
#[derive(Clone, Debug, Default)]
pub struct HdcpKeys {
    /// kd = dkey0 || dkey1 — 256-bit derived key from km, rn (§2.7).
    pub kd: [u8; 32],
    /// kh = HMAC-SHA256(kd, "kh")[..16] — pairing-info wrap key.
    pub kh: [u8; 16],
}

impl HdcpKeys {
    /// Derive kd + kh from the current context's km + rn. Call after
    /// AKE_No_Stored_km has been built (so km is set) and after LC_Init
    /// has chosen rn.
    pub fn derive(km: &[u8; HDCP_KM_LEN], rn: &[u8; HDCP_RN_LEN]) -> Self {
        let kd = nc_hdcp::derive_kd(km, rn);
        let kh = nc_hdcp::derive_kh(&kd);
        Self { kd, kh }
    }
}

/// Errors surfaced by the in-kernel HDCP crypto handler.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdcpCryptoError {
    /// RSAES-OAEP encrypt of km failed (e.g. message too long — should
    /// never fire for a 16-byte km).
    KmWrap,
    /// H' did not match the value the host recomputed.
    HPrimeMismatch,
    /// L' did not match the value the host recomputed.
    LPrimeMismatch,
}

/// Build the `E_kpubrx(km)` payload that sits inside AKE_No_Stored_km.
/// The receiver's public-key modulus (`n_be`) and the host-generated
/// 32-byte OAEP seed come from the caller (SEC2's random source for
/// the seed; the cert-rx payload for `n_be`).
pub fn wrap_km_for_ake_no_stored(
    n_be: &[u8; rsaes_oaep::RSA_3072_LEN],
    seed: &[u8; rsaes_oaep::SHA256_HASH_LEN],
    km: &[u8; HDCP_KM_LEN],
) -> Result<[u8; rsaes_oaep::RSA_3072_LEN], HdcpCryptoError> {
    rsaes_oaep::rsaes_oaep_sha256_encrypt(
        n_be,
        rsaes_oaep::HDCP_RSA_PUB_EXP_F4,
        seed,
        km,
        b"", // HDCP uses an empty label.
    )
    .map_err(|_| HdcpCryptoError::KmWrap)
}

/// Verify the AKE_Send_H_prime message. The host recomputes H' from
/// the link's kd, the rtx it sent in AKE_Init, and the RxCaps / TxCaps
/// exchanged earlier; returns Ok if the receiver's H' matches.
pub fn verify_ake_send_h_prime(
    keys: &HdcpKeys,
    ctx: &HdcpContext,
    presented_h_prime: &[u8; nc_hdcp::HDCP_MIC_LEN],
) -> Result<(), HdcpCryptoError> {
    if !nc_hdcp::verify_h_prime(
        &keys.kd,
        &ctx.rtx,
        &ctx.rx_caps,
        &ctx.tx_caps,
        presented_h_prime,
    ) {
        return Err(HdcpCryptoError::HPrimeMismatch);
    }
    Ok(())
}

/// Verify the LC_Send_L_prime message. Receiver-side rrx + host-side rn
/// drive the recomputation per §2.3.
pub fn verify_lc_send_l_prime(
    keys: &HdcpKeys,
    ctx: &HdcpContext,
    presented_l_prime: &[u8; nc_hdcp::HDCP_MIC_LEN],
) -> Result<(), HdcpCryptoError> {
    if !nc_hdcp::verify_l_prime(&keys.kd, &ctx.rrx, &ctx.rn, presented_l_prime) {
        return Err(HdcpCryptoError::LPrimeMismatch);
    }
    Ok(())
}

/// Build SKE_Send_Eks payload: `E_dkey_ks` (CTR-wrapped ks) + riv.
/// `kd_low16` is the lower half of kd per §2.7 (the bytes that drive
/// the CTR keystream); `riv` is the 64-bit IV the host sends, generated
/// fresh per session.
pub fn build_ske_send_eks(
    keys: &HdcpKeys,
    riv: &[u8; HDCP_RIV_LEN],
    ks: &[u8; HDCP_KS_LEN],
) -> ([u8; HDCP_EDKEY_KS_LEN], [u8; HDCP_RIV_LEN]) {
    let mut kd_low16 = [0u8; 16];
    kd_low16.copy_from_slice(&keys.kd[..16]);
    let e_dkey_ks = nc_hdcp::wrap_ks_ctr(&kd_low16, riv, ks);
    (e_dkey_ks, *riv)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod nvidia_hdcp_crypto_tests {
    use super::*;

    #[test]
    fn verify_h_prime_round_trip() {
        let km = [0xAAu8; HDCP_KM_LEN];
        let rn = [0xBBu8; HDCP_RN_LEN];
        let keys = HdcpKeys::derive(&km, &rn);

        let mut ctx = HdcpContext::new();
        ctx.rtx = [0x11u8; HDCP_RTX_LEN];
        ctx.rx_caps = [0x02, 0, 0];
        ctx.tx_caps = [0x02, 0, 0];

        // Compute H' as the receiver would, then verify host-side.
        let h = nc_hdcp::compute_h_prime(&keys.kd, &ctx.rtx, &ctx.rx_caps, &ctx.tx_caps);
        assert!(verify_ake_send_h_prime(&keys, &ctx, &h).is_ok());

        let mut bad_h = h;
        bad_h[0] ^= 0x01;
        assert_eq!(
            verify_ake_send_h_prime(&keys, &ctx, &bad_h),
            Err(HdcpCryptoError::HPrimeMismatch)
        );
    }

    #[test]
    fn build_ske_send_eks_round_trip() {
        let km = [0xCCu8; HDCP_KM_LEN];
        let rn = [0xDDu8; HDCP_RN_LEN];
        let keys = HdcpKeys::derive(&km, &rn);
        let riv = [0xEEu8; HDCP_RIV_LEN];
        let ks = [0xFFu8; HDCP_KS_LEN];

        let (e_dkey_ks, out_riv) = build_ske_send_eks(&keys, &riv, &ks);
        assert_eq!(out_riv, riv);
        // CTR-unwrap with the same key+iv recovers ks.
        let mut kd_low16 = [0u8; 16];
        kd_low16.copy_from_slice(&keys.kd[..16]);
        let recovered = nc_hdcp::wrap_ks_ctr(&kd_low16, &riv, &e_dkey_ks);
        assert_eq!(recovered, ks);
    }
}
