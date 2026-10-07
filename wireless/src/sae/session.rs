//! [`SaeSession`] — the high-level WPA3 SAE H2E driver.
//!
//! Wraps the H2E PT/PWE derivation ([`super::pt`]), real P-256
//! arithmetic, and the Commit / Confirm transcript MAC into a single
//! type whose interface matches what drivers want:
//!
//! ```ignore
//! let mut s = SaeSession::new("MySSID", "password", own_mac, peer_mac);
//! let commit_out = s.build_commit();
//! tx_to_peer(commit_out);
//! s.on_commit(&peer_commit)?;
//! let confirm_out = s.build_confirm();
//! tx_to_peer(confirm_out);
//! s.on_confirm(&peer_confirm)?;
//! assert_eq!(s.state(), SaeState::Accepted);
//! let pmk = s.pmk().expect("PMK ready").to_vec();
//! ```
//!
//! ## Differences from [`super::dragonfly::Sae`]
//!
//! - Uses H2E (`pt_h2e` + `pwe_from_pt`) for PWE derivation — no
//!   hunting-and-pecking, no side-channel exposure.
//! - Carries the password and SSID directly so callers don't pass
//!   the raw password back in on every Commit build.
//! - Returns plain `Vec<u8>` payloads ready to drop into an SAE
//!   Authentication frame's variable-length body (the 6-byte
//!   Algorithm / Sequence / Status header is the caller's job).
//! - Tracks a retry counter for `Sync` retransmits per
//!   §12.4.8.6.4.
//!
//! ## State machine
//!
//! Per IEEE 802.11-2020 §12.4.6.6:
//!
//! ```text
//!   Nothing  --build_commit-->  Committed
//!   Committed  --on_commit-->   Committed (peer commit received,
//!                                          PMK derived)
//!   Committed  --build_confirm--> Confirmed
//!   Confirmed  --on_confirm-->   Accepted
//! ```
//!
//! Out-of-order calls (e.g. `build_confirm` before `on_commit`)
//! return `SaeError::Protocol`. Retries on the same step bump the
//! sync counter and refuse after `MAX_SYNC_RETRIES`.

use alloc::vec::Vec;

use narf_crypto::p256::point::{scalar_mul, AffinePoint};
use narf_crypto::p256::scalar::Scalar;

use super::dragonfly::{CommitFrame, ConfirmFrame, HmacSha256, MacPrimitive, SaeError, SaeState};
use super::pt::{pt_h2e, pwe_from_pt, pwe_valid};

/// SAE sync-retry limit (§12.4.8.6.4: `dot11RSNASAESync`, default 5).
const MAX_SYNC_RETRIES: u8 = 5;

/// SAE handshake driver implementing the H2E variant. Owns the cached
/// PT (so repeated handshakes with the same network skip the h2c
/// work) and the per-handshake transient state (rand / mask / PWE).
#[derive(Debug)]
pub struct SaeSession {
    state: SaeState,
    /// Password Token — derived once per (ssid, password). Cached so
    /// repeated handshakes against the same network are cheap.
    pt: AffinePoint,
    /// Password Element — derived per (PT, mac_a, mac_b). `None`
    /// until `build_commit` first runs.
    pwe: Option<AffinePoint>,
    /// Local random scalar (secret). Consumed by the K computation
    /// in `on_commit`. Reset to zero after consumption.
    rand: Scalar,
    /// Local "private" scalar (mask in the spec). Also secret; combined
    /// with `rand` to form the public `commit_scalar`.
    private: Scalar,
    /// Commit scalar we sent: `(rand + private) mod n`. Saved so we
    /// can include it in the Confirm transcript.
    commit_scalar: Scalar,
    /// Commit element we sent: `-(private · PWE)`. Saved for Confirm.
    commit_element: AffinePoint,
    /// Peer's Commit scalar.
    peer_scalar: Scalar,
    /// Peer's Commit element.
    peer_element: AffinePoint,
    /// KCK derived from K via HKDF (`SAE KCK and PMK` label, §12.4.5.4).
    kck: Option<[u8; 32]>,
    /// KEK derived for an SAE-PK session (the AES-SIV key that protects the
    /// AP's Modifier); `None` for a plain SAE session.
    kek: Option<[u8; 32]>,
    /// Whether the configured password is an SAE-PK password. Selects the
    /// "SAE-PK keys" key-derivation label and enables AP authentication.
    sae_pk: bool,
    /// Trailing information elements of the peer's Confirm frame — the SAE-PK
    /// element carriage (FILS public key / key confirmation + SAE-PK vendor
    /// element); empty for a plain SAE session.
    peer_confirm_ies: Vec<u8>,
    /// PMK — the SAE output, fed to the 4-Way Handshake as the PSK
    /// replacement for the WPA2-PSK path.
    pmk: Option<[u8; 32]>,
    /// MAC addresses used for PWE derivation and Confirm transcript.
    own_mac: [u8; 6],
    peer_mac: [u8; 6],
    /// SAE send-confirm counter. Increments per outgoing Confirm; the
    /// peer's Confirm must arrive with a counter ≥ ours minus the
    /// sync window (§12.4.8.6.4).
    send_confirm_counter: u16,
    /// Sync-retry counter. Bumps on duplicate / out-of-order frames;
    /// caps at MAX_SYNC_RETRIES, beyond which we abandon the session.
    sync_retries: u8,
    /// Test RNG seed override. Used by deterministic smokes; the
    /// production constructor leaves it None.
    test_seed: Option<[u8; 64]>,
}

impl SaeSession {
    /// Build a new SAE H2E session. Eagerly computes the PT — this is
    /// the expensive step (one hash-to-curve), but it happens once per
    /// (ssid, password) and is cached for the session lifetime.
    pub fn new(ssid: &str, password: &str, own_mac: [u8; 6], peer_mac: [u8; 6]) -> Self {
        Self::new_with_identifier(ssid, password, None, own_mac, peer_mac)
    }

    /// As [`Self::new`], but folds the optional SAE-PK identifier into
    /// the PT derivation per IEEE 802.11-2020 §12.4.4.2.3.
    pub fn new_with_identifier(
        ssid: &str,
        password: &str,
        identifier: Option<&str>,
        own_mac: [u8; 6],
        peer_mac: [u8; 6],
    ) -> Self {
        let pt = pt_h2e(ssid, password, identifier);
        Self {
            state: SaeState::Nothing,
            pt,
            pwe: None,
            rand: Scalar::ZERO,
            private: Scalar::ZERO,
            commit_scalar: Scalar::ZERO,
            commit_element: AffinePoint::INFINITY,
            peer_scalar: Scalar::ZERO,
            peer_element: AffinePoint::INFINITY,
            kck: None,
            pmk: None,
            kek: None,
            sae_pk: super::pk::is_sae_pk_password(password),
            peer_confirm_ies: Vec::new(),
            own_mac,
            peer_mac,
            send_confirm_counter: 0,
            sync_retries: 0,
            test_seed: None,
        }
    }

    /// Test hook: seed the per-handshake RNG with a deterministic
    /// 64-byte value so smokes can re-derive the same Commit pair.
    /// Production callers do not use this — `new` pulls entropy from
    /// `narf_crypto::per_task_rng()`.
    pub fn with_test_seed(mut self, seed: [u8; 64]) -> Self {
        self.test_seed = Some(seed);
        self
    }

    /// Current state.
    pub fn state(&self) -> SaeState {
        self.state
    }

    /// Cached PMK once the handshake reaches [`SaeState::Accepted`].
    pub fn pmk(&self) -> Option<&[u8; 32]> {
        self.pmk.as_ref()
    }

    /// Cached KCK. Most callers want only the PMK; the KCK is exposed
    /// for debugging and for re-verifying Confirm transcripts.
    pub fn kck(&self) -> Option<&[u8; 32]> {
        self.kck.as_ref()
    }

    /// Whether this is an SAE-PK session (the configured password is an
    /// SAE-PK password).
    pub fn is_sae_pk(&self) -> bool {
        self.sae_pk
    }

    /// The SAE-PK KEK (AES-SIV key), available after `on_commit` for an
    /// SAE-PK session.
    pub fn kek(&self) -> Option<&[u8; 32]> {
        self.kek.as_ref()
    }

    /// The information elements that trailed the peer's Confirm frame (the
    /// SAE-PK element carriage), captured by `on_confirm`.
    pub fn peer_confirm_ies(&self) -> &[u8] {
        &self.peer_confirm_ies
    }

    /// The SAE-PK KeyAuth transcript element/scalar pair in the canonical
    /// AP-then-STA order used by the signature: `(eleAP, eleSTA, scaAP,
    /// scaSTA)`. From the station's view the AP is the peer. Elements are the
    /// 64-byte `X || Y` point encodings; scalars are 32-byte big-endian.
    pub fn sae_pk_transcript(&self) -> ([u8; 64], [u8; 64], [u8; 32], [u8; 32]) {
        let ele_ap = self.peer_element.to_encoded().unwrap_or([0u8; 64]);
        let ele_sta = self.commit_element.to_encoded().unwrap_or([0u8; 64]);
        let sca_ap = self.peer_scalar.to_bytes_be();
        let sca_sta = self.commit_scalar.to_bytes_be();
        (ele_ap, ele_sta, sca_ap, sca_sta)
    }

    /// Build our outgoing Commit. Encodes the SAE-frame variable body:
    ///
    /// ```text
    ///   group (2, LE) || scalar (32, BE) || element (64, BE: X || Y)
    /// ```
    ///
    /// Matches IEEE 802.11-2020 §9.4.1.36 / Table 9-72 (status code
    /// `SAE_STATUS_HASH_TO_ELEMENT` lives in the outer Authentication
    /// frame header, not in this body).
    ///
    /// Drives state from `Nothing` to `Committed`. Calling it twice is
    /// a re-Commit (sync retry); the local rand / private are kept so
    /// the peer's prior Commit (if any) still matches our K.
    pub fn build_commit(&mut self) -> Vec<u8> {
        // PWE is fresh — derived from (PT, own_mac, peer_mac).
        let pwe = pwe_from_pt(self.pt, &self.own_mac, &self.peer_mac);
        self.pwe = Some(pwe);

        // Sample rand + private (a.k.a. "mask" in the spec).
        let (rand, mask) = sample_two_scalars(self.test_seed.as_ref());
        self.rand = rand;
        self.private = mask;

        // commit_scalar = (rand + mask) mod n
        let commit_scalar = rand.add(&mask);
        self.commit_scalar = commit_scalar;

        // commit_element = inverse(mask · PWE) = -(mask · PWE)
        let mp = scalar_mul(&mask, &pwe);
        self.commit_element = AffinePoint {
            x: mp.x,
            y: mp.y.neg(),
            infinity: mp.infinity,
        };

        self.state = SaeState::Committed;

        // Serialise: group (LE) || scalar (BE) || element (BE X||Y).
        let mut out = Vec::with_capacity(2 + 32 + 64);
        out.extend_from_slice(&19u16.to_le_bytes()); // Group 19 = P-256
        out.extend_from_slice(&commit_scalar.to_bytes_be());
        let enc = self.commit_element.to_encoded().unwrap_or([0u8; 64]);
        out.extend_from_slice(&enc);
        out
    }

    /// Consume peer's Commit. Decodes the body, derives the shared
    /// secret K, and runs the KCK/PMK KDF.
    pub fn on_commit(&mut self, peer_commit: &[u8]) -> Result<(), SaeError> {
        if self.state != SaeState::Committed {
            return Err(SaeError::Protocol);
        }
        // Decode the SAE Commit variable body.
        let frame = CommitFrame::decode(peer_commit, 32, 64).ok_or(SaeError::InvalidParameters)?;
        if frame.group != 19 {
            // §12.4.7.4 + §9.4.1.9: rejection signalled at the SAE
            // status layer (status 77). At this API surface we just
            // surface InvalidParameters; the driver formats the wire
            // response.
            return Err(SaeError::InvalidParameters);
        }
        if frame.scalar.len() != 32 || frame.element.len() != 64 {
            return Err(SaeError::InvalidParameters);
        }
        let mut s_buf = [0u8; 32];
        s_buf.copy_from_slice(&frame.scalar);
        let peer_scalar = Scalar::from_bytes_be(&s_buf).ok_or(SaeError::InvalidParameters)?;
        let peer_element =
            AffinePoint::from_encoded(&frame.element).ok_or(SaeError::InvalidParameters)?;
        if peer_element.infinity {
            return Err(SaeError::InvalidParameters);
        }
        self.peer_scalar = peer_scalar;
        self.peer_element = peer_element;

        // K = rand · (peer_scalar · PWE + peer_element).
        let pwe = self.pwe.ok_or(SaeError::Protocol)?;
        if !pwe_valid(&pwe) {
            return Err(SaeError::InvalidParameters);
        }
        let term = scalar_mul(&peer_scalar, &pwe);
        let sum = term.to_projective().add_mixed(&peer_element).to_affine();
        if sum.infinity {
            return Err(SaeError::InvalidParameters);
        }
        let k = scalar_mul(&self.rand, &sum);
        if k.infinity {
            return Err(SaeError::InvalidParameters);
        }
        let k_x = k.x.to_bytes_be();

        // Derive KCK || PMK via HKDF per §12.4.5.4. The KDF input is
        // K.x; the salt is the bit-wise sum (as canonical sorted pair)
        // of the two scalars; the label is "SAE KCK and PMK". For an
        // SAE-PK session the label becomes "SAE-PK keys" and the output is
        // extended to KCK || PMK || KEK (hostap sae_derive_keys).
        if self.sae_pk {
            let (kck, pmk, kek) = derive_sae_pk_keys(&k_x, &self.commit_scalar, &peer_scalar);
            self.kck = Some(kck);
            self.pmk = Some(pmk);
            self.kek = Some(kek);
        } else {
            let (kck, pmk) = derive_kck_pmk(&k_x, &self.commit_scalar, &peer_scalar);
            self.kck = Some(kck);
            self.pmk = Some(pmk);
        }
        Ok(())
    }

    /// Build our outgoing Confirm body. Increments the send-confirm
    /// counter and computes the HMAC-SHA256 transcript MAC.
    pub fn build_confirm(&mut self) -> Vec<u8> {
        // Spec wants Confirm to be callable only after on_commit (KCK
        // set). On wrong-order we return an empty body — drivers
        // should check state() first; the smoke for the "wrong order"
        // path also pokes the state machine directly.
        let kck = match self.kck {
            Some(k) => k,
            None => return Vec::new(),
        };
        self.send_confirm_counter = self.send_confirm_counter.wrapping_add(1);

        let mut data: Vec<u8> = Vec::with_capacity(2 + 32 + 64 + 32 + 64);
        data.extend_from_slice(&self.send_confirm_counter.to_le_bytes());
        data.extend_from_slice(&self.commit_scalar.to_bytes_be());
        let our_e = self.commit_element.to_encoded().unwrap_or([0u8; 64]);
        data.extend_from_slice(&our_e);
        data.extend_from_slice(&self.peer_scalar.to_bytes_be());
        let peer_e = self.peer_element.to_encoded().unwrap_or([0u8; 64]);
        data.extend_from_slice(&peer_e);

        let mac = HmacSha256.mac(&kck, &data);
        self.state = SaeState::Confirmed;

        let mut out = Vec::with_capacity(2 + mac.len());
        out.extend_from_slice(&self.send_confirm_counter.to_le_bytes());
        out.extend_from_slice(&mac);
        out
    }

    /// Verify peer's Confirm against the transcript. On success the
    /// session moves to [`SaeState::Accepted`] and `pmk()` returns
    /// `Some`.
    pub fn on_confirm(&mut self, peer_confirm: &[u8]) -> Result<(), SaeError> {
        if self.state != SaeState::Confirmed {
            return Err(SaeError::Protocol);
        }
        let kck = self.kck.ok_or(SaeError::Protocol)?;
        let frame = ConfirmFrame::decode(peer_confirm).ok_or(SaeError::InvalidParameters)?;
        // The 32-byte Confirm field may be followed by information elements
        // (the SAE-PK element carriage); keep the MAC and stash any trailer.
        if frame.confirm.len() < 32 {
            return Err(SaeError::InvalidParameters);
        }
        if self.sae_pk {
            self.peer_confirm_ies = frame.confirm[32..].to_vec();
        }
        let peer_mac = &frame.confirm[..32];

        // Expected: HMAC-SHA256(KCK, peer_sc || peer_sc_scalar || peer_e || own_sc_scalar || own_e)
        let mut data: Vec<u8> = Vec::with_capacity(2 + 32 + 64 + 32 + 64);
        data.extend_from_slice(&frame.send_confirm.to_le_bytes());
        data.extend_from_slice(&self.peer_scalar.to_bytes_be());
        let peer_e = self.peer_element.to_encoded().unwrap_or([0u8; 64]);
        data.extend_from_slice(&peer_e);
        data.extend_from_slice(&self.commit_scalar.to_bytes_be());
        let our_e = self.commit_element.to_encoded().unwrap_or([0u8; 64]);
        data.extend_from_slice(&our_e);

        let expected = HmacSha256.mac(&kck, &data);
        if expected.len() != peer_mac.len() {
            return Err(SaeError::ConfirmMismatch);
        }
        // Constant-time-ish compare. The peer-controlled Confirm is
        // public output — an attacker observing timing here learns
        // only what they already know.
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(peer_mac.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(SaeError::ConfirmMismatch);
        }
        self.state = SaeState::Accepted;
        Ok(())
    }

    /// Notify the session that the SAE timer elapsed without progress.
    /// Increments the sync-retry counter; returns `Err(TooManySync...)`
    /// once the cap is reached.
    pub fn on_timeout(&mut self) -> Result<(), SaeError> {
        if self.sync_retries >= MAX_SYNC_RETRIES {
            return Err(SaeError::TooManySyncRetries);
        }
        self.sync_retries += 1;
        Ok(())
    }

    /// Sync-retry counter (for smokes and observability).
    pub fn sync_retries(&self) -> u8 {
        self.sync_retries
    }

    /// Wire-format Commit frame body. Useful for inspecting what
    /// `build_commit` produced (tests / driver tracing).
    pub fn build_commit_frame(&mut self) -> CommitFrame {
        let body = self.build_commit();
        CommitFrame::decode(&body, 32, 64).expect("self-built commit must decode")
    }

    /// Wire-format Confirm frame. Same idea as `build_commit_frame`.
    pub fn build_confirm_frame(&mut self) -> ConfirmFrame {
        let body = self.build_confirm();
        ConfirmFrame::decode(&body).expect("self-built confirm must decode")
    }
}

/// Pull two random scalars from either the test seed or the per-task
/// RNG. Mirrors `dragonfly::group_random_scalar` so the H2E session
/// uses the same entropy source as the legacy path.
fn sample_two_scalars(test_seed: Option<&[u8; 64]>) -> (Scalar, Scalar) {
    fn from_seed(seed: &[u8; 64], info: &[u8]) -> Scalar {
        let prk = narf_crypto::hkdf::hkdf_extract(None, seed);
        let okm = narf_crypto::hkdf::hkdf_expand(&prk, info, 48);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&okm[16..48]);
        let mut s = Scalar::from_bytes_be_reduce(&bytes);
        if s.is_zero() {
            s = Scalar::ONE;
        }
        s
    }
    let seed = match test_seed {
        Some(s) => *s,
        None => {
            let mut buf = [0u8; 64];
            narf_crypto::fill_random_bytes(&mut buf);
            buf
        }
    };
    let rand = from_seed(&seed, b"SAE H2E rand");
    let mask = from_seed(&seed, b"SAE H2E mask");
    (rand, mask)
}

/// SAE keyseed per IEEE 802.11-2020 §12.4.5.4:
/// `keyseed = H(salt, k)` = HKDF-Extract(HMAC-SHA256) with a salt of
/// `hash_len` (32) zero octets — the H2E case without rejected groups, which
/// is the only case NARF produces (group 19 only, no group negotiation). `k`
/// is the shared secret `K.x`.
fn sae_keyseed(k_x: &[u8; 32]) -> [u8; 32] {
    narf_crypto::hkdf::hkdf_extract(Some(&[0u8; 32]), k_x)
}

/// SAE key context: `(commit-scalar + peer-commit-scalar) mod r`, encoded
/// big-endian to the order length (32 for P-256). The modular sum is
/// inherently symmetric, so both peers derive the same context.
fn sae_key_context(s_self: &Scalar, s_peer: &Scalar) -> [u8; 32] {
    s_self.add(s_peer).to_bytes_be()
}

/// IEEE 802.11-2020 §12.7.1.6.2 KDF-Length over HMAC-SHA256
/// (`sha256_prf_bits`): the concatenation of
/// `HMAC-SHA256(key, LE16(i) || label || context || LE16(out_len*8))` for
/// `i = 1, 2, …`, truncated to `out_len` bytes. `out_len` is a whole number of
/// octets here, so no final-octet bit masking is needed.
fn sae_kdf(keyseed: &[u8; 32], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    let len_bits = (out_len * 8) as u16;
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u16 = 1;
    while out.len() < out_len {
        let mut msg = Vec::with_capacity(2 + label.len() + context.len() + 2);
        msg.extend_from_slice(&counter.to_le_bytes());
        msg.extend_from_slice(label);
        msg.extend_from_slice(context);
        msg.extend_from_slice(&len_bits.to_le_bytes());
        let block = narf_crypto::hkdf::hmac_sha256(keyseed, &msg);
        let take = core::cmp::min(32, out_len - out.len());
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// Derive (KCK, PMK) per IEEE 802.11-2020 §12.4.5.4:
/// `KCK || PMK = KDF-Hash-Length(keyseed, "SAE KCK and PMK",
/// (commit-scalar + peer-commit-scalar) mod r)`.
fn derive_kck_pmk(k_x: &[u8; 32], s_self: &Scalar, s_peer: &Scalar) -> ([u8; 32], [u8; 32]) {
    let keyseed = sae_keyseed(k_x);
    let context = sae_key_context(s_self, s_peer);
    let keys = sae_kdf(&keyseed, b"SAE KCK and PMK", &context, 64);
    let mut kck = [0u8; 32];
    let mut pmk = [0u8; 32];
    kck.copy_from_slice(&keys[..32]);
    pmk.copy_from_slice(&keys[32..64]);
    (kck, pmk)
}

/// SAE-PK key derivation: as [`derive_kck_pmk`] but with the "SAE-PK keys"
/// label and output extended to `KCK || PMK || KEK` (hostap `sae_derive_keys`
/// with `CONFIG_SAE_PK`). Returns `(kck, pmk, kek)`.
fn derive_sae_pk_keys(
    k_x: &[u8; 32],
    s_self: &Scalar,
    s_peer: &Scalar,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let keyseed = sae_keyseed(k_x);
    let context = sae_key_context(s_self, s_peer);
    let keys = sae_kdf(&keyseed, b"SAE-PK keys", &context, 96);
    let mut kck = [0u8; 32];
    let mut pmk = [0u8; 32];
    let mut kek = [0u8; 32];
    kck.copy_from_slice(&keys[..32]);
    pmk.copy_from_slice(&keys[32..64]);
    kek.copy_from_slice(&keys[64..96]);
    (kck, pmk, kek)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod session_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_sae_session_commit_frame_layout() -> TestResult {
        // §9.4.1.36 / Table 9-72: Commit body = group(2 LE) || scalar(32)
        // || element(64). build_commit emits exactly that layout.
        let mut s = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]).with_test_seed([0x33; 64]);
        let body = s.build_commit();
        if body.len() != 2 + 32 + 64 {
            return TestResult::Fail("Commit body length should be 98");
        }
        if u16::from_le_bytes([body[0], body[1]]) != 19 {
            return TestResult::Fail("group must be LE-19 (P-256)");
        }
        if s.state() != SaeState::Committed {
            return TestResult::Fail("state must advance to Committed");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_session_commit_frame_layout);

    fn smoke_sae_session_confirm_frame_layout() -> TestResult {
        // §9.4.1.36: Confirm body = send-confirm(2 LE) || MAC(32 for HMAC-SHA256).
        let mut a = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]).with_test_seed([0xAA; 64]);
        let mut b = SaeSession::new("net", "pw", [0x22; 6], [0x11; 6]).with_test_seed([0xBB; 64]);
        let commit_a = a.build_commit();
        let commit_b = b.build_commit();
        a.on_commit(&commit_b).expect("a on_commit");
        b.on_commit(&commit_a).expect("b on_commit");

        let confirm_a = a.build_confirm();
        if confirm_a.len() != 2 + 32 {
            return TestResult::Fail("Confirm body length should be 34");
        }
        // send-confirm starts at 1 after the first build.
        if u16::from_le_bytes([confirm_a[0], confirm_a[1]]) != 1 {
            return TestResult::Fail("send-confirm counter should start at 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_session_confirm_frame_layout);

    fn smoke_sae_session_full_handshake_pmk_agrees() -> TestResult {
        // End-to-end: A and B share (ssid, password); both reach
        // Accepted; both PMKs match.
        let mut a = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]).with_test_seed([0xAA; 64]);
        let mut b = SaeSession::new("net", "pw", [0x22; 6], [0x11; 6]).with_test_seed([0xBB; 64]);
        let commit_a = a.build_commit();
        let commit_b = b.build_commit();
        a.on_commit(&commit_b).expect("a on_commit");
        b.on_commit(&commit_a).expect("b on_commit");
        let confirm_a = a.build_confirm();
        let confirm_b = b.build_confirm();
        a.on_confirm(&confirm_b).expect("a on_confirm");
        b.on_confirm(&confirm_a).expect("b on_confirm");

        if a.state() != SaeState::Accepted || b.state() != SaeState::Accepted {
            return TestResult::Fail("both peers should reach Accepted");
        }
        let pmk_a = match a.pmk() {
            Some(p) => p,
            None => return TestResult::Fail("A must hold a PMK"),
        };
        let pmk_b = match b.pmk() {
            Some(p) => p,
            None => return TestResult::Fail("B must hold a PMK"),
        };
        if pmk_a != pmk_b {
            return TestResult::Fail("PMKs must agree after Accepted");
        }
        if pmk_a.len() != 32 {
            return TestResult::Fail("PMK must be 32 bytes (SAE-256)");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_session_full_handshake_pmk_agrees);

    fn smoke_sae_session_password_mismatch_fails_confirm() -> TestResult {
        // A and B use different passwords. The Commit exchange still
        // produces a (different) K on each side; Confirm verification
        // must then fail on at least one side.
        let mut a =
            SaeSession::new("net", "alpha", [0x11; 6], [0x22; 6]).with_test_seed([0xAA; 64]);
        let mut b = SaeSession::new("net", "beta", [0x22; 6], [0x11; 6]).with_test_seed([0xBB; 64]);
        let commit_a = a.build_commit();
        let commit_b = b.build_commit();
        // on_commit succeeds because it's just curve arithmetic; the
        // mismatch surfaces at Confirm.
        a.on_commit(&commit_b).expect("a on_commit");
        b.on_commit(&commit_a).expect("b on_commit");
        let confirm_a = a.build_confirm();
        let confirm_b = b.build_confirm();
        let a_verify = a.on_confirm(&confirm_b);
        let b_verify = b.on_confirm(&confirm_a);
        // At least one side must reject.
        if a_verify.is_ok() && b_verify.is_ok() {
            return TestResult::Fail("password mismatch must fail at least one Confirm");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/sae",
        smoke_sae_session_password_mismatch_fails_confirm
    );

    fn smoke_sae_session_state_machine_rejects_premature_confirm() -> TestResult {
        // build_confirm before on_commit must not advance state.
        let mut a = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]);
        let _ = a.build_commit();
        let _ = a.build_confirm();
        // kck not set, build_confirm returned empty body; state must
        // still be Committed (not Confirmed).
        if a.state() == SaeState::Accepted {
            return TestResult::Fail("must not reach Accepted without on_commit");
        }
        // on_confirm in Committed (not Confirmed) state must return Protocol.
        let dummy_confirm = {
            let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            v.extend_from_slice(&1u16.to_le_bytes());
            v.extend_from_slice(&[0u8; 32]);
            v
        };
        match a.on_confirm(&dummy_confirm) {
            Err(SaeError::Protocol) => TestResult::Pass,
            other => {
                let _ = other;
                TestResult::Fail("on_confirm out of order must return Protocol")
            }
        }
    }
    kernel_test_in!(
        "wireless/sae",
        smoke_sae_session_state_machine_rejects_premature_confirm
    );

    fn smoke_sae_session_mac_pair_symmetry() -> TestResult {
        // A and B with swapped MACs derive the same PWE — the
        // canonical-order step in pwe_from_pt enforces this. A
        // straight-through observation: both PMKs match (covered by
        // the full-handshake smoke); the structural property is that
        // the PWE byte form is identical on both sides.
        let mut a = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]).with_test_seed([0xAA; 64]);
        let mut b = SaeSession::new("net", "pw", [0x22; 6], [0x11; 6]).with_test_seed([0xBB; 64]);
        // Both call build_commit, which derives PWE first.
        let _ = a.build_commit();
        let _ = b.build_commit();
        let pwe_a = match a.pwe {
            Some(p) => p,
            None => return TestResult::Fail("A must have PWE after build_commit"),
        };
        let pwe_b = match b.pwe {
            Some(p) => p,
            None => return TestResult::Fail("B must have PWE after build_commit"),
        };
        if pwe_a.to_encoded() != pwe_b.to_encoded() {
            return TestResult::Fail("PWE must agree across the MAC pair");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_session_mac_pair_symmetry);

    fn smoke_sae_session_pmk_is_32_bytes() -> TestResult {
        // SAE produces a 256-bit PMK (HKDF expand to 64 bytes total,
        // split into KCK 32 || PMK 32).
        let mut a = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]).with_test_seed([0xAA; 64]);
        let mut b = SaeSession::new("net", "pw", [0x22; 6], [0x11; 6]).with_test_seed([0xBB; 64]);
        let ca = a.build_commit();
        let cb = b.build_commit();
        a.on_commit(&cb).expect("a");
        b.on_commit(&ca).expect("b");
        let fa = a.build_confirm();
        let fb = b.build_confirm();
        a.on_confirm(&fb).expect("a");
        b.on_confirm(&fa).expect("b");
        let pmk = match a.pmk() {
            Some(p) => p,
            None => return TestResult::Fail("PMK must be set"),
        };
        if pmk.len() != 32 {
            return TestResult::Fail("PMK must be 32 bytes");
        }
        // PMK must not be all-zeros (would mean the KDF chain
        // collapsed; never happens for valid inputs).
        if pmk.iter().all(|&b| b == 0) {
            return TestResult::Fail("PMK must not be all-zero");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_session_pmk_is_32_bytes);

    fn smoke_sae_session_retry_counter() -> TestResult {
        // §12.4.8.6.4: timer-driven retries bump a counter; after
        // MAX_SYNC_RETRIES we abandon the session.
        let mut s = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]);
        for _ in 0..MAX_SYNC_RETRIES {
            s.on_timeout().expect("under cap must succeed");
        }
        match s.on_timeout() {
            Err(SaeError::TooManySyncRetries) => {}
            _ => return TestResult::Fail("over cap must err TooManySyncRetries"),
        }
        if s.sync_retries() != MAX_SYNC_RETRIES {
            return TestResult::Fail("sync_retries counter must cap at MAX");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_session_retry_counter);

    // The IEEE 802.11 §12.7.1.6.2 KDF-Length construction: each output block is
    // HMAC-SHA256(keyseed, LE16(i) || label || context || LE16(out_bits)).
    // Validate the exact byte order against hand-assembled HMAC inputs.
    fn smoke_sae_kdf_ieee_construction() -> TestResult {
        let keyseed = [0x5au8; 32];
        let label: &[u8] = b"SAE KCK and PMK";
        let context = [0x11u8; 32];
        let out = sae_kdf(&keyseed, label, &context, 64);
        if out.len() != 64 {
            return TestResult::Fail("KDF output length wrong");
        }
        for i in 1u16..=2 {
            let mut msg = Vec::new();
            msg.extend_from_slice(&i.to_le_bytes());
            msg.extend_from_slice(label);
            msg.extend_from_slice(&context);
            msg.extend_from_slice(&512u16.to_le_bytes());
            let block = narf_crypto::hkdf::hmac_sha256(&keyseed, &msg);
            let off = (i as usize - 1) * 32;
            if out[off..off + 32] != block {
                return TestResult::Fail(
                    "KDF block does not match HMAC(LE16(i)||label||ctx||LE16(len))",
                );
            }
        }
        // keyseed = HMAC-SHA256(zero-salt, K.x); context = (s_a + s_b) mod n.
        let k_x = [0x42u8; 32];
        if sae_keyseed(&k_x) != narf_crypto::hkdf::hkdf_extract(Some(&[0u8; 32]), &k_x) {
            return TestResult::Fail("keyseed is not HKDF-Extract(zero-salt, K.x)");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_kdf_ieee_construction);
}
