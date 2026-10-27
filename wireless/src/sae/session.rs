//! [`SaeSession`] — the high-level WPA3 SAE H2E driver.
//!
//! Wraps the H2E PT/PWE derivation ([`super::pt`]), real P-256
//! arithmetic, and the Commit / Confirm transcript MAC into a single
//! type whose interface matches what drivers want:
//!
//! ```ignore
//! let mut s = SaeSession::new("MySSID", "password", own_mac, peer_mac);
//! let commit_out = s.try_build_commit()?;
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
use zeroize::Zeroizing;

use narf_crypto::p256::point::{scalar_mul, AffinePoint};
use narf_crypto::p256::scalar::Scalar;

use super::dragonfly::{CommitFrame, ConfirmFrame, HmacSha256, MacPrimitive, SaeError, SaeState};
use super::pt::{pt_h2e_bytes, pwe_from_pt, pwe_hunt_and_peck, pwe_valid};

/// `WLAN_EID_EXT_REJECTED_GROUPS`.
pub const EID_EXT_REJECTED_GROUPS: u8 = 92;
/// `WLAN_EID_EXT_ANTI_CLOGGING_TOKEN`.
pub const EID_EXT_ANTI_CLOGGING_TOKEN: u8 = 93;
/// `WLAN_EID_EXT_AKM_SUITE_SELECTOR` (hostap ieee802_11_defs.h).
pub const EID_EXT_AKM_SUITE_SELECTOR: u8 = 114;

/// How the session derives its PWE (hostap `sae->h2e`).
#[derive(Debug, Clone)]
enum PweSource {
    /// Hash-to-Element from the cached PT (`sae_prepare_commit_pt`).
    H2e(AffinePoint),
    /// Hunting and pecking over the password (`sae_prepare_commit`).
    HuntAndPeck(Vec<u8>),
}

/// SAE sync-retry limit (§12.4.8.6.4: `dot11RSNASAESync`, default 5).
const MAX_SYNC_RETRIES: u8 = 5;

/// SAE handshake driver implementing the H2E variant. Owns the cached
/// PT (so repeated handshakes with the same network skip the h2c
/// work) and the per-handshake transient state (rand / mask / PWE).
#[derive(Debug)]
pub struct SaeSession {
    state: SaeState,
    /// The PWE source: the Password Token (H2E, derived once per
    /// (ssid, password)) or the password (hunting and pecking).
    pwe_src: PweSource,
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
    /// Test override of `(rand, mask)` (the IEEE 802.11 Annex J.10
    /// vectors fix both).
    test_rand_mask: Option<(Scalar, Scalar)>,
    /// PMKID = L((commit-scalar + peer-commit-scalar) mod r, 0, 128).
    pmkid: Option<[u8; 16]>,
    /// The peer's Rejected Groups element payload (H2E), the keyseed salt.
    peer_rejected_groups: Vec<u8>,
    /// Our AKM Suite Selector element (hostap `own_akm_suite_selector`),
    /// sent in every Commit for an SAE-EXT-KEY (AKM 24) session.
    own_akm_suite: Option<[u8; 4]>,
    /// The peer Commit's AKM Suite Selector (`peer_akm_suite_selector`).
    peer_akm_suite: Option<[u8; 4]>,
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
        let pt = pt_h2e_bytes(
            ssid.as_bytes(),
            password.as_bytes(),
            identifier.map(str::as_bytes),
        );
        let mut s = Self::with_source(PweSource::H2e(pt), own_mac, peer_mac);
        s.sae_pk = super::pk::is_sae_pk_password(password);
        s
    }

    /// An H2E session over raw SSID / password octets.
    pub fn new_h2e_bytes(
        ssid: &[u8],
        password: &[u8],
        own_mac: [u8; 6],
        peer_mac: [u8; 6],
    ) -> Self {
        let pt = pt_h2e_bytes(ssid, password, None);
        let mut s = Self::with_source(PweSource::H2e(pt), own_mac, peer_mac);
        // Netlink and scan paths retain SSIDs/passwords as raw octets, so
        // drivers use this constructor rather than `new(&str, &str, ...)`.
        // SAE-PK passwords are ASCII by definition; recognize them here too
        // or the session would derive the ordinary SAE key schedule and lose
        // the KEK needed to authenticate the AP's KeyAuth Confirm element.
        s.sae_pk = core::str::from_utf8(password).is_ok_and(super::pk::is_sae_pk_password);
        s
    }

    /// A hunting-and-pecking session (hostap `sae_prepare_commit`, the
    /// Commit sent with status 0): the PWE comes from
    /// [`pwe_hunt_and_peck`] over `(password, own, peer)`.
    pub fn new_hunt_and_peck(password: &[u8], own_mac: [u8; 6], peer_mac: [u8; 6]) -> Self {
        let mut s = Self::with_source(PweSource::HuntAndPeck(password.to_vec()), own_mac, peer_mac);
        s.sae_pk = core::str::from_utf8(password).is_ok_and(super::pk::is_sae_pk_password);
        s
    }

    fn with_source(pwe_src: PweSource, own_mac: [u8; 6], peer_mac: [u8; 6]) -> Self {
        Self {
            state: SaeState::Nothing,
            pwe_src,
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
            sae_pk: false,
            peer_confirm_ies: Vec::new(),
            own_mac,
            peer_mac,
            send_confirm_counter: 0,
            sync_retries: 0,
            test_seed: None,
            test_rand_mask: None,
            pmkid: None,
            peer_rejected_groups: Vec::new(),
            own_akm_suite: None,
            peer_akm_suite: None,
        }
    }

    /// Bind this H2E session to an AKM Suite Selector element (hostap
    /// `sae_write_commit` for `wpa_key_mgmt_sae_ext_key`): every Commit
    /// carries it and the peer's Commit must carry the same selector
    /// (`sae_parse_commit`: "AKM suite selector mismatch"). hostap parses
    /// the peer's element only under H2E, so a hunting-and-pecking session
    /// cannot complete AKM 24 and is refused here.
    pub fn with_akm_suite_selector(mut self, suite: [u8; 4]) -> Result<Self, SaeError> {
        if !self.is_h2e() || self.state != SaeState::Nothing {
            return Err(SaeError::Protocol);
        }
        self.own_akm_suite = Some(suite);
        Ok(self)
    }

    /// Our AKM Suite Selector binding, if any.
    pub fn akm_suite_selector(&self) -> Option<[u8; 4]> {
        self.own_akm_suite
    }

    /// The `(own, peer)` MAC pair the PWE and transcript are bound to.
    pub fn addresses(&self) -> ([u8; 6], [u8; 6]) {
        (self.own_mac, self.peer_mac)
    }

    /// The peer Commit's AKM Suite Selector, once processed.
    pub fn peer_akm_suite_selector(&self) -> Option<[u8; 4]> {
        self.peer_akm_suite
    }

    /// Whether the PWE is Hash-to-Element (hostap `sae->h2e`): the Commit
    /// carries status 126 and the token goes in a container element.
    pub fn is_h2e(&self) -> bool {
        matches!(self.pwe_src, PweSource::H2e(_))
    }

    /// Test hook: fix `rand` and `mask` (big-endian, each in `[1, r)`)
    /// the way hostap's `sae_tests` overrides `sae->tmp->sae_rand`.
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn with_test_rand_mask(mut self, rand: [u8; 32], mask: [u8; 32]) -> Self {
        if let (Some(r), Some(m)) = (Scalar::from_bytes_be(&rand), Scalar::from_bytes_be(&mask)) {
            self.test_rand_mask = Some((r, m));
        }
        self
    }

    /// The PMKID (`sae->pmkid`) once the peer's Commit was processed.
    pub fn pmkid(&self) -> Option<&[u8; 16]> {
        self.pmkid.as_ref()
    }

    /// The Commit body for the current scalar / element (hostap
    /// `sae_write_commit`): group (LE) || [legacy token] || scalar ||
    /// element || [H2E Anti-Clogging Token Container]. An anti-clogging
    /// retry resends the same scalar and element with the AP's token
    /// (`sme_auth_build_sae_commit(.., reuse = 1)`). Empty before
    /// [`Self::build_commit`].
    pub fn commit_body(&self, token: Option<&[u8]>) -> Vec<u8> {
        if self.state == SaeState::Nothing {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(2 + 32 + 64 + token.map_or(0, |t| t.len() + 3));
        out.extend_from_slice(&19u16.to_le_bytes()); // Group 19 = P-256
        if let (false, Some(t)) = (self.is_h2e(), token) {
            out.extend_from_slice(t);
        }
        out.extend_from_slice(&self.commit_scalar.to_bytes_be());
        out.extend_from_slice(&self.commit_element.to_encoded().unwrap_or([0u8; 64]));
        if let (true, Some(t)) = (self.is_h2e(), token) {
            out.push(0xFF); // WLAN_EID_EXTENSION
            out.push((1 + t.len()) as u8);
            out.push(EID_EXT_ANTI_CLOGGING_TOKEN);
            out.extend_from_slice(t);
        }
        if let Some(suite) = self.own_akm_suite {
            out.extend_from_slice(&[0xFF, 5, EID_EXT_AKM_SUITE_SELECTOR]);
            out.extend_from_slice(&suite);
        }
        out
    }

    /// Test hook: seed the per-handshake RNG with a deterministic
    /// 64-byte value so smokes can re-derive the same Commit pair.
    /// Production callers do not use this — `new` pulls entropy from
    /// guarded hardware entropy, with no timing-seeded fallback.
    #[cfg(any(test, feature = "kernel-test"))]
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
        self.try_build_commit().unwrap_or_default()
    }

    /// Build a commit only with secure entropy. Failure exposes no Commit and
    /// leaves all ephemeral/state fields unchanged. Retries return the same
    /// cached scalar/element without resampling or resetting the transcript.
    pub fn try_build_commit(&mut self) -> Result<Vec<u8>, SaeError> {
        self.try_build_commit_with_entropy(|out| {
            narf_crypto::try_fill_random_bytes(out).map_err(|_| SaeError::EntropyUnavailable)
        })
    }
    /// Use a driver's entropy provider. The provider must fill every requested
    /// byte with unpredictable secure randomness, or return EntropyUnavailable;
    /// timing counters and deterministic fallbacks are forbidden. Partial output
    /// is private and zeroized on failure. A committed retry does not call it.
    pub fn try_build_commit_with_entropy(
        &mut self,
        mut entropy: impl FnMut(&mut [u8]) -> Result<(), SaeError>,
    ) -> Result<Vec<u8>, SaeError> {
        match self.state {
            SaeState::Committed => return Ok(self.commit_body(None)),
            SaeState::Nothing => {}
            _ => return Err(SaeError::Protocol),
        }
        let pwe = match &self.pwe_src {
            PweSource::H2e(pt) => pwe_from_pt(*pt, &self.own_mac, &self.peer_mac),
            PweSource::HuntAndPeck(pw) => pwe_hunt_and_peck(pw, &self.own_mac, &self.peer_mac)
                .map(|(p, _)| p)
                .ok_or(SaeError::InvalidParameters)?,
        };
        if pwe.infinity {
            return Err(SaeError::InvalidParameters);
        }
        let (rand, mask, commit_scalar) = match self.test_rand_mask {
            Some((r, m)) => (r, m, r.add(&m)),
            None => {
                let mut sampled = None;
                for retry in 0..16 {
                    let (r, m) = sample_two_scalars(self.test_seed.as_ref(), retry, &mut entropy)?;
                    let c = r.add(&m);
                    if !c.is_zero() && c != Scalar::ONE {
                        sampled = Some((r, m, c));
                        break;
                    }
                }
                sampled.ok_or(SaeError::InvalidParameters)?
            }
        };
        if rand.is_zero()
            || mask.is_zero()
            || commit_scalar.is_zero()
            || commit_scalar == Scalar::ONE
        {
            return Err(SaeError::InvalidParameters);
        }
        let mp = scalar_mul(&mask, &pwe);
        let commit_element = AffinePoint {
            x: mp.x,
            y: mp.y.neg(),
            infinity: mp.infinity,
        };
        if commit_element.to_encoded().is_none() {
            return Err(SaeError::InvalidParameters);
        }
        // Commit only after entropy, geometry and scalar/point checks succeed.
        self.pwe = Some(pwe);
        self.rand = rand;
        self.private = mask;
        self.commit_scalar = commit_scalar;
        self.commit_element = commit_element;
        self.state = SaeState::Committed;
        Ok(self.commit_body(None))
    }

    /// Consume the peer's Commit body (after the Authentication frame's
    /// algorithm / transaction / status), as hostap `sae_parse_commit` +
    /// `sae_process_commit`: group 19 (`sae_group_allowed`), commit-scalar
    /// in `(1, r)` (`sae_parse_commit_scalar`), COMMIT-ELEMENT on the
    /// curve (`sae_parse_commit_element`); for H2E the trailing Rejected
    /// Groups element (which must not name group 19,
    /// `sme_check_sae_rejected_groups`) feeds the keyseed salt; a Commit
    /// equal to ours is a reflection (`SAE_SILENTLY_DISCARD` →
    /// [`SaeError::Reflection`]). Then `K = rand · (peer-scalar · PWE +
    /// PEER-ELEMENT)`, keyseed, KCK || PMK, PMKID (`sae_derive_keys`).
    pub fn on_commit(&mut self, peer_commit: &[u8]) -> Result<(), SaeError> {
        if self.state != SaeState::Committed {
            return Err(SaeError::Protocol);
        }
        let frame = CommitFrame::decode(peer_commit, 32, 64).ok_or(SaeError::InvalidParameters)?;
        if frame.group != 19 {
            // WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED at the
            // frame layer; the driver formats the response.
            return Err(SaeError::InvalidParameters);
        }
        let mut s_buf = [0u8; 32];
        s_buf.copy_from_slice(&frame.scalar);
        let peer_scalar = Scalar::from_bytes_be(&s_buf).ok_or(SaeError::InvalidParameters)?;
        // "Invalid peer scalar": scalar <= 1 or >= r.
        if peer_scalar.is_zero() || peer_scalar == Scalar::ONE {
            return Err(SaeError::InvalidParameters);
        }
        let peer_element =
            AffinePoint::from_encoded(&frame.element).ok_or(SaeError::InvalidParameters)?;
        if peer_element.infinity || !peer_element.is_on_curve() {
            return Err(SaeError::InvalidParameters);
        }
        // H2E elements after the element (Rejected Groups; the
        // Anti-Clogging Token Container is skipped).
        let mut rejected = Vec::new();
        let mut peer_akm = None;
        if self.is_h2e() {
            let mut rest = &peer_commit[2 + 32 + 64..];
            while rest.len() >= 3 && rest[0] == 0xFF {
                let len = rest[1] as usize;
                if len == 0 || rest.len() < 2 + len {
                    break;
                }
                if rest[2] == EID_EXT_REJECTED_GROUPS {
                    let groups = &rest[3..2 + len];
                    // sae_parse_rejected_groups: a list of 16-bit groups.
                    if groups.len() % 2 != 0 {
                        return Err(SaeError::InvalidParameters);
                    }
                    // sme_check_sae_rejected_groups: the AP claims it
                    // rejected a group we would have used.
                    if groups
                        .chunks(2)
                        .any(|g| u16::from_le_bytes([g[0], g[1]]) == 19)
                    {
                        return Err(SaeError::InvalidParameters);
                    }
                    rejected = groups.to_vec();
                }
                if rest[2] == EID_EXT_AKM_SUITE_SELECTOR {
                    // sae_parse_akm_suite_selector: at least one selector.
                    let body = &rest[3..2 + len];
                    peer_akm = Some(
                        <[u8; 4]>::try_from(body.get(..4).ok_or(SaeError::InvalidParameters)?)
                            .map_err(|_| SaeError::InvalidParameters)?,
                    );
                }
                rest = &rest[2 + len..];
            }
        }
        if self.own_akm_suite.is_some() && self.own_akm_suite != peer_akm {
            // "SAE: AKM suite selector mismatch".
            return Err(SaeError::InvalidParameters);
        }
        // Reflection check: the peer sent our own scalar and element.
        if peer_scalar == self.commit_scalar
            && peer_element.to_encoded() == self.commit_element.to_encoded()
        {
            return Err(SaeError::Reflection);
        }
        self.peer_scalar = peer_scalar;
        self.peer_element = peer_element;
        self.peer_rejected_groups = rejected;
        self.peer_akm_suite = peer_akm;

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

        // sae_derive_keys: keyseed = H(salt, k); salt = the rejected
        // groups (H2E, the peer's list: we never reject one) or 32 zeros.
        let keyseed = sae_keyseed(&k_x, &self.peer_rejected_groups);
        let context = sae_key_context(&self.commit_scalar, &peer_scalar);
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(&context[..16]);
        self.pmkid = Some(pmkid);
        let take = |b: &[u8]| -> [u8; 32] {
            let mut k = [0u8; 32];
            k.copy_from_slice(b);
            k
        };
        if self.sae_pk {
            let keys = kdf_sha256(&keyseed, b"SAE-PK keys", &context, 96);
            self.kck = Some(take(&keys[..32]));
            self.pmk = Some(take(&keys[32..64]));
            self.kek = Some(take(&keys[64..96]));
        } else {
            let keys = kdf_sha256(&keyseed, b"SAE KCK and PMK", &context, 64);
            self.kck = Some(take(&keys[..32]));
            self.pmk = Some(take(&keys[32..64]));
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
    pub fn try_build_commit_frame(&mut self) -> Result<CommitFrame, SaeError> {
        CommitFrame::decode(&self.try_build_commit()?, 32, 64).ok_or(SaeError::InvalidParameters)
    }
    /// Legacy wrapper: an entropy failure returns empty scalar/element fields
    /// and never advances the session. Transmitters must use the fallible API.
    pub fn build_commit_frame(&mut self) -> CommitFrame {
        self.try_build_commit_frame()
            .unwrap_or_else(|_| CommitFrame {
                group: 19,
                scalar: Vec::new(),
                element: Vec::new(),
            })
    }

    /// Wire-format Confirm frame. Same idea as `build_commit_frame`.
    pub fn build_confirm_frame(&mut self) -> ConfirmFrame {
        let body = self.build_confirm();
        ConfirmFrame::decode(&body).expect("self-built confirm must decode")
    }
}

/// Sample separate nonzero scalars without modular-reduction bias. Production
/// obtains independent 32-byte candidates; explicit fixture seeds use separate
/// domain/counter expansions and change their transcript on a pair retry.
fn sample_two_scalars(
    test_seed: Option<&[u8; 64]>,
    retry: u8,
    entropy: &mut impl FnMut(&mut [u8]) -> Result<(), SaeError>,
) -> Result<(Scalar, Scalar), SaeError> {
    use super::dragonfly::{random_scalar_from_seed, sample_scalar};
    match test_seed {
        Some(seed) => {
            let mut seed = Zeroizing::new(*seed);
            seed[0] ^= retry;
            Ok((
                random_scalar_from_seed(&seed, b"SAE H2E rand")?,
                random_scalar_from_seed(&seed, b"SAE H2E mask")?,
            ))
        }
        None => Ok((
            sample_scalar(|_, candidate| entropy(candidate))?,
            sample_scalar(|_, candidate| entropy(candidate))?,
        )),
    }
}

/// SAE keyseed (IEEE 802.11-2020 §12.4.5.4, hostap `sae_derive_keys`):
/// `keyseed = HKDF-Extract(salt, K.x)` with the H2E rejected-groups list
/// as the salt when one was exchanged, else 32 zero octets.
fn sae_keyseed(k_x: &[u8; 32], rejected_groups: &[u8]) -> [u8; 32] {
    if rejected_groups.is_empty() {
        narf_crypto::hkdf::hkdf_extract(Some(&[0u8; 32]), k_x)
    } else {
        narf_crypto::hkdf::hkdf_extract(Some(rejected_groups), k_x)
    }
}

/// SAE key context: `(commit-scalar + peer-commit-scalar) mod r`, encoded
/// big-endian to the order length (32 for P-256).
fn sae_key_context(s_self: &Scalar, s_peer: &Scalar) -> [u8; 32] {
    s_self.add(s_peer).to_bytes_be()
}

/// IEEE 802.11-2020 §12.7.1.6.2 KDF-Hash-Length over HMAC-SHA256 (hostap
/// `sha256_prf` / `sha256_prf_bits` for whole octets): the concatenation
/// of `HMAC-SHA256(key, LE16(i) || label || context || LE16(out_len·8))`
/// for `i = 1, 2, …`, truncated to `out_len` octets. Shared by SAE
/// (`sae_kdf_hash`, hunting and pecking) and the SHA-256 AKMs' PTK
/// (`wpa_pmk_to_ptk` → `sha256_prf`), so the Annex J.10 vector pins both.
pub fn kdf_sha256(key: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    let len_bits = (out_len * 8) as u16;
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u16 = 1;
    while out.len() < out_len {
        let mut msg = Vec::with_capacity(2 + label.len() + context.len() + 2);
        msg.extend_from_slice(&counter.to_le_bytes());
        msg.extend_from_slice(label);
        msg.extend_from_slice(context);
        msg.extend_from_slice(&len_bits.to_le_bytes());
        let block = narf_crypto::hkdf::hmac_sha256(key, &msg);
        let take = core::cmp::min(32, out_len - out.len());
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod session_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_sae_entropy_failure_preserves_commit_state_and_retry() -> TestResult {
        for hp in [false, true] {
            let mut s = if hp {
                SaeSession::new_hunt_and_peck(b"pw", [0x11; 6], [0x22; 6])
            } else {
                SaeSession::new("net", "pw", [0x11; 6], [0x22; 6])
            };
            if s.try_build_commit_with_entropy(|out| {
                out[..32].fill(0xaa);
                Err(SaeError::EntropyUnavailable)
            }) != Err(SaeError::EntropyUnavailable)
                || s.state() != SaeState::Nothing
                || s.pwe.is_some()
                || s.rand != Scalar::ZERO
                || s.private != Scalar::ZERO
                || !s.commit_body(None).is_empty()
                || s.pmk().is_some()
            {
                return TestResult::Fail("failed SAE entropy published/retained a partial commit");
            }
            let commit = s
                .try_build_commit_with_entropy(|out| {
                    out.fill(0x55);
                    Ok(())
                })
                .unwrap();
            if commit.len() != 98
                || s.state() != SaeState::Committed
                || s.try_build_commit_with_entropy(|_| Err(SaeError::EntropyUnavailable))
                    != Ok(commit)
            {
                return TestResult::Fail(
                    "SAE retry resampled instead of retaining committed scalars",
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/sae",
        smoke_sae_entropy_failure_preserves_commit_state_and_retry
    );

    fn smoke_sae_scalar_rejection_keeps_session_uncommitted() -> TestResult {
        let mut session = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]);
        let mut calls = 0;
        if session.try_build_commit_with_entropy(|bytes| {
            calls += 1;
            bytes.fill(0);
            Ok(())
        }) != Err(SaeError::InvalidParameters)
            || calls != 16
            || session.state() != SaeState::Nothing
            || session.pwe.is_some()
            || session.rand != Scalar::ZERO
            || session.private != Scalar::ZERO
            || !session.commit_body(None).is_empty()
        {
            return TestResult::Fail("bounded rejection published a zero/partial SAE commit");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/sae",
        smoke_sae_scalar_rejection_keeps_session_uncommitted
    );

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
        let mut a = SaeSession::new("net", "pw", [0x11; 6], [0x22; 6]).with_test_seed([0x11; 64]);
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
        let out = kdf_sha256(&keyseed, label, &context, 64);
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
        if sae_keyseed(&k_x, &[]) != narf_crypto::hkdf::hkdf_extract(Some(&[0u8; 32]), &k_x) {
            return TestResult::Fail("keyseed is not HKDF-Extract(zero-salt, K.x)");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_kdf_ieee_construction);
    // ── IEEE Std 802.11-2020 Annex J.10 (hostap `sae_tests`) ─────────

    const J10_ADDR1: [u8; 6] = [0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87];
    const J10_ADDR2: [u8; 6] = [0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c];
    const J10_RAND: [u8; 32] = [
        0x99, 0x24, 0x65, 0xfd, 0x3d, 0xaa, 0x3c, 0x60, 0xaa, 0x65, 0x65, 0xb7, 0xf6, 0x2a, 0x2a,
        0x7f, 0x2e, 0x12, 0xdd, 0x12, 0xf1, 0x98, 0xfa, 0xf4, 0xfb, 0xed, 0x89, 0xd7, 0xff, 0x1a,
        0xce, 0x94,
    ];
    const J10_MASK: [u8; 32] = [
        0x95, 0x07, 0xa9, 0x0f, 0x77, 0x7a, 0x04, 0x4d, 0x6a, 0x08, 0x30, 0xb9, 0x1e, 0xa3, 0xd5,
        0xdd, 0x70, 0xbe, 0xce, 0x44, 0xe1, 0xac, 0xff, 0xb8, 0x69, 0x83, 0xb5, 0xe1, 0xbf, 0x9f,
        0xb3, 0x22,
    ];
    pub(crate) const J10_LOCAL_COMMIT: [u8; 98] = [
        0x13, 0x00, 0x2e, 0x2c, 0x0f, 0x0d, 0xb5, 0x24, 0x40, 0xad, 0x14, 0x6d, 0x96, 0x71, 0x14,
        0xce, 0x00, 0x5c, 0xe1, 0xea, 0xb0, 0xaa, 0x2c, 0x2e, 0x5c, 0x28, 0x71, 0xb7, 0x74, 0xf6,
        0xc2, 0x57, 0x5c, 0x65, 0xd5, 0xad, 0x9e, 0x00, 0x82, 0x97, 0x07, 0xaa, 0x36, 0xba, 0x8b,
        0x85, 0x97, 0x38, 0xfc, 0x96, 0x1d, 0x08, 0x24, 0x35, 0x05, 0xf4, 0x7c, 0x03, 0x53, 0x76,
        0xd7, 0xac, 0x4b, 0xc8, 0xd7, 0xb9, 0x50, 0x83, 0xbf, 0x43, 0x82, 0x7d, 0x0f, 0xc3, 0x1e,
        0xd7, 0x78, 0xdd, 0x36, 0x71, 0xfd, 0x21, 0xa4, 0x6d, 0x10, 0x91, 0xd6, 0x4b, 0x6f, 0x9a,
        0x1e, 0x12, 0x72, 0x62, 0x13, 0x25, 0xdb, 0xe1,
    ];
    pub(crate) const J10_PEER_COMMIT: [u8; 98] = [
        0x13, 0x00, 0x59, 0x1b, 0x96, 0xf3, 0x39, 0x7f, 0xb9, 0x45, 0x10, 0x08, 0x48, 0xe7, 0xb5,
        0x50, 0x54, 0x3b, 0x67, 0x20, 0xd8, 0x83, 0x37, 0xee, 0x93, 0xfc, 0x49, 0xfd, 0x6d, 0xf7,
        0xe0, 0x8b, 0x52, 0x23, 0xe7, 0x1b, 0x9b, 0xb0, 0x48, 0xd3, 0x87, 0x3f, 0x20, 0x55, 0x69,
        0x53, 0xa9, 0x6c, 0x91, 0x53, 0x6f, 0xd8, 0xee, 0x6c, 0xa9, 0xb4, 0xa6, 0x8a, 0x14, 0x8b,
        0x05, 0x6a, 0x90, 0x9b, 0xe0, 0x3e, 0x83, 0xae, 0x20, 0x8f, 0x60, 0xf8, 0xef, 0x55, 0x37,
        0x85, 0x80, 0x74, 0xdb, 0x06, 0x68, 0x70, 0x32, 0x39, 0x98, 0x62, 0x99, 0x9b, 0x51, 0x1e,
        0x0a, 0x15, 0x52, 0xa5, 0xfe, 0xa3, 0x17, 0xc2,
    ];
    const J10_KCK: [u8; 32] = [
        0x1e, 0x73, 0x3f, 0x6d, 0x9b, 0xd5, 0x32, 0x56, 0x28, 0x73, 0x04, 0x33, 0x88, 0x31, 0xb0,
        0x9a, 0x39, 0x40, 0x6d, 0x12, 0x10, 0x17, 0x07, 0x3a, 0x5c, 0x30, 0xdb, 0x36, 0xf3, 0x6c,
        0xb8, 0x1a,
    ];
    const J10_PMK: [u8; 32] = [
        0x4e, 0x4d, 0xfa, 0xb1, 0xa2, 0xdd, 0x8a, 0xc1, 0xa9, 0x17, 0x90, 0xf9, 0x53, 0xfa, 0xaa,
        0x45, 0x2a, 0xe5, 0xc6, 0x87, 0x3a, 0xb7, 0x5b, 0x63, 0x60, 0x5b, 0xa6, 0x63, 0xf8, 0xa7,
        0xfe, 0x59,
    ];
    const J10_PMKID: [u8; 16] = [
        0x87, 0x47, 0xa6, 0x00, 0xee, 0xa3, 0xf9, 0xf2, 0x24, 0x75, 0xdf, 0x58, 0xca, 0x1e, 0x54,
        0x98,
    ];

    /// Hunting-and-pecking PWE, the Commit from fixed rand / mask, and
    /// KCK / PMK / PMKID after the peer's Commit: hostap
    /// `common_module_tests.c::sae_tests` (IEEE 802.11-2020 Annex J.10,
    /// password "mekmitasdigoat").
    fn smoke_sae_hunt_and_peck_ieee_j10_vector() -> TestResult {
        let mut s = SaeSession::new_hunt_and_peck(b"mekmitasdigoat", J10_ADDR1, J10_ADDR2)
            .with_test_rand_mask(J10_RAND, J10_MASK);
        if s.is_h2e() {
            return TestResult::Fail("hunting-and-pecking session reports H2E");
        }
        let commit = s.build_commit();
        if commit[..] != J10_LOCAL_COMMIT[..] {
            return TestResult::Fail("J.10 local commit");
        }
        if s.on_commit(&J10_PEER_COMMIT).is_err() {
            return TestResult::Fail("J.10 peer commit rejected");
        }
        if s.kck() != Some(&J10_KCK) {
            return TestResult::Fail("J.10 KCK");
        }
        if s.pmk() != Some(&J10_PMK) {
            return TestResult::Fail("J.10 PMK");
        }
        if s.pmkid() != Some(&J10_PMKID) {
            return TestResult::Fail("J.10 PMKID");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_hunt_and_peck_ieee_j10_vector);

    /// H2E: PT from (SSID "byteme", "mekmitasdigoat", identifier
    /// "psk4internet") and PWE for 00:09:5b:66:ec:1e / 00:0b:6b:d9:02:46 —
    /// the group 19 `pwe_19_x` / `pwe_19_y` of hostap `sae_tests`
    /// (IEEE 802.11-2020 Annex J.10).
    fn smoke_sae_h2e_pwe_ieee_j10_vector() -> TestResult {
        let pt =
            super::super::pt::pt_h2e_bytes(b"byteme", b"mekmitasdigoat", Some(b"psk4internet"));
        let pwe = pwe_from_pt(
            pt,
            &[0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e],
            &[0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46],
        );
        let want: [u8; 64] = [
            0xc9, 0x30, 0x49, 0xb9, 0xe6, 0x40, 0x00, 0xf8, 0x48, 0x20, 0x16, 0x49, 0xe9, 0x99,
            0xf2, 0xb5, 0xc2, 0x2d, 0xea, 0x69, 0xb5, 0x63, 0x2c, 0x9d, 0xf4, 0xd6, 0x33, 0xb8,
            0xaa, 0x1f, 0x6c, 0x1e, 0x73, 0x63, 0x4e, 0x94, 0xb5, 0x3d, 0x82, 0xe7, 0x38, 0x3a,
            0x8d, 0x25, 0x81, 0x99, 0xd9, 0xdc, 0x1a, 0x5e, 0xe8, 0x26, 0x9d, 0x06, 0x03, 0x82,
            0xcc, 0xbf, 0x33, 0xe6, 0x14, 0xff, 0x59, 0xa0,
        ];
        if pwe.to_encoded() != Some(want) {
            return TestResult::Fail("J.10 H2E PWE");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_h2e_pwe_ieee_j10_vector);

    /// Negative: a reflected Commit, a scalar of 1, an off-curve element,
    /// another group, and an H2E Rejected Groups element naming 19 are
    /// all refused; the anti-clogging token is placed per hostap
    /// `sae_write_commit` (inline for hunting and pecking, a container
    /// element for H2E) around the unchanged scalar / element.
    fn smoke_sae_commit_parse_rejects_and_token_placement() -> TestResult {
        let mk = || {
            SaeSession::new_hunt_and_peck(b"mekmitasdigoat", J10_ADDR1, J10_ADDR2)
                .with_test_rand_mask(J10_RAND, J10_MASK)
        };
        let mut s = mk();
        let own = s.build_commit();
        if s.on_commit(&own) != Err(SaeError::Reflection) {
            return TestResult::Fail("reflected commit accepted");
        }
        let mut one = J10_PEER_COMMIT;
        one[2..34].fill(0);
        one[33] = 1;
        if mk().commit_then(&one) != Err(SaeError::InvalidParameters) {
            return TestResult::Fail("scalar 1 accepted");
        }
        let mut off = J10_PEER_COMMIT;
        off[97] ^= 1;
        if mk().commit_then(&off) != Err(SaeError::InvalidParameters) {
            return TestResult::Fail("off-curve element accepted");
        }
        let mut g20 = J10_PEER_COMMIT;
        g20[0] = 20;
        if mk().commit_then(&g20) != Err(SaeError::InvalidParameters) {
            return TestResult::Fail("group 20 accepted");
        }
        // Legacy token: group || token || scalar || element.
        let tok = [0xAB, 0xCD, 0xEF];
        let b = s.commit_body(Some(&tok));
        if b[..2] != own[..2] || b[2..5] != tok || b[5..] != own[2..] {
            return TestResult::Fail("legacy token placement");
        }
        // H2E: container element after the element; rejected group 19.
        let mut h = SaeSession::new_h2e_bytes(b"byteme", b"pw", J10_ADDR1, J10_ADDR2)
            .with_test_rand_mask(J10_RAND, J10_MASK);
        let hc = h.build_commit();
        let hb = h.commit_body(Some(&tok));
        if hb[..98] != hc[..]
            || hb[98..] != [0xFF, 4, EID_EXT_ANTI_CLOGGING_TOKEN, 0xAB, 0xCD, 0xEF]
        {
            return TestResult::Fail("H2E token container");
        }
        let mut peer = SaeSession::new_h2e_bytes(b"byteme", b"pw", J10_ADDR2, J10_ADDR1)
            .with_test_seed([0x77; 64]);
        let mut pc = peer.build_commit();
        pc.extend_from_slice(&[0xFF, 3, EID_EXT_REJECTED_GROUPS, 19, 0]);
        if h.on_commit(&pc) != Err(SaeError::InvalidParameters) {
            return TestResult::Fail("rejected group 19 accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/sae",
        smoke_sae_commit_parse_rejects_and_token_placement
    );

    /// SAE-EXT-KEY (AKM 24): both Commits carry the AKM Suite Selector
    /// element after the H2E elements (hostap `sae_write_commit`), a
    /// matching peer completes with agreeing PMKs, and a missing or
    /// different peer selector fails (`sae_parse_commit` mismatch). A
    /// hunting-and-pecking session cannot bind AKM 24.
    fn smoke_sae_ext_key_akm_suite_selector() -> TestResult {
        const AKM24: [u8; 4] = [0x00, 0x0F, 0xAC, 24];
        let mk = |own, peer, seed| {
            SaeSession::new_h2e_bytes(b"net", b"pw", own, peer).with_test_seed([seed; 64])
        };
        let mut a = mk([0x11; 6], [0x22; 6], 0xA1)
            .with_akm_suite_selector(AKM24)
            .unwrap();
        let mut b = mk([0x22; 6], [0x11; 6], 0xB2)
            .with_akm_suite_selector(AKM24)
            .unwrap();
        let ca = a.build_commit();
        let cb = b.build_commit();
        if ca.len() != 98 + 7
            || ca[98..] != [0xFF, 5, EID_EXT_AKM_SUITE_SELECTOR, 0, 0x0F, 0xAC, 24]
        {
            return TestResult::Fail("AKM suite selector element layout");
        }
        if a.on_commit(&cb).is_err() || b.on_commit(&ca).is_err() {
            return TestResult::Fail("matching AKM 24 commits refused");
        }
        let (fa, fb) = (a.build_confirm(), b.build_confirm());
        if a.on_confirm(&fb).is_err()
            || b.on_confirm(&fa).is_err()
            || a.pmk() != b.pmk()
            || a.peer_akm_suite_selector() != Some(AKM24)
        {
            return TestResult::Fail("AKM 24 handshake did not agree");
        }
        let mut c = mk([0x11; 6], [0x22; 6], 0xC3)
            .with_akm_suite_selector(AKM24)
            .unwrap();
        c.build_commit();
        let mut plain = mk([0x22; 6], [0x11; 6], 0xD4);
        if c.on_commit(&plain.build_commit()) != Err(SaeError::InvalidParameters) {
            return TestResult::Fail("missing peer AKM selector accepted");
        }
        let mut d = mk([0x11; 6], [0x22; 6], 0xE5)
            .with_akm_suite_selector(AKM24)
            .unwrap();
        d.build_commit();
        let mut wrong = cb.clone();
        let n = wrong.len();
        wrong[n - 1] = 8;
        if d.on_commit(&wrong) != Err(SaeError::InvalidParameters) {
            return TestResult::Fail("mismatched peer AKM selector accepted");
        }
        if SaeSession::new_hunt_and_peck(b"pw", [0x11; 6], [0x22; 6])
            .with_akm_suite_selector(AKM24)
            .is_ok()
        {
            return TestResult::Fail("hunting-and-pecking AKM 24 accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_ext_key_akm_suite_selector);

    impl SaeSession {
        fn commit_then(mut self, peer: &[u8]) -> Result<(), SaeError> {
            self.build_commit();
            self.on_commit(peer)
        }
    }
}
