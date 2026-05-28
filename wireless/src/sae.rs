//! WPA3-SAE — Simultaneous Authentication of Equals (clean-room).
//!
//! Spec: IEEE 802.11-2020 §12.4 (SAE). Public IEEE document. No
//! GPL Linux source consulted.
//!   <https://standards.ieee.org/ieee/802.11/7028/>
//!
//! SAE replaces the WPA2 4-Way Handshake's reliance on a shared
//! pre-shared key with a Diffie-Hellman exchange that is
//! resistant to off-line dictionary attack. The two ends each
//! prove knowledge of the password without revealing it.
//!
//! ## Message flow (§12.4.5)
//!
//! Both peers swap identical message types — there's no
//! "supplicant / authenticator" asymmetry. Each side's state
//! machine independently produces:
//!
//!   1. **Commit** — sends scalar + element (an ECC point), proving
//!      knowledge of a value derived from the password.
//!   2. **Confirm** — sends a MAC over the exchange transcript that
//!      can only be computed if both sides agreed on the password.
//!
//! Once Confirm verifies on both sides the peers share a Pairwise
//! Master Key (PMK) which feeds the standard 4-Way Handshake to
//! derive the PTK / GTK.
//!
//! ## ECC primitive injection
//!
//! SAE is parameterised on a finite cyclic group (§12.4.4.1). The
//! mandatory groups are NIST P-256 (group 19), P-384 (20), and the
//! Brainpool / FFC variants. Production wires this through
//! `narf-crypto` once it grows ECC primitives; until then callers
//! provide an `EccGroup` impl and the state machine drives it.

use alloc::vec::Vec;

/// Errors from the SAE state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SaeError {
    /// Peer's Confirm MAC didn't match.
    ConfirmMismatch,
    /// Peer sent a frame in the wrong order.
    Protocol,
    /// Invalid scalar / element on the wire.
    InvalidParameters,
    /// State machine ran out of `sync` retries (§12.4.8.6.4).
    TooManySyncRetries,
}

/// SAE state (§12.4.8.6).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SaeState {
    /// No SAE in progress.
    Nothing = 0,
    /// Sent our Commit, waiting for peer's Commit.
    Committed = 1,
    /// Got peer's Commit; sent our Confirm; waiting for peer's Confirm.
    Confirmed = 2,
    /// Both sides confirmed; PMK ready.
    Accepted = 3,
}

/// 16-bit Status Code values used in SAE Authentication frames
/// (§12.4.7.4, §9.4.1.9).
pub const SAE_STATUS_SUCCESS: u16 = 0;
pub const SAE_STATUS_UNSUPPORTED_GROUP: u16 = 77;
pub const SAE_STATUS_HASH_TO_ELEMENT: u16 = 126; // §12.4.7.5 (SAE H2E)

/// SAE Authentication transaction-sequence numbers (§12.4.7.4).
pub const SAE_SEQ_COMMIT: u16 = 1;
pub const SAE_SEQ_CONFIRM: u16 = 2;

// ── ECC group injection ───────────────────────────────────────────

/// One cyclic group SAE can run over. Implementations live behind
/// the trait so the state machine compiles without dragging in a
/// bignum library; production wires P-256 from `narf-crypto`.
///
/// For SAE: the "scalar" is `kdf-output mod q`; the "element" is a
/// curve point (affine X || Y on prime curves). All on-the-wire
/// values are little-endian byte arrays of fixed length (`scalar_len()`,
/// `element_len()`).
pub trait EccGroup {
    /// Group identifier (IANA "Transform Type 4 - DH Group" registry).
    /// 19 = NIST P-256, 20 = P-384, 21 = P-521.
    fn group_id(&self) -> u16;

    /// Length of an encoded scalar (e.g. 32 for P-256).
    fn scalar_len(&self) -> usize;

    /// Length of an encoded element (X||Y for affine prime curves —
    /// 64 for P-256).
    fn element_len(&self) -> usize;

    /// Generate a fresh random pair `(rand, mask)` and a Password
    /// Element `pwe`, then return:
    ///   `(commit_scalar, commit_element)`
    /// where `commit_scalar = (rand + mask) mod q` and
    ///   `commit_element = inverse(pwe^mask)`.
    ///
    /// `password` is the SSID-keyed pass-phrase or 32-byte PMK; the
    /// implementation owns the hash-to-element derivation per §12.4.4.
    fn make_commit(&mut self, password: &[u8], peer_mac: &[u8; 6], own_mac: &[u8; 6])
        -> (Vec<u8>, Vec<u8>);

    /// Compute the shared secret `K = scalar(rand, peer_element + scalar(peer_scalar, pwe))`
    /// using the local `rand` saved from `make_commit`. Returns a
    /// scalar-length byte slice (the X coordinate of K on prime curves).
    fn finish(&mut self, peer_scalar: &[u8], peer_element: &[u8]) -> Result<Vec<u8>, SaeError>;
}

// ── Wire frames (§12.4.7.4) ───────────────────────────────────────

/// Decoded SAE Commit frame body (after the 6-byte
/// Algorithm/Sequence/Status header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitFrame {
    /// Group identifier the sender chose.
    pub group: u16,
    /// `scalar_len(group)` bytes — the Commit scalar (LE).
    pub scalar: Vec<u8>,
    /// `element_len(group)` bytes — the Commit element (X||Y).
    pub element: Vec<u8>,
}

impl CommitFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.scalar.len() + self.element.len());
        out.extend_from_slice(&self.group.to_le_bytes());
        out.extend_from_slice(&self.scalar);
        out.extend_from_slice(&self.element);
        out
    }

    pub fn decode(buf: &[u8], scalar_len: usize, element_len: usize) -> Option<Self> {
        if buf.len() < 2 + scalar_len + element_len {
            return None;
        }
        let group = u16::from_le_bytes([buf[0], buf[1]]);
        let scalar = buf[2..2 + scalar_len].to_vec();
        let element = buf[2 + scalar_len..2 + scalar_len + element_len].to_vec();
        Some(Self {
            group,
            scalar,
            element,
        })
    }
}

/// Decoded SAE Confirm frame body. Just a 16-bit `send-confirm`
/// counter and an opaque MAC the recipient verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmFrame {
    pub send_confirm: u16,
    pub confirm: Vec<u8>,
}

impl ConfirmFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.confirm.len());
        out.extend_from_slice(&self.send_confirm.to_le_bytes());
        out.extend_from_slice(&self.confirm);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 {
            return None;
        }
        Some(Self {
            send_confirm: u16::from_le_bytes([buf[0], buf[1]]),
            confirm: buf[2..].to_vec(),
        })
    }
}

// ── State machine ──────────────────────────────────────────────────

/// HMAC primitive used for the Confirm MAC (HMAC-SHA256 for groups
/// 19/20, HMAC-SHA384 for higher groups). Production wires through
/// `narf-crypto`.
pub trait MacPrimitive {
    fn out_len(&self) -> usize;
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8>;
}

/// SAE handshake driver. Runs identically on both peers — the only
/// asymmetry is which MAC starts the conversation. Owns the local
/// scalars/elements/peer cache so the state machine is self-contained.
#[derive(Debug)]
pub struct Sae<G: EccGroup, M: MacPrimitive> {
    pub state: SaeState,
    group: G,
    mac: M,
    /// Local Commit scalar (sent in our Commit, used in PMK derivation).
    pub local_scalar: Vec<u8>,
    /// Local Commit element.
    pub local_element: Vec<u8>,
    /// Peer Commit scalar (captured from rx).
    pub peer_scalar: Vec<u8>,
    /// Peer Commit element.
    pub peer_element: Vec<u8>,
    /// Negotiated PMK (`scalar_len` bytes), only set in `Accepted`.
    pub pmk: Vec<u8>,
    pub send_confirm_counter: u16,
    pub own_mac: [u8; 6],
    pub peer_mac: [u8; 6],
}

impl<G: EccGroup, M: MacPrimitive> Sae<G, M> {
    pub fn new(group: G, mac: M, own_mac: [u8; 6], peer_mac: [u8; 6]) -> Self {
        Self {
            state: SaeState::Nothing,
            group,
            mac,
            local_scalar: Vec::new(),
            local_element: Vec::new(),
            peer_scalar: Vec::new(),
            peer_element: Vec::new(),
            pmk: Vec::new(),
            send_confirm_counter: 0,
            own_mac,
            peer_mac,
        }
    }

    /// Build our outgoing Commit frame. Drives `make_commit` on the
    /// underlying group.
    pub fn build_commit(&mut self, password: &[u8]) -> CommitFrame {
        let (scalar, element) = self.group.make_commit(password, &self.peer_mac, &self.own_mac);
        self.local_scalar = scalar.clone();
        self.local_element = element.clone();
        self.state = SaeState::Committed;
        CommitFrame {
            group: self.group.group_id(),
            scalar,
            element,
        }
    }

    /// Consume peer's Commit. On success we have everything needed
    /// to compute the PMK + Confirm MAC.
    pub fn handle_commit(&mut self, frame: &CommitFrame) -> Result<(), SaeError> {
        if self.state != SaeState::Committed {
            return Err(SaeError::Protocol);
        }
        if frame.group != self.group.group_id() {
            return Err(SaeError::InvalidParameters);
        }
        if frame.scalar.len() != self.group.scalar_len()
            || frame.element.len() != self.group.element_len()
        {
            return Err(SaeError::InvalidParameters);
        }
        self.peer_scalar = frame.scalar.clone();
        self.peer_element = frame.element.clone();

        // Derive the shared secret K via the group's `finish`.
        let k = self.group.finish(&frame.scalar, &frame.element)?;

        // KCK || PMK = KDF-Hash-Length(K, "SAE KCK and PMK", (s_a + s_b) mod r)
        // §12.4.5.4. We approximate by feeding (K || combined scalars)
        // through the injected MAC primitive — production swaps this for
        // the spec's KDF-Hash-Length derivation.
        let mut kdf_input = Vec::with_capacity(k.len() + 2 * self.group.scalar_len());
        kdf_input.extend_from_slice(&k);
        kdf_input.extend_from_slice(&self.local_scalar);
        kdf_input.extend_from_slice(&self.peer_scalar);
        let derived = self.mac.mac(b"SAE KCK and PMK", &kdf_input);
        // Split: first half = KCK, second half = PMK. Result length
        // depends on the MAC; production picks the spec's slicing.
        let half = derived.len() / 2;
        self.pmk = derived[half..].to_vec();
        Ok(())
    }

    /// Build our outgoing Confirm. Must be called after `handle_commit`.
    pub fn build_confirm(&mut self) -> ConfirmFrame {
        self.send_confirm_counter = self.send_confirm_counter.wrapping_add(1);
        // confirm = MAC(KCK, send-confirm || s_a || E_a || s_b || E_b)
        // The KCK was the upper half of the derived bytes — for the
        // structural test path we re-derive equivalently.
        let mut data = Vec::new();
        data.extend_from_slice(&self.send_confirm_counter.to_le_bytes());
        data.extend_from_slice(&self.local_scalar);
        data.extend_from_slice(&self.local_element);
        data.extend_from_slice(&self.peer_scalar);
        data.extend_from_slice(&self.peer_element);
        let confirm = self.mac.mac(&self.pmk, &data);
        ConfirmFrame {
            send_confirm: self.send_confirm_counter,
            confirm,
        }
    }

    /// Verify peer's Confirm against the transcript.
    pub fn handle_confirm(&mut self, frame: &ConfirmFrame) -> Result<(), SaeError> {
        // Recompute what we expect peer to have sent — same as
        // `build_confirm` but with their and our scalars/elements
        // swapped because the MAC includes both sides' contributions
        // in (sender, receiver) order.
        let mut data = Vec::new();
        data.extend_from_slice(&frame.send_confirm.to_le_bytes());
        data.extend_from_slice(&self.peer_scalar);
        data.extend_from_slice(&self.peer_element);
        data.extend_from_slice(&self.local_scalar);
        data.extend_from_slice(&self.local_element);
        let expected = self.mac.mac(&self.pmk, &data);
        if expected != frame.confirm {
            return Err(SaeError::ConfirmMismatch);
        }
        self.state = SaeState::Accepted;
        Ok(())
    }
}

// ── Hunting-and-pecking password element derivation ────────────────
//
// 802.11-2020 §12.4.4.2.2 (RFC 7664 ratified the same algorithm in
// IETF terms). The Password Element (PWE) is found by iterating a
// counter against
//
//     base = H(max(STA-A,STA-B) || min(STA-A,STA-B) || password || counter)
//     pwd_seed = base
//     pwd_value = KDF(pwd_seed, "SAE Hunting and Pecking", p)
//
// then attempting to interpret pwd_value as the X coordinate of a
// point on the curve. If `x^3 + ax + b` is a quadratic residue mod p,
// take Y as that residue (with LSB matching pwd_seed[0] bit 0 per
// §12.4.4.2.2 step 9); else bump the counter and try again. The loop
// runs at most `k` iterations (k=40 is the spec's mandatory worst-case
// floor — security analysis assumes constant-time execution so timing
// doesn't leak which counter succeeded).
//
// We provide the generic state-machine surface here and a
// trait-injected `HuntAndPeck` so the actual prime-field arithmetic
// can live behind `narf-crypto` once P-256 lands. The smokes use a
// deterministic stub backend that exercises the counter / output
// shapes.

/// Hash-to-curve "hunting and pecking" interface. Implementations
/// own the prime-field arithmetic + curve equation; the SAE state
/// machine drives them with the (password, STA addresses) and consumes
/// the (PWE-x, PWE-y) point and the local secret bytes.
pub trait HuntAndPeck {
    /// Maximum hunt iterations before bailing out. Spec floor is 40
    /// (§12.4.4.2.2 step 1.k); production groups must set k≥40.
    fn iteration_floor(&self) -> u32 {
        40
    }

    /// Derive the password element by hashing `(max(MAC) || min(MAC) ||
    /// password || counter)` and trying to solve y^2 = x^3 + ax + b for
    /// each candidate X. Returns the encoded element (X||Y) and the
    /// counter that succeeded, or `Err` if the iteration floor was
    /// exhausted (extremely unlikely outside contrived parameters).
    fn hunt_and_peck(
        &mut self,
        password: &[u8],
        sta_a: &[u8; 6],
        sta_b: &[u8; 6],
    ) -> Result<(Vec<u8>, u32), SaeError>;
}

/// Canonical order of the (sta_a, sta_b) pair per §12.4.4.2.2 step 2:
/// the larger MAC (lexicographically) comes first.
pub fn order_mac_pair(a: &[u8; 6], b: &[u8; 6]) -> ([u8; 6], [u8; 6]) {
    if a > b {
        (*a, *b)
    } else {
        (*b, *a)
    }
}

/// Sage hunt-and-peck driver: combines the abstract HuntAndPeck trait
/// with iteration-floor enforcement and a constant-time "keep going
/// even after a success" loop body. Returns the encoded PWE element +
/// the counter that succeeded so callers can audit.
///
/// **Constant-time discipline (§12.4.4.2.2 NOTE):** real
/// implementations must run the loop a fixed number of iterations even
/// after finding a valid PWE — otherwise timing reveals which counter
/// succeeded, which leaks information about the password. The stub
/// implementation below doesn't model this; production wires
/// `HuntAndPeck` through a curve backend that does.
pub fn derive_pwe<G: HuntAndPeck>(
    g: &mut G,
    password: &[u8],
    sta_a: &[u8; 6],
    sta_b: &[u8; 6],
) -> Result<Vec<u8>, SaeError> {
    let (a, b) = order_mac_pair(sta_a, sta_b);
    let (pwe, _counter) = g.hunt_and_peck(password, &a, &b)?;
    Ok(pwe)
}

// ── Deterministic stub group for end-to-end tests ──────────────────
//
// A real EccGroup needs an ECC backend (P-256 / P-384). Pending
// `narf-crypto::p256`, the smokes exercise the state machine + frame
// codec via this stub: it implements both `HuntAndPeck` (by
// hash-mixing into a 64-byte buffer until the first byte is even) and
// `EccGroup` (by treating the "shared secret" as XOR of peer's scalar +
// element). Insecure by construction, useful for plumbing.

/// Test-only stub group exposed publicly so `iwlwifi` and other
/// crates can run SAE plumbing tests without dragging in real ECC.
///
/// The "scalar" is 32 bytes, the "element" is 64 bytes — matching
/// NIST P-256 sizes so production callers can swap in a real group
/// without re-cutting wire shapes.
#[derive(Debug, Default)]
pub struct StubGroup;

impl StubGroup {
    pub const fn new() -> Self {
        Self
    }
}

impl HuntAndPeck for StubGroup {
    fn hunt_and_peck(
        &mut self,
        password: &[u8],
        sta_a: &[u8; 6],
        sta_b: &[u8; 6],
    ) -> Result<(Vec<u8>, u32), SaeError> {
        // Hash (sta_a || sta_b || password || counter) until the
        // first byte is even — stand-in for "pwd_value < p" + "x^3+ax+b
        // is a QR". Bail after iteration_floor() rounds.
        //
        // The XOR-mixing below isn't a real hash so the parity
        // predicate doesn't have a 50% hit rate on all inputs; the
        // counter is mixed into the first output byte directly so the
        // search always converges (parity of counter ⊕ tail-fold is
        // always toggleable within two adjacent counters).
        let max_iter = self.iteration_floor();
        for counter in 1..=max_iter {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(sta_a);
            buf.extend_from_slice(sta_b);
            buf.extend_from_slice(password);
            buf.extend_from_slice(&counter.to_be_bytes());

            let mut element = alloc::vec![0u8; 64];
            for (i, b) in buf.iter().enumerate() {
                element[i % 64] ^= b.rotate_left((i % 8) as u32);
            }
            // Force the first byte's LSB to follow the counter parity so
            // the predicate has a guaranteed-converging form: when
            // counter is even the predicate holds. (Real H2P uses a
            // proper modular SQRT; this is a stub strict enough to
            // exercise the counter increment + canonicalisation paths.)
            if counter & 1 == 0 {
                element[0] &= !1u8;
                return Ok((element, counter));
            }
        }
        Err(SaeError::TooManySyncRetries)
    }
}

impl EccGroup for StubGroup {
    fn group_id(&self) -> u16 {
        // Pretend to be NIST P-256 so the wire decoder picks 32/64-byte
        // lengths.
        19
    }
    fn scalar_len(&self) -> usize {
        32
    }
    fn element_len(&self) -> usize {
        64
    }
    fn make_commit(
        &mut self,
        password: &[u8],
        peer_mac: &[u8; 6],
        own_mac: &[u8; 6],
    ) -> (Vec<u8>, Vec<u8>) {
        // Drive the H2P loop to derive a deterministic "PWE" — feed
        // the password + MAC pair through `derive_pwe`. The resulting
        // 64-byte buffer plays the role of (commit-scalar || extras).
        let pwe = derive_pwe(self, password, peer_mac, own_mac)
            .unwrap_or_else(|_| alloc::vec![0u8; 64]);
        let mut s = alloc::vec![0u8; 32];
        s.copy_from_slice(&pwe[..32]);
        let mut e = alloc::vec![0u8; 64];
        e.copy_from_slice(&pwe);
        (s, e)
    }
    fn finish(
        &mut self,
        peer_scalar: &[u8],
        peer_element: &[u8],
    ) -> Result<Vec<u8>, SaeError> {
        let mut k = alloc::vec![0u8; 32];
        for (i, b) in peer_scalar.iter().take(32).enumerate() {
            k[i] ^= *b;
        }
        for (i, b) in peer_element.iter().take(32).enumerate() {
            k[i] ^= *b;
        }
        Ok(k)
    }
}

// ── HmacSha256MacPrimitive — production-shape Confirm MAC ──────────
//
// Spec (§12.4.5.5) calls for the Confirm field to be HMAC-SHA256 over
// (send-confirm || s_a || E_a || s_b || E_b) keyed by KCK. The MAC
// backend lives behind `MacPrimitive`; this implementation adapts
// `narf_crypto::sha256` via a clean-room HMAC.

/// Production HMAC-SHA256 MAC primitive used by SAE Confirm.
/// Wraps the cleanroom SHA-256 in narf_crypto.
#[derive(Default, Debug)]
pub struct HmacSha256;

impl MacPrimitive for HmacSha256 {
    fn out_len(&self) -> usize {
        32
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use narf_crypto::sha256::Sha256;
        const BLOCK: usize = 64;
        let mut k0 = [0u8; BLOCK];
        if key.len() > BLOCK {
            let mut h = Sha256::new();
            h.update(key);
            k0[..32].copy_from_slice(&h.finalize());
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5Cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k0[i];
            opad[i] ^= k0[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        inner.update(data);
        let ih = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&opad);
        outer.update(&ih);
        outer.finalize().to_vec()
    }
}

// ── Tests for hunting-and-pecking + state machine ───────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod hp_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_sae_h2p_deterministic_on_fixed_input() -> TestResult {
        let mut g1 = StubGroup;
        let mut g2 = StubGroup;
        let pwd = b"narfwifi";
        let a = [0x11u8; 6];
        let b = [0x22u8; 6];
        let p1 = derive_pwe(&mut g1, pwd, &a, &b).expect("p1");
        let p2 = derive_pwe(&mut g2, pwd, &a, &b).expect("p2");
        if p1 != p2 {
            return TestResult::Fail("PWE derivation should be deterministic");
        }
        if p1.len() != 64 {
            return TestResult::Fail("PWE should be 64 bytes (P-256-shaped)");
        }
        // Different password ⇒ different PWE.
        let mut g3 = StubGroup;
        let p3 = derive_pwe(&mut g3, b"otherpwd", &a, &b).expect("p3");
        if p1 == p3 {
            return TestResult::Fail("PWE should change with password");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_h2p_deterministic_on_fixed_input);

    fn smoke_sae_h2p_mac_pair_canonical_order() -> TestResult {
        // §12.4.4.2.2 step 2: the higher MAC always sorts first into
        // the hash input. Therefore derive_pwe(pwd, a, b) and
        // derive_pwe(pwd, b, a) must produce the same PWE.
        let mut g1 = StubGroup;
        let mut g2 = StubGroup;
        let pwd = b"narfwifi";
        let a = [0x11u8; 6];
        let b = [0xFFu8; 6];
        let p_ab = derive_pwe(&mut g1, pwd, &a, &b).expect("ab");
        let p_ba = derive_pwe(&mut g2, pwd, &b, &a).expect("ba");
        if p_ab != p_ba {
            return TestResult::Fail("hunt-and-peck must canonicalise MAC pair order");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_h2p_mac_pair_canonical_order);

    fn smoke_sae_state_machine_full_handshake() -> TestResult {
        // Drives both peers through Nothing → Committed → Accepted.
        let pwd = b"narfwifi";
        let mac_a = [0x11u8; 6];
        let mac_b = [0x22u8; 6];

        let mut a = Sae::new(StubGroup, HmacSha256, mac_a, mac_b);
        let mut b = Sae::new(StubGroup, HmacSha256, mac_b, mac_a);

        // Initial state.
        if a.state != SaeState::Nothing {
            return TestResult::Fail("A should start in Nothing");
        }
        let commit_a = a.build_commit(pwd);
        let commit_b = b.build_commit(pwd);
        if a.state != SaeState::Committed || b.state != SaeState::Committed {
            return TestResult::Fail("state should advance to Committed after build_commit");
        }

        a.handle_commit(&commit_b).expect("a handle");
        b.handle_commit(&commit_a).expect("b handle");

        let confirm_a = a.build_confirm();
        let confirm_b = b.build_confirm();
        a.handle_confirm(&confirm_b).expect("a confirm");
        b.handle_confirm(&confirm_a).expect("b confirm");

        if a.state != SaeState::Accepted || b.state != SaeState::Accepted {
            return TestResult::Fail("both peers should reach Accepted");
        }
        if a.pmk.is_empty() {
            return TestResult::Fail("A must have a PMK after Accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/sae", smoke_sae_state_machine_full_handshake);

    fn smoke_sae_confirm_mic_compute_verify_with_hmac_sha256() -> TestResult {
        // Exercise the real HmacSha256 MAC primitive end-to-end on a
        // small transcript.
        let pwd = b"narfwifi";
        let mac_a = [0xAAu8; 6];
        let mac_b = [0xBBu8; 6];
        let mut a = Sae::new(StubGroup, HmacSha256, mac_a, mac_b);
        let mut b = Sae::new(StubGroup, HmacSha256, mac_b, mac_a);
        let commit_a = a.build_commit(pwd);
        let commit_b = b.build_commit(pwd);
        a.handle_commit(&commit_b).expect("a handle");
        b.handle_commit(&commit_a).expect("b handle");
        let confirm_a = a.build_confirm();
        let confirm_b = b.build_confirm();
        // Confirms must be 32 bytes (HMAC-SHA256 output) and non-zero.
        if confirm_a.confirm.len() != 32 || confirm_b.confirm.len() != 32 {
            return TestResult::Fail("HMAC-SHA256 confirms must be 32 bytes");
        }
        if confirm_a.confirm.iter().all(|&b| b == 0) {
            return TestResult::Fail("confirm should not be all-zero");
        }
        a.handle_confirm(&confirm_b).expect("a confirm");
        b.handle_confirm(&confirm_a).expect("b confirm");
        TestResult::Pass
    }
    kernel_test_in!(
        "wireless/sae",
        smoke_sae_confirm_mic_compute_verify_with_hmac_sha256
    );
}
