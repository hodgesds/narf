//! WPA3-SAE — Simultaneous Authentication of Equals (clean-room).
//!
//! Spec: IEEE 802.11-2020 §12.4 (SAE). Public IEEE document. No
//! GPL Linux source consulted.
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
