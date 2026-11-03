//! Bond store — persistent (across disconnects) SMP bonding state.
//!
//! Spec: Bluetooth Core Specification 5.3 Vol 3 Part H. Public
//! Bluetooth SIG document. No GPL Linux source consulted.
//!
//! A bond is what survives a disconnect: the LTK derived by LE
//! Secure Connections pairing plus whatever the peer distributed
//! in the Phase 3 key-distribution exchange (IRK, identity address,
//! CSRK). The store is owned by [`crate::pump::PumpCore`] — driver
//! domain state, reachable only through pump APIs, never a global
//! and never exposed to userspace. It is **not** on-disk storage:
//! bonds survive disconnects and reconnects within a controller
//! lifetime, and are lost on controller removal or reboot. Sealed
//! on-disk persistence is future work.
//!
//! Lookup rules (fail-closed):
//! - Bonds are keyed by peer address (`[address-type, bd_addr]`,
//!   the same 7-byte shape the pump tracks per connection).
//! - An LE LTK Request is answered only when the stored EDIV and
//!   Rand match the event's values exactly. For LE Secure
//!   Connections both are zero by spec (Part H §2.4.3.1: "When both
//!   devices support LE Secure Connections, the EDIV and Rand are
//!   set to zero"), so SC bonds are stored with EDIV 0 / Rand 0 and
//!   match SC reconnects. A mismatch negative-replies — the store
//!   never hands out an LTK for a diversifier it did not record.
//! - Storing a bond for an already-bonded peer replaces the old
//!   one (re-pairing overwrites). The store holds at most
//!   [`MAX_BONDS`] bonds and evicts the oldest on overflow, so
//!   remote-triggered pairings cannot grow it without bound.

use alloc::vec::Vec;

/// Maximum bonds held. An implementation choice, not a protocol
/// constant: 32 peers is ample for a host stack, and the cap bounds
/// memory growth from remote-triggered pairings.
pub const MAX_BONDS: usize = 32;

/// One bonded peer: the LTK plus the peer's Phase 3 keys.
///
/// `ediv` / `rand` identify the LTK to the peer's controller on
/// reconnect (LE LTK Request event fields). For LE Secure
/// Connections both are zero — the LTK is derived via f5 on both
/// sides, not distributed (Part H §3.6.1: "In LE Secure
/// Connections pairing, when SMP is running on the LE transport,
/// then the EncKey field shall be ignored. EDIV and Rand shall be
/// set to zero and shall not be distributed").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bond {
    /// Peer address: `[address-type, bd_addr(wire order, 6)]`.
    pub peer_addr: [u8; 7],
    /// LTK from f5 (LE Secure Connections) — always 16 bytes.
    pub ltk: [u8; 16],
    /// Encrypted diversifier recorded with the LTK (0 for SC).
    pub ediv: u16,
    /// Random number recorded with the LTK (all zero for SC).
    pub rand: [u8; 8],
    /// True when MITM protection was negotiated (method other than
    /// Just Works). Records the pairing's authentication level; it
    /// does not gate LTK replies (the LTK Request match is
    /// address + EDIV/Rand, above).
    pub authenticated: bool,
    /// Peer's IRK from Identity Information, if distributed.
    pub peer_irk: Option<[u8; 16]>,
    /// Peer's identity address from Identity Address Information,
    /// if distributed (same 7-byte address shape).
    pub peer_identity_addr: Option<[u8; 7]>,
    /// Peer's CSRK from Signing Information, if distributed.
    pub peer_csrk: Option<[u8; 16]>,
}

/// Small bond database, insertion-ordered (index 0 is oldest).
#[derive(Debug, Default)]
pub struct BondStore {
    bonds: Vec<Bond>,
}

impl BondStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of bonds held.
    pub fn len(&self) -> usize {
        self.bonds.len()
    }

    /// True when no bonds are held.
    pub fn is_empty(&self) -> bool {
        self.bonds.is_empty()
    }

    /// Store a bond, replacing any bond for the same peer. Evicts
    /// the oldest bond when the store is already at capacity.
    pub fn store(&mut self, bond: Bond) {
        if let Some(slot) = self
            .bonds
            .iter_mut()
            .find(|b| b.peer_addr == bond.peer_addr)
        {
            *slot = bond;
            return;
        }
        if self.bonds.len() >= MAX_BONDS {
            self.bonds.remove(0);
        }
        self.bonds.push(bond);
    }

    /// Look up a bond by peer address.
    pub fn lookup(&self, peer_addr: &[u8; 7]) -> Option<&Bond> {
        self.bonds.iter().find(|b| &b.peer_addr == peer_addr)
    }

    /// Look up the bond answering an LE LTK Request: peer address
    /// must match and the event's EDIV/Rand must match the stored
    /// values exactly. Anything else returns `None` (the caller
    /// negative-replies).
    pub fn lookup_for_ltk_request(
        &self,
        peer_addr: &[u8; 7],
        ediv: u16,
        rand: u64,
    ) -> Option<&Bond> {
        self.lookup(peer_addr)
            .filter(|b| b.ediv == ediv && u64::from_le_bytes(b.rand) == rand)
    }

    /// Forget a peer's bond. Returns true when one was removed.
    pub fn forget(&mut self, peer_addr: &[u8; 7]) -> bool {
        if let Some(pos) = self.bonds.iter().position(|b| &b.peer_addr == peer_addr) {
            self.bonds.remove(pos);
            true
        } else {
            false
        }
    }
}
