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
//! and never exposed to userspace.
//!
//! On-disk form: the store encodes to a versioned image
//! ([`BondStore::encode`] / [`BondStore::decode`]) and seals it
//! with ChaCha20-Poly1305 ([`BondStore::seal`] /
//! [`BondStore::unseal`]) under a provisioned sealing key, so a
//! bond image at rest is authenticated ciphertext, not bare key
//! material. Two hookups are still missing and are NOT built
//! here: the sealing key has no provisioning service yet (the
//! suspend programme's key custody owns that decision — the pump
//! holds an explicitly-provisioned key slot that starts empty
//! and seals nothing until filled), and no driver-domain file
//! write path exists to carry the sealed image to disk (the pump
//! exposes the image via `sealed_bonds_image` /
//! `restore_sealed_bonds` for the future disk layer). Until both
//! land, bonds still live for the controller lifetime.
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

impl Bond {
    /// Encode one bond as a record: peer address (7), LTK (16),
    /// EDIV (2 LE), Rand (8), authenticated (1), presence flags
    /// (1: bit 0 IRK, bit 1 identity address, bit 2 CSRK), then
    /// the present optional keys in IRK / identity-address /
    /// CSRK order. This is our own on-disk record layout, not a
    /// wire format — the version byte on the store image is the
    /// evolution point.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(61);
        out.extend_from_slice(&self.peer_addr);
        out.extend_from_slice(&self.ltk);
        out.extend_from_slice(&self.ediv.to_le_bytes());
        out.extend_from_slice(&self.rand);
        out.push(u8::from(self.authenticated));
        let mut flags = 0u8;
        if self.peer_irk.is_some() {
            flags |= 0x01;
        }
        if self.peer_identity_addr.is_some() {
            flags |= 0x02;
        }
        if self.peer_csrk.is_some() {
            flags |= 0x04;
        }
        out.push(flags);
        if let Some(irk) = self.peer_irk {
            out.extend_from_slice(&irk);
        }
        if let Some(addr) = self.peer_identity_addr {
            out.extend_from_slice(&addr);
        }
        if let Some(csrk) = self.peer_csrk {
            out.extend_from_slice(&csrk);
        }
        out
    }

    /// Decode one record produced by [`Bond::encode`]. Returns
    /// the bond and the bytes consumed, or `None` on truncation
    /// or an unknown presence flag. Strict: unknown flag bits
    /// fail the record rather than being skipped.
    pub fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        if bytes.len() < 36 {
            return None;
        }
        let mut peer_addr = [0u8; 7];
        peer_addr.copy_from_slice(&bytes[..7]);
        let mut ltk = [0u8; 16];
        ltk.copy_from_slice(&bytes[7..23]);
        let ediv = u16::from_le_bytes([bytes[23], bytes[24]]);
        let mut rand = [0u8; 8];
        rand.copy_from_slice(&bytes[25..33]);
        let authenticated = match bytes[33] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let flags = bytes[34];
        if flags & !0x07 != 0 {
            return None;
        }
        let mut pos = 35;
        let take = |bytes: &[u8], pos: &mut usize, n: usize| -> Option<Vec<u8>> {
            if bytes.len() < *pos + n {
                return None;
            }
            let out = bytes[*pos..*pos + n].to_vec();
            *pos += n;
            Some(out)
        };
        let peer_irk = if flags & 0x01 != 0 {
            let mut v = [0u8; 16];
            v.copy_from_slice(&take(bytes, &mut pos, 16)?);
            Some(v)
        } else {
            None
        };
        let peer_identity_addr = if flags & 0x02 != 0 {
            let mut v = [0u8; 7];
            v.copy_from_slice(&take(bytes, &mut pos, 7)?);
            Some(v)
        } else {
            None
        };
        let peer_csrk = if flags & 0x04 != 0 {
            let mut v = [0u8; 16];
            v.copy_from_slice(&take(bytes, &mut pos, 16)?);
            Some(v)
        } else {
            None
        };
        Some((
            Self {
                peer_addr,
                ltk,
                ediv,
                rand,
                authenticated,
                peer_irk,
                peer_identity_addr,
                peer_csrk,
            },
            pos,
        ))
    }
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

    /// Record the peer IRK for an already-bonded peer (mgmt
    /// LOAD_IRKS, issue #815): the IRK arrives independently of
    /// the LTK, so a bond created by pairing gains its peer IRK
    /// when userspace later loads it. Returns false when no bond
    /// exists for the peer — the IRK is then held only in the
    /// mgmt-level IRK list, never fabricated into a bond.
    pub fn set_peer_irk(&mut self, peer_addr: &[u8; 7], irk: [u8; 16]) -> bool {
        match self.bonds.iter_mut().find(|b| &b.peer_addr == peer_addr) {
            Some(bond) => {
                bond.peer_irk = Some(irk);
                true
            }
            None => false,
        }
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

    /// Encode every bond as one versioned image (the on-disk
    /// format): magic + version + count + one record per bond.
    /// Decoding is strict — see [`BondStore::decode`].
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(11 + self.bonds.len() * 61);
        out.extend_from_slice(BOND_IMAGE_MAGIC);
        out.push(BOND_IMAGE_VERSION);
        out.extend_from_slice(&(self.bonds.len() as u16).to_le_bytes());
        for bond in &self.bonds {
            out.extend_from_slice(&bond.encode());
        }
        out
    }

    /// Decode an image produced by [`BondStore::encode`]. Fails
    /// closed (`None`) on a bad magic, an unknown version, a
    /// count that does not match the bytes, a malformed record,
    /// trailing bytes, or more than [`MAX_BONDS`] bonds — a
    /// truncated or tampered image never yields a partial store.
    pub fn decode(image: &[u8]) -> Option<Self> {
        if image.len() < 11 || &image[..8] != BOND_IMAGE_MAGIC || image[8] != BOND_IMAGE_VERSION {
            return None;
        }
        let count = u16::from_le_bytes([image[9], image[10]]) as usize;
        if count > MAX_BONDS {
            return None;
        }
        let mut store = Self::new();
        let mut rest = &image[11..];
        for _ in 0..count {
            let (bond, used) = Bond::decode(rest)?;
            store.bonds.push(bond);
            rest = &rest[used..];
        }
        if !rest.is_empty() {
            return None;
        }
        Some(store)
    }
}

/// On-disk bond-image framing: 8-byte magic + 1-byte version +
/// u16-LE bond count + [`Bond::encode`] records. The version
/// byte is the only evolution point — a future format bumps it
/// and `decode` rejects what it does not know.
pub const BOND_IMAGE_MAGIC: &[u8; 8] = b"NARFBOND";
pub const BOND_IMAGE_VERSION: u8 = 1;

/// Seal a bond image for disk: ChaCha20-Poly1305 (RFC 8439,
/// [`narf_crypto::aead`]) over the encoded store. The returned
/// blob is `nonce (12) ‖ ciphertext ‖ tag (16)`; `aad` binds the
/// image to its controller (callers pass the controller index +
/// format tag). The sealing key is provisioned by the caller —
/// there is no key service for bonding yet, so an unprovisioned
/// store seals nothing (see [`BondStore::seal`]).
pub fn seal_bonds(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], image: &[u8]) -> Vec<u8> {
    let mut ct = image.to_vec();
    let tag = narf_crypto::aead::chacha20_poly1305_seal(key, nonce, aad, &mut ct);
    let mut out = Vec::with_capacity(12 + ct.len() + 16);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

/// Open a blob produced by [`seal_bonds`]. Returns `None` on a
/// short blob or a tag mismatch — tampered ciphertext never
/// yields bonds.
pub fn unseal_bonds(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 + 16 {
        return None;
    }
    let (nonce, rest) = blob.split_at(12);
    let (ct, tag) = rest.split_at(rest.len() - 16);
    let mut buf = ct.to_vec();
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(tag);
    if narf_crypto::aead::chacha20_poly1305_open(key, &nonce_arr, aad, &mut buf, &tag_arr) {
        Some(buf)
    } else {
        None
    }
}

impl BondStore {
    /// Seal this store for disk with a provisioned sealing key.
    /// The nonce must be fresh per seal (callers draw it from
    /// the production RNG); `aad` binds the image to its
    /// controller.
    pub fn seal(&self, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) -> Vec<u8> {
        seal_bonds(key, nonce, aad, &self.encode())
    }

    /// Open a sealed image produced by [`BondStore::seal`] and
    /// decode the store it carries. `None` on a bad tag or a
    /// malformed image.
    pub fn unseal(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Self> {
        let image = unseal_bonds(key, aad, blob)?;
        Self::decode(&image)
    }
}
