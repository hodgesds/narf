//! Checked software CCMP ownership for the RTL8188EU station path.
//! The protocol layer owns header/AAD/nonce formatting. This owner adds strict
//! header/CCMP bounds, peer binding, per-key/TID replay and non-wrapping TX PN.
//! It does not open a controlled port or install keys before RSNA completes.
use alloc::vec::Vec;
use narf_wireless::ccmp::{self, AesCcm, CcmpError, ReplayWindow};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_PN: u64 = (1u64 << 48) - 1;
const MAX_BODY: usize = 4096;
const NON_QOS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Key,
    Length,
    Exhausted,
    Crypto(CcmpError),
}
/// Pairwise and group keys have different station address/packet ownership.
/// GTK KeyID zero is legal and must never be confused with a transmit PTK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Pairwise,
    Group,
}
struct Ccm;
impl AesCcm for Ccm {
    fn encrypt(&self, key: &[u8; 16], nonce: &[u8; 13], aad: &[u8], body: &mut [u8]) -> [u8; 8] {
        // Every production caller first bounds body to MAX_BODY (4096).
        narf_crypto::aes_ccm::seal(key, nonce, aad, body).expect("bounded CCMP body")
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag).map_err(|_| CcmpError::AuthFailed)
    }
}

/// One immutable key-ID/peer binding, kept for the connection's lifetime.
/// Only construct for a fresh temporal key. An EAPOL retransmission must use
/// `reinstall`, which preserves counters for an identical key. The station
/// retains these slots across rekeys/failed joins; it must not rebuild an
/// identical key with a reset PN. GTK slots are receive-only in station mode.
/// Hardware encryption must remain disabled while software CCMP owns packets.
pub struct Key {
    tk: Zeroizing<[u8; 16]>,
    key_id: u8,
    role: Role,
    local: [u8; 6],
    peer: [u8; 6],
    tx_pn: u64,
    receive: [ReplayWindow; 17],
}
impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Key")
            .field("key_id", &self.key_id)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}
impl Key {
    pub fn new(
        tk: &[u8; 16],
        key_id: u8,
        role: Role,
        local: [u8; 6],
        peer: [u8; 6],
        rsc: u64,
    ) -> Result<Self, Error> {
        if key_id > 3
            || (role == Role::Pairwise && key_id != 0)
            || rsc > MAX_PN
            || !unicast(local)
            || !unicast(peer)
            || local == peer
        {
            return Err(Error::Key);
        }
        Ok(Self {
            tk: Zeroizing::new(*tk),
            key_id,
            role,
            local,
            peer,
            tx_pn: 0,
            receive: [ReplayWindow { last_seen_pn: rsc }; 17],
        })
    }
    /// Return true when material changed. An identical-key retry must not
    /// roll TX/RX state back, even if the peer repeats a smaller receive RSC.
    pub fn reinstall(&mut self, tk: &[u8; 16], rsc: u64) -> Result<bool, Error> {
        if rsc > MAX_PN {
            return Err(Error::Key);
        }
        if *self.tk == *tk {
            return Ok(false);
        }
        self.tk.zeroize();
        self.tk.copy_from_slice(tk);
        self.tx_pn = 0;
        self.receive = [ReplayWindow { last_seen_pn: rsc }; 17];
        Ok(true)
    }
    /// Protect a validated native data header/body. Increment before handing
    /// bytes to USB; a dropped or failed TX consumes its PN permanently.
    pub fn protect(&mut self, header: &[u8], body: &[u8]) -> Result<Vec<u8>, Error> {
        let shape = shape(header)?;
        if self.role != Role::Pairwise
            || header[1] & 3 != 1
            || header[4..10] != self.peer
            || header[10..16] != self.local
            || header[16..22] == [0; 6]
        {
            return Err(Error::Key);
        }
        if body.len() > MAX_BODY {
            return Err(Error::Length);
        }
        if self.tx_pn == MAX_PN {
            return Err(Error::Exhausted);
        }
        self.tx_pn += 1;
        let mut ciphertext = Zeroizing::new(body.to_vec());
        Ok(ccmp::protect(
            &Ccm,
            header,
            &self.tk,
            self.tx_pn,
            self.key_id,
            shape.priority,
            false,
            &mut ciphertext,
        ))
    }
    /// Authenticate before committing this key/TID's replay tracker. All
    /// admission/MIC/replay failures leave the entire wire buffer unchanged.
    pub fn unprotect(&mut self, header: &[u8], wire: &mut [u8]) -> Result<Vec<u8>, Error> {
        let shape = shape(header)?;
        if header[1] & 3 != 2
            || header[10..16] != self.peer
            || !unicast(header[16..22].try_into().unwrap())
            || match self.role {
                Role::Pairwise => header[4..10] != self.local,
                Role::Group => header[4] & 1 == 0,
            }
        {
            return Err(Error::Key);
        }
        if !(16..=MAX_BODY + 16).contains(&wire.len()) {
            return Err(Error::Length);
        }
        if wire[2] != 0 || wire[3] & 0x3f != 0x20 || wire[3] >> 6 != self.key_id {
            return Err(Error::Key);
        }
        // Keep the driver transaction explicit even though shared unprotect
        // also commits only after MIC. This binds state to the selected TID.
        let mut candidate = self.receive[shape.index];
        let plaintext = ccmp::unprotect(
            &Ccm,
            header,
            &self.tk,
            shape.priority,
            false,
            &mut candidate,
            wire,
        )
        .map_err(Error::Crypto)?;
        self.receive[shape.index] = candidate;
        Ok(plaintext)
    }
}
fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
struct Shape {
    index: usize,
    priority: u8,
}
fn shape(header: &[u8]) -> Result<Shape, Error> {
    if header.len() < 24 || !matches!(header[0], 0x08 | 0x88) || header[1] & 0x40 == 0 {
        return Err(Error::Header);
    }
    // Fragment reassembly is not admitted in the initial station profile.
    if header[1] & 4 != 0 || header[22] & 15 != 0 {
        return Err(Error::Header);
    }
    let qos = header[0] & 0x80 != 0;
    let offset = if header[1] & 3 == 3 { 30 } else { 24 };
    let length =
        offset + if qos { 2 } else { 0 } + if qos && header[1] & 0x80 != 0 { 4 } else { 0 };
    if header.len() != length {
        return Err(Error::Header);
    }
    if qos {
        // A-MSDU needs separate subframe admission and is not enabled yet.
        if header[offset] & 0x80 != 0 {
            return Err(Error::Header);
        }
        let priority = header[offset] & 15;
        Ok(Shape {
            index: usize::from(priority),
            priority,
        })
    } else {
        Ok(Shape {
            index: NON_QOS,
            priority: 0,
        })
    }
}
#[cfg(feature = "kernel-test")]
#[path = "ccmp_runtime_tests.rs"]
mod tests;
