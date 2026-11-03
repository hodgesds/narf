//! Explicit CCMP fragment authentication and opaque key-color reassembly.
//! Ordinary Key methods keep refusing fragments. No native/source/port grant.
use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
const CACHE: usize = 4;
const LIFETIME_MS: u64 = 2_000;
#[derive(Clone)]
/// Original key-instance lifetime, a fixed denial-only observation. It cannot
/// expose or keep a key installed, and grants no packet/native/port authority.
pub struct KeyIdentity(Arc<AtomicBool>);
impl core::fmt::Debug for KeyIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FragmentKeyIdentity")
    }
}
impl KeyIdentity {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
    pub(super) fn retire(&self) {
        self.0.store(false, Ordering::Release);
    }
    pub fn current(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        self.current() && other.current() && Arc::ptr_eq(&self.0, &other.0)
    }
}
/// An original header/body authenticated by exactly one retained key instance.
/// No key bytes, native receive proof, radio or controlled-port grant is exposed.
pub struct AuthenticatedFragment {
    header: Vec<u8>,
    body: Zeroizing<Vec<u8>>,
    color: KeyIdentity,
    pn: u64,
    index: usize,
    management: bool,
}
impl core::fmt::Debug for AuthenticatedFragment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthenticatedFragment")
            .field("body_len", &self.body.len())
            .field("management", &self.management)
            .finish_non_exhaustive()
    }
}
struct Shape {
    index: usize,
    priority: u8,
    management: bool,
}
fn shape(header: &[u8]) -> Result<Shape, Error> {
    if header.len() < 24
        || header[0] & 3 != 0
        || header[1] & 0xc0 != 0x40
        || header[4] & 1 != 0
        || header[22] & 15 == 0 && header[1] & 4 == 0
        || header[22] & 15 == 15 && header[1] & 4 != 0
    {
        return Err(Error::Header);
    }
    let management = header[0] & 12 == 0;
    if management {
        if header.len() != 24 || !matches!(header[0], 0xa0 | 0xc0 | 0xd0) || header[1] & 3 != 0 {
            return Err(Error::Header);
        }
        return Ok(Shape {
            index: MGMT,
            priority: 0,
            management: true,
        });
    }
    if !matches!(header[0], 8 | 0x88) || !matches!(header[1] & 3, 1 | 2) {
        return Err(Error::Header);
    }
    if header[0] == 0x88 {
        if header.len() != 26 || header[24] & 0xf0 != 0 || header[25] != 0 {
            return Err(Error::Header);
        }
        Ok(Shape {
            index: usize::from(header[24] & 15),
            priority: header[24] & 15,
            management: false,
        })
    } else if header.len() == 24 {
        Ok(Shape {
            index: NON_QOS,
            priority: 0,
            management: false,
        })
    } else {
        Err(Error::Header)
    }
}
impl Key {
    /// Read-only fixture observation of the actual retained transmit counter;
    /// compiled out of production and never an install/reset/grant operation.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn fragment_model_tx_pn(&self) -> u64 {
        self.tx_pn
    }
    pub(crate) fn retire_fragment_identity(&self) {
        if let Some(color) = self.fragment_color.as_ref() {
            color.retire();
        }
    }
    pub(crate) fn fragment_key_identity(&mut self) -> Result<KeyIdentity, Error> {
        if self.role != Role::Pairwise || self.mld.is_some() {
            return Err(Error::Key);
        }
        Ok(self
            .fragment_color
            .get_or_insert_with(KeyIdentity::new)
            .clone())
    }
    /// Protect one original fragment. Caller already owns a bounded train
    /// with one SN/strict frag0..15/MoreFrag and fixed rate/NAV/terminal order.
    /// Every successful or failed seal consumes a fresh PN; Busy never calls
    /// this API again for an already retained train. MLD stays unsupported.
    pub fn protect_fragment(&mut self, header: &[u8], body: &[u8]) -> Result<Vec<u8>, Error> {
        let shape = shape(header)?;
        if self.role != Role::Pairwise
            || self.mld.is_some()
            || header[4..10] != self.peer
            || header[10..16] != self.local
            || !shape.management && (header[1] & 3 != 1 || header[16..22] == [0; 6])
        {
            return Err(Error::Key);
        }
        if body.is_empty() || body.len() > MAX_BODY {
            return Err(Error::Length);
        }
        if self.tx_pn == MAX_PN {
            return Err(Error::Exhausted);
        }
        self.tx_pn += 1;
        let mut plaintext = Zeroizing::new(body.to_vec());
        ccmp::protect(
            &Ccm,
            header,
            &self.tk,
            self.tx_pn,
            self.key_id,
            shape.priority,
            shape.management,
            &mut plaintext,
        )
        .map_err(Error::Crypto)
    }
    /// Authenticate the exact original fragment before committing its key/TID
    /// replay state. Fragment-number and MoreFrag remain in the CCMP AAD;
    /// no header normalization occurs before authentication. MLD/group denied.
    pub fn unprotect_fragment(
        &mut self,
        header: &[u8],
        wire: &mut [u8],
    ) -> Result<AuthenticatedFragment, Error> {
        let shape = shape(header)?;
        if self.role != Role::Pairwise
            || self.mld.is_some()
            || header[4..10] != self.local
            || header[10..16] != self.peer
            || !shape.management
                && (header[1] & 3 != 2 || !unicast(header[16..22].try_into().unwrap()))
        {
            return Err(Error::Key);
        }
        if !(17..=MAX_BODY + 16).contains(&wire.len()) {
            return Err(Error::Length);
        }
        if wire[2] != 0 || wire[3] & 0x3f != 0x20 || wire[3] >> 6 != self.key_id {
            return Err(Error::Key);
        }
        let pn = u64::from_le_bytes([wire[0], wire[1], wire[4], wire[5], wire[6], wire[7], 0, 0]);
        let mut candidate = self.receive[shape.index];
        let body = ccmp::unprotect(
            &Ccm,
            header,
            &self.tk,
            shape.priority,
            shape.management,
            &mut candidate,
            wire,
        )
        .map_err(Error::Crypto)?;
        self.receive[shape.index] = candidate;
        let color = self
            .fragment_color
            .get_or_insert_with(KeyIdentity::new)
            .clone();
        Ok(AuthenticatedFragment {
            header: header.to_vec(),
            body: Zeroizing::new(body),
            color,
            pn,
            index: shape.index,
            management: shape.management,
        })
    }
}
struct Part {
    header: Vec<u8>,
    body: Zeroizing<Vec<u8>>,
    color: Option<KeyIdentity>,
    pn: Option<u64>,
    index: usize,
    management: bool,
}
struct Entry {
    header: Vec<u8>,
    body: Zeroizing<Vec<u8>>,
    color: Option<KeyIdentity>,
    pn: Option<u64>,
    index: usize,
    management: bool,
    sequence: u16,
    last: u8,
    first: u64,
}
/// Four-entry round-robin/two-second cache from mac80211 rx_h_defragment.
/// Public input requires authenticated original fragments. Security's private
/// plaintext EAPOL lane shares these same FOUR slots without gaining any
/// cryptographic authority. The native owner must still
/// prove original peer/channel/association/copy epochs and retire its cache on
/// source loss. Opaque key-color denial prevents mixing rekeyed material.
pub struct Reassembly {
    entries: [Option<Entry>; CACHE],
    next: usize,
}
impl core::fmt::Debug for Reassembly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FragmentReassembly")
            .field("pending", &self.pending())
            .finish_non_exhaustive()
    }
}
impl Default for Reassembly {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            next: 0,
        }
    }
}
/// A complete authenticated DATA or robust-management body with the first
/// original MAC header. Protected/MoreFrag/fragment number are cleared only
/// after every fragment's MIC, key-color and consecutive PN proof succeeded.
pub struct Reassembled {
    bytes: Vec<u8>,
    management: bool,
}
impl core::fmt::Debug for Reassembled {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reassembled")
            .field("len", &self.bytes.len())
            .field("management", &self.management)
            .finish_non_exhaustive()
    }
}
impl Reassembled {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn management(&self) -> bool {
        self.management
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl Reassembly {
    pub fn pending(&self) -> bool {
        self.entries.iter().any(Option::is_some)
    }
    pub fn clear(&mut self) {
        self.entries = core::array::from_fn(|_| None);
    }
    pub fn expire(&mut self, now_ms: u64) {
        for slot in &mut self.entries {
            if slot.as_ref().is_some_and(|entry| {
                entry.color.as_ref().is_some_and(|color| !color.current())
                    || now_ms < entry.first
                    || now_ms - entry.first > LIFETIME_MS
            }) {
                *slot = None;
            }
        }
    }
    pub fn push(
        &mut self,
        fragment: AuthenticatedFragment,
        now_ms: u64,
    ) -> Result<Option<Reassembled>, Error> {
        let AuthenticatedFragment {
            header,
            body,
            color,
            pn,
            index,
            management,
        } = fragment;
        self.push_inner(
            Part {
                header,
                body,
                color: Some(color),
                pn: Some(pn),
                index,
                management,
            },
            now_ms,
        )
    }
    /// Crate-private plaintext input is usable only by the retained Security
    /// EAPOL verifier. It returns bytes, never an authenticated-fragment proof.
    pub(crate) fn push_plain(
        &mut self,
        header: &[u8],
        body: &[u8],
        color: Option<KeyIdentity>,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        if header.len() < 24
            || !matches!(header[0], 8 | 0x88)
            || header[1] & 0xc3 != 2
            || header[4] & 1 != 0
            || header[22] & 15 == 0 && header[1] & 4 == 0
            || body.is_empty()
        {
            return Err(Error::Header);
        }
        let index = if header[0] == 0x88 {
            if header.len() != 26 || header[24] & 0xf0 != 0 || header[25] != 0 {
                return Err(Error::Header);
            }
            usize::from(header[24] & 15)
        } else {
            if header.len() != 24 {
                return Err(Error::Header);
            }
            NON_QOS
        };
        let part = Part {
            header: header.to_vec(),
            body: Zeroizing::new(body.to_vec()),
            color,
            pn: None,
            index,
            management: false,
        };
        self.push_inner(part, now_ms)
            .map(|frame| frame.map(Reassembled::into_bytes))
    }
    fn push_inner(&mut self, part: Part, now_ms: u64) -> Result<Option<Reassembled>, Error> {
        self.expire(now_ms);
        let Part {
            header,
            body,
            color,
            pn,
            index,
            management,
        } = part;
        if color.as_ref().is_some_and(|color| !color.current()) {
            return Err(Error::Key);
        }
        if header
            .len()
            .checked_add(body.len())
            .is_none_or(|length| length > MAX_BODY)
        {
            return Err(Error::Length);
        }
        let sc = u16::from_le_bytes([header[22], header[23]]);
        let number = (sc & 15) as u8;
        let sequence = sc >> 4;
        let more = header[1] & 4 != 0;
        if number == 15 && more {
            return Err(Error::Header);
        }
        if number == 0 {
            if !more {
                return Err(Error::Header);
            }
            self.entries[self.next] = Some(Entry {
                header,
                body,
                color,
                pn,
                index,
                management,
                sequence,
                last: 0,
                first: now_ms,
            });
            self.next = (self.next + 1) % CACHE;
            return Ok(None);
        }
        let Some(at) = self.entries.iter().position(|slot| {
            slot.as_ref().is_some_and(|entry| {
                entry.sequence == sequence
                    && entry.last + 1 == number
                    && entry.index == index
                    && entry.management == management
                    && entry.header[0] == header[0]
                    && entry.header[4..22] == header[4..22]
                    && entry.pn.is_some() == pn.is_some()
                    && match (&entry.color, &color) {
                        (None, None) => true,
                        (Some(a), Some(b)) => a.same(b),
                        _ => false,
                    }
            })
        }) else {
            return Err(Error::Header);
        };
        let entry = self.entries[at].as_mut().unwrap();
        if let Some(old) = entry.pn {
            if old.checked_add(1) != pn {
                return Err(Error::Crypto(CcmpError::Replay));
            }
        }
        if entry
            .body
            .len()
            .checked_add(body.len())
            .is_none_or(|length| length + entry.header.len() > MAX_BODY)
        {
            self.entries[at] = None;
            return Err(Error::Length);
        }
        entry
            .body
            .try_reserve(body.len())
            .map_err(|_| Error::Length)?;
        entry.body.extend_from_slice(&body);
        entry.last = number;
        entry.pn = pn;
        if more {
            return Ok(None);
        }
        let mut entry = self.entries[at].take().unwrap();
        entry
            .header
            .try_reserve(entry.body.len())
            .map_err(|_| Error::Length)?;
        entry.header[1] &= !(0x40 | 4);
        entry.header[22] &= 0xf0;
        entry.header.extend_from_slice(&entry.body);
        Ok(Some(Reassembled {
            bytes: entry.header,
            management,
        }))
    }
}

#[cfg(feature = "kernel-test")]
#[path = "packet_key_fragment_tests.rs"]
mod tests;
