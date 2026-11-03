// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B AP host CCMP owner and retained temporal-key history (shared
//! shape with the mt7921 AP owner). rtw89 keeps `RTW89_ADDR_CAM_SEC_NORMAL`
//! with no security CAM entry while this owner handles packets, so every
//! pairwise/group key is applied here (mac80211 wpa.c `ccmp_encrypt_skb` /
//! `ieee80211_crypto_ccmp_decrypt` for a software key).
use alloc::{collections::BTreeMap, vec::Vec};
use narf_wireless::ccmp::{self, AesCcm, CcmpError, ReplayWindow};
use zeroize::Zeroizing;

const MAX_PN: u64 = (1 << 48) - 1;
const HISTORY_LIMIT: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Error {
    Header,
    Key,
    Replay,
    Exhausted,
    Allocation,
    Authentication,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Target {
    Pairwise([u8; 6]),
    Group(u8),
}

/// Secret staging is constructed synchronously, before an async operation
/// exists. Dropping an unpolled key operation still erases its temporal key.
pub(in crate::rtw89) struct Install {
    pub target: Target,
    pub tk: Zeroizing<[u8; 16]>,
    pub rsc: u64,
}
impl core::fmt::Debug for Install {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApKeyInstall")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}
impl Install {
    pub fn prepare(params: narf_wireless::KeyParams) -> Result<Self, Error> {
        let owned = narf_wireless::OwnedKey::new(params);
        Self::from_params(owned.params())
    }
    pub fn from_params(params: &narf_wireless::KeyParams) -> Result<Self, Error> {
        if params.cipher != 0x000f_ac04
            || params.key.len() != 16
            || params.default_mgmt
            || !matches!(params.seq.len(), 0 | 6)
        {
            return Err(Error::Key);
        }
        let target = target(params.idx, params.pairwise, params.peer)?;
        let mut tk = Zeroizing::new([0; 16]);
        tk.copy_from_slice(&params.key);
        let mut rsc = [0; 8];
        rsc[..params.seq.len()].copy_from_slice(&params.seq);
        Ok(Self {
            target,
            tk,
            rsc: u64::from_le_bytes(rsc),
        })
    }
}
pub(in crate::rtw89) fn target(
    index: u8,
    pairwise: bool,
    peer: Option<[u8; 6]>,
) -> Result<Target, Error> {
    match (index, pairwise, peer) {
        (0, true, Some(peer)) if peer != [0; 6] && peer[0] & 1 == 0 => Ok(Target::Pairwise(peer)),
        (0..=3, false, None) => Ok(Target::Group(index)),
        _ => Err(Error::Key),
    }
}

pub(in crate::rtw89) struct Ccm;
impl AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body).map_err(|e| match e {
            narf_crypto::aes_ccm::Error::Length => CcmpError::TooLong,
            narf_crypto::aes_ccm::Error::Authentication => CcmpError::AuthFailed,
        })
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
struct Slot {
    tk: Zeroizing<[u8; 16]>,
    tx_pn: u64,
    rx: [ReplayWindow; 17],
}
impl Slot {
    fn new(tk: &[u8; 16], rsc: u64) -> Self {
        Self {
            tk: Zeroizing::new(*tk),
            tx_pn: 0,
            rx: [ReplayWindow { last_seen_pn: rsc }; 17],
        }
    }
    fn same(&self, tk: &[u8; 16]) -> bool {
        same(self.tk.as_slice(), tk)
    }
}
/// History survives role stop/reset for this native device owner. Deleting a
/// key never makes its material eligible for a fresh PN space. Exhaustion
/// refuses a new key instead of evicting evidence or resetting a counter.
#[derive(Default)]
pub(in crate::rtw89) struct Keys {
    pair: BTreeMap<[u8; 6], Slot>,
    group: [Option<Slot>; 4],
    history: Vec<Zeroizing<[u8; 16]>>,
}
impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApCcmpKeys")
            .field("peers", &self.pair.len())
            .field("material_generations", &self.history.len())
            .finish_non_exhaustive()
    }
}
impl Keys {
    pub fn clear_active(&mut self) {
        self.pair.clear();
        self.group.fill_with(|| None);
    }
    pub fn has_pair(&self, peer: [u8; 6]) -> bool {
        self.pair.contains_key(&peer)
    }
    pub fn has_group(&self, index: u8) -> bool {
        self.group
            .get(usize::from(index))
            .is_some_and(Option::is_some)
    }
    /// Identical current material preserves every RX/TX counter. Material
    /// retired from any key ID or peer cannot return with a reset nonce.
    pub fn install(&mut self, target: Target, key: &[u8; 16], rsc: u64) -> Result<bool, Error> {
        if !self.check_install(target, key, rsc)? {
            return Ok(false);
        }
        self.history.try_reserve(1).map_err(|_| Error::Allocation)?;
        self.history.push(Zeroizing::new(*key));
        let slot = Slot::new(key, rsc);
        match target {
            Target::Pairwise(peer) => {
                self.pair.insert(peer, slot);
            }
            Target::Group(id) => self.group[usize::from(id)] = Some(slot),
        }
        Ok(true)
    }
    /// Preflight never changes current ports/queues or retires a live key.
    pub fn check_install(&self, target: Target, key: &[u8; 16], rsc: u64) -> Result<bool, Error> {
        if rsc > MAX_PN
            || matches!(target,Target::Group(id) if id>3)
            || matches!(target,Target::Pairwise(mac) if mac==[0;6] || mac[0]&1!=0)
        {
            return Err(Error::Key);
        }
        let current = match target {
            Target::Pairwise(peer) => self.pair.get(&peer),
            Target::Group(id) => self.group[usize::from(id)].as_ref(),
        };
        if current.is_some_and(|slot| slot.same(key)) {
            return Ok(false);
        }
        if self.history.iter().any(|old| same(old.as_slice(), key)) {
            return Err(Error::Key);
        }
        if self.history.len() == HISTORY_LIMIT {
            return Err(Error::Exhausted);
        }
        Ok(true)
    }
    /// The last transmit PN consumed on `target` (GET_KEY sequence).
    pub fn transmit_pn(&self, target: Target) -> Result<u64, Error> {
        match target {
            Target::Pairwise(peer) => self.pair.get(&peer),
            Target::Group(id) => self.group.get(usize::from(id)).and_then(Option::as_ref),
        }
        .map(|slot| slot.tx_pn)
        .ok_or(Error::Key)
    }
    pub fn remove(&mut self, target: Target) -> Result<(), Error> {
        let found = match target {
            Target::Pairwise(peer) => self.pair.remove(&peer).is_some(),
            Target::Group(id) => self
                .group
                .get_mut(usize::from(id))
                .is_some_and(|s| s.take().is_some()),
        };
        if found {
            Ok(())
        } else {
            Err(Error::Key)
        }
    }
    pub fn protect(
        &mut self,
        own: [u8; 6],
        target: Target,
        header: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (_, priority) = shape(header)?;
        if header[1] & 3 != 2 || header[10..16] != own || body.len() > 4096 {
            return Err(Error::Header);
        }
        let (slot, id) = match target {
            Target::Pairwise(peer) if header[4..10] == peer => {
                (self.pair.get_mut(&peer).ok_or(Error::Key)?, 0)
            }
            Target::Group(id) if header[4] & 1 != 0 => (
                self.group
                    .get_mut(usize::from(id))
                    .and_then(Option::as_mut)
                    .ok_or(Error::Key)?,
                id,
            ),
            _ => return Err(Error::Key),
        };
        if slot.tx_pn == MAX_PN {
            return Err(Error::Exhausted);
        }
        slot.tx_pn += 1; // Publication failure/cancellation never reuses a PN.
        let mut scratch = Zeroizing::new(body.to_vec());
        ccmp::protect(
            &Ccm,
            header,
            &slot.tk,
            slot.tx_pn,
            id,
            priority,
            false,
            &mut scratch,
        )
        .map_err(|_| Error::Authentication)
    }
    pub fn unprotect(
        &mut self,
        own: [u8; 6],
        peer: [u8; 6],
        header: &[u8],
        wire: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (index, priority) = shape(header)?;
        if header[1] & 3 != 1
            || header[4..10] != own
            || header[10..16] != peer
            || !(16..=4112).contains(&wire.len())
            || wire[2] != 0
            || wire[3] != 0x20
        {
            return Err(Error::Header);
        }
        let slot = self.pair.get_mut(&peer).ok_or(Error::Key)?;
        let mut replay = slot.rx[index];
        let mut scratch = Zeroizing::new(wire.to_vec());
        let plaintext = ccmp::unprotect(
            &Ccm,
            header,
            &slot.tk,
            priority,
            false,
            &mut replay,
            &mut scratch,
        )
        .map_err(|e| match e {
            CcmpError::Replay => Error::Replay,
            _ => Error::Authentication,
        })?;
        slot.rx[index] = replay;
        Ok(plaintext)
    }
}
fn shape(header: &[u8]) -> Result<(usize, u8), Error> {
    if !matches!(header.len(), 24 | 26)
        || !matches!(header[0], 0x08 | 0x88)
        || (header[0] == 0x88) != (header.len() == 26)
        || header[1] & 0xc4 != 0x40
        || header[22] & 15 != 0
        || header[4..10] == [0; 6]
        || header[10..16] == [0; 6]
        || header[10] & 1 != 0
        || header[16..22] == [0; 6]
    {
        return Err(Error::Header);
    }
    if header.len() == 26 {
        // No A-MSDU/PSMP admission. EOSP (bit 4) is masked out of the AAD
        // (`ccmp_special_blocks`: qos_tid & IEEE80211_QOS_CTL_TID_MASK), so
        // a U-APSD rewrite after protection keeps the MIC valid.
        if header[24] & 0xe0 != 0 || header[25] != 0 {
            return Err(Error::Header);
        }
        Ok((usize::from(header[24] & 15), header[24] & 15))
    } else {
        Ok((16, 0))
    }
}

/// Constant-time equality for retained temporal-key material.
fn same(a: &[u8], b: &[u8; 16]) -> bool {
    a.len() == 16 && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
