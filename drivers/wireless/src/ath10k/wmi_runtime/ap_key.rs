// SPDX-License-Identifier: GPL-2.0-or-later
//! AP-owned nohwcrypt CCMP; shared protocol/AES primitives, physical AP MACs.
//! Native peer/port/epoch admission precedes these methods. No native key ACK
//! is inferred: the admitted RAW image has hardware crypto disabled.
use super::Error;
use alloc::vec::Vec;
use narf_wireless::{
    ccmp::{self, AesCcm, CcmpError, ReplayWindow},
    KeyParams,
};
use zeroize::Zeroizing;

const MAX_PN: u64 = (1 << 48) - 1;
struct Ccm;
impl AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        bytes: &mut [u8],
    ) -> Result<[u8; 8], CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, bytes).map_err(|e| match e {
            narf_crypto::aes_ccm::Error::Length => CcmpError::TooLong,
            narf_crypto::aes_ccm::Error::Authentication => CcmpError::AuthFailed,
        })
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        bytes: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, bytes, tag).map_err(|_| CcmpError::AuthFailed)
    }
}
pub(super) fn digest(params: &KeyParams) -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(&params.key);
    hash.finalize()
}
#[derive(Debug, Default)]
pub(super) struct History(Vec<[u8; 32]>);
impl History {
    pub fn remember(&mut self, digest: [u8; 32]) -> Result<(), Error> {
        if self.0.contains(&digest) || self.0.len() == 64 {
            return Err(Error::Unsupported);
        }
        self.0.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.0.push(digest);
        Ok(())
    }
}
pub(super) struct Key {
    tk: Zeroizing<[u8; 16]>,
    pub id: u8,
    pub peer: Option<[u8; 6]>,
    pub digest: [u8; 32],
    pn: u64,
    rx: [ReplayWindow; 17],
}
pub(super) struct Decoded {
    pub plain: Vec<u8>,
    index: usize,
    replay: ReplayWindow,
    digest: [u8; 32],
}
impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApSoftwareKey")
            .field("id", &self.id)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}
impl Key {
    pub fn sequence(&self) -> [u8; 6] {
        self.pn.to_le_bytes()[..6].try_into().unwrap()
    }
    pub fn new(params: &KeyParams) -> Result<Self, Error> {
        if params.cipher != narf_wireless::CIPHER_SUITE_CCMP
            || params.key.len() != 16
            || params.idx > 3
            || params.pairwise && params.idx != 0
            || params.pairwise != params.peer.is_some()
            || params.peer.is_some_and(|mac| !super::ap_wire::unicast(mac))
            || !matches!(params.seq.len(), 0 | 6)
            || params.default_mgmt
        {
            return Err(Error::Unsupported);
        }
        let mut bytes = [0; 8];
        bytes[..params.seq.len()].copy_from_slice(&params.seq);
        let floor = u64::from_le_bytes(bytes);
        let mut material = Zeroizing::new([0; 16]);
        material.copy_from_slice(&params.key);
        Ok(Self {
            tk: material,
            id: params.idx,
            peer: params.peer,
            digest: digest(params),
            pn: 0,
            rx: [ReplayWindow {
                last_seen_pn: floor,
            }; 17],
        })
    }
    pub fn matches(&self, params: &KeyParams) -> bool {
        self.id == params.idx && self.peer == params.peer && self.digest == digest(params)
    }
    /// Validate complete original FromDS DATA before consuming one AP-owned
    /// TX PN. Group and pairwise keys retain distinct IDs and destinations.
    pub fn protect(&mut self, own: [u8; 6], header: &[u8], body: &[u8]) -> Result<Vec<u8>, Error> {
        let tid = shape(header, 2)?;
        if header[10..16] != own
            || body.len() > 2304
            || self
                .peer
                .map_or(header[4] & 1 == 0, |peer| header[4..10] != peer)
        {
            return Err(Error::Malformed);
        }
        if self.pn == MAX_PN {
            return Err(Error::Exhausted);
        }
        self.pn += 1;
        let mut body = Zeroizing::new(body.to_vec());
        ccmp::protect(
            &Ccm,
            header,
            &self.tk,
            self.pn,
            self.id,
            tid.unwrap_or(0),
            false,
            &mut body,
        )
        .map_err(|_| Error::Malformed)
    }
    /// Original ToDS physical RA/TA/peer/TID and MIC precede replay commit.
    /// The caller then gates Ethernet/control publication in its same epoch.
    pub fn unprotect(
        &self,
        own: [u8; 6],
        header: &[u8],
        bytes: &mut [u8],
    ) -> Result<Decoded, Error> {
        let tid = shape(header, 1)?;
        if self.peer.is_none_or(|peer| header[10..16] != peer)
            || header[4..10] != own
            || !(16..=2320).contains(&bytes.len())
            || bytes[2] != 0
            || bytes[3] & 0x3f != 0x20
            || bytes[3] >> 6 != self.id
        {
            return Err(Error::Malformed);
        }
        let index = tid.map_or(16, usize::from);
        let mut replay = self.rx[index];
        let plain = ccmp::unprotect(
            &Ccm,
            header,
            &self.tk,
            tid.unwrap_or(0),
            false,
            &mut replay,
            bytes,
        )
        .map_err(|_| Error::Malformed)?;
        Ok(Decoded {
            plain,
            index,
            replay,
            digest: self.digest,
        })
    }
    pub fn commit(&mut self, decoded: Decoded) -> Result<Vec<u8>, Error> {
        if decoded.digest != self.digest
            || decoded.replay.last_seen_pn <= self.rx[decoded.index].last_seen_pn
        {
            return Err(Error::Malformed);
        }
        self.rx[decoded.index] = decoded.replay;
        Ok(decoded.plain)
    }
}
fn shape(header: &[u8], direction: u8) -> Result<Option<u8>, Error> {
    if header.len() < 24
        || !matches!(header[0], 8 | 0x88)
        || header[1] & 0xc7 != 0x40 | direction
        || header[22] & 15 != 0
        || header[16..22] == [0; 6]
    {
        return Err(Error::Malformed);
    }
    if header[0] == 0x88 {
        if header.len() != 26 || header[24] & !15 != 0 || header[25] != 0 || header[24] & 15 > 7 {
            return Err(Error::Unsupported);
        }
        Ok(Some(header[24] & 15))
    } else if header.len() == 24 {
        Ok(None)
    } else {
        Err(Error::Malformed)
    }
}
