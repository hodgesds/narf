// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained native install receipts and reinstallation denial. The firmware
//! owns CCMP PN/replay state; no host counter is exported as a native PN.
use super::{
    ap_native::KeyReceipt,
    ap_scope::{Capture, Epoch},
    ap_wire,
};
use crate::cyw43439::{runtime::Error, station::external};
use alloc::vec::Vec;
use narf_wireless::{ap_control::ApEmissionAuthority, KeyParams};
use zeroize::Zeroizing;

pub(crate) fn validate(key: &KeyParams) -> Result<(), Error> {
    if key.cipher != narf_wireless::CIPHER_SUITE_CCMP
        || key.key.len() != 16
        || key.default_mgmt
        || !matches!(key.seq.len(), 0 | 6)
        || key.pairwise && (key.idx != 0 || key.peer.is_none_or(|peer| !ap_wire::unicast(peer)))
        || !key.pairwise && (!(1..=3).contains(&key.idx) || key.peer.is_some())
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn digest(key: &KeyParams) -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(&key.key);
    hash.finalize()
}
/// Denial metadata only. Remember before the first install attempt, since a
/// cancelled/missing response may still have reached the firmware key cache.
#[derive(Default)]
pub(crate) struct History(Vec<[u8; 32]>);
impl History {
    pub(super) fn remember(&mut self, key: &KeyParams) -> Result<(), Error> {
        let digest = digest(key);
        if self.0.len() == 64 || self.0.contains(&digest) {
            return Err(Error::Unsupported);
        }
        self.0.try_reserve(1).map_err(|_| Error::Busy)?;
        self.0.push(digest);
        Ok(())
    }
}
pub(super) struct Installed {
    pub(super) index: u8,
    peer: Option<[u8; 6]>,
    digest: [u8; 32],
    initial_seq: [u8; 6],
    seq_len: usize,
    pub(super) epoch: Epoch,
    pub(super) source: ApEmissionAuthority,
    original: Capture,
}
impl Installed {
    /// Only after the matching native wsec_key transaction terminal and
    /// final original source/peer/role checks. Material is not retained.
    pub(super) fn from_receipt(key: &KeyParams, receipt: KeyReceipt) -> Result<Self, Error> {
        validate(key)?;
        let original = receipt.consume(key)?;
        let source = original.source.clone();
        let mut initial_seq = [0; 6];
        initial_seq[..key.seq.len()].copy_from_slice(&key.seq);
        Ok(Self {
            index: key.idx,
            peer: key.peer,
            digest: digest(key),
            initial_seq,
            seq_len: key.seq.len(),
            epoch: Epoch::new(),
            source,
            original,
        })
    }
    pub(super) fn current(&self) -> bool {
        self.epoch.current() && self.source.current() && self.original.current().is_ok()
    }
    /// A retry returns the retained receipt only. It cannot rewrite native
    /// TX PN/RX RSC or rebind a revoked original key actor to another socket.
    pub(super) fn same_retry(&self, key: &KeyParams) -> bool {
        validate(key).is_ok()
            && self.index == key.idx
            && self.peer == key.peer
            && self.digest == digest(key)
            && self.seq_len == key.seq.len()
            && self.initial_seq[..self.seq_len] == key.seq
            && self.current()
    }
}
impl Drop for Installed {
    fn drop(&mut self) {
        self.epoch.close();
    }
}
pub(super) fn body(key: &KeyParams) -> Result<Zeroizing<[u8; external::WSEC_KEY_LEN]>, Error> {
    validate(key)?;
    external::wsec_key(key.idx, &key.key, &key.seq, key.peer)
}
/// Linux DEL_KEY clears a PRIMARY default slot. It does not define a
/// peer-selective OFF encoding. Pairwise deletion uses actual SCB removal.
pub(super) fn off_group(index: u8) -> Result<[u8; external::WSEC_KEY_LEN], Error> {
    if !(1..=3).contains(&index) {
        return Err(Error::Unsupported);
    }
    let mut out = [0; external::WSEC_KEY_LEN];
    out[..4].copy_from_slice(&u32::from(index).to_le_bytes());
    out[116..120].copy_from_slice(&external::PRIMARY_KEY.to_le_bytes());
    Ok(out)
}
