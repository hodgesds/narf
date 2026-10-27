//! Slot records and their serialization (power-suspend design §3.1,
//! §4.2, §10.2).
//!
//! A slot record is the on-disk form of one enrolled factor's wrap of
//! the slot master secret (SMS): the anchor kind, the SMS epoch it
//! belongs to, the anchor's public parameters, and the wrapped blob
//! in the anchor's own framing. Records are the *only* form in which
//! SMS ever touches a disk — the plaintext secret exists only in
//! [`Secret32`] custody in memory.
//!
//! The record codec is shared by the two places records are written:
//! the suspend partition's slot area (the [`SlotArea`] container) and
//! the image header's embedded slot array (format §3.3), so both
//! parties parse exactly the bytes the writer produced. The parser is
//! strict and total: every length is bounds-checked against the
//! remaining input and a fixed cap before any allocation, trailing
//! garbage is an error, and no input can make it panic — slot bytes
//! are untrusted input on the resume path.

use alloc::vec::Vec;
use core::fmt;

use super::anchor::{AnchorKind, WrappedSlot};
use super::custody::Secret32;
use super::ServiceError;

/// Largest accepted anchor-params payload. Real anchors need a few
/// hundred bytes at most (a TPM sealed blob, a credential id + salt);
/// the cap exists so a hostile length prefix cannot force an absurd
/// allocation in the resume environment.
pub const MAX_SLOT_PARAMS_LEN: usize = 64 * 1024;
/// Largest accepted wrapped-blob payload (same reasoning as above).
pub const MAX_SLOT_BLOB_LEN: usize = 64 * 1024;
/// Most slot records accepted in one epoch / container.
pub const MAX_SLOTS_PER_EPOCH: usize = 256;

/// One enrolled factor's wrap of the SMS, in on-disk form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotRecord {
    pub kind: AnchorKind,
    pub epoch: u64,
    pub params: Vec<u8>,
    pub blob: Vec<u8>,
}

impl SlotRecord {
    /// The anchor-facing view of this record (kind + epoch are the
    /// service's framing around it).
    pub fn wrapped(&self) -> WrappedSlot {
        WrappedSlot {
            params: self.params.clone(),
            blob: self.blob.clone(),
        }
    }

    fn write_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind.code());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&(self.params.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.params);
        out.extend_from_slice(&(self.blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.blob);
    }
}

/// Bounds-checked cursor over untrusted bytes. Every read either
/// consumes exactly the requested bytes or fails with
/// [`ServiceError::Malformed`]; lengths are never trusted.
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub(crate) fn is_done(&self) -> bool {
        self.pos == self.bytes.len()
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], ServiceError> {
        if self.remaining() < n {
            return Err(ServiceError::Malformed);
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.bytes[start..self.pos])
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ServiceError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ServiceError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, ServiceError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ServiceError> {
        let b = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }
}

fn parse_record(cur: &mut Cursor<'_>) -> Result<SlotRecord, ServiceError> {
    let kind = AnchorKind::from_code(cur.u8()?).ok_or(ServiceError::Malformed)?;
    let epoch = cur.u64()?;
    let params_len = cur.u32()? as usize;
    if params_len > MAX_SLOT_PARAMS_LEN {
        return Err(ServiceError::Malformed);
    }
    let params = cur.take(params_len)?.to_vec();
    let blob_len = cur.u32()? as usize;
    if blob_len > MAX_SLOT_BLOB_LEN {
        return Err(ServiceError::Malformed);
    }
    let blob = cur.take(blob_len)?.to_vec();
    Ok(SlotRecord {
        kind,
        epoch,
        params,
        blob,
    })
}

/// Serialize a list of slot records (count-prefixed). This is the
/// shared codec used inside the image header.
pub(crate) fn write_records(records: &[SlotRecord], out: &mut Vec<u8>) {
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for record in records {
        record.write_into(out);
    }
}

/// Parse a count-prefixed record list from `cur`, advancing it past
/// the list. Shared by the whole-input codec below and the image
/// header parser, where the list sits mid-preamble.
pub(crate) fn read_records_from(cur: &mut Cursor<'_>) -> Result<Vec<SlotRecord>, ServiceError> {
    let count = cur.u32()? as usize;
    if count > MAX_SLOTS_PER_EPOCH {
        return Err(ServiceError::Malformed);
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(parse_record(cur)?);
    }
    Ok(records)
}

/// The suspend partition's slot area: every retained epoch's slot
/// records, without any plaintext secret (design §10.2 — the
/// non-secret mirror the resume environment finds slots through).
/// Serialization is `MAGIC ‖ epoch_count ‖ { epoch ‖ records }`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlotArea {
    pub epochs: Vec<EpochSlots>,
}

/// One epoch's records inside a [`SlotArea`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochSlots {
    pub epoch: u64,
    pub records: Vec<SlotRecord>,
}

const SLOT_AREA_MAGIC: &[u8; 8] = b"NARFSLT1";
const MAX_SLOT_AREA_EPOCHS: usize = 64;

impl SlotArea {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SLOT_AREA_MAGIC);
        out.extend_from_slice(&(self.epochs.len() as u32).to_le_bytes());
        for group in &self.epochs {
            out.extend_from_slice(&group.epoch.to_le_bytes());
            write_records(&group.records, &mut out);
        }
        out
    }

    /// Parse a slot area. Strict and total, like the record codec:
    /// bad magic, truncation, oversized counts, and trailing garbage
    /// are all `Malformed`, never a panic.
    pub fn parse(bytes: &[u8]) -> Result<Self, ServiceError> {
        let mut cur = Cursor::new(bytes);
        if cur.take(8)? != SLOT_AREA_MAGIC {
            return Err(ServiceError::Malformed);
        }
        let epoch_count = cur.u32()? as usize;
        if epoch_count > MAX_SLOT_AREA_EPOCHS {
            return Err(ServiceError::Malformed);
        }
        let mut epochs = Vec::with_capacity(epoch_count);
        for _ in 0..epoch_count {
            let epoch = cur.u64()?;
            // Parse the count-prefixed list from the area's own
            // cursor: the record codec is self-delimiting, so the
            // cursor lands exactly on the next epoch group. (An
            // earlier draft re-sliced the remainder and demanded a
            // whole-input parse of it — which rejected every area
            // with more than one epoch group, since the remainder
            // includes the later groups.)
            let records = read_records_from(&mut cur)?;
            epochs.push(EpochSlots { epoch, records });
        }
        if !cur.is_done() {
            return Err(ServiceError::Malformed);
        }
        Ok(SlotArea { epochs })
    }

    /// Records for one epoch, if the area retains it.
    pub fn records_for(&self, epoch: u64) -> Option<&[SlotRecord]> {
        self.epochs
            .iter()
            .find(|g| g.epoch == epoch)
            .map(|g| g.records.as_slice())
    }
}

/// Running custody of one SMS epoch: the plaintext secret in
/// [`Secret32`] custody, its enrolled slot records, and the images
/// written under it that have not yet been consumed (an epoch with
/// outstanding images must not be retired — design §10.4).
pub(crate) struct EpochCustody {
    pub epoch: u64,
    pub sms: Secret32,
    pub slots: Vec<SlotRecord>,
    pub images_outstanding: Vec<[u8; 16]>,
}

impl fmt::Debug for EpochCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochCustody")
            .field("epoch", &self.epoch)
            .field("sms", &self.sms)
            .field("slots", &self.slots.len())
            .field("images_outstanding", &self.images_outstanding.len())
            .finish()
    }
}

/// The running slot store: every retained epoch's custody, plus
/// which epoch is current (the one new images are written under).
#[derive(Debug, Default)]
pub(crate) struct SlotStore {
    pub epochs: Vec<EpochCustody>,
    pub current: Option<u64>,
}

impl SlotStore {
    pub(crate) fn current_epoch(&self) -> Option<u64> {
        self.current
    }

    pub(crate) fn get(&self, epoch: u64) -> Option<&EpochCustody> {
        self.epochs.iter().find(|e| e.epoch == epoch)
    }

    pub(crate) fn get_mut(&mut self, epoch: u64) -> Option<&mut EpochCustody> {
        self.epochs.iter_mut().find(|e| e.epoch == epoch)
    }

    pub(crate) fn insert(&mut self, custody: EpochCustody) {
        self.epochs.push(custody);
    }

    pub(crate) fn remove(&mut self, epoch: u64) -> Option<EpochCustody> {
        let idx = self.epochs.iter().position(|e| e.epoch == epoch)?;
        Some(self.epochs.remove(idx))
    }

    /// Snapshot of the store in persisted (secret-free) form.
    pub(crate) fn slot_area(&self) -> SlotArea {
        SlotArea {
            epochs: self
                .epochs
                .iter()
                .map(|e| EpochSlots {
                    epoch: e.epoch,
                    records: e.slots.clone(),
                })
                .collect(),
        }
    }
}
