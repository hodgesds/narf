// SPDX-License-Identifier: GPL-2.0-or-later
//! Module build of the signed deployment board selection: the same NBSP v1
//! manifest ([`super::MANIFEST`]), the same record parser and matching, and
//! the same per-asset rules as the built-in reads — but over the KABI
//! firmware exports instead of the kernel's `FirmwareRegistry` caps.
//!
//! - The manifest must carry a verified signer (`narf_firmware_signed`).
//! - Every asset is read whole and must match its record's length and
//!   SHA-256 exactly, and carry a signer where the record says so.
//! - A [`Proof`] keeps one receipt per file. The KABI exposes no blob
//!   identity to re-check, so [`Proof::validate`] re-opens each file and
//!   refuses when it disappeared or its size or signedness changed; the
//!   bytes themselves were hashed once at load, and the booted firmware is
//!   those bytes.
use super::{executable_shape, parse, Asset, Assets, Error, Family, Selection};
use crate::platform::{bus::HostIdentity, firmware};
use alloc::{string::String, sync::Arc, vec::Vec};

/// Largest file any record may name (the built-in bound).
const MAX_FILE: usize = 16 * 1024 * 1024;

/// What a successful read saw.
#[derive(Clone, Debug)]
pub(super) struct Receipt {
    key: String,
    length: usize,
    signed: bool,
}
impl Receipt {
    fn check(&self) -> Result<(), Error> {
        match firmware::stat(&self.key) {
            Some((length, signed)) if length == self.length && signed == self.signed => Ok(()),
            _ => Err(Error::Stale),
        }
    }
}

/// The receipts of one selection's manifest and assets.
#[derive(Debug)]
pub(crate) struct Proof {
    receipts: Vec<Receipt>,
}
impl Proof {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.receipts.iter().try_for_each(Receipt::check)
    }
}

/// The built-in `read_using`: the whole file, its signer and, for a record
/// asset, its exact length and digest.
fn read(key: &str, asset: Option<&Asset>, signed: bool) -> Result<(Vec<u8>, Receipt), Error> {
    let blob = firmware::load(key, MAX_FILE).map_err(|error| match error {
        firmware::FwError::NotFound => Error::Missing,
        firmware::FwError::NoMemory => Error::Memory,
        firmware::FwError::Invalid => Error::Mismatch,
    })?;
    if blob.bytes.is_empty() {
        return Err(Error::Mismatch);
    }
    if signed && !blob.signed {
        return Err(Error::Unsigned);
    }
    if asset.is_none() && signed && blob.bytes.len() > super::super::firmware::NVRAM_MAX_SIZE {
        return Err(Error::Invalid);
    }
    if let Some(asset) = asset {
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(&blob.bytes);
        if blob.bytes.len() != asset.length || digest.finalize() != asset.sha256 {
            return Err(Error::Mismatch);
        }
    }
    let receipt = Receipt {
        key: key.into(),
        length: blob.bytes.len(),
        signed: blob.signed,
    };
    Ok((blob.bytes, receipt))
}

/// The built-in `select_using` over [`super::MANIFEST`]: the one record for
/// this family and host (PCIe: function 0, no card).
pub(crate) fn select_kabi(family: Family, host: HostIdentity) -> Result<Selection, Error> {
    let (bytes, source) = read(super::MANIFEST, None, true)?;
    let mut records = parse(&bytes)?;
    let mut found = None;
    for record in records.drain(..) {
        if record.family == family && record.host == host && record.function == 0 {
            if found.is_some() {
                return Err(Error::Ambiguous);
            }
            found = Some(record);
        }
    }
    let mut result = found.ok_or(Error::Mismatch)?;
    result.source = Some(source);
    Ok(result)
}

impl Selection {
    /// The built-in `load_using`: the manifest receipt still holds, then
    /// every asset is read and checked, then the whole proof is re-checked.
    pub(crate) fn load_kabi(&self) -> Result<Assets, Error> {
        let mut receipts = Vec::new();
        receipts.try_reserve_exact(4).map_err(|_| Error::Memory)?;
        if let Some(source) = &self.source {
            source.check()?;
            receipts.push(source.clone());
        }
        let mut bodies = Vec::new();
        bodies
            .try_reserve_exact(self.assets.len())
            .map_err(|_| Error::Memory)?;
        for asset in &self.assets {
            let (body, receipt) = read(&asset.key, Some(asset), asset.signed)?;
            bodies.push(body);
            receipts.push(receipt);
        }
        let mut bodies = bodies.into_iter();
        let result = Assets {
            firmware: bodies.next().ok_or(Error::Invalid)?,
            nvram: bodies.next().ok_or(Error::Invalid)?,
            clm: bodies.next().unwrap_or_default(),
            proof: Arc::new(Proof { receipts }),
        };
        executable_shape(self.family, result.firmware.len())?;
        result.proof.validate()?;
        Ok(result)
    }
}
