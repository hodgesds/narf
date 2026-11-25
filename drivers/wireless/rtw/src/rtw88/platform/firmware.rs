//! `narf_firmware` for the module: firmware files through
//! `narf_firmware_open` / `_read` / `_signed` / `_close`.
//!
//! The driver opens the NIC image and its signed per-board records
//! (`N21Q`, `N2BP`, ...) by name and reads them through a view borrowed
//! from the blob capability, as built in. Here `open` reads the whole file
//! once and keeps it for the module's lifetime (each name at most once, so
//! the 500 ms provisioning retries do not re-read it); the blob capability
//! names that cache slot and `view_of` borrows from it.
//!
//! The KABI reports whether a file carries a verified signer
//! (`narf_firmware_signed`) but not the signer's key. The driver only ever
//! requires that a record *is* signed, so a signed file's view reports
//! [`MODULE_SIGNER`] as its signer and an unsigned one reports none.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::ffi;
use super::narf_capabilities::{Cap, Read, Write};
use super::narf_lib::sync::IrqSafeSpinLock;

/// The firmware registry (the loader's authority object).
#[derive(Debug)]
pub enum FirmwareRegistry {}
/// One registered firmware file.
#[derive(Debug)]
pub enum FirmwareBlob {}

/// The signer a signed file's view reports: the KABI proves a verified
/// signer without naming it.
pub const MODULE_SIGNER: [u8; 32] = [0; 32];

/// Why a firmware file could not be had (the built-in variants).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirmwareError {
    NotFound,
    SignatureInvalid,
    BadFormat,
    OutOfMemory,
    AuthorityRevoked,
    UnsignedRejected,
    InvalidName,
    BufferTooSmall,
}

/// A read-only view of an opened file.
#[derive(Clone, Copy, Debug)]
pub struct BlobView<'a> {
    pub signer: Option<[u8; 32]>,
    pub bytes: &'a [u8],
    /// No physical address crosses the KABI; USB never DMAs from it.
    pub phys: u64,
}

struct Entry {
    name: String,
    signed: bool,
    /// Never freed while the module is loaded: views borrow from it.
    bytes: &'static [u8],
}

/// Files read so far; a blob capability's id is its index here.
static CACHE: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

/// The KABI reads at most this much per call.
const CHUNK: usize = 64 * 1024;
/// Largest file accepted (rtw88 images are under 1 MiB).
const MAX_FILE: usize = 4 << 20;

/// The trusted loader's authority. In the module that is the module's own
/// `Firmware:Read` grant, so it always exists.
pub fn trusted_loader_authority() -> Option<Cap<FirmwareRegistry, Write>> {
    Some(Cap::token(0))
}

/// `request_firmware`: open `name`, reading it through the KABI the first
/// time.
pub fn open(
    name: &str,
    _auth: &Cap<FirmwareRegistry, Read>,
) -> Result<Cap<FirmwareBlob, Read>, FirmwareError> {
    if name.is_empty() || name.starts_with('/') || name.split('/').any(|c| c == "..") {
        return Err(FirmwareError::InvalidName);
    }
    if let Some(i) = CACHE.lock().iter().position(|e| e.name == name) {
        return Ok(Cap::token(i as u64));
    }
    let (signed, bytes) = read(name)?;
    let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
    let mut cache = CACHE.lock();
    // A concurrent open of the same name may have won; keep the first.
    if let Some(i) = cache.iter().position(|e| e.name == name) {
        return Ok(Cap::token(i as u64));
    }
    cache.push(Entry {
        name: String::from(name),
        signed,
        bytes,
    });
    Ok(Cap::token((cache.len() - 1) as u64))
}

/// The opened file's bytes and signer.
pub fn view_of(cap: &Cap<FirmwareBlob, Read>) -> Result<BlobView<'_>, FirmwareError> {
    let cache = CACHE.lock();
    let entry = cache
        .get(cap.id() as usize)
        .ok_or(FirmwareError::AuthorityRevoked)?;
    Ok(BlobView {
        signer: entry.signed.then_some(MODULE_SIGNER),
        bytes: entry.bytes,
        phys: 0,
    })
}

fn read(name: &str) -> Result<(bool, Vec<u8>), FirmwareError> {
    let (mut handle, mut size) = (0u64, 0usize);
    // SAFETY: `name` is a live `&str`; both outputs are live locals.
    let rc = unsafe { ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) };
    if rc != 0 {
        return Err(FirmwareError::NotFound);
    }
    let result = (|| {
        if size == 0 || size > MAX_FILE {
            return Err(FirmwareError::BadFormat);
        }
        // SAFETY: argument-only call on our open handle.
        let signed = unsafe { ffi::narf_firmware_signed(handle) } == 1;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| FirmwareError::OutOfMemory)?;
        bytes.resize(size, 0);
        let mut at = 0usize;
        while at < size {
            let want = (size - at).min(CHUNK);
            let mut got = 0usize;
            // SAFETY: `bytes[at..at + want]` is writable and in bounds.
            let rc = unsafe {
                ffi::narf_firmware_read(handle, at as u64, bytes[at..].as_mut_ptr(), want, &mut got)
            };
            if rc != 0 || got == 0 {
                return Err(FirmwareError::BadFormat);
            }
            at += got;
        }
        Ok((signed, bytes))
    })();
    // SAFETY: closing our own open handle once.
    let _ = unsafe { ffi::narf_firmware_close(handle) };
    result
}
