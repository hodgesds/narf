//! The firmware loader, module build, under the built-in
//! `narf_drivers_wireless_core::firmware_asset` names (`crate::firmware_asset`).
//!
//! Built in, an [`Asset`] is a private copy of a registry blob plus the
//! revocable capability, verified signer and SHA-256 the registry recorded
//! for it. A module reads the blob through `narf_firmware_open` / `_read`
//! (its manifest `Firmware` cap is the authority the kernel checks there),
//! asks the kernel for the verified signer (`narf_firmware_signer`) and
//! hashes the bytes itself, so every field the driver consumes carries the
//! same value it would built in. The capability is the module's unit
//! authority (see `kernel.rs`): the copy cannot be revoked under it.

use alloc::vec::Vec;

use super::kernel::narf_capabilities::{Cap, Read};
use super::kernel::narf_firmware::{FirmwareBlob, FirmwareError, FirmwareRegistry};

mod ffi {
    unsafe extern "C" {
        pub fn narf_firmware_open(
            name: *const u8,
            name_len: usize,
            out_handle: *mut u64,
            out_size: *mut usize,
        ) -> i32;
        pub fn narf_firmware_read(
            handle: u64,
            offset: u64,
            buf: *mut u8,
            len: usize,
            out_read: *mut usize,
        ) -> i32;
        pub fn narf_firmware_signer(handle: u64, out: *mut u8, len: usize) -> i32;
        pub fn narf_firmware_close(handle: u64) -> i32;
    }
}

const ENOENT: i32 = -2;
const ENODATA: i32 = -61;
/// The KABI reads at most this much per call.
const CHUNK: usize = 64 * 1024;

/// One loaded firmware file (the built-in `Asset` fields).
#[derive(Debug)]
pub struct Asset {
    pub bytes: Vec<u8>,
    pub cap: Cap<FirmwareBlob, Read>,
    pub signer: Option<[u8; 32]>,
    pub digest: [u8; 32],
}

impl Asset {
    /// Built in: the registry capability still names these bytes. Module:
    /// always (the bytes are a private copy; see the module docs).
    pub fn current(&self) -> bool {
        true
    }
}

/// `firmware_asset::load`: the whole file `name`, at most `max` bytes;
/// `signed` requires a verified signer, as built in.
pub fn load(
    _authority: &Cap<FirmwareRegistry, Read>,
    name: &str,
    max: usize,
    signed: bool,
) -> Result<Asset, FirmwareError> {
    let (mut handle, mut size) = (0u64, 0usize);
    // SAFETY: `name` is a live `&str`; both outputs are live locals.
    let rc = unsafe { ffi::narf_firmware_open(name.as_ptr(), name.len(), &mut handle, &mut size) };
    match rc {
        0 => {}
        ENOENT => return Err(FirmwareError::NotFound),
        _ => return Err(FirmwareError::BadFormat),
    }
    let result = (|| {
        if size == 0 || size > max {
            return Err(FirmwareError::BadFormat);
        }
        let mut key = [0u8; 32];
        // SAFETY: `key` names 32 writable bytes.
        let signer = match unsafe { ffi::narf_firmware_signer(handle, key.as_mut_ptr(), 32) } {
            0 => Some(key),
            ENODATA => None,
            _ => return Err(FirmwareError::BadFormat),
        };
        if signed && signer.is_none() {
            return Err(FirmwareError::UnsignedRejected);
        }
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
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(&bytes);
        let digest = hash.finalize();
        Ok(Asset {
            bytes,
            cap: Cap::device(),
            signer,
            digest,
        })
    })();
    // SAFETY: closing our own open handle once.
    let _ = unsafe { ffi::narf_firmware_close(handle) };
    result
}
