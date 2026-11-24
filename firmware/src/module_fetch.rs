//! Loadable-module firmware blob fetch broker.
//!
//! A loadable module cannot hold a `Cap<FirmwareBlob, Read>` or borrow kernel
//! memory, and vendor firmware images exceed any single bounded copy. So a
//! module fetches firmware by name through owner-scoped, never-reused integer
//! handles and bounded byte chunks:
//!
//! - `open(owner, name)` resolves the blob through the kernel's bootstrap
//!   registry authority and retains its `Cap<FirmwareBlob, Read>`, reporting a
//!   handle and the total size.
//! - `read(owner, handle, offset, out)` copies one bounded chunk.
//! - `close(owner, handle)` — and module unload via [`retire_owner`] — drops
//!   the retained cap.
//!
//! Authorisation is the caller's `CapKind::Firmware` grant, enforced at the
//! `narf_firmware_*` exports; this broker performs the lookup with the kernel
//! registry authority once that gate has passed. The exports live in
//! `modules/src/kabi.rs`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{Cap, Read};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{FirmwareBlob, FirmwareError};

/// Largest chunk copied per `read`. Images are read in bounded pieces.
pub const MAX_CHUNK: usize = 65_536;
/// Firmware-name length bound (registry keys are short paths).
pub const MAX_NAME: usize = 256;

/// `-ENOENT`: the name did not resolve, or the blob failed validation.
const ENOENT: i32 = -2;
/// `-EBADF`: no such open handle for this owner.
const EBADF: i32 = -9;

#[derive(Clone, Copy)]
struct Binding {
    owner: u64,
    handle: u64,
    size: usize,
    blob: Cap<FirmwareBlob, Read>,
}

static BINDINGS: IrqSafeSpinLock<Vec<Binding>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn errno(_: FirmwareError) -> i32 {
    ENOENT
}

/// Resolve `name`, retain its blob, and report `(handle, size)`.
pub fn open(owner: u64, name: &str) -> Result<(u64, usize), i32> {
    // The kernel bootstrap registry authority performs the lookup; the caller's
    // `CapKind::Firmware` grant (checked at the export) is what authorised it.
    let (_write, read) = crate::bootstrap_authority();
    let blob = crate::open(name, &read).map_err(errno)?;
    let size = crate::view_of(&blob).map_err(errno)?.bytes.len();
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    BINDINGS.lock().push(Binding {
        owner,
        handle,
        size,
        blob,
    });
    Ok((handle, size))
}

/// Copy up to `out.len()` bytes of `handle` starting at `offset`. Returns the
/// number copied (`0` at or past end of blob).
pub fn read(owner: u64, handle: u64, offset: u64, out: &mut [u8]) -> Result<usize, i32> {
    // Copy the cap out of the lock, then borrow the blob view without holding
    // the broker lock during the copy.
    let blob = {
        let bindings = BINDINGS.lock();
        bindings
            .iter()
            .find(|b| b.owner == owner && b.handle == handle)
            .map(|b| b.blob)
            .ok_or(EBADF)?
    };
    let view = crate::view_of(&blob).map_err(errno)?;
    let bytes = view.bytes;
    let offset = offset as usize;
    if offset >= bytes.len() {
        return Ok(0);
    }
    let end = offset.saturating_add(out.len()).min(bytes.len());
    let n = end - offset;
    out[..n].copy_from_slice(&bytes[offset..end]);
    Ok(n)
}

/// Report a handle's total size without copying, for callers that lost it.
pub fn size_of(owner: u64, handle: u64) -> Result<usize, i32> {
    BINDINGS
        .lock()
        .iter()
        .find(|b| b.owner == owner && b.handle == handle)
        .map(|b| b.size)
        .ok_or(EBADF)
}

/// Whether `handle`'s blob carries a verified signer. The built-in drivers
/// refuse unsigned board/regulatory data (`firmware_asset::load(.., signer:
/// true)`); a module needs the same fact to apply the same policy.
pub fn signed(owner: u64, handle: u64) -> Result<bool, i32> {
    let blob = {
        let bindings = BINDINGS.lock();
        bindings
            .iter()
            .find(|b| b.owner == owner && b.handle == handle)
            .map(|b| b.blob)
            .ok_or(EBADF)?
    };
    Ok(crate::view_of(&blob).map_err(errno)?.signer.is_some())
}

/// Release one handle. `-EBADF` when the owner holds no such handle.
pub fn close(owner: u64, handle: u64) -> i32 {
    let mut bindings = BINDINGS.lock();
    let before = bindings.len();
    bindings.retain(|b| !(b.owner == owner && b.handle == handle));
    if bindings.len() == before {
        EBADF
    } else {
        0
    }
}

/// Drop every handle held by `owner`. Called from the module unload path.
pub fn retire_owner(owner: u64) {
    BINDINGS.lock().retain(|b| b.owner != owner);
}
