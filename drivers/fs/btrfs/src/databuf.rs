//! Data buffers: the only way the write, truncate, punch and read paths get a
//! buffer whose size follows file data.
//!
//! Such a buffer is allocated fallibly and answers `OutOfMemory` (ENOMEM)
//! when the heap cannot give it, instead of aborting the kernel: a large
//! contiguous block can be missing from a fragmented heap with gigabytes
//! free. The paths keep them to one extent's worth — `MAX_WRITE_EXTENT`,
//! 128 KiB — whatever the length of the call, as Linux works folio by folio
//! and extent by extent and never holds a whole write in one buffer.
//!
//! [`largest`] reports the biggest one asked for since [`reset_largest`], and
//! [`fail_from`] makes every request of at least a given size fail, for
//! tests.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

use narf_filesystem::FsError;

static LARGEST: AtomicUsize = AtomicUsize::new(0);
/// Requests of at least this many bytes fail; `u64::MAX` for none.
static FAIL_FROM: AtomicU64 = AtomicU64::new(u64::MAX);

/// A zeroed buffer of `len` bytes, or `OutOfMemory`.
pub(crate) fn zeroed(len: usize) -> Result<Vec<u8>, FsError> {
    LARGEST.fetch_max(len, Relaxed);
    if len as u64 >= FAIL_FROM.load(Relaxed) {
        return Err(FsError::OutOfMemory);
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(len)
        .map_err(|_| FsError::OutOfMemory)?;
    buf.resize(len, 0);
    Ok(buf)
}

/// The largest data buffer asked for since [`reset_largest`].
pub fn largest() -> usize {
    LARGEST.load(Relaxed)
}

/// Start [`largest`] again from zero.
pub fn reset_largest() {
    LARGEST.store(0, Relaxed);
}

/// For tests: make every data buffer of at least `len` bytes fail with
/// `OutOfMemory` (`None`: none). Never set on a production mount.
pub fn fail_from(len: Option<usize>) {
    FAIL_FROM.store(len.map_or(u64::MAX, |l| l as u64), Relaxed);
}
