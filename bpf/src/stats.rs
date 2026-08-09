//! Global runtime-statistics enablement and its lifetime fd.
//!
//! Linux makes `BPF_ENABLE_STATS(BPF_STATS_RUN_TIME)` return an anonymous fd.
//! Program runtime accounting stays enabled while at least one independently
//! created stats file description remains live; duplicating one fd does not
//! add another enable because both descriptors share the same file object.

use core::sync::atomic::{AtomicU32, Ordering};

/// Linux rejects new enables well before its static-key reference count can
/// overflow. Keep the same conservative ceiling.
const MAX_USERS: u32 = i32::MAX as u32 / 2;

static USERS: AtomicU32 = AtomicU32::new(0);

/// Why runtime-statistics enablement failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StatsError {
    /// Too many independent enable fds are already live. `EBUSY`.
    Busy,
}

/// The anonymous file returned by `BPF_ENABLE_STATS`.
///
/// The global reference is acquired at construction and released only when
/// the final `Arc<dyn FileOps>` for this file description dies. That makes
/// ordinary fd duplication match Linux: dup shares one enable lease, whereas
/// another `BPF_ENABLE_STATS` call creates a second one.
#[derive(Debug)]
pub struct StatsFile;

impl StatsFile {
    /// Acquire one independent runtime-statistics lease.
    ///
    /// # Errors
    ///
    /// [`StatsError::Busy`] at the conservative global reference ceiling.
    pub fn enable() -> Result<Self, StatsError> {
        let mut current = USERS.load(Ordering::Relaxed);
        loop {
            if current >= MAX_USERS {
                return Err(StatsError::Busy);
            }
            match USERS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for StatsFile {
    fn drop(&mut self) {
        let previous = USERS.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "BPF stats enable count underflow");
    }
}

impl narf_filesystem::FileOps for StatsFile {
    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }

    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// Whether at least one independent stats file description is live.
#[inline]
#[must_use]
pub fn enabled() -> bool {
    USERS.load(Ordering::Acquire) != 0
}

/// Start timestamp for one program invocation, when accounting is enabled at
/// entry. Enabling halfway through a run does not retroactively count it.
#[inline]
pub(crate) fn run_start() -> Option<u64> {
    enabled().then(narf_time::monotonic_ns)
}

/// Elapsed nanoseconds for an invocation admitted by [`run_start`].
#[inline]
pub(crate) fn run_elapsed(start: Option<u64>) -> Option<u64> {
    start.map(|at| narf_time::monotonic_ns().saturating_sub(at))
}
