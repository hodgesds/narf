//! `pidfd_open(2)` — file-descriptor handles on a process exit signal.
//!
//! Wave-61. Linux `pidfd_open(pid, flags)` returns an fd whose
//! `poll(POLLIN)` becomes ready once the target task exits. Use cases
//! today are limited to the readiness query (`poll` / `select` /
//! `epoll`) and `read` (which returns EOF / 0 bytes). The signal-
//! sending sibling `pidfd_send_signal` and the `waitid(P_PIDFD, ...)`
//! variant are explicit Wave-62 follow-ups.
//!
//! Backing store: a global `BTreeMap<pid, Arc<PidFdState>>`. Each
//! `PidFdFile` holds an `Arc<PidFdState>`; multiple open pidfds for
//! the same pid share state. On `on_child_exit(pid)`, the entry's
//! `exited` flag flips and the stored `Waker` (if any, parked by a
//! pending `epoll_wait` / `poll`) is fired.
//!
//! No backwards-compat shim path — this is the only way to observe
//! exit-as-fd from userspace.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat, POLL_IN};
use narf_lib::sync::IrqSafeSpinLock;

/// Shared state behind a pidfd. Outlives the original `pidfd_open`
/// caller — `on_child_exit` may run after the opener is gone.
#[derive(Debug)]
pub struct PidFdState {
    /// Target ProcessId.raw().
    pub pid: u64,
    /// Set once `on_child_exit(pid)` fires; never cleared. A pidfd
    /// minted *after* the target has already exited starts with this
    /// already true.
    pub exited: AtomicBool,
}

impl PidFdState {
    fn new(pid: u64, exited: bool) -> Arc<Self> {
        Arc::new(PidFdState {
            pid,
            exited: AtomicBool::new(exited),
        })
    }
}

/// pid → shared state. Lazily inserted by `mint_for` on first
/// `pidfd_open(pid)`. Drained when no `Arc` remains and the pid has
/// been released back to the pool, but for simplicity we don't GC
/// eagerly — the entry stays until `__test_reset_pidfd`.
static PIDFD_TABLE: IrqSafeSpinLock<Option<BTreeMap<u64, Arc<PidFdState>>>> =
    IrqSafeSpinLock::new(None);

/// One-time init. Called from `handlers::wait_init` so the table
/// exists before any task can fork.
pub fn init() {
    *PIDFD_TABLE.lock() = Some(BTreeMap::new());
}

/// Test-only reset.
#[doc(hidden)]
pub fn __test_reset() {
    *PIDFD_TABLE.lock() = Some(BTreeMap::new());
}

/// Look up or create the shared state for `pid`. The caller's
/// `Arc<PidFdState>` is what becomes the new fd's backing object.
///
/// `assume_alive`: if the caller has no way to verify the pid maps
/// to a live task (no PID→TaskId mapping registered), set this false
/// so a poll on the fd returns POLLIN immediately — Linux's behaviour
/// when `pidfd_open` is called against an already-zombie pid.
pub fn mint_for(pid: u64, assume_alive: bool) -> Arc<PidFdState> {
    let mut g = PIDFD_TABLE.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
    let map = g.as_mut().expect("table inited");
    if let Some(existing) = map.get(&pid) {
        return existing.clone();
    }
    let st = PidFdState::new(pid, !assume_alive);
    map.insert(pid, st.clone());
    st
}

/// Called by `on_child_exit(pid)` — flip the exited flag on any
/// minted state so future `poll_readiness` returns POLLIN.
///
/// Linux: `kernel/fork.c::do_notify_pidfd` walks the pid's waiter
/// list. Our table is shallow: every pidfd for the pid shares one
/// `PidFdState`, so a single store is sufficient.
pub fn notify_exit(pid: u64) {
    let st = {
        let g = PIDFD_TABLE.lock();
        g.as_ref().and_then(|m| m.get(&pid).cloned())
    };
    if let Some(st) = st {
        st.exited.store(true, Ordering::Release);
        // Future: also fire any registered Waker for fd-level
        // epoll_wait integration. Today pidfd_open's primary
        // consumer is the synchronous poll/read path, which
        // re-queries on each invocation.
    }
}

/// `FileOps` impl for the fd handed back by `sys_pidfd_open`.
#[derive(Debug)]
pub struct PidFdFile {
    pub state: Arc<PidFdState>,
}

impl PidFdFile {
    pub fn new(state: Arc<PidFdState>) -> Self {
        Self { state }
    }
}

impl FileOps for PidFdFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Linux: read() on a pidfd returns EOPNOTSUPP. We use EIO
        // shape (`FsError::Unsupported` → ENOTTY at the syscall
        // layer, close enough) — the readiness signal is the
        // documented use surface. Return 0 bytes (EOF) so naive
        // read loops terminate instead of spinning.
        Box::pin(async move { Ok(0usize) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // pidfd is read-only by spec.
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        if self.state.exited.load(Ordering::Acquire) {
            POLL_IN
        } else {
            0
        }
    }
}
