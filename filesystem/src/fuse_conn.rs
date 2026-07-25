//! FUSE connection + `/dev/fuse` transport + `FuseFs` VFS bridge.
//!
//! This is the client half of a FUSE filesystem: the kernel VFS turns
//! `lookup`/`getattr`/`open`/`read`/`write`/`readdir`/`release`/`forget`
//! into FUSE requests, ships them over a [`FuseConnection`] to a userspace
//! daemon (virtiofsd / a libfuse program), and awaits the reply.
//!
//! Data flow (Linux `fs/fuse/dev.c` is the reference):
//!
//! ```text
//!   VFS op ──enqueue(req)──▶ FuseConnection.pending  ──read(/dev/fuse)──▶ daemon
//!                                                                            │
//!   VFS op ◀──await reply──  FuseConnection.replies  ◀─write(/dev/fuse)──────┘
//! ```
//!
//! - The daemon opens `/dev/fuse` (an fd), reads a request (a
//!   [`FuseInHeader`] + body), services it, and writes back a
//!   [`FuseOutHeader`] + body keyed by the request's `unique` id.
//! - `read(/dev/fuse)` blocks (parks) until a request is queued; `write`
//!   parses the reply and wakes the parked VFS caller.
//!
//! The whole thing is transport-agnostic: the in-kernel tests drive both
//! ends with the cooperative scheduler and no real daemon, and a real
//! daemon over a virtqueue would plug into the exact same
//! [`FuseConnection`].

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::fuse::*;
use crate::{
    DirEntry, DirOps, FileLock, FileOps, FileType, FsError, FsFuture, FsInstance, FsStat, Mode,
    Stat, POLL_IN, POLL_OUT,
};

/// A completed reply from the daemon: the `error` field of the
/// `fuse_out_header` (0 = success, negative errno on failure) plus the
/// reply body bytes (everything after the header).
#[derive(Clone, Debug)]
struct FuseReply {
    error: i32,
    body: Vec<u8>,
}

type PollState = (Arc<AtomicU32>, Arc<AtomicBool>);
type PendingPoll = (u64, Arc<AtomicU32>, Arc<AtomicBool>);

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FuseRequestContext {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

pub type FuseRequestContextProvider = fn() -> FuseRequestContext;

static REQUEST_CONTEXT_PROVIDER: AtomicUsize = AtomicUsize::new(0);

pub fn install_request_context_provider(provider: FuseRequestContextProvider) {
    REQUEST_CONTEXT_PROVIDER.store(provider as usize, Ordering::Release);
}

fn request_context() -> FuseRequestContext {
    let raw = REQUEST_CONTEXT_PROVIDER.load(Ordering::Acquire);
    if raw == 0 {
        return FuseRequestContext::default();
    }
    // SAFETY: the only writer accepts exactly a FuseRequestContextProvider,
    // and the slot is never interpreted as another function-pointer type.
    let provider: FuseRequestContextProvider = unsafe { core::mem::transmute(raw) };
    provider()
}

#[doc(hidden)]
pub fn __test_reset_request_context_provider() {
    REQUEST_CONTEXT_PROVIDER.store(0, Ordering::Release);
}

/// Shared queue object connecting the kernel VFS to a userspace FUSE
/// daemon. One is minted per `open("/dev/fuse")`.
///
/// - `pending`: FIFO of fully-encoded requests (`fuse_in_header` + body)
///   waiting for the daemon to `read()` them.
/// - `replies`: `unique` → reply slot map. A VFS caller inserts an empty
///   slot when it enqueues, then awaits until the daemon's `write()` fills
///   it.
/// - `connected`: cleared when the daemon closes `/dev/fuse` so parked
///   callers can fail with `ENOTCONN`/`Unsupported` instead of hanging.
pub struct FuseConnection {
    pending: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    replies: IrqSafeSpinLock<BTreeMap<u64, Option<FuseReply>>>,
    delivered: IrqSafeSpinLock<BTreeSet<u64>>,
    poll_requests: IrqSafeSpinLock<BTreeMap<u64, PendingPoll>>,
    poll_handles: IrqSafeSpinLock<BTreeMap<u64, PollState>>,
    next_unique: AtomicU64,
    connected: core::sync::atomic::AtomicBool,
    /// True once FUSE_INIT has completed successfully.
    initialized: core::sync::atomic::AtomicBool,
    negotiated_minor: AtomicU32,
    negotiated_flags: AtomicU64,
    max_write: AtomicU32,
}

impl core::fmt::Debug for FuseConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FuseConnection")
            .field("pending", &self.pending.lock().len())
            .field("in_flight", &self.replies.lock().len())
            .field("connected", &self.connected.load(Ordering::Relaxed))
            .finish()
    }
}

impl Default for FuseConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseConnection {
    pub fn new() -> Self {
        FuseConnection {
            pending: IrqSafeSpinLock::new(VecDeque::new()),
            replies: IrqSafeSpinLock::new(BTreeMap::new()),
            delivered: IrqSafeSpinLock::new(BTreeSet::new()),
            poll_requests: IrqSafeSpinLock::new(BTreeMap::new()),
            poll_handles: IrqSafeSpinLock::new(BTreeMap::new()),
            // Linux starts `unique` at 1 and only ever uses even values in
            // some versions; any monotone non-zero sequence is spec-legal.
            next_unique: AtomicU64::new(1),
            connected: core::sync::atomic::AtomicBool::new(true),
            initialized: core::sync::atomic::AtomicBool::new(false),
            negotiated_minor: AtomicU32::new(0),
            negotiated_flags: AtomicU64::new(0),
            max_write: AtomicU32::new(4096),
        }
    }

    fn alloc_unique(&self) -> u64 {
        self.next_unique.fetch_add(1, Ordering::Relaxed)
    }

    /// True until the daemon closes its `/dev/fuse` fd.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    pub fn negotiated_minor(&self) -> u32 {
        self.negotiated_minor.load(Ordering::Acquire)
    }

    pub fn negotiated_flags(&self) -> u64 {
        self.negotiated_flags.load(Ordering::Acquire)
    }

    pub fn max_write(&self) -> u32 {
        self.max_write.load(Ordering::Acquire)
    }

    /// Mark the connection dead (daemon closed `/dev/fuse`). Any in-flight
    /// requests are failed so parked callers unwind.
    pub fn disconnect(&self) {
        self.connected.store(false, Ordering::Release);
        // Fail every outstanding request with -ENOTCONN so awaiters wake.
        let mut g = self.replies.lock();
        for slot in g.values_mut() {
            if slot.is_none() {
                *slot = Some(FuseReply {
                    error: -(ENOTCONN as i32),
                    body: Vec::new(),
                });
            }
        }
    }

    /// Encode `fuse_in_header` + `body` for `opcode`/`nodeid`, enqueue it,
    /// and register an empty reply slot. Returns the request's `unique`.
    fn submit(&self, opcode: FuseOpcode, nodeid: u64, body: &[u8]) -> u64 {
        let unique = self.alloc_unique();
        let total = core::mem::size_of::<FuseInHeader>() + body.len();
        let context = request_context();
        let hdr = FuseInHeader {
            len: total as u32,
            opcode: opcode as u32,
            unique,
            nodeid,
            uid: context.uid,
            gid: context.gid,
            pid: context.pid,
            _padding: 0,
        };
        let mut msg = pod_as_bytes(&hdr);
        msg.extend_from_slice(body);
        self.replies.lock().insert(unique, None);
        self.pending.lock().push_back(msg);
        unique
    }

    /// Enqueue an operation whose reply will not be awaited.
    pub(crate) fn submit_noreply(&self, opcode: FuseOpcode, nodeid: u64, body: &[u8]) {
        let unique = self.alloc_unique();
        let total = core::mem::size_of::<FuseInHeader>() + body.len();
        let context = request_context();
        let hdr = FuseInHeader {
            len: total as u32,
            opcode: opcode as u32,
            unique,
            nodeid,
            uid: context.uid,
            gid: context.gid,
            pid: context.pid,
            _padding: 0,
        };
        let mut msg = pod_as_bytes(&hdr);
        msg.extend_from_slice(body);
        self.pending.lock().push_back(msg);
    }

    fn cancel_request(&self, unique: u64) {
        self.replies.lock().remove(&unique);
        let mut removed_pending = false;
        self.pending.lock().retain(|request| {
            let keep = pod_from_bytes::<FuseInHeader>(request)
                .map(|header| header.unique != unique)
                .unwrap_or(false);
            removed_pending |= !keep;
            keep
        });
        if !removed_pending && self.delivered.lock().remove(&unique) && self.is_connected() {
            self.submit_noreply(
                FuseOpcode::Interrupt,
                0,
                &pod_as_bytes(&FuseInterruptIn { unique }),
            );
        }
    }

    /// Daemon side: dequeue the next request bytes, if any. Non-blocking.
    pub fn dequeue_request(&self) -> Option<Vec<u8>> {
        let request = self.take_pending_request(usize::MAX).ok()??;
        if let Some(header) = pod_from_bytes::<FuseInHeader>(&request) {
            if header.opcode != FuseOpcode::Interrupt as u32
                && header.opcode != FuseOpcode::Forget as u32
                && header.opcode != FuseOpcode::BatchForget as u32
            {
                self.delivered.lock().insert(header.unique);
            }
        }
        Some(request)
    }

    fn take_pending_request(&self, max_len: usize) -> Result<Option<Vec<u8>>, FsError> {
        let mut pending = self.pending.lock();
        let Some(front) = pending.front() else {
            return Ok(None);
        };
        let header: FuseInHeader = pod_from_bytes(front).ok_or(FsError::InvalidData)?;
        if header.opcode != FuseOpcode::Forget as u32 {
            if front.len() > max_len {
                return Err(FsError::InvalidData);
            }
            return Ok(pending.pop_front());
        }

        let fixed =
            core::mem::size_of::<FuseInHeader>() + core::mem::size_of::<FuseBatchForgetIn>();
        if max_len < fixed + core::mem::size_of::<FuseForgetOne>() {
            return Err(FsError::InvalidData);
        }
        let max_entries = (max_len - fixed) / core::mem::size_of::<FuseForgetOne>();
        let mut entries = Vec::new();
        let mut index = 0;
        while index < pending.len() && entries.len() < max_entries {
            let request = &pending[index];
            let Some(candidate) = pod_from_bytes::<FuseInHeader>(request) else {
                index += 1;
                continue;
            };
            if candidate.opcode != FuseOpcode::Forget as u32 {
                index += 1;
                continue;
            }
            let body_offset = core::mem::size_of::<FuseInHeader>();
            let forget: FuseForgetIn =
                pod_from_bytes(&request[body_offset..]).ok_or(FsError::InvalidData)?;
            entries.push(FuseForgetOne {
                nodeid: candidate.nodeid,
                nlookup: forget.nlookup,
            });
            pending.remove(index);
        }
        if entries.is_empty() {
            return Err(FsError::InvalidData);
        }
        let batch = FuseBatchForgetIn {
            count: entries.len() as u32,
            dummy: 0,
        };
        let total = fixed + entries.len() * core::mem::size_of::<FuseForgetOne>();
        let mut request = pod_as_bytes(&FuseInHeader {
            len: total as u32,
            opcode: FuseOpcode::BatchForget as u32,
            unique: header.unique,
            nodeid: 0,
            uid: header.uid,
            gid: header.gid,
            pid: header.pid,
            _padding: 0,
        });
        request.extend_from_slice(&pod_as_bytes(&batch));
        for entry in entries {
            request.extend_from_slice(&pod_as_bytes(&entry));
        }
        Ok(Some(request))
    }

    /// Copy one complete request into a daemon buffer.
    ///
    /// Linux leaves an oversized request queued and returns `EINVAL`
    /// when the daemon's read buffer is too small.
    fn read_request(&self, buf: &mut [u8]) -> Result<Option<usize>, FsError> {
        let Some(request) = self.take_pending_request(buf.len())? else {
            return Ok(None);
        };
        let n = request.len();
        buf[..n].copy_from_slice(&request);
        if let Some(header) = pod_from_bytes::<FuseInHeader>(&request) {
            if header.opcode != FuseOpcode::Interrupt as u32
                && header.opcode != FuseOpcode::Forget as u32
                && header.opcode != FuseOpcode::BatchForget as u32
            {
                self.delivered.lock().insert(header.unique);
            }
        }
        Ok(Some(n))
    }

    /// True when a request is queued for the daemon to read.
    pub fn has_request(&self) -> bool {
        !self.pending.lock().is_empty()
    }

    /// Daemon side: complete the request identified by the reply's
    /// `fuse_out_header.unique`. `reply` is the full daemon write
    /// (`fuse_out_header` + body). Returns the number of bytes consumed on
    /// success, or `None` if the buffer is malformed / unknown `unique`.
    pub fn complete_reply(&self, reply: &[u8]) -> Option<usize> {
        let hdr: FuseOutHeader = pod_from_bytes(reply)?;
        let hdr_len = core::mem::size_of::<FuseOutHeader>();
        // `len` counts the header + body; clamp to what was actually
        // supplied so a lying daemon can't make us read OOB.
        let claimed = hdr.len as usize;
        if claimed < hdr_len || claimed > reply.len() || hdr.error < -4095 {
            return None;
        }
        let body = reply[hdr_len..claimed].to_vec();
        if hdr.unique == 0 && hdr.error == FUSE_NOTIFY_POLL {
            let notify: FuseNotifyPollWakeupOut = pod_from_bytes(&body)?;
            if let Some((_, registered)) = self.poll_handles.lock().get(&notify.kh).cloned() {
                registered.store(false, Ordering::Release);
            }
            return Some(claimed);
        }
        if hdr.unique == 0 {
            let valid = match hdr.error {
                FUSE_NOTIFY_INVAL_INODE => {
                    let notify: FuseNotifyInvalInodeOut = pod_from_bytes(&body)?;
                    notify.ino != 0 && body.len() == core::mem::size_of::<FuseNotifyInvalInodeOut>()
                }
                FUSE_NOTIFY_INVAL_ENTRY => {
                    let notify: FuseNotifyInvalEntryOut = pod_from_bytes(&body)?;
                    notify.parent != 0
                        && notify.namelen != 0
                        && body.len()
                            == core::mem::size_of::<FuseNotifyInvalEntryOut>()
                                + notify.namelen as usize
                }
                FUSE_NOTIFY_DELETE => {
                    let notify: FuseNotifyDeleteOut = pod_from_bytes(&body)?;
                    notify.parent != 0
                        && notify.child != 0
                        && notify.namelen != 0
                        && body.len()
                            == core::mem::size_of::<FuseNotifyDeleteOut>() + notify.namelen as usize
                }
                _ => false,
            };
            return valid.then_some(claimed);
        }
        if hdr.error > 0 {
            return None;
        }
        if let Some((kh, readiness, registered)) = self.poll_requests.lock().remove(&hdr.unique) {
            if hdr.error == 0 {
                let out: FusePollOut = pod_from_bytes(&body)?;
                readiness.store(out.revents, Ordering::Release);
                self.poll_handles.lock().insert(kh, (readiness, registered));
            }
            self.replies.lock().remove(&hdr.unique);
            self.delivered.lock().remove(&hdr.unique);
            return Some(claimed);
        }
        self.delivered.lock().remove(&hdr.unique);
        let mut g = self.replies.lock();
        match g.get_mut(&hdr.unique) {
            Some(slot @ None) => {
                *slot = Some(FuseReply {
                    error: hdr.error,
                    body,
                });
                Some(claimed)
            }
            // Unknown or already-completed unique: drop it (a duplicate
            // reply is not fatal), still report bytes consumed so the
            // daemon's write loop advances.
            _ => Some(claimed),
        }
    }

    /// Take the completed reply for `unique`, if it has landed.
    fn take_reply(&self, unique: u64) -> Option<FuseReply> {
        let mut g = self.replies.lock();
        match g.get(&unique) {
            Some(Some(_)) => g.remove(&unique).flatten(),
            _ => None,
        }
    }

    /// Submit a request and await its reply. On success returns the reply
    /// body bytes; a negative `error` becomes an [`FsError`].
    async fn request(
        self: &Arc<Self>,
        opcode: FuseOpcode,
        nodeid: u64,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, FsError> {
        if !self.is_connected() {
            return Err(FsError::Unsupported);
        }
        let unique = self.submit(opcode, nodeid, &body);
        let reply = ReplyFuture {
            conn: Arc::clone(self),
            unique,
        }
        .await;
        match reply.error {
            0 => Ok(reply.body),
            e => Err(errno_to_fs_error(e)),
        }
    }
}

/// Future that parks a VFS caller until its FUSE reply lands. Each poll
/// checks the reply map; while pending it re-arms its own waker so the
/// cooperative scheduler re-polls it (the daemon task, driven on the same
/// executor, fills the slot between polls). On a dead connection it
/// resolves to an `-ENOTCONN` reply so callers never park forever.
struct ReplyFuture {
    conn: Arc<FuseConnection>,
    unique: u64,
}

impl Drop for ReplyFuture {
    fn drop(&mut self) {
        // A cancelled VFS future must not leave an unreachable reply
        // slot or unsent request behind. A late daemon reply is safely
        // treated as unknown.
        self.conn.cancel_request(self.unique);
    }
}

impl core::future::Future for ReplyFuture {
    type Output = FuseReply;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if let Some(reply) = self.conn.take_reply(self.unique) {
            return core::task::Poll::Ready(reply);
        }
        if !self.conn.is_connected() {
            // Connection died with no reply — synthesize ENOTCONN.
            return core::task::Poll::Ready(FuseReply {
                error: -(ENOTCONN as i32),
                body: Vec::new(),
            });
        }
        // Re-arm: the daemon completes the reply on another task, so we
        // must be re-polled. `wake_by_ref` schedules exactly that on the
        // cooperative executor (and is a no-op-safe re-poll under the
        // test's manual poll loop too).
        cx.waker().wake_by_ref();
        core::task::Poll::Pending
    }
}

/// Linux `ENOTCONN` — daemon went away mid-request.
const ENOTCONN: u32 = 107;

/// Translate a FUSE `-errno` reply into an [`FsError`].
fn errno_to_fs_error(neg_errno: i32) -> FsError {
    match -neg_errno {
        1 => FsError::PermissionDenied,       // EPERM
        2 => FsError::NotFound,               // ENOENT
        13 => FsError::PermissionDenied,      // EACCES
        11 | 16 | 17 | 39 => FsError::Busy,   // EAGAIN / EBUSY / EEXIST / ENOTEMPTY
        20 | 21 | 36 => FsError::InvalidPath, // ENOTDIR / EISDIR / ENAMETOOLONG
        22 => FsError::InvalidData,           // EINVAL
        28 => FsError::NoSpace,               // ENOSPC
        30 => FsError::ReadOnly,              // EROFS
        95 => FsError::Unsupported,           // EOPNOTSUPP
        _ => FsError::Unsupported,
    }
}

// ── /dev/fuse char device ─────────────────────────────────────────────

/// The `/dev/fuse` file node. Each `open()` (via [`DevFuse::open_new`])
/// mints a fresh [`FuseConnection`]; reads pull queued requests toward the
/// daemon and writes push replies back.
#[derive(Debug)]
pub struct DevFuse {
    conn: Arc<FuseConnection>,
}

impl DevFuse {
    /// Mint a new `/dev/fuse` connection. Returned as a `FileOps` for the
    /// caller's fd table; the mount path later recovers the connection via
    /// [`DevFuse::connection_of`].
    pub fn open_new() -> Arc<dyn FileOps> {
        Arc::new(DevFuse {
            conn: Arc::new(FuseConnection::new()),
        })
    }

    /// The connection this device fd owns.
    pub fn connection(&self) -> Arc<FuseConnection> {
        Arc::clone(&self.conn)
    }

    /// Recover the [`FuseConnection`] from an `Arc<dyn FileOps>` that is a
    /// `/dev/fuse` node (used by `sys_mount` to bind `fd=N`). Returns
    /// `None` if the fd is not a `/dev/fuse` device.
    pub fn connection_of(ops: &Arc<dyn FileOps>) -> Option<Arc<FuseConnection>> {
        ops.as_any()
            .and_then(|a| a.downcast_ref::<DevFuse>())
            .map(|d| d.connection())
    }
}

impl FileOps for DevFuse {
    /// Daemon read: hand back exactly one complete queued request.
    /// The syscall layer parks blocking reads while the queue is empty.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            match self.conn.read_request(buf)? {
                Some(n) => Ok(n),
                None => Ok(0),
            }
        })
    }

    /// Daemon write: parse a reply (`fuse_out_header` + body) and complete
    /// the matching in-flight request, waking its parked VFS caller.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            match self.conn.complete_reply(buf) {
                Some(_consumed) => Ok(buf.len()),
                None => Err(FsError::InvalidData),
            }
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    /// Readable whenever a request is queued for the daemon; always
    /// writable (replies are accepted at once).
    fn poll_readiness(&self) -> u32 {
        let mut ev = POLL_OUT;
        if self.conn.has_request() {
            ev |= POLL_IN;
        }
        ev
    }

    fn read_should_block(&self) -> bool {
        // A daemon read with no queued request should park, not EOF.
        !self.conn.has_request()
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

// ── FuseFs: VFS ⇒ FUSE translation ────────────────────────────────────

/// Attributes decoded from a daemon reply, cached on the node handle.
#[derive(Copy, Clone, Debug)]
struct NodeAttr {
    nodeid: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl NodeAttr {
    fn file_type(&self) -> FileType {
        match self.mode & S_IFMT {
            S_IFDIR => FileType::Dir,
            S_IFLNK => FileType::Symlink,
            S_IFREG => FileType::File,
            S_IFIFO => FileType::Fifo,
            S_IFSOCK => FileType::Socket,
            _ => FileType::Special,
        }
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.size,
            blocks: self.size.div_ceil(512),
            mode: Mode {
                file_type: self.file_type(),
                perms: (self.mode & 0o777) as u16,
            },
            mtime_cycles: 0,
        }
    }
}

/// A file node in a FUSE filesystem: a `nodeid` on a shared connection.
/// Lazily opens (obtaining a daemon `fh`) on first read; drops (RELEASE +
/// FORGET) when the last handle disappears.
pub struct FuseFile {
    conn: Arc<FuseConnection>,
    attr: NodeAttr,
    /// Daemon file handle from FUSE_OPEN, if opened. Guarded because
    /// `open` happens lazily inside an async read.
    fh: IrqSafeSpinLock<Option<u64>>,
    poll_kh: u64,
    poll_registered: Arc<AtomicBool>,
    readiness: Arc<AtomicU32>,
}

impl core::fmt::Debug for FuseFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FuseFile")
            .field("nodeid", &self.attr.nodeid)
            .field("size", &self.attr.size)
            .finish_non_exhaustive()
    }
}

impl FuseFile {
    async fn ensure_open(&self) -> Result<u64, FsError> {
        if let Some(fh) = *self.fh.lock() {
            return Ok(fh);
        }
        // FUSE_OPEN: O_RDONLY (0). The daemon returns a file handle.
        let body = pod_as_bytes(&FuseOpenIn {
            flags: 0,
            open_flags: 0,
        });
        let reply = self
            .conn
            .request(FuseOpcode::Open, self.attr.nodeid, body)
            .await?;
        let out: FuseOpenOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
        *self.fh.lock() = Some(out.fh);
        Ok(out.fh)
    }

    async fn setattr(&self, input: FuseSetattrIn) -> Result<(), FsError> {
        let reply = self
            .conn
            .request(FuseOpcode::Setattr, self.attr.nodeid, pod_as_bytes(&input))
            .await?;
        let _: FuseAttrOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
        Ok(())
    }
}

impl FileOps for FuseFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if self.attr.stat().mode.file_type == FileType::Symlink {
                if offset != 0 {
                    return Ok(0);
                }
                let data = self
                    .conn
                    .request(FuseOpcode::Readlink, self.attr.nodeid, Vec::new())
                    .await?;
                let n = core::cmp::min(buf.len(), data.len());
                buf[..n].copy_from_slice(&data[..n]);
                return Ok(n);
            }
            let fh = self.ensure_open().await?;
            let body = pod_as_bytes(&FuseReadIn {
                fh,
                offset,
                size: buf.len() as u32,
                read_flags: 0,
                lock_owner: 0,
                flags: 0,
                padding: 0,
            });
            let data = self
                .conn
                .request(FuseOpcode::Read, self.attr.nodeid, body)
                .await?;
            let n = core::cmp::min(buf.len(), data.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if buf.is_empty() {
                return Ok(0);
            }
            let fh = self.ensure_open().await?;
            let max_write = self.conn.max_write() as usize;
            let mut written = 0usize;
            while written < buf.len() {
                let chunk_len = core::cmp::min(buf.len() - written, max_write);
                let chunk_offset = offset
                    .checked_add(written as u64)
                    .ok_or(FsError::InvalidData)?;
                let header = FuseWriteIn {
                    fh,
                    offset: chunk_offset,
                    size: chunk_len as u32,
                    write_flags: 0,
                    lock_owner: 0,
                    flags: 0,
                    padding: 0,
                };
                let mut body = pod_as_bytes(&header);
                body.extend_from_slice(&buf[written..written + chunk_len]);
                let reply = self
                    .conn
                    .request(FuseOpcode::Write, self.attr.nodeid, body)
                    .await?;
                let out: FuseWriteOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
                let chunk_written = out.size as usize;
                if chunk_written > chunk_len {
                    return Err(FsError::InvalidData);
                }
                written += chunk_written;
                if chunk_written < chunk_len {
                    break;
                }
            }
            Ok(written)
        })
    }

    fn stat(&self) -> Stat {
        self.attr.stat()
    }

    fn ino(&self) -> u64 {
        self.attr.nodeid
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.setattr(FuseSetattrIn {
                valid: FATTR_SIZE,
                size: len,
                ..Default::default()
            })
            .await
        })
    }

    fn owners(&self) -> (u32, u32) {
        (self.attr.uid, self.attr.gid)
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.setattr(FuseSetattrIn {
                valid: FATTR_UID | FATTR_GID,
                uid,
                gid,
                ..Default::default()
            })
            .await
        })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.setattr(FuseSetattrIn {
                valid: FATTR_MODE,
                mode: (self.attr.mode & S_IFMT) | u32::from(perms),
                ..Default::default()
            })
            .await
        })
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move {
            // Refresh via FUSE_GETATTR so size reflects daemon-side writes.
            let body = pod_as_bytes(&FuseGetattrIn::default());
            let reply = self
                .conn
                .request(FuseOpcode::Getattr, self.attr.nodeid, body)
                .await?;
            let out: FuseAttrOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(NodeAttr {
                nodeid: self.attr.nodeid,
                size: out.attr.size,
                mode: out.attr.mode,
                uid: out.attr.uid,
                gid: out.attr.gid,
            }
            .stat())
        })
    }

    fn flush<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let fh = self.ensure_open().await?;
            let body = pod_as_bytes(&FuseFlushIn {
                fh,
                ..Default::default()
            });
            self.conn
                .request(FuseOpcode::Flush, self.attr.nodeid, body)
                .await
                .map(|_| ())
        })
    }

    fn fsync<'a>(&'a self, data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let fh = self.ensure_open().await?;
            let body = pod_as_bytes(&FuseFsyncIn {
                fh,
                fsync_flags: if data_only { FUSE_FSYNC_FDATASYNC } else { 0 },
                padding: 0,
            });
            self.conn
                .request(FuseOpcode::Fsync, self.attr.nodeid, body)
                .await
                .map(|_| ())
        })
    }

    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut body = pod_as_bytes(&FuseSetxattrIn {
                size: value.len() as u32,
                flags,
                ..Default::default()
            });
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(value);
            self.conn
                .request(FuseOpcode::Setxattr, self.attr.nodeid, body)
                .await
                .map(|_| ())
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let probe = pod_as_bytes(&FuseGetxattrIn::default());
            let mut probe = probe;
            probe.extend_from_slice(name.as_bytes());
            probe.push(0);
            let size_reply = self
                .conn
                .request(FuseOpcode::Getxattr, self.attr.nodeid, probe)
                .await?;
            let size: FuseGetxattrOut = pod_from_bytes(&size_reply).ok_or(FsError::InvalidData)?;
            let mut body = pod_as_bytes(&FuseGetxattrIn {
                size: size.size,
                padding: 0,
            });
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            self.conn
                .request(FuseOpcode::Getxattr, self.attr.nodeid, body)
                .await
        })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let probe = pod_as_bytes(&FuseGetxattrIn::default());
            let size_reply = self
                .conn
                .request(FuseOpcode::Listxattr, self.attr.nodeid, probe)
                .await?;
            let size: FuseGetxattrOut = pod_from_bytes(&size_reply).ok_or(FsError::InvalidData)?;
            self.conn
                .request(
                    FuseOpcode::Listxattr,
                    self.attr.nodeid,
                    pod_as_bytes(&FuseGetxattrIn {
                        size: size.size,
                        padding: 0,
                    }),
                )
                .await
        })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut body = name.as_bytes().to_vec();
            body.push(0);
            self.conn
                .request(FuseOpcode::Removexattr, self.attr.nodeid, body)
                .await
                .map(|_| ())
        })
    }

    fn access<'a>(&'a self, mask: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.conn
                .request(
                    FuseOpcode::Access,
                    self.attr.nodeid,
                    pod_as_bytes(&FuseAccessIn { mask, padding: 0 }),
                )
                .await
                .map(|_| ())
        })
    }

    fn get_lock<'a>(&'a self, owner: u64, lock: FileLock) -> FsFuture<'a, FileLock> {
        Box::pin(async move {
            let fh = self.ensure_open().await?;
            let reply = self
                .conn
                .request(
                    FuseOpcode::Getlk,
                    self.attr.nodeid,
                    pod_as_bytes(&FuseLkIn {
                        fh,
                        owner,
                        lk: FuseFileLock {
                            start: lock.start,
                            end: lock.end,
                            type_: lock.type_,
                            pid: lock.pid,
                        },
                        ..Default::default()
                    }),
                )
                .await?;
            let out: FuseLkOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(FileLock {
                start: out.lk.start,
                end: out.lk.end,
                type_: out.lk.type_,
                pid: out.lk.pid,
            })
        })
    }

    fn set_lock<'a>(&'a self, owner: u64, lock: FileLock, wait: bool) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let fh = self.ensure_open().await?;
            self.conn
                .request(
                    if wait {
                        FuseOpcode::Setlkw
                    } else {
                        FuseOpcode::Setlk
                    },
                    self.attr.nodeid,
                    pod_as_bytes(&FuseLkIn {
                        fh,
                        owner,
                        lk: FuseFileLock {
                            start: lock.start,
                            end: lock.end,
                            type_: lock.type_,
                            pid: lock.pid,
                        },
                        ..Default::default()
                    }),
                )
                .await
                .map(|_| ())
        })
    }

    fn fallocate<'a>(&'a self, mode: u32, offset: u64, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let fh = self.ensure_open().await?;
            self.conn
                .request(
                    FuseOpcode::Fallocate,
                    self.attr.nodeid,
                    pod_as_bytes(&FuseFallocateIn {
                        fh,
                        offset,
                        length: len,
                        mode,
                        padding: 0,
                    }),
                )
                .await
                .map(|_| ())
        })
    }

    fn seek<'a>(&'a self, offset: u64, whence: u32) -> FsFuture<'a, u64> {
        Box::pin(async move {
            let fh = self.ensure_open().await?;
            let reply = self
                .conn
                .request(
                    FuseOpcode::Lseek,
                    self.attr.nodeid,
                    pod_as_bytes(&FuseLseekIn {
                        fh,
                        offset,
                        whence,
                        padding: 0,
                    }),
                )
                .await?;
            let out: FuseLseekOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(out.offset)
        })
    }

    fn copy_file_range_to<'a>(
        &'a self,
        off_in: u64,
        out: &'a dyn FileOps,
        off_out: u64,
        len: u64,
        flags: u64,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            let target = out
                .as_any()
                .and_then(|any| any.downcast_ref::<FuseFile>())
                .ok_or(FsError::Unsupported)?;
            if !Arc::ptr_eq(&self.conn, &target.conn) {
                return Err(FsError::Unsupported);
            }
            let fh_in = self.ensure_open().await?;
            let fh_out = target.ensure_open().await?;
            let reply = self
                .conn
                .request(
                    FuseOpcode::CopyFileRange,
                    self.attr.nodeid,
                    pod_as_bytes(&FuseCopyFileRangeIn {
                        fh_in,
                        off_in,
                        nodeid_out: target.attr.nodeid,
                        fh_out,
                        off_out,
                        len,
                        flags,
                    }),
                )
                .await?;
            let out: FuseWriteOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(u64::from(out.size))
        })
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn poll_readiness(&self) -> u32 {
        if !self.poll_registered.swap(true, Ordering::AcqRel) {
            if let Some(fh) = *self.fh.lock() {
                let body = pod_as_bytes(&FusePollIn {
                    fh,
                    kh: self.poll_kh,
                    flags: FUSE_POLL_SCHEDULE_NOTIFY,
                    events: POLL_IN | POLL_OUT,
                });
                let unique = self.conn.submit(FuseOpcode::Poll, self.attr.nodeid, &body);
                self.conn.poll_requests.lock().insert(
                    unique,
                    (
                        self.poll_kh,
                        Arc::clone(&self.readiness),
                        Arc::clone(&self.poll_registered),
                    ),
                );
            } else {
                self.poll_registered.store(false, Ordering::Release);
            }
        }
        self.readiness.load(Ordering::Acquire)
    }
}

impl Drop for FuseFile {
    fn drop(&mut self) {
        // Best-effort RELEASE + FORGET. We can't await in `Drop`, so we
        // just enqueue the requests (fire-and-forget); the daemon drains
        // them on its next read. A dead connection drops them harmlessly.
        if !self.conn.is_connected() {
            return;
        }
        if let Some(fh) = *self.fh.lock() {
            let body = pod_as_bytes(&FuseReleaseIn {
                fh,
                flags: 0,
                release_flags: 0,
                lock_owner: 0,
            });
            self.conn
                .submit_noreply(FuseOpcode::Release, self.attr.nodeid, &body);
        }
        // Never forget the root (nodeid 1) — Linux keeps it pinned.
        if self.attr.nodeid != FUSE_ROOT_ID {
            let body = pod_as_bytes(&FuseForgetIn { nlookup: 1 });
            self.conn
                .submit_noreply(FuseOpcode::Forget, self.attr.nodeid, &body);
        }
    }
}

/// A directory node in a FUSE filesystem.
pub struct FuseDir {
    conn: Arc<FuseConnection>,
    nodeid: u64,
}

impl core::fmt::Debug for FuseDir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FuseDir")
            .field("nodeid", &self.nodeid)
            .finish()
    }
}

impl FuseDir {
    fn file_from_entry(&self, out: FuseEntryOut, fh: Option<u64>) -> Arc<dyn FileOps> {
        let poll_kh = self.conn.alloc_unique();
        Arc::new(FuseFile {
            conn: Arc::clone(&self.conn),
            attr: NodeAttr {
                nodeid: out.nodeid,
                size: out.attr.size,
                mode: out.attr.mode,
                uid: out.attr.uid,
                gid: out.attr.gid,
            },
            fh: IrqSafeSpinLock::new(fh),
            poll_kh,
            poll_registered: Arc::new(AtomicBool::new(false)),
            readiness: Arc::new(AtomicU32::new(POLL_IN | POLL_OUT)),
        }) as Arc<dyn FileOps>
    }

    fn dir_from_entry(&self, out: FuseEntryOut) -> Arc<dyn DirOps> {
        Arc::new(FuseDir {
            conn: Arc::clone(&self.conn),
            nodeid: out.nodeid,
        }) as Arc<dyn DirOps>
    }

    async fn named_request(
        &self,
        opcode: FuseOpcode,
        prefix: &[u8],
        names: &[&str],
    ) -> Result<Vec<u8>, FsError> {
        let name_bytes: usize = names.iter().map(|name| name.len() + 1).sum();
        let mut body = Vec::with_capacity(prefix.len() + name_bytes);
        body.extend_from_slice(prefix);
        for name in names {
            if name.as_bytes().contains(&0) {
                return Err(FsError::InvalidPath);
            }
            body.extend_from_slice(name.as_bytes());
            body.push(0);
        }
        self.conn.request(opcode, self.nodeid, body).await
    }

    /// FUSE_LOOKUP: resolve `name` under this directory into a
    /// [`NodeAttr`].
    async fn lookup_attr(&self, name: &str) -> Result<NodeAttr, FsError> {
        // LOOKUP body is the NUL-terminated child name.
        let mut body = Vec::with_capacity(name.len() + 1);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        let reply = self
            .conn
            .request(FuseOpcode::Lookup, self.nodeid, body)
            .await?;
        let out: FuseEntryOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
        Ok(NodeAttr {
            nodeid: out.nodeid,
            size: out.attr.size,
            mode: out.attr.mode,
            uid: out.attr.uid,
            gid: out.attr.gid,
        })
    }
}

impl DirOps for FuseDir {
    fn ino(&self) -> u64 {
        self.nodeid
    }

    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // Synchronous lookup can't drive the async transport; callers use
        // `lookup_async`. Returning None here forces the async path.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let attr = self.lookup_attr(name).await?;
            if attr.file_type() == FileType::Dir {
                return Err(FsError::InvalidPath);
            }
            let poll_kh = self.conn.alloc_unique();
            Ok(Arc::new(FuseFile {
                conn: Arc::clone(&self.conn),
                attr,
                fh: IrqSafeSpinLock::new(None),
                poll_kh,
                poll_registered: Arc::new(AtomicBool::new(false)),
                readiness: Arc::new(AtomicU32::new(POLL_IN | POLL_OUT)),
            }) as Arc<dyn FileOps>)
        })
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let attr = self.lookup_attr(name).await?;
            if attr.file_type() != FileType::Dir {
                return Err(FsError::NotFound);
            }
            Ok(Arc::new(FuseDir {
                conn: Arc::clone(&self.conn),
                nodeid: attr.nodeid,
            }) as Arc<dyn DirOps>)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Names live in daemon replies (owned), not `&'static str`; readdir
        // goes through `enumerate_async`.
        Box::new(core::iter::empty())
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            // FUSE_READDIR needs a directory `fh` from FUSE_OPENDIR. We
            // (re)open per enumerate — cheap and stateless for the client.
            let openbody = pod_as_bytes(&FuseOpenIn {
                flags: 0,
                open_flags: 0,
            });
            let oreply = self
                .conn
                .request(FuseOpcode::OpenDir, self.nodeid, openbody)
                .await?;
            let oout: FuseOpenOut = pod_from_bytes(&oreply).ok_or(FsError::InvalidData)?;
            let fh = oout.fh;

            let plus = self.conn.negotiated_flags() & FuseInitFlag::DoReaddirplus as u64 != 0;
            let readbody = pod_as_bytes(&FuseReadIn {
                fh,
                offset: 0,
                size: 4096,
                read_flags: 0,
                lock_owner: 0,
                flags: 0,
                padding: 0,
            });
            let data = self
                .conn
                .request(
                    if plus {
                        FuseOpcode::ReadDirPlus
                    } else {
                        FuseOpcode::ReadDir
                    },
                    self.nodeid,
                    readbody,
                )
                .await?;

            let mut out: Vec<(String, FileType)> = Vec::new();
            let mut pos = 0usize;
            let header_len = if plus {
                FUSE_DIRENTPLUS_HEADER_LEN
            } else {
                FUSE_DIRENT_HEADER_LEN
            };
            while pos + header_len <= data.len() {
                let (de, nodeid) = if plus {
                    let entry: FuseDirentPlus =
                        pod_from_bytes(&data[pos..]).ok_or(FsError::InvalidData)?;
                    (entry.dirent, Some(entry.entry_out.nodeid))
                } else {
                    let entry: FuseDirent =
                        pod_from_bytes(&data[pos..]).ok_or(FsError::InvalidData)?;
                    (entry, None)
                };
                let namelen = de.namelen as usize;
                let name_start = pos + header_len;
                let name_end = name_start + namelen;
                if namelen == 0 || name_end > data.len() {
                    return Err(FsError::InvalidData);
                }
                let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
                let ft = match de.type_ {
                    // fuse_dirent.type is the high bits of st_mode >> 12
                    // (DT_DIR=4, DT_REG=8, DT_LNK=10).
                    4 => FileType::Dir,
                    10 => FileType::Symlink,
                    _ => FileType::File,
                };
                if name != "." && name != ".." {
                    out.push((name, ft));
                }
                if let Some(nodeid) = nodeid.filter(|nodeid| *nodeid != 0) {
                    self.conn.submit_noreply(
                        FuseOpcode::Forget,
                        nodeid,
                        &pod_as_bytes(&FuseForgetIn { nlookup: 1 }),
                    );
                }
                pos = name_end;
                // Records are 8-byte aligned on the wire.
                pos = fuse_dirent_align(pos);
            }

            // Release the directory handle.
            let rel = pod_as_bytes(&FuseReleaseIn {
                fh,
                flags: 0,
                release_flags: 0,
                lock_owner: 0,
            });
            let _ = self
                .conn
                .request(FuseOpcode::ReleaseDir, self.nodeid, rel)
                .await;

            Ok(out.into_iter().skip(cursor).take(max).collect())
        })
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let prefix = pod_as_bytes(&FuseCreateIn {
                flags: 2, // O_RDWR
                mode: S_IFREG | 0o644,
                umask: 0,
                open_flags: 0,
            });
            let reply = self
                .named_request(FuseOpcode::Create, &prefix, &[name])
                .await?;
            let entry: FuseEntryOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            let open_off = core::mem::size_of::<FuseEntryOut>();
            let open: FuseOpenOut =
                pod_from_bytes(reply.get(open_off..).ok_or(FsError::InvalidData)?)
                    .ok_or(FsError::InvalidData)?;
            Ok(self.file_from_entry(entry, Some(open.fh)))
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let prefix = pod_as_bytes(&FuseMkdirIn {
                mode: S_IFDIR | 0o755,
                umask: 0,
            });
            let reply = self
                .named_request(FuseOpcode::Mkdir, &prefix, &[name])
                .await?;
            let entry: FuseEntryOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            if entry.attr.mode & S_IFMT != S_IFDIR {
                return Err(FsError::InvalidData);
            }
            Ok(self.dir_from_entry(entry))
        })
    }

    fn mknod<'a>(
        &'a self,
        name: &'a str,
        file_type: FileType,
        rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let type_bits = match file_type {
                FileType::File => S_IFREG,
                FileType::Symlink => S_IFLNK,
                FileType::Special => S_IFCHR,
                FileType::Socket => S_IFSOCK,
                FileType::Fifo => S_IFIFO,
                FileType::Dir => return Err(FsError::InvalidData),
            };
            let prefix = pod_as_bytes(&FuseMknodIn {
                mode: type_bits | 0o644,
                rdev: rdev as u32,
                umask: 0,
                padding: 0,
            });
            let reply = self
                .named_request(FuseOpcode::Mknod, &prefix, &[name])
                .await?;
            let entry: FuseEntryOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(self.file_from_entry(entry, None))
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.named_request(FuseOpcode::Unlink, &[], &[name])
                .await
                .map(|_| ())
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.named_request(FuseOpcode::Rmdir, &[], &[name])
                .await
                .map(|_| ())
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let prefix = pod_as_bytes(&FuseRenameIn {
                newdir: self.nodeid,
            });
            self.named_request(FuseOpcode::Rename, &prefix, &[old_name, new_name])
                .await
                .map(|_| ())
        })
    }

    fn rename_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
        flags: u32,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let target = new_dir
                .as_any()
                .and_then(|any| any.downcast_ref::<FuseDir>())
                .ok_or(FsError::Unsupported)?;
            if !Arc::ptr_eq(&self.conn, &target.conn) {
                return Err(FsError::Unsupported);
            }
            let (opcode, prefix) = if flags == 0 {
                (
                    FuseOpcode::Rename,
                    pod_as_bytes(&FuseRenameIn {
                        newdir: target.nodeid,
                    }),
                )
            } else {
                (
                    FuseOpcode::Rename2,
                    pod_as_bytes(&FuseRename2In {
                        newdir: target.nodeid,
                        flags,
                        padding: 0,
                    }),
                )
            };
            self.named_request(opcode, &prefix, &[old_name, new_name])
                .await
                .map(|_| ())
        })
    }

    fn link<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let old = self.lookup_attr(old_name).await?;
            let prefix = pod_as_bytes(&FuseLinkIn {
                oldnodeid: old.nodeid,
            });
            let reply = self
                .named_request(FuseOpcode::Link, &prefix, &[new_name])
                .await?;
            let _: FuseEntryOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(())
        })
    }

    fn link_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let target = new_dir
                .as_any()
                .and_then(|any| any.downcast_ref::<FuseDir>())
                .ok_or(FsError::Unsupported)?;
            if !Arc::ptr_eq(&self.conn, &target.conn) {
                return Err(FsError::Unsupported);
            }
            let old = self.lookup_attr(old_name).await?;
            let prefix = pod_as_bytes(&FuseLinkIn {
                oldnodeid: old.nodeid,
            });
            let reply = target
                .named_request(FuseOpcode::Link, &prefix, &[new_name])
                .await?;
            let _: FuseEntryOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(())
        })
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let reply = self
                .named_request(FuseOpcode::Symlink, &[], &[name, target])
                .await?;
            let entry: FuseEntryOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(self.file_from_entry(entry, None))
        })
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// A mounted FUSE filesystem. Holds the shared connection; its root is the
/// well-known nodeid 1.
pub struct FuseFs {
    name: String,
    conn: Arc<FuseConnection>,
}

impl core::fmt::Debug for FuseFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FuseFs")
            .field("name", &self.name)
            .field("conn", &self.conn)
            .finish()
    }
}

impl FuseFs {
    /// Build a `FuseFs` over an existing connection (recovered from the
    /// mount's `fd=N`). The FUSE_INIT handshake must be driven separately
    /// via [`FuseFs::init`] before the FS is usable.
    pub fn new(name: impl Into<String>, conn: Arc<FuseConnection>) -> Self {
        FuseFs {
            name: name.into(),
            conn,
        }
    }

    /// The shared connection, e.g. so a caller can drive the daemon side.
    pub fn connection(&self) -> Arc<FuseConnection> {
        Arc::clone(&self.conn)
    }

    /// Drive the FUSE_INIT handshake: send our version + feature flags and
    /// accept the daemon's negotiated reply. Must be awaited (concurrently
    /// with the daemon) before the mount serves traffic.
    pub async fn init(&self) -> Result<FuseInitOut, FsError> {
        let body = pod_as_bytes(&FuseInitIn {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: 0,
            flags: FUSE_SUPPORTED_INIT_FLAGS,
            flags2: 0,
            unused: [0; 11],
        });
        // FUSE_INIT is addressed to nodeid 0.
        let reply = self.conn.request(FuseOpcode::Init, 0, body).await?;
        if reply.len() < 8 || reply.len() > core::mem::size_of::<FuseInitOut>() {
            return Err(FsError::InvalidData);
        }
        let mut padded = [0u8; core::mem::size_of::<FuseInitOut>()];
        padded[..reply.len()].copy_from_slice(&reply);
        let out: FuseInitOut = pod_from_bytes(&padded).ok_or(FsError::InvalidData)?;
        if out.major != FUSE_KERNEL_VERSION || out.minor < 5 {
            return Err(FsError::Unsupported);
        }
        let minor = core::cmp::min(out.minor, FUSE_KERNEL_MINOR_VERSION);
        let flags = (out.flags & FUSE_SUPPORTED_INIT_FLAGS) as u64
            | if out.flags & FuseInitFlag::InitExt as u32 != 0 {
                (out.flags2 as u64) << 32
            } else {
                0
            };
        let max_write = core::cmp::max(out.max_write, 4096);
        self.conn.negotiated_minor.store(minor, Ordering::Release);
        self.conn.negotiated_flags.store(flags, Ordering::Release);
        self.conn.max_write.store(max_write, Ordering::Release);
        self.conn.initialized.store(true, Ordering::Release);
        Ok(out)
    }
}

impl FsInstance for FuseFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(FuseDir {
            conn: Arc::clone(&self.conn),
            nodeid: FUSE_ROOT_ID,
        }) as Arc<dyn DirOps>
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        Box::pin(async move {
            let reply = self
                .conn
                .request(FuseOpcode::Statfs, FUSE_ROOT_ID, Vec::new())
                .await?;
            let out: FuseStatfsOut = pod_from_bytes(&reply).ok_or(FsError::InvalidData)?;
            Ok(FsStat {
                blocks: out.st.blocks,
                blocks_free: out.st.bfree,
                blocks_available: out.st.bavail,
                files: out.st.files,
                files_free: out.st.ffree,
                block_size: out.st.bsize,
                name_len: out.st.namelen,
                fragment_size: out.st.frsize,
            })
        })
    }
}
