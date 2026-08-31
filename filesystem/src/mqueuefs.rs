//! Linux-compatible POSIX message-queue filesystem.
//!
//! Linux uses one set of mqueue inode objects for both the `mq_*` syscalls and
//! every mount of `mqueue` in the same IPC namespace.  This module mirrors
//! that shape: named queues live in a namespace-keyed registry, open message
//! queue descriptions retain the queue after unlink, and [`MqueueFs`] exposes
//! the same live names and queue-status files through the VFS.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    posix_access_ok, AccessRequest, Accessor, DirEntry, DirOps, FileOps, FileOwner, FileType,
    FsError, FsFuture, FsInstance, FsStat, Mode, Stat, POLL_IN, POLL_OUT,
};

/// Linux `MQ_PRIO_MAX` (`include/uapi/linux/mqueue.h`).
pub const MQ_PRIO_MAX: u32 = 32_768;
pub const MQ_DEFAULT_MAXMSG: i64 = 10;
pub const MQ_DEFAULT_MSGSIZE: i64 = 8_192;
pub const MQ_MAXMSG: i64 = 10;
pub const MQ_MSGSIZE_MAX: i64 = 8_192;
pub const MQ_QUEUES_MAX: usize = 256;

pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_ACCMODE: u32 = 3;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NONBLOCK: u32 = 0o4000;

/// Linux `struct mq_attr` fields used by the kernel ABI.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MqueueAttr {
    pub flags: i64,
    pub maxmsg: i64,
    pub msgsize: i64,
    pub curmsgs: i64,
}

impl Default for MqueueAttr {
    fn default() -> Self {
        Self {
            flags: 0,
            maxmsg: MQ_DEFAULT_MAXMSG,
            msgsize: MQ_DEFAULT_MSGSIZE,
            curmsgs: 0,
        }
    }
}

/// Errors surfaced by the typed mqueue API and translated to Linux errno by
/// the userspace syscall layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MqueueError {
    NotFound,
    Exists,
    Invalid,
    NameTooLong,
    PermissionDenied,
    NoSpace,
    BadDescriptor,
    MessageTooLarge,
    WouldBlock,
    Busy,
}

/// Creation and open-file-description inputs for [`open`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MqueueOpenOptions {
    pub flags: u32,
    pub mode: u16,
    pub umask: u16,
    pub uid: u32,
    pub gid: u32,
    pub attr: Option<MqueueAttr>,
}

/// One-shot notification registration. `method` uses Linux SIGEV_* values.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MqueueNotification {
    pub task_id: u64,
    pub method: i32,
    pub signal: i32,
    /// `sigev_value` (the sigval union) registered at mq_notify time. Delivered
    /// as the notification signal's `si_value` (Linux mqueue.c __do_notify).
    pub value: u64,
}

#[derive(Debug)]
struct Message {
    priority: u32,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct QueueState {
    messages: Vec<Message>,
    queued_bytes: usize,
    notification: Option<MqueueNotification>,
}

#[derive(Debug)]
struct Queue {
    inode: u64,
    owner: u32,
    group: u32,
    mode: u16,
    maxmsg: i64,
    msgsize: i64,
    state: IrqSafeSpinLock<QueueState>,
    /// Durable per-fd readiness cell (see `narf_lib::readiness`) — the migration
    /// target that gives a poll/epoll parked on an mqd a TARGETED wake instead
    /// of the `notify(0)` herd + ~10 ms backstop. POLL_IN when the queue holds a
    /// message, POLL_OUT when it has room below `maxmsg` — exactly what
    /// `poll_readiness` reports. Lives on the shared `Arc<Queue>`, so
    /// `MqueueFile::readiness()` reaches it directly and the default
    /// `arm_readiness`/`disarm_readiness` serve it — the SOLE readiness mechanism
    /// (there is no edge token). `send` publishes and `notify`s POLL_IN; `receive`
    /// publishes and `notify`s POLL_OUT. `notify` fires the wait-queue
    /// unconditionally so an EPOLLET consumer re-fires even at the same level.
    readiness: narf_lib::readiness::Readiness,
}

impl Queue {
    fn new(inode: u64, owner: u32, group: u32, mode: u16, attr: MqueueAttr) -> Self {
        Self {
            inode,
            owner,
            group,
            mode,
            maxmsg: attr.maxmsg,
            msgsize: attr.msgsize,
            state: IrqSafeSpinLock::new(QueueState {
                messages: Vec::new(),
                queued_bytes: 0,
                notification: None,
            }),
            // A fresh queue is empty: has room (writable), no message (not
            // readable).
            readiness: narf_lib::readiness::Readiness::new(POLL_OUT),
        }
    }

    /// Recompute the durable readiness cell from the current message count:
    /// POLL_IN iff non-empty, POLL_OUT iff below `maxmsg`. Reads the state under
    /// its lock, then RELEASES it before `set` (the cell has its own lock; the
    /// two are never held together). Called after every `send`/`receive`;
    /// `event` is the just-changed direction (POLL_IN on send, POLL_OUT on recv).
    fn sync_readiness(&self, event: u32) {
        let (readable, writable) = {
            let state = self.state.lock();
            (
                !state.messages.is_empty(),
                state.messages.len() < self.maxmsg as usize,
            )
        };
        let add = (if readable { POLL_IN } else { 0 }) | (if writable { POLL_OUT } else { 0 });
        let clear = (if readable { 0 } else { POLL_IN }) | (if writable { 0 } else { POLL_OUT });
        self.readiness.set(add, clear);
        // Fire the wait-queue for the just-changed direction, masked to ready.
        self.readiness.notify(event & add);
    }
}

#[derive(Debug)]
struct MqueueFile {
    handle_id: u64,
    queue: Arc<Queue>,
    flags: AtomicU32,
}

impl MqueueFile {
    fn new(handle_id: u64, queue: Arc<Queue>, flags: u32) -> Self {
        Self {
            handle_id,
            queue,
            flags: AtomicU32::new(flags & (O_ACCMODE | O_NONBLOCK)),
        }
    }

    fn attr(&self) -> MqueueAttr {
        let state = self.queue.state.lock();
        MqueueAttr {
            flags: i64::from(self.flags.load(Ordering::Acquire) & O_NONBLOCK),
            maxmsg: self.queue.maxmsg,
            msgsize: self.queue.msgsize,
            curmsgs: state.messages.len() as i64,
        }
    }
}

impl FileOps for MqueueFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let state = self.queue.state.lock();
            let text = format!(
                "QSIZE:{:<10} NOTIFY:{:<5} SIGNO:{:<5} NOTIFY_PID:{:<6}\n",
                state.queued_bytes,
                state.notification.map_or(0, |n| n.method),
                state.notification.map_or(0, |n| n.signal),
                state.notification.map_or(0, |n| n.task_id)
            );
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidData)?;
            if offset >= text.len() {
                return Ok(0);
            }
            let bytes = &text.as_bytes()[offset..];
            let count = bytes.len().min(buf.len());
            buf[..count].copy_from_slice(&bytes[..count]);
            Ok(count)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) })
    }

    fn stat(&self) -> Stat {
        Stat {
            // Linux mqueue.c uses a fixed FILENT_SIZE of 80 bytes.
            size: 80,
            blocks: 0,
            mode: Mode {
                file_type: FileType::File,
                perms: self.queue.mode,
            },
            mtime_cycles: 0,
        }
    }

    fn ino(&self) -> u64 {
        self.queue.inode
    }

    fn owners(&self) -> (u32, u32) {
        (self.queue.owner, self.queue.group)
    }

    fn access<'a>(&'a self, mask: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // The generic VFS access hook lacks caller credentials.  Queue
            // descriptors are checked with credentials in `open`; pathname
            // access remains permissive until Accessor is threaded here.
            let _ = mask;
            Ok(())
        })
    }

    fn poll_readiness(&self) -> u32 {
        let state = self.queue.state.lock();
        let mut ready = 0;
        if !state.messages.is_empty() {
            ready |= POLL_IN;
        }
        if state.messages.len() < self.queue.maxmsg as usize {
            ready |= POLL_OUT;
        }
        ready
    }

    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        // The cell reaches this FileOps type directly through the shared
        // `Arc<Queue>`, so the default `arm_readiness`/`disarm_readiness`
        // delegate here — a `send` (POLL_IN edge) or a `receive` (POLL_OUT edge)
        // fires exactly the waiter armed on this mqd.
        Some(&self.queue.readiness)
    }

    fn mq_queue_id(&self) -> Option<u64> {
        Some(self.handle_id)
    }
}

#[derive(Debug)]
struct Registry {
    names: BTreeMap<(u64, String), Arc<Queue>>,
    handles: BTreeMap<u64, Weak<MqueueFile>>,
    next_id: u64,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            names: BTreeMap::new(),
            handles: BTreeMap::new(),
            // Inode 1 is the mounted root.
            next_id: 1,
        }
    }
}

impl Registry {
    fn alloc_id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.next_id
    }

    fn register_handle(&mut self, queue: Arc<Queue>, flags: u32) -> Arc<MqueueFile> {
        // Bound stale weak entries without needing close hooks in the fd layer.
        self.handles.retain(|_, weak| weak.strong_count() != 0);
        let id = self.alloc_id();
        let file = Arc::new(MqueueFile::new(id, queue, flags));
        self.handles.insert(id, Arc::downgrade(&file));
        file
    }
}

static REGISTRY: IrqSafeSpinLock<Option<Registry>> = IrqSafeSpinLock::new(None);

fn with_registry<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    let mut guard = REGISTRY.lock();
    f(guard.get_or_insert_with(Registry::default))
}

fn normalize_name(name: &str) -> Result<&str, MqueueError> {
    let Some(name) = name.strip_prefix('/') else {
        return Err(MqueueError::Invalid);
    };
    if name.is_empty() || name.contains('/') {
        return Err(MqueueError::Invalid);
    }
    if name.len() > 255 {
        return Err(MqueueError::NameTooLong);
    }
    Ok(name)
}

fn validate_attr(attr: MqueueAttr, privileged: bool) -> Result<MqueueAttr, MqueueError> {
    if attr.maxmsg <= 0 || attr.msgsize <= 0 {
        return Err(MqueueError::Invalid);
    }
    let maxmsg_limit = if privileged { 65_536 } else { MQ_MAXMSG };
    let msgsize_limit = if privileged {
        16 * 1024 * 1024
    } else {
        MQ_MSGSIZE_MAX
    };
    if attr.maxmsg > maxmsg_limit || attr.msgsize > msgsize_limit {
        return Err(MqueueError::Invalid);
    }
    let _ = usize::try_from(attr.maxmsg)
        .ok()
        .and_then(|n| {
            usize::try_from(attr.msgsize)
                .ok()
                .and_then(|s| n.checked_mul(s))
        })
        .ok_or(MqueueError::Invalid)?;
    Ok(MqueueAttr {
        flags: 0,
        curmsgs: 0,
        ..attr
    })
}

fn requested_access(flags: u32) -> Result<AccessRequest, MqueueError> {
    match flags & O_ACCMODE {
        O_RDONLY => Ok(AccessRequest {
            read: true,
            ..AccessRequest::default()
        }),
        O_WRONLY => Ok(AccessRequest {
            write: true,
            ..AccessRequest::default()
        }),
        O_RDWR => Ok(AccessRequest {
            read: true,
            write: true,
            exec: false,
        }),
        _ => Err(MqueueError::Invalid),
    }
}

/// Open or create a queue in `namespace`. The returned `FileOps` is one open
/// file description: its `O_NONBLOCK` state is shared by dup/fork through the
/// descriptor's `Arc`, but independent of other `mq_open` calls.
pub fn open(
    namespace: u64,
    name: &str,
    options: MqueueOpenOptions,
) -> Result<Arc<dyn FileOps>, MqueueError> {
    let MqueueOpenOptions {
        flags,
        mode,
        umask,
        uid,
        gid,
        attr,
    } = options;
    let name = normalize_name(name)?.to_string();
    let want = requested_access(flags)?;
    with_registry(|registry| {
        let key = (namespace, name);
        let queue = if let Some(queue) = registry.names.get(&key) {
            if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
                return Err(MqueueError::Exists);
            }
            if !posix_access_ok(
                FileOwner {
                    uid: queue.owner,
                    gid: queue.group,
                    perms: queue.mode,
                    // A message queue is a file, never a directory.
                    is_dir: false,
                },
                &Accessor::new(uid, gid),
                want,
            ) {
                return Err(MqueueError::PermissionDenied);
            }
            queue.clone()
        } else {
            if flags & O_CREAT == 0 {
                return Err(MqueueError::NotFound);
            }
            let queue_count = registry
                .names
                .keys()
                .filter(|(ns, _)| *ns == namespace)
                .count();
            if queue_count >= MQ_QUEUES_MAX && uid != 0 {
                return Err(MqueueError::NoSpace);
            }
            let attr = validate_attr(attr.unwrap_or_default(), uid == 0)?;
            let inode = registry.alloc_id();
            let queue = Arc::new(Queue::new(inode, uid, gid, mode & !umask & 0o777, attr));
            registry.names.insert(key, queue.clone());
            queue
        };
        Ok(registry.register_handle(queue, flags) as Arc<dyn FileOps>)
    })
}

/// Remove a queue name. Existing descriptors retain the queue object until
/// their final `Arc` is dropped, matching Linux inode lifetime.
pub fn unlink(namespace: u64, name: &str, uid: u32) -> Result<(), MqueueError> {
    let name = normalize_name(name)?;
    with_registry(|registry| {
        let key = (namespace, name.to_string());
        let Some(queue) = registry.names.get(&key) else {
            return Err(MqueueError::NotFound);
        };
        // mqueuefs root is sticky: only root or the queue owner may unlink.
        if uid != 0 && uid != queue.owner {
            return Err(MqueueError::PermissionDenied);
        }
        registry.names.remove(&key);
        Ok(())
    })
}

fn handle(handle_id: u64) -> Result<Arc<MqueueFile>, MqueueError> {
    with_registry(|registry| {
        registry
            .handles
            .get(&handle_id)
            .and_then(Weak::upgrade)
            .ok_or(MqueueError::BadDescriptor)
    })
}

pub fn attributes(handle_id: u64) -> Result<MqueueAttr, MqueueError> {
    Ok(handle(handle_id)?.attr())
}

pub fn set_nonblock(handle_id: u64, enabled: bool) -> Result<(), MqueueError> {
    let file = handle(handle_id)?;
    if enabled {
        file.flags.fetch_or(O_NONBLOCK, Ordering::AcqRel);
    } else {
        file.flags.fetch_and(!O_NONBLOCK, Ordering::AcqRel);
    }
    Ok(())
}

pub fn is_nonblock(handle_id: u64) -> Result<bool, MqueueError> {
    Ok(handle(handle_id)?.flags.load(Ordering::Acquire) & O_NONBLOCK != 0)
}

pub fn send(
    handle_id: u64,
    bytes: Vec<u8>,
    priority: u32,
) -> Result<Option<MqueueNotification>, MqueueError> {
    let file = handle(handle_id)?;
    if file.flags.load(Ordering::Acquire) & O_ACCMODE == O_RDONLY {
        return Err(MqueueError::BadDescriptor);
    }
    if priority >= MQ_PRIO_MAX {
        return Err(MqueueError::Invalid);
    }
    if bytes.len() > file.queue.msgsize as usize {
        return Err(MqueueError::MessageTooLarge);
    }
    let mut state = file.queue.state.lock();
    if state.messages.len() >= file.queue.maxmsg as usize {
        return Err(MqueueError::WouldBlock);
    }
    let was_empty = state.messages.is_empty();
    state.queued_bytes += bytes.len();
    state.messages.push(Message { priority, bytes });
    let notification = if was_empty {
        state.notification.take()
    } else {
        None
    };
    drop(state);
    // Durable per-fd wake: a send makes the queue readable (and possibly fills
    // it); republish + fire the wait-queue so a reader parked on this mqd's cell
    // wakes directly, even on a same-level second message.
    file.queue.sync_readiness(POLL_IN);
    Ok(notification)
}

/// Install, replace-by-cancellation, or remove a Linux one-shot mq_notify
/// registration. A second owner gets EBUSY. Cancellation by a non-owner is a
/// successful no-op, matching `do_mq_notify`.
pub fn notify(
    handle_id: u64,
    task_id: u64,
    notification: Option<MqueueNotification>,
) -> Result<(), MqueueError> {
    let file = handle(handle_id)?;
    let mut state = file.queue.state.lock();
    match notification {
        None => {
            if state
                .notification
                .is_some_and(|current| current.task_id == task_id)
            {
                state.notification = None;
            }
        }
        Some(notification) => {
            if state.notification.is_some() {
                return Err(MqueueError::Busy);
            }
            state.notification = Some(notification);
        }
    }
    Ok(())
}

pub fn close_notification(handle_id: u64, task_id: u64) {
    let _ = notify(handle_id, task_id, None);
}

pub fn receive(handle_id: u64, buffer_len: usize) -> Result<(Vec<u8>, u32), MqueueError> {
    let file = handle(handle_id)?;
    if file.flags.load(Ordering::Acquire) & O_ACCMODE == O_WRONLY {
        return Err(MqueueError::BadDescriptor);
    }
    if buffer_len < file.queue.msgsize as usize {
        return Err(MqueueError::MessageTooLarge);
    }
    let mut state = file.queue.state.lock();
    if state.messages.is_empty() {
        return Err(MqueueError::WouldBlock);
    }
    let mut best = 0;
    for index in 1..state.messages.len() {
        if state.messages[index].priority > state.messages[best].priority {
            best = index;
        }
    }
    let message = state.messages.remove(best);
    state.queued_bytes -= message.bytes.len();
    drop(state);
    // Draining a message makes the queue writable (and possibly empties it);
    // republish + fire the wait-queue so a writer parked on this mqd's cell wakes
    // directly, even on a same-level free.
    file.queue.sync_readiness(POLL_OUT);
    Ok((message.bytes, message.priority))
}

/// A mount of one IPC namespace's live mqueue registry.
#[derive(Debug)]
pub struct MqueueFs {
    namespace: u64,
}

impl MqueueFs {
    pub const fn new(namespace: u64) -> Self {
        Self { namespace }
    }
}

#[derive(Debug)]
struct MqueueDir {
    namespace: u64,
}

impl DirOps for MqueueDir {
    fn ino(&self) -> u64 {
        1
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        with_registry(|registry| {
            let queue = registry
                .names
                .get(&(self.namespace, name.to_string()))?
                .clone();
            Some(registry.register_handle(queue, O_RDONLY) as Arc<dyn FileOps>)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        with_registry(|registry| {
            registry
                .names
                .keys()
                .filter(|(namespace, _)| *namespace == self.namespace)
                .skip(cursor)
                .take(max)
                .map(|(_, name)| (name.clone(), FileType::File))
                .collect()
        })
    }

    fn dir_mode(&self) -> u16 {
        0o1777
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            with_registry(|registry| {
                registry
                    .names
                    .remove(&(self.namespace, name.to_string()))
                    .map(|_| ())
                    .ok_or(FsError::NotFound)
            })
        })
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            open(
                self.namespace,
                &format!("/{name}"),
                MqueueOpenOptions {
                    flags: O_CREAT | O_RDWR,
                    mode: 0o666,
                    umask: 0o022,
                    uid: 0,
                    gid: 0,
                    attr: None,
                },
            )
            .map_err(|error| match error {
                MqueueError::Exists => FsError::Busy,
                MqueueError::NoSpace => FsError::NoSpace,
                MqueueError::PermissionDenied => FsError::PermissionDenied,
                _ => FsError::InvalidData,
            })
        })
    }
}

impl FsInstance for MqueueFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(MqueueDir {
            namespace: self.namespace,
        })
    }

    fn name(&self) -> &str {
        "mqueue"
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        Box::pin(async move {
            let files = with_registry(|registry| {
                registry
                    .names
                    .keys()
                    .filter(|(namespace, _)| *namespace == self.namespace)
                    .count() as u64
            });
            Ok(FsStat {
                files,
                files_free: MQ_QUEUES_MAX as u64 - files,
                block_size: 4096,
                name_len: 255,
                fragment_size: 4096,
                ..FsStat::default()
            })
        })
    }
}

#[doc(hidden)]
pub(crate) fn reset_for_test() {
    *REGISTRY.lock() = Some(Registry::default());
}
