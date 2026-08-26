//! Per-task file-descriptor table.
//!
//! Stage-4 needed by real `Read` / `Write` / `Close` syscall
//! handlers: a handler reads `arg0` as an `fd` (a small u32), looks
//! it up in the calling task's table, and routes the operation to
//! the backing `FileOps` impl. fd 0..=2 are reserved for stdin /
//! stdout / stderr; subsequent slots are first-free.
//!
//! The table is per-task and stored in a global `BTreeMap<TaskId,
//! FdTable>`. Tests + the scheduler call `attach_to(task_id, ops)`
//! to install a backing FileOps; the `Open` handler (when wired)
//! calls `attach_to(current_task, ops)` after VFS resolves a path.
//! `detach(task_id)` removes the whole table on task exit.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

/// Per-task fd table entry.
#[derive(Clone)]
pub struct FdEntry {
    pub ops: Arc<dyn FileOps>,
    /// Initial/debug mirror of the shared description position. Runtime users
    /// must call `FdTable::offset`; dup/fork aliases intentionally do not keep
    /// every slot mirror synchronized.
    pub offset: u64,
    /// Per-fd-slot flags. `FD_CLOEXEC = bit 0`. Mirrors the kernel
    /// fd-table "fd flags" word that `fcntl(F_GETFD/F_SETFD)`
    /// manipulates — not the open-file-description status flags
    /// (those live in `status_flags`).
    pub flags: u32,
    /// Open-file-description status flags (`F_GETFL`/`F_SETFL`).
    /// This value seeds the shared description when a fresh fd is installed;
    /// runtime users must call `FdTable::status_flags`, because aliases may
    /// change the shared value without updating every slot's debug mirror.
    pub status_flags: u32,
}

/// State owned by a Linux open-file description (`struct file`), rather than
/// by one descriptor-table slot.  `dup*` and `fork` install another reference
/// to this object, so file position and mutable status flags remain shared;
/// `FD_CLOEXEC` deliberately stays in [`FdEntry::flags`] because it is per-fd.
#[derive(Debug)]
struct OpenFileState {
    offset: u64,
    status_flags: u32,
}

/// Shared `struct file` analogue. The async mutex serializes sequential I/O
/// across dup/fork aliases without disabling IRQs while FileOps may park.
#[derive(Debug)]
pub(crate) struct OpenFileDescription {
    state: IrqSafeSpinLock<OpenFileState>,
    pub(crate) position_lock: narf_lib::mutex::Mutex<()>,
    /// Index into the bounded inode/FileOps append-lock shard table.
    append_lock_index: usize,
}

pub(crate) type Description = Arc<OpenFileDescription>;

const APPEND_LOCK_SHARDS: usize = 64;
static APPEND_LOCKS: [narf_lib::mutex::Mutex<()>; APPEND_LOCK_SHARDS] =
    [const { narf_lib::mutex::Mutex::new(()) }; APPEND_LOCK_SHARDS];

fn append_lock_index(ops: &Arc<dyn FileOps>) -> usize {
    // Stable inode numbers also cover filesystems that return a fresh FileOps
    // wrapper per lookup. Synthetic zero-inode objects fall back to Arc
    // identity. Collisions only serialize unrelated appenders; they cannot
    // weaken atomicity, and the fixed table avoids an unbounded global map.
    let mut key = ops.ino() as usize;
    if key == 0 {
        key = Arc::as_ptr(ops) as *const () as usize;
    }
    key ^= key >> 17;
    key ^= key >> 9;
    key % APPEND_LOCK_SHARDS
}

impl OpenFileDescription {
    pub(crate) fn offset(&self) -> u64 {
        self.state.lock().offset
    }

    pub(crate) fn set_offset(&self, offset: u64) {
        self.state.lock().offset = offset;
    }

    pub(crate) fn append_lock(&self) -> &'static narf_lib::mutex::Mutex<()> {
        &APPEND_LOCKS[self.append_lock_index]
    }
}

/// `FD_CLOEXEC` — bit 0 of `FdEntry::flags`. Mirrors POSIX. Kept
/// here so callers don't have to import a libc-style header to
/// poke the bit.
pub const FD_CLOEXEC: u32 = 1;

// ── Open-file status flag bits (Linux x86_64 numbering) ────────────
//
// These live in `FdEntry::status_flags` and are toggled by
// `fcntl(F_SETFL)`. Access-mode bits (`O_RDONLY`/`O_WRONLY`/`O_RDWR`)
// are reported by `F_GETFL` but ignored by `F_SETFL` (POSIX: only the
// mutable subset is settable).
pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_ACCMODE: u32 = 0o3;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_APPEND: u32 = 0o2000;
pub const O_DIRECT: u32 = 0o40000;
pub const O_CLOEXEC: u32 = 0o2000000;
/// Path-only open description. Unlike the access-mode value 0 (`O_RDONLY`),
/// an `O_PATH` file has neither Linux `FMODE_READ` nor `FMODE_WRITE`.
pub const O_PATH: u32 = 0o10000000;

/// Settable subset of file status flags per `F_SETFL`. Linux honours
/// these and silently masks the rest.
pub const O_SETFL_MASK: u32 = O_NONBLOCK | O_APPEND | O_DIRECT;

impl core::fmt::Debug for FdEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FdEntry")
            .field("offset", &self.offset)
            .field("flags", &self.flags)
            .field("status_flags", &self.status_flags)
            .finish_non_exhaustive()
    }
}

/// Per-task fd table. Slot 0/1/2 are stdin/stdout/stderr; the
/// kernel populates them at task creation (today's helper:
/// `attach_console_stdio`).
#[derive(Debug)]
pub struct FdTable {
    slots: Vec<Option<FdEntry>>,
    /// Parallel to `slots`. An occupied fd always has exactly one description.
    descriptions: Vec<Option<Description>>,
    /// In-flight fd-number reservations (fanotify delivery). Reserved slots
    /// are not visible through get()/procfs/fork and contain no published file,
    /// but concurrent opens skip them until commit or rollback.
    reserved: BTreeSet<u32>,
    // Linux exposes the allocated fdtable extent to select(2): positive
    // `nfds` is clamped to this value, not to libc's FD_SETSIZE. Keep the
    // semantic extent explicit instead of depending on Vec's allocator-
    // chosen capacity.
    max_fds: usize,
    /// The owning task's RLIMIT_NOFILE soft limit — the `end` argument of
    /// `fs/file.c::alloc_fd`, which reports -EMFILE once the lowest free
    /// descriptor reaches it. Refreshed from the task's rlimits by
    /// [`with_table`] on every access, so a `setrlimit` takes effect on the
    /// next fd-creating call without the table having to be notified.
    nofile_limit: u64,
}

/// Why a descriptor could not be allocated.
///
/// `fs/file.c` keeps these apart deliberately, and the two errnos are not
/// interchangeable: a caller retries or sheds load on -EMFILE, and treats
/// -EBADF as a bug in its own bookkeeping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FdAllocError {
    /// The source descriptor is not open. Linux: -EBADF.
    BadFd,
    /// No free descriptor below the task's RLIMIT_NOFILE. Linux: -EMFILE.
    TooManyFiles,
}

impl FdTable {
    const INITIAL_MAX_FDS: usize = 64;

    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            descriptions: Vec::new(),
            reserved: BTreeSet::new(),
            max_fds: Self::INITIAL_MAX_FDS,
            // Until a task's rlimits are consulted, impose no limit: the
            // boot path seeds stdio into tables that have no task behind
            // them yet, and a limit of zero there would fail every one.
            nofile_limit: u64::MAX,
        }
    }

    /// Publish the owning task's RLIMIT_NOFILE soft limit. Called by
    /// [`with_table`] before handing the table to a caller.
    pub fn set_nofile_limit(&mut self, limit: u64) {
        self.nofile_limit = limit;
    }

    /// The limit descriptor allocation is measured against.
    pub fn nofile_limit(&self) -> u64 {
        self.nofile_limit
    }

    /// Whether a descriptor could be allocated right now — i.e. whether some
    /// free number exists below the task's RLIMIT_NOFILE. A read-only probe
    /// for callers that must decide BEFORE they reach the allocation, and
    /// cannot report an error once they have.
    pub fn can_allocate(&self) -> bool {
        self.next_free_from(0).is_some()
    }

    fn grow_max_fds_for(&mut self, fd: usize) {
        if fd < self.max_fds {
            return;
        }
        self.max_fds = fd
            .saturating_add(1)
            .next_power_of_two()
            .max(Self::INITIAL_MAX_FDS);
    }

    /// Current semantic fdtable extent used by Linux select(2) clamping.
    pub fn max_fds(&self) -> usize {
        self.max_fds
    }

    /// The fd numbers currently open in this table, ascending. Backs
    /// `/proc/<pid>/fd` enumeration (an exact snapshot of the open set,
    /// not a probe of a fixed range).
    pub fn open_fd_numbers(&self) -> Vec<u32> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|_| i as u32))
            .collect()
    }

    /// Insert `entry` at the lowest free fd. POSIX `open(2)` returns the
    /// lowest-numbered descriptor not currently open — so when stdio
    /// occupies 0..=2 this lands at 3+, but a program that closes a low
    /// fd gets that slot back. busybox ash relies on this: to redirect an
    /// async job's stdin it does `close(0); if (open("/dev/null") != 0)
    /// error`, asserting the reopened fd is exactly 0. Skipping 0..=2
    /// unconditionally made every `cmd &` in the distro fail with
    /// "can't open '/dev/null'".
    /// `None` is -EMFILE: no free descriptor below the task's RLIMIT_NOFILE.
    pub fn open(&mut self, entry: FdEntry) -> Option<u32> {
        let description = Self::new_description(&entry);
        let fd = self.next_free_from(0)? as u32;
        self.set_with_description(fd, entry, description);
        Some(fd)
    }

    /// Insert `entry` at the lowest free slot ≥ `min`. Used by
    /// `fcntl(F_DUPFD)` / `F_DUPFD_CLOEXEC`, which POSIX defines as the
    /// lowest free fd at or above `min` — honour `min` verbatim (a free
    /// slot below 3, e.g. a closed stdio fd, is a valid target).
    /// `None` is -EMFILE, as in [`Self::open`].
    pub fn open_at_least(&mut self, entry: FdEntry, min: u32) -> Option<u32> {
        let description = Self::new_description(&entry);
        let fd = self.next_free_from(min as usize)? as u32;
        self.set_with_description(fd, entry, description);
        Some(fd)
    }

    /// Lowest free descriptor at or above `candidate`, or `None` once that
    /// would reach the task's RLIMIT_NOFILE.
    ///
    /// This is `fs/file.c::alloc_fd`'s core:
    ///
    /// ```text
    ///   fd = find_next_fd(fdt, fd);
    ///   error = -EMFILE;
    ///   if (unlikely(fd >= end)) goto out;
    /// ```
    ///
    /// where `end` is `rlimit(RLIMIT_NOFILE)` for every ordinary fd-creating
    /// call. Without the bound the search ran forever upward and NARF could
    /// never report -EMFILE — so a descriptor leak grew without limit instead
    /// of failing at the point the program could still notice.
    fn next_free_from(&self, mut candidate: usize) -> Option<usize> {
        loop {
            if candidate as u64 >= self.nofile_limit {
                return None;
            }
            let occupied = self.slots.get(candidate).is_some_and(Option::is_some);
            if !occupied && !self.reserved.contains(&(candidate as u32)) {
                return Some(candidate);
            }
            candidate = candidate.saturating_add(1);
        }
    }

    /// Place `entry` at a specific slot (typically used for stdio).
    pub fn set(&mut self, fd: u32, entry: FdEntry) {
        let description = Self::new_description(&entry);
        self.set_with_description(fd, entry, description);
    }

    fn set_with_description(&mut self, fd: u32, entry: FdEntry, description: Description) {
        let i = fd as usize;
        self.grow_max_fds_for(i);
        while self.slots.len() <= i {
            self.slots.push(None);
            self.descriptions.push(None);
        }
        self.slots[i] = Some(entry);
        self.descriptions[i] = Some(description);
        self.reserved.remove(&fd);
    }

    /// Reserve lowest-free fd numbers without publishing FileOps. Used by
    /// fanotify, whose metadata must contain the eventual fd number even though
    /// Linux does not install that fd until the user copy has succeeded.
    /// `None` is -EMFILE: fanotify needs `count` descriptor numbers and the
    /// task's RLIMIT_NOFILE does not have that many free. Reservations made
    /// before the shortfall are rolled back, so a failed batch leaves the
    /// table exactly as it was.
    pub(crate) fn reserve_fds(&mut self, count: usize) -> Option<Vec<u32>> {
        let mut out = Vec::with_capacity(count);
        let mut candidate = 0u32;
        while out.len() < count {
            if u64::from(candidate) >= self.nofile_limit {
                for fd in &out {
                    self.reserved.remove(fd);
                }
                return None;
            }
            let occupied = self
                .slots
                .get(candidate as usize)
                .is_some_and(Option::is_some);
            if !occupied && !self.reserved.contains(&candidate) {
                self.reserved.insert(candidate);
                self.grow_max_fds_for(candidate as usize);
                out.push(candidate);
            }
            candidate = candidate.saturating_add(1);
        }
        Some(out)
    }

    pub(crate) fn install_reserved_batch(&mut self, entries: Vec<(u32, FdEntry)>) -> bool {
        if entries.iter().any(|(fd, _)| {
            !self.reserved.contains(fd) || self.slots.get(*fd as usize).is_some_and(Option::is_some)
        }) {
            return false;
        }
        for (fd, entry) in entries {
            let removed = self.reserved.remove(&fd);
            debug_assert!(removed);
            self.set(fd, entry);
        }
        true
    }

    pub(crate) fn release_reserved(&mut self, fds: &[u32]) {
        for fd in fds {
            self.reserved.remove(fd);
        }
    }

    fn new_description(entry: &FdEntry) -> Description {
        Arc::new(OpenFileDescription {
            state: IrqSafeSpinLock::new(OpenFileState {
                offset: entry.offset,
                status_flags: entry.status_flags,
            }),
            position_lock: narf_lib::mutex::Mutex::new(()),
            append_lock_index: append_lock_index(&entry.ops),
        })
    }

    /// Duplicate `oldfd` into the lowest free slot, sharing its open-file
    /// description while resetting the new slot's descriptor flags.
    pub fn duplicate(&mut self, oldfd: u32, min: u32, flags: u32) -> Result<u32, FdAllocError> {
        let old = oldfd as usize;
        let entry = self
            .slots
            .get(old)
            .and_then(Option::as_ref)
            .ok_or(FdAllocError::BadFd)?;
        let description = self
            .descriptions
            .get(old)
            .and_then(Option::as_ref)
            .ok_or(FdAllocError::BadFd)?
            .clone();
        let state = description.state.lock();
        let clone = FdEntry {
            ops: entry.ops.clone(),
            offset: state.offset,
            flags,
            status_flags: state.status_flags,
        };
        drop(state);

        let min = min as usize;
        // Probe for a free slot BEFORE growing, so a request that cannot be
        // satisfied does not extend the table on its way to -EMFILE.
        let target = self.next_free_from(min).ok_or(FdAllocError::TooManyFiles)?;
        self.grow_max_fds_for(min);
        while self.slots.len() <= min {
            self.slots.push(None);
            self.descriptions.push(None);
        }
        self.set_with_description(target as u32, clone, description);
        Ok(target as u32)
    }

    /// Duplicate `oldfd` onto one exact slot, atomically replacing that slot.
    pub fn duplicate_to(&mut self, oldfd: u32, newfd: u32, flags: u32) -> Option<()> {
        // An in-flight fanotify event owns this number until its metadata copy
        // commits or rolls back; do not publish another object into it.
        if self.reserved.contains(&newfd) {
            return None;
        }
        let old = oldfd as usize;
        let entry = self.slots.get(old)?.as_ref()?;
        let description = self.descriptions.get(old)?.as_ref()?.clone();
        let state = description.state.lock();
        let clone = FdEntry {
            ops: entry.ops.clone(),
            offset: state.offset,
            flags,
            status_flags: state.status_flags,
        };
        drop(state);
        self.set_with_description(newfd, clone, description);
        Some(())
    }

    /// Export one open file for SCM_RIGHTS. The returned description is the
    /// same object used by dup/fork, not a snapshot.
    pub(crate) fn export_description(
        &self,
        fd: u32,
    ) -> Option<(Arc<dyn FileOps>, Description, u32)> {
        let i = fd as usize;
        let entry = self.slots.get(i)?.as_ref()?;
        let description = self.descriptions.get(i)?.as_ref()?.clone();
        let status_flags = description.state.lock().status_flags;
        Some((entry.ops.clone(), description, status_flags))
    }

    /// Install an SCM_RIGHTS file as a fresh fd slot while retaining the
    /// sender's open-file description identity.
    /// `None` is -EMFILE. A descriptor arriving over SCM_RIGHTS is allocated
    /// with `get_unused_fd_flags` like any other (`net/core/scm.c::
    /// scm_detach_fds`), so a receiver at its RLIMIT_NOFILE must be told the
    /// message could not be delivered rather than handed a slot past the
    /// limit it set.
    pub(crate) fn open_transferred(
        &mut self,
        ops: Arc<dyn FileOps>,
        description: Option<Description>,
        status_flags: u32,
        flags: u32,
    ) -> Option<u32> {
        let entry = FdEntry {
            ops,
            offset: description
                .as_ref()
                .map(|description| description.state.lock().offset)
                .unwrap_or(0),
            flags,
            status_flags,
        };
        let Some(description) = description else {
            return self.open(entry);
        };
        let target = self.next_free_from(0)?;
        self.grow_max_fds_for(target);
        while self.slots.len() <= target {
            self.slots.push(None);
            self.descriptions.push(None);
        }
        self.slots[target] = Some(entry);
        self.descriptions[target] = Some(description);
        self.reserved.remove(&(target as u32));
        Some(target as u32)
    }

    /// Remove the entry at `fd`. Returns `true` if it existed.
    pub fn close(&mut self, fd: u32) -> bool {
        let i = fd as usize;
        match self.slots.get_mut(i) {
            Some(slot @ Some(_)) => {
                *slot = None;
                self.descriptions[i] = None;
                true
            }
            _ => false,
        }
    }

    /// Whether another descriptor in this table refers to the same open file.
    pub fn has_other_ops(
        &self,
        fd: u32,
        ops: &alloc::sync::Arc<dyn narf_filesystem::FileOps>,
    ) -> bool {
        self.slots.iter().enumerate().any(|(index, slot)| {
            index != fd as usize
                && slot
                    .as_ref()
                    .map(|entry| alloc::sync::Arc::ptr_eq(&entry.ops, ops))
                    .unwrap_or(false)
        })
    }

    /// `close_range(first, last, flags)` — close every open fd in the
    /// inclusive range `[first, last]`. With `cloexec` set
    /// (CLOSE_RANGE_CLOEXEC) the fds are marked FD_CLOEXEC instead of
    /// being closed. Out-of-range bounds are clamped to the table.
    pub fn close_range(&mut self, first: u32, last: u32, cloexec: bool) {
        let lo = first as usize;
        if lo >= self.slots.len() {
            return;
        }
        let hi = (last as usize).min(self.slots.len() - 1);
        if hi < lo {
            return;
        }
        for (relative, slot) in self.slots[lo..=hi].iter_mut().enumerate() {
            if let Some(entry) = slot {
                if cloexec {
                    entry.flags |= FD_CLOEXEC;
                } else {
                    *slot = None;
                    self.descriptions[lo + relative] = None;
                }
            }
        }
    }

    /// Close every fd marked `FD_CLOEXEC` (the exec path). Returns the
    /// number closed. Dropping each `Some` entry releases its
    /// `Arc<dyn FileLike>` reference (closing the underlying object
    /// when this was the last holder).
    pub fn close_cloexec_slots(&mut self) -> usize {
        let mut n = 0;
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if let Some(entry) = slot {
                if entry.flags & FD_CLOEXEC != 0 {
                    *slot = None;
                    self.descriptions[i] = None;
                    n += 1;
                }
            }
        }
        n
    }

    /// Borrow the entry at `fd` without removing it.
    pub fn get(&self, fd: u32) -> Option<&FdEntry> {
        self.slots.get(fd as usize).and_then(Option::as_ref)
    }

    /// Mutable borrow — used by Read/Write to advance the offset.
    pub fn get_mut(&mut self, fd: u32) -> Option<&mut FdEntry> {
        self.slots.get_mut(fd as usize).and_then(Option::as_mut)
    }

    /// Snapshot the shared open-file-description position.
    pub fn offset(&self, fd: u32) -> Option<u64> {
        Some(
            self.descriptions
                .get(fd as usize)?
                .as_ref()?
                .state
                .lock()
                .offset,
        )
    }

    /// Set the shared open-file-description position.
    pub fn set_offset(&mut self, fd: u32, offset: u64) -> Option<()> {
        let i = fd as usize;
        let description = self.descriptions.get(i)?.as_ref()?;
        description.set_offset(offset);
        if let Some(entry) = self.slots.get_mut(i)?.as_mut() {
            entry.offset = offset;
        }
        Some(())
    }

    /// Snapshot the shared open-file-description status flags.
    pub fn status_flags(&self, fd: u32) -> Option<u32> {
        Some(
            self.descriptions
                .get(fd as usize)?
                .as_ref()?
                .state
                .lock()
                .status_flags,
        )
    }

    /// Replace the shared open-file-description status flags.
    pub fn set_status_flags(&mut self, fd: u32, status_flags: u32) -> Option<()> {
        let i = fd as usize;
        let description = self.descriptions.get(i)?.as_ref()?;
        description.state.lock().status_flags = status_flags;
        if let Some(entry) = self.slots.get_mut(i)?.as_mut() {
            entry.status_flags = status_flags;
        }
        Some(())
    }

    pub(crate) fn description(&self, fd: u32) -> Option<Description> {
        self.descriptions.get(fd as usize)?.as_ref().cloned()
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Sharded per-task table ─────────────────────────────────────────

/// `TaskId.raw()` → the task's fd table. The table is behind an
/// `Arc<IrqSafeSpinLock<…>>` so that CLONE_FILES threads can SHARE one table
/// (the same `Arc` is installed under each thread's TaskId; see `share`) while
/// fork still gets an independent COPY (`fork`). The shard lock guards only the
/// map (Arc lookup/insert/remove); fd operations run under the per-table inner
/// lock, so distinct processes don't serialise and a long `poll_blocking` read
/// holds only its own table's lock, not the whole shard.
type Tables = BTreeMap<u64, Arc<IrqSafeSpinLock<FdTable>>>;

/// A fresh fd table pre-populated with the three stdio slots routed to the
/// kernel console (stdin reads EOF until a real backing lands).
fn fresh_table() -> FdTable {
    let mut t = FdTable::new();
    let console: Arc<dyn FileOps> = Arc::new(ConsoleFile::new());
    for fd in 0..3u32 {
        t.set(
            fd,
            FdEntry {
                ops: console.clone(),
                offset: 0,
                flags: 0,
                status_flags: if fd == 0 { O_RDONLY } else { O_WRONLY },
            },
        );
    }
    t
}

/// Number of fd-table shards (power of two). The fd table is consulted on
/// EVERY fd syscall (read/write/epoll resolve fd→FileOps via `with_table`),
/// keyed by task id. A single global lock there serialized all tasks — under
/// an 8-worker server every read/write/poll contended one lock (a hot
/// contributor to the 8-thread mt-echo lock-spin wedge). Sharding by task id
/// means distinct tasks almost never share a shard lock. Same idea as the
/// TCP `TCB_TABLE` / `CONN_INDEX` shards.
const TABLE_SHARDS: usize = 32;

#[inline]
fn table_shard(task_id: u64) -> usize {
    (task_id as usize) & (TABLE_SHARDS - 1)
}

/// The shard array is const-initialised to empty maps: there is NO
/// "store not yet initialised" state.
///
/// It used to be `Option<Tables>` seeded by an explicit `init()`, and every
/// accessor mapped the `None` to a silent failure — `with_table` returned
/// `None`, which `open_impl`'s directory branch reported as the generic `-1`
/// open failure rather than an errno. Because `init()` ran from
/// `boot_userspace_init` (x86_64 + `boot-init` only, and never in a
/// `kernel-test` boot), the whole fd layer was live only if some earlier
/// smoke happened to call `init()`/`__test_reset()` first. That made every
/// fd-using kernel test silently depend on link-section registration order:
/// `smoke_sandbox_root_swap_deep_path_resolves` failed on aarch64 with
/// `openat(/mrfs, O_PATH) failed` purely because a reordering moved the last
/// initialiser after it. `BTreeMap::new()` is `const`, so the uninitialised
/// state buys nothing — deleting it makes the failure unrepresentable.
static TABLES: [IrqSafeSpinLock<Tables>; TABLE_SHARDS] =
    [const { IrqSafeSpinLock::new(BTreeMap::new()) }; TABLE_SHARDS];

/// Look up + run `op` against the table for `task_id`. Creates a
/// fresh table — pre-populated with stdio at fds 0/1/2 — on first
/// reference. Returns the closure's value.
///
/// Always `Some`. The `Option` is retained because ~240 call sites read it,
/// not because the lookup can fail.
pub fn with_table<R>(task_id: u64, op: impl FnOnce(&mut FdTable) -> R) -> Option<R> {
    // Get-or-create this task's table Arc under the shard lock, clone the Arc,
    // then DROP the shard lock before running `op` under the per-table lock.
    // This keeps the hot shard lock held only for the brief map lookup, and lets
    // CLONE_FILES siblings (who share one Arc) serialise on the table itself.
    let arc = {
        let mut map = TABLES[table_shard(task_id)].lock();
        map.entry(task_id)
            .or_insert_with(|| Arc::new(IrqSafeSpinLock::new(fresh_table())))
            .clone()
    };
    let mut table = arc.lock();
    Some(op(&mut table))
}

/// [`with_table`] for an operation that may ALLOCATE a descriptor.
///
/// The task's RLIMIT_NOFILE is read and published to the table first, so the
/// allocation is bounded by the limit in force at this instant — a
/// `setrlimit` therefore applies to the very next fd-creating call, with no
/// table state to invalidate, and a table seeded before its task had rlimits
/// (the boot path installs stdio that way) picks the real limit up on first
/// use.
///
/// Kept separate from `with_table` deliberately. `with_table` is on the hot
/// path — every read, write, epoll and poll resolves fd → FileOps through it —
/// and refreshing the bound there would have put two global lock acquisitions
/// into every one of those syscalls to serve the handful that can allocate.
pub fn with_table_alloc<R>(task_id: u64, op: impl FnOnce(&mut FdTable) -> R) -> Option<R> {
    // Read the limit BEFORE taking the table lock: the lookup reaches into
    // the rlimit store, and nesting that under the table lock would fix a
    // lock order this module has no reason to impose.
    let limit = nofile_limit_for(task_id);
    with_table(task_id, |t| {
        t.set_nofile_limit(limit);
        op(t)
    })
}

/// Install `entry` in `task`'s table at the lowest free descriptor, honouring
/// the task's RLIMIT_NOFILE.
///
/// `None` is -EMFILE. This is the shape every fd-creating syscall wants —
/// `get_unused_fd_flags` + `fd_install` in one step — so handlers do not each
/// have to reach through [`with_table`] and flatten two layers of `Option`.
pub fn install(task_id: u64, entry: FdEntry) -> Option<u32> {
    with_table_alloc(task_id, |t| t.open(entry)).flatten()
}

/// Install two descriptors that must both exist, or neither.
///
/// `fs/pipe.c::__do_pipe_flags` allocates the read end, then the write end,
/// and if the second allocation fails it does `put_unused_fd(fdr)` before
/// returning the error. That rollback is the whole contract: a `pipe(2)` that
/// reports -EMFILE must not have consumed a descriptor on its way out, or a
/// caller that frees a slot and retries loses one more slot every attempt and
/// never recovers.
///
/// `None` is -EMFILE, with the table exactly as it was.
pub fn install_pair(task_id: u64, first: FdEntry, second: FdEntry) -> Option<(u32, u32)> {
    with_table_alloc(task_id, |t| {
        let a = t.open(first)?;
        match t.open(second) {
            Some(b) => Some((a, b)),
            None => {
                t.close(a);
                None
            }
        }
    })
    .flatten()
}

/// Whether `task` could allocate a descriptor right now. See
/// [`FdTable::can_allocate`]; the limit is refreshed as for any allocation.
pub fn has_free_descriptor(task_id: u64) -> bool {
    with_table_alloc(task_id, |t| t.can_allocate()).unwrap_or(false)
}

/// As [`install`], but at the lowest free descriptor at or above `min`.
/// Backs `fcntl(F_DUPFD)`-shaped allocation.
pub fn install_at_least(task_id: u64, entry: FdEntry, min: u32) -> Option<u32> {
    with_table_alloc(task_id, |t| t.open_at_least(entry, min)).flatten()
}

/// Hook supplying a task's RLIMIT_NOFILE soft limit. The rlimit store lives
/// in the syscall layer, above this module, so it is injected rather than
/// reached for — the same shape as the task-id lookup.
type NofileLimitFn = fn(u64) -> u64;
static NOFILE_LIMIT_LOOKUP: IrqSafeSpinLock<Option<NofileLimitFn>> = IrqSafeSpinLock::new(None);

/// Install the RLIMIT_NOFILE lookup. Until this is called every table is
/// unbounded, which is what the early-boot seeding path needs.
pub fn install_nofile_limit_lookup(f: NofileLimitFn) {
    *NOFILE_LIMIT_LOOKUP.lock() = Some(f);
}

/// Drop the lookup again. Test-only: the kernel-test harness rebuilds global
/// state between cases and must not inherit another case's limit.
pub fn __test_clear_nofile_limit_lookup() {
    *NOFILE_LIMIT_LOOKUP.lock() = None;
}

fn nofile_limit_for(task_id: u64) -> u64 {
    // Copy the pointer out and drop the guard before calling: the callback
    // takes the rlimit store's lock, and holding this one across it would
    // create a lock order for no reason.
    let lookup = *NOFILE_LIMIT_LOOKUP.lock();
    match lookup {
        Some(f) => f(task_id),
        None => u64::MAX,
    }
}

/// `with_table` for callers running in the timer trap, which can interrupt
/// a CPU already holding either the shard lock or the table lock — blocking
/// on those deadlocks the machine under observation. `None` on contention.
///
/// Also, unlike [`with_table`], this NEVER creates a table: a diagnostic
/// probe that materialises the thing it is inspecting is not a probe.
#[cfg(feature = "unix-latency-trace")]
pub fn try_with_table<R>(task_id: u64, op: impl FnOnce(&mut FdTable) -> R) -> Option<R> {
    let arc = {
        let map = TABLES[table_shard(task_id)].try_lock()?;
        map.get(&task_id)?.clone()
    };
    let mut table = arc.try_lock()?;
    Some(op(&mut table))
}

/// The fd numbers currently open for `task_id`, ascending. Returns an
/// empty vec if the task has no table yet. Backs `/proc/<pid>/fd`.
pub fn open_fds(task_id: u64) -> Vec<u32> {
    with_table(task_id, |t| t.open_fd_numbers()).unwrap_or_default()
}

/// Per-tty backing. Reads drain the input ring; writes go to the
/// kernel console via `narf_console::Writer`. Each `ConsoleFile`
/// instance owns its own foreground process group, so once `/dev/pts`
/// lands a per-PTY TIOCSPGRP write only affects that one tty.
///
/// The stdio fast-path (fd 0/1/2 sharing one `Arc<ConsoleFile>`) still
/// shares fg_pgrp across the three slots — that matches POSIX: stdio
/// inherits from the controlling tty, so tcsetpgrp on fd 0 is visible
/// on fd 1/2 of the same shell.
/// The kernel-ABI `struct termios` is 36 bytes (`NCCS = 19`): four 32-bit
/// flags (16) + `c_line` (1) + `c_cc[19]` (19). This is what the TCGETS/
/// TCSETS ioctls read/write — NOT libc's userspace `struct termios` (60
/// bytes, `NCCS = 32` + `c_ispeed`/`c_ospeed`). glibc's tcgetattr/tcsetattr
/// pass a 36-byte `__kernel_termios` and convert; writing 60 bytes to that
/// buffer overruns the caller's stack by 24 bytes (clobbering its stack
/// canary → SIGABRT in systemd's isatty() during log setup). musl happens
/// to pass a 60-byte buffer so it tolerated the old behaviour. NARF's
/// internal termios is a 60-byte buffer in the libc layout; its first 36
/// bytes are exactly the kernel struct (the speeds live at offset 52+).
const KERNEL_TERMIOS_LEN: usize = 36;

/// SMAP-safe read of a kernel `struct termios` (36 bytes) from a user
/// pointer, zero-extended into NARF's 60-byte internal buffer. Uses
/// `read_unaligned` inside the SMAP window deliberately: a memcpy escapes
/// the STAC/CLAC bracket and faults the kernel reading the user page.
unsafe fn read_user_termios(uptr: u64) -> Result<[u8; 60], FsError> {
    if uptr == 0 || crate::handlers::validate_user_range(uptr, KERNEL_TERMIOS_LEN).is_err() {
        return Err(FsError::InvalidData);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range-validated; with_user_access brackets SMAP and
    // read_unaligned emits inline loads.
    let k = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::read_unaligned(uptr as *const [u8; KERNEL_TERMIOS_LEN])
        })
    };
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: range-validated; no SMAP off x86_64.
    let k = unsafe { core::ptr::read_unaligned(uptr as *const [u8; KERNEL_TERMIOS_LEN]) };
    let mut out = [0u8; 60];
    out[..KERNEL_TERMIOS_LEN].copy_from_slice(&k);
    Ok(out)
}

/// SMAP-safe write of a kernel `struct termios` (the first 36 bytes of
/// NARF's 60-byte internal buffer) to a user pointer.
unsafe fn write_user_termios(uptr: u64, src: [u8; 60]) -> Result<(), FsError> {
    if uptr == 0 || crate::handlers::validate_user_range(uptr, KERNEL_TERMIOS_LEN).is_err() {
        return Err(FsError::InvalidData);
    }
    let mut k = [0u8; KERNEL_TERMIOS_LEN];
    k.copy_from_slice(&src[..KERNEL_TERMIOS_LEN]);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range-validated; with_user_access brackets SMAP and
    // write_unaligned emits inline stores.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut [u8; KERNEL_TERMIOS_LEN], k)
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: range-validated; no SMAP off x86_64.
    unsafe {
        core::ptr::write_unaligned(uptr as *mut [u8; KERNEL_TERMIOS_LEN], k);
    }
    Ok(())
}

/// Kernel `struct termios2` length: the 36-byte `termios` + `c_ispeed`/
/// `c_ospeed`. glibc's `tcgetattr`/`tcsetattr` use TCGETS2/TCSETS2 on Linux.
const KERNEL_TERMIOS2_LEN: usize = 44;
/// Fixed baud reported in TCGETS2's `c_ispeed`/`c_ospeed` for the virtual
/// console (no real line rate); tcgetattr only needs a consistent value.
const TERMIOS2_BAUD: u32 = 38400;

/// SMAP-safe read of a kernel `struct termios2` (44 bytes); keep the 36-byte
/// `termios` part in NARF's 60-byte internal buffer (speeds are meaningless
/// for a virtual console).
unsafe fn read_user_termios2(uptr: u64) -> Result<[u8; 60], FsError> {
    if uptr == 0 || crate::handlers::validate_user_range(uptr, KERNEL_TERMIOS2_LEN).is_err() {
        return Err(FsError::InvalidData);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range-validated; with_user_access brackets SMAP.
    let k = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::read_unaligned(uptr as *const [u8; KERNEL_TERMIOS_LEN])
        })
    };
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: range-validated; no SMAP off x86_64.
    let k = unsafe { core::ptr::read_unaligned(uptr as *const [u8; KERNEL_TERMIOS_LEN]) };
    let mut out = [0u8; 60];
    out[..KERNEL_TERMIOS_LEN].copy_from_slice(&k);
    Ok(out)
}

/// SMAP-safe write of a kernel `struct termios2` (44 bytes): the 36-byte
/// `termios` (first 36 bytes of the internal buffer) + `c_ispeed`/`c_ospeed`.
unsafe fn write_user_termios2(uptr: u64, src: [u8; 60]) -> Result<(), FsError> {
    if uptr == 0 || crate::handlers::validate_user_range(uptr, KERNEL_TERMIOS2_LEN).is_err() {
        return Err(FsError::InvalidData);
    }
    let mut k = [0u8; KERNEL_TERMIOS2_LEN];
    k[..KERNEL_TERMIOS_LEN].copy_from_slice(&src[..KERNEL_TERMIOS_LEN]);
    k[36..40].copy_from_slice(&TERMIOS2_BAUD.to_ne_bytes());
    k[40..44].copy_from_slice(&TERMIOS2_BAUD.to_ne_bytes());
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range-validated; with_user_access brackets SMAP.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut [u8; KERNEL_TERMIOS2_LEN], k)
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: range-validated; no SMAP off x86_64.
    unsafe {
        core::ptr::write_unaligned(uptr as *mut [u8; KERNEL_TERMIOS2_LEN], k);
    }
    Ok(())
}

/// The boot console behind fd 0/1/2. Stateless: the console is a
/// singleton, so its terminal attributes (termios, winsize) and job-
/// control foreground pgrp all live in `narf_filesystem::console_tty`,
/// shared with `/dev/console` (`DevConsole`). A `tcsetpgrp` on fd 0 is
/// therefore visible to the shell reading `/dev/console` and vice versa.
pub struct ConsoleFile;

impl ConsoleFile {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ConsoleFile {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ConsoleFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConsoleFile").finish()
    }
}

// ── Terminal ioctl numbers (Linux ABI) ─────────────────────────────
//
// The console serves as the system tty. Real userspace (ls, bash,
// vi, less) probes these to decide whether stdout is a terminal,
// what dimensions to draw to, and how many bytes are waiting to be
// read. Returning a sensible default for each is enough to unblock
// every "is this a tty" code path; the actual values can stay
// 80x24/0/etc. until a real tty driver lands.

/// `ioctl(fd, TCGETS, &termios)` — read termios state. musl's
/// `isatty(fd)` calls `tcgetattr(fd, ...)` → `ioctl(fd, TCGETS, ...)`
/// and treats success as "this fd is a tty". Without it, libc
/// thinks stdio isn't a tty → switches to block-buffered mode →
/// `puts` / `printf` output never flushes on \n and a short-lived
/// program (busybox pwd, uname, etc.) exits before fflush runs.
pub const TCGETS: u32 = 0x5401;
/// `ioctl(fd, TCSETS, &termios)` — set terminal attributes (immediate).
pub const TCSETS: u32 = 0x5402;
/// `ioctl(fd, TCSETSW, &termios)` — set terminal attributes (drain output).
pub const TCSETSW: u32 = 0x5403;
/// `ioctl(fd, TCSETSF, &termios)` — set terminal attributes (drain + flush).
pub const TCSETSF: u32 = 0x5404;
/// `ioctl(fd, TCGETS2, &termios2)` — modern glibc `tcgetattr` uses this,
/// NOT TCGETS. Without it `isatty`/`tcgetattr` on fd 0/1/2 fails and systemd
/// disables console logging (see the DevConsole note).
pub const TCGETS2: u32 = 0x802c542a;
/// `ioctl(fd, TCSETS2/TCSETSW2/TCSETSF2, &termios2)` — glibc `tcsetattr`.
pub const TCSETS2: u32 = 0x402c542b;
pub const TCSETSW2: u32 = 0x402c542c;
pub const TCSETSF2: u32 = 0x402c542d;
/// `ioctl(fd, TIOCSCTTY, 0)` — make this the caller's controlling tty.
pub const TIOCSCTTY: u32 = 0x540E;
/// `ioctl(fd, TIOCNOTTY, 0)` — give up this controlling tty. `login`
/// drops a leftover session's ctty before claiming the console itself.
pub const TIOCNOTTY: u32 = 0x5422;
/// `ioctl(fd, TIOCGSID, &pid_t)` — session id of the tty's session leader
/// (`tcgetsid(3)`). getty/login read it back to confirm the ctty is theirs.
pub const TIOCGSID: u32 = 0x5429;
/// `ioctl(fd, TCSBRK, int)` — drain output, optionally send a BREAK.
/// The console has no hardware BREAK; drain is a no-op, so this succeeds.
pub const TCSBRK: u32 = 0x5409;
/// `ioctl(fd, TCXONC, int)` — suspend/resume output (tcflow). No flow
/// control on the singleton console — accepted as a no-op.
pub const TCXONC: u32 = 0x540A;
/// `ioctl(fd, TCFLSH, int)` — flush pending input/output (tcflush).
/// Best-effort: input is drained through the shared discipline; output
/// is unbuffered, so this succeeds without further work.
pub const TCFLSH: u32 = 0x540B;
/// `ioctl(fd, TIOCGWINSZ, &winsize)` — query window dimensions.
pub const TIOCGWINSZ: u32 = 0x5413;
/// `ioctl(fd, TIOCSWINSZ, &winsize)` — set window dimensions.
pub const TIOCSWINSZ: u32 = 0x5414;
/// `ioctl(fd, FIONREAD, &i32)` — bytes immediately readable.
pub const FIONREAD: u32 = 0x541B;
/// `ioctl(fd, TIOCGPGRP, &pid_t)` — foreground process group.
pub const TIOCGPGRP: u32 = 0x540F;
/// `ioctl(fd, TIOCSPGRP, &pid_t)` — set foreground process group.
pub const TIOCSPGRP: u32 = 0x5410;
/// `ioctl(fd, KDGKBMODE, &int)` — query the keyboard translation mode.
/// VT-console keyboard control; NARF has no VT, so it reports the
/// default `K_XLATE` (0) so the query succeeds.
pub const KDGKBMODE: u32 = 0x4B44;
/// `ioctl(fd, KDSKBMODE, int)` — set the keyboard translation mode.
/// Accepted and ignored (no VT keyboard state to change).
pub const KDSKBMODE: u32 = 0x4B45;
/// `ioctl(fd, KDSIGACCEPT, int)` — nominate the signal delivered on the
/// magic "keyboard request" (kbrequest) SysRq. systemd-PID-1 arms this
/// on `/dev/console` during early init; accepted and ignored (NARF has
/// no VT kbrequest source to route through it).
pub const KDSIGACCEPT: u32 = 0x4B4E;
/// `ioctl(fd, KDGETMODE, &int)` — query the VT graphics/text mode. agetty
/// on a Linux VT probes this; NARF has no VT, so it reports `KD_TEXT` (0).
pub const KDGETMODE: u32 = 0x4B3B;
/// `ioctl(fd, VT_OPENQRY, &int)` — first free VT index. NARF has no VT
/// layer; report ENOTTY so a VT-aware getty degrades to serial mode.
pub const VT_OPENQRY: u32 = 0x5600;
/// `ioctl(fd, VT_GETMODE, &vt_mode)` — current VT switching mode.
pub const VT_GETMODE: u32 = 0x5601;
/// `ioctl(fd, VT_GETSTATE, &vt_stat)` — active-VT state.
pub const VT_GETSTATE: u32 = 0x5603;
/// `ioctl(fd, VT_ACTIVATE, vtnum)` — switch to VT `vtnum`.
pub const VT_ACTIVATE: u32 = 0x5606;
/// `ioctl(fd, VT_WAITACTIVE, vtnum)` — block until VT `vtnum` is active.
pub const VT_WAITACTIVE: u32 = 0x5607;

/// POSIX `struct winsize` — row/col + pixel hints. Pixel fields
/// stay zero (we don't model a pixel-aware terminal).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// Default console dimensions. Override via TIOCSWINSZ; survives
/// until reboot. 80x24 matches the historical VT default and is
/// what every "$LINES not set" autocheck falls back to.
static CONSOLE_WINSIZE: IrqSafeSpinLock<Winsize> = IrqSafeSpinLock::new(Winsize {
    ws_row: 24,
    ws_col: 80,
    ws_xpixel: 0,
    ws_ypixel: 0,
});

/// Query the current console window size. Test hook + introspection.
pub fn console_winsize() -> Winsize {
    *CONSOLE_WINSIZE.lock()
}

/// Override the console window size. Wired by `TIOCSWINSZ`.
pub fn set_console_winsize(ws: Winsize) {
    *CONSOLE_WINSIZE.lock() = ws;
}

/// Reset terminal state — test hook. The console's foreground pgrp +
/// termios + line discipline are singleton state in `console_tty` now, so
/// clear them too (a leaked fg_pgrp would perturb later job-control tests).
#[doc(hidden)]
pub fn __test_reset_tty() {
    *CONSOLE_WINSIZE.lock() = Winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    narf_filesystem::console_tty::__test_reset_cooked();
}

impl FileOps for ConsoleFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Route through the single shared console line discipline
        // (`narf_filesystem::console_tty`), the same path /dev/console
        // uses. It owns the termios + cooked/raw mode and drains both
        // input rings (serial bytes + translated keys), so fd 0 and
        // /dev/console see one console with one termios. Cooked mode
        // (the default) returns whole lines with echo + backspace;
        // a program that TCSETSes raw gets byte-at-a-time.
        let n = narf_filesystem::console_tty::read_into(buf);
        let would_block = n == 0 && narf_filesystem::console_tty::block_on_input();
        Box::pin(async move {
            if would_block {
                Err(narf_filesystem::FsError::WouldBlock)
            } else {
                Ok(n)
            }
        })
    }
    /// Block an empty console read on the input waker (woken by the
    /// serial/keyboard IRQ) instead of returning a spurious 0. This is what
    /// lets an interactive shell `read(stdin)` truly sleep until a keystroke
    /// rather than busy-poll. sys_read parks via the `console_read_pending`
    /// path when this is true and the fd is blocking. Delegates to the
    /// shared discipline: park while no completed line/byte is buffered.
    fn block_on_input(&self) -> bool {
        narf_filesystem::console_tty::block_on_input()
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = buf.len();
        // Eagerly write: the future just reports the count.
        use core::fmt::Write as _;
        let mut w = narf_console::Writer;
        for &b in buf {
            let _ = w.write_char(b as char);
        }
        Box::pin(async move { Ok(n) })
    }
    /// fds 0/1/2 are the boot console — a TTY, so they must `fstat` as
    /// `S_IFCHR`, exactly as `/dev/console` does. Reporting `S_IFREG`
    /// here is not cosmetic: GNU coreutils switches `cat` from a
    /// read/write loop to `copy_file_range(2)` when *both* ends stat as
    /// regular files, so a "regular file" stdout sent every `cat` in a
    /// glibc distro down the in-kernel copy path with a char device on
    /// the other end. Anything else that branches on `S_ISREG(stdout)`
    /// (shells deciding on buffering, `less`, `tee`) was mislead too.
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o620,
            },
            mtime_cycles: 0,
        }
    }
    /// `poll(2)` readiness — POLLIN only when at least one ASCII
    /// byte is queued in the input ring, POLLOUT always (the
    /// kernel console writer never blocks). Returning POLLIN
    /// unconditionally — the default — breaks interactive shells:
    /// busybox sh's read-loop does `poll(stdin, POLLIN, -1)`,
    /// reads zero bytes when the ring is empty, interprets that
    /// as EOF and exits the moment the user gets to a prompt.
    fn poll_readiness(&self) -> u32 {
        let mut mask = narf_filesystem::POLL_OUT;
        if narf_filesystem::console_tty::readable_bytes() > 0 {
            mask |= narf_filesystem::POLL_IN;
        }
        mask
    }
    /// Job control: the boot console's stable tty id.
    fn tty_id(&self) -> Option<u32> {
        Some(narf_filesystem::TTY_ID_CONSOLE)
    }
    /// Job control: the console's (singleton) foreground process group.
    fn tty_fg_pgrp(&self) -> Option<u64> {
        Some(narf_filesystem::console_tty::fg_pgrp())
    }
    /// Job control: TOSTOP from the shared console termios.
    fn tty_tostop(&self) -> bool {
        narf_filesystem::console_tty::tostop()
    }
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        // Terminal ioctls. All return Ok(0) on success; any
        // user-pointer fault is reported as FsError::InvalidData
        // (→ EINVAL at the syscall layer — close enough to EFAULT
        // for ABI purposes since the wire shape is the same).
        match cmd {
            TCGETS => {
                // Return the current termios from the shared console_tty
                // (cooked default until a program TCSETS its own), so
                // isatty(0) succeeds AND an interactive shell sees a real
                // cooked tty (ICANON|ECHO). The discipline now enforces it.
                let raw = narf_filesystem::console_tty::termios();
                // SAFETY: `arg` is the user `struct termios *` from ioctl;
                // write_user_termios range-validates + SMAP-brackets it.
                unsafe { write_user_termios(arg as u64, raw)? };
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                // Round-trip the caller's termios into the shared state so
                // a program can switch raw/cooked; the console_tty line
                // discipline reads these flags on the next read (what
                // vi/less/readline rely on). Visible to TCGETS on fd 1/2
                // and /dev/console alike.
                // SAFETY: `arg` is the validated user `struct termios *`.
                let raw = unsafe { read_user_termios(arg as u64)? };
                narf_filesystem::console_tty::set_termios(raw);
                Ok(0)
            }
            TCGETS2 => {
                let raw = narf_filesystem::console_tty::termios();
                // SAFETY: `arg` is the user `struct termios2 *` from ioctl.
                unsafe { write_user_termios2(arg as u64, raw)? };
                Ok(0)
            }
            TCSETS2 | TCSETSW2 | TCSETSF2 => {
                // SAFETY: `arg` is the validated user `struct termios2 *`.
                let raw = unsafe { read_user_termios2(arg as u64)? };
                narf_filesystem::console_tty::set_termios(raw);
                Ok(0)
            }
            TIOCSCTTY => {
                // Make the boot console the caller's controlling terminal.
                // Needed after setsid() (which detaches): a getty/login that
                // claims the console as its session's ctty records it here so
                // the job-control SIGTTIN/SIGTTOU check recognises it.
                #[cfg(feature = "linux-compat")]
                crate::handlers::set_controlling_tty_console(crate::handlers::current_task_id());
                Ok(0)
            }
            TIOCNOTTY => {
                // Give up the controlling terminal (tcsetsid teardown /
                // login's pre-claim reset). Mark the caller detached so a
                // later open/TIOCSCTTY re-acquires cleanly.
                #[cfg(feature = "linux-compat")]
                crate::handlers::detach_controlling_tty(crate::handlers::current_task_id());
                Ok(0)
            }
            #[cfg(feature = "linux-compat")]
            TIOCGSID => {
                // tcgetsid(3): session id of the tty's session. NARF's
                // console is the session leader's ctty, so report the
                // caller's session id (visible-pid space).
                let sid = crate::handlers::current_task_sid_user() as i32;
                let bytes = sid.to_le_bytes();
                // SAFETY: `copy_to_user` validates `arg` through the SMAP
                // window; the length is the fixed 4-byte `pid_t` encoding.
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TCSBRK | TCXONC | TCFLSH => {
                // Output is unbuffered and there is no hardware BREAK or
                // flow control on the singleton console, so drain/flush/
                // flow requests have nothing to do — succeed so a program
                // that flushes on mode changes (readline, agetty) proceeds.
                Ok(0)
            }
            TIOCGWINSZ => {
                let ws = console_winsize();
                // SAFETY: `Winsize` is a `repr(C)` POD of four `u16` (8 bytes)
                // with no padding, so its layout matches `[u8; 8]` exactly.
                // SAFETY: Valid memory or trusted environment
                let bytes: [u8; 8] = unsafe { core::mem::transmute(ws) };
                // SAFETY: `copy_to_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 8-byte
                // `bytes` buffer holding the serialized `struct winsize`.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCSWINSZ => {
                let mut bytes = [0u8; 8];
                // SAFETY: `copy_from_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 8-byte
                // `bytes` buffer that receives the serialized `struct winsize`.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_from_user(&mut bytes, arg as u64) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                // SAFETY: `Winsize` is a `repr(C)` POD of four `u16` (8 bytes)
                // with no padding and every bit pattern valid, so the
                // round-trip from `[u8; 8]` is sound.
                // SAFETY: Valid memory or trusted environment
                let ws: Winsize = unsafe { core::mem::transmute(bytes) };
                set_console_winsize(ws);
                Ok(0)
            }
            FIONREAD => {
                // Best-effort: bytes immediately readable through the
                // shared discipline (completed lines + queued raw input).
                let n: i32 = narf_filesystem::console_tty::readable_bytes() as i32;
                let bytes = n.to_le_bytes();
                // SAFETY: `copy_to_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 4-byte
                // little-endian encoding of the `i32` pending-byte count.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCGPGRP => {
                // pid_t = i32 on Linux x86_64.
                //
                // POSIX `tcgetpgrp(3)` returns the foreground process
                // group ID of the controlling terminal. NARF boots
                // straight into a single console without going through
                // a getty/login that would `setsid` + `TIOCSCTTY` +
                // `tcsetpgrp` — so the first caller to ask for the
                // foreground pgid arrives with `fg_pgrp == 0`. Return
                // a real pgid in that case by auto-installing the
                // caller's pgrp, mirroring how a session leader
                // implicitly acquires the controlling tty.
                //
                // Without this, busybox `sh`'s job-control init loop
                // (`while tcgetpgrp(0) != getpgrp() { raise(SIGTTIN); }`)
                // spins forever because tcgetpgrp returns 0 and
                // getpgrp returns the shell's tid.
                // fg_pgrp is kept in task-id space internally; report it
                // to userspace in the visible-pid space getpid/getpgrp use.
                let pgrp = crate::handlers::pgid_to_user(
                    narf_filesystem::console_tty::fg_pgrp_or_install(
                        crate::handlers::current_task_pgid(),
                    ),
                );
                let bytes = (pgrp as i32).to_le_bytes();
                // SAFETY: `copy_to_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 4-byte
                // little-endian encoding of the `pid_t` foreground pgid.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            TIOCSPGRP => {
                let mut bytes = [0u8; 4];
                // SAFETY: `copy_from_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 4-byte
                // buffer that receives the little-endian `pid_t` pgid.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_from_user(&mut bytes, arg as u64) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                let pgrp = i32::from_le_bytes(bytes);
                if pgrp < 0 {
                    return Err(FsError::InvalidData);
                }
                // Userspace passes a visible pid; the tty stores fg_pgrp in
                // task-id space (consistent with read_pgid / the SIGTTIN
                // check), so translate before storing.
                let pgrp = crate::handlers::pgid_from_user(pgrp as u64);
                narf_filesystem::console_tty::set_fg_pgrp(pgrp);
                Ok(0)
            }
            KDSIGACCEPT | KDSKBMODE => {
                // VT keyboard/kbrequest control. NARF drives a single serial
                // console with no VT layer, so there is no kbrequest source
                // or keyboard-translation state to change — accept and no-op
                // so systemd's early-init arming step succeeds instead of
                // logging "Inappropriate ioctl for device".
                Ok(0)
            }
            KDGKBMODE => {
                // Report the default keyboard mode `K_XLATE` (0). `arg` is an
                // `int *` out-parameter.
                let bytes = 0i32.to_le_bytes();
                // SAFETY: `copy_to_user` validates `arg` as a user address
                // through the SMAP window; the length is the fixed 4-byte
                // little-endian encoding of the `int` keyboard mode.
                // SAFETY: Valid memory or trusted environment
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            KDGETMODE => {
                // VT graphics/text mode. No VT layer → always text (`KD_TEXT`
                // = 0). `arg` is an `int *` out-parameter.
                let bytes = 0i32.to_le_bytes();
                // SAFETY: `copy_to_user` validates `arg` through the SMAP
                // window; the length is the fixed 4-byte `int` encoding.
                if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
                    return Err(FsError::InvalidData);
                }
                Ok(0)
            }
            VT_OPENQRY | VT_GETMODE | VT_GETSTATE | VT_ACTIVATE | VT_WAITACTIVE => {
                // Virtual-terminal control. NARF drives a serial/dumb console
                // with no VT layer, so report ENOTTY (via Unsupported): a
                // VT-aware agetty treats this as "not a VT" and degrades to
                // plain serial operation rather than aborting. Distinct from
                // a bare -1 — the errno is what lets getty branch correctly.
                Err(FsError::Unsupported)
            }
            _ => Err(FsError::Unsupported),
        }
    }
}

/// Duplicate every fd entry from `parent` into a fresh table for
/// `child`. POSIX fork(2): the child inherits an independent copy
/// of the descriptor table whose entries reference the same
/// underlying open-file objects (Arc::clone on the inner `FileOps`
/// trait object — refcount up, no extra `Box::new`). Per-fd `flags`
/// remain per-slot. The open-file descriptions themselves are shared, exactly
/// as Linux shares `struct file`: file position and status changes made by
/// either process are immediately visible to the other.
///
/// Idempotent only if the child table doesn't already exist; if it
/// does, the existing table is overwritten with the parent's
/// snapshot — fork is the entry point that should hit this, and a
/// child's table cannot pre-exist its own creation.
///
/// Returns the number of fds copied.
pub fn fork(parent: u64, child: u64) -> usize {
    // Snapshot the parent's slots (under the parent table's own lock), build an
    // INDEPENDENT copy in a fresh Arc, install for the child. Never hold two
    // shard locks at once → no lock-ordering hazard.
    let parent_arc = TABLES[table_shard(parent)].lock().get(&parent).cloned();
    let (parent_slots, parent_descriptions, parent_max_fds) = match parent_arc {
        Some(a) => {
            let table = a.lock();
            (
                table.slots.clone(),
                table.descriptions.clone(),
                table.max_fds,
            )
        }
        None => (Vec::new(), Vec::new(), FdTable::INITIAL_MAX_FDS),
    };
    let copied = parent_slots.iter().filter(|s| s.is_some()).count();
    let mut child_table = FdTable::new();
    child_table.slots = parent_slots;
    child_table.descriptions = parent_descriptions;
    child_table.max_fds = parent_max_fds;
    TABLES[table_shard(child)]
        .lock()
        .insert(child, Arc::new(IrqSafeSpinLock::new(child_table)));
    copied
}

/// Whether any fd table OTHER than `closing_task`'s still holds `ops`.
///
/// `FdTable::has_other_ops` only sees one process's descriptors, so after a
/// fork every process believes it owns the last copy of an inherited file
/// description. For a bound AF_UNIX socket that is the difference between
/// "the last descriptor closed, release the path" and "a child dropped its
/// inherited copy while the parent is still listening".
///
/// CLONE_FILES siblings share one table `Arc`, so the closing task's table
/// is identified by pointer and skipped wholesale: its own duplicates are
/// already covered by `has_other_ops`.
///
/// Linear in live tasks, so callers must reach it only on the close of a
/// descriptor that actually owns a registration — not on every close.
pub fn ops_held_by_other_task(
    closing_task: u64,
    ops: &alloc::sync::Arc<dyn narf_filesystem::FileOps>,
) -> bool {
    let own = TABLES[table_shard(closing_task)]
        .lock()
        .get(&closing_task)
        .cloned();
    for shard in TABLES.iter() {
        // Clone the shard's table Arcs out from under its lock, so the
        // per-table locks below are never taken while a shard lock is held.
        let tables: Vec<Arc<IrqSafeSpinLock<FdTable>>> = shard.lock().values().cloned().collect();
        for table in tables {
            if let Some(own) = own.as_ref() {
                if Arc::ptr_eq(&table, own) {
                    continue;
                }
            }
            let held = table.lock().slots.iter().any(|slot| {
                slot.as_ref()
                    .map(|entry| alloc::sync::Arc::ptr_eq(&entry.ops, ops))
                    .unwrap_or(false)
            });
            if held {
                return true;
            }
        }
    }
    false
}

/// CLONE_FILES: install the SAME table `Arc` under the child's TaskId so the
/// child and parent (and every other thread of the process) share one fd table
/// — an fd opened by any thread is visible to all, and `close` in one closes it
/// for all (Linux thread semantics). The table is freed only when the last
/// sharer `detach`es (Arc refcount). Returns the number of fds in the table.
pub fn share(parent: u64, child: u64) -> usize {
    // Get-or-create the parent's table Arc atomically (same logic as
    // `with_table`'s first-touch), then install that same Arc for the child.
    let arc = {
        let mut map = TABLES[table_shard(parent)].lock();
        map.entry(parent)
            .or_insert_with(|| Arc::new(IrqSafeSpinLock::new(fresh_table())))
            .clone()
    };
    let n = arc.lock().slots.iter().filter(|s| s.is_some()).count();
    TABLES[table_shard(child)].lock().insert(child, arc);
    n
}

/// Close every `FD_CLOEXEC`-marked fd for `task_id` (the exec path).
/// Returns the count closed; no-op if the task has no table (never
/// opened an fd). Shares one fd table with CLONE_FILES siblings, so a
/// CLOEXEC close is visible to them too — matching Linux, where exec
/// unshares files first; NARF's exec implies a non-shared table.
pub fn close_cloexec(task_id: u64) -> usize {
    let arc = match TABLES[table_shard(task_id)].lock().get(&task_id).cloned() {
        Some(a) => a,
        None => return 0,
    };
    let n = arc.lock().close_cloexec_slots();
    n
}

/// Drop the entire fd table for `task_id`. Call on task exit so
/// the FileOps `Arc`s can release.
pub fn detach(task_id: u64) {
    TABLES[table_shard(task_id)].lock().remove(&task_id);
    // Drop any advisory POSIX locks the task held so its peers can
    // make progress on shared inodes — and wake their F_SETLKW waiters
    // NOW. This is the FIRST of the two exit-path release_owner calls
    // (release_task_tables runs after and finds the table already
    // drained), so the immediate wake must fire from here or a waiter
    // blocked on a dead holder only gets its 1 ms backstop.
    #[cfg(feature = "linux-compat")]
    for key in locks::release_owner(task_id) {
        for (waiter, w) in locks::drain_waiters(key) {
            crate::handlers::wake_one(waiter, w);
        }
    }
}

/// Test/reset hook — wipe every per-task table. Lets independent
/// kernel_test cases share state cleanly.
#[doc(hidden)]
pub fn __test_reset() {
    for shard in TABLES.iter() {
        shard.lock().clear();
    }
}

/// Number of tasks with at least one fd installed. Diagnostic.
pub fn live_task_count() -> usize {
    TABLES.iter().map(|s| s.lock().len()).sum()
}

// ── Advisory POSIX file locks (Wave-68, linux-compat) ──────────────
//
// `fcntl(F_SETLK/F_SETLKW/F_GETLK)` advisory range locks. Keyed by
// the underlying open-file object identity (`Arc::as_ptr` cast to
// usize), so two fds that point at the same inode share locks.
// Conflict rule: a write lock conflicts with any other lock on an
// overlapping range; a read lock conflicts only with a write lock.
// `owner` is the holding task id — same owner replaces / extends.
//
// F_SETLKW (blocking) is *not* wired to a waker; today it returns
// EAGAIN on conflict just like F_SETLK. A follow-up wave will add
// the per-inode wait queue.

#[cfg(feature = "linux-compat")]
pub mod locks {
    use super::*;

    /// `l_type` values from POSIX `struct flock`.
    pub const F_RDLCK: i16 = 0;
    pub const F_WRLCK: i16 = 1;
    pub const F_UNLCK: i16 = 2;

    #[derive(Clone, Copy, Debug)]
    pub struct Lock {
        pub owner: u64,
        pub ty: i16, // F_RDLCK or F_WRLCK
        pub start: i64,
        pub len: i64, // 0 = to EOF
    }

    impl Lock {
        /// Inclusive end of this range; `i64::MAX` if `len == 0`.
        pub fn end(&self) -> i64 {
            if self.len == 0 {
                i64::MAX
            } else {
                self.start.saturating_add(self.len).saturating_sub(1)
            }
        }
        pub fn overlaps(&self, other: &Lock) -> bool {
            self.start <= other.end() && other.start <= self.end()
        }
        pub fn conflicts(&self, other: &Lock) -> bool {
            if self.owner == other.owner {
                return false;
            }
            if !self.overlaps(other) {
                return false;
            }
            self.ty == F_WRLCK || other.ty == F_WRLCK
        }
    }

    static TABLE: IrqSafeSpinLock<Option<BTreeMap<usize, Vec<Lock>>>> = IrqSafeSpinLock::new(None);

    fn ensure() {
        let mut g = TABLE.lock();
        if g.is_none() {
            *g = Some(BTreeMap::new());
        }
    }

    /// Attempt to install `req`. Returns Ok if installed, Err with
    /// the first conflicting lock if not.
    pub fn try_set(key: usize, req: Lock) -> Result<(), Lock> {
        ensure();
        let mut g = TABLE.lock();
        let map = g.as_mut().unwrap();
        let bucket = map.entry(key).or_default();
        if req.ty == F_UNLCK {
            bucket.retain(|l| !(l.owner == req.owner && l.overlaps(&req)));
            return Ok(());
        }
        for l in bucket.iter() {
            if l.conflicts(&req) {
                return Err(*l);
            }
        }
        // Merge with same-owner locks of the same type, drop covered.
        bucket.retain(|l| !(l.owner == req.owner && l.overlaps(&req)));
        bucket.push(req);
        Ok(())
    }

    /// Probe `req`. If a conflict exists, returns the blocker; else
    /// returns None (caller should report F_UNLCK).
    pub fn probe(key: usize, req: Lock) -> Option<Lock> {
        let g = TABLE.lock();
        let map = g.as_ref()?;
        let bucket = map.get(&key)?;
        bucket.iter().copied().find(|l| l.conflicts(&req))
    }

    /// Drop every lock owned by `owner`. Call on task exit so leaked
    /// locks don't pin out other tasks forever. Returns the keys that
    /// actually lost a lock — the caller wakes their F_SETLKW waiters
    /// (the wake needs `wake_one`, which lives with the handlers).
    pub fn release_owner(owner: u64) -> Vec<usize> {
        let mut g = TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => return Vec::new(),
        };
        let mut touched = Vec::new();
        for (key, bucket) in map.iter_mut() {
            let before = bucket.len();
            bucket.retain(|l| l.owner != owner);
            if bucket.len() != before {
                touched.push(*key);
            }
        }
        map.retain(|_, v| !v.is_empty());
        touched
    }

    // ── F_SETLKW waiters ─────────────────────────────────────────────
    //
    // key → (tid → waker). Registered by `park_should_block` while a
    // task is parked in a blocked F_SETLKW (the uctx `flock_key` field
    // routes it here, exactly like `futex_uaddr` routes to the futex
    // queue); drained-and-woken by the unlock paths so a waiter retries
    // IMMEDIATELY instead of riding out its 1 ms wheel backstop. The
    // backstop stays armed — it bounds the register-vs-unlock race
    // window to one period, so a missed wake degrades, never wedges.
    static WAITERS: IrqSafeSpinLock<Option<BTreeMap<usize, BTreeMap<u64, core::task::Waker>>>> =
        IrqSafeSpinLock::new(None);

    pub fn register_waiter(key: usize, tid: u64, waker: core::task::Waker) {
        let mut g = WAITERS.lock();
        g.get_or_insert_with(BTreeMap::new)
            .entry(key)
            .or_default()
            .insert(tid, waker);
    }

    pub fn drop_waiter(key: usize, tid: u64) {
        let mut g = WAITERS.lock();
        if let Some(m) = g.as_mut() {
            if let Some(set) = m.get_mut(&key) {
                set.remove(&tid);
                if set.is_empty() {
                    m.remove(&key);
                }
            }
        }
    }

    /// Drop `tid` from every key's waiter set (task exit).
    pub fn drop_waiter_owner(tid: u64) {
        let mut g = WAITERS.lock();
        if let Some(m) = g.as_mut() {
            for set in m.values_mut() {
                set.remove(&tid);
            }
            m.retain(|_, s| !s.is_empty());
        }
    }

    /// Take every waiter parked on `key`. The caller fires the wakes
    /// AFTER this lock is dropped (wake() may re-enter the scheduler).
    pub fn drain_waiters(key: usize) -> Vec<(u64, core::task::Waker)> {
        let mut g = WAITERS.lock();
        g.as_mut()
            .and_then(|m| m.remove(&key))
            .map(|set| set.into_iter().collect())
            .unwrap_or_default()
    }

    #[doc(hidden)]
    pub fn __test_reset() {
        *TABLE.lock() = Some(BTreeMap::new());
        *WAITERS.lock() = Some(BTreeMap::new());
    }
}
