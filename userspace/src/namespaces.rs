//! Wave-72 — per-task Linux-style namespaces beyond CLONE_NEWNS.
//!
//! Three more namespace flavours stack on top of the Wave-67
//! MountNamespace work in `narf_filesystem`:
//!
//!   * `UtsNamespace`  — CLONE_NEWUTS (0x04000000). Per-ns
//!     hostname + domainname; uname(2) and {get,set}hostname
//!     read/write namespace-local fields.
//!   * `NetNamespace`  — CLONE_NEWNET (0x40000000). Per-ns iface
//!     identity seeded with a synthetic `lo`. Physical interfaces,
//!     IPv4 FIB entries, netfilter state, rtnetlink views, and raw
//!     ingress delivery are selected by that identity.
//!   * `IpcNamespace`  — CLONE_NEWIPC (0x08000000). Per-ns SysV
//!     IPC keyspace (shmget/semget/msgget) and POSIX mqueue keys.
//!     The subsystems are themselves stubbed in NARF, so this
//!     skill mints the per-ns counter and resolves no real
//!     segments — full impl lands once the SysV IPC surface
//!     does.
//!
//! All three are stored behind `Arc<…>` in per-task BTreeMaps
//! keyed by `current_task_id()`, mirroring how Wave-67's
//! mount-namespace plumbing is wired in `handlers.rs`. The
//! whole module is gated on `feature = "container"` so the
//! default kernel build pays no cost (the `mod namespaces`
//! declaration in `lib.rs` carries the `#[cfg]`).

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Stable namespace identity (NsId) ─────────────────────────────
//
// Every namespace flavour (uts/net/ipc/pid/mount/cgroup/user) carries
// a process-global, monotonically increasing `NsId`. Linux uses the
// namespace's inode number in the nsfs filesystem for the same job —
// it's what `readlink /proc/<pid>/ns/<flavour>` renders inside
// `flavour:[<id>]` and what `stat().st_ino` reports on an open ns-fd,
// so two fds naming the same namespace compare equal. A single shared
// counter across all flavours keeps ids globally unique (matches
// Linux nsfs, where the inode space is shared), which the ns-fd
// equality check below relies on.

/// A stable, process-global namespace identity. Minted from one shared
/// monotonic counter so ids never collide across flavours.
pub type NsId = u64;

static NS_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static INITIAL_NET_NS_ID: AtomicU64 = AtomicU64::new(0);
static INITIAL_IPC_NS_ID: AtomicU64 = AtomicU64::new(0);
static INITIAL_PID_NS_ID: AtomicU64 = AtomicU64::new(0);

/// Allocate a fresh, never-reused namespace id.
pub fn alloc_ns_id() -> NsId {
    NS_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn initial_ns_id(slot: &AtomicU64) -> NsId {
    let current = slot.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let fresh = alloc_ns_id();
    match slot.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(existing) => existing,
    }
}

/// Linux ns-flavour tags used to render `readlink` text and to tag the
/// ns-fd so `setns(fd, nstype)` can sanity-check the flavour.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NsFlavour {
    Uts,
    Net,
    Ipc,
    Pid,
    Mnt,
    Cgroup,
    User,
}

impl NsFlavour {
    /// The token Linux uses in `readlink` output (`uts:[…]`, `net:[…]`).
    pub fn tag(self) -> &'static str {
        match self {
            NsFlavour::Uts => "uts",
            NsFlavour::Net => "net",
            NsFlavour::Ipc => "ipc",
            NsFlavour::Pid => "pid",
            NsFlavour::Mnt => "mnt",
            NsFlavour::Cgroup => "cgroup",
            NsFlavour::User => "user",
        }
    }

    /// The `CLONE_NEW*` bit a `setns(fd, nstype)` would pass to select
    /// this flavour. `0` means "any nstype is accepted" (Linux allows
    /// `setns(fd, 0)` to join every namespace the fd names).
    pub fn clone_flag(self) -> u64 {
        match self {
            NsFlavour::Uts => CLONE_NEWUTS,
            NsFlavour::Net => CLONE_NEWNET,
            NsFlavour::Ipc => CLONE_NEWIPC,
            NsFlavour::Pid => CLONE_NEWPID,
            NsFlavour::Mnt => CLONE_NEWNS,
            NsFlavour::Cgroup => CLONE_NEWCGROUP,
            NsFlavour::User => CLONE_NEWUSER,
        }
    }
}

// ── Linux clone(2) namespace flags we honour beyond CLONE_NEWNS ────

/// `CLONE_NEWNS` (Linux) — fresh mount namespace.
pub const CLONE_NEWNS: u64 = 0x0002_0000;

/// `CLONE_NEWCGROUP` (Linux) — fresh cgroup namespace.
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;

/// `CLONE_NEWUTS` (Linux) — fresh UTS namespace (hostname +
/// domainname).
pub const CLONE_NEWUTS: u64 = 0x0400_0000;

/// `CLONE_NEWIPC` (Linux) — fresh SysV/POSIX IPC namespace.
pub const CLONE_NEWIPC: u64 = 0x0800_0000;

/// `CLONE_NEWUSER` (Linux) — fresh user namespace (uid/gid maps).
pub const CLONE_NEWUSER: u64 = 0x1000_0000;

/// `CLONE_NEWPID` (Linux) — fresh PID namespace.
pub const CLONE_NEWPID: u64 = 0x2000_0000;

/// `CLONE_NEWNET` (Linux) — fresh network namespace.
pub const CLONE_NEWNET: u64 = 0x4000_0000;

// ── UTS namespace ────────────────────────────────────────────────

/// Bound matches Linux's `__NEW_UTS_LEN = 64`. NARF's POSIX
/// HOST_NAME_MAX uses the same value, so the shared cap keeps the
/// global and per-ns paths in step.
pub const UTS_NAME_MAX: usize = 64;

/// Default hostname seeded into the boot/global UTS namespace and
/// every freshly-unshared namespace that does not get a
/// `sethostname` before its first `gethostname`.
pub const DEFAULT_HOSTNAME: &str = "narf";

/// Per-namespace UTS state. Holds the hostname + domainname behind
/// a single lock — both are short strings, contention is non-issue.
#[derive(Debug)]
pub struct UtsNamespace {
    id: NsId,
    inner: IrqSafeSpinLock<UtsInner>,
}

#[derive(Debug)]
struct UtsInner {
    hostname: String,
    domainname: String,
}

impl UtsNamespace {
    /// Seed a fresh namespace with the boot defaults.
    pub fn new_default() -> Arc<Self> {
        Arc::new(Self {
            id: alloc_ns_id(),
            inner: IrqSafeSpinLock::new(UtsInner {
                hostname: String::from(DEFAULT_HOSTNAME),
                domainname: String::from("(none)"),
            }),
        })
    }

    /// Stable namespace id (nsfs inode in Linux).
    pub fn id(&self) -> NsId {
        self.id
    }

    /// Clone the current state into a new namespace — unshare(2)
    /// semantics for UTS are "copy on unshare", so the child sees
    /// the parent's hostname until it overwrites it.
    pub fn clone_from(other: &Self) -> Arc<Self> {
        let g = other.inner.lock();
        Arc::new(Self {
            id: alloc_ns_id(),
            inner: IrqSafeSpinLock::new(UtsInner {
                hostname: g.hostname.clone(),
                domainname: g.domainname.clone(),
            }),
        })
    }

    pub fn hostname(&self) -> String {
        self.inner.lock().hostname.clone()
    }

    pub fn domainname(&self) -> String {
        self.inner.lock().domainname.clone()
    }

    /// Replace the hostname. Caller enforces the 64-byte cap.
    pub fn set_hostname(&self, s: &str) {
        let mut g = self.inner.lock();
        g.hostname.clear();
        g.hostname.push_str(s);
    }

    /// Replace the domainname. Caller enforces the 64-byte cap.
    pub fn set_domainname(&self, s: &str) {
        let mut g = self.inner.lock();
        g.domainname.clear();
        g.domainname.push_str(s);
    }
}

// ── Net namespace ────────────────────────────────────────────────

/// Per-namespace interface view. Physical device ownership is authoritative
/// in `narf_net::iface`; this object owns the synthetic loopback description
/// and stable namespace identity used by sockets and network control planes.
#[derive(Debug)]
pub struct NetNamespace {
    id: NsId,
    inner: IrqSafeSpinLock<NetInner>,
}

#[derive(Debug, Clone)]
pub struct NetIfaceStub {
    pub name: String,
    pub mac: [u8; 6],
    pub ipv4: [u8; 4],
    pub prefix_len: u8,
}

#[derive(Debug)]
struct NetInner {
    ifaces: Vec<NetIfaceStub>,
}

impl NetNamespace {
    /// Seed a fresh netns with the standard synthetic `lo` and
    /// nothing else — matches Linux `unshare(CLONE_NEWNET)` shape
    /// where every other device must be moved in explicitly.
    pub fn new_with_loopback() -> Arc<Self> {
        let lo = NetIfaceStub {
            name: String::from("lo"),
            mac: [0u8; 6],
            ipv4: [127, 0, 0, 1],
            prefix_len: 8,
        };
        Arc::new(Self {
            id: alloc_ns_id(),
            inner: IrqSafeSpinLock::new(NetInner {
                ifaces: alloc::vec![lo],
            }),
        })
    }

    /// Stable namespace id (nsfs inode in Linux).
    pub fn id(&self) -> NsId {
        self.id
    }

    /// List interface names in this netns. Used by smoke tests and
    /// future `/proc/net/dev` plumbing.
    pub fn iface_names(&self) -> Vec<String> {
        let g = self.inner.lock();
        g.ifaces.iter().map(|i| i.name.clone()).collect()
    }

    /// Snapshot the per-iface stubs.
    pub fn ifaces(&self) -> Vec<NetIfaceStub> {
        self.inner.lock().ifaces.clone()
    }

    /// Add an iface to this netns. Returns `false` if a same-named
    /// iface already exists.
    pub fn add_iface(&self, iface: NetIfaceStub) -> bool {
        let mut g = self.inner.lock();
        if g.ifaces.iter().any(|i| i.name == iface.name) {
            return false;
        }
        g.ifaces.push(iface);
        true
    }
}

impl Drop for NetNamespace {
    fn drop(&mut self) {
        narf_net::release_network_namespace(self.id);
    }
}

// ── IPC namespace ────────────────────────────────────────────────

/// Per-namespace SysV IPC + POSIX mqueue keyspace. Today this is
/// a counter + key→id BTreeMap; the SysV IPC subsystem itself is
/// largely stubbed in NARF so we mint distinct ids per-ns and
/// leave segment storage to the follow-up that lights up shm/sem/msg
/// for real.
#[derive(Debug)]
pub struct IpcNamespace {
    id: NsId,
    next_id: AtomicU32,
    inner: IrqSafeSpinLock<IpcInner>,
}

#[derive(Debug, Default)]
struct IpcInner {
    shm: BTreeMap<u32, u32>, // key → id
    sem: BTreeMap<u32, u32>,
    msg: BTreeMap<u32, u32>,
    mq: BTreeMap<String, u32>, // POSIX mqueue name → id
}

impl IpcNamespace {
    /// Fresh namespace — id counter starts at 1 so `0` (IPC_PRIVATE
    /// in Linux) never collides with a real id.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            id: alloc_ns_id(),
            next_id: AtomicU32::new(1),
            inner: IrqSafeSpinLock::new(IpcInner::default()),
        })
    }

    /// Stable namespace id (nsfs inode in Linux).
    pub fn id(&self) -> NsId {
        self.id
    }

    fn alloc_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// `shmget(key, …)` — return the id for `key`, allocating one
    /// the first time it is seen in this namespace.
    pub fn shmget(&self, key: u32) -> u32 {
        let mut g = self.inner.lock();
        if let Some(&id) = g.shm.get(&key) {
            return id;
        }
        let id = self.alloc_id();
        g.shm.insert(key, id);
        id
    }

    pub fn semget(&self, key: u32) -> u32 {
        let mut g = self.inner.lock();
        if let Some(&id) = g.sem.get(&key) {
            return id;
        }
        let id = self.alloc_id();
        g.sem.insert(key, id);
        id
    }

    pub fn msgget(&self, key: u32) -> u32 {
        let mut g = self.inner.lock();
        if let Some(&id) = g.msg.get(&key) {
            return id;
        }
        let id = self.alloc_id();
        g.msg.insert(key, id);
        id
    }

    /// POSIX `mq_open` resolution — distinct keyspace from SysV.
    pub fn mq_open(&self, name: &str) -> u32 {
        let mut g = self.inner.lock();
        if let Some(&id) = g.mq.get(name) {
            return id;
        }
        let id = self.alloc_id();
        g.mq.insert(String::from(name), id);
        id
    }
}

// ── Per-task NS tables ───────────────────────────────────────────
//
// Each namespace lives in its own BTreeMap keyed by task id. An
// absent entry means the task shares the global / default
// namespace for that flavour. Lookups are O(log n) under the lock;
// hot paths cache the Arc.

type UtsTable = BTreeMap<u64, Arc<UtsNamespace>>;
type NetTable = BTreeMap<u64, Arc<NetNamespace>>;
type IpcTable = BTreeMap<u64, Arc<IpcNamespace>>;

static UTS_BY_TASK: IrqSafeSpinLock<Option<UtsTable>> = IrqSafeSpinLock::new(None);
static NET_BY_TASK: IrqSafeSpinLock<Option<NetTable>> = IrqSafeSpinLock::new(None);
static IPC_BY_TASK: IrqSafeSpinLock<Option<IpcTable>> = IrqSafeSpinLock::new(None);

// Global / default namespaces. Tasks without a per-task override
// read/write these.
static GLOBAL_UTS: IrqSafeSpinLock<Option<Arc<UtsNamespace>>> = IrqSafeSpinLock::new(None);

fn global_uts() -> Arc<UtsNamespace> {
    let mut g = GLOBAL_UTS.lock();
    if g.is_none() {
        *g = Some(UtsNamespace::new_default());
    }
    g.as_ref().expect("just inserted").clone()
}

fn ensure_uts_table() {
    let mut g = UTS_BY_TASK.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

fn ensure_net_table() {
    let mut g = NET_BY_TASK.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

fn ensure_ipc_table() {
    let mut g = IPC_BY_TASK.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

/// Look up the calling task's UTS namespace. Returns the global
/// fallback when the task has not unshared.
pub fn current_uts_ns(task: u64) -> Arc<UtsNamespace> {
    let g = UTS_BY_TASK.lock();
    if let Some(map) = g.as_ref() {
        if let Some(arc) = map.get(&task) {
            return arc.clone();
        }
    }
    drop(g);
    global_uts()
}

/// Like `current_uts_ns` but returns `None` if the task has no
/// explicit UTS namespace. Used by `setns(2)` to refuse joining a
/// task that still shares the global default.
pub fn uts_ns_of(task: u64) -> Option<Arc<UtsNamespace>> {
    let g = UTS_BY_TASK.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// Alias for `current_net_ns` matching the `*_ns_of` naming used by
/// setns(2) call sites.
pub fn net_ns_of(task: u64) -> Option<Arc<NetNamespace>> {
    current_net_ns(task)
}

/// Alias for `current_ipc_ns` matching the `*_ns_of` naming used by
/// setns(2) call sites.
pub fn ipc_ns_of(task: u64) -> Option<Arc<IpcNamespace>> {
    current_ipc_ns(task)
}

/// Look up the calling task's net namespace. `None` means "share
/// the global iface registry" — the caller routes through
/// `narf_net::iface::*` as before.
pub fn current_net_ns(task: u64) -> Option<Arc<NetNamespace>> {
    let g = NET_BY_TASK.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// Look up the calling task's IPC namespace. `None` means "share
/// the global SysV keyspace" — today that path is itself a stub.
pub fn current_ipc_ns(task: u64) -> Option<Arc<IpcNamespace>> {
    let g = IPC_BY_TASK.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// Install a per-task UTS namespace, cloned from whatever the task
/// currently sees. Called from `sys_unshare(CLONE_NEWUTS)`.
pub fn unshare_uts(task: u64) {
    let cur = current_uts_ns(task);
    let fresh = UtsNamespace::clone_from(&cur);
    ensure_uts_table();
    let mut g = UTS_BY_TASK.lock();
    if let Some(map) = g.as_mut() {
        map.insert(task, fresh);
    }
}

/// Install a fresh per-task net namespace (just `lo`).
pub fn unshare_net(task: u64) {
    let fresh = NetNamespace::new_with_loopback();
    ensure_net_table();
    let mut g = NET_BY_TASK.lock();
    if let Some(map) = g.as_mut() {
        map.insert(task, fresh);
    }
}

/// Install a fresh per-task IPC namespace.
pub fn unshare_ipc(task: u64) {
    let fresh = IpcNamespace::new();
    ensure_ipc_table();
    let mut g = IPC_BY_TASK.lock();
    if let Some(map) = g.as_mut() {
        map.insert(task, fresh);
    }
}

// ── setns(2) — join an existing namespace by Arc ─────────────────
//
// Linux `setns` takes an fd that names an existing namespace. Procfs and
// pidfd ioctls mint `NsFd`, then the syscall downcasts it and routes the held
// `Arc` through these shared install routines.

pub fn setns_uts(task: u64, ns: Arc<UtsNamespace>) {
    ensure_uts_table();
    let mut g = UTS_BY_TASK.lock();
    if let Some(map) = g.as_mut() {
        map.insert(task, ns);
    }
}

pub fn setns_net(task: u64, ns: Arc<NetNamespace>) {
    ensure_net_table();
    let mut g = NET_BY_TASK.lock();
    if let Some(map) = g.as_mut() {
        map.insert(task, ns);
    }
}

pub fn setns_ipc(task: u64, ns: Arc<IpcNamespace>) {
    ensure_ipc_table();
    let mut g = IPC_BY_TASK.lock();
    if let Some(map) = g.as_mut() {
        map.insert(task, ns);
    }
}

fn setns_initial_net(task: u64) {
    if let Some(map) = NET_BY_TASK.lock().as_mut() {
        map.remove(&task);
    }
}

fn setns_initial_ipc(task: u64) {
    if let Some(map) = IPC_BY_TASK.lock().as_mut() {
        map.remove(&task);
    }
}

/// Drop the task-owned references to namespaces. Namespace fds and sockets
/// retain their own `Arc`, so final teardown occurs only after those close.
pub fn release_task(task: u64) {
    if let Some(map) = UTS_BY_TASK.lock().as_mut() {
        map.remove(&task);
    }
    if let Some(map) = NET_BY_TASK.lock().as_mut() {
        map.remove(&task);
    }
    if let Some(map) = IPC_BY_TASK.lock().as_mut() {
        map.remove(&task);
    }
    if let Some(map) = USER_BY_TASK.lock().as_mut() {
        map.remove(&task);
    }
}

// ── fork(2)/clone(2) inheritance (UTS / NET / IPC / User) ─────────
//
// Mirrors Linux copy_*ns with no CLONE_NEW* flag: the child SHARES the
// parent's namespace (an extra Arc ref to the SAME ns), not a fresh
// copy. A parent still riding the global/default for a flavour has no
// per-task entry; the child is left without one too so it shares that
// same global default. CLONE_NEW* is layered on top by the caller.
pub fn inherit_into_child(parent: u64, child: u64) {
    if let Some(ns) = uts_ns_of(parent) {
        setns_uts(child, ns);
    }
    if let Some(ns) = net_ns_of(parent) {
        setns_net(child, ns);
    }
    if let Some(ns) = ipc_ns_of(parent) {
        setns_ipc(child, ns);
    }
    if let Some(ns) = user_ns_of(parent) {
        setns_user(child, ns);
    }
}

// ── User namespace (CLONE_NEWUSER) ───────────────────────────────
//
// SECURITY-CRITICAL. A user namespace carries uid/gid id-maps and a
// parent pointer. The map translates an *inner* id (what the process
// inside the ns sees) to a *host-absolute* outer id (what the kernel
// uses for DAC). The DAC funnel `crate::handlers::current_accessor`
// MUST translate a task's in-ns fsuid/fsgid to host ids through this
// map before building the `Accessor` it hands to `posix_access_ok`,
// because that function treats uid==0 as omnipotent root — and inner-0
// is host-root ONLY if the map maps inner-0 → outer-0.

/// Linux "overflow" id returned for an unmapped translation
/// (`/proc/sys/kernel/overflowuid`, default 65534 = `nobody`).
pub const OVERFLOW_ID: u32 = 65534;

/// One line of a uid_map / gid_map: a contiguous run mapping
/// `[inner_start, inner_start+count)` ↔ `[outer_start, outer_start+count)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IdMapEntry {
    pub inner_start: u32,
    pub outer_start: u32,
    pub count: u32,
}

impl IdMapEntry {
    /// Translate an inner id to its outer id if it falls in this run.
    fn inner_to_outer(&self, id: u32) -> Option<u32> {
        if id >= self.inner_start && (id - self.inner_start) < self.count {
            Some(self.outer_start + (id - self.inner_start))
        } else {
            None
        }
    }
    /// Translate an outer id to its inner id if it falls in this run.
    fn outer_to_inner(&self, id: u32) -> Option<u32> {
        if id >= self.outer_start && (id - self.outer_start) < self.count {
            Some(self.inner_start + (id - self.outer_start))
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
struct UserInner {
    uid_map: Vec<IdMapEntry>,
    gid_map: Vec<IdMapEntry>,
    /// Linux one-shot rule: uid_map/gid_map may be written exactly
    /// once. Tracked separately per map.
    uid_map_written: bool,
    gid_map_written: bool,
}

/// A user namespace. `parent` is `None` only for the initial (host)
/// namespace, which by convention maps every id to itself (identity).
#[derive(Debug)]
pub struct UserNamespace {
    id: NsId,
    /// Parent user-ns. Translation that a map doesn't cover does NOT
    /// chase the parent in this MVP (Linux does, recursively); see the
    /// deferral note on `translate_uid_to_host`.
    parent: Option<Arc<UserNamespace>>,
    /// Host-absolute uid of the task that created this ns (the
    /// owner). Linux uses it for the `CAP_*`-in-owner checks.
    owner_uid: u32,
    inner: IrqSafeSpinLock<UserInner>,
}

impl UserNamespace {
    /// The initial (host/root) user namespace: identity map for the
    /// full id range, no parent. Created lazily and shared.
    pub fn new_initial() -> Arc<Self> {
        Arc::new(Self {
            id: alloc_ns_id(),
            parent: None,
            owner_uid: 0,
            inner: IrqSafeSpinLock::new(UserInner {
                uid_map: alloc::vec![IdMapEntry {
                    inner_start: 0,
                    outer_start: 0,
                    count: u32::MAX,
                }],
                gid_map: alloc::vec![IdMapEntry {
                    inner_start: 0,
                    outer_start: 0,
                    count: u32::MAX,
                }],
                uid_map_written: true,
                gid_map_written: true,
            }),
        })
    }

    /// `unshare(CLONE_NEWUSER)` — a fresh user namespace owned by
    /// `owner_uid` (the creator's host uid), child of `parent`. The
    /// maps start EMPTY: until uid_map/gid_map is written, every id
    /// translates to the overflow id, which is the Linux behaviour and
    /// is the safe default (an unconfigured ns has no host authority).
    pub fn new_child(parent: Arc<UserNamespace>, owner_uid: u32) -> Arc<Self> {
        Arc::new(Self {
            id: alloc_ns_id(),
            parent: Some(parent),
            owner_uid,
            inner: IrqSafeSpinLock::new(UserInner::default()),
        })
    }

    pub fn id(&self) -> NsId {
        self.id
    }

    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub fn is_initial(&self) -> bool {
        self.parent.is_none()
    }

    /// Translate an inner uid to a host-absolute uid. Unmapped ids
    /// return [`OVERFLOW_ID`] — the safe default that grants no host
    /// authority. (Recursive parent translation is deferred: NARF
    /// builds shallow, single-level user namespaces today, so a
    /// uid_map entry's `outer_start` is already a host id. Nesting
    /// would require walking `parent` here.)
    pub fn translate_uid_to_host(&self, inner: u32) -> u32 {
        let g = self.inner.lock();
        for e in g.uid_map.iter() {
            if let Some(o) = e.inner_to_outer(inner) {
                return o;
            }
        }
        OVERFLOW_ID
    }

    /// Translate an inner gid to a host-absolute gid.
    pub fn translate_gid_to_host(&self, inner: u32) -> u32 {
        let g = self.inner.lock();
        for e in g.gid_map.iter() {
            if let Some(o) = e.inner_to_outer(inner) {
                return o;
            }
        }
        OVERFLOW_ID
    }

    /// Translate a host uid to the id this ns sees, or `None` if the
    /// host uid isn't mapped into this ns.
    pub fn translate_uid_from_host(&self, host: u32) -> Option<u32> {
        let g = self.inner.lock();
        g.uid_map.iter().find_map(|e| e.outer_to_inner(host))
    }

    /// Translate a host gid to the id this ns sees, or `None` if the
    /// host gid isn't mapped into this ns.
    pub fn translate_gid_from_host(&self, host: u32) -> Option<u32> {
        let g = self.inner.lock();
        g.gid_map.iter().find_map(|e| e.outer_to_inner(host))
    }

    /// True if inner uid `id` is mapped (so e.g. setuid to it is OK).
    pub fn uid_is_mapped(&self, inner: u32) -> bool {
        let g = self.inner.lock();
        g.uid_map.iter().any(|e| e.inner_to_outer(inner).is_some())
    }

    pub fn gid_is_mapped(&self, inner: u32) -> bool {
        let g = self.inner.lock();
        g.gid_map.iter().any(|e| e.inner_to_outer(inner).is_some())
    }

    /// Write the uid_map (Linux one-shot rule). Returns Err if already
    /// written or the entries are malformed.
    pub fn write_uid_map(&self, entries: Vec<IdMapEntry>) -> Result<(), ()> {
        let mut g = self.inner.lock();
        if g.uid_map_written || entries.is_empty() {
            return Err(());
        }
        g.uid_map = entries;
        g.uid_map_written = true;
        Ok(())
    }

    pub fn write_gid_map(&self, entries: Vec<IdMapEntry>) -> Result<(), ()> {
        let mut g = self.inner.lock();
        if g.gid_map_written || entries.is_empty() {
            return Err(());
        }
        g.gid_map = entries;
        g.gid_map_written = true;
        Ok(())
    }

    /// Render the uid_map / gid_map as Linux does:
    /// `      0     1000          1\n`. `is_uid` selects which map.
    pub fn render_map(&self, is_uid: bool) -> String {
        use core::fmt::Write as _;
        let g = self.inner.lock();
        let map = if is_uid { &g.uid_map } else { &g.gid_map };
        let mut s = String::new();
        for e in map.iter() {
            let _ = writeln!(
                s,
                "{:>10} {:>10} {:>10}",
                e.inner_start, e.outer_start, e.count
            );
        }
        s
    }
}

type UserTable = BTreeMap<u64, Arc<UserNamespace>>;
static USER_BY_TASK: IrqSafeSpinLock<Option<UserTable>> = IrqSafeSpinLock::new(None);
static GLOBAL_USER: IrqSafeSpinLock<Option<Arc<UserNamespace>>> = IrqSafeSpinLock::new(None);

fn global_user() -> Arc<UserNamespace> {
    let mut g = GLOBAL_USER.lock();
    if g.is_none() {
        *g = Some(UserNamespace::new_initial());
    }
    g.as_ref().expect("just inserted").clone()
}

fn ensure_user_table() {
    let mut g = USER_BY_TASK.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

/// The user namespace the task belongs to (initial/host if none).
pub fn current_user_ns(task: u64) -> Arc<UserNamespace> {
    let g = USER_BY_TASK.lock();
    if let Some(map) = g.as_ref() {
        if let Some(arc) = map.get(&task) {
            return arc.clone();
        }
    }
    drop(g);
    global_user()
}

/// The task's explicit user-ns, or None when it rides the host ns.
pub fn user_ns_of(task: u64) -> Option<Arc<UserNamespace>> {
    let g = USER_BY_TASK.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// `unshare(CLONE_NEWUSER)` — mint a child user-ns owned by the
/// caller's host uid and install it. Returns the new ns.
pub fn unshare_user(task: u64, owner_host_uid: u32) -> Arc<UserNamespace> {
    let parent = current_user_ns(task);
    let fresh = UserNamespace::new_child(parent, owner_host_uid);
    ensure_user_table();
    let mut g = USER_BY_TASK.lock();
    if let Some(map) = g.as_mut() {
        map.insert(task, fresh.clone());
    }
    fresh
}

/// Install a user-ns for `task` (setns / inheritance).
pub fn setns_user(task: u64, ns: Arc<UserNamespace>) {
    ensure_user_table();
    let mut g = USER_BY_TASK.lock();
    if let Some(map) = g.as_mut() {
        map.insert(task, ns);
    }
}

// ── ns-fd: a FileOps that HOLDS a namespace Arc ──────────────────
//
// Opening `/proc/<pid>/ns/<flavour>` mints one of these. Holding the
// namespace `Arc` keeps the namespace alive after the originating
// task exits (Linux: an open ns-fd pins the namespace). `setns(fd,
// nstype)` downcasts the fd's FileOps via `FileOps::as_any` and
// installs the held namespace.

/// The namespace an [`NsFd`] holds. One variant per flavour; each
/// keeps the flavour's `Arc` so the namespace outlives its creator.
#[derive(Clone, Debug)]
pub enum HeldNs {
    Uts(Arc<UtsNamespace>),
    Net(Arc<NetNamespace>),
    NetGlobal(NsId),
    Ipc(Arc<IpcNamespace>),
    IpcGlobal(NsId),
    Pid(Arc<crate::pid_ns::PidNamespace>),
    PidGlobal(NsId),
    Mnt(Arc<narf_filesystem::MountNamespace>),
    /// The shared initial mount namespace is backed directly by the global
    /// mount registry, so it has identity but no snapshot `MountNamespace`.
    MntGlobal(NsId),
    #[cfg(feature = "cgroup")]
    Cgroup(Arc<narf_filesystem::cgroupfs::CgroupNamespace>),
    User(Arc<UserNamespace>),
}

impl HeldNs {
    pub fn flavour(&self) -> NsFlavour {
        match self {
            HeldNs::Uts(_) => NsFlavour::Uts,
            HeldNs::Net(_) => NsFlavour::Net,
            HeldNs::NetGlobal(_) => NsFlavour::Net,
            HeldNs::Ipc(_) => NsFlavour::Ipc,
            HeldNs::IpcGlobal(_) => NsFlavour::Ipc,
            HeldNs::Pid(_) => NsFlavour::Pid,
            HeldNs::PidGlobal(_) => NsFlavour::Pid,
            HeldNs::Mnt(_) => NsFlavour::Mnt,
            HeldNs::MntGlobal(_) => NsFlavour::Mnt,
            #[cfg(feature = "cgroup")]
            HeldNs::Cgroup(_) => NsFlavour::Cgroup,
            HeldNs::User(_) => NsFlavour::User,
        }
    }
    pub fn id(&self) -> NsId {
        match self {
            HeldNs::Uts(n) => n.id(),
            HeldNs::Net(n) => n.id(),
            HeldNs::NetGlobal(id) => *id,
            HeldNs::Ipc(n) => n.id(),
            HeldNs::IpcGlobal(id) => *id,
            HeldNs::Pid(n) => n.id(),
            HeldNs::PidGlobal(id) => *id,
            HeldNs::Mnt(n) => n.id(),
            HeldNs::MntGlobal(id) => *id,
            #[cfg(feature = "cgroup")]
            HeldNs::Cgroup(n) => n.id(),
            HeldNs::User(n) => n.id(),
        }
    }
}

/// A namespace file descriptor. `Arc<NsFd>` is installed in the fd
/// table; `setns` recovers it through `FileOps::as_any`.
#[derive(Debug)]
pub struct NsFd {
    held: HeldNs,
}

impl NsFd {
    pub fn new(held: HeldNs) -> Arc<Self> {
        Arc::new(Self { held })
    }
    pub fn held(&self) -> &HeldNs {
        &self.held
    }
    /// `readlink` text Linux renders for `/proc/<pid>/ns/<flavour>`:
    /// e.g. `uts:[4026531838]`.
    pub fn link_text(&self) -> String {
        let mut s = String::new();
        use core::fmt::Write as _;
        let _ = write!(s, "{}:[{}]", self.held.flavour().tag(), self.held.id());
        s
    }
}

impl narf_filesystem::FileOps for NsFd {
    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        // An ns-fd is not a readable byte stream — it exists only to be
        // passed to setns(2). Linux read() on it returns EINVAL.
        Box::pin(async move { Err(narf_filesystem::FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        Box::pin(async move { Err(narf_filesystem::FsError::ReadOnly) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        // Report the ns id in `size` so `st_ino` (synthesised from
        // size in the stat syscall) carries the namespace identity —
        // two fds naming the same ns then stat() equal.
        narf_filesystem::Stat {
            size: self.held.id(),
            blocks: 0,
            mode: narf_filesystem::Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o444,
            },
            mtime_cycles: 0,
        }
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// Mint an ns-fd for `task`'s current namespace of `flavour`. Returns
/// `None` for flavours NARF doesn't track per-task yet for `task`
/// (e.g. a mount-ns the task hasn't unshared). Used by the
/// `/proc/<pid>/ns/<flavour>` open path.
pub fn ns_fd_for(task: u64, flavour: NsFlavour) -> Option<Arc<NsFd>> {
    let held = match flavour {
        NsFlavour::Uts => HeldNs::Uts(current_uts_ns(task)),
        NsFlavour::Net => current_net_ns(task)
            .map(HeldNs::Net)
            .unwrap_or_else(|| HeldNs::NetGlobal(initial_ns_id(&INITIAL_NET_NS_ID))),
        NsFlavour::Ipc => current_ipc_ns(task)
            .map(HeldNs::Ipc)
            .unwrap_or_else(|| HeldNs::IpcGlobal(initial_ns_id(&INITIAL_IPC_NS_ID))),
        NsFlavour::Pid => crate::pid_ns::ns_of(task)
            .map(HeldNs::Pid)
            .unwrap_or_else(|| HeldNs::PidGlobal(initial_ns_id(&INITIAL_PID_NS_ID))),
        NsFlavour::User => HeldNs::User(current_user_ns(task)),
        // Mount and cgroup namespace ownership spans the handlers/filesystem
        // layers; the handlers' namespace_fd_for_task bridge mints those.
        NsFlavour::Mnt | NsFlavour::Cgroup => return None,
    };
    Some(NsFd::new(held))
}

/// Install the namespace an ns-fd holds onto `caller`. The bridge
/// from `setns(fd, nstype)` once the fd has been downcast to `NsFd`.
/// `outer_pid` is the caller's outer pid (needed to bind into a PID
/// namespace). Returns `false` if `nstype` is non-zero and doesn't
/// match the held flavour.
pub fn install_held_ns(caller: u64, outer_pid: u64, held: &HeldNs, nstype: u64) -> bool {
    if nstype != 0 && (nstype & held.flavour().clone_flag()) == 0 {
        return false;
    }
    match held {
        HeldNs::Uts(n) => setns_uts(caller, n.clone()),
        HeldNs::Net(n) => setns_net(caller, n.clone()),
        HeldNs::NetGlobal(_) => setns_initial_net(caller),
        HeldNs::Ipc(n) => setns_ipc(caller, n.clone()),
        HeldNs::IpcGlobal(_) => setns_initial_ipc(caller),
        HeldNs::User(n) => setns_user(caller, n.clone()),
        HeldNs::Pid(n) => {
            let _ = crate::pid_ns::attach_to_ns(caller, outer_pid, n.clone());
        }
        HeldNs::PidGlobal(_) => crate::pid_ns::clear_ns(caller),
        HeldNs::Mnt(_) => {
            // Mount-ns install lives in the handlers layer
            // (install_mount_namespace); the caller handles it.
            return false;
        }
        HeldNs::MntGlobal(_) => return false,
        #[cfg(feature = "cgroup")]
        HeldNs::Cgroup(n) => {
            narf_filesystem::cgroupfs::install_cgroup_namespace(outer_pid, n.clone());
        }
    }
    true
}

// ── Test hooks ───────────────────────────────────────────────────

#[doc(hidden)]
pub fn __test_reset_all() {
    *UTS_BY_TASK.lock() = None;
    *NET_BY_TASK.lock() = None;
    *IPC_BY_TASK.lock() = None;
    *USER_BY_TASK.lock() = None;
    *GLOBAL_UTS.lock() = None;
    *GLOBAL_USER.lock() = None;
}
