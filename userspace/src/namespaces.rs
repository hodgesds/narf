//! Wave-72 — per-task Linux-style namespaces beyond CLONE_NEWNS.
//!
//! Three more namespace flavours stack on top of the Wave-67
//! MountNamespace work in `narf_filesystem`:
//!
//!   * `UtsNamespace`  — CLONE_NEWUTS (0x04000000). Per-ns
//!     hostname + domainname; uname(2) and {get,set}hostname
//!     read/write namespace-local fields.
//!   * `NetNamespace`  — CLONE_NEWNET (0x40000000). Per-ns iface
//!     table seeded with a synthetic `lo`. The global
//!     `net::iface::*` registry remains the default view; only
//!     tasks that have called unshare(CLONE_NEWNET) consult the
//!     per-ns list. The deep refactor that threads NS through
//!     every iface call site is deferred; today we install the
//!     storage and an opt-in lookup.
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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Linux clone(2) namespace flags we honour beyond CLONE_NEWNS ────

/// `CLONE_NEWUTS` (Linux) — fresh UTS namespace (hostname +
/// domainname).
pub const CLONE_NEWUTS: u64 = 0x0400_0000;

/// `CLONE_NEWIPC` (Linux) — fresh SysV/POSIX IPC namespace.
pub const CLONE_NEWIPC: u64 = 0x0800_0000;

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
            inner: IrqSafeSpinLock::new(UtsInner {
                hostname: String::from(DEFAULT_HOSTNAME),
                domainname: String::from("(none)"),
            }),
        })
    }

    /// Clone the current state into a new namespace — unshare(2)
    /// semantics for UTS are "copy on unshare", so the child sees
    /// the parent's hostname until it overwrites it.
    pub fn clone_from(other: &Self) -> Arc<Self> {
        let g = other.inner.lock();
        Arc::new(Self {
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

/// Per-namespace interface view. The global `narf_net::iface`
/// registry remains the default; only tasks that have
/// `unshare(CLONE_NEWNET)`'d consult this table. The deep refactor
/// that threads NS through every `iface::send`/`iface::lookup` call
/// site is deferred — the storage lands here so the syscall surface
/// is observable.
#[derive(Debug)]
pub struct NetNamespace {
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
            inner: IrqSafeSpinLock::new(NetInner {
                ifaces: alloc::vec![lo],
            }),
        })
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

// ── IPC namespace ────────────────────────────────────────────────

/// Per-namespace SysV IPC + POSIX mqueue keyspace. Today this is
/// a counter + key→id BTreeMap; the SysV IPC subsystem itself is
/// largely stubbed in NARF so we mint distinct ids per-ns and
/// leave segment storage to the follow-up that lights up shm/sem/msg
/// for real.
#[derive(Debug)]
pub struct IpcNamespace {
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
            next_id: AtomicU32::new(1),
            inner: IrqSafeSpinLock::new(IpcInner::default()),
        })
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
// Linux `setns` takes an fd that names an existing namespace; NARF
// has no namespace-fd plumbing yet (it lands with /proc/<pid>/ns/*
// in a later wave). Until then, these entrypoints accept an
// `Arc<…>` directly so tests and the future fd path share one
// install routine.

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

// ── Test hooks ───────────────────────────────────────────────────

#[doc(hidden)]
pub fn __test_reset_all() {
    *UTS_BY_TASK.lock() = None;
    *NET_BY_TASK.lock() = None;
    *IPC_BY_TASK.lock() = None;
    *GLOBAL_UTS.lock() = None;
}
