//! `SysFs` — Linux-shaped `/sys` kobject hierarchy.
//!
//! Implements the kobject tree that gives userspace a structured view of
//! the kernel's device/driver model.  Mounts at `/sys`.
//!
//! Linux references:
//!   `lib/kobject.c`               — kobject lifecycle, path helpers (6.9)
//!   `lib/kobject_uevent.c`        — uevent emit path (6.9)
//!   `fs/sysfs/`                   — VFS glue
//!   `Documentation/filesystems/sysfs.rst`
//!
//! # Standard subtrees
//!
//! ```text
//! /sys/
//!   class/
//!     block/<dev>/  ← one per registered block device
//!     input/<eventN>/ ← one per registered input device
//!     net/<iface>/  ← one per registered net interface
//!     tty/          ← stub
//!   devices/        ← stub (PCI topology: Stage 4+)
//!   block/          ← flat view of block devices
//!   bus/
//!     pci/
//!       devices/    ← stub
//!   firmware/
//!     acpi/         ← stub (ACPI tables: Stage 4+)
//!   kernel/
//!     uevent_seqnum ← current seqnum
//! ```
//!
//! # Design notes
//!
//! The kobject tree is represented as `Arc<Kobject>` nodes in a
//! parent→children `Vec`.  Attributes are `fn() -> String` function
//! pointers stored by `&'static str` key in a `BTreeMap`.
//!
//! The FS side (`SysFs` / `SysRoot` / `SysKobjDir`) wraps the tree
//! so that `lookup`/`iter` reflect the live kobject graph.  Attr
//! files are wrapped in `SysAttrFile` which calls the show-fn on
//! every read (lazy generation).
//!
//! Net-interface population uses a hook installed by the net subsystem
//! (see `install_net_snapshot_hook`) so this crate does not take a
//! direct dependency on `narf-net`.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::uevent::{emit, UeventAction};
use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

// ── Attr function types ───────────────────────────────────────────────

/// Attribute show function: called on every read, returns a `String`.
/// Using `Arc<dyn Fn>` rather than a bare `fn()` so that drivers can
/// capture device-specific state (e.g. capacity from a block device)
/// without needing a global registry.
/// Linux ref: `struct attribute / show` (include/linux/sysfs.h:24).
pub type AttrShow = Arc<dyn Fn() -> String + Send + Sync>;

/// Attribute store (write) function for writable sysfs files.
/// Called with the raw user-supplied bytes; returns
/// `Err(FsError::InvalidData)` for malformed input.
/// Linux ref: `struct attribute / store` (include/linux/sysfs.h:26).
pub type AttrStore = Arc<dyn Fn(&[u8]) -> Result<(), crate::FsError> + Send + Sync>;

/// Binary-attribute read function: called with `(offset, buf)`.
/// Returns the number of bytes written.
/// Linux ref: `struct bin_attribute / read` (include/linux/sysfs.h:68).
pub type BinAttrRead = fn(offset: usize, buf: &mut [u8]) -> usize;

// ── Net interface snapshot hook ───────────────────────────────────────

/// Snapshot of one net interface's key fields.  Returned by the hook
/// so sysfs doesn't need to take a hard dep on `narf-net`.
#[derive(Clone, Debug)]
pub struct NetIfaceInfo {
    pub name: String,
    pub mac: [u8; 6],
    pub mtu: u32,
    pub link_up: bool,
}

/// Hook type: returns a Vec of `NetIfaceInfo` for all registered interfaces.
type NetSnapshotFn = fn() -> Vec<NetIfaceInfo>;

static NET_SNAPSHOT_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the net-interface snapshot hook.  Called by the net subsystem
/// at boot before sysfs `populate_all()` runs.
pub fn install_net_snapshot_hook(f: NetSnapshotFn) {
    NET_SNAPSHOT_HOOK.store(f as usize, Ordering::Release);
}

fn net_snapshots() -> Vec<NetIfaceInfo> {
    let ptr = NET_SNAPSHOT_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return Vec::new();
    }
    // SAFETY: ptr was stored via NET_SNAPSHOT_HOOK which only accepts function pointers
    // matching the NetSnapshotFn signature; non-zero check above ensures it is valid.
    let f: NetSnapshotFn = unsafe { core::mem::transmute(ptr) };
    f()
}

// ── Kobject ───────────────────────────────────────────────────────────

/// One node in the kobject hierarchy.
///
/// Linux ref: `struct kobject` (include/linux/kobject.h:64 in 6.9).
pub struct Kobject {
    /// Node name (single path component, no slashes).
    name: String,
    /// Strong reference to parent so we can compute the full path.
    /// `None` for the tree root.
    parent: Option<Arc<Kobject>>,
    /// Direct children.
    children: IrqSafeSpinLock<Vec<Arc<Kobject>>>,
    /// Text attribute files (`show` callbacks).
    attrs: IrqSafeSpinLock<BTreeMap<&'static str, AttrShow>>,
    /// Write callbacks for read-write attributes.
    /// Linux ref: `struct attribute / store` (include/linux/sysfs.h:26).
    store_attrs: IrqSafeSpinLock<BTreeMap<&'static str, AttrStore>>,
    /// Binary attribute files.
    bin_attrs: IrqSafeSpinLock<BTreeMap<&'static str, BinAttrRead>>,
}

impl fmt::Debug for Kobject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kobject")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Kobject {
    /// Create a root kobject (no parent).
    pub fn new_root(name: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            parent: None,
            children: IrqSafeSpinLock::new(Vec::new()),
            attrs: IrqSafeSpinLock::new(BTreeMap::new()),
            store_attrs: IrqSafeSpinLock::new(BTreeMap::new()),
            bin_attrs: IrqSafeSpinLock::new(BTreeMap::new()),
        })
    }

    /// Create a child kobject attached to `parent`.
    /// Linux ref: `kobject_add_internal` (lib/kobject.c:193).
    pub fn new_child(parent: Arc<Kobject>, name: impl Into<String>) -> Arc<Self> {
        let child = Arc::new(Self {
            name: name.into(),
            parent: Some(parent.clone()),
            children: IrqSafeSpinLock::new(Vec::new()),
            attrs: IrqSafeSpinLock::new(BTreeMap::new()),
            store_attrs: IrqSafeSpinLock::new(BTreeMap::new()),
            bin_attrs: IrqSafeSpinLock::new(BTreeMap::new()),
        });
        parent.children.lock().push(child.clone());
        child
    }

    /// Return the name of this kobject.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Compute the absolute sysfs path for this kobject (e.g.
    /// `/sys/class/net/eth0`).
    /// Linux ref: `kobject_get_path` (lib/kobject.c:110).
    pub fn path(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push(self.name.clone());
        let mut p_opt = self.parent.clone();
        while let Some(par) = p_opt {
            parts.push(par.name.clone());
            p_opt = par.parent.clone();
        }
        parts.reverse();
        let mut path = String::from("/sys");
        for part in &parts {
            path.push('/');
            path.push_str(part);
        }
        path
    }

    /// List child names.
    pub fn child_names(&self) -> Vec<String> {
        self.children
            .lock()
            .iter()
            .map(|c| c.name.clone())
            .collect()
    }

    /// Look up a child by name.
    pub fn get_child(&self, name: &str) -> Option<Arc<Kobject>> {
        self.children
            .lock()
            .iter()
            .find(|c| c.name == name)
            .cloned()
    }

    /// List text attribute names.
    pub fn attr_names(&self) -> Vec<&'static str> {
        self.attrs.lock().keys().copied().collect()
    }

    /// Call the show function for `name` and return its output.
    pub fn attr_show(&self, name: &str) -> Option<String> {
        let show = self.attrs.lock().get(name)?.clone();
        Some(show())
    }

    /// Call the store function for `name` with raw user bytes.
    /// Returns `None` if `name` has no store callback (attr is read-only).
    /// Linux ref: `sysfs_kf_write` (fs/sysfs/file.c:160).
    pub fn attr_store(&self, name: &str, data: &[u8]) -> Option<Result<(), crate::FsError>> {
        let store = self.store_attrs.lock().get(name)?.clone();
        Some(store(data))
    }

    /// True if `name` has a registered store callback (i.e. is writable).
    pub fn attr_is_writable(&self, name: &str) -> bool {
        self.store_attrs.lock().contains_key(name)
    }

    /// Recover the `&'static str` key matching `name` by scanning the
    /// attrs BTreeMap.  Used by VFS lookup so that any attr registered
    /// via `kobject_add_attr` / `kobject_add_writable_attr` is
    /// automatically visible in the VFS without a separate static list.
    pub fn find_attr_key(&self, name: &str) -> Option<&'static str> {
        self.attrs.lock().keys().copied().find(|&k| k == name)
    }

    /// Call the bin-attr read function for `name`.
    pub fn bin_attr_read(&self, name: &str, offset: usize, buf: &mut [u8]) -> Option<usize> {
        let read = *self.bin_attrs.lock().get(name)?;
        Some(read(offset, buf))
    }

    /// True if `name` is a registered text or binary attribute.
    pub fn has_attr(&self, name: &str) -> bool {
        self.attrs.lock().contains_key(name) || self.bin_attrs.lock().contains_key(name)
    }
}

// ── Kobject global registry ───────────────────────────────────────────

/// The single sysfs root kobject.
/// Linux: `sysfs_root_kobj` (fs/sysfs/mount.c:43).
static SYSFS_ROOT: IrqSafeSpinLock<Option<Arc<Kobject>>> = IrqSafeSpinLock::new(None);

fn ensure_root() -> Arc<Kobject> {
    let mut g = SYSFS_ROOT.lock();
    if let Some(r) = g.as_ref() {
        return r.clone();
    }
    let root = Kobject::new_root("sys");
    *g = Some(root.clone());
    root
}

fn get_root() -> Arc<Kobject> {
    ensure_root()
}

/// Return the sysfs root kobject. Used by tests to navigate the tree
/// after `populate_*` calls.
///
/// Returns a clone of the root `Arc<Kobject>`; the root is created
/// lazily on first call (same as `ensure_root`).
pub fn sysfs_root() -> Arc<Kobject> {
    get_root()
}

// ── Driver registration API ───────────────────────────────────────────

/// Register (or return existing) `/sys/class/<class>/` kobject.
/// Linux ref: `class_register` (drivers/base/class.c:219).
pub fn class_register(class: &'static str) -> Arc<Kobject> {
    let root = get_root();
    let class_dir = get_or_create_child(&root, "class");
    get_or_create_child(&class_dir, class)
}

/// Register a device under `/sys/class/<class>/<name>/`.
/// Returns the new (or existing) device kobject.
/// Linux ref: `device_register` → `kobject_add` (drivers/base/core.c:3549).
pub fn class_device_register(class: Arc<Kobject>, name: &str) -> Arc<Kobject> {
    get_or_create_child(&class, name)
}

/// Add a text attribute to a kobject.
/// Linux ref: `sysfs_create_file` → `kernfs_create_file_ns`
///            (fs/sysfs/file.c:413).
///
/// Accepts either a function pointer (`fn() -> String`) or a capturing
/// closure.  Both are wrapped in an `Arc` for storage.
pub fn kobject_add_attr<F>(kobj: &Kobject, name: &'static str, show: F)
where
    F: Fn() -> String + Send + Sync + 'static,
{
    kobj.attrs.lock().insert(name, Arc::new(show));
}

/// Add a binary attribute to a kobject.
/// Linux ref: `sysfs_create_bin_file` (fs/sysfs/bin.c:209).
pub fn kobject_add_bin_attr(kobj: &Kobject, name: &'static str, read: BinAttrRead) {
    kobj.bin_attrs.lock().insert(name, read);
}

/// Add a read-write text attribute (show + store) to a kobject.
///
/// `show` is called on every `read()`.  `store` is called on `write()`
/// and receives the raw user-supplied bytes; returns
/// `Err(FsError::InvalidData)` for malformed input.
///
/// Linux ref: `struct attribute` with both `.show` and `.store`
/// pointers set (`include/linux/sysfs.h:24-26`).  Examples:
/// `cur_state_store` at `drivers/thermal/thermal_sysfs.c:533`,
/// `brightness_store` at `drivers/leds/led-class.c`.
pub fn kobject_add_writable_attr<F, G>(kobj: &Kobject, name: &'static str, show: F, store: G)
where
    F: Fn() -> String + Send + Sync + 'static,
    G: Fn(&[u8]) -> Result<(), crate::FsError> + Send + Sync + 'static,
{
    kobj.attrs.lock().insert(name, Arc::new(show));
    kobj.store_attrs.lock().insert(name, Arc::new(store));
}

/// Emit a uevent for `kobj` with `action`.
/// Linux ref: `kobject_uevent` (lib/kobject_uevent.c:639).
pub fn kobject_emit_uevent(kobj: &Kobject, action: UeventAction) {
    let devpath = kobj.path();
    // subsystem = the class parent's name, or "kernel" fallback.
    // Linux uses kobject's kset name here; we use the parent name.
    let subsystem = kobj
        .parent
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "kernel".to_string());
    emit(action, devpath, subsystem);
}

// ── Internal helpers ──────────────────────────────────────────────────

fn get_or_create_child(parent: &Arc<Kobject>, name: &str) -> Arc<Kobject> {
    if let Some(c) = parent.get_child(name) {
        return c;
    }
    Kobject::new_child(parent.clone(), name)
}

// ── Auto-population ───────────────────────────────────────────────────

/// Populate `/sys/class/block/<name>/` for every registered block device.
/// Also registers under `/sys/block/<name>/` (flat view).
/// Linux ref: `blk_register_queue` (block/blk-sysfs.c:852).
pub fn populate_block_class() {
    let root = get_root();
    let class_block = {
        let class_dir = get_or_create_child(&root, "class");
        get_or_create_child(&class_dir, "block")
    };
    let sys_block = get_or_create_child(&root, "block");

    for dev in narf_block::block_devices() {
        let name: &'static str = dev.name;
        let capacity = dev.dev.capacity();
        let lba_size = dev.dev.lba_size();

        // /sys/class/block/<name>/
        let kobj = class_device_register(class_block.clone(), name);
        kobject_add_attr(&kobj, "size", move || {
            format!("{}\n", capacity * (lba_size as u64))
        });
        kobject_add_attr(&kobj, "removable", || "0\n".to_string());
        kobject_add_attr(&kobj, "queue/scheduler", || "none\n".to_string());

        // /sys/block/<name>/ — flat view
        let flat = get_or_create_child(&sys_block, name);
        kobject_add_attr(&flat, "size", move || {
            format!("{}\n", capacity * (lba_size as u64))
        });
        kobject_add_attr(&flat, "removable", || "0\n".to_string());
    }
}

/// Populate `/sys/class/net/<iface>/` for every registered net interface.
/// Linux ref: `netdev_register_kobject` (net/core/net-sysfs.c:1814).
///
/// The net-interface data comes from the hook installed via
/// `install_net_snapshot_hook` — avoids a hard dep on `narf-net`.
pub fn populate_net_class() {
    let root = get_root();
    let class_net = {
        let class_dir = get_or_create_child(&root, "class");
        get_or_create_child(&class_dir, "net")
    };

    for info in net_snapshots() {
        let name_owned = info.name.clone();
        let kobj = class_device_register(class_net.clone(), &name_owned);
        let mtu = info.mtu;
        let mac = info.mac;
        let link_up = info.link_up;
        kobject_add_attr(&kobj, "mtu", move || format!("{}\n", mtu));
        kobject_add_attr(&kobj, "address", move || {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            )
        });
        kobject_add_attr(&kobj, "operstate", move || {
            if link_up {
                "up\n".to_string()
            } else {
                "down\n".to_string()
            }
        });
    }
}

/// Populate `/sys/class/input/event<N>/` for up to `n` input device slots.
/// Linux ref: `evdev_connect` (drivers/input/evdev.c:1306).
///
/// `narf-input` has a global `EventRing` but no per-device registry with
/// stable names.  We expose stubs for slots 0..n.
pub fn populate_input_class(n: usize) {
    let root = get_root();
    let class_dir = get_or_create_child(&root, "class");
    let class_input = get_or_create_child(&class_dir, "input");

    for i in 0..n {
        let slot_name = format!("event{}", i);
        let kobj = class_device_register(class_input.clone(), &slot_name);
        let idx = i as u64;
        kobject_add_attr(&kobj, "name", move || format!("input{}\n", idx));
        kobject_add_attr(&kobj, "capabilities/key", || "0\n".to_string());
        kobject_add_attr(&kobj, "capabilities/rel", || "0\n".to_string());
    }
}

/// Populate `/sys/kernel/` with standard kernel-global files.
/// Linux ref: `kernel_kobj` (lib/kobject.c:817).
pub fn populate_kernel_dir() {
    let root = get_root();
    let kernel = get_or_create_child(&root, "kernel");
    kobject_add_attr(&kernel, "uevent_seqnum", crate::uevent::gen_uevent_seqnum);
}

/// Call all `populate_*` functions.  Invoked from the sysfs initcall.
pub fn populate_all() {
    populate_block_class();
    populate_net_class();
    populate_kernel_dir();
    // Stub class directories expected by userspace tooling.
    let root = get_root();
    let class_dir = get_or_create_child(&root, "class");
    get_or_create_child(&class_dir, "tty");
    // Stub top-level dirs.
    get_or_create_child(&root, "devices");
    let bus = get_or_create_child(&root, "bus");
    let pci = get_or_create_child(&bus, "pci");
    get_or_create_child(&pci, "devices");
    let firmware = get_or_create_child(&root, "firmware");
    get_or_create_child(&firmware, "acpi");
}

// ── SysFs FsInstance ─────────────────────────────────────────────────

/// The sysfs `FsInstance`.  Mount at `/sys`.
#[derive(Debug)]
pub struct SysFs;

impl Default for SysFs {
    fn default() -> Self {
        Self::new()
    }
}

impl SysFs {
    pub fn new() -> Self {
        SysFs
    }
}

impl FsInstance for SysFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(SysRoot)
    }
    fn name(&self) -> &str {
        "sysfs"
    }
}

// ── VFS nodes ─────────────────────────────────────────────────────────

/// The `/sys` root directory: delegates to the root Kobject.
#[derive(Debug)]
struct SysRoot;

impl DirOps for SysRoot {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let kobj = get_root();
        // Text attrs: use find_attr_key so any dynamically-registered attr
        // is visible without a separate static allowlist.
        if let Some(attr_s) = kobj.find_attr_key(name) {
            return Some(Arc::new(SysAttrFile {
                kobj: kobj.clone(),
                attr_name: attr_s,
            }));
        }
        // Sub-kobjects look like directories
        if kobj.get_child(name).is_some() {
            return Some(Arc::new(SysDirMarker));
        }
        None
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        get_root()
            .get_child(name)
            .map(|child| Arc::new(SysKobjDir { kobj: child }) as Arc<dyn DirOps>)
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        let root = get_root();
        let names = root.child_names();
        let entries: Vec<DirEntry> = names
            .into_iter()
            .map(|n| {
                let leaked: &'static str = Box::leak(n.into_boxed_str());
                DirEntry {
                    name: leaked,
                    file_type: FileType::Dir,
                }
            })
            .collect();
        Box::new(entries.into_iter())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        get_root()
            .child_names()
            .into_iter()
            .skip(cursor)
            .take(max)
            .map(|n| (n, FileType::Dir))
            .collect()
    }
}

/// A directory that mirrors a `Kobject` node's children + attributes.
#[derive(Debug, Clone)]
pub struct SysKobjDir {
    pub kobj: Arc<Kobject>,
}

impl DirOps for SysKobjDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Text attrs: use find_attr_key so any dynamically-registered attr
        // (backlight, leds, hwmon, etc.) is visible without a static list.
        if let Some(attr_s) = self.kobj.find_attr_key(name) {
            return Some(Arc::new(SysAttrFile {
                kobj: self.kobj.clone(),
                attr_name: attr_s,
            }));
        }
        // Child dirs look like files so resolve() can stat them
        if self.kobj.get_child(name).is_some() {
            return Some(Arc::new(SysDirMarker));
        }
        None
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        self.kobj
            .get_child(name)
            .map(|child| Arc::new(SysKobjDir { kobj: child }) as Arc<dyn DirOps>)
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        let child_names = self.kobj.child_names();
        let attr_names = self.kobj.attr_names();
        let mut entries: Vec<DirEntry> = Vec::new();
        for n in child_names {
            let leaked: &'static str = Box::leak(n.into_boxed_str());
            entries.push(DirEntry {
                name: leaked,
                file_type: FileType::Dir,
            });
        }
        for n in attr_names {
            entries.push(DirEntry {
                name: n,
                file_type: FileType::File,
            });
        }
        Box::new(entries.into_iter())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let child_names = self.kobj.child_names();
        let attr_names = self.kobj.attr_names();
        let mut all: Vec<(String, FileType)> = Vec::new();
        for n in child_names {
            all.push((n, FileType::Dir));
        }
        for n in attr_names {
            all.push((n.to_string(), FileType::File));
        }
        all.into_iter().skip(cursor).take(max).collect()
    }
}

/// Marker returned by `lookup` for a child that is a directory.
/// `stat()` reports `Dir` so `resolve()` knows to descend.
#[derive(Debug)]
struct SysDirMarker;

impl FileOps for SysDirMarker {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::DIR_RO,
            mtime_cycles: 0,
        }
    }
}

/// A text attribute file: read calls the show-fn on demand;
/// write calls the store-fn if present, else returns `ReadOnly`.
#[derive(Clone)]
struct SysAttrFile {
    kobj: Arc<Kobject>,
    /// The key into `kobj.attrs`; must be `&'static str` because it
    /// is stored as such in the `BTreeMap`.
    attr_name: &'static str,
}

impl fmt::Debug for SysAttrFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SysAttrFile")
            .field("attr", &self.attr_name)
            .finish_non_exhaustive()
    }
}

impl FileOps for SysAttrFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let content = self.kobj.attr_show(self.attr_name).unwrap_or_default();
        Box::pin(async move {
            let bytes = content.as_bytes();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(0);
            }
            let slice = &bytes[start..];
            let n = slice.len().min(buf.len());
            buf[..n].copy_from_slice(&slice[..n]);
            Ok(n)
        })
    }

    /// Write to a sysfs attribute file.
    ///
    /// Delegates to the store callback registered via
    /// `kobject_add_writable_attr`.  Returns `FsError::ReadOnly` for
    /// read-only attributes (no store callback registered).
    /// Linux ref: `sysfs_kf_write` (fs/sysfs/file.c:160).
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        match self.kobj.attr_store(self.attr_name, buf) {
            Some(Ok(())) => {
                let n = buf.len();
                Box::pin(async move { Ok(n) })
            }
            Some(Err(e)) => Box::pin(async move { Err(e) }),
            None => Box::pin(async move { Err(FsError::ReadOnly) }),
        }
    }

    fn stat(&self) -> Stat {
        let is_writable = self.kobj.attr_is_writable(self.attr_name);
        let size = self
            .kobj
            .attr_show(self.attr_name)
            .map(|s| s.len() as u64)
            .unwrap_or(0);
        Stat {
            size,
            blocks: 0,
            mode: if is_writable {
                Mode::FILE_RW
            } else {
                Mode::FILE_RO
            },
            mtime_cycles: 0,
        }
    }
}

// ── Default mount helper ──────────────────────────────────────────────

/// Mount sysfs at `/sys` and populate standard subtrees.
/// Called from the `procfs-mount` initcall (replaces the old empty MemFs).
pub fn mount_sysfs() {
    use crate::{bootstrap_mount_authority, registry};
    let auth = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/sys", SysFs::new());
    populate_all();
}

// ── Reset helper for tests ────────────────────────────────────────────

/// Reset global sysfs state for test isolation.  NOT for production.
#[doc(hidden)]
pub fn __reset_for_test() {
    *SYSFS_ROOT.lock() = None;
}
