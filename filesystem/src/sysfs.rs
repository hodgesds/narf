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

use crate::uevent::UeventAction;
use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

// ── NUMA topology weak hooks ──────────────────────────────────────────
//
// `/sys/devices/system/node/` needs the SRAT/SLIT topology, but taking a
// direct `narf-acpi` dependency here grows the kernel image just enough
// to tip lld's orphan-section placement (the multi-MB DWARF `.debug_*`
// sections then collide with `.boot`'s file range at link time). The
// kernel binary (`narf-frame`) — which links narf-acpi anyway — provides
// these `#[no_mangle]` shims; host unit-test builds that exercise sysfs
// directly fall back to the single-node defaults below.
extern "Rust" {
    fn narf_numa_node_count() -> u32;
    fn narf_node_distance(from: u32, to: u32) -> u32;
    fn narf_cpu_node_opt(cpu: u32) -> u32;
}

#[inline]
fn numa_node_count() -> u32 {
    // SAFETY: narf-frame provides the definition; weak-linked elsewhere.
    let n = unsafe { narf_numa_node_count() };
    n.max(1)
}

#[inline]
fn node_distance(from: u32, to: u32) -> u8 {
    // SAFETY: narf-frame provides the definition.
    let d = unsafe { narf_node_distance(from, to) };
    if d == 0 {
        if from == to {
            10
        } else {
            20
        }
    } else {
        d as u8
    }
}

/// CPU's NUMA node, or `None` when it has no SRAT proximity entry.
#[inline]
fn cpu_node(cpu: u32) -> Option<u32> {
    // SAFETY: narf-frame provides the definition.
    let n = unsafe { narf_cpu_node_opt(cpu) };
    if n == u32::MAX {
        None
    } else {
        Some(n)
    }
}

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
    // SAFETY: Valid memory or trusted environment
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
    /// Symlink children: name → target path (verbatim, as `readlink`
    /// returns it). udev relies on `subsystem`/`device`/`driver` links and
    /// the `/sys/dev/char/<maj>:<min>` layout.
    symlinks: IrqSafeSpinLock<BTreeMap<String, String>>,
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
            symlinks: IrqSafeSpinLock::new(BTreeMap::new()),
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
            symlinks: IrqSafeSpinLock::new(BTreeMap::new()),
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

    /// Add (or replace) a symlink child `name` pointing at `target`.
    /// `target` is stored verbatim (relative or absolute); `readlink`
    /// returns it as-is, which is all udev needs (it basenames the result).
    pub fn add_symlink(&self, name: impl Into<String>, target: impl Into<String>) {
        self.symlinks.lock().insert(name.into(), target.into());
    }

    /// Symlink target for `name`, if any.
    pub fn get_symlink(&self, name: &str) -> Option<String> {
        self.symlinks.lock().get(name).cloned()
    }

    /// List symlink child names.
    pub fn symlink_names(&self) -> Vec<String> {
        self.symlinks.lock().keys().cloned().collect()
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

/// Register a `/sys/dev/char/<major>:<minor>` symlink pointing at the
/// canonical `/sys/class/<class>/<name>` node (and ensure `/sys/dev/block`
/// exists so a udev scandir of it doesn't fail).
///
/// eudev / libudev's `sd_device_new_from_devnum` resolves a device *by
/// devnum* by reading `/sys/dev/char/<maj>:<min>` and `realpath()`-ing it to
/// the class dir; elogind's seat enumeration (`add_match_tag("master-of-seat")`
/// → `sd_device_new_from_device_id("c<maj>:<min>")`) goes through the same
/// path. Without this link the device is invisible to udev-based lookups, so
/// e.g. a DRM card never attaches to a seat and `seat0.CanGraphical` stays
/// false → the compositor's `TakeDevice` finds no GPU.
///
/// Linux ref: `device_add` → `device_create_sys_dev_entry`
/// (drivers/base/core.c) which makes the `/sys/dev/{char,block}/<maj>:<min>`
/// symlinks.
pub fn register_char_dev_link(major: u32, minor: u32, class: &str, name: &str) {
    let root = get_root();
    let dev_dir = get_or_create_child(&root, "dev");
    let dev_char = get_or_create_child(&dev_dir, "char");
    // udev scandir()s both dirs and fails the whole enumerate if either is
    // missing — keep /sys/dev/block present even when no block dev linked yet.
    let _dev_block = get_or_create_child(&dev_dir, "block");
    dev_char.add_symlink(
        format!("{}:{}", major, minor),
        format!("../../class/{}/{}", class, name),
    );
}

/// Like [`register_char_dev_link`] but for block devices
/// (`/sys/dev/block/<major>:<minor>`).
pub fn register_block_dev_link(major: u32, minor: u32, class: &str, name: &str) {
    let root = get_root();
    let dev_dir = get_or_create_child(&root, "dev");
    let _dev_char = get_or_create_child(&dev_dir, "char");
    let dev_block = get_or_create_child(&dev_dir, "block");
    dev_block.add_symlink(
        format!("{}:{}", major, minor),
        format!("../../class/{}/{}", class, name),
    );
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
/// Map the string written to a `uevent` file ("add" / "change" / "remove"
/// / "online" / "offline" …) to a [`UeventAction`]. Unknown verbs fall
/// back to `Change` (matches Linux's `kobject_action_type` leniency for
/// the common trigger verbs). Linux ref: `kobject_synth_uevent`.
pub(crate) fn uevent_action_from_write(data: &[u8]) -> UeventAction {
    let s = core::str::from_utf8(data).unwrap_or("").trim();
    let verb = s.split_whitespace().next().unwrap_or("");
    match verb {
        "add" => UeventAction::Add,
        "remove" => UeventAction::Remove,
        _ => UeventAction::Change,
    }
}

pub fn kobject_emit_uevent(kobj: &Kobject, action: UeventAction) {
    // DEVPATH is relative to the sysfs mount: udev/udevd read `/sys$DEVPATH`,
    // so it must NOT carry the `/sys` prefix (else they look up
    // `/sys/sys/...` and the device is never found). `kobj.path()` returns
    // the absolute `/sys/...` path; strip the mount prefix.
    let full = kobj.path();
    let devpath = full.strip_prefix("/sys").unwrap_or(&full).to_string();
    // subsystem = basename of the `subsystem` symlink target if present
    // (matches how udev derives it, and stays correct when a device is
    // rooted under /sys/devices/... rather than directly under its class
    // dir — e.g. evdev nodes at /sys/devices/.../inputN/eventN whose parent
    // kobject is `inputN`, not the `input` class). Falls back to the parent
    // kobject's name, then "kernel". Linux uses the kobject's kset name.
    let subsystem = kobj
        .get_symlink("subsystem")
        .and_then(|t| {
            t.trim_end_matches('/')
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .or_else(|| kobj.parent.as_ref().map(|p| p.name.clone()))
        .unwrap_or_else(|| "kernel".to_string());
    // Make the netlink message self-contained: fold the device's
    // synthesised `uevent` attr (MAJOR=/MINOR=/DEVNAME=/EV=/KEY=/…) into
    // the broadcast as extras, so udevd + the input_id builtin get the
    // full property set without re-reading sysfs. Drop the mandatory trio
    // (we set those from the env) to avoid duplicates.
    let mut extras: alloc::vec::Vec<(String, String)> = alloc::vec::Vec::new();
    if let Some(text) = kobj.attr_show("uevent") {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if !matches!(k, "ACTION" | "DEVPATH" | "SUBSYSTEM" | "SEQNUM") {
                    extras.push((k.to_string(), v.to_string()));
                }
            }
        }
    }
    crate::uevent::emit_with_extras(action, devpath, subsystem, extras);
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

/// Populate `/sys/class/input/event<N>/` for every registered evdev device.
/// Linux ref: `evdev_connect` (drivers/input/evdev.c:1306).
///
/// libudev/libinput enumerate input via `/sys/class/input/`: for each node
/// they read `dev` (`<major>:<minor>`) and `uevent` (MAJOR/MINOR/DEVNAME),
/// then open `/dev/input/event<N>` and tag it via EVIOCGBIT. We expose one
/// kobject per device the `narf-input` router actually has (event0 = the
/// virtio keyboard, event1 = the virtio tablet, …), keyed off
/// `ROUTER.device_ids()` so sysfs matches the real `/dev/input/` nodes.
/// Major 13 / minor 64+N is the Linux evdev `dev_t` convention.
/// Format an evdev capability bitmap as Linux's uevent/`input_print_bitmap`
/// string: space-separated `unsigned long` hex words, most-significant word
/// first, word 0 always printed. libudev's `make_bit` parses it from the end.
fn fmt_cap_bitmap(words: &[u64]) -> alloc::string::String {
    let hi = words.iter().rposition(|&w| w != 0).unwrap_or(0);
    let mut s = alloc::string::String::new();
    for i in (0..=hi).rev() {
        if i != hi {
            s.push(' ');
        }
        s.push_str(&format!("{:x}", words[i]));
    }
    s
}

/// Build the `EV=`/`KEY=`/`REL=`/`ABS=` uevent lines a device's capability
/// set contributes. udev (libudev/libudev-zero, replacing the kernel's
/// `60-input-id` builtin) reads these to set `ID_INPUT*` — without them
/// libinput skips the device entirely. Linux ref: `input_add_uevent_bm_var`
/// (drivers/input/input.c).
pub(crate) fn evdev_caps_uevent(caps: &narf_input::evdev::DeviceCaps) -> alloc::string::String {
    use narf_input::evdev::EventType;
    let mut s = format!("EV={:x}\n", caps.evbit);
    let has_key = caps.evbit & (1 << (EventType::Key as u16)) != 0;
    let has_rel = caps.evbit & (1 << (EventType::Rel as u16)) != 0;
    let has_abs = caps.evbit & (1 << (EventType::Abs as u16)) != 0;
    if has_key {
        s.push_str(&format!("KEY={}\n", fmt_cap_bitmap(&caps.keybit.words)));
    }
    if has_rel {
        s.push_str(&format!("REL={}\n", fmt_cap_bitmap(&caps.relbit.words)));
    }
    if has_abs {
        s.push_str(&format!("ABS={}\n", fmt_cap_bitmap(&caps.absbit.words)));
    }
    // ID_INPUT* properties. On real Linux these are added by udev's
    // `input_id` builtin (reading the same capability bitmaps) and are
    // what libinput keys on to accept + classify a device. NARF has no
    // udevd, so emit them directly in the synthesised uevent — udev reads
    // uevent-file properties without a database, so libinput's
    // `evdev_configure_device` sees the device type and stops reporting
    // "no input devices". Classification mirrors input_id's coarse rules:
    // a relative pointer is a mouse, an absolute device a touchscreen,
    // otherwise a key-only device is a keyboard.
    s.push_str("ID_INPUT=1\n");
    // BTN_LEFT (0x110) present ⇒ the device carries mouse buttons.
    let has_mouse_btn = caps.keybit.get(0x110);
    if has_rel {
        s.push_str("ID_INPUT_MOUSE=1\n");
    } else if has_abs && has_mouse_btn {
        // Absolute axes + mouse buttons + no direct-touch property = an
        // absolute pointer (QEMU virtio-tablet). udev's input_id tags this
        // ID_INPUT_MOUSE, and libinput turns it into a wl_pointer that reports
        // POINTER_MOTION_ABSOLUTE — so the pointer sits at the true host
        // position. Tagging it TOUCHSCREEN instead would route it through
        // touch handling and starve apps of pointer/click events.
        s.push_str("ID_INPUT_MOUSE=1\n");
    } else if has_abs {
        s.push_str("ID_INPUT_TOUCHSCREEN=1\n");
    } else if has_key {
        s.push_str("ID_INPUT_KEYBOARD=1\n");
    }
    s
}

pub fn populate_input_class() {
    let class_input = class_register("input");
    let root = get_root();
    // Mirror Linux's /sys/devices/.../inputN/eventN topology. This is
    // load-bearing for logind: elogind's `session_device_verify` (TakeDevice)
    // classifies an evdev node then requires a *parent* device whose subsystem
    // is "input" via `sd_device_get_parent_with_subsystem_devtype(dev,"input")`
    // — DRM nodes skip this, evdev nodes do not. A flat /sys/class/input/eventN
    // has no such parent, so TakeDevice returns -ENODEV and libinput never
    // opens the device (kwin: "Failed to open /dev/input/eventN (No such
    // device)"). Rooting eventN under an `inputN` parent (subsystem=input)
    // gives the walk a device to find. The seat tag then attaches to the
    // parent `inputN` (via /run/udev/data/+input:inputN); Linux ref:
    // drivers/input/input.c `input_register_device` (creates input%d) +
    // evdev.c (creates event%d as its child).
    let devices = get_or_create_child(&root, "devices");
    let platform = get_or_create_child(&devices, "platform");
    let narf_input = get_or_create_child(&platform, "narf-input");
    let dev_dir = get_or_create_child(&root, "dev");
    let dev_char = get_or_create_child(&dev_dir, "char");
    // udev scandir()s both /sys/dev/{char,block}; keep block present too.
    let _dev_block = get_or_create_child(&dev_dir, "block");

    for id in narf_input::evdev::ROUTER.device_ids() {
        let n = id.0.saturating_sub(1);
        let minor = 64 + n;

        // ── Parent input device: /sys/devices/platform/narf-input/inputN ──
        let inputn = Kobject::new_child(narf_input.clone(), format!("input{}", n));
        kobject_add_attr(&inputn, "name", move || format!("narf-input{}\n", n));
        // A `uevent` file is what sd_device_new_from_syspath uses to accept a
        // directory as a device (so the parent walk resolves it). Writable, like
        // the child eventN below: `udevadm trigger --action=add` walks /sys and
        // writes "add" to every device's uevent file — including this parent
        // input *device* node. Without a store, that write hits ReadOnly and no
        // parent-device ADD is ever broadcast, so real udevd never runs its
        // input rules against inputN and never writes /run/udev/data/+input:inputN
        // (the seat-tag DB file libinput needs — see the topology comment above).
        // In Linux EVERY kobject's uevent attr is writable (`uevent_store`,
        // drivers/base/core.c:2453); mirror that. Weak ref avoids a closure↔kobject
        // refcount cycle.
        {
            let pu = format!("PRODUCT=0/0/0/0\nNAME=\"narf-input{}\"\n", n);
            let weak = alloc::sync::Arc::downgrade(&inputn);
            kobject_add_writable_attr(
                &inputn,
                "uevent",
                move || pu.clone(),
                move |data: &[u8]| {
                    if let Some(k) = weak.upgrade() {
                        kobject_emit_uevent(&k, uevent_action_from_write(data));
                    }
                    Ok(())
                },
            );
        }
        // subsystem → /sys/class/input (basename "input"). From
        // /sys/devices/platform/narf-input/inputN that is four levels up.
        inputn.add_symlink("subsystem", "../../../../class/input");

        // ── evdev char node: …/inputN/eventN ──
        let eventn = Kobject::new_child(inputn.clone(), format!("event{}", n));
        {
            let dev = format!("13:{}\n", minor);
            kobject_add_attr(&eventn, "dev", move || dev.clone());
        }
        // Capability bitmaps (EV/KEY/REL/ABS) so udev tags ID_INPUT* and
        // libinput classifies + opens the device. Sourced from the live
        // router so they match what EVIOCGBIT reports on /dev/input/eventN.
        let caps_lines = narf_input::evdev::ROUTER
            .caps(id)
            .map(|c| evdev_caps_uevent(&c))
            .unwrap_or_default();
        let uevent = format!(
            "MAJOR=13\nMINOR={}\nDEVNAME=input/event{}\n{}",
            minor, n, caps_lines
        );
        // Writable so `udevadm trigger` (which writes "add"/"change" to the
        // uevent file) makes the kernel broadcast a netlink uevent. Weak ref
        // so the attr closure doesn't pin the kobject in a cycle. Linux ref:
        // `uevent_store` (drivers/base/core.c:2453).
        let weak = alloc::sync::Arc::downgrade(&eventn);
        kobject_add_writable_attr(
            &eventn,
            "uevent",
            move || uevent.clone(),
            move |data: &[u8]| {
                if let Some(k) = weak.upgrade() {
                    kobject_emit_uevent(&k, uevent_action_from_write(data));
                }
                Ok(())
            },
        );
        // subsystem → /sys/class/input (five levels up from the event node).
        eventn.add_symlink("subsystem", "../../../../../class/input");

        // ── /sys/class/input/{inputN,eventN} → the /sys/devices nodes ──
        // Linux makes the class entries symlinks into /sys/devices.
        class_input.add_symlink(
            format!("input{}", n),
            format!("../../devices/platform/narf-input/input{}", n),
        );
        class_input.add_symlink(
            format!("event{}", n),
            format!("../../devices/platform/narf-input/input{}/event{}", n, n),
        );

        // ── /sys/dev/char/13:<minor> → the evdev node under /sys/devices ──
        // sd_device_new_from_devnum('c',13:<minor>) realpath()s this link;
        // landing under /sys/devices/.../inputN/eventN gives it a walkable
        // "input" parent (unlike the old /sys/class/input/eventN target).
        dev_char.add_symlink(
            format!("13:{}", minor),
            format!("../../devices/platform/narf-input/input{}/event{}", n, n),
        );
    }
}

/// Populate `/sys/kernel/` with standard kernel-global files.
/// Linux ref: `kernel_kobj` (lib/kobject.c:817).
pub fn populate_kernel_dir() {
    let root = get_root();
    let kernel = get_or_create_child(&root, "kernel");
    kobject_add_attr(&kernel, "uevent_seqnum", crate::uevent::gen_uevent_seqnum);
}

/// Build a Linux-style CPU bitmap string (comma-separated 32-bit
/// hex words, high word first) for the CPUs whose SRAT proximity
/// domain is `node`. Empty mask renders as a single "0".
/// Linux ref: `node_read_cpumap` (drivers/base/node.c).
fn node_cpumap_string(node: u32) -> String {
    let mut mask: u128 = 0;
    for cpu in 0..128u32 {
        if cpu_node(cpu) == Some(node) {
            mask |= 1u128 << cpu;
        }
    }
    // 128 bits → four 32-bit words, high first, comma-joined.
    let w3 = (mask >> 96) as u32;
    let w2 = (mask >> 64) as u32;
    let w1 = (mask >> 32) as u32;
    let w0 = mask as u32;
    format!("{:08x},{:08x},{:08x},{:08x}\n", w3, w2, w1, w0)
}

/// Build a Linux-style CPU list string ("0-7", "8-15", …) for the
/// CPUs in proximity domain `node`.
/// Linux ref: `node_read_cpulist` (drivers/base/node.c).
fn node_cpulist_string(node: u32) -> String {
    let mut cpus: Vec<u32> = Vec::new();
    for cpu in 0..256u32 {
        if cpu_node(cpu) == Some(node) {
            cpus.push(cpu);
        }
    }
    if cpus.is_empty() {
        return "\n".to_string();
    }
    let mut out = String::new();
    let mut i = 0;
    while i < cpus.len() {
        let start = cpus[i];
        let mut end = start;
        while i + 1 < cpus.len() && cpus[i + 1] == end + 1 {
            end += 1;
            i += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            out.push_str(&format!("{}", start));
        } else {
            out.push_str(&format!("{}-{}", start, end));
        }
        i += 1;
    }
    out.push('\n');
    out
}

/// Populate `/sys/devices/system/node/` with one `nodeN/` directory
/// per NUMA node plus `online` / `possible` summaries.
///
/// Per-node attributes:
/// - `distance`  — space-separated SLIT row (`node_distance(n, j)`).
/// - `meminfo`   — `Node N MemTotal/MemFree:` lines from the per-node
///   buddy free counts.
/// - `cpulist` / `cpumap` — the CPUs in this proximity domain.
///
/// Linux ref: `drivers/base/node.c` (`register_node`,
/// `node_read_distance`, `node_read_meminfo`).
pub fn populate_numa_nodes() {
    let root = get_root();
    let devices = get_or_create_child(&root, "devices");
    let system = get_or_create_child(&devices, "system");
    let node_dir = get_or_create_child(&system, "node");

    let n = numa_node_count().max(1);

    // /sys/devices/system/node/online and /possible: "0" or "0-N".
    let range = if n <= 1 {
        "0\n".to_string()
    } else {
        format!("0-{}\n", n - 1)
    };
    let online = range.clone();
    let possible = range.clone();
    kobject_add_attr(&node_dir, "online", move || online.clone());
    kobject_add_attr(&node_dir, "possible", move || possible.clone());
    kobject_add_attr(&node_dir, "has_normal_memory", move || range.clone());

    for node in 0..n {
        let name = format!("node{}", node);
        let kobj = get_or_create_child(&node_dir, &name);

        // distance: SLIT row, space-separated, newline-terminated.
        kobject_add_attr(&kobj, "distance", move || {
            let cols = numa_node_count().max(1);
            let mut s = String::new();
            for to in 0..cols {
                if to > 0 {
                    s.push(' ');
                }
                s.push_str(&format!("{}", node_distance(node, to)));
            }
            s.push('\n');
            s
        });

        // meminfo: per-node MemTotal / MemFree from the buddy.
        let node_idx = node as usize;
        kobject_add_attr(&kobj, "meminfo", move || {
            let free_pages = if node_idx < narf_memory::FRAME_MAX_NUMA_NODES {
                narf_memory::node_free(node_idx)
            } else {
                0
            };
            let free_kb = (free_pages as u64) * 4;
            format!(
                "Node {n} MemTotal:       {tot} kB\n\
                 Node {n} MemFree:        {free} kB\n\
                 Node {n} MemUsed:        {used} kB\n",
                n = node_idx,
                tot = free_kb,
                free = free_kb,
                used = 0u64,
            )
        });

        kobject_add_attr(&kobj, "cpulist", move || node_cpulist_string(node));
        kobject_add_attr(&kobj, "cpumap", move || node_cpumap_string(node));
    }
}

/// Call all `populate_*` functions.  Invoked from the sysfs initcall.
pub fn populate_all() {
    populate_block_class();
    populate_net_class();
    populate_input_class();
    populate_kernel_dir();
    populate_numa_nodes();
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
        if let Some(child) = kobj.get_child(name) {
            return Some(Arc::new(SysDirMarker { kobj: child }));
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

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, alloc::vec::Vec<(alloc::string::String, FileType)>> {
        let r = self.enumerate(cursor, max);
        Box::pin(async move { Ok(r) })
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
        // Symlinks (subsystem/device/driver, …) — readlink reads the target.
        if let Some(target) = self.kobj.get_symlink(name) {
            return Some(Arc::new(SysSymlinkFile { target }));
        }
        // Child dirs look like files so resolve() can stat them
        if let Some(child) = self.kobj.get_child(name) {
            return Some(Arc::new(SysDirMarker { kobj: child }));
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
        let symlink_names = self.kobj.symlink_names();
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
        for n in symlink_names {
            let leaked: &'static str = Box::leak(n.into_boxed_str());
            entries.push(DirEntry {
                name: leaked,
                file_type: FileType::Symlink,
            });
        }
        Box::new(entries.into_iter())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let child_names = self.kobj.child_names();
        let attr_names = self.kobj.attr_names();
        let symlink_names = self.kobj.symlink_names();
        let mut all: Vec<(String, FileType)> = Vec::new();
        for n in child_names {
            all.push((n, FileType::Dir));
        }
        for n in attr_names {
            all.push((n.to_string(), FileType::File));
        }
        for n in symlink_names {
            all.push((n, FileType::Symlink));
        }
        all.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, alloc::vec::Vec<(alloc::string::String, FileType)>> {
        // getdents64 drives this (not the sync enumerate); without it every
        // sysfs directory read-dir comes back empty.
        let r = self.enumerate(cursor, max);
        Box::pin(async move { Ok(r) })
    }
}

/// Marker returned by `lookup` for a child that is a directory.
/// `stat()` reports `Dir` so `resolve()` knows to descend, and `as_dir()`
/// hands back the child's `SysKobjDir` so `getdents64`/`readdir` can
/// enumerate it — without this, opening a sysfs subdir (e.g.
/// `/sys/class/input`) as a file yielded a directory fd with no backing
/// `DirOps`, so `ls` (and libudev's `/sys/class/*` scan) saw it empty.
#[derive(Debug)]
struct SysDirMarker {
    kobj: Arc<Kobject>,
}

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
    fn as_dir(&self) -> Option<Arc<dyn DirOps>> {
        Some(Arc::new(SysKobjDir {
            kobj: self.kobj.clone(),
        }))
    }
}

/// A sysfs symlink. `stat()` reports `Symlink` (so `readlink`/`lstat` treat
/// it as one) and `read()` returns the target verbatim — the same shape the
/// VFS path walker and `sys_readlink` use for symlinks elsewhere.
#[derive(Debug)]
struct SysSymlinkFile {
    target: String,
}

impl FileOps for SysSymlinkFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let bytes = self.target.as_bytes();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(0);
            }
            let n = (bytes.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            Ok(n)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: self.target.len() as u64,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Symlink,
                perms: 0o777,
            },
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
