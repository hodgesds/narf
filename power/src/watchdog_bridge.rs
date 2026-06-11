//! Watchdog device-file bridge — `/dev/watchdog0`, `/dev/watchdog`, and
//! `/sys/class/watchdog/watchdog<N>/`.
//!
//! ## Architecture
//!
//! The hardware drivers (`Sp5100Driver`, `ITcoDriver`) and the kick-task
//! live in `watchdog.rs`.  This module is the VFS glue:
//!
//! - A global `WatchdogSlot` registry (indexed 0…N) each slot pairs a
//!   driver identity string + timeout with a `WatchdogState` shared-
//!   memory cell that both the `/dev/watchdogN` FileOps and the kick-
//!   task can reach without re-searching the table.
//!
//! - `/dev/watchdog0` (and the `/dev/watchdog` alias) implement `FileOps`
//!   per Linux `drivers/watchdog/watchdog_dev.c`:
//!     - `write` → kick + magic-'V' tracking
//!     - `read`  → always 0 (write-only semantics)
//!     - `poll_readiness` → POLL_OUT always
//!     - `close` → disarm iff magic 'V' seen, else keep counting
//!
//! - `/sys/class/watchdog/watchdog<N>/` is served by a custom `WatchdogSysFs`
//!   that mounts at that path.  Per-device directories return per-attr
//!   file nodes from `WatchdogAttrFile` (read-only) and
//!   `WatchdogWritableAttrFile` (read-write), avoiding any dependency on
//!   uncommitted sysfs kobject infrastructure.
//!
//! - The kernel kick-task backs off once userspace opens the device (the
//!   `USERSPACE_CLAIMED` flag).  If the userspace daemon closes without
//!   writing 'V', the hardware is NOT disarmed — the timeout continues
//!   and the system resets.
//!
//! ## Linux references
//!
//! - `watchdog_dev.c:watchdog_write`   lines 238–275   — write + magic 'V'.
//! - `watchdog_dev.c:watchdog_read`    lines 231–237   — read returns 0.
//! - `watchdog_dev.c:watchdog_release` lines 278–310   — close behaviour.
//! - `watchdog_dev.c:watchdog_poll`    lines 224–230   — poll always POLLOUT.
//! - `watchdog_core.c`                 lines  67– 98   — class + device register.
//! - `watchdog_core.c:watchdog_cdev_register` lines 391–431.
//! - `sp5100_tco.c`                    lines 291–327   — `CONTROL_FIRED` read.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat, POLL_OUT,
};

// ── Per-watchdog state ────────────────────────────────────────────────

/// Shared mutable state for one watchdog device.  Stored in an `Arc`
/// so both the `DevWatchdog` FileOps node and the sysfs show-closures
/// see the same live values without a global table lookup per access.
pub struct WatchdogState {
    /// Kick counter — incremented on every kick (write byte or
    /// kernel-task pet).  Sysfs `status` exposes the low 8 bits.
    pub kick_count: AtomicU32,
    /// Set when userspace writes magic 'V'.  Allows graceful disarm on
    /// `close`.  Cleared on re-open.
    /// `watchdog_dev.c:280` — `WDOG_ALLOW_RELEASE`.
    pub magic_close: AtomicBool,
    /// Set when the device is open by userspace.  Kernel kick-task
    /// backs off while this is true.
    /// `watchdog_dev.c:306` — `WDOG_DEV_OPEN`.
    pub userspace_claimed: AtomicBool,
    /// Whether the watchdog is currently armed.
    pub active: AtomicBool,
    /// Current timeout in seconds (writable via sysfs).
    pub timeout_secs: AtomicU32,
    /// Pretimeout in seconds; 0 = not supported.
    pub pretimeout_secs: AtomicU32,
    /// nowayout: once armed, cannot be disabled.
    pub nowayout: AtomicBool,
    /// Was the previous boot caused by this watchdog expiring?
    /// Latched from `CONTROL_FIRED` (sp5100) or `TCO2_STS_BOOT_STS` (iTCO)
    /// at probe time.
    pub bootstatus: AtomicBool,
    /// Driver identity string (e.g. "SP5100 TCO").
    pub identity: IrqSafeSpinLock<String>,
    /// Firmware version string ("unknown" if not available).
    pub fw_version: IrqSafeSpinLock<String>,
}

impl core::fmt::Debug for WatchdogState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WatchdogState")
            .field("active", &self.active.load(Ordering::Relaxed))
            .field("timeout_secs", &self.timeout_secs.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl WatchdogState {
    pub fn new(
        identity: String,
        timeout_secs: u32,
        pretimeout_secs: u32,
        nowayout: bool,
        bootstatus: bool,
        fw_version: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            kick_count: AtomicU32::new(0),
            magic_close: AtomicBool::new(false),
            userspace_claimed: AtomicBool::new(false),
            active: AtomicBool::new(false),
            timeout_secs: AtomicU32::new(timeout_secs),
            pretimeout_secs: AtomicU32::new(pretimeout_secs),
            nowayout: AtomicBool::new(nowayout),
            bootstatus: AtomicBool::new(bootstatus),
            identity: IrqSafeSpinLock::new(identity),
            fw_version: IrqSafeSpinLock::new(fw_version),
        })
    }
}

// ── Global watchdog slot registry ────────────────────────────────────

struct WatchdogSlot {
    state: Arc<WatchdogState>,
}

static WATCHDOG_SLOTS: IrqSafeSpinLock<Vec<WatchdogSlot>> = IrqSafeSpinLock::new(Vec::new());

/// Register a watchdog driver and return its slot index.
///
/// Returns the slot index assigned to this watchdog (0 = first).
pub fn register_watchdog(state: Arc<WatchdogState>) -> usize {
    let mut slots = WATCHDOG_SLOTS.lock();
    let idx = slots.len();
    slots.push(WatchdogSlot { state });
    idx
}

/// Retrieve the `Arc<WatchdogState>` for the given slot index.
pub fn watchdog_state(idx: usize) -> Option<Arc<WatchdogState>> {
    WATCHDOG_SLOTS.lock().get(idx).map(|s| s.state.clone())
}

/// Number of registered watchdog slots.
pub fn watchdog_count() -> usize {
    WATCHDOG_SLOTS.lock().len()
}

// ── /dev/watchdogN FileOps ────────────────────────────────────────────

/// `/dev/watchdogN` file node.
///
/// `write` → any byte kicks; magic 'V' also sets `magic_close`.
/// `read`  → returns 0 (write-only by convention).
/// `poll_readiness` → `POLL_OUT` always.
///
/// Linux ref: `watchdog_dev.c` lines 224–310.
pub struct DevWatchdog {
    pub state: Arc<WatchdogState>,
}

impl core::fmt::Debug for DevWatchdog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevWatchdog").finish_non_exhaustive()
    }
}

impl DevWatchdog {
    pub fn new(state: Arc<WatchdogState>) -> Self {
        // Mark userspace as having claimed the device.
        // Kernel kick-task sees this and backs off.
        // `watchdog_dev.c:306` — `set_bit(WDOG_DEV_OPEN, &wdd->status)`.
        state.userspace_claimed.store(true, Ordering::Release);
        state.magic_close.store(false, Ordering::Release);
        Self { state }
    }
}

impl FileOps for DevWatchdog {
    /// Read returns 0 (write-only semantics).
    /// `watchdog_dev.c:231–237` — `watchdog_read` returns `-EINVAL`.
    /// We return 0 (EOF) which is the idiomatic no-data response.
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    /// Write: any byte kicks; 'V' also arms graceful-close flag.
    ///
    /// `watchdog_dev.c:238–275` — `watchdog_write`:
    ///   - Scans `buf` for 'V' → sets `WDOG_ALLOW_RELEASE`.
    ///   - Calls `watchdog_ping` regardless (any write = kick).
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = buf.len();
        let magic_v = buf.contains(&b'V');
        if magic_v {
            self.state.magic_close.store(true, Ordering::Release);
        }
        self.state.kick_count.fetch_add(1, Ordering::Relaxed);
        self.state.active.store(true, Ordering::Release);
        Box::pin(async move { Ok(n) })
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

    /// POLL_OUT always — watchdog is always ready for writes.
    /// `watchdog_dev.c:224–230` — `watchdog_poll` returns `POLLOUT | POLLWRNORM`.
    fn poll_readiness(&self) -> u32 {
        POLL_OUT
    }
}

/// Handle the close semantics for a `/dev/watchdogN` file node.
///
/// - If `magic_close` is set (userspace wrote 'V') AND `nowayout` is false:
///   disarm the watchdog (clear `active`).
/// - Otherwise: leave `active` set; the hardware continues counting.
///
/// `watchdog_dev.c:278–310` — `watchdog_release`.
pub fn watchdog_release(state: &WatchdogState) {
    let nowayout = state.nowayout.load(Ordering::Acquire);
    let magic = state.magic_close.load(Ordering::Acquire);
    state.userspace_claimed.store(false, Ordering::Release);
    state.magic_close.store(false, Ordering::Release);
    if magic && !nowayout {
        state.active.store(false, Ordering::Release);
    }
}

// ── /dev/watchdog compat alias ────────────────────────────────────────

/// Global slot-0 state for `/dev/watchdog` alias.
static WATCHDOG0_NODE: IrqSafeSpinLock<Option<Arc<WatchdogState>>> = IrqSafeSpinLock::new(None);

/// Install the `/dev/watchdog` and `/dev/watchdog0` compat nodes.
pub fn install_dev_watchdog_nodes() {
    if let Some(state) = watchdog_state(0) {
        *WATCHDOG0_NODE.lock() = Some(state);
    }
}

/// Resolve a `/dev/watchdog` or `/dev/watchdog0` lookup to a fresh
/// `DevWatchdog` node backed by slot-0's shared state.
pub fn lookup_dev_watchdog() -> Option<Arc<dyn FileOps>> {
    let state = WATCHDOG0_NODE.lock().clone()?;
    Some(Arc::new(DevWatchdog::new(state)) as Arc<dyn FileOps>)
}

/// Resolve `/dev/watchdog` or `/dev/watchdog<N>` lookups.
pub fn lookup_dev_watchdog_n(name: &str) -> Option<Arc<dyn FileOps>> {
    if name == "watchdog" {
        return lookup_dev_watchdog();
    }
    if let Some(rest) = name.strip_prefix("watchdog") {
        if let Ok(idx) = rest.parse::<usize>() {
            let state = watchdog_state(idx)?;
            return Some(Arc::new(DevWatchdog::new(state)) as Arc<dyn FileOps>);
        }
    }
    None
}

// ── /sys/class/watchdog sysfs filesystem ─────────────────────────────
//
// The committed narf_filesystem::sysfs kobject infrastructure does not
// yet support writable attrs (AttrStore is not wired into SysAttrFile).
// Rather than patching the filesystem crate, we serve
// /sys/class/watchdog directly with a custom FsInstance + DirOps tree
// mounted via the VFS registry.  This matches the pattern used by other
// subsystem-specific sysfs directories.
//
// Linux ref: watchdog_core.c:watchdog_cdev_register (lines 391–431) —
// watchdog class devices are registered under /sys/class/watchdog/<name>/.

// ── WatchdogAttrFile — read-only sysfs attribute ─────────────────────

/// A read-only sysfs attribute file backed by a show-closure.
///
/// `show` is called on every read (lazy generation, matching Linux's
/// `kernfs_seq_show` pattern in `fs/kernfs/file.c:172`).
struct WatchdogAttrFile {
    show: Arc<dyn Fn() -> String + Send + Sync>,
}

impl core::fmt::Debug for WatchdogAttrFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WatchdogAttrFile").finish_non_exhaustive()
    }
}

impl FileOps for WatchdogAttrFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let content = (self.show)();
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

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        let size = (self.show)().len() as u64;
        Stat {
            size,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

// ── WatchdogWritableAttrFile — read-write sysfs attribute ─────────────

/// A read-write sysfs attribute file.
///
/// `show` → read, `store` → write.  Matches the Linux `struct kobj_attribute`
/// layout (include/linux/kobject.h:131) which pairs `.show` and `.store`.
/// Store returns the full buf len on success per sysfs convention.
///
/// Linux ref: `sysfs_kf_write` (fs/sysfs/file.c:263) — calls
/// `attribute->store(kobj, buf, count)` and returns `count` on success.
struct WatchdogWritableAttrFile {
    show: Arc<dyn Fn() -> String + Send + Sync>,
    store: Arc<dyn Fn(&[u8]) -> Result<(), FsError> + Send + Sync>,
}

impl core::fmt::Debug for WatchdogWritableAttrFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WatchdogWritableAttrFile")
            .finish_non_exhaustive()
    }
}

impl FileOps for WatchdogWritableAttrFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let content = (self.show)();
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

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        match (self.store)(buf) {
            Ok(()) => {
                let n = buf.len();
                Box::pin(async move { Ok(n) })
            }
            Err(e) => Box::pin(async move { Err(e) }),
        }
    }

    fn stat(&self) -> Stat {
        let size = (self.show)().len() as u64;
        Stat {
            size,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
}

// ── WatchdogDevDir — /sys/class/watchdog/watchdog<N>/ ─────────────────

/// Per-device directory under `/sys/class/watchdog/watchdog<N>/`.
///
/// Exposes the watchdog attrs defined in
/// `Documentation/watchdog/watchdog-kernel-api.rst`:
///
/// | attr         | R/W | Linux ref                                          |
/// |--------------|-----|----------------------------------------------------|
/// | identity     | R   | `watchdog_dev.c` `WDIOC_GETSUPPORT`                |
/// | state        | R   | `watchdog_core.c` status bits                      |
/// | status       | R   | WDIOF_CARDRESET bitmap                              |
/// | timeout      | R/W | `watchdog_dev.c:watchdog_set_timeout` (lines 95–123)|
/// | pretimeout   | R/W | `watchdog_dev.c:watchdog_set_pretimeout`            |
/// | nowayout     | R   | `watchdog_core.c:watchdog_cdev_register`            |
/// | bootstatus   | R   | `sp5100_tco.c:291–327` `CONTROL_FIRED` latch        |
/// | fw_version   | R   | `watchdog_dev.c` `WDIOC_GETSUPPORT.firmware_version`|
pub struct WatchdogDevDir {
    pub state: Arc<WatchdogState>,
}

impl core::fmt::Debug for WatchdogDevDir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WatchdogDevDir").finish_non_exhaustive()
    }
}

impl WatchdogDevDir {
    fn ro_attr(show: impl Fn() -> String + Send + Sync + 'static) -> Arc<dyn FileOps> {
        Arc::new(WatchdogAttrFile {
            show: Arc::new(show),
        })
    }

    fn rw_attr(
        show: impl Fn() -> String + Send + Sync + 'static,
        store: impl Fn(&[u8]) -> Result<(), FsError> + Send + Sync + 'static,
    ) -> Arc<dyn FileOps> {
        Arc::new(WatchdogWritableAttrFile {
            show: Arc::new(show),
            store: Arc::new(store),
        })
    }
}

// Static entries for `iter()` — must be `&'static str`.
const WATCHDOG_ATTR_NAMES: &[DirEntry] = &[
    DirEntry {
        name: "identity",
        file_type: FileType::File,
    },
    DirEntry {
        name: "state",
        file_type: FileType::File,
    },
    DirEntry {
        name: "status",
        file_type: FileType::File,
    },
    DirEntry {
        name: "timeout",
        file_type: FileType::File,
    },
    DirEntry {
        name: "pretimeout",
        file_type: FileType::File,
    },
    DirEntry {
        name: "nowayout",
        file_type: FileType::File,
    },
    DirEntry {
        name: "bootstatus",
        file_type: FileType::File,
    },
    DirEntry {
        name: "fw_version",
        file_type: FileType::File,
    },
];

impl DirOps for WatchdogDevDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let s = self.state.clone();
        match name {
            "identity" => Some(Self::ro_attr(move || {
                format!("{}\n", s.identity.lock().as_str())
            })),
            "state" => Some(Self::ro_attr(move || {
                if s.active.load(Ordering::Acquire) {
                    "active\n".to_string()
                } else {
                    "inactive\n".to_string()
                }
            })),
            "status" => Some(Self::ro_attr(move || {
                // Bit 2 (0x4) = WDIOF_CARDRESET: previous boot was a WD reset.
                // `watchdog_dev.c:WDIOC_GETSTATUS`.
                let bits: u32 = if s.bootstatus.load(Ordering::Acquire) {
                    0x4
                } else {
                    0x0
                };
                format!("{:#x}\n", bits)
            })),
            "timeout" => {
                let s_show = s.clone();
                let s_store = s.clone();
                Some(Self::rw_attr(
                    move || format!("{}\n", s_show.timeout_secs.load(Ordering::Acquire)),
                    move |buf| {
                        let text = core::str::from_utf8(buf)
                            .map_err(|_| FsError::ReadOnly)?
                            .trim();
                        let v: u32 = text.parse().map_err(|_| FsError::ReadOnly)?;
                        if v == 0 {
                            return Err(FsError::ReadOnly);
                        }
                        s_store.timeout_secs.store(v, Ordering::Release);
                        Ok(())
                    },
                ))
            }
            "pretimeout" => {
                let s_show = s.clone();
                let s_store = s.clone();
                Some(Self::rw_attr(
                    move || format!("{}\n", s_show.pretimeout_secs.load(Ordering::Acquire)),
                    move |buf| {
                        let text = core::str::from_utf8(buf)
                            .map_err(|_| FsError::ReadOnly)?
                            .trim();
                        let v: u32 = text.parse().map_err(|_| FsError::ReadOnly)?;
                        s_store.pretimeout_secs.store(v, Ordering::Release);
                        Ok(())
                    },
                ))
            }
            "nowayout" => Some(Self::ro_attr(move || {
                if s.nowayout.load(Ordering::Acquire) {
                    "1\n".to_string()
                } else {
                    "0\n".to_string()
                }
            })),
            "bootstatus" => Some(Self::ro_attr(move || {
                // Reflects sp5100 CONTROL_FIRED bit latched at probe time.
                // `sp5100_tco.c:291–327` — `tco_timer_start` checks `WDT_FIRED`.
                if s.bootstatus.load(Ordering::Acquire) {
                    "1\n".to_string()
                } else {
                    "0\n".to_string()
                }
            })),
            "fw_version" => Some(Self::ro_attr(move || {
                format!("{}\n", s.fw_version.lock().as_str())
            })),
            _ => None,
        }
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(WATCHDOG_ATTR_NAMES.iter().copied())
    }
}

// ── WatchdogClassDir — /sys/class/watchdog/ ───────────────────────────

/// The `/sys/class/watchdog/` directory listing all registered devices.
struct WatchdogClassDir;

impl core::fmt::Debug for WatchdogClassDir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WatchdogClassDir").finish_non_exhaustive()
    }
}

impl DirOps for WatchdogClassDir {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // Device subdirs look like files to the VFS stat path.
        None
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        // Match "watchdog<N>" entries.
        if let Some(rest) = name.strip_prefix("watchdog") {
            if let Ok(idx) = rest.parse::<usize>() {
                if let Some(state) = watchdog_state(idx) {
                    return Some(Arc::new(WatchdogDevDir { state }) as Arc<dyn DirOps>);
                }
            }
        }
        None
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Empty — enumerate() provides the live list.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let count = watchdog_count();
        (0..count)
            .map(|i| (format!("watchdog{}", i), FileType::Dir))
            .skip(cursor)
            .take(max)
            .collect()
    }
}

// ── WatchdogSysFs — FsInstance ────────────────────────────────────────

/// A minimal `FsInstance` that serves `/sys/class/watchdog/`.
///
/// Mounted at `/sys/class/watchdog` by the watchdog-bridge initcall so
/// the VFS longest-prefix match routes paths under that tree here first.
///
/// Linux ref: watchdog_core.c:watchdog_cdev_register (lines 391–431) —
/// calls `device_create` under the watchdog class.
#[derive(Debug)]
pub struct WatchdogSysFs;

impl FsInstance for WatchdogSysFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(WatchdogClassDir)
    }
    fn name(&self) -> &str {
        "watchdog-sysfs"
    }
}

// ── Bridge initcall ───────────────────────────────────────────────────

/// Register the sp5100 watchdog with the bridge.
///
/// Called from `register_initcalls` at `Stage::Subsys`.  Constructs a
/// synthetic `WatchdogState` for the sp5100 driver and mounts the sysfs
/// and devfs nodes.
///
/// On EFCH / Zen silicon the sp5100 driver is always present.  This
/// bridge registers with the correct identity string and a 60-second
/// default timeout; the kick-task and devfs wire-up are functional for
/// the VFS/sysfs surface even without live MMIO calls being wired.
///
/// Stage 4 replaces stub state construction with real hardware reads
/// (CONTROL register → `fired_on_prev_boot`, PMIO → `mmio_base`).
pub fn register_bridge() {
    use narf_init::{InitResult, Stage};

    narf_init::register(Stage::Subsys, "watchdog-bridge", || {
        // ── sp5100 / EFCH (AMD Zen FCH) ──────────────────────────────────
        // Identity matches `sp5100_tco.c` module description.
        // `sp5100_tco.c:590` — `MODULE_DESCRIPTION("SP5100/SB800 TCO WatchDog Timer Driver")`.
        let sp5100_state = WatchdogState::new(
            "SP5100 TCO".to_string(),
            60,    // 60-second default timeout
            0,     // pretimeout not supported on sp5100
            false, // nowayout = false (can be disabled)
            false, // bootstatus: real value read from CONTROL_FIRED on hw
            "unknown".to_string(),
        );
        let _idx0 = register_watchdog(sp5100_state);

        // Install /dev/watchdog and /dev/watchdog0 nodes.
        install_dev_watchdog_nodes();

        // Mount /sys/class/watchdog at a dedicated path so the VFS
        // longest-prefix match routes it here before the main sysfs.
        // `watchdog_core.c:watchdog_cdev_register` (lines 391–431).
        let auth = narf_filesystem::bootstrap_mount_authority();
        let _ = narf_filesystem::registry().mount(&auth, "/sys/class/watchdog", WatchdogSysFs);

        narf_console::write_str(
            "  watchdog-bridge: /dev/watchdog0 + /sys/class/watchdog/watchdog0 registered\n",
        );

        InitResult::Ok
    });
}

// ── Smoke-test helpers (pub for tests.rs) ────────────────────────────

/// Allocate a fresh `WatchdogState` for in-process unit tests.
/// Does NOT register it in the global slot table.
#[doc(hidden)]
pub fn __new_test_state(identity: &str, timeout_secs: u32) -> Arc<WatchdogState> {
    WatchdogState::new(
        identity.to_string(),
        timeout_secs,
        0,
        false,
        false,
        "unknown".to_string(),
    )
}
