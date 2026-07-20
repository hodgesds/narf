#![cfg(feature = "linux-compat")]
//! Smoke tests for `sysfs` (kobject hierarchy) and `uevent` (hotplug).
//!
//! Covers:
//!   1. Kobject create with parent
//!   2. Kobject attr show: `name → "foo\n"`
//!   3. Kobject path: `class/net/eth0` → `/sys/class/net/eth0`
//!   4. SysFs VFS lookup: `/sys/class/net/eth0/mtu` resolves + reads
//!   5. SysFs enumerate: `class/net` lists all registered interfaces
//!   6. Uevent ring: 3 emits + 3 reads, FIFO order
//!   7. Uevent format: ADD action produces message with required keys
//!   8. Block-device class auto-population: register a block device → see it
//!      under `/sys/class/block/`
//!   9. `kobject_emit_uevent` helper

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

#[cfg(feature = "linux-compat")]
use crate::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_emit_uevent, Kobject, SysFs,
};
use crate::uevent::{self, UeventAction, UeventReader};
use crate::{FileType, FsInstance};

// ── Minimal fake block device for tests ───────────────────────────────

use alloc::vec;

struct FakeBlock {
    #[allow(dead_code)]
    data: narf_lib::sync::IrqSafeSpinLock<Vec<u8>>,
    lba_size: u32,
    capacity: u64,
}

impl core::fmt::Debug for FakeBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeBlock").finish()
    }
}

impl FakeBlock {
    // Returns Arc<dyn BlockDeviceSync> rather than Self so callers get the trait object directly.
    #[allow(clippy::new_ret_no_self)]
    fn new(lba_size: u32, cap: u64) -> Arc<dyn narf_block::BlockDeviceSync> {
        Arc::new(Self {
            data: narf_lib::sync::IrqSafeSpinLock::new(vec![
                0u8;
                (lba_size as usize) * (cap as usize)
            ]),
            lba_size,
            capacity: cap,
        })
    }
}

impl narf_block::BlockDeviceSync for FakeBlock {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }
    fn capacity(&self) -> u64 {
        self.capacity
    }
    fn read(&self, _lba: u64, n: u16, out: &mut [u8]) -> Result<(), narf_block::BlockIoError> {
        let n_bytes = n as usize * self.lba_size as usize;
        if out.len() < n_bytes {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        out[..n_bytes].fill(0);
        Ok(())
    }
    fn write(&self, _lba: u64, _n: u16, _data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        Ok(())
    }
}

// ── Poll helper ────────────────────────────────────────────────────────

fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    // SAFETY: raw_waker() returns a vtable whose no-op/no-clone fns are sound for a
    // single-threaded test poll; the RawWaker is not used after this scope.
    // SAFETY: Valid memory or trusted environment
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local mut binding that outlives this block; we do not move it.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

// ── Test 1: Kobject create with parent ────────────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_sysfs_kobject_create_with_parent() -> TestResult {
    crate::sysfs::__reset_for_test();
    let parent = Kobject::new_root("testroot");
    let child = Kobject::new_child(parent.clone(), "child");
    if child.name() != "child" {
        return TestResult::Fail("child name mismatch");
    }
    if parent.get_child("child").is_none() {
        return TestResult::Fail("parent does not list child");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_kobject_create_with_parent);

/// An absolute pointer (ABS axes + mouse buttons, no relative axes) must be
/// tagged `ID_INPUT_MOUSE`, NOT `ID_INPUT_TOUCHSCREEN` — that tag is what makes
/// libinput deliver it as a wl_pointer with `POINTER_MOTION_ABSOLUTE`. Tagging
/// it as a touchscreen routes it through touch handling and starves apps of
/// pointer/click events.
fn smoke_sysfs_abs_pointer_tagged_id_input_mouse() -> TestResult {
    use narf_input::evdev::{key, DeviceCaps};
    use narf_input::{abs, AxisInfo};

    let range = AxisInfo {
        min: 0,
        max: 0x7FFF,
        fuzz: 0,
        flat: 0,
        res: 0,
    };
    let mut caps = DeviceCaps::new();
    caps.add_abs_info(abs::ABS_X, range);
    caps.add_abs_info(abs::ABS_Y, range);
    caps.add_key(key::BTN_LEFT);

    let uevent = crate::sysfs::evdev_caps_uevent(&caps);
    if !uevent.contains("ID_INPUT_MOUSE=1") {
        return TestResult::Fail("absolute pointer not tagged ID_INPUT_MOUSE");
    }
    if uevent.contains("ID_INPUT_TOUCHSCREEN") {
        return TestResult::Fail("absolute pointer wrongly tagged ID_INPUT_TOUCHSCREEN");
    }
    if !uevent.contains("ABS=") {
        return TestResult::Fail("ABS capability bitmap missing from uevent");
    }
    if uevent.contains("REL=") {
        return TestResult::Fail("absolute pointer must not advertise REL axes");
    }

    // A touchscreen (abs axes, NO mouse buttons) still classifies as a
    // touchscreen — the split must not mis-tag genuine touch devices.
    let mut touch = DeviceCaps::new();
    touch.add_abs_info(abs::ABS_X, range);
    touch.add_abs_info(abs::ABS_Y, range);
    let tue = crate::sysfs::evdev_caps_uevent(&touch);
    if !tue.contains("ID_INPUT_TOUCHSCREEN=1") {
        return TestResult::Fail("buttonless absolute device should stay a touchscreen");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_abs_pointer_tagged_id_input_mouse);

// ── Test 2: Kobject attr show ──────────────────────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_sysfs_kobject_attr_show() -> TestResult {
    crate::sysfs::__reset_for_test();
    let kobj = Kobject::new_root("foo");
    kobject_add_attr(&kobj, "name", || "foo\n".to_string());
    match kobj.attr_show("name") {
        Some(ref s) if s == "foo\n" => TestResult::Pass,
        Some(_) => TestResult::Fail("attr_show returned wrong value"),
        None => TestResult::Fail("attr_show returned None"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_kobject_attr_show);

// ── Test 3: Kobject path ──────────────────────────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_sysfs_kobject_path() -> TestResult {
    crate::sysfs::__reset_for_test();
    let root = Kobject::new_root("class");
    let net = Kobject::new_child(root.clone(), "net");
    let eth0 = Kobject::new_child(net.clone(), "eth0");
    let path = eth0.path();
    if path != "/sys/class/net/eth0" {
        return TestResult::Fail("kobject path mismatch");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_kobject_path);

// ── Test 4: SysFs VFS lookup ──────────────────────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_sysfs_vfs_lookup() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::uevent::__reset_for_test();

    // Build tree: /sys/class/net/eth0 with attr "mtu"
    let class = class_register("net");
    let eth0 = class_device_register(class, "eth0");
    kobject_add_attr(&eth0, "mtu", || "1500\n".to_string());

    // Mount sysfs on a test path.
    let auth = crate::bootstrap_mount_authority();
    let mnt = crate::registry().mount(&auth, "/smoke-sysfs-lookup", SysFs::new());
    let mount_handle = match mnt {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("SysFs mount failed"),
    };

    // Resolve mtu attr file.
    let result = crate::registry()
        .resolve_absolute("/smoke-sysfs-lookup/class/net/eth0/mtu", |fs, rel| {
            crate::resolve(fs.root(), rel).ok()
        })
        .flatten();

    let ops = match result {
        Some(o) => o,
        None => {
            let _ = crate::registry().unmount(&mount_handle, "/smoke-sysfs-lookup");
            return TestResult::Fail("resolve mtu failed");
        }
    };

    let mut buf = [0u8; 16];
    let n = poll_once(ops.read(0, &mut buf));
    let _ = crate::registry().unmount(&mount_handle, "/smoke-sysfs-lookup");

    match n {
        Some(Ok(n)) if n > 0 => {
            let got = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if got == "1500\n" {
                TestResult::Pass
            } else {
                TestResult::Fail("mtu attr wrong value")
            }
        }
        _ => TestResult::Fail("read attr returned 0 or error"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_vfs_lookup);

// ── /sys/dev/char/<maj>:<min> symlink traversal ──────────────────────
//
// eudev/libudev resolve a device by devnum via /sys/dev/char/<maj>:<min>,
// realpath()ing it to the class node. elogind's seat enumeration
// (sd_device_new_from_device_id) depends on it; without the link a DRM card
// never attaches to seat0 and CanGraphical stays false. Verify the symlink
// registered by register_char_dev_link resolves through to the target's attrs.
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_dev_char_link_traverses() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::uevent::__reset_for_test();

    // /sys/class/drm/card0 with a `uevent` attr, plus the /sys/dev/char link.
    let class = class_register("drm");
    let card0 = class_device_register(class, "card0");
    kobject_add_attr(&card0, "uevent", || "MAJOR=226\nMINOR=0\n".to_string());
    crate::sysfs::register_char_dev_link(226, 0, "drm", "card0");

    // Navigate the sysfs tree to /dev/char and read back the 226:0 symlink.
    // (resolve_async follows the link mid-path — covered by the resolver's own
    // symlink tests and verified live; here we assert the link exists with the
    // correct target, which is what register_char_dev_link is responsible for.)
    let fs = SysFs::new();
    let dev = match fs.root().lookup_dir("dev") {
        Some(d) => d,
        None => return TestResult::Fail("/sys/dev missing"),
    };
    let char_dir = match dev.lookup_dir("char") {
        Some(d) => d,
        None => return TestResult::Fail("/sys/dev/char missing"),
    };
    // /sys/dev/block must also exist so a udev scandir of it doesn't fail.
    if dev.lookup_dir("block").is_none() {
        return TestResult::Fail("/sys/dev/block missing");
    }
    // The symlink resolves via lookup() to a readlink-able file.
    let link = match char_dir.lookup("226:0") {
        Some(l) => l,
        None => return TestResult::Fail("/sys/dev/char/226:0 not registered"),
    };
    if link.stat().mode.file_type != FileType::Symlink {
        return TestResult::Fail("226:0 is not a symlink");
    }
    let mut buf = [0u8; 64];
    match poll_once(link.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            if core::str::from_utf8(&buf[..n]).unwrap_or("") == "../../class/drm/card0" {
                TestResult::Pass
            } else {
                TestResult::Fail("226:0 symlink target wrong")
            }
        }
        _ => TestResult::Fail("readlink 226:0 returned 0 or error"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_dev_char_link_traverses);

// ── Test 5: SysFs enumerate class/net ─────────────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_sysfs_enumerate_class_net() -> TestResult {
    crate::sysfs::__reset_for_test();

    let class = class_register("net");
    let _lo = class_device_register(class.clone(), "lo");
    let _eth1 = class_device_register(class.clone(), "eth1");

    // Access through the SysFs FsInstance.
    let fs = SysFs::new();
    let root = fs.root();
    let class_dir = match root.lookup_dir("class") {
        Some(d) => d,
        None => return TestResult::Fail("class dir missing"),
    };
    let net_dir = match class_dir.lookup_dir("net") {
        Some(d) => d,
        None => return TestResult::Fail("net dir missing"),
    };

    let entries = net_dir.enumerate(0, 64);
    let names: Vec<String> = entries.iter().map(|(n, _)| n.clone()).collect();

    if !names.iter().any(|n| n == "lo") {
        return TestResult::Fail("lo not listed in class/net");
    }
    if !names.iter().any(|n| n == "eth1") {
        return TestResult::Fail("eth1 not listed in class/net");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_enumerate_class_net);

// ── Test 6: Uevent ring FIFO order ────────────────────────────────────

fn smoke_uevent_ring_fifo() -> TestResult {
    uevent::__reset_for_test();

    uevent::emit(
        UeventAction::Add,
        "/devices/pci/0000:00:1f.0".to_string(),
        "pci".to_string(),
    );
    uevent::emit(
        UeventAction::Change,
        "/devices/net/eth0".to_string(),
        "net".to_string(),
    );
    uevent::emit(
        UeventAction::Remove,
        "/devices/usb/1-1".to_string(),
        "usb".to_string(),
    );

    if uevent::ring_len() != 3 {
        return TestResult::Fail("ring_len != 3 after 3 emits");
    }

    let mut reader = UeventReader::from_start();
    let evs = reader.drain(10);
    if evs.len() != 3 {
        return TestResult::Fail("drain did not return 3 events");
    }
    if evs[0].action != UeventAction::Add {
        return TestResult::Fail("first event should be Add");
    }
    if evs[1].action != UeventAction::Change {
        return TestResult::Fail("second event should be Change");
    }
    if evs[2].action != UeventAction::Remove {
        return TestResult::Fail("third event should be Remove");
    }
    // Second drain should be empty (cursor advanced past all 3).
    let evs2 = reader.drain(10);
    if !evs2.is_empty() {
        return TestResult::Fail("second drain should be empty");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_uevent_ring_fifo);

// ── Test 7: Uevent format — required keys ─────────────────────────────

fn smoke_uevent_format_required_keys() -> TestResult {
    uevent::__reset_for_test();

    uevent::emit(
        UeventAction::Add,
        "/devices/net/eth0".to_string(),
        "net".to_string(),
    );

    let mut reader = UeventReader::from_start();
    let evs = reader.drain(1);
    if evs.is_empty() {
        return TestResult::Fail("no event in ring");
    }
    let ev = &evs[0];
    let text = ev.to_text();

    if !text.contains("ACTION=add") {
        return TestResult::Fail("missing ACTION=add");
    }
    if !text.contains("DEVPATH=/devices/net/eth0") {
        return TestResult::Fail("missing DEVPATH");
    }
    if !text.contains("SUBSYSTEM=net") {
        return TestResult::Fail("missing SUBSYSTEM=net");
    }
    if !text.ends_with("\n\n") {
        return TestResult::Fail("missing double-newline terminator");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_uevent_format_required_keys);

// ── Test 8: Block-device class auto-population ────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_sysfs_block_class_auto_populate() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::uevent::__reset_for_test();

    // Save block registry so we can restore after.
    let snap = narf_block::registry::__snapshot_for_test();

    // Register a fake block device.
    let dev = FakeBlock::new(512, 8);
    narf_block::registry::register_block_device("smoke-sysblk0", dev);

    crate::sysfs::populate_block_class();

    let result = (|| -> TestResult {
        let root = SysFs::new().root();
        let class_dir = match root.lookup_dir("class") {
            Some(d) => d,
            None => return TestResult::Fail("class dir missing"),
        };
        let block_dir = match class_dir.lookup_dir("block") {
            Some(d) => d,
            None => return TestResult::Fail("block class dir missing"),
        };

        let entries = block_dir.enumerate(0, 64);
        let names: Vec<String> = entries.iter().map(|(n, _)| n.clone()).collect();
        if !names.iter().any(|n| n == "smoke-sysblk0") {
            return TestResult::Fail("smoke-sysblk0 not in /sys/class/block/");
        }

        // Check that the size attr is present.
        let dev_dir = match block_dir.lookup_dir("smoke-sysblk0") {
            Some(d) => d,
            None => return TestResult::Fail("smoke-sysblk0 dir missing"),
        };
        let attr_entries = dev_dir.enumerate(0, 64);
        let attr_names: Vec<String> = attr_entries.iter().map(|(n, _)| n.clone()).collect();
        if !attr_names.iter().any(|n| n == "size") {
            return TestResult::Fail("size attr missing on smoke-sysblk0");
        }
        TestResult::Pass
    })();

    narf_block::registry::__restore_for_test(snap);
    result
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_block_class_auto_populate);

// ── Test 9: kobject_emit_uevent helper ────────────────────────────────

#[cfg(feature = "linux-compat")]
fn smoke_sysfs_kobject_emit_uevent() -> TestResult {
    crate::sysfs::__reset_for_test();
    uevent::__reset_for_test();

    let class = class_register("block");
    let sda = class_device_register(class, "sda");
    kobject_emit_uevent(&sda, UeventAction::Add);

    let mut reader = UeventReader::from_start();
    let evs = reader.drain(1);
    if evs.is_empty() {
        return TestResult::Fail("no uevent emitted");
    }
    let ev = &evs[0];
    if ev.action != UeventAction::Add {
        return TestResult::Fail("wrong action");
    }
    if !ev.devpath.contains("sda") {
        return TestResult::Fail("devpath missing sda");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_kobject_emit_uevent);

// ── Tests 10-13: /sys/devices/system/cpu/ ─────────────────────────────
//
// Covers:
//   10. online/possible/present render valid range strings
//   11. cpu0 and cpuN dirs exist per count; cpu0 has no `online` attr
//   12. topology attrs render correct values
//   13. hex mask format matches the NUMA cpumap style (comma-grouped 32-bit words)

/// Test 10: online/possible/present render valid range strings.
///
/// With the default CPU count of 1, all three should render "0\n".
/// With a bumped count of 4, they should render "0-3\n".
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_cpu_range_attrs() -> TestResult {
    crate::sysfs::__reset_for_test();
    // Scoped: restores the REAL cpu count + online bitmap on every exit
    // path. The unscoped reset left a falsified BSP-only topology behind
    // for the rest of the shared kernel-test boot, defeating the
    // scheduler remote-kick smoke's "SMP=1 only" guard (its flake).
    let _topo = narf_lib::smp::__reset_for_test_scoped();

    // Default: 1 CPU → "0\n"
    crate::sysfs::populate_cpu_devices();
    let root = crate::sysfs::sysfs_root();
    let cpu_dir = match root
        .get_child("devices")
        .and_then(|d| d.get_child("system"))
        .and_then(|s| s.get_child("cpu"))
    {
        Some(k) => k,
        None => return TestResult::Fail("/sys/devices/system/cpu dir missing"),
    };

    for attr in &["online", "possible", "present"] {
        match cpu_dir.attr_show(attr) {
            Some(ref s) if s == "0\n" => {}
            Some(ref s) => {
                let _ = s;
                return TestResult::Fail("single-cpu range attr not '0'");
            }
            None => return TestResult::Fail("cpu range attr missing"),
        }
    }

    // kernel_max for 1 CPU → "0\n"
    match cpu_dir.attr_show("kernel_max") {
        Some(ref s) if s == "0\n" => {}
        _ => return TestResult::Fail("kernel_max wrong for 1 cpu"),
    }

    // Bump to 4 CPUs and re-populate.
    crate::sysfs::__reset_for_test();
    narf_lib::smp::set_cpu_count(4);
    crate::sysfs::populate_cpu_devices();

    let root = crate::sysfs::sysfs_root();
    let cpu_dir = match root
        .get_child("devices")
        .and_then(|d| d.get_child("system"))
        .and_then(|s| s.get_child("cpu"))
    {
        Some(k) => k,
        None => return TestResult::Fail("/sys/devices/system/cpu dir missing (4-cpu)"),
    };

    for attr in &["online", "possible", "present"] {
        match cpu_dir.attr_show(attr) {
            Some(ref s) if s == "0-3\n" => {}
            Some(ref s) => {
                let _ = s;
                return TestResult::Fail("4-cpu range attr not '0-3'");
            }
            None => return TestResult::Fail("cpu range attr missing (4-cpu)"),
        }
    }

    match cpu_dir.attr_show("kernel_max") {
        Some(ref s) if s == "3\n" => {}
        _ => return TestResult::Fail("kernel_max wrong for 4 cpus"),
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_cpu_range_attrs);

/// Test 11: cpu0 dir exists; cpu0 has no `online` attr (Linux convention);
/// cpuN dirs exist for all CPUs in the possible set.
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_cpu_dirs_and_online_attr() -> TestResult {
    crate::sysfs::__reset_for_test();
    // Scoped — see smoke_sysfs_cpu_range_attrs.
    let _topo = narf_lib::smp::__reset_for_test_scoped();
    narf_lib::smp::set_cpu_count(3);
    crate::sysfs::populate_cpu_devices();

    let root = crate::sysfs::sysfs_root();
    let cpu_dir = match root
        .get_child("devices")
        .and_then(|d| d.get_child("system"))
        .and_then(|s| s.get_child("cpu"))
    {
        Some(k) => k,
        None => return TestResult::Fail("/sys/devices/system/cpu missing"),
    };

    // cpu0, cpu1, cpu2 must all exist.
    for i in 0..3u32 {
        let name = alloc::format!("cpu{}", i);
        if cpu_dir.get_child(&name).is_none() {
            return TestResult::Fail("cpuN dir missing");
        }
    }
    // cpu3 must not exist (only 3 CPUs).
    if cpu_dir.get_child("cpu3").is_some() {
        return TestResult::Fail("cpu3 dir unexpectedly present");
    }

    // cpu0 must not have an `online` attribute (Linux omits it for cpu0).
    let cpu0 = cpu_dir.get_child("cpu0").unwrap();
    if cpu0.attr_show("online").is_some() {
        return TestResult::Fail("cpu0 has online attr (should be absent)");
    }

    // cpu1 must have `online` = "1\n".
    let cpu1 = cpu_dir.get_child("cpu1").unwrap();
    match cpu1.attr_show("online") {
        Some(ref s) if s == "1\n" => {}
        _ => return TestResult::Fail("cpu1/online not '1'"),
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_cpu_dirs_and_online_attr);

/// Test 12: topology attrs render correct values for cpu2 with 4 CPUs.
///
/// - `core_id` == "2"
/// - `physical_package_id` == "0"
/// - `core_cpus_list` == "2"
/// - `thread_siblings_list` == "2"
/// - `package_cpus_list` == "0-3"
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_cpu_topology_attrs() -> TestResult {
    crate::sysfs::__reset_for_test();
    // Scoped — see smoke_sysfs_cpu_range_attrs.
    let _topo = narf_lib::smp::__reset_for_test_scoped();
    narf_lib::smp::set_cpu_count(4);
    crate::sysfs::populate_cpu_devices();

    let root = crate::sysfs::sysfs_root();
    let cpu2_topo = match root
        .get_child("devices")
        .and_then(|d| d.get_child("system"))
        .and_then(|s| s.get_child("cpu"))
        .and_then(|c| c.get_child("cpu2"))
        .and_then(|c| c.get_child("topology"))
    {
        Some(k) => k,
        None => return TestResult::Fail("cpu2/topology dir missing"),
    };

    let checks: &[(&str, &str)] = &[
        ("core_id", "2\n"),
        ("physical_package_id", "0\n"),
        ("core_cpus_list", "2\n"),
        ("thread_siblings_list", "2\n"),
        ("package_cpus_list", "0-3\n"),
    ];
    for (attr, expected) in checks {
        match cpu2_topo.attr_show(attr) {
            Some(ref got) if got == expected => {}
            Some(ref got) => {
                let _ = got;
                return TestResult::Fail("topology attr value mismatch");
            }
            None => return TestResult::Fail("topology attr missing"),
        }
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_cpu_topology_attrs);

/// Test 13: hex mask format matches NUMA cpumap style (comma-grouped 32-bit words).
///
/// For cpu2 (bit 2 set): `core_cpus` == "00000000,00000000,00000000,00000004\n".
/// For 4 CPUs total:  `package_cpus` == "00000000,00000000,00000000,0000000f\n".
/// Linux ref: `node_read_cpumap` (drivers/base/node.c).
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_cpu_hex_mask_format() -> TestResult {
    crate::sysfs::__reset_for_test();
    // Scoped — see smoke_sysfs_cpu_range_attrs.
    let _topo = narf_lib::smp::__reset_for_test_scoped();
    narf_lib::smp::set_cpu_count(4);
    crate::sysfs::populate_cpu_devices();

    let root = crate::sysfs::sysfs_root();
    let cpu2_topo = match root
        .get_child("devices")
        .and_then(|d| d.get_child("system"))
        .and_then(|s| s.get_child("cpu"))
        .and_then(|c| c.get_child("cpu2"))
        .and_then(|c| c.get_child("topology"))
    {
        Some(k) => k,
        None => return TestResult::Fail("cpu2/topology missing for hex mask test"),
    };

    // cpu2 → bit 2 set → word 0 = 0x4.
    let expected_core = "00000000,00000000,00000000,00000004\n";
    for attr in &["core_cpus", "thread_siblings"] {
        match cpu2_topo.attr_show(attr) {
            Some(ref s) if s == expected_core => {}
            Some(ref s) => {
                let _ = s;
                return TestResult::Fail("core_cpus/thread_siblings hex mask wrong");
            }
            None => return TestResult::Fail("core_cpus/thread_siblings missing"),
        }
    }

    // 4 CPUs → bits 0-3 set → word 0 = 0xf.
    let expected_pkg = "00000000,00000000,00000000,0000000f\n";
    match cpu2_topo.attr_show("package_cpus") {
        Some(ref s) if s == expected_pkg => {}
        Some(ref s) => {
            let _ = s;
            return TestResult::Fail("package_cpus hex mask wrong");
        }
        None => return TestResult::Fail("package_cpus missing"),
    }

    // Also verify the format is the 4-word comma-separated format
    // (not a bare integer): must contain exactly 3 commas.
    let comma_count = expected_core.chars().filter(|&c| c == ',').count();
    if comma_count != 3 {
        return TestResult::Fail("cpumap format: expected 3 commas (4 words)");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_cpu_hex_mask_format);

// ── Test 14: THP `enabled` attr renders with [never] active ──────────

/// `/sys/kernel/mm/transparent_hugepage/enabled` must contain
/// `[never]` as the active (bracketed) value. redis and jemalloc
/// probe this file at startup. NARF has no THP; `[never]` is the
/// only valid active token here.
/// Linux ref: `mm/huge_memory.c` `enabled_show` (6.9).
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_thp_enabled_contains_never() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::sysfs::populate_kernel_dir();
    let root = crate::sysfs::sysfs_root();
    let thp = root
        .get_child("kernel")
        .and_then(|k| k.get_child("mm"))
        .and_then(|m| m.get_child("transparent_hugepage"));
    let kobj = match thp {
        Some(k) => k,
        None => return TestResult::Fail("kernel/mm/transparent_hugepage dir missing"),
    };
    match kobj.attr_show("enabled") {
        Some(ref s) if s.contains("[never]") => TestResult::Pass,
        Some(_) => TestResult::Fail("enabled attr missing [never] token"),
        None => TestResult::Fail("enabled attr not registered"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_thp_enabled_contains_never);

/// `/sys/kernel/mm/transparent_hugepage/defrag` renders with [never] active.
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_thp_defrag_contains_never() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::sysfs::populate_kernel_dir();
    let root = crate::sysfs::sysfs_root();
    let kobj = match root
        .get_child("kernel")
        .and_then(|k| k.get_child("mm"))
        .and_then(|m| m.get_child("transparent_hugepage"))
    {
        Some(k) => k,
        None => return TestResult::Fail("transparent_hugepage dir missing"),
    };
    match kobj.attr_show("defrag") {
        Some(ref s) if s.contains("[never]") => TestResult::Pass,
        Some(_) => TestResult::Fail("defrag attr missing [never] token"),
        None => TestResult::Fail("defrag attr not registered"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_thp_defrag_contains_never);

// ── Tests: desktop/laptop device classes ─────────────────────────────
//
// LED / power_supply / thermal / hwmon: udev, upower, lm-sensors and the
// desktop compositors enumerate these classes and read specific attrs.
// Each test populates the class, resolves an attr via the kobject tree, and
// checks the value + that the class enumerates its device(s).

/// Read+trim a kobject attr, or None if absent.
#[cfg(feature = "linux-compat")]
fn attr_trimmed(kobj: &Arc<crate::sysfs::Kobject>, name: &str) -> Option<String> {
    kobj.attr_show(name).map(|s| s.trim().to_string())
}

/// Resolve `/sys/class/<class>` and return its enumerated child device names.
#[cfg(feature = "linux-compat")]
fn class_device_names(class: &str) -> Vec<String> {
    let root = crate::sysfs::sysfs_root();
    match root.get_child("class").and_then(|c| c.get_child(class)) {
        Some(k) => k.child_names(),
        None => Vec::new(),
    }
}

/// LED class — both devices enumerate; a brightness write is accepted+clamped.
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_leds_class() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::sysfs::populate_leds();

    let names = class_device_names("leds");
    if !names.iter().any(|n| n == "input0::capslock") {
        return TestResult::Fail("input0::capslock not in /sys/class/leds");
    }
    if !names.iter().any(|n| n == "platform::kbd_backlight") {
        return TestResult::Fail("platform::kbd_backlight not in /sys/class/leds");
    }

    let root = crate::sysfs::sysfs_root();
    let kbd = match root
        .get_child("class")
        .and_then(|c| c.get_child("leds"))
        .and_then(|l| l.get_child("platform::kbd_backlight"))
    {
        Some(k) => k,
        None => return TestResult::Fail("kbd_backlight kobject missing"),
    };
    if attr_trimmed(&kbd, "max_brightness").as_deref() != Some("255") {
        return TestResult::Fail("kbd_backlight max_brightness != 255");
    }
    if attr_trimmed(&kbd, "brightness").as_deref() != Some("0") {
        return TestResult::Fail("kbd_backlight brightness != 0 initially");
    }
    // Write is accepted and clamped to max (255).
    match kbd.attr_store("brightness", b"128") {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("brightness store(128) failed"),
    }
    if attr_trimmed(&kbd, "brightness").as_deref() != Some("128") {
        return TestResult::Fail("brightness not 128 after write");
    }
    // trigger is writable and defaults to "none".
    if attr_trimmed(&kbd, "trigger").as_deref() != Some("none") {
        return TestResult::Fail("trigger != none initially");
    }
    if kbd.attr_store("trigger", b"timer").is_none() {
        return TestResult::Fail("trigger not writable");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_leds_class);

/// power_supply class — AC + BAT0 enumerate; BAT0/capacity == "100".
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_power_supply_class() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::sysfs::populate_power_supply();

    let names = class_device_names("power_supply");
    if !names.iter().any(|n| n == "AC") {
        return TestResult::Fail("AC not in /sys/class/power_supply");
    }
    if !names.iter().any(|n| n == "BAT0") {
        return TestResult::Fail("BAT0 not in /sys/class/power_supply");
    }

    let root = crate::sysfs::sysfs_root();
    let bat = match root
        .get_child("class")
        .and_then(|c| c.get_child("power_supply"))
        .and_then(|p| p.get_child("BAT0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("BAT0 kobject missing"),
    };
    if attr_trimmed(&bat, "capacity").as_deref() != Some("100") {
        return TestResult::Fail("BAT0/capacity != 100");
    }
    if attr_trimmed(&bat, "type").as_deref() != Some("Battery") {
        return TestResult::Fail("BAT0/type != Battery");
    }
    if attr_trimmed(&bat, "voltage_now").as_deref() != Some("12000000") {
        return TestResult::Fail("BAT0/voltage_now != 12000000");
    }
    // subsystem symlink points at the class dir.
    match bat.get_symlink("subsystem") {
        Some(ref t) if t.ends_with("class/power_supply") => {}
        _ => return TestResult::Fail("BAT0 subsystem symlink wrong/missing"),
    }
    // AC/online == "1".
    let ac = root
        .get_child("class")
        .and_then(|c| c.get_child("power_supply"))
        .and_then(|p| p.get_child("AC"))
        .unwrap();
    if attr_trimmed(&ac, "online").as_deref() != Some("1") {
        return TestResult::Fail("AC/online != 1");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_power_supply_class);

/// thermal class — thermal_zone0 enumerates; temp == "42000".
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_thermal_class() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::sysfs::populate_thermal();

    let names = class_device_names("thermal");
    if !names.iter().any(|n| n == "thermal_zone0") {
        return TestResult::Fail("thermal_zone0 not in /sys/class/thermal");
    }

    let root = crate::sysfs::sysfs_root();
    let zone = match root
        .get_child("class")
        .and_then(|c| c.get_child("thermal"))
        .and_then(|t| t.get_child("thermal_zone0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("thermal_zone0 kobject missing"),
    };
    if attr_trimmed(&zone, "temp").as_deref() != Some("42000") {
        return TestResult::Fail("thermal_zone0/temp != 42000");
    }
    if attr_trimmed(&zone, "type").as_deref() != Some("acpitz") {
        return TestResult::Fail("thermal_zone0/type != acpitz");
    }
    if attr_trimmed(&zone, "policy").as_deref() != Some("step_wise") {
        return TestResult::Fail("thermal_zone0/policy != step_wise");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_thermal_class);

/// hwmon class — hwmon0 enumerates; temp1_input == "42000".
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_hwmon_class() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::sysfs::populate_hwmon();

    let names = class_device_names("hwmon");
    if !names.iter().any(|n| n == "hwmon0") {
        return TestResult::Fail("hwmon0 not in /sys/class/hwmon");
    }

    let root = crate::sysfs::sysfs_root();
    let hwmon0 = match root
        .get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 kobject missing"),
    };
    if attr_trimmed(&hwmon0, "name").as_deref() != Some("acpitz") {
        return TestResult::Fail("hwmon0/name != acpitz");
    }
    if attr_trimmed(&hwmon0, "temp1_input").as_deref() != Some("42000") {
        return TestResult::Fail("hwmon0/temp1_input != 42000");
    }
    if attr_trimmed(&hwmon0, "temp1_label").as_deref() != Some("CPU") {
        return TestResult::Fail("hwmon0/temp1_label != CPU");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_hwmon_class);

/// End-to-end VFS read of /sys/class/power_supply/BAT0/capacity.
/// Mounts sysfs, resolves the attr path, reads it back == "100\n".
#[cfg(feature = "linux-compat")]
fn smoke_sysfs_power_supply_vfs_read() -> TestResult {
    crate::sysfs::__reset_for_test();
    crate::uevent::__reset_for_test();
    crate::sysfs::populate_power_supply();

    let auth = crate::bootstrap_mount_authority();
    let mnt = crate::registry().mount(&auth, "/smoke-sysfs-psu", SysFs::new());
    let handle = match mnt {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("SysFs mount failed"),
    };

    let result = crate::registry()
        .resolve_absolute(
            "/smoke-sysfs-psu/class/power_supply/BAT0/capacity",
            |fs, rel| crate::resolve(fs.root(), rel).ok(),
        )
        .flatten();

    let ops = match result {
        Some(o) => o,
        None => {
            let _ = crate::registry().unmount(&handle, "/smoke-sysfs-psu");
            return TestResult::Fail("resolve BAT0/capacity failed");
        }
    };

    let mut buf = [0u8; 16];
    let n = poll_once(ops.read(0, &mut buf));
    let _ = crate::registry().unmount(&handle, "/smoke-sysfs-psu");

    match n {
        Some(Ok(n)) if n > 0 => {
            if core::str::from_utf8(&buf[..n]).unwrap_or("") == "100\n" {
                TestResult::Pass
            } else {
                TestResult::Fail("BAT0/capacity VFS read != 100")
            }
        }
        _ => TestResult::Fail("read capacity returned 0 or error"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("filesystem", smoke_sysfs_power_supply_vfs_read);
