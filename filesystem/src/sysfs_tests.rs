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

use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_emit_uevent, Kobject,
    SysFs,
};
use crate::uevent::{self, UeventAction, UeventReader};
use crate::FsInstance;

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
    fn new(lba_size: u32, cap: u64) -> Arc<dyn narf_block::BlockDeviceSync> {
        Arc::new(Self {
            data: narf_lib::sync::IrqSafeSpinLock::new(
                vec![0u8; (lba_size as usize) * (cap as usize)],
            ),
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
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

// ── Test 1: Kobject create with parent ────────────────────────────────

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
kernel_test_in!("filesystem", smoke_sysfs_kobject_create_with_parent);

// ── Test 2: Kobject attr show ──────────────────────────────────────────

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
kernel_test_in!("filesystem", smoke_sysfs_kobject_attr_show);

// ── Test 3: Kobject path ──────────────────────────────────────────────

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
kernel_test_in!("filesystem", smoke_sysfs_kobject_path);

// ── Test 4: SysFs VFS lookup ──────────────────────────────────────────

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
kernel_test_in!("filesystem", smoke_sysfs_vfs_lookup);

// ── Test 5: SysFs enumerate class/net ─────────────────────────────────

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
kernel_test_in!("filesystem", smoke_sysfs_block_class_auto_populate);

// ── Test 9: kobject_emit_uevent helper ────────────────────────────────

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
kernel_test_in!("filesystem", smoke_sysfs_kobject_emit_uevent);
