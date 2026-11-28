//! In-kernel smokes for module-backed disks (`module_block.rs`).
//!
//! No module text runs here. Disks are registered under the kernel's own
//! owner id, so the request path calls the kernel-side fake callback below
//! directly instead of through the module call gate. The end-to-end proof
//! with real module text driving a real controller is `cargo narf
//! nvme-module-block-smoke`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use narf_block::registry::{BlockDeviceSync, BlockIoError};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::{
    copy, register_unchecked, retire_owner, DiskSpec, Endpoint, ModuleDisk, DISKS, FLAG_READ_ONLY,
    FLAG_VOLATILE_CACHE, OP_FLUSH, OP_READ, OP_WRITE,
};

const OWNER: u64 = crate::symbols::KERNEL_MODULE_ID.0;
const TOKEN: u64 = 0xB10C_0000_0000_0001;
/// A DMA handle no bus context owns.
const DMA: Endpoint = Endpoint::Dma {
    handle: 1,
    offset: 0,
};

/// `(cookie, op, lba, count)` of every request the fake callback saw.
static CALLS: IrqSafeSpinLock<Vec<(u64, u32, u64, u32)>> = IrqSafeSpinLock::new(Vec::new());
/// What the fake callback returns.
static RESULT: AtomicI32 = AtomicI32::new(0);
/// Copy results the fake callback collected while a request ran.
static COPIES: IrqSafeSpinLock<Vec<i32>> = IrqSafeSpinLock::new(Vec::new());
/// Request id the fake callback saw last.
static LAST_REQUEST: AtomicU64 = AtomicU64::new(0);

extern "C" fn fake_request(cookie: u64, request: u64, op: u32, lba: u64, count: u32) -> i32 {
    CALLS.lock().push((cookie, op, lba, count));
    LAST_REQUEST.store(request, Ordering::Relaxed);
    RESULT.load(Ordering::Relaxed)
}

/// Exercises `copy` from inside a running request. No bus context exists
/// for `TOKEN`, so a copy that passes the request checks fails in the DMA
/// lookup (`-EINVAL`); the checks themselves are what is under test.
extern "C" fn copying_request(_: u64, request: u64, op: u32, _: u64, count: u32) -> i32 {
    let len = count as usize * 512;
    let read = op == OP_READ;
    let mut results = COPIES.lock();
    // The wrong owner, the wrong token, and a request that is not running.
    results.push(copy(OWNER + 1, TOKEN, request, DMA, 0..len, read));
    results.push(copy(OWNER, TOKEN + 1, request, DMA, 0..len, read));
    results.push(copy(OWNER, TOKEN, request + 1000, DMA, 0..len, read));
    // The wrong direction, an empty range, and a range past the buffer.
    results.push(copy(OWNER, TOKEN, request, DMA, 0..len, !read));
    results.push(copy(OWNER, TOKEN, request, DMA, 8..8, read));
    results.push(copy(OWNER, TOKEN, request, DMA, 0..len + 1, read));
    // Well formed: reaches the DMA lookup, which has no context.
    results.push(copy(OWNER, TOKEN, request, DMA, 0..len, read));
    LAST_REQUEST.store(request, Ordering::Relaxed);
    0
}

fn spec(capacity: u64, max_blocks: u32, flags: u32) -> DiskSpec {
    DiskSpec {
        lba_size: 512,
        capacity,
        max_blocks,
        flags,
        request: fake_request,
        cookie: 0xC00C,
    }
}

fn disk_named(name: &str) -> Option<ModuleDisk> {
    DISKS
        .lock()
        .iter()
        .find(|d| d.name == name)
        .map(|d| ModuleDisk(Arc::clone(d)))
}

fn reset() {
    retire_owner(OWNER);
    CALLS.lock().clear();
    COPIES.lock().clear();
    RESULT.store(0, Ordering::Relaxed);
}

fn smoke_module_block_register_validates() -> TestResult {
    reset();
    let bad = [
        (&b""[..], spec(64, 8, 0)),
        (&b"Upper"[..], spec(64, 8, 0)),
        (&b"0lead"[..], spec(64, 8, 0)),
        (&b"has space"[..], spec(64, 8, 0)),
        (&b"a-name-that-is-longer-than-31-bytes"[..], spec(64, 8, 0)),
        (&b"mblkt"[..], spec(0, 8, 0)),
        (&b"mblkt"[..], spec(64, 0, 0)),
        // 4096 blocks of 512 bytes is 2 MiB, over the 1 MiB request cap.
        (&b"mblkt"[..], spec(64, 4096, 0)),
        (&b"mblkt"[..], spec(64, 8, 1 << 7)),
        (
            &b"mblkt"[..],
            DiskSpec {
                lba_size: 1000,
                ..spec(64, 8, 0)
            },
        ),
        (
            &b"mblkt"[..],
            DiskSpec {
                lba_size: 8192,
                ..spec(64, 8, 0)
            },
        ),
    ];
    for (name, spec) in bad {
        if register_unchecked(OWNER, TOKEN, name, spec) != -22 {
            reset();
            return TestResult::Fail("a malformed disk name or geometry was accepted");
        }
    }
    if register_unchecked(OWNER, TOKEN, b"mblkt0", spec(64, 8, 0)) != 0 {
        reset();
        return TestResult::Fail("a well-formed disk was refused");
    }
    let listed = narf_block::block_devices()
        .iter()
        .any(|d| d.name == "mblkt0");
    let duplicate = register_unchecked(OWNER, TOKEN, b"mblkt0", spec(64, 8, 0));
    let mut filled = true;
    for i in 1..super::MAX_DISKS_PER_OWNER {
        let name = alloc::format!("mblkt{i}");
        filled &= register_unchecked(OWNER, TOKEN, name.as_bytes(), spec(64, 8, 0)) == 0;
    }
    let over = register_unchecked(OWNER, TOKEN, b"mblkt9", spec(64, 8, 0));
    let held = super::__disk_count_for_test(OWNER);
    reset();
    let gone = super::__disk_count_for_test(OWNER) == 0
        && !narf_block::block_devices()
            .iter()
            .any(|d| d.name.starts_with("mblkt"));
    if !listed {
        return TestResult::Fail("a module disk did not join the block registry");
    }
    if duplicate != -17 {
        return TestResult::Fail("a taken disk name was not -EEXIST");
    }
    if !filled || over != -28 || held != super::MAX_DISKS_PER_OWNER {
        return TestResult::Fail("the per-module disk limit was not enforced with -ENOSPC");
    }
    if !gone {
        return TestResult::Fail("retiring the owner left a disk registered");
    }
    TestResult::Pass
}
kernel_test_in!("modules/block", smoke_module_block_register_validates);

fn smoke_module_block_splits_and_maps_requests() -> TestResult {
    reset();
    if register_unchecked(OWNER, TOKEN, b"mblks0", spec(64, 4, 0)) != 0 {
        reset();
        return TestResult::Fail("could not register the test disk");
    }
    let Some(disk) = disk_named("mblks0") else {
        reset();
        return TestResult::Fail("registered disk not found");
    };
    CALLS.lock().clear();
    let mut buf = [0u8; 10 * 512];
    let read = disk.read(6, 10, &mut buf);
    let split = CALLS.lock().clone();
    let expected = [
        (0xC00C, OP_READ, 6, 4),
        (0xC00C, OP_READ, 10, 4),
        (0xC00C, OP_READ, 14, 2),
    ];
    CALLS.lock().clear();
    let write = disk.write(0, 1, &buf[..512]);
    let wrote = CALLS.lock().clone();
    CALLS.lock().clear();
    let out_of_range = disk.read(60, 5, &mut buf);
    let short = disk.read(0, 2, &mut buf[..600]);
    let untouched = CALLS.lock().is_empty();
    RESULT.store(-5, Ordering::Relaxed);
    let driver = disk.read(0, 1, &mut buf);
    RESULT.store(-19, Ordering::Relaxed);
    let removed = disk.read(0, 1, &mut buf);
    RESULT.store(0, Ordering::Relaxed);
    CALLS.lock().clear();
    let flush = disk.flush();
    let flush_called = !CALLS.lock().is_empty();
    reset();
    let after_retire = disk.read(0, 1, &mut buf);
    let called_after = !CALLS.lock().is_empty();

    if read.is_err() || split.as_slice() != expected {
        return TestResult::Fail("a 10-block read was not split into 4 + 4 + 2 requests");
    }
    if write.is_err() || wrote.as_slice() != [(0xC00C, OP_WRITE, 0, 1)] {
        return TestResult::Fail("a write did not reach the module as one write request");
    }
    if out_of_range != Err(BlockIoError::OutOfRange)
        || short != Err(BlockIoError::BufferTooSmall)
        || !untouched
    {
        return TestResult::Fail("a bad range or short buffer reached the module");
    }
    if driver != Err(BlockIoError::DriverError) || removed != Err(BlockIoError::DeviceRemoved) {
        return TestResult::Fail("module errnos were not mapped to block errors");
    }
    if flush.is_err() || flush_called || disk.has_real_flush() || disk.capabilities().volatile_cache
    {
        return TestResult::Fail("a write-through disk sent a flush to the module");
    }
    if after_retire != Err(BlockIoError::DeviceRemoved) || called_after {
        return TestResult::Fail("a retired disk still called into the module");
    }
    TestResult::Pass
}
kernel_test_in!("modules/block", smoke_module_block_splits_and_maps_requests);

fn smoke_module_block_flags() -> TestResult {
    reset();
    let flags = FLAG_VOLATILE_CACHE | FLAG_READ_ONLY;
    if register_unchecked(OWNER, TOKEN, b"mblkf0", spec(64, 8, flags)) != 0 {
        reset();
        return TestResult::Fail("could not register the test disk");
    }
    let Some(disk) = disk_named("mblkf0") else {
        reset();
        return TestResult::Fail("registered disk not found");
    };
    CALLS.lock().clear();
    let write = disk.write(0, 1, &[0u8; 512]);
    let wrote = !CALLS.lock().is_empty();
    let flush = disk.flush();
    let flushed = CALLS.lock().clone();
    let (read_only, real_flush, caps) = (
        disk.is_read_only(),
        disk.has_real_flush(),
        disk.capabilities(),
    );
    reset();
    if write != Err(BlockIoError::ReadOnly) || wrote || !read_only {
        return TestResult::Fail("a read-only module disk let a write through");
    }
    if flush.is_err() || flushed.as_slice() != [(0xC00C, OP_FLUSH, 0, 0)] {
        return TestResult::Fail("a volatile-cache disk did not send one flush request");
    }
    if !real_flush || !caps.volatile_cache || caps.fua {
        return TestResult::Fail("a volatile-cache disk advertised the wrong flush caps");
    }
    TestResult::Pass
}
kernel_test_in!("modules/block", smoke_module_block_flags);

fn smoke_module_block_copy_checks_request() -> TestResult {
    reset();
    let spec = DiskSpec {
        request: copying_request,
        ..spec(64, 8, 0)
    };
    if register_unchecked(OWNER, TOKEN, b"mblkc0", spec) != 0 {
        reset();
        return TestResult::Fail("could not register the test disk");
    }
    let Some(disk) = disk_named("mblkc0") else {
        reset();
        return TestResult::Fail("registered disk not found");
    };
    COPIES.lock().clear();
    let mut buf = [0u8; 1024];
    let read = disk.read(0, 2, &mut buf);
    let during_read = COPIES.lock().clone();
    COPIES.lock().clear();
    let write = disk.write(0, 2, &buf);
    let during_write = COPIES.lock().clone();
    let finished = LAST_REQUEST.load(Ordering::Relaxed);
    let stale = copy(OWNER, TOKEN, finished, DMA, 0..512, false);
    reset();
    if read.is_err() || write.is_err() {
        return TestResult::Fail("the copying request callback failed");
    }
    for results in [&during_read, &during_write] {
        if results.len() != 7 || results.iter().any(|&rc| rc != -22) {
            return TestResult::Fail(
                "a copy with a bad owner, token, id, direction or range passed",
            );
        }
    }
    if stale != -22 {
        return TestResult::Fail("a finished request still accepted a copy");
    }
    TestResult::Pass
}
kernel_test_in!("modules/block", smoke_module_block_copy_checks_request);

/// Bytes the module-memory callback serves for reads.
static PATTERN: [u8; 1024] = {
    let mut p = [0u8; 1024];
    let mut i = 0;
    while i < p.len() {
        p[i] = (i as u8).wrapping_mul(7) ^ 0x5A;
        i += 1;
    }
    p
};
/// Where the module-memory callback lands writes.
static SINK: IrqSafeSpinLock<[u8; 1024]> = IrqSafeSpinLock::new([0; 1024]);

/// A USB-style driver: reads are filled from module memory, writes are
/// fetched into module memory.
extern "C" fn module_memory_request(_: u64, request: u64, op: u32, _: u64, count: u32) -> i32 {
    let len = count as usize * 512;
    if op == OP_READ {
        let side = Endpoint::Module(PATTERN.as_ptr() as usize);
        copy(OWNER, TOKEN, request, side, 0..len, true)
    } else {
        let mut sink = SINK.lock();
        let side = Endpoint::Module(sink.as_mut_ptr() as usize);
        copy(OWNER, TOKEN, request, side, 0..len, false)
    }
}

fn smoke_module_block_module_memory_copy() -> TestResult {
    reset();
    let spec = DiskSpec {
        request: module_memory_request,
        ..spec(64, 2, 0)
    };
    if register_unchecked(OWNER, TOKEN, b"mblkm0", spec) != 0 {
        reset();
        return TestResult::Fail("could not register the test disk");
    }
    let Some(disk) = disk_named("mblkm0") else {
        reset();
        return TestResult::Fail("registered disk not found");
    };
    // Four blocks over a two-block maximum: two requests, each copying the
    // same 1 KiB pattern, so both halves must match it.
    let mut buf = [0u8; 2048];
    let read = disk.read(0, 4, &mut buf);
    let data: alloc::vec::Vec<u8> = (0..2048u32)
        .map(|i| ((i % 1024) as u8).wrapping_mul(7) ^ 0x5A)
        .collect();
    let mut written = [0u8; 1024];
    for (i, b) in written.iter_mut().enumerate() {
        *b = !(i as u8);
    }
    *SINK.lock() = [0; 1024];
    let write = disk.write(0, 2, &written);
    let landed = *SINK.lock() == written;
    reset();
    if read.is_err() || buf.as_slice() != data.as_slice() {
        return TestResult::Fail("a read did not return the module-memory bytes");
    }
    if write.is_err() || !landed {
        return TestResult::Fail("a write did not land in module memory");
    }
    TestResult::Pass
}
kernel_test_in!("modules/block", smoke_module_block_module_memory_copy);

fn smoke_module_block_retire_token_is_per_device() -> TestResult {
    reset();
    let a = register_unchecked(OWNER, TOKEN, b"mblkr0", spec(64, 8, 0));
    let b = register_unchecked(OWNER, TOKEN + 1, b"mblkr1", spec(64, 8, 0));
    if a != 0 || b != 0 {
        reset();
        return TestResult::Fail("could not register the test disks");
    }
    // The bus reports a retired context through the hook the module
    // subsystem installs at boot (installed again here; it is idempotent).
    narf_bus::set_module_context_retired_hook(super::retire_token);
    narf_bus::module_context_retired(OWNER, TOKEN);
    let first_gone = disk_named("mblkr0").is_none()
        && !narf_block::block_devices()
            .iter()
            .any(|d| d.name == "mblkr0");
    let second_kept = disk_named("mblkr1").is_some();
    reset();
    if !first_gone {
        return TestResult::Fail("a retired device context left its disk registered");
    }
    if !second_kept {
        return TestResult::Fail("retiring one device context removed another device's disk");
    }
    TestResult::Pass
}
kernel_test_in!(
    "modules/block",
    smoke_module_block_retire_token_is_per_device
);
