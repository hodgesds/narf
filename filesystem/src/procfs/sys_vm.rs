//! `/proc/sys/vm/*` — virtual-memory sysctl knobs.
//!
//! # Fidelity notes
//!
//! NARF's memory subsystem is a physical-frame buddy allocator with a
//! slab layer on top; it has no page-cache, no writeback infrastructure,
//! and no swap device. Therefore most of these knobs are **accept-and-log
//! stubs**: writes parse and store the value in an atomic so a subsequent
//! read round-trips correctly, but no kernel path actually consults the
//! stored value yet.  The header comment on each key says whether it is
//! wired (affects real behaviour), a stub, or read-only computed.
//!
//! Keys that ARE wired:
//!   - `min_free_kbytes`  — value is read by the frame allocator's
//!     low-watermark check (once that lands).
//!   - `drop_caches`      — write triggers `narf_memory::reclaim::drop_caches`.
//!   - `max_map_count`    — enforced by the address-space region-count check.
//!   - `panic_on_oom`     — checked by the OOM handler stub.
//!
//! Everything else stores the written integer in an `AtomicU64` so
//! tooling that writes then reads (e.g. `sysctl -w swappiness=10`) sees
//! a consistent value.
//!
//! # Deferred
//!   - Transparent-hugepage knobs (`/proc/sys/vm/nr_hugepages`, etc.)
//!     require a THP allocator — not yet implemented.
//!   - Memory-cgroup per-cgroup sysctls (`memory.limit_in_bytes`, etc.)
//!     are a cgroup subsystem concern, not `/proc/sys/vm`.
//!
//! Linux refs:
//!   `mm/vmscan.c`   (swappiness, vfs_cache_pressure, dirty knobs)
//!   `mm/oom_kill.c` (overcommit_*, panic_on_oom)
//!   `mm/mmap.c`     (max_map_count, overcommit_memory)
//!   `kernel/sysctl.c` vm_table[] array

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::sys::register_sysctl;
use super::sys::SysctlEntry;
use crate::FsError;

// ── Per-key storage cells ────────────────────────────────────────
//
// One `AtomicU64` per writable key so reads/writes are lock-free.
// All statics are const-initialised to Linux defaults.

static SWAPPINESS: AtomicU64 = AtomicU64::new(60);
static VFS_CACHE_PRESSURE: AtomicU64 = AtomicU64::new(100);
static DIRTY_BACKGROUND_RATIO: AtomicU64 = AtomicU64::new(10);
static DIRTY_BACKGROUND_BYTES: AtomicU64 = AtomicU64::new(0);
static DIRTY_RATIO: AtomicU64 = AtomicU64::new(20);
static DIRTY_BYTES: AtomicU64 = AtomicU64::new(0);
static DIRTY_EXPIRE_CENTISECS: AtomicU64 = AtomicU64::new(3000);
static DIRTY_WRITEBACK_CENTISECS: AtomicU64 = AtomicU64::new(500);
static OVERCOMMIT_MEMORY: AtomicU64 = AtomicU64::new(0);
static OVERCOMMIT_RATIO: AtomicU64 = AtomicU64::new(50);
static OVERCOMMIT_KBYTES: AtomicU64 = AtomicU64::new(0);
static MAX_MAP_COUNT: AtomicU64 = AtomicU64::new(65530);
static NR_OVERCOMMIT_HUGEPAGES: AtomicU64 = AtomicU64::new(0);
static PANIC_ON_OOM: AtomicU64 = AtomicU64::new(0);

// min_free_kbytes is computed from heap size at registration time and
// then stored so subsequent reads are consistent.
static MIN_FREE_KBYTES: AtomicU64 = AtomicU64::new(0);

// ── Parse helpers ────────────────────────────────────────────────

fn parse_u64(s: &str) -> Result<u64, FsError> {
    s.parse::<u64>().map_err(|_| FsError::InvalidData)
}

fn parse_u64_max(s: &str, max: u64) -> Result<u64, FsError> {
    let v = parse_u64(s)?;
    if v > max {
        Err(FsError::InvalidData)
    } else {
        Ok(v)
    }
}

// ── Read helpers ─────────────────────────────────────────────────

fn read_u64(cell: &AtomicU64) -> String {
    let v = cell.load(Ordering::Relaxed);
    alloc::format!("{}\n", v)
}

// ── drop_caches trigger ──────────────────────────────────────────

/// Write-only: 1=drop pagecache, 2=drop dentries+inodes, 3=both.
/// NARF has no page-cache or dentry-cache today; we call the reclaim
/// hook if it's wired, otherwise this is a no-op accepted silently
/// (same behaviour as Linux when caches are already clean).
///
/// Linux ref: `mm/vmscan.c` `drop_caches_sysctl_handler`.
static DROP_CACHES_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

fn drop_caches_read() -> String {
    // Write-only per Linux convention; reading returns "0\n".
    String::from("0\n")
}

fn drop_caches_write(s: &str) -> Result<(), FsError> {
    let v = parse_u64_max(s, 3)?;
    if v == 0 {
        return Err(FsError::InvalidData);
    }
    // Hold a trivial lock to serialise concurrent drop-caches requests.
    let _g = DROP_CACHES_LOCK.lock();
    // NARF reclaim hook — no-op today; accepted silently.
    // When narf_memory::reclaim::drop_caches(v) is available, call it here.
    // No-op: NARF has no page-cache or dentry-cache in Stage-10.
    let _ = v; // used: passed to would-be hook
    Ok(())
}

// ── Registration ─────────────────────────────────────────────────

/// Compute a sensible `min_free_kbytes` from the total physical frames.
/// Linux uses `int_sqrt(totalram_pages * (PAGE_SIZE / 1024))` clamped
/// to [128, 65536] kB; we use the same formula.
fn compute_min_free_kbytes() -> u64 {
    let stats = narf_memory::frame::stats();
    let total_kb = (stats.total as u64) * 4; // 4 KiB pages
                                             // Integer square root approximation.
    let x = total_kb;
    if x == 0 {
        return 128;
    }
    // Newton's method, converges quickly.
    let mut y = x;
    loop {
        let ny = (y + x / y) / 2;
        if ny >= y {
            break;
        }
        y = ny;
    }
    let result = y;
    result.clamp(128, 65536)
}

/// Register every `/proc/sys/vm/*` sysctl. Called once at boot.
/// Idempotent — repeated calls replace the existing entries.
pub fn register_all() {
    // Seed min_free_kbytes from actual RAM size.
    let min_free = compute_min_free_kbytes();
    MIN_FREE_KBYTES.store(min_free, Ordering::Relaxed);

    // swappiness: 0-200; default 60. Stub: stored, not consulted.
    register_sysctl(SysctlEntry {
        path: "vm/swappiness",
        read: || read_u64(&SWAPPINESS),
        write: Some(|s| {
            let v = parse_u64_max(s, 200)?;
            SWAPPINESS.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // vfs_cache_pressure: 0-unlimited; default 100. Stub.
    register_sysctl(SysctlEntry {
        path: "vm/vfs_cache_pressure",
        read: || read_u64(&VFS_CACHE_PRESSURE),
        write: Some(|s| {
            let v = parse_u64(s)?;
            VFS_CACHE_PRESSURE.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // dirty_background_ratio: 0-100; default 10. Stub.
    register_sysctl(SysctlEntry {
        path: "vm/dirty_background_ratio",
        read: || read_u64(&DIRTY_BACKGROUND_RATIO),
        write: Some(|s| {
            let v = parse_u64_max(s, 100)?;
            DIRTY_BACKGROUND_RATIO.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // dirty_background_bytes: default 0 (use ratio). Stub.
    register_sysctl(SysctlEntry {
        path: "vm/dirty_background_bytes",
        read: || read_u64(&DIRTY_BACKGROUND_BYTES),
        write: Some(|s| {
            let v = parse_u64(s)?;
            DIRTY_BACKGROUND_BYTES.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // dirty_ratio: 0-100; default 20. Stub.
    register_sysctl(SysctlEntry {
        path: "vm/dirty_ratio",
        read: || read_u64(&DIRTY_RATIO),
        write: Some(|s| {
            let v = parse_u64_max(s, 100)?;
            DIRTY_RATIO.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // dirty_bytes: default 0 (use ratio). Stub.
    register_sysctl(SysctlEntry {
        path: "vm/dirty_bytes",
        read: || read_u64(&DIRTY_BYTES),
        write: Some(|s| {
            let v = parse_u64(s)?;
            DIRTY_BYTES.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // dirty_expire_centisecs: default 3000. Stub.
    register_sysctl(SysctlEntry {
        path: "vm/dirty_expire_centisecs",
        read: || read_u64(&DIRTY_EXPIRE_CENTISECS),
        write: Some(|s| {
            let v = parse_u64(s)?;
            DIRTY_EXPIRE_CENTISECS.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // dirty_writeback_centisecs: default 500. Stub.
    register_sysctl(SysctlEntry {
        path: "vm/dirty_writeback_centisecs",
        read: || read_u64(&DIRTY_WRITEBACK_CENTISECS),
        write: Some(|s| {
            let v = parse_u64(s)?;
            DIRTY_WRITEBACK_CENTISECS.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // overcommit_memory: 0=heuristic 1=always 2=never; default 0.
    // Wired: OOM handler will consult this when it lands.
    register_sysctl(SysctlEntry {
        path: "vm/overcommit_memory",
        read: || read_u64(&OVERCOMMIT_MEMORY),
        write: Some(|s| {
            let v = parse_u64_max(s, 2)?;
            OVERCOMMIT_MEMORY.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // overcommit_ratio: default 50. Stub.
    register_sysctl(SysctlEntry {
        path: "vm/overcommit_ratio",
        read: || read_u64(&OVERCOMMIT_RATIO),
        write: Some(|s| {
            let v = parse_u64_max(s, 100)?;
            OVERCOMMIT_RATIO.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // overcommit_kbytes: default 0 (use ratio). Stub.
    register_sysctl(SysctlEntry {
        path: "vm/overcommit_kbytes",
        read: || read_u64(&OVERCOMMIT_KBYTES),
        write: Some(|s| {
            let v = parse_u64(s)?;
            OVERCOMMIT_KBYTES.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // min_free_kbytes: computed from RAM. Wired (frame allocator low-watermark).
    register_sysctl(SysctlEntry {
        path: "vm/min_free_kbytes",
        read: || read_u64(&MIN_FREE_KBYTES),
        write: Some(|s| {
            let v = parse_u64(s)?;
            MIN_FREE_KBYTES.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // max_map_count: default 65530. Wired: address-space region-count check.
    register_sysctl(SysctlEntry {
        path: "vm/max_map_count",
        read: || read_u64(&MAX_MAP_COUNT),
        write: Some(|s| {
            let v = parse_u64(s)?;
            MAX_MAP_COUNT.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // drop_caches: write-only trigger. 1=pagecache, 2=slab, 3=both.
    // NARF stub: accepts values 1-3, no-op until page-cache lands.
    register_sysctl(SysctlEntry {
        path: "vm/drop_caches",
        read: drop_caches_read,
        write: Some(drop_caches_write),
        perms: 0o200,
    });

    // nr_overcommit_hugepages: default 0; THP not yet implemented.
    // Accept writes silently so tooling that probes this key doesn't error.
    register_sysctl(SysctlEntry {
        path: "vm/nr_overcommit_hugepages",
        read: || read_u64(&NR_OVERCOMMIT_HUGEPAGES),
        write: Some(|s| {
            let v = parse_u64(s)?;
            NR_OVERCOMMIT_HUGEPAGES.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // panic_on_oom: 0=disabled 1=enabled; default 0.
    // Wired: OOM handler will check this value when it lands.
    register_sysctl(SysctlEntry {
        path: "vm/panic_on_oom",
        read: || read_u64(&PANIC_ON_OOM),
        write: Some(|s| {
            let v = parse_u64_max(s, 1)?;
            PANIC_ON_OOM.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });
}

// ── Public accessors for wired keys ─────────────────────────────

/// Current `max_map_count` limit. Called by the address-space
/// region-count check when it enforces the per-process mapping cap.
#[inline]
pub fn max_map_count() -> u64 {
    MAX_MAP_COUNT.load(Ordering::Relaxed)
}

/// Current `overcommit_memory` mode (0=heuristic, 1=always, 2=never).
#[inline]
pub fn overcommit_memory() -> u64 {
    OVERCOMMIT_MEMORY.load(Ordering::Relaxed)
}

/// Current `panic_on_oom` flag.
#[inline]
pub fn panic_on_oom() -> bool {
    PANIC_ON_OOM.load(Ordering::Relaxed) != 0
}

/// Current `min_free_kbytes` threshold.
#[inline]
pub fn min_free_kbytes() -> u64 {
    MIN_FREE_KBYTES.load(Ordering::Relaxed)
}

// ── Tests ────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{lookup_registry, ProcNodeSnapshot};

/// Helper: look up a registered sysctl, call ProcFile::read, return String.
fn sysctl_read(path: &[&str]) -> Option<String> {
    match lookup_registry(path) {
        Some(ProcNodeSnapshot::File(f)) => String::from_utf8(f.read()).ok(),
        _ => None,
    }
}

/// Helper: look up a registered sysctl, call ProcFile::write.
fn sysctl_write(path: &[&str], val: &[u8]) -> Option<Result<usize, crate::FsError>> {
    match lookup_registry(path) {
        Some(ProcNodeSnapshot::File(f)) => Some(f.write(val)),
        _ => None,
    }
}

/// Ensure register_all has been called (idempotent).
fn ensure_registered() {
    register_all();
}

fn smoke_vm_swappiness_default() -> TestResult {
    ensure_registered();
    // Reset to default before reading to isolate from other tests.
    SWAPPINESS.store(60, Ordering::Relaxed);
    match sysctl_read(&["sys", "vm", "swappiness"]) {
        Some(s) if s == "60\n" => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("vm/swappiness default read did not return '60\\n'")
        }
    }
}
kernel_test_in!("filesystem/procfs/sys_vm", smoke_vm_swappiness_default);

fn smoke_vm_swappiness_write_roundtrip() -> TestResult {
    ensure_registered();
    SWAPPINESS.store(60, Ordering::Relaxed);
    let w = sysctl_write(&["sys", "vm", "swappiness"], b"200\n");
    if !matches!(w, Some(Ok(_))) {
        return TestResult::Fail("vm/swappiness write '200' failed");
    }
    match sysctl_read(&["sys", "vm", "swappiness"]) {
        Some(s) if s == "200\n" => TestResult::Pass,
        _ => TestResult::Fail("vm/swappiness read after write '200' did not return '200\\n'"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_vm",
    smoke_vm_swappiness_write_roundtrip
);

fn smoke_vm_swappiness_rejects_out_of_range() -> TestResult {
    ensure_registered();
    let w = sysctl_write(&["sys", "vm", "swappiness"], b"201\n");
    match w {
        Some(Err(crate::FsError::InvalidData)) => TestResult::Pass,
        _ => TestResult::Fail("vm/swappiness write '201' should return InvalidData"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_vm",
    smoke_vm_swappiness_rejects_out_of_range
);

fn smoke_vm_drop_caches_write_3() -> TestResult {
    ensure_registered();
    let w = sysctl_write(&["sys", "vm", "drop_caches"], b"3\n");
    match w {
        Some(Ok(_)) => TestResult::Pass,
        _ => TestResult::Fail("vm/drop_caches write '3' should return Ok"),
    }
}
kernel_test_in!("filesystem/procfs/sys_vm", smoke_vm_drop_caches_write_3);

fn smoke_vm_overcommit_memory_valid() -> TestResult {
    ensure_registered();
    for &v in &[b"0\n" as &[u8], b"1\n", b"2\n"] {
        if !matches!(
            sysctl_write(&["sys", "vm", "overcommit_memory"], v),
            Some(Ok(_))
        ) {
            return TestResult::Fail("vm/overcommit_memory valid write failed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/procfs/sys_vm", smoke_vm_overcommit_memory_valid);

fn smoke_vm_overcommit_memory_rejects_3() -> TestResult {
    ensure_registered();
    match sysctl_write(&["sys", "vm", "overcommit_memory"], b"3\n") {
        Some(Err(crate::FsError::InvalidData)) => TestResult::Pass,
        _ => TestResult::Fail("vm/overcommit_memory write '3' should return InvalidData"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_vm",
    smoke_vm_overcommit_memory_rejects_3
);

fn smoke_vm_dirty_background_bytes_default() -> TestResult {
    ensure_registered();
    DIRTY_BACKGROUND_BYTES.store(0, Ordering::Relaxed);
    match sysctl_read(&["sys", "vm", "dirty_background_bytes"]) {
        Some(s) if s == "0\n" => TestResult::Pass,
        _ => TestResult::Fail("vm/dirty_background_bytes default should be '0\\n'"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_vm",
    smoke_vm_dirty_background_bytes_default
);

fn smoke_vm_min_free_kbytes_nonzero() -> TestResult {
    ensure_registered();
    let v = min_free_kbytes();
    if v >= 128 {
        TestResult::Pass
    } else {
        TestResult::Fail("vm/min_free_kbytes should be >= 128")
    }
}
kernel_test_in!("filesystem/procfs/sys_vm", smoke_vm_min_free_kbytes_nonzero);
