//! `/proc/sys/fs/*` — filesystem sysctl knobs.
//!
//! # Fidelity notes
//!
//! NARF has a VFS layer but no per-process file-descriptor table larger
//! than a simple array, no inotify subsystem, and no AIO/epoll engine.
//! Most keys are therefore **accept-and-log stubs**: writes parse and
//! store the value so a subsequent read returns the same number, but no
//! kernel path consults the stored value yet.
//!
//! Keys that ARE wired (or become wired once their consumer lands):
//!   - `file-max`       — global fd-table ceiling (VFS alloc checks TBD).
//!   - `nr_open`        — per-process fd limit (VFS alloc checks TBD).
//!   - `pipe-max-size`  — enforced by pipe-buffer alloc (TBD).
//!
//! Everything else stores the written integer in an `AtomicU64`.
//!
//! # Format notes
//!   - `file-nr`    emits "<open> <free> <max>" on one line (Linux 2.6+
//!     shape; earlier kernels used two integers — we use three).
//!   - `dentry-state` emits six space-separated integers; NARF stubs
//!     all six as 0 since there is no dcache yet.
//!
//! Linux refs:
//!   `fs/file.c`            (`file-max`, `file-nr`, `nr_open`)
//!   `fs/inotify_user.c`    (inotify/* keys)
//!   `fs/pipe.c`            (`pipe-max-size`, `pipe-user-pages-hard`)
//!   `fs/aio.c`             (`aio-max-nr`)
//!   `fs/eventpoll.c`       (`epoll/max_user_watches`)
//!   `fs/locks.c`           (`lease-break-time`)
//!   `fs/dcache.c`          (`dentry-state`)
//!   `kernel/sysctl.c`      fs_table[]

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use super::sys::register_sysctl;
use super::sys::SysctlEntry;
use crate::FsError;

// ── Per-key storage cells ────────────────────────────────────────

static FILE_MAX: AtomicU64 = AtomicU64::new(4096);
static NR_OPEN: AtomicU64 = AtomicU64::new(1024);
static PIPE_MAX_SIZE: AtomicU64 = AtomicU64::new(1_048_576);
static PIPE_USER_PAGES_HARD: AtomicU64 = AtomicU64::new(0);
static INOTIFY_MAX_USER_WATCHES: AtomicU64 = AtomicU64::new(8192);
static INOTIFY_MAX_USER_INSTANCES: AtomicU64 = AtomicU64::new(128);
static INOTIFY_MAX_QUEUED_EVENTS: AtomicU64 = AtomicU64::new(16384);
static AIO_MAX_NR: AtomicU64 = AtomicU64::new(65536);
static EPOLL_MAX_USER_WATCHES: AtomicU64 = AtomicU64::new(1 << 20); // 1 M, Linux default
static LEASE_BREAK_TIME: AtomicU64 = AtomicU64::new(45);

// ── Parse helpers ────────────────────────────────────────────────

fn parse_u64(s: &str) -> Result<u64, FsError> {
    s.parse::<u64>().map_err(|_| FsError::InvalidData)
}

fn parse_u64_range(s: &str, min: u64, max: u64) -> Result<u64, FsError> {
    let v = parse_u64(s)?;
    if v < min || v > max {
        Err(FsError::InvalidData)
    } else {
        Ok(v)
    }
}

// ── Read helpers ─────────────────────────────────────────────────

fn read_u64(cell: &AtomicU64) -> String {
    alloc::format!("{}\n", cell.load(Ordering::Relaxed))
}

// ── file-nr renderer ─────────────────────────────────────────────
//
// Linux format (fs/file.c `proc_nr_files`):
//   "<allocated> <unused-but-reserved> <max>\n"
// NARF doesn't track per-process fd allocation yet; report:
//   0  0  <file-max>
fn gen_file_nr() -> String {
    let max = FILE_MAX.load(Ordering::Relaxed);
    alloc::format!("0\t0\t{}\n", max)
}

// ── dentry-state renderer ────────────────────────────────────────
//
// Linux format (fs/dcache.c `proc_nr_dentry`):
//   "<nr_dentry> <nr_unused> <age_limit> <want_pages> 0 0\n"
// NARF has no dcache; stub all six as 0.
fn gen_dentry_state() -> String {
    String::from("0 0 0 0 0 0\n")
}

// ── Registration ─────────────────────────────────────────────────

/// Register every `/proc/sys/fs/*` sysctl. Called once at boot.
/// Idempotent — repeated calls replace the existing entries.
pub fn register_all() {
    // file-max: global open-file ceiling; default 4096.
    register_sysctl(SysctlEntry {
        path: "fs/file-max",
        read: || read_u64(&FILE_MAX),
        write: Some(|s| {
            let v = parse_u64(s)?;
            FILE_MAX.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // file-nr: read-only three-integer snapshot.
    // Linux ref: `fs/file.c` proc_nr_files().
    register_sysctl(SysctlEntry {
        path: "fs/file-nr",
        read: gen_file_nr,
        write: None,
        perms: 0o444,
    });

    // nr_open: per-process fd table ceiling; default 1024.
    register_sysctl(SysctlEntry {
        path: "fs/nr_open",
        read: || read_u64(&NR_OPEN),
        write: Some(|s| {
            // Linux floor is BITS_PER_LONG (64 on x86_64); we mirror that.
            let v = parse_u64_range(s, 64, u64::MAX)?;
            NR_OPEN.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // pipe-max-size: single-pipe buffer ceiling; default 1 MiB.
    // Linux ref: `fs/pipe.c` do_fcntl_setpipe_sz.
    register_sysctl(SysctlEntry {
        path: "fs/pipe-max-size",
        read: || read_u64(&PIPE_MAX_SIZE),
        write: Some(|s| {
            let v = parse_u64(s)?;
            // Must be a power-of-two and >= PAGE_SIZE (4096).
            if v < 4096 || !v.is_power_of_two() {
                return Err(FsError::InvalidData);
            }
            PIPE_MAX_SIZE.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // pipe-user-pages-hard: per-uid pipe-page hard limit; 0=disabled.
    register_sysctl(SysctlEntry {
        path: "fs/pipe-user-pages-hard",
        read: || read_u64(&PIPE_USER_PAGES_HARD),
        write: Some(|s| {
            let v = parse_u64(s)?;
            PIPE_USER_PAGES_HARD.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // inotify/max_user_watches: per-uid inotify watch ceiling; default 8192. Stub.
    register_sysctl(SysctlEntry {
        path: "fs/inotify/max_user_watches",
        read: || read_u64(&INOTIFY_MAX_USER_WATCHES),
        write: Some(|s| {
            let v = parse_u64(s)?;
            INOTIFY_MAX_USER_WATCHES.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // inotify/max_user_instances: per-uid inotify-fd ceiling; default 128. Stub.
    register_sysctl(SysctlEntry {
        path: "fs/inotify/max_user_instances",
        read: || read_u64(&INOTIFY_MAX_USER_INSTANCES),
        write: Some(|s| {
            let v = parse_u64(s)?;
            INOTIFY_MAX_USER_INSTANCES.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // inotify/max_queued_events: per-inotify-fd event queue depth; default 16384. Stub.
    register_sysctl(SysctlEntry {
        path: "fs/inotify/max_queued_events",
        read: || read_u64(&INOTIFY_MAX_QUEUED_EVENTS),
        write: Some(|s| {
            let v = parse_u64(s)?;
            INOTIFY_MAX_QUEUED_EVENTS.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // aio-max-nr: global AIO request ceiling; default 65536. Stub.
    register_sysctl(SysctlEntry {
        path: "fs/aio-max-nr",
        read: || read_u64(&AIO_MAX_NR),
        write: Some(|s| {
            let v = parse_u64(s)?;
            AIO_MAX_NR.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // epoll/max_user_watches: per-uid epoll watch ceiling. Stub.
    register_sysctl(SysctlEntry {
        path: "fs/epoll/max_user_watches",
        read: || read_u64(&EPOLL_MAX_USER_WATCHES),
        write: Some(|s| {
            let v = parse_u64(s)?;
            EPOLL_MAX_USER_WATCHES.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // dentry-state: six-integer read-only snapshot. Stub: all zeros.
    register_sysctl(SysctlEntry {
        path: "fs/dentry-state",
        read: gen_dentry_state,
        write: None,
        perms: 0o444,
    });

    // lease-break-time: seconds to wait before breaking a lease; default 45.
    register_sysctl(SysctlEntry {
        path: "fs/lease-break-time",
        read: || read_u64(&LEASE_BREAK_TIME),
        write: Some(|s| {
            let v = parse_u64(s)?;
            LEASE_BREAK_TIME.store(v, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });
}

// ── Public accessors for wired keys ─────────────────────────────

/// Current global file-max ceiling.
#[inline]
pub fn file_max() -> u64 {
    FILE_MAX.load(Ordering::Relaxed)
}

/// Current per-process nr_open limit.
#[inline]
pub fn nr_open() -> u64 {
    NR_OPEN.load(Ordering::Relaxed)
}

/// Current pipe-max-size ceiling in bytes.
#[inline]
pub fn pipe_max_size() -> u64 {
    PIPE_MAX_SIZE.load(Ordering::Relaxed)
}

// ── Tests ────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{lookup_registry, ProcNodeSnapshot};

fn sysctl_read(path: &[&str]) -> Option<String> {
    match lookup_registry(path) {
        Some(ProcNodeSnapshot::File(f)) => String::from_utf8(f.read()).ok(),
        _ => None,
    }
}

fn sysctl_write(path: &[&str], val: &[u8]) -> Option<Result<usize, crate::FsError>> {
    match lookup_registry(path) {
        Some(ProcNodeSnapshot::File(f)) => Some(f.write(val)),
        _ => None,
    }
}

fn ensure_registered() {
    register_all();
}

fn smoke_fs_file_max_read() -> TestResult {
    ensure_registered();
    FILE_MAX.store(4096, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "file-max"]) {
        Some(s) if s == "4096\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/file-max default read did not return '4096\\n'"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_file_max_read);

fn smoke_fs_file_max_write_roundtrip() -> TestResult {
    ensure_registered();
    let w = sysctl_write(&["sys", "fs", "file-max"], b"8192\n");
    if !matches!(w, Some(Ok(_))) {
        return TestResult::Fail("fs/file-max write failed");
    }
    match sysctl_read(&["sys", "fs", "file-max"]) {
        Some(s) if s == "8192\n" => {
            FILE_MAX.store(4096, Ordering::Relaxed); // restore
            TestResult::Pass
        }
        _ => TestResult::Fail("fs/file-max read after write did not round-trip"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_fs",
    smoke_fs_file_max_write_roundtrip
);

fn smoke_fs_file_nr_three_values() -> TestResult {
    ensure_registered();
    match sysctl_read(&["sys", "fs", "file-nr"]) {
        Some(s) => {
            // Must have exactly two tab-separated separators (three fields).
            let parts: alloc::vec::Vec<&str> = s.trim().split('\t').collect();
            if parts.len() == 3 {
                TestResult::Pass
            } else {
                TestResult::Fail("fs/file-nr did not return three tab-separated values")
            }
        }
        None => TestResult::Fail("fs/file-nr lookup failed"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_file_nr_three_values);

fn smoke_fs_pipe_max_size_default() -> TestResult {
    ensure_registered();
    PIPE_MAX_SIZE.store(1_048_576, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "pipe-max-size"]) {
        Some(s) if s == "1048576\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/pipe-max-size default should be '1048576\\n'"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_pipe_max_size_default);

fn smoke_fs_inotify_max_user_watches_default() -> TestResult {
    ensure_registered();
    INOTIFY_MAX_USER_WATCHES.store(8192, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "inotify", "max_user_watches"]) {
        Some(s) if s == "8192\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/inotify/max_user_watches default should be '8192\\n'"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_fs",
    smoke_fs_inotify_max_user_watches_default
);

fn smoke_fs_dentry_state_six_ints() -> TestResult {
    ensure_registered();
    match sysctl_read(&["sys", "fs", "dentry-state"]) {
        Some(s) => {
            let parts: alloc::vec::Vec<&str> = s.trim().split(' ').collect();
            if parts.len() == 6 && parts.iter().all(|p| p.parse::<u64>().is_ok()) {
                TestResult::Pass
            } else {
                TestResult::Fail("fs/dentry-state did not return six integer values")
            }
        }
        None => TestResult::Fail("fs/dentry-state lookup failed"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_dentry_state_six_ints);

fn smoke_fs_pipe_max_size_rejects_non_power_of_two() -> TestResult {
    ensure_registered();
    match sysctl_write(&["sys", "fs", "pipe-max-size"], b"65537\n") {
        Some(Err(crate::FsError::InvalidData)) => TestResult::Pass,
        _ => TestResult::Fail("fs/pipe-max-size should reject non-power-of-two values"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_fs",
    smoke_fs_pipe_max_size_rejects_non_power_of_two
);

fn smoke_fs_lease_break_time_default() -> TestResult {
    ensure_registered();
    LEASE_BREAK_TIME.store(45, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "lease-break-time"]) {
        Some(s) if s == "45\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/lease-break-time default should be '45\\n'"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_fs",
    smoke_fs_lease_break_time_default
);

fn smoke_fs_nr_open_default() -> TestResult {
    ensure_registered();
    NR_OPEN.store(1024, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "nr_open"]) {
        Some(s) if s == "1024\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/nr_open default should be '1024\\n'"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_nr_open_default);

fn smoke_fs_pipe_user_pages_hard_default() -> TestResult {
    ensure_registered();
    PIPE_USER_PAGES_HARD.store(0, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "pipe-user-pages-hard"]) {
        Some(s) if s == "0\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/pipe-user-pages-hard default should be '0\\n'"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_pipe_user_pages_hard_default);

fn smoke_fs_inotify_max_user_instances_default() -> TestResult {
    ensure_registered();
    INOTIFY_MAX_USER_INSTANCES.store(128, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "inotify", "max_user_instances"]) {
        Some(s) if s == "128\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/inotify/max_user_instances default should be '128\\n'"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_inotify_max_user_instances_default);

fn smoke_fs_inotify_max_queued_events_default() -> TestResult {
    ensure_registered();
    INOTIFY_MAX_QUEUED_EVENTS.store(16384, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "inotify", "max_queued_events"]) {
        Some(s) if s == "16384\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/inotify/max_queued_events default should be '16384\\n'"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_inotify_max_queued_events_default);

fn smoke_fs_aio_max_nr_default() -> TestResult {
    ensure_registered();
    AIO_MAX_NR.store(65536, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "aio-max-nr"]) {
        Some(s) if s == "65536\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/aio-max-nr default should be '65536\\n'"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_aio_max_nr_default);

fn smoke_fs_epoll_max_user_watches_default() -> TestResult {
    ensure_registered();
    EPOLL_MAX_USER_WATCHES.store(1048576, Ordering::Relaxed);
    match sysctl_read(&["sys", "fs", "epoll", "max_user_watches"]) {
        Some(s) if s == "1048576\n" => TestResult::Pass,
        _ => TestResult::Fail("fs/epoll/max_user_watches default should be '1048576\\n'"),
    }
}
kernel_test_in!("filesystem/procfs/sys_fs", smoke_fs_epoll_max_user_watches_default);
