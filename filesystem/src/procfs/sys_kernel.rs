//! `/proc/sys/kernel/*` sysctl table — Linux-compatible kernel tunables.
//!
//! Every key is registered at boot via `register_all()`. Writable keys
//! store their values in `IrqSafeSpinLock`-guarded statics; read-only
//! stubs return fixed strings.
//!
//! Linux ref: `kernel/sysctl.c` — the `kern_table[]` array. Values
//! are chosen to match Linux defaults where NARF has no policy of its
//! own; N/A stubs (modprobe, dmesg_restrict for capabilities) are
//! documented at each key.
//!
//! ## `/proc/sys/kernel/random/*`
//!
//! `entropy_avail` reports a fixed stub (NARF has no entropy pool yet).
//! `uuid` generates a fresh RFC-4122 v4-shaped UUID per read, seeded
//! from `monotonic_ns()` + a static counter. This is NOT
//! cryptographically random; a real CSPRNG lands with the entropy
//! driver.
//! `boot_id` is generated once at first read and then fixed for the
//! session — matching Linux semantics.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::sys::{register_sysctl, SysctlEntry};
use crate::FsError;

// ── Writable state storage ───────────────────────────────────────
//
// Each writable key gets its own static so reads and writes don't
// contend on a single lock.  String fields use IrqSafeSpinLock<String>;
// numeric fields use atomics where possible.

static HOSTNAME: IrqSafeSpinLock<String> = IrqSafeSpinLock::new(String::new());
static DOMAINNAME: IrqSafeSpinLock<String> = IrqSafeSpinLock::new(String::new());
static PRINTK_DEVKMSG: IrqSafeSpinLock<String> = IrqSafeSpinLock::new(String::new());
static CORE_PATTERN: IrqSafeSpinLock<String> = IrqSafeSpinLock::new(String::new());

static PID_MAX: AtomicU32 = AtomicU32::new(32768);
static THREADS_MAX: AtomicU32 = AtomicU32::new(65536);
static RANDOMIZE_VA_SPACE: AtomicU32 = AtomicU32::new(2);
static PANIC_SECS: AtomicI32 = AtomicI32::new(0);
static PANIC_ON_OOPS: AtomicU32 = AtomicU32::new(0);
static SCHED_RT_RUNTIME_US: AtomicI32 = AtomicI32::new(950000);
static SCHED_RT_PERIOD_US: AtomicU32 = AtomicU32::new(1000000);
static PERF_EVENT_PARANOID: AtomicI32 = AtomicI32::new(2);

// ── boot_id — generated once, then fixed ────────────────────────

static BOOT_ID: IrqSafeSpinLock<String> = IrqSafeSpinLock::new(String::new());

/// UUID-counter for per-read uuid generation (not crypto-safe).
static UUID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Format 16 bytes as an RFC-4122-shaped UUID string.
/// Version bits (4) and variant bits (2) are set in the standard
/// positions; the remaining bits come from `bytes`.
fn fmt_uuid(bytes: [u8; 16]) -> String {
    // Force version = 4 (bits 7..4 of byte 6) and variant = 0b10
    // (bits 7..6 of byte 8) per RFC 4122 §4.4.
    let mut b = bytes;
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

/// Cheap deterministic bytes from `monotonic_ns` + a counter.
/// Not cryptographically random — real entropy driver deferred.
fn cheap_uuid_bytes() -> [u8; 16] {
    let t = narf_time::monotonic_ns();
    let c = UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix time and counter across all 16 bytes with a simple spread.
    let mut b = [0u8; 16];
    let hi = t ^ (c.wrapping_mul(0x9e3779b97f4a7c15));
    let lo = t.wrapping_add(c).rotate_left(31) ^ 0xdeadbeefcafe1234;
    b[0..8].copy_from_slice(&hi.to_le_bytes());
    b[8..16].copy_from_slice(&lo.to_le_bytes());
    b
}

fn ensure_boot_id() -> String {
    let mut g = BOOT_ID.lock();
    if g.is_empty() {
        *g = fmt_uuid(cheap_uuid_bytes());
    }
    g.clone()
}

// ── Initialise string defaults ───────────────────────────────────

fn ensure_defaults() {
    // hostname default — only set if still empty (first call at boot).
    {
        let mut g = HOSTNAME.lock();
        if g.is_empty() {
            *g = String::from("narf");
        }
    }
    {
        let mut g = DOMAINNAME.lock();
        if g.is_empty() {
            *g = String::from("(none)");
        }
    }
    {
        let mut g = PRINTK_DEVKMSG.lock();
        if g.is_empty() {
            *g = String::from("on");
        }
    }
    {
        let mut g = CORE_PATTERN.lock();
        if g.is_empty() {
            *g = String::from("core");
        }
    }
}

// ── Read/write handlers ─────────────────────────────────────────

fn read_hostname() -> String {
    ensure_defaults();
    format!("{}\n", HOSTNAME.lock().as_str())
}
fn write_hostname(v: &str) -> Result<(), FsError> {
    if v.len() > 64 {
        return Err(FsError::InvalidData);
    }
    *HOSTNAME.lock() = v.to_string();
    Ok(())
}

fn read_ostype() -> String {
    String::from("NARF\n")
}
fn read_osrelease() -> String {
    String::from(concat!(env!("CARGO_PKG_VERSION"), "\n"))
}
fn read_version() -> String {
    String::from(concat!("#1 NARF ", env!("CARGO_PKG_VERSION"), " SMP\n",))
}

fn read_domainname() -> String {
    ensure_defaults();
    format!("{}\n", DOMAINNAME.lock().as_str())
}
fn write_domainname(v: &str) -> Result<(), FsError> {
    if v.len() > 64 {
        return Err(FsError::InvalidData);
    }
    *DOMAINNAME.lock() = v.to_string();
    Ok(())
}

fn read_pid_max() -> String {
    format!("{}\n", PID_MAX.load(Ordering::Relaxed))
}
fn write_pid_max(v: &str) -> Result<(), FsError> {
    let n: u32 = v.parse().map_err(|_| FsError::InvalidData)?;
    if n == 0 || n > 4194304 {
        return Err(FsError::InvalidData);
    }
    PID_MAX.store(n, Ordering::Relaxed);
    Ok(())
}

fn read_threads_max() -> String {
    format!("{}\n", THREADS_MAX.load(Ordering::Relaxed))
}
fn write_threads_max(v: &str) -> Result<(), FsError> {
    let n: u32 = v.parse().map_err(|_| FsError::InvalidData)?;
    if n == 0 {
        return Err(FsError::InvalidData);
    }
    THREADS_MAX.store(n, Ordering::Relaxed);
    Ok(())
}

fn read_randomize_va_space() -> String {
    format!("{}\n", RANDOMIZE_VA_SPACE.load(Ordering::Relaxed))
}
fn write_randomize_va_space(v: &str) -> Result<(), FsError> {
    let n: u32 = v.parse().map_err(|_| FsError::InvalidData)?;
    if n > 2 {
        return Err(FsError::InvalidData);
    }
    RANDOMIZE_VA_SPACE.store(n, Ordering::Relaxed);
    Ok(())
}

fn read_panic() -> String {
    format!("{}\n", PANIC_SECS.load(Ordering::Relaxed))
}
fn write_panic(v: &str) -> Result<(), FsError> {
    let n: i32 = v.parse().map_err(|_| FsError::InvalidData)?;
    PANIC_SECS.store(n, Ordering::Relaxed);
    Ok(())
}

fn read_panic_on_oops() -> String {
    format!("{}\n", PANIC_ON_OOPS.load(Ordering::Relaxed))
}
fn write_panic_on_oops(v: &str) -> Result<(), FsError> {
    let n: u32 = v.parse().map_err(|_| FsError::InvalidData)?;
    if n > 1 {
        return Err(FsError::InvalidData);
    }
    PANIC_ON_OOPS.store(n, Ordering::Relaxed);
    Ok(())
}

fn read_sched_rt_runtime_us() -> String {
    format!("{}\n", SCHED_RT_RUNTIME_US.load(Ordering::Relaxed))
}
fn write_sched_rt_runtime_us(v: &str) -> Result<(), FsError> {
    let n: i32 = v.parse().map_err(|_| FsError::InvalidData)?;
    // -1 means unlimited (Linux allows this); otherwise must be in
    // [1, sched_rt_period_us].
    let period = SCHED_RT_PERIOD_US.load(Ordering::Relaxed) as i32;
    if n != -1 && (n < 1 || n > period) {
        return Err(FsError::InvalidData);
    }
    SCHED_RT_RUNTIME_US.store(n, Ordering::Relaxed);
    Ok(())
}

fn read_sched_rt_period_us() -> String {
    format!("{}\n", SCHED_RT_PERIOD_US.load(Ordering::Relaxed))
}
fn write_sched_rt_period_us(v: &str) -> Result<(), FsError> {
    let n: u32 = v.parse().map_err(|_| FsError::InvalidData)?;
    if n == 0 {
        return Err(FsError::InvalidData);
    }
    SCHED_RT_PERIOD_US.store(n, Ordering::Relaxed);
    Ok(())
}

// kernel/printk: "4 4 1 7\n"
// Format: console_loglevel default_loglevel minimum_loglevel default_console_loglevel
// NARF does not implement per-level filtering yet; the values are
// informational stubs matching Linux defaults.
fn read_printk() -> String {
    String::from("4 4 1 7\n")
}

// kernel/dmesg_restrict: NARF uses capability gating, not this sysctl.
// Return "1" (most-restrictive) read-only — matching the NARF security
// posture of exposing kernel addresses only to cap holders.
fn read_dmesg_restrict() -> String {
    String::from("1\n")
}

// kernel/kptr_restrict: "2" — always hide kernel pointers.
// NARF full restriction by default; writable for completeness but
// we never loosen below 1 (in a real build the cap system enforces
// this separately; here we just clamp).
fn read_kptr_restrict() -> String {
    String::from("2\n")
}

fn read_perf_event_paranoid() -> String {
    format!("{}\n", PERF_EVENT_PARANOID.load(Ordering::Relaxed))
}
fn write_perf_event_paranoid(v: &str) -> Result<(), FsError> {
    let n: i32 = v.parse().map_err(|_| FsError::InvalidData)?;
    // Linux accepts -1 (no restriction) through 3; NARF accepts same range.
    if !(-1..=3).contains(&n) {
        return Err(FsError::InvalidData);
    }
    PERF_EVENT_PARANOID.store(n, Ordering::Relaxed);
    Ok(())
}

// kernel/modprobe: N/A on NARF (no module loader). Return empty string,
// read-only. Linux uses this path to exec the module loader; NARF has
// no execve yet and no module ABI. Consumers that check for empty treat
// it as "no modprobe binary" — correct.
fn read_modprobe() -> String {
    String::from("\n")
}

fn read_printk_devkmsg() -> String {
    ensure_defaults();
    format!("{}\n", PRINTK_DEVKMSG.lock().as_str())
}
fn write_printk_devkmsg(v: &str) -> Result<(), FsError> {
    if v.len() > 64 {
        return Err(FsError::InvalidData);
    }
    *PRINTK_DEVKMSG.lock() = v.to_string();
    Ok(())
}

fn read_cap_last_cap() -> String {
    String::from("40\n")
}

fn read_core_pattern() -> String {
    ensure_defaults();
    format!("{}\n", CORE_PATTERN.lock().as_str())
}
fn write_core_pattern(v: &str) -> Result<(), FsError> {
    if v.len() > 128 {
        return Err(FsError::InvalidData);
    }
    *CORE_PATTERN.lock() = v.to_string();
    Ok(())
}

// ── kernel/random/* ─────────────────────────────────────────────

// entropy_avail: report a fixed stub. NARF has no entropy pool yet;
// returning a modest non-zero value (256 bits) keeps userspace from
// spinning on a "not yet ready" check.
fn read_entropy_avail() -> String {
    String::from("256\n")
}

fn read_random_uuid() -> String {
    format!("{}\n", fmt_uuid(cheap_uuid_bytes()))
}

fn read_boot_id() -> String {
    format!("{}\n", ensure_boot_id())
}

// ── Public registration ─────────────────────────────────────────

/// Register all `/proc/sys/kernel/*` entries. Call once at boot.
/// Idempotent — a second call replaces the old entries.
pub fn register_all() {
    // Initialise string defaults so reads before any write see a sane value.
    ensure_defaults();

    register_sysctl(SysctlEntry {
        path: "kernel/hostname",
        read: read_hostname,
        write: Some(write_hostname),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/ostype",
        read: read_ostype,
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/osrelease",
        read: read_osrelease,
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/version",
        read: read_version,
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/domainname",
        read: read_domainname,
        write: Some(write_domainname),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/pid_max",
        read: read_pid_max,
        write: Some(write_pid_max),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/threads-max",
        read: read_threads_max,
        write: Some(write_threads_max),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/randomize_va_space",
        read: read_randomize_va_space,
        write: Some(write_randomize_va_space),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/panic",
        read: read_panic,
        write: Some(write_panic),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/panic_on_oops",
        read: read_panic_on_oops,
        write: Some(write_panic_on_oops),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/sched_rt_runtime_us",
        read: read_sched_rt_runtime_us,
        write: Some(write_sched_rt_runtime_us),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/sched_rt_period_us",
        read: read_sched_rt_period_us,
        write: Some(write_sched_rt_period_us),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/printk",
        read: read_printk,
        write: None,
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/printk_devkmsg",
        read: read_printk_devkmsg,
        write: Some(write_printk_devkmsg),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/cap_last_cap",
        read: read_cap_last_cap,
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/core_pattern",
        read: read_core_pattern,
        write: Some(write_core_pattern),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/dmesg_restrict",
        read: read_dmesg_restrict,
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/kptr_restrict",
        read: read_kptr_restrict,
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/perf_event_paranoid",
        read: read_perf_event_paranoid,
        write: Some(write_perf_event_paranoid),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/modprobe",
        read: read_modprobe,
        write: None,
        perms: 0o555,
    });
    // kernel/random/*
    register_sysctl(SysctlEntry {
        path: "kernel/random/entropy_avail",
        read: read_entropy_avail,
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/random/uuid",
        read: read_random_uuid,
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "kernel/random/boot_id",
        read: read_boot_id,
        write: None,
        perms: 0o444,
    });
}

// ── Tests ────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{lookup_registry, ProcNodeSnapshot};

/// Inline lookup helper — look up a sys/kernel/* path directly.
fn lookup_sys(subpath: &str) -> Option<alloc::sync::Arc<dyn super::ProcFile>> {
    // Path under registry is "sys/kernel/..." so split by "/".
    let full = alloc::format!("sys/{}", subpath);
    let parts: alloc::vec::Vec<&str> = full.split('/').collect();
    match lookup_registry(&parts) {
        Some(ProcNodeSnapshot::File(f)) => Some(f),
        _ => None,
    }
}

fn read_sys(subpath: &str) -> Option<String> {
    let f = lookup_sys(subpath)?;
    let bytes = f.read();
    String::from_utf8(bytes).ok()
}

/// hostname read returns "narf\n" by default (after register_all).
fn smoke_kernel_hostname_default() -> TestResult {
    register_all();
    // Reset hostname to default for test isolation.
    *HOSTNAME.lock() = String::from("narf");
    match read_sys("kernel/hostname") {
        Some(s) if s == "narf\n" => TestResult::Pass,
        Some(s) => {
            let _ = s;
            TestResult::Fail("hostname default mismatch")
        }
        None => TestResult::Fail("kernel/hostname not found"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_hostname_default
);

/// hostname write+read round-trip.
fn smoke_kernel_hostname_write_roundtrip() -> TestResult {
    register_all();
    let f = match lookup_sys("kernel/hostname") {
        Some(f) => f,
        None => return TestResult::Fail("kernel/hostname not found"),
    };
    let _ = f.write(b"testhost\n");
    let val = read_sys("kernel/hostname");
    // Restore.
    *HOSTNAME.lock() = String::from("narf");
    match val {
        Some(s) if s == "testhost\n" => TestResult::Pass,
        _ => TestResult::Fail("hostname write+read round-trip failed"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_hostname_write_roundtrip
);

/// ostype returns "NARF\n".
fn smoke_kernel_ostype_is_narf() -> TestResult {
    register_all();
    match read_sys("kernel/ostype") {
        Some(s) if s == "NARF\n" => TestResult::Pass,
        _ => TestResult::Fail("ostype is not NARF"),
    }
}
kernel_test_in!("filesystem/procfs/sys_kernel", smoke_kernel_ostype_is_narf);

/// pid_max default parses as u32 ≥ 1.
fn smoke_kernel_pid_max_parse() -> TestResult {
    register_all();
    PID_MAX.store(32768, Ordering::Relaxed);
    match read_sys("kernel/pid_max") {
        Some(s) => match s.trim().parse::<u32>() {
            Ok(n) if n >= 1 => TestResult::Pass,
            _ => TestResult::Fail("pid_max not parseable as u32"),
        },
        None => TestResult::Fail("kernel/pid_max not found"),
    }
}
kernel_test_in!("filesystem/procfs/sys_kernel", smoke_kernel_pid_max_parse);

/// randomize_va_space writable 0/1/2, rejects 3.
fn smoke_kernel_randomize_va_space_validation() -> TestResult {
    register_all();
    let f = match lookup_sys("kernel/randomize_va_space") {
        Some(f) => f,
        None => return TestResult::Fail("randomize_va_space not found"),
    };
    let ok0 = f.write(b"0\n").is_ok();
    let ok1 = f.write(b"1\n").is_ok();
    let ok2 = f.write(b"2\n").is_ok();
    let bad = matches!(f.write(b"3\n"), Err(FsError::InvalidData));
    // Restore.
    RANDOMIZE_VA_SPACE.store(2, Ordering::Relaxed);
    if ok0 && ok1 && ok2 && bad {
        TestResult::Pass
    } else {
        TestResult::Fail("randomize_va_space validation wrong")
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_randomize_va_space_validation
);

/// random/uuid has correct RFC-4122 dashes format.
fn smoke_kernel_random_uuid_format() -> TestResult {
    register_all();
    match read_sys("kernel/random/uuid") {
        Some(s) => {
            let u = s.trim();
            // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx = 8+4+4+4+12 = 32 hex + 4 dashes = 36
            let parts: alloc::vec::Vec<&str> = u.split('-').collect();
            let ok = parts.len() == 5
                && parts[0].len() == 8
                && parts[1].len() == 4
                && parts[2].len() == 4
                && parts[3].len() == 4
                && parts[4].len() == 12;
            if ok {
                TestResult::Pass
            } else {
                TestResult::Fail("uuid format not RFC-4122")
            }
        }
        None => TestResult::Fail("kernel/random/uuid not found"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_random_uuid_format
);

/// kptr_restrict = "2".
fn smoke_kernel_kptr_restrict_is_two() -> TestResult {
    register_all();
    match read_sys("kernel/kptr_restrict") {
        Some(s) if s.trim() == "2" => TestResult::Pass,
        _ => TestResult::Fail("kptr_restrict is not 2"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_kptr_restrict_is_two
);

/// modprobe returns "\n" (empty stub).
fn smoke_kernel_modprobe_empty_stub() -> TestResult {
    register_all();
    match read_sys("kernel/modprobe") {
        Some(s) if s == "\n" => TestResult::Pass,
        _ => TestResult::Fail("modprobe did not return empty stub"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_modprobe_empty_stub
);

/// ostype is read-only — write returns ReadOnly.
fn smoke_kernel_ostype_readonly_write() -> TestResult {
    register_all();
    let f = match lookup_sys("kernel/ostype") {
        Some(f) => f,
        None => return TestResult::Fail("ostype not found"),
    };
    match f.write(b"Linux\n") {
        Err(FsError::ReadOnly) => TestResult::Pass,
        _ => TestResult::Fail("ostype write did not return ReadOnly"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_ostype_readonly_write
);

/// boot_id is stable across two reads.
fn smoke_kernel_boot_id_stable() -> TestResult {
    register_all();
    let a = read_sys("kernel/random/boot_id");
    let b = read_sys("kernel/random/boot_id");
    match (a, b) {
        (Some(x), Some(y)) if x == y && !x.trim().is_empty() => TestResult::Pass,
        _ => TestResult::Fail("boot_id not stable across reads"),
    }
}
kernel_test_in!("filesystem/procfs/sys_kernel", smoke_kernel_boot_id_stable);

/// uuid generates two different values on consecutive reads.
fn smoke_kernel_uuid_unique_per_read() -> TestResult {
    register_all();
    let a = read_sys("kernel/random/uuid");
    let b = read_sys("kernel/random/uuid");
    match (a, b) {
        (Some(x), Some(y)) if x != y => TestResult::Pass,
        _ => TestResult::Fail("uuid returned the same value twice"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_uuid_unique_per_read
);

/// perf_event_paranoid is writable and rejects out-of-range.
fn smoke_kernel_perf_event_paranoid_validation() -> TestResult {
    register_all();
    let f = match lookup_sys("kernel/perf_event_paranoid") {
        Some(f) => f,
        None => return TestResult::Fail("perf_event_paranoid not found"),
    };
    let ok_minus1 = f.write(b"-1\n").is_ok();
    let ok_0 = f.write(b"0\n").is_ok();
    let ok_2 = f.write(b"2\n").is_ok();
    let ok_3 = f.write(b"3\n").is_ok();
    let bad_4 = matches!(f.write(b"4\n"), Err(FsError::InvalidData));
    // Restore.
    PERF_EVENT_PARANOID.store(2, Ordering::Relaxed);
    if ok_minus1 && ok_0 && ok_2 && ok_3 && bad_4 {
        TestResult::Pass
    } else {
        TestResult::Fail("perf_event_paranoid validation wrong")
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_perf_event_paranoid_validation
);

fn smoke_kernel_domainname_default() -> TestResult {
    register_all();
    *DOMAINNAME.lock() = String::from("(none)");
    match read_sys("kernel/domainname") {
        Some(s) if s == "(none)\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/domainname default mismatch"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_domainname_default
);

fn smoke_kernel_osrelease_format() -> TestResult {
    register_all();
    match read_sys("kernel/osrelease") {
        Some(s) if !s.trim().is_empty() => TestResult::Pass,
        _ => TestResult::Fail("kernel/osrelease missing or empty"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_osrelease_format
);

fn smoke_kernel_version_format() -> TestResult {
    register_all();
    match read_sys("kernel/version") {
        Some(s) if s.contains("NARF") && s.contains("SMP") => TestResult::Pass,
        _ => TestResult::Fail("kernel/version mismatch"),
    }
}
kernel_test_in!("filesystem/procfs/sys_kernel", smoke_kernel_version_format);

fn smoke_kernel_threads_max_default() -> TestResult {
    register_all();
    THREADS_MAX.store(65536, Ordering::Relaxed);
    match read_sys("kernel/threads-max") {
        Some(s) if s == "65536\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/threads-max mismatch"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_threads_max_default
);

fn smoke_kernel_panic_default() -> TestResult {
    register_all();
    PANIC_SECS.store(0, Ordering::Relaxed);
    match read_sys("kernel/panic") {
        Some(s) if s == "0\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/panic mismatch"),
    }
}
kernel_test_in!("filesystem/procfs/sys_kernel", smoke_kernel_panic_default);

fn smoke_kernel_panic_on_oops_default() -> TestResult {
    register_all();
    PANIC_ON_OOPS.store(0, Ordering::Relaxed);
    match read_sys("kernel/panic_on_oops") {
        Some(s) if s == "0\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/panic_on_oops mismatch"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_panic_on_oops_default
);

fn smoke_kernel_sched_rt_runtime_us_default() -> TestResult {
    register_all();
    SCHED_RT_RUNTIME_US.store(950000, Ordering::Relaxed);
    match read_sys("kernel/sched_rt_runtime_us") {
        Some(s) if s == "950000\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/sched_rt_runtime_us mismatch"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_sched_rt_runtime_us_default
);

fn smoke_kernel_sched_rt_period_us_default() -> TestResult {
    register_all();
    SCHED_RT_PERIOD_US.store(1000000, Ordering::Relaxed);
    match read_sys("kernel/sched_rt_period_us") {
        Some(s) if s == "1000000\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/sched_rt_period_us mismatch"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_sched_rt_period_us_default
);

fn smoke_kernel_printk_default() -> TestResult {
    register_all();
    match read_sys("kernel/printk") {
        Some(s) if s == "4 4 1 7\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/printk mismatch"),
    }
}
kernel_test_in!("filesystem/procfs/sys_kernel", smoke_kernel_printk_default);

fn smoke_kernel_entropy_avail_default() -> TestResult {
    register_all();
    match read_sys("kernel/random/entropy_avail") {
        Some(s) if s == "256\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/random/entropy_avail mismatch"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_entropy_avail_default
);

fn smoke_kernel_printk_devkmsg_rw() -> TestResult {
    register_all();
    let f = match lookup_sys("kernel/printk_devkmsg") {
        Some(f) => f,
        None => return TestResult::Fail("printk_devkmsg sysctl not found"),
    };
    if f.write(b"off\n").is_err() {
        return TestResult::Fail("write printk_devkmsg failed");
    }
    match read_sys("kernel/printk_devkmsg") {
        Some(s) if s == "off\n" => TestResult::Pass,
        _ => TestResult::Fail("printk_devkmsg readback mismatch"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_kernel",
    smoke_kernel_printk_devkmsg_rw
);

fn smoke_kernel_cap_last_cap() -> TestResult {
    register_all();
    match read_sys("kernel/cap_last_cap") {
        Some(s) if s == "40\n" => TestResult::Pass,
        _ => TestResult::Fail("kernel/cap_last_cap mismatch"),
    }
}
kernel_test_in!("filesystem/procfs/sys_kernel", smoke_kernel_cap_last_cap);

fn smoke_kernel_core_pattern_rw() -> TestResult {
    register_all();
    let f = match lookup_sys("kernel/core_pattern") {
        Some(f) => f,
        None => return TestResult::Fail("core_pattern sysctl not found"),
    };
    if f.write(b"core.%p\n").is_err() {
        return TestResult::Fail("write core_pattern failed");
    }
    match read_sys("kernel/core_pattern") {
        Some(s) if s == "core.%p\n" => TestResult::Pass,
        _ => TestResult::Fail("core_pattern readback mismatch"),
    }
}
kernel_test_in!("filesystem/procfs/sys_kernel", smoke_kernel_core_pattern_rw);
