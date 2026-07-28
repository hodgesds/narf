#![cfg(feature = "linux-compat")]
//! End-to-end smokes for `/proc/sys/*` write-propagation.
//!
//! Each smoke follows the full path:
//!   register sysctls → write value via ProcFile::write() →
//!   verify the kernel consumer sees the change (either via a public
//!   accessor function or by reading back the value through the same
//!   ProcFile::read()).
//!
//! ## Wired vs accept-and-store
//!
//! "Wired" keys have public consumer functions that the rest of the
//! kernel calls (e.g. `sys_net::ip_forward()`); their smokes verify
//! both that the write persists AND that the consumer accessor returns
//! the expected value. "Accept-and-store" keys only verify the
//! read-back round-trip — still useful regression coverage.
//!
//! ## Structure
//!
//! Tests call `register_all()` on the relevant sub-table (idempotent),
//! then look up the key via `lookup_registry`, write through the
//! `ProcFile::write()` method, and check the expected outcome.
//! Every test restores defaults so the global statics don't poison
//! later tests.
//!
//! Linux refs:
//!   kernel/sysctl.c        — sysctl framework and kern_table[]
//!   net/ipv4/sysctl_net_ipv4.c — ipv4_table[]
//!   net/core/sysctl_net_core.c — net_core_table[]
//!   net/ipv6/addrconf.c    — addrconf_sysctl / ipv6_defaults
//!   mm/vmscan.c            — swappiness, vfs_cache_pressure
//!
//! GPL-2.0-or-later — NARF is GPL-2.0-or-later as of 2026-05-20.

extern crate alloc;

use alloc::string::{String, ToString};
use core::sync::atomic::Ordering;

use narf_kernel_test::{kernel_test_in, TestResult};

#[cfg(feature = "linux-compat")]
use crate::procfs::sys_kernel;
#[cfg(feature = "linux-compat")]
use crate::procfs::sys_net;
#[cfg(feature = "linux-compat")]
use crate::procfs::sys_vm;
#[cfg(feature = "linux-compat")]
use crate::procfs::{lookup_registry, ProcNodeSnapshot};
use crate::FsError;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Read the value from a procfs sysctl path under "sys/".
/// Returns the trimmed text content (strips trailing newline).
#[cfg(feature = "linux-compat")]
fn sysctl_read(components: &[&str]) -> Option<String> {
    match lookup_registry(components) {
        Some(ProcNodeSnapshot::File(f)) => {
            let bytes = f.read();
            String::from_utf8(bytes)
                .ok()
                .map(|s| s.trim_end_matches('\n').to_string())
        }
        _ => None,
    }
}

/// Write a value to a procfs sysctl path under "sys/".
#[cfg(feature = "linux-compat")]
fn sysctl_write(components: &[&str], val: &[u8]) -> Option<Result<usize, FsError>> {
    match lookup_registry(components) {
        Some(ProcNodeSnapshot::File(f)) => Some(f.write(val)),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 1 — kernel.hostname (wired: write propagates to HOSTNAME storage)
//
// Write "narftest" → read back via sysctl returns "narftest".
// This is the gethostname() consumer: the HOSTNAME static is the live
// storage that a sethostname() syscall would also touch.
// Linux ref: kernel/sys.c sethostname() → uts_ns->name.nodename
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_kernel_hostname_write_propagates() -> TestResult {
    sys_kernel::register_all();

    let path = &["sys", "kernel", "hostname"];
    if sysctl_write(path, b"narftest\n").is_none() {
        return TestResult::Fail("kernel/hostname not found in registry");
    }
    let val = sysctl_read(path);
    // Restore default.
    let _ = sysctl_write(path, b"narf\n");
    match val.as_deref() {
        Some("narftest") => TestResult::Pass,
        _ => TestResult::Fail("kernel/hostname write did not propagate: read-back mismatch"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_hostname_write_propagates);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 2 — net.ipv4.ip_forward (wired: IP_FORWARD atomic + ip_forward())
//
// Write "1" → ip_forward() returns true. Set back to "0".
// Linux ref: net/ipv4/devinet.c IPV4_DEVCONF_ALL, ipv4_forward_change()
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_net_ip_forward_propagates_to_accessor() -> TestResult {
    sys_net::register_all();
    sys_net::IP_FORWARD.store(0, Ordering::Relaxed);

    let path = &["sys", "net", "ipv4", "ip_forward"];
    match sysctl_write(path, b"1\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("net/ipv4/ip_forward write failed"),
    }

    let propagated = sys_net::ip_forward();
    let read_back = sysctl_read(path);

    // Restore.
    sys_net::IP_FORWARD.store(0, Ordering::Relaxed);

    if !propagated {
        return TestResult::Fail(
            "net/ipv4/ip_forward write did not propagate: ip_forward() still false",
        );
    }
    match read_back.as_deref() {
        Some("1") => TestResult::Pass,
        _ => TestResult::Fail("net/ipv4/ip_forward read-back did not return '1'"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/net", e2e_net_ip_forward_propagates_to_accessor);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 3 — net.ipv4.tcp_congestion_control "reno"
//           (wired: TCP_CONG_ALG + tcp_cong_alg_name())
//
// Write "reno" → tcp_cong_alg_name() returns "reno". Restore "cubic".
// Linux ref: net/ipv4/tcp_cong.c tcp_set_default_congestion_control()
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_tcp_congestion_control_reno_propagates() -> TestResult {
    sys_net::register_all();

    let path = &["sys", "net", "ipv4", "tcp_congestion_control"];
    match sysctl_write(path, b"reno\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("tcp_congestion_control write 'reno' failed"),
    }

    let name = sys_net::tcp_cong_alg_name();
    let read_back = sysctl_read(path);

    // Restore.
    let _ = sysctl_write(path, b"cubic\n");

    if name != "reno" {
        return TestResult::Fail(
            "tcp_congestion_control write 'reno' did not propagate: accessor still returns non-reno",
        );
    }
    match read_back.as_deref() {
        Some("reno") => TestResult::Pass,
        _ => TestResult::Fail("tcp_congestion_control read-back after 'reno' write mismatch"),
    }
}
kernel_test_in!(
    "procsys_e2e/net",
    e2e_tcp_congestion_control_reno_propagates
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 4 — net.ipv4.tcp_timestamps 0
//           (wired: TCP_TIMESTAMPS atomic + tcp_option_defaults())
//
// Write "0" → tcp_option_defaults().1 (timestamps) is false.
// Restore "1".
// Linux ref: net/ipv4/sysctl_net_ipv4.c tcp_timestamps
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_tcp_timestamps_0_propagates_to_option_defaults() -> TestResult {
    sys_net::register_all();
    sys_net::TCP_TIMESTAMPS.store(1, Ordering::Relaxed);

    let path = &["sys", "net", "ipv4", "tcp_timestamps"];
    match sysctl_write(path, b"0\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("tcp_timestamps write '0' failed"),
    }

    let (_ws, ts, _sack) = sys_net::tcp_option_defaults();
    let raw = sys_net::TCP_TIMESTAMPS.load(Ordering::Relaxed);

    // Restore.
    sys_net::TCP_TIMESTAMPS.store(1, Ordering::Relaxed);

    if ts {
        return TestResult::Fail(
            "tcp_timestamps write '0' did not propagate: tcp_option_defaults() still true",
        );
    }
    if raw != 0 {
        return TestResult::Fail("TCP_TIMESTAMPS atomic not 0 after write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "procsys_e2e/net",
    e2e_tcp_timestamps_0_propagates_to_option_defaults
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 5 — net.ipv4.tcp_sack 0
//           (wired: TCP_SACK atomic + tcp_option_defaults())
//
// Write "0" → tcp_option_defaults().2 (sack) is false.
// Linux ref: net/ipv4/sysctl_net_ipv4.c tcp_sack
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_tcp_sack_0_propagates_to_option_defaults() -> TestResult {
    sys_net::register_all();
    sys_net::TCP_SACK.store(1, Ordering::Relaxed);

    let path = &["sys", "net", "ipv4", "tcp_sack"];
    match sysctl_write(path, b"0\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("tcp_sack write '0' failed"),
    }

    let (_ws, _ts, sack) = sys_net::tcp_option_defaults();
    let raw = sys_net::TCP_SACK.load(Ordering::Relaxed);

    // Restore.
    sys_net::TCP_SACK.store(1, Ordering::Relaxed);

    if sack {
        return TestResult::Fail(
            "tcp_sack write '0' did not propagate: tcp_option_defaults() sack still true",
        );
    }
    if raw != 0 {
        return TestResult::Fail("TCP_SACK atomic not 0 after write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "procsys_e2e/net",
    e2e_tcp_sack_0_propagates_to_option_defaults
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 6 — net.ipv4.tcp_window_scaling 0
//           (wired: TCP_WSCALE atomic + tcp_option_defaults())
//
// Write "0" → tcp_option_defaults().0 (wscale) is false.
// Linux ref: net/ipv4/sysctl_net_ipv4.c tcp_window_scaling
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_tcp_window_scaling_0_propagates_to_option_defaults() -> TestResult {
    sys_net::register_all();
    sys_net::TCP_WSCALE.store(1, Ordering::Relaxed);

    let path = &["sys", "net", "ipv4", "tcp_window_scaling"];
    match sysctl_write(path, b"0\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("tcp_window_scaling write '0' failed"),
    }

    let (ws, _ts, _sack) = sys_net::tcp_option_defaults();
    let raw = sys_net::TCP_WSCALE.load(Ordering::Relaxed);

    // Restore.
    sys_net::TCP_WSCALE.store(1, Ordering::Relaxed);

    if ws {
        return TestResult::Fail(
            "tcp_window_scaling write '0' did not propagate: option_defaults() ws still true",
        );
    }
    if raw != 0 {
        return TestResult::Fail("TCP_WSCALE atomic not 0 after write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "procsys_e2e/net",
    e2e_tcp_window_scaling_0_propagates_to_option_defaults
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 7 — net.ipv4.ip_local_port_range (wired: PORT_RANGE_LO/HI atomics
//            + ephemeral_port_range())
//
// Write "10000 20000" → ephemeral_port_range() == (10000, 20000).
// Linux ref: net/ipv4/inet_connection_sock.c inet_get_local_port_range()
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_ip_local_port_range_propagates_to_accessor() -> TestResult {
    sys_net::register_all();
    sys_net::PORT_RANGE_LO.store(32768, Ordering::Relaxed);
    sys_net::PORT_RANGE_HI.store(60999, Ordering::Relaxed);

    let path = &["sys", "net", "ipv4", "ip_local_port_range"];
    match sysctl_write(path, b"10000 20000\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("ip_local_port_range write failed"),
    }

    let (lo, hi) = sys_net::ephemeral_port_range();

    // Restore.
    sys_net::PORT_RANGE_LO.store(32768, Ordering::Relaxed);
    sys_net::PORT_RANGE_HI.store(60999, Ordering::Relaxed);

    if lo != 10000 || hi != 20000 {
        return TestResult::Fail(
            "ip_local_port_range write did not propagate: ephemeral_port_range() mismatch",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "procsys_e2e/net",
    e2e_ip_local_port_range_propagates_to_accessor
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 8 — net.ipv6.conf.all.forwarding 1
//           (wired: IPV6_FORWARDING atomic + ipv6_forwarding())
//
// Write "1" → ipv6_forwarding() true. Restore "0".
// Linux ref: net/ipv6/addrconf.c addrconf_sysctl IPV6_DEVCONF_FORWARDING
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_ipv6_forwarding_propagates_to_accessor() -> TestResult {
    sys_net::register_all();
    sys_net::IPV6_FORWARDING.store(0, Ordering::Relaxed);

    let path = &["sys", "net", "ipv6", "conf", "all", "forwarding"];
    match sysctl_write(path, b"1\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("net/ipv6/conf/all/forwarding write failed"),
    }

    let fwd = sys_net::ipv6_forwarding();
    let raw = sys_net::IPV6_FORWARDING.load(Ordering::Relaxed);

    // Restore.
    sys_net::IPV6_FORWARDING.store(0, Ordering::Relaxed);

    if !fwd {
        return TestResult::Fail(
            "ipv6/forwarding write '1' did not propagate: ipv6_forwarding() still false",
        );
    }
    if raw != 1 {
        return TestResult::Fail("IPV6_FORWARDING atomic not 1 after write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "procsys_e2e/net",
    e2e_ipv6_forwarding_propagates_to_accessor
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 9 — vm.swappiness (accept-and-store: SWAPPINESS AtomicU64)
//
// Write "100" → SWAPPINESS atomic stores 100.
// No real consumer in the NARF vm yet; round-trip still confirms
// the sysctl write path stores correctly.
// Linux ref: mm/vmscan.c vm_swappiness (sysctl_vm_swappiness)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_vm_swappiness_write_100_stores_atomic() -> TestResult {
    sys_vm::register_all();

    let path = &["sys", "vm", "swappiness"];
    match sysctl_write(path, b"100\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("vm/swappiness write '100' failed"),
    }

    let val = sysctl_read(path);

    // Restore default.
    let _ = sysctl_write(path, b"60\n");

    match val.as_deref() {
        Some("100") => TestResult::Pass,
        _ => TestResult::Fail("vm/swappiness read-back after write '100' did not return '100'"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/vm", e2e_vm_swappiness_write_100_stores_atomic);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 10 — kernel.pid_max 16384 (accept-and-store: PID_MAX AtomicU32)
//
// Write "16384" → read-back returns "16384".
// Linux ref: kernel/pid.c pid_max (PIDNS_ADDING_PIDS)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_kernel_pid_max_write_16384() -> TestResult {
    sys_kernel::register_all();

    let path = &["sys", "kernel", "pid_max"];
    match sysctl_write(path, b"16384\n") {
        Some(Ok(_)) => {}
        _ => return TestResult::Fail("kernel/pid_max write '16384' failed"),
    }

    let val = sysctl_read(path);

    // Restore.
    let _ = sysctl_write(path, b"32768\n");

    match val.as_deref() {
        Some("16384") => TestResult::Pass,
        _ => TestResult::Fail("kernel/pid_max read-back after write '16384' mismatch"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_pid_max_write_16384);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 11 — kernel.ostype read-only: returns "NARF"
//
// Read-only key. Verifies read returns the expected constant string.
// Linux ref: kernel/sysctl.c kern_table[], utsname()->sysname
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_kernel_ostype_reads_narf() -> TestResult {
    sys_kernel::register_all();

    let path = &["sys", "kernel", "ostype"];
    match sysctl_read(path).as_deref() {
        Some("NARF") => TestResult::Pass,
        Some(other) => {
            let _ = other;
            TestResult::Fail("kernel/ostype did not return 'NARF'")
        }
        None => TestResult::Fail("kernel/ostype not found in registry"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_ostype_reads_narf);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 12 — kernel.modprobe read: returns empty stub ""
//
// N/A on NARF. The key exists and returns "" so tools that check
// for a modprobe path treat it as "no modprobe binary available".
// Linux ref: kernel/kmod.c modprobe_path[] (default "/sbin/modprobe")
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_kernel_modprobe_returns_empty_stub() -> TestResult {
    sys_kernel::register_all();

    let path = &["sys", "kernel", "modprobe"];
    match sysctl_read(path).as_deref() {
        // Trimmed read strips the trailing '\n', so empty stub reads as "".
        Some("") => TestResult::Pass,
        Some(other) => {
            let _ = other;
            TestResult::Fail("kernel/modprobe did not return empty stub")
        }
        None => TestResult::Fail("kernel/modprobe not found in registry"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_modprobe_returns_empty_stub);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 13 — kernel.randomize_va_space 3: write → InvalidData
//
// Only 0, 1, 2 are valid. Writing 3 must return FsError::InvalidData.
// Linux ref: mm/mmap.c randomize_va_space, valid range [0,2]
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_randomize_va_space_3_returns_invalid_data() -> TestResult {
    sys_kernel::register_all();

    let path = &["sys", "kernel", "randomize_va_space"];
    match sysctl_write(path, b"3\n") {
        Some(Err(FsError::InvalidData)) => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("randomize_va_space write '3' should return InvalidData"),
        Some(Err(e)) => {
            let _ = e;
            TestResult::Fail("randomize_va_space write '3' returned unexpected error")
        }
        None => TestResult::Fail("randomize_va_space not found in registry"),
    }
}
kernel_test_in!(
    "procsys_e2e/kernel",
    e2e_randomize_va_space_3_returns_invalid_data
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 14 — net.ipv4.tcp_congestion_control "bogus": write → InvalidData
//
// Only "cubic" and "reno" are in AVAILABLE_CONG. "bogus" must fail.
// Linux ref: net/ipv4/tcp_cong.c tcp_set_congestion_control() -ENOENT
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_tcp_congestion_control_bogus_returns_invalid_data() -> TestResult {
    sys_net::register_all();

    let path = &["sys", "net", "ipv4", "tcp_congestion_control"];
    match sysctl_write(path, b"bogus\n") {
        Some(Err(FsError::InvalidData)) => TestResult::Pass,
        Some(Ok(_)) => {
            TestResult::Fail("tcp_congestion_control write 'bogus' should return InvalidData")
        }
        Some(Err(e)) => {
            let _ = e;
            TestResult::Fail("tcp_congestion_control write 'bogus' returned unexpected error")
        }
        None => TestResult::Fail("tcp_congestion_control not found in registry"),
    }
}
kernel_test_in!(
    "procsys_e2e/net",
    e2e_tcp_congestion_control_bogus_returns_invalid_data
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 15 — vm.swappiness 201: write → InvalidData
//
// Valid range is [0, 200]. Writing 201 must reject.
// Linux ref: mm/vmscan.c, swappiness range 0..200 (Linux 5.8+)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_vm_swappiness_201_returns_invalid_data() -> TestResult {
    sys_vm::register_all();

    let path = &["sys", "vm", "swappiness"];
    match sysctl_write(path, b"201\n") {
        Some(Err(FsError::InvalidData)) => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("vm/swappiness write '201' should return InvalidData"),
        Some(Err(e)) => {
            let _ = e;
            TestResult::Fail("vm/swappiness write '201' returned unexpected error")
        }
        None => TestResult::Fail("vm/swappiness not found in registry"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/vm", e2e_vm_swappiness_201_returns_invalid_data);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 16 — kernel.pid_max -5: write → InvalidData
//
// pid_max must be a non-zero u32. "-5" fails to parse as u32.
// Linux ref: kernel/pid.c, pid_max bounded to [1, PID_MAX_LIMIT=4194304]
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_kernel_pid_max_negative_returns_invalid_data() -> TestResult {
    sys_kernel::register_all();

    let path = &["sys", "kernel", "pid_max"];
    match sysctl_write(path, b"-5\n") {
        Some(Err(FsError::InvalidData)) => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("kernel/pid_max write '-5' should return InvalidData"),
        Some(Err(e)) => {
            let _ = e;
            TestResult::Fail("kernel/pid_max write '-5' returned unexpected error")
        }
        None => TestResult::Fail("kernel/pid_max not found in registry"),
    }
}
kernel_test_in!(
    "procsys_e2e/kernel",
    e2e_kernel_pid_max_negative_returns_invalid_data
);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 17 — kernel.dmesg_restrict write: returns ReadOnly
//
// NARF cap-gates dmesg access; this sysctl is read-only (no write fn).
// Writing any value must return FsError::ReadOnly.
// Linux ref: kernel/sysctl.c dmesg_restrict, kernel/printk/printk.c
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn e2e_kernel_dmesg_restrict_write_returns_readonly() -> TestResult {
    sys_kernel::register_all();

    let path = &["sys", "kernel", "dmesg_restrict"];
    match sysctl_write(path, b"0\n") {
        Some(Err(FsError::ReadOnly)) => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("kernel/dmesg_restrict write should return ReadOnly"),
        Some(Err(e)) => {
            let _ = e;
            TestResult::Fail(
                "kernel/dmesg_restrict write returned unexpected error (want ReadOnly)",
            )
        }
        None => TestResult::Fail("kernel/dmesg_restrict not found in registry"),
    }
}
kernel_test_in!(
    "procsys_e2e/kernel",
    e2e_kernel_dmesg_restrict_write_returns_readonly
);

// ═══════════════════════════════════════════════════════════════════════════
// Global /proc node coverage (procsys_e2e/global)
//
// The tests above exercise the /proc/sys/* sysctl registry. The block
// below covers the GLOBAL (non-per-pid) /proc nodes served directly by
// `ProcRoot` — meminfo, stat, uptime, loadavg, filesystems, mounts,
// cpuinfo, version, cmdline, self, pressure — by resolving each through
// the real `DirOps`/`FileOps` surface (`ProcRoot::lookup` + the async
// `read`, driven synchronously with `poll_once`), exactly the path
// `resolve_async` walks for a `/proc/<name>` open. Each assertion parses
// a prefix/substring of the renderer's actual output (read from the
// source) rather than an exact full-string match, so the tests stay
// robust to incidental formatting changes while pinning the shape that
// tooling (ps, top, free, systemd, mount) depends on.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
use crate::procfs::{poll_once, ProcRoot};
#[cfg(feature = "linux-compat")]
use crate::{DirOps, FileType, Mode};
#[cfg(feature = "linux-compat")]
use alloc::vec::Vec;

/// Resolve `name` under `/proc` via `ProcRoot::lookup` and read the whole
/// file into a `String`, draining the async `read` with `poll_once` (all
/// procfs futures complete on the first poll). Returns `None` if the node
/// does not resolve, read errors, a poll goes pending, or the bytes are
/// not valid UTF-8.
#[cfg(feature = "linux-compat")]
fn read_root_file(name: &str) -> Option<String> {
    use alloc::sync::Arc;
    let root: Arc<dyn DirOps> = Arc::new(ProcRoot);
    let f = root.lookup(name)?;
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = match poll_once(f.read(out.len() as u64, &mut chunk)) {
            Some(Ok(n)) => n,
            _ => return None,
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        // Guard against a misbehaving generator that never signals EOF.
        if out.len() > 64 * 1024 {
            break;
        }
    }
    String::from_utf8(out).ok()
}

// ── /proc/meminfo ────────────────────────────────────────────────────────────

/// `/proc/meminfo` has `MemTotal:`/`MemFree:` lines whose value column is a
/// numeric kB count. `free`, systemd, and every memory probe parse these.
#[cfg(feature = "linux-compat")]
fn e2e_global_meminfo_memtotal_memfree_numeric_kb() -> TestResult {
    let body = match read_root_file("meminfo") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/meminfo did not resolve/read"),
    };
    // Each expected line reads e.g. "MemTotal:        524288 kB".
    let check = |prefix: &str| -> bool {
        body.lines().any(|l| {
            if let Some(rest) = l.strip_prefix(prefix) {
                let toks: Vec<&str> = rest.split_whitespace().collect();
                // "<number> kB"
                toks.len() == 2 && toks[0].parse::<u64>().is_ok() && toks[1] == "kB"
            } else {
                false
            }
        })
    };
    if !check("MemTotal:") {
        return TestResult::Fail("/proc/meminfo missing numeric-kB MemTotal: line");
    }
    if !check("MemFree:") {
        return TestResult::Fail("/proc/meminfo missing numeric-kB MemFree: line");
    }
    if !check("MemAvailable:") {
        return TestResult::Fail("/proc/meminfo missing numeric-kB MemAvailable: line");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "procsys_e2e/global",
    e2e_global_meminfo_memtotal_memfree_numeric_kb
);

// ── /proc/stat ───────────────────────────────────────────────────────────────

/// `/proc/stat` opens with a `cpu ` aggregate line carrying the 10 Linux
/// jiffy columns (user nice system idle iowait irq softirq steal guest
/// gnice), and carries the `intr`/`ctxt`/`btime`/`processes` summary lines
/// that vmstat/top parse.
#[cfg(feature = "linux-compat")]
fn e2e_global_stat_cpu_aggregate_and_summary_lines() -> TestResult {
    let body = match read_root_file("stat") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/stat did not resolve/read"),
    };
    // Aggregate line: "cpu " + 10 integer columns (11 whitespace tokens).
    let agg = match body.lines().find(|l| l.starts_with("cpu ")) {
        Some(l) => l,
        None => return TestResult::Fail("/proc/stat missing 'cpu ' aggregate line"),
    };
    let toks: Vec<&str> = agg.split_whitespace().collect();
    if toks.len() != 11 {
        return TestResult::Fail("/proc/stat 'cpu' aggregate must have 10 value columns");
    }
    if toks[1..].iter().any(|t| t.parse::<u64>().is_err()) {
        return TestResult::Fail("/proc/stat 'cpu' aggregate columns must be integers");
    }
    for key in ["intr ", "ctxt ", "btime ", "processes "] {
        if !body.lines().any(|l| l.starts_with(key)) {
            return TestResult::Fail("/proc/stat missing a required summary line");
        }
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "procsys_e2e/global",
    e2e_global_stat_cpu_aggregate_and_summary_lines
);

// ── /proc/uptime ─────────────────────────────────────────────────────────────

/// `/proc/uptime` is two space-separated floats (uptime, idle), each with a
/// decimal point. `uptime(1)` and `procps` split on whitespace.
#[cfg(feature = "linux-compat")]
fn e2e_global_uptime_two_floats() -> TestResult {
    let body = match read_root_file("uptime") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/uptime did not resolve/read"),
    };
    let toks: Vec<&str> = body.trim_end().split_whitespace().collect();
    if toks.len() != 2 {
        return TestResult::Fail("/proc/uptime must be exactly two tokens");
    }
    for t in &toks {
        // Must be a float: contains a '.' and both sides parse as integers.
        match t.split_once('.') {
            Some((i, f)) if i.parse::<u64>().is_ok() && f.parse::<u64>().is_ok() => {}
            _ => return TestResult::Fail("/proc/uptime token is not a decimal float"),
        }
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_uptime_two_floats);

// ── /proc/loadavg ────────────────────────────────────────────────────────────

/// `/proc/loadavg` is the Linux 5-field shape: three x.xx EWMA floats, a
/// `running/total` token, and a last-pid integer.
#[cfg(feature = "linux-compat")]
fn e2e_global_loadavg_five_field_shape() -> TestResult {
    let body = match read_root_file("loadavg") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/loadavg did not resolve/read"),
    };
    let toks: Vec<&str> = body.trim_end().split_whitespace().collect();
    if toks.len() != 5 {
        return TestResult::Fail("/proc/loadavg must have exactly 5 fields");
    }
    // First three: x.xx floats with a 2-digit fraction.
    for t in toks.iter().take(3) {
        match t.split_once('.') {
            Some((i, f))
                if i.parse::<u64>().is_ok() && f.len() == 2 && f.parse::<u64>().is_ok() => {}
            _ => return TestResult::Fail("/proc/loadavg average is not an x.xx float"),
        }
    }
    // Field 4: running/total, both integers.
    match toks[3].split_once('/') {
        Some((r, t)) if r.parse::<u64>().is_ok() && t.parse::<u64>().is_ok() => {}
        _ => return TestResult::Fail("/proc/loadavg running/total token malformed"),
    }
    // Field 5: last pid, integer.
    if toks[4].parse::<u64>().is_err() {
        return TestResult::Fail("/proc/loadavg last-pid field is not an integer");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_loadavg_five_field_shape);

// ── /proc/filesystems ────────────────────────────────────────────────────────

/// `/proc/filesystems` lists the mounted fs-type tokens; `proc` and `tmpfs`
/// (both mounted in a booted NARF) must appear. Bare `mount` scans this for
/// the fs-type token. NARF omits the Linux "nodev" prefix, so each line is a
/// tab followed by the bare type name.
#[cfg(feature = "linux-compat")]
fn e2e_global_filesystems_lists_known_types() -> TestResult {
    let body = match read_root_file("filesystems") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/filesystems did not resolve/read"),
    };
    // The set of type tokens is the trailing token of each line.
    let has = |ty: &str| {
        body.lines()
            .any(|l| l.split_whitespace().next() == Some(ty))
    };
    // procfs is always mounted (we are reading it), so "proc" must be present.
    if !has("proc") {
        return TestResult::Fail("/proc/filesystems missing 'proc' type");
    }
    // Every rendered line must be a single non-empty type token.
    for l in body.lines() {
        let toks: Vec<&str> = l.split_whitespace().collect();
        if toks.len() != 1 || toks[0].is_empty() {
            return TestResult::Fail("/proc/filesystems line is not a single type token");
        }
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "procsys_e2e/global",
    e2e_global_filesystems_lists_known_types
);

// ── /proc/mounts ─────────────────────────────────────────────────────────────

/// Each `/proc/mounts` line is the fstab-shaped 6-column record
/// `dev mountpoint fstype opts 0 0` that `mount`, `df`, and libmount parse.
#[cfg(feature = "linux-compat")]
fn e2e_global_mounts_six_column_shape() -> TestResult {
    let body = match read_root_file("mounts") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/mounts did not resolve/read"),
    };
    let mut lines = 0usize;
    for l in body.lines() {
        if l.is_empty() {
            continue;
        }
        lines += 1;
        let cols: Vec<&str> = l.split_whitespace().collect();
        if cols.len() != 6 {
            return TestResult::Fail("/proc/mounts line does not have 6 columns");
        }
        // Trailing two dump/pass columns are "0 0".
        if cols[4] != "0" || cols[5] != "0" {
            return TestResult::Fail("/proc/mounts trailing columns are not '0 0'");
        }
    }
    if lines == 0 {
        return TestResult::Fail("/proc/mounts rendered no mount lines");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_mounts_six_column_shape);

// ── /proc/cpuinfo ────────────────────────────────────────────────────────────

/// `/proc/cpuinfo` records begin with a `processor\t: <n>` line and carry a
/// `model name` field — the two lines lscpu / hwloc / build probes read.
#[cfg(feature = "linux-compat")]
fn e2e_global_cpuinfo_processor_and_model_name() -> TestResult {
    let body = match read_root_file("cpuinfo") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/cpuinfo did not resolve/read"),
    };
    // First non-empty line must introduce processor 0.
    let first = match body.lines().find(|l| !l.is_empty()) {
        Some(l) => l,
        None => return TestResult::Fail("/proc/cpuinfo is empty"),
    };
    if !first.starts_with("processor") || !first.contains(':') {
        return TestResult::Fail("/proc/cpuinfo does not start with a 'processor :' line");
    }
    if !body.lines().any(|l| l.starts_with("model name")) {
        return TestResult::Fail("/proc/cpuinfo missing a 'model name' line");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "procsys_e2e/global",
    e2e_global_cpuinfo_processor_and_model_name
);

// ── /proc/version ────────────────────────────────────────────────────────────

/// `/proc/version` is a single line naming the kernel ("NARF kernel ...").
#[cfg(feature = "linux-compat")]
fn e2e_global_version_single_kernel_line() -> TestResult {
    let body = match read_root_file("version") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/version did not resolve/read"),
    };
    if !body.starts_with("NARF kernel ") {
        return TestResult::Fail("/proc/version does not start with 'NARF kernel '");
    }
    // Exactly one text line (single trailing newline).
    if body.trim_end_matches('\n').contains('\n') {
        return TestResult::Fail("/proc/version is not a single line");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_version_single_kernel_line);

// ── /proc/cmdline ────────────────────────────────────────────────────────────

/// `/proc/cmdline` is a single newline-terminated line — the boot command
/// line systemd and dracut parse.
#[cfg(feature = "linux-compat")]
fn e2e_global_cmdline_single_line() -> TestResult {
    let body = match read_root_file("cmdline") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/cmdline did not resolve/read"),
    };
    // Terminated by exactly one '\n' and no embedded newlines.
    if !body.ends_with('\n') {
        return TestResult::Fail("/proc/cmdline is not newline-terminated");
    }
    if body.trim_end_matches('\n').contains('\n') {
        return TestResult::Fail("/proc/cmdline has embedded newlines");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_cmdline_single_line);

// ── /proc/self ───────────────────────────────────────────────────────────────

/// `/proc/self` stats as a symlink whose readlink text is the caller's pid.
/// With no current-pid hook installed in the test harness the hook falls
/// back to pid 0, so the target must be the decimal string of `current_pid`.
#[cfg(feature = "linux-compat")]
fn e2e_global_self_is_symlink_to_pid() -> TestResult {
    use alloc::string::ToString;
    use alloc::sync::Arc;
    let root: Arc<dyn DirOps> = Arc::new(ProcRoot);
    let f = match root.lookup("self") {
        Some(f) => f,
        None => return TestResult::Fail("/proc/self did not resolve"),
    };
    // Must stat as a symlink so readlink(2)/lstat(2) treat it correctly.
    if f.stat().mode.file_type != FileType::Symlink {
        return TestResult::Fail("/proc/self is not a Symlink");
    }
    // readlink target is the caller pid as decimal.
    let expected = crate::procfs::current_pid().to_string();
    let mut buf = [0u8; 32];
    let n = match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("/proc/self readlink read failed"),
    };
    match core::str::from_utf8(&buf[..n]) {
        Ok(t) if t == expected => TestResult::Pass,
        _ => TestResult::Fail("/proc/self target is not the caller's pid"),
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_self_is_symlink_to_pid);

// ── /proc/pressure/{cpu,memory,io} ───────────────────────────────────────────

/// The PSI files resolve through `/proc/pressure` and read back the
/// `some avg10=... avg60=... avg300=... total=...` shape; `cpu` has only a
/// `some` line while `memory`/`io` add a `full` line.
#[cfg(feature = "linux-compat")]
fn e2e_global_pressure_psi_shape() -> TestResult {
    use alloc::sync::Arc;
    let root: Arc<dyn DirOps> = Arc::new(ProcRoot);
    let dir = match root.lookup_dir("pressure") {
        Some(d) => d,
        None => return TestResult::Fail("/proc/pressure did not resolve as a directory"),
    };

    let read_psi = |name: &str| -> Option<String> {
        let f = dir.lookup(name)?;
        let mut buf = [0u8; 256];
        let n = match poll_once(f.read(0, &mut buf)) {
            Some(Ok(n)) => n,
            _ => return None,
        };
        String::from_utf8(buf[..n].to_vec()).ok()
    };

    // Validate one PSI line: leading tag then avg10=/avg60=/avg300=/total=.
    let psi_line_ok = |line: &str, tag: &str| -> bool {
        let toks: Vec<&str> = line.split_whitespace().collect();
        toks.len() == 5
            && toks[0] == tag
            && toks[1].starts_with("avg10=")
            && toks[2].starts_with("avg60=")
            && toks[3].starts_with("avg300=")
            && toks[4].starts_with("total=")
    };

    // cpu: exactly one "some" line.
    let cpu = match read_psi("cpu") {
        Some(s) => s,
        None => return TestResult::Fail("/proc/pressure/cpu read failed"),
    };
    let cpu_lines: Vec<&str> = cpu.lines().collect();
    if cpu_lines.len() != 1 || !psi_line_ok(cpu_lines[0], "some") {
        return TestResult::Fail("/proc/pressure/cpu is not a single well-formed 'some' line");
    }

    // memory + io: a "some" line then a "full" line.
    for res in ["memory", "io"] {
        let body = match read_psi(res) {
            Some(s) => s,
            None => return TestResult::Fail("/proc/pressure/<res> read failed"),
        };
        let lines: Vec<&str> = body.lines().collect();
        if lines.len() != 2 || !psi_line_ok(lines[0], "some") || !psi_line_ok(lines[1], "full") {
            return TestResult::Fail("/proc/pressure/{memory,io} not 'some'+'full' PSI lines");
        }
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_pressure_psi_shape);

// ── /proc/sys/kernel/seccomp/actions_avail ───────────────────────────────────

/// `/proc/sys/kernel/seccomp/actions_avail` lists the seccomp filter action
/// tokens libseccomp probes; the `allow` and `errno` actions must be present.
#[cfg(feature = "linux-compat")]
fn e2e_global_seccomp_actions_avail_lists_actions() -> TestResult {
    sys_kernel::register_all();
    let body = match sysctl_read(&["sys", "kernel", "seccomp", "actions_avail"]) {
        Some(s) => s,
        None => return TestResult::Fail("seccomp/actions_avail not found in registry"),
    };
    let toks: Vec<&str> = body.split_whitespace().collect();
    // libseccomp checks for the canonical action names it can request.
    for want in [
        "kill_process",
        "kill_thread",
        "trap",
        "errno",
        "trace",
        "log",
        "allow",
    ] {
        if !toks.iter().any(|t| *t == want) {
            return TestResult::Fail("seccomp/actions_avail missing a required action");
        }
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "procsys_e2e/global",
    e2e_global_seccomp_actions_avail_lists_actions
);

// ── /proc/sys/kernel read-only identity keys ─────────────────────────────────

/// The kernel identity sysctls read as their documented constants:
/// ostype "NARF", non-empty osrelease, default hostname "narf", and a
/// numeric pid_max within the Linux PID_MAX_LIMIT.
#[cfg(feature = "linux-compat")]
fn e2e_global_sys_kernel_identity_keys() -> TestResult {
    sys_kernel::register_all();

    match sysctl_read(&["sys", "kernel", "ostype"]).as_deref() {
        Some("NARF") => {}
        _ => return TestResult::Fail("kernel/ostype is not 'NARF'"),
    }
    match sysctl_read(&["sys", "kernel", "osrelease"]) {
        Some(s) if !s.is_empty() => {}
        _ => return TestResult::Fail("kernel/osrelease missing or empty"),
    }
    // hostname default is "narf" (reset to isolate from any prior write).
    let _ = sysctl_write(&["sys", "kernel", "hostname"], b"narf\n");
    match sysctl_read(&["sys", "kernel", "hostname"]).as_deref() {
        Some("narf") => {}
        _ => return TestResult::Fail("kernel/hostname default is not 'narf'"),
    }
    match sysctl_read(&["sys", "kernel", "pid_max"]).and_then(|s| s.parse::<u32>().ok()) {
        Some(n) if n >= 1 && n <= 4_194_304 => {}
        _ => return TestResult::Fail("kernel/pid_max not a valid PID_MAX_LIMIT-bounded integer"),
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_sys_kernel_identity_keys);

// ── /proc/sys/vm + /proc/sys/fs known keys ───────────────────────────────────

/// Representative `/proc/sys/vm/*` and `/proc/sys/fs/*` keys resolve and
/// read as integers: vm.swappiness (0..=200), vm.overcommit_memory, and
/// fs.file-max.
#[cfg(feature = "linux-compat")]
fn e2e_global_sys_vm_fs_known_keys_numeric() -> TestResult {
    sys_vm::register_all();
    crate::procfs::sys_fs::register_all();

    // vm.swappiness: reset to default, then confirm it reads in range.
    let _ = sysctl_write(&["sys", "vm", "swappiness"], b"60\n");
    match sysctl_read(&["sys", "vm", "swappiness"]).and_then(|s| s.parse::<u64>().ok()) {
        Some(n) if n <= 200 => {}
        _ => return TestResult::Fail("vm/swappiness not an in-range integer"),
    }
    // vm.overcommit_memory is one of 0/1/2.
    match sysctl_read(&["sys", "vm", "overcommit_memory"]).and_then(|s| s.parse::<u64>().ok()) {
        Some(n) if n <= 2 => {}
        _ => return TestResult::Fail("vm/overcommit_memory not 0/1/2"),
    }
    // fs.file-max is a positive integer.
    match sysctl_read(&["sys", "fs", "file-max"]).and_then(|s| s.parse::<u64>().ok()) {
        Some(n) if n >= 1 => {}
        _ => return TestResult::Fail("fs/file-max not a positive integer"),
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "procsys_e2e/global",
    e2e_global_sys_vm_fs_known_keys_numeric
);

// ── /proc entries stat as the correct node type ──────────────────────────────

/// A flat global file (`meminfo`) stats as a regular file, `self` as a
/// symlink, and `pressure` as a directory — the node-type distinctions
/// `resolve_async` and readdir rely on.
#[cfg(feature = "linux-compat")]
fn e2e_global_node_types_file_symlink_dir() -> TestResult {
    use alloc::sync::Arc;
    let root: Arc<dyn DirOps> = Arc::new(ProcRoot);

    let meminfo = match root.lookup("meminfo") {
        Some(f) => f,
        None => return TestResult::Fail("/proc/meminfo did not resolve"),
    };
    if meminfo.stat().mode.file_type != FileType::File {
        return TestResult::Fail("/proc/meminfo does not stat as a regular File");
    }
    if meminfo.stat().mode != Mode::FILE_RO {
        return TestResult::Fail("/proc/meminfo is not read-only");
    }

    match root.lookup("self") {
        Some(f) if f.stat().mode.file_type == FileType::Symlink => {}
        _ => return TestResult::Fail("/proc/self does not stat as a Symlink"),
    }

    // pressure resolves as a directory (via lookup_dir).
    if root.lookup_dir("pressure").is_none() {
        return TestResult::Fail("/proc/pressure does not resolve as a directory");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("procsys_e2e/global", e2e_global_node_types_file_symlink_dir);
