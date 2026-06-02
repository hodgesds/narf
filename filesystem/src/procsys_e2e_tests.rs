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

use crate::procfs::{lookup_registry, ProcNodeSnapshot};
use crate::procfs::sys_kernel;
use crate::procfs::sys_net;
use crate::procfs::sys_vm;
use crate::FsError;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Read the value from a procfs sysctl path under "sys/".
/// Returns the trimmed text content (strips trailing newline).
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
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_hostname_write_propagates);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 2 — net.ipv4.ip_forward (wired: IP_FORWARD atomic + ip_forward())
//
// Write "1" → ip_forward() returns true. Set back to "0".
// Linux ref: net/ipv4/devinet.c IPV4_DEVCONF_ALL, ipv4_forward_change()
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/net", e2e_net_ip_forward_propagates_to_accessor);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 3 — net.ipv4.tcp_congestion_control "reno"
//           (wired: TCP_CONG_ALG + tcp_cong_alg_name())
//
// Write "reno" → tcp_cong_alg_name() returns "reno". Restore "cubic".
// Linux ref: net/ipv4/tcp_cong.c tcp_set_default_congestion_control()
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/net", e2e_tcp_congestion_control_reno_propagates);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 4 — net.ipv4.tcp_timestamps 0
//           (wired: TCP_TIMESTAMPS atomic + tcp_option_defaults())
//
// Write "0" → tcp_option_defaults().1 (timestamps) is false.
// Restore "1".
// Linux ref: net/ipv4/sysctl_net_ipv4.c tcp_timestamps
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/net", e2e_tcp_timestamps_0_propagates_to_option_defaults);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 5 — net.ipv4.tcp_sack 0
//           (wired: TCP_SACK atomic + tcp_option_defaults())
//
// Write "0" → tcp_option_defaults().2 (sack) is false.
// Linux ref: net/ipv4/sysctl_net_ipv4.c tcp_sack
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/net", e2e_tcp_sack_0_propagates_to_option_defaults);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 6 — net.ipv4.tcp_window_scaling 0
//           (wired: TCP_WSCALE atomic + tcp_option_defaults())
//
// Write "0" → tcp_option_defaults().0 (wscale) is false.
// Linux ref: net/ipv4/sysctl_net_ipv4.c tcp_window_scaling
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/net", e2e_tcp_window_scaling_0_propagates_to_option_defaults);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 7 — net.ipv4.ip_local_port_range (wired: PORT_RANGE_LO/HI atomics
//            + ephemeral_port_range())
//
// Write "10000 20000" → ephemeral_port_range() == (10000, 20000).
// Linux ref: net/ipv4/inet_connection_sock.c inet_get_local_port_range()
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/net", e2e_ip_local_port_range_propagates_to_accessor);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 8 — net.ipv6.conf.all.forwarding 1
//           (wired: IPV6_FORWARDING atomic + ipv6_forwarding())
//
// Write "1" → ipv6_forwarding() true. Restore "0".
// Linux ref: net/ipv6/addrconf.c addrconf_sysctl IPV6_DEVCONF_FORWARDING
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/net", e2e_ipv6_forwarding_propagates_to_accessor);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 9 — vm.swappiness (accept-and-store: SWAPPINESS AtomicU64)
//
// Write "100" → SWAPPINESS atomic stores 100.
// No real consumer in the NARF vm yet; round-trip still confirms
// the sysctl write path stores correctly.
// Linux ref: mm/vmscan.c vm_swappiness (sysctl_vm_swappiness)
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/vm", e2e_vm_swappiness_write_100_stores_atomic);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 10 — kernel.pid_max 16384 (accept-and-store: PID_MAX AtomicU32)
//
// Write "16384" → read-back returns "16384".
// Linux ref: kernel/pid.c pid_max (PIDNS_ADDING_PIDS)
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_pid_max_write_16384);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 11 — kernel.ostype read-only: returns "NARF"
//
// Read-only key. Verifies read returns the expected constant string.
// Linux ref: kernel/sysctl.c kern_table[], utsname()->sysname
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_ostype_reads_narf);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 12 — kernel.modprobe read: returns empty stub ""
//
// N/A on NARF. The key exists and returns "" so tools that check
// for a modprobe path treat it as "no modprobe binary available".
// Linux ref: kernel/kmod.c modprobe_path[] (default "/sbin/modprobe")
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_modprobe_returns_empty_stub);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 13 — kernel.randomize_va_space 3: write → InvalidData
//
// Only 0, 1, 2 are valid. Writing 3 must return FsError::InvalidData.
// Linux ref: mm/mmap.c randomize_va_space, valid range [0,2]
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/kernel", e2e_randomize_va_space_3_returns_invalid_data);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 14 — net.ipv4.tcp_congestion_control "bogus": write → InvalidData
//
// Only "cubic" and "reno" are in AVAILABLE_CONG. "bogus" must fail.
// Linux ref: net/ipv4/tcp_cong.c tcp_set_congestion_control() -ENOENT
// ═══════════════════════════════════════════════════════════════════════════

fn e2e_tcp_congestion_control_bogus_returns_invalid_data() -> TestResult {
    sys_net::register_all();

    let path = &["sys", "net", "ipv4", "tcp_congestion_control"];
    match sysctl_write(path, b"bogus\n") {
        Some(Err(FsError::InvalidData)) => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("tcp_congestion_control write 'bogus' should return InvalidData"),
        Some(Err(e)) => {
            let _ = e;
            TestResult::Fail("tcp_congestion_control write 'bogus' returned unexpected error")
        }
        None => TestResult::Fail("tcp_congestion_control not found in registry"),
    }
}
kernel_test_in!("procsys_e2e/net", e2e_tcp_congestion_control_bogus_returns_invalid_data);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 15 — vm.swappiness 201: write → InvalidData
//
// Valid range is [0, 200]. Writing 201 must reject.
// Linux ref: mm/vmscan.c, swappiness range 0..200 (Linux 5.8+)
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/vm", e2e_vm_swappiness_201_returns_invalid_data);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 16 — kernel.pid_max -5: write → InvalidData
//
// pid_max must be a non-zero u32. "-5" fails to parse as u32.
// Linux ref: kernel/pid.c, pid_max bounded to [1, PID_MAX_LIMIT=4194304]
// ═══════════════════════════════════════════════════════════════════════════

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
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_pid_max_negative_returns_invalid_data);

// ═══════════════════════════════════════════════════════════════════════════
// Smoke 17 — kernel.dmesg_restrict write: returns ReadOnly
//
// NARF cap-gates dmesg access; this sysctl is read-only (no write fn).
// Writing any value must return FsError::ReadOnly.
// Linux ref: kernel/sysctl.c dmesg_restrict, kernel/printk/printk.c
// ═══════════════════════════════════════════════════════════════════════════

fn e2e_kernel_dmesg_restrict_write_returns_readonly() -> TestResult {
    sys_kernel::register_all();

    let path = &["sys", "kernel", "dmesg_restrict"];
    match sysctl_write(path, b"0\n") {
        Some(Err(FsError::ReadOnly)) => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("kernel/dmesg_restrict write should return ReadOnly"),
        Some(Err(e)) => {
            let _ = e;
            TestResult::Fail("kernel/dmesg_restrict write returned unexpected error (want ReadOnly)")
        }
        None => TestResult::Fail("kernel/dmesg_restrict not found in registry"),
    }
}
kernel_test_in!("procsys_e2e/kernel", e2e_kernel_dmesg_restrict_write_returns_readonly);
