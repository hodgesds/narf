//! `/proc/sys/net/*` — network sysctl keys.
//!
//! Implements the Linux `/proc/sys/net/{core,ipv4,ipv6}` sysctl surface.
//! All values are stored in static atomics so reads/writes are lock-free
//! and safe from any context (including IRQ handlers on the read path,
//! though writes come from userspace).
//!
//! ## Wire-up vs. accept-and-store
//!
//! | Key                          | Wired to                                  |
//! |------------------------------|-------------------------------------------|
//! | `ip_forward`                 | `IP_FORWARD` atomic, consulted by routing |
//! | `tcp_congestion_control`     | `TCP_CONG_ALG` IrqSafeSpinLock<String>   |
//! | `tcp_timestamps`             | `TCP_TIMESTAMPS` atomic                   |
//! | `tcp_sack`                   | `TCP_SACK` atomic                         |
//! | `tcp_window_scaling`         | `TCP_WSCALE` atomic                       |
//! | `ip_local_port_range`        | `PORT_RANGE_LO/HI` atomics                |
//! | everything else              | accept-and-store in dedicated atomics     |
//!
//! Linux refs:
//! - `net/ipv4/sysctl_net_ipv4.c` — `ipv4_table[]` ctl_table array
//! - `net/core/sysctl_net_core.c` — `net_core_table[]`
//! - `net/ipv6/addrconf.c`        — `addrconf_sysctl` / `ipv6_defaults`

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::sys::{register_sysctl, SysctlEntry};
use crate::FsError;

// ── net.core atomics ────────────────────────────────────────────────────

static SOMAXCONN: AtomicU32 = AtomicU32::new(128);
static NETDEV_MAX_BACKLOG: AtomicU32 = AtomicU32::new(1000);
static RMEM_DEFAULT: AtomicU32 = AtomicU32::new(212992);
static RMEM_MAX: AtomicU32 = AtomicU32::new(212992);
static WMEM_DEFAULT: AtomicU32 = AtomicU32::new(212992);
static WMEM_MAX: AtomicU32 = AtomicU32::new(212992);
static BPF_JIT_ENABLE: AtomicU32 = AtomicU32::new(0);
static BPF_JIT_KALLSYMS: AtomicU32 = AtomicU32::new(0);
// default_qdisc is a short string; 16 bytes is enough.
static DEFAULT_QDISC: IrqSafeSpinLock<[u8; 16]> =
    IrqSafeSpinLock::new(*b"fq_codel\0\0\0\0\0\0\0\0");

// ── net.ipv4 atomics ────────────────────────────────────────────────────

/// Consulted by the routing path: 1 = forward packets between interfaces.
pub static IP_FORWARD: AtomicU32 = AtomicU32::new(0);
static IP_DEFAULT_TTL: AtomicU32 = AtomicU32::new(64);
static TCP_KEEPALIVE_TIME: AtomicU32 = AtomicU32::new(7200);
static TCP_KEEPALIVE_INTVL: AtomicU32 = AtomicU32::new(75);
static TCP_KEEPALIVE_PROBES: AtomicU32 = AtomicU32::new(9);
static TCP_FIN_TIMEOUT: AtomicU32 = AtomicU32::new(60);
static TCP_MAX_SYN_BACKLOG: AtomicU32 = AtomicU32::new(256);
static TCP_SYNACK_RETRIES: AtomicU32 = AtomicU32::new(5);
static TCP_SYN_RETRIES: AtomicU32 = AtomicU32::new(6);
/// Exposed to TCP options layer. 1 = window scaling enabled by default.
pub static TCP_WSCALE: AtomicU32 = AtomicU32::new(1);
/// Exposed to TCP options layer. 1 = timestamps enabled by default.
pub static TCP_TIMESTAMPS: AtomicU32 = AtomicU32::new(1);
/// Exposed to TCP options layer. 1 = SACK enabled by default.
pub static TCP_SACK: AtomicU32 = AtomicU32::new(1);
static TCP_ECN: AtomicU32 = AtomicU32::new(2);
static TCP_NO_METRICS_SAVE: AtomicU32 = AtomicU32::new(0);
static TCP_MAX_ORPHANS: AtomicU32 = AtomicU32::new(4096);
static TCP_MTU_PROBING: AtomicU32 = AtomicU32::new(0);
// tcp_rmem: min / default / max (bytes)
static TCP_RMEM_MIN: AtomicU32 = AtomicU32::new(4096);
static TCP_RMEM_DEFAULT: AtomicU32 = AtomicU32::new(131072);
static TCP_RMEM_MAX: AtomicU32 = AtomicU32::new(6291456);
// tcp_wmem: min / default / max (bytes)
static TCP_WMEM_MIN: AtomicU32 = AtomicU32::new(4096);
static TCP_WMEM_DEFAULT: AtomicU32 = AtomicU32::new(16384);
static TCP_WMEM_MAX: AtomicU32 = AtomicU32::new(4194304);
// udp socket minimums
static UDP_RMEM_MIN: AtomicU32 = AtomicU32::new(4096);
static UDP_WMEM_MIN: AtomicU32 = AtomicU32::new(4096);
// icmp
static ICMP_ECHO_IGNORE_ALL: AtomicU32 = AtomicU32::new(0);
static ICMP_ECHO_IGNORE_BROADCASTS: AtomicU32 = AtomicU32::new(1);
static ICMP_RATELIMIT: AtomicU32 = AtomicU32::new(1000);
// ephemeral port range
pub static PORT_RANGE_LO: AtomicU32 = AtomicU32::new(32768);
pub static PORT_RANGE_HI: AtomicU32 = AtomicU32::new(60999);

/// Active congestion-control algorithm name. Defaults to "cubic".
/// Valid values: "cubic", "reno" (subset of available).
pub static TCP_CONG_ALG: IrqSafeSpinLock<[u8; 16]> =
    IrqSafeSpinLock::new(*b"cubic\0\0\0\0\0\0\0\0\0\0\0");
/// Allowed set for writes (validated at write time).
const AVAILABLE_CONG: &[&str] = &["cubic", "reno"];
/// Allowed congestion algorithms (writable subset of available).
static TCP_ALLOWED_CONG: IrqSafeSpinLock<[u8; 32]> =
    IrqSafeSpinLock::new(*b"cubic reno\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

// ── net.ipv6 atomics ────────────────────────────────────────────────────

pub static IPV6_FORWARDING: AtomicU32 = AtomicU32::new(0);
static IPV6_ACCEPT_RA: AtomicU32 = AtomicU32::new(1);
static IPV6_AUTOCONF: AtomicU32 = AtomicU32::new(1);
static IPV6_USE_TEMPADDR: AtomicU32 = AtomicU32::new(2);
static IPV6_DISABLE_IPV6: AtomicU32 = AtomicU32::new(0);
static IPV6_BINDV6ONLY: AtomicU32 = AtomicU32::new(0);

// ── Helpers ──────────────────────────────────────────────────────────────

fn read_cstring_16(slot: &IrqSafeSpinLock<[u8; 16]>) -> String {
    let g = slot.lock();
    let end = g.iter().position(|&b| b == 0).unwrap_or(16);
    core::str::from_utf8(&g[..end]).unwrap_or("?").to_string()
}

fn read_cstring_32(slot: &IrqSafeSpinLock<[u8; 32]>) -> String {
    let g = slot.lock();
    let end = g.iter().position(|&b| b == 0).unwrap_or(32);
    core::str::from_utf8(&g[..end]).unwrap_or("?").to_string()
}

fn write_cstring_16(slot: &IrqSafeSpinLock<[u8; 16]>, val: &str) -> Result<(), FsError> {
    let bytes = val.as_bytes();
    if bytes.len() >= 16 {
        return Err(FsError::InvalidData);
    }
    let mut g = slot.lock();
    *g = [0u8; 16];
    g[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

fn write_cstring_32(slot: &IrqSafeSpinLock<[u8; 32]>, val: &str) -> Result<(), FsError> {
    let bytes = val.as_bytes();
    if bytes.len() >= 32 {
        return Err(FsError::InvalidData);
    }
    let mut g = slot.lock();
    *g = [0u8; 32];
    g[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

fn parse_u32(s: &str) -> Result<u32, FsError> {
    s.parse::<u32>().map_err(|_| FsError::InvalidData)
}

fn fmt_u32(v: u32) -> String {
    format!("{}\n", v)
}

fn read_atomic(a: &'static AtomicU32) -> String {
    fmt_u32(a.load(Ordering::Relaxed))
}

fn write_atomic(a: &'static AtomicU32, s: &str) -> Result<(), FsError> {
    let v = parse_u32(s)?;
    a.store(v, Ordering::Relaxed);
    Ok(())
}

fn write_bool_atomic(a: &'static AtomicU32, s: &str) -> Result<(), FsError> {
    let v = parse_u32(s)?;
    if v > 1 {
        return Err(FsError::InvalidData);
    }
    a.store(v, Ordering::Relaxed);
    Ok(())
}

// ── Public accessors (consulted by net stack) ────────────────────────────

/// True iff IP forwarding is globally enabled.
#[inline]
pub fn ip_forward() -> bool {
    IP_FORWARD.load(Ordering::Relaxed) != 0
}

/// True iff IPv6 forwarding is globally enabled.
#[inline]
pub fn ipv6_forwarding() -> bool {
    IPV6_FORWARDING.load(Ordering::Relaxed) != 0
}

/// Current default congestion control algorithm name.
pub fn tcp_cong_alg_name() -> String {
    read_cstring_16(&TCP_CONG_ALG)
}

/// Default ephemeral port range [lo, hi].
#[inline]
pub fn ephemeral_port_range() -> (u16, u16) {
    let lo = PORT_RANGE_LO.load(Ordering::Relaxed) as u16;
    let hi = PORT_RANGE_HI.load(Ordering::Relaxed) as u16;
    (lo, hi)
}

/// Default TCP options flags (window_scaling, timestamps, sack).
#[inline]
pub fn tcp_option_defaults() -> (bool, bool, bool) {
    let ws = TCP_WSCALE.load(Ordering::Relaxed) != 0;
    let ts = TCP_TIMESTAMPS.load(Ordering::Relaxed) != 0;
    let sack = TCP_SACK.load(Ordering::Relaxed) != 0;
    (ws, ts, sack)
}

// ── Registration ─────────────────────────────────────────────────────────

/// Register all `/proc/sys/net/*` sysctl keys.
/// Called once from boot init. Idempotent via `register_proc` semantics.
pub fn register_all() {
    // ── net.core ─────────────────────────────────────────────────────────

    register_sysctl(SysctlEntry {
        path: "net/core/somaxconn",
        read: || read_atomic(&SOMAXCONN),
        write: Some(|s| write_atomic(&SOMAXCONN, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/core/netdev_max_backlog",
        read: || read_atomic(&NETDEV_MAX_BACKLOG),
        write: Some(|s| write_atomic(&NETDEV_MAX_BACKLOG, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/core/rmem_default",
        read: || read_atomic(&RMEM_DEFAULT),
        write: Some(|s| write_atomic(&RMEM_DEFAULT, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/core/rmem_max",
        read: || read_atomic(&RMEM_MAX),
        write: Some(|s| write_atomic(&RMEM_MAX, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/core/wmem_default",
        read: || read_atomic(&WMEM_DEFAULT),
        write: Some(|s| write_atomic(&WMEM_DEFAULT, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/core/wmem_max",
        read: || read_atomic(&WMEM_MAX),
        write: Some(|s| write_atomic(&WMEM_MAX, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/core/default_qdisc",
        read: || {
            let mut s = read_cstring_16(&DEFAULT_QDISC);
            s.push('\n');
            s
        },
        write: Some(|s| write_cstring_16(&DEFAULT_QDISC, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/core/bpf_jit_enable",
        read: || read_atomic(&BPF_JIT_ENABLE),
        write: Some(|s| write_bool_atomic(&BPF_JIT_ENABLE, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/core/bpf_jit_kallsyms",
        read: || read_atomic(&BPF_JIT_KALLSYMS),
        write: Some(|s| write_bool_atomic(&BPF_JIT_KALLSYMS, s)),
        perms: 0o644,
    });

    // ── net.ipv4 ─────────────────────────────────────────────────────────

    register_sysctl(SysctlEntry {
        path: "net/ipv4/ip_forward",
        read: || read_atomic(&IP_FORWARD),
        write: Some(|s| write_bool_atomic(&IP_FORWARD, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/ip_default_ttl",
        read: || read_atomic(&IP_DEFAULT_TTL),
        write: Some(|s| write_atomic(&IP_DEFAULT_TTL, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_congestion_control",
        read: || {
            let mut s = read_cstring_16(&TCP_CONG_ALG);
            s.push('\n');
            s
        },
        write: Some(|s| {
            // Validate against available list.
            if !AVAILABLE_CONG.contains(&s) {
                return Err(FsError::InvalidData);
            }
            write_cstring_16(&TCP_CONG_ALG, s)
        }),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_available_congestion_control",
        read: || String::from("cubic reno\n"),
        write: None,
        perms: 0o444,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_allowed_congestion_control",
        read: || {
            let mut s = read_cstring_32(&TCP_ALLOWED_CONG);
            s.push('\n');
            s
        },
        write: Some(|s| {
            // Each space-separated token must be in available list.
            for tok in s.split_whitespace() {
                if !AVAILABLE_CONG.contains(&tok) {
                    return Err(FsError::InvalidData);
                }
            }
            write_cstring_32(&TCP_ALLOWED_CONG, s)
        }),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_keepalive_time",
        read: || read_atomic(&TCP_KEEPALIVE_TIME),
        write: Some(|s| write_atomic(&TCP_KEEPALIVE_TIME, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_keepalive_intvl",
        read: || read_atomic(&TCP_KEEPALIVE_INTVL),
        write: Some(|s| write_atomic(&TCP_KEEPALIVE_INTVL, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_keepalive_probes",
        read: || read_atomic(&TCP_KEEPALIVE_PROBES),
        write: Some(|s| write_atomic(&TCP_KEEPALIVE_PROBES, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_fin_timeout",
        read: || read_atomic(&TCP_FIN_TIMEOUT),
        write: Some(|s| write_atomic(&TCP_FIN_TIMEOUT, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_max_syn_backlog",
        read: || read_atomic(&TCP_MAX_SYN_BACKLOG),
        write: Some(|s| write_atomic(&TCP_MAX_SYN_BACKLOG, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_synack_retries",
        read: || read_atomic(&TCP_SYNACK_RETRIES),
        write: Some(|s| write_atomic(&TCP_SYNACK_RETRIES, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_syn_retries",
        read: || read_atomic(&TCP_SYN_RETRIES),
        write: Some(|s| write_atomic(&TCP_SYN_RETRIES, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_window_scaling",
        read: || read_atomic(&TCP_WSCALE),
        write: Some(|s| write_bool_atomic(&TCP_WSCALE, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_timestamps",
        read: || read_atomic(&TCP_TIMESTAMPS),
        write: Some(|s| write_bool_atomic(&TCP_TIMESTAMPS, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_sack",
        read: || read_atomic(&TCP_SACK),
        write: Some(|s| write_bool_atomic(&TCP_SACK, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_ecn",
        read: || read_atomic(&TCP_ECN),
        write: Some(|s| write_atomic(&TCP_ECN, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_no_metrics_save",
        read: || read_atomic(&TCP_NO_METRICS_SAVE),
        write: Some(|s| write_bool_atomic(&TCP_NO_METRICS_SAVE, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_max_orphans",
        read: || read_atomic(&TCP_MAX_ORPHANS),
        write: Some(|s| write_atomic(&TCP_MAX_ORPHANS, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_mtu_probing",
        read: || read_atomic(&TCP_MTU_PROBING),
        write: Some(|s| write_atomic(&TCP_MTU_PROBING, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_rmem",
        read: || {
            format!(
                "{}\t{}\t{}\n",
                TCP_RMEM_MIN.load(Ordering::Relaxed),
                TCP_RMEM_DEFAULT.load(Ordering::Relaxed),
                TCP_RMEM_MAX.load(Ordering::Relaxed)
            )
        },
        write: Some(|s| {
            let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
            if parts.len() != 3 {
                return Err(FsError::InvalidData);
            }
            let mn = parse_u32(parts[0])?;
            let def = parse_u32(parts[1])?;
            let mx = parse_u32(parts[2])?;
            if mn > def || def > mx {
                return Err(FsError::InvalidData);
            }
            TCP_RMEM_MIN.store(mn, Ordering::Relaxed);
            TCP_RMEM_DEFAULT.store(def, Ordering::Relaxed);
            TCP_RMEM_MAX.store(mx, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_wmem",
        read: || {
            format!(
                "{}\t{}\t{}\n",
                TCP_WMEM_MIN.load(Ordering::Relaxed),
                TCP_WMEM_DEFAULT.load(Ordering::Relaxed),
                TCP_WMEM_MAX.load(Ordering::Relaxed)
            )
        },
        write: Some(|s| {
            let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
            if parts.len() != 3 {
                return Err(FsError::InvalidData);
            }
            let mn = parse_u32(parts[0])?;
            let def = parse_u32(parts[1])?;
            let mx = parse_u32(parts[2])?;
            if mn > def || def > mx {
                return Err(FsError::InvalidData);
            }
            TCP_WMEM_MIN.store(mn, Ordering::Relaxed);
            TCP_WMEM_DEFAULT.store(def, Ordering::Relaxed);
            TCP_WMEM_MAX.store(mx, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/udp_rmem_min",
        read: || read_atomic(&UDP_RMEM_MIN),
        write: Some(|s| write_atomic(&UDP_RMEM_MIN, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/udp_wmem_min",
        read: || read_atomic(&UDP_WMEM_MIN),
        write: Some(|s| write_atomic(&UDP_WMEM_MIN, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/icmp_echo_ignore_all",
        read: || read_atomic(&ICMP_ECHO_IGNORE_ALL),
        write: Some(|s| write_bool_atomic(&ICMP_ECHO_IGNORE_ALL, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/icmp_echo_ignore_broadcasts",
        read: || read_atomic(&ICMP_ECHO_IGNORE_BROADCASTS),
        write: Some(|s| write_bool_atomic(&ICMP_ECHO_IGNORE_BROADCASTS, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/icmp_ratelimit",
        read: || read_atomic(&ICMP_RATELIMIT),
        write: Some(|s| write_atomic(&ICMP_RATELIMIT, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/ip_local_port_range",
        read: || {
            format!(
                "{}\t{}\n",
                PORT_RANGE_LO.load(Ordering::Relaxed),
                PORT_RANGE_HI.load(Ordering::Relaxed)
            )
        },
        write: Some(|s| {
            let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(FsError::InvalidData);
            }
            let lo = parse_u32(parts[0])?;
            let hi = parse_u32(parts[1])?;
            if lo > hi || hi > 65535 {
                return Err(FsError::InvalidData);
            }
            PORT_RANGE_LO.store(lo, Ordering::Relaxed);
            PORT_RANGE_HI.store(hi, Ordering::Relaxed);
            Ok(())
        }),
        perms: 0o644,
    });

    // ── net.ipv6 (conf/all/* + global) ──────────────────────────────────

    register_sysctl(SysctlEntry {
        path: "net/ipv6/conf/all/forwarding",
        read: || read_atomic(&IPV6_FORWARDING),
        write: Some(|s| write_bool_atomic(&IPV6_FORWARDING, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv6/conf/all/accept_ra",
        read: || read_atomic(&IPV6_ACCEPT_RA),
        write: Some(|s| write_bool_atomic(&IPV6_ACCEPT_RA, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv6/conf/all/autoconf",
        read: || read_atomic(&IPV6_AUTOCONF),
        write: Some(|s| write_bool_atomic(&IPV6_AUTOCONF, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv6/conf/all/use_tempaddr",
        read: || read_atomic(&IPV6_USE_TEMPADDR),
        write: Some(|s| write_atomic(&IPV6_USE_TEMPADDR, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv6/conf/all/disable_ipv6",
        read: || read_atomic(&IPV6_DISABLE_IPV6),
        write: Some(|s| write_bool_atomic(&IPV6_DISABLE_IPV6, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv6/bindv6only",
        read: || read_atomic(&IPV6_BINDV6ONLY),
        write: Some(|s| write_bool_atomic(&IPV6_BINDV6ONLY, s)),
        perms: 0o644,
    });
}

// ── Tests ────────────────────────────────────────────────────────────────

use super::{lookup_registry, ProcNodeSnapshot};
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_core_somaxconn_default_128() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "net", "core", "somaxconn"]);
    match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("").trim();
            if s == "128" {
                TestResult::Pass
            } else {
                TestResult::Fail("somaxconn default not 128")
            }
        }
        _ => TestResult::Fail("somaxconn not found in registry"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_core_somaxconn_default_128
);

fn smoke_core_somaxconn_write_roundtrip() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "net", "core", "somaxconn"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            // Reset first.
            SOMAXCONN.store(128, Ordering::Relaxed);
            let wr = f.write(b"256\n");
            if wr.is_err() {
                return TestResult::Fail("write returned error");
            }
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("").trim();
            s == "256"
        }
        _ => return TestResult::Fail("somaxconn not found"),
    };
    SOMAXCONN.store(128, Ordering::Relaxed);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("somaxconn round-trip failed")
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_core_somaxconn_write_roundtrip
);

fn smoke_ipv4_ip_forward_0_1() -> TestResult {
    register_all();
    IP_FORWARD.store(0, Ordering::Relaxed);
    let snap = lookup_registry(&["sys", "net", "ipv4", "ip_forward"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let v0 = f.read();
            let s0 = core::str::from_utf8(&v0).unwrap_or("").trim();
            if s0 != "0" {
                return TestResult::Fail("ip_forward default not 0");
            }
            let _ = f.write(b"1\n");
            let v1 = f.read();
            let s1 = core::str::from_utf8(&v1).unwrap_or("").trim();
            s1 == "1"
        }
        _ => return TestResult::Fail("ip_forward not found"),
    };
    IP_FORWARD.store(0, Ordering::Relaxed);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("ip_forward toggle failed")
    }
}
kernel_test_in!("filesystem/procfs/sys_net", smoke_ipv4_ip_forward_0_1);

fn smoke_ipv4_ip_default_ttl_write_32() -> TestResult {
    register_all();
    IP_DEFAULT_TTL.store(64, Ordering::Relaxed);
    let snap = lookup_registry(&["sys", "net", "ipv4", "ip_default_ttl"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let _ = f.write(b"32\n");
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("").trim();
            s == "32"
        }
        _ => return TestResult::Fail("ip_default_ttl not found"),
    };
    IP_DEFAULT_TTL.store(64, Ordering::Relaxed);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("ip_default_ttl write failed")
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_ipv4_ip_default_ttl_write_32
);

fn smoke_tcp_available_congestion_control_has_cubic_reno() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "net", "ipv4", "tcp_available_congestion_control"]);
    match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("");
            if s.contains("cubic") && s.contains("reno") {
                TestResult::Pass
            } else {
                TestResult::Fail("available_congestion_control missing cubic or reno")
            }
        }
        _ => TestResult::Fail("tcp_available_congestion_control not found"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_tcp_available_congestion_control_has_cubic_reno
);

fn smoke_tcp_congestion_control_write_reno() -> TestResult {
    register_all();
    // Reset to cubic.
    write_cstring_16(&TCP_CONG_ALG, "cubic").ok();
    let snap = lookup_registry(&["sys", "net", "ipv4", "tcp_congestion_control"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let wr = f.write(b"reno\n");
            if wr.is_err() {
                return TestResult::Fail("write reno returned error");
            }
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("").trim();
            s == "reno"
        }
        _ => return TestResult::Fail("tcp_congestion_control not found"),
    };
    write_cstring_16(&TCP_CONG_ALG, "cubic").ok();
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("congestion control reno write failed")
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_tcp_congestion_control_write_reno
);

fn smoke_tcp_congestion_control_write_bogus_invalid_data() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "net", "ipv4", "tcp_congestion_control"]);
    match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let result = f.write(b"bogus\n");
            if matches!(result, Err(FsError::InvalidData)) {
                TestResult::Pass
            } else {
                TestResult::Fail("bogus cc did not return InvalidData")
            }
        }
        _ => TestResult::Fail("tcp_congestion_control not found"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_tcp_congestion_control_write_bogus_invalid_data
);

fn smoke_tcp_rmem_returns_3_int_format() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "net", "ipv4", "tcp_rmem"]);
    match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("").trim();
            let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
            if parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()) {
                TestResult::Pass
            } else {
                TestResult::Fail("tcp_rmem did not return 3-int format")
            }
        }
        _ => TestResult::Fail("tcp_rmem not found"),
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_tcp_rmem_returns_3_int_format
);

fn smoke_ip_local_port_range_roundtrip() -> TestResult {
    register_all();
    PORT_RANGE_LO.store(32768, Ordering::Relaxed);
    PORT_RANGE_HI.store(60999, Ordering::Relaxed);
    let snap = lookup_registry(&["sys", "net", "ipv4", "ip_local_port_range"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let _ = f.write(b"1024\t65000\n");
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("").trim();
            let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
            parts.len() == 2 && parts[0] == "1024" && parts[1] == "65000"
        }
        _ => return TestResult::Fail("ip_local_port_range not found"),
    };
    PORT_RANGE_LO.store(32768, Ordering::Relaxed);
    PORT_RANGE_HI.store(60999, Ordering::Relaxed);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("port_range round-trip failed")
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_ip_local_port_range_roundtrip
);

fn smoke_icmp_echo_ignore_all_0_1() -> TestResult {
    register_all();
    ICMP_ECHO_IGNORE_ALL.store(0, Ordering::Relaxed);
    let snap = lookup_registry(&["sys", "net", "ipv4", "icmp_echo_ignore_all"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let v0 = f.read();
            let s0 = core::str::from_utf8(&v0).unwrap_or("").trim();
            if s0 != "0" {
                return TestResult::Fail("icmp_echo_ignore_all default not 0");
            }
            let _ = f.write(b"1\n");
            let v1 = f.read();
            let s1 = core::str::from_utf8(&v1).unwrap_or("").trim();
            s1 == "1"
        }
        _ => return TestResult::Fail("icmp_echo_ignore_all not found"),
    };
    ICMP_ECHO_IGNORE_ALL.store(0, Ordering::Relaxed);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("icmp_echo_ignore_all toggle failed")
    }
}
kernel_test_in!("filesystem/procfs/sys_net", smoke_icmp_echo_ignore_all_0_1);

fn smoke_ipv6_conf_all_forwarding_0_1() -> TestResult {
    register_all();
    IPV6_FORWARDING.store(0, Ordering::Relaxed);
    let snap = lookup_registry(&["sys", "net", "ipv6", "conf", "all", "forwarding"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let v0 = f.read();
            let s0 = core::str::from_utf8(&v0).unwrap_or("").trim();
            if s0 != "0" {
                return TestResult::Fail("ipv6 forwarding default not 0");
            }
            let _ = f.write(b"1\n");
            let v1 = f.read();
            let s1 = core::str::from_utf8(&v1).unwrap_or("").trim();
            s1 == "1"
        }
        _ => return TestResult::Fail("ipv6/conf/all/forwarding not found"),
    };
    IPV6_FORWARDING.store(0, Ordering::Relaxed);
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("ipv6 forwarding toggle failed")
    }
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_ipv6_conf_all_forwarding_0_1
);

fn smoke_tcp_syn_retries_default_6() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "net", "ipv4", "tcp_syn_retries"]);
    match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("").trim();
            if s == "6" {
                TestResult::Pass
            } else {
                TestResult::Fail("tcp_syn_retries default not 6")
            }
        }
        _ => TestResult::Fail("tcp_syn_retries not found"),
    }
}
kernel_test_in!("filesystem/procfs/sys_net", smoke_tcp_syn_retries_default_6);
