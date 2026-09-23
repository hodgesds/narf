//! `/proc/sys/net/*` — network sysctl keys.
//!
//! Implements the Linux `/proc/sys/net/{core,ipv4,ipv6}` sysctl surface.
//! All values are stored in static atomics so reads/writes are lock-free
//! and safe from any context (including IRQ handlers on the read path,
//! though writes come from userspace).
//!
//! ## Enforced vs. accept-and-store
//!
//! Most keys here are accept-and-store: the value round-trips through
//! `/proc` and nothing consults it. That is not always visible from this
//! crate, because the code that *would* obey a `net.*` key lives in
//! `narf-net`, which cannot see `narf-filesystem` (no dependency either way;
//! `frame::cross_crate_init` bridges them with read-only hooks). A key that
//! must reach the datapath therefore lives in `narf_lib::sysctl`, which both
//! crates depend on — that, not the presence of an atomic here, is what
//! makes one enforced.
//!
//! Enforced, with the code that obeys it:
//!
//! | Key                            | Obeyed by                              |
//! |--------------------------------|----------------------------------------|
//! | `ip_forward`                   | `net::ip_forward::try_forward`         |
//! | `conf/<dev>/forwarding`        | ditto, per ingress interface           |
//! | `conf/<dev>/send_redirects`    | `net::ip_forward` redirect generation  |
//! | `ip_default_ttl`               | `net::pkt::write_ipv4_header`          |
//! | `icmp_echo_ignore_all`         | `net::icmp_sock::handle_echo_request`  |
//! | `icmp_echo_ignore_broadcasts`  | ditto                                  |
//! | `tcp_window_scaling`           | `net::tcp::options` (SYN + negotiate)  |
//! | `tcp_timestamps`               | ditto                                  |
//! | `tcp_sack`                     | ditto                                  |
//! | `net/core/somaxconn`           | `net::tcp::core::listen_in`            |
//!
//! Accept-and-store — the value is kept and returned, and nothing reads it.
//! Named individually because each one previously carried, or still carries,
//! an accessor that reads like a wiring claim:
//!
//! - `tcp_congestion_control` / `tcp_cong_alg_name()` — no caller outside
//!   tests; the TCP stack does not select its algorithm from this.
//! - `ip_local_port_range` / `ephemeral_port_range()` — no caller outside
//!   tests. `tcp::core::fresh_local_port` is a bare incrementing counter and
//!   `udp_sock` has its own `UDP_EPHEMERAL_MIN/MAX` constants.
//! - `ipv6/conf/all/forwarding` / `ipv6_forwarding()` — no caller outside
//!   tests.
//! - everything else registered below.
//!
//! ## Write validation
//!
//! Each key's accepted range mirrors the `proc_handler` Linux gives it, and
//! a rejected write is `FsError::InvalidData` → EINVAL, as
//! `proc_dointvec_minmax` returns. The bound is not always 0..=1 even for a
//! key that reads like a boolean: `proc_dou8vec_minmax` defaults to 0..=255
//! when the ctl_table carries no `extra1`/`extra2`, which is how
//! `tcp_timestamps=2` is a valid Linux setting.
//!
//! Linux refs:
//! - `net/ipv4/sysctl_net_ipv4.c` — `ipv4_table[]` ctl_table array
//! - `net/core/sysctl_net_core.c` — `net_core_table[]`
//! - `net/ipv6/addrconf.c`        — `addrconf_sysctl` / `ipv6_defaults`

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::sys::{register_sysctl, SysctlEntry};
use crate::FsError;

// ── net.core atomics ────────────────────────────────────────────────────

// Consulted by `listen(2)` in `narf-net`; see the ICMP knobs below.
pub use narf_lib::sysctl::ipv4::SOMAXCONN;
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

/// Consulted by the IPv4 forwarding path in `narf-net`, so it lives in
/// `narf_lib::sysctl` for the same reason the ICMP knobs below do.
pub use narf_lib::sysctl::ipv4::IP_FORWARD;
// Stamped on locally-originated packets by `narf-net`.
pub use narf_lib::sysctl::ipv4::IP_DEFAULT_TTL;
static TCP_KEEPALIVE_TIME: AtomicU32 = AtomicU32::new(7200);
static TCP_KEEPALIVE_INTVL: AtomicU32 = AtomicU32::new(75);
static TCP_KEEPALIVE_PROBES: AtomicU32 = AtomicU32::new(9);
static TCP_FIN_TIMEOUT: AtomicU32 = AtomicU32::new(60);
static TCP_MAX_SYN_BACKLOG: AtomicU32 = AtomicU32::new(256);
static TCP_SYNACK_RETRIES: AtomicU32 = AtomicU32::new(5);
static TCP_SYN_RETRIES: AtomicU32 = AtomicU32::new(6);
// Consulted by the TCP option layer in `narf-net`, so these live in
// `narf_lib::sysctl` for the same reason the ICMP and forwarding knobs do.
pub use narf_lib::sysctl::ipv4::TCP_SACK;
pub use narf_lib::sysctl::ipv4::TCP_TIMESTAMPS;
pub use narf_lib::sysctl::ipv4::TCP_WINDOW_SCALING as TCP_WSCALE;
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
//
// These two live in `narf_lib::sysctl` rather than here: the ICMP datapath
// in `narf-net` has to read them on every echo request, and `narf-net` and
// `narf-filesystem` cannot see each other. Keeping a copy here would mean a
// write to `/proc/sys` reading back correctly while the datapath kept
// answering from a second, untouched copy.
use narf_lib::sysctl::ipv4::{ICMP_ECHO_IGNORE_ALL, ICMP_ECHO_IGNORE_BROADCASTS};
static ICMP_RATELIMIT: AtomicU32 = AtomicU32::new(1000);
// ephemeral port range
pub static PORT_RANGE_LO: AtomicU32 = AtomicU32::new(32768);
pub static PORT_RANGE_HI: AtomicU32 = AtomicU32::new(60999);
static UNIX_MAX_DGRAM_QLEN: AtomicU32 = AtomicU32::new(512);

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

/// Write `ip_forward` / `conf.all.forwarding`, which is not a plain store:
/// Linux's `inet_forward_change` stamps `conf.default` and overwrites every
/// interface's setting. See `narf_lib::sysctl::ipv4::set_all_forwarding`.
fn write_all_forwarding(s: &str) -> Result<(), FsError> {
    // `devinet_sysctl_forward` runs `proc_dointvec`: no 0/1 bound, any
    // non-zero means on.
    let v = parse_u32(s)?;
    if v > i32::MAX as u32 {
        return Err(FsError::InvalidData);
    }
    narf_lib::sysctl::ipv4::set_all_forwarding(v != 0);
    Ok(())
}

/// `proc_dou8vec_minmax` — a u8-backed key, rejected with EINVAL outside
/// `[min, max]`.
///
/// Linux defaults the bounds to 0..=255 when the ctl_table carries no
/// `extra1`/`extra2`, which is why several boolean-looking keys accept far
/// more than 0 and 1: `tcp_timestamps` takes 2 ("on, without the random
/// per-connection offset"), and `sysctl -w net.ipv4.tcp_timestamps=2` is a
/// configuration real systems use. Refusing it is an ABI difference, not a
/// stricter-is-safer choice.
fn write_u8_minmax(a: &'static AtomicU32, s: &str, min: u32, max: u32) -> Result<(), FsError> {
    let v = parse_u32(s)?;
    if v < min || v > max {
        return Err(FsError::InvalidData);
    }
    a.store(v, Ordering::Relaxed);
    Ok(())
}

/// `proc_dointvec` / `proc_dointvec_minmax` with `extra1 = SYSCTL_ZERO` — an
/// int-backed key with no upper bound below `INT_MAX`.
///
/// Linux's `proc_dointvec` keys additionally accept negative values and treat
/// any non-zero as set. NARF stores these in a `u32` and answers EINVAL for a
/// negative, which is the one place this surface still diverges; no writer in
/// practice sets a negative here.
fn write_uint_atomic(a: &'static AtomicU32, s: &str) -> Result<(), FsError> {
    let v = parse_u32(s)?;
    if v > i32::MAX as u32 {
        return Err(FsError::InvalidData);
    }
    a.store(v, Ordering::Relaxed);
    Ok(())
}

/// A key Linux bounds to 0..=1 (`extra1 = SYSCTL_ZERO, extra2 = SYSCTL_ONE`).
fn write_bool_atomic(a: &'static AtomicU32, s: &str) -> Result<(), FsError> {
    write_u8_minmax(a, s, 0, 1)
}

// ── Public accessors (consulted by net stack) ────────────────────────────

/// True iff IP forwarding is globally enabled.
#[inline]
pub fn ip_forward() -> bool {
    narf_lib::sysctl::ipv4::ip_forward()
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
    narf_lib::sysctl::ipv4::tcp_option_defaults()
}

// ── Registration ─────────────────────────────────────────────────────────

/// Register all `/proc/sys/net/*` sysctl keys.
/// Called once from boot init. Idempotent via `register_proc` semantics.
pub fn register_all() {
    // ── net.core ─────────────────────────────────────────────────────────

    register_sysctl(SysctlEntry {
        path: "net/core/somaxconn",
        read: || read_atomic(&SOMAXCONN),
        write: Some(|s| write_uint_atomic(&SOMAXCONN, s)),
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
        write: Some(write_all_forwarding),
        perms: 0o644,
    });
    // Linux presents the same value under both names.
    register_sysctl(SysctlEntry {
        path: "net/ipv4/conf/all/forwarding",
        read: || read_atomic(&IP_FORWARD),
        write: Some(write_all_forwarding),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/conf/all/send_redirects",
        read: || read_atomic(&narf_lib::sysctl::ipv4::SEND_REDIRECTS_ALL),
        write: Some(|s| write_uint_atomic(&narf_lib::sysctl::ipv4::SEND_REDIRECTS_ALL, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/conf/default/send_redirects",
        read: || read_atomic(&narf_lib::sysctl::ipv4::SEND_REDIRECTS_DEFAULT),
        write: Some(|s| write_uint_atomic(&narf_lib::sysctl::ipv4::SEND_REDIRECTS_DEFAULT, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/conf/default/forwarding",
        read: || read_atomic(&narf_lib::sysctl::ipv4::IP_FORWARD_DEFAULT),
        write: Some(|s| write_uint_atomic(&narf_lib::sysctl::ipv4::IP_FORWARD_DEFAULT, s)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/ip_default_ttl",
        read: || read_atomic(&IP_DEFAULT_TTL),
        // `ip_ttl_min` = 1, `ip_ttl_max` = 255 in sysctl_net_ipv4.c: a TTL of
        // 0 would put packets on the wire that die at the first hop, so Linux
        // refuses it rather than accepting and clamping.
        write: Some(|s| write_u8_minmax(&IP_DEFAULT_TTL, s, 1, 255)),
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
        // `proc_dou8vec_minmax` with no extras — the full u8 range.
        write: Some(|s| write_u8_minmax(&TCP_WSCALE, s, 0, 255)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_timestamps",
        read: || read_atomic(&TCP_TIMESTAMPS),
        // `proc_dou8vec_minmax` with no extras — the full u8 range.
        write: Some(|s| write_u8_minmax(&TCP_TIMESTAMPS, s, 0, 255)),
        perms: 0o644,
    });
    register_sysctl(SysctlEntry {
        path: "net/ipv4/tcp_sack",
        read: || read_atomic(&TCP_SACK),
        // `proc_dou8vec_minmax` with no extras — the full u8 range.
        write: Some(|s| write_u8_minmax(&TCP_SACK, s, 0, 255)),
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
    register_sysctl(SysctlEntry {
        path: "net/unix/max_dgram_qlen",
        read: || read_atomic(&UNIX_MAX_DGRAM_QLEN),
        write: Some(|s| write_atomic(&UNIX_MAX_DGRAM_QLEN, s)),
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

fn smoke_unix_max_dgram_qlen_rw() -> TestResult {
    register_all();
    let snap = lookup_registry(&["sys", "net", "unix", "max_dgram_qlen"]);
    match snap {
        Some(ProcNodeSnapshot::File(f)) => {
            let _ = f.write(b"1024\n");
            let v = f.read();
            let s = core::str::from_utf8(&v).unwrap_or("").trim();
            if s == "1024" {
                TestResult::Pass
            } else {
                TestResult::Fail("max_dgram_qlen readback mismatch")
            }
        }
        _ => TestResult::Fail("max_dgram_qlen not found"),
    }
}
kernel_test_in!("filesystem/procfs/sys_net", smoke_unix_max_dgram_qlen_rw);

// ── Per-interface net.ipv4.conf.<dev>.* ─────────────────────────────────
//
// These cannot be `SysctlEntry`s: that struct carries a `&'static str` path
// and zero-argument read/write fns, so an entry has no way to know which
// interface it belongs to. A `ProcFile` implementation can hold the name,
// and `register_proc` takes a runtime path, so the per-device keys are
// registered directly against the procfs registry instead.
//
// Registration is driven from `narf-net`, which is where interfaces appear,
// through a hook installed in `frame::cross_crate_init` — procfs cannot see
// the net stack to enumerate them itself.

/// Which per-interface key a [`DevConfFile`] serves.
#[derive(Copy, Clone, Debug)]
enum DevKey {
    Forwarding,
    SendRedirects,
}

impl DevKey {
    fn name(self) -> &'static str {
        match self {
            DevKey::Forwarding => "forwarding",
            DevKey::SendRedirects => "send_redirects",
        }
    }

    fn get(self, iface: &str) -> u32 {
        match self {
            DevKey::Forwarding => narf_lib::sysctl::ipv4::device_forwarding_value(iface),
            DevKey::SendRedirects => narf_lib::sysctl::ipv4::device_send_redirects_value(iface),
        }
    }

    fn set(self, iface: &str, on: bool) {
        match self {
            DevKey::Forwarding => narf_lib::sysctl::ipv4::set_device_forwarding(iface, on),
            DevKey::SendRedirects => narf_lib::sysctl::ipv4::set_device_send_redirects(iface, on),
        }
    }
}

#[derive(Debug)]
struct DevConfFile {
    iface: alloc::string::String,
    key: DevKey,
}

impl super::ProcFile for DevConfFile {
    fn read(&self) -> alloc::vec::Vec<u8> {
        let v = self.key.get(&self.iface);
        alloc::format!("{v}\n").into_bytes()
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&self, buf: &[u8]) -> Result<usize, FsError> {
        let s = core::str::from_utf8(buf).map_err(|_| FsError::InvalidData)?;
        let v = parse_u32(s.trim())?;
        // `devinet_conf_proc` is `proc_dointvec`: no 0/1 bound here either.
        if v > i32::MAX as u32 {
            return Err(FsError::InvalidData);
        }
        self.key.set(&self.iface, v != 0);
        Ok(buf.len())
    }
}

fn dev_conf_path(iface: &str, key: DevKey) -> alloc::string::String {
    let k = key.name();
    alloc::format!("sys/net/ipv4/conf/{iface}/{k}")
}

/// Publish `/proc/sys/net/ipv4/conf/<iface>/*` and seed the interface's
/// settings from the matching `conf.default` keys.
pub fn register_dev_conf(iface: &str) {
    narf_lib::sysctl::ipv4::init_device_conf(iface);
    for key in [DevKey::Forwarding, DevKey::SendRedirects] {
        super::register_proc(
            &dev_conf_path(iface, key),
            alloc::sync::Arc::new(DevConfFile {
                iface: alloc::string::String::from(iface),
                key,
            }),
        );
    }
}

// The per-device conf keys are not `SysctlEntry`s, so they bypass
// `register_all` and the sysctl plumbing entirely. This checks the file
// really lands in the registry and that reading and writing it moves the
// value the forwarding datapath consults.
fn smoke_conf_dev_forwarding_roundtrip() -> TestResult {
    const DEV: &str = "smoke-conf0";
    register_all();
    narf_lib::sysctl::ipv4::__reset_for_test();
    register_dev_conf(DEV);

    let snap = lookup_registry(&["sys", "net", "ipv4", "conf", DEV, "forwarding"]);
    let f = match snap {
        Some(ProcNodeSnapshot::File(f)) => f,
        _ => {
            narf_lib::sysctl::ipv4::__reset_for_test();
            return TestResult::Fail("conf/<dev>/forwarding not registered");
        }
    };

    // Seeded from conf.default, which the reset put at 0.
    let initial = core::str::from_utf8(&f.read()).unwrap_or("").trim() == "0";
    // A write must reach the value the datapath reads, not just the file.
    let _ = f.write(b"1\n");
    let after_write = narf_lib::sysctl::ipv4::device_forwarding(DEV);
    let reads_back = core::str::from_utf8(&f.read()).unwrap_or("").trim() == "1";
    // A global write that does not CHANGE conf.all propagates nothing, so
    // this interface keeps the 1 set above. Linux gates `inet_forward_change`
    // on `*valp != val` the same way, and the distinction matters: otherwise
    // any write to ip_forward would silently erase per-interface settings.
    // conf.all is still 0 here, so writing 0 is that no-op.
    narf_lib::sysctl::ipv4::set_all_forwarding(false);
    let noop_kept = core::str::from_utf8(&f.read()).unwrap_or("").trim() == "1";

    // A write that does change it propagates into every interface, and is
    // visible through this file: 0 → 1 → 0 ends with the interface off,
    // despite having been set to 1 by hand.
    narf_lib::sysctl::ipv4::set_all_forwarding(true);
    narf_lib::sysctl::ipv4::set_all_forwarding(false);
    let after_global = core::str::from_utf8(&f.read()).unwrap_or("").trim() == "0";
    // `devinet_conf_proc` is `proc_dointvec` with no min/max, so a value
    // above 1 is accepted and any non-zero means on. This case used to
    // assert the opposite, which was NARF's behaviour and not Linux's.
    let accepts_two = f.write(b"2\n").is_ok();
    let two_is_on = narf_lib::sysctl::ipv4::device_forwarding(DEV);

    narf_lib::sysctl::ipv4::__reset_for_test();

    if !initial {
        return TestResult::Fail("conf/<dev>/forwarding did not start at conf.default");
    }
    if !after_write {
        return TestResult::Fail("write did not reach device_forwarding()");
    }
    if !reads_back {
        return TestResult::Fail("conf/<dev>/forwarding did not read back 1");
    }
    if !noop_kept {
        return TestResult::Fail("unchanged global write erased the per-device setting");
    }
    if !after_global {
        return TestResult::Fail("global forwarding write not visible per-device");
    }
    if !accepts_two {
        return TestResult::Fail("conf/<dev>/forwarding rejected 2, which Linux accepts");
    }
    if !two_is_on {
        return TestResult::Fail("conf/<dev>/forwarding=2 did not read as enabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_conf_dev_forwarding_roundtrip
);

// Write validation must match the `proc_handler` Linux gives each key: the
// accepted range, and EINVAL (FsError::InvalidData) outside it.
//
// The bound is not 0..=1 just because a key reads like a boolean.
// `proc_dou8vec_minmax` defaults to 0..=255 when the ctl_table carries no
// extras, which is why `tcp_timestamps=2` -- "on, without the random
// per-connection offset" -- is a setting real systems use. NARF used to
// answer EINVAL for it.
fn smoke_sysctl_write_ranges_match_linux() -> TestResult {
    register_all();

    let write = |path: &[&str], v: &[u8]| -> Option<bool> {
        match lookup_registry(path) {
            Some(ProcNodeSnapshot::File(f)) => Some(f.write(v).is_ok()),
            _ => None,
        }
    };

    // ip_default_ttl: proc_dou8vec_minmax, ip_ttl_min=1, ip_ttl_max=255.
    let ttl = ["sys", "net", "ipv4", "ip_default_ttl"];
    let ttl_zero = write(&ttl, b"0\n");
    let ttl_big = write(&ttl, b"256\n");
    let ttl_ok = write(&ttl, b"255\n");
    let _ = write(&ttl, b"64\n");

    // tcp_timestamps: proc_dou8vec_minmax with no extras → 0..=255.
    let ts = ["sys", "net", "ipv4", "tcp_timestamps"];
    let ts_two = write(&ts, b"2\n");
    let ts_big = write(&ts, b"256\n");
    let _ = write(&ts, b"1\n");

    // icmp_echo_ignore_all: extras are SYSCTL_ZERO/SYSCTL_ONE → 0..=1.
    let ig = ["sys", "net", "ipv4", "icmp_echo_ignore_all"];
    let ig_two = write(&ig, b"2\n");
    let ig_one = write(&ig, b"1\n");
    let _ = write(&ig, b"0\n");

    // Malformed input is EINVAL everywhere.
    let junk = write(&ttl, b"banana\n");

    if ttl_zero != Some(false) {
        return TestResult::Fail("ip_default_ttl accepted 0; Linux bounds it at 1");
    }
    if ttl_big != Some(false) {
        return TestResult::Fail("ip_default_ttl accepted 256");
    }
    if ttl_ok != Some(true) {
        return TestResult::Fail("ip_default_ttl rejected 255");
    }
    if ts_two != Some(true) {
        return TestResult::Fail("tcp_timestamps rejected 2, which Linux accepts");
    }
    if ts_big != Some(false) {
        return TestResult::Fail("tcp_timestamps accepted 256");
    }
    if ig_two != Some(false) {
        return TestResult::Fail("icmp_echo_ignore_all accepted 2; Linux bounds it at 1");
    }
    if ig_one != Some(true) {
        return TestResult::Fail("icmp_echo_ignore_all rejected 1");
    }
    if junk != Some(false) {
        return TestResult::Fail("a non-numeric sysctl write was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/procfs/sys_net",
    smoke_sysctl_write_ranges_match_linux
);
