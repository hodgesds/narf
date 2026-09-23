//! Cross-subsystem sysctl tunables.
//!
//! Most `/proc/sys` knobs live next to the subsystem that enforces them.
//! These do not, because the two crates involved cannot see each other:
//! `narf-filesystem` owns the procfs registry that presents the knob, and
//! `narf-net` owns the code that must obey it, and neither depends on the
//! other (`frame/src/cross_crate_init.rs` wires them at boot). The existing
//! bridge in `filesystem/src/procfs/net.rs` is a set of read-only
//! fn-pointer hooks — procfs pulling a snapshot *out* of the net stack.
//! A sysctl runs the other way: procfs writes policy that the net stack
//! reads on the datapath.
//!
//! Rather than grow write hooks, the few knobs with that shape live here,
//! in the crate both sides already depend on. Storing them anywhere else
//! risks the split-brain this module exists to prevent: procfs updating one
//! copy while the datapath reads another, so a write to `/proc/sys` reads
//! back correctly and changes nothing.
//!
//! Add to this module only when a knob genuinely spans that boundary.

/// `net.ipv4.*` tunables.
pub mod ipv4 {
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};

    use crate::sync::IrqSafeSpinLock;

    /// `net.ipv4.ip_forward`, which Linux aliases to
    /// `net.ipv4.conf.all.forwarding`. Non-zero means: route packets that are
    /// not addressed to this host out toward their destination instead of
    /// dropping them. Linux default 0.
    ///
    /// This value is NOT the one the datapath tests. Forwarding is decided
    /// per ingress interface — see [`device_forwarding`] — and writing this
    /// knob propagates to every interface via [`set_all_forwarding`].
    pub static IP_FORWARD: AtomicU32 = AtomicU32::new(0);

    /// `net.ipv4.conf.default.forwarding`. The value an interface takes when
    /// it has no setting of its own — including one that appears after the
    /// fact, which is how Linux's `devconf_dflt` behaves at device creation.
    pub static IP_FORWARD_DEFAULT: AtomicU32 = AtomicU32::new(0);

    /// `net.ipv4.conf.all.send_redirects`. Linux's `IN_DEV_TX_REDIRECTS` is
    /// an OR of this and the per-interface value, and both default to 1 --
    /// a router sends redirects unless told not to.
    pub static SEND_REDIRECTS_ALL: AtomicU32 = AtomicU32::new(1);

    /// `net.ipv4.conf.default.send_redirects`.
    pub static SEND_REDIRECTS_DEFAULT: AtomicU32 = AtomicU32::new(1);

    /// One interface's `net.ipv4.conf.<dev>.*` values.
    #[derive(Clone, Debug)]
    struct DevConf {
        name: String,
        forwarding: u32,
        send_redirects: u32,
    }

    /// Per-interface conf, for interfaces that have been seeded. Absent means
    /// "inherit the `conf.default` value".
    static DEV_CONF: IrqSafeSpinLock<Vec<DevConf>> = IrqSafeSpinLock::new(Vec::new());

    /// `net.ipv4.icmp_echo_ignore_all`. Non-zero means: do not answer ICMP
    /// echo requests at all. Linux default 0 (`icmp_sk_init`,
    /// `net/ipv4/icmp.c`).
    pub static ICMP_ECHO_IGNORE_ALL: AtomicU32 = AtomicU32::new(0);

    /// `net.ipv4.icmp_echo_ignore_broadcasts`. Non-zero means: do not answer
    /// echo requests addressed to a broadcast or multicast destination.
    /// Linux default 1 — this is the Smurf-amplification guard, so the
    /// secure value is the default and a fresh boot must already enforce it.
    pub static ICMP_ECHO_IGNORE_BROADCASTS: AtomicU32 = AtomicU32::new(1);

    /// `net.ipv4.tcp_window_scaling`. Linux default 1.
    pub static TCP_WINDOW_SCALING: AtomicU32 = AtomicU32::new(1);

    /// `net.ipv4.tcp_timestamps`. Linux default 1. Linux also accepts 2,
    /// meaning "on, but without the random per-connection offset"; NARF has
    /// no such offset, so any non-zero value behaves as 1.
    pub static TCP_TIMESTAMPS: AtomicU32 = AtomicU32::new(1);

    /// `net.ipv4.tcp_sack`. Linux default 1.
    pub static TCP_SACK: AtomicU32 = AtomicU32::new(1);

    /// The three TCP option knobs, as `(window_scaling, timestamps, sack)`.
    ///
    /// They gate both directions, as in Linux. On a SYN we send, each option
    /// is offered only if its knob allows (`tcp_syn_options`). On a SYN we
    /// receive, an option the knob forbids is ignored rather than negotiated
    /// (`tcp_parse_options` tests them with `!estab`), so a peer cannot turn
    /// on something this host has switched off.
    pub fn tcp_option_defaults() -> (bool, bool, bool) {
        (
            TCP_WINDOW_SCALING.load(Ordering::Relaxed) != 0,
            TCP_TIMESTAMPS.load(Ordering::Relaxed) != 0,
            TCP_SACK.load(Ordering::Relaxed) != 0,
        )
    }

    /// True iff `net.ipv4.ip_forward` (`conf.all.forwarding`) is set.
    ///
    /// Callers deciding whether to forward a packet want
    /// [`device_forwarding`] instead: Linux's `IN_DEV_FORWARD` reads the
    /// ingress device's own value, and `conf.all` reaches the datapath only
    /// by having been propagated into it.
    #[inline]
    pub fn ip_forward() -> bool {
        IP_FORWARD.load(Ordering::Relaxed) != 0
    }

    /// The forwarding setting for `iface`, falling back to
    /// `conf.default.forwarding` when the interface has no value of its own.
    ///
    /// This is the predicate the forwarding path tests. Linux:
    /// `IN_DEV_FORWARD(in_dev)` is `IN_DEV_CONF_GET(in_dev, FORWARDING)` --
    /// the ingress device alone, not ANDed with `conf.all`. `conf.all` is
    /// ANDed in for MC_FORWARDING and BC_FORWARDING, but not for this one.
    pub fn device_forwarding(iface: &str) -> bool {
        device_forwarding_value(iface) != 0
    }

    /// As [`device_forwarding`], but the raw value — what procfs prints.
    pub fn device_forwarding_value(iface: &str) -> u32 {
        let g = DEV_CONF.lock();
        match g.iter().find(|d| d.name == iface) {
            Some(d) => d.forwarding,
            None => IP_FORWARD_DEFAULT.load(Ordering::Relaxed),
        }
    }

    /// Set one interface's `conf.<dev>.forwarding`. Affects only that
    /// interface, as writing the per-device key does in Linux.
    pub fn set_device_forwarding(iface: &str, on: bool) {
        let v = u32::from(on);
        let mut g = DEV_CONF.lock();
        match g.iter_mut().find(|d| d.name == iface) {
            Some(d) => d.forwarding = v,
            None => {
                let dflt = SEND_REDIRECTS_DEFAULT.load(Ordering::Relaxed);
                g.push(DevConf {
                    name: String::from(iface),
                    forwarding: v,
                    send_redirects: dflt,
                });
            }
        }
    }

    /// True iff this interface may send ICMP Redirects.
    ///
    /// Linux: `IN_DEV_TX_REDIRECTS` is `IN_DEV_ORCONF(SEND_REDIRECTS)` — the
    /// OR of `conf.all` and the interface's own value, unlike forwarding,
    /// which reads the interface alone. So silencing redirects takes clearing
    /// both.
    pub fn device_send_redirects(iface: &str) -> bool {
        if SEND_REDIRECTS_ALL.load(Ordering::Relaxed) != 0 {
            return true;
        }
        device_send_redirects_value(iface) != 0
    }

    /// The raw per-interface `send_redirects` value — what procfs prints.
    pub fn device_send_redirects_value(iface: &str) -> u32 {
        let g = DEV_CONF.lock();
        match g.iter().find(|d| d.name == iface) {
            Some(d) => d.send_redirects,
            None => SEND_REDIRECTS_DEFAULT.load(Ordering::Relaxed),
        }
    }

    /// Set one interface's `conf.<dev>.send_redirects`.
    pub fn set_device_send_redirects(iface: &str, on: bool) {
        let v = u32::from(on);
        let mut g = DEV_CONF.lock();
        match g.iter_mut().find(|d| d.name == iface) {
            Some(d) => d.send_redirects = v,
            None => {
                let dflt = IP_FORWARD_DEFAULT.load(Ordering::Relaxed);
                g.push(DevConf {
                    name: String::from(iface),
                    forwarding: dflt,
                    send_redirects: v,
                });
            }
        }
    }

    /// Write `net.ipv4.ip_forward` / `conf.all.forwarding`.
    ///
    /// Linux's `inet_forward_change` (net/ipv4/devinet.c) does not merely
    /// store the value: it stamps `conf.default` and then overwrites EVERY
    /// device's setting. So enabling forwarding globally really does turn it
    /// on everywhere, including on interfaces previously turned off by hand,
    /// and an interface created later inherits it through the default.
    ///
    /// Also as in Linux, the propagation runs only when the value actually
    /// changes — rewriting the current value leaves per-device settings
    /// alone.
    pub fn set_all_forwarding(on: bool) {
        let v = u32::from(on);
        if IP_FORWARD.swap(v, Ordering::Relaxed) == v {
            return;
        }
        IP_FORWARD_DEFAULT.store(v, Ordering::Relaxed);
        let mut g = DEV_CONF.lock();
        for d in g.iter_mut() {
            d.forwarding = v;
        }
    }

    /// Give `iface` its starting values, inherited from the `conf.default` keys.
    /// Called when an interface is registered, mirroring Linux seeding a new
    /// `in_device`'s cnf from `devconf_dflt`.
    pub fn init_device_conf(iface: &str) {
        let mut g = DEV_CONF.lock();
        if g.iter().any(|d| d.name == iface) {
            return;
        }
        g.push(DevConf {
            name: String::from(iface),
            forwarding: IP_FORWARD_DEFAULT.load(Ordering::Relaxed),
            send_redirects: SEND_REDIRECTS_DEFAULT.load(Ordering::Relaxed),
        });
    }

    /// Drop an interface's settings when it goes away.
    pub fn forget_device_conf(iface: &str) {
        DEV_CONF.lock().retain(|d| d.name != iface);
    }

    /// True iff echo requests must be ignored outright.
    #[inline]
    pub fn icmp_echo_ignore_all() -> bool {
        ICMP_ECHO_IGNORE_ALL.load(Ordering::Relaxed) != 0
    }

    /// True iff echo requests to broadcast/multicast must be ignored.
    #[inline]
    pub fn icmp_echo_ignore_broadcasts() -> bool {
        ICMP_ECHO_IGNORE_BROADCASTS.load(Ordering::Relaxed) != 0
    }

    /// Restore both knobs to their Linux defaults. Test-only.
    pub fn __reset_for_test() {
        IP_FORWARD.store(0, Ordering::Relaxed);
        IP_FORWARD_DEFAULT.store(0, Ordering::Relaxed);
        TCP_WINDOW_SCALING.store(1, Ordering::Relaxed);
        TCP_TIMESTAMPS.store(1, Ordering::Relaxed);
        TCP_SACK.store(1, Ordering::Relaxed);
        SEND_REDIRECTS_ALL.store(1, Ordering::Relaxed);
        SEND_REDIRECTS_DEFAULT.store(1, Ordering::Relaxed);
        DEV_CONF.lock().clear();
        ICMP_ECHO_IGNORE_ALL.store(0, Ordering::Relaxed);
        ICMP_ECHO_IGNORE_BROADCASTS.store(1, Ordering::Relaxed);
    }
}
