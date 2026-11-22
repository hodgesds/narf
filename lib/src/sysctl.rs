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

    /// `net.ipv4.conf.all.rp_filter`: reverse-path filtering, 0 off, 1
    /// strict, 2 loose (RFC 3704). The device's mode is the larger of this
    /// and its own value (`IN_DEV_RPFILTER` is `IN_DEV_MAXCONF`). Linux
    /// default 0; systemd's `50-default.conf` writes 2.
    pub static RP_FILTER_ALL: AtomicU32 = AtomicU32::new(0);

    /// `net.ipv4.conf.default.rp_filter`, seeding new devices.
    pub static RP_FILTER_DEFAULT: AtomicU32 = AtomicU32::new(0);

    /// Devices whose own `rp_filter` is not 0, kept under `DEV_CONF`'s lock
    /// so the receive path skips the per-device lookup while every value is
    /// 0 (the Linux default).
    static RP_FILTER_DEVICES: AtomicU32 = AtomicU32::new(0);

    fn count_rp_filter_devices(g: &[DevConf]) {
        let n = g.iter().filter(|d| d.rp_filter != 0).count() as u32;
        RP_FILTER_DEVICES.store(n, Ordering::Release);
    }

    /// `IN_DEV_RPFILTER(in_dev)` for `iface`: the larger of `conf.all` and
    /// the device's own `rp_filter` (`IN_DEV_MAXCONF`). 0 means no
    /// reverse-path check.
    pub fn rp_filter_mode(iface: &str) -> u32 {
        let all = RP_FILTER_ALL.load(Ordering::Relaxed);
        if RP_FILTER_DEVICES.load(Ordering::Acquire) == 0
            && RP_FILTER_DEFAULT.load(Ordering::Relaxed) == 0
        {
            return all;
        }
        all.max(device_rp_filter_value(iface))
    }

    /// One interface's `net.ipv4.conf.<dev>.*` values.
    #[derive(Clone, Debug)]
    struct DevConf {
        name: String,
        forwarding: u32,
        send_redirects: u32,
        rp_filter: u32,
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

    /// `net.ipv4.ip_default_ttl`. The TTL stamped on packets this host
    /// originates. Linux default 64 (`IPDEFTTL`), read through
    /// `ip4_dst_hoplimit()` when the route carries no hoplimit of its own.
    ///
    /// Forwarded packets are unaffected: they keep the sender's TTL, minus
    /// one for this hop.
    pub static IP_DEFAULT_TTL: AtomicU32 = AtomicU32::new(64);

    /// `net.core.somaxconn`. The ceiling `listen(2)` clamps its backlog to.
    /// Linux default 4096 in current kernels; NARF keeps the older 128,
    /// which is what its procfs default already advertised.
    pub static SOMAXCONN: AtomicU32 = AtomicU32::new(128);

    /// The TTL to stamp on a locally-originated packet.
    #[inline]
    pub fn ip_default_ttl() -> u8 {
        // The knob is clamped to 1..=255 on write; saturate defensively so a
        // 0 can never produce a packet that dies on the first hop.
        IP_DEFAULT_TTL.load(Ordering::Relaxed).clamp(1, 255) as u8
    }

    /// Clamp a `listen(2)` backlog to `net.core.somaxconn`, as
    /// `__sys_listen_socket` does before the protocol's own listen runs.
    #[inline]
    pub fn clamp_backlog(backlog: usize) -> usize {
        backlog.min(SOMAXCONN.load(Ordering::Relaxed) as usize)
    }

    /// `net.ipv4.tcp_window_scaling`. Linux default 1.
    pub static TCP_WINDOW_SCALING: AtomicU32 = AtomicU32::new(1);

    /// `net.ipv4.tcp_timestamps`. Linux default 1. Linux also accepts 2,
    /// meaning "on, but without the random per-connection offset"; NARF has
    /// no such offset, so any non-zero value behaves as 1.
    pub static TCP_TIMESTAMPS: AtomicU32 = AtomicU32::new(1);

    /// `net.ipv4.tcp_sack`. Linux default 1.
    pub static TCP_SACK: AtomicU32 = AtomicU32::new(1);

    /// `net.ipv4.tcp_rmem[2]`: the most receive-buffer autotuning may give
    /// one connection (`tcp_rcvbuf_grow`). Linux default 6 MiB.
    pub static TCP_RMEM_MAX: AtomicU32 = AtomicU32::new(6_291_456);

    /// `net.ipv4.tcp_wmem[2]`: the most send-buffer autotuning may give one
    /// connection (`tcp_sndbuf_expand`). Linux default 4 MiB.
    pub static TCP_WMEM_MAX: AtomicU32 = AtomicU32::new(4_194_304);

    /// `net.ipv4.tcp_limit_output_bytes`: the ceiling on what one
    /// connection may leave in a device queue (TCP Small Queues). Linux
    /// default 4 MiB.
    pub static TCP_LIMIT_OUTPUT_BYTES: AtomicU32 = AtomicU32::new(4 << 20);

    /// `net.ipv4.tcp_moderate_rcvbuf`. Linux default 1: grow the receive
    /// buffer to match what the application reads per round trip.
    pub static TCP_MODERATE_RCVBUF: AtomicU32 = AtomicU32::new(1);

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
                    rp_filter: RP_FILTER_DEFAULT.load(Ordering::Relaxed),
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
                    rp_filter: RP_FILTER_DEFAULT.load(Ordering::Relaxed),
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
            rp_filter: RP_FILTER_DEFAULT.load(Ordering::Relaxed),
        });
        count_rp_filter_devices(&g);
    }

    /// The raw per-interface `rp_filter` value — what procfs prints.
    pub fn device_rp_filter_value(iface: &str) -> u32 {
        let g = DEV_CONF.lock();
        match g.iter().find(|d| d.name == iface) {
            Some(d) => d.rp_filter,
            None => RP_FILTER_DEFAULT.load(Ordering::Relaxed),
        }
    }

    /// Set one interface's `conf.<dev>.rp_filter`.
    pub fn set_device_rp_filter(iface: &str, v: u32) {
        let mut g = DEV_CONF.lock();
        match g.iter_mut().find(|d| d.name == iface) {
            Some(d) => d.rp_filter = v,
            None => g.push(DevConf {
                name: String::from(iface),
                forwarding: IP_FORWARD_DEFAULT.load(Ordering::Relaxed),
                send_redirects: SEND_REDIRECTS_DEFAULT.load(Ordering::Relaxed),
                rp_filter: v,
            }),
        }
        count_rp_filter_devices(&g);
    }

    /// Drop an interface's settings when it goes away.
    pub fn forget_device_conf(iface: &str) {
        let mut g = DEV_CONF.lock();
        g.retain(|d| d.name != iface);
        count_rp_filter_devices(&g);
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
        IP_DEFAULT_TTL.store(64, Ordering::Relaxed);
        SOMAXCONN.store(128, Ordering::Relaxed);
        TCP_WINDOW_SCALING.store(1, Ordering::Relaxed);
        TCP_TIMESTAMPS.store(1, Ordering::Relaxed);
        TCP_SACK.store(1, Ordering::Relaxed);
        TCP_RMEM_MAX.store(6_291_456, Ordering::Relaxed);
        TCP_WMEM_MAX.store(4_194_304, Ordering::Relaxed);
        TCP_MODERATE_RCVBUF.store(1, Ordering::Relaxed);
        TCP_LIMIT_OUTPUT_BYTES.store(4 << 20, Ordering::Relaxed);
        SEND_REDIRECTS_ALL.store(1, Ordering::Relaxed);
        SEND_REDIRECTS_DEFAULT.store(1, Ordering::Relaxed);
        RP_FILTER_ALL.store(0, Ordering::Relaxed);
        RP_FILTER_DEFAULT.store(0, Ordering::Relaxed);
        DEV_CONF.lock().clear();
        RP_FILTER_DEVICES.store(0, Ordering::Release);
        ICMP_ECHO_IGNORE_ALL.store(0, Ordering::Relaxed);
        ICMP_ECHO_IGNORE_BROADCASTS.store(1, Ordering::Relaxed);
    }
}

/// `net.ipv6.conf.{all,default,<dev>}.*` (Linux `ipv6_devconf`): the keys
/// NetworkManager writes for a device it manages. NetworkManager runs its own
/// router discovery and sets the device's `accept_ra` to 0 and
/// `addr_gen_mode` to 1 (none), so the kernel takes no router, route,
/// prefix or address from an RA. The values live here because the IPv6
/// stack in `narf-net` reads them and `narf-filesystem` publishes them.
pub mod ipv6 {
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicI32, Ordering};

    use crate::sync::IrqSafeSpinLock;

    /// A per-device IPv6 key.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Key {
        AcceptRa,
        Autoconf,
        UseTempaddr,
        DisableIpv6,
        AddrGenMode,
        HopLimit,
        Mtu,
    }

    const KEYS: usize = 7;

    impl Key {
        /// Every key, in procfs order.
        pub const ALL: [Key; KEYS] = [
            Key::AcceptRa,
            Key::Autoconf,
            Key::UseTempaddr,
            Key::DisableIpv6,
            Key::AddrGenMode,
            Key::HopLimit,
            Key::Mtu,
        ];

        /// The file name under `conf/<dev>/`.
        pub fn name(self) -> &'static str {
            match self {
                Key::AcceptRa => "accept_ra",
                Key::Autoconf => "autoconf",
                Key::UseTempaddr => "use_tempaddr",
                Key::DisableIpv6 => "disable_ipv6",
                Key::AddrGenMode => "addr_gen_mode",
                Key::HopLimit => "hop_limit",
                Key::Mtu => "mtu",
            }
        }

        /// The values a write may set (the key's `proc_handler` bounds):
        /// `addrconf_sysctl_addr_gen_mode` takes 0..=3, `hop_limit` is
        /// `proc_dointvec_minmax` 1..=255, `addrconf_sysctl_mtu` starts at
        /// IPV6_MIN_MTU, and the rest are `proc_dointvec`.
        pub fn bounds(self) -> (i32, i32) {
            match self {
                Key::AddrGenMode => (0, 3),
                Key::HopLimit => (1, 255),
                Key::Mtu => (1280, 65535),
                _ => (i32::MIN, i32::MAX),
            }
        }

        fn index(self) -> usize {
            self as usize
        }

        /// Linux `ipv6_devconf` / `ipv6_devconf_dflt` defaults.
        const fn linux_default(self) -> i32 {
            match self {
                Key::AcceptRa | Key::Autoconf => 1,
                Key::UseTempaddr | Key::DisableIpv6 | Key::AddrGenMode => 0,
                Key::HopLimit => 64,
                Key::Mtu => 1280,
            }
        }
    }

    const fn defaults() -> [AtomicI32; KEYS] {
        [
            AtomicI32::new(Key::AcceptRa.linux_default()),
            AtomicI32::new(Key::Autoconf.linux_default()),
            AtomicI32::new(Key::UseTempaddr.linux_default()),
            AtomicI32::new(Key::DisableIpv6.linux_default()),
            AtomicI32::new(Key::AddrGenMode.linux_default()),
            AtomicI32::new(Key::HopLimit.linux_default()),
            AtomicI32::new(Key::Mtu.linux_default()),
        ]
    }

    static ALL: [AtomicI32; KEYS] = defaults();
    static DEFAULT: [AtomicI32; KEYS] = defaults();

    #[derive(Clone, Debug)]
    struct DevConf {
        name: String,
        values: [i32; KEYS],
    }

    static DEV_CONF: IrqSafeSpinLock<Vec<DevConf>> = IrqSafeSpinLock::new(Vec::new());

    /// `conf.all.<key>`.
    pub fn all(key: Key) -> i32 {
        ALL[key.index()].load(Ordering::Relaxed)
    }

    /// Write `conf.all.<key>`. `disable_ipv6` reaches every device, as
    /// `addrconf_disable_ipv6` writes it into each `inet6_dev`.
    pub fn set_all(key: Key, v: i32) {
        ALL[key.index()].store(v, Ordering::Relaxed);
        if key == Key::DisableIpv6 {
            DEFAULT[key.index()].store(v, Ordering::Relaxed);
            for d in DEV_CONF.lock().iter_mut() {
                d.values[key.index()] = v;
            }
        }
    }

    /// `conf.default.<key>`, which seeds new devices.
    pub fn default_value(key: Key) -> i32 {
        DEFAULT[key.index()].load(Ordering::Relaxed)
    }

    /// Write `conf.default.<key>`.
    pub fn set_default(key: Key, v: i32) {
        DEFAULT[key.index()].store(v, Ordering::Relaxed);
    }

    fn seeded(name: &str) -> DevConf {
        let mut values = [0; KEYS];
        for key in Key::ALL {
            values[key.index()] = default_value(key);
        }
        DevConf {
            name: String::from(name),
            values,
        }
    }

    /// `<dev>`'s value of `key`, `conf.default`'s for an unseeded device.
    pub fn device(iface: &str, key: Key) -> i32 {
        let g = DEV_CONF.lock();
        match g.iter().find(|d| d.name == iface) {
            Some(d) => d.values[key.index()],
            None => default_value(key),
        }
    }

    /// Write `<dev>`'s `key`.
    pub fn set_device(iface: &str, key: Key, v: i32) {
        let mut g = DEV_CONF.lock();
        match g.iter_mut().find(|d| d.name == iface) {
            Some(d) => d.values[key.index()] = v,
            None => {
                let mut d = seeded(iface);
                d.values[key.index()] = v;
                g.push(d);
            }
        }
    }

    /// Seed `iface` from `conf.default`, its `mtu` from the device's
    /// (`ipv6_add_dev`: `ndev->cnf.mtu6 = dev->mtu`).
    pub fn init_device_conf(iface: &str, mtu: u32) {
        let mut g = DEV_CONF.lock();
        if g.iter().any(|d| d.name == iface) {
            return;
        }
        let mut d = seeded(iface);
        d.values[Key::Mtu.index()] = mtu.min(i32::MAX as u32) as i32;
        g.push(d);
    }

    /// Drop `iface`'s values when it goes away.
    pub fn forget_device_conf(iface: &str) {
        DEV_CONF.lock().retain(|d| d.name != iface);
    }

    /// `ipv6_accept_ra(idev)`: whether `iface` processes router
    /// advertisements. NARF does not forward IPv6, so forwarding's
    /// `accept_ra == 2` hybrid mode does not arise.
    pub fn accept_ra(iface: &str) -> bool {
        device(iface, Key::AcceptRa) != 0
    }

    /// `in6_dev->cnf.autoconf`: whether a prefix makes SLAAC addresses.
    pub fn autoconf(iface: &str) -> bool {
        device(iface, Key::Autoconf) != 0
    }

    /// `in6_dev->cnf.use_tempaddr`: above 0, SLAAC adds RFC 8981 temporary
    /// addresses.
    pub fn use_tempaddr(iface: &str) -> i32 {
        device(iface, Key::UseTempaddr)
    }

    /// Every value back at its Linux default. Test-only.
    pub fn __reset_for_test() {
        for key in Key::ALL {
            ALL[key.index()].store(key.linux_default(), Ordering::Relaxed);
            DEFAULT[key.index()].store(key.linux_default(), Ordering::Relaxed);
        }
        DEV_CONF.lock().clear();
    }
}
