//! Cross-crate fn-pointer hook installation, factored out of
//! `bare_main.rs` so the boot-time wiring is in one readable place
//! instead of scattered through 2.5 KLOC of staged setup.
//!
//! Every entry here is the same shape: a kernel-side crate
//! (filesystem, net, ...) needs a fn pointer from another crate
//! (userspace handlers, drivers, ...) wired in at boot. The
//! receiver crate stores the pointer in an `AtomicUsize` and
//! reads it on demand, so the dep direction stays one-way.

extern crate alloc;

use core::fmt::Write as _;

use narf_console as console;

/// Wire every cross-crate fn-pointer hook the kernel needs at
/// boot time. Called once from `bare_main` after the per-task
/// initialisers (sigaction_init, signal_init,
/// init_per_task_state) have run.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub fn install_all_hooks() {
    // Cgroup membership is keyed by userspace ProcessId, whereas the executor
    // only knows its private TaskId. Install the translation before any cgroup
    // controller activates allocator charging, so memory.max observes the
    // same process identity as cgroup.procs.
    #[cfg(feature = "cgroup")]
    narf_scheduler::install_memory_pid_resolver(narf_userspace::handlers::task_to_pid_raw);
    #[cfg(feature = "cgroup")]
    narf_scheduler::install_process_task_resolver(narf_userspace::handlers::pid_to_task_raw);
    install_console_signal_hook();
    #[cfg(feature = "linux-compat")]
    install_proc_hooks();
    #[cfg(feature = "linux-compat")]
    install_proc_ext_hooks();
    #[cfg(feature = "linux-compat")]
    install_proc_path_hooks();
    #[cfg(feature = "linux-compat")]
    install_proc_write_hooks();
    install_net_stack();
    #[cfg(feature = "linux-compat")]
    install_procfs_net_hooks();
    #[cfg(feature = "linux-compat")]
    install_proc_mountinfo_hook();
    #[cfg(all(feature = "linux-compat", feature = "container"))]
    install_ns_proc_hooks();
}

/// Mount namespaces back Linux service sandboxing even when the broader
/// container feature is disabled. Their `/proc/self/mountinfo` view must
/// therefore be wired independently of the container-only namespace hooks.
#[cfg(feature = "linux-compat")]
fn install_proc_mountinfo_hook() {
    narf_filesystem::procfs::install_mountinfo_hook(narf_userspace::handlers::proc_ns_mountinfo);
    narf_filesystem::procfs::install_mountinfo_generation_hook(
        narf_userspace::handlers::proc_ns_mountinfo_generation,
    );
    narf_filesystem::install_mount_change_hook(wake_mountinfo_waiters);
}

/// Wake poll/epoll waiters after a mount-table mutation. `/proc/*/mountinfo`
/// exposes the namespace generation as POLLPRI; the scheduler must be kicked
/// so systemd's libmount monitor drains that edge before it observes SIGCHLD
/// from the successful mount helper.
#[cfg(feature = "linux-compat")]
fn wake_mountinfo_waiters() {
    narf_net::readiness::notify(0);
}

/// Wire the namespace procfs hooks so /proc/<pid>/ns/*, uid_map,
/// gid_map, and the per-ns mountinfo view reach the userspace
/// namespace tables. Gated on container (the source of the state)
/// AND linux-compat (where the procfs nodes live).
#[cfg(all(feature = "linux-compat", feature = "container"))]
fn install_ns_proc_hooks() {
    narf_filesystem::procfs::install_ns_proc_hooks(
        narf_userspace::handlers::proc_ns_readlink,
        narf_userspace::handlers::proc_ns_mountinfo,
        narf_userspace::handlers::proc_ns_idmap_render,
        narf_userspace::handlers::proc_ns_idmap_write,
    );
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn install_console_signal_hook() {
    // ^C / ^\ / ^Z input-byte handling into the console driver
    // so they deliver SIGINT/SIGQUIT/SIGTSTP to the foreground
    // process group instead of bubbling up as ASCII bytes.
    narf_filesystem::install_console_signal_hook(
        narf_userspace::handlers::maybe_deliver_signal_for_input,
    );
    // Same job-control signals for pseudoterminals: the shared n_tty
    // discipline raises ^C/^\/^Z to a PTY's foreground process group via
    // this hook (the PTY knows its own fg_pgrp, so it passes it directly).
    narf_filesystem::devfs_pty::install_pty_signal_hook(
        narf_userspace::handlers::deliver_signal_to_pgrp,
    );
}

#[cfg(feature = "linux-compat")]
fn install_proc_hooks() {
    // /proc per-pid hooks — exposes the live scheduler task list
    // and per-task metadata to /proc/[pid]/* and /proc/self/*.
    narf_filesystem::procfs::install_proc_hooks(
        narf_userspace::handlers::proc_current_pid,
        narf_userspace::handlers::proc_list_pids,
        narf_userspace::handlers::proc_task_info,
    );
    // PID-namespace translation for /proc: resolve reader-namespace path
    // numbers to outer ProcessIds, and the caller's outer pid for /proc/self.
    // Identity in the root namespace.
    narf_filesystem::procfs::install_proc_pidns_hooks(
        narf_userspace::handlers::proc_current_outer_pid,
        narf_userspace::handlers::proc_pid_resolve,
        narf_userspace::handlers::proc_pid_report,
    );
}

#[cfg(feature = "linux-compat")]
fn install_proc_ext_hooks() {
    // Extended /proc/[pid]/* read hooks: fd, rlimits, nice, environ, auxv.
    narf_filesystem::procfs::install_proc_ext_hooks(
        narf_userspace::handlers::fd_path_of,
        narf_userspace::handlers::rlimits_of,
        narf_userspace::handlers::nice_of,
        narf_userspace::handlers::proc_environ_of,
        narf_userspace::handlers::proc_auxv_of,
    );
    // /proc/<pid>/fd enumeration: the exact open fd set from the fd table.
    narf_filesystem::procfs::set_fd_list_hook(narf_userspace::handlers::proc_fd_list);
    // /proc/<pid>/fdinfo/<n> "Pid:"/"NSpid:" lines for pidfd fds —
    // systemd's pidfd_get_pid() fallback parses these after pidfd_spawn.
    narf_filesystem::procfs::set_fd_pidfd_pid_hook(narf_userspace::handlers::proc_fd_pidfd_pid);
}

#[cfg(feature = "linux-compat")]
fn install_proc_path_hooks() {
    // /proc/[pid]/{exe,cwd,root} magic-link targets: exec'd image path
    // (published by sys_execve), per-task cwd, and the chroot prefix.
    narf_filesystem::procfs::install_proc_path_hooks(
        narf_userspace::handlers::proc_exe_path,
        narf_userspace::handlers::proc_cwd_path,
        narf_userspace::handlers::proc_root_path,
    );
}

#[cfg(feature = "linux-compat")]
fn install_proc_write_hooks() {
    // Writable per-pid procfs hooks: comm, oom_score_adj, coredump_filter.
    narf_filesystem::procfs::install_proc_write_hooks(
        narf_userspace::handlers::proc_set_comm,
        narf_userspace::handlers::proc_oom_adj_of,
        narf_userspace::handlers::proc_set_oom_adj,
        narf_userspace::handlers::proc_coredump_filter_of,
        narf_userspace::handlers::proc_set_coredump_filter,
        narf_userspace::handlers::proc_oom_score_of,
    );
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn install_net_stack() {
    // TCP-over-NIC: register the RX dispatch handler and spawn an
    // async kernel task that drains the NIC RX ring. Inline drain
    // via `iface::drain_pump` covers the syscall-context busy
    // wait; this background task picks up frames between syscalls.
    narf_net::tcp_stack::init();
    let _ = writeln!(
        console::Writer,
        "  net: tcp_stack init; iface count = {}",
        narf_net::iface::count()
    );
    // QEMU SLIRP static config: the user-mode network backend always
    // hands the guest 10.0.2.15/24 with the gateway + DNS at 10.0.2.2.
    // Assign it statically to the virtio-net iface so a guest server is
    // reachable from the host through `-netdev user,hostfwd=...` (the
    // off-box serving smoke). Opt-in feature: real hardware should run
    // the DHCP client instead of hardcoding the SLIRP lease.
    #[cfg(feature = "qemu-net")]
    {
        narf_net::iface::add_addr("vnet0", [10, 0, 2, 15], 24);
        narf_net::iface::set_iface_ipv4("vnet0", [10, 0, 2, 15], [10, 0, 2, 2]);
        let _ = writeln!(
            console::Writer,
            "  net: qemu-net static config — vnet0 = 10.0.2.15/24 gw 10.0.2.2 ({} virtio-net queue pair(s))",
            narf_drivers_virtio::net_pci::primary_num_pairs()
        );
    }
    // Stackful: the e1000 RX pump's inner `while rx_pump_step()`
    // could starve the executor on real silicon if the device's
    // RX descriptor ring stays "ready" indefinitely (e.g.
    // 0xFFFFFFFF reads on absent-device). Preemption caps it at
    // a 10 ms slice.
    //
    // Idle backoff: the old form `yield_now().await` after every empty
    // drain self-woke on EVERY executor round, so this task was always
    // runnable — the cooperative executor never halted (nr_running never
    // hit 0), pinning the CPU and pacing every round at the spin rate.
    // With an idle e1000 (off-box redis runs on virtio-net) it spun
    // forever, adding ~one-round (~230 µs) of latency to every request on
    // the OTHER NIC. PARK ~1 ms on the wheel after an empty drain so the
    // executor can halt; tight-poll only while frames are flowing.
    narf_scheduler::spawn_stackful(async {
        let idle_park_cycles =
            1_000_000u64.saturating_mul(narf_time::cycles_per_ns().max(1) as u64);
        loop {
            let mut any = false;
            while narf_drivers_net::e1000::rx_pump_step() {
                any = true;
            }
            if any {
                narf_scheduler::yield_now().await;
            } else {
                narf_time::sleep_cycles(idle_park_cycles).await;
            }
        }
    });
}

// ── /proc/net/* — bridge the net stack into procfs ──────────────
//
// The per-subsystem snapshot APIs live in `narf-net`; the per-file
// renderers live in `narf-filesystem::procfs::net`. This module
// stitches them together by installing fn-pointer hooks the
// renderers call on every `read()`.
//
// Per-subsystem snapshot types differ between the source (typed
// per crate) and the FS surface (a single SnapshotXxx wire-format
// type per file). Tiny adapter fns convert one to the other.

#[cfg(feature = "linux-compat")]
fn install_procfs_net_hooks() {
    use narf_filesystem::procfs::net as pn;

    pn::install_hooks(
        tcp_adapter,
        udp_adapter,
        raw_adapter,
        arp_adapter,
        route_adapter,
        iface_counters_adapter,
        ipv6_ifaddr_adapter,
        ipv6_route_adapter,
        conntrack_adapter,
        snmp_adapter,
        igmp_adapter,
        igmp6_adapter,
        tcp6_adapter,
        udp6_adapter,
        raw6_adapter,
    );
    // Register the actual /proc/net/* files on the procfs registry.
    pn::register_all();
}

#[cfg(feature = "linux-compat")]
#[cfg(feature = "container")]
fn current_net_ns_id() -> u64 {
    let task = narf_userspace::handlers::current_task_id();
    narf_userspace::namespaces::current_net_ns(task)
        .map(|namespace| namespace.id())
        .unwrap_or(0)
}

#[cfg(feature = "linux-compat")]
#[cfg(not(feature = "container"))]
fn current_net_ns_id() -> u64 {
    0
}

#[cfg(feature = "linux-compat")]
fn tcp_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::TcbSnapshot> {
    narf_net::tcp::core::snapshot_in(current_net_ns_id())
        .into_iter()
        .map(|t| narf_filesystem::procfs::net::TcbSnapshot {
            local_addr: t.local_addr,
            local_port: t.local_port,
            remote_addr: t.remote_addr,
            remote_port: t.remote_port,
            state_code: t.state_code,
            tx_queue: t.tx_queue,
            rx_queue: t.rx_queue,
            retrnsmt: t.retrnsmt,
            uid: 0,
            timeout: 0,
            inode: 0,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn udp_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::UdpSocketSnapshot> {
    narf_net::udp_sock::snapshot_in(current_net_ns_id())
        .into_iter()
        .map(|u| narf_filesystem::procfs::net::UdpSocketSnapshot {
            local_addr: u.local_addr,
            local_port: u.local_port,
            remote_addr: u.remote_addr,
            remote_port: u.remote_port,
            state_code: u.state_code,
            tx_queue: u.tx_queue,
            rx_queue: u.rx_queue,
            uid: 0,
            inode: 0,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn raw_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::RawSocketSnapshot> {
    narf_net::raw_sock::snapshot_in(current_net_ns_id())
        .into_iter()
        .map(|r| narf_filesystem::procfs::net::RawSocketSnapshot {
            local_addr: r.local_addr,
            local_port: r.local_port,
            remote_addr: r.remote_addr,
            remote_port: r.remote_port,
            state_code: r.state_code,
            uid: 0,
            inode: 0,
            protocol: r.protocol,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn arp_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::ArpSnapshot> {
    narf_net::arp_cache::snapshot_in(current_net_ns_id())
        .into_iter()
        .map(|a| narf_filesystem::procfs::net::ArpSnapshot {
            ip: a.ip,
            mac: a.mac,
            iface: a.iface,
            flags: a.flags,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn route_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::RouteSnapshot> {
    narf_net::route::snapshot_in(current_net_ns_id())
        .into_iter()
        .map(|r| narf_filesystem::procfs::net::RouteSnapshot {
            iface: r.iface,
            dst: r.dst,
            gateway: r.gateway,
            flags: r.flags,
            refcnt: r.refcnt,
            use_count: r.use_count,
            metric: r.metric,
            mask: r.mask,
            mtu: r.mtu,
            window: r.window,
            irtt: r.irtt,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn iface_counters_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::IfaceCounterSnapshot> {
    narf_net::iface::snapshot_counters_in(current_net_ns_id())
        .into_iter()
        .map(|c| narf_filesystem::procfs::net::IfaceCounterSnapshot {
            name: c.name,
            rx_bytes: c.rx_bytes,
            rx_packets: c.rx_packets,
            rx_errs: c.rx_errs,
            rx_drop: c.rx_drop,
            rx_fifo: c.rx_fifo,
            rx_frame: c.rx_frame,
            rx_compressed: c.rx_compressed,
            rx_multicast: c.rx_multicast,
            tx_bytes: c.tx_bytes,
            tx_packets: c.tx_packets,
            tx_errs: c.tx_errs,
            tx_drop: c.tx_drop,
            tx_fifo: c.tx_fifo,
            tx_colls: c.tx_colls,
            tx_carrier: c.tx_carrier,
            tx_compressed: c.tx_compressed,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn ipv6_ifaddr_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::Ipv6IfAddrSnapshot> {
    narf_net::ipv6::addrs::snapshot()
        .into_iter()
        .map(|a| narf_filesystem::procfs::net::Ipv6IfAddrSnapshot {
            iface: a.iface,
            addr: a.addr,
            ifindex: a.ifindex,
            prefix_len: a.prefix_len,
            scope: a.scope,
            flags: a.flags,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn ipv6_route_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::Ipv6RouteSnapshot> {
    narf_net::ipv6::route::snapshot()
        .into_iter()
        .map(|r| narf_filesystem::procfs::net::Ipv6RouteSnapshot {
            dst: r.dst,
            dst_prefix_len: r.dst_prefix_len,
            src: r.src,
            src_prefix_len: r.src_prefix_len,
            gateway: r.gateway,
            metric: r.metric,
            refcnt: r.refcnt,
            use_count: r.use_count,
            flags: r.flags,
            iface: r.iface,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn conntrack_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::ConntrackSnapshot> {
    narf_net::netfilter::conntrack::snapshot_in(current_net_ns_id())
        .into_iter()
        .map(|c| narf_filesystem::procfs::net::ConntrackSnapshot {
            l3proto: c.l3proto,
            l3proto_num: c.l3proto_num,
            l4proto: c.l4proto,
            l4proto_num: c.l4proto_num,
            timeout: c.timeout,
            state: c.state,
            orig_src: c.orig_src,
            orig_dst: c.orig_dst,
            orig_sport: c.orig_sport,
            orig_dport: c.orig_dport,
            reply_src: c.reply_src,
            reply_dst: c.reply_dst,
            reply_sport: c.reply_sport,
            reply_dport: c.reply_dport,
            assured: c.assured,
            use_count: c.use_count,
        })
        .collect()
}

#[cfg(feature = "linux-compat")]
fn snmp_adapter() -> narf_filesystem::procfs::net::SnmpMib {
    // SNMP counters live in atomic globals across the net stack;
    // until those land in narf_net, surface a baseline MIB with
    // the static defaults RFC 1213 specifies as well-known.
    narf_filesystem::procfs::net::SnmpMib {
        ip_forwarding: 2, // 1=router, 2=host (NARF: host today)
        ip_default_ttl: 64,
        tcp_rto_algorithm: 1, // 1=other, 2=constant, 3=mil-std-1778, 4=van-jacobson
        tcp_rto_min: 200,
        tcp_rto_max: 120_000,
        tcp_max_conn: -1i64 as u64, // unbounded
        ..Default::default()
    }
}

#[cfg(feature = "linux-compat")]
fn igmp_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::IgmpSnapshot> {
    // IGMP membership tracking lives in pkt_dhcp / dhcp paths and
    // isn't centralised yet. Return empty — the header line still
    // renders so libnetfilter-mcast probes don't fail.
    alloc::vec::Vec::new()
}

#[cfg(feature = "linux-compat")]
fn igmp6_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::Igmp6Snapshot> {
    // MLD membership: same status as IGMP — empty until centralised.
    alloc::vec::Vec::new()
}

#[cfg(feature = "linux-compat")]
fn tcp6_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::Tcb6Snapshot> {
    // IPv6 TCP sockets ride the same tcp::core table today; the
    // stack maps IPv4 + IPv6 onto separate TCBs once that lands.
    alloc::vec::Vec::new()
}

#[cfg(feature = "linux-compat")]
fn udp6_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::Udp6SocketSnapshot> {
    alloc::vec::Vec::new()
}

#[cfg(feature = "linux-compat")]
fn raw6_adapter() -> alloc::vec::Vec<narf_filesystem::procfs::net::Raw6SocketSnapshot> {
    alloc::vec::Vec::new()
}
