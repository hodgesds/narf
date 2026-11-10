//! `sockets` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// poll / select / pselect6 / epoll smoke tests
// ─────────────────────────────────────────────────────────────────────────────
//
// Test fixture: `ReadyFile` — a `FileOps` whose readiness mask is
// controlled by an `AtomicU32`. Tests install it as an fd, then call
// poll/epoll and verify the returned masks.

/// Connected Unix SEQPACKET pairs preserve one record per send.
fn smoke_unix_seqpacket_socketpair_preserves_records() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();
    let mut sv = [0i32; 2];
    let pair = call(
        Syscall::SocketPair,
        SyscallArgs {
            arg0: crate::socket::AF_UNIX as u64,
            arg1: crate::socket::SOCK_SEQPACKET as u64,
            arg3: sv.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if pair.value != 0 {
        return TestResult::Fail("SOCK_SEQPACKET socketpair failed");
    }
    for payload in [&b"first"[..], &b"second"[..]] {
        let sent = call(
            Syscall::SocketSend,
            SyscallArgs {
                arg0: sv[0] as u64,
                arg1: payload.as_ptr() as u64,
                arg2: payload.len() as u64,
                ..SyscallArgs::default()
            },
        );
        if sent.value != payload.len() as u64 {
            return TestResult::Fail("SEQPACKET send failed");
        }
    }
    let mut out = [0u8; 16];
    let first = call(
        Syscall::SocketRecv,
        SyscallArgs {
            arg0: sv[1] as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: out.len() as u64,
            ..SyscallArgs::default()
        },
    );
    if first.value != 5 || &out[..5] != b"first" {
        return TestResult::Fail("first SEQPACKET record was coalesced");
    }
    out.fill(0);
    let second = call(
        Syscall::SocketRecv,
        SyscallArgs {
            arg0: sv[1] as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: out.len() as u64,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if second.value != 6 || &out[..6] != b"second" {
        return TestResult::Fail("second SEQPACKET record was not preserved");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_unix_seqpacket_socketpair_preserves_records
);

// ── AF_INET socket smokes ────────────────────────────────────────────
//
// Exercise the `SocketFile::dispatch_op` surface directly — that's the
// boundary every POSIX syscall lands on, and it doesn't require a
// full syscall-table fixture per test. The smokes cover:
// - SOCK_STREAM bind / listen / connect (loopback path)
// - SOCK_DGRAM bind / connect / sendto / recvfrom
// - SOCK_RAW (IPPROTO_ICMP) — local-loop ICMP echo path
// - Socket options: SO_REUSEADDR, SO_BROADCAST, TCP_NODELAY,
//   TCP_CONGESTION, SO_BINDTODEVICE, SO_TYPE/DOMAIN/PROTOCOL
// - Sockaddr validation: invalid family rejected
// - O_NONBLOCK: recv on empty socket returns EAGAIN
// - SO_ERROR consumes-and-clears pending_error
// - getsockname / getpeername return the bound/peer addrs
// - 16-socket concurrent fan-out

/// AF_INET SOCK_STREAM loopback: socket → bind → listen → connect
/// pairs the listener and connecter via the in-process registry.
fn smoke_socket_inet_tcp_bind_listen_connect() -> TestResult {
    let server = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    // Bind to 127.0.0.1:1234.
    let addr = build_sockaddr_in(0x7F00_0001, 1234);
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind failed");
    }
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("listen failed");
    }
    let client = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    if !matches!(
        client.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        server.unregister();
        return TestResult::Fail("connect failed");
    }
    // Accept the pending connection.
    match server.dispatch_op(crate::socket::SocketOp::Accept) {
        crate::socket::SocketOpResult::Accepted { .. } => {
            server.unregister();
            TestResult::Pass
        }
        _ => {
            server.unregister();
            TestResult::Fail("accept did not return Accepted")
        }
    }
}
kernel_test_in!("userspace", smoke_socket_inet_tcp_bind_listen_connect);

/// AF_INET SOCK_STREAM loopback: full send/recv round-trip after
/// a paired connect+accept.
fn smoke_socket_inet_tcp_send_recv_loopback() -> TestResult {
    let server = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let addr = build_sockaddr_in(0x7F00_0001, 1235);
    let _ = server.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() });
    let _ = server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 1 });
    let client = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let _ = client.dispatch_op(crate::socket::SocketOp::Connect { addr });
    let accepted = match server.dispatch_op(crate::socket::SocketOp::Accept) {
        crate::socket::SocketOpResult::Accepted { socket, .. } => socket,
        _ => {
            server.unregister();
            return TestResult::Fail("no accept");
        }
    };
    // Client → server.
    let payload = b"hello narf";
    let r = client.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: None,
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(n) if n == payload.len() as u64) {
        server.unregister();
        return TestResult::Fail("client send mismatch");
    }
    let mut recv_buf = [0u8; 16];
    let r = accepted.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut recv_buf,
        flags: 0,
    });
    server.unregister();
    match r {
        crate::socket::SocketOpResult::Received { n, .. } => {
            if &recv_buf[..n] != payload {
                TestResult::Fail("recv payload mismatch")
            } else {
                TestResult::Pass
            }
        }
        _ => TestResult::Fail("recv did not return Received"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet_tcp_send_recv_loopback);

/// shutdown(SHUT_WR) closes the tx half on a loopback connection.
fn smoke_socket_inet_tcp_shutdown_wr() -> TestResult {
    let server = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let addr = build_sockaddr_in(0x7F00_0001, 1236);
    let _ = server.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() });
    let _ = server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 1 });
    let client = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let _ = client.dispatch_op(crate::socket::SocketOp::Connect { addr });
    let _ = server.dispatch_op(crate::socket::SocketOp::Accept);
    let r = client.dispatch_op(crate::socket::SocketOp::Shutdown {
        how: crate::socket::SHUT_WR,
    });
    server.unregister();
    if matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        TestResult::Pass
    } else {
        TestResult::Fail("shutdown(SHUT_WR) failed")
    }
}
kernel_test_in!("userspace", smoke_socket_inet_tcp_shutdown_wr);

/// AF_INET SOCK_DGRAM: bind, sendto self, recvfrom returns payload.
fn smoke_socket_inet_udp_send_recv_self() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let addr = build_sockaddr_in(0x7F00_0001, 5000);
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("udp bind failed");
    }
    let payload = b"udp-ping";
    let _ = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(addr),
    });
    let mut buf = [0u8; 32];
    let r = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    });
    sock.unregister();
    match r {
        crate::socket::SocketOpResult::Received { n, peer } => {
            if &buf[..n] != payload {
                return TestResult::Fail("udp payload mismatch");
            }
            if peer.is_none() {
                return TestResult::Fail("udp recv did not return peer");
            }
            TestResult::Pass
        }
        _ => TestResult::Fail("udp recv did not return Received"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet_udp_send_recv_self);

/// SO_BROADCAST: without it, sendto to 255.255.255.255 fails;
/// with it, the send succeeds (queue drop is OK).
fn smoke_socket_inet_udp_so_broadcast_gate() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let addr = build_sockaddr_in(0x7F00_0001, 5001);
    let _ = sock.dispatch_op(crate::socket::SocketOp::Bind { addr });
    let bcast = build_sockaddr_in(0xFFFF_FFFF, 5002);
    let payload = b"bcast";
    // Without SO_BROADCAST: must fail.
    let r = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(bcast.clone()),
    });
    if matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        sock.unregister();
        return TestResult::Fail("broadcast send w/o SO_BROADCAST should fail");
    }
    // Set SO_BROADCAST = 1.
    let one = 1u32.to_ne_bytes();
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_BROADCAST,
        value: &one,
    });
    let r2 = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(bcast),
    });
    sock.unregister();
    if matches!(r2, crate::socket::SocketOpResult::Ok(_)) {
        TestResult::Pass
    } else {
        TestResult::Fail("broadcast send w/ SO_BROADCAST should succeed")
    }
}
kernel_test_in!("userspace", smoke_socket_inet_udp_so_broadcast_gate);

/// UDP connect()'d mode filters packets from a different peer.
fn smoke_socket_inet_udp_connected_filter() -> TestResult {
    // Sock A binds to port 6001, will recv only from 127.0.0.1:6002.
    let a = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = a.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 6001),
    });
    let peer_b = build_sockaddr_in(0x7F00_0001, 6002);
    let _ = a.dispatch_op(crate::socket::SocketOp::Connect {
        addr: peer_b.clone(),
    });
    // Sock C (different sender) shoots a packet at A.
    let c = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = c.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 6003),
    });
    let _ = c.dispatch_op(crate::socket::SocketOp::Send {
        buf: b"stranger",
        flags: 0,
        addr: Some(build_sockaddr_in(0x7F00_0001, 6001)),
    });
    let mut buf = [0u8; 16];
    let r = a.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    });
    a.unregister();
    c.unregister();
    // Connected mode filter drops the unmatched packet → WouldBlock.
    match r {
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            TestResult::Pass
        }
        _ => TestResult::Fail("connected udp did not filter wrong peer"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet_udp_connected_filter);

/// MSG_PEEK on an AF_UNIX stream must not consume the bytes inspected.
fn smoke_socket_unix_stream_msg_peek_preserves_data() -> TestResult {
    let (sender, receiver) = crate::socket::SocketFile::unix_stream_pair();
    let payload = b"dbus-header";
    if !matches!(
        sender.dispatch_op(crate::socket::SocketOp::Send {
            buf: payload,
            flags: 0,
            addr: None,
        }),
        crate::socket::SocketOpResult::Ok(n) if n == payload.len() as u64
    ) {
        return TestResult::Fail("AF_UNIX stream setup send failed");
    }

    let mut peeked = [0u8; 4];
    if !matches!(
        receiver.dispatch_op(crate::socket::SocketOp::Recv {
            buf: &mut peeked,
            flags: crate::socket::MSG_PEEK,
        }),
        crate::socket::SocketOpResult::Received { n: 4, .. }
    ) || &peeked != b"dbus"
    {
        return TestResult::Fail("MSG_PEEK returned the wrong prefix");
    }

    let mut received = [0u8; 11];
    match receiver.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut received,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received { n, .. }
            if n == payload.len() && &received[..n] == payload =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("MSG_PEEK consumed AF_UNIX stream bytes"),
    }
}
kernel_test_in!(
    "userspace",
    smoke_socket_unix_stream_msg_peek_preserves_data
);

/// AF_INET SOCK_RAW with IPPROTO_ICMP: send + recv round-trip.
fn smoke_socket_inet_raw_icmp_loopback() -> TestResult {
    let sock = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_INET,
        crate::socket::SOCK_RAW,
        crate::socket::IPPROTO_ICMP,
    );
    let dest = build_sockaddr_in(0x7F00_0001, 0);
    let payload = b"\x08\x00\x00\x00ping";
    let r = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(dest),
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("icmp send failed");
    }
    let mut buf = [0u8; 64];
    let r = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    });
    match r {
        crate::socket::SocketOpResult::Received { n, .. } => {
            if &buf[..n] != payload {
                TestResult::Fail("icmp recv payload mismatch")
            } else {
                TestResult::Pass
            }
        }
        _ => TestResult::Fail("icmp recv did not return Received"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet_raw_icmp_loopback);

// ── AF_INET ICMP echo sockets ──────────────────────────────────────────────

static ICMP_TX_CAPTURE: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<alloc::vec::Vec<u8>>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

fn icmp_capture_send(frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    ICMP_TX_CAPTURE.lock().push(frame.to_vec());
    Ok(())
}

/// The unprivileged ping socket must take the real ICMP path, rather than the
/// UDP dispatcher that happens to share `SOCK_DGRAM`.
fn smoke_socket_inet_dgram_icmp_reaches_wire_and_receives_echo() -> TestResult {
    use narf_filesystem::FileOps;

    const IFACE: &str = "icmp-ping-test0";
    const LOCAL: [u8; 4] = [10, 77, 0, 2];
    const PEER: [u8; 4] = [10, 77, 0, 9];
    const SEQUENCE: u16 = 0x1234;
    const PAYLOAD: &[u8] = b"narf-ping";

    narf_net::iface::register(IFACE, [0x02, 0, 0, 0, 0, 0x77], icmp_capture_send);
    narf_net::iface::set_default_ipv4(LOCAL, LOCAL);
    narf_net::iface::add_addr(IFACE, LOCAL, 24);
    narf_net::arp_cache::insert(IFACE, PEER, [0x02, 0, 0, 0, 0, 0x79]);
    narf_net::tcp_stack::__arp_insert_legacy(PEER, [0x02, 0, 0, 0, 0, 0x79]);
    ICMP_TX_CAPTURE.lock().clear();

    let sock = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_INET,
        crate::socket::SOCK_DGRAM,
        crate::socket::IPPROTO_ICMP,
    );
    let local = match sock.local_addr() {
        Some(local) => local,
        None => return TestResult::Fail("ICMP echo socket has no local address"),
    };
    let identifier = match crate::socket::parse_sockaddr_in(&local) {
        Some((_addr, id)) if id != 0 => id,
        _ => return TestResult::Fail("ICMP echo socket did not allocate an identifier"),
    };

    let mut request = alloc::vec![narf_net::pkt::ICMP_ECHO_REQUEST, 0, 0, 0, 0, 0];
    request.extend_from_slice(&SEQUENCE.to_be_bytes());
    request.extend_from_slice(PAYLOAD);
    let sent = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &request,
        flags: 0,
        addr: Some(build_sockaddr_in(u32::from_be_bytes(PEER), 0)),
    });
    if !matches!(sent, crate::socket::SocketOpResult::Ok(n) if n == request.len() as u64) {
        return TestResult::Fail("ICMP echo request did not reach the net socket");
    }
    let frames = ICMP_TX_CAPTURE.lock().clone();
    let Some(frame) = frames.first() else {
        return TestResult::Fail("ICMP echo request emitted no Ethernet frame");
    };
    if frame.len() < 14 + 20 + 8 || frame[14 + 9] != narf_net::pkt::IP_PROTO_ICMP {
        return TestResult::Fail("ping socket emitted a non-ICMP frame");
    }
    if u16::from_be_bytes([frame[14 + 20 + 4], frame[14 + 20 + 5]]) != identifier {
        return TestResult::Fail("kernel did not stamp the echo-socket identifier");
    }

    // Model the reply at the network RX boundary, as a virtio-net receive
    // would. This exercises net's ICMP demux and SocketFile's datagram bridge.
    let mut reply = alloc::vec![narf_net::pkt::ICMP_ECHO_REPLY, 0, 0, 0];
    reply.extend_from_slice(&identifier.to_be_bytes());
    reply.extend_from_slice(&SEQUENCE.to_be_bytes());
    reply.extend_from_slice(PAYLOAD);
    let checksum = narf_net::pkt::ip_checksum(&reply);
    reply[2..4].copy_from_slice(&checksum.to_be_bytes());
    narf_net::icmp_sock::on_icmp_rx(PEER, LOCAL, &reply);

    if sock.poll_readiness() & narf_filesystem::POLL_IN == 0 {
        return TestResult::Fail("ICMP echo reply did not publish POLL_IN");
    }
    let mut received = [0u8; 64];
    match sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut received,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received {
            n,
            peer: Some(peer),
        } if n == reply.len()
            && received[..n] == reply
            && crate::socket::parse_sockaddr_in(&peer) == Some((u32::from_be_bytes(PEER), 0)) =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("ICMP echo reply did not reach the ping socket"),
    }
}
kernel_test_in!(
    "userspace/net",
    smoke_socket_inet_dgram_icmp_reaches_wire_and_receives_echo
);

/// SO_REUSEADDR: stored value round-trips through get/setsockopt.
fn smoke_socket_so_reuseaddr_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let one = 1u32.to_ne_bytes();
    let r = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_REUSEADDR,
        value: &one,
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("setsockopt(SO_REUSEADDR) failed");
    }
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_REUSEADDR,
        buf: &mut out,
    });
    match r {
        crate::socket::SocketOpResult::OptValue { n: 4 } => {
            let v = u32::from_ne_bytes(out);
            if v == 1 {
                TestResult::Pass
            } else {
                TestResult::Fail("got != 1")
            }
        }
        _ => TestResult::Fail("getsockopt did not return OptValue"),
    }
}
kernel_test_in!("userspace", smoke_socket_so_reuseaddr_round_trip);

/// TCP_NODELAY: stored value round-trips through get/setsockopt.
fn smoke_socket_tcp_nodelay_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let one = 1u32.to_ne_bytes();
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_NODELAY,
        value: &one,
    });
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_NODELAY,
        buf: &mut out,
    });
    if matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 }) && u32::from_ne_bytes(out) == 1
    {
        TestResult::Pass
    } else {
        TestResult::Fail("TCP_NODELAY did not round-trip")
    }
}
kernel_test_in!("userspace", smoke_socket_tcp_nodelay_round_trip);

/// TCP_CONGESTION: round-trip "reno" then "cubic".
fn smoke_socket_tcp_congestion_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_CONGESTION,
        value: b"reno",
    });
    let mut out = [0u8; 16];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_CONGESTION,
        buf: &mut out,
    });
    let n = match r {
        crate::socket::SocketOpResult::OptValue { n } => n,
        _ => return TestResult::Fail("TCP_CONGESTION get failed"),
    };
    if &out[..n] != b"reno" {
        return TestResult::Fail("TCP_CONGESTION 'reno' round-trip failed");
    }
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_CONGESTION,
        value: b"cubic",
    });
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::IPPROTO_TCP,
        name: crate::socket::TCP_CONGESTION,
        buf: &mut out,
    });
    let n = match r {
        crate::socket::SocketOpResult::OptValue { n } => n,
        _ => return TestResult::Fail("TCP_CONGESTION (cubic) get failed"),
    };
    if &out[..n] != b"cubic" {
        return TestResult::Fail("TCP_CONGESTION 'cubic' round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_tcp_congestion_round_trip);

/// SO_BINDTODEVICE names a device that must EXIST.
///
/// `sock_setbindtodevice` (`net/core/sock.c:685`) resolves the name with
/// `dev_get_by_name_rcu` and answers -ENODEV when it misses
/// (`net/core/sock.c:719`); an empty name unbinds. This test used to bind
/// to "eth0" while discarding the setsockopt result and then assert only
/// that getsockopt echoed the string back — which passed precisely BECAUSE
/// nothing validated the name or enforced anything. A round-trip is not
/// evidence of a device binding.
fn smoke_socket_so_bindtodevice_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let set = |value: &[u8]| {
        sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
            level: crate::socket::SOL_SOCKET,
            name: crate::socket::SO_BINDTODEVICE,
            value,
        })
    };

    // A device that does not exist is ENODEV, not silent acceptance.
    match set(b"definitely-not-a-nic") {
        crate::socket::SocketOpResult::Err(e) if e.errno() == 19 => {}
        crate::socket::SocketOpResult::Ok(_) => {
            return TestResult::Fail("binding to a nonexistent device must fail")
        }
        _ => return TestResult::Fail("binding to a nonexistent device must be ENODEV"),
    }

    // A real interface binds and round-trips. Loopback is always present.
    let Some(dev) = narf_net::iface::snapshot_all()
        .into_iter()
        .map(|i| i.name)
        .find(|n| narf_net::iface::ifindex_of(n).is_some())
    else {
        return TestResult::Skip("no interface registered to bind to");
    };
    if !matches!(set(dev.as_bytes()), crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("binding to a live interface should succeed");
    }
    let mut out = [0u8; 16];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_BINDTODEVICE,
        buf: &mut out,
    });
    let n = match r {
        crate::socket::SocketOpResult::OptValue { n } => n,
        _ => return TestResult::Fail("SO_BINDTODEVICE get failed"),
    };
    // Linux sock_getbindtodevice includes the terminating NUL in optlen.
    if n != dev.len() + 1 || &out[..dev.len()] != dev.as_bytes() || out[dev.len()] != 0 {
        return TestResult::Fail("SO_BINDTODEVICE round-trip mismatch");
    }

    // An empty name unbinds. The harness task is privileged, so the
    // CAP_NET_RAW re-bind gate does not block this.
    if !matches!(set(b""), crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("an empty device name must unbind");
    }
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_BINDTODEVICE,
        buf: &mut out,
    });
    match r {
        crate::socket::SocketOpResult::OptValue { n: 0 } => TestResult::Pass,
        crate::socket::SocketOpResult::OptValue { .. } => {
            TestResult::Fail("an unbound socket must report no device")
        }
        _ => TestResult::Fail("SO_BINDTODEVICE get failed after unbind"),
    }
}
kernel_test_in!("userspace", smoke_socket_so_bindtodevice_round_trip);

/// sockaddr_in with invalid family rejected by Connect: `tcp_v4_connect`
/// answers a foreign `sin_family` with -EAFNOSUPPORT.
fn smoke_socket_sockaddr_invalid_family_rejected() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let mut bogus = crate::socket::make_sockaddr_in(0x7F00_0001, 4321);
    bogus.family = 9999; // not AF_INET / AF_UNIX / AF_INET6
    let r = sock.dispatch_op(crate::socket::SocketOp::Connect { addr: bogus });
    if matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::AfNoSupport)
    ) {
        TestResult::Pass
    } else {
        TestResult::Fail("invalid family was not rejected with EAFNOSUPPORT")
    }
}
kernel_test_in!("userspace", smoke_socket_sockaddr_invalid_family_rejected);

/// sockaddr_in port is honored in network byte order.
fn smoke_socket_sockaddr_port_network_byte_order() -> TestResult {
    // Build an explicit body with port 0x4321 (BE) + IP 127.0.0.1.
    let body = alloc::vec![0x43u8, 0x21, 127, 0, 0, 1];
    let addr = crate::socket::SockAddr {
        family: crate::socket::AF_INET,
        body,
    };
    match crate::socket::parse_sockaddr_in(&addr) {
        Some((ip, port)) => {
            if ip == 0x7F00_0001 && port == 0x4321 {
                TestResult::Pass
            } else {
                TestResult::Fail("port/ip parse mismatch")
            }
        }
        None => TestResult::Fail("parse failed"),
    }
}
kernel_test_in!("userspace", smoke_socket_sockaddr_port_network_byte_order);

/// O_NONBLOCK: recv on empty socket returns EAGAIN immediately.
fn smoke_socket_nonblock_recv_returns_eagain() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = sock.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 7000),
    });
    sock.set_nonblock(true);
    if !sock.is_nonblock() {
        sock.unregister();
        return TestResult::Fail("set_nonblock didn't take");
    }
    let mut buf = [0u8; 8];
    let r = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    });
    sock.unregister();
    match r {
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            TestResult::Pass
        }
        _ => TestResult::Fail("nonblock recv did not return WouldBlock"),
    }
}
kernel_test_in!("userspace", smoke_socket_nonblock_recv_returns_eagain);

/// SO_ERROR consumes and clears a pending async error.
fn smoke_socket_so_error_consumes_and_clears() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    sock.set_pending_error(crate::socket::SockError::ConnectionRefused);
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_ERROR,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 }) {
        return TestResult::Fail("first SO_ERROR get failed");
    }
    let v = u32::from_ne_bytes(out);
    // ConnectionRefused → errno 111.
    if v != 111 {
        return TestResult::Fail("SO_ERROR returned wrong errno");
    }
    // Second read should return 0 (cleared).
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_ERROR,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 }) {
        return TestResult::Fail("second SO_ERROR get failed");
    }
    let v = u32::from_ne_bytes(out);
    if v != 0 {
        return TestResult::Fail("SO_ERROR did not clear");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_so_error_consumes_and_clears);

/// getsockname after bind returns the assigned (port, ip).
fn smoke_socket_getsockname_after_bind() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = sock.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 4040),
    });
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockName);
    sock.unregister();
    match r {
        crate::socket::SocketOpResult::Addr(addr) => {
            match crate::socket::parse_sockaddr_in(&addr) {
                Some((ip, port)) if ip == 0x7F00_0001 && port == 4040 => TestResult::Pass,
                _ => TestResult::Fail("getsockname returned wrong addr"),
            }
        }
        _ => TestResult::Fail("getsockname did not return Addr"),
    }
}
kernel_test_in!("userspace", smoke_socket_getsockname_after_bind);

/// getpeername on a connected UDP socket returns the connect()'d peer.
fn smoke_socket_getpeername_after_connect() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let peer = build_sockaddr_in(0x7F00_0001, 9999);
    let _ = sock.dispatch_op(crate::socket::SocketOp::Connect { addr: peer });
    let r = sock.dispatch_op(crate::socket::SocketOp::GetPeerName);
    // connect() autobound an ephemeral port; release it.
    sock.unregister();
    match r {
        crate::socket::SocketOpResult::Addr(addr) => {
            match crate::socket::parse_sockaddr_in(&addr) {
                Some((ip, port)) if ip == 0x7F00_0001 && port == 9999 => TestResult::Pass,
                _ => TestResult::Fail("getpeername returned wrong addr"),
            }
        }
        _ => TestResult::Fail("getpeername did not return Addr"),
    }
}
kernel_test_in!("userspace", smoke_socket_getpeername_after_connect);

/// SO_TYPE, SO_DOMAIN, SO_PROTOCOL all report what socket() captured.
fn smoke_socket_so_type_domain_protocol() -> TestResult {
    let sock = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_INET,
        crate::socket::SOCK_DGRAM,
        crate::socket::IPPROTO_UDP,
    );
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_TYPE,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        || u32::from_ne_bytes(out) != crate::socket::SOCK_DGRAM
    {
        return TestResult::Fail("SO_TYPE mismatch");
    }
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_DOMAIN,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        || u32::from_ne_bytes(out) != crate::socket::AF_INET as u32
    {
        return TestResult::Fail("SO_DOMAIN mismatch");
    }
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_PROTOCOL,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        || u32::from_ne_bytes(out) != crate::socket::IPPROTO_UDP
    {
        return TestResult::Fail("SO_PROTOCOL mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_so_type_domain_protocol);

/// IP_TTL is validated on the way in (0 and >255 → InvalidArg) and
/// round-trips otherwise.
fn smoke_socket_ip_ttl_validated_and_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    // Reject 0.
    let zero = 0u32.to_ne_bytes();
    let r = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_IP,
        name: crate::socket::IP_TTL,
        value: &zero,
    });
    if !matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("IP_TTL=0 should be rejected");
    }
    // Reject 300.
    let big = 300u32.to_ne_bytes();
    let r = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_IP,
        name: crate::socket::IP_TTL,
        value: &big,
    });
    if !matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("IP_TTL=300 should be rejected");
    }
    // Accept 32.
    let val = 32u32.to_ne_bytes();
    let r = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_IP,
        name: crate::socket::IP_TTL,
        value: &val,
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("IP_TTL=32 set failed");
    }
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::IPPROTO_IP,
        name: crate::socket::IP_TTL,
        buf: &mut out,
    });
    if matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        && u32::from_ne_bytes(out) == 32
    {
        TestResult::Pass
    } else {
        TestResult::Fail("IP_TTL did not round-trip 32")
    }
}
kernel_test_in!("userspace", smoke_socket_ip_ttl_validated_and_round_trip);

/// 16 concurrent UDP sockets — verify no allocator pressure / state leak.
fn smoke_socket_inet_udp_16_concurrent() -> TestResult {
    let mut socks: alloc::vec::Vec<alloc::sync::Arc<crate::socket::SocketFile>> =
        alloc::vec::Vec::with_capacity(16);
    for i in 0..16u16 {
        let s = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
        let r = s.dispatch_op(crate::socket::SocketOp::Bind {
            addr: build_sockaddr_in(0x7F00_0001, 8000 + i),
        });
        if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
            for s in &socks {
                s.unregister();
            }
            return TestResult::Fail("16 concurrent bind failed");
        }
        socks.push(s);
    }
    // sendto self for each.
    for (i, s) in socks.iter().enumerate() {
        let payload = (i as u32).to_ne_bytes();
        let _ = s.dispatch_op(crate::socket::SocketOp::Send {
            buf: &payload,
            flags: 0,
            addr: Some(build_sockaddr_in(0x7F00_0001, 8000 + i as u16)),
        });
    }
    // recvfrom each, verify payload.
    let mut ok = true;
    for (i, s) in socks.iter().enumerate() {
        let mut buf = [0u8; 4];
        let r = s.dispatch_op(crate::socket::SocketOp::Recv {
            buf: &mut buf,
            flags: 0,
        });
        match r {
            crate::socket::SocketOpResult::Received { n: 4, .. } => {
                if u32::from_ne_bytes(buf) != i as u32 {
                    ok = false;
                }
            }
            _ => {
                ok = false;
            }
        }
    }
    for s in &socks {
        s.unregister();
    }
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("16 concurrent payload mismatch")
    }
}
kernel_test_in!("userspace", smoke_socket_inet_udp_16_concurrent);

fn smoke_socket_inet6_udp_loopback_round_trip() -> TestResult {
    let rx = crate::socket::SocketFile::new(crate::socket::AF_INET6, crate::socket::SOCK_DGRAM);
    let tx = crate::socket::SocketFile::new(crate::socket::AF_INET6, crate::socket::SOCK_DGRAM);
    let loopback = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let addr = crate::socket::make_sockaddr_in6(loopback, 8123);
    if !matches!(
        rx.dispatch_op(crate::socket::SocketOp::Bind { addr: addr.clone() }),
        crate::socket::SocketOpResult::Ok(0)
    ) {
        return TestResult::Fail("AF_INET6 UDP bind(::1) failed");
    }
    let payload = b"udp6";
    if !matches!(
        tx.dispatch_op(crate::socket::SocketOp::Send {
            buf: payload,
            flags: 0,
            addr: Some(addr),
        }),
        crate::socket::SocketOpResult::Ok(4)
    ) {
        rx.unregister();
        tx.unregister();
        return TestResult::Fail("AF_INET6 UDP sendto(::1) failed");
    }
    let mut out = [0u8; 8];
    let result = rx.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    });
    rx.unregister();
    tx.unregister();
    if matches!(result, crate::socket::SocketOpResult::Received { n: 4, .. })
        && &out[..4] == payload
    {
        TestResult::Pass
    } else {
        TestResult::Fail("AF_INET6 UDP loopback payload mismatch")
    }
}
kernel_test_in!("userspace", smoke_socket_inet6_udp_loopback_round_trip);

fn smoke_socket_inet6_udp_preserves_scope_id() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET6, crate::socket::SOCK_DGRAM);
    let mut body = alloc::vec::Vec::new();
    body.extend_from_slice(&9000u16.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    body.extend_from_slice(&7u32.to_ne_bytes());
    let addr = crate::socket::SockAddr {
        family: crate::socket::AF_INET6,
        body,
    };
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Ok(0)
    ) {
        sock.unregister();
        return TestResult::Fail("scoped UDP6 connect failed");
    }
    let peer = sock.peer_addr();
    sock.unregister();
    match peer {
        Some(peer)
            if peer.body.len() == 26
                && u32::from_ne_bytes([
                    peer.body[22],
                    peer.body[23],
                    peer.body[24],
                    peer.body[25],
                ]) == 7 =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("UDP6 getpeername lost sin6_scope_id"),
    }
}
kernel_test_in!("userspace", smoke_socket_inet6_udp_preserves_scope_id);

fn smoke_socket_inet6_v6only_rejects_change_after_bind() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET6, crate::socket::SOCK_DGRAM);
    let loopback = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Bind {
            addr: crate::socket::make_sockaddr_in6(loopback, 8124),
        }),
        crate::socket::SocketOpResult::Ok(0)
    ) {
        return TestResult::Fail("UDP6 bind for V6ONLY test failed");
    }
    let one = 1u32.to_ne_bytes();
    let result = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_IPV6,
        name: crate::socket::IPV6_V6ONLY,
        value: &one,
    });
    sock.unregister();
    if matches!(
        result,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        TestResult::Pass
    } else {
        TestResult::Fail("IPV6_V6ONLY changed after UDP6 bind")
    }
}
kernel_test_in!(
    "userspace",
    smoke_socket_inet6_v6only_rejects_change_after_bind
);

fn smoke_socket_dual_stack_udp_receives_v4_as_mapped() -> TestResult {
    const PORT: u16 = 8125;
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET6, crate::socket::SOCK_DGRAM);
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Bind {
            addr: crate::socket::make_sockaddr_in6([0; 16], PORT),
        }),
        crate::socket::SocketOpResult::Ok(0)
    ) {
        return TestResult::Fail("dual-stack UDP6 wildcard bind failed");
    }
    if !crate::socket::deliver_wire_datagram(
        sock.net_ns_id(),
        &[192, 0, 2, 1],
        9000,
        &[127, 0, 0, 1],
        PORT,
        b"mapped",
        1,
        narf_net::udp_sock::RxIpMeta::default(),
    ) {
        sock.unregister();
        return TestResult::Fail("IPv4 datagram did not enter dual-stack UDP6 socket");
    }
    let mut out = [0u8; 16];
    let result = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    });
    sock.unregister();
    match result {
        crate::socket::SocketOpResult::Received {
            n: 6,
            peer: Some(peer),
        } if &out[..6] == b"mapped"
            && peer.body[6..18] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
            && peer.body[18..22] == [192, 0, 2, 1] =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("dual-stack UDP6 recvfrom address was not IPv4-mapped"),
    }
}
kernel_test_in!(
    "userspace",
    smoke_socket_dual_stack_udp_receives_v4_as_mapped
);

fn smoke_socket_udp_cross_family_bind_arbitration() -> TestResult {
    const PORT: u16 = 8126;
    let v4 = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let dual = crate::socket::SocketFile::new(crate::socket::AF_INET6, crate::socket::SOCK_DGRAM);
    let only = crate::socket::SocketFile::new(crate::socket::AF_INET6, crate::socket::SOCK_DGRAM);
    if !matches!(
        v4.dispatch_op(crate::socket::SocketOp::Bind {
            addr: build_sockaddr_in(0, PORT),
        }),
        crate::socket::SocketOpResult::Ok(0)
    ) {
        return TestResult::Fail("IPv4 wildcard bind failed");
    }
    if !matches!(
        dual.dispatch_op(crate::socket::SocketOp::Bind {
            addr: crate::socket::make_sockaddr_in6([0; 16], PORT),
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::AddrInUse)
    ) {
        v4.unregister();
        dual.unregister();
        return TestResult::Fail("dual-stack UDP6 wildcard did not conflict with IPv4");
    }
    let one = 1u32.to_ne_bytes();
    let _ = only.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::IPPROTO_IPV6,
        name: crate::socket::IPV6_V6ONLY,
        value: &one,
    });
    let result = only.dispatch_op(crate::socket::SocketOp::Bind {
        addr: crate::socket::make_sockaddr_in6([0; 16], PORT),
    });
    v4.unregister();
    dual.unregister();
    only.unregister();
    if matches!(result, crate::socket::SocketOpResult::Ok(0)) {
        TestResult::Pass
    } else {
        TestResult::Fail("V6ONLY UDP bind incorrectly conflicted with IPv4")
    }
}
kernel_test_in!("userspace", smoke_socket_udp_cross_family_bind_arbitration);

/// SO_REUSEADDR + double-bind: the second bind to the same
/// (addr, port) succeeds when SO_REUSEADDR is set on the second
/// socket. Without it, the second bind returns EADDRINUSE.
fn smoke_socket_so_reuseaddr_double_bind_inet() -> TestResult {
    let a = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let one = 1u32.to_ne_bytes();
    let _ = a.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_REUSEADDR,
        value: &one,
    });
    let bound = a.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 9100),
    });
    if !matches!(bound, crate::socket::SocketOpResult::Ok(_)) {
        a.unregister();
        return TestResult::Fail("first bind failed");
    }
    // Second socket without SO_REUSEADDR — must reject.
    let b = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let r = b.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 9100),
    });
    if !matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::AddrInUse)
    ) {
        a.unregister();
        b.unregister();
        return TestResult::Fail("second bind without SO_REUSEADDR should fail");
    }
    // Third socket WITH SO_REUSEADDR — must succeed.
    let c = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = c.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_REUSEADDR,
        value: &one,
    });
    let r = c.dispatch_op(crate::socket::SocketOp::Bind {
        addr: build_sockaddr_in(0x7F00_0001, 9100),
    });
    a.unregister();
    c.unregister();
    if matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        TestResult::Pass
    } else {
        TestResult::Fail("second bind with SO_REUSEADDR should succeed")
    }
}
kernel_test_in!("userspace", smoke_socket_so_reuseaddr_double_bind_inet);

/// SO_RCVBUF / SO_SNDBUF store twice the request (`sk_setsockopt`), floored
/// at SOCK_MIN_RCVBUF (2304) / SOCK_MIN_SNDBUF (4608).
fn smoke_socket_so_rcvbuf_sndbuf_clamp() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    // Set RCVBUF to 100; 200 is below SOCK_MIN_RCVBUF, so it floors at 2304.
    let v = 100u32.to_ne_bytes();
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_RCVBUF,
        value: &v,
    });
    let mut out = [0u8; 4];
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_RCVBUF,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 }) {
        return TestResult::Fail("SO_RCVBUF get failed");
    }
    if u32::from_ne_bytes(out) != 2_304 {
        return TestResult::Fail("SO_RCVBUF did not clamp");
    }
    // Set SNDBUF to 64 KiB; Linux reports the doubled 128 KiB.
    let v = 65_536u32.to_ne_bytes();
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_SNDBUF,
        value: &v,
    });
    let r = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_SNDBUF,
        buf: &mut out,
    });
    if !matches!(r, crate::socket::SocketOpResult::OptValue { n: 4 })
        || u32::from_ne_bytes(out) != 131_072
    {
        return TestResult::Fail("SO_SNDBUF was not doubled");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_so_rcvbuf_sndbuf_clamp);

/// unshare(CLONE_NEWNET) seeds a fresh netns containing only `lo`.
#[cfg(feature = "container")]
fn smoke_wave72_net_ns_loopback_only() -> TestResult {
    crate::namespaces::__test_reset_all();
    let task: u64 = 0xB000_0001;
    crate::namespaces::unshare_net(task);
    let ns = match crate::namespaces::current_net_ns(task) {
        Some(ns) => ns,
        None => {
            crate::namespaces::__test_reset_all();
            return TestResult::Fail("unshare_net did not install per-task entry");
        }
    };
    let names = ns.iface_names();
    if names.len() != 1 || names[0] != "lo" {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("fresh netns iface list != [lo]");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_wave72_net_ns_loopback_only);

/// net-ns dual-bind: two SocketFiles stamped with DIFFERENT net-ns ids
/// can both bind the same UDP (addr, port); two in the SAME ns
/// collide with EADDRINUSE.
#[cfg(feature = "container")]
fn smoke_net_ns_dual_bind_same_port() -> TestResult {
    use crate::socket::{SockAddr, SocketFile, SocketOp, SocketOpResult};
    use crate::socket::{AF_INET, SOCK_DGRAM};

    // A full sockaddr_in (port, ip, sin_zero): `inet_bind_sk` rejects an
    // address shorter than sizeof(struct sockaddr_in). Port 7777, 0.0.0.0.
    let mk_addr = || -> SockAddr { crate::socket::make_sockaddr_in(0, 7777) };

    // ns 100 and ns 200 both bind 0.0.0.0:7777 — both succeed.
    let s1 = SocketFile::with_protocol(AF_INET, SOCK_DGRAM, 0);
    s1.set_net_ns_id(100);
    let s2 = SocketFile::with_protocol(AF_INET, SOCK_DGRAM, 0);
    s2.set_net_ns_id(200);
    let r1 = s1.dispatch_op(SocketOp::Bind { addr: mk_addr() });
    let r2 = s2.dispatch_op(SocketOp::Bind { addr: mk_addr() });
    if !matches!(r1, SocketOpResult::Ok(_)) {
        return TestResult::Fail("ns 100 bind failed");
    }
    if !matches!(r2, SocketOpResult::Ok(_)) {
        return TestResult::Fail("ns 200 dual-bind same port was rejected");
    }

    // Same ns (300) collides on the second bind.
    let s3 = SocketFile::with_protocol(AF_INET, SOCK_DGRAM, 0);
    s3.set_net_ns_id(300);
    let s4 = SocketFile::with_protocol(AF_INET, SOCK_DGRAM, 0);
    s4.set_net_ns_id(300);
    let r3 = s3.dispatch_op(SocketOp::Bind { addr: mk_addr() });
    let r4 = s4.dispatch_op(SocketOp::Bind { addr: mk_addr() });
    if !matches!(r3, SocketOpResult::Ok(_)) {
        return TestResult::Fail("ns 300 first bind failed");
    }
    if !matches!(r4, SocketOpResult::Err(_)) {
        return TestResult::Fail("same-ns second bind did NOT collide");
    }

    // Cleanup the registry entries this test left behind.
    s1.unregister();
    s2.unregister();
    s3.unregister();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_net_ns_dual_bind_same_port);

#[cfg(feature = "container")]
fn smoke_net_ns_loopback_delivery_and_final_teardown() -> TestResult {
    use crate::socket::{SockAddr, SocketFile, SocketOp, SocketOpResult, AF_INET, SOCK_DGRAM};

    crate::namespaces::__test_reset_all();
    let task = 0xB000_0901;
    crate::namespaces::unshare_net(task);
    let namespace = crate::namespaces::current_net_ns(task).expect("namespace");
    let namespace_id = namespace.id();
    let receiver = SocketFile::with_protocol(AF_INET, SOCK_DGRAM, 0);
    receiver.set_net_namespace(namespace.clone());
    let sender = SocketFile::with_protocol(AF_INET, SOCK_DGRAM, 0);
    sender.set_net_namespace(namespace.clone());
    drop(namespace);

    let port = 19001u16;
    let loopback = u32::from_be_bytes([127, 0, 0, 1]);
    // A full sockaddr_in: `inet_bind_sk` / `ip4_datagram_connect` reject an
    // address shorter than sizeof(struct sockaddr_in).
    let addr: SockAddr = crate::socket::make_sockaddr_in(loopback, port);
    if !matches!(
        receiver.dispatch_op(SocketOp::Bind { addr: addr.clone() }),
        SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("namespace loopback bind failed");
    }
    if !matches!(
        sender.dispatch_op(SocketOp::Connect { addr: addr.clone() }),
        SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("namespace loopback connect failed");
    }
    if !matches!(
        sender.dispatch_op(SocketOp::Send {
            buf: b"namespace-loopback",
            flags: 0,
            addr: None,
        }),
        SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("namespace loopback send failed");
    }
    let mut received = [0u8; 32];
    if !matches!(
        receiver.dispatch_op(SocketOp::Recv {
            buf: &mut received,
            flags: 0,
        }),
        SocketOpResult::Received { n: 18, .. }
    ) || &received[..18] != b"namespace-loopback"
    {
        return TestResult::Fail("namespace loopback payload was not delivered");
    }

    narf_net::route::route_add(narf_net::route::Route {
        net_ns_id: namespace_id,
        dst: narf_net::route::Ipv4Net {
            addr: narf_net::ipv4::Ipv4Addr([198, 18, 0, 0]),
            prefix_len: 15,
        },
        gateway: None,
        iface: alloc::string::String::from("lo"),
        src_hint: Some(narf_net::ipv4::Ipv4Addr([127, 0, 0, 1])),
        metric: 0,
        scope: narf_net::route::Scope::Host,
        table: narf_net::route::TABLE_MAIN,
        protocol: narf_net::route::RTPROT_KERNEL,
    });
    crate::namespaces::release_task(task);
    if narf_net::route::route_list_in(namespace_id).is_empty() {
        return TestResult::Fail("live socket did not retain namespace state");
    }
    // Close both endpoints. The sender autobound on connect()
    // (`inet_autobind`), so it holds a port-table entry — and with it the
    // namespace — until unregistered, exactly like the bound receiver.
    receiver.unregister();
    sender.unregister();
    drop(receiver);
    drop(sender);
    if !narf_net::route::route_list_in(namespace_id).is_empty() {
        return TestResult::Fail("final namespace reference did not reclaim routes");
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!(
    "userspace",
    smoke_net_ns_loopback_delivery_and_final_teardown
);

fn smoke_stack_admin_delegates_only_to_current_netlink_socket() -> TestResult {
    use narf_capabilities::{Cap, Invoke};
    use narf_net::{StackAttach, StackDaemon};

    const TASK: u64 = 0x4E45_544C;
    fn task_lookup() -> u64 {
        TASK
    }
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            crate::handlers::__test_reset_task_id_lookup();
        }
    }
    let _cleanup = Cleanup;

    let iface_name = "lo.userspace-admin-delegate";
    narf_scheduler::__reset_queues_for_test();
    narf_net::bypass::__reset_for_test();
    if narf_net::registry()
        .with_interface(iface_name, |_| ())
        .is_none()
    {
        let authority = narf_net::bootstrap_authority();
        if narf_net::register_loopback_named(&authority, iface_name).is_err() {
            return TestResult::Fail("failed to register delegation test interface");
        }
    }
    let iface = narf_net::registry()
        .with_handle(iface_name, |handle| *handle)
        .expect("registered interface handle");
    let request = StackAttach {
        iface,
        daemon: Cap::<StackDaemon, Invoke>::bootstrap(),
    };
    let umem = match narf_net::bypass::Umem::register(8192, 2048) {
        Ok(umem) => umem,
        Err(_) => return TestResult::Skip("Umem::register NoMemory (no DMA in test env)"),
    };
    let parts = narf_net::bypass::XdpSocket::create(umem);
    let reply = match narf_net::stack::attach_registered(&request, parts.socket) {
        Ok(reply) => reply,
        Err(_) => return TestResult::Fail("registered stack attach failed"),
    };

    crate::install_task_id_lookup(task_lookup);
    crate::fd::__test_reset();
    let route = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_NETLINK,
        crate::socket::SOCK_RAW,
        crate::socket::NETLINK_ROUTE,
    );
    let inet = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let generic = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_NETLINK,
        crate::socket::SOCK_RAW,
        crate::socket::NETLINK_GENERIC,
    );
    let (route_fd, inet_fd, generic_fd) = crate::fd::with_table(TASK, |table| {
        let route_fd = table.open(crate::fd::FdEntry {
            ops: route.clone(),
            offset: 0,
            flags: 0,
            status_flags: 0,
        });
        let inet_fd = table.open(crate::fd::FdEntry {
            ops: inet,
            offset: 0,
            flags: 0,
            status_flags: 0,
        });
        let generic_fd = table.open(crate::fd::FdEntry {
            ops: generic.clone(),
            offset: 0,
            flags: 0,
            status_flags: 0,
        });
        (
            route_fd.expect("fixture fd"),
            inet_fd.expect("fixture fd"),
            generic_fd.expect("fixture fd"),
        )
    })
    .expect("current task fd table");

    if crate::delegate_stack_admin_to_route_socket(inet_fd, &reply)
        != Err(crate::socket::SockError::InvalidArg)
    {
        return TestResult::Fail("admin delegated to a non-route socket");
    }
    if crate::delegate_stack_admin_to_route_socket(route_fd, &reply).is_err() {
        return TestResult::Fail("route-socket admin delegation failed");
    }
    if !route.__test_has_netlink_admin() {
        return TestResult::Fail("route socket did not retain delegated admin");
    }
    if crate::delegate_stack_admin_to_generic_socket(route_fd, &reply)
        != Err(crate::socket::SockError::InvalidArg)
        || crate::delegate_stack_admin_to_route_socket(generic_fd, &reply)
            != Err(crate::socket::SockError::InvalidArg)
        || crate::delegate_stack_admin_to_generic_socket(inet_fd, &reply)
            != Err(crate::socket::SockError::InvalidArg)
    {
        return TestResult::Fail("launcher bridge accepted the wrong socket protocol");
    }
    if crate::delegate_stack_admin_to_generic_socket(generic_fd, &reply).is_err()
        || !generic.__test_has_netlink_admin()
    {
        return TestResult::Fail("generic socket did not retain delegated admin");
    }
    if crate::delegate_stack_admin_to_route_socket(route_fd + 1000, &reply)
        != Err(crate::socket::SockError::BadFd)
    {
        return TestResult::Fail("delegation escaped the current task fd table");
    }
    if crate::delegate_stack_admin_to_generic_socket(generic_fd + 1000, &reply)
        != Err(crate::socket::SockError::BadFd)
    {
        return TestResult::Fail("generic delegation escaped the current task fd table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/netlink",
    smoke_stack_admin_delegates_only_to_current_netlink_socket
);

// ── AF_INET datagram sockets on the wire ─────────────────────────────────────

/// Frames the synthetic NIC captured, for the wire-UDP test below.
static UDP_TX_CAPTURE: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<alloc::vec::Vec<u8>>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

fn udp_capture_send(frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    UDP_TX_CAPTURE.lock().push(frame.to_vec());
    Ok(())
}

/// A userspace AF_INET datagram socket reaches the NETWORK, in both
/// directions.
///
/// `sendto` to an address no local socket owns used to look the peer up in
/// an in-kernel table and, finding nothing, `return SocketOpResult::Ok(len)`
/// — reporting every byte as written while the datagram went nowhere. TCP
/// has had a wired path (`SocketState::InetWired` into `tcp_stack`) all
/// along; UDP had no counterpart, so a userspace program could not send or
/// receive a datagram off-box at all.
fn smoke_socket_inet_dgram_reaches_the_wire() -> TestResult {
    const IFACE: &str = "udptest0";
    const LOCAL: [u8; 4] = [10, 7, 0, 2];
    const PEER: [u8; 4] = [10, 7, 0, 9];
    const LOCAL_PORT: u16 = 4242;
    const PEER_PORT: u16 = 5353;

    narf_net::iface::register(IFACE, [0x02, 0, 0, 0, 0, 0x07], udp_capture_send);
    narf_net::iface::set_default_ipv4(LOCAL, LOCAL);
    narf_net::iface::add_addr(IFACE, LOCAL, 24);
    // Seed ARP: the send path resolves without blocking, and an unresolved
    // neighbour would be dropped rather than queued.
    narf_net::arp_cache::insert(IFACE, PEER, [0x02, 0, 0, 0, 0, 0x09]);
    narf_net::tcp_stack::__arp_insert_legacy(PEER, [0x02, 0, 0, 0, 0, 0x09]);
    UDP_TX_CAPTURE.lock().clear();

    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let mut bind_addr: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    bind_addr.extend_from_slice(&LOCAL_PORT.to_be_bytes());
    bind_addr.extend_from_slice(&[0, 0, 0, 0]); // INADDR_ANY
    bind_addr.extend_from_slice(&[0; 8]); // sin_zero: a full sockaddr_in
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Bind {
            addr: crate::socket::SockAddr {
                family: crate::socket::AF_INET,
                body: bind_addr,
            },
        }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind failed");
    }

    // ── TX: a datagram for a remote peer must leave on the wire ──
    let mut to: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    to.extend_from_slice(&PEER_PORT.to_be_bytes());
    to.extend_from_slice(&PEER);
    to.extend_from_slice(&[0; 8]);
    let r = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: b"ping",
        flags: 0,
        addr: Some(crate::socket::SockAddr {
            family: crate::socket::AF_INET,
            body: to,
        }),
    });
    if !matches!(r, crate::socket::SocketOpResult::Ok(_)) {
        return TestResult::Fail("sendto to a remote peer failed");
    }
    let frames = UDP_TX_CAPTURE.lock().clone();
    if frames.is_empty() {
        return TestResult::Fail("sendto to a remote peer emitted no frame — silently dropped");
    }
    // Ethernet(14) + IPv4(20) + UDP(8); check the ports and payload landed.
    let f = &frames[0];
    if f.len() < 14 + 20 + 8 + 4 {
        return TestResult::Fail("captured frame is too short to be the datagram");
    }
    let udp = &f[34..];
    if u16::from_be_bytes([udp[0], udp[1]]) != LOCAL_PORT {
        return TestResult::Fail("datagram carries the wrong source port");
    }
    if u16::from_be_bytes([udp[2], udp[3]]) != PEER_PORT {
        return TestResult::Fail("datagram carries the wrong destination port");
    }
    if &udp[8..12] != b"ping" {
        return TestResult::Fail("datagram carries the wrong payload");
    }

    // ── RX: a datagram from the wire must reach the socket ──
    if !crate::socket::deliver_wire_datagram(
        sock.net_ns_id(),
        &PEER,
        PEER_PORT,
        &LOCAL,
        LOCAL_PORT,
        b"pong",
        0, // arrival interface unknown: matches any binding
        narf_net::udp_sock::RxIpMeta::default(),
    ) {
        return TestResult::Fail("a wire datagram was not delivered to the bound socket");
    }
    let mut out = [0u8; 32];
    match sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received { n, .. } if &out[..n] == b"pong" => {}
        _ => return TestResult::Fail("recv did not return the wire datagram"),
    }

    // A datagram for a port nobody bound is refused, so the net layer can
    // fall through to its own handling rather than silently swallowing it.
    if crate::socket::deliver_wire_datagram(
        sock.net_ns_id(),
        &PEER,
        PEER_PORT,
        &LOCAL,
        LOCAL_PORT + 1,
        b"nobody",
        0,
        narf_net::udp_sock::RxIpMeta::default(),
    ) {
        return TestResult::Fail("an unbound port must not accept a wire datagram");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_inet_dgram_reaches_the_wire);

fn udp_bound_source_wire(mapped: bool) -> TestResult {
    use crate::socket::{SocketFile, SocketOp, SocketOpResult, AF_INET, AF_INET6, SOCK_DGRAM};
    const IFACE: &str = "udp-source-test0";
    const PRIMARY: [u8; 4] = [198, 18, 197, 2];
    const BOUND: [u8; 4] = [198, 18, 197, 3];
    const PEER: [u8; 4] = [198, 18, 197, 9];
    let address = |ip: [u8; 4], port| {
        if mapped {
            let mut v6 = [0; 16];
            v6[10..12].copy_from_slice(&[0xff, 0xff]);
            v6[12..].copy_from_slice(&ip);
            crate::socket::make_sockaddr_in6(v6, port)
        } else {
            build_sockaddr_in(u32::from_be_bytes(ip), port)
        }
    };
    narf_net::iface::register(IFACE, [2, 0, 0, 0, 0xc5, 2], udp_capture_send);
    narf_net::iface::add_addr(IFACE, PRIMARY, 24);
    narf_net::iface::add_addr(IFACE, BOUND, 24);
    narf_net::iface::set_link_state(IFACE, true);
    narf_net::arp_cache::insert(IFACE, PEER, [2, 0, 0, 0, 0xc5, 9]);
    narf_net::tcp_stack::__arp_insert_legacy(PEER, [2, 0, 0, 0, 0xc5, 9]);
    UDP_TX_CAPTURE.lock().clear();
    let sock = SocketFile::new(if mapped { AF_INET6 } else { AF_INET }, SOCK_DGRAM);
    let result = (|| -> Result<(), &'static str> {
        if !matches!(
            sock.dispatch_op(SocketOp::Bind {
                addr: address(BOUND, 56767)
            }),
            SocketOpResult::Ok(0)
        ) {
            return Err("binding UDP to a local secondary address failed");
        }
        if !matches!(
            sock.dispatch_op(SocketOp::Send {
                buf: b"bound-source",
                flags: 0,
                addr: Some(address(PEER, 56768)),
            }),
            SocketOpResult::Ok(12)
        ) {
            return Err("bound-source UDP send failed");
        }
        let frames = UDP_TX_CAPTURE.lock();
        let frame = frames.last().ok_or("bound-source UDP emitted no frame")?;
        if frame.len() < 42 || frame[26..30] != BOUND || frame[30..34] != PEER {
            return Err("wire IPv4 source ignored bind and used the interface primary address");
        }
        Ok(())
    })();
    sock.unregister();
    narf_net::iface::unregister(IFACE);
    UDP_TX_CAPTURE.lock().clear();
    match result {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}

fn smoke_socket_udp_bound_source_reaches_wire() -> TestResult {
    udp_bound_source_wire(false)
}
kernel_test_in!(
    "userspace/socket_source",
    smoke_socket_udp_bound_source_reaches_wire
);

fn smoke_socket_udp_mapped_bound_source_reaches_wire() -> TestResult {
    udp_bound_source_wire(true)
}
kernel_test_in!(
    "userspace/socket_source",
    smoke_socket_udp_mapped_bound_source_reaches_wire
);

/// SO_BINDTODEVICE is enforced on RECEIVE, not just stored.
///
/// `compute_score` (`net/ipv4/udp.c:400`) drops a socket from consideration
/// entirely when it is bound to a different interface:
///
/// ```c
/// dev_match = udp_sk_bound_dev_eq(net, sk->sk_bound_dev_if, dif, sdif);
/// if (!dev_match)
///         return -1;
/// ```
///
/// Until the arrival interface was plumbed through the RX path there was
/// nothing to compare against, so a socket pinned to one NIC still received
/// traffic that came in on another — the isolation the option exists to
/// provide, silently absent.
fn smoke_socket_bindtodevice_filters_receive() -> TestResult {
    const IFACE_A: &str = "btdtest0";
    const IFACE_B: &str = "btdtest1";
    const LOCAL: [u8; 4] = [10, 8, 0, 2];
    const PEER: [u8; 4] = [10, 8, 0, 9];
    const PORT: u16 = 4343;

    narf_net::iface::register(IFACE_A, [0x02, 0, 0, 0, 1, 0], |_, _| Ok(()));
    narf_net::iface::register(IFACE_B, [0x02, 0, 0, 0, 1, 1], |_, _| Ok(()));
    let (Some(idx_a), Some(idx_b)) = (
        narf_net::iface::ifindex_of(IFACE_A),
        narf_net::iface::ifindex_of(IFACE_B),
    ) else {
        return TestResult::Skip("test interfaces did not register");
    };
    if idx_a == idx_b {
        return TestResult::Fail("the two test interfaces must have distinct indices");
    }

    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let mut bind_addr: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    bind_addr.extend_from_slice(&PORT.to_be_bytes());
    bind_addr.extend_from_slice(&[0, 0, 0, 0]);
    bind_addr.extend_from_slice(&[0; 8]);
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Bind {
            addr: crate::socket::SockAddr {
                family: crate::socket::AF_INET,
                body: bind_addr,
            },
        }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind failed");
    }
    // Pin the socket to interface A.
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
            level: crate::socket::SOL_SOCKET,
            name: crate::socket::SO_BINDTODEVICE,
            value: IFACE_A.as_bytes(),
        }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("SO_BINDTODEVICE to a live interface should succeed");
    }

    let ns = sock.net_ns_id();
    // Arriving on the WRONG interface: refused.
    if crate::socket::deliver_wire_datagram(
        ns,
        &PEER,
        9,
        &LOCAL,
        PORT,
        b"wrong",
        idx_b,
        narf_net::udp_sock::RxIpMeta::default(),
    ) {
        return TestResult::Fail("a datagram from another interface must not be delivered");
    }
    // Arriving on the RIGHT interface: delivered.
    if !crate::socket::deliver_wire_datagram(
        ns,
        &PEER,
        9,
        &LOCAL,
        PORT,
        b"right",
        idx_a,
        narf_net::udp_sock::RxIpMeta::default(),
    ) {
        return TestResult::Fail("a datagram from the bound interface must be delivered");
    }
    // An unknown arrival interface cannot contradict the binding.
    if !crate::socket::deliver_wire_datagram(
        ns,
        &PEER,
        9,
        &LOCAL,
        PORT,
        b"any",
        0,
        narf_net::udp_sock::RxIpMeta::default(),
    ) {
        return TestResult::Fail("an unknown arrival interface must still be delivered");
    }

    // Only the accepted datagrams are queued, in order.
    let mut out = [0u8; 32];
    for expect in [b"right".as_slice(), b"any".as_slice()] {
        match sock.dispatch_op(crate::socket::SocketOp::Recv {
            buf: &mut out,
            flags: 0,
        }) {
            crate::socket::SocketOpResult::Received { n, .. } if &out[..n] == expect => {}
            _ => return TestResult::Fail("queued datagrams do not match what was accepted"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_bindtodevice_filters_receive);

/// setsockopt of a read-only SOL_SOCKET option is ENOPROTOOPT, not EINVAL:
/// Linux `sk_setsockopt` (net/core/sock.c) — `case SO_TYPE: case
/// SO_PROTOCOL: case SO_DOMAIN: case SO_ERROR: return -ENOPROTOOPT;`.
fn smoke_socket_setsockopt_readonly_is_enoprotoopt() -> TestResult {
    use crate::socket::{SocketOp, SocketOpResult, SO_DOMAIN, SO_ERROR, SO_PROTOCOL, SO_TYPE};
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let one = 1u32.to_ne_bytes();
    for name in [SO_TYPE, SO_PROTOCOL, SO_DOMAIN, SO_ERROR] {
        let r = sock.dispatch_op(SocketOp::SetSockOpt {
            level: crate::socket::SOL_SOCKET,
            name,
            value: &one,
        });
        match r {
            SocketOpResult::Err(e) if e.errno() == crate::errno::ENOPROTOOPT as i32 => {}
            _ => return TestResult::Fail("setsockopt of a read-only option must be ENOPROTOOPT"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_setsockopt_readonly_is_enoprotoopt);

/// Kernel-TCP errnos cross into the socket layer unchanged, except that
/// EAGAIN / EPIPE / ENOTCONN fold into the variants callers act on (park,
/// SIGPIPE) — whose errno is still the same Linux value.
fn smoke_socket_stack_errno_passthrough() -> TestResult {
    use crate::errno;
    use crate::socket::SockError;
    for e in [
        errno::EAGAIN,
        errno::EPIPE,
        errno::ENOTCONN,
        errno::ECONNRESET,
        errno::ECONNREFUSED,
        errno::ETIMEDOUT,
        errno::EHOSTUNREACH,
        errno::ENETUNREACH,
        errno::EHOSTDOWN,
        errno::ENONET,
        errno::EPROTO,
    ] {
        if SockError::from_stack(e as i32).errno() != e as i32 {
            return TestResult::Fail("kernel-TCP errno changed crossing into SockError");
        }
    }
    if SockError::from_stack(errno::EAGAIN as i32) != SockError::WouldBlock
        || SockError::from_stack(errno::EPIPE as i32) != SockError::Pipe
    {
        return TestResult::Fail("EAGAIN / EPIPE must map to WouldBlock / Pipe");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_socket_stack_errno_passthrough);

// ── AF_BLUETOOTH L2CAP/RFCOMM channel sockets (issue #814) ──────────────
//
// Exercise the `SocketFile::dispatch_op` surface against a scripted
// fake bridge installed into `narf_filesystem::bluetooth`: the fake
// plays the pump's role (PSM registry, pending channels, staged
// inbound data, send recording) so the tests prove the socket state
// machine and the broker contract. The real pump is covered by the
// pump fixture tests in `narf-bluetooth` and the frame e2e fixture;
// this layer never touches a real controller.

/// Scripted fake for the L2CAP/RFCOMM bridge + HCI ioctl providers.
struct FakeBt {
    /// The fixture controller's bdaddr (hci_dev_info bytes 10..16).
    dev_bdaddr: [u8; 6],
    /// Registered listening PSMs: (dev, psm, le).
    registered: alloc::vec::Vec<(u16, u16, bool)>,
    /// Peer-opened channels awaiting accept: (dev, psm, le, channel).
    pending: alloc::vec::Vec<(u16, u16, bool, narf_filesystem::bluetooth::BtPendingChannel)>,
    /// Peer-opened RFCOMM DLCs awaiting accept: (dev, channel, dlc).
    pending_rfcomm: alloc::vec::Vec<(u16, u8, narf_filesystem::bluetooth::BtPendingRfcomm)>,
    /// Claimed L2CAP channels: (handle, local cid).
    open: alloc::vec::Vec<(u16, u16)>,
    /// Claimed RFCOMM DLCs: (handle, local cid, dlci).
    open_rfcomm: alloc::vec::Vec<(u16, u16, u8)>,
    /// Staged inbound L2CAP SDUs: (handle, local cid, sdu).
    rx: alloc::vec::Vec<(u16, u16, alloc::vec::Vec<u8>)>,
    /// Staged inbound RFCOMM payloads: (handle, local cid, dlci, data).
    rx_rfcomm: alloc::vec::Vec<(u16, u16, u8, alloc::vec::Vec<u8>)>,
    /// Recorded L2CAP sends: (handle, local cid, payload).
    sent: alloc::vec::Vec<(u16, u16, alloc::vec::Vec<u8>)>,
    /// Recorded RFCOMM sends: (handle, local cid, dlci, payload).
    sent_rfcomm: alloc::vec::Vec<(u16, u16, u8, alloc::vec::Vec<u8>)>,
    /// Recorded L2CAP disconnects: (handle, local cid).
    disconnected: alloc::vec::Vec<(u16, u16)>,
    /// Recorded RFCOMM closes: (handle, local cid, dlci).
    closed_rfcomm: alloc::vec::Vec<(u16, u16, u8)>,
    /// Scripted outbound-connect outcomes, in call order:
    /// (dev, peer, psm, le, rfcomm, status). Each `bt_connect`
    /// call pops the first matching entry; no entry → Pending.
    connect_script: alloc::vec::Vec<(
        u16,
        [u8; 7],
        u16,
        bool,
        bool,
        narf_filesystem::bluetooth::BtConnectStatus,
    )>,
    /// Recorded outbound-connect calls: (dev, peer, psm, le, rfcomm).
    connect_calls: alloc::vec::Vec<(u16, [u8; 7], u16, bool, bool)>,
    /// Recorded outbound-connect cancels: (dev, peer, psm, le, rfcomm).
    connect_cancels: alloc::vec::Vec<(u16, [u8; 7], u16, bool, bool)>,
    /// Open SCO links: (handle, peer, mtu, dev_class).
    sco_links: alloc::vec::Vec<(u16, [u8; 6], u16, [u8; 3])>,
    /// SCO setups in flight: (dev, peer).
    sco_pending: alloc::vec::Vec<(u16, [u8; 6])>,
    /// Staged inbound SCO frames: (handle, payload).
    rx_sco: alloc::vec::Vec<(u16, alloc::vec::Vec<u8>)>,
    /// Recorded SCO sends: (handle, payload).
    sent_sco: alloc::vec::Vec<(u16, alloc::vec::Vec<u8>)>,
    /// Recorded SCO disconnects: handle.
    disconnected_sco: alloc::vec::Vec<u16>,
    /// When set, SCO connect reports NoPump (no transport).
    sco_no_pump: bool,
    /// SCO MTU the fake controller reports (64, like the pump fixture).
    sco_mtu: u16,
}

impl FakeBt {
    const fn new() -> Self {
        Self {
            dev_bdaddr: [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
            registered: alloc::vec::Vec::new(),
            pending: alloc::vec::Vec::new(),
            pending_rfcomm: alloc::vec::Vec::new(),
            open: alloc::vec::Vec::new(),
            open_rfcomm: alloc::vec::Vec::new(),
            rx: alloc::vec::Vec::new(),
            rx_rfcomm: alloc::vec::Vec::new(),
            sent: alloc::vec::Vec::new(),
            sent_rfcomm: alloc::vec::Vec::new(),
            disconnected: alloc::vec::Vec::new(),
            closed_rfcomm: alloc::vec::Vec::new(),
            connect_script: alloc::vec::Vec::new(),
            connect_calls: alloc::vec::Vec::new(),
            connect_cancels: alloc::vec::Vec::new(),
            sco_links: alloc::vec::Vec::new(),
            sco_pending: alloc::vec::Vec::new(),
            rx_sco: alloc::vec::Vec::new(),
            sent_sco: alloc::vec::Vec::new(),
            disconnected_sco: alloc::vec::Vec::new(),
            sco_no_pump: false,
            sco_mtu: 64,
        }
    }
}

static FAKE_BT: IrqSafeSpinLock<FakeBt> = IrqSafeSpinLock::new(FakeBt::new());

fn fake_bt_hci_dev_count() -> usize {
    1
}

fn fake_bt_hci_dev_info(dev: u16) -> Option<alloc::vec::Vec<u8>> {
    if dev != 0 {
        return None;
    }
    let mut info = alloc::vec![0u8; 24];
    info[0..2].copy_from_slice(&0u16.to_le_bytes());
    info[2..10].copy_from_slice(b"hci0\0\0\0\0");
    info[10..16].copy_from_slice(&FAKE_BT.lock().dev_bdaddr);
    info[16..20].copy_from_slice(&1u32.to_le_bytes());
    Some(info)
}

fn fake_bt_hci_dev_power(_dev: u16, _on: bool) -> bool {
    true
}

fn fake_bt_register_psm(
    dev: u16,
    psm: u16,
    le: bool,
) -> narf_filesystem::bluetooth::BtRegisterStatus {
    use narf_filesystem::bluetooth::BtRegisterStatus;
    if psm == 0x0001 || psm == 0x0003 {
        return BtRegisterStatus::InUse;
    }
    let mut fake = FAKE_BT.lock();
    if fake
        .registered
        .iter()
        .any(|(d, p, l)| *d == dev && *p == psm && *l == le)
    {
        return BtRegisterStatus::InUse;
    }
    fake.registered.push((dev, psm, le));
    BtRegisterStatus::Registered
}

fn fake_bt_unregister_psm(dev: u16, psm: u16, le: bool) {
    FAKE_BT
        .lock()
        .registered
        .retain(|(d, p, l)| !(*d == dev && *p == psm && *l == le));
}

fn fake_bt_take_pending_channel(
    dev: u16,
    psm: u16,
    le: bool,
) -> Option<narf_filesystem::bluetooth::BtPendingChannel> {
    let mut fake = FAKE_BT.lock();
    let idx = fake
        .pending
        .iter()
        .position(|(d, p, l, _)| *d == dev && *p == psm && *l == le)?;
    let (_, _, _, ch) = fake.pending.remove(idx);
    fake.open.push((ch.0, ch.1));
    Some(ch)
}

fn fake_bt_pending_channel(dev: u16, psm: u16, le: bool) -> bool {
    FAKE_BT
        .lock()
        .pending
        .iter()
        .any(|(d, p, l, _)| *d == dev && *p == psm && *l == le)
}

fn fake_bt_send_channel(
    _dev: u16,
    handle: u16,
    cid: u16,
    payload: &[u8],
) -> Result<usize, narf_filesystem::bluetooth::BtSendError> {
    use narf_filesystem::bluetooth::BtSendError;
    let mut fake = FAKE_BT.lock();
    if !fake.open.iter().any(|(h, c)| *h == handle && *c == cid) {
        return Err(BtSendError::NoChannel);
    }
    fake.sent.push((handle, cid, payload.to_vec()));
    Ok(payload.len())
}

fn fake_bt_drain_channel(
    _dev: u16,
    handle: u16,
    cid: u16,
) -> Option<alloc::vec::Vec<alloc::vec::Vec<u8>>> {
    let mut fake = FAKE_BT.lock();
    if !fake.open.iter().any(|(h, c)| *h == handle && *c == cid) {
        return None;
    }
    let mut out = alloc::vec::Vec::new();
    fake.rx.retain(|(h, c, p)| {
        if *h == handle && *c == cid {
            out.push(p.clone());
            false
        } else {
            true
        }
    });
    Some(out)
}

fn fake_bt_channel_rx_pending(_dev: u16, handle: u16, cid: u16) -> bool {
    let fake = FAKE_BT.lock();
    fake.open.iter().any(|(h, c)| *h == handle && *c == cid)
        && fake.rx.iter().any(|(h, c, _)| *h == handle && *c == cid)
}

fn fake_bt_disconnect_channel(_dev: u16, handle: u16, cid: u16) -> bool {
    let mut fake = FAKE_BT.lock();
    let was_open = fake.open.iter().any(|(h, c)| *h == handle && *c == cid);
    fake.open.retain(|(h, c)| !(*h == handle && *c == cid));
    fake.disconnected.push((handle, cid));
    was_open
}

fn fake_bt_take_pending_rfcomm(
    dev: u16,
    channel: u8,
) -> Option<narf_filesystem::bluetooth::BtPendingRfcomm> {
    let mut fake = FAKE_BT.lock();
    let idx = fake
        .pending_rfcomm
        .iter()
        .position(|(d, c, _)| *d == dev && *c == channel)?;
    let (_, _, dlc) = fake.pending_rfcomm.remove(idx);
    fake.open_rfcomm.push((dlc.0, dlc.1, dlc.3));
    Some(dlc)
}

fn fake_bt_pending_rfcomm(dev: u16, channel: u8) -> bool {
    FAKE_BT
        .lock()
        .pending_rfcomm
        .iter()
        .any(|(d, c, _)| *d == dev && *c == channel)
}

fn fake_bt_send_rfcomm(
    _dev: u16,
    handle: u16,
    cid: u16,
    dlci: u8,
    payload: &[u8],
) -> Result<usize, narf_filesystem::bluetooth::BtSendError> {
    use narf_filesystem::bluetooth::BtSendError;
    let mut fake = FAKE_BT.lock();
    if !fake
        .open_rfcomm
        .iter()
        .any(|(h, c, d)| *h == handle && *c == cid && *d == dlci)
    {
        return Err(BtSendError::NoChannel);
    }
    fake.sent_rfcomm.push((handle, cid, dlci, payload.to_vec()));
    Ok(payload.len())
}

fn fake_bt_drain_rfcomm(
    _dev: u16,
    handle: u16,
    cid: u16,
    dlci: u8,
) -> Option<alloc::vec::Vec<alloc::vec::Vec<u8>>> {
    let mut fake = FAKE_BT.lock();
    if !fake
        .open_rfcomm
        .iter()
        .any(|(h, c, d)| *h == handle && *c == cid && *d == dlci)
    {
        return None;
    }
    let mut out = alloc::vec::Vec::new();
    fake.rx_rfcomm.retain(|(h, c, d, p)| {
        if *h == handle && *c == cid && *d == dlci {
            out.push(p.clone());
            false
        } else {
            true
        }
    });
    Some(out)
}

fn fake_bt_rfcomm_rx_pending(_dev: u16, handle: u16, cid: u16, dlci: u8) -> bool {
    let fake = FAKE_BT.lock();
    fake.open_rfcomm
        .iter()
        .any(|(h, c, d)| *h == handle && *c == cid && *d == dlci)
        && fake
            .rx_rfcomm
            .iter()
            .any(|(h, c, d, _)| *h == handle && *c == cid && *d == dlci)
}

fn fake_bt_close_rfcomm(_dev: u16, handle: u16, cid: u16, dlci: u8) -> bool {
    let mut fake = FAKE_BT.lock();
    let was_open = fake
        .open_rfcomm
        .iter()
        .any(|(h, c, d)| *h == handle && *c == cid && *d == dlci);
    fake.open_rfcomm
        .retain(|(h, c, d)| !(*h == handle && *c == cid && *d == dlci));
    fake.closed_rfcomm.push((handle, cid, dlci));
    was_open
}

/// Outbound-connect fake (#1532): pop the first scripted outcome
/// for this open (default Pending), recording the call. An Open
/// outcome claims the channel in the fake, so send/recv work
/// after connect().
fn fake_bt_connect(
    dev: u16,
    peer: [u8; 7],
    psm: u16,
    le: bool,
    rfcomm: bool,
) -> narf_filesystem::bluetooth::BtConnectStatus {
    use narf_filesystem::bluetooth::BtConnectStatus;
    let mut fake = FAKE_BT.lock();
    fake.connect_calls.push((dev, peer, psm, le, rfcomm));
    let idx = fake.connect_script.iter().position(|(d, p, s, l, r, _)| {
        *d == dev && *p == peer && *s == psm && *l == le && *r == rfcomm
    });
    match idx {
        Some(i) => {
            let (_, _, _, _, _, st) = fake.connect_script.remove(i);
            match st {
                BtConnectStatus::Open((h, local, _, _)) => {
                    fake.open.push((h, local));
                }
                BtConnectStatus::OpenRfcomm((h, local, _, dlci, _)) => {
                    fake.open_rfcomm.push((h, local, dlci));
                }
                _ => {}
            }
            st
        }
        None => BtConnectStatus::Pending,
    }
}

/// Whether a scripted Open outcome awaits for this open
/// (non-consuming peek, mirroring the pump's `connect_ready`).
fn fake_bt_connect_ready(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool {
    use narf_filesystem::bluetooth::BtConnectStatus;
    FAKE_BT
        .lock()
        .connect_script
        .iter()
        .any(|(d, p, s, l, r, st)| {
            *d == dev
                && *p == peer
                && *s == psm
                && *l == le
                && *r == rfcomm
                && matches!(
                    st,
                    BtConnectStatus::Open(_) | BtConnectStatus::OpenRfcomm(_)
                )
        })
}

/// Cancel a scripted outbound open (#1532): drop its scripted
/// outcomes and record the cancel. `true` when a scripted outcome
/// was dropped, `false` when nothing was in flight.
fn fake_bt_cancel_connect(dev: u16, peer: [u8; 7], psm: u16, le: bool, rfcomm: bool) -> bool {
    let mut fake = FAKE_BT.lock();
    fake.connect_cancels.push((dev, peer, psm, le, rfcomm));
    let before = fake.connect_script.len();
    fake.connect_script.retain(|(d, p, s, l, r, _)| {
        !(*d == dev && *p == peer && *s == psm && *l == le && *r == rfcomm)
    });
    fake.connect_script.len() != before
}

/// SCO connect: NoPump when the fixture says so, AlreadyConnected
/// for a live link, Pending (and a recorded in-flight setup) else.
/// Re-entering while the setup is in flight stays Pending.
fn fake_bt_sco_connect(
    dev: u16,
    peer: [u8; 6],
    _voice_setting: u16,
) -> narf_filesystem::bluetooth::BtScoConnectResult {
    use narf_filesystem::bluetooth::BtScoConnectResult;
    let mut fake = FAKE_BT.lock();
    if fake.sco_no_pump {
        return BtScoConnectResult::NoPump;
    }
    if fake.sco_links.iter().any(|(_, p, _, _)| *p == peer) {
        return BtScoConnectResult::AlreadyConnected;
    }
    if fake
        .sco_pending
        .iter()
        .any(|(d, p)| *d == dev && *p == peer)
    {
        return BtScoConnectResult::Pending;
    }
    fake.sco_pending.push((dev, peer));
    BtScoConnectResult::Pending
}

/// SCO connect status: the first poll after the setup completes
/// the link (handle 0x0043, the fixture SCO MTU, the peer's class
/// from its inquiry record); a later poll re-reports the live
/// link; no pending setup and no link is Aborted.
fn fake_bt_sco_connect_status(
    dev: u16,
    peer: [u8; 6],
) -> narf_filesystem::bluetooth::BtScoConnectResult {
    use narf_filesystem::bluetooth::BtScoConnectResult;
    let mut fake = FAKE_BT.lock();
    if fake.sco_no_pump {
        return BtScoConnectResult::NoPump;
    }
    if let Some((handle, mtu, dev_class)) = fake
        .sco_links
        .iter()
        .find(|(_, p, _, _)| *p == peer)
        .map(|(h, _, m, c)| (*h, *m, *c))
    {
        return BtScoConnectResult::Connected {
            handle,
            mtu,
            dev_class,
        };
    }
    if fake
        .sco_pending
        .iter()
        .any(|(d, p)| *d == dev && *p == peer)
    {
        fake.sco_pending.retain(|(d, p)| !(*d == dev && *p == peer));
        let mtu = fake.sco_mtu;
        fake.sco_links.push((0x0043, peer, mtu, [0x10, 0x01, 0x00]));
        return BtScoConnectResult::Connected {
            handle: 0x0043,
            mtu,
            dev_class: [0x10, 0x01, 0x00],
        };
    }
    BtScoConnectResult::Aborted
}

fn fake_bt_send_sco(
    _dev: u16,
    handle: u16,
    payload: &[u8],
) -> Result<usize, narf_filesystem::bluetooth::BtSendError> {
    use narf_filesystem::bluetooth::BtSendError;
    let mut fake = FAKE_BT.lock();
    let Some((_, _, mtu, _)) = fake
        .sco_links
        .iter()
        .find(|(h, _, _, _)| *h == handle)
        .copied()
    else {
        return Err(BtSendError::NoChannel);
    };
    if payload.len() > mtu as usize {
        return Err(BtSendError::TooBig);
    }
    fake.sent_sco.push((handle, payload.to_vec()));
    Ok(payload.len())
}

fn fake_bt_drain_sco(_dev: u16, handle: u16) -> Option<alloc::vec::Vec<alloc::vec::Vec<u8>>> {
    let mut fake = FAKE_BT.lock();
    if !fake.sco_links.iter().any(|(h, _, _, _)| *h == handle) {
        return None;
    }
    let mut out = alloc::vec::Vec::new();
    fake.rx_sco.retain(|(h, p)| {
        if *h == handle {
            out.push(p.clone());
            false
        } else {
            true
        }
    });
    Some(out)
}

fn fake_bt_sco_rx_pending(_dev: u16, handle: u16) -> bool {
    let fake = FAKE_BT.lock();
    fake.sco_links.iter().any(|(h, _, _, _)| *h == handle)
        && fake.rx_sco.iter().any(|(h, _)| *h == handle)
}

fn fake_bt_disconnect_sco(_dev: u16, handle: u16) -> bool {
    let mut fake = FAKE_BT.lock();
    let was_open = fake.sco_links.iter().any(|(h, _, _, _)| *h == handle);
    fake.sco_links.retain(|(h, _, _, _)| *h != handle);
    if was_open {
        fake.disconnected_sco.push(handle);
    }
    was_open
}

fn fake_bt_sco_cancel_connect(_dev: u16, peer: [u8; 6]) {
    FAKE_BT.lock().sco_pending.retain(|(_, p)| *p != peer);
}

/// Reset the fake and install it as the bridge + HCI providers.
fn install_fake_bt_bridge() {
    *FAKE_BT.lock() = FakeBt::new();
    narf_filesystem::bluetooth::install_hci_ioctl_handlers(
        fake_bt_hci_dev_count,
        fake_bt_hci_dev_info,
        fake_bt_hci_dev_power,
    );
    narf_filesystem::bluetooth::install_bt_l2cap_handlers(
        fake_bt_register_psm,
        fake_bt_unregister_psm,
        fake_bt_take_pending_channel,
        fake_bt_pending_channel,
        fake_bt_send_channel,
        fake_bt_drain_channel,
        fake_bt_channel_rx_pending,
        fake_bt_disconnect_channel,
    );
    narf_filesystem::bluetooth::install_bt_rfcomm_handlers(
        fake_bt_take_pending_rfcomm,
        fake_bt_pending_rfcomm,
        fake_bt_send_rfcomm,
        fake_bt_drain_rfcomm,
        fake_bt_rfcomm_rx_pending,
        fake_bt_close_rfcomm,
    );
    narf_filesystem::bluetooth::install_bt_connect_handlers(
        fake_bt_connect,
        fake_bt_connect_ready,
        fake_bt_cancel_connect,
    );
    narf_filesystem::bluetooth::install_bt_sco_handlers(
        fake_bt_sco_connect,
        fake_bt_sco_connect_status,
        fake_bt_send_sco,
        fake_bt_drain_sco,
        fake_bt_sco_rx_pending,
        fake_bt_disconnect_sco,
        fake_bt_sco_cancel_connect,
    );
}

/// Script one outbound-connect outcome for the next matching
/// `connect()` call (#1532).
fn fake_bt_script_connect(
    dev: u16,
    peer: [u8; 7],
    psm: u16,
    le: bool,
    rfcomm: bool,
    status: narf_filesystem::bluetooth::BtConnectStatus,
) {
    FAKE_BT
        .lock()
        .connect_script
        .push((dev, peer, psm, le, rfcomm, status));
}

/// Script a peer-opened LE/BR-EDR channel for `psm` (peer bdaddr
/// B0:B1:B2:B3:B4:B5, address type 1 for LE).
fn fake_bt_script_channel(psm: u16, le: bool, handle: u16, local_cid: u16, peer_cid: u16) {
    FAKE_BT.lock().pending.push((
        0,
        psm,
        le,
        (
            handle,
            local_cid,
            peer_cid,
            [1, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
        ),
    ));
}

/// Script a peer-opened RFCOMM DLC for `channel` (DLCI `2*channel+1`).
fn fake_bt_script_rfcomm(channel: u8, handle: u16, local_cid: u16, peer_cid: u16, dlci: u8) {
    FAKE_BT.lock().pending_rfcomm.push((
        0,
        channel,
        (
            handle,
            local_cid,
            peer_cid,
            dlci,
            [0, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
        ),
    ));
}

fn fake_bt_stage_rx(handle: u16, cid: u16, payload: &[u8]) {
    FAKE_BT.lock().rx.push((handle, cid, payload.to_vec()));
}

fn fake_bt_stage_rfcomm_rx(handle: u16, cid: u16, dlci: u8, payload: &[u8]) {
    FAKE_BT
        .lock()
        .rx_rfcomm
        .push((handle, cid, dlci, payload.to_vec()));
}

fn fake_bt_stage_sco_rx(handle: u16, payload: &[u8]) {
    FAKE_BT.lock().rx_sco.push((handle, payload.to_vec()));
}

fn bt_l2cap_addr(psm: u16, bdaddr: [u8; 6], addr_type: u8) -> crate::socket::SockAddr {
    let mut body = alloc::vec![];
    body.extend_from_slice(&psm.to_le_bytes());
    body.extend_from_slice(&bdaddr);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.push(addr_type);
    crate::socket::SockAddr {
        family: crate::socket::AF_BLUETOOTH,
        body,
    }
}

fn bt_rfcomm_addr(bdaddr: [u8; 6], channel: u8) -> crate::socket::SockAddr {
    let mut body = alloc::vec![];
    body.extend_from_slice(&bdaddr);
    body.push(channel);
    crate::socket::SockAddr {
        family: crate::socket::AF_BLUETOOTH,
        body,
    }
}

/// SCO peer address: `sockaddr_sco` body is just the 6-byte bdaddr.
fn bt_sco_addr(bdaddr: [u8; 6]) -> crate::socket::SockAddr {
    crate::socket::SockAddr {
        family: crate::socket::AF_BLUETOOTH,
        body: bdaddr.to_vec(),
    }
}

/// L2CAP LE CoC: bind → listen → accept (EAGAIN, then a scripted
/// peer open) → getpeername → recv a staged SDU → send → shutdown
/// disconnects. The send/recv cross the broker into the fake.
fn smoke_bt_l2cap_listen_accept_send_recv() -> TestResult {
    install_fake_bt_bridge();
    let server =
        crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    let addr = bt_l2cap_addr(0x0080, [0; 6], 1);
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("L2CAP bind failed");
    }
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("L2CAP listen failed");
    }
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Accept),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock)
    ) {
        return TestResult::Fail("accept with no pending channel should be EAGAIN");
    }
    fake_bt_script_channel(0x0080, true, 0x0041, 0x0040, 0x0041);
    let child = match server.dispatch_op(crate::socket::SocketOp::Accept) {
        crate::socket::SocketOpResult::Accepted { socket, peer } => {
            let mut expected = alloc::vec![];
            expected.extend_from_slice(&0x0080u16.to_le_bytes());
            expected.extend_from_slice(&[0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5]);
            expected.extend_from_slice(&0x0041u16.to_le_bytes());
            expected.push(1);
            match peer {
                Some(crate::socket::SockAddr { family, body })
                    if family == crate::socket::AF_BLUETOOTH && body == expected => {}
                _ => return TestResult::Fail("accept peer sockaddr mismatch"),
            }
            socket
        }
        _ => return TestResult::Fail("accept did not return Accepted"),
    };
    match child.dispatch_op(crate::socket::SocketOp::GetPeerName) {
        crate::socket::SocketOpResult::Addr(addr) if addr.body.len() == 11 => {}
        _ => return TestResult::Fail("getpeername failed on accepted channel"),
    }
    fake_bt_stage_rx(0x0041, 0x0040, b"ping");
    let mut out = [0u8; 16];
    match child.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received { n, .. } if n == 4 && &out[..4] == b"ping" => {}
        _ => return TestResult::Fail("recv did not return the staged SDU"),
    }
    if !matches!(
        child.dispatch_op(crate::socket::SocketOp::Recv {
            buf: &mut out,
            flags: 0,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock)
    ) {
        return TestResult::Fail("recv on empty channel should be EAGAIN");
    }
    match child.dispatch_op(crate::socket::SocketOp::Send {
        buf: b"pong",
        flags: 0,
        addr: None,
    }) {
        crate::socket::SocketOpResult::Ok(4) => {}
        _ => return TestResult::Fail("send did not report 4 bytes"),
    }
    if FAKE_BT.lock().sent != alloc::vec![(0x0041u16, 0x0040u16, b"pong".to_vec())] {
        return TestResult::Fail("send did not reach the fake bridge");
    }
    if !matches!(
        child.dispatch_op(crate::socket::SocketOp::Shutdown { how: 0 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("shutdown failed");
    }
    if !FAKE_BT
        .lock()
        .disconnected
        .contains(&(0x0041u16, 0x0040u16))
    {
        return TestResult::Fail("shutdown did not disconnect the channel");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_l2cap_listen_accept_send_recv);

/// L2CAP listen/accept/send/recv/connect error paths: unbound
/// listen, unlistened accept, send/recv without a channel,
/// connect() (in flight — #1532, EINPROGRESS until the peer
/// answers), unroutable bdaddr, service PSM, and a second
/// listener on the same PSM.
fn smoke_bt_l2cap_listen_errors() -> TestResult {
    install_fake_bt_bridge();
    let s = crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::BadFdState)
    ) {
        return TestResult::Fail("listen without bind should be EBADFD");
    }
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Accept),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::BadFdState)
    ) {
        return TestResult::Fail("accept without listen should be EBADFD");
    }
    let mut out = [0u8; 8];
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Send {
            buf: b"x",
            flags: 0,
            addr: None,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NotConnected)
    ) {
        return TestResult::Fail("send without a channel should be ENOTCONN");
    }
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Recv {
            buf: &mut out,
            flags: 0,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NotConnected)
    ) {
        return TestResult::Fail("recv without a channel should be ENOTCONN");
    }
    let addr = bt_l2cap_addr(0x0080, [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5], 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail("connect should be EINPROGRESS while the open is in flight");
    }
    // Unroutable local bdaddr: no controller — ENODEV.
    let s2 =
        crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    let addr = bt_l2cap_addr(0x0080, [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5], 1);
    if !matches!(
        s2.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind for the unroutable-addr case failed");
    }
    if !matches!(
        s2.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NoDevice)
    ) {
        return TestResult::Fail("listen on an unroutable bdaddr should be ENODEV");
    }
    // Service PSM (SDP 0x0001): EADDRINUSE.
    let s3 =
        crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    let addr = bt_l2cap_addr(0x0001, [0; 6], 0);
    if !matches!(
        s3.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind for the service-PSM case failed");
    }
    if !matches!(
        s3.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::AddrInUse)
    ) {
        return TestResult::Fail("listen on SDP PSM 0x0001 should be EADDRINUSE");
    }
    // Second listener on the same PSM: EADDRINUSE.
    let s4 =
        crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    let addr = bt_l2cap_addr(0x0080, [0; 6], 1);
    if !matches!(
        s4.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind for the second-listener case failed");
    }
    if !matches!(
        s4.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("first listen on PSM 0x0080 failed");
    }
    let s5 =
        crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    let addr = bt_l2cap_addr(0x0080, [0; 6], 1);
    if !matches!(
        s5.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind for the second listener failed");
    }
    if !matches!(
        s5.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::AddrInUse)
    ) {
        return TestResult::Fail("second listen on the same PSM should be EADDRINUSE");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_l2cap_listen_errors);

/// RFCOMM: channel 0 invalid, channel 5 listen → second listener
/// EADDRINUSE → accept a scripted DLC → recv a staged payload →
/// send → shutdown closes the DLC. Dropping the listener frees
/// the channel for a fresh listener.
fn smoke_bt_rfcomm_listen_accept_send_recv() -> TestResult {
    install_fake_bt_bridge();
    let server = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_STREAM,
        crate::socket::BTPROTO_RFCOMM,
    );
    let addr = bt_rfcomm_addr([0; 6], 0);
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("RFCOMM bind failed");
    }
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("listen on server channel 0 should be EINVAL");
    }
    let addr = bt_rfcomm_addr([0; 6], 5);
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("RFCOMM bind on channel 5 failed");
    }
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("RFCOMM listen on channel 5 failed");
    }
    let server2 = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_STREAM,
        crate::socket::BTPROTO_RFCOMM,
    );
    let addr = bt_rfcomm_addr([0; 6], 5);
    if !matches!(
        server2.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("second RFCOMM bind failed");
    }
    if !matches!(
        server2.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::AddrInUse)
    ) {
        return TestResult::Fail("second RFCOMM listener on channel 5 should be EADDRINUSE");
    }
    if !matches!(
        server.dispatch_op(crate::socket::SocketOp::Accept),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock)
    ) {
        return TestResult::Fail("RFCOMM accept with no pending DLC should be EAGAIN");
    }
    fake_bt_script_rfcomm(5, 0x0041, 0x0040, 0x0041, 11);
    let child = match server.dispatch_op(crate::socket::SocketOp::Accept) {
        crate::socket::SocketOpResult::Accepted { socket, peer } => {
            let mut expected = alloc::vec![];
            expected.extend_from_slice(&[0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5]);
            expected.push(5);
            match peer {
                Some(crate::socket::SockAddr { family, body })
                    if family == crate::socket::AF_BLUETOOTH && body == expected => {}
                _ => return TestResult::Fail("RFCOMM accept peer sockaddr mismatch"),
            }
            socket
        }
        _ => return TestResult::Fail("RFCOMM accept did not return Accepted"),
    };
    fake_bt_stage_rfcomm_rx(0x0041, 0x0040, 11, b"hello");
    let mut out = [0u8; 16];
    match child.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received { n, .. } if n == 5 && &out[..5] == b"hello" => {}
        _ => return TestResult::Fail("RFCOMM recv did not return the staged payload"),
    }
    match child.dispatch_op(crate::socket::SocketOp::Send {
        buf: b"world",
        flags: 0,
        addr: None,
    }) {
        crate::socket::SocketOpResult::Ok(5) => {}
        _ => return TestResult::Fail("RFCOMM send did not report 5 bytes"),
    }
    if FAKE_BT.lock().sent_rfcomm != alloc::vec![(0x0041u16, 0x0040u16, 11u8, b"world".to_vec())] {
        return TestResult::Fail("RFCOMM send did not reach the fake bridge");
    }
    if !matches!(
        child.dispatch_op(crate::socket::SocketOp::Shutdown { how: 0 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("RFCOMM shutdown failed");
    }
    if !FAKE_BT
        .lock()
        .closed_rfcomm
        .contains(&(0x0041u16, 0x0040u16, 11u8))
    {
        return TestResult::Fail("RFCOMM shutdown did not close the DLC");
    }
    // Dropping the listener frees the channel: a fresh listener on
    // channel 5 succeeds (dead registry entries prune on lookup).
    drop(server);
    let server3 = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_STREAM,
        crate::socket::BTPROTO_RFCOMM,
    );
    let addr = bt_rfcomm_addr([0; 6], 5);
    if !matches!(
        server3.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("RFCOMM rebind after drop failed");
    }
    if !matches!(
        server3.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("RFCOMM listen after drop should succeed");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_rfcomm_listen_accept_send_recv);

/// Drop teardown: dropping an accepted L2CAP socket disconnects
/// its channel, and dropping the listener unregisters its PSM.
fn smoke_bt_l2cap_drop_teardown() -> TestResult {
    install_fake_bt_bridge();
    {
        let server =
            crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
        let addr = bt_l2cap_addr(0x0080, [0; 6], 1);
        if !matches!(
            server.dispatch_op(crate::socket::SocketOp::Bind { addr }),
            crate::socket::SocketOpResult::Ok(_)
        ) {
            return TestResult::Fail("bind for the drop case failed");
        }
        if !matches!(
            server.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
            crate::socket::SocketOpResult::Ok(_)
        ) {
            return TestResult::Fail("listen for the drop case failed");
        }
        if !FAKE_BT.lock().registered.contains(&(0u16, 0x0080u16, true)) {
            return TestResult::Fail("listen did not register the PSM");
        }
        fake_bt_script_channel(0x0080, true, 0x0041, 0x0040, 0x0041);
        let child = match server.dispatch_op(crate::socket::SocketOp::Accept) {
            crate::socket::SocketOpResult::Accepted { socket, .. } => socket,
            _ => return TestResult::Fail("accept for the drop case failed"),
        };
        drop(child);
        if !FAKE_BT
            .lock()
            .disconnected
            .contains(&(0x0041u16, 0x0040u16))
        {
            return TestResult::Fail("dropping the accepted socket did not disconnect");
        }
    }
    if FAKE_BT
        .lock()
        .registered
        .iter()
        .any(|(_, p, _)| *p == 0x0080)
    {
        return TestResult::Fail("dropping the listener did not unregister the PSM");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_l2cap_drop_teardown);

/// #1532: L2CAP LE CoC connect — first call EINPROGRESS, readiness
/// flips when the peer answers, the retry completes into the
/// channel, and send/recv/getpeername/shutdown work on it.
fn smoke_bt_l2cap_connect_pending_then_open() -> TestResult {
    install_fake_bt_bridge();
    let s = crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    let mut peer = [0u8; 7];
    peer[0] = 1;
    peer[1..7].copy_from_slice(&peer6);
    // First call: the fake has no scripted outcome → Pending.
    let addr = bt_l2cap_addr(0x0080, peer6, 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail("first connect should be EINPROGRESS");
    }
    // Not ready yet: no Open outcome scripted.
    if narf_filesystem::bluetooth::bt_connect_ready(0, peer, 0x0080, true, false) {
        return TestResult::Fail("pending open must not read ready");
    }
    // The peer answers: script the Open, readiness flips, the
    // retry completes into the channel.
    fake_bt_script_connect(
        0,
        peer,
        0x0080,
        true,
        false,
        narf_filesystem::bluetooth::BtConnectStatus::Open((0x0041, 0x0040, 0x0041, peer)),
    );
    if !narf_filesystem::bluetooth::bt_connect_ready(0, peer, 0x0080, true, false) {
        return TestResult::Fail("completed open should read ready");
    }
    let addr = bt_l2cap_addr(0x0080, peer6, 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("connect retry should complete the open");
    }
    // A connected socket refuses a second connect.
    let addr = bt_l2cap_addr(0x0080, peer6, 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::AlreadyConnected)
    ) {
        return TestResult::Fail("connect on a connected socket should be EISCONN");
    }
    // getpeername reports the peer.
    match s.dispatch_op(crate::socket::SocketOp::GetPeerName) {
        crate::socket::SocketOpResult::Addr(addr) => {
            let mut expected = alloc::vec![];
            expected.extend_from_slice(&0x0080u16.to_le_bytes());
            expected.extend_from_slice(&peer6);
            expected.extend_from_slice(&0x0041u16.to_le_bytes());
            expected.push(1);
            if addr.body != expected {
                return TestResult::Fail("getpeername body mismatch after connect");
            }
        }
        _ => return TestResult::Fail("getpeername failed on a connected socket"),
    }
    fake_bt_stage_rx(0x0041, 0x0040, b"hi");
    let mut out = [0u8; 16];
    match s.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received { n, .. } if n == 2 && &out[..2] == b"hi" => {}
        _ => return TestResult::Fail("recv did not return the staged SDU"),
    }
    match s.dispatch_op(crate::socket::SocketOp::Send {
        buf: b"yo",
        flags: 0,
        addr: None,
    }) {
        crate::socket::SocketOpResult::Ok(2) => {}
        _ => return TestResult::Fail("send did not report 2 bytes"),
    }
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Shutdown { how: 0 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("shutdown failed");
    }
    if !FAKE_BT
        .lock()
        .disconnected
        .contains(&(0x0041u16, 0x0040u16))
    {
        return TestResult::Fail("shutdown did not disconnect the channel");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_l2cap_connect_pending_then_open);

/// #1532: RFCOMM connect — first call EINPROGRESS, the retry
/// completes into the DLC, and send/recv/shutdown work on it.
fn smoke_bt_rfcomm_connect_open() -> TestResult {
    install_fake_bt_bridge();
    let s = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_STREAM,
        crate::socket::BTPROTO_RFCOMM,
    );
    let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    let mut peer = [0u8; 7];
    peer[0] = 0;
    peer[1..7].copy_from_slice(&peer6);
    let addr = bt_rfcomm_addr(peer6, 5);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail("first RFCOMM connect should be EINPROGRESS");
    }
    fake_bt_script_connect(
        0,
        peer,
        5,
        false,
        true,
        narf_filesystem::bluetooth::BtConnectStatus::OpenRfcomm((0x0041, 0x0040, 0x0041, 11, peer)),
    );
    let addr = bt_rfcomm_addr(peer6, 5);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("RFCOMM connect retry should complete the open");
    }
    // getpeername reports the peer + server channel 5.
    match s.dispatch_op(crate::socket::SocketOp::GetPeerName) {
        crate::socket::SocketOpResult::Addr(addr) => {
            let mut expected = alloc::vec![];
            expected.extend_from_slice(&peer6);
            expected.push(5);
            if addr.body != expected {
                return TestResult::Fail("RFCOMM getpeername body mismatch after connect");
            }
        }
        _ => return TestResult::Fail("RFCOMM getpeername failed on a connected socket"),
    }
    fake_bt_stage_rfcomm_rx(0x0041, 0x0040, 11, b"hello");
    let mut out = [0u8; 16];
    match s.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received { n, .. } if n == 5 && &out[..5] == b"hello" => {}
        _ => return TestResult::Fail("RFCOMM recv did not return the staged payload"),
    }
    match s.dispatch_op(crate::socket::SocketOp::Send {
        buf: b"world",
        flags: 0,
        addr: None,
    }) {
        crate::socket::SocketOpResult::Ok(5) => {}
        _ => return TestResult::Fail("RFCOMM send did not report 5 bytes"),
    }
    if FAKE_BT.lock().sent_rfcomm != alloc::vec![(0x0041u16, 0x0040u16, 11u8, b"world".to_vec())] {
        return TestResult::Fail("RFCOMM send did not reach the fake bridge");
    }
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Shutdown { how: 0 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("RFCOMM shutdown failed");
    }
    if !FAKE_BT
        .lock()
        .closed_rfcomm
        .contains(&(0x0041u16, 0x0040u16, 11u8))
    {
        return TestResult::Fail("RFCOMM shutdown did not close the DLC");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_rfcomm_connect_open);

/// #1532: connect failure mapping — a refused open is
/// ECONNREFUSED, a failed link or an undiscovered BR/EDR peer is
/// ENETUNREACH, and a failed open leaves no pending state behind
/// (a fresh connect starts cleanly).
fn smoke_bt_connect_refused_failed() -> TestResult {
    install_fake_bt_bridge();
    let s = crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    let mut peer = [0u8; 7];
    peer[0] = 1;
    peer[1..7].copy_from_slice(&peer6);
    // Refusal: script it, then the first call reports it.
    fake_bt_script_connect(
        0,
        peer,
        0x0080,
        true,
        false,
        narf_filesystem::bluetooth::BtConnectStatus::Refused(0x0002),
    );
    let addr = bt_l2cap_addr(0x0080, peer6, 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::ConnectionRefused)
    ) {
        return TestResult::Fail("refused connect should be ECONNREFUSED");
    }
    // Link failure: same socket, fresh open.
    fake_bt_script_connect(
        0,
        peer,
        0x0080,
        true,
        false,
        narf_filesystem::bluetooth::BtConnectStatus::Failed,
    );
    let addr = bt_l2cap_addr(0x0080, peer6, 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NetUnreach)
    ) {
        return TestResult::Fail("failed connect should be ENETUNREACH");
    }
    // Undiscovered BR/EDR peer: same mapping.
    fake_bt_script_connect(
        0,
        peer,
        0x1001,
        false,
        false,
        narf_filesystem::bluetooth::BtConnectStatus::UnknownPeer,
    );
    let addr = bt_l2cap_addr(0x1001, peer6, 0);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NetUnreach)
    ) {
        return TestResult::Fail("unknown-peer connect should be ENETUNREACH");
    }
    // A failed open leaves no pending state: a fresh connect
    // starts cleanly (EINPROGRESS, not a stale refusal).
    let addr = bt_l2cap_addr(0x0080, peer6, 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail("connect after a failure should start a fresh open");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_connect_refused_failed);

/// #1532: connect argument/state errors — bad PSM / address type /
/// server channel, a listening socket, a retry to a different peer
/// while one is in flight. SCO connect has a backend now
/// (#814); its error paths are covered by
/// smoke_bt_sco_connect_errors below.
fn smoke_bt_connect_errors() -> TestResult {
    install_fake_bt_bridge();
    let s = crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    // PSM 0 is not a connectable PSM.
    let addr = bt_l2cap_addr(0x0000, [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5], 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("connect to PSM 0 should be EINVAL");
    }
    // Address type 3 is not a real address type.
    let addr = bt_l2cap_addr(0x0080, [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5], 3);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("connect with address type 3 should be EINVAL");
    }
    // RFCOMM server channel 31 is out of range.
    let r = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_STREAM,
        crate::socket::BTPROTO_RFCOMM,
    );
    let addr = bt_rfcomm_addr([0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5], 31);
    if !matches!(
        r.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("connect to RFCOMM channel 31 should be EINVAL");
    }
    // A retry to a different peer while one is in flight stays
    // EINPROGRESS (it does not start a second open).
    let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    let addr = bt_l2cap_addr(0x0080, peer6, 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail("first connect should be EINPROGRESS");
    }
    let other = bt_l2cap_addr(0x0080, [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5], 1);
    if !matches!(
        s.dispatch_op(crate::socket::SocketOp::Connect { addr: other }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail(
            "connect to a different peer while in flight should be EINPROGRESS",
        );
    }
    // A listening socket refuses connect.
    let l = crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
    let addr = bt_l2cap_addr(0x0080, [0; 6], 1);
    if !matches!(
        l.dispatch_op(crate::socket::SocketOp::Bind { addr }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("bind for the listening-socket case failed");
    }
    if !matches!(
        l.dispatch_op(crate::socket::SocketOp::Listen { backlog: 8 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("listen for the listening-socket case failed");
    }
    let addr = bt_l2cap_addr(0x0080, peer6, 1);
    if !matches!(
        l.dispatch_op(crate::socket::SocketOp::Connect { addr }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::BadFdState)
    ) {
        return TestResult::Fail("connect on a listening socket should be EBADFD");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_connect_errors);

/// #1532: dropping a socket with an in-flight connect cancels the
/// open — no half-open channel survives the socket.
fn smoke_bt_connect_drop_cancels() -> TestResult {
    install_fake_bt_bridge();
    let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
    let mut peer = [0u8; 7];
    peer[0] = 1;
    peer[1..7].copy_from_slice(&peer6);
    {
        let s =
            crate::socket::SocketFile::new(crate::socket::AF_BLUETOOTH, crate::socket::SOCK_STREAM);
        let addr = bt_l2cap_addr(0x0080, peer6, 1);
        if !matches!(
            s.dispatch_op(crate::socket::SocketOp::Connect { addr }),
            crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
        ) {
            return TestResult::Fail("first connect should be EINPROGRESS");
        }
        drop(s);
    }
    if !FAKE_BT
        .lock()
        .connect_cancels
        .contains(&(0u16, peer, 0x0080u16, true, false))
    {
        return TestResult::Fail("dropping a connecting socket did not cancel the open");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_connect_drop_cancels);

/// SCO: connect (EINPROGRESS, then re-run completes) → getpeername
/// → send → recv a staged frame → SCO_OPTIONS / SCO_CONNINFO →
/// shutdown disconnects. The send/recv cross the broker into the fake.
fn smoke_bt_sco_connect_send_recv() -> TestResult {
    install_fake_bt_bridge();
    let sock = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_SEQPACKET,
        crate::socket::BTPROTO_SCO,
    );
    let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
    // 1. First connect starts the setup: EINPROGRESS.
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail("SCO connect did not report EINPROGRESS");
    }
    if !sock.bt_sco_connect_pending() {
        return TestResult::Fail("SCO connect did not leave a setup pending");
    }
    // 2. Re-running connect polls the setup to completion.
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("SCO connect re-run did not complete");
    }
    // 3. getpeername reports the connected peer.
    match sock.dispatch_op(crate::socket::SocketOp::GetPeerName) {
        crate::socket::SocketOpResult::Addr(addr)
            if addr.family == crate::socket::AF_BLUETOOTH && addr.body == peer.to_vec() => {}
        _ => return TestResult::Fail("SCO getpeername did not report the peer"),
    }
    // 4. Send one frame; the fake bridge sees it.
    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: b"voice",
        flags: 0,
        addr: None,
    }) {
        crate::socket::SocketOpResult::Ok(5) => {}
        _ => return TestResult::Fail("SCO send did not report 5 bytes"),
    }
    if FAKE_BT.lock().sent_sco != alloc::vec![(0x0043u16, b"voice".to_vec())] {
        return TestResult::Fail("SCO send did not reach the fake bridge");
    }
    // 5. Recv returns the staged frame.
    fake_bt_stage_sco_rx(0x0043, b"echo");
    let mut out = [0u8; 16];
    match sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received { n, .. } if n == 4 && &out[..4] == b"echo" => {}
        _ => return TestResult::Fail("SCO recv did not return the staged frame"),
    }
    // 6. SCO_OPTIONS / SCO_CONNINFO report the live link.
    let mut opt = [0u8; 2];
    match sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SCO,
        name: crate::socket::SCO_OPTIONS,
        buf: &mut opt,
    }) {
        crate::socket::SocketOpResult::OptValue { n } if n == 2 && opt == 64u16.to_ne_bytes() => {}
        _ => return TestResult::Fail("SCO_OPTIONS did not report mtu 64"),
    }
    let mut info = [0u8; 5];
    match sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level: crate::socket::SOL_SCO,
        name: crate::socket::SCO_CONNINFO,
        buf: &mut info,
    }) {
        crate::socket::SocketOpResult::OptValue { n }
            if n == 5 && info == [0x43, 0x00, 0x10, 0x01, 0x00] => {}
        _ => return TestResult::Fail("SCO_CONNINFO did not report handle/class"),
    }
    // 7. Shutdown disconnects the link; send refuses after.
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Shutdown { how: 0 }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("SCO shutdown failed");
    }
    if !FAKE_BT.lock().disconnected_sco.contains(&0x0043u16) {
        return TestResult::Fail("SCO shutdown did not disconnect the link");
    }
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Send {
            buf: b"x",
            flags: 0,
            addr: None,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NotConnected)
    ) {
        return TestResult::Fail("SCO send after shutdown should be ENOTCONN");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_sco_connect_send_recv);

/// SCO error paths: send/recv/getpeername/SCO_OPTIONS without a
/// link, connect with no pump, double connect, MSG_OOB send,
/// oversize send, and a SOCK_STREAM SCO connect.
fn smoke_bt_sco_connect_errors() -> TestResult {
    install_fake_bt_bridge();
    let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
    let sock = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_SEQPACKET,
        crate::socket::BTPROTO_SCO,
    );
    // Send/recv/getpeername without a link: ENOTCONN.
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Send {
            buf: b"x",
            flags: 0,
            addr: None,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NotConnected)
    ) {
        return TestResult::Fail("SCO send without a link should be ENOTCONN");
    }
    let mut out = [0u8; 16];
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Recv {
            buf: &mut out,
            flags: 0,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NotConnected)
    ) {
        return TestResult::Fail("SCO recv without a link should be ENOTCONN");
    }
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::GetPeerName),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NotConnected)
    ) {
        return TestResult::Fail("SCO getpeername without a link should be ENOTCONN");
    }
    // SCO_OPTIONS without a link: ENOTCONN.
    let mut opt = [0u8; 2];
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
            level: crate::socket::SOL_SCO,
            name: crate::socket::SCO_OPTIONS,
            buf: &mut opt,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NotConnected)
    ) {
        return TestResult::Fail("SCO_OPTIONS without a link should be ENOTCONN");
    }
    // Connect with no pump: ENODEV.
    FAKE_BT.lock().sco_no_pump = true;
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NoDevice)
    ) {
        return TestResult::Fail("SCO connect without a pump should be ENODEV");
    }
    FAKE_BT.lock().sco_no_pump = false;
    // Connect, complete, then a second connect is EBADFD.
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail("SCO connect did not report EINPROGRESS");
    }
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("SCO connect re-run did not complete");
    }
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::BadFdState)
    ) {
        return TestResult::Fail("second SCO connect should be EBADFD");
    }
    // MSG_OOB send: EOPNOTSUPP. Oversize send (mtu 64): EINVAL.
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Send {
            buf: b"x",
            flags: crate::socket::MSG_OOB,
            addr: None,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::NotSupported)
    ) {
        return TestResult::Fail("MSG_OOB SCO send should be EOPNOTSUPP");
    }
    let big = [0xAAu8; 65];
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Send {
            buf: &big,
            flags: 0,
            addr: None,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("oversize SCO send should be EINVAL");
    }
    // A SOCK_STREAM SCO socket cannot connect.
    let stream = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_STREAM,
        crate::socket::BTPROTO_SCO,
    );
    if !matches!(
        stream.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        return TestResult::Fail("SOCK_STREAM SCO connect should be EINVAL");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_sco_connect_errors);

/// SCO recv is SEQPACKET: a short buffer truncates one frame
/// (ReceivedTruncated) and MSG_PEEK leaves the frame queued.
fn smoke_bt_sco_recv_truncation_and_peek() -> TestResult {
    install_fake_bt_bridge();
    let sock = crate::socket::SocketFile::with_protocol(
        crate::socket::AF_BLUETOOTH,
        crate::socket::SOCK_SEQPACKET,
        crate::socket::BTPROTO_SCO,
    );
    let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
    ) {
        return TestResult::Fail("SCO connect did not report EINPROGRESS");
    }
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Connect {
            addr: bt_sco_addr(peer)
        }),
        crate::socket::SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("SCO connect re-run did not complete");
    }
    fake_bt_stage_sco_rx(0x0043, b"abcd");
    let mut small = [0u8; 2];
    match sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut small,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::ReceivedTruncated {
            copied, full_len, ..
        } if copied == 2 && full_len == 4 && small == *b"ab" => {}
        _ => return TestResult::Fail("short SCO recv did not truncate the frame"),
    }
    // The truncated frame is consumed, not left staged.
    let mut out = [0u8; 16];
    if !matches!(
        sock.dispatch_op(crate::socket::SocketOp::Recv {
            buf: &mut out,
            flags: 0,
        }),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock)
    ) {
        return TestResult::Fail("recv after a truncated frame should be EAGAIN");
    }
    fake_bt_stage_sco_rx(0x0043, b"peek");
    match sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: crate::socket::MSG_PEEK,
    }) {
        crate::socket::SocketOpResult::Received { n, .. } if n == 4 && &out[..4] == b"peek" => {}
        _ => return TestResult::Fail("MSG_PEEK SCO recv did not return the frame"),
    }
    match sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut out,
        flags: 0,
    }) {
        crate::socket::SocketOpResult::Received { n, .. } if n == 4 && &out[..4] == b"peek" => {}
        _ => return TestResult::Fail("MSG_PEEK SCO recv consumed the frame"),
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_sco_recv_truncation_and_peek);

/// Drop teardown: dropping a connected SCO socket disconnects its
/// link, and dropping one mid-setup cancels the pending setup.
fn smoke_bt_sco_drop_teardown() -> TestResult {
    install_fake_bt_bridge();
    let peer = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5];
    {
        let sock = crate::socket::SocketFile::with_protocol(
            crate::socket::AF_BLUETOOTH,
            crate::socket::SOCK_SEQPACKET,
            crate::socket::BTPROTO_SCO,
        );
        if !matches!(
            sock.dispatch_op(crate::socket::SocketOp::Connect {
                addr: bt_sco_addr(peer)
            }),
            crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
        ) {
            return TestResult::Fail("SCO connect did not report EINPROGRESS");
        }
        if !matches!(
            sock.dispatch_op(crate::socket::SocketOp::Connect {
                addr: bt_sco_addr(peer)
            }),
            crate::socket::SocketOpResult::Ok(_)
        ) {
            return TestResult::Fail("SCO connect re-run did not complete");
        }
    }
    if !FAKE_BT.lock().disconnected_sco.contains(&0x0043u16) {
        return TestResult::Fail("dropping the connected SCO socket did not disconnect");
    }
    {
        let sock = crate::socket::SocketFile::with_protocol(
            crate::socket::AF_BLUETOOTH,
            crate::socket::SOCK_SEQPACKET,
            crate::socket::BTPROTO_SCO,
        );
        if !matches!(
            sock.dispatch_op(crate::socket::SocketOp::Connect {
                addr: bt_sco_addr(peer)
            }),
            crate::socket::SocketOpResult::Err(crate::socket::SockError::InProgress)
        ) {
            return TestResult::Fail("SCO connect did not report EINPROGRESS");
        }
        if FAKE_BT.lock().sco_pending.is_empty() {
            return TestResult::Fail("SCO connect did not leave a setup pending");
        }
    }
    if !FAKE_BT.lock().sco_pending.is_empty() {
        return TestResult::Fail("dropping a mid-setup SCO socket did not cancel the setup");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_bt_sco_drop_teardown);
