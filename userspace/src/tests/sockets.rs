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

/// SO_BINDTODEVICE: string round-trip.
fn smoke_socket_so_bindtodevice_round_trip() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    let _ = sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level: crate::socket::SOL_SOCKET,
        name: crate::socket::SO_BINDTODEVICE,
        value: b"eth0",
    });
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
    if &out[..n] == b"eth0" {
        TestResult::Pass
    } else {
        TestResult::Fail("SO_BINDTODEVICE round-trip mismatch")
    }
}
kernel_test_in!("userspace", smoke_socket_so_bindtodevice_round_trip);

/// sockaddr_in with invalid family rejected by Connect.
fn smoke_socket_sockaddr_invalid_family_rejected() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_STREAM);
    let mut bogus = crate::socket::make_sockaddr_in(0x7F00_0001, 4321);
    bogus.family = 9999; // not AF_INET / AF_UNIX / AF_INET6
    let r = sock.dispatch_op(crate::socket::SocketOp::Connect { addr: bogus });
    if matches!(
        r,
        crate::socket::SocketOpResult::Err(crate::socket::SockError::InvalidArg)
    ) {
        TestResult::Pass
    } else {
        TestResult::Fail("invalid family was not rejected")
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

/// SO_RCVBUF / SO_SNDBUF clamp small values to ≥ 2 KiB and
/// round-trip larger values verbatim.
fn smoke_socket_so_rcvbuf_sndbuf_clamp() -> TestResult {
    let sock = crate::socket::SocketFile::new(crate::socket::AF_INET, crate::socket::SOCK_DGRAM);
    // Set RCVBUF to 100; should clamp to 2048.
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
    if u32::from_ne_bytes(out) != 2_048 {
        return TestResult::Fail("SO_RCVBUF did not clamp");
    }
    // Set SNDBUF to 64 KiB; should round-trip exact.
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
        || u32::from_ne_bytes(out) != 65_536
    {
        return TestResult::Fail("SO_SNDBUF did not round-trip");
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

    // sockaddr_in body: port (BE) + ip (BE). Port 7777, 0.0.0.0.
    let port: u16 = 7777;
    let mut body = alloc::vec::Vec::new();
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    let mk_addr = || SockAddr {
        family: AF_INET,
        body: body.clone(),
    };

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
    let addr = SockAddr {
        family: AF_INET,
        body: [
            port.to_be_bytes().as_slice(),
            loopback.to_be_bytes().as_slice(),
        ]
        .concat(),
    };
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
    });
    crate::namespaces::release_task(task);
    if narf_net::route::route_list_in(namespace_id).is_empty() {
        return TestResult::Fail("live socket did not retain namespace state");
    }
    receiver.unregister();
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

fn smoke_stack_admin_delegates_only_to_current_route_socket() -> TestResult {
    use narf_capabilities::{Cap, Invoke};
    use narf_net::{StackAttach, StackDaemon};

    const TASK: u64 = 0x4E45_544C;
    fn task_lookup() -> u64 {
        TASK
    }

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
    let (route_fd, inet_fd) = crate::fd::with_table(TASK, |table| {
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
        (route_fd, inet_fd)
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
    if crate::delegate_stack_admin_to_route_socket(route_fd + 1000, &reply)
        != Err(crate::socket::SockError::BadFd)
    {
        return TestResult::Fail("delegation escaped the current task fd table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/netlink",
    smoke_stack_admin_delegates_only_to_current_route_socket
);
