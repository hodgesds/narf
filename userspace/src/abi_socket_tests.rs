//! Linux syscall ABI conformance — socket group.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

// ── Linux socket constants (subset the NARF handlers understand) ──
const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_PASSCRED: u64 = 16;
const SO_PEERCRED: u64 = 17;
const SO_ACCEPTCONN: u64 = 30;
const SHUT_RDWR: u64 = 2;
/// SCM control-message types (SOL_SOCKET level).
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const O_NONBLOCK: i64 = 0o4000;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;

// A clearly-invalid fd that no freshly-created table will ever hand out.
const BAD_FD: u64 = 4096;

/// Open an AF_UNIX SOCK_STREAM socket via the real `socket(2)` handler and
/// return its fd. Panics-as-Err if the handler reports the -1 sentinel.
fn open_unix_stream() -> Result<u64, &'static str> {
    let n = Syscall::SocketOpen.raw();
    match call(n, a2(AF_UNIX, SOCK_STREAM, 0)) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("socket(AF_UNIX, SOCK_STREAM) did not return a valid fd"),
    }
}

/// Build a NARF/Linux `sockaddr_un`-ish buffer: family(u16 LE) + path bytes.
/// The bind/connect path trims trailing NULs, so a bare path works.
fn unix_sockaddr(path: &[u8]) -> ([u8; 128], u64) {
    let mut buf = [0u8; 128];
    buf[0..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    let n = core::cmp::min(path.len(), 110);
    buf[2..2 + n].copy_from_slice(&path[..n]);
    let len = (2 + n) as u64;
    (buf, len)
}

// ───────────────────────────── SocketOpen ─────────────────────────────

fn smoke_abi_socket_socket_open_pos() -> TestResult {
    with_setup(|| {
        let n = Syscall::SocketOpen.raw();
        let fd = call(n, a2(AF_UNIX, SOCK_STREAM, 0)).ok_or("status not Ok")?;
        if fd < 0 {
            return Err("socket() returned the -1 failure sentinel for a valid family");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_socket_open_pos);

fn smoke_abi_socket_socket_open_neg() -> TestResult {
    with_setup(|| {
        let n = Syscall::SocketOpen.raw();
        // Family 9999 is not AF_UNIX/INET/INET6/BYPASS/NETLINK → rejected.
        let r = call(n, a2(9999, SOCK_STREAM, 0)).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EAFNOSUPPORT (-97); NARF returns the bare
        // -1 sentinel for an unknown family.
        if r != -1 {
            return Err("unknown family did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_socket_open_neg);

// ───────────────────────────── SocketBind ─────────────────────────────

fn smoke_abi_socket_bind_pos() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-bind-pos");
        let n = Syscall::SocketBind.raw();
        let r = call(n, a2(fd, addr.as_ptr() as u64, alen)).ok_or("status not Ok")?;
        if r != 0 {
            return Err("bind() to a fresh path did not return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_bind_pos);

fn smoke_abi_socket_bind_neg() -> TestResult {
    with_setup(|| {
        let (addr, alen) = unix_sockaddr(b"/abi-bind-neg");
        let n = Syscall::SocketBind.raw();
        // No such fd → current_socket() fails → -1.
        let r = call(n, a2(BAD_FD, addr.as_ptr() as u64, alen)).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns the -1 sentinel.
        if r != -1 {
            return Err("bind() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_bind_neg);

// ──────────────────────────── SocketListen ────────────────────────────

fn smoke_abi_socket_listen_pos() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-listen-pos");
        let bind = Syscall::SocketBind.raw();
        if call(bind, a2(fd, addr.as_ptr() as u64, alen)).ok_or("bind status")? != 0 {
            return Err("bind() pre-listen failed");
        }
        let n = Syscall::SocketListen.raw();
        let r = call(n, a1(fd, 16)).ok_or("status not Ok")?;
        if r != 0 {
            return Err("listen() on a bound socket did not return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_listen_pos);

fn smoke_abi_socket_listen_neg() -> TestResult {
    with_setup(|| {
        // listen() on a fresh (unbound) socket: state is Fresh, not
        // UnixListener → dispatch returns InvalidArg → -1.
        let fd = open_unix_stream()?;
        let n = Syscall::SocketListen.raw();
        let r = call(n, a1(fd, 16)).ok_or("status not Ok")?;
        if r != -1 {
            return Err("listen() on an unbound socket did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_listen_neg);

// ──────────────────────────── SocketConnect ───────────────────────────

fn smoke_abi_socket_connect_pos() -> TestResult {
    with_setup(|| {
        // Stand up a listener, then connect a second socket to its path.
        let srv = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-connect-pos");
        let bind = Syscall::SocketBind.raw();
        if call(bind, a2(srv, addr.as_ptr() as u64, alen)).ok_or("bind status")? != 0 {
            return Err("server bind failed");
        }
        let listen = Syscall::SocketListen.raw();
        if call(listen, a1(srv, 16)).ok_or("listen status")? != 0 {
            return Err("server listen failed");
        }
        let cli = open_unix_stream()?;
        let n = Syscall::SocketConnect.raw();
        let r = call(n, a2(cli, addr.as_ptr() as u64, alen)).ok_or("status not Ok")?;
        if r != 0 {
            return Err("connect() to a live listener did not return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_connect_pos);

fn smoke_abi_socket_bound_client_connects() -> TestResult {
    with_setup(|| {
        let srv = open_unix_stream()?;
        let (server_addr, server_len) = unix_sockaddr(b"/abi-bound-connect-server");
        if call(
            Syscall::SocketBind.raw(),
            a2(srv, server_addr.as_ptr() as u64, server_len),
        )
        .ok_or("server bind status")?
            != 0
            || call(Syscall::SocketListen.raw(), a1(srv, 16)).ok_or("listen status")? != 0
        {
            return Err("bound-client test could not create listener");
        }

        let cli = open_unix_stream()?;
        let (client_addr, client_len) = unix_sockaddr(b"\0abi-bound-connect-client");
        if call(
            Syscall::SocketBind.raw(),
            a2(cli, client_addr.as_ptr() as u64, client_len),
        )
        .ok_or("client bind status")?
            != 0
        {
            return Err("client bind failed");
        }
        match call(
            Syscall::SocketConnect.raw(),
            a2(cli, server_addr.as_ptr() as u64, server_len),
        ) {
            Some(0) => Ok(()),
            _ => Err("connect() rejected a locally bound Unix client socket"),
        }
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_bound_client_connects);

fn smoke_abi_socket_connect_neg() -> TestResult {
    with_setup(|| {
        // No listener bound at this path → ConnectionRefused → -errno.
        let cli = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-connect-nope");
        let n = Syscall::SocketConnect.raw();
        let r = call(n, a2(cli, addr.as_ptr() as u64, alen)).ok_or("status not Ok")?;
        // Connect maps SockError → -errno; the only requirement that must hold
        // for a regression pin is that it is a negative failure, not 0.
        if r >= 0 {
            return Err("connect() to an absent path did not fail");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_connect_neg);

// ───────────────────────────── SocketAccept ───────────────────────────

fn smoke_abi_socket_accept_neg() -> TestResult {
    with_setup(|| {
        let n = Syscall::SocketAccept.raw();
        let r = call(n, a0(BAD_FD)).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns the -1 sentinel.
        if r != -1 {
            return Err("accept() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_accept_neg);

fn smoke_abi_socket_accept_empty_eagain() -> TestResult {
    with_setup(|| {
        // A bound+listen socket with no pending connection. In the kernel-test
        // harness there is no user-task executor, so the blocking WouldBlock
        // path falls through to -EAGAIN instead of parking.
        let srv = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-accept-empty");
        let bind = Syscall::SocketBind.raw();
        if call(bind, a2(srv, addr.as_ptr() as u64, alen)).ok_or("bind status")? != 0 {
            return Err("bind failed");
        }
        let listen = Syscall::SocketListen.raw();
        if call(listen, a1(srv, 16)).ok_or("listen status")? != 0 {
            return Err("listen failed");
        }
        let n = Syscall::SocketAccept.raw();
        let r = call(n, a0(srv)).ok_or("status not Ok")?;
        if r != EAGAIN {
            return Err("accept() on an empty blocking listener did not return -EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_accept_empty_eagain);

/// The varlink primitive: a path-bound AF_UNIX stream listener, a client
/// connect, the server accept()ing the queued connection, and BIDIRECTIONAL
/// request→reply data over the accepted pair. This is exactly the shape
/// systemd's sd-varlink uses (e.g. udevd → io.systemd.Multiplexer → userdbd
/// worker → reply). If a connect doesn't enqueue, accept doesn't dequeue, or
/// the reply doesn't flow back, a Type=notify service that gates readiness on
/// such a call hangs and times out.
fn smoke_abi_socket_unix_stream_request_reply() -> TestResult {
    with_setup(|| {
        let srv = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-varlink-rr");
        if call(
            Syscall::SocketBind.raw(),
            a2(srv, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("server bind failed");
        }
        if call(Syscall::SocketListen.raw(), a1(srv, 16)).ok_or("listen status")? != 0 {
            return Err("server listen failed");
        }
        let cli = open_unix_stream()?;
        if call(
            Syscall::SocketConnect.raw(),
            a2(cli, addr.as_ptr() as u64, alen),
        )
        .ok_or("connect status")?
            != 0
        {
            return Err("client connect failed");
        }
        // Server accepts the queued connection.
        let conn = call(Syscall::SocketAccept.raw(), a0(srv)).ok_or("accept status")?;
        if conn < 0 {
            return Err("accept did not return a connection fd for a queued connect");
        }
        let conn = conn as u64;
        // Client → server request.
        let req = b"REQUEST";
        if call(
            Syscall::SocketSend.raw(),
            a3(cli, req.as_ptr() as u64, req.len() as u64, 0),
        )
        .ok_or("cli send status")?
            != req.len() as i64
        {
            return Err("client send did not write the whole request");
        }
        let mut sbuf = [0u8; 16];
        let rn = call(
            Syscall::SocketRecv.raw(),
            a3(conn, sbuf.as_mut_ptr() as u64, sbuf.len() as u64, 0),
        )
        .ok_or("srv recv status")?;
        if rn != req.len() as i64 || &sbuf[..req.len()] != req {
            return Err("server did not receive the client's request");
        }
        // Server → client reply.
        let rep = b"REPLY";
        if call(
            Syscall::SocketSend.raw(),
            a3(conn, rep.as_ptr() as u64, rep.len() as u64, 0),
        )
        .ok_or("srv send status")?
            != rep.len() as i64
        {
            return Err("server send did not write the whole reply");
        }
        let mut cbuf = [0u8; 16];
        let cn = call(
            Syscall::SocketRecv.raw(),
            a3(cli, cbuf.as_mut_ptr() as u64, cbuf.len() as u64, 0),
        )
        .ok_or("cli recv status")?;
        if cn != rep.len() as i64 || &cbuf[..rep.len()] != rep {
            return Err("client did not receive the server's reply");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_unix_stream_request_reply
);

// ──────────────────────────── SocketAccept4 ───────────────────────────

fn smoke_abi_socket_accept4_neg() -> TestResult {
    with_setup(|| {
        let n = Syscall::SocketAccept4.raw();
        let r = call(n, a3(BAD_FD, 0, 0, 0)).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns the -1 sentinel.
        if r != -1 {
            return Err("accept4() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_accept4_neg);

fn smoke_abi_socket_accept4_empty_eagain() -> TestResult {
    with_setup(|| {
        let srv = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-accept4-empty");
        let bind = Syscall::SocketBind.raw();
        if call(bind, a2(srv, addr.as_ptr() as u64, alen)).ok_or("bind status")? != 0 {
            return Err("bind failed");
        }
        let listen = Syscall::SocketListen.raw();
        if call(listen, a1(srv, 16)).ok_or("listen status")? != 0 {
            return Err("listen failed");
        }
        let n = Syscall::SocketAccept4.raw();
        let r = call(n, a3(srv, 0, 0, 0)).ok_or("status not Ok")?;
        if r != EAGAIN {
            return Err("accept4() on an empty blocking listener did not return -EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_accept4_empty_eagain);

fn smoke_abi_socket_accept4_uses_shared_nonblock_state() -> TestResult {
    with_setup(|| {
        let srv = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-accept4-shared-nonblock");
        if call(
            Syscall::SocketBind.raw(),
            a2(srv, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("bind failed");
        }
        if call(Syscall::SocketListen.raw(), a1(srv, 16)) != Some(0) {
            return Err("listen failed");
        }

        // F_SETFL updates the SocketFile's shared open-file-description state
        // and the descriptor snapshot. Simulate an inherited/remapped fd whose
        // snapshot was rebuilt without status flags, as systemd socket
        // activation exposed during the CachyOS boot.
        if call(Syscall::Fcntl.raw(), a2(srv, F_SETFL, O_NONBLOCK as u64)) != Some(0) {
            return Err("F_SETFL(O_NONBLOCK) failed");
        }
        let cleared = fd::with_table(FAKE_TASK, |table| {
            table.get_mut(srv as u32).map(|entry| {
                entry.status_flags &= !(O_NONBLOCK as u32);
            })
        })
        .flatten()
        .is_some();
        if !cleared {
            return Err("listener fd disappeared");
        }
        if !crate::handlers::__test_socket_listener_nonblock(srv as u32) {
            return Err("accept4 ignored shared SocketFile O_NONBLOCK state");
        }

        let r =
            call(Syscall::SocketAccept4.raw(), a3(srv, 0, 0, 0)).ok_or("accept4 status not Ok")?;
        if r != EAGAIN {
            return Err("empty inherited nonblocking listener did not return -EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_accept4_uses_shared_nonblock_state
);

// ───────────────────────────── SocketPair ─────────────────────────────

fn smoke_abi_socket_pair_pos() -> TestResult {
    with_setup(|| {
        let mut sv = [0u8; 8];
        let n = Syscall::SocketPair.raw();
        let r =
            call(n, a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("status not Ok")?;
        if r != 0 {
            return Err("socketpair(AF_UNIX, SOCK_STREAM) did not return 0");
        }
        // sv[0]/sv[1] must be two valid (>=0) fds written by the handler.
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]);
        let fd1 = i32::from_ne_bytes([sv[4], sv[5], sv[6], sv[7]]);
        if fd0 < 0 || fd1 < 0 || fd0 == fd1 {
            return Err("socketpair did not write two distinct valid fds into sv[2]");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_pair_pos);

fn smoke_abi_socket_pair_neg() -> TestResult {
    with_setup(|| {
        let mut sv = [0u8; 8];
        let n = Syscall::SocketPair.raw();
        // AF_INET is not implemented for socketpair → -1.
        let r =
            call(n, a3(AF_INET, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EOPNOTSUPP (-95); NARF returns -1.
        if r != -1 {
            return Err("socketpair(AF_INET, ...) did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_pair_neg);

// ───────────────────────────── SocketSend ─────────────────────────────

fn smoke_abi_socket_send_pos() -> TestResult {
    with_setup(|| {
        // socketpair gives a connected stream pair; send into one half.
        let mut sv = [0u8; 8];
        let pair = Syscall::SocketPair.raw();
        if call(pair, a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
        let payload = b"hello-narf";
        let n = Syscall::SocketSend.raw();
        let r = call(n, a3(fd0, payload.as_ptr() as u64, payload.len() as u64, 0))
            .ok_or("status not Ok")?;
        if r != payload.len() as i64 {
            return Err("send() into a connected pair did not return the byte count");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_send_pos);

fn smoke_abi_socket_send_neg() -> TestResult {
    with_setup(|| {
        let payload = b"x";
        let n = Syscall::SocketSend.raw();
        let r = call(
            n,
            a3(BAD_FD, payload.as_ptr() as u64, payload.len() as u64, 0),
        )
        .ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns -1.
        if r != -1 {
            return Err("send() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_send_neg);

// ───────────────────────────── SocketRecv ─────────────────────────────

fn smoke_abi_socket_recv_pos() -> TestResult {
    with_setup(|| {
        // Send into one half of a pair, then recv from the other half.
        let mut sv = [0u8; 8];
        let pair = Syscall::SocketPair.raw();
        if call(pair, a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
        let fd1 = i32::from_ne_bytes([sv[4], sv[5], sv[6], sv[7]]) as u64;

        let payload = b"abcd";
        let send = Syscall::SocketSend.raw();
        if call(
            send,
            a3(fd0, payload.as_ptr() as u64, payload.len() as u64, 0),
        )
        .ok_or("send status")?
            != payload.len() as i64
        {
            return Err("priming send failed");
        }
        let mut rbuf = [0u8; 16];
        let n = Syscall::SocketRecv.raw();
        let r = call(n, a3(fd1, rbuf.as_mut_ptr() as u64, rbuf.len() as u64, 0))
            .ok_or("status not Ok")?;
        if r != payload.len() as i64 {
            return Err("recv() did not return the sent byte count");
        }
        if &rbuf[..payload.len()] != payload {
            return Err("recv() did not deliver the sent bytes");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_recv_pos);

fn smoke_abi_socket_recv_neg() -> TestResult {
    with_setup(|| {
        let mut rbuf = [0u8; 8];
        let n = Syscall::SocketRecv.raw();
        let r = call(
            n,
            a3(BAD_FD, rbuf.as_mut_ptr() as u64, rbuf.len() as u64, 0),
        )
        .ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns -1.
        if r != -1 {
            return Err("recv() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_recv_neg);

// ── Non-blocking empty-but-open stream must EAGAIN, never a phantom 0 ──
// Regression for the AF_UNIX read/recv spurious-EOF bug: a non-blocking read
// or recv on an empty-but-OPEN stream socket returned 0 (which the caller
// reads as EOF / peer-hangup) instead of -EAGAIN. GLib's GDBus/GSocket poll
// loop treated that phantom 0 as a hangup and the KDE session-bus handshake
// (and libdbus's next marshalled message) desynced. The file op now returns
// `WouldBlock` while the peer is open, so EOF (peer closed) stays 0.
const SOCK_NONBLOCK: u64 = 0x800;
const MSG_DONTWAIT: u64 = 0x40;

fn make_pair(kind: u64) -> Result<(u64, u64), &'static str> {
    let mut sv = [0u8; 8];
    let pair = Syscall::SocketPair.raw();
    if call(pair, a3(AF_UNIX, kind, 0, sv.as_mut_ptr() as u64)).ok_or("pair status")? != 0 {
        return Err("socketpair setup failed");
    }
    let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
    let fd1 = i32::from_ne_bytes([sv[4], sv[5], sv[6], sv[7]]) as u64;
    Ok((fd0, fd1))
}

fn add_level_epollin(fd: u64) -> Result<u64, &'static str> {
    let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create status")?;
    if epfd < 0 {
        return Err("epoll_create failed");
    }
    let mut interest = [0u8; 12];
    interest[..4].copy_from_slice(&1u32.to_ne_bytes()); // EPOLLIN, no EPOLLET.
    interest[4..].copy_from_slice(&0x4442_5553u64.to_ne_bytes());
    if call(
        Syscall::EpollCtl.raw(),
        a3(epfd as u64, 1, fd, interest.as_ptr() as u64),
    ) != Some(0)
    {
        return Err("epoll_ctl ADD level EPOLLIN failed");
    }
    Ok(epfd as u64)
}

fn epoll_ready_now(epfd: u64) -> Result<i64, &'static str> {
    let mut event = [0u8; 12];
    call(
        Syscall::EpollWait.raw(),
        a3(epfd, event.as_mut_ptr() as u64, 1, 0),
    )
    .ok_or("epoll_wait status")
}

/// D-Bus commonly queues a method reply and a following broadcast on the same
/// connected AF_UNIX stream. If userspace consumes only the first complete
/// message, level-triggered epoll must immediately return the still-readable
/// fd again; it cannot require another peer write to manufacture a wake.
fn smoke_abi_socket_stream_epoll_level_redelivers_queued_message() -> TestResult {
    with_setup(|| {
        let (tx, rx) = make_pair(SOCK_STREAM | SOCK_NONBLOCK)?;
        let epfd = add_level_epollin(rx)?;
        let reply = b"method-reply";
        let broadcast = b"name-owner-changed";
        for message in [reply.as_slice(), broadcast.as_slice()] {
            if call(
                Syscall::SocketSend.raw(),
                a3(tx, message.as_ptr() as u64, message.len() as u64, 0),
            ) != Some(message.len() as i64)
            {
                return Err("AF_UNIX stream message send failed");
            }
        }
        if epoll_ready_now(epfd)? != 1 {
            return Err("epoll did not report the queued method reply");
        }
        let mut first = [0u8; 12];
        if call(
            Syscall::SocketRecv.raw(),
            a3(rx, first.as_mut_ptr() as u64, first.len() as u64, 0),
        ) != Some(reply.len() as i64)
            || &first != reply
        {
            return Err("recv did not consume exactly the first queued message");
        }
        if epoll_ready_now(epfd)? != 1 {
            return Err("level epoll lost the unread D-Bus-shaped broadcast");
        }
        let mut second = [0u8; 18];
        if call(
            Syscall::SocketRecv.raw(),
            a3(rx, second.as_mut_ptr() as u64, second.len() as u64, 0),
        ) != Some(broadcast.len() as i64)
            || &second != broadcast
        {
            return Err("recv did not deliver the queued broadcast");
        }
        if epoll_ready_now(epfd)? != 0 {
            return Err("drained AF_UNIX stream remained spuriously readable");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_stream_epoll_level_redelivers_queued_message
);

/// Cover the same level-trigger rule when both logical messages arrive in one
/// stream write and the first read stops inside a message. Message boundaries
/// are userspace state; kernel readiness must depend only on unread bytes.
fn smoke_abi_socket_stream_epoll_level_redelivers_partial_read() -> TestResult {
    with_setup(|| {
        let (tx, rx) = make_pair(SOCK_STREAM | SOCK_NONBLOCK)?;
        let epfd = add_level_epollin(rx)?;
        let wire = b"reply|broadcast";
        if call(
            Syscall::SocketSend.raw(),
            a3(tx, wire.as_ptr() as u64, wire.len() as u64, 0),
        ) != Some(wire.len() as i64)
        {
            return Err("coalesced AF_UNIX stream send failed");
        }
        if epoll_ready_now(epfd)? != 1 {
            return Err("epoll did not report coalesced stream bytes");
        }
        let mut prefix = [0u8; 3];
        if call(
            Syscall::SocketRecv.raw(),
            a3(rx, prefix.as_mut_ptr() as u64, prefix.len() as u64, 0),
        ) != Some(prefix.len() as i64)
            || &prefix != b"rep"
        {
            return Err("partial stream recv returned the wrong prefix");
        }
        if epoll_ready_now(epfd)? != 1 {
            return Err("level epoll lost unread bytes after a partial recv");
        }
        let mut rest = [0u8; 12];
        if call(
            Syscall::SocketRecv.raw(),
            a3(rx, rest.as_mut_ptr() as u64, rest.len() as u64, 0),
        ) != Some(rest.len() as i64)
            || &rest != b"ly|broadcast"
        {
            return Err("recv did not deliver the unread stream suffix");
        }
        if epoll_ready_now(epfd)? != 0 {
            return Err("drained partial-read stream remained readable");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_stream_epoll_level_redelivers_partial_read
);

fn smoke_abi_socket_read_nonblock_empty_eagain() -> TestResult {
    with_setup(|| {
        let (_fd0, fd1) = make_pair(SOCK_STREAM | SOCK_NONBLOCK)?;
        let mut rbuf = [0u8; 16];
        let read = Syscall::Read.raw();
        let r = call(read, a2(fd1, rbuf.as_mut_ptr() as u64, rbuf.len() as u64))
            .ok_or("status not Ok")?;
        if r != EAGAIN {
            return Err("read() on an empty-but-open O_NONBLOCK socket returned a phantom 0/EOF instead of -EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_read_nonblock_empty_eagain
);

fn smoke_abi_socket_recv_dontwait_empty_eagain() -> TestResult {
    with_setup(|| {
        // A *blocking* pair, but MSG_DONTWAIT forces non-blocking semantics:
        // an empty-open ring must EAGAIN immediately, never park.
        let (_fd0, fd1) = make_pair(SOCK_STREAM)?;
        let mut rbuf = [0u8; 16];
        let recv = Syscall::SocketRecv.raw();
        let r = call(
            recv,
            a3(
                fd1,
                rbuf.as_mut_ptr() as u64,
                rbuf.len() as u64,
                MSG_DONTWAIT,
            ),
        )
        .ok_or("status not Ok")?;
        if r != EAGAIN {
            return Err("recv(MSG_DONTWAIT) on an empty-but-open socket did not return -EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_recv_dontwait_empty_eagain
);

fn smoke_abi_socket_read_nonblock_then_data() -> TestResult {
    with_setup(|| {
        // The EAGAIN must be transient: once data lands, the same non-blocking
        // read delivers it (proves we didn't just wire read() to always EAGAIN).
        let (fd0, fd1) = make_pair(SOCK_STREAM | SOCK_NONBLOCK)?;
        let payload = b"xyz";
        let send = Syscall::SocketSend.raw();
        if call(
            send,
            a3(fd0, payload.as_ptr() as u64, payload.len() as u64, 0),
        )
        .ok_or("send status")?
            != payload.len() as i64
        {
            return Err("priming send failed");
        }
        let mut rbuf = [0u8; 16];
        let read = Syscall::Read.raw();
        let r = call(read, a2(fd1, rbuf.as_mut_ptr() as u64, rbuf.len() as u64))
            .ok_or("status not Ok")?;
        if r != payload.len() as i64 {
            return Err("non-blocking read() did not deliver buffered data");
        }
        if &rbuf[..payload.len()] != payload {
            return Err("non-blocking read() delivered wrong bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_read_nonblock_then_data
);

fn smoke_abi_socket_read_eof_after_peer_shutdown() -> TestResult {
    with_setup(|| {
        // A genuine EOF (peer half shut down) must still return 0, NOT EAGAIN —
        // the fix distinguishes empty-open (EAGAIN) from closed (EOF).
        let (fd0, fd1) = make_pair(SOCK_STREAM | SOCK_NONBLOCK)?;
        let shutdown = Syscall::SocketShutdown.raw();
        let generation = narf_net::readiness::generation();
        if call(shutdown, a1(fd0, SHUT_RDWR)).ok_or("shutdown status")? != 0 {
            return Err("shutdown(fd0) failed");
        }
        if narf_net::readiness::generation() <= generation {
            return Err("shutdown did not publish a readiness wake");
        }
        let mut rbuf = [0u8; 16];
        let read = Syscall::Read.raw();
        let r = call(read, a2(fd1, rbuf.as_mut_ptr() as u64, rbuf.len() as u64))
            .ok_or("status not Ok")?;
        if r != 0 {
            return Err("read() after peer shutdown did not return 0 (EOF)");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_read_eof_after_peer_shutdown
);

/// A server parked in `ppoll`/`epoll_wait` with an INFINITE timeout on a
/// LISTENING AF_UNIX socket must wake within bounded time of a peer's
/// `connect()` (a compositor's wayland-0 listener is exactly this shape).
/// The park machinery (`park_should_block` + the readiness-generation
/// lost-wake guard + the ~10 ms backstop) already bounds the re-scan for
/// any event source that (a) publishes a readiness notify and (b) reports
/// POLLIN when the re-executed scan asks again. This pins BOTH halves for
/// the listen/accept side — the data side's equivalents are the shutdown
/// generation check above and the eventfd `readiness_notifies` test in
/// `tests/fd_io.rs`:
///   1. `connect()` must bump the readiness generation (the wake channel
///      that breaks an infinite park out of its re-park loop), and
///   2. the same poll scan a parked poller re-executes on wake must flip
///      the listener 0 → POLLIN once a connection is pending.
///
/// Either half regressing re-opens the "listener never accepts / accepts
/// only on an unrelated wake" class (weston no-serve).
fn smoke_abi_socket_unix_listener_connect_wakes_parked_poller() -> TestResult {
    with_setup(|| {
        let srv = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-listener-wake");
        if call(
            Syscall::SocketBind.raw(),
            a2(srv, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("server bind failed");
        }
        if call(Syscall::SocketListen.raw(), a1(srv, 16)).ok_or("listen status")? != 0 {
            return Err("server listen failed");
        }

        // pollfd { fd: srv, events: POLLIN(0x1), revents: 0 } — 8 bytes.
        let mut pfd = [0u8; 8];
        pfd[0..4].copy_from_slice(&(srv as i32).to_ne_bytes());
        pfd[4..6].copy_from_slice(&0x1u16.to_ne_bytes());
        // Negative half: an idle listener must NOT report POLLIN — a false
        // positive here would make the parked server spin accept/EAGAIN.
        if call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)) != Some(0) {
            return Err("idle listener reported ready before any connect");
        }

        let before = narf_net::readiness::generation();
        let cli = open_unix_stream()?;
        if call(
            Syscall::SocketConnect.raw(),
            a2(cli, addr.as_ptr() as u64, alen),
        )
        .ok_or("connect status")?
            != 0
        {
            return Err("client connect failed");
        }
        // Half 1: the wake channel. Without this bump a poller parked with
        // an infinite timeout only ever re-scans off the 10 ms backstop —
        // and before that backstop existed, never.
        if narf_net::readiness::generation() <= before {
            return Err("connect() did not publish a readiness wake for a parked listener");
        }
        // Half 2: the re-scan's answer. poll(timeout=0) runs the same
        // `poll_scan` a woken parked poller re-executes.
        pfd[6..8].copy_from_slice(&0u16.to_ne_bytes()); // clear revents
        match call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)) {
            Some(1) if u16::from_ne_bytes(pfd[6..8].try_into().unwrap()) & 0x1 != 0 => {}
            _ => return Err("pending connection did not make the listener POLLIN"),
        }
        // And the accept the woken server then issues must deliver it.
        let conn = call(Syscall::SocketAccept.raw(), a0(srv)).ok_or("accept status")?;
        if conn < 0 {
            return Err("accept() after the poll wake did not return a connection fd");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_unix_listener_connect_wakes_parked_poller
);

/// A listening AF_UNIX socket watched through an epoll fd that is ITSELF
/// polled — libwayland's shape. `wl_event_loop` owns an epoll containing
/// the display socket and hands its fd to the toolkit's main loop, which
/// `poll(2)`s it alongside everything else. So a client's `connect()` has
/// to travel: listener → epoll ready-list → the outer `poll` over the
/// epoll fd. A break anywhere on that chain looks identical from outside
/// — the compositor simply never accepts.
///
/// Covers both trigger modes deliberately. Level-triggered is a plain
/// "is the ready list non-empty" query; EPOLLET adds the edge bookkeeping
/// (`last_mask` / `poll_edge_token`) that `EpollInstance::poll_readiness`
/// has to mirror from `collect_ready`, and a listener's edge comes from
/// `listener_readable_token`, which only the enqueue in `connect()`
/// advances.
fn smoke_abi_socket_listener_readable_through_nested_epoll() -> TestResult {
    with_setup(|| {
        for (label, et) in [("level", 0u32), ("edge", crate::epoll::EPOLLET)] {
            let srv = open_unix_stream()?;
            let (addr, alen) = unix_sockaddr(if et == 0 {
                b"/abi-nested-epoll-lvl"
            } else {
                b"/abi-nested-epoll-et"
            });
            if call(
                Syscall::SocketBind.raw(),
                a2(srv, addr.as_ptr() as u64, alen),
            )
            .ok_or("bind status")?
                != 0
            {
                return Err("listener bind failed");
            }
            if call(Syscall::SocketListen.raw(), a1(srv, 16)).ok_or("listen status")? != 0 {
                return Err("listen failed");
            }

            let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create status")?;
            if epfd < 0 {
                return Err("epoll_create failed");
            }
            let epfd = epfd as u64;
            let mut interest = [0u8; 12];
            interest[..4].copy_from_slice(&(1u32 | et).to_ne_bytes()); // EPOLLIN [| EPOLLET]
            interest[4..].copy_from_slice(&0x4C49_5354u64.to_ne_bytes());
            if call(
                Syscall::EpollCtl.raw(),
                a3(epfd, 1, srv, interest.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("epoll_ctl ADD of the listener failed");
            }

            // pollfd { fd: epfd, events: POLLIN, revents: 0 }.
            let mut pfd = [0u8; 8];
            pfd[0..4].copy_from_slice(&(epfd as i32).to_ne_bytes());
            pfd[4..6].copy_from_slice(&0x1u16.to_ne_bytes());

            // Negative half: an idle listener must not make the epoll fd
            // readable, or the outer loop spins on an epoll_wait that
            // returns nothing.
            if call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)) != Some(0) {
                return Err("idle listener made the nested epoll fd readable");
            }

            let cli = open_unix_stream()?;
            if call(
                Syscall::SocketConnect.raw(),
                a2(cli, addr.as_ptr() as u64, alen),
            )
            .ok_or("connect status")?
                != 0
            {
                return Err("client connect failed");
            }

            // The epoll fd must now be POLLIN to an outer poll(2)...
            pfd[6..8].copy_from_slice(&0u16.to_ne_bytes());
            match call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)) {
                Some(1) if u16::from_ne_bytes(pfd[6..8].try_into().unwrap()) & 0x1 != 0 => {}
                _ => {
                    return Err(if et == 0 {
                        "pending connection did not make the nested epoll fd POLLIN (level)"
                    } else {
                        "pending connection did not make the nested epoll fd POLLIN (edge)"
                    })
                }
            }
            // ...and the epoll_wait the woken loop then runs must agree.
            // Disagreement here is worse than a miss: the outer poll returns
            // ready, epoll_wait returns nothing, and the loop spins hot.
            if epoll_ready_now(epfd)? != 1 {
                return Err(if et == 0 {
                    "outer poll said ready but epoll_wait delivered no event (level)"
                } else {
                    "outer poll said ready but epoll_wait delivered no event (edge)"
                });
            }
            // And the accept it then issues must produce the connection.
            let conn = call(Syscall::SocketAccept.raw(), a0(srv)).ok_or("accept status")?;
            if conn < 0 {
                return Err("accept after the nested-epoll wake returned no connection");
            }
            let _ = label;
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_listener_readable_through_nested_epoll
);

/// A task parked in `epoll_wait` with an INFINITE timeout on a CONNECTED
/// AF_UNIX socketpair must wake when its peer sends.
///
/// This is the shape a udev worker sits in: `epoll_wait(-1)` on its worker
/// socket, waiting for udevd to hand it a device event. Measured on a real
/// boot, those workers park with `checks` CLIMBING — the park re-fires and
/// the scan re-runs — and still never see a message, until udevd is stuck
/// at "18 children at max", `/run/udev/data` stays empty, no device gets a
/// `seat` tag, and libinput enumerates nothing.
///
/// The neighbouring `..._epoll_level_redelivers_partial_read` covers the
/// SCAN (`epoll_wait` with timeout 0, asking "is it ready now"). It cannot
/// catch a missing wake, because a fresh scan finds the data whether or not
/// anything was ever notified. Both halves are asserted here for the same
/// reason they are on the listener test:
///   1. `send()` must bump the readiness generation — the channel that
///      breaks an infinite park out of its re-park loop.
///   2. the re-executed scan must then report the fd ready.
///
/// Half 1 failing is invisible to every timeout-0 epoll test in the file.
fn smoke_abi_socket_connected_pair_send_wakes_parked_epoll() -> TestResult {
    with_setup(|| {
        let (tx, rx) = make_pair(SOCK_STREAM | SOCK_NONBLOCK)?;
        let epfd = add_level_epollin(rx)?;

        // Negative half: an idle pair must not report ready, or a parked
        // worker degenerates into a read/EAGAIN spin.
        if epoll_ready_now(epfd)? != 0 {
            return Err("idle socketpair reported epoll-ready before any send");
        }

        let before = narf_net::readiness::generation();
        let wire = b"udev-device-event";
        if call(
            Syscall::SocketSend.raw(),
            a3(tx, wire.as_ptr() as u64, wire.len() as u64, 0),
        ) != Some(wire.len() as i64)
        {
            return Err("send on the connected pair failed");
        }

        // Half 1: the wake channel. Without this bump a peer parked in
        // `epoll_wait(-1)` only ever re-scans off the lost-wake backstop —
        // which is exactly the "checks climbing, nothing ever ready" shape
        // the udev workers show.
        if narf_net::readiness::generation() <= before {
            return Err("send() published no readiness wake for a parked epoll waiter");
        }
        // Half 2: the scan a woken waiter re-executes must see the data.
        if epoll_ready_now(epfd)? != 1 {
            return Err("sent bytes did not make the connected pair epoll-readable");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_connected_pair_send_wakes_parked_epoll
);

// ─────────────────────────── SocketShutdown ───────────────────────────

fn smoke_abi_socket_shutdown_pos() -> TestResult {
    with_setup(|| {
        // shutdown() on a connected pair half → Ok(0).
        let mut sv = [0u8; 8];
        let pair = Syscall::SocketPair.raw();
        if call(pair, a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
        let n = Syscall::SocketShutdown.raw();
        let r = call(n, a1(fd0, SHUT_RDWR)).ok_or("status not Ok")?;
        if r != 0 {
            return Err("shutdown() on a connected socket did not return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_shutdown_pos);

fn smoke_abi_socket_shutdown_neg() -> TestResult {
    with_setup(|| {
        let n = Syscall::SocketShutdown.raw();
        let r = call(n, a1(BAD_FD, SHUT_RDWR)).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns -1.
        if r != -1 {
            return Err("shutdown() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_shutdown_neg);

// ──────────────────────────── SocketGetSockOpt ────────────────────────

fn smoke_abi_socket_getsockopt_pos() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let mut val = [0u8; 4];
        let mut optlen = (val.len() as u32).to_ne_bytes();
        let n = Syscall::SocketGetSockOpt.raw();
        // getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &optlen).
        let args = SyscallArgs {
            arg0: fd,
            arg1: SOL_SOCKET,
            arg2: SO_TYPE,
            arg3: val.as_mut_ptr() as u64,
            arg4: optlen.as_mut_ptr() as u64,
            ..Default::default()
        };
        let r = call(n, args).ok_or("status not Ok")?;
        if r != 0 {
            return Err("getsockopt(SO_TYPE) did not return 0");
        }
        // The handler writes the socket type back and updates optlen to 4.
        let got = u32::from_ne_bytes(val);
        if got != SOCK_STREAM as u32 {
            return Err("getsockopt(SO_TYPE) did not report SOCK_STREAM");
        }
        if u32::from_ne_bytes(optlen) != 4 {
            return Err("getsockopt did not update optlen to 4");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_getsockopt_pos);

fn smoke_abi_socket_getsockopt_neg() -> TestResult {
    with_setup(|| {
        let n = Syscall::SocketGetSockOpt.raw();
        let mut val = [0u8; 4];
        let mut optlen = (val.len() as u32).to_ne_bytes();
        let args = SyscallArgs {
            arg0: BAD_FD,
            arg1: SOL_SOCKET,
            arg2: SO_TYPE,
            arg3: val.as_mut_ptr() as u64,
            arg4: optlen.as_mut_ptr() as u64,
            ..Default::default()
        };
        let r = call(n, args).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns -1.
        if r != -1 {
            return Err("getsockopt() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_getsockopt_neg);

fn smoke_abi_socket_getsockopt_peersec_without_lsm() -> TestResult {
    with_setup(|| {
        const SO_PEERSEC: u64 = 31;
        let fd = open_unix_stream()?;
        let mut val = [0u8; 64];
        let mut optlen = (val.len() as u32).to_ne_bytes();
        let args = SyscallArgs {
            arg0: fd,
            arg1: SOL_SOCKET,
            arg2: SO_PEERSEC,
            arg3: val.as_mut_ptr() as u64,
            arg4: optlen.as_mut_ptr() as u64,
            ..Default::default()
        };
        match call(Syscall::SocketGetSockOpt.raw(), args) {
            Some(-92) => Ok(()),
            _ => Err("SO_PEERSEC without an LSM did not return ENOPROTOOPT"),
        }
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_getsockopt_peersec_without_lsm
);

fn smoke_abi_socket_getsockopt_peergroups() -> TestResult {
    with_setup(|| {
        const SO_PEERGROUPS: u64 = 59;
        let groups = [12u32, 34, 56];
        if call(
            Syscall::Setgroups.raw(),
            a1(groups.len() as u64, groups.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setgroups setup failed");
        }
        let mut sv = [0u8; 8];
        if call(
            Syscall::SocketPair.raw(),
            a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("socketpair setup failed");
        }
        let fd = i32::from_ne_bytes(sv[0..4].try_into().unwrap()) as u64;
        let mut val = [0u8; 64];
        let mut optlen = (val.len() as u32).to_ne_bytes();
        let args = SyscallArgs {
            arg0: fd,
            arg1: SOL_SOCKET,
            arg2: SO_PEERGROUPS,
            arg3: val.as_mut_ptr() as u64,
            arg4: optlen.as_mut_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::SocketGetSockOpt.raw(), args) != Some(0) {
            return Err("SO_PEERGROUPS failed");
        }
        if u32::from_ne_bytes(optlen) != 12 {
            return Err("SO_PEERGROUPS returned wrong length");
        }
        let returned = [
            u32::from_ne_bytes(val[0..4].try_into().unwrap()),
            u32::from_ne_bytes(val[4..8].try_into().unwrap()),
            u32::from_ne_bytes(val[8..12].try_into().unwrap()),
        ];
        if returned != groups {
            return Err("SO_PEERGROUPS returned wrong gids");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_getsockopt_peergroups);

fn smoke_abi_socket_getsockopt_peerpidfd_unavailable() -> TestResult {
    with_setup(|| {
        const SO_PEERPIDFD: u64 = 77;
        let fd = open_unix_stream()?;
        let mut val = [0u8; 8];
        let mut optlen = (val.len() as u32).to_ne_bytes();
        let args = SyscallArgs {
            arg0: fd,
            arg1: SOL_SOCKET,
            arg2: SO_PEERPIDFD,
            arg3: val.as_mut_ptr() as u64,
            arg4: optlen.as_mut_ptr() as u64,
            ..Default::default()
        };
        match call(Syscall::SocketGetSockOpt.raw(), args) {
            Some(-92) => Ok(()),
            _ => Err("SO_PEERPIDFD without retained pidfd did not return ENOPROTOOPT"),
        }
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_getsockopt_peerpidfd_unavailable
);

// getsockopt(SO_ACCEPTCONN) is the gate systemd's is_socket_internal() (behind
// sd_is_socket, which decides whether sd-bus negotiates SCM_RIGHTS fd-passing)
// probes whenever its `listening` arg is >= 0 — e.g. sd_bus's
// sd_is_socket(fd, AF_UNIX, 0, 0). A fresh (non-listening) socket must report 0;
// an error there disables NEGOTIATE_UNIX_FD and breaks elogind CreateSession.
fn smoke_abi_socket_acceptconn_not_listening() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let mut val = [0u8; 4];
        let mut optlen = (val.len() as u32).to_ne_bytes();
        let args = SyscallArgs {
            arg0: fd,
            arg1: SOL_SOCKET,
            arg2: SO_ACCEPTCONN,
            arg3: val.as_mut_ptr() as u64,
            arg4: optlen.as_mut_ptr() as u64,
            ..Default::default()
        };
        let r = call(Syscall::SocketGetSockOpt.raw(), args).ok_or("status not Ok")?;
        if r != 0 {
            return Err("getsockopt(SO_ACCEPTCONN) did not return 0");
        }
        if u32::from_ne_bytes(val) != 0 {
            return Err("SO_ACCEPTCONN on a non-listening socket was not 0");
        }
        if u32::from_ne_bytes(optlen) != 4 {
            return Err("getsockopt(SO_ACCEPTCONN) did not update optlen to 4");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_acceptconn_not_listening
);

fn smoke_abi_socket_acceptconn_listening() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-acceptconn");
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind() pre-listen failed");
        }
        if call(Syscall::SocketListen.raw(), a1(fd, 16)).ok_or("listen status")? != 0 {
            return Err("listen() failed");
        }
        let mut val = [0u8; 4];
        let mut optlen = (val.len() as u32).to_ne_bytes();
        let args = SyscallArgs {
            arg0: fd,
            arg1: SOL_SOCKET,
            arg2: SO_ACCEPTCONN,
            arg3: val.as_mut_ptr() as u64,
            arg4: optlen.as_mut_ptr() as u64,
            ..Default::default()
        };
        let r = call(Syscall::SocketGetSockOpt.raw(), args).ok_or("status not Ok")?;
        if r != 0 {
            return Err("getsockopt(SO_ACCEPTCONN) did not return 0");
        }
        if u32::from_ne_bytes(val) != 1 {
            return Err("SO_ACCEPTCONN on a listening socket was not 1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_acceptconn_listening);

// A socket fd must `fstat` as S_IFSOCK (0o140000), not a char device. systemd's
// is_socket_internal() rejects any fd whose st_mode fails S_ISSOCK before it
// even looks at the family — so without this, sd-bus fd-passing never turns on.
fn smoke_abi_socket_fstat_is_sock() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        // Linux x86_64 `struct stat` (this suite is linux-compat, so Fstat
        // routes to sys_fstat_linux): st_dev(8) st_ino(8) st_nlink(8) then
        // st_mode(u32) at offset 24.
        let mut stat = [0u8; 256];
        let r =
            call(Syscall::Fstat.raw(), a1(fd, stat.as_mut_ptr() as u64)).ok_or("status not Ok")?;
        if r != 0 {
            return Err("fstat of a socket fd did not return 0");
        }
        let mode = u32::from_ne_bytes([stat[24], stat[25], stat[26], stat[27]]);
        if mode & 0o170000 != 0o140000 {
            return Err("socket fd did not fstat as S_IFSOCK");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_fstat_is_sock);

// ──────────────────────────── SocketSetSockOpt ────────────────────────

fn smoke_abi_socket_setsockopt_pos() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let val = 1u32.to_ne_bytes();
        let n = Syscall::SocketSetSockOpt.raw();
        // setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &1, 4).
        let args = SyscallArgs {
            arg0: fd,
            arg1: SOL_SOCKET,
            arg2: SO_REUSEADDR,
            arg3: val.as_ptr() as u64,
            arg4: val.len() as u64,
            ..Default::default()
        };
        let r = call(n, args).ok_or("status not Ok")?;
        if r != 0 {
            return Err("setsockopt(SO_REUSEADDR) did not return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_setsockopt_pos);

fn smoke_abi_socket_setsockopt_neg() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let val = 1u32.to_ne_bytes();
        let n = Syscall::SocketSetSockOpt.raw();
        // val_len == 0 → handler rejects up front with the -1 sentinel.
        let args = SyscallArgs {
            arg0: fd,
            arg1: SOL_SOCKET,
            arg2: SO_REUSEADDR,
            arg3: val.as_ptr() as u64,
            arg4: 0,
            ..Default::default()
        };
        let r = call(n, args).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EINVAL (-22); NARF returns -1.
        if r != -1 {
            return Err("setsockopt() with zero optlen did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_setsockopt_neg);

// ─────────────────────────── SocketGetSockName ────────────────────────

fn smoke_abi_socket_getsockname_pos() -> TestResult {
    with_setup(|| {
        // A bound UnixListener has a local_addr (its path).
        let fd = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-getsockname");
        let bind = Syscall::SocketBind.raw();
        if call(bind, a2(fd, addr.as_ptr() as u64, alen)).ok_or("bind status")? != 0 {
            return Err("bind failed");
        }
        let listen = Syscall::SocketListen.raw();
        if call(listen, a1(fd, 16)).ok_or("listen status")? != 0 {
            return Err("listen failed");
        }
        let mut out = [0u8; 128];
        let mut outlen = (out.len() as u32).to_ne_bytes();
        let n = Syscall::SocketGetSockName.raw();
        let r = call(
            n,
            a2(fd, out.as_mut_ptr() as u64, outlen.as_mut_ptr() as u64),
        )
        .ok_or("status not Ok")?;
        if r != 0 {
            return Err("getsockname() on a bound listener did not return 0");
        }
        // family u16 must be AF_UNIX.
        let fam = u16::from_le_bytes([out[0], out[1]]);
        if fam != AF_UNIX as u16 {
            return Err("getsockname() did not report AF_UNIX family");
        }
        // optlen reports the full encoded length (>= 2).
        if u32::from_ne_bytes(outlen) < 2 {
            return Err("getsockname() did not update the address length");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_getsockname_pos);

fn smoke_abi_socket_getsockname_neg() -> TestResult {
    with_setup(|| {
        let mut out = [0u8; 16];
        let mut outlen = (out.len() as u32).to_ne_bytes();
        let n = Syscall::SocketGetSockName.raw();
        let r = call(
            n,
            a2(BAD_FD, out.as_mut_ptr() as u64, outlen.as_mut_ptr() as u64),
        )
        .ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns -1.
        if r != -1 {
            return Err("getsockname() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_getsockname_neg);

// ─────────────────────────── SocketGetPeerName ────────────────────────

fn smoke_abi_socket_getpeername_socketpair_pos() -> TestResult {
    with_setup(|| {
        let mut sv = [0u8; 8];
        let pair = Syscall::SocketPair.raw();
        if call(pair, a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;

        // An unnamed AF_UNIX peer is encoded as sa_family alone.  Keep the
        // caller capacity at one byte to also pin Linux's truncation rule:
        // copy only the available prefix, but report the full length.
        let mut out = [0xa5u8; 1];
        let mut outlen = 1u32.to_ne_bytes();
        let n = Syscall::SocketGetPeerName.raw();
        let r = call(
            n,
            a2(fd0, out.as_mut_ptr() as u64, outlen.as_mut_ptr() as u64),
        )
        .ok_or("status not Ok")?;
        if r != 0 {
            return Err("getpeername() on an unnamed socketpair failed");
        }
        if out[0] != (AF_UNIX as u16).to_le_bytes()[0] {
            return Err("getpeername() did not copy the available address prefix");
        }
        if u32::from_ne_bytes(outlen) != 2 {
            return Err("getpeername() did not report the full unnamed address length");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_getpeername_socketpair_pos
);

fn smoke_abi_socket_getpeername_neg_badfd() -> TestResult {
    with_setup(|| {
        let mut out = [0u8; 16];
        let mut outlen = (out.len() as u32).to_ne_bytes();
        let n = Syscall::SocketGetPeerName.raw();
        let r = call(
            n,
            a2(BAD_FD, out.as_mut_ptr() as u64, outlen.as_mut_ptr() as u64),
        )
        .ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns -1.
        if r != -1 {
            return Err("getpeername() on a bad fd did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_getpeername_neg_badfd);

fn smoke_abi_socket_getpeername_neg_unconnected() -> TestResult {
    with_setup(|| {
        // A fresh socket has no peer_addr() entry:
        // GetPeerName → NotConnected → -1.
        let fd = open_unix_stream()?;
        let mut out = [0u8; 16];
        let mut outlen = (out.len() as u32).to_ne_bytes();
        let n = Syscall::SocketGetPeerName.raw();
        let r = call(
            n,
            a2(fd, out.as_mut_ptr() as u64, outlen.as_mut_ptr() as u64),
        )
        .ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -ENOTCONN (-107); NARF returns -1.
        if r != -1 {
            return Err("getpeername() on an unconnected socket did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_getpeername_neg_unconnected
);

// ───────────────────────────── SocketSendMsg ──────────────────────────

fn smoke_abi_socket_sendmsg_pos() -> TestResult {
    with_setup(|| {
        // Connected pair + a crafted msghdr with one iovec.
        let mut sv = [0u8; 8];
        let pair = Syscall::SocketPair.raw();
        if call(pair, a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;

        let payload = b"msg-bytes";
        // struct iovec { void *base; size_t len; }
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
        // struct msghdr { name; namelen; iov; iovlen; ctrl; ctrllen; flags }
        let mut msg = [0u8; 56];
        // name = 0, namelen = 0 (offsets 0..12 stay zero)
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes()); // iov ptr
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes()); // iovlen = 1
                                                          // ctrl = 0, ctrllen = 0 (offsets 32..48 stay zero)
        let n = Syscall::SocketSendMsg.raw();
        let r = call(n, a2(fd0, msg.as_ptr() as u64, 0)).ok_or("status not Ok")?;
        if r != payload.len() as i64 {
            return Err("sendmsg() did not return the iovec byte count");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_sendmsg_pos);

fn smoke_abi_socket_sendmsg_neg() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let n = Syscall::SocketSendMsg.raw();
        // msg_ptr == 0 → handler rejects with the -1 sentinel.
        let r = call(n, a2(fd, 0, 0)).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EFAULT (-14); NARF returns -1.
        if r != -1 {
            return Err("sendmsg() with NULL msghdr did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_sendmsg_neg);

// ───────────────────────────── SocketRecvMsg ──────────────────────────

fn smoke_abi_socket_recvmsg_pos() -> TestResult {
    with_setup(|| {
        // Prime one half of a pair, then recvmsg from the other.
        let mut sv = [0u8; 8];
        let pair = Syscall::SocketPair.raw();
        if call(pair, a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
        let fd1 = i32::from_ne_bytes([sv[4], sv[5], sv[6], sv[7]]) as u64;
        let payload = b"rcv";
        let send = Syscall::SocketSend.raw();
        if call(
            send,
            a3(fd0, payload.as_ptr() as u64, payload.len() as u64, 0),
        )
        .ok_or("send status")?
            != payload.len() as i64
        {
            return Err("priming send failed");
        }

        let mut dst = [0u8; 16];
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
        let mut msg = [0u8; 56];
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        let n = Syscall::SocketRecvMsg.raw();
        let r = call(n, a2(fd1, msg.as_ptr() as u64, 0)).ok_or("status not Ok")?;
        if r != payload.len() as i64 {
            return Err("recvmsg() did not return the sent byte count");
        }
        if &dst[..payload.len()] != payload {
            return Err("recvmsg() did not scatter the sent bytes into the iovec");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_recvmsg_pos);

fn smoke_abi_socket_recvmsg_neg() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let n = Syscall::SocketRecvMsg.raw();
        // msg_ptr == 0 → -1 sentinel.
        let r = call(n, a2(fd, 0, 0)).ok_or("status not Ok")?;
        // LINUX-GAP: Linux returns -EFAULT (-14); NARF returns -1.
        if r != -1 {
            return Err("recvmsg() with NULL msghdr did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_recvmsg_neg);

// ─────────────────────────── SockRegisterBuf ──────────────────────────

fn smoke_abi_socket_sock_register_buf_pos() -> TestResult {
    with_setup(|| {
        let backing = [0u8; 64];
        let n = Syscall::SockRegisterBuf.raw();
        let r =
            call(n, a1(backing.as_ptr() as u64, backing.len() as u64)).ok_or("status not Ok")?;
        // Returns a non-negative buffer id (>= 0) on success.
        if r < 0 {
            return Err("sock_register_buf() did not return a valid buffer id");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_sock_register_buf_pos);

fn smoke_abi_socket_sock_register_buf_neg() -> TestResult {
    with_setup(|| {
        let n = Syscall::SockRegisterBuf.raw();
        // ptr == 0 → register_user_buffer returns None → -1.
        let r = call(n, a1(0, 64)).ok_or("status not Ok")?;
        if r != -1 {
            return Err("sock_register_buf(NULL) did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_sock_register_buf_neg);

// ───────────────────────────── SockSendZc ─────────────────────────────

fn smoke_abi_socket_sock_send_zc_pos() -> TestResult {
    with_setup(|| {
        // Register a buffer, connect a pair, send the registered slice.
        let mut sv = [0u8; 8];
        let pair = Syscall::SocketPair.raw();
        if call(pair, a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64)).ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;

        let backing = *b"zerocopy";
        let reg = Syscall::SockRegisterBuf.raw();
        let buf_id = call(reg, a1(backing.as_ptr() as u64, backing.len() as u64))
            .ok_or("register status")?;
        if buf_id < 0 {
            return Err("buffer registration failed");
        }
        let n = Syscall::SockSendZc.raw();
        // sock_send_zc(fd, buf_id, off=0, len=8, flags=0).
        let r = call(n, a3(fd0, buf_id as u64, 0, backing.len() as u64)).ok_or("status not Ok")?;
        if r != backing.len() as i64 {
            return Err("sock_send_zc() did not return the sent byte count");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_sock_send_zc_pos);

fn smoke_abi_socket_sock_send_zc_neg() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let n = Syscall::SockSendZc.raw();
        // buf_id 9999 was never registered → registered_buffer_slice None → -1.
        let r = call(n, a3(fd, 9999, 0, 8)).ok_or("status not Ok")?;
        if r != -1 {
            return Err("sock_send_zc() with an unregistered buf_id did not return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_sock_send_zc_neg);

// ─────────────────── AF_UNIX abstract namespace ───────────────────

/// Build a `sockaddr_un` for the ABSTRACT namespace: family + a leading
/// NUL + the abstract name. `addrlen` counts the leading NUL, matching
/// how systemd forms `$NOTIFY_SOCKET`.
fn abstract_sockaddr(name: &[u8]) -> ([u8; 128], u64) {
    let mut buf = [0u8; 128];
    buf[0..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    // buf[2] is the leading NUL (already zero); name follows.
    let n = core::cmp::min(name.len(), 100);
    buf[3..3 + n].copy_from_slice(&name[..n]);
    // addrlen = 2 (family) + 1 (leading NUL) + name length.
    let len = (2 + 1 + n) as u64;
    (buf, len)
}

/// Open an AF_UNIX socket of the given `kind`, returning its fd.
fn open_unix(kind: u64) -> Result<u64, &'static str> {
    match call(Syscall::SocketOpen.raw(), a2(AF_UNIX, kind, 0)) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("socket(AF_UNIX) did not return a valid fd"),
    }
}

/// Abstract datagram roundtrip: bind a receiver to an abstract name, then
/// `sendto` a payload from a second socket and read it back.
fn smoke_abi_socket_abstract_dgram_roundtrip() -> TestResult {
    with_setup(|| {
        let rx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = abstract_sockaddr(b"narf-abstract-dgram");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind() to an abstract datagram name did not return 0");
        }

        let tx = open_unix(SOCK_DGRAM)?;
        let payload = b"READY=1\n";
        // sendto(fd, buf, len, flags, dest_addr, dest_len) — dest in arg4/arg5.
        let send_args = SyscallArgs {
            arg0: tx,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            arg3: 0,
            arg4: addr.as_ptr() as u64,
            arg5: alen,
        };
        let sent = call(Syscall::SocketSend.raw(), send_args).ok_or("send status")?;
        if sent != payload.len() as i64 {
            return Err("sendto() to an abstract name did not return the byte count");
        }

        let mut rbuf = [0u8; 32];
        let got = call(
            Syscall::SocketRecv.raw(),
            a3(rx, rbuf.as_mut_ptr() as u64, rbuf.len() as u64, 0),
        )
        .ok_or("recv status")?;
        if got != payload.len() as i64 {
            return Err("recvfrom() on the abstract socket returned the wrong count");
        }
        if &rbuf[..payload.len()] != payload {
            return Err("recvfrom() delivered the wrong bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_abstract_dgram_roundtrip
);

/// A bound AF_UNIX datagram socket (the shape of systemd's
/// `$NOTIFY_SOCKET`) must retain an EPOLLET edge across a drain/refill even
/// when no epoll scan observes its inbox empty. Connected socketpairs use
/// RingBuf tokens; named datagram endpoints keep their own inbox and need the
/// same guarantee.
fn smoke_abi_socket_abstract_dgram_epollet_drain_refill() -> TestResult {
    with_setup(|| {
        let rx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = abstract_sockaddr(b"narf-abstract-dgram-et");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind() to abstract EPOLLET datagram name failed");
        }

        let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create status")?;
        if epfd < 0 {
            return Err("epoll_create failed");
        }
        let mut interest = [0u8; 12];
        interest[..4].copy_from_slice(&(1u32 | (1u32 << 31)).to_ne_bytes());
        interest[4..].copy_from_slice(&0x4E4F_5449_4659u64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            a3(epfd as u64, 1, rx, interest.as_ptr() as u64),
        )
        .ok_or("epoll_ctl status")?
            != 0
        {
            return Err("epoll_ctl ADD EPOLLET failed");
        }

        let tx = open_unix(SOCK_DGRAM)?;
        let mut out = [0u8; 12];
        for payload in [b"one".as_slice(), b"two".as_slice()] {
            let sent = call(
                Syscall::SocketSend.raw(),
                SyscallArgs {
                    arg0: tx,
                    arg1: payload.as_ptr() as u64,
                    arg2: payload.len() as u64,
                    arg4: addr.as_ptr() as u64,
                    arg5: alen,
                    ..SyscallArgs::default()
                },
            )
            .ok_or("sendto status")?;
            if sent != payload.len() as i64 {
                return Err("sendto() to abstract EPOLLET datagram name failed");
            }

            let ready = call(
                Syscall::EpollWait.raw(),
                a3(epfd as u64, out.as_mut_ptr() as u64, 1, 0),
            )
            .ok_or("epoll_wait status")?;
            if ready != 1 {
                return Err("EPOLLET lost abstract datagram drain/refill edge");
            }

            let mut buf = [0u8; 8];
            let received = call(
                Syscall::SocketRecv.raw(),
                a3(rx, buf.as_mut_ptr() as u64, buf.len() as u64, 0),
            )
            .ok_or("recv status")?;
            if received != payload.len() as i64 || &buf[..payload.len()] != payload {
                return Err("recv() did not drain the abstract datagram");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_abstract_dgram_epollet_drain_refill
);

/// The exact sd_notify(READY=1) → PID 1 shape end-to-end: a PATH-bound AF_UNIX
/// SOCK_DGRAM notify socket ($NOTIFY_SOCKET = /run/systemd/notify) with
/// SO_PASSCRED, waited on via epoll. A service sends a PLAIN datagram (a normal
/// notify has send_ucred=false, so it attaches NO SCM_CREDENTIALS — the KERNEL
/// must stamp the sender's credentials on the SO_PASSCRED receiver). PID 1's
/// epoll_wait must wake, and recvmsg must deliver the payload plus an
/// SCM_CREDENTIALS cmsg naming the sender; otherwise the Type=notify unit never
/// sees READY and times out. Abstract-name delivery is covered above; this pins
/// the PATH-bound (UNIX_DGRAM_BOUND) path systemd actually uses.
fn smoke_abi_socket_notify_path_dgram_epoll_scm() -> TestResult {
    with_setup(|| {
        let rx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = unix_sockaddr(b"/notify-e2e.sock");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind() of the PATH notify datagram socket failed");
        }
        // PID 1 sets SO_PASSCRED so the kernel attaches sender creds on recvmsg.
        let on = 1u32.to_ne_bytes();
        call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: rx,
                arg1: SOL_SOCKET,
                arg2: SO_PASSCRED,
                arg3: on.as_ptr() as u64,
                arg4: on.len() as u64,
                arg5: 0,
            },
        )
        .ok_or("setsockopt status")?;

        let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create status")?;
        if epfd < 0 {
            return Err("epoll_create failed");
        }
        let mut interest = [0u8; 12];
        interest[..4].copy_from_slice(&1u32.to_ne_bytes()); // EPOLLIN
        interest[4..].copy_from_slice(&0xABCDu64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            a3(epfd as u64, 1, rx, interest.as_ptr() as u64),
        )
        .ok_or("epoll_ctl status")?
            != 0
        {
            return Err("epoll_ctl ADD of notify fd failed");
        }

        // Service sends a plain READY=1 datagram (no control message).
        let tx = open_unix(SOCK_DGRAM)?;
        let payload = b"READY=1\n";
        let sent = call(
            Syscall::SocketSend.raw(),
            SyscallArgs {
                arg0: tx,
                arg1: payload.as_ptr() as u64,
                arg2: payload.len() as u64,
                arg4: addr.as_ptr() as u64,
                arg5: alen,
                ..SyscallArgs::default()
            },
        )
        .ok_or("sendto status")?;
        if sent != payload.len() as i64 {
            return Err("sendto() of READY=1 to the notify path failed");
        }

        // PID 1's epoll_wait must report the notify fd readable.
        let mut out = [0u8; 12];
        let ready = call(
            Syscall::EpollWait.raw(),
            a3(epfd as u64, out.as_mut_ptr() as u64, 1, 0),
        )
        .ok_or("epoll_wait status")?;
        if ready != 1 {
            return Err("epoll_wait did not wake on the PATH notify datagram (READY lost)");
        }

        // recvmsg delivers the payload + an SCM_CREDENTIALS cmsg for the sender.
        let mut dst = [0u8; 32];
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
        let mut ctrl = [0u8; 64];
        let mut msg = [0u8; 56];
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
        msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
        let n = call(Syscall::SocketRecvMsg.raw(), a2(rx, msg.as_ptr() as u64, 0))
            .ok_or("recvmsg status")?;
        if n != payload.len() as i64 || &dst[..payload.len()] != payload {
            return Err("recvmsg did not deliver the READY=1 payload");
        }
        let ctrllen = u64::from_ne_bytes([
            msg[40], msg[41], msg[42], msg[43], msg[44], msg[45], msg[46], msg[47],
        ]) as usize;
        if ctrllen < 16 + 12 {
            return Err("recvmsg did not attach SCM_CREDENTIALS for a plain notify datagram");
        }
        let ctype = i32::from_le_bytes([ctrl[12], ctrl[13], ctrl[14], ctrl[15]]);
        if ctype != SCM_CREDENTIALS {
            return Err("notify cmsg was not SCM_CREDENTIALS");
        }
        let cred_pid = u32::from_le_bytes([ctrl[16], ctrl[17], ctrl[18], ctrl[19]]);
        let my_pid = call(Syscall::GetPid.raw(), a0(0)).ok_or("getpid")? as u32;
        if cred_pid != my_pid {
            return Err("notify SCM_CREDENTIALS pid did not name the sender");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_notify_path_dgram_epoll_scm
);

/// `sd_notify()` sends its plain `READY=1` datagram with `sendmsg()`, rather
/// than `sendto()`.  PID 1 enables `SO_PASSCRED` on `/run/systemd/notify`, so
/// the path-bound datagram must wake its epoll waiter and arrive with the
/// sender's credentials even when the sender supplied no control messages.
fn smoke_abi_socket_notify_path_sendmsg_epoll_scm() -> TestResult {
    with_setup(|| {
        let rx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = unix_sockaddr(b"/notify-sendmsg-e2e.sock");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("bind() of the sendmsg notify datagram socket failed");
        }

        let on = 1u32.to_ne_bytes();
        if call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: rx,
                arg1: SOL_SOCKET,
                arg2: SO_PASSCRED,
                arg3: on.as_ptr() as u64,
                arg4: on.len() as u64,
                arg5: 0,
            },
        ) != Some(0)
        {
            return Err("setsockopt(SO_PASSCRED) for sendmsg notify failed");
        }

        let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create status")?;
        if epfd < 0 {
            return Err("epoll_create for sendmsg notify failed");
        }
        let mut interest = [0u8; 12];
        interest[..4].copy_from_slice(&1u32.to_ne_bytes()); // EPOLLIN
        interest[4..].copy_from_slice(&0xD0D0u64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            a3(epfd as u64, 1, rx, interest.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("epoll_ctl ADD for sendmsg notify failed");
        }

        let tx = open_unix(SOCK_DGRAM)?;
        let payload = b"READY=1\n";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
        let mut msg = [0u8; 56];
        msg[..8].copy_from_slice(&(addr.as_ptr() as u64).to_ne_bytes());
        msg[8..16].copy_from_slice(&alen.to_ne_bytes());
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        if call(Syscall::SocketSendMsg.raw(), a2(tx, msg.as_ptr() as u64, 0))
            != Some(payload.len() as i64)
        {
            return Err("sendmsg() of READY=1 to the notify path failed");
        }

        let mut events = [0u8; 12];
        if call(
            Syscall::EpollWait.raw(),
            a3(epfd as u64, events.as_mut_ptr() as u64, 1, 0),
        ) != Some(1)
        {
            return Err("epoll_wait did not wake for sendmsg READY=1");
        }

        let mut dst = [0u8; 32];
        let mut riov = [0u8; 16];
        riov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
        riov[8..].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
        let mut ctrl = [0u8; 64];
        let mut rmsg = [0u8; 56];
        rmsg[16..24].copy_from_slice(&(riov.as_ptr() as u64).to_ne_bytes());
        rmsg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        rmsg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
        rmsg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
        if call(
            Syscall::SocketRecvMsg.raw(),
            a2(rx, rmsg.as_ptr() as u64, 0),
        ) != Some(payload.len() as i64)
            || &dst[..payload.len()] != payload
        {
            return Err("recvmsg did not receive sendmsg READY=1");
        }
        let cred_type = i32::from_le_bytes(ctrl[12..16].try_into().unwrap());
        let cred_pid = u32::from_le_bytes(ctrl[16..20].try_into().unwrap());
        let sender_pid = call(Syscall::GetPid.raw(), a0(0)).ok_or("getpid")? as u32;
        if cred_type != SCM_CREDENTIALS || cred_pid != sender_pid {
            return Err("sendmsg READY=1 did not carry the sender SCM_CREDENTIALS");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_notify_path_sendmsg_epoll_scm
);

/// `systemd` identifies a Type=notify sender from SCM_CREDENTIALS in PID 1's
/// PID namespace. Exercise the real sendmsg/recvmsg transport with distinct
/// outer task IDs and assert that a child service arrives as PID 2, rather
/// than leaking its host-visible PID to the manager.
#[cfg(feature = "container")]
fn smoke_abi_socket_notify_sendmsg_pid_namespace_credentials() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xC100;
        const MANAGER_PID: u64 = 4100;
        const SERVICE_TASK: u64 = 0xC101;
        const SERVICE_PID: u64 = 4101;

        crate::pid_ns::__test_reset();
        let result = (|| {
            set_task(MANAGER_TASK);
            crate::handlers::register_pid_task_mapping(MANAGER_PID, MANAGER_TASK);
            crate::pid_ns::unshare_pid_ns(MANAGER_TASK, MANAGER_PID);

            let rx = open_unix(SOCK_DGRAM)?;
            let (addr, alen) = unix_sockaddr(b"/notify-pidns-e2e.sock");
            if call(
                Syscall::SocketBind.raw(),
                a2(rx, addr.as_ptr() as u64, alen),
            ) != Some(0)
            {
                return Err("manager could not bind its notify socket");
            }
            let on = 1u32.to_ne_bytes();
            if call(
                Syscall::SocketSetSockOpt.raw(),
                SyscallArgs {
                    arg0: rx,
                    arg1: SOL_SOCKET,
                    arg2: SO_PASSCRED,
                    arg3: on.as_ptr() as u64,
                    arg4: on.len() as u64,
                    arg5: 0,
                },
            ) != Some(0)
            {
                return Err("manager could not enable SO_PASSCRED");
            }

            crate::handlers::register_pid_task_mapping(SERVICE_PID, SERVICE_TASK);
            if crate::pid_ns::inherit_into_child(MANAGER_TASK, SERVICE_TASK, SERVICE_PID) != Some(2)
            {
                return Err("service was not assigned PID 2 in the manager namespace");
            }
            set_task(SERVICE_TASK);
            let tx = open_unix(SOCK_DGRAM)?;
            let payload = b"READY=1\n";
            let mut iov = [0u8; 16];
            iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
            iov[8..].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
            let mut msg = [0u8; 56];
            msg[..8].copy_from_slice(&(addr.as_ptr() as u64).to_ne_bytes());
            msg[8..16].copy_from_slice(&alen.to_ne_bytes());
            msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
            if call(Syscall::SocketSendMsg.raw(), a2(tx, msg.as_ptr() as u64, 0))
                != Some(payload.len() as i64)
            {
                return Err("service sendmsg(READY=1) failed");
            }

            set_task(MANAGER_TASK);
            let mut dst = [0u8; 32];
            let mut iov = [0u8; 16];
            iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
            iov[8..].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
            let mut ctrl = [0u8; 64];
            let mut msg = [0u8; 56];
            msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
            msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
            msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
            if call(Syscall::SocketRecvMsg.raw(), a2(rx, msg.as_ptr() as u64, 0))
                != Some(payload.len() as i64)
                || &dst[..payload.len()] != payload
            {
                return Err("manager did not receive the service READY=1 datagram");
            }
            let cred_type = i32::from_le_bytes(ctrl[12..16].try_into().unwrap());
            let cred_pid = u32::from_le_bytes(ctrl[16..20].try_into().unwrap());
            if cred_type != SCM_CREDENTIALS || cred_pid != 2 {
                return Err("SCM_CREDENTIALS did not report the service as PID 2");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        result
    })
}
#[cfg(feature = "container")]
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_notify_sendmsg_pid_namespace_credentials
);

/// `PrivateMounts=yes` gives a service a cloned mount tree, rather than an
/// unrelated filesystem. A pathname `$NOTIFY_SOCKET` bound by PID 1 must
/// therefore remain reachable after the service unshares only its mount
/// namespace. This is the systemd Type=notify topology: path lookup is in the
/// service's namespace, while the socket inode is shared with the manager.
fn smoke_abi_socket_notify_sendmsg_across_cloned_mount_namespace() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xC180;
        const SERVICE_TASK: u64 = 0xC181;
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const MOUNT: &str = "/abi-notify-shared-mount-ns";
        const SOCKET: &[u8] = b"/abi-notify-shared-mount-ns/notify";

        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let mount = registry()
            .mount_arc(
                &auth,
                MOUNT,
                alloc::sync::Arc::new(MemFs::with_seeds("notify-shared", &[])),
            )
            .map_err(|_| "shared notify mount setup failed")?;
        let result = (|| {
            set_task(MANAGER_TASK);
            let rx = open_unix(SOCK_DGRAM)?;
            let (addr, alen) = unix_sockaddr(SOCKET);
            if call(
                Syscall::SocketBind.raw(),
                a2(rx, addr.as_ptr() as u64, alen),
            ) != Some(0)
            {
                return Err("manager could not bind the shared notify socket");
            }
            let on = 1u32.to_ne_bytes();
            if call(
                Syscall::SocketSetSockOpt.raw(),
                SyscallArgs {
                    arg0: rx,
                    arg1: SOL_SOCKET,
                    arg2: SO_PASSCRED,
                    arg3: on.as_ptr() as u64,
                    arg4: on.len() as u64,
                    arg5: 0,
                },
            ) != Some(0)
            {
                return Err("manager could not enable SO_PASSCRED");
            }
            let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create failed")?;
            let mut interest = [0u8; 12];
            interest[..4].copy_from_slice(&1u32.to_ne_bytes());
            if call(
                Syscall::EpollCtl.raw(),
                a3(epfd as u64, 1, rx, interest.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("manager could not add notify socket to epoll");
            }

            set_task(SERVICE_TASK);
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("service could not clone its mount namespace");
            }
            let tx = open_unix(SOCK_DGRAM)?;
            let payload = b"READY=1\nSTATUS=Processing requests...";
            let mut iov = [0u8; 16];
            iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
            iov[8..].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
            let mut msg = [0u8; 56];
            msg[..8].copy_from_slice(&(addr.as_ptr() as u64).to_ne_bytes());
            msg[8..16].copy_from_slice(&alen.to_ne_bytes());
            msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
            if call(Syscall::SocketSendMsg.raw(), a2(tx, msg.as_ptr() as u64, 0))
                != Some(payload.len() as i64)
            {
                return Err("service sendmsg(READY=1) did not reach the shared notify socket");
            }

            set_task(MANAGER_TASK);
            let mut events = [0u8; 12];
            if call(
                Syscall::EpollWait.raw(),
                a3(epfd as u64, events.as_mut_ptr() as u64, 1, 0),
            ) != Some(1)
            {
                return Err("manager epoll did not observe service READY=1");
            }
            let mut received = [0u8; 64];
            if call(
                Syscall::SocketRecv.raw(),
                a3(rx, received.as_mut_ptr() as u64, received.len() as u64, 0),
            ) != Some(payload.len() as i64)
                || &received[..payload.len()] != payload
            {
                return Err("manager did not receive service READY=1");
            }
            Ok(())
        })();
        set_task(SERVICE_TASK);
        crate::handlers::clear_current_mount_namespace_for_test();
        set_task(MANAGER_TASK);
        let _ = registry().unmount(&mount, MOUNT);
        set_task(FAKE_TASK);
        result
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_notify_sendmsg_across_cloned_mount_namespace
);

/// systemd's `PrivateMounts=yes` setup may overmount the directory that holds
/// `$NOTIFY_SOCKET`, then bind the notify *file* back into the service view.
/// The target spelling is therefore under a different parent mount even though
/// it denotes the same socket inode. A Type=notify service must still deliver
/// `READY=1` to PID 1 through that stacked file bind.
fn smoke_abi_socket_notify_sendmsg_through_stacked_file_bind() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xC1A0;
        const SERVICE_TASK: u64 = 0xC1A1;
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const MS_BIND: u64 = 1 << 12;
        const SOURCE_MOUNT: &str = "/abi-notify-file-bind-source";
        const PRIVATE_MOUNT: &str = "/abi-notify-file-bind-private";
        const SOURCE_PATH: &str = "/abi-notify-file-bind-source/notify";
        const TARGET_PATH: &str = "/abi-notify-file-bind-private/notify";
        const SOURCE_SOCKET: &[u8] = b"/abi-notify-file-bind-source/notify\0";
        const TARGET_SOCKET: &[u8] = b"/abi-notify-file-bind-private/notify\0";

        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let source = registry()
            .mount_arc(
                &auth,
                SOURCE_MOUNT,
                alloc::sync::Arc::new(MemFs::with_seeds("notify-file-source", &[])),
            )
            .map_err(|_| "notify source mount setup failed")?;
        let private = registry()
            .mount_arc(
                &auth,
                PRIVATE_MOUNT,
                alloc::sync::Arc::new(MemFs::with_seeds("notify-file-private", &[])),
            )
            .map_err(|_| "notify private mount setup failed")?;

        let result = (|| {
            set_task(MANAGER_TASK);
            let rx = open_unix(SOCK_DGRAM)?;
            let (source_addr, source_len) = unix_sockaddr(SOURCE_SOCKET);
            if call(
                Syscall::SocketBind.raw(),
                a2(rx, source_addr.as_ptr() as u64, source_len),
            ) != Some(0)
            {
                return Err("manager could not bind the source notify socket");
            }
            let source_key = crate::handlers::unix_socket_path_key(
                core::str::from_utf8(&SOURCE_SOCKET[..SOURCE_SOCKET.len() - 1])
                    .map_err(|_| "source notify path was not UTF-8")?,
            )
            .ok_or("manager notify socket has no VFS identity")?;
            let source_inode = crate::handlers::current_resolve_absolute(SOURCE_PATH, |fs, rel| {
                narf_filesystem::resolve(fs.root(), rel)
                    .ok()
                    .map(|file| (fs.backing_identity(), file.ino()))
            })
            .flatten()
            .ok_or("manager bind did not materialise its socket inode")?;
            let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create failed")?;
            let mut interest = [0u8; 12];
            interest[..4].copy_from_slice(&1u32.to_ne_bytes());
            if call(
                Syscall::EpollCtl.raw(),
                a3(epfd as u64, 1, rx, interest.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("manager could not watch source notify socket");
            }

            set_task(SERVICE_TASK);
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("service could not clone its mount namespace");
            }
            let ns = crate::handlers::current_mount_namespace()
                .ok_or("service mount namespace missing after unshare")?;
            ns.mount_arc(
                &auth,
                PRIVATE_MOUNT,
                alloc::sync::Arc::new(MemFs::with_seeds("notify-private-overmount", &[])),
            )
            .map_err(|_| "service could not overmount notify parent")?;

            if call(
                Syscall::Mount.raw(),
                SyscallArgs {
                    arg0: SOURCE_SOCKET.as_ptr() as u64,
                    arg1: TARGET_SOCKET.as_ptr() as u64,
                    arg3: MS_BIND,
                    ..Default::default()
                },
            ) != Some(0)
            {
                return Err("service could not bind the notify file into its private mount");
            }
            let target_key = crate::handlers::unix_socket_path_key(
                core::str::from_utf8(&TARGET_SOCKET[..TARGET_SOCKET.len() - 1])
                    .map_err(|_| "target notify path was not UTF-8")?,
            )
            .ok_or("private notify file bind has no VFS identity")?;
            let target_inode = crate::handlers::current_resolve_absolute(TARGET_PATH, |fs, rel| {
                if !rel.is_empty() {
                    return None;
                }
                fs.root_file()
                    .map(|file| (fs.backing_identity(), file.ino()))
            })
            .flatten()
            .ok_or("private notify bind did not install a file-rooted mount")?;
            if target_inode.0 != source_inode.0 {
                return Err("file bind changed the notify socket backing filesystem");
            }
            if target_inode.1 != source_inode.1 {
                return Err("file bind changed the notify socket inode");
            }
            if target_key != source_key {
                return Err("file bind did not preserve the notify socket VFS identity");
            }

            let tx = open_unix(SOCK_DGRAM)?;
            let (target_addr, target_len) = unix_sockaddr(TARGET_SOCKET);
            let payload = b"READY=1\nSTATUS=stacked file bind";
            let mut iov = [0u8; 16];
            iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
            iov[8..].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
            let mut msg = [0u8; 56];
            msg[..8].copy_from_slice(&(target_addr.as_ptr() as u64).to_ne_bytes());
            msg[8..16].copy_from_slice(&target_len.to_ne_bytes());
            msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
            if call(Syscall::SocketSendMsg.raw(), a2(tx, msg.as_ptr() as u64, 0))
                != Some(payload.len() as i64)
            {
                return Err("sendmsg through stacked notify file bind did not reach PID 1");
            }

            set_task(MANAGER_TASK);
            let mut events = [0u8; 12];
            if call(
                Syscall::EpollWait.raw(),
                a3(epfd as u64, events.as_mut_ptr() as u64, 1, 0),
            ) != Some(1)
            {
                return Err("PID 1 epoll did not observe stacked-bind READY=1");
            }
            let mut received = [0u8; 64];
            if call(
                Syscall::SocketRecv.raw(),
                a3(rx, received.as_mut_ptr() as u64, received.len() as u64, 0),
            ) != Some(payload.len() as i64)
                || &received[..payload.len()] != payload
            {
                return Err("PID 1 did not receive stacked-bind READY=1");
            }
            Ok(())
        })();

        set_task(SERVICE_TASK);
        crate::handlers::clear_current_mount_namespace_for_test();
        set_task(MANAGER_TASK);
        let _ = registry().unmount(&private, PRIVATE_MOUNT);
        let _ = registry().unmount(&source, SOURCE_MOUNT);
        set_task(FAKE_TASK);
        result
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_notify_sendmsg_through_stacked_file_bind
);

/// Pathname AF_UNIX sockets name filesystem inodes, not globally interned
/// strings.  Two services whose private mount namespaces overmount the same
/// `/run` directory therefore may bind the same visible notify pathname: each
/// name resolves to a different socket inode.  This is how systemd's
/// `PrivateTmp=`/mount-sandboxed services avoid colliding with host sockets.
fn smoke_abi_socket_bind_pathname_isolated_by_mount_namespace() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xC200;
        const SERVICE_TASK: u64 = 0xC201;
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const MOUNT: &str = "/abi-notify-mount-ns";
        const SOCKET: &[u8] = b"/abi-notify-mount-ns/notify.sock";

        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let global = registry()
            .mount_arc(
                &auth,
                MOUNT,
                alloc::sync::Arc::new(MemFs::with_seeds("notify-global", &[])),
            )
            .map_err(|_| "global notify mount setup failed")?;
        let result = (|| {
            set_task(MANAGER_TASK);
            let manager_rx = open_unix(SOCK_DGRAM)?;
            let (addr, alen) = unix_sockaddr(SOCKET);
            if call(
                Syscall::SocketBind.raw(),
                a2(manager_rx, addr.as_ptr() as u64, alen),
            ) != Some(0)
            {
                return Err("manager could not bind its pathname socket");
            }

            set_task(SERVICE_TASK);
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("service could not unshare its mount namespace");
            }
            let private = crate::handlers::current_mount_namespace()
                .ok_or("unshare did not install a private mount namespace")?;
            private
                .mount_arc(
                    &auth,
                    MOUNT,
                    alloc::sync::Arc::new(MemFs::with_seeds("notify-private", &[])),
                )
                .map_err(|_| "private notify mount setup failed")?;

            let service_rx = open_unix(SOCK_DGRAM)?;
            if call(
                Syscall::SocketBind.raw(),
                a2(service_rx, addr.as_ptr() as u64, alen),
            ) != Some(0)
            {
                return Err("private mount namespace collided with the manager socket");
            }
            Ok(())
        })();
        set_task(SERVICE_TASK);
        crate::handlers::clear_current_mount_namespace_for_test();
        set_task(MANAGER_TASK);
        let _ = registry().unmount(&global, MOUNT);
        set_task(FAKE_TASK);
        result
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_bind_pathname_isolated_by_mount_namespace
);

/// A bind mount is a second VFS path to the same directory inode.  AF_UNIX
/// must consequently route a pathname sent through the alias to the socket
/// bound through the source path, and reject a second bind through that alias.
/// This complements the private-overmount case above: namespace isolation
/// must not turn two aliases *within the same mount view* into different
/// socket names.
fn smoke_abi_socket_pathname_bind_mount_aliases_same_inode() -> TestResult {
    with_setup(|| {
        const SOURCE: &[u8] = b"/abi-unix-alias-source\0";
        const ALIAS: &[u8] = b"/abi-unix-alias-dest\0";
        const TMPFS: &[u8] = b"tmpfs\0";
        const MS_BIND: u64 = 1 << 12;

        if call(
            Syscall::Mount.raw(),
            SyscallArgs {
                arg0: c"none".as_ptr() as u64,
                arg1: SOURCE.as_ptr() as u64,
                arg2: TMPFS.as_ptr() as u64,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("could not mount the source directory for the AF_UNIX alias test");
        }
        if call(
            Syscall::Mount.raw(),
            SyscallArgs {
                arg0: SOURCE.as_ptr() as u64,
                arg1: ALIAS.as_ptr() as u64,
                arg3: MS_BIND,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("could not bind-mount the AF_UNIX alias directory");
        }

        let rx = open_unix(SOCK_DGRAM)?;
        let (source_addr, source_len) = unix_sockaddr(b"/abi-unix-alias-source/notify.sock");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, source_addr.as_ptr() as u64, source_len),
        ) != Some(0)
        {
            return Err("could not bind the source-path AF_UNIX socket");
        }

        let tx = open_unix(SOCK_DGRAM)?;
        let (alias_addr, alias_len) = unix_sockaddr(b"/abi-unix-alias-dest/notify.sock");
        let payload = b"alias";
        if call(
            Syscall::SocketSend.raw(),
            SyscallArgs {
                arg0: tx,
                arg1: payload.as_ptr() as u64,
                arg2: payload.len() as u64,
                arg3: 0,
                arg4: alias_addr.as_ptr() as u64,
                arg5: alias_len,
            },
        ) != Some(payload.len() as i64)
        {
            return Err("sendto through the bind-mount alias did not find the socket");
        }
        let mut received = [0u8; 16];
        if call(
            Syscall::SocketRecv.raw(),
            a3(rx, received.as_mut_ptr() as u64, received.len() as u64, 0),
        ) != Some(payload.len() as i64)
            || &received[..payload.len()] != payload
        {
            return Err("source-path socket did not receive datagram sent through its alias");
        }

        let duplicate = open_unix(SOCK_DGRAM)?;
        if call(
            Syscall::SocketBind.raw(),
            a2(duplicate, alias_addr.as_ptr() as u64, alias_len),
        ) != Some(-1)
        {
            return Err("bind through alias did not see source-path socket inode as occupied");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_pathname_bind_mount_aliases_same_inode
);

/// Linux keeps abstract AF_UNIX names in `struct net`, not in the mount
/// namespace. Two independent network namespaces may therefore bind the same
/// abstract DGRAM name; a global registry leaks traffic and spuriously returns
/// EADDRINUSE to the second service.
#[cfg(feature = "container")]
fn smoke_abi_socket_abstract_dgram_isolated_by_net_namespace() -> TestResult {
    with_setup(|| {
        const HOST_TASK: u64 = 0xC300;
        const PRIVATE_TASK: u64 = 0xC301;
        const CLONE_NEWNET: u64 = 0x4000_0000;

        crate::namespaces::__test_reset_all();
        let result = (|| {
            set_task(HOST_TASK);
            let host = open_unix(SOCK_DGRAM)?;
            let (addr, alen) = abstract_sockaddr(b"notify-netns-e2e");
            if call(
                Syscall::SocketBind.raw(),
                a2(host, addr.as_ptr() as u64, alen),
            ) != Some(0)
            {
                return Err("host netns could not bind the abstract notify socket");
            }

            set_task(PRIVATE_TASK);
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNET)) != Some(0) {
                return Err("private task could not unshare its network namespace");
            }
            let private = open_unix(SOCK_DGRAM)?;
            if call(
                Syscall::SocketBind.raw(),
                a2(private, addr.as_ptr() as u64, alen),
            ) != Some(0)
            {
                return Err("abstract socket collided across network namespaces");
            }

            let private_tx = open_unix(SOCK_DGRAM)?;
            let private_payload = b"private";
            if call(
                Syscall::SocketSend.raw(),
                SyscallArgs {
                    arg0: private_tx,
                    arg1: private_payload.as_ptr() as u64,
                    arg2: private_payload.len() as u64,
                    arg3: 0,
                    arg4: addr.as_ptr() as u64,
                    arg5: alen,
                },
            ) != Some(private_payload.len() as i64)
            {
                return Err("private netns could not send to its abstract socket");
            }
            let mut private_buf = [0u8; 16];
            if call(
                Syscall::SocketRecv.raw(),
                a3(
                    private,
                    private_buf.as_mut_ptr() as u64,
                    private_buf.len() as u64,
                    0,
                ),
            ) != Some(private_payload.len() as i64)
                || &private_buf[..private_payload.len()] != private_payload
            {
                return Err("private netns did not receive its own abstract datagram");
            }

            set_task(HOST_TASK);
            let host_tx = open_unix(SOCK_DGRAM)?;
            let host_payload = b"host";
            if call(
                Syscall::SocketSend.raw(),
                SyscallArgs {
                    arg0: host_tx,
                    arg1: host_payload.as_ptr() as u64,
                    arg2: host_payload.len() as u64,
                    arg3: 0,
                    arg4: addr.as_ptr() as u64,
                    arg5: alen,
                },
            ) != Some(host_payload.len() as i64)
            {
                return Err("host netns could not send to its abstract socket");
            }
            let mut host_buf = [0u8; 16];
            if call(
                Syscall::SocketRecv.raw(),
                a3(host, host_buf.as_mut_ptr() as u64, host_buf.len() as u64, 0),
            ) != Some(host_payload.len() as i64)
                || &host_buf[..host_payload.len()] != host_payload
            {
                return Err("host netns did not receive its own abstract datagram");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::namespaces::__test_reset_all();
        result
    })
}
#[cfg(feature = "container")]
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_abstract_dgram_isolated_by_net_namespace
);

/// connect()/sendto to an unbound abstract name is ECONNREFUSED (-111),
/// never the bare -1 sentinel.
fn smoke_abi_socket_abstract_dgram_refused() -> TestResult {
    with_setup(|| {
        let tx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = abstract_sockaddr(b"narf-abstract-nobody");
        let payload = b"x";
        let send_args = SyscallArgs {
            arg0: tx,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            arg3: 0,
            arg4: addr.as_ptr() as u64,
            arg5: alen,
        };
        let r = call(Syscall::SocketSend.raw(), send_args).ok_or("send status")?;
        if r != -111 {
            return Err("sendto() to an unbound abstract name was not ECONNREFUSED (-111)");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_abstract_dgram_refused
);

/// A second bind to a live abstract name is EADDRINUSE (-98 via the
/// dispatcher's AddrInUse → the handler's -1 sentinel is NOT used here
/// because bind maps the SockError through; assert the address is taken).
fn smoke_abi_socket_abstract_stream_inuse() -> TestResult {
    with_setup(|| {
        let a = open_unix(SOCK_STREAM)?;
        let (addr, alen) = abstract_sockaddr(b"narf-abstract-stream");
        if call(Syscall::SocketBind.raw(), a2(a, addr.as_ptr() as u64, alen))
            .ok_or("bind status")?
            != 0
        {
            return Err("first bind() to an abstract stream name failed");
        }
        // Second socket binding the SAME abstract name must fail.
        let b = open_unix(SOCK_STREAM)?;
        let r = call(Syscall::SocketBind.raw(), a2(b, addr.as_ptr() as u64, alen));
        // bind()'s handler maps a non-Ok dispatcher result to the -1 sentinel.
        if r != Some(-1) {
            return Err("second bind() to a live abstract name did not fail");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_abstract_stream_inuse);

/// Autobind: bind with `addrlen == sizeof(sa_family_t)` (2) assigns a
/// fresh abstract name; getsockname reports a usable abstract address
/// (leading NUL, non-empty).
fn smoke_abi_socket_autobind() -> TestResult {
    with_setup(|| {
        let fd = open_unix(SOCK_DGRAM)?;
        // sockaddr with ONLY the family — addrlen 2 → autobind.
        let mut addr = [0u8; 128];
        addr[0..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
        if call(Syscall::SocketBind.raw(), a2(fd, addr.as_ptr() as u64, 2)).ok_or("bind status")?
            != 0
        {
            return Err("autobind bind() did not return 0");
        }
        // getsockname must report an abstract address: family + leading NUL.
        let mut out = [0u8; 128];
        let mut outlen = [0u8; 4];
        outlen[0..4].copy_from_slice(&(out.len() as u32).to_ne_bytes());
        let r = call(
            Syscall::SocketGetSockName.raw(),
            a2(fd, out.as_mut_ptr() as u64, outlen.as_mut_ptr() as u64),
        )
        .ok_or("getsockname status")?;
        if r != 0 {
            return Err("getsockname() on an autobound socket failed");
        }
        let reported = u32::from_ne_bytes(outlen);
        // family(2) + leading NUL(1) + at least one name byte.
        if reported < 4 {
            return Err("autobind produced no abstract name");
        }
        if out[2] != 0 {
            return Err("autobind name is not in the abstract namespace (no leading NUL)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_autobind);

// ─────────────────── SO_PASSCRED / SO_PEERCRED / SCM ───────────────────

/// SO_PEERCRED on a connected socketpair reports the peer's ucred (12
/// bytes: pid, uid, gid). The two ends share this process's identity.
fn smoke_abi_socket_so_peercred() -> TestResult {
    with_setup(|| {
        let mut sv = [0u8; 8];
        if call(
            Syscall::SocketPair.raw(),
            a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64),
        )
        .ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
        let mut cred = [0u8; 12];
        let mut clen = (cred.len() as u32).to_ne_bytes();
        let r = call(
            Syscall::SocketGetSockOpt.raw(),
            SyscallArgs {
                arg0: fd0,
                arg1: SOL_SOCKET,
                arg2: SO_PEERCRED,
                arg3: cred.as_mut_ptr() as u64,
                arg4: clen.as_mut_ptr() as u64,
                arg5: 0,
            },
        )
        .ok_or("getsockopt status")?;
        if r != 0 {
            return Err("getsockopt(SO_PEERCRED) did not succeed");
        }
        if u32::from_ne_bytes(clen) != 12 {
            return Err("SO_PEERCRED did not return a 12-byte ucred");
        }
        // The peer's pid must match this task's pid (both ends are ours).
        let my_pid = call(Syscall::GetPid.raw(), a0(0)).ok_or("getpid")? as u32;
        let peer_pid = u32::from_ne_bytes([cred[0], cred[1], cred[2], cred[3]]);
        if peer_pid != my_pid {
            return Err("SO_PEERCRED pid did not match the connecting process pid");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_so_peercred);

/// SO_PASSCRED round-trips through set/getsockopt.
fn smoke_abi_socket_so_passcred_roundtrip() -> TestResult {
    with_setup(|| {
        let fd = open_unix(SOCK_STREAM)?;
        let on = 1u32.to_ne_bytes();
        let r = call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_SOCKET,
                arg2: SO_PASSCRED,
                arg3: on.as_ptr() as u64,
                arg4: on.len() as u64,
                arg5: 0,
            },
        )
        .ok_or("setsockopt status")?;
        if r != 0 {
            return Err("setsockopt(SO_PASSCRED, 1) did not succeed");
        }
        let mut out = [0u8; 4];
        let mut olen = (out.len() as u32).to_ne_bytes();
        call(
            Syscall::SocketGetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_SOCKET,
                arg2: SO_PASSCRED,
                arg3: out.as_mut_ptr() as u64,
                arg4: olen.as_mut_ptr() as u64,
                arg5: 0,
            },
        )
        .ok_or("getsockopt status")?;
        let _ = &mut olen;
        if u32::from_ne_bytes(out) != 1 {
            return Err("getsockopt(SO_PASSCRED) did not read back 1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_so_passcred_roundtrip);

/// SO_PASSCRED + recvmsg attaches an SCM_CREDENTIALS control message
/// naming the sender. Send over a socketpair, then recvmsg the other end
/// with SO_PASSCRED set and a control buffer.
fn smoke_abi_socket_recvmsg_scm_credentials() -> TestResult {
    with_setup(|| {
        let mut sv = [0u8; 8];
        if call(
            Syscall::SocketPair.raw(),
            a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64),
        )
        .ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
        let fd1 = i32::from_ne_bytes([sv[4], sv[5], sv[6], sv[7]]) as u64;

        // Enable SO_PASSCRED on the receiving end.
        let on = 1u32.to_ne_bytes();
        call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: fd1,
                arg1: SOL_SOCKET,
                arg2: SO_PASSCRED,
                arg3: on.as_ptr() as u64,
                arg4: on.len() as u64,
                arg5: 0,
            },
        )
        .ok_or("setsockopt status")?;

        let payload = b"hi";
        if call(
            Syscall::SocketSend.raw(),
            a3(fd0, payload.as_ptr() as u64, payload.len() as u64, 0),
        )
        .ok_or("send status")?
            != payload.len() as i64
        {
            return Err("priming send failed");
        }

        // recvmsg with a control buffer for the SCM_CREDENTIALS cmsg.
        let mut dst = [0u8; 16];
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
        let mut ctrl = [0u8; 64];
        let mut msg = [0u8; 56];
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes()); // iov
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes()); // iovlen
        msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes()); // ctrl
        msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes()); // ctrllen
        let n = call(
            Syscall::SocketRecvMsg.raw(),
            a2(fd1, msg.as_ptr() as u64, 0),
        )
        .ok_or("recvmsg status")?;
        if n != payload.len() as i64 {
            return Err("recvmsg() did not return the sent byte count");
        }
        // msg_controllen (offset 40) is the bytes the kernel wrote.
        let ctrllen = u64::from_ne_bytes([
            msg[40], msg[41], msg[42], msg[43], msg[44], msg[45], msg[46], msg[47],
        ]) as usize;
        if ctrllen < 16 + 12 {
            return Err("recvmsg() did not attach an SCM_CREDENTIALS cmsg");
        }
        // cmsghdr { u64 len; i32 level; i32 type; } then struct ucred.
        let level = i32::from_le_bytes([ctrl[8], ctrl[9], ctrl[10], ctrl[11]]);
        let ctype = i32::from_le_bytes([ctrl[12], ctrl[13], ctrl[14], ctrl[15]]);
        if level != SOL_SOCKET as i32 || ctype != SCM_CREDENTIALS {
            return Err("recvmsg cmsg was not SOL_SOCKET/SCM_CREDENTIALS");
        }
        let cred_pid = u32::from_le_bytes([ctrl[16], ctrl[17], ctrl[18], ctrl[19]]);
        let my_pid = call(Syscall::GetPid.raw(), a0(0)).ok_or("getpid")? as u32;
        if cred_pid != my_pid {
            return Err("SCM_CREDENTIALS pid did not name the sender");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_recvmsg_scm_credentials
);

/// The exact shape of PID 1's `$NOTIFY_SOCKET`: a bound PATH AF_UNIX/SOCK_DGRAM
/// socket with SO_PASSCRED, watched via LEVEL-TRIGGERED EPOLLIN
/// (`sd_event_add_io(..., EPOLLIN, manager_dispatch_notify_fd)`). A datagram
/// delivered from another socket — a service's `sd_notify(READY=1)` — must
/// (a) make `epoll_wait` report EPOLLIN (the wake systemd's event loop blocks
/// on) and (b) `recvmsg` with an SCM_CREDENTIALS cmsg naming the sender. If a
/// bound-dgram delivery does not surface EPOLLIN, PID 1 never reads READY=1 and
/// every Type=notify service (systemd-udevd, systemd-userdbd, dbus-broker,
/// logind, …) times out.
fn smoke_abi_socket_notify_path_dgram_epollin_deliver() -> TestResult {
    with_setup(|| {
        let rx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = unix_sockaddr(b"/run/systemd/notify-test");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind() to the notify path failed");
        }
        // SO_PASSCRED, exactly as PID 1 sets it.
        let on = 1u32.to_ne_bytes();
        call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: rx,
                arg1: SOL_SOCKET,
                arg2: SO_PASSCRED,
                arg3: on.as_ptr() as u64,
                arg4: on.len() as u64,
                arg5: 0,
            },
        )
        .ok_or("setsockopt status")?;

        // Level-triggered EPOLLIN (NO EPOLLET) — how sd_event watches the fd.
        let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create status")?;
        if epfd < 0 {
            return Err("epoll_create failed");
        }
        let mut interest = [0u8; 12];
        interest[..4].copy_from_slice(&1u32.to_ne_bytes()); // EPOLLIN
        interest[4..].copy_from_slice(&0x4E4F_5449_4659u64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            a3(epfd as u64, 1, rx, interest.as_ptr() as u64),
        )
        .ok_or("epoll_ctl status")?
            != 0
        {
            return Err("epoll_ctl ADD EPOLLIN failed");
        }
        // Nothing delivered yet → epoll_wait(timeout 0) reports no events.
        let mut evt = [0u8; 12];
        if call(
            Syscall::EpollWait.raw(),
            a3(epfd as u64, evt.as_mut_ptr() as u64, 1, 0),
        )
        .ok_or("epoll_wait status")?
            != 0
        {
            return Err("empty notify socket must not report EPOLLIN");
        }

        // A service delivers sd_notify(READY=1) from its own datagram socket.
        let tx = open_unix(SOCK_DGRAM)?;
        let payload = b"READY=1\n";
        let sent = call(
            Syscall::SocketSend.raw(),
            SyscallArgs {
                arg0: tx,
                arg1: payload.as_ptr() as u64,
                arg2: payload.len() as u64,
                arg4: addr.as_ptr() as u64,
                arg5: alen,
                ..SyscallArgs::default()
            },
        )
        .ok_or("send status")?;
        if sent != payload.len() as i64 {
            return Err("sendto() to the notify path failed");
        }

        // epoll must now report EPOLLIN — the exact wake PID 1's sd_event needs.
        if call(
            Syscall::EpollWait.raw(),
            a3(epfd as u64, evt.as_mut_ptr() as u64, 1, 0),
        )
        .ok_or("epoll_wait status")?
            != 1
        {
            return Err("delivered notify datagram must report EPOLLIN to epoll");
        }

        // recvmsg it, with an SCM_CREDENTIALS cmsg naming the sender.
        let mut dst = [0u8; 16];
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
        let mut ctrl = [0u8; 64];
        let mut msg = [0u8; 56];
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
        msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
        let n = call(Syscall::SocketRecvMsg.raw(), a2(rx, msg.as_ptr() as u64, 0))
            .ok_or("recvmsg status")?;
        if n != payload.len() as i64 || &dst[..payload.len()] != payload {
            return Err("recvmsg did not return the READY=1 datagram");
        }
        let ctrllen = u64::from_ne_bytes([
            msg[40], msg[41], msg[42], msg[43], msg[44], msg[45], msg[46], msg[47],
        ]) as usize;
        if ctrllen < 16 + 12 {
            return Err("notify recvmsg did not attach SCM_CREDENTIALS");
        }
        let ctype = i32::from_le_bytes([ctrl[12], ctrl[13], ctrl[14], ctrl[15]]);
        if ctype != SCM_CREDENTIALS {
            return Err("notify cmsg was not SCM_CREDENTIALS");
        }
        let cred_pid = u32::from_le_bytes([ctrl[16], ctrl[17], ctrl[18], ctrl[19]]);
        let my_pid = call(Syscall::GetPid.raw(), a0(0)).ok_or("getpid")? as u32;
        if cred_pid != my_pid {
            return Err("notify SCM_CREDENTIALS pid did not name the sender");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_notify_path_dgram_epollin_deliver
);

/// SCM_RIGHTS: sendmsg an fd over one socketpair half, recvmsg the other
/// half, and confirm a NEW fd (different number, usable) was installed.
fn smoke_abi_socket_scm_rights_fd_passing() -> TestResult {
    with_setup(|| {
        let mut sv = [0u8; 8];
        if call(
            Syscall::SocketPair.raw(),
            a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64),
        )
        .ok_or("pair status")?
            != 0
        {
            return Err("socketpair setup failed");
        }
        let fd0 = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
        let fd1 = i32::from_ne_bytes([sv[4], sv[5], sv[6], sv[7]]) as u64;

        // Queue ordinary stream bytes before the fd-bearing message. Rights
        // must remain attached to the latter's first byte rather than being
        // stolen by the first receive.
        let prefix = b"plain";
        if call(
            Syscall::SocketSend.raw(),
            a3(fd0, prefix.as_ptr() as u64, prefix.len() as u64, 0),
        ) != Some(prefix.len() as i64)
        {
            return Err("ordinary prefix send failed");
        }

        // The fd we pass: an independent nonblocking socket.
        // systemd hands dbus-broker its activation listener in exactly this
        // shape. SCM_RIGHTS duplicates the open file description, so Linux
        // preserves O_NONBLOCK on the descriptor installed by recvmsg.
        let passed_fd = call(
            Syscall::SocketOpen.raw(),
            a2(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0),
        )
        .ok_or("nonblocking socket status")? as i32;
        if passed_fd < 0 {
            return Err("nonblocking socket setup failed");
        }

        // sendmsg with an SCM_RIGHTS cmsg carrying `passed_fd`.
        let payload = b"fd";
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
        // cmsghdr(16) + one int fd(4), padded to 8 → 24 bytes of control.
        let mut ctrl = [0u8; 24];
        let cmsg_len = (16 + 4) as u64;
        ctrl[0..8].copy_from_slice(&cmsg_len.to_le_bytes());
        ctrl[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_le_bytes());
        ctrl[12..16].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
        ctrl[16..20].copy_from_slice(&passed_fd.to_le_bytes());
        let mut smsg = [0u8; 56];
        smsg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        smsg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        smsg[32..40].copy_from_slice(&(ctrl.as_ptr() as u64).to_ne_bytes());
        smsg[40..48].copy_from_slice(&(24u64).to_le_bytes());
        let sent = call(
            Syscall::SocketSendMsg.raw(),
            a2(fd0, smsg.as_ptr() as u64, 0),
        )
        .ok_or("sendmsg status")?;
        if sent != payload.len() as i64 {
            return Err("sendmsg(SCM_RIGHTS) did not return the payload byte count");
        }

        let mut prefix_out = [0u8; 5];
        if call(
            Syscall::SocketRecv.raw(),
            a3(
                fd1,
                prefix_out.as_mut_ptr() as u64,
                prefix_out.len() as u64,
                0,
            ),
        ) != Some(prefix.len() as i64)
            || &prefix_out != prefix
        {
            return Err("ordinary prefix receive failed");
        }

        // recvmsg the other half with a control buffer.
        let mut dst = [0u8; 16];
        let mut riov = [0u8; 16];
        riov[0..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
        riov[8..16].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
        let mut rctrl = [0u8; 64];
        let mut rmsg = [0u8; 56];
        rmsg[16..24].copy_from_slice(&(riov.as_ptr() as u64).to_ne_bytes());
        rmsg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        rmsg[32..40].copy_from_slice(&(rctrl.as_mut_ptr() as u64).to_ne_bytes());
        rmsg[40..48].copy_from_slice(&(rctrl.len() as u64).to_ne_bytes());
        let n = call(
            Syscall::SocketRecvMsg.raw(),
            a2(fd1, rmsg.as_ptr() as u64, 0),
        )
        .ok_or("recvmsg status")?;
        if n != payload.len() as i64 {
            return Err("recvmsg() did not return the sent byte count");
        }
        let ctrllen = u64::from_ne_bytes([
            rmsg[40], rmsg[41], rmsg[42], rmsg[43], rmsg[44], rmsg[45], rmsg[46], rmsg[47],
        ]) as usize;
        if ctrllen < 16 + 4 {
            return Err("recvmsg() did not attach an SCM_RIGHTS cmsg");
        }
        let level = i32::from_le_bytes([rctrl[8], rctrl[9], rctrl[10], rctrl[11]]);
        let ctype = i32::from_le_bytes([rctrl[12], rctrl[13], rctrl[14], rctrl[15]]);
        if level != SOL_SOCKET as i32 || ctype != SCM_RIGHTS {
            return Err("recvmsg cmsg was not SOL_SOCKET/SCM_RIGHTS");
        }
        let new_fd = i32::from_le_bytes([rctrl[16], rctrl[17], rctrl[18], rctrl[19]]);
        if new_fd < 0 {
            return Err("SCM_RIGHTS did not install a valid fd");
        }
        // The received fd is a distinct number, and closeable.
        if new_fd as u64 == fd1 {
            return Err("SCM_RIGHTS installed fd collided with the receiving fd");
        }
        let installed_status = fd::with_table(FAKE_TASK, |table| {
            table.get(new_fd as u32).map(|entry| entry.status_flags)
        })
        .flatten()
        .ok_or("received SCM_RIGHTS fd was absent from the fd table")?;
        if installed_status & O_NONBLOCK as u32 == 0 {
            return Err("SCM_RIGHTS receiver fd lost its O_NONBLOCK status");
        }
        let received_status = call(Syscall::Fcntl.raw(), a2(new_fd as u64, F_GETFL, 0))
            .ok_or("F_GETFL on received SCM_RIGHTS fd failed")?;
        if received_status & O_NONBLOCK == 0 {
            return Err("SCM_RIGHTS did not preserve O_NONBLOCK");
        }
        let _ = call(Syscall::Close.raw(), a0(new_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_socket_scm_rights_fd_passing);

/// AF_UNIX datagrams carry SCM_RIGHTS too. This exercises the complete syscall
/// path used by sd_notify FDSTORE: sendmsg parses the control record, the
/// datagram queue preserves it with the payload, recvmsg installs a fresh
/// receiver fd, and the returned cmsghdr names that new fd.
fn smoke_abi_socket_dgram_scm_rights_fd_passing() -> TestResult {
    with_setup(|| {
        let rx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = abstract_sockaddr(b"narf-dgram-scm-rights");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("AF_UNIX datagram receiver bind failed");
        }
        // PID 1 enables SO_PASSCRED on its notify socket: the received
        // credentials identify which service sent READY=/FDSTORE=.
        let on = 1u32.to_ne_bytes();
        if call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: rx,
                arg1: SOL_SOCKET,
                arg2: SO_PASSCRED,
                arg3: on.as_ptr() as u64,
                arg4: on.len() as u64,
                arg5: 0,
            },
        ) != Some(0)
        {
            return Err("enabling SO_PASSCRED on datagram receiver failed");
        }
        let tx = open_unix(SOCK_DGRAM)?;

        // Supply a real, independently open descriptor as SCM_RIGHTS data.
        let mut pair = [0u8; 8];
        if call(
            Syscall::SocketPair.raw(),
            a3(AF_UNIX, SOCK_STREAM, 0, pair.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("passed-fd socketpair setup failed");
        }
        let passed_fd = i32::from_ne_bytes([pair[0], pair[1], pair[2], pair[3]]);

        let payload = b"FDSTORE=1";
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
        let mut ctrl = [0u8; 24];
        ctrl[0..8].copy_from_slice(&(20u64).to_ne_bytes()); // cmsghdr + one fd
        ctrl[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
        ctrl[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
        ctrl[16..20].copy_from_slice(&passed_fd.to_ne_bytes());
        let mut smsg = [0u8; 56];
        smsg[0..8].copy_from_slice(&(addr.as_ptr() as u64).to_ne_bytes());
        smsg[8..16].copy_from_slice(&alen.to_ne_bytes());
        smsg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        smsg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        smsg[32..40].copy_from_slice(&(ctrl.as_ptr() as u64).to_ne_bytes());
        smsg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
        if call(
            Syscall::SocketSendMsg.raw(),
            a2(tx, smsg.as_ptr() as u64, 0),
        ) != Some(payload.len() as i64)
        {
            return Err("dgram sendmsg(SCM_RIGHTS) did not send its payload");
        }

        let mut dst = [0u8; 32];
        let mut riov = [0u8; 16];
        riov[0..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
        riov[8..16].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
        let mut rctrl = [0u8; 64];
        let mut rmsg = [0u8; 56];
        rmsg[16..24].copy_from_slice(&(riov.as_ptr() as u64).to_ne_bytes());
        rmsg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        rmsg[32..40].copy_from_slice(&(rctrl.as_mut_ptr() as u64).to_ne_bytes());
        rmsg[40..48].copy_from_slice(&(rctrl.len() as u64).to_ne_bytes());
        if call(
            Syscall::SocketRecvMsg.raw(),
            a2(rx, rmsg.as_ptr() as u64, 0),
        ) != Some(payload.len() as i64)
            || &dst[..payload.len()] != payload
        {
            return Err("dgram recvmsg did not receive the FDSTORE datagram");
        }
        let ctrllen = u64::from_ne_bytes(rmsg[40..48].try_into().unwrap()) as usize;
        if ctrllen < 56 {
            return Err("dgram recvmsg did not return rights and credentials");
        }
        let level = i32::from_ne_bytes(rctrl[8..12].try_into().unwrap());
        let ctype = i32::from_ne_bytes(rctrl[12..16].try_into().unwrap());
        if level != SOL_SOCKET as i32 || ctype != SCM_RIGHTS {
            return Err("dgram recvmsg returned the wrong ancillary record");
        }
        let received_fd = i32::from_ne_bytes(rctrl[16..20].try_into().unwrap());
        if received_fd < 0 || received_fd as u64 == rx {
            return Err("dgram recvmsg did not install a distinct receiver fd");
        }
        // The rights cmsg is padded to 24 bytes; SCM_CREDENTIALS follows it.
        let cred_level = i32::from_ne_bytes(rctrl[32..36].try_into().unwrap());
        let cred_type = i32::from_ne_bytes(rctrl[36..40].try_into().unwrap());
        let cred_pid = u32::from_ne_bytes(rctrl[40..44].try_into().unwrap());
        let sender_pid = call(Syscall::GetPid.raw(), a0(0)).ok_or("getpid")? as u32;
        if cred_level != SOL_SOCKET as i32 || cred_type != SCM_CREDENTIALS || cred_pid != sender_pid
        {
            return Err("dgram SCM_CREDENTIALS did not name the sender");
        }
        if call(Syscall::Close.raw(), a0(received_fd as u64)) != Some(0) {
            return Err("dgram SCM_RIGHTS fd was not usable by the receiver");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_dgram_scm_rights_fd_passing
);

/// Closing a duplicated listener fd must not unbind the listener while the
/// original fd remains open (dbus-broker receives its listener this way).
fn smoke_abi_socket_dup_listener_close_keeps_binding() -> TestResult {
    with_setup(|| {
        let listener = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-dup-listener");
        if call(
            Syscall::SocketBind.raw(),
            a2(listener, addr.as_ptr() as u64, alen),
        ) != Some(0)
            || call(Syscall::SocketListen.raw(), a1(listener, 16)) != Some(0)
        {
            return Err("listener setup failed");
        }
        let duplicate =
            call(Syscall::Fcntl.raw(), a2(listener, F_DUPFD_CLOEXEC, 20)).ok_or("fcntl status")?;
        if duplicate < 0 || call(Syscall::Close.raw(), a0(duplicate as u64)) != Some(0) {
            return Err("listener duplicate/close failed");
        }
        let client = open_unix_stream()?;
        if call(
            Syscall::SocketConnect.raw(),
            a2(client, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("closing duplicate unbound the live listener");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_dup_listener_close_keeps_binding
);

// ───────────────────────────── AF_NETLINK ─────────────────────────────
//
// systemd-udevd / systemd-networkd open AF_NETLINK sockets: NETLINK_ROUTE
// (protocol 0) for the RTM_GETLINK / RTM_GETADDR interface+address dump, and
// NETLINK_KOBJECT_UEVENT (protocol 15) to monitor device hotplug uevents.

const AF_NETLINK: u64 = 16;
const SOCK_RAW: u64 = 3;
const NETLINK_ROUTE: u64 = 0;
const NETLINK_KOBJECT_UEVENT: u64 = 15;
const SOL_NETLINK: u64 = 270;
const NETLINK_ADD_MEMBERSHIP: u64 = 1;
const NETLINK_EXT_ACK: u64 = 11;
const NETLINK_LIST_MEMBERSHIPS: u64 = 9;
const SIOCINQ: u64 = 0x541B;
/// rtnetlink message types (rtnetlink.h).
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const RTM_GETNEIGH: u16 = 30;
const RTM_NEWRULE: u16 = 32;
const RTM_GETRULE: u16 = 34;
const RTM_NEWQDISC: u16 = 36;
const RTM_GETQDISC: u16 = 38;
const RTM_GETTFILTER: u16 = 46;
/// netlink control message types (netlink.h).
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLMSG_HDRLEN: usize = 16;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
/// `NLM_F_REQUEST | NLM_F_DUMP` — the flags a dump request carries.
const NLM_F_REQUEST_DUMP: u16 = 0x01 | (0x100 | 0x200);

/// Open an `AF_NETLINK` socket of the given protocol, returning its fd.
fn open_netlink(protocol: u64) -> Result<u64, &'static str> {
    match call(
        Syscall::SocketOpen.raw(),
        a2(AF_NETLINK, SOCK_RAW, protocol),
    ) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("socket(AF_NETLINK) did not return a valid fd"),
    }
}

/// Build a `sockaddr_nl`: family(u16) pad(u16) pid(u32) groups(u32) = 12 bytes.
fn netlink_sockaddr(groups: u32) -> ([u8; 12], u64) {
    let mut buf = [0u8; 12];
    buf[0..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
    buf[8..12].copy_from_slice(&groups.to_le_bytes());
    (buf, 12)
}

fn netlink_sockaddr_port(portid: u32) -> ([u8; 12], u64) {
    let mut buf = [0u8; 12];
    buf[0..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
    buf[4..8].copy_from_slice(&portid.to_ne_bytes());
    (buf, 12)
}

/// Build a `struct nlmsghdr` dump request: len(16) type flags(REQUEST|DUMP)
/// seq pid.
fn nlmsg_request(msg_type: u16, seq: u32) -> [u8; NLMSG_HDRLEN] {
    let mut b = [0u8; NLMSG_HDRLEN];
    b[0..4].copy_from_slice(&(NLMSG_HDRLEN as u32).to_le_bytes());
    b[4..6].copy_from_slice(&msg_type.to_le_bytes());
    b[6..8].copy_from_slice(&NLM_F_REQUEST_DUMP.to_le_bytes());
    b[8..12].copy_from_slice(&seq.to_le_bytes());
    // pid = 0 (unbound); the kernel echoes it back.
    b
}

/// Read the `nlmsg_type` field (offset 4) of a framed netlink message.
fn nlmsg_type_of(msg: &[u8]) -> u16 {
    u16::from_le_bytes([msg[4], msg[5]])
}

/// sendto(fd, buf, len, 0, NULL, 0).
fn netlink_send(fd: u64, buf: &[u8]) -> Option<i64> {
    let mut args = a3(fd, buf.as_ptr() as u64, buf.len() as u64, 0);
    args.arg4 = 0;
    args.arg5 = 0;
    call(Syscall::SocketSend.raw(), args)
}

/// recvfrom(fd, buf, len, MSG_DONTWAIT, NULL, NULL).
fn netlink_recv(fd: u64, buf: &mut [u8]) -> Option<i64> {
    netlink_recv_flags(fd, buf, MSG_DONTWAIT)
}

fn netlink_recv_flags(fd: u64, buf: &mut [u8], flags: u64) -> Option<i64> {
    call(
        Syscall::SocketRecv.raw(),
        a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, flags),
    )
}

fn netlink_inq(fd: u64) -> Result<u32, &'static str> {
    let mut bytes = 0u32;
    let result = call(
        Syscall::Ioctl.raw(),
        a2(fd, SIOCINQ, (&mut bytes as *mut u32) as u64),
    )
    .ok_or("ioctl status")?;
    if result != 0 {
        return Err("SIOCINQ did not return success");
    }
    Ok(bytes)
}

fn netlink_set_u32(fd: u64, option: u64, value: u32) -> Result<(), &'static str> {
    let value = value.to_ne_bytes();
    let result = call(
        Syscall::SocketSetSockOpt.raw(),
        SyscallArgs {
            arg0: fd,
            arg1: SOL_NETLINK,
            arg2: option,
            arg3: value.as_ptr() as u64,
            arg4: value.len() as u64,
            arg5: 0,
        },
    )
    .ok_or("setsockopt status")?;
    if result != 0 {
        return Err("SOL_NETLINK setsockopt failed");
    }
    Ok(())
}

fn smoke_abi_netlink_route_socket_bind() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let (addr, alen) = netlink_sockaddr(0);
        let r = call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?;
        if r != 0 {
            return Err("bind(NETLINK_ROUTE) did not return 0");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_socket_bind);

fn smoke_abi_netlink_route_siocinq() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETLINK, 40);
        if netlink_send(fd, &req).ok_or("route send")? != req.len() as i64 {
            return Err("RTM_GETLINK send failed");
        }
        let queued = netlink_inq(fd)?;
        if queued < NLMSG_HDRLEN as u32 {
            return Err("SIOCINQ did not report the queued route datagram");
        }
        let mut reply = [0u8; 512];
        let received = netlink_recv(fd, &mut reply).ok_or("route recv")?;
        if received != queued as i64 {
            return Err("SIOCINQ route size disagreed with recv length");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_siocinq);

fn smoke_abi_netlink_route_msg_peek() -> TestResult {
    with_setup(|| {
        const MSG_PEEK: u64 = 0x02;
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETLINK, 41);
        if netlink_send(fd, &req).ok_or("route send")? != req.len() as i64 {
            return Err("RTM_GETLINK send failed");
        }
        let queued = netlink_inq(fd)?;
        let mut peeked = [0u8; 512];
        let peek_n =
            netlink_recv_flags(fd, &mut peeked, MSG_DONTWAIT | MSG_PEEK).ok_or("peek recv")?;
        if peek_n != queued as i64 || netlink_inq(fd)? != queued {
            return Err("MSG_PEEK consumed or resized the queued netlink datagram");
        }
        let mut consumed = [0u8; 512];
        let recv_n = netlink_recv(fd, &mut consumed).ok_or("consume recv")?;
        if recv_n != peek_n || consumed[..recv_n as usize] != peeked[..peek_n as usize] {
            return Err("MSG_PEEK bytes differed from the consumed netlink datagram");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_msg_peek);

fn smoke_abi_netlink_route_msg_trunc() -> TestResult {
    with_setup(|| {
        const MSG_TRUNC: u64 = 0x20;
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETLINK, 42);

        if netlink_send(fd, &req).ok_or("first route send")? != req.len() as i64 {
            return Err("first RTM_GETLINK send failed");
        }
        let mut short = [0xA5u8; 8];
        let copied = netlink_recv_flags(fd, &mut short, MSG_DONTWAIT).ok_or("short normal recv")?;
        if copied != short.len() as i64 {
            return Err("short netlink recv did not return copied length");
        }

        if netlink_send(fd, &req).ok_or("second route send")? != req.len() as i64 {
            return Err("second RTM_GETLINK send failed");
        }
        let full = netlink_inq(fd)?;
        let mut truncated = [0x5Au8; 8];
        let returned = netlink_recv_flags(fd, &mut truncated, MSG_DONTWAIT | MSG_TRUNC)
            .ok_or("MSG_TRUNC recv")?;
        if returned != full as i64 || returned <= truncated.len() as i64 {
            return Err("MSG_TRUNC did not return the full netlink datagram length");
        }
        if truncated == [0x5A; 8] {
            return Err("MSG_TRUNC did not copy the available prefix");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_msg_trunc);

/// Every unicast rtnetlink reply must carry `nlmsg_pid == <bound port id>`.
/// sd-netlink's `parse_message_one` silently drops any non-broadcast message
/// whose `nlmsg_pid` differs from the socket's own port; the real kernel stamps
/// a unicast reply's `nlmsg_pid` with the recipient's port (`netlink_ack` /
/// `__nlmsg_put`). With a zero `nlmsg_pid`, systemd's `loopback_setup` never
/// sees the ack for its RTM_NEWADDR/RTM_SETLINK requests, so `n_messages` never
/// reaches zero and it spins in `ppoll` forever — wedging PID 1 boot right after
/// the "Welcome to …" banner. This covers dump entries, NLMSG_DONE, and the
/// NLMSG_ERROR ack path (the exact loopback_setup request shape).
fn smoke_abi_netlink_reply_pid_matches_bound_port() -> TestResult {
    with_setup(|| {
        const AF_INET_ADDR: u8 = 2;
        const IFA_LOCAL: u16 = 2;

        let fd = open_netlink(NETLINK_ROUTE)?;

        // A dump: RTM_GETLINK → one or more RTM_NEWLINK + a terminating
        // NLMSG_DONE. The send allocates the socket's port id.
        let req = nlmsg_request(RTM_GETLINK, 77);
        if netlink_send(fd, &req).ok_or("dump send")? != req.len() as i64 {
            return Err("RTM_GETLINK send failed");
        }

        let mut local = [0u8; 12];
        let mut local_len = (local.len() as u32).to_ne_bytes();
        if call(
            Syscall::SocketGetSockName.raw(),
            a2(fd, local.as_mut_ptr() as u64, local_len.as_mut_ptr() as u64),
        )
        .ok_or("getsockname status")?
            != 0
        {
            return Err("netlink getsockname failed");
        }
        let portid = u32::from_ne_bytes(local[4..8].try_into().unwrap());
        if portid == 0 {
            return Err("netlink port id was not allocated");
        }

        // Every message in the dump must be stamped with our port id.
        let mut saw_done = false;
        for _ in 0..64 {
            let mut reply = [0u8; 1024];
            let n = netlink_recv(fd, &mut reply).ok_or("dump recv")?;
            if n < NLMSG_HDRLEN as i64 {
                return Err("dump recv returned a short message");
            }
            let msg_pid = u32::from_ne_bytes(reply[12..16].try_into().unwrap());
            if msg_pid != portid {
                return Err("dump reply nlmsg_pid did not match the bound port id");
            }
            if nlmsg_type_of(&reply) == NLMSG_DONE {
                saw_done = true;
                break;
            }
        }
        if !saw_done {
            return Err("dump did not terminate with NLMSG_DONE");
        }

        // The NLMSG_ERROR ack path: RTM_NEWADDR(127.0.0.1/8 on lo) with
        // NLM_F_ACK — the exact request systemd's loopback_setup enqueues. It
        // fails with EPERM here (no admin capability), but the error ack must
        // still carry our port id so the caller's wait loop can complete.
        let mut add = [0u8; 32];
        add[0..4].copy_from_slice(&32u32.to_le_bytes());
        add[4..6].copy_from_slice(&RTM_NEWADDR.to_le_bytes());
        add[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_le_bytes());
        add[8..12].copy_from_slice(&88u32.to_le_bytes());
        // struct ifaddrmsg: family, prefixlen, flags, scope, index(u32).
        add[16] = AF_INET_ADDR;
        add[17] = 8;
        add[20..24].copy_from_slice(&1u32.to_ne_bytes());
        // rtattr IFA_LOCAL = 127.0.0.1 (len includes the 4-byte header).
        add[24..26].copy_from_slice(&8u16.to_le_bytes());
        add[26..28].copy_from_slice(&IFA_LOCAL.to_le_bytes());
        add[28..32].copy_from_slice(&[127, 0, 0, 1]);

        if netlink_send(fd, &add).ok_or("newaddr send")? != add.len() as i64 {
            return Err("RTM_NEWADDR send failed");
        }
        let mut ack = [0u8; 512];
        let an = netlink_recv(fd, &mut ack).ok_or("ack recv")?;
        if an < NLMSG_HDRLEN as i64 {
            return Err("ack recv returned a short message");
        }
        if nlmsg_type_of(&ack) != NLMSG_ERROR {
            return Err("RTM_NEWADDR ack was not NLMSG_ERROR");
        }
        if i32::from_ne_bytes(ack[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap())
            != EPERM as i32
        {
            return Err("ordinary route socket gained loopback admin authority");
        }
        let ack_pid = u32::from_ne_bytes(ack[12..16].try_into().unwrap());
        if ack_pid != portid {
            return Err("NLMSG_ERROR ack nlmsg_pid did not match the bound port id");
        }

        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_reply_pid_matches_bound_port
);

/// systemd PID 1 creates a route socket during early boot and sends this
/// RTM_SETLINK request for synthetic loopback. The kernel grants only this
/// socket a loopback-bound handle; ordinary sockets remain covered by the
/// preceding EPERM regression test.
fn smoke_abi_netlink_pid1_can_start_loopback() -> TestResult {
    with_setup(|| {
        const AF_INET: u8 = 2;
        const AF_INET6: u8 = 10;
        const IFA_LOCAL: u16 = 2;
        const EEXIST: i32 = -17;

        crate::handlers::register_task_to_pid(FAKE_TASK, 1);
        let fd = open_netlink(NETLINK_ROUTE)?;

        // struct ifinfomsg: family/pad/type/index/flags/change. This is the
        // sd_rtnl_message_link_set_flags(IFF_UP, IFF_UP) request emitted by
        // systemd's loopback_setup().
        let mut set_link = [0u8; 32];
        set_link[0..4].copy_from_slice(&32u32.to_ne_bytes());
        set_link[4..6].copy_from_slice(&RTM_SETLINK.to_ne_bytes());
        set_link[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        set_link[8..12].copy_from_slice(&89u32.to_ne_bytes());
        set_link[20..24].copy_from_slice(&1i32.to_ne_bytes());
        set_link[24..28].copy_from_slice(&1u32.to_ne_bytes()); // IFF_UP
        set_link[28..32].copy_from_slice(&1u32.to_ne_bytes()); // IFF_UP mask

        if netlink_send(fd, &set_link).ok_or("setlink send")? != set_link.len() as i64 {
            return Err("PID 1 RTM_SETLINK send failed");
        }
        let mut ack = [0u8; 512];
        let received = netlink_recv(fd, &mut ack).ok_or("setlink recv")?;
        if received < (NLMSG_HDRLEN + 4) as i64 || nlmsg_type_of(&ack) != NLMSG_ERROR {
            return Err("PID 1 RTM_SETLINK did not receive an NLMSG_ERROR ack");
        }
        if i32::from_ne_bytes(ack[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap()) != 0 {
            return Err("PID 1 RTM_SETLINK loopback ack was not successful");
        }

        // Linux creates the two loopback addresses before userspace starts.
        // systemd intentionally re-adds them and treats EEXIST as success, so
        // model their built-in state rather than granting a one-off bypass.
        let mut add_v4 = [0u8; 32];
        add_v4[0..4].copy_from_slice(&32u32.to_ne_bytes());
        add_v4[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
        add_v4[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        add_v4[8..12].copy_from_slice(&90u32.to_ne_bytes());
        add_v4[16] = AF_INET;
        add_v4[17] = 8;
        add_v4[20..24].copy_from_slice(&1u32.to_ne_bytes());
        add_v4[24..26].copy_from_slice(&8u16.to_ne_bytes());
        add_v4[26..28].copy_from_slice(&IFA_LOCAL.to_ne_bytes());
        add_v4[28..32].copy_from_slice(&[127, 0, 0, 1]);

        if netlink_send(fd, &add_v4).ok_or("ipv4 add send")? != add_v4.len() as i64 {
            return Err("PID 1 RTM_NEWADDR IPv4 send failed");
        }
        let received = netlink_recv(fd, &mut ack).ok_or("ipv4 add recv")?;
        if received < (NLMSG_HDRLEN + 4) as i64
            || i32::from_ne_bytes(ack[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap()) != EEXIST
        {
            return Err("PID 1 RTM_NEWADDR IPv4 did not report built-in loopback state");
        }

        let mut add_v6 = [0u8; 44];
        add_v6[0..4].copy_from_slice(&44u32.to_ne_bytes());
        add_v6[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
        add_v6[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        add_v6[8..12].copy_from_slice(&91u32.to_ne_bytes());
        add_v6[16] = AF_INET6;
        add_v6[17] = 128;
        add_v6[20..24].copy_from_slice(&1u32.to_ne_bytes());
        add_v6[24..26].copy_from_slice(&20u16.to_ne_bytes());
        add_v6[26..28].copy_from_slice(&IFA_LOCAL.to_ne_bytes());
        add_v6[43] = 1;

        if netlink_send(fd, &add_v6).ok_or("ipv6 add send")? != add_v6.len() as i64 {
            return Err("PID 1 RTM_NEWADDR IPv6 send failed");
        }
        let received = netlink_recv(fd, &mut ack).ok_or("ipv6 add recv")?;
        if received < (NLMSG_HDRLEN + 4) as i64
            || i32::from_ne_bytes(ack[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap()) != EEXIST
        {
            return Err("PID 1 RTM_NEWADDR IPv6 did not report built-in loopback state");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_pid1_can_start_loopback
);

fn smoke_abi_netlink_address_and_options_roundtrip() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let (addr, alen) = netlink_sockaddr(0);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("netlink bind failed");
        }

        // Join group 2 via the Linux SOL_NETLINK membership API.
        let group = 2u32.to_ne_bytes();
        let r = call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_NETLINK,
                arg2: NETLINK_ADD_MEMBERSHIP,
                arg3: group.as_ptr() as u64,
                arg4: group.len() as u64,
                arg5: 0,
            },
        )
        .ok_or("membership status")?;
        if r != 0 {
            return Err("NETLINK_ADD_MEMBERSHIP failed");
        }

        let mut local = [0u8; 12];
        let mut local_len = (local.len() as u32).to_ne_bytes();
        if call(
            Syscall::SocketGetSockName.raw(),
            a2(fd, local.as_mut_ptr() as u64, local_len.as_mut_ptr() as u64),
        )
        .ok_or("getsockname status")?
            != 0
        {
            return Err("netlink getsockname failed");
        }
        let portid = u32::from_ne_bytes(local[4..8].try_into().unwrap());
        let groups = u32::from_ne_bytes(local[8..12].try_into().unwrap());
        if portid == 0 || groups != 0b10 {
            return Err("netlink local port ID/groups did not round-trip");
        }

        let enabled = 1u32.to_ne_bytes();
        call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_NETLINK,
                arg2: NETLINK_EXT_ACK,
                arg3: enabled.as_ptr() as u64,
                arg4: enabled.len() as u64,
                arg5: 0,
            },
        )
        .ok_or("set NETLINK_EXT_ACK")?;
        let mut out = [0u8; 4];
        let mut out_len = 4u32.to_ne_bytes();
        call(
            Syscall::SocketGetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_NETLINK,
                arg2: NETLINK_EXT_ACK,
                arg3: out.as_mut_ptr() as u64,
                arg4: out_len.as_mut_ptr() as u64,
                arg5: 0,
            },
        )
        .ok_or("get NETLINK_EXT_ACK")?;
        if u32::from_ne_bytes(out) != 1 {
            return Err("NETLINK_EXT_ACK did not round-trip");
        }

        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_address_and_options_roundtrip
);

fn smoke_abi_netlink_uevent_socket_bind() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_KOBJECT_UEVENT)?;
        // group 1 = the kernel uevent broadcast group.
        let (addr, alen) = netlink_sockaddr(1);
        let r = call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?;
        if r != 0 {
            return Err("bind(NETLINK_KOBJECT_UEVENT) did not return 0");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_uevent_socket_bind);

// sd-netlink's netlink_socket_get_multicast_groups() probes the required
// bitmap length with getsockopt(SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, NULL,
// &len) where *len starts at 0. It runs on EVERY sd_netlink_open() (loopback
// setup, udev, rtnetlink). NARF's getsockopt handler previously rejected the
// NULL/zero-length probe with -1, which libc maps to EPERM — the exact cause
// of systemd PID 1's "Failed to open netlink, ignoring: Operation not
// permitted". This test reproduces the probe and asserts it now succeeds and
// reports the required length, and that the follow-up bitmap read agrees.
fn smoke_abi_netlink_list_memberships_length_probe() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;

        // A fresh socket has joined no groups: the NULL-optval, *optlen=0
        // probe must succeed (return 0) and report a required length of 0.
        let mut probe_len = 0u32.to_ne_bytes();
        let r = call(
            Syscall::SocketGetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_NETLINK,
                arg2: NETLINK_LIST_MEMBERSHIPS,
                arg3: 0, // optval == NULL, the sd-netlink probe form
                arg4: probe_len.as_mut_ptr() as u64,
                arg5: 0,
            },
        )
        .ok_or("list-memberships probe status")?;
        if r != 0 {
            return Err("NETLINK_LIST_MEMBERSHIPS NULL probe did not return 0 (was EPERM)");
        }
        if u32::from_ne_bytes(probe_len) != 0 {
            return Err("empty NETLINK_LIST_MEMBERSHIPS probe reported nonzero length");
        }

        // Join group 65 → highest group forces a 3-word (12-byte) bitmap.
        let group = 65u32.to_ne_bytes();
        if call(
            Syscall::SocketSetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_NETLINK,
                arg2: NETLINK_ADD_MEMBERSHIP,
                arg3: group.as_ptr() as u64,
                arg4: group.len() as u64,
                arg5: 0,
            },
        )
        .ok_or("add-membership status")?
            != 0
        {
            return Err("NETLINK_ADD_MEMBERSHIP failed");
        }

        // The NULL-optval probe now reports the required 12-byte length.
        let mut probe_len = 0u32.to_ne_bytes();
        let r = call(
            Syscall::SocketGetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_NETLINK,
                arg2: NETLINK_LIST_MEMBERSHIPS,
                arg3: 0,
                arg4: probe_len.as_mut_ptr() as u64,
                arg5: 0,
            },
        )
        .ok_or("list-memberships probe#2 status")?;
        if r != 0 {
            return Err("NETLINK_LIST_MEMBERSHIPS probe after join did not return 0");
        }
        if u32::from_ne_bytes(probe_len) != 12 {
            return Err("NETLINK_LIST_MEMBERSHIPS probe reported the wrong required length");
        }

        // A follow-up read of the reported length returns the bitmap with the
        // group-65 bit set in the third word, and updates optlen to 12.
        let mut bitmap = [0u8; 12];
        let mut read_len = (bitmap.len() as u32).to_ne_bytes();
        let r = call(
            Syscall::SocketGetSockOpt.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: SOL_NETLINK,
                arg2: NETLINK_LIST_MEMBERSHIPS,
                arg3: bitmap.as_mut_ptr() as u64,
                arg4: read_len.as_mut_ptr() as u64,
                arg5: 0,
            },
        )
        .ok_or("list-memberships read status")?;
        if r != 0 {
            return Err("NETLINK_LIST_MEMBERSHIPS bitmap read did not return 0");
        }
        if u32::from_ne_bytes(read_len) != 12 {
            return Err("NETLINK_LIST_MEMBERSHIPS read did not update optlen to 12");
        }
        // group 65 → word 2 (bytes 8..12), bit (65-1) % 32 == 0.
        if u32::from_ne_bytes(bitmap[8..12].try_into().unwrap()) != 1
            || u32::from_ne_bytes(bitmap[0..4].try_into().unwrap()) != 0
        {
            return Err("NETLINK_LIST_MEMBERSHIPS bitmap did not report group 65");
        }

        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_list_memberships_length_probe
);

fn smoke_abi_netlink_route_getlink_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETLINK, 42);
        if netlink_send(fd, &req).ok_or("send status")? != req.len() as i64 {
            return Err("send(RTM_GETLINK) did not echo the request length");
        }
        // First reply must be a well-formed RTM_NEWLINK naming `lo`.
        let mut buf = [0u8; 512];
        let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
        if n < NLMSG_HDRLEN as i64 {
            return Err("recv did not return a full RTM_NEWLINK message");
        }
        let n = n as usize;
        if nlmsg_type_of(&buf) != RTM_NEWLINK {
            return Err("first dump message was not RTM_NEWLINK");
        }
        // The nlmsg_len field must match the returned byte count.
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len != n {
            return Err("RTM_NEWLINK nlmsg_len disagrees with recv byte count");
        }
        // The loopback link carries an IFLA_IFNAME rtattr with "lo".
        if !window_contains(&buf[..n], b"lo\0") {
            return Err("RTM_NEWLINK dump did not contain the `lo` interface name");
        }
        if !window_contains(&buf[..n], b"noqueue\0") {
            return Err("RTM_NEWLINK dump did not contain the qdisc");
        }
        // Drain remaining links until NLMSG_DONE terminates the dump.
        let mut saw_done = false;
        for _ in 0..16 {
            let mut b2 = [0u8; 512];
            let m = netlink_recv(fd, &mut b2).ok_or("drain recv status")?;
            if m < NLMSG_HDRLEN as i64 {
                break;
            }
            if nlmsg_type_of(&b2) == NLMSG_DONE {
                saw_done = true;
                break;
            }
        }
        if !saw_done {
            return Err("RTM_GETLINK dump did not terminate with NLMSG_DONE");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_getlink_dump);

fn smoke_abi_netlink_route_getaddr_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETADDR, 7);
        if netlink_send(fd, &req).ok_or("send status")? != req.len() as i64 {
            return Err("send(RTM_GETADDR) did not echo the request length");
        }
        let mut buf = [0u8; 512];
        let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
        if n < NLMSG_HDRLEN as i64 {
            return Err("recv did not return a full RTM_NEWADDR message");
        }
        if nlmsg_type_of(&buf) != RTM_NEWADDR {
            return Err("first addr-dump message was not RTM_NEWADDR");
        }
        // ifaddrmsg.ifa_family (offset 16) must be AF_INET (2).
        if buf[NLMSG_HDRLEN] != AF_INET as u8 {
            return Err("RTM_NEWADDR ifa_family was not AF_INET");
        }
        // Terminates with NLMSG_DONE.
        let mut saw_done = false;
        for _ in 0..16 {
            let mut b2 = [0u8; 512];
            let m = netlink_recv(fd, &mut b2).ok_or("drain recv status")?;
            if m < NLMSG_HDRLEN as i64 {
                break;
            }
            if nlmsg_type_of(&b2) == NLMSG_DONE {
                saw_done = true;
                break;
            }
        }
        if !saw_done {
            return Err("RTM_GETADDR dump did not terminate with NLMSG_DONE");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_getaddr_dump);

fn smoke_abi_netlink_route_getaddr_family_filter() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let mut req = [0u8; 24];
        req[0..4].copy_from_slice(&24u32.to_ne_bytes());
        req[4..6].copy_from_slice(&RTM_GETADDR.to_ne_bytes());
        req[6..8].copy_from_slice(&NLM_F_REQUEST_DUMP.to_ne_bytes());
        req[8..12].copy_from_slice(&15u32.to_ne_bytes());
        req[16] = 10; // AF_INET6; synthetic loopback publishes ::1/128.
        if netlink_send(fd, &req).ok_or("filtered addr send")? != req.len() as i64 {
            return Err("filtered RTM_GETADDR send failed");
        }
        let mut reply = [0u8; 64];
        let n = netlink_recv(fd, &mut reply).ok_or("filtered addr recv")?;
        if n < NLMSG_HDRLEN as i64 || nlmsg_type_of(&reply) != RTM_NEWADDR {
            return Err("IPv6-filtered address dump did not return loopback ::1");
        }
        if reply[NLMSG_HDRLEN] != 10
            || reply[NLMSG_HDRLEN + 1] != 128
            || reply[NLMSG_HDRLEN + 3] != 254 // RT_SCOPE_HOST
            || reply[43] != 1
        {
            return Err("IPv6-filtered address dump did not describe ::1/128");
        }
        let mut done = [0u8; 64];
        let n = netlink_recv(fd, &mut done).ok_or("filtered addr done recv")?;
        if n < NLMSG_HDRLEN as i64 || nlmsg_type_of(&done) != NLMSG_DONE {
            return Err("IPv6-filtered address dump did not terminate with NLMSG_DONE");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_route_getaddr_family_filter
);

fn smoke_abi_netlink_route_getroute_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETROUTE, 9);
        if netlink_send(fd, &req).ok_or("send status")? != req.len() as i64 {
            return Err("send(RTM_GETROUTE) did not echo the request length");
        }
        let mut buf = [0u8; 512];
        let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
        if n < (NLMSG_HDRLEN + 12) as i64 {
            return Err("recv did not return a full RTM_NEWROUTE message");
        }
        if nlmsg_type_of(&buf) != RTM_NEWROUTE {
            return Err("first route-dump message was not RTM_NEWROUTE");
        }
        if buf[NLMSG_HDRLEN] != AF_INET as u8 {
            return Err("RTM_NEWROUTE rtm_family was not AF_INET");
        }
        let mut saw_done = false;
        for _ in 0..32 {
            let mut b2 = [0u8; 512];
            let m = netlink_recv(fd, &mut b2).ok_or("drain recv status")?;
            if m < NLMSG_HDRLEN as i64 {
                break;
            }
            if nlmsg_type_of(&b2) == NLMSG_DONE {
                saw_done = true;
                break;
            }
        }
        if !saw_done {
            return Err("RTM_GETROUTE dump did not terminate with NLMSG_DONE");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_getroute_dump);

fn smoke_abi_netlink_route_point_lookup() -> TestResult {
    with_setup(|| {
        fn discard(_: &[u8]) -> Result<(), ()> {
            Ok(())
        }

        let iface = "abi-rtnl-route0";
        narf_net::iface::register(iface, [0x02, 0, 0, 0, 5, 1], discard);
        narf_net::route::route_add(narf_net::route::Route {
            net_ns_id: 0,
            dst: narf_net::route::Ipv4Net {
                addr: narf_net::ipv4::Ipv4Addr([198, 19, 7, 0]),
                prefix_len: 24,
            },
            gateway: Some(narf_net::ipv4::Ipv4Addr([192, 0, 2, 1])),
            iface: alloc::string::String::from(iface),
            src_hint: None,
            metric: 0,
            scope: narf_net::route::Scope::Universe,
            table: narf_net::route::TABLE_MAIN,
        });

        let fd = open_netlink(NETLINK_ROUTE)?;
        let mut req = [0u8; 36];
        req[0..4].copy_from_slice(&36u32.to_ne_bytes());
        req[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
        req[6..8].copy_from_slice(&1u16.to_ne_bytes());
        req[8..12].copy_from_slice(&14u32.to_ne_bytes());
        req[16] = AF_INET as u8;
        req[17] = 32;
        req[20] = narf_net::route::TABLE_MAIN;
        // RTA_DST { len=8, type=1, address=198.19.7.42 }.
        req[28..30].copy_from_slice(&8u16.to_ne_bytes());
        req[30..32].copy_from_slice(&1u16.to_ne_bytes());
        req[32..36].copy_from_slice(&[198, 19, 7, 42]);
        if netlink_send(fd, &req).ok_or("route point send")? != req.len() as i64 {
            return Err("RTM_GETROUTE point send failed");
        }
        let mut reply = [0u8; 512];
        let n = netlink_recv(fd, &mut reply).ok_or("route point recv")?;
        if n < (NLMSG_HDRLEN + 12) as i64 || nlmsg_type_of(&reply) != RTM_NEWROUTE {
            return Err("RTM_GETROUTE point lookup did not return RTM_NEWROUTE");
        }
        let flags = u16::from_ne_bytes([reply[6], reply[7]]);
        if flags & 2 != 0 || reply[NLMSG_HDRLEN + 1] != 24 {
            return Err("route point reply was multipart or selected the wrong prefix");
        }
        if !window_contains(&reply[..n as usize], &[192, 0, 2, 1]) {
            return Err("route point reply omitted the selected gateway");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        narf_net::route::route_delete(
            narf_net::route::Ipv4Net {
                addr: narf_net::ipv4::Ipv4Addr([198, 19, 7, 0]),
                prefix_len: 24,
            },
            iface,
            narf_net::route::TABLE_MAIN,
        );
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_point_lookup);

fn smoke_abi_netlink_route_getneigh_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETNEIGH, 10);
        if netlink_send(fd, &req).ok_or("send status")? != req.len() as i64 {
            return Err("send(RTM_GETNEIGH) did not echo the request length");
        }
        // An empty neighbor cache is valid; it must still complete rather
        // than leaving Linux tooling blocked forever.
        let mut saw_done = false;
        for _ in 0..32 {
            let mut buf = [0u8; 512];
            let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
            if n < NLMSG_HDRLEN as i64 {
                break;
            }
            if nlmsg_type_of(&buf) == NLMSG_DONE {
                saw_done = true;
                break;
            }
        }
        if !saw_done {
            return Err("RTM_GETNEIGH dump did not terminate with NLMSG_DONE");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_getneigh_dump);

fn smoke_abi_netlink_route_getrule_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETRULE, 11);
        if netlink_send(fd, &req).ok_or("send status")? != req.len() as i64 {
            return Err("send(RTM_GETRULE) did not echo the request length");
        }
        for expected_priority in [0u32, 32_766, 32_767] {
            let mut buf = [0u8; 512];
            let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
            if n < (NLMSG_HDRLEN + 12) as i64 || nlmsg_type_of(&buf) != RTM_NEWRULE {
                return Err("RTM_GETRULE did not return three RTM_NEWRULE entries");
            }
            if !window_contains(&buf[..n as usize], &expected_priority.to_ne_bytes()) {
                return Err("RTM_NEWRULE priority was missing");
            }
        }
        let mut done = [0u8; 64];
        let n = netlink_recv(fd, &mut done).ok_or("done recv")?;
        if n < NLMSG_HDRLEN as i64 || nlmsg_type_of(&done) != NLMSG_DONE {
            return Err("RTM_GETRULE did not terminate with NLMSG_DONE");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_getrule_dump);

fn smoke_abi_netlink_route_getqdisc_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETQDISC, 12);
        if netlink_send(fd, &req).ok_or("send status")? != req.len() as i64 {
            return Err("send(RTM_GETQDISC) did not echo the request length");
        }
        let mut first = [0u8; 512];
        let n = netlink_recv(fd, &mut first).ok_or("recv status")?;
        if n < (NLMSG_HDRLEN + 20) as i64 || nlmsg_type_of(&first) != RTM_NEWQDISC {
            return Err("RTM_GETQDISC did not return RTM_NEWQDISC");
        }
        if !window_contains(&first[..n as usize], b"noqueue\0") {
            return Err("RTM_NEWQDISC did not identify noqueue");
        }
        let mut saw_done = false;
        for _ in 0..32 {
            let mut buf = [0u8; 512];
            let n = netlink_recv(fd, &mut buf).ok_or("drain status")?;
            if n >= NLMSG_HDRLEN as i64 && nlmsg_type_of(&buf) == NLMSG_DONE {
                saw_done = true;
                break;
            }
        }
        if !saw_done {
            return Err("RTM_GETQDISC did not terminate with NLMSG_DONE");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_route_getqdisc_dump);

fn smoke_abi_netlink_empty_collection_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_ROUTE)?;
        let req = nlmsg_request(RTM_GETTFILTER, 13);
        if netlink_send(fd, &req).ok_or("send status")? != req.len() as i64 {
            return Err("send(RTM_GETTFILTER) did not echo request length");
        }
        let mut buf = [0u8; 64];
        let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
        if n < NLMSG_HDRLEN as i64 || nlmsg_type_of(&buf) != NLMSG_DONE {
            return Err("empty RTM_GETTFILTER dump did not return NLMSG_DONE");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_empty_collection_dump
);

fn smoke_abi_netlink_uevent_recv() -> TestResult {
    with_setup(|| {
        // The uevent monitor starts at the ring tail, so create the socket
        // FIRST, then emit — a tail-started reader only sees future events.
        let fd = open_netlink(NETLINK_KOBJECT_UEVENT)?;
        let (addr, alen) = netlink_sockaddr(1);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind(NETLINK_KOBJECT_UEVENT) failed");
        }
        // Emit a synthetic hotplug event via the kernel uevent API.
        narf_filesystem::uevent::emit(
            narf_filesystem::uevent::UeventAction::Add,
            alloc::string::String::from("/devices/abi-netlink-test"),
            alloc::string::String::from("net"),
        );
        let queued = netlink_inq(fd)? as i64;
        if queued <= 4 {
            return Err("SIOCINQ did not report the pending uevent");
        }
        let sized = call(
            Syscall::SocketRecv.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: 0,
                arg2: 0,
                arg3: MSG_DONTWAIT | 0x02 | 0x20,
                arg4: 0,
                arg5: 0,
            },
        )
        .ok_or("zero-length uevent MSG_PEEK|MSG_TRUNC status")?;
        if sized != queued {
            return Err("zero-length uevent probe did not return complete datagram length");
        }
        let mut short = [0u8; 4];
        let peeked = netlink_recv_flags(fd, &mut short, MSG_DONTWAIT | 0x02 | 0x20)
            .ok_or("uevent MSG_PEEK|MSG_TRUNC status")?;
        if peeked != queued {
            return Err("uevent MSG_TRUNC did not return the complete datagram length");
        }
        // recv the event; the netlink wire text begins "add@<devpath>".
        let mut buf = [0u8; 512];
        let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
        if n <= 0 {
            return Err("uevent recv returned no bytes after emit");
        }
        let n = n as usize;
        if !window_contains(&buf[..n], b"add@/devices/abi-netlink-test") {
            return Err("uevent recv did not carry the emitted action@devpath header");
        }
        if !window_contains(&buf[..n], b"SUBSYSTEM=net") {
            return Err("uevent recv did not carry the emitted SUBSYSTEM");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_uevent_recv);

/// `MSG_PEEK` on a connectionless AF_UNIX datagram must NOT consume the
/// datagram: the next receive has to return the same message again.
///
/// The connectionless receive branch ignores its flags entirely and always
/// pops the inbox, so a peek destroys the message it was only supposed to
/// look at. Every size-probe consumer is affected — systemd's
/// `next_datagram_size_fd()` is exactly `recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC)`
/// and is what `sd-device-monitor` calls before every real receive, so a
/// peek that eats the datagram silently loses it.
///
/// Linux ref: `unix_dgram_recvmsg` — MSG_PEEK takes a reference to the skb
/// and leaves it on the queue.
fn smoke_abi_socket_unix_dgram_msg_peek_does_not_consume() -> TestResult {
    with_setup(|| {
        const MSG_PEEK: u64 = 0x02;
        let rx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = unix_sockaddr(b"\0narf-peek-dgram");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("bind of the abstract datagram receiver failed");
        }
        let tx = open_unix(SOCK_DGRAM)?;
        for payload in [b"FIRST---".as_ref(), b"SECOND--".as_ref()] {
            let sent = call(
                Syscall::SocketSend.raw(),
                SyscallArgs {
                    arg0: tx,
                    arg1: payload.as_ptr() as u64,
                    arg2: payload.len() as u64,
                    arg4: addr.as_ptr() as u64,
                    arg5: alen,
                    ..SyscallArgs::default()
                },
            );
            if sent != Some(payload.len() as i64) {
                return Err("sendto of a test datagram failed");
            }
        }

        // Peek: must return the FIRST datagram and leave it queued.
        let mut peek = [0u8; 16];
        let n = call(
            Syscall::SocketRecv.raw(),
            a3(rx, peek.as_mut_ptr() as u64, peek.len() as u64, MSG_PEEK),
        )
        .ok_or("MSG_PEEK recv status")?;
        if n != 8 || &peek[..8] != b"FIRST---" {
            return Err("MSG_PEEK did not return the first datagram");
        }

        // A real receive must still see FIRST — the peek consumed nothing.
        let mut first = [0u8; 16];
        let n = call(
            Syscall::SocketRecv.raw(),
            a3(rx, first.as_mut_ptr() as u64, first.len() as u64, 0),
        )
        .ok_or("recv-after-peek status")?;
        if n != 8 || &first[..8] != b"FIRST---" {
            return Err("MSG_PEEK consumed the datagram it only peeked at");
        }

        // And the queue must still hold the second, in order.
        let mut second = [0u8; 16];
        let n = call(
            Syscall::SocketRecv.raw(),
            a3(rx, second.as_mut_ptr() as u64, second.len() as u64, 0),
        )
        .ok_or("second recv status")?;
        if n != 8 || &second[..8] != b"SECOND--" {
            return Err("datagram order was not preserved across a peek");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_unix_dgram_msg_peek_does_not_consume
);

/// `recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC)` on a connectionless AF_UNIX
/// datagram must report the FULL datagram length, not the number of bytes
/// copied (zero, for this probe shape).
///
/// This is systemd's `next_datagram_size_fd()` verbatim, and it is how
/// `sd-device-monitor` sizes its receive buffer before every real recvmsg:
/// answer 0 and it allocates nothing and then rejects the message as short
/// (libudev drops anything under 32 bytes). Pairs with the peek test above —
/// the probe is useless unless it is BOTH non-destructive and correctly
/// sized.
fn smoke_abi_socket_unix_dgram_peek_trunc_reports_full_size() -> TestResult {
    with_setup(|| {
        const MSG_PEEK: u64 = 0x02;
        const MSG_TRUNC_F: u64 = 0x20;
        let rx = open_unix(SOCK_DGRAM)?;
        let (addr, alen) = unix_sockaddr(b"\0narf-peektrunc-dgram");
        if call(
            Syscall::SocketBind.raw(),
            a2(rx, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("bind of the abstract datagram receiver failed");
        }
        let tx = open_unix(SOCK_DGRAM)?;
        let payload = b"READY=1\nSTATUS=probe-me\n";
        if call(
            Syscall::SocketSend.raw(),
            SyscallArgs {
                arg0: tx,
                arg1: payload.as_ptr() as u64,
                arg2: payload.len() as u64,
                arg4: addr.as_ptr() as u64,
                arg5: alen,
                ..SyscallArgs::default()
            },
        ) != Some(payload.len() as i64)
        {
            return Err("sendto of the probe datagram failed");
        }

        // Zero-length probe: NULL buffer, length 0.
        let sized = call(
            Syscall::SocketRecv.raw(),
            a3(rx, 0, 0, MSG_PEEK | MSG_TRUNC_F),
        )
        .ok_or("size-probe status")?;
        if sized != payload.len() as i64 {
            return Err("MSG_PEEK|MSG_TRUNC size probe did not report the full datagram length");
        }

        // A short buffer must report the full length too, while copying only
        // what fits.
        let mut short = [0u8; 4];
        let sized = call(
            Syscall::SocketRecv.raw(),
            a3(
                rx,
                short.as_mut_ptr() as u64,
                short.len() as u64,
                MSG_PEEK | MSG_TRUNC_F,
            ),
        )
        .ok_or("short-probe status")?;
        if sized != payload.len() as i64 {
            return Err("MSG_TRUNC with a short buffer did not report the full datagram length");
        }

        // And the probes consumed nothing: the real receive still gets it all.
        let mut full = [0u8; 64];
        let n = call(
            Syscall::SocketRecv.raw(),
            a3(rx, full.as_mut_ptr() as u64, full.len() as u64, 0),
        )
        .ok_or("real recv status")?;
        if n != payload.len() as i64 || &full[..payload.len()] != payload {
            return Err("size probes consumed or corrupted the datagram");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_socket_unix_dgram_peek_trunc_reports_full_size
);

/// The recvmsg-side half of libudev's `device_monitor_receive_device()`
/// checks. A uevent that passes every payload rule is STILL dropped unless
/// the receive itself reports the right sender and credentials:
///
///   - `msg_name` must come back as a `sockaddr_nl` whose `nl_groups` is the
///     KERNEL monitor group (1) and whose `nl_pid` is 0. A non-zero pid is
///     treated as a spoofed multicast message and ignored.
///   - an `SCM_CREDENTIALS` cmsg MUST be attached; "no sender credentials
///     received" is an outright drop.
///   - those credentials must carry uid 0, or `check_sender_uid()` rejects
///     the message.
///
/// All three are silent at debug level, and journald is not up early enough
/// in boot to capture them — which is exactly why udevd could receive every
/// uevent we emit and still queue nothing. Pinned here so a regression names
/// itself instead of presenting as "udev does nothing".
fn smoke_abi_netlink_uevent_recvmsg_sender_and_creds() -> TestResult {
    with_setup(|| {
        const SCM_CREDENTIALS_TYPE: i32 = 2;
        const MONITOR_GROUP_KERNEL: u32 = 1;

        let fd = open_netlink(NETLINK_KOBJECT_UEVENT)?;
        let (addr, alen) = netlink_sockaddr(1);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("bind(NETLINK_KOBJECT_UEVENT) failed");
        }
        narf_filesystem::uevent::emit(
            narf_filesystem::uevent::UeventAction::Add,
            alloc::string::String::from("/devices/platform/narf-drm/card0"),
            alloc::string::String::from("drm"),
        );

        let mut name = [0u8; 32];
        let mut dst = [0u8; 512];
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
        iov[8..].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
        let mut ctrl = [0u8; 128];
        let mut msg = [0u8; 56];
        msg[..8].copy_from_slice(&(name.as_mut_ptr() as u64).to_ne_bytes());
        msg[8..12].copy_from_slice(&(name.len() as u32).to_ne_bytes());
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
        msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());

        let n = call(Syscall::SocketRecvMsg.raw(), a2(fd, msg.as_ptr() as u64, 0))
            .ok_or("recvmsg status")?;
        if n <= 0 {
            return Err("recvmsg on a uevent monitor returned no bytes");
        }
        // libudev drops anything under 32 bytes before looking at it.
        if n < 32 {
            return Err("uevent datagram is under libudev's 32-byte minimum");
        }

        // sockaddr_nl: nl_family u16 @0, nl_pad u16 @2, nl_pid u32 @4,
        // nl_groups u32 @8.
        let namelen = u32::from_ne_bytes(msg[8..12].try_into().unwrap());
        if (namelen as usize) < 12 {
            return Err("recvmsg did not return a full sockaddr_nl for the sender");
        }
        let nl_pid = u32::from_ne_bytes(name[4..8].try_into().unwrap());
        let nl_groups = u32::from_ne_bytes(name[8..12].try_into().unwrap());
        if nl_pid != 0 {
            return Err("uevent sender nl_pid != 0 (libudev treats it as spoofed multicast)");
        }
        if nl_groups != MONITOR_GROUP_KERNEL {
            return Err("uevent sender nl_groups is not the KERNEL monitor group");
        }

        // cmsghdr: cmsg_len u64 @0, cmsg_level i32 @8, cmsg_type i32 @12,
        // then struct ucred { pid, uid, gid } u32 x3 @16.
        let ctrllen = u64::from_ne_bytes(msg[40..48].try_into().unwrap()) as usize;
        if ctrllen < 16 + 12 {
            return Err("recvmsg attached no SCM_CREDENTIALS to the uevent");
        }
        let ctype = i32::from_le_bytes(ctrl[12..16].try_into().unwrap());
        if ctype != SCM_CREDENTIALS_TYPE {
            return Err("uevent ancillary data was not SCM_CREDENTIALS");
        }
        let uid = u32::from_le_bytes(ctrl[20..24].try_into().unwrap());
        if uid != 0 {
            return Err("uevent SCM_CREDENTIALS uid != 0 (check_sender_uid rejects it)");
        }

        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_uevent_recvmsg_sender_and_creds
);

/// A LEVEL-triggered epoll on a uevent monitor must keep reporting the fd
/// readable while events remain queued — including on the epoll_wait that
/// follows a partial drain, when no new uevent has been emitted since.
///
/// This is the shape `systemd-udevd` runs: its monitor fd is registered
/// level-triggered, it reads one event per wakeup, and it returns to
/// `epoll_wait(-1)` with the rest of the queue still pending. Nothing emits
/// a fresh uevent afterwards, so if that epoll_wait parks on the strength of
/// "no new readiness notification arrived", the daemon sleeps forever on data
/// that is already sitting in its socket.
///
/// That is exactly what was observed on the Fedora gate: udevd read seqnum 2
/// and 3, went back to epoll_wait with seqnums 4..31 still queued, and stayed
/// parked with a frozen park-check counter for 300 seconds — no workers, no
/// `/run/udev/data`. Readiness REPORTING was never the problem
/// (`poll_readiness` sets POLL_IN whenever the reader has pending events);
/// the question this pins is whether epoll consults it before parking.
fn smoke_abi_netlink_uevent_epoll_level_redelivers_pending() -> TestResult {
    with_setup(|| {
        const EPOLLIN: u32 = 1;
        let fd = open_netlink(NETLINK_KOBJECT_UEVENT)?;
        let (addr, alen) = netlink_sockaddr(1);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("bind(NETLINK_KOBJECT_UEVENT) failed");
        }

        // Queue THREE events before epoll ever sees the fd, mirroring a boot
        // coldplug that completed before the daemon started.
        for i in 0..3u32 {
            narf_filesystem::uevent::emit(
                narf_filesystem::uevent::UeventAction::Add,
                alloc::format!("/devices/epoll-level-{i}"),
                alloc::string::String::from("drm"),
            );
        }

        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create failed"),
        };
        let mut interest = [0u8; 12];
        interest[..4].copy_from_slice(&EPOLLIN.to_ne_bytes());
        interest[4..].copy_from_slice(&0xEEEEu64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            a3(epfd, 1, fd, interest.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("epoll_ctl ADD of the uevent monitor failed");
        }

        // Drain one event per wakeup, exactly as udevd does. Every iteration
        // must wake: the queue is still non-empty and NOTHING emits a new
        // uevent to supply a fresh readiness edge.
        //
        // A BLOCKING wait on purpose, with a finite timeout so a regression
        // fails the suite instead of hanging it.
        //
        // KNOWN LIMIT: this harness has no user-task context, so even a
        // blocking epoll_wait is answered by the immediate readiness scan and
        // never reaches the own-stack park. That makes this test real
        // coverage of the LEVEL-TRIGGERED contract but NOT a reproducer for
        // the udevd wedge, whose distinguishing feature is a park whose
        // re-check never runs (`dbg_park_checks` frozen). Reproducing that
        // needs a test that actually parks — do not read this test passing as
        // evidence the park path is correct.
        const BLOCK_MS: u64 = 2_000;
        for i in 0..3 {
            let mut out = [0u8; 12];
            let ready = call(
                Syscall::EpollWait.raw(),
                a3(epfd, out.as_mut_ptr() as u64, 1, BLOCK_MS),
            )
            .ok_or("epoll_wait status")?;
            if ready != 1 {
                return match i {
                    0 => Err("epoll_wait did not report a monitor queued before registration"),
                    _ => Err("epoll_wait parked with uevents still queued after a partial drain"),
                };
            }
            let mut buf = [0u8; 512];
            if netlink_recv(fd, &mut buf).unwrap_or(-1) <= 0 {
                return Err("recv returned nothing for an epoll-reported readable monitor");
            }
        }

        let _ = call(Syscall::Close.raw(), a0(epfd));
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_uevent_epoll_level_redelivers_pending
);

/// A NETLINK_KOBJECT_UEVENT monitor is udevd's primary event source.  Its
/// queue may be drained between epoll scans, so EPOLLET must see a subsequent
/// uevent even though no scan observed the temporary empty state.
fn smoke_abi_netlink_uevent_epollet_drain_refill() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_KOBJECT_UEVENT)?;
        let (addr, alen) = netlink_sockaddr(1);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        ) != Some(0)
        {
            return Err("bind(NETLINK_KOBJECT_UEVENT) failed");
        }
        let epfd = call(Syscall::EpollCreate.raw(), a0(0)).ok_or("epoll_create status")?;
        if epfd < 0 {
            return Err("epoll_create failed");
        }
        let mut interest = [0u8; 12];
        interest[..4].copy_from_slice(&(1u32 | (1u32 << 31)).to_ne_bytes());
        interest[4..].copy_from_slice(&0x5545_5645_4E54u64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            a3(epfd as u64, 1, fd, interest.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("epoll_ctl ADD EPOLLET uevent monitor failed");
        }

        let mut events = [0u8; 12];
        for devpath in ["/devices/abi-uevent-et-one", "/devices/abi-uevent-et-two"] {
            narf_filesystem::uevent::emit(
                narf_filesystem::uevent::UeventAction::Add,
                alloc::string::String::from(devpath),
                alloc::string::String::from("net"),
            );
            if call(
                Syscall::EpollWait.raw(),
                a3(epfd as u64, events.as_mut_ptr() as u64, 1, 0),
            ) != Some(1)
            {
                return Err("EPOLLET lost NETLINK_KOBJECT_UEVENT drain/refill edge");
            }
            let mut buf = [0u8; 512];
            if netlink_recv(fd, &mut buf).ok_or("uevent recv status")? <= 0 {
                return Err("uevent monitor did not drain its ready datagram");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_uevent_epollet_drain_refill
);

// systemd PID 1's audit setup opens `socket(AF_NETLINK, SOCK_RAW, 9)`.
// Status queries return a disabled audit_status; configuration remains denied
// without native NARF authority.
const NETLINK_AUDIT: u64 = 9;
const NETLINK_SOCK_DIAG: u64 = 4;
const NETLINK_NETFILTER: u64 = 12;
const NETLINK_GENERIC: u64 = 16;

fn smoke_abi_netlink_audit_socket_open_bind_send() -> TestResult {
    with_setup(|| {
        // socket() must return a real fd, never the -1 EPERM sentinel.
        let fd = open_netlink(NETLINK_AUDIT)?;
        // bind(sockaddr_nl{groups=0}) must succeed (return 0).
        let (addr, alen) = netlink_sockaddr(0);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind(NETLINK_AUDIT) did not return 0");
        }
        const AUDIT_GET: u16 = 1000;
        let msg = nlmsg_request(AUDIT_GET, 1);
        if netlink_send(fd, &msg).ok_or("send status")? != msg.len() as i64 {
            return Err("send(NETLINK_AUDIT) did not accept the message");
        }
        let mut buf = [0u8; 80];
        let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
        if n < 60 || nlmsg_type_of(&buf) != AUDIT_GET {
            return Err("NETLINK_AUDIT did not return audit_status");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_audit_socket_open_bind_send
);

/// libaudit emits userspace event records while systemd records boot state.
/// With auditing disabled, Linux accepts the record and returns a successful
/// `NLMSG_ERROR` ACK rather than rejecting it as an unsupported operation.
fn smoke_abi_netlink_audit_user_record_acknowledged() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_AUDIT)?;
        let (addr, alen) = netlink_sockaddr(0);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind(NETLINK_AUDIT) did not return 0");
        }

        const AUDIT_FIRST_USER_MSG: u16 = 1100;
        let mut message = [0u8; NLMSG_HDRLEN + 16];
        let message_len = message.len() as u32;
        message[0..4].copy_from_slice(&message_len.to_ne_bytes());
        message[4..6].copy_from_slice(&AUDIT_FIRST_USER_MSG.to_ne_bytes());
        message[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        message[8..12].copy_from_slice(&2u32.to_ne_bytes());
        message[NLMSG_HDRLEN..].copy_from_slice(b"narf audit event");
        if netlink_send(fd, &message).ok_or("send status")? != message.len() as i64 {
            return Err("NETLINK_AUDIT did not accept a userspace audit record");
        }

        let mut ack = [0u8; 80];
        let n = netlink_recv(fd, &mut ack).ok_or("recv status")?;
        if n < (NLMSG_HDRLEN + 4) as i64 || nlmsg_type_of(&ack) != NLMSG_ERROR {
            return Err("NETLINK_AUDIT userspace audit record did not receive an ACK");
        }
        if i32::from_ne_bytes(ack[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap()) != 0 {
            return Err("NETLINK_AUDIT rejected a userspace audit record");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_audit_user_record_acknowledged
);

fn smoke_abi_netlink_generic_socket_open() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_GENERIC)?;
        let (addr, alen) = netlink_sockaddr(0);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("bind status")?
            != 0
        {
            return Err("bind(NETLINK_GENERIC) did not return 0");
        }

        // GENL_ID_CTRL / CTRL_CMD_GETFAMILY with
        // CTRL_ATTR_FAMILY_NAME="nlctrl".
        let mut req = [0u8; 32];
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&16u16.to_ne_bytes());
        req[6..8].copy_from_slice(&1u16.to_ne_bytes());
        req[8..12].copy_from_slice(&91u32.to_ne_bytes());
        req[16] = 3;
        req[17] = 2;
        req[20..22].copy_from_slice(&11u16.to_ne_bytes());
        req[22..24].copy_from_slice(&2u16.to_ne_bytes());
        req[24..31].copy_from_slice(b"nlctrl\0");
        if netlink_send(fd, &req).ok_or("generic send status")? != req.len() as i64 {
            return Err("CTRL_CMD_GETFAMILY send failed");
        }
        let queued = netlink_inq(fd)?;
        if queued < 24 {
            return Err("SIOCINQ did not report the generic-netlink reply");
        }
        let mut reply = [0u8; 256];
        let n = netlink_recv(fd, &mut reply).ok_or("generic recv status")?;
        if n != queued as i64 {
            return Err("SIOCINQ generic-netlink size disagreed with recv length");
        }
        if n < 24 || nlmsg_type_of(&reply) != 16 {
            return Err("generic netlink did not return GENL_ID_CTRL");
        }
        if !window_contains(&reply[..n as usize], b"nlctrl\0") {
            return Err("generic netlink reply did not name nlctrl");
        }

        // The wireless subsystem registers nl80211 through the generic-family
        // registry during boot. Resolve it by name through the real socket
        // path, proving the init hook and family dispatch boundary are live.
        let mut wireless = [0u8; 32];
        wireless[0..4].copy_from_slice(&32u32.to_ne_bytes());
        wireless[4..6].copy_from_slice(&16u16.to_ne_bytes());
        wireless[6..8].copy_from_slice(&1u16.to_ne_bytes());
        wireless[8..12].copy_from_slice(&92u32.to_ne_bytes());
        wireless[16] = 3;
        wireless[17] = 2;
        wireless[20..22].copy_from_slice(&12u16.to_ne_bytes());
        wireless[22..24].copy_from_slice(&2u16.to_ne_bytes());
        wireless[24..32].copy_from_slice(b"nl80211\0");
        if netlink_send(fd, &wireless).ok_or("nl80211 lookup send status")? != wireless.len() as i64
        {
            return Err("CTRL_CMD_GETFAMILY nl80211 send failed");
        }
        let n = netlink_recv(fd, &mut reply).ok_or("nl80211 lookup recv status")?;
        if n < 24 || nlmsg_type_of(&reply) != 16 {
            return Err("nl80211 lookup did not return GENL_ID_CTRL");
        }
        if !window_contains(&reply[..n as usize], b"nl80211\0")
            || !window_contains(&reply[..n as usize], &0x13u16.to_ne_bytes())
        {
            return Err("generic netlink reply did not describe nl80211");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_generic_socket_open);

fn smoke_abi_netlink_generic_batched_requests() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_GENERIC)?;
        let mut one = [0u8; 32];
        one[0..4].copy_from_slice(&32u32.to_ne_bytes());
        one[4..6].copy_from_slice(&16u16.to_ne_bytes());
        one[6..8].copy_from_slice(&1u16.to_ne_bytes());
        one[16] = 3;
        one[17] = 2;
        one[20..22].copy_from_slice(&11u16.to_ne_bytes());
        one[22..24].copy_from_slice(&2u16.to_ne_bytes());
        one[24..31].copy_from_slice(b"nlctrl\0");
        let mut batch = [0u8; 64];
        one[8..12].copy_from_slice(&92u32.to_ne_bytes());
        batch[..32].copy_from_slice(&one);
        one[8..12].copy_from_slice(&93u32.to_ne_bytes());
        batch[32..].copy_from_slice(&one);

        if netlink_send(fd, &batch).ok_or("generic batch send")? != batch.len() as i64 {
            return Err("batched generic-netlink send failed");
        }
        for expected_seq in [92u32, 93] {
            let mut reply = [0u8; 256];
            let n = netlink_recv(fd, &mut reply).ok_or("generic batch recv")?;
            if n < 24 || nlmsg_type_of(&reply) != 16 {
                return Err("batched generic-netlink reply was malformed");
            }
            let seq = u32::from_ne_bytes(reply[8..12].try_into().unwrap());
            if seq != expected_seq {
                return Err("batched generic-netlink sequence was not preserved");
            }
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_generic_batched_requests
);

fn smoke_abi_netlink_generic_extended_capped_error() -> TestResult {
    with_setup(|| {
        const NETLINK_CAP_ACK: u64 = 10;
        let fd = open_netlink(NETLINK_GENERIC)?;
        netlink_set_u32(fd, NETLINK_EXT_ACK, 1)?;
        netlink_set_u32(fd, NETLINK_CAP_ACK, 1)?;

        let mut request = [0u8; 32];
        request[0..4].copy_from_slice(&32u32.to_ne_bytes());
        request[4..6].copy_from_slice(&16u16.to_ne_bytes());
        request[6..8].copy_from_slice(&1u16.to_ne_bytes());
        request[8..12].copy_from_slice(&94u32.to_ne_bytes());
        request[16] = 3;
        request[17] = 2;
        request[20..22].copy_from_slice(&12u16.to_ne_bytes());
        request[22..24].copy_from_slice(&2u16.to_ne_bytes());
        request[24..32].copy_from_slice(b"missing\0");
        if netlink_send(fd, &request).ok_or("generic error send")? != request.len() as i64 {
            return Err("unknown generic family send failed");
        }
        let mut reply = [0u8; 256];
        let n = netlink_recv(fd, &mut reply).ok_or("generic error recv")?;
        if n < 36 || nlmsg_type_of(&reply) != 2 {
            return Err("unknown generic family did not return NLMSG_ERROR");
        }
        let flags = u16::from_ne_bytes([reply[6], reply[7]]);
        if flags & 0x100 == 0 || flags & 0x200 == 0 {
            return Err("generic error omitted CAPPED or ACK_TLVS flags");
        }
        if !window_contains(
            &reply[..n as usize],
            b"generic-netlink family does not exist\0",
        ) {
            return Err("generic extended ACK diagnostic was missing");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_generic_extended_capped_error
);

fn smoke_abi_netlink_sock_diag_tcp_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_SOCK_DIAG)?;
        let (addr, alen) = netlink_sockaddr(0);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("sock_diag bind status")?
            != 0
        {
            return Err("bind(NETLINK_SOCK_DIAG) failed");
        }

        // nlmsghdr + inet_diag_req_v2. Request every IPv4 TCP state.
        let mut request = [0u8; 72];
        request[0..4].copy_from_slice(&72u32.to_ne_bytes());
        request[4..6].copy_from_slice(&20u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
        request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
        request[8..12].copy_from_slice(&314u32.to_ne_bytes());
        request[16] = 2; // AF_INET
        request[17] = 6; // IPPROTO_TCP
        request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
        if netlink_send(fd, &request).ok_or("sock_diag send status")? != request.len() as i64 {
            return Err("send(NETLINK_SOCK_DIAG) did not consume request");
        }

        let mut saw_done = false;
        for _ in 0..256 {
            let mut reply = [0u8; 256];
            let n = netlink_recv(fd, &mut reply).ok_or("sock_diag recv status")?;
            if n < 16 {
                return Err("short NETLINK_SOCK_DIAG reply");
            }
            let kind = nlmsg_type_of(&reply);
            if kind == 3 {
                saw_done = true;
                break;
            }
            if kind != 20 || n < 88 {
                return Err("NETLINK_SOCK_DIAG returned a malformed inet_diag_msg");
            }
            if u32::from_ne_bytes(reply[8..12].try_into().unwrap_or([0; 4])) != 314 {
                return Err("NETLINK_SOCK_DIAG did not preserve request sequence");
            }
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        if !saw_done {
            return Err("NETLINK_SOCK_DIAG dump omitted NLMSG_DONE");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_sock_diag_tcp_dump);

fn smoke_abi_netlink_conntrack_dump() -> TestResult {
    with_setup(|| {
        let fd = open_netlink(NETLINK_NETFILTER)?;
        let (addr, alen) = netlink_sockaddr(0);
        if call(
            Syscall::SocketBind.raw(),
            a2(fd, addr.as_ptr() as u64, alen),
        )
        .ok_or("netfilter bind status")?
            != 0
        {
            return Err("bind(NETLINK_NETFILTER) failed");
        }
        let mut request = [0u8; 20];
        request[0..4].copy_from_slice(&20u32.to_ne_bytes());
        request[4..6].copy_from_slice(&0x0101u16.to_ne_bytes());
        request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
        request[8..12].copy_from_slice(&411u32.to_ne_bytes());
        request[16] = 2; // AF_INET nfgenmsg
        if netlink_send(fd, &request).ok_or("conntrack send status")? != request.len() as i64 {
            return Err("conntrack dump request was not consumed");
        }
        let mut saw_done = false;
        for _ in 0..4097 {
            let mut reply = [0u8; 512];
            let n = netlink_recv(fd, &mut reply).ok_or("conntrack recv status")?;
            if n < 16 {
                return Err("short conntrack netlink reply");
            }
            let kind = nlmsg_type_of(&reply);
            if kind == 3 {
                saw_done = true;
                break;
            }
            if kind != 0x0100 || n < 20 {
                return Err("malformed conntrack dump record");
            }
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        if !saw_done {
            return Err("conntrack dump omitted NLMSG_DONE");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/socket", smoke_abi_netlink_conntrack_dump);

fn smoke_abi_netlink_userspace_unicast_and_unique_portid() -> TestResult {
    with_setup(|| {
        let sender = open_netlink(NETLINK_AUDIT)?;
        let receiver = open_netlink(NETLINK_AUDIT)?;
        let duplicate = open_netlink(NETLINK_AUDIT)?;
        let (sender_addr, sender_len) = netlink_sockaddr_port(70_001);
        let (receiver_addr, receiver_len) = netlink_sockaddr_port(70_002);
        if call(
            Syscall::SocketBind.raw(),
            a2(sender, sender_addr.as_ptr() as u64, sender_len),
        )
        .ok_or("sender bind status")?
            != 0
            || call(
                Syscall::SocketBind.raw(),
                a2(receiver, receiver_addr.as_ptr() as u64, receiver_len),
            )
            .ok_or("receiver bind status")?
                != 0
        {
            return Err("explicit netlink port bind failed");
        }
        if call(
            Syscall::SocketBind.raw(),
            a2(duplicate, sender_addr.as_ptr() as u64, sender_len),
        )
        .ok_or("duplicate bind status")?
            >= 0
        {
            return Err("duplicate netlink port ID was accepted");
        }

        let payload = b"user-netlink";
        let mut send_args = a3(sender, payload.as_ptr() as u64, payload.len() as u64, 0);
        send_args.arg4 = receiver_addr.as_ptr() as u64;
        send_args.arg5 = receiver_len;
        if call(Syscall::SocketSend.raw(), send_args).ok_or("user sendto status")?
            != payload.len() as i64
        {
            return Err("userspace netlink sendto failed");
        }

        let mut received = [0u8; 32];
        let mut peer = [0u8; 12];
        let mut peer_len = peer.len() as u32;
        let mut recv_args = a3(
            receiver,
            received.as_mut_ptr() as u64,
            received.len() as u64,
            MSG_DONTWAIT,
        );
        recv_args.arg4 = peer.as_mut_ptr() as u64;
        recv_args.arg5 = (&mut peer_len as *mut u32) as u64;
        let n = call(Syscall::SocketRecv.raw(), recv_args).ok_or("user recvfrom status")?;
        if n != payload.len() as i64 || &received[..payload.len()] != payload {
            return Err("userspace netlink payload did not round-trip");
        }
        if u32::from_ne_bytes(peer[4..8].try_into().unwrap_or([0; 4])) != 70_001 {
            return Err("userspace netlink sender port ID was not reported");
        }

        if call(
            Syscall::SocketConnect.raw(),
            a2(sender, receiver_addr.as_ptr() as u64, receiver_len),
        )
        .ok_or("netlink connect status")?
            != 0
            || netlink_send(sender, b"connected").ok_or("connected send status")? != 9
        {
            return Err("connected userspace netlink send failed");
        }
        let n = netlink_recv(receiver, &mut received).ok_or("connected recv status")?;
        if n != 9 || &received[..9] != b"connected" {
            return Err("connected userspace netlink payload did not arrive");
        }
        for fd in [sender, receiver, duplicate] {
            let _ = call(Syscall::Close.raw(), a0(fd));
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket",
    smoke_abi_netlink_userspace_unicast_and_unique_portid
);

/// True iff `needle` appears as a contiguous byte window in `hay`.
fn window_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}
