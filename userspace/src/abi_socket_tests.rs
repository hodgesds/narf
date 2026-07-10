//! Linux syscall ABI conformance — socket group.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

// ── Linux socket constants (subset the NARF handlers understand) ──
const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ACCEPTCONN: u64 = 30;
const SHUT_RDWR: u64 = 2;

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
kernel_test_in!("syscall_abi", smoke_abi_socket_socket_open_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_socket_open_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_bind_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_bind_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_listen_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_listen_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_connect_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_connect_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_accept_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_accept_empty_eagain);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_accept4_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_accept4_empty_eagain);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_pair_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_pair_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_send_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_send_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_recv_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_recv_neg);

// ── Non-blocking empty-but-open stream must EAGAIN, never a phantom 0 ──
// Regression for the AF_UNIX read/recv spurious-EOF bug: a non-blocking read
// or recv on an empty-but-OPEN stream socket returned 0 (which the caller
// reads as EOF / peer-hangup) instead of -EAGAIN. GLib's GDBus/GSocket poll
// loop treated that phantom 0 as a hangup and the KDE session-bus handshake
// (and libdbus's next marshalled message) desynced. `read_should_block()` is
// true exactly while the peer is still open, so EOF (peer closed) stays 0.
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
kernel_test_in!("syscall_abi", smoke_abi_socket_read_nonblock_empty_eagain);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_recv_dontwait_empty_eagain);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_read_nonblock_then_data);

fn smoke_abi_socket_read_eof_after_peer_shutdown() -> TestResult {
    with_setup(|| {
        // A genuine EOF (peer half shut down) must still return 0, NOT EAGAIN —
        // the fix distinguishes empty-open (EAGAIN) from closed (EOF).
        let (fd0, fd1) = make_pair(SOCK_STREAM | SOCK_NONBLOCK)?;
        let shutdown = Syscall::SocketShutdown.raw();
        if call(shutdown, a1(fd0, SHUT_RDWR)).ok_or("shutdown status")? != 0 {
            return Err("shutdown(fd0) failed");
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
kernel_test_in!("syscall_abi", smoke_abi_socket_read_eof_after_peer_shutdown);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_shutdown_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_shutdown_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_getsockopt_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_getsockopt_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_acceptconn_not_listening);

fn smoke_abi_socket_acceptconn_listening() -> TestResult {
    with_setup(|| {
        let fd = open_unix_stream()?;
        let (addr, alen) = unix_sockaddr(b"/abi-acceptconn");
        if call(Syscall::SocketBind.raw(), a2(fd, addr.as_ptr() as u64, alen))
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
kernel_test_in!("syscall_abi", smoke_abi_socket_acceptconn_listening);

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
        let r = call(Syscall::Fstat.raw(), a1(fd, stat.as_mut_ptr() as u64))
            .ok_or("status not Ok")?;
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
kernel_test_in!("syscall_abi", smoke_abi_socket_fstat_is_sock);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_setsockopt_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_setsockopt_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_getsockname_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_getsockname_neg);

// ─────────────────────────── SocketGetPeerName ────────────────────────

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
kernel_test_in!("syscall_abi", smoke_abi_socket_getpeername_neg_badfd);

fn smoke_abi_socket_getpeername_neg_unconnected() -> TestResult {
    with_setup(|| {
        // A fresh (or connected AF_UNIX stream) socket has no peer_addr()
        // entry → GetPeerName → NotConnected → -1. NARF never reports a
        // peer name for AF_UNIX stream sockets, so the success path is
        // unreachable from this harness; pin the unconnected error instead.
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
kernel_test_in!("syscall_abi", smoke_abi_socket_getpeername_neg_unconnected);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_sendmsg_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_sendmsg_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_recvmsg_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_recvmsg_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_sock_register_buf_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_sock_register_buf_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_sock_send_zc_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_sock_send_zc_neg);
