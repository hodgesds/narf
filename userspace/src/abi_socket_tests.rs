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
kernel_test_in!("syscall_abi", smoke_abi_socket_abstract_dgram_roundtrip);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_abstract_dgram_refused);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_abstract_stream_inuse);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_autobind);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_so_peercred);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_so_passcred_roundtrip);

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
kernel_test_in!("syscall_abi", smoke_abi_socket_recvmsg_scm_credentials);

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

        // The fd we pass: a second, independent socketpair end.
        let mut sv2 = [0u8; 8];
        if call(
            Syscall::SocketPair.raw(),
            a3(AF_UNIX, SOCK_STREAM, 0, sv2.as_mut_ptr() as u64),
        )
        .ok_or("pair2 status")?
            != 0
        {
            return Err("second socketpair setup failed");
        }
        let passed_fd = i32::from_ne_bytes([sv2[0], sv2[1], sv2[2], sv2[3]]);

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
        let _ = call(Syscall::Close.raw(), a0(new_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_socket_scm_rights_fd_passing);

// ───────────────────────────── AF_NETLINK ─────────────────────────────
//
// systemd-udevd / systemd-networkd open AF_NETLINK sockets: NETLINK_ROUTE
// (protocol 0) for the RTM_GETLINK / RTM_GETADDR interface+address dump, and
// NETLINK_KOBJECT_UEVENT (protocol 15) to monitor device hotplug uevents.

const AF_NETLINK: u64 = 16;
const SOCK_RAW: u64 = 3;
const NETLINK_ROUTE: u64 = 0;
const NETLINK_KOBJECT_UEVENT: u64 = 15;
/// rtnetlink message types (rtnetlink.h).
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
/// netlink control message types (netlink.h).
const NLMSG_DONE: u16 = 3;
const NLMSG_HDRLEN: usize = 16;
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
    call(
        Syscall::SocketRecv.raw(),
        a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, MSG_DONTWAIT),
    )
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
kernel_test_in!("syscall_abi", smoke_abi_netlink_route_socket_bind);

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
kernel_test_in!("syscall_abi", smoke_abi_netlink_uevent_socket_bind);

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
kernel_test_in!("syscall_abi", smoke_abi_netlink_route_getlink_dump);

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
kernel_test_in!("syscall_abi", smoke_abi_netlink_route_getaddr_dump);

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
kernel_test_in!("syscall_abi", smoke_abi_netlink_route_getroute_dump);

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
kernel_test_in!("syscall_abi", smoke_abi_netlink_uevent_recv);

// systemd PID 1's audit setup opens `socket(AF_NETLINK, SOCK_RAW, 9)`. NARF
// does not model audit/generic/netfilter netlink, but MUST still hand back a
// usable fd whose bind/send no-op succeed — a socket-open failure surfaced to
// glibc as the -1 sentinel (errno EPERM) → "Failed to open netlink, ignoring:
// Operation not permitted". These smokes pin the no-op sink behaviour.
const NETLINK_AUDIT: u64 = 9;
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
        // A best-effort audit message send is accepted (and dropped): the
        // return echoes the byte count, matching a quiet-but-open socket.
        let msg = nlmsg_request(0, 1);
        if netlink_send(fd, &msg).ok_or("send status")? != msg.len() as i64 {
            return Err("send(NETLINK_AUDIT) did not accept the message");
        }
        // recv on the empty sink is non-blocking EAGAIN (no reply queued).
        let mut buf = [0u8; 64];
        let n = netlink_recv(fd, &mut buf).ok_or("recv status")?;
        if n > 0 {
            return Err("NETLINK_AUDIT sink unexpectedly returned data");
        }
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_netlink_audit_socket_open_bind_send);

fn smoke_abi_netlink_generic_socket_open() -> TestResult {
    with_setup(|| {
        // NETLINK_GENERIC (genetlink) is likewise backed by the sink: open +
        // bind succeed so callers get a usable fd instead of EPERM.
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
        let _ = call(Syscall::Close.raw(), a0(fd));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_netlink_generic_socket_open);

/// True iff `needle` appears as a contiguous byte window in `hay`.
fn window_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}
