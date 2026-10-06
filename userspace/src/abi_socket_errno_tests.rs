//! Linux syscall ABI conformance — socket errno parity.
//!
//! Each case pins one errno path of the socket syscall layer against the
//! Linux function that produces it (named in the case's comment), including
//! the ORDER in which Linux runs its checks where two errors compete. The
//! companion `abi_socket_tests.rs` covers the AF_UNIX happy paths and the
//! descriptor errors (EBADF / ENOTSOCK) shared by every socket call; this
//! file covers what those do not: AF_INET / AF_INET6 / raw / netlink, the
//! address-validation order, connect(AF_UNSPEC), and the sockopt surface.
use crate::abi_test_support::*;

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_NETLINK: u64 = 16;
const AF_BLUETOOTH: u64 = 31;
const BTPROTO_HCI: u64 = 1;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_SEQPACKET: u64 = 5;
const SOCK_PACKET: u64 = 10;
const SOCK_NONBLOCK: u64 = 0o4000;
const IPPROTO_ICMP: u64 = 1;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_IPV6: u64 = 41;
const IPPROTO_IP: u64 = 0;
const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_ATTACH_FILTER: u64 = 26;
const SO_TIMESTAMP_OLD: u64 = 29;
const SO_ACCEPTCONN: u64 = 30;
const SO_SNDBUFFORCE: u64 = 32;
const SO_RCVBUFFORCE: u64 = 33;
const SO_TIMESTAMPNS_OLD: u64 = 35;
const SO_TIMESTAMP_NEW: u64 = 63;
const SO_TIMESTAMPNS_NEW: u64 = 64;
const IP_TOS: u64 = 1;
const IP_TTL: u64 = 2;
const IP_MTU: u64 = 14;
const IP_FREEBIND: u64 = 15;
const IP_MULTICAST_TTL: u64 = 33;
const TCP_MAXSEG: u64 = 2;
const TCP_KEEPIDLE: u64 = 4;
const TCP_KEEPINTVL: u64 = 5;
const TCP_KEEPCNT: u64 = 6;
const TCP_SYNCNT: u64 = 7;
const TCP_LINGER2: u64 = 8;
const TCP_DEFER_ACCEPT: u64 = 9;
const TCP_WINDOW_CLAMP: u64 = 10;
const TCP_INFO: u64 = 11;
const TCP_CONGESTION: u64 = 13;
const TCP_THIN_LINEAR_TIMEOUTS: u64 = 16;
const TCP_THIN_DUPACK: u64 = 17;
const TCP_USER_TIMEOUT: u64 = 18;
const TCP_NOTSENT_LOWAT: u64 = 25;
const TCP_FASTOPEN_NO_COOKIE: u64 = 34;
const TCP_INQ: u64 = 36;
const TCP_TX_DELAY: u64 = 37;
const TCP_IS_MPTCP: u64 = 43;
const IPV6_V6ONLY: u64 = 26;
const MSG_OOB: u64 = 0x1;
const MSG_DONTWAIT: u64 = 0x40;
const SHUT_WR: u64 = 1;
const SHUT_RDWR: u64 = 2;
const LOOPBACK: u32 = 0x7F00_0001;
/// TEST-NET-3 (RFC 5737): assigned to no interface in the test image.
const NONLOCAL: u32 = 0xCB00_7107;
const BAD_USER_PTR: u64 = 1 << 47;
const ENOENT_ERR: i64 = -2;
const EDESTADDRREQ_ERR: i64 = -89;
const EPROTONOSUPPORT_ERR: i64 = -93;
const ESOCKTNOSUPPORT_ERR: i64 = -94;
const EADDRINUSE_ERR: i64 = -98;
const EADDRNOTAVAIL_ERR: i64 = -99;
const EISCONN_ERR: i64 = -106;
const ENOTCONN_ERR: i64 = -107;
const EACCES_ERR: i64 = -13;
const ENOPROTOOPT_ERR: i64 = -92;

// ── helpers ─────────────────────────────────────────────────────────────────

fn sys(n: Syscall, args: SyscallArgs) -> Option<i64> {
    call(n.raw(), args)
}

/// All six argument slots — sendto/recvfrom take six.
fn a5(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
    }
}

fn open(domain: u64, kind: u64, proto: u64) -> Result<u64, &'static str> {
    match sys(Syscall::SocketOpen, a2(domain, kind, proto)) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("socket() setup failed"),
    }
}

fn close(fd: u64) {
    let _ = sys(Syscall::Close, a0(fd));
}

/// A full 16-byte `struct sockaddr_in`: family, port (BE), address (BE),
/// sin_zero.
fn sin(family: u64, ip: u32, port: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&(family as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&ip.to_be_bytes());
    b
}

/// A 28-byte `struct sockaddr_in6` for `::1` (or `::` when `any`).
fn sin6(family: u64, port: u16, any: bool) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&(family as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    if !any {
        b[23] = 1;
    }
    b
}

fn unix_addr(path: &[u8]) -> ([u8; 128], u64) {
    let mut buf = [0u8; 128];
    buf[0..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    let n = core::cmp::min(path.len(), 126);
    buf[2..2 + n].copy_from_slice(&path[..n]);
    (buf, (2 + n) as u64)
}

fn netlink_addr(pid: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    b[4..8].copy_from_slice(&pid.to_ne_bytes());
    b
}

fn bind(fd: u64, addr: &[u8]) -> Option<i64> {
    sys(
        Syscall::SocketBind,
        a2(fd, addr.as_ptr() as u64, addr.len() as u64),
    )
}

fn connect(fd: u64, addr: &[u8]) -> Option<i64> {
    sys(
        Syscall::SocketConnect,
        a2(fd, addr.as_ptr() as u64, addr.len() as u64),
    )
}

fn listen(fd: u64) -> Option<i64> {
    sys(Syscall::SocketListen, a1(fd, 8))
}

fn send(fd: u64, buf: &[u8], flags: u64) -> Option<i64> {
    sys(
        Syscall::SocketSend,
        a3(fd, buf.as_ptr() as u64, buf.len() as u64, flags),
    )
}

fn sendto(fd: u64, buf: &[u8], flags: u64, addr: &[u8]) -> Option<i64> {
    sys(
        Syscall::SocketSend,
        a5(
            fd,
            buf.as_ptr() as u64,
            buf.len() as u64,
            flags,
            addr.as_ptr() as u64,
            addr.len() as u64,
        ),
    )
}

fn recv(fd: u64, buf: &mut [u8], flags: u64) -> Option<i64> {
    sys(
        Syscall::SocketRecv,
        a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, flags),
    )
}

fn setsockopt(fd: u64, level: u64, name: u64, val: &[u8]) -> Option<i64> {
    sys(
        Syscall::SocketSetSockOpt,
        a4(fd, level, name, val.as_ptr() as u64, val.len() as u64),
    )
}

fn set_int(fd: u64, level: u64, name: u64, v: i32) -> Option<i64> {
    setsockopt(fd, level, name, &v.to_ne_bytes())
}

/// getsockopt into `out`; returns (result, reported optlen).
fn getsockopt(fd: u64, level: u64, name: u64, out: &mut [u8]) -> (Option<i64>, i32) {
    let mut len = (out.len() as i32).to_ne_bytes();
    let r = sys(
        Syscall::SocketGetSockOpt,
        a4(
            fd,
            level,
            name,
            out.as_mut_ptr() as u64,
            len.as_mut_ptr() as u64,
        ),
    );
    (r, i32::from_ne_bytes(len))
}

/// getsockname / getpeername into a 128-byte buffer; returns (result, len,
/// buffer).
fn get_name(fd: u64, peer: bool) -> (Option<i64>, i32, [u8; 128]) {
    let mut out = [0u8; 128];
    let mut len = 128i32.to_ne_bytes();
    let n = if peer {
        Syscall::SocketGetPeerName
    } else {
        Syscall::SocketGetSockName
    };
    let r = sys(n, a2(fd, out.as_mut_ptr() as u64, len.as_mut_ptr() as u64));
    (r, i32::from_ne_bytes(len), out)
}

fn local_port(fd: u64) -> Result<u16, &'static str> {
    let (r, len, out) = get_name(fd, false);
    if r != Some(0) || len != 16 {
        return Err("getsockname on an INET socket failed or was not 16 bytes");
    }
    Ok(u16::from_be_bytes([out[2], out[3]]))
}

/// A bound + listening loopback TCP socket on `port`.
fn tcp_listener(port: u16) -> Result<u64, &'static str> {
    let fd = open(AF_INET, SOCK_STREAM, 0)?;
    if bind(fd, &sin(AF_INET, LOOPBACK, port)) != Some(0) {
        return Err("TCP listener bind failed");
    }
    if listen(fd) != Some(0) {
        return Err("TCP listener listen failed");
    }
    Ok(fd)
}

// ───────────────────────────── socket(2) ─────────────────────────────

/// `net/socket.c::__sock_create`: PF_INET + SOCK_PACKET is redirected to
/// PF_PACKET before the family lookup. The family is checked as the full
/// `int`: a value that merely truncates to AF_INET in 16 bits is outside
/// [0, NPROTO).
fn smoke_abi_socket_errno_socket_family_type_order() -> TestResult {
    with_setup(|| {
        let packet = sys(Syscall::SocketOpen, a2(AF_INET, SOCK_PACKET, 0));
        if packet.is_none_or(|fd| fd < 0) {
            return Err("AF_INET/SOCK_PACKET must redirect to the registered PF_PACKET family");
        }
        close(packet.unwrap_or_default() as u64);
        if sys(Syscall::SocketOpen, a2(0x1_0002, SOCK_STREAM, 0)) != Some(EAFNOSUPPORT) {
            return Err("a family that only truncates to AF_INET must be EAFNOSUPPORT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_socket_family_type_order
);

/// AF_BLUETOOTH/BTPROTO_HCI create + bind error codes, matching Linux
/// `bt_sock_create` / `hci_sock_create` / `hci_sock_bind`.
fn smoke_abi_socket_errno_bluetooth_hci() -> TestResult {
    with_setup(|| {
        // A raw HCI socket is valid.
        let fd = open(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)?;
        // Wrong socket type → ESOCKTNOSUPPORT (hci_sock_create accepts RAW).
        if sys(
            Syscall::SocketOpen,
            a2(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_HCI),
        ) != Some(ESOCKTNOSUPPORT)
        {
            return Err("AF_BLUETOOTH non-RAW type must be ESOCKTNOSUPPORT");
        }
        // protocol >= BT_MAX_PROTO → EINVAL (bt_sock_create range check).
        if sys(Syscall::SocketOpen, a2(AF_BLUETOOTH, SOCK_RAW, 99)) != Some(EINVAL) {
            return Err("AF_BLUETOOTH proto >= BT_MAX_PROTO must be EINVAL");
        }
        // In-range but unregistered protocol (BTPROTO_L2CAP=0) → EPROTONOSUPPORT.
        if sys(Syscall::SocketOpen, a2(AF_BLUETOOTH, SOCK_RAW, 0)) != Some(EPROTONOSUPPORT) {
            return Err("unimplemented BT protocol must be EPROTONOSUPPORT");
        }
        // bind(sockaddr_hci{dev=HCI_DEV_NONE, channel=CONTROL}) — the mgmt
        // channel binds device-independent.
        let mut control = [0u8; 6];
        control[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_le_bytes());
        control[2..4].copy_from_slice(&0xffffu16.to_le_bytes()); // HCI_DEV_NONE
        control[4..6].copy_from_slice(&3u16.to_le_bytes()); // HCI_CHANNEL_CONTROL
        if bind(fd, &control) != Some(0) {
            return Err("bind to the mgmt control channel must succeed");
        }
        // An unknown channel is -EINVAL (hci_sock_bind).
        let mut bad = control;
        bad[4..6].copy_from_slice(&99u16.to_le_bytes());
        let fd2 = open(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)?;
        if bind(fd2, &bad) != Some(EINVAL) {
            return Err("bind to an unknown HCI channel must be EINVAL");
        }
        close(fd);
        close(fd2);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_bluetooth_hci
);

/// End-to-end mgmt read API over an HCI_CHANNEL_CONTROL socket: a
/// READ_VERSION command returns a CMD_COMPLETE wrapping it. Exercises the
/// socket -> filesystem broker -> narf_bluetooth::mgmt path.
fn smoke_abi_socket_bluetooth_mgmt_read_version() -> TestResult {
    with_setup(|| {
        let fd = open(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)?;
        let mut control = [0u8; 6];
        control[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_le_bytes());
        control[2..4].copy_from_slice(&0xffffu16.to_le_bytes()); // HCI_DEV_NONE
        control[4..6].copy_from_slice(&3u16.to_le_bytes()); // HCI_CHANNEL_CONTROL
        if bind(fd, &control) != Some(0) {
            return Err("bind to mgmt control channel failed");
        }
        // mgmt_hdr{ opcode=READ_VERSION(1), index=MGMT_INDEX_NONE, len=0 }.
        let cmd = [0x01, 0x00, 0xff, 0xff, 0x00, 0x00];
        if send(fd, &cmd, 0) != Some(cmd.len() as i64) {
            return Err("mgmt READ_VERSION send failed");
        }
        let mut buf = [0u8; 64];
        let n = match recv(fd, &mut buf, 0) {
            Some(n) if n > 0 => n as usize,
            _ => return Err("mgmt reply recv returned no data"),
        };
        // CMD_COMPLETE(0x0001), index NONE, body = READ_VERSION op + status 0.
        if n < 9
            || u16::from_le_bytes([buf[0], buf[1]]) != 0x0001
            || u16::from_le_bytes([buf[2], buf[3]]) != 0xffff
            || u16::from_le_bytes([buf[6], buf[7]]) != 0x0001
            || buf[8] != 0x00
        {
            return Err("mgmt READ_VERSION reply shape mismatch");
        }
        close(fd);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_bluetooth_mgmt_read_version
);

/// Raw HCI channel plumbing: bind RAW, install an HCI_FILTER, send a
/// type-prefixed command (accepted), and recv with no controller -> EAGAIN.
fn smoke_abi_socket_bluetooth_hci_raw() -> TestResult {
    with_setup(|| {
        let fd = open(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)?;
        let mut raw = [0u8; 6];
        raw[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_le_bytes());
        raw[2..4].copy_from_slice(&0u16.to_le_bytes()); // dev 0
        raw[4..6].copy_from_slice(&0u16.to_le_bytes()); // HCI_CHANNEL_RAW
        if bind(fd, &raw) != Some(0) {
            return Err("bind to the raw HCI channel failed");
        }
        // setsockopt(SOL_HCI=0, HCI_FILTER=2, struct hci_filter) is accepted.
        let filter = [0u8; 14];
        if setsockopt(fd, 0, 2, &filter) != Some(0) {
            return Err("HCI_FILTER setsockopt was rejected");
        }
        // A type-prefixed HCI_Reset command is accepted (no controller to run it).
        let cmd = [0x01u8, 0x03, 0x0c, 0x00];
        if send(fd, &cmd, 0) != Some(cmd.len() as i64) {
            return Err("raw HCI command send failed");
        }
        // With no controller bound there are no events: recv -> EAGAIN.
        let mut buf = [0u8; 32];
        if recv(fd, &mut buf, 0) != Some(EAGAIN) {
            return Err("raw HCI recv with no events must be EAGAIN");
        }
        close(fd);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_bluetooth_hci_raw
);

/// Legacy HCI ioctls on an AF_BLUETOOTH socket: HCIGETDEVLIST returns the
/// controller count (0 in QEMU), and HCIGETDEVINFO/HCIDEVUP on an absent
/// controller are ENODEV (matching hci_sock.c).
fn smoke_abi_socket_bluetooth_hci_ioctls() -> TestResult {
    with_setup(|| {
        let fd = open(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)?;
        // HCIGETDEVLIST: dev_num capacity in, controller count out.
        let mut list = [0u8; 4 + 4 * 8];
        list[0..2].copy_from_slice(&4u16.to_le_bytes());
        if sys(
            Syscall::Ioctl,
            a2(fd, 0x8004_48d2, list.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("HCIGETDEVLIST failed");
        }
        if u16::from_le_bytes([list[0], list[1]]) != 0 {
            return Err("HCIGETDEVLIST count should be 0 with no controllers");
        }
        // HCIGETDEVINFO for dev 0 → ENODEV (no controller present).
        let mut info = [0u8; 92];
        if sys(
            Syscall::Ioctl,
            a2(fd, 0x8004_48d3, info.as_mut_ptr() as u64),
        ) != Some(ENODEV)
        {
            return Err("HCIGETDEVINFO on an absent controller must be ENODEV");
        }
        // HCIDEVUP with dev id 0 by value → ENODEV.
        if sys(Syscall::Ioctl, a2(fd, 0x4004_48c9, 0)) != Some(ENODEV) {
            return Err("HCIDEVUP on an absent controller must be ENODEV");
        }
        close(fd);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_bluetooth_hci_ioctls
);

/// Binding HCI_CHANNEL_MONITOR is accepted; with no controllers the replay is
/// empty so recv returns EAGAIN (the plumbing btmon drives).
fn smoke_abi_socket_bluetooth_monitor() -> TestResult {
    with_setup(|| {
        let fd = open(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)?;
        let mut mon = [0u8; 6];
        mon[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_le_bytes());
        mon[2..4].copy_from_slice(&0xffffu16.to_le_bytes()); // HCI_DEV_NONE
        mon[4..6].copy_from_slice(&2u16.to_le_bytes()); // HCI_CHANNEL_MONITOR
        if bind(fd, &mon) != Some(0) {
            return Err("bind to the monitor channel failed");
        }
        let mut buf = [0u8; 64];
        if recv(fd, &mut buf, 0) != Some(EAGAIN) {
            return Err("monitor recv with no controllers must be EAGAIN");
        }
        close(fd);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_bluetooth_monitor
);

/// L2CAP/RFCOMM/SCO protocol-family surface: per-protocol socket-type rules
/// (ESOCKTNOSUPPORT), sockaddr bind, and a hardware-gated connect that fails.
fn smoke_abi_socket_bluetooth_conn_family() -> TestResult {
    with_setup(|| {
        // L2CAP (proto 0) accepts SOCK_SEQPACKET.
        let l2 = open(AF_BLUETOOTH, SOCK_SEQPACKET, 0)?;
        // RFCOMM (proto 3) requires SOCK_STREAM.
        if sys(Syscall::SocketOpen, a2(AF_BLUETOOTH, SOCK_SEQPACKET, 3)) != Some(ESOCKTNOSUPPORT) {
            return Err("RFCOMM non-STREAM must be ESOCKTNOSUPPORT");
        }
        let rc = open(AF_BLUETOOTH, SOCK_STREAM, 3)?;
        // SCO (proto 2) requires SOCK_SEQPACKET.
        if sys(Syscall::SocketOpen, a2(AF_BLUETOOTH, SOCK_STREAM, 2)) != Some(ESOCKTNOSUPPORT) {
            return Err("SCO non-SEQPACKET must be ESOCKTNOSUPPORT");
        }
        let sco = open(AF_BLUETOOTH, SOCK_SEQPACKET, 2)?;
        // bind a sockaddr_l2 (family + psm + bdaddr + cid + bdaddr_type = 13).
        let mut addr = [0u8; 13];
        addr[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_le_bytes());
        addr[2..4].copy_from_slice(&0x1001u16.to_le_bytes()); // l2_psm
        if bind(l2, &addr) != Some(0) {
            return Err("L2CAP bind failed");
        }
        // connect needs a controller + reachable peer: it must fail here.
        if connect(l2, &addr).is_none_or(|r| r >= 0) {
            return Err("hardware-gated L2CAP connect should fail");
        }
        close(l2);
        close(rc);
        close(sco);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_bluetooth_conn_family
);

/// `inet_create`: SOCK_RAW without CAP_NET_RAW → EPERM (after the protocol
/// lookup, so a bad protocol is still EPROTONOSUPPORT).
/// `__inet_bind`: a port below 1024 without CAP_NET_BIND_SERVICE → EACCES.
fn smoke_abi_socket_errno_unprivileged_raw_and_low_port() -> TestResult {
    with_setup(|| {
        let tcp = open(AF_INET, SOCK_STREAM, 0)?;
        drop_to_unprivileged_uid()?;
        if sys(Syscall::SocketOpen, a2(AF_INET, SOCK_RAW, IPPROTO_ICMP)) != Some(EPERM) {
            return Err("SOCK_RAW without CAP_NET_RAW must be EPERM");
        }
        if sys(Syscall::SocketOpen, a2(AF_INET, SOCK_RAW, 0)) != Some(EPROTONOSUPPORT_ERR) {
            return Err("the protocol lookup must precede the CAP_NET_RAW check");
        }
        if bind(tcp, &sin(AF_INET, LOOPBACK, 80)) != Some(EACCES_ERR) {
            return Err("binding port 80 without CAP_NET_BIND_SERVICE must be EACCES");
        }
        if bind(tcp, &sin(AF_INET, LOOPBACK, 31001)) != Some(0) {
            return Err("an unprivileged bind to a high port must succeed");
        }
        close(tcp);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_unprivileged_raw_and_low_port
);

// ─────────────────────────── socketpair(2) ───────────────────────────

/// `net/socket.c::__sys_socketpair` stores the descriptors to `usockvec`
/// (EFAULT) BEFORE `sock_create` runs, so a bad `sv` beats every family /
/// type / protocol error; then `sock_create`'s own checks apply, and only a
/// family without ->socketpair reaches EOPNOTSUPP.
fn smoke_abi_socket_errno_socketpair_order() -> TestResult {
    with_setup(|| {
        let mut sv = [0u8; 8];
        let svp = sv.as_mut_ptr() as u64;
        if sys(Syscall::SocketPair, a3(9999, SOCK_STREAM, 0, BAD_USER_PTR)) != Some(EFAULT) {
            return Err("a faulting sv must be EFAULT before the family check");
        }
        if sys(
            Syscall::SocketPair,
            a3(AF_INET, SOCK_STREAM, 0, BAD_USER_PTR),
        ) != Some(EFAULT)
        {
            return Err("a faulting sv must be EFAULT before EOPNOTSUPP");
        }
        if sys(Syscall::SocketPair, a3(AF_INET, 12, 0, svp)) != Some(EINVAL) {
            return Err("socketpair type >= SOCK_MAX must be EINVAL");
        }
        if sys(Syscall::SocketPair, a3(AF_INET, SOCK_SEQPACKET, 0, svp))
            != Some(ESOCKTNOSUPPORT_ERR)
        {
            return Err("socketpair(AF_INET, SEQPACKET) must fail inet_create first");
        }
        if sys(Syscall::SocketPair, a3(AF_UNIX, SOCK_STREAM, 2, svp)) != Some(EPROTONOSUPPORT_ERR) {
            return Err("socketpair(AF_UNIX) with a foreign protocol must be EPROTONOSUPPORT");
        }
        if sys(Syscall::SocketPair, a3(AF_UNIX, SOCK_RAW, 0, svp)) != Some(0) {
            return Err("socketpair(AF_UNIX, SOCK_RAW) must succeed as a datagram pair");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_socketpair_order
);

// ────────────────────────────── bind(2) ──────────────────────────────

/// `net/ipv4/af_inet.c::__inet_bind` on a TCP socket, after the addrlen /
/// family checks: an address no interface owns → EADDRNOTAVAIL (before the
/// already-bound EINVAL), unless IP_FREEBIND is set — for UDP too.
fn smoke_abi_socket_errno_bind_inet_validation_order() -> TestResult {
    with_setup(|| {
        let fd = open(AF_INET, SOCK_STREAM, 0)?;
        if bind(fd, &sin(AF_INET, NONLOCAL, 31002)) != Some(EADDRNOTAVAIL_ERR) {
            return Err("a TCP bind to a non-local address must be EADDRNOTAVAIL");
        }
        if bind(fd, &sin(AF_INET, LOOPBACK, 31002)) != Some(0) {
            return Err("a valid loopback bind must succeed");
        }
        if bind(fd, &sin(AF_INET, NONLOCAL, 31102)) != Some(EADDRNOTAVAIL_ERR) {
            return Err("EADDRNOTAVAIL must precede the already-bound EINVAL");
        }
        if bind(fd, &sin(AF_INET, LOOPBACK, 31102)) != Some(EINVAL) {
            return Err("a second TCP bind must be EINVAL");
        }
        close(fd);
        for (kind, port) in [(SOCK_STREAM, 31302u16), (SOCK_DGRAM, 31303u16)] {
            let free = open(AF_INET, kind, 0)?;
            if set_int(free, IPPROTO_IP, IP_FREEBIND, 1) != Some(0)
                || bind(free, &sin(AF_INET, NONLOCAL, port)) != Some(0)
            {
                return Err("IP_FREEBIND must permit a non-local bind");
            }
            close(free);
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_bind_inet_validation_order
);

/// `inet_csk_get_port` / `inet_bind_conflict`: a TCP port stays reserved from
/// bind(2) whether or not the owner listens, a wildcard bind conflicts with
/// a specific one, and SO_REUSEADDR on both sides shares the port only while
/// the holder is not listening.
fn smoke_abi_socket_errno_bind_tcp_port_conflicts() -> TestResult {
    with_setup(|| {
        let port = 31010;
        let a = open(AF_INET, SOCK_STREAM, 0)?;
        if bind(a, &sin(AF_INET, LOOPBACK, port)) != Some(0) {
            return Err("first bind failed");
        }
        let b = open(AF_INET, SOCK_STREAM, 0)?;
        if bind(b, &sin(AF_INET, LOOPBACK, port)) != Some(EADDRINUSE_ERR) {
            return Err("a second bind of a bound (not listening) port must be EADDRINUSE");
        }
        if bind(b, &sin(AF_INET, 0, port)) != Some(EADDRINUSE_ERR) {
            return Err("a wildcard bind must conflict with a specific one");
        }
        close(a);
        close(b);

        let port = 31011;
        let a = open(AF_INET, SOCK_STREAM, 0)?;
        let b = open(AF_INET, SOCK_STREAM, 0)?;
        let c = open(AF_INET, SOCK_STREAM, 0)?;
        for fd in [a, b, c] {
            if set_int(fd, SOL_SOCKET, SO_REUSEADDR, 1) != Some(0) {
                return Err("SO_REUSEADDR set failed");
            }
        }
        if bind(a, &sin(AF_INET, LOOPBACK, port)) != Some(0)
            || bind(b, &sin(AF_INET, LOOPBACK, port)) != Some(0)
        {
            return Err("SO_REUSEADDR on both non-listening sockets must share the port");
        }
        if listen(a) != Some(0) {
            return Err("listen failed");
        }
        if bind(c, &sin(AF_INET, LOOPBACK, port)) != Some(EADDRINUSE_ERR) {
            return Err("SO_REUSEADDR must not share a port with a listener");
        }
        close(a);
        close(b);
        close(c);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_bind_tcp_port_conflicts
);

/// `inet_csk_get_port` with snum == 0 (TCP): port 0 selects a distinct
/// ephemeral port per socket instead of literally binding port 0 (which made
/// the second wildcard bind EADDRINUSE).
fn smoke_abi_socket_errno_bind_port_zero_is_ephemeral() -> TestResult {
    with_setup(|| {
        {
            let a = open(AF_INET, SOCK_STREAM, 0)?;
            let b = open(AF_INET, SOCK_STREAM, 0)?;
            if bind(a, &sin(AF_INET, LOOPBACK, 0)) != Some(0)
                || bind(b, &sin(AF_INET, LOOPBACK, 0)) != Some(0)
            {
                return Err("two port-0 binds must both succeed");
            }
            let (pa, pb) = (local_port(a)?, local_port(b)?);
            if pa == 0 || pb == 0 || pa == pb {
                return Err("port-0 binds must report distinct non-zero ports");
            }
            close(a);
            close(b);
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_bind_port_zero_is_ephemeral
);

/// `net/unix/af_unix.c::unix_bind_bsd`: `vfs_mknod` runs before the
/// already-bound test and an existing name is EEXIST → EADDRINUSE — even for
/// an already-bound socket — while a fresh name on a bound socket is EINVAL.
/// `unix_validate_addr`: a sun_path longer than 108 bytes is EINVAL.
fn smoke_abi_socket_errno_bind_unix_existing_path() -> TestResult {
    with_memfs("/ue", "ue", &[], || {
        let a = open(AF_UNIX, SOCK_STREAM, 0)?;
        let (addr, alen) = unix_addr(b"/ue/sock");
        if sys(Syscall::SocketBind, a2(a, addr.as_ptr() as u64, alen)) != Some(0) {
            return Err("first pathname bind failed");
        }
        close(a); // the node outlives the socket, exactly as on Linux
        let b = open(AF_UNIX, SOCK_DGRAM, 0)?;
        if sys(Syscall::SocketBind, a2(b, addr.as_ptr() as u64, alen)) != Some(EADDRINUSE_ERR) {
            return Err("binding an existing pathname must be EADDRINUSE");
        }
        let (fresh, flen) = unix_addr(b"/ue/other");
        if sys(Syscall::SocketBind, a2(b, fresh.as_ptr() as u64, flen)) != Some(0) {
            return Err("binding a fresh pathname failed");
        }
        if sys(Syscall::SocketBind, a2(b, addr.as_ptr() as u64, alen)) != Some(EADDRINUSE_ERR) {
            return Err("an existing pathname is EADDRINUSE even on a bound socket");
        }
        let (third, tlen) = unix_addr(b"/ue/third");
        if sys(Syscall::SocketBind, a2(b, third.as_ptr() as u64, tlen)) != Some(EINVAL) {
            return Err("a fresh pathname on a bound socket must be EINVAL");
        }
        let c = open(AF_UNIX, SOCK_STREAM, 0)?;
        let long = [b'x'; 109];
        let (laddr, llen) = unix_addr(&long);
        if sys(Syscall::SocketBind, a2(c, laddr.as_ptr() as u64, llen)) != Some(EINVAL) {
            return Err("a sun_path over 108 bytes must be EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_bind_unix_existing_path
);

/// `net/ipv6/af_inet6.c::inet6_bind_sk` / `__inet6_bind`: addrlen <
/// SIN6_LEN_RFC2133 → EINVAL, then a foreign family → EAFNOSUPPORT.
fn smoke_abi_socket_errno_bind_inet6_validation() -> TestResult {
    with_setup(|| {
        let fd = open(AF_INET6, SOCK_STREAM, 0)?;
        let full = sin6(AF_INET6, 31020, false);
        if bind(fd, &full[..16]) != Some(EINVAL) {
            return Err("a 16-byte sockaddr_in6 must be EINVAL");
        }
        if bind(fd, &sin6(AF_INET, 31020, false)) != Some(EAFNOSUPPORT) {
            return Err("an AF_INET family on an AF_INET6 bind must be EAFNOSUPPORT");
        }
        if bind(fd, &full[..24]) != Some(0) {
            return Err("a SIN6_LEN_RFC2133 (24-byte) address must bind");
        }
        let (r, len, _) = get_name(fd, false);
        if r != Some(0) || len != 28 {
            return Err("getsockname on AF_INET6 must report sizeof(sockaddr_in6)");
        }
        close(fd);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_bind_inet6_validation
);

// ───────────────────────────── listen(2) ─────────────────────────────

/// `__inet_listen_sk` → `inet_csk_listen_start` → `get_port(sk, 0)`: listen
/// on a never-bound TCP socket autobinds an ephemeral port (it is not
/// EINVAL); a second listen is fine; a connected socket is EINVAL.
/// SO_ACCEPTCONN (`sk_getsockopt`) is `sk_state == TCP_LISTEN`, so a
/// merely-bound socket reports 0.
fn smoke_abi_socket_errno_listen_tcp_autobind_and_state() -> TestResult {
    with_setup(|| {
        let fd = open(AF_INET, SOCK_STREAM, 0)?;
        if listen(fd) != Some(0) {
            return Err("listen on an unbound TCP socket must autobind and succeed");
        }
        if local_port(fd)? == 0 {
            return Err("the autobound listener must report a non-zero port");
        }
        if listen(fd) != Some(0) {
            return Err("a second TCP listen must succeed");
        }
        let mut out = [0u8; 4];
        if getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 1
        {
            return Err("SO_ACCEPTCONN must be 1 on a listener");
        }
        let bound = open(AF_INET, SOCK_STREAM, 0)?;
        if bind(bound, &sin(AF_INET, LOOPBACK, 31030)) != Some(0) {
            return Err("bind failed");
        }
        if getsockopt(bound, SOL_SOCKET, SO_ACCEPTCONN, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 0
        {
            return Err("SO_ACCEPTCONN must be 0 on a bound, non-listening socket");
        }
        let srv = tcp_listener(31031)?;
        let cli = open(AF_INET, SOCK_STREAM, 0)?;
        if connect(cli, &sin(AF_INET, LOOPBACK, 31031)) != Some(0) {
            return Err("loopback connect failed");
        }
        if listen(cli) != Some(EINVAL) {
            return Err("listen on a connected TCP socket must be EINVAL");
        }
        close(fd);
        close(bound);
        close(srv);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_listen_tcp_autobind_and_state
);

// ───────────────────────────── accept(2) ─────────────────────────────

/// `inet_csk_accept`: a socket that is bound but not listening is EINVAL, not
/// an empty listener's EAGAIN. `sock_no_accept`: datagram sockets →
/// EOPNOTSUPP.
fn smoke_abi_socket_errno_accept_not_listening() -> TestResult {
    with_setup(|| {
        let fd = open(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)?;
        if bind(fd, &sin(AF_INET, LOOPBACK, 31040)) != Some(0) {
            return Err("bind failed");
        }
        if sys(Syscall::SocketAccept4, a3(fd, 0, 0, 0)) != Some(EINVAL) {
            return Err("accept on a bound, non-listening TCP socket must be EINVAL");
        }
        let fresh = open(AF_INET, SOCK_STREAM, 0)?;
        if sys(Syscall::SocketAccept, a2(fresh, 0, 0)) != Some(EINVAL) {
            return Err("accept on a fresh TCP socket must be EINVAL");
        }
        for (d, t) in [(AF_INET, SOCK_DGRAM), (AF_UNIX, SOCK_DGRAM)] {
            let s = open(d, t, 0)?;
            if sys(Syscall::SocketAccept, a2(s, 0, 0)) != Some(EOPNOTSUPP) {
                return Err("accept on a datagram socket must be EOPNOTSUPP");
            }
            close(s);
        }
        close(fd);
        close(fresh);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_accept_not_listening
);

// ───────────────────────────── connect(2) ────────────────────────────

/// `net/ipv4/af_inet.c::__inet_stream_connect`: the socket-state switch runs
/// before `tcp_v4_connect` looks at the address, so a connected (or
/// listening) socket is EISCONN whatever address follows, while a bound but
/// non-listening socket is still TCP_CLOSE and may connect.
fn smoke_abi_socket_errno_connect_tcp_order() -> TestResult {
    with_setup(|| {
        let srv = tcp_listener(31051)?;
        let cli = open(AF_INET, SOCK_STREAM, 0)?;
        if connect(cli, &sin(AF_INET, LOOPBACK, 31051)) != Some(0) {
            return Err("loopback connect failed");
        }
        if connect(cli, &sin(AF_UNIX, LOOPBACK, 1)[..8]) != Some(EISCONN_ERR) {
            return Err("a connected socket must be EISCONN before the address is checked");
        }
        if connect(srv, &sin(AF_INET, LOOPBACK, 31051)) != Some(EISCONN_ERR) {
            return Err("connect on a listener must be EISCONN");
        }
        // A bound, non-listening socket is still TCP_CLOSE and may connect.
        let bound = open(AF_INET, SOCK_STREAM, 0)?;
        if bind(bound, &sin(AF_INET, LOOPBACK, 31052)) != Some(0)
            || connect(bound, &sin(AF_INET, LOOPBACK, 31051)) != Some(0)
        {
            return Err("a bound client must be able to connect");
        }
        close(cli);
        close(bound);
        close(srv);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_connect_tcp_order
);

/// connect(AF_UNSPEC) dissolves an association and succeeds on every family:
/// `__inet_stream_connect` → `tcp_disconnect`, `unix_dgram_connect`
/// ("1003.1g breaking connected state with AF_UNSPEC"), `inet_dgram_connect`
/// on a raw socket, and `netlink_connect`. (UDP: abi_udp_tests.)
fn smoke_abi_socket_errno_connect_af_unspec_disconnects() -> TestResult {
    with_memfs("/uu", "uu", &[], || {
        let unspec = [0u8; 16];
        let tcp = open(AF_INET, SOCK_STREAM, 0)?;
        let udg = open(AF_UNIX, SOCK_DGRAM, 0)?;
        let raw = open(AF_INET, SOCK_RAW, IPPROTO_ICMP)?;
        let nl = open(AF_NETLINK, SOCK_RAW, 0)?;
        for fd in [tcp, udg, raw, nl] {
            if connect(fd, &unspec) != Some(0) {
                return Err("connect(AF_UNSPEC) must succeed on every family");
            }
        }
        // A connected unix datagram socket really forgets its peer.
        let srv = open(AF_UNIX, SOCK_DGRAM, 0)?;
        let (addr, alen) = unix_addr(b"/uu/d");
        if sys(Syscall::SocketBind, a2(srv, addr.as_ptr() as u64, alen)) != Some(0)
            || sys(Syscall::SocketConnect, a2(udg, addr.as_ptr() as u64, alen)) != Some(0)
            || send(udg, b"x", 0) != Some(1)
        {
            return Err("unix datagram connect/send setup failed");
        }
        if connect(udg, &unspec) != Some(0) || send(udg, b"x", 0) != Some(ENOTCONN_ERR) {
            return Err("after AF_UNSPEC a unix datagram send must be ENOTCONN");
        }
        // A connected TCP socket is back to TCP_CLOSE and may connect again.
        let lst = tcp_listener(31061)?;
        if connect(tcp, &sin(AF_INET, LOOPBACK, 31061)) != Some(0)
            || connect(tcp, &unspec) != Some(0)
            || get_name(tcp, true).0 != Some(ENOTCONN_ERR)
        {
            return Err("TCP connect(AF_UNSPEC) must dissolve the connection");
        }
        close(lst);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_connect_af_unspec_disconnects
);

/// `unix_stream_connect`: after the peer lookup, only TCP_ESTABLISHED is
/// EISCONN — a listening socket is EINVAL.
fn smoke_abi_socket_errno_connect_unix_listener_einval() -> TestResult {
    with_memfs("/uc", "uc", &[], || {
        let a = open(AF_UNIX, SOCK_STREAM, 0)?;
        let b = open(AF_UNIX, SOCK_STREAM, 0)?;
        let (aa, al) = unix_addr(b"/uc/a");
        let (ba, bl) = unix_addr(b"/uc/b");
        if sys(Syscall::SocketBind, a2(a, aa.as_ptr() as u64, al)) != Some(0)
            || sys(Syscall::SocketBind, a2(b, ba.as_ptr() as u64, bl)) != Some(0)
            || listen(a) != Some(0)
            || listen(b) != Some(0)
        {
            return Err("unix listener setup failed");
        }
        if sys(Syscall::SocketConnect, a2(a, ba.as_ptr() as u64, bl)) != Some(EINVAL) {
            return Err("connect from a unix listener must be EINVAL");
        }
        close(a);
        close(b);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_connect_unix_listener_einval
);

// ────────────────────────────── send(2) ──────────────────────────────

/// `unix_stream_sendmsg`: a destination address on a stream socket is
/// EISCONN when connected and EOPNOTSUPP otherwise.
/// `unix_dgram_sendmsg` → `unix_validate_addr`: a non-AF_UNIX name → EINVAL.
fn smoke_abi_socket_errno_send_unix_with_address() -> TestResult {
    with_setup(|| {
        let mut sv = [0u8; 8];
        if sys(
            Syscall::SocketPair,
            a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("socketpair setup failed");
        }
        let end = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
        let (addr, alen) = unix_addr(b"/nowhere");
        if sendto(end, b"x", 0, &addr[..alen as usize]) != Some(EISCONN_ERR) {
            return Err("sendto with an address on a connected stream must be EISCONN");
        }
        let lone = open(AF_UNIX, SOCK_STREAM, 0)?;
        if sendto(lone, b"x", 0, &addr[..alen as usize]) != Some(EOPNOTSUPP) {
            return Err("sendto with an address on an unconnected stream must be EOPNOTSUPP");
        }
        let dg = open(AF_UNIX, SOCK_DGRAM, 0)?;
        if sendto(dg, b"x", 0, &sin(AF_INET, LOOPBACK, 1)) != Some(EINVAL) {
            return Err("a unix datagram sendto with a non-AF_UNIX name must be EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_send_unix_with_address
);

/// `net/ipv4/raw.c::raw_sendmsg`: MSG_OOB → EOPNOTSUPP; no name and not
/// connected → EDESTADDRREQ. `raw_recvmsg`: MSG_OOB → EOPNOTSUPP.
/// `inet_shutdown`: an unconnected raw socket is TCP_CLOSE → ENOTCONN.
fn smoke_abi_socket_errno_raw_socket_rules() -> TestResult {
    with_setup(|| {
        let raw = open(AF_INET, SOCK_RAW, IPPROTO_ICMP)?;
        if send(raw, b"x", MSG_OOB) != Some(EOPNOTSUPP) {
            return Err("raw MSG_OOB send must be EOPNOTSUPP");
        }
        if send(raw, b"x", 0) != Some(EDESTADDRREQ_ERR) {
            return Err("an unconnected raw send with no name must be EDESTADDRREQ");
        }
        let mut buf = [0u8; 8];
        if recv(raw, &mut buf, MSG_OOB) != Some(EOPNOTSUPP) {
            return Err("raw MSG_OOB recv must be EOPNOTSUPP");
        }
        if sys(Syscall::SocketShutdown, a1(raw, SHUT_RDWR)) != Some(ENOTCONN_ERR) {
            return Err("shutdown on an unconnected raw socket must be ENOTCONN");
        }
        if bind(raw, &sin(AF_INET, NONLOCAL, 0)) != Some(EADDRNOTAVAIL_ERR) {
            return Err("raw_bind to a non-local address must be EADDRNOTAVAIL");
        }
        close(raw);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_raw_socket_rules
);

// ────────────────────────────── recv(2) ──────────────────────────────

/// `tcp_recvmsg_locked`: a never-connected socket is ENOTCONN, as is a
/// listener; with MSG_OOB a listener is still ENOTCONN, anything else finds
/// no urgent byte in `tcp_recv_urg` → EINVAL.
fn smoke_abi_socket_errno_recv_tcp_rules() -> TestResult {
    with_setup(|| {
        let fresh = open(AF_INET, SOCK_STREAM, 0)?;
        let listener = tcp_listener(31110)?;
        let mut buf = [0u8; 8];
        if recv(fresh, &mut buf, MSG_DONTWAIT) != Some(ENOTCONN_ERR) {
            return Err("recv on a fresh TCP socket must be ENOTCONN");
        }
        if recv(listener, &mut buf, MSG_DONTWAIT) != Some(ENOTCONN_ERR) {
            return Err("recv on a TCP listener must be ENOTCONN");
        }
        if recv(fresh, &mut buf, MSG_OOB) != Some(EINVAL) {
            return Err("MSG_OOB recv without urgent data must be EINVAL");
        }
        if recv(listener, &mut buf, MSG_OOB) != Some(ENOTCONN_ERR) {
            return Err("MSG_OOB recv on a listener must be ENOTCONN");
        }
        close(fresh);
        close(listener);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_recv_tcp_rules
);

/// `unix_dgram_recvmsg` needs neither a name nor a peer: an unbound AF_UNIX
/// datagram socket simply has nothing queued → EAGAIN under MSG_DONTWAIT
/// (not ENOTCONN).
fn smoke_abi_socket_errno_recv_unbound_dgram_eagain() -> TestResult {
    with_setup(|| {
        {
            let fd = open(AF_UNIX, SOCK_DGRAM, 0)?;
            let mut buf = [0u8; 8];
            if recv(fd, &mut buf, MSG_DONTWAIT) != Some(EAGAIN) {
                return Err("recv on an unbound datagram socket must be EAGAIN");
            }
            close(fd);
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_recv_unbound_dgram_eagain
);

// ──────────────────────────── shutdown(2) ────────────────────────────

/// `net/ipv4/af_inet.c::inet_shutdown`: a TCP listener is not ENOTCONN — the
/// TCP_LISTEN arm succeeds, and a shutdown including the receive side stops
/// listening (`tcp_disconnect`), after which accept is EINVAL. A bound but
/// never-listening TCP socket is TCP_CLOSE → ENOTCONN.
/// `unix_shutdown`: a `how` outside SHUT_RD..=SHUT_RDWR is EINVAL for
/// datagram sockets too. `sock_no_shutdown` (netlink) → EOPNOTSUPP.
fn smoke_abi_socket_errno_shutdown_rules() -> TestResult {
    with_setup(|| {
        let listener = tcp_listener(31130)?;
        if sys(Syscall::SocketShutdown, a1(listener, SHUT_WR)) != Some(0) {
            return Err("shutdown(SHUT_WR) on a listener must succeed");
        }
        if sys(Syscall::SocketShutdown, a1(listener, SHUT_RDWR)) != Some(0) {
            return Err("shutdown(SHUT_RDWR) on a listener must succeed");
        }
        if sys(Syscall::SocketAccept, a2(listener, 0, 0)) != Some(EINVAL) {
            return Err("a listener shut down for reading must stop listening");
        }
        let bound = open(AF_INET, SOCK_STREAM, 0)?;
        if bind(bound, &sin(AF_INET, LOOPBACK, 31131)) != Some(0)
            || sys(Syscall::SocketShutdown, a1(bound, SHUT_RDWR)) != Some(ENOTCONN_ERR)
        {
            return Err("shutdown on a bound, non-listening TCP socket must be ENOTCONN");
        }
        let udg = open(AF_UNIX, SOCK_DGRAM, 0)?;
        if sys(Syscall::SocketShutdown, a1(udg, 3)) != Some(EINVAL) {
            return Err("a bad how on a unix datagram socket must be EINVAL");
        }
        let nl = open(AF_NETLINK, SOCK_RAW, 0)?;
        if sys(Syscall::SocketShutdown, a1(nl, SHUT_RDWR)) != Some(EOPNOTSUPP) {
            return Err("shutdown on a netlink socket must be EOPNOTSUPP");
        }
        close(listener);
        close(bound);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_shutdown_rules
);

// ─────────────────────── getsockname / getpeername ───────────────────────

/// `inet6_getname` reports a full `struct sockaddr_in6` (28 bytes, with
/// sin6_scope_id), bound or not.
fn smoke_abi_socket_errno_getname_inet6_length() -> TestResult {
    with_setup(|| {
        let v6 = open(AF_INET6, SOCK_STREAM, 0)?;
        let (r, len, _) = get_name(v6, false);
        if r != Some(0) || len != 28 {
            return Err("getsockname on an unbound AF_INET6 socket must report 28 bytes");
        }
        close(v6);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_getname_inet6_length
);

// ──────────────────────── getsockopt / setsockopt ────────────────────────

/// INET getsockopt levels: `do_ip_getsockopt` / `do_tcp_getsockopt` default
/// → ENOPROTOOPT, but a level that is neither the transport's own nor SOL_IP
/// (incl. IPPROTO_TCP on a UDP socket) reaches `do_ip_getsockopt`'s
/// `if (level != SOL_IP) return -EOPNOTSUPP;`.
fn smoke_abi_socket_errno_getsockopt_unknown_by_level() -> TestResult {
    with_setup(|| {
        let tcp = open(AF_INET, SOCK_STREAM, 0)?;
        let udp = open(AF_INET, SOCK_DGRAM, 0)?;
        let mut out = [0u8; 4];
        let cases: &[(u64, u64, u64, i64)] = &[
            (tcp, IPPROTO_IP, 9999, ENOPROTOOPT_ERR),
            (tcp, IPPROTO_TCP, 9999, ENOPROTOOPT_ERR),
            (tcp, 9999, 1, EOPNOTSUPP),
            (udp, IPPROTO_TCP, TCP_MAXSEG, EOPNOTSUPP),
        ];
        for &(fd, level, name, want) in cases {
            if getsockopt(fd, level, name, &mut out).0 != Some(want) {
                return Err("getsockopt unknown-option errno mismatch");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_getsockopt_unknown_by_level
);

fn smoke_abi_socket_errno_setsockopt_unknown_is_enoprotoopt() -> TestResult {
    with_setup(|| {
        let tcp = open(AF_INET, SOCK_STREAM, 0)?;
        let udp = open(AF_INET, SOCK_DGRAM, 0)?;
        let value = 1i32.to_ne_bytes();
        for &(fd, level, name) in &[
            (tcp, IPPROTO_TCP, 9999),
            (tcp, IPPROTO_IP, 9999),
            (udp, IPPROTO_TCP, TCP_MAXSEG),
        ] {
            if setsockopt(fd, level, name, &value) != Some(ENOPROTOOPT_ERR) {
                return Err("unknown setsockopt must return ENOPROTOOPT");
            }
        }
        close(tcp);
        close(udp);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_setsockopt_unknown_is_enoprotoopt
);

/// Linux `net/core/sock.c::{sk_setsockopt,sk_getsockopt}` accepts all four
/// receive-timestamp ABI names on every socket family.  Enabling one selects
/// the same SOCK_RCVTSTAMP/SOCK_RCVTSTAMPNS/SOCK_TSTAMP_NEW state; disabling
/// any one clears SOCK_RCVTSTAMP, and a short set value is EINVAL before
/// option dispatch. Linux's compatibility quirk makes SO_TIMESTAMP_NEW read
/// true for the SO_TIMESTAMPNS_NEW state as well.
fn smoke_abi_socket_timestamp_options_match_linux() -> TestResult {
    with_setup(|| {
        let fd = open(AF_UNIX, SOCK_DGRAM, 0)?;
        let variants = [
            SO_TIMESTAMP_OLD,
            SO_TIMESTAMPNS_OLD,
            SO_TIMESTAMP_NEW,
            SO_TIMESTAMPNS_NEW,
        ];
        let mut out = [0u8; 4];
        for &selected in &variants {
            if set_int(fd, SOL_SOCKET, selected, 1) != Some(0) {
                return Err("Linux SO_TIMESTAMP variant must be accepted");
            }
            for &name in &variants {
                out.fill(0);
                let (result, len) = getsockopt(fd, SOL_SOCKET, name, &mut out);
                let expected = u32::from(
                    name == selected
                        || (selected == SO_TIMESTAMPNS_NEW && name == SO_TIMESTAMP_NEW),
                );
                if result != Some(0) || len != 4 || u32::from_ne_bytes(out) != expected {
                    return Err("SO_TIMESTAMP variants did not expose Linux's state mapping");
                }
            }
        }
        if setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP_OLD, &[1, 0, 0]) != Some(EINVAL) {
            return Err("short SO_TIMESTAMP optval must be EINVAL");
        }
        if set_int(fd, SOL_SOCKET, SO_TIMESTAMP_OLD, 0) != Some(0) {
            return Err("disabling SO_TIMESTAMP must succeed");
        }
        for &name in &variants {
            out.fill(0xA5);
            if getsockopt(fd, SOL_SOCKET, name, &mut out).0 != Some(0)
                || u32::from_ne_bytes(out) != 0
            {
                return Err("disabling one timestamp variant must clear receive timestamping");
            }
        }
        close(fd);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_timestamp_options_match_linux
);

/// `sk_setsockopt` gives CAP_NET_ADMIN holders the forced buffer variants,
/// doubles their signed-int request exactly as Linux does, and validates a
/// native `sock_fprog` before attaching SO_ATTACH_FILTER. These are the three
/// options systemd-logind installs while bringing up its uevent monitors.
fn smoke_abi_socket_logind_sockopts_match_linux() -> TestResult {
    with_setup(|| {
        let fd = open(AF_UNIX, SOCK_DGRAM, 0)?;

        if set_int(fd, SOL_SOCKET, SO_SNDBUFFORCE, 65_536) != Some(0)
            || set_int(fd, SOL_SOCKET, SO_RCVBUFFORCE, 32_768) != Some(0)
        {
            return Err("privileged forced socket buffers must be accepted");
        }
        let mut out = [0u8; 4];
        if getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 131_072
        {
            return Err("SO_SNDBUFFORCE must use Linux's doubled value");
        }
        out.fill(0);
        if getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 65_536
        {
            return Err("SO_RCVBUFFORCE must use Linux's doubled value");
        }

        // BPF_RET | BPF_K, return all bytes.
        let mut filter = [0u8; 8];
        filter[0..2].copy_from_slice(&0x06u16.to_ne_bytes());
        filter[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
        let mut fprog = [0u8; 16];
        fprog[0..2].copy_from_slice(&1u16.to_ne_bytes());
        fprog[8..16].copy_from_slice(&(filter.as_ptr() as u64).to_ne_bytes());
        if setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog) != Some(0) {
            return Err("valid one-instruction classic filter must attach");
        }
        if setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog[..15]) != Some(EINVAL) {
            return Err("non-native sock_fprog size must be EINVAL");
        }
        fprog[0..2].copy_from_slice(&0u16.to_ne_bytes());
        if setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog) != Some(EINVAL) {
            return Err("zero-length classic filter must be EINVAL");
        }
        let invalid_filter = [0u8; 8]; // BPF_LD | BPF_IMM, not a final RET.
        fprog[0..2].copy_from_slice(&1u16.to_ne_bytes());
        fprog[8..16].copy_from_slice(&(invalid_filter.as_ptr() as u64).to_ne_bytes());
        if setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog) != Some(EINVAL) {
            return Err("invalid classic-filter image must be EINVAL");
        }
        fprog[8..16].copy_from_slice(&0u64.to_ne_bytes());
        if setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog) != Some(EFAULT) {
            return Err("unreadable classic-filter image must be EFAULT");
        }

        crate::handlers::__test_set_caps(FAKE_TASK, 0, 0);
        if set_int(fd, SOL_SOCKET, SO_SNDBUFFORCE, 4096) != Some(EPERM)
            || set_int(fd, SOL_SOCKET, SO_RCVBUFFORCE, 4096) != Some(EPERM)
        {
            return Err("unprivileged forced socket buffer must be EPERM");
        }
        if setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &[0; 3]) != Some(EINVAL) {
            return Err("short forced-buffer value must be EINVAL before capability check");
        }
        close(fd);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_logind_sockopts_match_linux
);

fn smoke_abi_socket_errno_ipv6_v6only_is_explicitly_supported() -> TestResult {
    with_setup(|| {
        let v6 = open(AF_INET6, SOCK_STREAM, 0)?;
        let v4 = open(AF_INET, SOCK_STREAM, 0)?;
        if set_int(v6, IPPROTO_IPV6, IPV6_V6ONLY, 1) != Some(0) {
            return Err("IPV6_V6ONLY must be accepted on AF_INET6");
        }
        let mut out = [0u8; 4];
        if getsockopt(v6, IPPROTO_IPV6, IPV6_V6ONLY, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 1
        {
            return Err("IPV6_V6ONLY round-trip mismatch");
        }
        if set_int(v4, IPPROTO_IPV6, IPV6_V6ONLY, 1) != Some(ENOPROTOOPT_ERR) {
            return Err("IPV6_V6ONLY on AF_INET must be ENOPROTOOPT");
        }
        close(v6);
        close(v4);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_ipv6_v6only_is_explicitly_supported
);

/// `do_tcp_setsockopt` value ranges: TCP_MAXSEG 0 or 88..=32767
/// (`tcp_sock_set_maxseg`), TCP_KEEPIDLE / TCP_KEEPINTVL 1..=32767, TCP_KEEPCNT
/// 1..=127, TCP_USER_TIMEOUT >= 0; an unregistered TCP_CONGESTION algorithm is
/// ENOENT (`tcp_set_congestion_control`).
fn smoke_abi_socket_errno_setsockopt_tcp_ranges() -> TestResult {
    with_setup(|| {
        let fd = open(AF_INET, SOCK_STREAM, 0)?;
        let cases: &[(u64, i32, i64)] = &[
            (TCP_MAXSEG, 87, EINVAL),
            (TCP_MAXSEG, 32_768, EINVAL),
            (TCP_MAXSEG, 0, 0),
            (TCP_MAXSEG, 536, 0),
            (TCP_KEEPIDLE, 0, EINVAL),
            (TCP_KEEPIDLE, 32_768, EINVAL),
            (TCP_KEEPIDLE, 60, 0),
            (TCP_KEEPINTVL, 0, EINVAL),
            (TCP_KEEPINTVL, 32_768, EINVAL),
            (TCP_KEEPCNT, 0, EINVAL),
            (TCP_KEEPCNT, 128, EINVAL),
            (TCP_KEEPCNT, 127, 0),
            (TCP_USER_TIMEOUT, -1, EINVAL),
            (TCP_USER_TIMEOUT, 0, 0),
        ];
        for &(name, v, want) in cases {
            if set_int(fd, IPPROTO_TCP, name, v) != Some(want) {
                return Err("TCP option range check mismatch");
            }
        }
        if setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, b"no-such-cc\0") != Some(ENOENT_ERR) {
            return Err("an unknown TCP_CONGESTION must be ENOENT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_setsockopt_tcp_ranges
);

fn smoke_abi_socket_errno_tcp_extended_options() -> TestResult {
    with_setup(|| {
        let fd = open(AF_INET, SOCK_STREAM, 0)?;
        let invalid: &[(u64, i32)] = &[
            (TCP_SYNCNT, 0),
            (TCP_SYNCNT, 128),
            (TCP_THIN_LINEAR_TIMEOUTS, -1),
            (TCP_THIN_LINEAR_TIMEOUTS, 2),
            (TCP_THIN_DUPACK, -1),
            (TCP_INQ, 2),
            (TCP_FASTOPEN_NO_COOKIE, -1),
            (TCP_TX_DELAY, 1 << 28),
        ];
        for &(name, value) in invalid {
            if set_int(fd, IPPROTO_TCP, name, value) != Some(EINVAL) {
                return Err("extended TCP option range errno mismatch");
            }
        }
        let accepted: &[(u64, i32, u32)] = &[
            (TCP_SYNCNT, 127, 127),
            (TCP_LINGER2, 999, 120),
            (TCP_LINGER2, -1, u32::MAX),
            (TCP_DEFER_ACCEPT, 2, 3),
            (TCP_WINDOW_CLAMP, 1, 1152),
            (TCP_THIN_LINEAR_TIMEOUTS, 1, 1),
            // Current Linux accepts this legacy knob as a no-op.
            (TCP_THIN_DUPACK, 1, 0),
            (TCP_NOTSENT_LOWAT, 4096, 4096),
            (TCP_FASTOPEN_NO_COOKIE, 1, 1),
            (TCP_INQ, 1, 1),
            (TCP_TX_DELAY, 999, 999),
        ];
        let mut out = [0u8; 4];
        for &(name, value, want) in accepted {
            if set_int(fd, IPPROTO_TCP, name, value) != Some(0)
                || getsockopt(fd, IPPROTO_TCP, name, &mut out).0 != Some(0)
                || u32::from_ne_bytes(out) != want
            {
                return Err("extended TCP option round-trip mismatch");
            }
        }
        if getsockopt(fd, IPPROTO_TCP, TCP_IS_MPTCP, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 0
        {
            return Err("ordinary TCP socket must report TCP_IS_MPTCP=0");
        }
        close(fd);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_tcp_extended_options
);

fn smoke_abi_socket_tcp_info_linux_layout() -> TestResult {
    with_setup(|| {
        let fresh = open(AF_INET, SOCK_STREAM, 0)?;
        let listener = tcp_listener(31240)?;
        let mut info = [0xA5u8; 288];
        let (r, len) = getsockopt(fresh, IPPROTO_TCP, TCP_INFO, &mut info);
        if r != Some(0) || len != 288 || info[0] != 0x07 {
            return Err("fresh TCP_INFO must report TCP_CLOSE in full Linux layout");
        }
        if info[1..].iter().any(|&byte| byte != 0) {
            return Err("unsupported fresh TCP_INFO metrics must be zero");
        }
        let mut short = [0u8; 8];
        let (r, len) = getsockopt(listener, IPPROTO_TCP, TCP_INFO, &mut short);
        if r != Some(0) || len != 8 || short[0] != 0x0A {
            return Err("short TCP_INFO must truncate and report TCP_LISTEN");
        }
        close(fresh);
        close(listener);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_tcp_info_linux_layout
);

/// `do_ip_setsockopt`: IP_TTL -1 restores the default (64), a 1-byte optval is
/// accepted, 0 is EINVAL; IP_TOS has no range check (a u8 is kept);
/// IP_MULTICAST_TTL -1 means 1 and is EINVAL on a stream socket.
/// `do_ip_getsockopt` IP_MTU: no route (unconnected) → ENOTCONN.
fn smoke_abi_socket_errno_setsockopt_ip_values() -> TestResult {
    with_setup(|| {
        let udp = open(AF_INET, SOCK_DGRAM, 0)?;
        let tcp = open(AF_INET, SOCK_STREAM, 0)?;
        let mut out = [0u8; 4];
        if set_int(udp, IPPROTO_IP, IP_TTL, 0) != Some(EINVAL) {
            return Err("IP_TTL 0 must be EINVAL");
        }
        if setsockopt(udp, IPPROTO_IP, IP_TTL, &[9u8]) != Some(0) {
            return Err("a 1-byte IP_TTL must be accepted");
        }
        if set_int(udp, IPPROTO_IP, IP_TTL, -1) != Some(0) {
            return Err("IP_TTL -1 must be accepted");
        }
        if getsockopt(udp, IPPROTO_IP, IP_TTL, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 64
        {
            return Err("IP_TTL -1 must restore the default 64");
        }
        if set_int(udp, IPPROTO_IP, IP_TOS, 0x1B8) != Some(0) {
            return Err("IP_TOS has no range check");
        }
        if getsockopt(udp, IPPROTO_IP, IP_TOS, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 0xB8
        {
            return Err("IP_TOS must keep the low byte");
        }
        if set_int(udp, IPPROTO_IP, IP_MULTICAST_TTL, -1) != Some(0) {
            return Err("IP_MULTICAST_TTL -1 must be accepted");
        }
        if getsockopt(udp, IPPROTO_IP, IP_MULTICAST_TTL, &mut out).0 != Some(0)
            || u32::from_ne_bytes(out) != 1
        {
            return Err("IP_MULTICAST_TTL -1 must read back as 1");
        }
        if set_int(tcp, IPPROTO_IP, IP_MULTICAST_TTL, 4) != Some(EINVAL) {
            return Err("IP_MULTICAST_TTL on a stream socket must be EINVAL");
        }
        if getsockopt(udp, IPPROTO_IP, IP_MTU, &mut out).0 != Some(ENOTCONN_ERR) {
            return Err("IP_MTU on an unconnected socket must be ENOTCONN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_setsockopt_ip_values
);

// ────────────────────────────── netlink ──────────────────────────────

/// `net/netlink/af_netlink.c::netlink_bind`: a bound socket may bind again to
/// its own portid (updating groups) but any other nl_pid is EINVAL.
fn smoke_abi_socket_errno_netlink_rebind() -> TestResult {
    with_setup(|| {
        let nl = open(AF_NETLINK, SOCK_RAW, 0)?;
        if bind(nl, &netlink_addr(0)) != Some(0) {
            return Err("netlink autobind failed");
        }
        let (r, len, out) = get_name(nl, false);
        if r != Some(0) || len != 12 {
            return Err("netlink getsockname failed");
        }
        let pid = u32::from_ne_bytes([out[4], out[5], out[6], out[7]]);
        if bind(nl, &netlink_addr(pid)) != Some(0) {
            return Err("re-binding a netlink socket to its own portid must succeed");
        }
        if bind(nl, &netlink_addr(pid.wrapping_add(7))) != Some(EINVAL) {
            return Err("re-binding a netlink socket to another portid must be EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_netlink_rebind
);

/// Descriptor, socket type, and argument precedence for shutdown(2).
/// Linux net/socket.c::__sys_shutdown:
/// 1. fd_empty(f) -> -EBADF
/// 2. !sock -> -ENOTSOCK
/// 3. how > SHUT_RDWR -> -EINVAL
/// 4. unconnected stream -> -ENOTCONN
fn smoke_abi_socket_errno_shutdown_precedence() -> TestResult {
    with_setup(|| {
        const BAD_FD: u64 = 4096;
        let mut pipefd = [0u8; 8];
        if sys(Syscall::Pipe2, a1(pipefd.as_mut_ptr() as u64, 0)) != Some(0) {
            return Err("pipe2 failed");
        }
        let pipe = i32::from_ne_bytes(pipefd[..4].try_into().unwrap()) as u64;

        // 1. Bad fd beats invalid how:
        if sys(Syscall::SocketShutdown, a1(BAD_FD, 99)) != Some(EBADF) {
            return Err("shutdown(BAD_FD, 99) must return -EBADF");
        }

        // 2. Non-socket fd beats invalid how:
        if sys(Syscall::SocketShutdown, a1(pipe, 99)) != Some(ENOTSOCK) {
            return Err("shutdown(pipe, 99) must return -ENOTSOCK");
        }

        // 3. Socket with invalid how returns -EINVAL:
        let sock = open(AF_INET, SOCK_STREAM, 0)?;
        if sys(Syscall::SocketShutdown, a1(sock, 99)) != Some(EINVAL) {
            return Err("shutdown(sock, 99) must return -EINVAL");
        }

        // 4. Unconnected TCP socket with valid how returns -ENOTCONN:
        if sys(Syscall::SocketShutdown, a1(sock, SHUT_RDWR)) != Some(ENOTCONN_ERR) {
            return Err("shutdown(unconnected, SHUT_RDWR) must return -ENOTCONN");
        }

        close(pipe);
        close(sock);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_shutdown_precedence
);

/// Descriptor and buffer validation precedence for setsockopt(2) and getsockopt(2).
/// Linux net/socket.c:
/// __sys_setsockopt:
///   1. EBADF (bad fd)
///   2. ENOTSOCK (non-socket file)
///   3. EINVAL (optlen < 0)
///   4. EFAULT (optval pointer copy fails)
///   5. ENOPROTOOPT (unknown option)
///
/// __sys_getsockopt:
///   1. EBADF (bad fd)
///   2. ENOTSOCK (non-socket file)
///   3. EFAULT (optlen pointer read fails)
///   4. EINVAL (*optlen < 0)
///   5. ENOPROTOOPT (unknown option)
fn smoke_abi_socket_errno_sockopt_precedence() -> TestResult {
    with_setup(|| {
        const BAD_FD: u64 = 4096;
        let mut pipefd = [0u8; 8];
        if sys(Syscall::Pipe2, a1(pipefd.as_mut_ptr() as u64, 0)) != Some(0) {
            return Err("pipe2 failed");
        }
        let pipe = i32::from_ne_bytes(pipefd[..4].try_into().unwrap()) as u64;
        let sock = open(AF_INET, SOCK_STREAM, 0)?;

        // --- setsockopt precedence ---
        // 1. EBADF beats negative optlen and bad pointer:
        if sys(
            Syscall::SocketSetSockOpt,
            a4(
                BAD_FD,
                SOL_SOCKET,
                SO_REUSEADDR,
                BAD_USER_PTR,
                (-1i32) as u64,
            ),
        ) != Some(EBADF)
        {
            return Err("setsockopt(BAD_FD) must return -EBADF");
        }

        // 2. ENOTSOCK beats negative optlen and bad pointer:
        if sys(
            Syscall::SocketSetSockOpt,
            a4(pipe, SOL_SOCKET, SO_REUSEADDR, BAD_USER_PTR, (-1i32) as u64),
        ) != Some(ENOTSOCK)
        {
            return Err("setsockopt(pipe) must return -ENOTSOCK");
        }

        // 3. Negative optlen beats bad optval pointer:
        if sys(
            Syscall::SocketSetSockOpt,
            a4(sock, SOL_SOCKET, SO_REUSEADDR, BAD_USER_PTR, (-1i32) as u64),
        ) != Some(EINVAL)
        {
            return Err("setsockopt(negative optlen) must return -EINVAL");
        }

        // 4. Bad optval pointer with valid optlen gives -EFAULT:
        if sys(
            Syscall::SocketSetSockOpt,
            a4(sock, SOL_SOCKET, SO_REUSEADDR, BAD_USER_PTR, 4),
        ) != Some(EFAULT)
        {
            return Err("setsockopt(BAD_USER_PTR, 4) must return -EFAULT");
        }

        // 5. Unknown option with valid value gives -ENOPROTOOPT:
        let one = 1i32.to_ne_bytes();
        if sys(
            Syscall::SocketSetSockOpt,
            a4(sock, SOL_SOCKET, 0x7FFF, one.as_ptr() as u64, 4),
        ) != Some(ENOPROTOOPT_ERR)
        {
            return Err("setsockopt(unknown option) must return -ENOPROTOOPT");
        }

        // --- getsockopt precedence ---
        // 1. EBADF beats bad len_ptr:
        if sys(
            Syscall::SocketGetSockOpt,
            a4(BAD_FD, SOL_SOCKET, SO_REUSEADDR, BAD_USER_PTR, BAD_USER_PTR),
        ) != Some(EBADF)
        {
            return Err("getsockopt(BAD_FD) must return -EBADF");
        }

        // 2. ENOTSOCK beats bad len_ptr:
        if sys(
            Syscall::SocketGetSockOpt,
            a4(pipe, SOL_SOCKET, SO_REUSEADDR, BAD_USER_PTR, BAD_USER_PTR),
        ) != Some(ENOTSOCK)
        {
            return Err("getsockopt(pipe) must return -ENOTSOCK");
        }

        // 3. Bad len_ptr on socket gives -EFAULT:
        if sys(
            Syscall::SocketGetSockOpt,
            a4(sock, SOL_SOCKET, SO_REUSEADDR, BAD_USER_PTR, BAD_USER_PTR),
        ) != Some(EFAULT)
        {
            return Err("getsockopt(BAD_USER_PTR len) must return -EFAULT");
        }

        // 4. Negative *len_ptr gives -EINVAL:
        let mut neg_len = (-1i32).to_ne_bytes();
        let mut out_val = [0u8; 4];
        if sys(
            Syscall::SocketGetSockOpt,
            a4(
                sock,
                SOL_SOCKET,
                SO_REUSEADDR,
                out_val.as_mut_ptr() as u64,
                neg_len.as_mut_ptr() as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("getsockopt(negative *len) must return -EINVAL");
        }

        // 5. Unknown option gives -ENOPROTOOPT:
        let mut four = 4i32.to_ne_bytes();
        if sys(
            Syscall::SocketGetSockOpt,
            a4(
                sock,
                SOL_SOCKET,
                0x7FFF,
                out_val.as_mut_ptr() as u64,
                four.as_mut_ptr() as u64,
            ),
        ) != Some(ENOPROTOOPT_ERR)
        {
            return Err("getsockopt(unknown option) must return -ENOPROTOOPT");
        }

        close(pipe);
        close(sock);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_sockopt_precedence
);

/// Descriptor and address-validation precedence for bind(2) and connect(2).
/// Linux net/socket.c:
/// __sys_bind:
///   1. EBADF (bad fd)
///   2. ENOTSOCK (non-socket file)
///   3. move_addr_to_kernel: ulen < 0 || ulen > 128 -> -EINVAL
///   4. move_addr_to_kernel: copy_from_user -> -EFAULT
///   5. ulen < 2 -> -EINVAL
///
/// __sys_connect:
///   1. EBADF (bad fd)
///   2. move_addr_to_kernel: ulen < 0 || ulen > 128 -> -EINVAL
///   3. move_addr_to_kernel: copy_from_user -> -EFAULT
///   4. ENOTSOCK (non-socket file checked in __sys_connect_file)
///   5. ulen < 2 -> -EINVAL
fn smoke_abi_socket_errno_bind_connect_precedence() -> TestResult {
    with_setup(|| {
        const BAD_FD: u64 = 4096;
        let mut pipefd = [0u8; 8];
        if sys(Syscall::Pipe2, a1(pipefd.as_mut_ptr() as u64, 0)) != Some(0) {
            return Err("pipe2 failed");
        }
        let pipe = i32::from_ne_bytes(pipefd[..4].try_into().unwrap()) as u64;
        let sock = open(AF_INET, SOCK_STREAM, 0)?;
        let valid_sin = sin(AF_INET, LOOPBACK, 31099);

        // --- bind precedence ---
        // 1. EBADF beats bad addrlen and bad pointer:
        if sys(Syscall::SocketBind, a2(BAD_FD, BAD_USER_PTR, 1000)) != Some(EBADF) {
            return Err("bind(BAD_FD) must return -EBADF");
        }

        // 2. In bind, ENOTSOCK precedes move_addr_to_kernel:
        if sys(Syscall::SocketBind, a2(pipe, BAD_USER_PTR, 1000)) != Some(ENOTSOCK) {
            return Err("bind(pipe) must return -ENOTSOCK before address checks");
        }

        // 3. Addrlen > 128 beats bad address pointer:
        if sys(Syscall::SocketBind, a2(sock, BAD_USER_PTR, 1000)) != Some(EINVAL) {
            return Err("bind(addrlen > 128) must return -EINVAL");
        }

        // 4. Negative addrlen beats bad address pointer:
        if sys(Syscall::SocketBind, a2(sock, BAD_USER_PTR, (-1i32) as u64)) != Some(EINVAL) {
            return Err("bind(addrlen < 0) must return -EINVAL");
        }

        // 5. Valid length with bad pointer gives -EFAULT:
        if sys(Syscall::SocketBind, a2(sock, BAD_USER_PTR, 16)) != Some(EFAULT) {
            return Err("bind(BAD_USER_PTR, 16) must return -EFAULT");
        }

        // 6. Addrlen < 2 gives -EINVAL:
        if sys(Syscall::SocketBind, a2(sock, valid_sin.as_ptr() as u64, 1)) != Some(EINVAL) {
            return Err("bind(addrlen < 2) must return -EINVAL");
        }

        // --- connect precedence ---
        // 1. EBADF beats bad addrlen and bad pointer:
        if sys(Syscall::SocketConnect, a2(BAD_FD, BAD_USER_PTR, 1000)) != Some(EBADF) {
            return Err("connect(BAD_FD) must return -EBADF");
        }

        // 2. In connect, move_addr_to_kernel precedes ENOTSOCK:
        // Addrlen > 128 returns -EINVAL even on a non-socket file:
        if sys(Syscall::SocketConnect, a2(pipe, BAD_USER_PTR, 1000)) != Some(EINVAL) {
            return Err("connect(pipe, len=1000) must return -EINVAL before ENOTSOCK");
        }

        // 3. Bad pointer returns -EFAULT even on a non-socket file:
        if sys(Syscall::SocketConnect, a2(pipe, BAD_USER_PTR, 16)) != Some(EFAULT) {
            return Err("connect(pipe, BAD_USER_PTR) must return -EFAULT before ENOTSOCK");
        }

        // 4. Only after valid address copy does a non-socket file return -ENOTSOCK:
        if sys(
            Syscall::SocketConnect,
            a2(pipe, valid_sin.as_ptr() as u64, 16),
        ) != Some(ENOTSOCK)
        {
            return Err("connect(pipe, valid_addr) must return -ENOTSOCK");
        }

        // 5. On a socket: addrlen > 128 gives -EINVAL:
        if sys(Syscall::SocketConnect, a2(sock, BAD_USER_PTR, 1000)) != Some(EINVAL) {
            return Err("connect(sock, len=1000) must return -EINVAL");
        }

        // 6. On a socket: addrlen < 0 gives -EINVAL:
        if sys(
            Syscall::SocketConnect,
            a2(sock, BAD_USER_PTR, (-1i32) as u64),
        ) != Some(EINVAL)
        {
            return Err("connect(sock, len < 0) must return -EINVAL");
        }

        // 7. On a socket: bad pointer gives -EFAULT:
        if sys(Syscall::SocketConnect, a2(sock, BAD_USER_PTR, 16)) != Some(EFAULT) {
            return Err("connect(sock, BAD_USER_PTR) must return -EFAULT");
        }

        // 8. On a socket: addrlen < 2 gives -EINVAL:
        if sys(
            Syscall::SocketConnect,
            a2(sock, valid_sin.as_ptr() as u64, 1),
        ) != Some(EINVAL)
        {
            return Err("connect(sock, len < 2) must return -EINVAL");
        }

        close(pipe);
        close(sock);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/socket_errno",
    smoke_abi_socket_errno_bind_connect_precedence
);
