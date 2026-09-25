//! Linux syscall ABI conformance — AF_INET `SOCK_DGRAM` (UDP).
//!
//! Every case drives the real syscall handlers (`socket`, `bind`, `connect`,
//! `sendto`, `recvfrom`, `recvmsg`, `getsockname`, `getpeername`,
//! `getsockopt`, `setsockopt`, `shutdown`, `poll`, `ioctl`, `close`) and
//! asserts the result Linux v6.12 produces. Each expected errno cites the
//! line of Linux source that returns it, so a failing case says exactly which
//! kernel behaviour NARF diverged from.
//!
//! Sockets are opened `SOCK_NONBLOCK`: the harness has no user task to park,
//! so a blocking receive on an empty queue cannot be exercised here.
use crate::abi_test_support::*;

const AF_UNSPEC: u16 = 0;
const AF_INET: u64 = 2;
const AF_INET6: u16 = 10;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_NONBLOCK: u64 = 0o4000;
const IPPROTO_UDP: u32 = 17;
const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_BROADCAST: u64 = 6;
const SO_RCVBUF: u64 = 8;
const SO_REUSEPORT: u64 = 15;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const MSG_OOB: u64 = 0x1;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_ERRQUEUE: u64 = 0x2000;
const SHUT_RD: u64 = 0;
const SHUT_WR: u64 = 1;
const SHUT_RDWR: u64 = 2;
const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLERR: u16 = 0x8;
const POLLHUP: u16 = 0x10;
const SIOCINQ: u64 = 0x541B;
const SIGPIPE: u64 = 13;

const LO: [u8; 4] = [127, 0, 0, 1];
const ANY: [u8; 4] = [0, 0, 0, 0];

/// A socket fd that is closed when the case returns, so a failing case does
/// not leave its port bound for the rest of the suite.
struct Fd(u64);

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = call(Syscall::Close.raw(), a0(self.0));
    }
}

fn udp() -> Result<Fd, &'static str> {
    match call(
        Syscall::SocketOpen.raw(),
        a2(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0),
    ) {
        Some(fd) if fd >= 0 => Ok(Fd(fd as u64)),
        _ => Err("socket(AF_INET, SOCK_DGRAM) failed"),
    }
}

/// A `struct sockaddr_in` with an arbitrary family field.
fn sa_fam(family: u16, ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&family.to_ne_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&ip);
    b
}

fn sa(ip: [u8; 4], port: u16) -> [u8; 16] {
    sa_fam(AF_INET as u16, ip, port)
}

fn bind_len(fd: &Fd, addr: &[u8; 16], len: u64) -> Result<i64, &'static str> {
    call(
        Syscall::SocketBind.raw(),
        a2(fd.0, addr.as_ptr() as u64, len),
    )
    .ok_or("bind status")
}

fn bind(fd: &Fd, ip: [u8; 4], port: u16) -> Result<i64, &'static str> {
    bind_len(fd, &sa(ip, port), 16)
}

fn connect_len(fd: &Fd, addr: &[u8; 16], len: u64) -> Result<i64, &'static str> {
    call(
        Syscall::SocketConnect.raw(),
        a2(fd.0, addr.as_ptr() as u64, len),
    )
    .ok_or("connect status")
}

fn connect(fd: &Fd, ip: [u8; 4], port: u16) -> Result<i64, &'static str> {
    connect_len(fd, &sa(ip, port), 16)
}

fn sendto_raw(
    fd: &Fd,
    buf: &[u8],
    flags: u64,
    addr: Option<&[u8; 16]>,
    len: u64,
) -> Result<i64, &'static str> {
    call(
        Syscall::SocketSend.raw(),
        SyscallArgs {
            arg0: fd.0,
            arg1: buf.as_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: flags,
            arg4: addr.map(|a| a.as_ptr() as u64).unwrap_or(0),
            arg5: if addr.is_some() { len } else { 0 },
        },
    )
    .ok_or("sendto status")
}

fn sendto(fd: &Fd, buf: &[u8], ip: [u8; 4], port: u16) -> Result<i64, &'static str> {
    sendto_raw(fd, buf, 0, Some(&sa(ip, port)), 16)
}

fn send(fd: &Fd, buf: &[u8]) -> Result<i64, &'static str> {
    sendto_raw(fd, buf, 0, None, 0)
}

/// `recvfrom` → (return value, source sockaddr, the addrlen the kernel wrote).
fn recvfrom(fd: &Fd, buf: &mut [u8], flags: u64) -> Result<(i64, [u8; 16], u32), &'static str> {
    let mut from = [0xAAu8; 16];
    let mut len: u32 = 16;
    let r = call(
        Syscall::SocketRecv.raw(),
        SyscallArgs {
            arg0: fd.0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: flags,
            arg4: from.as_mut_ptr() as u64,
            arg5: &mut len as *mut u32 as u64,
        },
    )
    .ok_or("recvfrom status")?;
    Ok((r, from, len))
}

fn recv(fd: &Fd, buf: &mut [u8]) -> Result<i64, &'static str> {
    recvfrom(fd, buf, 0).map(|(r, _, _)| r)
}

fn name(fd: &Fd, peer: bool) -> Result<(i64, [u8; 16], u32), &'static str> {
    let mut out = [0xAAu8; 16];
    let mut len: u32 = 16;
    let n = if peer {
        Syscall::SocketGetPeerName
    } else {
        Syscall::SocketGetSockName
    };
    let r = call(
        n.raw(),
        a2(fd.0, out.as_mut_ptr() as u64, &mut len as *mut u32 as u64),
    )
    .ok_or("getname status")?;
    Ok((r, out, len))
}

fn port_of(sa: &[u8; 16]) -> u16 {
    u16::from_be_bytes([sa[2], sa[3]])
}

fn ip_of(sa: &[u8; 16]) -> [u8; 4] {
    [sa[4], sa[5], sa[6], sa[7]]
}

fn local_port(fd: &Fd) -> Result<u16, &'static str> {
    let (r, a, _) = name(fd, false)?;
    if r != 0 {
        return Err("getsockname failed");
    }
    Ok(port_of(&a))
}

fn setsockopt_int(fd: &Fd, level: u64, opt: u64, v: u32) -> Result<i64, &'static str> {
    let val = v.to_ne_bytes();
    call(
        Syscall::SocketSetSockOpt.raw(),
        a4(fd.0, level, opt, val.as_ptr() as u64, 4),
    )
    .ok_or("setsockopt status")
}

fn getsockopt_int(fd: &Fd, level: u64, opt: u64) -> Result<u32, &'static str> {
    let mut val = [0u8; 4];
    let mut len: u32 = 4;
    let r = call(
        Syscall::SocketGetSockOpt.raw(),
        SyscallArgs {
            arg0: fd.0,
            arg1: level,
            arg2: opt,
            arg3: val.as_mut_ptr() as u64,
            arg4: &mut len as *mut u32 as u64,
            ..SyscallArgs::default()
        },
    )
    .ok_or("getsockopt status")?;
    if r != 0 {
        return Err("getsockopt failed");
    }
    Ok(u32::from_ne_bytes(val))
}

fn revents(fd: &Fd, events: u16) -> Result<u16, &'static str> {
    let mut pfd = [0u8; 8];
    pfd[0..4].copy_from_slice(&(fd.0 as i32).to_ne_bytes());
    pfd[4..6].copy_from_slice(&events.to_ne_bytes());
    call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)).ok_or("poll status")?;
    Ok(u16::from_ne_bytes([pfd[6], pfd[7]]))
}

fn inq(fd: &Fd) -> Result<i32, &'static str> {
    let mut v: i32 = -1;
    let r = call(
        Syscall::Ioctl.raw(),
        a2(fd.0, SIOCINQ, &mut v as *mut i32 as u64),
    )
    .ok_or("ioctl status")?;
    if r != 0 {
        return Err("ioctl(SIOCINQ) failed");
    }
    Ok(v)
}

/// A bound receiver on 127.0.0.1:`port`.
fn receiver(port: u16) -> Result<Fd, &'static str> {
    let fd = udp()?;
    if bind(&fd, LO, port)? != 0 {
        return Err("bind of the receiver failed");
    }
    Ok(fd)
}

// ───────────────────────────── socket(2) ─────────────────────────────

/// `inet_create` resolves protocol 0 to the type's default, IPPROTO_UDP
/// (`net/ipv4/af_inet.c:281-283`).
fn smoke_abi_udp_socket_reports_type_domain_protocol() -> TestResult {
    with_setup(|| {
        let s = udp()?;
        if getsockopt_int(&s, SOL_SOCKET, SO_TYPE)? != SOCK_DGRAM as u32 {
            return Err("SO_TYPE is not SOCK_DGRAM");
        }
        if getsockopt_int(&s, SOL_SOCKET, SO_DOMAIN)? != AF_INET as u32 {
            return Err("SO_DOMAIN is not AF_INET");
        }
        if getsockopt_int(&s, SOL_SOCKET, SO_PROTOCOL)? != IPPROTO_UDP {
            return Err("SO_PROTOCOL of socket(AF_INET, SOCK_DGRAM, 0) is not IPPROTO_UDP");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_socket_reports_type_domain_protocol
);

// ─────────────────────────── getsockname(2) ──────────────────────────

/// An unbound socket reports 0.0.0.0:0 with `addrlen == 16`
/// (`inet_getname`, `net/ipv4/af_inet.c:819-829`).
fn smoke_abi_udp_getsockname_unbound_is_any_zero() -> TestResult {
    with_setup(|| {
        let s = udp()?;
        let (r, a, len) = name(&s, false)?;
        if r != 0 {
            return Err("getsockname on an unbound UDP socket failed");
        }
        if len != 16 {
            return Err("getsockname addrlen is not sizeof(struct sockaddr_in)");
        }
        if a != sa(ANY, 0) {
            return Err("unbound UDP socket is not 0.0.0.0:0");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_getsockname_unbound_is_any_zero
);

/// getpeername on an unconnected socket is ENOTCONN
/// (`net/ipv4/af_inet.c:808-812`).
fn smoke_abi_udp_getpeername_unconnected_enotconn() -> TestResult {
    with_setup(|| {
        let s = receiver(41001)?;
        if name(&s, true)?.0 != ENOTCONN {
            return Err("getpeername on an unconnected socket is not ENOTCONN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_getpeername_unconnected_enotconn
);

// ───────────────────────────── bind(2) ───────────────────────────────

/// `addr_len < sizeof(struct sockaddr_in)` → EINVAL
/// (`inet_bind_sk`, `net/ipv4/af_inet.c:453`).
fn smoke_abi_udp_bind_short_addrlen_einval() -> TestResult {
    with_setup(|| {
        let s = udp()?;
        if bind_len(&s, &sa(LO, 41010), 8)? != EINVAL {
            return Err("bind with addrlen 8 is not EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_bind_short_addrlen_einval);

/// A non-AF_INET family is EAFNOSUPPORT; AF_UNSPEC is accepted only with
/// INADDR_ANY (`net/ipv4/af_inet.c:483-489`).
fn smoke_abi_udp_bind_family_rules() -> TestResult {
    with_setup(|| {
        let s = udp()?;
        if bind_len(&s, &sa_fam(AF_INET6, LO, 41011), 16)? != EAFNOSUPPORT {
            return Err("bind with sa_family AF_INET6 is not EAFNOSUPPORT");
        }
        if bind_len(&s, &sa_fam(AF_UNSPEC, LO, 41011), 16)? != EAFNOSUPPORT {
            return Err("bind AF_UNSPEC with a non-ANY address is not EAFNOSUPPORT");
        }
        if bind_len(&s, &sa_fam(AF_UNSPEC, ANY, 41011), 16)? != 0 {
            return Err("bind AF_UNSPEC + INADDR_ANY must be accepted as AF_INET");
        }
        if local_port(&s)? != 41011 {
            return Err("AF_UNSPEC bind did not take the port");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_bind_family_rules);

/// A second bind on a bound socket is EINVAL (`net/ipv4/af_inet.c:522`).
fn smoke_abi_udp_bind_twice_einval() -> TestResult {
    with_setup(|| {
        let s = receiver(41012)?;
        if bind(&s, LO, 41013)? != EINVAL {
            return Err("a second bind is not EINVAL");
        }
        if local_port(&s)? != 41012 {
            return Err("the failed second bind changed the binding");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_bind_twice_einval);

/// Binding an address that is not local is EADDRNOTAVAIL
/// (`inet_addr_valid_or_nonlocal`, `net/ipv4/af_inet.c:499-501`).
/// 192.0.2.1 is TEST-NET-1 (RFC 5737), never assigned to the test image.
fn smoke_abi_udp_bind_nonlocal_eaddrnotavail() -> TestResult {
    with_setup(|| {
        let s = udp()?;
        if bind(&s, [192, 0, 2, 1], 41014)? != EADDRNOTAVAIL {
            return Err("bind to a non-local address is not EADDRNOTAVAIL");
        }
        // Every address in 127.0.0.0/8 is local.
        if bind(&s, [127, 0, 0, 7], 41014)? != 0 {
            return Err("bind to 127.0.0.7 must succeed");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_bind_nonlocal_eaddrnotavail);

/// Port 0 picks a free ephemeral port (`udp_lib_get_port`,
/// `net/ipv4/udp.c:248-290`); two such binds never share one.
fn smoke_abi_udp_bind_port_zero_allocates() -> TestResult {
    with_setup(|| {
        let a = udp()?;
        let b = udp()?;
        if bind(&a, LO, 0)? != 0 || bind(&b, LO, 0)? != 0 {
            return Err("bind to port 0 failed");
        }
        let (pa, pb) = (local_port(&a)?, local_port(&b)?);
        if pa == 0 || pb == 0 {
            return Err("bind to port 0 left the socket on port 0");
        }
        if pa == pb {
            return Err("two port-0 binds got the same port");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_bind_port_zero_allocates);

/// Overlapping bindings are EADDRINUSE, and INADDR_ANY overlaps a specific
/// address in both directions (`udp_lib_lport_inuse` +
/// `inet_rcv_saddr_equal(match_wildcard)`, `net/ipv4/udp.c:150-157`;
/// `error = -EADDRINUSE`, `net/ipv4/udp.c:246`). Distinct specific addresses
/// on one port do not overlap.
fn smoke_abi_udp_bind_conflicts_eaddrinuse() -> TestResult {
    with_setup(|| {
        let a = receiver(41020)?;
        let b = udp()?;
        if bind(&b, LO, 41020)? != EADDRINUSE {
            return Err("same addr:port bind is not EADDRINUSE");
        }
        if bind(&b, ANY, 41020)? != EADDRINUSE {
            return Err("INADDR_ANY over a specific binding is not EADDRINUSE");
        }
        if bind(&b, [127, 0, 0, 2], 41020)? != 0 {
            return Err("a different specific address on the same port must bind");
        }
        drop(a);
        let c = udp()?;
        if bind(&c, ANY, 41021)? != 0 {
            return Err("wildcard bind failed");
        }
        let d = udp()?;
        if bind(&d, LO, 41021)? != EADDRINUSE {
            return Err("a specific address under a wildcard binding is not EADDRINUSE");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_bind_conflicts_eaddrinuse);

/// SO_REUSEADDR shares a port only when BOTH sockets set it
/// (`(!sk2->sk_reuse || !sk->sk_reuse)`, `net/ipv4/udp.c:153`).
fn smoke_abi_udp_bind_reuseaddr_needs_both() -> TestResult {
    with_setup(|| {
        let a = udp()?;
        setsockopt_int(&a, SOL_SOCKET, SO_REUSEADDR, 1)?;
        if bind(&a, LO, 41022)? != 0 {
            return Err("first bind failed");
        }
        let b = udp()?;
        if bind(&b, LO, 41022)? != EADDRINUSE {
            return Err("sharing without SO_REUSEADDR on the newcomer is not EADDRINUSE");
        }
        setsockopt_int(&b, SOL_SOCKET, SO_REUSEADDR, 1)?;
        if bind(&b, LO, 41022)? != 0 {
            return Err("both SO_REUSEADDR must share the port");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_bind_reuseaddr_needs_both);

/// SO_REUSEPORT on both sockets (same uid) shares a port
/// (`net/ipv4/udp.c:158-163`).
fn smoke_abi_udp_bind_reuseport_both_share() -> TestResult {
    with_setup(|| {
        let a = udp()?;
        let b = udp()?;
        setsockopt_int(&a, SOL_SOCKET, SO_REUSEPORT, 1)?;
        if bind(&a, LO, 41023)? != 0 {
            return Err("first bind failed");
        }
        if bind(&b, LO, 41023)? != EADDRINUSE {
            return Err("SO_REUSEPORT on only one socket must not share");
        }
        setsockopt_int(&b, SOL_SOCKET, SO_REUSEPORT, 1)?;
        if bind(&b, LO, 41023)? != 0 {
            return Err("both SO_REUSEPORT must share the port");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_bind_reuseport_both_share);

/// close() releases the binding.
fn smoke_abi_udp_close_releases_port() -> TestResult {
    with_setup(|| {
        drop(receiver(41024)?);
        let again = udp()?;
        if bind(&again, LO, 41024)? != 0 {
            return Err("port still in use after close");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_close_releases_port);

// ───────────────────────── sendto / recvfrom ─────────────────────────

/// sendto on an unbound socket autobinds it (`inet_send_prepare`,
/// `net/ipv4/af_inet.c:838`); the receiver sees that port and the route's
/// source, 127.0.0.1 (`net/ipv4/route.c:2768-2771`), in a full 16-byte
/// sockaddr_in with zeroed `sin_zero` (`net/ipv4/udp.c:1886-1891`).
fn smoke_abi_udp_sendto_autobinds_and_recvfrom_reports_source() -> TestResult {
    with_setup(|| {
        let rx = receiver(41030)?;
        let tx = udp()?;
        if sendto(&tx, b"hello", LO, 41030)? != 5 {
            return Err("sendto from an unbound socket did not send 5 bytes");
        }
        let port = local_port(&tx)?;
        if port == 0 {
            return Err("sendto did not autobind the sender");
        }
        let mut buf = [0u8; 16];
        let (n, from, len) = recvfrom(&rx, &mut buf, 0)?;
        if n != 5 || &buf[..5] != b"hello" {
            return Err("receiver did not get the payload");
        }
        if len != 16 {
            return Err("recvfrom addrlen is not sizeof(struct sockaddr_in)");
        }
        if from != sa(LO, port) {
            return Err("recvfrom source is not 127.0.0.1:<sender port> with zero padding");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_sendto_autobinds_and_recvfrom_reports_source
);

/// A wildcard-bound sender's datagram to any 127/8 address carries source
/// 127.0.0.1 (`prefsrc` of the loopback route, `net/ipv4/route.c:2770`) and
/// reaches a wildcard-bound receiver.
fn smoke_abi_udp_wildcard_sender_source_is_loopback() -> TestResult {
    with_setup(|| {
        let rx = udp()?;
        if bind(&rx, ANY, 41031)? != 0 {
            return Err("wildcard bind failed");
        }
        let tx = udp()?;
        if bind(&tx, ANY, 41032)? != 0 {
            return Err("sender bind failed");
        }
        if sendto(&tx, b"x", [127, 0, 0, 9], 41031)? != 1 {
            return Err("sendto 127.0.0.9 failed");
        }
        let mut buf = [0u8; 4];
        let (n, from, _) = recvfrom(&rx, &mut buf, 0)?;
        if n != 1 {
            return Err("wildcard receiver did not get the datagram");
        }
        if ip_of(&from) != LO || port_of(&from) != 41032 {
            return Err("source is not 127.0.0.1:41032");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_wildcard_sender_source_is_loopback
);

/// No destination on an unconnected socket → EDESTADDRREQ
/// (`net/ipv4/udp.c:1127-1128`).
fn smoke_abi_udp_send_unconnected_edestaddrreq() -> TestResult {
    with_setup(|| {
        let s = receiver(41033)?;
        if send(&s, b"x")? != EDESTADDRREQ {
            return Err("send with no destination is not EDESTADDRREQ");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_send_unconnected_edestaddrreq
);

/// Destination checks, in `udp_sendmsg`'s order: short namelen → EINVAL,
/// foreign family → EAFNOSUPPORT, port 0 → EINVAL
/// (`net/ipv4/udp.c:1115-1125`). AF_UNSPEC is treated as AF_INET.
fn smoke_abi_udp_sendto_address_validation() -> TestResult {
    with_setup(|| {
        let rx = receiver(41034)?;
        let tx = udp()?;
        if sendto_raw(&tx, b"x", 0, Some(&sa(LO, 41034)), 8)? != EINVAL {
            return Err("sendto with namelen 8 is not EINVAL");
        }
        if sendto_raw(&tx, b"x", 0, Some(&sa_fam(AF_INET6, LO, 41034)), 16)? != EAFNOSUPPORT {
            return Err("sendto to an AF_INET6-family address is not EAFNOSUPPORT");
        }
        if sendto(&tx, b"x", LO, 0)? != EINVAL {
            return Err("sendto to port 0 is not EINVAL");
        }
        if sendto_raw(&tx, b"u", 0, Some(&sa_fam(AF_UNSPEC, LO, 41034)), 16)? != 1 {
            return Err("sendto with AF_UNSPEC must be accepted as AF_INET");
        }
        let mut buf = [0u8; 4];
        if recv(&rx, &mut buf)? != 1 || buf[0] != b'u' {
            return Err("the AF_UNSPEC datagram was not delivered");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_sendto_address_validation);

/// The size limits: `len > 0xFFFF` (`net/ipv4/udp.c:1081`) and more than
/// 65535 - 20 - 8 = 65507 payload bytes (`__ip_append_data`,
/// `net/ipv4/ip_output.c:992-995`) are EMSGSIZE; exactly 65507 arrives whole.
fn smoke_abi_udp_sendto_size_limits() -> TestResult {
    with_setup(|| {
        let rx = receiver(41035)?;
        setsockopt_int(&rx, SOL_SOCKET, SO_RCVBUF, 1 << 20)?;
        let tx = udp()?;
        let big = alloc::vec![0x5Au8; 65536];
        if sendto(&tx, &big[..65536], LO, 41035)? != EMSGSIZE {
            return Err("a 65536-byte datagram is not EMSGSIZE");
        }
        if sendto(&tx, &big[..65508], LO, 41035)? != EMSGSIZE {
            return Err("a 65508-byte datagram is not EMSGSIZE");
        }
        if sendto(&tx, &big[..65507], LO, 41035)? != 65507 {
            return Err("a 65507-byte datagram must send");
        }
        let mut out = alloc::vec![0u8; 70000];
        if recv(&rx, &mut out)? != 65507 || out[..65507] != big[..65507] {
            return Err("the maximum-size datagram did not arrive intact");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_sendto_size_limits);

/// MSG_OOB → EOPNOTSUPP (`net/ipv4/udp.c:1088-1089`).
fn smoke_abi_udp_sendto_msg_oob_eopnotsupp() -> TestResult {
    with_setup(|| {
        let _rx = receiver(41036)?;
        let tx = udp()?;
        if sendto_raw(&tx, b"x", MSG_OOB, Some(&sa(LO, 41036)), 16)? != EOPNOTSUPP {
            return Err("MSG_OOB is not EOPNOTSUPP");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_sendto_msg_oob_eopnotsupp);

/// Broadcast without SO_BROADCAST is EACCES for sendto
/// (`net/ipv4/udp.c:1247-1250`) and connect (`net/ipv4/datagram.c:59-62`).
fn smoke_abi_udp_broadcast_needs_so_broadcast() -> TestResult {
    with_setup(|| {
        let s = receiver(41037)?;
        if sendto(&s, b"b", [255, 255, 255, 255], 41038)? != EACCES {
            return Err("broadcast sendto without SO_BROADCAST is not EACCES");
        }
        if connect(&s, [255, 255, 255, 255], 41038)? != EACCES {
            return Err("broadcast connect without SO_BROADCAST is not EACCES");
        }
        if name(&s, true)?.0 != ENOTCONN {
            return Err("the refused connect left the socket connected");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_broadcast_needs_so_broadcast
);

/// With SO_BROADCAST a broadcast is also looped back to this host
/// (`ip_mc_output` clones it, `net/ipv4/ip_output.c:413-419`), where EVERY
/// socket on the port whose bound address is INADDR_ANY or the broadcast
/// address gets a copy; one bound to 127.0.0.1 does not
/// (`__udp_is_mcast_sock`, `net/ipv4/udp.c:590`).
fn smoke_abi_udp_broadcast_loops_back_to_every_listener() -> TestResult {
    with_setup(|| {
        let a = udp()?;
        let b = udp()?;
        let lo = udp()?;
        for s in [&a, &b, &lo] {
            setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, 1)?;
        }
        if bind(&a, ANY, 41110)? != 0 || bind(&b, ANY, 41110)? != 0 || bind(&lo, LO, 41110)? != 0 {
            return Err("SO_REUSEADDR binds failed");
        }
        let tx = udp()?;
        setsockopt_int(&tx, SOL_SOCKET, SO_BROADCAST, 1)?;
        if sendto(&tx, b"all", [255, 255, 255, 255], 41110)? != 3 {
            return Err("broadcast sendto with SO_BROADCAST failed");
        }
        let mut buf = [0u8; 4];
        if recv(&a, &mut buf)? != 3 || recv(&b, &mut buf)? != 3 {
            return Err("a wildcard listener did not get its broadcast copy");
        }
        if recv(&lo, &mut buf)? != EAGAIN {
            return Err("a socket bound to 127.0.0.1 got a 255.255.255.255 broadcast");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_broadcast_loops_back_to_every_listener
);

/// A zero-length datagram is a datagram: recv returns 0 and still reports
/// the source.
fn smoke_abi_udp_zero_length_datagram() -> TestResult {
    with_setup(|| {
        let rx = receiver(41039)?;
        let tx = receiver(41040)?;
        if sendto(&tx, b"", LO, 41039)? != 0 {
            return Err("zero-length sendto did not return 0");
        }
        if revents(&rx, POLLIN)? & POLLIN == 0 {
            return Err("a queued zero-length datagram does not make the socket readable");
        }
        let mut buf = [0u8; 4];
        let (n, from, _) = recvfrom(&rx, &mut buf, 0)?;
        if n != 0 || port_of(&from) != 41040 {
            return Err("zero-length datagram not received with its source");
        }
        if recv(&rx, &mut buf)? != EAGAIN {
            return Err("zero-length datagram was not consumed");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_zero_length_datagram);

/// Each recv returns exactly one datagram, in send order.
fn smoke_abi_udp_preserves_message_boundaries() -> TestResult {
    with_setup(|| {
        let rx = receiver(41041)?;
        let tx = udp()?;
        for m in [b"one".as_slice(), b"three".as_slice(), b"xy".as_slice()] {
            if sendto(&tx, m, LO, 41041)? != m.len() as i64 {
                return Err("sendto failed");
            }
        }
        let mut buf = [0u8; 64];
        for m in [b"one".as_slice(), b"three".as_slice(), b"xy".as_slice()] {
            let n = recv(&rx, &mut buf)?;
            if n != m.len() as i64 || &buf[..m.len()] != m {
                return Err("datagrams merged, split or reordered");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_preserves_message_boundaries
);

/// A short buffer truncates and DISCARDS the rest of the datagram; with
/// MSG_TRUNC the call returns the real length (`net/ipv4/udp.c:1838-1841`,
/// `:1905-1906`).
fn smoke_abi_udp_truncation_and_msg_trunc() -> TestResult {
    with_setup(|| {
        let rx = receiver(41042)?;
        let tx = udp()?;
        sendto(&tx, b"abcdefgh", LO, 41042)?;
        sendto(&tx, b"12345678", LO, 41042)?;
        sendto(&tx, b"next", LO, 41042)?;
        let mut small = [0u8; 3];
        if recv(&rx, &mut small)? != 3 || &small != b"abc" {
            return Err("truncating recv did not return the first 3 bytes");
        }
        if recvfrom(&rx, &mut small, MSG_TRUNC)?.0 != 8 || &small != b"123" {
            return Err("recv with MSG_TRUNC did not return the full datagram length");
        }
        let mut buf = [0u8; 16];
        if recv(&rx, &mut buf)? != 4 || &buf[..4] != b"next" {
            return Err("the truncated remainder was not discarded");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_truncation_and_msg_trunc);

/// MSG_PEEK leaves the datagram queued (`peeking`, `net/ipv4/udp.c:1823`,
/// `:1908`); `recv(NULL, 0, MSG_PEEK|MSG_TRUNC)` is the size probe.
fn smoke_abi_udp_msg_peek_does_not_consume() -> TestResult {
    with_setup(|| {
        let rx = receiver(41043)?;
        let tx = receiver(41044)?;
        sendto(&tx, b"peekaboo", LO, 41043)?;
        let probe = call(
            Syscall::SocketRecv.raw(),
            a3(rx.0, 0, 0, MSG_PEEK | MSG_TRUNC),
        )
        .ok_or("probe status")?;
        if probe != 8 {
            return Err("MSG_PEEK|MSG_TRUNC size probe did not return 8");
        }
        let mut buf = [0u8; 16];
        let (n, from, _) = recvfrom(&rx, &mut buf, MSG_PEEK)?;
        if n != 8 || &buf[..8] != b"peekaboo" || port_of(&from) != 41044 {
            return Err("MSG_PEEK did not return the datagram and its source");
        }
        buf = [0u8; 16];
        if recv(&rx, &mut buf)? != 8 || &buf[..8] != b"peekaboo" {
            return Err("MSG_PEEK consumed the datagram");
        }
        if recv(&rx, &mut buf)? != EAGAIN {
            return Err("the datagram was delivered twice after the real recv");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_msg_peek_does_not_consume);

/// An empty queue is EAGAIN for a non-blocking socket and for MSG_DONTWAIT,
/// and an UNBOUND socket is no different — UDP is not connection-based, so
/// there is no ENOTCONN (`net/core/datagram.c:110-113`; EAGAIN from
/// `__skb_recv_udp`, `net/ipv4/udp.c:1733`).
fn smoke_abi_udp_recv_empty_eagain_even_unbound() -> TestResult {
    with_setup(|| {
        let unbound = udp()?;
        let mut buf = [0u8; 4];
        if recv(&unbound, &mut buf)? != EAGAIN {
            return Err("recv on an unbound UDP socket is not EAGAIN");
        }
        let blocking = match call(Syscall::SocketOpen.raw(), a2(AF_INET, SOCK_DGRAM, 0)) {
            Some(fd) if fd >= 0 => Fd(fd as u64),
            _ => return Err("socket() failed"),
        };
        if bind(&blocking, LO, 41045)? != 0 {
            return Err("bind failed");
        }
        if recvfrom(&blocking, &mut buf, MSG_DONTWAIT)?.0 != EAGAIN {
            return Err("MSG_DONTWAIT on an empty blocking socket is not EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_recv_empty_eagain_even_unbound
);

/// NARF keeps no ICMP error queue, so MSG_ERRQUEUE finds it empty: EAGAIN
/// (`ip_recv_error`, `net/ipv4/ip_sockglue.c:535-538`) — immediately, even on
/// a blocking socket.
fn smoke_abi_udp_msg_errqueue_empty_eagain() -> TestResult {
    with_setup(|| {
        let blocking = match call(Syscall::SocketOpen.raw(), a2(AF_INET, SOCK_DGRAM, 0)) {
            Some(fd) if fd >= 0 => Fd(fd as u64),
            _ => return Err("socket() failed"),
        };
        if bind(&blocking, LO, 41046)? != 0 {
            return Err("bind failed");
        }
        let mut buf = [0u8; 4];
        if recvfrom(&blocking, &mut buf, MSG_ERRQUEUE)?.0 != EAGAIN {
            return Err("MSG_ERRQUEUE on an empty error queue is not EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_msg_errqueue_empty_eagain);

/// recvmsg: `msg_namelen` = 16 and MSG_TRUNC in `msg_flags` on truncation
/// (`net/ipv4/udp.c:1841`, `:1891`).
fn smoke_abi_udp_recvmsg_namelen_and_trunc_flag() -> TestResult {
    with_setup(|| {
        let rx = receiver(41047)?;
        let tx = receiver(41048)?;
        sendto(&tx, b"0123456789", LO, 41047)?;
        let mut data = [0u8; 4];
        let mut from = [0u8; 16];
        let iov: [u64; 2] = [data.as_mut_ptr() as u64, data.len() as u64];
        // struct msghdr: name, namelen(+pad), iov, iovlen, control,
        // controllen, flags.
        let mut msg = [0u8; 56];
        msg[0..8].copy_from_slice(&(from.as_mut_ptr() as u64).to_ne_bytes());
        msg[8..12].copy_from_slice(&16u32.to_ne_bytes());
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        let r = call(
            Syscall::SocketRecvMsg.raw(),
            a2(rx.0, msg.as_mut_ptr() as u64, 0),
        )
        .ok_or("recvmsg status")?;
        if r != 4 || &data != b"0123" {
            return Err("recvmsg did not return the first 4 bytes");
        }
        let namelen = u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);
        if namelen != 16 || port_of(&from) != 41048 || ip_of(&from) != LO {
            return Err("recvmsg did not report a 16-byte source address");
        }
        let flags = u32::from_ne_bytes([msg[48], msg[49], msg[50], msg[51]]);
        if flags & MSG_TRUNC as u32 == 0 {
            return Err("recvmsg did not set MSG_TRUNC in msg_flags");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_recvmsg_namelen_and_trunc_flag
);

/// SIOCINQ is the size of the NEXT datagram, not the queue total
/// (`first_packet_length`, `net/ipv4/udp.c:1701-1704`).
fn smoke_abi_udp_siocinq_is_next_datagram_size() -> TestResult {
    with_setup(|| {
        let rx = receiver(41049)?;
        let tx = udp()?;
        if inq(&rx)? != 0 {
            return Err("SIOCINQ on an empty queue is not 0");
        }
        sendto(&tx, b"seven77", LO, 41049)?;
        sendto(&tx, b"two", LO, 41049)?;
        if inq(&rx)? != 7 {
            return Err("SIOCINQ is not the first datagram's length");
        }
        let mut buf = [0u8; 16];
        recv(&rx, &mut buf)?;
        if inq(&rx)? != 3 {
            return Err("SIOCINQ did not advance to the next datagram");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_siocinq_is_next_datagram_size
);

/// A full receive buffer drops ARRIVING datagrams and keeps the queued ones
/// (`if (rmem > rcvbuf) goto drop;`, `net/ipv4/udp.c:1527-1528`), and the
/// queue is bounded.
fn smoke_abi_udp_rcvbuf_full_drops_newest() -> TestResult {
    with_setup(|| {
        let rx = receiver(41050)?;
        setsockopt_int(&rx, SOL_SOCKET, SO_RCVBUF, 4096)?;
        let tx = udp()?;
        let mut payload = [0u8; 1000];
        for i in 0..64u16 {
            payload[..2].copy_from_slice(&i.to_be_bytes());
            if sendto(&tx, &payload, LO, 41050)? != 1000 {
                return Err("sendto must report success even when the receiver drops");
            }
        }
        let mut buf = [0u8; 1000];
        let mut got = 0u16;
        while recv(&rx, &mut buf)? == 1000 {
            if u16::from_be_bytes([buf[0], buf[1]]) != got {
                return Err("received datagrams are not the OLDEST ones, in order");
            }
            got += 1;
        }
        if got == 0 {
            return Err("nothing was queued");
        }
        if got == 64 {
            return Err("SO_RCVBUF did not bound the queue");
        }
        // The buffer drained, so new datagrams are accepted again.
        sendto(&tx, b"again", LO, 41050)?;
        if recv(&rx, &mut buf)? != 5 {
            return Err("a drained socket did not accept a new datagram");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_rcvbuf_full_drops_newest);

// ───────────────────────────── connect(2) ────────────────────────────

/// connect autobinds (`net/ipv4/af_inet.c:592`), fixes the local address to
/// the route source (`net/ipv4/datagram.c:64-70`), reports the peer, and
/// lets send() omit the address.
fn smoke_abi_udp_connect_autobinds_and_sets_peer() -> TestResult {
    with_setup(|| {
        let rx = receiver(41060)?;
        let tx = udp()?;
        if connect(&tx, LO, 41060)? != 0 {
            return Err("connect failed");
        }
        let (r, local, _) = name(&tx, false)?;
        if r != 0 || port_of(&local) == 0 || ip_of(&local) != LO {
            return Err("connect did not autobind to 127.0.0.1:<ephemeral>");
        }
        let (r, peer, len) = name(&tx, true)?;
        if r != 0 || len != 16 || peer != sa(LO, 41060) {
            return Err("getpeername does not report the connected peer");
        }
        if send(&tx, b"hi")? != 2 {
            return Err("send on a connected socket failed");
        }
        let mut buf = [0u8; 4];
        let (n, from, _) = recvfrom(&rx, &mut buf, 0)?;
        if n != 2 || port_of(&from) != port_of(&local) {
            return Err("connected send did not reach the peer from the bound port");
        }
        // A connected socket may still sendto another destination.
        let other = receiver(41061)?;
        if sendto(&tx, b"o", LO, 41061)? != 1 || recv(&other, &mut buf)? != 1 {
            return Err("sendto an explicit address from a connected socket failed");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_connect_autobinds_and_sets_peer
);

/// connect's address checks: short → EINVAL, wrong family → EAFNOSUPPORT
/// (`net/ipv4/datagram.c:30-34`).
fn smoke_abi_udp_connect_address_validation() -> TestResult {
    with_setup(|| {
        let s = udp()?;
        if connect_len(&s, &sa(LO, 41062), 8)? != EINVAL {
            return Err("connect with addrlen 8 is not EINVAL");
        }
        if connect_len(&s, &sa_fam(AF_INET6, LO, 41062), 16)? != EAFNOSUPPORT {
            return Err("connect to an AF_INET6-family address is not EAFNOSUPPORT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_connect_address_validation);

/// A connected socket only receives from its peer — others are not queued —
/// and datagrams queued BEFORE connect stay readable (connect does not purge
/// the queue; the filter is `compute_score`, `net/ipv4/udp.c:389-399`).
fn smoke_abi_udp_connect_filters_other_senders() -> TestResult {
    with_setup(|| {
        let rx = receiver(41063)?;
        let peer = receiver(41064)?;
        let stranger = receiver(41065)?;
        sendto(&stranger, b"early", LO, 41063)?;
        if connect(&rx, LO, 41064)? != 0 {
            return Err("connect failed");
        }
        sendto(&stranger, b"late", LO, 41063)?;
        sendto(&peer, b"peer", LO, 41063)?;
        let mut buf = [0u8; 8];
        if recv(&rx, &mut buf)? != 5 || &buf[..5] != b"early" {
            return Err("a datagram queued before connect was lost");
        }
        let (n, from, _) = recvfrom(&rx, &mut buf, 0)?;
        if n != 4 || &buf[..4] != b"peer" || port_of(&from) != 41064 {
            return Err("the peer's datagram was not next — a stranger's got through");
        }
        if recv(&rx, &mut buf)? != EAGAIN {
            return Err("a stranger's datagram was queued on a connected socket");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_connect_filters_other_senders
);

/// connect(AF_UNSPEC) dissolves the association (`net/ipv4/af_inet.c:583`):
/// no peer, EDESTADDRREQ on send, other senders accepted again. An autobound
/// port is released and the route-chosen address forgotten
/// (`__udp_disconnect`, `net/ipv4/udp.c:1950-1960`); an explicit bind keeps
/// its port.
fn smoke_abi_udp_connect_af_unspec_disconnects() -> TestResult {
    with_setup(|| {
        let unspec = sa_fam(AF_UNSPEC, ANY, 0);
        // Explicitly bound to 0.0.0.0:41066: the port survives, the address
        // reverts to INADDR_ANY.
        let s = udp()?;
        if bind(&s, ANY, 41066)? != 0 || connect(&s, LO, 41067)? != 0 {
            return Err("bind/connect failed");
        }
        if name(&s, false)?.1 != sa(LO, 41066) {
            return Err("connect did not set the local address");
        }
        if connect_len(&s, &unspec, 16)? != 0 {
            return Err("connect(AF_UNSPEC) failed");
        }
        if name(&s, true)?.0 != ENOTCONN {
            return Err("still connected after AF_UNSPEC");
        }
        if name(&s, false)?.1 != sa(ANY, 41066) {
            return Err("disconnect did not keep the bound port / reset the address");
        }
        if send(&s, b"x")? != EDESTADDRREQ {
            return Err("send after disconnect is not EDESTADDRREQ");
        }
        let other = receiver(41068)?;
        sendto(&other, b"any", LO, 41066)?;
        let mut buf = [0u8; 4];
        if recv(&s, &mut buf)? != 3 {
            return Err("a disconnected socket still filters senders");
        }
        // Autobound by connect: disconnect releases the port.
        let t = udp()?;
        if connect(&t, LO, 41067)? != 0 {
            return Err("connect failed");
        }
        if connect_len(&t, &unspec, 16)? != 0 {
            return Err("connect(AF_UNSPEC) failed");
        }
        if name(&t, false)?.1 != sa(ANY, 0) {
            return Err("disconnect did not release the autobound port");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_connect_af_unspec_disconnects
);

/// A connected socket whose datagram hits a port nobody owns gets
/// ECONNREFUSED — port-unreachable is `icmp_err_convert[3]`
/// (`net/ipv4/icmp.c:134`), stored in `sk_err` for connected sockets
/// (`net/ipv4/udp.c:802-808`) — reported once by the next recv
/// (`net/ipv4/udp.c:1729`), and flagged by poll as POLLERR
/// (`net/core/datagram.c:893-896`). An unconnected sender gets nothing.
fn smoke_abi_udp_connected_port_unreachable_econnrefused() -> TestResult {
    with_setup(|| {
        let s = udp()?;
        if connect(&s, LO, 41070)? != 0 {
            return Err("connect failed");
        }
        if send(&s, b"anyone?")? != 7 {
            return Err("the send itself must succeed");
        }
        if revents(&s, POLLIN)? & POLLERR == 0 {
            return Err("poll does not report POLLERR for the pending error");
        }
        let mut buf = [0u8; 8];
        if recv(&s, &mut buf)? != ECONNREFUSED {
            return Err("recv after port-unreachable is not ECONNREFUSED");
        }
        if recv(&s, &mut buf)? != EAGAIN {
            return Err("the error was reported more than once");
        }
        // Via send and via SO_ERROR as well.
        send(&s, b"again")?;
        if send(&s, b"third")? != ECONNREFUSED {
            return Err("send does not report the pending ECONNREFUSED");
        }
        send(&s, b"fourth")?;
        if getsockopt_int(&s, SOL_SOCKET, SO_ERROR)? != 111 {
            return Err("SO_ERROR is not ECONNREFUSED");
        }
        if getsockopt_int(&s, SOL_SOCKET, SO_ERROR)? != 0 {
            return Err("SO_ERROR did not clear");
        }
        let u = udp()?;
        sendto(&u, b"x", LO, 41070)?;
        if recv(&u, &mut buf)? != EAGAIN {
            return Err("an unconnected sender got an ICMP error");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_connected_port_unreachable_econnrefused
);

// ────────────────────────── lookup precedence ────────────────────────

/// A socket bound to the exact destination wins over a wildcard one
/// (`__udp4_lib_lookup`, `net/ipv4/udp.c:497-527`), and a connected socket
/// outranks an unconnected one for its peer's traffic
/// (`compute_score`, `net/ipv4/udp.c:389-399`).
fn smoke_abi_udp_lookup_precedence() -> TestResult {
    with_setup(|| {
        let wild = udp()?;
        let exact = udp()?;
        for s in [&wild, &exact] {
            setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, 1)?;
        }
        if bind(&exact, LO, 41080)? != 0 || bind(&wild, ANY, 41080)? != 0 {
            return Err("SO_REUSEADDR binds failed");
        }
        let tx = receiver(41081)?;
        sendto(&tx, b"e", LO, 41080)?;
        let mut buf = [0u8; 4];
        if recv(&exact, &mut buf)? != 1 || recv(&wild, &mut buf)? != EAGAIN {
            return Err("the exact-address socket did not win over the wildcard");
        }

        let plain = udp()?;
        let conn = udp()?;
        for s in [&conn, &plain] {
            setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, 1)?;
            if bind(s, LO, 41082)? != 0 {
                return Err("SO_REUSEADDR bind failed");
            }
        }
        // `conn` bound first, so a plain tie would go to the newer `plain`.
        if connect(&conn, LO, 41081)? != 0 {
            return Err("connect failed");
        }
        sendto(&tx, b"c", LO, 41082)?;
        if recv(&conn, &mut buf)? != 1 || recv(&plain, &mut buf)? != EAGAIN {
            return Err("the connected socket did not win its peer's datagram");
        }
        let other = receiver(41083)?;
        sendto(&other, b"o", LO, 41082)?;
        if recv(&plain, &mut buf)? != 1 || recv(&conn, &mut buf)? != EAGAIN {
            return Err("a non-peer datagram reached the connected socket");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_lookup_precedence);

/// A SO_REUSEPORT group splits flows across its members
/// (`inet_lookup_reuseport`, `net/ipv4/udp.c:453`).
fn smoke_abi_udp_reuseport_distributes_flows() -> TestResult {
    with_setup(|| {
        let a = udp()?;
        let b = udp()?;
        for s in [&a, &b] {
            setsockopt_int(s, SOL_SOCKET, SO_REUSEPORT, 1)?;
            if bind(s, LO, 41090)? != 0 {
                return Err("SO_REUSEPORT bind failed");
            }
        }
        let mut senders = alloc::vec::Vec::new();
        for p in 0..8u16 {
            let s = receiver(41091 + p)?;
            sendto(&s, b"f", LO, 41090)?;
            senders.push(s);
        }
        let (mut na, mut nb) = (0, 0);
        let mut buf = [0u8; 4];
        while recv(&a, &mut buf)? == 1 {
            na += 1;
        }
        while recv(&b, &mut buf)? == 1 {
            nb += 1;
        }
        if na + nb != 8 {
            return Err("reuseport group lost or duplicated datagrams");
        }
        if na == 0 || nb == 0 {
            return Err("all flows went to one member of the reuseport group");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_reuseport_distributes_flows);

// ──────────────────────── shutdown / listen / poll ───────────────────

/// Invalid `how` → EINVAL (`net/ipv4/af_inet.c:904-905`); on an unconnected
/// socket the bits are set but the call is ENOTCONN
/// (`net/ipv4/af_inet.c:917-923`).
fn smoke_abi_udp_shutdown_errnos() -> TestResult {
    with_setup(|| {
        let s = receiver(41100)?;
        if call(Syscall::SocketShutdown.raw(), a1(s.0, 3)) != Some(EINVAL) {
            return Err("shutdown(how=3) is not EINVAL");
        }
        if call(Syscall::SocketShutdown.raw(), a1(s.0, SHUT_RD)) != Some(ENOTCONN) {
            return Err("shutdown on an unconnected UDP socket is not ENOTCONN");
        }
        // ...but it took effect: recv on the empty queue is now EOF.
        let mut buf = [0u8; 4];
        if recv(&s, &mut buf)? != 0 {
            return Err("SHUT_RD on an unconnected socket did not take effect");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_shutdown_errnos);

/// SHUT_RD: queued data is still readable, then recv returns 0 instead of
/// EAGAIN (`net/core/datagram.c:104-105`) and poll reports POLLIN
/// (`net/core/datagram.c:899-900`).
fn smoke_abi_udp_shutdown_rd_eof() -> TestResult {
    with_setup(|| {
        let s = receiver(41101)?;
        let peer = receiver(41102)?;
        connect(&s, LO, 41102)?;
        sendto(&peer, b"last", LO, 41101)?;
        if call(Syscall::SocketShutdown.raw(), a1(s.0, SHUT_RD)) != Some(0) {
            return Err("shutdown(SHUT_RD) on a connected socket failed");
        }
        let mut buf = [0u8; 8];
        if recv(&s, &mut buf)? != 4 {
            return Err("queued data was not readable after SHUT_RD");
        }
        if recv(&s, &mut buf)? != 0 {
            return Err("recv after SHUT_RD on an empty queue is not 0");
        }
        if revents(&s, POLLIN)? & POLLIN == 0 {
            return Err("poll does not report POLLIN after SHUT_RD");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_shutdown_rd_eof);

/// SHUT_WR: send is EPIPE (`sock_alloc_send_pskb`, `net/core/sock.c:2872-2874`)
/// and raises NO SIGPIPE — only the stream error path does
/// (`sk_stream_error`, `net/core/stream.c:191`).
fn smoke_abi_udp_shutdown_wr_epipe_without_sigpipe() -> TestResult {
    with_setup(|| {
        let s = receiver(41103)?;
        let _peer = receiver(41104)?;
        connect(&s, LO, 41104)?;
        if call(Syscall::SocketShutdown.raw(), a1(s.0, SHUT_WR)) != Some(0) {
            return Err("shutdown(SHUT_WR) failed");
        }
        if send(&s, b"x")? != EPIPE {
            return Err("send after SHUT_WR is not EPIPE");
        }
        if sendto(&s, b"x", LO, 41104)? != EPIPE {
            return Err("sendto after SHUT_WR is not EPIPE");
        }
        let mut mask = 0u64;
        if call(
            Syscall::RtSigpending.raw(),
            a1(&mut mask as *mut u64 as u64, 8),
        ) != Some(0)
        {
            return Err("rt_sigpending failed");
        }
        if mask & (1 << (SIGPIPE - 1)) != 0 {
            return Err("UDP EPIPE raised SIGPIPE");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_shutdown_wr_epipe_without_sigpipe
);

/// listen / accept are `sock_no_listen` / `sock_no_accept` → EOPNOTSUPP
/// (`net/core/sock.c:3339-3362`).
fn smoke_abi_udp_listen_accept_eopnotsupp() -> TestResult {
    with_setup(|| {
        let s = receiver(41105)?;
        if call(Syscall::SocketListen.raw(), a1(s.0, 1)) != Some(EOPNOTSUPP) {
            return Err("listen on UDP is not EOPNOTSUPP");
        }
        if call(Syscall::SocketAccept.raw(), a2(s.0, 0, 0)) != Some(EOPNOTSUPP) {
            return Err("accept on UDP is not EOPNOTSUPP");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_listen_accept_eopnotsupp);

/// `datagram_poll` (`net/core/datagram.c:882-925`): always writable, even
/// unbound; POLLIN once a datagram is queued; POLLHUP (+POLLIN) after
/// SHUT_RDWR.
fn smoke_abi_udp_poll_bits() -> TestResult {
    with_setup(|| {
        let fresh = udp()?;
        if revents(&fresh, POLLIN | POLLOUT)? != POLLOUT {
            return Err("a fresh UDP socket is not exactly POLLOUT");
        }
        let rx = receiver(41106)?;
        if revents(&rx, POLLIN | POLLOUT)? != POLLOUT {
            return Err("an idle bound UDP socket is not exactly POLLOUT");
        }
        sendto(&fresh, b"x", LO, 41106)?;
        if revents(&rx, POLLIN | POLLOUT)? != POLLIN | POLLOUT {
            return Err("a socket with a queued datagram is not POLLIN|POLLOUT");
        }
        let _ = call(Syscall::SocketShutdown.raw(), a1(rx.0, SHUT_RDWR));
        let mut buf = [0u8; 4];
        recv(&rx, &mut buf)?;
        let ev = revents(&rx, POLLIN | POLLOUT)?;
        if ev & POLLHUP == 0 || ev & POLLIN == 0 {
            return Err("SHUT_RDWR does not report POLLHUP|POLLIN");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_poll_bits);

/// A stream socket and a datagram socket may use the same port number —
/// separate tables, as on Linux. Guards against the UDP table leaking into
/// TCP's.
fn smoke_abi_udp_and_tcp_ports_are_independent() -> TestResult {
    with_setup(|| {
        let u = receiver(41107)?;
        let t = match call(Syscall::SocketOpen.raw(), a2(AF_INET, SOCK_STREAM, 0)) {
            Some(fd) if fd >= 0 => Fd(fd as u64),
            _ => return Err("socket(SOCK_STREAM) failed"),
        };
        if bind(&t, LO, 41107)? != 0 {
            return Err("TCP bind collided with a UDP binding");
        }
        drop(u);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_and_tcp_ports_are_independent
);

/// recvmsg honours the caller's `msg_namelen`: `move_addr_to_user` copies at
/// most that many bytes of the source address (it used to write the whole
/// sockaddr past a short buffer) and stores the full length back.
fn smoke_abi_udp_recvmsg_short_namelen_truncates() -> TestResult {
    with_setup(|| {
        let rx = receiver(41190)?;
        let tx = receiver(41191)?;
        sendto(&tx, b"abc", LO, 41190)?;
        let mut data = [0u8; 8];
        let mut from = [0xAAu8; 16];
        let iov: [u64; 2] = [data.as_mut_ptr() as u64, data.len() as u64];
        let mut msg = [0u8; 56];
        msg[0..8].copy_from_slice(&(from.as_mut_ptr() as u64).to_ne_bytes());
        msg[8..12].copy_from_slice(&4u32.to_ne_bytes());
        msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        let r = call(
            Syscall::SocketRecvMsg.raw(),
            a2(rx.0, msg.as_mut_ptr() as u64, 0),
        )
        .ok_or("recvmsg status")?;
        if r != 3 {
            return Err("recvmsg did not return the datagram");
        }
        let namelen = u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);
        if namelen != 16 {
            return Err("recvmsg did not report the full sockaddr_in length");
        }
        if from[4..] != [0xAA; 12] {
            return Err("recvmsg wrote the source address past msg_namelen");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_recvmsg_short_namelen_truncates
);
