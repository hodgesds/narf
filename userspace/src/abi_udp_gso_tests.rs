//! Linux syscall ABI conformance — UDP GSO / GRO (`SOL_UDP` `UDP_SEGMENT`,
//! `UDP_GRO`).
//!
//! Every case drives the real `socket`, `bind`, `setsockopt`, `getsockopt`,
//! `sendto`, `sendmsg`, `sendmmsg`, `recvfrom` and `recvmsg` handlers over
//! loopback and asserts what Linux produces:
//!
//! - `udp_lib_setsockopt` / `udp_lib_getsockopt` (`net/ipv4/udp.c`) for the
//!   option values and errnos;
//! - `udp_cmsg_send` / `__udp_cmsg_send` for the per-send `UDP_SEGMENT`
//!   cmsg, applied after `udp_sendmsg`'s address checks;
//! - `udp_send_skb` / `udp_v6_send_skb` for the GSO limits;
//! - lo carries a GSO skb up unsegmented (`NETIF_F_GSO_SOFTWARE`), so a
//!   receiver without `UDP_GRO` sees the batched datagrams
//!   (`udp_unexpected_gso` → `udp_rcv_segment`) while a `UDP_GRO` receiver
//!   reads one coalesced datagram with a `UDP_GRO` cmsg (`udp_cmsg_recv`).
//!
//! Sockets are `SOCK_NONBLOCK`: the harness has no user task to park.
use crate::abi_test_support::*;
use alloc::vec::Vec;

const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOL_SOCKET: u64 = 1;
const SO_NO_CHECK: u64 = 11;
const SO_RCVBUF: u64 = 8;
const IPPROTO_IP: u64 = 0;
const IP_PKTINFO: u64 = 8;
const SOL_UDP: u64 = 17;
const UDP_CORK: u64 = 1;
const UDP_NO_CHECK6_TX: u64 = 101;
const UDP_SEGMENT: u64 = 103;
const UDP_GRO: u64 = 104;
const UDPLITE_SEND_CSCOV: u64 = 10;
const MSG_TRUNC: u32 = 0x20;
const MSG_CTRUNC: u32 = 0x8;

const LO: [u8; 4] = [127, 0, 0, 1];
const LO6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// A socket fd closed when the case returns.
struct Fd(u64);

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = call(Syscall::Close.raw(), a0(self.0));
    }
}

fn open(domain: u64, kind: u64) -> Result<Fd, &'static str> {
    match call(
        Syscall::SocketOpen.raw(),
        a2(domain, kind | SOCK_NONBLOCK, 0),
    ) {
        Some(fd) if fd >= 0 => Ok(Fd(fd as u64)),
        _ => Err("socket() failed"),
    }
}

fn sin(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&ip);
    b
}

fn sin6(ip: [u8; 16], port: u16) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[8..24].copy_from_slice(&ip);
    b
}

fn bind_raw(fd: &Fd, addr: &[u8]) -> Result<(), &'static str> {
    match call(
        Syscall::SocketBind.raw(),
        a2(fd.0, addr.as_ptr() as u64, addr.len() as u64),
    ) {
        Some(0) => Ok(()),
        _ => Err("bind failed"),
    }
}

/// A bound 127.0.0.1:`port` UDP receiver with a 1 MiB receive buffer.
fn receiver(port: u16) -> Result<Fd, &'static str> {
    let fd = open(AF_INET, SOCK_DGRAM)?;
    bind_raw(&fd, &sin(LO, port))?;
    setsockopt_int(&fd, SOL_SOCKET, SO_RCVBUF, 1 << 20)?;
    Ok(fd)
}

/// A bound [::1]:`port` UDP receiver.
fn receiver6(port: u16) -> Result<Fd, &'static str> {
    let fd = open(AF_INET6, SOCK_DGRAM)?;
    bind_raw(&fd, &sin6(LO6, port))?;
    setsockopt_int(&fd, SOL_SOCKET, SO_RCVBUF, 1 << 20)?;
    Ok(fd)
}

fn setsockopt_raw(fd: &Fd, level: u64, opt: u64, val: &[u8]) -> Result<i64, &'static str> {
    call(
        Syscall::SocketSetSockOpt.raw(),
        a4(fd.0, level, opt, val.as_ptr() as u64, val.len() as u64),
    )
    .ok_or("setsockopt status")
}

fn setsockopt_int(fd: &Fd, level: u64, opt: u64, v: i32) -> Result<i64, &'static str> {
    setsockopt_raw(fd, level, opt, &v.to_ne_bytes())
}

/// `getsockopt` with a `len`-byte buffer → (return, value bytes, optlen).
fn getsockopt_len(
    fd: &Fd,
    level: u64,
    opt: u64,
    len: u32,
) -> Result<(i64, [u8; 4], u32), &'static str> {
    let mut val = [0xEEu8; 4];
    let mut optlen = len;
    let r = call(
        Syscall::SocketGetSockOpt.raw(),
        SyscallArgs {
            arg0: fd.0,
            arg1: level,
            arg2: opt,
            arg3: val.as_mut_ptr() as u64,
            arg4: &mut optlen as *mut u32 as u64,
            ..SyscallArgs::default()
        },
    )
    .ok_or("getsockopt status")?;
    Ok((r, val, optlen))
}

fn getsockopt_int(fd: &Fd, level: u64, opt: u64) -> Result<i32, &'static str> {
    let (r, val, len) = getsockopt_len(fd, level, opt, 4)?;
    if r != 0 || len != 4 {
        return Err("getsockopt failed");
    }
    Ok(i32::from_ne_bytes(val))
}

/// A `SOL_UDP` control message of type `kind` carrying `data`, with an
/// explicit `cmsg_len` (normally `16 + data.len()`), padded to CMSG_SPACE.
fn cmsg(kind: i32, data: &[u8], cmsg_len: u64) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&cmsg_len.to_ne_bytes());
    c.extend_from_slice(&(SOL_UDP as i32).to_ne_bytes());
    c.extend_from_slice(&kind.to_ne_bytes());
    c.extend_from_slice(data);
    while c.len() % 8 != 0 {
        c.push(0);
    }
    c
}

/// The `UDP_SEGMENT` cmsg for `gso`: a `__u16`, `cmsg_len` CMSG_LEN(2).
fn segment_cmsg(gso: u16) -> Vec<u8> {
    cmsg(UDP_SEGMENT as i32, &gso.to_ne_bytes(), 18)
}

/// A `struct msghdr` (56 bytes) naming `name` (if any), one iovec and the
/// control buffer `ctrl`.
fn msghdr(name: Option<&[u8]>, iov: &[u64; 2], ctrl: &[u8]) -> [u8; 56] {
    let mut msg = [0u8; 56];
    if let Some(n) = name {
        msg[0..8].copy_from_slice(&(n.as_ptr() as u64).to_ne_bytes());
        msg[8..12].copy_from_slice(&(n.len() as u32).to_ne_bytes());
    }
    msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
    msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
    if !ctrl.is_empty() {
        msg[32..40].copy_from_slice(&(ctrl.as_ptr() as u64).to_ne_bytes());
        msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
    }
    msg
}

/// `sendmsg(fd, {name, [buf], ctrl}, 0)`.
fn sendmsg(fd: &Fd, name: Option<&[u8]>, buf: &[u8], ctrl: &[u8]) -> Result<i64, &'static str> {
    let iov: [u64; 2] = [buf.as_ptr() as u64, buf.len() as u64];
    let msg = msghdr(name, &iov, ctrl);
    call(
        Syscall::SocketSendMsg.raw(),
        a2(fd.0, msg.as_ptr() as u64, 0),
    )
    .ok_or("sendmsg status")
}

fn sendto(fd: &Fd, buf: &[u8], name: &[u8]) -> Result<i64, &'static str> {
    call(
        Syscall::SocketSend.raw(),
        SyscallArgs {
            arg0: fd.0,
            arg1: buf.as_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: 0,
            arg4: name.as_ptr() as u64,
            arg5: name.len() as u64,
        },
    )
    .ok_or("sendto status")
}

fn recv(fd: &Fd, buf: &mut [u8]) -> Result<i64, &'static str> {
    call(
        Syscall::SocketRecv.raw(),
        SyscallArgs {
            arg0: fd.0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
    )
    .ok_or("recv status")
}

/// `recvmsg` into a 70000-byte buffer with a `ctrl_len`-byte control buffer
/// → (return, msg_flags, msg_controllen, control bytes, data).
type RecvMsg = (i64, u32, u64, Vec<u8>, Vec<u8>);

fn recvmsg(fd: &Fd, ctrl_len: usize) -> Result<RecvMsg, &'static str> {
    let mut data = alloc::vec![0u8; 70_000];
    let mut ctrl = alloc::vec![0xEEu8; ctrl_len.max(1)];
    let iov: [u64; 2] = [data.as_mut_ptr() as u64, data.len() as u64];
    let mut msg = [0u8; 56];
    msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
    msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
    if ctrl_len != 0 {
        msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
        msg[40..48].copy_from_slice(&(ctrl_len as u64).to_ne_bytes());
    }
    let r = call(
        Syscall::SocketRecvMsg.raw(),
        a2(fd.0, msg.as_mut_ptr() as u64, 0),
    )
    .ok_or("recvmsg status")?;
    let flags = u32::from_ne_bytes([msg[48], msg[49], msg[50], msg[51]]);
    let controllen = u64::from_ne_bytes(msg[40..48].try_into().unwrap_or([0; 8]));
    if r >= 0 {
        data.truncate(r as usize);
    }
    ctrl.truncate(ctrl_len);
    Ok((r, flags, controllen, ctrl, data))
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(29) ^ seed).collect()
}

/// Drain `fd` (non-blocking) and return every datagram's bytes in order.
fn drain(fd: &Fd) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut out = Vec::new();
    let mut buf = alloc::vec![0u8; 70_000];
    loop {
        let n = recv(fd, &mut buf)?;
        if n == EAGAIN {
            return Ok(out);
        }
        if n < 0 {
            return Err("recv on the receiver failed");
        }
        out.push(buf[..n as usize].to_vec());
    }
}

/// `datagrams` must be `payload` cut at every `gso` bytes.
fn expect_segments(datagrams: &[Vec<u8>], payload: &[u8], gso: usize) -> Result<(), &'static str> {
    let want: Vec<&[u8]> = payload.chunks(gso).collect();
    if datagrams.len() != want.len() {
        return Err("the receiver did not get one datagram per gso_size bytes");
    }
    if datagrams
        .iter()
        .zip(want)
        .any(|(got, w)| got.as_slice() != w)
    {
        return Err("a received segment differs from its slice of the GSO payload");
    }
    Ok(())
}

// ───────────────────────────── setsockopt / getsockopt ─────────────────────

/// `udp_lib_setsockopt` / `udp_lib_getsockopt`: UDP_SEGMENT is a u16 GSO
/// size (`val < 0 || val > USHRT_MAX` → EINVAL), UDP_GRO a boolean, both
/// default 0; `optlen < sizeof(int)` is EINVAL for every SOL_UDP option;
/// setting UDP-Lite's options is ENOPROTOOPT on a UDP socket, as is an
/// unknown name; getsockopt copies `min(len, sizeof(int))` bytes and reports
/// UDP_CORK's 0.
fn smoke_abi_udp_gso_sockopts() -> TestResult {
    with_setup(|| {
        for domain in [AF_INET, AF_INET6] {
            let s = open(domain, SOCK_DGRAM)?;
            if getsockopt_int(&s, SOL_UDP, UDP_SEGMENT)? != 0
                || getsockopt_int(&s, SOL_UDP, UDP_GRO)? != 0
            {
                return Err("UDP_SEGMENT / UDP_GRO do not default to 0");
            }
            if setsockopt_int(&s, SOL_UDP, UDP_SEGMENT, 1200)? != 0
                || getsockopt_int(&s, SOL_UDP, UDP_SEGMENT)? != 1200
            {
                return Err("UDP_SEGMENT 1200 did not round-trip");
            }
            if setsockopt_int(&s, SOL_UDP, UDP_SEGMENT, 65535)? != 0
                || getsockopt_int(&s, SOL_UDP, UDP_SEGMENT)? != 65535
            {
                return Err("UDP_SEGMENT USHRT_MAX was refused");
            }
            if setsockopt_int(&s, SOL_UDP, UDP_SEGMENT, 65536)? != EINVAL
                || setsockopt_int(&s, SOL_UDP, UDP_SEGMENT, -1)? != EINVAL
            {
                return Err("UDP_SEGMENT outside 0..=USHRT_MAX is not EINVAL");
            }
            if getsockopt_int(&s, SOL_UDP, UDP_SEGMENT)? != 65535 {
                return Err("a refused UDP_SEGMENT changed the value");
            }
            if setsockopt_int(&s, SOL_UDP, UDP_SEGMENT, 0)? != 0
                || getsockopt_int(&s, SOL_UDP, UDP_SEGMENT)? != 0
            {
                return Err("UDP_SEGMENT 0 did not clear the GSO size");
            }
            if setsockopt_int(&s, SOL_UDP, UDP_GRO, 7)? != 0
                || getsockopt_int(&s, SOL_UDP, UDP_GRO)? != 1
            {
                return Err("UDP_GRO does not store a boolean");
            }
            if setsockopt_int(&s, SOL_UDP, UDP_GRO, 0)? != 0
                || getsockopt_int(&s, SOL_UDP, UDP_GRO)? != 0
            {
                return Err("UDP_GRO 0 did not disable GRO");
            }
            if setsockopt_raw(&s, SOL_UDP, UDP_SEGMENT, &[0, 4])? != EINVAL
                || setsockopt_raw(&s, SOL_UDP, 9999, &[1])? != EINVAL
            {
                return Err("a SOL_UDP optlen < sizeof(int) is not EINVAL");
            }
            if setsockopt_int(&s, SOL_UDP, 9999, 1)? != ENOPROTOOPT
                || setsockopt_int(&s, SOL_UDP, UDPLITE_SEND_CSCOV, 8)? != ENOPROTOOPT
            {
                return Err("an unknown / UDP-Lite SOL_UDP option is not ENOPROTOOPT");
            }
            if getsockopt_len(&s, SOL_UDP, 9999, 4)?.0 != ENOPROTOOPT {
                return Err("getsockopt of an unknown SOL_UDP option is not ENOPROTOOPT");
            }
            if getsockopt_int(&s, SOL_UDP, UDP_CORK)? != 0 {
                return Err("UDP_CORK does not read 0");
            }
            setsockopt_int(&s, SOL_UDP, UDP_SEGMENT, 0x0102)?;
            let (r, val, len) = getsockopt_len(&s, SOL_UDP, UDP_SEGMENT, 1)?;
            if r != 0 || len != 1 || val[0] != 0x02u16.to_ne_bytes()[0] || val[1] != 0xEE {
                return Err("a 1-byte UDP_SEGMENT getsockopt did not copy exactly one byte");
            }
        }
        // A TCP socket hands SOL_UDP to IP: `do_ip_setsockopt` is
        // ENOPROTOOPT for a foreign level, `do_ip_getsockopt` EOPNOTSUPP.
        let t = open(AF_INET, SOCK_STREAM)?;
        if setsockopt_int(&t, SOL_UDP, UDP_SEGMENT, 1200)? != ENOPROTOOPT {
            return Err("SOL_UDP on a TCP socket is not ENOPROTOOPT");
        }
        if getsockopt_len(&t, SOL_UDP, UDP_SEGMENT, 4)?.0 != EOPNOTSUPP {
            return Err("getsockopt(SOL_UDP) on a TCP socket is not EOPNOTSUPP");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_gso_sockopts);

// ───────────────────────────── GSO send ────────────────────────────────────

/// A `UDP_SEGMENT` cmsg splits one sendmsg into `gso_size`-byte datagrams
/// plus a shorter tail; the sendmsg returns the whole length and a receiver
/// without UDP_GRO gets each datagram on its own.
fn smoke_abi_udp_gso_cmsg_splits_into_datagrams() -> TestResult {
    with_setup(|| {
        let rx = receiver(41301)?;
        let tx = open(AF_INET, SOCK_DGRAM)?;
        let payload = pattern(5 * 1200 + 700, 0x11);
        let dst = sin(LO, 41301);
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(1200))? != payload.len() as i64 {
            return Err("a GSO sendmsg did not report the whole payload as sent");
        }
        expect_segments(&drain(&rx)?, &payload, 1200)?;
        // A payload no larger than gso_size is one ordinary datagram.
        let small = pattern(900, 0x12);
        if sendmsg(&tx, Some(&dst), &small, &segment_cmsg(1200))? != 900 {
            return Err("a GSO sendmsg <= gso_size failed");
        }
        expect_segments(&drain(&rx)?, &small, 1200)?;
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_gso_cmsg_splits_into_datagrams
);

/// `ipc.gso_size = up->gso_size`: the UDP_SEGMENT socket option segments
/// every send, plain `sendto` included; a `UDP_SEGMENT` cmsg overrides it,
/// and a cmsg of 0 sends one datagram. The cmsg applies to its own sendmsg
/// only.
fn smoke_abi_udp_gso_socket_default_and_cmsg_override() -> TestResult {
    with_setup(|| {
        let rx = receiver(41302)?;
        let tx = open(AF_INET, SOCK_DGRAM)?;
        let dst = sin(LO, 41302);
        if setsockopt_int(&tx, SOL_UDP, UDP_SEGMENT, 1000)? != 0 {
            return Err("setsockopt(UDP_SEGMENT) failed");
        }
        let payload = pattern(3500, 0x21);
        if sendto(&tx, &payload, &dst)? != 3500 {
            return Err("a sendto on a UDP_SEGMENT socket failed");
        }
        expect_segments(&drain(&rx)?, &payload, 1000)?;
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(500))? != 3500 {
            return Err("a sendmsg overriding UDP_SEGMENT failed");
        }
        expect_segments(&drain(&rx)?, &payload, 500)?;
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(0))? != 3500 {
            return Err("a sendmsg with a zero UDP_SEGMENT cmsg failed");
        }
        expect_segments(&drain(&rx)?, &payload, 3500)?;
        // Back to the socket default on the next send.
        if sendto(&tx, &payload, &dst)? != 3500 {
            return Err("a sendto after a cmsg override failed");
        }
        expect_segments(&drain(&rx)?, &payload, 1000)?;
        // A cmsg on a socket without a default does not linger either.
        setsockopt_int(&tx, SOL_UDP, UDP_SEGMENT, 0)?;
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(700))? != 3500 {
            return Err("a GSO sendmsg failed");
        }
        expect_segments(&drain(&rx)?, &payload, 700)?;
        if sendto(&tx, &payload, &dst)? != 3500 {
            return Err("a plain sendto failed");
        }
        expect_segments(&drain(&rx)?, &payload, 3500)?;
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_gso_socket_default_and_cmsg_override
);

/// `__udp_cmsg_send`: a UDP_SEGMENT cmsg whose `cmsg_len` is not
/// CMSG_LEN(sizeof(__u16)) and any other SOL_UDP cmsg type are EINVAL —
/// but only once `udp_sendmsg` has passed its own earlier checks: `len >
/// 0xFFFF` (EMSGSIZE) and a missing destination (EDESTADDRREQ) win.
/// Nothing is delivered on an error.
fn smoke_abi_udp_gso_cmsg_errors_and_order() -> TestResult {
    with_setup(|| {
        let rx = receiver(41303)?;
        let tx = open(AF_INET, SOCK_DGRAM)?;
        let dst = sin(LO, 41303);
        let payload = pattern(3000, 0x31);
        let long = cmsg(UDP_SEGMENT as i32, &1200u32.to_ne_bytes(), 20);
        if sendmsg(&tx, Some(&dst), &payload, &long)? != EINVAL {
            return Err("a 4-byte UDP_SEGMENT cmsg is not EINVAL");
        }
        let short = cmsg(UDP_SEGMENT as i32, &[0xB0], 17);
        if sendmsg(&tx, Some(&dst), &payload, &short)? != EINVAL {
            return Err("a 1-byte UDP_SEGMENT cmsg is not EINVAL");
        }
        let gro = cmsg(UDP_GRO as i32, &1200u16.to_ne_bytes(), 18);
        if sendmsg(&tx, Some(&dst), &payload, &gro)? != EINVAL {
            return Err("a SOL_UDP cmsg other than UDP_SEGMENT is not EINVAL");
        }
        // The first error stops the walk even after a valid record.
        let mut both = segment_cmsg(1200);
        both.extend_from_slice(&gro);
        if sendmsg(&tx, Some(&dst), &payload, &both)? != EINVAL {
            return Err("a bad SOL_UDP record after a good one is not EINVAL");
        }
        if !drain(&rx)?.is_empty() {
            return Err("a send refused for its cmsg delivered data");
        }
        // Address errors precede the cmsg.
        if sendmsg(&tx, None, &payload, &gro)? != EDESTADDRREQ {
            return Err("EDESTADDRREQ does not precede a bad SOL_UDP cmsg");
        }
        let huge = alloc::vec![0u8; 65_536];
        if sendmsg(&tx, Some(&dst), &huge, &gro)? != EMSGSIZE {
            return Err("len > 0xFFFF does not precede a bad SOL_UDP cmsg");
        }
        // A good GSO send after the errors is unaffected by them.
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(1200))? != 3000 {
            return Err("a GSO send after refused ones failed");
        }
        expect_segments(&drain(&rx)?, &payload, 1200)?;
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_gso_cmsg_errors_and_order);

/// `udp_send_skb`: more than `UDP_MAX_SEGMENTS` (128) segments is EINVAL,
/// 128 is accepted; SO_NO_CHECK (`sk_no_check_tx`) refuses a GSO send with
/// EINVAL even when it would not be split, but not a plain send. A GSO send
/// is appended against IP_MAX_MTU, so the IPv4 payload ceiling (65507)
/// still applies.
fn smoke_abi_udp_gso_send_limits() -> TestResult {
    with_setup(|| {
        let rx = receiver(41304)?;
        let tx = open(AF_INET, SOCK_DGRAM)?;
        let dst = sin(LO, 41304);
        let payload = pattern(65_508, 0x41);
        if sendmsg(&tx, Some(&dst), &payload[..129], &segment_cmsg(1))? != EINVAL {
            return Err("129 one-byte segments are not EINVAL");
        }
        if sendmsg(&tx, Some(&dst), &payload[..1290], &segment_cmsg(10))? != EINVAL {
            return Err("129 ten-byte segments are not EINVAL");
        }
        if !drain(&rx)?.is_empty() {
            return Err("an over-limit GSO send delivered data");
        }
        if sendmsg(&tx, Some(&dst), &payload[..1280], &segment_cmsg(10))? != 1280 {
            return Err("128 ten-byte segments were refused");
        }
        expect_segments(&drain(&rx)?, &payload[..1280], 10)?;
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(1200))? != EMSGSIZE {
            return Err("a 65508-byte GSO payload is not EMSGSIZE");
        }
        if sendmsg(&tx, Some(&dst), &payload[..65_507], &segment_cmsg(1200))? != 65_507 {
            return Err("a 65507-byte GSO payload was refused");
        }
        expect_segments(&drain(&rx)?, &payload[..65_507], 1200)?;
        if setsockopt_int(&tx, SOL_SOCKET, SO_NO_CHECK, 1)? != 0 {
            return Err("setsockopt(SO_NO_CHECK) failed");
        }
        if sendmsg(&tx, Some(&dst), &payload[..3000], &segment_cmsg(1200))? != EINVAL {
            return Err("a GSO send with SO_NO_CHECK is not EINVAL");
        }
        if sendmsg(&tx, Some(&dst), &payload[..100], &segment_cmsg(1200))? != EINVAL {
            return Err("an unsplit GSO send with SO_NO_CHECK is not EINVAL");
        }
        if !drain(&rx)?.is_empty() {
            return Err("a GSO send refused for SO_NO_CHECK delivered data");
        }
        if sendto(&tx, &payload[..100], &dst)? != 100 {
            return Err("a plain send with SO_NO_CHECK failed");
        }
        expect_segments(&drain(&rx)?, &payload[..100], 100)?;
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_gso_send_limits);

/// `sendmmsg` applies each message's own control buffer: a GSO message, a
/// plain one and a GSO message of a different size arrive as 1000 x 3,
/// 500, and 250 x 2.
fn smoke_abi_udp_gso_sendmmsg_per_message_cmsg() -> TestResult {
    with_setup(|| {
        let rx = receiver(41305)?;
        let tx = open(AF_INET, SOCK_DGRAM)?;
        let dst = sin(LO, 41305);
        let a = pattern(3000, 0x51);
        let b = pattern(500, 0x52);
        let c = pattern(500, 0x53);
        let ca = segment_cmsg(1000);
        let cc = segment_cmsg(250);
        let iovs: [[u64; 2]; 3] = [
            [a.as_ptr() as u64, a.len() as u64],
            [b.as_ptr() as u64, b.len() as u64],
            [c.as_ptr() as u64, c.len() as u64],
        ];
        // struct mmsghdr { struct msghdr; unsigned msg_len; } = 64 bytes.
        let mut vec = [0u8; 3 * 64];
        for (i, ctrl) in [&ca[..], &[][..], &cc[..]].iter().enumerate() {
            let m = msghdr(Some(&dst), &iovs[i], ctrl);
            vec[i * 64..i * 64 + 56].copy_from_slice(&m);
        }
        let r = call(
            Syscall::Sendmmsg.raw(),
            a3(tx.0, vec.as_mut_ptr() as u64, 3, 0),
        )
        .ok_or("sendmmsg status")?;
        if r != 3 {
            return Err("sendmmsg did not send all three messages");
        }
        let lens: Vec<u32> = (0..3)
            .map(|i| u32::from_ne_bytes(vec[i * 64 + 56..i * 64 + 60].try_into().unwrap_or([0; 4])))
            .collect();
        if lens != [3000, 500, 500] {
            return Err("sendmmsg msg_len values are not each message's full length");
        }
        let got = drain(&rx)?;
        if got.len() != 6 {
            return Err("sendmmsg did not deliver 3 + 1 + 2 datagrams");
        }
        expect_segments(&got[..3], &a, 1000)?;
        expect_segments(&got[3..4], &b, 500)?;
        expect_segments(&got[4..], &c, 250)?;
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_gso_sendmmsg_per_message_cmsg
);

// ───────────────────────────── GRO receive ─────────────────────────────────

/// A UDP_GRO receiver reads a loopback GSO send as one coalesced datagram
/// with a `SOL_UDP`/`UDP_GRO` cmsg holding the segment size as an int
/// (`udp_cmsg_recv`), placed before the IP-level records (IP_PKTINFO). An
/// ordinary datagram carries no UDP_GRO cmsg. Control-buffer accounting is
/// `put_cmsg`'s: CMSG_SPACE consumed when it fits, a short buffer truncates
/// the record and sets MSG_CTRUNC, and one smaller than a cmsghdr takes
/// nothing.
fn smoke_abi_udp_gro_receives_coalesced_with_cmsg() -> TestResult {
    with_setup(|| {
        let rx = receiver(41306)?;
        if setsockopt_int(&rx, SOL_UDP, UDP_GRO, 1)? != 0 {
            return Err("setsockopt(UDP_GRO) failed");
        }
        let tx = open(AF_INET, SOCK_DGRAM)?;
        let dst = sin(LO, 41306);
        let payload = pattern(4 * 1200 + 300, 0x61);
        let send_gso = || sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(1200));
        if send_gso()? != payload.len() as i64 {
            return Err("a GSO send to a UDP_GRO receiver failed");
        }
        let (r, flags, clen, ctrl, data) = recvmsg(&rx, 64)?;
        if r != payload.len() as i64 || data != payload {
            return Err("a UDP_GRO receiver did not read the GSO send as one datagram");
        }
        if flags & (MSG_TRUNC | MSG_CTRUNC) != 0 || clen != 24 {
            return Err("the UDP_GRO cmsg did not consume exactly CMSG_SPACE(sizeof(int))");
        }
        let cmsg_len = u64::from_ne_bytes(ctrl[0..8].try_into().unwrap_or([0; 8]));
        let level = i32::from_ne_bytes(ctrl[8..12].try_into().unwrap_or([0; 4]));
        let kind = i32::from_ne_bytes(ctrl[12..16].try_into().unwrap_or([0; 4]));
        let gso = i32::from_ne_bytes(ctrl[16..20].try_into().unwrap_or([0; 4]));
        if cmsg_len != 20 || level != SOL_UDP as i32 || kind != UDP_GRO as i32 || gso != 1200 {
            return Err("the cmsg is not SOL_UDP/UDP_GRO, CMSG_LEN(4), gso_size 1200");
        }
        if !drain(&rx)?.is_empty() {
            return Err("a coalesced GSO send also queued its segments");
        }
        // An ordinary datagram: no UDP_GRO cmsg.
        if sendto(&tx, &payload[..800], &dst)? != 800 {
            return Err("a plain send to a UDP_GRO receiver failed");
        }
        let (r, flags, clen, _, _) = recvmsg(&rx, 64)?;
        if r != 800 || clen != 0 || flags & MSG_CTRUNC != 0 {
            return Err("an ordinary datagram carried a control message");
        }
        // UDP_GRO precedes IP_PKTINFO.
        setsockopt_int(&rx, IPPROTO_IP, IP_PKTINFO, 1)?;
        send_gso()?;
        let (r, _, clen, ctrl, _) = recvmsg(&rx, 64)?;
        let second = i32::from_ne_bytes(ctrl[24 + 8..24 + 12].try_into().unwrap_or([0; 4]));
        let second_kind = i32::from_ne_bytes(ctrl[24 + 12..24 + 16].try_into().unwrap_or([0; 4]));
        if r != payload.len() as i64
            || i32::from_ne_bytes(ctrl[12..16].try_into().unwrap_or([0; 4])) != UDP_GRO as i32
            || second != IPPROTO_IP as i32
            || second_kind != IP_PKTINFO as i32
            || clen != 24 + 32
        {
            return Err("UDP_GRO did not come first, followed by IP_PKTINFO");
        }
        setsockopt_int(&rx, IPPROTO_IP, IP_PKTINFO, 0)?;
        // A control buffer of exactly CMSG_LEN(4) holds the record whole.
        send_gso()?;
        let (_, flags, clen, _, _) = recvmsg(&rx, 20)?;
        if flags & MSG_CTRUNC != 0 || clen != 20 {
            return Err("a CMSG_LEN-sized control buffer truncated the UDP_GRO record");
        }
        // 18 bytes: the record is cut short and MSG_CTRUNC set.
        send_gso()?;
        let (r, flags, clen, ctrl, _) = recvmsg(&rx, 18)?;
        if r != payload.len() as i64
            || flags & MSG_CTRUNC == 0
            || clen != 18
            || u64::from_ne_bytes(ctrl[0..8].try_into().unwrap_or([0; 8])) != 18
        {
            return Err("a short control buffer did not truncate with MSG_CTRUNC");
        }
        // 8 bytes (< sizeof(cmsghdr)): nothing written, MSG_CTRUNC.
        send_gso()?;
        let (_, flags, clen, _, _) = recvmsg(&rx, 8)?;
        if flags & MSG_CTRUNC == 0 || clen != 0 {
            return Err("a control buffer smaller than a cmsghdr did not set MSG_CTRUNC");
        }
        // No control buffer at all: MSG_CTRUNC, the data still arrives.
        send_gso()?;
        let (r, flags, _, _, _) = recvmsg(&rx, 0)?;
        if r != payload.len() as i64 || flags & MSG_CTRUNC == 0 {
            return Err("recvmsg without a control buffer did not flag MSG_CTRUNC");
        }
        // Once UDP_GRO is off, GSO sends arrive segmented again.
        setsockopt_int(&rx, SOL_UDP, UDP_GRO, 0)?;
        send_gso()?;
        expect_segments(&drain(&rx)?, &payload, 1200)?;
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/udp",
    smoke_abi_udp_gro_receives_coalesced_with_cmsg
);

// ───────────────────────────── IPv6 ────────────────────────────────────────

/// AF_INET6 (`udpv6_sendmsg` → `udp_v6_send_skb`): a UDP_SEGMENT cmsg splits
/// a send to [::1]; a UDP_GRO receiver reads it whole with the UDP_GRO cmsg;
/// more than 128 segments and UDP_NO_CHECK6_TX are EINVAL for GSO.
fn smoke_abi_udp_gso_ipv6() -> TestResult {
    with_setup(|| {
        let rx = receiver6(41307)?;
        let tx = open(AF_INET6, SOCK_DGRAM)?;
        let dst = sin6(LO6, 41307);
        let payload = pattern(3 * 1200 + 50, 0x71);
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(1200))? != payload.len() as i64 {
            return Err("an IPv6 GSO sendmsg failed");
        }
        expect_segments(&drain(&rx)?, &payload, 1200)?;
        if sendmsg(&tx, Some(&dst), &payload[..129], &segment_cmsg(1))? != EINVAL {
            return Err("129 IPv6 segments are not EINVAL");
        }
        let gro = cmsg(UDP_GRO as i32, &1200u16.to_ne_bytes(), 18);
        if sendmsg(&tx, Some(&dst), &payload, &gro)? != EINVAL {
            return Err("a bad SOL_UDP cmsg on IPv6 is not EINVAL");
        }
        setsockopt_int(&rx, SOL_UDP, UDP_GRO, 1)?;
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(1200))? != payload.len() as i64 {
            return Err("an IPv6 GSO send to a UDP_GRO receiver failed");
        }
        let (r, _, clen, ctrl, data) = recvmsg(&rx, 64)?;
        if r != payload.len() as i64 || data != payload || clen != 24 {
            return Err("an IPv6 UDP_GRO receiver did not read one coalesced datagram");
        }
        if i32::from_ne_bytes(ctrl[12..16].try_into().unwrap_or([0; 4])) != UDP_GRO as i32
            || i32::from_ne_bytes(ctrl[16..20].try_into().unwrap_or([0; 4])) != 1200
        {
            return Err("the IPv6 UDP_GRO cmsg does not carry gso_size 1200");
        }
        if setsockopt_int(&tx, SOL_UDP, UDP_NO_CHECK6_TX, 1)? != 0
            || getsockopt_int(&tx, SOL_UDP, UDP_NO_CHECK6_TX)? != 1
        {
            return Err("UDP_NO_CHECK6_TX did not round-trip");
        }
        if sendmsg(&tx, Some(&dst), &payload, &segment_cmsg(1200))? != EINVAL {
            return Err("an IPv6 GSO send with UDP_NO_CHECK6_TX is not EINVAL");
        }
        if !drain(&rx)?.is_empty() {
            return Err("a refused IPv6 GSO send delivered data");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/udp", smoke_abi_udp_gso_ipv6);
