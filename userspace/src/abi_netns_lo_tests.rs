//! Linux syscall ABI conformance — a network namespace's own `lo`.
//!
//! `setup_net` runs every pernet init for a new namespace, and
//! `loopback_net_init` (drivers/net/loopback.c) registers that namespace's
//! `lo` at LOOPBACK_IFINDEX (1). `register_netdevice` leaves it down with no
//! address (`gen_lo_setup`: `dev->flags = IFF_LOOPBACK`). Inside the
//! namespace, the device ioctls (`dev_ioctl`) and rtnetlink resolve devices
//! with `__dev_get_by_name(net, ...)` / `__dev_get_by_index(net, ...)` over
//! that namespace only.
//!
//! bubblewrap's `--unshare-net` (`network.c` `loopback_setup`) depends on
//! exactly that: `if_nametoindex("lo")` (SIOCGIFINDEX on an AF_UNIX
//! datagram socket, glibc `__opensock`), then RTM_NEWADDR 127.0.0.1/8 with
//! NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, then RTM_NEWLINK IFF_UP with
//! NLM_F_ACK, each acknowledged with error 0 to the bound port id.
use crate::abi_test_support::*;

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_NETLINK: u64 = 16;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_CLOEXEC: u64 = 0o2000000;
const NETLINK_ROUTE: u64 = 0;
const MSG_DONTWAIT: u64 = 0x40;
const CLONE_NEWNET: u64 = 0x4000_0000;

const SIOCGIFNAME: u64 = 0x8910;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCGIFINDEX: u64 = 0x8933;

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_HDRLEN: usize = 16;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_F_PERMANENT: u8 = 0x80;
const RT_SCOPE_HOST: u8 = 254;
const RTNL_AF_UNSPEC: u8 = 0;
const RTNL_AF_INET: u8 = 2;

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

fn sys(n: Syscall, args: SyscallArgs) -> Option<i64> {
    call(n.raw(), args)
}

fn expect(cond: bool, msg: &'static str) -> Result<(), &'static str> {
    if cond {
        Ok(())
    } else {
        Err(msg)
    }
}

fn open(domain: u64, kind: u64, proto: u64) -> Result<u64, &'static str> {
    match sys(Syscall::SocketOpen, a2(domain, kind, proto)) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("socket() failed"),
    }
}

fn close(fd: u64) {
    let _ = sys(Syscall::Close, a0(fd));
}

/// A 40-byte `struct ifreq` naming `name`.
fn ifreq(name: &str) -> [u8; 40] {
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name.as_bytes());
    ifr
}

/// `if_nametoindex`: SIOCGIFINDEX; the errno on failure.
fn ifindex(fd: u64, name: &str) -> Result<i32, i64> {
    let mut ifr = ifreq(name);
    match sys(
        Syscall::Ioctl,
        a2(fd, SIOCGIFINDEX, ifr.as_mut_ptr() as u64),
    ) {
        Some(0) => Ok(i32::from_ne_bytes(ifr[16..20].try_into().unwrap())),
        Some(e) => Err(e),
        None => Err(i64::MIN),
    }
}

/// SIOCGIFFLAGS: `ifr_flags` (a short); the errno on failure.
fn ifflags(fd: u64, name: &str) -> Result<u32, i64> {
    let mut ifr = ifreq(name);
    match sys(
        Syscall::Ioctl,
        a2(fd, SIOCGIFFLAGS, ifr.as_mut_ptr() as u64),
    ) {
        Some(0) => Ok(u32::from(u16::from_ne_bytes([ifr[16], ifr[17]]))),
        Some(e) => Err(e),
        None => Err(i64::MIN),
    }
}

/// SIOCSIFFLAGS with `flags` as `ifr_flags`.
fn set_ifflags(fd: u64, name: &str, flags: u32) -> Option<i64> {
    let mut ifr = ifreq(name);
    ifr[16..18].copy_from_slice(&(flags as u16).to_ne_bytes());
    sys(
        Syscall::Ioctl,
        a2(fd, SIOCSIFFLAGS, ifr.as_mut_ptr() as u64),
    )
}

/// `if_indextoname`: SIOCGIFNAME; the errno on failure.
fn ifname(fd: u64, index: i32) -> Result<alloc::string::String, i64> {
    let mut ifr = [0u8; 40];
    ifr[16..20].copy_from_slice(&index.to_ne_bytes());
    match sys(Syscall::Ioctl, a2(fd, SIOCGIFNAME, ifr.as_mut_ptr() as u64)) {
        Some(0) => {
            let end = ifr[..16].iter().position(|b| *b == 0).unwrap_or(16);
            Ok(alloc::string::String::from_utf8_lossy(&ifr[..end]).into_owned())
        }
        Some(e) => Err(e),
        None => Err(i64::MIN),
    }
}

/// bubblewrap `rtnl_setup`: a NETLINK_ROUTE socket bound to port id
/// `getpid()`. Returns the fd and that port id.
fn open_route() -> Result<(u64, u32), &'static str> {
    let fd = open(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)?;
    let pid = sys(Syscall::GetPid, a0(0)).ok_or("getpid")? as u32;
    let mut sa = [0u8; 12];
    sa[0..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    sa[4..8].copy_from_slice(&pid.to_ne_bytes());
    expect(
        sys(Syscall::SocketBind, a2(fd, sa.as_ptr() as u64, 12)) == Some(0),
        "bind(sockaddr_nl { nl_pid = getpid() })",
    )?;
    Ok((fd, pid))
}

fn push_attr(body: &mut alloc::vec::Vec<u8>, kind: u16, payload: &[u8]) {
    body.resize((body.len() + 3) & !3, 0);
    body.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    body.extend_from_slice(&kind.to_ne_bytes());
    body.extend_from_slice(payload);
    body.resize((body.len() + 3) & !3, 0);
}

fn rtnl_request(msg_type: u16, flags: u16, seq: u32, body: &[u8]) -> alloc::vec::Vec<u8> {
    let len = NLMSG_HDRLEN + body.len();
    let mut m = alloc::vec::Vec::with_capacity((len + 3) & !3);
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&msg_type.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(body);
    m.resize((len + 3) & !3, 0);
    m
}

/// Send `req`; return every message queued in reply, split out of however
/// many datagrams carry them.
fn exchange(fd: u64, req: &[u8]) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, &'static str> {
    let mut args = a3(fd, req.as_ptr() as u64, req.len() as u64, 0);
    args.arg4 = 0;
    args.arg5 = 0;
    expect(
        sys(Syscall::SocketSend, args) == Some(req.len() as i64),
        "rtnetlink send did not consume the request",
    )?;
    let mut out = alloc::vec::Vec::new();
    for _ in 0..512 {
        let mut buf = [0u8; 8192];
        let n = match sys(
            Syscall::SocketRecv,
            a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, MSG_DONTWAIT),
        ) {
            Some(n) if n == EAGAIN => return Ok(out),
            Some(n) if n >= NLMSG_HDRLEN as i64 => n as usize,
            _ => return Err("rtnetlink recv failed"),
        };
        let mut off = 0;
        while off + NLMSG_HDRLEN <= n {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            if len < NLMSG_HDRLEN || off + len > n {
                return Err("malformed rtnetlink reply");
            }
            out.push(buf[off..off + len].to_vec());
            off += (len + 3) & !3;
        }
    }
    Err("rtnetlink reply stream did not drain")
}

fn msg_type(m: &[u8]) -> u16 {
    u16::from_ne_bytes([m[4], m[5]])
}

fn msg_seq(m: &[u8]) -> u32 {
    u32::from_ne_bytes(m[8..12].try_into().unwrap())
}

fn msg_pid(m: &[u8]) -> u32 {
    u32::from_ne_bytes(m[12..16].try_into().unwrap())
}

/// The attribute `kind` in `m` after a `fixed`-byte family header.
fn attr(m: &[u8], fixed: usize, kind: u16) -> Option<&[u8]> {
    let mut off = NLMSG_HDRLEN + fixed;
    while off + 4 <= m.len() {
        let len = u16::from_ne_bytes([m[off], m[off + 1]]) as usize;
        let k = u16::from_ne_bytes([m[off + 2], m[off + 3]]) & 0x3fff;
        if len < 4 || off + len > m.len() {
            return None;
        }
        if k == kind {
            return Some(&m[off + 4..off + len]);
        }
        off += (len + 3) & !3;
    }
    None
}

/// bubblewrap `rtnl_read_reply`: the request's one reply must be the
/// NLMSG_ERROR for its sequence number, addressed to the bound port id
/// `pid`. Returns `nlmsgerr.error`.
fn ack_error(replies: &[alloc::vec::Vec<u8>], seq: u32, pid: u32) -> Result<i32, &'static str> {
    let [ack] = replies else {
        return Err("a doit request was not answered by exactly one message");
    };
    expect(msg_type(ack) == NLMSG_ERROR, "the reply is not NLMSG_ERROR")?;
    expect(
        msg_seq(ack) == seq,
        "the ACK carries another sequence number",
    )?;
    expect(
        msg_pid(ack) == pid,
        "the ACK is not addressed to the bound port id",
    )?;
    Ok(i32::from_ne_bytes(ack[16..20].try_into().unwrap()))
}

/// A 16-byte `struct sockaddr_in`.
fn sockaddr_in(addr: [u8; 4], port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&addr);
    sa
}

/// RTM_GETLINK dump: `(ifindex, name, ifi_flags)` per link.
fn dump_links(
    fd: u64,
    seq: u32,
) -> Result<alloc::vec::Vec<(i32, alloc::string::String, u32)>, &'static str> {
    let replies = exchange(
        fd,
        &rtnl_request(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, seq, &[0u8; 16]),
    )?;
    let mut links = alloc::vec::Vec::new();
    for m in &replies {
        match msg_type(m) {
            RTM_NEWLINK => {
                let index = i32::from_ne_bytes(m[20..24].try_into().unwrap());
                let flags = u32::from_ne_bytes(m[24..28].try_into().unwrap());
                let name = attr(m, 16, IFLA_IFNAME).ok_or("RTM_NEWLINK without IFLA_IFNAME")?;
                let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
                links.push((
                    index,
                    alloc::string::String::from_utf8_lossy(&name[..end]).into_owned(),
                    flags,
                ));
            }
            NLMSG_DONE => return Ok(links),
            _ => return Err("RTM_GETLINK dump carried an unexpected message"),
        }
    }
    Err("RTM_GETLINK dump did not end with NLMSG_DONE")
}

/// One RTM_GETADDR dump entry: `(ifindex, prefixlen, address)`.
type AddrEntry = (u32, u8, alloc::vec::Vec<u8>);

/// RTM_GETADDR dump for `family`, one [`AddrEntry`] per entry.
fn dump_addrs(fd: u64, seq: u32, family: u8) -> Result<alloc::vec::Vec<AddrEntry>, &'static str> {
    let mut body = [0u8; 8];
    body[0] = family;
    let replies = exchange(
        fd,
        &rtnl_request(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, seq, &body),
    )?;
    let mut addrs = alloc::vec::Vec::new();
    for m in &replies {
        match msg_type(m) {
            RTM_NEWADDR => {
                let index = u32::from_ne_bytes(m[20..24].try_into().unwrap());
                let address = attr(m, 8, IFA_LOCAL)
                    .or_else(|| attr(m, 8, IFA_ADDRESS))
                    .ok_or("RTM_NEWADDR without an address")?;
                addrs.push((index, m[17], address.to_vec()));
            }
            NLMSG_DONE => return Ok(addrs),
            _ => return Err("RTM_GETADDR dump carried an unexpected message"),
        }
    }
    Err("RTM_GETADDR dump did not end with NLMSG_DONE")
}

/// A fresh network namespace has its own `lo`: ifindex 1, `IFF_LOOPBACK`
/// only (down, so neither IFF_UP nor IFF_RUNNING; a loopback device has no
/// IFF_MULTICAST), and no IPv4 address. SIOCGIFINDEX / SIOCGIFFLAGS /
/// SIOCGIFNAME and the RTM_GETLINK / RTM_GETADDR dumps all agree, and the
/// initial namespace's `lo` stays up.
fn smoke_abi_netns_lo_new_namespace_has_down_loopback() -> TestResult {
    with_setup(|| {
        narf_net::iface::register_loopback_iface();
        expect(
            sys(Syscall::Unshare, a0(CLONE_NEWNET)) == Some(0),
            "unshare(CLONE_NEWNET)",
        )?;
        // glibc `__opensock`: the first socket family that opens, AF_UNIX.
        let unix = open(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)?;
        expect(
            ifindex(unix, "lo") == Ok(1),
            "SIOCGIFINDEX(lo) in a new network namespace is not ifindex 1",
        )?;
        expect(
            ifflags(unix, "lo") == Ok(IFF_LOOPBACK),
            "a new network namespace's lo is not IFF_LOOPBACK and down",
        )?;
        expect(
            ifname(unix, 1).as_deref() == Ok("lo"),
            "SIOCGIFNAME(1) in a new network namespace is not lo",
        )?;
        let (route, _) = open_route()?;
        let links = dump_links(route, 1)?;
        expect(
            links.len() == 1 && links[0].0 == 1 && links[0].1 == "lo",
            "a new network namespace's RTM_GETLINK dump is not exactly lo at ifindex 1",
        )?;
        expect(
            links[0].2 & (IFF_UP | IFF_RUNNING) == 0 && links[0].2 & IFF_LOOPBACK != 0,
            "RTM_GETLINK reports a new network namespace's lo up",
        )?;
        expect(
            dump_addrs(route, 2, RTNL_AF_INET)?.is_empty(),
            "a new network namespace's lo has an IPv4 address before it is configured",
        )?;
        expect(
            narf_net::iface::lookup_in(0, "lo").is_some_and(|lo| lo.link_up),
            "the initial namespace's lo went down",
        )?;
        close(route);
        close(unix);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/netns-lo",
    smoke_abi_netns_lo_new_namespace_has_down_loopback
);

/// bubblewrap `loopback_setup` (`network.c`) in a namespace made by
/// unshare(CLONE_NEWNET): `if_nametoindex("lo")`, RTM_NEWADDR 127.0.0.1/8
/// (IFA_F_PERMANENT, RT_SCOPE_HOST, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)
/// and RTM_NEWLINK IFF_UP (NLM_F_ACK), each ACKed with 0 to the port id the
/// socket bound. Both act on that namespace's `lo`: `inet_rtm_newaddr`
/// finds no matching address there, and NETDEV_UP's own 127.0.0.1/8
/// (`inetdev_event`) is the same address, not a second one. The device stays
/// configured across SIOCSIFFLAGS down/up (IPv4 addresses survive
/// NETDEV_DOWN), the initial namespace's `lo` is untouched, and a UDP
/// datagram to 127.0.0.1 is delivered inside the namespace.
fn smoke_abi_netns_lo_bwrap_loopback_setup() -> TestResult {
    with_setup(|| {
        narf_net::iface::register_loopback_iface();
        let initial_lo_addrs = narf_net::iface::get_addrs("lo");
        expect(
            sys(Syscall::Unshare, a0(CLONE_NEWNET)) == Some(0),
            "unshare(CLONE_NEWNET)",
        )?;
        let unix = open(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)?;
        let lo = ifindex(unix, "lo").map_err(|_| "loopback: Failed to look up lo")?;
        let (route, pid) = open_route()?;

        let mut addr = alloc::vec![RTNL_AF_INET, 8, IFA_F_PERMANENT, RT_SCOPE_HOST];
        addr.extend_from_slice(&(lo as u32).to_ne_bytes());
        push_attr(&mut addr, IFA_LOCAL, &LOOPBACK);
        push_attr(&mut addr, IFA_ADDRESS, &LOOPBACK);
        let flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
        let replies = exchange(route, &rtnl_request(RTM_NEWADDR, flags, 10, &addr))?;
        expect(
            ack_error(&replies, 10, pid)? == 0,
            "loopback: Failed RTM_NEWADDR",
        )?;

        let mut link = alloc::vec![RTNL_AF_UNSPEC, 0, 0, 0];
        link.extend_from_slice(&lo.to_ne_bytes());
        link.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_flags
        link.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_change
        let replies = exchange(
            route,
            &rtnl_request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 11, &link),
        )?;
        expect(
            ack_error(&replies, 11, pid)? == 0,
            "loopback: Failed RTM_NEWLINK",
        )?;
        expect(
            ifflags(unix, "lo") == Ok(IFF_LOOPBACK | IFF_UP | IFF_RUNNING),
            "lo is not up and running after RTM_NEWLINK IFF_UP",
        )?;
        let addrs = dump_addrs(route, 12, RTNL_AF_INET)?;
        expect(
            addrs.len() == 1 && addrs[0] == (1, 8, LOOPBACK.to_vec()),
            "lo does not hold exactly 127.0.0.1/8 after loopback_setup",
        )?;
        // Now the address exists: `inet_rtm_newaddr` with NLM_F_EXCL is EEXIST.
        let replies = exchange(route, &rtnl_request(RTM_NEWADDR, flags, 13, &addr))?;
        expect(
            i64::from(ack_error(&replies, 13, pid)?) == EEXIST,
            "a second exclusive RTM_NEWADDR 127.0.0.1/8 was not EEXIST",
        )?;

        // `dev_change_flags` through SIOCSIFFLAGS reaches the same device.
        expect(
            set_ifflags(unix, "lo", 0) == Some(0),
            "SIOCSIFFLAGS(lo, 0) failed",
        )?;
        expect(
            ifflags(unix, "lo") == Ok(IFF_LOOPBACK),
            "SIOCSIFFLAGS did not take the namespace's lo down",
        )?;
        expect(
            narf_net::iface::lookup_in(0, "lo").is_some_and(|lo| lo.link_up),
            "taking a namespace's lo down took the initial namespace's lo down",
        )?;
        expect(
            dump_addrs(route, 14, RTNL_AF_INET)? == addrs,
            "lo lost 127.0.0.1/8 going down",
        )?;
        expect(
            set_ifflags(unix, "lo", IFF_UP) == Some(0),
            "SIOCSIFFLAGS(lo, IFF_UP) failed",
        )?;
        expect(
            ifflags(unix, "lo") == Ok(IFF_LOOPBACK | IFF_UP | IFF_RUNNING),
            "SIOCSIFFLAGS did not bring the namespace's lo back up",
        )?;
        expect(
            narf_net::iface::get_addrs("lo") == initial_lo_addrs,
            "the namespace's lo configuration changed the initial namespace's lo",
        )?;

        // A UDP datagram over 127.0.0.1 stays inside the namespace.
        let rx = open(AF_INET, SOCK_DGRAM, 0)?;
        let to = sockaddr_in(LOOPBACK, 47011);
        expect(
            sys(Syscall::SocketBind, a2(rx, to.as_ptr() as u64, 16)) == Some(0),
            "bind(127.0.0.1:47011) in the namespace",
        )?;
        let tx = open(AF_INET, SOCK_DGRAM, 0)?;
        let payload = b"netns-lo";
        let send = SyscallArgs {
            arg0: tx,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            arg3: 0,
            arg4: to.as_ptr() as u64,
            arg5: 16,
        };
        expect(
            sys(Syscall::SocketSend, send) == Some(payload.len() as i64),
            "sendto(127.0.0.1:47011) in the namespace",
        )?;
        let mut buf = [0u8; 32];
        expect(
            sys(
                Syscall::SocketRecv,
                a3(rx, buf.as_mut_ptr() as u64, buf.len() as u64, MSG_DONTWAIT),
            ) == Some(payload.len() as i64)
                && &buf[..payload.len()] == payload,
            "the datagram to 127.0.0.1 was not delivered inside the namespace",
        )?;
        for fd in [tx, rx, route, unix] {
            close(fd);
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/netns-lo",
    smoke_abi_netns_lo_bwrap_loopback_setup
);
