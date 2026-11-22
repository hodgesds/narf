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
const AF_NETLINK: u64 = 16;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_CLOEXEC: u64 = 0o2000000;
const NETLINK_ROUTE: u64 = 0;
const MSG_DONTWAIT: u64 = 0x40;
const CLONE_NEWNET: u64 = 0x4000_0000;

const SIOCGIFNAME: u64 = 0x8910;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCGIFINDEX: u64 = 0x8933;

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLMSG_DONE: u16 = 3;
const NLMSG_HDRLEN: usize = 16;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTNL_AF_INET: u8 = 2;


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
