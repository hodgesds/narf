//! Linux syscall ABI conformance — AF_PACKET sockets.
//!
//! Every case pins behaviour of `net/packet/af_packet.c` (named per case):
//! creation and its capability check, `sockaddr_ll` binding, receive and
//! transmit through real devices (`lo` and a capture NIC registered by the
//! test), `PACKET_AUXDATA` / timestamp control messages, classic BPF
//! filters, `SOL_PACKET` options, readiness, and the exact call sequences
//! the DHCP clients NetworkManager (n-dhcp4), systemd-networkd
//! (sd-dhcp-client) and dhcpcd issue.
use crate::abi_test_support::*;

use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

const AF_INET: u64 = 2;
const AF_PACKET: u64 = 17;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_SEQPACKET: u64 = 5;
const SOCK_PACKET: u64 = 10;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;
const SOL_SOCKET: u64 = 1;
const SOL_PACKET: u64 = 263;
const IPPROTO_IP: u64 = 0;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_RCVBUF: u64 = 8;
const SO_PRIORITY: u64 = 12;
const SO_ATTACH_FILTER: u64 = 26;
const SO_DETACH_FILTER: u64 = 27;
const SO_TIMESTAMP_OLD: u64 = 29;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const SO_LOCK_FILTER: u64 = 44;
const SO_BINDTOIFINDEX: u64 = 62;
const PACKET_ADD_MEMBERSHIP: u64 = 1;
const PACKET_DROP_MEMBERSHIP: u64 = 2;
const PACKET_RX_RING: u64 = 5;
const PACKET_STATISTICS: u64 = 6;
const PACKET_AUXDATA: u64 = 8;
const PACKET_VERSION: u64 = 10;
const PACKET_HDRLEN: u64 = 11;
const PACKET_TX_RING: u64 = 13;
const PACKET_VNET_HDR: u64 = 15;
const PACKET_FANOUT: u64 = 18;
const PACKET_QDISC_BYPASS: u64 = 20;
const PACKET_IGNORE_OUTGOING: u64 = 23;
const PACKET_MR_MULTICAST: u16 = 0;
const PACKET_MR_PROMISC: u16 = 1;
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_8021Q: u16 = 0x8100;
/// IEEE 802 "local experimental" ethertype: nothing else in the kernel
/// produces or consumes it, so these frames are unambiguous.
const ETH_P_TEST: u16 = 0x88b5;
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const PACKET_HOST: u8 = 0;
const PACKET_BROADCAST: u8 = 1;
const PACKET_MULTICAST: u8 = 2;
const PACKET_OTHERHOST: u8 = 3;
const PACKET_OUTGOING: u8 = 4;
const TP_STATUS_USER: u32 = 1;
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_CTRUNC: u32 = 0x8;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_ERRQUEUE: u64 = 0x2000;
const MSG_NOSIGNAL: u64 = 0x4000;
const FIONREAD: u64 = 0x541B;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCGIFINDEX: u64 = 0x8933;
const SIOCGIFHWADDR: u64 = 0x8927;
const EPOLLIN: u32 = 0x1;
const EPOLLOUT: u32 = 0x4;
const EPOLLERR: u32 = 0x8;
const EPOLLET: u32 = 1 << 31;
const LO_IFINDEX: i32 = 1;

/// The capture NIC every device-level case uses.
const NIC: &str = "pkttest0";
const NIC_MAC: [u8; 6] = [0x02, 0x50, 0x4b, 0x54, 0x00, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0x50, 0x4b, 0x54, 0x00, 0x02];

// ── harness ────────────────────────────────────────────────────────────────

fn sys(n: Syscall, args: SyscallArgs) -> Option<i64> {
    call(n.raw(), args)
}

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

fn socket(domain: u64, kind: u64, proto: u64) -> Option<i64> {
    sys(Syscall::SocketOpen, a2(domain, kind, proto))
}

fn open(domain: u64, kind: u64, proto: u64) -> Result<u64, &'static str> {
    match socket(domain, kind, proto) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("socket(AF_PACKET) failed"),
    }
}

/// `socket(AF_PACKET, kind, htons(proto))`.
fn open_packet(kind: u64, proto: u16) -> Result<u64, &'static str> {
    open(AF_PACKET, kind, u64::from(proto.to_be()))
}

fn close(fd: u64) {
    let _ = sys(Syscall::Close, a0(fd));
}

/// A 20-byte `struct sockaddr_ll`.
fn sll(proto: u16, ifindex: i32, hatype: u16, halen: u8, addr: &[u8]) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&proto.to_be_bytes());
    b[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    b[8..10].copy_from_slice(&hatype.to_ne_bytes());
    b[11] = halen;
    b[12..12 + addr.len()].copy_from_slice(addr);
    b
}

fn bind(fd: u64, addr: &[u8]) -> Option<i64> {
    sys(
        Syscall::SocketBind,
        a2(fd, addr.as_ptr() as u64, addr.len() as u64),
    )
}

fn bind_ll(fd: u64, proto: u16, ifindex: i32) -> Result<(), &'static str> {
    if bind(fd, &sll(proto, ifindex, 0, 0, &[])) != Some(0) {
        return Err("bind(sockaddr_ll) failed");
    }
    Ok(())
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

fn get_int(fd: u64, level: u64, name: u64) -> Result<i32, &'static str> {
    let mut out = [0u8; 4];
    match getsockopt(fd, level, name, &mut out) {
        (Some(0), 4) => Ok(i32::from_ne_bytes(out)),
        _ => Err("getsockopt(int) failed"),
    }
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

fn send(fd: u64, buf: &[u8]) -> Option<i64> {
    sys(
        Syscall::SocketSend,
        a3(fd, buf.as_ptr() as u64, buf.len() as u64, 0),
    )
}

/// recvfrom; returns (result, address bytes, reported address length).
fn recvfrom(fd: u64, buf: &mut [u8], flags: u64) -> (Option<i64>, [u8; 32], u32) {
    let mut from = [0xAAu8; 32];
    let mut len: u32 = 32;
    let r = sys(
        Syscall::SocketRecv,
        a5(
            fd,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            flags,
            from.as_mut_ptr() as u64,
            &mut len as *mut u32 as u64,
        ),
    );
    (r, from, len)
}

/// Result of one recvmsg.
struct Msg {
    ret: Option<i64>,
    flags: u32,
    controllen: u64,
    name: [u8; 32],
    namelen: u32,
}

/// recvmsg over `iovs` with a `control` buffer of the given length.
fn recvmsg(fd: u64, iovs: &mut [&mut [u8]], control: &mut [u8], flags: u64) -> Msg {
    let mut name = [0u8; 32];
    let mut iov = alloc::vec![0u8; iovs.len() * 16];
    for (i, b) in iovs.iter_mut().enumerate() {
        iov[i * 16..i * 16 + 8].copy_from_slice(&(b.as_mut_ptr() as u64).to_ne_bytes());
        iov[i * 16 + 8..i * 16 + 16].copy_from_slice(&(b.len() as u64).to_ne_bytes());
    }
    let mut hdr = [0u8; 56];
    hdr[0..8].copy_from_slice(&(name.as_mut_ptr() as u64).to_ne_bytes());
    hdr[8..12].copy_from_slice(&32u32.to_ne_bytes());
    hdr[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
    hdr[24..32].copy_from_slice(&(iovs.len() as u64).to_ne_bytes());
    let ctrl_ptr = if control.is_empty() {
        0
    } else {
        control.as_mut_ptr() as u64
    };
    hdr[32..40].copy_from_slice(&ctrl_ptr.to_ne_bytes());
    hdr[40..48].copy_from_slice(&(control.len() as u64).to_ne_bytes());
    hdr[48..52].copy_from_slice(&0xffff_ffffu32.to_ne_bytes());
    let ret = sys(
        Syscall::SocketRecvMsg,
        a2(fd, hdr.as_mut_ptr() as u64, flags),
    );
    Msg {
        ret,
        flags: u32::from_ne_bytes(hdr[48..52].try_into().unwrap()),
        controllen: u64::from_ne_bytes(hdr[40..48].try_into().unwrap()),
        name,
        namelen: u32::from_ne_bytes(hdr[8..12].try_into().unwrap()),
    }
}

/// sendmsg of `iovs` to an optional address.
fn sendmsg(fd: u64, iovs: &[&[u8]], name: Option<&[u8]>, flags: u64) -> Option<i64> {
    let mut iov = alloc::vec![0u8; iovs.len() * 16];
    for (i, b) in iovs.iter().enumerate() {
        iov[i * 16..i * 16 + 8].copy_from_slice(&(b.as_ptr() as u64).to_ne_bytes());
        iov[i * 16 + 8..i * 16 + 16].copy_from_slice(&(b.len() as u64).to_ne_bytes());
    }
    let mut hdr = [0u8; 56];
    if let Some(n) = name {
        hdr[0..8].copy_from_slice(&(n.as_ptr() as u64).to_ne_bytes());
        hdr[8..12].copy_from_slice(&(n.len() as u32).to_ne_bytes());
    }
    hdr[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
    hdr[24..32].copy_from_slice(&(iovs.len() as u64).to_ne_bytes());
    sys(Syscall::SocketSendMsg, a2(fd, hdr.as_ptr() as u64, flags))
}

/// The cmsgs in a control buffer: (level, type, data).
fn cmsgs(control: &[u8], controllen: u64) -> alloc::vec::Vec<(i32, i32, alloc::vec::Vec<u8>)> {
    let mut out = alloc::vec::Vec::new();
    let end = (controllen as usize).min(control.len());
    let mut off = 0usize;
    while off + 16 <= end {
        let len = u64::from_ne_bytes(control[off..off + 8].try_into().unwrap()) as usize;
        if len < 16 || off + len > end {
            break;
        }
        let level = i32::from_ne_bytes(control[off + 8..off + 12].try_into().unwrap());
        let kind = i32::from_ne_bytes(control[off + 12..off + 16].try_into().unwrap());
        out.push((level, kind, control[off + 16..off + len].to_vec()));
        off += (len + 7) & !7;
    }
    out
}

/// A decoded `struct tpacket_auxdata`.
#[derive(Debug, PartialEq, Eq)]
struct Aux {
    status: u32,
    len: u32,
    snaplen: u32,
    mac: u16,
    net: u16,
    vlan_tci: u16,
    vlan_tpid: u16,
}

fn aux_of(data: &[u8]) -> Option<Aux> {
    if data.len() != 20 {
        return None;
    }
    let u32_at = |o: usize| u32::from_ne_bytes(data[o..o + 4].try_into().unwrap());
    let u16_at = |o: usize| u16::from_ne_bytes(data[o..o + 2].try_into().unwrap());
    Some(Aux {
        status: u32_at(0),
        len: u32_at(4),
        snaplen: u32_at(8),
        mac: u16_at(12),
        net: u16_at(14),
        vlan_tci: u16_at(16),
        vlan_tpid: u16_at(18),
    })
}

/// The `sockaddr_ll` fields a receive reports.
#[derive(Debug, PartialEq, Eq)]
struct Sll {
    family: u16,
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [u8; 8],
}

fn sll_of(b: &[u8]) -> Sll {
    Sll {
        family: u16::from_ne_bytes([b[0], b[1]]),
        protocol: u16::from_be_bytes([b[2], b[3]]),
        ifindex: i32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        hatype: u16::from_ne_bytes([b[8], b[9]]),
        pkttype: b[10],
        halen: b[11],
        addr: b[12..20].try_into().unwrap(),
    }
}

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> alloc::vec::Vec<u8> {
    let mut f = alloc::vec::Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Frames the capture NIC's driver was asked to transmit.
static CAPTURED: IrqSafeSpinLock<alloc::vec::Vec<alloc::vec::Vec<u8>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());
static REJECT_SEND: AtomicBool = AtomicBool::new(false);

fn capture_send(frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    CAPTURED.lock().push(frame.to_vec());
    if REJECT_SEND.load(Ordering::Acquire) {
        Err(())
    } else {
        Ok(())
    }
}

/// Register (or re-register) the capture NIC, set its link state, and
/// return its ifindex.
fn nic(up: bool) -> Result<i32, &'static str> {
    let name = narf_net::iface::register(NIC, NIC_MAC, capture_send);
    narf_net::iface::set_link_state(&name, up);
    CAPTURED.lock().clear();
    narf_net::iface::ifindex_of(&name)
        .map(|i| i as i32)
        .ok_or("capture NIC has no ifindex")
}

fn nic_down() {
    narf_net::iface::set_link_state(NIC, false);
}

/// Hand `frame` to the stack as if the capture NIC received it.
fn inject(frame: &[u8]) {
    let mut f = frame.to_vec();
    narf_net::tcp_stack::rx_handler(NIC, &mut f);
}

fn captured() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    core::mem::take(&mut *CAPTURED.lock())
}

fn lo() {
    narf_net::iface::register_loopback_iface();
}

/// Receive (MSG_DONTWAIT) until a frame carrying `marker` arrives, skipping
/// unrelated traffic; returns the bytes and the source address.
fn recv_marked(fd: u64, marker: &[u8]) -> Result<(alloc::vec::Vec<u8>, Sll, u32), &'static str> {
    for _ in 0..64 {
        let mut buf = [0u8; 2048];
        let (r, from, len) = recvfrom(fd, &mut buf, MSG_DONTWAIT);
        let n = match r {
            Some(n) if n >= 0 => n as usize,
            _ => return Err("expected frame was not received"),
        };
        let data = &buf[..n.min(buf.len())];
        if data.windows(marker.len()).any(|w| w == marker) {
            return Ok((data.to_vec(), sll_of(&from), len));
        }
    }
    Err("expected frame was not received")
}

/// No frame carrying `marker` is queued.
fn none_marked(fd: u64, marker: &[u8]) -> Result<(), &'static str> {
    for _ in 0..64 {
        let mut buf = [0u8; 2048];
        let (r, _, _) = recvfrom(fd, &mut buf, MSG_DONTWAIT);
        let n = match r {
            Some(n) if n >= 0 => n as usize,
            _ => return Ok(()),
        };
        if buf[..n.min(buf.len())]
            .windows(marker.len())
            .any(|w| w == marker)
        {
            return Err("an unexpected frame was received");
        }
    }
    Ok(())
}

/// Discard whatever is queued (frames that arrived before a bind or filter
/// took effect — the window dhcpcd's `bpf_open` comment describes).
fn drain(fd: u64) {
    let mut buf = [0u8; 2048];
    for _ in 0..256 {
        if recvfrom(fd, &mut buf, MSG_DONTWAIT).0.is_none_or(|r| r < 0) {
            return;
        }
    }
}

fn expect(cond: bool, msg: &'static str) -> Result<(), &'static str> {
    if cond {
        Ok(())
    } else {
        Err(msg)
    }
}

/// classic BPF instruction.
const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> [u8; 8] {
    let c = code.to_ne_bytes();
    let k = k.to_ne_bytes();
    [c[0], c[1], jt, jf, k[0], k[1], k[2], k[3]]
}

fn attach(fd: u64, prog: &[[u8; 8]]) -> Option<i64> {
    let image: alloc::vec::Vec<u8> = prog.iter().flatten().copied().collect();
    let mut fprog = [0u8; 16];
    fprog[0..2].copy_from_slice(&(prog.len() as u16).to_ne_bytes());
    fprog[8..16].copy_from_slice(&(image.as_ptr() as u64).to_ne_bytes());
    setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog)
}

/// An IPv4/UDP datagram carrying a BOOTREPLY (`op = 2`) with `xid`.
fn dhcp_reply(dst_port: u16, op: u8, xid: u32) -> alloc::vec::Vec<u8> {
    let mut bootp = alloc::vec![0u8; 244];
    bootp[0] = op;
    bootp[1] = 1; // htype ethernet
    bootp[2] = 6; // hlen
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    bootp[28..34].copy_from_slice(&NIC_MAC); // chaddr
    bootp[236..240].copy_from_slice(&0x6382_5363u32.to_be_bytes());
    bootp[240..244].copy_from_slice(&[53, 1, 2, 255]); // DHCPOFFER, end
    let udp_len = 8 + bootp.len();
    let mut ip = alloc::vec![0u8; 20 + udp_len];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 0, 2, 2]);
    ip[16..20].copy_from_slice(&[255, 255, 255, 255]);
    ip[20..22].copy_from_slice(&67u16.to_be_bytes());
    ip[22..24].copy_from_slice(&dst_port.to_be_bytes());
    ip[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    ip[28..].copy_from_slice(&bootp);
    ip
}

/// NetworkManager's internal DHCPv4 client (n-dhcp4,
/// `n_dhcp4_c_socket_packet_new`): the filter for a SOCK_DGRAM packet
/// socket, whose offsets start at the IP header.
fn n_dhcp4_filter() -> alloc::vec::Vec<[u8; 8]> {
    alloc::vec![
        insn(0x30, 0, 0, 9),  // A <- ip.protocol
        insn(0x15, 1, 0, 17), // UDP ?
        insn(0x06, 0, 0, 0),
        insn(0x28, 0, 0, 6),      // A <- ip.frag_off
        insn(0x54, 0, 0, 0x3fff), // IP_MF | IP_OFFMASK
        insn(0x15, 1, 0, 0),
        insn(0x06, 0, 0, 0),
        insn(0xb1, 0, 0, 0),       // X <- ihl * 4
        insn(0x80, 0, 0, 0),       // A <- len
        insn(0x1c, 0, 0, 0),       // A -= X
        insn(0x35, 1, 0, 8 + 240), // >= udphdr + NDhcp4Message ?
        insn(0x06, 0, 0, 0),
        insn(0x48, 0, 0, 2), // A <- udp.dest
        insn(0x15, 1, 0, 68),
        insn(0x06, 0, 0, 0),
        insn(0x00, 0, 0, 8), // A <- sizeof(udphdr)
        insn(0x0c, 0, 0, 0), // A += X
        insn(0x07, 0, 0, 0), // X <- A
        insn(0x50, 0, 0, 0), // A <- op
        insn(0x15, 1, 0, 2), // BOOTREPLY ?
        insn(0x06, 0, 0, 0),
        insn(0x40, 0, 0, 236), // A <- magic
        insn(0x15, 1, 0, 0x6382_5363),
        insn(0x06, 0, 0, 0),
        insn(0x06, 0, 0, 65535),
    ]
}

/// dhcpcd's style for a SOCK_RAW ETH_P_ALL socket: Ethernet-relative
/// offsets, checked with the `SKF_AD_PROTOCOL` ancillary load first.
fn dhcpcd_style_filter() -> alloc::vec::Vec<[u8; 8]> {
    alloc::vec![
        insn(0x28, 0, 0, 0xffff_f000), // A <- skb->protocol
        insn(0x15, 1, 0, 0x0800),
        insn(0x06, 0, 0, 0),
        insn(0x30, 0, 0, 14 + 9), // A <- ip.protocol
        insn(0x15, 1, 0, 17),
        insn(0x06, 0, 0, 0),
        insn(0xb1, 0, 0, 14),     // X <- ihl * 4
        insn(0x48, 0, 0, 14 + 2), // A <- udp.dest
        insn(0x15, 1, 0, 68),
        insn(0x06, 0, 0, 0),
        insn(0x06, 0, 0, 0x7fff_ffff), // BPF_WHOLEPACKET
    ]
}

// ───────────────────────────── socket(2) ─────────────────────────────

/// `packet_create`: SOCK_RAW, SOCK_DGRAM and SOCK_PACKET are accepted (with
/// SOCK_CLOEXEC / SOCK_NONBLOCK); anything else is ESOCKTNOSUPPORT;
/// `sk_protocol` is never set, so SO_PROTOCOL reads 0. `__sock_create`
/// turns PF_INET + SOCK_PACKET into PF_PACKET.
fn smoke_abi_packet_socket_create_types() -> TestResult {
    with_setup(|| {
        let dgram = open(
            AF_PACKET,
            SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
            u64::from(ETH_P_IP.to_be()),
        )?;
        expect(get_int(dgram, SOL_SOCKET, SO_DOMAIN)? == 17, "SO_DOMAIN")?;
        expect(get_int(dgram, SOL_SOCKET, SO_TYPE)? == 2, "SO_TYPE dgram")?;
        expect(
            get_int(dgram, SOL_SOCKET, SO_PROTOCOL)? == 0,
            "SO_PROTOCOL is 0",
        )?;
        let raw = open_packet(SOCK_RAW, ETH_P_ALL)?;
        expect(get_int(raw, SOL_SOCKET, SO_TYPE)? == 3, "SO_TYPE raw")?;
        let spkt = open_packet(SOCK_PACKET, ETH_P_ALL)?;
        expect(get_int(spkt, SOL_SOCKET, SO_TYPE)? == 10, "SO_TYPE packet")?;
        let inet_spkt = open(AF_INET, SOCK_PACKET, 0)?;
        expect(
            get_int(inet_spkt, SOL_SOCKET, SO_DOMAIN)? == 17,
            "PF_INET/SOCK_PACKET is created as PF_PACKET",
        )?;
        for kind in [SOCK_STREAM, SOCK_SEQPACKET] {
            expect(
                socket(AF_PACKET, kind, 0) == Some(ESOCKTNOSUPPORT),
                "a stream/seqpacket packet socket must be ESOCKTNOSUPPORT",
            )?;
        }
        // The protocol is an opaque be16: any value is accepted.
        let odd = open(AF_PACKET, SOCK_DGRAM, 0x1_2345)?;
        let mut sv = [0u8; 8];
        expect(
            sys(
                Syscall::SocketPair,
                a3(AF_PACKET, SOCK_DGRAM, 0, sv.as_mut_ptr() as u64),
            ) == Some(EOPNOTSUPP),
            "socketpair(AF_PACKET) must be EOPNOTSUPP (sock_no_socketpair)",
        )?;
        for fd in [dgram, raw, spkt, inet_spkt, odd] {
            close(fd);
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_socket_create_types);

/// `packet_create`: `ns_capable(net->user_ns, CAP_NET_RAW)` is checked
/// FIRST — before the type — so an unprivileged caller gets EPERM even for a
/// bad type; socketpair inherits it.
fn smoke_abi_packet_socket_needs_cap_net_raw() -> TestResult {
    with_setup(|| {
        #[cfg(feature = "container")]
        const CLONE_NEWUSER: u64 = 0x1000_0000;
        #[cfg(feature = "container")]
        const CLONE_NEWNET: u64 = 0x4000_0000;
        drop_to_unprivileged_uid()?;
        expect(
            socket(AF_PACKET, SOCK_RAW, u64::from(ETH_P_ALL.to_be())) == Some(EPERM),
            "an unprivileged packet socket must be EPERM",
        )?;
        expect(
            socket(AF_PACKET, SOCK_STREAM, 0) == Some(EPERM),
            "the CAP_NET_RAW check precedes the type check",
        )?;
        expect(
            socket(AF_INET, SOCK_PACKET, 0) == Some(EPERM),
            "PF_INET/SOCK_PACKET reaches packet_create's EPERM",
        )?;
        let mut sv = [0u8; 8];
        expect(
            sys(
                Syscall::SocketPair,
                a3(AF_PACKET, SOCK_DGRAM, 0, sv.as_mut_ptr() as u64),
            ) == Some(EPERM),
            "socketpair(AF_PACKET) creates first: EPERM",
        )?;
        // Namespace ownership exists only in `--features container` builds.
        // The default kernel still accepts CLONE_NEWUSER as a compatibility
        // no-op, but deliberately cannot use it to mint namespace-scoped
        // capabilities, so keep this half of the regression in the build
        // that actually implements user/network namespaces.
        #[cfg(feature = "container")]
        {
            expect(
                sys(Syscall::Unshare, a0(CLONE_NEWUSER)) == Some(0),
                "unshare(CLONE_NEWUSER)",
            )?;
            expect(
                socket(AF_PACKET, SOCK_RAW, 0) == Some(EPERM),
                "CAP_NET_RAW in a child user namespace does not govern the initial net namespace",
            )?;
            expect(
                sys(Syscall::Unshare, a0(CLONE_NEWNET)) == Some(0),
                "unshare(CLONE_NEWNET)",
            )?;
            let fd = open(AF_PACKET, SOCK_RAW, 0)?;
            close(fd);
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_socket_needs_cap_net_raw
);

// ───────────────────────────── bind / getsockname ─────────────────────

/// `packet_bind` / `packet_do_bind`: addrlen < sizeof(sockaddr_ll) and a
/// family other than AF_PACKET are EINVAL; an unknown ifindex is ENODEV;
/// ifindex 0 binds to every device. `packet_getname` reports the bound
/// device's type and address (`offsetof(sll_addr) + halen` bytes);
/// getpeername is EOPNOTSUPP.
fn smoke_abi_packet_bind_and_getname() -> TestResult {
    with_setup(|| {
        lo();
        let fd = open_packet(SOCK_DGRAM, ETH_P_IP)?;
        let good = sll(ETH_P_IP, LO_IFINDEX, 0, 0, &[]);
        expect(
            bind(fd, &good[..19]) == Some(EINVAL),
            "short sockaddr_ll is EINVAL",
        )?;
        let mut wrong = good;
        wrong[0..2].copy_from_slice(&2u16.to_ne_bytes());
        expect(
            bind(fd, &wrong) == Some(EINVAL),
            "a non-AF_PACKET family is EINVAL",
        )?;
        expect(
            bind(fd, &sll(ETH_P_IP, 0x7fff_0000, 0, 0, &[])) == Some(ENODEV),
            "an unknown ifindex is ENODEV",
        )?;
        expect(
            bind(fd, &sll(ETH_P_IP, -5, 0, 0, &[])) == Some(ENODEV),
            "a negative ifindex is ENODEV",
        )?;
        expect(bind(fd, &good) == Some(0), "binding to lo succeeds")?;
        let mut name = [0u8; 32];
        let mut len: u32 = 32;
        expect(
            sys(
                Syscall::SocketGetSockName,
                a2(fd, name.as_mut_ptr() as u64, &mut len as *mut u32 as u64),
            ) == Some(0),
            "getsockname",
        )?;
        expect(
            len == 18,
            "packet_getname returns offsetof(sll_addr) + halen",
        )?;
        let got = sll_of(&name);
        expect(got.family == 17, "sll_family")?;
        expect(
            got.protocol == ETH_P_IP,
            "sll_protocol is the bound protocol",
        )?;
        expect(got.ifindex == LO_IFINDEX, "sll_ifindex")?;
        expect(got.hatype == ARPHRD_LOOPBACK, "lo is ARPHRD_LOOPBACK")?;
        expect(
            got.pkttype == 0 && got.halen == 6,
            "pkttype 0, halen = addr_len",
        )?;
        // Protocol 0 keeps the current protocol; ifindex 0 unbinds the device.
        expect(
            bind(fd, &sll(0, 0, 0, 0, &[])) == Some(0),
            "rebind to all devices",
        )?;
        len = 32;
        let _ = sys(
            Syscall::SocketGetSockName,
            a2(fd, name.as_mut_ptr() as u64, &mut len as *mut u32 as u64),
        );
        let got = sll_of(&name);
        expect(
            len == 12 && got.ifindex == 0 && got.protocol == ETH_P_IP && got.hatype == 0,
            "an unbound socket reports ifindex 0, its protocol, no address",
        )?;
        let mut peer = [0u8; 32];
        let mut plen: u32 = 32;
        expect(
            sys(
                Syscall::SocketGetPeerName,
                a2(fd, peer.as_mut_ptr() as u64, &mut plen as *mut u32 as u64),
            ) == Some(EOPNOTSUPP),
            "getpeername is EOPNOTSUPP",
        )?;
        close(fd);
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_bind_and_getname);

/// The `sock_no_*` proto_ops: connect, listen, accept and shutdown are all
/// EOPNOTSUPP on a packet socket.
fn smoke_abi_packet_unsupported_ops() -> TestResult {
    with_setup(|| {
        let fd = open_packet(SOCK_RAW, ETH_P_ALL)?;
        let addr = sll(ETH_P_ALL, LO_IFINDEX, 0, 0, &[]);
        expect(
            sys(
                Syscall::SocketConnect,
                a2(fd, addr.as_ptr() as u64, addr.len() as u64),
            ) == Some(EOPNOTSUPP),
            "connect is EOPNOTSUPP",
        )?;
        expect(
            sys(Syscall::SocketListen, a1(fd, 4)) == Some(EOPNOTSUPP),
            "listen is EOPNOTSUPP",
        )?;
        expect(
            sys(Syscall::SocketAccept, a2(fd, 0, 0)) == Some(EOPNOTSUPP),
            "accept is EOPNOTSUPP",
        )?;
        expect(
            sys(Syscall::SocketShutdown, a1(fd, 2)) == Some(EOPNOTSUPP),
            "shutdown is EOPNOTSUPP",
        )?;
        close(fd);
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_unsupported_ops);

/// `packet_do_bind` to a device that is down returns 0 but leaves the hook
/// unregistered and sets `sk_err = ENETDOWN`: SO_ERROR and the first recv
/// report it (once), poll reports EPOLLERR. `packet_notifier` NETDEV_UP then
/// registers the hook and frames flow; NETDEV_DOWN unhooks again with
/// ENETDOWN.
fn smoke_abi_packet_bind_down_device_and_notifier() -> TestResult {
    with_setup(|| {
        let ifindex = nic(false)?;
        // Protocol 0: no hook until bind, so nothing can be queued early.
        let fd = open(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0)?;
        expect(
            bind(fd, &sll(ETH_P_ALL, ifindex, 0, 0, &[])) == Some(0),
            "bind to a down device",
        )?;
        let mut buf = [0u8; 64];
        expect(
            recvfrom(fd, &mut buf, 0).0 == Some(ENETDOWN),
            "the first recv reports sk_err = ENETDOWN",
        )?;
        expect(
            recvfrom(fd, &mut buf, 0).0 == Some(EAGAIN),
            "sock_error clears sk_err",
        )?;
        narf_net::iface::set_link_state(NIC, true);
        let marker = b"notifier-up";
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_TEST, marker));
        let (_, from, _) = recv_marked(fd, marker)?;
        expect(from.ifindex == ifindex, "NETDEV_UP registered the hook")?;
        narf_net::iface::set_link_state(NIC, false);
        expect(
            get_int(fd, SOL_SOCKET, SO_ERROR)? == 100,
            "NETDEV_DOWN sets sk_err = ENETDOWN, read by SO_ERROR",
        )?;
        expect(
            get_int(fd, SOL_SOCKET, SO_ERROR)? == 0,
            "SO_ERROR clears it",
        )?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_bind_down_device_and_notifier
);

// ───────────────────────────── receive ─────────────────────────────

/// `packet_rcv` + `dev_queue_xmit_nit` on `lo`: an ETH_P_ALL SOCK_RAW
/// listener sees a frame sent on lo twice — first as PACKET_OUTGOING (the
/// transmit tap), then as PACKET_HOST (the loopback receive) — with the
/// whole frame, `sll_hatype = ARPHRD_LOOPBACK`, the source MAC in
/// `sll_addr`, and a 20-byte address. The sending socket itself never sees
/// its own transmit (`skb_loop_sk`), only the receive.
fn smoke_abi_packet_raw_lo_outgoing_and_host() -> TestResult {
    with_setup(|| {
        lo();
        let rx = open_packet(SOCK_RAW, ETH_P_ALL)?;
        bind_ll(rx, ETH_P_ALL, LO_IFINDEX)?;
        let tx = open_packet(SOCK_RAW, ETH_P_ALL)?;
        bind_ll(tx, ETH_P_ALL, LO_IFINDEX)?;
        let marker = b"raw-lo-roundtrip";
        let src = [0x02, 0, 0, 0, 0, 0x77];
        let frame = eth([0; 6], src, ETH_P_TEST, marker);
        expect(
            send(tx, &frame) == Some(frame.len() as i64),
            "send on a bound SOCK_RAW socket returns the frame length",
        )?;
        let (data, out, len) = recv_marked(rx, marker)?;
        expect(data == frame, "SOCK_RAW delivers the whole frame")?;
        expect(len == 20, "msg_namelen is sizeof(sockaddr_ll)")?;
        expect(
            out.pkttype == PACKET_OUTGOING,
            "the transmit tap is PACKET_OUTGOING",
        )?;
        expect(
            out.protocol == ETH_P_TEST && out.ifindex == LO_IFINDEX,
            "sll_protocol/ifindex of the tap",
        )?;
        expect(
            out.hatype == ARPHRD_LOOPBACK && out.halen == 6 && out.addr[..6] == src,
            "sll_hatype and the source MAC",
        )?;
        let (data, host, _) = recv_marked(rx, marker)?;
        expect(data == frame, "the loopback receive carries the frame")?;
        expect(
            host.pkttype == PACKET_HOST,
            "lo's receive copy is PACKET_HOST",
        )?;
        let (_, own, _) = recv_marked(tx, marker)?;
        expect(
            own.pkttype == PACKET_HOST,
            "the sender sees only the receive copy",
        )?;
        none_marked(tx, marker)?;
        close(rx);
        close(tx);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_raw_lo_outgoing_and_host
);

/// `packet_rcv` on a real device: SOCK_DGRAM strips the link header; a
/// socket bound to one ethertype receives only it and never sees transmit
/// taps (those are `ptype_all` only); `eth_type_trans` classifies the
/// destination as HOST / BROADCAST / MULTICAST / OTHERHOST.
fn smoke_abi_packet_dgram_receive_and_pkttype() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        bind_ll(fd, ETH_P_TEST, ifindex)?;
        let cases: [([u8; 6], u8, &[u8]); 4] = [
            (NIC_MAC, PACKET_HOST, b"pkttype-host"),
            ([0xff; 6], PACKET_BROADCAST, b"pkttype-bcast"),
            (
                [0x01, 0x00, 0x5e, 0, 0, 1],
                PACKET_MULTICAST,
                b"pkttype-mcast",
            ),
            ([0x02, 9, 9, 9, 9, 9], PACKET_OTHERHOST, b"pkttype-other"),
        ];
        for (dst, pkttype, payload) in cases {
            inject(&eth(dst, PEER_MAC, ETH_P_TEST, payload));
            let (data, from, _) = recv_marked(fd, payload)?;
            expect(
                data == payload,
                "SOCK_DGRAM delivers from the network header",
            )?;
            expect(from.pkttype == pkttype, "eth_type_trans packet type")?;
            expect(
                from.hatype == ARPHRD_ETHER && from.ifindex == ifindex,
                "Ethernet device fields",
            )?;
            expect(from.addr[..6] == PEER_MAC, "sll_addr is the source MAC")?;
        }
        // Another ethertype is not delivered to this hook.
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_ARP, b"pkttype-arp"));
        none_marked(fd, b"pkttype-arp")?;
        // A transmit on the device is not seen by an ethertype hook.
        let tx = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        let to = sll(ETH_P_TEST, ifindex, 0, 6, &[0xff; 6]);
        expect(
            sendto(tx, b"pkttype-tx", 0, &to) == Some(10),
            "sendto on the capture NIC",
        )?;
        none_marked(fd, b"pkttype-tx")?;
        close(tx);
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_dgram_receive_and_pkttype
);

/// `packet_recvmsg` flags: MSG_PEEK leaves the frame, MSG_TRUNC returns the
/// full length (and `recv(NULL, 0, MSG_PEEK|MSG_TRUNC)` is sd-dhcp's size
/// probe), SIOCINQ/FIONREAD reports the head frame, MSG_DONTWAIT on an empty
/// queue is EAGAIN, MSG_ERRQUEUE finds the (always empty) error queue, and
/// any other flag (MSG_WAITALL, MSG_CMSG_CLOEXEC) is EINVAL.
fn smoke_abi_packet_recv_flags() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        bind_ll(fd, ETH_P_TEST, ifindex)?;
        let payload = b"recv-flags-0123456789";
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_TEST, payload));
        let probe = sys(Syscall::SocketRecv, a3(fd, 0, 0, MSG_PEEK | MSG_TRUNC));
        expect(
            probe == Some(payload.len() as i64),
            "recv(NULL, 0, MSG_PEEK|MSG_TRUNC) reports the datagram length",
        )?;
        let mut inq = [0u8; 4];
        expect(
            sys(Syscall::Ioctl, a2(fd, FIONREAD, inq.as_mut_ptr() as u64)) == Some(0)
                && i32::from_ne_bytes(inq) == payload.len() as i32,
            "FIONREAD is the head frame's length",
        )?;
        let mut small = [0u8; 4];
        let (r, _, _) = recvfrom(fd, &mut small, MSG_PEEK);
        expect(
            r == Some(4) && &small == b"recv",
            "MSG_PEEK copies a prefix",
        )?;
        let (r, _, _) = recvfrom(fd, &mut small, MSG_TRUNC);
        expect(
            r == Some(payload.len() as i64),
            "MSG_TRUNC returns the real length",
        )?;
        let (r, _, _) = recvfrom(fd, &mut small, MSG_DONTWAIT);
        expect(
            r == Some(EAGAIN),
            "an empty queue with MSG_DONTWAIT is EAGAIN",
        )?;
        expect(
            sys(
                Syscall::SocketRecv,
                a3(fd, small.as_mut_ptr() as u64, 4, MSG_ERRQUEUE),
            ) == Some(EAGAIN),
            "an empty error queue is EAGAIN",
        )?;
        for bad in [MSG_WAITALL, 0x4000_0000] {
            expect(
                sys(
                    Syscall::SocketRecv,
                    a3(fd, small.as_mut_ptr() as u64, 4, bad),
                ) == Some(EINVAL),
                "flags packet_recvmsg does not accept are EINVAL",
            )?;
        }
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_recv_flags);

/// `PACKET_AUXDATA` + `put_cmsg`: the SOL_PACKET/PACKET_AUXDATA cmsg carries
/// tp_status = TP_STATUS_USER, tp_len, tp_snaplen, tp_mac = 0 and tp_net
/// (0 for SOCK_DGRAM, 14 for SOCK_RAW); a control buffer of exactly
/// CMSG_LEN(20) (n-dhcp4's size) holds it; SO_TIMESTAMP adds an SCM_TIMESTAMP
/// cmsg BEFORE it (`sock_recv_cmsgs` runs first); a buffer with no room is
/// MSG_CTRUNC with msg_controllen 0; a short one gets a truncated record.
fn smoke_abi_packet_auxdata_cmsg() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let dgram = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        bind_ll(dgram, ETH_P_TEST, ifindex)?;
        let raw = open_packet(SOCK_RAW, ETH_P_TEST)?;
        bind_ll(raw, ETH_P_TEST, ifindex)?;
        expect(
            get_int(dgram, SOL_PACKET, PACKET_AUXDATA)? == 0,
            "AUXDATA defaults off",
        )?;
        for fd in [dgram, raw] {
            expect(
                set_int(fd, SOL_PACKET, PACKET_AUXDATA, 1) == Some(0),
                "enable AUXDATA",
            )?;
        }
        expect(
            get_int(dgram, SOL_PACKET, PACKET_AUXDATA)? == 1,
            "AUXDATA reads back",
        )?;
        let payload = b"auxdata-payload";
        let frame = eth(NIC_MAC, PEER_MAC, ETH_P_TEST, payload);

        inject(&frame);
        let mut data = [0u8; 64];
        let mut control = [0u8; 36];
        let m = recvmsg(dgram, &mut [&mut data], &mut control, 0);
        expect(m.ret == Some(payload.len() as i64), "recvmsg length")?;
        expect(m.flags & MSG_CTRUNC == 0, "CMSG_LEN(auxdata) fits")?;
        expect(
            m.namelen == 20 && sll_of(&m.name).pkttype == PACKET_HOST,
            "msg_name",
        )?;
        let c = cmsgs(&control, m.controllen);
        expect(
            c.len() == 1 && c[0].0 == 263 && c[0].1 == 8,
            "one PACKET_AUXDATA cmsg",
        )?;
        let aux = aux_of(&c[0].2).ok_or("auxdata size")?;
        expect(
            aux == Aux {
                status: TP_STATUS_USER,
                len: payload.len() as u32,
                snaplen: payload.len() as u32,
                mac: 0,
                net: 0,
                vlan_tci: 0,
                vlan_tpid: 0,
            },
            "SOCK_DGRAM tpacket_auxdata",
        )?;
        let m = recvmsg(raw, &mut [&mut data], &mut control, 0);
        let c = cmsgs(&control, m.controllen);
        let aux = aux_of(&c.first().ok_or("raw cmsg")?.2).ok_or("raw auxdata size")?;
        expect(
            aux.net == 14 && aux.len == frame.len() as u32 && aux.snaplen == frame.len() as u32,
            "SOCK_RAW tp_net is the link-header length",
        )?;

        // Timestamp first, then auxdata.
        expect(
            set_int(dgram, SOL_SOCKET, SO_TIMESTAMP_OLD, 1) == Some(0),
            "SO_TIMESTAMP",
        )?;
        inject(&frame);
        let mut both = [0u8; 32 + 40];
        let m = recvmsg(dgram, &mut [&mut data], &mut both, MSG_DONTWAIT);
        let c = cmsgs(&both, m.controllen);
        expect(
            m.flags & MSG_CTRUNC == 0
                && c.len() == 2
                && (c[0].0, c[0].1) == (1, 29)
                && c[0].2.len() == 16
                && (c[1].0, c[1].1) == (263, 8),
            "SCM_TIMESTAMP precedes PACKET_AUXDATA",
        )?;
        expect(
            m.controllen == 32 + 40,
            "msg_controllen counts both CMSG_SPACEs",
        )?;
        let _ = set_int(dgram, SOL_SOCKET, SO_TIMESTAMP_OLD, 0);

        // No room at all: MSG_CTRUNC, nothing written.
        inject(&frame);
        let m = recvmsg(dgram, &mut [&mut data], &mut [], 0);
        expect(
            m.ret == Some(payload.len() as i64) && m.flags & MSG_CTRUNC != 0 && m.controllen == 0,
            "no control buffer: MSG_CTRUNC",
        )?;
        // Room for the header and part of the data: a truncated record.
        inject(&frame);
        let mut short = [0u8; 24];
        let m = recvmsg(dgram, &mut [&mut data], &mut short, 0);
        expect(
            m.flags & MSG_CTRUNC != 0
                && m.controllen == 24
                && u64::from_ne_bytes(short[0..8].try_into().unwrap()) == 24,
            "a short control buffer gets a truncated cmsg",
        )?;
        close(dgram);
        close(raw);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_auxdata_cmsg);

/// `__netif_receive_skb_core` untags an 802.1Q frame before the `ptype_all`
/// taps: an ETH_P_ALL SOCK_RAW socket gets the untagged frame and the tag
/// in its auxdata (TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID). With
/// no VLAN device for VID 5 the frame reaches the inner protocol's hooks as
/// PACKET_OTHERHOST and without the tag.
fn smoke_abi_packet_vlan_rx() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let all = open_packet(SOCK_RAW, ETH_P_ALL)?;
        bind_ll(all, ETH_P_ALL, ifindex)?;
        let inner = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        bind_ll(inner, ETH_P_TEST, ifindex)?;
        for fd in [all, inner] {
            let _ = set_int(fd, SOL_PACKET, PACKET_AUXDATA, 1);
        }
        let payload = b"vlan-tagged-frame";
        let mut tagged = alloc::vec::Vec::new();
        tagged.extend_from_slice(&NIC_MAC);
        tagged.extend_from_slice(&PEER_MAC);
        tagged.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
        tagged.extend_from_slice(&0x2005u16.to_be_bytes()); // PCP 1, VID 5
        tagged.extend_from_slice(&ETH_P_TEST.to_be_bytes());
        tagged.extend_from_slice(payload);
        inject(&tagged);
        let mut data = [0u8; 128];
        let mut control = [0u8; 64];
        let m = recvmsg(all, &mut [&mut data], &mut control, MSG_DONTWAIT);
        let n = m.ret.ok_or("tap recvmsg")? as usize;
        expect(
            data[..n] == eth(NIC_MAC, PEER_MAC, ETH_P_TEST, payload)[..],
            "the tap sees the untagged frame",
        )?;
        let from = sll_of(&m.name);
        expect(
            from.protocol == ETH_P_TEST && from.pkttype == PACKET_HOST,
            "the tap sees the inner protocol",
        )?;
        let c = cmsgs(&control, m.controllen);
        let aux = aux_of(&c.first().ok_or("tap cmsg")?.2).ok_or("tap aux")?;
        expect(
            aux.status == TP_STATUS_USER | TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID
                && aux.vlan_tci == 0x2005
                && aux.vlan_tpid == ETH_P_8021Q,
            "the tag is reported in auxdata",
        )?;
        let m = recvmsg(inner, &mut [&mut data], &mut control, MSG_DONTWAIT);
        let n = m.ret.ok_or("inner recvmsg")? as usize;
        expect(&data[..n] == payload, "the inner hook gets the payload")?;
        expect(
            sll_of(&m.name).pkttype == PACKET_OTHERHOST,
            "an unclaimed VID makes the frame PACKET_OTHERHOST",
        )?;
        let c = cmsgs(&control, m.controllen);
        let aux = aux_of(&c.first().ok_or("inner cmsg")?.2).ok_or("inner aux")?;
        expect(
            aux.status == TP_STATUS_USER && aux.vlan_tci == 0,
            "the tag is cleared",
        )?;
        close(all);
        close(inner);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_vlan_rx);

// ───────────────────────────── send ─────────────────────────────

/// `packet_snd` for SOCK_DGRAM: the Ethernet header is built from
/// `sll_addr` (destination), the device address (source) and `sll_protocol`;
/// the call returns the payload length. Errors in Linux's order: namelen <
/// sizeof(sockaddr_ll) EINVAL, namelen < halen + 12 EINVAL, no device
/// ENXIO, device down ENETDOWN, len > mtu + VLAN_HLEN EMSGSIZE; an unbound
/// send without an address is ENXIO.
fn smoke_abi_packet_dgram_send_builds_header() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        let dst = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let to = sll(ETH_P_TEST, ifindex, 0, 6, &dst);
        let payload = b"dgram-send";
        expect(
            sendto(fd, payload, 0, &to) == Some(payload.len() as i64),
            "sendto returns the payload length",
        )?;
        let frames = captured();
        expect(frames.len() == 1, "one frame reached the driver")?;
        expect(
            frames[0] == eth(dst, NIC_MAC, ETH_P_TEST, payload),
            "dev_hard_header built dst/src/type",
        )?;
        expect(
            sendto(fd, payload, 0, &to[..19]) == Some(EINVAL),
            "namelen < 20 is EINVAL",
        )?;
        let mut big_halen = to;
        big_halen[11] = 9;
        expect(
            sendto(fd, payload, 0, &big_halen) == Some(EINVAL),
            "namelen < halen + offsetof(sll_addr) is EINVAL",
        )?;
        expect(
            sendto(fd, payload, 0, &sll(ETH_P_TEST, 0x7fff_0000, 0, 6, &dst)) == Some(ENXIO),
            "an unknown ifindex is ENXIO",
        )?;
        expect(
            send(fd, payload) == Some(ENXIO),
            "an unbound send without address is ENXIO",
        )?;
        let mtu = narf_net::iface::lookup(NIC).ok_or("nic")?.mtu as usize;
        let oversize = alloc::vec![0u8; mtu + 5];
        expect(
            sendto(fd, &oversize, 0, &to) == Some(EMSGSIZE),
            "len > mtu + VLAN_HLEN is EMSGSIZE",
        )?;
        let just_over = alloc::vec![0u8; mtu + 1];
        expect(
            sendto(fd, &just_over, 0, &to) == Some(EMSGSIZE),
            "a non-VLAN frame over the MTU is EMSGSIZE",
        )?;
        let vlan_to = sll(ETH_P_8021Q, ifindex, 0, 6, &dst);
        expect(
            sendto(fd, &just_over, 0, &vlan_to) == Some((mtu + 1) as i64),
            "an 802.1Q frame may carry VLAN_HLEN extra",
        )?;
        let _ = captured();
        nic_down();
        expect(
            sendto(fd, payload, 0, &to) == Some(ENETDOWN),
            "a down device is ENETDOWN",
        )?;
        // Bound to the device: send() has no destination for eth_header.
        let _ = nic(true)?;
        bind_ll(fd, ETH_P_TEST, ifindex)?;
        expect(
            send(fd, payload) == Some(EINVAL),
            "a bound Ethernet SOCK_DGRAM send without address is EINVAL",
        )?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_dgram_send_builds_header
);

/// `packet_snd` for SOCK_RAW: the frame goes out as given (its protocol is
/// parsed from the header when the socket's is 0); a frame shorter than the
/// 14-byte header is EINVAL (`dev_validate_header`); len > mtu + 14 + 4 is
/// EMSGSIZE. write(2) and writev(2) are the same send (dhcpcd writes the
/// header and payload as two iovecs). An ETH_P_ALL listener on the device
/// sees each as PACKET_OUTGOING.
fn smoke_abi_packet_raw_send_and_write() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let tap = open_packet(SOCK_RAW, ETH_P_ALL)?;
        bind_ll(tap, ETH_P_ALL, ifindex)?;
        let fd = open(AF_PACKET, SOCK_RAW, 0)?;
        bind_ll(fd, 0, ifindex)?;
        let frame = eth([0xff; 6], NIC_MAC, ETH_P_TEST, b"raw-send-frame");
        expect(
            send(fd, &frame) == Some(frame.len() as i64),
            "send a raw frame",
        )?;
        expect(
            captured() == [frame.clone()],
            "the frame is transmitted as given",
        )?;
        let (data, from, _) = recv_marked(tap, b"raw-send-frame")?;
        expect(
            data == frame && from.pkttype == PACKET_OUTGOING && from.protocol == ETH_P_TEST,
            "the tap sees the transmit with the parsed protocol",
        )?;
        expect(
            send(fd, &frame[..13]) == Some(EINVAL),
            "a short frame is EINVAL",
        )?;
        REJECT_SEND.store(true, Ordering::Release);
        let rejected = send(fd, &frame);
        REJECT_SEND.store(false, Ordering::Release);
        expect(rejected == Some(ENOBUFS), "a qdisc/driver drop is ENOBUFS")?;
        let _ = captured();
        let mtu = narf_net::iface::lookup(NIC).ok_or("nic")?.mtu as usize;
        let huge = alloc::vec![0u8; mtu + 14 + 5];
        expect(
            send(fd, &huge) == Some(EMSGSIZE),
            "len > mtu + 18 is EMSGSIZE",
        )?;
        // write(2)
        let w = eth([0xff; 6], NIC_MAC, ETH_P_TEST, b"raw-write-frame");
        expect(
            sys(Syscall::Write, a2(fd, w.as_ptr() as u64, w.len() as u64)) == Some(w.len() as i64),
            "write(2) sends one frame",
        )?;
        // writev(2) of header + payload.
        let header = &w[..14];
        let body = b"raw-writev-frame";
        let mut iov = [0u8; 32];
        iov[0..8].copy_from_slice(&(header.as_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&14u64.to_ne_bytes());
        iov[16..24].copy_from_slice(&(body.as_ptr() as u64).to_ne_bytes());
        iov[24..32].copy_from_slice(&(body.len() as u64).to_ne_bytes());
        expect(
            sys(Syscall::Writev, a2(fd, iov.as_ptr() as u64, 2)) == Some(14 + body.len() as i64),
            "writev(2) sends one frame",
        )?;
        let frames = captured();
        expect(frames.len() == 2, "write and writev each sent one frame")?;
        expect(
            frames[1][..14] == *header && &frames[1][14..] == body,
            "writev frame",
        )?;
        let unbound = open(AF_PACKET, SOCK_RAW, 0)?;
        expect(
            sys(
                Syscall::Write,
                a2(unbound, w.as_ptr() as u64, w.len() as u64),
            ) == Some(ENXIO),
            "write(2) on an unbound packet socket is packet_snd's ENXIO",
        )?;
        expect(
            sys(Syscall::Writev, a2(unbound, iov.as_ptr() as u64, 2)) == Some(ENXIO),
            "writev(2) preserves packet_snd's ENXIO",
        )?;
        for f in [tap, fd, unbound] {
            close(f);
        }
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_raw_send_and_write);

/// `dev_queue_xmit_nit` taps every frame the kernel stack transmits: a
/// gratuitous ARP sent by the IPv4 stack on the device reaches an ETH_P_ALL
/// listener as PACKET_OUTGOING; PACKET_IGNORE_OUTGOING suppresses it, and a
/// sender with PACKET_QDISC_BYPASS (`packet_direct_xmit`) bypasses the taps.
fn smoke_abi_packet_outgoing_tap_of_stack_frames() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let tap = open_packet(SOCK_RAW, ETH_P_ALL)?;
        bind_ll(tap, ETH_P_ALL, ifindex)?;
        let quiet = open_packet(SOCK_RAW, ETH_P_ALL)?;
        bind_ll(quiet, ETH_P_ALL, ifindex)?;
        expect(
            set_int(quiet, SOL_PACKET, PACKET_IGNORE_OUTGOING, 1) == Some(0),
            "PACKET_IGNORE_OUTGOING",
        )?;
        let addr = [198, 51, 100, 77];
        narf_net::arp_cache::send_gratuitous_arp(NIC, addr);
        let (data, from, _) = recv_marked(tap, &addr)?;
        expect(
            from.pkttype == PACKET_OUTGOING && from.protocol == ETH_P_ARP && data[12..14] == [8, 6],
            "the stack's ARP transmit is tapped as PACKET_OUTGOING",
        )?;
        none_marked(quiet, &addr)?;
        // QDISC_BYPASS: no tap.
        let tx = open_packet(SOCK_RAW, ETH_P_ALL)?;
        bind_ll(tx, ETH_P_ALL, ifindex)?;
        expect(
            set_int(tx, SOL_PACKET, PACKET_QDISC_BYPASS, 1) == Some(0),
            "PACKET_QDISC_BYPASS",
        )?;
        let frame = eth([0xff; 6], NIC_MAC, ETH_P_TEST, b"bypass-frame");
        expect(send(tx, &frame) == Some(frame.len() as i64), "bypass send")?;
        none_marked(tap, b"bypass-frame")?;
        expect(captured().contains(&frame), "the driver still got it")?;
        for f in [tap, quiet, tx] {
            close(f);
        }
        nic_down();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_outgoing_tap_of_stack_frames
);

// ───────────────────────────── filters ─────────────────────────────

/// SO_ATTACH_FILTER runs the classic program on each frame (`run_filter`):
/// n-dhcp4's DGRAM filter (BPF_MSH, BPF_IND, BPF_LEN, ALU SUB/ADD X, TAX)
/// passes only BOOTREPLY datagrams to port 68; a return value below the
/// length trims the frame (tp_len keeps the original, MSG_TRUNC reports
/// it); SO_DETACH_FILTER removes it; SO_LOCK_FILTER makes both EPERM.
fn smoke_abi_packet_classic_filter() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_DGRAM, ETH_P_IP)?;
        expect(
            attach(fd, &n_dhcp4_filter()) == Some(0),
            "attach n-dhcp4's filter",
        )?;
        bind_ll(fd, ETH_P_IP, ifindex)?;
        let offer = dhcp_reply(68, 2, 0x1234_5678);
        let wrong_port = dhcp_reply(53, 2, 0x1234_5678);
        let request = dhcp_reply(68, 1, 0x1234_5678);
        for ip in [&wrong_port, &request, &offer] {
            inject(&eth([0xff; 6], PEER_MAC, ETH_P_IP, ip));
        }
        let mut buf = [0u8; 600];
        let (r, from, _) = recvfrom(fd, &mut buf, MSG_DONTWAIT);
        expect(
            r == Some(offer.len() as i64),
            "only the BOOTREPLY to port 68 passes",
        )?;
        expect(buf[..offer.len()] == offer[..], "the accepted datagram")?;
        expect(
            sll_of(&from).pkttype == PACKET_BROADCAST,
            "broadcast DHCPOFFER",
        )?;
        expect(
            recvfrom(fd, &mut buf, MSG_DONTWAIT).0 == Some(EAGAIN),
            "nothing else",
        )?;

        // A snap length: RET #28 keeps the IP and UDP headers.
        let trim = [insn(0x06, 0, 0, 28)];
        expect(attach(fd, &trim) == Some(0), "replace the filter")?;
        expect(
            set_int(fd, SOL_PACKET, PACKET_AUXDATA, 1) == Some(0),
            "auxdata",
        )?;
        inject(&eth([0xff; 6], PEER_MAC, ETH_P_IP, &offer));
        let mut data = [0u8; 600];
        let mut control = [0u8; 64];
        let m = recvmsg(fd, &mut [&mut data], &mut control, MSG_TRUNC);
        expect(
            m.ret == Some(28),
            "the filter's return value is the snap length",
        )?;
        let c = cmsgs(&control, m.controllen);
        let aux = aux_of(&c.first().ok_or("cmsg")?.2).ok_or("aux")?;
        expect(
            aux.len == offer.len() as u32 && aux.snaplen == 28,
            "tp_len is the original length, tp_snaplen the kept one",
        )?;
        expect(
            setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &0i32.to_ne_bytes()) == Some(0),
            "detach",
        )?;
        expect(
            setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &0i32.to_ne_bytes()) == Some(ENOENT),
            "detaching nothing is ENOENT",
        )?;
        inject(&eth([0xff; 6], PEER_MAC, ETH_P_IP, &request));
        expect(
            recvfrom(fd, &mut buf, MSG_DONTWAIT).0 == Some(request.len() as i64),
            "without a filter everything passes",
        )?;
        expect(attach(fd, &trim) == Some(0), "attach")?;
        expect(
            set_int(fd, SOL_SOCKET, SO_LOCK_FILTER, 1) == Some(0),
            "lock",
        )?;
        expect(
            attach(fd, &trim) == Some(EPERM),
            "a locked filter cannot be replaced",
        )?;
        expect(
            setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &0i32.to_ne_bytes()) == Some(EPERM),
            "a locked filter cannot be detached",
        )?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_classic_filter);

/// Classic ancillary loads see the packet socket's `sk_buff`:
/// `SKF_AD_PROTOCOL`, `SKF_AD_PKTTYPE`, `SKF_AD_IFINDEX` and
/// `SKF_AD_HATYPE`, and `SKF_LL_OFF` reaches the MAC header from a SOCK_DGRAM
/// socket whose data starts at the network header.
fn smoke_abi_packet_filter_ancillary_loads() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        bind_ll(fd, ETH_P_TEST, ifindex)?;
        let prog = [
            insn(0x28, 0, 0, 0xffff_f000), // protocol
            insn(0x15, 1, 0, u32::from(ETH_P_TEST)),
            insn(0x06, 0, 0, 0),
            insn(0x30, 0, 0, 0xffff_f004), // pkttype
            insn(0x15, 1, 0, u32::from(PACKET_BROADCAST)),
            insn(0x06, 0, 0, 0),
            insn(0x20, 0, 0, 0xffff_f008), // ifindex
            insn(0x15, 1, 0, ifindex as u32),
            insn(0x06, 0, 0, 0),
            insn(0x28, 0, 0, 0xffff_f01c), // hatype
            insn(0x15, 1, 0, u32::from(ARPHRD_ETHER)),
            insn(0x06, 0, 0, 0),
            insn(0x30, 0, 0, 0xffe0_000b), // SKF_LL_OFF + 11: src MAC last byte
            insn(0x15, 1, 0, u32::from(PEER_MAC[5])),
            insn(0x06, 0, 0, 0),
            insn(0x06, 0, 0, u32::MAX),
        ];
        expect(attach(fd, &prog) == Some(0), "attach the ancillary program")?;
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_TEST, b"anc-unicast"));
        let mut other_src = PEER_MAC;
        other_src[5] ^= 0xff;
        inject(&eth([0xff; 6], other_src, ETH_P_TEST, b"anc-other-src"));
        inject(&eth([0xff; 6], PEER_MAC, ETH_P_TEST, b"anc-pass"));
        let (data, _, _) = recv_marked(fd, b"anc-")?;
        expect(
            data == b"anc-pass",
            "only the broadcast from PEER_MAC passes",
        )?;
        none_marked(fd, b"anc-")?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_filter_ancillary_loads
);

// ───────────────────────────── options ─────────────────────────────

/// `packet_setsockopt` / `packet_getsockopt`: a foreign level is
/// ENOPROTOOPT (SOCK_PACKET has no handlers: EOPNOTSUPP); fixed-size int
/// options demand exactly sizeof(int); PACKET_VERSION accepts V1..V3;
/// PACKET_HDRLEN reads the version from optval; PACKET_IGNORE_OUTGOING
/// accepts 0/1. The unimplemented ring/fanout/vnet options are refused with
/// ENOPROTOOPT (LINUX-GAP).
fn smoke_abi_packet_sockopts() -> TestResult {
    with_setup(|| {
        let fd = open_packet(SOCK_DGRAM, ETH_P_IP)?;
        expect(
            set_int(fd, IPPROTO_IP, 1, 1) == Some(ENOPROTOOPT),
            "SOL_IP is ENOPROTOOPT",
        )?;
        let mut v = [0u8; 4];
        expect(
            getsockopt(fd, IPPROTO_IP, 1, &mut v).0 == Some(ENOPROTOOPT),
            "getsockopt SOL_IP is ENOPROTOOPT",
        )?;
        expect(
            set_int(fd, SOL_PACKET, 99, 1) == Some(ENOPROTOOPT),
            "unknown option",
        )?;
        expect(
            setsockopt(fd, SOL_PACKET, PACKET_VERSION, &[2, 0, 0, 0, 0, 0, 0, 0]) == Some(EINVAL),
            "PACKET_VERSION needs exactly sizeof(int)",
        )?;
        expect(
            set_int(fd, SOL_PACKET, PACKET_VERSION, 3) == Some(EINVAL),
            "no TPACKET_V4",
        )?;
        expect(
            set_int(fd, SOL_PACKET, PACKET_VERSION, 2) == Some(0),
            "TPACKET_V3",
        )?;
        expect(
            get_int(fd, SOL_PACKET, PACKET_VERSION)? == 2,
            "PACKET_VERSION reads back",
        )?;
        let mut hdr = 1i32.to_ne_bytes();
        let (r, len) = getsockopt(fd, SOL_PACKET, PACKET_HDRLEN, &mut hdr);
        expect(
            r == Some(0) && len == 4 && i32::from_ne_bytes(hdr) == 32,
            "PACKET_HDRLEN(TPACKET_V2) = sizeof(tpacket2_hdr)",
        )?;
        let mut hdr = 2i32.to_ne_bytes();
        let _ = getsockopt(fd, SOL_PACKET, PACKET_HDRLEN, &mut hdr);
        expect(
            i32::from_ne_bytes(hdr) == 48,
            "PACKET_HDRLEN(TPACKET_V3) = 48",
        )?;
        let mut hdr = 7i32.to_ne_bytes();
        expect(
            getsockopt(fd, SOL_PACKET, PACKET_HDRLEN, &mut hdr).0 == Some(EINVAL),
            "an unknown version is EINVAL",
        )?;
        let mut two = [0u8; 2];
        expect(
            getsockopt(fd, SOL_PACKET, PACKET_HDRLEN, &mut two).0 == Some(EINVAL),
            "PACKET_HDRLEN needs sizeof(int)",
        )?;
        expect(
            set_int(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, 2) == Some(EINVAL),
            "PACKET_IGNORE_OUTGOING accepts only 0/1",
        )?;
        expect(
            setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &[1, 0, 0, 0, 9, 9, 9, 9]) == Some(0),
            "PACKET_AUXDATA takes optlen >= sizeof(int)",
        )?;
        expect(
            setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &[1, 0]) == Some(EINVAL),
            "a short PACKET_AUXDATA is EINVAL",
        )?;
        expect(
            set_int(fd, SOL_PACKET, PACKET_VNET_HDR, 1) == Some(EINVAL),
            "PACKET_VNET_HDR on SOCK_DGRAM is EINVAL",
        )?;
        let raw = open_packet(SOCK_RAW, ETH_P_ALL)?;
        expect(
            set_int(raw, SOL_PACKET, PACKET_VNET_HDR, 0) == Some(0),
            "no vnet header",
        )?;
        expect(
            get_int(raw, SOL_PACKET, PACKET_VNET_HDR)? == 0,
            "vnet header is off",
        )?;
        // LINUX-GAP refusals.
        expect(
            set_int(raw, SOL_PACKET, PACKET_VNET_HDR, 1) == Some(ENOPROTOOPT),
            "vnet gap",
        )?;
        let req = [0u8; 16];
        for opt in [PACKET_RX_RING, PACKET_TX_RING] {
            expect(
                setsockopt(raw, SOL_PACKET, opt, &req) == Some(ENOPROTOOPT),
                "ring gap",
            )?;
        }
        expect(
            set_int(raw, SOL_PACKET, PACKET_FANOUT, 1) == Some(ENOPROTOOPT),
            "fanout gap",
        )?;
        expect(
            get_int(raw, SOL_PACKET, PACKET_FANOUT)? == 0,
            "no fanout group",
        )?;
        let spkt = open_packet(SOCK_PACKET, ETH_P_ALL)?;
        expect(
            set_int(spkt, SOL_PACKET, PACKET_AUXDATA, 1) == Some(EOPNOTSUPP),
            "SOCK_PACKET has no setsockopt",
        )?;
        expect(
            getsockopt(spkt, SOL_PACKET, PACKET_AUXDATA, &mut v).0 == Some(EOPNOTSUPP),
            "SOCK_PACKET has no getsockopt",
        )?;
        expect(
            set_int(spkt, SOL_SOCKET, SO_RCVBUF, 4096) == Some(0),
            "SOL_SOCKET still works",
        )?;
        for f in [fd, raw, spkt] {
            close(f);
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_sockopts);

/// PACKET_STATISTICS reports `tp_packets` (delivered + dropped) and
/// `tp_drops` (frames refused because `sk_rmem_alloc >= sk_rcvbuf`), and
/// resets both on read.
fn smoke_abi_packet_statistics_and_rcvbuf() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        bind_ll(fd, ETH_P_TEST, ifindex)?;
        expect(
            set_int(fd, SOL_SOCKET, SO_RCVBUF, 1) == Some(0),
            "minimum SO_RCVBUF",
        )?;
        let rcvbuf = get_int(fd, SOL_SOCKET, SO_RCVBUF)? as usize;
        let payload = alloc::vec![0x5au8; 1000];
        let frames = rcvbuf / 1000 + 8;
        for _ in 0..frames {
            inject(&eth(NIC_MAC, PEER_MAC, ETH_P_TEST, &payload));
        }
        let mut st = [0u8; 8];
        let (r, len) = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &mut st);
        expect(r == Some(0) && len == 8, "struct tpacket_stats")?;
        let packets = u32::from_ne_bytes(st[0..4].try_into().unwrap()) as usize;
        let drops = u32::from_ne_bytes(st[4..8].try_into().unwrap()) as usize;
        expect(
            packets == frames,
            "tp_packets counts every frame, dropped or not",
        )?;
        expect(drops > 0 && drops < frames, "a full receive buffer drops")?;
        let mut queued = 0;
        let mut buf = [0u8; 1100];
        while recvfrom(fd, &mut buf, MSG_DONTWAIT).0 == Some(1000) {
            queued += 1;
        }
        expect(queued == frames - drops, "queued = delivered - dropped")?;
        let _ = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &mut st);
        expect(st == [0u8; 8], "statistics reset on read")?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_statistics_and_rcvbuf);

/// `packet_mc_add`: optlen < sizeof(packet_mreq) is EINVAL; an unknown
/// ifindex is ENODEV; mr_alen beyond the device address is EINVAL;
/// PACKET_MR_MULTICAST needs an alen equal to the device's; PACKET_MR_PROMISC
/// and an unknown type are accepted; PACKET_DROP_MEMBERSHIP always succeeds.
fn smoke_abi_packet_membership() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_RAW, ETH_P_ALL)?;
        let mreq = |ifindex: i32, ty: u16, alen: u16, addr: &[u8]| {
            let mut m = [0u8; 16];
            m[0..4].copy_from_slice(&ifindex.to_ne_bytes());
            m[4..6].copy_from_slice(&ty.to_ne_bytes());
            m[6..8].copy_from_slice(&alen.to_ne_bytes());
            m[8..8 + addr.len()].copy_from_slice(addr);
            m
        };
        let group = [0x01, 0x80, 0xc2, 0, 0, 0x0e];
        let mc = mreq(ifindex, PACKET_MR_MULTICAST, 6, &group);
        expect(
            setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mc[..15]) == Some(EINVAL),
            "a short packet_mreq is EINVAL",
        )?;
        expect(
            setsockopt(
                fd,
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq(0x7fff_0000, 0, 6, &group),
            ) == Some(ENODEV),
            "an unknown ifindex is ENODEV",
        )?;
        expect(
            setsockopt(
                fd,
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq(ifindex, 0, 7, &group),
            ) == Some(EINVAL),
            "mr_alen > dev->addr_len is EINVAL",
        )?;
        expect(
            setsockopt(
                fd,
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq(ifindex, 0, 4, &group),
            ) == Some(EINVAL),
            "a multicast address of the wrong length is EINVAL",
        )?;
        expect(
            setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mc) == Some(0),
            "join a multicast group",
        )?;
        expect(
            setsockopt(
                fd,
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq(ifindex, PACKET_MR_PROMISC, 0, &[]),
            ) == Some(0),
            "PACKET_MR_PROMISC",
        )?;
        let mut ifr = [0u8; 40];
        ifr[..NIC.len()].copy_from_slice(NIC.as_bytes());
        expect(
            sys(
                Syscall::Ioctl,
                a2(fd, SIOCGIFFLAGS, ifr.as_mut_ptr() as u64),
            ) == Some(0)
                && u16::from_ne_bytes([ifr[16], ifr[17]]) & 0x100 != 0,
            "PACKET_MR_PROMISC is visible through SIOCGIFFLAGS",
        )?;
        expect(
            setsockopt(
                fd,
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq(ifindex, 9, 0, &[]),
            ) == Some(0),
            "an unknown membership type is accepted",
        )?;
        expect(
            setsockopt(
                fd,
                SOL_PACKET,
                PACKET_DROP_MEMBERSHIP,
                &mreq(ifindex, 0, 6, &[9; 6]),
            ) == Some(0),
            "dropping a membership that does not exist succeeds",
        )?;
        expect(
            setsockopt(fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mc) == Some(0),
            "drop the group",
        )?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_membership);

// ───────────────────────────── readiness ─────────────────────────────

/// `packet_poll` → `datagram_poll`: a packet socket is always writable,
/// readable while a frame is queued, and EPOLLERR while `sk_err` is set.
/// An epoll registration sees each new frame (also edge-triggered).
fn smoke_abi_packet_epoll_readiness() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open(
            AF_PACKET,
            SOCK_DGRAM | SOCK_NONBLOCK,
            u64::from(ETH_P_TEST.to_be()),
        )?;
        bind_ll(fd, ETH_P_TEST, ifindex)?;
        let epfd = sys(Syscall::EpollCreate, a0(0)).ok_or("epoll_create")?;
        expect(epfd >= 0, "epoll_create")?;
        let epfd = epfd as u64;
        let mut ev = [0u8; 16];
        ev[..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_ne_bytes());
        expect(
            sys(Syscall::EpollCtl, a3(epfd, 1, fd, ev.as_ptr() as u64)) == Some(0),
            "EPOLL_CTL_ADD",
        )?;
        let wait = || -> Option<(i64, u32)> {
            let mut out = [0u8; 16];
            let n = sys(Syscall::EpollWait, a3(epfd, out.as_mut_ptr() as u64, 1, 0))?;
            Some((n, u32::from_ne_bytes(out[0..4].try_into().unwrap())))
        };
        expect(wait() == Some((0, 0)), "an empty socket is not readable")?;
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_TEST, b"epoll-1"));
        let (n, events) = wait().ok_or("epoll_wait")?;
        expect(n == 1 && events & EPOLLIN != 0, "a queued frame is EPOLLIN")?;
        expect(wait() == Some((0, 0)), "EPOLLET reports the edge once")?;
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_TEST, b"epoll-2"));
        let (n, _) = wait().ok_or("epoll_wait")?;
        expect(n == 1, "a second frame on a readable socket is a new edge")?;
        let mut buf = [0u8; 64];
        while recvfrom(fd, &mut buf, 0).0.is_some_and(|r| r > 0) {}
        // Level-triggered view: OUT always, ERR on sk_err.
        let mut ev = [0u8; 16];
        ev[..4].copy_from_slice(&(EPOLLIN | EPOLLOUT).to_ne_bytes());
        expect(
            sys(Syscall::EpollCtl, a3(epfd, 3, fd, ev.as_ptr() as u64)) == Some(0),
            "EPOLL_CTL_MOD",
        )?;
        let (n, events) = wait().ok_or("epoll_wait")?;
        expect(
            n == 1 && events & EPOLLOUT != 0 && events & EPOLLIN == 0,
            "a drained packet socket is writable only",
        )?;
        nic_down();
        let (_, events) = wait().ok_or("epoll_wait")?;
        expect(events & EPOLLERR != 0, "NETDEV_DOWN raises EPOLLERR")?;
        close(epfd);
        close(fd);
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_epoll_readiness);

/// A parked waiter is woken by delivery: a persistent (epoll-style) arm on
/// the socket's readiness fires its waker when a frame is queued, and again
/// for a second frame while the socket is still readable.
fn smoke_abi_packet_delivery_wakes_parked_waiter() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};
    static WAKES: AtomicU32 = AtomicU32::new(0);
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn wake(_: *const ()) {
        WAKES.fetch_add(1, Ordering::SeqCst);
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, noop);
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_DGRAM, ETH_P_TEST)?;
        bind_ll(fd, ETH_P_TEST, ifindex)?;
        let ops = fd::with_table(FAKE_TASK, |t| t.get(fd as u32).map(|e| e.ops.clone()))
            .flatten()
            .ok_or("fd lookup")?;
        // SAFETY: the vtable's functions ignore the data pointer.
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        WAKES.store(0, Ordering::SeqCst);
        let ready = ops
            .arm_readiness_persistent(0xfeed, narf_filesystem::POLL_IN, &waker)
            .ok_or("packet sockets have a durable readiness cell")?;
        expect(ready & narf_filesystem::POLL_IN == 0, "nothing queued yet")?;
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_TEST, b"wake-1"));
        expect(
            WAKES.load(Ordering::SeqCst) >= 1,
            "delivery woke the waiter",
        )?;
        let before = WAKES.load(Ordering::SeqCst);
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_TEST, b"wake-2"));
        expect(
            WAKES.load(Ordering::SeqCst) > before,
            "a same-level delivery still wakes (epoll ready-list event)",
        )?;
        ops.disarm_readiness(0xfeed);
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_delivery_wakes_parked_waiter
);

/// The generic socket ioctls work on a packet socket (`packet_ioctl` falls
/// through to `dev_ioctl`): SIOCGIFINDEX and SIOCGIFHWADDR, which DHCP
/// clients use to fill `sockaddr_ll`.
fn smoke_abi_packet_device_ioctls() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open_packet(SOCK_DGRAM, ETH_P_IP)?;
        let mut ifr = [0u8; 40];
        ifr[..NIC.len()].copy_from_slice(NIC.as_bytes());
        expect(
            sys(
                Syscall::Ioctl,
                a2(fd, SIOCGIFINDEX, ifr.as_mut_ptr() as u64),
            ) == Some(0),
            "SIOCGIFINDEX",
        )?;
        expect(
            i32::from_ne_bytes(ifr[16..20].try_into().unwrap()) == ifindex,
            "ifr_ifindex",
        )?;
        expect(
            sys(
                Syscall::Ioctl,
                a2(fd, SIOCGIFHWADDR, ifr.as_mut_ptr() as u64),
            ) == Some(0),
            "SIOCGIFHWADDR",
        )?;
        expect(
            u16::from_ne_bytes([ifr[16], ifr[17]]) == ARPHRD_ETHER && ifr[18..24] == NIC_MAC,
            "ifr_hwaddr",
        )?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_device_ioctls);

// ───────────────────────────── SOCK_PACKET ─────────────────────────────

/// `packet_ops_spkt`: bind takes exactly a 16-byte `struct sockaddr` naming
/// the device (EINVAL otherwise, ENODEV for an unknown name); getsockname
/// returns that name; recvfrom reports a `sockaddr_pkt` (family = dev->type,
/// the device name, the protocol); sendto needs an address (ENOTCONN), at
/// least a `struct sockaddr` (EINVAL) naming a device (ENODEV).
fn smoke_abi_packet_sock_packet() -> TestResult {
    with_setup(|| {
        let _ = nic(true)?;
        let fd = open_packet(SOCK_PACKET, ETH_P_ALL)?;
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
        sa[2..2 + NIC.len()].copy_from_slice(NIC.as_bytes());
        expect(
            bind(fd, &sa[..15]) == Some(EINVAL),
            "spkt bind needs sizeof(sockaddr)",
        )?;
        let mut bogus = sa;
        bogus[2..6].copy_from_slice(b"zzzz");
        expect(
            bind(fd, &bogus) == Some(ENODEV),
            "an unknown device is ENODEV",
        )?;
        expect(bind(fd, &sa) == Some(0), "bind by device name")?;
        drain(fd);
        let mut name = [0u8; 32];
        let mut len: u32 = 32;
        let _ = sys(
            Syscall::SocketGetSockName,
            a2(fd, name.as_mut_ptr() as u64, &mut len as *mut u32 as u64),
        );
        expect(
            len == 16 && name[2..2 + NIC.len()] == *NIC.as_bytes(),
            "spkt getname",
        )?;
        let frame = eth(NIC_MAC, PEER_MAC, ETH_P_TEST, b"spkt-rx");
        inject(&frame);
        let mut buf = [0u8; 64];
        let (r, from, flen) = recvfrom(fd, &mut buf, MSG_DONTWAIT);
        expect(
            r == Some(frame.len() as i64) && buf[..frame.len()] == frame[..],
            "whole frame",
        )?;
        expect(
            flen == 18
                && u16::from_ne_bytes([from[0], from[1]]) == ARPHRD_ETHER
                && from[2..2 + NIC.len()] == *NIC.as_bytes()
                && u16::from_be_bytes([from[16], from[17]]) == ETH_P_TEST,
            "sockaddr_pkt",
        )?;
        let out = eth([0xff; 6], NIC_MAC, ETH_P_TEST, b"spkt-tx");
        expect(
            send(fd, &out) == Some(ENOTCONN),
            "spkt send needs an address",
        )?;
        expect(
            sendto(fd, &out, 0, &sa[..15]) == Some(EINVAL),
            "short address",
        )?;
        expect(
            sendto(fd, &out, 0, &bogus) == Some(ENODEV),
            "unknown device",
        )?;
        let _ = captured();
        expect(
            sendto(fd, &out, 0, &sa) == Some(out.len() as i64),
            "spkt sendto",
        )?;
        expect(captured() == [out], "transmitted as given")?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_sock_packet);

// ───────────────────────────── DHCP clients ─────────────────────────────

/// NetworkManager's internal DHCPv4 client (n-dhcp4): the exact calls of
/// `n_dhcp4_c_socket_packet_new`, `packet_recvfrom_udp` and
/// `packet_sendto_udp`, end to end over the capture NIC.
fn smoke_abi_packet_n_dhcp4_client_sequence() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        // socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)
        let fd = open(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)?;
        expect(attach(fd, &n_dhcp4_filter()) == Some(0), "SO_ATTACH_FILTER")?;
        expect(
            set_int(fd, SOL_PACKET, PACKET_AUXDATA, 1) == Some(0),
            "PACKET_AUXDATA",
        )?;
        expect(
            bind(fd, &sll(ETH_P_IP, ifindex, 0, 0, &[])) == Some(0),
            "bind(sockaddr_ll{ETH_P_IP, ifindex})",
        )?;
        // packet_sendto_udp: sendmsg(ip, udp, payload) to a 44-byte
        // packet_sockaddr_ll (sll_addr[MAX_ADDR_LEN]).
        let discover = dhcp_reply(67, 1, 0x0bad_cafe);
        let mut dest = [0u8; 44];
        dest[..20].copy_from_slice(&sll(ETH_P_IP, ifindex, 0, 6, &[0xff; 6]));
        let r = sendmsg(
            fd,
            &[&discover[..20], &discover[20..28], &discover[28..]],
            Some(&dest),
            0,
        );
        expect(
            r == Some(discover.len() as i64),
            "sendmsg returns the length",
        )?;
        let sent = captured();
        expect(
            sent.len() == 1 && sent[0] == eth([0xff; 6], NIC_MAC, ETH_P_IP, &discover),
            "a broadcast IPv4 frame from the NIC's MAC",
        )?;
        // The server's DHCPOFFER arrives; first a peek at the IP header.
        let offer = dhcp_reply(68, 2, 0x0bad_cafe);
        inject(&eth([0xff; 6], PEER_MAC, ETH_P_IP, &offer));
        let mut iphdr = [0u8; 20];
        let (r, _, _) = recvfrom(fd, &mut iphdr, MSG_PEEK);
        expect(
            r == Some(20) && iphdr[0] == 0x45,
            "recv(MSG_PEEK) of the IP header",
        )?;
        let mut ip = [0u8; 20];
        let mut udp = [0u8; 8];
        let mut body = [0u8; 600];
        let mut control = [0u8; 36]; // CMSG_LEN(sizeof(struct tpacket_auxdata))
        let m = recvmsg(fd, &mut [&mut ip, &mut udp, &mut body], &mut control, 0);
        expect(m.ret == Some(offer.len() as i64), "recvmsg of the datagram")?;
        expect(udp[2..4] == 68u16.to_be_bytes(), "scattered UDP header")?;
        let c = cmsgs(&control, m.controllen);
        let aux = aux_of(&c.first().ok_or("auxdata cmsg")?.2).ok_or("auxdata")?;
        expect(
            c[0].0 == 263 && c[0].1 == 8 && aux.status & 8 == 0,
            "PACKET_AUXDATA without TP_STATUS_CSUMNOTREADY",
        )?;
        // A non-matching frame is discarded with recv(fd, NULL, 0, 0).
        inject(&eth([0xff; 6], PEER_MAC, ETH_P_IP, &offer));
        expect(
            sys(Syscall::SocketRecv, a3(fd, 0, 0, 0)) == Some(0),
            "recv(NULL, 0, 0)",
        )?;
        expect(
            recvfrom(fd, &mut body, 0).0 == Some(EAGAIN),
            "the discard consumed the frame",
        )?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_n_dhcp4_client_sequence
);

/// systemd's sd-dhcp-client (`client_open_raw_socket`, `client_receive_
/// message`, `dhcp_message_send_raw`): SO_BINDTOIFINDEX, the filter,
/// SO_TIMESTAMP, SO_PRIORITY, PACKET_AUXDATA, bind, `next_datagram_size_fd`
/// (recv MSG_PEEK|MSG_TRUNC, then FIONREAD), recvmsg(MSG_DONTWAIT) with
/// CMSG_SPACE_TIMEVAL + CMSG_SPACE(auxdata) (MSG_CTRUNC there is fatal:
/// `recvmsg_safe` → -EXFULL), sendmsg(MSG_NOSIGNAL), getsockopt(SO_DOMAIN).
fn smoke_abi_packet_sd_dhcp_client_sequence() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)?;
        expect(
            set_int(fd, SOL_SOCKET, SO_BINDTOIFINDEX, ifindex) == Some(0),
            "SO_BINDTOIFINDEX",
        )?;
        expect(attach(fd, &n_dhcp4_filter()) == Some(0), "SO_ATTACH_FILTER")?;
        expect(
            set_int(fd, SOL_SOCKET, SO_TIMESTAMP_OLD, 1) == Some(0),
            "SO_TIMESTAMP",
        )?;
        expect(
            set_int(fd, SOL_SOCKET, SO_PRIORITY, 6) == Some(0),
            "SO_PRIORITY",
        )?;
        expect(
            set_int(fd, SOL_PACKET, PACKET_AUXDATA, 1) == Some(0),
            "PACKET_AUXDATA",
        )?;
        expect(
            bind(fd, &sll(ETH_P_IP, ifindex, ARPHRD_ETHER, 6, &[0xff; 6])) == Some(0),
            "bind with sll_hatype/halen/addr filled",
        )?;
        expect(
            get_int(fd, SOL_SOCKET, SO_DOMAIN)? == 17,
            "client_get_socket's SO_DOMAIN",
        )?;
        let offer = dhcp_reply(68, 2, 0x5d5d_0001);
        inject(&eth([0xff; 6], PEER_MAC, ETH_P_IP, &offer));
        let size = sys(Syscall::SocketRecv, a3(fd, 0, 0, MSG_PEEK | MSG_TRUNC));
        expect(size == Some(offer.len() as i64), "next_datagram_size_fd")?;
        let mut inq = [0u8; 4];
        expect(
            sys(Syscall::Ioctl, a2(fd, FIONREAD, inq.as_mut_ptr() as u64)) == Some(0)
                && i32::from_ne_bytes(inq) as usize == offer.len(),
            "FIONREAD fallback",
        )?;
        let mut buf = alloc::vec![0u8; offer.len()];
        let mut control = [0u8; 32 + 40];
        let m = recvmsg(fd, &mut [&mut buf], &mut control, MSG_DONTWAIT);
        expect(m.ret == Some(offer.len() as i64) && buf == offer, "recvmsg")?;
        expect(
            m.flags & MSG_CTRUNC == 0,
            "no MSG_CTRUNC (recvmsg_safe → -EXFULL)",
        )?;
        let c = cmsgs(&control, m.controllen);
        expect(
            c.iter()
                .any(|(l, t, d)| (*l, *t) == (1, 29) && d.len() == 16)
                && c.iter().any(|(l, t, _)| (*l, *t) == (263, 8)),
            "SCM_TIMESTAMP and PACKET_AUXDATA",
        )?;
        let request = dhcp_reply(67, 1, 0x5d5d_0001);
        let dest = sll(ETH_P_IP, ifindex, 0, 6, &[0xff; 6]);
        expect(
            sendmsg(
                fd,
                &[&request[..20], &request[20..28], &request[28..]],
                Some(&dest),
                MSG_NOSIGNAL,
            ) == Some(request.len() as i64),
            "sendmsg(MSG_NOSIGNAL)",
        )?;
        expect(
            captured() == [eth([0xff; 6], NIC_MAC, ETH_P_IP, &request)],
            "the request went out broadcast",
        )?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/packet",
    smoke_abi_packet_sd_dhcp_client_sequence
);

/// dhcpcd's Linux `bpf_open` / `bpf_attach` / `bpf_read` / `bpf_send`:
/// SOCK_RAW with htons(ETH_P_ALL), bind(ETH_P_ALL, ifindex) BEFORE the
/// filter, SO_ATTACH_FILTER + SO_LOCK_FILTER, PACKET_AUXDATA, recvmsg(0)
/// with a CMSG_SPACE(auxdata) buffer, writev of header + payload.
fn smoke_abi_packet_dhcpcd_sequence() -> TestResult {
    with_setup(|| {
        let ifindex = nic(true)?;
        let fd = open(
            AF_PACKET,
            SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
            u64::from(ETH_P_ALL.to_be()),
        )?;
        expect(
            bind(fd, &sll(ETH_P_ALL, ifindex, 0, 0, &[])) == Some(0),
            "bind ETH_P_ALL",
        )?;
        expect(
            attach(fd, &dhcpcd_style_filter()) == Some(0),
            "SO_ATTACH_FILTER",
        )?;
        expect(
            set_int(fd, SOL_SOCKET, SO_LOCK_FILTER, 1) == Some(0),
            "SO_LOCK_FILTER",
        )?;
        expect(
            set_int(fd, SOL_PACKET, PACKET_AUXDATA, 1) == Some(0),
            "PACKET_AUXDATA",
        )?;
        drain(fd);
        let offer = dhcp_reply(68, 2, 0xdcdc_0001);
        let frame = eth([0xff; 6], PEER_MAC, ETH_P_IP, &offer);
        inject(&eth(NIC_MAC, PEER_MAC, ETH_P_ARP, b"dhcpcd-arp-noise"));
        inject(&frame);
        let mut buf = [0u8; 1500];
        let mut control = [0u8; 40]; // CMSG_SPACE(sizeof(struct tpacket_auxdata))
        let m = recvmsg(fd, &mut [&mut buf], &mut control, 0);
        expect(
            m.ret == Some(frame.len() as i64),
            "only the DHCP frame passes",
        )?;
        expect(buf[..frame.len()] == frame[..], "the whole Ethernet frame")?;
        let c = cmsgs(&control, m.controllen);
        expect(
            c.len() == 1 && (c[0].0, c[0].1) == (263, 8),
            "PACKET_AUXDATA",
        )?;
        // bpf_send: writev(ether_header, payload).
        let request = dhcp_reply(67, 1, 0xdcdc_0001);
        let header = eth([0xff; 6], NIC_MAC, ETH_P_IP, &[]);
        let mut iov = [0u8; 32];
        iov[0..8].copy_from_slice(&(header.as_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&14u64.to_ne_bytes());
        iov[16..24].copy_from_slice(&(request.as_ptr() as u64).to_ne_bytes());
        iov[24..32].copy_from_slice(&(request.len() as u64).to_ne_bytes());
        expect(
            sys(Syscall::Writev, a2(fd, iov.as_ptr() as u64, 2)) == Some(14 + request.len() as i64),
            "writev",
        )?;
        expect(
            captured() == [eth([0xff; 6], NIC_MAC, ETH_P_IP, &request)],
            "the frame went out",
        )?;
        close(fd);
        nic_down();
        Ok(())
    })
}
kernel_test_in!("syscall_abi/packet", smoke_abi_packet_dhcpcd_sequence);
