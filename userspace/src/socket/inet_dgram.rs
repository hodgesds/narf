//! AF_INET `SOCK_DGRAM` (UDP) for userspace sockets.
//!
//! Every errno below is taken from Linux v6.12, cited `file:line`:
//!
//! - `net/ipv4/af_inet.c` — `__inet_bind`, `inet_dgram_connect`,
//!   `inet_autobind`, `inet_send_prepare`, `inet_shutdown`, `inet_getname`.
//! - `net/ipv4/datagram.c` — `__ip4_datagram_connect`.
//! - `net/ipv4/udp.c` — `udp_lib_lport_inuse`, `udp_lib_get_port`,
//!   `compute_score`, `__udp4_lib_lookup`, `udp_sendmsg`, `udp_recvmsg`,
//!   `__skb_recv_udp`, `__udp_enqueue_schedule_skb`, `__udp_disconnect`,
//!   `__udp4_lib_err`.
//! - `net/ipv4/ip_output.c` — `__ip_append_data` (the 65507-byte limit).
//! - `net/core/datagram.c` — `__skb_wait_for_more_packets`, `datagram_poll`.
//! - `net/core/sock.c` — `sock_alloc_send_pskb` (EPIPE after `SHUT_WR`).
//!
//! Lock order: [`INET_DGRAM_BOUND`] → a socket's `state` → its `options` /
//! `local_cred` / `pending_error`. Bind-conflict checks and receive-side
//! socket lookup read OTHER sockets' state while holding the table lock, so
//! nothing may take the table lock while holding a socket's `state`.

use super::*;

/// `sk_shutdown` bits (`include/net/sock.h`: `RCV_SHUTDOWN`, `SEND_SHUTDOWN`).
pub(crate) const RCV_SHUTDOWN: u8 = 1;
pub(crate) const SEND_SHUTDOWN: u8 = 2;
const SHUTDOWN_MASK: u8 = RCV_SHUTDOWN | SEND_SHUTDOWN;

/// `MSG_ERRQUEUE` (`include/linux/socket.h`).
pub const MSG_ERRQUEUE: u32 = 0x2000;
const AF_UNSPEC: u16 = 0;
const INADDR_ANY: u32 = 0;
const INADDR_LOOPBACK: u32 = 0x7F00_0001;

/// `sizeof(struct sockaddr_in) - sizeof(sa_family_t)`: the address body every
/// AF_INET bind / connect / sendto must supply at least.
pub const SOCKADDR_IN_BODY_LEN: usize = 14;

/// Charge per queued datagram on top of its payload, standing in for the
/// `sk_buff` + `skb_shared_info` part of `skb->truesize` that Linux counts
/// against `SO_RCVBUF`. An approximation — the exact figure depends on the
/// kernel config — but it keeps a flood of tiny datagrams bounded the same
/// way.
const DGRAM_TRUESIZE_OVERHEAD: usize = 576;

/// Every AF_INET datagram socket bound to a port, per `(net_ns_id, port)`,
/// newest first. Newest-first is the order `udp_lib_get_port` leaves the
/// hash chain in (`hlist_add_head_rcu`), and it decides score ties.
type InetDgramMap = BTreeMap<(u64, u16), Vec<Arc<SocketFile>>>;

/// The AF_INET datagram binding table. See the module docs for lock order.
pub(super) static INET_DGRAM_BOUND: IrqSafeSpinLock<Option<InetDgramMap>> =
    IrqSafeSpinLock::new(None);

/// What bind-conflict and receive lookup need to know about a bound socket.
#[derive(Clone, Copy)]
struct BindView {
    addr: u32,
    peer: Option<(u32, u16)>,
    dev: u32,
    reuseaddr: bool,
    reuseport: bool,
    uid: u32,
}

/// Read `s`'s binding. Call with [`INET_DGRAM_BOUND`] held.
fn view_of(s: &SocketFile) -> Option<BindView> {
    let (addr, peer) = match &*s.state.lock() {
        SocketState::InetDgram {
            local_addr, peer, ..
        } => (*local_addr, *peer),
        _ => return None,
    };
    let (dev, reuseaddr, reuseport) = {
        let o = s.options.lock();
        (o.bindtodevice_index, o.reuseaddr, o.reuseport)
    };
    Some(BindView {
        addr,
        peer,
        dev,
        reuseaddr,
        reuseport,
        uid: s.local_cred.lock().uid,
    })
}

/// `(ip, port)` out of an AF_INET / AF_UNSPEC sockaddr body whose length the
/// caller has already checked.
fn sin_of(addr: &SockAddr) -> (u32, u16) {
    let b = &addr.body;
    (
        u32::from_be_bytes([b[2], b[3], b[4], b[5]]),
        u16::from_be_bytes([b[0], b[1]]),
    )
}

/// Would binding `me` to `port` collide with a socket already there?
///
/// `udp_lib_lport_inuse` (`net/ipv4/udp.c:150`): another socket conflicts
/// unless BOTH set `SO_REUSEADDR`, or they are pinned to different devices,
/// or their addresses do not overlap (`inet_rcv_saddr_equal` with
/// `match_wildcard`, so INADDR_ANY overlaps everything); an overlapping pair
/// may still share when BOTH set `SO_REUSEPORT` and have the same uid.
fn lport_inuse(map: &InetDgramMap, ns: u64, port: u16, me: &BindView, skip: &SocketFile) -> bool {
    let Some(socks) = map.get(&(ns, port)) else {
        return false;
    };
    socks.iter().any(|other| {
        if core::ptr::eq(Arc::as_ptr(other), skip) {
            return false;
        }
        let Some(o) = view_of(other) else {
            return false;
        };
        if o.reuseaddr && me.reuseaddr {
            return false;
        }
        if o.dev != 0 && me.dev != 0 && o.dev != me.dev {
            return false;
        }
        let overlap = o.addr == me.addr || o.addr == INADDR_ANY || me.addr == INADDR_ANY;
        if !overlap {
            return false;
        }
        !(o.reuseport && me.reuseport && o.uid == me.uid)
    })
}

/// Pick an ephemeral port no socket in `ns` conflicts on.
///
/// Exhaustion is the caller's to map: `bind()` reports EADDRINUSE
/// (`udp_lib_get_port`'s `error = -EADDRINUSE`, `net/ipv4/udp.c:246`), while
/// `connect()` / `sendto()` autobind reports EAGAIN (`inet_autobind`,
/// `net/ipv4/af_inet.c:182`).
fn alloc_port(map: &InetDgramMap, ns: u64, me: &BindView, skip: &SocketFile) -> Option<u16> {
    use crate::ephemeral_port::{alloc, free, SocketProto, EPHEMERAL_COUNT};
    let mut rejected = Vec::new();
    let mut found = None;
    for _ in 0..EPHEMERAL_COUNT {
        match alloc(AF_INET, 0, SocketProto::Udp) {
            None => break,
            Some(p) if lport_inuse(map, ns, p, me, skip) => rejected.push(p),
            Some(p) => {
                found = Some(p);
                break;
            }
        }
    }
    for p in rejected {
        free(AF_INET, 0, SocketProto::Udp, p);
    }
    found
}

/// `inet->inet_num == 0`: never bound, or unhashed again by a disconnect
/// (`__udp_disconnect` zeroes the port of a socket that was autobound but
/// keeps its receive queue).
fn is_unbound(st: &SocketState) -> bool {
    matches!(
        st,
        SocketState::Fresh | SocketState::InetDgram { local_port: 0, .. }
    )
}

/// Every socket on `dport` that takes a copy of a broadcast from
/// `saddr:sport` to `daddr` — `__udp_is_mcast_sock` (`net/ipv4/udp.c:579`):
/// a connected peer must match the sender, a bound address must be the
/// destination, and a device binding must match the arrival device.
fn broadcast_targets(
    map: &InetDgramMap,
    ns: u64,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
) -> Vec<Arc<SocketFile>> {
    let Some(socks) = map.get(&(ns, dport)) else {
        return Vec::new();
    };
    socks
        .iter()
        .filter(|s| {
            let Some(v) = view_of(s) else {
                return false;
            };
            if let Some((pa, pp)) = v.peer {
                if pa != saddr || pp != sport {
                    return false;
                }
            }
            v.addr == INADDR_ANY || v.addr == daddr
        })
        .cloned()
        .collect()
}

/// Insert `sock` at the head of its port's chain.
fn hash(map: &mut InetDgramMap, ns: u64, port: u16, sock: &Arc<SocketFile>) {
    map.entry((ns, port)).or_default().insert(0, sock.clone());
}

/// Remove `sock` (and only `sock`) from its port's chain.
fn unhash(map: &mut InetDgramMap, ns: u64, port: u16, sock: &SocketFile) {
    if let Some(v) = map.get_mut(&(ns, port)) {
        v.retain(|s| !core::ptr::eq(Arc::as_ptr(s), sock));
        if v.is_empty() {
            map.remove(&(ns, port));
        }
    }
}

/// Find the socket a datagram `saddr:sport → daddr:dport` belongs to.
///
/// `__udp4_lib_lookup` (`net/ipv4/udp.c:484`) looks among sockets bound to
/// exactly `daddr` first and falls back to INADDR_ANY ones only when that
/// finds nothing. Within one pass `compute_score` (`net/ipv4/udp.c:369`)
/// rejects a connected socket whose peer is not the sender and a socket
/// pinned to another device, and adds 4 each for a matching peer address,
/// peer port and device binding; the highest score wins, the chain's first
/// entry on a tie. A `SO_REUSEPORT` group splits flows across its members by
/// a hash of the source (`inet_lookup_reuseport`).
fn lookup(
    map: &InetDgramMap,
    ns: u64,
    saddr: u32,
    sport: u16,
    daddr: u32,
    dport: u16,
    dif: u32,
) -> Option<Arc<SocketFile>> {
    let socks = map.get(&(ns, dport))?;
    let views: Vec<(Arc<SocketFile>, BindView)> = socks
        .iter()
        .filter_map(|s| view_of(s).map(|v| (s.clone(), v)))
        .collect();
    let pass = |want: u32| -> Option<Arc<SocketFile>> {
        let mut best: Option<(i32, usize)> = None;
        let mut scored = Vec::new();
        for (i, (_, v)) in views.iter().enumerate() {
            if v.addr != want {
                continue;
            }
            let mut score = 2;
            if let Some((pa, pp)) = v.peer {
                if pa != saddr || pp != sport {
                    continue;
                }
                score += 8;
            }
            if v.dev != 0 {
                if dif != 0 && v.dev != dif {
                    continue;
                }
                score += 4;
            }
            scored.push((score, i));
            if best.is_none_or(|(b, _)| score > b) {
                best = Some((score, i));
            }
        }
        let (score, i) = best?;
        let (_, v) = &views[i];
        if v.reuseport && v.peer.is_none() {
            let group: Vec<usize> = scored
                .iter()
                .filter(|(s, j)| *s == score && views[*j].1.reuseport && views[*j].1.peer.is_none())
                .map(|(_, j)| *j)
                .collect();
            if group.len() > 1 {
                let h =
                    saddr.wrapping_mul(0x9E37_79B9) ^ u32::from(sport).wrapping_mul(0x85EB_CA6B);
                return Some(views[group[(h as usize) % group.len()]].0.clone());
            }
        }
        Some(views[i].0.clone())
    };
    pass(daddr).or_else(|| {
        if daddr != INADDR_ANY {
            pass(INADDR_ANY)
        } else {
            None
        }
    })
}

/// The source address Linux's route lookup would give a datagram to `daddr`.
///
/// A local destination resolves to an `RTN_LOCAL` route whose `prefsrc` is
/// the owning interface address — 127.0.0.1 for the whole loopback /8
/// (`ip_route_output_key_hash_rcu`, `net/ipv4/route.c:2768`). Anything else
/// takes its egress interface's address; no interface at all is ENETUNREACH.
fn select_source(ns: u64, daddr: u32, dev: u32) -> Result<u32, SockError> {
    let d = daddr.to_be_bytes();
    if d[0] == 127 {
        return Ok(INADDR_LOOPBACK);
    }
    if narf_net::iface::is_local_addr_in(ns, d) {
        return Ok(daddr);
    }
    if dev != 0 {
        if let Some(i) = narf_net::iface::snapshot_all_in(ns)
            .into_iter()
            .find(|i| narf_net::iface::ifindex_of(&i.name) == Some(dev))
        {
            return Ok(u32::from_be_bytes(i.ipv4));
        }
    }
    narf_net::iface::for_dst_in(ns, d)
        .map(|i| u32::from_be_bytes(i.ipv4))
        .ok_or(SockError::NetUnreach)
}

/// Queue `pkt` on `sock`, or drop it when the receive buffer is full.
///
/// `__udp_enqueue_schedule_skb` (`net/ipv4/udp.c:1527`) drops the ARRIVING
/// datagram once `sk_rmem_alloc > sk_rcvbuf` — checked before charging, so
/// one datagram always fits — and keeps everything already queued.
fn enqueue(sock: &SocketFile, pkt: DgramPacket) -> bool {
    let rcvbuf = sock.options.lock().rcvbuf as usize;
    let charge = pkt.payload.len() + DGRAM_TRUESIZE_OVERHEAD;
    let mut st = sock.state.lock();
    let SocketState::InetDgram { inbox, rmem, .. } = &mut *st else {
        return false;
    };
    if *rmem > rcvbuf {
        return false;
    }
    *rmem += charge;
    inbox.push_back(pkt);
    drop(st);
    sock.dgram_readiness.set(narf_filesystem::POLL_IN, 0);
    sock.dgram_readiness.notify(narf_filesystem::POLL_IN);
    narf_net::readiness::notify(0);
    true
}

/// Deliver a datagram that arrived from the wire. See
/// [`super::deliver_wire_datagram`].
pub(super) fn deliver_wire(
    ns: u64,
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    payload: &[u8],
    in_ifindex: u32,
) -> bool {
    let saddr = u32::from_be_bytes(src);
    let sock = {
        let bound = INET_DGRAM_BOUND.lock();
        bound.as_ref().and_then(|m| {
            lookup(
                m,
                ns,
                saddr,
                sport,
                u32::from_be_bytes(dst),
                dport,
                in_ifindex,
            )
        })
    };
    let Some(sock) = sock else {
        return false;
    };
    enqueue(
        &sock,
        DgramPacket {
            peer_unix: None,
            sender_cred: Ucred::default(),
            peer_addr: saddr,
            peer_port: sport,
            payload: payload.to_vec(),
            fds: Vec::new(),
        },
    );
    // Consumed even when the receive buffer dropped it: a socket owns the
    // port, so the net layer must not treat the datagram as unclaimed.
    true
}

impl SocketFile {
    pub(super) fn sk_shutdown(&self) -> u8 {
        self.sk_shutdown.load(Ordering::Acquire)
    }

    /// `bind(2)` — `__inet_bind` (`net/ipv4/af_inet.c:473`).
    pub(super) fn inet_dgram_bind(self: &Arc<Self>, addr: &SockAddr) -> SocketOpResult {
        // `inet_bind_sk`: `addr_len < sizeof(struct sockaddr_in)` → EINVAL
        // (`net/ipv4/af_inet.c:453`).
        if addr.body.len() < SOCKADDR_IN_BODY_LEN {
            return SocketOpResult::Err(SockError::InvalidArg);
        }
        let (ip, port) = sin_of(addr);
        // AF_UNSPEC is accepted as AF_INET only with INADDR_ANY; any other
        // family is EAFNOSUPPORT (`net/ipv4/af_inet.c:483-489`).
        if addr.family != AF_INET && (addr.family != AF_UNSPEC || ip != INADDR_ANY) {
            return SocketOpResult::Err(SockError::AfNoSupport);
        }
        let ns = self.net_ns_id();
        // A non-local address is EADDRNOTAVAIL (`inet_addr_valid_or_nonlocal`,
        // `net/ipv4/af_inet.c:500`); INADDR_ANY, local unicast, broadcast and
        // multicast are all bindable.
        let ipb = ip.to_be_bytes();
        let bindable = ip == INADDR_ANY
            || (224..=239).contains(&ipb[0])
            || narf_net::iface::is_local_addr_in(ns, ipb)
            || narf_net::iface::is_broadcast_in(ns, ipb);
        if !bindable {
            return SocketOpResult::Err(SockError::AddrNotAvail);
        }
        let mut bound = INET_DGRAM_BOUND.lock();
        let map = bound.get_or_insert_with(BTreeMap::new);
        // Already bound (explicitly or by autobind) → EINVAL
        // (`net/ipv4/af_inet.c:522`).
        if !is_unbound(&self.state.lock()) {
            return SocketOpResult::Err(SockError::InvalidArg);
        }
        let me = {
            let o = self.options.lock();
            BindView {
                addr: ip,
                peer: None,
                dev: o.bindtodevice_index,
                reuseaddr: o.reuseaddr,
                reuseport: o.reuseport,
                uid: self.local_cred.lock().uid,
            }
        };
        let port = if port == 0 {
            match alloc_port(map, ns, &me, self) {
                Some(p) => p,
                None => return SocketOpResult::Err(SockError::AddrInUse),
            }
        } else if lport_inuse(map, ns, port, &me, self) {
            return SocketOpResult::Err(SockError::AddrInUse);
        } else {
            port
        };
        let explicit_port = sin_of(addr).1 != 0;
        self.install_binding(ip, port, ip != INADDR_ANY, explicit_port);
        hash(map, ns, port, self);
        SocketOpResult::Ok(0)
    }

    /// Record a binding, keeping the receive queue (and the connected peer)
    /// of a socket a disconnect had unhashed.
    fn install_binding(&self, addr: u32, port: u16, addr_locked: bool, port_locked: bool) {
        let mut st = self.state.lock();
        if let SocketState::InetDgram {
            local_addr,
            local_port,
            addr_locked: al,
            port_locked: pl,
            ..
        } = &mut *st
        {
            *local_addr = addr;
            *local_port = port;
            *al = addr_locked;
            *pl = port_locked;
            return;
        }
        *st = SocketState::InetDgram {
            local_addr: addr,
            local_port: port,
            inbox: VecDeque::new(),
            peer: None,
            addr_locked,
            port_locked,
            rmem: 0,
        };
    }

    /// Autobind an unbound socket to INADDR_ANY and an ephemeral port
    /// (`inet_autobind`, `net/ipv4/af_inet.c:174`). Call with the table
    /// locked. Failure is EAGAIN (`net/ipv4/af_inet.c:182`, `:840`).
    fn inet_dgram_autobind(self: &Arc<Self>, map: &mut InetDgramMap) -> Result<(), SockError> {
        // An autobind keeps an address the socket already has (bound
        // without a port, or kept across a disconnect).
        let (addr, addr_locked) = {
            let st = self.state.lock();
            if !is_unbound(&st) {
                return Ok(());
            }
            match &*st {
                SocketState::InetDgram {
                    local_addr,
                    addr_locked,
                    ..
                } => (*local_addr, *addr_locked),
                _ => (INADDR_ANY, false),
            }
        };
        let ns = self.net_ns_id();
        let me = {
            let o = self.options.lock();
            BindView {
                addr,
                peer: None,
                dev: o.bindtodevice_index,
                reuseaddr: o.reuseaddr,
                reuseport: o.reuseport,
                uid: self.local_cred.lock().uid,
            }
        };
        let port = alloc_port(map, ns, &me, self).ok_or(SockError::WouldBlock)?;
        self.install_binding(addr, port, addr_locked, false);
        hash(map, ns, port, self);
        Ok(())
    }

    /// `connect(2)` — `inet_dgram_connect` (`net/ipv4/af_inet.c:570`) then
    /// `__ip4_datagram_connect` (`net/ipv4/datagram.c:19`).
    pub(super) fn inet_dgram_connect(self: &Arc<Self>, addr: &SockAddr) -> SocketOpResult {
        // AF_UNSPEC dissolves the association (`net/ipv4/af_inet.c:583`);
        // the sa_family-only length check before it is enforced by the
        // syscall's sockaddr import.
        if addr.family == AF_UNSPEC {
            self.inet_dgram_disconnect();
            return SocketOpResult::Ok(0);
        }
        // `__ip4_datagram_connect`: short address → EINVAL, wrong family →
        // EAFNOSUPPORT (`net/ipv4/datagram.c:30-34`).
        if addr.body.len() < SOCKADDR_IN_BODY_LEN {
            return SocketOpResult::Err(SockError::InvalidArg);
        }
        if addr.family != AF_INET {
            return SocketOpResult::Err(SockError::AfNoSupport);
        }
        let (ip, port) = sin_of(addr);
        let ns = self.net_ns_id();
        {
            let mut bound = INET_DGRAM_BOUND.lock();
            let map = bound.get_or_insert_with(BTreeMap::new);
            if let Err(e) = self.inet_dgram_autobind(map) {
                return SocketOpResult::Err(e);
            }
        }
        // The route lookup below takes the interface registry's lock, so it
        // runs with the binding table released.
        let (dev, broadcast) = {
            let o = self.options.lock();
            (o.bindtodevice_index, o.broadcast)
        };
        let src = match select_source(ns, ip, dev) {
            Ok(s) => s,
            Err(e) => return SocketOpResult::Err(e),
        };
        // A broadcast route without SO_BROADCAST → EACCES
        // (`net/ipv4/datagram.c:59-62`).
        if narf_net::iface::is_broadcast_in(ns, ip.to_be_bytes()) && !broadcast {
            return SocketOpResult::Err(SockError::Access);
        }
        let mut st = self.state.lock();
        if let SocketState::InetDgram {
            local_addr, peer, ..
        } = &mut *st
        {
            // An unbound local address takes the route's source
            // (`net/ipv4/datagram.c:64-70`).
            if *local_addr == INADDR_ANY {
                *local_addr = src;
            }
            *peer = Some((ip, port));
        }
        SocketOpResult::Ok(0)
    }

    /// `__udp_disconnect` (`net/ipv4/udp.c:1938`): forget the peer and the
    /// device binding, give back an address or port the socket did not bind
    /// explicitly, and unhash an autobound socket entirely.
    fn inet_dgram_disconnect(self: &Arc<Self>) {
        let ns = self.net_ns_id();
        let mut bound = INET_DGRAM_BOUND.lock();
        let freed_port = {
            let mut st = self.state.lock();
            let SocketState::InetDgram {
                local_addr,
                local_port,
                peer,
                addr_locked,
                port_locked,
                ..
            } = &mut *st
            else {
                return;
            };
            *peer = None;
            if !*addr_locked {
                *local_addr = INADDR_ANY;
            }
            if *port_locked || *local_port == 0 {
                None
            } else {
                let p = *local_port;
                *local_port = 0;
                Some(p)
            }
        };
        {
            let mut o = self.options.lock();
            o.bindtodevice_index = 0;
            o.bindtodevice = None;
        }
        if let Some(p) = freed_port {
            if let Some(map) = bound.as_mut() {
                unhash(map, ns, p, self);
            }
            crate::ephemeral_port::free(AF_INET, 0, crate::ephemeral_port::SocketProto::Udp, p);
        }
    }

    /// `sendto(2)` / `send(2)` — `inet_sendmsg` → `udp_sendmsg`
    /// (`net/ipv4/udp.c:1059`), checks in Linux's order.
    pub(super) fn inet_dgram_send(
        self: &Arc<Self>,
        buf: &[u8],
        flags: u32,
        addr: Option<&SockAddr>,
    ) -> SocketOpResult {
        let ns = self.net_ns_id();
        // `inet_send_prepare` autobinds first; failure → EAGAIN
        // (`net/ipv4/af_inet.c:838-840`).
        {
            let mut bound = INET_DGRAM_BOUND.lock();
            let map = bound.get_or_insert_with(BTreeMap::new);
            if let Err(e) = self.inet_dgram_autobind(map) {
                return SocketOpResult::Err(e);
            }
        }
        // `len > 0xFFFF` → EMSGSIZE (`net/ipv4/udp.c:1081`).
        if buf.len() > 0xFFFF {
            return SocketOpResult::Err(SockError::MsgSize);
        }
        // MSG_OOB → EOPNOTSUPP (`net/ipv4/udp.c:1088`).
        if flags & MSG_OOB != 0 {
            return SocketOpResult::Err(SockError::NotSupported);
        }
        let (local_addr, local_port, connected) = match &*self.state.lock() {
            SocketState::InetDgram {
                local_addr,
                local_port,
                peer,
                ..
            } => (*local_addr, *local_port, *peer),
            _ => return SocketOpResult::Err(SockError::InvalidArg),
        };
        let dest = match addr {
            Some(a) => {
                // `msg_namelen < sizeof(*usin)` → EINVAL; a family other
                // than AF_INET / AF_UNSPEC → EAFNOSUPPORT; port 0 → EINVAL
                // (`net/ipv4/udp.c:1115-1125`).
                if a.body.len() < SOCKADDR_IN_BODY_LEN {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                if a.family != AF_INET && a.family != AF_UNSPEC {
                    return SocketOpResult::Err(SockError::AfNoSupport);
                }
                let (ip, port) = sin_of(a);
                if port == 0 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                (ip, port)
            }
            // Not connected and no address → EDESTADDRREQ
            // (`net/ipv4/udp.c:1127-1128`).
            None => match connected {
                Some(p) => p,
                None => return SocketOpResult::Err(SockError::DestAddrReq),
            },
        };
        let (dev, broadcast, ip_ttl, ip_tos) = {
            let o = self.options.lock();
            (o.bindtodevice_index, o.broadcast, o.ip_ttl, o.ip_tos)
        };
        // Route lookup: no route → ENETUNREACH (`net/ipv4/udp.c:1238-1244`);
        // a broadcast route without SO_BROADCAST → EACCES
        // (`net/ipv4/udp.c:1247-1250`).
        let src = match select_source(ns, dest.0, dev) {
            Ok(s) => s,
            Err(e) => return SocketOpResult::Err(e),
        };
        let dest_is_broadcast = narf_net::iface::is_broadcast_in(ns, dest.0.to_be_bytes());
        if dest_is_broadcast && !broadcast {
            return SocketOpResult::Err(SockError::Access);
        }
        // `__ip_append_data`: more than IP_MAX_MTU - iphdr - udphdr = 65507
        // payload bytes → EMSGSIZE (`net/ipv4/ip_output.c:992-995`).
        if buf.len() > narf_net::udp_sock::UDP_MAX_PAYLOAD {
            return SocketOpResult::Err(SockError::MsgSize);
        }
        // `sock_alloc_send_pskb` reports a pending socket error first, then
        // EPIPE after SHUT_WR (`net/core/sock.c:2869-2875`).
        if let Some(e) = self.take_pending_error() {
            return SocketOpResult::Err(e);
        }
        if self.sk_shutdown() & SEND_SHUTDOWN != 0 {
            return SocketOpResult::Err(SockError::Pipe);
        }
        let from = if local_addr == INADDR_ANY {
            src
        } else {
            local_addr
        };

        // A local destination is looped back in-process; everything else
        // leaves on the wire.
        let dest_local = dest.0.to_be_bytes()[0] == 127
            || narf_net::iface::is_local_addr_in(ns, dest.0.to_be_bytes());
        if dest_is_broadcast {
            // A broadcast route's output (`ip_mc_output`,
            // `net/ipv4/ip_output.c:413`) loops a clone back to this host,
            // where every matching socket on the port gets a copy.
            let targets = {
                let bound = INET_DGRAM_BOUND.lock();
                bound
                    .as_ref()
                    .map(|m| broadcast_targets(m, ns, from, local_port, dest.0, dest.1))
                    .unwrap_or_default()
            };
            for t in targets {
                enqueue(
                    &t,
                    DgramPacket {
                        peer_unix: None,
                        sender_cred: Ucred::default(),
                        peer_addr: from,
                        peer_port: local_port,
                        payload: buf.to_vec(),
                        fds: Vec::new(),
                    },
                );
            }
        }
        if !dest_local || dest_is_broadcast {
            let udp_opts = narf_net::udp_sock::UdpOptions {
                broadcast,
                bind_to_device: dev,
                ip_ttl: ip_ttl.min(255) as u8,
                ip_tos: ip_tos.min(255) as u8,
                sndbuf: narf_net::udp_sock::UDP_MAX_PAYLOAD,
                ..Default::default()
            };
            let dst = narf_net::udp_sock::SocketAddrV4::new(dest.0.to_be_bytes(), dest.1);
            return match narf_net::udp_sock::udp_send_from(
                ns, local_port, dst, buf, &udp_opts, // Never block a sendto on ARP.
                0,
            ) {
                Ok(n) => SocketOpResult::Ok(n as u64),
                Err(narf_net::udp_sock::UdpError::NoBroadcastPermission) => {
                    SocketOpResult::Err(SockError::Access)
                }
                Err(narf_net::udp_sock::UdpError::MsgTooLong) => {
                    SocketOpResult::Err(SockError::MsgSize)
                }
                // An unresolved neighbour is not an error to the caller:
                // Linux queues the skb on the neighbour and returns success
                // (`neigh_resolve_output`), so report the bytes as sent.
                Err(narf_net::udp_sock::UdpError::NetworkUnreachable) => {
                    SocketOpResult::Ok(buf.len() as u64)
                }
                Err(_) => SocketOpResult::Err(SockError::NetUnreach),
            };
        }

        let dest_sock = {
            let bound = INET_DGRAM_BOUND.lock();
            bound
                .as_ref()
                .and_then(|m| lookup(m, ns, from, local_port, dest.0, dest.1, 0))
        };
        match dest_sock {
            Some(d) => {
                enqueue(
                    &d,
                    DgramPacket {
                        peer_unix: None,
                        sender_cred: Ucred::default(),
                        peer_addr: from,
                        peer_port: local_port,
                        payload: buf.to_vec(),
                        fds: Vec::new(),
                    },
                );
            }
            None => {
                // Nobody owns the port: the loopback answers with ICMP
                // port-unreachable, which `__udp4_lib_err` turns into
                // ECONNREFUSED on the sender only when it is connected to
                // that destination (`net/ipv4/udp.c:802-808`; the code's
                // errno is `icmp_err_convert[ICMP_PORT_UNREACH]`,
                // `net/ipv4/icmp.c:134`). The send itself succeeds.
                if connected == Some(dest) {
                    self.set_pending_error(SockError::ConnectionRefused);
                    self.dgram_readiness.notify(narf_filesystem::POLL_ERR);
                    narf_net::readiness::notify(0);
                }
            }
        }
        SocketOpResult::Ok(buf.len() as u64)
    }

    /// `recv(2)` family — `udp_recvmsg` (`net/ipv4/udp.c:1816`).
    pub(super) fn inet_dgram_recv(&self, buf: &mut [u8], flags: u32) -> SocketOpResult {
        // NARF keeps no ICMP error queue, so MSG_ERRQUEUE always finds it
        // empty: `ip_recv_error` → EAGAIN (`net/ipv4/ip_sockglue.c:535`).
        // The syscall layer treats this as non-blocking.
        if flags & MSG_ERRQUEUE != 0 {
            return SocketOpResult::Err(SockError::WouldBlock);
        }
        // `__skb_recv_udp` reports a pending socket error before looking at
        // the queue (`net/ipv4/udp.c:1729`).
        if let Some(e) = self.take_pending_error() {
            return SocketOpResult::Err(e);
        }
        let peek = flags & MSG_PEEK != 0;
        {
            let mut st = self.state.lock();
            if let SocketState::InetDgram { inbox, rmem, .. } = &mut *st {
                if let Some(front) = inbox.front() {
                    let full_len = front.payload.len();
                    let n = core::cmp::min(buf.len(), full_len);
                    buf[..n].copy_from_slice(&front.payload[..n]);
                    let peer = Some(make_sockaddr_in(front.peer_addr, front.peer_port));
                    if !peek {
                        inbox.pop_front();
                        *rmem = rmem.saturating_sub(full_len + DGRAM_TRUESIZE_OVERHEAD);
                    }
                    // `copied < ulen` sets MSG_TRUNC and `flags & MSG_TRUNC`
                    // returns the datagram's real length
                    // (`net/ipv4/udp.c:1840-1841`, `:1905-1906`); the
                    // syscall layer applies both from this.
                    if n < full_len {
                        return SocketOpResult::ReceivedTruncated {
                            copied: n,
                            full_len,
                            peer,
                        };
                    }
                    return SocketOpResult::Received { n, peer };
                }
            }
        }
        // Empty queue. After SHUT_RD the wait returns 0 instead of blocking
        // (`__skb_wait_for_more_packets`, `net/core/datagram.c:104-105`);
        // otherwise EAGAIN / block. An unbound socket is no different — UDP
        // is not connection-based, so there is no ENOTCONN
        // (`net/core/datagram.c:110-113`).
        if self.sk_shutdown() & RCV_SHUTDOWN != 0 {
            return SocketOpResult::Received { n: 0, peer: None };
        }
        SocketOpResult::Err(SockError::WouldBlock)
    }

    /// `shutdown(2)` — `inet_shutdown` (`net/ipv4/af_inet.c:893`).
    pub(super) fn inet_dgram_shutdown(&self, how: u32) -> SocketOpResult {
        // `how++` maps SHUT_RD/WR/RDWR onto the RCV/SEND bits; anything
        // else is EINVAL (`net/ipv4/af_inet.c:901-905`).
        if how > 2 {
            return SocketOpResult::Err(SockError::InvalidArg);
        }
        let bits = (how + 1) as u8 & SHUTDOWN_MASK;
        self.sk_shutdown.fetch_or(bits, Ordering::AcqRel);
        // Wake anyone parked on the socket: a reader must see EOF
        // (`sk_state_change`, `net/ipv4/af_inet.c:943`).
        self.dgram_readiness.set(narf_filesystem::POLL_IN, 0);
        self.dgram_readiness.notify(narf_filesystem::POLL_IN);
        narf_net::readiness::notify(0);
        // An unconnected UDP socket is `TCP_CLOSE`: the bits are still set
        // but the call reports ENOTCONN (`net/ipv4/af_inet.c:917-923`).
        let connected = matches!(
            &*self.state.lock(),
            SocketState::InetDgram { peer: Some(_), .. }
        );
        if connected {
            SocketOpResult::Ok(0)
        } else {
            SocketOpResult::Err(SockError::NotConnected)
        }
    }

    /// Poll bits for an AF_INET datagram socket — `datagram_poll`
    /// (`net/core/datagram.c:882`).
    pub(super) fn inet_dgram_poll_bits(&self, readable: bool) -> u32 {
        let mut bits = narf_filesystem::POLL_OUT;
        if readable {
            bits |= narf_filesystem::POLL_IN;
        }
        if self.pending_error.lock().is_some() {
            bits |= narf_filesystem::POLL_ERR;
        }
        let shut = self.sk_shutdown();
        if shut & RCV_SHUTDOWN != 0 {
            bits |= narf_filesystem::POLL_IN;
        }
        if shut == SHUTDOWN_MASK {
            bits |= narf_filesystem::POLL_HUP;
        }
        bits
    }

    /// Drop this socket's binding on close.
    pub(super) fn inet_dgram_unregister(&self, port: u16, port_locked: bool) {
        let ns = self.net_ns_id();
        if let Some(map) = INET_DGRAM_BOUND.lock().as_mut() {
            unhash(map, ns, port, self);
        }
        if !port_locked {
            crate::ephemeral_port::free(AF_INET, 0, crate::ephemeral_port::SocketProto::Udp, port);
        }
    }
}
