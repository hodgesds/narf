//! AF_INET6 `SOCK_DGRAM` compatibility state.
//!
//! This module owns native 128-bit bind/connect/demux state. It intentionally
//! does not encode IPv4-mapped addresses as IPv4 entries: `IPV6_V6ONLY` and
//! dual-stack wildcard arbitration are policy layered over this table.

use super::*;

const UNSPEC: [u8; 16] = [0; 16];
const LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DGRAM_TRUESIZE_OVERHEAD: usize = 576;

type Inet6DgramMap = BTreeMap<(u64, u16), Vec<Arc<SocketFile>>>;
static INET6_DGRAM_BOUND: IrqSafeSpinLock<Option<Inet6DgramMap>> = IrqSafeSpinLock::new(None);

type Inet6Peer = ([u8; 16], u16, u32);

fn state_view(sock: &SocketFile) -> Option<([u8; 16], u32, Option<Inet6Peer>)> {
    match &*sock.state.lock() {
        SocketState::Inet6Dgram {
            local_addr,
            local_scope_id,
            peer,
            ..
        } => Some((*local_addr, *local_scope_id, *peer)),
        _ => None,
    }
}

fn conflicts(map: &Inet6DgramMap, ns: u64, port: u16, addr: [u8; 16], me: &SocketFile) -> bool {
    let (my_reuseaddr, my_reuseport, my_uid) = {
        let o = me.options.lock();
        (o.reuseaddr, o.reuseport, me.local_cred.lock().uid)
    };
    map.get(&(ns, port)).is_some_and(|socks| {
        socks.iter().any(|other| {
            if core::ptr::eq(Arc::as_ptr(other), me) {
                return false;
            }
            let Some((other_addr, _, _)) = state_view(other) else {
                return false;
            };
            let o = other.options.lock();
            if o.reuseaddr && my_reuseaddr {
                return false;
            }
            let overlap = addr == UNSPEC || other_addr == UNSPEC || addr == other_addr;
            overlap && !(o.reuseport && my_reuseport && other.local_cred.lock().uid == my_uid)
        })
    })
}

fn alloc_port(map: &Inet6DgramMap, ns: u64, me: &SocketFile) -> Option<u16> {
    use crate::ephemeral_port::{alloc, free, SocketProto, EPHEMERAL_COUNT};
    let mut rejected = Vec::new();
    for _ in 0..EPHEMERAL_COUNT {
        let port = alloc(AF_INET6, 0, SocketProto::Udp)?;
        if conflicts(map, ns, port, UNSPEC, me) {
            rejected.push(port);
        } else {
            for p in rejected {
                free(AF_INET6, 0, SocketProto::Udp, p);
            }
            return Some(port);
        }
    }
    for p in rejected {
        free(AF_INET6, 0, SocketProto::Udp, p);
    }
    None
}

fn lookup(
    map: &Inet6DgramMap,
    ns: u64,
    src: [u8; 16],
    sport: u16,
    dst: [u8; 16],
    dport: u16,
    dif: u32,
) -> Option<Arc<SocketFile>> {
    let socks = map.get(&(ns, dport))?;
    for wanted in [dst, UNSPEC] {
        if let Some(found) = socks.iter().find(|sock| {
            let bound_dev = sock.options.lock().bindtodevice_index;
            (bound_dev == 0 || dif == 0 || bound_dev == dif)
                && state_view(sock).is_some_and(|(local, scope, peer)| {
                    local == wanted
                        && (scope == 0 || dif == 0 || scope == dif)
                        && peer.is_none_or(|p| {
                            p.0 == src && p.1 == sport && (p.2 == 0 || dif == 0 || p.2 == dif)
                        })
                })
        }) {
            return Some(found.clone());
        }
        if wanted == UNSPEC {
            break;
        }
    }
    None
}

impl SocketFile {
    pub(super) fn dispatch_inet6_dgram(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => self.inet6_dgram_bind(&addr),
            SocketOp::Connect { addr } => self.inet6_dgram_connect(&addr),
            SocketOp::Send { buf, flags, addr } => self.inet6_dgram_send(buf, flags, addr.as_ref()),
            SocketOp::Recv { buf, flags } => self.inet6_dgram_recv(buf, flags),
            SocketOp::Listen { .. } | SocketOp::Accept => {
                SocketOpResult::Err(SockError::NotSupported)
            }
            SocketOp::Shutdown { how } => self.inet_dgram_shutdown(how),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    fn install_inet6_binding(&self, addr: [u8; 16], port: u16, scope_id: u32, port_locked: bool) {
        let old_peer = match &*self.state.lock() {
            SocketState::Inet6Dgram { peer, .. } => *peer,
            _ => None,
        };
        *self.state.lock() = SocketState::Inet6Dgram {
            local_addr: addr,
            local_port: port,
            local_scope_id: scope_id,
            inbox: VecDeque::new(),
            peer: old_peer,
            port_locked,
            rmem: 0,
        };
    }

    fn inet6_dgram_autobind(self: &Arc<Self>, map: &mut Inet6DgramMap) -> Result<(), SockError> {
        if matches!(&*self.state.lock(), SocketState::Inet6Dgram { local_port, .. } if *local_port != 0)
        {
            return Ok(());
        }
        let port = alloc_port(map, self.net_ns_id(), self).ok_or(SockError::WouldBlock)?;
        self.install_inet6_binding(UNSPEC, port, 0, false);
        map.entry((self.net_ns_id(), port))
            .or_default()
            .insert(0, self.clone());
        Ok(())
    }

    fn inet6_dgram_bind(self: &Arc<Self>, addr: &SockAddr) -> SocketOpResult {
        let (ip, requested_port, scope_id) = match inet6_sockaddr_scoped(addr) {
            Ok(v) => v,
            Err(e) => return SocketOpResult::Err(e),
        };
        if !matches!(&*self.state.lock(), SocketState::Fresh) {
            return SocketOpResult::Err(SockError::InvalidArg);
        }
        if inet_port_denied(requested_port) {
            return SocketOpResult::Err(SockError::Access);
        }
        if ip != UNSPEC && ip != LOOPBACK && !narf_net::ipv6::addrs::is_local(&ip) {
            return SocketOpResult::Err(SockError::AddrNotAvail);
        }
        let ns = self.net_ns_id();
        let mut guard = INET6_DGRAM_BOUND.lock();
        let map = guard.get_or_insert_with(BTreeMap::new);
        let port = if requested_port == 0 {
            match alloc_port(map, ns, self) {
                Some(p) => p,
                None => return SocketOpResult::Err(SockError::AddrInUse),
            }
        } else {
            if conflicts(map, ns, requested_port, ip, self) {
                return SocketOpResult::Err(SockError::AddrInUse);
            }
            requested_port
        };
        self.install_inet6_binding(ip, port, scope_id, requested_port != 0);
        map.entry((ns, port)).or_default().insert(0, self.clone());
        SocketOpResult::Ok(0)
    }

    fn inet6_dgram_connect(self: &Arc<Self>, addr: &SockAddr) -> SocketOpResult {
        if addr.family == AF_UNSPEC {
            if let SocketState::Inet6Dgram { peer, .. } = &mut *self.state.lock() {
                *peer = None;
            }
            return SocketOpResult::Ok(0);
        }
        let peer = match inet6_sockaddr_scoped(addr) {
            Ok((_, 0, _)) => return SocketOpResult::Err(SockError::InvalidArg),
            Ok(v) => v,
            Err(e) => return SocketOpResult::Err(e),
        };
        {
            let mut guard = INET6_DGRAM_BOUND.lock();
            let map = guard.get_or_insert_with(BTreeMap::new);
            if let Err(e) = self.inet6_dgram_autobind(map) {
                return SocketOpResult::Err(e);
            }
        }
        if let SocketState::Inet6Dgram { peer: slot, .. } = &mut *self.state.lock() {
            *slot = Some(peer);
        }
        SocketOpResult::Ok(0)
    }

    fn inet6_dgram_send(
        self: &Arc<Self>,
        buf: &[u8],
        flags: u32,
        addr: Option<&SockAddr>,
    ) -> SocketOpResult {
        {
            let mut guard = INET6_DGRAM_BOUND.lock();
            let map = guard.get_or_insert_with(BTreeMap::new);
            if let Err(e) = self.inet6_dgram_autobind(map) {
                return SocketOpResult::Err(e);
            }
        }
        if buf.len() > 65_527 {
            return SocketOpResult::Err(SockError::MsgSize);
        }
        if flags & MSG_OOB != 0 {
            return SocketOpResult::Err(SockError::NotSupported);
        }
        let (local, local_port, connected) = match &*self.state.lock() {
            SocketState::Inet6Dgram {
                local_addr,
                local_port,
                peer,
                ..
            } => (*local_addr, *local_port, *peer),
            _ => return SocketOpResult::Err(SockError::InvalidArg),
        };
        let dest = match addr {
            Some(a) => match inet6_sockaddr_scoped(a) {
                Ok((_, 0, _)) => return SocketOpResult::Err(SockError::InvalidArg),
                Ok(v) => v,
                Err(e) => return SocketOpResult::Err(e),
            },
            None => match connected {
                Some(p) => p,
                None => return SocketOpResult::Err(SockError::DestAddrReq),
            },
        };
        if self.sk_shutdown() & inet_dgram::SEND_SHUTDOWN != 0 {
            return SocketOpResult::Err(SockError::Pipe);
        }
        let is_local = dest.0 == LOOPBACK || narf_net::ipv6::addrs::is_local(&dest.0);
        if !is_local {
            let bound_ifindex = if dest.2 != 0 {
                dest.2
            } else {
                self.options.lock().bindtodevice_index
            };
            return match narf_net::ipv6_stack::send_udp(
                self.net_ns_id(),
                (local != UNSPEC).then_some(local),
                local_port,
                dest.0,
                dest.1,
                buf,
                bound_ifindex,
                64,
            ) {
                Ok(n) => SocketOpResult::Ok(n as u64),
                Err(narf_net::ipv6_stack::Udp6SendError::MessageTooLong) => {
                    SocketOpResult::Err(SockError::MsgSize)
                }
                // Linux queues the skb while neighbour discovery runs and
                // reports the datagram as accepted to sendmsg.
                Err(narf_net::ipv6_stack::Udp6SendError::NeighborPending) => {
                    SocketOpResult::Ok(buf.len() as u64)
                }
                Err(narf_net::ipv6_stack::Udp6SendError::NoSourceAddress) => {
                    SocketOpResult::Err(SockError::AddrNotAvail)
                }
                Err(_) => SocketOpResult::Err(SockError::NetUnreach),
            };
        }
        let source = if local == UNSPEC { LOOPBACK } else { local };
        let target = {
            let guard = INET6_DGRAM_BOUND.lock();
            guard.as_ref().and_then(|m| {
                lookup(
                    m,
                    self.net_ns_id(),
                    source,
                    local_port,
                    dest.0,
                    dest.1,
                    dest.2,
                )
            })
        };
        if let Some(target) = target {
            let mut state = target.state.lock();
            if let SocketState::Inet6Dgram { inbox, rmem, .. } = &mut *state {
                let charge = buf.len() + DGRAM_TRUESIZE_OVERHEAD;
                if rmem.saturating_add(charge) <= target.options.lock().rcvbuf as usize {
                    inbox.push_back(DgramPacket6 {
                        peer_addr: source,
                        peer_port: local_port,
                        scope_id: dest.2,
                        payload: buf.to_vec(),
                    });
                    *rmem += charge;
                    target.dgram_readiness.set(narf_filesystem::POLL_IN, 0);
                    target.dgram_readiness.notify(narf_filesystem::POLL_IN);
                }
            }
        } else if connected == Some(dest) {
            self.set_pending_error(SockError::ConnectionRefused);
        }
        SocketOpResult::Ok(buf.len() as u64)
    }

    fn inet6_dgram_recv(&self, buf: &mut [u8], flags: u32) -> SocketOpResult {
        if flags & MSG_ERRQUEUE != 0 {
            return SocketOpResult::Err(SockError::WouldBlock);
        }
        if let Some(e) = self.take_pending_error() {
            return SocketOpResult::Err(e);
        }
        let peek = flags & MSG_PEEK != 0;
        let mut state = self.state.lock();
        if let SocketState::Inet6Dgram { inbox, rmem, .. } = &mut *state {
            if let Some(packet) = inbox.front() {
                let full_len = packet.payload.len();
                let n = buf.len().min(full_len);
                buf[..n].copy_from_slice(&packet.payload[..n]);
                let peer = Some(make_sockaddr_in6_scoped(
                    packet.peer_addr,
                    packet.peer_port,
                    packet.scope_id,
                ));
                if !peek {
                    inbox.pop_front();
                    *rmem = rmem.saturating_sub(full_len + DGRAM_TRUESIZE_OVERHEAD);
                }
                return if n < full_len {
                    SocketOpResult::ReceivedTruncated {
                        copied: n,
                        full_len,
                        peer,
                    }
                } else {
                    SocketOpResult::Received { n, peer }
                };
            }
        }
        if self.sk_shutdown() & inet_dgram::RCV_SHUTDOWN != 0 {
            SocketOpResult::Received { n: 0, peer: None }
        } else {
            SocketOpResult::Err(SockError::WouldBlock)
        }
    }

    pub(super) fn inet6_dgram_unregister(&self, port: u16, port_locked: bool) {
        let ns = self.net_ns_id();
        if let Some(map) = INET6_DGRAM_BOUND.lock().as_mut() {
            if let Some(socks) = map.get_mut(&(ns, port)) {
                socks.retain(|s| !core::ptr::eq(Arc::as_ptr(s), self));
                if socks.is_empty() {
                    map.remove(&(ns, port));
                }
            }
        }
        if port != 0 && !port_locked {
            crate::ephemeral_port::free(AF_INET6, 0, crate::ephemeral_port::SocketProto::Udp, port);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn deliver_wire(
    net_ns_id: u64,
    src_ip: [u8; 16],
    src_port: u16,
    dst_ip: [u8; 16],
    dst_port: u16,
    payload: &[u8],
    in_ifindex: u32,
) -> bool {
    let target = {
        let guard = INET6_DGRAM_BOUND.lock();
        guard.as_ref().and_then(|map| {
            lookup(
                map, net_ns_id, src_ip, src_port, dst_ip, dst_port, in_ifindex,
            )
        })
    };
    let Some(target) = target else {
        return false;
    };
    let mut state = target.state.lock();
    let SocketState::Inet6Dgram { inbox, rmem, .. } = &mut *state else {
        return false;
    };
    let charge = payload.len() + DGRAM_TRUESIZE_OVERHEAD;
    if rmem.saturating_add(charge) > target.options.lock().rcvbuf as usize {
        return true;
    }
    inbox.push_back(DgramPacket6 {
        peer_addr: src_ip,
        peer_port: src_port,
        scope_id: in_ifindex,
        payload: payload.to_vec(),
    });
    *rmem += charge;
    target.dgram_readiness.set(narf_filesystem::POLL_IN, 0);
    target.dgram_readiness.notify(narf_filesystem::POLL_IN);
    true
}
