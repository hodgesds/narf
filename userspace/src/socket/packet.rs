//! AF_PACKET socket operations: the `packet_ops` / `packet_ops_spkt`
//! proto_ops of Linux `net/packet/af_packet.c`, on top of the kernel state
//! and delivery in `narf_net::raw_sock`.
//!
//! This layer owns what crosses the syscall boundary: `sockaddr_ll` /
//! `sockaddr_pkt` encoding, `SOL_PACKET` options, the per-receive ancillary
//! data (`PACKET_AUXDATA`, receive timestamps) and the `sock_no_*` errnos.

use super::*;

use narf_net::raw_sock::{self as packet, PacketSock};

/// `AF_PACKET` / `PF_PACKET`.
pub const AF_PACKET: u16 = 17;
/// `SOCK_PACKET` (obsolete `packet_ops_spkt` sockets).
pub const SOCK_PACKET: u32 = 10;
/// `SOL_PACKET`.
pub const SOL_PACKET: u32 = 263;

pub const PACKET_ADD_MEMBERSHIP: u32 = 1;
pub const PACKET_DROP_MEMBERSHIP: u32 = 2;
pub const PACKET_RX_RING: u32 = 5;
pub const PACKET_STATISTICS: u32 = 6;
pub const PACKET_COPY_THRESH: u32 = 7;
pub const PACKET_AUXDATA: u32 = 8;
pub const PACKET_ORIGDEV: u32 = 9;
pub const PACKET_VERSION: u32 = 10;
pub const PACKET_HDRLEN: u32 = 11;
pub const PACKET_RESERVE: u32 = 12;
pub const PACKET_TX_RING: u32 = 13;
pub const PACKET_LOSS: u32 = 14;
pub const PACKET_VNET_HDR: u32 = 15;
pub const PACKET_TIMESTAMP: u32 = 17;
pub const PACKET_FANOUT: u32 = 18;
pub const PACKET_TX_HAS_OFF: u32 = 19;
pub const PACKET_QDISC_BYPASS: u32 = 20;
pub const PACKET_ROLLOVER_STATS: u32 = 21;
pub const PACKET_FANOUT_DATA: u32 = 22;
pub const PACKET_IGNORE_OUTGOING: u32 = 23;
pub const PACKET_VNET_HDR_SZ: u32 = 24;

/// `TPACKET_V1..V3`.
const TPACKET_V1: i32 = 0;
const TPACKET_V2: i32 = 1;
const TPACKET_V3: i32 = 2;

/// `TP_STATUS_*` bits reported in `tpacket_auxdata.tp_status`.
pub const TP_STATUS_USER: u32 = 1 << 0;
pub const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
pub const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;

/// `sizeof(struct packet_mreq)` and `sizeof(struct packet_mreq_max)`.
const PACKET_MREQ_LEN: usize = 16;
const PACKET_MREQ_MAX_LEN: usize = 8 + packet::MAX_ADDR_LEN;

/// `sizeof(struct virtio_net_hdr)` / `struct virtio_net_hdr_mrg_rxbuf`.
const VIRTIO_NET_HDR_LEN: i32 = 10;
const VIRTIO_NET_HDR_MRG_RXBUF_LEN: i32 = 12;

/// Flags `packet_recvmsg` accepts.
const MSG_DONTWAIT: u32 = 0x40;
const MSG_CMSG_COMPAT: u32 = 0x8000_0000;

/// The ancillary data one packet receive produced, held between the
/// dequeue in `dispatch_op(Recv)` and the recvmsg syscall that reports it.
#[derive(Clone, Debug)]
pub(crate) struct PacketRecvAncillary {
    /// `struct tpacket_auxdata` (20 bytes) when `PACKET_AUXDATA` was set.
    pub auxdata: Option<[u8; 20]>,
    /// `skb->tstamp` (CLOCK_REALTIME).
    pub tstamp_secs: i64,
    pub tstamp_nanos: u32,
}

fn sock_err(e: i32) -> SocketOpResult {
    SocketOpResult::Err(SockError::from_stack(e))
}

fn read_int(value: &[u8]) -> Option<i32> {
    value
        .get(..4)
        .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

/// Write an int option value: `if (len > lv) len = lv`, copy `len` bytes.
fn put_int(buf: &mut [u8], v: i32) -> SocketOpResult {
    put_bytes(buf, &v.to_ne_bytes())
}

fn put_bytes(buf: &mut [u8], v: &[u8]) -> SocketOpResult {
    let n = buf.len().min(v.len());
    buf[..n].copy_from_slice(&v[..n]);
    SocketOpResult::OptValue { n }
}

impl SocketFile {
    /// `packet_create` past `validate_socket_create`'s checks: build the
    /// kernel half in this socket's network namespace. `protocol` is the
    /// `socket(2)` argument (`(__force __be16)protocol`).
    pub(crate) fn init_packet(&self, protocol: u32) {
        let rcvbuf = self.options.lock().rcvbuf as usize;
        let sock = PacketSock::create(self.net_ns_id(), self.kind, protocol as u16, rcvbuf);
        *self.state.lock() = SocketState::Packet { sock };
    }

    pub(crate) fn packet_sock(&self) -> Option<Arc<PacketSock>> {
        match &*self.state.lock() {
            SocketState::Packet { sock } => Some(sock.clone()),
            _ => None,
        }
    }

    pub(crate) fn take_packet_recv_ancillary(&self) -> Option<PacketRecvAncillary> {
        self.packet_recv_ancillary
            .lock()
            .remove(&crate::handlers::current_task_id())
    }

    /// Whether `SO_TIMESTAMP*` is on, and which variant: `(enabled, ns, new)`.
    pub(crate) fn rcv_timestamp_mode(&self) -> (bool, bool, bool) {
        let o = self.options.lock();
        (o.timestamp_enabled, o.timestamp_ns, o.timestamp_new)
    }

    /// `packet_ops` / `packet_ops_spkt`.
    pub(super) fn dispatch_packet(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        let Some(sock) = self.packet_sock() else {
            return SocketOpResult::Err(SockError::BadFd);
        };
        let spkt = self.kind == SOCK_PACKET;
        match op {
            SocketOp::Bind { addr } => {
                let len = 2 + addr.body.len();
                let result = if spkt {
                    // `packet_bind_spkt`: exactly `sizeof(struct sockaddr)`;
                    // the family is not examined.
                    if len != packet::SOCKADDR_LEN {
                        return SocketOpResult::Err(SockError::InvalidArg);
                    }
                    let raw = &addr.body[..14];
                    let raw = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
                    match core::str::from_utf8(raw) {
                        Ok(name) => sock.bind(Some(name), 0, 0),
                        Err(_) => Err(packet::errno::ENODEV),
                    }
                } else {
                    // `packet_bind`.
                    if len < packet::SOCKADDR_LL_LEN || addr.family != AF_PACKET {
                        return SocketOpResult::Err(SockError::InvalidArg);
                    }
                    let b = &addr.body;
                    let proto_be = u16::from_ne_bytes([b[0], b[1]]);
                    let ifindex = i32::from_ne_bytes([b[2], b[3], b[4], b[5]]);
                    sock.bind(None, ifindex, proto_be)
                };
                match result {
                    Ok(()) => SocketOpResult::Ok(0),
                    Err(e) => sock_err(e),
                }
            }
            SocketOp::GetSockName => SocketOpResult::Addr(packet_getname(&sock, spkt)),
            // `packet_getname(sock, uaddr, peer = 1)`.
            SocketOp::GetPeerName => SocketOpResult::Err(SockError::NotSupported),
            // `sock_no_connect` / `sock_no_listen` / `sock_no_accept` /
            // `sock_no_shutdown`.
            SocketOp::Connect { .. }
            | SocketOp::Listen { .. }
            | SocketOp::Accept
            | SocketOp::Shutdown { .. } => SocketOpResult::Err(SockError::NotSupported),
            SocketOp::Send { buf, addr, .. } => {
                let name = addr.map(|a| {
                    let mut raw = Vec::with_capacity(2 + a.body.len());
                    raw.extend_from_slice(&a.family.to_ne_bytes());
                    raw.extend_from_slice(&a.body);
                    raw
                });
                match sock.sendmsg(buf, name.as_deref()) {
                    Ok(n) => SocketOpResult::Ok(n as u64),
                    Err(e) => sock_err(e),
                }
            }
            SocketOp::Recv { buf, flags } => self.packet_recv(&sock, buf, flags),
            SocketOp::SetSockOpt { level, name, value } => {
                self.packet_setsockopt(&sock, level, name, value)
            }
            SocketOp::GetSockOpt { level, name, buf } => {
                self.packet_getsockopt(&sock, level, name, buf)
            }
        }
    }

    /// `packet_recvmsg`, minus the parts the recvmsg syscall performs with
    /// the user buffers (it copies the data, writes the address returned
    /// here, and emits the cmsgs stashed for this task).
    fn packet_recv(&self, sock: &PacketSock, buf: &mut [u8], flags: u32) -> SocketOpResult {
        if flags & !(MSG_PEEK | MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_COMPAT | MSG_ERRQUEUE) != 0 {
            return SocketOpResult::Err(SockError::InvalidArg);
        }
        if flags & MSG_ERRQUEUE != 0 {
            // `sock_recv_errqueue`: packet sockets queue nothing there (no
            // PACKET_TX_TIMESTAMP support), so the queue is always empty.
            return SocketOpResult::Err(SockError::WouldBlock);
        }
        let record = match sock.recv(flags & MSG_PEEK != 0) {
            Ok(r) => r,
            Err(e) => return sock_err(e),
        };
        let full_len = record.data.len();
        let copied = full_len.min(buf.len());
        buf[..copied].copy_from_slice(&record.data[..copied]);
        let auxdata = sock.with_opts(|o| o.auxdata).then(|| {
            let mut status = TP_STATUS_USER;
            let (tci, tpid) = match record.vlan {
                Some(v) => {
                    status |= TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID;
                    v
                }
                None => (0, 0),
            };
            let mut aux = [0u8; 20];
            aux[0..4].copy_from_slice(&status.to_ne_bytes());
            aux[4..8].copy_from_slice(&record.origlen.to_ne_bytes());
            aux[8..12].copy_from_slice(&(full_len as u32).to_ne_bytes());
            // tp_mac = 0.
            aux[14..16].copy_from_slice(&record.net_off.to_ne_bytes());
            aux[16..18].copy_from_slice(&tci.to_ne_bytes());
            aux[18..20].copy_from_slice(&tpid.to_ne_bytes());
            aux
        });
        self.packet_recv_ancillary.lock().insert(
            crate::handlers::current_task_id(),
            PacketRecvAncillary {
                auxdata,
                tstamp_secs: record.tstamp_secs,
                tstamp_nanos: record.tstamp_nanos,
            },
        );
        let peer = Some(packet_source_addr(&record, self.kind == SOCK_PACKET));
        if copied < full_len {
            SocketOpResult::ReceivedTruncated {
                copied,
                full_len,
                peer,
            }
        } else {
            SocketOpResult::Received { n: copied, peer }
        }
    }

    /// `packet_setsockopt` (`SOCK_PACKET` has none: any level but
    /// `SOL_SOCKET` is `-EOPNOTSUPP`).
    fn packet_setsockopt(
        &self,
        sock: &PacketSock,
        level: u32,
        name: u32,
        value: &[u8],
    ) -> SocketOpResult {
        if level == SOL_SOCKET {
            let result = self.handle_setsockopt(level, name, value);
            if matches!(result, SocketOpResult::Ok(_)) {
                self.sync_packet_socket_options(sock);
            }
            return result;
        }
        if self.kind == SOCK_PACKET {
            return SocketOpResult::Err(SockError::NotSupported);
        }
        if level != SOL_PACKET {
            return SocketOpResult::Err(SockError::NoProtoOpt);
        }
        let int_exact = |value: &[u8]| -> Result<i32, SockError> {
            if value.len() != 4 {
                return Err(SockError::InvalidArg);
            }
            Ok(read_int(value).unwrap_or(0))
        };
        let int_at_least = |value: &[u8]| -> Result<i32, SockError> {
            read_int(value).ok_or(SockError::InvalidArg)
        };
        let set = |f: &dyn Fn(&mut packet::PacketOpts)| {
            sock.with_opts(|o| f(o));
            SocketOpResult::Ok(0)
        };
        match name {
            PACKET_ADD_MEMBERSHIP | PACKET_DROP_MEMBERSHIP => {
                if value.len() < PACKET_MREQ_LEN {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let len = value.len().min(PACKET_MREQ_MAX_LEN);
                let mut raw = [0u8; PACKET_MREQ_MAX_LEN];
                raw[..len].copy_from_slice(&value[..len]);
                let mut addr = [0u8; packet::MAX_ADDR_LEN];
                addr.copy_from_slice(&raw[8..8 + packet::MAX_ADDR_LEN]);
                let mreq = packet::PacketMreq {
                    ifindex: i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]),
                    mr_type: u16::from_ne_bytes([raw[4], raw[5]]),
                    alen: u16::from_ne_bytes([raw[6], raw[7]]),
                    addr,
                };
                if len < usize::from(mreq.alen) + 8 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                if name == PACKET_ADD_MEMBERSHIP {
                    match sock.mc_add(&mreq) {
                        Ok(()) => SocketOpResult::Ok(0),
                        Err(e) => sock_err(e),
                    }
                } else {
                    sock.mc_drop(&mreq);
                    SocketOpResult::Ok(0)
                }
            }
            // LINUX-GAP: PACKET_RX_RING / PACKET_TX_RING (PACKET_MMAP,
            // `packet_set_ring`) and PACKET_FANOUT / PACKET_FANOUT_DATA
            // (`fanout_add`) are not implemented. Refused with -ENOPROTOOPT,
            // what a kernel without the option answers, so a caller such as
            // libpcap falls back or fails visibly instead of waiting on a ring
            // that is never filled. Docs: packet(7), Documentation/networking/
            // packet_mmap.rst.
            PACKET_RX_RING | PACKET_TX_RING | PACKET_FANOUT | PACKET_FANOUT_DATA => {
                SocketOpResult::Err(SockError::NoProtoOpt)
            }
            PACKET_COPY_THRESH => match int_exact(value) {
                Ok(v) => set(&|o| o.copy_thresh = v),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_VERSION => match int_exact(value) {
                Ok(v @ (TPACKET_V1 | TPACKET_V2 | TPACKET_V3)) => set(&|o| o.tp_version = v),
                Ok(_) => SocketOpResult::Err(SockError::InvalidArg),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_RESERVE => match int_exact(value) {
                Ok(v) if v < 0 => SocketOpResult::Err(SockError::InvalidArg),
                Ok(v) => set(&|o| o.tp_reserve = v as u32),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_LOSS => match int_exact(value) {
                Ok(v) => set(&|o| o.tp_loss = v != 0),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_AUXDATA => match int_at_least(value) {
                Ok(v) => set(&|o| o.auxdata = v != 0),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_ORIGDEV => match int_at_least(value) {
                // NARF has no stacked devices (bonding, team, VLAN), so the
                // original device is always the receiving one.
                Ok(v) => set(&|o| o.origdev = v != 0),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_VNET_HDR | PACKET_VNET_HDR_SZ => {
                if self.kind != SOCK_RAW {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let v = match int_at_least(value) {
                    Ok(v) => v,
                    Err(e) => return SocketOpResult::Err(e),
                };
                if name == PACKET_VNET_HDR_SZ
                    && v != 0
                    && v != VIRTIO_NET_HDR_LEN
                    && v != VIRTIO_NET_HDR_MRG_RXBUF_LEN
                {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                if v == 0 {
                    // No virtio-net header: the state every socket is in.
                    return SocketOpResult::Ok(0);
                }
                // LINUX-GAP: PACKET_VNET_HDR / PACKET_VNET_HDR_SZ with a
                // non-zero header (`packet_rcv_vnet`, `packet_snd_vnet_parse`,
                // GSO offload) are not implemented; -ENOPROTOOPT as for an
                // option the kernel lacks.
                SocketOpResult::Err(SockError::NoProtoOpt)
            }
            PACKET_TIMESTAMP => match int_exact(value) {
                Ok(v) => set(&|o| o.tp_tstamp = v),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_IGNORE_OUTGOING => match int_exact(value) {
                Ok(v @ (0 | 1)) => set(&|o| o.ignore_outgoing = v != 0),
                Ok(_) => SocketOpResult::Err(SockError::InvalidArg),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_TX_HAS_OFF => match int_exact(value) {
                Ok(v) => set(&|o| o.tx_has_off = v != 0),
                Err(e) => SocketOpResult::Err(e),
            },
            PACKET_QDISC_BYPASS => match int_exact(value) {
                Ok(v) => set(&|o| o.qdisc_bypass = v != 0),
                Err(e) => SocketOpResult::Err(e),
            },
            _ => SocketOpResult::Err(SockError::NoProtoOpt),
        }
    }

    /// `packet_getsockopt`. For `PACKET_HDRLEN` the caller pre-loads `buf`
    /// with the user's input value (the option is read-modify-write).
    fn packet_getsockopt(
        &self,
        sock: &PacketSock,
        level: u32,
        name: u32,
        buf: &mut [u8],
    ) -> SocketOpResult {
        if level == SOL_SOCKET {
            // packet_create leaves sk_protocol zero even though po->num keeps
            // the packet hook's opaque Ethernet protocol selector.
            if name == SO_PROTOCOL {
                return put_int(buf, 0);
            }
            // Device notifier/bind errors live in sk_err and sock_error
            // consumes them exactly once.
            if name == SO_ERROR {
                return put_int(buf, sock.take_error());
            }
            return self.handle_getsockopt(level, name, buf);
        }
        if self.kind == SOCK_PACKET {
            return SocketOpResult::Err(SockError::NotSupported);
        }
        if level != SOL_PACKET {
            return SocketOpResult::Err(SockError::NoProtoOpt);
        }
        let opts = sock.with_opts(|o| o.clone());
        match name {
            PACKET_STATISTICS => {
                let (packets, drops) = sock.take_statistics();
                let mut v = [0u8; 12];
                v[0..4].copy_from_slice(&packets.to_ne_bytes());
                v[4..8].copy_from_slice(&drops.to_ne_bytes());
                // tp_freeze_q_cnt (v3 only) stays 0: no ring to freeze.
                let lv = if opts.tp_version == TPACKET_V3 { 12 } else { 8 };
                put_bytes(buf, &v[..lv])
            }
            PACKET_AUXDATA => put_int(buf, i32::from(opts.auxdata)),
            PACKET_ORIGDEV => put_int(buf, i32::from(opts.origdev)),
            // No virtio-net header can be configured (see the setsockopt
            // LINUX-GAP), so both report the unset state.
            PACKET_VNET_HDR | PACKET_VNET_HDR_SZ => put_int(buf, 0),
            PACKET_COPY_THRESH => put_int(buf, opts.copy_thresh),
            PACKET_VERSION => put_int(buf, opts.tp_version),
            PACKET_HDRLEN => {
                if buf.len() < 4 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let v = match read_int(buf) {
                    // sizeof(struct tpacket_hdr / tpacket2_hdr /
                    // tpacket3_hdr).
                    Some(TPACKET_V1) | Some(TPACKET_V2) => 32,
                    Some(TPACKET_V3) => 48,
                    _ => return SocketOpResult::Err(SockError::InvalidArg),
                };
                put_int(&mut buf[..4], v)
            }
            PACKET_RESERVE => put_int(buf, opts.tp_reserve as i32),
            PACKET_LOSS => put_int(buf, i32::from(opts.tp_loss)),
            PACKET_TIMESTAMP => put_int(buf, opts.tp_tstamp),
            // A socket can never join a fanout group (setsockopt LINUX-GAP),
            // so it reports none.
            PACKET_FANOUT => put_int(buf, 0),
            PACKET_IGNORE_OUTGOING => put_int(buf, i32::from(opts.ignore_outgoing)),
            // `if (!po->rollover) return -EINVAL;` — no fanout, no rollover.
            PACKET_ROLLOVER_STATS => SocketOpResult::Err(SockError::InvalidArg),
            PACKET_TX_HAS_OFF => put_int(buf, i32::from(opts.tx_has_off)),
            PACKET_QDISC_BYPASS => put_int(buf, i32::from(opts.qdisc_bypass)),
            _ => SocketOpResult::Err(SockError::NoProtoOpt),
        }
    }

    /// Push the `SOL_SOCKET` state the delivery path reads (`sk_filter`,
    /// `sk_rcvbuf`) down into the kernel half after a successful setsockopt.
    fn sync_packet_socket_options(&self, sock: &PacketSock) {
        let (filter, rcvbuf) = {
            let o = self.options.lock();
            (o.classic_filter.clone(), o.rcvbuf as usize)
        };
        sock.set_filter(
            filter
                .as_deref()
                .and_then(narf_net::cbpf::Program::from_bytes)
                .map(Arc::new),
        );
        sock.set_rcvbuf(rcvbuf);
    }
}

/// The address `packet_recvmsg` reports: a `sockaddr_ll` of
/// `max(offsetof(sll_addr) + sll_halen, sizeof(sockaddr_ll))` bytes, or a
/// `sockaddr_pkt` for `SOCK_PACKET`.
fn packet_source_addr(record: &packet::PacketRecord, spkt: bool) -> SockAddr {
    if spkt {
        // `spkt_family = dev->type`, `spkt_device`, `spkt_protocol`.
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&record.dev_name);
        body.extend_from_slice(&record.protocol.to_be_bytes());
        return SockAddr {
            family: record.hatype,
            body,
        };
    }
    let mut sa = [0u8; packet::SOCKADDR_LL_LEN];
    sa[2..4].copy_from_slice(&record.protocol.to_be_bytes());
    sa[4..8].copy_from_slice(&(record.ifindex as i32).to_ne_bytes());
    sa[8..10].copy_from_slice(&record.hatype.to_ne_bytes());
    sa[10] = record.pkttype;
    sa[11] = record.halen;
    sa[12..20].copy_from_slice(&record.addr);
    let namelen =
        (packet::SLL_ADDR_OFFSET + usize::from(record.halen)).max(packet::SOCKADDR_LL_LEN);
    SockAddr {
        family: AF_PACKET,
        body: sa[2..namelen].to_vec(),
    }
}

/// `packet_getname` / `packet_getname_spkt`.
fn packet_getname(sock: &PacketSock, spkt: bool) -> SockAddr {
    let (ifindex, proto_be, hatype, halen, dev_addr, dev_name) = sock.getname();
    if spkt {
        let mut body = alloc::vec![0u8; 14];
        if let Some(name) = dev_name {
            let n = name.len().min(13);
            body[..n].copy_from_slice(&name.as_bytes()[..n]);
        }
        return SockAddr {
            family: AF_PACKET,
            body,
        };
    }
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&proto_be.to_ne_bytes());
    body.extend_from_slice(&ifindex.to_ne_bytes());
    body.extend_from_slice(&hatype.to_ne_bytes());
    body.push(0); // sll_pkttype
    body.push(halen);
    body.extend_from_slice(&dev_addr[..usize::from(halen)]);
    SockAddr {
        family: AF_PACKET,
        body,
    }
}

/// The AF_PACKET socket behind an open file, for the `read(2)` /
/// `write(2)` family: those reach a socket through `sock_read_iter` /
/// `sock_write_iter`, i.e. `packet_recvmsg` / `packet_sendmsg`, whose
/// errnos (ENXIO, ENETDOWN, EMSGSIZE, a pending `sk_err`, …) the generic
/// file path cannot carry.
pub(crate) fn packet_socket_of(ops: &dyn narf_filesystem::FileOps) -> Option<&SocketFile> {
    ops.as_any()?
        .downcast_ref::<SocketFile>()
        .filter(|sock| sock.domain == AF_PACKET)
}

impl SocketFile {
    /// `sock_write_iter` → `packet_sendmsg` without an address.
    pub(crate) fn packet_write(&self, data: &[u8]) -> Result<usize, i64> {
        let sock = self.packet_sock().ok_or(errno::EBADF)?;
        sock.sendmsg(data, None).map_err(i64::from)
    }

    /// `sock_read_iter` → `packet_recvmsg(flags = 0)`: the head frame,
    /// truncated to `buf`. `Err(EAGAIN)` on an empty queue (the caller
    /// blocks or not per `O_NONBLOCK`).
    pub(crate) fn packet_read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        let sock = self.packet_sock().ok_or(errno::EBADF)?;
        let record = sock.recv(false).map_err(i64::from)?;
        let n = record.data.len().min(buf.len());
        buf[..n].copy_from_slice(&record.data[..n]);
        Ok(n)
    }
}
