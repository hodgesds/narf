//! AF_PACKET sockets: the protocol hooks, receive queues, transmit path and
//! device-event handling behind `socket(AF_PACKET, …)`.
//!
//! Linux `net/packet/af_packet.c` is the authority for every rule here
//! (GPL-2.0; NARF is GPL-2.0-or-later). The pieces map one-to-one:
//!
//! | Linux                              | here                                  |
//! |------------------------------------|---------------------------------------|
//! | `packet_create`                    | [`PacketSock::create`]                |
//! | `packet_do_bind` / `packet_bind*`  | [`PacketSock::bind`]                  |
//! | `register_prot_hook` + `ptype_*`   | `Inner::running` + [`netif_receive`]  |
//! | `packet_rcv` / `packet_rcv_spkt`   | `PacketSock::rcv`                     |
//! | `dev_queue_xmit_nit`               | [`dev_queue_xmit_nit`]                |
//! | `packet_snd` / `packet_sendmsg_spkt`| [`PacketSock::sendmsg`]              |
//! | `packet_recvmsg` (queue half)      | [`PacketSock::recv`]                  |
//! | `packet_notifier`                  | [`netdev_event`]                      |
//! | `packet_mc_add` / `packet_mc_drop` | [`PacketSock::mc_add`] / `mc_drop`    |
//! | `packet_release`                   | [`PacketSock::release`]               |
//!
//! Received frames reach [`netif_receive`] from `tcp_stack::rx_handler`
//! (after any XDP program, before L3) — the `__netif_receive_skb_core`
//! position. Every frame the kernel transmits passes
//! [`crate::iface::NetIfaceSnapshot::xmit`], which runs
//! [`dev_queue_xmit_nit`] first, so `ETH_P_ALL` sockets see outgoing
//! traffic as `PACKET_OUTGOING` exactly as Linux taps do.
//!
//! The socket-facing half (sockaddr encoding, options, cmsgs) lives in
//! `userspace/src/socket/packet.rs`; this module owns state and delivery.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use narf_lib::readiness::Readiness;
use narf_lib::sync::IrqSafeSpinLock;

use crate::cbpf;
use crate::iface::NetIfaceSnapshot;
use crate::pkt::ETH_HDR_LEN;

/// `ETH_P_ALL`: every protocol (the `ptype_all` hook list).
pub const ETH_P_ALL: u16 = 0x0003;
/// `ETH_P_802_3`: a raw 802.3 frame (Novell's `0xFFFF` SAP hack).
pub const ETH_P_802_3: u16 = 0x0001;
/// `ETH_P_802_2`: an 802.3 frame carrying an 802.2 LLC header.
pub const ETH_P_802_2: u16 = 0x0004;
/// `ETH_P_802_3_MIN`: values below this in the type field are lengths.
pub const ETH_P_802_3_MIN: u16 = 0x0600;
/// `ETH_P_8021Q`.
pub const ETH_P_8021Q: u16 = 0x8100;
/// `ETH_P_8021AD`.
pub const ETH_P_8021AD: u16 = 0x88a8;

/// `sll_pkttype` values (`include/uapi/linux/if_packet.h`).
pub const PACKET_HOST: u8 = 0;
pub const PACKET_BROADCAST: u8 = 1;
pub const PACKET_MULTICAST: u8 = 2;
pub const PACKET_OTHERHOST: u8 = 3;
pub const PACKET_OUTGOING: u8 = 4;

/// `PACKET_MR_*` membership types.
pub const PACKET_MR_MULTICAST: u16 = 0;
pub const PACKET_MR_PROMISC: u16 = 1;
pub const PACKET_MR_ALLMULTI: u16 = 2;
pub const PACKET_MR_UNICAST: u16 = 3;

/// `ARPHRD_ETHER` / `ARPHRD_LOOPBACK`.
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;

/// Socket types `packet_create` accepts.
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_PACKET: u32 = 10;

/// `VLAN_HLEN`.
const VLAN_HLEN: usize = 4;
/// `MAX_ADDR_LEN`.
pub const MAX_ADDR_LEN: usize = 32;
/// `offsetof(struct sockaddr_ll, sll_addr)`.
pub const SLL_ADDR_OFFSET: usize = 12;
/// `sizeof(struct sockaddr_ll)`.
pub const SOCKADDR_LL_LEN: usize = 20;
/// `sizeof(struct sockaddr_pkt)`.
pub const SOCKADDR_PKT_LEN: usize = 18;
/// `sizeof(struct sockaddr)`.
pub const SOCKADDR_LEN: usize = 16;

/// Bytes charged against `SO_RCVBUF` beyond the payload for each queued
/// frame — the `sk_buff` + `skb_shared_info` share of `skb->truesize`. The
/// same constant the AF_INET datagram queues use.
pub const SKB_TRUESIZE_OVERHEAD: usize = 576;

/// Linux errno values this layer returns (positive).
pub mod errno {
    pub const ENOENT: i32 = 2;
    pub const ENXIO: i32 = 6;
    pub const EAGAIN: i32 = 11;
    pub const ENOBUFS: i32 = 105;
    pub const EINVAL: i32 = 22;
    pub const ENODEV: i32 = 19;
    pub const EMSGSIZE: i32 = 90;
    pub const ENETDOWN: i32 = 100;
    pub const ENOTCONN: i32 = 107;
    pub const EOVERFLOW: i32 = 75;
}

/// Readiness bits (`POLLIN` / `POLLOUT` / `POLLERR`).
pub const POLL_IN: u32 = 0x0001;
pub const POLL_OUT: u32 = 0x0004;
pub const POLL_ERR: u32 = 0x0008;

/// The `struct net_device` fields packet sockets read.
#[derive(Clone, Debug)]
pub struct NetDev {
    pub ifindex: u32,
    pub name: String,
    pub dev_addr: [u8; 6],
    /// `dev->type`.
    pub hatype: u16,
    /// `dev->flags & IFF_UP`.
    pub up: bool,
    pub mtu: u32,
    pub net_ns_id: u64,
}

impl NetDev {
    #[must_use]
    pub fn from_snapshot(snap: &NetIfaceSnapshot) -> Self {
        Self {
            ifindex: snap.ifindex,
            name: snap.name.clone(),
            dev_addr: snap.mac,
            hatype: snap.hatype(),
            up: snap.link_up,
            mtu: snap.mtu,
            net_ns_id: snap.net_ns_id,
        }
    }

    /// `dev->broadcast`: `ether_setup` sets all-ones; `loopback_setup`
    /// leaves it zeroed.
    fn broadcast(&self) -> [u8; 6] {
        if self.hatype == ARPHRD_LOOPBACK {
            [0; 6]
        } else {
            [0xff; 6]
        }
    }

    /// `dev->addr_len`: `ETH_ALEN` for both Ethernet and loopback.
    #[must_use]
    pub fn addr_len(&self) -> usize {
        6
    }
}

fn dev_by_index(net_ns_id: u64, ifindex: u32) -> Option<NetDev> {
    crate::iface::by_index_in(net_ns_id, ifindex).map(|s| NetDev::from_snapshot(&s))
}

fn dev_by_name(net_ns_id: u64, name: &str) -> Option<NetDev> {
    crate::iface::lookup_in(net_ns_id, name).map(|s| NetDev::from_snapshot(&s))
}

/// One queued frame, carrying what `packet_rcv` / `packet_rcv_spkt` store in
/// `PACKET_SKB_CB` plus the `sk_buff` fields `packet_recvmsg` reports.
#[derive(Clone, Debug)]
pub struct PacketRecord {
    /// The bytes `recvmsg` copies out (`skb->data .. +skb->len` after the
    /// snaplen trim).
    pub data: Vec<u8>,
    /// `PACKET_SKB_CB(skb)->sa.origlen`: the length before trimming (0 for
    /// `SOCK_PACKET`, which never stores it).
    pub origlen: u32,
    pub ifindex: u32,
    pub hatype: u16,
    pub pkttype: u8,
    pub halen: u8,
    pub addr: [u8; 8],
    /// `sll_protocol` (host order) as `packet_recvmsg` computes it, or
    /// `spkt_protocol` for `SOCK_PACKET`.
    pub protocol: u16,
    /// `skb_network_offset(skb)` relative to the delivered data (`tp_net`).
    pub net_off: u16,
    /// `tp_vlan_tci` / `tp_vlan_tpid` when `TP_STATUS_VLAN_VALID` applies.
    pub vlan: Option<(u16, u16)>,
    /// `skb->tstamp` (CLOCK_REALTIME) taken at enqueue.
    pub tstamp_secs: i64,
    pub tstamp_nanos: u32,
    /// `spkt_device` for `SOCK_PACKET` receivers.
    pub dev_name: [u8; 14],
    charge: usize,
}

/// One `packet_mclist` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct McEntry {
    ifindex: i32,
    mr_type: u16,
    alen: u16,
    addr: [u8; MAX_ADDR_LEN],
    count: u32,
}

/// `packet_mreq_max`.
#[derive(Clone, Copy, Debug)]
pub struct PacketMreq {
    pub ifindex: i32,
    pub mr_type: u16,
    pub alen: u16,
    pub addr: [u8; MAX_ADDR_LEN],
}

/// The `SOL_PACKET` flags and values `packet_setsockopt` stores.
#[derive(Clone, Debug, Default)]
pub struct PacketOpts {
    pub auxdata: bool,
    pub origdev: bool,
    pub ignore_outgoing: bool,
    pub qdisc_bypass: bool,
    pub tp_loss: bool,
    pub tx_has_off: bool,
    pub tp_version: i32,
    pub tp_reserve: u32,
    pub tp_tstamp: i32,
    pub copy_thresh: i32,
}

#[derive(Debug)]
struct Inner {
    /// `po->num`, host byte order.
    num: u16,
    /// `po->ifindex`: 0 unbound, the bound device, or -1 once that device
    /// left the namespace.
    ifindex: i32,
    /// `po->prot_hook.dev`: the device the hook is bound to.
    bound_dev: Option<u32>,
    /// `PACKET_SOCK_RUNNING`: the hook is registered.
    running: bool,
    filter: Option<Arc<cbpf::Program>>,
    queue: VecDeque<PacketRecord>,
    /// `sk_rmem_alloc`.
    rmem: usize,
    /// `sk_rcvbuf`.
    rcvbuf: usize,
    /// `sk_err`.
    sk_err: i32,
    /// `po->stats.stats1.tp_packets`.
    tp_packets: u32,
    mclist: Vec<McEntry>,
    opts: PacketOpts,
}

/// An AF_PACKET socket's kernel half.
#[derive(Debug)]
pub struct PacketSock {
    pub net_ns_id: u64,
    /// `sock->type`: `SOCK_RAW`, `SOCK_DGRAM` or `SOCK_PACKET`.
    pub sock_type: u32,
    inner: IrqSafeSpinLock<Inner>,
    /// `po->tp_drops`.
    tp_drops: AtomicU32,
    /// POLL_IN while the queue is non-empty, POLL_OUT always (a packet
    /// socket's send completes synchronously, so `sock_writeable` holds),
    /// POLL_ERR while `sk_err` is set.
    readiness: Readiness,
}

/// `net->packet.sklist`: every live packet socket.
static SKLIST: IrqSafeSpinLock<Vec<Arc<PacketSock>>> = IrqSafeSpinLock::new(Vec::new());
/// Number of sockets with a registered hook; lets the per-frame paths skip
/// all work when nobody is listening.
static RUNNING: AtomicUsize = AtomicUsize::new(0);

impl PacketSock {
    /// `packet_create` after its checks: `po->num = protocol` and, for a
    /// non-zero protocol, `__register_prot_hook` on every device.
    /// `protocol_be` is the `socket(2)` argument as given (network order).
    #[must_use]
    pub fn create(net_ns_id: u64, sock_type: u32, protocol_be: u16, rcvbuf: usize) -> Arc<Self> {
        let num = u16::from_be(protocol_be);
        let sock = Arc::new(Self {
            net_ns_id,
            sock_type,
            inner: IrqSafeSpinLock::new(Inner {
                num,
                ifindex: 0,
                bound_dev: None,
                running: false,
                filter: None,
                queue: VecDeque::new(),
                rmem: 0,
                rcvbuf,
                sk_err: 0,
                tp_packets: 0,
                mclist: Vec::new(),
                opts: PacketOpts {
                    tp_version: 0, // TPACKET_V1
                    ..PacketOpts::default()
                },
            }),
            tp_drops: AtomicU32::new(0),
            readiness: Readiness::new(POLL_OUT),
        });
        if num != 0 {
            let mut g = sock.inner.lock();
            register_prot_hook(&mut g);
        }
        SKLIST.lock().push(sock.clone());
        sock
    }

    /// The socket's durable readiness cell.
    #[must_use]
    pub fn readiness(&self) -> &Readiness {
        &self.readiness
    }

    /// The live POLL_IN / POLL_OUT / POLL_ERR level (`packet_poll` →
    /// `datagram_poll`).
    #[must_use]
    pub fn poll_mask(&self) -> u32 {
        let g = self.inner.lock();
        let mut mask = POLL_OUT;
        if !g.queue.is_empty() {
            mask |= POLL_IN;
        }
        if g.sk_err != 0 {
            mask |= POLL_ERR;
        }
        mask
    }

    /// Re-synchronise the readiness cell with the queue/error state.
    fn sync_readiness(&self, g: &Inner) {
        let mut add = POLL_OUT;
        let mut clear = 0;
        if g.queue.is_empty() {
            clear |= POLL_IN;
        } else {
            add |= POLL_IN;
        }
        if g.sk_err != 0 {
            add |= POLL_ERR;
        } else {
            clear |= POLL_ERR;
        }
        self.readiness.set(add, clear);
    }

    /// `packet_release`: unhook, drop every multicast membership and purge
    /// the queue.
    pub fn release(self: &Arc<Self>) {
        SKLIST.lock().retain(|s| !Arc::ptr_eq(s, self));
        let mclist = {
            let mut g = self.inner.lock();
            unregister_prot_hook(&mut g);
            g.queue.clear();
            g.rmem = 0;
            core::mem::take(&mut g.mclist)
        };
        // `packet_flush_mclist`: one device reference per entry, whatever its
        // socket-level count.
        for ml in mclist {
            if let Some(dev) = dev_by_index(self.net_ns_id, ml.ifindex as u32) {
                let _ = packet_dev_mc(&dev, &ml, false);
            }
        }
    }

    /// `packet_do_bind(sk, name, ifindex, proto)`. `proto_be == 0` keeps the
    /// current protocol. Exactly one of `name` / `ifindex` selects the device;
    /// neither (ifindex 0, no name) binds to every device.
    pub fn bind(&self, name: Option<&str>, ifindex: i32, proto_be: u16) -> Result<(), i32> {
        let dev = if let Some(name) = name {
            match dev_by_name(self.net_ns_id, name) {
                Some(dev) => Some(dev),
                None => return Err(errno::ENODEV),
            }
        } else if ifindex != 0 {
            if ifindex < 0 {
                return Err(errno::ENODEV);
            }
            match dev_by_index(self.net_ns_id, ifindex as u32) {
                Some(dev) => Some(dev),
                None => return Err(errno::ENODEV),
            }
        } else {
            None
        };
        let mut g = self.inner.lock();
        let proto = if proto_be == 0 {
            g.num
        } else {
            u16::from_be(proto_be)
        };
        let dev_index = dev.as_ref().map(|d| d.ifindex);
        // `po->prot_hook.type` always equals `po->num` outside this function.
        let need_rehook = g.num != proto || g.bound_dev != dev_index;
        if need_rehook {
            if g.running {
                g.num = 0;
                unregister_prot_hook(&mut g);
            }
            g.num = proto;
            g.bound_dev = dev_index;
            g.ifindex = dev_index.map_or(0, |i| i as i32);
        }
        if proto == 0 || !need_rehook {
            return Ok(());
        }
        if dev.as_ref().is_none_or(|d| d.up) {
            register_prot_hook(&mut g);
        } else {
            // `sk->sk_err = ENETDOWN; sk_error_report(sk)`.
            g.sk_err = errno::ENETDOWN;
            self.sync_readiness(&g);
            self.readiness.notify(POLL_ERR);
        }
        Ok(())
    }

    /// `packet_getname`: `(ifindex, protocol_be, hatype, halen, dev_addr)`.
    /// `packet_getname_spkt` reads only the device name from this.
    #[must_use]
    pub fn getname(&self) -> (i32, u16, u16, u8, [u8; 6], Option<String>) {
        let (ifindex, num) = {
            let g = self.inner.lock();
            (g.ifindex, g.num)
        };
        let dev = if ifindex > 0 {
            dev_by_index(self.net_ns_id, ifindex as u32)
        } else {
            None
        };
        match dev {
            Some(dev) => (
                ifindex,
                num.to_be(),
                dev.hatype,
                dev.addr_len() as u8,
                dev.dev_addr,
                Some(dev.name),
            ),
            None => (ifindex, num.to_be(), 0, 0, [0; 6], None),
        }
    }

    /// Install (or with `None`, remove) the socket filter `run_filter` uses.
    pub fn set_filter(&self, filter: Option<Arc<cbpf::Program>>) {
        self.inner.lock().filter = filter;
    }

    /// `sk->sk_rcvbuf`.
    pub fn set_rcvbuf(&self, rcvbuf: usize) {
        self.inner.lock().rcvbuf = rcvbuf;
    }

    /// Read or update the `SOL_PACKET` option block.
    pub fn with_opts<R>(&self, f: impl FnOnce(&mut PacketOpts) -> R) -> R {
        f(&mut self.inner.lock().opts)
    }

    /// `sock_error(sk)`: take and clear `sk_err` (0 when none).
    pub fn take_error(&self) -> i32 {
        let mut g = self.inner.lock();
        let err = core::mem::take(&mut g.sk_err);
        if err != 0 {
            self.sync_readiness(&g);
        }
        err
    }

    /// `SIOCINQ`: the length of the head frame.
    #[must_use]
    pub fn inq(&self) -> usize {
        self.inner.lock().queue.front().map_or(0, |r| r.data.len())
    }

    /// Number of queued frames (diagnostics and tests).
    #[must_use]
    pub fn queued(&self) -> usize {
        self.inner.lock().queue.len()
    }

    /// The `skb_recv_datagram` half of `packet_recvmsg`: a pending socket
    /// error is reported (and cleared) first, then the head frame is taken
    /// (or, with `peek`, copied). `Err(EAGAIN)` on an empty queue.
    pub fn recv(&self, peek: bool) -> Result<PacketRecord, i32> {
        let mut g = self.inner.lock();
        if g.sk_err != 0 {
            let err = core::mem::take(&mut g.sk_err);
            self.sync_readiness(&g);
            return Err(err);
        }
        let record = if peek {
            g.queue.front().cloned()
        } else {
            let record = g.queue.pop_front();
            if let Some(r) = &record {
                g.rmem = g.rmem.saturating_sub(r.charge);
            }
            record
        };
        match record {
            Some(r) => {
                if g.queue.is_empty() {
                    self.sync_readiness(&g);
                }
                Ok(r)
            }
            None => Err(errno::EAGAIN),
        }
    }

    /// `PACKET_STATISTICS`: `(tp_packets, tp_drops)`, both reset. Linux
    /// reports `tp_packets` including the drops.
    pub fn take_statistics(&self) -> (u32, u32) {
        let mut g = self.inner.lock();
        let packets = core::mem::take(&mut g.tp_packets);
        drop(g);
        let drops = self.tp_drops.swap(0, Ordering::AcqRel);
        (packets.wrapping_add(drops), drops)
    }

    /// `packet_mc_add`.
    pub fn mc_add(&self, mreq: &PacketMreq) -> Result<(), i32> {
        let Some(dev) = (mreq.ifindex > 0)
            .then(|| dev_by_index(self.net_ns_id, mreq.ifindex as u32))
            .flatten()
        else {
            return Err(errno::ENODEV);
        };
        if usize::from(mreq.alen) > dev.addr_len() {
            return Err(errno::EINVAL);
        }
        let mut g = self.inner.lock();
        let alen = usize::from(mreq.alen);
        if let Some(ml) = g.mclist.iter_mut().find(|ml| {
            ml.ifindex == mreq.ifindex
                && ml.mr_type == mreq.mr_type
                && ml.alen == mreq.alen
                && ml.addr[..alen] == mreq.addr[..alen]
        }) {
            ml.count += 1;
            return Ok(());
        }
        let mut addr = [0u8; MAX_ADDR_LEN];
        addr[..alen].copy_from_slice(&mreq.addr[..alen]);
        let entry = McEntry {
            ifindex: mreq.ifindex,
            mr_type: mreq.mr_type,
            alen: mreq.alen,
            addr,
            count: 1,
        };
        packet_dev_mc(&dev, &entry, true)?;
        g.mclist.push(entry);
        Ok(())
    }

    /// `packet_mc_drop`: always succeeds; an unknown membership is ignored.
    pub fn mc_drop(&self, mreq: &PacketMreq) {
        let mut g = self.inner.lock();
        let alen = usize::from(mreq.alen).min(MAX_ADDR_LEN);
        let Some(pos) = g.mclist.iter().position(|ml| {
            ml.ifindex == mreq.ifindex
                && ml.mr_type == mreq.mr_type
                && ml.alen == mreq.alen
                && ml.addr[..alen] == mreq.addr[..alen]
        }) else {
            return;
        };
        g.mclist[pos].count -= 1;
        if g.mclist[pos].count == 0 {
            let ml = g.mclist.remove(pos);
            drop(g);
            if let Some(dev) = dev_by_index(self.net_ns_id, ml.ifindex as u32) {
                let _ = packet_dev_mc(&dev, &ml, false);
            }
        }
    }

    /// `packet_rcv` (and, for `SOCK_PACKET`, `packet_rcv_spkt` +
    /// `sock_queue_rcv_skb`) for one hook match.
    fn rcv(&self, dev: &NetDev, skb: &Skb<'_>) {
        // `skb->pkt_type == PACKET_LOOPBACK` never occurs: NARF has no
        // multicast loopback path that would mark it.
        let spkt = self.sock_type == SOCK_PACKET;
        // `dev_has_header(dev)` holds for Ethernet and loopback: a SOCK_DGRAM
        // receiver starts at the network header, everyone else at the MAC
        // header.
        let data_off = if self.sock_type == SOCK_DGRAM {
            skb.net_off
        } else {
            0
        };
        let len = skb.frame.len().saturating_sub(data_off);
        let mut g = self.inner.lock();
        let view = cbpf::SkbView {
            frame: skb.frame,
            data_off,
            len,
            mac_off: 0,
            net_off: skb.net_off,
            protocol: skb.protocol,
            pkt_type: skb.pkt_type,
            ifindex: dev.ifindex,
            hatype: dev.hatype,
            vlan: skb.vlan,
        };
        let mut snaplen = len;
        if let Some(filter) = &g.filter {
            let res = cbpf::run(filter, &view) as usize;
            if res == 0 {
                return;
            }
            if spkt {
                // `sk_filter_trim_cap(sk, skb, 1)`: `pskb_trim(skb,
                // max(cap, pkt_len))`.
                snaplen = snaplen.min(res.max(1));
            } else if snaplen > res {
                snaplen = res;
            }
        }
        if g.rmem >= g.rcvbuf {
            if !spkt {
                self.tp_drops.fetch_add(1, Ordering::AcqRel);
            }
            return;
        }
        let data = skb.frame[data_off..data_off + snaplen].to_vec();
        let mut addr = [0u8; 8];
        // `dev_parse_header` → `eth_header_parse`: the source MAC.
        addr[..6].copy_from_slice(&skb.frame[6..12]);
        let mut dev_name = [0u8; 14];
        // `strscpy(spkt_device, dev->name, sizeof(spkt_device))`.
        let n = dev.name.len().min(13);
        dev_name[..n].copy_from_slice(&dev.name.as_bytes()[..n]);
        let protocol = if !spkt && self.sock_type == SOCK_DGRAM {
            skb.dgram_protocol()
        } else {
            skb.protocol
        };
        // `aux.tp_vlan_*`: a hardware-style tag (split off on receive), or
        // for SOCK_DGRAM an in-frame tag read back from the MAC header.
        let vlan = match skb.vlan {
            Some(v) => Some(v),
            None if self.sock_type == SOCK_DGRAM && eth_type_vlan(skb.protocol) => {
                // Linux `vlan_get_tci` uses `skb_header_pointer` for the
                // complete four-byte VLAN header. A truncated header returns
                // TCI 0 (while PACKET_AUXDATA still marks the VLAN protocol
                // valid), never an unchecked dereference.
                let tci = skb
                    .frame
                    .get(ETH_HDR_LEN..ETH_HDR_LEN + VLAN_HLEN)
                    .map_or(0, |tag| u16::from_be_bytes([tag[0], tag[1]]));
                Some((tci, skb.protocol))
            }
            None => None,
        };
        let wall = narf_scheduler::narf_time::now_wall();
        let charge = snaplen + SKB_TRUESIZE_OVERHEAD;
        let record = PacketRecord {
            data,
            origlen: if spkt { 0 } else { len as u32 },
            ifindex: dev.ifindex,
            hatype: dev.hatype,
            pkttype: skb.pkt_type,
            halen: 6,
            addr,
            protocol,
            net_off: (skb.net_off - data_off) as u16,
            vlan,
            tstamp_secs: wall.secs,
            tstamp_nanos: wall.nanos,
            dev_name,
            charge,
        };
        g.rmem += charge;
        if !spkt {
            g.tp_packets = g.tp_packets.wrapping_add(1);
        }
        g.queue.push_back(record);
        drop(g);
        // `sk->sk_data_ready(sk)`: a rising POLL_IN edge, plus an
        // unconditional event so an already-readable socket's epoll
        // ready-list still sees the new frame.
        self.readiness.set(POLL_IN, 0);
        self.readiness.notify(POLL_IN);
        crate::readiness::notify(0);
    }

    /// `packet_sendmsg` / `packet_sendmsg_spkt`. `name` is the raw sockaddr
    /// the caller passed (family included) — `None` for `send(2)`/`write(2)`.
    /// Returns the byte count Linux reports (`len`).
    pub fn sendmsg(self: &Arc<Self>, data: &[u8], name: Option<&[u8]>) -> Result<usize, i32> {
        if self.sock_type == SOCK_PACKET {
            return self.sendmsg_spkt(data, name);
        }
        let len = data.len();
        let (dev, proto, daddr): (Option<NetDev>, u16, Option<[u8; 6]>) = match name {
            None => {
                let (dev_index, num) = {
                    let g = self.inner.lock();
                    (g.bound_dev, g.num)
                };
                // `packet_cached_dev_get`.
                (
                    dev_index.and_then(|i| dev_by_index(self.net_ns_id, i)),
                    num,
                    None,
                )
            }
            Some(sa) => {
                if sa.len() < SOCKADDR_LL_LEN {
                    return Err(errno::EINVAL);
                }
                let halen = usize::from(sa[11]);
                if sa.len() < halen + SLL_ADDR_OFFSET {
                    return Err(errno::EINVAL);
                }
                let proto = u16::from_be_bytes([sa[2], sa[3]]);
                let ifindex = i32::from_ne_bytes([sa[4], sa[5], sa[6], sa[7]]);
                let dev = (ifindex > 0)
                    .then(|| dev_by_index(self.net_ns_id, ifindex as u32))
                    .flatten();
                let mut daddr = None;
                if self.sock_type == SOCK_DGRAM {
                    if let Some(dev) = &dev {
                        if sa.len() < dev.addr_len() + SLL_ADDR_OFFSET {
                            return Err(errno::EINVAL);
                        }
                    }
                    let mut a = [0u8; 6];
                    a.copy_from_slice(&sa[SLL_ADDR_OFFSET..SLL_ADDR_OFFSET + 6]);
                    daddr = Some(a);
                }
                (dev, proto, daddr)
            }
        };
        let Some(dev) = dev else {
            return Err(errno::ENXIO);
        };
        if !dev.up {
            return Err(errno::ENETDOWN);
        }
        let reserve = if self.sock_type == SOCK_RAW {
            ETH_HDR_LEN
        } else {
            0
        };
        let mtu = dev.mtu as usize;
        if len > mtu + reserve + VLAN_HLEN {
            return Err(errno::EMSGSIZE);
        }
        let frame = if self.sock_type == SOCK_DGRAM {
            // `dev_hard_header` → `eth_header`.
            let daddr = match daddr {
                Some(a) => a,
                None if dev.hatype == ARPHRD_LOOPBACK => [0; 6],
                None => return Err(errno::EINVAL),
            };
            let mut frame = Vec::with_capacity(ETH_HDR_LEN + len);
            frame.extend_from_slice(&daddr);
            frame.extend_from_slice(&dev.dev_addr);
            let h_proto = if proto != ETH_P_802_3 && proto != ETH_P_802_2 {
                proto
            } else {
                len as u16
            };
            frame.extend_from_slice(&h_proto.to_be_bytes());
            frame.extend_from_slice(data);
            frame
        } else {
            // `dev_validate_header`: an Ethernet frame needs its whole
            // 14-byte header (`min_header_len == hard_header_len`).
            if len < ETH_HDR_LEN {
                return Err(errno::EINVAL);
            }
            data.to_vec()
        };
        if len > mtu + reserve && !extra_vlan_len_allowed(&dev, &frame) {
            return Err(errno::EMSGSIZE);
        }
        // `packet_parse_headers`: a SOCK_RAW frame sent with protocol 0 or
        // ETH_P_ALL takes its protocol from the header.
        let protocol = if (proto == 0 || proto == ETH_P_ALL) && self.sock_type == SOCK_RAW {
            u16::from_be_bytes([frame[12], frame[13]])
        } else {
            proto
        };
        let bypass = self.inner.lock().opts.qdisc_bypass;
        let Some(snap) = crate::iface::by_index_in(self.net_ns_id, dev.ifindex) else {
            return Err(errno::ENXIO);
        };
        if bypass {
            // `packet_direct_xmit`: no taps, and a driver refusal is
            // `NET_XMIT_DROP` → -ENOBUFS.
            snap.xmit_direct(&frame).map_err(|()| errno::ENOBUFS)?;
        } else {
            snap.xmit_from(&frame, protocol, Some(self))
                .map_err(|()| errno::ENOBUFS)?;
        }
        Ok(len)
    }

    /// `packet_sendmsg_spkt`.
    fn sendmsg_spkt(self: &Arc<Self>, data: &[u8], name: Option<&[u8]>) -> Result<usize, i32> {
        let Some(sa) = name else {
            return Err(errno::ENOTCONN);
        };
        if sa.len() < SOCKADDR_LEN {
            return Err(errno::EINVAL);
        }
        let proto = if sa.len() == SOCKADDR_PKT_LEN {
            u16::from_be_bytes([sa[16], sa[17]])
        } else {
            0
        };
        // `spkt_device[sizeof(spkt_device) - 1] = 0`.
        let device = &sa[2..15];
        let device = &device[..device.iter().position(|&b| b == 0).unwrap_or(device.len())];
        let dev = core::str::from_utf8(device)
            .ok()
            .and_then(|name| dev_by_name(self.net_ns_id, name));
        let Some(dev) = dev else {
            return Err(errno::ENODEV);
        };
        if !dev.up {
            return Err(errno::ENETDOWN);
        }
        let len = data.len();
        let mtu = dev.mtu as usize;
        if len > mtu + ETH_HDR_LEN + VLAN_HLEN {
            return Err(errno::EMSGSIZE);
        }
        if len < ETH_HDR_LEN {
            return Err(errno::EINVAL);
        }
        if len > mtu + ETH_HDR_LEN && !extra_vlan_len_allowed(&dev, data) {
            return Err(errno::EMSGSIZE);
        }
        let Some(snap) = crate::iface::by_index_in(self.net_ns_id, dev.ifindex) else {
            return Err(errno::ENODEV);
        };
        // Legacy packet_sendmsg_spkt deliberately ignores dev_queue_xmit's
        // return value; only modern packet_snd maps NET_XMIT_DROP to ENOBUFS.
        let _ = snap.xmit_from(data, proto, Some(self));
        Ok(len)
    }
}

/// `packet_extra_vlan_len_allowed`.
fn extra_vlan_len_allowed(dev: &NetDev, frame: &[u8]) -> bool {
    dev.hatype == ARPHRD_ETHER
        && frame.len() >= ETH_HDR_LEN
        && u16::from_be_bytes([frame[12], frame[13]]) == ETH_P_8021Q
}

/// `packet_dev_mc`: apply (`add`) or revert one membership on `dev`.
fn packet_dev_mc(dev: &NetDev, ml: &McEntry, add: bool) -> Result<(), i32> {
    let alen = usize::from(ml.alen);
    match ml.mr_type {
        PACKET_MR_MULTICAST | PACKET_MR_UNICAST => {
            if alen != dev.addr_len() {
                return Err(errno::EINVAL);
            }
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&ml.addr[..6]);
            let unicast = ml.mr_type == PACKET_MR_UNICAST;
            if add {
                crate::iface::dev_hw_addr_add(dev.net_ns_id, dev.ifindex, addr, unicast)
            } else {
                crate::iface::dev_hw_addr_del(dev.net_ns_id, dev.ifindex, addr, unicast)
            }
        }
        PACKET_MR_PROMISC => {
            crate::iface::dev_set_promiscuity(dev.net_ns_id, dev.ifindex, if add { 1 } else { -1 })
        }
        PACKET_MR_ALLMULTI => {
            crate::iface::dev_set_allmulti(dev.net_ns_id, dev.ifindex, if add { 1 } else { -1 })
        }
        _ => Ok(()),
    }
}

fn register_prot_hook(g: &mut Inner) {
    if !g.running {
        g.running = true;
        RUNNING.fetch_add(1, Ordering::AcqRel);
    }
}

fn unregister_prot_hook(g: &mut Inner) {
    if g.running {
        g.running = false;
        RUNNING.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `eth_type_vlan`.
#[must_use]
pub fn eth_type_vlan(proto: u16) -> bool {
    proto == ETH_P_8021Q || proto == ETH_P_8021AD
}

/// The `sk_buff` a hook sees: the linear frame from its MAC header plus
/// the metadata `__netif_receive_skb_core` / `dev_queue_xmit_nit` set.
#[derive(Debug)]
struct Skb<'a> {
    frame: &'a [u8],
    /// `skb_network_offset` from the MAC header.
    net_off: usize,
    /// `skb->protocol`, host order.
    protocol: u16,
    pkt_type: u8,
    /// A tag split off the frame (`skb_vlan_tag_present`).
    vlan: Option<(u16, u16)>,
}

impl Skb<'_> {
    /// `vlan_get_protocol_dgram`: for an in-frame VLAN tag the protocol
    /// behind the tags.
    fn dgram_protocol(&self) -> u16 {
        if !eth_type_vlan(self.protocol) {
            return self.protocol;
        }
        let mut off = 12;
        let mut proto = self.protocol;
        while eth_type_vlan(proto) && self.frame.len() >= off + 2 + VLAN_HLEN {
            off += VLAN_HLEN;
            proto = u16::from_be_bytes([self.frame[off], self.frame[off + 1]]);
        }
        proto
    }
}

/// `eth_type_trans`'s protocol: the type field, or for an 802.3 length the
/// `ETH_P_802_3` / `ETH_P_802_2` guess from the first two payload bytes.
fn eth_proto(frame: &[u8], type_at: usize) -> u16 {
    let ty = u16::from_be_bytes([frame[type_at], frame[type_at + 1]]);
    if ty >= ETH_P_802_3_MIN {
        return ty;
    }
    let sap = frame.get(type_at + 2..type_at + 4);
    if sap == Some(&[0xff, 0xff][..]) {
        ETH_P_802_3
    } else {
        ETH_P_802_2
    }
}

/// `eth_skb_pkt_type`.
fn eth_pkt_type(frame: &[u8], dev: &NetDev) -> u8 {
    let dest = &frame[0..6];
    if dest == dev.dev_addr {
        PACKET_HOST
    } else if dest[0] & 1 != 0 {
        if dest == dev.broadcast() {
            PACKET_BROADCAST
        } else {
            PACKET_MULTICAST
        }
    } else {
        PACKET_OTHERHOST
    }
}

/// `skb_vlan_untag`: split the outer tag off `frame`, returning the
/// untagged frame, `(tci, tpid)` and the encapsulated protocol.
fn vlan_untag(frame: &[u8], tpid: u16) -> Option<(Vec<u8>, (u16, u16), u16)> {
    if frame.len() < ETH_HDR_LEN + VLAN_HLEN {
        return None;
    }
    let tci = u16::from_be_bytes([frame[14], frame[15]]);
    let proto = eth_proto(frame, 16);
    let mut untagged = Vec::with_capacity(frame.len() - VLAN_HLEN);
    untagged.extend_from_slice(&frame[..12]);
    untagged.extend_from_slice(&frame[16..]);
    Some((untagged, (tci, tpid), proto))
}

/// Snapshot the hooks that match `(dev, protocol)` in `net_ns_id`.
fn hooks(net_ns_id: u64, ifindex: u32, matches: impl Fn(u16) -> bool) -> Vec<Arc<PacketSock>> {
    SKLIST
        .lock()
        .iter()
        .filter(|s| s.net_ns_id == net_ns_id)
        .filter(|s| {
            let g = s.inner.lock();
            g.running && g.bound_dev.is_none_or(|d| d == ifindex) && matches(g.num)
        })
        .cloned()
        .collect()
}

/// Receive-side tap: `__netif_receive_skb_core` from the packet-socket
/// point of view. `dev` is the ingress device; `frame` starts at the MAC
/// header.
pub fn netif_receive(dev: &NetIfaceSnapshot, frame: &[u8]) {
    if RUNNING.load(Ordering::Acquire) == 0 || frame.len() < ETH_HDR_LEN {
        return;
    }
    let dev = NetDev::from_snapshot(dev);
    // `enqueue_to_backlog`: a device that is not running delivers nothing.
    if !dev.up {
        return;
    }
    let pkt_type = eth_pkt_type(frame, &dev);
    let mut protocol = eth_proto(frame, 12);
    // `if (eth_type_vlan(skb->protocol)) skb = skb_vlan_untag(skb);`
    let mut owned: Option<Vec<u8>> = None;
    let mut vlan = None;
    if eth_type_vlan(protocol) {
        if let Some((untagged, tag, inner)) = vlan_untag(frame, protocol) {
            owned = Some(untagged);
            vlan = Some(tag);
            protocol = inner;
        }
    }
    let ns = dev.net_ns_id;
    // `ptype_all` (global, then the device's own list).
    {
        let bytes = owned.as_deref().unwrap_or(frame);
        let skb = Skb {
            frame: bytes,
            net_off: ETH_HDR_LEN,
            protocol,
            pkt_type,
            vlan,
        };
        for sock in hooks(ns, dev.ifindex, |num| num == ETH_P_ALL) {
            sock.rcv(&dev, &skb);
        }
    }
    // No VLAN device claims a tag: `check_vlan_id`. A non-zero VID makes the
    // frame PACKET_OTHERHOST; a priority tag (VID 0) over another tag is
    // stripped and the inner tag examined in turn.
    let mut pkt_type = pkt_type;
    while let Some((tci, _)) = vlan {
        if tci & 0x0fff != 0 {
            pkt_type = PACKET_OTHERHOST;
            vlan = None;
        } else if eth_type_vlan(protocol) {
            let bytes = owned.clone().unwrap_or_else(|| frame.to_vec());
            match vlan_untag(&bytes, protocol) {
                Some((untagged, tag, inner)) => {
                    owned = Some(untagged);
                    vlan = Some(tag);
                    protocol = inner;
                }
                None => vlan = None,
            }
        } else {
            vlan = None;
        }
    }
    let bytes = owned.as_deref().unwrap_or(frame);
    let skb = Skb {
        frame: bytes,
        net_off: ETH_HDR_LEN,
        protocol,
        pkt_type,
        vlan: None,
    };
    // `ptype_base[protocol]` plus the device's specific list.
    for sock in hooks(ns, dev.ifindex, |num| num == protocol && num != ETH_P_ALL) {
        sock.rcv(&dev, &skb);
    }
}

/// `dev_queue_xmit_nit`: show a transmitted frame to every `ETH_P_ALL`
/// hook on `dev` as `PACKET_OUTGOING`, skipping hooks that set
/// `PACKET_IGNORE_OUTGOING` and the sending socket itself (`skb_loop_sk`).
/// `protocol` is `skb->protocol` (host order).
pub fn dev_queue_xmit_nit(
    dev: &NetIfaceSnapshot,
    frame: &[u8],
    protocol: u16,
    origin: Option<&PacketSock>,
) {
    if RUNNING.load(Ordering::Acquire) == 0 || frame.len() < ETH_HDR_LEN {
        return;
    }
    // Read the device's live state: callers may hold a snapshot taken long
    // before (TCP caches its egress), and a device that is down transmits
    // nothing for a tap to see.
    let Some(dev) = dev_by_index(dev.net_ns_id, dev.ifindex) else {
        return;
    };
    if !dev.up {
        return;
    }
    // `packet_parse_headers` / the IP stack leave the network header past
    // any in-frame VLAN tags of a VLAN-typed frame.
    let mut net_off = ETH_HDR_LEN;
    if eth_type_vlan(protocol) {
        let mut proto = protocol;
        while eth_type_vlan(proto) && frame.len() >= net_off + VLAN_HLEN {
            proto = u16::from_be_bytes([frame[net_off + 2], frame[net_off + 3]]);
            net_off += VLAN_HLEN;
        }
    }
    let skb = Skb {
        frame,
        net_off,
        protocol,
        pkt_type: PACKET_OUTGOING,
        vlan: None,
    };
    for sock in hooks(dev.net_ns_id, dev.ifindex, |num| num == ETH_P_ALL) {
        if origin.is_some_and(|o| core::ptr::eq(o, Arc::as_ptr(&sock))) {
            continue;
        }
        if sock.inner.lock().opts.ignore_outgoing {
            continue;
        }
        sock.rcv(&dev, &skb);
    }
}

/// The protocol the IP stack stamps on a frame it transmits
/// (`skb->protocol`): the frame's own type field.
#[must_use]
pub fn tx_protocol(frame: &[u8]) -> u16 {
    if frame.len() < ETH_HDR_LEN {
        return 0;
    }
    u16::from_be_bytes([frame[12], frame[13]])
}

/// Device notifier events `packet_notifier` handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetdevEvent {
    Up,
    Down,
    /// The device left `net_ns_id` (`NETDEV_UNREGISTER` in that namespace).
    Unregister,
}

/// `packet_notifier` for an ordinary event whose device is still found in
/// `net_ns_id` (UP/DOWN, or unregister-before-removal).
pub fn netdev_event(net_ns_id: u64, ifindex: u32, event: NetdevEvent) {
    netdev_event_inner(net_ns_id, ifindex, event, None);
}

/// `dev_change_net_namespace` has already published the device in its new
/// namespace when it reports NETDEV_UNREGISTER to the old namespace.  Keep a
/// snapshot of that same device so packet_flush_mclist can undo its hardware
/// address/promiscuity references after removing old-namespace memberships.
pub(crate) fn netdev_unregister_moved(old_net_ns_id: u64, moved: &NetIfaceSnapshot) {
    let dev = NetDev::from_snapshot(moved);
    netdev_event_inner(
        old_net_ns_id,
        moved.ifindex,
        NetdevEvent::Unregister,
        Some(&dev),
    );
}

fn netdev_event_inner(
    net_ns_id: u64,
    ifindex: u32,
    event: NetdevEvent,
    cleanup_dev: Option<&NetDev>,
) {
    let live_dev = cleanup_dev
        .cloned()
        .or_else(|| dev_by_index(net_ns_id, ifindex));
    let socks: Vec<Arc<PacketSock>> = SKLIST
        .lock()
        .iter()
        .filter(|s| s.net_ns_id == net_ns_id)
        .cloned()
        .collect();
    for sock in socks {
        let mut g = sock.inner.lock();
        let removed = if event == NetdevEvent::Unregister {
            // `packet_dev_mclist_delete`: memberships on a vanished device
            // leave the socket list, then packet_dev_mc(-1) runs outside the
            // socket lock just as Linux drops its RCU read-side section first.
            let (removed, kept): (Vec<_>, Vec<_>) = g
                .mclist
                .drain(..)
                .partition(|ml| ml.ifindex == ifindex as i32);
            g.mclist = kept;
            removed
        } else {
            Vec::new()
        };
        if g.ifindex != ifindex as i32 {
            drop(g);
            if let Some(dev) = &live_dev {
                for ml in removed {
                    let _ = packet_dev_mc(dev, &ml, false);
                }
            }
            continue;
        }
        match event {
            NetdevEvent::Down | NetdevEvent::Unregister => {
                if g.running {
                    unregister_prot_hook(&mut g);
                    g.sk_err = errno::ENETDOWN;
                    sock.sync_readiness(&g);
                    sock.readiness.notify(POLL_ERR);
                }
                if event == NetdevEvent::Unregister {
                    g.ifindex = -1;
                    g.bound_dev = None;
                }
            }
            NetdevEvent::Up => {
                if g.num != 0 {
                    register_prot_hook(&mut g);
                }
            }
        }
        drop(g);
        if let Some(dev) = &live_dev {
            for ml in removed {
                let _ = packet_dev_mc(dev, &ml, false);
            }
        }
    }
}

/// Snapshot of one packet socket for `/proc/net/raw`. The raw row format is
/// the same as TCP/UDP — local/remote address, queues — even though most
/// fields are unused for a packet socket.
#[derive(Clone, Debug)]
pub struct RawSocketSnapshot {
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    /// Convention: 7=CLOSE for raw (no L4 state).
    pub state_code: u8,
    pub protocol: u8,
}

/// Snapshot every packet socket in the initial namespace.
#[must_use]
pub fn snapshot() -> Vec<RawSocketSnapshot> {
    snapshot_in(0)
}

#[must_use]
pub fn snapshot_in(net_ns_id: u64) -> Vec<RawSocketSnapshot> {
    SKLIST
        .lock()
        .iter()
        .filter(|s| s.net_ns_id == net_ns_id)
        .map(|s| {
            let num = s.inner.lock().num;
            RawSocketSnapshot {
                local_addr: [0u8; 4],
                local_port: 0,
                remote_addr: [0u8; 4],
                remote_port: 0,
                state_code: 0x07,
                // ETH_P_ALL → 0xFF sentinel: there is no L4 protocol number.
                protocol: if num == ETH_P_ALL {
                    0xFF
                } else {
                    (num & 0xFF) as u8
                },
            }
        })
        .collect()
}

pub(crate) fn remove_namespace(net_ns_id: u64) {
    let removed: Vec<Arc<PacketSock>> = {
        let mut list = SKLIST.lock();
        let (gone, kept): (Vec<_>, Vec<_>) = list.drain(..).partition(|s| s.net_ns_id == net_ns_id);
        *list = kept;
        gone
    };
    for sock in removed {
        unregister_prot_hook(&mut sock.inner.lock());
    }
}
