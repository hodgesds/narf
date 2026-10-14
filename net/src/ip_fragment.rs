//! IPv4 fragment reassembly for locally delivered datagrams.
//!
//! Linux ref: `net/ipv4/ip_fragment.c` (`ip_defrag`, `ip_frag_queue`,
//! `ip_frag_reasm`, `ip_expire`) and `net/ipv4/inet_fragment.c`
//! (`inet_frag_find`, `inet_frag_queue_insert`). `ip_local_deliver` calls
//! `ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER)` when `ip_is_fragment()`,
//! after the input routing decision and before `NF_INET_LOCAL_IN`, so
//! forwarded fragments are never reassembled and LOCAL_IN sees the whole
//! datagram. [`crate::tcp_stack`]'s `handle_ipv4` calls [`ip_defrag`] at the
//! same point.
//!
//! What is mirrored, in Linux's order:
//!
//! * Queue key `(saddr, daddr, id, protocol)` per network namespace. The
//!   `user` part of Linux's key is always `IP_DEFRAG_LOCAL_DELIVER` here, and
//!   `vif` is the L3 master device index, which NARF does not have (0).
//! * `ipfrag_high_thresh` (4 MiB): once the namespace's fragment memory is
//!   above it, `inet_frag_find` refuses every fragment — new or for an
//!   existing queue — and `ip_defrag` counts a ReasmFails. Queues that stop
//!   receiving then die by timeout. `ipfrag_low_thresh` (3 MiB) has no
//!   datapath effect in Linux since the evictor was removed; it is kept as
//!   the documented default only.
//! * `ipfrag_time` (30 s) from queue creation. On expiry ReasmFails and
//!   ReasmTimeout are counted and, if the offset-0 fragment arrived, an ICMP
//!   Time Exceeded / fragment reassembly time exceeded is sent quoting it.
//! * `ip_frag_queue`: a last fragment ending short of data already seen, or
//!   disagreeing with an earlier last fragment, discards the queue; a
//!   non-last fragment's length is TRUNCATED to a multiple of 8 (Linux does
//!   not drop it), and one reaching past a known end discards the queue; a
//!   fragment left with no data discards the queue.
//! * `inet_frag_queue_insert`, including its fragment-run structure: a
//!   fragment entirely inside one existing run is `IPFRAG_DUP` (dropped,
//!   queue kept), any other overlap is `IPFRAG_OVERLAP` and discards the
//!   whole queue (RFC 5722, the CVE-2018-5391 hardening).
//! * `ip_frag_reasm`: invalid ECN mixes and a reassembled length above
//!   65535 fail; the result carries the first fragment's header with total
//!   length fixed, MF/offset cleared (DF kept only when the largest fragment
//!   had DF), ECN CE folded in, and a recomputed header checksum.
//!
//! The non-fragment fast path is [`is_fragment`]: one branch on the
//! flags/offset word, no lock, no allocation.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::pkt::ip_checksum;

/// `IP_FRAG_TIME` — fragment lifetime (`include/net/ip.h`: `30 * HZ`).
pub const IPFRAG_TIME_NS: u64 = 30_000_000_000;
/// `net->ipv4.fqdir->high_thresh` default (`ipv4_frags_init_net`).
pub const IPFRAG_HIGH_THRESH: usize = 4 * 1024 * 1024;
/// `net->ipv4.fqdir->low_thresh` default. Sysctl-only in Linux: nothing in
/// the datapath reads it.
pub const IPFRAG_LOW_THRESH: usize = 3 * 1024 * 1024;

const IP_DF: u16 = 0x4000;
const IP_MF: u16 = 0x2000;
const IP_OFFSET: u16 = 0x1FFF;
const IPV4_MIN_HDR: usize = 20;

/// Stand-in for `skb->truesize`'s fixed part: `SKB_DATA_ALIGN(sizeof(struct
/// sk_buff)) + SKB_DATA_ALIGN(sizeof(struct skb_shared_info))` on x86_64
/// (256 + 320). Each queued fragment is charged its bytes plus this, so the
/// 4 MiB threshold bounds roughly the same fragment count it does in Linux.
const SKB_TRUESIZE_OVERHEAD: usize = 576;

// `IPFRAG_ECN_*` (`include/net/inet_frag.h`).
const IPFRAG_ECN_NOT_ECT: u8 = 0x01;
const IPFRAG_ECN_ECT_1: u8 = 0x02;
const IPFRAG_ECN_ECT_0: u8 = 0x04;
const IPFRAG_ECN_CE: u8 = 0x08;
const INET_ECN_CE: u8 = 3;

/// `ip_frag_ecn_table` (`net/ipv4/inet_fragment.c`): the ECN bits to OR into
/// the reassembled header, or `0xff` for a mix that must be dropped.
fn ip_frag_ecn_table(seen: u8) -> u8 {
    let not_ect = seen & IPFRAG_ECN_NOT_ECT != 0;
    let ce = seen & IPFRAG_ECN_CE != 0;
    let ect = seen & (IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1) != 0;
    if not_ect && (ce || ect) {
        0xff
    } else if ce && ect {
        INET_ECN_CE
    } else {
        0
    }
}

/// `ip_is_fragment()`: MF set or a nonzero offset. `packet` is an IPv4
/// packet already validated by `parse_ipv4`.
#[inline]
pub fn is_fragment(packet: &[u8]) -> bool {
    packet.len() >= IPV4_MIN_HDR
        && u16::from_be_bytes([packet[6], packet[7]]) & (IP_MF | IP_OFFSET) != 0
}

/// `struct frag_v4_compare_key`, minus `user`/`vif` (constant here), plus
/// the namespace that owns the `fqdir`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FragKey {
    saddr: [u8; 4],
    daddr: [u8; 4],
    id: u16,
    protocol: u8,
}

/// A run of contiguous fragments — `FRAG_CB(head)->frag_run_len` and the
/// skbs chained behind it, flattened into one buffer.
#[derive(Debug)]
struct Run {
    offset: usize,
    data: Vec<u8>,
}

impl Run {
    fn end(&self) -> usize {
        self.offset + self.data.len()
    }
}

/// `struct ipq` / `struct inet_frag_queue`.
#[derive(Debug)]
struct Queue {
    /// Runs sorted by offset, non-overlapping. The last run holds
    /// `fragments_tail`: fragments inserted by the rb-tree search always lie
    /// below it.
    runs: Vec<Run>,
    /// `q.len`: the datagram length implied so far.
    len: usize,
    /// `q.meat`: bytes actually queued.
    meat: usize,
    first_in: bool,
    last_in: bool,
    /// The offset-0 fragment's IP header (options included) — the head of
    /// the reassembled datagram and of the ICMP quote.
    head_hdr: Vec<u8>,
    /// Payload length of the offset-0 fragment (what `ip_expire` quotes).
    head_len: usize,
    /// `qp->iif`: the interface the latest fragment arrived on.
    iif: String,
    /// `qp->ecn`: `IPFRAG_ECN_*` bits seen.
    ecn: u8,
    max_size: usize,
    max_df_size: usize,
    created_ns: u64,
    /// This queue's share of the namespace's fragment memory.
    mem: usize,
}

/// `/proc/net/snmp` reassembly counters (`IPSTATS_MIB_REASM*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReasmStats {
    pub reqds: u64,
    pub oks: u64,
    pub fails: u64,
    pub timeout: u64,
}

/// Per-namespace `struct fqdir`.
#[derive(Debug)]
struct Fqdir {
    queues: BTreeMap<FragKey, Queue>,
    mem: usize,
    high_thresh: usize,
    stats: ReasmStats,
}

impl Fqdir {
    fn new() -> Self {
        Self {
            queues: BTreeMap::new(),
            mem: 0,
            high_thresh: IPFRAG_HIGH_THRESH,
            stats: ReasmStats::default(),
        }
    }

    /// `inet_frag_kill` + the final `inet_frag_putn`: unhash and free.
    fn kill(&mut self, key: &FragKey) {
        if let Some(q) = self.queues.remove(key) {
            self.mem = self.mem.saturating_sub(q.mem);
            QUEUE_COUNT.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

static FQDIRS: IrqSafeSpinLock<BTreeMap<u64, Fqdir>> = IrqSafeSpinLock::new(BTreeMap::new());
/// Live queues across all namespaces, so the timer tick skips the lock when
/// nothing is being reassembled.
static QUEUE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// `inet_frag_queue_insert` results.
enum Insert {
    Ok,
    Dup,
    Overlap,
}

/// `inet_frag_queue_insert` over the flattened run list.
fn queue_insert(runs: &mut Vec<Run>, offset: usize, end: usize, data: &[u8]) -> Insert {
    let Some(last) = runs.last_mut() else {
        // First fragment: `fragrun_create`.
        runs.push(Run {
            offset,
            data: data.to_vec(),
        });
        return Insert::Ok;
    };
    let tail_end = last.end();
    if tail_end < end {
        // The common case: the fragment goes to the end.
        if offset < tail_end {
            return Insert::Overlap;
        }
        if offset == tail_end {
            // `fragrun_append_to_last`.
            last.data.extend_from_slice(data);
        } else {
            runs.push(Run {
                offset,
                data: data.to_vec(),
            });
        }
        return Insert::Ok;
    }
    // The rb-tree search. Runs never overlap, so the first run the fragment
    // intersects decides: wholly inside it is a duplicate, anything else an
    // overlap. A fragment inserted here always starts a run of its own.
    let mut at = runs.len();
    for (i, run) in runs.iter().enumerate() {
        if end <= run.offset {
            at = i;
            break;
        }
        if offset >= run.end() {
            continue;
        }
        if offset >= run.offset && end <= run.end() {
            return Insert::Dup;
        }
        return Insert::Overlap;
    }
    runs.insert(
        at,
        Run {
            offset,
            data: data.to_vec(),
        },
    );
    Insert::Ok
}

/// Reassemble `packet` (an IPv4 packet for which [`is_fragment`] holds,
/// already routed to local delivery) that arrived on `iface_in`.
///
/// Returns the reassembled datagram once the last missing piece arrives;
/// `None` while the datagram is incomplete or when the fragment was dropped
/// (`ip_defrag` returning nonzero — the skb is consumed either way).
pub fn ip_defrag(net_ns_id: u64, iface_in: &str, packet: &[u8]) -> Option<Vec<u8>> {
    let now = narf_scheduler::narf_time::monotonic_ns();
    ip_defrag_at(now, net_ns_id, iface_in, packet)
}

/// [`ip_defrag`] with an explicit clock, so the timeout can be exercised
/// deterministically.
#[doc(hidden)]
pub fn ip_defrag_at(now_ns: u64, net_ns_id: u64, iface_in: &str, packet: &[u8]) -> Option<Vec<u8>> {
    let (hdr, payload) = split(packet)?;
    let key = FragKey {
        saddr: [hdr[12], hdr[13], hdr[14], hdr[15]],
        daddr: [hdr[16], hdr[17], hdr[18], hdr[19]],
        id: u16::from_be_bytes([hdr[4], hdr[5]]),
        protocol: hdr[9],
    };

    let mut all = FQDIRS.lock();
    let dir = all.entry(net_ns_id).or_insert_with(Fqdir::new);
    dir.stats.reqds += 1;

    // `inet_frag_find`: over the high threshold, nothing is looked up or
    // created.
    if dir.high_thresh == 0 || dir.mem > dir.high_thresh {
        dir.stats.fails += 1;
        return None;
    }
    if let alloc::collections::btree_map::Entry::Vacant(slot) = dir.queues.entry(key) {
        // `inet_frag_alloc` charges the queue itself (`f->qsize`).
        let qsize = core::mem::size_of::<Queue>();
        slot.insert(Queue {
            runs: Vec::new(),
            len: 0,
            meat: 0,
            first_in: false,
            last_in: false,
            head_hdr: Vec::new(),
            head_len: 0,
            iif: String::new(),
            ecn: 0,
            max_size: 0,
            max_df_size: 0,
            created_ns: now_ns,
            mem: qsize,
        });
        dir.mem += qsize;
        QUEUE_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    frag_queue(dir, key, iface_in, hdr, payload)
}

/// Split a validated IPv4 packet into header and (Total-Length-trimmed)
/// payload.
fn split(packet: &[u8]) -> Option<(&[u8], &[u8])> {
    if packet.len() < IPV4_MIN_HDR {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ihl < IPV4_MIN_HDR || total < ihl || total > packet.len() {
        return None;
    }
    Some((&packet[..ihl], &packet[ihl..total]))
}

/// `ip_frag_queue` (+ `ip_frag_reasm` on completion).
fn frag_queue(
    dir: &mut Fqdir,
    key: FragKey,
    iface_in: &str,
    hdr: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    let ihl = hdr.len();
    let tos = hdr[1];
    let frag_word = u16::from_be_bytes([hdr[6], hdr[7]]);
    let ecn = 1u8 << (tos & 0x03);
    let offset = ((frag_word & IP_OFFSET) as usize) << 3;
    let mut end = offset + payload.len();

    let q = dir.queues.get_mut(&key)?;
    let mut discard = false;
    if frag_word & IP_MF == 0 {
        // The final fragment: data already beyond its end, or a different
        // end from an earlier final fragment, is corruption.
        if end < q.len || (q.last_in && end != q.len) {
            discard = true;
        } else {
            q.last_in = true;
            q.len = end;
        }
    } else {
        // Non-final fragments carry a multiple of 8 bytes; Linux trims the
        // excess rather than dropping the fragment.
        end &= !7;
        if end > q.len {
            if q.last_in {
                discard = true;
            } else {
                q.len = end;
            }
        }
    }
    if !discard && end == offset {
        discard = true;
    }
    if discard {
        dir.kill(&key);
        dir.stats.fails += 1;
        return None;
    }
    let data = &payload[..end - offset];

    match queue_insert(&mut q.runs, offset, end, data) {
        Insert::Ok => {}
        // `IPFRAG_DUP`: drop the skb, keep the queue.
        Insert::Dup => return None,
        // `IPFRAG_OVERLAP`: ReasmOverlaps (netstat) and the whole queue goes.
        Insert::Overlap => {
            dir.kill(&key);
            dir.stats.fails += 1;
            return None;
        }
    }

    if q.iif != iface_in {
        q.iif = String::from(iface_in);
    }
    q.meat += data.len();
    q.ecn |= ecn;
    let charge = ihl + data.len() + SKB_TRUESIZE_OVERHEAD;
    q.mem += charge;
    dir.mem += charge;
    if offset == 0 {
        q.first_in = true;
        q.head_hdr = hdr.to_vec();
        q.head_len = data.len();
    }
    let fragsize = data.len() + ihl;
    if fragsize > q.max_size {
        q.max_size = fragsize;
    }
    if frag_word & IP_DF != 0 && fragsize > q.max_df_size {
        q.max_df_size = fragsize;
    }

    if !(q.first_in && q.last_in && q.meat == q.len) {
        return None;
    }

    // ── ip_frag_reasm ── (the queue is unhashed first, whatever happens)
    let q = dir.queues.remove(&key)?;
    dir.mem = dir.mem.saturating_sub(q.mem);
    QUEUE_COUNT.fetch_sub(1, Ordering::Relaxed);

    let ecn_bits = ip_frag_ecn_table(q.ecn);
    if ecn_bits == 0xff {
        dir.stats.fails += 1;
        return None;
    }
    let head_ihl = q.head_hdr.len();
    let len = head_ihl + q.len;
    if len > 65535 {
        // `-E2BIG`: "Oversized IP packet".
        dir.stats.fails += 1;
        return None;
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&q.head_hdr);
    for run in &q.runs {
        out.extend_from_slice(&run.data);
    }
    out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    out[1] |= ecn_bits;
    // DF survives only when the largest fragment carried it, so a forwarded
    // refragmentation never emits DF pieces bigger than the sender's.
    let frag_off = if q.max_df_size == q.max_size {
        IP_DF
    } else {
        0
    };
    out[6..8].copy_from_slice(&frag_off.to_be_bytes());
    out[10..12].copy_from_slice(&[0, 0]);
    let cs = ip_checksum(&out[..head_ihl]);
    out[10..12].copy_from_slice(&cs.to_be_bytes());
    dir.stats.oks += 1;
    Some(out)
}

/// One expired queue that owes the sender an ICMP error.
#[derive(Debug)]
struct Expired {
    net_ns_id: u64,
    iif: String,
    /// The offset-0 fragment as received: header + its own payload.
    head: Vec<u8>,
}

/// Net timer tick: expire queues older than `ipfrag_time`.
pub fn tick() {
    if QUEUE_COUNT.load(Ordering::Relaxed) == 0 {
        return;
    }
    expire_at(narf_scheduler::narf_time::monotonic_ns());
}

/// `ip_expire` for every queue created at least [`IPFRAG_TIME_NS`] before
/// `now_ns`. Returns how many queues expired.
#[doc(hidden)]
pub fn expire_at(now_ns: u64) -> usize {
    let mut owed: Vec<Expired> = Vec::new();
    let mut expired = 0;
    {
        let mut all = FQDIRS.lock();
        for (&net_ns_id, dir) in all.iter_mut() {
            let dead: Vec<FragKey> = dir
                .queues
                .iter()
                .filter(|(_, q)| now_ns.saturating_sub(q.created_ns) >= IPFRAG_TIME_NS)
                .map(|(k, _)| *k)
                .collect();
            for key in dead {
                let Some(q) = dir.queues.remove(&key) else {
                    continue;
                };
                dir.mem = dir.mem.saturating_sub(q.mem);
                QUEUE_COUNT.fetch_sub(1, Ordering::Relaxed);
                dir.stats.fails += 1;
                dir.stats.timeout += 1;
                expired += 1;
                if !q.first_in {
                    continue;
                }
                // The head is the lowest run; offset 0 is in it.
                let Some(first) = q.runs.first().filter(|r| r.offset == 0) else {
                    continue;
                };
                let mut head = q.head_hdr.clone();
                head.extend_from_slice(&first.data[..q.head_len.min(first.data.len())]);
                owed.push(Expired {
                    net_ns_id,
                    iif: q.iif,
                    head,
                });
            }
        }
    }
    // Sent with the lock dropped: the ICMP path takes the iface and ARP
    // locks and transmits.
    for e in owed {
        send_reasm_timeout(&e);
    }
    expired
}

/// The tail of `ip_expire`: re-route the head, then `icmp_send(head,
/// ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME, 0)` with `__icmp_send`'s gates.
fn send_reasm_timeout(e: &Expired) {
    use crate::pkt_icmp_extra::{build_time_exceeded, TE_FRAGMENT_REASSEMBLY_TIMEOUT};
    let head = &e.head;
    if head.len() < IPV4_MIN_HDR {
        return;
    }
    let ihl = ((head[0] & 0x0F) as usize) * 4;
    let src = [head[12], head[13], head[14], head[15]];
    let dst = [head[16], head[17], head[18], head[19]];
    // `head->dev = dev_get_by_index_rcu(net, qp->iif)`: gone → no ICMP.
    match crate::iface::lookup_in(e.net_ns_id, &e.iif) {
        Some(dev) if dev.net_ns_id == e.net_ns_id => {}
        _ => return,
    }
    // `ip_route_input_noref` again; the queue only ever held local traffic,
    // so a destination no longer local means the route went away.
    if !crate::ip_local::deliver_locally_in(e.net_ns_id, dst) {
        return;
    }
    // `__icmp_send`: no errors about broadcast/multicast destinations ...
    if crate::ip_local::is_limited_broadcast(dst)
        || crate::ip_local::is_multicast(dst)
        || crate::ip_local::is_broadcast_or_multicast_on(&e.iif, dst)
    {
        return;
    }
    // ... nor about non-first fragments, bogus sources, or ICMP errors.
    if !crate::ip_forward::icmp_error_permitted(head, ihl) {
        return;
    }
    crate::ip_forward::send_icmp_error_nonblocking(
        e.net_ns_id,
        crate::ipv4::Ipv4Addr(src),
        Some(dst),
        build_time_exceeded(TE_FRAGMENT_REASSEMBLY_TIMEOUT, head),
    );
}

/// `/proc/net/snmp` reassembly counters for `net_ns_id`.
pub fn stats_in(net_ns_id: u64) -> ReasmStats {
    FQDIRS
        .lock()
        .get(&net_ns_id)
        .map(|d| d.stats)
        .unwrap_or_default()
}

/// `fqdir_exit`: a dead namespace's queues are freed without ICMP.
pub(crate) fn remove_namespace(net_ns_id: u64) {
    if let Some(dir) = FQDIRS.lock().remove(&net_ns_id) {
        QUEUE_COUNT.fetch_sub(dir.queues.len(), Ordering::Relaxed);
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    FQDIRS.lock().clear();
    QUEUE_COUNT.store(0, Ordering::Relaxed);
}

/// Write `net.ipv4.ipfrag_high_thresh` for `net_ns_id`.
#[doc(hidden)]
pub fn __set_high_thresh_for_test(net_ns_id: u64, bytes: usize) {
    FQDIRS
        .lock()
        .entry(net_ns_id)
        .or_insert_with(Fqdir::new)
        .high_thresh = bytes;
}

/// `(live queues, fragment memory)` for `net_ns_id`.
#[doc(hidden)]
pub fn __usage_in(net_ns_id: u64) -> (usize, usize) {
    FQDIRS
        .lock()
        .get(&net_ns_id)
        .map_or((0, 0), |d| (d.queues.len(), d.mem))
}
