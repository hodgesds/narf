//! Network scaling harness (`net/scale`).
//!
//! The hardware this tree boots on tops out at a 1 Gb/s link, so progress
//! towards 100 Gb/s and beyond has to be visible in software. This module
//! drives the real stack entry points with a model NIC and reports what one
//! core spends per packet and per byte, and how that cost changes when
//! several cores do the same work at once. Contention shows up as sub-linear
//! scaling.
//!
//! Four experiments, all through public entry points:
//!
//! - **RX pktgen** — pre-built TCP (and UDP) flows are injected into
//!   [`iface::on_native_rx_timestamped`], the call a NIC pump makes per frame,
//!   on N CPUs at once. A sink reads the socket after every poll burst and
//!   accounts delivered bytes.
//! - **Hairpin** — a sender and a receiver connection joined by a model NIC
//!   whose transmit hook is a bounded descriptor ring drained at a configured
//!   wire rate. Every byte goes `send` → `pump_send` → ring → wire → RX → ACK
//!   → `recv`, so it is both the transmit-side measurement (backpressure, TSO
//!   batching) and the stack-only "loopback" ceiling.
//! - **Card profiles** — the same two experiments parameterised by a
//!   [`CardProfile`]: link speed, queue count, ring size, poll budget and
//!   interrupt moderation. One run models a 1 Gb/s, a 25 Gb/s and a 100 Gb/s
//!   card, which is how "no constant tuned for one card" gets checked.
//! - **Timer sweep** — the per-connection cost of the periodic timer scan.
//!
//! Every result is a `NETBENCH` line, which `cargo xtask test` relays after
//! the summary. The numbers come from a QEMU guest on a shared host: they are
//! **harness numbers, not performance claims** (`verification/` §8 governs
//! those). Use them to rank bottlenecks and to compare before and after a
//! change on the same machine. The tests always pass unless the harness
//! itself is broken (nothing delivered); they are not gates.
//!
//! Compiled only under `kernel-test`; production kernels link none of it and
//! no counter here sits on a production path.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_console::klog;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::narf_time::{cycles_to_ns, now_cycles, ns_to_cycles};
use narf_scheduler::{spawn_with_spec, Affinity, CpuId, TaskSpec};

use crate::iface;
use crate::pkt::{set_ipv4_checksum, ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_TCP, IP_PROTO_UDP};
use crate::pkt_tcp::{ipv4_pseudo_checksum, ipv4_pseudo_checksum_proto, FLAG_ACK, FLAG_PSH};
use crate::tcp::core as tcp;
use crate::tcp::state_machine::TcpState;
use crate::udp_sock::{self, SocketAddrV4, UdpOptions, UdpSocket};

// ── Card profiles ───────────────────────────────────────────────────

/// What a network card contributes to the data path's sizing. The harness
/// takes these as parameters so one run can model several cards; nothing in
/// the experiments is tuned for one of them.
#[derive(Clone, Copy)]
struct CardProfile {
    name: &'static str,
    /// Negotiated link speed.
    link_mbps: u64,
    mtu: usize,
    /// Hardware RX/TX queue pairs (RSS width).
    queues: usize,
    /// Descriptors per ring.
    ring: usize,
    /// Descriptors one poll may consume.
    budget: usize,
    /// Interrupt moderation interval.
    itr_us: u64,
    /// Largest TSO frame the card segments, 0 for none.
    tso_bytes: u32,
}

/// The cards modelled by `scale_card_profiles`. The first row is what NARF's
/// igc driver programs on the I225 today; the others are typical defaults of
/// 25 Gb/s and 100 Gb/s adapters, and the last is the 100 Gb/s card with
/// jumbo frames. Add a row to model another card.
const PROFILES: [CardProfile; 4] = [
    CardProfile {
        name: "1G-I225",
        link_mbps: 1_000,
        mtu: 1500,
        queues: 4,
        ring: 256,
        budget: 64,
        itr_us: 166,
        tso_bytes: 65_535,
    },
    CardProfile {
        name: "25G",
        link_mbps: 25_000,
        mtu: 1500,
        queues: 8,
        ring: 1024,
        budget: 64,
        itr_us: 50,
        tso_bytes: 65_535,
    },
    CardProfile {
        name: "100G",
        link_mbps: 100_000,
        mtu: 1500,
        queues: 16,
        ring: 4096,
        budget: 64,
        itr_us: 8,
        tso_bytes: 65_535,
    },
    CardProfile {
        name: "100G-9k",
        link_mbps: 100_000,
        mtu: 9000,
        queues: 16,
        ring: 4096,
        budget: 64,
        itr_us: 8,
        tso_bytes: 65_535,
    },
];

/// Preamble, start delimiter, FCS and inter-frame gap: the bytes a frame
/// occupies on the wire beyond its Ethernet header and payload.
const WIRE_OVERHEAD: usize = 24;

impl CardProfile {
    /// Frames per second the link carries at full-size frames.
    fn line_pps(&self) -> u64 {
        let frame_bits = ((self.mtu + ETH_HDR_LEN + WIRE_OVERHEAD) * 8) as u64;
        self.link_mbps * 1_000_000 / frame_bits
    }

    /// Frames one queue sees per poll when the link is saturated and RSS
    /// spreads evenly: what arrives in one moderation interval, bounded by
    /// the poll budget and the ring.
    fn frames_per_poll(&self) -> usize {
        let per_queue = self.line_pps() / self.queues.max(1) as u64;
        let per_irq = (per_queue * self.itr_us / 1_000_000) as usize;
        per_irq.clamp(1, self.budget.min(self.ring))
    }
}

// ── Parallel runner ─────────────────────────────────────────────────

/// Most CPUs an experiment runs on. The model stays inside what a small
/// host can give a guest without oversubscribing its physical cores.
const MAX_WORKERS: usize = 4;

const ARMED: u64 = 0;
const RUN: u64 = 1;
const STOP: u64 = 2;

/// `(generation << 2) | state`. One word, so a worker left over from an
/// abandoned round can never mistake a later round's start for its own.
static PHASE: AtomicU64 = AtomicU64::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);

const fn phase(generation: u64, state: u64) -> u64 {
    (generation << 2) | state
}

/// A worker's view of the round it belongs to.
struct Ctl {
    generation: u64,
    /// The leader runs on the test's own CPU and ends the round.
    leader: bool,
    deadline: u64,
}

impl Ctl {
    /// Whether the round is over. The leader ends it when the measurement
    /// interval has passed; everyone else follows the shared word.
    fn stopped(&self) -> bool {
        if PHASE.load(Ordering::Relaxed) != phase(self.generation, RUN) {
            return true;
        }
        if self.leader && now_cycles() >= self.deadline {
            PHASE.store(phase(self.generation, STOP), Ordering::Release);
            return true;
        }
        false
    }
}

fn spin_until(deadline: u64, mut done: impl FnMut() -> bool) -> bool {
    loop {
        if done() {
            return true;
        }
        if now_cycles() >= deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

fn ms_from_now(ms: u64) -> u64 {
    now_cycles().wrapping_add(ns_to_cycles(ms * 1_000_000))
}

/// Online CPUs other than the caller's, at most `n`.
fn other_cpus(n: usize) -> Vec<u32> {
    let me = narf_lib::percpu::current_cpu() as u32;
    let bits = narf_scheduler::online_cpu_set().bits();
    (0..64u32)
        .filter(|cpu| bits & (1u64 << cpu) != 0 && *cpu != me)
        .take(n)
        .collect()
}

/// How many workers an experiment may ask for on this machine.
fn usable_workers() -> usize {
    (other_cpus(MAX_WORKERS).len() + 1).min(MAX_WORKERS)
}

/// Run `work` once per element of `args`, all at the same time, each on its
/// own CPU, for `ms` milliseconds. The first element runs on the caller's CPU
/// and ends the round; the rest run as tasks pinned to other CPUs. `None`
/// when the other CPUs did not take their tasks in time (the round is
/// abandoned and the tasks exit on their own).
fn run_parallel<A, O>(mut args: Vec<A>, ms: u64, work: fn(&mut A, &Ctl) -> O) -> Option<Vec<O>>
where
    A: Send + 'static,
    O: Send + 'static,
{
    let n = args.len();
    if n == 0 {
        return None;
    }
    let cpus = other_cpus(n - 1);
    if cpus.len() < n - 1 {
        return None;
    }
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    PHASE.store(phase(generation, ARMED), Ordering::Release);
    let ready = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let results: Arc<IrqSafeSpinLock<Vec<Option<O>>>> =
        Arc::new(IrqSafeSpinLock::new((0..n).map(|_| None).collect()));

    let mut leader_args = args.remove(0);
    for (i, mut a) in args.into_iter().enumerate() {
        let (ready, done, results) = (ready.clone(), done.clone(), results.clone());
        let mut spec = TaskSpec::unthrottled();
        spec.affinity = Affinity::pinned(CpuId(cpus[i]));
        spawn_with_spec(
            async move {
                ready.fetch_add(1, Ordering::AcqRel);
                loop {
                    let now = PHASE.load(Ordering::Acquire);
                    if now == phase(generation, RUN) {
                        break;
                    }
                    if now != phase(generation, ARMED) {
                        return;
                    }
                    narf_scheduler::yield_now().await;
                }
                let ctl = Ctl {
                    generation,
                    leader: false,
                    deadline: 0,
                };
                let out = work(&mut a, &ctl);
                results.lock()[i + 1] = Some(out);
                done.fetch_add(1, Ordering::AcqRel);
            },
            spec,
        );
    }
    if !spin_until(ms_from_now(3_000), || {
        ready.load(Ordering::Acquire) == n - 1
    }) {
        PHASE.store(phase(generation, STOP), Ordering::Release);
        return None;
    }
    let ctl = Ctl {
        generation,
        leader: true,
        deadline: ms_from_now(ms),
    };
    PHASE.store(phase(generation, RUN), Ordering::Release);
    let out = work(&mut leader_args, &ctl);
    PHASE.store(phase(generation, STOP), Ordering::Release);
    results.lock()[0] = Some(out);
    if !spin_until(ms_from_now(10_000), || {
        done.load(Ordering::Acquire) == n - 1
    }) {
        return None;
    }
    let collected: Vec<Option<O>> = core::mem::take(&mut *results.lock());
    collected.into_iter().collect()
}

// ── Counters ────────────────────────────────────────────────────────

/// One cache line per slot: a counter the model NIC bumps on one CPU must
/// not share a line with another CPU's, or the harness would manufacture the
/// contention it is trying to measure.
#[repr(align(64))]
struct TxCounters {
    frames: AtomicU64,
    bytes: AtomicU64,
    tso_frames: AtomicU64,
    doorbells: AtomicU64,
    refused: AtomicU64,
}

impl TxCounters {
    const fn new() -> Self {
        Self {
            frames: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            tso_frames: AtomicU64::new(0),
            doorbells: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }

    fn reset(&self) {
        self.frames.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
        self.tso_frames.store(0, Ordering::Relaxed);
        self.doorbells.store(0, Ordering::Relaxed);
        self.refused.store(0, Ordering::Relaxed);
    }
}

const MAX_CPUS: usize = narf_lib::percpu::MAX_CPUS;

/// Frames the stack handed the pktgen NIC (its ACKs), per transmitting CPU.
static PKTGEN_TX: [TxCounters; MAX_CPUS] = [const { TxCounters::new() }; MAX_CPUS];

fn pktgen_tx_frames() -> u64 {
    PKTGEN_TX
        .iter()
        .map(|c| c.frames.load(Ordering::Relaxed))
        .sum()
}

/// The pktgen NIC's transmit hook: a sink that counts.
fn pktgen_send(frame: &[u8], _meta: crate::TxMeta) -> Result<(), ()> {
    let c = &PKTGEN_TX[narf_lib::percpu::current_cpu().min(MAX_CPUS - 1)];
    c.frames.fetch_add(1, Ordering::Relaxed);
    c.bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
    Ok(())
}

/// Slab allocations plus frees (objects up to 4 KiB) since boot, all CPUs.
/// Larger allocations go to the page allocator and are not counted.
fn slab_ops() -> u64 {
    let s = narf_memory::slab::magazine_stats();
    s.mag_hit_count.wrapping_add(s.mag_miss_count)
}

// ── Frame construction ──────────────────────────────────────────────

const DUT_MAC: [u8; 6] = [0x02, 0, 0, 0x5c, 0xa1, 0x01];
const PEER_MAC: [u8; 6] = [0x52, 0x54, 0, 0, 0, 1];
const TCP_OFF: usize = ETH_HDR_LEN + IPV4_HDR_LEN;
const TCP_HDR: usize = 20;
const UDP_HDR: usize = 8;

/// Sum of big-endian 16-bit words, unfolded. Frames here are far too short
/// to overflow a `u32`.
fn sum_words(bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    let mut sum = 0u32;
    for w in &mut chunks {
        sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn write_eth_ipv4(frame: &mut [u8], proto: u8, src: [u8; 4], dst: [u8; 4]) {
    frame[..6].copy_from_slice(&DUT_MAC);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = ETH_HDR_LEN;
    let ip_total = (frame.len() - ETH_HDR_LEN) as u16;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&ip_total.to_be_bytes());
    // DF with a fixed ID, as a Linux sender emits for a connected socket.
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = proto;
    frame[ip + 12..ip + 16].copy_from_slice(&src);
    frame[ip + 16..ip + 20].copy_from_slice(&dst);
    set_ipv4_checksum(&mut frame[ip..ip + IPV4_HDR_LEN]);
}

/// One pktgen TCP flow: a data-segment template and what is needed to stamp
/// the next sequence number into it without summing the payload again.
struct RxFlow {
    tcb: u32,
    frame: Vec<u8>,
    /// Checksum sum of the pseudo-header, the header with sequence number 0
    /// and the payload.
    base: u32,
    seq: u32,
}

impl RxFlow {
    fn new(tcb: u32, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: usize) -> Self {
        let mut frame = vec![0u8; TCP_OFF + TCP_HDR + payload];
        write_eth_ipv4(&mut frame, IP_PROTO_TCP, src, dst);
        frame[TCP_OFF..TCP_OFF + 2].copy_from_slice(&sport.to_be_bytes());
        frame[TCP_OFF + 2..TCP_OFF + 4].copy_from_slice(&dport.to_be_bytes());
        // Acknowledge nothing new: the test connection's `snd_una`.
        frame[TCP_OFF + 8..TCP_OFF + 12].copy_from_slice(&TEST_ISS.to_be_bytes());
        frame[TCP_OFF + 12] = (TCP_HDR as u8 / 4) << 4;
        frame[TCP_OFF + 13] = FLAG_ACK;
        frame[TCP_OFF + 14..TCP_OFF + 16].copy_from_slice(&u16::MAX.to_be_bytes());
        for (i, b) in frame[TCP_OFF + TCP_HDR..].iter_mut().enumerate() {
            *b = i as u8;
        }
        let tcp_len = (TCP_HDR + payload) as u32;
        let base = sum_words(&src)
            + sum_words(&dst)
            + u32::from(IP_PROTO_TCP)
            + tcp_len
            + sum_words(&frame[TCP_OFF..]);
        Self {
            tcb,
            frame,
            base,
            seq: TEST_IRS,
        }
    }

    /// Make the template the next segment of the flow. `push` marks the last
    /// segment of a burst, as the tail of a sender's TSO frame is.
    fn stamp(&mut self, push: bool) {
        let seq = self.seq;
        let flags = if push { FLAG_ACK | FLAG_PSH } else { FLAG_ACK };
        self.frame[TCP_OFF + 4..TCP_OFF + 8].copy_from_slice(&seq.to_be_bytes());
        self.frame[TCP_OFF + 13] = flags;
        let sum = self.base + (seq >> 16) + (seq & 0xffff) + u32::from(flags & FLAG_PSH);
        let csum = !fold(sum);
        self.frame[TCP_OFF + 16..TCP_OFF + 18].copy_from_slice(&csum.to_be_bytes());
    }
}

/// A UDP datagram frame with a valid checksum.
fn udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: usize) -> Vec<u8> {
    let mut frame = vec![0u8; TCP_OFF + UDP_HDR + payload];
    write_eth_ipv4(&mut frame, IP_PROTO_UDP, src, dst);
    let udp_len = (UDP_HDR + payload) as u16;
    frame[TCP_OFF..TCP_OFF + 2].copy_from_slice(&sport.to_be_bytes());
    frame[TCP_OFF + 2..TCP_OFF + 4].copy_from_slice(&dport.to_be_bytes());
    frame[TCP_OFF + 4..TCP_OFF + 6].copy_from_slice(&udp_len.to_be_bytes());
    for (i, b) in frame[TCP_OFF + UDP_HDR..].iter_mut().enumerate() {
        *b = i as u8;
    }
    let csum = ipv4_pseudo_checksum_proto(src, dst, IP_PROTO_UDP, &frame[TCP_OFF..]);
    let csum = if csum == 0 { 0xffff } else { csum };
    frame[TCP_OFF + 6..TCP_OFF + 8].copy_from_slice(&csum.to_be_bytes());
    frame
}

// ── Test connections ────────────────────────────────────────────────

/// `__install_test_tcb_in` starts every connection at these sequence numbers.
const TEST_ISS: u32 = 0x10000;
const TEST_IRS: u32 = 0x20000;
/// Window scale both ends of a test connection use.
const TEST_WSCALE: u8 = 7;

/// Give an installed test connection the state a completed handshake would
/// have left: sequence numbers `iss` / `irs`, window scaling on, `mss` bytes
/// per segment, and a receive buffer of `rcvbuf` bytes.
fn tune_tcb(id: u32, iss: u32, irs: u32, mss: u16, rcvbuf: usize) {
    tcp::__with_tcb_mut(id, |t| {
        t.iss = iss;
        t.snd_una = iss;
        t.snd_nxt = iss;
        t.snd_high = iss;
        t.send_buf.unacked_head_seq = iss;
        t.irs = irs;
        t.rcv_nxt = irs;
        t.rcv_wup = irs;
        t.snd_wl1 = irs;
        t.snd_wl2 = iss;
        t.snd_wnd = 256 * 1024;
        t.opts.wscale_active = true;
        t.opts.our_wscale = TEST_WSCALE;
        t.opts.peer_wscale = TEST_WSCALE;
        t.opts.peer_mss = mss;
        t.opts.our_mss = mss;
        t.cong.mss = u32::from(mss);
        t.recv_buf.limit = rcvbuf;
        t.nagle_enabled = false;
    });
}

// ── RX pktgen ───────────────────────────────────────────────────────

const PKTGEN_IFACE: &str = "nspg0";
const PKTGEN_LOCAL: [u8; 4] = [10, 77, 0, 1];
const PKTGEN_PORT: u16 = 5001;
/// Flows each pktgen worker rotates through, one burst at a time.
const FLOWS_PER_WORKER: usize = 4;
/// Largest burst a pktgen receive buffer must hold between reads.
const PKTGEN_RCVBUF: usize = 4 * 1024 * 1024;

/// Bring the stack up as `install_net_stack` does on a real boot. The
/// kernel-test boot skips that step, and without the receive handlers every
/// injected frame is counted and dropped at the interface. Netfilter is
/// reset first because `tcp_stack::init` registers the default hooks again.
fn stack_up() {
    crate::netfilter::__reset_all_for_test();
    crate::tcp_stack::init();
}

fn pktgen_up(gro: bool, mtu: usize) {
    stack_up();
    iface::register(PKTGEN_IFACE, DUT_MAC, pktgen_send);
    iface::set_mtu(PKTGEN_IFACE, mtu as u32);
    iface::set_link_state(PKTGEN_IFACE, true);
    iface::add_addr(PKTGEN_IFACE, PKTGEN_LOCAL, 16);
    iface::set_offloads(
        PKTGEN_IFACE,
        crate::OffloadCapabilities {
            tx_checksum: true,
            rx_checksum: true,
            max_tso_bytes: 0,
            vlan_insert: false,
        },
    );
    iface::set_software_gro(PKTGEN_IFACE, gro);
}

fn pktgen_down() {
    iface::del_addr(PKTGEN_IFACE, PKTGEN_LOCAL, 16);
    iface::unregister(PKTGEN_IFACE);
}

struct RxArgs {
    flows: Vec<RxFlow>,
    burst: usize,
    payload: u32,
    sink: Vec<u8>,
}

#[derive(Clone, Copy, Default)]
struct RxOut {
    packets: u64,
    bytes_in: u64,
    bytes_out: u64,
    stack_cycles: u64,
    read_cycles: u64,
}

/// One pktgen queue: inject a poll burst into the stack's RX entry point,
/// flush GRO as a driver does when its ring drains, then read the socket as
/// the application would.
fn rx_tcp_worker(a: &mut RxArgs, ctl: &Ctl) -> RxOut {
    let mut out = RxOut::default();
    let mut turn = 0usize;
    while !ctl.stopped() {
        let flow_count = a.flows.len();
        let flow = &mut a.flows[turn % flow_count];
        turn += 1;
        let t0 = now_cycles();
        for i in 0..a.burst {
            flow.stamp(i + 1 == a.burst);
            iface::on_native_rx_timestamped(PKTGEN_IFACE, &mut flow.frame, None);
            flow.seq = flow.seq.wrapping_add(a.payload);
        }
        crate::tcp_stack::gro_flush();
        let t1 = now_cycles();
        while let Ok(n) = tcp::recv_errno(flow.tcb, &mut a.sink) {
            if n == 0 {
                break;
            }
            out.bytes_out += n as u64;
        }
        let t2 = now_cycles();
        out.packets += a.burst as u64;
        out.bytes_in += a.burst as u64 * u64::from(a.payload);
        out.stack_cycles += t1.wrapping_sub(t0);
        out.read_cycles += t2.wrapping_sub(t1);
    }
    out
}

/// Totals of one pktgen round across its workers.
#[derive(Clone, Copy, Default)]
struct RxRound {
    /// Sum of the workers' own packets-per-second.
    pps: u64,
    packets: u64,
    bytes_in: u64,
    bytes_out: u64,
    stack_cycles: u64,
    read_cycles: u64,
    tx_frames: u64,
    slab_ops: u64,
}

impl RxRound {
    fn from_workers(outs: &[RxOut], tx_frames: u64, slab_ops: u64) -> Self {
        let mut r = Self {
            tx_frames,
            slab_ops,
            ..Self::default()
        };
        for o in outs {
            let ns = cycles_to_ns(o.stack_cycles + o.read_cycles).max(1);
            r.pps += o.packets.saturating_mul(1_000_000_000) / ns;
            r.packets += o.packets;
            r.bytes_in += o.bytes_in;
            r.bytes_out += o.bytes_out;
            r.stack_cycles += o.stack_cycles;
            r.read_cycles += o.read_cycles;
        }
        r
    }
}

/// How long one measured round runs.
const ROUND_MS: u64 = 150;
/// Rounds per configuration; the best one is reported, which discards
/// rounds the host preempted.
const ROUNDS: usize = 2;

fn rx_tcp_round(workers: usize, burst: usize, payload: usize) -> Option<RxRound> {
    let mut tcbs = Vec::new();
    let mut args = Vec::new();
    for w in 0..workers {
        let mut flows = Vec::new();
        for f in 0..FLOWS_PER_WORKER {
            let remote = [10, 77, 1 + w as u8, 2 + f as u8];
            let rport = 20_000 + (w * FLOWS_PER_WORKER + f) as u16;
            let id = tcp::__install_test_tcb_in(
                0,
                PKTGEN_LOCAL,
                PKTGEN_PORT,
                remote,
                rport,
                TcpState::Established,
            );
            tune_tcb(id, TEST_ISS, TEST_IRS, payload as u16, PKTGEN_RCVBUF);
            tcbs.push(id);
            flows.push(RxFlow::new(
                id,
                remote,
                PKTGEN_LOCAL,
                rport,
                PKTGEN_PORT,
                payload,
            ));
        }
        args.push(RxArgs {
            flows,
            burst,
            payload: payload as u32,
            sink: vec![0u8; 256 * 1024],
        });
    }
    let (tx0, slab0) = (pktgen_tx_frames(), slab_ops());
    let outs = run_parallel(args, ROUND_MS, rx_tcp_worker);
    let (tx1, slab1) = (pktgen_tx_frames(), slab_ops());
    for id in tcbs {
        tcp::remove_tcb(id);
    }
    outs.map(|outs| RxRound::from_workers(&outs, tx1 - tx0, slab1.wrapping_sub(slab0)))
}

fn best_rx(mut round: impl FnMut() -> Option<RxRound>) -> Option<RxRound> {
    let mut best: Option<RxRound> = None;
    for _ in 0..ROUNDS {
        let r = round()?;
        if best.is_none_or(|b| r.pps > b.pps) {
            best = Some(r);
        }
    }
    best
}

/// Print one pktgen result. `base_pps` is the one-CPU rate of the same
/// configuration, for the scaling efficiency.
fn report_rx(
    label: &str,
    workers: usize,
    burst: usize,
    payload: usize,
    r: &RxRound,
    base_pps: u64,
) {
    let packets = r.packets.max(1);
    let stack = r.stack_cycles / packets;
    let read = r.read_cycles / packets;
    let centi_cyc_per_byte = (r.stack_cycles + r.read_cycles) * 100 / r.bytes_in.max(1);
    let gbps_centi = r.pps * payload as u64 * 8 / 10_000_000;
    let efficiency = r.pps * 100 / (base_pps.max(1) * workers as u64);
    let delivered = r.bytes_out * 100 / r.bytes_in.max(1);
    let slab_deci = r.slab_ops * 10 / packets;
    klog!(
        "NETBENCH scale/{} cpus={} burst={} payload={}: {}.{:03} Mpps {}.{:02} Gb/s | {} cyc/pkt stack + {} read ({}.{:02} cyc/B) | scaling {}% | tx {} per 1000 pkts | slab ops {}.{}/pkt | delivered {}% (harness, non-protocol)",
        label,
        workers,
        burst,
        payload,
        r.pps / 1_000_000,
        r.pps / 1_000 % 1_000,
        gbps_centi / 100,
        gbps_centi % 100,
        stack,
        read,
        centi_cyc_per_byte / 100,
        centi_cyc_per_byte % 100,
        efficiency,
        r.tx_frames * 1_000 / packets,
        slab_deci / 10,
        slab_deci % 10,
        delivered
    );
}

/// Worker counts an experiment sweeps: 1, 2, 4, as far as the machine goes.
fn worker_sweep() -> Vec<usize> {
    [1usize, 2, 4]
        .into_iter()
        .filter(|n| *n <= usable_workers())
        .collect()
}

/// TCP receive, per packet and per aggregate, on 1..N CPUs.
fn scale_rx_tcp_pktgen() -> TestResult {
    const PAYLOAD: usize = 1460;
    const BURST: usize = 64;
    for gro in [false, true] {
        pktgen_up(gro, 1500);
        let label = if gro { "rx-tcp-gro" } else { "rx-tcp" };
        let mut base_pps = 0;
        for workers in worker_sweep() {
            let Some(r) = best_rx(|| rx_tcp_round(workers, BURST, PAYLOAD)) else {
                klog!(
                    "NETBENCH scale/{} cpus={}: other CPUs did not run the workers; row skipped",
                    label,
                    workers
                );
                continue;
            };
            if r.bytes_out == 0 {
                pktgen_down();
                return TestResult::Fail("pktgen delivered nothing to the socket");
            }
            if workers == 1 {
                base_pps = r.pps;
            }
            report_rx(label, workers, BURST, PAYLOAD, &r, base_pps);
        }
        pktgen_down();
    }
    TestResult::Pass
}
kernel_test_in!("net/scale", scale_rx_tcp_pktgen);

struct UdpArgs {
    sock: Arc<UdpSocket>,
    frame: Vec<u8>,
    burst: usize,
    payload: u32,
    sink: Vec<u8>,
}

/// One pktgen queue of UDP datagrams, QUIC-sized, to one bound socket.
fn rx_udp_worker(a: &mut UdpArgs, ctl: &Ctl) -> RxOut {
    let mut out = RxOut::default();
    while !ctl.stopped() {
        let t0 = now_cycles();
        for _ in 0..a.burst {
            iface::on_native_rx_timestamped(PKTGEN_IFACE, &mut a.frame, None);
        }
        let t1 = now_cycles();
        while let Ok((n, _)) = udp_sock::udp_recv(&a.sock, &mut a.sink) {
            out.bytes_out += n as u64;
        }
        let t2 = now_cycles();
        out.packets += a.burst as u64;
        out.bytes_in += a.burst as u64 * u64::from(a.payload);
        out.stack_cycles += t1.wrapping_sub(t0);
        out.read_cycles += t2.wrapping_sub(t1);
    }
    out
}

fn rx_udp_round(workers: usize, burst: usize, payload: usize) -> Option<RxRound> {
    let mut socks = Vec::new();
    let mut args = Vec::new();
    for w in 0..workers {
        let port = 7_000 + w as u16;
        let Ok(sock) = udp_sock::udp_bind_in(
            0,
            SocketAddrV4::new(PKTGEN_LOCAL, port),
            UdpOptions::default(),
        ) else {
            break;
        };
        socks.push(sock.clone());
        args.push(UdpArgs {
            sock,
            frame: udp_frame(
                [10, 77, 1 + w as u8, 2],
                PKTGEN_LOCAL,
                40_000,
                port,
                payload,
            ),
            burst,
            payload: payload as u32,
            sink: vec![0u8; 2048],
        });
    }
    let outs = if args.len() == workers {
        let slab0 = slab_ops();
        run_parallel(args, ROUND_MS, rx_udp_worker)
            .map(|outs| RxRound::from_workers(&outs, 0, slab_ops().wrapping_sub(slab0)))
    } else {
        None
    };
    for sock in &socks {
        udp_sock::udp_close(sock);
    }
    outs
}

/// UDP receive on 1..N CPUs. The burst stays under the socket's default
/// 128-datagram queue, so nothing is dropped for want of a reader.
fn scale_rx_udp_pktgen() -> TestResult {
    const PAYLOAD: usize = 1200;
    const BURST: usize = 64;
    pktgen_up(false, 1500);
    let mut base_pps = 0;
    for workers in worker_sweep() {
        let Some(r) = best_rx(|| rx_udp_round(workers, BURST, PAYLOAD)) else {
            klog!(
                "NETBENCH scale/rx-udp cpus={}: round did not run; row skipped",
                workers
            );
            continue;
        };
        if r.bytes_out == 0 {
            pktgen_down();
            return TestResult::Fail("pktgen delivered no datagram to the socket");
        }
        if workers == 1 {
            base_pps = r.pps;
        }
        report_rx("rx-udp", workers, BURST, PAYLOAD, &r, base_pps);
    }
    pktgen_down();
    TestResult::Pass
}
kernel_test_in!("net/scale", scale_rx_udp_pktgen);

// ── Hairpin ─────────────────────────────────────────────────────────

const HAIRPIN_IFACE: &str = "nshp0";
const HAIRPIN_A: [u8; 4] = [10, 79, 0, 1];
const HAIRPIN_B: [u8; 4] = [10, 79, 0, 2];
/// Sender ports start here; a frame's lower port names its worker.
const HAIRPIN_PORT: u16 = 30_000;
const HAIRPIN_PEER_PORT: u16 = 40_000;

/// A frame sitting in the model NIC's transmit ring.
struct RingFrame {
    bytes: Vec<u8>,
    tso_mss: Option<u16>,
    /// The stack left the L4 checksum to the card.
    csum_offload: bool,
}

/// One transmit ring per worker. Frames are routed by flow, not by the CPU
/// that sent them, so an ACK emitted from a timer on another CPU still lands
/// in its connection's ring.
static HAIRPIN_RING: [IrqSafeSpinLock<VecDeque<RingFrame>>; MAX_WORKERS] =
    [const { IrqSafeSpinLock::new(VecDeque::new()) }; MAX_WORKERS];
static HAIRPIN_TX: [TxCounters; MAX_WORKERS] = [const { TxCounters::new() }; MAX_WORKERS];
/// Descriptors per ring in the current experiment.
static HAIRPIN_RING_SIZE: AtomicUsize = AtomicUsize::new(256);

/// The hairpin NIC's transmit hook: post one descriptor, or refuse when the
/// ring is full, as a driver with no free descriptor does.
fn hairpin_send(frame: &[u8], meta: crate::TxMeta) -> Result<(), ()> {
    if frame.len() < TCP_OFF + 4 || frame[ETH_HDR_LEN + 9] != IP_PROTO_TCP {
        return Ok(());
    }
    let sport = u16::from_be_bytes([frame[TCP_OFF], frame[TCP_OFF + 1]]);
    let dport = u16::from_be_bytes([frame[TCP_OFF + 2], frame[TCP_OFF + 3]]);
    let w = usize::from(sport.min(dport).wrapping_sub(HAIRPIN_PORT));
    if w >= MAX_WORKERS {
        return Ok(());
    }
    let counters = &HAIRPIN_TX[w];
    // The copy a driver without an owned-frame path makes into its DMA
    // buffer. Taken before the ring lock so the lock covers a push only.
    let posted = RingFrame {
        bytes: frame.to_vec(),
        tso_mss: meta.tso_mss,
        csum_offload: meta.tso_mss.is_some() || meta.csum_l4.is_some(),
    };
    {
        let mut ring = HAIRPIN_RING[w].lock();
        if ring.len() >= HAIRPIN_RING_SIZE.load(Ordering::Relaxed) {
            drop(ring);
            counters.refused.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
        ring.push_back(posted);
    }
    counters.frames.fetch_add(1, Ordering::Relaxed);
    counters
        .bytes
        .fetch_add(frame.len() as u64, Ordering::Relaxed);
    if meta.tso_mss.is_some() {
        counters.tso_frames.fetch_add(1, Ordering::Relaxed);
    }
    if !meta.more {
        counters.doorbells.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

fn hairpin_up(tso_bytes: u32, gro: bool, mtu: usize, ring: usize) {
    stack_up();
    HAIRPIN_RING_SIZE.store(ring, Ordering::Relaxed);
    iface::register(HAIRPIN_IFACE, DUT_MAC, hairpin_send);
    iface::set_mtu(HAIRPIN_IFACE, mtu as u32);
    iface::set_link_state(HAIRPIN_IFACE, true);
    iface::add_addr(HAIRPIN_IFACE, HAIRPIN_A, 24);
    iface::add_addr(HAIRPIN_IFACE, HAIRPIN_B, 24);
    iface::set_offloads(
        HAIRPIN_IFACE,
        crate::OffloadCapabilities {
            tx_checksum: true,
            rx_checksum: true,
            max_tso_bytes: tso_bytes,
            vlan_insert: false,
        },
    );
    iface::set_software_gro(HAIRPIN_IFACE, gro);
}

fn hairpin_down() {
    iface::del_addr(HAIRPIN_IFACE, HAIRPIN_B, 24);
    iface::del_addr(HAIRPIN_IFACE, HAIRPIN_A, 24);
    iface::unregister(HAIRPIN_IFACE);
    for ring in &HAIRPIN_RING {
        ring.lock().clear();
    }
}

struct HairpinArgs {
    worker: usize,
    sender: u32,
    receiver: u32,
    budget: usize,
    /// Wire rate, 0 for unlimited.
    link_mbps: u64,
    mss: usize,
    source: Vec<u8>,
    sink: Vec<u8>,
}

#[derive(Clone, Copy, Default)]
struct HairpinOut {
    sent: u64,
    received: u64,
    send_cycles: u64,
    wire_cycles: u64,
    rx_cycles: u64,
    read_cycles: u64,
    wall_cycles: u64,
}

/// What the card does to a frame the stack left unfinished: fill in the TCP
/// checksum the stack offloaded.
fn finish_tcp_checksum(frame: &mut [u8]) {
    if frame.len() < TCP_OFF + TCP_HDR {
        return;
    }
    let ip = ETH_HDR_LEN;
    let src = [
        frame[ip + 12],
        frame[ip + 13],
        frame[ip + 14],
        frame[ip + 15],
    ];
    let dst = [
        frame[ip + 16],
        frame[ip + 17],
        frame[ip + 18],
        frame[ip + 19],
    ];
    frame[TCP_OFF + 16] = 0;
    frame[TCP_OFF + 17] = 0;
    let csum = ipv4_pseudo_checksum(src, dst, &frame[TCP_OFF..]);
    frame[TCP_OFF + 16..TCP_OFF + 18].copy_from_slice(&csum.to_be_bytes());
}

/// One connection pair on one CPU: the application writes, the model NIC
/// carries what the wire rate allows from its ring to the receive entry
/// point, and the application on the far end reads.
fn hairpin_worker(a: &mut HairpinArgs, ctl: &Ctl) -> HairpinOut {
    let mut out = HairpinOut::default();
    let ring = &HAIRPIN_RING[a.worker];
    let mut staged: Vec<RingFrame> = Vec::new();
    let mut wire: Vec<Vec<u8>> = Vec::new();
    let mut wire_bytes = 0u64;
    let start = now_cycles();
    while !ctl.stopped() {
        let t0 = now_cycles();
        if let Ok(n) = tcp::send_errno(a.sender, &a.source) {
            out.sent += n as u64;
        }
        let t1 = now_cycles();

        // The wire: take what the link could have carried by now.
        let allowed = if a.link_mbps == 0 {
            u64::MAX
        } else {
            let elapsed_ns = cycles_to_ns(t1.wrapping_sub(start));
            (elapsed_ns * a.link_mbps / 8_000).saturating_sub(wire_bytes)
        };
        let mut taken = 0u64;
        {
            let mut ring = ring.lock();
            while staged.len() < a.budget {
                let Some(front) = ring.front() else { break };
                let segments = front.bytes.len().div_ceil(a.mss.max(1)) as u64;
                let on_wire = front.bytes.len() as u64 + segments * WIRE_OVERHEAD as u64;
                if a.link_mbps != 0 && taken + on_wire > allowed {
                    break;
                }
                taken += on_wire;
                staged.extend(ring.pop_front());
            }
        }
        wire_bytes += taken;
        // The card: segment TSO frames, complete offloaded checksums.
        for mut frame in staged.drain(..) {
            match frame.tso_mss {
                Some(mss) => wire.extend(
                    crate::gso::segment_ipv4_tcp(&frame.bytes, usize::from(mss))
                        .unwrap_or_default(),
                ),
                None => {
                    if frame.csum_offload {
                        finish_tcp_checksum(&mut frame.bytes);
                    }
                    wire.push(frame.bytes);
                }
            }
        }
        let t2 = now_cycles();

        let delivered = !wire.is_empty();
        for frame in wire.iter_mut() {
            iface::on_native_rx_timestamped(HAIRPIN_IFACE, frame, None);
        }
        wire.clear();
        if delivered {
            crate::tcp_stack::gro_flush();
        }
        let t3 = now_cycles();

        let before = out.received;
        while let Ok(n) = tcp::recv_errno(a.receiver, &mut a.sink) {
            if n == 0 {
                break;
            }
            out.received += n as u64;
        }
        let t4 = now_cycles();

        out.send_cycles += t1.wrapping_sub(t0);
        out.wire_cycles += t2.wrapping_sub(t1);
        out.rx_cycles += t3.wrapping_sub(t2);
        out.read_cycles += t4.wrapping_sub(t3);
        if !delivered && out.received == before {
            // Nothing moved: let the connection's timers run.
            tcp::tick_all();
            core::hint::spin_loop();
        }
    }
    out.wall_cycles = now_cycles().wrapping_sub(start);
    out
}

/// Totals of one hairpin round.
#[derive(Clone, Copy, Default)]
struct HairpinRound {
    goodput_bps: u64,
    sent: u64,
    received: u64,
    send_cycles: u64,
    wire_cycles: u64,
    rx_cycles: u64,
    read_cycles: u64,
    frames: u64,
    frame_bytes: u64,
    tso_frames: u64,
    doorbells: u64,
    refused: u64,
    retransmits: u64,
}

/// Install a sender/receiver pair for worker `w` and return their ids.
fn hairpin_pair(w: usize, mss: u16) -> (u32, u32) {
    let (sport, rport) = (HAIRPIN_PORT + w as u16, HAIRPIN_PEER_PORT + w as u16);
    let sender =
        tcp::__install_test_tcb_in(0, HAIRPIN_A, sport, HAIRPIN_B, rport, TcpState::Established);
    let receiver =
        tcp::__install_test_tcb_in(0, HAIRPIN_B, rport, HAIRPIN_A, sport, TcpState::Established);
    tune_tcb(sender, TEST_ISS, TEST_IRS, mss, 256 * 1024);
    tune_tcb(receiver, TEST_IRS, TEST_ISS, mss, 256 * 1024);
    (sender, receiver)
}

fn hairpin_round(
    flows: usize,
    budget: usize,
    link_mbps: u64,
    mss: usize,
    ms: u64,
) -> Option<HairpinRound> {
    let mut pairs = Vec::new();
    let mut args = Vec::new();
    for w in 0..flows {
        HAIRPIN_TX[w].reset();
        HAIRPIN_RING[w].lock().clear();
        let (sender, receiver) = hairpin_pair(w, mss as u16);
        pairs.push((sender, receiver));
        args.push(HairpinArgs {
            worker: w,
            sender,
            receiver,
            budget,
            link_mbps,
            mss,
            source: vec![0x5au8; 64 * 1024],
            sink: vec![0u8; 256 * 1024],
        });
    }
    let outs = run_parallel(args, ms, hairpin_worker);
    let mut round = HairpinRound::default();
    for (w, (sender, receiver)) in pairs.iter().enumerate() {
        round.retransmits += tcp::__with_tcb(*sender, |t| u64::from(t.total_retrans)).unwrap_or(0);
        let c = &HAIRPIN_TX[w];
        round.frames += c.frames.load(Ordering::Relaxed);
        round.frame_bytes += c.bytes.load(Ordering::Relaxed);
        round.tso_frames += c.tso_frames.load(Ordering::Relaxed);
        round.doorbells += c.doorbells.load(Ordering::Relaxed);
        round.refused += c.refused.load(Ordering::Relaxed);
        tcp::remove_tcb(*sender);
        tcp::remove_tcb(*receiver);
        HAIRPIN_RING[w].lock().clear();
    }
    let outs = outs?;
    for o in &outs {
        let ns = cycles_to_ns(o.wall_cycles).max(1);
        round.goodput_bps += o.received.saturating_mul(8_000_000_000) / ns;
        round.sent += o.sent;
        round.received += o.received;
        round.send_cycles += o.send_cycles;
        round.wire_cycles += o.wire_cycles;
        round.rx_cycles += o.rx_cycles;
        round.read_cycles += o.read_cycles;
    }
    Some(round)
}

fn centi_per_byte(cycles: u64, bytes: u64) -> (u64, u64) {
    let c = cycles * 100 / bytes.max(1);
    (c / 100, c % 100)
}

fn report_hairpin(label: &str, flows: usize, r: &HairpinRound, base_bps: u64) {
    let gbps_centi = r.goodput_bps / 10_000_000;
    let bytes = r.received.max(1);
    let (s0, s1) = centi_per_byte(r.send_cycles, bytes);
    let (w0, w1) = centi_per_byte(r.wire_cycles, bytes);
    let (x0, x1) = centi_per_byte(r.rx_cycles, bytes);
    let (a0, a1) = centi_per_byte(r.read_cycles, bytes);
    let efficiency = r.goodput_bps * 100 / (base_bps.max(1) * flows as u64);
    klog!(
        "NETBENCH scale/{} flows={}: {}.{:02} Gb/s goodput, {} of {} MiB queued were delivered | cyc/B send {}.{:02} card-model {}.{:02} rx+ack {}.{:02} read {}.{:02} | scaling {}% | {} B/frame, {} of {} frames TSO, {} doorbells | ring refused {} retransmits {} (harness, non-protocol)",
        label,
        flows,
        gbps_centi / 100,
        gbps_centi % 100,
        r.received >> 20,
        r.sent >> 20,
        s0,
        s1,
        w0,
        w1,
        x0,
        x1,
        a0,
        a1,
        efficiency,
        r.frame_bytes / r.frames.max(1),
        r.tso_frames,
        r.frames,
        r.doorbells,
        r.refused,
        r.retransmits
    );
}

/// How long one hairpin round runs. Longer than a pktgen round: the
/// connection has to leave slow start before the rate means anything.
const HAIRPIN_MS: u64 = 250;

/// Stack-only ceiling: sender and receiver through the whole stack with an
/// unlimited wire and a ring too large to refuse, on 1..N CPUs.
fn scale_tcp_hairpin() -> TestResult {
    const MSS: usize = 1460;
    for (label, tso_bytes) in [("hairpin-tso", 65_535u32), ("hairpin-notso", 0)] {
        hairpin_up(tso_bytes, true, 1500, 1 << 20);
        let mut base = 0;
        for flows in worker_sweep() {
            let Some(r) = hairpin_round(flows, 64, 0, MSS, HAIRPIN_MS) else {
                klog!(
                    "NETBENCH scale/{} flows={}: round did not run; row skipped",
                    label,
                    flows
                );
                continue;
            };
            if flows == 1 {
                if r.received == 0 {
                    hairpin_down();
                    return TestResult::Fail("hairpin moved no data end to end");
                }
                base = r.goodput_bps;
            }
            report_hairpin(label, flows, &r, base);
        }
        hairpin_down();
    }
    TestResult::Pass
}
kernel_test_in!("net/scale", scale_tcp_hairpin);

// ── Card profiles ───────────────────────────────────────────────────

/// Model each card in [`PROFILES`]: receive at the burst length its link
/// speed, queue count and moderation produce, and transmit through a ring of
/// its size drained at its link speed.
fn scale_card_profiles() -> TestResult {
    for p in PROFILES {
        let payload = p.mtu - IPV4_HDR_LEN - TCP_HDR;
        let queues = p.queues.min(usable_workers());
        let burst = p.frames_per_poll();
        let line_pps = p.line_pps();
        let queue_pps = line_pps / p.queues as u64;
        klog!(
            "NETBENCH scale/card {} link={}Mb/s mtu={} queues={} ring={} budget={} itr={}us: line rate {} pps, {} pps/queue, {} frames/poll, a stalled pump overflows the ring in {} us (arithmetic)",
            p.name,
            p.link_mbps,
            p.mtu,
            p.queues,
            p.ring,
            p.budget,
            p.itr_us,
            line_pps,
            queue_pps,
            burst,
            p.ring as u64 * 1_000_000 / queue_pps.max(1)
        );

        // Two regimes: the burst the card delivers while the core keeps up
        // with its moderation timer, and a full poll budget, which is what
        // the ring holds once the core has fallen behind.
        pktgen_up(true, p.mtu);
        let light = best_rx(|| rx_tcp_round(queues, burst, payload));
        let full = best_rx(|| rx_tcp_round(queues, p.budget.min(p.ring), payload));
        pktgen_down();
        match (light, full) {
            (Some(light), Some(full)) if light.packets > 0 && full.packets > 0 => {
                let per_queue = full.pps / queues as u64;
                klog!(
                    "NETBENCH scale/card {} rx: {} of {} queues modelled, {} cyc/pkt at {} frames/poll, {} cyc/pkt at a full budget; one core takes {} pps = {}% of a queue's line-rate share; the link needs {} such cores; delivered {}% (harness, non-protocol)",
                    p.name,
                    queues,
                    p.queues,
                    (light.stack_cycles + light.read_cycles) / light.packets,
                    burst,
                    (full.stack_cycles + full.read_cycles) / full.packets,
                    per_queue,
                    per_queue * 100 / queue_pps.max(1),
                    line_pps.div_ceil(per_queue.max(1)),
                    full.bytes_out * 100 / full.bytes_in.max(1)
                );
            }
            _ => klog!("NETBENCH scale/card {} rx: round did not run", p.name),
        }

        hairpin_up(p.tso_bytes, true, p.mtu, p.ring);
        let tx = hairpin_round(1, p.budget, p.link_mbps, payload, HAIRPIN_MS);
        hairpin_down();
        match tx {
            Some(r) => {
                let link_bps = p.link_mbps * 1_000_000;
                let gbps_centi = r.goodput_bps / 10_000_000;
                klog!(
                    "NETBENCH scale/card {} tx: one flow {}.{:02} Gb/s = {}% of the link | {} B/frame, {} doorbells for {} frames | ring refused {} retransmits {} (harness, non-protocol)",
                    p.name,
                    gbps_centi / 100,
                    gbps_centi % 100,
                    r.goodput_bps * 100 / link_bps,
                    r.frame_bytes / r.frames.max(1),
                    r.doorbells,
                    r.frames,
                    r.refused,
                    r.retransmits
                );
            }
            None => klog!("NETBENCH scale/card {} tx: round did not run", p.name),
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/scale", scale_card_profiles);

// ── Timer sweep ─────────────────────────────────────────────────────

/// Per-connection cost of the periodic timer scan. `tick_all` visits every
/// connection once a millisecond; this times that visit over idle
/// connections, which is what bounds how many one core can carry.
fn scale_timer_sweep() -> TestResult {
    for count in [1_000usize, 10_000] {
        let ids: Vec<u32> = (0..count)
            .map(|i| {
                tcp::__install_test_tcb_in(
                    0,
                    [10, 80, 0, 1],
                    6_000,
                    [10, 81, (i >> 8) as u8, i as u8],
                    10_000 + (i >> 16) as u16,
                    TcpState::Established,
                )
            })
            .collect();
        let mut best = u64::MAX;
        for _ in 0..3 {
            let t0 = now_cycles();
            for id in &ids {
                if let Some(tcb) = tcp::lookup_tcb(*id) {
                    tcp::tick_retransmit(&tcb);
                }
            }
            best = best.min(now_cycles().wrapping_sub(t0));
        }
        for id in ids {
            tcp::remove_tcb(id);
        }
        let ns_each = cycles_to_ns(best) / count as u64;
        klog!(
            "NETBENCH scale/timer-sweep connections={}: {} cyc, {} ns per connection per scan; a 1 ms scan fills one core at {} connections (harness, non-protocol)",
            count,
            best / count as u64,
            ns_each,
            1_000_000 / ns_each.max(1)
        );
    }
    TestResult::Pass
}
kernel_test_in!("net/scale", scale_timer_sweep);

// ── Loopback probe ──────────────────────────────────────────────────

fn status_name(id: u32) -> &'static str {
    match tcp::connect_status(id) {
        tcp::ConnectStatus::InProgress => "in-progress",
        tcp::ConnectStatus::Connected => "connected",
        tcp::ConnectStatus::Failed(_) => "failed",
    }
}

/// Whether a TCP handshake over the stack's own `lo` completes. `lo` delivers
/// inline, so the reply to a frame is sent while that frame is still being
/// delivered. This records what the stack does with it; the hairpin above is
/// the loopback measurement because it does not depend on the answer.
fn scale_lo_handshake_probe() -> TestResult {
    const PORT: u16 = 47_011;
    stack_up();
    iface::register_loopback_iface();
    crate::route::install_loopback_route();
    let Ok(listener) = tcp::listen_in(0, [127, 0, 0, 1], PORT, 8) else {
        return TestResult::Skip("could not listen on 127.0.0.1");
    };
    let client =
        match tcp::connect_start_in(0, [127, 0, 0, 1], PORT, tcp::ConnectOptions::default()) {
            Ok(id) => id,
            Err(_) => {
                tcp::remove_tcb(listener);
                return TestResult::Skip("could not start a connect to 127.0.0.1");
            }
        };
    let inline = status_name(client);
    spin_until(ms_from_now(50), || {
        tcp::tick_all();
        tcp::connect_status(client) != tcp::ConnectStatus::InProgress
    });
    let later = status_name(client);
    klog!(
        "NETBENCH scale/lo-handshake: connect to 127.0.0.1 is {} when connect returns, {} after 50 ms",
        inline,
        later
    );
    let child = tcp::accept(listener).ok().flatten();
    for snapshot in tcp::snapshot() {
        if snapshot.local_port == PORT || snapshot.remote_port == PORT {
            tcp::remove_tcb(snapshot.id);
        }
    }
    if let Some(child) = child {
        tcp::remove_tcb(child);
    }
    tcp::remove_tcb(client);
    tcp::remove_tcb(listener);
    TestResult::Pass
}
kernel_test_in!("net/scale", scale_lo_handshake_probe);

/// The profile arithmetic is the part of the harness other results rest on.
fn scale_profile_arithmetic() -> TestResult {
    let gig = PROFILES[0];
    // 1 Gb/s of 1538-byte wire frames.
    if gig.line_pps() != 81_274 {
        return TestResult::Fail("1 Gb/s line rate at MTU 1500 is 81274 frames/s");
    }
    // 20318 frames/s per queue over a 166 us interval.
    if gig.frames_per_poll() != 3 {
        return TestResult::Fail("the I225 profile sees 3 frames per poll");
    }
    let hundred = PROFILES[2];
    if hundred.line_pps() != 8_127_438 {
        return TestResult::Fail("100 Gb/s line rate at MTU 1500 is 8127438 frames/s");
    }
    // 507964 frames/s per queue over 8 us.
    if hundred.frames_per_poll() != 4 {
        return TestResult::Fail("the 100G profile sees 4 frames per poll");
    }
    let mut flow = RxFlow::new(0, [10, 0, 0, 2], [10, 0, 0, 1], 1, 2, 100);
    flow.seq = 0xfffe_fff0;
    flow.stamp(true);
    if ipv4_pseudo_checksum([10, 0, 0, 2], [10, 0, 0, 1], &flow.frame[TCP_OFF..]) != 0 {
        return TestResult::Fail("stamped segment does not carry a valid TCP checksum");
    }
    TestResult::Pass
}
kernel_test_in!("net/scale", scale_profile_arithmetic);
