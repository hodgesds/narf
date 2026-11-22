//! Kernel tests for the zero-copy transmit pools of a multi-queue device:
//! every frame must be built in the pool of the queue it is posted on.
//!
//! A driver with a transmit-queue contract posts a flow on the queue it
//! selects (`ndo_select_queue`, [`TxBackpressure::tx_select_queue`]) and
//! recycles a completed frame's buffer into that ring's pool. A frame built
//! in any other queue's pool moves a buffer between pools: on the hardware
//! host (igc, four queues) the stack built every unbound TCP frame in the
//! pool its own 4-tuple hash named, while igc posts by its Toeplitz RSS
//! queue, so the pools the hash picked ran dry ("transmit pool empty",
//! `tx_queue_{0,2}_pool_misses`) while the others filled to their cap.
//! Linux has no pools; it picks a socket's queue once (`netdev_pick_tx`,
//! `sk_tx_queue_set`) and the driver posts on `skb->queue_mapping`.

#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_io::pool::DmaPool;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use crate::iface;
use crate::rss::RssConfig;
use crate::tcp::core::{self, Tcb};
use crate::txq::{TxBackpressure, TxCharge, TxQueue, TxQueueGeometry, TxRefusal};

const QUEUES: usize = 4;
/// igc's indirection table length (`RssConfig::standard(count, 128)`).
const RSS_TABLE: usize = 128;

/// A four-queue device that selects transmit queues exactly as igc does:
/// the Toeplitz RSS queue of the frame's flow (`Igc::tx_select_queue`, and
/// `submit_frame_on` for a frame offered without a queue).
#[derive(Debug)]
struct RssNic {
    rss: RssConfig,
    queues: Vec<Arc<TxQueue>>,
}

impl RssNic {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            rss: RssConfig::standard(QUEUES, RSS_TABLE),
            queues: (0..QUEUES)
                .map(|_| {
                    TxQueue::new(TxQueueGeometry {
                        ring_len: 256,
                        max_frame_descs: 19,
                    })
                })
                .collect(),
        })
    }
}

impl TxBackpressure for RssNic {
    fn tx_queue_count(&self) -> u16 {
        QUEUES as u16
    }
    fn tx_queue(&self, q: u16) -> Option<Arc<TxQueue>> {
        self.queues.get(usize::from(q)).cloned()
    }
    fn tx_select_queue(&self, frame: &[u8]) -> u16 {
        self.rss.rx_queue(frame) as u16
    }
    fn tx_link_speed_mbps(&self) -> u32 {
        1000
    }
    fn try_xmit(
        &self,
        _q: u16,
        _frame: crate::Frame,
        _meta: crate::TxMeta,
    ) -> Result<(), TxRefusal> {
        Ok(())
    }
    fn try_xmit_copy(
        &self,
        _q: u16,
        _frame: &[u8],
        _meta: crate::TxMeta,
        _charge: Option<TxCharge>,
    ) -> Result<(), TxRefusal> {
        Ok(())
    }
}

fn plain_send(_frame: &[u8], _meta: crate::TxMeta) -> Result<(), ()> {
    Ok(())
}

fn owned_send(_frame: crate::Frame, _meta: crate::TxMeta) -> Result<(), ()> {
    Ok(())
}

/// A registered interface with one prefilled pool per queue, flow-affine as
/// igc publishes it, and `nic` as its transmit-queue contract.
fn pooled_iface(name: &str, nic: &Arc<RssNic>) -> Result<iface::NetIfaceSnapshot, &'static str> {
    let name = iface::register(name, [2, 0, 0, 0, 0x7a, 0x11], plain_send);
    let mut pools = Vec::new();
    for _ in 0..QUEUES {
        let pool = Arc::new(DmaPool::new(2048, DomainId::DRIVER_0, 8));
        if pool.prefill(8) != 8 {
            return Err("could not prefill a queue's TX pool");
        }
        pools.push(pool);
    }
    iface::enable_zero_copy_tx_pools_with_affinity(&name, owned_send, pools, 0, true);
    if !iface::set_tx_backpressure(&name, nic.clone()) {
        return Err("the transmit-queue contract was not installed");
    }
    iface::lookup(&name).ok_or("pooled interface lookup failed")
}

/// Build one unbound segment of `t` and check its pool is the queue the
/// driver posts it on (`tx_select_queue` of the frame as built). Returns the
/// queue, so a caller can check the flows covered every queue.
fn check_unbound(
    dev: &iface::NetIfaceSnapshot,
    nic: &RssNic,
    t: &Tcb,
) -> Result<u16, &'static str> {
    if t.tx_bind.is_some() {
        return Err("fixture TCB is already bound to a queue");
    }
    let Some((pool_queue, bytes)) = core::__tcb_frame_pool_queue_for_test(dev, t) else {
        return Err("a prefilled pool gave no buffer");
    };
    let posted = nic.tx_select_queue(&bytes);
    if pool_queue != posted {
        return Err("unbound segment built in a pool not of its posting queue");
    }
    Ok(posted)
}

/// The SYN, the handshake ACK and the first data segment of a connection
/// are built before it is bound to a transmit queue. Each must come from
/// the pool of the queue the driver posts the flow on, for IPv4 and IPv6,
/// over enough flows between one pair of hosts to cover every queue.
fn smoke_txpool_unbound_tcp_builds_in_posting_queue_pool() -> TestResult {
    let nic = RssNic::new();
    let dev = match pooled_iface("txpool-q-selftest", &nic) {
        Ok(dev) => dev,
        Err(e) => return TestResult::Fail(e),
    };
    let local = [192, 168, 3, 165];
    let remote = [95, 216, 195, 133];
    let mut local6 = [0u8; 16];
    local6[..2].copy_from_slice(&[0x20, 0x01]);
    local6[15] = 0x65;
    let mut remote6 = [0u8; 16];
    remote6[..2].copy_from_slice(&[0x2a, 0x01]);
    remote6[15] = 0x33;
    let mut seen4 = [false; QUEUES];
    let mut seen6 = [false; QUEUES];
    let mut result = Ok(());
    for port in 40_000u16..40_064 {
        let t = Tcb::new_active(0, local, port, remote, 80, [0x52, 0x54, 0, 0, 0, 1], 1);
        match check_unbound(&dev, &nic, &t) {
            Ok(q) => seen4[usize::from(q)] = true,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
        let mut t6 = Tcb::new_active(0, [0; 4], port, [0; 4], 443, [0x52, 0x54, 0, 0, 0, 1], 1);
        t6.is_ipv6 = true;
        t6.local_addr6 = local6;
        t6.remote_addr6 = remote6;
        match check_unbound(&dev, &nic, &t6) {
            Ok(q) => seen6[usize::from(q)] = true,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    let _ = iface::unregister(&dev.name);
    if let Err(e) = result {
        return TestResult::Fail(e);
    }
    if seen4.iter().any(|s| !s) || seen6.iter().any(|s| !s) {
        return TestResult::Fail("64 flows between two hosts did not reach every queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/txpool-queue",
    smoke_txpool_unbound_tcp_builds_in_posting_queue_pool
);

/// `ipv4_flow_queue` is the queue a driver without a transmit-queue contract
/// posts a flow on (virtio-net `flow_tx_pair`) and the pool the stack builds
/// that flow's unbound segments in. It must stay symmetric (both directions
/// of a flow on one queue) and spread the flows between one pair of hosts
/// over every queue: the ports, folded into both halves of one word, used to
/// cancel in the finaliser's `h ^ h >> 16`, leaving one port bit to choose,
/// so two hosts' flows reached at most two queues whatever the queue count.
fn smoke_txpool_flow_hash_spreads_ports_over_every_queue() -> TestResult {
    let pairs: [([u8; 4], [u8; 4]); 3] = [
        ([192, 168, 3, 165], [95, 216, 195, 133]),
        ([10, 0, 0, 1], [10, 0, 0, 2]),
        ([192, 0, 2, 11], [198, 51, 100, 7]),
    ];
    const FLOWS: u16 = 1024;
    for queues in [2usize, 4, 8, 16] {
        for (a, b) in pairs {
            let mut hits = [0u32; 16];
            for i in 0..FLOWS {
                let sport = 32_768 + i;
                let q = crate::ipv4_flow_queue(a, b, sport, 443, queues);
                if q >= queues {
                    return TestResult::Fail("flow hash chose a queue out of range");
                }
                if crate::ipv4_flow_queue(b, a, 443, sport, queues) != q {
                    return TestResult::Fail("the two directions of a flow hashed apart");
                }
                hits[q] += 1;
            }
            // Every queue takes at least half of its fair share.
            let fair = u32::from(FLOWS) / queues as u32;
            if hits[..queues].iter().any(|&h| h < fair / 2) {
                return TestResult::Fail("one host pair's ports did not reach every queue");
            }
        }
    }
    if crate::ipv4_flow_queue([1, 2, 3, 4], [5, 6, 7, 8], 1, 2, 1) != 0 {
        return TestResult::Fail("a single queue was not queue 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/txpool-hash",
    smoke_txpool_flow_hash_spreads_ports_over_every_queue
);
