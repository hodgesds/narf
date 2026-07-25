//! NUMA memory tiers and demotion-target selection.
//!
//! Nodes with identical HMAT local bandwidth/latency coordinates share a
//! tier. Lower tier numbers are faster. Unknown nodes remain in tier zero:
//! firmware omissions must not silently classify ordinary DRAM as slow
//! memory. Demotion always moves strictly downward and honors an explicit
//! allowed-node mask.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::frame::{node_distance, MAX_NUMA_NODES};

const UNKNOWN_TIER: u8 = u8::MAX;

static BANDWIDTH: [AtomicU64; MAX_NUMA_NODES] = [const { AtomicU64::new(0) }; MAX_NUMA_NODES];
static LATENCY: [AtomicU64; MAX_NUMA_NODES] = [const { AtomicU64::new(0) }; MAX_NUMA_NODES];
static TIER: [AtomicU8; MAX_NUMA_NODES] = [const { AtomicU8::new(UNKNOWN_TIER) }; MAX_NUMA_NODES];
static CONFIG_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// Publish one node's local HMAT performance coordinates and rebuild tiers.
///
/// At least one coordinate must be non-zero. Bandwidth sorts descending;
/// latency breaks bandwidth ties ascending. Equal coordinates share a tier.
pub fn set_node_performance(node: usize, bandwidth: u64, latency: u64) -> Result<(), ()> {
    if node >= MAX_NUMA_NODES || (bandwidth == 0 && latency == 0) {
        return Err(());
    }
    let _guard = CONFIG_LOCK.lock();
    BANDWIDTH[node].store(bandwidth, Ordering::Release);
    LATENCY[node].store(latency, Ordering::Release);
    rebuild_locked();
    Ok(())
}

fn faster(a_bw: u64, a_lat: u64, b_bw: u64, b_lat: u64) -> bool {
    if a_bw != b_bw {
        // A missing bandwidth coordinate sorts after a real coordinate.
        return a_bw != 0 && (b_bw == 0 || a_bw > b_bw);
    }
    a_lat != 0 && (b_lat == 0 || a_lat < b_lat)
}

fn rebuild_locked() {
    let mut nodes = [0usize; MAX_NUMA_NODES];
    let mut count = 0usize;
    for node in 0..MAX_NUMA_NODES {
        if BANDWIDTH[node].load(Ordering::Acquire) != 0
            || LATENCY[node].load(Ordering::Acquire) != 0
        {
            nodes[count] = node;
            count += 1;
        } else {
            TIER[node].store(UNKNOWN_TIER, Ordering::Release);
        }
    }
    for i in 1..count {
        let mut j = i;
        while j > 0 {
            let a = nodes[j];
            let b = nodes[j - 1];
            if faster(
                BANDWIDTH[a].load(Ordering::Acquire),
                LATENCY[a].load(Ordering::Acquire),
                BANDWIDTH[b].load(Ordering::Acquire),
                LATENCY[b].load(Ordering::Acquire),
            ) {
                nodes.swap(j, j - 1);
                j -= 1;
            } else {
                break;
            }
        }
    }

    let mut tier = 0u8;
    for i in 0..count {
        if i > 0 {
            let prev = nodes[i - 1];
            let cur = nodes[i];
            if BANDWIDTH[prev].load(Ordering::Acquire) != BANDWIDTH[cur].load(Ordering::Acquire)
                || LATENCY[prev].load(Ordering::Acquire) != LATENCY[cur].load(Ordering::Acquire)
            {
                tier = tier.saturating_add(1);
            }
        }
        TIER[nodes[i]].store(tier, Ordering::Release);
    }
}

/// Linux-style abstract memory tier for a node. Unknown nodes are tier zero.
pub fn node_tier(node: usize) -> Option<u8> {
    let raw = TIER.get(node)?.load(Ordering::Acquire);
    Some(if raw == UNKNOWN_TIER { 0 } else { raw })
}

/// Mask of online nodes assigned to `tier`.
pub fn tier_nodes(tier: u8) -> u64 {
    let online = crate::frame::online_node_mask();
    let mut mask = 0u64;
    for node in 0..MAX_NUMA_NODES {
        if online & (1u64 << node) != 0 && node_tier(node) == Some(tier) {
            mask |= 1u64 << node;
        }
    }
    mask
}

/// Pick the closest allowed node in the nearest strictly slower tier.
pub fn demotion_target(source: usize, allowed: u64) -> Option<usize> {
    let source_tier = node_tier(source)?;
    let candidates = allowed & crate::frame::online_node_mask() & !(1u64 << source);
    let mut best: Option<(u8, u32, usize)> = None;
    for node in 0..MAX_NUMA_NODES {
        if candidates & (1u64 << node) == 0 {
            continue;
        }
        let tier = node_tier(node)?;
        if tier <= source_tier {
            continue;
        }
        let key = (tier, node_distance(source, node), node);
        if best.is_none_or(|current| key < current) {
            best = Some(key);
        }
    }
    best.map(|(_, _, node)| node)
}

fn smoke_memory_tier_demotion_target() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if crate::frame::online_node_mask() & 0b11 != 0b11 {
        return TestResult::Skip("requires two online NUMA nodes");
    }
    let old = [
        (
            BANDWIDTH[0].load(Ordering::Acquire),
            LATENCY[0].load(Ordering::Acquire),
        ),
        (
            BANDWIDTH[1].load(Ordering::Acquire),
            LATENCY[1].load(Ordering::Acquire),
        ),
    ];
    let failed = set_node_performance(0, 100, 10).is_err()
        || set_node_performance(1, 50, 20).is_err()
        || node_tier(0) != Some(0)
        || node_tier(1) != Some(1)
        || demotion_target(0, 0b11) != Some(1)
        || demotion_target(1, 0b11).is_some()
        || demotion_target(0, 0b01).is_some();

    let _guard = CONFIG_LOCK.lock();
    for node in 0..2 {
        BANDWIDTH[node].store(old[node].0, Ordering::Release);
        LATENCY[node].store(old[node].1, Ordering::Release);
    }
    rebuild_locked();
    if failed {
        TestResult::Fail("tier rank or allowed-mask demotion selection failed")
    } else {
        TestResult::Pass
    }
}

narf_kernel_test::kernel_test_in!("memory/numa", smoke_memory_tier_demotion_target);
