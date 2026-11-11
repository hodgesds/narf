//! Bounded two-choice donor sampling; all search decisions stay in policy.

use super::*;

const FULL_SCAN_AFTER_MISSES: u8 = 4;
const MAX_BACKOFF_NS: u64 = 1_000_000;

#[repr(align(64))]
struct SearchState {
    online: u64,
    generation: u64,
    tiers: [u64; 3],
    random: u64,
    retry_at: u64,
    delay: u64,
    misses: u8,
    cursor: u32,
}

impl SearchState {
    fn new(cpu: usize) -> Self {
        Self {
            online: 0,
            generation: u64::MAX,
            tiers: [0; 3],
            random: (cpu as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15),
            retry_at: 0,
            delay: 0,
            misses: 0,
            cursor: cpu as u32,
        }
    }

    fn refresh(&mut self, thief: CpuId, context: &StealContext<'_>) {
        self.online = context.online_mask & !(1u64 << thief.0);
        self.generation = context.topology_generation;
        let llc = context.llc_id(thief);
        let node = context.numa_node(thief);
        let mut local = 0;
        let mut numa = 0;
        // Cold: only CPU online/topology publication invalidates these sets.
        // Runnable/idle changes do not rebuild them or add enqueue writes.
        for cpu in cpus_in(self.online) {
            let bit = 1u64 << cpu.0;
            if llc.is_some() && context.llc_id(cpu) == llc {
                local |= bit;
            } else if node.is_some() && context.numa_node(cpu) == node {
                numa |= bit;
            }
        }
        self.tiers = [local, numa, self.online & !local & !numa];
        self.retry_at = 0;
        self.delay = 0;
        self.misses = 0;
    }

    fn plan(&mut self, thief: CpuId, context: &StealContext<'_>) -> Option<SearchPlan> {
        if self.online != context.online_mask & !(1u64 << thief.0)
            || self.generation != context.topology_generation
        {
            self.refresh(thief, context);
        }
        if self.online == 0 || context.now_cycles() < self.retry_at {
            return None;
        }
        let mut pairs = [[None; 2]; 3];
        for (pair, mut mask) in pairs.iter_mut().zip(self.tiers) {
            for slot in pair {
                if mask == 0 {
                    break;
                }
                // Private per-CPU xorshift64* state: no shared RNG counter.
                self.random ^= self.random >> 12;
                self.random ^= self.random << 25;
                self.random ^= self.random >> 27;
                let rank =
                    self.random.wrapping_mul(0x2545_f491_4f6c_dd1d) % u64::from(mask.count_ones());
                let cpu = CpuId(select_bit(mask, rank as u32));
                *slot = Some(cpu);
                mask &= !(1u64 << cpu.0);
            }
        }
        Some(SearchPlan {
            pairs,
            online: self.online,
            full: self.misses >= FULL_SCAN_AFTER_MISSES - 1,
            cursor: self.cursor,
        })
    }

    fn finish(&mut self, now: u64, moved: bool, saw_work: bool, full: bool) {
        if moved {
            self.misses = 0;
        } else if full {
            self.misses = 0;
            self.cursor = (self.cursor + 1) % MAX_CPUS as u32;
        } else {
            self.misses = self.misses.saturating_add(1);
        }
        if moved || saw_work {
            self.delay = 0;
            self.retry_at = 0;
        } else {
            // Search-only backoff: direct local/IPI wake dispatch never waits
            // on it. Start at 1 us and double to a 1 ms ceiling; experimental
            // defaults, not a hardware-specific latency guarantee.
            self.delay = if self.delay == 0 {
                narf_time::ns_to_cycles(1_000).max(1)
            } else {
                self.delay.saturating_mul(2)
            }
            .min(narf_time::ns_to_cycles(MAX_BACKOFF_NS).max(1));
            self.retry_at = now.saturating_add(self.delay);
        }
    }
}

/// Select the rank-th set bit in six bounded steps, without enumerating CPUs.
fn select_bit(mut mask: u64, mut rank: u32) -> u32 {
    debug_assert!(rank < mask.count_ones());
    let mut offset = 0;
    for width in [32, 16, 8, 4, 2, 1] {
        let lower = mask & ((1u64 << width) - 1);
        let count = lower.count_ones();
        if rank < count {
            mask = lower;
        } else {
            rank -= count;
            mask >>= width;
            offset += width;
        }
    }
    offset
}

struct SearchPlan {
    pairs: [[Option<CpuId>; 2]; 3],
    online: u64,
    full: bool,
    cursor: u32,
}

/// Sample two donors per locality tier; try the more heavily queued first.
/// Periodic full coverage and bounded backoff keep sparse work discoverable.
pub struct Pick2Steal {
    state: Box<[IrqSafeSpinLock<SearchState>]>,
}

impl core::fmt::Debug for Pick2Steal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pick2Steal").finish_non_exhaustive()
    }
}

impl Default for Pick2Steal {
    fn default() -> Self {
        Self::new()
    }
}

impl Pick2Steal {
    pub fn new() -> Self {
        Self {
            state: (0..MAX_CPUS)
                .map(|cpu| IrqSafeSpinLock::new(SearchState::new(cpu)))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }
}

impl StealStrategy for Pick2Steal {
    fn name(&self) -> &'static str {
        "pick2"
    }

    fn order_victims(&self, thief: CpuId, online: &[CpuId]) -> Vec<CpuId> {
        // Legacy callers have no load/topology snapshot; retain full coverage.
        NumaAwareSteal.order_victims(thief, online)
    }

    fn visit_victims(
        &self,
        thief: CpuId,
        context: &StealContext<'_>,
        visit: &mut dyn FnMut(CpuId) -> bool,
    ) {
        let Some(state) = self.state.get(thief.0 as usize) else {
            return;
        };
        let plan = {
            let Some(mut state) = state.try_lock() else {
                return;
            };
            state.plan(thief, context)
        };
        let Some(plan) = plan else { return };
        // No policy-state lock spans a queue sample or core migration visitor.
        let mut moved = false;
        let mut saw_work = false;
        let mut attempted = 0;
        'tiers: for pair in plan.pairs {
            let load = |cpu: Option<CpuId>| {
                let cpu = cpu?;
                if context.is_idle(cpu) || !context.may_have_runnable_peer(cpu) {
                    return None;
                }
                context
                    .queued_load(cpu)
                    .filter(|&n| n > 0)
                    .map(|n| (cpu, n))
            };
            let mut choices = [load(pair[0]), load(pair[1])];
            if choices[1].map(|(_, n)| n).unwrap_or(0) > choices[0].map(|(_, n)| n).unwrap_or(0) {
                choices.swap(0, 1);
            }
            for (cpu, _) in choices.into_iter().flatten() {
                saw_work = true;
                attempted |= 1u64 << cpu.0;
                if visit(cpu) {
                    moved = true;
                    break 'tiers;
                }
            }
        }
        if !moved && plan.full {
            // Ignore advisory load/idle hints during full coverage: stale
            // false negatives must not hide work indefinitely. Rotate across
            // every online peer, including remote NUMA/cache domains.
            for offset in 1..=MAX_CPUS as u32 {
                let cpu = CpuId((plan.cursor + offset) % MAX_CPUS as u32);
                let bit = 1u64 << cpu.0;
                if plan.online & !attempted & bit != 0 && visit(cpu) {
                    moved = true;
                    break;
                }
            }
        }
        if let Some(mut state) = state.try_lock() {
            state.finish(context.now_cycles(), moved, saw_work, plan.full);
        }
    }
}

mod tests {
    use super::*;
    use core::cell::Cell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn pick2_sparse_masks_select_distinct_peers() -> TestResult {
        for mask in [1, 1u64 << 63, 0x8000_0000_0000_0081, u64::MAX, 0xaaaa_5555] {
            let expected: Vec<_> = cpus_in(mask).map(|cpu| cpu.0).collect();
            for (rank, &cpu) in expected.iter().enumerate() {
                if select_bit(mask, rank as u32) != cpu {
                    return TestResult::Fail("bit selection skipped or repeated a CPU");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("scheduler/steal", pick2_sparse_masks_select_distinct_peers);

    fn pick2_prefers_load_and_releases_policy_lock() -> TestResult {
        let policy = Pick2Steal::new();
        let context = StealContext::new(
            0b110,
            &|_| false,
            &|_| true,
            &|_| Some(0),
            &|_| None,
            &|cpu| Some(cpu.0 as usize),
            &|| 0,
        );
        let mut visited = Vec::new();
        let mut unlocked = true;
        policy.visit_victims(CpuId(0), &context, &mut |cpu| {
            unlocked &= policy.state[0].try_lock().is_some();
            visited.push(cpu);
            cpu == CpuId(1) // the heavier donor can refuse on affinity/budget
        });
        if unlocked && visited == [CpuId(2), CpuId(1)] {
            TestResult::Pass
        } else {
            TestResult::Fail("load ordering, fallback, or lock lifetime failed")
        }
    }
    kernel_test_in!(
        "scheduler/steal",
        pick2_prefers_load_and_releases_policy_lock
    );

    fn pick2_sparse_work_survives_stale_hints_and_topology_changes() -> TestResult {
        let policy = Pick2Steal::new();
        let now = Cell::new(0);
        let clock = || now.get();
        let mut context = StealContext::new(
            0b1110,
            &|_| true,
            &|_| false,
            &|_| None,
            &|_| None,
            &|_| None,
            &clock,
        );
        let mut found = false;
        for _ in 0..FULL_SCAN_AFTER_MISSES {
            now.set(now.get() + narf_time::ns_to_cycles(MAX_BACKOFF_NS * 2).max(2));
            policy.visit_victims(CpuId(0), &context, &mut |cpu| {
                found |= cpu == CpuId(3);
                found
            });
        }
        if !found {
            return TestResult::Fail("stale hints hid sparse work from full coverage");
        }
        context.online_mask = 1 << 5;
        context.topology_generation = context.topology_generation.wrapping_add(1);
        found = false;
        for _ in 0..FULL_SCAN_AFTER_MISSES {
            now.set(now.get() + narf_time::ns_to_cycles(MAX_BACKOFF_NS * 2).max(2));
            policy.visit_victims(CpuId(0), &context, &mut |cpu| {
                found |= cpu == CpuId(5);
                found
            });
        }
        if found {
            TestResult::Pass
        } else {
            TestResult::Fail("online-set cache remained stale")
        }
    }
    kernel_test_in!(
        "scheduler/steal",
        pick2_sparse_work_survives_stale_hints_and_topology_changes
    );

    fn pick2_backoff_is_bounded_and_success_resets_it() -> TestResult {
        let mut state = SearchState::new(0);
        for _ in 0..64 {
            state.finish(10, false, false, false);
        }
        let bounded = state.delay == narf_time::ns_to_cycles(MAX_BACKOFF_NS).max(1);
        state.finish(20, true, false, false);
        if bounded && state.retry_at == 0 && state.misses == 0 {
            TestResult::Pass
        } else {
            TestResult::Fail("backoff bound or success reset failed")
        }
    }
    kernel_test_in!(
        "scheduler/steal",
        pick2_backoff_is_bounded_and_success_resets_it
    );
}
