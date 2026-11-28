//! Registry I/O accounting used by Linux diskstats and sysfs.
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::sync::{IrqSafeSpinLock, OnceLock};

use crate::{BlockOp, BoxedCompletion};

/// Completed storage traffic submitted in a user process's context.
#[derive(Debug, Default)]
pub struct ProcessStorageIo {
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
    /// Dirty page-cache bytes this process caused to never reach disk, by
    /// truncating or evicting them before writeback (Linux
    /// `cancelled_write_bytes`). Charged to the process doing the
    /// truncation, per folio, at the page granularity Linux uses — the
    /// page cache records dirtiness, not the dirtier.
    cancelled_write_bytes: AtomicU64,
}

impl ProcessStorageIo {
    /// Completed read and write bytes respectively.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.read_bytes.load(Ordering::Relaxed),
            self.write_bytes.load(Ordering::Relaxed),
        )
    }

    /// Bytes cancelled before writeback (see the field doc).
    pub fn cancelled_write_bytes(&self) -> u64 {
        self.cancelled_write_bytes.load(Ordering::Relaxed)
    }

    /// Add `bytes` to the cancelled counter. Saturates like the
    /// task-layer character counters rather than wrapping.
    pub fn add_cancelled_write_bytes(&self, bytes: u64) {
        let _ = self.cancelled_write_bytes.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(bytes)),
        );
    }
}

type Submitter = fn() -> Option<Arc<ProcessStorageIo>>;
static SUBMITTER: OnceLock<Submitter> = OnceLock::new();

/// Install the task layer's lookup for the submitting process. Kernel
/// workers without a user owner contribute only to device statistics.
pub fn install_submitter(lookup: fn() -> Option<Arc<ProcessStorageIo>>) {
    let _ = SUBMITTER.set(lookup);
}

/// The storage accumulator of the process submitting on this task, if
/// the task layer installed its lookup and this task has an owner.
/// Filesystem code that drops dirty pages before writeback (page-cache
/// truncation) charges the cancellation here, without going through the
/// task table.
pub fn current_submitter() -> Option<Arc<ProcessStorageIo>> {
    SUBMITTER.get().and_then(|lookup| lookup())
}

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Read,
    Write,
    Discard,
    Flush,
}

impl From<BlockOp> for Operation {
    fn from(op: BlockOp) -> Self {
        match op {
            BlockOp::Read => Self::Read,
            BlockOp::Write { .. } | BlockOp::WriteZeroes => Self::Write,
            BlockOp::Trim => Self::Discard,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    completed: u64,
    bytes: u64,
    ns: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct State {
    ops: [Counts; 4],
    in_flight: u64,
    last_ns: u64,
    busy_ns: u64,
    weighted_ns: u64,
}

impl State {
    fn advance(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last_ns);
        self.last_ns = now.max(self.last_ns);
        if self.in_flight != 0 {
            self.busy_ns = self.busy_ns.wrapping_add(elapsed);
            self.weighted_ns = self
                .weighted_ns
                .wrapping_add(elapsed.wrapping_mul(self.in_flight));
        }
    }
}

/// Cumulative counters for one registration, reset when the device is replaced.
#[derive(Debug)]
pub struct DiskStats(IrqSafeSpinLock<State>);

impl DiskStats {
    pub(crate) fn new() -> Self {
        Self(IrqSafeSpinLock::new(State::default()))
    }

    /// The 17 Linux block stat fields in ABI order. Sectors are always 512 bytes.
    pub fn linux_fields(&self) -> [u64; 17] {
        let s = {
            let mut state = self.0.lock();
            state.advance(narf_time::monotonic_ns());
            *state
        };
        let [r, w, d, f] = s.ops;
        let ms = |ns: u64| ns / 1_000_000;
        [
            r.completed,
            0,
            r.bytes / 512,
            ms(r.ns),
            w.completed,
            0,
            w.bytes / 512,
            ms(w.ns),
            s.in_flight,
            ms(s.busy_ns),
            ms(s.weighted_ns),
            d.completed,
            0,
            d.bytes / 512,
            ms(d.ns),
            f.completed,
            ms(f.ns),
        ]
    }
}

#[derive(Clone)]
pub(crate) struct Accounting {
    pub(crate) local: Arc<DiskStats>,
    charge_submitter: bool,
    // A scanned partition normally translates directly to the raw disk,
    // bypassing the whole-disk guard. Mirror these transfers to that disk.
    pub(crate) raw_parent: Option<Arc<DiskStats>>,
}

impl Accounting {
    pub(crate) fn new(charge_submitter: bool) -> Self {
        Self {
            local: Arc::new(DiskStats::new()),
            raw_parent: None,
            charge_submitter,
        }
    }

    fn each(&self, mut f: impl FnMut(&mut State)) {
        f(&mut self.local.0.lock());
        if let Some(parent) = &self.raw_parent {
            f(&mut parent.0.lock());
        }
    }

    pub(crate) fn start(&self, op: Operation, bytes: u64) -> Transfer {
        let start_ns = narf_time::monotonic_ns();
        self.each(|s| {
            s.advance(start_ns);
            s.in_flight += 1;
        });
        // Capture the owner on submission. Its small counter object can
        // outlive the task while another CPU polls the completion.
        let owner = if self.charge_submitter && matches!(op, Operation::Read | Operation::Write) {
            SUBMITTER.get().and_then(|lookup| lookup())
        } else {
            None
        };
        Transfer {
            owner,
            accounting: self.clone(),
            op,
            bytes,
            start_ns,
            succeeded: false,
        }
    }
}

pub(crate) struct Transfer {
    owner: Option<Arc<ProcessStorageIo>>,
    accounting: Accounting,
    op: Operation,
    bytes: u64,
    start_ns: u64,
    succeeded: bool,
}

impl Transfer {
    pub(crate) fn finish<T, E>(mut self, result: Result<T, E>) -> Result<T, E> {
        self.succeeded = result.is_ok();
        result
    }

    pub(crate) fn completion(mut self, future: BoxedCompletion) -> BoxedCompletion {
        Box::pin(async move {
            let completion = future.await;
            self.succeeded = completion.result.is_ok();
            drop(self);
            completion
        })
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.as_ref().filter(|_| self.succeeded) {
            let bytes = self.bytes;
            match self.op {
                Operation::Read => {
                    owner.read_bytes.fetch_add(bytes, Ordering::Relaxed);
                }
                Operation::Write => {
                    owner.write_bytes.fetch_add(bytes, Ordering::Relaxed);
                }
                Operation::Flush | Operation::Discard => {}
            }
        }
        let end = narf_time::monotonic_ns();
        self.accounting.each(|s| {
            s.advance(end);
            s.in_flight -= 1;
            let op = &mut s.ops[self.op as usize];
            op.ns = op.ns.wrapping_add(end.saturating_sub(self.start_ns));
            if self.succeeded {
                op.completed = op.completed.wrapping_add(1);
                op.bytes = op.bytes.wrapping_add(self.bytes);
            }
        });
    }
}

fn smoke_overlapping_and_dropped_transfers() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let accounting = Accounting::new(true);
    let a = accounting.start(Operation::Read, 16 * 512);
    let b = accounting.start(Operation::Write, 8 * 512);
    if accounting.local.linux_fields()[8] != 2 {
        return TestResult::Fail("two outstanding transfers");
    }
    drop(b.completion(crate::queue::ready_completion(1, Ok(()))));
    let completion =
        narf_scheduler::block_on_spin(a.completion(crate::queue::ready_completion(2, Ok(()))));
    let fields = accounting.local.linux_fields();
    if completion.user_tag != 2
        || fields[0] != 1
        || fields[2] != 16
        || fields[4] != 0
        || fields[6] != 0
        || fields[8] != 0
    {
        return TestResult::Fail("an unobserved completion cannot report a successful transfer");
    }
    let mut state = State {
        in_flight: 2,
        last_ns: 50,
        ..State::default()
    };
    state.advance(70);
    state.in_flight -= 1;
    state.advance(100);
    if state.busy_ns != 50 || state.weighted_ns != 70 {
        return TestResult::Fail(
            "account overlapping busy intervals once and weight by queue depth",
        );
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("block/stats", smoke_overlapping_and_dropped_transfers);
