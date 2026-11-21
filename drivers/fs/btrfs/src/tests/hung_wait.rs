//! The transaction gate's waits are uninterruptible kernel waits (Linux
//! `wait_current_trans` and `btrfs_commit_transaction` sleep in
//! TASK_UNINTERRUPTIBLE): each records itself for the hung-task detector
//! from its first `Pending` until it is admitted or dropped.

use super::*;
use crate::txn_gate::{TxnGate, CLOSE_WAIT, JOIN_WAIT};

/// The recorded waits on `gate`: `(kind name, detail, call-site line)`.
fn waits_on(gate: &TxnGate) -> Vec<(&'static str, u64, u32)> {
    let mut out = Vec::new();
    narf_lib::hung_task::for_each_blocked(|w| {
        if w.object == core::ptr::from_ref(gate) as usize {
            out.push((w.kind.name, w.detail, w.site.map_or(0, |s| s.line())));
        }
    });
    out.sort_unstable();
    out
}

fn check() -> Result<(), &'static str> {
    let gate = TxnGate::new();
    let running = poll_once(gate.join()).ok_or("an open gate refused a join")?;
    if !waits_on(&gate).is_empty() {
        return Err("an admitted join was recorded as blocked");
    }
    let close_line = line!() + 1;
    let mut close = gate.close();
    if poll_once(&mut close).is_some() {
        return Err("a close went ahead of a joined operation");
    }
    let join_line = line!() + 1;
    let mut join = gate.join();
    if poll_once(&mut join).is_some() {
        return Err("a join went ahead of a waiting close");
    }
    let want = [
        (CLOSE_WAIT.name, 1, close_line),
        (JOIN_WAIT.name, 0, join_line),
    ];
    let mut want = want.to_vec();
    want.sort_unstable();
    if waits_on(&gate) != want {
        return Err("the waiting close and join were not recorded with their call sites");
    }
    // A cancelled join leaves the record; the close, admitted, leaves too.
    drop(join);
    drop(running);
    let closed = poll_once(&mut close).ok_or("the close was not admitted")?;
    if !waits_on(&gate).is_empty() {
        return Err("an ended wait stayed recorded");
    }
    drop(closed);
    Ok(())
}

/// Transaction-gate waits are visible to the hung-task detector.
fn smoke_btrfs_txn_gate_waits_recorded_for_hung_task() -> TestResult {
    match check() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

kernel_test_in!(
    "drivers/fs/btrfs/hung_task",
    smoke_btrfs_txn_gate_waits_recorded_for_hung_task
);
