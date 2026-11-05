#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_ring_kick(ctx: &mut dyn TrapContext) {
    use narf_abi::{FileOpArgs, FileOpKind, NarfStatus, OpCode, SharedConsumer, SharedProducer};

    type SqRing = SharedRing<Submission, BOOTSTRAP_SHARED_RING_DEPTH>;
    type CqRing = SharedRing<Completion, BOOTSTRAP_SHARED_RING_DEPTH>;

    let task = current_task_id();
    let pair = match shared_rings_for(task) {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    // SAFETY: per-task BOOTSTRAP_TABLE owns the phys backings; only
    // one ring-kick can run at a time per task because it executes
    // synchronously inside this task's syscall trap.
    // SAFETY: Valid memory or trusted environment
    let mut sq = unsafe {
        SharedConsumer::<Submission, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.sq_phys.kernel_mut_ptr::<SqRing>()
        )
    };
    // SAFETY: `pair.cq_phys` is the CQ frame this task owns in BOOTSTRAP_TABLE,
    // initialized as a CqRing by `mint_shared_ring_pair`; identity-mapped and
    // accessed only from this synchronous trap, so the producer has exclusive use.
    // SAFETY: Valid memory or trusted environment
    let mut cq = unsafe {
        SharedProducer::<Completion, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.cq_phys.kernel_mut_ptr::<CqRing>()
        )
    };

    let mut processed: u64 = 0;
    while let Ok(sub) = sq.try_recv() {
        let tag = sub.tag();
        // Cap gate (#1363 wiring): the same check
        // `Dispatcher::dispatch_one` runs — every presented cap
        // resolves against the submitting task's own table
        // (capabilities/ §8 steps 1–4). A failure completes with
        // the cap status and the op never runs. This trap runs in
        // the submitter's own context, so the owner is the current
        // task id.
        if let Err(status) =
            narf_abi::validate_submission_caps(Some(narf_scheduler::TaskId(task)), &sub.caps)
        {
            let _ = cq.try_send(Completion::with(tag, status, [0; 6]));
            processed = processed.saturating_add(1);
            continue;
        }
        let completion = match sub.op {
            OpCode::Noop => Completion::ok(tag),
            OpCode::OpenFile
            | OpCode::Read
            | OpCode::Write
            | OpCode::Close
            | OpCode::Mmap
            | OpCode::Munmap => {
                let kind = match sub.op {
                    OpCode::OpenFile => FileOpKind::Open,
                    OpCode::Read => FileOpKind::Read,
                    OpCode::Write => FileOpKind::Write,
                    OpCode::Close => FileOpKind::Close,
                    OpCode::Mmap => FileOpKind::Mmap,
                    OpCode::Munmap => FileOpKind::Munmap,
                    _ => unreachable!(),
                };
                let args = FileOpArgs {
                    a0: sub.inline[0],
                    a1: sub.inline[1],
                    a2: sub.inline[2],
                    a3: sub.inline[3],
                    a4: sub.inline[4],
                    a5: sub.inline[5],
                };
                let r = abi_file_op_bridge(kind, &args, &narf_abi::CancelCtx::detached());
                let status = if r.status == 0 {
                    NarfStatus::Ok
                } else {
                    NarfStatus::InvalidOp
                };
                let mut result = [0u64; 6];
                result[0] = r.value;
                Completion::with(tag, status, result)
            }
            OpCode::CapTransfer => {
                // §9.1 Grant-gated transfer via the ABI; same
                // semantics as the `Dispatcher` arm. `caps[0]` is
                // the sender's Grant cap, `caps[1]` the cap to
                // transfer, `inline[0]` the target task id;
                // `result[0]` is the receiver's fresh slot number.
                let target = narf_scheduler::TaskId(sub.inline[0]);
                match narf_scheduler::transfer_task_cap(
                    narf_scheduler::TaskId(task),
                    target,
                    sub.caps[0],
                    sub.caps[1],
                ) {
                    Ok(slot) => {
                        let mut result = [0u64; 6];
                        result[0] = u64::from(slot);
                        Completion::with(tag, NarfStatus::Ok, result)
                    }
                    Err(e) => Completion::with(tag, narf_abi::cap_error_status(e), [0; 6]),
                }
            }
            _ => Completion::with(tag, NarfStatus::InvalidOp, [0; 6]),
        };
        let _ = cq.try_send(completion);
        processed = processed.saturating_add(1);
    }

    ctx.set_return(SyscallReturn::ok(processed));
}
