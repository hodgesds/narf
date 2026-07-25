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
            pair.sq_phys.raw() as *mut SqRing
        )
    };
    // SAFETY: `pair.cq_phys` is the CQ frame this task owns in BOOTSTRAP_TABLE,
    // initialized as a CqRing by `mint_shared_ring_pair`; identity-mapped and
    // accessed only from this synchronous trap, so the producer has exclusive use.
    // SAFETY: Valid memory or trusted environment
    let mut cq = unsafe {
        SharedProducer::<Completion, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.cq_phys.raw() as *mut CqRing
        )
    };

    let mut processed: u64 = 0;
    while let Ok(sub) = sq.try_recv() {
        let tag = sub.tag();
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
            _ => Completion::with(tag, NarfStatus::InvalidOp, [0; 6]),
        };
        let _ = cq.try_send(completion);
        processed = processed.saturating_add(1);
    }

    ctx.set_return(SyscallReturn::ok(processed));
}
