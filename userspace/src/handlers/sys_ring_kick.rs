#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_ring_kick(ctx: &mut dyn TrapContext) {
    if crate::user_task::with_current_task_owner(|owner| {
        // SAFETY: only the current owner can replace its session, and no
        // Bootstrap/exec operation is supported recursively within RingKick.
        match unsafe { owner.native_session.get() } {
            Some(session) => ring_kick_session(ctx, session),
            None => ctx.set_return(SyscallReturn::invalid_op()),
        }
    })
    .is_some()
    {
        return;
    }
    #[cfg(feature = "kernel-test")]
    {
        // Explicit synthetic fixture fallback; never compiled into user boots.
        let session = BOOTSTRAP_TABLE
            .lock()
            .as_ref()
            .and_then(|m| m.get(&current_task_id()))
            .map(|e| e.session.clone());
        if let Some(session) = session {
            ring_kick_session(ctx, &session);
            return;
        }
    }
    ctx.set_return(SyscallReturn::invalid_op());
}

fn ring_kick_session(ctx: &mut dyn TrapContext, session: &NativeSession) {
    use narf_abi::{FileOpArgs, FileOpKind, NarfStatus, OpCode, SharedConsumer, SharedProducer};
    type SqRing = SharedRing<Submission, BOOTSTRAP_SHARED_RING_DEPTH>;
    type CqRing = SharedRing<Completion, BOOTSTRAP_SHARED_RING_DEPTH>;
    let pair = session.shared;
    let subject = session.context();
    // SAFETY: the retained session owns the phys backings; only
    // one ring-kick can run at a time per task because it executes
    // synchronously inside this task's syscall trap.
    // SAFETY: Valid memory or trusted environment
    let mut sq = unsafe {
        SharedConsumer::<Submission, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.sq_phys.kernel_mut_ptr::<SqRing>(),
        )
    };
    // SAFETY: `pair.cq_phys` is the CQ frame this session owns,
    // initialized as a CqRing by `mint_shared_ring_pair`; identity-mapped and
    // accessed only from this synchronous trap, so the producer has exclusive use.
    // SAFETY: Valid memory or trusted environment
    let mut cq = unsafe {
        SharedProducer::<Completion, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.cq_phys.kernel_mut_ptr::<CqRing>(),
        )
    };

    let mut processed: u64 = 0;
    while let Ok(sub) = sq.try_recv() {
        let tag = sub.tag();
        let admission = if session.closed.load(Ordering::Acquire) {
            Err(NarfStatus::CapRevoked)
        } else {
            subject.validate(&sub)
        };
        if let Err(status) = admission {
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
                let r = abi_file_op_bridge(
                    Some(subject),
                    kind,
                    &args,
                    &narf_abi::CancelCtx::detached(),
                );
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
                let result = narf_scheduler::task_authority(target)
                    .ok_or(narf_capabilities::CapError::Revoked)
                    .and_then(|target| {
                        session
                            .authority
                            .transfer_to(&target, sub.caps[0], sub.caps[1])
                    });
                match result {
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
