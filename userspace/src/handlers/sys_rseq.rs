#[allow(unused_imports)]
use super::*;

/// `rseq(rseq, len, flags, sig)` — register/unregister a restartable-
/// sequence area.
///
/// NARF does NOT implement rseq semantics: it never writes the `cpu_id`/
/// `cpu_id_start` fields on return-to-user, and never restarts (aborts to
/// `rseq_cs.abort_ip`) a critical section when the task is preempted or
/// MIGRATED to another CPU. The old handler faked success on the rationale
/// that NARF was "a cooperative single-CPU kernel with no preemption
/// mid-sequence" — that is no longer true (NARF is now preemptive SMP).
///
/// Faking success is actively unsafe under SMP: glibc >= 2.35 registers rseq
/// at thread start and, on success, publishes `__rseq_size != 0` and trusts
/// the ABI area — so any rseq user (glibc's `sched_getcpu()` fast path, and
/// rseq-based per-CPU allocators) reads a `cpu_id` that never advances and runs
/// critical sections un-restarted across a real CPU migration, silently
/// corrupting per-CPU state. That corruption is SMP-only and matches the KDE
/// greeter's heap `abort()`.
///
/// Return `-ENOSYS`, exactly as a kernel that does not implement rseq: glibc
/// then leaves rseq unregistered (`__rseq_size == 0`) and falls back to the
/// `getcpu(2)` path, which is correct on every CPU count.
pub(crate) fn sys_rseq(ctx: &mut dyn TrapContext) {
    // -ENOSYS (38): NARF provides no rseq restart/cpu_id semantics.
    ctx.set_return(SyscallReturn::ok((-38i64) as u64));
}
