#[allow(unused_imports)]
use super::*;

/// `kernel/exec_domain.c::SYSCALL_DEFINE1(personality, unsigned int,
/// personality)`.
///
/// ```text
/// unsigned int old = current->personality;
///
/// if (personality != 0xffffffff)
///         set_personality(personality);
///
/// return old;
/// ```
///
/// Three things in four lines, and this handler had none of them: it returned
/// a constant 0 and kept no state.
///
///   * The return value is the PREVIOUS personality. `0xffffffff` is not a
///     persona but the query spelling — every caller that reads its own
///     personality (glibc's `personality(0xffffffff)`, `setarch` before it
///     modifies anything) goes through it.
///   * The word is remembered, so a later query reads back what was set.
///   * The flags in it mean something. `ADDR_NO_RANDOMIZE` is honoured by
///     [`randomize_user_layout`] at the three places NARF randomises a user
///     layout (program base, interpreter base, stack top), and
///     `READ_IMPLIES_EXEC` by `mmap`/`mprotect`. Before this, `setarch -R
///     prog` reported success and `prog` was randomised exactly as before —
///     the worst shape for a debugging aid, because the caller cannot tell.
///
/// LINUX-GAP: the execution DOMAIN half (the low byte: `PER_SVR4`,
/// `PER_BSD`, `PER_LINUX32`, …) is remembered and reported but changes
/// nothing. Linux's own domains are nearly vestigial — the surviving
/// behaviour is `PER_LINUX32`'s 32-bit address-space limit and
/// `ADDR_LIMIT_3GB`/`ADDR_LIMIT_32BIT`, which need a 32-bit user ABI NARF
/// does not have. A caller asking for one gets it stored, not emulated, as
/// it would on a Linux built without the (also vestigial) `PER_*` handlers.
pub(crate) fn sys_personality(ctx: &mut dyn TrapContext) {
    // `unsigned int` — only the low 32 bits are the request, and the compare
    // against 0xffffffff is done in that width.
    let requested = ctx.args().arg0 as u32;
    let task = current_task_id();
    let old = read_personality(task);
    if requested != 0xffff_ffff {
        write_personality(task, requested);
    }
    ctx.set_return(SyscallReturn::ok(u64::from(old)));
}
