//! Kernel-stack overflow report — Linux `handle_stack_overflow`
//! (`arch/x86/kernel/traps.c`) / arm64 `handle_bad_stack`.
//!
//! Spec: `frame/specification/spec.md` §3 (trap entry) and §4 (overflow
//! invariant).
//!
//! Both arches reach [`report`] only from a context that is NOT the
//! overflowed stack: x86_64 from #DF on its IST stack, or from #PF after
//! switching onto that IST stack; aarch64 from the exception entry after it
//! switched to the per-CPU overflow stack. Nothing here reads the guard VA,
//! takes a lock or allocates. The report names the task, the stack bounds,
//! the guard address, the faulting pc/sp, and a backtrace recovered from the
//! overflowed stack itself (frame-pointer chain, then the deepest return
//! addresses, which sit just above the stack base).

use core::fmt::Write;

use narf_console::TrapWriter;
use narf_memory::kstack::GuardHit;

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
}

fn text_range() -> (u64, u64) {
    // Linker-provided symbols; only their addresses are taken.
    (
        core::ptr::addr_of!(__text_start) as u64,
        core::ptr::addr_of!(__text_end) as u64,
    )
}

/// Executor stack size for an AP: the 64 KiB its boot stack had.
const AP_EXECUTOR_STACK_BYTES: usize = 64 * 1024;

/// Enter this AP's scheduler loop on a guarded `KernelStack` instead of the
/// direct-mapped boot block the trampoline handed it (Linux runs each CPU's
/// idle task on its own vmapped stack). The boot block is simply abandoned:
/// nothing below this call ever returns to it. Falls back to the current
/// stack if no guarded stack can be had.
pub fn run_executor_on_guarded_stack() -> ! {
    match narf_memory::kstack::KernelStack::alloc(AP_EXECUTOR_STACK_BYTES) {
        Ok(stack) => {
            let top = stack.top() & !0xF;
            core::mem::forget(stack); // the CPU's executor stack, never freed
                                      // SAFETY: `top` is the 16-byte-aligned top of a fresh, mapped,
                                      // exclusively owned stack; the entry never returns.
            unsafe { switch_stack_and_run(top) }
        }
        Err(_) => narf_scheduler::run_forever(),
    }
}

extern "C" fn executor_entry() -> ! {
    narf_scheduler::run_forever()
}

/// Load `top` into the stack pointer and call [`executor_entry`].
///
/// # Safety
/// `top` must be the 16-byte-aligned top of a mapped stack this CPU owns for
/// good: the current stack is abandoned.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_stack_and_run(top: u64) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "xor ebp, ebp",
        "call {entry}",
        "ud2",
        entry = sym executor_entry,
    );
}

/// Load `top` into SP and branch-link to [`executor_entry`].
///
/// # Safety
/// As for the x86_64 variant.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_stack_and_run(top: u64) -> ! {
    core::arch::naked_asm!(
        "mov sp, x0",
        "mov x29, xzr",
        "mov x30, xzr",
        "bl {entry}",
        "brk #0",
        entry = sym executor_entry,
    );
}

/// Word at `at`, if it lies inside the (mapped) overflowed stack.
fn word(hit: &GuardHit, at: u64) -> Option<u64> {
    if at < hit.stack_base || at.checked_add(8)? > hit.stack_top || at & 7 != 0 {
        return None;
    }
    // SAFETY: `[stack_base, stack_top)` is the live, mapped stack `guard_hit`
    // attributed the fault to; 8-aligned and in bounds (checked above).
    Some(unsafe { core::ptr::read_volatile(at as *const u64) })
}

/// Report an overflow of `hit` and either panic or, when a kernel test armed
/// exactly this overflow, return the `(pc, sp)` to resume at (the scheduler's
/// test recovery, which retires the overflowed task).
///
/// `how` names the exception ("double fault", "page fault", "bad stack").
pub fn report(
    how: &str,
    hit: GuardHit,
    fault: u64,
    pc: u64,
    sp: u64,
    fp: u64,
) -> Option<(u64, u64)> {
    let cpu = narf_lib::percpu::current_cpu();
    let task = narf_scheduler::current_task_id().raw();
    let _ = writeln!(
        TrapWriter,
        "\n*** kernel stack overflow ({how}) ***\n  cpu {cpu} task {task}: stack \
         [{:#x}, {:#x}) ({} KiB), guard hit at {fault:#x} ({} bytes below the base)\n  \
         pc {pc:#x} sp {sp:#x} fp {fp:#x}",
        hit.stack_base,
        hit.stack_top,
        (hit.stack_top - hit.stack_base) / 1024,
        hit.stack_base.saturating_sub(fault),
    );
    let (ts, te) = text_range();
    let _ = writeln!(
        TrapWriter,
        "  backtrace (frame-pointer chain, +off = addr2line):"
    );
    let mut frame = fp;
    for _ in 0..32 {
        let (Some(next), Some(ret)) = (word(&hit, frame), word(&hit, frame.wrapping_add(8))) else {
            break;
        };
        if (ts..te).contains(&ret) {
            let _ = writeln!(TrapWriter, "    {ret:#018x} (+{:#x})", ret - ts);
        }
        if next <= frame {
            break;
        }
        frame = next;
    }
    let _ = writeln!(
        TrapWriter,
        "  deepest return addresses (stack words in .text from the base up):"
    );
    let mut shown = 0;
    let mut at = hit.stack_base;
    while at < hit.stack_top && shown < 24 {
        if let Some(v) = word(&hit, at) {
            if (ts..te).contains(&v) {
                let _ = writeln!(
                    TrapWriter,
                    "    [base+{:#06x}] {v:#018x} (+{:#x})",
                    at - hit.stack_base,
                    v - ts
                );
                shown += 1;
            }
        }
        at += 8;
    }
    if let Some(resume) =
        narf_scheduler::stackful::overflow_test_recovery(hit.stack_base, hit.stack_top, fault)
    {
        let _ = writeln!(
            TrapWriter,
            "  (expected by a kernel test: retiring the task)"
        );
        return Some(resume);
    }
    panic!(
        "kernel stack overflow ({how}): cpu {cpu} task {task} stack [{:#x}, {:#x}) guard {fault:#x} pc {pc:#x}",
        hit.stack_base, hit.stack_top
    );
}
