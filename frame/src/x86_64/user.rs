//! User-mode entry — the `iretq` transfer into CPL=3.
//!
//! After the scheduler has `activate()`-d the target task's
//! `AddressSpace` (MOV CR3 done) and populated `TSS.rsp0` with the
//! task's kernel stack, the kernel reaches user mode by pushing a
//! synthetic iretq frame and executing `iretq`. The CPU pops
//! `ss:rsp` + `rflags` + `cs:rip` from the stack and atomically
//! transitions to CPL=3.
//!
//! An `iretq` from kernel to user requires:
//! - `cs` = user-code selector (DPL=3): `UCODE_SEL` (0x33)
//! - `ss` = user-data selector (DPL=3): `UDATA_SEL` (0x2B)
//! - `rflags` with IF=1 so interrupts are enabled in user mode
//!   (bit 9 = 0x200), plus the reserved bit 1 (0x002) that's
//!   always 1.
//! - `cs.dpl >= cpl (= 0)` — DPL=3 is always >= 0, so this is
//!   structurally fine.
//!
//! `enter_user_mode` does not return. The only way back into the
//! kernel is a trap — `int 0x80` for syscalls (vector 128, now DPL=3
//! so user mode can trigger it), CPU exceptions (page fault etc.),
//! or an external IRQ.

use core::arch::{asm, naked_asm};

use super::gdt::{UCODE_SEL, UDATA_SEL};

/// Callee-saved register snapshot for the `setjmp`/`longjmp` pair
/// tests use to resume cleanly after a user-mode round-trip.
/// Field order is load-bearing — the naked asm reads by byte
/// offset.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct JmpBuf {
    pub rbx: u64,  // offset 0
    pub rbp: u64,  // offset 8
    pub r12: u64,  // offset 16
    pub r13: u64,  // offset 24
    pub r14: u64,  // offset 32
    pub r15: u64,  // offset 40
    pub rsp: u64,  // offset 48
    pub rip: u64,  // offset 56
}

/// Save callee-saved registers + caller's RSP + caller's return
/// RIP into `*buf`. Returns `0` on the initial call. A subsequent
/// `longjmp(buf, val)` resumes at the saved RIP, returning `val`
/// (forced non-zero so callers can distinguish) — effectively a
/// second "return" from this call site.
///
/// # Safety
/// `buf` must point at a valid, properly-aligned `JmpBuf`.
#[unsafe(naked)]
pub unsafe extern "C" fn setjmp(buf: *mut JmpBuf) -> u64 {
    naked_asm!(
        // SysV ABI: first ptr arg in rdi.
        "mov [rdi +  0], rbx",
        "mov [rdi +  8], rbp",
        "mov [rdi + 16], r12",
        "mov [rdi + 24], r13",
        "mov [rdi + 32], r14",
        "mov [rdi + 40], r15",
        // Caller's RSP is one qword above the CALL-pushed return
        // address — i.e. `rsp + 8` here inside this naked fn.
        "lea rax, [rsp + 8]",
        "mov [rdi + 48], rax",
        // Caller's return RIP is at the top of the stack.
        "mov rax, [rsp]",
        "mov [rdi + 56], rax",
        "xor rax, rax",
        "ret",
    );
}

/// Resume at `buf`'s saved state, returning `val` from the
/// corresponding `setjmp`. `val = 0` is rewritten to `1` so the
/// caller can always distinguish initial-call from longjmp paths.
///
/// # Safety
/// `buf` must have been populated by a prior `setjmp`, and the
/// saved RSP must still reference a live kernel stack.
#[unsafe(naked)]
pub unsafe extern "C" fn longjmp(buf: *const JmpBuf, val: u64) -> ! {
    naked_asm!(
        // SysV: buf in rdi, val in rsi.
        "mov rbx, [rdi +  0]",
        "mov rbp, [rdi +  8]",
        "mov r12, [rdi + 16]",
        "mov r13, [rdi + 24]",
        "mov r14, [rdi + 32]",
        "mov r15, [rdi + 40]",
        "mov rsp, [rdi + 48]",
        "mov rax, rsi",
        "test rax, rax",
        "jnz 1f",
        "inc rax",
        "1:",
        "jmp qword ptr [rdi + 56]",
    );
}

/// RFLAGS value to hand user mode: IF=1 (interrupts enabled), the
/// always-set reserved bit at position 1. Everything else zero —
/// user code shouldn't inherit kernel debug / alignment flags.
pub const USER_RFLAGS: u64 = 0x0000_0202;

/// Transfer into user mode. Does not return.
///
/// Layout at `iretq`: the CPU reads `ss:rsp, rflags, cs:rip` from
/// the current kernel stack (5 qwords). We push them in the spec-
/// defined order — bottom-of-stack-first is `rip`, then `cs`,
/// `rflags`, `rsp`, `ss`.
///
/// # Safety
/// - The active page table must map `rip` executable + user-mode
///   accessible, and `rsp` writable + user-mode accessible.
/// - `TSS.rsp0` must hold a valid kernel-stack top so the inevitable
///   trap back into the kernel has somewhere to land.
/// - The caller must have set up any per-CPU state
///   (`IA32_KERNEL_GS_BASE` etc.) the user context expects.
/// - Interrupts should be disabled across the iretq — this function
///   does not disable them; the caller owns that invariant.
pub unsafe fn enter_user_mode(rip: u64, rsp: u64) -> ! {
    // swapgs before iretq:
    //   Pre:  GS.base = kernel_percpu, KERNEL_GS_BASE = user_gs
    //         (caller must have populated KERNEL_GS_BASE — 0 is a
    //          valid sentinel for "user starts with null gs").
    //   Post: GS.base = user_gs, KERNEL_GS_BASE = kernel_percpu
    // The kernel's gs.base now rides in KERNEL_GS_BASE, ready for
    // the entry-side swapgs on the next user→kernel trap to swing
    // it back into GS.base.
    //
    // SAFETY: 5 pushes + iretq is the architecturally-defined
    // protocol for entering a lower privilege level in long mode.
    // Clobbering the stack is fine because we never return — the
    // caller's frame is discarded.
    unsafe {
        asm!(
            "swapgs",
            // Push the synthetic iretq frame (ss, rsp, rflags, cs, rip
            // — pushed in REVERSE order because stack grows down).
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss     = in(reg) UDATA_SEL as u64,
            rsp    = in(reg) rsp,
            rflags = in(reg) USER_RFLAGS,
            cs     = in(reg) UCODE_SEL as u64,
            rip    = in(reg) rip,
            options(noreturn),
        )
    }
}
