//! User-mode entry/resume primitives.
//!
//! Exposed here (rather than in `narf-frame`) so any crate
//! downstream of `narf-arch` can build a polling future around a
//! task that lives at CPL=3 between polls. `narf-frame` still
//! owns the trap-side glue and the GDT/IDT setup; this module
//! holds only the wire-stable state shape, the naked-asm
//! `iretq` resume / first-entry, and the kernel-side
//! `setjmp`/`longjmp` pair the polling routine uses to bounce
//! out of user mode on a trap.
//!
//! Pairs with `narf_userspace::TrapContext::save_user_state`,
//! which the trap handler calls to populate a `UserState` slot
//! before either re-entering user mode or signalling the future.

#![allow(unused)]

use core::arch::{asm, naked_asm};
use core::sync::atomic::{compiler_fence, Ordering};

/// MSR index `IA32_FS_BASE` (Intel SDM Vol. 4 §2.6, "MSRs Common to
/// the IA-32 Family"). On x86_64 Linux and the SysV-AMD64 TLS model,
/// the FS segment base is the thread pointer — `mov rax, fs:[0]`
/// fetches `*(fs_base + 0)` which the ABI defines as the TCB self-
/// pointer. Writing this MSR is the canonical way to plant a per-
/// thread pointer in CPL=0 / CPL=3 transitions; the `wrfsbase`
/// instruction is gated on `CR4.FSGSBASE = 1` and so is not relied
/// upon here.
pub const IA32_FS_BASE: u32 = 0xC000_0100;

/// Program `IA32_FS_BASE` so the next user-mode entry observes
/// `fs:[N]` reading from `fs_base + N`. The kernel calls this just
/// before `enter_user_mode` / `enter_user_mode_resume` whenever the
/// outgoing task carries a TLS block (relibc Path B / `narf-libc`'s
/// `__libc_start_main` reads `*(fs:0)` for its TCB).
///
/// This is a thin `wrmsr` wrapper kept separate from
/// `enter_user_mode` so we don't have to break the existing naked-
/// asm signature (every call site would otherwise need to update);
/// the polling future + testbin runner call this immediately after
/// activating the AS and before the iretq trampoline.
///
/// # Safety
/// Writing `IA32_FS_BASE` is always legal at CPL=0 on long-mode
/// x86_64 (no CPUID gate — it's part of the architectural baseline).
/// The supplied `fs_base` must be a canonical user vaddr if the
/// next user-mode access through `fs:` is to land on a mapped page;
/// nothing here validates that.
#[inline]
pub unsafe fn set_user_fs_base(fs_base: u64) {
    let low  = fs_base as u32;
    let high = (fs_base >> 32) as u32;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: IA32_FS_BASE is unconditional on x86_64-long-mode; the
    // caller owns the canonical-vaddr precondition.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") IA32_FS_BASE,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Snapshot of a user-mode task's CPU state at trap time. Field
/// order is load-bearing — `enter_user_mode_resume`'s naked asm
/// reads by byte offset.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UserState {
    // GPRs in trap-frame order (matches narf_frame::x86_64::trap::TrapFrame).
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9:  u64, pub r8:  u64,
    pub rbp: u64, pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub rcx: u64, pub rbx: u64, pub rax: u64,
    /// User-mode RIP at the instruction the trap returns to.
    pub rip:    u64,
    /// User-mode RFLAGS at trap entry.
    pub rflags: u64,
    /// User-mode RSP.
    pub rsp:    u64,
    /// `1` once the trap path has populated this snapshot, `0`
    /// otherwise. Useful for "first-run vs resume" branches.
    pub valid:  u64,
}

/// User-code segment selector (DPL=3). Matches the GDT layout in
/// `narf-frame`. Hard-coded here because we can't pull `narf-frame`
/// (the kernel binary) into a library dep.
const UCODE_SEL: u64 = 0x33;
/// User-data segment selector (DPL=3).
const UDATA_SEL: u64 = 0x2B;

/// RFLAGS value to hand user mode: IF=1 (interrupts enabled), the
/// always-set reserved bit at position 1. Everything else zero —
/// user code shouldn't inherit kernel debug / alignment flags.
pub const USER_RFLAGS: u64 = 0x0000_0202;

/// Callee-saved register snapshot for the `setjmp`/`longjmp` pair
/// the polling-future / verification harnesses use to resume
/// cleanly after a user-mode round-trip. Field order is
/// load-bearing — the naked asm reads by byte offset.
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

/// First-entry transfer into user mode. Builds a synthetic iretq
/// frame `(ss, rsp, rflags, cs, rip)` and `iretq`s. Does not
/// return — the only path back is a trap.
///
/// # Safety
/// - The active page table must map `rip` executable + user-mode
///   accessible, and `rsp` writable + user-mode accessible.
/// - `TSS.rsp0` must hold a valid kernel-stack top so the inevitable
///   trap back into the kernel has somewhere to land.
/// - The caller must have set up any per-CPU state
///   (`IA32_KERNEL_GS_BASE` etc.) the user context expects; the
///   `swapgs` here moves the kernel's GS.base into KERNEL_GS_BASE
///   so the entry-side swapgs in the trap path can swing it back.
/// - Interrupts should be disabled across the iretq — this function
///   does not disable them; the caller owns that invariant.
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user_mode(rip: u64, rsp: u64) -> ! {
    naked_asm!(
        // SysV: rip in rdi, rsp in rsi.
        "swapgs",
        "push {udata}",                   // ss
        "push rsi",                       // rsp
        "push {rflags}",                  // rflags (IF=1)
        "push {ucode}",                   // cs
        "push rdi",                       // rip
        "iretq",
        udata  = const UDATA_SEL,
        ucode  = const UCODE_SEL,
        rflags = const USER_RFLAGS,
    );
}

/// Resume user mode at the state captured in `*state`. Restores
/// every GPR + RIP + RFLAGS + RSP via the iretq frame; never
/// returns.
///
/// # Safety
/// - The active page table must map `state.rip` executable + user
///   and `state.rsp` writable + user.
/// - `TSS.rsp0` must hold a valid kernel-stack top so the next
///   user→kernel trap has somewhere to land.
/// - The caller must have set `IA32_KERNEL_GS_BASE` to the per-CPU
///   pointer the trap path expects after the entry-side swapgs.
/// - The state in `*state` must have come from a prior trap from
///   user mode (the page tables / TSS / GS still match).
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user_mode_resume(state: *const UserState) -> ! {
    naked_asm!(
        // SysV: state ptr in rdi.
        // Push iretq frame (ss, rsp, rflags, cs, rip — reverse).
        "mov rax, {udata}",
        "push rax",                       // ss
        "push qword ptr [rdi + 8*17]",    // user rsp
        "push qword ptr [rdi + 8*16]",    // rflags
        "mov rax, {ucode}",
        "push rax",                       // cs
        "push qword ptr [rdi + 8*15]",    // rip
        // Restore GPRs (rdi loaded last so it can serve as base).
        "mov r15, [rdi + 8*0]",
        "mov r14, [rdi + 8*1]",
        "mov r13, [rdi + 8*2]",
        "mov r12, [rdi + 8*3]",
        "mov r11, [rdi + 8*4]",
        "mov r10, [rdi + 8*5]",
        "mov r9,  [rdi + 8*6]",
        "mov r8,  [rdi + 8*7]",
        "mov rbp, [rdi + 8*8]",
        "mov rsi, [rdi + 8*10]",
        "mov rdx, [rdi + 8*11]",
        "mov rcx, [rdi + 8*12]",
        "mov rbx, [rdi + 8*13]",
        "mov rax, [rdi + 8*14]",
        "mov rdi, [rdi + 8*9]",
        "swapgs",
        "iretq",
        udata = const UDATA_SEL,
        ucode = const UCODE_SEL,
    );
}
