//! User-mode entry/resume primitives.
//!
//! Exposed here (rather than in `narf-frame`) so any crate
//! downstream of `narf-arch` can build a polling future around a
//! task that lives at CPL=3 between polls. `narf-frame` still
//! owns the trap-side glue and the GDT/IDT setup; this module
//! holds only the wire-stable state shape and the naked-asm
//! `iretq` resume.
//!
//! Pairs with `narf_userspace::TrapContext::save_user_state`,
//! which the trap handler calls to populate a `UserState` slot
//! before either re-entering user mode or signalling the future.

#![allow(unused)]

use core::arch::naked_asm;

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
