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

use core::arch::asm;

use super::gdt::{UCODE_SEL, UDATA_SEL};

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
    // SAFETY: 5 pushes + iretq is the architecturally-defined
    // protocol for entering a lower privilege level in long mode.
    // Clobbering the stack is fine because we never return — the
    // caller's frame is discarded.
    unsafe {
        asm!(
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
