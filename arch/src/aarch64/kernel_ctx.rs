//! AArch64 kernel context switch for scheduler-owned task stacks.

#![allow(dead_code)]

use core::arch::naked_asm;

/// AAPCS64 callee-saved state plus the stack, resume PC, and interrupt mask.
/// Offsets are consumed directly by [`kernel_switch`].
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct KernelContext {
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub sp: u64,
    pub pc: u64,
    pub daif: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(KernelContext, x19) == 0);
    assert!(core::mem::offset_of!(KernelContext, x29) == 80);
    assert!(core::mem::offset_of!(KernelContext, sp) == 88);
    assert!(core::mem::offset_of!(KernelContext, pc) == 96);
    assert!(core::mem::offset_of!(KernelContext, daif) == 104);
    assert!(core::mem::size_of::<KernelContext>() == 112);
    assert!(core::mem::align_of::<KernelContext>() == 16);
};

impl KernelContext {
    pub const fn zeroed() -> Self {
        Self {
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            x29: 0,
            sp: 0,
            pc: 0,
            daif: 0,
        }
    }

    /// Seed a fresh task. `arg` is carried in x19 to the trampoline.
    pub fn fresh(stack_top: u64, entry: u64, arg: u64) -> Self {
        Self {
            x19: arg,
            sp: stack_top & !0xF,
            pc: entry,
            // DAIF clear: a fresh task begins with IRQ/FIQ enabled.
            ..Self::zeroed()
        }
    }
}

/// Swap the current AAPCS64 kernel continuation with `incoming`.
///
/// # Safety
/// Both contexts and the incoming stack/PC must remain live. Callers own all
/// per-task address-space, domain-rights, and interrupt-context invariants.
#[unsafe(naked)]
pub unsafe extern "C" fn kernel_switch(out: *mut KernelContext, incoming: *const KernelContext) {
    naked_asm!(
        "stp x19, x20, [x0, #0]",
        "stp x21, x22, [x0, #16]",
        "stp x23, x24, [x0, #32]",
        "stp x25, x26, [x0, #48]",
        "stp x27, x28, [x0, #64]",
        "str x29, [x0, #80]",
        "mov x9, sp",
        "str x9, [x0, #88]",
        "str x30, [x0, #96]",
        "mrs x9, daif",
        "str x9, [x0, #104]",
        "ldp x19, x20, [x1, #0]",
        "ldp x21, x22, [x1, #16]",
        "ldp x23, x24, [x1, #32]",
        "ldp x25, x26, [x1, #48]",
        "ldp x27, x28, [x1, #64]",
        "ldr x29, [x1, #80]",
        "ldr x9, [x1, #88]",
        "mov sp, x9",
        "ldr x16, [x1, #96]",
        "ldr x17, [x1, #104]",
        "msr daif, x17",
        "br x16",
    );
}
