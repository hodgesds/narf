//! aarch64 EL0 (user-mode) entry — the `eret` transfer into EL0.
//!
//! After the scheduler has swapped TTBR0_EL1 to the target task's
//! root and populated SP_EL0 with the user stack, the kernel
//! reaches user mode by setting ELR_EL1 = entry, SPSR_EL1 with
//! M[3:0] = 0 (EL0t), and executing `eret`. The CPU atomically
//! transitions to EL0 with the supplied PC + PSTATE + SP.
//!
//! Trap-back from EL0:
//! - `svc #0` → vec.S `__narf_vec_sync_el0` → `rust_aarch64_sync_
//!   dispatch` → `kernel_syscall_entry`.
//! - Page faults / SError → fatal sync vector → `rust_aarch64_sync`.
//!
//! `enter_user_mode` does not return.

use core::arch::asm;

/// SPSR_EL1 value for EL0t entry: mode bits = 0b0000 (EL0 + SP_EL0),
/// DAIF cleared so user mode runs with interrupts enabled.
pub const USER_SPSR: u64 = 0;

/// Transfer into EL0. Does not return.
///
/// # Safety
/// - The currently-active TTBR0 must map `rip` executable +
///   user-accessible (AP_RW_EL0/EL1 with !UXN) and `rsp` writable
///   + user-accessible.
/// - Caller must have populated SP_EL0 if the user code expects
///   anything but a freshly-set SP — this primitive sets SP_EL0
///   from `rsp`.
pub unsafe fn enter_user_mode(rip: u64, rsp: u64) -> ! {
    // SAFETY: SP_EL0/ELR_EL1/SPSR_EL1 writes at EL1 are
    // architecturally defined; eret with SPSR.M = 0 enters EL0.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "msr sp_el0,  {rsp}",
            "msr elr_el1, {rip}",
            "msr spsr_el1, xzr",        // SPSR = 0 → EL0t, IF/DAIF clear
            "eret",
            rip = in(reg) rip,
            rsp = in(reg) rsp,
            options(noreturn),
        )
    }
}
