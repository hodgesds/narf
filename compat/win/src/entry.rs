//! Per-arch Win32 thread entry primitive.
//!
//! `enter_winprocess` is the per-arch trampoline that:
//! 1. Activates the WinProcess's address space.
//! 2. Programs the TEB-pointer system register
//!    (`IA32_KERNEL_GS_BASE` on amd64 — picked up via `swapgs` on
//!    the way into user mode; `TPIDR_EL0` on aarch64).
//! 3. Calls `enter_user_mode(entry, stack_top - 8)` to `iretq` /
//!    `eret` into the PE entry point.
//!
//! Once this is reached on amd64, a Win32 caller's
//! `mov rax, gs:[0x30]` resolves to the TEB self-pointer,
//! `mov rax, gs:[0x60]` to the PEB pointer, and so on. The
//! per-process trampoline page sits at `WinProcess.trampoline_va`
//! so any `call qword ptr [iat]` from the PE lands on a Ring-3
//! `int 0x80` that the kernel-side `SYS_WIN_THUNK` handler
//! dispatches.

use crate::process::WinProcess;

/// Per-arch entry. Activates the process's AS, programs the
/// TEB-pointer reg, and dives into user mode at `proc.entry`.
///
/// # Safety
/// - Caller must run with interrupts disabled (per
///   `enter_user_mode`'s contract).
/// - The frame allocator and TSS.rsp0 must be set up so the
///   inevitable trap back into the kernel has a stack to land on.
/// - The `compat-win-rt` system DLL must already be mapped into
///   the WinProcess's AS and the IAT patched with its symbol
///   VAs — `load_pe` does this. PE's `call qword ptr [iat]`
///   instructions are ordinary user-mode calls; no kernel-side
///   thunk handler is involved per spec v1.0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enter_winprocess(proc: &WinProcess) -> ! {
    use narf_arch::x86_64::user_mode::{enter_user_mode, set_user_gs_base};

    // SAFETY: AS::activate is per-arch the MOV CR3 / TTBR0 write;
    // safe at CPL=0 with the AS in a coherent state (load_pe
    // guarantees that).
    // SAFETY: Valid memory or trusted environment
    unsafe {
        // A failed activation is unrecoverable — we cannot enter
        // user mode without the right page table live. Panic with
        // context rather than silently dropping the error.
        proc.address_space
            .activate()
            .expect("compat/win: AddressSpace::activate failed");

        // Program IA32_KERNEL_GS_BASE so post-`swapgs` user mode
        // sees gs_base = teb_va. enter_user_mode does the swapgs
        // immediately before iretq.
        set_user_gs_base(proc.teb_va.as_u64());

        // RSP starts one qword down from the high end so an
        // immediate `push` lands inside the mapped stack region.
        let rsp = proc.stack_top.as_u64().wrapping_sub(8);
        enter_user_mode(proc.entry.as_u64(), rsp);
    }
}

/// aarch64 stub of the per-arch entry — see the x86_64 variant above.
///
/// # Safety
/// Same contract as the x86_64 variant (interrupts disabled, trap stack
/// set up, `load_pe` completed). The body currently panics — aarch64 has
/// no user-mode entry primitive yet — so no unsafe operation is actually
/// performed; the signature stays `unsafe` for cross-arch parity.
#[cfg(target_arch = "aarch64")]
pub unsafe fn enter_winprocess(_proc: &WinProcess) -> ! {
    // aarch64 user-mode entry primitive doesn't exist in the
    // current `arch/aarch64` surface (no `user_mode.rs` parallel
    // to x86_64). When it lands, this body programs `TPIDR_EL0`
    // ← `proc.teb_va` via `msr tpidr_el0, x0` and dispatches to
    // the eventual `enter_user_mode_eret(rip, sp)` shim.
    //
    // Until then: panic. aarch64 `load_pe` already returns
    // `LoadError::AddressSpace` on `new_for_user` (TTBR0 not yet
    // wired up), so this path is unreachable in practice.
    panic!("compat/win: aarch64 user-mode entry not implemented");
}

// Host-test fallback so the module type-checks under
// cargo test on x86_64-unknown-linux-gnu. `enter_user_mode` is
// gated on `target_arch = "x86_64"`, but the *kernel* x86_64
// target gates the asm specifically; the Linux x86_64 host build
// shouldn't try to enter user mode at all. We provide a panicking
// stub so the symbol resolves regardless of cfg.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub unsafe fn enter_winprocess(_proc: &WinProcess) -> ! {
    panic!("compat/win: enter_winprocess unsupported on this target");
}
