//! Arch-specific startup primitives.
//!
//! `_start` is the kernel-visible ELF entry point (see the validate
//! sub-crate's linker script `ENTRY(_start)`). On x86_64 it is naked
//! because the SysV-AMD64 startup contract requires reading `rsp`
//! before any prologue clobbers it: the kernel hands argc/argv/envp
//! on the entry stack, and a normal Rust prologue would push rbp /
//! adjust rsp before we get a chance to capture it.
//!
//! We mirror the testbin's shape exactly (mov rdi, rsp ; align ;
//! call into Rust ; ud2) so any future change here can be ported
//! one-for-one.

/// SysV-AMD64 entry. Captures `rsp` (which points at argc), aligns
/// the stack to 16 bytes per the ABI, then calls into
/// [`crate::__libc_start_main`]. The trailing `ud2` only fires if
/// `__libc_start_main` returns — it is `-> !` so that should never
/// happen, but we want a hard fault rather than silent fall-through.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rsp",
        "and rsp, -16",
        "call {entry}",
        "ud2",
        entry = sym crate::__libc_start_main,
    );
}

/// aarch64 entry. The Stage-4 aarch64 user-mode pipeline does not
/// hand argv/envp on the stack yet; we forward 0 as `rsp_at_entry`
/// and let `__libc_start_main` skip the SysV-stack walk.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // SAFETY: forwarding into the Rust startup pipeline; the function
    // is `-> !` so control never returns here.
    // SAFETY: Valid memory or trusted environment
    unsafe { crate::__libc_start_main(0) }
}
