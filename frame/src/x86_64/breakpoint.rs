//! x86_64 software-breakpoint primitives (INT3 patching).
//!
//! Implements the arch hook consumed by the GDB stub's Z0/z0 packet
//! handlers. INT3 is the single-byte encoding `0xCC` (opcode 3);
//! installing a software breakpoint means:
//!   1. Reading the original byte at the target virtual address.
//!   2. Writing `0xCC` in its place.
//!
//! Restoring undoes the patch by writing the saved byte back.
//!
//! Reference: Intel SDM Vol. 2A §3.2 — INT3 (opcode CC) generates
//! trap #BP (interrupt vector 3), which the IDT routes to the GDB stub
//! handler. Linux reference: kernel/debug/gdbstub.c::kgdb_arch_set_breakpoint
//! (GPL-2.0-or-later; adapted under NARF's post-2026-05-20 licence).
//!
//! # Safety contract
//!
//! Both public functions are `unsafe` because they write to arbitrary
//! virtual addresses. Callers (the GDB stub) are the kernel TCB and
//! have already validated the address via the cap-gated attach entry
//! point. A write to a bad address will fault — accepted as the
//! failure mode for misuse of the GDB stub.

/// Error type for breakpoint operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BpError {
    /// The target virtual address is not writable (e.g. read-only
    /// text mapped without write permission, or outside the kernel's
    /// address space). NARF's identity-mapped kernel text is always
    /// writable at CPL=0, so in practice this variant surfaces only
    /// if a caller passed a bogus address.
    NotWritable,
}

/// INT3 opcode — the single-byte "breakpoint" encoding.
pub const INT3: u8 = 0xCC;

/// Install a software breakpoint at `va` by overwriting the byte at
/// that virtual address with `INT3` (`0xCC`). Returns the original
/// byte so the caller can restore it later.
///
/// # Safety
/// `va` must be a valid kernel virtual address pointing to mapped,
/// writable memory. Passing an unmapped or user-space address will
/// cause a fault. The caller is the GDB stub, which is cap-gated.
///
/// Linux reference: kernel/debug/gdbstub.c::kgdb_arch_set_breakpoint
pub unsafe fn install_int3_breakpoint(va: u64) -> Result<u8, BpError> {
    let ptr = va as *mut u8;
    // SAFETY: caller asserts `va` is a valid, writable kernel address.
    let original = unsafe { core::ptr::read_volatile(ptr) };
    // SAFETY: same assertion — write the INT3 opcode.
    unsafe { core::ptr::write_volatile(ptr, INT3) };
    Ok(original)
}

/// Restore the byte at `va` to `original`, removing the INT3 patch
/// installed by [`install_int3_breakpoint`].
///
/// # Safety
/// Same contract as [`install_int3_breakpoint`]: `va` must be a valid,
/// writable kernel address. The caller is the GDB stub, which is
/// cap-gated.
///
/// Linux reference: kernel/debug/gdbstub.c::kgdb_arch_remove_breakpoint
pub unsafe fn restore_byte(va: u64, original: u8) -> Result<(), BpError> {
    let ptr = va as *mut u8;
    // SAFETY: caller asserts `va` is a valid, writable kernel address.
    unsafe { core::ptr::write_volatile(ptr, original) };
    Ok(())
}
