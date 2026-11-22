//! Compat (IA-32) user pointers and structure access.
//!
//! An i386 pointer is a 32-bit register, so `compat_ptr()` only
//! zero-extends it; what the kernel must still refuse is a structure that
//! runs past `TASK_SIZE_32`, where no IA-32 mapping can be. These helpers
//! check that bound (EFAULT, as the faulting copy would report on Linux)
//! and then copy through the ordinary guarded user-access path.

use narf_memory::AddressSpace;

/// Is `[ptr, ptr + len)` inside the IA-32 address space?
#[inline]
pub(crate) fn user_range_ok(ptr: u64, len: usize) -> bool {
    ptr.checked_add(len as u64)
        .is_some_and(|end| end <= AddressSpace::COMPAT32_TASK_SIZE)
}

/// Copy `buf.len()` bytes from the i386 user address `ptr`.
/// `Err(EFAULT)` for a range past `TASK_SIZE_32` or a faulting copy.
pub(crate) fn read_user(ptr: u64, buf: &mut [u8]) -> Result<(), i64> {
    if ptr == 0 || !user_range_ok(ptr, buf.len()) {
        return Err(crate::errno::EFAULT);
    }
    // SAFETY: the caller's address space is the live one (a syscall of the
    // task that owns `ptr`); `copy_from_user` validates and fault-guards.
    unsafe { crate::handlers::copy_from_user(buf, ptr) }.map_err(|_| crate::errno::EFAULT)
}

/// Copy `bytes` to the i386 user address `ptr`; errors as [`read_user`].
pub(crate) fn write_user(ptr: u64, bytes: &[u8]) -> Result<(), i64> {
    if ptr == 0 || !user_range_ok(ptr, bytes.len()) {
        return Err(crate::errno::EFAULT);
    }
    // SAFETY: as `read_user`.
    unsafe { crate::handlers::copy_to_user(ptr, bytes) }.map_err(|_| crate::errno::EFAULT)
}

/// The little-endian `u32` at byte `index * 4` of `raw`.
#[inline]
pub(crate) fn word(raw: &[u8], index: usize) -> u32 {
    let at = index * 4;
    u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]])
}

/// A 32-bit register value as the `int`/`long` C argument it carries:
/// sign-extended, as `__SC_COMPAT_CAST` makes the `__ia32_sys_*` wrappers do.
#[inline]
pub(crate) const fn sext(reg: u64) -> u64 {
    reg as u32 as i32 as i64 as u64
}
