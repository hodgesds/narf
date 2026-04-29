//! Cap-checked user-pointer accessor.
//!
//! Win32 thunks dereference user-VA pointers handed to them by the
//! PE caller (e.g. `WriteConsoleA`'s `lpBuffer`). The caller is
//! Ring-3, the AS is the WinProcess's, and the kernel handler runs
//! in CPL=0 with the user AS active — so the kernel *can* read the
//! user VA via a plain pointer, but doing so unconditionally is
//! one bug away from a kernel-mode read of a kernel page.
//!
//! This module bounds the read against the active task's
//! `AddressSpace` region table:
//!
//! 1. Resolve the active AS via `narf_userspace::active_user_as()`.
//! 2. Find the region containing `[va, va + len)`.
//! 3. Verify the region carries `READ` and lies entirely below the
//!    kernel/user split (no canonical-high-half VAs — those are
//!    kernel-only by construction in NARF's split AS).
//! 4. `copy_nonoverlapping` into a kernel buffer.
//!
//! A failure at any step returns `Err(UserPtrError::Inaccessible)`
//! and the thunk converts that to the documented Win32 failure
//! return for its signature.

use alloc::sync::Arc;

use narf_memory::{AddressSpace, RegionPerms, VirtAddr};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UserPtrError {
    /// The active address space lookup wasn't installed, or the
    /// task has no AS attached. Programmer / boot-time error.
    NoActiveAs,
    /// `va` is `0`, the range crosses into kernel space, or the
    /// length wraps `u64`.
    Invalid,
    /// `[va, va + len)` does not lie entirely inside one mapped
    /// user-readable region.
    Inaccessible,
}

/// Maximum byte count accepted in a single `copy_in` call. Win32
/// `WriteConsole`'s nominal max is `DWORD::MAX` chars, but
/// dereferencing a 4-GiB user buffer through a single kernel
/// stack accessor is silly — chunk in the caller.
pub const MAX_USER_COPY: usize = 4096;

/// Copy `dst.len()` bytes from user VA `va` into `dst`. Returns
/// `Ok(())` on success, an `UserPtrError` on any check failure.
///
/// # Safety
/// - The caller must run with the task's AS active (true inside a
///   `SyscallHandler::invoke` body — the trap path arrives with
///   the user AS live and doesn't switch).
/// - Concurrent unmaps of the user buffer race this read; M0
///   accepts the race because Win32 thunks run synchronously
///   within a single user thread that cannot itself unmap. A
///   future M2 hardening pass adds an RCU read-side critical
///   section around the region check + copy.
pub unsafe fn copy_in(va: u64, dst: &mut [u8]) -> Result<(), UserPtrError> {
    if dst.is_empty() { return Ok(()); }
    if dst.len() > MAX_USER_COPY {
        return Err(UserPtrError::Invalid);
    }
    if va == 0 {
        return Err(UserPtrError::Invalid);
    }
    let end = va.checked_add(dst.len() as u64).ok_or(UserPtrError::Invalid)?;
    // Refuse anything in canonical-high-half (kernel) territory.
    if va >= 0xFFFF_8000_0000_0000 || end > 0xFFFF_8000_0000_0000 {
        return Err(UserPtrError::Invalid);
    }

    let as_arc: Arc<AddressSpace> = narf_userspace::active_user_as()
        .ok_or(UserPtrError::NoActiveAs)?;

    // Find the region containing `va`. The buffer must fit inside
    // a single region; cross-region reads are refused at this
    // level. (A real M1 walker stitches them when needed.)
    let region = as_arc.lookup(VirtAddr::new(va))
        .ok_or(UserPtrError::Inaccessible)?;
    if !region.perms.contains(RegionPerms::READ) {
        return Err(UserPtrError::Inaccessible);
    }
    let region_end = region.base.as_u64()
        .checked_add(region.len)
        .ok_or(UserPtrError::Inaccessible)?;
    if end > region_end {
        return Err(UserPtrError::Inaccessible);
    }

    // SAFETY: bounds checked above; caller-side AS-active contract
    // documented on the function. Identity-mapped low-4-GiB or the
    // region's user mapping makes the read reach the backing pages.
    unsafe {
        core::ptr::copy_nonoverlapping(
            va as *const u8,
            dst.as_mut_ptr(),
            dst.len(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn rejects_zero_va() {
        let mut buf = [0u8; 16];
        // SAFETY: never reaches the actual read — bounds check
        // refuses va=0 first.
        let r = unsafe { copy_in(0, &mut buf) };
        assert_eq!(r, Err(UserPtrError::Invalid));
    }

    #[test]
    fn rejects_kernel_high_half() {
        let mut buf = [0u8; 16];
        // SAFETY: bounds check catches the high-half VA before
        // any read happens.
        let r = unsafe { copy_in(0xFFFF_8000_0000_0000, &mut buf) };
        assert_eq!(r, Err(UserPtrError::Invalid));
    }

    #[test]
    fn rejects_too_large() {
        let mut buf = [0u8; MAX_USER_COPY + 1];
        // SAFETY: bounds check refuses oversized read.
        let r = unsafe { copy_in(0x1000, &mut buf) };
        assert_eq!(r, Err(UserPtrError::Invalid));
    }
}
