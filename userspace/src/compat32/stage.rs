//! Native-layout scratch space on an i386 caller's own user stack.
//!
//! Some compat entry points hand a native handler a structure the handler
//! reads and writes through user pointers — a `struct msghdr` with its
//! iovec array and control buffer, an `mmsghdr` vector. Linux converted
//! those with `compat_alloc_user_space()` until 5.11: the native structure
//! was built on the caller's user stack, below its stack pointer (i386 has
//! no red zone; a 64-bit caller's 128-byte one is skipped), and the native
//! code ran against it. The area is dead stack — nothing the caller can see
//! lives below its stack pointer during the call — and it is rebuilt from
//! the compat structures each time the call is (re-)issued.
//!
//! A [`Stage`] reserves the whole area up front and hands out 16-byte
//! aligned pieces of it.

use alloc::vec::Vec;

use crate::errno::EFAULT;
use crate::syscall::TrapContext;

/// The x86_64 red zone a 64-bit `int 0x80` caller may have live below its
/// stack pointer.
const RED_ZONE: u64 = 128;
/// The lowest address a stage may start at (`mmap_min_addr`).
const FLOOR: u64 = 0x1_0000;

/// A reserved region of the caller's stack; see the module documentation.
#[derive(Debug)]
pub(crate) struct Stage {
    cursor: u64,
    end: u64,
}

impl Stage {
    /// Reserve `len` bytes below the caller's stack pointer.
    pub(crate) fn new(ctx: &dyn TrapContext, len: usize) -> Result<Self, i64> {
        let mut sp = ctx.user_rsp();
        if !ctx.in_compat_mode() {
            sp = sp.wrapping_sub(RED_ZONE);
        }
        let len = (len as u64).checked_add(15).ok_or(EFAULT)? & !15;
        let base = sp.checked_sub(len).ok_or(EFAULT)? & !15;
        if base < FLOOR {
            return Err(EFAULT);
        }
        Ok(Self {
            cursor: base,
            end: base + len,
        })
    }

    /// The next `len` bytes (16-byte aligned), uninitialised.
    pub(crate) fn alloc(&mut self, len: usize) -> Result<u64, i64> {
        let at = self.cursor;
        let next = at
            .checked_add((len as u64).checked_add(15).ok_or(EFAULT)? & !15)
            .ok_or(EFAULT)?;
        if next > self.end {
            return Err(EFAULT);
        }
        self.cursor = next;
        Ok(at)
    }

    /// Copy `bytes` into the next piece and return its user address.
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<u64, i64> {
        let at = self.alloc(bytes.len())?;
        if !bytes.is_empty() {
            // SAFETY: the caller's address space is the live one; the copy
            // validates the range and catches a fault (an unmapped stack page
            // below the caller's stack pointer) as EFAULT.
            unsafe { crate::handlers::copy_to_user(at, bytes) }.map_err(|_| EFAULT)?;
        }
        Ok(at)
    }
}

/// Read `len` bytes the native handler left at staged address `at`.
pub(crate) fn read_back(at: u64, len: usize) -> Result<Vec<u8>, i64> {
    let mut out = alloc::vec![0u8; len];
    if len != 0 {
        // SAFETY: as `Stage::put`.
        unsafe { crate::handlers::copy_from_user(&mut out, at) }.map_err(|_| EFAULT)?;
    }
    Ok(out)
}
