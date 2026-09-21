//! Standard Linux errno definitions.
//!
//! Re-exports canonical Linux errno constants from [`narf_lib::errno`],
//! and provides userspace-specific return conversion [`to_ret`].

#![allow(dead_code)]

pub use narf_lib::errno::wire;
pub use narf_lib::errno::*;

/// Convert a positive errno into a [`crate::syscall::SyscallReturn`] with status `Ok`
/// and the negated errno as the return value.
#[inline]
pub const fn to_ret(errno: i64) -> crate::syscall::SyscallReturn {
    crate::syscall::SyscallReturn::ok((-errno) as u64)
}
