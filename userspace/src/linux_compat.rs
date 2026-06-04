//! Linux-compat personality stub.
//!
//! Gated on `#[cfg(feature = "linux-compat")]`.  Waves 63-67 will land
//! the real implementations here:
//!
//! - epoll_create1 / epoll_ctl / epoll_wait
//! - eventfd / eventfd2
//! - timerfd_create / timerfd_settime / timerfd_gettime
//! - clone3 (task + address-space flags)
//! - mprotect / madvise
//! - dynamic-linker (PT_INTERP) plumbing
//!
//! Nothing is exported yet; the module exists so downstream crates can
//! write `#[cfg(feature = "linux-compat")] use narf_userspace::linux_compat;`
//! without a compile error.
