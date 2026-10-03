//! Narf kernel side of the one-address-space Reverie backend.
//!
//! Narf calls its syscall interceptor on the trapping task's own kernel
//! stack, with the task's address space active and the Tool's state in the
//! same kernel address space. This crate turns that call into a callback of an
//! unmodified [`reverie::Tool`] hosted by [`reverie_narf_core::NarfToolHost`]:
//!
//! * [`NarfKernelServices`] is the per-entry
//!   [`reverie_narf_core::KernelServices`]: the task's root-namespace Linux
//!   IDs, its entry registers, its memory, and the kernel-owned native
//!   transition of the one intercepted syscall;
//! * [`IrqSpinTaskLock`] is the host's task-table lock;
//! * [`ReverieInterceptor`] is the [`narf_userspace::syscall::SyscallInterceptor`]
//!   that owns the host and forwards syscall entries and task lifecycle
//!   events to it.
//!
//! There is no IPC, ptrace emulation, signal, binary rewriting or polling: the
//! kernel calls the interceptor, the interceptor polls the Tool's future once,
//! and every Tool-to-kernel operation is a direct call.
//!
//! The crate is x86_64-only because Reverie's syscall layer is defined
//! without `std` only for x86_64; on any other target it is empty.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
mod interceptor;
#[cfg(target_arch = "x86_64")]
mod services;
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
mod tests;

#[cfg(target_arch = "x86_64")]
pub use interceptor::{ConsoleSink, IrqSpinTaskLock, ReverieInterceptor, TaskExitRecord};
#[cfg(target_arch = "x86_64")]
pub use services::{map_native_outcome, NarfKernelServices, NarfMemory};
