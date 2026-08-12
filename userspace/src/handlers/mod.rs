//! Core syscall handler bodies.
//!
//! POSIX-shaped syscall implementations behind the `Syscall` enum.
//! Each handler runs in trap context after the arch trap stub has
//! saved user registers and the `TrapContext` bridge is constructed.
//!
//! - `Open` — resolves an absolute or per-mount path through the
//!   VFS registry, allocates a new fd in the calling task's
//!   `FdTable`, returns the fd.
//! - `Read` / `Write` — look up the fd in the per-task table,
//!   poll the resulting `FileOps::{read,write}` to completion via
//!   `poll_once` (Stage-4 in-memory FSes resolve on first poll),
//!   advance the per-fd offset, return bytes transferred. fd 1/2
//!   bypass the table and write directly to the kernel console.
//! - `Close` / `Dup` / `Dup2` / `Fcntl` — direct fd-table operations.
//! - `Mmap` / `Munmap` — manipulate the calling task's `AddressSpace`.
//! - `ExitTask` — rewrites the trap frame (via
//!   `redirect_to_kernel`) to a landing pad the kernel publishes
//!   through `set_exit_landing`.
//! - `Yield` / `Sleep` — no-op Ok.
//!
//! `install_core_syscalls(table)` drops every handler above into a
//! freshly-built `SyscallTable` so kernels that want the common
//! set don't each have to wire every slot.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_memory::{AddressSpace, HugeRegion, Region, RegionPerms, VirtAddr};

use crate::{
    fd, RawFnHandler, SigDeliveryParams, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
    TrapContext,
};

// Keep the implementation fragments in this module's scope: the syscall
// handlers deliberately share private state and helpers, and turning the
// fragments into child modules would widen that internal visibility.
include!("core.inc.rs");
include!("compat.inc.rs");
