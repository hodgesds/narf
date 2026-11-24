//! Kernel-free runtime for NARF loadable modules.
//!
//! A `.ko` crosses into the kernel only through the primitive C KABI. That is
//! enough for a hundred-line driver that polls a ring; it is not enough for a
//! driver written against `alloc`, `async` and locks. This crate supplies
//! those, built from five KABI exports (`narf_printk`, `narf_kmalloc`,
//! `narf_kfree`, `narf_monotonic_ns`, `narf_module_param`) and nothing
//! else:
//!
//! * [`heap`] — the module's `#[global_allocator]`, over the kernel heap.
//! * [`console`] — whole-line console output ([`printkln!`]).
//! * [`sync`] — a spin lock whose guard is `!Send` and an async mutex.
//! * [`time`] — the monotonic clock, deadlines and sleep futures.
//! * [`exec`] — an executor for the module's own futures.
//! * [`param`] — the module's load parameters (`.narf_kparams`, overridden
//!   by `<module>.<param>=` on the kernel command line or the load string).
//!
//! ## Execution model
//!
//! Module text never runs in hard-IRQ context: the kernel calls a module from
//! task context only (its init/exit, probe, the device poller and per-vector
//! IRQ upcalls — `bus/src/driver_match.rs`). Those calls may run concurrently
//! on different CPUs, so the locks here spin, but none of them can interrupt
//! one another on the same CPU, so nothing needs to mask interrupts.
//!
//! A module cannot hand a `Future` to the kernel's scheduler. Instead it owns
//! an [`exec::Executor`] and runs it from every upcall it receives; the
//! kernel's 1 ms device poller (`narf_spawn_poller`) is the heartbeat that
//! guarantees forward progress. Wakers only request another pass sooner.

#![cfg_attr(not(test), no_std)]
#![feature(negative_impls)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

mod abi;

pub mod console;
pub mod exec;
pub mod heap;
pub mod param;
pub mod sync;
pub mod time;

#[cfg(test)]
mod tests;
