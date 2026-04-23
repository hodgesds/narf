//! narf-memory — physical/virtual addresses + allocators + MMU.
//!
//! Spec: `memory/specification/spec.md`. Wave-1 scope: just the `PhysAddr`
//! and `VirtAddr` newtypes that other crates need to talk about memory.
//! Buddy frame allocator, page tables, folios, slab magazines — Wave 2.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod addr;

pub use addr::{PhysAddr, VirtAddr};
