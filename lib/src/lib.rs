//! narf-lib — shared no_std primitives.
//!
//! Spec: `lib/specification/spec.md`. Stage 1 lands typed IDs, the spinlock
//! family, `Once`/`OnceLock`, `Bitmap`, `IntrusiveList`, and base assertion
//! macros. Later stages add `SeqLock`, `RbTree`, `Mutex`/`RwLock`, and the
//! domain-aware diagnostic wiring (that one waits on `tracing/` and `frame/`).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![feature(generic_const_exprs)]
#![feature(negative_impls)]
#![allow(incomplete_features)]

extern crate alloc;

pub mod assert;
pub mod bitmap;
pub mod context;
pub mod id;
pub mod intrusive;
pub mod mutex;
pub mod percpu;
pub mod smp;
pub mod sync;

mod tests;
