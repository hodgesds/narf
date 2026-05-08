//! 9P2000 Protocol implementation for NARF.
//!
//! Clean-room implementation based on:
//! - Plan 9 Manual (Section 5)
//! - 9P2000 Protocol Draft
//! - 9P2000.u Extensions

#![no_std]

extern crate alloc;

pub mod message;
pub mod session;
pub mod volume;
pub mod node;

pub use message::{MsgType, Qid};
