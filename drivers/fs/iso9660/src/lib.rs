//! ISO 9660 (ECMA-119) Filesystem Driver for NARF.
//!
//! Clean-room implementation based on:
//! - ECMA-119 Standard (3rd Edition)
//! - OSDev Wiki (ISO 9660)

#![no_std]

extern crate alloc;

pub mod descriptor;
pub mod dir;
pub mod volume;
pub mod node;

/// ISO 9660 Sector Size (standard)
pub const SECTOR_SIZE: usize = 2048;
