//! exFAT (Extended FAT) Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL/LGPL exFAT source (the Linux
//! `fs/exfat/*` tree, Samsung's pre-2019 GPL driver, fuse-exfat, or
//! any other licensed implementation) was consulted while writing
//! this crate. Every layout, magic number, sentinel value, and
//! algorithmic step traces back to one of the public references
//! below. Per-file headers cite the specific spec section consulted.
//!
//! References (entire crate):
//! - "exFAT file system specification" — Microsoft Corporation,
//!   published 2019. The single normative source.
//!   <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>
//! - OSDev Wiki, "exFAT" — algorithmic narrative only (no code
//!   reproductions). <https://wiki.osdev.org/ExFAT>
//!
//! Background only (not load-bearing for any code in this crate):
//! - Microsoft 2019 announcement opening the exFAT specification and
//!   patents for implementation.
//!
//! Scope of the first cut: read-only mount + directory walk + file
//! read. Write paths, the bitmap allocator, and on-disk up-case
//! checksum verification are explicitly deferred (see TODOs in
//! `volume.rs` / `node.rs`).

#![no_std]

extern crate alloc;

pub mod boot;
pub mod dir;
pub mod fat;
pub mod upcase;
pub mod volume;
pub mod node;

mod tests;
