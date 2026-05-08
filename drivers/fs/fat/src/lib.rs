//! FAT Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL Linux `fs/fat/*` or LGPL FatFs
//! source was consulted while writing this crate; every layout, magic
//! number, and algorithm trace back to one of the public references
//! below. Per-file headers cite the specific section consulted.
//!
//! References (entire crate):
//! - Microsoft FAT File System Specification (FATGEN v1.03), the
//!   primary normative source.
//!   <https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf>
//! - UEFI Specification v2.10 §13.3 — "File System Format" — the
//!   profile required by EFI System Partitions.
//!   <https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#file-system-format>
//! - OSDev Wiki, "FAT" — algorithmic descriptions only (no code copied).
//!   <https://wiki.osdev.org/FAT>
//! - Specs/research notes vendored in `specification/` and `research/`.

#![no_std]

extern crate alloc;

pub mod bpb;
pub mod fat;
pub mod dir;
pub mod fsinfo;
pub mod volume;
pub mod node;

mod tests;

/// FAT Version
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FatVersion {
    Fat12,
    Fat16,
    Fat32,
}
