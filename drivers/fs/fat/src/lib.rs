//! FAT Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL Linux `fs/fat/*` or LGPL FatFs
//! source was consulted while writing this crate; every layout, magic
//! number, and algorithm trace back to one of the public references
//! below. Per-file headers cite the specific section consulted.
//!
//! References (entire crate). Every source below is **freely
//! available** — no paywall, no signup, no NDA required to read or
//! redistribute:
//!
//! - Microsoft FAT File System Specification (FATGEN v1.03), the
//!   primary normative source. Direct PDF on Microsoft's CDN, no
//!   account required:
//!   <https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf>
//! - UEFI Specification v2.10 §13.3 — "File System Format" — the
//!   profile required by EFI System Partitions. UEFI Forum
//!   publishes specs gratis:
//!   <https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#file-system-format>
//! - OSDev Wiki, "FAT" — algorithmic descriptions only (no code
//!   copied). Wiki content is CC-BY-SA 4.0:
//!   <https://wiki.osdev.org/FAT>
//! - Specs/research notes vendored in `specification/` and
//!   `research/` (this repository, project license).

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
