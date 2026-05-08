//! ISO 9660 (ECMA-119) filesystem driver for NARF.
//!
//! Clean-room implementation. No GPL Linux `fs/isofs/*`, libcdio,
//! libisoburn, GRUB iso9660, or FreeBSD cd9660 source was consulted
//! while writing this crate. Every layout, magic byte, and algorithm
//! traces back to one of the public references below; per-file
//! headers cite the specific ECMA-119 section.
//!
//! References (entire crate). Every source below is **freely
//! available** — no paywall, no signup, no NDA required to read or
//! redistribute:
//!
//! - ECMA-119 (3rd edition, December 2017) — "Volume and File
//!   Structure of CDROM for Information Interchange". The
//!   normative source. ECMA publishes all its standards as
//!   gratis-downloadable PDFs:
//!   <https://www.ecma-international.org/publications-and-standards/standards/ecma-119/>
//! - ISO/IEC 9660 — the same text republished by ISO. (Note: the
//!   ISO-branded copy is paywalled; we cite the ECMA edition above
//!   which is the identical text and is gratis.)
//! - OSDev Wiki, "ISO 9660" — narrative algorithmic description
//!   (no code copied). Wiki content is CC-BY-SA 4.0:
//!   <https://wiki.osdev.org/ISO_9660>
//! - Specs/research notes vendored in `specification/` and
//!   `research/` (this repository, project license).
//!
//! Read-only by design: ISO 9660 is the on-disc CD/DVD layout —
//! authoring tools (mkisofs, xorriso) build images offline. All
//! mutating `DirOps`/`FileOps` methods return `FsError::ReadOnly`.

#![no_std]

extern crate alloc;

pub mod descriptor;
pub mod dir;
pub mod node;
pub mod volume;

mod tests;

/// ISO 9660 logical block size — fixed at 2048 bytes by ECMA-119
/// §6.1.2 ("Logical Sector"). The standard allows 512/1024 only as
/// edge cases that no real disc uses; this driver requires the
/// underlying `BlockDevice` to report `logical_block_size() == 2048`
/// for a 1:1 sector mapping. Devices with a smaller LBS need to be
/// wrapped in an aggregator beforehand (or use `RamBlockDevice` with
/// `lbs = 2048`, as the in-tree tests do).
pub const SECTOR_SIZE: usize = 2048;
