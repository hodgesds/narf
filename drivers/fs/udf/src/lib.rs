//! UDF (Universal Disk Format / ECMA-167 / OSTA UDF 2.60) read-only
//! filesystem driver for NARF.
//!
//! Clean-room implementation. No GPL/LGPL UDF source was consulted
//! while writing this crate — specifically, none of the Linux kernel
//! `fs/udf/*`, libudfread, GRUB's UDF driver, or the FreeBSD UDF
//! tree was opened. Every layout, magic byte, and algorithm traces
//! back to one of the public references below; per-file headers
//! cite the specific ECMA-167 / OSTA UDF section.
//!
//! References (entire crate):
//! - ECMA-167 (3rd edition, June 1997) — "Volume and File Structure
//!   of Read-Only and Write-Once and Rewritable Media using
//!   Non-Sequential Recording for Information Interchange". Base
//!   normative spec; freely published.
//!   <https://ecma-international.org/publications-and-standards/standards/ecma-167/>
//! - OSTA UDF 2.60 — "Universal Disk Format Specification".
//!   Disc-format profile layered on top of ECMA-167.
//!   <https://www.osta.org/specs/index.htm>
//! - ECMA-119 (ISO 9660) for the Bridge format context — already
//!   implemented in `drivers/fs/iso9660`.
//! - Specs/research notes vendored in `specification/` and
//!   `research/`.
//!
//! Read-only by design: optical UDF media (DVD-Video, BD-ROM) is
//! authored offline; the in-kernel write surface for rewritable UDF
//! is large enough to deserve its own driver. All mutating
//! `DirOps` / `FileOps` methods inherit the trait-default
//! `FsError::Unsupported`; `FileOps::write` returns `FsError::ReadOnly`.

#![no_std]

extern crate alloc;

pub mod descriptor;
pub mod fid;
pub mod icb;
pub mod node;
pub mod volume;

mod tests;

/// UDF logical block size — fixed at 2048 bytes by every real UDF
/// authoring tool (ECMA-167 allows 512 / 1024 in theory; OSTA UDF
/// 2.60 §2.2.1 strongly recommends 2048 and every disc in
/// circulation conforms). This driver requires the underlying
/// `BlockDevice` to report `logical_block_size() == 2048` for a
/// 1:1 sector mapping. Devices with a smaller LBS need to be
/// wrapped in an aggregator beforehand (or use `RamBlockDevice`
/// with `lbs = 2048`, as the in-tree tests do).
pub const SECTOR_SIZE: usize = 2048;

/// OSTA UDF 2.60 §2.2.3 — primary AVDP location. The Anchor Volume
/// Descriptor Pointer must be at sector 256 on every conformant
/// volume (the two fall-back positions live in [`volume`]).
pub const AVDP_PRIMARY_SECTOR: u64 = 256;
