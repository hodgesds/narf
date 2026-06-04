//! exFAT (Extended FAT) Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL/LGPL exFAT source (the Linux
//! `fs/exfat/*` tree, Samsung's pre-2019 GPL driver, fuse-exfat, or
//! any other licensed implementation) was consulted while writing
//! this crate. Every layout, magic number, sentinel value, and
//! algorithmic step traces back to one of the public references
//! below. Per-file headers cite the specific spec section consulted.
//!
//! References (entire crate). Every source below is **freely
//! available** — no paywall, no signup, no NDA required to read or
//! redistribute:
//!
//! - "exFAT file system specification" — Microsoft Corporation,
//!   published 2019. The single normative source. Hosted on
//!   Microsoft Learn (publicly readable, no Microsoft account
//!   needed): <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>
//! - OSDev Wiki, "exFAT" — algorithmic narrative only (no code
//!   reproductions). Wiki content is CC-BY-SA 4.0:
//!   <https://wiki.osdev.org/ExFAT>
//!
//! Background only (not load-bearing for any code in this crate):
//! - Microsoft 2019 announcement opening the exFAT specification and
//!   patents for implementation.
//!
//! Scope: read-only mount + directory walk + file read on the
//! consumption side. Write scaffolding lands in this commit —
//! `volume.rs` exposes `write_sector` / `write_cluster` /
//! `alloc_clusters` / `free_chain` (§7.1 bitmap allocator) and
//! `write_fat_entry`; `dir.rs` exposes §6.3.3 `set_checksum` /
//! `finalize_set_checksum` / `verify_set_checksum`; `upcase.rs`
//! exposes §7.2.3 `upcase_checksum`. The directory-entry edit path
//! (creating a §7.4 / §7.6 / §7.7 entry group, updating cluster
//! counts on its enclosing primary, and walking the parent
//! cluster chain for a free slot) is deferred — see the FileOps
//! `write` / `truncate` and DirOps mutator stubs in `node.rs`.

#![no_std]

extern crate alloc;

pub mod boot;
pub mod dir;
pub mod fat;
pub mod node;
pub mod upcase;
pub mod volume;

mod tests;
