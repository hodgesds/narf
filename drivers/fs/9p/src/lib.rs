//! 9P2000 Protocol implementation for NARF.
//!
//! Clean-room implementation. The 9P protocol is fundamentally a
//! message-passing surface (T-message → R-reply pairs over a
//! `Transport`), not an on-disk format — this crate decodes /
//! encodes the wire format, manages fids + qids, and exposes the
//! result through `narf_filesystem::FsInstance`. No GPL/LGPL 9p
//! source (Linux `fs/9p`/`net/9p`, diod, plan9port, FreeBSD
//! v9fs) was consulted while writing this crate.
//!
//! References:
//! - Plan 9 Programmer's Manual, Vol. 1, Section 5 — the
//!   normative protocol description. Per-message man pages cited
//!   in `message.rs`: `intro(5)`, `version(5)`, `attach(5)`,
//!   `walk(5)`, `open(5)`, `read(5)`, `write(5)`, `clunk(5)`,
//!   `stat(5)`, `error(5)`.
//!   <https://9fans.github.io/plan9port/man/man9/>
//! - "Plan 9 from User Space" man pages at
//!   <http://man.cat-v.org/plan_9/5/0intro> (mirror of the
//!   protocol section).
//! - `qid` semantics from `intro(5)` + Inferno OS Styx docs
//!   (cross-validation only).

#![no_std]

extern crate alloc;

pub mod message;
pub mod node;
pub mod session;
pub mod volume;

// NOTE: `loopback.rs` and `tests.rs` are partial work from a
// background agent that left the crate's protocol surface
// half-refactored — its files reference a `Transport` trait /
// `WireRead` / `WireWrite` / `frame_message` / `NinepVolume` API
// that doesn't exist yet in message.rs / session.rs / volume.rs
// (which still expose the older `P9Transport` / `P9FileSystem`
// shape). Both files are kept on disk as a starting point for a
// future pass to reconcile, but they are NOT registered as
// modules so the crate continues to build. See
// drivers/fs/9p/src/{loopback,tests}.rs.

pub use message::{MsgType, Qid};
