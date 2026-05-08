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
//! References (entire crate). Every source below is **freely
//! available** — no paywall, no signup, no NDA required to read
//! or redistribute:
//!
//! - Plan 9 Programmer's Manual, Vol. 1, Section 5 — the
//!   normative protocol description. Plan 9 was released under
//!   the MIT/X11 license in 2002; the manual pages are mirrored
//!   gratis. Per-message pages cited in `message.rs`: `intro(5)`,
//!   `version(5)`, `attach(5)`, `walk(5)`, `open(5)`, `read(5)`,
//!   `write(5)`, `clunk(5)`, `stat(5)`, `error(5)`.
//!   <https://9fans.github.io/plan9port/man/man9/>
//! - "Plan 9 from User Space" man pages at
//!   <http://man.cat-v.org/plan_9/5/0intro> — second public mirror
//!   of the Plan 9 protocol section, gratis to read.
//! - `qid` semantics cross-validated against the Inferno OS Styx
//!   protocol docs (Inferno is also gratis-published by Vita Nuova).

#![no_std]

extern crate alloc;

pub mod loopback;
pub mod message;
pub mod node;
pub mod session;
pub mod volume;

mod tests;

pub use message::{MsgType, Qid};
