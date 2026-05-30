//! narf-event-bus — cap-gated SPMC publish/subscribe bus.
//!
//! Phase 1: in-kernel SPMC ring with per-consumer cursor, gap signal
//! on slow subscriber, three cap kinds (`TopicRegistry`, `Publisher`,
//! `Subscriber`), audit log, and the async `Subscriber::next().await`
//! surface. No wildcards, no fd surface, no mmap cross-domain. See
//! `event_bus/SPEC.md` and `event_bus/notes/CAPS_AND_HOOKS.md`.
//!
//! Design pillars:
//! - **Publisher never blocks.** Slow subscribers observe `Gapped {
//!   skipped }`; producer wins the race.
//! - **Per-topic distinct caps.** Holding `Cap<Subscriber, _>` for
//!   `acpi.button` does not allow publishing on it.
//! - **Reserved-root prefixes are kernel-only.** Userspace mints
//!   under `user.<daemon>.`; the registry refuses cross-prefix
//!   mints with `MintError::ReservedPrefix`.
//! - **Audit log.** Every privileged-root cap mint or revoke
//!   publishes on `system.security.audit`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

mod engine;
pub mod audit;
pub mod cap;
pub mod payload;
pub mod publisher;
pub mod registry;
pub mod subscriber;
pub mod topic;

mod tests;

pub use audit::AuditEvent;
pub use cap::{Publisher as PublisherCap, Subscriber as SubscriberCap, TopicRegistry};
pub use engine::SeqNum;
pub use payload::{ArenaHandle, Event};
pub use publisher::{PublishError, Publisher};
pub use registry::{
    audit_subscribe_kernel, create_topic, create_topic_with_arena, init, lookup_topic,
    CreateError, LookupError, TopicId,
};
pub use subscriber::{RecvError, Subscriber};
pub use topic::{NameError, TopicName, MAX_NAME_BYTES, MAX_SEGMENTS};
