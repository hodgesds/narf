//! Cap-type markers wiring the three new `CapKind`s
//! (`TopicRegistry`, `EventPublisher`, `EventSubscriber`) into
//! `narf_capabilities::Cap<T, R>`.
//!
//! Why three distinct types: per-topic asymmetry. A subscriber to
//! `input.evdev` holds `Cap<Subscriber<input_evdev>>` and cannot
//! mint a `Cap<Publisher<input_evdev>>` from it. The two cap
//! lattices are unrelated, so an attacker who compromises the
//! subscriber cannot forge events on the topic it observes.

use narf_capabilities::{CapKind, CapType};

/// Authority to create / look up topics. Holding `Cap<TopicRegistry,
/// Write>` lets the bearer mint new topics (with the reserved-root
/// rule); `Cap<TopicRegistry, Read>` allows topic enumeration without
/// mint authority.
#[derive(Copy, Clone, Debug)]
pub struct TopicRegistry;

impl CapType for TopicRegistry {
    const KIND: CapKind = CapKind::TopicRegistry;
}

/// Authority to publish on a topic. Single-owner per topic (the
/// registry mints exactly one publisher cap per topic at creation
/// time). Revocation drains in-flight publishes and rejects further
/// `publish()` calls with `PublishError::CapRevoked`.
#[derive(Copy, Clone, Debug)]
pub struct Publisher;

impl CapType for Publisher {
    const KIND: CapKind = CapKind::EventPublisher;
}

/// Authority to subscribe to a topic. Each subscribe call mints a
/// fresh cap so revocation is per-subscriber. Revocation drops the
/// subscriber's cursor; pending `next().await` futures return
/// `RecvError::CapRevoked`.
#[derive(Copy, Clone, Debug)]
pub struct Subscriber;

impl CapType for Subscriber {
    const KIND: CapKind = CapKind::EventSubscriber;
}
