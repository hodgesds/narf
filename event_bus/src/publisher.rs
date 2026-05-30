//! `Publisher<T>` — single-owner handle to publish into a topic ring.
//!
//! Holding a `Publisher<T>` proves prior authorisation (the cap was
//! minted by `create_topic`); each `publish()` revalidates via
//! `cap.check_live()` so revocation takes effect on the next call.

use alloc::sync::Arc;

use narf_capabilities::{Cap, Invoke};

use crate::cap::Publisher as PublisherCap;
use crate::engine::{Ring, SeqNum};
use crate::payload::{Arena, ArenaHandle, Event};
use crate::registry::TopicId;

/// Per-topic publisher handle. `Clone`-able by callers that want to
/// hand one out to a forwarding adapter; revocation invalidates all
/// clones at once via the cap-table epoch.
pub struct Publisher<T: Event> {
    cap: Cap<PublisherCap, Invoke>,
    ring: Arc<Ring<T>>,
    arena: Option<Arc<Arena>>,
    topic_id: TopicId,
}

impl<T: Event> Clone for Publisher<T> {
    fn clone(&self) -> Self {
        Self {
            cap: self.cap,
            ring: self.ring.clone(),
            arena: self.arena.clone(),
            topic_id: self.topic_id,
        }
    }
}

impl<T: Event> core::fmt::Debug for Publisher<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Publisher")
            .field("topic_id", &self.topic_id)
            .finish_non_exhaustive()
    }
}

/// Errors from `publish`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PublishError {
    /// Publisher cap has been revoked.
    CapRevoked,
    /// No arena attached, but `publish_with_bytes` was called.
    NoArena,
}

impl<T: Event> Publisher<T> {
    pub(crate) fn new(
        cap: Cap<PublisherCap, Invoke>,
        ring: Arc<Ring<T>>,
        arena: Option<Arc<Arena>>,
        topic_id: TopicId,
    ) -> Self {
        Self {
            cap,
            ring,
            arena,
            topic_id,
        }
    }

    /// Topic this publisher writes to.
    #[inline]
    pub fn topic_id(&self) -> TopicId {
        self.topic_id
    }

    /// Publish a fixed-size event. Wait-free; safe from IRQ context.
    pub fn publish(&self, event: T) -> Result<SeqNum, PublishError> {
        if self.cap.check_live().is_err() {
            // Closure of the ring lets pending subscribers wake up
            // and observe the revocation.
            self.ring.close();
            return Err(PublishError::CapRevoked);
        }
        Ok(self.ring.publish(event))
    }

    /// Publish an event plus a variable-size byte payload via the
    /// per-topic arena. Caller is responsible for stamping the
    /// `ArenaHandle` into the event payload `T` before this call —
    /// `publish_with_arena` returns the handle, the caller writes it
    /// into the event struct, and then calls `publish`.
    ///
    /// Returns the handle for inclusion in subsequent `publish`. The
    /// arena allocation is decoupled so the event struct stays
    /// fully-typed.
    pub fn alloc_arena(&self, bytes: &[u8]) -> Result<ArenaHandle, PublishError> {
        if self.cap.check_live().is_err() {
            self.ring.close();
            return Err(PublishError::CapRevoked);
        }
        let arena = self.arena.as_ref().ok_or(PublishError::NoArena)?;
        Ok(arena.write(bytes))
    }

    /// Revoke this publisher's cap. Future `publish` calls return
    /// `CapRevoked`; subscribers wake and see the close.
    pub fn revoke(self) {
        let Publisher {
            cap,
            ring,
            arena: _,
            topic_id: _,
        } = self;
        ring.close();
        cap.revoke();
    }
}
