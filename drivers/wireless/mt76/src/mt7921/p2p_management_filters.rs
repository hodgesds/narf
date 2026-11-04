//! Actual source-bound cfg80211 management subscriptions for one WDEV.
//! Host registration alone creates no native capture/channel/started owner.
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::ap_control::{RadioControlAuthority, RadioEventAuthority};
const MAX_FILTERS: usize = 16;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Debug)]
struct Filter {
    frame_type: u16,
    prefix: Vec<u8>,
    source: RadioEventAuthority,
}
#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub generation: u64,
    entries: Vec<Filter>,
}
#[derive(Debug)]
pub(crate) struct Subscriptions {
    state: IrqSafeSpinLock<Snapshot>,
}
impl Default for Subscriptions {
    fn default() -> Self {
        Self {
            state: IrqSafeSpinLock::new(Snapshot {
                generation: 0,
                entries: Vec::new(),
            }),
        }
    }
}
#[derive(Debug)]
pub(crate) struct Install {
    expected: u64,
    next: Snapshot,
}
impl Subscriptions {
    pub fn snapshot(&self) -> Snapshot {
        self.state.lock().clone()
    }
    /// Prepare outside every driver/registry spinlock. Linux rejects an
    /// overlapping prefix globally on that WDEV (mlme.c705ff), irrespective
    /// of socket port-id; a closed/revoked old source cannot reserve it.
    pub fn prepare(
        &self,
        authority: &RadioControlAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<Install, i32> {
        super::p2p_management_wire::registration(frame_type, prefix)?;
        authority.require_mode(10).map_err(|_| 1)?;
        if !authority.has_reservation() {
            return Err(1);
        }
        let mut next = self.snapshot();
        let expected = next.generation;
        next.entries
            .retain(|filter| filter.source.registration_current().is_ok());
        if next
            .entries
            .iter()
            .filter(|filter| filter.frame_type == frame_type)
            .any(|filter| {
                let length = core::cmp::min(filter.prefix.len(), prefix.len());
                filter.prefix[..length] == prefix[..length]
            })
        {
            return Err(114);
        }
        if next.entries.len() == MAX_FILTERS {
            return Err(28);
        }
        let source = authority.event_authority().map_err(|_| 1)?;
        let generation = NEXT_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                next.checked_add(1)
            })
            .map_err(|_| 75)?;
        next.generation = generation;
        next.entries.insert(
            0,
            Filter {
                frame_type,
                prefix: prefix.to_vec(),
                source,
            },
        );
        Ok(Install { expected, next })
    }
    /// The native owner has already closed capture and drained its finite
    /// completed descriptor prefix before committing this new generation.
    /// It then opens only a separately proved started/channel capture owner.
    pub fn commit(&self, install: Install) -> Result<Snapshot, i32> {
        if install
            .next
            .entries
            .first()
            .is_none_or(|filter| filter.source.registration_current().is_err())
        {
            return Err(1);
        }
        let (previous, snapshot) = {
            let mut state = self.state.lock();
            if state.generation != install.expected {
                return Err(16);
            }
            let previous = core::mem::replace(&mut *state, install.next);
            (previous, state.clone())
        };
        drop(previous); // Source destructors never run under the driver lock.
        Ok(snapshot)
    }
}
impl Snapshot {
    pub fn has_current_source(&self) -> bool {
        self.entries
            .iter()
            .any(|filter| filter.source.registration_current().is_ok())
    }
    /// The caller separately proves the actual native capture epoch,
    /// started BSS and RF/channel owner. This selects only its exact current
    /// registered source and never creates frame-admission authority.
    pub fn receiver(&self, frame_type: u16, body: &[u8]) -> Option<RadioEventAuthority> {
        self.entries
            .iter()
            .find(|filter| {
                filter.frame_type == frame_type
                    && body.starts_with(&filter.prefix)
                    && filter.source.registration_current().is_ok()
            })
            .map(|filter| filter.source.clone())
    }
}
impl Install {
    pub fn generation(&self) -> u64 {
        self.next.generation
    }
}
/// A shared host metadata owner, with no native device/capture grant.
pub(crate) type Shared = Arc<Subscriptions>;
