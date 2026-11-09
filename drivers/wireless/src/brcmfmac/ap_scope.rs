// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed original AP/peer/DATA copy generations. Dynamic socket/provider
//! work is completed by the frontend before this callback-free final fence.
use super::{ap_native::Scope, ap_source::Source, runtime::Error};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_wireless::{ap_control::ApEmissionAuthority, reg::RegulatoryDomain};

#[derive(Clone, Debug)]
pub(crate) struct Epoch {
    word: Arc<AtomicU64>,
    value: u64,
}
impl Epoch {
    pub(super) fn new() -> Self {
        Self {
            word: Arc::new(AtomicU64::new(1)),
            value: 1,
        }
    }
    pub(super) fn capture(&self) -> Self {
        Self {
            word: self.word.clone(),
            value: self.word.load(Ordering::Acquire),
        }
    }
    pub(super) fn advance(&mut self) -> Result<(), Error> {
        let next = self
            .word
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1).filter(|next| *next < u64::MAX)
            })
            .map_err(|_| {
                self.close();
                Error::Exhausted
            })?
            + 1;
        self.value = next;
        Ok(())
    }
    pub(super) fn close(&self) {
        self.word.store(u64::MAX, Ordering::Release);
    }
    pub(crate) fn current(&self) -> bool {
        self.value != u64::MAX && self.word.load(Ordering::Acquire) == self.value
    }
    pub(super) fn serial(&self) -> u64 {
        self.word.load(Ordering::Acquire)
    }
    pub(super) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.word, &other.word) && self.value == other.value
    }
}
/// A concrete immutable policy source, never an arbitrary PolicySource
/// callback inside native State. Pointer identity is the original installed
/// signed-domain instance; equal-byte replacement is not the same authority.
#[derive(Clone)]
pub(crate) struct Policy {
    domain: Arc<RegulatoryDomain>,
    database: Option<Arc<narf_wireless::reg::db::Database>>,
}
impl Policy {
    pub(crate) fn installed() -> Result<Self, Error> {
        let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
        Ok(Self {
            domain,
            database: None,
        })
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn scoped(database: Arc<narf_wireless::reg::db::Database>) -> Result<Self, Error> {
        let domain = database.snapshot().ok_or(Error::Access)?;
        Ok(Self {
            domain,
            database: Some(database),
        })
    }
    pub(crate) fn domain(&self) -> &Arc<RegulatoryDomain> {
        &self.domain
    }
    pub(crate) fn current(&self) -> bool {
        let now = self
            .database
            .as_ref()
            .map_or_else(narf_wireless::reg::db::snapshot, |database| {
                database.snapshot()
            });
        now.as_ref()
            .is_some_and(|now| Arc::ptr_eq(now, &self.domain))
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Use {
    Lifecycle,
    Receive,
    /// Denial-only hold from a real association indication until actual SCB
    /// verification. It grants no transmit, DATA, installed key or port.
    EarlyControl,
    Data,
    Control,
}
#[derive(Clone)]
pub struct Capture {
    pub(super) native: Source,
    pub(super) source: ApEmissionAuthority,
    pub(super) sources: Vec<ApEmissionAuthority>,
    pub(super) policy: Policy,
    /// The AP scope this capture belongs to: its firmware events carry
    /// this scope's (ifidx, bsscfgidx) pair. `program_event_blocks`
    /// classifies with it, so a benign event on a secondary vif no
    /// longer spuriously blocks Program SET, and a secondary
    /// association indication still blocks.
    pub(super) scope: Scope,
    pub(super) role: Epoch,
    pub(super) copy: Epoch,
    pub(super) peer: Option<Epoch>,
    pub(super) data: Option<Epoch>,
    pub(super) key: Option<Epoch>,
    pub(super) epochs: Vec<Epoch>,
    pub(super) purpose: Use,
    pub(super) target: Option<[u8; 6]>,
    pub(super) own: [u8; 6],
    pub(super) running: Option<Arc<AtomicBool>>,
    pub(super) mode: Arc<AtomicU64>,
    pub(super) mode_value: u64,
}
impl core::fmt::Debug for Capture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacApCapture")
            .field("purpose", &self.purpose)
            .field("mode_generation", &self.mode_value)
            .finish_non_exhaustive()
    }
}
impl Capture {
    /// Consumed records remain queued until Session applies them. A native
    /// GET can inspect firmware without opening a port or publishing RF/key
    /// state, but Program SET must not step past an unapplied denial or
    /// association generation transition. Mirrors Session::native_event's
    /// actual event classes; this classifies no arbitrary BSS metadata.
    pub(crate) fn program_event_blocks(
        &self,
        header: &crate::cyw43439::events::EventHeader,
    ) -> bool {
        !matches!(
            super::ap_wire::event_transition(header, self.own, self.scope.indices()),
            Ok(super::ap_wire::Transition::Benign)
        )
    }
    /// Compare only the retained original native Runtime identity. No raw
    /// source, firmware registry or other owner's access is exposed.
    pub(crate) fn belongs_to(&self, live: &Arc<AtomicBool>) -> bool {
        self.native.belongs_to(live)
    }
    pub(crate) fn lifecycle(&self) -> bool {
        matches!(self.purpose, Use::Lifecycle)
    }
    pub(crate) fn transmit(&self, bytes: &[u8]) -> bool {
        if !(14..=1514).contains(&bytes.len())
            || self
                .target
                .as_ref()
                .is_none_or(|target| bytes[..6] != *target)
            || bytes[6..12] == [0; 6]
            || bytes[6] & 1 != 0
            || self
                .running
                .as_ref()
                .is_none_or(|running| !running.load(Ordering::Acquire))
        {
            return false;
        }
        let protocol = u16::from_be_bytes([bytes[12], bytes[13]]);
        match self.purpose {
            Use::Data => protocol >= 0x600 && !matches!(protocol, 0x888e | 0x88c7),
            Use::Control => {
                matches!(protocol, 0x888e | 0x88c7)
                    && bytes[6..12] == self.own
                    && bytes[0] & 1 == 0
                    && self.peer.is_some()
            }
            _ => false,
        }
    }
    pub(crate) fn same_role(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.role.word, &other.role.word) && self.role.value == other.role.value
    }
    pub(crate) fn role_current(&self) -> Result<(), Error> {
        if !self.source.current()
            || !self.sources.iter().all(ApEmissionAuthority::current)
            || !self.policy.current()
            || !self.role.current()
            || self.mode_value == u64::MAX
            || self.mode.load(Ordering::Acquire) != self.mode_value
        {
            return Err(Error::Access);
        }
        self.native.current()
    }
    fn fixed(&self) -> bool {
        self.source.current()
            && self.sources.iter().all(ApEmissionAuthority::current)
            && self.policy.current()
            && self.role.current()
            && self.copy.current()
            && self.peer.as_ref().is_none_or(Epoch::current)
            && self.data.as_ref().is_none_or(Epoch::current)
            && self.key.as_ref().is_none_or(Epoch::current)
            && self.epochs.iter().all(Epoch::current)
            && self
                .running
                .as_ref()
                .is_none_or(|running| running.load(Ordering::Acquire))
            && self.mode_value != u64::MAX
            && self.mode.load(Ordering::Acquire) == self.mode_value
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        if !self.fixed() {
            return Err(Error::Access);
        }
        self.native.current()
    }
    /// Final publication after ALL dynamic callbacks. The original native
    /// source is invoked again and only original fixed facts can reach copy.
    /// The caller may copy bytes/deliver a prepared token; never recapture.
    pub(crate) fn publish<T>(&self, copy: impl FnOnce() -> T) -> Result<T, Error> {
        self.native.invoke(|| {
            if !self.fixed() {
                Err(Error::Access)
            } else {
                Ok(copy())
            }
        })?
    }
}
