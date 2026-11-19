// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-bound Action subscriptions and retained native WMI copies. Metadata
//! registration grants no RF owner; only current FOREIGN_CHANNEL opens copies.
use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::ap_control::{PreparedRadioManagementEvent, RadioReceiveFence};

#[derive(Clone, Debug)]
struct Filter {
    frame_type: u16,
    prefix: Vec<u8>,
    emission: RadioEmissionAuthority,
    event: RadioEventAuthority,
}
#[derive(Clone, Debug)]
struct Snapshot {
    generation: u64,
    filters: Vec<Arc<Filter>>,
}
#[derive(Debug)]
pub(in crate::ath10k) struct Subscriptions {
    state: IrqSafeSpinLock<Snapshot>,
    probe_request: bool,
    pub(super) epoch: Arc<AtomicU64>,
}
#[derive(Debug)]
pub(in crate::ath10k) struct Install {
    before: u64,
    next: Snapshot,
}
/// Keep the prior source references alive until the caller releases Radio.
#[derive(Debug)]
pub(in crate::ath10k) struct RetiredSubscriptions {
    _snapshot: Snapshot,
}
impl Subscriptions {
    pub(in crate::ath10k) fn new() -> Self {
        Self::with_probe_request(false)
    }
    /// The P2P_DEVICE wdev's set also admits Probe Request registrations.
    pub(in crate::ath10k) fn with_probe_request(probe_request: bool) -> Self {
        Self {
            state: IrqSafeSpinLock::new(Snapshot {
                generation: 0,
                filters: Vec::new(),
            }),
            probe_request,
            epoch: Arc::new(AtomicU64::new(1)),
        }
    }
    /// All dynamic source callbacks run before native Radio is borrowed.
    /// Overlapping prefixes on this interface return EALREADY, as cfg80211
    /// does regardless of which socket installed the existing subscription.
    pub(in crate::ath10k) fn prepare(
        &self,
        event: RadioEventAuthority,
        emission: RadioEmissionAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<Install, i32> {
        // Action on every owner; Probe Request only on the P2P_DEVICE wdev
        // (`ieee80211_default_mgmt_stypes[NL80211_IFTYPE_P2P_DEVICE].rx`),
        // whose owner passes `probe_request`.
        if !(frame_type == 0xd0 || frame_type == 0x40 && self.probe_request) || prefix.len() > 2280
        {
            return Err(22);
        }
        event.current().map_err(|_| 1)?;
        if !emission.current() {
            return Err(1);
        }
        let mut next = self.state.lock().clone();
        let before = next.generation;
        next.filters
            .retain(|f| f.emission.current() && f.event.registration_current().is_ok());
        if next
            .filters
            .iter()
            .filter(|f| f.frame_type == frame_type)
            .any(|f| {
                let length = f.prefix.len().min(prefix.len());
                f.prefix[..length] == prefix[..length]
            })
        {
            return Err(114);
        }
        if next.filters.len() == 16 {
            return Err(28);
        }
        next.generation = before.checked_add(1).filter(|n| *n < u64::MAX).ok_or(75)?;
        next.filters.try_reserve(1).map_err(|_| 12)?;
        next.filters.push(Arc::new(Filter {
            frame_type,
            prefix: prefix.to_vec(),
            emission,
            event,
        }));
        Ok(Install { before, next })
    }
    pub(in crate::ath10k) fn invalidate(&self) {
        let _ = self.advance();
    }
    pub(super) fn advance(&self) -> Result<u64, Error> {
        match self
            .epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(1).filter(|n| *n < u64::MAX)
            }) {
            Ok(old) => Ok(old + 1),
            Err(_) => {
                self.epoch.store(u64::MAX, Ordering::Release);
                Err(Error::Exhausted)
            }
        }
    }
    pub(super) fn commit(&self, install: Install) -> Result<RetiredSubscriptions, Error> {
        if install
            .next
            .filters
            .last()
            .is_none_or(|f| !f.emission.current())
        {
            return Err(Error::Failed);
        }
        let old = {
            let mut state = self.state.lock();
            if state.generation != install.before {
                return Err(Error::Failed);
            }
            core::mem::replace(&mut *state, install.next)
        };
        Ok(RetiredSubscriptions { _snapshot: old })
    }
}

#[derive(Debug)]
struct CapturePolicy {
    plan: active_scan::Plan,
    caps: wmi_boot::Capabilities,
    deadline: narf_time::Deadline,
}
#[derive(Debug)]
pub(in crate::ath10k) struct Captured {
    policy: CapturePolicy,
    pub frequency: u16,
    pub frame: Vec<u8>,
    source: Arc<Filter>,
    origin: RadioEmissionAuthority,
    epoch: Arc<AtomicU64>,
    generation: u64,
    io: Option<crate::ath10k::firmware_source::Source>,
}
impl Captured {
    pub(in crate::ath10k) fn prepare<I: narf_wireless::WirelessNetIface + ?Sized>(
        &self,
        iface: &I,
    ) -> Result<PreparedRadioManagementEvent, Error> {
        self.source
            .event
            .check_for(iface)
            .map_err(|_| Error::Failed)?;
        self.source
            .event
            .prepare_management_received(u32::from(self.frequency), None, &self.frame)
            .map_err(|_| Error::Failed)
    }
    /// Run after event preparation (and therefore after every dynamic source
    /// callback), outside Radio. Final delivery itself checks only the actual
    /// retained emission proofs and the native/filter copy epoch.
    pub(in crate::ath10k) fn deliver(
        &self,
        event: PreparedRadioManagementEvent,
        domain: &RegulatoryDomain,
    ) -> Result<(), Error> {
        self.policy.plan.validate(&self.policy.caps, domain)?;
        if self.policy.deadline.expired()
            || !self.source.emission.current()
            || !self.origin.current()
            || self.epoch.load(Ordering::Acquire) != self.generation
        {
            return Err(Error::Failed);
        }
        crate::ath10k::firmware_source::invoke(self.io.as_ref(), || {
            event
                .deliver(RadioReceiveFence {
                    epoch: &self.epoch,
                    generation: self.generation,
                    receiver: &self.source.emission,
                    origin: &self.origin,
                })
                .map_err(|_| Error::Failed)
        })
        .map_err(|_| Error::Failed)?
    }
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn bind_roc_subscriptions(
        &mut self,
        subscriptions: Arc<Subscriptions>,
    ) -> Result<(), Error> {
        // The managed netdev and the P2P_DEVICE wdev each own a set
        // (cfg80211 registrations are per wdev). The bound set follows the
        // ROC owner and may change only while no ROC holds capture state.
        if self
            .management_subscriptions
            .as_ref()
            .is_some_and(|old| !Arc::ptr_eq(old, &subscriptions))
            && self.roc.is_some()
        {
            return Err(Error::Failed);
        }
        self.management_subscriptions = Some(subscriptions);
        Ok(())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn take_roc_capture(&mut self) -> Option<Captured> {
        self.management_received.pop_front()
    }
    pub(in crate::ath10k) fn take_roc_captures(
        &mut self,
    ) -> alloc::collections::VecDeque<Captured> {
        core::mem::take(&mut self.management_received)
    }
    pub(super) fn close_roc_capture(&mut self) -> Result<(), Error> {
        if let Some(s) = &self.management_subscriptions {
            s.advance()?;
        }
        if let Some(w) = &mut self.roc {
            w.capture_epoch = None;
        }
        // Stale owned copies are moved out by the service caller after
        // unlocking Radio. Epoch closure already makes them undeliverable.
        Ok(())
    }
    pub(super) fn open_roc_capture(&mut self) -> Result<(), Error> {
        let Some(subscriptions) = &self.management_subscriptions else {
            return Ok(());
        };
        let epoch = subscriptions.advance()?;
        if let Some(w) = &mut self.roc {
            if w.started && w.foreign && !w.terminal && !w.stop_sent {
                w.capture_epoch = Some(epoch);
            }
        }
        Ok(())
    }
    /// Change filters only after the old native completed prefix is drained.
    /// A late old packet cannot be grafted onto the newly installed source.
    pub(in crate::ath10k) async fn install_roc_filter(
        &mut self,
        install: Install,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<RetiredSubscriptions, Error> {
        let subscriptions = self.management_subscriptions.clone().ok_or(Error::Failed)?;
        self.close_roc_capture()?;
        let deadline = narf_time::Deadline::after_ms(1500);
        let mut idle = false;
        for _ in 0..4096 {
            validate()?;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = checked_policy(
                async { self.htt.poll().await.map_err(Error::from) },
                validate,
            )
            .await?;
            if matches!(event, htt::Event::Idle) {
                idle = true;
                break;
            }
            let event = self.station_event(event)?;
            // No new RF traffic or key reply is generated by registration.
            // Preserve ordinary DATA for its usual current owner after unlock.
            if !matches!(event, htt::Event::Progress | htt::Event::Tx(_)) {
                self.queue(event)?;
            }
            narf_scheduler::yield_now().await;
        }
        if !idle {
            return Err(Error::Exhausted);
        }
        validate()?;
        // No suspension/capture occurs between opening the new epoch and
        // swapping metadata. Return old source references for post-unlock
        // retirement, including when a pruned sink has a custom destructor.
        self.open_roc_capture()?;
        subscriptions.commit(install)
    }
    pub(in crate::ath10k::wmi_runtime) fn capture_roc_management(
        &mut self,
        event: &htt::Event,
    ) -> Result<(), Error> {
        let Some(w) = self.roc.as_ref().filter(|w| {
            !self.failed
                && w.started
                && w.foreign
                && !w.terminal
                && !w.stop_sent
                && w.owner.emission.current()
        }) else {
            return Ok(());
        };
        let Some(generation) = w.capture_epoch else {
            return Ok(());
        };
        let Some(deadline) = w.response_deadline().filter(|d| !d.expired()) else {
            return Ok(());
        };
        let htt::Event::Wmi(bytes) = event else {
            return Ok(());
        };
        if wire::word(bytes, 0)? & 0xffffff != self.wire.management_event {
            return Ok(());
        }
        let native = self.wire.management(&bytes[4..], self.features)?;
        let frame = &native.frame;
        let own = self.vdev_address(w.vdev)?;
        // A P2P_DEVICE in Listen receives broadcast/wildcard Probe Requests
        // (`ieee80211_rx_h_mgmt` for P2P_DEVICE, delivered to the registered
        // socket); every other copy is a directed Public Action.
        let probe = self.p2p_device_vdev() == Some(w.vdev)
            && frame.first() == Some(&0x40)
            && frame.len() >= 24
            && (frame[4..10] == own || frame[4..10] == [255; 6]);
        if native.status & !0x40 != 0
            || wire::channel_to_frequency(native.channel) != Some(w.receipt.frequency)
            || !(if probe { 24 } else { 26 }..=2304).contains(&frame.len())
            || !(probe || frame[0] == 0xd0)
            || frame[1] & 0xc7 != 0
            || frame[22] & 15 != 0
            || frame[10..16] == [0; 6]
            || frame[10] & 1 != 0
            || frame[10..16] == own
            // No RECEIVE_MULTICAST/monitor-vdev capability is advertised by
            // these profiles. Default registration is directed RX only.
            || !probe && frame[4..10] != own
            || !probe && frame[24] != 4
        {
            return Ok(());
        }
        let frame_type = u16::from(frame[0]);
        let Some(subscriptions) = &self.management_subscriptions else {
            return Ok(());
        };
        if subscriptions.epoch.load(Ordering::Acquire) != generation {
            return Ok(());
        }
        let snapshot = subscriptions.state.lock().clone();
        let Some(source) = snapshot
            .filters
            .iter()
            .find(|f| {
                f.frame_type == frame_type
                    && f.emission.current()
                    && frame[24..].starts_with(&f.prefix)
            })
            .cloned()
        else {
            return Ok(());
        };
        if self.management_received.len() == 16 {
            return Ok(());
        }
        self.management_received
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        self.management_received.push_back(Captured {
            policy: CapturePolicy {
                plan: w.plan.clone(),
                caps: w.caps.clone(),
                deadline,
            },
            frequency: w.receipt.frequency,
            frame: native.frame,
            source,
            origin: w.owner.emission.clone(),
            epoch: subscriptions.epoch.clone(),
            generation,
            io: self.htt.wmi.htc.transport.current_sources(),
        });
        Ok(())
    }
}
