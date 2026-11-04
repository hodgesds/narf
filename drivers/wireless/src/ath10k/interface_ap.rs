// SPDX-License-Identifier: GPL-2.0-or-later
//! Original-source AP frontend. Dynamic socket/interface work stays outside
//! Radio; the native transition sees only fixed guards and original policy.
use super::*;
use core::{num::NonZeroU64, task::Waker};
use narf_wireless::ap_control::{ApControlAuthority, ApEmissionAuthority, ApEventAuthority};
use wmi_runtime::ap::{Event, Policy as ApPolicy};

pub(super) struct WakeOwner {
    pub(super) signal: IrqSafeSpinLock<Option<Arc<super::super::irq::Signal>>>,
}
impl alloc::task::Wake for WakeOwner {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let signal = self.signal.lock().clone();
        if let Some(signal) = signal {
            signal.raise();
        }
    }
}
struct Registration {
    event: ApEventAuthority,
    frame_type: u16,
    prefix: Vec<u8>,
}
pub(super) struct Host {
    pub(super) wake: Arc<WakeOwner>,
    registrations: IrqSafeSpinLock<Vec<Arc<Registration>>>,
    control: IrqSafeSpinLock<Option<ApEventAuthority>>,
    #[cfg(any(test, feature = "kernel-test"))]
    database: IrqSafeSpinLock<Option<Arc<narf_wireless::reg::db::Database>>>,
}
impl Host {
    pub(super) fn new() -> Self {
        Self {
            wake: Arc::new(WakeOwner {
                signal: IrqSafeSpinLock::new(None),
            }),
            registrations: IrqSafeSpinLock::new(Vec::new()),
            control: IrqSafeSpinLock::new(None),
            #[cfg(any(test, feature = "kernel-test"))]
            database: IrqSafeSpinLock::new(None),
        }
    }
    fn policy(&self) -> Result<ApPolicy, Error> {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(database) = self.database.lock().clone() {
            return ApPolicy::scoped(database);
        }
        ApPolicy::installed()
    }
}
pub(super) fn ethernet(bytes: &[u8]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[..6] != [0; 6]
        && bytes[6..12] != [0; 6]
        && bytes[6] & 1 == 0
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && u16::from_be_bytes([bytes[12], bytes[13]]) != narf_wireless::ETH_P_PAE
}
pub(super) fn errno(error: WirelessError) -> i32 {
    match error {
        WirelessError::Denied => 1,
        WirelessError::Busy => 16,
        WirelessError::InvalidArgs => 22,
        WirelessError::NotSupported => 95,
        WirelessError::Timeout => 110,
        WirelessError::HardwareError => 5,
    }
}
pub(in crate::ath10k) enum Operation {
    Start(
        Box<narf_wireless::ApConfig>,
        Box<narf_wireless::ApStartSettings>,
    ),
    Stop,
    Beacon(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>),
    Add(narf_wireless::StationConfig),
    Set(narf_wireless::StationConfig),
    Delete(Option<[u8; 6]>),
    Key(narf_wireless::OwnedKey),
    DeleteKey(u8, bool, Option<[u8; 6]>),
    DefaultKey(u8, (bool, bool, bool, bool)),
    Control(narf_wireless::ControlPortTxRequest),
    Management(narf_wireless::MgmtTxRequest),
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> Device<T> {
    pub(in crate::ath10k) fn ap_mode(&self) -> u32 {
        u32::from(self.mode.load(Ordering::Acquire))
    }
    pub(in crate::ath10k) fn ap_generation(&self) -> Option<NonZeroU64> {
        if !self.ap_capable
            || self.closed.load(Ordering::Acquire)
            || self.retired.load(Ordering::Acquire)
        {
            return None;
        }
        NonZeroU64::new(self.mode_generation.load(Ordering::Acquire))
            .filter(|v| v.get() != u64::MAX)
    }
    /// The nl80211 iftype of an AP-capable netdev: 9 for the GO netdev
    /// (AP mode for its whole life), else the managed netdev's mode.
    pub(in crate::ath10k) fn ap_iftype(&self) -> u32 {
        if self.go {
            9
        } else {
            self.ap_mode()
        }
    }
    /// `SET_INTERFACE`: the GO netdev keeps iftype 9 (a change would be
    /// `ieee80211_if_change_type`, not offered); the managed netdev switches
    /// between station and AP.
    pub(in crate::ath10k) fn ap_set_iftype(&self, mode: u32) -> Result<(), WirelessError> {
        if self.go {
            return if mode == 9 {
                Ok(())
            } else {
                Err(WirelessError::NotSupported)
            };
        }
        self.ap_set_mode(mode)
    }
    pub(in crate::ath10k) fn ap_set_mode(&self, mode: u32) -> Result<(), WirelessError> {
        if !matches!(mode, 2 | 3) || mode == 3 && !self.ap_capable {
            return Err(WirelessError::NotSupported);
        }
        let _lease = self.radio_control.try_reserve()?;
        if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
            return Err(WirelessError::HardwareError);
        }
        if self.up.load(Ordering::Acquire)
            || narf_net::iface::lookup(&self.name).is_some_and(|s| s.link_up)
        {
            return Err(WirelessError::Busy);
        }
        let mut radio = self.radio.try_lock().ok_or(WirelessError::Busy)?;
        // The AP replaces the managed station vdev and is not yet
        // sibling-aware: no AP beside a P2P client vdev or a GO (the radio
        // has one AP session). A running GO is its own netdev's and does
        // not hold the managed netdev's role.
        if radio.ap_exists() && !radio.ap_is_go()
            || radio.scan_in_progress()
            || radio.roc_active()
            || radio.prepared_peer().is_some()
            || (mode == 3 && (radio.p2p_client_vdev().is_some() || radio.ap_is_go()))
        {
            return Err(WirelessError::Busy);
        }
        radio
            .htt
            .wmi
            .htc
            .transport
            .check_current()
            .map_err(|_| WirelessError::Denied)?;
        let _publication = self.publication.lock();
        if self.mode.load(Ordering::Acquire) == mode as u8 {
            return Ok(());
        }
        let next = self
            .mode_generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(WirelessError::Denied)?;
        self.mode_generation.store(next, Ordering::Release);
        self.mode.store(mode as u8, Ordering::Release);
        self.management_subscriptions.invalidate();
        // Role changes erase software staging; no old role's source is
        // re-captured as a later AP key/default request.
        radio.ap_retire_staging();
        let retired = core::mem::take(&mut *self.ap_host.registrations.lock());
        if let Some(mut state) = self.state.try_lock() {
            state.clear();
        }
        drop(_publication);
        drop(radio);
        drop(retired);
        Ok(())
    }
    fn ap_role(&self, emission: &ApEmissionAuthority) -> Result<(), Error>
    where
        Self: WirelessNetIface,
    {
        if self.closed.load(Ordering::Acquire)
            || self.retired.load(Ordering::Acquire)
            || self.mode.load(Ordering::Acquire) != 3
            || !self.ap_generation().is_some_and(|generation| {
                // The authority binds the nl80211 iftype: 9 on the GO.
                emission.matches_role(self, if self.go { 9 } else { 3 }, generation)
            })
        {
            return Err(Error::Failed);
        }
        Ok(())
    }
    fn ap_authority(
        &self,
        authority: &ApControlAuthority,
    ) -> Result<ApEmissionAuthority, WirelessError>
    where
        Self: WirelessNetIface,
    {
        authority.check_for(self)?;
        if !authority.has_reservation()
            || self.mode.load(Ordering::Acquire) != 3
            || !self.ap_capable
        {
            return Err(WirelessError::Denied);
        }
        let emission = authority.native_emission_for(self)?;
        // One physical pump owner, never a historical per-request ACK waker.
        if !emission.watch(&Waker::from(self.ap_host.wake.clone())) {
            return Err(WirelessError::Denied);
        }
        self.ap_role(&emission).map_err(error)?;
        Ok(emission)
    }
    pub(in crate::ath10k) async fn ap_control(
        &self,
        authority: &ApControlAuthority,
        operation: Operation,
    ) -> Result<bool, WirelessError>
    where
        Self: WirelessNetIface,
    {
        let emission = self.ap_authority(authority)?;
        let starting = matches!(&operation, Operation::Start(..));
        let control_event = if starting {
            Some(authority.event_authority()?)
        } else {
            None
        };
        let stopping = matches!(&operation, Operation::Stop);
        // Retain the exact database Arc before borrowing native State. A
        // replaced equal-valued signed policy cannot revive this operation.
        let start_policy = if starting {
            Some(self.ap_host.policy().map_err(error)?)
        } else {
            None
        };
        let mut radio = self.radio.lock().await;
        // One AP session: the GO's belongs to the GO netdev, the managed AP
        // to the home netdev; neither controls the other's.
        if radio.ap_exists() && radio.ap_is_go() != self.go {
            return Err(WirelessError::Busy);
        }
        if !radio.ap_exists()
            && matches!(
                &operation,
                Operation::Key(_) | Operation::DeleteKey(..) | Operation::DefaultKey(..)
            )
        {
            let result = match operation {
                Operation::Key(key) => radio.ap_stage_key(key, emission.clone(), self.go),
                Operation::DeleteKey(index, pairwise, peer) => {
                    radio.ap_stage_delete(index, pairwise, peer, self.go)
                }
                Operation::DefaultKey(index, flags) => {
                    radio.ap_stage_default(index, flags, emission.clone(), self.go)
                }
                _ => unreachable!(),
            };
            let source = radio.htt.wmi.htc.transport.current_sources();
            drop(radio);
            authority.check_for(self)?;
            authority.require_up()?;
            let final_result =
                super::super::firmware_source::invoke(source.as_ref(), || self.ap_role(&emission));
            if !matches!(final_result, Ok(Ok(()))) {
                self.close();
                return Err(WirelessError::Denied);
            }
            return result.map(|()| true).map_err(error);
        }
        let policy = start_policy
            .or_else(|| radio.ap_policy())
            .ok_or(WirelessError::InvalidArgs)?;
        let source = radio.htt.wmi.htc.transport.current_sources();
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let current = || {
            self.ap_role(&emission)?;
            if !stopping && !policy.current() {
                return Err(Error::Unsupported);
            }
            Ok(())
        };
        current().map_err(error)?;
        let mut terminal = None;
        let result = match operation {
            Operation::Start(config, settings) if self.go => radio
                .go_start(
                    self.mac,
                    *config,
                    *settings,
                    emission.clone(),
                    policy.clone(),
                    &current,
                )
                .await
                .map(|()| true),
            Operation::Start(config, settings) => radio
                .ap_start(
                    *config,
                    *settings,
                    emission.clone(),
                    policy.clone(),
                    &current,
                )
                .await
                .map(|()| true),
            Operation::Stop => radio.ap_cleanup(&current).await.map(|()| true),
            Operation::Beacon(head, tail, probe) => radio
                .ap_set_beacon(
                    (head, tail, probe),
                    emission.clone(),
                    policy.domain(),
                    &current,
                )
                .await
                .map(|()| true),
            Operation::Add(station) => radio
                .ap_add_station(station, emission.clone(), policy.domain(), &current)
                .await
                .map(|()| true),
            Operation::Set(station) => radio
                .ap_set_station(station, emission.clone(), policy.domain(), &current)
                .await
                .map(|()| true),
            Operation::Delete(peer) => radio
                .ap_del_station(peer, emission.clone(), policy.domain(), &current)
                .await
                .map(|()| true),
            Operation::Key(key) => radio
                .ap_add_key(key, emission.clone(), policy.domain(), &current)
                .await
                .map(|()| true),
            Operation::DeleteKey(index, pairwise, peer) => radio
                .ap_del_key(
                    index,
                    pairwise,
                    peer,
                    emission.clone(),
                    policy.domain(),
                    &current,
                )
                .await
                .map(|()| true),
            Operation::DefaultKey(index, flags) => radio
                .ap_default_key(index, flags, emission.clone(), policy.domain())
                .map(|()| true),
            Operation::Control(request) => radio
                .ap_tx_control(request, emission.clone(), policy.domain(), &current)
                .await
                .map(|(ack, capture)| {
                    terminal = Some(capture);
                    ack
                }),
            Operation::Management(request) => radio
                .ap_tx_management(request, emission.clone(), policy.domain(), &current)
                .await
                .map(|(ack, capture)| {
                    terminal = Some(capture);
                    ack
                }),
        };
        if result.is_ok() && !stopping && terminal.is_none() {
            terminal = Some(radio.ap_capture().map_err(error)?);
        }
        if result.is_err() {
            // Pure rejected input must not tear down an otherwise healthy AP.
            // Any ambiguous staged native work stays busy and is cleaned by
            // the physical worker after this borrowed waiter disappears.
            if !radio.ap_abandoned() && current().is_ok() {
                attempt.armed = false;
            }
            return result.map_err(error);
        }
        drop(radio);
        // These can run arbitrary source/interface callbacks. The original
        // fixed native/copy/policy/role proof is checked only AFTER them.
        authority.check_for(self)?;
        authority.require_up()?;
        super::super::firmware_source::invoke(source.as_ref(), || {
            current()?;
            if let Some(capture) = &terminal {
                capture.current(policy.domain())?;
            }
            let _publication = self.publication.lock();
            current()?;
            if starting {
                self.publish_link(Some(self.mac));
            }
            if stopping {
                self.publish_link(None);
            }
            Ok::<_, Error>(())
        })
        .map_err(|_| WirelessError::Denied)?
        .map_err(error)?;
        let retired = if starting {
            core::mem::replace(&mut *self.ap_host.control.lock(), control_event)
        } else if stopping {
            self.ap_host.control.lock().take()
        } else {
            None
        };
        drop(retired);
        attempt.armed = false;
        self.kick();
        result.map_err(error)
    }
    /// Terminal AP cleanup creates a new control generation on this same
    /// still-current physical device. Original abandoned requests/copies
    /// cannot become a replacement BSS merely because cleanup finished.
    pub(super) fn ap_cleanup_complete(&self) -> Result<(), Error> {
        let _publication = self.publication.lock();
        if self.retired.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        let next = self
            .mode_generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .filter(|generation| *generation != u64::MAX)
            .ok_or(Error::Exhausted)?;
        self.mode_generation.store(next, Ordering::Release);
        self.closed.store(false, Ordering::Release);
        Ok(())
    }
    pub(super) fn ap_retire_metadata(&self) {
        let registrations = core::mem::take(&mut *self.ap_host.registrations.lock());
        let control = self.ap_host.control.lock().take();
        drop(registrations);
        drop(control);
    }
    pub(in crate::ath10k) async fn ap_register(
        &self,
        authority: &ApControlAuthority,
        frame_type: u16,
        prefix: Vec<u8>,
    ) -> Result<(), WirelessError>
    where
        Self: WirelessNetIface,
    {
        authority.check_for(self)?;
        if !authority.has_reservation()
            || !self.ap_capable
            || self.mode.load(Ordering::Acquire) != 3
            || !matches!(frame_type, 0 | 0x20 | 0x40 | 0xb0 | 0xa0 | 0xc0 | 0xd0)
            || prefix.len() > 256
        {
            return Err(WirelessError::NotSupported);
        }
        let event = authority.event_authority()?;
        let mut registrations = self.ap_host.registrations.lock().clone();
        // Registration may precede UP. No receive/filter/RF authority follows
        // from this metadata; delivery captures the exact original source.
        registrations.retain(|registration| registration.event.registration_current().is_ok());
        if registrations.len() >= 16 {
            return Err(WirelessError::Busy);
        }
        registrations
            .try_reserve(1)
            .map_err(|_| WirelessError::HardwareError)?;
        registrations.push(Arc::new(Registration {
            event,
            frame_type,
            prefix,
        }));
        authority.check_for(self)?;
        let retired = core::mem::replace(&mut *self.ap_host.registrations.lock(), registrations);
        drop(retired);
        Ok(())
    }
    pub(in crate::ath10k) async fn ap_sequence(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<narf_wireless::KeySequence, i32>
    where
        Self: WirelessNetIface,
    {
        let emission = self.ap_authority(authority).map_err(|_| 1)?;
        let radio = self.radio.lock().await;
        if !self.owns_ap(&radio) {
            return Err(2);
        }
        let policy = radio.ap_policy().ok_or(2)?;
        let (seq, capture) = radio
            .ap_key_sequence(index, pairwise, peer, policy.domain())
            .map_err(|_| 2)?;
        let source = radio.htt.wmi.htc.transport.current_sources();
        drop(radio);
        authority.check_for(self).map_err(|_| 1)?;
        authority.require_up().map_err(|_| 1)?;
        super::super::firmware_source::invoke(source.as_ref(), || {
            self.ap_role(&emission)?;
            capture.current(policy.domain())?;
            Ok::<_, Error>(narf_wireless::KeySequence {
                cipher: narf_wireless::CIPHER_SUITE_CCMP,
                seq,
            })
        })
        .map_err(|_| 1)?
        .map_err(|_| 1)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn ap_database_for_test(
        &self,
        database: Arc<narf_wireless::reg::db::Database>,
    ) {
        *self.ap_host.database.lock() = Some(database);
    }
}
impl<T: Hif + HostMemory + HttMemory + Send + 'static> Device<T> {
    /// Real native RX and DMA progress under the retained owner. Public event
    /// callbacks run later, after both Radio and packet-state locks are gone.
    pub(super) fn ap_drain(&self) -> bool {
        if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
            return false;
        }
        let result = (|| {
            let mut radio = self
                .radio
                .try_lock()
                .ok_or(Error::Htt(super::super::htt_runtime::Error::Busy))?;
            // The other netdev's AP session (GO vs managed) is not drained.
            if !self.owns_ap(&radio) {
                return Ok(None);
            }
            if radio.ap_abandoned() || radio.ap_failed() {
                return Err(Error::Failed);
            }
            // A staged or still-starting session has no live native rings:
            // its WMI completions are consumed by the START/STOP path under
            // the Radio lock. Polling it here would read a transport that
            // is not yet the AP's and close a healthy netdev.
            if !radio.ap_running() {
                return Ok(None);
            }
            let policy = radio.ap_policy().ok_or(Error::Failed)?;
            let mut state = self
                .state
                .try_lock()
                .ok_or(Error::Htt(super::super::htt_runtime::Error::Busy))?;
            let _publication = self.publication.lock();
            if self.closed.load(Ordering::Acquire) || self.mode.load(Ordering::Acquire) != 3 {
                return Err(Error::Failed);
            }
            let received = radio.ap_poll_now(policy.domain())?;
            let source = radio.htt.wmi.htc.transport.current_sources();
            if state.pending.is_none() {
                for _ in 0..16 {
                    let Ok(Some(frame)) = state.tx.try_recv() else {
                        break;
                    };
                    if ethernet(frame.payload())
                        && frame.tx_meta().csum_l4.is_none()
                        && frame.tx_meta().tso_mss.is_none()
                        && frame.tx_meta().vlan_tag.is_none()
                    {
                        state.pending_ap = Some(radio.ap_data_capture()?);
                        state.pending = Some(frame);
                        break;
                    }
                }
            }
            if let (Some(frame), Some(original)) = (&state.pending, &state.pending_ap) {
                if original.current(policy.domain()).is_err()
                    || radio.ap_begin_ethernet(policy.domain(), frame.payload(), original)?
                {
                    state.pending = None;
                    state.pending_ap = None;
                }
            }
            Ok(Some((received, policy, source)))
        })();
        let (received, policy, source) = match result {
            Ok(Some(batch)) => batch,
            Ok(None) | Err(Error::Htt(super::super::htt_runtime::Error::Busy)) => return false,
            Err(_) => {
                self.close();
                return false;
            }
        };
        let progressed = !received.is_empty();
        let registrations = self.ap_host.registrations.lock().clone();
        let control = self.ap_host.control.lock().clone();
        for received in received {
            let fixed = || {
                if self.closed.load(Ordering::Acquire)
                    || self.retired.load(Ordering::Acquire)
                    || self.mode.load(Ordering::Acquire) != 3
                {
                    return Err(Error::Failed);
                }
                received.capture.current(policy.domain())
            };
            match received.event {
                Event::Data(mut bytes) => {
                    if let Ok(memory) =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                    {
                        let mut frame = Frame::new(memory, bytes.len() as u32);
                        frame.payload_mut().copy_from_slice(&bytes);
                        #[cfg(any(test, feature = "kernel-test"))]
                        self.receive_point_for_test(ReceivePoint::AfterFrameAllocation);
                        let _ = super::super::firmware_source::invoke(source.as_ref(), || {
                            fixed()?;
                            if let Some(mut state) = self.state.try_lock() {
                                let _ = state.rx.try_send(frame);
                            }
                            Ok::<_, Error>(())
                        });
                    }
                    #[cfg(any(test, feature = "kernel-test"))]
                    self.receive_point_for_test(ReceivePoint::BeforeCallbackAdmission);
                    let _ = super::super::firmware_source::invoke(source.as_ref(), || {
                        fixed()?;
                        narf_net::iface::on_rx_frame_from(&self.name, &mut bytes);
                        Ok::<_, Error>(())
                    });
                }
                Event::Management(frame) => {
                    for registration in &registrations {
                        if u16::from_le_bytes([frame[0], frame[1]]) & 0xfc
                            != registration.frame_type
                            || !frame[24..].starts_with(&registration.prefix)
                        {
                            continue;
                        }
                        let prepared = registration.event.prepare_management_received(
                            u32::from(received.capture.permission.frequency),
                            None,
                            &frame,
                        );
                        if let Ok(prepared) = prepared {
                            let _ = super::super::firmware_source::invoke(source.as_ref(), || {
                                fixed()?;
                                prepared.deliver().map_err(|_| Error::Failed)
                            });
                        }
                    }
                }
                Event::Control {
                    peer,
                    ethertype,
                    pdu,
                    unencrypted,
                } => {
                    if let Some(control) = &control {
                        let prepared =
                            control.prepare_control_received(peer, ethertype, &pdu, unencrypted);
                        if let Ok(prepared) = prepared {
                            let _ = super::super::firmware_source::invoke(source.as_ref(), || {
                                fixed()?;
                                prepared.deliver().map_err(|_| Error::Failed)
                            });
                        }
                    }
                }
            }
        }
        progressed
    }
}
