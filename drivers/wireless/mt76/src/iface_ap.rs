//! Concrete AP control publication. The shared request grant, native BSS
//! receipt and completed net-interface identity are independent owners.
use super::*;
use crate::mt7921::firmware_transport::{boot_ap, Error};
use alloc::sync::Weak;
use core::num::NonZeroU64;
use narf_wireless::ap_control::{ApControlAuthority, ApEventAuthority, ApInterfaceIdentity};

#[derive(Clone, Debug)]
struct Registration {
    frame_type: u16,
    prefix: Vec<u8>,
    source: ApEventAuthority,
}
#[derive(Debug, Default)]
pub(super) struct Host {
    identity: Option<ApInterfaceIdentity>,
    metadata: Option<narf_net::iface::NetIfaceSnapshot>,
    control: Option<(narf_wireless::ControlPort, ApEventAuthority)>,
    registrations: Vec<Registration>,
}

impl Mt76Iface {
    pub(super) fn reset_ap_registrations(&self) {
        self.ap_host.lock().registrations.clear();
    }
    fn active_weak(&self) -> Result<Weak<Self>, WirelessError> {
        ACTIVE
            .lock()
            .as_ref()
            .filter(|active| core::ptr::eq(Arc::as_ptr(active), self))
            .map(Arc::downgrade)
            .ok_or(WirelessError::Denied)
    }
    pub(crate) fn ap_request_current(
        &self,
        authority: &ApControlAuthority,
    ) -> Result<(), WirelessError> {
        self.active_weak()?;
        authority.check_for(self)?;
        if self.current_iftype() != 3 || self.sleeping.load(Ordering::Acquire) {
            return Err(WirelessError::Denied);
        }
        Ok(())
    }
    pub(crate) fn ap_cleanup_current(&self) -> Result<(), WirelessError> {
        self.active_weak().map(|_| ())
    }
    pub(crate) fn ap_work_started(&self) {
        self.ap_owned.store(true, Ordering::Release);
    }
    pub(crate) fn commit_ap_started(
        &self,
        authority: &ApControlAuthority,
        identity: ApInterfaceIdentity,
        epoch: u64,
        control: narf_wireless::ControlPort,
    ) -> Result<(), WirelessError> {
        self.ap_request_current(authority)?;
        identity.check_for(self)?;
        if epoch == 0 {
            return Err(WirelessError::HardwareError);
        }
        let source = if control.enabled && control.over_nl80211 {
            Some((control, authority.event_authority()?))
        } else {
            None
        };
        let snapshot = identity.metadata_snapshot()?;
        self.active_weak()?;
        self.retire_ap_rings();
        self.open_ap_rings(epoch);
        {
            let mut host = self.ap_host.lock();
            host.identity = Some(identity);
            host.metadata = Some(snapshot.clone());
            host.control = source;
        }
        self.ap_owned.store(true, Ordering::Release);
        self.ap_started.store(true, Ordering::Release);
        if !narf_net::iface::set_link_metadata_for(&snapshot, true, None, None) {
            self.close_ap_host();
            return Err(WirelessError::Denied);
        }
        self.ap_request_current(authority)?;
        Ok(())
    }
    pub(crate) fn commit_ap_epoch(
        &self,
        authority: &ApControlAuthority,
        epoch: u64,
    ) -> Result<(), WirelessError> {
        self.ap_request_current(authority)?;
        if !self.ap_host_current() || epoch == 0 {
            return Err(WirelessError::Denied);
        }
        self.retire_ap_rings();
        self.open_ap_rings(epoch);
        Ok(())
    }
    fn open_ap_rings(&self, epoch: u64) {
        let (tx, tx_cons) = narf_ipc::channel::<Frame, TX_RING_N>();
        *self.tx_ring.lock() = Some(tx);
        *self.tx_cons.lock() = Some(tx_cons);
        self.ensure_receive_epoch(epoch);
    }
    fn retire_ap_rings(&self) {
        self.retire_receive_ipc();
        *self.tx_ring.lock() = None;
        *self.tx_cons.lock() = None;
        *self.pending_tx.lock() = None;
    }
    pub(super) fn close_ap_host(&self) {
        self.ap_started.store(false, Ordering::Release);
        let metadata = {
            let mut host = self.ap_host.lock();
            host.identity = None;
            host.control = None;
            host.metadata.take()
        };
        self.retire_ap_rings();
        // DOWN or namespace transfer invalidates the completed UP identity.
        // The original immutable registration identity may only withdraw
        // carrier, and cannot clear a replacement registration's carrier.
        if let Some(snapshot) = metadata {
            narf_net::iface::withdraw_link_metadata_for(&snapshot);
        }
    }
    /// Called only after the actual native owner has been reset/retired.
    pub(crate) fn commit_ap_stopped(&self) {
        self.close_ap_host();
        self.ap_owned.store(false, Ordering::Release);
    }
    fn ap_host_current(&self) -> bool {
        if self.current_iftype() != 3
            || !self.ap_started.load(Ordering::Acquire)
            || self.sleeping.load(Ordering::Acquire)
            || self.active_weak().is_err()
        {
            return false;
        }
        let identity = self.ap_host.lock().identity.clone();
        identity.is_some_and(|identity| identity.check_for(self).is_ok())
    }
    pub(super) fn ap_link_up(&self) -> bool {
        self.ap_host_current()
    }
    pub(super) async fn poll_ap(&self) -> Result<(), WirelessError> {
        if self.ap_owned.load(Ordering::Acquire) && !self.ap_host_current() {
            self.close_ap_host();
            let Some(_control) = self.control.try_lock() else {
                return Ok(());
            };
            boot_ap::cleanup(self.active_weak()?)
                .await
                .map_err(map_error)?;
            return Ok(());
        }
        self.drain_ap_network().map(|_| ())
    }
    pub(super) fn drain_ap_network(&self) -> Result<bool, WirelessError> {
        if !self.ap_host_current() {
            if self.ap_started.load(Ordering::Acquire) {
                self.close_ap_host();
            }
            return Ok(false);
        }
        let result = {
            let mut pending = self.pending_tx.lock();
            if pending.is_none() {
                *pending = self.next_ap_tx();
            }
            let result = boot_ap::step(pending.as_ref().map(Frame::payload));
            if result.as_ref().is_ok_and(|(step, _)| step.transmitted) {
                *pending = None;
            }
            result
        };
        let (step, events) = match result {
            Ok(step) => step,
            Err(Error::Busy) => return Ok(false),
            Err(error) => {
                self.close_ap_host();
                return Err(map_error(error));
            }
        };
        let progress = step.transmitted || !step.received.is_empty() || !events.is_empty();
        deliver_received_batch(
            step,
            |epoch| self.ap_receive_current(epoch),
            |data| narf_net::iface::on_rx_frame_from(&self.name, data),
            |data, epoch| {
                if let Ok(mut buffer) =
                    narf_io::alloc_coherent(data.len(), narf_lib::id::DomainId::DRIVER_0)
                {
                    buffer.as_mut_slice()[..data.len()].copy_from_slice(&data);
                    let frame = Frame::new(buffer, data.len() as u32);
                    boot_ap::publish(epoch, || {
                        if self.ap_host_current()
                            && self.receive_epoch.load(Ordering::Acquire) == epoch
                        {
                            if let Some(producer) = self.rx_prod.lock().as_mut() {
                                let _ = producer.try_send(frame);
                            }
                        }
                    })
                    .map_err(map_error)?;
                }
                Ok(())
            },
        )?;
        for event in events {
            self.deliver_ap_event(event)?;
        }
        Ok(progress)
    }
    fn next_ap_tx(&self) -> Option<Frame> {
        let mut consumer = self.tx_cons.lock();
        let consumer = consumer.as_mut()?;
        for _ in 0..16 {
            let frame = consumer.try_recv().ok().flatten()?;
            if self.ap_transmit_admitted(frame.payload()) {
                return Some(frame);
            }
        }
        None
    }
    pub(super) fn ap_transmit_admitted(&self, frame: &[u8]) -> bool {
        if !(14..=1514).contains(&frame.len()) || frame[6] & 1 != 0 || frame[6..12] == [0; 6] {
            return false;
        }
        let proto = u16::from_be_bytes([frame[12], frame[13]]);
        let no_preauth = self
            .ap_host
            .lock()
            .control
            .as_ref()
            .is_some_and(|(control, _)| control.no_preauth);
        proto >= 0x600 && proto != 0x888e && (proto != 0x88c7 || no_preauth)
    }
    fn ap_receive_current(&self, epoch: u64) -> Result<bool, WirelessError> {
        if !self.ap_host_current()
            || epoch == 0
            || epoch != self.receive_epoch.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        boot_ap::current(epoch).map_err(map_error)
    }
    fn deliver_ap_event(
        &self,
        event: crate::mt7921::firmware_transport::ApRxEvent,
    ) -> Result<(), WirelessError> {
        self.deliver_ap_event_with(event, |epoch| self.ap_receive_current(epoch))
    }
    pub(crate) fn deliver_ap_event_with(
        &self,
        event: crate::mt7921::firmware_transport::ApRxEvent,
        mut current: impl FnMut(u64) -> Result<bool, WirelessError>,
    ) -> Result<(), WirelessError> {
        use crate::mt7921::firmware_transport::ApEvent;
        if !self.ap_host_current() || !current(event.epoch)? {
            return Ok(());
        }
        match event.event {
            ApEvent::Management {
                frequency_mhz,
                signal_dbm,
                frame,
            } => {
                if frame.len() < 24 {
                    return Ok(());
                }
                let frame_type = u16::from_le_bytes([frame[0], frame[1]]) & 0x00fc;
                let sources: Vec<_> = self
                    .ap_host
                    .lock()
                    .registrations
                    .iter()
                    .filter(|r| r.frame_type == frame_type && frame[24..].starts_with(&r.prefix))
                    .map(|r| r.source.clone())
                    .collect();
                for source in sources {
                    if !self.ap_host_current() || !current(event.epoch)? {
                        break;
                    }
                    if source.check_for(self).is_ok() {
                        let _ = source.management_received(frequency_mhz, signal_dbm, &frame);
                    }
                }
            }
            ApEvent::Control {
                peer,
                ethertype,
                pdu,
                unencrypted,
            } => {
                let control = self.ap_host.lock().control.clone();
                if let Some((control, source)) = control {
                    if control.enabled
                        && control.over_nl80211
                        && (ethertype == control.ethertype
                            || ethertype == 0x88c7 && !control.no_preauth)
                        && self.ap_host_current()
                        && current(event.epoch)?
                        && source.check_for(self).is_ok()
                    {
                        let _ = source.control_received(peer, ethertype, &pdu, unencrypted);
                    }
                }
            }
        }
        Ok(())
    }
    async fn ap_request(
        &self,
        authority: &ApControlAuthority,
        request: boot_ap::Request,
    ) -> Result<boot_ap::Reply, WirelessError> {
        let _control = self.control.lock().await;
        self.ap_request_current(authority)?;
        boot_ap::request(self.active_weak()?, Arc::new(authority.clone()), request)
            .await
            .map_err(map_error)
    }
    pub(super) async fn ap_start(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), WirelessError> {
        self.ap_request(
            authority,
            boot_ap::Request::Start(Box::new((config, settings))),
        )
        .await
        .map(|_| ())
    }
    pub(super) async fn ap_stop(
        &self,
        authority: &ApControlAuthority,
    ) -> Result<(), WirelessError> {
        self.ap_request(authority, boot_ap::Request::Stop)
            .await
            .map(|_| ())
    }
    pub(super) async fn ap_beacon(
        &self,
        authority: &ApControlAuthority,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe: Option<Vec<u8>>,
    ) -> Result<(), WirelessError> {
        self.ap_request(authority, boot_ap::Request::Beacon(head, tail, probe))
            .await
            .map(|_| ())
    }
    pub(super) async fn ap_add_station(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_request(authority, boot_ap::Request::AddStation(config))
            .await
            .map(|_| ())
    }
    pub(super) async fn ap_set_station(
        &self,
        authority: &ApControlAuthority,
        config: narf_wireless::StationConfig,
    ) -> Result<(), WirelessError> {
        self.ap_request(authority, boot_ap::Request::SetStation(config))
            .await
            .map(|_| ())
    }
    pub(super) async fn ap_del_station(
        &self,
        authority: &ApControlAuthority,
        peer: Option<[u8; 6]>,
    ) -> Result<(), WirelessError> {
        self.ap_request(authority, boot_ap::Request::DelStation(peer))
            .await
            .map(|_| ())
    }
    pub(super) async fn ap_add_key(
        &self,
        authority: &ApControlAuthority,
        key: narf_wireless::OwnedKey,
    ) -> Result<(), i32> {
        self.ap_request(authority, boot_ap::Request::AddKey(key))
            .await
            .map(|_| ())
            .map_err(errno)
    }
    pub(super) async fn ap_del_key(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), i32> {
        self.ap_request(authority, boot_ap::Request::DelKey(index, pairwise, peer))
            .await
            .map(|_| ())
            .map_err(errno)
    }
    pub(super) async fn ap_default_key(
        &self,
        authority: &ApControlAuthority,
        index: u8,
        _unicast: bool,
        multicast: bool,
        management: bool,
        beacon: bool,
    ) -> Result<(), i32> {
        // This profile has GTK only; it cannot select IGTK/BIGTK or a
        // unicast-only default key in place of the per-peer PTK owner.
        // KEY_DEFAULT without DEFAULT_TYPES selects both, as in Linux;
        // the group selection never changes a per-peer key.
        if !multicast || management || beacon {
            return Err(-95);
        }
        self.ap_request(authority, boot_ap::Request::DefaultKey(index))
            .await
            .map(|_| ())
            .map_err(errno)
    }
    pub(super) async fn ap_management(
        &self,
        authority: &ApControlAuthority,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        match self
            .ap_request(authority, boot_ap::Request::Management(request))
            .await?
        {
            boot_ap::Reply::Ack(ack) => Ok(ack),
            boot_ap::Reply::Done => Err(WirelessError::HardwareError),
        }
    }
    pub(super) async fn ap_control_tx(
        &self,
        authority: &ApControlAuthority,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, i32> {
        match self
            .ap_request(authority, boot_ap::Request::Control(request))
            .await
            .map_err(errno)?
        {
            boot_ap::Reply::Ack(ack) => Ok(ack),
            boot_ap::Reply::Done => Err(-5),
        }
    }
    pub(super) async fn ap_register_frame(
        &self,
        authority: &ApControlAuthority,
        frame_type: u16,
        prefix: Vec<u8>,
    ) -> Result<(), WirelessError> {
        let _control = self.control.lock().await;
        self.ap_request_current(authority)?;
        // Only management subtypes the native RX owner actually emits.
        if frame_type & !0x00f0 != 0
            || !matches!(frame_type >> 4, 0 | 2 | 4 | 11 | 10 | 12 | 13)
            || prefix.len() > 256
        {
            return Err(WirelessError::NotSupported);
        }
        let source = authority.event_authority()?;
        // Check before locking: capability invocation/registry lookup never
        // happens under an IRQ-safe host-state lock.
        let previous = self.ap_host.lock().registrations.clone();
        let mut current: Vec<_> = previous
            .into_iter()
            .filter(|r| r.source.registration_current().is_ok())
            .collect();
        let refusal = if current.len() >= 64
            || current
                .iter()
                .any(|r| r.frame_type == frame_type && r.prefix == prefix)
        {
            Some(WirelessError::Busy)
        } else {
            None
        };
        if refusal.is_none() {
            current.push(Registration {
                frame_type,
                prefix,
                source,
            });
        }
        self.ap_host.lock().registrations = current;
        self.ap_request_current(authority)?;
        refusal.map_or(Ok(()), Err)
    }
    pub(super) fn ap_generation(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.ap_generation.load(Ordering::Acquire))
    }
}
fn map_error(error: Error) -> WirelessError {
    match error {
        Error::Bounds => WirelessError::InvalidArgs,
        Error::UnsupportedFirmware => WirelessError::NotSupported,
        Error::Busy => WirelessError::Busy,
        Error::Authority | Error::Cancelled => WirelessError::Denied,
        Error::Timeout => WirelessError::Timeout,
        _ => WirelessError::HardwareError,
    }
}
fn errno(error: WirelessError) -> i32 {
    match error {
        WirelessError::InvalidArgs => -22,
        WirelessError::NotSupported => -95,
        WirelessError::Busy => -16,
        WirelessError::Denied => -1,
        WirelessError::Timeout => -110,
        _ => -5,
    }
}
