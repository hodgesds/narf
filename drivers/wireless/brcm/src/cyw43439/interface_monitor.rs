// SPDX-License-Identifier: GPL-2.0-or-later
//! Original-receiver native monitor lifecycle. Metadata UP is no hardware
//! grant: actual retained source, mode/policy/format/filter/channel receipts
//! and the separate original AF_PACKET token all remain mandatory.
use super::*;
use crate::brcmfmac::{
    ap_scope::Policy,
    monitor::Session,
    monitor_scope::{Capture, Received as RawReceived},
};
use alloc::sync::Weak;

#[derive(Clone)]
struct Selection {
    channel: narf_wireless::monitor::Channel,
    policy: Policy,
    generation: u64,
}
struct Request {
    event: narf_net::iface::OpenStopEvent,
    generation: u64,
}
pub(super) struct Host {
    pub(super) capable: AtomicBool,
    selection: IrqSafeSpinLock<Option<Selection>>,
    request: IrqSafeSpinLock<Option<Arc<Request>>>,
    capture: IrqSafeSpinLock<Option<Capture>>,
    token: IrqSafeSpinLock<Option<narf_net::iface::MonitorRxToken>>,
    signal: IrqSafeSpinLock<Option<Arc<crate::brcmfmac::irq::Signal>>>,
}
impl Host {
    pub(super) fn new() -> Self {
        Self {
            capable: AtomicBool::new(false),
            selection: IrqSafeSpinLock::new(None),
            request: IrqSafeSpinLock::new(None),
            capture: IrqSafeSpinLock::new(None),
            token: IrqSafeSpinLock::new(None),
            signal: IrqSafeSpinLock::new(None),
        }
    }
    fn close_capture(&self) {
        if let Some(capture) = self.capture.lock().take() {
            capture.retire();
        }
        if let Some(token) = self.token.lock().take() {
            narf_net::iface::end_monitor_rx(token);
        }
    }
    pub(super) fn close(&self) {
        self.close_capture();
        self.request.lock().take();
        self.wake();
    }
    pub(super) fn clear_selection(&self) {
        self.close();
        self.selection.lock().take();
    }
    fn wake(&self) {
        if let Some(signal) = self.signal.lock().clone() {
            signal.raise();
        }
    }
    fn clear_request(&self, expected: Option<&Arc<Request>>) {
        let mut request = self.request.lock();
        if request
            .as_ref()
            .zip(expected)
            .is_some_and(|(actual, expected)| Arc::ptr_eq(actual, expected))
        {
            request.take();
        }
    }
}
struct Target<R: Fullmac + 'static>(Weak<Device<R>>);
impl<R: Fullmac + 'static> core::fmt::Debug for Target<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FullmacMonitorTarget")
    }
}
impl<R: Fullmac + 'static> narf_net::iface::OpenStopTarget for Target<R> {
    fn transition(&self, event: narf_net::iface::OpenStopEvent) {
        if let Some(device) = self.0.upgrade() {
            device.monitor_event(event);
        }
    }
}
impl<R: Fullmac + 'static> Device<R> {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) async fn monitor_fixture_setup(
        self: &Arc<Self>,
        database: Arc<narf_wireless::reg::db::Database>,
    ) -> Result<(), Error> {
        self.ap_fixture_setup(database);
        self.lifecycle.ap.capable.store(false, Ordering::Release);
        let capable = {
            let mut state = self.state.lock().await;
            match crate::brcmfmac::monitor_native::discovery(&mut state.station.runtime).await {
                Ok(capable) => capable,
                Err(Error::Unsupported | Error::Malformed | Error::Firmware(_)) => false,
                Err(error) => return Err(error),
            }
        };
        self.lifecycle
            .monitor
            .capable
            .store(capable, Ordering::Release);
        let receiver = narf_net::iface::lookup(&self.name).ok_or(Error::Authority)?;
        if !narf_net::iface::set_open_stop_target(&receiver, self.monitor_target()) {
            return Err(Error::Authority);
        }
        Ok(())
    }
    pub(super) fn monitor_capable(&self) -> bool {
        R::PRIMARY_MONITOR
            && !self.withdrawn()
            && self.lifecycle.monitor.capable.load(Ordering::Acquire)
    }
    pub(super) fn monitor_target(self: &Arc<Self>) -> Arc<dyn narf_net::iface::OpenStopTarget> {
        Arc::new(Target(Arc::downgrade(self)))
    }
    fn monitor_event(&self, event: narf_net::iface::OpenStopEvent) {
        if event.name() != self.name || self.withdrawn() {
            return;
        }
        if !event.up() {
            self.lifecycle.monitor.close();
            if self.ap_mode() == 6 {
                self.up.store(false, Ordering::Release);
            } else if self.ap_mode() == 3 {
                // Admin link-down retires this endpoint's AP program (the
                // driver's ndo_stop equivalent): a retired program must not
                // keep the device link up. Monitor mode above keeps its own
                // direct drop; AP mode goes through the AP carrier so the
                // generation advances and link metadata is withdrawn.
                self.ap_carrier(false);
            }
            return;
        }
        if self.ap_mode() != 6 || !self.monitor_capable() || !event.current() {
            return;
        }
        self.lifecycle.monitor.close_capture();
        *self.lifecycle.monitor.request.lock() = Some(Arc::new(Request {
            event,
            generation: self.lifecycle.ap.generation.load(Ordering::Acquire),
        }));
        self.lifecycle.monitor.wake();
    }
    pub(super) fn monitor_channel(
        &self,
        channel: narf_wireless::monitor::Channel,
    ) -> Result<(), WirelessError> {
        if self.ap_mode() != 6 || !self.monitor_capable() {
            return Err(WirelessError::NotSupported);
        }
        let _reservation = self.lifecycle.ap.control.try_reserve()?;
        let metadata = narf_net::iface::lookup(&self.name).ok_or(WirelessError::Denied)?;
        if metadata.link_up || metadata.carrier {
            return Err(WirelessError::Busy);
        }
        let state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        if state.monitor.is_some() || state.ap.is_some() {
            return Err(WirelessError::Busy);
        }
        let policy = self.lifecycle.ap.policy().map_err(wireless_error)?;
        state
            .station
            .monitor_channel(&policy, channel)
            .map_err(wireless_error)?;
        *self.lifecycle.monitor.selection.lock() = Some(Selection {
            channel,
            policy,
            generation: self.lifecycle.ap.generation.load(Ordering::Acquire),
        });
        Ok(())
    }
    async fn monitor_cleanup(
        &self,
        state: &mut State<R>,
        request: Option<&Arc<Request>>,
    ) -> Result<(), Error> {
        self.lifecycle.monitor.close_capture();
        self.up.store(false, Ordering::Release);
        state.clear_transmit();
        let State {
            station, monitor, ..
        } = state;
        let result = match monitor.as_mut() {
            Some(session) => session.stop(station).await,
            None => Ok(()),
        };
        if result.is_ok() {
            *monitor = None;
            self.lifecycle.monitor.clear_request(request);
        } else {
            station.runtime.fail();
            let _ = station.runtime.stop_transport().await;
            self.lifecycle.monitor.close();
            self.lifecycle
                .monitor
                .capable
                .store(false, Ordering::Release);
            self.lifecycle.ap.retire();
            self.closing.store(true, Ordering::Release);
            self.power_save.store(2, Ordering::Release);
        }
        result
    }
    pub(super) async fn monitor_worker(&self) {
        if self.ap_mode() != 6 || self.withdrawn() {
            return;
        }
        let request = self.lifecycle.monitor.request.lock().clone();
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        if let Some((signal, _)) = state.station.runtime.wake_source() {
            *self.lifecycle.monitor.signal.lock() = Some(signal);
        }
        if state.monitor.is_some() {
            if request.is_none()
                || state
                    .monitor
                    .as_ref()
                    .is_some_and(|session| !session.active())
            {
                let Ok(_reservation) = self.lifecycle.ap.control.try_reserve() else {
                    return;
                };
                let _ = self.monitor_cleanup(&mut state, request.as_ref()).await;
                return;
            }
            drop(state);
            self.monitor_drain();
            return;
        }
        let Some(request) = request else {
            if state.station.runtime.poll().is_err() {
                state.station.runtime.fail();
                let _ = state.station.runtime.stop_transport().await;
                self.lifecycle
                    .monitor
                    .capable
                    .store(false, Ordering::Release);
                self.lifecycle.ap.retire();
                self.closing.store(true, Ordering::Release);
            }
            while state.station.runtime.pop_data().is_some() {}
            while state.station.runtime.pop_event().is_some() {}
            return;
        };
        if !request.event.current()
            || request.generation != self.lifecycle.ap.generation.load(Ordering::Acquire)
        {
            self.lifecycle.monitor.clear_request(Some(&request));
            return;
        }
        let Some(selection) = self.lifecycle.monitor.selection.lock().clone() else {
            return;
        };
        if selection.generation != request.generation {
            return;
        }
        let Ok(_reservation) = self.lifecycle.ap.control.try_reserve() else {
            return;
        };
        let session = match Session::prepare(
            &state.station,
            request.event.clone(),
            selection.channel,
            selection.policy,
            self.lifecycle.ap.generation.clone(),
            request.generation,
        ) {
            Ok(session) => session,
            Err(_) => {
                self.lifecycle.monitor.clear_request(Some(&request));
                return;
            }
        };
        state.clear_transmit();
        self.clear_rx();
        *self.lifecycle.monitor.capture.lock() = Some(session.original().clone());
        state.monitor = Some(Box::new(session));
        let result = {
            let State {
                station, monitor, ..
            } = &mut *state;
            monitor.as_mut().unwrap().start(station).await
        };
        if result.is_err() {
            let _ = self.monitor_cleanup(&mut state, Some(&request)).await;
            return;
        }
        let original = state.monitor.as_ref().unwrap().original().clone();
        let token = original.publish(|| narf_net::iface::begin_monitor_rx(&original.receiver()));
        match token {
            Ok(Some(token)) if original.current().is_ok() => {
                *self.lifecycle.monitor.token.lock() = Some(token);
                self.up.store(true, Ordering::Release);
            }
            Ok(Some(token)) => {
                narf_net::iface::end_monitor_rx(token);
                let _ = self.monitor_cleanup(&mut state, Some(&request)).await;
            }
            _ => {
                let _ = self.monitor_cleanup(&mut state, Some(&request)).await;
            }
        }
    }
    pub(super) fn monitor_drain(&self) -> bool {
        if self.ap_mode() != 6 || self.withdrawn() {
            return false;
        }
        let frames = {
            let Some(mut state) = self.state.try_lock() else {
                return false;
            };
            let State {
                station, monitor, ..
            } = &mut *state;
            let Some(session) = monitor.as_mut() else {
                return false;
            };
            match session.step(station) {
                Ok(frames) => frames,
                Err(_) => {
                    session.retire();
                    self.lifecycle.monitor.close_capture();
                    self.up.store(false, Ordering::Release);
                    return false;
                }
            }
        };
        self.monitor_deliver(frames)
    }
    pub(super) fn monitor_deliver(&self, frames: Vec<RawReceived>) -> bool {
        let Some(token) = *self.lifecycle.monitor.token.lock() else {
            return false;
        };
        let mut delivered = false;
        for frame in frames {
            delivered |= frame
                .original()
                .publish(|| narf_net::iface::on_monitor_frame_from(token, frame.bytes()))
                .unwrap_or(false);
        }
        delivered
    }
    pub(super) async fn monitor_suspend(&self) -> Result<(), Error> {
        let _reservation = self
            .lifecycle
            .ap
            .control
            .try_reserve()
            .map_err(|_| Error::Busy)?;
        self.lifecycle.monitor.close();
        self.up.store(false, Ordering::Release);
        let mut state = self.state.lock().await;
        self.monitor_cleanup(&mut state, None).await?;
        state.station.runtime.suspend_transport().await
    }
}
