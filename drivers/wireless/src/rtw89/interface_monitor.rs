// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Public down-only role selection and original-registration raw capture.
use super::*;
use crate::rtw89::{monitor, monitor_wire as wire};
#[derive(Clone)]
pub(super) struct Capture {
    source: monitor::Source,
    token: narf_net::iface::MonitorRxToken,
}
impl<I: Io + 'static> Device<I> {
    pub(in crate::rtw89) fn new_selected(
        name: &str,
        local: [u8; 6],
        lifecycle: Arc<Lifecycle<I>>,
        environment: Arc<dyn Environment>,
        desired: Arc<monitor::Desired>,
    ) -> Self {
        let mut device = Self::new(name, local, lifecycle, environment);
        device.selection = desired.snapshot();
        device.desired = desired;
        device
    }
    pub(super) fn original_snapshot(&self) -> Option<narf_net::iface::NetIfaceSnapshot> {
        let original = self.registration.lock().clone()?;
        // This owned event retains the sealed private registration. Metadata
        // representation changes may invalidate a full packet snapshot while
        // its original registration/admin/ownership observation stays current.
        // This is metadata intent only, never native RF/capture authority.
        original.current().then(|| original.original_snapshot())
    }
    pub(super) fn role_changed(&self) -> bool {
        !self.desired.current(self.selection)
    }
    pub(super) fn monitor_selected(&self) -> bool {
        self.selection.mode == wire::IFTYPE
    }
    pub(super) fn select_mode(&self, mode: u32) -> Result<(), WirelessError> {
        if !self.monitor_capable.load(Ordering::Acquire) {
            return Err(WirelessError::NotSupported);
        }
        if !matches!(mode, 2 | 6) {
            return Err(WirelessError::NotSupported);
        }
        let original = self
            .original_snapshot()
            .ok_or(WirelessError::HardwareError)?;
        if original.link_up {
            return Err(WirelessError::Busy);
        }
        if !self.published.load(Ordering::Acquire)
            || self.retired.load(Ordering::Acquire)
            || !self.desired.current(self.selection)
        {
            return Err(WirelessError::Busy);
        }
        if mode == self.selection.mode {
            return Ok(());
        }
        // No async native operation is invented by this metadata ACK. Close
        // old packet admission first; the supervisor retires/fences its actual
        // DMA and starts a fresh physical generation before any monitor RX.
        self.close();
        let layer = if mode == wire::IFTYPE {
            narf_net::iface::LinkLayer::Ieee80211Radiotap
        } else {
            narf_net::iface::LinkLayer::Ethernet
        };
        narf_net::iface::set_link_layer(&self.name, layer).map_err(|_| WirelessError::Busy)?;
        self.desired
            .select(self.selection, mode)
            .ok_or(WirelessError::Busy)?;
        self.line.raise();
        Ok(())
    }
    pub(super) fn retire_capture(&self) {
        let captured = self.capture.lock().take();
        if let Some(captured) = captured {
            captured.source.retire();
            narf_net::iface::end_monitor_rx(captured.token);
        }
    }
    pub(super) async fn monitor_service(&self) {
        if !self.admitted.load(Ordering::Acquire) {
            return;
        }
        if self.closed() || self.role_changed() {
            self.retire_capture();
            return;
        }
        let event = self.monitor_admin.lock().clone();
        let Some(event) = event.filter(|event| event.up() && event.current()) else {
            return;
        };
        let snapshot = event.original_snapshot();
        if snapshot.link_layer != narf_net::iface::LinkLayer::Ieee80211Radiotap
            || snapshot.mac != self.local
        {
            return;
        }
        let existing = self.capture.lock().clone();
        if existing.is_none() {
            let result = {
                let mut storage = self.lifecycle.retained.lock().await;
                match storage.as_mut() {
                    Some(owner) if !self.closed() => {
                        owner
                            .io
                            .monitor_start(self.desired.clone(), self.admission.clone())
                            .await
                    }
                    _ => Err(crate::rtw89::power::Error::Terminal),
                }
            };
            let Ok(source) = result else {
                self.close();
                return;
            };
            if self.closed() || !event.current() || self.role_changed() {
                source.retire();
                self.close();
                return;
            }
            let token = source
                .with_current(|| narf_net::iface::begin_monitor_rx(&snapshot))
                .ok()
                .flatten();
            let Some(token) = token else {
                source.retire();
                self.close();
                return;
            };
            if self.closed() || !event.current() {
                source.retire();
                narf_net::iface::end_monitor_rx(token);
                self.close();
                return;
            }
            *self.capture.lock() = Some(Capture { source, token });
        }
        let frames = {
            let mut storage = self.lifecycle.retained.lock().await;
            match storage.as_mut() {
                Some(owner) if !self.closed() => owner.io.monitor_poll(),
                _ => Err(crate::rtw89::power::Error::Terminal),
            }
        };
        let Ok(frames) = frames else {
            self.retire_capture();
            self.close();
            return;
        };
        let Some(capture) = self.capture.lock().clone() else {
            return;
        };
        // All Native/lifecycle guards are gone before raw socket delivery.
        // Frequency is the exact sealed same-Native A/B RF observation; no
        // configured-channel or unmatched PPDU signal value is substituted.
        for frame in frames {
            let Ok(bytes) = narf_wireless::monitor::encode(
                &frame,
                narf_wireless::monitor::Metadata {
                    frequency_mhz: capture.source.frequency_mhz(),
                    signal_dbm: None,
                },
            ) else {
                continue;
            };
            if capture
                .source
                .with_current(|| narf_net::iface::on_monitor_frame_from(capture.token, &bytes))
                .ok()
                != Some(true)
            {
                self.retire_capture();
                self.close();
                break;
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
impl<I: Io + 'static> Device<I> {
    /// Explicit inert full-RFK/passive-station attach boundary for metadata
    /// sequencing. It earns no admission, native capture/peer/queue or TX.
    pub(in crate::rtw89) fn model_monitor_metadata_ready(
        &self,
    ) -> Result<(), crate::rtw89::power::Error> {
        let mut retained = self
            .lifecycle
            .retained
            .try_lock()
            .ok_or(crate::rtw89::power::Error::Busy)?;
        if !retained
            .as_mut()
            .ok_or(crate::rtw89::power::Error::Terminal)?
            .io
            .monitor_capable()?
        {
            return Err(crate::rtw89::power::Error::Unsupported);
        }
        self.monitor_capable.store(true, Ordering::Release);
        Ok(())
    }
}
