//! Receive-only monitor control on the real registered radio. Native state
//! and the AF_PACKET generation are separate owners, both closed on stop.
use super::*;
use crate::mt7921::firmware_transport::{
    start_boot_monitor, step_boot_monitor, stop_boot_monitor, validate_monitor_channel, Error,
};

impl Mt76Iface {
    pub(super) fn close_monitor(&self) {
        if let Some(token) = self.monitor_token.lock().take() {
            narf_net::iface::end_monitor_rx(token);
        }
    }
    pub(super) fn change_iftype(&self, iftype: u32) -> Result<(), WirelessError> {
        if ![2, 3, 6, 8, 9].contains(&iftype) {
            return Err(WirelessError::NotSupported);
        }
        let _control = self.control.try_lock().ok_or(WirelessError::Busy)?;
        let _reservation = self.ap_serial.try_reserve()?;
        // The synchronous mode change cannot stop firmware's scheduled scan;
        // userspace stops it first (STOP_SCHED_SCAN).
        if self.sleeping.load(Ordering::Acquire) || self.sched_scan_running() {
            return Err(WirelessError::Busy);
        }
        // The group link shares the home station owner's channel context
        // and is never retained beside a home AP or monitor.
        if !matches!(iftype, 2 | 8)
            && (self.p2p_group.lock().is_some() || self.p2p_go.lock().is_some())
        {
            return Err(WirelessError::Busy);
        }
        let entry = narf_net::iface::lookup(&self.name).ok_or(WirelessError::HardwareError)?;
        if entry.link_up
            || entry.carrier
            || self.associated_bssid.lock().is_some()
            || self.monitor_started.load(Ordering::Acquire)
            || self.ap_owned.load(Ordering::Acquire)
            || matches!(
                crate::mt7921::firmware_transport::boot_status(),
                crate::mt7921::firmware_transport::BootStatus::Running
            )
            || radio_needs_recovery()
        {
            return Err(WirelessError::Busy);
        }
        let layer = if iftype == 6 {
            narf_net::iface::LinkLayer::Ieee80211Radiotap
        } else {
            narf_net::iface::LinkLayer::Ethernet
        };
        let generation = (iftype != self.current_iftype())
            .then(|| self.ap_generation.load(Ordering::Acquire).checked_add(1));
        if generation == Some(None) {
            return Err(WirelessError::Denied);
        }
        narf_net::iface::set_link_layer(&self.name, layer).map_err(|_| WirelessError::Busy)?;
        if let Some(Some(generation)) = generation {
            self.ap_generation.store(generation, Ordering::Release);
            self.reset_ap_registrations();
        }
        self.iftype.store(iftype, Ordering::Release);
        self.wowlan.lock().take();
        self.clear_scan_cache();
        Ok(())
    }
    pub(super) fn configure_monitor(
        &self,
        channel: narf_wireless::monitor::Channel,
    ) -> Result<(), WirelessError> {
        let _control = self.control.try_lock().ok_or(WirelessError::Busy)?;
        if self.sleeping.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        let entry = narf_net::iface::lookup(&self.name).ok_or(WirelessError::HardwareError)?;
        if self.current_iftype() != 6 {
            return Err(WirelessError::NotSupported);
        }
        if entry.link_up || entry.carrier || self.monitor_started.load(Ordering::Acquire) {
            return Err(WirelessError::Busy);
        }
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| WirelessError::Denied)?;
        validate_monitor_channel(self.radio, &domain, channel).map_err(map_error)?;
        *self.monitor_channel.lock() = Some(channel);
        Ok(())
    }
    fn monitor_active(&self) -> bool {
        ACTIVE
            .lock()
            .as_ref()
            .is_some_and(|active| core::ptr::eq(active.as_ref(), self))
    }
    pub(super) async fn poll_monitor(&self) -> Result<(), WirelessError> {
        if !self.monitor_active() {
            return Err(WirelessError::Denied);
        }
        let Some(_control) = self.control.try_lock() else {
            return Ok(());
        };
        if radio_needs_recovery() {
            self.close_monitor();
            self.finish_teardown(false).await?;
            self.monitor_started.store(false, Ordering::Release);
        }
        let entry = narf_net::iface::lookup(&self.name).ok_or(WirelessError::HardwareError)?;
        let running = self.monitor_started.load(Ordering::Acquire);
        let token = *self.monitor_token.lock();
        if running
            && (!entry.link_up
                || token.is_none_or(|token| !narf_net::iface::monitor_rx_current(token)))
        {
            self.close_monitor();
            stop_boot_monitor().await.map_err(map_error)?;
            self.monitor_started.store(false, Ordering::Release);
            return Ok(());
        }
        if !entry.link_up {
            return Ok(());
        }
        if !running {
            let channel = (*self.monitor_channel.lock()).ok_or_else(|| {
                narf_net::iface::set_link_state(&self.name, false);
                WirelessError::InvalidArgs
            })?;
            match start_boot_monitor(channel).await {
                Ok(()) => {}
                Err(Error::Busy) => return Ok(()),
                Err(error) => {
                    if !self.monitor_active() {
                        return Err(WirelessError::Denied);
                    }
                    self.close_monitor();
                    narf_net::iface::set_link_state(&self.name, false);
                    return Err(map_error(error));
                }
            }
            if !self.monitor_active() {
                return Err(WirelessError::Denied);
            }
            self.monitor_started.store(true, Ordering::Release);
            let Some(token) = narf_net::iface::begin_monitor_rx(&entry) else {
                self.close_monitor();
                stop_boot_monitor().await.map_err(map_error)?;
                self.monitor_started.store(false, Ordering::Release);
                return Ok(());
            };
            *self.monitor_token.lock() = Some(token);
        }
        let report = match step_boot_monitor() {
            Ok(report) => report,
            Err(Error::Busy) => return Ok(()),
            Err(error) => {
                if !self.monitor_active() {
                    return Err(WirelessError::Denied);
                }
                self.close_monitor();
                narf_net::iface::set_link_state(&self.name, false);
                // Native failure retains its owner until verified recovery;
                // a policy-only closure may still perform normal stop.
                if !radio_needs_recovery() {
                    stop_boot_monitor().await.map_err(map_error)?;
                    self.monitor_started.store(false, Ordering::Release);
                }
                return Err(map_error(error));
            }
        };
        if let Some(token) = *self.monitor_token.lock() {
            for frame in report.frames {
                if !narf_net::iface::on_monitor_frame_from(token, &frame) {
                    break;
                }
            }
        }
        Ok(())
    }
}
fn map_error(error: Error) -> WirelessError {
    match error {
        Error::Bounds => WirelessError::InvalidArgs,
        Error::UnsupportedFirmware => WirelessError::NotSupported,
        Error::Busy => WirelessError::Busy,
        Error::Authority => WirelessError::Denied,
        Error::Timeout => WirelessError::Timeout,
        _ => WirelessError::HardwareError,
    }
}
