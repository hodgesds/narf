//! Native WoW control over the retained platform/firmware ownership path.
use super::*;
use narf_power::system_pm::SystemSleepState;
use narf_wireless::{GtkRekeyData, WowlanConfig, WowlanSupport};
use zeroize::Zeroize;

impl Mt76Iface {
    pub(super) fn native_wowlan_support(&self) -> Option<WowlanSupport> {
        self.wowlan_support_with(crate::mt7921::firmware_transport::boot_wake_route_available)
    }

    pub(super) fn wowlan_support_with(
        &self,
        probe: impl FnOnce() -> Result<bool, crate::mt7921::firmware_transport::Error>,
    ) -> Option<WowlanSupport> {
        if !self.station_role() {
            return None;
        }
        if !self.wake_reported.load(Ordering::Acquire) {
            if probe() != Ok(true) {
                return None;
            }
            self.wake_reported.store(true, Ordering::Release);
        }
        Some(WowlanSupport {
            disconnect: true,
            magic_packet: true,
            gtk_rekey: true,
            gtk_rekey_failure: false,
            max_patterns: 1,
            min_pattern_len: 1,
            max_pattern_len: 128,
            max_packet_offset: 0,
            net_detect_max_match_sets: 10,
            net_detect_random_mac: true,
        })
    }

    pub(super) fn configure_wowlan(&self, config: Option<WowlanConfig>) -> Result<(), i32> {
        self.configure_wowlan_with(
            config,
            crate::mt7921::firmware_transport::boot_wake_route_available,
        )
    }

    pub(super) fn configure_wowlan_with(
        &self,
        config: Option<WowlanConfig>,
        probe: impl FnOnce() -> Result<bool, crate::mt7921::firmware_transport::Error>,
    ) -> Result<(), i32> {
        let _control = self.control.try_lock().ok_or(-16)?;
        if self.sleeping.load(Ordering::Acquire) {
            return Err(-16);
        }
        if let Some(config) = config.as_ref() {
            if !self.station_role() {
                return Err(-95);
            }
            match probe() {
                Ok(true) => self.wake_reported.store(true, Ordering::Release),
                Err(crate::mt7921::firmware_transport::Error::Busy) => return Err(-16),
                Err(crate::mt7921::firmware_transport::Error::Authority) => return Err(-1),
                _ => return Err(-95),
            }
            crate::mt7921::wowlan::validate(config).map_err(|_| -22)?;
        }
        *self.wowlan.lock() = config;
        Ok(())
    }

    pub(super) fn validate_rekey_data(&self, mut data: GtkRekeyData) -> Result<(), i32> {
        let result = (|| {
            let _control = self.control.try_lock().ok_or(-16)?;
            if self.sleeping.load(Ordering::Acquire) {
                return Err(-16);
            }
            if !self.station_role() || !self.link_up() {
                return Err(-107);
            }
            // This driver owns the RSNA. An external offload request can
            // confirm its current authenticated keys; it cannot replace
            // them, change the replay counter, or authorize a stale RSNA.
            crate::mt7921::firmware_transport::boot_validate_rekey_data(&data).map_err(|error| {
                if error == crate::mt7921::firmware_transport::Error::Busy {
                    -16
                } else {
                    -22
                }
            })
        })();
        data.kek.zeroize();
        data.kck.zeroize();
        result
    }

    pub(super) async fn prepare_suspend_target(
        &self,
        target: SystemSleepState,
    ) -> Result<(), WirelessError> {
        let _control = self.control.lock().await;
        if self.monitor_started.load(Ordering::Acquire) {
            self.close_monitor();
            crate::mt7921::firmware_transport::stop_boot_monitor()
                .await
                .map_err(|_| WirelessError::HardwareError)?;
            self.monitor_started.store(false, Ordering::Release);
        }
        let config = self.wowlan.lock().clone();
        let connected = self.associated_bssid.lock().is_some();
        if config
            .as_ref()
            .is_some_and(|config| config.net_detect.is_none())
            && !connected
            && !self.sleeping.load(Ordering::Acquire)
        {
            // Unassociated sleep requires the explicit NLO owner.
            return Err(WirelessError::NotSupported);
        }
        if connected {
            self.teardown_needed.store(true, Ordering::Release);
        }
        self.sleeping.store(true, Ordering::Release);
        self.clear_link();
        self.clear_scan_cache();
        if connected {
            // The host association ends even though its firmware context
            // remains temporarily live for wake. Resume creates a fresh
            // RSNA after reset, with no inferred firmware key/replay state.
            narf_wireless::nl80211::notify_disconnect(&self.name, 3, false);
        }
        let result = match config {
            Some(config) => {
                crate::mt7921::firmware_transport::suspend_boot_wowlan(config, target).await
            }
            None => crate::mt7921::firmware_transport::suspend_boot_radio().await,
        };
        if result.is_err() {
            self.sleeping.store(false, Ordering::Release);
        }
        suspend_result(result)?;
        // Both ordinary and WoW suspend have retired any independent
        // control BSS/finite ROC before the actual low-power handoff.
        self.commit_p2p_stopped();
        // Non-WoW AP suspend has stopped the actual autonomous BSS and
        // completed its verified reset before the PCI low-power handoff.
        if self.ap_owned.load(Ordering::Acquire) {
            self.commit_ap_stopped();
        }
        self.teardown_needed.store(false, Ordering::Release);
        Ok(())
    }
}
