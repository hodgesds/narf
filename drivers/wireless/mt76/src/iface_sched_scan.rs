//! Host scheduled scan on the home station (NL80211_CMD_START_SCHED_SCAN).
//! cfg80211 `rdev_sched_scan_start` / `rdev_sched_scan_stop` over the
//! native owner (mt7921_start_sched_scan / mt7921_stop_sched_scan), each
//! finished firmware cycle reported as SCHED_SCAN_RESULTS
//! (`ieee80211_sched_scan_results`) with its BSSs in the GET_SCAN cache,
//! and the stop cfg80211 performs itself before a scan, a connection or a
//! suspend, or when the interface goes down (`cfg80211_stop_sched_scan_req`,
//! which reports SCHED_SCAN_STOPPED).
use super::*;
use crate::mt7921::firmware_transport::{
    start_boot_sched_scan, step_boot_sched_scan, stop_boot_sched_scan, Error,
};
use narf_wireless::ap_control::RadioControlAuthority;

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBUSY: i32 = 16;
const EINVAL: i32 = 22;
const EOPNOTSUPP: i32 = 95;
const ETIMEDOUT: i32 = 110;
/// cfg80211_sched_scan_req_possible: one legacy request at a time.
const EINPROGRESS: i32 = 115;

fn errno(error: Error) -> i32 {
    match error {
        Error::Bounds | Error::InvalidIdentity => EINVAL,
        Error::Busy => EBUSY,
        Error::Authority => EPERM,
        Error::Timeout => ETIMEDOUT,
        _ => EIO,
    }
}

impl Mt76Iface {
    pub(super) fn sched_scan_running(&self) -> bool {
        self.sched_scan.lock().is_some()
    }

    pub(super) async fn start_sched_scan_native(
        &self,
        authority: &RadioControlAuthority,
        request: narf_wireless::SchedScanRequest,
    ) -> Result<(), i32> {
        authority.check_for(self).map_err(|_| EPERM)?;
        authority.require_mode(2).map_err(|_| EPERM)?;
        authority.require_link().map_err(|_| EPERM)?;
        if !authority.has_reservation() {
            return Err(EPERM);
        }
        let event = authority.event_authority().map_err(|_| EPERM)?;
        let _control = self.control.lock().await;
        if !self.station_role() {
            return Err(EOPNOTSUPP);
        }
        if self.sched_scan_running() {
            return Err(EINPROGRESS);
        }
        // Periodic scanning is the idle station's: a connected station
        // roams and reconnects through ordinary scans.
        if self.sleeping.load(Ordering::Acquire) || self.link_up() {
            return Err(EBUSY);
        }
        self.finish_teardown(true)
            .await
            .map_err(|error| match error {
                WirelessError::Busy => EBUSY,
                _ => EIO,
            })?;
        start_boot_sched_scan(&request).await.map_err(|error| {
            note_failure("sched scan start", &error);
            errno(error)
        })?;
        // The request's interface may have gone while firmware was
        // programmed; it does not keep a scan nobody can stop.
        if authority.check_for(self).is_err() || authority.require_link().is_err() {
            let _ = stop_boot_sched_scan().await;
            return Err(EPERM);
        }
        *self.sched_scan.lock() = Some(event);
        Ok(())
    }

    pub(super) async fn stop_sched_scan_native(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<(), i32> {
        authority.check_for(self).map_err(|_| EPERM)?;
        authority.require_link().map_err(|_| EPERM)?;
        let _control = self.control.lock().await;
        if !self.sched_scan_running() {
            return Err(ENOENT);
        }
        let result = stop_boot_sched_scan().await;
        match result {
            Err(Error::Busy) => return Err(EBUSY),
            Err(Error::Cancelled) | Ok(()) => {}
            Err(error) => note_failure("sched scan stop", &error),
        }
        // A failed stop leaves the radio to the verified reset path; the
        // request is over either way.
        self.sched_scan.lock().take();
        match result {
            Ok(()) | Err(Error::Cancelled) => Ok(()),
            Err(error) => Err(errno(error)),
        }
    }

    /// cfg80211 ends the scheduled scan itself and reports
    /// SCHED_SCAN_STOPPED. Called with `control` held.
    pub(super) async fn end_sched_scan(&self) -> Result<(), WirelessError> {
        if !self.sched_scan_running() {
            return Ok(());
        }
        let result = stop_boot_sched_scan().await;
        if matches!(result, Err(Error::Busy)) {
            return Err(WirelessError::Busy);
        }
        if let Some(event) = self.sched_scan.lock().take() {
            let _ = event.scheduled_scan_stopped();
        }
        match result {
            Ok(()) | Err(Error::Cancelled) => Ok(()),
            Err(error) => {
                note_failure("sched scan stop", &error);
                Err(WirelessError::HardwareError)
            }
        }
    }

    /// One bounded collection step; a finished cycle's BSSs replace the
    /// scan cache and are reported as SCHED_SCAN_RESULTS.
    pub(super) async fn poll_sched_scan(&self) {
        let Some(event) = self.sched_scan.lock().clone() else {
            return;
        };
        let Some(_control) = self.control.try_lock() else {
            return;
        };
        if !self.sched_scan_running() {
            return;
        }
        // cfg80211 stops the request when its interface goes down.
        if event.check_for(self).is_err() || !self.station_role() {
            let _ = self.end_sched_scan().await;
            return;
        }
        match step_boot_sched_scan() {
            Ok(None) | Err(Error::Busy) => {}
            Ok(Some(report)) => {
                let results = report
                    .bss
                    .iter()
                    .map(|bss| (bss_info(bss), bss.information_elements.clone()))
                    .collect();
                *self.scan_cache.lock() = report.bss;
                *self.scan_beaconed.lock() = report.beaconed;
                match event.scheduled_scan_results_with_bss(results) {
                    // A one-shot GET_SCAN refresh owns the cache right now.
                    Ok(()) | Err(WirelessError::Busy) => {}
                    Err(_) => {
                        let _ = self.end_sched_scan().await;
                    }
                }
            }
            // A verified reset retired the firmware request.
            Err(Error::Cancelled) => {
                if let Some(event) = self.sched_scan.lock().take() {
                    let _ = event.scheduled_scan_stopped();
                }
            }
            Err(error) => {
                note_failure("sched scan", &error);
                let _ = self.end_sched_scan().await;
            }
        }
    }
}
