// SPDX-License-Identifier: GPL-2.0-or-later
//! Station-owned 8821A call sites. Original controller/grants remain beside
//! the rings; cancellation closes the station epoch before any publication.
use super::super::super::rtl8821ae::coex_runtime::Notify;
use super::super::packet::ae::CoexAttempt;
use super::*;

impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    /// Retain the exact original RAM fixture Arc without replaying physical
    /// bring-up. The actual start, inquiry and qualification still run.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fixture_8821_stage_base(
        &mut self,
        base: Arc<super::super::super::rtl8821ae::envelope::Calibration>,
    ) -> Result<(), Error> {
        if self.phase != Hardware::MacConfigured || self.station_phase() != Phase::Dormant {
            return Err(Error::State);
        }
        let permission = self.rtl8821ae_power.ok_or(Error::State)?;
        let domain = narf_wireless::reg::db::snapshot().ok_or(Error::State)?;
        if base
            .permission_for(&domain, permission.operating())
            .map_err(|_| Error::State)?
            != permission
        {
            return Err(Error::State);
        }
        base.with_current(|| {
            self.station.calibration = Some(super::super::super::station_power::Base::Rtl8821ae(
                base.clone(),
            ));
            Ok(())
        })
        .map_err(Error::Radio)
    }

    /// RAM fixture metadata only: a completed peer and the first linked IQK
    /// interval. This supplies no over-air, firmware or physical join proof.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fixture_8821_linked_iqk_due(
        &mut self,
        program: Arc<super::super::super::rtl8821ae::coex_program::Program>,
        candidate: Candidate,
    ) {
        self.station.calibration = Some(super::super::super::station_power::Base::Rtl8821aeCoex(
            program,
        ));
        self.station.phase = Phase::Open;
        self.station.candidate = Some(candidate);
        self.station.native_associated = true;
        self.station.admitted = true;
        self.station.iqk.tick(true);
    }

    pub(crate) fn station_full_coex(&self) -> bool {
        self.rtl8821ae_full_coex()
    }
    pub(crate) fn station_8821_scanning(&self) -> bool {
        self.rtl8821ae_coex
            .as_ref()
            .is_some_and(|owner| owner.btc.wifi.scanning)
    }

    pub(crate) fn station_8821_scan_count(&mut self, count: u8) -> Result<(), Error> {
        let program = self
            .rtl8821ae_coex
            .as_ref()
            .and_then(|owner| owner.program.clone())
            .ok_or(Error::State)?;
        let mut terminal = CoexAttempt::new(&self.io);
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        program
            .invoke(|| {
                self.rtl8821ae_coex
                    .as_mut()
                    .ok_or(RadioError::State)?
                    .btc
                    .wifi
                    .ap_num = count;
                Ok(())
            })
            .map_err(Error::Radio)?;
        terminal.complete();
        attempt.armed = false;
        Ok(())
    }

    fn apply_8821_aggregation(&mut self) {
        if let Some(cfg) = self
            .rtl8821ae_coex
            .as_ref()
            .and_then(|owner| owner.full.as_ref())
            .and_then(|full| full.ampdu())
        {
            // Source rtl_rx_ampdu_apply only writes this receive-window cap;
            // reject_agg is logged there, not a per-MPDU rejection rule.
            self.station.coex_rx_window = if cfg.ctrl_agg_size {
                u16::from(cfg.agg_size).min(BA_MAX_WINDOW)
            } else {
                BA_MAX_WINDOW
            };
        }
    }

    pub(crate) fn station_8821_eapol(&mut self, now: u64) -> Result<(), Error> {
        let program = self
            .rtl8821ae_coex
            .as_ref()
            .and_then(|owner| owner.program.clone())
            .ok_or(Error::State)?;
        program
            .invoke(|| {
                let owner = self.rtl8821ae_coex.as_mut().ok_or(RadioError::State)?;
                let full = owner.full.as_mut().ok_or(RadioError::State)?;
                full.eapol(&mut owner.btc, now);
                full.lps_gate().enter_allowed = false;
                Ok(())
            })
            .map_err(Error::Radio)
    }

    pub(crate) async fn station_8821_notify(
        &mut self,
        op: Notify<'_>,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if !self.rtl8821ae_full_coex() {
            return Ok(());
        }
        let mut terminal = CoexAttempt::new(&self.io);
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        self.check_station_policy(environment)?;
        let result = self
            .ae_coex_notify(op)
            .await
            .map_err(Error::Radio)
            .and_then(|()| self.check_station_policy(environment));
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        }
        result?;
        self.apply_8821_aggregation();
        terminal.complete();
        Ok(())
    }

    pub(crate) async fn station_coex_service(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if !self.rtl8821ae_full_coex() {
            return Ok(());
        }
        let mut terminal = CoexAttempt::new(&self.io);
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        self.check_station_policy(environment)?;
        let program = self
            .rtl8821ae_coex
            .as_ref()
            .and_then(|owner| owner.program.clone())
            .ok_or(Error::State)?;
        let result = program
            .wait(self.ae_service_coex())
            .await
            .map_err(Error::Radio)
            .and_then(|()| self.check_station_policy(environment));
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        }
        result?;
        self.apply_8821_aggregation();
        terminal.complete();
        Ok(())
    }

    pub(super) async fn station_8821_watchdog(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if !self.rtl8821ae_full_coex() {
            return Ok(());
        }
        let mut terminal = CoexAttempt::new(&self.io);
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        self.station_coex_service(environment).await?;
        self.check_station_policy(environment)?;
        let now = environment.now_ms();
        let pwdb = self.station.ra.smoothed();
        let count = self
            .rtl8821ae_coex
            .as_ref()
            .map_or(0, |owner| owner.btc.wifi.ap_num);
        let encryption = self
            .station
            .plan
            .as_ref()
            .is_some_and(|plan| plan.security().is_wpa2());
        let ps_allowed = self.station_linked() && self.station.deferred_eapol.is_none();
        let result = self
            .ae_coex_watchdog(now, pwdb, count, encryption, ps_allowed)
            .await
            .map_err(Error::Radio)
            .and_then(|()| self.check_station_policy(environment));
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        }
        result?;
        self.apply_8821_aggregation();
        terminal.complete();
        Ok(())
    }
}
