// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained native source automatic EE hardware/SMART antenna transitions.
use super::super::super::{antenna, radio, tracking};
use super::*;
impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    pub(super) fn station_operating_gains(
        &self,
        environment: &impl Environment,
    ) -> Result<tracking::Gains, Error> {
        if let Some(state) = &self.station.tracking {
            Ok(state.applied)
        } else {
            Ok(tracking::Gains::nominal(
                self.station.ht.as_deref(),
                &environment.domain()?,
                self.permission.ok_or(Error::State)?,
            )?)
        }
    }
    pub(super) async fn install_station_antenna(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        // 88EE-only grant: the 8821AE profile installs no antenna program.
        let Some(base) = self.ee_base()? else {
            return Ok(());
        };
        let tracking = self.station.tracking.as_ref().map(|s| s.grant.clone());
        let grant = environment.antenna(
            base.clone(),
            self.station.ht.clone(),
            self.station.protection.clone(),
            tracking.clone(),
        )?;
        let Some(grant) = grant else {
            return Ok(());
        };
        let permission = self.permission.ok_or(Error::State)?;
        if !grant.matches_owners(
            &base,
            self.station.ht.as_ref(),
            self.station.protection.as_ref(),
            tracking.as_ref(),
            permission.channel(),
        ) {
            return Err(Error::Profile);
        }
        let gains = self.station_operating_gains(environment)?;
        grant.check(&environment.domain()?, permission, gains)?;
        if self.station.pending.is_some() || !self.transmit_ready() {
            return Err(Error::State);
        }
        let rf = self.radio.as_ref().ok_or(Error::State)?.channel_rf;
        let width = self.packet.width;
        let timing = self.packet.ht;
        let ht = self.station.ht.clone();
        self.phase = Hardware::Failed;
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let io = &self.io;
        let slot = &mut self.station.antenna;
        let install = grant.clone();
        let result = antenna::wait(grant, permission, environment, async {
            io.authority(true, || Ok(()))?;
            antenna::quiesce(io, rf, gains, ht.as_deref(), timing, width, async {
                *slot = Some(antenna::State::initialize(io, install)?);
                Ok(())
            })
            .await
        })
        .await;
        attempt.armed = false;
        if let Err(error) = result {
            self.abort_station();
            return Err(Error::Radio(error));
        }
        self.packet.antenna = self.station.antenna.as_ref().and_then(|s| s.descriptor());
        self.phase = Hardware::Running;
        self.check_station_policy(environment)
    }
    /// Restore the exact original static antenna and recalibrate it before
    /// withdrawing the extension. A preceding static measurement is never
    /// relabelled as authority for an IQK result from another antenna path.
    pub(super) async fn restore_station_antenna(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        let Some(state) = &self.station.antenna else {
            return Ok(());
        };
        if self.station.pending.is_some() || !self.transmit_ready() {
            return Err(Error::State);
        }
        self.check_station_policy(environment)?;
        let grant = state.grant.clone();
        let permission = self.permission.ok_or(Error::State)?;
        let gains = self.station_operating_gains(environment)?;
        let ht = self.station.ht.clone();
        let width = self.packet.width;
        let timing = self.packet.ht;
        let rf = self.radio.as_ref().ok_or(Error::State)?.channel_rf;
        self.phase = Hardware::Failed;
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let io = &self.io;
        let state = self.station.antenna.as_ref().ok_or(Error::State)?;
        let report = self.radio.as_mut().ok_or(Error::State)?;
        let result = antenna::wait(grant, permission, environment, async {
            io.authority(true, || Ok(()))?;
            antenna::quiesce(io, rf, gains, ht.as_deref(), timing, width, async {
                state.restore(io)?;
                radio::recalibrate(io, report, true, true)
                    .await
                    .map_err(RadioError::Radio)?;
                state.restored_readback(io)?;
                Ok(())
            })
            .await
        })
        .await;
        attempt.armed = false;
        if let Err(error) = result {
            self.abort_station();
            return Err(Error::Radio(error));
        }
        self.station.antenna = None;
        self.packet.antenna = None;
        self.phase = Hardware::Running;
        self.check_station_policy(environment)
    }
    pub(crate) async fn progress_station_antenna(
        &mut self,
        environment: &impl Environment,
    ) -> Result<bool, Error> {
        let result = self.progress_station_antenna_inner(environment).await;
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    async fn progress_station_antenna_inner(
        &mut self,
        environment: &impl Environment,
    ) -> Result<bool, Error> {
        if self.leisure() || self.station.pending.is_some() || !self.transmit_ready() {
            return Ok(false);
        }
        if !matches!(self.station.phase, Phase::Open | Phase::Passive) {
            return Ok(false);
        }
        let Some(state) = self.station.antenna.as_ref() else {
            return Ok(false);
        };
        let linked = self.station.phase == Phase::Open && self.station.native_associated;
        let Some(plan) = state.plan(environment.now_ms(), linked)? else {
            return Ok(false);
        };
        self.check_station_policy(environment)?;
        let grant = state.grant.clone();
        let permission = self.permission.ok_or(Error::State)?;
        let gains = self.station_operating_gains(environment)?;
        grant.check(&environment.domain()?, permission, gains)?;
        let own = self.local().ok_or(Error::State)?;
        let ht = self.station.ht.clone();
        let rf = self.radio.as_ref().ok_or(Error::State)?.channel_rf;
        let width = self.packet.width;
        let timing = self.packet.ht;
        self.station.rx_idle = false;
        self.phase = Hardware::Failed;
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let io = &self.io;
        let state = self.station.antenna.as_mut().ok_or(Error::State)?;
        let result = antenna::wait(grant, permission, environment, async {
            io.authority(true, || Ok(()))?;
            antenna::quiesce(io, rf, gains, ht.as_deref(), timing, width, async {
                state.apply(io, plan, own)
            })
            .await
        })
        .await;
        attempt.armed = false;
        if let Err(error) = result {
            return Err(Error::Radio(error));
        }
        self.packet.antenna = self.station.antenna.as_ref().and_then(|s| s.descriptor());
        self.phase = Hardware::Running;
        self.check_station_policy(environment)?;
        Ok(true)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn antenna_for_test(&self) -> Option<(u8, u8, bool, [u64; 2])> {
        self.station.antenna.as_ref().map(|s| s.fixture_state())
    }
}
