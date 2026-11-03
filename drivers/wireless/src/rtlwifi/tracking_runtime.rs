// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual retained EE thermal meter and quiescent TXAGC/calibration updates.
use super::super::super::{radio, tracking};
use super::*;
impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn tracking_for_test(&self) -> Option<(tracking::Gains, Option<u8>, Option<u8>)> {
        self.station
            .tracking
            .as_ref()
            .map(|s| (s.applied, s.lck, s.iqk))
    }
    pub(super) fn install_station_tracking(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        // 88EE-only grant: the 8821AE profile installs no tracking.
        let Some(base) = self.ee_base()? else {
            return Ok(());
        };
        let grant = environment.tracking(
            base.clone(),
            self.station.ht.clone(),
            self.station.protection.clone(),
        )?;
        self.station.tracking = if let Some(grant) = grant {
            if !grant.matches(
                &base,
                self.station.ht.as_ref(),
                self.station.protection.as_ref(),
                self.permission.ok_or(Error::State)?.channel(),
            ) {
                return Err(Error::Profile);
            }
            Some(tracking::State::new(
                grant,
                &environment.domain()?,
                self.permission.ok_or(Error::State)?,
                &self.io,
            )?)
        } else {
            None
        };
        Ok(())
    }
    /// A prior associated program may have left reduced gains while Passive.
    /// Restore the original program using fresh host policy and current old
    /// authority BEFORE selecting another peer's width/protection/measurement.
    pub(super) async fn restore_station_tracking(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        let Some(state) = &self.station.tracking else {
            return Ok(());
        };
        let nominal = state.nominal();
        if state.applied != nominal {
            self.apply_station_tracking(
                tracking::Update {
                    gains: nominal,
                    lck: false,
                    iqk: false,
                    average: 0,
                },
                environment,
            )
            .await?;
        }
        self.station.tracking = None;
        Ok(())
    }
    pub(crate) async fn track_station_gain(
        &mut self,
        environment: &impl Environment,
    ) -> Result<bool, Error> {
        let result = self.track_station_gain_inner(environment).await;
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    async fn track_station_gain_inner(
        &mut self,
        environment: &impl Environment,
    ) -> Result<bool, Error> {
        if self.station.phase != Phase::Open
            || self.leisure()
            || self.station.pending.is_some()
            || !self.transmit_ready()
        {
            return Ok(false);
        }
        let now = environment.now_ms();
        let Some(state) = self.station.tracking.as_ref() else {
            return Ok(false);
        };
        if !state.due(now) {
            return Ok(false);
        }
        self.check_station_policy(environment)?;
        let grant = state.grant.clone();
        let sample = state.needs_sample();
        let permission = self.permission.ok_or(Error::State)?;
        let antenna = self.station.antenna.as_ref().map(|s| s.grant.clone());
        self.phase = Hardware::Failed;
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let result = tracking::wait(grant, antenna, permission, environment, async {
            self.io.authority(true, || Ok(()))?;
            let value = radio::rf_read(&self.io, 0x42)
                .await
                .map_err(RadioError::Radio)?;
            if sample {
                Ok(Some(((value & 0xfc00) >> 10) as u8))
            } else {
                let trigger = (value & !0x30000) | 0x30000;
                radio::rf_write(&self.io, 0x42, trigger)
                    .await
                    .map_err(RadioError::Radio)?;
                // Source RF trigger bits are a command, not a documented
                // sticky completion receipt. The next watchdog reads actual
                // RF42 thermal bits; all64 signed rows bound even stale data.
                Ok(None)
            }
        })
        .await;
        attempt.armed = false;
        let result = match result {
            Ok(raw) => {
                self.phase = Hardware::Running;
                if let Some(raw) = raw {
                    let update = self
                        .station
                        .tracking
                        .as_mut()
                        .ok_or(Error::State)?
                        .sample(raw, now)?;
                    let current = self.station.tracking.as_ref().ok_or(Error::State)?.applied;
                    if current != update.gains || update.lck || update.iqk {
                        self.apply_station_tracking(update, environment).await?;
                    }
                } else {
                    self.station
                        .tracking
                        .as_mut()
                        .ok_or(Error::State)?
                        .triggered(now)?;
                }
                self.check_station_policy(environment)?;
                Ok(true)
            }
            Err(e) => Err(Error::Radio(e)),
        };
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    async fn apply_station_tracking(
        &mut self,
        update: tracking::Update,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.station.pending.is_some()
            || !self.transmit_ready()
            || !matches!(self.station.phase, Phase::Joining | Phase::Open)
        {
            return Err(Error::State);
        }
        self.check_station_policy(environment)?;
        let grant = self
            .station
            .tracking
            .as_ref()
            .ok_or(Error::State)?
            .grant
            .clone();
        let permission = self.permission.ok_or(Error::State)?;
        grant.check(&environment.domain()?, permission, update.gains)?;
        let antenna = self.station.antenna.as_ref().map(|s| s.grant.clone());
        if let Some(q) = &antenna {
            q.check(&environment.domain()?, permission, update.gains)?;
        }
        let ht = self.station.ht.clone();
        // This changes TX gain only, not peer/channel/key/receive identity.
        // Captured frames retain the same current full-program authority;
        // active BA/reorder ownership and epochs are preserved.
        self.station.rx_idle = false;
        self.phase = Hardware::Failed;
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let result = tracking::wait(
            grant.clone(),
            antenna.clone(),
            permission,
            environment,
            async {
                self.io.authority(true, || Ok(()))?;
                let pause = self.io.read8(0x522)?;
                self.io.write8(0x522, 0xff)?;
                if self.io.read8(0x522)? != 0xff {
                    return Err(RadioError::Readback);
                }
                let mut idle = false;
                for _ in 0..101 {
                    if self.io.read32(0x5f8)? == 0 {
                        idle = true;
                        break;
                    }
                    self.io.delay_us(10).await;
                }
                if !idle {
                    return Err(RadioError::PacketTimeout);
                }
                let cr = self.io.read8(0x100)?;
                if cr & 0xc0 != 0xc0 {
                    return Err(RadioError::State);
                }
                self.io.write8(0x100, cr & !0xc0)?;
                if self.io.read8(0x100)? & 0xc0 != 0 {
                    return Err(RadioError::Readback);
                }
                let expected_rf = self.radio.as_ref().ok_or(RadioError::State)?.channel_rf;
                if radio::rf_read(&self.io, 0x18)
                    .await
                    .map_err(RadioError::Radio)?
                    != expected_rf
                {
                    return Err(RadioError::Readback);
                }
                if update.lck || update.iqk {
                    let report = self.radio.as_mut().ok_or(RadioError::State)?;
                    radio::recalibrate(&self.io, report, update.lck, update.iqk)
                        .await
                        .map_err(RadioError::Radio)?;
                    // Existing native LCK/IQK owns its source MAC pause sequences;
                    // ordinary MAC TX/RX stays closed throughout and we re-pause
                    // all queues before touching final gains or opening either gate.
                    self.io.write8(0x522, 0xff)?;
                    if self.io.read8(0x522)? != 0xff || self.io.read8(0x100)? & 0xc0 != 0 {
                        return Err(RadioError::Readback);
                    }
                }
                tracking::program(&self.io, update.gains)?;
                if radio::rf_read(&self.io, 0x18)
                    .await
                    .map_err(RadioError::Radio)?
                    != expected_rf
                {
                    return Err(RadioError::Readback);
                }
                if let Some(ht) = &ht {
                    ht.readback_width(
                        &self.io,
                        update.gains.mcs,
                        self.packet.ht,
                        self.packet.width,
                    )?;
                }
                grant.check(
                    &environment.domain().map_err(|_| RadioError::State)?,
                    permission,
                    update.gains,
                )?;
                if let Some(q) = &antenna {
                    q.check(
                        &environment.domain().map_err(|_| RadioError::State)?,
                        permission,
                        update.gains,
                    )?;
                    self.station
                        .antenna
                        .as_ref()
                        .ok_or(RadioError::State)?
                        .readback(&self.io)?;
                }
                self.io.write8(0x100, cr)?;
                self.io.write8(0x522, pause)?;
                if self.io.read8(0x100)? != cr || self.io.read8(0x522)? != pause {
                    return Err(RadioError::Readback);
                }
                Ok(())
            },
        )
        .await;
        attempt.armed = false;
        if let Err(e) = result {
            self.abort_station();
            return Err(Error::Radio(e));
        }
        let state = self.station.tracking.as_mut().ok_or(Error::State)?;
        state.applied = update.gains;
        if update.lck {
            state.lck = Some(update.average);
        }
        if update.iqk {
            state.iqk = Some(update.average);
        }
        self.station.ht_indices = update.gains.mcs;
        self.phase = Hardware::Running;
        self.check_station_policy(environment)
    }
}
