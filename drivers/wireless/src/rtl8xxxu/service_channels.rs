// SPDX-License-Identifier: GPL-2.0-or-later
//! Qualified idle channel selection and bounded passive dwell ownership.
use super::*;

impl<C: ControlIo, B: packet_transport::Io, E: Environment> Service<C, B, E> {
    pub(in crate::rtl8xxxu) fn channel(&self) -> Result<u8, Error> {
        if self.phase() == Phase::Failed {
            Err(Error::State)
        } else {
            Ok(self.permission.channel())
        }
    }

    pub(super) fn check_current(&mut self) -> Result<(), Error> {
        match self.current() {
            Ok(_) => Ok(()),
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }

    pub(super) fn channel_permission(
        &self,
        channel: u8,
    ) -> Result<power_policy::Permission, Error> {
        let permission = if let Some(radio) = &self.radio {
            radio.permission_for_channel(channel).map_err(Error::Radio)
        } else {
            self.station
                .as_ref()
                .ok_or(Error::State)?
                .channel_permission(channel)
                .map_err(Error::Station)
        };
        match permission {
            Ok(permission) => Ok(permission),
            // An existing current-channel token grants no retune authority.
            Err(_) if channel == self.permission.channel() => {
                self.current()?;
                Ok(self.permission)
            }
            Err(_) => Err(Error::Profile),
        }
    }

    pub(in crate::rtl8xxxu) fn scan_channels(&mut self) -> Result<Vec<u8>, Error> {
        self.check_current()?;
        let mut channels = Vec::new();
        for channel in 1..=13 {
            let permission = self.channel_permission(channel);
            // Missing target rows are ordinary omissions. A lost current
            // authority during enumeration must instead poison the owner.
            self.check_current()?;
            if permission.is_ok() {
                channels.push(channel);
            }
        }
        self.check_current()?;
        Ok(channels)
    }

    pub(in crate::rtl8xxxu) async fn select_channel(&mut self, channel: u8) -> Result<(), Error> {
        if channel == self.permission.channel() {
            return self.check_current();
        }
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        self.check_current()?;
        let permission = self.channel_permission(channel)?;
        if self.channel()? == channel {
            return Ok(());
        }
        let next = self.generation.checked_add(1).ok_or(Error::State)?;
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = self
            .radio
            .as_mut()
            .ok_or(Error::State)?
            .cold_retune(channel)
            .await
            .map_err(Error::Radio);
        attempt.armed = false;
        match result {
            Ok(actual) if actual == permission => {
                self.permission = actual;
                self.generation = next;
                Ok(())
            }
            Ok(_) => {
                self.fail();
                Err(Error::Profile)
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }

    pub(in crate::rtl8xxxu) async fn passive_scan(
        &mut self,
        channels: &[u8],
        dwell_ms: u64,
        mandatory: bool,
    ) -> Result<(), Error> {
        if self.phase() == Phase::Connected {
            return self
                .associated_passive_scan(channels, dwell_ms, mandatory)
                .await;
        }
        if self.phase() != Phase::Passive || channels.is_empty() || !(1..=1024).contains(&dwell_ms)
        {
            return Err(Error::State);
        }
        self.check_current()?;
        // All request admission precedes the first stop/power/channel write.
        for channel in channels {
            self.channel_permission(*channel)?;
        }
        let home = self.channel()?;
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = async {
            for channel in channels {
                self.select_channel(*channel).await?;
                let until = self.now()?.checked_add(dwell_ms).ok_or(Error::State)?;
                let mut completed = false;
                for _ in 0..20_000 {
                    self.poll()?;
                    if self.now()? >= until {
                        completed = true;
                        break;
                    }
                    self.environment.pause().await;
                }
                if !completed {
                    return Err(Error::State);
                }
            }
            self.select_channel(home).await?;
            self.check_current()?;
            Ok(())
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }

    async fn associated_passive_scan(
        &mut self,
        channels: &[u8],
        dwell_ms: u64,
        mandatory: bool,
    ) -> Result<(), Error> {
        self.check_current()?;
        // Pure request admission happens before arming the terminal owner.
        if !self.station.as_ref().is_some_and(Station::scan_admissible) {
            return Err(Error::State);
        }
        if channels.is_empty() || dwell_ms == 0 || dwell_ms > 1024 || mandatory && dwell_ms > 125 {
            return Err(Error::Profile);
        }
        for &channel in channels {
            let permission = self.channel_permission(channel);
            self.check_current()?;
            permission?;
        }
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = self
            .station
            .as_mut()
            .ok_or(Error::State)?
            .passive_scan(
                channels,
                dwell_ms,
                mandatory,
                &self.environment,
                &mut self.generation,
            )
            .await
            .map_err(Error::Station);
        attempt.armed = false;
        match result {
            Ok(observations) => {
                for observation in observations {
                    let entry = Entry {
                        candidate: observation.candidate,
                        seen: observation.seen,
                        generation: observation.generation,
                    };
                    if let Some(old) = self
                        .cache
                        .iter_mut()
                        .find(|old| old.candidate.bssid() == entry.candidate.bssid())
                    {
                        *old = entry;
                    } else {
                        if self.cache.len() == 32 {
                            let oldest = self
                                .cache
                                .iter()
                                .enumerate()
                                .min_by_key(|(_, old)| old.seen)
                                .map(|(i, _)| i)
                                .unwrap();
                            self.cache.swap_remove(oldest);
                        }
                        self.cache.push(entry);
                    }
                }
                self.check_current()
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
}
