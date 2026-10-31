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

    fn check_current(&mut self) -> Result<(), Error> {
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
        let radio = self.radio.as_ref().ok_or(Error::State)?;
        match radio.permission_for_channel(channel) {
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
    ) -> Result<(), Error> {
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
}
