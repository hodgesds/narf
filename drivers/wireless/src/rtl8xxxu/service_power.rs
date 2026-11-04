// SPDX-License-Identifier: GPL-2.0-or-later
//! Administrative park/wake over the original radio and firmware claims.
use super::*;

impl<C: ControlIo, B: packet_transport::Io, E: Environment> Service<C, B, E> {
    pub(in crate::rtl8xxxu) async fn park(&mut self) -> Result<(), Error> {
        if self.phase() == Phase::Parked {
            return self.check_current();
        }
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = async {
            self.check_current()?;
            self.disconnect().await?;
            if self.phase() != Phase::Passive {
                return Err(Error::State);
            }
            self.cache.clear();
            self.initial_nonce = None;
            self.radio
                .as_mut()
                .ok_or(Error::State)?
                .park()
                .await
                .map_err(Error::Radio)
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }

    pub(in crate::rtl8xxxu) async fn resume_parked(&mut self) -> Result<(), Error> {
        if self.phase() != Phase::Parked {
            return Err(Error::State);
        }
        self.check_current()?;
        let next = self.generation.checked_add(1).ok_or(Error::State)?;
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = self
            .radio
            .as_mut()
            .ok_or(Error::State)?
            .resume_parked()
            .await
            .map_err(Error::Radio);
        attempt.armed = false;
        match result {
            Ok(permission) if permission == self.permission => {
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
}
