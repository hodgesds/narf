// SPDX-License-Identifier: GPL-2.0-or-later
//! Typed managed-netdev requests; event callbacks run after native locks drop.
use super::*;
use narf_wireless::ap_control::{RadioControlAuthority, RadioEmissionAuthority};
use wmi_runtime::offchannel::{Owner, Receipt};
impl Native {
    fn offchannel_authority(
        &self,
        authority: &RadioControlAuthority,
    ) -> Result<RadioEmissionAuthority, WirelessError> {
        authority.require_mode(2)?;
        authority.check_for(self)?;
        authority.require_link()?;
        if !authority.has_reservation()
            || self.closed.load(Ordering::Acquire)
            || self.retired.load(Ordering::Acquire)
        {
            return Err(WirelessError::Denied);
        }
        authority.native_emission_for(self)
    }
    pub(super) async fn start_offchannel(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        frequency: u32,
        duration: u32,
    ) -> Result<(), WirelessError> {
        let emission = self.offchannel_authority(authority)?;
        let receipt = Receipt {
            cookie,
            frequency: u16::try_from(frequency).map_err(|_| WirelessError::InvalidArgs)?,
            duration,
        };
        if !self.frequencies.contains(&receipt.frequency)
            || !super::super::regulatory::Permission::profile_frequency(receipt.frequency)
        {
            return Err(WirelessError::NotSupported);
        }
        let owner = Owner {
            emission: emission.clone(),
            event: authority.event_authority()?,
            identity: authority.identity()?,
        };
        let mut radio = self.radio.lock().await;
        radio
            .validate_roc_request(receipt, &self.policy.current().map_err(error)?)
            .map_err(error)?;
        radio
            .bind_roc_subscriptions(self.management_subscriptions.clone())
            .map_err(error)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        radio
            .begin_roc(owner.clone(), receipt, true, || {
                if self.closed.load(Ordering::Acquire) || !emission.current() {
                    return Err(Error::Failed);
                }
                self.policy.current()
            })
            .await
            .map_err(error)?;
        if radio.roc_receipt() != Some(receipt)
            || !radio
                .roc_current(&self.policy.current().map_err(error)?)
                .map_err(error)?
        {
            return Err(WirelessError::HardwareError);
        }
        drop(radio);
        owner.event.check_for(self)?;
        owner.event.roc_ready(cookie, frequency, duration)?;
        attempt.armed = false;
        self.kick();
        Ok(())
    }
    pub(super) async fn register_offchannel_frame(
        &self,
        authority: &RadioControlAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        let emission = self.offchannel_authority(authority).map_err(|_| 1)?;
        let event = authority.event_authority().map_err(|_| 1)?;
        let install =
            self.management_subscriptions
                .prepare(event, emission.clone(), frame_type, prefix)?;
        let mut radio = self.radio.lock().await;
        if self.closed.load(Ordering::Acquire) || !emission.current() {
            return Err(1);
        }
        radio
            .bind_roc_subscriptions(self.management_subscriptions.clone())
            .map_err(|_| 16)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        let retired = radio
            .install_roc_filter(install, &|| {
                if self.closed.load(Ordering::Acquire)
                    || self.retired.load(Ordering::Acquire)
                    || !emission.current()
                {
                    Err(Error::Failed)
                } else {
                    Ok(())
                }
            })
            .await
            .map_err(|_| 5)?;
        drop(radio);
        drop(retired);
        authority.check_for(self).map_err(|_| 1)?;
        attempt.armed = false;
        Ok(())
    }
    pub(in crate::ath10k) async fn service_offchannel(&self) -> Result<(), WirelessError> {
        let Some(mut radio) = self.radio.try_lock() else {
            return Ok(());
        };
        let Some(owner) = radio.roc_owner() else {
            return Ok(());
        };
        let force = self.closed.load(Ordering::Acquire)
            || self.retired.load(Ordering::Acquire)
            || !owner.emission.matches_role(
                self,
                core::num::NonZeroU64::new(self.mode_generation.load(Ordering::Acquire))
                    .ok_or(WirelessError::Denied)?,
            );
        let result = radio
            .service_roc(
                force,
                || self.policy.current(),
                || {
                    if self.retired.load(Ordering::Acquire) {
                        Err(Error::Failed)
                    } else {
                        Ok(())
                    }
                },
            )
            .await;
        match result {
            Ok(notice) => {
                let failed = radio.roc_failed();
                let copies = radio.take_roc_captures();
                drop(radio);
                for copy in copies {
                    if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(prepared) = copy.prepare(self) else {
                        continue;
                    };
                    // All dynamic source/interface callbacks have finished.
                    // Recheck actual policy/host facts before fixed delivery.
                    if self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) {
                        continue;
                    }
                    if let Ok(domain) = self.policy.current() {
                        let _ = copy.deliver(prepared, &domain);
                    }
                }
                if failed || force {
                    self.close();
                }
                if let Some((owner, receipt)) = notice {
                    if !self.closed.load(Ordering::Acquire) && owner.emission.current() {
                        owner.event.check_for(self)?;
                        owner.event.roc_expired(
                            receipt.cookie,
                            u32::from(receipt.frequency),
                            receipt.duration,
                        )?;
                    }
                }
                Ok(())
            }
            Err(cause) => {
                radio.fail_station_data();
                drop(radio);
                self.close();
                Err(error(cause))
            }
        }
    }
    pub(super) async fn cancel_offchannel(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
    ) -> Result<(), WirelessError> {
        let emission = self.offchannel_authority(authority)?;
        {
            let mut radio = self.radio.lock().await;
            let owner = radio.roc_owner().ok_or(WirelessError::InvalidArgs)?;
            // Callback/source identity checks occur outside the native lock.
            drop(radio);
            authority.check_identity(&owner.identity)?;
            radio = self.radio.lock().await;
            if !emission.current() {
                return Err(WirelessError::Denied);
            }
            radio.roc_cancel(cookie).map_err(error)?;
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        self.kick();
        for _ in 0..65536 {
            if !emission.current() {
                return Err(WirelessError::Denied);
            }
            self.service_offchannel().await?;
            if !self.radio.lock().await.roc_active() {
                if self.closed.load(Ordering::Acquire) {
                    return Err(WirelessError::HardwareError);
                }
                attempt.armed = false;
                return Ok(());
            }
            narf_scheduler::yield_now().await;
        }
        Err(WirelessError::Timeout)
    }
    pub(super) async fn transmit_offchannel(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        let emission = self.offchannel_authority(authority)?;
        let mut radio = self.radio.lock().await;
        let existing = radio.roc_owner();
        if existing.is_none() {
            if u16::try_from(request.frequency_mhz).ok().is_none_or(|f| {
                !self.frequencies.contains(&f)
                    || !super::super::regulatory::Permission::profile_frequency(f)
            }) {
                return Err(WirelessError::NotSupported);
            }
            radio
                .validate_private_frame(cookie, &request, &self.policy.current().map_err(error)?)
                .map_err(error)?;
        }
        drop(radio);
        let owner = if let Some(owner) = existing {
            authority.check_identity(&owner.identity)?;
            owner
        } else {
            Owner {
                emission: emission.clone(),
                event: authority.event_authority()?,
                identity: authority.identity()?,
            }
        };
        radio = self.radio.lock().await;
        radio
            .bind_roc_subscriptions(self.management_subscriptions.clone())
            .map_err(error)?;
        if radio.roc_active() {
            radio
                .validate_roc_action(
                    cookie,
                    &request,
                    &emission,
                    &self.policy.current().map_err(error)?,
                )
                .map_err(error)?;
        } else {
            radio
                .validate_private_frame(cookie, &request, &self.policy.current().map_err(error)?)
                .map_err(error)?;
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        if !radio.roc_active() {
            radio
                .begin_private_frame(owner, cookie, &request, || {
                    if self.closed.load(Ordering::Acquire) || !emission.current() {
                        return Err(Error::Failed);
                    }
                    self.policy.current()
                })
                .await
                .map_err(error)?;
        }
        radio
            .begin_roc_action(cookie, &request, emission.clone(), || {
                if self.closed.load(Ordering::Acquire) || !emission.current() {
                    return Err(Error::Failed);
                }
                self.policy.current()
            })
            .await
            .map_err(error)?;
        drop(radio);
        self.kick();
        for _ in 0..65536 {
            if self.closed.load(Ordering::Acquire) || !emission.current() {
                return Err(WirelessError::Denied);
            }
            self.service_offchannel().await?;
            let status = self
                .radio
                .lock()
                .await
                .take_roc_action_status(cookie)
                .map_err(error)?;
            if let Some(status) = status {
                authority.check_for(self)?;
                attempt.armed = false;
                return Ok(status);
            }
            narf_scheduler::yield_now().await;
        }
        Err(WirelessError::Timeout)
    }
}
