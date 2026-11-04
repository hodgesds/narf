// SPDX-License-Identifier: GPL-2.0-or-later
//! Typed managed-netdev requests; event callbacks run after native locks drop.
use super::*;
use narf_wireless::ap_control::{RadioControlAuthority, RadioEmissionAuthority};
use narf_wireless::WirelessNetIface;
use wmi_runtime::offchannel::{Owner, Receipt, Subscriptions};
/// The wdev an offchannel request belongs to: the managed netdev (its
/// primary vdev) or the control-only P2P_DEVICE wdev (its own vdev and
/// registration set). Source/event checks bind to `iface`.
pub(super) struct Side<'a> {
    pub iface: &'a dyn WirelessNetIface,
    pub subscriptions: Arc<Subscriptions>,
    pub p2p_device: bool,
}
impl Native {
    fn primary_side(&self) -> Side<'_> {
        Side {
            iface: self,
            subscriptions: self.management_subscriptions.clone(),
            p2p_device: false,
        }
    }
    fn side_vdev(
        side: &Side<'_>,
        radio: &Radio<super::super::boot::PciBoot>,
    ) -> Result<u8, WirelessError> {
        if side.p2p_device {
            radio.p2p_device_vdev().ok_or(WirelessError::NotSupported)
        } else {
            u8::try_from(radio.primary_vdev()).map_err(|_| WirelessError::HardwareError)
        }
    }
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
        self.start_offchannel_on(
            self.primary_side(),
            authority,
            emission,
            cookie,
            frequency,
            duration,
        )
        .await
    }
    pub(super) async fn start_offchannel_on(
        &self,
        side: Side<'_>,
        authority: &RadioControlAuthority,
        emission: RadioEmissionAuthority,
        cookie: u64,
        frequency: u32,
        duration: u32,
    ) -> Result<(), WirelessError> {
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
        let vdev = Self::side_vdev(&side, &radio)?;
        if radio.roc_active() {
            return Err(WirelessError::Busy);
        }
        radio
            .bind_roc_subscriptions(side.subscriptions.clone())
            .map_err(error)?;
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        radio
            .begin_roc_on(vdev, owner.clone(), receipt, true, || {
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
        owner.event.check_for(side.iface)?;
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
        self.register_offchannel_frame_on(
            self.primary_side(),
            authority,
            emission,
            frame_type,
            prefix,
        )
        .await
    }
    pub(super) async fn register_offchannel_frame_on(
        &self,
        side: Side<'_>,
        authority: &RadioControlAuthority,
        emission: RadioEmissionAuthority,
        frame_type: u16,
        prefix: &[u8],
    ) -> Result<(), i32> {
        let event = authority.event_authority().map_err(|_| 1)?;
        let install = side
            .subscriptions
            .prepare(event, emission.clone(), frame_type, prefix)?;
        let mut radio = self.radio.lock().await;
        if self.closed.load(Ordering::Acquire) || !emission.current() {
            return Err(1);
        }
        // Another wdev's ROC holds the native capture state (EBUSY).
        radio
            .bind_roc_subscriptions(side.subscriptions.clone())
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
        authority.check_for(side.iface).map_err(|_| 1)?;
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
        // A ROC on the P2P_DEVICE vdev belongs to the wdev: its control
        // emission and events bind to the wdev, not to this netdev.
        // A withdrawn wdev's ROC is orphaned: it is forced down and its
        // expiry has no current receiver.
        let on_device = radio.roc_on_p2p_device();
        let wdev = if on_device { self.p2p_wdev() } else { None };
        let orphan = on_device && wdev.is_none();
        let target: &dyn WirelessNetIface = match &wdev {
            Some(wdev) => wdev.as_ref(),
            None => self,
        };
        let stale = orphan
            || match &wdev {
                Some(wdev) => !wdev.owns_emission(&owner.emission),
                None => !owner.emission.matches_role(
                    self,
                    core::num::NonZeroU64::new(self.mode_generation.load(Ordering::Acquire))
                        .ok_or(WirelessError::Denied)?,
                ),
            };
        let force =
            self.closed.load(Ordering::Acquire) || self.retired.load(Ordering::Acquire) || stale;
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
                    let Ok(prepared) = copy.prepare(target) else {
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
                // A stale wdev owner only ends its own ROC; the netdev
                // closes for native failure or its own staleness.
                if failed || force && !on_device {
                    self.close();
                }
                if let Some((owner, receipt)) = notice {
                    if !orphan && !self.closed.load(Ordering::Acquire) && owner.emission.current() {
                        owner.event.check_for(target)?;
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
        self.cancel_offchannel_on(false, authority, emission, cookie)
            .await
    }
    pub(super) async fn cancel_offchannel_on(
        &self,
        p2p_device: bool,
        authority: &RadioControlAuthority,
        emission: RadioEmissionAuthority,
        cookie: u64,
    ) -> Result<(), WirelessError> {
        {
            let mut radio = self.radio.lock().await;
            let owner = radio.roc_owner().ok_or(WirelessError::InvalidArgs)?;
            if radio.roc_on_p2p_device() != p2p_device {
                return Err(WirelessError::InvalidArgs);
            }
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
        self.transmit_offchannel_on(self.primary_side(), authority, emission, cookie, request)
            .await
    }
    pub(super) async fn transmit_offchannel_on(
        &self,
        side: Side<'_>,
        authority: &RadioControlAuthority,
        emission: RadioEmissionAuthority,
        cookie: u64,
        request: narf_wireless::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        let mut radio = self.radio.lock().await;
        let vdev = Self::side_vdev(&side, &radio)?;
        let existing = radio.roc_owner();
        if existing.is_some() && radio.roc_on_p2p_device() != side.p2p_device {
            return Err(WirelessError::Busy);
        }
        if existing.is_none() {
            if u16::try_from(request.frequency_mhz).ok().is_none_or(|f| {
                !self.frequencies.contains(&f)
                    || !super::super::regulatory::Permission::profile_frequency(f)
            }) {
                return Err(WirelessError::NotSupported);
            }
            radio
                .validate_private_frame(
                    vdev,
                    cookie,
                    &request,
                    &self.policy.current().map_err(error)?,
                )
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
        if radio.roc_active() && radio.roc_on_p2p_device() != side.p2p_device {
            return Err(WirelessError::Busy);
        }
        radio
            .bind_roc_subscriptions(side.subscriptions.clone())
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
                .validate_private_frame(
                    vdev,
                    cookie,
                    &request,
                    &self.policy.current().map_err(error)?,
                )
                .map_err(error)?;
        }
        let mut attempt = Attempt {
            device: self,
            armed: true,
        };
        if !radio.roc_active() {
            radio
                .begin_private_frame(vdev, owner, cookie, &request, || {
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
                authority.check_for(side.iface)?;
                attempt.armed = false;
                return Ok(status);
            }
            narf_scheduler::yield_now().await;
        }
        Err(WirelessError::Timeout)
    }
}
