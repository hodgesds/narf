//! Actual P2P-device BSS lifetime (next coherent native role batch).
//! A completed wdev is independent of IFF_UP and has no Ethernet carrier,
//! peer controlled port or RF/channel grant. CNM acquisition is separate.
use super::{station::Command, Backend, Error, RadioInfo, Session, Stage, State};
use alloc::sync::Arc;
use core::future::Future;
use narf_wireless::ap_control::{RadioControlAuthority, RadioInterfaceIdentity};
#[path = "p2p_roc.rs"]
mod roc;
pub(super) use roc::Receipt as RocReceipt;

#[derive(Debug)]
pub(super) struct Owner {
    pub info: RadioInfo,
    pub identity: RadioInterfaceIdentity,
    pub cnm: crate::mt7921::p2p_cnm::Cnm,
    pub pending: Option<Arc<RadioControlAuthority>>,
    pub activated: bool,
    pub ready: bool,
    pub vif: crate::mt7921::vif_slots::Vif,
    pub management: super::p2p_management::Management,
    roc: Option<roc::Roc>,
}
impl<B: Backend> Session<B> {
    pub(super) async fn start_p2p_device(
        &mut self,
        authority: Arc<RadioControlAuthority>,
    ) -> Result<(), Error> {
        self.start_p2p_device_on(authority, crate::mt7921::vif_slots::Vif::new(0)?)
            .await
    }
    pub(super) async fn start_p2p_device_on(
        &mut self,
        authority: Arc<RadioControlAuthority>,
        vif: crate::mt7921::vif_slots::Vif,
    ) -> Result<(), Error> {
        authority.require_mode(10).map_err(|_| Error::Authority)?;
        if self.p2p_owner.is_some() {
            return Err(Error::Busy);
        }
        let home = self.state;
        let sidecar = vif.index() != 0;
        let info = match home {
            State::RadioReady(info) | State::ScanReady(info) => info,
            State::Associated { info, .. } | State::AccessPoint { info, .. } if sidecar => info,
            _ => return Err(Error::Busy),
        };
        if !authority.has_reservation() {
            return Err(Error::Authority);
        }
        let identity = authority.identity().map_err(|_| Error::Authority)?;
        if identity.mac() == [0; 6] || identity.mac()[0] & 1 != 0 {
            return Err(Error::Authority);
        }
        // Retain the actual request before the first native await. Even a
        // dropped reset waiter cannot release its serialization lease while
        // old hardware resources remain uncertain.
        self.p2p_owner = Some(Owner {
            info,
            identity: identity.clone(),
            cnm: Default::default(),
            pending: Some(authority.clone()),
            activated: false,
            ready: false,
            vif,
            management: Default::default(),
            roc: None,
        });
        // BSS0 takeover retires the previous role. A separately allocated
        // P2P-device BSS owns no peer/key/FIFO and must not reset the live
        // station/AP merely to add its own DEV/BSS, as mt7921_add_interface.
        let info = if sidecar {
            info
        } else {
            self.recover(info.capabilities.mac).await?
        };
        authority.current().map_err(|_| Error::Authority)?;
        identity.current().map_err(|_| Error::Authority)?;
        self.p2p_owner = Some(Owner {
            info,
            identity,
            cnm: crate::mt7921::p2p_cnm::Cnm::from_next(self.p2p_next),
            pending: Some(authority.clone()),
            activated: false,
            ready: false,
            vif,
            management: Default::default(),
            roc: None,
        });
        self.stage(Stage::P2pDeviceStart);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            // The actual registered P2P wdev may have its own address.
            // Concrete retained work separately checks the physical radio's
            // device/PCI identity; local MAC equality is no such grant.
            let local = self.p2p_owner.as_ref().ok_or(Error::Busy)?.identity.mac();
            let (device, bss) = vif.device_payloads(local, true, false)?;
            self.p2p_exchange(&authority, Command::Unified { id: 1 }, &device)
                .await?;
            self.p2p_exchange(&authority, Command::Unified { id: 2 }, &bss)
                .await?;
            // mt7921_add_interface reserves 19-idx only after add-dev and
            // clears its admission counters. This is not peer/key setup.
            self.backend.clear_wtbl(vif.bmc())?;
            self.wait(100, |backend| {
                backend.wtbl_idle().map(|idle| idle.then_some(()))
            })
            .await?;
            self.check_p2p_request(&authority)?;
            Ok(())
        }
        .await;
        self.boot_started = None;
        match result {
            Ok(()) => {
                self.p2p_owner.as_mut().ok_or(Error::Busy)?.ready = true;
                self.state = if sidecar {
                    home
                } else {
                    State::P2pDevice(info)
                };
                Ok(())
            }
            Err(error) => Err(self.p2p_failure(error).await),
        }
    }
    /// The real concrete interface calls this inside the retained start
    /// operation after its actual native BSS receipts/current-source check.
    /// It still opens no RF lease, packet capture, Ethernet ring or carrier.
    pub(super) fn commit_p2p_device(
        &mut self,
        authority: &RadioControlAuthority,
    ) -> Result<RadioInterfaceIdentity, Error> {
        if !self.p2p_ready() {
            return Err(Error::Busy);
        }
        self.check_p2p_request(authority)?;
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        owner.activated = true;
        owner.pending = None;
        Ok(owner.identity.clone())
    }
    pub(super) async fn stop_p2p_device(
        &mut self,
        authority: &RadioControlAuthority,
    ) -> Result<(), Error> {
        authority.current().map_err(|_| Error::Authority)?;
        authority.require_mode(10).map_err(|_| Error::Authority)?;
        self.check_p2p_request(authority)?;
        if !authority.has_reservation() {
            return Err(Error::Authority);
        }
        self.p2p_owner.as_mut().ok_or(Error::Busy)?.pending = Some(Arc::new(authority.clone()));
        self.stop_p2p_device_owned().await
    }
    pub(super) async fn stop_p2p_device_owned(&mut self) -> Result<(), Error> {
        self.close_p2p_management_capture();
        let owner = self.p2p_owner.as_ref().ok_or(Error::Busy)?;
        let info = owner.info;
        let sidecar = owner.vif.index() != 0;
        let home = self.state;
        if sidecar {
            if self.check_p2p_home().is_err() {
                return self.recover(info.capabilities.mac).await.map(|_| ());
            }
        } else {
            self.renew_receive_epoch()?;
        }
        self.stage(Stage::P2pDeviceStop);
        let result = async {
            if sidecar {
                self.retire_p2p_roc_owned().await?;
            }
            let abort = self
                .p2p_owner
                .as_ref()
                .and_then(|owner| owner.cnm.lease())
                .map(|lease| (lease.cookie, lease.request.abort()));
            if let Some((cookie, abort)) = abort {
                self.p2p_owner
                    .as_mut()
                    .ok_or(Error::Busy)?
                    .cnm
                    .abort(cookie)?;
                self.notify(
                    Command::Unified {
                        id: crate::mt7921::p2p_wire::UNIFIED_ROC,
                    },
                    &abort,
                )
                .await?;
            }
            let local = self.p2p_owner.as_ref().ok_or(Error::Busy)?.identity.mac();
            let vif = self.p2p_owner.as_ref().ok_or(Error::Busy)?.vif;
            let (device, bss) = vif.device_payloads(local, false, true)?;
            // Linux uni_add_dev disables BSS before DEV. No fresh admin
            // grant is required to clean up an already-owned native wdev.
            self.exchange(Command::Unified { id: 2 }, &bss).await?;
            self.exchange(Command::Unified { id: 1 }, &device).await?;
            if sidecar {
                self.confirm_command_progress().await?;
                self.backend.clear_wtbl(vif.bmc())?;
                self.wait(100, |backend| {
                    backend.wtbl_idle().map(|idle| idle.then_some(()))
                })
                .await?;
                self.p2p_owner = None;
                self.state = home;
                return Ok(());
            }
            // A no-response CNM abort could be outstanding; only verified
            // reset/retirement permits owner/token/capture release here.
            self.recover(info.capabilities.mac).await.map(|_| ())
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(self.p2p_failure(error).await),
        }
    }
    pub(super) fn check_p2p_request(&self, authority: &RadioControlAuthority) -> Result<(), Error> {
        authority.current().map_err(|_| Error::Authority)?;
        self.backend.check()?;
        let owner = self.p2p_owner.as_ref().ok_or(Error::Busy)?;
        authority
            .check_identity(&owner.identity)
            .map_err(|_| Error::Authority)
    }
    /// BSS1..3 are independent metadata/device contexts. Only these actual
    /// home states may be restored after their native transaction; never
    /// resurrect a saved association after another operation changed it.
    pub(super) fn check_p2p_home(&self) -> Result<(), Error> {
        match self.state {
            State::RadioReady(_)
            | State::ScanReady(_)
            | State::Associated { .. }
            | State::AccessPoint { .. } => Ok(()),
            _ => Err(Error::Busy),
        }
    }
    pub(super) fn p2p_ready(&self) -> bool {
        self.p2p_owner.as_ref().is_some_and(|owner| {
            owner.ready
                && if owner.vif.index() == 0 {
                    matches!(self.state, State::P2pDevice(_))
                } else {
                    self.check_p2p_home().is_ok()
                }
        })
    }
    pub(super) fn p2p_rf_busy(&self) -> bool {
        self.p2p_owner
            .as_ref()
            .is_some_and(|owner| owner.cnm.pending())
    }
    pub(super) async fn p2p_exchange(
        &mut self,
        authority: &RadioControlAuthority,
        command: Command,
        body: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, Error> {
        self.check_p2p_request(authority)?;
        let result = {
            let mut operation = alloc::boxed::Box::pin(self.exchange(command, body));
            core::future::poll_fn(|cx| {
                if authority.current().is_err() {
                    return core::task::Poll::Ready(Err(Error::Authority));
                }
                operation.as_mut().poll(cx)
            })
            .await
        }?;
        self.check_p2p_request(authority)?;
        Ok(result)
    }
    pub(super) async fn p2p_failure(&mut self, error: Error) -> Error {
        if let Some(cleanup) = self
            .p2p_owner
            .as_ref()
            .and_then(|owner| owner.management.worker_cleanup.as_ref())
        {
            // Only a native failure/retirement edge sets this observation.
            // A lost borrower may not drop an already published reset body.
            cleanup.store(true, core::sync::atomic::Ordering::Release);
        }
        if let Some(info) = self.p2p_owner.as_ref().map(|owner| owner.info) {
            let stage = match self.state {
                State::Running(stage) | State::Failed { stage, .. } => stage,
                _ => Stage::P2pDeviceStart,
            };
            self.state = State::Failed { stage, error };
            let _ = self.recover(info.capabilities.mac).await;
        }
        error
    }
}
