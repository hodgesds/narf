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
    roc: Option<roc::Roc>,
}
impl<B: Backend> Session<B> {
    pub(super) async fn start_p2p_device(
        &mut self,
        authority: Arc<RadioControlAuthority>,
    ) -> Result<(), Error> {
        authority.require_mode(10).map_err(|_| Error::Authority)?;
        let info = match self.state {
            State::RadioReady(info) | State::ScanReady(info) => info,
            _ => return Err(Error::Busy),
        };
        if !authority.has_reservation() {
            return Err(Error::Authority);
        }
        let identity = authority.identity().map_err(|_| Error::Authority)?;
        if identity.mac() != info.capabilities.mac {
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
            roc: None,
        });
        // Actual WFSYS/DMA retirement precedes a new role/key/FIFO owner.
        // This does not manufacture a scan or CNM/packet receipt.
        let info = self.recover(info.capabilities.mac).await?;
        authority.current().map_err(|_| Error::Authority)?;
        identity.current().map_err(|_| Error::Authority)?;
        self.p2p_owner = Some(Owner {
            info,
            identity,
            cnm: Default::default(),
            pending: Some(authority.clone()),
            activated: false,
            roc: None,
        });
        self.stage(Stage::P2pDeviceStart);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            let (device, bss) = device_payloads(info.capabilities.mac, true)?;
            self.p2p_exchange(&authority, Command::Unified { id: 1 }, &device)
                .await?;
            self.p2p_exchange(&authority, Command::Unified { id: 2 }, &bss)
                .await?;
            // mt7921_add_interface reserves WTBL19 only after add-dev and
            // clears its admission counters. This is not peer/key setup.
            self.backend.clear_wtbl(19)?;
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
                self.state = State::P2pDevice(info);
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
        if !matches!(self.state, State::P2pDevice(_)) {
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
        let info = self.p2p_owner.as_ref().ok_or(Error::Busy)?.info;
        self.renew_receive_epoch()?;
        self.stage(Stage::P2pDeviceStop);
        let result = async {
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
            let (device, bss) = device_payloads(info.capabilities.mac, false)?;
            // Linux uni_add_dev disables BSS before DEV. No fresh admin
            // grant is required to clean up an already-owned native wdev.
            self.exchange(Command::Unified { id: 2 }, &bss).await?;
            self.exchange(Command::Unified { id: 1 }, &device).await?;
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

/// Linux mt76_connac_mcu_uni_add_dev's actual P2P-device DEV/BSS basic
/// records. This first add-dev receives the fresh unassigned/default WCID0;
/// it does not invent an associated AP peer, beacon interval or group key.
fn device_payloads(own: [u8; 6], enable: bool) -> Result<([u8; 16], [u8; 36]), Error> {
    if own == [0; 6] || own[0] & 1 != 0 {
        return Err(Error::Bounds);
    }
    let mut device = [0; 16];
    device[6..8].copy_from_slice(&12u16.to_le_bytes());
    device[8] = u8::from(enable);
    device[10..16].copy_from_slice(&own);
    let mut bss = [0; 36];
    bss[6..8].copy_from_slice(&32u16.to_le_bytes());
    bss[8] = u8::from(enable);
    bss[12..16].copy_from_slice(&crate::mt7921::p2p_wire::CONNECTION_P2P_GO.to_le_bytes());
    bss[16] = 1;
    if !enable {
        // The completed wdev now owns the reserved WTBL19. Its removal
        // uses that real assigned identity, unlike the initial add-dev0.
        bss[24..26].copy_from_slice(&19u16.to_le_bytes());
        bss[30..32].copy_from_slice(&19u16.to_le_bytes());
    }
    Ok((device, bss))
}
