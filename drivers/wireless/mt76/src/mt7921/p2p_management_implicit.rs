//! A FRAME without a public ROC owns a real finite native acquisition.
//! The host cookie and admission plan never substitute for a CNM grant.
use super::p2p_management_power::Plan;
use super::*;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_wireless::ap_control::RadioControlAuthority;

#[derive(Clone, Copy, Debug)]
pub(super) struct Owner {
    pub plan: Plan,
    pub home: State,
    pub cookie: u64,
    pub report_armed: bool,
}
impl<B: Backend> Session<B> {
    pub(super) async fn send_p2p_management(
        &mut self,
        authority: Arc<RadioControlAuthority>,
        cookie: u64,
        request: &narf_wireless::MgmtTxRequest,
        cleanup: Arc<AtomicBool>,
    ) -> Result<bool, Error> {
        self.check_p2p_request(&authority)?;
        authority.require_mode(10).map_err(|_| Error::Authority)?;
        if cookie == 0 || request.duration > crate::mt7921::p2p_wire::MAX_DURATION_MS {
            return Err(Error::Bounds);
        }
        if !authority.has_reservation() || !self.p2p_ready() {
            return Err(Error::Busy);
        }
        // A pre-existing public lease keeps its own cookie, deadline and
        // event ownership. Mismatch/pending work never causes replacement.
        if self.p2p_rf_busy() {
            return self.emit_p2p_management_on_roc(authority, request).await;
        }
        if request.frequency_mhz == 0 || !request.offchannel_ok {
            return Err(Error::Bounds);
        }
        if !self.firmware.cnm_capability()? {
            return Err(Error::UnsupportedFirmware);
        }
        let owner = self.p2p_owner.as_ref().ok_or(Error::Busy)?;
        if !owner.activated || owner.management.implicit.is_some() {
            return Err(Error::Busy);
        }
        let header =
            super::p2p_management_tx_wire::Header::prepare(&request.frame, owner.identity.mac())?;
        let info = owner.info;
        let vif = owner.vif;
        let home = self.state;
        let domain = self.backend.regulatory_domain()?;
        let plan = Plan::prepare(
            info,
            domain.as_ref(),
            request.frequency_mhz,
            self.p2p_home_permission()?,
            request.no_cck,
        )?;
        // Quiesce keys/home packets before reserving the new native report
        // PID. A Busy PID never resets or borrows an unrelated BA sample.
        self.quiesce_p2p_home().await?;
        self.check_p2p_request(&authority)?;
        self.check_p2p_management_plan(plan, home)?;
        if !header.multicast {
            self.backend.arm_p2p_management(vif, header.tid)?;
        }
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        owner.management.implicit = Some(Owner {
            plan,
            home,
            cookie,
            report_armed: !header.multicast,
        });
        owner.management.worker_cleanup = Some(cleanup.clone());
        // mac80211 gives a zero-wait management ROC a finite10ms minimum.
        // Firmware may grant less: only the received max_interval governs.
        let duration = if request.duration == 0 {
            10
        } else {
            request.duration
        };
        let result = async {
            self.acquire_p2p_frame_roc(authority.clone(), cookie, request.frequency_mhz, duration)
                .await?;
            self.commit_p2p_frame_roc(&authority)?;
            let ack = self.emit_p2p_management_on_roc(authority, request).await?;
            // Packet/TXS and home-power restore are now terminal. Keep the
            // same worker even if the borrower disappears during no-TX tail.
            cleanup.store(true, Ordering::Release);
            self.stage(Stage::P2pRocExpire);
            self.retain_p2p_frame_response_window(plan, home).await?;
            self.retire_p2p_roc_owned().await?;
            let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
            owner.pending = None;
            owner.management.implicit = None;
            owner.management.worker_cleanup = None;
            self.state = home;
            Ok(ack)
        }
        .await;
        match result {
            Ok(ack) => Ok(ack),
            Err(error) => {
                // Before reserve/publication only our unpublished PID exists.
                // Once CNM may own hardware, use verified reset/retirement.
                if self.p2p_owner.as_ref().is_some_and(|owner| {
                    owner.cnm.lease().is_none()
                        && owner.management.tx.is_none()
                        && owner.management.implicit.is_some()
                }) && self.state == home
                {
                    if !header.multicast {
                        self.backend.cancel_transmit_sequence();
                    }
                    let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
                    owner.management.implicit = None;
                    owner.management.worker_cleanup = None;
                    Err(error)
                } else {
                    Err(self.p2p_failure(error).await)
                }
            }
        }
    }
    async fn retain_p2p_frame_response_window(
        &mut self,
        plan: Plan,
        home: State,
    ) -> Result<(), Error> {
        let expires = match self
            .p2p_owner
            .as_ref()
            .and_then(|owner| owner.cnm.lease())
            .map(|lease| lease.phase)
        {
            Some(crate::mt7921::p2p_cnm::Phase::Granted { expires_ns, .. }) => expires_ns,
            _ => return Err(Error::Busy),
        };
        core::future::poll_fn(|cx| {
            if let Err(error) = self
                .backend
                .check()
                .and_then(|()| self.check_p2p_management_home(plan.home, home))
            {
                return core::task::Poll::Ready(Err(error));
            }
            if self.backend.now_ns() >= expires {
                return core::task::Poll::Ready(Ok(()));
            }
            // No new transmission is permitted here. Keep subscribed raw
            // responses under the exact source/copy-time/grant checks until
            // the real finite deadline. Lost source/listen policy closes RX.
            if let Err(error) = self.service_p2p_management_receive() {
                return core::task::Poll::Ready(Err(error));
            }
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        })
        .await
    }
}
