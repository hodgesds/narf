//! Native CNM acquire/grant and finite receive-only ROC lifetime.
use super::*;
use crate::mt7921::{
    p2p_cnm::Phase,
    p2p_wire::{self, Kind},
};
use narf_wireless::ap_control::RadioEventAuthority;
#[path = "p2p_channel.rs"]
mod admission;
use admission::Listen;
#[path = "p2p_cancel.rs"]
mod cancel;

#[derive(Debug)]
pub(super) struct Roc {
    channel: Listen,
    cookie: u64,
    source: RadioEventAuthority,
    activated: bool,
    public_events: bool,
    home_permission: Option<crate::mt7921::association::TxPermission>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub cookie: u64,
    pub frequency_mhz: u32,
    pub duration_ms: u32,
}
impl<B: Backend> Session<B> {
    /// Retained facts only; callers may notify expiry solely after proving
    /// native stop/reset. This is not an abort or terminal receipt itself.
    pub(in crate::mt7921::firmware_transport) fn p2p_stop_roc_notification(
        &self,
    ) -> Option<(RadioEventAuthority, Receipt)> {
        let owner = self.p2p_owner.as_ref()?;
        let roc = owner.roc.as_ref()?;
        let lease = owner.cnm.lease()?;
        let Phase::Granted { interval_ms, .. } = lease.phase else {
            return None;
        };
        (owner.activated && roc.activated && roc.public_events).then(|| {
            (
                roc.source.clone(),
                Receipt {
                    cookie: lease.cookie,
                    frequency_mhz: lease.frequency_mhz,
                    duration_ms: interval_ms,
                },
            )
        })
    }
    pub(in crate::mt7921::firmware_transport) fn p2p_roc_current(
        &self,
        cookie: u64,
        frequency_mhz: u32,
    ) -> Result<bool, Error> {
        self.backend.check()?;
        let Some(owner) = self.p2p_owner.as_ref() else {
            return Ok(false);
        };
        let Some(roc) = owner.roc.as_ref() else {
            return Ok(false);
        };
        let domain = self.backend.regulatory_domain()?;
        Ok(owner.activated
            && roc.activated
            && owner.identity.current().is_ok()
            && roc.source.current().is_ok()
            && roc.channel.current(&domain).is_ok()
            && owner
                .cnm
                .current(cookie, frequency_mhz, self.backend.now_ns()))
    }
    pub(in crate::mt7921::firmware_transport) async fn acquire_p2p_roc(
        &mut self,
        authority: Arc<RadioControlAuthority>,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<u32, Error> {
        self.acquire_p2p_roc_inner(authority, cookie, frequency_mhz, duration_ms, true, false)
            .await
    }
    pub(in crate::mt7921::firmware_transport) async fn acquire_p2p_frame_roc(
        &mut self,
        authority: Arc<RadioControlAuthority>,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<u32, Error> {
        self.acquire_p2p_roc_inner(authority, cookie, frequency_mhz, duration_ms, false, true)
            .await
    }
    async fn acquire_p2p_roc_inner(
        &mut self,
        authority: Arc<RadioControlAuthority>,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
        public_events: bool,
        quiesced: bool,
    ) -> Result<u32, Error> {
        self.check_p2p_request(&authority)?;
        authority.require_mode(10).map_err(|_| Error::Authority)?;
        if !authority.has_reservation() {
            return Err(Error::Authority);
        }
        if !self.p2p_ready() || self.p2p_owner.as_ref().is_none_or(|owner| !owner.activated) {
            return Err(Error::Busy);
        }
        // Linux gates ROC, independently of starting the P2P-device BSS.
        if !self.firmware.cnm_capability()? {
            return Err(Error::UnsupportedFirmware);
        }
        // Reject invalid requests before changing the native radio owner.
        if cookie == 0 {
            return Err(Error::Bounds);
        }
        let info = self.p2p_owner.as_ref().ok_or(Error::Busy)?.info;
        let domain = self.backend.regulatory_domain()?;
        let _ = Listen::prepare(info, &domain, frequency_mhz)?;
        let _ = p2p_wire::Request::new(0, 1, frequency_mhz, duration_ms, Kind::Remain)?;
        // The scheduled scan's firmware cycles own the radio's off-channel
        // time: as the scheduled-scan start refuses a pending ROC, a ROC
        // (listen or off-channel action) waits for the scan's stop.
        if self.p2p_rf_busy() || self.sched_scan_running() {
            return Err(Error::Busy);
        }
        if !quiesced {
            self.quiesce_p2p_home().await?;
        }
        self.check_p2p_request(&authority)?;
        let home = self.state;
        let home_permission = self.p2p_home_permission()?;
        let domain = self.backend.regulatory_domain()?;
        let listen = Listen::prepare(info, &domain, frequency_mhz)?;
        let source = authority.event_authority().map_err(|_| Error::Authority)?;
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        let request = owner.cnm.reserve(
            owner.vif.index(),
            cookie,
            frequency_mhz,
            duration_ms,
            Kind::Remain,
        )?;
        self.p2p_next = owner.cnm.next_token();
        owner.pending = Some(authority.clone());
        owner.roc = Some(Roc {
            channel: listen,
            cookie,
            source,
            activated: false,
            public_events,
            home_permission,
        });
        self.stage(Stage::P2pRocAcquire);
        let result = async {
            // The listen grant adds no TX permission. Preserve only the
            // actual occupied home-channel grant when another BSS is live;
            // all other firmware channels remain NO_IR.
            let six = listen.band == crate::mt7921::channel::Band::Ghz6;
            let mut domain = if let Some(permission) = home_permission {
                super::super::scan::occupied_domain(info, permission, six)?
            } else if six {
                super::super::scan::passive_domain_6ghz(info)
            } else {
                super::super::scan::passive_domain(info)
            };
            domain[..2].copy_from_slice(&listen.country);
            self.notify(
                Command::Ce {
                    id: 0x0f,
                    query: false,
                },
                &domain,
            )
            .await?;
            self.confirm_command_progress().await?;
            self.check_p2p_roc_pending()?;
            // CONNAC2 always encodes unified option7, even when Linux's
            // send_msg waits=false. Its ACK/DMA/PSE progress is no grant.
            self.notify(
                Command::Unified {
                    id: p2p_wire::UNIFIED_ROC,
                },
                &request.acquire(),
            )
            .await?;
            let began = self.backend.now_ns();
            loop {
                self.check_p2p_roc_pending()?;
                let left =
                    1_000_000_000u64.saturating_sub(self.backend.now_ns().saturating_sub(began));
                if left < 1_000_000 {
                    return Err(Error::Timeout);
                }
                let queued = self
                    .events
                    .iter()
                    .position(|event| event.get(28) == Some(&0x27));
                let mut event = if let Some(index) = queued {
                    self.events.remove(index).ok_or(Error::Ring)?
                } else {
                    self.wait(left / 1_000_000, Backend::receive).await?
                };
                if event.len() < 36 {
                    return Err(Error::MalformedEvent);
                }
                let length = usize::from(u16::from_le_bytes([event[24], event[25]])) + 24;
                if length < 36 || length > event.len() {
                    return Err(Error::MalformedEvent);
                }
                event.truncate(length);
                if event[28] != 0x27 {
                    if roc_ack(&event) {
                        continue;
                    }
                    if self.events.len() == super::super::MAX_EVENTS {
                        return Err(Error::EventOverflow);
                    }
                    self.events.push_back(event);
                    continue;
                }
                if length != 60 || event[30] & 4 == 0 {
                    return Err(Error::MalformedEvent);
                }
                // A foreign/delayed grant is not this request. The source
                // ABI has one outstanding acquisition and one terminal grant;
                // successful finite retirement, unlike timeout/ambiguity,
                // permits normal opaque-u8 recycling as Linux does.
                let bss = self.p2p_owner.as_ref().ok_or(Error::Busy)?.vif.index();
                if event[44] != bss || event[45] != request.token() {
                    continue;
                }
                let now = self.backend.now_ns();
                let duration = self
                    .p2p_owner
                    .as_mut()
                    .ok_or(Error::Busy)?
                    .cnm
                    .grant(&event[36..], now)?;
                self.check_p2p_roc_pending()?;
                return Ok(duration);
            }
        }
        .await;
        match result {
            Ok(duration) => {
                self.state = home;
                Ok(duration)
            }
            Err(error) => Err(self.p2p_failure(error).await),
        }
    }
    pub(in crate::mt7921::firmware_transport) fn check_p2p_roc_pending(&self) -> Result<(), Error> {
        self.backend.check()?;
        let owner = self.p2p_owner.as_ref().ok_or(Error::Busy)?;
        let authority = owner.pending.as_ref().ok_or(Error::Authority)?;
        self.check_p2p_request(authority)?;
        let roc = owner.roc.as_ref().ok_or(Error::Busy)?;
        roc.source.current().map_err(|_| Error::Authority)?;
        if let Some(permission) = roc.home_permission {
            self.backend.check_tx_permission(permission)?;
        }
        roc.channel
            .current(self.backend.regulatory_domain()?.as_ref())?;
        if let Some(implicit) = owner.management.implicit {
            if roc.public_events
                || implicit.cookie != roc.cookie
                || implicit.plan.frequency_mhz != roc.channel.frequency_mhz
            {
                return Err(Error::Authority);
            }
            self.check_p2p_management_plan(implicit.plan, implicit.home)?;
        }
        Ok(())
    }
    pub(in crate::mt7921::firmware_transport) fn commit_p2p_roc(
        &mut self,
        authority: &RadioControlAuthority,
    ) -> Result<Receipt, Error> {
        self.commit_p2p_roc_inner(authority, true)
    }
    pub(in crate::mt7921::firmware_transport) fn commit_p2p_frame_roc(
        &mut self,
        authority: &RadioControlAuthority,
    ) -> Result<Receipt, Error> {
        self.commit_p2p_roc_inner(authority, false)
    }
    fn commit_p2p_roc_inner(
        &mut self,
        authority: &RadioControlAuthority,
        public_events: bool,
    ) -> Result<Receipt, Error> {
        self.check_p2p_request(authority)?;
        self.check_p2p_roc_pending()?;
        let now = self.backend.now_ns();
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        let roc = owner.roc.as_mut().ok_or(Error::Busy)?;
        if roc.public_events != public_events {
            return Err(Error::Authority);
        }
        if !owner
            .cnm
            .current(roc.cookie, roc.channel.frequency_mhz, now)
        {
            return Err(Error::Timeout);
        }
        let duration_ms = match owner.cnm.lease().ok_or(Error::Busy)?.phase {
            Phase::Granted { interval_ms, .. } => interval_ms,
            _ => return Err(Error::Busy),
        };
        let receipt = Receipt {
            cookie: roc.cookie,
            frequency_mhz: roc.channel.frequency_mhz,
            duration_ms,
        };
        // The same current source still owns terminal publication after a
        // possible reentrant event sink. Only then shed serialization.
        authority.current().map_err(|_| Error::Authority)?;
        roc.source.current().map_err(|_| Error::Authority)?;
        self.backend.check()?;
        let domain = self.backend.regulatory_domain()?;
        roc.channel.current(&domain)?;
        if !owner
            .cnm
            .current(roc.cookie, roc.channel.frequency_mhz, self.backend.now_ns())
        {
            return Err(Error::Timeout);
        }
        roc.activated = true;
        owner.pending = None;
        let source = roc.source.clone();
        self.refresh_p2p_management_capture()?;
        if public_events {
            source
                .roc_ready(receipt.cookie, receipt.frequency_mhz, receipt.duration_ms)
                .map_err(|_| Error::Authority)?;
        }
        authority.current().map_err(|_| Error::Authority)?;
        source.current().map_err(|_| Error::Authority)?;
        if !self.p2p_roc_current(receipt.cookie, receipt.frequency_mhz)? {
            return Err(Error::Authority);
        }
        Ok(receipt)
    }
    pub(in crate::mt7921::firmware_transport) async fn expire_p2p_roc(
        &mut self,
    ) -> Result<bool, Error> {
        self.backend.check()?;
        let owner = self.p2p_owner.as_ref().ok_or(Error::Busy)?;
        let Some(roc) = &owner.roc else {
            return Ok(false);
        };
        let policy_current = self
            .backend
            .regulatory_domain()
            .is_ok_and(|domain| roc.channel.current(&domain).is_ok());
        if owner.identity.current().is_err() || roc.source.current().is_err() || !policy_current {
            let notify = owner.cnm.lease().and_then(|lease| match lease.phase {
                Phase::Granted { interval_ms, .. } if roc.activated && roc.public_events => Some((
                    roc.source.clone(),
                    Receipt {
                        cookie: lease.cookie,
                        frequency_mhz: lease.frequency_mhz,
                        duration_ms: interval_ms,
                    },
                )),
                _ => None,
            });
            self.stop_p2p_device_owned().await?;
            self.backend.check()?;
            if let Some((source, receipt)) = notify {
                if source.current().is_ok() {
                    source
                        .roc_expired(receipt.cookie, receipt.frequency_mhz, receipt.duration_ms)
                        .map_err(|_| Error::Authority)?;
                }
            }
            return Ok(true);
        }
        let now = self.backend.now_ns();
        if !owner.cnm.expired(now) {
            return Ok(false);
        }
        let home = self.state;
        let abort = owner.cnm.lease().ok_or(Error::Busy)?.request.abort();
        self.poll_data_tx()?;
        if !self.data_pending.is_empty() {
            return Ok(false);
        }
        self.stage(Stage::P2pRocExpire);
        let result = async {
            self.notify(
                Command::Unified {
                    id: p2p_wire::UNIFIED_ROC,
                },
                &abort,
            )
            .await?;
            self.confirm_command_progress().await?;
            // Unified ACK option is set by the source builder even for
            // wait=false. Retire these inert ROC ACKs; keeping them forever
            // would invent a small successful-request lifetime limit.
            self.events.retain(|event| !roc_ack(event));
            let now = self.backend.now_ns();
            let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
            let lease = owner.cnm.release_expired_after_packets(now)?;
            let roc = owner.roc.take().ok_or(Error::Busy)?;
            self.state = home;
            if roc.activated && roc.public_events && roc.source.current().is_ok() {
                let duration = match lease.phase {
                    Phase::Granted { interval_ms, .. } => interval_ms,
                    _ => return Err(Error::Busy),
                };
                roc.source
                    .roc_expired(lease.cookie, lease.frequency_mhz, duration)
                    .map_err(|_| Error::Authority)?;
            }
            Ok(true)
        }
        .await;
        match result {
            Ok(value) => Ok(value),
            Err(error) => Err(self.p2p_failure(error).await),
        }
    }

    /// Stop/cancel has no firmware terminal-abort event. For an actual
    /// granted lease, retain host/RF/token ownership through its observed
    /// finite deadline, native packet retirement and ordered owned abort.
    /// Ambiguous acquisitions require the separate verified reset path.
    pub(in crate::mt7921::firmware_transport) async fn retire_p2p_roc_owned(
        &mut self,
    ) -> Result<(), Error> {
        self.close_p2p_management_capture();
        let Some(lease) = self.p2p_owner.as_ref().and_then(|owner| owner.cnm.lease()) else {
            return Ok(());
        };
        let Phase::Granted { expires_ns, .. } = lease.phase else {
            return Err(Error::Busy);
        };
        let abort = lease.request.abort();
        if let Some(roc) = self.p2p_owner.as_mut().and_then(|owner| owner.roc.as_mut()) {
            roc.activated = false;
        }
        self.notify(
            Command::Unified {
                id: p2p_wire::UNIFIED_ROC,
            },
            &abort,
        )
        .await?;
        self.confirm_command_progress().await?;
        let left = expires_ns.saturating_sub(self.backend.now_ns());
        self.wait(left.div_ceil(1_000_000).saturating_add(1), |backend| {
            Ok((backend.now_ns() >= expires_ns).then_some(()))
        })
        .await?;
        self.quiesce_p2p_packets().await?;
        self.events.retain(|event| !roc_ack(event));
        let now = self.backend.now_ns();
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        owner.cnm.release_expired_after_packets(now)?;
        owner.roc = None;
        Ok(())
    }

    pub(in crate::mt7921::firmware_transport) fn p2p_home_permission(
        &self,
    ) -> Result<Option<crate::mt7921::association::TxPermission>, Error> {
        let permission = match self.state {
            State::Associated { .. } => Some(self.station.permission.ok_or(Error::Authority)?),
            State::AccessPoint { .. } => {
                let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
                owner.identity.current().map_err(|_| Error::Authority)?;
                Some(owner.plan.permission)
            }
            _ => None,
        };
        if let Some(permission) = permission {
            self.backend.check_tx_permission(permission)?;
        }
        Ok(permission)
    }
    pub(in crate::mt7921::firmware_transport) async fn quiesce_p2p_home(
        &mut self,
    ) -> Result<(), Error> {
        self.quiesce_p2p_packets().await?;
        if matches!(self.state, State::Associated { .. }) {
            self.service_keys().await?;
        }
        self.quiesce_p2p_packets().await
    }
    pub(in crate::mt7921::firmware_transport) async fn quiesce_p2p_packets(
        &mut self,
    ) -> Result<(), Error> {
        let began = self.backend.now_ns();
        core::future::poll_fn(|cx| {
            if let Err(error) = self.poll_data_tx() {
                return core::task::Poll::Ready(Err(error));
            }
            if self.data_pending.is_empty() && self.station.tx_fragments.is_empty() {
                return core::task::Poll::Ready(Ok(()));
            }
            if self.backend.now_ns().saturating_sub(began) >= super::super::TIMEOUT_MS * 1_000_000 {
                return core::task::Poll::Ready(Err(Error::Timeout));
            }
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        })
        .await
    }
}
fn roc_ack(event: &[u8]) -> bool {
    event.len() == 44 && event[28] == 1 && event[30] & 4 == 0 && event[36] == 0x27
}
