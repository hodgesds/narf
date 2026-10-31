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
        (owner.activated && roc.activated).then(|| {
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
        self.check_p2p_request(&authority)?;
        authority.require_mode(10).map_err(|_| Error::Authority)?;
        if !authority.has_reservation() {
            return Err(Error::Authority);
        }
        if !matches!(self.state, State::P2pDevice(_))
            || self.p2p_owner.as_ref().is_none_or(|owner| !owner.activated)
        {
            return Err(Error::Busy);
        }
        // Linux gates ROC, independently of starting the P2P-device BSS.
        if !self.firmware.cnm_capability()? {
            return Err(Error::UnsupportedFirmware);
        }
        // Validate caller inputs before a possible idle-token rebuild too;
        // malformed requests cannot cause physical role/reset side effects.
        if cookie == 0 {
            return Err(Error::Bounds);
        }
        let info = self.p2p_owner.as_ref().ok_or(Error::Busy)?.info;
        let domain = self.backend.regulatory_domain()?;
        let _ = Listen::prepare(info, &domain, frequency_mhz)?;
        let _ = p2p_wire::Request::new(0, 1, frequency_mhz, duration_ms, Kind::Remain)?;
        if self
            .p2p_owner
            .as_ref()
            .is_some_and(|owner| owner.cnm.exhausted())
        {
            // Rebuild the actual idle wdev after verified MAC retirement,
            // rather than wrapping into a delayed old grant or imposing a
            // synthetic lifetime limit on successful ROC requests.
            self.p2p_owner.as_mut().ok_or(Error::Busy)?.pending = Some(authority.clone());
            self.stop_p2p_device_owned().await?;
            self.start_p2p_device(authority.clone()).await?;
            self.commit_p2p_device(&authority)?;
        }
        let info = self.p2p_owner.as_ref().ok_or(Error::Busy)?.info;
        let domain = self.backend.regulatory_domain()?;
        let listen = Listen::prepare(info, &domain, frequency_mhz)?;
        let source = authority.event_authority().map_err(|_| Error::Authority)?;
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        let request = owner
            .cnm
            .reserve(0, cookie, frequency_mhz, duration_ms, Kind::Remain)?;
        owner.pending = Some(authority.clone());
        owner.roc = Some(Roc {
            channel: listen,
            cookie,
            source,
            activated: false,
        });
        self.stage(Stage::P2pRocAcquire);
        let result = async {
            // Keep every firmware channel NO_IR. The CNM grant permits
            // listening, and never substitutes for active TX power/policy.
            let mut domain = if listen.band == crate::mt7921::channel::Band::Ghz6 {
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
                // A delayed grant for an older token or different BSS is
                // not this request. Tokens never wrap before actual reset.
                if event[44] != 0 || event[45] != request.token() {
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
                self.state = State::P2pDevice(info);
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
        roc.channel
            .current(self.backend.regulatory_domain()?.as_ref())
    }
    pub(in crate::mt7921::firmware_transport) fn commit_p2p_roc(
        &mut self,
        authority: &RadioControlAuthority,
    ) -> Result<Receipt, Error> {
        self.check_p2p_request(authority)?;
        self.check_p2p_roc_pending()?;
        let now = self.backend.now_ns();
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        let roc = owner.roc.as_mut().ok_or(Error::Busy)?;
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
        roc.source
            .roc_ready(receipt.cookie, receipt.frequency_mhz, receipt.duration_ms)
            .map_err(|_| Error::Authority)?;
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
                Phase::Granted { interval_ms, .. } if roc.activated => Some((
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
        let info = owner.info;
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
            self.state = State::P2pDevice(info);
            if roc.activated && roc.source.current().is_ok() {
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
}
fn roc_ack(event: &[u8]) -> bool {
    event.len() == 44 && event[28] == 1 && event[30] & 4 == 0 && event[36] == 0x27
}
