//! Native VDEV RTS/CTS intent, following ath10k/mac.c::set_rts_threshold,
//! recalc_rtscts_prot and mac_set_cts_prot. CE submission is not an air ACK.
use super::*;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// None encodes the Linux disabled threshold (u32::MAX);0 forces RTS.
    pub rts_threshold: Option<u16>,
    /// The native use_cts_prot boolean; never an IEEE HT-operation enum.
    pub cts_protection: bool,
}
impl Request {
    pub(super) const HT40: Self = Self {
        rts_threshold: Some(0),
        cts_protection: false,
    };
}
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub fn submitted_station_protection(&self) -> Option<Request> {
        (!self.failed).then_some(self.protection).flatten()
    }
    pub(in crate::ath10k) async fn set_station_protection(
        &mut self,
        request: Request,
        current: impl Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error>,
    ) -> Result<Request, Error> {
        if request.rts_threshold.is_some_and(|n| n > 2347) {
            return Err(Error::Unsupported);
        }
        let peer = self.peer.as_ref().ok_or(Error::Failed)?;
        if self.failed
            || peer.associated.is_none()
            || peer.mapped().is_none()
            || self.data.as_ref().is_some_and(|d| !d.protection_allowed())
        {
            return Err(Error::Failed);
        }
        if peer
            .ht
            .is_some_and(|h| h.secondary.is_some() && h.protection_required())
            && request.rts_threshold != Some(0)
        {
            return Err(Error::Unsupported);
        }
        let permission = peer.permission;
        let source = self.htt.wmi.htc.transport.current_sources();
        let validate = || permission.check(&current()?);
        validate()?;
        self.htt
            .wmi
            .htc
            .transport
            .check_current()
            .map_err(crate::ath10k::control::Error::from)
            .map_err(htt::Error::from)?;
        let commands = self.wire.protection(request)?;
        // Reserve before any native wait. Cancellation cannot return the
        // still-programmed owner to ordinary packet admission.
        self.failed = true;
        let deadline = narf_time::Deadline::after_ms(3000);
        let mut drained = false;
        for _ in 0..4096 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = checked_policy(self.station_progress(), &validate).await?;
            if self
                .peer
                .as_ref()
                .is_none_or(|p| p.associated.is_none() || p.mapped().is_none())
            {
                return Err(Error::Failed);
            }
            while let Some(receipt) = self.htt.take_tx_receipt() {
                if let Some(data) = &mut self.data {
                    data.protection_receipt(receipt)?;
                }
            }
            let idle = matches!(event, htt::Event::Idle);
            if !matches!(event, htt::Event::Idle | htt::Event::Progress) {
                self.queue(event)?;
            }
            if idle
                && self.data.as_ref().is_none_or(|d| d.protection_idle())
                && self.htt.source_ready()?
            {
                drained = true;
                break;
            }
            narf_scheduler::yield_now().await;
        }
        if !drained {
            return Err(Error::Exhausted);
        }
        for command in commands {
            checked_policy(
                async {
                    self.htt
                        .wmi
                        .htc
                        .send_wmi(&command)
                        .await
                        .map_err(htt::Error::from)?;
                    Ok(())
                },
                &validate,
            )
            .await?;
        }
        // Consume only the completed native prefix; this is not a MAC/FIFO
        // quiescence or firmware-parameter ACK. Retain every peer/control RX.
        let mut settled = false;
        for _ in 0..4096 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = checked_policy(self.station_progress(), &validate).await?;
            if self
                .peer
                .as_ref()
                .is_none_or(|p| p.associated.is_none() || p.mapped().is_none())
            {
                return Err(Error::Failed);
            }
            if matches!(event, htt::Event::Idle) {
                settled = true;
                break;
            }
            if !matches!(event, htt::Event::Progress) {
                self.queue(event)?;
            }
            narf_scheduler::yield_now().await;
        }
        if !settled {
            return Err(Error::Exhausted);
        }
        validate()?;
        crate::ath10k::firmware_source::invoke(source.as_ref(), || {
            self.protection = Some(request);
            self.failed = false;
        })
        .map_err(|_| Error::Failed)?;
        Ok(request)
    }
}
