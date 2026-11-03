//! A midstream restart samples a real queued user MPDU. No invented RF
//! traffic or guessed host sequence can advance this retained owner.
use super::{Backend, Error, Session, Stage, State};

#[derive(Clone, Copy, Debug)]
pub(super) struct Request {
    pub tid: u8,
    epoch: u64,
    since: Option<u64>,
}
impl Request {
    pub fn waiting_receipt(self) -> bool {
        self.since.is_some()
    }
}
impl<B: Backend> Session<B> {
    /// Queue one restart after all earlier native packets retire. The next
    /// actual user MPDU (or final fragment) is sampled; no executor task is
    /// awaited for traffic that does not yet exist.
    pub(super) async fn request_transmit_ba_restart_tid(&mut self, tid: u8) -> Result<(), Error> {
        if tid >= 8 {
            return Err(Error::Bounds);
        }
        let associated = self.state;
        if !matches!(associated, State::Associated { .. })
            || self.station.ht20_profile.is_none()
            || self.station.wmm.is_none()
            || self.station.tx_restart.is_some()
            || !self.data_pending.is_empty()
            || !self.station.tx_fragments.is_empty()
            || self.data_controls_pending()
        {
            return Err(Error::Busy);
        }
        self.check_station_tx()?;
        // Native arm independently proves its whole token queue empty. It
        // reserves a distinct PID; ambiguous published cancellation cannot
        // make it reusable before full firmware retirement.
        self.backend.arm_transmit_sequence(tid)?;
        self.station.tx_restart = Some(Request {
            tid,
            epoch: self.receive_epoch,
            since: None,
        });
        self.stage(Stage::StaRecord);
        let result = async {
            self.retire_transmit_ba_tid(tid, true).await?;
            self.check_station_tx()?;
            self.poll_originator_frames(associated)?;
            if self.station.peer_lost {
                return Err(Error::DeviceGone);
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.state = associated;
                Ok(())
            }
            Err(error) => Err(self.fail_data(error)),
        }
    }
    pub(super) fn restart_blocks(&self, tid: u8) -> bool {
        self.station.tx_restart.is_some_and(|request| {
            request.tid == tid && (request.since.is_some() || !self.data_pending.is_empty())
        })
    }
    pub(super) fn note_sequence_publication(&mut self, tid: u8) {
        if let Some(request) = self
            .station
            .tx_restart
            .as_mut()
            .filter(|request| request.tid == tid && request.since.is_none())
        {
            if self.backend.transmit_sequence_published(tid) {
                request.since = Some(self.backend.now_ns());
            }
        }
    }
    pub(super) fn cancel_transmit_ba_restart(&mut self) {
        if self.station.tx_restart.take().is_some() {
            self.backend.cancel_transmit_sequence();
        }
    }
    pub(super) async fn service_transmit_ba_restart(
        &mut self,
        associated: State,
        restore: State,
    ) -> Result<(), Error> {
        let Some(request) = self.station.tx_restart else {
            return Ok(());
        };
        if request.epoch != self.receive_epoch
            || self.station.peer_lost
            || self
                .station
                .security
                .as_ref()
                .is_some_and(|security| security.has_pending())
        {
            self.cancel_transmit_ba_restart();
            return Ok(());
        }
        let Some(since) = request.since else {
            return Ok(());
        };
        // Both native packet receipts must be terminal before the reported
        // sequence can define the next ADDBA window. Other TIDs may queue;
        // this conservative bound drains them too before management setup.
        if !self.data_pending.is_empty() {
            return Ok(());
        }
        if self.backend.now_ns().saturating_sub(since) >= 3_000_000_000 {
            return Err(self.fail_data(Error::Timeout));
        }
        if self.data_controls_pending() {
            return Ok(());
        }
        let observed = match self.backend.poll_transmit_sequence(request.tid) {
            Ok(value) => value,
            Err(error) => return Err(self.fail_data(error)),
        };
        let Some(observed) = observed else {
            return Ok(());
        };
        // Keep same-TID publication fenced across all protocol/native waits.
        // The real observation is consumed once; only the ADDBA starting
        // sequence uses next SN. Linux's TX_OPERATIONAL WTBL SN stays zero.
        let next = (observed + 1) & 0x0fff;
        let result = self
            .negotiate_transmit_ba_tid_at(associated, restore, request.tid, Some(next))
            .await;
        self.station.tx_restart = None;
        result.map(|_| ())
    }
}
