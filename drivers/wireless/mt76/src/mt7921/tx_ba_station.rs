//! Completed originator protocol/control before native aggregate eligibility.
use super::{station::Command, Backend, Error, Session, Stage, State};

impl<B: Backend> Session<B> {
    /// First fresh-peer TID0 agreement only. Existing QoS sequence state is
    /// never guessed or reset by a midstream retry of this entry point.
    pub(super) async fn negotiate_transmit_ba(&mut self) -> Result<bool, Error> {
        let associated = self.state;
        let State::Associated {
            info,
            peer,
            channel,
            ..
        } = associated
        else {
            return Err(Error::Busy);
        };
        if self.ht20_profile.is_none() || self.wmm.is_none() {
            return Ok(false);
        }
        if self.tid0_used || !self.data_pending.is_empty() || self.data_controls_pending() {
            return Err(Error::Busy);
        }
        self.check_station_tx()?;
        if !self.tx_ba.start(info.capabilities.mac, peer, channel)? {
            return Ok(false);
        }
        self.stage(Stage::StaRecord);
        let result = async {
            self.send_management(&self.tx_ba.request(), 1).await?;
            let started = self.backend.now_ns();
            for _ in 0..2500 {
                self.check_station_tx()?;
                self.poll_originator_frames(associated)?;
                if self.security.as_ref().is_some_and(|s| s.has_pending()) {
                    self.tx_ba.abandon();
                    break;
                }
                if self.tx_ba.offered() || self.tx_ba.abandoned() {
                    break;
                }
                if self.backend.now_ns().saturating_sub(started) >= 1_000_000_000 {
                    self.tx_ba.abandon();
                    break;
                }
                narf_scheduler::yield_now().await;
            }
            if !self.tx_ba.offered() {
                self.retire_transmit_ba(true).await?;
                return Ok(false);
            }
            self.tx_ba.configuring(); // retain uncertainty before first native wait.
            self.exchange_station(Command::Unified { id: 3 }, &self.tx_ba.wtbl(true))
                .await?;
            self.exchange_station(Command::Unified { id: 3 }, &self.tx_ba.station(true))
                .await?;
            self.tx_ba.activate(self.backend.now_ns())?;
            // Control waits may have collected a later peer close, DELBA or
            // key challenge. Process those before handing packets to firmware.
            self.poll_originator_frames(associated)?;
            if self.tx_ba.pending(self.backend.now_ns())
                || self.security.as_ref().is_some_and(|s| s.has_pending())
            {
                self.retire_transmit_ba(true).await?;
                return Ok(false);
            }
            self.check_station_tx()?;
            Ok(true)
        }
        .await;
        match result {
            Ok(active) => {
                self.state = associated;
                Ok(active)
            }
            Err(error) => Err(self.fail_data(error)),
        }
    }
    fn poll_originator_frames(&mut self, associated: State) -> Result<(), Error> {
        let running = self.state;
        // Exclusive borrowed owner: this transient state is never held over
        // an await or published to another producer. RX uses the same genuine
        // peer/HT/security/recipient BA parser as ordinary retained service.
        for _ in 0..64 {
            self.state = associated;
            let result = self.receive_ethernet();
            if self.state == associated {
                self.state = running;
            }
            result?;
            if self.backend.receive_idle()? {
                return Ok(());
            }
        }
        Err(Error::EventOverflow)
    }
    pub(super) async fn service_transmit_ba(&mut self) -> Result<(), Error> {
        self.tx_ba.tick(self.backend.now_ns());
        if self.tx_ba.pending(self.backend.now_ns()) {
            let notify = self.tx_ba.notify();
            self.retire_transmit_ba(notify).await?;
        }
        Ok(())
    }
    pub(super) async fn retire_transmit_ba(&mut self, notify: bool) -> Result<(), Error> {
        if !self.tx_ba.published() && !self.tx_ba.remote() {
            self.tx_ba.fallback();
            return Ok(());
        }
        self.tx_ba.stop(notify);
        // Caller has stopped replenishment and drained every packet proof.
        if !self.data_pending.is_empty() {
            return Err(Error::Busy);
        }
        if self.tx_ba.published() {
            self.exchange(Command::Unified { id: 3 }, &self.tx_ba.wtbl(false))
                .await?;
            self.exchange(Command::Unified { id: 3 }, &self.tx_ba.station(false))
                .await?;
        }
        if self.tx_ba.notify() && self.tx_ba.remote() {
            self.send_management(&self.tx_ba.delba(), 1).await?;
        }
        self.tx_ba.fallback();
        Ok(())
    }
}
