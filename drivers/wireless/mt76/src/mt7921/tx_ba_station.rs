//! Completed originator protocol/control before native aggregate eligibility.
use super::{station::Command, Backend, Error, Session, Stage, State};

impl<B: Backend> Session<B> {
    /// First fresh-peer TID0 agreement only. Existing QoS sequence state is
    /// never guessed or reset by a midstream retry of this entry point.
    pub(super) async fn negotiate_transmit_ba(&mut self) -> Result<bool, Error> {
        self.negotiate_transmit_ba_tid(0).await
    }
    /// A separate immediate agreement for each admitted QoS TID. A TID
    /// whose hardware sequence has already advanced is still refused.
    pub(super) async fn negotiate_transmit_ba_tid(&mut self, tid: u8) -> Result<bool, Error> {
        let associated = self.state;
        self.negotiate_transmit_ba_tid_at(associated, associated, tid, None)
            .await
    }
    /// `ssn` exists only after the retained native sample owner completed.
    pub(super) async fn negotiate_transmit_ba_tid_at(
        &mut self,
        associated: State,
        restore: State,
        tid: u8,
        ssn: Option<u16>,
    ) -> Result<bool, Error> {
        if tid >= 8 {
            return Err(Error::Bounds);
        }
        let State::Associated {
            info,
            peer,
            channel,
            ..
        } = associated
        else {
            return Err(Error::Busy);
        };
        if self.station.ht20_profile.is_none() || self.station.wmm.is_none() {
            return Ok(false);
        }
        if (ssn.is_none() && self.station.used_tids & (1 << tid) != 0)
            || !self.data_pending.is_empty()
            || self.data_controls_pending()
        {
            return Err(Error::Busy);
        }
        self.check_station_tx()?;
        let started = match ssn {
            Some(ssn) => self.station.tx_ba.get_mut(tid)?.restart(
                info.capabilities.mac,
                peer,
                channel,
                ssn,
            )?,
            None => self
                .station
                .tx_ba
                .get_mut(tid)?
                .start(info.capabilities.mac, peer, channel)?,
        };
        if !started {
            return Ok(false);
        }
        self.stage(Stage::StaRecord);
        let result = async {
            self.send_management(
                &self.station.tx_ba.get(tid)?.request(),
                u16::from(self.station.link.peer()),
            )
            .await?;
            let started = self.backend.now_ns();
            for _ in 0..2500 {
                self.check_station_tx()?;
                self.poll_originator_frames(associated)?;
                if self
                    .station
                    .security
                    .as_ref()
                    .is_some_and(|s| s.has_pending())
                {
                    self.station.tx_ba.get_mut(tid)?.abandon();
                    break;
                }
                if self.station.tx_ba.get(tid)?.offered()
                    || self.station.tx_ba.get(tid)?.abandoned()
                {
                    break;
                }
                if self.backend.now_ns().saturating_sub(started) >= 1_000_000_000 {
                    self.station.tx_ba.get_mut(tid)?.abandon();
                    break;
                }
                narf_scheduler::yield_now().await;
            }
            if !self.station.tx_ba.get(tid)?.offered() {
                self.retire_transmit_ba_tid(tid, true).await?;
                return Ok(false);
            }
            self.station.tx_ba.get_mut(tid)?.configuring(); // retain uncertainty before first native wait.
            self.exchange_station(
                Command::Unified { id: 3 },
                &self.station.tx_ba.get(tid)?.wtbl(self.station.link, true),
            )
            .await?;
            self.exchange_station(
                Command::Unified { id: 3 },
                &self
                    .station
                    .tx_ba
                    .get(tid)?
                    .station(self.station.link, true),
            )
            .await?;
            self.station
                .tx_ba
                .get_mut(tid)?
                .activate(self.backend.now_ns())?;
            // Control waits may have collected a later peer close, DELBA or
            // key challenge. Process those before handing packets to firmware.
            self.poll_originator_frames(associated)?;
            if self.station.tx_ba.get(tid)?.pending(self.backend.now_ns())
                || self
                    .station
                    .security
                    .as_ref()
                    .is_some_and(|s| s.has_pending())
            {
                self.retire_transmit_ba_tid(tid, true).await?;
                return Ok(false);
            }
            self.check_station_tx()?;
            Ok(true)
        }
        .await;
        match result {
            Ok(active) => {
                self.state = restore;
                Ok(active)
            }
            Err(error) => Err(self.fail_data(error)),
        }
    }
    pub(super) fn poll_originator_frames(&mut self, associated: State) -> Result<(), Error> {
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
        self.station.tx_ba.tick(self.backend.now_ns());
        for tid in 0..8 {
            if self.station.tx_ba.get(tid)?.pending(self.backend.now_ns()) {
                let notify = self.station.tx_ba.get(tid)?.notify();
                self.retire_transmit_ba_tid(tid, notify).await?;
            }
        }
        Ok(())
    }
    pub(super) async fn retire_transmit_ba(&mut self, notify: bool) -> Result<(), Error> {
        for tid in 0..8 {
            self.retire_transmit_ba_tid(tid, notify).await?;
        }
        Ok(())
    }
    pub(super) async fn retire_transmit_ba_tid(
        &mut self,
        tid: u8,
        notify: bool,
    ) -> Result<(), Error> {
        let agreement = self.station.tx_ba.get_mut(tid)?;
        if !agreement.published() && !agreement.remote() {
            agreement.fallback();
            return Ok(());
        }
        agreement.stop(notify);
        // Caller has stopped replenishment and drained every packet proof.
        if !self.data_pending.is_empty() {
            return Err(Error::Busy);
        }
        if self.station.tx_ba.get(tid)?.published() {
            self.exchange(
                Command::Unified { id: 3 },
                &self.station.tx_ba.get(tid)?.wtbl(self.station.link, false),
            )
            .await?;
            self.exchange(
                Command::Unified { id: 3 },
                &self
                    .station
                    .tx_ba
                    .get(tid)?
                    .station(self.station.link, false),
            )
            .await?;
        }
        if self.station.tx_ba.get(tid)?.notify() && self.station.tx_ba.get(tid)?.remote() {
            self.send_management(
                &self.station.tx_ba.get(tid)?.delba(),
                u16::from(self.station.link.peer()),
            )
            .await?;
        }
        self.station.tx_ba.get_mut(tid)?.fallback();
        Ok(())
    }
}
