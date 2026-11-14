// SPDX-License-Identifier: GPL-2.0-or-later
//! `station::Engine` for the AR9300 EDMA owner. The legacy station path
//! (start, one queue-0 frame, delivery, HP/LP receive, interrupts, the
//! port's periodic calibration and the terminal stop) delegates to the
//! inherent EDMA methods; `Delivery` and `ReceiveStep` are the shared
//! station types already.
//!
//! This owner carries no HT, EDCA, QoS, block-ack, aggregation or power-save
//! program (no AR9003 `ar9003_txc` HT/aggregate encoding, no measured
//! records for them). Every such operation returns exactly what the AR9002
//! `packet::Packet` returns when that program is absent: no grant is
//! offered (`None`), so `station::Radio` never attempts them, and a direct
//! call fails with the AR9002 error for the missing program (`State`,
//! `Packet` for HT data, `Access` for `set_ht` without an HT grant).
use super::{Packet, Phase};
use crate::ath9k::{
    channel_width::Geometry,
    channels, ht, irq,
    packet::{Delivery, Error, PairDelivery, Port, ReceiveStep},
    ps, qos, rates, rx_ba, station, tx_ba,
};
use alloc::{sync::Arc, vec::Vec};
use narf_wireless::association::phy::Offer;

/// AR9002 `submit`/`submit_rates`: a PM-marked frame needs the power-save
/// program (`descriptor::ps_unmark` under `ps`), which is absent here.
fn unmarked(frame: &[u8]) -> Result<(), Error> {
    if frame.get(1).is_some_and(|flag| flag & 0x10 != 0) {
        return Err(Error::State);
    }
    Ok(())
}

/// The station's view of `ar9003_hw_get_isr`'s causes: RX is either FIFO
/// (`ATH9K_INT_RXHP | ATH9K_INT_RXLP`); EDMA never fills `ah->intr_txqs`
/// (TX completion is the status ring), and the AR9300 imask carries no
/// `ATH9K_INT_TIM_TIMER` (no power-save program). FATAL and the BB
/// watchdog already failed the owner in `service_begin`, queueing an
/// in-place reset (`reset_request`).
fn shared_events(events: super::irq::Events) -> irq::Events {
    irq::Events {
        rx: events.rx_hp || events.rx_lp,
        tx: events.tx,
        txqs: 0,
        rx_eol: events.rx_eol,
        rx_overrun: events.rx_overrun,
        fatal: events.fatal,
        tim_timer: false,
        bmiss: events.bmiss,
        tsf_oor: events.tsf_oor,
        sync_cause: events.sync_cause,
    }
}

impl<P: Port> station::Engine for Packet<P> {
    fn phase(&self) -> Phase {
        Packet::phase(self)
    }
    fn reclaimed(&self) -> bool {
        Packet::reclaimed(self)
    }
    fn idle_admissible(&self) -> bool {
        Packet::idle_admissible(self)
    }
    fn check_transmit(&self) -> Result<(), Error> {
        Packet::check_transmit(self)
    }
    fn geometry(&self) -> Geometry {
        self.port.geometry()
    }
    fn frequency_mhz(&self) -> u16 {
        self.port.frequency_mhz()
    }
    fn channel_mask(&self) -> u64 {
        self.port.channel_mask()
    }
    fn channel(&self) -> u8 {
        channels::channel(self.port.frequency_mhz()).unwrap_or(0)
    }
    fn ht_grant(&self) -> Option<Arc<ht::Grant>> {
        None
    }
    fn rx_ba_grant(&self) -> Option<Arc<rx_ba::Grant>> {
        None
    }
    fn ps_grant(&self) -> Option<Arc<ps::Grant>> {
        None
    }
    fn enable_ps(&mut self, _source: &Arc<ps::Grant>) -> Result<(), Error> {
        Err(Error::State)
    }
    fn ps_receive_on(&self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn ps_timers(&mut self, _plan: ps::tim::Plan) -> Result<(), Error> {
        Err(Error::State)
    }
    fn ps_awake_mode(&mut self) -> Result<(), Error> {
        Err(Error::State)
    }
    fn ps_sleep(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || self.pending.is_some() {
            return Err(Error::Busy);
        }
        Packet::check_transmit(self)?;
        Err(Error::State)
    }
    fn ps_tsf(&self) -> Result<u64, Error> {
        Err(Error::State)
    }
    fn submit_ps(
        &mut self,
        _frame: &[u8],
        _ap: [u8; 6],
        _aid: u16,
        _basic: usize,
    ) -> Result<u64, Error> {
        Err(Error::State)
    }
    fn tx_ba_grant(&self) -> Option<Arc<tx_ba::Grant>> {
        None
    }
    fn enable_tx_ba(&mut self, _grant: &Arc<tx_ba::Grant>) -> Result<(), Error> {
        Err(Error::State)
    }
    fn qos_grant(&self) -> Option<Arc<qos::Grant>> {
        None
    }
    fn qos(&self) -> Option<qos::Profile> {
        None
    }
    fn enable_qos(
        &mut self,
        _grant: &Arc<qos::Grant>,
        _profile: qos::Profile,
    ) -> Result<(), Error> {
        Err(Error::State)
    }
    fn enable_rx_ba(&mut self, _grant: &Arc<rx_ba::Grant>) -> Result<(), Error> {
        Err(Error::State)
    }
    fn set_ht(&mut self, profile: ht::Profile) -> Result<(), Error> {
        if profile.geometry() != self.port.geometry()
            || self.phase != Phase::Running
            || self.pending.is_some()
        {
            return Err(Error::State);
        }
        Err(Error::Access)
    }
    fn ht_profile(&self) -> Option<ht::Profile> {
        None
    }
    fn observe_ht(&mut self, _offer: &Offer, _ies: &[u8], _basic: usize) -> Result<(), Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        Packet::check_transmit(self)?;
        Err(Error::State)
    }
    fn set_peer(&mut self, peer: Option<([u8; 6], u16)>, slot_us: u32) -> Result<(), Error> {
        Packet::set_peer(self, peer, slot_us)
    }
    fn start(&mut self) -> Result<(), Error> {
        Packet::start(self)
    }
    fn submit(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        unmarked(frame)?;
        Packet::submit(self, frame, rate)
    }
    fn submit_rates(&mut self, frame: &[u8], series: rates::Series) -> Result<u64, Error> {
        unmarked(frame)?;
        Packet::submit_rates(self, frame, series)
    }
    fn submit_ba_response(&mut self, _frame: &[u8], _rate: usize) -> Result<u64, Error> {
        Err(Error::State)
    }
    fn submit_delba(&mut self, _frame: &[u8], _rate: usize) -> Result<u64, Error> {
        Err(Error::State)
    }
    fn submit_ht(&mut self, _frame: &[u8], _mcs: u8, _basic: usize) -> Result<u64, Error> {
        Err(Error::Packet)
    }
    fn submit_sender_action(&mut self, _frame: &[u8], _basic: usize) -> Result<u64, Error> {
        Err(Error::State)
    }
    fn submit_bar(&mut self, _frame: &[u8], _basic: usize) -> Result<u64, Error> {
        Err(Error::State)
    }
    fn submit_aggregate(
        &mut self,
        _frames: &[Vec<u8>],
        _mcs: u8,
        _basic: usize,
        _permit: tx_ba::AggregatePermit,
    ) -> Result<u64, Error> {
        Err(Error::State)
    }
    fn pair_delivery(&mut self) -> Result<Option<PairDelivery>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        Ok(None)
    }
    fn delivery(&mut self) -> Result<Option<Delivery>, Error> {
        Packet::delivery(self)
    }
    fn receive(&mut self) -> Result<ReceiveStep, Error> {
        Packet::receive(self)
    }
    fn enable_interrupts(&mut self) -> Result<bool, Error> {
        Packet::enable_interrupts(self)
    }
    fn long_calibration(&mut self) -> Result<Option<i32>, Error> {
        Packet::long_calibration(self)
    }
    fn check_bt(&mut self) -> Result<(), Error> {
        Packet::check_bt(self)
    }
    fn interrupt(&self) -> Option<Arc<irq::Signal>> {
        Packet::interrupt(self)
    }
    fn service_begin(&mut self) -> Result<Option<irq::Events>, Error> {
        Ok(Packet::service_begin(self)?.map(shared_events))
    }
    fn service_end(&mut self) -> Result<(), Error> {
        Packet::service_end(self)
    }
    fn stop(&mut self) -> Result<(), Error> {
        Packet::stop(self)
    }
    // No HT program, so the shared `periodic::Owner` (HT20 ANI/NF under a
    // measured grant) is never bound; the AR9003 calibration runs through
    // `long_calibration` on the port.
    fn periodic_epoch(&mut self) {}
    fn periodic_bound(&self) -> bool {
        false
    }
    fn periodic_beacon(&mut self, _rssi: i8) {}
    fn periodic_service(&mut self, _eligible: bool) -> Result<(), Error> {
        Ok(())
    }
    fn periodic_deferred(&self) -> Result<bool, Error> {
        Ok(false)
    }
    fn reset_request(&self) -> Option<station::ResetType> {
        Packet::reset_request(self)
    }
}
