// SPDX-License-Identifier: GPL-2.0-or-later
//! `station::Engine` for the AR9300 EDMA owner. The legacy station path
//! (start, one queue-0 frame, delivery, HP/LP receive, interrupts, the
//! port's periodic calibration and the terminal stop) delegates to the
//! inherent EDMA methods; `Delivery` and `ReceiveStep` are the shared
//! station types already.
//!
//! This owner carries no HT, EDCA, QoS, block-ack or aggregation
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

/// The station's view of `ar9003_hw_get_isr`'s causes: RX is either FIFO
/// (`ATH9K_INT_RXHP | ATH9K_INT_RXLP`); EDMA never fills `ah->intr_txqs`
/// (TX completion is the status ring). AUTOSLEEP S2 TIM/DTIM causes are
/// translated into the shared station's beacon-wait wake. FATAL and the BB
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
        tim_timer: events.tim || events.dtim || events.dtim_sync,
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
    fn manual_scope(&self) -> Option<Arc<crate::ath9k::ar9003::antenna::manual::Latch>> {
        self.port.manual_scope()
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
        self.port
            .ps_grant()
            .filter(|source| source.ar9003_wa().is_some())
    }
    fn ps_request(&self) -> Option<ps::Request> {
        self.port.ps_request()
    }
    fn sleep_service(&mut self) -> Result<(), Error> {
        Packet::sleep_service(self)
    }
    fn enable_ps(&mut self, source: &Arc<ps::Grant>) -> Result<(), Error> {
        Packet::enable_ps(self, source)
    }
    fn ps_receive_on(&self) -> Result<(), Error> {
        Packet::ps_receive_on(self)
    }
    fn ps_timers(&mut self, plan: ps::tim::Plan) -> Result<(), Error> {
        Packet::ps_timers(self, plan)
    }
    fn ps_awake_mode(&mut self) -> Result<(), Error> {
        Packet::ps_awake_mode(self)
    }
    fn ps_sleep(&mut self) -> Result<(), Error> {
        Packet::ps_sleep(self)
    }
    fn ps_tsf(&self) -> Result<u64, Error> {
        Packet::ps_tsf(self)
    }
    fn submit_ps(
        &mut self,
        frame: &[u8],
        ap: [u8; 6],
        aid: u16,
        basic: usize,
    ) -> Result<u64, Error> {
        Packet::submit_ps(self, frame, ap, aid, basic)
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
        Packet::submit(self, frame, rate)
    }
    fn submit_rates(&mut self, frame: &[u8], series: rates::Series) -> Result<u64, Error> {
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
    fn coex_wait_us(&self) -> Option<u64> {
        Packet::coex_wait_us(self)
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
    // Distinct original AR9003 P owner; no AR9285 HT/ANI alias.
    fn periodic_epoch(&mut self) {
        self.port.ar9003_ani_epoch();
    }
    fn periodic_bound(&self) -> bool {
        self.port.ar9003_ani_bound()
    }
    // Radio::cache admits the bound peer beacon after native descriptor/CRC
    // validation. The exact same bound-peer sample feeds MCI and AR9003 P.
    fn periodic_beacon(&mut self, rssi: i8) {
        if self.phase() == Phase::Running {
            self.mci.lock().beacon_rssi(rssi);
            self.port.ar9003_ani_beacon(rssi);
        }
    }
    fn periodic_service(&mut self, eligible: bool) -> Result<(), Error> {
        self.port
            .ar9003_ani_service(eligible && self.pending.is_none())
    }
    fn periodic_deferred(&self) -> Result<bool, Error> {
        Ok(false)
    }
    fn reset_request(&self) -> Option<station::ResetType> {
        Packet::reset_request(self)
    }
}
