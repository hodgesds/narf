// SPDX-License-Identifier: GPL-2.0-or-later
//! The packet engine a station drives. `packet::Packet<P>` (AR5008/AR9002
//! descriptor DMA) implements it by delegating to its inherent methods, so
//! every AR9002 behaviour and register stream is unchanged; the AR9003 EDMA
//! owner implements it as well.
use crate::ath9k::{
    channel_width::Geometry,
    ht, irq,
    packet::{Delivery, Error, Packet, PairDelivery, Phase, Port, ReceiveStep},
    ps, qos, rates, rx_ba, tx_ba,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use narf_wireless::association::phy::Offer;

/// Every packet-owner operation `station::Radio` uses.
pub(in crate::ath9k) trait Engine {
    fn phase(&self) -> Phase;
    fn reclaimed(&self) -> bool;
    fn idle_admissible(&self) -> bool;
    fn check_transmit(&self) -> Result<(), Error>;
    fn geometry(&self) -> Geometry;
    fn frequency_mhz(&self) -> u16;
    fn channel_mask(&self) -> u64;
    fn channel(&self) -> u8;
    fn ht_grant(&self) -> Option<Arc<ht::Grant>>;
    fn rx_ba_grant(&self) -> Option<Arc<rx_ba::Grant>>;
    fn ps_grant(&self) -> Option<Arc<ps::Grant>>;
    fn enable_ps(&mut self, source: &Arc<ps::Grant>) -> Result<(), Error>;
    fn ps_receive_on(&self) -> Result<(), Error>;
    fn ps_timers(&mut self, plan: ps::tim::Plan) -> Result<(), Error>;
    fn ps_awake_mode(&mut self) -> Result<(), Error>;
    fn ps_sleep(&mut self) -> Result<(), Error>;
    fn ps_tsf(&self) -> Result<u64, Error>;
    fn submit_ps(
        &mut self,
        frame: &[u8],
        ap: [u8; 6],
        aid: u16,
        basic: usize,
    ) -> Result<u64, Error>;
    fn tx_ba_grant(&self) -> Option<Arc<tx_ba::Grant>>;
    fn enable_tx_ba(&mut self, grant: &Arc<tx_ba::Grant>) -> Result<(), Error>;
    fn qos_grant(&self) -> Option<Arc<qos::Grant>>;
    fn qos(&self) -> Option<qos::Profile>;
    fn enable_qos(&mut self, grant: &Arc<qos::Grant>, profile: qos::Profile) -> Result<(), Error>;
    fn enable_rx_ba(&mut self, grant: &Arc<rx_ba::Grant>) -> Result<(), Error>;
    fn set_ht(&mut self, profile: ht::Profile) -> Result<(), Error>;
    fn ht_profile(&self) -> Option<ht::Profile>;
    fn observe_ht(&mut self, offer: &Offer, ies: &[u8], basic: usize) -> Result<(), Error>;
    fn set_peer(&mut self, peer: Option<([u8; 6], u16)>, slot_us: u32) -> Result<(), Error>;
    fn start(&mut self) -> Result<(), Error>;
    fn submit(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error>;
    fn submit_rates(&mut self, frame: &[u8], series: rates::Series) -> Result<u64, Error>;
    fn submit_ba_response(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error>;
    fn submit_delba(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error>;
    fn submit_ht(&mut self, frame: &[u8], mcs: u8, basic: usize) -> Result<u64, Error>;
    fn submit_sender_action(&mut self, frame: &[u8], basic: usize) -> Result<u64, Error>;
    fn submit_bar(&mut self, frame: &[u8], basic: usize) -> Result<u64, Error>;
    fn submit_aggregate(
        &mut self,
        frames: &[Vec<u8>],
        mcs: u8,
        basic: usize,
        permit: tx_ba::AggregatePermit,
    ) -> Result<u64, Error>;
    fn pair_delivery(&mut self) -> Result<Option<PairDelivery>, Error>;
    fn delivery(&mut self) -> Result<Option<Delivery>, Error>;
    fn receive(&mut self) -> Result<ReceiveStep, Error>;
    fn enable_interrupts(&mut self) -> Result<bool, Error>;
    fn long_calibration(&mut self) -> Result<Option<i32>, Error>;
    fn interrupt(&self) -> Option<Arc<irq::Signal>>;
    fn service_begin(&mut self) -> Result<Option<irq::Events>, Error>;
    fn service_end(&mut self) -> Result<(), Error>;
    fn stop(&mut self) -> Result<(), Error>;
    fn periodic_epoch(&mut self);
    fn periodic_bound(&self) -> bool;
    fn periodic_beacon(&mut self, rssi: i8);
    fn periodic_service(&mut self, eligible: bool) -> Result<(), Error>;
    fn periodic_deferred(&self) -> Result<bool, Error>;
    /// The `ath9k_queue_reset` cause behind this engine's last failure,
    /// when an in-place `ath_reset` (rather than a generation retirement)
    /// is how Linux recovers it. Engines without an in-place reset path
    /// report none.
    fn reset_request(&self) -> Option<crate::ath9k::station::ResetType> {
        None
    }
}

impl<P: Port> Engine for Packet<P> {
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
        Packet::geometry(self)
    }
    fn frequency_mhz(&self) -> u16 {
        Packet::frequency_mhz(self)
    }
    fn channel_mask(&self) -> u64 {
        Packet::channel_mask(self)
    }
    fn channel(&self) -> u8 {
        Packet::channel(self)
    }
    fn ht_grant(&self) -> Option<Arc<ht::Grant>> {
        Packet::ht_grant(self)
    }
    fn rx_ba_grant(&self) -> Option<Arc<rx_ba::Grant>> {
        Packet::rx_ba_grant(self)
    }
    fn ps_grant(&self) -> Option<Arc<ps::Grant>> {
        Packet::ps_grant(self)
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
        Packet::tx_ba_grant(self)
    }
    fn enable_tx_ba(&mut self, grant: &Arc<tx_ba::Grant>) -> Result<(), Error> {
        Packet::enable_tx_ba(self, grant)
    }
    fn qos_grant(&self) -> Option<Arc<qos::Grant>> {
        Packet::qos_grant(self)
    }
    fn qos(&self) -> Option<qos::Profile> {
        Packet::qos(self)
    }
    fn enable_qos(&mut self, grant: &Arc<qos::Grant>, profile: qos::Profile) -> Result<(), Error> {
        Packet::enable_qos(self, grant, profile)
    }
    fn enable_rx_ba(&mut self, grant: &Arc<rx_ba::Grant>) -> Result<(), Error> {
        Packet::enable_rx_ba(self, grant)
    }
    fn set_ht(&mut self, profile: ht::Profile) -> Result<(), Error> {
        Packet::set_ht(self, profile)
    }
    fn ht_profile(&self) -> Option<ht::Profile> {
        Packet::ht_profile(self)
    }
    fn observe_ht(&mut self, offer: &Offer, ies: &[u8], basic: usize) -> Result<(), Error> {
        Packet::observe_ht(self, offer, ies, basic)
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
    fn submit_ba_response(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        Packet::submit_ba_response(self, frame, rate)
    }
    fn submit_delba(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        Packet::submit_delba(self, frame, rate)
    }
    fn submit_ht(&mut self, frame: &[u8], mcs: u8, basic: usize) -> Result<u64, Error> {
        Packet::submit_ht(self, frame, mcs, basic)
    }
    fn submit_sender_action(&mut self, frame: &[u8], basic: usize) -> Result<u64, Error> {
        Packet::submit_sender_action(self, frame, basic)
    }
    fn submit_bar(&mut self, frame: &[u8], basic: usize) -> Result<u64, Error> {
        Packet::submit_bar(self, frame, basic)
    }
    fn submit_aggregate(
        &mut self,
        frames: &[Vec<u8>],
        mcs: u8,
        basic: usize,
        permit: tx_ba::AggregatePermit,
    ) -> Result<u64, Error> {
        Packet::submit_aggregate(self, frames, mcs, basic, permit)
    }
    fn pair_delivery(&mut self) -> Result<Option<PairDelivery>, Error> {
        Packet::pair_delivery(self)
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
    fn interrupt(&self) -> Option<Arc<irq::Signal>> {
        Packet::interrupt(self)
    }
    fn service_begin(&mut self) -> Result<Option<irq::Events>, Error> {
        Packet::service_begin(self)
    }
    fn service_end(&mut self) -> Result<(), Error> {
        Packet::service_end(self)
    }
    fn stop(&mut self) -> Result<(), Error> {
        Packet::stop(self)
    }
    fn periodic_epoch(&mut self) {
        Packet::periodic_epoch(self)
    }
    fn periodic_bound(&self) -> bool {
        Packet::periodic_bound(self)
    }
    fn periodic_beacon(&mut self, rssi: i8) {
        Packet::periodic_beacon(self, rssi)
    }
    fn periodic_service(&mut self, eligible: bool) -> Result<(), Error> {
        Packet::periodic_service(self, eligible)
    }
    fn periodic_deferred(&self) -> Result<bool, Error> {
        Packet::periodic_deferred(self)
    }
}

/// The packet engine a native station owns: the AR5008/AR9002 descriptor
/// owner or the AR9003 EDMA owner. Every operation delegates to the held
/// engine unchanged, so each chip's behaviour and register stream is
/// exactly its own engine's.
pub(in crate::ath9k) enum Dispatch<P: Port> {
    Ar9002(Box<Packet<P>>),
    Ar9003(Box<crate::ath9k::ar9003::packet::Packet<P>>),
}

impl<P: Port> From<Packet<P>> for Dispatch<P> {
    fn from(packet: Packet<P>) -> Self {
        Self::Ar9002(Box::new(packet))
    }
}

impl<P: Port> From<crate::ath9k::ar9003::packet::Packet<P>> for Dispatch<P> {
    fn from(packet: crate::ath9k::ar9003::packet::Packet<P>) -> Self {
        Self::Ar9003(Box::new(packet))
    }
}

/// `Engine::$method` on whichever engine `$self` holds.
macro_rules! dispatch {
    ($self:ident.$method:ident($($arg:expr),*)) => {
        match $self {
            Dispatch::Ar9002(packet) => <Packet<P> as Engine>::$method(packet $(, $arg)*),
            Dispatch::Ar9003(packet) => {
                <crate::ath9k::ar9003::packet::Packet<P> as Engine>::$method(packet $(, $arg)*)
            }
        }
    };
}

impl<P: Port> Engine for Dispatch<P> {
    fn phase(&self) -> Phase {
        dispatch!(self.phase())
    }
    fn reclaimed(&self) -> bool {
        dispatch!(self.reclaimed())
    }
    fn idle_admissible(&self) -> bool {
        dispatch!(self.idle_admissible())
    }
    fn check_transmit(&self) -> Result<(), Error> {
        dispatch!(self.check_transmit())
    }
    fn geometry(&self) -> Geometry {
        dispatch!(self.geometry())
    }
    fn frequency_mhz(&self) -> u16 {
        dispatch!(self.frequency_mhz())
    }
    fn channel_mask(&self) -> u64 {
        dispatch!(self.channel_mask())
    }
    fn channel(&self) -> u8 {
        dispatch!(self.channel())
    }
    fn ht_grant(&self) -> Option<Arc<ht::Grant>> {
        dispatch!(self.ht_grant())
    }
    fn rx_ba_grant(&self) -> Option<Arc<rx_ba::Grant>> {
        dispatch!(self.rx_ba_grant())
    }
    fn ps_grant(&self) -> Option<Arc<ps::Grant>> {
        dispatch!(self.ps_grant())
    }
    fn enable_ps(&mut self, source: &Arc<ps::Grant>) -> Result<(), Error> {
        dispatch!(self.enable_ps(source))
    }
    fn ps_receive_on(&self) -> Result<(), Error> {
        dispatch!(self.ps_receive_on())
    }
    fn ps_timers(&mut self, plan: ps::tim::Plan) -> Result<(), Error> {
        dispatch!(self.ps_timers(plan))
    }
    fn ps_awake_mode(&mut self) -> Result<(), Error> {
        dispatch!(self.ps_awake_mode())
    }
    fn ps_sleep(&mut self) -> Result<(), Error> {
        dispatch!(self.ps_sleep())
    }
    fn ps_tsf(&self) -> Result<u64, Error> {
        dispatch!(self.ps_tsf())
    }
    fn submit_ps(
        &mut self,
        frame: &[u8],
        ap: [u8; 6],
        aid: u16,
        basic: usize,
    ) -> Result<u64, Error> {
        dispatch!(self.submit_ps(frame, ap, aid, basic))
    }
    fn tx_ba_grant(&self) -> Option<Arc<tx_ba::Grant>> {
        dispatch!(self.tx_ba_grant())
    }
    fn enable_tx_ba(&mut self, grant: &Arc<tx_ba::Grant>) -> Result<(), Error> {
        dispatch!(self.enable_tx_ba(grant))
    }
    fn qos_grant(&self) -> Option<Arc<qos::Grant>> {
        dispatch!(self.qos_grant())
    }
    fn qos(&self) -> Option<qos::Profile> {
        dispatch!(self.qos())
    }
    fn enable_qos(&mut self, grant: &Arc<qos::Grant>, profile: qos::Profile) -> Result<(), Error> {
        dispatch!(self.enable_qos(grant, profile))
    }
    fn enable_rx_ba(&mut self, grant: &Arc<rx_ba::Grant>) -> Result<(), Error> {
        dispatch!(self.enable_rx_ba(grant))
    }
    fn set_ht(&mut self, profile: ht::Profile) -> Result<(), Error> {
        dispatch!(self.set_ht(profile))
    }
    fn ht_profile(&self) -> Option<ht::Profile> {
        dispatch!(self.ht_profile())
    }
    fn observe_ht(&mut self, offer: &Offer, ies: &[u8], basic: usize) -> Result<(), Error> {
        dispatch!(self.observe_ht(offer, ies, basic))
    }
    fn set_peer(&mut self, peer: Option<([u8; 6], u16)>, slot_us: u32) -> Result<(), Error> {
        dispatch!(self.set_peer(peer, slot_us))
    }
    fn start(&mut self) -> Result<(), Error> {
        dispatch!(self.start())
    }
    fn submit(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        dispatch!(self.submit(frame, rate))
    }
    fn submit_rates(&mut self, frame: &[u8], series: rates::Series) -> Result<u64, Error> {
        dispatch!(self.submit_rates(frame, series))
    }
    fn submit_ba_response(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        dispatch!(self.submit_ba_response(frame, rate))
    }
    fn submit_delba(&mut self, frame: &[u8], rate: usize) -> Result<u64, Error> {
        dispatch!(self.submit_delba(frame, rate))
    }
    fn submit_ht(&mut self, frame: &[u8], mcs: u8, basic: usize) -> Result<u64, Error> {
        dispatch!(self.submit_ht(frame, mcs, basic))
    }
    fn submit_sender_action(&mut self, frame: &[u8], basic: usize) -> Result<u64, Error> {
        dispatch!(self.submit_sender_action(frame, basic))
    }
    fn submit_bar(&mut self, frame: &[u8], basic: usize) -> Result<u64, Error> {
        dispatch!(self.submit_bar(frame, basic))
    }
    fn submit_aggregate(
        &mut self,
        frames: &[Vec<u8>],
        mcs: u8,
        basic: usize,
        permit: tx_ba::AggregatePermit,
    ) -> Result<u64, Error> {
        dispatch!(self.submit_aggregate(frames, mcs, basic, permit))
    }
    fn pair_delivery(&mut self) -> Result<Option<PairDelivery>, Error> {
        dispatch!(self.pair_delivery())
    }
    fn delivery(&mut self) -> Result<Option<Delivery>, Error> {
        dispatch!(self.delivery())
    }
    fn receive(&mut self) -> Result<ReceiveStep, Error> {
        dispatch!(self.receive())
    }
    fn enable_interrupts(&mut self) -> Result<bool, Error> {
        dispatch!(self.enable_interrupts())
    }
    fn long_calibration(&mut self) -> Result<Option<i32>, Error> {
        dispatch!(self.long_calibration())
    }
    fn interrupt(&self) -> Option<Arc<irq::Signal>> {
        dispatch!(self.interrupt())
    }
    fn service_begin(&mut self) -> Result<Option<irq::Events>, Error> {
        dispatch!(self.service_begin())
    }
    fn service_end(&mut self) -> Result<(), Error> {
        dispatch!(self.service_end())
    }
    fn stop(&mut self) -> Result<(), Error> {
        dispatch!(self.stop())
    }
    fn periodic_epoch(&mut self) {
        dispatch!(self.periodic_epoch())
    }
    fn periodic_bound(&self) -> bool {
        dispatch!(self.periodic_bound())
    }
    fn periodic_beacon(&mut self, rssi: i8) {
        dispatch!(self.periodic_beacon(rssi))
    }
    fn periodic_service(&mut self, eligible: bool) -> Result<(), Error> {
        dispatch!(self.periodic_service(eligible))
    }
    fn periodic_deferred(&self) -> Result<bool, Error> {
        dispatch!(self.periodic_deferred())
    }
    fn reset_request(&self) -> Option<crate::ath9k::station::ResetType> {
        dispatch!(self.reset_request())
    }
}
