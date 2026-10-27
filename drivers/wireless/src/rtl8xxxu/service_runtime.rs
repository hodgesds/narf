//! One retained RTL8188EU station lifecycle. The asynchronous join and the
//! synchronous network drain operate on the same native/RSNA owners.
use super::{
    firmware_transport::ControlIo,
    management_runtime::{self, Candidate, Join, SecurityMode},
    packet_transport, power_policy,
    receive_runtime::{self, Receiver},
    station_runtime::{self, Station},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    State,
    Profile,
    Entropy,
    Radio(receive_runtime::Error),
    Management(management_runtime::Error),
    Station(station_runtime::Error),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Passive,
    Joining,
    Connected,
    Stopped,
    Failed,
}
/// No timer-derived nonce is admissible. The native environment delegates to
/// the fallible hardware-entropy policy; fixtures supply deterministic bytes.
pub trait Environment: Send + Sync {
    fn now_ms(&self) -> u64;
    fn fresh_nonce(&self) -> Result<[u8; 32], Error>;
    fn pause(&self) -> impl Future<Output = ()> + Send;
}
struct Entry {
    candidate: Candidate,
    seen: u64,
}
struct Attempt {
    failed: Arc<AtomicBool>,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            self.failed.store(true, Ordering::Release);
        }
    }
}
pub struct Service<C: ControlIo, B: packet_transport::Io, E: Environment> {
    radio: Option<Receiver<C, B>>,
    station: Option<Station<C, B>>,
    permission: power_policy::Permission,
    environment: E,
    cache: Vec<Entry>,
    failed: Arc<AtomicBool>,
    initial_nonce: Option<[u8; 32]>,
    own: [u8; 6],
    last_now: u64,
    retire: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl<C: ControlIo, B: packet_transport::Io, E: Environment> core::fmt::Debug for Service<C, B, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euService")
            .field("phase", &self.phase())
            .finish_non_exhaustive()
    }
}
impl<C: ControlIo, B: packet_transport::Io, E: Environment> Service<C, B, E> {
    pub async fn start(
        mut radio: Receiver<C, B>,
        permission: power_policy::Permission,
        environment: E,
    ) -> Result<Self, Error> {
        if !radio.matches_power(permission) {
            return Err(Error::Profile);
        }
        let own = radio.local().ok_or(Error::State)?;
        radio
            .authority()
            .fence(radio.start(), core::convert::identity)
            .await
            .map_err(Error::Radio)?;
        let now = environment.now_ms();
        Ok(Self {
            radio: Some(radio),
            station: None,
            permission,
            environment,
            cache: Vec::new(),
            failed: Arc::new(AtomicBool::new(false)),
            initial_nonce: None,
            own,
            last_now: now,
            retire: None,
        })
    }
    pub fn phase(&self) -> Phase {
        if self.failed.load(Ordering::Acquire) {
            return Phase::Failed;
        }
        if let Some(station) = &self.station {
            return match station.phase() {
                station_runtime::Phase::Open => Phase::Connected,
                station_runtime::Phase::Stopped => Phase::Stopped,
                station_runtime::Phase::Failed => Phase::Failed,
                _ => Phase::Joining,
            };
        }
        match self.radio.as_ref().map(Receiver::phase) {
            Some(receive_runtime::Phase::Receiving) => Phase::Passive,
            _ => Phase::Failed,
        }
    }
    pub fn local(&self) -> [u8; 6] {
        self.own
    }
    pub(super) fn ht_enabled(&self) -> bool {
        self.radio.as_ref().is_some_and(Receiver::ht_enabled)
            || self.station.as_ref().is_some_and(Station::ht_enabled)
    }
    pub(super) fn close_flag(&self) -> Arc<AtomicBool> {
        self.failed.clone()
    }
    pub(super) fn set_retirement(&mut self, retire: Arc<dyn Fn() + Send + Sync>) {
        self.retire = Some(retire);
    }
    pub(super) fn current(&self) -> Result<receive_runtime::Authority, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        let authority = if let Some(station) = &self.station {
            station.authority()
        } else {
            self.radio.as_ref().ok_or(Error::State)?.authority()
        };
        authority.invoke(|| ()).map_err(Error::Radio)?;
        Ok(authority)
    }
    pub(super) fn receive_open(&self) -> bool {
        !self.failed.load(Ordering::Acquire)
            && self
                .station
                .as_ref()
                .is_some_and(Station::controlled_port_open)
    }
    pub(super) fn receive_epoch(&self) -> Option<(Arc<core::sync::atomic::AtomicU64>, u64)> {
        self.station.as_ref().map(Station::receive_epoch)
    }
    pub fn connected_peer(&self) -> Option<[u8; 6]> {
        self.station
            .as_ref()
            .filter(|s| s.carrier_up())
            .filter(|_| self.phase() == Phase::Connected)
            .map(Station::peer)
    }
    fn fail(&mut self) {
        self.failed.store(true, Ordering::Release);
        if let Some(station) = &mut self.station {
            station.abort();
        }
        if let Some(radio) = &mut self.radio {
            radio.fail_terminal();
        }
    }
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.environment.now_ms();
        if now < self.last_now {
            self.fail();
            return Err(Error::State);
        }
        self.last_now = now;
        Ok(now)
    }
    pub fn candidates(&self) -> Vec<Candidate> {
        let now = self.environment.now_ms();
        self.cache
            .iter()
            .filter(|e| now >= e.seen && now - e.seen < 10000)
            .map(|e| e.candidate.clone())
            .collect()
    }
    /// Bounded progress from both a worker and a synchronous network waiter.
    /// No EP0 await, block_on, or dependence on another executor task occurs.
    pub fn poll(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let result = self.poll_inner();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let now = self.now()?;
        match self.phase() {
            Phase::Passive => {
                let radio = self.radio.as_mut().ok_or(Error::State)?;
                if let Some(frames) = radio.poll().map_err(Error::Radio)? {
                    for frame in frames {
                        let Ok(candidate) = Candidate::from_receive_with_phy(
                            &frame,
                            radio.channel(),
                            self.own,
                            radio.ht_local().as_ref(),
                        ) else {
                            continue;
                        };
                        if let Some(entry) = self
                            .cache
                            .iter_mut()
                            .find(|e| e.candidate.bssid() == candidate.bssid())
                        {
                            *entry = Entry {
                                candidate,
                                seen: now,
                            };
                        } else {
                            if self.cache.len() == 32 {
                                let oldest = self
                                    .cache
                                    .iter()
                                    .enumerate()
                                    .min_by_key(|(_, e)| e.seen)
                                    .map(|(i, _)| i)
                                    .unwrap();
                                self.cache.swap_remove(oldest);
                            }
                            self.cache.push(Entry {
                                candidate,
                                seen: now,
                            });
                        }
                    }
                }
                Ok(Vec::new())
            }
            Phase::Connected => {
                let environment = &self.environment;
                let initial_nonce = &mut self.initial_nonce;
                let nonce = || {
                    initial_nonce
                        .take()
                        .or_else(|| environment.fresh_nonce().ok())
                };
                let station = self.station.as_mut().ok_or(Error::State)?;
                station
                    .poll_network_with_nonce(now, nonce)
                    .map_err(Error::Station)?;
                let mut frames = Vec::new();
                for _ in 0..32 {
                    let Some(frame) = station.pop_received() else {
                        break;
                    };
                    frames.push(frame);
                }
                Ok(frames)
            }
            Phase::Stopped => Ok(Vec::new()),
            _ => Err(Error::State),
        }
    }
    /// Pure validation precedes moving the sole receive owner. Optional SME
    /// IEs use the same common plan validation/forwarding as the native frames.
    pub async fn connect(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        mode: SecurityMode,
        pmk: Option<Zeroizing<[u8; 32]>>,
        ies: &[u8],
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        let candidate = self
            .candidates()
            .into_iter()
            .find(|b| b.bssid() == bssid && b.ssid() == ssid)
            .ok_or(Error::Profile)?;
        let mut plan = Join::prepare_with_phy(
            candidate.clone(),
            self.own,
            ssid,
            mode,
            self.radio.as_ref().and_then(Receiver::ht_local),
        )
        .map_err(Error::Management)?;
        plan.append_sme_ies(ies).map_err(Error::Management)?;
        if mode.is_wpa2() != pmk.is_some() {
            return Err(Error::Profile);
        }
        // Fail entropy admission before changing any radio/TX state.
        let initial_nonce = if mode.is_wpa2() {
            Some(self.environment.fresh_nonce()?)
        } else {
            None
        };
        let now = self.now()?;
        let radio = self.radio.take().ok_or(Error::State)?;
        let mut station = Station::new(radio, candidate, ssid, mode, pmk, self.permission)
            .map_err(Error::Station)?;
        station.set_retirement(self.retire.clone());
        station.append_sme_ies(ies).map_err(Error::Station)?;
        self.initial_nonce = initial_nonce;
        self.station = Some(station);
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = async {
            self.station
                .as_mut()
                .unwrap()
                .begin(now)
                .await
                .map_err(Error::Station)?;
            // Independent bounded iteration count also terminates a stalled
            // clock source. Normal phase/receipt deadlines are monotonic ms.
            for _ in 0..20000 {
                let now = self.now()?;
                let environment = &self.environment;
                let initial_nonce = &mut self.initial_nonce;
                let nonce = || {
                    initial_nonce
                        .take()
                        .or_else(|| environment.fresh_nonce().ok())
                };
                self.station
                    .as_mut()
                    .unwrap()
                    .step_with_nonce(now, nonce)
                    .await
                    .map_err(Error::Station)?;
                if self.connected_peer().is_some() {
                    return Ok(());
                }
                self.environment.pause().await;
            }
            Err(Error::Station(station_runtime::Error::Timeout))
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }
    pub fn transmit_ready(&self) -> bool {
        self.phase() == Phase::Connected
            && self.station.as_ref().is_some_and(Station::transmit_ready)
    }
    pub fn transmit(&mut self, frame: &[u8]) -> Result<(), Error> {
        if !self.transmit_ready() {
            return Err(Error::State);
        }
        let now = self.now()?;
        let result = self
            .station
            .as_mut()
            .ok_or(Error::State)?
            .send_ethernet(frame, now)
            .map_err(Error::Station);
        if self
            .station
            .as_ref()
            .is_some_and(|s| s.phase() == station_runtime::Phase::Failed)
        {
            self.fail();
        }
        result
    }
    pub async fn disconnect(&mut self) -> Result<(), Error> {
        match self.phase() {
            Phase::Passive | Phase::Stopped => return Ok(()),
            Phase::Connected | Phase::Joining => (),
            _ => return Err(Error::State),
        }
        let mut attempt = Attempt {
            failed: self.failed.clone(),
            armed: true,
        };
        let result = self
            .station
            .as_mut()
            .ok_or(Error::State)?
            .disconnect()
            .await
            .map_err(Error::Station);
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }
}
