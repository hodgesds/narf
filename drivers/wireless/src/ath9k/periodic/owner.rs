// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained source continuation under the same native packet owner.
//! Hardware measurement runs under the old live receipt; only finite host
//! mutation/load windows keep actual RX parked. No key/PN/SC/BA owner moves.
use super::{
    Ani, AniPlan, BeaconRssi, Correction, Due, Error, Io, Live, Mode, Mutation, Noise, Pa,
    PaUpdate, Receipt, Sampler, Schedule, Step,
};

pub(in crate::ath9k) trait Context: Io {
    /// Publish before any host mutation, and after actual receipt readback.
    /// The concrete owner is bound to the exact current P/base/PCI source.
    fn publish(&self, live: Live) -> Result<(), Error>;
    /// CPU denial only; available even if source/PCI revocation prevents an
    /// MMIO cleanup. Existing terminal ownership must still close BME and
    /// quarantine every allocation whose complete stop is unproved.
    fn failed(&self);
}
#[derive(Clone, Copy)]
pub(in crate::ath9k) enum Work {
    CalStart(Mode),
    CalCollect,
    Long,
    Noise,
    Ani(AniPlan),
}
enum Phase {
    Idle,
    Calibration(Sampler),
    NoiseMeasurement(u64),
    NoiseLoad(Mutation, u64),
    Failed,
}
pub(in crate::ath9k) struct Owner {
    live: Live,
    schedule: Schedule,
    ani: Ani,
    rssi: BeaconRssi,
    pa: Pa,
    noise: Noise,
    phase: Phase,
    pending: Option<Work>,
    wide: bool,
    cursor: usize,
    caldone: bool,
    interference: bool,
    reset_ani: bool,
}
impl Owner {
    /// Actual P binding, software TX/control idle and hardware quiet precede
    /// this call. Report and optional WideReport are this retained generation's
    /// original actual receipts; neither identity is changed or refreshed.
    pub fn new(
        io: &impl Context,
        report: super::super::calibration::Report,
        wide: Option<super::super::calibration::wide::WideReport>,
    ) -> Result<Self, Error> {
        super::receipt::quiet(io)?;
        let ani = Ani::begin(io, wide.is_some())?;
        let live = Live::new(Receipt::initial(io, report, wide)?);
        live.readback(io)?;
        io.publish(live)?;
        Ok(Self {
            live,
            schedule: Schedule::new(io.now_us() / 1000),
            ani,
            rssi: BeaconRssi::new(),
            pa: Pa::new(report.pa_offset)?,
            noise: Noise::new(report.noise_dbm, wide.map(|actual| actual.ext_noise_dbm))?,
            phase: Phase::Idle,
            pending: None,
            wide: wide.is_some(),
            cursor: 0,
            // Start a real source list after binding; provisioning an optional
            // P asset long after initial reset is not a fresh calibration.
            caldone: false,
            interference: false,
            reset_ani: false,
        })
    }
    pub fn beacon(&mut self, native_rssi: i8) {
        self.rssi.beacon(native_rssi);
    }
    pub fn peer_epoch(&mut self) {
        self.rssi = BeaconRssi::new();
        self.reset_ani = true;
        if matches!(self.pending, Some(Work::Ani(_))) {
            self.pending = None;
        }
    }
    pub fn blocked(&self) -> bool {
        matches!(self.phase, Phase::NoiseLoad(..) | Phase::Failed)
    }
    pub fn urgent_retry(&self, now: u64) -> Result<bool, Error> {
        match &self.phase {
            Phase::Calibration(sampler) => sampler.expired(now),
            Phase::Failed => Err(Error::State),
            _ => Ok(false),
        }
    }
    fn mode(&self) -> Mode {
        if !self.wide {
            Mode::Iq
        } else {
            [Mode::AdcGain, Mode::AdcDc, Mode::Iq][self.cursor]
        }
    }
    fn abort<T>(&mut self, io: &impl Context, error: Error) -> Result<T, Error> {
        self.live.fail();
        self.phase = Phase::Failed;
        self.pending = None;
        io.failed();
        Err(error)
    }
    /// This probe performs only current raw counter/status I/O. The packet
    /// worker retains any returned work until actual native quiet is available;
    /// normal traffic continues meanwhile under the prior sealed receipt.
    pub fn work(&mut self, io: &impl Context) -> Result<Option<Work>, Error> {
        let result = self.next(io);
        match result {
            Ok(work) => Ok(work),
            Err(error) => self.abort(io, error),
        }
    }
    fn next(&mut self, io: &impl Context) -> Result<Option<Work>, Error> {
        if let Some(work) = self.pending {
            return Ok(Some(work));
        }
        let now = io.now_us();
        let work = match &self.phase {
            Phase::Failed => return Err(Error::State),
            Phase::Calibration(sampler) => {
                if io.read(0x9920)? & 0x10000 == 0 || sampler.expired(now)? {
                    Some(Work::CalCollect)
                } else {
                    None
                }
            }
            Phase::NoiseMeasurement(began) => {
                if now < *began || now - *began >= 222_000 {
                    return Err(Error::Timeout);
                }
                (io.read(0x9860)? & 2 == 0).then_some(Work::Noise)
            }
            Phase::NoiseLoad(_, began) => {
                if now < *began || now - *began >= 222_000 {
                    return Err(Error::Timeout);
                }
                Some(Work::Noise)
            }
            Phase::Idle => {
                let now = now / 1000;
                if self.reset_ani {
                    self.ani.reset_counters(io)?;
                    self.schedule.started(
                        now,
                        Due {
                            ani: true,
                            ..Due::default()
                        },
                    )?;
                    self.reset_ani = false;
                }
                let due = self
                    .schedule
                    .due(now, true, self.caldone, self.interference)?;
                if due.restart {
                    // Actual software validity-list retirement; no hardware
                    // receipt is minted by this source reset-valid decision.
                    self.caldone = false;
                    self.cursor = 0;
                    self.schedule.started(
                        now,
                        Due {
                            restart: true,
                            ..Due::default()
                        },
                    )?;
                }
                if due.long {
                    Some(Work::Long)
                } else if due.short || due.restart {
                    Some(Work::CalStart(self.mode()))
                } else if due.ani {
                    if let Some(rssi) = self.rssi.value() {
                        let plan = self.ani.observe(io, rssi)?;
                        if let Some(plan) = plan {
                            Some(Work::Ani(plan))
                        } else {
                            self.schedule.started(
                                now,
                                Due {
                                    ani: true,
                                    ..Due::default()
                                },
                            )?;
                            None
                        }
                    } else {
                        None // no fabricated current-peer RSSI observation.
                    }
                } else {
                    None
                }
            }
        };
        self.pending = work;
        Ok(work)
    }
    /// Same sole generation, no pending native/software DATA/control ticket,
    /// actual all-QCU idle, retained RX descriptors and actual RXabort/state0.
    /// A returned normal receipt permits the caller to re-enable actual RX;
    /// NoiseLoad instead retains the same parked mappings across bounded polls.
    pub fn run(&mut self, io: &impl Context, work: Work) -> Result<(), Error> {
        let result = self.run_quiet(io, work);
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.abort(io, error),
        }
    }
    fn run_quiet(&mut self, io: &impl Context, work: Work) -> Result<(), Error> {
        super::receipt::quiet(io)?;
        if !self.pending.is_some_and(|retained| retained.same(work)) {
            return Err(Error::State);
        }
        match work {
            Work::CalStart(mode) => {
                if !matches!(self.phase, Phase::Idle) || self.caldone || mode != self.mode() {
                    return Err(Error::State);
                }
                let mutation = self.live.begin(io)?;
                io.publish(self.live)?;
                let sampler = Sampler::begin(io, mode, self.wide)?;
                self.live.sampling(io, mutation, mode)?;
                io.publish(self.live)?;
                self.phase = Phase::Calibration(sampler);
                self.schedule.started(
                    io.now_us() / 1000,
                    Due {
                        short: true,
                        ..Due::default()
                    },
                )?;
            }
            Work::CalCollect => {
                let Phase::Calibration(sampler) = &mut self.phase else {
                    return Err(Error::State);
                };
                let mutation = if sampler.expired(io.now_us())? {
                    self.live.begin_retry(io)?
                } else {
                    self.live.begin(io)?
                };
                io.publish(self.live)?;
                let correction = match sampler.poll(io)? {
                    Step::Waiting => return Err(Error::State),
                    Step::Retry(mode) => {
                        if mode != self.mode() {
                            return Err(Error::State);
                        }
                        None
                    }
                    Step::Complete(mode, correction) => {
                        if mode != self.mode() {
                            return Err(Error::State);
                        }
                        Some(correction)
                    }
                };
                self.finish(io, mutation, correction, None, None, None)?;
                self.phase = Phase::Idle;
                if correction.is_some() {
                    self.cursor += 1;
                    self.caldone = self.cursor == if self.wide { 3 } else { 1 };
                }
            }
            Work::Long => {
                if !matches!(self.phase, Phase::Idle) {
                    return Err(Error::State);
                }
                let mutation = self.live.begin(io)?;
                io.publish(self.live)?;
                let pa = match self.pa.long(io)? {
                    PaUpdate::Measured(offset) => Some(offset),
                    PaUpdate::Disabled => None,
                    PaUpdate::Skipped(remaining) => {
                        if remaining > 8 {
                            return Err(Error::State);
                        }
                        None
                    }
                };
                self.finish(io, mutation, None, pa, None, None)?;
                let mutation = self.live.begin(io)?;
                io.publish(self.live)?;
                self.noise.start(io)?;
                self.live.noise(io, mutation)?;
                io.publish(self.live)?;
                self.phase = Phase::NoiseMeasurement(io.now_us());
                self.schedule.started(
                    io.now_us() / 1000,
                    Due {
                        long: true,
                        ..Due::default()
                    },
                )?;
            }
            Work::Noise => {
                let (mutation, began) = match core::mem::replace(&mut self.phase, Phase::Failed) {
                    Phase::NoiseMeasurement(_) => {
                        let mutation = self.live.begin(io)?;
                        io.publish(self.live)?;
                        (mutation, io.now_us())
                    }
                    Phase::NoiseLoad(mutation, began) => (mutation, began),
                    _ => return Err(Error::State),
                };
                if let Some(receipt) = self.noise.poll(io)? {
                    self.finish(io, mutation, None, None, Some(receipt), None)?;
                    self.interference = receipt.raw[0] > -108 || self.wide && receipt.raw[1] > -108;
                    self.phase = Phase::Idle;
                } else {
                    self.phase = Phase::NoiseLoad(mutation, began);
                }
            }
            Work::Ani(plan) => {
                if !matches!(self.phase, Phase::Idle) {
                    return Err(Error::State);
                }
                let mutation = self.live.begin(io)?;
                io.publish(self.live)?;
                let settings = self.ani.apply(io, plan)?;
                self.finish(io, mutation, None, None, None, Some(settings))?;
                self.schedule.started(
                    io.now_us() / 1000,
                    Due {
                        ani: true,
                        ..Due::default()
                    },
                )?;
            }
        }
        self.pending = None;
        Ok(())
    }
    fn finish(
        &mut self,
        io: &impl Context,
        mutation: Mutation,
        correction: Option<Correction>,
        pa: Option<u8>,
        noise: Option<super::noise::Receipt>,
        ani: Option<super::AniSettings>,
    ) -> Result<(), Error> {
        self.live
            .complete(io, mutation, correction, pa, noise, ani)?;
        io.publish(self.live)
    }
}
impl Work {
    fn same(self, other: Self) -> bool {
        match (self, other) {
            (Self::CalStart(a), Self::CalStart(b)) => a == b,
            (Self::Ani(a), Self::Ani(b)) => a == b,
            (Self::CalCollect, Self::CalCollect)
            | (Self::Long, Self::Long)
            | (Self::Noise, Self::Noise) => true,
            _ => false,
        }
    }
}
