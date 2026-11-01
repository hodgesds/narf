//! DG2 PL1 controls. MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad
//! xe_hwmon.c::{xe_hwmon_power_max_read,xe_hwmon_power_max_write,
//! xe_hwmon_power_rated_max_read,xe_hwmon_power_max_interval_show,
//! xe_hwmon_power_max_interval_store}, regs/xe_mchbar_regs.h. Only DG2 uses
//! this direct register protocol; BMG's mailbox power-source switch is absent.

use super::{Io, INTERVAL_NS, MAX_AGE_NS};
use alloc::{format, string::String};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

const UNIT: u64 = 0x145938;
const SKU: u64 = 0x145930;
const PL1: u64 = 0x1459a0;
const VALUE: u32 = 0x7fff;
const ENABLE: u32 = 1 << 15;
const MASK: u32 = VALUE | ENABLE;
const TIME: u32 = 0x7f << 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Boot {
    shift: u8,
    ceiling: u32,
}
#[derive(Clone, Copy, Debug)]
struct Observation {
    shift: u8,
    time_shift: u8,
    min: u32,
    max: u32,
    rated: u32,
    pl1: u32,
}
impl Observation {
    fn read(io: &mut impl Io) -> Option<Self> {
        let unit = io.read(UNIT)?;
        // Bounded high/low/high read refuses a torn SKU rather than retrying.
        let high = io.read(SKU + 4)?;
        let low = io.read(SKU)?;
        let again = io.read(SKU + 4)?;
        let pl1 = io.read(PL1)?;
        if [unit, high, low, pl1].contains(&u32::MAX) || high != again {
            return None;
        }
        let min = (low >> 16) & VALUE;
        let max = high & VALUE;
        let rated = low & VALUE;
        (min != 0 && min <= max && rated != 0).then_some(Self {
            shift: (unit & 0xf) as u8,
            time_shift: ((unit >> 16) & 0xf) as u8,
            min,
            max,
            rated,
            pl1,
        })
    }
    fn microwatts(self, raw: u32) -> u64 {
        (u64::from(raw) * 1_000_000) >> self.shift
    }
    fn enabled(self) -> bool {
        self.pl1 & ENABLE != 0 && self.pl1 & VALUE != 0
    }
    fn interval(self, bits: u32) -> u64 {
        let x = (bits >> 22) & 3;
        let y = (bits >> 17) & 31;
        (((4 | u64::from(x)) << y) * 1000) >> (self.time_shift + 2)
    }
    fn interval_max(self) -> u64 {
        // Pinned xe_hwmon.c uses x=0,y=18: existing dGPU SKU MAX_WIN
        // is unreliable. 256 seconds applies only to time unit shift10.
        self.interval(18 << 17)
    }
    fn bounds(self, boot: Boot) -> Option<(u32, u32)> {
        let max = self.max.min(boot.ceiling);
        (boot.shift == self.shift && self.enabled() && self.min <= max).then_some((self.min, max))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Closed,
    Access,
    Bounds,
    Readback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Unavailable,
    Ready,
    Queued(u64),
    Applying(u64),
    Applied(u64),
    Failed(u64, Failure),
}
#[derive(Clone, Copy, Debug)]
struct Request {
    id: u64,
    setting: Setting,
}
#[derive(Clone, Copy, Debug)]
enum Setting {
    Power(u32),
    Interval { bits: u32, shift: u8 },
}
#[derive(Debug)]
struct State {
    epoch: u64,
    next: u64,
    sampled: Option<u64>,
    observed: Option<Observation>,
    // The first valid, enabled firmware cap of this card's lifetime survives
    // close/activate. A limit we lowered must not become the next boot ceiling.
    boot: Option<Boot>,
    queued: Option<Request>,
    applying: Option<Request>,
    outcome: Outcome,
}

#[derive(Debug)]
pub(super) struct Power {
    admission: AtomicU64,
    state: IrqSafeSpinLock<State>,
}
impl Power {
    pub(super) fn new() -> Self {
        Self {
            admission: AtomicU64::new(0),
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                next: 1,
                sampled: None,
                observed: None,
                boot: None,
                queued: None,
                applying: None,
                outcome: Outcome::Unavailable,
            }),
        }
    }
    pub(super) fn activate(&self, epoch: u64) {
        self.close();
        let mut state = self.state.lock();
        state.epoch = epoch;
        self.admission.store(epoch, Ordering::Release);
    }
    pub(super) fn close(&self) {
        self.admission.store(0, Ordering::Release);
        let mut state = self.state.lock();
        state.epoch = 0;
        state.sampled = None;
        state.observed = None;
        let cancelled = state.applying.take().or_else(|| state.queued.take());
        state.queued = None;
        state.outcome = cancelled.map_or(Outcome::Unavailable, |r| {
            Outcome::Failed(r.id, Failure::Closed)
        });
    }
    fn current(&self, epoch: u64) -> bool {
        epoch != 0 && self.admission.load(Ordering::Acquire) == epoch
    }
    pub(super) fn access_lost(&self, epoch: u64) {
        let mut state = self.state.lock();
        if state.epoch != epoch || !self.current(epoch) {
            return;
        }
        state.observed = None;
        let cancelled = state.applying.take().or_else(|| state.queued.take());
        state.queued = None;
        if let Some(request) = cancelled {
            state.outcome = Outcome::Failed(request.id, Failure::Access);
        }
        // Keep the original boot ceiling, last attempt timestamp and last
        // completed request outcome; this is observation loss, not a reset.
    }
    pub(super) fn service(&self, epoch: u64, now: u64, io: &mut impl Io) {
        let (request, boot) = {
            let mut state = self.state.lock();
            if !self.current(epoch) || state.epoch != epoch || state.applying.is_some() {
                return;
            }
            let request = state.queued.take();
            if request.is_none()
                && state
                    .sampled
                    .is_some_and(|at| now >= at && now - at < INTERVAL_NS)
            {
                return;
            }
            state.applying = request;
            if let Some(request) = request {
                state.outcome = Outcome::Applying(request.id);
                state.observed = None;
            }
            (request, state.boot)
        };
        // No software lock is held over capability validation or MMIO. The
        // retained GT mutex serializes hardware access; publication rechecks
        // admission so close/reset cannot be undone by an old service call.
        let mut observation = Observation::read(io);
        let mut failure = None;
        if let Some(request) = request {
            failure = Some(Failure::Access);
            if let (Some(observed), Some(boot)) = (observation, boot) {
                failure = Some(Failure::Bounds);
                let wanted = observed
                    .bounds(boot)
                    .and_then(|(min, max)| match request.setting {
                        Setting::Power(raw) if (min..=max).contains(&raw) => {
                            Some((observed.pl1 & !MASK) | ENABLE | raw)
                        }
                        Setting::Interval { bits, shift }
                            if shift == observed.time_shift
                                && observed.interval(bits) != 0
                                && observed.interval(bits) <= observed.interval_max() =>
                        {
                            Some((observed.pl1 & !TIME) | bits)
                        }
                        _ => None,
                    });
                if let Some(wanted) = wanted.filter(|_| self.current(epoch)) {
                    // Preserve every field outside the selected value/window.
                    // The pinned DG2 source defines no PL1 lock bit. Refuse
                    // a non-sticking/locked write through exact readback.
                    failure = Some(Failure::Access);
                    if io.write(PL1, wanted) {
                        if let Some(readback) = io.read(PL1) {
                            if readback != u32::MAX {
                                observation = Some(Observation {
                                    pl1: readback,
                                    ..observed
                                });
                                failure = (readback != wanted).then_some(Failure::Readback);
                            } else {
                                observation = None;
                            }
                        } else {
                            observation = None;
                        }
                    } else {
                        observation = None;
                    }
                }
            }
        }
        let mut state = self.state.lock();
        if !self.current(epoch) || state.epoch != epoch {
            return;
        }
        state.sampled = Some(now);
        state.observed = observation;
        if state.boot.is_none() {
            if let Some(observed) = observation.filter(|o| o.enabled()) {
                state.boot = Some(Boot {
                    shift: observed.shift,
                    ceiling: observed.pl1 & VALUE,
                });
            }
        }
        if let Some(request) = request {
            state.applying = None;
            state.outcome = failure.map_or(Outcome::Applied(request.id), |error| {
                Outcome::Failed(request.id, error)
            });
        } else if state.outcome == Outcome::Unavailable && observation.is_some() {
            state.outcome = Outcome::Ready;
        }
    }
    pub(super) fn store(&self, bytes: &[u8], now: u64) -> Result<(), FsError> {
        // A compatibility administrative grant, not DRM master/render access.
        // Checked on every store, including writes through an already open fd.
        if !narf_filesystem::caller_capable(21) {
            return Err(FsError::OperationNotPermitted);
        }
        if bytes.len() > 32 {
            return Err(FsError::InvalidData);
        }
        let text = core::str::from_utf8(bytes)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
            return Err(FsError::InvalidData);
        }
        let microwatts: u64 = text.parse().map_err(|_| FsError::InvalidData)?;
        let mut state = self.state.lock();
        if !self.current(state.epoch) {
            return Err(FsError::NoDevice);
        }
        if state.queued.is_some() || state.applying.is_some() {
            return Err(FsError::Busy);
        }
        let observed = fresh(&state, now).ok_or(FsError::NoDevice)?;
        let (min, max) = observed
            .bounds(state.boot.ok_or(FsError::Unsupported)?)
            .ok_or(FsError::Unsupported)?;
        let raw = microwatts
            .checked_mul(1u64 << observed.shift)
            .and_then(|n| n.checked_add(500_000))
            .map(|n| n / 1_000_000)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(FsError::InvalidData)?;
        // No disable, silent truncation/clamping or increase above the card's
        // original enabled boot ceiling. Quantization follows Xe nearest-round.
        if microwatts == 0
            || !(min..=max).contains(&raw)
            || microwatts < observed.microwatts(min)
            || microwatts > observed.microwatts(max)
        {
            return Err(FsError::InvalidData);
        }
        let id = state.next;
        state.next = id.checked_add(1).ok_or(FsError::Busy)?;
        state.queued = Some(Request {
            id,
            setting: Setting::Power(raw),
        });
        state.outcome = Outcome::Queued(id);
        Ok(())
    }
    pub(super) fn store_interval(&self, bytes: &[u8], now: u64) -> Result<(), FsError> {
        if !narf_filesystem::caller_capable(21) {
            return Err(FsError::OperationNotPermitted);
        }
        let milliseconds = super::decimal(bytes)?;
        let mut state = self.state.lock();
        if !self.current(state.epoch) {
            return Err(FsError::NoDevice);
        }
        if state.queued.is_some() || state.applying.is_some() {
            return Err(FsError::Busy);
        }
        let observed = fresh(&state, now).ok_or(FsError::NoDevice)?;
        observed
            .bounds(state.boot.ok_or(FsError::Unsupported)?)
            .ok_or(FsError::Unsupported)?;
        if milliseconds == 0 || milliseconds > observed.interval_max() {
            return Err(FsError::InvalidData);
        }
        // Exact pinned Xe algorithm: nearest hardware units plus one, then
        // the 1.x * 2^y encoding (x has two fractional bits).
        let units = milliseconds
            .checked_shl(u32::from(observed.time_shift))
            .and_then(|v| v.checked_add(500))
            .map(|v| v / 1000)
            .and_then(|v| v.checked_add(1))
            .ok_or(FsError::InvalidData)?;
        let y = units.ilog2();
        let x = ((units - (1u64 << y)) << 2) >> y;
        let bits = (x as u32) << 22 | y << 17;
        if observed.interval(bits) == 0 || observed.interval(bits) > observed.interval_max() {
            return Err(FsError::InvalidData);
        }
        let id = state.next;
        state.next = id.checked_add(1).ok_or(FsError::Busy)?;
        state.queued = Some(Request {
            id,
            setting: Setting::Interval {
                bits,
                shift: observed.time_shift,
            },
        });
        state.outcome = Outcome::Queued(id);
        Ok(())
    }
    pub(super) fn show(&self, attribute: &str, now: u64) -> String {
        let state = self.state.lock();
        if attribute == "power2_max_status" {
            return match state.outcome {
                Outcome::Unavailable => "unavailable\n".into(),
                Outcome::Ready => "ready\n".into(),
                Outcome::Queued(id) => format!("queued {id}\n"),
                Outcome::Applying(id) => format!("applying {id}\n"),
                Outcome::Applied(id) => format!("applied {id}\n"),
                Outcome::Failed(id, error) => format!("failed {id} {error:?}\n"),
            };
        }
        if !self.current(state.epoch) {
            return String::new();
        }
        let Some(observed) = fresh(&state, now) else {
            return String::new();
        };
        let value = match attribute {
            "power2_max_interval" => Some(observed.interval(observed.pl1)),
            "power2_max_interval_min" => Some((1000u64 >> observed.time_shift).max(1)),
            "power2_max_interval_max" => Some(observed.interval_max()),
            "power2_max" => Some(if observed.enabled() {
                observed.microwatts((observed.pl1 & VALUE).clamp(observed.min, observed.max))
            } else {
                0
            }),
            "power2_rated_max" => Some(observed.microwatts(observed.rated)),
            "power2_max_default" => state
                .boot
                .filter(|b| b.shift == observed.shift)
                .map(|b| observed.microwatts(b.ceiling)),
            "power2_max_min" => state
                .boot
                .and_then(|b| observed.bounds(b))
                .map(|(min, _)| observed.microwatts(min)),
            "power2_max_max" => state
                .boot
                .and_then(|b| observed.bounds(b))
                .map(|(_, max)| observed.microwatts(max)),
            _ => None,
        };
        value.map_or_else(String::new, |value| format!("{value}\n"))
    }
}
fn fresh(state: &State, now: u64) -> Option<Observation> {
    state
        .sampled
        .filter(|&at| now >= at && now - at <= MAX_AGE_NS)?;
    state.observed
}
