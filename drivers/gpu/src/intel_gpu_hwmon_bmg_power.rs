//! BMG card/package PL1/PL2 and interval actors. MIT Linux
//! b90c984d615e8ce2af96f5b1411a962d83fed2ad
//! xe_hwmon.c::{xe_hwmon_pcode_read_power_limit,xe_hwmon_pcode_rmw_power_limit,
//! xe_hwmon_get_preregistration_info,xe_hwmon_power_max_write,
//! xe_hwmon_power_max_interval_show,xe_hwmon_power_max_interval_store},
//! xe_pcode_api.h and regs/xe_mchbar_regs.h. Firmware-source discovery is
//! passive; only an explicit administrative request switches to PCODE limits.

use super::{
    interval,
    pcode::{Client, Command, Fault, Reply},
    INTERVAL_NS, MAX_AGE_NS,
};
use alloc::{format, string::String};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug)]
enum Channel {
    Package,
    Card,
}
impl Channel {
    fn read(self) -> u32 {
        match self {
            Self::Package => 0x087c,
            Self::Card => 0x067c,
        }
    }
    fn write(self) -> u32 {
        match self {
            Self::Package => 0x097c,
            Self::Card => 0x077c,
        }
    }
    fn client(self) -> Client {
        match self {
            Self::Package => Client::Power,
            Self::Card => Client::CardPower,
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Self::Package => "power2",
            Self::Card => "power1",
        }
    }
}
// PWR_LIM_VAL[14:0], PWR_LIM_EN[15], PWR_LIM[15:0]. BMG PWR_UNIT=3.
const VALUE: u32 = 0x7fff;
const ENABLE: u32 = 1 << 15;
const MASK: u32 = VALUE | ENABLE;
const STEP_UW: u64 = 125_000;
const TIME_SHIFT: u8 = 10; // xe_hwmon.c TIME_UNIT for mailbox power limits

fn enabled(word: u32) -> bool {
    word & ENABLE != 0 && word & VALUE != 0
}

#[derive(Clone, Copy, Debug)]
enum Setting {
    Limit(u32),
    Interval(u32),
}

#[derive(Clone, Copy, Debug)]
struct Request {
    id: u64,
    index: usize,
    setting: Setting,
}
impl Request {
    fn apply(self, mut pair: [u32; 2], boot: [Option<u32>; 2]) -> Option<[u32; 2]> {
        let max = boot[self.index]?;
        if !enabled(pair[self.index]) {
            return None;
        }
        // A paired write must not switch an unqualified/increased sibling
        // limit into the PCODE source. Only a selected limit reduction may
        // repair a current value above its retained ceiling.
        for (index, &word) in pair.iter().enumerate() {
            if word & ENABLE != 0 && word & VALUE == 0 {
                return None;
            }
            if enabled(word)
                && !(index == self.index && matches!(self.setting, Setting::Limit(_)))
                && boot[index].is_none_or(|ceiling| word & VALUE > ceiling)
            {
                return None;
            }
        }
        let word = &mut pair[self.index];
        *word = match self.setting {
            Setting::Limit(raw) if (1..=max).contains(&raw) => (*word & !MASK) | ENABLE | raw,
            Setting::Interval(bits)
                if interval::decode(bits, TIME_SHIFT) != 0
                    && interval::decode(bits, TIME_SHIFT) <= interval::maximum(TIME_SHIFT) =>
            {
                (*word & !interval::MASK) | bits
            }
            _ => return None,
        };
        Some(pair)
    }
}
#[derive(Clone, Copy, Debug)]
struct Observation {
    pair: [u32; 2],
    live: bool,
    at: u64,
}
#[derive(Clone, Copy, Debug)]
enum Phase {
    Idle,
    Reading(Option<Request>, bool), // bool: current PCODE source
    NeedWrite(Request, [u32; 2]),
    Writing(Request, [u32; 2]),
    NeedVerify(Request, [u32; 2]),
    Verifying(Request, [u32; 2]),
}
impl Phase {
    fn id(self) -> u64 {
        match self {
            Self::Reading(Some(r), _)
            | Self::NeedWrite(r, _)
            | Self::Writing(r, _)
            | Self::NeedVerify(r, _)
            | Self::Verifying(r, _) => r.id,
            _ => 0,
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum Error {
    Mailbox(Fault),
    Bounds,
    Readback,
    Closed,
}
#[derive(Clone, Copy, Debug)]
enum Outcome {
    Unavailable,
    DefaultOnly,
    Ready,
    Queued(u64),
    Applying(u64),
    Applied(u64),
    Failed(u64, Error),
}
#[derive(Debug)]
struct State {
    epoch: u64,
    next: u64,
    // First valid enabled firmware-source PL1/PL2 values, retained across
    // activations independently. Never adopt our lowered PCODE values.
    boot: [Option<u32>; 2],
    observed: Option<Observation>,
    last_post: Option<u64>,
    queued: Option<Request>,
    phase: Phase,
    source_owned: bool,
    disabled: bool,
    outcome: Outcome,
}
#[derive(Debug)]
pub(super) struct Power {
    channel: Channel,
    admission: AtomicU64,
    state: IrqSafeSpinLock<State>,
}
impl Power {
    pub(super) fn new() -> Self {
        Self::with_channel(Channel::Package)
    }
    pub(super) fn card() -> Self {
        Self::with_channel(Channel::Card)
    }
    fn with_channel(channel: Channel) -> Self {
        Self {
            channel,
            admission: AtomicU64::new(0),
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                next: 1,
                boot: [None; 2],
                observed: None,
                last_post: None,
                queued: None,
                phase: Phase::Idle,
                source_owned: false,
                disabled: false,
                outcome: Outcome::Unavailable,
            }),
        }
    }
    fn current(&self, epoch: u64) -> bool {
        epoch != 0 && self.admission.load(Ordering::Acquire) == epoch
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
        let id = state.queued.map_or(state.phase.id(), |r| r.id);
        state.epoch = 0;
        state.observed = None;
        state.last_post = None;
        state.queued = None;
        state.phase = Phase::Idle;
        state.source_owned = false;
        state.disabled = false;
        state.outcome = if id == 0 {
            Outcome::Unavailable
        } else {
            Outcome::Failed(id, Error::Closed)
        };
    }
    pub(super) fn access_lost(&self, epoch: u64) {
        self.port_lost(epoch, Fault::Access);
    }
    pub(super) fn port_lost(&self, epoch: u64, fault: Fault) {
        let mut state = self.state.lock();
        if !self.current(epoch) || state.epoch != epoch {
            return;
        }
        let id = state.queued.map_or(state.phase.id(), |r| r.id);
        state.observed = None;
        state.queued = None;
        state.phase = Phase::Idle;
        state.disabled = true;
        if id != 0 || !matches!(state.outcome, Outcome::Failed(_, _)) {
            state.outcome = Outcome::Failed(id, Error::Mailbox(fault))
        }
    }
    pub(super) fn command(&self, epoch: u64, now: u64) -> Option<Command> {
        let mut state = self.state.lock();
        if !self.current(epoch) || state.epoch != epoch || state.disabled {
            return None;
        }
        let (word, input, reply) = match state.phase {
            Phase::Idle => {
                let request = state.queued.take();
                if request.is_none()
                    && state
                        .last_post
                        .is_some_and(|at| now >= at && now - at < INTERVAL_NS)
                {
                    return None;
                }
                let current = state.source_owned;
                state.last_post = Some(now);
                state.phase = Phase::Reading(request, current);
                if let Some(request) = request {
                    state.outcome = Outcome::Applying(request.id);
                    state.observed = None;
                }
                (
                    self.channel.read() | if current { 0 } else { 1 << 16 },
                    [0; 2],
                    Reply::Two,
                )
            }
            Phase::NeedWrite(request, pair) => {
                state.phase = Phase::Writing(request, pair);
                (self.channel.write(), pair, Reply::None)
            }
            Phase::NeedVerify(request, pair) => {
                state.phase = Phase::Verifying(request, pair);
                (self.channel.read(), [0; 2], Reply::Two)
            }
            _ => return None,
        };
        Some(Command {
            client: self.channel.client(),
            word,
            input,
            reply,
        })
    }
    pub(super) fn in_transaction(&self, epoch: u64) -> bool {
        let state = self.state.lock();
        self.current(epoch) && state.epoch == epoch && state.phase.id() != 0
    }
    pub(super) fn complete(&self, epoch: u64, now: u64, result: Result<[u32; 2], Fault>) {
        let mut state = self.state.lock();
        if !self.current(epoch) || state.epoch != epoch {
            return;
        }
        let phase = state.phase;
        let error = match result {
            Err(error) => Some(Error::Mailbox(error)),
            Ok(pair) => match phase {
                Phase::Reading(request, current) => {
                    if !pair.iter().any(|&word| enabled(word)) {
                        Some(Error::Bounds)
                    } else {
                        if !current {
                            for (index, &word) in pair.iter().enumerate() {
                                if enabled(word) && state.boot[index].is_none() {
                                    state.boot[index] = Some(word & VALUE)
                                }
                            }
                        }
                        if let Some(request) = request {
                            if let Some(wanted) = request.apply(pair, state.boot) {
                                state.phase = Phase::NeedWrite(request, wanted);
                                None
                            } else {
                                Some(Error::Bounds)
                            }
                        } else {
                            state.observed = Some(Observation {
                                pair,
                                live: current,
                                at: now,
                            });
                            state.phase = Phase::Idle;
                            if matches!(
                                state.outcome,
                                Outcome::Unavailable | Outcome::Ready | Outcome::DefaultOnly
                            ) {
                                state.outcome = if current {
                                    Outcome::Ready
                                } else {
                                    Outcome::DefaultOnly
                                };
                            }
                            None
                        }
                    }
                }
                Phase::Writing(request, pair) => {
                    state.phase = Phase::NeedVerify(request, pair);
                    None
                }
                Phase::Verifying(request, wanted) => {
                    if pair != wanted {
                        Some(Error::Readback)
                    } else {
                        state.source_owned = true;
                        state.observed = Some(Observation {
                            pair,
                            live: true,
                            at: now,
                        });
                        state.phase = Phase::Idle;
                        state.outcome = Outcome::Applied(request.id);
                        None
                    }
                }
                _ => Some(Error::Mailbox(Fault::Identity)),
            },
        };
        if let Some(error) = error {
            state.observed = None;
            state.phase = Phase::Idle;
            state.disabled = true;
            state.outcome = Outcome::Failed(phase.id(), error);
        }
    }
    pub(super) fn store(&self, bytes: &[u8], now: u64) -> Result<(), FsError> {
        self.store_attribute("power2_max", bytes, now)
    }
    pub(super) fn store_attribute(
        &self,
        attribute: &str,
        bytes: &[u8],
        now: u64,
    ) -> Result<(), FsError> {
        if !narf_filesystem::caller_capable(21) {
            return Err(FsError::OperationNotPermitted);
        }
        let value = super::decimal(bytes)?;
        let (index, window) = match attribute.strip_prefix(self.channel.prefix()) {
            Some("_max") => (0, false),
            Some("_cap") => (1, false),
            Some("_max_interval") => (0, true),
            Some("_cap_interval") => (1, true),
            _ => return Err(FsError::Unsupported),
        };
        let mut state = self.state.lock();
        if !self.current(state.epoch) {
            return Err(FsError::NoDevice);
        }
        if state.queued.is_some() || !matches!(state.phase, Phase::Idle) {
            return Err(FsError::Busy);
        }
        if state.disabled {
            return Err(FsError::Unsupported);
        }
        let observed = state
            .observed
            .filter(|o| now >= o.at && now - o.at <= MAX_AGE_NS)
            .ok_or(FsError::NoDevice)?;
        if !enabled(observed.pair[index]) {
            return Err(FsError::Unsupported);
        }
        let max = state.boot[index].ok_or(FsError::Unsupported)?;
        let setting = if window {
            Setting::Interval(interval::encode(value, TIME_SHIFT)?)
        } else {
            let raw = value
                .checked_add(STEP_UW / 2)
                .map(|v| v / STEP_UW)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(FsError::InvalidData)?;
            if value < STEP_UW || value > u64::from(max) * STEP_UW || !(1..=max).contains(&raw) {
                return Err(FsError::InvalidData);
            }
            Setting::Limit(raw)
        };
        let id = state.next;
        state.next = id.checked_add(1).ok_or(FsError::Busy)?;
        state.queued = Some(Request { id, index, setting });
        state.outcome = Outcome::Queued(id);
        Ok(())
    }
    pub(super) fn show(&self, attribute: &str, now: u64) -> String {
        let Some(attribute) = attribute.strip_prefix(self.channel.prefix()) else {
            return String::new();
        };
        let state = self.state.lock();
        if matches!(attribute, "_max_status" | "_cap_status") {
            return match state.outcome {
                Outcome::Unavailable => "unavailable\n".into(),
                Outcome::DefaultOnly => "default-only\n".into(),
                Outcome::Ready => "ready\n".into(),
                Outcome::Queued(id) => format!("queued {id}\n"),
                Outcome::Applying(id) => format!("applying {id}\n"),
                Outcome::Applied(id) => format!("applied {id}\n"),
                Outcome::Failed(id, Error::Mailbox(error)) => format!("failed {id} {error:?}\n"),
                Outcome::Failed(id, error) => format!("failed {id} {error:?}\n"),
            };
        }
        if !self.current(state.epoch) {
            return String::new();
        }
        let Some(observed) = state
            .observed
            .filter(|o| now >= o.at && now - o.at <= MAX_AGE_NS)
        else {
            return String::new();
        };
        let (index, suffix) = if let Some(suffix) = attribute.strip_prefix("_max") {
            (0, suffix)
        } else if let Some(suffix) = attribute.strip_prefix("_cap") {
            (1, suffix)
        } else if attribute == "_rated_max" {
            (0, "")
        } else {
            return String::new();
        };
        if !enabled(observed.pair[index]) || state.boot[index].is_none() {
            return String::new();
        }
        if suffix.starts_with("_interval") {
            let value = match suffix {
                "_interval" if observed.live => {
                    Some(interval::decode(observed.pair[index], TIME_SHIFT))
                }
                "_interval_min" => Some(interval::minimum(TIME_SHIFT)),
                "_interval_max" => Some(interval::maximum(TIME_SHIFT)),
                _ => None,
            };
            return value.map_or_else(String::new, |value| format!("{value}\n"));
        }
        let raw = match suffix {
            "" if observed.live => Some(observed.pair[index] & VALUE),
            "_default" | "_max" => state.boot[index],
            // A representable policy floor, not a source-invented SKU fuse.
            "_min" => Some(1),
            _ => None,
        };
        raw.map_or_else(String::new, |v| format!("{}\n", u64::from(v) * STEP_UW))
    }
}
