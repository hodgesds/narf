//! BMG I1 threshold actor. MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad
//! xe_hwmon.c::{xe_hwmon_pcode_read_i1,xe_hwmon_pcode_write_i1,
//! xe_hwmon_power_curr_crit_read,xe_hwmon_power_curr_crit_write}, xe_pcode_api.h.
//! DG2 explicitly rejects READ_I1 in that source. Firmware selects watts or
//! amperes; WRITE_I1 takes only U10.6 data and cannot select the mode.

use super::{
    pcode::{Client, Command, Fault, Reply},
    INTERVAL_NS, MAX_AGE_NS,
};
use alloc::{format, string::String};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

const READ: u32 = 0x047c;
const WRITE: u32 = 0x057c;
const DATA: u32 = 0xffff;
const WATTS: u32 = 1 << 31;
const IDENTITY: u32 = WATTS | DATA;

#[derive(Clone, Copy, Debug)]
struct Request {
    id: u64,
    value: u32,
    watts: bool,
}
#[derive(Clone, Copy, Debug)]
struct Observation {
    word: u32,
    at: u64,
}
impl Observation {
    fn watts(self) -> bool {
        self.word & WATTS != 0
    }
    fn raw(self) -> u32 {
        self.word & DATA
    }
    fn units(self, raw: u32) -> u64 {
        (u64::from(raw) * if self.watts() { 1_000_000 } else { 1000 }) >> 6
    }
}
#[derive(Clone, Copy, Debug)]
enum Phase {
    Idle,
    Reading(Option<Request>),
    NeedWrite(Request),
    Writing(Request),
    NeedVerify(Request),
    Verifying(Request),
}
impl Phase {
    fn id(self) -> u64 {
        match self {
            Self::Reading(Some(r))
            | Self::NeedWrite(r)
            | Self::Writing(r)
            | Self::NeedVerify(r)
            | Self::Verifying(r) => r.id,
            _ => 0,
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum Error {
    Mailbox(Fault),
    Bounds,
    Mode,
    Readback,
    Closed,
}
#[derive(Clone, Copy, Debug)]
enum Outcome {
    Unavailable,
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
    // NARF policy: the first nonzero threshold/mode is a retained ceiling,
    // never a SKU claim and never replaced with our own lowered threshold.
    boot: Option<Observation>,
    observed: Option<Observation>,
    last_post: Option<u64>,
    queued: Option<Request>,
    phase: Phase,
    disabled: bool,
    outcome: Outcome,
}
#[derive(Debug)]
pub(super) struct I1 {
    admission: AtomicU64,
    state: IrqSafeSpinLock<State>,
}
impl I1 {
    pub(super) fn new() -> Self {
        Self {
            admission: AtomicU64::new(0),
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                next: 1,
                boot: None,
                observed: None,
                last_post: None,
                queued: None,
                phase: Phase::Idle,
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
            state.outcome = Outcome::Failed(id, Error::Mailbox(fault));
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
                state.last_post = Some(now);
                state.phase = Phase::Reading(request);
                if let Some(r) = request {
                    state.observed = None;
                    state.outcome = Outcome::Applying(r.id);
                }
                (READ, 0, Reply::One)
            }
            Phase::NeedWrite(r) => {
                state.phase = Phase::Writing(r);
                (WRITE, r.value, Reply::None)
            }
            Phase::NeedVerify(r) => {
                state.phase = Phase::Verifying(r);
                (READ, 0, Reply::One)
            }
            _ => return None,
        };
        Some(Command {
            client: Client::I1,
            word,
            input: [input, 0],
            reply,
        })
    }
    pub(super) fn in_transaction(&self, epoch: u64) -> bool {
        let state = self.state.lock();
        self.current(epoch) && state.epoch == epoch && state.phase.id() != 0
    }
    pub(super) fn complete(&self, epoch: u64, now: u64, result: Result<[u32; 2], Fault>) {
        let mut state = self.state.lock();
        if !self.current(epoch) || state.epoch != epoch || state.disabled {
            return;
        }
        let id = state.phase.id();
        let failure = match result {
            Err(error) => Some(Error::Mailbox(error)),
            Ok(data) => match state.phase {
                Phase::Reading(request) => {
                    let observed = Observation {
                        word: data[0] & IDENTITY,
                        at: now,
                    };
                    if observed.raw() == 0 {
                        Some(Error::Bounds)
                    } else if state
                        .boot
                        .is_some_and(|boot| boot.watts() != observed.watts())
                    {
                        Some(Error::Mode)
                    } else {
                        let boot = *state.boot.get_or_insert(observed);
                        if let Some(request) = request {
                            if request.watts != observed.watts() {
                                Some(Error::Mode)
                            } else if request.value > boot.raw() || request.value == 0 {
                                Some(Error::Bounds)
                            } else {
                                state.phase = Phase::NeedWrite(request);
                                None
                            }
                        } else {
                            state.observed = Some(observed);
                            state.phase = Phase::Idle;
                            if matches!(state.outcome, Outcome::Unavailable) {
                                state.outcome = Outcome::Ready;
                            }
                            None
                        }
                    }
                }
                Phase::Writing(request) => {
                    state.phase = Phase::NeedVerify(request);
                    None
                }
                Phase::Verifying(request) => {
                    let wanted = request.value | if request.watts { WATTS } else { 0 };
                    if data[0] & IDENTITY != wanted {
                        Some(Error::Readback)
                    } else {
                        state.observed = Some(Observation {
                            word: wanted,
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
        if let Some(error) = failure {
            state.observed = None;
            state.queued = None;
            state.phase = Phase::Idle;
            state.disabled = true;
            state.outcome = Outcome::Failed(id, error);
        }
    }
    pub(super) fn store(&self, attribute: &str, bytes: &[u8], now: u64) -> Result<(), FsError> {
        if !narf_filesystem::caller_capable(21) {
            return Err(FsError::OperationNotPermitted);
        }
        let value = super::decimal(bytes)?;
        let watts = match attribute {
            "power1_crit" => true,
            "curr2_crit" => false,
            _ => return Err(FsError::Unsupported),
        };
        let mut state = self.state.lock();
        if !self.current(state.epoch) || state.disabled {
            return Err(FsError::NoDevice);
        }
        if state.queued.is_some() || !matches!(state.phase, Phase::Idle) {
            return Err(FsError::Busy);
        }
        let observed = state
            .observed
            .filter(|o| now >= o.at && now - o.at <= MAX_AGE_NS)
            .ok_or(FsError::NoDevice)?;
        let boot = state.boot.ok_or(FsError::NoDevice)?;
        if observed.watts() != watts || boot.watts() != watts {
            return Err(FsError::Unsupported);
        }
        let scale = if watts { 1_000_000 } else { 1000 };
        let raw = value
            .checked_mul(64)
            .and_then(|v| v.checked_add(scale / 2))
            .map(|v| v / scale)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(FsError::InvalidData)?;
        if raw == 0 || raw > boot.raw() || value < boot.units(1) || value > boot.units(boot.raw()) {
            return Err(FsError::InvalidData);
        }
        let id = state.next;
        state.next = id.checked_add(1).ok_or(FsError::Busy)?;
        state.queued = Some(Request {
            id,
            value: raw,
            watts,
        });
        state.outcome = Outcome::Queued(id);
        Ok(())
    }
    pub(super) fn show(&self, attribute: &str, now: u64) -> String {
        let state = self.state.lock();
        if attribute == "i1_status" {
            return match state.outcome {
                Outcome::Unavailable => "unavailable\n".into(),
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
        let (watts, suffix) = if let Some(suffix) = attribute.strip_prefix("power1_") {
            (true, suffix)
        } else if let Some(suffix) = attribute.strip_prefix("curr2_") {
            (false, suffix)
        } else {
            return String::new();
        };
        if observed.watts() != watts {
            return String::new();
        }
        if suffix == "label" {
            return if watts { "card\n" } else { "pkg\n" }.into();
        }
        let raw = match suffix {
            "crit" => Some(observed.raw()),
            "crit_default" | "crit_max" => state.boot.map(|boot| boot.raw()),
            "crit_min" => Some(1),
            _ => None,
        };
        raw.map_or_else(String::new, |raw| format!("{}\n", observed.units(raw)))
    }
}
