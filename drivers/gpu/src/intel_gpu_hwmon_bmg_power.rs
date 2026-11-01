//! BMG package PL1 actor. MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad
//! xe_hwmon.c::{xe_hwmon_pcode_read_power_limit,xe_hwmon_pcode_rmw_power_limit,
//! xe_hwmon_get_preregistration_info,xe_hwmon_power_max_write},
//! xe_pcode_api.h and regs/xe_mchbar_regs.h. Firmware-source discovery is
//! passive; only an explicit administrative request switches to PCODE limits.

use super::{
    pcode::{Client, Command, Fault, Reply},
    INTERVAL_NS, MAX_AGE_NS,
};
use alloc::{format, string::String};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

const READ: u32 = 0x087c;
const READ_FW: u32 = 0x01087c;
const WRITE: u32 = 0x097c;
// PWR_LIM_VAL[14:0], PWR_LIM_EN[15], PWR_LIM[15:0]. BMG PWR_UNIT=3.
const VALUE: u32 = 0x7fff;
const ENABLE: u32 = 1 << 15;
const MASK: u32 = VALUE | ENABLE;
const STEP_UW: u64 = 125_000;

#[derive(Clone, Copy, Debug)]
struct Request {
    id: u64,
    raw: u32,
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
    // First valid enabled firmware-source PL1, retained across all activations.
    boot: Option<u32>,
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
                boot: None,
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
                (if current { READ } else { READ_FW }, [0; 2], Reply::Two)
            }
            Phase::NeedWrite(request, pair) => {
                state.phase = Phase::Writing(request, pair);
                (WRITE, pair, Reply::None)
            }
            Phase::NeedVerify(request, pair) => {
                state.phase = Phase::Verifying(request, pair);
                (READ, [0; 2], Reply::Two)
            }
            _ => return None,
        };
        Some(Command {
            client: Client::Power,
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
                    if pair[0] & ENABLE == 0 || pair[0] & VALUE == 0 {
                        Some(Error::Bounds)
                    } else {
                        if !current && state.boot.is_none() {
                            state.boot = Some(pair[0] & VALUE)
                        }
                        if let Some(request) = request {
                            if state
                                .boot
                                .is_none_or(|max| request.raw == 0 || request.raw > max)
                            {
                                Some(Error::Bounds)
                            } else {
                                state.phase = Phase::NeedWrite(
                                    request,
                                    [(pair[0] & !MASK) | ENABLE | request.raw, pair[1]],
                                );
                                None
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
        let value: u64 = text.parse().map_err(|_| FsError::InvalidData)?;
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
        if observed.pair[0] & ENABLE == 0 {
            return Err(FsError::Unsupported);
        }
        let max = state.boot.ok_or(FsError::Unsupported)?;
        let raw = value
            .checked_add(STEP_UW / 2)
            .map(|v| v / STEP_UW)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(FsError::InvalidData)?;
        if value < STEP_UW || value > u64::from(max) * STEP_UW || !(1..=max).contains(&raw) {
            return Err(FsError::InvalidData);
        }
        let id = state.next;
        state.next = id.checked_add(1).ok_or(FsError::Busy)?;
        state.queued = Some(Request { id, raw });
        state.outcome = Outcome::Queued(id);
        Ok(())
    }
    pub(super) fn show(&self, attribute: &str, now: u64) -> String {
        let state = self.state.lock();
        if attribute == "power2_max_status" {
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
        let raw = match attribute {
            "power2_max" | "power2_rated_max" if observed.live => Some(observed.pair[0] & VALUE),
            "power2_max_default" | "power2_max_max" => state.boot,
            // A representable policy floor, not a source-invented SKU fuse.
            "power2_max_min" => Some(1),
            _ => None,
        };
        raw.map_or_else(String::new, |v| format!("{}\n", u64::from(v) * STEP_UW))
    }
}
