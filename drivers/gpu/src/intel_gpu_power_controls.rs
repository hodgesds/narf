//! Per-card userspace SLPC requests, serviced by the existing GT owner.
//!
//! Frequency names follow MIT Linux i915's gt_*_freq_mhz attributes; range,
//! profile and status files are NARF extensions. Stores enqueue bounded work:
//! no sysfs callback waits for firmware or bridges into the executor. Only a
//! matched firmware reply/readback publishes confirmed values. Fused bounds
//! and BMG conservative constraints remain owned by intel_gpu_slpc.

use alloc::{format, string::String, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::{
    sysfs::{kobject_add_attr, kobject_add_writable_attr, Kobject},
    FsError,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_guc_boot::BootAllocator,
    intel_gpu_guc_gt::{GtError, GtState, GuCGt},
    intel_gpu_slpc::{FrequencyRange, PowerProfile, SlpcError, SlpcState, Status},
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Change {
    Range(FrequencyRange),
    Profile(PowerProfile),
}
#[derive(Copy, Clone, Debug)]
struct Request {
    id: u64,
    epoch: u64,
    change: Change,
    remember: bool,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Unavailable,
    Ready,
    Queued(u64),
    Applying(u64),
    Applied(u64),
    Failed(u64, SlpcError),
}
#[derive(Debug)]
struct State {
    epoch: u64,
    next: u64,
    confirmed: Option<Status>,
    queued: Option<Request>,
    applying: Option<Request>,
    desired: Option<Status>,
    replay_failed: bool,
    outcome: Outcome,
}

/// A per-GT policy mailbox. Admission is explicitly reopened by a verified
/// ready-epoch publication, never by servicing an old worker observation.
#[derive(Debug)]
pub struct PowerControls {
    admission: AtomicU64,
    state: IrqSafeSpinLock<State>,
}
impl Default for PowerControls {
    fn default() -> Self {
        Self::new()
    }
}

trait Target {
    fn state(&self) -> SlpcState;
    fn status(&self) -> Option<Status>;
    fn begin(&mut self, change: Change, now: u64) -> Result<(), SlpcError>;
}
impl<M: MmioWindow, A: BootAllocator> Target for GuCGt<M, A> {
    fn state(&self) -> SlpcState {
        self.slpc()
    }
    fn status(&self) -> Option<Status> {
        self.slpc_status()
    }
    fn begin(&mut self, change: Change, now: u64) -> Result<(), SlpcError> {
        match change {
            Change::Range(range) => self.begin_slpc_frequency_range(range, now),
            Change::Profile(profile) => self.begin_slpc_power_profile(profile, now),
        }
        .map_err(|error| match error {
            GtError::Busy => SlpcError::Busy,
            GtError::State => SlpcError::State,
            _ => SlpcError::Unavailable,
        })
    }
}

impl PowerControls {
    pub fn new() -> Self {
        Self {
            admission: AtomicU64::new(0),
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                next: 1,
                confirmed: None,
                queued: None,
                applying: None,
                desired: None,
                replay_failed: false,
                outcome: Outcome::Unavailable,
            }),
        }
    }
    pub(crate) fn activate(&self, epoch: u64) {
        if epoch == 0 {
            self.close();
            return;
        }
        let mut state = self.state.lock();
        state.epoch = epoch;
        state.confirmed = None;
        state.queued = None;
        state.applying = None;
        state.replay_failed = false;
        state.outcome = Outcome::Unavailable;
        self.admission.store(epoch, Ordering::Release);
    }
    pub(crate) fn close(&self) {
        self.admission.store(0, Ordering::Release);
        let mut state = self.state.lock();
        state.epoch = 0;
        state.confirmed = None;
        let cancelled = state.applying.take().or_else(|| state.queued.take());
        state.queued = None;
        state.outcome = cancelled.map_or(Outcome::Unavailable, |r| {
            Outcome::Failed(r.id, SlpcError::State)
        });
    }
    pub fn confirmed(&self) -> Option<Status> {
        let state = self.state.lock();
        (state.epoch != 0 && self.admission.load(Ordering::Acquire) == state.epoch)
            .then_some(state.confirmed)
            .flatten()
    }
    fn enqueue(
        &self,
        make: impl FnOnce(Status) -> Result<Change, FsError>,
    ) -> Result<u64, FsError> {
        let mut state = self.state.lock();
        let epoch = self.admission.load(Ordering::Acquire);
        if epoch == 0 || state.epoch != epoch {
            return Err(FsError::NoDevice);
        }
        if state.queued.is_some() || state.applying.is_some() {
            return Err(FsError::Busy);
        }
        let status = state.confirmed.ok_or(FsError::Unsupported)?;
        let change = make(status)?;
        let id = state.next;
        state.next = id.checked_add(1).ok_or(FsError::Busy)?;
        state.queued = Some(Request {
            id,
            epoch,
            change,
            remember: true,
        });
        state.replay_failed = false;
        state.confirmed = None;
        state.outcome = Outcome::Queued(id);
        Ok(id)
    }
    pub fn request_range(&self, range: FrequencyRange) -> Result<u64, FsError> {
        self.enqueue(|status| {
            status
                .limits
                .validate(range)
                .map_err(|_| FsError::InvalidData)?;
            Ok(Change::Range(range))
        })
    }
    pub fn request_profile(&self, profile: PowerProfile) -> Result<u64, FsError> {
        self.enqueue(|_| Ok(Change::Profile(profile)))
    }
    pub(crate) fn service<M: MmioWindow, A: BootAllocator>(
        &self,
        gt: &mut GuCGt<M, A>,
        epoch: u64,
        now: u64,
    ) {
        if gt.state() != GtState::SchedulingReady {
            self.close();
            return;
        }
        self.service_target(gt, epoch, now);
    }
    fn service_target(&self, target: &mut impl Target, epoch: u64, now: u64) {
        let observed = target.status();
        let request = {
            let mut state = self.state.lock();
            if epoch == 0 || state.epoch != epoch || self.admission.load(Ordering::Acquire) != epoch
            {
                return;
            }
            if let Some(active) = state.applying {
                match target.state() {
                    SlpcState::Running if observed.is_some() => {
                        state.applying = None;
                        state.confirmed = observed;
                        if active.remember {
                            state.desired = observed;
                        }
                        state.outcome = Outcome::Applied(active.id);
                        replay(&mut state, observed, epoch);
                    }
                    SlpcState::Off | SlpcState::Unavailable => {
                        state.applying = None;
                        state.confirmed = None;
                        state.outcome = Outcome::Failed(active.id, SlpcError::Unavailable);
                        state.replay_failed = true;
                    }
                    _ => {}
                }
                return;
            }
            if let Some(request) = state.queued.take() {
                if request.epoch != epoch
                    || observed.is_none()
                    || target.state() != SlpcState::Running
                {
                    state.outcome = Outcome::Failed(request.id, SlpcError::Unavailable);
                    return;
                }
                state.applying = Some(request);
                state.outcome = Outcome::Applying(request.id);
                Some(request)
            } else {
                state.confirmed = observed;
                if observed.is_some() && state.outcome == Outcome::Unavailable {
                    state.outcome = Outcome::Ready;
                }
                replay(&mut state, observed, epoch);
                None
            }
        };
        if let Some(request) = request {
            // No await and no policy lock while issuing the native GT call.
            // The caller retains the GT reset/power mutex for this service.
            if self.admission.load(Ordering::Acquire) != epoch {
                return;
            }
            if let Err(error) = target.begin(request.change, now) {
                let mut state = self.state.lock();
                if state.epoch == epoch && self.admission.load(Ordering::Acquire) == epoch {
                    state.applying = None;
                    state.confirmed = target.status();
                    state.outcome = Outcome::Failed(request.id, error);
                    state.replay_failed = true;
                }
            }
        }
    }
    fn report(&self) -> String {
        let state = self.state.lock();
        format!(
            "epoch={} state={:?}\n",
            self.admission.load(Ordering::Acquire),
            state.outcome
        )
    }
    fn store(&self, attribute: &str, data: &[u8]) -> Result<(), FsError> {
        let text = core::str::from_utf8(data)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        if text.len() > 64 {
            return Err(FsError::InvalidData);
        }
        match attribute {
            "slpc_frequency_range" => {
                let mut fields = text.split_ascii_whitespace();
                let min_mhz = number(fields.next().ok_or(FsError::InvalidData)?)?;
                let max_mhz = number(fields.next().ok_or(FsError::InvalidData)?)?;
                if fields.next().is_some() {
                    return Err(FsError::InvalidData);
                }
                self.request_range(FrequencyRange { min_mhz, max_mhz })?;
            }
            "gt_min_freq_mhz" | "gt_max_freq_mhz" => {
                let value = number(text)?;
                self.enqueue(|status| {
                    let range = if attribute == "gt_min_freq_mhz" {
                        FrequencyRange {
                            min_mhz: value,
                            ..status.range
                        }
                    } else {
                        FrequencyRange {
                            max_mhz: value,
                            ..status.range
                        }
                    };
                    status
                        .limits
                        .validate(range)
                        .map_err(|_| FsError::InvalidData)?;
                    Ok(Change::Range(range))
                })?;
            }
            "slpc_power_profile" => {
                self.request_profile(match text {
                    "base" => PowerProfile::Base,
                    "power-saving" => PowerProfile::PowerSaving,
                    _ => return Err(FsError::InvalidData),
                })?;
            }
            _ => return Err(FsError::Unsupported),
        }
        Ok(())
    }
    fn show(&self, attribute: &str) -> String {
        if attribute == "slpc_status" {
            return self.report();
        }
        let Some(status) = self.confirmed() else {
            return String::new();
        };
        match attribute {
            "gt_min_freq_mhz" => format!("{}\n", status.range.min_mhz),
            "gt_max_freq_mhz" => format!("{}\n", status.range.max_mhz),
            "gt_RPn_freq_mhz" => format!("{}\n", status.limits.rpn_mhz),
            "gt_RP1_freq_mhz" => format!("{}\n", status.limits.rpe_mhz),
            "gt_RP0_freq_mhz" => format!("{}\n", status.limits.rp0_mhz),
            "slpc_frequency_range" => {
                format!("{} {}\n", status.range.min_mhz, status.range.max_mhz)
            }
            "slpc_power_profile" => String::from(match status.profile {
                PowerProfile::Base => "base\n",
                PowerProfile::PowerSaving => "power-saving\n",
            }),
            _ => String::new(),
        }
    }
}
fn replay(state: &mut State, observed: Option<Status>, epoch: u64) {
    let (Some(wanted), Some(current)) = (state.desired, observed) else {
        return;
    };
    if state.replay_failed || (wanted.range == current.range && wanted.profile == current.profile) {
        return;
    }
    let id = state.next;
    let Some(next) = id.checked_add(1) else {
        return;
    };
    state.next = next;
    if current.limits.validate(wanted.range).is_err() {
        state.replay_failed = true;
        state.outcome = Outcome::Failed(id, SlpcError::FrequencyRange);
        return;
    }
    let change = if wanted.range != current.range {
        Change::Range(wanted.range)
    } else {
        Change::Profile(wanted.profile)
    };
    state.queued = Some(Request {
        id,
        epoch,
        change,
        remember: false,
    });
    state.confirmed = None;
    state.outcome = Outcome::Queued(id);
}
fn number(text: &str) -> Result<u32, FsError> {
    text.parse().map_err(|_| FsError::InvalidData)
}
fn controls(index: u32) -> Option<Arc<PowerControls>> {
    crate::drm_registry::card(index)?
        .intel_user_backend()?
        .power_controls()
}

/// Install before firmware readiness as well; every callback resolves this
/// card's current backend rather than capturing an old GT/reset incarnation.
pub(crate) fn populate_card(index: u32, node: &Kobject) {
    if crate::drm_registry::card(index).is_none_or(|card| card.vendor_id() != 0x8086) {
        return;
    }
    for attribute in [
        "gt_min_freq_mhz",
        "gt_max_freq_mhz",
        "slpc_frequency_range",
        "slpc_power_profile",
    ] {
        kobject_add_writable_attr(
            node,
            attribute,
            move || controls(index).map_or_else(String::new, |c| c.show(attribute)),
            move |data| {
                controls(index)
                    .ok_or(FsError::NoDevice)?
                    .store(attribute, data)
            },
        );
    }
    for attribute in [
        "gt_RPn_freq_mhz",
        "gt_RP1_freq_mhz",
        "gt_RP0_freq_mhz",
        "slpc_status",
    ] {
        kobject_add_attr(node, attribute, move || {
            controls(index).map_or_else(String::new, |c| c.show(attribute))
        });
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_power_controls_tests.rs"]
mod tests;
