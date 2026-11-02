//! Per-card runtime-PM policy through the actual PCI/GT owner.
//!
//! MIT Linux b90c984d drivers/base/power/sysfs.c control_store,
//! autosuspend_delay_ms_store and runtime_status_show. Callbacks enqueue one
//! bounded request; the card worker executes it outside the GT mutex. Policy
//! selection is distinct from live active/suspended state and callback errors.

use alloc::{
    format,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::{
    sysfs::{get_or_create_child, kobject_add_attr, kobject_add_writable_attr, Kobject},
    FsError,
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::runtime_pm::{RpmError, RpmStatus, RuntimePmDevice};

#[derive(Clone, Copy, Debug)]
enum Change {
    On,
    Auto,
    Delay(i32),
}
#[derive(Clone, Copy, Debug)]
struct Request {
    id: u64,
    epoch: u64,
    change: Change,
}
#[derive(Clone, Copy, Debug)]
enum Outcome {
    Closed,
    Ready,
    Queued(u64),
    Applying(u64),
    Applied(u64),
    Failed(u64, RpmError),
}
struct State {
    epoch: u64,
    next: u64,
    autosuspend_ready: bool,
    queued: Option<Request>,
    applying: Option<Request>,
    outcome: Outcome,
}

pub(crate) struct Control {
    device: Arc<RuntimePmDevice>,
    epoch: Arc<AtomicU64>,
    auto_eligible: bool,
    state: IrqSafeSpinLock<State>,
}
static CONTROLS: IrqSafeSpinLock<Vec<(u32, Weak<Control>)>> = IrqSafeSpinLock::new(Vec::new());

impl Control {
    pub(crate) fn register(
        index: u32,
        device: Arc<RuntimePmDevice>,
        epoch: Arc<AtomicU64>,
        auto_eligible: bool,
    ) -> Arc<Self> {
        let control = Arc::new(Self {
            device,
            epoch,
            auto_eligible,
            state: IrqSafeSpinLock::new(State {
                epoch: 0,
                next: 1,
                autosuspend_ready: false,
                queued: None,
                applying: None,
                outcome: Outcome::Closed,
            }),
        });
        let old = {
            let mut controls = CONTROLS.lock();
            if let Some(slot) = controls.iter_mut().find(|(card, _)| *card == index) {
                Some(core::mem::replace(&mut slot.1, Arc::downgrade(&control)))
            } else {
                controls.push((index, Arc::downgrade(&control)));
                None
            }
        };
        drop(old);
        control
    }
    /// Fresh user publication opens requests; old queued operations never replay.
    pub(crate) fn activate(&self, epoch: u64) {
        let mut state = self.state.lock();
        if state.epoch != epoch {
            state.queued = None;
            state.applying = None;
            state.outcome = Outcome::Ready;
        }
        state.epoch = epoch;
    }
    pub(crate) fn autosuspend_ready(&self) {
        self.state.lock().autosuspend_ready = true;
    }
    pub(crate) fn close(&self) {
        let mut state = self.state.lock();
        state.epoch = 0;
        state.queued = None;
        state.applying = None;
        state.outcome = Outcome::Closed;
    }
    fn enqueue(&self, change: Change) -> Result<(), FsError> {
        let mut state = self.state.lock();
        let epoch = self.epoch.load(Ordering::Acquire);
        if epoch == 0 || state.epoch != epoch {
            return Err(FsError::NoDevice);
        }
        if !matches!(change, Change::On) && (!self.auto_eligible || !state.autosuspend_ready) {
            return Err(FsError::Unsupported);
        }
        if state.queued.is_some() || state.applying.is_some() {
            return Err(FsError::Busy);
        }
        let id = state.next;
        state.next = id.checked_add(1).ok_or(FsError::Busy)?;
        state.queued = Some(Request { id, epoch, change });
        state.outcome = Outcome::Queued(id);
        Ok(())
    }
    fn store(&self, attribute: &str, bytes: &[u8]) -> Result<(), FsError> {
        if bytes.len() > 32 {
            return Err(FsError::InvalidData);
        }
        let text = core::str::from_utf8(bytes)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        let change = match attribute {
            "control" => match text {
                "on" => Change::On,
                "auto" => Change::Auto,
                _ => return Err(FsError::InvalidData),
            },
            "autosuspend_delay_ms" => {
                Change::Delay(text.parse().map_err(|_| FsError::InvalidData)?)
            }
            _ => return Err(FsError::Unsupported),
        };
        self.enqueue(change)
    }
    fn show(&self, attribute: &str) -> String {
        let outcome = {
            let state = self.state.lock();
            let epoch = self.epoch.load(Ordering::Acquire);
            if state.epoch == 0 || state.epoch != epoch {
                return String::new();
            }
            state.outcome
        };
        // In-memory core snapshot only: neither reads nor time accounting
        // invoke the driver, resume a parked card, or touch PCI/MMIO.
        let actual = self.device.state();
        match attribute {
            "control" => String::from(if actual.runtime_auto {
                "auto\n"
            } else {
                "on\n"
            }),
            "autosuspend_delay_ms" if actual.use_autosuspend => {
                format!("{}\n", actual.autosuspend_delay_ms)
            }
            "runtime_status" => String::from(if actual.runtime_error.is_some() {
                "error\n"
            } else if actual.disable_depth != 0 {
                "unsupported\n"
            } else {
                match actual.status {
                    RpmStatus::Active => "active\n",
                    RpmStatus::Suspended => "suspended\n",
                    RpmStatus::Suspending => "suspending\n",
                    RpmStatus::Resuming => "resuming\n",
                }
            }),
            "runtime_active_time" => format!("{}\n", actual.active_time_ns / 1_000_000),
            "runtime_suspended_time" => format!("{}\n", actual.suspended_time_ns / 1_000_000),
            "runtime_control_status" => match outcome {
                Outcome::Closed => String::new(),
                Outcome::Ready => String::from("ready\n"),
                Outcome::Queued(id) => format!("queued {id}\n"),
                Outcome::Applying(id) => format!("applying {id}\n"),
                Outcome::Applied(id) => format!("applied {id}\n"),
                Outcome::Failed(id, error) => format!("failed {id} {error:?}\n"),
            },
            _ => String::new(),
        }
    }
    /// Called only outside the GT mutex: forbid/delay can resume or park,
    /// and those callbacks acquire that same mutex. No IRQ-safe guard awaits.
    pub(crate) async fn service(&self, current: impl Fn() -> bool) {
        if !current() {
            self.close();
            return;
        }
        let request = {
            let mut state = self.state.lock();
            let epoch = self.epoch.load(Ordering::Acquire);
            if epoch == 0 || state.epoch != epoch {
                state.queued = None;
                state.applying = None;
                state.epoch = 0;
                state.outcome = Outcome::Closed;
                return;
            }
            let Some(request) = state.queued.take() else {
                return;
            };
            if request.epoch != epoch {
                return;
            }
            state.applying = Some(request);
            state.outcome = Outcome::Applying(request.id);
            request
        };
        let mut guard = Applying {
            control: self,
            request,
            done: false,
        };
        let operation = async {
            match request.change {
                Change::On => self.device.forbid().await.map(|_| ()),
                Change::Auto => {
                    self.device.allow();
                    Ok(())
                }
                Change::Delay(delay) => {
                    self.device.set_autosuspend_delay(delay).await;
                    Ok(())
                }
            }
        };
        let result = narf_time::timeout(narf_time::Deadline::after_ms(2000), operation)
            .await
            .unwrap_or(Err(RpmError::Cancelled));
        let current = current();
        let actual = self.device.state();
        let mut state = self.state.lock();
        guard.done = true;
        if state
            .applying
            .is_none_or(|active| active.id != request.id || active.epoch != request.epoch)
        {
            return;
        }
        state.applying = None;
        if !current
            || self.epoch.load(Ordering::Acquire) != request.epoch
            || state.epoch != request.epoch
        {
            state.epoch = 0;
            state.outcome = Outcome::Closed;
            return;
        }
        state.outcome = match result.and_then(|()| actual.runtime_error.map_or(Ok(()), Err)) {
            Ok(()) => Outcome::Applied(request.id),
            Err(error) => Outcome::Failed(request.id, error),
        };
    }
}
struct Applying<'a> {
    control: &'a Control,
    request: Request,
    done: bool,
}
impl Drop for Applying<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut state = self.control.state.lock();
        if state.applying.is_some_and(|active| {
            active.id == self.request.id && active.epoch == self.request.epoch
        }) {
            state.applying = None;
            state.outcome = Outcome::Failed(self.request.id, RpmError::Cancelled);
        }
    }
}
fn lookup(index: u32) -> Option<Arc<Control>> {
    CONTROLS
        .lock()
        .iter()
        .find(|(card, _)| *card == index)?
        .1
        .upgrade()
}

/// PCI parent projection. A pre-existing generic owner is never overwritten.
/// Resolve at each callback so early sysfs publication and reset cannot pin
/// an old incarnation. Current CAP_SYS_ADMIN is checked at each store.
pub(crate) fn populate_card(index: u32, parent: &Arc<Kobject>) {
    if crate::drm_registry::card(index).is_none_or(|card| card.vendor_id() != 0x8086) {
        return;
    }
    let power = get_or_create_child(parent, "power");
    populate(&power, move || lookup(index));
}
fn populate(
    node: &Kobject,
    resolve: impl Fn() -> Option<Arc<Control>> + Clone + Send + Sync + 'static,
) {
    if node.has_attr("control") {
        return;
    }
    for attribute in ["control", "autosuspend_delay_ms"] {
        let show = resolve.clone();
        let store = resolve.clone();
        kobject_add_writable_attr(
            node,
            attribute,
            move || show().map_or_else(String::new, |control| control.show(attribute)),
            move |bytes| {
                if !narf_filesystem::caller_capable(21) {
                    return Err(FsError::OperationNotPermitted);
                }
                store().ok_or(FsError::NoDevice)?.store(attribute, bytes)
            },
        );
    }
    for attribute in [
        "runtime_status",
        "runtime_active_time",
        "runtime_suspended_time",
        "runtime_control_status",
    ] {
        let show = resolve.clone();
        kobject_add_attr(node, attribute, move || {
            show().map_or_else(String::new, |control| control.show(attribute))
        });
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_runtime_power_tests.rs"]
mod tests;
