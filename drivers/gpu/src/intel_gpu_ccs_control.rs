//! Client-free compute partition changes, serviced by the retained GT owner.
//!
//! MIT Linux b90c984d xe_gt_ccs_mode.c holds drm.filelist_mutex from its
//! empty-client check through reset. Our shared gate covers primary/render
//! namespace construction and teardown; an accepted asynchronous request
//! retains that gate until a verified fresh ready epoch. Sysfs never touches
//! hardware, waits for the worker, or reopens an uncertain transaction.

use alloc::{format, string::String, sync::Arc, vec::Vec};
use narf_filesystem::{
    sysfs::{kobject_add_attr, kobject_add_writable_attr, Kobject},
    FsError,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_engine::compute_selection,
    intel_gpu_gt::GtPlatform,
    intel_gpu_guc_boot::BootAllocator,
    intel_gpu_guc_gt::{GtError, GuCGt},
};

#[derive(Debug, Default)]
struct Clients {
    count: usize,
    blocked: bool,
}

#[derive(Debug)]
struct ClientGate(IrqSafeSpinLock<Clients>);

impl Default for ClientGate {
    fn default() -> Self {
        Self(IrqSafeSpinLock::new(Clients::default()))
    }
}

/// Held after every per-file namespace field has been destroyed. Cloned file
/// descriptors share one file lease, as Linux's drm_file does.
#[derive(Debug)]
pub struct ClientLease {
    gate: Arc<ClientGate>,
}

impl Drop for ClientLease {
    fn drop(&mut self) {
        let mut clients = self.gate.0.lock();
        clients.count = clients.count.checked_sub(1).expect("DRM client lease");
    }
}

impl ClientGate {
    fn open(self: &Arc<Self>) -> Result<ClientLease, FsError> {
        let mut clients = self.0.lock();
        if clients.blocked {
            return Err(FsError::Busy);
        }
        clients.count = clients.count.checked_add(1).ok_or(FsError::Busy)?;
        Ok(ClientLease { gate: self.clone() })
    }

    fn close_if_empty(&self) -> Result<(), FsError> {
        let mut clients = self.0.lock();
        if clients.blocked || clients.count != 0 {
            return Err(FsError::Busy);
        }
        clients.blocked = true;
        Ok(())
    }

    fn reopen(&self) {
        let mut clients = self.0.lock();
        if clients.blocked {
            assert_eq!(clients.count, 0);
            clients.blocked = false;
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_ccs_devfs_tests.rs"]
mod devfs_tests;

struct Entry {
    index: u32,
    gate: Arc<ClientGate>,
    control: Option<Arc<Control>>,
}
static CARDS: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

/// Only registered Intel card indices can allocate a card-lifetime gate.
/// This also tracks opens made before firmware/backend publication. The
/// synchronous devfs lookup maps Busy to a temporarily absent node; it never
/// constructs an uncounted namespace while reconfiguration owns the gate.
pub(crate) fn client_open(index: u32) -> Result<Option<ClientLease>, FsError> {
    if crate::drm_registry::driver_name(index) != Some("intel-gpu") {
        return Ok(None);
    }
    let gate = {
        let mut cards = CARDS.lock();
        gate(&mut cards, index)
    };
    gate.open().map(Some)
}

fn gate(cards: &mut Vec<Entry>, index: u32) -> Arc<ClientGate> {
    if let Some(entry) = cards.iter().find(|entry| entry.index == index) {
        return entry.gate.clone();
    }
    let gate = Arc::new(ClientGate::default());
    cards.push(Entry {
        index,
        gate: gate.clone(),
        control: None,
    });
    gate
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Configuration {
    epoch: u64,
    mask: u8,
    mode: u8,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct Request {
    pub(crate) id: u64,
    pub(crate) epoch: u64,
    pub(crate) mask: u8,
    pub(crate) mode: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Unavailable,
    Ready,
    Queued(u64),
    Applying(u64),
    Applied(u64),
    Failed(u64, FsError),
}

#[derive(Debug)]
struct State {
    available: bool,
    confirmed: Option<Configuration>,
    next: u64,
    queued: Option<Request>,
    applying: Option<Request>,
    outcome: Outcome,
    /// An accepted destructive transition can never reuse this or an older
    /// epoch, even if its request was cancelled by loss/system suspend.
    retired_epoch: u64,
}

/// One bounded mailbox per registered discrete card. Lock order is GT reset
/// mutex -> control -> client gate. Opens/drop take only the gate and release
/// it before entering DRM, namespace, or GT locks.
#[derive(Debug)]
pub struct Control {
    gate: Arc<ClientGate>,
    state: IrqSafeSpinLock<State>,
}

impl Control {
    #[cfg(feature = "kernel-test")]
    pub(crate) fn fixture() -> Self {
        Self::with_gate(Arc::new(ClientGate::default()))
    }

    #[cfg(feature = "kernel-test")]
    pub(crate) fn fixture_client(&self) -> Result<ClientLease, FsError> {
        self.gate.open()
    }

    #[cfg(feature = "kernel-test")]
    pub(crate) fn fixture_request(&self, mode: u8) -> Result<(), FsError> {
        self.enqueue(mode)
    }

    pub(crate) fn new(index: u32) -> Option<Arc<Self>> {
        let card = crate::drm_registry::card(index)?;
        if card.driver() != "intel-gpu"
            || !GtPlatform::from_pci(card.vendor_id(), card.device_id())?.is_discrete()
        {
            return None;
        }
        let mut cards = CARDS.lock();
        let gate = gate(&mut cards, index);
        let entry = cards.iter_mut().find(|entry| entry.index == index)?;
        Some(
            entry
                .control
                .get_or_insert_with(|| Arc::new(Self::with_gate(gate)))
                .clone(),
        )
    }

    fn with_gate(gate: Arc<ClientGate>) -> Self {
        Self {
            gate,
            state: IrqSafeSpinLock::new(State {
                available: false,
                confirmed: None,
                next: 1,
                queued: None,
                applying: None,
                outcome: Outcome::Unavailable,
                retired_epoch: 0,
            }),
        }
    }

    /// Caller has completed every selected engine's default/private probes
    /// and display recovery, under its reset mutex, before epoch publication.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn publish(&self, epoch: u64, configuration: (u8, u8)) -> Result<(), FsError> {
        self.publish_with(epoch, configuration, || {})
    }

    pub(crate) fn publish_with(
        &self,
        epoch: u64,
        configuration: (u8, u8),
        publish_epoch: impl FnOnce(),
    ) -> Result<(), FsError> {
        let (mask, mode) = configuration;
        if epoch == 0 || compute_selection(mask, mode).is_none() {
            return Err(FsError::InvalidData);
        }
        let mut state = self.state.lock();
        if epoch <= state.retired_epoch {
            return Err(FsError::NoDevice);
        }
        if let Some(request) = state.applying {
            if request.epoch == epoch || request.mask != mask || request.mode != mode {
                return Err(FsError::NoDevice);
            }
            state.applying = None;
            state.outcome = Outcome::Applied(request.id);
        } else if !matches!(state.outcome, Outcome::Failed(_, _) | Outcome::Queued(_)) {
            state.outcome = Outcome::Ready;
        }
        state.confirmed = Some(Configuration { epoch, mask, mode });
        state.available = true;
        publish_epoch();
        if state.queued.is_none() {
            self.gate.reopen();
        }
        Ok(())
    }

    /// Loss/S3 retires the confirmed epoch even without a pending request.
    /// A gate already held by a transaction stays closed until publish has a
    /// fresh verified graph; drop cannot reopen it. Clean idle park omits this.
    pub(crate) fn close(&self) {
        let mut state = self.state.lock();
        state.available = false;
        if let Some(confirmed) = state.confirmed {
            state.retired_epoch = state.retired_epoch.max(confirmed.epoch);
        }
        let cancelled = state.applying.take().or_else(|| state.queued.take());
        state.queued = None;
        if let Some(request) = cancelled {
            state.retired_epoch = state.retired_epoch.max(request.epoch);
            state.outcome = Outcome::Failed(request.id, FsError::NoDevice);
        } else if !matches!(state.outcome, Outcome::Failed(_, _)) {
            state.outcome = Outcome::Unavailable;
        }
    }

    pub(crate) fn needs_power(&self) -> bool {
        let state = self.state.lock();
        state.queued.is_some() || state.applying.is_some()
    }

    /// Claim only while the exclusive reset owner still sees the old ready
    /// epoch/configuration. Pending jobs include registration and retirement,
    /// even when their original file has closed. A busy refusal performs no
    /// reset and can safely reopen the unchanged ready graph.
    pub(crate) fn claim<M: MmioWindow, A: BootAllocator>(
        &self,
        gt: &GuCGt<M, A>,
        epoch: u64,
    ) -> Result<Option<Request>, GtError> {
        let mut state = self.state.lock();
        let Some(request) = state.queued else {
            return Ok(None);
        };
        if !state.available
            || request.epoch != epoch
            || gt.user_epoch() != Some(epoch)
            || gt.compute_configuration()
                != state.confirmed.map(|current| (request.mask, current.mode))
        {
            state.queued = None;
            state.available = false;
            state.outcome = Outcome::Failed(request.id, FsError::NoDevice);
            return Err(GtError::State);
        }
        state.queued = None;
        if !gt.idle() {
            state.outcome = Outcome::Failed(request.id, FsError::Busy);
            self.gate.reopen();
            return Ok(None);
        }
        state.applying = Some(request);
        state.retired_epoch = state.retired_epoch.max(request.epoch);
        state.available = false;
        state.outcome = Outcome::Applying(request.id);
        Ok(Some(request))
    }

    /// Run only under the physical GT reset mutex and a retained runtime-PM
    /// usage reference. The callback closes the published epoch, controls and
    /// IRQ delivery before the first reset write; it never awaits a display
    /// lock. An error leaves the applying request and gate retained.
    pub(crate) fn begin<M: MmioWindow, A: BootAllocator>(
        &self,
        gt: &mut GuCGt<M, A>,
        epoch: u64,
        now: u64,
        close: impl FnOnce(u8),
    ) -> Result<Option<u8>, GtError> {
        let Some(request) = self.claim(gt, epoch)? else {
            return Ok(None);
        };
        close(request.mode);
        gt.begin_stop(now)?;
        Ok(Some(request.mode))
    }

    fn enqueue(&self, mode: u8) -> Result<(), FsError> {
        let mut state = self.state.lock();
        if !state.available {
            return Err(FsError::NoDevice);
        }
        if state.queued.is_some() || state.applying.is_some() {
            return Err(FsError::Busy);
        }
        let current = state.confirmed.ok_or(FsError::NoDevice)?;
        if current.mask.count_ones() <= 1 {
            return Err(FsError::Unsupported);
        }
        if compute_selection(current.mask, mode).is_none() {
            return Err(FsError::InvalidData);
        }
        let id = state.next;
        let next = id.checked_add(1).ok_or(FsError::Busy)?;
        self.gate.close_if_empty()?;
        state.next = next;
        if mode == current.mode {
            state.outcome = Outcome::Applied(id);
            self.gate.reopen();
        } else {
            state.queued = Some(Request {
                id,
                epoch: current.epoch,
                mask: current.mask,
                mode,
            });
            state.outcome = Outcome::Queued(id);
        }
        Ok(())
    }

    pub(crate) fn store(&self, data: &[u8]) -> Result<(), FsError> {
        if !narf_filesystem::caller_capable(21) {
            return Err(FsError::OperationNotPermitted);
        }
        if data.len() > 16 {
            return Err(FsError::InvalidData);
        }
        let text = core::str::from_utf8(data)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        let mode = match text {
            "1" => 1,
            "2" => 2,
            "3" => 3,
            "4" => 4,
            _ => return Err(FsError::InvalidData),
        };
        self.enqueue(mode)
    }

    fn show(&self, attribute: &str) -> String {
        let state = self.state.lock();
        if attribute == "ccs_mode_status" {
            return match state.outcome {
                Outcome::Unavailable => String::from("unavailable\n"),
                Outcome::Ready => String::from("ready\n"),
                Outcome::Queued(id) => format!("queued {id}\n"),
                Outcome::Applying(id) => format!("applying {id}\n"),
                Outcome::Applied(id) => format!("applied {id}\n"),
                Outcome::Failed(id, error) => format!("failed {id} {error:?}\n"),
            };
        }
        let Some(current) = state.confirmed else {
            return String::new();
        };
        match attribute {
            "ccs_mode" => format!("{}\n", current.mode),
            "num_cslices" => format!("{}\n", current.mask.count_ones()),
            _ => String::new(),
        }
    }
}

fn control(index: u32) -> Option<Arc<Control>> {
    crate::drm_registry::card(index)?
        .intel_user_backend()?
        .ccs_control()
}

pub(crate) fn populate_card(index: u32, node: &Kobject) {
    let Some(card) = crate::drm_registry::card(index) else {
        return;
    };
    if card.driver() != "intel-gpu"
        || !GtPlatform::from_pci(card.vendor_id(), card.device_id())
            .is_some_and(GtPlatform::is_discrete)
    {
        return;
    }
    kobject_add_writable_attr(
        node,
        "ccs_mode",
        move || control(index).map_or_else(String::new, |control| control.show("ccs_mode")),
        move |data| control(index).ok_or(FsError::NoDevice)?.store(data),
    );
    for attribute in ["num_cslices", "ccs_mode_status"] {
        kobject_add_attr(node, attribute, move || {
            control(index).map_or_else(String::new, |control| control.show(attribute))
        });
    }
}
