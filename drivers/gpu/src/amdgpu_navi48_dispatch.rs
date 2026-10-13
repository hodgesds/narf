//! Owner- and generation-checked delivery of native Navi48 completions,
//! faults, display events and terminal device errors. This follows Linux
//! amdgpu_fence.c: an interrupt vector only *wakes* its owner
//! (amdgpu_fence_process), which then validates its own memory fence. The
//! per-waiter watchdog plays amdgpu_fence_fallback's role when an interrupt is
//! lost, and terminal delivery replaces amdgpu_fence_driver_force_completion
//! on a dead device. No IV payload ever completes work by itself, and a vector
//! for an unregistered, retired or mismatched owner only increments a counter.
use crate::{amdgpu_ih7 as ih, amdgpu_navi48_sources as src};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

pub const SLOTS: usize = 16;
const WAITERS: usize = 8;
/// Every waiter re-checks its owner's fence at least this often, even with
/// no interrupt (Linux's fallback timer uses 500 ms).
pub const WATCHDOG_MS: u64 = 100;

/// The hardware identity a completion or fault vector is attributed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// A CP hardware queue slot (kernel or MES-mapped), exact ME/pipe/queue.
    Cp(src::Queue),
    /// An SDMA instance/queue.
    Sdma { instance: u8, queue: u8 },
    /// A user queue named by its non-zero doorbell offset, as the CP EOP
    /// and SDMA fence payloads carry it (amdgpu_userq_process_fence_irq).
    Doorbell(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub key: Key,
    /// Completion vectors must carry exactly this VMID and PASID, and VM or
    /// shader faults are attributed to every owner of the faulting context.
    pub vmid: u8,
    pub pasid: u16,
}
/// One registration of an owner. A retired or recovered registration bumps
/// the slot generation, so older handles observe `Stale` and never complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    slot: u8,
    generation: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    /// MMIO reads all-ones: surprise removal or a dead link.
    DeviceGone,
    /// The interrupt service failed and stopped draining.
    Interrupts(ih::Error),
    /// Poison/RAS consumption; Linux would reset the GPU.
    Poison(src::Poison),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitError {
    /// The handle's registration was retired or recovered.
    Stale,
    /// The owner faulted; it must recover before new work can complete.
    Faulted(src::Fault),
    Terminal(Terminal),
    Timeout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    Invalid,
    /// The key already has a live owner.
    Busy,
    Full,
    Terminal(Terminal),
}
/// Observable completion paths. `watchdog_completions` counts fences first
/// seen by the watchdog rather than after a wake: evidence of a lost or
/// unrouted interrupt, as Linux warns from its fallback timer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub signals: u64,
    pub completions: u64,
    pub signal_wakes: u64,
    pub watchdog_wakes: u64,
    pub watchdog_completions: u64,
    pub timeouts: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub owner: Owner,
    pub generation: u32,
    pub fault: Option<src::Fault>,
    pub stats: Stats,
}
/// Display event bits for `wait_display`.
pub const HOTPLUG: u32 = 1;
pub const FLIP: u32 = 2;
pub const VUPDATE: u32 = 4;
pub const VBLANK: u32 = 8;
pub const VLINE: u32 = 16;
pub const DMUB: u32 = 32;
/// Per-instance DCN401 event counts. `lost` counts IH overflows (and the
/// terminal transition), after which a consumer must re-read hardware state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayEvents {
    pub hpd: [u64; 6],
    pub hpd_rx: [u64; 6],
    pub vblank: [u64; 6],
    pub vline0: [u64; 6],
    pub flip: [u64; 6],
    pub vupdate: [u64; 6],
    pub dmub: u64,
    pub lost: u64,
}
impl DisplayEvents {
    fn version(&self, mask: u32) -> u64 {
        let sum = |a: &[u64; 6]| a.iter().fold(0u64, |s, v| s.wrapping_add(*v));
        let mut v = self.lost;
        for (bit, count) in [
            (HOTPLUG, sum(&self.hpd).wrapping_add(sum(&self.hpd_rx))),
            (FLIP, sum(&self.flip)),
            (VUPDATE, sum(&self.vupdate)),
            (VBLANK, sum(&self.vblank)),
            (VLINE, sum(&self.vline0)),
            (DMUB, self.dmub),
        ] {
            if mask & bit != 0 {
                v = v.wrapping_add(count);
            }
        }
        v
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Completion vectors with no live owner, or a VMID/PASID mismatch.
    pub unowned: u64,
    /// Faults with no live owner; they still raise recovery.
    pub unattributed: u64,
    pub media: u64,
    pub power: u64,
    pub shader_messages: u64,
    pub unknown: u64,
    /// IH overflows: every waiter was woken to re-check its fence.
    pub lost: u64,
    /// Waiters that could not park and rely on the watchdog alone.
    pub unparked: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    pub terminal: Option<Terminal>,
    pub live: usize,
    pub counters: Counters,
    pub display: DisplayEvents,
}
/// What one vector did, for diagnostics and models.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Signaled,
    Faulted(usize),
    Unowned,
    Unattributed,
    Terminal(Terminal),
    Display,
    Ignored,
}

type Waiters = [Option<(u64, u32, Waker)>; WAITERS];
fn park(waiters: &mut Waiters, id: u64, mask: u32, waker: &Waker) -> bool {
    if let Some(w) = waiters.iter_mut().flatten().find(|w| w.0 == id) {
        w.1 = mask;
        w.2.clone_from(waker);
        return true;
    }
    match waiters.iter_mut().find(|w| w.is_none()) {
        Some(free) => {
            *free = Some((id, mask, waker.clone()));
            true
        }
        None => false,
    }
}
fn unpark(waiters: &mut Waiters, id: u64) {
    for w in waiters.iter_mut() {
        if w.as_ref().is_some_and(|w| w.0 == id) {
            *w = None;
        }
    }
}
fn wake(waiters: &Waiters, mask: u32) {
    for (_, interest, waker) in waiters.iter().flatten() {
        if interest & mask != 0 {
            waker.wake_by_ref();
        }
    }
}

#[derive(Debug)]
struct Slot {
    owner: Option<Owner>,
    generation: u32,
    seq: u64,
    fault: Option<src::Fault>,
    stats: Stats,
    waiters: Waiters,
}
impl Slot {
    const fn new() -> Self {
        Self {
            owner: None,
            generation: 1,
            seq: 0,
            fault: None,
            stats: Stats {
                signals: 0,
                completions: 0,
                signal_wakes: 0,
                watchdog_wakes: 0,
                watchdog_completions: 0,
                timeouts: 0,
            },
            waiters: [const { None }; WAITERS],
        }
    }
    fn bump(&mut self) {
        self.seq = self.seq.wrapping_add(1);
        wake(&self.waiters, u32::MAX);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Slot(u8),
    Display(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Woke {
    First,
    Signal,
    Watchdog,
}
#[derive(Debug)]
pub struct Table {
    slots: [Slot; SLOTS],
    terminal: Option<Terminal>,
    display: DisplayEvents,
    display_waiters: Waiters,
    next_id: u64,
    counters: Counters,
}
impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}
impl Table {
    pub const fn new() -> Self {
        Self {
            slots: [const { Slot::new() }; SLOTS],
            terminal: None,
            display: DisplayEvents {
                hpd: [0; 6],
                hpd_rx: [0; 6],
                vblank: [0; 6],
                vline0: [0; 6],
                flip: [0; 6],
                vupdate: [0; 6],
                dmub: 0,
                lost: 0,
            },
            display_waiters: [const { None }; WAITERS],
            next_id: 1,
            counters: Counters {
                unowned: 0,
                unattributed: 0,
                media: 0,
                power: 0,
                shader_messages: 0,
                unknown: 0,
                lost: 0,
                unparked: 0,
            },
        }
    }
    fn slot(&self, h: Handle) -> Result<&Slot, WaitError> {
        let slot = self.slots.get(h.slot as usize).ok_or(WaitError::Stale)?;
        if slot.owner.is_none() || slot.generation != h.generation {
            return Err(WaitError::Stale);
        }
        Ok(slot)
    }
    fn slot_mut(&mut self, h: Handle) -> Result<&mut Slot, WaitError> {
        self.slot(h)?;
        Ok(&mut self.slots[h.slot as usize])
    }
    pub fn register(&mut self, owner: Owner) -> Result<Handle, RegisterError> {
        if let Some(t) = self.terminal {
            return Err(RegisterError::Terminal(t));
        }
        if owner.key == Key::Doorbell(0) || owner.vmid > 15 {
            return Err(RegisterError::Invalid);
        }
        if self
            .slots
            .iter()
            .any(|s| s.owner.is_some_and(|o| o.key == owner.key))
        {
            return Err(RegisterError::Busy);
        }
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.owner.is_none())
            .ok_or(RegisterError::Full)?;
        slot.owner = Some(owner);
        slot.fault = None;
        slot.stats = Stats::default();
        Ok(Handle {
            slot: index as u8,
            generation: slot.generation,
        })
    }
    fn next_generation(slot: &mut Slot) {
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.bump();
    }
    /// End a registration. Its waiters observe `Stale`.
    pub fn retire(&mut self, h: Handle) -> Result<(), WaitError> {
        let slot = self.slot_mut(h)?;
        slot.owner = None;
        slot.fault = None;
        Self::next_generation(slot);
        Ok(())
    }
    /// Start a fresh generation for a faulted owner after the owner itself
    /// has reset or unmapped its hardware queue. Old handles become `Stale`,
    /// so nothing from the faulted generation can complete afterwards.
    pub fn recover(&mut self, h: Handle) -> Result<Handle, WaitError> {
        if let Some(t) = self.terminal {
            return Err(WaitError::Terminal(t));
        }
        let slot = self.slot_mut(h)?;
        if slot.fault.is_none() {
            return Err(WaitError::Stale);
        }
        slot.fault = None;
        Self::next_generation(slot);
        Ok(Handle {
            slot: h.slot,
            generation: slot.generation,
        })
    }
    pub fn endpoint(&self, h: Handle) -> Result<Endpoint, WaitError> {
        let slot = self.slot(h)?;
        Ok(Endpoint {
            owner: slot.owner.unwrap(),
            generation: slot.generation,
            fault: slot.fault,
            stats: slot.stats,
        })
    }
    pub fn summary(&self) -> Summary {
        Summary {
            terminal: self.terminal,
            live: self.slots.iter().filter(|s| s.owner.is_some()).count(),
            counters: self.counters,
            display: self.display,
        }
    }
    fn find(&self, key: Key) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.owner.is_some_and(|o| o.key == key))
    }
    fn signal(&mut self, keys: &[Key], v: &ih::Vector) -> Delivery {
        for key in keys {
            let Some(i) = self.find(*key) else {
                continue;
            };
            let slot = &mut self.slots[i];
            let owner = slot.owner.unwrap();
            // A vector naming another context is never this owner's work.
            if owner.vmid != v.vmid || owner.pasid != v.pasid {
                break;
            }
            slot.stats.signals = slot.stats.signals.saturating_add(1);
            slot.bump();
            return Delivery::Signaled;
        }
        self.counters.unowned = self.counters.unowned.saturating_add(1);
        Delivery::Unowned
    }
    fn fault(&mut self, keys: &[Key], v: &ih::Vector, fault: src::Fault) -> Delivery {
        let mut hit = 0;
        for slot in self.slots.iter_mut() {
            let Some(owner) = slot.owner else {
                continue;
            };
            // Queue faults name a slot or doorbell. VM and shader faults name
            // a context and are attributed to every owner sharing it.
            let attributed = if keys.is_empty() {
                owner.vmid == v.vmid && owner.pasid == v.pasid
            } else {
                keys.contains(&owner.key)
            };
            if attributed {
                // Keep the first fault: later ones are usually consequences.
                slot.fault.get_or_insert(fault);
                slot.bump();
                hit += 1;
            }
        }
        if hit == 0 {
            self.counters.unattributed = self.counters.unattributed.saturating_add(1);
            return Delivery::Unattributed;
        }
        Delivery::Faulted(hit)
    }
    fn display(&mut self, d: src::Display) -> Delivery {
        let e = &mut self.display;
        let (count, bit) = match d {
            src::Display::Hpd(n) => (&mut e.hpd[n as usize % 6], HOTPLUG),
            src::Display::HpdRx(n) => (&mut e.hpd_rx[n as usize % 6], HOTPLUG),
            src::Display::Vblank(n) => (&mut e.vblank[n as usize % 6], VBLANK),
            src::Display::Vline0(n) => (&mut e.vline0[n as usize % 6], VLINE),
            src::Display::Flip(n) => (&mut e.flip[n as usize % 6], FLIP),
            src::Display::Vupdate(n) => (&mut e.vupdate[n as usize % 6], VUPDATE),
            src::Display::DmubOutbox => (&mut e.dmub, DMUB),
        };
        *count = count.wrapping_add(1);
        wake(&self.display_waiters, bit);
        Delivery::Display
    }
    /// Route one complete, classified vector to its current owner.
    pub fn route(&mut self, event: &ih::Event, class: src::Class) -> Delivery {
        let v = &event.vector;
        if let Some(t) = self.terminal {
            return Delivery::Terminal(t);
        }
        match class {
            src::Class::Eop { queue, doorbell } => {
                // gfx_v12_0_eop_irq: the exact kernel slot wins; only then
                // does a non-zero doorbell name a user queue.
                if doorbell != 0 {
                    self.signal(&[Key::Cp(queue), Key::Doorbell(doorbell)], v)
                } else {
                    self.signal(&[Key::Cp(queue)], v)
                }
            }
            src::Class::SdmaTrap { instance, queue } => {
                self.signal(&[Key::Sdma { instance, queue }], v)
            }
            src::Class::SdmaFence { doorbell } if doorbell != 0 => {
                self.signal(&[Key::Doorbell(doorbell)], v)
            }
            src::Class::SdmaFence { .. } => {
                self.counters.unowned = self.counters.unowned.saturating_add(1);
                Delivery::Unowned
            }
            src::Class::Fault(f) => match f {
                // amdgpu_gfx_handle_priv_fault: slot first, then the user
                // queue doorbell carried in context ID 0.
                src::Fault::Command { queue, .. } => {
                    let doorbell = v.data[0] & 0x3ff;
                    if doorbell != 0 {
                        self.fault(&[Key::Cp(queue), Key::Doorbell(doorbell)], v, f)
                    } else {
                        self.fault(&[Key::Cp(queue)], v, f)
                    }
                }
                src::Fault::Sdma {
                    instance, queue, ..
                } => self.fault(&[Key::Sdma { instance, queue }], v, f),
                src::Fault::Vm { .. } | src::Fault::Shader { .. } => self.fault(&[], v, f),
            },
            src::Class::Poison(p) => {
                self.fail_all(Terminal::Poison(p));
                Delivery::Terminal(Terminal::Poison(p))
            }
            src::Class::Display(d) => self.display(d),
            src::Class::Media(_) => {
                self.counters.media = self.counters.media.saturating_add(1);
                Delivery::Ignored
            }
            src::Class::Power => {
                self.counters.power = self.counters.power.saturating_add(1);
                Delivery::Ignored
            }
            src::Class::ShaderMessage { .. } => {
                self.counters.shader_messages = self.counters.shader_messages.saturating_add(1);
                Delivery::Ignored
            }
            src::Class::IhSelf => Delivery::Ignored,
            src::Class::Unknown => {
                self.counters.unknown = self.counters.unknown.saturating_add(1);
                Delivery::Ignored
            }
        }
    }
    /// A VM protection latch found after lost vectors. Only its VMID is
    /// known, so every owner in that VMID is faulted.
    pub fn latched(&mut self, vmid: u8, mm_hub: bool) -> Delivery {
        let fault = src::Fault::Vm { mm_hub };
        let mut hit = 0;
        for slot in self.slots.iter_mut() {
            if slot.owner.is_some_and(|o| o.vmid == vmid) {
                slot.fault.get_or_insert(fault);
                slot.bump();
                hit += 1;
            }
        }
        if hit == 0 {
            self.counters.unattributed = self.counters.unattributed.saturating_add(1);
            return Delivery::Unattributed;
        }
        Delivery::Faulted(hit)
    }
    /// Vectors were lost (IH overflow): wake everyone to re-check hardware.
    pub fn lost(&mut self) {
        self.counters.lost = self.counters.lost.saturating_add(1);
        self.display.lost = self.display.lost.wrapping_add(1);
        for slot in self.slots.iter_mut() {
            slot.bump();
        }
        wake(&self.display_waiters, u32::MAX);
    }
    /// Deliver a terminal device error to every current and future waiter.
    /// The first cause is retained.
    pub fn fail_all(&mut self, t: Terminal) {
        if self.terminal.is_some() {
            return;
        }
        self.terminal = Some(t);
        self.display.lost = self.display.lost.wrapping_add(1);
        for slot in self.slots.iter_mut() {
            slot.bump();
        }
        wake(&self.display_waiters, u32::MAX);
    }
    fn version(&self, target: Target) -> u64 {
        match target {
            Target::Slot(i) => self.slots[i as usize].seq,
            Target::Display(mask) => self.display.version(mask),
        }
    }
    fn park(&mut self, target: Target, id: u64, waker: &Waker) {
        let parked = match target {
            Target::Slot(i) => park(&mut self.slots[i as usize].waiters, id, u32::MAX, waker),
            Target::Display(mask) => park(&mut self.display_waiters, id, mask, waker),
        };
        if !parked {
            self.counters.unparked = self.counters.unparked.saturating_add(1);
        }
    }
    fn unpark(&mut self, target: Target, id: u64) {
        match target {
            Target::Slot(i) => unpark(&mut self.slots[i as usize].waiters, id),
            Target::Display(_) => unpark(&mut self.display_waiters, id),
        }
    }
    fn id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
}

/// Resolves when the target's version moves past `seen`. Dropping it (for
/// example on watchdog expiry) removes its waker.
struct Change<'a> {
    table: &'a IrqSafeSpinLock<Table>,
    target: Target,
    seen: u64,
    id: u64,
}
impl Future for Change<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut t = self.table.lock();
        if t.version(self.target) != self.seen || t.terminal.is_some() {
            return Poll::Ready(());
        }
        t.park(self.target, self.id, cx.waker());
        Poll::Pending
    }
}
impl Drop for Change<'_> {
    fn drop(&mut self) {
        self.table.lock().unpark(self.target, self.id);
    }
}

/// Wait for `check` (the owner's own memory-fence validation) to succeed.
/// Each round snapshots the endpoint before checking, so a vector arriving
/// during the check is never lost; a watchdog bounds every sleep. Faults,
/// staleness and terminal errors are reported instead of waiting further.
pub async fn wait_in<T>(
    table: &IrqSafeSpinLock<Table>,
    handle: Handle,
    deadline: Deadline,
    mut check: impl FnMut() -> Option<T>,
) -> Result<T, WaitError> {
    let id = table.lock().id();
    let mut woke = Woke::First;
    loop {
        let seen = {
            let t = table.lock();
            if let Some(e) = t.terminal {
                return Err(WaitError::Terminal(e));
            }
            t.slot(handle)?.seq
        };
        if let Some(value) = check() {
            let mut t = table.lock();
            let slot = t.slot_mut(handle)?;
            slot.stats.completions = slot.stats.completions.saturating_add(1);
            if woke == Woke::Watchdog {
                slot.stats.watchdog_completions = slot.stats.watchdog_completions.saturating_add(1);
            }
            return Ok(value);
        }
        {
            let mut t = table.lock();
            let slot = t.slot_mut(handle)?;
            if let Some(fault) = slot.fault {
                return Err(WaitError::Faulted(fault));
            }
            if deadline.expired() {
                slot.stats.timeouts = slot.stats.timeouts.saturating_add(1);
                return Err(WaitError::Timeout);
            }
        }
        let watchdog = Deadline::after_ms(WATCHDOG_MS).min(deadline);
        let change = Change {
            table,
            target: Target::Slot(handle.slot),
            seen,
            id,
        };
        woke = match narf_time::timeout(watchdog, change).await {
            Ok(()) => Woke::Signal,
            Err(_) => Woke::Watchdog,
        };
        if let Ok(slot) = table.lock().slot_mut(handle) {
            match woke {
                Woke::Signal => slot.stats.signal_wakes = slot.stats.signal_wakes.saturating_add(1),
                _ => slot.stats.watchdog_wakes = slot.stats.watchdog_wakes.saturating_add(1),
            }
        }
    }
}
/// Wait until a display event in `mask` (or an overflow/terminal transition)
/// moves past the version returned by an earlier call, or `deadline` passes.
/// Returns the new version; the first call should pass `None`.
pub async fn wait_display_in(
    table: &IrqSafeSpinLock<Table>,
    mask: u32,
    since: Option<u64>,
    deadline: Deadline,
) -> Result<u64, WaitError> {
    let (id, now) = {
        let mut t = table.lock();
        if let Some(e) = t.terminal {
            return Err(WaitError::Terminal(e));
        }
        (t.id(), t.display.version(mask))
    };
    let seen = since.unwrap_or(now);
    if seen != now {
        return Ok(now);
    }
    let change = Change {
        table,
        target: Target::Display(mask),
        seen,
        id,
    };
    narf_time::timeout(deadline, change)
        .await
        .map_err(|_| WaitError::Timeout)?;
    let t = table.lock();
    match t.terminal {
        Some(e) => Err(WaitError::Terminal(e)),
        None => Ok(t.display.version(mask)),
    }
}

/// The single native Navi48's delivery table.
pub(crate) static TABLE: IrqSafeSpinLock<Table> = IrqSafeSpinLock::new(Table::new());

pub fn register(owner: Owner) -> Result<Handle, RegisterError> {
    TABLE.lock().register(owner)
}
pub fn retire(handle: Handle) -> Result<(), WaitError> {
    TABLE.lock().retire(handle)
}
/// # Safety
/// The caller owns the faulted hardware queue and has reset or unmapped it,
/// so no write from the faulted generation can land after this returns.
pub unsafe fn recover(handle: Handle) -> Result<Handle, WaitError> {
    TABLE.lock().recover(handle)
}
pub fn endpoint(handle: Handle) -> Result<Endpoint, WaitError> {
    TABLE.lock().endpoint(handle)
}
pub fn summary() -> Summary {
    TABLE.lock().summary()
}
pub async fn wait<T>(
    handle: Handle,
    deadline: Deadline,
    check: impl FnMut() -> Option<T>,
) -> Result<T, WaitError> {
    wait_in(&TABLE, handle, deadline, check).await
}
pub async fn wait_display(
    mask: u32,
    since: Option<u64>,
    deadline: Deadline,
) -> Result<u64, WaitError> {
    wait_display_in(&TABLE, mask, since, deadline).await
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_dispatch_tests.rs"]
mod tests;
