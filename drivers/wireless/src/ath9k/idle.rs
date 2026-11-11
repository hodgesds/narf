// SPDX-License-Identifier: GPL-2.0-or-later
//! Original-controller idle and retained cold wake, distinct from station PS.
use super::*;
use alloc::{boxed::Box, task::Wake, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
#[path = "idle/hardware.rs"]
pub(super) mod hardware;
#[cfg(feature = "kernel-test")]
#[path = "idle/tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Operational,
    Quiescing,
    Armed,
    Asleep,
    Waking,
    Blocked,
    Failed,
    Removed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub desired: bool,
    pub state: State,
    pub users: u32,
    pub generation: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Stale,
    Removed,
    Hardware(BringUpError),
}
struct Count {
    desired: bool,
    phase: State,
    users: u32,
    serial: u64,
    wake: Option<Waker>,
}
pub(super) struct Owner(IrqSafeSpinLock<Count>);
impl Owner {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self(IrqSafeSpinLock::new(Count {
            desired: false,
            phase: State::Operational,
            users: 0,
            serial: 1,
            wake: None,
        })))
    }
    pub(super) fn status(&self, generation: u32) -> Status {
        let s = self.0.lock();
        Status {
            desired: s.desired,
            state: s.phase,
            users: s.users,
            generation,
        }
    }
    pub(super) fn use_awake(self: &Arc<Self>, station: bool) -> Result<WakeGuard, Error> {
        let mut s = self.0.lock();
        if s.desired || !(s.phase == State::Operational || station && s.phase == State::Waking) {
            return Err(Error::Busy);
        }
        let Some(next) = s.users.checked_add(1) else {
            s.phase = State::Failed;
            return Err(Error::Hardware(BringUpError::BadState));
        };
        s.users = next;
        Ok(WakeGuard(self.clone()))
    }
    fn desired(&self) -> bool {
        self.0.lock().desired
    }
    fn begin_idle(&self, expected_users: u32) -> Result<(), Error> {
        let mut s = self.0.lock();
        if s.phase != State::Operational || s.desired || s.users != expected_users {
            return Err(Error::Busy);
        }
        let Some(serial) = s.serial.checked_add(1) else {
            s.phase = State::Failed;
            return Err(Error::Hardware(BringUpError::BadState));
        };
        s.serial = serial;
        s.desired = true;
        Ok(())
    }
    fn set_desired(&self, value: bool) -> Result<(), Error> {
        let wake = {
            let mut s = self.0.lock();
            if matches!(s.phase, State::Removed | State::Blocked) {
                return Err(Error::Removed);
            }
            if value && s.phase != State::Operational {
                return Err(Error::Busy);
            }
            if s.desired != value {
                let Some(next) = s.serial.checked_add(1) else {
                    s.phase = State::Failed;
                    return Err(Error::Hardware(BringUpError::BadState));
                };
                s.serial = next;
                s.desired = value;
            }
            s.wake.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
        Ok(())
    }
    pub(super) fn block(&self, removed: bool) {
        let wake = {
            let mut s = self.0.lock();
            s.desired = false;
            s.phase = if removed {
                State::Removed
            } else {
                State::Blocked
            };
            s.wake.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
    fn phase(&self, phase: State) {
        let mut s = self.0.lock();
        if s.phase != State::Removed {
            s.phase = phase;
        }
    }
    fn armed(&self) -> Result<(), Error> {
        let mut s = self.0.lock();
        if s.phase != State::Quiescing || s.users != 0 {
            if s.phase != State::Removed {
                s.phase = State::Failed;
            }
            return Err(Error::Busy);
        }
        s.phase = State::Armed;
        Ok(())
    }
    /// The retained worker, not a public waiter's future, owns this delay.
    /// A leaving-idle request wakes it without polling or touching sleeping IO.
    async fn wait_armed(&self, timer: impl Future<Output = ()>) -> bool {
        let mut timer = core::pin::pin!(timer);
        core::future::poll_fn(|cx| {
            let mut s = self.0.lock();
            if !s.desired || s.phase != State::Armed {
                return Poll::Ready(false);
            }
            s.wake = Some(cx.waker().clone());
            drop(s);
            let ready = timer.as_mut().poll(cx);
            if ready.is_ready() {
                // Do not retain the completed worker through its wake chain.
                let wake = self.0.lock().wake.take();
                drop(wake);
            }
            ready.map(|_| true)
        })
        .await
    }
    fn enter(&self, io: &mut impl hardware::Io) -> Result<(), Error> {
        {
            let s = self.0.lock();
            if !s.desired || s.phase != State::Armed || s.users != 0 {
                return Err(Error::Busy);
            }
        }
        if let Err(error) = hardware::enter(io) {
            self.phase(State::Failed);
            return Err(Error::Hardware(error));
        }
        self.phase(State::Asleep);
        Ok(())
    }
    pub(super) fn operational(&self) -> bool {
        self.0.lock().phase == State::Operational
    }
    pub(super) fn can_initialize(&self) -> bool {
        let s = self.0.lock();
        !s.desired && matches!(s.phase, State::Operational | State::Waking)
    }
    pub(super) fn system_block(&self, users: u32) -> bool {
        let mut s = self.0.lock();
        if s.desired || s.phase != State::Operational || s.users != users {
            return false;
        }
        s.phase = State::Blocked;
        true
    }
}
/// Counted original-controller use preventing idle FULL_SLEEP. It grants no
/// register/key/DMA access and does not disable separately qualified S1 sleep.
pub struct WakeGuard(Arc<Owner>);
impl core::fmt::Debug for WakeGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath9kIdleWakeGuard").finish_non_exhaustive()
    }
}
impl Drop for WakeGuard {
    fn drop(&mut self) {
        let wake = {
            let mut s = self.0 .0.lock();
            if let Some(next) = s.users.checked_sub(1) {
                s.users = next;
            } else {
                s.phase = State::Failed;
            }
            s.wake.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}
type Outcome = core::result::Result<Status, Error>;
struct Completion {
    result: Option<Outcome>,
    waiters: Vec<Waker>,
}
type Slot = Arc<IrqSafeSpinLock<Completion>>;
struct DriverWake(IrqSafeSpinLock<Option<Waker>>);
impl Wake for DriverWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let w = self.0.lock().clone();
        if let Some(w) = w {
            w.wake();
        }
    }
}
struct Work {
    owner: Arc<Retained>,
    generation: u32,
    idle: bool,
    result: Slot,
    wake: Arc<DriverWake>,
    future: Pin<Box<dyn Future<Output = Outcome> + Send>>,
}
static WORK: Mutex<Option<Work>> = Mutex::new(None);

fn admit<P: packet::Port, E: station::Environment, K: station::Engine>(
    owner: &Owner,
    radio: &station::Radio<P, E, K>,
    expected_users: u32,
) -> Result<(), Error> {
    if !radio.idle_admissible() {
        return Err(Error::Busy);
    }
    owner.begin_idle(expected_users)
}

/// One terminal boundary shared by the retained physical controller and
/// native fixtures. Keep the counted pin, all mappings and original owner
/// on any missing stop proof; a host withdrawal alone never releases it.
pub(super) async fn retire_station<P: packet::Port, E: station::Environment, K: station::Engine>(
    station: &Arc<Mutex<station::Radio<P, E, K>>>,
    counted: &mut Option<WakeGuard>,
    withdraw: impl FnOnce(),
) -> bool {
    withdraw();
    if !station.lock().await.retire() {
        return false;
    }
    *counted = None;
    true
}

fn preflight(
    controller: &Ath9k,
    owner: &Retained,
    generation: u32,
    idle: bool,
) -> core::result::Result<(), Error> {
    if owner.removed.load(core::sync::atomic::Ordering::Acquire) {
        return Err(Error::Removed);
    }
    if controller.pinned {
        return Err(Error::Hardware(BringUpError::BadState));
    }
    if controller.suspended {
        return Err(Error::Busy);
    }
    if controller.generation != generation {
        return Err(Error::Stale);
    }
    if idle {
        let radio = controller
            .station
            .as_ref()
            .ok_or(Error::Busy)?
            .try_lock()
            .ok_or(Error::Busy)?;
        if !radio.idle_admissible()
            || owner.idle.status(generation).users != u32::from(controller.station_use.is_some())
        {
            return Err(Error::Busy);
        }
    }
    Ok(())
}
fn request_on(
    owner: Arc<Retained>,
    generation: u32,
    idle: bool,
) -> core::result::Result<Slot, Error> {
    let mut slot = WORK.try_lock().ok_or(Error::Busy)?;
    if let Some(work) = slot.as_ref() {
        if !Arc::ptr_eq(&work.owner, &owner)
            || work.generation != generation
            || idle && (!work.idle || !owner.idle.desired())
        {
            return Err(Error::Busy);
        }
        // Leaving idle cancels its delay immediately. The retained original
        // worker restores a fresh generation even if retirement already ran.
        if !idle {
            owner.idle.set_desired(false)?;
        }
        return Ok(work.result.clone());
    }
    {
        let controller = owner.state.try_lock().ok_or(Error::Busy)?;
        preflight(&controller, &owner, generation, idle)?;
        if idle {
            let radio = controller
                .station
                .as_ref()
                .ok_or(Error::Busy)?
                .try_lock()
                .ok_or(Error::Busy)?;
            admit(
                &owner.idle,
                &radio,
                u32::from(controller.station_use.is_some()),
            )?;
        } else {
            owner.idle.set_desired(false)?;
        }
    }
    let result = Arc::new(IrqSafeSpinLock::new(Completion {
        result: None,
        waiters: Vec::new(),
    }));
    let wake = Arc::new(DriverWake(IrqSafeSpinLock::new(None)));
    let original = owner.clone();
    *slot = Some(Work {
        owner,
        generation,
        idle,
        result: result.clone(),
        wake: wake.clone(),
        future: Box::pin(async move { run(&original, generation, idle).await }),
    });
    drop(slot);
    let done = result.clone();
    narf_scheduler::spawn(core::future::poll_fn(move |cx| {
        *wake.0.lock() = Some(cx.waker().clone());
        poll(cx);
        if done.lock().result.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }));
    Ok(result)
}
async fn wait(result: Slot) -> Outcome {
    core::future::poll_fn(move |cx| {
        {
            let mut c = result.lock();
            if let Some(r) = c.result {
                return Poll::Ready(r);
            }
            if !c.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                if c.waiters.len() == 16 {
                    return Poll::Ready(Err(Error::Busy));
                }
                c.waiters.push(cx.waker().clone());
            }
        }
        poll(cx);
        result.lock().result.map_or(Poll::Pending, Poll::Ready)
    })
    .await
}
pub async fn set(idle: bool) -> Outcome {
    let owner = { CONTROLLER.lock().clone() }.ok_or(Error::Removed)?;
    let generation = {
        let controller = owner.state.try_lock().ok_or(Error::Busy)?;
        preflight(&controller, &owner, controller.generation, false)?;
        let status = owner.idle.status(controller.generation);
        // Idempotent desired setting is cached completion metadata, never
        // new current register, key or native publication authority.
        if idle && status.desired && status.state == State::Asleep {
            return Ok(status);
        }
        controller.generation
    };
    wait(request_on(owner, generation, idle)?).await
}
pub fn status() -> Option<Status> {
    let owner = { CONTROLLER.lock().clone() }?;
    let controller = owner.state.try_lock()?;
    Some(owner.idle.status(controller.generation))
}
pub async fn wake_use() -> core::result::Result<WakeGuard, Error> {
    let owner = { CONTROLLER.lock().clone() }.ok_or(Error::Removed)?;
    let generation = owner.state.try_lock().ok_or(Error::Busy)?.generation;
    wait(request_on(owner.clone(), generation, false)?).await?;
    let guard = owner.idle.use_awake(false)?;
    let controller = owner.state.lock().await;
    if owner.removed.load(core::sync::atomic::Ordering::Acquire)
        || controller.pinned
        || controller.suspended
    {
        return Err(Error::Removed);
    }
    let radio = controller.station.as_ref().ok_or(Error::Busy)?.lock().await;
    radio
        .idle_wake_current()
        .map_err(|_| Error::Hardware(BringUpError::BadState))?;
    Ok(guard)
}
pub(super) fn poll(cx: &mut Context<'_>) {
    let Some(mut slot) = WORK.try_lock() else {
        cx.waker().wake_by_ref();
        return;
    };
    let Some(work) = slot.as_mut() else {
        return;
    };
    let wake = Waker::from(work.wake.clone());
    if let Poll::Ready(result) = work.future.as_mut().poll(&mut Context::from_waker(&wake)) {
        let work = slot.take().unwrap();
        drop(slot);
        let waiters = {
            let mut c = work.result.lock();
            c.result = Some(result);
            core::mem::take(&mut c.waiters)
        };
        for w in waiters {
            w.wake();
        }
    }
}

struct NativeIo<'a> {
    registers: identity::Registers,
    device: narf_bus::BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    owner: &'a Retained,
}
impl identity::RegisterIo for NativeIo<'_> {
    fn authorized(&self) -> bool {
        !self
            .owner
            .removed
            .load(core::sync::atomic::Ordering::Acquire)
            && self.registers.authorized()
    }
    fn read32(&mut self, r: u64) -> u32 {
        if self.authorized() {
            self.registers.read32(r)
        } else {
            u32::MAX
        }
    }
    fn write32(&mut self, r: u64, v: u32) {
        if self.authorized() {
            self.registers.write32(r, v);
        }
    }
}
impl hardware::Io for NativeIo<'_> {
    fn bus_master(&mut self) -> core::result::Result<bool, BringUpError> {
        if !identity::RegisterIo::authorized(self) {
            return Err(BringUpError::DeviceGone);
        }
        let command = identity::invoke(&self.cap, || {
            narf_bus::pci::read_command(&self.cap, &self.device)
        })
        .map_err(|_| BringUpError::DeviceGone)?
        .map_err(|_| BringUpError::DeviceGone)?;
        if command == u16::MAX {
            return Err(BringUpError::DeviceGone);
        }
        Ok(command & narf_bus::pci::cmd::BUS_MASTER != 0)
    }
}
async fn run(owner: &Retained, generation: u32, idle: bool) -> Outcome {
    let _control = CONTROL.lock().await;
    let mut retired = false;
    {
        let mut controller = owner.state.lock().await;
        if let Err(e) = preflight(&controller, owner, generation, idle) {
            let _ = owner.idle.set_desired(false);
            return Err(e);
        }
        if !idle && owner.idle.status(generation).state == State::Operational {
            return Ok(owner.idle.status(generation));
        }
        if idle {
            owner.idle.phase(State::Quiescing);
            if !retire_generation(&mut controller).await {
                owner.idle.phase(State::Failed);
                return Err(Error::Hardware(BringUpError::BadState));
            }
            retired = true;
            controller.radio = calibration::Calibration::default();
            controller.wide = None;
            controller.wide_report = None;
            controller.packet_attempted = true;
            owner.idle.armed()?;
        }
    }
    if retired {
        let timer = narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(100_000_000));
        let expired = owner.idle.wait_armed(timer).await;
        if expired && owner.idle.desired() {
            let controller = owner.state.lock().await;
            if owner.removed.load(core::sync::atomic::Ordering::Acquire)
                || controller.generation != generation
                || owner.idle.status(generation).users != 0
            {
                owner.idle.phase(State::Failed);
                return Err(Error::Removed);
            }
            let mut io = NativeIo {
                registers: identity::Registers::new(controller._mmio, controller._cap),
                device: controller._device,
                cap: controller._cap,
                owner,
            };
            owner.idle.enter(&mut io)?;
            if owner.idle.desired() {
                return Ok(owner.idle.status(generation));
            }
        }
    }
    cold_wake_inner(owner).await
}
async fn cold_wake_inner(owner: &Retained) -> Outcome {
    owner.idle.phase(State::Waking);
    {
        owner.idle.0.lock().desired = false;
    }
    let geometry = owner.state.lock().await.baseband.geometry.twenty();
    match reset_owner_geometry_inner(owner, geometry, None).await {
        Ok(_) => {
            owner.idle.phase(State::Operational);
            Ok(owner.idle.status(owner.state.lock().await.generation))
        }
        Err(e) => {
            owner.idle.phase(State::Failed);
            Err(Error::Hardware(e))
        }
    }
}
pub(super) async fn system_resume(owner: &Retained) -> core::result::Result<(), BringUpError> {
    let _control = CONTROL.lock().await;
    cold_wake_inner(owner)
        .await
        .map(|_| ())
        .map_err(|e| match e {
            Error::Hardware(e) => e,
            _ => BringUpError::BadState,
        })
}

/// How long netdev activity waits for an idle owner to leave FULL_SLEEP.
const ACTIVITY_WAKE_NS: u64 = 10_000_000_000;
/// Debounce before an unassociated, quiet netdev enters idle. mac80211
/// (`iface.c::__ieee80211_recalc_idle`) idles at once; here leaving idle is
/// a full cold generation reset, so a scan followed by a connect within this
/// window must not pay it twice.
pub(super) const IDLE_GRACE_NS: u64 = 5_000_000_000;

/// mac80211 `IEEE80211_CONF_IDLE` for the single station vif: the published
/// generation is unassociated with nothing in flight (`idle_admissible`), no
/// scan/connect/configuration ran within the grace window (`quiet`), the
/// owner is operational and not already idle, and no counted use beyond the
/// station's own pin (`station_users`) is held.
pub(super) fn idle_wanted(
    admissible: bool,
    quiet: bool,
    status: Status,
    station_users: u32,
) -> bool {
    admissible
        && quiet
        && status.state == State::Operational
        && !status.desired
        && status.users == station_users
}

/// Supervisor tick of the original controller: enter idle FULL_SLEEP when
/// [`idle_wanted`] holds (Linux `main.c::ath9k_config` with
/// `IEEE80211_CONF_IDLE`: `ath_cancel_work`, then `ath9k_ps_restore` takes
/// the chip to FULL_SLEEP). Returns the entered status, if any.
pub(super) async fn enter_when_idle(owner: &Retained) -> Option<Status> {
    let wanted = {
        let controller = owner.state.try_lock()?;
        let station = controller.station.as_ref()?;
        let admissible = station.try_lock()?.idle_admissible();
        idle_wanted(
            admissible,
            interface::quiet_for(IDLE_GRACE_NS),
            owner.idle.status(controller.generation),
            u32::from(controller.station_use.is_some()),
        )
    };
    if !wanted {
        return None;
    }
    set(true).await.ok()
}

/// Netdev control activity (scan, connect, configuration) leaves idle:
/// mac80211 clears `IEEE80211_CONF_IDLE` and `main.c::ath9k_config` wakes
/// the chip with a reset ("the chip needs a reset to properly wake up from
/// full sleep"). An awake owner only counts the use, so idle cannot be
/// admitted while the request runs; an idle-desired, armed or asleep owner
/// cancels the delay or cold-wakes into a fresh generation first. `None`
/// when no original controller exists or it is blocked/removed; the caller
/// then waits for a generation as usual.
pub(super) async fn activity() -> Option<WakeGuard> {
    let owner = { CONTROLLER.lock().clone() }?;
    let deadline = narf_time::monotonic_ns().saturating_add(ACTIVITY_WAKE_NS);
    loop {
        if let Ok(guard) = owner.idle.use_awake(false) {
            return Some(guard);
        }
        owner.idle.set_desired(false).ok()?;
        match wake_use().await {
            Ok(guard) => return Some(guard),
            Err(Error::Removed) => return None,
            Err(_) if narf_time::monotonic_ns() >= deadline => return None,
            Err(_) => {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(20_000_000)).await;
            }
        }
    }
}
