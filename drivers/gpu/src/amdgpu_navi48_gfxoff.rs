//! GC12 GFXOFF references. Lock order is controller, then platform OWNER.
//! The request-count state machine is shared with RDNA2; instances are separate.
use crate::amdgpu_navi22_gfxoff::{Control, Controller};
pub use crate::amdgpu_navi22_gfxoff::{Error, Status};
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use narf_lib::mutex::Mutex;
// 0: known powered, controller disabled; 1: active; 2: uncertain/transition.
static MODE: AtomicU8 = AtomicU8::new(0);
static EPOCH: AtomicU64 = AtomicU64::new(0);
static REQUESTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);
struct State {
    epoch: u64,
    controller: Controller,
}
static STATE: Mutex<State> = Mutex::new(State {
    epoch: 0,
    controller: Controller::new(),
});
struct Platform(u64);
impl Control for Platform {
    async fn control(&mut self, allow: bool) -> Result<(), ()> {
        crate::amdgpu_navi48_platform::gfxoff_command(self.0, allow)
            .await
            .map_err(|_| ())
    }
}
/// Boot policy, before the native owner starts.
pub fn set_enabled(enabled: bool) {
    REQUESTED.store(enabled, Ordering::Release);
}
pub(crate) fn epoch() -> u64 {
    EPOCH.load(Ordering::Acquire)
}
/// Called with OWNER held only after an acquired GC reference or proved
/// reset. Old delayed work and releases cannot affect the replacement.
pub(crate) fn invalidate() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    MODE.store(0, Ordering::Release);
}
pub(crate) fn lose() {
    MODE.store(2, Ordering::Release);
}
pub(crate) fn transitioning() {
    MODE.store(2, Ordering::Release);
}
#[derive(Debug)]
#[must_use = "retain GC power until the MMIO owner is released"]
pub(crate) struct Reference(Option<u64>);
impl Reference {
    pub(crate) async fn acquire() -> Result<Self, Error> {
        if MODE.load(Ordering::Acquire) == 0 {
            return Ok(Self(None));
        }
        // Initialization owns this mutex through its power commands. Wait
        // for that transition; a cancelled/failed one leaves MODE=2 after
        // releasing the mutex and is then refused below.
        let mut state = STATE.lock().await;
        match MODE.load(Ordering::Acquire) {
            0 => return Ok(Self(None)),
            2 => return Err(Error::Failed),
            _ => {}
        }
        if state.epoch != epoch() {
            return Err(Error::Failed);
        }
        let generation = state.epoch;
        state.controller.disallow(&mut Platform(generation)).await?;
        Ok(Self(Some(generation)))
    }
    pub(crate) fn covers_access(&self) -> bool {
        match MODE.load(Ordering::Acquire) {
            0 => true,
            1 => self.0 == Some(epoch()),
            _ => false,
        }
    }
}
impl Drop for Reference {
    fn drop(&mut self) {
        if let Some(epoch) = self.0.take() {
            narf_scheduler::spawn(release(epoch));
        }
    }
}
async fn release(generation: u64) {
    let work = {
        let mut state = STATE.lock().await;
        if state.epoch != generation || epoch() != generation || MODE.load(Ordering::Acquire) != 1 {
            return;
        }
        match state.controller.allow() {
            Ok(Some(work)) => work,
            _ => return,
        }
    };
    delayed(generation, work).await;
}
async fn delayed(generation: u64, work: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(100).as_instant()).await;
    let mut state = STATE.lock().await;
    if state.epoch == generation
        && epoch() == generation
        && MODE.load(Ordering::Acquire) == 1
        && state
            .controller
            .delayed_allow(work, &mut Platform(generation))
            .await
            .is_err()
    {
        lose();
    }
}
pub(crate) fn start() {
    if !REQUESTED.load(Ordering::Acquire) {
        return;
    }
    let generation = epoch();
    narf_scheduler::spawn(async move {
        let mut state = STATE.lock().await;
        if epoch() != generation || MODE.load(Ordering::Acquire) != 0 {
            return;
        }
        // Fresh controller per device incarnation; reset/suspend may start
        // another one after the new owner has proved its queues.
        state.epoch = generation;
        state.controller = Controller::new();
        let result = crate::amdgpu_navi48_platform::enable_gfxoff(generation).await;
        if epoch() == generation {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: rdna4 GFXOFF startup {result:?}"
            );
        }
        let Some(work) = finish_start(
            &mut state,
            generation,
            &EPOCH,
            &MODE,
            result.map_err(|_| ()),
        ) else {
            return;
        };
        drop(state);
        delayed(generation, work).await;
    });
}
fn finish_start(
    state: &mut State,
    generation: u64,
    clock: &AtomicU64,
    mode: &AtomicU8,
    result: Result<bool, ()>,
) -> Option<u64> {
    // Startup may have waited for an owner which a reset replaced. No
    // outcome of that stale operation can change its successor's mode.
    if clock.load(Ordering::Acquire) != generation {
        return None;
    }
    match result {
        Ok(false) => {
            mode.store(0, Ordering::Release);
            return None;
        }
        Ok(true) => {}
        Err(()) => {
            mode.store(2, Ordering::Release);
            return None;
        }
    }
    if state.controller.start().is_err() {
        mode.store(2, Ordering::Release);
        return None;
    }
    mode.store(1, Ordering::Release);
    match state.controller.allow() {
        Ok(Some(work)) => Some(work),
        _ => {
            mode.store(2, Ordering::Release);
            None
        }
    }
}
pub fn status() -> Option<Status> {
    let state = STATE.try_lock()?;
    if MODE.load(Ordering::Acquire) == 0 || state.epoch != epoch() {
        return Some(Status::default());
    }
    Some(Status {
        failed: MODE.load(Ordering::Acquire) == 2 || state.controller.status().failed,
        ..state.controller.status()
    })
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn rdna4_gfxoff_stale_startup_cannot_poison_reset_successor() -> TestResult {
        let clock = AtomicU64::new(7);
        let mode = AtomicU8::new(0);
        let mut state = State {
            epoch: 6,
            controller: Controller::new(),
        };
        let before = state.controller.status();
        assert_eq!(finish_start(&mut state, 6, &clock, &mode, Err(())), None);
        assert_eq!(mode.load(Ordering::Acquire), 0);
        assert_eq!(state.controller.status(), before);
        state.epoch = 7;
        mode.store(2, Ordering::Release);
        assert!(finish_start(&mut state, 7, &clock, &mode, Ok(true)).is_some());
        assert_eq!(mode.load(Ordering::Acquire), 1);
        assert!(state.controller.status().enabled && state.controller.status().pending);
        assert_eq!(state.controller.status().requests, 0);
        clock.store(8, Ordering::Release);
        mode.store(0, Ordering::Release);
        assert_eq!(finish_start(&mut state, 7, &clock, &mode, Err(())), None);
        assert_eq!(mode.load(Ordering::Acquire), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/rdna4-idle",
        rdna4_gfxoff_stale_startup_cannot_poison_reset_successor
    );
}
