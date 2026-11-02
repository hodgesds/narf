//! Qualified MTL/Arrow full-AUX SDR panel backlight. MIT Linux b90c984d:
//! display/drm_dp_helper.c::drm_edp_backlight_{probe_max,enable,disable},
//! include/drm/display/drm_dp.h. No PWM/product/luminance-mode admission.
use crate::{
    dp_aux::{AuxChannel, AuxError, AuxRequest, AuxResponse},
    intel_gpu_aux::{IntelAux, MmioWindow},
};
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use narf_drivers_backlight::{BacklightDevice, BacklightKind, Ownership};
use narf_filesystem::FsError;
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;

const NAME: &str = "intel_aux_backlight";
const MODE: u32 = 0x721;
const CONTROL: u32 = 0x720;
const LEVEL: u32 = 0x722;
const PWM_BITS: u32 = 0x724;
const FREQUENCY: u32 = 0x728;

/// The transport boundary retains current PCI authority, D0 and the owned
/// live Pipe-A internal-panel route. Unavailable MMIO never resembles zero.
trait PanelAccess: MmioWindow + Send {
    fn available(&self) -> bool;
    fn now(&self) -> u64 {
        narf_time::monotonic_ns()
    }
    fn wait(&self, deadline: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(narf_time::SleepUntil::new(
            narf_time::Deadline::after_ns(deadline.saturating_sub(self.now())).as_instant(),
        ))
    }
    fn close_gate(&self) -> Result<u64, AuxError>
    where
        Self: Sized,
    {
        let delay =
            crate::intel_gpu_edp::park_aux_backlight(self).map_err(|_| AuxError::ShortReply)?;
        self.now().checked_add(delay).ok_or(AuxError::UnknownStatus)
    }
    fn prepare_relight(&self) -> Result<u64, AuxError>
    where
        Self: Sized,
    {
        let delay = crate::intel_gpu_edp::prepare_aux_backlight_relight(self)
            .map_err(|_| AuxError::ShortReply)?;
        self.now().checked_add(delay).ok_or(AuxError::UnknownStatus)
    }
}
#[derive(Debug)]
struct Physical {
    bar: narf_bus::MmioRegion,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    window: crate::intel_gpu_gt_hw::AuthorizedWindow,
}
fn panel_live(io: &impl MmioWindow) -> bool {
    let pipe = io.read32(0x70008);
    let route = io.read32(0x60400);
    let status = io.read32(crate::intel_gpu_edp::PP_STATUS);
    let control = io.read32(crate::intel_gpu_edp::PP_CONTROL);
    ![pipe, route, status, control].contains(&u32::MAX)
        && pipe & (3 << 30) == 3 << 30
        // TRANS_DDI_FUNC_CTL enable, DDI A(index+1), DP SST.
        && route & 0xff00_0000 == 0x8a00_0000
        && status & 0xb000_000f == 0x8000_0008
        && control & 1 != 0
}
impl PanelAccess for Physical {
    fn available(&self) -> bool {
        self.bar.len >= 0xc7210
            && self.powered()
            && crate::intel_gpu_multipipe::pipe_owner(crate::intel_gpu_pipes::Pipe::A)
                == Some(crate::intel_gpu_multipipe::PipeOwner {
                    ddi: crate::intel_gpu_ddi::Ddi::A,
                    used_for: crate::intel_gpu_multipipe::PipeUse::InternalPanel,
                })
            && panel_live(&self.window)
    }
    fn prepare_relight(&self) -> Result<u64, AuxError> {
        let delay = crate::intel_gpu_edp::prepare_aux_backlight_relight(&PowerWindow(self))
            .map_err(|_| AuxError::ShortReply)?;
        self.now().checked_add(delay).ok_or(AuxError::UnknownStatus)
    }
}
impl Physical {
    fn powered(&self) -> bool {
        narf_bus::pci::power_state(&self.cap, &self.device)
            == Ok(Some(narf_bus::pci::PciPowerState::D0))
    }
}
struct PowerWindow<'a>(&'a Physical);
impl MmioWindow for PowerWindow<'_> {
    fn read32(&self, reg: u64) -> u32 {
        if self.0.powered() {
            self.0.window.read32(reg)
        } else {
            u32::MAX
        }
    }
    fn write32(&self, reg: u64, value: u32) {
        if self.0.powered() {
            self.0.window.write32(reg, value);
        }
    }
}
impl MmioWindow for Physical {
    fn read32(&self, reg: u64) -> u32 {
        if self.available() {
            self.window.read32(reg)
        } else {
            u32::MAX
        }
    }
    fn write32(&self, reg: u64, value: u32) {
        if self.available() {
            self.window.write32(reg, value);
        }
    }
}
#[derive(Debug)]
struct Channel<M: PanelAccess>(M);
impl<M: PanelAccess> AuxChannel for Channel<M> {
    fn transact<'a>(
        &mut self,
        request: &AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError> {
        if !self.0.available() {
            return Err(AuxError::ShortReply);
        }
        let response =
            IntelAux::with_base(&self.0, crate::intel_gpu_xelpg::XeLpgPort::A.aux_base())
                .transact(request, reply)?;
        if !self.0.available() {
            return Err(AuxError::ShortReply);
        }
        Ok(response)
    }
}
trait ControlledChannel: AuxChannel + Send {
    fn available(&self) -> bool;
    fn now(&self) -> u64;
    fn wait(&self, deadline: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
    fn close_gate(&self) -> Result<u64, AuxError>;
    fn gate_open(&self) -> bool;
    fn gate_closed(&self) -> bool;
    fn prepare_relight(&self) -> Result<u64, AuxError>;
    fn finish_relight(&self, deadline: u64) -> Result<(), AuxError>;
}
impl<M: PanelAccess> ControlledChannel for Channel<M> {
    fn available(&self) -> bool {
        self.0.available()
    }
    fn now(&self) -> u64 {
        self.0.now()
    }
    fn wait(&self, deadline: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.0.wait(deadline)
    }
    fn close_gate(&self) -> Result<u64, AuxError> {
        self.0.close_gate()
    }
    fn gate_open(&self) -> bool {
        let control = self.0.read32(crate::intel_gpu_edp::PP_CONTROL);
        self.available() && control != u32::MAX && control & 4 != 0
    }
    fn gate_closed(&self) -> bool {
        let control = self.0.read32(crate::intel_gpu_edp::PP_CONTROL);
        control != u32::MAX && control & 4 == 0
    }
    fn prepare_relight(&self) -> Result<u64, AuxError> {
        self.0.prepare_relight()
    }
    fn finish_relight(&self, deadline: u64) -> Result<(), AuxError> {
        if !self.available() {
            return Err(AuxError::ShortReply);
        }
        crate::intel_gpu_edp::finish_aux_backlight_relight(&self.0, deadline, self.now())
            .map_err(|_| AuxError::ShortReply)
    }
}
fn read(channel: &mut impl AuxChannel, address: u32) -> Result<u8, AuxError> {
    let mut value = [0];
    channel.dpcd_read(address, &mut value)?;
    Ok(value[0])
}
fn checked(channel: &mut impl AuxChannel, address: u32, value: u8) -> Result<(), AuxError> {
    channel.dpcd_write(address, &[value])?;
    if read(channel, address)? != value {
        return Err(AuxError::UnknownStatus);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Profile {
    caps: [u8; 4],
    hdr: [u8; 4],
    pwm: [u8; 3],
    mode: u8,
    frequency: Option<u8>,
    bytes: usize,
    max: u32,
}
impl Profile {
    fn hdr_caps(channel: &mut impl AuxChannel) -> Result<[u8; 4], AuxError> {
        let mut hdr = [0; 4];
        match channel.dpcd_read(0x340, &mut hdr) {
            Ok(()) => Ok(hdr),
            Err(AuxError::Nacked) => Ok([0; 4]), // no proprietary Intel interface
            Err(error) => Err(error),
        }
    }
    fn capture(channel: &mut impl AuxChannel) -> Result<Self, AuxError> {
        let mut caps = [0; 4];
        channel.dpcd_read(0x700, &mut caps)?;
        let hdr = Self::hdr_caps(channel)?;
        if hdr[0] >= 1 {
            return Err(AuxError::UnknownStatus);
        }
        // eDP1.2..1.4b, TCON + AUX enable, AUX level. Mixed PWM/product,
        // passthrough, dynamic/regional and luminance paths stay unsupported.
        if !(1..=5).contains(&caps[0])
            || caps[1] & 5 != 5
            || caps[2] & 2 == 0
            || caps[2] & 0x59 != 0
            || caps[3] & 0x50 != 0
        {
            return Err(AuxError::UnknownStatus);
        }
        let bytes = if caps[2] & 4 != 0 { 2 } else { 1 };
        let mut pwm = [0; 3];
        channel.dpcd_read(PWM_BITS, &mut pwm)?;
        if pwm.iter().any(|byte| byte & !31 != 0) {
            return Err(AuxError::UnknownStatus);
        }
        let [bits, low, high] = pwm.map(|v| v & 31);
        if low == 0 || low > high || high > bytes as u8 * 8 || bits < low || bits > high {
            return Err(AuxError::UnknownStatus);
        }
        let mode = read(channel, MODE)?;
        // Capture only already-DPCD firmware state: never infer an initial
        // level from a PWM/preset register or switch a mixed-control panel.
        if mode & !8 != 2 || (mode & 8 != 0 && caps[2] & 32 == 0) {
            return Err(AuxError::UnknownStatus);
        }
        let frequency = if mode & 8 != 0 {
            let divider = read(channel, FREQUENCY)?;
            if divider == 0 {
                return Err(AuxError::UnknownStatus);
            }
            Some(divider)
        } else {
            None
        };
        Ok(Self {
            caps,
            hdr,
            pwm,
            mode,
            frequency,
            bytes,
            max: (1u32 << bits) - 1,
        })
    }
    fn caps_match(self, channel: &mut impl AuxChannel) -> Result<(), AuxError> {
        let mut caps = [0; 4];
        channel.dpcd_read(0x700, &mut caps)?;
        let mut limits = [0; 2];
        channel.dpcd_read(PWM_BITS + 1, &mut limits)?;
        if caps != self.caps || limits != self.pwm[1..] || Self::hdr_caps(channel)? != self.hdr {
            return Err(AuxError::UnknownStatus);
        }
        Ok(())
    }
    fn level(self, channel: &mut impl AuxChannel) -> Result<u32, AuxError> {
        let mut bytes = [0; 2];
        channel.dpcd_read(LEVEL, &mut bytes[..self.bytes])?;
        let level = if self.bytes == 2 {
            u32::from(u16::from_be_bytes(bytes))
        } else {
            u32::from(bytes[0])
        };
        if level > self.max {
            return Err(AuxError::UnknownStatus);
        }
        Ok(level)
    }
    fn set_level(self, channel: &mut impl AuxChannel, level: u32) -> Result<(), AuxError> {
        let data = (level as u16).to_be_bytes();
        channel.dpcd_write(LEVEL, if self.bytes == 2 { &data } else { &data[1..] })?;
        if self.level(channel)? != level {
            return Err(AuxError::UnknownStatus);
        }
        Ok(())
    }
    fn current(self, channel: &mut impl AuxChannel) -> Result<u32, AuxError> {
        if read(channel, MODE)? != self.mode || read(channel, PWM_BITS)? != self.pwm[0] {
            return Err(AuxError::UnknownStatus);
        }
        if let Some(frequency) = self.frequency {
            if read(channel, FREQUENCY)? != frequency {
                return Err(AuxError::UnknownStatus);
            }
        }
        if read(channel, CONTROL)? & 1 == 0 {
            return Ok(0);
        }
        self.level(channel)
    }
    fn apply(
        self,
        channel: &mut impl AuxChannel,
        level: u32,
        resume: bool,
    ) -> Result<(), AuxError> {
        self.caps_match(channel)?;
        let control = read(channel, CONTROL)?;
        if resume {
            // A fresh post-S3 panel may have reset control mode/bit count.
            // Prove the AUX backlight disabled before restoring waveform and
            // mode; the platform keeps its PPS gate closed until this finishes.
            checked(channel, CONTROL, control & !1)?;
            checked(channel, PWM_BITS, self.pwm[0])?;
            if let Some(frequency) = self.frequency {
                checked(channel, FREQUENCY, frequency)?;
            }
            checked(channel, MODE, self.mode)?;
        } else {
            let _ = self.current(channel)?;
        }
        self.set_level(channel, level)?;
        checked(channel, CONTROL, (control & !1) | u8::from(level != 0))?;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
struct Relight {
    deadline: u64,
    // Preparation closes the gate before modeset. Only the explicit resume
    // after successful video publication may admit a worker to reopen it.
    admitted: bool,
}
struct State<C: AuxChannel> {
    channel: C,
    confirmed: u32,
    parked: bool,
    failed: bool,
    relight: Option<Relight>,
    off_deadline: Option<u64>,
}
struct Vesa<C: AuxChannel> {
    name: &'static str,
    profile: Profile,
    state: Mutex<State<C>>,
    requested: AtomicU32,
    scheduled: AtomicBool,
    me: Weak<Self>,
}
impl<C: AuxChannel> core::fmt::Debug for Vesa<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VesaBacklight")
            .field("name", &self.name)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}
impl<C: ControlledChannel + 'static> Vesa<C> {
    fn probe(name: &'static str, mut channel: C) -> Result<Arc<Self>, AuxError> {
        // Initial adoption does not grant permission to light a dark source
        // gate. Probe follows published video + the existing PPS/T8 sequence;
        // only later explicit suspend/relight owns gate transitions.
        if !channel.gate_open() {
            return Err(AuxError::ShortReply);
        }
        let profile = Profile::capture(&mut channel)?;
        let _ = profile.level(&mut channel)?; // validate even a stale disabled level
        let confirmed = profile.current(&mut channel)?;
        // CONTROL.enable=0 means effective initial intent is dark, regardless
        // of a nonzero stale BRIGHTNESS field. Registration must not enable it.
        let requested = confirmed;
        Ok(Arc::new_cyclic(|me| Self {
            name,
            profile,
            state: Mutex::new(State {
                channel,
                confirmed,
                parked: false,
                failed: false,
                relight: None,
                off_deadline: None,
            }),
            requested: AtomicU32::new(requested),
            scheduled: AtomicBool::new(false),
            me: me.clone(),
        }))
    }
    fn elected(&self) -> bool {
        narf_drivers_backlight::panel_owner()
            .is_some_and(|owner| core::ptr::eq(owner.as_ref(), self as &dyn BacklightDevice))
    }
    fn register(self: &Arc<Self>) -> Ownership {
        let standing = narf_drivers_backlight::register_backlight(self.clone());
        if standing == Ownership::Owner {
            let _ = self.resume();
        }
        standing
    }
    fn prepare_relight(&self) -> Result<(), AuxError> {
        if !self.elected() {
            return Ok(());
        }
        let mut state = self.state.try_lock().ok_or(AuxError::Deferred)?;
        state.parked = true;
        state.relight = None;
        // Superseding video preparation invalidates an older suspend waiter's
        // gate-close witness, even while the gate happens to remain closed.
        state.off_deadline = None;
        let deadline = state.channel.prepare_relight()?;
        state.relight = Some(Relight {
            deadline,
            admitted: false,
        });
        Ok(())
    }
    fn suspend(&self) -> Result<(), AuxError> {
        let elected = self.elected();
        let mut state = self.state.try_lock().ok_or(AuxError::Deferred)?;
        state.parked = true; // retained even if disable/access is uncertain
        state.relight = None;
        state.off_deadline = None;
        if !elected {
            return Ok(());
        }
        // Even a partial/failed disable may already have shut the source
        // gate. Failed-prepare rollback must use the gate-aware replay path.
        state.relight = Some(Relight {
            deadline: state.channel.now(),
            admitted: false,
        });
        let result = (|| {
            let control = read(&mut state.channel, CONTROL)?;
            checked(&mut state.channel, CONTROL, control & !1)?;
            let deadline = state.channel.close_gate()?;
            state.off_deadline = Some(deadline);
            // Rollback of a later failed S3 prepare can replay under the still
            // live video. Power-on T8 has already elapsed; the gate stays shut
            // until resume explicitly admits that replay.
            state.relight = Some(Relight {
                deadline: state.channel.now(),
                admitted: false,
            });
            Ok(())
        })();
        state.failed = result.is_err();
        if result.is_ok() {
            state.confirmed = 0;
        }
        result
    }
    async fn suspend_complete(&self) -> Result<(), AuxError> {
        self.suspend()?;
        loop {
            let wait = {
                let state = self.state.lock().await;
                if !self.elected() {
                    return Ok(());
                }
                let deadline = state.off_deadline.ok_or(AuxError::UnknownStatus)?;
                if !state.parked || !state.channel.gate_closed() {
                    return Err(AuxError::ShortReply);
                }
                if state.channel.now() >= deadline {
                    return Ok(());
                }
                state.channel.wait(deadline)
            };
            wait.await;
        }
    }
    fn resume(&self) -> Result<(), AuxError> {
        if !self.elected() {
            return Ok(());
        }
        let mut state = self.state.try_lock().ok_or(AuxError::Deferred)?;
        if state.relight.is_some() {
            if !state.channel.available() {
                return Err(AuxError::ShortReply);
            }
            state.off_deadline = None;
            state.relight.as_mut().expect("retained relight").admitted = true;
            state.failed = false;
            drop(state);
            self.schedule();
            return Ok(());
        }
        state.off_deadline = None;
        let level = self.requested.load(Ordering::Acquire);
        let result = self.profile.apply(&mut state.channel, level, true);
        state.failed = result.is_err();
        if result.is_ok() {
            state.confirmed = level;
            state.parked = false;
        }
        result
    }
    fn schedule(&self) {
        if self
            .scheduled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        if let Some(owner) = self.me.upgrade() {
            let _ = narf_scheduler::spawn(async move {
                owner.process().await;
            });
        } else {
            self.scheduled.store(false, Ordering::Release);
        }
    }
    async fn process(&self) {
        struct Running<'a>(&'a AtomicBool);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let running = Running(&self.scheduled);
        let mut observed = self.requested.load(Ordering::Acquire);
        let mut retry = false;
        let mut deferrals = 0;
        for _ in 0..32 {
            let wait = {
                let state = self.state.lock().await;
                state
                    .relight
                    .filter(|relight| relight.admitted && state.channel.now() < relight.deadline)
                    .map(|relight| state.channel.wait(relight.deadline))
            };
            if let Some(wait) = wait {
                wait.await;
                continue;
            }
            let mut state = self.state.lock().await;
            if !self.elected()
                || (state.parked && !state.relight.is_some_and(|relight| relight.admitted))
            {
                break;
            }
            observed = self.requested.load(Ordering::Acquire);
            let relight = state.relight;
            if relight.is_none() && !state.failed && state.confirmed == observed {
                break;
            }
            let result = self
                .profile
                .apply(&mut state.channel, observed, relight.is_some());
            let result = result.and_then(|()| {
                if let Some(relight) = relight {
                    state.channel.finish_relight(relight.deadline)
                } else {
                    Ok(())
                }
            });
            state.failed = result.is_err();
            if result == Err(AuxError::Deferred) && deferrals < 8 {
                // Both native DEFER and the shared transport's try-lock/busy
                // refusal are ordinary contention. Keep intent/gate ownership,
                // release the state lock, and retry on a bounded timer.
                deferrals += 1;
                let wait = state
                    .channel
                    .wait(state.channel.now().saturating_add(1_000_000));
                drop(state);
                wait.await;
                continue;
            }
            if result.is_err() {
                break;
            }
            deferrals = 0;
            state.confirmed = observed;
            state.parked = false;
            state.relight = None;
            retry = self.requested.load(Ordering::Acquire) != observed;
            if !retry {
                break;
            }
        }
        let can_retry = {
            let state = self.state.lock().await;
            let admitted = state.relight.is_some_and(|relight| relight.admitted);
            retry |= !state.failed && admitted;
            !state.failed && (!state.parked || admitted)
        };
        drop(running);
        if can_retry && (retry || self.requested.load(Ordering::Acquire) != observed) {
            self.schedule();
        }
    }
}
impl<C: ControlledChannel + 'static> BacklightDevice for Vesa<C> {
    fn name(&self) -> &str {
        self.name
    }
    fn kind(&self) -> BacklightKind {
        BacklightKind::Raw
    }
    fn max_brightness(&self) -> u32 {
        self.profile.max
    }
    fn current_brightness(&self) -> u32 {
        if !self.elected() {
            return 0;
        }
        let Some(mut state) = self.state.try_lock() else {
            return 0;
        };
        if state.parked || state.failed {
            return 0;
        }
        match self.profile.current(&mut state.channel) {
            Ok(level) => {
                state.confirmed = level;
                state.confirmed
            }
            Err(_) => 0,
        }
    }
    fn set_brightness(&self, level: u32) {
        if !self.elected() {
            return;
        }
        let level = level.min(self.profile.max);
        self.requested.store(level, Ordering::Release);
        self.schedule();
    }
}
type Device = Vesa<Channel<Physical>>;
static DEVICES: IrqSafeSpinLock<Vec<(u64, Arc<Device>)>> = IrqSafeSpinLock::new(Vec::new());

pub(crate) fn install_mtl(
    gpu: &crate::intel_gpu::IntelGpu,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) {
    if gpu.chip.generation != crate::intel_gpu::Generation::MeteorLake
        || gpu.current_mode().is_none()
    {
        return;
    }
    let bar = gpu.gtt_mmadr;
    if DEVICES.lock().iter().any(|(key, _)| *key == bar.phys.raw()) {
        return;
    }
    let channel = Channel(Physical {
        bar,
        device,
        cap,
        window: crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap),
    });
    let Ok(owner) = Vesa::probe(NAME, channel) else {
        return;
    };
    // Retain failed/ambiguous owners too: promoting another control source
    // after an uncertain AUX write would create competing panel ownership.
    DEVICES.lock().push((bar.phys.raw(), owner.clone()));
    owner.register();
}
fn find(bar: &narf_bus::MmioRegion) -> Option<Arc<Device>> {
    DEVICES
        .lock()
        .iter()
        .find(|(key, _)| *key == bar.phys.raw())
        .map(|(_, owner)| owner.clone())
}
pub(crate) fn suspend_for_bar(bar: &narf_bus::MmioRegion) -> Result<bool, FsError> {
    let Some(owner) = find(bar) else {
        return Ok(false);
    };
    let elected = owner.elected();
    owner.suspend().map_err(|_| FsError::NoDevice)?;
    Ok(elected)
}
pub(crate) async fn suspend_complete_for_bar(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
    let Some(owner) = find(bar) else {
        return Ok(());
    };
    owner
        .suspend_complete()
        .await
        .map_err(|_| FsError::NoDevice)
}
pub(crate) fn resume_for_bar(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
    let Some(owner) = find(bar) else {
        return Ok(());
    };
    owner.resume().map_err(|_| FsError::NoDevice)
}
pub(crate) fn installed(bar: &narf_bus::MmioRegion) -> bool {
    find(bar).is_some()
}
pub(crate) fn prepare_relight_for_bar(bar: &narf_bus::MmioRegion) -> Result<(), FsError> {
    let Some(owner) = find(bar) else {
        return Ok(());
    };
    owner.prepare_relight().map_err(|_| FsError::NoDevice)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_dpcd_bl_owner_tests.rs"]
mod tests;
