//! Native conversations through the production Device/Guard/Presenter/PollIo
//! path. Register vectors follow MIT Linux b90c984d, intel_display_regs.h;
//! only the platform boundary and the next display tick are modeled.

use super::*;
use alloc::collections::BTreeMap;
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

static NEXT_GGTT_KEY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1 << 63);

const SURF: u64 = 0x7019c;
const LIVE: u64 = 0x701ac;
const FRAME: u64 = 0x70040;
const IIR: u64 = 0x44408;
const IMR: u64 = 0x44404;
const IER: u64 = 0x4440c;
const CONSOLE: u32 = 0x01000000;
const PTE_START: u64 = GGTT_ARRAY_BASE + GEM_SCANOUT_GTT_START / 4096 * 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Pause,
    Takeover,
    Arm(u32),
    Latch(u32),
    Resume,
    ColorArm(u64),
    SourceOffset(u32),
}
#[derive(Debug)]
struct Hardware {
    ggtt_key: u64,
    regs: BTreeMap<u64, u32>,
    actions: Vec<Action>,
    palette: [u32; 1024],
    palette_writes: usize,
    legacy_collisions: bool,
    legacy_posted: usize,
    refuse_palette: bool,
    allowed: bool,
    powered: bool,
    pause_blocked: bool,
    takeover_error: Option<FsError>,
    pending_surface: Option<u32>,
    pending_cursor: Option<u32>,
    flips: bool,
    frames: bool,
    now: u64,
    tick_ns: u64,
    deliveries: u32,
    pte_installs: usize,
    pte_clears: usize,
    refuse_ptes: bool,
    refuse_console: bool,
    refuse_status_restore: bool,
    dsb_pc: [u32; 2],
    dsb_wait: [Option<u32>; 2],
    dsb_delay: [bool; 2],
    dsb_stalled: [bool; 2],
    dsb_writes: Vec<(u64, u32)>,
    poison_dsb_read: bool,
}
#[derive(Clone, Debug)]
pub(crate) struct MockPlatform(Arc<IrqSafeSpinLock<Hardware>>, Arc<AtomicBool>, bool);
impl MockPlatform {
    pub(crate) fn new() -> Self {
        Self(
            Arc::new(IrqSafeSpinLock::new(Hardware {
                ggtt_key: NEXT_GGTT_KEY.fetch_add(1, Ordering::Relaxed),
                regs: [
                    (0x70180, 0x84000000),
                    (0x701cc, 1 << 13),
                    (0x70188, 4),
                    (0x70190, 0x001f003f),
                    (SURF, CONSOLE),
                    (LIVE, CONSOLE),
                    (FRAME, 40),
                    (IIR, 0),
                    (IMR, u32::MAX),
                    (IER, 0),
                    (0x4804, 4),
                ]
                .into_iter()
                .collect(),
                actions: Vec::new(),
                palette: core::array::from_fn(|i| i as u32),
                palette_writes: 0,
                legacy_collisions: false,
                legacy_posted: 0,
                refuse_palette: false,
                allowed: true,
                powered: true,
                pause_blocked: false,
                takeover_error: None,
                pending_surface: None,
                pending_cursor: None,
                flips: true,
                frames: true,
                now: 1000,
                tick_ns: 250_000,
                deliveries: 0,
                pte_installs: 0,
                pte_clears: 0,
                refuse_ptes: false,
                refuse_console: false,
                refuse_status_restore: false,
                dsb_pc: [0; 2],
                dsb_wait: [None; 2],
                dsb_delay: [false; 2],
                dsb_stalled: [false; 2],
                dsb_writes: Vec::new(),
                poison_dsb_read: false,
            })),
            Arc::new(AtomicBool::new(false)),
            false,
        )
    }
    pub(crate) fn tiger(&self) -> Device<Self> {
        Device::new(self.clone(), Generation::TigerLake, 0x1000000, console())
    }
    pub(crate) fn meteor(&self) -> Device<Self> {
        Device::new(self.clone(), Generation::MeteorLake, 0x1000000, console())
    }
    pub(crate) fn meteor_pitch(&self, pitch: u32) -> Device<Self> {
        self.set(0x70188, pitch / 64);
        let mut saved = console();
        saved.stride_bytes = pitch;
        Device::new(self.clone(), Generation::MeteorLake, 0x1000000, saved)
    }
    pub(crate) fn primary_updates(&self) -> Vec<(u64, u32)> {
        self.0
            .lock()
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::SourceOffset(value) => Some((0x701a4, *value)),
                Action::Arm(value) => Some((SURF, *value)),
                _ => None,
            })
            .collect()
    }
    pub(crate) fn set(&self, register: u64, value: u32) {
        self.0.lock().regs.insert(register, value);
    }
    pub(crate) fn palette_writes(&self) -> usize {
        self.0.lock().palette_writes
    }
    pub(crate) fn refuse_palette(&self, refuse: bool) {
        self.0.lock().refuse_palette = refuse;
    }
    pub(crate) fn legacy_collisions(&self, enabled: bool) {
        self.0.lock().legacy_collisions = enabled;
    }
    pub(crate) fn legacy_posted(&self) -> usize {
        self.0.lock().legacy_posted
    }
    pub(crate) fn poison(&self) {
        self.1.store(true, Ordering::Release);
    }
    pub(crate) fn dsb_timing(&self) -> crate::intel_gpu_dsb::Timing {
        // Same software timing carried by this fixture's real Card mode.
        let t = crate::intel_gpu_dsb::Timing {
            clock: 1034,
            width: 64,
            height: 32,
            htotal: 224,
            vtotal: 77,
            flags: 0,
        };
        self.set(0x60000, 223 << 16 | 63);
        self.set(0x6000c, 76 << 16 | 31);
        self.set(0x60010, 76 << 16 | 31);
        self.set(0x70008, 3 << 30);
        self.set(0x45780, 6 | (8 << 16));
        self.set(0x45784, 10 | (12 << 16));
        self.set(0x45788, 14 | (16 << 16));
        t
    }
    pub(crate) fn cursor_resources(&self) -> crate::intel_gpu_dsb::Timing {
        let timing = self.dsb_timing();
        self.set(0x70008, 0);
        self.set(0x70180, 0);
        self.set(0x510a0, (14 << 22) | 8);
        self.set(0x46070, 0xc0000010);
        self.set(0x46000, 612);
        self.set(0x46008, 0);
        let mode = crate::intel_gpu_modeset::Mode {
            pixel_clock_khz: timing.clock,
            h_active: timing.width,
            h_total: timing.htotal,
            v_active: timing.height,
            v_total: timing.vtotal,
            ..crate::intel_gpu_modeset::Mode::VESA_1024X768_60
        };
        crate::intel_gpu_display_resources::initialize(self, &mode, 307200)
            .unwrap()
            .unwrap();
        self.set(0x70008, 3 << 30);
        self.set(0x70180, 0x84000000);
        timing
    }
    pub(crate) fn allow_flips(&self, enabled: bool) {
        self.0.lock().flips = enabled;
    }
    pub(crate) fn arm_order(&self) -> Vec<u64> {
        self.0
            .lock()
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::ColorArm(r) => Some(*r),
                Action::Arm(_) => Some(SURF),
                _ => None,
            })
            .collect()
    }
    pub(crate) fn primary_mappings(&self) -> Vec<(u64, u32)> {
        self.0
            .lock()
            .regs
            .range(PTE_START..(GGTT_ARRAY_BASE + GEM_SCANOUT_GTT_END / 4096 * 8))
            .map(|(&r, &v)| (r, v))
            .collect()
    }
    pub(crate) fn stall_dsb(&self, id: usize, stalled: bool) {
        self.0.lock().dsb_stalled[id] = stalled;
    }
    pub(crate) fn dsb_writes(&self) -> Vec<(u64, u32)> {
        self.0.lock().dsb_writes.clone()
    }
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn dsb_commands(&self) -> Vec<(u32, u32)> {
        self.dsb_stream(0)
    }
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn dsb_stream(&self, id: u64) -> Vec<(u32, u32)> {
        let hw = self.0.lock();
        let head = hw.regs[&(0x70b00 + id * 0x100)];
        let tail = hw.regs[&(0x70b04 + id * 0x100)];
        (head..tail)
            .step_by(8)
            .map(|pc| (hw.dsb_word(pc).unwrap(), hw.dsb_word(pc + 4).unwrap()))
            .collect()
    }
    pub(crate) fn dsb_mappings(&self) -> Vec<(u64, u32)> {
        let hw = self.0.lock();
        hw.regs
            .range(
                (GGTT_ARRAY_BASE + 144 * 1024 * 1024 / 4096 * 8)
                    ..(GGTT_ARRAY_BASE + 160 * 1024 * 1024 / 4096 * 8),
            )
            .map(|(&r, &v)| (r, v))
            .collect()
    }
    pub(crate) fn poison_next_dsb_read(&self) {
        self.0.lock().poison_dsb_read = true;
    }
    pub(crate) fn console_resumes(&self) -> usize {
        self.0
            .lock()
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Resume))
            .count()
    }
    pub(crate) fn primary_arms(&self) -> usize {
        self.0
            .lock()
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Arm(_)))
            .count()
    }
    pub(crate) fn step(&self) {
        let mut hw = self.0.lock();
        hw.now = hw.now.saturating_add(hw.tick_ns);
        if !hw.allowed || !hw.powered {
            return;
        }
        if hw.frames {
            let count = hw.regs[&FRAME].wrapping_add(1);
            hw.regs.insert(FRAME, count);
        }
        if hw.flips {
            if let Some(surface) = hw.pending_surface.take() {
                hw.regs.insert(LIVE, surface);
                // Actual register programming enables latching; IMR suppresses
                // delivery. The test never injects flipdone into a disabled IER.
                if hw.regs[&IER] & 8 != 0 {
                    *hw.regs.get_mut(&IIR).unwrap() |= 8;
                    if hw.regs[&IMR] & 8 == 0 {
                        hw.deliveries += 1;
                    }
                }
                hw.actions.push(Action::Latch(surface));
            }
        }
        if hw.flips {
            if let Some(base) = hw.pending_cursor.take() {
                hw.regs.insert(0x700ac, base);
            }
        }
        hw.execute_dsb(0);
        hw.execute_dsb(1);
    }
    fn actions(&self) -> Vec<Action> {
        self.0.lock().actions.clone()
    }
    fn mapping_count(&self) -> usize {
        self.0
            .lock()
            .regs
            .range(PTE_START..)
            .filter(|(offset, value)| **offset % 8 == 0 && **value != 0)
            .count()
    }
}
impl MmioWindow for MockPlatform {
    fn read32(&self, offset: u64) -> u32 {
        let mut hw = self.0.lock();
        if offset == 0x70b08 && hw.poison_dsb_read {
            hw.poison_dsb_read = false;
            self.1.store(true, Ordering::Release);
        }
        if (self.reset_lost() && !self.2) || !hw.allowed || !hw.powered {
            return u32::MAX;
        }
        if offset == 0x4a404 {
            return hw.palette[(hw.regs.get(&0x4a400).copied().unwrap_or(0) & 1023) as usize];
        }
        hw.regs.get(&offset).copied().unwrap_or(0)
    }
    fn write32(&self, offset: u64, value: u32) {
        let mut hw = self.0.lock();
        if (self.reset_lost() && !self.2) || !hw.allowed || !hw.powered {
            return;
        }
        hw.write(offset, value);
    }
}
impl Hardware {
    fn write(&mut self, offset: u64, value: u32) {
        if (0x4a000..0x4a400).contains(&offset) {
            if self.refuse_palette {
                return;
            }
            if self.legacy_collisions && self.regs.get(&0x70c08).copied().unwrap_or(0) & 1 != 0 {
                self.legacy_posted += 1;
                if self.legacy_posted % 2 != 0 {
                    return;
                }
            }
        }
        if offset == 0x45234 {
            self.regs.insert(offset, value & !(1 << 31));
            return;
        }
        if [0x45008, 0x44fe8, 0x44300, 0x44304].contains(&offset) {
            self.regs.insert(
                offset,
                if value & (1 << 31) != 0 {
                    value | (1 << 30)
                } else {
                    value & !(1 << 30)
                },
            );
            return;
        }
        if offset == 0x70084 {
            self.pending_cursor = Some(value);
        }
        if offset == crate::intel_gpu_color::MODE || offset == crate::intel_gpu_color::GAMMA {
            self.actions.push(Action::ColorArm(offset));
        }
        for id in 0..2 {
            let base = 0x70b00 + id as u64 * 0x100;
            if (base..=base + 0xf0).contains(&offset) {
                self.dsb_writes.push((offset, value));
                if offset == base + 0x28 {
                    let old = self.regs.get(&offset).copied().unwrap_or(0);
                    self.regs
                        .insert(offset, (value & 0xffff0000) | ((old & 0xffff) & !value));
                    return;
                }
                if offset == base + 8 {
                    let busy = self.regs.get(&offset).copied().unwrap_or(0) & 1;
                    self.regs.insert(offset, (value & !1) | busy);
                    return;
                }
                self.regs.insert(offset, value);
                if offset == base + 4
                    && self.regs.get(&(base + 8)).copied().unwrap_or(0) & (1 << 31) != 0
                {
                    let control = self.regs.get_mut(&(base + 8)).unwrap();
                    *control |= 1;
                    self.dsb_pc[id] = self.regs.get(&base).copied().unwrap_or(0);
                    self.regs.insert(base + 0x2c, self.dsb_pc[id]);
                    self.dsb_wait[id] = if *self.regs.get(&(base + 8)).unwrap() & (1 << 28) != 0 {
                        Some(self.regs[&FRAME].wrapping_add(1))
                    } else {
                        None
                    };
                }
                return;
            }
        }
        if offset == 0x4a404 {
            self.palette_writes += 1;
            if !self.refuse_palette {
                let index = self.regs.get(&0x4a400).copied().unwrap_or(0);
                self.palette[(index & 1023) as usize] = value;
                if index & (1 << 15) != 0 {
                    self.regs.insert(0x4a400, (1 << 15) | ((index + 1) & 1023));
                }
            }
        } else if offset >= GGTT_ARRAY_BASE {
            if value == 0 {
                self.pte_clears += 1;
            } else {
                self.pte_installs += 1;
            }
            if self.refuse_ptes {
                return;
            }
            if value == 0 {
                self.regs.remove(&offset);
            } else {
                self.regs.insert(offset, value);
            }
        } else if offset == IIR {
            *self.regs.get_mut(&IIR).unwrap() &= !value;
        } else {
            if (offset == SURF && value == CONSOLE && self.refuse_console)
                || (offset == IER && value & 8 == 0 && self.refuse_status_restore)
            {
                return;
            }
            self.regs.insert(offset, value);
            if offset == 0x701a4 {
                self.actions.push(Action::SourceOffset(value));
            }
            if offset == SURF {
                self.pending_surface = Some(value);
                self.actions.push(Action::Arm(value));
            }
        }
    }
    fn dsb_word(&self, address: u32) -> Option<u32> {
        if !(144 * 1024 * 1024..160 * 1024 * 1024).contains(&address) || address % 4 != 0 {
            return None;
        }
        let pte = GGTT_ARRAY_BASE + u64::from(address) / 4096 * 8;
        let value =
            u64::from(*self.regs.get(&pte)?) | (u64::from(*self.regs.get(&(pte + 4))?) << 32);
        if value & 1 == 0 {
            return None;
        }
        let physical = (value & crate::intel_gpu_gtt::PTE_PHYS_MASK) + u64::from(address % 4096);
        // SAFETY: this vector follows the actual present GGTT PTE, installed
        // by the production owner from retained allocated WC GEM frames.
        Some(unsafe {
            narf_memory::PhysAddr::new(physical)
                .kernel_ptr::<u32>()
                .read_volatile()
        })
    }
    fn execute_dsb(&mut self, id: usize) {
        let base = 0x70b00 + id as u64 * 0x100;
        if self.dsb_stalled[id] || self.regs.get(&(base + 8)).copied().unwrap_or(0) & 1 == 0 {
            return;
        }
        if let Some(frame) = self.dsb_wait[id] {
            if self.regs[&FRAME].wrapping_sub(frame) > 0x7fff_ffff {
                return;
            }
            self.dsb_wait[id] = None;
        }
        if self.dsb_delay[id] {
            self.dsb_delay[id] = false;
        }
        let tail = self.regs.get(&(base + 4)).copied().unwrap_or(0);
        for _ in 0..2048 {
            let pc = self.dsb_pc[id];
            if pc == tail {
                *self.regs.get_mut(&(base + 8)).unwrap() &= !1;
                self.regs.insert(base + 0x2c, tail);
                return;
            }
            let Some(low) = self.dsb_word(pc) else {
                self.regs.insert(base + 0x28, 8);
                return;
            };
            let Some(high) = self.dsb_word(pc + 4) else {
                self.regs.insert(base + 0x28, 8);
                return;
            };
            let mut next = pc + 8;
            let mut wait = false;
            match high >> 24 {
                0 => {}
                1 => {
                    let r = u64::from(high & 0xfffff);
                    let mut mask = 0;
                    for byte in 0..4 {
                        if high & (1 << (20 + byte)) != 0 {
                            mask |= 255 << (byte * 8);
                        }
                    }
                    let old = self.regs.get(&r).copied().unwrap_or(0);
                    self.write(r, (old & !mask) | (low & mask));
                }
                2 => {
                    self.dsb_delay[id] = true;
                    wait = true;
                }
                4 => {
                    self.dsb_wait[id] = Some(self.regs[&FRAME].wrapping_add(low));
                    wait = true;
                }
                6 => {
                    // Progress at the source-qualified active scanline. The
                    // chained leaf starts only at the following vblank.
                    let window = u64::from(low) | (u64::from(high & 255) << 32);
                    let lower = (window & 0xfffff) as u32;
                    let upper = (window >> 20) as u32;
                    let line = 8;
                    if if lower <= upper {
                        line >= lower && line <= upper
                    } else {
                        line >= lower || line <= upper
                    } {
                        return;
                    }
                }
                7 => {
                    let ints = self.regs.entry(base + 0x28).or_default();
                    *ints |= 1;
                    if *ints & (1 << 16) != 0 && self.regs[&IER] & (1 << (13 + id)) != 0 {
                        *self.regs.get_mut(&IIR).unwrap() |= 1 << (13 + id);
                        if self.regs[&IMR] & (1 << (13 + id)) == 0 {
                            self.deliveries += 1;
                        }
                    }
                }
                9 => {
                    for index in 0..low {
                        let Some(value) = self.dsb_word(pc + 8 + index * 4) else {
                            self.regs.insert(base + 0x28, 8);
                            return;
                        };
                        self.write(u64::from(high & 0xfffff), value);
                    }
                    next += low.div_ceil(2) * 8;
                }
                _ => {
                    self.regs.insert(base + 0x28, 2);
                    return;
                }
            }
            self.dsb_pc[id] = next;
            self.regs.insert(base + 0x2c, next);
            if wait {
                return;
            }
        }
        panic!("native DSB model exceeded bounded command count");
    }
}
// SAFETY: each fixture owns its complete register bank. Every access refuses
// revoked authority/power, and the Arc retains the bank for pending futures.
unsafe impl DisplayAccess for MockPlatform {
    fn ggtt_key(&self) -> Option<u64> {
        Some(self.0.lock().ggtt_key)
    }

    fn access_ok(&self) -> bool {
        let hw = self.0.lock();
        (!self.reset_lost() || self.2) && hw.allowed && hw.powered
    }
}
impl Platform for MockPlatform {
    fn takeover(&self, _owned_cursor: bool) -> Result<(), FsError> {
        if self.reset_lost() {
            return Err(FsError::NoDevice);
        }
        let mut hw = self.0.lock();
        hw.actions.push(Action::Takeover);
        hw.takeover_error.map_or(Ok(()), Err)
    }
    fn pause_console(&self) -> Wait<'_> {
        self.0.lock().actions.push(Action::Pause);
        Box::pin(core::future::poll_fn(move |_| {
            if self.0.lock().pause_blocked {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }))
    }
    fn resume_console(&self) {
        if self.reset_lost() {
            return;
        }
        self.0.lock().actions.push(Action::Resume);
    }
    fn now(&self) -> u64 {
        self.0.lock().now
    }
    fn reset_lost(&self) -> bool {
        self.1.load(Ordering::Acquire)
    }
    fn recovery_platform(&self, owned_dsb: bool, owned_cursor: bool) -> Result<Self, FsError> {
        let mut fresh = self.clone();
        fresh.2 = true;
        if !fresh.access_ok() {
            return Err(FsError::NoDevice);
        }
        fetchers_with_cursor(&fresh, Generation::MeteorLake, owned_dsb, owned_cursor)?;
        Ok(fresh)
    }
    fn recovery_complete(&self) {
        self.1.store(false, Ordering::Release);
    }
    fn tick(&self) -> Wait<'_> {
        let mut yielded = false;
        Box::pin(core::future::poll_fn(move |cx| {
            if !yielded {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                self.step();
                Poll::Ready(())
            }
        }))
    }
}
fn console() -> ActiveScanout {
    ActiveScanout {
        width: 64,
        height: 32,
        stride_bytes: 256,
        gtt_offset: CONSOLE,
        phys_base: 0x100000,
    }
}
fn geometry() -> Geometry {
    Geometry {
        width: 64,
        height: 32,
        pitch: 256,
    }
}
fn device(platform: &MockPlatform) -> Device<MockPlatform> {
    Device::new(
        platform.clone(),
        Generation::TigerLake,
        0x1000000,
        console(),
    )
}
fn once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn complete<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..128 {
        if let Poll::Ready(result) = once(future.as_mut()) {
            return result;
        }
    }
    panic!("native KMS conversation did not finish");
}
fn object(wc: bool) -> Result<Arc<GemObject>, FsError> {
    use crate::intel_gpu_gem::{GemState, Placement};
    let gem = GemState::new();
    let handle = gem.create_placed(
        8192,
        None,
        if wc {
            Placement::SystemWc
        } else {
            Placement::System
        },
        |_, _| Ok(()),
    )?;
    let object = gem.object(handle)?;
    object.mark_scanout();
    gem.close(handle)?;
    Ok(object)
}

fn smoke_kms_cross_open_serialization_and_legacy_exclusion() -> TestResult {
    let platform = MockPlatform::new();
    let device = device(&platform);
    let first = complete(device.session()).unwrap();
    let mut other_open = Box::pin(device.session());
    assert!(once(other_open.as_mut()).is_pending());
    assert!(
        device.legacy().is_err(),
        "legacy bypassed active session mutex"
    );
    drop(first);
    let mut second = complete(other_open).unwrap();
    complete(second.start()).unwrap();
    assert!(device.legacy().is_err());
    drop(second);
    assert!(
        device.legacy().is_err(),
        "legacy stole paused console/status owner"
    );
    let mut next = complete(device.session()).unwrap();
    complete(next.restore_console()).unwrap();
    drop(next);
    assert!(device.legacy().is_ok());
    complete(device.quiesce()).unwrap();
    assert!(complete(device.session()).is_err());
    let mut legacy = device.legacy().unwrap();
    legacy.suspend();
    legacy.console_replaced(&console());
    drop(legacy);
    assert!(
        complete(device.session()).is_ok(),
        "console replacement failed to reopen admission"
    );
    assert_eq!(platform.read32(IER), 0);
    assert_eq!(platform.read32(IMR), u32::MAX);
    assert_eq!(platform.mapping_count(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_cross_open_serialization_and_legacy_exclusion
);

fn smoke_kms_pause_cancellation_retains_transaction_until_next_client() -> TestResult {
    let platform = MockPlatform::new();
    let device = device(&platform);
    platform.0.lock().pause_blocked = true;
    let mut first = complete(device.session()).unwrap();
    let mut call = Box::pin(first.start());
    assert!(once(call.as_mut()).is_pending());
    let mut other = Box::pin(device.session());
    assert!(once(other.as_mut()).is_pending());
    drop(call);
    drop(first);
    assert_eq!(platform.actions(), [Action::Pause]);
    assert!(
        device.legacy().is_err(),
        "cancelled pause opened unsafe legacy access"
    );
    let mut next = complete(other).unwrap();
    assert!(next.state.paused);
    assert!(next.state.presenter.is_none());
    complete(next.restore_console()).unwrap();
    assert_eq!(platform.actions(), [Action::Pause, Action::Resume]);
    platform.0.lock().pause_blocked = false;
    complete(next.start()).unwrap();
    complete(next.restore_console()).unwrap();
    drop(next);
    assert!(device.legacy().is_ok());
    assert_eq!(platform.0.lock().deliveries, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_pause_cancellation_retains_transaction_until_next_client
);

fn smoke_kms_console_vblank_is_observed_and_loss_is_not_a_stamp() -> TestResult {
    let platform = MockPlatform::new();
    let device = device(&platform);
    let mut guard = complete(device.session()).unwrap();
    let mut call = Box::pin(guard.wait_vblank());
    assert!(once(call.as_mut()).is_pending());
    assert_eq!(platform.read32(FRAME), 40);
    let stamp = complete(call).unwrap();
    assert_eq!(stamp.sequence, 41);
    assert_eq!(stamp.ns, 251000);
    assert!(
        platform.actions().is_empty(),
        "console vblank paused or armed scanout"
    );
    platform.0.lock().frames = false;
    platform.0.lock().tick_ns = 500_000_000;
    assert!(complete(guard.wait_vblank()).is_err());
    platform.0.lock().allowed = false;
    assert_eq!(complete(guard.wait_vblank()), Err(FsError::NoDevice));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_console_vblank_is_observed_and_loss_is_not_a_stamp
);

fn smoke_kms_start_refusal_and_hard_failure_never_fall_back() -> TestResult {
    for hard in [false, true] {
        let platform = MockPlatform::new();
        let device = device(&platform);
        if hard {
            let mut hw = platform.0.lock();
            hw.refuse_ptes = true;
            hw.regs.insert(PTE_START, 0x12345001);
        } else {
            platform.0.lock().takeover_error = Some(FsError::Unsupported);
        }
        let mut guard = complete(device.session()).unwrap();
        assert!(complete(guard.start()).is_err());
        assert_eq!(guard.state.failed, hard);
        assert_eq!(guard.state.paused, hard);
        assert_eq!(
            platform
                .actions()
                .iter()
                .filter(|a| **a == Action::Resume)
                .count(),
            usize::from(!hard)
        );
        assert!(!platform
            .actions()
            .iter()
            .any(|a| matches!(a, Action::Arm(_))));
        drop(guard);
        if hard {
            assert!(complete(device.session()).is_err());
            assert!(device.legacy().is_err());
            assert!(complete(device.quiesce()).is_err());
        } else {
            assert!(device.legacy().is_ok());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_start_refusal_and_hard_failure_never_fall_back
);

fn smoke_kms_arena_bounds_refuse_before_console_or_pte_changes() -> TestResult {
    let platform = MockPlatform::new();
    let device = Device::new(platform.clone(), Generation::TigerLake, 0x800000, console());
    let mut guard = complete(device.session()).unwrap();
    assert_eq!(complete(guard.start()), Err(FsError::Unsupported));
    assert!(!guard.state.paused && guard.state.presenter.is_none() && !guard.state.failed);
    assert!(platform.actions().is_empty());
    let hw = platform.0.lock();
    assert_eq!((hw.pte_installs, hw.pte_clears), (0, 0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_arena_bounds_refuse_before_console_or_pte_changes
);

fn smoke_kms_gt_reset_quarantines_owned_or_busy_state_without_waiting() -> TestResult {
    // No presenter and no in-flight display owner: epoch-zero publication
    // by the GT caller is sufficient to prevent a premature next takeover.
    let platform = MockPlatform::new();
    let idle_device = device(&platform);
    quarantine_reset_state(&idle_device.state, &platform.1);
    assert!(!platform.reset_lost());
    assert!(complete(idle_device.session()).is_ok());

    // A busy legacy owner cannot clear reset loss by publishing console
    // metadata from a sequence which raced reset/PAT re-initialization.
    let mut legacy = idle_device.legacy().unwrap();
    quarantine_reset_state(&idle_device.state, &platform.1);
    assert!(platform.reset_lost());
    legacy.console_replaced(&console());
    assert!(legacy.state.failed && legacy.state.blocked);
    drop(legacy);
    assert!(idle_device.legacy().is_err());
    assert!(complete(idle_device.session()).is_err());
    assert!(complete(idle_device.quiesce()).is_err());
    assert!(platform.actions().is_empty());

    // Cancellation/in-flight CPU quiescence has not created a Presenter
    // yet. Reset still poisons its cloned IO and cannot resume the console.
    let paused_platform = MockPlatform::new();
    let paused_device = device(&paused_platform);
    paused_platform.0.lock().pause_blocked = true;
    let mut guard = complete(paused_device.session()).unwrap();
    let mut start = Box::pin(guard.start());
    assert!(once(start.as_mut()).is_pending());
    quarantine_reset_state(&paused_device.state, &paused_platform.1);
    paused_platform.0.lock().pause_blocked = false;
    assert_eq!(complete(start), Err(FsError::NoDevice));
    assert!(guard.state.paused && guard.state.failed && guard.state.presenter.is_none());
    assert_eq!(complete(guard.restore_console()), Err(FsError::NoDevice));
    assert_eq!(paused_platform.actions(), [Action::Pause]);

    #[cfg(target_arch = "x86_64")]
    {
        let front_platform = MockPlatform::new();
        let front_device = device(&front_platform);
        let front = object(true).unwrap();
        let weak = Arc::downgrade(&front);
        let mut guard = complete(front_device.session()).unwrap();
        complete(guard.present(front, geometry())).unwrap();
        drop(guard);
        let mapped = front_platform.mapping_count();
        let actions = front_platform.actions();
        quarantine_reset_state(&front_device.state, &front_platform.1);
        assert!(front_platform.reset_lost());
        assert!(weak.upgrade().is_some());
        assert_eq!(front_platform.mapping_count(), mapped);
        assert!(complete(front_device.session()).is_err());
        assert!(complete(front_device.quiesce()).is_err());
        assert_eq!(front_platform.actions(), actions);
        assert!(weak.upgrade().is_some());
        // Intentionally no fake fetch-stop: the real Presenter destructor
        // quarantines these two pages and its IO owner, as on hardware loss.
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_gt_reset_quarantines_owned_or_busy_state_without_waiting
);

fn smoke_kms_gt_recovery_waits_for_fresh_console_before_reclaim() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    {
        let platform = MockPlatform::new();
        // Original owned bits and foreign sources must survive two status
        // acquisitions. Our already-enabled bits are not firmware state.
        platform.0.lock().regs.insert(IER, (1 << 7) | 1);
        let device = device(&platform);
        let first = object(true).unwrap();
        let first_weak = Arc::downgrade(&first);
        let second = object(true).unwrap();
        let second_weak = Arc::downgrade(&second);
        let mut session = complete(device.session()).unwrap();
        complete(session.present(first, geometry())).unwrap();
        let mut pending = Box::pin(session.present(second, geometry()));
        assert!(once(pending.as_mut()).is_pending());
        platform.0.lock().flips = false;
        quarantine_reset_state(&device.state, &platform.1);
        assert!(complete(pending).is_err());
        drop(session);
        platform.0.lock().flips = true;
        // The pre-reset pending write differs from SURFLIVE. Recovery must
        // overwrite it and prove a new console latch, never retire by either
        // pre-reset sample or a successful GT reset alone.
        let mapped = platform.mapping_count();
        assert_eq!(mapped, 4);
        {
            let hw = platform.0.lock();
            assert_ne!(hw.regs[&SURF], hw.regs[&LIVE]);
        }
        let mut recovery = Box::pin(device.recover());
        assert!(once(recovery.as_mut()).is_pending());
        assert!(device.reset_lost());
        assert!(first_weak.upgrade().is_some() && second_weak.upgrade().is_some());
        assert_eq!(platform.mapping_count(), mapped);
        assert!(!platform.actions().contains(&Action::Resume));
        complete(recovery).unwrap();
        assert!(!device.reset_lost());
        assert!(first_weak.upgrade().is_none() && second_weak.upgrade().is_none());
        assert_eq!(platform.mapping_count(), 0);
        assert_eq!(platform.read32(LIVE), CONSOLE);
        assert_eq!(platform.read32(IER), (1 << 7) | 1);
        assert_eq!(platform.read32(IMR), u32::MAX);
        let actions = platform.actions();
        assert!(
            actions
                .iter()
                .rposition(|a| *a == Action::Latch(CONSOLE))
                .unwrap()
                < actions.iter().position(|a| *a == Action::Resume).unwrap()
        );
        let mut next = complete(device.session()).unwrap();
        complete(next.present(object(true).unwrap(), geometry())).unwrap();
        complete(next.restore_console()).unwrap();
        assert_eq!(platform.read32(IER), (1 << 7) | 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_gt_recovery_waits_for_fresh_console_before_reclaim
);

fn smoke_kms_gt_recovery_waits_for_busy_owner_and_retires_pause() -> TestResult {
    let platform = MockPlatform::new();
    let device = device(&platform);
    let session = complete(device.session()).unwrap();
    assert!(session.ownership_valid().is_ok());
    quarantine_reset_state(&device.state, &platform.1);
    assert_eq!(session.ownership_valid(), Err(FsError::NoDevice));
    let mut recovery = Box::pin(device.recover());
    assert!(once(recovery.as_mut()).is_pending());
    assert!(
        platform.actions().is_empty(),
        "recovery overtook the busy display owner"
    );
    drop(session);
    assert!(once(recovery.as_mut()).is_pending());
    assert!(device.reset_lost());
    complete(recovery).unwrap();
    assert!(!device.reset_lost());
    assert!(device.legacy().is_ok());
    assert_eq!(
        platform.actions(),
        [
            Action::Pause,
            Action::Arm(CONSOLE),
            Action::Latch(CONSOLE),
            Action::Resume
        ]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_gt_recovery_waits_for_busy_owner_and_retires_pause
);

fn smoke_kms_gt_recovery_does_not_wait_for_retained_gpu_fences() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    {
        let platform = MockPlatform::new();
        let device = device(&platform);
        let gpu_owner = object(true).unwrap();
        let weak = Arc::downgrade(&gpu_owner);
        let mut session = complete(device.session()).unwrap();
        complete(session.present(gpu_owner.clone(), geometry())).unwrap();
        drop(session);
        let fence = Arc::new(crate::intel_gpu_fence::CompletionFence::new());
        crate::intel_gpu_gem::reserve_gpu_explicit(&[(gpu_owner.clone(), true)], &fence);
        assert!(!gpu_owner.idle(false));
        quarantine_reset_state(&device.state, &platform.1);
        // The independent GPU residency owner remains responsible for its
        // fence/pages. Display recovery must neither await that fence while
        // holding its mutex nor consume somebody else's residency owner.
        complete(device.recover()).unwrap();
        assert!(fence.result().is_none());
        assert_eq!(platform.mapping_count(), 0);
        assert!(weak.upgrade().is_some());
        fence.signal(Err(crate::intel_gpu_fence::JobError::Reset));
        drop(gpu_owner);
        assert!(weak.upgrade().is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_gt_recovery_does_not_wait_for_retained_gpu_fences
);

fn smoke_kms_gt_recovery_failure_retains_front_and_pending() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    for failure in 0..6 {
        let platform = MockPlatform::new();
        let device = device(&platform);
        let front = object(true).unwrap();
        let weak = Arc::downgrade(&front);
        let pending_object = object(true).unwrap();
        let pending_weak = Arc::downgrade(&pending_object);
        let mut session = complete(device.session()).unwrap();
        complete(session.present(front, geometry())).unwrap();
        let mut pending = Box::pin(session.present(pending_object, geometry()));
        assert!(once(pending.as_mut()).is_pending());
        platform.0.lock().flips = false;
        quarantine_reset_state(&device.state, &platform.1);
        assert!(complete(pending).is_err());
        drop(session);
        {
            let mut hw = platform.0.lock();
            hw.flips = true;
            match failure {
                0 => hw.allowed = false,
                1 => {
                    hw.flips = false;
                    hw.tick_ns = 500_000_000;
                }
                2 => hw.refuse_ptes = true,
                3 => {
                    hw.regs.insert(0x70188, 5);
                }
                4 => hw.refuse_status_restore = true,
                _ => hw.refuse_console = true,
            }
        }
        assert!(complete(device.recover()).is_err());
        assert!(device.reset_lost());
        assert!(weak.upgrade().is_some() && pending_weak.upgrade().is_some());
        // Even when every PTE cleared, failed original-status restoration
        // conservatively retains all pages and keeps admission closed.
        assert_eq!(platform.mapping_count(), if failure == 4 { 0 } else { 4 });
        assert!(device.legacy().is_err());
        assert!(complete(device.session()).is_err());
        assert!(!platform.actions().contains(&Action::Resume));
        // Give the fixture an independently verified fresh latch to avoid
        // leaking native pages during test teardown. Production retry is
        // initiated only by a subsequent verified GT restart.
        {
            let mut hw = platform.0.lock();
            hw.allowed = true;
            hw.flips = true;
            hw.refuse_ptes = false;
            hw.refuse_console = false;
            hw.refuse_status_restore = false;
            hw.regs.insert(0x70188, 4);
        }
        complete(device.recover()).unwrap();
        assert!(weak.upgrade().is_none() && pending_weak.upgrade().is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_gt_recovery_failure_retains_front_and_pending
);

fn smoke_kms_public_wc_flip_restore_and_retirement() -> TestResult {
    let platform = MockPlatform::new();
    let device = device(&platform);
    let wc = object(true);
    #[cfg(target_arch = "aarch64")]
    {
        assert!(matches!(wc, Err(FsError::NotImplemented)));
        let mut guard = complete(device.session()).unwrap();
        assert_eq!(
            complete(guard.present(object(false).unwrap(), geometry())),
            Err(FsError::Unsupported)
        );
        assert!(platform.actions().is_empty());
    }
    #[cfg(target_arch = "x86_64")]
    {
        let object = wc.unwrap();
        let weak = Arc::downgrade(&object);
        let mut guard = complete(device.session()).unwrap();
        let stamp = complete(guard.present(object.clone(), geometry())).unwrap();
        assert_eq!(stamp.sequence, 41);
        let surface = platform.read32(LIVE);
        assert!((GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(surface)));
        assert_eq!(platform.mapping_count(), 2);
        assert_eq!(platform.0.lock().deliveries, 0);
        drop(object);
        assert!(weak.upgrade().is_some());
        assert!(
            complete(guard.wait_vblank()).is_err(),
            "native presenter allowed synthetic console vblank path"
        );
        let mut restore = Box::pin(guard.restore_console());
        assert!(once(restore.as_mut()).is_pending());
        assert_eq!(platform.read32(SURF), CONSOLE);
        assert_eq!(
            platform.read32(LIVE),
            surface,
            "arm fabricated console latch"
        );
        assert!(
            weak.upgrade().is_some(),
            "console arm released still-live GEM"
        );
        complete(restore).unwrap();
        assert_eq!(platform.read32(LIVE), CONSOLE);
        assert_eq!(platform.mapping_count(), 0);
        assert!(weak.upgrade().is_none());
        assert_eq!(platform.read32(IER), 0);
        assert_eq!(platform.read32(IMR), u32::MAX);
        assert_eq!(
            platform.actions(),
            [
                Action::Pause,
                Action::Takeover,
                Action::Arm(surface),
                Action::Latch(surface),
                Action::Arm(CONSOLE),
                Action::Latch(CONSOLE),
                Action::Resume
            ]
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_public_wc_flip_restore_and_retirement
);

fn smoke_kms_cancelled_flip_drains_before_next_client_arms() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    {
        let platform = MockPlatform::new();
        let device = device(&platform);
        let first = object(true).unwrap();
        let first_weak = Arc::downgrade(&first);
        let second = object(true).unwrap();
        let second_weak = Arc::downgrade(&second);
        let mut guard = complete(device.session()).unwrap();
        let mut pending = Box::pin(guard.present(first.clone(), geometry()));
        assert!(once(pending.as_mut()).is_pending());
        let first_surface = platform.read32(SURF);
        assert_eq!(platform.read32(LIVE), CONSOLE);
        drop(pending);
        drop(guard);
        drop(first);
        assert!(first_weak.upgrade().is_some());
        assert!(device.legacy().is_err());
        let mut next = complete(device.session()).unwrap();
        complete(next.present(second.clone(), geometry())).unwrap();
        let second_surface = platform.read32(LIVE);
        assert_ne!(first_surface, second_surface);
        assert!(
            first_weak.upgrade().is_none(),
            "retired first client mapping remained pinned"
        );
        let actions = platform.actions();
        let first_latch = actions
            .iter()
            .position(|a| *a == Action::Latch(first_surface))
            .unwrap();
        let next_arm = actions
            .iter()
            .position(|a| *a == Action::Arm(second_surface))
            .unwrap();
        assert!(
            first_latch < next_arm,
            "next client armed over unretired cancelled flip"
        );
        drop(second);
        complete(next.restore_console()).unwrap();
        assert!(second_weak.upgrade().is_none());
        assert_eq!(platform.mapping_count(), 0);
    }
    #[cfg(target_arch = "aarch64")]
    assert!(matches!(object(true), Err(FsError::NotImplemented)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_cancelled_flip_drains_before_next_client_arms
);

fn smoke_kms_timeout_retains_pending_pages_and_closes_admission() -> TestResult {
    #[cfg(target_arch = "x86_64")]
    {
        let platform = MockPlatform::new();
        let device = device(&platform);
        let object = object(true).unwrap();
        let weak = Arc::downgrade(&object);
        let mut guard = complete(device.session()).unwrap();
        platform.0.lock().flips = false;
        platform.0.lock().tick_ns = 500_000_000;
        assert!(complete(guard.present(object.clone(), geometry())).is_err());
        drop(object);
        assert!(weak.upgrade().is_some());
        assert!(guard.state.pending.is_some());
        assert!(guard.state.failed && guard.state.paused);
        assert!(complete(guard.restore_console()).is_err());
        assert!(!platform.actions().contains(&Action::Resume));
        drop(guard);
        assert!(complete(device.session()).is_err());
        assert!(device.legacy().is_err());
        assert_eq!(platform.mapping_count(), 2);
        // Explicit fixture teardown supplies an independent fetch-stop proof;
        // a production timeout itself cannot release any of these resources.
        let mut state = complete(device.state.lock());
        platform.0.lock().pending_surface = None;
        platform.0.lock().regs.insert(0x70180, 0);
        // SAFETY: the native display is stopped; this fixture owns every
        // fetcher, page-table slot, authority and power reference.
        unsafe { state.presenter.as_mut().unwrap().shutdown_stopped() }.unwrap();
        state.presenter = None;
        state.current = None;
        state.pending = None;
        assert!(weak.upgrade().is_none());
    }
    #[cfg(target_arch = "aarch64")]
    assert!(matches!(object(true), Err(FsError::NotImplemented)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_timeout_retains_pending_pages_and_closes_admission
);

fn smoke_kms_inherited_fetchers_block_arena_claim() -> TestResult {
    // Primary plane A is the retained console. Every other universal plane,
    // hardware cursor, FBC instance and display state buffer is unowned.
    for (generation, enabled) in [
        (Generation::TigerLake, 0x70080),  // Cursor A, mode bits.
        (Generation::AlderLake, 0x73080),  // Cursor D.
        (Generation::MeteorLake, 0x72080), // Cursor C.
        (Generation::TigerLake, 0x43208),  // FBC A.
        (Generation::MeteorLake, 0x43248), // FBC B.
        (Generation::TigerLake, 0x70280),  // Pipe A plane 2.
        (Generation::MeteorLake, 0x73580), // Pipe D plane 5.
        (Generation::TigerLake, 0x70b08),  // DSB A0.
        (Generation::MeteorLake, 0x73d08), // DSB D2.
    ] {
        let platform = MockPlatform::new();
        assert_eq!(inherited_fetchers_idle(&platform, generation), Ok(()));
        let cursor = matches!(enabled, 0x70080 | 0x72080 | 0x73080);
        let dsb = matches!(enabled, 0x70b08 | 0x73d08);
        if dsb {
            platform.0.lock().regs.insert(enabled, 1); // Busy without enable.
            assert_eq!(
                inherited_fetchers_idle(&platform, generation),
                Err(FsError::Unsupported)
            );
        }
        let value = if cursor { 0x27 } else { 1 << 31 };
        platform.0.lock().regs.insert(enabled, value);
        assert_eq!(
            inherited_fetchers_idle(&platform, generation),
            Err(FsError::Unsupported)
        );
        platform.0.lock().regs.insert(enabled, u32::MAX);
        assert_eq!(
            inherited_fetchers_idle(&platform, generation),
            Err(FsError::NoDevice)
        );
        assert!(platform.actions().is_empty());
        assert_eq!(platform.0.lock().pte_clears, 0);
    }
    let owned = MockPlatform::new();
    owned.set(0x70b08, (1 << 31) | 1);
    owned.set(0x70c08, (1 << 31) | 1);
    assert_eq!(
        inherited_fetchers_idle(&owned, Generation::MeteorLake),
        Err(FsError::Unsupported)
    );
    assert_eq!(fetchers_idle(&owned, Generation::MeteorLake, true), Ok(()));
    for r in [0x70d08, 0x71b08, 0x72080, 0x43208] {
        owned.set(r, 1 << 31 | 1);
        assert_eq!(
            fetchers_idle(&owned, Generation::MeteorLake, true),
            Err(FsError::Unsupported)
        );
        owned.set(r, 0);
    }
    let platform = MockPlatform::new();
    platform.0.lock().allowed = false;
    assert_eq!(
        inherited_fetchers_idle(&platform, Generation::MeteorLake),
        Err(FsError::NoDevice)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_kms",
    smoke_kms_inherited_fetchers_block_arena_claim
);

#[path = "intel_gpu_color_kms_tests.rs"]
mod color;
