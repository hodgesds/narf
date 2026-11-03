//! ACP 6.3 SoundWire DMA payload engine (issue #870): moves PCM
//! samples between host memory and the SDW manager once the port is
//! enabled, implementing [`crate::soundwire::PayloadEngine`] for the
//! generic SDW card's streams.
//!
//! The engine mirrors the in-tree ACP PDM path (`crate::acp63`):
//! one [`crate::native_pcm::Ring`] per lease, ATU/window programming
//! at prepare (PTE pairs per 4 KiB page, fixed DMA window), a
//! hi/lo/hi snapshot hardware counter, wrap/xrun discipline copied
//! from the PDM read path, and failed-stop retention (a stop whose
//! DMA-disable handshake times out keeps the ring, the position, and
//! the channel claim; the caller retries the stop).
//!
//! UNVERIFIED HARDWARE ASSUMPTION — READ BEFORE TOUCHING SILICON:
//! this engine programs the ACP DMA channel block
//! (`DMA_ENABLE`/`RING_ADDR`/`RING_SIZE`/`WATERMARK`/`COUNT_*` plus the
//! function-wide ATU) that the in-tree PDM path uses, on the premise
//! that the SDW binding owns the function exclusively — the SDW probe
//! declines whenever PDM owns the function, and PDM+SDW coexistence
//! is a separate follow-up — so the channel is free for the SDW
//! stream. Linux's `sound/soc/amd/ps/ps-sdw-dma.c` register map was
//! NOT verified from source in this lane: no `sound/` tree exists on
//! the build machine, and lore.kernel.org denied the patch text, so
//! the per-stream position-register model Linux documents (per-manager
//! `AUDIO*_TX`/`AUDIO*_RX` registers) could not be checked against
//! this block. If silicon disagrees, the correction belongs in
//! [`AcpDmaRegs`] alone — the ring, accounting, and lifecycle code
//! does not name registers. Validate on hardware before treating the
//! channel programming as proven.
//!
//! Consequences of the single-channel model, stated plainly:
//! - Playback and capture leases on one card share one channel: a
//!   second stream's `start` fails `DeviceBusy` while the first runs.
//!   Concurrent bidirectional streaming needs the per-stream channel
//!   map above, and is out of scope until that map is verified.
//! - The engine is direction-agnostic at the register level: the same
//!   channel programming serves a playback lease and a capture lease,
//!   serialized by the guard. The wire direction is the port's job
//!   (sink vs source port in the generic profile), not the DMA
//!   channel's.
//! - IRQ-driven xrun detection is not wired: position is polled by
//!   `pointer`/`write`/`read` (the 2 ms service timer in the audio
//!   spec §3.3 covers the same polling for the other native paths).

use crate::{
    acp63::{
        ATU_BASE, ATU_CONTROL, ATU_PAGE_SIZE, COUNT_HIGH, COUNT_LOW, DMA_ENABLE, DMA_WINDOW,
        PTE_BASE, RING_ADDR, RING_SIZE, SCRATCH, WATERMARK,
    },
    native_pcm::Ring,
    soundwire::{PayloadEngine, PayloadEngineFactory},
};
use alloc::{boxed::Box, sync::Arc};
use narf_bus::MmioRegion;
use narf_drivers_sound::{format::HwParams, SoundError};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

/// Register access for the ACP DMA channel block. Production uses
/// [`AcpDmaRegs`] (live BAR); fixtures use the kernel-test fake.
pub trait DmaRegs: Send + Sync + core::fmt::Debug {
    fn read(&self, offset: u64) -> u32;
    fn write(&mut self, offset: u64, value: u32);
}

/// Live ACP BAR access for the DMA channel block. The caller owns the
/// ACP function exclusively (probe claimed it and validated the BAR
/// covers the DMA block); offsets are fixed and inside that window.
#[derive(Copy, Clone, Debug)]
pub struct AcpDmaRegs {
    mmio: MmioRegion,
}

impl DmaRegs for AcpDmaRegs {
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: caller-owned BAR; offset inside the validated window.
        unsafe { self.mmio.read32(offset) }
    }
    fn write(&mut self, offset: u64, value: u32) {
        // SAFETY: caller-owned BAR; offset inside the validated window.
        unsafe { self.mmio.write32(offset, value) }
    }
}

/// ACP SDW DMA engine: one ring, one channel claim, PDM-mirrored
/// lifecycle. `R` is the register block; production uses
/// [`AcpDmaRegs`], fixtures use the kernel-test fake.
#[derive(Debug)]
pub struct SdwDma<R: DmaRegs> {
    regs: R,
    /// Single active DMA stream per card (see module doc). Claimed in
    /// `start`, released in `stop` and in `shutdown_for_drop`.
    guard: Arc<IrqSafeSpinLock<bool>>,
    ring: Option<Ring>,
    /// Hardware counter value at the last start: the logical position
    /// survives PAUSE/RESUME while prepare resets hardware to zero.
    baseline: u64,
}

fn wait(predicate: impl FnMut() -> bool) -> bool {
    narf_scheduler::responsive_spin_until(predicate, Deadline::after_ms(100))
}

impl<R: DmaRegs> SdwDma<R> {
    pub fn new(regs: R, guard: Arc<IrqSafeSpinLock<bool>>) -> Self {
        Self {
            regs,
            guard,
            ring: None,
            baseline: 0,
        }
    }

    fn count(&self) -> Result<u64, SoundError> {
        // Counter can roll over between reads; bounded high/low/high
        // snapshot (acp63).
        for _ in 0..4 {
            let hi = self.regs.read(COUNT_HIGH);
            let lo = self.regs.read(COUNT_LOW);
            let again = self.regs.read(COUNT_HIGH);
            if hi == again {
                return Ok(((hi as u64) << 32) | lo as u64);
            }
        }
        Err(SoundError::BadState)
    }

    /// Poll the hardware counter into the ring, stopping on xrun.
    /// Borrows are scoped so the stop below never overlaps a ring
    /// borrow (the ring lives in this struct, unlike acp63's split
    /// controller/state).
    fn update(&mut self) {
        if !self.ring.as_ref().is_some_and(|ring| ring.running) {
            return;
        }
        match self.count() {
            Err(_) => {
                if let Some(ring) = self.ring.as_mut() {
                    ring.xrun = true;
                }
                let _ = self.stop();
            }
            Ok(count) => {
                let overrun = {
                    let ring = self.ring.as_mut().unwrap();
                    // Floor to a whole-frame boundary (S16LE stereo:
                    // 4 bytes/frame; acp63 floors to its 8-byte frame).
                    ring.hardware =
                        count.wrapping_sub(self.baseline) & !(ring.frame_bytes as u64 - 1);
                    ring.hardware.saturating_sub(ring.application) > ring.bytes as u64
                };
                if overrun {
                    if let Some(ring) = self.ring.as_mut() {
                        ring.xrun = true;
                    }
                    let _ = self.stop();
                }
            }
        }
    }
}

impl<R: DmaRegs> PayloadEngine for SdwDma<R> {
    fn configure(&mut self, params: HwParams) -> Result<(), SoundError> {
        if self.ring.as_ref().is_some_and(|ring| ring.running) {
            return Err(SoundError::BadState);
        }
        let ring = Ring::new(params)?;
        self.ring = Some(ring);
        self.baseline = 0;
        Ok(())
    }

    fn prepare(&mut self) -> Result<(), SoundError> {
        // Stop first (idempotent when already stopped); a failed stop
        // retains the old stream and fails the prepare (acp63).
        self.stop()?;
        let ring = self.ring.as_mut().ok_or(SoundError::BadState)?;
        ring.reset();
        // ACP's internal ATU translates its fixed DMA window to system
        // DMA pages; a CPU virtual address must never be programmed
        // here (acp63). PTE pairs per 4 KiB page: low word = address
        // low, high word = address high | valid bit.
        self.regs.write(ATU_BASE, PTE_BASE | (1 << 31));
        self.regs.write(ATU_PAGE_SIZE, 2);
        for page in 0..ring.bytes.div_ceil(4096) {
            let address = ring.data.dma_addr_at((page * 4096) as u64).raw();
            self.regs.write(SCRATCH + page as u64 * 8, address as u32);
            self.regs.write(
                SCRATCH + page as u64 * 8 + 4,
                (address >> 32) as u32 | (1 << 31),
            );
        }
        self.regs.write(RING_ADDR, DMA_WINDOW);
        self.regs.write(RING_SIZE, ring.bytes as u32);
        self.regs
            .write(WATERMARK, ring.params.period_bytes() as u32);
        self.regs.write(ATU_CONTROL, 1);
        Ok(())
    }

    fn start(&mut self) -> Result<(), SoundError> {
        if !self
            .ring
            .as_ref()
            .is_some_and(|ring| ring.prepared && !ring.xrun && !ring.running)
        {
            return Err(SoundError::BadState);
        }
        // Count before claiming: a failed count must not leave the
        // channel claimed.
        let baseline = self
            .count()?
            .wrapping_sub(self.ring.as_ref().unwrap().hardware);
        {
            let mut claimed = self.guard.lock();
            if *claimed {
                return Err(SoundError::DeviceBusy);
            }
            *claimed = true;
        }
        self.baseline = baseline;
        self.regs.write(DMA_ENABLE, 1);
        // Set before polling: even a timed-out start may have begun DMA.
        self.ring.as_mut().unwrap().running = true;
        if !wait(|| self.regs.read(DMA_ENABLE) & 2 != 0) {
            let _ = self.stop();
            return Err(SoundError::BadState);
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), SoundError> {
        if self.regs.read(DMA_ENABLE) & 3 != 0 {
            self.regs.write(DMA_ENABLE, 2);
        }
        if !wait(|| self.regs.read(DMA_ENABLE) & 2 == 0) {
            // Failed-stop retention: ring, position, and channel claim
            // are all retained; the caller must retry the stop.
            return Err(SoundError::BadState);
        }
        if let Some(ring) = self.ring.as_mut() {
            ring.running = false;
            ring.prepared = false;
        }
        *self.guard.lock() = false;
        Ok(())
    }

    fn mark_prepared(&mut self) -> Result<(), SoundError> {
        let ring = self.ring.as_mut().ok_or(SoundError::BadState)?;
        if ring.running {
            return Err(SoundError::BadState);
        }
        ring.prepared = true;
        Ok(())
    }

    fn pointer(&mut self) -> u64 {
        self.update();
        self.ring
            .as_ref()
            .map_or(0, |ring| ring.hardware / ring.frame_bytes as u64)
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, SoundError> {
        self.update();
        let count = self
            .ring
            .as_mut()
            .ok_or(SoundError::BadState)?
            .write(data)?;
        self.update();
        if self.ring.as_ref().is_some_and(|ring| ring.xrun) {
            let _ = self.stop();
            return Err(SoundError::BadState);
        }
        Ok(count)
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize, SoundError> {
        self.update();
        let original = self.ring.as_mut().ok_or(SoundError::BadState)?.application;
        let count = self.ring.as_mut().ok_or(SoundError::BadState)?.read(out)?;
        // Detect a DMA wrap racing the CPU copy; don't report
        // overwritten data (acp63 read path).
        self.update();
        let (xrun, wrapped) = {
            let ring = self.ring.as_mut().ok_or(SoundError::BadState)?;
            (
                ring.xrun,
                ring.hardware.saturating_sub(original) > ring.bytes as u64,
            )
        };
        if xrun || wrapped {
            if let Some(ring) = self.ring.as_mut() {
                ring.xrun = true;
            }
            let _ = self.stop();
            return Err(SoundError::BadState);
        }
        Ok(count)
    }

    fn shutdown_for_drop(&mut self) -> bool {
        if self.stop().is_ok() {
            return true;
        }
        // Stop failed: release the channel claim so the card is not
        // wedged, and report that the ring must NOT be freed (DMA may
        // still be running into it).
        *self.guard.lock() = false;
        false
    }
}

/// Production payload-engine factory for one ACP SDW card: every
/// engine it builds programs the same function BAR and shares the
/// card's single-channel guard.
#[derive(Debug)]
pub struct AcpSdwDmaFactory {
    mmio: MmioRegion,
    guard: Arc<IrqSafeSpinLock<bool>>,
}

impl AcpSdwDmaFactory {
    pub fn new(mmio: MmioRegion) -> Self {
        Self {
            mmio,
            guard: Arc::new(IrqSafeSpinLock::new(false)),
        }
    }
}

impl PayloadEngineFactory for AcpSdwDmaFactory {
    fn create(&self) -> Box<dyn PayloadEngine> {
        Box::new(SdwDma::new(
            AcpDmaRegs { mmio: self.mmio },
            self.guard.clone(),
        ))
    }
}

#[cfg(feature = "kernel-test")]
use alloc::collections::BTreeMap;

/// Modelled DMA channel block for fixtures: a register map plus the
/// `DMA_ENABLE` handshake (write 1 latches the running bit, write 2
/// clears it unless a stop failure is armed) and a scriptable 64-bit
/// hardware counter. Shared by handle so tests can drive the hardware
/// while the engine owns its copy.
#[cfg(feature = "kernel-test")]
#[derive(Clone, Debug)]
pub(crate) struct FakeRegs {
    inner: Arc<IrqSafeSpinLock<FakeRegsInner>>,
}

#[cfg(feature = "kernel-test")]
#[derive(Debug, Default)]
struct FakeRegsInner {
    regs: BTreeMap<u64, u32>,
    fail_stop: bool,
}

#[cfg(feature = "kernel-test")]
impl FakeRegs {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(IrqSafeSpinLock::new(FakeRegsInner::default())),
        }
    }

    pub(crate) fn read_reg(&self, offset: u64) -> u32 {
        self.inner.lock().regs.get(&offset).copied().unwrap_or(0)
    }

    /// Script the hardware counter (bytes) the engine's `count`
    /// snapshot reads.
    pub(crate) fn set_counter(&self, bytes: u64) {
        let mut inner = self.inner.lock();
        inner.regs.insert(COUNT_HIGH, (bytes >> 32) as u32);
        inner.regs.insert(COUNT_LOW, bytes as u32);
    }

    /// Arm (or clear) the stop-failure mode: with it armed, a
    /// `DMA_ENABLE` stop write never clears the running bit, so the
    /// engine's stop handshake times out.
    pub(crate) fn set_fail_stop(&self, fail: bool) {
        self.inner.lock().fail_stop = fail;
    }
}

#[cfg(feature = "kernel-test")]
impl DmaRegs for FakeRegs {
    fn read(&self, offset: u64) -> u32 {
        self.read_reg(offset)
    }

    fn write(&mut self, offset: u64, value: u32) {
        let mut inner = self.inner.lock();
        if offset == DMA_ENABLE {
            match value {
                // Start latches the running bit the engine polls for.
                1 => {
                    inner.regs.insert(offset, 1 | 2);
                }
                // Stop clears it — unless a stop failure is armed.
                2 => {
                    if !inner.fail_stop {
                        inner.regs.insert(offset, 0);
                    }
                }
                _ => {
                    inner.regs.insert(offset, value);
                }
            }
            return;
        }
        inner.regs.insert(offset, value);
    }
}

/// Fixture factory building [`SdwDma`] engines over one shared
/// [`FakeRegs`] block and one shared channel guard, so lease-level
/// tests (in `crate::soundwire`) can drive the same hardware the
/// engine programs.
#[cfg(feature = "kernel-test")]
#[derive(Debug)]
pub(crate) struct FakeDmaFactory {
    regs: FakeRegs,
    guard: Arc<IrqSafeSpinLock<bool>>,
}

#[cfg(feature = "kernel-test")]
impl FakeDmaFactory {
    pub(crate) fn new(regs: FakeRegs) -> Self {
        Self {
            regs,
            guard: Arc::new(IrqSafeSpinLock::new(false)),
        }
    }
}

#[cfg(feature = "kernel-test")]
impl PayloadEngineFactory for FakeDmaFactory {
    fn create(&self) -> Box<dyn PayloadEngine> {
        Box::new(SdwDma::new(self.regs.clone(), self.guard.clone()))
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_drivers_sound::format::{ChannelCount, SampleFormat, SampleRate};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn fixed_params() -> HwParams {
        HwParams {
            format: SampleFormat::S16LE,
            rate: SampleRate::R48000,
            channels: ChannelCount::Stereo,
            period_size: 1024,
            periods: 4,
        }
    }

    /// One engine plus its fake block and channel guard. The ring is
    /// 4 periods x 1024 frames x 4 bytes = 16 KiB; one period is
    /// 4096 bytes.
    fn make_engine() -> (SdwDma<FakeRegs>, FakeRegs, Arc<IrqSafeSpinLock<bool>>) {
        let regs = FakeRegs::new();
        let guard = Arc::new(IrqSafeSpinLock::new(false));
        (SdwDma::new(regs.clone(), guard.clone()), regs, guard)
    }

    fn started_engine() -> (SdwDma<FakeRegs>, FakeRegs, Arc<IrqSafeSpinLock<bool>>) {
        let (mut engine, regs, guard) = make_engine();
        if engine.configure(fixed_params()).is_err()
            || engine.prepare().is_err()
            || engine.start().is_err()
        {
            panic!("fixture engine failed to start");
        }
        (engine, regs, guard)
    }

    fn ring_layout_programmed_on_prepare() -> TestResult {
        let (mut engine, regs, _) = make_engine();
        if engine.configure(fixed_params()) != Ok(()) {
            return TestResult::Fail("configure failed");
        }
        if engine.prepare() != Ok(()) {
            return TestResult::Fail("prepare failed");
        }
        // ATU/window programming, pinned exactly (acp63 PDM shape).
        if regs.read_reg(ATU_BASE) != PTE_BASE | (1 << 31)
            || regs.read_reg(ATU_PAGE_SIZE) != 2
            || regs.read_reg(RING_ADDR) != DMA_WINDOW
            || regs.read_reg(RING_SIZE) != 16384
            || regs.read_reg(WATERMARK) != 4096
            || regs.read_reg(ATU_CONTROL) != 1
        {
            return TestResult::Fail("ATU/window programming mismatch");
        }
        // One PTE pair per 4 KiB page, from the ring's own DMA
        // addresses (low word, high word | valid bit).
        let ring = engine.ring.as_ref().unwrap();
        for page in 0..4 {
            let address = ring.data.dma_addr_at((page * 4096) as u64).raw();
            if regs.read_reg(SCRATCH + page as u64 * 8) != address as u32
                || regs.read_reg(SCRATCH + page as u64 * 8 + 4)
                    != (address >> 32) as u32 | (1 << 31)
            {
                return TestResult::Fail("scratch PTE mismatch");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", ring_layout_programmed_on_prepare);

    fn counter_pointer_accounting() -> TestResult {
        let (mut engine, regs, _) = started_engine();
        if engine.pointer() != 0 {
            return TestResult::Fail("pointer must start at 0");
        }
        regs.set_counter(8192);
        if engine.pointer() != 2048 {
            return TestResult::Fail("pointer must be 8192 bytes / 4 = 2048 frames");
        }
        regs.set_counter(8192 + 4096);
        if engine.pointer() != 3072 {
            return TestResult::Fail("pointer must track the counter monotonically");
        }
        // 64-bit counter composition across the 32-bit boundary. A
        // 4 GiB jump past a 16 KiB ring is also an overrun (the
        // stream xrun-stops), but the composed pointer value itself
        // must still be hi/lo-correct.
        regs.set_counter(0x1_0000_0000);
        if engine.pointer() != 0x4000_0000 {
            return TestResult::Fail("pointer must compose hi/lo counter words");
        }
        if !engine.ring.as_ref().unwrap().xrun {
            return TestResult::Fail("giant counter jump must latch overrun");
        }
        // A stopped stream keeps its last position (update no-ops).
        if engine.stop() != Ok(()) {
            return TestResult::Fail("stop failed");
        }
        if engine.pointer() != 0x4000_0000 {
            return TestResult::Fail("stopped pointer must retain position");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", counter_pointer_accounting);

    fn playback_write_queues_and_caps() -> TestResult {
        let (mut engine, _, _) = started_engine();
        // Frame alignment is enforced by the ring.
        if engine.write(&[0u8; 3]) != Err(SoundError::InvalidParams) {
            return TestResult::Fail("unaligned write must be rejected");
        }
        let pattern: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        if engine.write(&pattern) != Ok(4096) {
            return TestResult::Fail("first period write must take all 4096 bytes");
        }
        // Ring holds 16384; 4096 queued, so a 16384-byte write caps
        // at the 12288 free bytes.
        if engine.write(&[0xAAu8; 16384]) != Ok(12288) {
            return TestResult::Fail("write must cap at free ring space");
        }
        // Queued bytes land in the ring in order, starting at 0.
        let ring = engine.ring.as_ref().unwrap();
        let mut head = [0u8; 16];
        for (i, byte) in head.iter_mut().enumerate() {
            // SAFETY: Fixture owns the ring; index is within the first
            // period, far below the 16 KiB ring size.
            *byte = unsafe { *ring.data.cpu_ptr::<u8>().add(i) };
        }
        if head != pattern[..16] {
            return TestResult::Fail("queued bytes mismatch at ring head");
        }
        if ring.application != 16384 {
            return TestResult::Fail("application must track queued bytes");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", playback_write_queues_and_caps);

    fn capture_read_returns_completed_and_wraps() -> TestResult {
        let (mut engine, regs, _) = started_engine();
        // Simulate DMA filling the first period, then read it back.
        let ring = engine.ring.as_mut().unwrap();
        for i in 0..4096 {
            // SAFETY: Fixture owns the ring; index is within the
            // first period, far below the 16 KiB ring size.
            unsafe {
                ring.data
                    .cpu_mut_ptr::<u8>()
                    .add(i)
                    .write_volatile((i % 251) as u8);
            }
        }
        regs.set_counter(4096);
        let mut out = [0u8; 4096];
        if engine.read(&mut out) != Ok(4096) {
            return TestResult::Fail("read must return the completed period");
        }
        for (i, byte) in out.iter().enumerate() {
            if *byte != (i % 251) as u8 {
                return TestResult::Fail("capture bytes mismatch");
            }
        }
        // Nothing new completed: the next read is empty, not an error.
        if engine.read(&mut out) != Ok(0) {
            return TestResult::Fail("read with no new data must return 0");
        }
        // Advance the application near the ring end, then place a
        // pattern straddling the wrap and read it back in order.
        regs.set_counter(14336);
        let mut drain = [0u8; 10240];
        if engine.read(&mut drain) != Ok(10240) {
            return TestResult::Fail("drain to near ring end failed");
        }
        let pattern: Vec<u8> = (0..4096u32).map(|i| (255 - (i % 251)) as u8).collect();
        {
            let ring = engine.ring.as_mut().unwrap();
            for (i, byte) in pattern.iter().enumerate() {
                let offset = (14336 + i) % 16384;
                // SAFETY: Fixture owns the ring; offset is reduced
                // modulo the 16 KiB ring size, so it is in bounds.
                unsafe {
                    ring.data
                        .cpu_mut_ptr::<u8>()
                        .add(offset)
                        .write_volatile(*byte);
                }
            }
        }
        regs.set_counter(14336 + 4096);
        let mut wrapped = [0u8; 4096];
        if engine.read(&mut wrapped) != Ok(4096) || wrapped != pattern[..] {
            return TestResult::Fail("wrapped capture read mismatch");
        }
        // Overrun: hardware more than a whole ring past the
        // application is an xrun, and the stream stops.
        regs.set_counter(18432 + 16384 + 4);
        if engine.read(&mut [0u8; 4096]) != Err(SoundError::BadState) {
            return TestResult::Fail("overrun must fail the read");
        }
        if !engine.ring.as_ref().unwrap().xrun {
            return TestResult::Fail("overrun must latch xrun");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "audio/acp63-sdw-dma",
        capture_read_returns_completed_and_wraps
    );

    fn failed_stop_retains_stream() -> TestResult {
        let (mut engine, regs, guard) = started_engine();
        regs.set_fail_stop(true);
        if engine.stop() != Err(SoundError::BadState) {
            return TestResult::Fail("armed stop failure must fail the stop");
        }
        // Retention: ring, running state, prepare state, channel
        // claim, and position all survive the failed stop.
        let ring = engine.ring.as_ref().unwrap();
        if !ring.running || !ring.prepared {
            return TestResult::Fail("failed stop must retain running/prepared");
        }
        if !*guard.lock() {
            return TestResult::Fail("failed stop must retain the channel claim");
        }
        regs.set_counter(4096);
        if engine.pointer() != 1024 {
            return TestResult::Fail("retained stream must still report position");
        }
        // Retry with the failure cleared: the stop now succeeds and
        // releases everything.
        regs.set_fail_stop(false);
        if engine.stop() != Ok(()) {
            return TestResult::Fail("stop retry must succeed");
        }
        let ring = engine.ring.as_ref().unwrap();
        if ring.running || ring.prepared {
            return TestResult::Fail("successful stop must clear running/prepared");
        }
        if *guard.lock() {
            return TestResult::Fail("successful stop must release the channel");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", failed_stop_retains_stream);

    fn second_stream_start_busy() -> TestResult {
        let (mut first, regs, guard) = make_engine();
        let mut second = SdwDma::new(regs.clone(), guard.clone());
        for engine in [&mut first, &mut second] {
            if engine.configure(fixed_params()) != Ok(()) || engine.prepare() != Ok(()) {
                return TestResult::Fail("fixture prepare failed");
            }
        }
        if first.start() != Ok(()) {
            return TestResult::Fail("first start must succeed");
        }
        if second.start() != Err(SoundError::DeviceBusy) {
            return TestResult::Fail("second start must fail DeviceBusy");
        }
        if first.stop() != Ok(()) {
            return TestResult::Fail("first stop failed");
        }
        if second.start() != Ok(()) {
            return TestResult::Fail("start after release must succeed");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", second_stream_start_busy);

    fn pause_preserves_queue_and_position() -> TestResult {
        let (mut engine, regs, _) = started_engine();
        if engine.write(&[0x5Au8; 4096]) != Ok(4096) {
            return TestResult::Fail("playback queue failed");
        }
        regs.set_counter(2048);
        if engine.pointer() != 512 {
            return TestResult::Fail("pointer before pause mismatch");
        }
        // Pause shape: stop, then re-mark prepared without
        // reprogramming. Queued samples and position survive.
        if engine.stop() != Ok(()) || engine.mark_prepared() != Ok(()) {
            return TestResult::Fail("pause-shape stop/mark failed");
        }
        let ring = engine.ring.as_ref().unwrap();
        if ring.application != 4096 || ring.hardware != 2048 {
            return TestResult::Fail("pause must retain queue and position");
        }
        if engine.start() != Ok(()) {
            return TestResult::Fail("resume start failed");
        }
        regs.set_counter(4096);
        if engine.pointer() != 1024 {
            return TestResult::Fail("resumed pointer must continue from pause");
        }
        if engine.write(&[0xA5u8; 4096]) != Ok(4096) {
            return TestResult::Fail("post-resume write failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", pause_preserves_queue_and_position);

    fn configure_rejects_bad_geometry() -> TestResult {
        let (mut engine, _, _) = make_engine();
        let mut periods = fixed_params();
        periods.periods = 1;
        if engine.configure(periods) != Err(SoundError::InvalidParams) {
            return TestResult::Fail("periods=1 must be rejected");
        }
        let mut period_size = fixed_params();
        period_size.period_size = 100;
        if engine.configure(period_size) != Err(SoundError::InvalidParams) {
            return TestResult::Fail("unaligned period must be rejected");
        }
        // Configure while running is a BadState (lease must stop
        // first); configure while merely prepared replaces the ring.
        let (mut engine, _, _) = started_engine();
        if engine.configure(fixed_params()) != Err(SoundError::BadState) {
            return TestResult::Fail("configure while running must fail");
        }
        if engine.stop() != Ok(()) || engine.configure(fixed_params()) != Ok(()) {
            return TestResult::Fail("configure after stop must succeed");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", configure_rejects_bad_geometry);
}
