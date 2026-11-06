//! ACP 6.3 SoundWire DMA payload engine (issue #870, register map
//! grounded by #1337): moves PCM samples between host memory and the
//! SDW manager once the port is enabled, implementing
//! [`crate::soundwire::PayloadEngine`] for the generic SDW card's
//! streams.
//!
//! The engine mirrors the in-tree ACP PDM path (`crate::acp63`) for
//! ring/accounting/lifecycle shape only: one
//! [`crate::native_pcm::Ring`] per lease, a hi/lo/hi snapshot
//! hardware counter, wrap/xrun discipline copied from the PDM read
//! path, and failed-stop retention (a stop whose DMA-disable
//! handshake times out keeps the ring, the position, and the channel
//! claim; the caller retries the stop). The register programming is
//! NOT the PDM channel block: Linux programs one DMA channel per SDW
//! stream, and this engine does the same.
//!
//! GROUNDED REGISTER MAP (#1337) — Linux
//! `sound/soc/amd/ps/ps-sdw-dma.c`, `sound/soc/amd/ps/acp63.h`,
//! `include/sound/acp63_chip_offset_byte.h` at torvalds/linux
//! `a91337fb5e8e` (2026-11-06). SDW0 exposes six DMA streams,
//! Linux stream ids 0..=5: TX0/TX1/TX2 (ids 0/1/2) and RX0/RX1/RX2
//! (ids 3/4/5). Each stream owns its own register block: ring-buffer
//! address/size, FIFO address/size, DMA size, interrupt watermark,
//! 64-bit linear position counter (high word at the lower offset,
//! low word above it), and an enable register whose status register
//! sits 4 bytes above it. The per-stream values Linux writes:
//! ring-buffer address `0x4800000 + stream_id * 0x20000`, FIFO
//! address `0x100 + stream_id * 0x100`, DMA size `0x40`, FIFO size
//! `0x100`, watermark = period bytes. Enable writes 1 (start) or 0
//! (stop) and polls the status register until it reads back the
//! written value (`readl_poll_timeout`, 5 us interval, 20000 us
//! timeout); this engine uses the same handshake with the local
//! 100 ms bounded wait. The ATU is group 2, not the PDM path's
//! group 1: base register `0xC0C` gets `0x03800400 | BIT(31)`,
//! page-size register `0xC08` gets `2` (4 KiB pages), PTE pairs
//! land in scratch SRAM at `0x10000 + 0x400 + stream_id * 0x100`
//! (low word, high word | valid bit), and the shared ATU control
//! `0xC40` gets `1` after the PTEs.
//!
//! Consequences of the per-stream model, stated plainly:
//! - Playback and capture leases on one card use different channels
//!   (the card's TX/RX pair) and run concurrently. A second start of
//!   the SAME stream still fails `DeviceBusy`: the per-stream claim
//!   is defense-in-depth against two engines driving one channel
//!   (the card already arbitrates one lease per direction).
//! - The engine is direction-aware at the register level: a playback
//!   lease programs a TX block, a capture lease an RX block. The wire
//!   direction is still the port's job (sink vs source port in the
//!   generic profile); the DMA channel follows the lease direction.
//! - ATU group 2's base/page-size/control registers are shared across
//!   streams, but every stream writes the same values there, so a
//!   second stream's prepare is idempotent against a running first
//!   stream; only the per-stream PTE slice and ring registers differ.
//! - The 0x2c08 block (`ACP_WOV_PDM_DMA_ENABLE`) is the PDM DMA
//!   channel and is never touched here; the #870 engine's reuse of
//!   it for SDW was the error #1337 corrects.
//! - IRQ-driven xrun detection is not wired: position is polled by
//!   `pointer`/`write`/`read` (the 2 ms service timer in the audio
//!   spec §3.3 covers the same polling for the other native paths).
//!   Linux also sets a per-stream bit in `ACP_EXTERNAL_INTR_CNTL`
//!   (`0x1A04`, SDW0) / `CNTL1` (`0x1A08`, SDW1) at hw_params;
//!   wiring that bit needs the ACP external-interrupt routing and a
//!   handler, so it is a follow-up, not part of this lane.
//! - Position counting deviates from Linux in one safe direction:
//!   Linux reads the counter high word once, then the low word;
//!   this engine keeps the PDM path's hi/lo/hi snapshot so a low-word
//!   rollover between the two reads cannot tear the value.
//!
//! REMAINDER (#1337): validate on silicon (Phoenix ACP 6.3,
//! SoundWire-only pin config) — playback and capture each moving
//! real samples through the published SDW card. The register map
//! above is grounded in Linux source; the silicon behaviour of the
//! enable handshake, the ATU group-2 window, and the position
//! counters is still unproven on hardware. SDW1 (two streams,
//! `ACP_P1_AUDIO1_*` registers, window `0x48C0000`) is not bound by
//! NARF and is out of scope here.

use crate::{
    acp63::{ATU_CONTROL, SCRATCH},
    native_pcm::Ring,
    soundwire::{Direction, PayloadEngine, PayloadEngineFactory},
};
use alloc::{boxed::Box, sync::Arc};
use narf_bus::MmioRegion;
use narf_drivers_sound::{format::HwParams, SoundError};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

/// Register access for one SDW DMA stream's block. Production uses
/// [`AcpDmaRegs`] (live BAR); fixtures use the kernel-test fake.
pub trait DmaRegs: Send + Sync + core::fmt::Debug {
    fn read(&self, offset: u64) -> u32;
    fn write(&mut self, offset: u64, value: u32);
}

/// Live ACP BAR access for the SDW DMA stream blocks. The caller owns
/// the ACP function exclusively (probe claimed it and validated the
/// BAR covers the SDW register blocks); offsets are fixed and inside
/// that window.
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

/// One SDW0 DMA stream's register block, verbatim from Linux
/// `include/sound/acp63_chip_offset_byte.h`. The enable register's
/// status register is always 4 bytes above it. Ordered by Linux
/// stream id: TX0, TX1, TX2, RX0, RX1, RX2.
#[derive(Copy, Clone, Debug)]
struct SdwStreamRegs {
    dma_size: u64,
    fifo_addr: u64,
    fifo_size: u64,
    ring_buf_size: u64,
    ring_buf_addr: u64,
    watermark: u64,
    pos_low: u64,
    pos_high: u64,
    enable: u64,
}

/// SDW0 DMA stream count (Linux `ACP63_SDW0_DMA_MAX_STREAMS`).
const SDW0_STREAMS: usize = 6;

const SDW0_STREAM_REGS: [SdwStreamRegs; SDW0_STREAMS] = [
    // TX0 (stream 0).
    SdwStreamRegs {
        dma_size: 0x2038,
        fifo_addr: 0x2030,
        fifo_size: 0x2034,
        ring_buf_size: 0x2028,
        ring_buf_addr: 0x2024,
        watermark: 0x2044,
        pos_low: 0x2040,
        pos_high: 0x203c,
        enable: 0x3010,
    },
    // TX1 (stream 1).
    SdwStreamRegs {
        dma_size: 0x2080,
        fifo_addr: 0x2078,
        fifo_size: 0x207c,
        ring_buf_size: 0x2070,
        ring_buf_addr: 0x206c,
        watermark: 0x208c,
        pos_low: 0x2088,
        pos_high: 0x2084,
        enable: 0x3050,
    },
    // TX2 (stream 2).
    SdwStreamRegs {
        dma_size: 0x20c8,
        fifo_addr: 0x20c0,
        fifo_size: 0x20c4,
        ring_buf_size: 0x20b8,
        ring_buf_addr: 0x20b4,
        watermark: 0x20d4,
        pos_low: 0x20d0,
        pos_high: 0x20cc,
        enable: 0x306c,
    },
    // RX0 (stream 3).
    SdwStreamRegs {
        dma_size: 0x2014,
        fifo_addr: 0x200c,
        fifo_size: 0x2010,
        ring_buf_size: 0x2004,
        ring_buf_addr: 0x2000,
        watermark: 0x2020,
        pos_low: 0x201c,
        pos_high: 0x2018,
        enable: 0x3088,
    },
    // RX1 (stream 4).
    SdwStreamRegs {
        dma_size: 0x205c,
        fifo_addr: 0x2054,
        fifo_size: 0x2058,
        ring_buf_size: 0x204c,
        ring_buf_addr: 0x2048,
        watermark: 0x2068,
        pos_low: 0x2064,
        pos_high: 0x2060,
        enable: 0x3128,
    },
    // RX2 (stream 5).
    SdwStreamRegs {
        dma_size: 0x20a4,
        fifo_addr: 0x209c,
        fifo_size: 0x20a0,
        ring_buf_size: 0x2094,
        ring_buf_addr: 0x2090,
        watermark: 0x20b0,
        pos_low: 0x20ac,
        pos_high: 0x20a8,
        enable: 0x3144,
    },
];

/// ATU group 2 registers (Linux `ACPAXI2AXI_ATU_BASE_ADDR_GRP_2` /
/// `ACPAXI2AXI_ATU_PAGE_SIZE_GRP_2`): the SDW DMA group, distinct
/// from the PDM path's group 1 (`0xC04` / `0xC00`).
const ATU_GRP2_BASE: u64 = 0xc0c;
const ATU_GRP2_PAGE_SIZE: u64 = 0xc08;
/// SDW PTE-table SRAM address (Linux `ACP_SDW_SRAM_PTE_OFFSET`).
const SDW_ATU_PTE_BASE: u32 = 0x03800400;
/// SDW0 DMA window base (Linux `SDW0_MEM_WINDOW_START`).
const SDW_MEM_WINDOW: u32 = 0x4800000;
/// Per-stream ring-buffer stride (Linux
/// `ACP_SDW_RING_BUFF_ADDR_OFFSET`, 128 KiB).
const SDW_RING_STRIDE: u32 = 0x20000;
/// FIFO address base / per-stream stride (Linux
/// `ACP_SDW_FIFO_OFFSET(0)` / `SDW_FIFO_OFFSET`).
const SDW_FIFO_BASE: u32 = 0x100;
const SDW_FIFO_STRIDE: u32 = 0x100;
/// PTE-table scratch offset for SDW0 stream 0 / per-stream stride
/// (Linux `SDW_PTE_OFFSET(0)` / `ACP_SDW_PTE_OFFSET`).
const SDW_PTE_TABLE: u64 = 0x400;
const SDW_PTE_STRIDE: u64 = 0x100;
/// Values Linux writes to every stream's DMA-size / FIFO-size
/// registers (`SDW_DMA_SIZE` / `SDW_FIFO_SIZE`).
const SDW_DMA_SIZE: u32 = 0x40;
const SDW_FIFO_SIZE: u32 = 0x100;

/// Exclusive end of the scratch-SRAM region the engine can write:
/// the last stream's PTE slice plus the largest ring `Ring::new`
/// accepts (256 KiB = 64 pages, 8 bytes per PTE pair). The probe
/// validates the BAR covers this before binding, so every
/// `MmioRegion` access in `prepare` stays in-range.
pub(crate) const SDW_PTE_TABLE_END: u64 =
    SCRATCH + SDW_PTE_TABLE + (SDW0_STREAMS as u64 - 1) * SDW_PTE_STRIDE + 64 * 8;

/// ACP SDW DMA engine: one ring, one stream channel, PDM-mirrored
/// lifecycle. `R` is the register block; production uses
/// [`AcpDmaRegs`], fixtures use the kernel-test fake. `stream` is
/// the Linux SDW0 stream id (0..=5); `claims` is the factory's
/// per-stream claim set, shared by every engine the factory builds.
#[derive(Debug)]
pub struct SdwDma<R: DmaRegs> {
    regs: R,
    stream: u8,
    claims: Arc<IrqSafeSpinLock<[bool; SDW0_STREAMS]>>,
    ring: Option<Ring>,
    /// Hardware counter value at the last start: the logical position
    /// survives PAUSE/RESUME while prepare resets hardware to zero.
    baseline: u64,
}

fn wait(predicate: impl FnMut() -> bool) -> bool {
    narf_scheduler::responsive_spin_until(predicate, Deadline::after_ms(100))
}

impl<R: DmaRegs> SdwDma<R> {
    pub fn new(regs: R, stream: u8, claims: Arc<IrqSafeSpinLock<[bool; SDW0_STREAMS]>>) -> Self {
        debug_assert!((stream as usize) < SDW0_STREAMS);
        Self {
            regs,
            stream,
            claims,
            ring: None,
            baseline: 0,
        }
    }

    fn stream_regs(&self) -> SdwStreamRegs {
        SDW0_STREAM_REGS[self.stream as usize]
    }

    fn count(&self) -> Result<u64, SoundError> {
        // Counter can roll over between reads; bounded high/low/high
        // snapshot (acp63). Linux reads high once then low; the extra
        // high read only hardens the snapshot, it changes no value.
        let regs = self.stream_regs();
        for _ in 0..4 {
            let hi = self.regs.read(regs.pos_high);
            let lo = self.regs.read(regs.pos_low);
            let again = self.regs.read(regs.pos_high);
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
        let regs = self.stream_regs();
        // ATU group 2 (SDW), Linux `acp63_config_dma`: base and
        // page size, then this stream's PTE slice in scratch SRAM
        // (PTE pairs per 4 KiB page: low word = address low, high
        // word = address high | valid bit), then the shared ATU
        // control. A CPU virtual address must never be programmed
        // here (acp63). The group-2 base/page-size/control values
        // are identical for every stream, so a second stream's
        // prepare is idempotent against a running first stream.
        self.regs.write(ATU_GRP2_BASE, SDW_ATU_PTE_BASE | (1 << 31));
        self.regs.write(ATU_GRP2_PAGE_SIZE, 2);
        let pte = SCRATCH + SDW_PTE_TABLE + self.stream as u64 * SDW_PTE_STRIDE;
        for page in 0..ring.bytes.div_ceil(4096) {
            let address = ring.data.dma_addr_at((page * 4096) as u64).raw();
            self.regs.write(pte + page as u64 * 8, address as u32);
            self.regs.write(
                pte + page as u64 * 8 + 4,
                (address >> 32) as u32 | (1 << 31),
            );
        }
        self.regs.write(ATU_CONTROL, 1);
        // Per-stream ring buffer, Linux
        // `acp63_configure_sdw_ringbuffer`: size, address (this
        // stream's 128 KiB slice of the SDW0 DMA window), FIFO
        // address, DMA/FIFO sizes, then the watermark (period
        // bytes, as Linux writes it in hw_params).
        self.regs.write(regs.ring_buf_size, ring.bytes as u32);
        self.regs.write(
            regs.ring_buf_addr,
            SDW_MEM_WINDOW + self.stream as u32 * SDW_RING_STRIDE,
        );
        self.regs.write(
            regs.fifo_addr,
            SDW_FIFO_BASE + self.stream as u32 * SDW_FIFO_STRIDE,
        );
        self.regs.write(regs.dma_size, SDW_DMA_SIZE);
        self.regs.write(regs.fifo_size, SDW_FIFO_SIZE);
        self.regs
            .write(regs.watermark, ring.params.period_bytes() as u32);
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
            let mut claims = self.claims.lock();
            if claims[self.stream as usize] {
                return Err(SoundError::DeviceBusy);
            }
            claims[self.stream as usize] = true;
        }
        self.baseline = baseline;
        // Per-stream enable, Linux `acp63_sdw_dma_enable`: write 1
        // and poll the status register (enable + 4) until it reads
        // back 1.
        let regs = self.stream_regs();
        self.regs.write(regs.enable, 1);
        // Set before polling: even a timed-out start may have begun DMA.
        self.ring.as_mut().unwrap().running = true;
        if !wait(|| self.regs.read(regs.enable + 4) == 1) {
            let _ = self.stop();
            return Err(SoundError::BadState);
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), SoundError> {
        let regs = self.stream_regs();
        if self.regs.read(regs.enable + 4) != 0 {
            self.regs.write(regs.enable, 0);
        }
        if !wait(|| self.regs.read(regs.enable + 4) == 0) {
            // Failed-stop retention: ring, position, and channel claim
            // are all retained; the caller must retry the stop.
            return Err(SoundError::BadState);
        }
        if let Some(ring) = self.ring.as_mut() {
            ring.running = false;
            ring.prepared = false;
        }
        self.claims.lock()[self.stream as usize] = false;
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
        self.claims.lock()[self.stream as usize] = false;
        false
    }
}

/// Production payload-engine factory for one ACP SDW card: every
/// engine it builds programs the same function BAR. The card's
/// channel pair is fixed at bind time (`pair` 0..=2): playback uses
/// TX`pair` (Linux stream id `pair`), capture uses RX`pair` (stream
/// id `pair + 3`). The per-stream claim set is shared by every
/// engine this factory builds, so two engines for the same stream
/// can never drive one channel concurrently.
#[derive(Debug)]
pub struct AcpSdwDmaFactory {
    mmio: MmioRegion,
    tx: u8,
    rx: u8,
    claims: Arc<IrqSafeSpinLock<[bool; SDW0_STREAMS]>>,
}

impl AcpSdwDmaFactory {
    pub fn new(mmio: MmioRegion, pair: u8) -> Self {
        debug_assert!(pair < 3, "SDW0 has three TX/RX channel pairs");
        Self {
            mmio,
            tx: pair,
            rx: pair + 3,
            claims: Arc::new(IrqSafeSpinLock::new([false; SDW0_STREAMS])),
        }
    }
}

impl PayloadEngineFactory for AcpSdwDmaFactory {
    fn create(&self, direction: Direction) -> Box<dyn PayloadEngine> {
        let stream = match direction {
            Direction::Playback => self.tx,
            Direction::Capture => self.rx,
        };
        Box::new(SdwDma::new(
            AcpDmaRegs { mmio: self.mmio },
            stream,
            self.claims.clone(),
        ))
    }
}

#[cfg(feature = "kernel-test")]
use alloc::collections::BTreeMap;

/// Modelled per-stream DMA register blocks for fixtures: a register
/// map plus the per-stream enable handshake (an EN write of 1/0
/// sets the stream's EN_STATUS register to the same value, unless a
/// stop failure is armed, in which case a 0-write leaves the status
/// at 1) and scriptable 64-bit hardware counters, one per stream.
/// Shared by handle so tests can drive the hardware while the engine
/// owns its copy.
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
    /// snapshot reads for one stream.
    pub(crate) fn set_counter(&self, stream: u8, bytes: u64) {
        let regs = SDW0_STREAM_REGS[stream as usize];
        let mut inner = self.inner.lock();
        inner.regs.insert(regs.pos_high, (bytes >> 32) as u32);
        inner.regs.insert(regs.pos_low, bytes as u32);
    }

    /// Arm (or clear) the stop-failure mode: with it armed, a
    /// stream's enable 0-write never clears its status register, so
    /// the engine's stop handshake times out.
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
        for regs in SDW0_STREAM_REGS {
            if offset == regs.enable {
                inner.regs.insert(offset, value);
                // A stop write never clears the running status while
                // a stop failure is armed.
                if !(value == 0 && inner.fail_stop) {
                    inner.regs.insert(offset + 4, value);
                }
                return;
            }
        }
        inner.regs.insert(offset, value);
    }
}

/// Fixture factory building [`SdwDma`] engines over one shared
/// [`FakeRegs`] block and one shared per-stream claim set, so
/// lease-level tests (in `crate::soundwire`) can drive the same
/// hardware the engine programs. `pair` is the card's channel pair,
/// as in [`AcpSdwDmaFactory::new`].
#[cfg(feature = "kernel-test")]
#[derive(Debug)]
pub(crate) struct FakeDmaFactory {
    regs: FakeRegs,
    tx: u8,
    rx: u8,
    claims: Arc<IrqSafeSpinLock<[bool; SDW0_STREAMS]>>,
}

#[cfg(feature = "kernel-test")]
impl FakeDmaFactory {
    pub(crate) fn new(regs: FakeRegs, pair: u8) -> Self {
        debug_assert!(pair < 3, "SDW0 has three TX/RX channel pairs");
        Self {
            regs,
            tx: pair,
            rx: pair + 3,
            claims: Arc::new(IrqSafeSpinLock::new([false; SDW0_STREAMS])),
        }
    }
}

#[cfg(feature = "kernel-test")]
impl PayloadEngineFactory for FakeDmaFactory {
    fn create(&self, direction: Direction) -> Box<dyn PayloadEngine> {
        let stream = match direction {
            Direction::Playback => self.tx,
            Direction::Capture => self.rx,
        };
        Box::new(SdwDma::new(self.regs.clone(), stream, self.claims.clone()))
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

    /// One engine plus its fake block and per-stream claim set. The
    /// ring is 4 periods x 1024 frames x 4 bytes = 16 KiB; one period
    /// is 4096 bytes.
    fn make_engine(
        stream: u8,
    ) -> (
        SdwDma<FakeRegs>,
        FakeRegs,
        Arc<IrqSafeSpinLock<[bool; SDW0_STREAMS]>>,
    ) {
        let regs = FakeRegs::new();
        let claims = Arc::new(IrqSafeSpinLock::new([false; SDW0_STREAMS]));
        (
            SdwDma::new(regs.clone(), stream, claims.clone()),
            regs,
            claims,
        )
    }

    fn started_engine(
        stream: u8,
    ) -> (
        SdwDma<FakeRegs>,
        FakeRegs,
        Arc<IrqSafeSpinLock<[bool; SDW0_STREAMS]>>,
    ) {
        let (mut engine, regs, claims) = make_engine(stream);
        if engine.configure(fixed_params()).is_err()
            || engine.prepare().is_err()
            || engine.start().is_err()
        {
            panic!("fixture engine failed to start");
        }
        (engine, regs, claims)
    }

    /// Pin one stream's prepare programming: ATU group 2, this
    /// stream's PTE slice, ring address/size, FIFO address/size,
    /// DMA size, watermark — and assert the PDM channel block
    /// (0x2c08) was never touched.
    fn assert_layout(stream: u8, ring_addr: u32, fifo_addr: u32, pte_base: u64) -> TestResult {
        let (mut engine, regs, _) = make_engine(stream);
        if engine.configure(fixed_params()) != Ok(()) {
            return TestResult::Fail("configure failed");
        }
        if engine.prepare() != Ok(()) {
            return TestResult::Fail("prepare failed");
        }
        let r = SDW0_STREAM_REGS[stream as usize];
        if regs.read_reg(ATU_GRP2_BASE) != SDW_ATU_PTE_BASE | (1 << 31)
            || regs.read_reg(ATU_GRP2_PAGE_SIZE) != 2
            || regs.read_reg(r.ring_buf_addr) != ring_addr
            || regs.read_reg(r.ring_buf_size) != 16384
            || regs.read_reg(r.fifo_addr) != fifo_addr
            || regs.read_reg(r.fifo_size) != SDW_FIFO_SIZE
            || regs.read_reg(r.dma_size) != SDW_DMA_SIZE
            || regs.read_reg(r.watermark) != 4096
            || regs.read_reg(ATU_CONTROL) != 1
        {
            return TestResult::Fail("per-stream ring/ATU programming mismatch");
        }
        // One PTE pair per 4 KiB page, from the ring's own DMA
        // addresses (low word, high word | valid bit), in this
        // stream's PTE slice.
        let ring = engine.ring.as_ref().unwrap();
        for page in 0..4 {
            let address = ring.data.dma_addr_at((page * 4096) as u64).raw();
            if regs.read_reg(pte_base + page as u64 * 8) != address as u32
                || regs.read_reg(pte_base + page as u64 * 8 + 4)
                    != (address >> 32) as u32 | (1 << 31)
            {
                return TestResult::Fail("scratch PTE mismatch");
            }
        }
        // The PDM channel block must stay untouched: the SDW engine
        // programs per-stream registers, never 0x2c08.
        if regs.read_reg(0x2c08) != 0 || regs.read_reg(0x2c0c) != 0 || regs.read_reg(0x2c10) != 0 {
            return TestResult::Fail("PDM channel block must not be programmed");
        }
        TestResult::Pass
    }

    fn ring_layout_programmed_on_prepare_tx0() -> TestResult {
        // TX0 (stream 0): ring window 0x4800000, FIFO 0x100, PTEs
        // at scratch + 0x400.
        assert_layout(0, 0x4800000, 0x100, SCRATCH + 0x400)
    }
    kernel_test_in!("audio/acp63-sdw-dma", ring_layout_programmed_on_prepare_tx0);

    fn ring_layout_programmed_on_prepare_rx0() -> TestResult {
        // RX0 (stream 3): ring window 0x4800000 + 3*0x20000,
        // FIFO 0x100 + 3*0x100, PTEs at scratch + 0x400 + 3*0x100.
        assert_layout(3, 0x4860000, 0x400, SCRATCH + 0x700)
    }
    kernel_test_in!("audio/acp63-sdw-dma", ring_layout_programmed_on_prepare_rx0);

    fn counter_pointer_accounting() -> TestResult {
        let (mut engine, regs, _) = started_engine(0);
        if engine.pointer() != 0 {
            return TestResult::Fail("pointer must start at 0");
        }
        regs.set_counter(0, 8192);
        if engine.pointer() != 2048 {
            return TestResult::Fail("pointer must be 8192 bytes / 4 = 2048 frames");
        }
        regs.set_counter(0, 8192 + 4096);
        if engine.pointer() != 3072 {
            return TestResult::Fail("pointer must track the counter monotonically");
        }
        // 64-bit counter composition across the 32-bit boundary. A
        // 4 GiB jump past a 16 KiB ring is also an overrun (the
        // stream xrun-stops), but the composed pointer value itself
        // must still be hi/lo-correct.
        regs.set_counter(0, 0x1_0000_0000);
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
        let (mut engine, _, _) = started_engine(0);
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
        let (mut engine, regs, _) = started_engine(3);
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
        regs.set_counter(3, 4096);
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
        regs.set_counter(3, 14336);
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
        regs.set_counter(3, 14336 + 4096);
        let mut wrapped = [0u8; 4096];
        if engine.read(&mut wrapped) != Ok(4096) || wrapped != pattern[..] {
            return TestResult::Fail("wrapped capture read mismatch");
        }
        // Overrun: hardware more than a whole ring past the
        // application is an xrun, and the stream stops.
        regs.set_counter(3, 18432 + 16384 + 4);
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
        let (mut engine, regs, claims) = started_engine(0);
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
        if !claims.lock()[0] {
            return TestResult::Fail("failed stop must retain the channel claim");
        }
        regs.set_counter(0, 4096);
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
        if claims.lock()[0] {
            return TestResult::Fail("successful stop must release the channel");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", failed_stop_retains_stream);

    fn concurrent_playback_and_capture_start() -> TestResult {
        // The per-stream model lifts the single-channel limit: a TX
        // stream and an RX stream run concurrently, each on its own
        // channel with its own counter.
        let regs = FakeRegs::new();
        let claims = Arc::new(IrqSafeSpinLock::new([false; SDW0_STREAMS]));
        let mut playback = SdwDma::new(regs.clone(), 0, claims.clone());
        let mut capture = SdwDma::new(regs.clone(), 3, claims.clone());
        for engine in [&mut playback, &mut capture] {
            if engine.configure(fixed_params()) != Ok(()) || engine.prepare() != Ok(()) {
                return TestResult::Fail("fixture prepare failed");
            }
        }
        if playback.start() != Ok(()) {
            return TestResult::Fail("playback start must succeed");
        }
        if capture.start() != Ok(()) {
            return TestResult::Fail("capture start must succeed while playback runs");
        }
        // Independent counters: advancing one stream's counter must
        // not move the other's pointer.
        regs.set_counter(0, 4096);
        regs.set_counter(3, 8192);
        if playback.pointer() != 1024 {
            return TestResult::Fail("playback pointer must track its own counter");
        }
        if capture.pointer() != 2048 {
            return TestResult::Fail("capture pointer must track its own counter");
        }
        if playback.stop() != Ok(()) || capture.stop() != Ok(()) {
            return TestResult::Fail("concurrent stop failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", concurrent_playback_and_capture_start);

    fn same_stream_second_start_busy() -> TestResult {
        // Two engines for the SAME stream still arbitrate: the
        // per-stream claim is defense-in-depth against two drivers
        // of one channel (the card already arbitrates one lease per
        // direction).
        let regs = FakeRegs::new();
        let claims = Arc::new(IrqSafeSpinLock::new([false; SDW0_STREAMS]));
        let mut first = SdwDma::new(regs.clone(), 0, claims.clone());
        let mut second = SdwDma::new(regs.clone(), 0, claims.clone());
        for engine in [&mut first, &mut second] {
            if engine.configure(fixed_params()) != Ok(()) || engine.prepare() != Ok(()) {
                return TestResult::Fail("fixture prepare failed");
            }
        }
        if first.start() != Ok(()) {
            return TestResult::Fail("first start must succeed");
        }
        if second.start() != Err(SoundError::DeviceBusy) {
            return TestResult::Fail("second start of the same stream must fail DeviceBusy");
        }
        if first.stop() != Ok(()) {
            return TestResult::Fail("first stop failed");
        }
        if second.start() != Ok(()) {
            return TestResult::Fail("start after release must succeed");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63-sdw-dma", same_stream_second_start_busy);

    fn pause_preserves_queue_and_position() -> TestResult {
        let (mut engine, regs, _) = started_engine(0);
        if engine.write(&[0x5Au8; 4096]) != Ok(4096) {
            return TestResult::Fail("playback queue failed");
        }
        regs.set_counter(0, 2048);
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
        regs.set_counter(0, 4096);
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
        let (mut engine, _, _) = make_engine(0);
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
        let (mut engine, _, _) = started_engine(0);
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
