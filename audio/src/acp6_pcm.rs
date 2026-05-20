//! AMD ACP I2S0 TX passthrough DMA — playback path.
//!
//! Programs the ACP I2S0 TX engine to stream S16LE 48 kHz stereo
//! PCM from a kernel-side ring buffer to the off-die codec. The
//! ACP DSP is not used in this path — the I2S TX engine + DMA are
//! standalone bus-master units (Renoir / Cezanne PPR §13.7).
//!
//! ## References (all GPL-2.0-or-later, freely citable as of
//! 2026-05-20 — see top-level licence note)
//!
//! - Linux `sound/soc/amd/raven/acp3x-pcm-dma.c`:
//!     * `acp3x_dma_open()` (~lines 145-185) — ring + FIFO alloc
//!     * `acp3x_dma_hw_params()` (~lines 220-260) — register
//!       programming sequence (RINGBUFADDR → RINGBUFSIZE →
//!       FIFOADDR → FIFOSIZE → DMA_SIZE → IER)
//!     * `acp3x_dma_trigger()` (~lines 270-305) — start/stop
//!       via `ACP_BTTDM_ITER` link enable
//! - Linux `sound/soc/amd/renoir/acp3x.c`:
//!     * `acp3x_dai_i2s_hwparams()` (~lines 110-145) — frame
//!       format / word length encoding in `ACP_BTTDM_TXFRMT`
//!     * `acp3x_dai_set_clkdiv()` (~lines 75-100) — BCLK divider
//!       in `ACP_I2S_AUDIO_CLK_DIV`
//! - Linux `sound/soc/amd/acp/acp-mach.c` — version-multiplex
//!   table; confirms the I2S TX register block is at the same
//!   `0x1242` base on ACP3 → ACP6.
//!
//! ## Operating envelope
//!
//! - **Format**: S16LE, 48 kHz, stereo (matches HDA + virtio-sound
//!   defaults; lib.rs::AudioFormat::default_playback())
//! - **Ring**: one 4 KiB page = 1024 frames = 21.33 ms
//! - **FIFO**: 512 bytes in ACP scratch RAM
//! - **Wedge thresholds**: 100 ms on ITER enable ack (typical
//!   sub-millisecond per Renoir PPR §13.7.4)
//!
//! Capture / microphone is out of scope this round.

extern crate alloc;

use core::sync::atomic::{compiler_fence, Ordering};

use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::acp6::{regs, with_controller_mut, AcpDevice};

/// One I2S0 TX session — owns the ring buffer + its phys address.
/// Lives in the `STREAM` singleton; a fresh prepare cycles the
/// buffer.
struct I2sTxStream {
    /// Holds the page alive — drop frees the DMA region. Accessed
    /// via `ring_phys` for the volatile writes since the engine
    /// reads phys, not the kernel view.
    _ring: DmaBuffer,
    ring_phys: u64,
    /// Bytes the engine sees as one wraparound — `ring.len()`.
    cyclic_bytes: u32,
    /// `true` once `ACP_BTTDM_ITER.ENABLE` has been set.
    running: bool,
}

impl core::fmt::Debug for I2sTxStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("I2sTxStream")
            .field("ring_phys", &format_args!("{:#x}", self.ring_phys))
            .field("cyclic_bytes", &self.cyclic_bytes)
            .field("running", &self.running)
            .finish()
    }
}

static STREAM: IrqSafeSpinLock<Option<I2sTxStream>> = IrqSafeSpinLock::new(None);

/// Errors produced by the I2S TX path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PcmError {
    /// No ACP controller is probed.
    NoController,
    /// Ring buffer allocation failed.
    DmaAllocFailed,
    /// `play_pcm` called with no samples / wrong length.
    BadBuffer,
    /// I2S TX engine never asserted RUN within the spin budget.
    StartTimeout,
    /// `stop_pcm` couldn't pull the engine out of RUN.
    StopTimeout,
}

/// PCM frame format the I2S0 TX engine is programmed for.
/// Stage-6 baseline only; multi-format negotiation is a follow-up.
const SAMPLE_RATE_HZ: u32 = 48_000;
const CHANNELS: u32 = 2;
const BITS_PER_SAMPLE: u32 = 16;

/// Bytes per PCM frame (one sample per channel).
pub const BYTES_PER_FRAME: u32 = (CHANNELS * BITS_PER_SAMPLE) / 8;

/// ACP scratch RAM offset where the I2S0 TX FIFO lives.
const FIFO_SCRATCH_OFFSET: u32 = regs::I2STX_FIFO_SCRATCH_OFFSET;
const FIFO_BYTES: u32 = regs::I2STX_FIFO_BYTES;
const RING_BYTES: u32 = regs::I2STX_RING_BYTES;

/// Encode `(channels, slot bits, word length)` into the
/// `ACP_BTTDM_TXFRMT` register. Matches Linux's
/// `acp3x_dai_i2s_hwparams()` packing:
///
/// ```text
/// bits[0:1]  channels (0=1ch, 1=2ch, 2=4ch, 3=8ch)
/// bits[2:4]  slot bits encoding (0=16, 1=20, 2=24, 3=32)
/// bits[5:8]  word length (16/20/24/32 minus 1)
/// ```
fn frame_format(channels: u32, word_len: u32) -> u32 {
    let ch_code = match channels {
        1 => 0,
        2 => 1,
        4 => 2,
        _ => 3,
    };
    let slot_code = match word_len {
        16 => 0,
        20 => 1,
        24 => 2,
        _ => 3,
    };
    ch_code | (slot_code << 2) | ((word_len - 1) << 5)
}

/// Prepare the I2S0 TX engine for playback: allocate the ring,
/// program the DMA registers, set the BCLK divider for 48 kHz / 16-bit
/// stereo, but leave the link engine *off* (`ACP_BTTDM_ITER.ENABLE`
/// cleared). `play_pcm` flips that bit.
///
/// Idempotent — calling twice tears down the previous stream first.
pub fn prepare_i2s0_tx() -> Result<(), PcmError> {
    // Tear down any previous stream so the ring buffer's Drop runs.
    let _ = stop_pcm();
    *STREAM.lock() = None;

    let result = with_controller_mut(|dev| -> Result<(), PcmError> {
        let ring = alloc_coherent(RING_BYTES as usize, DomainId::DRIVER_0)
            .map_err(|_| PcmError::DmaAllocFailed)?;
        let ring_phys = ring.phys_addr().raw();

        // Zero the ring so a partial buffer doesn't leak stale data
        // onto the wire if the engine wraps before `play_pcm` writes.
        // SAFETY: identity-mapped DMA page, `ring.len()` bytes.
        unsafe {
            core::ptr::write_bytes(ring_phys as *mut u8, 0, RING_BYTES as usize);
        }

        program_dma_registers(dev, ring_phys, RING_BYTES);
        program_i2s_frame(dev);
        program_bclk_divider(dev, SAMPLE_RATE_HZ);

        dev.i2s_tx_prepared = true;
        *STREAM.lock() = Some(I2sTxStream {
            _ring: ring,
            ring_phys,
            cyclic_bytes: RING_BYTES,
            running: false,
        });
        Ok(())
    });
    match result {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(e),
        None => Err(PcmError::NoController),
    }
}

/// Write the DMA + FIFO registers from `acp3x_dma_hw_params()`.
///
/// Reference: Linux `sound/soc/amd/raven/acp3x-pcm-dma.c`,
/// `acp3x_dma_hw_params()` ~lines 220-260. ACP6 reuses the same
/// offsets — confirmed by `sound/soc/amd/acp/acp-pci.c` version
/// multiplex.
fn program_dma_registers(dev: &AcpDevice, ring_phys: u64, ring_bytes: u32) {
    // SAFETY: BAR0 mapped + exclusively owned by the singleton
    // ACP controller for its lifetime.
    unsafe {
        // Ring buffer base — phys. Linux writes low then high; the
        // engine latches on the size write.
        dev.mmio
            .write32(regs::ACP_I2STX_RINGBUFADDR, ring_phys as u32);
        // High word — the BAR0 register file is 32-bit, the ring
        // address is single-word on ACP3 but ACP6 broadens to 64-bit
        // via a follow-on offset. The Renoir PPR §13.7.3 table
        // documents the high word at +0x18 of the I2S TX block,
        // but the actively-used Linux driver only programs the low
        // 32 bits for buffers < 4 GiB (ours are page-allocated, so
        // we follow suit — guarantees the upper bits are 0).
        debug_assert!(ring_phys < 0x1_0000_0000, "ring_phys must fit u32");
        dev.mmio.write32(regs::ACP_I2STX_RINGBUFSIZE, ring_bytes);

        // FIFO lives in the ACP's scratch SRAM; the engine reads
        // from the ring and pushes here for the I2S serialiser to
        // drain onto the wire.
        dev.mmio
            .write32(regs::ACP_I2STX_FIFOADDR, FIFO_SCRATCH_OFFSET);
        dev.mmio.write32(regs::ACP_I2STX_FIFOSIZE, FIFO_BYTES);

        // DMA burst size — one frame (4 bytes for S16LE stereo) per
        // pull. Linux uses `ACP_I2S_BURST_SIZE = 0x4` here.
        dev.mmio.write32(regs::ACP_I2STX_DMA_SIZE, BYTES_PER_FRAME);

        // Watermark — the engine fires `EXTINTR_I2STX_DMA_DONE`
        // every time it reads this many bytes. We set it to half
        // the ring so a single buffer's playback raises exactly
        // one IRQ (half-buffer + wrap). Mirrors Linux's
        // `period_bytes / 2` convention.
        dev.mmio
            .write32(regs::ACP_I2STX_INTR_WATERMARK_SIZE, ring_bytes / 2);

        // Linear position counter starts at 0; explicitly clear
        // so `output_position()` is meaningful from the first read.
        dev.mmio.write32(regs::ACP_I2STX_LINEARPOSITION_CNTR_LOW, 0);
        dev.mmio.write32(regs::ACP_I2STX_LINEARPOSITION_CNTR_HIGH, 0);
    }
    compiler_fence(Ordering::SeqCst);
}

/// Program `ACP_BTTDM_TXFRMT` + arm the TX path. The link enable
/// bit in `ACP_BTTDM_ITER` is *not* asserted here — `play_pcm`
/// does that once the ring is filled.
fn program_i2s_frame(dev: &AcpDevice) {
    let frmt = frame_format(CHANNELS, BITS_PER_SAMPLE);
    // SAFETY: BAR0 mapped, exclusive owner.
    unsafe {
        dev.mmio.write32(regs::ACP_BTTDM_TXFRMT, frmt);
        // Arm the TX interrupt enable (does not start the link —
        // that's `ACP_BTTDM_ITER`).
        dev.mmio
            .write32(regs::ACP_BTTDM_IER, regs::TDM_TX_ENABLE);
        // Enable the controller-side DMA-complete interrupt source.
        let cur = dev.mmio.read32(regs::ACP_EXTERNAL_INTR_ENB);
        dev.mmio.write32(
            regs::ACP_EXTERNAL_INTR_ENB,
            cur | regs::EXTINTR_I2STX_DMA_DONE,
        );
    }
}

/// Program the I2S BCLK divider for the requested sample rate.
///
/// The ACP I2S reference clock is 25 MHz (Renoir PPR §13.2). BCLK
/// = sample_rate × channels × bits_per_sample = 48 000 × 2 × 16 =
/// 1.536 MHz, so the divider is `25_000_000 / 1_536_000 = 16` (rounds
/// to the nearest integer — Linux `acp3x_dai_set_clkdiv()` does the
/// same rounding).
fn program_bclk_divider(dev: &AcpDevice, sample_rate_hz: u32) {
    let bclk_hz = sample_rate_hz * CHANNELS * BITS_PER_SAMPLE;
    let div = (25_000_000u32 + bclk_hz / 2) / bclk_hz;
    // SAFETY: BAR0 mapped, exclusive owner.
    unsafe {
        dev.mmio.write32(regs::ACP_I2S_AUDIO_CLK_DIV, div);
    }
}

/// Submit one buffer of i16 PCM samples + start playback. Blocks
/// until the engine acknowledges RUN, then returns — the caller
/// polls completion via `output_position()` or `is_done()`.
///
/// `samples.len()` must be a non-zero multiple of `CHANNELS` and
/// not exceed `period_samples()`.
///
/// The ring is cyclic — if the buffer is shorter than the ring,
/// the tail is left at its previous contents (zeroed at prepare).
pub fn play_pcm(samples: &[i16]) -> Result<usize, PcmError> {
    if samples.is_empty() || (samples.len() % CHANNELS as usize) != 0 {
        return Err(PcmError::BadBuffer);
    }
    let n = samples.len().min(period_samples());

    let mut guard = STREAM.lock();
    let stream = guard.as_mut().ok_or(PcmError::NoController)?;

    // Copy samples into the ring. The ring is identity-mapped DMA
    // memory — volatile writes guarantee the device sees them in
    // order. Same shape as `hda::load_period`.
    let ring_phys = stream.ring_phys;
    // SAFETY: identity-mapped DMA page; n × 2 ≤ ring.len().
    unsafe {
        for i in 0..n {
            core::ptr::write_volatile((ring_phys + (i * 2) as u64) as *mut i16, samples[i]);
        }
        // Zero the tail so a short buffer doesn't replay stale
        // samples from a previous load.
        for i in n..period_samples() {
            core::ptr::write_volatile((ring_phys + (i * 2) as u64) as *mut i16, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);

    if !stream.running {
        let ok = with_controller_mut(|dev| -> bool {
            // SAFETY: BAR0 mapped, exclusive owner.
            unsafe {
                // Set ITER link enable — the engine begins fetching
                // ring entries and pushing to the FIFO.
                dev.mmio
                    .write32(regs::ACP_BTTDM_ITER, regs::TDM_ITER_ENABLE);
            }
            // Wait for the engine to ack ITER.ENABLE. responsive_spin_until
            // ticks sleep_pumps so cursor/FB/serial stay alive across
            // the ack window. 100 ms wedge threshold (typical sub-ms
            // per Renoir PPR §13.7.4).
            narf_scheduler::responsive_spin_until(
                // SAFETY: same.
                || unsafe { dev.mmio.read32(regs::ACP_BTTDM_ITER) } & regs::TDM_ITER_ENABLE != 0,
                narf_time::Deadline::after_ms(100),
            )
        })
        .ok_or(PcmError::NoController)?;
        if !ok {
            return Err(PcmError::StartTimeout);
        }
        stream.running = true;
    }
    Ok(n)
}

/// Stop the engine: clear `ACP_BTTDM_ITER.ENABLE` and wait for
/// the controller to acknowledge. Idempotent.
pub fn stop_pcm() -> Result<(), PcmError> {
    let mut guard = STREAM.lock();
    let stream = match guard.as_mut() {
        Some(s) => s,
        None => return Ok(()),
    };
    if !stream.running {
        return Ok(());
    }
    let ok = with_controller_mut(|dev| -> bool {
        // SAFETY: BAR0 mapped, exclusive owner.
        unsafe {
            dev.mmio.write32(regs::ACP_BTTDM_ITER, 0);
        }
        narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { dev.mmio.read32(regs::ACP_BTTDM_ITER) } & regs::TDM_ITER_ENABLE == 0,
            narf_time::Deadline::after_ms(100),
        )
    })
    .ok_or(PcmError::NoController)?;
    if !ok {
        return Err(PcmError::StopTimeout);
    }
    stream.running = false;
    Ok(())
}

/// Drain — wait for the engine's linear position counter to reach
/// the cyclic length (i.e. it has emitted every sample in the
/// ring at least once), then stop. Used by `play_pcm` callers that
/// want a one-shot semantics.
///
/// Bounded by `deadline_ms` so a wedged engine doesn't stall the
/// caller forever.
pub fn drain(deadline_ms: u64) -> Result<(), PcmError> {
    let cyclic = {
        let g = STREAM.lock();
        match g.as_ref() {
            Some(s) => s.cyclic_bytes as u64,
            None => return Err(PcmError::NoController),
        }
    };
    let _ = with_controller_mut(|dev| -> bool {
        narf_scheduler::responsive_spin_until(
            // SAFETY: BAR0 mapped, exclusive owner.
            || unsafe {
                let lo = dev.mmio.read32(regs::ACP_I2STX_LINEARPOSITION_CNTR_LOW) as u64;
                let hi = dev.mmio.read32(regs::ACP_I2STX_LINEARPOSITION_CNTR_HIGH) as u64;
                ((hi << 32) | lo) >= cyclic
            },
            narf_time::Deadline::after_ms(deadline_ms),
        )
    });
    stop_pcm()
}

/// Bytes the engine has fetched from the ring since the last
/// `prepare_i2s0_tx`. Wraps modulo 2^64 — sufficient for any
/// realistic playback duration.
pub fn linear_position() -> Option<u64> {
    with_controller_mut(|dev| -> u64 {
        // SAFETY: BAR0 mapped, exclusive owner.
        unsafe {
            let lo = dev.mmio.read32(regs::ACP_I2STX_LINEARPOSITION_CNTR_LOW) as u64;
            let hi = dev.mmio.read32(regs::ACP_I2STX_LINEARPOSITION_CNTR_HIGH) as u64;
            (hi << 32) | lo
        }
    })
}

/// `true` iff the I2S TX engine has emitted at least `cyclic_bytes`
/// — i.e. has cycled past the last ring entry once.
pub fn is_done() -> bool {
    let g = STREAM.lock();
    match g.as_ref() {
        Some(s) => match linear_position() {
            Some(p) => p >= s.cyclic_bytes as u64,
            None => false,
        },
        None => false,
    }
}

/// Capacity in i16 sample slots. With S16LE stereo at the configured
/// ring size, capacity is `RING_BYTES / 2` i16 slots.
pub const fn period_samples() -> usize {
    (RING_BYTES as usize) / 2
}

/// `true` if the I2S0 TX engine has been prepared and the ring is
/// allocated. False after a fresh probe or after `tear_down`.
pub fn is_prepared() -> bool {
    STREAM.lock().is_some()
}

/// Drop the ring + clear ACP-side state. Used by test code and by
/// the eventual `close` path; safe to call after `stop_pcm`.
pub fn tear_down() {
    let _ = stop_pcm();
    *STREAM.lock() = None;
    let _ = with_controller_mut(|dev| {
        dev.i2s_tx_prepared = false;
        // SAFETY: BAR0 mapped, exclusive owner.
        unsafe {
            dev.mmio.write32(regs::ACP_BTTDM_IER, 0);
        }
    });
}

/// Build the canonical WM8960 codec init sequence for the I2S0 TX
/// path. The list is consumed by an I2C transport (I2C-HID or
/// FCH SMBus in NARF's case) — the codec sits on a separate I2C
/// bus from the ACP block, addressed at 7-bit `0x1A`.
///
/// The returned vec is `(register, 9-bit-value)` pairs in the order
/// the codec datasheet §10 ("Software Reset") prescribes:
///   1. Software reset
///   2. Power up VREF + VMID
///   3. Power up DAC, headphone, line-out drivers
///   4. Audio interface: I2S master mode, 16-bit word length
///   5. DAC volume → 0 dB
///   6. Output mixer enables (LD2LO / RD2RO)
///   7. Headphone / speaker volumes → 0 dB
///
/// Linux `sound/soc/codecs/wm8960.c::wm8960_probe()` does the same
/// in `wm8960_set_pll()` + a series of `regmap_write` calls; ours
/// is the equivalent baked-list rendering.
pub fn build_wm8960_init_for_i2s0_tx() -> alloc::vec::Vec<(u8, u16)> {
    crate::wm8960::build_init_sequence_i2s_master_16bit()
}

// ── Test helpers ────────────────────────────────────────────────────

#[doc(hidden)]
pub fn __reset_for_test() {
    *STREAM.lock() = None;
}
