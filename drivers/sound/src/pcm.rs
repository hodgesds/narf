//! PCM substream — open / hw_params / prepare / trigger /
//! pointer / close lifecycle, ALSA-style.
//!
//! References:
//! - `sound/core/pcm_native.c::snd_pcm_kernel_ioctl`
//! - `sound/core/pcm_native.c::snd_pcm_hw_params_choose`
//! - `sound/core/pcm.c::snd_pcm_lib_period_bytes`
//!
//! The substream model:
//!
//! ```text
//!   Opened ──hw_params──▶ Prepared ──trigger(START)──▶ Running
//!     ▲                                                   │
//!     │                                                trigger(STOP)
//!     │                                                   │
//!     └─────────────────close───────────────────────────◀─┘
//! ```

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::format::{pack_sdfmt, HwParams};
use crate::hda::streams::{BdlEntry, StreamDescriptor};
use crate::SoundError;

/// Substream lifecycle state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SubstreamState {
    /// No `hw_params` issued yet.
    Open,
    /// `hw_params` written, BDL not yet built.
    Configured,
    /// `prepare` complete — BDL + SDxFMT programmed, RUN clear.
    Prepared,
    /// `trigger(START)` issued — DMA shifting samples.
    Running,
    /// `trigger(STOP)` issued.
    Stopped,
}

/// PCM substream — one stream descriptor + its cyclic buffer + BDL.
#[derive(Debug)]
pub struct PcmSubstream {
    #[allow(dead_code)]
    pub(crate) controller_index: usize,
    #[allow(dead_code)]
    pub(crate) device: u32,
    pub(crate) is_capture: bool,
    pub(crate) state: SubstreamState,
    pub(crate) params: Option<HwParams>,
    /// SDxFMT register image. Programmed in `prepare`.
    pub(crate) sd_fmt: u16,
    /// Cyclic DMA buffer (host-side mirror — on real HW this is the
    /// `alloc_coherent` buffer and we'd hold the `DmaBuffer` itself).
    pub(crate) buffer: Vec<u8>,
    /// BDL — one entry per period.
    pub(crate) bdl: Vec<BdlEntry>,
    /// Position pointer reflected from SDxLPIB or the DMA-pos buffer.
    /// Tests drive this directly.
    pub(crate) position_frames: AtomicU64,
    /// Software write cursor into the cyclic buffer (byte offset).
    pub(crate) write_cursor: usize,
    /// Stream descriptor allocated from the controller.
    #[allow(dead_code)]
    pub(crate) stream_slot: usize,
    /// Stream descriptor location in BAR0.
    pub(crate) descriptor: StreamDescriptor,
    /// Stream tag programmed in SDxCTL.STRM and matched in the codec's
    /// SET_CONVERTER_STREAM_CHANNEL verb.
    pub(crate) stream_tag: u8,
}

impl PcmSubstream {
    fn new(controller_index: usize, device: u32, is_capture: bool)
           -> Result<Self, SoundError> {
        // Slot allocation happens against the controller. For the
        // off-HW test path we use the device number as a synthetic
        // slot — real probe-time wiring claims slots via
        // `HdaController::claim_output` / `claim_input`.
        let slot = device as usize;
        let descriptor = StreamDescriptor {
            offset: 0x80 + (slot as u64) * 0x20,
            is_input: is_capture,
        };
        Ok(PcmSubstream {
            controller_index,
            device,
            is_capture,
            state: SubstreamState::Open,
            params: None,
            sd_fmt: 0,
            buffer: Vec::new(),
            bdl: Vec::new(),
            position_frames: AtomicU64::new(0),
            write_cursor: 0,
            stream_slot: slot,
            descriptor,
            stream_tag: 1 + (slot as u8 & 0xF),
        })
    }

    pub fn new_playback(controller_index: usize, device: u32) -> Result<Self, SoundError> {
        Self::new(controller_index, device, false)
    }

    pub fn new_capture(controller_index: usize, device: u32) -> Result<Self, SoundError> {
        Self::new(controller_index, device, true)
    }

    /// Configure hw_params. Allocates the cyclic buffer + builds BDL.
    pub fn hw_params(&mut self, params: HwParams) -> Result<(), SoundError> {
        if !matches!(self.state, SubstreamState::Open | SubstreamState::Configured) {
            return Err(SoundError::BadState);
        }
        if params.period_size == 0 || params.periods == 0 {
            return Err(SoundError::InvalidParams);
        }
        let buf_bytes = params.buffer_bytes();
        if buf_bytes == 0 || buf_bytes > 256 * 1024 {
            return Err(SoundError::InvalidParams);
        }
        let period_bytes = params.period_bytes();
        let mut buffer = vec![0u8; buf_bytes];
        // Zero-fill so capture starts clean and playback doesn't
        // shift random memory through the codec.
        for b in buffer.iter_mut() { *b = 0; }
        // BDL: one entry per period, IOC on every entry so we get
        // per-period IRQs.
        let mut bdl = Vec::with_capacity(params.periods as usize);
        let buf_phys = buffer.as_ptr() as u64;
        for i in 0..params.periods as u64 {
            bdl.push(BdlEntry::new(
                buf_phys + i * period_bytes as u64,
                period_bytes as u32,
                true,
            ));
        }
        self.params = Some(params);
        self.buffer = buffer;
        self.bdl = bdl;
        self.sd_fmt = pack_sdfmt(params.format, params.rate, params.channels);
        self.write_cursor = 0;
        self.position_frames.store(0, Ordering::SeqCst);
        self.state = SubstreamState::Configured;
        Ok(())
    }

    /// Prepare the stream. On real HW: write SDxFMT, SDxCBL, SDxLVI,
    /// SDxBDPL/SDxBDPU, reset SRST, then clear SRST. Here: bookkeeping.
    pub fn prepare(&mut self) -> Result<(), SoundError> {
        if !matches!(self.state, SubstreamState::Configured | SubstreamState::Prepared
                     | SubstreamState::Stopped) {
            return Err(SoundError::BadState);
        }
        self.position_frames.store(0, Ordering::SeqCst);
        self.write_cursor = 0;
        self.state = SubstreamState::Prepared;
        Ok(())
    }

    /// Trigger SDxCTL.RUN.
    pub fn trigger_start(&mut self) -> Result<(), SoundError> {
        if !matches!(self.state, SubstreamState::Prepared | SubstreamState::Stopped) {
            return Err(SoundError::BadState);
        }
        self.state = SubstreamState::Running;
        Ok(())
    }

    /// Clear SDxCTL.RUN.
    pub fn trigger_stop(&mut self) -> Result<(), SoundError> {
        if !matches!(self.state, SubstreamState::Running) {
            return Err(SoundError::BadState);
        }
        self.state = SubstreamState::Stopped;
        Ok(())
    }

    /// Current position in frames since `trigger_start`.
    pub fn pointer(&self) -> u64 {
        self.position_frames.load(Ordering::Acquire)
    }

    /// Synthetic position increment — tests call this to simulate
    /// the DMA engine advancing its pointer.
    pub fn advance_position_test(&self, frames: u64) {
        self.position_frames.fetch_add(frames, Ordering::AcqRel);
    }

    /// Write playback samples. Returns bytes copied.
    pub fn write(&mut self, samples: &[u8]) -> Result<usize, SoundError> {
        if !matches!(self.state,
                     SubstreamState::Running | SubstreamState::Prepared)
            || self.is_capture
        {
            return Err(SoundError::BadState);
        }
        let total = self.buffer.len();
        if total == 0 {
            return Err(SoundError::BadState);
        }
        let mut written = 0;
        for &b in samples.iter() {
            self.buffer[self.write_cursor] = b;
            self.write_cursor = (self.write_cursor + 1) % total;
            written += 1;
        }
        Ok(written)
    }

    /// Read capture samples into `out`. Returns bytes copied.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, SoundError> {
        if !matches!(self.state,
                     SubstreamState::Running | SubstreamState::Prepared)
            || !self.is_capture
        {
            return Err(SoundError::BadState);
        }
        let total = self.buffer.len();
        if total == 0 {
            return Err(SoundError::BadState);
        }
        let mut read = 0;
        for slot in out.iter_mut() {
            *slot = self.buffer[self.write_cursor];
            self.write_cursor = (self.write_cursor + 1) % total;
            read += 1;
        }
        Ok(read)
    }

    /// Drain — wait until the position catches up to the write cursor.
    /// On the synthetic test bus this is a no-op (position is driven
    /// externally); on real HW it spins on SDxLPIB.
    pub fn drain(&mut self) -> Result<(), SoundError> {
        if !matches!(self.state, SubstreamState::Running) {
            return Err(SoundError::BadState);
        }
        self.state = SubstreamState::Stopped;
        Ok(())
    }

    /// Number of BDL entries.
    pub fn bdl_len(&self) -> usize {
        self.bdl.len()
    }

    /// Read the SDxFMT register image that `prepare` programmed.
    pub fn sd_fmt(&self) -> u16 {
        self.sd_fmt
    }

    /// Current state.
    pub fn state(&self) -> SubstreamState {
        self.state
    }

    /// SDxCBL register image (cyclic buffer length in bytes).
    pub fn cbl(&self) -> u32 {
        self.buffer.len() as u32
    }

    /// SDxLVI register image (last valid BDL index).
    pub fn lvi(&self) -> u8 {
        (self.bdl.len() as u8).saturating_sub(1)
    }

    /// Stream tag.
    pub fn stream_tag(&self) -> u8 {
        self.stream_tag
    }

    /// Stream descriptor offset within BAR0.
    pub fn descriptor_offset(&self) -> u64 {
        self.descriptor.offset
    }
}
