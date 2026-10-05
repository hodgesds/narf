//! narf-audio — PCM audio subsystem.
//!
//! VirtIO and native HDA playback, HDA/ACP 6.3 capture, and the
//! capability-gated kernel API. Native PCM and mixer endpoints are also
//! published through narf-drivers-sound's card/file bridge.
//!
//! Surface (parallels narf-fb's shape):
//!
//!   * `AudioStream` — trait every backend implements. Exposes the
//!     supported formats + a `submit / wait / close` lifecycle.
//!   * `select_active_playback() -> Option<&'static dyn AudioStream>`
//!     — picker that returns the best-available output stream.
//!   * `AudioWriter` — typed handle over a `Cap<AudioStreamCap, Write>`
//!     that submits PCM buffers + observes completions.
//!
//! Cap typing — `AudioStreamCap`:
//!     `Cap<AudioStreamCap, Read>`  — capture (recording)
//!     `Cap<AudioStreamCap, Write>` — playback
//!
//! AudioReader requires explicit capture authority; enumeration never
//! starts recording. See specification/spec.md for the implemented formats
//! and the distinction between the NARF file protocol and Linux ALSA.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod acp6;
pub mod acp63;
pub mod acp6_bdl;
pub mod acp6_codec_link;
pub mod acp6_pcm;
pub mod codec;
pub mod hda;
pub mod hda_codec;
pub mod i2s;
pub mod msbc;
mod native_firmware;
mod native_irq;
mod native_pci;
mod native_pcm;
pub mod realtek_alc;
pub mod sbc;
pub mod wm8960;

mod hda_tests;
mod tests;

use core::sync::atomic::{AtomicUsize, Ordering};

use narf_capabilities::{Cap, CapKind, CapType, Read, Write};

/// Sample format the kernel exposes. New formats add new variants;
/// the integer wire encoding lives in `narf-user-runtime` as
/// `AUDIO_FORMAT_*` and must stay in sync.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SampleFormat {
    /// 16-bit signed little-endian. Stage-4 baseline; matches the
    /// virtio-sound "S16" feature flag and what nearly every PCM
    /// stream actually carries.
    S16Le,
    /// 32-bit IEEE float little-endian. Optional; backends advertise
    /// support via `AudioStream::supports`.
    F32Le,
    /// Signed 32-bit PCM, used by the native ACP digital microphone.
    S32Le,
}

/// Channel layout. Stage-4 supports mono + stereo; multichannel
/// (5.1, 7.1) lands when the audio server / mixer arrives.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChannelLayout {
    Mono = 1,
    Stereo = 2,
}

/// PCM format triple: rate × format × channels. The kernel-side
/// driver negotiates this at stream open; userspace requests a
/// preferred triple via `SYS_AUDIO_OPEN` (when it lands).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AudioFormat {
    pub sample_rate_hz: u32,
    pub format: SampleFormat,
    pub channels: ChannelLayout,
}

impl AudioFormat {
    /// Stage-4 default: 48 kHz / S16LE / Stereo. Covers >95% of
    /// userspace consumers and matches the virtio-sound spec's
    /// recommended baseline.
    pub const fn default_playback() -> Self {
        Self {
            sample_rate_hz: 48_000,
            format: SampleFormat::S16Le,
            channels: ChannelLayout::Stereo,
        }
    }

    /// Bytes per PCM frame (one sample per channel).
    pub const fn bytes_per_frame(self) -> u32 {
        let per_sample = match self.format {
            SampleFormat::S16Le => 2,
            SampleFormat::F32Le | SampleFormat::S32Le => 4,
        };
        per_sample * (self.channels as u32)
    }
}

/// Cap-typed authority over an audio stream.
#[derive(Copy, Clone, Debug)]
pub struct AudioStreamCap;

impl CapType for AudioStreamCap {
    const KIND: CapKind = CapKind::AudioStream;
}

/// Backend-agnostic audio stream. Implementations are zero-cost
/// wrappers over the underlying driver's stream state.
pub trait AudioStream: Send + Sync + core::fmt::Debug {
    /// Currently negotiated format. `None` if the stream hasn't
    /// been opened yet.
    fn current_format(&self) -> Option<AudioFormat>;
    /// `true` if this stream can transport `fmt`. Used by the
    /// negotiator + by tests asserting QEMU's exposed support.
    fn supports(&self, fmt: AudioFormat) -> bool;
    /// Identifier — "virtio-sound", "hda", "ac97". Used by the
    /// picker log and tests that want to assert which backend won.
    fn name(&self) -> &'static str;
    /// `true` iff this stream is configured for playback (writes
    /// PCM to host). `false` for capture (reads PCM from host).
    fn is_playback(&self) -> bool;
}

// ── virtio-sound backend ────────────────────────────────────────────
//
// Light wrapper that asks the virtio-sound driver whether its tx
// stream is up. Real format negotiation lands when snd_pci grows
// `current_format` + `submit_pcm`.

#[derive(Debug)]
struct VirtioSoundPlayback;

impl AudioStream for VirtioSoundPlayback {
    fn current_format(&self) -> Option<AudioFormat> {
        for sample_rate_hz in [48_000, 44_100] {
            for channels in [ChannelLayout::Stereo, ChannelLayout::Mono] {
                let format = AudioFormat {
                    sample_rate_hz,
                    channels,
                    format: SampleFormat::S16Le,
                };
                if self.supports(format) {
                    return Some(format);
                }
            }
        }
        None
    }
    fn supports(&self, fmt: AudioFormat) -> bool {
        virtio_params(fmt).is_some_and(narf_drivers_virtio::snd_pci::supports_playback)
    }
    fn name(&self) -> &'static str {
        "virtio-sound"
    }
    fn is_playback(&self) -> bool {
        true
    }
}

static PLAYBACK: VirtioSoundPlayback = VirtioSoundPlayback;

fn virtio_params(format: AudioFormat) -> Option<narf_drivers_virtio::snd_pci::PcmParams> {
    use narf_drivers_virtio::snd_pci;
    if format.format != SampleFormat::S16Le
        || !matches!(format.channels, ChannelLayout::Mono | ChannelLayout::Stereo)
    {
        return None;
    }
    Some(snd_pci::PcmParams {
        channels: format.channels as u8,
        rate: match format.sample_rate_hz {
            44_100 => snd_pci::VIRTIO_SND_PCM_RATE_44100,
            48_000 => snd_pci::VIRTIO_SND_PCM_RATE_48000,
            _ => return None,
        },
        ..snd_pci::PcmParams::default_playback()
    })
}

// ── Intel HDA backend ───────────────────────────────────────────────
//
// HDA reaches its `current_format` once the controller is probed +
// at least one codec has been enumerated. The format is fixed at the
// driver's bring-up choice (48 kHz S16LE stereo) — a `set_format`
// path lands when the codec verb walker grows beyond enumeration.

#[derive(Debug)]
struct IntelHdaPlayback;

impl AudioStream for IntelHdaPlayback {
    fn current_format(&self) -> Option<AudioFormat> {
        if hda::is_probed() {
            Some(AudioFormat::default_playback())
        } else {
            None
        }
    }
    fn supports(&self, fmt: AudioFormat) -> bool {
        fmt.format == SampleFormat::S16Le
            && fmt.sample_rate_hz == 48_000
            && fmt.channels == ChannelLayout::Stereo
    }
    fn name(&self) -> &'static str {
        "intel-hda"
    }
    fn is_playback(&self) -> bool {
        true
    }
}

static HDA_PLAYBACK: IntelHdaPlayback = IntelHdaPlayback;

/// Pick the best-available playback stream. virtio-sound wins when
/// it's probed (more flexibility today: 44.1 + 48 kHz, mono +
/// stereo); fall through to Intel HDA on bare metal.
pub fn select_active_playback() -> Option<&'static dyn AudioStream> {
    if PLAYBACK.current_format().is_some() {
        return Some(&PLAYBACK);
    }
    if HDA_PLAYBACK.current_format().is_some() {
        return Some(&HDA_PLAYBACK);
    }
    None
}

// ── AudioWriter ─────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AudioWriteError {
    NoActiveStream,
    UnsupportedFormat,
    StreamClosed,
}

/// Cap-gated handle over a playback stream. Holding this by-value
/// guarantees the cap is live for the duration; cap revocation
/// invalidates the writer at construction time + on each op.
#[derive(Debug)]
pub struct AudioWriter {
    stream: &'static dyn AudioStream,
    cap: Cap<AudioStreamCap, Write>,
    format: AudioFormat,
}

// Keep the actual operation behind the epoch gate, including its device access.
struct AudioOp<F>(F);
impl<R: narf_capabilities::Rights, F: FnOnce() -> T, T> narf_capabilities::CapOp<AudioStreamCap, R>
    for AudioOp<F>
{
    type Output = T;
    fn execute(self, _: &Cap<AudioStreamCap, R>) -> Result<T, narf_capabilities::CapError> {
        Ok((self.0)())
    }
}

impl AudioWriter {
    /// Construct from a Write cap + requested format. Returns
    /// `NoActiveStream` if no playback backend is up;
    /// `UnsupportedFormat` if the backend rejects the triple.
    pub fn open(
        cap: Cap<AudioStreamCap, Write>,
        fmt: AudioFormat,
    ) -> Result<Self, AudioWriteError> {
        cap.invoke(narf_capabilities::NoopOp)
            .map_err(|_| AudioWriteError::StreamClosed)?;
        let stream = select_active_playback().ok_or(AudioWriteError::NoActiveStream)?;
        if !stream.supports(fmt) {
            return Err(AudioWriteError::UnsupportedFormat);
        }
        Ok(Self {
            stream,
            cap,
            format: fmt,
        })
    }

    /// Currently negotiated format.
    pub fn format(&self) -> AudioFormat {
        self.format
    }

    /// Backend name — for diagnostics.
    pub fn name(&self) -> &'static str {
        self.stream.name()
    }

    /// Submit a buffer of PCM frames for playback. Blocks until the
    /// backend acks the buffer; returns the frame count in this
    /// submission (derived from the byte count, since the
    /// virtio-sound device doesn't expose a frame counter directly).
    ///
    /// `pcm.len()` must be a non-zero multiple of `format.bytes_per_frame()`.
    pub fn submit(&self, pcm: &[u8]) -> Result<u64, AudioWriteError> {
        self.cap
            .invoke(AudioOp(|| self.submit_live(pcm)))
            .map_err(|_| AudioWriteError::StreamClosed)?
    }
    fn submit_live(&self, pcm: &[u8]) -> Result<u64, AudioWriteError> {
        let bpf = self.format.bytes_per_frame() as usize;
        if pcm.is_empty() || bpf == 0 || pcm.len() % bpf != 0 {
            return Err(AudioWriteError::UnsupportedFormat);
        }
        match self.stream.name() {
            "intel-hda" => self.submit_hda(pcm),
            _ => self.submit_virtio_sound(pcm),
        }
    }

    fn submit_virtio_sound(&self, pcm: &[u8]) -> Result<u64, AudioWriteError> {
        let bpf = self.format.bytes_per_frame() as usize;
        use narf_drivers_virtio::snd_pci;
        let params = virtio_params(self.format).ok_or(AudioWriteError::UnsupportedFormat)?;
        snd_pci::play_buffer(params, pcm).map_err(|_| AudioWriteError::StreamClosed)?;
        Ok((pcm.len() / bpf) as u64)
    }

    /// Feed the HDA ring with backpressure, drain all submitted frames, and stop.
    fn submit_hda(&self, pcm: &[u8]) -> Result<u64, AudioWriteError> {
        let written = hda::play_buffer(pcm).map_err(|_| AudioWriteError::StreamClosed)?;
        Ok((written / self.format.bytes_per_frame() as usize) as u64)
    }

    /// Zero-copy submit: forwards a `(shmem_handle, byte_offset,
    /// byte_len)` triple to the backend. The PCM bytes already
    /// live in the kernel-coherent shmem region; the device reads
    /// them in place. Same blocking + completion semantics as
    /// `submit`.
    ///
    /// The payload must be physically contiguous — i.e. it must
    /// stay within a single page of the shmem region. Multi-page
    /// submissions (chained descriptor groups) land when a real
    /// streaming consumer needs them.
    pub fn submit_shmem(
        &self,
        shmem_handle: u64,
        byte_offset: u64,
        byte_len: u64,
    ) -> Result<u64, AudioWriteError> {
        self.cap
            .invoke(AudioOp(|| {
                self.submit_shmem_live(shmem_handle, byte_offset, byte_len)
            }))
            .map_err(|_| AudioWriteError::StreamClosed)?
    }
    fn submit_shmem_live(
        &self,
        shmem_handle: u64,
        byte_offset: u64,
        byte_len: u64,
    ) -> Result<u64, AudioWriteError> {
        let bpf = self.format.bytes_per_frame() as u64;
        if byte_len == 0 || bpf == 0 || byte_len % bpf != 0 {
            return Err(AudioWriteError::UnsupportedFormat);
        }
        // Single-page contiguity: offset + len must not cross a
        // page boundary. The Stage-4 contract — multi-page chains
        // are a follow-up.
        if (byte_offset & 0xFFF) + byte_len > 4096 {
            return Err(AudioWriteError::UnsupportedFormat);
        }
        let phys =
            narf_shmem::phys_at(shmem_handle, byte_offset).ok_or(AudioWriteError::StreamClosed)?;
        if self.stream.name() == "intel-hda" {
            return Err(AudioWriteError::UnsupportedFormat);
        }
        use narf_drivers_virtio::snd_pci::{
            self, PcmParams, VIRTIO_SND_PCM_FMT_S16, VIRTIO_SND_PCM_RATE_44100,
            VIRTIO_SND_PCM_RATE_48000,
        };
        let rate_code = match self.format.sample_rate_hz {
            44_100 => VIRTIO_SND_PCM_RATE_44100,
            48_000 => VIRTIO_SND_PCM_RATE_48000,
            _ => return Err(AudioWriteError::UnsupportedFormat),
        };
        let format_code = match self.format.format {
            SampleFormat::S16Le => VIRTIO_SND_PCM_FMT_S16,
            SampleFormat::F32Le | SampleFormat::S32Le => {
                return Err(AudioWriteError::UnsupportedFormat)
            }
        };
        let params = PcmParams {
            buffer_bytes: 8192,
            period_bytes: 2048,
            channels: self.format.channels as u8,
            format: format_code,
            rate: rate_code,
        };
        snd_pci::play_buffer_phys(params, phys, byte_len as u32)
            .map_err(|_| AudioWriteError::StreamClosed)?;
        Ok(byte_len / bpf)
    }
}

/// Errors from native PCM capture.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AudioReadError {
    NoActiveStream,
    UnsupportedFormat,
    StreamClosed,
    Timeout,
}

/// Capability-gated microphone stream. Capture starts only when explicitly
/// opened with a live Read capability; Drop stops DMA through the PCM lease.
#[derive(Debug)]
pub struct AudioReader {
    cap: Cap<AudioStreamCap, Read>,
    stream: narf_drivers_sound::CaptureStream,
    format: AudioFormat,
}
impl AudioReader {
    pub fn open(cap: Cap<AudioStreamCap, Read>) -> Result<Self, AudioReadError> {
        cap.invoke(AudioOp(|| Self::open_live(cap)))
            .map_err(|_| AudioReadError::StreamClosed)?
    }
    fn open_live(cap: Cap<AudioStreamCap, Read>) -> Result<Self, AudioReadError> {
        let card = acp63::capture_card()
            .or_else(hda::capture_card)
            .ok_or(AudioReadError::NoActiveStream)?;
        let params = narf_drivers_sound::default_hw_params(card, true)
            .map_err(|_| AudioReadError::UnsupportedFormat)?;
        let format = AudioFormat {
            sample_rate_hz: params.rate.hz(),
            channels: ChannelLayout::Stereo,
            format: match params.format {
                narf_drivers_sound::format::SampleFormat::S32LE => SampleFormat::S32Le,
                narf_drivers_sound::format::SampleFormat::S16LE => SampleFormat::S16Le,
                _ => return Err(AudioReadError::UnsupportedFormat),
            },
        };
        let mut stream = narf_drivers_sound::open_capture(card, 0)
            .map_err(|_| AudioReadError::NoActiveStream)?;
        stream
            .hw_params(params)
            .map_err(|_| AudioReadError::UnsupportedFormat)?;
        stream.prepare().map_err(|_| AudioReadError::StreamClosed)?;
        stream.start().map_err(|_| AudioReadError::StreamClosed)?;
        Ok(Self {
            cap,
            stream,
            format,
        })
    }
    pub fn format(&self) -> AudioFormat {
        self.format
    }
    /// Return completed whole frames; wait up to 500 ms for the first samples.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, AudioReadError> {
        if out.is_empty() || out.len() % self.format.bytes_per_frame() as usize != 0 {
            return Err(AudioReadError::UnsupportedFormat);
        }
        let mut result = Ok(0);
        let done = narf_scheduler::responsive_spin_until(
            || {
                result = match self.cap.invoke(AudioOp(|| self.stream.read(out))) {
                    Ok(read) => read.map_err(|_| AudioReadError::StreamClosed),
                    Err(_) => {
                        let _ = self.stream.stop();
                        Err(AudioReadError::StreamClosed)
                    }
                };
                !matches!(result, Ok(0))
            },
            narf_time::Deadline::after_ms(500),
        );
        if !done {
            return Err(AudioReadError::Timeout);
        }
        result
    }
    pub fn stop(&mut self) -> Result<(), AudioReadError> {
        self.stream.stop().map_err(|_| AudioReadError::StreamClosed)
    }
}

// ── Test-mode authority bootstrap ───────────────────────────────────

/// Mint a Write cap for the active playback stream. Same shape as
/// `narf_fb::bootstrap_writer` — the kernel-test runner / boot
/// initcalls call this; userspace consumers eventually receive a
/// derived cap from the audio server.
pub fn bootstrap_writer() -> Cap<AudioStreamCap, Write> {
    Cap::<AudioStreamCap, Write>::bootstrap()
}

// ── Init wiring ─────────────────────────────────────────────────────

static INIT_BACKEND_NAME: AtomicUsize = AtomicUsize::new(0);
static INIT_BACKEND_LEN: AtomicUsize = AtomicUsize::new(0);

/// Test helper: name of the playback backend the boot picker
/// selected, or `None` if none was available at init time.
pub fn last_picked_backend() -> Option<&'static str> {
    let p = INIT_BACKEND_NAME.load(Ordering::Acquire) as *const u8;
    let l = INIT_BACKEND_LEN.load(Ordering::Acquire);
    if p.is_null() || l == 0 {
        return None;
    }
    // SAFETY: published from a `&'static str`.
    unsafe {
        let slice = core::slice::from_raw_parts(p, l);
        Some(core::str::from_utf8_unchecked(slice))
    }
}

/// Stage::Late initcall: probe the picker + record the chosen
/// backend so smokes can assert which won without re-running the
/// picker.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    // Register the Intel-HDA PCI match so the bus probe walker
    // binds AMD Phoenix / Radeon HD Audio Controllers.
    narf_init::register(Stage::Subsys, "hda-pci", || {
        hda::register_pci_driver();
        InitResult::Ok
    });
    // Native Phoenix ACP 6.3 PDM capture; PCI revision and ACPI gate probe.
    narf_init::register(Stage::Subsys, "acp6-pci", || {
        acp6::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "native-audio-devices", || {
        narf_drivers_sound::sound_fs_initcall();
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "audio-playback-picker", || {
        if let Some(s) = select_active_playback() {
            INIT_BACKEND_NAME.store(s.name().as_ptr() as usize, Ordering::Release);
            INIT_BACKEND_LEN.store(s.name().len(), Ordering::Release);
            InitResult::Ok
        } else {
            InitResult::NotPresent
        }
    });
}
