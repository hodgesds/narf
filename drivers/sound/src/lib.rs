//! narf-drivers-sound — Intel/AMD HDA controller + Realtek codec + ALSA surface.
//!
//! Targets the AMD HDA controllers that ship on the user's two
//! bring-up laptops (Zen2 Renoir `1022:15E3`, Phoenix HawkPoint1
//! `1022:15E2`) and the Realtek ALC-family codec on the codec link.
//! Also probes Intel PCH HDA — the programming model is identical;
//! only PCI IDs change.
//!
//! Layered like Linux's `sound/hda/`:
//!
//! - `hda::controller`  — PCI probe, BAR map, GCAP/GCTL/INTCTL reset
//!                        sequence, INTSTS path.
//! - `hda::corb`        — Command Output Ring Buffer (verb send).
//! - `hda::rirb`        — Response Input Ring Buffer (verb response).
//! - `hda::streams`     — Stream descriptors + Buffer Descriptor List.
//! - `hda::widget`      — Codec widget graph + node walking.
//! - `codec::generic`   — Vendor-agnostic AFG bring-up (any compliant
//!                        codec — power, unmute, default routing).
//! - `codec::realtek`   — ALC233/235/236/255/256/270/280/282/283/285/
//!                        286/287/289/290/292/293/294/295/298/3204/
//!                        3225/3236/3254/3266/3268/3286/3287 init
//!                        verb sequences.
//! - `codec::quirks`    — Per-laptop-model widget connection quirks
//!                        (Lenovo, Dell, HP, ASUS, MSI laptop tables).
//! - `pcm`              — PCM substream model (open/hw_params/prepare/
//!                        trigger/pointer/close).
//! - `mixer`            — ALSA-style mixer control surface (volume,
//!                        mute, jack-sense).
//! - `format`           — Sample formats (S16/S24/S32 LE,
//!                        44.1/48/96/192 kHz).
//!
//! ## What this crate is for
//!
//! Without this driver, the laptop speakers + mic + headphone jack
//! are dead. The boot chime, system beep, and any userspace audio
//! goes nowhere.
//!
//! ## Relationship to other audio code in NARF
//!
//! - `narf-audio` (`audio/`) is the older Stage-4 scaffold for the
//!   virtio-sound-pci backend. It carries an early HDA bring-up
//!   inside that crate. This crate is the long-form HDA path with
//!   the per-codec init tables and the ALSA-equivalent PCM/mixer
//!   surface that userspace can drive.
//! - `narf-audio::acp6` is a separate AMD-specific path. Most AMD
//!   laptops expose HDA alongside or instead of ACP6 depending on
//!   chipset — this crate targets the standard HDA controller path.
//! - USB Audio Class is a separate driver under `drivers/usb/` and is
//!   not in this scope.
//!
//! ## Linux source citations (post-2026-05-20 relicense)
//!
//! - `sound/hda/controllers/intel.c` — `azx_first_init`, GCAP/GCTL
//!   reset sequence, CORB/RIRB ring setup.
//! - `sound/hda/core/controller.c` — generic HDA controller state
//!   machine (reset, codec mask scan, stream alloc).
//! - `sound/hda/codecs/realtek/realtek.c` + per-`alc<N>.c` —
//!   `alc_init`, `alc_subsystem_id`, `alc269_quirks[]`, per-chip
//!   `alc<N>_setup_*` verb sequences.
//! - `sound/hda/codecs/generic.c` — `snd_hda_gen_parse_auto_config`
//!   widget-graph walker.
//! - `sound/core/pcm_native.c` — `snd_pcm_kernel_ioctl`,
//!   `snd_pcm_hw_params`, `snd_pcm_trigger`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod codec;
pub mod devfs_bridge;
pub mod format;
pub mod hda;
pub mod mixer;
pub mod pcm;
pub mod procfs_bridge;
pub mod sysfs_bridge;

mod tests;

#[cfg(feature = "kernel-test")]
mod e2e_tests;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::format::{HwParams, SampleFormat};
use crate::mixer::{ControlId, ControlValue, MixerError};

// ── Card / device identity ──────────────────────────────────────────

/// Per-card info reported by [`list_cards`]. Mirrors ALSA's
/// `snd_card` summary — index + an opaque driver string + a
/// human-readable id ("HDA Intel PCH", "HDA AMD Phoenix",
/// "HDA AMD Renoir").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardInfo {
    /// Stable card index assigned at probe time. The bring-up path
    /// uses `0` for the first probed controller, `1` for the second,
    /// etc.
    pub index: u32,
    /// Driver identifier (e.g. `"hda-intel"`). Maps to the
    /// `azx_driver_name` field in Linux's `azx_driver[]` table.
    pub driver: &'static str,
    /// Short id for the card. ALSA exposes this through `sysfs` as
    /// `card<N>/id`. We surface the same string.
    pub id: &'static str,
    /// Long human-readable name including PCI subsystem when known.
    pub name: &'static str,
    /// Number of PCM playback substreams on this card.
    pub playback_count: u32,
    /// Number of PCM capture substreams on this card.
    pub capture_count: u32,
}

/// Errors returned by the public surface. Mirrors ALSA's
/// `-EINVAL`/`-EBUSY`/`-ENODEV` distinctions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SoundError {
    /// No card with the given index is registered. Maps to `-ENODEV`.
    NoSuchCard,
    /// No device on the card matches the substream selector. Maps to
    /// `-ENODEV` (within an existing card).
    NoSuchDevice,
    /// All substreams on the target device are claimed. Maps to
    /// `-EBUSY`.
    DeviceBusy,
    /// Hardware-params combo isn't supported by the codec or
    /// controller. Maps to `-EINVAL`.
    InvalidParams,
    /// Caller called an operation in the wrong state (e.g.
    /// `write` before `prepare`). Maps to `-EPIPE` (xrun).
    BadState,
    /// DMA buffer allocation failed. Maps to `-ENOMEM`.
    NoMemory,
    /// Mixer control look-up failed. Maps to `-ENOENT`.
    NoSuchControl,
    /// Mixer value out of range. Maps to `-ERANGE`.
    OutOfRange,
}

impl From<MixerError> for SoundError {
    fn from(e: MixerError) -> Self {
        match e {
            MixerError::NoSuchControl => SoundError::NoSuchControl,
            MixerError::OutOfRange => SoundError::OutOfRange,
            MixerError::ReadOnly => SoundError::BadState,
        }
    }
}

// ── Card registry ──────────────────────────────────────────────────

/// A registered sound card. Wraps an `HdaController` instance plus
/// the codec(s) discovered on its codec link.
#[derive(Debug)]
pub struct SoundCard {
    info: CardInfo,
    /// Pointer to the controller in the controller registry. The
    /// controller is owned by `hda::controller::REGISTRY` so the
    /// card entry is `Copy`-safe (it doesn't own MMIO state).
    controller_index: usize,
}

impl SoundCard {
    pub fn info(&self) -> &CardInfo {
        &self.info
    }

    pub fn controller_index(&self) -> usize {
        self.controller_index
    }
}

static CARD_REGISTRY: narf_lib::sync::IrqSafeSpinLock<Vec<SoundCard>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());

static NEXT_CARD_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Register a probed controller as a card. Called from
/// `hda::controller::probe` after the controller is brought out of
/// reset and its codecs enumerated.
pub fn register_card(
    driver: &'static str,
    id: &'static str,
    name: &'static str,
    controller_index: usize,
    playback_count: u32,
    capture_count: u32,
) -> u32 {
    let index = NEXT_CARD_INDEX.fetch_add(1, Ordering::AcqRel) as u32;
    let info = CardInfo {
        index,
        driver,
        id,
        name,
        playback_count,
        capture_count,
    };
    let card = SoundCard {
        info,
        controller_index,
    };
    CARD_REGISTRY.lock().push(card);
    index
}

/// List every probed sound card. Mirrors `cat /proc/asound/cards`.
pub fn list_cards() -> Vec<CardInfo> {
    CARD_REGISTRY
        .lock()
        .iter()
        .map(|c| c.info.clone())
        .collect()
}

/// Look up a card by index.
pub fn card_count() -> usize {
    CARD_REGISTRY.lock().len()
}

/// Reset registry for tests.
pub fn __reset_for_test() {
    CARD_REGISTRY.lock().clear();
    NEXT_CARD_INDEX.store(0, Ordering::SeqCst);
}

// ── Public stream API ───────────────────────────────────────────────

/// Playback stream — an opened PCM playback substream. The handle
/// owns the stream descriptor + its BDL until `close`.
#[derive(Debug)]
pub struct PlaybackStream {
    pub(crate) card: u32,
    pub(crate) device: u32,
    pub(crate) substream: crate::pcm::PcmSubstream,
}

impl PlaybackStream {
    pub fn card(&self) -> u32 {
        self.card
    }
    pub fn device(&self) -> u32 {
        self.device
    }
    /// Configure hardware parameters. Must be called before `prepare`.
    pub fn hw_params(&mut self, params: HwParams) -> Result<(), SoundError> {
        self.substream.hw_params(params)
    }
    /// Prepare the stream — install BDL, program SDxFMT/SDxCBL/SDxLVI.
    pub fn prepare(&mut self) -> Result<(), SoundError> {
        self.substream.prepare()
    }
    /// Start DMA — set SDxCTL.RUN. Stream begins shifting samples to
    /// the codec on the next BDL period.
    pub fn start(&mut self) -> Result<(), SoundError> {
        self.substream.trigger_start()
    }
    /// Stop DMA — clear SDxCTL.RUN.
    pub fn stop(&mut self) -> Result<(), SoundError> {
        self.substream.trigger_stop()
    }
    /// Stream position in frames since `start`. Reads SDxLPIB or the
    /// DMA position buffer (whichever the chip implements).
    pub fn pointer(&self) -> u64 {
        self.substream.pointer()
    }
    /// Write `frames` worth of PCM samples into the cyclic buffer at
    /// the current write pointer. Returns the number of frames the
    /// driver was able to absorb (may be less than requested if the
    /// cyclic buffer is full).
    pub fn write(&mut self, samples: &[u8]) -> Result<usize, SoundError> {
        self.substream.write(samples)
    }
    /// Drain remaining samples and stop. Blocks until the position
    /// catches up to the last write pointer.
    pub fn drain(&mut self) -> Result<(), SoundError> {
        self.substream.drain()
    }
}

/// Capture stream — same shape as `PlaybackStream` but consuming the
/// input direction. PCM data is copied *out* of the cyclic buffer.
#[derive(Debug)]
pub struct CaptureStream {
    pub(crate) card: u32,
    pub(crate) device: u32,
    pub(crate) substream: crate::pcm::PcmSubstream,
}

impl CaptureStream {
    pub fn card(&self) -> u32 {
        self.card
    }
    pub fn device(&self) -> u32 {
        self.device
    }
    pub fn hw_params(&mut self, params: HwParams) -> Result<(), SoundError> {
        self.substream.hw_params(params)
    }
    pub fn prepare(&mut self) -> Result<(), SoundError> {
        self.substream.prepare()
    }
    pub fn start(&mut self) -> Result<(), SoundError> {
        self.substream.trigger_start()
    }
    pub fn stop(&mut self) -> Result<(), SoundError> {
        self.substream.trigger_stop()
    }
    pub fn pointer(&self) -> u64 {
        self.substream.pointer()
    }
    /// Read available capture frames into `out`. Returns the number
    /// of bytes actually copied.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, SoundError> {
        self.substream.read(out)
    }
}

/// Open a playback substream. Picks the first free playback stream
/// descriptor on the named card's controller. Returns
/// `SoundError::NoSuchCard` / `DeviceBusy` per ALSA conventions.
pub fn open_playback(card: u32, device: u32) -> Result<PlaybackStream, SoundError> {
    let registry = CARD_REGISTRY.lock();
    let _card = registry
        .iter()
        .find(|c| c.info.index == card)
        .ok_or(SoundError::NoSuchCard)?;
    if device >= _card.info.playback_count {
        return Err(SoundError::NoSuchDevice);
    }
    let controller_index = _card.controller_index;
    drop(registry);
    let substream = crate::pcm::PcmSubstream::new_playback(controller_index, device)?;
    Ok(PlaybackStream {
        card,
        device,
        substream,
    })
}

/// Open a capture substream — picks the first free input stream
/// descriptor on the named card's controller.
pub fn open_capture(card: u32, device: u32) -> Result<CaptureStream, SoundError> {
    let registry = CARD_REGISTRY.lock();
    let _card = registry
        .iter()
        .find(|c| c.info.index == card)
        .ok_or(SoundError::NoSuchCard)?;
    if device >= _card.info.capture_count {
        return Err(SoundError::NoSuchDevice);
    }
    let controller_index = _card.controller_index;
    drop(registry);
    let substream = crate::pcm::PcmSubstream::new_capture(controller_index, device)?;
    Ok(CaptureStream {
        card,
        device,
        substream,
    })
}

// ── Mixer access ────────────────────────────────────────────────────

/// Open the mixer for a card. The returned `Mixer` references the
/// card's codec capability cache and routes get/set through codec
/// verbs at call time.
pub fn mixer(card: u32) -> Result<Mixer, SoundError> {
    let registry = CARD_REGISTRY.lock();
    let c = registry
        .iter()
        .find(|c| c.info.index == card)
        .ok_or(SoundError::NoSuchCard)?;
    let controller_index = c.controller_index;
    drop(registry);
    Ok(Mixer {
        card,
        controller_index,
    })
}

/// ALSA-equivalent mixer handle.
#[derive(Debug)]
pub struct Mixer {
    card: u32,
    controller_index: usize,
}

impl Mixer {
    pub fn card(&self) -> u32 {
        self.card
    }

    /// List every control on the card. Returns IDs that
    /// `get_control_value`/`set_control_value` accept.
    pub fn list_controls(&self) -> Vec<ControlId> {
        crate::mixer::list_for_controller(self.controller_index)
    }

    /// Read a control's current value.
    pub fn get_control_value(&self, id: ControlId) -> Result<ControlValue, SoundError> {
        crate::mixer::get(self.controller_index, id).map_err(SoundError::from)
    }

    /// Write a control. Range-checks against the control's
    /// `info.value_max` and emits the underlying codec verb.
    pub fn set_control_value(&self, id: ControlId, val: ControlValue) -> Result<(), SoundError> {
        crate::mixer::set(self.controller_index, id, val).map_err(SoundError::from)
    }
}

/// Format helper re-export so callers don't have to import the
/// `format` submodule directly for the common case.
pub use crate::format::{ChannelCount, SampleRate};

/// Probe-time entry point. Called by `hda::controller::probe` once
/// the controller is fully brought up.
pub fn finalize_probe(
    driver: &'static str,
    id: &'static str,
    name: &'static str,
    controller_index: usize,
    playback_count: u32,
    capture_count: u32,
) -> u32 {
    register_card(
        driver,
        id,
        name,
        controller_index,
        playback_count,
        capture_count,
    )
}

/// Sample-format / rate / channel quick-check used by tests.
pub fn supported_format(fmt: SampleFormat, rate: SampleRate, channels: ChannelCount) -> bool {
    crate::format::supported(fmt, rate, channels)
}

// ── VFS bridge initcall ─────────────────────────────────────────────────

/// Register all sound-driver VFS bridges.
///
/// Called once from the kernel's filesystem initcall sequence after the
/// first HDA controller is probed.  Idempotent — safe to call again
/// (replaces the existing delegates with fresh instances that still read
/// from the same live `CARD_REGISTRY`).
///
/// Order:
///   1. sysfs  — `/sys/class/sound/*` kobjects  (no ordering dep on devfs)
///   2. devfs  — `/dev/snd/*` character nodes
///   3. procfs — `/proc/asound/*` generators (stub until Wave-19 API lands)
pub fn sound_fs_initcall() {
    crate::sysfs_bridge::register_all_cards_sysfs();
    crate::devfs_bridge::register_devfs_snd();
    crate::procfs_bridge::register_procfs_asound();
}

// ── Test support ────────────────────────────────────────────────────────

/// Helpers used by `devfs_bridge` and `sysfs_bridge` unit tests to
/// drive `FsFuture` without a full async executor.
pub mod tests_support {
    /// Synchronously poll `fut` once with a no-op waker.
    ///
    /// `FsFuture` values produced by the bridge `FileOps` impls are always
    /// immediately ready — they do not yield to the executor.  The no-op
    /// waker is therefore correct: we never need to wake it.
    pub fn poll_once<T>(fut: impl core::future::Future<Output = T>) -> T {
        use core::pin::Pin;
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        let mut boxed = alloc::boxed::Box::pin(fut);
        match boxed.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("poll_once: future is pending"),
        }
    }
}
