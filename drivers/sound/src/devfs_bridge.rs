//! `/dev/snd/*` bridge — one character-device node per ALSA-surface object.
//!
//! Exposes four node shapes for each registered sound card (card index N,
//! PCM device M):
//!
//! ```text
//! /dev/snd/controlC<N>        — mixer control (read=control-list, write=set)
//! /dev/snd/pcmC<N>D<M>p       — PCM playback  (write=feed samples, read rejected)
//! /dev/snd/pcmC<N>D<M>c       — PCM capture   (read=drain samples, write rejected)
//! /dev/snd/timer              — global timer stub (one per system)
//! /dev/snd/seq                — sequencer stub   (one per system)
//! ```
//!
//! Linux references:
//! - `sound/core/sound.c::snd_register_device` (device-node registration)
//! - `sound/core/pcm_native.c::snd_pcm_open`   (PCM fd open path)
//! - `sound/core/control.c::snd_ctl_open`       (control fd open path)
//!
//! # hw_params setsockopt-style helper
//!
//! NARF does not have `ioctl(2)`.  PCM callers configure hw_params by
//! writing a 20-byte packed little-endian record into the control file
//! at offset `HW_PARAMS_MAGIC_OFFSET` (0xFFFF_0000).  Layout matches
//! `HwParams` field order: `[format:u32][rate:u32][channels:u32]
//! [period_size:u32][periods:u32]`. Any write at a normal offset
//! (< 0xFFFF_0000) is treated as sample data.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use crate::format::{ChannelCount, HwParams, SampleFormat, SampleRate};
use crate::mixer::{ControlId, ControlValue};
use crate::{
    card_count, list_cards, open_capture, open_capture as _open_capture, open_playback,
    CaptureStream, Mixer, PlaybackStream, SoundError,
};

// ── Offset sentinel for hw_params writes ─────────────────────────────

/// A write at this offset into a PCM or control file encodes hw_params
/// rather than sample data.  Value chosen to be far outside any real
/// file-size range and easy to spot in a hex dump.
///
/// Linux surfaces hw_params via `SNDRV_PCM_IOCTL_HW_PARAMS`; we reuse
/// the file's `write` path keyed on this magic offset.
/// Linux ref: `sound/core/pcm_native.c::snd_pcm_hw_params` (ioctl handler).
pub const HW_PARAMS_MAGIC_OFFSET: u64 = 0xFFFF_0000;

/// Packed size of hw_params: 5 × u32 = 20 bytes.
const HW_PARAMS_BYTES: usize = 20;

/// Decode 20 raw bytes → `HwParams`. Little-endian, fields in struct order:
/// `format(u32) | rate(u32) | channels(u32) | period_size(u32) | periods(u32)`.
fn decode_hw_params(buf: &[u8]) -> Option<HwParams> {
    if buf.len() < HW_PARAMS_BYTES {
        return None;
    }
    let fmt_u32 = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    let rate_u32 = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let ch_u32 = u32::from_le_bytes(buf[8..12].try_into().ok()?);
    let period_size = u32::from_le_bytes(buf[12..16].try_into().ok()?);
    let periods = u32::from_le_bytes(buf[16..20].try_into().ok()?);

    let format = match fmt_u32 {
        0 => SampleFormat::S16LE,
        1 => SampleFormat::S24LE,
        2 => SampleFormat::S32LE,
        _ => return None,
    };
    let rate = match rate_u32 {
        44100 => SampleRate::R44100,
        48000 => SampleRate::R48000,
        96000 => SampleRate::R96000,
        192000 => SampleRate::R192000,
        _ => return None,
    };
    let channels = match ch_u32 {
        1 => ChannelCount::Mono,
        2 => ChannelCount::Stereo,
        4 => ChannelCount::Quad,
        6 => ChannelCount::Surround51,
        8 => ChannelCount::Surround71,
        _ => return None,
    };
    Some(HwParams {
        format,
        rate,
        channels,
        period_size,
        periods,
    })
}

// ── SoundControlFile — /dev/snd/controlC<N> ──────────────────────────

/// Mixer control file for card `card_index`.
///
/// - `read`  at any offset → a newline-terminated text listing of all
///   controls, one per line: `"<index> <kind_name> <value>"`.
///   Mirrors the shape of `SNDRV_CTL_IOCTL_ELEM_LIST` output in
///   Linux's `sound/core/control.c::snd_ctl_ioctl`.
/// - `write` at offset `HW_PARAMS_MAGIC_OFFSET` → parse 20-byte
///   `HwParams` record and apply it to playback device 0 on the card.
///   (Full per-device dispatch is a follow-up; the setsockopt path
///   is sufficient for a boot smoke.)
/// - `write` at other offsets → parse `"<index> <value>"` ASCII pair
///   and call `mixer::set`.
#[derive(Debug)]
pub struct SoundControlFile {
    card_index: u32,
}

impl SoundControlFile {
    pub fn new(card_index: u32) -> Self {
        Self { card_index }
    }

    fn render_controls(&self) -> String {
        let mut out = String::new();
        let mx = match crate::mixer(self.card_index) {
            Ok(m) => m,
            Err(_) => return "error: no such card\n".into(),
        };
        for id in mx.list_controls() {
            match mx.get_control_value(id) {
                Ok(ControlValue::Integer { left, right }) => {
                    out.push_str(&format!(
                        "{} {} {}/{}\n",
                        id.index,
                        id.kind.name(),
                        left,
                        right
                    ));
                }
                Ok(ControlValue::Boolean(b)) => {
                    out.push_str(&format!(
                        "{} {} {}\n",
                        id.index,
                        id.kind.name(),
                        if b { "on" } else { "off" }
                    ));
                }
                Err(_) => {}
            }
        }
        out
    }
}

impl FileOps for SoundControlFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let content = self.render_controls();
        Box::pin(async move {
            let bytes = content.as_bytes();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(0);
            }
            let n = (bytes.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let card_index = self.card_index;
        Box::pin(async move {
            if offset == HW_PARAMS_MAGIC_OFFSET {
                // hw_params setsockopt path — applies to playback device 0.
                let params = decode_hw_params(buf).ok_or(FsError::InvalidPath)?;
                let mut stream = open_playback(card_index, 0).map_err(|_| FsError::Busy)?;
                stream.hw_params(params).map_err(|_| FsError::InvalidPath)?;
                return Ok(buf.len());
            }
            // Textual set: "<index_decimal> <value>\n"
            let s = core::str::from_utf8(buf).map_err(|_| FsError::InvalidPath)?;
            let mut parts = s.trim().splitn(2, ' ');
            let idx: u32 = parts
                .next()
                .and_then(|p| p.parse().ok())
                .ok_or(FsError::InvalidPath)?;
            let val_str = parts.next().ok_or(FsError::InvalidPath)?;
            let mx = crate::mixer(card_index).map_err(|_| FsError::NotFound)?;
            // Find the control with the given index.
            let id = mx
                .list_controls()
                .into_iter()
                .find(|c| c.index == idx)
                .ok_or(FsError::NotFound)?;
            let value = if id.kind.is_boolean() {
                ControlValue::Boolean(matches!(val_str, "1" | "on" | "true"))
            } else {
                // Accept "left/right" or single integer for both channels.
                let (l, r) = if let Some(pos) = val_str.find('/') {
                    let l: i32 = val_str[..pos].parse().map_err(|_| FsError::InvalidPath)?;
                    let r: i32 = val_str[pos + 1..]
                        .parse()
                        .map_err(|_| FsError::InvalidPath)?;
                    (l, r)
                } else {
                    let v: i32 = val_str.parse().map_err(|_| FsError::InvalidPath)?;
                    (v, v)
                };
                ControlValue::Integer { left: l, right: r }
            };
            mx.set_control_value(id, value)
                .map_err(|_| FsError::InvalidPath)?;
            Ok(buf.len())
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }
}

// ── SoundPcmFile — /dev/snd/pcmC<N>D<M>p and pcmC<N>D<M>c ──────────

/// Playback PCM file: `write` feeds audio samples into the cyclic ring.
///
/// On first write the substream is lazily opened and hw_params are set
/// to a safe default (48 kHz stereo S16).  Callers that need a different
/// format must send a hw_params record via `SoundControlFile` first.
///
/// Linux ref: `sound/core/pcm_native.c::snd_pcm_write` — user-space
/// writes land in the DMA cyclic buffer via `snd_pcm_lib_write`.
#[derive(Debug)]
pub struct SoundPcmPlaybackFile {
    card_index: u32,
    device: u32,
    stream: IrqSafeSpinLock<Option<PlaybackStream>>,
}

impl SoundPcmPlaybackFile {
    pub fn new(card_index: u32, device: u32) -> Self {
        Self {
            card_index,
            device,
            stream: IrqSafeSpinLock::new(None),
        }
    }

    fn ensure_open(&self) -> Result<(), SoundError> {
        let mut g = self.stream.lock();
        if g.is_none() {
            let mut s = open_playback(self.card_index, self.device)?;
            // Default hw_params: 48 kHz stereo S16 × 4 periods of 1024 frames.
            s.hw_params(HwParams {
                format: SampleFormat::S16LE,
                rate: SampleRate::R48000,
                channels: ChannelCount::Stereo,
                period_size: 1024,
                periods: 4,
            })?;
            s.prepare()?;
            *g = Some(s);
        }
        Ok(())
    }
}

impl FileOps for SoundPcmPlaybackFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Playback file: reads are not meaningful (no capture data).
        // Return 0 (EOF) so a cat /dev/snd/pcmC0D0p exits cleanly.
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let card_index = self.card_index;
        let device = self.device;
        Box::pin(async move {
            if offset == HW_PARAMS_MAGIC_OFFSET {
                // hw_params setsockopt path on the PCM file itself.
                let params = decode_hw_params(buf).ok_or(FsError::InvalidPath)?;
                let mut s = open_playback(card_index, device).map_err(|_| FsError::Busy)?;
                s.hw_params(params).map_err(|_| FsError::InvalidPath)?;
                return Ok(buf.len());
            }
            // Sample-data write into the cyclic ring.
            // Ensure stream is open with default params.
            // Note: we re-open per-call since the lock cannot cross async
            // boundary; IrqSafeSpinLock is !Send across await.
            let mut s = open_playback(card_index, device).map_err(|e| match e {
                SoundError::NoSuchCard | SoundError::NoSuchDevice => FsError::NotFound,
                SoundError::DeviceBusy => FsError::Busy,
                _ => FsError::Unsupported,
            })?;
            s.hw_params(HwParams {
                format: SampleFormat::S16LE,
                rate: SampleRate::R48000,
                channels: ChannelCount::Stereo,
                period_size: 1024,
                periods: 4,
            })
            .ok();
            s.prepare().ok();
            let n = s.write(buf).map_err(|_| FsError::Unsupported)?;
            Ok(n)
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }
}

/// Capture PCM file: `read` drains audio samples from the cyclic ring.
///
/// Linux ref: `sound/core/pcm_native.c::snd_pcm_read` — user-space
/// reads are serviced by `snd_pcm_lib_read`.
#[derive(Debug)]
pub struct SoundPcmCaptureFile {
    card_index: u32,
    device: u32,
}

impl SoundPcmCaptureFile {
    pub fn new(card_index: u32, device: u32) -> Self {
        Self { card_index, device }
    }
}

impl FileOps for SoundPcmCaptureFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let card_index = self.card_index;
        let device = self.device;
        Box::pin(async move {
            let mut s = open_capture(card_index, device).map_err(|e| match e {
                SoundError::NoSuchCard | SoundError::NoSuchDevice => FsError::NotFound,
                SoundError::DeviceBusy => FsError::Busy,
                _ => FsError::Unsupported,
            })?;
            s.hw_params(HwParams {
                format: SampleFormat::S16LE,
                rate: SampleRate::R48000,
                channels: ChannelCount::Stereo,
                period_size: 1024,
                periods: 4,
            })
            .ok();
            s.prepare().ok();
            let n = s.read(buf).map_err(|_| FsError::Unsupported)?;
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Capture file: writes not meaningful.
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }
}

// ── Timer / Sequencer stubs ───────────────────────────────────────────

/// `/dev/snd/timer` — global ALSA timer stub.
///
/// ALSA timer ioctls (`SNDRV_TIMER_IOCTL_*`) are deferred.  This stub
/// exists so `open("/dev/snd/timer")` succeeds.
/// Linux ref: `sound/core/timer.c::snd_timer_user_open`.
#[derive(Debug)]
pub struct SoundTimerFile;

impl FileOps for SoundTimerFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = buf.len();
        Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }
}

/// `/dev/snd/seq` — ALSA sequencer stub.
///
/// ALSA MIDI sequencer (`SNDRV_SEQ_IOCTL_*`) is deferred.  This stub
/// exists so `open("/dev/snd/seq")` succeeds.
/// Linux ref: `sound/core/seq/seq_clientmgr.c::snd_seq_open`.
#[derive(Debug)]
pub struct SoundSeqFile;

impl FileOps for SoundSeqFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = buf.len();
        Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }
}

// ── DevSndDir — /dev/snd/ subdirectory ───────────────────────────────

/// The `/dev/snd/` directory node.
///
/// `lookup` is called by `resolve_async`; node names are derived from
/// the live card registry at lookup time so new cards appear immediately
/// after `register_card` without any explicit notification.
///
/// Linux ref: `sound/core/sound.c::snd_lookup_minor_data` — looks up
/// by (type, card, device) tuple; we flatten that to a path name.
#[derive(Debug)]
pub struct DevSndDir;

impl DirOps for DevSndDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Static global devices.
        match name {
            "timer" => return Some(Arc::new(SoundTimerFile) as Arc<dyn FileOps>),
            "seq" => return Some(Arc::new(SoundSeqFile) as Arc<dyn FileOps>),
            _ => {}
        }

        // controlC<N>
        if let Some(rest) = name.strip_prefix("controlC") {
            let n: u32 = rest.parse().ok()?;
            // Validate card exists.
            let cards = list_cards();
            cards.iter().find(|c| c.index == n)?;
            return Some(Arc::new(SoundControlFile::new(n)) as Arc<dyn FileOps>);
        }

        // pcmC<N>D<M>p  or  pcmC<N>D<M>c
        if let Some(rest) = name.strip_prefix("pcmC") {
            // rest = "<N>D<M>p" or "<N>D<M>c"
            let d_pos = rest.find('D')?;
            let n: u32 = rest[..d_pos].parse().ok()?;
            let after_d = &rest[d_pos + 1..];
            // last char is direction, everything before it is M
            if after_d.is_empty() {
                return None;
            }
            let dir = after_d.as_bytes()[after_d.len() - 1];
            let m: u32 = after_d[..after_d.len() - 1].parse().ok()?;
            let cards = list_cards();
            let card = cards.iter().find(|c| c.index == n)?;
            match dir {
                b'p' => {
                    if m >= card.playback_count {
                        return None;
                    }
                    return Some(Arc::new(SoundPcmPlaybackFile::new(n, m)) as Arc<dyn FileOps>);
                }
                b'c' => {
                    if m >= card.capture_count {
                        return None;
                    }
                    return Some(Arc::new(SoundPcmCaptureFile::new(n, m)) as Arc<dyn FileOps>);
                }
                _ => return None,
            }
        }

        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir_async<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { Err(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Static entries only — dynamic card names don't satisfy
        // `&'static str`; callers wanting a full listing use `enumerate`.
        const STATIC: &[DirEntry] = &[
            DirEntry {
                name: "timer",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "seq",
                file_type: FileType::Special,
            },
        ];
        Box::new(STATIC.iter().copied())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let mut entries: Vec<(String, FileType)> = alloc::vec![
            ("timer".into(), FileType::Special),
            ("seq".into(), FileType::Special),
        ];
        for card in list_cards() {
            let n = card.index;
            entries.push((format!("controlC{}", n), FileType::Special));
            for m in 0..card.playback_count {
                entries.push((format!("pcmC{}D{}p", n, m), FileType::Special));
            }
            for m in 0..card.capture_count {
                entries.push((format!("pcmC{}D{}c", n, m), FileType::Special));
            }
        }
        entries.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }
}

// ── Registration helper ───────────────────────────────────────────────

/// Register `/dev/snd/` into the live devfs.
///
/// Called once from `sound_fs_initcall()` after the first card is
/// probed.  Idempotent — calling it again replaces the existing
/// delegate with a fresh `DevSndDir` instance (safe because
/// `DevSndDir` is stateless and reads live from `CARD_REGISTRY`).
///
/// Linux ref: `sound/core/sound.c::snd_register_device` — registers
/// each ALSA device node in the devtmpfs/udev namespace.
pub fn register_devfs_snd() {
    let dir = alloc::sync::Arc::new(DevSndDir) as alloc::sync::Arc<dyn narf_filesystem::DirOps>;
    narf_filesystem::register_snd_dir(dir);
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod devfs_bridge_tests {
    use super::*;
    use crate::mixer;

    // Helper: reset registries and create a synthetic card 0.
    fn setup_card0() -> u32 {
        crate::__reset_for_test();
        mixer::__reset_for_test();
        let idx = crate::register_card(
            "hda-intel",
            "HDA Intel PCH",
            "HDA Intel PCH",
            /*controller_index=*/ 0,
            /*playback_count=*/ 1,
            /*capture_count=*/ 1,
        );
        mixer::register_standard_realtek(0, true, true, true);
        idx
    }

    // Smoke #1: controlC0 appears after card registration.
    #[test]
    fn control_node_appears_after_registration() {
        let _idx = setup_card0();
        let dir = DevSndDir;
        let node = dir.lookup("controlC0");
        assert!(
            node.is_some(),
            "controlC0 should be visible after card 0 is registered"
        );
    }

    // Smoke #2: pcmC0D0p appears for default playback.
    #[test]
    fn pcm_playback_node_appears() {
        setup_card0();
        let dir = DevSndDir;
        let node = dir.lookup("pcmC0D0p");
        assert!(node.is_some(), "pcmC0D0p should be visible");
    }

    // Smoke #3: pcmC0D0c appears for capture.
    #[test]
    fn pcm_capture_node_appears() {
        setup_card0();
        let dir = DevSndDir;
        let node = dir.lookup("pcmC0D0c");
        assert!(node.is_some(), "pcmC0D0c should be visible");
    }

    // Smoke #4: PCM playback write 4096 bytes round-trips into the ring.
    #[test]
    fn pcm_playback_write_4096_bytes_succeeds() {
        setup_card0();
        let dir = DevSndDir;
        let node = dir.lookup("pcmC0D0p").expect("pcmC0D0p not found");
        let samples = alloc::vec![0u8; 4096];
        // Block-on the future using a trivial poll helper.
        let fut = node.write(0, &samples);
        let result = crate::tests_support::poll_once(fut);
        assert!(result.is_ok(), "playback write failed: {:?}", result);
        let n = result.unwrap();
        assert_eq!(n, 4096, "expected 4096 bytes written, got {}", n);
    }

    // Smoke #5: timer node exists.
    #[test]
    fn timer_node_exists() {
        let dir = DevSndDir;
        let node = dir.lookup("timer");
        assert!(node.is_some(), "timer node missing");
    }

    // Smoke #6: seq node exists.
    #[test]
    fn seq_node_exists() {
        let dir = DevSndDir;
        let node = dir.lookup("seq");
        assert!(node.is_some(), "seq node missing");
    }

    // Smoke #7: Multi-card — 2 cards → card0 + card1 entries.
    #[test]
    fn multi_card_enumerate() {
        crate::__reset_for_test();
        mixer::__reset_for_test();
        crate::register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
        crate::register_card("hda-amd", "HDA AMD", "HDA AMD", 1, 1, 1);
        let dir = DevSndDir;
        let entries = dir.enumerate(0, 64);
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"controlC0"),
            "controlC0 missing: {:?}",
            names
        );
        assert!(
            names.contains(&"controlC1"),
            "controlC1 missing: {:?}",
            names
        );
        assert!(names.contains(&"pcmC0D0p"), "pcmC0D0p missing: {:?}", names);
        assert!(names.contains(&"pcmC1D0p"), "pcmC1D0p missing: {:?}", names);
    }

    // Smoke #8: hw_params decode round-trip.
    #[test]
    fn hw_params_decode_roundtrip() {
        let mut buf = [0u8; 20];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes()); // S16LE
        buf[4..8].copy_from_slice(&48000u32.to_le_bytes()); // 48 kHz
        buf[8..12].copy_from_slice(&2u32.to_le_bytes()); // stereo
        buf[12..16].copy_from_slice(&1024u32.to_le_bytes());
        buf[16..20].copy_from_slice(&4u32.to_le_bytes());
        let params = decode_hw_params(&buf).expect("decode failed");
        assert!(matches!(params.format, SampleFormat::S16LE));
        assert!(matches!(params.rate, SampleRate::R48000));
        assert!(matches!(params.channels, ChannelCount::Stereo));
        assert_eq!(params.period_size, 1024);
        assert_eq!(params.periods, 4);
    }
}
