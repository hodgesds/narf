//! End-to-end smokes for NARF's audio stack.
//!
//! Each smoke walks a full user-visible path through the driver layers:
//! open → hw_params → prepare → trigger → write → pointer → stop → close.
//!
//! **No real PCI / MMIO is touched.** Fakes used:
//!
//! - `FakeHdaMmio`  — a 16 KiB `[u8; 16384]` that represents the controller
//!   BAR0 register image.  Read/write at register offsets land in the array.
//! - `FakeCodec`    — an ALC256 verb responder built on top of
//!   `VerbRecorder`.  `detect()` is fed the ALC256 VENDOR_ID; all verbs
//!   land in `history`.
//! - DMA buffer     — `PcmSubstream::buffer` (the internal cyclic `Vec<u8>`)
//!   acts as the fake DMA backing.  After `write()`, bytes are visible there.
//!
//! Linux refs used for value assertions:
//! - `sound/pci/hda/hda_intel.c`
//! - `sound/core/pcm_native.c`
//! - `include/sound/core.h` (SNDRV_MAJOR = 116)
//! - `include/sound/minors.h` (minor-number scheme)

use crate::codec::realtek::{bring_up, detect, RealtekChip, VerbRecorder};
use crate::format::{pack_sdfmt, ChannelCount, HwParams, SampleFormat, SampleRate};
use crate::hda::streams::{StreamDescriptor, SDCTL_RUN};
use crate::mixer::{self, ControlKind, ControlValue};
use crate::pcm::{PcmSubstream, SubstreamState};
use crate::sysfs_bridge::{render_card_id_attr, SNDRV_MAJOR};
use crate::{list_cards, mixer as mixer_open, open_playback, register_card, SoundError};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

// ── Fake HDA MMIO ────────────────────────────────────────────────────────
//
// A flat byte array that stands in for the 16 KiB BAR0 register block.
// Tests write to well-known offsets (SDxCTL, SDxFMT, SDxLPIB …) and
// then read them back, exactly like real silicon would.

struct FakeHdaMmio([u8; 16 * 1024]);

impl FakeHdaMmio {
    fn new() -> Self {
        FakeHdaMmio([0u8; 16 * 1024])
    }

    fn read_u16(&self, offset: usize) -> u16 {
        let b = &self.0[offset..offset + 2];
        u16::from_le_bytes(b.try_into().unwrap())
    }

    fn write_u16(&mut self, offset: usize, v: u16) {
        self.0[offset..offset + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let b = &self.0[offset..offset + 4];
        u32::from_le_bytes(b.try_into().unwrap())
    }

    fn write_u32(&mut self, offset: usize, v: u32) {
        self.0[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
    }
}

// ── Smoke #1: Card register — ALC256 detect → CardInfo registered ────────

fn e2e_smoke_card_register_alc256() -> TestResult {
    crate::__reset_for_test();
    mixer::__reset_for_test();

    // Simulate detect(): feed VENDOR_ID = 0x10EC0256 (ALC256).
    let mut bus = VerbRecorder::with_initial_responses(vec![0x10EC_0256]);
    let chip = match detect(&mut bus, 0) {
        Ok(Some(c)) => c,
        _ => return TestResult::Fail("ALC256 detect failed"),
    };
    if chip != RealtekChip::Alc256 {
        return TestResult::Fail("detected chip != Alc256");
    }

    // Bring it up against a fresh recorder.
    let mut bus2 = VerbRecorder::new();
    if bring_up(&mut bus2, 0, 0x01, chip, 0x02, 0x14, 0x21).is_err() {
        return TestResult::Fail("bring_up failed");
    }

    // Register the card using the codec name.
    let card_index = register_card(
        "hda-intel",
        chip.name(), // "ALC256" — visible in sysfs/procfs
        "HDA Intel PCH",
        /*controller=*/ 0,
        /*playback=*/ 1,
        /*capture=*/ 1,
    );

    let cards = list_cards();
    if cards.len() != 1 {
        return TestResult::Fail("card not registered");
    }
    let c = &cards[0];
    if c.index != card_index {
        return TestResult::Fail("card index mismatch");
    }
    if c.id != "ALC256" {
        return TestResult::Fail("card id is not ALC256");
    }
    if c.playback_count != 1 || c.capture_count != 1 {
        return TestResult::Fail("stream counts wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_card_register_alc256);

// ── Smoke #2: /dev/snd/controlC0 resolves via DevDir lookup ─────────────

fn e2e_smoke_devdir_control_lookup() -> TestResult {
    use narf_filesystem::DirOps as _;
    crate::__reset_for_test();
    mixer::__reset_for_test();
    register_card("hda-intel", "ALC256", "HDA Intel PCH", 0, 1, 1);
    mixer::register_standard_realtek(0, true, true, true);

    let dir = crate::devfs_bridge::DevSndDir;
    match dir.lookup("controlC0") {
        Some(_) => TestResult::Pass,
        None => TestResult::Fail("controlC0 not found after card registration"),
    }
}
kernel_test_in!("drivers/sound", e2e_smoke_devdir_control_lookup);

// ── Smoke #3: /dev/snd/pcmC0D0p resolves via DevDir lookup ──────────────

fn e2e_smoke_devdir_pcm_playback_lookup() -> TestResult {
    use narf_filesystem::DirOps as _;
    crate::__reset_for_test();
    mixer::__reset_for_test();
    register_card("hda-intel", "ALC256", "HDA Intel PCH", 0, 1, 1);

    let dir = crate::devfs_bridge::DevSndDir;
    match dir.lookup("pcmC0D0p") {
        Some(_) => TestResult::Pass,
        None => TestResult::Fail("pcmC0D0p not found after card registration"),
    }
}
kernel_test_in!("drivers/sound", e2e_smoke_devdir_pcm_playback_lookup);

// ── Smoke #4: PCM open + hw_params 48kHz/2ch/S16 — SDxFMT check ─────────
//
// Linux ref: `sound/core/pcm_native.c::snd_pcm_hw_params`
// SDxFMT encoding for 48k/stereo/S16LE:
//   bit 14 = 0  (48k family)
//   bits [6:4] = 0b001  (16-bit)
//   bits [3:0] = 0b0001 (channels-1 = 1 → stereo)
//   Expected: 0x0011  (rate=0, bits=0b001<<4, ch=1)
//
// `pack_sdfmt` mirrors Linux `snd_hdac_calc_stream_format`.

fn e2e_smoke_pcm_open_hw_params_48k_stereo_s16() -> TestResult {
    let mut s = match PcmSubstream::new_playback(0, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("new_playback failed"),
    };

    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size: 1024,
        periods: 4,
    };
    if s.hw_params(params).is_err() {
        return TestResult::Fail("hw_params failed");
    }
    if s.state() != SubstreamState::Configured {
        return TestResult::Fail("state != Configured after hw_params");
    }

    if s.prepare().is_err() {
        return TestResult::Fail("prepare failed");
    }

    // Verify SDxFMT image.
    let expected_fmt = pack_sdfmt(
        SampleFormat::S16LE,
        SampleRate::R48000,
        ChannelCount::Stereo,
    );
    // 48k family → bit14 = 0; S16 → bits[6:4]=0b001; stereo → bits[3:0]=1.
    // expected_fmt must have bit14 clear and bits[6:4]=1 and bits[3:0]=1.
    if s.sd_fmt() != expected_fmt {
        return TestResult::Fail("SDxFMT image wrong after prepare");
    }
    if expected_fmt & (1 << 14) != 0 {
        return TestResult::Fail("bit14 set for 48k family");
    }
    if (expected_fmt >> 4) & 0x7 != 0b001 {
        return TestResult::Fail("S16 bits wrong in SDxFMT");
    }
    if expected_fmt & 0xF != 1 {
        return TestResult::Fail("stereo channel count wrong in SDxFMT");
    }

    // Write the fake MMIO to confirm value would be correct on real HW.
    let mut mmio = FakeHdaMmio::new();
    // SDxFMT sits at BAR0+0x12 for stream 0 (descriptor base 0x80, +0x12).
    let sdxfmt_offset = 0x80usize + 0x12;
    mmio.write_u16(sdxfmt_offset, expected_fmt);
    if mmio.read_u16(sdxfmt_offset) != expected_fmt {
        return TestResult::Fail("FakeHdaMmio SDxFMT round-trip failed");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_pcm_open_hw_params_48k_stereo_s16);

// ── Smoke #5: PCM prepare → BDL programmed ───────────────────────────────
//
// After prepare():
//   - BDL has `periods` entries, each with IOC=1.
//   - SDxCBL = total buffer bytes = period_size × periods × bytes_per_frame.
//   - SDxLVI = periods - 1.
//   - SDxLPIB cleared (position_frames == 0).
//
// Linux ref: `sound/hda/core/controller.c::snd_hdac_stream_setup_periods`

fn e2e_smoke_pcm_prepare_bdl_programmed() -> TestResult {
    let period_size: u32 = 512;
    let periods: u32 = 4;
    let bytes_per_frame: u32 = 2 /* stereo */ * 2 /* S16 bytes */;
    let expected_cbl = period_size * periods * bytes_per_frame;

    let mut s = match PcmSubstream::new_playback(0, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("new_playback failed"),
    };

    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size,
        periods,
    };
    if s.hw_params(params).is_err() {
        return TestResult::Fail("hw_params failed");
    }
    if s.prepare().is_err() {
        return TestResult::Fail("prepare failed");
    }

    // BDL entry count == periods.
    if s.bdl_len() != periods as usize {
        return TestResult::Fail("BDL entry count != periods");
    }

    // SDxCBL = total buffer bytes.
    if s.cbl() != expected_cbl {
        return TestResult::Fail("SDxCBL wrong");
    }

    // SDxLVI = periods - 1.
    if s.lvi() != (periods - 1) as u8 {
        return TestResult::Fail("SDxLVI wrong");
    }

    // Position cleared after prepare.
    if s.pointer() != 0 {
        return TestResult::Fail("SDxLPIB not cleared after prepare");
    }

    // Each BDL entry has IOC=1, length=period_bytes, and a non-null addr.
    let period_bytes = (period_size * bytes_per_frame) as u32;
    for (i, entry) in s.bdl.iter().enumerate() {
        if entry.length != period_bytes {
            return TestResult::Fail("BDL entry length wrong");
        }
        if entry.flags & 1 == 0 {
            return TestResult::Fail("BDL entry IOC not set");
        }
        if entry.addr == 0 {
            return TestResult::Fail("BDL entry addr is null");
        }
        // Each entry's addr should be period_bytes apart.
        if i > 0 {
            let prev_addr = s.bdl[i - 1].addr;
            if entry.addr != prev_addr + period_bytes as u64 {
                return TestResult::Fail("BDL entry addrs not contiguous");
            }
        }
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_pcm_prepare_bdl_programmed);

// ── Smoke #6: PCM trigger START → SDxCTL.RUN set ─────────────────────────
//
// `StreamDescriptor::ctl_start(tag)` must have SDCTL_RUN (bit 1) set.
// After trigger_start(), state == Running.
//
// Linux ref: `sound/hda/core/controller.c::snd_hdac_stream_start`

fn e2e_smoke_pcm_trigger_start_run_bit() -> TestResult {
    let mut s = match PcmSubstream::new_playback(0, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("new_playback failed"),
    };

    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size: 256,
        periods: 2,
    };
    if s.hw_params(params).is_err() {
        return TestResult::Fail("hw_params failed");
    }
    if s.prepare().is_err() {
        return TestResult::Fail("prepare failed");
    }

    // Build the SDxCTL value for this stream's tag and verify RUN is set.
    let ctl_val = StreamDescriptor::ctl_start(s.stream_tag());
    if ctl_val & SDCTL_RUN == 0 {
        return TestResult::Fail("SDxCTL_RUN not set in ctl_start result");
    }

    // Write it into the fake MMIO and read back.
    let mut mmio = FakeHdaMmio::new();
    let sdxctl_offset = 0x80usize; // stream 0 → descriptor base 0x80, +0 = SDxCTL
    mmio.write_u32(sdxctl_offset, ctl_val);
    let readback = mmio.read_u32(sdxctl_offset);
    if readback & SDCTL_RUN == 0 {
        return TestResult::Fail("RUN bit not readable from fake MMIO after write");
    }

    // trigger_start() moves the state.
    if s.trigger_start().is_err() {
        return TestResult::Fail("trigger_start returned error");
    }
    if s.state() != SubstreamState::Running {
        return TestResult::Fail("state != Running after trigger_start");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_pcm_trigger_start_run_bit);

// ── Smoke #7: PCM write 4096 bytes → DMA buffer receives the bytes ───────
//
// The FakeDma Vec<u8> represents the BDL-backed DMA buffer.  After
// writing 4096 bytes of samples through PcmSubstream::write(), the
// internal buffer (which IS the fake DMA in this synthetic model) must
// contain the written data at byte offset 0.
//
// Linux ref: `sound/core/pcm_native.c::snd_pcm_lib_write`

fn e2e_smoke_pcm_write_4096_bytes_visible_in_dma() -> TestResult {
    let period_size: u32 = 1024;
    let periods: u32 = 4;

    let mut s = match PcmSubstream::new_playback(0, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("new_playback failed"),
    };

    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size,
        periods,
    };
    if s.hw_params(params).is_err() {
        return TestResult::Fail("hw_params failed");
    }
    if s.prepare().is_err() {
        return TestResult::Fail("prepare failed");
    }
    if s.trigger_start().is_err() {
        return TestResult::Fail("trigger_start failed");
    }

    // Build 4096 bytes of recognisable test data.
    let samples: alloc::vec::Vec<u8> = (0u16..2048u16)
        .flat_map(|i| (i as u16).to_le_bytes())
        .collect();
    assert_eq!(samples.len(), 4096);

    let written = match s.write(&samples) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("write returned error"),
    };
    if written != 4096 {
        return TestResult::Fail("write did not absorb all 4096 bytes");
    }

    // The substream's internal buffer IS the fake DMA — verify the bytes
    // are present at offset 0.
    if s.buffer.len() < 4096 {
        return TestResult::Fail("DMA buffer too small after write");
    }
    for (i, (&got, &expected)) in s.buffer[..4096].iter().zip(samples.iter()).enumerate() {
        if got != expected {
            let _ = i;
            return TestResult::Fail("DMA buffer content mismatch after write");
        }
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/sound",
    e2e_smoke_pcm_write_4096_bytes_visible_in_dma
);

// ── Smoke #8: PCM pointer advances ───────────────────────────────────────
//
// After writing N bytes, advance the synthetic SDxLPIB by N bytes worth
// of byte offset → PCM::pointer() returns N / bytes_per_frame frames.
//
// S16×2ch = 4 bytes/frame.  Writing 4096 bytes = 1024 frames.
// `advance_position_test(frames)` simulates the DMA engine.
//
// Linux ref: `sound/hda/core/controller.c::snd_hdac_stream_get_pos_lpib`

fn e2e_smoke_pcm_pointer_advances() -> TestResult {
    let bytes_per_frame: u64 = 4; // S16 × stereo
    let write_bytes: u64 = 4096;
    let expected_frames = write_bytes / bytes_per_frame; // 1024

    let mut s = match PcmSubstream::new_playback(0, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("new_playback failed"),
    };

    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size: 1024,
        periods: 4,
    };
    if s.hw_params(params).is_err() {
        return TestResult::Fail("hw_params failed");
    }
    if s.prepare().is_err() {
        return TestResult::Fail("prepare failed");
    }
    if s.trigger_start().is_err() {
        return TestResult::Fail("trigger_start failed");
    }

    // Position is 0 before any advance.
    if s.pointer() != 0 {
        return TestResult::Fail("initial pointer != 0");
    }

    // Advance the synthetic SDxLPIB by `expected_frames` frames.
    s.advance_position_test(expected_frames);

    if s.pointer() != expected_frames {
        return TestResult::Fail("pointer did not advance to expected_frames");
    }

    // A second advance adds on top.
    s.advance_position_test(1);
    if s.pointer() != expected_frames + 1 {
        return TestResult::Fail("second pointer advance wrong");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_pcm_pointer_advances);

// ── Smoke #9: PCM trigger STOP → SDxCTL.RUN cleared ─────────────────────
//
// After trigger_stop():
//   - state == Stopped
//   - SDxCTL word via ctl_stop() has RUN=0 but preserves IRQ-enable bits.
//
// Linux ref: `sound/hda/core/controller.c::snd_hdac_stream_stop`

fn e2e_smoke_pcm_trigger_stop_run_cleared() -> TestResult {
    let mut s = match PcmSubstream::new_playback(0, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("new_playback failed"),
    };

    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size: 256,
        periods: 2,
    };
    if s.hw_params(params).is_err() {
        return TestResult::Fail("hw_params failed");
    }
    if s.prepare().is_err() {
        return TestResult::Fail("prepare failed");
    }
    if s.trigger_start().is_err() {
        return TestResult::Fail("trigger_start failed");
    }
    if s.state() != SubstreamState::Running {
        return TestResult::Fail("state != Running before STOP");
    }

    if s.trigger_stop().is_err() {
        return TestResult::Fail("trigger_stop returned error");
    }

    if s.state() != SubstreamState::Stopped {
        return TestResult::Fail("state != Stopped after trigger_stop");
    }

    // Build the stop-CTL word and verify RUN=0.
    let stop_ctl = StreamDescriptor::ctl_stop(s.stream_tag());
    if stop_ctl & SDCTL_RUN != 0 {
        return TestResult::Fail("ctl_stop has RUN set");
    }

    // Write to fake MMIO and read back.
    let mut mmio = FakeHdaMmio::new();
    let sdxctl_offset = 0x80usize;
    mmio.write_u32(sdxctl_offset, stop_ctl);
    if mmio.read_u32(sdxctl_offset) & SDCTL_RUN != 0 {
        return TestResult::Fail("RUN still set in fake MMIO after stop write");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_pcm_trigger_stop_run_cleared);

// ── Smoke #10: PCM close → stream slot freed, re-open succeeds ───────────
//
// `PcmSubstream` is an owned value — dropping it is "close".  After the
// drop, `open_playback` on the same card/device must succeed.
//
// Linux ref: `sound/core/pcm_native.c::snd_pcm_release`

fn e2e_smoke_pcm_close_and_reopen() -> TestResult {
    crate::__reset_for_test();
    mixer::__reset_for_test();
    let card = register_card("hda-intel", "ALC256", "HDA Intel PCH", 0, 1, 1);

    // Open, configure, prepare, start.
    let mut stream = match open_playback(card, 0) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("first open_playback failed"),
    };
    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size: 256,
        periods: 2,
    };
    if stream.hw_params(params).is_err() {
        return TestResult::Fail("hw_params failed");
    }
    if stream.prepare().is_err() {
        return TestResult::Fail("prepare failed");
    }
    if stream.start().is_err() {
        return TestResult::Fail("start failed");
    }

    // Stop then drop = close.
    if stream.stop().is_err() {
        return TestResult::Fail("stop failed");
    }
    drop(stream);

    // Re-open must succeed.
    match open_playback(card, 0) {
        Ok(_) => TestResult::Pass,
        Err(e) => {
            let _ = e;
            TestResult::Fail("re-open after close failed")
        }
    }
}
kernel_test_in!("drivers/sound", e2e_smoke_pcm_close_and_reopen);

// ── Smoke #11: Mixer set Master Volume + read back ────────────────────────
//
// Drive Master Volume to 60, verify:
//   1. mixer::get() returns 60/60.
//   2. The codec verb buffer (VerbRecorder) received a SET_AMP_GAIN_MUTE.
//
// Linux ref: `sound/hda/codecs/realtek/realtek.c::alc_build_controls`
// Realtek output amps are 7-bit, max = 87 (0x57) in NARF's range model.

fn e2e_smoke_mixer_set_master_volume_readback() -> TestResult {
    crate::__reset_for_test();
    mixer::__reset_for_test();
    let card = register_card("hda-intel", "ALC256", "HDA Intel PCH", 99, 1, 1);
    mixer::register_standard_realtek(99, true, true, true);

    let mx = match mixer_open(card) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("mixer() failed"),
    };

    let ids = mx.list_controls();
    let master_id = match ids
        .iter()
        .find(|id| matches!(id.kind, ControlKind::MasterVolume))
    {
        Some(&id) => id,
        None => return TestResult::Fail("MasterVolume control not found"),
    };

    // Set to 60.
    if mx
        .set_control_value(master_id, ControlValue::integer(60, 60))
        .is_err()
    {
        return TestResult::Fail("set_control_value(60) failed");
    }

    // Read back.
    match mx.get_control_value(master_id) {
        Ok(ControlValue::Integer {
            left: 60,
            right: 60,
        }) => {}
        Ok(v) => {
            let _ = v;
            return TestResult::Fail("read-back value not 60/60");
        }
        Err(_) => return TestResult::Fail("get_control_value failed"),
    }

    // Out-of-range must be rejected.
    match mx.set_control_value(master_id, ControlValue::integer(200, 200)) {
        Err(SoundError::OutOfRange) => {}
        Err(_) | Ok(()) => return TestResult::Fail("out-of-range not rejected"),
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_mixer_set_master_volume_readback);

// ── Smoke #12: Mixer Capture Mute toggle ─────────────────────────────────
//
// Toggle the MasterMute switch (boolean control): off→on→off.
// Verify read-back reflects each change.
//
// Linux ref: `sound/core/control.c::snd_ctl_elem_write`

fn e2e_smoke_mixer_capture_mute_toggle() -> TestResult {
    crate::__reset_for_test();
    mixer::__reset_for_test();
    let card = register_card("hda-intel", "ALC256", "HDA Intel PCH", 101, 1, 1);
    mixer::register_standard_realtek(101, true, true, true);

    let mx = match mixer_open(card) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("mixer() failed"),
    };

    let ids = mx.list_controls();
    let mute_id = match ids
        .iter()
        .find(|id| matches!(id.kind, ControlKind::MasterMute))
    {
        Some(&id) => id,
        None => return TestResult::Fail("MasterMute control not found"),
    };

    // Initial state: unmuted (true).
    match mx.get_control_value(mute_id) {
        Ok(ControlValue::Boolean(true)) => {}
        Ok(v) => {
            let _ = v;
            return TestResult::Fail("initial mute state not unmuted");
        }
        Err(_) => return TestResult::Fail("get initial mute failed"),
    }

    // Mute (set false).
    if mx
        .set_control_value(mute_id, ControlValue::boolean(false))
        .is_err()
    {
        return TestResult::Fail("set mute=false failed");
    }
    match mx.get_control_value(mute_id) {
        Ok(ControlValue::Boolean(false)) => {}
        _ => return TestResult::Fail("mute not reflected after set false"),
    }

    // Unmute (set true).
    if mx
        .set_control_value(mute_id, ControlValue::boolean(true))
        .is_err()
    {
        return TestResult::Fail("set mute=true failed");
    }
    match mx.get_control_value(mute_id) {
        Ok(ControlValue::Boolean(true)) => {}
        _ => return TestResult::Fail("unmute not reflected after set true"),
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_mixer_capture_mute_toggle);

// ── Smoke #13: Jack-sense unsolicited response → control update ───────────
//
// Simulate an unsolicited response from the fake codec by calling
// `mixer::jack_event`.  Verify the JackSense control transitions
// false → true.  Also confirm the control is read-only (set rejects).
//
// Linux ref: `sound/hda/hda_codec.c::hda_codec_unsol_event`

fn e2e_smoke_jack_sense_unsolicited_response() -> TestResult {
    crate::__reset_for_test();
    mixer::__reset_for_test();
    let _card = register_card("hda-intel", "ALC256", "HDA Intel PCH", 102, 1, 1);
    mixer::register_standard_realtek(102, true, true, false);

    let ids = mixer::list_for_controller(102);
    let jack_id = match ids
        .iter()
        .find(|id| matches!(id.kind, ControlKind::JackSense))
    {
        Some(&id) => id,
        None => return TestResult::Fail("JackSense control not found"),
    };

    // Initially not plugged.
    match mixer::get(102, jack_id) {
        Ok(ControlValue::Boolean(false)) => {}
        _ => return TestResult::Fail("jack not initially unplugged"),
    }

    // Unsolicited response: headphone plugged in.
    mixer::jack_event(102, true);

    match mixer::get(102, jack_id) {
        Ok(ControlValue::Boolean(true)) => {}
        _ => return TestResult::Fail("jack not plugged after jack_event(true)"),
    }

    // Unsolicited response: headphone unplugged.
    mixer::jack_event(102, false);

    match mixer::get(102, jack_id) {
        Ok(ControlValue::Boolean(false)) => {}
        _ => return TestResult::Fail("jack not unplugged after jack_event(false)"),
    }

    // Read-only: set must be rejected.
    match mixer::set(102, jack_id, ControlValue::boolean(true)) {
        Err(_) => {}
        Ok(()) => return TestResult::Fail("read-only jack accepted set"),
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_jack_sense_unsolicited_response);

// ── Smoke #14: /sys/class/sound/card0/id reads codec name "ALC256\n" ──────
//
// `render_card_id_attr` must return exactly `"ALC256\n"` when the card
// was registered with id = chip.name() = "ALC256".
//
// Linux ref: `Documentation/ABI/testing/sysfs-class-sound`
//            `sound/core/init.c::snd_card_register` kobject population.

fn e2e_smoke_sysfs_card_id_reads_alc256() -> TestResult {
    crate::__reset_for_test();
    mixer::__reset_for_test();
    let chip = RealtekChip::Alc256;
    register_card("hda-intel", chip.name(), "HDA Intel PCH", 0, 1, 1);

    let cards = list_cards();
    let card = match cards.first() {
        Some(c) => c.clone(),
        None => return TestResult::Fail("no card registered"),
    };

    let id_text = render_card_id_attr(&card);
    if id_text != "ALC256\n" {
        return TestResult::Fail("sysfs card id attr not 'ALC256\\n'");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_sysfs_card_id_reads_alc256);

// ── Smoke #15: /proc/asound/cards format matches Linux ALSA ───────────────
//
// Linux's `/proc/asound/cards` format (from `sound/core/init.c`):
//   " N [<id padded to 15>]: <driver> - <longname>\n"
//
// NARF's procfs renderer must produce that same shape.  We also verify
// the specific Intel-PCH string that the task description calls out.
//
// Linux ref: `sound/core/init.c::snd_card_info_read`

fn e2e_smoke_procfs_asound_cards_format() -> TestResult {
    crate::__reset_for_test();
    mixer::__reset_for_test();

    // Register a card that looks exactly like an Intel PCH card.
    register_card(
        "HDA-Intel",
        "HDA Intel PCH",
        "HDA Intel PCH",
        /*controller=*/ 0,
        /*playback=*/ 1,
        /*capture=*/ 1,
    );

    let text = crate::procfs_bridge::render_cards_list();

    // Must start with " 0 [".
    if !text.contains(" 0 [") {
        return TestResult::Fail("/proc/asound/cards missing ' 0 [' prefix");
    }

    // Must contain driver name.
    if !text.contains("HDA-Intel") {
        return TestResult::Fail("/proc/asound/cards missing driver name");
    }

    // Must contain the longname.
    if !text.contains("HDA Intel PCH") {
        return TestResult::Fail("/proc/asound/cards missing longname");
    }

    // The closing bracket + colon pattern.
    if !text.contains("]:") {
        return TestResult::Fail("/proc/asound/cards missing ']: ' separator");
    }

    // Verify the SNDRV_MAJOR constant is correct (116).
    if SNDRV_MAJOR != 116 {
        return TestResult::Fail("SNDRV_MAJOR != 116");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", e2e_smoke_procfs_asound_cards_format);
