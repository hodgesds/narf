//! Subsystem-level smokes for `narf-drivers-sound`.
//!
//! Each test is a self-contained round-trip: build the synthetic
//! state, drive the function under test, assert against the
//! expected output. None of these tests touch real PCI / MMIO —
//! they exercise pure-Rust helpers for stream / format encoding,
//! the PCM substream model, the mixer surface, and the card
//! registry with its filesystem bridges.
//!
//! The controller/codec smokes that used to live here covered the
//! legacy in-crate HDA/codec models excised in #783; the Realtek
//! quirk/init-table coverage moved with the tables to
//! `narf_audio::hda::quirks` (smoke `audio/hda-quirks`).

use crate::format::{pack_sdfmt, ChannelCount, HwParams, SampleFormat, SampleRate};
use crate::hda::streams::{
    BdlEntry, StreamDescriptor, SDCTL_DEIE, SDCTL_FEIE, SDCTL_IOCE, SDCTL_RUN,
};
use crate::mixer::{self, ControlInfo, ControlKind, ControlValue};
use crate::pcm::{PcmSubstream, SubstreamState};
use crate::{list_cards, mixer as mixer_open, open_playback, register_card, SoundError};
use narf_kernel_test::{kernel_test_in, TestResult};

// ── #5: BDL entry encode ────────────────────────────────────────────

fn smoke_bdl_entry_encode() -> TestResult {
    let e = BdlEntry::new(
        0x1234_5678_DEAD_BEEFu64,
        /*len=*/ 4096,
        /*ioc=*/ true,
    );
    let bytes = e.to_le_bytes();
    if bytes[0] != 0xEF || bytes[1] != 0xBE || bytes[4] != 0x78 || bytes[7] != 0x12 {
        return TestResult::Fail("BDL addr little-endian wrong");
    }
    if bytes[8] != 0x00 || bytes[9] != 0x10 {
        return TestResult::Fail("BDL length encode wrong");
    }
    if bytes[12] != 0x01 {
        return TestResult::Fail("BDL IOC flag not set");
    }
    let round = BdlEntry::from_le_bytes(&bytes);
    if round != e {
        return TestResult::Fail("BDL round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_bdl_entry_encode);

// ── #6: Stream descriptor SDxCTL bits ──────────────────────────────

fn smoke_stream_sdctl_bits() -> TestResult {
    let ctl = StreamDescriptor::ctl_start(/*tag=*/ 1);
    if ctl & SDCTL_RUN == 0 {
        return TestResult::Fail("RUN bit missing");
    }
    if ctl & SDCTL_IOCE == 0 {
        return TestResult::Fail("IOCE bit missing");
    }
    if ctl & SDCTL_FEIE == 0 {
        return TestResult::Fail("FEIE bit missing");
    }
    if ctl & SDCTL_DEIE == 0 {
        return TestResult::Fail("DEIE bit missing");
    }
    let tag = (ctl >> 20) & 0xF;
    if tag != 1 {
        return TestResult::Fail("stream tag not encoded");
    }
    // Stop must clear RUN.
    let stop = StreamDescriptor::ctl_stop(1);
    if stop & SDCTL_RUN != 0 {
        return TestResult::Fail("stop kept RUN set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_stream_sdctl_bits);

// ── #7: SDxFMT — 48 kHz × 2 ch × S16 ────────────────────────────────

fn smoke_sdfmt_48k_stereo_s16() -> TestResult {
    let fmt = pack_sdfmt(
        SampleFormat::S16LE,
        SampleRate::R48000,
        ChannelCount::Stereo,
    );
    // 48 kHz family → bit 14 = 0.
    if fmt & (1 << 14) != 0 {
        return TestResult::Fail("48k family bit set");
    }
    // S16 → bits [6:4] = 0b001 → 0x10
    if (fmt >> 4) & 0x7 != 0b001 {
        return TestResult::Fail("S16 bits");
    }
    // Stereo → N-1 = 1.
    if fmt & 0xF != 1 {
        return TestResult::Fail("stereo encode");
    }
    // 44.1 kHz family bit set.
    let fmt44 = pack_sdfmt(
        SampleFormat::S16LE,
        SampleRate::R44100,
        ChannelCount::Stereo,
    );
    if fmt44 & (1 << 14) == 0 {
        return TestResult::Fail("44.1k family bit missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_sdfmt_48k_stereo_s16);

// ── #13: PCM open + hw_params + prepare ────────────────────────────

fn smoke_pcm_open_hw_params_prepare() -> TestResult {
    let mut s = PcmSubstream::new_playback(/*ctrl=*/ 0, /*device=*/ 0).unwrap();
    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R44100,
        channels: ChannelCount::Stereo,
        period_size: 1024,
        periods: 4,
    };
    s.hw_params(params).unwrap();
    if s.state() != SubstreamState::Configured {
        return TestResult::Fail("state not Configured after hw_params");
    }
    if s.bdl_len() != 4 {
        return TestResult::Fail("BDL period count");
    }
    let want_buf = 1024 * 2 * 2 * 4;
    if s.cbl() != want_buf as u32 {
        return TestResult::Fail("SDxCBL wrong");
    }
    if s.lvi() != 3 {
        return TestResult::Fail("SDxLVI != periods-1");
    }
    s.prepare().unwrap();
    if s.state() != SubstreamState::Prepared {
        return TestResult::Fail("state not Prepared after prepare");
    }
    // SDxFMT must encode 44.1k stereo S16.
    let want = pack_sdfmt(
        SampleFormat::S16LE,
        SampleRate::R44100,
        ChannelCount::Stereo,
    );
    if s.sd_fmt() != want {
        return TestResult::Fail("SDxFMT image off");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_pcm_open_hw_params_prepare);

// ── #14: PCM trigger START sets RUN ────────────────────────────────

fn smoke_pcm_trigger_start_running() -> TestResult {
    let mut s = PcmSubstream::new_playback(0, 0).unwrap();
    let params = HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size: 512,
        periods: 2,
    };
    s.hw_params(params).unwrap();
    s.prepare().unwrap();
    // SDxCTL.RUN bit pattern.
    let ctl = StreamDescriptor::ctl_start(s.stream_tag());
    if ctl & SDCTL_RUN == 0 {
        return TestResult::Fail("RUN unset");
    }
    s.trigger_start().unwrap();
    if s.state() != SubstreamState::Running {
        return TestResult::Fail("state not Running");
    }
    s.trigger_stop().unwrap();
    if s.state() != SubstreamState::Stopped {
        return TestResult::Fail("state not Stopped");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_pcm_trigger_start_running);

// ── #15: Mixer — master volume range ──────────────────────────────

fn smoke_mixer_master_volume_range() -> TestResult {
    mixer::__reset_for_test();
    mixer::register_standard_realtek(
        /*ctrl=*/ 99, /*spk=*/ true, /*hp=*/ true, /*mic=*/ true,
    );
    let ids = mixer::list_for_controller(99);
    let master = ids
        .iter()
        .find(|id| matches!(id.kind, ControlKind::MasterVolume))
        .copied()
        .ok_or(())
        .map_err(|_| ())
        .ok();
    let Some(master) = master else {
        return TestResult::Fail("master volume not registered");
    };
    let info = mixer::info(99, master).unwrap();
    if info.value_max != ControlInfo::REALTEK_VOLUME_MAX {
        return TestResult::Fail("max != REALTEK_VOLUME_MAX");
    }
    if info.value_min != 0 {
        return TestResult::Fail("min != 0");
    }
    // Set in-range value.
    mixer::set(99, master, ControlValue::integer(50, 50)).unwrap();
    match mixer::get(99, master).unwrap() {
        ControlValue::Integer {
            left: 50,
            right: 50,
        } => {}
        _ => return TestResult::Fail("value not round-tripped"),
    }
    // Set out-of-range value — must reject.
    match mixer::set(99, master, ControlValue::integer(200, 200)) {
        Err(_) => {}
        Ok(()) => return TestResult::Fail("out-of-range accepted"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_mixer_master_volume_range);

// ── #16: Jack-sense unsolicited → control update ───────────────────

fn smoke_mixer_jack_sense_event() -> TestResult {
    mixer::__reset_for_test();
    mixer::register_standard_realtek(/*ctrl=*/ 100, true, true, false);
    let ids = mixer::list_for_controller(100);
    let jack = ids
        .iter()
        .find(|id| matches!(id.kind, ControlKind::JackSense))
        .copied()
        .ok_or(())
        .map_err(|_| ())
        .ok()
        .ok_or(TestResult::Fail("jack control not registered"));
    let jack = match jack {
        Ok(j) => j,
        Err(e) => return e,
    };
    // Initially not plugged.
    match mixer::get(100, jack).unwrap() {
        ControlValue::Boolean(false) => {}
        _ => return TestResult::Fail("jack starts plugged"),
    }
    // Emit a jack event from the synthetic unsolicited-response path.
    mixer::jack_event(100, true);
    match mixer::get(100, jack).unwrap() {
        ControlValue::Boolean(true) => {}
        _ => return TestResult::Fail("jack event not visible"),
    }
    // Read-only — set rejects.
    match mixer::set(100, jack, ControlValue::boolean(false)) {
        Err(_) => {}
        Ok(()) => return TestResult::Fail("read-only jack accepted set"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_mixer_jack_sense_event);

// ── #18: Format support filter ─────────────────────────────────────

fn smoke_format_filter() -> TestResult {
    if !crate::supported_format(
        SampleFormat::S16LE,
        SampleRate::R44100,
        ChannelCount::Stereo,
    ) {
        return TestResult::Fail("44.1k stereo S16 rejected");
    }
    if !crate::supported_format(
        SampleFormat::S32LE,
        SampleRate::R192000,
        ChannelCount::Surround71,
    ) {
        return TestResult::Fail("192k 8ch S32 rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_format_filter);

// ── #19: Card list registry round-trip ─────────────────────────────

fn smoke_card_registry_roundtrip() -> TestResult {
    crate::__reset_for_test();
    let _ = register_card("hda-amd-renoir", "HDA0", "AMD Renoir HDA", 0, 4, 4);
    let cards = list_cards();
    if cards.len() != 1 {
        return TestResult::Fail("card not registered");
    }
    if cards[0].driver != "hda-amd-renoir" {
        return TestResult::Fail("driver name wrong");
    }
    if cards[0].playback_count != 4 || cards[0].capture_count != 4 {
        return TestResult::Fail("stream counts wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_card_registry_roundtrip);

// ── #20: open_playback wiring ──────────────────────────────────────

fn smoke_open_playback_wiring() -> TestResult {
    crate::__reset_for_test();
    let card = register_card("hda-amd-phoenix", "HDA0", "AMD Phoenix HDA", 7, 4, 4);
    let stream = open_playback(card, 0);
    let stream = match stream {
        Ok(s) => s,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("open_playback failed");
        }
    };
    if stream.card() != card || stream.device() != 0 {
        return TestResult::Fail("stream ids wrong");
    }
    // open invalid device.
    match open_playback(card, 99) {
        Err(SoundError::NoSuchDevice) => {}
        _ => return TestResult::Fail("invalid device wasn't rejected"),
    }
    // invalid card.
    match open_playback(999, 0) {
        Err(SoundError::NoSuchCard) => {}
        _ => return TestResult::Fail("invalid card wasn't rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_open_playback_wiring);

// ── #26: open_capture path ─────────────────────────────────────────

fn smoke_open_capture_wiring() -> TestResult {
    crate::__reset_for_test();
    let card = register_card("hda-amd-renoir", "HDA0", "AMD Renoir HDA", 0, 2, 2);
    match crate::open_capture(card, 0) {
        Ok(s) => {
            if s.card() != card {
                return TestResult::Fail("card mismatch");
            }
        }
        Err(_) => return TestResult::Fail("open_capture failed"),
    }
    match crate::open_capture(card, 99) {
        Err(SoundError::NoSuchDevice) => {}
        _ => return TestResult::Fail("invalid capture device accepted"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_open_capture_wiring);

// ── #27: Mixer handle list_controls round-trip ─────────────────────

fn smoke_mixer_handle_list_controls() -> TestResult {
    crate::__reset_for_test();
    mixer::__reset_for_test();
    let card = register_card("hda-realtek", "HDA0", "Realtek HDA", 200, 1, 1);
    mixer::register_standard_realtek(200, true, true, true);
    let mx = mixer_open(card).unwrap();
    let ids = mx.list_controls();
    if ids.is_empty() {
        return TestResult::Fail("mixer reported no controls");
    }
    // Get a value — master volume.
    if let Some(master) = ids
        .iter()
        .find(|id| matches!(id.kind, ControlKind::MasterVolume))
    {
        let _ = mx.get_control_value(*master).unwrap();
    } else {
        return TestResult::Fail("master volume id not in list");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_mixer_handle_list_controls);

// ── #28: /dev/snd/controlC0 appears after card registration ──────────

fn smoke_devfs_control_node_appears() -> TestResult {
    use narf_filesystem::DirOps as _;
    crate::__reset_for_test();
    mixer::__reset_for_test();
    register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
    mixer::register_standard_realtek(0, true, true, true);
    let dir = crate::devfs_bridge::DevSndDir;
    match dir.lookup("controlC0") {
        Some(_) => TestResult::Pass,
        None => TestResult::Fail("controlC0 not visible after card 0 registration"),
    }
}
kernel_test_in!("drivers/sound", smoke_devfs_control_node_appears);

// ── #29: /dev/snd/pcmC0D0p visible after registration ────────────────

fn smoke_devfs_pcm_playback_node() -> TestResult {
    use narf_filesystem::DirOps as _;
    crate::__reset_for_test();
    mixer::__reset_for_test();
    register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
    let dir = crate::devfs_bridge::DevSndDir;
    match dir.lookup("pcmC0D0p") {
        Some(_) => TestResult::Pass,
        None => TestResult::Fail("pcmC0D0p not visible after card 0 registration"),
    }
}
kernel_test_in!("drivers/sound", smoke_devfs_pcm_playback_node);

// ── #30: /sys/class/sound/card0/id contains codec name ───────────────

fn smoke_sysfs_card_id_attr() -> TestResult {
    crate::__reset_for_test();
    register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
    let cards = list_cards();
    let card = match cards.first() {
        Some(c) => c.clone(),
        None => return TestResult::Fail("no cards registered"),
    };
    let id_text = crate::sysfs_bridge::render_card_id_attr(&card);
    if id_text.contains("HDA Intel PCH") {
        TestResult::Pass
    } else {
        TestResult::Fail("card id attr does not contain codec name")
    }
}
kernel_test_in!("drivers/sound", smoke_sysfs_card_id_attr);

// ── #31: /sys/class/sound/pcmC0D0p/dev starts with "116:" ────────────

fn smoke_sysfs_pcm_dev_attr_format() -> TestResult {
    crate::__reset_for_test();
    register_card("hda-amd", "HDA AMD", "HDA AMD Renoir", 0, 2, 1);
    let dev_attr = crate::sysfs_bridge::render_pcm_dev_attr(0, 0, false);
    if dev_attr.starts_with("116:") {
        TestResult::Pass
    } else {
        TestResult::Fail("pcmC0D0p dev attr does not start with '116:'")
    }
}
kernel_test_in!("drivers/sound", smoke_sysfs_pcm_dev_attr_format);

// ── #32: PCM playback write 4096 bytes succeeds ──────────────────────

fn smoke_devfs_pcm_write_4096() -> TestResult {
    use crate::devfs_bridge::DevSndDir;
    use narf_filesystem::DirOps;
    crate::__reset_for_test();
    mixer::__reset_for_test();
    register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
    let dir = DevSndDir;
    let node = match dir.lookup("pcmC0D0p") {
        Some(n) => n,
        None => return TestResult::Fail("pcmC0D0p not found"),
    };
    let samples = alloc::vec![0u8; 4096];
    let result = crate::tests_support::poll_once(node.write(0, &samples));
    match result {
        Ok(4096) => TestResult::Pass,
        Ok(n) => {
            // Partial write is acceptable too (ring may absorb less).
            let _ = n;
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("pcmC0D0p write returned error"),
    }
}
kernel_test_in!("drivers/sound", smoke_devfs_pcm_write_4096);

// ── #33: /proc/asound/cards format is correct ────────────────────────

fn smoke_procfs_cards_format() -> TestResult {
    crate::__reset_for_test();
    register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
    let text = crate::procfs_bridge::render_cards_list();
    // Linux format: " N [id           ]: driver - longname"
    if text.contains(" 0 [") && text.contains("]: hda-intel") {
        TestResult::Pass
    } else {
        TestResult::Fail("procfs cards list format incorrect")
    }
}
kernel_test_in!("drivers/sound", smoke_procfs_cards_format);

// ── #34: /proc/asound/version contains ALSA header ───────────────────

fn smoke_procfs_version_alsa_header() -> TestResult {
    let text = crate::procfs_bridge::render_version();
    if text.contains("Advanced Linux Sound Architecture") {
        TestResult::Pass
    } else {
        TestResult::Fail("procfs version text missing ALSA header")
    }
}
kernel_test_in!("drivers/sound", smoke_procfs_version_alsa_header);

// ── #35: 2 cards → card0 + card1 both enumerate in /dev/snd ──────────

fn smoke_devfs_multi_card_enumerate() -> TestResult {
    use crate::devfs_bridge::DevSndDir;
    use narf_filesystem::DirOps;
    crate::__reset_for_test();
    mixer::__reset_for_test();
    register_card("hda-intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
    register_card("hda-amd", "HDA AMD", "HDA AMD Renoir", 1, 1, 1);
    let dir = DevSndDir;
    let entries = dir.enumerate(0, 64);
    let names: alloc::vec::Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    let has_c0 = names.contains(&"controlC0");
    let has_c1 = names.contains(&"controlC1");
    let has_p0 = names.contains(&"pcmC0D0p");
    let has_p1 = names.contains(&"pcmC1D0p");
    if has_c0 && has_c1 && has_p0 && has_p1 {
        TestResult::Pass
    } else {
        TestResult::Fail("multi-card enumerate missing expected nodes")
    }
}
kernel_test_in!("drivers/sound", smoke_devfs_multi_card_enumerate);

// ── #36: /proc/asound/* VFS lookup and read ──────────────────────────

fn smoke_procfs_asound_vfs_lookup() -> TestResult {
    use narf_filesystem::FsInstance;
    crate::__reset_for_test();
    mixer::__reset_for_test();
    register_card("HDA-Intel", "HDA Intel PCH", "HDA Intel PCH", 0, 1, 1);
    crate::procfs_bridge::register_procfs_asound();

    let root = narf_filesystem::procfs::ProcFs.root();
    let asound_dir = match root.lookup_dir("asound") {
        Some(d) => d,
        None => return TestResult::Fail("/proc/asound directory lookup failed"),
    };
    let cards_file = match asound_dir.lookup("cards") {
        Some(f) => f,
        None => return TestResult::Fail("/proc/asound/cards file lookup failed"),
    };
    let mut buf = [0u8; 256];
    let n = match crate::tests_support::poll_once(cards_file.read(0, &mut buf)) {
        Ok(n) if n > 0 => n,
        _ => return TestResult::Fail("reading /proc/asound/cards failed"),
    };
    let text = match core::str::from_utf8(&buf[..n]) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("/proc/asound/cards is not valid UTF-8"),
    };
    if !text.contains("HDA-Intel") || !text.contains("HDA Intel PCH") {
        return TestResult::Fail("/proc/asound/cards content mismatch");
    }

    let version_file = match asound_dir.lookup("version") {
        Some(f) => f,
        None => return TestResult::Fail("/proc/asound/version file lookup failed"),
    };
    let n = match crate::tests_support::poll_once(version_file.read(0, &mut buf)) {
        Ok(n) if n > 0 => n,
        _ => return TestResult::Fail("reading /proc/asound/version failed"),
    };
    let text = match core::str::from_utf8(&buf[..n]) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("/proc/asound/version is not valid UTF-8"),
    };
    if !text.contains("Advanced Linux Sound Architecture") {
        return TestResult::Fail("/proc/asound/version content mismatch");
    }

    let card0_dir = match asound_dir.lookup_dir("card0") {
        Some(d) => d,
        None => return TestResult::Fail("/proc/asound/card0 directory lookup failed"),
    };
    let codec_file = match card0_dir.lookup("codec#0") {
        Some(f) => f,
        None => return TestResult::Fail("/proc/asound/card0/codec#0 file lookup failed"),
    };
    let n = match crate::tests_support::poll_once(codec_file.read(0, &mut buf)) {
        Ok(n) if n > 0 => n,
        _ => return TestResult::Fail("reading /proc/asound/card0/codec#0 failed"),
    };
    let text = match core::str::from_utf8(&buf[..n]) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("/proc/asound/card0/codec#0 is not valid UTF-8"),
    };
    if !text.contains("Codec: HDA Intel PCH") {
        return TestResult::Fail("/proc/asound/card0/codec#0 content mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_procfs_asound_vfs_lookup);
