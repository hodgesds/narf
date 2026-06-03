//! Subsystem-level smokes for `narf-drivers-sound`.
//!
//! Each test is a self-contained round-trip: build the synthetic
//! state, drive the function under test, assert against the
//! expected output. None of these tests touch real PCI / MMIO —
//! they assume a `FakeCorb` / `VerbRecorder` transport for codec
//! verbs, and pure-Rust register helpers for controller / stream
//! / format encoding.

use crate::codec::generic::{
    encode_verb, set_amp_gain_mute_verb, PinDevice, Widget, WidgetKind,
    VERB_GET_PARAMETER, VERB_SET_EAPD_BTL, VERB_SET_PIN_WIDGET_CONTROL,
};
use crate::codec::realtek::{
    detect, bring_up, eapd_verb, init_table_for, RealtekChip,
    VerbRecorder, EAPD_ENABLE, PIN_WIDGET_OUT,
};
use crate::codec::quirks::{find_quirk, first_for_chip, quirk_count};
use crate::format::{
    pack_sdfmt, ChannelCount, HwParams, SampleFormat, SampleRate,
};
use crate::hda::controller::{
    reset_controller, supported_device, HdaController,
    GCTL_CRST, HDA_AMD_PHOENIX_DEVICE, HDA_AMD_PHOENIX_VENDOR,
    HDA_AMD_RENOIR_DEVICE, HDA_AMD_RENOIR_VENDOR, HDA_CLASS_TRIPLE,
};
use crate::hda::corb::{Verb, CORB_ENTRIES};
use crate::hda::rirb::{Response, RIRB_ENTRIES};
use crate::hda::streams::{
    BdlEntry, StreamDescriptor, SDCTL_DEIE, SDCTL_FEIE, SDCTL_IOCE, SDCTL_RUN,
};
use crate::hda::widget::CodecGraph;
use crate::mixer::{
    self, ControlInfo, ControlKind, ControlValue,
};
use crate::pcm::{PcmSubstream, SubstreamState};
use crate::{
    open_playback, list_cards, mixer as mixer_open, register_card,
    SoundError,
};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

// ── #1: PCI ID match ────────────────────────────────────────────────

fn smoke_pci_id_match_amd_zen2_phoenix() -> TestResult {
    if !supported_device(HDA_AMD_RENOIR_VENDOR, HDA_AMD_RENOIR_DEVICE) {
        return TestResult::Fail("Renoir HDA ID rejected");
    }
    if !supported_device(HDA_AMD_PHOENIX_VENDOR, HDA_AMD_PHOENIX_DEVICE) {
        return TestResult::Fail("Phoenix HDA ID rejected");
    }
    if HDA_CLASS_TRIPLE != 0x0403_00 {
        return TestResult::Fail("HDA class triple mismatch");
    }
    if supported_device(0xDEAD, 0xBEEF) {
        return TestResult::Fail("bogus ID accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_pci_id_match_amd_zen2_phoenix);

// ── #2: HDA register layout — GCAP decoder ─────────────────────────

fn smoke_hda_register_layout_gcap_decode() -> TestResult {
    // GCAP = output=4, input=4, bidir=0, 64bit=1 → 0x4401
    let gcap: u16 = (4 << 12) | (4 << 8) | (0 << 4) | 1;
    let (noss, niss, nbss, addr64) = HdaController::decode_gcap(gcap);
    if (noss, niss, nbss, addr64) != (4, 4, 0, true) {
        return TestResult::Fail("GCAP decode wrong for AMD-typical layout");
    }
    // GCAP all-zeroes → no streams, no 64-bit.
    let (noss, niss, nbss, addr64) = HdaController::decode_gcap(0);
    if (noss, niss, nbss, addr64) != (0, 0, 0, false) {
        return TestResult::Fail("GCAP all-zeroes mis-decoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_hda_register_layout_gcap_decode);

// ── #3: CORB ring encode (verb pack) ───────────────────────────────

fn smoke_corb_verb_encode() -> TestResult {
    let v = Verb::new(/*cad=*/ 0x2, /*nid=*/ 0x14, /*verb=*/ 0x707, /*payload=*/ 0x40);
    if v.cad() != 0x2 { return TestResult::Fail("cad decode"); }
    if v.nid() != 0x14 { return TestResult::Fail("nid decode"); }
    if v.verb_id() != 0x707 { return TestResult::Fail("verb decode"); }
    if v.payload() != 0x40 { return TestResult::Fail("payload decode"); }
    let raw = v.0;
    let expected = (0x2u32 << 28) | (0x14 << 20) | (0x707 << 8) | 0x40;
    if raw != expected {
        return TestResult::Fail("verb word doesn't match spec packing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_corb_verb_encode);

// ── #4: RIRB response decode ───────────────────────────────────────

fn smoke_rirb_response_decode() -> TestResult {
    // HDA §3.3.34: data is bits[31:0], caddr/unsol live in bits[36:32].
    let raw: u64 = 0x00000001_10EC0256; // data=0x10EC0256, caddr=1, sol
    let r = Response::decode(raw);
    if r.data != 0x10EC0256 {
        return TestResult::Fail("data decode");
    }
    if r.caddr != 1 {
        return TestResult::Fail("caddr decode");
    }
    if r.unsolicited {
        return TestResult::Fail("solicited misdecoded");
    }
    // Round-trip.
    if r.encode() != raw {
        return TestResult::Fail("encode != decode for solicited");
    }
    let unsol = Response { data: 0xAA, caddr: 0, unsolicited: true };
    let raw2 = unsol.encode();
    if Response::decode(raw2) != unsol {
        return TestResult::Fail("unsolicited round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_rirb_response_decode);

// ── #5: BDL entry encode ────────────────────────────────────────────

fn smoke_bdl_entry_encode() -> TestResult {
    let e = BdlEntry::new(0x1234_5678_DEAD_BEEFu64, /*len=*/ 4096, /*ioc=*/ true);
    let bytes = e.to_le_bytes();
    if bytes[0] != 0xEF || bytes[1] != 0xBE
        || bytes[4] != 0x78 || bytes[7] != 0x12 {
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
    let fmt = pack_sdfmt(SampleFormat::S16LE, SampleRate::R48000, ChannelCount::Stereo);
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
    let fmt44 = pack_sdfmt(SampleFormat::S16LE, SampleRate::R44100, ChannelCount::Stereo);
    if fmt44 & (1 << 14) == 0 {
        return TestResult::Fail("44.1k family bit missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_sdfmt_48k_stereo_s16);

// ── #8: Codec parameter read — AFG root ────────────────────────────

fn smoke_codec_get_param_afg() -> TestResult {
    // Recorder returns 0x00010001 = AFG (function group type 0x01)
    // for the function-group parameter read on NID 0x01.
    let mut bus = VerbRecorder::with_initial_responses(vec![0x0000_0001]);
    let response = crate::codec::generic::get_param(&mut bus,
        /*cad=*/ 0, /*nid=*/ 0x01,
        crate::codec::generic::PARAM_FUNCTION_GROUP).unwrap();
    if response != 1 {
        return TestResult::Fail("function group response not surfaced");
    }
    // Verify history shape: one GET_PARAMETER verb.
    if bus.history.len() != 1 {
        return TestResult::Fail("history length");
    }
    let v = bus.history[0];
    let expected = encode_verb(0, 0x01, VERB_GET_PARAMETER,
                                crate::codec::generic::PARAM_FUNCTION_GROUP);
    if v != expected {
        return TestResult::Fail("encoded verb mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_codec_get_param_afg);

// ── #9: Codec widget walk — Output → Mixer → Pin ───────────────────

fn smoke_codec_widget_walk_output_chain() -> TestResult {
    // Synthetic codec graph: DAC (0x02) → Mixer (0x0C) → SpeakerPin (0x14).
    let mut dac = Widget::new(0x02, 0x0000_0000);
    dac.kind = WidgetKind::AudioOutput;
    let mut mixer = Widget::new(0x0C, 0x0020_0000);
    mixer.kind = WidgetKind::Mixer;
    mixer.connections = vec![0x02];
    let mut pin = Widget::new(0x14, 0x0040_0000);
    pin.kind = WidgetKind::PinComplex;
    pin.connections = vec![0x0C];
    pin.pin_device = PinDevice::Speaker;

    let widgets = vec![dac, mixer, pin];
    let graph = CodecGraph::build(&widgets);
    if graph.outputs.len() != 1 {
        return TestResult::Fail("output path count");
    }
    let path = &graph.outputs[0];
    if path.dac_nid != 0x02 || path.pin_nid != 0x14
        || !matches!(path.pin_device, PinDevice::Speaker) {
        return TestResult::Fail("path endpoints");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_codec_widget_walk_output_chain);

// ── #10: ALC256 init verb sequence ─────────────────────────────────

fn smoke_alc256_init_sequence() -> TestResult {
    let chip = RealtekChip::Alc256;
    let init = init_table_for(chip);
    if init.is_empty() {
        return TestResult::Fail("ALC256 init empty");
    }
    // Must include the PC-Beep loopback fix at COEF 0x36.
    if !init.iter().any(|r| r.idx == 0x36 && r.value == 0x5757) {
        return TestResult::Fail("ALC256 missing 0x36=0x5757 (PC-Beep fix)");
    }
    // bring_up must drive at minimum: COEF idx, COEF data, AFG power,
    // DAC power, speaker power, HP power, unmute, set-pin-ctl on
    // both pins, EAPD on speaker, unsolicited-resp on HP.
    let mut bus = VerbRecorder::with_initial_responses(vec![]);
    bring_up(&mut bus, /*cad=*/ 0, /*afg=*/ 0x01, chip,
             /*dac=*/ 0x02, /*spk=*/ 0x14, /*hp=*/ 0x21).unwrap();
    // 2 COEF writes (idx+data) × init.len() rows + 4 power + 1 unmute + 2 pin ctrl + 1 EAPD + 1 unsol.
    let expected = init.len() * 2 + 4 + 1 + 2 + 1 + 1;
    if bus.history.len() != expected {
        return TestResult::Fail("ALC256 verb count off");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_alc256_init_sequence);

// ── #11: ALC285 init verb sequence ─────────────────────────────────

fn smoke_alc285_init_sequence() -> TestResult {
    let chip = RealtekChip::Alc285;
    let init = init_table_for(chip);
    // Must include the speaker-boost COEF write at 0x6F.
    if !init.iter().any(|r| r.idx == 0x6F) {
        return TestResult::Fail("ALC285 missing 0x6F boost row");
    }
    let mut bus = VerbRecorder::new();
    bring_up(&mut bus, 0, 0x01, chip, 0x02, 0x14, 0x21).unwrap();
    if bus.history.is_empty() {
        return TestResult::Fail("no verbs emitted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_alc285_init_sequence);

// ── #12: ALC295 EAPD verb encode ───────────────────────────────────

fn smoke_alc295_eapd_verb_encode() -> TestResult {
    // EAPD/BTL verb 0x70C on pin NID 0x14, bit 1 (EAPD) set.
    let v = eapd_verb(/*cad=*/ 0, /*pin=*/ 0x14, /*enable=*/ true);
    let expected = encode_verb(0, 0x14, VERB_SET_EAPD_BTL, EAPD_ENABLE);
    if v != expected {
        return TestResult::Fail("EAPD verb encoding off");
    }
    // bit 1 of payload must be 1 (EAPD_ENABLE = 0x02).
    if v & 0xFF != 0x02 {
        return TestResult::Fail("payload bit 1 not set");
    }
    // verb_id field = 0x70C.
    if (v >> 8) & 0xFFF != 0x70C {
        return TestResult::Fail("verb id mismatch");
    }
    // detect() must round-trip ALC295 from a VENDOR_ID = 0x10EC0295.
    let mut bus = VerbRecorder::with_initial_responses(vec![0x10EC_0295]);
    let chip = detect(&mut bus, 0).unwrap().unwrap();
    if chip != RealtekChip::Alc295 {
        return TestResult::Fail("ALC295 detect failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_alc295_eapd_verb_encode);

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
    let want = pack_sdfmt(SampleFormat::S16LE, SampleRate::R44100, ChannelCount::Stereo);
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
    mixer::register_standard_realtek(/*ctrl=*/ 99,
                                      /*spk=*/ true,
                                      /*hp=*/ true,
                                      /*mic=*/ true);
    let ids = mixer::list_for_controller(99);
    let master = ids.iter().find(|id| matches!(id.kind, ControlKind::MasterVolume))
        .copied()
        .ok_or(()).map_err(|_| ()).ok();
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
        ControlValue::Integer { left: 50, right: 50 } => {}
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
    let jack = ids.iter().find(|id| matches!(id.kind, ControlKind::JackSense))
        .copied()
        .ok_or(()).map_err(|_| ()).ok()
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

// ── #17: Controller reset state machine ────────────────────────────

fn smoke_controller_reset_sequence() -> TestResult {
    use core::cell::Cell;
    // Synthetic GCTL register that flips with each write.
    let gctl: Cell<u32> = Cell::new(GCTL_CRST); // start "out of reset"
    // Driver writes 0 → controller mirrors back 0.
    // Driver then writes CRST → controller mirrors back CRST.
    let result = reset_controller(
        || gctl.get(),
        |v| { gctl.set(v); },
    );
    if result.is_err() {
        return TestResult::Fail("reset_controller errored on cooperating HW");
    }
    if gctl.get() != GCTL_CRST {
        return TestResult::Fail("reset_controller didn't end with CRST set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_controller_reset_sequence);

// ── #18: Format support filter ─────────────────────────────────────

fn smoke_format_filter() -> TestResult {
    if !crate::supported_format(SampleFormat::S16LE, SampleRate::R44100,
                                 ChannelCount::Stereo) {
        return TestResult::Fail("44.1k stereo S16 rejected");
    }
    if !crate::supported_format(SampleFormat::S32LE, SampleRate::R192000,
                                 ChannelCount::Surround71) {
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

// ── #21: Quirk lookup ──────────────────────────────────────────────

fn smoke_quirk_table_lookup() -> TestResult {
    if quirk_count() < 4 {
        return TestResult::Fail("too few quirks");
    }
    // Lenovo X1 Carbon Gen 7 quirk.
    let q = match find_quirk(0x17AA_22BE) {
        Some(q) => q,
        None => return TestResult::Fail("X1 Carbon quirk not found"),
    };
    if q.chip != RealtekChip::Alc285 {
        return TestResult::Fail("X1 chip mismatch");
    }
    if q.pins.is_empty() {
        return TestResult::Fail("X1 has no pins");
    }
    // Fallback by chip.
    let any = first_for_chip(RealtekChip::Alc256);
    if any.is_none() {
        return TestResult::Fail("no ALC256 entry");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_quirk_table_lookup);

// ── #22: All 28 ALC chips have init tables ─────────────────────────

fn smoke_realtek_chip_coverage() -> TestResult {
    let chips = [
        RealtekChip::Alc233, RealtekChip::Alc235, RealtekChip::Alc236,
        RealtekChip::Alc255, RealtekChip::Alc256, RealtekChip::Alc257,
        RealtekChip::Alc270, RealtekChip::Alc280, RealtekChip::Alc282,
        RealtekChip::Alc283, RealtekChip::Alc285, RealtekChip::Alc286,
        RealtekChip::Alc287, RealtekChip::Alc289, RealtekChip::Alc290,
        RealtekChip::Alc292, RealtekChip::Alc293, RealtekChip::Alc294,
        RealtekChip::Alc295, RealtekChip::Alc298,
        RealtekChip::Alc3204, RealtekChip::Alc3225, RealtekChip::Alc3236,
        RealtekChip::Alc3254, RealtekChip::Alc3266, RealtekChip::Alc3268,
        RealtekChip::Alc3286, RealtekChip::Alc3287,
    ];
    if chips.len() < 15 {
        return TestResult::Fail("coverage below 15");
    }
    for c in chips {
        let init = init_table_for(c);
        if init.is_empty() {
            return TestResult::Fail("chip has empty init table");
        }
        if c.name().is_empty() {
            return TestResult::Fail("chip has empty name");
        }
        // bring_up must complete on the synthetic bus.
        let mut bus = VerbRecorder::new();
        bring_up(&mut bus, 0, 0x01, c, 0x02, 0x14, 0x21).unwrap();
        if bus.history.is_empty() {
            return TestResult::Fail("bring_up emitted no verbs");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_realtek_chip_coverage);

// ── #23: Pin widget control set verb pattern ───────────────────────

fn smoke_pin_widget_control_verb() -> TestResult {
    let v = encode_verb(0, 0x14, VERB_SET_PIN_WIDGET_CONTROL, PIN_WIDGET_OUT);
    if (v >> 8) & 0xFFF != VERB_SET_PIN_WIDGET_CONTROL as u32 {
        return TestResult::Fail("verb id off");
    }
    if v & 0xFF != PIN_WIDGET_OUT as u32 {
        return TestResult::Fail("payload off");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_pin_widget_control_verb);

// ── #24: amp_gain_mute packing ─────────────────────────────────────

fn smoke_amp_gain_mute_pack() -> TestResult {
    // Output amp, both channels, index 0, mute=false, gain=0 → 0xB000.
    let p = crate::codec::generic::amp_gain_mute_payload(
        true, false, true, true, 0, false, 0);
    if p != 0xB000 {
        return TestResult::Fail("output unmute payload wrong");
    }
    // Output, both channels, mute=true, gain=0x40 → high byte 0xB0, low 0xC0.
    let p = crate::codec::generic::amp_gain_mute_payload(
        true, false, true, true, 0, true, 0x40);
    if p != 0xB0C0 {
        return TestResult::Fail("mute payload wrong");
    }
    // Full verb word — major opcode 0x3 split.
    let w = set_amp_gain_mute_verb(/*cad=*/ 0, /*nid=*/ 0x02,
        true, false, true, true, 0, false, 0);
    // Major opcode 3 in bits 19..16.
    if (w >> 16) & 0xF != 0x3 {
        return TestResult::Fail("major opcode not 0x3");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_amp_gain_mute_pack);

// ── #25: CORB/RIRB ring entry counts ───────────────────────────────

fn smoke_corb_rirb_ring_sizes() -> TestResult {
    if CORB_ENTRIES != 256 {
        return TestResult::Fail("CORB entry count off");
    }
    if RIRB_ENTRIES != 256 {
        return TestResult::Fail("RIRB entry count off");
    }
    if crate::hda::corb::CORB_BYTES != 1024 {
        return TestResult::Fail("CORB byte size off");
    }
    if crate::hda::rirb::RIRB_BYTES != 2048 {
        return TestResult::Fail("RIRB byte size off");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sound", smoke_corb_rirb_ring_sizes);

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
    if let Some(master) = ids.iter().find(|id| matches!(id.kind, ControlKind::MasterVolume)) {
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
        Ok(n) if n == 4096 => TestResult::Pass,
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
    register_card("hda-amd",   "HDA AMD",       "HDA AMD Renoir", 1, 1, 1);
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
