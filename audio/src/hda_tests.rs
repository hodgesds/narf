//! Per-driver smoke tests for `narf-audio::hda`. Tests register
//! via `narf_kernel_test::kernel_test_in!` so the runner groups
//! output under `audio/hda`.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_hda_match_amd_phoenix_ids() -> TestResult {
    // Register the HDA driver and verify both supported PCI ids
    // (AMD Ryzen Phoenix HDA + Radeon HD Audio) appear in the bus
    // match table. No live silicon required.
    use crate::hda;
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    use narf_bus::{registered_pci_drivers, MatchKind};
    bus_reset();
    hda::register_pci_driver();
    let regs = registered_pci_drivers();
    let mut saw_phoenix = false;
    let mut saw_radeon = false;
    for m in regs.iter() {
        if let MatchKind::VendorDevice { vendor, device } = m.kind {
            if vendor == hda::HDA_AMD_PHOENIX_VENDOR && device == hda::HDA_AMD_PHOENIX_DEVICE {
                saw_phoenix = true;
            }
            if vendor == hda::HDA_AMD_RADEON_VENDOR && device == hda::HDA_AMD_RADEON_DEVICE {
                saw_radeon = true;
            }
        }
    }
    if !saw_phoenix {
        return TestResult::Fail("AMD Phoenix 1022:15e3 not in match table");
    }
    if !saw_radeon {
        return TestResult::Fail("AMD Radeon 1002:1640 not in match table");
    }
    let mut saw_ich9 = false;
    for m in regs.iter() {
        if let MatchKind::VendorDevice { vendor, device } = m.kind {
            if vendor == hda::HDA_INTEL_ICH9_VENDOR && device == hda::HDA_INTEL_ICH9_DEVICE {
                saw_ich9 = true;
            }
        }
    }
    if !saw_ich9 {
        return TestResult::Fail("Intel ICH9 0x8086:0x293E not in match table");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", smoke_hda_match_amd_phoenix_ids);

fn smoke_hda_corb_size_layout() -> TestResult {
    // HDA spec rev 1.0a §3.3.18 / §3.3.25: CORB and RIRB rings must
    // be 128-byte aligned. The driver allocates 4 KiB pages from
    // alloc_coherent which trivially satisfy that. This smoke
    // round-trips the alignment invariant so a future allocator
    // change can't silently regress it.
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let corb = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent CORB"),
    };
    let rirb = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent RIRB"),
    };
    let corb_phys = corb.phys_addr().raw();
    let rirb_phys = rirb.phys_addr().raw();
    if corb_phys & 0x7F != 0 {
        return TestResult::Fail("CORB phys not 128-byte aligned");
    }
    if rirb_phys & 0x7F != 0 {
        return TestResult::Fail("RIRB phys not 128-byte aligned");
    }
    if (corb_phys & 0xFFF) + 1024 > 4096 {
        return TestResult::Fail("CORB 1024-byte ring spans a page");
    }
    if (rirb_phys & 0xFFF) + 2048 > 4096 {
        return TestResult::Fail("RIRB 2048-byte ring spans a page");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", smoke_hda_corb_size_layout);

fn smoke_hda_period_load_silence() -> TestResult {
    // Round-trip the period-buffer math against the bound
    // controller. Skips when no HDA silicon is bound.
    use crate::hda;
    if !hda::is_probed() {
        return TestResult::Skip("hda not probed");
    }
    let n = hda::with_controller(|c| {
        let _ = c.load_period(&[]);
        c.period_samples()
    });
    match n {
        Some(2048) => TestResult::Pass,
        Some(_) => TestResult::Fail("period_samples != 2048"),
        None => TestResult::Skip("hda controller missing"),
    }
}
kernel_test_in!("audio/hda", smoke_hda_period_load_silence);

fn smoke_acp6_pci_match_registered() -> TestResult {
    // Structural: register the ACP6 driver and assert the
    // AMD Phoenix ACP6.0 (1022:15E2) match is in the bus's table.
    use crate::acp6;
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    use narf_bus::{registered_pci_drivers, MatchKind};
    bus_reset();
    acp6::register_pci_driver();
    let regs = registered_pci_drivers();
    let matched = regs.iter().any(|m| {
        m.name == "acp6"
            && matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: acp6::ACP_VENDOR,
                    device: acp6::ACP_PHOENIX,
                }
            )
    });
    if !matched {
        return TestResult::Fail("acp6 PCI match table entry missing");
    }
    TestResult::Pass
}
kernel_test_in!("audio/acp6", smoke_acp6_pci_match_registered);

fn smoke_hda_codec_path_setup_widget_constants() -> TestResult {
    // Structural: confirm the widget-type constants the codec walker
    // matches against haven't drifted from the HDA spec encoding.
    // Bit-encoding of widget type is bits 20..23 of
    // PARAM_AUDIO_WIDGET_CAPS — the walker does
    // `((caps >> 20) & 0xF) as u8`, and these constants must equal
    // the spec's "Audio Output" / "Pin Complex" values.
    use crate::hda;

    if hda::WIDGET_TYPE_AUDIO_OUTPUT != 0x0 {
        return TestResult::Fail("WIDGET_TYPE_AUDIO_OUTPUT drift");
    }
    if hda::WIDGET_TYPE_PIN_COMPLEX != 0x4 {
        return TestResult::Fail("WIDGET_TYPE_PIN_COMPLEX drift");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda", smoke_hda_codec_path_setup_widget_constants);

#[cfg(target_arch = "x86_64")]
fn smoke_hda_writer_submit_round_trip() -> TestResult {
    // End-to-end PCM submit through AudioWriter → hda. Probes
    // the device, opens an AudioWriter at the default playback
    // format (S16LE / 48 kHz / stereo), and submits 1024 bytes.
    use crate::{bootstrap_writer, hda, AudioFormat, AudioWriter};
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};

    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == hda::HDA_INTEL_ICH9_VENDOR
            && d.id.device == hda::HDA_INTEL_ICH9_DEVICE
    });
    if !has {
        return TestResult::Skip("no intel-hda (ICH9)");
    }

    hda::__reset_for_test();
    bus_reset();
    hda::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }

    let cap = bootstrap_writer();
    let writer = match AudioWriter::open(cap, AudioFormat::default_playback()) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("AudioWriter::open"),
    };

    // 1024 bytes = 256 stereo S16 frames = ~5.3 ms @ 48 kHz.
    let silence = [0u8; 1024];
    let frames = match writer.submit(&silence) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("submit returned error"),
    };
    if frames != 256 {
        return TestResult::Fail("submit returned wrong frame count");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("audio/hda", smoke_hda_writer_submit_round_trip);



// ── HDA codec walker (transport-neutral) ──────────────────────────



fn smoke_hda_codec_enumerates_output_path_via_mock_verb_table() -> TestResult {

    use crate::hda_codec::{enumerate, find_output_path, make_verb, param, verb, WidgetType};

    use alloc::vec;



    // Synthetic codec: addr 0, AFG NID 1, three widgets:

    //   NID 2: PinComplex (Speaker), connections=[3]

    //   NID 3: AudioMixer, connections=[4]

    //   NID 4: AudioOutput

    let mut table = alloc::collections::BTreeMap::<u32, u32>::new();

    let addr = 0u8;

    // Vendor 0x10EC (Realtek), Device 0x0287.

    table.insert(make_verb(addr, 0, verb::GET_PARAMETER | param::VENDOR_ID), 0x0287_10EC);

    table.insert(make_verb(addr, 0, verb::GET_PARAMETER | param::REVISION_ID), 0x0010_0001);

    // Root subordinate node count: first FG = 1, count = 1.

    table.insert(make_verb(addr, 0, verb::GET_PARAMETER | param::SUBORDINATE_NODE_COUNT), 0x0001_0001);

    // FG type = 1 (Audio Function Group).

    table.insert(make_verb(addr, 1, verb::GET_PARAMETER | param::FUNCTION_GROUP_TYPE), 0x0000_0001);

    // AFG subordinate: first widget = 2, count = 3.

    table.insert(make_verb(addr, 1, verb::GET_PARAMETER | param::SUBORDINATE_NODE_COUNT), 0x0003_0002);

    // Widget 2: PinComplex, has conn list, has out amp.

    //   bits[23:20] = 4 (Pin), bit 8 = 1 (conn list), bit 2 = 1 (out amp), bit 0 = 1 (stereo)

    table.insert(make_verb(addr, 2, verb::GET_PARAMETER | param::AUDIO_WIDGET_CAPS), 0x0040_0105);

    table.insert(make_verb(addr, 2, verb::GET_PARAMETER | param::CONNECTION_LIST_LENGTH), 0x0000_0001);

    table.insert(make_verb(addr, 2, verb::GET_CONNECTION_LIST_ENTRY | 0), 0x0000_0003);

    table.insert(make_verb(addr, 2, verb::GET_PARAMETER | param::PIN_CAPS), 0x0000_0010); // out-capable

    // pin_config_default: default_device=1 (Speaker), connectivity=2 (fixed)

    table.insert(make_verb(addr, 2, verb::GET_CONFIG_DEFAULT), (2u32 << 30) | (1u32 << 20));

    table.insert(make_verb(addr, 2, verb::GET_PARAMETER | param::OUTPUT_AMP_CAPS), 0x8002_0F00);

    // Widget 3: AudioMixer (type 2), conn list, out amp

    table.insert(make_verb(addr, 3, verb::GET_PARAMETER | param::AUDIO_WIDGET_CAPS), 0x0020_0105);

    table.insert(make_verb(addr, 3, verb::GET_PARAMETER | param::CONNECTION_LIST_LENGTH), 0x0000_0001);

    table.insert(make_verb(addr, 3, verb::GET_CONNECTION_LIST_ENTRY | 0), 0x0000_0004);

    table.insert(make_verb(addr, 3, verb::GET_PARAMETER | param::OUTPUT_AMP_CAPS), 0x8002_0F00);

    // Widget 4: AudioOutput (type 0), no conn list, out amp

    table.insert(make_verb(addr, 4, verb::GET_PARAMETER | param::AUDIO_WIDGET_CAPS), 0x0000_0005);

    table.insert(make_verb(addr, 4, verb::GET_PARAMETER | param::OUTPUT_AMP_CAPS), 0x8002_0F00);



    let resolver = |v: u32| *table.get(&v).unwrap_or(&0);

    let codec = enumerate(addr, resolver);

    if codec.vendor_id != 0x10EC || codec.device_id != 0x0287 {

        return TestResult::Fail("vendor / device id mis-decoded");

    }

    if codec.afg_nid != 1 {

        return TestResult::Fail("AFG NID should be 1");

    }

    if codec.widgets.len() != 3 {

        return TestResult::Fail("widget count");

    }

    let pin = codec.widget(2).expect("pin");

    if pin.ty() != WidgetType::PinComplex {

        return TestResult::Fail("NID 2 should be PinComplex");

    }

    if pin.connections != vec![3u8] {

        return TestResult::Fail("pin connections");

    }

    if pin.pin_config.expect("cfg").default_device != 0x1 {

        return TestResult::Fail("speaker default device lost");

    }

    let path = find_output_path(&codec).expect("output path");

    if path.pin_nid != 2 || path.converter_nid != 4 {

        return TestResult::Fail("output path endpoints wrong");

    }

    if path.chain != vec![3u8] {

        return TestResult::Fail("output path should traverse mixer NID 3");

    }

    TestResult::Pass

}

kernel_test_in!("audio/hda-codec", smoke_hda_codec_enumerates_output_path_via_mock_verb_table);



fn smoke_hda_codec_pin_config_default_decoder() -> TestResult {

    use crate::hda_codec::PinConfigDefault;

    // Speaker: default_device=1, connectivity=2 (fixed), color=0xC (lime — default)

    let raw = (2u32 << 30) | (1u32 << 20);

    let p = PinConfigDefault::decode(raw);

    if !p.is_speaker() || !p.is_output_role() || p.is_input_role() {

        return TestResult::Fail("speaker classification wrong");

    }

    // Mic In: default_device=0xA, connectivity=0 (jack)

    let raw = 0xAu32 << 20;

    let p = PinConfigDefault::decode(raw);

    if !p.is_microphone() || !p.is_input_role() || p.is_output_role() {

        return TestResult::Fail("mic classification wrong");

    }

    TestResult::Pass

}

kernel_test_in!("audio/hda-codec", smoke_hda_codec_pin_config_default_decoder);



fn smoke_hda_codec_amp_caps_round_trip() -> TestResult {

    use crate::hda_codec::AmpCaps;

    // offset=0, num_steps=2, step_size=15 (0.25 dB units), mute capable

    let raw = (1u32 << 31) | (15u32 << 16) | (2u32 << 8);

    let a = AmpCaps::decode(raw);

    if a.num_steps != 2 || a.step_size != 15 || !a.mute_capable {

        return TestResult::Fail("AmpCaps decode wrong");

    }

    TestResult::Pass

}

kernel_test_in!("audio/hda-codec", smoke_hda_codec_amp_caps_round_trip);



// ── I2S + WM8960 codecs ───────────────────────────────────────────



fn smoke_i2s_bit_clock_math() -> TestResult {

    use crate::i2s::I2sFormat;

    let f = I2sFormat::cd_quality_stereo();

    // 44_100 × 2 × 16 = 1_411_200 Hz.

    if f.bit_clock_hz() != 1_411_200 {

        return TestResult::Fail("BCLK math");

    }

    if f.master_clock_hz(256) != 44_100 * 256 {

        return TestResult::Fail("MCLK math");

    }

    TestResult::Pass

}

kernel_test_in!("audio/i2s", smoke_i2s_bit_clock_math);



fn smoke_wm8960_register_write_round_trip() -> TestResult {

    use crate::wm8960::{pack_register_write, regs, unpack_register_write};

    let buf = pack_register_write(regs::AUDIO_INTERFACE, 0x142);

    let (reg, data) = unpack_register_write(buf);

    if reg != regs::AUDIO_INTERFACE || data != 0x142 {

        return TestResult::Fail("register write round-trip");

    }

    TestResult::Pass

}

kernel_test_in!("audio/wm8960", smoke_wm8960_register_write_round_trip);



fn smoke_wm8960_init_sequence_starts_with_reset() -> TestResult {

    use crate::wm8960::{build_init_sequence_i2s_master_16bit, regs};

    let seq = build_init_sequence_i2s_master_16bit();

    if seq.is_empty() || seq[0].0 != regs::RESET {

        return TestResult::Fail("first write must be RESET");

    }

    if !seq.iter().any(|(r, _)| *r == regs::AUDIO_INTERFACE) {

        return TestResult::Fail("audio-interface programming missing");

    }

    TestResult::Pass

}

kernel_test_in!("audio/wm8960", smoke_wm8960_init_sequence_starts_with_reset);

// ── deep audio/i2s ──────────────────────────────────────────────

fn smoke_i2s_word_length_variants_distinct() -> TestResult {
    use crate::i2s::WordLength;
    let all = [WordLength::Bits16, WordLength::Bits20, WordLength::Bits24, WordLength::Bits32];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("WordLength variants collapsed");
            }
        }
    }
    // repr(u8) values match the bit count.
    if WordLength::Bits16 as u8 != 16 { return TestResult::Fail("Bits16 != 16"); }
    if WordLength::Bits32 as u8 != 32 { return TestResult::Fail("Bits32 != 32"); }
    TestResult::Pass
}
kernel_test_in!("audio/i2s", smoke_i2s_word_length_variants_distinct);

fn smoke_i2s_channels_repr_matches_count() -> TestResult {
    use crate::i2s::Channels;
    if Channels::Mono as u8 != 1 { return TestResult::Fail("Mono != 1"); }
    if Channels::Stereo as u8 != 2 { return TestResult::Fail("Stereo != 2"); }
    if Channels::Tdm4 as u8 != 4 { return TestResult::Fail("Tdm4 != 4"); }
    if Channels::Tdm6 as u8 != 6 { return TestResult::Fail("Tdm6 != 6"); }
    if Channels::Tdm8 as u8 != 8 { return TestResult::Fail("Tdm8 != 8"); }
    TestResult::Pass
}
kernel_test_in!("audio/i2s", smoke_i2s_channels_repr_matches_count);

fn smoke_i2s_frame_format_variants_distinct() -> TestResult {
    use crate::i2s::FrameFormat;
    let all = [
        FrameFormat::Standard,
        FrameFormat::LeftJustified,
        FrameFormat::RightJustified,
        FrameFormat::DspPcm,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("FrameFormat variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("audio/i2s", smoke_i2s_frame_format_variants_distinct);

fn smoke_i2s_cd_quality_default_shape() -> TestResult {
    use crate::i2s::{Channels, FrameFormat, I2sFormat, WordLength};
    let f = I2sFormat::cd_quality_stereo();
    if f.word_length != WordLength::Bits16 { return TestResult::Fail("WL"); }
    if f.frame_format != FrameFormat::Standard { return TestResult::Fail("FF"); }
    if f.channels != Channels::Stereo { return TestResult::Fail("CH"); }
    if f.sample_rate_hz != 44_100 { return TestResult::Fail("SR"); }
    if !f.host_is_master { return TestResult::Fail("master flag"); }
    TestResult::Pass
}
kernel_test_in!("audio/i2s", smoke_i2s_cd_quality_default_shape);

fn smoke_i2s_bit_clock_scales_with_word_length_and_channels() -> TestResult {
    use crate::i2s::{Channels, FrameFormat, I2sFormat, WordLength};
    // 48 kHz / 24-bit / 8-ch TDM: 48000 * 8 * 24 = 9_216_000 Hz.
    let f = I2sFormat {
        word_length: WordLength::Bits24,
        frame_format: FrameFormat::DspPcm,
        channels: Channels::Tdm8,
        sample_rate_hz: 48_000,
        host_is_master: true,
    };
    if f.bit_clock_hz() != 48_000u64 * 8 * 24 {
        return TestResult::Fail("BCLK scaling drifted");
    }
    if f.master_clock_hz(384) != 48_000u64 * 384 {
        return TestResult::Fail("MCLK scaling drifted");
    }
    TestResult::Pass
}
kernel_test_in!("audio/i2s", smoke_i2s_bit_clock_scales_with_word_length_and_channels);

// ── deep audio/wm8960 ───────────────────────────────────────────

fn smoke_wm8960_i2c_address_pinned() -> TestResult {
    use crate::wm8960::I2C_ADDRESS;
    // Datasheet §6: hard-wired 7-bit address 0b0011010 = 0x1A.
    if I2C_ADDRESS != 0x1A {
        return TestResult::Fail("I2C address drifted from 0x1A");
    }
    TestResult::Pass
}
kernel_test_in!("audio/wm8960", smoke_wm8960_i2c_address_pinned);

fn smoke_wm8960_pack_unpack_walks_register_corners() -> TestResult {
    use crate::wm8960::{pack_register_write, unpack_register_write};
    // 7-bit register address (0..127) + 9-bit data (0..511).
    let corners = [
        (0u8, 0u16),
        (0x7F, 0x1FF),
        (0x40, 0x100),
        (0x01, 0x000),
        (0x37, 0x0AB),
    ];
    for (reg, data) in corners {
        let buf = pack_register_write(reg, data);
        let (r, d) = unpack_register_write(buf);
        if r != reg || d != data {
            return TestResult::Fail("pack/unpack failed at a corner");
        }
    }
    // High bit of reg must be masked (datasheet only specifies 7-bit
    // address). Verify upper-bit input doesn't leak into the data.
    let buf = pack_register_write(0xFF, 0x123);
    let (r, d) = unpack_register_write(buf);
    if r != 0x7F || d != 0x123 {
        return TestResult::Fail("register address high bit not masked");
    }
    TestResult::Pass
}
kernel_test_in!("audio/wm8960", smoke_wm8960_pack_unpack_walks_register_corners);

fn smoke_wm8960_audio_iface_format_bits_distinct() -> TestResult {
    use crate::wm8960::audio_iface::{
        FORMAT_DSP, FORMAT_I2S, FORMAT_LEFT_JUSTIFIED, FORMAT_RIGHT_JUSTIFIED,
    };
    let all = [FORMAT_RIGHT_JUSTIFIED, FORMAT_LEFT_JUSTIFIED, FORMAT_I2S, FORMAT_DSP];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("audio_iface FORMAT_* collapsed");
            }
        }
    }
    // Datasheet pins these values (R7 bits [1:0]).
    if FORMAT_RIGHT_JUSTIFIED != 0 { return TestResult::Fail("RJ != 0"); }
    if FORMAT_LEFT_JUSTIFIED != 1 { return TestResult::Fail("LJ != 1"); }
    if FORMAT_I2S != 2 { return TestResult::Fail("I2S != 2"); }
    if FORMAT_DSP != 3 { return TestResult::Fail("DSP != 3"); }
    TestResult::Pass
}
kernel_test_in!("audio/wm8960", smoke_wm8960_audio_iface_format_bits_distinct);

fn smoke_wm8960_init_sequence_drives_dac_volume() -> TestResult {
    use crate::wm8960::{build_init_sequence_i2s_master_16bit, regs};
    // The init sequence must drive both LEFT_DAC_VOLUME and
    // RIGHT_DAC_VOLUME with the simultaneous-update flag (bit 8 set)
    // — otherwise the codec only updates after the next L/R volume
    // write and audio is muted on the path between them.
    let seq = build_init_sequence_i2s_master_16bit();
    let left = seq.iter().find(|(r, _)| *r == regs::LEFT_DAC_VOLUME);
    let right = seq.iter().find(|(r, _)| *r == regs::RIGHT_DAC_VOLUME);
    match (left, right) {
        (Some((_, lv)), Some((_, rv))) => {
            if lv & (1 << 8) == 0 {
                return TestResult::Fail("LEFT_DAC missing simultaneous-update bit");
            }
            if rv & (1 << 8) == 0 {
                return TestResult::Fail("RIGHT_DAC missing simultaneous-update bit");
            }
            TestResult::Pass
        }
        _ => TestResult::Fail("init sequence skipped a DAC-volume write"),
    }
}
kernel_test_in!("audio/wm8960", smoke_wm8960_init_sequence_drives_dac_volume);
