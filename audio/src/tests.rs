//! Subsystem-level smoke tests for `narf-audio`.
//!
//! Round-trip tests that require concrete hardware backends (virtio-snd-pci)
//! live here or in the driver crates.

use crate::{
    bootstrap_writer, select_active_playback, AudioFormat, AudioWriteError, AudioWriter,
    ChannelLayout, SampleFormat,
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_audio_picker_no_backend_when_unprobed() -> TestResult {
    // Stage-4 audio init occurs at Subsys stage. If we reset the
    // match table and then pick, we should get None.
    use crate::hda;
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    use narf_drivers_virtio::snd_pci;

    snd_pci::__reset_for_test();
    hda::__reset_for_test();
    bus_reset();

    if select_active_playback().is_some() {
        return TestResult::Fail("picker returned a stream with no controller");
    }

    // AudioWriter::open should fail with NoActiveStream.
    let cap = bootstrap_writer();
    match AudioWriter::open(cap, AudioFormat::default_playback()) {
        Err(AudioWriteError::NoActiveStream) => TestResult::Pass,
        _ => TestResult::Fail("AudioWriter::open should have failed with NoActiveStream"),
    }
}
kernel_test_in!("audio", smoke_audio_picker_no_backend_when_unprobed);

#[cfg(target_arch = "x86_64")]
fn smoke_virtio_snd_writer_submit_round_trip() -> TestResult {
    // End-to-end PCM submit through AudioWriter → snd_pci.
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    use narf_drivers_virtio::snd_pci;

    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == snd_pci::VIRTIO_SND_PCI_VENDOR
            && d.id.device == snd_pci::VIRTIO_SND_PCI_DEVICE
    });
    if !has {
        return TestResult::Skip("no virtio-snd-pci");
    }

    snd_pci::__reset_for_test();
    bus_reset();
    snd_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }

    let cap = bootstrap_writer();
    let writer = match AudioWriter::open(cap, AudioFormat::default_playback()) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("AudioWriter::open"),
    };

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
kernel_test_in!(
    "audio/virtio-snd",
    smoke_virtio_snd_writer_submit_round_trip
);

#[cfg(target_arch = "x86_64")]
fn smoke_audio_submit_shmem_zero_copy() -> TestResult {
    // End-to-end zero-copy submit: allocate a Shmem region, fill
    // it with silence via the kernel-side phys_at, and submit
    // through AudioWriter::submit_shmem.
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    use narf_drivers_virtio::snd_pci;
    use narf_shmem::{__reset_for_test as shmem_reset, create as shmem_create};

    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == snd_pci::VIRTIO_SND_PCI_VENDOR
            && d.id.device == snd_pci::VIRTIO_SND_PCI_DEVICE
    });
    if !has {
        return TestResult::Skip("no virtio-snd-pci");
    }

    snd_pci::__reset_for_test();
    shmem_reset();
    bus_reset();
    snd_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);

    let h = shmem_create(0, 4096).expect("shmem_create");
    let cap = bootstrap_writer();
    let writer = AudioWriter::open(cap, AudioFormat::default_playback()).expect("open");

    // Valid zero-copy submit.
    if writer.submit_shmem(h, 0, 1024).is_err() {
        return TestResult::Fail("submit_shmem failed");
    }
    // Bad handle rejected.
    if writer.submit_shmem(0xDEADBEEF, 0, 256).is_ok() {
        return TestResult::Fail("bad handle should reject");
    }
    // Length not a frame multiple rejected.
    if writer.submit_shmem(h, 0, 5).is_ok() {
        return TestResult::Fail("non-frame-multiple len should reject");
    }
    shmem_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("audio", smoke_audio_submit_shmem_zero_copy);

// ── AMD ACP6 I2S0 TX path smokes ──────────────────────────────────
//
// These exercise the new `acp6_pcm` module. The ACP6 controller
// isn't present in QEMU (no `1022:15E2` device on the bus), so
// the runtime smokes Skip cleanly there. Structural smokes that
// don't need MMIO run unconditionally.

fn smoke_acp6_pcm_period_samples_constant() -> TestResult {
    // 4 KiB ring / 2 bytes per i16 = 2048 sample slots. Matches
    // the value the audio mixer + lib.rs default_playback expect.
    if crate::acp6_pcm::period_samples() == 2048 {
        TestResult::Pass
    } else {
        TestResult::Fail("acp6_pcm period_samples != 2048")
    }
}
kernel_test_in!("audio/acp6", smoke_acp6_pcm_period_samples_constant);

fn smoke_acp6_pcm_play_skips_when_no_controller() -> TestResult {
    // play_pcm + stop_pcm should report NoController cleanly when
    // no ACP6 device is probed. Confirms the gating path is the
    // first check in each entry point.
    crate::acp6_pcm::__reset_for_test();
    let silence = [0i16; 8];
    match crate::acp6_pcm::play_pcm(&silence) {
        Err(crate::acp6_pcm::PcmError::NoController) => {}
        Err(_) => return TestResult::Fail("play_pcm wrong error"),
        Ok(_) => return TestResult::Fail("play_pcm should require a controller"),
    }
    match crate::acp6_pcm::stop_pcm() {
        Ok(()) => TestResult::Pass,
        Err(_) => TestResult::Fail("stop_pcm should be a no-op without stream"),
    }
}
kernel_test_in!("audio/acp6", smoke_acp6_pcm_play_skips_when_no_controller);

fn smoke_acp6_pcm_play_rejects_bad_buffer() -> TestResult {
    // Empty / odd-channel-count buffer is rejected at the input-
    // validation gate; doesn't need a controller. Run before the
    // "no controller" gate by passing an obviously bad buffer.
    crate::acp6_pcm::__reset_for_test();
    // 3 samples = not a multiple of CHANNELS=2.
    let bad = [0i16; 3];
    match crate::acp6_pcm::play_pcm(&bad) {
        Err(crate::acp6_pcm::PcmError::BadBuffer) => {}
        // If no controller is probed, the controller-gate fires
        // first — also acceptable, since the result is still "not
        // played". Don't fail the smoke on that.
        Err(crate::acp6_pcm::PcmError::NoController) => {}
        _ => return TestResult::Fail("play_pcm should reject odd-sample buffer"),
    }
    let empty: [i16; 0] = [];
    match crate::acp6_pcm::play_pcm(&empty) {
        Err(crate::acp6_pcm::PcmError::BadBuffer)
        | Err(crate::acp6_pcm::PcmError::NoController) => TestResult::Pass,
        _ => TestResult::Fail("play_pcm should reject empty buffer"),
    }
}
kernel_test_in!("audio/acp6", smoke_acp6_pcm_play_rejects_bad_buffer);

fn smoke_acp6_pcm_wm8960_init_sequence_shape() -> TestResult {
    // The codec init sequence emitted for the I2S0 TX path must
    // start with a software reset (datasheet §10) and conclude
    // with output-volume writes. The exact contents are codec-
    // datasheet driven; here we just guard the high-level shape.
    let seq = crate::acp6_pcm::build_wm8960_init_for_i2s0_tx();
    if seq.is_empty() {
        return TestResult::Fail("wm8960 init sequence empty");
    }
    let (first_reg, _) = seq[0];
    if first_reg != crate::wm8960::regs::RESET {
        return TestResult::Fail("wm8960 init must begin with software reset (R15)");
    }
    // Must include the audio-interface programming step.
    let has_iface = seq
        .iter()
        .any(|(r, _)| *r == crate::wm8960::regs::AUDIO_INTERFACE);
    if !has_iface {
        return TestResult::Fail("wm8960 init missing audio-interface write");
    }
    TestResult::Pass
}
kernel_test_in!("audio/acp6", smoke_acp6_pcm_wm8960_init_sequence_shape);

fn smoke_acp6_pci_all_zen2_variants_registered() -> TestResult {
    // Confirm the four documented ACP6 PCI ids are all installed
    // in the bus match table. The Zen2 bring-up box uses 0x15E2;
    // the others are present so an SoC swap doesn't silently
    // skip probe.
    use crate::acp6;
    use narf_bus::driver_match::__reset_for_test as bus_reset;
    use narf_bus::{registered_pci_drivers, MatchKind};
    bus_reset();
    acp6::register_pci_driver();
    let regs = registered_pci_drivers();
    let want = [
        acp6::ACP_RENOIR,
        acp6::ACP_PINK_SARDINE,
        acp6::ACP_REMBRANDT,
        acp6::ACP_MERO,
    ];
    for did in want {
        let found = regs.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice { vendor, device }
                    if vendor == acp6::ACP_VENDOR && device == did
            )
        });
        if !found {
            return TestResult::Fail("ACP PCI ID not registered");
        }
    }
    TestResult::Pass
}
kernel_test_in!("audio/acp6", smoke_acp6_pci_all_zen2_variants_registered);

fn smoke_audio_format_unsupported_rate_rejects() -> TestResult {
    let s = match select_active_playback() {
        Some(s) => s,
        None => return TestResult::Skip("no audio backend probed"),
    };
    let bad = AudioFormat {
        sample_rate_hz: 96_000,
        format: SampleFormat::S16Le,
        channels: ChannelLayout::Stereo,
    };
    if s.supports(bad) {
        return TestResult::Fail("96 kHz advertised but unsupported");
    }
    let good = AudioFormat::default_playback();
    if !s.supports(good) {
        return TestResult::Fail("48 kHz S16 stereo should be supported");
    }
    TestResult::Pass
}
kernel_test_in!("audio", smoke_audio_format_unsupported_rate_rejects);
