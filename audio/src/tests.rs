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
