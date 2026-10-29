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

    // Put the world back on every path out.
    //
    // These three resets are global and outlive this test. Without a restore
    // the audio backend stays unprobed for the whole boot, and any later test
    // needing one skips -- `smoke_audio_format_unsupported_rate_rejects` did
    // exactly that, intermittently, depending on whether it happened to run
    // before or after this one. It read as a flaky audio test; it was this
    // test's teardown.
    let _restore = AudioProbeRestore;

    let picked = select_active_playback().is_some();
    // AudioWriter::open should fail with NoActiveStream.
    let cap = bootstrap_writer();
    let opened = AudioWriter::open(cap, AudioFormat::default_playback());

    if picked {
        return TestResult::Fail("picker returned a stream with no controller");
    }
    match opened {
        Err(AudioWriteError::NoActiveStream) => TestResult::Pass,
        _ => TestResult::Fail("AudioWriter::open should have failed with NoActiveStream"),
    }
}

/// Re-register the audio PCI drivers and re-probe, undoing the global resets
/// a test performed.
///
/// Best-effort by design: on a machine with no audio device there is nothing
/// to restore, and failing here would turn "this platform has no sound card"
/// into a test failure. What it must not do is leave the buses unregistered
/// after a test cleared them.
///
/// Registers *every* audio driver, not just the one the calling test cared
/// about. `driver_match::__reset_for_test` empties the whole table, so a test
/// that clears it and re-registers only its own subject leaves the others
/// missing for everything that runs afterwards.
pub(crate) fn restore_audio_probe_state() {
    use narf_bus::{bootstrap_registry_authority, probe_all_pci};
    use narf_drivers_virtio::snd_pci;

    crate::hda::register_pci_driver();
    crate::acp6::register_pci_driver();
    snd_pci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    let _ = probe_all_pci(&authority);
}

/// Scope guard that restores audio probe state on the way out.
///
/// Declared immediately after a test's `__reset_for_test` calls, it covers
/// every path out including early `return TestResult::Fail(..)` — which is
/// what a manual call at the end of the happy path does not. These tests have
/// several early returns each, and the state they clear is global and outlives
/// the boot.
pub(crate) struct AudioProbeRestore;

#[cfg(target_arch = "x86_64")]
fn smoke_virtio_sound_devfs_pcm_and_sysfs() -> TestResult {
    use narf_drivers_sound::tests_support::poll_once;
    use narf_drivers_virtio::snd_pci;
    use narf_filesystem::FsInstance;

    if !narf_bus::devices().iter().any(|d| {
        d.id.vendor == snd_pci::VIRTIO_SND_PCI_VENDOR
            && d.id.device == snd_pci::VIRTIO_SND_PCI_DEVICE
    }) {
        return TestResult::Skip("no virtio-snd-pci");
    }
    snd_pci::__reset_for_test();
    let _restore = AudioProbeRestore;
    restore_audio_probe_state();
    narf_drivers_sound::sound_fs_initcall();
    let result = (|| -> Result<(), &'static str> {
        let card = narf_drivers_sound::list_cards()
            .into_iter()
            .find(|card| card.driver == "virtio-sound")
            .ok_or("VirtIO is absent from sound registry")?;
        let root = narf_filesystem::sysfs::SysFs::new().root();
        let vendor = poll_once(narf_filesystem::resolve_async(
            root,
            &alloc::format!("class/sound/card{}/device/vendor", card.index),
        ))
        .map_err(|_| "VirtIO sound has no physical PCI parent")?;
        let mut buf = [0; 32];
        let count = poll_once(vendor.read(0, &mut buf)).map_err(|_| "PCI vendor read failed")?;
        if &buf[..count] != b"0x1af4\n" {
            return Err("VirtIO sound has the wrong PCI parent");
        }
        let snd = narf_filesystem::devfs::DevFs::new()
            .root()
            .lookup_dir("snd")
            .ok_or("/dev/snd missing")?;
        let name = alloc::format!("pcmC{}D0p", card.index);
        let file = snd.lookup(&name).ok_or("VirtIO playback node missing")?;
        // Cross the old scratch-buffer limit and the request/status boundary.
        if poll_once(file.write(0, &[0x42; 8192])).map_err(|_| "VirtIO devfs playback failed")?
            != 8192
        {
            return Err("VirtIO devfs playback returned the wrong byte count");
        }
        if narf_drivers_sound::open_playback(card.index, 0).is_ok() {
            return Err("VirtIO PCM lease was not exclusive");
        }
        if snd_pci::play_buffer(snd_pci::PcmParams::default_playback(), &[0; 16]).is_ok() {
            return Err("kernel submit bypassed the PCM lease");
        }
        poll_once(file.flush()).map_err(|_| "VirtIO drain/stop failed")?;
        drop(file);
        let file = snd
            .lookup(&name)
            .ok_or("VirtIO playback disappeared after close")?;
        let mut params = [0; 20];
        for (slot, value) in params.chunks_exact_mut(4).zip([0u32, 44100, 1, 1024, 4]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        poll_once(file.write(
            narf_drivers_sound::devfs_bridge::HW_PARAMS_MAGIC_OFFSET,
            &params,
        ))
        .map_err(|_| "VirtIO PCM reconfiguration failed")?;
        if poll_once(file.write(0, &[0; 1024]))
            .map_err(|_| "reconfigured VirtIO playback failed")?
            != 1024
        {
            return Err("reconfigured VirtIO byte count mismatch");
        }
        poll_once(file.flush()).map_err(|_| "reconfigured PCM drain failed")?;
        // QEMU 10.2 derives PCM_INFO.channels_max from the last prepared
        // voice (hw/audio/virtio-snd.c::virtio_snd_pcm_prepare). Restore the
        // stereo fixture before a later test resets and queries the device.
        for (slot, value) in params.chunks_exact_mut(4).zip([0u32, 48000, 2, 1024, 4]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        poll_once(file.write(
            narf_drivers_sound::devfs_bridge::HW_PARAMS_MAGIC_OFFSET,
            &params,
        ))
        .map_err(|_| "restoring VirtIO stereo configuration failed")?;
        poll_once(file.write(0, &[0; 16])).map_err(|_| "restoring VirtIO stereo voice failed")?;
        poll_once(file.flush()).map_err(|_| "restored VirtIO PCM drain failed")?;
        Ok(())
    })();
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("audio/virtio-snd", smoke_virtio_sound_devfs_pcm_and_sysfs);

impl Drop for AudioProbeRestore {
    fn drop(&mut self) {
        restore_audio_probe_state();
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

    // SAFETY: the kernel-test runner executes post-bootstrap, so the
    // memory map is parsed and the allocator is online; `ECAM_DEFAULT_BASE`
    // is the platform's well-known ECAM physical base, and `init` only
    // reads config-space words from it.
    // SAFETY: Valid memory or trusted environment
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

    // SAFETY: the kernel-test runner executes post-bootstrap, so the
    // memory map is parsed and the allocator is online; `ECAM_DEFAULT_BASE`
    // is the platform's well-known ECAM physical base, and `init` only
    // reads config-space words from it.
    // SAFETY: Valid memory or trusted environment
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
    let writer = match AudioWriter::open(cap, AudioFormat::default_playback()) {
        Ok(writer) => writer,
        Err(_) => return TestResult::Fail("AudioWriter shmem open"),
    };

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

fn smoke_acp63_pci_match_excludes_hda() -> TestResult {
    use narf_bus::{registered_pci_drivers, MatchKind};
    narf_bus::driver_match::__reset_for_test();
    let _restore = AudioProbeRestore;
    crate::acp6::register_pci_driver();
    let registrations = registered_pci_drivers();
    if !registrations.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice {
                vendor: 0x1022,
                device: 0x15e2
            }
        )
    }) {
        return TestResult::Fail("ACP 6.3 match missing");
    }
    if registrations.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice {
                vendor: 0x1022,
                device: 0x15e3
            }
        )
    }) {
        return TestResult::Fail("ACP must never claim the HDA function");
    }
    TestResult::Pass
}
kernel_test_in!("audio/acp63", smoke_acp63_pci_match_excludes_hda);

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

fn smoke_hda_quirks_table_contents() -> TestResult {
    use crate::hda::quirks::{
        find_quirk, first_for_chip, init_table_for, quirk_count, CoefRow, RealtekChip, QUIRK_TABLE,
    };

    // Rescued from drivers/sound/src/codec/{quirks,realtek}.rs (#783):
    // the table must carry all six subsystem quirks verbatim.
    if quirk_count() != 6 {
        return TestResult::Fail("quirk table must hold 6 entries");
    }
    let total_pins: usize = QUIRK_TABLE.iter().map(|q| q.pins.len()).sum();
    if total_pins != 21 {
        return TestResult::Fail("quirk table must hold 21 pin overrides in total");
    }
    let x1 = match find_quirk(0x17AA_22BE) {
        Some(q) => q,
        None => return TestResult::Fail("X1 Carbon quirk missing"),
    };
    if x1.name != "Lenovo ThinkPad X1 Carbon Gen 7" || x1.chip != RealtekChip::Alc285 {
        return TestResult::Fail("X1 Carbon quirk identity changed");
    }
    if (x1.pins[0].nid, x1.pins[0].cfg) != (0x14, 0x9017_0110) {
        return TestResult::Fail("X1 Carbon first pin override changed");
    }
    match find_quirk(0x103C_8716) {
        Some(q) if q.chip == RealtekChip::Alc285 => {}
        _ => return TestResult::Fail("EliteBook 845 G8 quirk missing or wrong chip"),
    }
    if find_quirk(0xDEAD_BEEF).is_some() {
        return TestResult::Fail("unknown subsystem id must not match a quirk");
    }
    match first_for_chip(RealtekChip::Alc256) {
        Some(q) if q.subsystem_id == 0x1028_0AB9 => {}
        _ => return TestResult::Fail("first ALC256 quirk must be the Dell entry"),
    }

    // Init tables: the 18 literal tables hold 29 coef rows in total.
    const BASE_CHIPS: [RealtekChip; 18] = [
        RealtekChip::Alc256,
        RealtekChip::Alc233,
        RealtekChip::Alc235,
        RealtekChip::Alc236,
        RealtekChip::Alc270,
        RealtekChip::Alc280,
        RealtekChip::Alc282,
        RealtekChip::Alc283,
        RealtekChip::Alc285,
        RealtekChip::Alc286,
        RealtekChip::Alc287,
        RealtekChip::Alc289,
        RealtekChip::Alc290,
        RealtekChip::Alc292,
        RealtekChip::Alc293,
        RealtekChip::Alc294,
        RealtekChip::Alc295,
        RealtekChip::Alc298,
    ];
    let total_rows: usize = BASE_CHIPS.iter().map(|c| init_table_for(*c).len()).sum();
    if total_rows != 29 {
        return TestResult::Fail("init tables must hold 29 coef rows in total");
    }
    if init_table_for(RealtekChip::Alc285)[1] != CoefRow::new(0x6F, 0x0007) {
        return TestResult::Fail("ALC285 init row 1 changed");
    }
    if init_table_for(RealtekChip::Alc287)[2] != CoefRow::new(0x38, 0x4901) {
        return TestResult::Fail("ALC287 init row 2 changed");
    }
    // Alias arms must resolve to the same tables as their base chips.
    if init_table_for(RealtekChip::Alc257) != init_table_for(RealtekChip::Alc256) {
        return TestResult::Fail("ALC257 must alias the ALC256 init table");
    }
    if init_table_for(RealtekChip::Alc3204) != init_table_for(RealtekChip::Alc287) {
        return TestResult::Fail("ALC3204 must alias the ALC287 init table");
    }
    // Chip identification by codec device id.
    if RealtekChip::from_vendor_id(0x10EC_0285) != Some(RealtekChip::Alc285) {
        return TestResult::Fail("0x10EC0285 must identify as ALC285");
    }
    if RealtekChip::from_vendor_id(0x10EC_9999).is_some() {
        return TestResult::Fail("unknown Realtek device id must not identify");
    }
    if RealtekChip::Alc295.name() != "ALC295" {
        return TestResult::Fail("ALC295 name changed");
    }
    TestResult::Pass
}
kernel_test_in!("audio/hda-quirks", smoke_hda_quirks_table_contents);
