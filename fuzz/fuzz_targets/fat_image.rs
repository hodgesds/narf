//! Fuzz target: FAT filesystem image parsing (mount + walk).
//!
//! Surface: `FatVolume::mount` over a RAM disk built from the raw
//! input, then a bounded directory walk with file reads
//! (`narf_fuzz::fswalk`). A filesystem image is untrusted input
//! parsed in kernel context at mount time — BPB geometry, FAT
//! chain walks, directory-entry and LFN reassembly all run on
//! attacker-chosen values. This exact surface produced a kernel
//! panic earlier this year (the FAT12 entry straddling a sector
//! boundary, now pinned by `smoke_fat12_chain_crosses_fat_sector_boundary`);
//! a standing fuzz target is how the next one gets found by a
//! machine instead of by a user.
//!
//! Invariant: never panic, never hang inside the harness, never
//! read out of bounds. `FsError` from mount or any walk step is a
//! fine outcome for a corrupt image.

#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use narf_block::ram::RamBlockDevice;
use narf_drivers_fs_fat::volume::FatVolume;
use narf_filesystem::FsInstance;
use narf_fuzz::{fswalk, host};
use narf_lib::id::DomainId;

/// Cap the image size: the seed is ~32 KiB, and real-world FAT
/// parsing risk lives in geometry arithmetic, not in bulk data.
/// Larger inputs mostly buy libFuzzer slower iterations.
const MAX_IMAGE: usize = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_IMAGE {
        return;
    }
    host::init();

    // RamBlockDevice wants a whole number of 512-byte blocks; pad
    // the tail with zeros (the parser sees a slightly larger,
    // zero-filled device — the same thing a truncated image file
    // on a real disk looks like).
    let mut image = data.to_vec();
    let rem = image.len() % 512;
    if rem != 0 {
        image.resize(image.len() + (512 - rem), 0);
    }
    let device: Arc<RamBlockDevice> = RamBlockDevice::from_image(512, image);

    if let Ok(volume) = host::block_on(FatVolume::mount(device, DomainId::DRIVER_0)) {
        fswalk::walk(volume.root());
    }
});
