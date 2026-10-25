//! Fuzz target: MINIX filesystem image parsing (mount + walk).
//!
//! Surface: `MinixVolume::mount` over a RAM disk built from the
//! raw input, then the same bounded walk as the FAT target. The
//! minix driver is a second, independent on-disk format with its
//! own superblock validation, inode decode, and zone-map
//! arithmetic (direct + indirect zones) — all over untrusted
//! values at mount and lookup time, and none of it sharing code
//! with the FAT parser, so it needs its own target.
//!
//! Invariant: never panic, never hang inside the harness, never
//! read out of bounds. `FsError` is a fine outcome for a corrupt
//! image.

#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use narf_block::ram::RamBlockDevice;
use narf_drivers_fs_minix::volume::MinixVolume;
use narf_filesystem::FsInstance;
use narf_fuzz::{fswalk, host};
use narf_lib::id::DomainId;

/// See fat_image: geometry arithmetic is the risk surface, not
/// bulk size.
const MAX_IMAGE: usize = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_IMAGE {
        return;
    }
    host::init();

    let mut image = data.to_vec();
    let rem = image.len() % 512;
    if rem != 0 {
        image.resize(image.len() + (512 - rem), 0);
    }
    let device: Arc<RamBlockDevice> = RamBlockDevice::from_image(512, image);

    if let Ok(volume) = host::block_on(MinixVolume::mount(device, DomainId::DRIVER_0)) {
        fswalk::walk(volume.root());
    }
});
