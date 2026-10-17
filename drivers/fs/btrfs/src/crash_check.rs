//! `narf.btrfs_crash=write|verify`: the guest half of
//! `cargo xtask btrfs-crash-smoke`.
//!
//! `write` mounts the first btrfs device, writes a patterned file, `fsync`s
//! it, prints [`COMMITTED`], and then keeps writing uncommitted noise until
//! the host kills QEMU. `verify` (the next boot of the same image) mounts it
//! read-only and checks that the fsynced file is intact. Together they show
//! that a returned `fsync` (a flushed and FUA-written commit) survives an
//! abrupt stop with I/O in flight.
//!
//! Test scaffolding that writes to a disk. It runs only when the command line
//! asks for it, and xtask passes that flag only with its own disposable image.

use alloc::sync::Arc;
use core::fmt::Write as _;

use narf_block::fs_detect::{detect_filesystem, FsType};
use narf_console::Writer as Serial;
use narf_filesystem::{FsError, FsInstance};

/// Serial line the host waits for before killing QEMU.
pub const COMMITTED: &str = "NARF-BTRFS-CRASH: COMMITTED";
/// Verdict lines of the `verify` boot.
pub const OK: &str = "NARF-BTRFS-CRASH: OK";
pub const FAIL: &str = "NARF-BTRFS-CRASH: FAIL";

const FILE: &str = "narf-crash.dat";
const LEN: usize = 256 * 1024;

fn pattern(i: usize) -> u8 {
    (i as u8).wrapping_mul(31) ^ (i >> 9) as u8
}

/// Register the Stage::Late hook (inert unless `narf.btrfs_crash` is given).
pub fn register() {
    narf_init::register(narf_init::Stage::Late, "btrfs-crash-check", || {
        let Some(mode) = narf_boot::args().value("narf.btrfs_crash") else {
            return narf_init::InitResult::NotPresent;
        };
        let Some(entry) = narf_block::block_devices()
            .into_iter()
            .find(|e| matches!(detect_filesystem(&e.dev), Ok(Some(FsType::Btrfs))))
        else {
            let _ = writeln!(Serial, "{FAIL} (no btrfs device)");
            return narf_init::InitResult::Error("no btrfs device");
        };
        let dev = entry.dev.clone();
        let members = crate::discover_members(dev.clone());
        match mode {
            "write" => {
                let result = narf_scheduler::block_on(async {
                    let vol = crate::registry::mount(&dev, members, None, false).await?;
                    let root = vol.root();
                    let file = root.create(FILE).await?;
                    let data: alloc::vec::Vec<u8> = (0..LEN).map(pattern).collect();
                    file.write(0, &data).await?;
                    file.fsync(false).await?;
                    Ok::<_, FsError>(vol)
                });
                let vol = match result {
                    Ok(vol) => vol,
                    Err(e) => {
                        let _ = writeln!(Serial, "{FAIL} (write: {e:?})");
                        return narf_init::InitResult::Error("btrfs crash write failed");
                    }
                };
                let _ = writeln!(Serial, "{COMMITTED}");
                // Keep the device busy with writes no fsync covers, so the
                // kill lands with I/O and an open transaction in flight.
                let root = vol.root();
                for i in 0u32.. {
                    let noise = narf_scheduler::block_on(async {
                        let f = root.create(&alloc::format!("narf-noise-{i}")).await?;
                        f.write(0, &[i as u8; 8192]).await
                    });
                    if noise.is_err() {
                        break;
                    }
                }
                core::mem::forget(vol);
                narf_init::InitResult::Ok
            }
            "verify" => {
                let verdict = narf_scheduler::block_on(async {
                    let vol: Arc<crate::volume::BtrfsVolume<narf_block::SyncBlock>> =
                        crate::registry::mount(&dev, members, None, true).await?;
                    let file = vol.root().lookup_async(FILE).await?;
                    let mut buf = alloc::vec![0u8; LEN + 16];
                    let n = file.read(0, &mut buf).await?;
                    Ok::<_, FsError>(
                        n == LEN && buf[..n].iter().enumerate().all(|(i, &b)| b == pattern(i)),
                    )
                });
                match verdict {
                    Ok(true) => {
                        let _ = writeln!(Serial, "{OK}");
                        narf_init::InitResult::Ok
                    }
                    other => {
                        let _ = writeln!(Serial, "{FAIL} (verify: {other:?})");
                        narf_init::InitResult::Error("btrfs crash verify failed")
                    }
                }
            }
            _ => narf_init::InitResult::NotPresent,
        }
    });
}
