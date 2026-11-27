//! `narf.ext4_interop=root`: the in-guest half of
//! `cargo xtask ext4-rootrw-interop`.
//!
//! Booted under `narf.disks=root-rw` against a host-built GPT disk whose
//! root is LUKS1 around a `mkfs.ext4 -d` filesystem (unlocked through the
//! console prompt, the passphrase typed on the emulated PS/2 keyboard), this
//! runs pacman- and systemd-shaped writes through the VFS on the mounted
//! root, then remounts it read-only, which marks the filesystem clean, and
//! prints one verdict line. `narf.ext4_interop=crash` instead leaves the
//! journaled root mounted read-write with one synced file and one only the
//! commit timer commits, for the host to kill NARF and recover the disk. The host decrypts the partition and lets
//! e2fsprogs judge it. Every byte written here is a pure function of the
//! mode, so the host checks content without a channel back.
//!
//! The workload refuses any root but the harness's: the LUKS container that
//! `root=UUID=` names and the ext4 inside it must both carry the harness
//! UUID prefix.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_filesystem::{DirOps, FileOps, FsError};

/// Verdict-line prefix the host matches.
pub const MARKER: &str = "EXT4-INTEROP:";
/// UUID prefix of every disposable image xtask builds (the btrfs harness's).
pub const HARNESS_UUID_PREFIX: &str = "c4c405ee-0000-4a11-9e57-";

/// `/etc/hostname` after the workload (write + fsync + rename over).
pub const HOSTNAME: &[u8] = b"narf-ext4-interop\n";
/// `/var/lib/pacman/local/ALPM_DB_VERSION` after the workload.
pub const ALPM_DB_VERSION: &[u8] = b"9\n";
/// The pacman `desc` the workload installs.
pub const PKG_DESC: &[u8] = b"%NAME%\nnarf-interop\n\n%VERSION%\n1.0-1\n";
/// Where `/usr/share/narf/big.bin` is overwritten, and with how many bytes
/// of `pattern(7, ..)`.
pub const BIG_PATCH: (u64, usize) = (300_000, 8192);
/// `/var/log/narf.log`: appended in 4 KiB writes of `pattern(9 + i, 4096)`.
pub const LOG_CHUNKS: u32 = 64;
/// New names in the indexed `/usr/lib/narf-many`; every third is removed.
pub const MANY: u32 = 3000;
/// Blocks of `/var/tmp/sparse` written, one in two, in shuffled order:
/// 1500 extents at 4 KiB blocks need an extent tree of depth 2.
pub const SPARSE: u32 = 1500;
/// `/usr/share/narf/trunc.bin` is truncated to this size.
pub const TRUNC_TO: u64 = 100_000;

/// Deterministic content: `len` bytes derived from `seed` (the host has the
/// same function).
pub fn pattern(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// The order `/var/tmp/sparse`'s blocks are written in: a Fisher-Yates
/// shuffle of `0..SPARSE` by the same xorshift.
pub fn sparse_order() -> Vec<u32> {
    let mut order: Vec<u32> = (0..SPARSE).collect();
    let mut x = 0x9e37_79b9u32;
    for i in (1..order.len()).rev() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        order.swap(i, x as usize % (i + 1));
    }
    order
}

async fn dir_at(root: &Arc<dyn DirOps>, path: &str) -> Result<Arc<dyn DirOps>, FsError> {
    let mut dir = root.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        dir = dir.lookup_dir_async(part).await?;
    }
    Ok(dir)
}

async fn write_all(file: &Arc<dyn FileOps>, mut at: u64, mut data: &[u8]) -> Result<(), FsError> {
    while !data.is_empty() {
        let n = file.write(at, data).await?;
        if n == 0 {
            return Err(FsError::NoSpace);
        }
        at += n as u64;
        data = &data[n..];
    }
    Ok(())
}

/// Write `data` to `dir/tmp`, fsync it, and rename it over `dir/name`, as
/// systemd and pacman replace a file.
async fn replace(dir: &Arc<dyn DirOps>, name: &str, data: &[u8]) -> Result<(), FsError> {
    let tmp = format!("{name}.narf-tmp");
    let file = dir.create(&tmp).await?;
    write_all(&file, 0, data).await?;
    file.fsync(false).await?;
    drop(file);
    dir.rename(&tmp, name).await
}

async fn run_root(root: &Arc<dyn DirOps>) -> Result<(), (&'static str, FsError)> {
    let etc = dir_at(root, "/etc").await.map_err(|e| ("/etc", e))?;
    replace(&etc, "hostname", HOSTNAME)
        .await
        .map_err(|e| ("replace /etc/hostname", e))?;

    let local = dir_at(root, "/var/lib/pacman/local")
        .await
        .map_err(|e| ("/var/lib/pacman/local", e))?;
    let pkg = local
        .mkdir("narf-interop-1.0-1")
        .await
        .map_err(|e| ("mkdir package dir", e))?;
    let desc = pkg.create("desc").await.map_err(|e| ("create desc", e))?;
    write_all(&desc, 0, PKG_DESC)
        .await
        .map_err(|e| ("write desc", e))?;
    replace(&local, "ALPM_DB_VERSION", ALPM_DB_VERSION)
        .await
        .map_err(|e| ("replace ALPM_DB_VERSION", e))?;

    let share = dir_at(root, "/usr/share/narf")
        .await
        .map_err(|e| ("/usr/share/narf", e))?;
    let big = share
        .lookup_async("big.bin")
        .await
        .map_err(|e| ("big.bin", e))?;
    write_all(&big, BIG_PATCH.0, &pattern(7, BIG_PATCH.1))
        .await
        .map_err(|e| ("overwrite big.bin", e))?;
    let trunc = share
        .lookup_async("trunc.bin")
        .await
        .map_err(|e| ("trunc.bin", e))?;
    trunc
        .truncate(TRUNC_TO)
        .await
        .map_err(|e| ("truncate trunc.bin", e))?;
    drop(trunc);
    share
        .unlink("remove-me")
        .await
        .map_err(|e| ("unlink remove-me", e))?;
    share
        .rmdir("empty-dir")
        .await
        .map_err(|e| ("rmdir empty-dir", e))?;

    let log_dir = dir_at(root, "/var/log")
        .await
        .map_err(|e| ("/var/log", e))?;
    let log = log_dir
        .create("narf.log")
        .await
        .map_err(|e| ("create narf.log", e))?;
    for i in 0..LOG_CHUNKS {
        write_all(&log, u64::from(i) * 4096, &pattern(9 + i, 4096))
            .await
            .map_err(|e| ("append narf.log", e))?;
        if i % 16 == 15 {
            log.fsync(false).await.map_err(|e| ("fsync narf.log", e))?;
        }
    }

    let many = dir_at(root, "/usr/lib/narf-many")
        .await
        .map_err(|e| ("/usr/lib/narf-many", e))?;
    for i in 0..MANY {
        let file = many
            .create(&format!("n{i:05}"))
            .await
            .map_err(|e| ("create in the indexed directory", e))?;
        write_all(&file, 0, format!("n{i:05}\n").as_bytes())
            .await
            .map_err(|e| ("write in the indexed directory", e))?;
    }
    for i in (0..MANY).step_by(3) {
        many.unlink(&format!("n{i:05}"))
            .await
            .map_err(|e| ("unlink in the indexed directory", e))?;
    }

    let vtmp = dir_at(root, "/var/tmp")
        .await
        .map_err(|e| ("/var/tmp", e))?;
    let sparse = vtmp
        .create("sparse")
        .await
        .map_err(|e| ("create sparse", e))?;
    for i in sparse_order() {
        write_all(&sparse, u64::from(i) * 2 * 4096, &pattern(1000 + i, 4096))
            .await
            .map_err(|e| ("write sparse", e))?;
    }

    let srv = dir_at(root, "/srv").await.map_err(|e| ("/srv", e))?;
    srv.mkdir("narf-new")
        .await
        .map_err(|e| ("mkdir /srv/narf-new", e))?;
    root.syncfs().await.map_err(|e| ("syncfs", e))?;
    Ok(())
}

/// The root's filesystem UUID from its superblock (canonical lowercase).
/// What `crash` mode writes; the host checks them
/// (`build/xtask/src/ext4_interop.rs`).
pub const CRASH_SYNCED_SEED: u32 = 0x5359_4e43;
pub const CRASH_SYNCED_LEN: usize = 300_000;
pub const CRASH_TIMER_SEED: u32 = 0x5449_4d52;
pub const CRASH_TIMER_LEN: usize = 50_000;

/// `narf.ext4_interop=crash`: the root is left mounted read-write for the
/// host to kill NARF under it.
/// - `/narf-crash/synced` is written, fsynced, renamed into place and
///   `syncfs`'d;
/// - `/narf-crash/timer` is written with no sync at all;
/// - then this waits past twice the journal's commit interval, so only the
///   commit timer can have committed `timer`.
async fn run_crash(root: &Arc<dyn DirOps>) -> Result<(), (&'static str, FsError)> {
    let dir = root
        .mkdir("narf-crash")
        .await
        .map_err(|e| ("mkdir /narf-crash", e))?;
    replace(
        &dir,
        "synced",
        &pattern(CRASH_SYNCED_SEED, CRASH_SYNCED_LEN),
    )
    .await
    .map_err(|e| ("write /narf-crash/synced", e))?;
    root.syncfs().await.map_err(|e| ("syncfs", e))?;
    let timer = dir
        .create("timer")
        .await
        .map_err(|e| ("create /narf-crash/timer", e))?;
    write_all(&timer, 0, &pattern(CRASH_TIMER_SEED, CRASH_TIMER_LEN))
        .await
        .map_err(|e| ("write /narf-crash/timer", e))?;
    let wait = 2 * crate::volume::jbd::COMMIT_INTERVAL_SECS + 2;
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(wait * 1_000_000_000)).await;
    Ok(())
}

fn ext4_uuid(dev: &dyn narf_block::BlockDeviceSync) -> Option<String> {
    let lba = dev.lba_size() as usize;
    if lba == 0 || lba > 1024 || 1024 % lba != 0 {
        return None;
    }
    let mut sb = alloc::vec![0u8; 1024];
    dev.read((1024 / lba) as u64, (1024 / lba) as u16, &mut sb)
        .ok()?;
    if sb[56..58] != crate::EXT2_SUPER_MAGIC.to_le_bytes() {
        return None;
    }
    let uuid: [u8; 16] = sb[104..120].try_into().ok()?;
    Some(narf_block::partition::format_uuid_bytes(&uuid).to_ascii_lowercase())
}

pub fn run(mode: &str) -> narf_init::InitResult {
    let line = |text: &str| {
        let _ = writeln!(narf_console::Writer, "{MARKER} {text}");
    };
    let root_fs = narf_filesystem::registry().fs_arc_at("/");
    let usable = narf_block::disk_policy::root_writable()
        && root_fs
            .as_ref()
            .is_some_and(|fs| matches!(fs.name(), "ext2" | "ext4") && !fs.always_read_only());
    let Some(fs) = root_fs.filter(|_| usable) else {
        line("NO-ROOT (no writable ext4 root under narf.disks=root-rw)");
        return narf_init::InitResult::NotPresent;
    };
    // Never a real root: the container `root=UUID=` names and the ext4 in
    // it must both be the harness's.
    let outer = narf_boot::args()
        .value("root")
        .and_then(|root| root.strip_prefix("UUID="))
        .map(|uuid| uuid.to_ascii_lowercase());
    let inner = narf_block::find_block_device("cryptroot").and_then(|dev| ext4_uuid(&*dev));
    let harness = |uuid: &Option<String>| {
        uuid.as_deref()
            .is_some_and(|u| u.starts_with(HARNESS_UUID_PREFIX))
    };
    if !harness(&outer) || !harness(&inner) {
        line("REFUSED (root is not the harness's LUKS + ext4 image)");
        return narf_init::InitResult::Error("ext4 root-rw interop refused a non-harness root");
    }
    let root = fs.root();
    let result = narf_scheduler::block_on(async {
        match mode {
            "root" => {
                run_root(&root)
                    .await
                    .map_err(|(what, e)| format!("{what}: {e:?}"))?;
                // A remount read-only marks the filesystem clean, as an
                // unmount does.
                fs.reconfigure_sb_async(
                    narf_filesystem::sb_flags::RDONLY,
                    narf_filesystem::sb_flags::RDONLY,
                    "",
                )
                .await
                .map_err(|e| format!("remount read-only: {e:?}"))
            }
            // Left mounted read-write: the host kills NARF here.
            "crash" => run_crash(&root)
                .await
                .map_err(|(what, e)| format!("{what}: {e:?}")),
            _ => Err(String::from("unknown mode")),
        }
    });
    match result {
        Ok(()) => {
            line(&format!("PASS {mode}"));
            narf_init::InitResult::Ok
        }
        Err(why) => {
            line(&format!("FAIL {mode}: {why}"));
            narf_init::InitResult::Error("ext4 root-rw interop workload failed")
        }
    }
}
