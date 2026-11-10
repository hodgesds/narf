//! The `enospc` scenario: running out of space under `narf.disks=root-rw`.
//!
//! A commit that runs out of metadata space aborts the transaction, and with
//! it every operation the filesystem had already acknowledged. So space has
//! to run out *before* an operation is accepted: the operation that cannot
//! reserve waits for reclaim (a commit, then a new chunk) or gets `ENOSPC`
//! itself, and the commit always succeeds. Three shapes:
//!
//!  * `full` — a device with nothing left to allocate, its metadata filled
//!    with acknowledged creates until one is refused. The refusal must be
//!    `ENOSPC`, the commit must succeed, unlinking must still work (it may
//!    borrow the global reserve), and afterwards there is room again;
//!  * `data-grow` — data block groups filled to the last megabyte with
//!    unallocated device space behind them: the write that does not fit gets
//!    a new DATA chunk at reservation time, and the save-file burst that
//!    follows (create a temporary file, write, fsync, rename over the old
//!    name) lands;
//!  * `metadata-grow` — the DUP metadata block group filled by tens of
//!    thousands of small files (to about 85%, where the reservation of the
//!    next batch no longer fits) until a METADATA chunk has to be allocated,
//!    then the same burst.
//!
//! In none of them may the filesystem abort: every later operation would
//! then fail read-only. `btrfs check` judges each final image.

use std::path::Path;
use std::sync::Arc;

use narf_filesystem::{DirOps, FsError, FsInstance};

use crate::dev::RecDev;
use crate::host::block_on;
use crate::{dev, fixture, linux, narf, Args};

fn mkfs(args: &Args, name: &str, size: u64, tag: u64) -> Result<std::path::PathBuf, String> {
    let dir = args.workdir.join(format!("enospc-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let rootdir = dir.join("rootdir");
    std::fs::create_dir_all(rootdir.join("@/etc")).unwrap();
    std::fs::create_dir_all(rootdir.join("@home")).unwrap();
    std::fs::write(rootdir.join("@/etc/hostname"), b"enospc\n").unwrap();
    let img = dir.join("fs.img");
    fixture::mkfs(
        &img,
        &rootdir,
        &fixture::MkfsSpec {
            uuid: &format!("c4c405ee-0000-4a11-9e57-{:012x}", 0xe505_0000_0000u64 + tag),
            size,
            nodesize: 16384,
            csum: "crc32c",
            features: "block-group-tree,free-space-tree,no-holes",
        },
    )?;
    Ok(img)
}

fn mount(img: &Path) -> Result<Arc<dyn FsInstance>, String> {
    let (fsid, node, _) = dev::image_identity(img);
    let dev = Arc::new(RecDev::open(img, 512, fsid, node));
    narf::register_root(dev, &fsid)?;
    Ok(narf::mount_root_rw(&fsid, "@", &[])?.remove(0))
}

fn sync(dir: &Arc<dyn DirOps>) -> Result<(), String> {
    block_on(dir.fsync(false)).map_err(|e| format!("sync: {e:?}"))
}

/// Incompressible bytes, different for every `seed`.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = (seed + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Create `name` holding `body`.
fn put(dir: &Arc<dyn DirOps>, name: &str, body: &[u8]) -> Result<(), FsError> {
    block_on(async {
        let file = dir.create(name).await?;
        let mut done = 0;
        while done < body.len() {
            let n = file.write(done as u64, &body[done..]).await?;
            if n == 0 {
                return Err(FsError::NoSpace);
            }
            done += n;
        }
        Ok(())
    })
}

/// KDE's `QSaveFile` pattern, `rounds` times over the same name: create a
/// temporary file, write 1.4 KiB, fsync it, rename it over the old name.
fn save_file_burst(dir: &Arc<dyn DirOps>, rounds: usize) -> Result<(), String> {
    put(dir, "settings.conf", &noise(0, 1400)).map_err(|e| format!("first save: {e:?}"))?;
    block_on(async {
        for i in 0..rounds {
            let tmp = format!("settings.conf.{i:06x}");
            let file = dir
                .create(&tmp)
                .await
                .map_err(|e| format!("burst create {i}: {e:?}"))?;
            file.write(0, &noise(i as u64 + 1, 1400))
                .await
                .map_err(|e| format!("burst write {i}: {e:?}"))?;
            file.fsync(false)
                .await
                .map_err(|e| format!("burst fsync {i}: {e:?}"))?;
            dir.rename(&tmp, "settings.conf")
                .await
                .map_err(|e| format!("burst rename {i}: {e:?}"))?;
        }
        Ok(())
    })
}

/// Linux's verdict, then a NARF remount that must still be writable.
fn judge(img: &Path, dir_name: &str) -> Result<(), String> {
    linux::check(img, false)?;
    linux::check(img, true)?;
    let fs = mount(img)?;
    if fs.always_read_only() {
        return Err("remounted read-only".into());
    }
    let dir = block_on(fs.root().lookup_dir_async(dir_name))
        .map_err(|e| format!("remount: lookup {dir_name}: {e:?}"))?;
    put(&dir, "after-remount", b"still writable\n")
        .map_err(|e| format!("write after remount: {e:?}"))?;
    sync(&dir)?;
    drop(dir);
    drop(fs);
    narf::reset();
    linux::check(img, false).map_err(|e| format!("after NARF remount: {e}"))
}

fn run_full(args: &Args) -> Result<String, String> {
    let img = mkfs(args, "full", 256 << 20, 1)?;
    let fs = mount(&img)?;
    let top = block_on(fs.root().mkdir("fill")).map_err(|e| format!("mkdir: {e:?}"))?;
    // Turn every unallocated byte into DATA chunks, then give the data back:
    // the metadata block group can no longer grow.
    let mut ballast = 0usize;
    loop {
        match put(
            &top,
            &format!("ballast{ballast}"),
            &noise(ballast as u64, 1 << 20),
        ) {
            Ok(()) => ballast += 1,
            Err(FsError::NoSpace) => {
                // The refused file may exist, empty or partial.
                let _ = block_on(top.unlink(&format!("ballast{ballast}")));
                break;
            }
            Err(e) => return Err(format!("ballast {ballast}: {e:?} (not ENOSPC)")),
        }
        if ballast > 4096 {
            return Err("the device never filled".into());
        }
    }
    sync(&top)?;
    for i in 0..ballast {
        block_on(top.unlink(&format!("ballast{i}")))
            .map_err(|e| format!("unlink ballast{i} on a full device: {e:?}"))?;
    }
    sync(&top)?;
    let chunks = linux::chunk_counts(&img);
    // Fill the metadata with acknowledged operations until one is refused.
    let body = noise(7, 1500);
    let mut made = 0usize;
    let refused = loop {
        match put(&top, &format!("m{made:07}-{}", "x".repeat(120)), &body) {
            Ok(()) => made += 1,
            Err(e) => break e,
        }
        if made > 2_000_000 {
            return Err("metadata never filled".into());
        }
    };
    if refused != FsError::NoSpace {
        return Err(format!(
            "after {made} creates the refusal was {refused:?}, not ENOSPC (aborted?)"
        ));
    }
    let why = crate::host::klog_take()
        .lines()
        .rev()
        .find(|l| l.contains("btrfs: ENOSPC:"))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| "(no reason logged)".into());
    // Everything acknowledged commits.
    sync(&top).map_err(|e| format!("commit of {made} acknowledged creates: {e}"))?;
    if linux::chunk_counts(&img) != chunks {
        return Err("a chunk was allocated on a device with no room".into());
    }
    // A full filesystem can still delete, and gets its space back.
    let drop_count = made / 4;
    for i in 0..drop_count {
        block_on(top.unlink(&format!("m{i:07}-{}", "x".repeat(120))))
            .map_err(|e| format!("unlink {i} on a full filesystem: {e:?}"))?;
    }
    sync(&top)?;
    put(&top, "after-full", &body).map_err(|e| format!("create after freeing: {e:?}"))?;
    sync(&top)?;
    let left = block_on(top.enumerate_async(0, usize::MAX))
        .map_err(|e| format!("readdir: {e:?}"))?
        .len();
    drop(top);
    drop(fs);
    narf::reset();
    // made - dropped files, the refused one if its create landed before its
    // write was refused, and `after-full`.
    let want = made - drop_count + 1;
    if left != want && left != want + 1 {
        return Err(format!(
            "{left} entries after ENOSPC, want {want} or {}",
            want + 1
        ));
    }
    judge(&img, "fill")?;
    if !args.keep {
        let _ = std::fs::remove_dir_all(img.parent().unwrap());
    }
    Ok(format!(
        "    full: {ballast} MiB of ballast allocated the device; {made} creates acknowledged, then ENOSPC; commit ok, {drop_count} unlinks ok, create ok again; btrfs check clean\n      {why}"
    ))
}

fn run_grow(args: &Args, metadata: bool) -> Result<String, String> {
    let name = if metadata {
        "metadata-grow"
    } else {
        "data-grow"
    };
    let img = mkfs(args, name, 2 << 30, if metadata { 3 } else { 2 })?;
    let before = linux::chunk_counts(&img);
    let fs = mount(&img)?;
    let top = block_on(fs.root().mkdir("grow")).map_err(|e| format!("mkdir: {e:?}"))?;
    // Fill the block groups of one type until the driver has to allocate
    // another: the operation that no longer fits must succeed all the same.
    let mut made = 0usize;
    let grown = loop {
        let result = if metadata {
            put(&top, &format!("i{made:07}"), &noise(made as u64, 1500))
        } else {
            put(&top, &format!("d{made:05}"), &noise(made as u64, 1 << 20))
        };
        result.map_err(|e| format!("{name}: op {made}: {e:?} although the device has room"))?;
        made += 1;
        if made % if metadata { 2000 } else { 16 } == 0 {
            sync(&top)?;
            let now = linux::chunk_counts(&img);
            let (was, is) = if metadata {
                (before.1, now.1)
            } else {
                (before.0, now.0)
            };
            if is > was {
                break now;
            }
        }
        if made > 1_000_000 {
            return Err(format!("{name}: no chunk was ever allocated"));
        }
    };
    save_file_burst(&top, 60)?;
    sync(&top)?;
    drop(top);
    drop(fs);
    narf::reset();
    judge(&img, "grow")?;
    if !args.keep {
        let _ = std::fs::remove_dir_all(img.parent().unwrap());
    }
    Ok(format!(
        "    {name}: {made} {} filled the block groups; chunks data {}->{} metadata {}->{}; 60-file save burst ok; btrfs check clean",
        if metadata {
            "1.5 KiB files"
        } else {
            "1 MiB files"
        },
        before.0,
        grown.0,
        before.1,
        grown.1
    ))
}

pub fn run(args: &Args) -> Result<String, String> {
    let lines = [
        run_full(args)?,
        run_grow(args, false)?,
        run_grow(args, true)?,
    ];
    Ok(format!(
        "enospc: OK\n{}\n    most a batch commit drew from the global reserve: {} blocks",
        lines.join("\n"),
        narf_drivers_fs_btrfs::stats::max_reserve_overrun()
    ))
}
