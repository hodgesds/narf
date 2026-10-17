//! `narf.rootrw_interop=<mode>`: the in-guest half of
//! `cargo xtask btrfs-rootrw-interop`.
//!
//! Booted under `narf.disks=root-rw` against a host-built btrfs image with
//! the installed CachyOS root's feature set and subvolume layout, this runs
//! systemd-/pacman-shaped writes through the VFS on the mounted root (the one
//! writable instance of the filesystem), syncs, reads everything back, and
//! prints one verdict line. The host then runs `btrfs check` on the image
//! and compares the files. Every byte written here is a pure function of the
//! mode, so the host can check content without a channel back.
//!
//! Modes (one per boot, matching `rootflags=subvol=/<subvolume>`):
//! - `root` (`@`): pacman local-db package add/remove, `ALPM_DB_VERSION` and
//!   `/etc/hostname` replaced by write+fsync+rename, a partial overwrite of a
//!   zstd-compressed file, an unlink.
//! - `home` (`@home`): a user's dotfiles: mkdir, config written to a temp
//!   name and renamed over, appends, an unlink.
//! - `log` (`@log`): journald: header rewrite and appends on a `chattr +C`
//!   (`NODATACOW|NODATASUM`) `system.journal`, rotation by rename, a new
//!   journal, removal of an old archived one.
//! - `fstab` (`@`): mount the six other CachyOS subvolumes read-write as
//!   the fstab does — views of one shared core — and write into each.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_filesystem::{DirOps, FileOps, FsError};

/// Verdict-line prefix the host matches.
pub const MARKER: &str = "ROOTRW-INTEROP:";

/// Deterministic content: `len` bytes derived from `seed`.
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

/// The pacman `desc` file the `root` mode installs.
pub const PKG_DESC: &[u8] = b"%NAME%\nnarf-interop\n\n%VERSION%\n1.0-1\n\n%DESC%\nNARF root-rw interop package\n\n%ARCH%\nx86_64\n";
/// The pacman `files` file the `root` mode installs.
pub const PKG_FILES: &[u8] =
    b"%FILES%\nusr/\nusr/share/\nusr/share/narf-interop/\nusr/share/narf-interop/README\n\n";
/// `/etc/hostname` after the `root` mode.
pub const HOSTNAME: &[u8] = b"narf-interop\n";
/// `ALPM_DB_VERSION` after the `root` mode.
pub const ALPM_DB_VERSION: &[u8] = b"9\n";
/// Offset and length of the overwrite inside `usr/share/narf/compressible.txt`.
pub const COMPRESSIBLE_PATCH: (u64, usize) = (40_960, 8192);
/// `.config/narf.conf` after the `home` mode.
pub const HOME_CONF: &[u8] = b"[narf]\nroot_rw = true\n";
/// Bytes the `log` mode appends to `system.journal` (in 4 KiB writes).
pub const JOURNAL_APPEND: usize = 32 * 4096;
/// Size of the journal files the image ships.
pub const JOURNAL_SIZE: u64 = 256 * 1024;

async fn dir_at(root: &Arc<dyn DirOps>, path: &str) -> Result<Arc<dyn DirOps>, FsError> {
    let mut dir = root.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        dir = dir.lookup_dir_async(part).await?;
    }
    Ok(dir)
}

async fn write_all(file: &Arc<dyn FileOps>, offset: u64, data: &[u8]) -> Result<(), FsError> {
    let mut done = 0usize;
    while done < data.len() {
        let n = file.write(offset + done as u64, &data[done..]).await?;
        if n == 0 {
            return Err(FsError::Io(narf_block::BlockError::IOError));
        }
        done += n;
    }
    Ok(())
}

async fn read_exact(file: &Arc<dyn FileOps>, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
    let mut buf = alloc::vec![0u8; len];
    let mut done = 0usize;
    while done < len {
        let n = file.read(offset + done as u64, &mut buf[done..]).await?;
        if n == 0 {
            break;
        }
        done += n;
    }
    buf.truncate(done);
    Ok(buf)
}

/// Write `data` to `dir/tmp`, fsync, rename over `dir/name` (the
/// write-temp-then-rename every package manager and systemd use).
async fn replace_file(
    dir: &Arc<dyn DirOps>,
    tmp: &str,
    name: &str,
    data: &[u8],
) -> Result<(), FsError> {
    let file = dir.create(tmp).await?;
    write_all(&file, 0, data).await?;
    file.fsync(false).await?;
    dir.rename(tmp, name).await
}

async fn expect(dir: &Arc<dyn DirOps>, name: &str, want: &[u8]) -> Result<(), &'static str> {
    let file = dir
        .lookup_async(name)
        .await
        .map_err(|_| "read-back lookup")?;
    let got = read_exact(&file, 0, want.len() + 1)
        .await
        .map_err(|_| "read-back read")?;
    if got != want {
        let first = got.iter().zip(want).position(|(a, b)| a != b);
        let _ = writeln!(
            narf_console::Writer,
            "{MARKER} detail: {name}: read {} bytes, want {}, first difference at {first:?}",
            got.len(),
            want.len()
        );
        return Err("read-back content mismatch");
    }
    Ok(())
}

async fn run_root(root: &Arc<dyn DirOps>) -> Result<(), &'static str> {
    // pacman -S: a new local-db entry.
    let local = dir_at(root, "var/lib/pacman/local")
        .await
        .map_err(|_| "no var/lib/pacman/local")?;
    let pkg = local
        .mkdir("narf-interop-1.0-1")
        .await
        .map_err(|_| "mkdir package dir")?;
    let desc = pkg.create("desc").await.map_err(|_| "create desc")?;
    // pacman writes the db entry in several small appends.
    let mut at = 0u64;
    for chunk in PKG_DESC.chunks(17) {
        write_all(&desc, at, chunk)
            .await
            .map_err(|_| "append desc")?;
        at += chunk.len() as u64;
    }
    desc.fsync(false).await.map_err(|_| "fsync desc")?;
    let files = pkg.create("files").await.map_err(|_| "create files")?;
    write_all(&files, 0, PKG_FILES)
        .await
        .map_err(|_| "write files")?;
    replace_file(
        &local,
        "ALPM_DB_VERSION.new",
        "ALPM_DB_VERSION",
        ALPM_DB_VERSION,
    )
    .await
    .map_err(|_| "replace ALPM_DB_VERSION")?;
    // pacman -R: drop a shipped package entry (its compressed extents and
    // their checksums are freed).
    let old = local
        .lookup_dir_async("narf-old-0.9-1")
        .await
        .map_err(|_| "no narf-old-0.9-1")?;
    for name in ["desc", "files", "mtree"] {
        old.unlink(name)
            .await
            .map_err(|_| "unlink old package file")?;
    }
    local
        .rmdir("narf-old-0.9-1")
        .await
        .map_err(|_| "rmdir old package")?;
    // systemd-firstboot/hostnamectl: /etc/hostname replaced atomically.
    let etc = dir_at(root, "etc").await.map_err(|_| "no etc")?;
    replace_file(&etc, ".#hostnameNARF", "hostname", HOSTNAME)
        .await
        .map_err(|_| "replace hostname")?;
    // A partial overwrite of a zstd-compressed file: the touched extent is
    // re-tiled uncompressed, the rest keeps its zstd extents.
    let share = dir_at(root, "usr/share/narf")
        .await
        .map_err(|_| "no usr/share/narf")?;
    let big = share
        .lookup_async("compressible.txt")
        .await
        .map_err(|_| "no compressible.txt")?;
    let (off, len) = COMPRESSIBLE_PATCH;
    write_all(&big, off, &pattern(7, len))
        .await
        .map_err(|_| "overwrite compressible.txt")?;
    big.fsync(true)
        .await
        .map_err(|_| "fsync compressible.txt")?;
    share
        .unlink("delete-me.bin")
        .await
        .map_err(|_| "unlink delete-me.bin")?;
    root.syncfs().await.map_err(|_| "syncfs")?;

    // Read back through fresh lookups.
    let local = dir_at(root, "var/lib/pacman/local")
        .await
        .map_err(|_| "relookup local")?;
    let pkg = local
        .lookup_dir_async("narf-interop-1.0-1")
        .await
        .map_err(|_| "package dir missing")?;
    expect(&pkg, "desc", PKG_DESC).await?;
    expect(&pkg, "files", PKG_FILES).await?;
    expect(&local, "ALPM_DB_VERSION", ALPM_DB_VERSION).await?;
    if local.lookup_dir_async("narf-old-0.9-1").await.is_ok() {
        return Err("removed package still present");
    }
    let etc = dir_at(root, "etc").await.map_err(|_| "relookup etc")?;
    expect(&etc, "hostname", HOSTNAME).await?;
    let share = dir_at(root, "usr/share/narf")
        .await
        .map_err(|_| "relookup share")?;
    let big = share
        .lookup_async("compressible.txt")
        .await
        .map_err(|_| "compressible.txt missing")?;
    let got = read_exact(&big, off, len).await.map_err(|_| "read patch")?;
    if got != pattern(7, len) {
        return Err("compressible.txt patch mismatch");
    }
    if share.lookup_async("delete-me.bin").await.is_ok() {
        return Err("unlinked file still present");
    }
    Ok(())
}

async fn run_home(root: &Arc<dyn DirOps>) -> Result<(), &'static str> {
    let user = dir_at(root, "narf").await.map_err(|_| "no /narf home")?;
    let config = user.mkdir(".config").await.map_err(|_| "mkdir .config")?;
    replace_file(&config, "narf.conf.XXXXXX", "narf.conf", HOME_CONF)
        .await
        .map_err(|_| "replace narf.conf")?;
    // A shell history: repeated small appends.
    let history = user
        .lookup_async(".bash_history")
        .await
        .map_err(|_| "no .bash_history")?;
    let base = history.stat_async().await.map_err(|_| "stat history")?.size;
    let mut at = base;
    for i in 0..16u32 {
        let line = format!("echo narf-interop {i}\n");
        write_all(&history, at, line.as_bytes())
            .await
            .map_err(|_| "append history")?;
        at += line.len() as u64;
    }
    history.fsync(false).await.map_err(|_| "fsync history")?;
    // A document: new file, 1 MiB in 64 KiB writes.
    let doc = user
        .create("notes.bin")
        .await
        .map_err(|_| "create notes.bin")?;
    let body = pattern(11, 1 << 20);
    for (i, chunk) in body.chunks(64 * 1024).enumerate() {
        write_all(&doc, (i * 64 * 1024) as u64, chunk)
            .await
            .map_err(|_| "write notes.bin")?;
    }
    user.unlink("scratch.tmp")
        .await
        .map_err(|_| "unlink scratch.tmp")?;
    root.syncfs().await.map_err(|_| "syncfs")?;

    let user = dir_at(root, "narf").await.map_err(|_| "relookup /narf")?;
    let config = user
        .lookup_dir_async(".config")
        .await
        .map_err(|_| ".config missing")?;
    expect(&config, "narf.conf", HOME_CONF).await?;
    expect(&user, "notes.bin", &body).await?;
    if user.lookup_async("scratch.tmp").await.is_ok() {
        return Err("unlinked scratch.tmp still present");
    }
    Ok(())
}

async fn run_log(root: &Arc<dyn DirOps>, machine_id: &str) -> Result<(), &'static str> {
    let dir = dir_at(root, &format!("journal/{machine_id}"))
        .await
        .map_err(|_| "no journal/<machine-id>")?;
    let journal = dir
        .lookup_async("system.journal")
        .await
        .map_err(|_| "no system.journal")?;
    // journald: rewrite the header in place, then append entries.
    write_all(&journal, 0, &pattern(21, 256))
        .await
        .map_err(|_| "rewrite journal header")?;
    let append = pattern(22, JOURNAL_APPEND);
    for (i, chunk) in append.chunks(4096).enumerate() {
        write_all(&journal, JOURNAL_SIZE + (i * 4096) as u64, chunk)
            .await
            .map_err(|_| "append journal")?;
    }
    journal.fsync(true).await.map_err(|_| "fsync journal")?;
    // Rotation: archive under a new name, start a fresh active file.
    dir.rename("system.journal", "system@narf-0001.journal")
        .await
        .map_err(|_| "rotate journal")?;
    let fresh = dir
        .create("system.journal")
        .await
        .map_err(|_| "create journal")?;
    write_all(&fresh, 0, &pattern(23, 64 * 1024))
        .await
        .map_err(|_| "write fresh journal")?;
    let user = dir
        .create("user-1000.journal")
        .await
        .map_err(|_| "create user journal")?;
    for i in 0..8u32 {
        write_all(&user, u64::from(i) * 32 * 1024, &pattern(30 + i, 32 * 1024))
            .await
            .map_err(|_| "write user journal")?;
    }
    // journald vacuum: drop the oldest archive.
    dir.unlink("system@old.journal")
        .await
        .map_err(|_| "vacuum old journal")?;
    root.syncfs().await.map_err(|_| "syncfs")?;

    let dir = dir_at(root, &format!("journal/{machine_id}"))
        .await
        .map_err(|_| "relookup journal dir")?;
    let archived = dir
        .lookup_async("system@narf-0001.journal")
        .await
        .map_err(|_| "archived journal missing")?;
    if read_exact(&archived, 0, 256)
        .await
        .map_err(|_| "read header")?
        != pattern(21, 256)
    {
        return Err("journal header mismatch");
    }
    if read_exact(&archived, JOURNAL_SIZE, JOURNAL_APPEND)
        .await
        .map_err(|_| "read appended")?
        != append
    {
        return Err("journal append mismatch");
    }
    expect(&dir, "system.journal", &pattern(23, 64 * 1024)).await?;
    if dir.lookup_async("system@old.journal").await.is_ok() {
        return Err("vacuumed journal still present");
    }
    Ok(())
}

/// The CachyOS fstab subvolumes other than `@`, mounted by the `fstab` mode.
pub const FSTAB_SUBVOLUMES: [&str; 6] = ["@home", "@root", "@srv", "@cache", "@tmp", "@log"];

/// Content the `fstab` mode writes into `<subvolume>/narf-fstab.txt`.
pub fn fstab_marker(subvol: &str) -> Vec<u8> {
    format!("written through the shared core into {subvol}\n").into_bytes()
}

/// `fstab` mode: with `@` at `/`, mount every other CachyOS subvolume
/// read-write the way systemd's fstab units do (`mount -t btrfs -o
/// subvol=/@x,defaults,noatime,compress=zstd:1`) — each a view of the one
/// shared core — and write a file into each, plus one into `@`.
async fn run_fstab(root: &Arc<dyn DirOps>) -> Result<(), &'static str> {
    let device = narf_block::disk_policy::designated_root().ok_or("no designated root")?;
    let source = format!("/dev/{device}");
    let fstype = narf_filesystem::lookup_fstype("btrfs").ok_or("btrfs fstype missing")?;
    let mut mounted = Vec::new();
    for subvol in FSTAB_SUBVOLUMES {
        let options = format!("subvol=/{subvol},defaults,noatime,compress=zstd:1");
        let fs = fstype
            .init(&narf_filesystem::MountRequest {
                fs_type: "btrfs",
                source: &source,
                options: &options,
                uid: 0,
                gid: 0,
                umask: 0o022,
                initial_namespace: true,
                read_only: false,
            })
            .map_err(|_| "a read-write fstab subvolume mount was refused")?;
        if fs.always_read_only() {
            return Err("an fstab subvolume mount came up read-only");
        }
        let dir = fs.root();
        let file = dir.create("narf-fstab.txt").await.map_err(|_| "create in subvolume")?;
        write_all(&file, 0, &fstab_marker(subvol))
            .await
            .map_err(|_| "write in subvolume")?;
        mounted.push((subvol, fs));
    }
    let file = root.create("narf-fstab.txt").await.map_err(|_| "create in @")?;
    write_all(&file, 0, &fstab_marker("@")).await.map_err(|_| "write in @")?;
    // One sync covers every subvolume: they share one transaction.
    root.syncfs().await.map_err(|_| "syncfs")?;
    for (subvol, fs) in &mounted {
        expect(&fs.root(), "narf-fstab.txt", &fstab_marker(subvol)).await?;
    }
    expect(root, "narf-fstab.txt", &fstab_marker("@")).await
}

/// Machine id of the interop image (journal directory name).
pub const MACHINE_ID: &str = "4e415246c4c405ee00000000000000aa";

/// Run the workload for `mode` on the filesystem mounted at `/` and print
/// the verdict. Refuses to touch anything unless `/` is a writable btrfs
/// under `narf.disks=root-rw` with a designated root.
pub fn run(mode: &str) -> narf_init::InitResult {
    let line = |text: &str| {
        let _ = writeln!(narf_console::Writer, "{MARKER} {text}");
    };
    let root_fs = narf_filesystem::registry().fs_arc_at("/");
    let usable = narf_block::disk_policy::root_writable()
        && root_fs
            .as_ref()
            .is_some_and(|fs| fs.name() == "btrfs" && !fs.always_read_only());
    let Some(fs) = root_fs.filter(|_| usable) else {
        line("NO-ROOT (no writable btrfs root under narf.disks=root-rw)");
        return narf_init::InitResult::NotPresent;
    };
    let root = fs.root();
    let result = narf_scheduler::block_on(async {
        match mode {
            "root" => run_root(&root).await,
            "home" => run_home(&root).await,
            "log" => run_log(&root, MACHINE_ID).await,
            "fstab" => run_fstab(&root).await,
            _ => Err("unknown mode"),
        }
    });
    match result {
        Ok(()) => {
            line(&format!("PASS {mode}"));
            narf_init::InitResult::Ok
        }
        Err(why) => {
            let mut text = String::new();
            let _ = write!(text, "FAIL {mode}: {why}");
            line(&text);
            narf_init::InitResult::Error("btrfs root-rw interop workload failed")
        }
    }
}
