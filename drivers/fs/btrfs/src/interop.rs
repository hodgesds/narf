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
/// Bytes journald-style KEEP_SIZE preallocation reserves for the fresh
/// `system.journal` in the `log` mode.
pub const JOURNAL_PREALLOC: u64 = 8 << 20;
/// Size of the journal files the image ships.
pub const JOURNAL_SIZE: u64 = 256 * 1024;

pub(crate) async fn dir_at(root: &Arc<dyn DirOps>, path: &str) -> Result<Arc<dyn DirOps>, FsError> {
    let mut dir = root.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        dir = dir.lookup_dir_async(part).await?;
    }
    Ok(dir)
}

pub(crate) async fn write_all(
    file: &Arc<dyn FileOps>,
    offset: u64,
    data: &[u8],
) -> Result<(), FsError> {
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

pub(crate) async fn read_exact(
    file: &Arc<dyn FileOps>,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, FsError> {
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
    // journald preallocates its file ahead of the writes, keeping the size
    // (`journal_file_allocate` → `posix_fallocate`-style KEEP_SIZE growth).
    fresh
        .fallocate(crate::write::FALLOC_FL_KEEP_SIZE, 0, JOURNAL_PREALLOC)
        .await
        .map_err(|_| "fallocate journal")?;
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

/// Directory the `files` mode works in (inside `@`).
pub const FILES_DIR: &str = "narf-sizes";

/// What the `files` mode leaves in [`FILES_DIR`], for the host to compare.
pub fn files_expected() -> Vec<(&'static str, Vec<u8>)> {
    let mut shrink = pattern(41, 300_000);
    shrink.truncate(150_001);
    shrink.resize(400_000, 0);
    let mut prealloc = alloc::vec![0u8; 1 << 20];
    prealloc[256 * 1024..256 * 1024 + 4096].copy_from_slice(&pattern(42, 4096));
    let journal: Vec<u8> = (0..64u32).flat_map(|i| pattern(100 + i, 4096)).collect();
    let mut punch = pattern(44, 200_000);
    punch[10_000..110_000].fill(0);
    let mut zero = pattern(45, 200_000);
    zero[50_000..110_000].fill(0);
    alloc::vec![
        ("db.conf", b"short\n".to_vec()),
        ("shrink.bin", shrink),
        ("prealloc.bin", prealloc),
        ("journal.bin", journal),
        ("punch.bin", punch),
        ("zero.bin", zero),
        ("after-rw.txt", b"rw again\n".to_vec()),
        ("attrs.txt", b"attrs\n".to_vec()),
    ]
}

/// What `files` sets on `narf-sizes/attrs.txt` (chmod, chown, utimensat):
/// `(mode, uid, gid, atime_ns, mtime_ns)`.
pub const ATTRS: (u32, u32, u32, u64, u64) = (
    0o100640,
    1000,
    1000,
    1_700_000_000_123_456_789,
    1_600_000_000_987_654_321,
);

/// `files` mode (`@`): the size and allocation calls pacman, journald,
/// editors and systemd make: `O_TRUNC` rewrite, `ftruncate` shrink and grow,
/// `fallocate` (mode 0, KEEP_SIZE then appends, PUNCH_HOLE, ZERO_RANGE, an
/// unsupported mode), then `mount -o remount,ro` (writes refused) and back
/// to `rw` (systemd-shutdown and systemd-remount-fs).
async fn run_files(
    fs: &Arc<dyn narf_filesystem::FsInstance>,
    root: &Arc<dyn DirOps>,
) -> Result<(), &'static str> {
    use crate::write::{FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE};
    let dir = root
        .mkdir(FILES_DIR)
        .await
        .map_err(|_| "mkdir narf-sizes")?;
    // pacman: a config rewritten in place through O_TRUNC.
    let f = dir.create("db.conf").await.map_err(|_| "create db.conf")?;
    write_all(&f, 0, &pattern(40, 20_000))
        .await
        .map_err(|_| "write db.conf")?;
    f.fsync(false).await.map_err(|_| "fsync db.conf")?;
    f.truncate(0).await.map_err(|_| "O_TRUNC db.conf")?;
    write_all(&f, 0, b"short\n")
        .await
        .map_err(|_| "rewrite db.conf")?;
    // ftruncate down to an unaligned size, then up again (zeros).
    let g = dir
        .create("shrink.bin")
        .await
        .map_err(|_| "create shrink.bin")?;
    write_all(&g, 0, &pattern(41, 300_000))
        .await
        .map_err(|_| "write shrink.bin")?;
    g.truncate(150_001).await.map_err(|_| "shrink")?;
    g.truncate(400_000).await.map_err(|_| "grow")?;
    // fallocate mode 0, then a write that converts part of it.
    let h = dir
        .create("prealloc.bin")
        .await
        .map_err(|_| "create prealloc.bin")?;
    h.fallocate(0, 0, 1 << 20)
        .await
        .map_err(|_| "fallocate 0")?;
    write_all(&h, 256 * 1024, &pattern(42, 4096))
        .await
        .map_err(|_| "write prealloc.bin")?;
    // journald: KEEP_SIZE reservation, 4 KiB appends, truncate at close.
    let j = dir
        .create("journal.bin")
        .await
        .map_err(|_| "create journal.bin")?;
    j.fallocate(FALLOC_FL_KEEP_SIZE, 0, 8 << 20)
        .await
        .map_err(|_| "fallocate keep")?;
    for i in 0..64u32 {
        write_all(&j, u64::from(i) * 4096, &pattern(100 + i, 4096))
            .await
            .map_err(|_| "append journal.bin")?;
    }
    j.truncate(64 * 4096)
        .await
        .map_err(|_| "truncate journal.bin")?;
    // Punch and zero-range in the middle of written files.
    let k = dir
        .create("punch.bin")
        .await
        .map_err(|_| "create punch.bin")?;
    write_all(&k, 0, &pattern(44, 200_000))
        .await
        .map_err(|_| "write punch.bin")?;
    k.fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 10_000, 100_000)
        .await
        .map_err(|_| "punch")?;
    let z = dir
        .create("zero.bin")
        .await
        .map_err(|_| "create zero.bin")?;
    write_all(&z, 0, &pattern(45, 200_000))
        .await
        .map_err(|_| "write zero.bin")?;
    z.fallocate(FALLOC_FL_ZERO_RANGE, 50_000, 60_000)
        .await
        .map_err(|_| "zero range")?;
    // COLLAPSE_RANGE is EOPNOTSUPP on btrfs.
    if !matches!(z.fallocate(0x08, 0, 4096).await, Err(FsError::Unsupported)) {
        return Err("COLLAPSE_RANGE was not refused");
    }
    root.syncfs().await.map_err(|_| "syncfs")?;
    // systemd-sysusers / ldconfig / update-done: chmod, chown, utimensat.
    let a = dir
        .create("attrs.txt")
        .await
        .map_err(|_| "create attrs.txt")?;
    write_all(&a, 0, b"attrs\n")
        .await
        .map_err(|_| "write attrs.txt")?;
    let (mode, uid, gid, atime, mtime) = ATTRS;
    a.set_perms((mode & 0o7777) as u16)
        .await
        .map_err(|_| "chmod")?;
    a.set_owners(uid, gid).await.map_err(|_| "chown")?;
    a.set_times(Some(atime), Some(mtime))
        .map_err(|_| "utimensat")?;
    if a.owners() != (uid, gid) || u32::from(a.stat().mode.perms) != mode & 0o777 {
        return Err("chmod/chown not visible through stat");
    }
    // systemd-shutdown: remount / read-only; nothing may write; then rw.
    use narf_filesystem::sb_flags::RDONLY;
    fs.reconfigure_sb(RDONLY, RDONLY, "")
        .map_err(|_| "remount ro")?;
    if dir.create("after-ro").await.is_ok() {
        return Err("a write succeeded after remount ro");
    }
    fs.reconfigure_sb(0, RDONLY, "").map_err(|_| "remount rw")?;
    let r = dir
        .create("after-rw.txt")
        .await
        .map_err(|_| "create after remount rw")?;
    write_all(&r, 0, b"rw again\n")
        .await
        .map_err(|_| "write after remount rw")?;
    root.syncfs().await.map_err(|_| "syncfs")?;

    let dir = root
        .lookup_dir_async(FILES_DIR)
        .await
        .map_err(|_| "relookup narf-sizes")?;
    for (name, want) in files_expected() {
        expect(&dir, name, &want).await?;
        let file = dir.lookup_async(name).await.map_err(|_| "relookup file")?;
        let size = file.stat_async().await.map_err(|_| "stat")?.size;
        if size != want.len() as u64 {
            let _ = writeln!(
                narf_console::Writer,
                "{MARKER} detail: {name}: size {size}, want {}",
                want.len()
            );
            return Err("size mismatch");
        }
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
        let file = dir
            .create("narf-fstab.txt")
            .await
            .map_err(|_| "create in subvolume")?;
        write_all(&file, 0, &fstab_marker(subvol))
            .await
            .map_err(|_| "write in subvolume")?;
        mounted.push((subvol, fs));
    }
    let file = root
        .create("narf-fstab.txt")
        .await
        .map_err(|_| "create in @")?;
    write_all(&file, 0, &fstab_marker("@"))
        .await
        .map_err(|_| "write in @")?;
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
    // `root_writable()` alone would let a stray `narf.rootrw_interop=` run
    // this workload on a real root: require the harness image's fsid as the
    // `root=UUID=` the root was mounted from.
    let root_uuid = crate::harness::cmdline_root_uuid();
    let verdict = match root_uuid.as_deref() {
        Some(uuid) => crate::harness::check_disposable(uuid, None, true),
        None => Err("root= is not a UUID= naming the harness image"),
    };
    if let Err(why) = verdict {
        line(&format!("REFUSED ({why})"));
        return narf_init::InitResult::Error("btrfs root-rw interop refused a non-harness root");
    }
    // `cargo xtask btrfs-cycles`: detaches this root and runs its own
    // mount/unmount cycles over the same image.
    if mode == "cycles" {
        return crate::cycles::run(fs);
    }
    let root = fs.root();
    let result = narf_scheduler::block_on(async {
        match mode {
            "root" => run_root(&root).await,
            "home" => run_home(&root).await,
            "log" => run_log(&root, MACHINE_ID).await,
            "fstab" => run_fstab(&root).await,
            "files" => run_files(&fs, &root).await,
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
