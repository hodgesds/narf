//! `narf.rootrw_interop=cycles`: the guest half of `cargo xtask btrfs-cycles`.
//!
//! One boot runs many mount → write → sync → unmount → remount → verify
//! cycles against the harness image, which booted as a `narf.disks=root-rw`
//! root (so the policy designated it and the `rw_gate` root-rw profile
//! applies to every mount of it). The boot root mount is detached first;
//! each cycle then mounts `@` and `@home` read-write through the `mount -t
//! btrfs` constructor (views of one shared core, as the CachyOS fstab
//! mounts are), checks every file the earlier cycles left against an
//! in-memory model, runs a seeded workload of namespace and data operations,
//! syncs, drops every reference and requires the core to be gone (full
//! teardown) before the next cycle mounts it again from disk.
//!
//! Every operation, the cycle's commit generation and a fail-fast diff go to
//! the serial console; after the last cycle a final remount verifies once
//! more and prints a manifest (`FILE`/`DIR` lines) the host compares with
//! `btrfs restore`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_filesystem::{DirOps, FileType, FsError, FsInstance};

use crate::interop::{dir_at, pattern, read_exact, write_all};

/// Prefix of every serial line the host parses.
pub const MARKER: &str = "BTRFS-CYCLES:";

/// The subvolumes each cycle mounts, by index in the model.
pub const SUBVOLS: [&str; 2] = ["@", "@home"];

/// Directory (in every subvolume) the workload owns.
pub const WORK_DIR: &str = "narf-cycles";

/// Text that compresses well (zstd extents at mkfs time).
pub fn compressible(seed: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut n = 0u32;
    while out.len() < len {
        let _ = writeln!(
            StrSink(&mut out),
            "narf btrfs cycles seed {seed:04} line {n:08} the quick brown fox"
        );
        n += 1;
    }
    out.truncate(len);
    out
}

struct StrSink<'a>(&'a mut Vec<u8>);

impl core::fmt::Write for StrSink<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// What a seed entry holds.
#[derive(Debug)]
pub enum SeedKind {
    File(Vec<u8>),
    Symlink(&'static str),
}

/// The files the host puts into the image with `mkfs.btrfs --rootdir`
/// (`(subvolume index, path, content)`). The workload never touches them;
/// every cycle checks they are intact.
pub fn seed_files() -> Vec<(usize, &'static str, SeedKind)> {
    alloc::vec![
        (0, "etc/hostname", SeedKind::File(b"cachyos\n".to_vec())),
        (
            0,
            "etc/os-release",
            SeedKind::File(b"NAME=\"CachyOS Linux\"\nID=cachyos\nBUILD_ID=rolling\n".to_vec()),
        ),
        (
            0,
            "usr/share/cycles/inline.txt",
            SeedKind::File(compressible(1, 300))
        ),
        (
            0,
            "usr/share/cycles/compressible.txt",
            SeedKind::File(compressible(2, 1 << 20)),
        ),
        (
            0,
            "usr/share/cycles/random.bin",
            SeedKind::File(pattern(77, 3 << 20))
        ),
        (
            0,
            "usr/share/cycles/random.link",
            SeedKind::Symlink("random.bin")
        ),
        (
            1,
            "narf/.bashrc",
            SeedKind::File(b"export EDITOR=vi\nalias ll='ls -l'\n".to_vec())
        ),
        (1, "narf/notes.bin", SeedKind::File(pattern(78, 200_000))),
    ]
}

/// FNV-1a, 64-bit: the per-file digest the manifest carries (the host
/// computes the same over what `btrfs restore` extracts).
pub fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// SplitMix64: the workload's deterministic choices.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (`n > 0`).
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    /// `len` bytes: random, compressible text, or mostly zeros.
    fn data(&mut self, len: usize) -> Vec<u8> {
        match self.below(10) {
            0..=4 => {
                let mut out = Vec::with_capacity(len + 8);
                while out.len() < len {
                    out.extend_from_slice(&self.next().to_le_bytes());
                }
                out.truncate(len);
                out
            }
            5..=8 => compressible(self.below(10_000) as u32, len),
            _ => {
                let mut out = alloc::vec![0u8; len];
                for i in (0..len).step_by(4096) {
                    out[i] = self.next() as u8 | 1;
                }
                out
            }
        }
    }
}

/// Tunables (`narf.btrfs_cycles_*`).
#[derive(Clone, Copy)]
struct Params {
    cycles: u32,
    seed: u64,
    ops: u32,
    max_live: usize,
    big_max: usize,
}

impl Params {
    fn from_cmdline() -> Self {
        let args = narf_boot::args();
        let num = |key: &str, default: u64| {
            args.value(key)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(default)
        };
        Params {
            cycles: num("narf.btrfs_cycles", 50) as u32,
            seed: num("narf.btrfs_cycles_seed", 1),
            ops: num("narf.btrfs_cycles_ops", 80) as u32,
            max_live: (num("narf.btrfs_cycles_live_kib", 32 * 1024) as usize) << 10,
            big_max: (num("narf.btrfs_cycles_big_kib", 8 * 1024) as usize) << 10,
        }
    }
}

struct FileModel {
    data: Vec<u8>,
    /// The last few operations that touched this file, for a failure diff.
    hist: Vec<String>,
    /// Names (hard links) referring to this inode.
    links: usize,
}

impl FileModel {
    fn note(&mut self, cycle: u32, op: &str) {
        if self.hist.len() == 6 {
            self.hist.remove(0);
        }
        self.hist.push(format!("c{cycle}:{op}"));
    }
}

type Key = (usize, String);

#[derive(Default)]
struct Model {
    /// Every file name, mapped to its inode in `inodes` (hard links share).
    files: BTreeMap<Key, u64>,
    inodes: BTreeMap<u64, FileModel>,
    dirs: BTreeSet<Key>,
    next: u64,
    live: usize,
}

fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

impl Model {
    fn fresh(&mut self, prefix: &str) -> String {
        self.next += 1;
        format!("{prefix}{}", self.next)
    }
    fn pick_file(&self, rng: &mut Rng) -> Option<Key> {
        if self.files.is_empty() {
            return None;
        }
        let n = rng.below(self.files.len() as u64) as usize;
        self.files.keys().nth(n).cloned()
    }
    fn pick_dir(&self, rng: &mut Rng, sv: Option<usize>) -> Key {
        let dirs: Vec<&Key> = self
            .dirs
            .iter()
            .filter(|(s, _)| sv.is_none_or(|want| *s == want))
            .collect();
        dirs[rng.below(dirs.len() as u64) as usize].clone()
    }
    fn children(&self, dir: &Key) -> Vec<String> {
        let prefix = format!("{}/", dir.1);
        let direct = |key: &Key| {
            key.0 == dir.0
                && key
                    .1
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| !rest.contains('/'))
        };
        self.files
            .keys()
            .filter(|k| direct(k))
            .chain(self.dirs.iter().filter(|k| direct(k)))
            .map(|k| split(&k.1).1.to_string())
            .collect()
    }
    fn file(&self, key: &Key) -> &FileModel {
        &self.inodes[&self.files[key]]
    }
    fn note(&mut self, key: &Key, cycle: u32, op: &str) {
        if let Some(file) = self.files.get(key).and_then(|ino| self.inodes.get_mut(ino)) {
            file.note(cycle, op);
        }
    }
    /// Replace the content of the file `key` names (every link sees it), or
    /// create it as a new inode.
    fn set(&mut self, key: Key, data: Vec<u8>, cycle: u32, op: &str) {
        let ino = match self.files.get(&key) {
            Some(ino) => *ino,
            None => {
                self.next += 1;
                let ino = self.next;
                self.inodes.insert(
                    ino,
                    FileModel {
                        data: Vec::new(),
                        hist: Vec::new(),
                        links: 1,
                    },
                );
                self.files.insert(key, ino);
                ino
            }
        };
        let entry = self.inodes.get_mut(&ino).expect("inode");
        self.live = self.live - entry.data.len() + data.len();
        entry.data = data;
        entry.note(cycle, op);
    }
    /// Drop the name `key`; the inode goes with its last name.
    fn remove(&mut self, key: &Key) -> Option<u64> {
        let ino = self.files.remove(key)?;
        let file = self.inodes.get_mut(&ino).expect("inode");
        file.links -= 1;
        if file.links == 0 {
            let gone = self.inodes.remove(&ino).expect("inode");
            self.live -= gone.data.len();
        }
        Some(ino)
    }
    /// `rename(src, dst)`: `dst` (if any) loses its name, `src`'s inode
    /// takes it.
    fn rename(&mut self, src: &Key, dst: Key, cycle: u32) {
        let ino = self.files[src];
        if self.files.get(&dst) == Some(&ino) {
            // Both names are links to one inode: POSIX rename does nothing.
            return;
        }
        self.remove(&dst);
        self.files.remove(src);
        self.files.insert(dst, ino);
        let file = self.inodes.get_mut(&ino).expect("inode");
        file.note(cycle, &format!("renamed from {}", src.1));
    }
    /// `link(src, dst)` for a new name `dst`.
    fn link(&mut self, src: &Key, dst: Key, cycle: u32) {
        let ino = self.files[src];
        self.files.insert(dst.clone(), ino);
        let file = self.inodes.get_mut(&ino).expect("inode");
        file.links += 1;
        file.note(cycle, &format!("linked as {}", dst.1));
    }
}

/// The two mounted views of one cycle.
struct Views {
    fs: Vec<Arc<dyn FsInstance>>,
    roots: Vec<Arc<dyn DirOps>>,
}

fn say(text: &str) {
    let _ = writeln!(narf_console::Writer, "{MARKER} {text}");
}

fn ms_since(start: u64) -> u64 {
    narf_time::monotonic_ns().saturating_sub(start) / 1_000_000
}

/// Mount `@` and `@home` read-write as the CachyOS fstab does.
fn mount_views(source: &str) -> Result<Views, String> {
    let fstype = narf_filesystem::lookup_fstype("btrfs").ok_or("btrfs fstype missing")?;
    let mut views = Views {
        fs: Vec::new(),
        roots: Vec::new(),
    };
    for sv in SUBVOLS {
        let options = format!("subvol=/{sv},defaults,noatime,compress=zstd:1");
        let fs = fstype
            .init(&narf_filesystem::MountRequest {
                fs_type: "btrfs",
                source,
                options: &options,
                uid: 0,
                gid: 0,
                umask: 0o022,
                initial_namespace: true,
                read_only: false,
            })
            .map_err(|e| format!("mount {sv} rw: {e:?}"))?;
        if fs.always_read_only() {
            return Err(format!("mount {sv} came up read-only"));
        }
        views.roots.push(fs.root());
        views.fs.push(fs);
    }
    Ok(views)
}

/// The commit generation of the live core, if one is mounted.
fn live_generation(fsid: &[u8; 16]) -> Option<u64> {
    crate::registry::instance_for(fsid).map(|core| core.committed_generation())
}

async fn verify_seeds(roots: &[Arc<dyn DirOps>]) -> Result<(), String> {
    for (sv, path, kind) in seed_files() {
        let (parent, name) = split(path);
        let dir = dir_at(&roots[sv], parent)
            .await
            .map_err(|e| format!("seed {}/{path}: parent: {e:?}", SUBVOLS[sv]))?;
        let file = dir
            .lookup_async(name)
            .await
            .map_err(|e| format!("seed {}/{path}: lookup: {e:?}", SUBVOLS[sv]))?;
        let want = match kind {
            SeedKind::File(data) => data,
            SeedKind::Symlink(target) => target.as_bytes().to_vec(),
        };
        let got = read_exact(&file, 0, want.len() + 1)
            .await
            .map_err(|e| format!("seed {}/{path}: read: {e:?}", SUBVOLS[sv]))?;
        if got != want {
            let at = got.iter().zip(&want).position(|(a, b)| a != b);
            return Err(format!(
                "seed {}/{path} changed: {} bytes, want {}, first difference at {at:?}",
                SUBVOLS[sv],
                got.len(),
                want.len()
            ));
        }
    }
    Ok(())
}

/// Check the whole model (every live file's size and bytes, every
/// directory's exact entry set) and the seed files.
async fn verify(roots: &[Arc<dyn DirOps>], model: &Model) -> Result<(), String> {
    verify_seeds(roots).await?;
    for dir in &model.dirs {
        let handle = dir_at(&roots[dir.0], &dir.1)
            .await
            .map_err(|e| format!("dir {}/{} missing: {e:?}", SUBVOLS[dir.0], dir.1))?;
        let listed = handle
            .enumerate_async(0, usize::MAX)
            .await
            .map_err(|e| format!("readdir {}/{}: {e:?}", SUBVOLS[dir.0], dir.1))?;
        let mut got: Vec<String> = listed.iter().map(|(n, _)| n.clone()).collect();
        let mut want = model.children(dir);
        got.sort();
        want.sort();
        if got != want {
            let extra: Vec<&String> = got.iter().filter(|n| !want.contains(n)).collect();
            let missing: Vec<&String> = want.iter().filter(|n| !got.contains(n)).collect();
            return Err(format!(
                "dir {}/{}: entries differ: extra {extra:?} missing {missing:?}",
                SUBVOLS[dir.0], dir.1
            ));
        }
        for (name, kind) in &listed {
            let is_dir = model.dirs.contains(&(dir.0, format!("{}/{name}", dir.1)));
            let ok = if is_dir {
                *kind == FileType::Dir
            } else {
                *kind == FileType::File
            };
            if !ok {
                return Err(format!(
                    "dir {}/{}: {name} has type {kind:?}",
                    SUBVOLS[dir.0], dir.1
                ));
            }
        }
    }
    for ((sv, path), ino) in &model.files {
        let file = &model.inodes[ino];
        let (parent, name) = split(path);
        let fail = |what: String| {
            format!(
                "file {}/{path}: {what} (history: {})",
                SUBVOLS[*sv],
                file.hist.join(", ")
            )
        };
        let dir = dir_at(&roots[*sv], parent)
            .await
            .map_err(|e| fail(format!("parent lookup {e:?}")))?;
        let handle = dir
            .lookup_async(name)
            .await
            .map_err(|e| fail(format!("lookup {e:?}")))?;
        let size = handle
            .stat_async()
            .await
            .map_err(|e| fail(format!("stat {e:?}")))?
            .size;
        if size != file.data.len() as u64 {
            return Err(fail(format!("size {size}, want {}", file.data.len())));
        }
        let got = read_exact(&handle, 0, file.data.len() + 1)
            .await
            .map_err(|e| fail(format!("read {e:?}")))?;
        if got != file.data {
            let at = got.iter().zip(&file.data).position(|(a, b)| a != b);
            let window = |d: &[u8], at: usize| -> String {
                d.iter()
                    .skip(at)
                    .take(16)
                    .map(|b| format!("{b:02x}"))
                    .collect()
            };
            let at_or = at.unwrap_or(got.len().min(file.data.len()));
            return Err(fail(format!(
                "content: read {} bytes, want {}, first difference at {at:?}: got {} want {}",
                got.len(),
                file.data.len(),
                window(&got, at_or),
                window(&file.data, at_or)
            )));
        }
    }
    Ok(())
}

/// One workload operation. Returns its description, or the description and
/// the error that stopped it.
async fn step(
    roots: &[Arc<dyn DirOps>],
    model: &mut Model,
    rng: &mut Rng,
    p: &Params,
    cycle: u32,
) -> Result<String, (String, FsError)> {
    let full = model.live > p.max_live;
    let mut choice = rng.below(100);
    if model.files.is_empty() {
        choice = 0;
    } else if full {
        // Over the live-data budget: shrink.
        choice = if rng.chance(50) { 45 } else { 55 };
    }
    macro_rules! dir {
        ($key:expr) => {
            dir_at(&roots[$key.0], &$key.1).await
        };
    }
    match choice {
        // Create: small (inline), medium, or a multi-MiB file.
        0..=19 => {
            let dir = model.pick_dir(rng, None);
            let name = model.fresh("f");
            let len = match rng.below(10) {
                0..=4 => rng.below(3000) as usize,
                5..=8 => rng.range(4096, 256 * 1024) as usize,
                _ if model.live + p.big_max < p.max_live => {
                    rng.range(1 << 20, p.big_max as u64) as usize
                }
                _ => rng.range(64 * 1024, 512 * 1024) as usize,
            };
            let data = rng.data(len);
            let path = format!("{}/{name}", dir.1);
            let op = format!("create {}/{path} len {len}", SUBVOLS[dir.0]);
            let r: Result<(), FsError> = async {
                let d = dir!(dir)?;
                let f = d.create(&name).await?;
                // Large files go down in 256 KiB writes, as `cp` does.
                for (i, chunk) in data.chunks(256 * 1024).enumerate() {
                    write_all(&f, (i * 256 * 1024) as u64, chunk).await?;
                }
                Ok(())
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            model.set((dir.0, path), data, cycle, &format!("create {len}"));
            Ok(op)
        }
        // Overwrite inside the file (or straddling / past EOF).
        20..=33 => {
            let key = model.pick_file(rng).expect("files");
            let old = model.file(&key).data.clone();
            let len = old.len() as u64;
            let off = match rng.below(4) {
                0 => rng.below(len + 1) & !4095,
                1 => len + rng.below(64 * 1024),
                _ => rng.below(len + 1),
            };
            let n = rng.range(1, 64 * 1024) as usize;
            let data = rng.data(n);
            let op = format!("write {}/{} off {off} len {n}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                let f = d.lookup_async(name).await?;
                write_all(&f, off, &data).await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            let mut new = old;
            let end = off as usize + n;
            if new.len() < end {
                new.resize(end, 0);
            }
            new[off as usize..end].copy_from_slice(&data);
            model.set(key, new, cycle, &format!("write {off}+{n}"));
            Ok(op)
        }
        // Append.
        34..=44 => {
            let key = model.pick_file(rng).expect("files");
            let n = rng.range(1, 128 * 1024) as usize;
            let data = rng.data(n);
            let mut new = model.file(&key).data.clone();
            let off = new.len() as u64;
            let op = format!("append {}/{} at {off} len {n}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                let f = d.lookup_async(name).await?;
                write_all(&f, off, &data).await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            new.extend_from_slice(&data);
            model.set(key, new, cycle, &format!("append {off}+{n}"));
            Ok(op)
        }
        // Truncate down (45..=52) or up (53..=54).
        45..=54 => {
            let key = model.pick_file(rng).expect("files");
            let mut new = model.file(&key).data.clone();
            let len = new.len() as u64;
            let to = if choice >= 53 {
                len + rng.range(1, 256 * 1024)
            } else {
                rng.below(len + 1)
            };
            let op = format!("truncate {}/{} {len} -> {to}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                let f = d.lookup_async(name).await?;
                f.truncate(to).await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            new.resize(to as usize, 0);
            model.set(key, new, cycle, &format!("truncate {to}"));
            Ok(op)
        }
        // Unlink.
        55..=61 => {
            let key = model.pick_file(rng).expect("files");
            let op = format!("unlink {}/{}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                d.unlink(name).await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            model.remove(&key);
            Ok(op)
        }
        // Rename: within or across directories of one subvolume, sometimes
        // over an existing file.
        62..=70 => {
            let key = model.pick_file(rng).expect("files");
            let dest_dir = model.pick_dir(rng, Some(key.0));
            let victims: Vec<Key> = model
                .files
                .keys()
                .filter(|k| k.0 == key.0 && split(&k.1).0 == dest_dir.1 && **k != key)
                .cloned()
                .collect();
            let dest_name = if !victims.is_empty() && rng.chance(30) {
                let v = &victims[rng.below(victims.len() as u64) as usize];
                split(&v.1).1.to_string()
            } else {
                model.fresh("r")
            };
            let dest_path = format!("{}/{dest_name}", dest_dir.1);
            let op = format!("rename {}/{} -> {dest_path}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let src = dir_at(&roots[key.0], parent).await?;
                if parent == dest_dir.1 {
                    src.rename(name, &dest_name).await
                } else {
                    let dst = dir!(dest_dir)?;
                    src.rename_to(name, &*dst, &dest_name, 0).await
                }
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            model.rename(&key, (key.0, dest_path), cycle);
            Ok(op)
        }
        // mkdir (bounded depth).
        71..=74 => {
            let parent = model.pick_dir(rng, None);
            if parent.1.matches('/').count() >= 3 {
                return Ok("mkdir skipped (depth)".into());
            }
            let name = model.fresh("d");
            let path = format!("{}/{name}", parent.1);
            let op = format!("mkdir {}/{path}", SUBVOLS[parent.0]);
            let r: Result<(), FsError> = async {
                let d = dir!(parent)?;
                d.mkdir(&name).await.map(|_| ())
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            model.dirs.insert((parent.0, path));
            Ok(op)
        }
        // rmdir of an empty directory.
        75..=77 => {
            let empty: Vec<Key> = model
                .dirs
                .iter()
                .filter(|d| d.1 != WORK_DIR && model.children(d).is_empty())
                .cloned()
                .collect();
            if empty.is_empty() {
                return Ok("rmdir skipped (none empty)".into());
            }
            let key = empty[rng.below(empty.len() as u64) as usize].clone();
            let op = format!("rmdir {}/{}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                d.rmdir(name).await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            model.dirs.remove(&key);
            Ok(op)
        }
        // fsync / fdatasync.
        78..=82 => {
            let key = model.pick_file(rng).expect("files");
            let data_only = rng.chance(50);
            let op = format!(
                "{} {}/{}",
                if data_only { "fdatasync" } else { "fsync" },
                SUBVOLS[key.0],
                key.1
            );
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                let f = d.lookup_async(name).await?;
                f.fsync(data_only).await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            model.note(&key, cycle, "fsync");
            Ok(op)
        }
        // Punch a hole (KEEP_SIZE): the range reads back as zeros.
        83..=87 => {
            let key = model.pick_file(rng).expect("files");
            let mut new = model.file(&key).data.clone();
            let len = new.len() as u64;
            let off = rng.below(len + 1);
            let n = rng.range(1, 256 * 1024);
            let op = format!("punch {}/{} off {off} len {n}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                let f = d.lookup_async(name).await?;
                f.fallocate(
                    crate::write::FALLOC_FL_PUNCH_HOLE | crate::write::FALLOC_FL_KEEP_SIZE,
                    off,
                    n,
                )
                .await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            let end = (off + n).min(len) as usize;
            new[off as usize..end].fill(0);
            model.set(key, new, cycle, &format!("punch {off}+{n}"));
            Ok(op)
        }
        // fallocate mode 0, sometimes past EOF (the size grows, zeros).
        88..=90 => {
            let key = model.pick_file(rng).expect("files");
            let mut new = model.file(&key).data.clone();
            let len = new.len() as u64;
            let off = rng.below(len + 64 * 1024);
            let n = rng.range(1, 256 * 1024);
            let op = format!("fallocate {}/{} off {off} len {n}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                let f = d.lookup_async(name).await?;
                f.fallocate(0, off, n).await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            if ((off + n) as usize) > new.len() {
                new.resize((off + n) as usize, 0);
            }
            model.set(key, new, cycle, &format!("fallocate {off}+{n}"));
            Ok(op)
        }
        // Hard link, in the same or another directory of the subvolume.
        91..=94 => {
            let key = model.pick_file(rng).expect("files");
            let dest_dir = model.pick_dir(rng, Some(key.0));
            let dest_name = model.fresh("l");
            let dest_path = format!("{}/{dest_name}", dest_dir.1);
            let op = format!("link {}/{} -> {dest_path}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let src = dir_at(&roots[key.0], parent).await?;
                if parent == dest_dir.1 {
                    src.link(name, &dest_name).await
                } else {
                    let dst = dir!(dest_dir)?;
                    src.link_to(name, &*dst, &dest_name).await
                }
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            model.link(&key, (key.0, dest_path), cycle);
            Ok(op)
        }
        // Atomic replace: write a temp file, fsync it, rename over the file.
        _ => {
            let key = model.pick_file(rng).expect("files");
            let len = rng.below(64 * 1024) as usize;
            let data = rng.data(len);
            let tmp = model.fresh(".tmp");
            let op = format!("replace {}/{} via {tmp} len {len}", SUBVOLS[key.0], key.1);
            let (parent, name) = split(&key.1);
            let r: Result<(), FsError> = async {
                let d = dir_at(&roots[key.0], parent).await?;
                let f = d.create(&tmp).await?;
                write_all(&f, 0, &data).await?;
                f.fsync(false).await?;
                d.rename(&tmp, name).await
            }
            .await;
            r.map_err(|e| (op.clone(), e))?;
            model.remove(&key);
            model.set(key, data, cycle, &format!("replaced {len}"));
            Ok(op)
        }
    }
}

/// Drop every reference of a cycle and require the shared core to be gone.
fn unmount(views: Views, fsid: &[u8; 16]) -> Result<(), String> {
    drop(views);
    match crate::registry::instance_for(fsid) {
        None => Ok(()),
        Some(core) => Err(format!(
            "the shared core outlived its last mount ({} other references)",
            Arc::strong_count(&core) - 1
        )),
    }
}

fn fsid_of(dev: &dyn narf_block::BlockDeviceSync) -> Option<[u8; 16]> {
    let fsid = crate::harness::btrfs_fsid(dev)?;
    let hex: Vec<u8> = fsid
        .bytes()
        .filter(|b| *b != b'-')
        .collect::<Vec<u8>>()
        .chunks(2)
        .map(|pair| {
            let s = core::str::from_utf8(pair).unwrap_or("00");
            u8::from_str_radix(s, 16).unwrap_or(0)
        })
        .collect();
    hex.try_into().ok()
}

fn print_manifest(model: &Model) {
    for (sv, path) in &model.dirs {
        say(&format!("DIR {} {path}", SUBVOLS[*sv]));
    }
    for ((sv, path), ino) in &model.files {
        let file = &model.inodes[ino];
        say(&format!(
            "FILE {} {path} {} {:016x}",
            SUBVOLS[*sv],
            file.data.len(),
            fnv64(&file.data)
        ));
    }
}

/// Run the cycles. `root` is the boot root mount (the harness image under
/// `narf.disks=root-rw`), already checked to be the disposable harness root.
pub fn run(root: Arc<dyn FsInstance>) -> narf_init::InitResult {
    match run_inner(root) {
        Ok(()) => narf_init::InitResult::Ok,
        Err(why) => {
            say(&format!("FAIL {why}"));
            narf_init::InitResult::Error("btrfs cycles failed")
        }
    }
}

fn run_inner(root: Arc<dyn FsInstance>) -> Result<(), String> {
    let p = Params::from_cmdline();
    say(&format!(
        "START cycles={} seed={} ops={} live_kib={} big_kib={}",
        p.cycles,
        p.seed,
        p.ops,
        p.max_live >> 10,
        p.big_max >> 10
    ));
    let device = narf_block::disk_policy::designated_root().ok_or("no designated root")?;
    let dev = narf_block::find_block_device(device).ok_or("designated root not registered")?;
    let fsid = fsid_of(&*dev).ok_or("no btrfs fsid on the designated root")?;
    let source = format!("/dev/{device}");
    drop(dev);

    // The boot mount: seeds intact, then detach `/` and drop the instance.
    let boot_root = root.root();
    narf_scheduler::block_on(async {
        let home = mount_views(&source)?;
        let roots = [boot_root.clone(), home.roots[1].clone()];
        let r = verify_seeds(&roots).await;
        drop(roots);
        drop(home);
        r
    })
    .map_err(|e| format!("cycle 0 (boot root): {e}"))?;
    drop(boot_root);
    drop(root);
    let handle =
        narf_capabilities::Cap::<narf_filesystem::MountPoint, narf_capabilities::Write>::bootstrap(
        );
    narf_filesystem::registry()
        .unmount(&handle, "/")
        .map_err(|e| format!("umount /: {e:?}"))?;
    if let Some(core) = crate::registry::instance_for(&fsid) {
        return Err(format!(
            "cycle 0: the boot root's core outlived `umount /` ({} other references)",
            Arc::strong_count(&core) - 1
        ));
    }
    say(&format!("BOOT-ROOT-DETACHED device={device}"));

    let mut rng = Rng(p.seed.wrapping_mul(0x2545_f491_4f6c_dd1d) ^ 0xb7e1_5162_8aed_2a6b);
    let mut model = Model::default();
    let mut last_gen = 0u64;
    let started = narf_time::monotonic_ns();
    for cycle in 1..=p.cycles + 1 {
        let final_check = cycle > p.cycles;
        let t = narf_time::monotonic_ns();
        let views = mount_views(&source).map_err(|e| format!("cycle {cycle}: {e}"))?;
        let mount_ms = ms_since(t);
        let mounted_gen = live_generation(&fsid).unwrap_or(0);
        if mounted_gen < last_gen {
            return Err(format!(
                "cycle {cycle}: mounted generation {mounted_gen} is older than the last commit {last_gen}"
            ));
        }
        if cycle == 1 {
            // The workload's own directory in every subvolume.
            for (sv, name) in SUBVOLS.iter().enumerate() {
                let root = views.roots[sv].clone();
                narf_scheduler::block_on(async move { root.mkdir(WORK_DIR).await.map(|_| ()) })
                    .map_err(|e| format!("cycle 1: mkdir {name}/{WORK_DIR}: {e:?}"))?;
                model.dirs.insert((sv, WORK_DIR.to_string()));
            }
        }
        let t = narf_time::monotonic_ns();
        narf_scheduler::block_on(verify(&views.roots, &model))
            .map_err(|e| format!("cycle {cycle}: verify after remount: {e}"))?;
        let verify_ms = ms_since(t);
        if final_check {
            print_manifest(&model);
            unmount(views, &fsid).map_err(|e| format!("final unmount: {e}"))?;
            say(&format!(
                "PASS cycles={} seed={} files={} dirs={} live={} gen={mounted_gen} ms={} final_verify_ms={verify_ms}",
                p.cycles,
                p.seed,
                model.files.len(),
                model.dirs.len(),
                model.live,
                ms_since(started)
            ));
            return Ok(());
        }
        let t = narf_time::monotonic_ns();
        let mut ops = 0u32;
        for _ in 0..p.ops {
            match narf_scheduler::block_on(step(&views.roots, &mut model, &mut rng, &p, cycle)) {
                Ok(_) => ops += 1,
                Err((op, e)) => return Err(format!("cycle {cycle}: op `{op}` failed: {e:?}")),
            }
        }
        let work_ms = ms_since(t);
        let t = narf_time::monotonic_ns();
        let root = views.roots[0].clone();
        narf_scheduler::block_on(async move { root.syncfs().await })
            .map_err(|e| format!("cycle {cycle}: syncfs: {e:?}"))?;
        let sync_ms = ms_since(t);
        let gen = live_generation(&fsid).unwrap_or(0);
        if gen <= mounted_gen {
            return Err(format!(
                "cycle {cycle}: syncfs after {ops} operations left the generation at {gen}"
            ));
        }
        last_gen = gen;
        let t = narf_time::monotonic_ns();
        unmount(views, &fsid).map_err(|e| format!("cycle {cycle}: unmount: {e}"))?;
        let umount_ms = ms_since(t);
        say(&format!(
            "CYCLE {cycle}/{} ok gen={gen} ops={ops} files={} dirs={} live={} uncalibrated-ms mount={mount_ms} verify={verify_ms} work={work_ms} sync={sync_ms} umount={umount_ms}",
            p.cycles,
            model.files.len(),
            model.dirs.len(),
            model.live
        ));
    }
    Ok(())
}
