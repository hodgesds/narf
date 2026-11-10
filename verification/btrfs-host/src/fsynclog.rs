//! Tree-log (fsync) scenarios: a log written by one implementation is
//! replayed by both, and the two results must agree.
//!
//! Every case is an op script (the grammar `vminit.c` runs in the Linux
//! guest; [`run_narf_line`] runs the same lines through NARF's VFS) that
//! ends in `crash`. The image as the crash left it is then mounted twice,
//! from two copies:
//!
//! * by a real Linux kernel ([`crate::linuxvm`]), whose mount replays the
//!   log; the guest lists every entry with a content hash and unmounts;
//! * by NARF, as a `root-rw` boot mounts it, replaying the log.
//!
//! The case passes when the two listings are equal entry for entry (type,
//! mode, link count, size, content), each replayed image passes
//! `btrfs check --check-data-csum`, the NARF-replayed image mounts on Linux
//! again unchanged, and the fsync promises the script made hold
//! ([`ScriptModel::check`]): a file fsynced since the last full commit is
//! there under a name it had, with exactly the content it had at that
//! fsync; a file that existed at the last commit is either as committed or
//! as some fsync left it, never empty or torn.
//!
//! `fsync-linux`: Linux writes the log (the guest is killed at `crash`).
//! `fsync-narf`: NARF writes it — the scripts run through NARF's VFS and the
//! image is copied at `crash`, before anything else can reach it — and the
//! run reports how many fsyncs went through the log and how many had to
//! commit, with the superblock writes and commits a sixty-file
//! write-temp + fsync + rename burst cost.
//! `fsync-sweep`: NARF runs a script while the device records every write;
//! the image is then rebuilt as it would be had power failed after each
//! write (all of a sample when there are many; with and without the
//! writes no flush had covered yet), and every one of those images must
//! replay under NARF to a state that keeps each fsync that had returned by
//! then, and pass `btrfs check`; a spread of them is also replayed by
//! Linux and compared.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use narf_filesystem::{DirOps, FileOps, FileType, FsError, FsInstance};

use crate::dev::{self, RecDev};
use crate::host::block_on;
use crate::linuxvm::{self, Ent, Listing, Vm};
use crate::narf::{dir_at, file_at, read_all, split};
use crate::workload::Rng;
use crate::{fixture, linux, narf};

/// The subvolumes a `root-rw` boot mounts, as the script paths name them.
const SUBVOLS: [&str; 2] = ["@", "@home"];

const FNV_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// The files every case starts from (`make_pristine`): `(path, length,
/// compressible)`. `mkfs.btrfs --compress zstd:1` stores the compressible
/// one as zstd extents, as most of a real root is stored.
const FIXTURE_FILES: [(&str, usize, bool); 4] = [
    ("@/etc/hostname", 5, false),
    ("@/usr/lib/blob", 300_000, false),
    ("@/usr/share/words", 200_000, true),
    ("@home/user/.profile", 40, false),
];

fn fixture_bytes(len: usize, compressible: bool) -> Vec<u8> {
    if compressible {
        (0..len).map(|i| b'a' + (i / 64 % 7) as u8).collect()
    } else {
        linuxvm::pattern_bytes(len as u64, 0, len)
    }
}

// ── The script model ───────────────────────────────────────────────

#[derive(Clone, Debug)]
enum Node {
    File(Vec<u8>),
    Dir,
    Symlink,
}

/// What an fsync promised about one inode.
#[derive(Clone, Debug)]
struct Promise {
    state: (u64, u64),
    /// The names the inode had when it was fsynced.
    names: BTreeSet<String>,
    /// Every state the inode has been in since that fsync. A crash may
    /// leave any of them: an fsync is a lower bound on what is durable, and
    /// both implementations do persist later states in places (a rename or
    /// link after a truncate logs the inode again).
    later: BTreeSet<(u64, u64)>,
}

/// The script as the harness understands it: enough of the namespace and
/// file contents to state what must survive the crash.
#[derive(Default)]
pub struct ScriptModel {
    inodes: Vec<Node>,
    names: BTreeMap<String, usize>,
    /// Files at the last full commit: path → (size, hash).
    committed: BTreeMap<String, (u64, u64)>,
    /// Latest fsync of each inode since the last commit.
    promises: BTreeMap<usize, Promise>,
    /// File inodes changed (or created) since the last commit whose latest
    /// change no fsync has covered. What a crash leaves of such a file is
    /// not promised: its name may be logged with its size but not its data.
    unsynced: BTreeSet<usize>,
    /// The state each inode was last fsynced in since the last commit.
    fsynced: BTreeMap<usize, (u64, u64)>,
    /// Every inode that has held each name since the last commit.
    holders: BTreeMap<String, BTreeSet<usize>>,
    /// Names removed (unlinked or renamed away) since the last commit.
    removed: BTreeSet<String>,
    /// The log was written by Linux, which after a rename or link of a file
    /// with unsynced changes may log the file's newer size without the data
    /// written since its fsync (the tail reads as zeros). Linux and NARF
    /// replay such a log identically, which the comparison of the two
    /// replays holds them to; the promise check then accepts a later size.
    pub linux_wrote: bool,
}

fn sig(data: &[u8]) -> (u64, u64) {
    (data.len() as u64, linuxvm::fnv(data))
}

impl ScriptModel {
    pub fn new() -> Self {
        let mut m = Self::default();
        for sv in SUBVOLS {
            m.inodes.push(Node::Dir);
            m.names.insert(sv.to_string(), m.inodes.len() - 1);
        }
        // The fixture's own files and directories, committed.
        for (path, len, compressible) in FIXTURE_FILES {
            let mut dir = String::new();
            for part in path.rsplit_once('/').unwrap().0.split('/') {
                if !dir.is_empty() {
                    dir.push('/');
                }
                dir.push_str(part);
                if !m.names.contains_key(&dir) {
                    m.inodes.push(Node::Dir);
                    m.names.insert(dir.clone(), m.inodes.len() - 1);
                }
            }
            m.inodes.push(Node::File(fixture_bytes(len, compressible)));
            m.names.insert(path.to_string(), m.inodes.len() - 1);
        }
        m.apply("sync");
        m
    }

    fn names_of(&self, ino: usize) -> BTreeSet<String> {
        self.names
            .iter()
            .filter(|(_, &i)| i == ino)
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The file at `path`, created empty if absent.
    fn file_ino(&mut self, path: &str) -> usize {
        if let Some(&ino) = self.names.get(path) {
            assert!(
                matches!(self.inodes[ino], Node::File(_)),
                "{path} is not a file"
            );
            return ino;
        }
        self.inodes.push(Node::File(Vec::new()));
        let ino = self.inodes.len() - 1;
        self.unsynced.insert(ino);
        self.give_name(path, ino);
        ino
    }

    /// Change the content of the file at `path` and record its new state.
    fn mutate(&mut self, path: &str, change: impl FnOnce(&mut Vec<u8>)) {
        let ino = self.file_ino(path);
        let Node::File(data) = &mut self.inodes[ino] else {
            unreachable!()
        };
        change(data);
        let state = sig(data);
        self.unsynced.insert(ino);
        if let Some(p) = self.promises.get_mut(&ino) {
            p.later.insert(state);
        }
    }

    pub fn size(&self, path: &str) -> u64 {
        match self.names.get(path).map(|&i| &self.inodes[i]) {
            Some(Node::File(d)) => d.len() as u64,
            _ => 0,
        }
    }

    pub fn files(&self) -> Vec<String> {
        self.names
            .iter()
            .filter(|(_, &i)| matches!(self.inodes[i], Node::File(_)))
            .map(|(n, _)| n.clone())
            .collect()
    }

    pub fn dirs(&self) -> Vec<String> {
        self.names
            .iter()
            .filter(|(_, &i)| matches!(self.inodes[i], Node::Dir))
            .map(|(n, _)| n.clone())
            .collect()
    }

    pub fn dir_is_empty(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        !self.names.keys().any(|n| n.starts_with(&prefix))
    }

    pub fn same_inode(&self, a: &str, b: &str) -> bool {
        self.names.contains_key(a) && self.names.get(a) == self.names.get(b)
    }

    fn drop_name(&mut self, path: &str) {
        if let Some(ino) = self.names.remove(path) {
            self.removed.insert(path.to_string());
            if self.names_of(ino).is_empty() {
                // Nothing names it any more: an fsync promised no more than
                // that it could be found by a name.
                self.promises.remove(&ino);
            }
        }
    }

    fn give_name(&mut self, path: &str, ino: usize) {
        self.names.insert(path.to_string(), ino);
        self.holders
            .entry(path.to_string())
            .or_default()
            .insert(ino);
    }

    /// Apply one script line. Returns `false` at `crash`.
    pub fn apply(&mut self, line: &str) -> bool {
        let w: Vec<&str> = line.split_whitespace().collect();
        let num = |i: usize| w[i].parse::<u64>().unwrap();
        match w[0] {
            "mkdir" => {
                self.inodes.push(Node::Dir);
                self.names.insert(w[1].to_string(), self.inodes.len() - 1);
            }
            "write" => {
                let (off, len, seed) = (num(2) as usize, num(3) as usize, num(4));
                self.mutate(w[1], |d| {
                    if d.len() < off + len {
                        d.resize(off + len, 0);
                    }
                    d[off..off + len]
                        .copy_from_slice(&linuxvm::pattern_bytes(seed, off as u64, len));
                });
            }
            "truncate" => {
                let size = num(2) as usize;
                self.mutate(w[1], |d| d.resize(size, 0));
            }
            "falloc" => {
                let (mode, off, len) = (num(2), num(3) as usize, num(4) as usize);
                self.mutate(w[1], |d| {
                    if mode & 2 != 0 {
                        let end = (off + len).min(d.len());
                        if off < end {
                            d[off..end].fill(0);
                        }
                    } else if mode & 1 == 0 && d.len() < off + len {
                        d.resize(off + len, 0);
                    }
                });
            }
            "fsync" | "fdatasync" => {
                let ino = self.names[w[1]];
                if let Node::File(d) = &self.inodes[ino] {
                    let promise = Promise {
                        state: sig(d),
                        names: self.names_of(ino),
                        later: BTreeSet::new(),
                    };
                    self.fsynced.insert(ino, promise.state);
                    self.unsynced.remove(&ino);
                    self.promises.insert(ino, promise);
                }
            }
            "fsyncdir" | "chmod" | "setxattr" | "rmxattr" => {}
            "rename" => {
                let (from, to) = (w[1].to_string(), w[2].to_string());
                let ino = self.names[&from];
                if let Some(old) = self.names.remove(&to) {
                    if self.names_of(old).is_empty() {
                        self.promises.remove(&old);
                    }
                }
                self.names.remove(&from);
                self.removed.insert(from.clone());
                self.give_name(&to, ino);
                // A directory takes everything under it along.
                let prefix = format!("{from}/");
                let moved: Vec<(String, usize)> = self
                    .names
                    .iter()
                    .filter(|(n, _)| n.starts_with(&prefix))
                    .map(|(n, &i)| (n.clone(), i))
                    .collect();
                for (old_name, child) in moved {
                    self.names.remove(&old_name);
                    self.removed.insert(old_name.clone());
                    let new_name = format!("{to}/{}", &old_name[prefix.len()..]);
                    self.give_name(&new_name, child);
                }
            }
            "link" => {
                let ino = self.names[w[1]];
                self.give_name(w[2], ino);
            }
            "symlink" => {
                self.inodes.push(Node::Symlink);
                self.names.insert(w[2].to_string(), self.inodes.len() - 1);
            }
            "unlink" | "rmdir" => self.drop_name(w[1]),
            "sync" => {
                self.committed.clear();
                self.unsynced.clear();
                self.fsynced.clear();
                self.holders.clear();
                for (name, &ino) in &self.names {
                    if let Node::File(d) = &self.inodes[ino] {
                        self.committed.insert(name.clone(), sig(d));
                        self.holders.entry(name.clone()).or_default().insert(ino);
                    }
                }
                self.promises.clear();
                self.removed.clear();
            }
            "crash" => return false,
            other => panic!("unknown script op {other}"),
        }
        true
    }

    /// The states a committed `path` may show after replay besides its
    /// committed one, when every file that has held the name since the
    /// commit is either untouched or fsynced after its last change: the
    /// fsynced states. (Write a temporary file, fsync it, rename it over
    /// the real one: the real one is the old content or the new, whole.)
    /// `None` when a holder has changes no fsync covered.
    fn allowed(&self, path: &str) -> Option<BTreeSet<(u64, u64)>> {
        let holders = self.holders.get(path)?;
        if holders.iter().any(|h| self.unsynced.contains(h)) {
            return None;
        }
        Some(
            holders
                .iter()
                .filter_map(|h| self.fsynced.get(h))
                .copied()
                .collect(),
        )
    }

    /// What the fsyncs promised, checked against a replayed tree.
    pub fn check(&self, who: &str, listing: &Listing) -> Vec<String> {
        let mut out = Vec::new();
        let state = |path: &str| match listing.get(&linuxvm::escape(path)) {
            Some(e) if e.kind == 'f' => Some((e.size, e.hash)),
            _ => None,
        };
        // An fsync of a file does not persist a rename of a directory above
        // it, so the file is looked for by its own name, wherever its
        // directory ended up.
        let base = |path: &str| path.rsplit('/').next().unwrap().to_string();
        for (&ino, p) in &self.promises {
            let mut names = p.names.clone();
            names.extend(self.names_of(ino));
            let wanted: BTreeSet<String> =
                names.iter().map(|n| linuxvm::escape(&base(n))).collect();
            let found = listing.iter().any(|(path, e)| {
                e.kind == 'f'
                    && ((e.size, e.hash) == p.state
                        || p.later.contains(&(e.size, e.hash))
                        || (self.linux_wrote && p.later.iter().any(|l| l.0 == e.size)))
                    && wanted.contains(&base(path))
            });
            if !found {
                out.push(format!(
                    "{who}: fsynced file {:?} (or a later state of it) not found under any of {:?}; found {:?}",
                    p.state,
                    names,
                    names.iter().map(|n| (n, state(n))).collect::<Vec<_>>()
                ));
            }
        }
        for (path, &was) in &self.committed {
            match state(path) {
                Some(now) => {
                    if let Some(allowed) = self.allowed(path) {
                        if now != was && !allowed.contains(&now) {
                            out.push(format!(
                                "{who}: {path} is neither as committed {was:?} nor as fsynced {allowed:?}: {now:?}"
                            ));
                        }
                    }
                }
                None if self.removed.contains(path) => {}
                None => out.push(format!(
                    "{who}: {path} was committed and never removed, but is gone"
                )),
            }
        }
        out
    }
}

// ── Running a script through NARF ──────────────────────────────────

/// The mounted subvolume views, in [`SUBVOLS`] order.
pub struct Mounted {
    pub views: Vec<Arc<dyn FsInstance>>,
    pub dev: Arc<RecDev>,
}

impl Mounted {
    pub fn mount(img: &Path, fsid: [u8; 16], nodesize: u32) -> Result<Self, String> {
        let dev = Arc::new(RecDev::open(img, 512, fsid, nodesize));
        narf::register_root(dev.clone(), &fsid)?;
        let views = narf::mount_root_rw(&fsid, SUBVOLS[0], &SUBVOLS[1..])?;
        Ok(Self { views, dev })
    }

    /// Unmount without making anything durable first is not possible (the
    /// last view commits), so a crash is taken by copying the image before
    /// this is called.
    pub fn unmount(self) -> Result<(), String> {
        let violations = self.dev.violations();
        drop(self.views);
        narf::reset();
        if !violations.is_empty() {
            return Err(format!("request-shape violations: {violations:?}"));
        }
        Ok(())
    }

    /// Every entry of both subvolumes, as the Linux guest lists them.
    pub fn listing(&self) -> Result<Listing, String> {
        let mut out = Listing::new();
        for (i, sv) in SUBVOLS.iter().enumerate() {
            let root = self.views[i].root();
            out.insert(
                sv.to_string(),
                Ent {
                    kind: 'd',
                    perms: u32::from(root.dir_mode() & 0o7777),
                    nlink: 1,
                    size: 0,
                    hash: FNV_BASIS,
                },
            );
            let mut stack: Vec<(String, Arc<dyn DirOps>)> = vec![(sv.to_string(), root)];
            while let Some((path, dir)) = stack.pop() {
                let entries = block_on(dir.enumerate_async(0, usize::MAX))
                    .map_err(|e| format!("readdir {path}: {e:?}"))?;
                for (name, ft) in entries {
                    let p = format!("{path}/{name}");
                    let key = linuxvm::escape(&p);
                    match ft {
                        FileType::Dir => {
                            let d = block_on(dir.lookup_dir_async(&name))
                                .map_err(|e| format!("lookup dir {p}: {e:?}"))?;
                            out.insert(
                                key,
                                Ent {
                                    kind: 'd',
                                    perms: u32::from(d.dir_mode() & 0o7777),
                                    nlink: 1,
                                    size: 0,
                                    hash: FNV_BASIS,
                                },
                            );
                            stack.push((p, d));
                        }
                        FileType::File | FileType::Symlink => {
                            let f = block_on(dir.lookup_async(&name))
                                .map_err(|e| format!("lookup {p}: {e:?}"))?;
                            let data =
                                block_on(read_all(&f)).map_err(|e| format!("read {p}: {e:?}"))?;
                            let st =
                                block_on(f.stat_async()).map_err(|e| format!("stat {p}: {e:?}"))?;
                            out.insert(
                                key,
                                Ent {
                                    kind: if ft == FileType::Symlink { 'l' } else { 'f' },
                                    perms: u32::from(st.mode.perms & 0o7777),
                                    nlink: u64::from(
                                        block_on(f.statx_async(0, u32::MAX))
                                            .map_err(|e| format!("statx {p}: {e:?}"))?
                                            .nlink,
                                    ),
                                    size: st.size,
                                    hash: linuxvm::fnv(&data),
                                },
                            );
                        }
                        other => return Err(format!("{p}: unexpected type {other:?}")),
                    }
                }
            }
        }
        Ok(out)
    }
}

// ── Running a script through NARF's VFS ────────────────────────────

impl Mounted {
    fn resolve(&self, path: &str) -> Result<(Arc<dyn DirOps>, String), String> {
        for (i, sv) in SUBVOLS.iter().enumerate() {
            if path == *sv {
                return Ok((self.views[i].root(), String::new()));
            }
            if let Some(rest) = path.strip_prefix(&format!("{sv}/")) {
                return Ok((self.views[i].root(), rest.to_string()));
            }
        }
        Err(format!("script path {path} is outside {SUBVOLS:?}"))
    }

    async fn file(&self, path: &str) -> Result<Arc<dyn FileOps>, String> {
        let (root, rel) = self.resolve(path)?;
        file_at(&root, &rel)
            .await
            .map_err(|e| format!("{path}: {e:?}"))
    }

    /// `open(path, O_CREAT, 0644)`, as the guest's `write` and `falloc` do.
    async fn open_or_create(&self, path: &str) -> Result<Arc<dyn FileOps>, FsError> {
        let (root, rel) = self.resolve(path).map_err(|_| FsError::NotFound)?;
        let (p, n) = split(&rel);
        let dir = dir_at(&root, p).await?;
        match dir.lookup_async(n).await {
            Err(FsError::NotFound) => {
                let f = dir.create(n).await?;
                f.set_perms(0o644).await?;
                Ok(f)
            }
            other => other,
        }
    }

    /// Run one script line (not `crash`) through NARF's VFS.
    pub fn run_line(&self, line: &str) -> Result<(), String> {
        let w: Vec<&str> = line.split_whitespace().collect();
        let num = |i: usize| w[i].parse::<u64>().unwrap();
        let fail = |e: FsError| format!("`{line}`: {e:?}");
        block_on(async {
            match w[0] {
                "mkdir" => {
                    let (root, rel) = self.resolve(w[1])?;
                    let (p, n) = split(&rel);
                    dir_at(&root, p)
                        .await
                        .map_err(fail)?
                        .mkdir(n)
                        .await
                        .map_err(fail)?;
                }
                "write" => {
                    let f = self.open_or_create(w[1]).await.map_err(fail)?;
                    let data = linuxvm::pattern_bytes(num(4), num(2), num(3) as usize);
                    let mut done = 0;
                    while done < data.len() {
                        let n = f
                            .write(num(2) + done as u64, &data[done..])
                            .await
                            .map_err(fail)?;
                        if n == 0 {
                            return Err(format!("`{line}`: short write"));
                        }
                        done += n;
                    }
                }
                "truncate" => self
                    .file(w[1])
                    .await?
                    .truncate(num(2))
                    .await
                    .map_err(fail)?,
                "falloc" => self
                    .open_or_create(w[1])
                    .await
                    .map_err(fail)?
                    .fallocate(num(2) as u32, num(3), num(4))
                    .await
                    .map_err(fail)?,
                "fsync" => self.file(w[1]).await?.fsync(false).await.map_err(fail)?,
                "fdatasync" => self.file(w[1]).await?.fsync(true).await.map_err(fail)?,
                "fsyncdir" => {
                    let (root, rel) = self.resolve(w[1])?;
                    dir_at(&root, &rel)
                        .await
                        .map_err(fail)?
                        .fsync(false)
                        .await
                        .map_err(fail)?;
                }
                "rename" | "link" => {
                    let (root, from) = self.resolve(w[1])?;
                    let (root2, to) = self.resolve(w[2])?;
                    let (fp, fname) = split(&from);
                    let (tp, tname) = split(&to);
                    let fd = dir_at(&root, fp).await.map_err(fail)?;
                    let td = dir_at(&root2, tp).await.map_err(fail)?;
                    if w[0] == "rename" {
                        fd.rename_to(fname, &*td, tname, 0).await.map_err(fail)?;
                    } else {
                        fd.link_to(fname, &*td, tname).await.map_err(fail)?;
                    }
                }
                "symlink" => {
                    let (root, rel) = self.resolve(w[2])?;
                    let (p, n) = split(&rel);
                    dir_at(&root, p)
                        .await
                        .map_err(fail)?
                        .symlink(n, w[1])
                        .await
                        .map_err(fail)?;
                }
                "unlink" | "rmdir" => {
                    let (root, rel) = self.resolve(w[1])?;
                    let (p, n) = split(&rel);
                    let dir = dir_at(&root, p).await.map_err(fail)?;
                    if w[0] == "unlink" {
                        dir.unlink(n).await.map_err(fail)?;
                    } else {
                        dir.rmdir(n).await.map_err(fail)?;
                    }
                }
                "chmod" => {
                    let perms = u16::from_str_radix(w[2], 8).unwrap();
                    self.file(w[1])
                        .await?
                        .set_perms(perms)
                        .await
                        .map_err(fail)?;
                }
                "setxattr" => {
                    let value = linuxvm::pattern_bytes(num(4), 0, num(3) as usize);
                    self.file(w[1])
                        .await?
                        .set_xattr(w[2], &value, 0)
                        .await
                        .map_err(fail)?;
                }
                "rmxattr" => self
                    .file(w[1])
                    .await?
                    .remove_xattr(w[2])
                    .await
                    .map_err(fail)?,
                "sync" => self.views[0].root().syncfs().await.map_err(fail)?,
                other => return Err(format!("unknown script op {other}")),
            }
            Ok(())
        })
    }
}

// ── Cases ──────────────────────────────────────────────────────────

/// One named script.
pub struct Case {
    pub name: String,
    pub script: Vec<String>,
}

fn case(name: &str, script: &str) -> Case {
    Case {
        name: name.to_string(),
        // Linux commits in full on the first fsync after a mount; a leading
        // sync gets that out of the way so the script's fsyncs reach the log.
        script: std::iter::once("sync")
            .chain(script.lines().map(str::trim))
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect(),
    }
}

/// The fixed cases: each fsync shape the writer and the replay must handle.
pub fn fixed_cases() -> Vec<Case> {
    let mut cases = vec![
        case(
            "new-file",
            "write @/n1 0 70000 1
             fsync @/n1
             crash",
        ),
        case(
            "new-small-file",
            "write @/tiny 0 300 2
             fsync @/tiny
             crash",
        ),
        case(
            "overwrite",
            "write @/o 0 200000 3
             sync
             write @/o 4096 8192 4
             fsync @/o
             crash",
        ),
        case(
            "append",
            "write @/a 0 5000 5
             sync
             write @/a 5000 3000 6
             fsync @/a
             write @/a 8000 100000 7
             fdatasync @/a
             crash",
        ),
        case(
            "truncate-down",
            "write @/t 0 300000 8
             sync
             truncate @/t 100001
             fsync @/t
             crash",
        ),
        case(
            "truncate-to-zero-then-write",
            "write @/t0 0 150000 9
             sync
             truncate @/t0 0
             write @/t0 0 4000 10
             fsync @/t0
             crash",
        ),
        case(
            "truncate-up",
            "write @/tu 0 6000 11
             sync
             truncate @/tu 500000
             write @/tu 400000 5000 12
             fsync @/tu
             crash",
        ),
        case(
            "inline-to-regular",
            "write @/in 0 100 13
             sync
             write @/in 100 20000 14
             fsync @/in
             crash",
        ),
        case(
            "new-dir-chain",
            "mkdir @/d1
             mkdir @/d1/d2
             mkdir @/d1/d2/d3
             write @/d1/d2/d3/f 0 9000 15
             fsync @/d1/d2/d3/f
             crash",
        ),
        case(
            "unsynced-after-fsync",
            "write @/u 0 50000 16
             sync
             write @/u 0 50000 17
             fsync @/u
             write @/u 10000 20000 18
             truncate @/u 30000
             write @/other 0 4096 19
             crash",
        ),
        case(
            "fsync-dir-after-create",
            "mkdir @/dd
             sync
             write @/dd/x 0 5000 20
             write @/dd/y 0 100 21
             fsyncdir @/dd
             crash",
        ),
        case(
            "fsync-dir-after-rename",
            "mkdir @/dr
             write @/dr/old 0 12000 22
             sync
             rename @/dr/old @/dr/new
             fsyncdir @/dr
             crash",
        ),
        case(
            "fsync-dir-after-unlink",
            "mkdir @/du
             write @/du/gone 0 12000 23
             write @/du/stays 0 12000 24
             sync
             unlink @/du/gone
             fsyncdir @/du
             crash",
        ),
        case(
            "hard-link",
            "write @/h1 0 30000 25
             sync
             link @/h1 @/h2
             write @/h1 0 100 26
             fsync @/h1
             crash",
        ),
        case(
            "punch-hole",
            "write @/p 0 400000 27
             sync
             falloc @/p 3 65536 131072
             fsync @/p
             crash",
        ),
        case(
            "prealloc-then-write",
            "falloc @/pre 0 0 1048576
             sync
             write @/pre 8192 20000 28
             fsync @/pre
             write @/pre 500000 4096 29
             fdatasync @/pre
             crash",
        ),
        case(
            "prealloc-keep-size",
            "write @/pk 0 10000 30
             falloc @/pk 1 0 1048576
             sync
             write @/pk 10000 50000 31
             fsync @/pk
             crash",
        ),
        case(
            "xattrs",
            "write @/x 0 10000 32
             setxattr @/x user.a 40 33
             setxattr @/x user.b 300 34
             sync
             rmxattr @/x user.a
             setxattr @/x user.c 10 35
             write @/x 0 100 36
             fsync @/x
             crash",
        ),
        case(
            "two-subvolumes",
            "write @/s1 0 30000 37
             write @home/s2 0 30000 38
             sync
             write @/s1 30000 30000 39
             fsync @/s1
             write @home/s2 0 10 40
             write @home/s3 0 80000 41
             fsync @home/s2
             fsync @home/s3
             crash",
        ),
        case(
            "unlink-after-fsync",
            "write @/ua 0 20000 42
             fsync @/ua
             unlink @/ua
             write @/ub 0 20000 43
             fsync @/ub
             crash",
        ),
        case(
            "rename-after-fsync",
            "write @/ra 0 20000 44
             fsync @/ra
             rename @/ra @/rb
             write @/rc 0 20000 45
             fsync @/rc
             crash",
        ),
        case(
            "fsync-across-commit",
            "write @/c1 0 40000 46
             fsync @/c1
             sync
             write @/c1 40000 40000 47
             write @/c2 0 40000 48
             fsync @/c2
             sync
             write @/c1 0 100 49
             fsync @/c1
             crash",
        ),
        case(
            "big-file",
            "write @/big 0 1500000 50
             sync
             write @/big 700000 300000 51
             write @/big 1500000 200000 52
             fsync @/big
             crash",
        ),
        case(
            "compressed-overwrite",
            "write @/usr/share/words 5000 20000 61
             fsync @/usr/share/words
             crash",
        ),
        case(
            "compressed-truncate",
            "truncate @/usr/share/words 70001
             fsync @/usr/share/words
             crash",
        ),
        case(
            "compressed-punch",
            "falloc @/usr/share/words 3 16384 65536
             fsync @/usr/share/words
             crash",
        ),
        case(
            "compressed-append",
            "write @/usr/share/words 200000 30000 62
             fdatasync @/usr/share/words
             write @/usr/lib/blob 100000 5000 63
             fsync @/usr/lib/blob
             crash",
        ),
        case(
            "symlink-and-dir-fsync",
            "mkdir @/sl
             sync
             symlink target/elsewhere @/sl/link
             mkdir @/sl/sub
             fsyncdir @/sl
             crash",
        ),
        case(
            "mode-change",
            "write @/m 0 5000 53
             sync
             chmod @/m 600
             fsync @/m
             crash",
        ),
        case(
            "rename-dir-with-fsynced-file",
            "mkdir @/rd
             write @/rd/f 0 30000 54
             sync
             write @/rd/f 0 30000 55
             fsync @/rd/f
             rename @/rd @/rd2
             write @/rd2/g 0 100 56
             fsync @/rd2/g
             crash",
        ),
        case(
            "replace-then-recreate-name",
            "write @/k 0 20000 57
             sync
             rename @/k @/k.bak
             write @/k 0 30000 58
             fsync @/k
             crash",
        ),
        case(
            "unlink-and-recreate",
            "write @/ur 0 20000 59
             sync
             unlink @/ur
             write @/ur 0 500 60
             fsync @/ur
             crash",
        ),
    ];
    // The pattern a desktop login produces: write a temp file, fsync it,
    // rename it over the real one, sixty times, then the machine dies.
    let mut burst = String::new();
    for i in 0..60 {
        burst.push_str(&format!(
            "write @home/cfg{i} 0 {} {}\n",
            2000 + i * 37,
            100 + i
        ));
    }
    burst.push_str("sync\n");
    for i in 0..60 {
        burst.push_str(&format!(
            "write @home/cfg{i}.tmp 0 {} {}\nfsync @home/cfg{i}.tmp\nrename @home/cfg{i}.tmp @home/cfg{i}\n",
            3000 + i * 53,
            200 + i
        ));
    }
    burst.push_str("crash\n");
    cases.push(case("temp-fsync-rename-burst", &burst));
    cases
}

/// A seeded random script: a committed base, then a mix of data and
/// namespace operations with fsyncs, ending in a crash.
pub fn random_case(seed: u64) -> Case {
    let mut rng = Rng::new(seed ^ 0x00f5_c109);
    let mut m = ScriptModel::new();
    let mut script: Vec<String> = vec!["sync".into()];
    let mut seq = 0u64;
    let emit = |m: &mut ScriptModel, script: &mut Vec<String>, line: String| {
        m.apply(&line);
        script.push(line);
    };
    let ops = 12 + rng.below(40);
    let mut synced = false;
    for step in 0..ops {
        // A full commit somewhere in the first half, usually.
        if !synced && step > 3 && rng.chance(25) {
            emit(&mut m, &mut script, "sync".into());
            synced = true;
            continue;
        }
        let files = m.files();
        let dirs = m.dirs();
        let dir = rng.pick(&dirs).unwrap().clone();
        // rename(2) and link(2) do not cross subvolumes.
        let subvol = |p: &str| p.split('/').next().unwrap().to_string();
        let dir_near = |rng: &mut Rng, f: &str| {
            let near: Vec<String> = dirs
                .iter()
                .filter(|d| subvol(d) == subvol(f))
                .cloned()
                .collect();
            rng.pick(&near).unwrap().clone()
        };
        seq += 1;
        let line = match rng.below(100) {
            0..=19 => {
                let len = match rng.below(4) {
                    0 => rng.range(1, 2000),
                    1 => rng.range(2000, 70000),
                    2 => rng.range(70000, 400_000),
                    _ => rng.range(1, 9000),
                };
                format!("write {dir}/f{seq} 0 {len} {seq}")
            }
            20..=39 if !files.is_empty() => {
                let f = rng.pick(&files).unwrap();
                let size = m.size(f);
                let off = rng.below(size + 5000);
                format!("write {f} {off} {} {seq}", rng.range(1, 100_000))
            }
            40..=47 if !files.is_empty() => {
                let f = rng.pick(&files).unwrap();
                format!("truncate {f} {}", rng.below(m.size(f) + 20000))
            }
            48..=53 if !files.is_empty() => {
                let f = rng.pick(&files).unwrap();
                let size = m.size(f);
                match rng.below(3) {
                    0 => format!(
                        "falloc {f} 0 {} {}",
                        rng.below(size + 8192),
                        rng.range(1, 262_144)
                    ),
                    1 => format!("falloc {f} 1 {} {}", size, rng.range(4096, 262_144)),
                    _ if size > 0 => {
                        format!("falloc {f} 3 {} {}", rng.below(size), rng.range(1, 131_072))
                    }
                    _ => format!("truncate {f} 4096"),
                }
            }
            54..=58 => format!("mkdir {dir}/d{seq}"),
            59..=66 if !files.is_empty() => {
                let f = rng.pick(&files).unwrap().clone();
                let dir = dir_near(&mut rng, &f);
                // Onto a fresh name, or over another file.
                if rng.chance(40) && files.len() > 1 {
                    let over = rng.pick(&files).unwrap().clone();
                    if m.same_inode(&over, &f) || subvol(&over) != subvol(&f) {
                        format!("rename {f} {dir}/r{seq}")
                    } else {
                        format!("rename {f} {over}")
                    }
                } else {
                    format!("rename {f} {dir}/r{seq}")
                }
            }
            67..=71 if !files.is_empty() => {
                format!("unlink {}", rng.pick(&files).unwrap())
            }
            72..=75 if !files.is_empty() => {
                let f = rng.pick(&files).unwrap().clone();
                let dir = dir_near(&mut rng, &f);
                format!("link {f} {dir}/l{seq}")
            }
            76..=78 => {
                let empty: Vec<String> = dirs
                    .iter()
                    .filter(|d| !SUBVOLS.contains(&d.as_str()) && m.dir_is_empty(d))
                    .cloned()
                    .collect();
                match rng.pick(&empty) {
                    Some(d) => format!("rmdir {d}"),
                    None => format!("mkdir {dir}/d{seq}"),
                }
            }
            79..=82 => format!("fsyncdir {dir}"),
            83..=85 if !files.is_empty() => {
                format!(
                    "setxattr {} user.x{} {} {seq}",
                    rng.pick(&files).unwrap(),
                    seq % 3,
                    rng.range(1, 200)
                )
            }
            _ if !files.is_empty() => {
                let f = rng.pick(&files).unwrap();
                if rng.chance(30) {
                    format!("fdatasync {f}")
                } else {
                    format!("fsync {f}")
                }
            }
            _ => format!("write {dir}/f{seq} 0 {} {seq}", rng.range(1, 30000)),
        };
        emit(&mut m, &mut script, line);
    }
    // End on an fsync so there is a log to replay more often than not.
    if let Some(f) = rng.pick(&m.files()) {
        script.push(format!("fsync {f}"));
    }
    script.push("crash".into());
    Case {
        name: format!("random-{seed}"),
        script,
    }
}

// ── Judging a crashed image ────────────────────────────────────────

pub struct Ctx<'a> {
    /// The Linux guest; without one only NARF's side can be judged.
    pub vm: Option<&'a Vm>,
    pub dir: PathBuf,
    pub pristine: PathBuf,
    pub fsid: [u8; 16],
    pub nodesize: u32,
}

/// `super.log_root` of an image.
pub fn log_root_of(img: &Path) -> u64 {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(img).unwrap();
    let mut sb = vec![0u8; dev::SB_LEN as usize];
    f.read_exact_at(&mut sb, 0x10000).unwrap();
    u64::from_le_bytes(sb[0x60..0x68].try_into().unwrap())
}

/// Build the fixture every case starts from: the `root-rw` shape (`@`
/// default, `@home`), a few committed files.
pub fn make_pristine(dir: &Path) -> Result<(PathBuf, [u8; 16], u32), String> {
    let rootdir = dir.join("rootdir");
    let _ = std::fs::remove_dir_all(&rootdir);
    for (path, len, compressible) in FIXTURE_FILES {
        let p = rootdir.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, fixture_bytes(len, compressible)).unwrap();
    }
    let pristine = dir.join("pristine.img");
    fixture::mkfs(
        &pristine,
        &rootdir,
        &fixture::MkfsSpec {
            uuid: "c4c405ee-0000-4a11-9e57-f5c109000001",
            size: 512 << 20,
            nodesize: 16384,
            csum: "crc32c",
            features: "block-group-tree,free-space-tree,no-holes",
        },
    )?;
    let _ = std::fs::remove_dir_all(&rootdir);
    linux::check(&pristine, true).map_err(|e| format!("pristine fixture: {e}"))?;
    let (fsid, nodesize, _) = dev::image_identity(&pristine);
    Ok((pristine, fsid, nodesize))
}

/// What judging one crashed image found.
#[derive(Default)]
pub struct Verdict {
    pub had_log: bool,
    pub entries: usize,
}

/// Replay `crashed` with Linux and with NARF, from separate copies, and
/// hold both to each other, to `btrfs check` and to the script's promises.
pub fn judge(
    ctx: &Ctx,
    what: &str,
    crashed: &Path,
    model: &ScriptModel,
) -> Result<Verdict, String> {
    let had_log = log_root_of(crashed) != 0;
    let vm = ctx.vm.ok_or("no Linux guest")?;
    let by_linux = ctx.dir.join(format!("{what}.linux.img"));
    let by_narf = ctx.dir.join(format!("{what}.narf.img"));
    linux::clone_file(crashed, &by_linux);
    linux::clone_file(crashed, &by_narf);

    // A real kernel replays the log.
    let lin = vm
        .mount_and_list(&by_linux)
        .map_err(|e| format!("{what}: Linux replay: {e}"))?;
    let complaints = lin.kernel_complaints();
    if !complaints.is_empty() {
        return Err(format!(
            "{what}: the Linux kernel complained while replaying:\n  {}",
            complaints.join("\n  ")
        ));
    }
    if log_root_of(&by_linux) != 0 {
        return Err(format!("{what}: log_root still set after Linux's mount"));
    }
    linux::check(&by_linux, true).map_err(|e| format!("{what}: after Linux replay: {e}"))?;

    // NARF replays the same log.
    let mounted = Mounted::mount(&by_narf, ctx.fsid, ctx.nodesize).map_err(|e| {
        format!(
            "{what}: NARF mount (replay): {e}\nklog:\n{}",
            crate::host::klog_take_filtered()
        )
    })?;
    let narf_listing = mounted.listing();
    mounted.unmount()?;
    let narf_listing = narf_listing.map_err(|e| format!("{what}: NARF after replay: {e}"))?;
    if log_root_of(&by_narf) != 0 {
        return Err(format!("{what}: log_root still set after NARF's mount"));
    }
    linux::check(&by_narf, true).map_err(|e| format!("{what}: after NARF replay: {e}"))?;

    let d = linuxvm::diff_listings(
        "Linux-replayed",
        &lin.listing,
        "NARF-replayed",
        &narf_listing,
        12,
    );
    if !d.is_empty() {
        linuxvm::save_listing(&ctx.dir.join(format!("{what}.linux.list")), &lin.listing);
        linuxvm::save_listing(&ctx.dir.join(format!("{what}.narf.list")), &narf_listing);
        return Err(format!(
            "{what}: Linux and NARF replayed the same log differently:\n  {}",
            d.join("\n  ")
        ));
    }
    let mut broken = model.check("Linux replay", &lin.listing);
    broken.extend(model.check("NARF replay", &narf_listing));
    if !broken.is_empty() {
        return Err(format!(
            "{what}: fsync promises broken:\n  {}",
            broken.join("\n  ")
        ));
    }

    // What NARF's replay committed must mount on Linux, unchanged.
    let again = vm
        .mount_and_list(&by_narf)
        .map_err(|e| format!("{what}: Linux mount of the NARF-replayed image: {e}"))?;
    let complaints = again.kernel_complaints();
    if !complaints.is_empty() {
        return Err(format!(
            "{what}: the Linux kernel complained about the NARF-replayed image:\n  {}",
            complaints.join("\n  ")
        ));
    }
    let d = linuxvm::diff_listings(
        "NARF-replayed",
        &narf_listing,
        "then-Linux",
        &again.listing,
        12,
    );
    if !d.is_empty() {
        return Err(format!(
            "{what}: Linux reads the NARF-replayed image differently:\n  {}",
            d.join("\n  ")
        ));
    }
    linux::check(&by_narf, true)
        .map_err(|e| format!("{what}: NARF-replayed image after a Linux mount: {e}"))?;
    let _ = std::fs::remove_file(&by_linux);
    let _ = std::fs::remove_file(&by_narf);
    Ok(Verdict {
        had_log,
        entries: narf_listing.len(),
    })
}

/// `fsync-linux` for one case: Linux writes the log and is killed.
fn linux_writes(ctx: &Ctx, vm: &Vm, case: &Case) -> Result<Verdict, String> {
    let what = format!("linux-{}", case.name);
    let crashed = ctx.dir.join(format!("{what}.crashed.img"));
    linux::clone_file(&ctx.pristine, &crashed);
    let mut model = ScriptModel::new();
    model.linux_wrote = true;
    for line in &case.script {
        if !model.apply(line) {
            break;
        }
    }
    let out = vm
        .run_script(&crashed, &case.script.join("\n"))
        .map_err(|e| format!("{what}: {e}"))?;
    if !out.crashed {
        return Err(format!("{what}: the guest did not stop at `crash`"));
    }
    let verdict = judge(ctx, &what, &crashed, &model)?;
    let _ = std::fs::remove_file(&crashed);
    Ok(verdict)
}

/// Locate the Linux guest or explain why the scenario is unverified.
pub fn locate_vm(args: &crate::Args, scenario: &str) -> Result<Option<Vm>, String> {
    match Vm::locate(&args.workdir.join("linuxvm")) {
        Ok(vm) => Ok(Some(vm)),
        Err(why) if args.require_linux => Err(format!(
            "{scenario}: no Linux guest and --require-linux given: {why}"
        )),
        Err(why) => {
            println!(
                "{scenario}: SKIPPED — UNVERIFIED, NOT A PASS: no Linux kernel could be booted to replay logs ({why})"
            );
            Ok(None)
        }
    }
}

/// The cases a run covers: the fixed ones plus `seeds` random scripts.
pub fn cases(args: &crate::Args) -> Vec<Case> {
    let mut all = fixed_cases();
    let random = if args.fsync_cases == 0 {
        args.seeds * 4
    } else {
        args.fsync_cases
    };
    all.extend((0..random).map(|i| random_case(args.seed + i)));
    if let Some(only) = &args.only_case {
        all.retain(|c| &c.name == only);
    }
    all
}

/// Scenario `fsync-linux`.
pub fn run_linux(args: &crate::Args) -> Result<String, String> {
    let t0 = std::time::Instant::now();
    let Some(vm) = locate_vm(args, "fsync-linux")? else {
        return Ok("fsync-linux: UNVERIFIED (skipped)".into());
    };
    let dir = args.workdir.join("fsync-linux");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (pristine, fsid, nodesize) = make_pristine(&dir)?;
    let ctx = Ctx {
        vm: Some(&vm),
        dir: dir.clone(),
        pristine,
        fsid,
        nodesize,
    };
    let all = cases(args);
    let (mut logs, mut failures) = (0, Vec::new());
    for case in &all {
        match linux_writes(&ctx, &vm, case) {
            Ok(v) => {
                logs += v.had_log as usize;
                if args.verbose {
                    println!(
                        "  fsync-linux {}: ok ({} entries, {})",
                        case.name,
                        v.entries,
                        if v.had_log {
                            "log replayed"
                        } else {
                            "no log on disk"
                        }
                    );
                }
            }
            Err(e) => {
                std::fs::write(
                    dir.join(format!("{}.script", case.name)),
                    case.script.join("\n"),
                )
                .unwrap();
                failures.push(e);
                narf::reset();
            }
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "{} of {} cases failed:\n{}",
            failures.len(),
            all.len(),
            failures.join("\n")
        ));
    }
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "fsync-linux: PASS in {:.1?} — {} — {} scripts, {} left a Linux-written log; each replayed by Linux and by NARF to identical trees, btrfs check --check-data-csum clean after both, NARF-replayed image mounted on Linux unchanged",
        t0.elapsed(),
        vm.describe(),
        all.len(),
        logs
    ))
}

// ── The Linux-written-log fixture of the kernel tests ──────────────

/// What Linux does before it is killed, in the fixture
/// `testdata/fixture-linuxlog.img.sparse`: one log holding every item
/// shape replay handles (new and partly rewritten extents with checksums,
/// truncation, an inline file grown out of its item, new directories, a
/// directory fsync after unlink + rename + create, a hard link, xattr
/// removal, a write into preallocated space).
const FIXTURE_SCRIPT: &str = "\
mkdir d
mkdir d/sub
write d/keep 0 12000 1
write d/gone 0 3000 2
write d/renamed-old 0 5000 3
write over 0 40000 4
write trunc 0 60000 5
write small 0 100 6
write linked 0 2000 7
write xa 0 1500 8
setxattr xa user.keep 20 9
setxattr xa user.drop 30 10
falloc pre 0 0 262144
sync
write new 0 20000 11
fsync new
write over 4096 8192 12
fsync over
truncate trunc 20001
fsync trunc
write small 100 9000 13
fsync small
mkdir nd
mkdir nd/deeper
write nd/deeper/f 0 4000 14
fsync nd/deeper/f
unlink d/gone
rename d/renamed-old d/renamed-new
write d/created 0 2500 15
fsyncdir d
link linked linked2
fsync linked
rmxattr xa user.drop
setxattr xa user.new 10 16
fsync xa
write pre 8192 20000 17
fsync pre
write tiny 0 300 18
fsync tiny
write unsynced 0 5000 19
crash
";

/// Write `img` as a `NARFBTR1` sparse fixture: runs of non-zero 4 KiB blocks.
fn write_sparse(img: &Path, out: &Path) -> Result<usize, String> {
    let data = std::fs::read(img).map_err(|e| format!("{}: {e}", img.display()))?;
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for (i, block) in data.chunks(4096).enumerate() {
        if block.iter().all(|&b| b == 0) {
            continue;
        }
        match runs.last_mut() {
            Some((start, len)) if *start + *len == i * 4096 => *len += block.len(),
            _ => runs.push((i * 4096, block.len())),
        }
    }
    let mut bytes = b"NARFBTR1".to_vec();
    bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(runs.len() as u32).to_le_bytes());
    for (start, len) in runs {
        bytes.extend_from_slice(&(start as u64).to_le_bytes());
        bytes.extend_from_slice(&(len as u64).to_le_bytes());
        bytes.extend_from_slice(&data[start..start + len]);
    }
    std::fs::write(out, &bytes).map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(bytes.len())
}

/// `--emit-linux-log-fixture OUT`: have Linux write the fixture's log, keep
/// the crashed image as `OUT`, and print what Linux's own replay of it
/// yields — the table the kernel test holds NARF's replay to.
pub fn emit_fixture(args: &crate::Args, out: &Path) -> Result<String, String> {
    let vm = Vm::locate(&args.workdir.join("linuxvm"))?;
    let dir = args.workdir.join("linuxlog-fixture");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join("fixture.img");
    let f = std::fs::File::create(&img).unwrap();
    f.set_len(128 << 20).unwrap();
    drop(f);
    let mk = std::process::Command::new("mkfs.btrfs")
        // Small nodes and single profiles keep the checked-in image small;
        // the scenarios cover 16 KiB nodes and DUP metadata.
        .args(["-q", "-f", "-n", "4096", "-s", "4096", "--csum", "crc32c"])
        .args(["-m", "single", "-d", "single"])
        .args([
            "-U",
            "c4c405ee-0000-4a11-9e57-f5c109f1c5e0",
            "-L",
            "narf-linuxlog",
        ])
        .arg(&img)
        .output()
        .map_err(|e| format!("mkfs.btrfs: {e}"))?;
    if !mk.status.success() {
        return Err(format!(
            "mkfs.btrfs: {}",
            String::from_utf8_lossy(&mk.stderr)
        ));
    }
    let ran = vm.run_script(&img, FIXTURE_SCRIPT)?;
    if !ran.crashed {
        return Err("the guest did not stop at `crash`".into());
    }
    if log_root_of(&img) == 0 {
        return Err("Linux left no log on the fixture".into());
    }
    let replayed = dir.join("replayed.img");
    linux::clone_file(&img, &replayed);
    let lin = vm.mount_and_list(&replayed)?;
    if !lin.kernel_complaints().is_empty() {
        return Err(format!("kernel complained: {:?}", lin.kernel_complaints()));
    }
    linux::check(&replayed, true)?;
    let size = write_sparse(&img, out)?;
    let mut table = String::new();
    for (path, e) in &lin.listing {
        table.push_str(&format!(
            "    (\"{path}\", '{}', {:#o}, {}, {}, {:#018x}),\n",
            e.kind, e.perms, e.nlink, e.size, e.hash
        ));
    }
    Ok(format!(
        "wrote {} ({size} bytes), log written by {}\nexpected after replay (path, kind, perms, nlink, size, fnv1a):\n{table}",
        out.display(),
        vm.describe()
    ))
}

// ── NARF writes the log ────────────────────────────────────────────

/// How NARF served the fsyncs of one stretch of work.
#[derive(Clone, Copy, Debug, Default)]
pub struct FsyncCost {
    pub logged: u64,
    pub clean: u64,
    pub committed: u64,
    pub superblocks: u64,
    pub commits: u64,
}

fn fsync_cost_now(dev: &RecDev) -> FsyncCost {
    let (logged, clean, committed) = narf_drivers_fs_btrfs::stats::fsync_counts();
    let log_roots = dev.sb_log_roots();
    FsyncCost {
        logged,
        clean,
        committed,
        superblocks: log_roots.len() as u64,
        commits: log_roots.iter().filter(|&&root| root == 0).count() as u64,
    }
}

impl FsyncCost {
    fn since(self, earlier: FsyncCost) -> FsyncCost {
        FsyncCost {
            logged: self.logged - earlier.logged,
            clean: self.clean - earlier.clean,
            committed: self.committed - earlier.committed,
            superblocks: self.superblocks - earlier.superblocks,
            commits: self.commits - earlier.commits,
        }
    }
}

/// One script run through NARF up to its `crash`.
struct NarfRun {
    /// The image as the crash left it.
    crashed: PathBuf,
    model: ScriptModel,
    /// What the part of the script after its last `sync` cost.
    cost: FsyncCost,
    /// The device requests of the whole script, when recorded.
    events: Vec<dev::Ev>,
    /// `events.len()` after each script line.
    marks: Vec<usize>,
}

/// Run `case` through NARF on a copy of the pristine image up to its
/// `crash`.
fn narf_runs(ctx: &Ctx, what: &str, case: &Case, record: bool) -> Result<NarfRun, String> {
    let work = ctx.dir.join(format!("{what}.work.img"));
    let crashed = ctx.dir.join(format!("{what}.crashed.img"));
    linux::clone_file(&ctx.pristine, &work);
    // The log path is off by default until it replaces the commit path;
    // these scenarios are what proves it, so they run with it on.
    narf_drivers_fs_btrfs::write::set_fsync_via_log(true);
    let mounted = Mounted::mount(&work, ctx.fsid, ctx.nodesize)?;
    let mut model = ScriptModel::new();
    let mut base = fsync_cost_now(&mounted.dev);
    // Log length after each script line, for the crash sweep.
    let mut marks = Vec::new();
    if record {
        // The sweep starts from the pristine image, so the mount's own
        // writes (none on a clean image) would have to be in the record.
        mounted.dev.set_recording(true);
    }
    let mut log_len = 0usize;
    let mut events: Vec<dev::Ev> = Vec::new();
    for line in &case.script {
        if !model.apply(line) {
            break;
        }
        mounted
            .run_line(line)
            .map_err(|e| format!("{what}: {e}\nklog:\n{}", crate::host::klog_take_filtered()))?;
        if line == "sync" {
            base = fsync_cost_now(&mounted.dev);
        }
        if record {
            let new = mounted.dev.take_log();
            log_len += new.len();
            events.extend(new);
            marks.push(log_len);
        }
    }
    let cost = fsync_cost_now(&mounted.dev).since(base);
    // The crash: whatever the device holds now, and nothing the driver
    // would still write on the way down.
    linux::clone_file(&work, &crashed);
    mounted.dev.set_recording(false);
    mounted.unmount()?;
    narf_drivers_fs_btrfs::write::set_fsync_via_log(false);
    let _ = std::fs::remove_file(&work);
    Ok(NarfRun {
        crashed,
        model,
        cost,
        events,
        marks,
    })
}

/// Scenario `fsync-narf`.
pub fn run_narf(args: &crate::Args) -> Result<String, String> {
    let t0 = std::time::Instant::now();
    let Some(vm) = locate_vm(args, "fsync-narf")? else {
        return Ok("fsync-narf: UNVERIFIED (skipped)".into());
    };
    let dir = args.workdir.join("fsync-narf");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (pristine, fsid, nodesize) = make_pristine(&dir)?;
    let ctx = Ctx {
        vm: Some(&vm),
        dir: dir.clone(),
        pristine,
        fsid,
        nodesize,
    };
    let all = cases(args);
    let (mut logs, mut failures) = (0, Vec::new());
    let mut total = FsyncCost::default();
    let mut burst = None;
    let fallbacks_before = narf_drivers_fs_btrfs::stats::fsync_fallbacks();
    for case in &all {
        let what = format!("narf-{}", case.name);
        let ran = narf_runs(&ctx, &what, case, false).and_then(|run| {
            let verdict = judge(&ctx, &what, &run.crashed, &run.model)?;
            let _ = std::fs::remove_file(&run.crashed);
            Ok((verdict, run.cost))
        });
        match ran {
            Ok((v, cost)) => {
                logs += v.had_log as usize;
                total.logged += cost.logged;
                total.clean += cost.clean;
                total.committed += cost.committed;
                if case.name == "temp-fsync-rename-burst" {
                    burst = Some(cost);
                }
                if args.verbose {
                    println!(
                        "  fsync-narf {}: ok ({} entries, {}; fsyncs: {} logged, {} committed, {} clean; {} superblock writes, {} commits)",
                        case.name,
                        v.entries,
                        if v.had_log { "log replayed" } else { "no log on disk" },
                        cost.logged,
                        cost.committed,
                        cost.clean,
                        cost.superblocks,
                        cost.commits
                    );
                }
            }
            Err(e) => {
                std::fs::write(
                    dir.join(format!("{}.script", case.name)),
                    case.script.join("\n"),
                )
                .unwrap();
                failures.push(e);
                narf::reset();
            }
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "{} of {} cases failed:\n{}",
            failures.len(),
            all.len(),
            failures.join("\n")
        ));
    }
    let why: Vec<String> = narf_drivers_fs_btrfs::stats::fsync_fallbacks()
        .into_iter()
        .map(|(reason, n)| {
            let before = fallbacks_before
                .iter()
                .find(|(r, _)| *r == reason)
                .map_or(0, |(_, n)| *n);
            (reason, n - before)
        })
        .filter(|&(_, n)| n != 0)
        .map(|(reason, n)| format!("{reason}: {n}"))
        .collect();
    if logs == 0 {
        return Err("no case left a NARF-written log: nothing was verified".into());
    }
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "fsync-narf: PASS in {:.1?} — {} — {} scripts, {} left a NARF-written log; each replayed by Linux and by NARF to identical trees, btrfs check --check-data-csum clean after both\n  fsyncs: {} through the log, {} by full commit ({}), {} with nothing to do\n  temp+fsync+rename burst of 60: {}",
        t0.elapsed(),
        vm.describe(),
        all.len(),
        logs,
        total.logged,
        total.committed,
        if why.is_empty() { "none".to_string() } else { why.join(", ") },
        total.clean,
        match burst {
            Some(b) => format!(
                "{} fsyncs logged, {} committed; {} superblock writes of which {} transaction commits",
                b.logged, b.committed, b.superblocks, b.commits
            ),
            None => "not run".into(),
        }
    ))
}

// ── Crash-point sweep ──────────────────────────────────────────────

/// The scripts the sweep cuts: short enough to cut at every write.
fn sweep_cases() -> Vec<Case> {
    let mut burst = String::new();
    for i in 0..10 {
        burst.push_str(&format!(
            "write @home/cfg{i} 0 {} {}\n",
            2000 + i * 37,
            100 + i
        ));
    }
    burst.push_str("sync\n");
    for i in 0..10 {
        burst.push_str(&format!(
            "write @home/cfg{i}.tmp 0 {} {}\nfsync @home/cfg{i}.tmp\nrename @home/cfg{i}.tmp @home/cfg{i}\n",
            3000 + i * 53,
            200 + i
        ));
    }
    burst.push_str("crash\n");
    vec![
        case("sweep-burst", &burst),
        case(
            "sweep-mixed",
            "write @/a 0 50000 1
             write @/t 0 300000 2
             write @/o 0 200000 3
             sync
             write @/a 50000 30000 4
             fsync @/a
             truncate @/t 100001
             fsync @/t
             write @/o 8192 20000 5
             fdatasync @/o
             mkdir @/nd
             mkdir @/nd/deep
             write @/nd/deep/f 0 9000 6
             fsync @/nd/deep/f
             write @home/h 0 70000 7
             fsync @home/h
             write @/a 0 100 8
             fsync @/a
             write @/unsynced 0 5000 9
             crash",
        ),
        case(
            "sweep-commit-boundaries",
            "write @/c1 0 40000 1
             fsync @/c1
             sync
             write @/c1 40000 40000 2
             write @/c2 0 40000 3
             fsync @/c2
             rename @/c2 @/c3
             fsync @/c3
             write @/c1 0 100 4
             fsync @/c1
             mkdir @/dd
             write @/dd/x 0 5000 5
             fsyncdir @/dd
             write @/dd/x 5000 5000 6
             fsync @/dd/x
             crash",
        ),
    ]
}

/// Scenario `fsync-sweep`.
pub fn run_sweep(args: &crate::Args) -> Result<String, String> {
    use std::os::unix::fs::FileExt;
    let t0 = std::time::Instant::now();
    let vm = locate_vm(args, "fsync-sweep (the Linux-replay sample)")?;
    let dir = args.workdir.join("fsync-sweep");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (pristine, fsid, nodesize) = make_pristine(&dir)?;
    // Without a guest only NARF's replay of each cut is checked.
    let (mut cuts_run, mut linux_run, mut with_log) = (0usize, 0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();
    for case in sweep_cases() {
        let ctx = Ctx {
            vm: vm.as_ref(),
            dir: dir.clone(),
            pristine: pristine.clone(),
            fsid,
            nodesize,
        };
        let what = case.name.clone();
        let run = narf_runs(&ctx, &what, &case, true)?;
        let _ = std::fs::remove_file(&run.crashed);
        let (events, marks) = (run.events, run.marks);
        // The model after each completed line.
        let mut models: Vec<ScriptModel> = Vec::new();
        let lines: Vec<&String> = case.script.iter().filter(|l| *l != "crash").collect();
        for upto in 0..=lines.len() {
            let mut m = ScriptModel::new();
            for line in &lines[..upto] {
                m.apply(line);
            }
            models.push(m);
        }
        // Cut points: every write when few, an even spread otherwise.
        let limit = if args.exhaustive {
            usize::MAX
        } else {
            args.cuts.max(1) * 4
        };
        let step = events.len().div_ceil(limit).max(1);
        let durable = dir.join(format!("{what}.durable.img"));
        linux::clone_file(&pristine, &durable);
        let dfile = std::fs::OpenOptions::new()
            .write(true)
            .open(&durable)
            .unwrap();
        let mut applied = 0usize;
        let mut cut = 0usize;
        while cut <= events.len() {
            // Bring the durable image up to `cut` events.
            for ev in &events[applied..cut] {
                if let dev::Ev::Write { off, data, .. } = ev {
                    dfile.write_all_at(data, *off).unwrap();
                }
            }
            applied = cut;
            // Lines whose every write is in the prefix have returned.
            let done = marks.iter().take_while(|&&m| m <= cut).count();
            for drop_unflushed in [false, true] {
                let img = dir.join(format!("{what}.cut{cut}.{}.img", drop_unflushed as u8));
                linux::clone_file(&durable, &img);
                if drop_unflushed {
                    // A volatile write cache: everything since the last
                    // flush that was not written FUA is lost. Rebuild from
                    // the pristine image with only the durable writes.
                    let last_flush = events[..cut]
                        .iter()
                        .rposition(|e| matches!(e, dev::Ev::Flush))
                        .unwrap_or(0);
                    if events[last_flush..cut]
                        .iter()
                        .all(|e| !matches!(e, dev::Ev::Write { fua: false, .. }))
                    {
                        let _ = std::fs::remove_file(&img);
                        continue; // identical to the other variant
                    }
                    linux::clone_file(&pristine, &img);
                    let f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
                    for (i, ev) in events[..cut].iter().enumerate() {
                        if let dev::Ev::Write { off, data, fua } = ev {
                            if i < last_flush || *fua {
                                f.write_all_at(data, *off).unwrap();
                            }
                        }
                    }
                }
                cuts_run += 1;
                with_log += (log_root_of(&img) != 0) as usize;
                let name = format!(
                    "{what} cut {cut}/{} ({})",
                    events.len(),
                    if drop_unflushed {
                        "unflushed writes lost"
                    } else {
                        "all writes kept"
                    }
                );
                // With unflushed writes lost, an fsync counts as returned
                // only if its last write (the FUA superblock) survived,
                // which the `done` count already reflects: every line's
                // writes end with a flush or FUA write when it promised
                // durability.
                let sample_linux = vm.is_some() && !drop_unflushed && (cut / step) % 8 == 0;
                match sweep_one(
                    &ctx,
                    &name,
                    &img,
                    &models[done],
                    models.get(done + 1),
                    sample_linux,
                ) {
                    Ok(()) => {
                        linux_run += sample_linux as usize;
                        let _ = std::fs::remove_file(&img);
                    }
                    Err(e) => {
                        failures.push(e);
                        narf::reset();
                    }
                }
                if failures.len() >= 5 {
                    return Err(format!(
                        "fsync-sweep: stopping after 5 failures:\n{}",
                        failures.join("\n")
                    ));
                }
            }
            if cut == events.len() {
                break;
            }
            cut = (cut + step).min(events.len());
        }
        let _ = std::fs::remove_file(&durable);
    }
    if !failures.is_empty() {
        return Err(failures.join("\n"));
    }
    if with_log == 0 {
        return Err("no cut image carried a log: the sweep proved nothing".into());
    }
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "fsync-sweep: PASS in {:.1?} — {} crash images ({} carrying a log): each replayed by NARF keeping every fsync that had returned, btrfs check --check-data-csum clean after replay; {}",
        t0.elapsed(),
        cuts_run,
        with_log,
        match &vm {
            Some(vm) => format!(
                "{linux_run} of them also replayed by {} to the identical tree",
                vm.describe()
            ),
            None => "Linux replay of the sample UNVERIFIED (no guest)".into(),
        }
    ))
}

/// One cut image: NARF replays it; the fsyncs that had returned hold;
/// `btrfs check` is clean; optionally Linux replays a second copy to the
/// same tree.
fn sweep_one(
    ctx: &Ctx,
    what: &str,
    img: &Path,
    model: &ScriptModel,
    next: Option<&ScriptModel>,
    with_linux: bool,
) -> Result<(), String> {
    if with_linux {
        let slug: String = what
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        // The line in flight may have become durable through a commit it
        // forced; then the tree matches the model after it.
        return match judge(ctx, &slug, img, model) {
            Ok(_) => Ok(()),
            Err(first) => match next {
                Some(next) => judge(ctx, &slug, img, next).map(|_| ()).map_err(|_| first),
                None => Err(first),
            },
        };
    }
    let by_narf = img.with_extension("replayed.img");
    linux::clone_file(img, &by_narf);
    let mounted = Mounted::mount(&by_narf, ctx.fsid, ctx.nodesize).map_err(|e| {
        format!(
            "{what}: NARF mount (replay): {e}\nklog:\n{}",
            crate::host::klog_take_filtered()
        )
    })?;
    let listing = mounted.listing();
    mounted.unmount()?;
    let listing = listing.map_err(|e| format!("{what}: NARF after replay: {e}"))?;
    if log_root_of(&by_narf) != 0 {
        return Err(format!("{what}: log_root still set after NARF's mount"));
    }
    linux::check(&by_narf, true).map_err(|e| format!("{what}: after NARF replay: {e}"))?;
    let broken = model.check("NARF replay", &listing);
    if !broken.is_empty() {
        let also = next.map(|n| n.check("NARF replay", &listing));
        if also.is_none_or(|b| !b.is_empty()) {
            return Err(format!(
                "{what}: fsync promises broken:\n  {}",
                broken.join("\n  ")
            ));
        }
    }
    let _ = std::fs::remove_file(&by_narf);
    Ok(())
}
