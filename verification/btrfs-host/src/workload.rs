//! Seeded random namespace/data workload against mounted NARF subvolumes,
//! mirrored op-for-op into a [`Model`].

use std::collections::BTreeMap;
use std::sync::Arc;

use narf_filesystem::{DirOps, FileOps, FsError};

use crate::dev::RecDev;
use crate::host::block_on;
use crate::model::{FlatTree, Inode, Kind, Model, ROOT};
use crate::narf::{dir_at, file_at, split};

/// SplitMix64: tiny, seedable, good enough for workload choices.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (`n > 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }
    pub fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> Option<&'a T> {
        if v.is_empty() {
            None
        } else {
            Some(&v[self.below(v.len() as u64) as usize])
        }
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Data of `len` bytes: incompressible, text-like compressible, or a
/// repeating short pattern (each exercises a different extent shape once the
/// mount compresses).
pub fn gen_data(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    match rng.below(3) {
        0 => rng.fill(&mut v),
        1 => {
            let mut s = String::with_capacity(len + 64);
            let tag = rng.next() % 1000;
            let mut i = 0u64;
            while s.len() < len {
                s.push_str(&format!(
                    "line {i} of generated text {tag}: lorem ipsum dolor sit amet\n"
                ));
                i += 1;
            }
            v.copy_from_slice(&s.as_bytes()[..len]);
        }
        _ => {
            let b = (rng.next() & 0xff) as u8;
            for (i, x) in v.iter_mut().enumerate() {
                *x = b.wrapping_add((i / 512) as u8);
            }
        }
    }
    v
}

/// One mounted subvolume being exercised.
pub struct Sub {
    pub name: String,
    pub root: Arc<dyn DirOps>,
    pub model: Model,
    /// Nested subvolumes under this one (never touched by the workload).
    pub nested: Vec<String>,
}

/// A commit the device saw while the workload ran, with the model states it
/// may hold (the state before and after the operation it happened in).
#[derive(Clone, Debug)]
pub struct CommitRec {
    pub gen: u64,
    /// Per candidate: one flattened tree per subvolume, in `subs` order.
    pub candidates: Vec<Vec<FlatTree>>,
}

#[derive(Clone, Debug)]
pub struct Params {
    pub ops: usize,
    /// Cap on modelled file bytes (keeps the image from filling).
    pub data_budget: usize,
    /// Size of the biggest file a "large file" burst writes.
    pub large_file: usize,
    /// Files in a "many small files" burst.
    pub burst: usize,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub ops: BTreeMap<&'static str, usize>,
    pub bytes_written: u64,
    pub commits: usize,
}

pub struct Workload<'a> {
    pub subs: Vec<Sub>,
    pub dev: &'a RecDev,
    pub rng: Rng,
    pub stats: Stats,
    pub commits: Vec<CommitRec>,
    seen_sb: usize,
    queue: Vec<Op>,
    name_seq: u64,
    pub trace: Vec<String>,
}

/// A primitive operation (bursts expand into many of these).
#[derive(Clone, Debug)]
pub enum Op {
    Create {
        sub: usize,
        dir: String,
        name: String,
        len: usize,
        perms: u16,
    },
    /// `open(O_CREAT)` alone; [`Op::Create`] is that, `fchmod` and `write`,
    /// each its own step (a commit can land between them).
    CreateEmpty {
        sub: usize,
        dir: String,
        name: String,
    },
    WriteAt {
        sub: usize,
        path: String,
        off: u64,
        len: usize,
    },
    Append {
        sub: usize,
        path: String,
        len: usize,
    },
    Truncate {
        sub: usize,
        path: String,
        len: u64,
    },
    Fallocate {
        sub: usize,
        path: String,
        mode: u32,
        off: u64,
        len: u64,
    },
    Rename {
        sub: usize,
        from: String,
        to: String,
    },
    Unlink {
        sub: usize,
        path: String,
    },
    Mkdir {
        sub: usize,
        path: String,
    },
    Rmdir {
        sub: usize,
        path: String,
    },
    Chmod {
        sub: usize,
        path: String,
        perms: u16,
    },
    Link {
        sub: usize,
        from: String,
        to: String,
    },
    Symlink {
        sub: usize,
        path: String,
        target: String,
    },
    SetXattr {
        sub: usize,
        path: String,
        name: String,
        len: usize,
    },
    RemoveXattr {
        sub: usize,
        path: String,
        name: String,
    },
    Fsync {
        sub: usize,
        path: String,
    },
    Sync {
        sub: usize,
    },
}

impl Op {
    fn kind(&self) -> &'static str {
        match self {
            Op::Create { .. } => "create",
            Op::CreateEmpty { .. } => "create-empty",
            Op::WriteAt { .. } => "write",
            Op::Append { .. } => "append",
            Op::Truncate { .. } => "truncate",
            Op::Fallocate { .. } => "fallocate",
            Op::Rename { .. } => "rename",
            Op::Unlink { .. } => "unlink",
            Op::Mkdir { .. } => "mkdir",
            Op::Rmdir { .. } => "rmdir",
            Op::Chmod { .. } => "chmod",
            Op::Link { .. } => "link",
            Op::Symlink { .. } => "symlink",
            Op::SetXattr { .. } => "setxattr",
            Op::RemoveXattr { .. } => "removexattr",
            Op::Fsync { .. } => "fsync",
            Op::Sync { .. } => "sync",
        }
    }
    /// The path a creating op makes, which must not exist yet.
    fn creates(&self) -> Option<(usize, String)> {
        match self {
            Op::Create { sub, dir, name, .. } | Op::CreateEmpty { sub, dir, name } => {
                Some((*sub, join(dir, name)))
            }
            Op::Mkdir { sub, path }
            | Op::Symlink { sub, path, .. }
            | Op::Link { sub, to: path, .. } => Some((*sub, path.clone())),
            _ => None,
        }
    }
    fn is_sync(&self) -> bool {
        matches!(self, Op::Fsync { .. } | Op::Sync { .. })
    }
}

const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

impl<'a> Workload<'a> {
    pub fn new(subs: Vec<Sub>, dev: &'a RecDev, seed: u64) -> Self {
        let seen_sb = dev.sb_count();
        Workload {
            subs,
            dev,
            rng: Rng::new(seed),
            stats: Stats::default(),
            commits: Vec::new(),
            seen_sb,
            queue: Vec::new(),
            name_seq: 0,
            trace: Vec::new(),
        }
    }

    fn flats(&self) -> Vec<FlatTree> {
        self.subs.iter().map(|s| s.model.flatten()).collect()
    }

    /// Attribute commits the device saw since the last call to the states
    /// `before` (and the current one).
    pub fn note_commits(&mut self, before: Option<Vec<FlatTree>>) {
        let gens = self.dev.sb_gens();
        if gens.len() == self.seen_sb {
            return;
        }
        let now = self.flats();
        let mut candidates = vec![now.clone()];
        if let Some(b) = before {
            if b != now {
                candidates.push(b);
            }
        }
        for &gen in &gens[self.seen_sb..] {
            self.commits.push(CommitRec {
                gen,
                candidates: candidates.clone(),
            });
            self.stats.commits += 1;
        }
        self.seen_sb = gens.len();
    }

    fn fresh_name(&mut self, prefix: &str) -> String {
        self.name_seq += 1;
        // Mix lengths so directory items differ in size (up to the 255 max).
        let pad = match self.rng.below(10) {
            0 => "x".repeat(self.rng.range(40, 200) as usize),
            1..=3 => format!("-{:x}", self.rng.next()),
            _ => String::new(),
        };
        // `_` keeps workload names apart from every fixture's (`f93`).
        format!("{prefix}_{}{pad}", self.name_seq)
    }

    fn total_bytes(&self) -> usize {
        self.subs
            .iter()
            .flat_map(|s| s.model.inodes.values())
            .map(|i| match &i.kind {
                Kind::File(d) => d.len(),
                _ => 0,
            })
            .sum()
    }

    fn paths(&self, sub: usize, want: fn(&Kind) -> bool) -> Vec<String> {
        let m = &self.subs[sub].model;
        m.walk()
            .into_iter()
            .filter(|(_, ino)| want(&m.get(*ino).kind))
            .map(|(p, _)| p)
            .collect()
    }

    fn dirs(&self, sub: usize) -> Vec<String> {
        let mut d = self.paths(sub, |k| matches!(k, Kind::Dir(_)));
        d.push(String::new());
        d
    }

    fn files(&self, sub: usize) -> Vec<String> {
        self.paths(sub, |k| matches!(k, Kind::File(_)))
    }

    /// Choose the next primitive op (expanding a burst when one is due).
    fn plan(&mut self, p: &Params) -> Option<Op> {
        if let Some(op) = self.queue.pop() {
            return Some(op);
        }
        let sub = if self.subs.len() > 1 && self.rng.chance(30) {
            1 + self.rng.below(self.subs.len() as u64 - 1) as usize
        } else {
            0
        };
        let over_budget = self.total_bytes() > p.data_budget;
        let r = self.rng.below(1000);
        let dirs = self.dirs(sub);
        let files = self.files(sub);
        let rng = &mut self.rng;
        let op = match r {
            // Many small files in one fresh directory: leaf splits, a taller
            // tree; queued in reverse (pop order).
            0..=2 if !over_budget => {
                let base = rng.pick(&dirs).unwrap().clone();
                self.name_seq += 1;
                let dir = join(&base, &format!("burst{}", self.name_seq));
                let n = rng.range(p.burst as u64 / 2, p.burst as u64) as usize;
                let mut ops = vec![Op::Mkdir {
                    sub,
                    path: dir.clone(),
                }];
                for i in 0..n {
                    let len = rng.below(1500) as usize;
                    ops.push(Op::Create {
                        sub,
                        dir: dir.clone(),
                        name: format!("small-{i:05}"),
                        len,
                        perms: 0o644,
                    });
                }
                ops.push(Op::Sync { sub });
                ops.reverse();
                self.queue = ops;
                return self.queue.pop();
            }
            // Delete most of a burst directory: leaf merges / tree shrinking.
            3..=7 => {
                let bursts: Vec<String> = dirs
                    .iter()
                    .filter(|d| d.contains("burst"))
                    .cloned()
                    .collect();
                let Some(dir) = rng.pick(&bursts).cloned() else {
                    return Some(Op::Sync { sub });
                };
                let m = &self.subs[sub].model;
                let ino = m.lookup(&dir).unwrap();
                let names: Vec<String> = m
                    .entries(ino)
                    .iter()
                    .filter(|(_, &c)| matches!(m.get(c).kind, Kind::File(_) | Kind::Symlink(_)))
                    .map(|(n, _)| n.clone())
                    .collect();
                let mut ops: Vec<Op> = names
                    .iter()
                    .filter(|_| self.rng.chance(85))
                    .map(|n| Op::Unlink {
                        sub,
                        path: join(&dir, n),
                    })
                    .collect();
                ops.push(Op::Sync { sub });
                ops.reverse();
                self.queue = ops;
                return self.queue.pop();
            }
            // A large file in 1 MiB writes: data chunk growth.
            8..=17 if !over_budget => {
                let dir = rng.pick(&dirs).unwrap().clone();
                self.name_seq += 1;
                let name = format!("large{}.bin", self.name_seq);
                let total = rng.range(p.large_file as u64 / 4, p.large_file as u64) as usize;
                let path = join(&dir, &name);
                let mut ops = vec![Op::Create {
                    sub,
                    dir,
                    name,
                    len: 0,
                    perms: 0o600,
                }];
                let mut off = 0;
                while off < total {
                    let len = (total - off).min(1 << 20);
                    ops.push(Op::Append {
                        sub,
                        path: path.clone(),
                        len,
                    });
                    off += len;
                }
                if rng.chance(50) {
                    ops.push(Op::Fsync { sub, path });
                }
                ops.reverse();
                self.queue = ops;
                return self.queue.pop();
            }
            18..=169 if !over_budget => {
                let dir = rng.pick(&dirs).unwrap().clone();
                let name = self.fresh_name("f");
                let rng = &mut self.rng;
                let len = match rng.below(10) {
                    0..=4 => rng.below(2049) as usize,        // inline
                    5..=7 => rng.range(2049, 65536) as usize, // a few extents
                    8 => rng.range(65536, 600_000) as usize,
                    _ => 0,
                };
                let perms = *rng.pick(&[0o644u16, 0o600, 0o755, 0o640, 0o444]).unwrap();
                Op::Create {
                    sub,
                    dir,
                    name,
                    len,
                    perms,
                }
            }
            170..=299 => {
                let path = rng.pick(&files)?.clone();
                let size = self.size_of(sub, &path);
                let rng = &mut self.rng;
                let off = rng.below(size as u64 + 65536);
                let len = match rng.below(4) {
                    0 => rng.range(1, 512),
                    1 => rng.range(1, 4096),
                    2 => 4096 * rng.range(1, 8),
                    _ => rng.range(1, 131072),
                } as usize;
                if over_budget && off + len as u64 > size as u64 {
                    Op::WriteAt {
                        sub,
                        path,
                        off: 0,
                        len: len.min(size),
                    }
                } else {
                    Op::WriteAt {
                        sub,
                        path,
                        off,
                        len,
                    }
                }
            }
            300..=369 if !over_budget => {
                let path = rng.pick(&files)?.clone();
                let len = rng.range(1, 70000) as usize;
                Op::Append { sub, path, len }
            }
            370..=429 => {
                let path = rng.pick(&files)?.clone();
                let size = self.size_of(sub, &path) as u64;
                let rng = &mut self.rng;
                let len = if rng.chance(60) || over_budget {
                    rng.below(size + 1)
                } else {
                    size + rng.range(1, 300_000)
                };
                Op::Truncate { sub, path, len }
            }
            430..=469 => {
                let path = rng.pick(&files)?.clone();
                let size = self.size_of(sub, &path) as u64;
                let rng = &mut self.rng;
                match rng.below(3) {
                    0 if !over_budget => Op::Fallocate {
                        sub,
                        path,
                        mode: 0,
                        off: rng.below(size + 8192),
                        len: rng.range(1, 262_144),
                    },
                    1 => Op::Fallocate {
                        sub,
                        path,
                        mode: FALLOC_FL_KEEP_SIZE,
                        off: rng.below(size + 8192),
                        len: rng.range(1, 131_072),
                    },
                    _ => {
                        if size == 0 {
                            return Some(Op::Sync { sub });
                        }
                        let off = rng.below(size);
                        Op::Fallocate {
                            sub,
                            path,
                            mode: FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                            off,
                            len: rng.range(1, size - off),
                        }
                    }
                }
            }
            470..=569 => self.plan_rename(sub)?,
            570..=629 => {
                let all = self.paths(sub, |k| !matches!(k, Kind::Dir(_)));
                Op::Unlink {
                    sub,
                    path: self.rng.pick(&all)?.clone(),
                }
            }
            630..=669 => {
                let dir = rng.pick(&dirs).unwrap().clone();
                let name = self.fresh_name("d");
                Op::Mkdir {
                    sub,
                    path: join(&dir, &name),
                }
            }
            670..=689 => {
                let m = &self.subs[sub].model;
                let empty: Vec<String> = dirs
                    .iter()
                    .filter(|d| !d.is_empty())
                    .filter(|d| m.entries(m.lookup(d).unwrap()).is_empty())
                    .cloned()
                    .collect();
                Op::Rmdir {
                    sub,
                    path: self.rng.pick(&empty)?.clone(),
                }
            }
            690..=729 => {
                let path = rng.pick(&files)?.clone();
                let perms = *rng
                    .pick(&[0o644u16, 0o600, 0o755, 0o700, 0o444, 0o640, 0o4755])
                    .unwrap();
                // Set-id bits are not round-tripped by every reader; keep 0o777.
                Op::Chmod {
                    sub,
                    path,
                    perms: perms & 0o777,
                }
            }
            730..=779 => {
                let from = rng.pick(&files)?.clone();
                let dir = rng.pick(&dirs).unwrap().clone();
                let name = self.fresh_name("hl");
                Op::Link {
                    sub,
                    from,
                    to: join(&dir, &name),
                }
            }
            780..=819 => {
                let dir = rng.pick(&dirs).unwrap().clone();
                let name = self.fresh_name("sl");
                let rng = &mut self.rng;
                let target = match rng.below(3) {
                    0 => rng
                        .pick(&files)
                        .cloned()
                        .unwrap_or_else(|| "missing".into()),
                    1 => format!("/usr/lib/libfoo.so.{}", rng.below(10)),
                    _ => {
                        "../".repeat(rng.below(3) as usize)
                            + "x".repeat(rng.range(1, 300) as usize).as_str()
                    }
                };
                Op::Symlink {
                    sub,
                    path: join(&dir, &name),
                    target,
                }
            }
            820..=869 => {
                let path = rng.pick(&files)?.clone();
                let name = format!("user.narf{}", rng.below(4));
                if rng.chance(25) {
                    Op::RemoveXattr { sub, path, name }
                } else {
                    let len = if rng.chance(80) {
                        rng.range(0, 64)
                    } else {
                        rng.range(64, 3000)
                    } as usize;
                    Op::SetXattr {
                        sub,
                        path,
                        name,
                        len,
                    }
                }
            }
            870..=919 => {
                let path = rng.pick(&files)?.clone();
                Op::Fsync { sub, path }
            }
            920..=959 => Op::Sync { sub },
            _ => {
                let path = rng.pick(&files)?.clone();
                let len = self.rng.range(1, 4096) as usize;
                Op::WriteAt {
                    sub,
                    path,
                    off: 0,
                    len,
                }
            }
        };
        Some(op)
    }

    fn plan_rename(&mut self, sub: usize) -> Option<Op> {
        let dirs = self.dirs(sub);
        let m = &self.subs[sub].model;
        let all: Vec<(String, u64)> = m.walk();
        let (from, from_ino) = self.rng.pick(&all)?.clone();
        let is_dir = matches!(m.get(from_ino).kind, Kind::Dir(_));
        // Destination directory: not the source itself or inside it.
        let dests: Vec<String> = dirs
            .into_iter()
            .filter(|d| !is_dir || (d != &from && !d.starts_with(&format!("{from}/"))))
            .collect();
        let dest_dir = self.rng.pick(&dests)?.clone();
        let m = &self.subs[sub].model;
        let dest_ino = m.lookup(&dest_dir).unwrap();
        // Overwrite an existing non-directory entry sometimes (file over file).
        let victims: Vec<(String, u64)> = m
            .entries(dest_ino)
            .iter()
            .filter(|(_, &c)| !matches!(m.get(c).kind, Kind::Dir(_)) && c != from_ino)
            .map(|(n, &c)| (n.clone(), c))
            .collect();
        let to = if !is_dir && !victims.is_empty() && self.rng.chance(30) {
            join(&dest_dir, &self.rng.pick(&victims).unwrap().0)
        } else {
            let n = self.fresh_name("r");
            join(&dest_dir, &n)
        };
        if to == from {
            return None;
        }
        Some(Op::Rename { sub, from, to })
    }

    fn size_of(&self, sub: usize, path: &str) -> usize {
        let m = &self.subs[sub].model;
        match &m.get(m.lookup(path).unwrap()).kind {
            Kind::File(d) => d.len(),
            _ => 0,
        }
    }

    /// Run a fixed op list (the regression cases), ending on a commit.
    pub fn run_script(&mut self, ops: Vec<Op>) -> Result<(), String> {
        for op in ops {
            self.apply(op)?;
        }
        self.apply(Op::Sync { sub: 0 })
    }

    /// Run `p.ops` operations; stops at the first NARF error.
    pub fn run(&mut self, p: &Params) -> Result<(), String> {
        let mut done = 0;
        let mut misses = 0;
        while done < p.ops {
            let Some(op) = self.plan(p) else {
                misses += 1;
                if misses > 10_000 {
                    return Err("workload could not plan an operation".into());
                }
                continue;
            };
            self.apply(op)?;
            done += 1;
        }
        // End on a commit, as a shutdown does.
        self.apply(Op::Sync { sub: 0 })?;
        Ok(())
    }

    /// Perform `op` on NARF, then mirror it into the model.
    fn apply(&mut self, op: Op) -> Result<(), String> {
        if let Op::Create {
            sub,
            dir,
            name,
            len,
            perms,
        } = op
        {
            *self.stats.ops.entry("create").or_default() += 1;
            let path = join(&dir, &name);
            self.apply(Op::CreateEmpty { sub, dir, name })?;
            self.apply(Op::Chmod {
                sub,
                path: path.clone(),
                perms,
            })?;
            if len > 0 {
                self.apply(Op::WriteAt {
                    sub,
                    path,
                    off: 0,
                    len,
                })?;
            }
            return Ok(());
        }
        if let Some((sub, path)) = op.creates() {
            // Never "create" over an existing name (O_EXCL semantics).
            if self.subs[sub].model.lookup(&path).is_some() {
                return Ok(());
            }
        }
        let line = format!("{op:?}");
        let short: String = line.chars().take(200).collect();
        self.trace.push(short.clone());
        let before = if op.is_sync() {
            None
        } else {
            Some(self.flats())
        };
        *self.stats.ops.entry(op.kind()).or_default() += 1;
        let r = self.apply_inner(op);
        self.note_commits(before);
        r.map_err(|e| {
            format!(
                "op #{} {short} failed: {e}\nklog tail:\n{}",
                self.trace.len(),
                tail(&crate::host::klog_take_filtered(), 40)
            )
        })
    }

    fn apply_inner(&mut self, op: Op) -> Result<(), String> {
        let e = |what: &str, err: FsError| format!("{what}: {err:?}");
        match op {
            Op::Create { .. } => unreachable!("expanded by apply"),
            Op::CreateEmpty { sub, dir, name } => {
                let root = self.subs[sub].root.clone();
                let perms = block_on(async {
                    let d = dir_at(&root, &dir).await?;
                    let f = d.create(&name).await?;
                    Ok::<_, FsError>(f.stat().mode.perms)
                })
                .map_err(|x| e("create", x))?;
                let m = &mut self.subs[sub].model;
                let ino = m.alloc(Inode {
                    kind: Kind::File(Arc::new(Vec::new())),
                    perms,
                    xattrs: BTreeMap::new(),
                });
                let d = m.lookup(&dir).unwrap();
                m.entries_mut(d).insert(name, ino);
            }
            Op::WriteAt {
                sub,
                path,
                off,
                len,
            } => {
                let data = gen_data(&mut self.rng, len);
                let data = self.narf_file(sub, &path, |f| async move {
                    write_full(&f, off, &data).await.map(|_| data)
                })?;
                self.stats.bytes_written += len as u64;
                self.with_file(sub, &path, |v| {
                    let end = off as usize + data.len();
                    if v.len() < end {
                        v.resize(end, 0);
                    }
                    v[off as usize..end].copy_from_slice(&data);
                });
            }
            Op::Append { sub, path, len } => {
                let off = self.size_of(sub, &path) as u64;
                return self.apply_inner(Op::WriteAt {
                    sub,
                    path,
                    off,
                    len,
                });
            }
            Op::Truncate { sub, path, len } => {
                self.narf_file(sub, &path, |f| async move { f.truncate(len).await })?;
                self.with_file(sub, &path, |v| v.resize(len as usize, 0));
            }
            Op::Fallocate {
                sub,
                path,
                mode,
                off,
                len,
            } => {
                self.narf_file(
                    sub,
                    &path,
                    |f| async move { f.fallocate(mode, off, len).await },
                )?;
                self.with_file(sub, &path, |v| {
                    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
                        let end = ((off + len) as usize).min(v.len());
                        if (off as usize) < end {
                            v[off as usize..end].fill(0);
                        }
                    } else if mode & FALLOC_FL_KEEP_SIZE == 0 {
                        let end = (off + len) as usize;
                        if v.len() < end {
                            v.resize(end, 0);
                        }
                    }
                });
            }
            Op::Rename { sub, from, to } => {
                let root = self.subs[sub].root.clone();
                let (fp, fname) = split(&from);
                let (tp, tname) = split(&to);
                block_on(async {
                    let fd = dir_at(&root, fp).await?;
                    let td = dir_at(&root, tp).await?;
                    fd.rename_to(fname, &*td, tname, 0).await
                })
                .map_err(|x| e("rename", x))?;
                let m = &mut self.subs[sub].model;
                let fdi = m.lookup(fp).unwrap();
                let tdi = m.lookup(tp).unwrap();
                let ino = m.entries_mut(fdi).remove(fname).unwrap();
                if let Some(old) = m.entries_mut(tdi).insert(tname.to_string(), ino) {
                    m.gc(old);
                }
            }
            Op::Unlink { sub, path } => {
                let root = self.subs[sub].root.clone();
                let (p, n) = split(&path);
                block_on(async { dir_at(&root, p).await?.unlink(n).await })
                    .map_err(|x| e("unlink", x))?;
                let m = &mut self.subs[sub].model;
                let d = m.lookup(p).unwrap();
                let ino = m.entries_mut(d).remove(n).unwrap();
                m.gc(ino);
            }
            Op::Mkdir { sub, path } => {
                let root = self.subs[sub].root.clone();
                let (p, n) = split(&path);
                let perms = block_on(async {
                    Ok::<_, FsError>(dir_at(&root, p).await?.mkdir(n).await?.dir_mode())
                })
                .map_err(|x| e("mkdir", x))?;
                let m = &mut self.subs[sub].model;
                let ino = m.alloc(Inode {
                    kind: Kind::Dir(BTreeMap::new()),
                    perms,
                    xattrs: BTreeMap::new(),
                });
                let d = m.lookup(p).unwrap();
                m.entries_mut(d).insert(n.to_string(), ino);
            }
            Op::Rmdir { sub, path } => {
                let root = self.subs[sub].root.clone();
                let (p, n) = split(&path);
                block_on(async { dir_at(&root, p).await?.rmdir(n).await })
                    .map_err(|x| e("rmdir", x))?;
                let m = &mut self.subs[sub].model;
                let d = m.lookup(p).unwrap();
                let ino = m.entries_mut(d).remove(n).unwrap();
                m.gc(ino);
            }
            Op::Chmod { sub, path, perms } => {
                self.narf_file(sub, &path, |f| async move { f.set_perms(perms).await })?;
                let m = &mut self.subs[sub].model;
                let ino = m.lookup(&path).unwrap();
                m.get_mut(ino).perms = perms;
            }
            Op::Link { sub, from, to } => {
                let root = self.subs[sub].root.clone();
                let (fp, fname) = split(&from);
                let (tp, tname) = split(&to);
                block_on(async {
                    let fd = dir_at(&root, fp).await?;
                    let td = dir_at(&root, tp).await?;
                    fd.link_to(fname, &*td, tname).await
                })
                .map_err(|x| e("link", x))?;
                let m = &mut self.subs[sub].model;
                let ino = m.lookup(&from).unwrap();
                let tdi = m.lookup(tp).unwrap();
                m.entries_mut(tdi).insert(tname.to_string(), ino);
            }
            Op::Symlink { sub, path, target } => {
                let root = self.subs[sub].root.clone();
                let (p, n) = split(&path);
                block_on(async {
                    dir_at(&root, p)
                        .await?
                        .symlink(n, &target)
                        .await
                        .map(|_| ())
                })
                .map_err(|x| e("symlink", x))?;
                let m = &mut self.subs[sub].model;
                let ino = m.alloc(Inode {
                    kind: Kind::Symlink(target),
                    perms: 0o777,
                    xattrs: BTreeMap::new(),
                });
                let d = m.lookup(p).unwrap();
                m.entries_mut(d).insert(n.to_string(), ino);
            }
            Op::SetXattr {
                sub,
                path,
                name,
                len,
            } => {
                let mut value = vec![0u8; len];
                self.rng.fill(&mut value);
                let v2 = value.clone();
                let n2 = name.clone();
                self.narf_file(
                    sub,
                    &path,
                    |f| async move { f.set_xattr(&n2, &v2, 0).await },
                )?;
                let m = &mut self.subs[sub].model;
                let ino = m.lookup(&path).unwrap();
                m.get_mut(ino).xattrs.insert(name, value);
            }
            Op::RemoveXattr { sub, path, name } => {
                let m = &self.subs[sub].model;
                let ino = m.lookup(&path).unwrap();
                let present = m.get(ino).xattrs.contains_key(&name);
                let n2 = name.clone();
                let r = block_on(async {
                    let f = file_at(&self.subs[sub].root, &path).await?;
                    f.remove_xattr(&n2).await
                });
                match (r, present) {
                    (Ok(()), true) => {}
                    (Err(FsError::NotFound), false) => {}
                    (r, _) => return Err(format!("removexattr (present={present}): {r:?}")),
                }
                self.subs[sub].model.get_mut(ino).xattrs.remove(&name);
            }
            Op::Fsync { sub, path } => {
                self.narf_file(sub, &path, |f| async move { f.fsync(false).await })?;
            }
            Op::Sync { sub } => {
                let root = self.subs[sub].root.clone();
                block_on(root.syncfs()).map_err(|x| e("syncfs", x))?;
            }
        }
        Ok(())
    }

    fn narf_file<T, F, Fut>(&self, sub: usize, path: &str, f: F) -> Result<T, String>
    where
        F: FnOnce(Arc<dyn FileOps>) -> Fut,
        Fut: std::future::Future<Output = Result<T, FsError>>,
    {
        let root = self.subs[sub].root.clone();
        block_on(async {
            let file = file_at(&root, path).await?;
            f(file).await
        })
        .map_err(|x| format!("{path}: {x:?}"))
    }

    fn with_file(&mut self, sub: usize, path: &str, f: impl FnOnce(&mut Vec<u8>)) {
        let m = &mut self.subs[sub].model;
        let ino = m.lookup(path).unwrap();
        match &mut m.get_mut(ino).kind {
            Kind::File(d) => f(Arc::make_mut(d)),
            _ => panic!("{path} is not a file"),
        }
    }
}

async fn write_full(f: &Arc<dyn FileOps>, off: u64, data: &[u8]) -> Result<(), FsError> {
    let mut done = 0;
    while done < data.len() {
        let n = f.write(off + done as u64, &data[done..]).await?;
        if n == 0 {
            return Err(FsError::Io(narf_block::BlockError::IOError));
        }
        done += n;
    }
    Ok(())
}

pub fn tail(s: &str, lines: usize) -> String {
    let v: Vec<&str> = s.lines().collect();
    v[v.len().saturating_sub(lines)..].join("\n")
}

/// Build a model from a NARF walk of `root` (the initial state, which the
/// caller cross-checks against Linux's view). Hard links in the fixture are
/// reconstructed from inode numbers.
pub fn model_from_narf(root: &Arc<dyn DirOps>) -> Result<(Model, Vec<String>), String> {
    let (_, nested) = crate::narf::walk(root)?;
    let mut m = Model::new(root.dir_mode());
    let mut by_ino: BTreeMap<u64, u64> = BTreeMap::new();
    block_on(async {
        let mut stack: Vec<(u64, Arc<dyn DirOps>, String)> =
            vec![(ROOT, root.clone(), String::new())];
        while let Some((mino, dir, path)) = stack.pop() {
            let entries = dir
                .enumerate_async(0, usize::MAX)
                .await
                .map_err(|e| format!("{e:?}"))?;
            for (name, ft) in entries {
                let p = join(&path, &name);
                if nested.contains(&p) {
                    continue;
                }
                use narf_filesystem::FileType;
                let child = match ft {
                    FileType::Dir => {
                        let d = dir
                            .lookup_dir_async(&name)
                            .await
                            .map_err(|e| format!("{p}: {e:?}"))?;
                        let ino = m.alloc(Inode {
                            kind: Kind::Dir(BTreeMap::new()),
                            perms: d.dir_mode(),
                            xattrs: BTreeMap::new(),
                        });
                        stack.push((ino, d, p.clone()));
                        ino
                    }
                    _ => {
                        let f = dir
                            .lookup_async(&name)
                            .await
                            .map_err(|e| format!("{p}: {e:?}"))?;
                        if let Some(&ino) = by_ino.get(&f.ino()) {
                            ino
                        } else {
                            let data = crate::narf::read_all(&f)
                                .await
                                .map_err(|e| format!("{p}: {e:?}"))?;
                            let inode = if ft == FileType::Symlink {
                                Inode {
                                    kind: Kind::Symlink(
                                        String::from_utf8_lossy(&data).into_owned(),
                                    ),
                                    perms: 0o777,
                                    xattrs: BTreeMap::new(),
                                }
                            } else {
                                Inode {
                                    kind: Kind::File(Arc::new(data)),
                                    perms: f.stat().mode.perms,
                                    xattrs: crate::narf::xattrs_of(&f)
                                        .await
                                        .map_err(|e| format!("{p}: {e:?}"))?,
                                }
                            };
                            let ino = m.alloc(inode);
                            by_ino.insert(f.ino(), ino);
                            ino
                        }
                    }
                };
                m.entries_mut(mino).insert(name, child);
            }
        }
        Ok::<_, String>(())
    })?;
    Ok((m, nested))
}
