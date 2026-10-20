//! The expected state of one subvolume: inodes (so hard links alias) and
//! directory entries. Cheap to clone — file contents are shared `Arc`s — so a
//! copy can be kept for every commit the crash pass may land on.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

pub type Ino = u64;
pub const ROOT: Ino = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    File(Arc<Vec<u8>>),
    Dir(BTreeMap<String, Ino>),
    Symlink(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    pub kind: Kind,
    /// Permission bits (`0o7777`).
    pub perms: u16,
    pub xattrs: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct Model {
    pub inodes: BTreeMap<Ino, Inode>,
    next: Ino,
}

/// One entry of a flattened, path-keyed view (what a restore or a NARF walk
/// can be compared against; hard links appear once per name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Flat {
    File {
        data: Arc<Vec<u8>>,
        perms: u16,
        xattrs: BTreeMap<String, Vec<u8>>,
    },
    Dir {
        perms: u16,
        xattrs: BTreeMap<String, Vec<u8>>,
    },
    Symlink(String),
}

pub type FlatTree = BTreeMap<String, Flat>;

impl Model {
    pub fn new(root_perms: u16) -> Self {
        let mut m = Model {
            inodes: BTreeMap::new(),
            next: ROOT + 1,
        };
        m.inodes.insert(
            ROOT,
            Inode {
                kind: Kind::Dir(BTreeMap::new()),
                perms: root_perms,
                xattrs: BTreeMap::new(),
            },
        );
        m
    }

    pub fn alloc(&mut self, inode: Inode) -> Ino {
        let ino = self.next;
        self.next += 1;
        self.inodes.insert(ino, inode);
        ino
    }

    pub fn get(&self, ino: Ino) -> &Inode {
        &self.inodes[&ino]
    }

    pub fn get_mut(&mut self, ino: Ino) -> &mut Inode {
        self.inodes.get_mut(&ino).unwrap()
    }

    pub fn entries(&self, dir: Ino) -> &BTreeMap<String, Ino> {
        match &self.get(dir).kind {
            Kind::Dir(e) => e,
            _ => panic!("not a dir"),
        }
    }

    pub fn entries_mut(&mut self, dir: Ino) -> &mut BTreeMap<String, Ino> {
        match &mut self.get_mut(dir).kind {
            Kind::Dir(e) => e,
            _ => panic!("not a dir"),
        }
    }

    /// Resolve a `/`-separated path relative to the root.
    pub fn lookup(&self, path: &str) -> Option<Ino> {
        let mut cur = ROOT;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            cur = *self.entries(cur).get(c)?;
        }
        Some(cur)
    }

    pub fn link_count(&self, ino: Ino) -> usize {
        self.inodes
            .values()
            .filter_map(|i| match &i.kind {
                Kind::Dir(e) => Some(e.values().filter(|&&c| c == ino).count()),
                _ => None,
            })
            .sum()
    }

    /// Drop inodes no entry references (after an unlink or a replacing
    /// rename).
    pub fn gc(&mut self, ino: Ino) {
        if ino != ROOT && self.link_count(ino) == 0 {
            self.inodes.remove(&ino);
        }
    }

    /// Every path, depth first, with its inode.
    pub fn walk(&self) -> Vec<(String, Ino)> {
        let mut out = Vec::new();
        let mut stack = vec![(String::new(), ROOT)];
        while let Some((path, ino)) = stack.pop() {
            if let Kind::Dir(e) = &self.get(ino).kind {
                for (name, &c) in e.iter().rev() {
                    let p = if path.is_empty() {
                        name.clone()
                    } else {
                        format!("{path}/{name}")
                    };
                    out.push((p.clone(), c));
                    stack.push((p, c));
                }
            }
        }
        out
    }

    pub fn flatten(&self) -> FlatTree {
        let mut t = FlatTree::new();
        for (path, ino) in self.walk() {
            let i = self.get(ino);
            t.insert(
                path,
                match &i.kind {
                    Kind::File(d) => Flat::File {
                        data: d.clone(),
                        perms: i.perms,
                        xattrs: i.xattrs.clone(),
                    },
                    Kind::Dir(_) => Flat::Dir {
                        perms: i.perms,
                        xattrs: i.xattrs.clone(),
                    },
                    Kind::Symlink(s) => Flat::Symlink(s.clone()),
                },
            );
        }
        t
    }
}

/// Which parts of an entry a comparison covers. `btrfs restore` recreates
/// permissions only with `-m`, and xattrs only with `-x`.
#[derive(Clone, Copy, Debug)]
pub struct Cmp {
    pub perms: bool,
    pub xattrs: bool,
    pub dir_perms: bool,
}

fn fmt_data(d: &[u8]) -> String {
    format!("{} bytes, fnv {:016x}", d.len(), fnv(d))
}

pub fn fnv(d: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in d {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// Differences between `want` and `got` (empty = equal), at most `limit`.
pub fn diff(want: &FlatTree, got: &FlatTree, cmp: Cmp, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |s: String| {
        if out.len() < limit {
            out.push(s)
        }
    };
    for (path, w) in want {
        let Some(g) = got.get(path) else {
            push(format!("missing: {path} ({})", describe(w)));
            continue;
        };
        match (w, g) {
            (
                Flat::File {
                    data: wd,
                    perms: wp,
                    xattrs: wx,
                },
                Flat::File {
                    data: gd,
                    perms: gp,
                    xattrs: gx,
                },
            ) => {
                if wd != gd {
                    let first = wd.iter().zip(gd.iter()).position(|(a, b)| a != b);
                    push(format!(
                        "content differs: {path}: want {} got {} (first diff at {first:?})",
                        fmt_data(wd),
                        fmt_data(gd)
                    ));
                }
                if cmp.perms && wp != gp {
                    push(format!("perms differ: {path}: want {wp:o} got {gp:o}"));
                }
                if cmp.xattrs && wx != gx {
                    push(format!("xattrs differ: {path}: want {wx:?} got {gx:?}"));
                }
            }
            (
                Flat::Dir {
                    perms: wp,
                    xattrs: wx,
                },
                Flat::Dir {
                    perms: gp,
                    xattrs: gx,
                },
            ) => {
                if cmp.dir_perms && wp != gp {
                    push(format!("dir perms differ: {path}: want {wp:o} got {gp:o}"));
                }
                if cmp.xattrs && wx != gx {
                    push(format!("dir xattrs differ: {path}: want {wx:?} got {gx:?}"));
                }
            }
            (Flat::Symlink(a), Flat::Symlink(b)) => {
                if a != b {
                    push(format!("symlink differs: {path}: want {a:?} got {b:?}"));
                }
            }
            _ => push(format!(
                "type differs: {path}: want {} got {}",
                describe(w),
                describe(g)
            )),
        }
    }
    for (path, g) in got {
        if !want.contains_key(path) {
            push(format!("unexpected: {path} ({})", describe(g)));
        }
    }
    out
}

fn describe(f: &Flat) -> String {
    match f {
        Flat::File { data, .. } => format!("file, {}", fmt_data(data)),
        Flat::Dir { .. } => "dir".into(),
        Flat::Symlink(t) => format!("symlink -> {t}"),
    }
}

pub fn summarize(t: &FlatTree) -> String {
    let (mut f, mut d, mut s, mut bytes) = (0, 0, 0, 0usize);
    for v in t.values() {
        match v {
            Flat::File { data, .. } => {
                f += 1;
                bytes += data.len();
            }
            Flat::Dir { .. } => d += 1,
            Flat::Symlink(_) => s += 1,
        }
    }
    let mut out = String::new();
    let _ = write!(
        out,
        "{f} files ({:.1} MiB), {d} dirs, {s} symlinks",
        bytes as f64 / 1048576.0
    );
    out
}
