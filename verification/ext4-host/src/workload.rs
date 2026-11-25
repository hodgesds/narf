//! A seeded random workload, applied to NARF and mirrored into the model.

use std::sync::Arc;

use narf_filesystem::{DirOps, FileOps, FsError};

use crate::host::block_on;
use crate::model::{join, parent, Model, Node};
use crate::narf::dir_at;
use crate::rng::Rng;

#[derive(Clone, Debug)]
pub enum Op {
    Create {
        dir: String,
        name: String,
        len: usize,
    },
    WriteAt {
        path: String,
        off: u64,
        len: usize,
    },
    Append {
        path: String,
        len: usize,
    },
    Truncate {
        path: String,
        len: u64,
    },
    Unlink {
        path: String,
    },
    Mkdir {
        dir: String,
        name: String,
    },
    Rmdir {
        path: String,
    },
    Symlink {
        dir: String,
        name: String,
        target: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Fsync {
        path: String,
    },
    Syncfs,
}

impl Op {
    pub fn kind(&self) -> &'static str {
        match self {
            Op::Create { .. } => "create",
            Op::WriteAt { .. } => "write",
            Op::Append { .. } => "append",
            Op::Truncate { .. } => "truncate",
            Op::Unlink { .. } => "unlink",
            Op::Mkdir { .. } => "mkdir",
            Op::Rmdir { .. } => "rmdir",
            Op::Symlink { .. } => "symlink",
            Op::Rename { .. } => "rename",
            Op::Fsync { .. } => "fsync",
            Op::Syncfs => "syncfs",
        }
    }
}

/// What a run does.
#[derive(Clone, Debug)]
pub struct Params {
    pub ops: usize,
    /// Directories whose subtrees the workload may change.
    pub roots: Vec<String>,
    /// Directories that receive extra creates (to fill directory blocks).
    pub hot_dirs: Vec<String>,
    /// Largest file a create or append produces.
    pub max_file: usize,
}

pub struct Workload {
    rng: Rng,
    pub model: Model,
    root: Arc<dyn DirOps>,
    pub trace: Vec<String>,
    pub counts: std::collections::BTreeMap<&'static str, usize>,
    serial: u64,
}

fn fs(what: &str, path: &str, e: FsError) -> String {
    format!("{what} {path}: {e:?}")
}

async fn write_all(f: &Arc<dyn FileOps>, mut off: u64, mut data: &[u8]) -> Result<(), FsError> {
    while !data.is_empty() {
        let n = f.write(off, data).await?;
        if n == 0 {
            return Err(FsError::NoSpace);
        }
        off += n as u64;
        data = &data[n..];
    }
    Ok(())
}

fn name_of(path: &str) -> &str {
    &path[path.rfind('/').map_or(0, |i| i + 1)..]
}

impl Workload {
    pub fn new(seed: u64, model: Model, root: Arc<dyn DirOps>) -> Self {
        Self {
            rng: Rng::new(seed),
            model,
            root,
            trace: Vec::new(),
            counts: Default::default(),
            serial: 0,
        }
    }

    fn fresh_name(&mut self) -> String {
        self.serial += 1;
        let tag = self.rng.next() as u32;
        if self.rng.chance(10) {
            // Long names: dirent sizes and hash inputs past the chunk sizes.
            let pad = "n".repeat(40 + self.rng.below(160));
            format!("{pad}_{}_{tag:08x}", self.serial)
        } else {
            format!("f{}_{tag:08x}", self.serial)
        }
    }

    /// Paths of one kind under the workload's roots.
    fn pick(&mut self, roots: &[String], want: fn(&Node) -> bool) -> Option<String> {
        let mut all: Vec<String> = Vec::new();
        for r in roots {
            if want(&Node::Dir) && self.model.is_dir(r) {
                all.push(r.clone());
            }
            for p in self.model.subtree(r) {
                if want(&self.model.nodes[&p]) {
                    all.push(p);
                }
            }
        }
        if all.is_empty() {
            return None;
        }
        let i = self.rng.below(all.len());
        Some(all.swap_remove(i))
    }

    fn gen(&mut self, p: &Params) -> Option<Op> {
        let is_dir = |n: &Node| matches!(n, Node::Dir);
        let is_file = |n: &Node| matches!(n, Node::File(_));
        let is_any = |_: &Node| true;
        let roll = self.rng.below(100);
        Some(match roll {
            0..=29 => {
                let dir = if !p.hot_dirs.is_empty() && self.rng.chance(50) {
                    p.hot_dirs[self.rng.below(p.hot_dirs.len())].clone()
                } else {
                    self.pick(&p.roots, is_dir)?
                };
                let len = if self.rng.chance(30) {
                    0
                } else {
                    self.rng.below(p.max_file)
                };
                Op::Create {
                    dir,
                    name: self.fresh_name(),
                    len,
                }
            }
            30..=39 => {
                let path = self.pick(&p.roots, is_file)?;
                let len = 1 + self.rng.below(32 * 1024);
                let off = self.rng.below(p.max_file + 8192) as u64;
                Op::WriteAt { path, off, len }
            }
            40..=46 => {
                let path = self.pick(&p.roots, is_file)?;
                Op::Append {
                    path,
                    len: 1 + self.rng.below(64 * 1024),
                }
            }
            47..=53 => {
                let path = self.pick(&p.roots, is_file)?;
                let len = self.rng.below(p.max_file) as u64;
                Op::Truncate { path, len }
            }
            54..=63 => Op::Unlink {
                path: self.pick(&p.roots, |n| !matches!(n, Node::Dir))?,
            },
            64..=71 => Op::Mkdir {
                dir: self.pick(&p.roots, is_dir)?,
                name: self.fresh_name(),
            },
            72..=75 => {
                let path = self.pick(&p.roots, is_dir)?;
                if p.roots.contains(&path) || !self.model.children(&path).is_empty() {
                    return None;
                }
                Op::Rmdir { path }
            }
            76..=81 => {
                let dir = self.pick(&p.roots, is_dir)?;
                // Fast (inline) and slow (block) symlinks.
                let target = if self.rng.chance(50) {
                    format!("../t{}", self.rng.below(1000))
                } else {
                    "x/".repeat(30 + self.rng.below(200))
                };
                Op::Symlink {
                    dir,
                    name: self.fresh_name(),
                    target,
                }
            }
            82..=91 => {
                let from = self.pick(&p.roots, is_any)?;
                if p.roots.contains(&from) {
                    return None;
                }
                let dir = self.pick(&p.roots, is_dir)?;
                if dir == from || dir.starts_with(&format!("{from}/")) {
                    return None;
                }
                Op::Rename {
                    from,
                    to: join(&dir, &self.fresh_name()),
                }
            }
            92..=96 => Op::Fsync {
                path: self.pick(&p.roots, is_file)?,
            },
            _ => Op::Syncfs,
        })
    }

    pub fn run(&mut self, p: &Params) -> Result<(), String> {
        let mut done = 0;
        let mut tries = 0;
        while done < p.ops {
            tries += 1;
            if tries > p.ops * 20 {
                return Err("workload could not generate enough operations".into());
            }
            let Some(op) = self.gen(p) else { continue };
            self.trace
                .push(format!("{op:?}").chars().take(160).collect());
            *self.counts.entry(op.kind()).or_default() += 1;
            self.apply(op).map_err(|e| {
                format!(
                    "op #{} failed: {e}\nlast ops:\n  {}\nklog tail:\n{}",
                    self.trace.len(),
                    self.trace[self.trace.len().saturating_sub(8)..].join("\n  "),
                    tail(&crate::host::klog_take_filtered(), 30)
                )
            })?;
            done += 1;
        }
        Ok(())
    }

    fn file_data(&mut self, path: &str) -> &mut Vec<u8> {
        match self.model.nodes.get_mut(path) {
            Some(Node::File(d)) => d,
            _ => panic!("{path} is not a file in the model"),
        }
    }

    fn apply(&mut self, op: Op) -> Result<(), String> {
        let root = self.root.clone();
        match op {
            Op::Create { dir, name, len } => {
                let data = self.rng.bytes(len);
                block_on(async {
                    let d = dir_at(&root, &dir).await?;
                    let f = d.create(&name).await?;
                    write_all(&f, 0, &data).await
                })
                .map_err(|e| fs("create", &join(&dir, &name), e))?;
                self.model.nodes.insert(join(&dir, &name), Node::File(data));
            }
            Op::WriteAt { path, off, len } => {
                let data = self.rng.bytes(len);
                block_on(async {
                    let f = dir_at(&root, parent(&path))
                        .await?
                        .lookup_async(name_of(&path))
                        .await?;
                    write_all(&f, off, &data).await
                })
                .map_err(|e| fs("write", &path, e))?;
                let d = self.file_data(&path);
                let end = off as usize + data.len();
                if d.len() < end {
                    d.resize(end, 0);
                }
                d[off as usize..end].copy_from_slice(&data);
            }
            Op::Append { path, len } => {
                let data = self.rng.bytes(len);
                let off = self.file_data(&path).len() as u64;
                block_on(async {
                    let f = dir_at(&root, parent(&path))
                        .await?
                        .lookup_async(name_of(&path))
                        .await?;
                    write_all(&f, off, &data).await
                })
                .map_err(|e| fs("append", &path, e))?;
                self.file_data(&path).extend_from_slice(&data);
            }
            Op::Truncate { path, len } => {
                block_on(async {
                    let f = dir_at(&root, parent(&path))
                        .await?
                        .lookup_async(name_of(&path))
                        .await?;
                    f.truncate(len).await
                })
                .map_err(|e| fs("truncate", &path, e))?;
                self.file_data(&path).resize(len as usize, 0);
            }
            Op::Unlink { path } => {
                block_on(async {
                    dir_at(&root, parent(&path))
                        .await?
                        .unlink(name_of(&path))
                        .await
                })
                .map_err(|e| fs("unlink", &path, e))?;
                self.model.nodes.remove(&path);
            }
            Op::Mkdir { dir, name } => {
                block_on(async { dir_at(&root, &dir).await?.mkdir(&name).await.map(drop) })
                    .map_err(|e| fs("mkdir", &join(&dir, &name), e))?;
                self.model.nodes.insert(join(&dir, &name), Node::Dir);
            }
            Op::Rmdir { path } => {
                block_on(async {
                    dir_at(&root, parent(&path))
                        .await?
                        .rmdir(name_of(&path))
                        .await
                })
                .map_err(|e| fs("rmdir", &path, e))?;
                self.model.nodes.remove(&path);
            }
            Op::Symlink { dir, name, target } => {
                block_on(async {
                    dir_at(&root, &dir)
                        .await?
                        .symlink(&name, &target)
                        .await
                        .map(drop)
                })
                .map_err(|e| fs("symlink", &join(&dir, &name), e))?;
                self.model
                    .nodes
                    .insert(join(&dir, &name), Node::Symlink(target));
            }
            Op::Rename { from, to } => {
                block_on(async {
                    let src = dir_at(&root, parent(&from)).await?;
                    if parent(&from) == parent(&to) {
                        src.rename(name_of(&from), name_of(&to)).await
                    } else {
                        let dst = dir_at(&root, parent(&to)).await?;
                        src.rename_to(name_of(&from), &*dst, name_of(&to), 0).await
                    }
                })
                .map_err(|e| fs("rename", &format!("{from} -> {to}"), e))?;
                let mut moved = vec![from.clone()];
                moved.extend(self.model.subtree(&from));
                for old in moved {
                    let node = self.model.nodes.remove(&old).unwrap();
                    let new = format!("{to}{}", &old[from.len()..]);
                    self.model.nodes.insert(new, node);
                }
            }
            Op::Fsync { path } => {
                block_on(async {
                    let f = dir_at(&root, parent(&path))
                        .await?
                        .lookup_async(name_of(&path))
                        .await?;
                    f.fsync(false).await
                })
                .map_err(|e| fs("fsync", &path, e))?;
            }
            Op::Syncfs => {
                block_on(root.syncfs()).map_err(|e| fs("syncfs", "/", e))?;
            }
        }
        Ok(())
    }
}

pub fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}
