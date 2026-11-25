//! The expected tree: what every reader (NARF after a remount, Linux's
//! debugfs) must see after a workload.

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Dir,
    File(Vec<u8>),
    Symlink(String),
}

/// Absolute paths ("/etc/x") to nodes. The root itself is implicit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Model {
    pub nodes: BTreeMap<String, Node>,
}

pub fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

pub fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => "/",
    }
}

impl Model {
    /// The tree under `dir` on the host (as `mkfs -d` saw it).
    pub fn load_host(dir: &Path) -> Self {
        let mut m = Model::default();
        fn walk(m: &mut Model, host: &Path, at: &str) {
            let mut entries: Vec<_> = std::fs::read_dir(host)
                .unwrap()
                .map(|e| e.unwrap())
                .collect();
            entries.sort_by_key(|e| e.file_name());
            for e in entries {
                let name = e.file_name().into_string().unwrap();
                let path = join(at, &name);
                let ft = e.file_type().unwrap();
                if ft.is_symlink() {
                    let t = std::fs::read_link(e.path()).unwrap();
                    m.nodes
                        .insert(path, Node::Symlink(t.to_string_lossy().into_owned()));
                } else if ft.is_dir() {
                    m.nodes.insert(path.clone(), Node::Dir);
                    walk(m, &e.path(), &path);
                } else {
                    m.nodes
                        .insert(path, Node::File(std::fs::read(e.path()).unwrap()));
                }
            }
        }
        walk(&mut m, dir, "/");
        m
    }

    pub fn get(&self, path: &str) -> Option<&Node> {
        self.nodes.get(path)
    }

    pub fn is_dir(&self, path: &str) -> bool {
        path == "/" || matches!(self.get(path), Some(Node::Dir))
    }

    /// Direct children of `dir`.
    pub fn children(&self, dir: &str) -> Vec<String> {
        let prefix = if dir == "/" {
            "/".to_string()
        } else {
            format!("{dir}/")
        };
        self.nodes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .filter(|(k, _)| !k[prefix.len()..].contains('/'))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Every node strictly under `dir`.
    pub fn subtree(&self, dir: &str) -> Vec<String> {
        let prefix = format!("{dir}/");
        self.nodes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Paths in `self` and `other` that differ, described, at most `limit`.
    pub fn diff(&self, other: &Model, limit: usize) -> Vec<String> {
        let mut out = Vec::new();
        let keys: std::collections::BTreeSet<&String> =
            self.nodes.keys().chain(other.nodes.keys()).collect();
        for k in keys {
            if out.len() == limit {
                out.push("...".into());
                break;
            }
            match (self.nodes.get(k), other.nodes.get(k)) {
                (Some(a), Some(b)) if a == b => {}
                (Some(_), None) => out.push(format!("{k}: missing")),
                (None, Some(_)) => out.push(format!("{k}: unexpected")),
                (Some(a), Some(b)) => {
                    out.push(format!("{k}: expected {}, found {}", brief(a), brief(b)))
                }
                (None, None) => {}
            }
        }
        out
    }
}

fn brief(n: &Node) -> String {
    match n {
        Node::Dir => "dir".into(),
        Node::Symlink(t) => format!("symlink -> {t}"),
        Node::File(d) => format!("file of {} bytes", d.len()),
    }
}
