//! Linux userspace (btrfs-progs) as the independent oracle: `btrfs check`,
//! `btrfs restore` and `dump-tree`, all on image files, none needing root.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use crate::model::{Flat, FlatTree};

pub fn btrfs() -> Command {
    let mut c = Command::new("btrfs");
    c.stdin(Stdio::null());
    c
}

/// Spawn `btrfs check --readonly [--check-data-csum] img` with its output
/// captured.
pub fn spawn_check(img: &Path, data_csum: bool) -> Child {
    let mut c = btrfs();
    c.arg("check").arg("--readonly");
    if data_csum {
        c.arg("--check-data-csum");
    }
    c.arg(img).stdout(Stdio::piped()).stderr(Stdio::piped());
    c.spawn().expect("spawn btrfs check")
}

pub fn wait_check(child: Child, what: &str) -> Result<(), String> {
    let out = child.wait_with_output().expect("wait btrfs check");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // `btrfs check` exits 0 even for some warnings it prints; treat the
    // explicit error markers as failures too.
    let bad = !out.status.success()
        || text.lines().any(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("error") || l.contains("errors found") && !l.contains("no error found")
        });
    if bad {
        return Err(format!(
            "btrfs check ({what}) failed ({}):\n{text}",
            out.status
        ));
    }
    Ok(())
}

pub fn check(img: &Path, data_csum: bool) -> Result<(), String> {
    wait_check(
        spawn_check(img, data_csum),
        if data_csum {
            "--check-data-csum"
        } else {
            "--readonly"
        },
    )
}

/// A subvolume from the root tree: id, its parent subvolume and its name.
#[derive(Clone, Debug)]
pub struct SubvolInfo {
    pub id: u64,
    pub parent: u64,
    pub name: String,
}

/// Every subvolume (ROOT_REF items of the root tree).
pub fn subvolumes(img: &Path) -> Result<Vec<SubvolInfo>, String> {
    let out = btrfs()
        .args(["inspect-internal", "dump-tree", "-t", "root"])
        .arg(img)
        .output()
        .map_err(|e| format!("dump-tree: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "dump-tree failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut v = Vec::new();
    let mut pending: Option<(u64, u64)> = None;
    for line in text.lines() {
        let l = line.trim();
        // "item 7 key (5 ROOT_REF 256) itemoff ... itemsize ..."
        if let Some(rest) = l.split_once("key (").map(|x| x.1) {
            pending = None;
            let mut it = rest.split([' ', ')']);
            let (a, ty, b) = (it.next(), it.next(), it.next());
            if ty == Some("ROOT_REF") {
                if let (Some(a), Some(b)) = (a, b) {
                    // dump-tree prints well-known objectids by name.
                    let id = |s: &str| {
                        if s == "FS_TREE" {
                            5
                        } else {
                            s.parse().unwrap_or(0)
                        }
                    };
                    pending = Some((id(a), id(b)));
                }
            }
        } else if let Some((parent, id)) = pending {
            // "root ref key dirid 256 sequence 2 name @"
            if let Some(name) = l.split_once(" name ").map(|x| x.1) {
                v.push(SubvolInfo {
                    id,
                    parent,
                    name: name.to_string(),
                });
                pending = None;
            }
        }
    }
    Ok(v)
}

/// The id of the top-level subvolume called `name`.
pub fn subvol_id(subs: &[SubvolInfo], name: &str) -> Option<u64> {
    subs.iter()
        .find(|s| s.parent == 5 && s.name == name)
        .map(|s| s.id)
}

/// `btrfs restore -r <id>` (with symlinks, xattrs and metadata) into `out`,
/// then read the result back as a flat tree.
///
/// `-m` restores owners, which an unprivileged process cannot set; the
/// restore therefore runs as root of a user namespace (`unshare
/// --map-auto --map-root-user`, the subuid range mapped), which then hands
/// the tree back to the invoking user (`chown -R 0:0` inside = us outside)
/// so it can be read. Modes and xattrs survive the hand-back.
pub fn restore(img: &Path, id: u64, out: &Path) -> Result<FlatTree, String> {
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out).unwrap();
    let script = r#"btrfs restore -r "$1" -S -x -m "$2" "$3" && chown -hR 0:0 "$3""#;
    let o = Command::new("unshare")
        .args([
            "--map-auto",
            "--map-root-user",
            "sh",
            "-c",
            script,
            "restore",
        ])
        .arg(id.to_string())
        .arg(img)
        .arg(out)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("unshare btrfs restore: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    if !o.status.success() || text.to_ascii_lowercase().contains("error") {
        return Err(format!(
            "btrfs restore -r {id} failed ({}):\n{text}",
            o.status
        ));
    }
    read_tree(out)
}

fn lxattrs(p: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    let mut buf = vec![0u8; 65536];
    // SAFETY: valid NUL-terminated path and buffer of the given length.
    let n = unsafe { libc::llistxattr(c.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
    if n <= 0 {
        return out;
    }
    for name in buf[..n as usize]
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty())
    {
        let s = String::from_utf8_lossy(name).into_owned();
        if !s.starts_with("user.") {
            continue;
        }
        let cn = CString::new(name).unwrap();
        let mut v = vec![0u8; 65536];
        // SAFETY: as above.
        let m =
            unsafe { libc::lgetxattr(c.as_ptr(), cn.as_ptr(), v.as_mut_ptr() as *mut _, v.len()) };
        if m >= 0 {
            v.truncate(m as usize);
            out.insert(s, v);
        }
    }
    out
}

/// Read a host directory tree (a restore) into the comparable form.
pub fn read_tree(root: &Path) -> Result<FlatTree, String> {
    let mut t = FlatTree::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        // A restored directory may carry a mode without owner rwx.
        let orig = std::fs::symlink_metadata(&dir)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode();
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(orig | 0o700));
        let rd = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for ent in rd {
            let ent = ent.map_err(|e| e.to_string())?;
            let p = ent.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let md = std::fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
            let perms = (md.permissions().mode() & 0o7777) as u16;
            if md.file_type().is_symlink() {
                let target = std::fs::read_link(&p).map_err(|e| e.to_string())?;
                t.insert(rel, Flat::Symlink(target.to_string_lossy().into_owned()));
            } else if md.is_dir() {
                t.insert(
                    rel,
                    Flat::Dir {
                        perms,
                        xattrs: lxattrs(&p),
                    },
                );
                stack.push(p);
            } else {
                let _ = std::fs::set_permissions(
                    &p,
                    std::fs::Permissions::from_mode(perms as u32 | 0o400),
                );
                let data = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                t.insert(
                    rel,
                    Flat::File {
                        data: Arc::new(data),
                        perms,
                        xattrs: lxattrs(&p),
                    },
                );
            }
        }
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(orig));
    }
    Ok(t)
}

/// Number of DATA / METADATA chunks (`dump-tree -t chunk`).
pub fn chunk_counts(img: &Path) -> (usize, usize) {
    let Ok(out) = btrfs()
        .args(["inspect-internal", "dump-tree", "-t", "chunk"])
        .arg(img)
        .output()
    else {
        return (0, 0);
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let data = text.lines().filter(|l| l.contains("type DATA")).count();
    let meta = text.lines().filter(|l| l.contains("type METADATA")).count();
    (data, meta)
}

/// Reflink (or copy) `src` to `dst`.
pub fn clone_file(src: &Path, dst: &Path) {
    let _ = std::fs::remove_file(dst);
    let ok = Command::new("cp")
        .args(["--reflink=auto", "--sparse=always"])
        .arg(src)
        .arg(dst)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "cp {} {}", src.display(), dst.display());
}
