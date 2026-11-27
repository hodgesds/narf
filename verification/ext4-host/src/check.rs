//! The Linux side's verdict on an image: e2fsck, debugfs, dumpe2fs.

use std::path::Path;
use std::process::Command;

use crate::model::Model;

/// `e2fsck -fn`: exit code and output. 0 means no problem found.
pub fn e2fsck(image: &Path) -> (i32, String) {
    let out = Command::new("e2fsck")
        .arg("-fn")
        .arg(image)
        .output()
        .expect("run e2fsck");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

/// The tree as e2fsprogs reads it (`debugfs rdump /`), `lost+found` aside.
pub fn debugfs_tree(image: &Path, scratch: &Path) -> Model {
    let _ = std::fs::remove_dir_all(scratch);
    std::fs::create_dir_all(scratch).unwrap();
    // rdump exits non-zero when it cannot chown as an unprivileged user;
    // the contents are what matters.
    let _ = Command::new("debugfs")
        .arg("-R")
        .arg(format!("rdump / {}", scratch.display()))
        .arg(image)
        .output()
        .expect("run debugfs");
    let _ = std::fs::remove_dir_all(scratch.join("lost+found"));
    let m = Model::load_host(scratch);
    let _ = std::fs::remove_dir_all(scratch);
    m
}

/// `dumpe2fs -h` fields by name ("Filesystem state", "Mount count", ...).
pub fn superblock(image: &Path) -> std::collections::BTreeMap<String, String> {
    let out = Command::new("dumpe2fs")
        .arg("-h")
        .arg(image)
        .output()
        .expect("run dumpe2fs");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Groups whose descriptor still says `BLOCK_UNINIT` and `INODE_UNINIT`
/// (`dumpe2fs` prints `[INODE_UNINIT, BLOCK_UNINIT, ...]` per group).
pub fn uninit_groups(image: &Path) -> (usize, usize) {
    let out = Command::new("dumpe2fs")
        .arg(image)
        .output()
        .expect("run dumpe2fs");
    let text = String::from_utf8_lossy(&out.stdout);
    let groups = text.lines().filter(|l| l.starts_with("Group "));
    let (mut block, mut inode) = (0, 0);
    for line in groups {
        block += usize::from(line.contains("BLOCK_UNINIT"));
        inode += usize::from(line.contains("INODE_UNINIT"));
    }
    (block, inode)
}

/// `debugfs htree <dir>`: the directory's `Indirect levels`, if indexed.
pub fn htree_levels(image: &Path, dir: &str) -> Option<u32> {
    let out = Command::new("debugfs")
        .arg("-R")
        .arg(format!("htree {dir}"))
        .arg(image)
        .output()
        .expect("run debugfs");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.trim().strip_prefix("Indirect levels:"))
        .and_then(|v| v.trim().parse().ok())
}

/// `debugfs ex <file>`: the depth of the file's extent tree (the `b` of the
/// first row's `a/ b` level column).
pub fn extent_depth(image: &Path, file: &str) -> Option<u32> {
    let out = Command::new("debugfs")
        .arg("-R")
        .arg(format!("ex {file}"))
        .arg(image)
        .output()
        .expect("run debugfs");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().find_map(|l| {
        let (_, depth) = l.trim().split_once('/')?;
        depth.split_whitespace().next()?.parse().ok()
    })
}
