//! Fixture images: a CachyOS-shaped tree written to the host, packed into a
//! fresh ext4 image by the real `mkfs.ext4 -d`, with the host's default
//! feature set (e2fsprogs >= 1.47: metadata_csum, orphan_file, 64bit,
//! flex_bg, extents, huge_file, dir_index with half-MD4 hashes).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::rng::Rng;

/// How one fixture image is made.
#[derive(Clone, Debug)]
pub struct Spec {
    /// `mkfs.ext4 -b`.
    pub block_size: u32,
    /// Image size.
    pub size_mib: u64,
    /// Files in `/usr/lib` (the big directory: several htree leaves).
    pub lib_files: usize,
    /// Packages under `/var/lib/pacman/local` (two files each).
    pub packages: usize,
    /// Extra `mkfs.ext4` arguments (`-O`, `-E`).
    pub mkfs_args: Vec<String>,
}

impl Spec {
    /// The default fixture: a small root with a multi-leaf `/usr/lib`.
    pub fn root() -> Self {
        Self {
            block_size: 4096,
            size_mib: 256,
            lib_files: 1500,
            packages: 120,
            mkfs_args: Vec::new(),
        }
    }
}

pub struct Fixture {
    pub image: PathBuf,
    /// The source tree `mkfs -d` packed (the model is loaded from it).
    pub tree: PathBuf,
}

fn write(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Build the source tree and the image under `work/<name>`.
pub fn build(work: &Path, name: &str, spec: &Spec, seed: u64) -> Fixture {
    let dir = work.join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let mut rng = Rng::new(seed ^ 0x6578_7434);

    for i in 0..40 {
        let body = format!("# /etc/conf{i}\nkey{i}=value{}\n", rng.below(1_000_000));
        write(&tree.join(format!("etc/conf{i}.conf")), body.as_bytes());
    }
    for i in 0..spec.lib_files {
        let name = format!("lib{i:05}_{:08x}.so.1", rng.next() as u32);
        let len = 64 + rng.below(16_384);
        write(&tree.join("usr/lib").join(&name), &rng.bytes(len));
        if i % 10 == 0 {
            let link = tree.join(format!("usr/lib/lib{i:05}.so"));
            std::os::unix::fs::symlink(&name, link).unwrap();
        }
    }
    for i in 0..spec.packages {
        let pkg = tree.join(format!(
            "var/lib/pacman/local/pkg{i:04}-1.{}-1",
            rng.below(9)
        ));
        write(&pkg.join("desc"), format!("%NAME%\npkg{i:04}\n").as_bytes());
        let len = rng.below(4096);
        write(&pkg.join("files"), &rng.bytes(len));
    }
    // One file big enough for several extents' worth of blocks.
    write(&tree.join("home/user/big.bin"), &rng.bytes(3 << 20));
    std::fs::create_dir_all(tree.join("work")).unwrap();

    let image = dir.join("root.img");
    let file = std::fs::File::create(&image).unwrap();
    file.set_len(spec.size_mib << 20).unwrap();
    drop(file);
    let status = Command::new("mkfs.ext4")
        .args([
            "-F",
            "-q",
            "-b",
            &spec.block_size.to_string(),
            "-L",
            "narf-host",
        ])
        .args(["-E", "root_owner=0:0"])
        .args(&spec.mkfs_args)
        .arg("-d")
        .arg(&tree)
        .arg(&image)
        .status()
        .expect("run mkfs.ext4");
    assert!(status.success(), "mkfs.ext4 failed for {name}");
    Fixture { image, tree }
}
