//! Fixture images: a CachyOS-shaped root made by `mkfs.btrfs --rootdir`
//! (no privileges), and the committed sparse fixtures in
//! `drivers/fs/btrfs/testdata/`.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::workload::{gen_data, Rng};

pub fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../drivers/fs/btrfs/testdata")
}

/// Expand a `NARFBTR1` sparse fixture (`regen_*.sh`) into a raw image.
pub fn unsparse(src: &Path, dst: &Path) {
    let raw = std::fs::read(src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
    assert_eq!(
        &raw[..8],
        b"NARFBTR1",
        "{}: not a sparse fixture",
        src.display()
    );
    let total = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let runs = u32::from_le_bytes(raw[16..20].try_into().unwrap());
    let f = std::fs::File::create(dst).unwrap();
    f.set_len(total).unwrap();
    let mut p = 20usize;
    for _ in 0..runs {
        let off = u64::from_le_bytes(raw[p..p + 8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[p + 8..p + 16].try_into().unwrap()) as usize;
        p += 16;
        std::os::unix::fs::FileExt::write_all_at(&f, &raw[p..p + len], off).unwrap();
        p += len;
    }
}

fn write(path: &Path, data: &[u8], mode: u32) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn setxattr(path: &Path, name: &str, value: &[u8]) {
    let p = CString::new(path.as_os_str().as_bytes()).unwrap();
    let n = CString::new(name).unwrap();
    // SAFETY: valid NUL-terminated strings and a value buffer of its length.
    let r = unsafe {
        libc::lsetxattr(
            p.as_ptr(),
            n.as_ptr(),
            value.as_ptr() as *const _,
            value.len(),
            0,
        )
    };
    assert_eq!(r, 0, "setxattr {} {name}", path.display());
}

/// Populate `dir` with an installed-root-like tree: `@/{etc,usr,var}` and
/// `@home/<user>` — many small (inline) config files, compressible text and
/// incompressible binaries (a few MiB each), symlinks (relative and
/// absolute), hard links, a pacman-style database of small directories, and
/// `user.*` xattrs.
pub fn populate_root(dir: &Path, seed: u64, scale: usize) {
    let _ = std::fs::remove_dir_all(dir);
    let mut rng = Rng::new(seed ^ 0xf1f1);
    let at = dir.join("@");
    let home = dir.join("@home");
    write(&at.join("etc/hostname"), b"narf-host\n", 0o644);
    write(
        &at.join("etc/fstab"),
        b"UUID=x / btrfs subvol=/@,noatime,compress=zstd:1 0 0\nUUID=x /home btrfs subvol=/@home,noatime,compress=zstd:1 0 0\n",
        0o644,
    );
    write(&at.join("etc/shadow"), b"root:*:19000::::::\n", 0o600);
    for i in 0..(120 * scale) {
        let len = rng.range(20, 1800) as usize;
        write(
            &at.join(format!("etc/conf.d/c{i:04}.conf")),
            &gen_data(&mut rng, len),
            0o644,
        );
    }
    for i in 0..(400 * scale) {
        let pkg = format!("var/lib/pacman/local/pkg{i:04}-1.0-1");
        write(
            &at.join(format!("{pkg}/desc")),
            format!("%NAME%\npkg{i}\n%VERSION%\n1.0-1\n").as_bytes(),
            0o644,
        );
        if i % 3 == 0 {
            let len = rng.range(100, 3000) as usize;
            write(
                &at.join(format!("{pkg}/files")),
                &gen_data(&mut rng, len),
                0o644,
            );
        }
    }
    for i in 0..(30 * scale) {
        let len = rng.range(8192, 200_000) as usize;
        write(
            &at.join(format!("usr/share/doc/doc{i}.txt")),
            &gen_data(&mut rng, len),
            0o644,
        );
    }
    // Incompressible binaries and one big compressible file.
    for i in 0..(2 * scale) {
        let mut v = vec![0u8; 3 << 20];
        rng.fill(&mut v);
        write(&at.join(format!("usr/lib/libbig{i}.so")), &v, 0o755);
    }
    let text: Vec<u8> = (0..(4 << 20))
        .map(|i: usize| b"abcdefgh\n"[i % 9])
        .collect();
    write(&at.join("usr/lib/locale/locale-archive"), &text, 0o644);
    write(
        &at.join("usr/bin/bash"),
        &gen_data(&mut rng, 900_000),
        0o755,
    );
    symlink("bash", at.join("usr/bin/sh")).unwrap();
    symlink("usr/bin", at.join("bin")).unwrap();
    symlink("/usr/lib/libbig0.so", at.join("usr/lib/libbig.so")).unwrap();
    symlink(
        "../../usr/share/doc/doc0.txt",
        at.join("etc/conf.d/doclink"),
    )
    .unwrap();
    std::fs::hard_link(at.join("usr/bin/bash"), at.join("usr/bin/rbash")).unwrap();
    std::fs::hard_link(at.join("etc/hostname"), at.join("etc/hostname.bak")).unwrap();
    setxattr(&at.join("usr/bin/bash"), "user.pax.flags", b"em");
    setxattr(
        &at.join("etc/shadow"),
        "user.narf.note",
        &[0u8, 1, 2, 3, 255],
    );
    std::fs::create_dir_all(at.join("var/empty")).unwrap();
    std::fs::create_dir_all(at.join("tmp")).unwrap();
    std::fs::set_permissions(at.join("var/empty"), std::fs::Permissions::from_mode(0o700)).unwrap();

    let user = home.join("daniel");
    write(
        &user.join(".bashrc"),
        b"[[ $- != *i* ]] && return\nalias ls='ls --color'\n",
        0o644,
    );
    write(
        &user.join(".ssh/authorized_keys"),
        b"ssh-ed25519 AAAA test\n",
        0o600,
    );
    std::fs::set_permissions(user.join(".ssh"), std::fs::Permissions::from_mode(0o700)).unwrap();
    for i in 0..(60 * scale) {
        let len = rng.range(0, 40_000) as usize;
        write(
            &user.join(format!("Documents/note{i}.md")),
            &gen_data(&mut rng, len),
            0o644,
        );
    }
    let mut photo = vec![0u8; 2 << 20];
    rng.fill(&mut photo);
    write(&user.join("Pictures/photo.jpg"), &photo, 0o644);
    symlink("Documents/note0.md", user.join("latest")).unwrap();
    setxattr(
        &user.join("Pictures/photo.jpg"),
        "user.xdg.origin.url",
        b"https://example.invalid/p.jpg",
    );
}

/// `mkfs.btrfs` options for the root fixture: 16K nodes, crc32c, the
/// free-space tree and block-group tree, `@` (default) and `@home`, zstd:1.
pub struct MkfsSpec<'a> {
    pub uuid: &'a str,
    pub size: u64,
    pub nodesize: u32,
    pub csum: &'a str,
    pub features: &'a str,
}

pub fn mkfs(img: &Path, rootdir: &Path, spec: &MkfsSpec) -> Result<(), String> {
    let _ = std::fs::remove_file(img);
    let f = std::fs::File::create(img).unwrap();
    f.set_len(spec.size).unwrap();
    drop(f);
    let out = Command::new("mkfs.btrfs")
        .args(["-q", "-f", "-U", spec.uuid, "-L", "narf-host-root"])
        .args([
            "-n",
            &spec.nodesize.to_string(),
            "-s",
            "4096",
            "--csum",
            spec.csum,
        ])
        .args(["-O", spec.features])
        .arg("--rootdir")
        .arg(rootdir)
        .args([
            "--subvol",
            "default:@",
            "--subvol",
            "rw:@home",
            "--compress",
            "zstd:1",
        ])
        .arg(img)
        .output()
        .map_err(|e| format!("mkfs.btrfs: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "mkfs.btrfs failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}
