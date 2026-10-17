//! `cargo xtask cachyos-root-smoke`: boot a CachyOS-layout btrfs root with
//! systemd as PID 1 and wait for the getty login prompt.
//!
//! The disk is a regular file built unprivileged by
//! `verification/data/cachyos-root/REGEN_cachyos_root_image.sh`: a GPT disk
//! with a FAT32 ESP and a btrfs root using the host's mkfs features and
//! CachyOS's `@` subvolume layout and fstab, populated with the real CachyOS
//! `base` userspace. It is attached as the guest's NVMe disk and booted with
//! the bare-metal command line, with only the UUID changed. No host block
//! device is ever opened.
//!
//! Default mode is `narf.disks=root-ro`. Its SHA-256 is checked
//! afterwards, so the run also proves that root-ro wrote nothing. `--rw` boots
//! `narf.disks=root-rw` on a scratch copy of the image instead.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Btrfs fsid of the smoke image. Keep in sync with the image script.
pub const IMAGE_BTRFS_UUID: &str = "c4c405ee-0000-4a11-9e57-00000000c0de";

/// Hostname baked into the image; agetty prints `<hostname> login:`.
pub const IMAGE_HOSTNAME: &str = "cachyos-narf";

/// Image path, relative to the workspace root.
const IMAGE: &str = "target/narf-cachyos-root.img";
/// Scratch copy a `--rw` boot writes to.
const RW_IMAGE: &str = "target/narf-cachyos-root-rw.img";
const SCRIPT: &str = "verification/data/cachyos-root/REGEN_cachyos_root_image.sh";

/// Options for the CachyOS root smoke.
#[derive(clap::Args, Clone)]
pub struct Args {
    #[command(flatten)]
    pub build: super::BuildArgs,

    /// Boot `narf.disks=root-rw` (the real root is mounted writable, no
    /// tmpfs overlay) on a fresh scratch copy of the image.
    #[arg(long)]
    pub rw: bool,

    /// Reinstall the image's userspace from scratch before booting.
    #[arg(long)]
    pub rebuild_image: bool,

    /// Extra kernel arguments, appended after the bare-metal command line.
    #[arg(long = "cmdline", value_name = "ARG")]
    pub cmdline: Vec<String>,
}

/// The bare-metal command line, for the smoke image's UUID.
pub fn smoke_cmdline(uuid: &str, rw: bool, extra: &[String]) -> String {
    let mut tokens = vec![
        format!("root=UUID={uuid}"),
        "rootflags=subvol=/@".to_string(),
        "systemd_pid1".to_string(),
        format!("narf.disks={}", if rw { "root-rw" } else { "root-ro" }),
    ];
    tokens.extend(extra.iter().cloned());
    tokens.join(" ")
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn ensure_image(root: &Path, rebuild: bool) -> Result<PathBuf> {
    let image = root.join(IMAGE);
    if image.exists() && !rebuild {
        return Ok(image);
    }
    println!("xtask cachyos-root-smoke: building {}", image.display());
    let status = Command::new("bash")
        .arg(root.join(SCRIPT))
        .env("CACHYOS_ROOT_IMG", &image)
        .env("CACHYOS_ROOT_REBUILD", if rebuild { "1" } else { "0" })
        .status()
        .context("run the CachyOS image script")?;
    if !status.success() {
        bail!("xtask cachyos-root-smoke: image build failed ({status})");
    }
    Ok(image)
}

pub fn run(args: &Args) -> Result<()> {
    let root = super::workspace_root()?;
    let image = ensure_image(&root, args.rebuild_image)?;
    let disk = if args.rw {
        let copy = root.join(RW_IMAGE);
        let _ = std::fs::remove_file(&copy);
        let status = Command::new("cp")
            .args(["--reflink=auto", "--sparse=always"])
            .arg(&image)
            .arg(&copy)
            .status()
            .context("copy the image for the root-rw boot")?;
        if !status.success() {
            bail!("xtask cachyos-root-smoke: copying the image failed");
        }
        copy
    } else {
        image.clone()
    };
    let before = (!args.rw).then(|| sha256_file(&disk)).transpose()?;

    let cmdline = smoke_cmdline(IMAGE_BTRFS_UUID, args.rw, &args.cmdline);
    println!(
        "xtask cachyos-root-smoke: disk {} cmdline `{cmdline}`",
        disk.display()
    );
    std::env::set_var("NARF_NVME_IMG", &disk);
    let existing = std::env::var("XTASK_QEMU_APPEND").unwrap_or_default();
    std::env::set_var(
        "XTASK_QEMU_APPEND",
        [existing.as_str(), cmdline.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" "),
    );
    let set_default = |key: &str, value: &str| {
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    };
    set_default(
        "XTASK_SYSTEMD_PID1_SUCCESS_MARKER",
        &format!("{IMAGE_HOSTNAME} login:"),
    );
    set_default(
        "XTASK_SYSTEMD_PID1_FAILURE_MARKER",
        "You are in emergency mode",
    );
    set_default("XTASK_SYSTEMD_PID1_TIMEOUT_SECS", "300");
    set_default("NARF_QEMU_MEM_MB", "4096");

    let result = super::systemd_pid1_cmd(&args.build);

    if let Some(before) = before {
        let after = sha256_file(&disk)?;
        if before != after {
            bail!(
                "xtask cachyos-root-smoke: narf.disks=root-ro boot MODIFIED {}",
                disk.display()
            );
        }
        println!(
            "xtask cachyos-root-smoke: image unchanged by the root-ro boot (SHA-256 verified)"
        );
    }
    result?;
    println!("xtask cachyos-root-smoke: OK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_is_the_bare_metal_shape() {
        assert_eq!(
            smoke_cmdline("u", false, &[]),
            "root=UUID=u rootflags=subvol=/@ systemd_pid1 narf.disks=root-ro"
        );
        assert_eq!(
            smoke_cmdline("u", true, &["quiet".into()]),
            "root=UUID=u rootflags=subvol=/@ systemd_pid1 narf.disks=root-rw quiet"
        );
    }
}
