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

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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
/// Decoy disk for the first NVMe controller.
const DECOY_IMAGE: &str = "target/narf-cachyos-decoy.img";
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

    /// Stop at the login prompt instead of logging in as root and running
    /// the post-boot checks.
    #[arg(long)]
    pub no_login: bool,

    /// Seconds to wait for the login prompt.
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,
}

/// Printed by the post-login check script once it ran to the end. Written as
/// `$((40+2))` in the typed command so the echoed command line cannot match.
const DONE_MARKER: &str = "NARF-CACHYOS-ROOT-42-DONE";

/// What the logged-in root shell runs, one line at a time: the failed units
/// (the smoke's report), the mounts systemd made from fstab, the boot state
/// and the udev view of the root, then the done marker.
const CHECK_COMMANDS: &[&str] = &[
    "stty -echo; export PAGER=cat SYSTEMD_COLORS=0",
    "systemctl --no-pager --no-legend --plain --failed",
    "echo NARF-STATE $(systemctl is-system-running)",
    "findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS -t btrfs,vfat,tmpfs",
    "echo NARF-VIRT $(systemd-detect-virt)",
    "mkdir -p /narf-smoke && echo ok > /narf-smoke/probe && sync /narf-smoke/probe && echo NARF-WRITE-ROOT $(cat /narf-smoke/probe)",
    "echo ok > /home/narf-smoke-probe && echo NARF-WRITE-HOME ok || echo NARF-WRITE-HOME refused",
    "ls /var/log/journal 2>/dev/null | head -n 3 | sed 's/^/NARF-JOURNAL /'",
    "udevadm info -q property -n /dev/disk/by-uuid/c4c405ee-0000-4a11-9e57-00000000c0de | grep -E 'DEVNAME|ID_FS_TYPE|BTRFS|SYSTEMD_READY'",
    "for u in $(systemctl --no-legend --plain --failed | cut -d' ' -f1); do echo NARF-UNIT $u; journalctl -b --no-pager -o cat -n 8 -u $u; done",
    "journalctl -b --no-pager -p warning -o cat | tail -n 40",
    "echo NARF-CACHYOS-ROOT-$((40+2))-DONE",
];

const PANIC_MARKERS: &[&str] = &[
    "*** KERNEL PANIC ***",
    "panicked at",
    "double fault",
    "general protection",
    "kernel page fault",
];

/// Type one line into the serial console a few bytes at a time: the 16550's
/// receive FIFO is 16 bytes, and a long burst loses characters.
fn type_slowly(stdin: &mut impl Write, line: &str) -> Result<()> {
    for chunk in line.as_bytes().chunks(4) {
        stdin.write_all(chunk)?;
        stdin.flush()?;
        std::thread::sleep(Duration::from_millis(20));
    }
    stdin.write_all(b"\r")?;
    stdin.flush()?;
    Ok(())
}

/// Drop terminal control sequences (CSI, and OSC such as systemd's 3008
/// context markers) from captured console output.
fn strip_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                Some('[') => {
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() || c == '~' {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\r' => {}
            c => out.push(c),
        }
    }
    out
}

fn print_report(report: &str) {
    println!("\nxtask cachyos-root-smoke: ==== post-login report ====");
    let clean = strip_escapes(report);
    for line in clean.lines() {
        let line = line.trim_end();
        if line.is_empty()
            || line.contains("$((40+2))")
            || line.starts_with("[root@")
            || CHECK_COMMANDS.iter().any(|c| line.ends_with(c))
        {
            continue;
        }
        println!("  {line}");
    }
}

/// Boot the kernel with the disks and command line already in the
/// environment, wait for agetty's prompt, then (unless `--no-login`) log in
/// as root through PAM and run [`CHECK_COMMANDS`].
fn boot_and_login(args: &Args) -> Result<()> {
    let mut build = args.build.clone();
    super::configure_systemd_pid1_build(&mut build, false);
    let root = super::workspace_root()?;
    let out_dir = super::cargo_build(&build, &root)?;
    let kernel = out_dir.join(&build.package);
    let qemu = build.arch.qemu_bin();
    let mut child = Command::new(qemu)
        .args(super::qemu_boot_args(&build, &kernel)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;
    let mut stdin = child.stdin.take().context("qemu stdin")?;
    let mut stdout = child.stdout.take().context("qemu stdout")?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = std::io::stdout().write_all(&buf[..n]);
                    let _ = std::io::stdout().flush();
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut serial = String::new();
    // Byte stream, not lines: the prompts end without a newline.
    let wait_for =
        |needles: &[&str], from: usize, secs: u64, serial: &mut String| -> Result<usize> {
            let deadline = Instant::now() + Duration::from_secs(secs);
            loop {
                if let Some(hit) = PANIC_MARKERS.iter().find(|m| serial[from..].contains(*m)) {
                    return Err(anyhow::anyhow!("kernel panic marker {hit:?}"));
                }
                if let Some(hit) = needles.iter().position(|n| serial[from..].contains(*n)) {
                    return Ok(hit);
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(anyhow::anyhow!("timed out waiting for {needles:?}"));
                }
                match rx.recv_timeout(left.min(Duration::from_millis(500))) {
                    Ok(bytes) => serial.push_str(&String::from_utf8_lossy(&bytes)),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(anyhow::anyhow!("QEMU exited"));
                    }
                }
            }
        };
    let prompt = format!("{IMAGE_HOSTNAME} login:");
    let result = (|| -> Result<()> {
        let emergency = match wait_for(
            &[&prompt, "You are in emergency mode"],
            0,
            args.timeout,
            &mut serial,
        )? {
            0 => {
                println!("\nxtask cachyos-root-smoke: reached {prompt:?}");
                false
            }
            _ => true,
        };
        if emergency {
            // Collect the same report from the maintenance shell, then fail.
            let mark = serial.len();
            if wait_for(&["Control-D", "root password"], mark, 60, &mut serial).is_ok() {
                std::thread::sleep(Duration::from_secs(1));
                for byte in b"narf\r" {
                    stdin.write_all(&[*byte])?;
                    stdin.flush()?;
                    std::thread::sleep(Duration::from_millis(50));
                }
                let mark = serial.len();
                if wait_for(&["]# ", "# "], mark, 60, &mut serial).is_ok() {
                    let mark = serial.len();
                    for line in CHECK_COMMANDS {
                        type_slowly(&mut stdin, line)?;
                        std::thread::sleep(Duration::from_millis(500));
                    }
                    let _ = wait_for(&[DONE_MARKER], mark, 180, &mut serial);
                    print_report(&serial[mark..]);
                }
            }
            bail!("systemd fell back to emergency mode");
        }
        if args.no_login {
            return Ok(());
        }
        // Let both gettys finish printing their banners before typing.
        std::thread::sleep(Duration::from_secs(3));
        let mark = serial.len();
        // Type slowly: the serial line has a small receive FIFO.
        let mut typed = false;
        for attempt in 0..4 {
            for byte in b"root\r" {
                stdin.write_all(&[*byte])?;
                stdin.flush()?;
                std::thread::sleep(Duration::from_millis(50));
            }
            if wait_for(&["Password:"], mark, 20, &mut serial).is_ok() {
                typed = true;
                break;
            }
            println!("\nxtask cachyos-root-smoke: no password prompt yet (attempt {attempt})");
        }
        if !typed {
            bail!("agetty/login never asked for a password");
        }
        let mark = serial.len();
        for byte in b"narf\r" {
            stdin.write_all(&[*byte])?;
            stdin.flush()?;
            std::thread::sleep(Duration::from_millis(50));
        }
        if wait_for(&["]# ", "Login incorrect"], mark, 90, &mut serial)? == 1 {
            bail!("PAM login as root failed");
        }
        println!("\nxtask cachyos-root-smoke: logged in as root");
        let mark = serial.len();
        for line in CHECK_COMMANDS {
            type_slowly(&mut stdin, line)?;
            std::thread::sleep(Duration::from_millis(500));
        }
        wait_for(&[DONE_MARKER], mark, 180, &mut serial)?;
        print_report(&serial[mark..]);
        Ok(())
    })();
    let _ = child.kill();
    let _ = child.wait();
    drop(rx);
    let _ = reader.join();
    result.map_err(|e| anyhow::anyhow!("xtask cachyos-root-smoke: {e}"))
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

pub(crate) fn ensure_image(root: &Path, rebuild: bool) -> Result<PathBuf> {
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

/// A 64 MiB disk with a recognisable pattern: no filesystem, so nothing may
/// mount it, and any write shows up in its hash.
fn write_decoy(path: &Path) -> Result<()> {
    let mut data = vec![0u8; 64 << 20];
    for (i, chunk) in data.chunks_mut(512).enumerate() {
        chunk[..16].copy_from_slice(b"NARF-DECOY-DISK!");
        chunk[16..24].copy_from_slice(&(i as u64).to_le_bytes());
    }
    std::fs::write(path, &data).with_context(|| format!("write {}", path.display()))
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
    // The host has two NVMe controllers and CachyOS is on the second. Put a
    // decoy disk on the first, so root=UUID= has to find the root by identity
    // rather than by position. The decoy must come out unchanged in both
    // modes.
    let decoy = root.join(DECOY_IMAGE);
    write_decoy(&decoy)?;
    let decoy_before = sha256_file(&decoy)?;

    let cmdline = smoke_cmdline(IMAGE_BTRFS_UUID, args.rw, &args.cmdline);
    println!(
        "xtask cachyos-root-smoke: disk {} cmdline `{cmdline}`",
        disk.display()
    );
    std::env::set_var("NARF_NVME_IMG", &decoy);
    std::env::set_var("NARF_NVME2_IMG", &disk);
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
    if std::env::var_os("NARF_QEMU_MEM_MB").is_none() {
        std::env::set_var("NARF_QEMU_MEM_MB", "4096");
    }

    let result = boot_and_login(args);

    if sha256_file(&decoy)? != decoy_before {
        bail!(
            "xtask cachyos-root-smoke: the boot MODIFIED the decoy disk {}",
            decoy.display()
        );
    }
    println!("xtask cachyos-root-smoke: decoy NVMe disk unchanged (SHA-256 verified)");
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
    fn report_strips_console_escapes() {
        assert_eq!(
            strip_escapes("\u{1b}]3008;start=x;type=shell\u{1b}\\NARF-VIRT kvm\r\n\u{1b}[?2004h"),
            "NARF-VIRT kvm\n"
        );
    }

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
