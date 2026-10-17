//! `cargo xtask btrfs-rootrw-interop`: prove that `narf.disks=root-rw`
//! writes leave a CachyOS-shaped btrfs root `btrfs check`-clean.
//!
//! 1. Build, unprivileged, a GPT disk image (FAT32 ESP + btrfs root) whose
//!    btrfs has the installed root's shape: `mkfs.btrfs` with nodesize 16 KiB,
//!    4 KiB sectors, crc32c, free-space tree, no-holes, `--compress zstd:1`,
//!    and the CachyOS subvolumes `@ @home @root @srv @cache @tmp @log`, with
//!    a pacman local db, `/etc/hostname`, a zstd-compressed file, a home
//!    directory and `chattr +C` journals. Two variants: the host's exact
//!    flags (with BLOCK_GROUP_TREE) and the same without BLOCK_GROUP_TREE.
//! 2. Boot NARF on it under `narf.disks=root-rw root=UUID=…
//!    rootflags=subvol=/<sv> narf.rootrw_interop=<mode>` once per subvolume
//!    (`@`, `@home`, `@log`); the kernel-side workload
//!    (`drivers/fs/btrfs/src/interop.rs`) writes, syncs, reads back and
//!    prints a verdict.
//! 3. After every boot: every byte outside the root partition (GPT, ESP) is
//!    unchanged, and host `btrfs check --readonly --check-data-csum` on the
//!    partition is clean. At the end, `btrfs restore` (an independent,
//!    unprivileged reader) extracts each subvolume and the written files are
//!    compared byte for byte. A `mount -o loop,ro` is attempted only when
//!    passwordless `sudo -n` is available; otherwise it is skipped with a note
//!    (unprivileged loop mounts of btrfs are not possible).
//! 4. The BLOCK_GROUP_TREE variant is booted the same way. Until the writer
//!    maintains the block-group tree it must be REFUSED read-write — the boot
//!    names BLOCK_GROUP_TREE in its refusal and the image stays bit-identical
//!    (`--bgt=refused`, the default). `--bgt=writable` runs the full write
//!    test on it instead, for when that support lands.
//!
//! The filesystem UUID is deliberately not the host root's.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

/// btrfs fsid of the interop image (not the host's).
pub const IMAGE_UUID: &str = "c4c405ee-0000-4a11-9e57-0000000a7e57";
/// Must equal `narf_drivers_fs_btrfs::interop::MACHINE_ID`.
const MACHINE_ID: &str = "4e415246c4c405ee00000000000000aa";
const ESP_MIB: u64 = 32;
const ROOT_MIB: u64 = 512;
const ESP_START: u64 = 2048;

/// What the BLOCK_GROUP_TREE (host-exact) variant must do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum BgtExpect {
    /// Refused read-write (current writer): the image must stay unchanged.
    Refused,
    /// Written like the non-BGT variant (once the writer maintains BGT).
    Writable,
    /// Do not boot the BGT variant.
    Skip,
}

/// Options for `cargo xtask btrfs-rootrw-interop`.
#[derive(clap::Args, Clone)]
pub struct Args {
    #[command(flatten)]
    pub build: super::BuildArgs,

    /// Expected outcome for the host-exact BLOCK_GROUP_TREE image.
    #[arg(long, value_enum, default_value_t = BgtExpect::Refused)]
    pub bgt: BgtExpect,

    /// Seconds to wait for each boot's verdict.
    #[arg(long, default_value_t = 240)]
    pub timeout: u64,
}

fn tool(name: &str) -> Result<()> {
    if super::which(name).is_none() {
        bail!("btrfs-rootrw-interop: `{name}` not on $PATH");
    }
    Ok(())
}

fn run(cmd: &mut Command, what: &str) -> Result<String> {
    let out = cmd.output().with_context(|| format!("running {what}"))?;
    if !out.status.success() {
        bail!(
            "btrfs-rootrw-interop: {what} failed ({}):\n{}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Deterministic bytes; must equal `interop::pattern`.
pub fn pattern(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))
}

/// The `--rootdir` tree: top-level directories become the subvolumes.
fn stage(dir: &Path) -> Result<()> {
    let _ = std::fs::remove_dir_all(dir);
    let at = dir.join("@");
    write(&at.join("etc/hostname"), b"cachyos\n")?;
    write(
        &at.join("etc/machine-id"),
        format!("{MACHINE_ID}\n").as_bytes(),
    )?;
    write(
        &at.join("etc/fstab"),
        format!("UUID={IMAGE_UUID} / btrfs subvol=/@,defaults,noatime,compress=zstd:1 0 0\n")
            .as_bytes(),
    )?;
    let local = at.join("var/lib/pacman/local");
    write(&local.join("ALPM_DB_VERSION"), b"8\n")?;
    for i in 0..40u32 {
        let pkg = local.join(format!("pkg{i:02}-1.{i}-1"));
        let desc = format!(
            "%NAME%\npkg{i:02}\n\n%VERSION%\n1.{i}-1\n\n%DESC%\n{}\n",
            "x".repeat(200)
        );
        write(&pkg.join("desc"), desc.as_bytes())?;
        write(
            &pkg.join("files"),
            format!("%FILES%\nusr/lib/pkg{i:02}/\n")
                .repeat(40)
                .as_bytes(),
        )?;
    }
    let old = local.join("narf-old-0.9-1");
    write(
        &old.join("desc"),
        "%NAME%\nnarf-old\n".repeat(64).as_bytes(),
    )?;
    write(
        &old.join("files"),
        "%FILES%\nusr/share/narf-old/\n".repeat(128).as_bytes(),
    )?;
    write(&old.join("mtree"), &pattern(3, 6000))?;
    // Highly compressible so mkfs stores it as zstd extents.
    let text: Vec<u8> = (0..(512 * 1024))
        .map(|i| b"narf root-rw interop line\n"[i % 26])
        .collect();
    write(&at.join("usr/share/narf/compressible.txt"), &text)?;
    write(
        &at.join("usr/share/narf/delete-me.bin"),
        &pattern(5, 300 * 1024),
    )?;
    for sub in [
        "home",
        "root",
        "srv",
        "var/cache",
        "var/tmp",
        "var/log",
        "boot/efi",
        "tmp",
    ] {
        std::fs::create_dir_all(at.join(sub))?;
    }
    let home = dir.join("@home/narf");
    write(&home.join(".bash_history"), b"ls\npacman -Syu\n")?;
    write(&home.join("scratch.tmp"), &pattern(9, 70 * 1024))?;
    write(
        &home.join("Documents/readme.txt"),
        "home sweet home\n".repeat(500).as_bytes(),
    )?;
    let journal = dir.join(format!("@log/journal/{MACHINE_ID}"));
    write(&journal.join("system.journal"), &pattern(20, 256 * 1024))?;
    write(
        &journal.join("system@old.journal"),
        "old journal entry\n".repeat(8000).as_bytes(),
    )?;
    for sub in ["@root", "@srv", "@cache", "@tmp"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    Ok(())
}

/// Build the GPT disk image at `out` with btrfs `features`.
fn build_image(work: &Path, out: &Path, features: &str) -> Result<()> {
    let stage_dir = work.join("stage");
    stage(&stage_dir)?;
    let root_img = work.join("root.btrfs");
    let esp_img = work.join("esp.fat");
    let _ = std::fs::remove_file(&root_img);
    let _ = std::fs::remove_file(&esp_img);
    std::fs::File::create(&root_img)?.set_len(ROOT_MIB << 20)?;
    let journal = format!("@log/journal/{MACHINE_ID}");
    let mut mkfs = Command::new("mkfs.btrfs");
    mkfs.args([
        "-q", "-f", "-U", IMAGE_UUID, "-L", "cachyos", "-n", "16384", "-s", "4096",
    ])
    .args(["--csum", "crc32c", "-O", features, "--compress", "zstd:1"])
    .arg("--rootdir")
    .arg(&stage_dir);
    for sv in ["@", "@home", "@root", "@srv", "@cache", "@tmp", "@log"] {
        mkfs.args(["--subvol", &format!("rw:{sv}")]);
    }
    // journald's chattr +C (NODATACOW|NODATASUM) on the journal directory
    // and the active journal.
    mkfs.args(["--inode-flags", &format!("nodatacow:{journal}")]);
    mkfs.args([
        "--inode-flags",
        &format!("nodatacow:{journal}/system.journal"),
    ]);
    mkfs.arg(&root_img);
    run(&mut mkfs, "mkfs.btrfs")?;

    std::fs::File::create(&esp_img)?.set_len(ESP_MIB << 20)?;
    run(
        Command::new("mkfs.fat")
            .args(["-F", "32", "-i", "CA50EF16", "-n", "EFI"])
            .arg(&esp_img),
        "mkfs.fat",
    )?;
    let esp_sectors = ESP_MIB * 2048;
    let root_start = ESP_START + esp_sectors;
    let root_sectors = ROOT_MIB * 2048;
    let total = root_start + root_sectors + 2048;
    let _ = std::fs::remove_file(out);
    std::fs::File::create(out)?.set_len(total * 512)?;
    let table = format!(
        "label: gpt\nstart={ESP_START}, size={esp_sectors}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=\"EFI system partition\"\n\
         start={root_start}, size={root_sectors}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=\"root\"\n"
    );
    let mut sfdisk = Command::new("sfdisk")
        .arg("-q")
        .arg(out)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("spawn sfdisk")?;
    std::io::Write::write_all(
        sfdisk
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("sfdisk stdin"))?,
        table.as_bytes(),
    )?;
    if !sfdisk.wait()?.success() {
        bail!("btrfs-rootrw-interop: sfdisk failed");
    }
    for (src, start) in [(&esp_img, ESP_START), (&root_img, root_start)] {
        run(
            Command::new("dd")
                .arg(format!("if={}", src.display()))
                .arg(format!("of={}", out.display()))
                .args([
                    "bs=1M",
                    &format!("seek={}", start / 2048),
                    "conv=notrunc,sparse",
                    "status=none",
                ]),
            "dd",
        )?;
    }
    Ok(())
}

fn root_range() -> (u64, u64) {
    let start = (ESP_START + ESP_MIB * 2048) * 512;
    (start, start + (ROOT_MIB << 20))
}

/// SHA-256 of the bytes outside the root partition, and of the partition.
fn hashes(image: &Path) -> Result<([u8; 32], [u8; 32])> {
    let (start, end) = root_range();
    let mut file = std::fs::File::open(image)?;
    let mut outside = Sha256::new();
    let mut inside = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut pos = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        let (lo, hi) = (pos, pos + n as u64);
        // The part of this chunk inside [start, end).
        let a = start.clamp(lo, hi) - lo;
        let b = end.clamp(lo, hi) - lo;
        outside.update(&chunk[..a as usize]);
        inside.update(&chunk[a as usize..b as usize]);
        outside.update(&chunk[b as usize..]);
        pos += n as u64;
    }
    Ok((outside.finalize().into(), inside.finalize().into()))
}

fn extract_partition(image: &Path, out: &Path) -> Result<()> {
    let (start, _) = root_range();
    run(
        Command::new("dd")
            .arg(format!("if={}", image.display()))
            .arg(format!("of={}", out.display()))
            .args([
                "bs=1M",
                &format!("skip={}", start >> 20),
                &format!("count={ROOT_MIB}"),
            ])
            .args(["conv=sparse", "status=none"]),
        "dd (extract root partition)",
    )?;
    Ok(())
}

fn btrfs_check(part: &Path) -> Result<()> {
    let out = Command::new("btrfs")
        .args(["check", "--readonly", "--check-data-csum"])
        .arg(part)
        .output()
        .context("running btrfs check")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() || text.contains("ERROR") || text.contains("error(s) found") {
        bail!("btrfs-rootrw-interop: btrfs check found errors:\n{text}");
    }
    println!("btrfs-rootrw-interop: btrfs check --readonly --check-data-csum: clean");
    Ok(())
}

/// Boot `kernel` on `image` with `cmdline`; return the serial lines once a
/// verdict line appears (or the timeout passes).
fn boot(args: &Args, kernel: &Path, image: &Path, cmdline: &str) -> Result<Vec<String>> {
    std::env::set_var("NARF_NVME_IMG", image);
    std::env::set_var("XTASK_QEMU_APPEND", cmdline);
    let mut cmd = Command::new(args.build.arch.qemu_bin());
    cmd.args(super::qemu_boot_args(&args.build, kernel)?);
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    println!(
        "btrfs-rootrw-interop: boot `{cmdline}` on {}",
        image.display()
    );
    let mut child = cmd.spawn().context("spawn qemu")?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("qemu stdout"))?;
    let lines = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicU8::new(0));
    let (lines2, done2) = (lines.clone(), done.clone());
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let verdict = [
                "ROOTRW-INTEROP: PASS",
                "ROOTRW-INTEROP: FAIL",
                "ROOTRW-INTEROP: NO-ROOT",
            ]
            .iter()
            .any(|m| line.contains(m));
            if line.contains("ROOTRW-INTEROP: detail") {
                println!("  | {line}");
            }
            if verdict
                || line.contains("disks:")
                || line.contains("btrfs ")
                || line.contains("root-mount")
            {
                println!("  | {line}");
            }
            if line.contains("panicked at") || line.contains("KERNEL PANIC") {
                done2.store(2, Ordering::Release);
            }
            if let Ok(mut g) = lines2.lock() {
                g.push(line);
            }
            if verdict {
                done2.store(1, Ordering::Release);
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(args.timeout);
    loop {
        if matches!(child.try_wait(), Ok(Some(_)))
            || done.load(Ordering::Acquire) != 0
            || std::time::Instant::now() >= deadline
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    // The workload synced before printing; give QEMU a moment to drain the
    // last guest writes into the image file, then stop it.
    std::thread::sleep(Duration::from_millis(500));
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let lines = lines.lock().map(|g| g.clone()).unwrap_or_default();
    if done.load(Ordering::Acquire) == 2 {
        bail!("btrfs-rootrw-interop: kernel panic");
    }
    Ok(lines)
}

fn verdict(lines: &[String]) -> Option<&str> {
    lines
        .iter()
        .filter(|l| !l.contains("ROOTRW-INTEROP: detail"))
        .find_map(|l| l.split_once("ROOTRW-INTEROP: ").map(|(_, v)| v.trim()))
}

fn cmdline(subvol: &str, mode: &str) -> String {
    format!(
        "narf.disks=root-rw root=UUID={IMAGE_UUID} rootflags=subvol=/{subvol} narf.rootrw_interop={mode}"
    )
}

/// `(subvolume id, name)` from `btrfs inspect-internal dump-tree -t root`.
fn subvol_ids(part: &Path) -> Result<Vec<(u64, String)>> {
    let text = run(
        Command::new("btrfs")
            .args(["inspect-internal", "dump-tree", "-t", "root"])
            .arg(part),
        "btrfs dump-tree -t root",
    )?;
    let mut out = Vec::new();
    let mut pending: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim();
        // `item N key (FS_TREE ROOT_REF 256) ...` then `root ref key ... name @`
        let rest = line
            .split_once("key (5 ROOT_REF ")
            .or_else(|| line.split_once("key (FS_TREE ROOT_REF "))
            .map(|(_, r)| r);
        if let Some(rest) = rest {
            pending = rest.split(')').next().and_then(|n| n.trim().parse().ok());
        } else if let (Some(id), Some(name)) = (pending, line.split_once("name ").map(|(_, n)| n)) {
            out.push((id, name.trim().to_string()));
            pending = None;
        }
    }
    Ok(out)
}

/// Extract subvolume `name` with `btrfs restore` and compare `expect`ed files.
fn restore_and_compare(
    part: &Path,
    work: &Path,
    ids: &[(u64, String)],
    name: &str,
    expect: &[(&str, Vec<u8>)],
    absent: &[&str],
) -> Result<()> {
    let id = ids
        .iter()
        .find(|(_, n)| n == name)
        .map(|(id, _)| *id)
        .ok_or_else(|| anyhow!("subvolume {name} not found in the root tree"))?;
    let dest = work.join(format!("restore-{}", name.trim_start_matches('@')));
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::create_dir_all(&dest)?;
    run(
        Command::new("btrfs")
            .args(["restore", "-r", &id.to_string()])
            .arg(part)
            .arg(&dest),
        "btrfs restore",
    )?;
    for (path, want) in expect {
        let got = std::fs::read(dest.join(path))
            .with_context(|| format!("{name}/{path} missing after restore"))?;
        if &got != want {
            bail!(
                "btrfs-rootrw-interop: {name}/{path} differs after restore ({} vs {} bytes)",
                got.len(),
                want.len()
            );
        }
    }
    for path in absent {
        if dest.join(path).exists() {
            bail!("btrfs-rootrw-interop: {name}/{path} should have been removed");
        }
    }
    println!(
        "btrfs-rootrw-interop: btrfs restore of {name}: {} files match",
        expect.len()
    );
    Ok(())
}

fn try_loop_mount(part: &Path, work: &Path) {
    let sudo_ok = Command::new("sudo")
        .args(["-n", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !sudo_ok {
        println!(
            "btrfs-rootrw-interop: NOTE: host `mount -o loop,ro` skipped — needs root \
             (no passwordless sudo); btrfs check + btrfs restore verified the image instead"
        );
        return;
    }
    let mnt = work.join("mnt");
    let _ = std::fs::create_dir_all(&mnt);
    let ok = Command::new("sudo")
        .args(["-n", "mount", "-t", "btrfs", "-o", "loop,ro,subvol=/@"])
        .arg(part)
        .arg(&mnt)
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        let read = std::fs::read(mnt.join("etc/hostname")).unwrap_or_default();
        println!(
            "btrfs-rootrw-interop: host loop mount ro OK (etc/hostname = {:?})",
            String::from_utf8_lossy(&read).trim()
        );
        let _ = Command::new("sudo")
            .args(["-n", "umount"])
            .arg(&mnt)
            .status();
    } else {
        println!("btrfs-rootrw-interop: WARNING: host loop mount failed");
    }
}

fn write_boots(args: &Args, kernel: &Path, image: &Path, work: &Path, label: &str) -> Result<()> {
    let part = work.join(format!("{label}-part.img"));
    for (subvol, mode) in [("@", "root"), ("@home", "home"), ("@log", "log")] {
        let (outside_before, _) = hashes(image)?;
        let lines = boot(args, kernel, image, &cmdline(subvol, mode))?;
        match verdict(&lines) {
            Some(v) if v == format!("PASS {mode}") => {}
            Some(v) => bail!("btrfs-rootrw-interop: {label} {mode}: {v}"),
            None => bail!("btrfs-rootrw-interop: {label} {mode}: no verdict before timeout"),
        }
        if !lines
            .iter()
            .any(|l| l.contains("disks: WRITABLE:") && l.contains(IMAGE_UUID))
        {
            bail!("btrfs-rootrw-interop: the root-rw banner naming the writable UUID is missing");
        }
        let (outside_after, _) = hashes(image)?;
        if outside_before != outside_after {
            bail!("btrfs-rootrw-interop: {label} {mode}: bytes OUTSIDE the root partition changed (GPT/ESP)");
        }
        println!("btrfs-rootrw-interop: {label} {mode}: PASS; GPT + ESP unchanged");
        extract_partition(image, &part)?;
        btrfs_check(&part)?;
    }
    let ids = subvol_ids(&part)?;
    let compressible = {
        let mut text: Vec<u8> = (0..(512 * 1024))
            .map(|i| b"narf root-rw interop line\n"[i % 26])
            .collect();
        text[40_960..40_960 + 8192].copy_from_slice(&pattern(7, 8192));
        text
    };
    restore_and_compare(
        &part,
        work,
        &ids,
        "@",
        &[
            ("etc/hostname", b"narf-interop\n".to_vec()),
            ("var/lib/pacman/local/ALPM_DB_VERSION", b"9\n".to_vec()),
            (
                "var/lib/pacman/local/narf-interop-1.0-1/desc",
                include_desc(),
            ),
            ("usr/share/narf/compressible.txt", compressible),
        ],
        &[
            "var/lib/pacman/local/narf-old-0.9-1",
            "usr/share/narf/delete-me.bin",
        ],
    )?;
    restore_and_compare(
        &part,
        work,
        &ids,
        "@home",
        &[
            (
                "narf/.config/narf.conf",
                b"[narf]\nroot_rw = true\n".to_vec(),
            ),
            ("narf/notes.bin", pattern(11, 1 << 20)),
        ],
        &["narf/scratch.tmp"],
    )?;
    let mut journal = pattern(20, 256 * 1024);
    journal[..256].copy_from_slice(&pattern(21, 256));
    journal.extend_from_slice(&pattern(22, 32 * 4096));
    restore_and_compare(
        &part,
        work,
        &ids,
        "@log",
        &[
            (
                &format!("journal/{MACHINE_ID}/system@narf-0001.journal"),
                journal,
            ),
            (
                &format!("journal/{MACHINE_ID}/system.journal"),
                pattern(23, 64 * 1024),
            ),
        ],
        &[&format!("journal/{MACHINE_ID}/system@old.journal")],
    )?;
    try_loop_mount(&part, work);
    Ok(())
}

/// Must equal `interop::PKG_DESC`.
fn include_desc() -> Vec<u8> {
    b"%NAME%\nnarf-interop\n\n%VERSION%\n1.0-1\n\n%DESC%\nNARF root-rw interop package\n\n%ARCH%\nx86_64\n"
        .to_vec()
}

pub fn run_cmd(args: &Args) -> Result<()> {
    if !matches!(args.build.arch, super::Arch::X86_64) {
        bail!("btrfs-rootrw-interop: x86_64 only");
    }
    for t in ["mkfs.btrfs", "btrfs", "mkfs.fat", "sfdisk", "dd"] {
        tool(t)?;
    }
    let root = super::workspace_root()?;
    let work = root.join("target/btrfs-rootrw-interop");
    std::fs::create_dir_all(&work)?;
    let kernel = super::cargo_build(&args.build, &root)?.join(&args.build.package);
    if !kernel.exists() {
        bail!("expected kernel at {}", kernel.display());
    }

    // Host flags minus BLOCK_GROUP_TREE: the full write test.
    let plain = work.join("interop-nobgt.img");
    build_image(&work, &plain, "free-space-tree,no-holes,^block-group-tree")?;
    write_boots(args, &kernel, &plain, &work, "no-bgt")?;

    // The host's exact flags.
    let bgt = work.join("interop-bgt.img");
    match args.bgt {
        BgtExpect::Skip => println!("btrfs-rootrw-interop: BLOCK_GROUP_TREE variant skipped"),
        BgtExpect::Writable => {
            build_image(&work, &bgt, "block-group-tree,free-space-tree,no-holes")?;
            write_boots(args, &kernel, &bgt, &work, "bgt")?;
        }
        BgtExpect::Refused => {
            build_image(&work, &bgt, "block-group-tree,free-space-tree,no-holes")?;
            let before = hashes(&bgt)?;
            let lines = boot(args, &kernel, &bgt, &cmdline("@", "root"))?;
            let after = hashes(&bgt)?;
            let refused = lines
                .iter()
                .any(|l| l.contains("REFUSING read-write mount") && l.contains("BLOCK_GROUP_TREE"));
            if !refused {
                bail!("btrfs-rootrw-interop: the BLOCK_GROUP_TREE image was not refused read-write by name");
            }
            if !lines.iter().any(|l| l.contains("ROOT MOUNT FAILED")) {
                bail!("btrfs-rootrw-interop: the refused root-rw boot did not fail visibly");
            }
            if before != after {
                bail!("btrfs-rootrw-interop: the refused BLOCK_GROUP_TREE image was MODIFIED");
            }
            let part = work.join("bgt-part.img");
            extract_partition(&bgt, &part)?;
            btrfs_check(&part)?;
            println!(
                "btrfs-rootrw-interop: BLOCK_GROUP_TREE image refused read-write (named), failed visibly, \
                 bit-identical (expected until the writer maintains the block-group tree)"
            );
        }
    }
    println!("btrfs-rootrw-interop: OK");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn cmdline_shape() {
        assert_eq!(
            super::cmdline("@home", "home"),
            format!(
                "narf.disks=root-rw root=UUID={} rootflags=subvol=/@home narf.rootrw_interop=home",
                super::IMAGE_UUID
            )
        );
    }
}
