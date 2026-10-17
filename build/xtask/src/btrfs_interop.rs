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
//!    (`@`, `@home`, `@log`, and `files` on `@`: truncate/fallocate/punch/
//!    zero-range and remount ro→rw); the kernel-side workload
//!    (`drivers/fs/btrfs/src/interop.rs`) writes, syncs, reads back and
//!    prints a verdict.
//! 3. After every boot: every byte outside the root partition (GPT, ESP) is
//!    unchanged, and host `btrfs check --readonly --check-data-csum` on the
//!    partition is clean. At the end, `btrfs restore` (an independent,
//!    unprivileged reader) extracts each subvolume and the written files are
//!    compared byte for byte. A `mount -o loop,ro` is attempted only when
//!    passwordless `sudo -n` is available; otherwise it is skipped with a note
//!    (unprivileged loop mounts of btrfs are not possible).
//! 4. The BLOCK_GROUP_TREE (host-exact) variant gets the same boots and
//!    checks (`--bgt=writable`, the default). A fourth boot per image
//!    (`fstab`) mounts the six other subvolumes read-write through the one
//!    shared core and writes into all seven. `--bgt=refused` instead requires
//!    the BGT image to be refused by name and stay bit-identical (a writer
//!    without block-group-tree support).
//!
//! 5. A `narf.disks=root-ro` boot with a `narf.bootlog=` USB stick: the
//!    stick's log partition (and nothing else) is written, after the root
//!    mounted, and the root image stays bit-identical (`--bootlog-only` runs
//!    just this).
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
    /// Refused read-write (a writer without block-group-tree support): the
    /// image must stay unchanged.
    Refused,
    /// Written like the non-BGT variant (the default).
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
    #[arg(long, value_enum, default_value_t = BgtExpect::Writable)]
    pub bgt: BgtExpect,

    /// Run only the root-ro boot-log stick check.
    #[arg(long)]
    pub bootlog_only: bool,

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
    let verdicts = [
        "ROOTRW-INTEROP: PASS",
        "ROOTRW-INTEROP: FAIL",
        "ROOTRW-INTEROP: NO-ROOT",
    ];
    Ok(
        boot_with(args, kernel, image, cmdline, &[], &verdicts, 500)?
            .into_iter()
            .map(|(_, line)| line)
            .collect(),
    )
}

/// Boot with extra QEMU arguments; stop `grace_ms` after the first line
/// containing one of `stop`. Each line carries the host seconds since QEMU
/// started.
fn boot_with(
    args: &Args,
    kernel: &Path,
    image: &Path,
    cmdline: &str,
    extra: &[String],
    stop: &[&'static str],
    grace_ms: u64,
) -> Result<Vec<(f64, String)>> {
    std::env::set_var("NARF_NVME_IMG", image);
    std::env::set_var("XTASK_QEMU_APPEND", cmdline);
    let mut cmd = Command::new(args.build.arch.qemu_bin());
    cmd.args(super::qemu_boot_args(&args.build, kernel)?);
    cmd.args(extra);
    let started = std::time::Instant::now();
    let stop: Vec<&'static str> = stop.to_vec();
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
            let verdict = stop.iter().any(|m| line.contains(m));
            if line.contains("ROOTRW-INTEROP: detail") {
                println!("  | {line}");
            }
            if verdict
                || line.contains("disks:")
                || line.contains("btrfs ")
                || line.contains("root-mount")
                || line.contains("bootlog:")
            {
                println!("  | {line}");
            }
            if line.contains("panicked at") || line.contains("KERNEL PANIC") {
                done2.store(2, Ordering::Release);
            }
            if let Ok(mut g) = lines2.lock() {
                g.push((started.elapsed().as_secs_f64(), line));
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
    // The workload synced before printing (or, for the boot log, the next
    // flushes are due); give QEMU a moment to drain the last guest writes
    // into the image file, then stop it.
    std::thread::sleep(Duration::from_millis(grace_ms));
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
    for (subvol, mode) in [
        ("@", "root"),
        ("@home", "home"),
        ("@log", "log"),
        ("@", "files"),
        ("@", "fstab"),
    ] {
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
    let sized: Vec<(String, Vec<u8>)> = files_expected()
        .into_iter()
        .map(|(name, data)| (format!("narf-sizes/{name}"), data))
        .collect();
    restore_and_compare(
        &part,
        work,
        &ids,
        "@",
        &sized
            .iter()
            .map(|(n, d)| (n.as_str(), d.clone()))
            .collect::<Vec<_>>(),
        &["narf-sizes/after-ro"],
    )?;
    for subvol in ["@", "@home", "@root", "@srv", "@cache", "@tmp", "@log"] {
        restore_and_compare(
            &part,
            work,
            &ids,
            subvol,
            &[(
                "narf-fstab.txt",
                format!("written through the shared core into {subvol}\n").into_bytes(),
            )],
            &[],
        )?;
    }
    try_loop_mount(&part, work);
    Ok(())
}

/// Must equal `narf_drivers_fs_btrfs::interop::files_expected` (the `files`
/// mode: truncate, fallocate, punch, zero-range, remount ro/rw).
fn files_expected() -> Vec<(&'static str, Vec<u8>)> {
    let mut shrink = pattern(41, 300_000);
    shrink.truncate(150_001);
    shrink.resize(400_000, 0);
    let mut prealloc = vec![0u8; 1 << 20];
    prealloc[256 * 1024..256 * 1024 + 4096].copy_from_slice(&pattern(42, 4096));
    let journal: Vec<u8> = (0..64u32).flat_map(|i| pattern(100 + i, 4096)).collect();
    let mut punch = pattern(44, 200_000);
    punch[10_000..110_000].fill(0);
    let mut zero = pattern(45, 200_000);
    zero[50_000..110_000].fill(0);
    vec![
        ("db.conf", b"short\n".to_vec()),
        ("shrink.bin", shrink),
        ("prealloc.bin", prealloc),
        ("journal.bin", journal),
        ("punch.bin", punch),
        ("zero.bin", zero),
        ("after-rw.txt", b"rw again\n".to_vec()),
    ]
}

/// A 64 MiB MBR stick with one FAT32 partition carrying `/NARFLOG.ID`.
fn build_stick(path: &Path, token: &str, work: &Path) -> Result<()> {
    const MIB: u64 = 1 << 20;
    let _ = std::fs::remove_file(path);
    std::fs::File::create(path)?.set_len(64 * MIB)?;
    let mut sf = Command::new("sfdisk")
        .args(["--quiet", "--no-reread", "--no-tell-kernel"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("spawn sfdisk (stick)")?;
    std::io::Write::write_all(
        sf.stdin.as_mut().ok_or_else(|| anyhow!("sfdisk stdin"))?,
        b"label: dos\nstart=2048, type=c\n",
    )?;
    drop(sf.stdin.take());
    if !sf.wait()?.success() {
        bail!("btrfs-rootrw-interop: sfdisk (stick) failed");
    }
    let spec = format!("{}@@{MIB}", path.display());
    run(
        Command::new("mformat")
            .env("MTOOLS_SKIP_CHECK", "1")
            .args(["-i", &spec, "-F", "-T"])
            .arg(((64 - 1) * MIB / 512).to_string())
            .args(["-H", "2048", "-v", "NARFLOG", "::"]),
        "mformat (stick)",
    )?;
    let id = work.join("NARFLOG.ID");
    std::fs::write(&id, format!("{token}\n"))?;
    run(
        Command::new("mcopy")
            .env("MTOOLS_SKIP_CHECK", "1")
            .args(["-i", &spec])
            .arg(&id)
            .arg("::/NARFLOG.ID"),
        "mcopy NARFLOG.ID",
    )?;
    Ok(())
}

/// The boot-log stick under `root-ro`: the stick (and only it) is written,
/// the root image stays bit-identical, and arming the log does not hold up
/// mounting the root.
fn bootlog_boot(args: &Args, kernel: &Path, image: &Path, work: &Path) -> Result<()> {
    for t in ["mformat", "mcopy", "mdir", "mtype"] {
        tool(t)?;
    }
    let token = "narfinterop0123456789abcdef";
    let stick = work.join("bootlog-stick.img");
    build_stick(&stick, token, work)?;
    let image_before = sha256_whole(image)?;
    let extra = [
        "-drive".to_string(),
        format!("if=none,id=stick,format=raw,file={}", stick.display()),
        "-device".to_string(),
        "usb-storage,bus=xhci0.0,drive=stick,removable=on".to_string(),
    ];
    let cmdline = format!(
        "narf.disks=root-ro root=UUID={IMAGE_UUID} rootflags=subvol=/@ narf.bootlog={token}"
    );
    // Stop a few flush periods after the log is armed.
    let lines = boot_with(
        args,
        kernel,
        image,
        &cmdline,
        &extra,
        &["bootlog: saving the kernel log to"],
        5_000,
    )?;
    let find = |needle: &str| lines.iter().find(|(_, l)| l.contains(needle));
    let Some((armed_at, armed)) = find("bootlog: saving the kernel log to") else {
        bail!("btrfs-rootrw-interop: the boot log was not armed under root-ro");
    };
    if !armed.contains("usb-msc") {
        bail!("btrfs-rootrw-interop: the boot log armed on a non-USB device: {armed}");
    }
    if find("disks: WRITABLE (log stick): usb-msc").is_none() {
        bail!("btrfs-rootrw-interop: no log-stick banner");
    }
    let Some((root_at, _)) = find("root-mount: ") else {
        bail!("btrfs-rootrw-interop: the root was not mounted");
    };
    let started = find("bootlog: waiting up to")
        .map(|(t, _)| *t)
        .unwrap_or(0.0);
    println!(
        "btrfs-rootrw-interop: bootlog armed {:.1}s, root mounted {:.1}s after the bootlog started",
        armed_at - started,
        root_at - started
    );
    // Under the root policies the log probes its stick only after the root
    // mount settled, so the stick's I/O cannot hold up the root.
    if root_at > armed_at {
        bail!("btrfs-rootrw-interop: the boot log armed before the root was mounted");
    }
    if root_at - started > 30.0 {
        bail!(
            "btrfs-rootrw-interop: arming the boot log delayed the root mount ({:.0} s)",
            root_at - started
        );
    }
    if sha256_whole(image)? != image_before {
        bail!("btrfs-rootrw-interop: the root-ro boot MODIFIED the root image");
    }
    let spec = format!("{}@@{}", stick.display(), 1u64 << 20);
    let listing = run(
        Command::new("mdir")
            .env("MTOOLS_SKIP_CHECK", "1")
            .args(["-b", "-i", &spec, "::/"]),
        "mdir (stick)",
    )?;
    let Some(log) = listing
        .lines()
        .map(|l| l.trim().trim_start_matches("::/").to_string())
        .find(|l| l.to_ascii_lowercase().starts_with("narf-boot-"))
    else {
        bail!("btrfs-rootrw-interop: no narf-boot-*.log on the stick:\n{listing}");
    };
    let text = run(
        Command::new("mtype").env("MTOOLS_SKIP_CHECK", "1").args([
            "-i",
            &spec,
            &format!("::/{log}"),
        ]),
        "mtype (log)",
    )?;
    for needle in ["disks: WRITABLE (log stick)", "root-mount: "] {
        if !text.contains(needle) {
            bail!("btrfs-rootrw-interop: the saved log lacks `{needle}`");
        }
    }
    println!(
        "btrfs-rootrw-interop: root-ro boot log written to the stick ({log}, {} bytes); root image unchanged",
        text.len()
    );
    Ok(())
}

fn sha256_whole(path: &Path) -> Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
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
    if args.bootlog_only {
        return bootlog_boot(args, &kernel, &plain, &work);
    }
    write_boots(args, &kernel, &plain, &work, "no-bgt")?;
    bootlog_boot(args, &kernel, &plain, &work)?;

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
