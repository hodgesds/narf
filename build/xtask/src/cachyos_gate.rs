//! `cargo xtask cachyos-gate`: the pre-hardware validation gate for booting
//! the host's installed CachyOS on NARF.
//!
//! It boots the real `cargo xtask grub-image` bundle under OVMF on a q35
//! machine whose storage mirrors the host:
//!
//! * NVMe controller 1 (`00:04.0`): a decoy GPT disk, vfat p1 + ext4 p2, the
//!   shape of the host's Sabrent data disk. NARF must never change a byte.
//! * NVMe controller 2 (`00:07.0`): the root disk, GPT vfat ESP p1 + btrfs
//!   p2 with the host root's mkfs features, CachyOS subvolumes and fstab
//!   (`cachyos-root-smoke`'s image, or `--real-root`). OVMF boots GRUB from
//!   its ESP; GRUB runs the bundle's `grub.cfg` stanza, which chainloads the
//!   bundle's Limine, which loads NARF with the bundle's command line.
//! * A USB stick carrying `/NARFLOG.ID` for `narf.bootlog=`.
//!
//! The matrix (see `docs/BOOTING_ON_CACHYOS.md`, "Pre-hardware validation
//! gate"): root-ro, root-rw, crash consistency, repeated cycles, Linux
//! interop + round trip. Every host-side check runs on regular files under
//! the work directory; no host block device is ever opened.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

/// The host's live CachyOS root (WD SN770 p2). An image carrying this fsid,
/// or an fstab naming it, is refused: it must never be attachable anywhere.
const HOST_ROOT_FSID: &str = "653602c3-cd42-420e-95ef-4c4033d17b56";
/// The host's ESP (`/boot/efi`) FAT serial.
const HOST_ESP_UUID: &str = "6D89-28C5";
/// The host's Sabrent data partition.
const HOST_DATA_UUID: &str = "15d044db-0c09-4ec4-a2d6-ccd1f92e4dd6";

const MIB: u64 = 1024 * 1024;
const GPT_ESP_TYPE: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
/// Directory on the root subvolume the workload writes.
const GATE_DIR: &str = "narf-gate";
const SMALL_FILES: u32 = 400;
const BIG_BYTES: u64 = 100 * MIB;

/// Matrix rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Case {
    /// `narf.disks=root-ro`: login, nothing written.
    Ro,
    /// `narf.disks=root-rw`: login, write workload, clean poweroff, host
    /// btrfs check + restore.
    Rw,
    /// QEMU killed at a random point of the workload, N times.
    Crash,
    /// N clean root-rw boot/poweroff cycles.
    Cycles,
    /// The host's Linux kernel boots the NARF-written root, writes, scrubs;
    /// then NARF boots it again.
    Linux,
    /// Linux takes snapper-style snapshots of `@` (nested `.snapshots`,
    /// divergent rounds, a writable one, a top-level one, `@home`) and
    /// balances; NARF then writes the shared root, every snapshot must stay
    /// byte-identical and the image check-clean; Linux deletes a snapshot
    /// and scrubs; NARF writes again.
    Snapshots,
}

#[derive(clap::Args, Clone)]
pub struct Args {
    #[command(flatten)]
    pub build: super::BuildArgs,

    /// Gate C: run the matrix against this disk image (a GPT copy of the
    /// host root: vfat ESP p1 + btrfs p2, built once with the commands in
    /// docs/BOOTING_ON_CACHYOS.md). It is copied into the work directory
    /// first unless `--in-place`.
    #[arg(long, value_name = "IMAGE")]
    pub real_root: Option<PathBuf>,

    /// With `--real-root`: boot the given image itself instead of a copy.
    #[arg(long, requires = "real_root")]
    pub in_place: bool,

    /// Rows to run, comma-separated, in matrix order.
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "ro,rw,crash,cycles,linux,snapshots"
    )]
    pub cases: Vec<Case>,

    /// Crash-consistency runs.
    #[arg(long, default_value_t = 10)]
    pub crash_runs: u32,

    /// Clean boot/poweroff cycles.
    #[arg(long, default_value_t = 10)]
    pub cycles: u32,

    /// Seed for the crash points (default: from the clock; printed).
    #[arg(long)]
    pub seed: Option<u64>,

    /// Work directory (default `target/cachyos-gate`). Wiped at start.
    #[arg(long)]
    pub work_dir: Option<PathBuf>,

    /// Reuse the bundles staged by a previous run in the work directory
    /// instead of running `grub-image` again.
    #[arg(long)]
    pub skip_build: bool,

    /// Rebuild the cachyos-root-smoke base image first.
    #[arg(long)]
    pub rebuild_image: bool,

    /// Linux kernel for the interop row.
    #[arg(long, default_value = "/boot/vmlinuz-linux-cachyos")]
    pub linux_kernel: PathBuf,

    /// Seconds a boot may take to reach the login prompt.
    #[arg(long, default_value_t = 600)]
    pub boot_timeout: u64,

    /// Console login (the generated image's credentials; the Gate C
    /// commands set the same on the copy).
    #[arg(long, default_value = "root")]
    pub login_user: String,
    #[arg(long, default_value = "narf")]
    pub login_password: String,

    /// Echo the guest serial console to stdout.
    #[arg(long)]
    pub verbose: bool,
}

// ── Results ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Fail,
}

struct Row {
    name: String,
    verdict: Verdict,
    detail: String,
}

fn print_table(rows: &[Row]) {
    let w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    println!();
    println!("cachyos-gate results");
    println!("{:<w$}  {:<6}  detail", "row", "result");
    println!("{:-<w$}  {:-<6}  {:-<40}", "", "", "");
    for r in rows {
        let v = match r.verdict {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
        };
        let mut lines = r.detail.lines();
        println!("{:<w$}  {:<6}  {}", r.name, v, lines.next().unwrap_or(""));
        for l in lines {
            println!("{:<w$}  {:<6}  {l}", "", "");
        }
    }
}

// ── Disk image model ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Part {
    start: u64,
    len: u64,
    type_guid: String,
    uuid: String,
}

fn guid(b: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

fn uuid_be(b: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

fn read_at(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)
        .with_context(|| format!("read {len} bytes at {offset:#x} of {}", path.display()))?;
    Ok(buf)
}

/// Partitions of a GPT disk image (512-byte sectors).
fn gpt_parts(path: &Path) -> Result<Vec<Part>> {
    let hdr = read_at(path, 512, 92)?;
    if &hdr[0..8] != b"EFI PART" {
        bail!("{} has no GPT", path.display());
    }
    let le64 = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let le32 = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let (lba, n, size) = (le64(&hdr, 72), le32(&hdr, 80), le32(&hdr, 84));
    let table = read_at(path, lba * 512, (n * size) as usize)?;
    let mut parts = Vec::new();
    for e in table.chunks(size as usize) {
        if e[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let (first, last) = (le64(e, 32), le64(e, 40));
        parts.push(Part {
            start: first * 512,
            len: (last + 1 - first) * 512,
            type_guid: guid(&e[0..16]),
            uuid: guid(&e[16..32]),
        });
    }
    Ok(parts)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SuperInfo {
    generation: u64,
    log_root: u64,
}

fn btrfs_super(path: &Path, part: &Part) -> Result<(String, SuperInfo)> {
    let sb = read_at(path, part.start + 65536, 4096)?;
    if &sb[64..72] != b"_BHRfS_M" {
        bail!(
            "no btrfs superblock in {} at {:#x}",
            path.display(),
            part.start
        );
    }
    let le64 = |o: usize| u64::from_le_bytes(sb[o..o + 8].try_into().unwrap());
    Ok((
        uuid_be(&sb[32..48]),
        SuperInfo {
            generation: le64(72),
            log_root: le64(96),
        },
    ))
}

/// FAT volume serial (`XXXX-XXXX`, the `UUID=` blkid reports).
fn fat_serial(path: &Path, part: &Part) -> Result<String> {
    let bs = read_at(path, part.start, 512)?;
    // FAT32 keeps the serial at 0x43, FAT12/16 at 0x27.
    let off = if &bs[0x52..0x57] == b"FAT32" {
        0x43
    } else {
        0x27
    };
    let s = u32::from_le_bytes(bs[off..off + 4].try_into().unwrap());
    Ok(format!("{:04X}-{:04X}", s >> 16, s & 0xffff))
}

struct RootDisk {
    path: PathBuf,
    esp: Part,
    root: Part,
    fsid: String,
    esp_uuid: String,
}

impl RootDisk {
    fn open(path: &Path) -> Result<Self> {
        let parts = gpt_parts(path)?;
        let esp = parts
            .iter()
            .find(|p| p.type_guid == GPT_ESP_TYPE)
            .cloned()
            .ok_or_else(|| anyhow!("{}: no EFI system partition", path.display()))?;
        let root = parts
            .iter()
            .find(|p| btrfs_super(path, p).is_ok())
            .cloned()
            .ok_or_else(|| anyhow!("{}: no btrfs partition", path.display()))?;
        let (fsid, _) = btrfs_super(path, &root)?;
        let esp_uuid = fat_serial(path, &esp)?;
        Ok(Self {
            path: path.to_path_buf(),
            esp,
            root,
            fsid,
            esp_uuid,
        })
    }

    fn sb(&self) -> Result<SuperInfo> {
        Ok(btrfs_super(&self.path, &self.root)?.1)
    }
}

// ── Hashing and copying ─────────────────────────────────────────────────

fn sha256_range(path: &Path, offset: u64, len: Option<u64>) -> Result<String> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    f.seek(SeekFrom::Start(offset))?;
    let mut left = len.unwrap_or(u64::MAX);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 4 * MIB as usize];
    while left > 0 {
        let want = buf.len().min(left.min(usize::MAX as u64) as usize);
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(hex(&h.finalize()))
}

fn sha256_file(path: &Path) -> Result<String> {
    sha256_range(path, 0, None)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Hashes of a root disk: the btrfs partition and everything else (the
/// GPT, the ESP, the slack), which root-rw must never touch.
#[derive(Clone, PartialEq, Eq, Debug)]
struct RootHashes {
    btrfs: String,
    outside: String,
}

/// Disk state captured after a boot's bundle install and immediately before
/// QEMU starts: the baseline every "did NARF write?" check compares against.
#[derive(Clone, Debug)]
struct PreBoot {
    /// Whole-image SHA-256 of the root NVMe image (GPT, ESP and btrfs).
    whole: String,
    hashes: RootHashes,
    sb: SuperInfo,
    /// [`InstallLedger`] position of the snapshot.
    seq: u64,
}

/// Orders bundle installs against the pre-boot snapshot. Installing the
/// bundle rewrites ESP files, so an install between the snapshot and the
/// boot (or between the snapshot and the post-boot comparison) would be
/// reported as NARF writing the disk, or would hide a real write.
#[derive(Debug, Default)]
struct InstallLedger {
    installs: u64,
}

impl InstallLedger {
    fn installed(&mut self) {
        self.installs += 1;
    }

    /// Position to record in a [`PreBoot`] snapshot.
    fn snapshot(&self) -> u64 {
        self.installs
    }

    /// Fail if a bundle install happened after the snapshot at `seq`.
    fn verify(&self, seq: u64) -> Result<()> {
        if self.installs != seq {
            bail!(
                "gate bug: {} bundle install(s) after the pre-boot snapshot",
                self.installs - seq
            );
        }
        Ok(())
    }
}

fn root_hashes(d: &RootDisk) -> Result<RootHashes> {
    let size = std::fs::metadata(&d.path)?.len();
    let end = d.root.start + d.root.len;
    let mut h = Sha256::new();
    h.update(sha256_range(&d.path, 0, Some(d.root.start))?.as_bytes());
    h.update(sha256_range(&d.path, end, Some(size.saturating_sub(end)))?.as_bytes());
    Ok(RootHashes {
        btrfs: sha256_range(&d.path, d.root.start, Some(d.root.len))?,
        outside: hex(&h.finalize()),
    })
}

/// Standard base64 (RFC 4648, with padding), wrapped at `width` characters
/// per line, each line newline-terminated, as `base64 -d` reads it.
fn base64_lines(data: &[u8], width: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut flat = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                flat.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                flat.push('=');
            }
        }
    }
    let mut out = String::with_capacity(flat.len() + flat.len() / width + 1);
    for line in flat.as_bytes().chunks(width.max(4)) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out
}

/// `cp --reflink=auto --sparse=always`.
fn copy_image(from: &Path, to: &Path) -> Result<()> {
    let _ = std::fs::remove_file(to);
    super::run_checked(
        Command::new("cp")
            .args(["--reflink=auto", "--sparse=always"])
            .arg(from)
            .arg(to),
        &format!("copy {} -> {}", from.display(), to.display()),
    )
}

/// Copy `part` of `disk` into a standalone file for the host btrfs tools
/// (`copy_file_range`, which reflinks on btrfs).
fn extract_part(disk: &Path, part: &Part, out: &Path) -> Result<()> {
    let _ = std::fs::remove_file(out);
    let mut src = std::fs::File::open(disk)?;
    src.seek(SeekFrom::Start(part.start))?;
    let mut dst = std::fs::File::create(out)?;
    let n = std::io::copy(&mut (&mut src).take(part.len), &mut dst)?;
    if n != part.len {
        bail!("short partition copy from {}", disk.display());
    }
    Ok(())
}

fn which(tool: &str) -> bool {
    super::which(tool).is_some()
}

// ── Host-side btrfs checks ──────────────────────────────────────────────

struct HostCheck {
    dir: PathBuf,
}

impl HostCheck {
    fn new(work: &Path) -> Result<Self> {
        let dir = work.join("check");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn part_file(&self) -> PathBuf {
        self.dir.join("root.btrfs")
    }

    /// Extract the root partition and run `btrfs check --readonly` (and the
    /// data-checksum variant when `csum`). Output goes to `<label>.check.log`.
    fn check(&self, d: &RootDisk, label: &str, csum: bool) -> Result<()> {
        let part = self.part_file();
        extract_part(&d.path, &d.root, &part)?;
        let mut modes: Vec<&[&str]> = vec![&["check", "--readonly"]];
        if csum {
            modes.push(&["check", "--readonly", "--check-data-csum"]);
        }
        for args in modes {
            let out = Command::new("btrfs")
                .args(args)
                .arg(&part)
                .output()
                .context("run btrfs check")?;
            let log = self.dir.join(format!(
                "{label}.{}.log",
                if args.len() == 3 {
                    "check-csum"
                } else {
                    "check"
                }
            ));
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            std::fs::write(&log, &text)?;
            if !out.status.success() || text.contains("ERROR:") {
                bail!(
                    "`btrfs {}` FAILED ({}); see {}\n{}",
                    args.join(" "),
                    out.status,
                    log.display(),
                    tail(&text, 12)
                );
            }
        }
        Ok(())
    }

    /// Subvolume id of `name` (e.g. `@`) in the extracted partition.
    fn subvol_id(&self, name: &str) -> Result<u64> {
        let out = Command::new("btrfs")
            .args(["inspect-internal", "dump-tree", "-t", "root"])
            .arg(self.part_file())
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut pending: Option<u64> = None;
        for line in text.lines() {
            if let Some(rest) = line.split("ROOT_REF ").nth(1) {
                pending = rest
                    .split(|c: char| !c.is_ascii_digit())
                    .find(|s| !s.is_empty())
                    .and_then(|s| s.parse().ok());
                continue;
            }
            if let (Some(id), Some(n)) = (pending, line.split(" name ").nth(1)) {
                if n.trim() == name {
                    return Ok(id);
                }
                pending = None;
            }
        }
        bail!("subvolume {name} not found in the root tree")
    }

    /// `btrfs restore` (unprivileged, on the extracted image file) of
    /// `regex` from subvolume `@`, into a fresh directory.
    fn restore(&self, regex: &str, label: &str) -> Result<PathBuf> {
        let id = self.subvol_id("@")?;
        let out_dir = self.dir.join(format!("restore-{label}"));
        let _ = std::fs::remove_dir_all(&out_dir);
        std::fs::create_dir_all(&out_dir)?;
        let out = Command::new("btrfs")
            .args(["restore", "-r", &id.to_string(), "--path-regex", regex])
            .arg(self.part_file())
            .arg(&out_dir)
            .output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::write(self.dir.join(format!("{label}.restore.log")), &text)?;
        if !out.status.success() {
            bail!("btrfs restore failed ({}): {}", out.status, tail(&text, 8));
        }
        Ok(out_dir)
    }

    /// `btrfs restore` of `regex` from subvolume `id` into a fresh directory.
    fn restore_id(&self, id: u64, regex: &str, label: &str) -> Result<PathBuf> {
        let out_dir = self.dir.join(format!("restore-{label}"));
        let _ = std::fs::remove_dir_all(&out_dir);
        std::fs::create_dir_all(&out_dir)?;
        let out = Command::new("btrfs")
            .args(["restore", "-r", &id.to_string(), "--path-regex", regex])
            .arg(self.part_file())
            .arg(&out_dir)
            .output()?;
        if !out.status.success() {
            bail!(
                "btrfs restore -r {id} failed ({}): {}",
                out.status,
                tail(&String::from_utf8_lossy(&out.stderr), 8)
            );
        }
        Ok(out_dir)
    }

    /// Snapshot subvolumes of the extracted partition: their ROOT_ITEM key
    /// offset is the creating transaction (plain subvolumes carry 0).
    fn snapshot_ids(&self) -> Result<Vec<u64>> {
        let out = Command::new("btrfs")
            .args(["inspect-internal", "dump-tree", "-t", "root"])
            .arg(self.part_file())
            .output()?;
        let mut ids = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let Some(rest) = line.split(" key (").nth(1) else {
                continue;
            };
            let mut f = rest.split([' ', ')']);
            let (Some(id), Some("ROOT_ITEM"), Some(off)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            if let (Ok(id), Ok(off)) = (id.parse::<u64>(), off.parse::<u64>()) {
                if id >= 256 && off != 0 && !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    /// `path -> sha256` of a snapshot's checked paths (see [`SNAP_REGEX`]).
    fn snapshot_manifest(&self, id: u64) -> Result<std::collections::BTreeMap<String, String>> {
        let dir = self.restore_id(id, SNAP_REGEX, &format!("snap{id}"))?;
        let mut out = std::collections::BTreeMap::new();
        let mut todo = vec![dir.clone()];
        while let Some(d) = todo.pop() {
            for entry in std::fs::read_dir(&d)? {
                let entry = entry?;
                let path = entry.path();
                let ft = entry.file_type()?;
                if ft.is_dir() {
                    todo.push(path);
                } else if ft.is_file() {
                    let rel = path.strip_prefix(&dir)?.display().to_string();
                    out.insert(rel, sha256_file(&path)?);
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        if out.is_empty() {
            bail!("snapshot {id} restored no files");
        }
        Ok(out)
    }

    /// The image's `/etc/fstab`, via `btrfs restore`.
    fn fstab(&self, d: &RootDisk) -> Result<String> {
        extract_part(&d.path, &d.root, &self.part_file())?;
        let dir = self.restore("^/(|etc(|/fstab))$", "fstab")?;
        std::fs::read_to_string(dir.join("etc/fstab")).context("the image has no /etc/fstab")
    }
}

/// What the snapshot row compares in each snapshot: its own tree, the gate
/// and snapshot workloads' files, two system files, `@home`'s gate files.
const SNAP_REGEX: &str = "^/(|narf-snap(|/.*)|narf-gate(|-.*|/.*)|etc(|/hostname|/fstab))$";

/// Linux side of the snapshot row: what snapper + snap-pac + a balance leave.
const SNAP_SCRIPT: &str = r#"set -eux
D=/narf-snap
mkdir -p $D
for i in $(seq 1 300); do echo "linux base $i" > $D/s$i; done
dd if=/dev/urandom of=$D/blob bs=1M count=8 status=none
cp --reflink=always $D/blob $D/blob-reflink
sync
[ -d /.snapshots ] || btrfs subvolume create /.snapshots
mkdir -p /.snapshots/1
btrfs subvolume snapshot -r / /.snapshots/1/snapshot
dev=$(findmnt -no SOURCE / | sed 's/\[.*//')
mkdir -p /run/narf-top
mount -o subvolid=5 "$dev" /run/narf-top
btrfs subvolume snapshot -r /run/narf-top/@home /run/narf-top/@home/.narf-snap-home
umount /run/narf-top
for i in $(seq 1 3 300); do echo "linux round2 $i" >> $D/s$i; done
dd if=/dev/urandom of=$D/blob bs=1M count=1 seek=2 conv=notrunc status=none
sync
mkdir -p /.snapshots/2
btrfs subvolume snapshot -r / /.snapshots/2/snapshot
mkdir -p /.snapshots/3
btrfs subvolume snapshot / /.snapshots/3/snapshot
echo "written after the snapshot" > /.snapshots/3/snapshot/narf-snap/after-snap
mount -o subvolid=5 "$dev" /run/narf-top
btrfs subvolume snapshot -r /run/narf-top/@ /run/narf-top/.narf-pre-rw-@
umount /run/narf-top
btrfs balance start -m /
btrfs balance start -dlimit=2 /
sync
btrfs subvolume list /
echo NARF-SNAP-DONE
"#;

/// NARF side: rewrite, truncate, delete and overwrite files the snapshots
/// share with `@` (on top of the gate workload, which replaces /narf-gate).
const SNAP_NARF_SCRIPT: &str = r#"set -u
D=/narf-snap
for i in $(seq 1 2 300); do printf 'narf rewrote %d
' $i > $D/s$i || exit 21; done
for i in $(seq 2 10 300); do rm -f $D/s$i || exit 22; done
dd if=/dev/zero of=$D/blob bs=1M count=2 seek=1 conv=notrunc status=none || exit 23
truncate -s 4096 $D/blob-reflink || exit 24
for i in $(seq 1 50); do echo "narf new $i" > $D/n$i || exit 25; done
sync -f $D || exit 26
echo NARF-SNAP-WRITES-DONE
"#;

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Every `UUID=` in `fstab` names the image's own btrfs or ESP, never the
/// host's disks.
fn check_fstab(fstab: &str, d: &RootDisk, host_uuids: &[String]) -> Result<()> {
    let mut saw_root = false;
    for line in fstab.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let src = line.split_whitespace().next().unwrap_or("");
        let lower = src.to_ascii_lowercase();
        if host_uuids
            .iter()
            .any(|h| lower.contains(&h.to_ascii_lowercase()))
        {
            bail!("fstab references a HOST disk: `{line}`");
        }
        if let Some(u) = src.strip_prefix("UUID=") {
            let u = u.to_ascii_lowercase();
            if u == d.fsid {
                saw_root = true;
            } else if u != d.esp_uuid.to_ascii_lowercase() {
                bail!("fstab names UUID {u}, which is neither the image's btrfs nor its ESP");
            }
        } else if src.starts_with("PARTUUID=")
            || src.starts_with("/dev/")
            || src.starts_with("LABEL=")
        {
            bail!("fstab source `{src}` is not pinned to the image by UUID");
        }
    }
    if !saw_root {
        bail!("fstab never mounts the image's btrfs (UUID={})", d.fsid);
    }
    Ok(())
}

// ── Guest workload ──────────────────────────────────────────────────────

/// Bash run in the guest with the round tag as `$1`. Deterministic content,
/// so the host can verify it with `btrfs restore`.
fn workload_script() -> String {
    format!(
        r#"set -u
T="$1"; G=/{GATE_DIR}; S=$G/small
mkdir -p $S || exit 10
echo "NARF-GATE-WORKLOAD-START $T"
for i in $(seq 1 {SMALL_FILES}); do printf 'narf-gate %s small %d\n' "$T" $i > $S/f$i || exit 11; done
for i in $(seq 1 50); do sync $S/f$i || exit 12; done
for i in $(seq 1 100); do mv -f $S/f$i $S/r$i || exit 13; done
for i in $(seq 101 200); do rm -f $S/f$i || exit 14; done
sync -f $S || exit 15
yes "narf-gate $T big" | head -c {BIG_BYTES} > $G/big.dat.tmp || exit 16
sync $G/big.dat.tmp || exit 17
mv -f $G/big.dat.tmp $G/big.dat || exit 18
printf '%s\n' "$T" > $G/TAG; sync $G/TAG $G || exit 19
if printf '%s\n' "$T" > /home/narf-gate-$T 2>/dev/null && sync /home/narf-gate-$T; then echo "GATE-HOME rw"; else echo "GATE-HOME ro"; fi
echo "NARF-GATE-JOURNAL $T" | systemd-cat -t narf-gate 2>/dev/null; journalctl --flush 2>/dev/null
if [ -d /var/log/journal ] && [ -n "$(ls -A /var/log/journal 2>/dev/null)" ]; then echo "GATE-JOURNAL persistent"; else echo "GATE-JOURNAL volatile"; fi
for m in / /home /var/log; do findmnt -rno TARGET,OPTIONS -M $m 2>/dev/null | sed 's/^/GATE-MNT /'; done
echo "NARF-GATE-WORKLOAD-DONE $T"
"#
    )
}

/// SHA-256 of the guest's `big.dat` for `tag`.
fn big_sha(tag: &str) -> String {
    let line = format!("narf-gate {tag} big\n");
    let mut h = Sha256::new();
    let mut left = BIG_BYTES as usize;
    let chunk = line.repeat(65536 / line.len() + 1);
    while left > 0 {
        let n = left.min(chunk.len());
        h.update(&chunk.as_bytes()[..n]);
        left -= n;
    }
    hex(&h.finalize())
}

/// Check a `btrfs restore` of `/narf-gate` against round `tag`.
fn verify_restored(dir: &Path, tag: &str) -> Result<()> {
    let g = dir.join(GATE_DIR);
    let s = g.join("small");
    let expect = |i: u32| format!("narf-gate {tag} small {i}\n");
    for i in 1..=100 {
        let got = std::fs::read_to_string(s.join(format!("r{i}")))
            .with_context(|| format!("restored small/r{i} missing"))?;
        if got != expect(i) {
            bail!("small/r{i}: content {got:?} != {:?}", expect(i));
        }
        if s.join(format!("f{i}")).exists() {
            bail!("small/f{i} survived its rename");
        }
    }
    for i in 101..=200 {
        if s.join(format!("f{i}")).exists() {
            bail!("small/f{i} survived its unlink");
        }
    }
    for i in 201..=SMALL_FILES {
        let got = std::fs::read_to_string(s.join(format!("f{i}")))
            .with_context(|| format!("restored small/f{i} missing"))?;
        if got != expect(i) {
            bail!("small/f{i}: content {got:?} != {:?}", expect(i));
        }
    }
    let big = g.join("big.dat");
    let len = std::fs::metadata(&big)
        .context("restored big.dat missing")?
        .len();
    if len != BIG_BYTES {
        bail!("big.dat is {len} bytes, expected {BIG_BYTES}");
    }
    let got = sha256_file(&big)?;
    if got != big_sha(tag) {
        bail!("big.dat content does not match round {tag}");
    }
    let t = std::fs::read_to_string(g.join("TAG")).unwrap_or_default();
    if t.trim() != tag {
        bail!("TAG is {:?}, expected {tag}", t.trim());
    }
    Ok(())
}

// ── QEMU driver ─────────────────────────────────────────────────────────

/// NARF's first console line.
const KERNEL_HELLO: &str = "hello from a bare kernel";

const FAIL_MARKERS: &[&str] = &[
    "*** KERNEL PANIC ***",
    "panicked at",
    "Kernel panic - not syncing",
    "You are in emergency mode",
    "Give root password for maintenance",
    "Cannot open access to console",
];

/// Console bytes as text without terminal escapes (CSI, and the OSC/DCS
/// strings systemd and bash emit, e.g. OSC 3008 context markers) or `\r`.
fn strip_escapes(b: &[u8]) -> String {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            0x1b if i + 1 < b.len() && b[i + 1] == b'[' => {
                i += 2;
                while i < b.len() && !(0x40..=0x7e).contains(&b[i]) {
                    i += 1;
                }
                i += 1;
            }
            0x1b if i + 1 < b.len() && matches!(b[i + 1], b']' | b'P' | b'_' | b'^') => {
                i += 2;
                while i < b.len() && b[i] != 0x07 && !(b[i] == 0x1b && b.get(i + 1) == Some(&b'\\'))
                {
                    i += 1;
                }
                i += if b.get(i) == Some(&0x07) { 1 } else { 2 };
            }
            0x1b => i += 2,
            b'\r' => i += 1,
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

struct Vm {
    child: Child,
    stdin: Option<ChildStdin>,
    buf: Arc<Mutex<Vec<u8>>>,
    cursor: usize,
    log: PathBuf,
}

impl Vm {
    fn spawn(mut cmd: Command, log: &Path, verbose: bool) -> Result<Self> {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().context("spawn qemu-system-x86_64")?;
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut file = std::fs::File::create(log)?;
        let mut out = child.stdout.take().unwrap();
        let b = buf.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = out.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let _ = file.write_all(&chunk[..n]);
                if verbose {
                    let _ = std::io::stdout().write_all(&chunk[..n]);
                }
                b.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        });
        let mut err = child.stderr.take().unwrap();
        let b = buf.clone();
        std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = err.read_to_end(&mut s);
            if !s.is_empty() {
                let mut g = b.lock().unwrap();
                g.extend_from_slice(b"\n[qemu stderr] ");
                g.extend_from_slice(&s);
            }
        });
        let stdin = child.stdin.take();
        Ok(Self {
            child,
            stdin,
            buf,
            cursor: 0,
            log: log.to_path_buf(),
        })
    }

    fn text(&self) -> String {
        strip_escapes(&self.buf.lock().unwrap())
    }

    fn err(&self, what: &str) -> anyhow::Error {
        let text = strip_escapes(&self.buf.lock().unwrap());
        anyhow!(
            "{what}; serial log {}\n{}",
            self.log.display(),
            tail(&text, 15)
        )
    }

    /// Like [`Self::wait_for`] but ignores [`FAIL_MARKERS`]: for driving the
    /// emergency shell itself.
    fn wait_raw(&mut self, pat: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            {
                let g = self.buf.lock().unwrap();
                let hay = &g[self.cursor.min(g.len())..];
                if let Some(pos) = find(hay, pat.as_bytes()) {
                    self.cursor += pos + pat.len();
                    return true;
                }
            }
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// After systemd fell back to emergency mode, log in to the maintenance
    /// shell and collect why the root's device unit never appeared (udev's
    /// record of the partition, the by-uuid links, the device unit, the
    /// relevant journal). Best effort; returns the cleaned transcript.
    fn emergency_diagnostics(&mut self, password: &str) -> Option<String> {
        if !self.text().contains("You are in emergency mode") {
            return None;
        }
        self.cursor = 0;
        if !self.wait_raw("root password for maintenance", Duration::from_secs(60))
            && !self.wait_raw("Press Enter", Duration::from_secs(5))
        {
            return None;
        }
        std::thread::sleep(Duration::from_secs(1));
        self.send(&format!("{password}\n")).ok()?;
        std::thread::sleep(Duration::from_secs(3));
        let start = self.buf.lock().unwrap().len();
        let dev =
            "dev-disk-by\\x2duuid-c4c405ee\\x2d0000\\x2d4a11\\x2d9e57\\x2d00000000c0de.device";
        let script = format!(
            "export SYSTEMD_COLORS=0 PAGER=cat; stty -echo; \
             udevadm info -q all -n /dev/nvme1n1p2; ls -l /dev/disk/by-uuid/; \
             systemctl status --no-pager {dev}; \
             systemctl status --no-pager sys-devices-virtual-block-nvme1n1p2.device; \
             ls -l /run/udev/data/ | head -n 40; \
             journalctl -b --no-pager -o short-monotonic | grep -iE 'nvme1n1p2|udevd|sd-device|btrfs' | tail -n 40; \
             echo NARF-GATE-DIAG-$((1+1))-END\n"
        );
        self.send(&script).ok()?;
        self.wait_raw("NARF-GATE-DIAG-2-END", Duration::from_secs(120));
        let g = self.buf.lock().unwrap();
        Some(strip_escapes(&g[start.min(g.len())..]))
    }

    /// Wait for one of `pats` after the cursor; moves the cursor past it.
    fn wait_for(&mut self, pats: &[&str], timeout: Duration) -> Result<usize> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let g = self.buf.lock().unwrap();
                let hay = &g[self.cursor.min(g.len())..];
                let best = pats
                    .iter()
                    .enumerate()
                    .filter_map(|(i, p)| find(hay, p.as_bytes()).map(|pos| (pos, i, p.len())))
                    .min();
                if let Some((pos, i, l)) = best {
                    self.cursor += pos + l;
                    return Ok(i);
                }
                if let Some(m) = FAIL_MARKERS
                    .iter()
                    .find(|m| find(hay, m.as_bytes()).is_some())
                {
                    drop(g);
                    return Err(self.err(&format!("guest failure marker `{m}`")));
                }
            }
            if let Some(status) = self.child.try_wait()? {
                std::thread::sleep(Duration::from_millis(300));
                return Err(self.err(&format!("QEMU exited ({status}) waiting for {pats:?}")));
            }
            if Instant::now() > deadline {
                return Err(self.err(&format!("timed out waiting for {pats:?}")));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Type `s` (the serial RX path gets small paced chunks).
    fn send(&mut self, s: &str) -> Result<()> {
        let stdin = self.stdin.as_mut().ok_or_else(|| anyhow!("stdin closed"))?;
        for chunk in s.as_bytes().chunks(16) {
            stdin.write_all(chunk)?;
            stdin.flush()?;
            std::thread::sleep(Duration::from_millis(15));
        }
        Ok(())
    }

    /// Log in at the getty and get a marked shell.
    fn login(&mut self, user: &str, pw: &str, timeout: Duration) -> Result<Duration> {
        let t0 = Instant::now();
        self.wait_for(&[" login: "], timeout)?;
        let booted = t0.elapsed();
        std::thread::sleep(Duration::from_millis(500));
        self.send(&format!("{user}\n"))?;
        self.wait_for(&["Password:"], Duration::from_secs(60))?;
        std::thread::sleep(Duration::from_millis(300));
        self.send(&format!("{pw}\n"))?;
        // Any shell prompt; then pin our own.
        std::thread::sleep(Duration::from_secs(2));
        self.send("export PS1='gate# '; stty -echo 2>/dev/null; echo \"@@READY\"\"@@\"\n")?;
        self.wait_for(&["@@READY@@"], Duration::from_secs(120))?;
        Ok(booted)
    }

    /// Run `cmd` in the guest shell; returns (exit code, output).
    fn run(&mut self, cmd: &str, timeout: Duration) -> Result<(i32, String)> {
        let start = self.cursor;
        self.send(&format!("{cmd}; echo \"@@RC=\"\"$?@@\"\n"))?;
        let deadline = Instant::now() + timeout;
        loop {
            {
                let g = self.buf.lock().unwrap();
                let hay = &g[start.min(g.len())..];
                let mut from = 0;
                while let Some(p) = find(&hay[from..], b"@@RC=") {
                    let at = from + p + 5;
                    let digits = hay[at..].iter().take_while(|c| c.is_ascii_digit()).count();
                    if digits > 0 && hay[at + digits..].starts_with(b"@@") {
                        let rc = std::str::from_utf8(&hay[at..at + digits])
                            .ok()
                            .and_then(|d| d.parse().ok())
                            .unwrap_or(-1);
                        let out = strip_escapes(&hay[..from + p]);
                        self.cursor = start + at + digits + 2;
                        return Ok((rc, out));
                    }
                    from = at;
                }
                if let Some(m) = FAIL_MARKERS
                    .iter()
                    .find(|m| find(hay, m.as_bytes()).is_some())
                {
                    drop(g);
                    return Err(self.err(&format!("guest failure marker `{m}` during `{cmd}`")));
                }
            }
            if let Some(status) = self.child.try_wait()? {
                return Err(self.err(&format!("QEMU exited ({status}) during `{cmd}`")));
            }
            if Instant::now() > deadline {
                return Err(self.err(&format!("timed out running `{cmd}`")));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Put `body` at `path` in the guest, verified.
    ///
    /// The console is the only channel into the guest, and typed text is not
    /// guaranteed to arrive intact: a byte lost or reordered anywhere (QEMU's
    /// chardev, the UART, the console line discipline, a process that read
    /// the tty in between) corrupts a shell script silently, which then fails
    /// in confusing ways (`unexpected EOF while looking for matching '"'`).
    /// So the body travels base64-encoded (only `[A-Za-z0-9+/=]` and
    /// newlines, nothing the shell or the line discipline interprets), is
    /// decoded into a temporary file, and only replaces `path` after its
    /// SHA-256 matches. A mismatch is retyped, up to three times.
    fn put_file(&mut self, path: &str, body: &str) -> Result<()> {
        let want = hex(&Sha256::digest(body.as_bytes()));
        let encoded = base64_lines(body.as_bytes(), 76);
        let tmp = format!("{path}.narf-xfer");
        for attempt in 1..=3 {
            let mut s = format!("base64 -d > {tmp} <<'NARF_GATE_EOF'\n");
            s.push_str(&encoded);
            s.push_str("NARF_GATE_EOF\n");
            self.send(&s)?;
            let (rc, out) = self.run(&format!("sha256sum {tmp}"), Duration::from_secs(60))?;
            if rc == 0 && out.contains(&want) {
                let (rc, _) = self.run(&format!("mv -f {tmp} {path}"), Duration::from_secs(60))?;
                if rc == 0 {
                    return Ok(());
                }
            }
            eprintln!(
                "cachyos-gate: {path}: transfer {attempt} did not verify (rc {rc}); retyping"
            );
        }
        bail!("could not transfer {path} to the guest intact (3 attempts)")
    }

    fn poweroff(&mut self, timeout: Duration) -> Result<ExitStatus> {
        self.send("systemctl poweroff || poweroff\n")?;
        self.wait_exit(timeout)
    }

    fn wait_exit(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(s) = self.child.try_wait()? {
                std::thread::sleep(Duration::from_millis(300));
                return Ok(s);
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err(self.err("guest did not power off"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            self.kill();
        }
    }
}

// ── The gate ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Policy {
    Ro,
    Rw,
}

impl Policy {
    fn name(self) -> &'static str {
        match self {
            Policy::Ro => "root-ro",
            Policy::Rw => "root-rw",
        }
    }
}

struct Gate {
    args: Args,
    work: PathBuf,
    logs: PathBuf,
    disk: RootDisk,
    decoy: PathBuf,
    decoy_sha: String,
    stick: PathBuf,
    token: String,
    ovmf_code: PathBuf,
    ovmf_vars: PathBuf,
    host: HostCheck,
    host_uuids: Vec<String>,
    boots: u32,
    /// Workload duration measured by the root-rw row (crash points).
    workload_secs: f64,
    rng: u64,
    /// Round tag of the last verified complete workload on the image.
    last_tag: Option<String>,
    accel: Option<String>,
    /// Milestones of the running row, kept in its detail if it fails.
    progress: Vec<String>,
    /// Boots that hung before the kernel ran (retried once).
    prekernel_hangs: Vec<String>,
    installs: InstallLedger,
    /// Baseline of the current boot (see [`PreBoot`]).
    preboot: Option<PreBoot>,
}

fn kvm_accel() -> Option<String> {
    std::env::var("XTASK_QEMU_ACCEL").ok().or_else(|| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .ok()
            .map(|_| "kvm".to_string())
    })
}

impl Gate {
    fn next_rand(&mut self) -> f64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.args.boot_timeout)
    }

    fn esp_dir(&self, p: Policy) -> PathBuf {
        self.work.join(format!("bundle-{}", p.name()))
    }

    /// Install `p`'s bundle (GRUB + the bundle's ESP tree) on the root
    /// disk's ESP. The ESP is part of the "outside the btrfs partition"
    /// hash, so this happens only between boots.
    fn install_bundle(&mut self, p: Policy) -> Result<()> {
        self.installs.installed();
        let spec = format!("{}@@{}", self.disk.path.display(), self.disk.esp.start);
        let mt = |tool: &str| {
            let mut c = Command::new(tool);
            c.env("MTOOLS_SKIP_CHECK", "1");
            c
        };
        for d in [
            "::/EFI",
            "::/EFI/BOOT",
            "::/EFI/NARF",
            "::/boot",
            "::/boot/limine",
        ] {
            let _ = mt("mmd").args(["-D", "s", "-i", &spec, d]).output();
        }
        let dir = self.esp_dir(p);
        for (src, dst) in [
            ("grub/BOOTX64.EFI", "::/EFI/BOOT/BOOTX64.EFI"),
            ("esp/EFI/NARF/BOOTX64.EFI", "::/EFI/NARF/BOOTX64.EFI"),
            ("esp/boot/limine/limine.conf", "::/boot/limine/limine.conf"),
            ("esp/boot/narf-frame", "::/boot/narf-frame"),
            ("esp/boot/initramfs.cpio", "::/boot/initramfs.cpio"),
        ] {
            super::run_checked(
                mt("mcopy")
                    .args(["-o", "-i", &spec])
                    .arg(dir.join(src))
                    .arg(dst),
                &format!("install {src} on the root disk's ESP"),
            )?;
        }
        Ok(())
    }

    fn narf_cmd(&self) -> Command {
        let mut c = Command::new("qemu-system-x86_64");
        c.arg("-drive")
            .arg(format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                self.ovmf_code.display()
            ))
            .arg("-drive")
            .arg(format!(
                "if=pflash,format=raw,unit=1,file={}",
                self.ovmf_vars.display()
            ))
            .args(["-machine", "q35", "-cpu", "max", "-smp", "4", "-m", "4096M"])
            .args([
                "-serial",
                "stdio",
                "-display",
                "none",
                "-no-reboot",
                "-monitor",
                "none",
            ])
            .args(["-nic", "none"])
            // Controller 1: the Sabrent-shaped decoy; controller 2: the root.
            .arg("-drive")
            .arg(format!(
                "if=none,id=decoy,format=raw,file={}",
                self.decoy.display()
            ))
            .args(["-device", "nvme,serial=GATEDECOY0001,drive=decoy,addr=0x4"])
            .arg("-drive")
            .arg(format!(
                "if=none,id=root,format=raw,file={}",
                self.disk.path.display()
            ))
            .args([
                "-device",
                "nvme,serial=GATEROOT00002,drive=root,addr=0x7,bootindex=0",
            ])
            .args(["-device", "qemu-xhci,id=xhci0"])
            .arg("-drive")
            .arg(format!(
                "if=none,id=stick,format=raw,file={}",
                self.stick.display()
            ))
            .args([
                "-device",
                "usb-storage,bus=xhci0.0,drive=stick,removable=on",
            ])
            .args(["-device", "usb-kbd,bus=xhci0.0"]);
        if let Some(a) = &self.accel {
            c.args(["-accel", a]);
        }
        c
    }

    /// Boot NARF under `p` up to a logged-in shell.
    fn boot_narf(&mut self, p: Policy, label: &str) -> Result<(Vm, Duration)> {
        // Exactly one install per boot, then the baseline, then QEMU.
        self.install_bundle(p)?;
        self.preboot = Some(PreBoot {
            whole: sha256_file(&self.disk.path)?,
            hashes: root_hashes(&self.disk)?,
            sb: self.disk.sb()?,
            seq: self.installs.snapshot(),
        });
        self.boots += 1;
        let log = self
            .logs
            .join(format!("{:02}-{label}.serial.log", self.boots));
        println!(
            "cachyos-gate: boot {} ({label}, narf.disks={})",
            self.boots,
            p.name()
        );
        let mut vm = Vm::spawn(self.narf_cmd(), &log, self.args.verbose)?;
        // Stage watchdog: the firmware must reach its boot manager, GRUB
        // must run the bundle stanza and Limine must hand over to NARF (its
        // first console line) well before the login timeout. A hang before
        // the kernel runs (firmware/GRUB/Limine) is retried and listed in the
        // `boot chain` row; nothing but the firmware has run, so no disk can
        // have been written.
        //
        // The hangs seen are OVMF's, between its console setup and the boot
        // manager (`BdsDxe:` never printed), and they track host CPU
        // oversubscription: idle, 0 of 166 boots of this exact QEMU command
        // line hung; with 14 busy loops on a 12-thread host, boots slowed
        // from ~2 s to 12-58 s and 7 of 60 never got there (one watched for
        // 400 s), with `-smp 2` as with `-smp 4`, `-cpu host` as `max`, with
        // or without the USB devices, but not in 6 boots with `-smp 1`:
        // OVMF's multi-processor bring-up, its vCPUs preempted by the host.
        // A host that busy (other QEMU jobs) can hit it twice in a row, so
        // the firmware stage gets its own short watchdog and up to three
        // retries.
        const PREKERNEL_ATTEMPTS: usize = 4;
        for attempt in 0..PREKERNEL_ATTEMPTS {
            let stage = vm
                .wait_for(&["BdsDxe: loading"], Duration::from_secs(60))
                .map_err(|_| "OVMF never reached its boot manager (60 s)")
                .and_then(|_| {
                    vm.wait_for(&["Booting `NARF'"], Duration::from_secs(120))
                        .map_err(|_| "GRUB never ran the bundle stanza (120 s)")
                })
                .and_then(|_| {
                    vm.wait_for(&[KERNEL_HELLO], Duration::from_secs(180))
                        .map_err(|_| "Limine never handed over to NARF (180 s)")
                });
            match stage {
                Ok(_) => break,
                Err(why) if attempt + 1 < PREKERNEL_ATTEMPTS => {
                    vm.kill();
                    self.prekernel_hangs
                        .push(format!("boot {} ({label}): {why}", self.boots));
                    let retry = self.logs.join(format!(
                        "{:02}-{label}.retry{}.serial.log",
                        self.boots,
                        attempt + 1
                    ));
                    vm = Vm::spawn(self.narf_cmd(), &retry, self.args.verbose)?;
                }
                Err(why) => {
                    return Err(vm.err(&format!("{why}, on all {PREKERNEL_ATTEMPTS} attempts")));
                }
            }
        }
        vm.wait_for(&["disks: POLICY narf.disks="], Duration::from_secs(240))
            .context("the NARF kernel never printed its disk policy")?;
        let booted = match vm.login(
            &self.args.login_user,
            &self.args.login_password,
            self.timeout(),
        ) {
            Ok(b) => b,
            Err(e) => {
                if let Some(diag) = vm.emergency_diagnostics(&self.args.login_password) {
                    let path = self
                        .logs
                        .join(format!("{:02}-{label}.emergency.txt", self.boots));
                    let _ = std::fs::write(&path, &diag);
                    eprintln!(
                        "cachyos-gate: emergency-mode diagnostics in {}",
                        path.display()
                    );
                }
                let refusals = Self::refusal_lines(&vm);
                if refusals.is_empty() {
                    return Err(e);
                }
                return Err(e.context(format!("{label}: {}", refusals.join(" | "))));
            }
        };
        println!("cachyos-gate:   login after {:.0}s", booted.as_secs_f64());
        Ok((vm, booted))
    }

    /// The current boot's pre-boot baseline, checked against the ledger.
    fn baseline(&self) -> Result<PreBoot> {
        let pre = self
            .preboot
            .clone()
            .ok_or_else(|| anyhow!("gate bug: no pre-boot snapshot"))?;
        self.installs.verify(pre.seq)?;
        Ok(pre)
    }

    fn decoy_unchanged(&self) -> Result<()> {
        let now = sha256_file(&self.decoy)?;
        if now != self.decoy_sha {
            bail!(
                "the decoy NVMe disk CHANGED (sha256 {} -> {now})",
                self.decoy_sha
            );
        }
        Ok(())
    }

    /// Mount state of `/` in the guest.
    fn root_is_rw(vm: &mut Vm) -> Result<bool> {
        let (_, out) = vm.run("findmnt -rno OPTIONS /", Duration::from_secs(60))?;
        Ok(out
            .lines()
            .any(|l| l.trim().split(',').next() == Some("rw")))
    }

    fn refusal_lines(vm: &Vm) -> Vec<String> {
        vm.text()
            .lines()
            .filter(|l| {
                l.contains("REFUSING read-write mount")
                    || l.contains("ROOT MOUNT FAILED")
                    || l.contains("systemd_pid1 requested but")
            })
            .map(|l| l.trim().to_string())
            .collect()
    }

    /// Run the workload for `tag`; returns (seconds, notes).
    fn workload(vm: &mut Vm, tag: &str) -> Result<(f64, String)> {
        vm.put_file("/run/narf-gate.sh", &workload_script())?;
        let t0 = Instant::now();
        let (rc, out) = vm.run(
            &format!("bash /run/narf-gate.sh {tag}"),
            Duration::from_secs(1800),
        )?;
        let secs = t0.elapsed().as_secs_f64();
        if rc != 0 || !out.contains(&format!("NARF-GATE-WORKLOAD-DONE {tag}")) {
            bail!(
                "workload {tag} failed (rc {rc}): {}",
                tail(&out.replace('\r', ""), 8)
            );
        }
        let notes: Vec<String> = out
            .lines()
            .filter_map(|l| l.trim().strip_prefix("GATE-").map(str::to_ascii_lowercase))
            .collect();
        Ok((secs, notes.join("; ")))
    }

    /// Host checks after a clean root-rw shutdown that ran workload `tag`.
    fn verify_clean(
        &mut self,
        label: &str,
        tag: Option<&str>,
        before_outside: &str,
    ) -> Result<String> {
        if let Some(pre) = &self.preboot {
            self.installs.verify(pre.seq)?;
        }
        let sb = self.disk.sb()?;
        if sb.log_root != 0 {
            bail!(
                "clean poweroff left a log tree (log_root {:#x}, generation {}): the next root-rw boot would refuse",
                sb.log_root,
                sb.generation
            );
        }
        let h = root_hashes(&self.disk)?;
        if h.outside != before_outside {
            bail!("bytes OUTSIDE the btrfs root partition changed (GPT/ESP)");
        }
        self.decoy_unchanged()?;
        self.host.check(&self.disk, label, true)?;
        if let Some(tag) = tag {
            let dir = self
                .host
                .restore(&format!("^/({GATE_DIR}(|/.*))?$"), label)?;
            verify_restored(&dir, tag)?;
            self.last_tag = Some(tag.to_string());
        }
        Ok(format!("gen {}", sb.generation))
    }

    // ── rows ──

    fn row_ro(&mut self) -> Result<String> {
        let (mut vm, booted) = self.boot_narf(Policy::Ro, "root-ro")?;
        let pre = self.baseline()?;
        let (before, sb0) = (pre.whole.clone(), pre.sb);
        let rw = Self::root_is_rw(&mut vm)?;
        // The overlay takes the writes; the disk must not.
        let (secs, notes) = Self::workload(&mut vm, "ro")?;
        let stick = vm.text().contains("bootlog: saving the kernel log to");
        let status = vm.poweroff(Duration::from_secs(300))?;
        drop(vm);
        self.installs.verify(pre.seq)?;
        let after = sha256_file(&self.disk.path)?;
        let sb1 = self.disk.sb()?;
        if after != before {
            bail!("root-ro boot MODIFIED the root disk (sha256 {before} -> {after})");
        }
        if sb1.generation != sb0.generation {
            bail!(
                "superblock generation moved {} -> {}",
                sb0.generation,
                sb1.generation
            );
        }
        self.decoy_unchanged()?;
        Ok(format!(
            "login {:.0}s; / {}; workload on overlay {:.0}s; root+decoy sha256 unchanged; gen {} unchanged; poweroff {status}; bootlog {}\n{notes}",
            booted.as_secs_f64(),
            if rw { "rw (overlay)" } else { "ro" },
            secs,
            sb1.generation,
            if stick { "saved" } else { "not saved" },
        ))
    }

    fn row_rw(&mut self) -> Result<String> {
        let (mut vm, booted) = self.boot_narf(Policy::Rw, "root-rw")?;
        let before = self.baseline()?.hashes;
        let refusals = Self::refusal_lines(&vm);
        if !Self::root_is_rw(&mut vm)? {
            bail!(
                "/ is not mounted read-write under root-rw: {}",
                refusals.join(" | ")
            );
        }
        let (secs, notes) = Self::workload(&mut vm, "rw")?;
        self.workload_secs = secs;
        let status = vm.poweroff(Duration::from_secs(300))?;
        drop(vm);
        let gen = self.verify_clean("rw", Some("rw"), &before.outside)?;
        Ok(format!(
            "login {:.0}s; workload {secs:.0}s; poweroff {status}; check+csum clean; restore verified; ESP/GPT+decoy unchanged; {gen}\n{notes}{}",
            booted.as_secs_f64(),
            if refusals.is_empty() {
                String::new()
            } else {
                format!("\nrefusals: {}", refusals.join(" | "))
            }
        ))
    }

    /// One NARF root-rw boot after an unclean stop. Returns Ok(true) when it
    /// mounted read-write (and the shell is ready in `vm`), Ok(false) when
    /// it correctly refused because of a log tree (the image untouched).
    fn crash_followup(&mut self, label: &str) -> Result<(Vm, bool)> {
        let (mut vm, _) = self.boot_narf(Policy::Rw, label)?;
        let pre = self.baseline()?;
        let (sb, before) = (pre.sb, pre.hashes);
        let rw = Self::root_is_rw(&mut vm)?;
        let refusals = Self::refusal_lines(&vm);
        if sb.log_root != 0 && rw {
            bail!(
                "root-rw mounted read-write over a log tree (log_root {:#x})",
                sb.log_root
            );
        }
        if !rw {
            let reason = refusals.join(" | ");
            if sb.log_root == 0 || !reason.contains("log tree") {
                bail!("root-rw refused read-write without a log-tree reason: {reason}");
            }
            vm.poweroff(Duration::from_secs(300))?;
            let after = root_hashes(&self.disk)?;
            if after != before {
                bail!("a boot that refused read-write still CHANGED the root disk");
            }
        }
        Ok((vm, rw))
    }

    fn row_crash(&mut self) -> Result<String> {
        let n = self.args.crash_runs;
        let w = if self.workload_secs > 0.0 {
            self.workload_secs
        } else {
            30.0
        };
        let mut lines = Vec::new();
        let mut refused = 0;
        for i in 1..=n {
            // This boot is also the verdict on the previous run's crash: it
            // must mount read-write cleanly or refuse with the log-tree
            // reason without writing.
            let (vm, rw) = self.crash_followup(&format!("crash{i}-boot"))?;
            let mut vm = if rw {
                vm
            } else {
                refused += 1;
                lines.push(format!(
                    "run {i}: boot refused RW (log tree), image untouched; replayed on Linux"
                ));
                drop(vm);
                self.linux_replay(&format!("crash{i}-replay"))?;
                self.host
                    .check(&self.disk, &format!("crash{i}-replayed"), false)?;
                let (vm, rw) = self.crash_followup(&format!("crash{i}-boot2"))?;
                if !rw {
                    bail!("run {i}: still refused after the Linux log replay");
                }
                vm
            };
            let tag = format!("c{i}");
            vm.put_file("/run/narf-gate.sh", &workload_script())?;
            let at = w * (0.05 + 0.9 * self.next_rand());
            vm.send(&format!("bash /run/narf-gate.sh {tag}\n"))?;
            vm.wait_for(
                &[&format!("NARF-GATE-WORKLOAD-START {tag}")],
                Duration::from_secs(120),
            )?;
            std::thread::sleep(Duration::from_secs_f64(at));
            let done = vm
                .text()
                .contains(&format!("NARF-GATE-WORKLOAD-DONE {tag}"));
            vm.kill();
            drop(vm);
            let sb = self.disk.sb()?;
            self.host.check(&self.disk, &format!("crash{i}"), false)?;
            self.decoy_unchanged()?;
            self.progress.push(format!("run {i} killed, check clean"));
            lines.push(format!(
                "run {i}: killed at {at:.1}s{}; check clean; gen {} log_root {}",
                if done { " (after DONE)" } else { "" },
                sb.generation,
                if sb.log_root != 0 { "SET" } else { "0" }
            ));
            // The next boot (next run's, or the final one) judges the
            // mount-time decision.
            if i == n {
                let (mut vm, rw) = self.crash_followup("crash-final")?;
                if rw {
                    vm.poweroff(Duration::from_secs(300))?;
                    drop(vm);
                    self.host.check(&self.disk, "crash-final", true)?;
                    lines.push(
                        "final boot: mounted RW cleanly, clean poweroff, check+csum clean".into(),
                    );
                } else {
                    refused += 1;
                    drop(vm);
                    lines.push("final boot: refused RW (log tree), image untouched".into());
                    self.linux_replay("crash-final-replay")?;
                    self.host.check(&self.disk, "crash-final-replayed", true)?;
                }
            }
        }
        lines.insert(0, format!("{n} kills, {refused} log-tree refusals"));
        Ok(lines.join("\n"))
    }

    fn row_cycles(&mut self) -> Result<String> {
        let mut gens = Vec::new();
        let mut boot_secs = Vec::new();
        for i in 1..=self.args.cycles {
            let (mut vm, booted) = self.boot_narf(Policy::Rw, &format!("cycle{i}"))?;
            let before = self.baseline()?.hashes;
            if !Self::root_is_rw(&mut vm)? {
                bail!(
                    "cycle {i}: / not read-write: {}",
                    Self::refusal_lines(&vm).join(" | ")
                );
            }
            let tag = format!("cy{i}");
            Self::workload(&mut vm, &tag).with_context(|| format!("cycle {i}"))?;
            vm.poweroff(Duration::from_secs(300))
                .with_context(|| format!("cycle {i}"))?;
            drop(vm);
            let gen = self
                .verify_clean(&format!("cycle{i}"), Some(&tag), &before.outside)
                .with_context(|| format!("cycle {i}"))?;
            gens.push(gen.trim_start_matches("gen ").to_string());
            self.progress.push(format!("cycle {i} clean"));
            boot_secs.push(format!("{:.0}", booted.as_secs_f64()));
        }
        Ok(format!(
            "{} cycles clean (check+csum+restore each); generations {}; login s {}",
            self.args.cycles,
            gens.join(","),
            boot_secs.join(",")
        ))
    }

    fn linux_cmd(&self) -> Command {
        let mut c = Command::new("qemu-system-x86_64");
        let mut append = format!(
            "root=PARTUUID={} rootflags=subvol=/@ rw console=ttyS0,115200 \
             systemd.mask=boot-efi.mount systemd.show_status=0 loglevel=4",
            self.disk.root.uuid
        );
        if let Ok(extra) = std::env::var("CACHYOS_GATE_LINUX_APPEND") {
            append.push(' ');
            append.push_str(&extra);
        }
        c.args(["-machine", "q35", "-m", "2048M", "-smp", "2"])
            .args([
                "-serial",
                "stdio",
                "-display",
                "none",
                "-no-reboot",
                "-monitor",
                "none",
            ])
            .args(["-nic", "none"])
            .arg("-kernel")
            .arg(self.work.join("vmlinuz"))
            .arg("-append")
            .arg(append)
            .arg("-drive")
            .arg(format!(
                "if=virtio,format=raw,file={}",
                self.decoy.display()
            ))
            .arg("-drive")
            .arg(format!(
                "if=virtio,format=raw,file={}",
                self.disk.path.display()
            ));
        match &self.accel {
            Some(a) => c.args(["-accel", a, "-cpu", "host"]),
            None => c.args(["-cpu", "max"]),
        };
        c
    }

    fn boot_linux(&mut self, label: &str) -> Result<Vm> {
        self.boots += 1;
        let log = self
            .logs
            .join(format!("{:02}-{label}.serial.log", self.boots));
        println!(
            "cachyos-gate: boot {} ({label}, Linux {})",
            self.boots,
            self.args.linux_kernel.display()
        );
        let mut vm = Vm::spawn(self.linux_cmd(), &log, self.args.verbose)?;
        vm.login(
            &self.args.login_user,
            &self.args.login_password,
            self.timeout(),
        )?;
        Ok(vm)
    }

    /// Mount the root once under Linux (replays a log tree) and power off.
    fn linux_replay(&mut self, label: &str) -> Result<()> {
        let mut vm = self.boot_linux(label)?;
        vm.run("sync", Duration::from_secs(120))?;
        vm.poweroff(Duration::from_secs(300))?;
        if self.disk.sb()?.log_root != 0 {
            bail!("Linux left a log tree after a clean poweroff");
        }
        Ok(())
    }

    fn row_linux(&mut self) -> Result<String> {
        let mut notes = Vec::new();
        let prev = self.last_tag.clone();
        let mut vm = self.boot_linux("linux-interop")?;
        if !Self::root_is_rw(&mut vm)? {
            bail!("Linux did not mount / read-write");
        }
        if let Some(tag) = &prev {
            let (_, out) = vm.run(
                &format!("sha256sum /{GATE_DIR}/big.dat; cat /{GATE_DIR}/small/r7 /{GATE_DIR}/TAG"),
                Duration::from_secs(300),
            )?;
            if !out.contains(&big_sha(tag)) || !out.contains(&format!("narf-gate {tag} small 7")) {
                bail!(
                    "Linux does not read the NARF-written files of round {tag}: {}",
                    tail(&out, 4)
                );
            }
            notes.push(format!("Linux read NARF round {tag}"));
            self.progress.push(format!("Linux read NARF round {tag}"));
        } else {
            notes.push("no NARF-written round to read (rw row not run)".into());
        }
        let (_, wnotes) = Self::workload(&mut vm, "linux")?;
        notes.push(format!("Linux workload ok ({wnotes})"));
        let (rc, out) = vm.run("btrfs scrub start -B /", Duration::from_secs(1800))?;
        if rc != 0 || !out.contains("no errors found") {
            bail!("btrfs scrub under Linux: rc {rc}: {}", tail(&out, 8));
        }
        notes.push("scrub clean".into());
        vm.poweroff(Duration::from_secs(300))?;
        drop(vm);
        let outside = root_hashes(&self.disk)?.outside;
        self.verify_clean("linux", Some("linux"), &outside)?;
        notes.push("host check+csum clean, restore verified".into());
        self.progress.push(
            "Linux mounted / rw, workload ok, scrub clean, host check+csum+restore clean".into(),
        );

        // Round trip: NARF reads Linux's writes, writes again.
        let (mut vm, _) = self.boot_narf(Policy::Rw, "roundtrip")?;
        let before = self.baseline()?.hashes;
        if !Self::root_is_rw(&mut vm)? {
            bail!(
                "NARF refused RW on the Linux-written image: {}",
                Self::refusal_lines(&vm).join(" | ")
            );
        }
        let (_, out) = vm.run(
            &format!("sha256sum /{GATE_DIR}/big.dat; cat /{GATE_DIR}/small/r7"),
            Duration::from_secs(600),
        )?;
        if !out.contains(&big_sha("linux")) || !out.contains("narf-gate linux small 7") {
            bail!(
                "NARF does not read the Linux-written round: {}",
                tail(&out, 4)
            );
        }
        Self::workload(&mut vm, "rt")?;
        vm.poweroff(Duration::from_secs(300))?;
        drop(vm);
        self.verify_clean("roundtrip", Some("rt"), &before.outside)?;
        notes.push("NARF round trip: read Linux files, wrote, check+restore clean".into());
        Ok(notes.join("\n"))
    }
}

impl Gate {
    fn snapshot_manifests(
        &self,
        label: &str,
    ) -> Result<std::collections::BTreeMap<u64, std::collections::BTreeMap<String, String>>> {
        self.host.check(&self.disk, label, true)?;
        let mut all = std::collections::BTreeMap::new();
        for id in self.host.snapshot_ids()? {
            all.insert(id, self.host.snapshot_manifest(id)?);
        }
        Ok(all)
    }

    fn snapshots_unchanged(
        &self,
        label: &str,
        before: &std::collections::BTreeMap<u64, std::collections::BTreeMap<String, String>>,
    ) -> Result<usize> {
        self.host.check(&self.disk, label, true)?;
        let now = self.host.snapshot_ids()?;
        let mut compared = 0;
        for (id, want) in before {
            if !now.contains(id) {
                continue; // deleted on purpose
            }
            let got = self.host.snapshot_manifest(*id)?;
            if &got != want {
                let diff: Vec<&String> = want
                    .keys()
                    .chain(got.keys())
                    .filter(|k| want.get(*k) != got.get(*k))
                    .take(4)
                    .collect();
                bail!("snapshot {id} CHANGED after {label}: {diff:?}");
            }
            compared += 1;
        }
        Ok(compared)
    }

    fn narf_snapshot_round(&mut self, label: &str, tag: &str) -> Result<()> {
        let (mut vm, _) = self.boot_narf(Policy::Rw, label)?;
        let before = self.baseline()?.hashes;
        if !Self::root_is_rw(&mut vm)? {
            bail!(
                "NARF refused RW on the snapshotted root: {}",
                Self::refusal_lines(&vm).join(" | ")
            );
        }
        vm.put_file("/run/narf-snap-narf.sh", SNAP_NARF_SCRIPT)?;
        let (rc, out) = vm.run("bash /run/narf-snap-narf.sh", Duration::from_secs(1800))?;
        if rc != 0 || !out.contains("NARF-SNAP-WRITES-DONE") {
            bail!(
                "NARF writes over shared files failed (rc {rc}): {}",
                tail(&out, 6)
            );
        }
        Self::workload(&mut vm, tag)?;
        vm.poweroff(Duration::from_secs(300))?;
        drop(vm);
        self.verify_clean(label, Some(tag), &before.outside)?;
        Ok(())
    }

    fn row_snapshots(&mut self) -> Result<String> {
        let mut notes = Vec::new();
        let mut vm = self.boot_linux("snap-linux")?;
        vm.put_file("/run/narf-snap.sh", SNAP_SCRIPT)?;
        let (rc, out) = vm.run("bash /run/narf-snap.sh", Duration::from_secs(3600))?;
        if rc != 0 || !out.contains("NARF-SNAP-DONE") {
            bail!("Linux snapshot script failed (rc {rc}): {}", tail(&out, 10));
        }
        vm.poweroff(Duration::from_secs(300))?;
        drop(vm);
        let before = self.snapshot_manifests("snap-linux")?;
        if before.len() < 5 {
            bail!("expected at least 5 snapshots, found {}", before.len());
        }
        notes.push(format!(
            "Linux: {} snapshots (nested .snapshots, rw one written after, top-level, @home), balance -m/-d; check clean",
            before.len()
        ));
        self.progress.push("Linux snapshots made".into());

        self.narf_snapshot_round("snap-narf1", "snap1")?;
        let n = self.snapshots_unchanged("snap-narf1", &before)?;
        notes.push(format!(
            "NARF rw over shared @: check+csum clean, restore verified, {n} snapshots byte-identical"
        ));
        self.progress.push("NARF round 1 clean".into());

        // Linux drops a snapshot (walks every ref NARF changed) and scrubs.
        let mut vm = self.boot_linux("snap-linux-delete")?;
        let (rc, out) = vm.run(
            "btrfs subvolume delete /.snapshots/1/snapshot && btrfs subvolume sync / && btrfs scrub start -B /",
            Duration::from_secs(1800),
        )?;
        if rc != 0 || !out.contains("no errors found") {
            bail!(
                "Linux snapshot delete/scrub failed (rc {rc}): {}",
                tail(&out, 8)
            );
        }
        vm.poweroff(Duration::from_secs(300))?;
        drop(vm);
        let n = self.snapshots_unchanged("snap-linux-delete", &before)?;
        notes.push(format!(
            "Linux deleted snapshot 1 + scrub clean; check clean; {n} snapshots identical"
        ));

        self.narf_snapshot_round("snap-narf2", "snap2")?;
        let n = self.snapshots_unchanged("snap-narf2", &before)?;
        notes.push(format!(
            "NARF round 2: check+csum clean, {n} snapshots byte-identical"
        ));
        Ok(notes.join("\n"))
    }
}

// ── Setup ───────────────────────────────────────────────────────────────

fn build_decoy(path: &Path, dir: &Path) -> Result<()> {
    let content = dir.join("decoy-content");
    std::fs::create_dir_all(content.join("data"))?;
    std::fs::write(
        content.join("data/precious.txt"),
        "Sabrent-shaped decoy: NARF must never write this disk\n",
    )?;
    let (p1, p1_len) = (MIB, MIB);
    let (p2, p2_len) = (2 * MIB, 64 * MIB);
    let _ = std::fs::remove_file(path);
    std::fs::File::create(path)?.set_len(p2 + p2_len + MIB)?;
    let mut sf = Command::new("sfdisk")
        .args(["--quiet", "--no-reread", "--no-tell-kernel"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()?;
    write!(
        sf.stdin.as_mut().unwrap(),
        "label: gpt\nstart={}, size={}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B\nstart={}, size={}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n",
        p1 / 512,
        p1_len / 512,
        p2 / 512,
        p2_len / 512
    )?;
    drop(sf.stdin.take());
    if !sf.wait()?.success() {
        bail!("sfdisk (decoy) failed");
    }
    let spec = format!("{}@@{p1}", path.display());
    super::run_checked(
        Command::new("mformat")
            .env("MTOOLS_SKIP_CHECK", "1")
            .args(["-i", &spec, "-T"])
            .arg((p1_len / 512).to_string())
            .args(["-v", "DECOYP1", "::"]),
        "mformat decoy p1",
    )?;
    let ext = dir.join("decoy-p2.ext4");
    let _ = std::fs::remove_file(&ext);
    std::fs::File::create(&ext)?.set_len(p2_len)?;
    super::run_checked(
        Command::new("mkfs.ext4")
            .args(["-q", "-F", "-L", "DECOYDATA", "-d"])
            .arg(&content)
            .arg(&ext),
        "mkfs.ext4 decoy p2",
    )?;
    let mut out = std::fs::OpenOptions::new().write(true).open(path)?;
    out.seek(SeekFrom::Start(p2))?;
    std::io::copy(&mut std::fs::File::open(&ext)?, &mut out)?;
    let _ = std::fs::remove_file(&ext);
    Ok(())
}

fn build_stick(path: &Path, token: &str, dir: &Path) -> Result<()> {
    let _ = std::fs::remove_file(path);
    std::fs::File::create(path)?.set_len(64 * MIB)?;
    let mut sf = Command::new("sfdisk")
        .args(["--quiet", "--no-reread", "--no-tell-kernel"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()?;
    write!(
        sf.stdin.as_mut().unwrap(),
        "label: dos\nstart=2048, type=c\n"
    )?;
    drop(sf.stdin.take());
    if !sf.wait()?.success() {
        bail!("sfdisk (stick) failed");
    }
    let spec = format!("{}@@{MIB}", path.display());
    super::run_checked(
        Command::new("mformat")
            .env("MTOOLS_SKIP_CHECK", "1")
            .args(["-i", &spec, "-F", "-T"])
            .arg(((64 - 1) * MIB / 512).to_string())
            .args(["-H", "2048", "-v", "NARFLOG", "::"]),
        "mformat bootlog stick",
    )?;
    let id = dir.join("NARFLOG.ID");
    std::fs::write(&id, format!("{token}\n"))?;
    super::run_checked(
        Command::new("mcopy")
            .env("MTOOLS_SKIP_CHECK", "1")
            .args(["-i", &spec])
            .arg(&id)
            .arg("::/NARFLOG.ID"),
        "mcopy NARFLOG.ID",
    )
}

/// `limine.conf` with `narf.bootlog=<token>` added to each command line
/// (only for re-tokenising an already built bundle with `--skip-build`; a
/// fresh bundle gets it from `grub-image --bootlog-token`).
fn with_bootlog(conf: &str, token: &str) -> String {
    conf.lines()
        .map(|l| {
            if l.trim_start().starts_with("kernel_cmdline:") && !l.contains("narf.bootlog=") {
                format!("{l} narf.bootlog={token}")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The bundle's command line (first `kernel_cmdline:`).
fn bundle_cmdline(conf: &str) -> String {
    conf.lines()
        .find_map(|l| l.trim().strip_prefix("kernel_cmdline:").map(str::trim))
        .unwrap_or_default()
        .to_string()
}

/// Build the `grub-image` bundle for `policy` and stage it (plus a
/// standalone GRUB whose embedded config is the bundle's own `grub.cfg`
/// stanza) under `out`.
fn stage_bundle(
    args: &Args,
    policy: Policy,
    uuid: &str,
    token: &str,
    out: &Path,
) -> Result<String> {
    let root = super::workspace_root()?;
    let mut build = args.build.clone();
    // The bundle a host install uses for the distro root: the systemd PID 1
    // configuration (boot-init, cgroup-all, container, unsigned firmware).
    super::configure_systemd_pid1_build(&mut build, false);
    super::ensure_feature(&mut build.features, "boot-init");
    super::ensure_feature(&mut build.features, "firmware-allow-unsigned");
    let grub = super::GrubImageArgs {
        build,
        allow_all_disks: false,
        root_policy: Some(match policy {
            Policy::Ro => super::RootPolicy::RootRo,
            Policy::Rw => super::RootPolicy::RootRw,
        }),
        root_uuid: Some(uuid.to_string()),
        rootflags: "subvol=/@".to_string(),
        bootlog_token: Some(token.to_string()),
    };
    super::grub_image_cmd(&grub)?;
    let bundle = root.join("target/grub-x86_64");
    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out.join("grub"))?;
    super::run_checked(
        Command::new("cp")
            .arg("-a")
            .arg(bundle.join("esp"))
            .arg(out.join("esp")),
        "stage the bundle ESP",
    )?;
    // `--bootlog-token` put `narf.bootlog=` on the command line already.
    let conf = std::fs::read_to_string(out.join("esp/boot/limine/limine.conf"))?;
    if !conf.contains(&format!("narf.bootlog={token}")) {
        bail!("grub-image --bootlog-token did not reach limine.conf");
    }
    let stanza = std::fs::read_to_string(bundle.join("grub.cfg"))?;
    std::fs::write(out.join("grub/bundle-grub.cfg"), &stanza)?;
    let cfg = out.join("grub/grub.cfg");
    std::fs::write(&cfg, format!("set timeout=0\nset default=0\n{stanza}"))?;
    super::run_checked(
        Command::new("grub-mkstandalone")
            .args(["-O", "x86_64-efi", "--locales=", "--fonts=", "--themes="])
            .arg("--modules=part_gpt part_msdos fat search search_fs_file chain")
            .arg("-o")
            .arg(out.join("grub/BOOTX64.EFI"))
            .arg(format!("boot/grub/grub.cfg={}", cfg.display())),
        "grub-mkstandalone",
    )?;
    Ok(bundle_cmdline(&conf))
}

fn host_uuids() -> Vec<String> {
    let mut v = vec![
        HOST_ROOT_FSID.to_string(),
        HOST_ESP_UUID.to_string(),
        HOST_DATA_UUID.to_string(),
    ];
    for m in ["/", "/boot/efi", "/home"] {
        if let Ok(o) = Command::new("findmnt").args(["-no", "UUID", m]).output() {
            let u = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !u.is_empty() && !v.contains(&u) {
                v.push(u);
            }
        }
    }
    v
}

pub fn run(args: &Args) -> Result<()> {
    if !matches!(args.build.arch, super::Arch::X86_64) {
        bail!("cachyos-gate is x86_64-only");
    }
    for tool in [
        "qemu-system-x86_64",
        "btrfs",
        "sfdisk",
        "mformat",
        "mcopy",
        "mmd",
        "mkfs.ext4",
        "grub-mkstandalone",
        "cp",
        "findmnt",
    ] {
        if !which(tool) {
            bail!("cachyos-gate: `{tool}` not on $PATH");
        }
    }
    let root = super::workspace_root()?;
    let work = args
        .work_dir
        .clone()
        .unwrap_or_else(|| root.join("target/cachyos-gate"));
    let logs = work.join("logs");
    if !args.skip_build {
        let _ = std::fs::remove_dir_all(&work);
    } else {
        let _ = std::fs::remove_dir_all(&logs);
        let _ = std::fs::remove_dir_all(work.join("check"));
    }
    std::fs::create_dir_all(&logs)?;
    let host_uuids = host_uuids();

    // The root disk: a fresh copy of the cachyos-root-smoke image (built by
    // its script on first use) or of the user's Gate C image.
    let disk_path = match &args.real_root {
        Some(img) if args.in_place => img.clone(),
        Some(img) => {
            let p = work.join("root.img");
            println!("cachyos-gate: copying {} (Gate C)", img.display());
            copy_image(img, &p)?;
            p
        }
        None => {
            let base = super::cachyos_root::ensure_image(&root, args.rebuild_image)?;
            let p = work.join("root.img");
            copy_image(&base, &p)?;
            p
        }
    };
    let disk = RootDisk::open(&disk_path)?;
    if host_uuids
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&disk.fsid) || h.eq_ignore_ascii_case(&disk.esp_uuid))
    {
        bail!(
            "the image shares a filesystem UUID with a HOST disk (btrfs {}, ESP {}); \
             rebuild it with a fresh fsid (`btrfstune -U`/mkfs -U) before running the gate",
            disk.fsid,
            disk.esp_uuid
        );
    }
    let host = HostCheck::new(&work)?;
    let sb = disk.sb()?;
    if sb.log_root != 0 {
        bail!("the image has a log tree (unclean); mount it once on Linux first");
    }
    let fstab = host.fstab(&disk)?;
    check_fstab(&fstab, &disk, &host_uuids)?;
    println!(
        "cachyos-gate: root disk {} (btrfs {} gen {}, ESP {}); fstab pinned to the image",
        disk.path.display(),
        disk.fsid,
        sb.generation,
        disk.esp_uuid
    );

    let token = format!("gate{:016x}", seed_now());
    let mut cmdlines = Vec::new();
    for p in [Policy::Ro, Policy::Rw] {
        let dir = work.join(format!("bundle-{}", p.name()));
        if args.skip_build && dir.join("grub/BOOTX64.EFI").exists() {
            let conf = std::fs::read_to_string(dir.join("esp/boot/limine/limine.conf"))?;
            let conf = conf
                .lines()
                .map(|l| {
                    if l.trim_start().starts_with("kernel_cmdline:") {
                        let kept: Vec<&str> = l
                            .split(' ')
                            .filter(|t| !t.starts_with("narf.bootlog="))
                            .collect();
                        kept.join(" ")
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let conf = with_bootlog(&conf, &token);
            std::fs::write(dir.join("esp/boot/limine/limine.conf"), &conf)?;
            cmdlines.push(bundle_cmdline(&conf));
        } else {
            cmdlines.push(stage_bundle(args, p, &disk.fsid, &token, &dir)?);
        }
    }
    for (p, c) in [Policy::Ro, Policy::Rw].iter().zip(&cmdlines) {
        println!("cachyos-gate: {} bundle cmdline: {c}", p.name());
        let want = format!("root=UUID={}", disk.fsid);
        if !c.contains(&want) || !c.contains("systemd_pid1") || !c.contains("rootflags=subvol=/@") {
            bail!(
                "the {} bundle's command line lacks the installed-root arguments",
                p.name()
            );
        }
    }

    let decoy = work.join("decoy-nvme.img");
    build_decoy(&decoy, &work)?;
    let stick = work.join("bootlog-stick.img");
    build_stick(&stick, &token, &work)?;
    let decoy_sha = sha256_file(&decoy)?;
    let ovmf = super::ovmf_code_path();
    let odir = ovmf.parent().map(Path::to_path_buf).unwrap_or_default();
    let (code, vars) = [
        ("OVMF_CODE.4m.fd", "OVMF_VARS.4m.fd"),
        ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd"),
        ("OVMF_CODE.fd", "OVMF_VARS.fd"),
    ]
    .iter()
    .map(|(c, v)| (odir.join(c), odir.join(v)))
    .find(|(c, v)| c.is_file() && v.is_file())
    .ok_or_else(|| anyhow!("split OVMF CODE/VARS not found next to {}", ovmf.display()))?;
    let ovmf_vars = work.join("OVMF_VARS.fd");
    std::fs::copy(&vars, &ovmf_vars)?;
    if args.cases.contains(&Case::Linux)
        || args.cases.contains(&Case::Crash)
        || args.cases.contains(&Case::Snapshots)
    {
        std::fs::copy(&args.linux_kernel, work.join("vmlinuz"))
            .with_context(|| format!("copy the Linux kernel {}", args.linux_kernel.display()))?;
    }
    let seed = args.seed.unwrap_or_else(seed_now);
    println!("cachyos-gate: crash seed {seed}");

    let mut gate = Gate {
        args: args.clone(),
        work: work.clone(),
        logs,
        disk,
        decoy,
        decoy_sha,
        stick,
        token,
        ovmf_code: code,
        ovmf_vars,
        host,
        host_uuids,
        boots: 0,
        installs: InstallLedger::default(),
        preboot: None,
        workload_secs: 0.0,
        rng: seed | 1,
        last_tag: None,
        accel: kvm_accel(),
        progress: Vec::new(),
        prekernel_hangs: Vec::new(),
    };
    let _ = (&gate.token, &gate.host_uuids);

    let mut rows = vec![Row {
        name: "topology".into(),
        verdict: Verdict::Pass,
        detail: format!(
            "q35+OVMF; OVMF -> GRUB (grub-mkstandalone, bundle grub.cfg) -> Limine -> NARF\n\
             nvme 00:04.0 decoy GPT vfat+ext4; nvme 00:07.0 root GPT ESP+btrfs {}\n\
             ro cmdline: {}\nrw cmdline: {}",
            gate.disk.fsid, cmdlines[0], cmdlines[1]
        ),
    }];
    let mut cases = args.cases.clone();
    cases.sort();
    cases.dedup();
    for case in cases {
        gate.progress.clear();
        let (name, r) = match case {
            Case::Ro => ("1 root-ro".to_string(), gate.row_ro()),
            Case::Rw => ("2 root-rw".to_string(), gate.row_rw()),
            Case::Crash => (format!("3 crash x{}", args.crash_runs), gate.row_crash()),
            Case::Cycles => (format!("4 cycles x{}", args.cycles), gate.row_cycles()),
            Case::Linux => ("5 linux interop".to_string(), gate.row_linux()),
            Case::Snapshots => ("6 snapshots".to_string(), gate.row_snapshots()),
        };
        let row = match r {
            Ok(detail) => Row {
                name,
                verdict: Verdict::Pass,
                detail,
            },
            Err(e) => Row {
                name,
                verdict: Verdict::Fail,
                detail: if gate.progress.is_empty() {
                    format!("{e:#}")
                } else {
                    format!("ok so far: {}\nFAILED: {e:#}", gate.progress.join("; "))
                },
            },
        };
        println!(
            "cachyos-gate: {} {}",
            row.name,
            if row.verdict == Verdict::Pass {
                "PASS"
            } else {
                "FAIL"
            }
        );
        rows.push(row);
    }
    rows.push(Row {
        name: "boot chain".into(),
        verdict: Verdict::Pass,
        detail: if gate.prekernel_hangs.is_empty() {
            format!("{} boots; none hung before the kernel", gate.boots)
        } else {
            format!(
                "{} boots; {} pre-kernel hang(s), each passed on retry:\n{}",
                gate.boots,
                gate.prekernel_hangs.len(),
                gate.prekernel_hangs.join("\n")
            )
        },
    });
    print_table(&rows);
    println!("\nlogs: {}", work.join("logs").display());
    println!("host check logs: {}", work.join("check").display());
    let failed = rows.iter().filter(|r| r.verdict == Verdict::Fail).count();
    if failed > 0 {
        bail!("cachyos-gate: {failed} row(s) FAILED");
    }
    println!("cachyos-gate: all rows PASS");
    Ok(())
}

fn seed_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(super::base64_lines(b"", 76), "");
        assert_eq!(super::base64_lines(b"f", 76), "Zg==\n");
        assert_eq!(super::base64_lines(b"fo", 76), "Zm8=\n");
        assert_eq!(super::base64_lines(b"foo", 76), "Zm9v\n");
        assert_eq!(super::base64_lines(b"foobar", 4), "Zm9v\nYmFy\n");
        assert_eq!(
            super::base64_lines(b"set -u\nT=\"$1\"\n", 76),
            "c2V0IC11ClQ9IiQxIgo=\n"
        );
    }

    #[test]
    fn install_after_snapshot_is_refused() {
        let mut ledger = InstallLedger::default();
        ledger.installed();
        let seq = ledger.snapshot();
        assert!(ledger.verify(seq).is_ok());
        // The old row_ro bug: install, hash, then boot_narf installed again.
        ledger.installed();
        assert!(ledger.verify(seq).is_err());
    }
    use super::*;

    #[test]
    fn escapes_are_stripped() {
        let raw = b"\x1b]3008;start=x;type=command\x1b\\rw,relatime\r\n\x1b[?2004hgate# ";
        assert_eq!(strip_escapes(raw), "rw,relatime\ngate# ");
    }

    #[test]
    fn guid_is_mixed_endian() {
        let b = [
            0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e,
            0xc9, 0x3b,
        ];
        assert_eq!(guid(&b), GPT_ESP_TYPE);
    }

    #[test]
    fn bootlog_is_appended_once() {
        let conf = "/NARF\n    path: boot():/boot/narf-frame\n    kernel_cmdline: narf.disks=root-rw root=UUID=u\n";
        let out = with_bootlog(conf, "tok12345");
        assert!(
            out.contains("kernel_cmdline: narf.disks=root-rw root=UUID=u narf.bootlog=tok12345")
        );
        assert_eq!(with_bootlog(&out, "tok12345"), out);
        assert_eq!(
            bundle_cmdline(&out),
            "narf.disks=root-rw root=UUID=u narf.bootlog=tok12345"
        );
    }

    #[test]
    fn fstab_must_be_pinned_to_the_image() {
        let d = RootDisk {
            path: PathBuf::new(),
            esp: Part {
                start: 0,
                len: 0,
                type_guid: String::new(),
                uuid: String::new(),
            },
            root: Part {
                start: 0,
                len: 0,
                type_guid: String::new(),
                uuid: String::new(),
            },
            fsid: "c4c405ee-0000-4a11-9e57-00000000c0de".into(),
            esp_uuid: "CA50-EF15".into(),
        };
        let hosts = vec![HOST_ROOT_FSID.to_string(), HOST_ESP_UUID.to_string()];
        let good = "UUID=CA50-EF15 /boot/efi vfat defaults 0 2\n\
                    UUID=c4c405ee-0000-4a11-9e57-00000000c0de / btrfs subvol=/@ 0 0\n\
                    tmpfs /tmp tmpfs defaults 0 0\n";
        check_fstab(good, &d, &hosts).unwrap();
        let host_root = good.replace("c4c405ee-0000-4a11-9e57-00000000c0de", HOST_ROOT_FSID);
        assert!(check_fstab(&host_root, &d, &hosts).is_err());
        let host_esp = good.replace("CA50-EF15", HOST_ESP_UUID);
        assert!(check_fstab(&host_esp, &d, &hosts).is_err());
        assert!(check_fstab("/dev/nvme0n1p2 / btrfs defaults 0 0\n", &d, &hosts).is_err());
    }

    #[test]
    fn big_sha_matches_yes_head() {
        // `yes "narf-gate t big" | head -c 100M | sha256sum`, computed the
        // slow way.
        let line = b"narf-gate t big\n";
        let mut h = Sha256::new();
        let mut n = 0u64;
        while n < BIG_BYTES {
            let take = (BIG_BYTES - n).min(line.len() as u64) as usize;
            h.update(&line[..take]);
            n += take as u64;
        }
        assert_eq!(big_sha("t"), hex(&h.finalize()));
    }
}
