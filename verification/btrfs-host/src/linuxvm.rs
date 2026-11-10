//! A real Linux kernel as the oracle for tree-log replay, without root: the
//! host's installed kernel booted under `qemu-system-x86_64` with the test
//! image as a virtio disk and a one-binary initramfs (`vminit.c`, built
//! static with the host `cc`).
//!
//! Two uses:
//!
//! * **Linux replays a log** ([`Vm::mount_and_list`]): the guest mounts the
//!   image read-write — which replays a tree log NARF (or Linux) left —
//!   lists every entry with its size and a content hash, unmounts cleanly
//!   and powers off. Kernel messages mentioning btrfs come back too.
//! * **Linux writes a log** ([`Vm::run_script`] with a `crash` line): the
//!   guest runs an op script (write, fsync, rename, …) and stops at `crash`;
//!   the VM is then killed, leaving the image as a power cut would.
//!
//! [`Vm::locate`] returns `Err(reason)` when no usable kernel, QEMU or
//! static C toolchain is found. Callers must report that as *unverified*,
//! never as a pass.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VMINIT_C: &str = include_str!("vminit.c");

/// The byte both sides write at absolute file offset `off` for a write of
/// `seed` (`vminit.c::pattern`).
pub fn pattern(seed: u64, off: u64) -> u8 {
    let mut x = off.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seed.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    x ^= x >> 29;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    (x >> 32) as u8
}

pub fn pattern_bytes(seed: u64, off: u64, len: usize) -> Vec<u8> {
    (0..len as u64).map(|i| pattern(seed, off + i)).collect()
}

/// FNV-1a, as `vminit.c::fnv`.
pub fn fnv(data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// One directory entry as a mounted filesystem shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ent {
    /// `f` regular, `d` directory, `l` symlink, `o` other.
    pub kind: char,
    pub perms: u32,
    pub nlink: u64,
    /// File size (0 for directories).
    pub size: u64,
    /// FNV-1a of the content (a symlink's target); the offset basis for
    /// directories.
    pub hash: u64,
}

/// Path → entry of a whole mounted tree.
pub type Listing = BTreeMap<String, Ent>;

/// What one guest run produced.
#[derive(Debug, Default)]
pub struct VmOut {
    pub release: String,
    pub mounted: bool,
    pub mount_errno: i32,
    pub listing: Listing,
    /// Script lines that failed: `(line, errno, text)`.
    pub failed_ops: Vec<(usize, i32, String)>,
    pub ops_ok: usize,
    pub kmsg: Vec<String>,
    /// The script reached its `crash` line and the VM was killed there.
    pub crashed: bool,
    /// The guest reported `VM-DONE ok`.
    pub done_ok: bool,
    pub raw: String,
}

impl VmOut {
    /// Kernel messages that mean the filesystem was not accepted as is.
    pub fn kernel_complaints(&self) -> Vec<&str> {
        self.kmsg
            .iter()
            .map(String::as_str)
            .filter(|l| {
                let l = l.to_ascii_lowercase();
                l.contains("error")
                    || l.contains("corrupt")
                    || l.contains("warning")
                    || l.contains("failed")
                    || l.contains("unable")
                    || l.contains("bad ")
            })
            .collect()
    }
}

pub struct Vm {
    kernel: PathBuf,
    initrd: PathBuf,
    kvm: bool,
    pub release: String,
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A `newc` cpio archive holding one executable `/init`.
fn cpio_with_init(init: &[u8]) -> Vec<u8> {
    fn entry(out: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        let fields = [
            1u32,                  // ino
            mode,                  // mode
            0,                     // uid
            0,                     // gid
            1,                     // nlink
            0,                     // mtime
            data.len() as u32,     // filesize
            0,                     // devmajor
            0,                     // devminor
            0,                     // rdevmajor
            0,                     // rdevminor
            name.len() as u32 + 1, // namesize
            0,                     // check
        ];
        out.extend_from_slice(b"070701");
        for f in fields {
            out.extend_from_slice(format!("{f:08x}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    let mut out = Vec::new();
    entry(&mut out, "init", 0o100755, init);
    entry(&mut out, "TRAILER!!!", 0, &[]);
    while out.len() % 512 != 0 {
        out.push(0);
    }
    out
}

impl Vm {
    /// Find a kernel that mounts btrfs from a virtio disk with nothing but
    /// our initramfs, and build that initramfs under `workdir`.
    ///
    /// `NARF_LINUX_KERNEL` names the kernel image to use; otherwise every
    /// readable `/boot/vmlinuz*` is tried, newest first.
    pub fn locate(workdir: &Path) -> Result<Vm, String> {
        for tool in ["qemu-system-x86_64", "cc", "mkfs.btrfs"] {
            if !have(tool) {
                return Err(format!("`{tool}` not on PATH"));
            }
        }
        std::fs::create_dir_all(workdir).map_err(|e| format!("{}: {e}", workdir.display()))?;
        let src = workdir.join("vminit.c");
        let init = workdir.join("vminit");
        std::fs::write(&src, VMINIT_C).map_err(|e| format!("write vminit.c: {e}"))?;
        let cc = Command::new("cc")
            .args(["-static", "-O1", "-o"])
            .arg(&init)
            .arg(&src)
            .output()
            .map_err(|e| format!("cc: {e}"))?;
        if !cc.status.success() {
            return Err(format!(
                "cannot build a static guest init (cc -static): {}",
                String::from_utf8_lossy(&cc.stderr).trim()
            ));
        }
        let initrd = workdir.join("vminit.cpio");
        let bin = std::fs::read(&init).map_err(|e| format!("read vminit: {e}"))?;
        std::fs::write(&initrd, cpio_with_init(&bin)).map_err(|e| format!("write initrd: {e}"))?;

        let mut kernels: Vec<PathBuf> = match std::env::var_os("NARF_LINUX_KERNEL") {
            Some(k) => vec![PathBuf::from(k)],
            None => {
                let mut found: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir("/boot")
                    .map_err(|e| format!("/boot: {e}"))?
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("vmlinuz"))
                            && std::fs::File::open(p).is_ok()
                    })
                    .map(|p| {
                        let t = std::fs::metadata(&p)
                            .and_then(|m| m.modified())
                            .unwrap_or(std::time::UNIX_EPOCH);
                        (t, p)
                    })
                    .collect();
                found.sort();
                found.into_iter().rev().map(|(_, p)| p).collect()
            }
        };
        if kernels.is_empty() {
            return Err("no readable /boot/vmlinuz* (set NARF_LINUX_KERNEL)".into());
        }
        let kvm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok();
        // Probe: the kernel must mount a fresh btrfs from /dev/vda.
        let probe = workdir.join("probe.img");
        let mut why = Vec::new();
        for kernel in kernels.drain(..) {
            let _ = std::fs::remove_file(&probe);
            let f = std::fs::File::create(&probe).map_err(|e| format!("probe image: {e}"))?;
            f.set_len(128 << 20)
                .map_err(|e| format!("probe image: {e}"))?;
            drop(f);
            let mk = Command::new("mkfs.btrfs")
                .arg("-q")
                .arg(&probe)
                .output()
                .map_err(|e| format!("mkfs.btrfs: {e}"))?;
            if !mk.status.success() {
                return Err("mkfs.btrfs failed on the probe image".into());
            }
            let vm = Vm {
                kernel: kernel.clone(),
                initrd: initrd.clone(),
                kvm,
                release: String::new(),
            };
            match vm.run(&probe, None) {
                Ok(out) if out.mounted && out.done_ok => {
                    let _ = std::fs::remove_file(&probe);
                    return Ok(Vm {
                        release: out.release,
                        ..vm
                    });
                }
                Ok(out) => why.push(format!(
                    "{}: {}",
                    kernel.display(),
                    if out.release.is_empty() {
                        "did not reach the guest init".to_string()
                    } else if !out.mounted {
                        format!(
                            "{} cannot mount btrfs from virtio (errno {}; both must be built in)",
                            out.release, out.mount_errno
                        )
                    } else {
                        format!("{} did not finish the probe", out.release)
                    }
                )),
                Err(e) => why.push(format!("{}: {e}", kernel.display())),
            }
        }
        let _ = std::fs::remove_file(&probe);
        Err(format!("no usable kernel: {}", why.join("; ")))
    }

    pub fn describe(&self) -> String {
        format!(
            "Linux {} ({}, {})",
            self.release,
            self.kernel.display(),
            if self.kvm { "kvm" } else { "tcg" }
        )
    }

    /// Mount `img` in the guest (replaying its log), list it, unmount.
    pub fn mount_and_list(&self, img: &Path) -> Result<VmOut, String> {
        let out = self.run(img, None)?;
        if !out.mounted {
            return Err(format!(
                "Linux refused to mount (errno {}):\n  {}",
                out.mount_errno,
                out.kmsg.join("\n  ")
            ));
        }
        if !out.done_ok {
            return Err(format!(
                "Linux guest did not finish cleanly:\n{}",
                tail(&out.raw, 30)
            ));
        }
        Ok(out)
    }

    /// Run `script` in the guest against `img`. A script ending in `crash`
    /// leaves the image as it was when that line was reached.
    pub fn run_script(&self, img: &Path, script: &str) -> Result<VmOut, String> {
        let out = self.run(img, Some(script))?;
        if !out.mounted {
            return Err(format!(
                "Linux refused to mount (errno {})",
                out.mount_errno
            ));
        }
        if let Some((line, errno, text)) = out.failed_ops.first() {
            return Err(format!(
                "guest script line {line} failed (errno {errno}): {text}"
            ));
        }
        Ok(out)
    }

    fn run(&self, img: &Path, script: Option<&str>) -> Result<VmOut, String> {
        let mut cmd = Command::new("qemu-system-x86_64");
        if self.kvm {
            cmd.args(["-enable-kvm", "-cpu", "host"]);
        } else {
            cmd.args(["-cpu", "max"]);
        }
        cmd.args([
            "-m",
            "768",
            "-display",
            "none",
            "-no-reboot",
            "-monitor",
            "none",
        ])
        .args(["-serial", "stdio"])
        .arg("-kernel")
        .arg(&self.kernel)
        .arg("-initrd")
        .arg(&self.initrd)
        .arg("-drive")
        .arg(format!(
            "file={},if=virtio,format=raw,cache=unsafe",
            img.display()
        ))
        .args(["-append", "console=ttyS0 panic=-1 quiet loglevel=3"]);
        let script_img = img.with_extension("vmscript");
        if let Some(script) = script {
            let mut bytes = script.as_bytes().to_vec();
            bytes.push(b'\n');
            if bytes.len() >= 1 << 20 {
                return Err("guest script too large".into());
            }
            bytes.resize(1 << 20, 0);
            std::fs::write(&script_img, bytes).map_err(|e| format!("script image: {e}"))?;
            cmd.arg("-drive").arg(format!(
                "file={},if=virtio,format=raw,readonly=on",
                script_img.display()
            ));
        }
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("qemu: {e}"))?;
        let stdout = child.stdout.take().unwrap();
        // The reader thread hands lines over a channel so a silent guest
        // times out instead of blocking forever.
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).split(b'\n').map_while(Result::ok) {
                let line = String::from_utf8_lossy(&line).trim_end().to_string();
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(if self.kvm { 120 } else { 600 });
        let mut out = VmOut::default();
        let mut finished = false;
        while Instant::now() < deadline {
            let line = match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => line,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
            out.raw.push_str(&line);
            out.raw.push('\n');
            let Some(at) = line.find("VM-") else {
                continue;
            };
            let rec = &line[at..];
            let mut words = rec.split(' ');
            match words.next() {
                Some("VM-UP") => out.release = words.next().unwrap_or("").to_string(),
                Some("VM-MOUNT") => {
                    out.mounted = words.next() == Some("ok");
                    out.mount_errno = words.next().and_then(|w| w.parse().ok()).unwrap_or(0);
                }
                Some("VM-OP") => {
                    let n = words.next().and_then(|w| w.parse().ok()).unwrap_or(0);
                    let ok = words.next() == Some("ok");
                    let errno = words.next().and_then(|w| w.parse().ok()).unwrap_or(0);
                    if ok {
                        out.ops_ok += 1;
                    } else {
                        out.failed_ops
                            .push((n, errno, words.collect::<Vec<_>>().join(" ")));
                    }
                }
                Some("VM-ENT") => {
                    let f: Vec<&str> = rec.splitn(7, ' ').collect();
                    if f.len() == 7 {
                        out.listing.insert(
                            f[6].to_string(),
                            Ent {
                                kind: f[1].chars().next().unwrap_or('?'),
                                perms: u32::from_str_radix(f[2], 8).unwrap_or(u32::MAX),
                                nlink: f[3].parse().unwrap_or(u64::MAX),
                                size: f[4].parse().unwrap_or(u64::MAX),
                                hash: u64::from_str_radix(f[5], 16).unwrap_or(0),
                            },
                        );
                    }
                }
                Some("VM-KMSG") => out.kmsg.push(rec["VM-KMSG".len()..].trim().to_string()),
                Some("VM-ERR") => {
                    out.failed_ops
                        .push((0, 0, rec["VM-ERR".len()..].trim().to_string()))
                }
                Some("VM-CRASH") => {
                    out.crashed = true;
                    finished = true;
                    break;
                }
                Some("VM-DONE") => {
                    out.done_ok = words.next() == Some("ok");
                    finished = true;
                    break;
                }
                _ => {}
            }
        }
        if out.crashed || !finished {
            // A power cut: no unmount, no flush of anything the guest held.
            let _ = child.kill();
        } else {
            // Let the guest power off so QEMU closes the image cleanly.
            let until = Instant::now() + Duration::from_secs(20);
            while Instant::now() < until {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
        }
        let _ = child.wait();
        let _ = reader.join();
        let _ = std::fs::remove_file(&script_img);
        if !finished {
            return Err(format!(
                "Linux guest produced no verdict before the timeout:\n{}",
                tail(&out.raw, 30)
            ));
        }
        Ok(out)
    }
}

fn tail(s: &str, lines: usize) -> String {
    let v: Vec<&str> = s.lines().collect();
    v[v.len().saturating_sub(lines)..].join("\n")
}

/// Escape a path the way `vminit.c::escape` prints it.
pub fn escape(path: &str) -> String {
    let mut out = String::new();
    for &b in path.as_bytes() {
        if b <= 0x20 || b >= 0x7f || b == b'\\' {
            out.push_str(&format!("\\x{b:02x}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

/// Differences between two listings, at most `limit` lines.
pub fn diff_listings(
    a_name: &str,
    a: &Listing,
    b_name: &str,
    b: &Listing,
    limit: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    for (path, ea) in a {
        match b.get(path) {
            None => out.push(format!("{path}: in {a_name} only ({ea:?})")),
            Some(eb) if ea != eb => out.push(format!("{path}: {a_name} {ea:?} vs {b_name} {eb:?}")),
            _ => {}
        }
    }
    for (path, eb) in b {
        if !a.contains_key(path) {
            out.push(format!("{path}: in {b_name} only ({eb:?})"));
        }
    }
    out.truncate(limit);
    out
}

/// Write a listing to `path` (for a failed run's work directory).
pub fn save_listing(path: &Path, listing: &Listing) {
    if let Ok(mut f) = std::fs::File::create(path) {
        for (p, e) in listing {
            let _ = writeln!(
                f,
                "{} {:o} {} {} {:016x} {p}",
                e.kind, e.perms, e.nlink, e.size, e.hash
            );
        }
    }
}
