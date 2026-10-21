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
//!
//! `--disk <image>` boots an existing installed CachyOS disk instead (for
//! example a desktop VM image with plymouth and plasmalogin). The image is
//! only ever a read-only qcow2 backing file: the guest's NVMe is a fresh
//! overlay, and under root-ro the overlay must come back with no data
//! allocated. With `--passthrough-device` (a GPU passed through VFIO) and
//! `--interactive`, this is the bench for a graphical boot on real silicon:
//! the picture is on the card's own outputs and the serial console is the
//! terminal.

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
/// Copy-on-write overlay over a `--disk` image.
const DISK_OVERLAY: &str = "target/narf-cachyos-disk-overlay.qcow2";
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

    /// Leave the guest running after the report instead of powering it off
    /// through systemd (the run then ends by killing QEMU).
    #[arg(long)]
    pub no_poweroff: bool,

    /// Seconds to wait for the login prompt.
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,

    /// Boot this installed CachyOS disk image (raw or qcow2) instead of the
    /// generated fixture. It is never written: the guest gets a fresh qcow2
    /// overlay backed by it. Its root password is unknown, so the run stops
    /// at the login prompt unless `--interactive`.
    #[arg(long, value_name = "IMAGE")]
    pub disk: Option<PathBuf>,

    /// Filesystem UUID of the `--disk` root. Default: the first btrfs or
    /// ext4 partition in the image's GPT (raw images only).
    #[arg(long, value_name = "UUID", requires = "disk")]
    pub root_uuid: Option<String>,

    /// Keep the `--disk` overlay after the run instead of deleting it.
    #[arg(long, requires = "disk")]
    pub keep_overlay: bool,

    /// Attach this terminal to the guest's serial console and run until the
    /// guest powers off (or Ctrl-C), instead of the scripted login.
    #[arg(long)]
    pub interactive: bool,

    /// Also write the guest's serial output to this file.
    #[arg(long, value_name = "FILE")]
    pub serial_log: Option<PathBuf>,
}

/// The `--disk` being booted, as `run` prepared it.
struct DiskBoot {
    base: PathBuf,
    overlay: PathBuf,
    /// `(length, mtime)` of the base before the boot.
    base_stamp: (u64, std::time::SystemTime),
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
    "mkdir -p /narf-smoke/many; n=0; for i in $(seq 1 60); do printf 'narf %d\\n' $i > /narf-smoke/many/f$i || break; n=$i; done; echo NARF-MANY-FILES $n",
    "ls /var/log/journal 2>/dev/null | head -n 3 | sed 's/^/NARF-JOURNAL /'",
    "udevadm info -q property -n /dev/nvme1n1p2 | grep -E 'DEVNAME|DEVLINKS|ID_FS|BTRFS|SYSTEMD|TAGS|USEC' | sed 's/^/NARF-UDEV /'",
    "for u in $(systemctl --no-legend --plain --failed | cut -d' ' -f1); do echo NARF-UNIT $u; journalctl -b --no-pager -o cat -n 8 -u $u; done",
    "/usr/lib/systemd/systemd-remount-fs 2>&1 | head -n 5 | sed 's/^/NARF-REMOUNT-FS /'",
    "systemd-sysusers 2>&1 | head -n 3 | sed 's/^/NARF-SYSUSERS /'",
    "/usr/lib/systemd/systemd-random-seed save 2>&1 | head -n 3 | sed 's/^/NARF-RANDOM-SEED /'",
    "ldconfig 2>&1 | head -n 3 | sed 's/^/NARF-LDCONFIG /'",
    "journalctl -b --no-pager -o cat _SYSTEMD_UNIT=systemd-sysusers.service | head -n 3 | sed 's/^/NARF-JOURNAL-UNIT /'",
    "echo NARF-JOURNAL-U $(journalctl -q -b -o cat -u systemd-journald.service | wc -l)",
    "echo NARF-PID1-MAPS $(wc -l < /proc/1/maps)",
    "timeout 5 /usr/lib/systemd/systemd-oomd 2>&1 | head -n 5 | sed 's/^/NARF-OOMD /'",
    "journalctl -b --no-pager -p warning -o cat | tail -n 40",
    "sed 's/^/NARF-MI /' /proc/1/mountinfo",
    "journalctl -b --no-pager -o cat _PID=1 | grep -iE 'mountinfo|libmount|mount table|monitor' | tail -n 25 | sed 's/^/NARF-PID1 /'",
    "echo NARF-CACHYOS-ROOT-$((40+2))-DONE",
];

/// systemd's verdict when a mount helper succeeded but PID 1 never saw the
/// mount appear in `/proc/self/mountinfo` (a lost libmount change edge).
const NO_MOUNT_MARKER: &str = "Mount process finished, but there is no mount";

/// systemd's verdict when a device unit (a `/dev/disk/by-uuid` link, a swap
/// device) never became ready: udev never finished the device, or nothing
/// will ever create it.
const DEVICE_TIMEOUT_MARKER: &str = "Timed out waiting for device";

/// Power-off waited on a unit stop job: a scope whose cgroup emptied without
/// systemd being told (the `cgroup.events` inotify edge) sits out its whole
/// stop timeout.
const STOP_JOB_MARKER: &str = "A stop job is running for";

/// systemd's boot status line for a job still starting.
const START_JOB_MARKER: &str = "A start job is running for";

/// Minutes a single start job may run before the boot counts as hung on it.
const STUCK_START_JOB_MIN: u32 = 2;

/// The status line of a start job that has been running for
/// [`STUCK_START_JOB_MIN`] or more: "A start job is running for <unit>
/// (2min 3s / no limit)". Nothing in this boot legitimately takes that long,
/// so the boot is hung on that job (a plymouth client waiting on the socket of
/// a daemon that had exited was one), and naming it beats a bare login
/// timeout minutes later.
fn stuck_start_job(serial: &str) -> Option<&str> {
    serial.match_indices(START_JOB_MARKER).find_map(|(at, _)| {
        let rest = &serial[at..];
        let line = rest.split(['\r', '\n']).next().unwrap_or(rest);
        let timer = &line[line.rfind('(')? + 1..];
        let elapsed = timer.split(" / ").next()?;
        let minutes: u32 = elapsed.split_once("min")?.0.parse().ok()?;
        (minutes >= STUCK_START_JOB_MIN).then_some(line)
    })
}

/// `NARF-PID1-MAPS <n>`: the lines of `/proc/1/maps` the login shell (an
/// unrelated process) read, or `None` when the report has no such line.
fn pid1_maps_lines(report: &str) -> Option<usize> {
    report.lines().find_map(|line| {
        line.trim()
            .strip_prefix("NARF-PID1-MAPS ")
            .and_then(|n| n.trim().parse().ok())
    })
}

/// `NARF-JOURNAL-U <n>`: the lines `journalctl -u systemd-journald` printed,
/// or `None` when the report has no such line (a mistyped command).
fn journal_unit_lines(report: &str) -> Option<usize> {
    report.lines().find_map(|line| {
        line.trim()
            .strip_prefix("NARF-JOURNAL-U ")
            .and_then(|n| n.trim().parse().ok())
    })
}

/// How many trailing bytes of `bytes` are the start of a UTF-8 sequence the
/// next read will finish. Decoding them now would turn one `…` into
/// replacement characters and break substring matches.
fn incomplete_utf8_tail(bytes: &[u8]) -> usize {
    match std::str::from_utf8(bytes) {
        Err(e) if e.error_len().is_none() => bytes.len() - e.valid_up_to(),
        _ => 0,
    }
}

/// The distinct units systemd showed as slow start jobs, with the last
/// elapsed time it printed for each: `(description, "1min 30s / no limit")`.
fn slow_start_jobs(serial: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    // systemd redraws the status line with CR, so split before stripping
    // escapes (which drops CRs).
    for segment in serial.split(['\n', '\r']) {
        let line = strip_escapes(segment);
        for rest in line.split(START_JOB_MARKER).skip(1) {
            let rest = rest.split_once(')').map_or(rest, |(job, _)| job);
            let (unit, time) = rest.rsplit_once(" (").unwrap_or((rest, ""));
            let unit = unit.trim().to_string();
            match out.iter_mut().find(|(u, _)| *u == unit) {
                Some(entry) => entry.1 = time.to_string(),
                None => out.push((unit, time.to_string())),
            }
        }
    }
    out
}

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
    super::add_passthrough_firmware(&mut build);
    let root = super::workspace_root()?;
    let out_dir = super::cargo_build(&build, &root)?;
    let kernel = out_dir.join(&build.package);
    // Firmware the display needs before the root mounts (a passed-through
    // GPU) arrives as the initramfs.
    let firmware = super::initramfs_firmware_entries(&build, &root)?;
    let initrd = if firmware.is_empty() {
        None
    } else {
        let entries: Vec<(&str, &[u8])> = firmware
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect();
        let path = out_dir.join("initramfs-cachyos-firmware.cpio");
        std::fs::write(&path, super::encode_cpio_newc(&entries))
            .with_context(|| format!("write {}", path.display()))?;
        println!(
            "xtask cachyos-root-smoke: {} firmware blob(s) in the initramfs",
            firmware.len()
        );
        Some(path)
    };
    if let Ok(mut slot) = super::TEST_INITRD.lock() {
        *slot = initrd;
    }
    let mut log = match &args.serial_log {
        Some(path) => Some(
            std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?,
        ),
        None => None,
    };
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
        // Bytes of a UTF-8 sequence the last read split (systemd's `…`).
        let mut carry: Vec<u8> = Vec::new();
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = std::io::stdout().write_all(&buf[..n]);
                    let _ = std::io::stdout().flush();
                    if let Some(log) = log.as_mut() {
                        let _ = log.write_all(&buf[..n]);
                    }
                    carry.extend_from_slice(&buf[..n]);
                    let keep = incomplete_utf8_tail(&carry);
                    let tail = carry.split_off(carry.len() - keep);
                    if tx.send(std::mem::replace(&mut carry, tail)).is_err() {
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
                if let Some(job) = stuck_start_job(&serial[from..]) {
                    return Err(anyhow::anyhow!(
                        "boot hung on a start job: {}",
                        strip_escapes(job)
                    ));
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
    if args.interactive {
        return interactive(child, stdin, rx, reader);
    }
    // A --disk image has its own hostname.
    let prompt = if args.disk.is_some() {
        " login:".to_string()
    } else {
        format!("{IMAGE_HOSTNAME} login:")
    };
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
        if args.no_login || args.disk.is_some() {
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
        if let Some(line) = strip_escapes(&serial)
            .lines()
            .find(|l| l.contains(DEVICE_TIMEOUT_MARKER))
        {
            bail!("a device never became ready: {}", line.trim());
        }
        if serial.contains(NO_MOUNT_MARKER) {
            bail!("systemd lost a mount: \"{NO_MOUNT_MARKER}\"");
        }
        // journald attributes each message to its unit; `journalctl -u`
        // finding nothing means the journal's field index is unreadable.
        if journal_unit_lines(&strip_escapes(&serial[mark..])) == Some(0) {
            bail!("journalctl -u systemd-journald returned no entries");
        }
        // systemd always has a text, heap and stack mapping. An empty
        // /proc/1/maps means another process could not find PID 1's mm.
        if pid1_maps_lines(&strip_escapes(&serial[mark..])) == Some(0) {
            bail!("/proc/1/maps read back empty from the login shell");
        }
        if args.no_poweroff {
            return Ok(());
        }
        // A clean shutdown is part of the contract: systemd-shutdown remounts
        // / read-only, syncs, and NARF powers off (NVMe CC.SHN on the way).
        let mark = serial.len();
        type_slowly(&mut stdin, "systemctl poweroff")?;
        let deadline = Instant::now() + Duration::from_secs(240);
        let mut exited = false;
        while Instant::now() < deadline {
            if let Some(hit) = PANIC_MARKERS.iter().find(|m| serial[mark..].contains(*m)) {
                bail!("kernel panic during shutdown ({hit:?})");
            }
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(bytes) => serial.push_str(&String::from_utf8_lossy(&bytes)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    exited = true;
                    break;
                }
            }
        }
        if !exited {
            bail!("the guest did not power off within 240 s");
        }
        let shutdown = strip_escapes(&serial[mark..]);
        // Errors: anything that could leave the root inconsistent. systemd-
        // shutdown's final read-only remount of / must succeed and both NVMe
        // controllers must complete the CC.SHN normal shutdown.
        let errors: Vec<&str> = shutdown
            .lines()
            .filter(|l| l.contains("Failed to remount") || l.contains("Failed to finalize"))
            .collect();
        // Warnings: a unit that could not unmount early (systemd-shutdown
        // retries every mount after killing the remaining processes).
        let warnings: Vec<&str> = shutdown
            .lines()
            .filter(|l| l.contains("FAILED") || l.contains("Failed unmounting"))
            .collect();
        println!("\nxtask cachyos-root-smoke: powered off");
        for line in &warnings {
            println!("  shutdown warning: {}", line.trim());
        }
        for line in &errors {
            println!("  shutdown ERROR: {}", line.trim());
        }
        let shn = shutdown
            .lines()
            .filter(|l| l.contains("CC.SHN normal shutdown: Complete"))
            .count();
        if !errors.is_empty() {
            bail!("unclean shutdown ({} error line(s))", errors.len());
        }
        if let Some(line) = shutdown.lines().find(|l| l.contains(STOP_JOB_MARKER)) {
            bail!("power-off waited on a stop job: {}", line.trim());
        }
        if shn < 2 {
            bail!("only {shn} of 2 NVMe controllers completed CC.SHN");
        }
        if !shutdown.contains("Remounting '/' read-only")
            && !shutdown.contains("All filesystems unmounted")
        {
            bail!("systemd-shutdown never finalized the filesystems");
        }
        Ok(())
    })();
    let _ = child.kill();
    let _ = child.wait();
    drop(rx);
    let _ = reader.join();
    report_start_jobs(&serial);
    result.map_err(|e| anyhow::anyhow!("xtask cachyos-root-smoke: {e}"))
}

/// Print the units systemd reported as slow start jobs: a unit that hangs
/// on NARF (and not on Linux) shows up here first.
fn report_start_jobs(serial: &str) {
    let jobs = slow_start_jobs(serial);
    if jobs.is_empty() {
        return;
    }
    println!("\nxtask cachyos-root-smoke: slow start jobs systemd reported:");
    for (unit, time) in jobs {
        println!("  {unit}  ({time})");
    }
}

/// `--interactive`: this terminal's input goes to the guest's serial
/// console until QEMU exits — the guest powered off, or Ctrl-C, which the
/// terminal delivers to QEMU too.
fn interactive(
    mut child: std::process::Child,
    mut stdin: std::process::ChildStdin,
    rx: mpsc::Receiver<Vec<u8>>,
    reader: std::thread::JoinHandle<()>,
) -> Result<()> {
    println!(
        "\nxtask cachyos-root-smoke: serial console attached; `systemctl poweroff` in the \
         guest (or Ctrl-C) ends the run"
    );
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        let mut input = std::io::stdin();
        while let Ok(n) = input.read(&mut buf) {
            if n == 0 {
                break;
            }
            // The terminal is line-buffered and sends LF; a serial getty
            // expects the CR a real terminal's Enter sends.
            let bytes: Vec<u8> = buf[..n]
                .iter()
                .map(|&b| if b == b'\n' { b'\r' } else { b })
                .collect();
            if stdin.write_all(&bytes).and_then(|_| stdin.flush()).is_err() {
                break;
            }
        }
    });
    let mut serial = String::new();
    while let Ok(bytes) = rx.recv() {
        serial.push_str(&String::from_utf8_lossy(&bytes));
    }
    let status = child.wait()?;
    let _ = reader.join();
    report_start_jobs(&serial);
    println!("\nxtask cachyos-root-smoke: QEMU exited ({status})");
    Ok(())
}

/// The bare-metal command line, for the smoke image's UUID.
pub fn smoke_cmdline(uuid: &str, rw: bool, extra: &[String]) -> String {
    root_cmdline(uuid, Some("subvol=/@"), rw, extra)
}

/// The bare-metal command line for any root: `rootflags` only when the root
/// needs them (a btrfs subvolume).
fn root_cmdline(uuid: &str, rootflags: Option<&str>, rw: bool, extra: &[String]) -> String {
    let mut tokens = vec![format!("root=UUID={uuid}")];
    if let Some(flags) = rootflags {
        tokens.push(format!("rootflags={flags}"));
    }
    tokens.extend([
        "systemd_pid1".to_string(),
        format!("narf.disks={}", if rw { "root-rw" } else { "root-ro" }),
    ]);
    // Same as the grub-image bundle: no zram device, so no zram swap units.
    if !extra.iter().any(|a| a.starts_with("systemd.zram=")) {
        tokens.push(super::NO_ZRAM_ARG.to_string());
    }
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

/// `qcow2` when `path` starts with the qcow2 magic, else `raw`.
fn image_format(path: &Path) -> Result<&'static str> {
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .with_context(|| format!("read {}", path.display()))?;
    Ok(if &magic == b"QFI\xfb" { "qcow2" } else { "raw" })
}

/// The standard text form of a 16-byte UUID stored in byte order (how both
/// ext4 and btrfs store theirs).
fn uuid_text(b: &[u8]) -> String {
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// `(uuid, "btrfs" | "ext4")` of the filesystem at byte `offset`, if any.
fn probe_fs(file: &mut std::fs::File, offset: u64) -> Option<(String, &'static str)> {
    use std::io::{Seek, SeekFrom};
    let mut sb = [0u8; 0x100];
    // btrfs: primary superblock at 64 KiB, magic at +0x40, fsid at +0x20.
    file.seek(SeekFrom::Start(offset + 0x1_0000)).ok()?;
    if file.read_exact(&mut sb).is_ok() && &sb[0x40..0x48] == b"_BHRfS_M" {
        return Some((uuid_text(&sb[0x20..0x30]), "btrfs"));
    }
    // ext2/3/4: superblock at 1 KiB, magic 0xEF53 at +0x38, uuid at +0x68.
    file.seek(SeekFrom::Start(offset + 1024)).ok()?;
    if file.read_exact(&mut sb).is_ok() && sb[0x38..0x3a] == [0x53, 0xef] {
        return Some((uuid_text(&sb[0x68..0x78]), "ext4"));
    }
    None
}

/// The first btrfs or ext4 partition in a raw GPT image (512-byte sectors).
fn find_root_partition(image: &Path) -> Result<(String, &'static str)> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(image).with_context(|| format!("open {}", image.display()))?;
    let mut hdr = [0u8; 92];
    f.seek(SeekFrom::Start(512))?;
    f.read_exact(&mut hdr)?;
    if &hdr[..8] != b"EFI PART" {
        bail!(
            "{} has no GPT (512-byte sectors); pass --root-uuid",
            image.display()
        );
    }
    let le64 = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
    let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let entries_lba = le64(&hdr[72..80]);
    let count = le32(&hdr[80..84]).min(256) as usize;
    let size = le32(&hdr[84..88]) as usize;
    if size < 128 {
        bail!("{}: bad GPT entry size {size}", image.display());
    }
    let mut table = vec![0u8; count * size];
    f.seek(SeekFrom::Start(entries_lba * 512))?;
    f.read_exact(&mut table)?;
    for entry in table.chunks(size) {
        let first = le64(&entry[32..40]);
        if entry[..16].iter().all(|&b| b == 0) || first == 0 {
            continue;
        }
        if let Some(found) = probe_fs(&mut f, first * 512) {
            return Ok(found);
        }
    }
    bail!(
        "{}: no btrfs or ext4 partition found; pass --root-uuid",
        image.display()
    )
}

/// `(length, mtime)`: cheap evidence a 40 GiB base image was not written.
fn file_stamp(path: &Path) -> Result<(u64, std::time::SystemTime)> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok((meta.len(), meta.modified()?))
}

/// Processes other than this one holding `path` open (`fuser`, from /proc).
fn image_users(path: &Path) -> Vec<String> {
    let me = std::process::id().to_string();
    let mut out = Vec::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return out;
    };
    for p in procs.flatten() {
        let pid = p.file_name().to_string_lossy().into_owned();
        if pid == me || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
            continue;
        };
        if fds
            .flatten()
            .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|t| t == path))
        {
            let comm = std::fs::read_to_string(p.path().join("comm")).unwrap_or_default();
            out.push(format!("{pid} ({})", comm.trim()));
        }
    }
    out
}

/// Did the guest write anything into the overlay? `qemu-img map` lists the
/// overlay's own data as `depth: 0` extents with `data: true`.
fn overlay_written_bytes(overlay: &Path) -> Result<u64> {
    let out = Command::new("qemu-img")
        .args(["map", "--output=json", "-f", "qcow2"])
        .arg(overlay)
        .output()
        .context("run qemu-img map")?;
    if !out.status.success() {
        bail!(
            "qemu-img map {} failed: {}",
            overlay.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    overlay_data_bytes(&String::from_utf8_lossy(&out.stdout))
}

fn overlay_data_bytes(map_json: &str) -> Result<u64> {
    let extents: Vec<serde_json::Value> =
        serde_json::from_str(map_json).context("parse qemu-img map output")?;
    Ok(extents
        .iter()
        .filter(|e| e["depth"] == 0 && e["data"] == true)
        .filter_map(|e| e["length"].as_u64())
        .sum())
}

/// Create a fresh overlay for `--disk` and point the second NVMe at it.
fn prepare_disk(root: &Path, base: &Path) -> Result<DiskBoot> {
    let base = base
        .canonicalize()
        .with_context(|| format!("--disk {}", base.display()))?;
    let users = image_users(&base);
    if !users.is_empty() {
        bail!(
            "{} is open in another process ({}); never boot an image something else is using",
            base.display(),
            users.join(", ")
        );
    }
    let format = image_format(&base)?;
    let overlay = root.join(DISK_OVERLAY);
    let _ = std::fs::remove_file(&overlay);
    let status = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", format, "-b"])
        .arg(&base)
        .arg(&overlay)
        .status()
        .context("run qemu-img create")?;
    if !status.success() {
        bail!("qemu-img create {} failed ({status})", overlay.display());
    }
    std::env::set_var("NARF_NVME2_FORMAT", "qcow2");
    Ok(DiskBoot {
        base_stamp: file_stamp(&base)?,
        base,
        overlay,
    })
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
    if let Some(base) = &args.disk {
        return run_disk(args, &root, base);
    }
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
    set_boot_env(&decoy, &disk, &cmdline);

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

/// The environment `qemu_boot_args` reads: the decoy on the first NVMe, the
/// root on the second, the root command line, and the guest's RAM.
fn set_boot_env(decoy: &Path, disk: &Path, cmdline: &str) {
    std::env::set_var("NARF_NVME_IMG", decoy);
    std::env::set_var("NARF_NVME2_IMG", disk);
    let existing = std::env::var("XTASK_QEMU_APPEND").unwrap_or_default();
    std::env::set_var(
        "XTASK_QEMU_APPEND",
        [existing.as_str(), cmdline]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" "),
    );
    if std::env::var_os("NARF_QEMU_MEM_MB").is_none() {
        std::env::set_var("NARF_QEMU_MEM_MB", "4096");
    }
}

/// `--disk`: boot an installed image through a fresh overlay.
fn run_disk(args: &Args, root: &Path, base: &Path) -> Result<()> {
    let disk = prepare_disk(root, base)?;
    let (uuid, rootflags) = match &args.root_uuid {
        Some(uuid) => (uuid.clone(), None),
        None => {
            let (uuid, fs) = find_root_partition(&disk.base)?;
            println!(
                "xtask cachyos-root-smoke: {} root {fs} UUID {uuid}",
                disk.base.display()
            );
            // CachyOS's btrfs layout puts / in `@`.
            (uuid, (fs == "btrfs").then_some("subvol=/@"))
        }
    };
    let decoy = root.join(DECOY_IMAGE);
    write_decoy(&decoy)?;
    let decoy_before = sha256_file(&decoy)?;
    let cmdline = root_cmdline(&uuid, rootflags, args.rw, &args.cmdline);
    println!(
        "xtask cachyos-root-smoke: disk {} (overlay {}) cmdline `{cmdline}`",
        disk.base.display(),
        disk.overlay.display()
    );
    set_boot_env(&decoy, &disk.overlay, &cmdline);

    let result = boot_and_login(args);

    let mut verdict = Ok(());
    if file_stamp(&disk.base)? != disk.base_stamp {
        verdict = Err(anyhow::anyhow!(
            "the base image {} CHANGED during the run",
            disk.base.display()
        ));
    }
    if sha256_file(&decoy)? != decoy_before {
        verdict = Err(anyhow::anyhow!("the boot MODIFIED the decoy disk"));
    }
    let written = overlay_written_bytes(&disk.overlay)?;
    if args.rw {
        println!("xtask cachyos-root-smoke: root-rw wrote {written} bytes to the overlay");
    } else if written != 0 {
        verdict = Err(anyhow::anyhow!(
            "narf.disks=root-ro WROTE {written} bytes to the overlay {}",
            disk.overlay.display()
        ));
    } else {
        println!("xtask cachyos-root-smoke: root-ro boot wrote nothing (overlay holds no data)");
    }
    if args.keep_overlay || verdict.is_err() {
        println!(
            "xtask cachyos-root-smoke: overlay kept at {}",
            disk.overlay.display()
        );
    } else {
        let _ = std::fs::remove_file(&disk.overlay);
    }
    verdict.map_err(|e| anyhow::anyhow!("xtask cachyos-root-smoke: {e}"))?;
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
    fn journal_unit_count_is_read_from_the_report() {
        assert_eq!(
            journal_unit_lines("  NARF-STATE running\n  NARF-JOURNAL-U 12\n"),
            Some(12)
        );
        assert_eq!(journal_unit_lines("NARF-JOURNAL-U 0"), Some(0));
        assert_eq!(pid1_maps_lines("  NARF-PID1-MAPS 57\n"), Some(57));
        assert_eq!(pid1_maps_lines("NARF-PID1-MAPS 0"), Some(0));
        assert_eq!(pid1_maps_lines("NARF-STATE running\n"), None);
        // A mistyped command leaves no verdict rather than a false zero.
        assert_eq!(journal_unit_lines("NARF-STATE running\n"), None);
        assert_eq!(journal_unit_lines("NARF-JOURNAL-U \n"), None);
    }

    #[test]
    fn a_start_job_past_two_minutes_is_a_hang() {
        let line = "\u{1b}[K[  \u{1b}[0;31m*\u{1b}[0m] A start job is running for Tell Ply\u{2026}e Out Runtime Data";
        let short = format!("{line} (59s / no limit)\r{line} (1min 59s / no limit)\r");
        assert_eq!(stuck_start_job(&short), None);
        let long = format!("{short}{line} (2min 1s / no limit)\r\n");
        assert_eq!(
            stuck_start_job(&long).map(|l| l.ends_with("(2min 1s / no limit)")),
            Some(true)
        );
        // The limit after the slash is not the elapsed time.
        assert_eq!(
            stuck_start_job("A start job is running for dev-x.device (5s / 3min 30s)"),
            None
        );
    }

    #[test]
    fn a_split_ellipsis_waits_for_its_last_byte() {
        let ellipsis = "…".as_bytes();
        assert_eq!(incomplete_utf8_tail(b"plain"), 0);
        assert_eq!(incomplete_utf8_tail(&[b'P', ellipsis[0], ellipsis[1]]), 2);
        assert_eq!(incomplete_utf8_tail(ellipsis), 0);
        // Invalid bytes are not held back; they are not going to complete.
        assert_eq!(incomplete_utf8_tail(&[0xff]), 0);
    }

    #[test]
    fn an_ext4_root_gets_no_rootflags() {
        assert_eq!(
            root_cmdline("u", None, false, &[]),
            "root=UUID=u systemd_pid1 narf.disks=root-ro systemd.zram=0"
        );
    }

    #[test]
    fn slow_start_jobs_keep_the_last_time_per_unit() {
        let serial = "[  *** ] A start job is running for Show Plymouth Boot Screen (5s / no limit)\r\
                      [ ***  ] A start job is running for Show Plymouth Boot Screen (1min 3s / no limit)\n\
                      [  OK  ] Started Something.\n\
                      [***   ] A start job is running for /dev/disk/by-uuid/x (12s / 1min 30s)\n";
        assert_eq!(
            slow_start_jobs(serial),
            vec![
                (
                    "Show Plymouth Boot Screen".into(),
                    "1min 3s / no limit".into()
                ),
                ("/dev/disk/by-uuid/x".into(), "12s / 1min 30s".into()),
            ]
        );
    }

    #[test]
    fn uuids_print_in_stored_byte_order() {
        let b = [
            0xaf, 0x80, 0xb0, 0x3f, 0xd9, 0xd6, 0x42, 0xf9, 0xb3, 0x37, 0x0f, 0x38, 0x25, 0xc1,
            0x97, 0x0a,
        ];
        assert_eq!(uuid_text(&b), "af80b03f-d9d6-42f9-b337-0f3825c1970a");
    }

    #[test]
    fn only_the_overlays_own_data_counts_as_written() {
        let map = r#"[
            {"start": 0, "length": 65536, "depth": 1, "present": true, "zero": false, "data": true, "compressed": false},
            {"start": 65536, "length": 4096, "depth": 0, "present": true, "zero": false, "data": true, "compressed": false},
            {"start": 69632, "length": 8192, "depth": 0, "present": true, "zero": true, "data": false, "compressed": false}
        ]"#;
        assert_eq!(overlay_data_bytes(map).unwrap(), 4096);
        assert_eq!(overlay_data_bytes("[]").unwrap(), 0);
    }

    #[test]
    fn cmdline_is_the_bare_metal_shape() {
        assert_eq!(
            smoke_cmdline("u", false, &[]),
            "root=UUID=u rootflags=subvol=/@ systemd_pid1 narf.disks=root-ro systemd.zram=0"
        );
        assert_eq!(
            smoke_cmdline("u", true, &["quiet".into()]),
            "root=UUID=u rootflags=subvol=/@ systemd_pid1 narf.disks=root-rw systemd.zram=0 quiet"
        );
    }
}
