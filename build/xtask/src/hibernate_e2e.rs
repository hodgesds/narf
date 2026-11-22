//! `cargo xtask hibernate-e2e`: hibernate NARF on one boot and resume it on
//! the next (S4 lane 9).
//!
//! 1. The host builds a fresh GPT disk with one ext4 partition (4 KiB
//!    blocks). The boot mounts it at `/mnt` (`mnt-mount-ext2`, the default
//!    `narf.disks=all`); the image file is `/mnt/hibernate.img`.
//! 2. Boot 1 runs the guest half
//!    (`power/src/hibernate/e2e.rs`, `narf.hibernate_e2e=hibernate`). It
//!    fills 16 MiB with a token-seeded pattern, prints the token and the
//!    pattern's digest, and hibernates into `/hibernate.img`. The guest
//!    prints the resume parameters, then powers down through `\_S4`
//!    (QEMU's ICH9 `disable_s4=0`).
//! 3. Boot 2, on the same image, passes those parameters back as
//!    `narf.resume=` and `narf.resume_offset=`. The restored image must
//!    report the same token and digest.
//!
//! The image is sealed under `narf.hibernate_policy=off` unless
//! `--tpm-state` points at a running swtpm socket (the host has to
//! provide one; NARF does not start it). x86_64 only, one CPU: lane 4 brings
//! secondary CPUs.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const MARKER: &str = "HIBERNATE-E2E:";
const IMAGE_UUID: &str = "41b1e2e0-5000-4a11-9e57-0000000005e5";
const IMAGE_MIB: u64 = 4096;
/// The root partition starts at 1 MiB.
const PART_START_LBA: u64 = 2048;
const GUEST_MIB: u64 = 2048;
/// Must match `power::hibernate::e2e::EXIT_*`, as QEMU reports them.
const EXIT_RESUMED: i32 = (0x10 << 1) | 1;

/// Options for `cargo xtask hibernate-e2e`.
#[derive(clap::Args, Clone)]
pub struct Args {
    #[command(flatten)]
    pub build: super::BuildArgs,

    /// Seconds each boot may take.
    #[arg(long, default_value_t = 600)]
    pub timeout_secs: u64,

    /// A swtpm control socket to attach as a TPM 2.0 (tpm-crb); without
    /// it the image is sealed under the OFF policy.
    #[arg(long, value_name = "SOCKET")]
    pub tpm_socket: Option<PathBuf>,

    /// Boot this kernel instead of building one.
    #[arg(long, value_name = "PATH")]
    pub kernel: Option<PathBuf>,
}

fn qemu_args(
    args: &Args,
    kernel: &Path,
    image: &Path,
    append: &str,
    kvm: bool,
    qemu_log: &Path,
    no_reboot: bool,
) -> Vec<String> {
    let mut q: Vec<String> = vec![
        "-machine".into(),
        "q35".into(),
        "-global".into(),
        "ICH9-LPC.disable_s4=0".into(),
        "-cpu".into(),
        "max,phys-bits=40".into(),
        "-smp".into(),
        "1".into(),
        "-m".into(),
        format!("{GUEST_MIB}M"),
    ];
    if kvm {
        q.extend(["-accel".into(), "kvm".into()]);
    }
    q.extend([
        "-nodefaults".into(),
        "-serial".into(),
        "stdio".into(),
        "-display".into(),
        "none".into(),
        // A triple fault resets the guest. Boot 1 exits on it (-no-reboot).
        // Boot 2 really resets, so this log holds the faulting state: its
        // image header is consumed, and the cold boot that follows exits
        // through NO-RESUME.
        "-d".into(),
        "cpu_reset,guest_errors".into(),
        "-D".into(),
        qemu_log.display().to_string(),
    ]);
    if no_reboot {
        q.push("-no-reboot".into());
    }
    q.extend([
        "-device".into(),
        "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
        "-drive".into(),
        format!("if=none,id=nvm0,format=raw,file={}", image.display()),
        "-device".into(),
        "nvme,drive=nvm0,serial=narfhib,logical_block_size=512,physical_block_size=4096".into(),
    ]);
    if let Some(socket) = &args.tpm_socket {
        q.extend([
            "-chardev".into(),
            format!("socket,id=chrtpm,path={}", socket.display()),
            "-tpmdev".into(),
            "emulator,id=tpm0,chardev=chrtpm".into(),
            "-device".into(),
            "tpm-crb,tpmdev=tpm0".into(),
        ]);
    }
    q.extend([
        "-append".into(),
        append.into(),
        "-kernel".into(),
        kernel.display().to_string(),
    ]);
    q
}

/// One boot: its serial lines and QEMU's exit status.
struct Boot {
    lines: Vec<String>,
    status: Option<i32>,
}

fn boot(
    args: &Args,
    kernel: &Path,
    image: &Path,
    append: &str,
    log: &Path,
    no_reboot: bool,
) -> Result<Boot> {
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    let mut child = Command::new(args.build.arch.qemu_bin())
        .args(qemu_args(
            args,
            kernel,
            image,
            append,
            kvm,
            &log.with_extension("qemu.log"),
            no_reboot,
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning QEMU")?;
    let stdout = child.stdout.take().context("QEMU stdout")?;
    let deadline = Instant::now() + Duration::from_secs(args.timeout_secs);
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut lines = Vec::new();
    let mut out = std::fs::File::create(log)?;
    let status = loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                use std::io::Write as _;
                let _ = writeln!(out, "{line}");
                if line.contains(MARKER) || line.contains("hibernate:") {
                    println!("  {line}");
                }
                lines.push(line);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break child.wait()?.code();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
    };
    let _ = reader.join();
    Ok(Boot { lines, status })
}

/// The value after `key=` on the first line holding `prefix`.
fn field(lines: &[String], prefix: &str, key: &str) -> Option<String> {
    let line = lines.iter().find(|l| l.contains(prefix))?;
    let at = line.find(&format!("{key}="))? + key.len() + 1;
    Some(line[at..].split_whitespace().next()?.to_string())
}

pub fn run(args: &Args) -> Result<()> {
    if !matches!(args.build.arch, super::Arch::X86_64) {
        bail!("hibernate-e2e: x86_64 only (no aarch64 restore yet)");
    }
    for tool in ["mkfs.ext4", "sfdisk", args.build.arch.qemu_bin()] {
        if super::which(tool).is_none() {
            bail!("hibernate-e2e: `{tool}` not on $PATH");
        }
    }
    let root = super::workspace_root()?;
    let kernel = match &args.kernel {
        Some(k) => k.clone(),
        None => super::cargo_build(&args.build, &root)?.join(&args.build.package),
    };
    if !kernel.exists() {
        bail!("hibernate-e2e: no kernel at {}", kernel.display());
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let run_dir = root
        .join("target/hibernate-e2e")
        .join(format!("run-{stamp}"));
    std::fs::create_dir_all(&run_dir)?;
    let image = run_dir.join("root.img");
    let ok = |cmd: &mut Command, what: &str| -> Result<()> {
        let status = cmd.status().with_context(|| what.to_string())?;
        if !status.success() {
            bail!("hibernate-e2e: {what} failed: {status}");
        }
        Ok(())
    };
    let sectors = IMAGE_MIB * 2048;
    std::fs::File::create(&image)?.set_len((PART_START_LBA + sectors + 2048) * 512)?;
    let table = format!(
        "label: gpt\nstart={PART_START_LBA}, size={sectors}, \
         type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=\"root\"\n"
    );
    let mut sfdisk = Command::new("sfdisk")
        .arg("-q")
        .arg(&image)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("spawn sfdisk")?;
    {
        use std::io::Write as _;
        sfdisk
            .stdin
            .as_mut()
            .context("sfdisk stdin")?
            .write_all(table.as_bytes())?;
    }
    if !sfdisk.wait()?.success() {
        bail!("hibernate-e2e: sfdisk failed");
    }
    ok(
        Command::new("mkfs.ext4")
            .args(["-F", "-q", "-b", "4096", "-U", IMAGE_UUID, "-L", "narfhib"])
            .arg(format!("-Eoffset={}", PART_START_LBA * 512))
            .arg(&image)
            .arg(format!("{IMAGE_MIB}M")),
        "mkfs.ext4",
    )?;
    let policy = if args.tpm_socket.is_some() {
        ""
    } else {
        " narf.hibernate_policy=off"
    };
    let base = format!("narf.hibernate_file=/mnt/hibernate.img{policy}");

    println!(
        "hibernate-e2e: boot 1 (hibernate), logs in {}",
        run_dir.display()
    );
    let first = boot(
        args,
        &kernel,
        &image,
        &format!("{base} narf.hibernate_e2e=hibernate"),
        &run_dir.join("boot1.serial.log"),
        true,
    )?;
    let (Some(token), Some(digest)) = (
        field(&first.lines, &format!("{MARKER} hibernating"), "token"),
        field(&first.lines, &format!("{MARKER} hibernating"), "digest"),
    ) else {
        bail!(
            "hibernate-e2e: boot 1 never started hibernating (status {:?})",
            first.status
        );
    };
    if let Some(line) = first
        .lines
        .iter()
        .find(|l| l.contains(&format!("{MARKER} FAIL")))
    {
        bail!("hibernate-e2e: boot 1: {line}");
    }
    let (Some(device), Some(offset)) = (
        field(&first.lines, "resume with", "narf.resume"),
        field(&first.lines, "resume with", "narf.resume_offset"),
    ) else {
        bail!(
            "hibernate-e2e: boot 1 wrote no image (status {:?})",
            first.status
        );
    };

    println!("hibernate-e2e: boot 2 (resume from {device} block {offset})");
    let second = boot(
        args,
        &kernel,
        &image,
        &format!(
            "{base} narf.resume={device} narf.resume_offset={offset} narf.hibernate_e2e=resume"
        ),
        &run_dir.join("boot2.serial.log"),
        false,
    )?;
    let resumed = format!("{MARKER} resumed");
    let (Some(token2), Some(digest2)) = (
        field(&second.lines, &resumed, "token"),
        field(&second.lines, &resumed, "digest"),
    ) else {
        let why = second
            .lines
            .iter()
            .find(|l| l.contains("hibernate: no resume"))
            .cloned()
            .unwrap_or_else(|| format!("no resumed line (status {:?})", second.status));
        bail!("hibernate-e2e: boot 2 did not resume: {why}");
    };
    if token2 != token || digest2 != digest || second.status != Some(EXIT_RESUMED) {
        bail!(
            "hibernate-e2e: resumed state differs: token {token} -> {token2}, \
             digest {digest} -> {digest2}, status {:?}",
            second.status
        );
    }
    println!("hibernate-e2e: PASS (token {token}, 16 MiB digest matches)");
    Ok(())
}
