//! `cargo xtask usb-image` — a UEFI USB-stick image with the persistent
//! boot log enabled.
//!
//! The image is a plain file (MBR, one FAT32 ESP partition) built without
//! root privileges from the `xtask image` staging tree:
//!
//! ```text
//! /EFI/BOOT/BOOTX64.EFI        Limine
//! /boot/limine/limine.conf     cmdline: narf.bootlog=<token> log_buf_len=...
//! /boot/narf-frame             kernel
//! /boot/initramfs.cpio         init/shell + --initramfs-firmware blobs
//! /NARFLOG.ID                  <token>
//! ```
//!
//! The kernel writes `/narf-boot-<n>.log` only to a USB FAT volume whose
//! `/NARFLOG.ID` matches the token on its command line, i.e. this stick.
//! Write the file to a stick with `cargo xtask disk-write --iso <image>`.
//!
//! `--qemu` boots a copy of the image under OVMF as a USB mass-storage
//! device (the bare-metal path: xHCI → MSC → FAT), once ending with a shell
//! `reboot` (final flush) and once with a deliberate panic (panic flush),
//! then prints the log files read back from the copy.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::{image_cmd, ovmf_code_path, run_checked, which, workspace_root, BuildArgs};

/// Byte offset of the ESP inside the image (1 MiB alignment).
const ESP_OFFSET: u64 = 1024 * 1024;
const SECTOR: u64 = 512;

#[derive(Parser, Clone)]
pub(crate) struct UsbImageArgs {
    #[command(flatten)]
    pub build: BuildArgs,

    /// ESP (FAT32) size in MiB. Holds kernel, initramfs, Limine and the
    /// boot logs (at most 32 x 4 MiB).
    #[arg(long, default_value_t = 512)]
    pub esp_size_mib: u64,

    /// Output image. Default: target/narf-x86_64-usb.img.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Leave the persistent boot log off (no token, no marker file).
    #[arg(long)]
    pub no_bootlog: bool,

    /// Marker token (8..=64 of [A-Za-z0-9_-]). Default: random per image.
    #[arg(long)]
    pub token: Option<String>,

    /// Extra kernel command-line arguments (repeatable).
    #[arg(long = "cmdline")]
    pub cmdline: Vec<String>,

    /// Kernel log store size (`log_buf_len=`), so nothing from a long cold
    /// boot is overwritten before the stick is armed.
    #[arg(long, default_value = "8M")]
    pub log_buf_len: String,

    /// Boot a copy of the image under QEMU/OVMF as USB storage and print the
    /// persistent logs it wrote. Never touches a real device.
    #[arg(long)]
    pub qemu: bool,
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
        .context("reading /dev/urandom for the boot-log token")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn valid_token(token: &str) -> bool {
    (8..=64).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `mtools` image spec for the ESP inside `image`.
fn esp(image: &Path) -> String {
    format!("{}@@{}", image.display(), ESP_OFFSET)
}

fn mtool(tool: &str) -> Command {
    let mut command = Command::new(tool);
    // Images built by this command carry no geometry; skip mtools' check.
    command.env("MTOOLS_SKIP_CHECK", "1");
    command
}

fn mcopy(image: &Path, src: &Path, dst: &str) -> Result<()> {
    run_checked(
        mtool("mcopy")
            .arg("-o")
            .arg("-i")
            .arg(esp(image))
            .arg(src)
            .arg(format!("::{dst}")),
        &format!("mcopy {} -> {dst}", src.display()),
    )
}

/// Kernel arguments the staged ISO config already carries (composition
/// boot arguments), so the USB image boots the same kernel configuration.
fn staged_cmdline(stage: &Path) -> String {
    std::fs::read_to_string(stage.join("boot/limine/limine.conf"))
        .ok()
        .and_then(|conf| {
            conf.lines()
                .find_map(|l| l.trim().strip_prefix("kernel_cmdline:").map(str::trim))
                .map(str::to_string)
        })
        .unwrap_or_default()
}

pub(crate) fn usb_image_cmd(args: &UsbImageArgs) -> Result<()> {
    if !matches!(args.build.arch, crate::Arch::X86_64) {
        bail!("usb-image currently builds the x86_64 UEFI stick only");
    }
    for tool in ["sfdisk", "mformat", "mmd", "mcopy"] {
        if which(tool).is_none() {
            bail!("`{tool}` not on $PATH (packages: util-linux, mtools)");
        }
    }
    let token = if args.no_bootlog {
        None
    } else {
        let token = match &args.token {
            Some(t) => t.clone(),
            None => random_token()?,
        };
        if !valid_token(&token) {
            bail!("--token must be 8..=64 characters of [A-Za-z0-9_-]");
        }
        Some(token)
    };

    image_cmd(&args.build)?;
    let root = workspace_root()?;
    let stage = root.join("target").join("iso-x86_64");
    let kernel = stage.join("boot/narf-frame");
    let initramfs = stage.join("boot/initramfs.cpio");
    let bootx64 = stage.join("EFI/BOOT/BOOTX64.EFI");
    for p in [&kernel, &initramfs, &bootx64] {
        if !p.is_file() {
            bail!("{} missing after `xtask image`", p.display());
        }
    }
    let payload: u64 = [&kernel, &initramfs, &bootx64]
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();
    let esp_bytes = args.esp_size_mib * 1024 * 1024;
    // Leave room for FAT overhead and the boot logs (32 x 4 MiB).
    if payload + 160 * 1024 * 1024 > esp_bytes {
        bail!(
            "ESP payload {} MiB does not leave room for boot logs in {} MiB; \
             raise --esp-size-mib or trim --initramfs-firmware",
            payload >> 20,
            args.esp_size_mib
        );
    }

    let out = args
        .out
        .clone()
        .unwrap_or_else(|| root.join("target").join("narf-x86_64-usb.img"));
    let _ = std::fs::remove_file(&out);
    let file =
        std::fs::File::create(&out).with_context(|| format!("creating {}", out.display()))?;
    file.set_len(ESP_OFFSET + esp_bytes)?;
    drop(file);

    // MBR with one bootable EFI System partition (type 0xEF). UEFI boots it
    // as removable media; unlike a GPT written to a file, there is no backup
    // header to land in the middle of a larger stick.
    let mut sfdisk = Command::new("sfdisk");
    sfdisk
        .arg("--quiet")
        .arg("--no-reread")
        .arg("--no-tell-kernel")
        .arg(&out)
        .stdin(Stdio::piped());
    let mut child = sfdisk.spawn().context("spawning sfdisk")?;
    writeln!(
        child.stdin.as_mut().unwrap(),
        "label: dos\nstart={}, size={}, type=ef, bootable",
        ESP_OFFSET / SECTOR,
        esp_bytes / SECTOR
    )?;
    let status = child.wait()?;
    if !status.success() {
        bail!("sfdisk failed with {status}");
    }
    run_checked(
        mtool("mformat")
            .arg("-i")
            .arg(esp(&out))
            .arg("-F")
            .arg("-T")
            .arg((esp_bytes / SECTOR).to_string())
            .arg("-H")
            .arg((ESP_OFFSET / SECTOR).to_string())
            .arg("-v")
            .arg("NARFBOOT")
            .arg("::"),
        "mformat FAT32 ESP",
    )?;
    for dir in ["EFI", "EFI/BOOT", "boot", "boot/limine"] {
        run_checked(
            mtool("mmd")
                .arg("-i")
                .arg(esp(&out))
                .arg(format!("::/{dir}")),
            &format!("mmd {dir}"),
        )?;
    }
    mcopy(&out, &bootx64, "/EFI/BOOT/BOOTX64.EFI")?;
    mcopy(&out, &kernel, "/boot/narf-frame")?;
    mcopy(&out, &initramfs, "/boot/initramfs.cpio")?;

    let mut cmdline = staged_cmdline(&stage);
    if let Some(token) = &token {
        cmdline.push_str(&format!(" narf.bootlog={token}"));
    }
    cmdline.push_str(&format!(" log_buf_len={}", args.log_buf_len));
    for extra in &args.cmdline {
        cmdline.push(' ');
        cmdline.push_str(extra);
    }
    let cmdline = cmdline.trim().to_string();
    let tmp = root.join("target").join("usb-image-staging");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    // No `quiet`: every checkpoint must reach the screen.
    let conf = format!(
        "\
timeout: 3
serial: yes
verbose: yes
default_entry: 1

/NARF
    protocol: multiboot2
    path: boot():/boot/narf-frame
    kernel_cmdline: {cmdline}
    module_path: boot():/boot/initramfs.cpio
    module_string: initramfs
"
    );
    std::fs::write(tmp.join("limine.conf"), conf)?;
    mcopy(&out, &tmp.join("limine.conf"), "/boot/limine/limine.conf")?;
    if let Some(token) = &token {
        std::fs::write(tmp.join("NARFLOG.ID"), format!("{token}\n"))?;
        mcopy(&out, &tmp.join("NARFLOG.ID"), "/NARFLOG.ID")?;
    }

    println!("xtask usb-image: wrote {}", out.display());
    println!("  kernel cmdline: {cmdline}");
    match &token {
        Some(token) => println!("  persistent boot log: on (token {token})"),
        None => println!("  persistent boot log: off"),
    }
    println!(
        "  write it (USB only, never the NVMe): \
         cargo xtask disk-write --iso {} --device /dev/sdX --fast-wipe",
        out.display()
    );

    if args.qemu {
        qemu_check(&out, &root, token.as_deref())?;
    }
    Ok(())
}

/// How a QEMU boot of the stick should end.
#[derive(Clone, Copy, Debug)]
enum Ending {
    /// Type `reboot` into the serial shell once armed.
    Reboot,
    /// Boot with `narf.bootlog.selftest=panic`.
    Panic,
}

fn qemu_check(image: &Path, root: &Path, token: Option<&str>) -> Result<()> {
    if token.is_none() {
        bail!("--qemu checks the persistent log; drop --no-bootlog");
    }
    let copy = root.join("target").join("narf-x86_64-usb-qemu.img");
    std::fs::copy(image, &copy)?;
    let mut logs = Vec::new();
    for (n, ending) in [(1, Ending::Reboot), (2, Ending::Panic)] {
        if matches!(ending, Ending::Panic) {
            add_selftest_arg(&copy, root)?;
        }
        boot_once(&copy, ending)?;
        let log = root.join("target").join(format!("narf-boot-{n}.qemu.log"));
        let _ = std::fs::remove_file(&log);
        run_checked(
            mtool("mcopy")
                .arg("-i")
                .arg(esp(&copy))
                .arg(format!("::/narf-boot-{n}.log"))
                .arg(&log),
            &format!("reading narf-boot-{n}.log back from the image"),
        )?;
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let needle = match ending {
            Ending::Reboot => "[bootlog: final flush before reboot/power-off]",
            Ending::Panic => "*** KERNEL PANIC ***",
        };
        if !text.contains("bootlog: saving the kernel log to") || !text.contains(needle) {
            bail!(
                "narf-boot-{n}.log ({} bytes) lacks the arming line or `{needle}`",
                text.len()
            );
        }
        println!(
            "xtask usb-image --qemu: narf-boot-{n}.log OK ({} bytes, {ending:?} path)",
            text.len()
        );
        logs.push(log);
    }
    let listing = mtool("mdir")
        .arg("-i")
        .arg(esp(&copy))
        .arg("::/")
        .output()?;
    println!("{}", String::from_utf8_lossy(&listing.stdout));
    for log in logs {
        println!("──── {} ────", log.display());
        print!("{}", std::fs::read_to_string(&log).unwrap_or_default());
    }
    Ok(())
}

/// Second QEMU boot: append the panic self-test to the image's cmdline.
fn add_selftest_arg(image: &Path, root: &Path) -> Result<()> {
    let tmp = root
        .join("target")
        .join("usb-image-staging")
        .join("limine.conf");
    let conf = std::fs::read_to_string(&tmp)?;
    let conf = conf.replace(
        "    kernel_cmdline: ",
        "    kernel_cmdline: narf.bootlog.selftest=panic ",
    );
    let patched = tmp.with_extension("selftest.conf");
    std::fs::write(&patched, conf)?;
    mcopy(image, &patched, "/boot/limine/limine.conf")
}

fn boot_once(image: &Path, ending: Ending) -> Result<()> {
    let ovmf = ovmf_code_path();
    if !ovmf.is_file() {
        bail!("OVMF not found at {}", ovmf.display());
    }
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            ovmf.display()
        ))
        .args(["-machine", "q35", "-cpu", "max", "-smp", "4", "-m", "4096M"])
        .args(["-serial", "stdio", "-display", "none", "-no-reboot"])
        .args(["-device", "qemu-xhci,id=xhci0"])
        .arg("-drive")
        .arg(format!(
            "if=none,id=narfstick,format=raw,file={}",
            image.display()
        ))
        .args([
            "-device",
            "usb-storage,bus=xhci0.0,drive=narfstick,removable=on,bootindex=0",
        ])
        .args(["-device", "usb-kbd,bus=xhci0.0"]);
    if let Ok(accel) = std::env::var("XTASK_QEMU_ACCEL") {
        cmd.args(["-accel", &accel]);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    println!("xtask usb-image --qemu: booting the stick image ({ending:?} ending)");
    let mut child = cmd.spawn().context("spawning qemu-system-x86_64")?;
    let stdout = child.stdout.take().unwrap();
    let mut stdin = child.stdin.take();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let timeout = std::env::var("XTASK_BOOT_SMOKE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut armed_at: Option<Instant> = None;
    let mut sent = false;
    // Getty: "NARF login:" then "Password:" (root / narf, like run-interactive),
    // then `reboot`. The prompts carry no newline, so pace by time.
    let script: [&[u8]; 3] = [b"root\n", b"narf\n", b"reboot\n"];
    let mut step = 0usize;
    let mut last_send: Option<Instant> = None;
    let mut done_at: Option<Instant> = None;
    let mut ok = false;
    loop {
        if let Some(status) = child.try_wait()? {
            ok |= matches!(ending, Ending::Reboot) && sent;
            println!("xtask usb-image --qemu: QEMU exited ({status})");
            break;
        }
        if Instant::now() > deadline {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                println!("  | {line}");
                if line.contains("bootlog: saving the kernel log to") {
                    armed_at = Some(Instant::now());
                }
                if line.contains("*** KERNEL PANIC ***") {
                    done_at = Some(Instant::now());
                }
                if line.contains("bootlog: no USB FAT volume") {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => {}
        }
        // Give the early 1 s flush cadence a few rounds, then end the boot.
        if let (Ending::Reboot, Some(at), false) = (ending, armed_at, sent) {
            let due = match last_send {
                None => at.elapsed() > Duration::from_secs(6),
                Some(t) => t.elapsed() > Duration::from_secs(3),
            };
            if due {
                if let Some(stdin) = stdin.as_mut() {
                    let _ = stdin.write_all(script[step]);
                    let _ = stdin.flush();
                }
                last_send = Some(Instant::now());
                step += 1;
                sent = step == script.len();
            }
        }
        // The panic flush is bounded at 3 s; wait it out, then stop QEMU.
        if let Some(at) = done_at {
            if at.elapsed() > Duration::from_secs(6) {
                ok = true;
                break;
            }
        }
    }
    drop(stdin.take());
    let _ = child.kill();
    let _ = child.wait();
    if !ok {
        bail!("QEMU boot of the stick image did not reach the {ending:?} ending");
    }
    Ok(())
}
