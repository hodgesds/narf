// NARF xtask orchestrator.
// Spec: build/specification/spec.md §3.
//
// `cargo xtask run   --arch=x86_64 [--release]`  — cross-build + QEMU boot
// `cargo xtask test  --arch=aarch64`             — boot + run kernel tests
// `cargo xtask image --arch=x86_64 --bootloader=limine` — bootable ISO

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(author, version, about = "NARF build orchestrator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Cross-compile the kernel.
    Build(BuildArgs),
    /// Cross-compile and boot under QEMU.
    Run(BuildArgs),
    /// Cross-compile and run kernel tests under QEMU.
    Test(BuildArgs),
    /// Produce a bootable image.
    Image(BuildArgs),
    /// Boot under QEMU with a graphical display + the user-mode
    /// testbin running.
    Demo(BuildArgs),
}

#[derive(Parser, Clone)]
struct BuildArgs {
    /// Target architecture.
    #[arg(long, value_enum, default_value_t = Arch::X86_64)]
    arch: Arch,

    /// Build with `--release`.
    #[arg(long)]
    release: bool,

    /// Crate to build.
    #[arg(long, default_value = "narf-frame")]
    package: String,

    /// Forward-list of cargo features to enable. Comma-separated.
    #[arg(long, default_value = "")]
    features: String,

    /// QEMU display mode.
    #[arg(long, default_value = "none")]
    display: String,

    /// Hardware profile to use for QEMU.
    #[arg(long, value_enum, default_value_t = HwProfile::Full)]
    hw_profile: HwProfile,
}

#[derive(Clone, Copy, ValueEnum, Default, Debug)]
pub enum HwProfile {
    /// All supported hardware enabled (Default).
    #[default]
    Full,
    /// Barebones machine (Serial only).
    Minimal,
    /// Only VirtIO devices enabled.
    VirtioOnly,
    /// Only non-VirtIO/Legacy devices enabled.
    LegacyOnly,
}

#[derive(Clone, Copy, ValueEnum)]
enum Arch {
    #[value(name = "x86_64")]
    X86_64,
    #[value(name = "aarch64")]
    Aarch64,
}

impl Arch {
    fn triple(self) -> &'static str {
        match self {
            Arch::X86_64  => "x86_64-unknown-none",
            Arch::Aarch64 => "aarch64-unknown-none",
        }
    }

    fn qemu_bin(self) -> &'static str {
        match self {
            Arch::X86_64  => "qemu-system-x86_64",
            Arch::Aarch64 => "qemu-system-aarch64",
        }
    }

    fn qemu_args(self, kernel: &Path, display: &str, profile: HwProfile) -> Vec<String> {
        let kernel = kernel.display().to_string();
        let display = display.to_string();
        match self {
            Arch::X86_64 => {
                let mut args = vec![
                    "-machine".into(), "q35,hmat=on".into(),
                    "-cpu".into(),     "max".into(),
                    "-smp".into(),     "16,sockets=2,cores=8".into(),
                    "-m".into(),       "256M".into(),
                    "-numa".into(),    "node,nodeid=0,cpus=0-7,memdev=mem0,initiator=0".into(),
                    "-numa".into(),    "node,nodeid=1,cpus=8-15,memdev=mem1,initiator=1".into(),
                    "-object".into(),  "memory-backend-ram,id=mem0,size=128M".into(),
                    "-object".into(),  "memory-backend-ram,id=mem1,size=128M".into(),
                    "-numa".into(),    "hmat-lb,initiator=0,target=0,hierarchy=memory,data-type=access-latency,latency=10".into(),
                    "-numa".into(),    "hmat-lb,initiator=0,target=1,hierarchy=memory,data-type=access-latency,latency=20".into(),
                    "-numa".into(),    "hmat-lb,initiator=1,target=0,hierarchy=memory,data-type=access-latency,latency=20".into(),
                    "-numa".into(),    "hmat-lb,initiator=1,target=1,hierarchy=memory,data-type=access-latency,latency=10".into(),
                    "-numa".into(),    "hmat-lb,initiator=0,target=0,hierarchy=memory,data-type=access-bandwidth,bandwidth=10G".into(),
                    "-numa".into(),    "hmat-lb,initiator=0,target=1,hierarchy=memory,data-type=access-bandwidth,bandwidth=5G".into(),
                    "-numa".into(),    "hmat-lb,initiator=1,target=0,hierarchy=memory,data-type=access-bandwidth,bandwidth=5G".into(),
                    "-numa".into(),    "hmat-lb,initiator=1,target=1,hierarchy=memory,data-type=access-bandwidth,bandwidth=10G".into(),
                    "-serial".into(),  "stdio".into(),
                    "-display".into(), display.clone(),
                    "-no-reboot".into(),
                    "-device".into(),  "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
                ];

                let virtio = matches!(profile, HwProfile::Full | HwProfile::VirtioOnly);
                let legacy = matches!(profile, HwProfile::Full | HwProfile::LegacyOnly);

                if legacy {
                    args.extend_from_slice(&[
                        "-drive".into(),  format!("if=none,id=nvm0,format=raw,file={}", nvme_image_path().display()),
                        "-device".into(), "nvme,drive=nvm0,serial=narf".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-netdev".into(), "user,id=n1".into(),
                        "-device".into(), "e1000,netdev=n1".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-drive".into(),  format!("if=none,id=sata0,format=raw,file={}", ahci_image_path().display()),
                        "-device".into(), "ide-hd,drive=sata0,bus=ide.0".into(),
                    ]);
                    args.extend_from_slice(&["-device".into(), "qemu-xhci,id=xhci0".into()]);
                    args.extend_from_slice(&["-vga".into(), "none".into(), "-device".into(), "bochs-display".into()]);
                    args.extend_from_slice(&[
                        "-audiodev".into(), "none,id=snd0".into(),
                        "-device".into(),   "intel-hda".into(),
                        "-device".into(),   "hda-duplex,audiodev=snd0".into(),
                    ]);
                }

                if virtio {
                    args.extend_from_slice(&[
                        "-drive".into(),  format!("if=none,id=vblk0,format=raw,file={}", virtio_blk_image_path().display()),
                        "-device".into(), "virtio-blk-pci,drive=vblk0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-netdev".into(), "user,id=n0".into(),
                        "-device".into(), "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-object".into(), "rng-random,id=rng0,filename=/dev/urandom".into(),
                        "-device".into(), "virtio-rng-pci,rng=rng0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&["-device".into(), "virtio-balloon-pci,disable-legacy=on,disable-modern=off".into()]);
                    args.extend_from_slice(&["-device".into(), "virtio-keyboard-pci,disable-legacy=on,disable-modern=off".into()]);
                    args.extend_from_slice(&["-device".into(), "virtio-gpu-pci,disable-legacy=on,disable-modern=off".into()]);
                    if !legacy {
                        args.extend_from_slice(&["-audiodev".into(), "none,id=snd0".into()]);
                    }
                    args.extend_from_slice(&["-device".into(), "virtio-sound-pci,audiodev=snd0,disable-legacy=on,disable-modern=off".into()]);
                }

                args.push("-kernel".into());
                args.push(kernel);
                args
            },
            Arch::Aarch64 => {
                let mut args = vec![
                    "-machine".into(),  "virt,gic-version=3,mte=on,highmem-ecam=off".into(),
                    "-cpu".into(),      "max".into(),
                    "-smp".into(),      "2".into(),
                    "-m".into(),        "256M".into(),
                    "-serial".into(),   "stdio".into(),
                    "-display".into(),  display.clone(),
                    "-no-reboot".into(),
                    "-semihosting".into(),
                ];

                let virtio = matches!(profile, HwProfile::Full | HwProfile::VirtioOnly);
                let legacy = matches!(profile, HwProfile::Full | HwProfile::LegacyOnly);

                if legacy {
                    args.extend_from_slice(&[
                        "-drive".into(),
                        format!("if=none,id=nvm0,format=raw,file={}",
                                nvme_image_path().display()),
                        "-device".into(),   "nvme,drive=nvm0,serial=narf".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-netdev".into(),  "user,id=n1".into(),
                        "-device".into(),  "e1000,netdev=n1".into(),
                    ]);
                }

                if virtio {
                    args.extend_from_slice(&[
                        "-drive".into(),
                        format!("if=none,id=vblk0,format=raw,file={}",
                                virtio_blk_image_path().display()),
                        "-device".into(),
                        "virtio-blk-pci,drive=vblk0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-netdev".into(),  "user,id=n0".into(),
                        "-device".into(),
                        "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-object".into(),
                        "rng-random,id=rng0,filename=/dev/urandom".into(),
                        "-device".into(),
                        "virtio-rng-pci,rng=rng0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&["-device".into(), "virtio-balloon-pci,disable-legacy=on,disable-modern=off".into()]);
                    args.extend_from_slice(&["-device".into(), "virtio-keyboard-pci,disable-legacy=on,disable-modern=off".into()]);
                    args.extend_from_slice(&["-device".into(), "virtio-gpu-pci,disable-legacy=on,disable-modern=off".into()]);
                    args.extend_from_slice(&["-audiodev".into(), "none,id=snd0".into()]);
                    args.extend_from_slice(&["-device".into(), "virtio-sound-pci,audiodev=snd0,disable-legacy=on,disable-modern=off".into()]);
                }

                args.extend_from_slice(&[
                    "-device".into(),
                    format!("loader,file={},addr={:#x},force-raw=on",
                            qemu_virt_dtb_path().display(), DTB_LOAD_ADDR),
                ]);

                args.push("-kernel".into());
                args.push(kernel);
                args
            }
        }
    }
}

const DTB_LOAD_ADDR: u64 = 0x4F00_0000;

fn qemu_virt_dtb_path() -> PathBuf {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let path = root.join("target").join("qemu-virt.dtb");
    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = Command::new("qemu-system-aarch64")
            .arg("-machine")
            .arg(format!(
                "virt,gic-version=3,mte=on,highmem-ecam=off,dumpdtb={}",
                path.display()))
            .arg("-cpu").arg("max")
            .arg("-smp").arg("2")
            .arg("-m").arg("256M")
            .arg("-display").arg("none")
            .arg("-no-reboot")
            .arg("-drive").arg(format!(
                "if=none,id=nvm0,format=raw,file={}",
                nvme_image_path().display()))
            .arg("-device").arg("nvme,drive=nvm0,serial=narf")
            .arg("-drive").arg(format!(
                "if=none,id=vblk0,format=raw,file={}",
                virtio_blk_image_path().display()))
            .arg("-device").arg("virtio-blk-pci,drive=vblk0")
            .arg("-netdev").arg("user,id=n0")
            .arg("-device").arg("virtio-net-pci,netdev=n0")
            .arg("-netdev").arg("user,id=n1")
            .arg("-device").arg("e1000,netdev=n1")
            .arg("-object").arg("rng-random,id=rng0,filename=/dev/urandom")
            .arg("-device").arg("virtio-rng-pci,rng=rng0")
            .status();
    }
    path
}

fn ahci_image_path() -> PathBuf {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let path = root.join("target").join("narf-sata.img");
    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut buf = vec![0u8; 1024 * 1024];
        for i in 0..512usize {
            buf[i] = (i as u8).wrapping_mul(0x6D) ^ 0x42;
        }
        let _ = std::fs::write(&path, &buf);
    }
    path
}

fn virtio_blk_image_path() -> PathBuf {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let path = root.join("target").join("narf-vblk.img");
    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut buf = vec![0u8; 1024 * 1024];
        for i in 0..512usize {
            buf[i] = (i as u8).wrapping_mul(0x97);
        }
        let _ = std::fs::write(&path, &buf);
    }
    path
}

fn nvme_image_path() -> PathBuf {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let path = root.join("target").join("narf-nvme.img");
    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, vec![0u8; 1024 * 1024]);
    }
    path
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set — run via `cargo xtask`")?;
    let root = Path::new(&manifest)
        .parent().ok_or_else(|| anyhow!("manifest dir has no parent"))?
        .parent().ok_or_else(|| anyhow!("manifest dir has no grandparent"))?
        .to_path_buf();
    Ok(root)
}

fn cargo_build(args: &BuildArgs, root: &Path) -> Result<PathBuf> {
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(root)
        .arg("build")
        .arg("-p").arg(&args.package)
        .arg("--target").arg(args.arch.triple())
        .arg("-Z").arg("build-std=core,compiler_builtins,alloc")
        .arg("-Z").arg("build-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128");
    if args.release { cmd.arg("--release"); }
    if !args.features.is_empty() {
        cmd.arg("--features").arg(&args.features);
    }

    let status = cmd.status().context("failed to invoke cargo build")?;
    if !status.success() {
        bail!("cargo build failed with status {status}");
    }

    let profile = if args.release { "release" } else { "debug" };
    let out = root
        .join("target")
        .join(args.arch.triple())
        .join(profile);
    Ok(out)
}

use std::time::Duration;
use wait_timeout::ChildExt;

fn run_cmd(args: &BuildArgs) -> Result<()> {
    let root = workspace_root()?;
    let out_dir = cargo_build(args, &root)?;

    let kernel = out_dir.join(&args.package);
    if !kernel.exists() {
        bail!("expected kernel binary at {} — did `cargo build` succeed?",
              kernel.display());
    }

    let qemu = args.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(args.arch.qemu_args(&kernel, &args.display, args.hw_profile));
    
    println!("xtask: launching {} {}", qemu, kernel.display());
    
    let mut child = cmd.spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let secs = std::env::var("XTASK_QEMU_TIMEOUT_SECS")
        .ok().and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(240);
    match child.wait_timeout(Duration::from_secs(secs))? {
        Some(status) => {
            println!("xtask: {qemu} exited with {status}");
        }
        None => {
            child.kill()?;
            child.wait()?;
            bail!("xtask: {qemu} timed out after {secs}s (possible kernel hang)");
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build(args) => { cargo_build(&args, &workspace_root()?)?; Ok(()) }
        Cmd::Run(args)   => run_cmd(&args),
        Cmd::Test(mut args)  => {
            if args.features.is_empty() {
                args.features = "kernel-test".into();
            } else if !args.features.contains("kernel-test") {
                args.features.push_str(",kernel-test");
            }
            run_cmd(&args)
        }
        Cmd::Image(args) => {
            eprintln!("xtask image: stub (arch={:?}); wires in with boot/ at Stage 1 Wave 1.",
                args.arch.triple());
            Ok(())
        }
        Cmd::Demo(mut args) => {
            if args.features.is_empty() {
                args.features = "kernel-test,user-mode-testbin".into();
            } else {
                if !args.features.contains("kernel-test") {
                    args.features.push_str(",kernel-test");
                }
                if !args.features.contains("user-mode-testbin") {
                    args.features.push_str(",user-mode-testbin");
                }
            }
            if args.display == "none" {
                args.display = "gtk".into();
            }
            run_cmd(&args)
        }
    }
}
