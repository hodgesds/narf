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
    /// Build the bootable Limine ISO and boot it under QEMU + OVMF.
    /// Equivalent to `xtask image` followed by the matching
    /// `qemu-system-x86_64 -bios OVMF.fd -cdrom <iso> ...` invocation.
    IsoBoot(BuildArgs),
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
            Arch::X86_64 => "x86_64-unknown-none",
            Arch::Aarch64 => "aarch64-unknown-none",
        }
    }

    fn qemu_bin(self) -> &'static str {
        match self {
            Arch::X86_64 => "qemu-system-x86_64",
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
                        "-drive".into(),
                        format!(
                            "if=none,id=nvm0,format=raw,file={}",
                            nvme_image_path().display()
                        ),
                        "-device".into(),
                        "nvme,drive=nvm0,serial=narf".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-netdev".into(),
                        "user,id=n1".into(),
                        "-device".into(),
                        "e1000,netdev=n1".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-drive".into(),
                        format!(
                            "if=none,id=sata0,format=raw,file={}",
                            ahci_image_path().display()
                        ),
                        "-device".into(),
                        "ide-hd,drive=sata0,bus=ide.0".into(),
                    ]);
                    args.extend_from_slice(&["-device".into(), "qemu-xhci,id=xhci0".into()]);
                    // Boot-protocol keyboard hanging off the xHCI
                    // controller so the `usb-hid-keyboard` initcall has
                    // something to attach to. With this in place the
                    // QEMU smoke harness exercises the full
                    // xHCI → HID-boot-keyboard → narf_input pipeline.
                    args.extend_from_slice(&[
                        "-device".into(),
                        "usb-kbd,bus=xhci0.0".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-vga".into(),
                        "none".into(),
                        "-device".into(),
                        "bochs-display".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-audiodev".into(),
                        "none,id=snd0".into(),
                        "-device".into(),
                        "intel-hda".into(),
                        "-device".into(),
                        "hda-duplex,audiodev=snd0".into(),
                    ]);
                }

                if virtio {
                    args.extend_from_slice(&[
                        "-drive".into(),
                        format!(
                            "if=none,id=vblk0,format=raw,file={}",
                            virtio_blk_image_path().display()
                        ),
                        "-device".into(),
                        "virtio-blk-pci,drive=vblk0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-netdev".into(),
                        "user,id=n0".into(),
                        "-device".into(),
                        "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-object".into(),
                        "rng-random,id=rng0,filename=/dev/urandom".into(),
                        "-device".into(),
                        "virtio-rng-pci,rng=rng0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-balloon-pci,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-keyboard-pci,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-gpu-pci,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    if !legacy {
                        args.extend_from_slice(&["-audiodev".into(), "none,id=snd0".into()]);
                    }
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-sound-pci,audiodev=snd0,disable-legacy=on,disable-modern=off"
                            .into(),
                    ]);
                }

                args.push("-kernel".into());
                args.push(kernel);
                args
            }
            Arch::Aarch64 => {
                let mut args = vec![
                    "-machine".into(),
                    "virt,gic-version=3,mte=on,highmem-ecam=off".into(),
                    "-cpu".into(),
                    "max".into(),
                    "-smp".into(),
                    "2".into(),
                    "-m".into(),
                    "256M".into(),
                    "-serial".into(),
                    "stdio".into(),
                    "-display".into(),
                    display.clone(),
                    "-no-reboot".into(),
                    "-semihosting".into(),
                ];

                let virtio = matches!(profile, HwProfile::Full | HwProfile::VirtioOnly);
                let legacy = matches!(profile, HwProfile::Full | HwProfile::LegacyOnly);

                if legacy {
                    args.extend_from_slice(&[
                        "-drive".into(),
                        format!(
                            "if=none,id=nvm0,format=raw,file={}",
                            nvme_image_path().display()
                        ),
                        "-device".into(),
                        "nvme,drive=nvm0,serial=narf".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-netdev".into(),
                        "user,id=n1".into(),
                        "-device".into(),
                        "e1000,netdev=n1".into(),
                    ]);
                }

                if virtio {
                    args.extend_from_slice(&[
                        "-drive".into(),
                        format!(
                            "if=none,id=vblk0,format=raw,file={}",
                            virtio_blk_image_path().display()
                        ),
                        "-device".into(),
                        "virtio-blk-pci,drive=vblk0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-netdev".into(),
                        "user,id=n0".into(),
                        "-device".into(),
                        "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-object".into(),
                        "rng-random,id=rng0,filename=/dev/urandom".into(),
                        "-device".into(),
                        "virtio-rng-pci,rng=rng0,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-balloon-pci,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-keyboard-pci,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-gpu-pci,disable-legacy=on,disable-modern=off".into(),
                    ]);
                    args.extend_from_slice(&["-audiodev".into(), "none,id=snd0".into()]);
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-sound-pci,audiodev=snd0,disable-legacy=on,disable-modern=off"
                            .into(),
                    ]);
                }

                args.extend_from_slice(&[
                    "-device".into(),
                    format!(
                        "loader,file={},addr={:#x},force-raw=on",
                        qemu_virt_dtb_path().display(),
                        DTB_LOAD_ADDR
                    ),
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
                path.display()
            ))
            .arg("-cpu")
            .arg("max")
            .arg("-smp")
            .arg("2")
            .arg("-m")
            .arg("256M")
            .arg("-display")
            .arg("none")
            .arg("-no-reboot")
            .arg("-drive")
            .arg(format!(
                "if=none,id=nvm0,format=raw,file={}",
                nvme_image_path().display()
            ))
            .arg("-device")
            .arg("nvme,drive=nvm0,serial=narf")
            .arg("-drive")
            .arg(format!(
                "if=none,id=vblk0,format=raw,file={}",
                virtio_blk_image_path().display()
            ))
            .arg("-device")
            .arg("virtio-blk-pci,drive=vblk0")
            .arg("-netdev")
            .arg("user,id=n0")
            .arg("-device")
            .arg("virtio-net-pci,netdev=n0")
            .arg("-netdev")
            .arg("user,id=n1")
            .arg("-device")
            .arg("e1000,netdev=n1")
            .arg("-object")
            .arg("rng-random,id=rng0,filename=/dev/urandom")
            .arg("-device")
            .arg("virtio-rng-pci,rng=rng0")
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
        // 1 MiB FAT12 with NARF.TXT in the root. Mirrors
        // `drivers/fs/fat/src/tests.rs::build_fat12_image` so the
        // boot-time `root-mount-from-nvme` initcall can complete
        // against this image in QEMU.
        let img = build_fat12_nvme_image(2048, b"narf\n");
        let _ = std::fs::write(&path, &img);
    }
    path
}

/// Minimal FAT12 image — single-FAT, single-root-dir-sector, one
/// file (`NARF.TXT`) at cluster 2. Layout per Microsoft FATGEN §3.
fn build_fat12_nvme_image(total_sectors: u32, data: &[u8]) -> Vec<u8> {
    const LBS: usize = 512;
    let mut img = vec![0u8; LBS * total_sectors as usize];

    // BPB
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"NARFFAT ");
    img[11..13].copy_from_slice(&(LBS as u16).to_le_bytes());
    img[13] = 1;
    img[14..16].copy_from_slice(&1u16.to_le_bytes());
    img[16] = 2;
    img[17..19].copy_from_slice(&16u16.to_le_bytes());
    img[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&1u16.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT 1 + FAT 2 — entry 0 media, entry 1 EOC, entry 2 EOC.
    for &lba in &[1usize, 2usize] {
        let fat = &mut img[lba * LBS..lba * LBS + LBS];
        fat12_set(fat, 0, 0xFF8);
        fat12_set(fat, 1, 0xFFF);
        if !data.is_empty() {
            fat12_set(fat, 2, 0xFFF);
        }
    }

    if !data.is_empty() {
        let root_lba = 3usize;
        let entry = &mut img[root_lba * LBS..root_lba * LBS + 32];
        entry[0..11].copy_from_slice(b"NARF    TXT");
        entry[11] = 0x20;
        entry[26..28].copy_from_slice(&2u16.to_le_bytes());
        entry[28..32].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let data_lba = 4usize;
        img[data_lba * LBS..data_lba * LBS + data.len()].copy_from_slice(data);
    }
    img
}

/// Build a FAT16 disk image at `out_path` populated with `/init`
/// and `/shell` (cargo-built on demand from the userspace crates).
/// Used by `iso-boot` so the kernel's `frame::boot_userspace_init`
/// disk-load path takes over from the baked
/// `narf_verification::*_ELF` fallback.
///
/// Requires mtools (`mformat`/`mcopy`) on the host. Returns an error
/// when mtools is missing or any sub-step fails — the caller falls
/// back to the legacy single-file FAT12 fixture.
fn build_userspace_disk_image(workspace: &Path, out_path: &Path) -> Result<()> {
    // mtools presence — check with `which`. mformat exits non-zero
    // when invoked with no args, so a quick which is the cleanest
    // probe.
    if Command::new("which")
        .arg("mformat")
        .output()
        .ok()
        .and_then(|o| if o.status.success() { Some(()) } else { None })
        .is_none()
    {
        bail!("mtools (mformat) not on PATH");
    }
    if Command::new("which")
        .arg("mcopy")
        .output()
        .ok()
        .and_then(|o| if o.status.success() { Some(()) } else { None })
        .is_none()
    {
        bail!("mtools (mcopy) not on PATH");
    }

    let init_elf = build_user_binary(
        workspace,
        "userspace/init",
        "init",
        "init.ld",
    )?;
    let shell_elf = build_user_binary(
        workspace,
        "userspace/shell",
        "shell",
        "shell.ld",
    )?;

    // 16 MiB raw image — comfortable headroom for a few-hundred-KiB
    // pair of user binaries plus future additions, well below FAT16's
    // 2 GiB cap, well above the FAT16 minimum (~4 MiB after BPB
    // overhead).
    const IMG_BYTES: usize = 16 * 1024 * 1024;
    if let Some(parent) = out_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(out_path, vec![0u8; IMG_BYTES])
        .with_context(|| format!("failed to allocate {} byte image", IMG_BYTES))?;

    // mformat -i <img> -F :: builds a FAT32; -F omits and lets
    // mformat pick FAT16 when the image is too small for FAT32's
    // 65525-cluster minimum. -v narf labels the volume.
    let status = Command::new("mformat")
        .arg("-i")
        .arg(out_path)
        .arg("-v")
        .arg("NARF")
        .arg("::")
        .status()
        .context("failed to spawn mformat")?;
    if !status.success() {
        bail!("mformat failed with {status}");
    }

    // mcopy -i <img> <src> ::/<dst> — drop the binaries at the FAT
    // root. Lowercase `init` / `shell` matches what the kernel's
    // `try_load_from_root("init"/"shell")` looks up.
    for (src, dst) in [(&init_elf, "init"), (&shell_elf, "shell")] {
        let status = Command::new("mcopy")
            .arg("-i")
            .arg(out_path)
            .arg(src)
            .arg(format!("::/{}", dst))
            .status()
            .context("failed to spawn mcopy")?;
        if !status.success() {
            bail!("mcopy {} failed with {status}", src.display());
        }
    }

    Ok(())
}

/// Build a single user-space binary the same way verification/build.rs
/// builds init/shell — same triple (x86_64-unknown-none),
/// same linker script + code-model=large rustflag — into a
/// dedicated target dir under target/iso-boot-userbins/. Returns
/// the path to the produced ELF.
fn build_user_binary(
    workspace: &Path,
    crate_dir: &str,
    bin_name: &str,
    linker_script_name: &str,
) -> Result<PathBuf> {
    let crate_path = workspace.join(crate_dir);
    let linker_script = crate_path.join(linker_script_name);
    let target_dir = workspace
        .join("target")
        .join("iso-boot-userbins")
        .join(bin_name);
    let triple = "x86_64-unknown-none";

    // CARGO_ENCODED_RUSTFLAGS uses 0x1f (unit separator) between
    // entries — verification/build.rs does the same. Keeps the
    // separate `-C link-arg=-T...` and `-C relocation-model=static`
    // flags from being parsed as a single shell-style string.
    let rustflags = [
        "-C".to_string(),
        format!("link-arg=-T{}", linker_script.display()),
        "-C".to_string(),
        "relocation-model=static".to_string(),
        "-C".to_string(),
        "code-model=large".to_string(),
    ]
    .join("\x1f");

    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg(triple)
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("-Zbuild-std=core")
        .arg("-Zbuild-std-features=")
        .current_dir(&crate_path)
        .env("CARGO_ENCODED_RUSTFLAGS", &rustflags)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .with_context(|| format!("failed to spawn cargo build for {}", bin_name))?;
    if !status.success() {
        bail!("cargo build for {} failed with {status}", bin_name);
    }

    let bin = target_dir.join(triple).join("release").join(bin_name);
    if !bin.exists() {
        bail!("expected output {} missing after cargo build", bin.display());
    }
    Ok(bin)
}

fn fat12_set(fat: &mut [u8], idx: u32, val: u16) {
    let off = (idx + idx / 2) as usize;
    let v = val & 0x0FFF;
    if idx % 2 == 0 {
        fat[off] = (v & 0xFF) as u8;
        fat[off + 1] = (fat[off + 1] & 0xF0) | (((v >> 8) & 0x0F) as u8);
    } else {
        fat[off] = (fat[off] & 0x0F) | (((v << 4) & 0xF0) as u8);
        fat[off + 1] = ((v >> 4) & 0xFF) as u8;
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set — run via `cargo xtask`")?;
    let root = Path::new(&manifest)
        .parent()
        .ok_or_else(|| anyhow!("manifest dir has no parent"))?
        .parent()
        .ok_or_else(|| anyhow!("manifest dir has no grandparent"))?
        .to_path_buf();
    Ok(root)
}

fn cargo_build(args: &BuildArgs, root: &Path) -> Result<PathBuf> {
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(root)
        .arg("build")
        .arg("-p")
        .arg(&args.package)
        .arg("--target")
        .arg(args.arch.triple())
        .arg("-Z")
        .arg("build-std=core,compiler_builtins,alloc")
        .arg("-Z")
        .arg("build-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128");
    if args.release {
        cmd.arg("--release");
    }
    if !args.features.is_empty() {
        cmd.arg("--features").arg(&args.features);
    }

    let status = cmd.status().context("failed to invoke cargo build")?;
    if !status.success() {
        bail!("cargo build failed with status {status}");
    }

    let profile = if args.release { "release" } else { "debug" };
    let out = root.join("target").join(args.arch.triple()).join(profile);
    Ok(out)
}

use std::time::Duration;
use wait_timeout::ChildExt;

fn run_cmd(args: &BuildArgs) -> Result<()> {
    let root = workspace_root()?;
    let out_dir = cargo_build(args, &root)?;

    let kernel = out_dir.join(&args.package);
    if !kernel.exists() {
        bail!(
            "expected kernel binary at {} — did `cargo build` succeed?",
            kernel.display()
        );
    }

    let qemu = args.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(args.arch.qemu_args(&kernel, &args.display, args.hw_profile));

    println!("xtask: launching {} {}", qemu, kernel.display());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let secs = std::env::var("XTASK_QEMU_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
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

/// Produce a Limine-bootable UEFI ISO at
/// `target/narf-<arch>.iso`. The ISO chainloads the kernel via the
/// multiboot2 protocol, so the same ELF that QEMU `-kernel` boots
/// (PVH) also boots from this ISO under OVMF / real UEFI firmware.
///
/// External dependencies discovered at runtime:
///   - `xorriso` on `$PATH` — produces the El-Torito ISO.
///   - Limine support files (`BOOTX64.EFI` for UEFI, `limine-bios.sys`
///     + `limine-bios-cd.bin` for the legacy BIOS path) found at
///     `$LIMINE_PATH`, `/usr/share/limine/`, or `vendor/limine/`.
///   - `limine` binary (optional, only needed for BIOS install).
fn image_cmd(args: &BuildArgs) -> Result<()> {
    if !matches!(args.arch, Arch::X86_64) {
        bail!(
            "xtask image: arch {:?} not yet supported (x86_64 only)",
            args.arch.triple()
        );
    }
    let root = workspace_root()?;
    let out_dir = cargo_build(args, &root)?;
    let kernel = out_dir.join(&args.package);
    if !kernel.exists() {
        bail!("expected kernel binary at {}", kernel.display());
    }

    let xorriso = which("xorriso").ok_or_else(|| {
        anyhow!(
            "`xorriso` not on $PATH — install with `pacman -S libisoburn` \
             (Arch) or `apt install xorriso` (Debian/Ubuntu)"
        )
    })?;

    let limine_dir = locate_limine().ok_or_else(|| {
        anyhow!(
            "Limine support files not found. Install via `pacman -S limine` \
             (Arch) or `apt install limine` (Debian/Ubuntu), or set \
             $LIMINE_PATH to a directory containing BOOTX64.EFI + \
             limine-bios.sys + limine-bios-cd.bin."
        )
    })?;
    let bootx64 = limine_dir.join("BOOTX64.EFI");
    if !bootx64.exists() {
        bail!(
            "{} missing (Limine UEFI app); is `limine-uefi-x86-64` installed?",
            bootx64.display()
        );
    }

    let stage = root.join("target").join("iso-x86_64");
    let _ = std::fs::remove_dir_all(&stage);
    let boot_dir = stage.join("boot");
    let limine_stage = boot_dir.join("limine");
    let efi_dir = stage.join("EFI").join("BOOT");
    std::fs::create_dir_all(&limine_stage).context("creating boot/limine/")?;
    std::fs::create_dir_all(&efi_dir).context("creating EFI/BOOT/")?;

    std::fs::copy(&kernel, boot_dir.join("narf-frame"))
        .with_context(|| format!("copying kernel from {}", kernel.display()))?;
    std::fs::copy(&bootx64, efi_dir.join("BOOTX64.EFI"))
        .with_context(|| format!("copying {}", bootx64.display()))?;

    // BIOS support files are nice-to-have. xorriso flags below
    // reference them; if missing, drop the BIOS-side El-Torito
    // entry so the ISO still builds (UEFI-only).
    let bios_sys = limine_dir.join("limine-bios.sys");
    let bios_cd = limine_dir.join("limine-bios-cd.bin");
    let efi_cd = limine_dir.join("limine-uefi-cd.bin");
    let have_bios = bios_sys.exists() && bios_cd.exists();
    let have_efi_eltorito = efi_cd.exists();
    if have_bios {
        std::fs::copy(&bios_sys, limine_stage.join("limine-bios.sys"))?;
        std::fs::copy(&bios_cd, limine_stage.join("limine-bios-cd.bin"))?;
    }
    if have_efi_eltorito {
        std::fs::copy(&efi_cd, limine_stage.join("limine-uefi-cd.bin"))?;
    }

    // Limine v8+ config (`limine.conf`). The kernel is loaded as a
    // multiboot2 binary because boot.S now exposes the §3.1 header.
    // `serial: yes` mirrors Limine's own bring-up logging to COM1
    // (16550A 0x3F8) so a `-serial stdio` QEMU run captures both
    // Limine's stages and the kernel's UART writes.
    let cfg = "\
timeout: 0
serial: yes
verbose: yes
quiet: no
default_entry: 1

/NARF
    protocol: multiboot2
    path: boot():/boot/narf-frame
";
    std::fs::write(limine_stage.join("limine.conf"), cfg).context("writing limine.conf")?;

    let iso = root.join("target").join("narf-x86_64.iso");
    let _ = std::fs::remove_file(&iso);

    let mut cmd = Command::new(&xorriso);
    cmd.arg("-as").arg("mkisofs").arg("-quiet");
    if have_bios {
        cmd.arg("-b")
            .arg("boot/limine/limine-bios-cd.bin")
            .arg("-no-emul-boot")
            .arg("-boot-load-size")
            .arg("4")
            .arg("-boot-info-table");
    }
    if have_efi_eltorito {
        cmd.arg("--efi-boot")
            .arg("boot/limine/limine-uefi-cd.bin")
            .arg("-efi-boot-part")
            .arg("--efi-boot-image")
            .arg("--protective-msdos-label");
    }
    cmd.arg(stage.as_os_str())
        .arg("-o")
        .arg(iso.as_os_str());

    let status = cmd.status().context("running xorriso")?;
    if !status.success() {
        bail!("xorriso exited with {status}");
    }

    if have_bios {
        if let Some(limine_bin) = which("limine") {
            let st = Command::new(limine_bin)
                .arg("bios-install")
                .arg(&iso)
                .status()
                .context("running `limine bios-install`")?;
            if !st.success() {
                bail!("`limine bios-install` exited with {st}");
            }
        } else {
            eprintln!(
                "xtask image: skipping `limine bios-install` (binary not on $PATH); \
                 ISO will still UEFI-boot, but legacy BIOS boot will be disabled."
            );
        }
    }

    println!("xtask image: wrote {}", iso.display());
    let ovmf = ovmf_code_path();
    println!(
        "  test under QEMU UEFI:  qemu-system-x86_64 -bios {} -cpu max -m 1024M \\\n\
         \x20                          -cdrom {} -serial stdio -display none -no-reboot",
        ovmf.display(),
        iso.display()
    );
    println!(
        "  -cpu max is required: the kernel uses RDTSCP / RDSEED / etc. that the\n\
         \x20 default qemu64 model doesn't expose.\n\
         \x20 -m 1024M leaves room for the kernel image (~52 MiB at LOAD_BASE 16 MiB)\n\
         \x20 + UEFI's reservations + the 32 MiB static heap arena."
    );
    Ok(())
}

/// Build a Limine ISO and boot it under QEMU with OVMF firmware.
/// Mirrors `image_cmd` for the build half, then assembles the
/// `qemu-system-x86_64 -bios <ovmf> -cdrom <iso> ...` invocation
/// that lets the kernel exercise the UEFI handoff path end-to-end
/// (the same path real consumer hardware takes).
fn iso_boot_cmd(args: &BuildArgs) -> Result<()> {
    if !matches!(args.arch, Arch::X86_64) {
        bail!(
            "xtask iso-boot: arch {:?} not yet supported (x86_64 only)",
            args.arch.triple()
        );
    }
    image_cmd(args)?;

    let root = workspace_root()?;
    let iso = root.join("target").join("narf-x86_64.iso");
    let ovmf = ovmf_code_path();
    // Regenerate the NVMe image — the kernel's NVMe smokes
    // (`smoke_nvme_io_round_trip`, async round-trip, MSI-X round-trip)
    // write sentinel patterns at LBA 0 / 1 to verify read-back, which
    // clobbers the FAT BPB if the image survives between runs. Forcing
    // a rewrite before iso-boot guarantees the boot-time
    // `root-mount-from-nvme` initcall sees a valid FAT volume.
    //
    // Try to populate the FAT root with /init + /shell so the
    // boot-init disk-load path of frame::boot_userspace_init takes
    // over from the baked narf_verification::*_ELF fallback. Needs
    // mtools (mformat/mcopy) on the host; falls back to the
    // hand-crafted single-file FAT12 image when mtools is missing.
    let _ = std::fs::remove_file(nvme_image_path());
    match build_userspace_disk_image(&root, &nvme_image_path()) {
        Ok(()) => {
            println!(
                "xtask iso-boot: FAT16 disk image populated with /init + /shell at {}",
                nvme_image_path().display()
            );
        }
        Err(e) => {
            println!(
                "xtask iso-boot: skipping disk-userspace populate ({e}); falling back to single-file FAT12 fixture"
            );
            // Force the legacy hand-crafted image to be regenerated.
            let _ = nvme_image_path();
        }
    }
    if !ovmf.is_file() {
        bail!(
            "OVMF firmware not found at {}; install `edk2-ovmf` (Arch) \
             or `ovmf` (Debian/Ubuntu), or symlink the firmware here.",
            ovmf.display()
        );
    }

    // Same NVMe + virtio devices as the `-kernel` smoke harness so
    // the boot-time `root-mount-from-nvme` initcall has a real
    // FAT-formatted disk to try, and so virtio drivers see their
    // expected backends.
    let virtio = matches!(args.hw_profile, HwProfile::Full | HwProfile::VirtioOnly);
    let legacy = matches!(args.hw_profile, HwProfile::Full | HwProfile::LegacyOnly);

    let display = if args.display.is_empty() {
        "none"
    } else {
        args.display.as_str()
    };

    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.arg("-bios").arg(&ovmf);
    // q35 — same chipset the smoke harness uses. The default `pc`
    // (i440FX) machine has no PCIe ECAM, only legacy CF8/CFC PCI
    // config IO, which the kernel's bus walker doesn't drive yet.
    cmd.arg("-machine").arg("q35");
    cmd.arg("-cpu").arg("max");
    cmd.arg("-smp").arg("2");
    cmd.arg("-m").arg("1024M");
    cmd.arg("-cdrom").arg(&iso);
    cmd.arg("-serial").arg("stdio");
    cmd.arg("-display").arg(display);
    cmd.arg("-no-reboot");

    if legacy {
        cmd.arg("-drive")
            .arg(format!(
                "if=none,id=nvm0,format=raw,file={}",
                nvme_image_path().display()
            ))
            .arg("-device")
            .arg("nvme,drive=nvm0,serial=narf");
    }
    if virtio {
        cmd.arg("-drive")
            .arg(format!(
                "if=none,id=vblk0,format=raw,file={}",
                virtio_blk_image_path().display()
            ))
            .arg("-device")
            .arg("virtio-blk-pci,drive=vblk0,disable-legacy=on,disable-modern=off");
    }

    println!("xtask iso-boot: launching qemu-system-x86_64 with ISO {}", iso.display());

    let mut child = cmd.spawn().context("failed to spawn qemu-system-x86_64")?;
    let secs = std::env::var("XTASK_QEMU_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);
    match child.wait_timeout(Duration::from_secs(secs))? {
        Some(status) => {
            println!("xtask iso-boot: qemu exited with {status}");
        }
        None => {
            child.kill()?;
            child.wait()?;
            bail!("xtask iso-boot: qemu timed out after {secs}s");
        }
    }
    Ok(())
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn locate_limine() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("LIMINE_PATH") {
        let pb = PathBuf::from(p);
        if pb.is_dir() {
            return Some(pb);
        }
    }
    for cand in ["/usr/share/limine", "/usr/local/share/limine"] {
        let pb = PathBuf::from(cand);
        if pb.is_dir() {
            return Some(pb);
        }
    }
    if let Ok(root) = workspace_root() {
        let pb = root.join("vendor").join("limine");
        if pb.is_dir() {
            return Some(pb);
        }
    }
    None
}

fn ovmf_code_path() -> PathBuf {
    for cand in [
        // Arch (edk2-ovmf >= 202311). The 4m variant ships with the
        // newer x64 image; the legacy `OVMF_CODE.fd` was renamed.
        "/usr/share/edk2/x64/OVMF.4m.fd",
        "/usr/share/edk2-ovmf/x64/OVMF.4m.fd",
        "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
        "/usr/share/edk2/x64/OVMF_CODE.fd",
        "/usr/share/ovmf/x64/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ] {
        let pb = PathBuf::from(cand);
        if pb.is_file() {
            return pb;
        }
    }
    PathBuf::from("OVMF_CODE.fd")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build(args) => {
            cargo_build(&args, &workspace_root()?)?;
            Ok(())
        }
        Cmd::Run(args) => run_cmd(&args),
        Cmd::Test(mut args) => {
            if args.features.is_empty() {
                args.features = "kernel-test".into();
            } else if !args.features.contains("kernel-test") {
                args.features.push_str(",kernel-test");
            }
            run_cmd(&args)
        }
        Cmd::Image(args) => image_cmd(&args),
        Cmd::IsoBoot(mut args) => {
            // Default-on boot-init so the ISO actually spawns the
            // userspace init + shell tasks; without it the kernel
            // halts at the async-demo exit gate before reaching
            // boot_userspace_init().
            if args.features.is_empty() {
                args.features = "boot-init".into();
            } else if !args.features.contains("boot-init") {
                args.features.push_str(",boot-init");
            }
            iso_boot_cmd(&args)
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
