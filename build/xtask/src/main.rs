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
    /// Wipe and burn the NARF ISO to a USB stick, with verification
    /// after a logical detach so the burn is guaranteed to land on
    /// real flash NAND (not USB-controller cache).
    DiskWrite(DiskWriteArgs),
    /// Wipe a USB stick and lay out a partitioned NARF disk:
    /// GPT with an ESP (FAT32) holding the kernel + Limine, and a
    /// labelled ext4 root partition (NARF_ROOT) holding /sbin/init
    /// + /bin/sh. Boot picks the root via `root=PARTLABEL=NARF_ROOT`
    /// on the kernel cmdline.
    DiskWritePartitioned(DiskWritePartitionedArgs),
    /// Wrap a raw firmware payload with the NARF trailer
    /// (`firmware/specification/spec.md` §6). Produces an unsigned
    /// blob — kernel must be built with `firmware-allow-unsigned`
    /// for these to load. The wrapped output goes into
    /// `firmware/<name>` inside the workspace (so `xtask image`
    /// auto-bundles it into the initramfs CPIO).
    PackFirmware(PackFirmwareArgs),
}

#[derive(Parser, Clone)]
struct PackFirmwareArgs {
    /// Canonical blob name as the kernel sees it, e.g.
    /// `amdgpu/phoenix.bin`. This drives the on-disk path under
    /// `firmware/` AND the registry key the driver opens with
    /// `narf_firmware::open(name, auth)`.
    #[arg(long)]
    name: String,

    /// Path to the raw firmware payload (what the device's
    /// firmware loader actually consumes; e.g. an
    /// /lib/firmware/amdgpu/*.bin file).
    #[arg(long)]
    payload: String,

    /// Optional version string baked into the trailer metadata
    /// (TLV tag 0x01). Surfaced in `BoundFirmware.version` so the
    /// kernel can log "loaded vN.N" alongside the bound driver.
    #[arg(long)]
    version: Option<String>,

    /// Output path. Defaults to `firmware/<name>` under the
    /// workspace root so subsequent `xtask image` runs pick it up.
    #[arg(long)]
    out: Option<String>,
}

#[derive(Parser, Clone)]
struct DiskWritePartitionedArgs {
    /// Block device to format (e.g. /dev/sda). Auto-detected USB
    /// when omitted.
    #[arg(long)]
    device: Option<String>,

    /// ESP partition size in MiB. Holds kernel + initramfs + Limine.
    /// 256 MiB fits the kernel + ramdisk + Limine with room to grow.
    #[arg(long, default_value_t = 256)]
    esp_size_mib: u64,

    /// Filesystem for the root partition.
    #[arg(long, value_enum, default_value_t = RootFs::Ext4)]
    root_fs: RootFs,

    /// Partition label for the root partition. The kernel cmdline
    /// installs `root=PARTLABEL=<label>` so this name pins boot
    /// selection. Default "NARF_ROOT" matches the kernel's
    /// recommended convention.
    #[arg(long, default_value = "NARF_ROOT")]
    root_label: String,

    /// Skip the user-confirmation prompt. Use only in automation;
    /// any wrong --device will wipe the wrong disk.
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum RootFs {
    Ext2,
    Ext4,
}

impl RootFs {
    fn mkfs_program(self) -> &'static str {
        match self {
            RootFs::Ext2 => "mkfs.ext2",
            RootFs::Ext4 => "mkfs.ext4",
        }
    }
}

#[derive(Parser, Clone)]
struct DiskWriteArgs {
    /// Block device to burn (e.g. /dev/sda). Auto-detected if omitted —
    /// xtask picks the first USB-attached disk it finds.
    #[arg(long)]
    device: Option<String>,

    /// Skip the slow full-device wipe (just dd the ISO over whatever's
    /// there). Use only if you know the USB has no leftover bootable
    /// signatures past the ISO size.
    #[arg(long)]
    no_wipe: bool,

    /// Fast wipe: zero only the first 100 MiB + last 4 MiB of the
    /// device. Covers MBR / GPT primary + backup / EFI ESP /
    /// El Torito boot records — everything firmware looks at to
    /// pick up bootable signatures. Skips the slow middle-of-disk
    /// zero-fill. Default behavior when the device is bigger than
    /// the ISO and fast-wipe gives the same boot-correctness as a
    /// full wipe.
    #[arg(long)]
    fast_wipe: bool,

    /// ISO to burn. Defaults to target/narf-x86_64.iso.
    #[arg(long)]
    iso: Option<String>,
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

/// Encode a CPIO newc (`070701`) archive containing `entries` plus
/// the mandatory `TRAILER!!!` sentinel. Each entry is `(name,
/// data)`; names appear at the archive's root (no leading `/`),
/// matching what `narf_filesystem::Initramfs::from_cpio` expects.
///
/// Format reference (POSIX 1003.1-1988 + the de-facto cpio newc
/// addendum used by Linux + BSD initramfs tooling):
///   <https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt>
///
/// 110-byte ASCII-hex header per entry followed by NUL-terminated
/// name (padded to 4-byte boundary including the 110-byte header)
/// + file data (padded to 4-byte boundary). Mode is 0o100644
/// (regular file, owner rw, others r). Inode + nlink + mtime are
/// fixed because we only build deterministic archives — anything
/// else would invalidate ISO checksums on rebuilds.
fn encode_cpio_newc(entries: &[(&str, &[u8])]) -> Vec<u8> {
    fn pad_to_4(out: &mut Vec<u8>) {
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    fn write_hex8(out: &mut Vec<u8>, v: u32) {
        // ASCII uppercase hex, exactly 8 chars, zero-padded.
        let s = format!("{:08X}", v);
        out.extend_from_slice(s.as_bytes());
    }
    fn write_entry(
        out: &mut Vec<u8>,
        ino: u32,
        mode: u32,
        name: &str,
        data: &[u8],
    ) {
        let name_bytes = name.as_bytes();
        let namesize = (name_bytes.len() + 1) as u32; // +1 for NUL
        out.extend_from_slice(b"070701");
        write_hex8(out, ino); // c_ino
        write_hex8(out, mode); // c_mode
        write_hex8(out, 0); // c_uid
        write_hex8(out, 0); // c_gid
        write_hex8(out, 1); // c_nlink
        write_hex8(out, 0); // c_mtime
        write_hex8(out, data.len() as u32); // c_filesize
        write_hex8(out, 0); // c_devmajor
        write_hex8(out, 0); // c_devminor
        write_hex8(out, 0); // c_rdevmajor
        write_hex8(out, 0); // c_rdevminor
        write_hex8(out, namesize); // c_namesize (incl. NUL)
        write_hex8(out, 0); // c_check (always 0 for newc)
        out.extend_from_slice(name_bytes);
        out.push(0); // NUL
        pad_to_4(out);
        out.extend_from_slice(data);
        pad_to_4(out);
    }
    let mut out = Vec::with_capacity(
        entries.iter().map(|(n, d)| 110 + n.len() + 4 + d.len() + 4).sum::<usize>() + 256,
    );
    for (i, (name, data)) in entries.iter().enumerate() {
        // Inode 0 is reserved for the trailer; start at 1.
        write_entry(&mut out, (i + 1) as u32, 0o100644, name, data);
    }
    // TRAILER!!! sentinel — type fields all zero, name is the
    // literal "TRAILER!!!" (10 bytes + NUL = 11), no data.
    write_entry(&mut out, 0, 0, "TRAILER!!!", &[]);
    out
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
/// Append `feature` to a comma-separated feature list if it isn't
/// already present. Avoids the duplicate-feature warnings from
/// downstream cargo calls when the user supplies an overlapping
/// `--features` arg.
fn ensure_feature(features: &mut String, feature: &str) {
    if features.is_empty() {
        features.push_str(feature);
        return;
    }
    if features.split(',').any(|f| f.trim() == feature) {
        return;
    }
    features.push(',');
    features.push_str(feature);
}

/// Recursively walk `fw_dir` collecting every regular file. Returns
/// `(cpio_name, bytes)` pairs where `cpio_name = "firmware/<rel>"`
/// — the prefix the kernel's `scan_initramfs` strips when it
/// registers entries by canonical name.
///
/// Empty result is fine — a build with no firmware just skips the
/// scan + ships the same init+shell-only CPIO as before.
fn collect_firmware_blobs(fw_dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    if !fw_dir.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![fw_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("read_dir {}", dir.display()))?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let rel = path
                .strip_prefix(fw_dir)
                .with_context(|| format!("strip_prefix {} vs {}", path.display(), fw_dir.display()))?;
            let rel_str = rel
                .to_str()
                .ok_or_else(|| anyhow!("firmware path {} not valid UTF-8", path.display()))?
                .replace('\\', "/");
            let cpio_name = format!("firmware/{}", rel_str);
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading firmware blob {}", path.display()))?;
            out.push((cpio_name, bytes));
        }
    }
    // Stable order so successive builds produce byte-identical CPIO
    // payloads when nothing in firmware/ changed (helps debugging +
    // any future reproducibility work).
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Wrap a raw firmware payload with the NARF trailer + write it to
/// disk. Reference: `firmware/src/signature.rs` — payload bytes,
/// then a 64-byte all-zero signature, 32-byte all-zero signer
/// fingerprint (the "unsigned" sentinel), metadata TLV bytes
/// (tag 0x01 = ASCII version), 4-byte LE metadata length, then
/// the 4-byte trailing magic `b"NRFW"`.
///
/// Kernel must be built with `firmware-allow-unsigned` to accept
/// these — the `firmware-init` initcall rejects unsigned blobs
/// otherwise.
fn pack_firmware_cmd(args: &PackFirmwareArgs) -> Result<()> {
    let payload = std::fs::read(&args.payload)
        .with_context(|| format!("reading payload from {}", &args.payload))?;
    if payload.is_empty() {
        bail!("payload {} is empty — NARF amdgpu rejects size==0", &args.payload);
    }

    // Metadata: TLV records (1-byte tag + 1-byte len + value).
    // Tag 0x01 = ASCII version string. Skipped when --version
    // wasn't supplied so the trailer stays minimal.
    let mut metadata: Vec<u8> = Vec::new();
    if let Some(ver) = &args.version {
        let bytes = ver.as_bytes();
        if bytes.len() > 255 {
            bail!("version string too long ({} > 255)", bytes.len());
        }
        metadata.push(0x01); // tag
        metadata.push(bytes.len() as u8);
        metadata.extend_from_slice(bytes);
    }

    let mut blob: Vec<u8> = Vec::with_capacity(payload.len() + 104 + metadata.len());
    blob.extend_from_slice(&payload);
    blob.extend_from_slice(&[0u8; 64]); // unsigned sig sentinel
    blob.extend_from_slice(&[0u8; 32]); // unsigned signer fingerprint
    blob.extend_from_slice(&metadata);
    blob.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    blob.extend_from_slice(b"NRFW");

    let out_path: PathBuf = match &args.out {
        Some(p) => PathBuf::from(p),
        None => workspace_root()?.join("firmware").join(&args.name),
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating output dir {}", parent.display()))?;
    }
    std::fs::write(&out_path, &blob)
        .with_context(|| format!("writing wrapped blob to {}", out_path.display()))?;
    println!(
        "xtask pack-firmware: wrote {} ({} payload bytes + {} trailer bytes = {} total)",
        out_path.display(),
        payload.len(),
        blob.len() - payload.len(),
        blob.len(),
    );
    println!(
        "  registry key: {}  (kernel opens via `narf_firmware::open(\"{}\", auth)`)",
        &args.name, &args.name,
    );
    if args.version.is_none() {
        println!("  no --version supplied; blob's BoundFirmware.version will be None");
    }
    Ok(())
}

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

    // Build init + shell ELFs into a CPIO newc archive that Limine
    // will pass through as a multiboot2 module tagged "initramfs".
    // The kernel's `narf_initramfs::stage_from_phys` parses it and
    // `root-mount-auto` mounts it at "/" so boot-init's
    // `try_load_from_root("init"/"shell")` resolves CPIO entries
    // instead of falling back to the baked-in ELFs. Lets the user
    // binaries iterate without rebuilding the kernel.
    let init_elf = build_user_binary(&root, "userspace/init", "init", "init.ld")?;
    let shell_elf = build_user_binary(&root, "userspace/shell", "shell", "shell.ld")?;
    let init_bytes = std::fs::read(&init_elf)
        .with_context(|| format!("reading init ELF at {}", init_elf.display()))?;
    let shell_bytes = std::fs::read(&shell_elf)
        .with_context(|| format!("reading shell ELF at {}", shell_elf.display()))?;

    // Firmware bundling: walk `firmware/` under the workspace root.
    // Each file lands in the initramfs CPIO as `firmware/<relpath>`
    // and the kernel's `firmware-scan-initramfs` initcall registers
    // it under that suffix. Pack with `cargo xtask pack-firmware`
    // — raw `/lib/firmware/amdgpu/*.bin` files won't load without
    // the NARF trailer.
    let fw_dir = root.join("firmware");
    let fw_entries = collect_firmware_blobs(&fw_dir)?;

    let mut cpio_entries: Vec<(&str, &[u8])> = Vec::new();
    cpio_entries.push(("init", &init_bytes));
    cpio_entries.push(("shell", &shell_bytes));
    for (path, bytes) in &fw_entries {
        cpio_entries.push((path.as_str(), bytes.as_slice()));
    }
    let cpio = encode_cpio_newc(&cpio_entries);
    let cpio_path = boot_dir.join("initramfs.cpio");
    std::fs::write(&cpio_path, &cpio)
        .with_context(|| format!("writing initramfs CPIO to {}", cpio_path.display()))?;
    if fw_entries.is_empty() {
        println!(
            "xtask image: bundled initramfs ({} bytes; init={} bytes, shell={} bytes, no firmware)",
            cpio.len(),
            init_bytes.len(),
            shell_bytes.len(),
        );
    } else {
        let fw_total: usize = fw_entries.iter().map(|(_, b)| b.len()).sum();
        println!(
            "xtask image: bundled initramfs ({} bytes; init={} bytes, shell={} bytes, \
             {} firmware blob(s) totalling {} bytes)",
            cpio.len(),
            init_bytes.len(),
            shell_bytes.len(),
            fw_entries.len(),
            fw_total,
        );
        for (name, bytes) in &fw_entries {
            println!("  firmware: {} ({} bytes)", name, bytes.len());
        }
    }

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
    // `module_path` ships the CPIO archive to the kernel as a
    // multiboot2 module; `module_string` sets the module's command-
    // line so `narf_boot::x86_64::multiboot2::initramfs_module`
    // matches it (case-insensitive equality with "initramfs").
    let cfg = "\
timeout: 5
serial: yes
verbose: yes
quiet: no
default_entry: 1
interface_resolution: 1024x768

/NARF
    protocol: multiboot2
    path: boot():/boot/narf-frame
    module_path: boot():/boot/initramfs.cpio
    module_string: initramfs
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
        "  test under QEMU UEFI:  qemu-system-x86_64 -bios {} -machine q35 -cpu max -m 1024M \\\n\
         \x20                          -cdrom {} -serial stdio -display none -no-reboot",
        ovmf.display(),
        iso.display()
    );
    println!(
        "  -machine q35 is required: the default `pc` (i440fx) machine has no PCIe\n\
         \x20 ECAM, only legacy CF8/CFC config space. Without an ACPI MCFG table the\n\
         \x20 kernel skips PCI enumeration entirely and no virtio / xhci / gpu device\n\
         \x20 probes.\n\
         \x20 -cpu max is required: the kernel uses RDTSCP / RDSEED / etc. that the\n\
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
    // CPU model. Default `max` = union of every feature QEMU can
    // emulate. Override via XTASK_CPU to reproduce a specific real
    // silicon: `XTASK_CPU=EPYC-Rome` matches Zen2 (Renoir / Lucienne
    // laptop CPUID), `XTASK_CPU=EPYC-Genoa` matches Zen4 (Phoenix
    // HawkPoint1 laptop). Lets us catch "boots in -cpu max, faults
    // on real silicon" bugs (missing NXE / Invariant TSC / SMEP
    // enable etc.) without the burn-and-pray loop.
    let cpu = std::env::var("XTASK_CPU").unwrap_or_else(|_| "max".into());
    cmd.arg("-cpu").arg(&cpu);
    // Default -smp 8 so iso-boot exercises the multi-core AP
    // bring-up path; bumping past 2 catches AP-side bugs that
    // single-socket-dual-core misses (APIC-id gaps, init-order
    // races, percpu storage init). Override via XTASK_SMP for
    // ad-hoc spelunking (XTASK_SMP=16, etc.).
    let smp = std::env::var("XTASK_SMP").unwrap_or_else(|_| "8".into());
    cmd.arg("-smp").arg(&smp);
    cmd.arg("-m").arg("1024M");
    cmd.arg("-cdrom").arg(&iso);
    cmd.arg("-serial").arg("stdio");
    cmd.arg("-display").arg(display);
    cmd.arg("-no-reboot");
    // USB input — xHCI + boot-protocol keyboard + absolute-pointing
    // tablet. Q35's PS/2 IRQ delivery is flaky under non-default
    // CPU models (e.g. XTASK_CPU=EPYC-Rome doesn't reliably fire
    // IRQ 1/12), so attach USB input that goes through the xHCI
    // pipeline instead. Works on every CPU model QEMU supports;
    // exercises the same xHCI HID path real silicon will use.
    cmd.arg("-device").arg("qemu-xhci,id=xhci0");
    cmd.arg("-device").arg("usb-kbd,bus=xhci0.0");
    cmd.arg("-device").arg("usb-tablet,bus=xhci0.0");

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

/// Burn the NARF ISO to a USB stick reliably:
///   1. Auto-detect or use --device. Refuse anything that isn't USB-
///      attached (sanity check against accidentally trashing your
///      NVMe / SATA root disk).
///   2. Unmount any partitions that udev mounted automatically.
///   3. Optionally wipe the entire device with zeros (default on) to
///      kill leftover bootable signatures from previous installer
///      images. Without this, the laptop's UEFI may pick up an old
///      OS's boot record past the new ISO's last byte.
///   4. dd the ISO with conv=fsync + oflag=direct so writes bypass
///      the OS page cache and complete to flash.
///   5. `sync` to flush filesystem-level caches, blockdev --flushbufs
///      to drain the kernel's buffer cache for the device.
///   6. `echo 1 > /sys/block/<dev>/device/delete` — kernel-level
///      detach. The kernel waits for in-flight I/O and signals the
///      USB controller to flush its internal cache before going away.
///      This is the *only* way to be sure consumer USB sticks have
///      actually committed to NAND (their write caches lie).
///   7. Prompt the user to physically unplug + replug.
///   8. Re-detect the device (it may come back as a different name
///      after replug) and SHA-verify the first $ISO_SIZE bytes match
///      the source ISO byte-for-byte.
fn disk_write_cmd(args: &DiskWriteArgs) -> Result<()> {
    use std::io::{BufRead, Write};

    let iso_path = args
        .iso
        .clone()
        .unwrap_or_else(|| {
            workspace_root()
                .ok()
                .map(|r| r.join("target").join("narf-x86_64.iso"))
                .unwrap_or_else(|| PathBuf::from("target/narf-x86_64.iso"))
                .display()
                .to_string()
        });
    let iso = PathBuf::from(&iso_path);
    if !iso.exists() {
        bail!("ISO not found at {}; run `cargo xtask image` first", iso.display());
    }
    let iso_size = std::fs::metadata(&iso)?.len();
    println!("ISO: {} ({} MiB)", iso.display(), iso_size / 1024 / 1024);

    let dev = match &args.device {
        Some(d) => d.clone(),
        None => detect_usb_device()?,
    };
    println!("Target device: {}", dev);

    // Sanity: reject if not USB. Prevents accidental NVMe wipe.
    if !is_usb_device(&dev)? {
        bail!(
            "{} is NOT a USB-attached disk. Refusing to wipe it. \
             Pass --device explicitly if you really mean this.",
            dev
        );
    }

    // Show the user what they're about to nuke.
    let _ = Command::new("lsblk")
        .args(["-o", "NAME,SIZE,MODEL,TRAN,MOUNTPOINTS"])
        .arg(&dev)
        .status();
    print!("This wipes EVERYTHING on {}. Proceed? [y/N] ", dev);
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        bail!("aborted");
    }

    // Unmount any partitions udev mounted automatically.
    for n in 1..=4 {
        let _ = Command::new("sudo")
            .args(["umount", &format!("{}{}", dev, n)])
            .status();
    }

    // Wipe strategy:
    //   --no-wipe:   skip entirely (only safe if device is already clean)
    //   --fast-wipe: zero first 100 MiB + last 4 MiB only
    //   default:     zero entire device (slowest, most thorough)
    if args.no_wipe {
        // nothing
    } else if args.fast_wipe {
        println!("Fast-wiping (first 100 MiB + last 4 MiB)...");
        // First 100 MiB
        let st = Command::new("sudo")
            .args([
                "dd",
                "if=/dev/zero",
                &format!("of={}", dev),
                "bs=1M",
                "count=100",
                "status=progress",
                "conv=fsync",
            ])
            .status()
            .context("running dd /dev/zero (head)")?;
        if !st.success() {
            bail!("fast-wipe head failed with {st}");
        }
        // Last 4 MiB. Compute device byte size to seek correctly.
        let size_out = Command::new("sudo")
            .args(["blockdev", "--getsize64", &dev])
            .output()
            .context("blockdev --getsize64")?;
        let size: u64 = String::from_utf8_lossy(&size_out.stdout)
            .trim()
            .parse()
            .context("parsing device size")?;
        let seek_blocks = (size / (1024 * 1024)).saturating_sub(4);
        let st = Command::new("sudo")
            .args([
                "dd",
                "if=/dev/zero",
                &format!("of={}", dev),
                "bs=1M",
                "count=4",
                &format!("seek={}", seek_blocks),
                "conv=fsync",
            ])
            .status()
            .context("running dd /dev/zero (tail)")?;
        if !st.success() {
            bail!("fast-wipe tail failed with {st}");
        }
    } else {
        println!("Wiping {} (zeroing — this is the slow part)...", dev);
        let st = Command::new("sudo")
            .args([
                "dd",
                "if=/dev/zero",
                &format!("of={}", dev),
                "bs=4M",
                "status=progress",
                "conv=fsync",
            ])
            .status()
            .context("running dd /dev/zero")?;
        // dd returns non-zero when it hits end-of-device, which is
        // the expected outcome here (we wanted to fill the whole
        // stick). Treat any other error as fatal.
        if !st.success() && st.code() != Some(1) {
            bail!("wipe dd failed with {st}");
        }
    }

    // Burn.
    println!("Burning {} → {}...", iso.display(), dev);
    let st = Command::new("sudo")
        .args([
            "dd",
            &format!("if={}", iso.display()),
            &format!("of={}", dev),
            "bs=4M",
            "status=progress",
            "oflag=direct",
            "conv=fsync",
        ])
        .status()
        .context("running dd ISO")?;
    if !st.success() {
        bail!("burn dd failed with {st}");
    }

    // OS-level + block-layer flush.
    let _ = Command::new("sync").status();
    let _ = Command::new("sudo")
        .args(["blockdev", "--flushbufs", &dev])
        .status();

    // Kernel-level detach: this drains in-flight I/O AND tells the
    // USB stick to commit its internal write cache. Without it,
    // even after sync, the stick's controller may have pending
    // writes in DRAM that haven't reached NAND.
    let dev_short = dev.trim_start_matches("/dev/");
    let delete_path = format!("/sys/block/{}/device/delete", dev_short);
    let st = Command::new("sudo")
        .args(["sh", "-c", &format!("echo 1 > {}", delete_path)])
        .status()
        .context("triggering sysfs delete")?;
    if !st.success() {
        eprintln!(
            "warning: kernel-level detach failed (sysfs delete returned {}); \
             you may need to manually safely-eject before unplugging",
            st
        );
    }

    println!();
    println!("Logical detach done. PHYSICALLY UNPLUG the USB stick now.");
    println!("Wait 5 seconds, then plug it back in.");
    print!("Press ENTER once it's plugged back in... ");
    std::io::stdout().flush()?;
    let mut _ignore = String::new();
    std::io::stdin().lock().read_line(&mut _ignore)?;

    // Give udev a moment to enumerate the replugged device.
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Re-detect — the device may come back as a different name.
    let dev2 = if args.device.is_some() && std::path::Path::new(&dev).exists() {
        dev.clone()
    } else {
        detect_usb_device()
            .context("USB stick not detected after replug — is it inserted?")?
    };
    if dev2 != dev {
        println!("USB came back as {} (was {})", dev2, dev);
    }

    // Drop kernel page caches for the device so the SHA we compute
    // is genuinely from re-reading flash, not a cached copy of the
    // bytes we just wrote. echo 3 > drop_caches drops pagecache,
    // dentries, and inodes.
    let _ = Command::new("sync").status();
    let _ = Command::new("sudo")
        .args(["sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"])
        .status();

    // SHA verify.
    println!("Verifying SHA from fresh-read flash...");
    let iso_sha = sha256_file(&iso)?;
    let usb_sha = sha256_first_n(&dev2, iso_size)?;
    println!("ISO: {}", iso_sha);
    println!("USB: {}", usb_sha);
    if iso_sha == usb_sha {
        println!("✓ MATCH — USB has the exact ISO content. Safe to boot.");
        Ok(())
    } else {
        bail!("✗ DIFFER — burn did not commit to flash");
    }
}

fn disk_write_partitioned_cmd(args: &DiskWritePartitionedArgs) -> Result<()> {
    use std::io::{BufRead, Write};

    // ── 1. Resolve device + safety checks ─────────────────────────
    let dev = match &args.device {
        Some(d) => d.clone(),
        None => detect_usb_device()?,
    };
    println!("Target device: {}", dev);
    if !is_usb_device(&dev)? {
        bail!(
            "{} is NOT a USB-attached disk. Refusing to partition. \
             Pass --device explicitly if you really mean this.",
            dev
        );
    }

    // Build a NARF image first — the partition layout is useless
    // without the kernel + init binaries to populate it with.
    let root = workspace_root().context("locating workspace root")?;
    let target_dir = root.join("target");
    // Pull every artifact from the `cargo xtask image` staging dir —
    // that's where the kernel + initramfs + Limine binaries exist in
    // a known layout, regardless of debug-vs-release and
    // bootloader-path quirks. `xtask image` builds without launching
    // QEMU; `xtask iso-boot` would also produce these (it calls
    // image internally) but it boots the ISO afterwards which we
    // don't want for a disk-burn workflow.
    let stage = target_dir.join("iso-x86_64");
    let kernel = stage.join("boot/narf-frame");
    let initramfs = stage.join("boot/initramfs.cpio");
    let limine_dir = stage.join("boot/limine");
    let bootx64 = stage.join("EFI/BOOT/BOOTX64.EFI");
    for (label, p) in [
        ("kernel", &kernel),
        ("initramfs", &initramfs),
        ("Limine support dir", &limine_dir),
        ("Limine UEFI loader", &bootx64),
    ] {
        if !p.exists() {
            bail!(
                "{} not found at {}; run `cargo xtask image` first to \
                 build the kernel + initramfs + Limine staging",
                label,
                p.display()
            );
        }
    }

    // Host-tool preflight. Names every missing binary up front so
    // we don't ask for sudo, unmount the user's partitions, and
    // then bail halfway through with a confusing "sgdisk not found"
    // io error. `mkfs.ext2`/`mkfs.ext4` depends on which root FS
    // they asked for — only check the one we'll actually invoke.
    let needed: &[(&str, &str)] = &[
        ("sgdisk", "gptfdisk (Arch) / gdisk (Debian, Fedora)"),
        ("partprobe", "parted"),
        ("mkfs.vfat", "dosfstools"),
        (args.root_fs.mkfs_program(), "e2fsprogs"),
        ("lsblk", "util-linux"),
        ("mount", "util-linux"),
        ("umount", "util-linux"),
    ];
    let mut missing: Vec<(&str, &str)> = Vec::new();
    for (bin, pkg) in needed {
        // `command -v` exits 0 iff the binary resolves on PATH; runs
        // in /bin/sh so we don't depend on the user's interactive
        // shell config. Stdout is suppressed since we only care
        // about exit status.
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {} >/dev/null 2>&1", bin)])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !found {
            missing.push((*bin, *pkg));
        }
    }
    if !missing.is_empty() {
        let mut msg = String::from(
            "missing host tools required by disk-write-partitioned:\n",
        );
        for (bin, pkg) in &missing {
            msg.push_str(&format!("  - {bin}  (package: {pkg})\n"));
        }
        msg.push_str("install these and re-run.");
        bail!(msg);
    }

    // ── 2. Confirm ────────────────────────────────────────────────
    let _ = Command::new("lsblk")
        .args(["-o", "NAME,SIZE,MODEL,TRAN,MOUNTPOINTS"])
        .arg(&dev)
        .status();
    println!(
        "Plan: GPT layout on {}",
        dev
    );
    println!("  - ESP (FAT32, {} MiB) — kernel + initramfs + Limine", args.esp_size_mib);
    println!(
        "  - {} ({}, rest of disk, PARTLABEL={})",
        "narf-root",
        args.root_fs.mkfs_program().trim_start_matches("mkfs."),
        args.root_label
    );
    if !args.yes {
        print!("This wipes EVERYTHING on {}. Proceed? [y/N] ", dev);
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            bail!("aborted");
        }
    }

    // ── 3. Unmount + partition ───────────────────────────────────
    // Any partition may have been auto-mounted by udisks; sweep N=1..8.
    for n in 1..=8 {
        let _ = Command::new("sudo")
            .args(["umount", &format!("{}{}", dev, n)])
            .status();
    }

    // sgdisk --zap-all blows away both protective MBR + GPT + backup
    // GPT in one go. sgdisk -n creates partitions; -t sets type GUID
    // (EF00 = ESP, 8300 = Linux filesystem); -c sets PARTLABEL.
    let esp_end = format!("+{}M", args.esp_size_mib);
    let st = Command::new("sudo")
        .args(["sgdisk", "--zap-all", &dev])
        .status()
        .context("sgdisk --zap-all")?;
    if !st.success() {
        bail!("sgdisk --zap-all failed with {st}");
    }
    let st = Command::new("sudo")
        .args([
            "sgdisk",
            "-n", &format!("1:0:{}", esp_end),
            "-t", "1:EF00",
            "-c", "1:ESP",
            "-n", "2:0:0",
            "-t", "2:8300",
            "-c", &format!("2:{}", args.root_label),
            &dev,
        ])
        .status()
        .context("sgdisk partition")?;
    if !st.success() {
        bail!("sgdisk partition failed with {st}");
    }
    // Tell the kernel to re-read the partition table.
    let _ = Command::new("sudo").args(["partprobe", &dev]).status();
    let _ = Command::new("sync").status();

    // Resolve partition device paths. /dev/sda → /dev/sda1 / /dev/sda2;
    // /dev/nvme0n1 → /dev/nvme0n1p1 / /dev/nvme0n1p2.
    let (esp_dev, root_dev) = partition_paths(&dev);
    println!("  ESP:   {}", esp_dev);
    println!("  ROOT:  {}", root_dev);

    // ── 4. mkfs ──────────────────────────────────────────────────
    let st = Command::new("sudo")
        .args(["mkfs.vfat", "-F32", "-n", "ESP", &esp_dev])
        .status()
        .context("mkfs.vfat ESP")?;
    if !st.success() {
        bail!("mkfs.vfat failed with {st}");
    }
    let st = Command::new("sudo")
        .args([
            args.root_fs.mkfs_program(),
            "-F", // force on a partition that just got created
            "-L", &args.root_label,
            &root_dev,
        ])
        .status()
        .context(format!("{} on root", args.root_fs.mkfs_program()))?;
    if !st.success() {
        bail!("root mkfs failed with {st}");
    }

    // ── 5. Mount, populate, unmount ──────────────────────────────
    let mnt_root = target_dir.join("disk-write-partitioned-mnt");
    let mnt_esp = mnt_root.join("esp");
    let mnt_fs = mnt_root.join("root");
    let _ = std::fs::remove_dir_all(&mnt_root);
    std::fs::create_dir_all(&mnt_esp)?;
    std::fs::create_dir_all(&mnt_fs)?;

    let st = Command::new("sudo")
        .args(["mount", &esp_dev, mnt_esp.to_str().unwrap()])
        .status()?;
    if !st.success() {
        bail!("mount ESP failed");
    }
    let st = Command::new("sudo")
        .args(["mount", &root_dev, mnt_fs.to_str().unwrap()])
        .status()?;
    if !st.success() {
        let _ = Command::new("sudo")
            .args(["umount", mnt_esp.to_str().unwrap()])
            .status();
        bail!("mount root failed");
    }

    // ── 5a. Populate the ESP ─────────────────────────────────────
    // Layout:
    //   /EFI/BOOT/BOOTX64.EFI         (Limine UEFI loader)
    //   /boot/narf-frame              (kernel)
    //   /boot/initramfs.cpio          (init/shell CPIO; staged by kernel
    //                                  even with a real root for early
    //                                  fallback if root mount fails)
    //   /boot/limine/                 (Limine support files)
    //   /boot/limine.conf             (cmdline wires root=PARTLABEL=)
    let mk = |sub: &str| -> Result<()> {
        let p = mnt_esp.join(sub);
        let st = Command::new("sudo")
            .args(["mkdir", "-p", p.to_str().unwrap()])
            .status()?;
        if !st.success() {
            bail!("mkdir {} failed", p.display());
        }
        Ok(())
    };
    mk("EFI/BOOT")?;
    mk("boot/limine")?;
    let cp = |src: &Path, dst_rel: &str| -> Result<()> {
        let dst = mnt_esp.join(dst_rel);
        let st = Command::new("sudo")
            .args([
                "cp",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ])
            .status()?;
        if !st.success() {
            bail!("cp {} -> {} failed", src.display(), dst.display());
        }
        Ok(())
    };
    cp(&bootx64, "EFI/BOOT/BOOTX64.EFI")?;
    cp(&kernel, "boot/narf-frame")?;
    cp(&initramfs, "boot/initramfs.cpio")?;
    // Copy Limine support files (BIOS stages, etc).
    let st = Command::new("sudo")
        .args([
            "sh",
            "-c",
            &format!(
                "cp {}/* {}/",
                limine_dir.display(),
                mnt_esp.join("boot/limine").display(),
            ),
        ])
        .status()?;
    if !st.success() {
        eprintln!("warning: Limine support-file copy reported failure (some boot modes may not work)");
    }
    // Limine config — same shape as the ISO's, but with `root=
    // PARTLABEL=<label>` so the kernel's root_selector picks the
    // ext4 partition.
    let limine_conf = format!(
        r#"timeout: 1

/NARF
    protocol: multiboot2
    kernel_path: boot():/boot/narf-frame
    kernel_cmdline: quiet root=PARTLABEL={label}
    module_path: boot():/boot/initramfs.cpio
    module_string: initramfs
"#,
        label = args.root_label,
    );
    write_as_root(&mnt_esp.join("boot/limine.conf"), &limine_conf)?;

    // ── 5b. Populate the root filesystem ─────────────────────────
    // Build init + shell binaries (same as iso-boot does).
    let init_elf = build_user_binary(&root, "userspace/init", "init", "init.ld")?;
    let shell_elf = build_user_binary(&root, "userspace/shell", "shell", "shell.ld")?;
    mk_root_dir(&mnt_fs, "sbin")?;
    mk_root_dir(&mnt_fs, "bin")?;
    cp_root(&init_elf, &mnt_fs.join("sbin/init"))?;
    cp_root(&shell_elf, &mnt_fs.join("bin/sh"))?;

    // ── 6. Unmount + sync ────────────────────────────────────────
    let _ = Command::new("sync").status();
    let st = Command::new("sudo")
        .args(["umount", mnt_esp.to_str().unwrap()])
        .status()?;
    if !st.success() {
        eprintln!("warning: umount ESP returned {st}");
    }
    let st = Command::new("sudo")
        .args(["umount", mnt_fs.to_str().unwrap()])
        .status()?;
    if !st.success() {
        eprintln!("warning: umount root returned {st}");
    }
    let _ = Command::new("sync").status();

    // ── 7. Install Limine BIOS stage for legacy boot ─────────────
    // UEFI works via /EFI/BOOT/BOOTX64.EFI (already copied). Legacy
    // BIOS needs a separate `limine bios-install` to write the
    // bootloader's stage 1 + stage 2 onto the MBR + a reserved
    // sector range. Skipped silently if `limine` isn't on PATH —
    // UEFI-only USBs still boot.
    let st = Command::new("sudo")
        .args(["limine", "bios-install", &dev])
        .status();
    match st {
        Ok(s) if s.success() => println!("Limine BIOS stage installed."),
        Ok(s) => eprintln!("limine bios-install returned {s} — UEFI-only boot will still work"),
        Err(_) => eprintln!("limine binary not on PATH — UEFI-only boot will still work"),
    }

    println!();
    println!("✓ {} is ready. Plug into the target laptop and boot.", dev);
    println!("  Kernel cmdline: root=PARTLABEL={}", args.root_label);
    Ok(())
}

fn partition_paths(dev: &str) -> (String, String) {
    // /dev/sda  → /dev/sda1 + /dev/sda2
    // /dev/nvme0n1 → /dev/nvme0n1p1 + /dev/nvme0n1p2
    // /dev/mmcblk0 → /dev/mmcblk0p1 + /dev/mmcblk0p2
    let needs_p = dev
        .chars()
        .last()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false);
    let sep = if needs_p { "p" } else { "" };
    (format!("{}{}1", dev, sep), format!("{}{}2", dev, sep))
}

fn write_as_root(dst: &Path, contents: &str) -> Result<()> {
    // Write to a temp file the build user owns, then `sudo cp` it
    // into place.
    let tmp = std::env::temp_dir().join(format!(
        "narf-disk-write-{}",
        std::process::id()
    ));
    std::fs::write(&tmp, contents)?;
    let st = Command::new("sudo")
        .args(["cp", tmp.to_str().unwrap(), dst.to_str().unwrap()])
        .status()?;
    let _ = std::fs::remove_file(&tmp);
    if !st.success() {
        bail!("write_as_root({}) failed with {st}", dst.display());
    }
    Ok(())
}

fn mk_root_dir(mnt: &Path, sub: &str) -> Result<()> {
    let p = mnt.join(sub);
    let st = Command::new("sudo")
        .args(["mkdir", "-p", p.to_str().unwrap()])
        .status()?;
    if !st.success() {
        bail!("mkdir {} failed", p.display());
    }
    Ok(())
}

fn cp_root(src: &Path, dst: &Path) -> Result<()> {
    let st = Command::new("sudo")
        .args([
            "cp",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ])
        .status()?;
    if !st.success() {
        bail!("cp {} -> {} failed", src.display(), dst.display());
    }
    Ok(())
}

/// Find the first USB-attached block device by reading lsblk.
fn detect_usb_device() -> Result<String> {
    let out = Command::new("lsblk")
        .args(["-ndo", "NAME,TRAN"])
        .output()
        .context("running lsblk")?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let name = it.next().unwrap_or("");
        let tran = it.next().unwrap_or("");
        if tran == "usb" {
            return Ok(format!("/dev/{}", name));
        }
    }
    bail!("no USB-attached disk found via lsblk")
}

/// Returns true iff `dev` is a USB-attached block device.
fn is_usb_device(dev: &str) -> Result<bool> {
    let name = dev.trim_start_matches("/dev/");
    let out = Command::new("lsblk")
        .args(["-ndo", "TRAN", &format!("/dev/{}", name)])
        .output()
        .context("running lsblk for device check")?;
    let tran = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(tran == "usb")
}

fn sha256_file(p: &Path) -> Result<String> {
    let out = Command::new("sha256sum")
        .arg(p)
        .output()
        .context("sha256sum")?;
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.split_whitespace().next().unwrap_or("").to_string())
}

fn sha256_first_n(dev: &str, n: u64) -> Result<String> {
    // dd to stdout, head -c N, sha256sum.
    let out = Command::new("sh")
        .arg("-c")
        .arg(&format!(
            "sudo dd if={} bs=1M count={} status=none | head -c {} | sha256sum",
            dev,
            (n + 1024 * 1024 - 1) / (1024 * 1024),
            n
        ))
        .output()
        .context("dd | sha256sum")?;
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.split_whitespace().next().unwrap_or("").to_string())
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
        Cmd::Image(mut args) => {
            // Default-on boot-init for parity with `iso-boot`. An
            // image without it boots to the async-demo loop and
            // never spawns /init or /shell, which is almost never
            // what someone running `xtask image` wants — they're
            // building an ISO to actually run.
            //
            // Default-on firmware-allow-unsigned so bring-up blobs
            // packed via `xtask pack-firmware` load. Production
            // signed-key infrastructure isn't wired yet; until it
            // is, the bring-up arc needs unsigned acceptance.
            ensure_feature(&mut args.features, "boot-init");
            ensure_feature(&mut args.features, "firmware-allow-unsigned");
            image_cmd(&args)
        }
        Cmd::IsoBoot(mut args) => {
            // Default-on boot-init so the ISO actually spawns the
            // userspace init + shell tasks; without it the kernel
            // halts at the async-demo exit gate before reaching
            // boot_userspace_init().
            ensure_feature(&mut args.features, "boot-init");
            ensure_feature(&mut args.features, "firmware-allow-unsigned");
            iso_boot_cmd(&args)
        }
        Cmd::DiskWrite(args) => disk_write_cmd(&args),
        Cmd::DiskWritePartitioned(args) => disk_write_partitioned_cmd(&args),
        Cmd::PackFirmware(args) => pack_firmware_cmd(&args),
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
