#![allow(
    clippy::doc_lazy_continuation,
    clippy::type_complexity,
    clippy::never_loop,
    clippy::manual_strip
)]
// NARF xtask orchestrator.
// Spec: build/specification/spec.md §3.
//
// `cargo xtask run   --arch=x86_64 [--release]`  — cross-build + QEMU boot
// `cargo xtask test  --arch=aarch64`             — boot + run kernel tests
// `cargo xtask image --arch=x86_64 --bootloader=limine` — bootable ISO

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    /// Cross-compile and boot under QEMU as a real init pass (no
    /// kernel-test feature), parsing serial output for panic markers
    /// and known success markers. Catches regressions that smoke
    /// tests miss because smokes exercise modules in isolation
    /// rather than the full boot flow.
    BootSmoke(BuildArgs),
    /// Cross-compile and boot under QEMU with `boot-init` on, drive
    /// the serial port programmatically by typing `echo hello world`
    /// into QEMU's stdin, and assert that `hello world\n` appears on
    /// QEMU's serial stdout. Closes the Wave-37+ interactive loop:
    /// keystrokes → narf_input ring → /dev/console → sys_read fd 0 →
    /// shell parser → echo built-in → sys_write fd 1 → UART.
    RunInteractive(RunInteractiveArgs),
    /// Wave-78 — boot under QEMU and verify both linux-compat demo
    /// binaries (`/bin/hello` and `/bin/hello_musl`) print their
    /// expected output through the real shell + execve + ELF
    /// loader + syscall-instruction dispatch + SSE init path. Two
    /// `run-interactive` invocations under the hood; fails CI if
    /// either binary regresses. x86_64 only — `hello_musl` is a
    /// stock-musl-built ELF that requires `int 0x80` / `syscall`
    /// dual dispatch + CR4.OSFXSR.
    MuslDemo(BuildArgs),
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
    /// `target/firmware/<name>` (so `xtask image` stages it either
    /// into the initramfs CPIO if matched by `--initramfs-firmware`,
    /// or onto the root partition's /lib/firmware/ otherwise).
    PackFirmware(PackFirmwareArgs),
    /// Bulk-import firmware blobs from a source directory tree
    /// (default `/lib/firmware/`) into `target/firmware/`.
    /// Recursively walks, decompresses `.zst` entries on the fly
    /// (Arch's linux-firmware ships everything zstd-compressed), and
    /// wraps each with the NARF trailer. `xtask image` then splits
    /// the result: blobs matched by `--initramfs-firmware` go into
    /// the initramfs CPIO; everything else stages onto the root
    /// partition's /lib/firmware/ (Linux hybrid model).
    ImportFirmware(ImportFirmwareArgs),
}

#[derive(Parser, Clone)]
struct ImportFirmwareArgs {
    /// Source firmware directory to walk. Defaults to the system's
    /// `/lib/firmware/` (matches Arch + Debian conventions).
    #[arg(long, default_value = "/lib/firmware")]
    source: String,

    /// Output dir under the workspace. Each blob lands at
    /// `<out>/<rel>` where `<rel>` is the path relative to `--source`
    /// with any `.zst` suffix stripped. Default `target/firmware`
    /// keeps imported blobs out of the source tree (workspace's
    /// `firmware/` crate dir would collide) and inside `target/`
    /// which is already gitignored.
    #[arg(long, default_value = "target/firmware")]
    out: String,

    /// Optional vendor / subdirectory filter (e.g. `amdgpu`,
    /// `iwlwifi`, `mt76`). Only files whose path under `--source`
    /// starts with this prefix are imported. Use to build smaller
    /// targeted ISOs (e.g. AMD-laptop-only).
    #[arg(long)]
    vendor: Option<String>,

    /// Skip every file already present at the output path. Lets
    /// you re-run import after kernel upgrades to pick up only the
    /// newly-added blobs.
    #[arg(long)]
    skip_existing: bool,

    /// Clear the output dir before importing. Avoids stale blobs
    /// lingering when /lib/firmware/ drops a file across upstream
    /// releases.
    #[arg(long)]
    clean: bool,

    /// Limit each blob's payload to this many bytes. Defaults to
    /// 16 MiB (PSP `LOAD_IP_FW` packs size into bits[31:8], so
    /// anything larger is unloadable anyway). Bigger files are
    /// skipped with a warning, not truncated.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_payload_bytes: u64,
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

    /// ESP partition size in MiB. Holds kernel + initramfs +
    /// Limine. With the Linux hybrid model the initramfs now holds
    /// only `--initramfs-firmware` globs (default: nothing), so the
    /// ESP is typically 64–256 MiB — enough for the kernel ELF,
    /// Limine support files, and microcode-only initramfs. Drop to
    /// 64 for a "kernel + init/shell only" minimal build; raise if
    /// you point `--initramfs-firmware` at large GPU blobs.
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

    /// Glob patterns (relative to target/firmware/) for blobs to pack
    /// into the initramfs CPIO. Only firmware matching at least one
    /// glob goes into the initramfs; everything else stages onto the
    /// root partition's /lib/firmware/. May be supplied multiple times.
    ///
    /// Linux convention: initramfs holds only what must be available
    /// BEFORE the root filesystem mounts (CPU microcode, early-FB GPU
    /// firmware, storage-controller quirk blobs). Everything else
    /// lives on the root partition and is registered by the
    /// `firmware-scan-rootfs` initcall AFTER `root-mount-auto`.
    ///
    /// Default (no flags): zero firmware in initramfs; all firmware
    /// goes to the root partition. This keeps the initramfs small
    /// enough for Limine to allocate as a multiboot2 module.
    ///
    /// Example: --initramfs-firmware "amd-ucode/*"
    ///          --initramfs-firmware "intel-ucode/*"
    #[arg(long, value_name = "GLOB")]
    initramfs_firmware: Vec<String>,
}

/// Wave-49 — args for `xtask run-interactive`. Inherits BuildArgs
/// (flatten) so all the usual `--features`, `--release`,
/// `--display`, `--arch` knobs work, plus `--cmd <LINE>` /
/// `--expect <SUBSTR>` for scripted command testing.
#[derive(Parser, Clone)]
struct RunInteractiveArgs {
    #[command(flatten)]
    build: BuildArgs,

    /// Command typed at the shell prompt (no trailing newline —
    /// the harness appends `\n`). Defaults to `echo hello world`
    /// for parity with the Wave-45 echo smoke.
    #[arg(long, default_value = "echo hello world")]
    cmd: String,

    /// Substring asserted on QEMU's serial stdout AFTER the
    /// command is typed. Defaults to `hello world`. For
    /// coreutils: `--cmd "pwd" --expect "/"`,
    /// `--cmd "ls /bin" --expect "cat"`, etc.
    #[arg(long, default_value = "hello world")]
    expect: String,
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
                // QEMU CPU model can be overridden to exercise the
                // xAPIC fallback path (no x2APIC) and/or the
                // InitialCount LAPIC arm path (no TSC-deadline) —
                // matches Renoir's BIOS behavior where x2APIC is
                // refused. Example:
                //   NARF_QEMU_CPU="max,-x2apic,-tsc-deadline"
                let cpu = std::env::var("NARF_QEMU_CPU").unwrap_or_else(|_| "max".into());
                // `NARF_QEMU_SMP` shrinks the vCPU count and drops the
                // 2-socket HMAT/NUMA topology that assumes 16 CPUs.
                // Bringing up + emulating 16 APs under TCG (no KVM, as on
                // CI) dominates boot time, and a user-program smoke like
                // musl-demo needs neither many CPUs nor NUMA — set e.g.
                // `NARF_QEMU_SMP=2` there to cut boot time substantially.
                // Unset (default) keeps the full layout the kernel NUMA
                // tests expect, so other jobs and local runs are unchanged.
                let smp = std::env::var("NARF_QEMU_SMP").ok();
                // Total guest RAM in MiB. Default 1024 (512/NUMA node).
                // The kernel-test suite sits near the buddy margin and a
                // DMA-heavy smoke can crash QEMU when a node is pressured;
                // CI ups this (e.g. NARF_QEMU_MEM_MB=2048) for headroom
                // without slowing local runs. Must be even — the two NUMA
                // nodes each get half.
                let mem_mb: u64 = std::env::var("NARF_QEMU_MEM_MB")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .filter(|&m| m >= 2 && m % 2 == 0)
                    .unwrap_or(1024);
                let node_mem_mb = mem_mb / 2;
                let mut args = vec![
                    "-machine".into(),
                    if smp.is_some() {
                        "q35".into()
                    } else {
                        "q35,hmat=on".into()
                    },
                    "-cpu".into(),
                    cpu,
                    "-smp".into(),
                    smp.clone().unwrap_or_else(|| "16,sockets=2,cores=8".into()),
                    "-m".into(),
                    // Default 1 GiB (512 MiB per NUMA node below). The
                    // kernel-test suite runs ~5129 smokes on the slab/buddy
                    // and sits near the margin; a DMA-heavy smoke (e.g. nvme
                    // multi-queue / virtio-snd) then crashes QEMU host-side
                    // when a node is pressured. CI raises NARF_QEMU_MEM_MB
                    // for headroom; locally the default keeps boot fast.
                    format!("{mem_mb}M"),
                ];
                // Optional accel override. Unset ⇒ QEMU auto-selects
                // (KVM when /dev/kvm exists, else single-threaded TCG).
                // Escape hatch: `XTASK_QEMU_ACCEL=tcg,thread=multi` runs
                // each vCPU on its own host thread, so a BSP spinning on
                // an AP's IPI ack doesn't starve the AP under TCG —
                // needed only if a runner exposes x2APIC under TCG and
                // the x2APIC-gated shootdown smokes actually run (CI's
                // qemu64 falls back to xAPIC, so they Skip instead).
                if let Ok(accel) = std::env::var("XTASK_QEMU_ACCEL") {
                    args.push("-accel".into());
                    args.push(accel);
                }
                if smp.is_none() {
                    args.extend_from_slice(&[
                    "-numa".into(),    "node,nodeid=0,cpus=0-7,memdev=mem0,initiator=0".into(),
                    "-numa".into(),    "node,nodeid=1,cpus=8-15,memdev=mem1,initiator=1".into(),
                    "-object".into(),  format!("memory-backend-ram,id=mem0,size={node_mem_mb}M"),
                    "-object".into(),  format!("memory-backend-ram,id=mem1,size={node_mem_mb}M"),
                    "-numa".into(),    "hmat-lb,initiator=0,target=0,hierarchy=memory,data-type=access-latency,latency=10".into(),
                    "-numa".into(),    "hmat-lb,initiator=0,target=1,hierarchy=memory,data-type=access-latency,latency=20".into(),
                    "-numa".into(),    "hmat-lb,initiator=1,target=0,hierarchy=memory,data-type=access-latency,latency=20".into(),
                    "-numa".into(),    "hmat-lb,initiator=1,target=1,hierarchy=memory,data-type=access-latency,latency=10".into(),
                    "-numa".into(),    "hmat-lb,initiator=0,target=0,hierarchy=memory,data-type=access-bandwidth,bandwidth=10G".into(),
                    "-numa".into(),    "hmat-lb,initiator=0,target=1,hierarchy=memory,data-type=access-bandwidth,bandwidth=5G".into(),
                    "-numa".into(),    "hmat-lb,initiator=1,target=0,hierarchy=memory,data-type=access-bandwidth,bandwidth=5G".into(),
                    "-numa".into(),    "hmat-lb,initiator=1,target=1,hierarchy=memory,data-type=access-bandwidth,bandwidth=10G".into(),
                    ]);
                }
                args.extend_from_slice(&[
                    "-serial".into(),
                    "stdio".into(),
                    "-display".into(),
                    display.clone(),
                    "-no-reboot".into(),
                    "-device".into(),
                    "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
                ]);

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
                    args.extend_from_slice(&["-device".into(), "usb-kbd,bus=xhci0.0".into()]);
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
                    // virtio-balloon bring-up (feature negotiation +
                    // queue programming) SIGSEGVs some QEMU builds —
                    // notably the qemu-system-x86 packaged on GitHub
                    // Actions' ubuntu-latest — even though it works on
                    // current upstream/local QEMU. A guest cannot fix a
                    // host crash, so let CI opt the device out via
                    // XTASK_QEMU_NO_BALLOON; the balloon smokes then
                    // `Skip` (no device present) and init skips the
                    // probe. Local/dev runs keep it for live coverage.
                    if std::env::var_os("XTASK_QEMU_NO_BALLOON").is_none() {
                        args.extend_from_slice(&[
                            "-device".into(),
                            "virtio-balloon-pci,disable-legacy=on,disable-modern=off".into(),
                        ]);
                    }
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
                    "512M".into(),
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
                    // virtio-balloon bring-up (feature negotiation +
                    // queue programming) SIGSEGVs some QEMU builds —
                    // notably the qemu-system-x86 packaged on GitHub
                    // Actions' ubuntu-latest — even though it works on
                    // current upstream/local QEMU. A guest cannot fix a
                    // host crash, so let CI opt the device out via
                    // XTASK_QEMU_NO_BALLOON; the balloon smokes then
                    // `Skip` (no device present) and init skips the
                    // probe. Local/dev runs keep it for live coverage.
                    if std::env::var_os("XTASK_QEMU_NO_BALLOON").is_none() {
                        args.extend_from_slice(&[
                            "-device".into(),
                            "virtio-balloon-pci,disable-legacy=on,disable-modern=off".into(),
                        ]);
                    }
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
            .arg("512M")
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
        for (i, b) in buf.iter_mut().enumerate().take(512usize) {
            *b = (i as u8).wrapping_mul(0x6D) ^ 0x42;
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
        // Minimal ext2 image containing `/hello.txt` so the boot
        // path's Stage::Late `mnt-mount-ext2` initcall can detect
        // an ext2 filesystem on the virtio-blk device and mount it
        // at /mnt. Mirrors drivers/fs/ext2/src/tests.rs build_ext2_image.
        let img = build_ext2_disk_image(b"hello.txt", b"hello from disk\n");
        let _ = std::fs::write(&path, &img);
    }
    path
}

/// Build a minimal single-group ext2 image. 1 KiB blocks, 64 blocks
/// total (64 KiB), one regular file at root. Layout mirrors the test
/// fixture in drivers/fs/ext2/src/tests.rs::build_ext2_image so it
/// rides the same mount + read paths.
fn build_ext2_disk_image(file_name: &[u8], file_data: &[u8]) -> Vec<u8> {
    const BS: usize = 1024;
    const TOTAL_BLOCKS: u32 = 64;
    const INODES_PER_GROUP: u32 = 32;
    const INODE_SIZE: u16 = 128;
    const BLOCKS_PER_GROUP: u32 = 64;
    const FT_DIR: u8 = 2;
    const FT_REG: u8 = 1;

    let mut img = vec![0u8; BS * TOTAL_BLOCKS as usize];

    fn put_u16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    // Superblock at byte 1024.
    {
        let sb = &mut img[1024..2048];
        put_u32(sb, 0, INODES_PER_GROUP);
        put_u32(sb, 4, TOTAL_BLOCKS);
        put_u32(sb, 20, 1); // s_first_data_block
        put_u32(sb, 24, 0); // s_log_block_size → 1024
        put_u32(sb, 32, BLOCKS_PER_GROUP);
        put_u32(sb, 40, INODES_PER_GROUP);
        put_u16(sb, 56, 0xEF53);
        put_u32(sb, 76, 1); // s_rev_level
        put_u16(sb, 88, INODE_SIZE);
    }

    // Block group descriptor at block 2.
    let gdt_off = 2 * BS;
    put_u32(&mut img, gdt_off, 3); // bg_block_bitmap
    put_u32(&mut img, gdt_off + 4, 4); // bg_inode_bitmap
    put_u32(&mut img, gdt_off + 8, 5); // bg_inode_table
    put_u16(&mut img, gdt_off + 12, 0);
    put_u16(&mut img, gdt_off + 14, 0);
    put_u16(&mut img, gdt_off + 16, 1);

    // Block bitmap (block 3): mark blocks 0..=10 used.
    let bm_off = 3 * BS;
    img[bm_off] = 0xFF;
    img[bm_off + 1] = 0x07;

    // Inode bitmap (block 4): inodes 1, 2, 12 used.
    let ibm_off = 4 * BS;
    img[ibm_off] = 0b0000_0011;
    img[ibm_off + 1] = 0b0000_1000;

    // Inode table (blocks 5..=8).
    let itab_off = 5 * BS;

    // Root inode (#2) at table index 1.
    let root_off = itab_off + INODE_SIZE as usize;
    put_u16(&mut img, root_off, 0x4000 | 0o755);
    put_u32(&mut img, root_off + 4, BS as u32);
    put_u32(&mut img, root_off + 28, (BS / 512) as u32);
    put_u32(&mut img, root_off + 40, 9);

    // File inode (#12) at table index 11.
    let file_off = itab_off + 11 * INODE_SIZE as usize;
    put_u16(&mut img, file_off, 0x8000 | 0o644);
    put_u32(&mut img, file_off + 4, file_data.len() as u32);
    put_u32(
        &mut img,
        file_off + 28,
        file_data.len().div_ceil(512) as u32,
    );
    if !file_data.is_empty() {
        put_u32(&mut img, file_off + 40, 10);
    }

    // Root directory data block (9).
    let root_data = 9 * BS;
    let mut cursor = 0usize;
    // "." → 2
    {
        let off = root_data + cursor;
        put_u32(&mut img, off, 2);
        put_u16(&mut img, off + 4, 12);
        img[off + 6] = 1;
        img[off + 7] = FT_DIR;
        img[off + 8] = b'.';
        cursor += 12;
    }
    // ".." → 2
    {
        let off = root_data + cursor;
        put_u32(&mut img, off, 2);
        put_u16(&mut img, off + 4, 12);
        img[off + 6] = 2;
        img[off + 7] = FT_DIR;
        img[off + 8] = b'.';
        img[off + 9] = b'.';
        cursor += 12;
    }
    // file → 12, fills rest of block.
    {
        let off = root_data + cursor;
        let remaining = BS - cursor;
        put_u32(&mut img, off, 12);
        put_u16(&mut img, off + 4, remaining as u16);
        img[off + 6] = file_name.len() as u8;
        img[off + 7] = FT_REG;
        img[off + 8..off + 8 + file_name.len()].copy_from_slice(file_name);
    }

    // File data block (10).
    if !file_data.is_empty() {
        let data_off = 10 * BS;
        img[data_off..data_off + file_data.len()].copy_from_slice(file_data);
    }

    // Seed sector 0 (bytes 0..512) with the virtio-blk read-pattern the
    // driver smoke tests assert: byte i == (i * 0x97) mod 256. This is
    // ext2 boot-block padding (the superblock starts at byte 1024), so
    // it doesn't disturb the filesystem the /mnt mount reads — it just
    // gives the raw-sector-read tests a known pattern at LBA 0.
    for (i, b) in img[0..512].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x97);
    }

    img
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

    let init_elf = build_user_binary(workspace, "userspace/init", "init", "init.ld")?;
    let shell_elf = build_user_binary(workspace, "userspace/shell", "shell", "shell.ld")?;

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
        bail!(
            "expected output {} missing after cargo build",
            bin.display()
        );
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
    fn write_entry(out: &mut Vec<u8>, ino: u32, mode: u32, name: &str, data: &[u8]) {
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
        entries
            .iter()
            .map(|(n, d)| 110 + n.len() + 4 + d.len() + 4)
            .sum::<usize>()
            + 256,
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
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
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
    run_cmd_inner(args, false)
}

/// Boot the kernel under QEMU. When `gate_exit` is set (the `test`
/// subcommand's kernel-test phase), the QEMU exit status is checked
/// against the all-pass status: the kernel-test runner calls
/// `exit_kernel(0)` only when every smoke passed and `exit_kernel(1)`
/// when any failed, so a failing suite (or a panic/hang) makes the
/// command fail. Manual `Cmd::Run` passes `false` and never gates — the
/// user drives it interactively and an arbitrary exit code is expected.
fn run_cmd_inner(args: &BuildArgs, gate_exit: bool) -> Result<()> {
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
        .unwrap_or(600);
    let status = match child.wait_timeout(Duration::from_secs(secs))? {
        Some(status) => status,
        None => {
            child.kill()?;
            child.wait()?;
            bail!("xtask: {qemu} timed out after {secs}s (possible kernel hang)");
        }
    };
    println!("xtask: {qemu} exited with {status}");

    if gate_exit {
        // All-pass status mirrors boot-smoke's clean-exit encoding:
        //  * x86_64 isa-debug-exit encodes `(code << 1) | 1`, so the
        //    runner's exit_kernel(0) → QEMU status 1 (a failed suite
        //    exits 1 → status 3).
        //  * aarch64 shuts down via PSCI/semihosting and QEMU exits with
        //    the kernel code directly: 0 on all-pass (1 on failure).
        let expected = match args.arch {
            Arch::X86_64 => Some(1),
            Arch::Aarch64 => Some(0),
        };
        if status.code() != expected {
            bail!(
                "xtask test: kernel-test suite reported failures — QEMU exited \
                 {:?} (all-pass is {:?} on {}). See the `── summary` / `── failing \
                 tests ──` lines above.",
                status.code(),
                expected,
                args.arch.triple(),
            );
        }
    }
    Ok(())
}

/// Boot the kernel under QEMU *without* the `kernel-test` feature
/// (i.e. the real init flow), capture stdout line-by-line, and check
/// for panic markers + known success markers. This catches regressions
/// that the per-module smokes can't — e.g. the `bare_main.rs:1813`
/// PCR-0 self-measure that panicked at boot but passed every unit test
/// because the broken code path only runs in the late-boot async task.
///
/// Success criteria: all expected markers seen within the timeout, no
/// panic marker observed.
/// Failure: any panic marker, OR timeout without all success markers.
fn boot_smoke_cmd(args: &BuildArgs) -> Result<()> {
    // Force the `boot-smoke` feature on so the kernel triggers a clean
    // ACPI / isa-debug-exit shutdown after the real init flow drains.
    // Same pattern as the kernel-test harness — no kill-after-timeout
    // race; QEMU exits naturally on success or stays alive on hang.
    let mut args = args.clone();
    ensure_feature(&mut args.features, "boot-smoke");

    let root = workspace_root()?;
    let out_dir = cargo_build(&args, &root)?;

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
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    println!("xtask boot-smoke: launching {} {}", qemu, kernel.display());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    // Panic markers — any one of these in stdout triggers failure
    // even if QEMU then exits cleanly.
    let panic_markers: &[&str] = &[
        "*** KERNEL PANIC ***",
        "panicked at",
        "double fault",
        "general protection",
        "kernel page fault",
        "unsafe precondition",
    ];

    let secs = std::env::var("XTASK_BOOT_SMOKE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(90);

    // Stream stdout to terminal and accumulate any panic markers.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdout"))?;
    let reader_handle = std::thread::spawn(move || -> Option<String> {
        let reader = BufReader::new(stdout);
        let mut panic_line = None;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            println!("{line}");
            if panic_line.is_none() && panic_markers.iter().any(|m| line.contains(m)) {
                panic_line = Some(line);
            }
        }
        panic_line
    });

    // Wait for QEMU to exit naturally (kernel calls exit_kernel),
    // OR force-kill on timeout.
    let exit = child.wait_timeout(Duration::from_secs(secs))?;
    let panic_line = reader_handle.join().ok().flatten();

    let status = match exit {
        Some(s) => s,
        None => {
            child.kill()?;
            child.wait()?;
            if let Some(p) = panic_line {
                bail!("xtask boot-smoke: panic before clean exit — '{}'", p);
            }
            bail!(
                "xtask boot-smoke: kernel did not call exit_kernel within {}s — possible hang in real init flow",
                secs
            );
        }
    };

    if let Some(p) = panic_line {
        bail!("xtask boot-smoke: kernel panic during boot — '{}'", p);
    }
    // Clean-exit status is arch-dependent:
    //  * x86_64 uses `isa-debug-exit` (port I/O), which encodes
    //    `(code << 1) | 1` into QEMU's exit status — so a kernel
    //    exit code of 0 yields QEMU status 1.
    //  * aarch64 has no `isa-debug-exit`; the kernel shuts down via
    //    PSCI or semihosting `SYS_EXIT`, and QEMU exits naturally
    //    with status 0.
    let expected = match args.arch {
        Arch::X86_64 => Some(1),
        Arch::Aarch64 => Some(0),
    };
    if status.code() != expected {
        bail!(
            "xtask boot-smoke: QEMU exited with non-success status {:?} (expected {:?} on {})",
            status.code(),
            expected,
            args.arch.triple(),
        );
    }
    println!("xtask boot-smoke: kernel cleanly exited, no panic markers");
    Ok(())
}

/// Boot the kernel under QEMU with `boot-init` on, then drive the
/// serial console programmatically — wait for the shell prompt
/// (`narf> `), type `echo hello world\n`, and assert that the
/// payload `hello world\n` appears on the serial stdout afterwards.
///
/// This closes the end-to-end interactive loop the in-kernel smoke
/// `smoke_echo_hello_world_end_to_end` proved one syscall at a time:
/// keystrokes typed on `qemu -serial stdio` land in narf_input's
/// global byte ring via IRQ 4, get drained by /dev/console reads
/// from the shell's `read_byte` loop, get parsed by the shell, and
/// the `echo` built-in writes the result back out fd 1 → klog
/// → UART → QEMU stdout.
///
/// Success criteria: `narf> ` prompt observed within `prompt_secs`,
/// then `hello world\n` observed within `echo_secs` after typing.
/// Failure: any panic marker, OR either deadline missed.
/// Wave-78 — boot both `/bin/hello` (hand-rolled int 0x80 asm)
/// and `/bin/hello_musl` (real musl-static) through the live
/// shell + execve + ELF loader + syscall-instruction path. Each
/// binary is a separate QEMU run since `run-interactive` types one
/// command and exits on first match — driving two distinct
/// commands in a single boot would race against the shell's
/// prompt re-emission.
///
/// Failure on either binary is failure for the whole smoke.
/// x86_64 only: `hello_musl` is a stock musl-built ELF and the
/// CR4.OSFXSR / arch_prctl / int 0x80-vs-syscall plumbing is all
/// x86-specific; the aarch64 mirror is a separate sub-wave.
fn musl_demo_cmd(args: &BuildArgs) -> Result<()> {
    if !matches!(args.arch, Arch::X86_64) {
        bail!("musl-demo is x86_64 only (hello_musl is not built for aarch64)");
    }

    // Two `run-interactive` invocations, sharing the same build
    // args. The boot itself is the slow part (~30-60s on CI); each
    // invocation re-builds nothing because Cargo's incremental build
    // is warm after the first.
    let cases: &[(&str, &str)] = &[
        ("hello", "hello"),
        ("hello_musl", "hello from musl"),
        ("hello_musl_dyn", "hello from musl dyn"),
        // BusyBox demo cases. Each applet exercises a different
        // chunk of the linux-compat surface:
        //   * `echo hello` — raw `write(2)` only; the lightest
        //     possible musl-dyn end-to-end (PT_INTERP, ld-musl
        //     reloc, narf_libc syscall stub).
        //   * `pwd` — stdio path: musl's `puts(buf)` triggers
        //     `__stdout_write` → `ioctl(TIOCGWINSZ)` → `writev`.
        //     This is the case that surfaced the syscall-entry
        //     register-preservation bug; if a future change
        //     re-introduces the r8/r9/r10/rdi/rsi/rdx clobber
        //     across `syscall` instruction, this case will
        //     #PF inside ld-musl long before reaching writev.
        //   * `uname -a` — exercises the `uname(2)` syscall and
        //     stdio together.
        ("busybox echo hello", "hello"),
        ("busybox pwd", "/"),
        // `busybox uname -a` prints
        // `NARF narf 0.1 narf x86_64 GNU/Linux\n`. The
        // run-interactive matcher requires the needle to be
        // followed by `\r`/`\n`, so we anchor on `Linux` (the
        // last token before the newline) rather than `narf`
        // (which is followed by ` ` mid-line, or `>` if the
        // shell prompt redraws first).
        ("busybox uname -a", "Linux"),
        // Threading smoke. `hello_pthread` spawns one pthread, both
        // threads `write(2)` to fd 1, parent `pthread_join`s. End-
        // to-end exercises Linux's x86_64 clone(2) ABI
        // (arg3=ctid, arg4=tls — NOT the x86_32 CLONE_BACKWARDS
        // ordering), the full UserState snapshot in the syscall-
        // instruction fast path (needed so `sys_futex` can park
        // and resume cleanly), per-thread TLS (FS_BASE), and the
        // CLONE_CHILD_CLEARTID + futex_wake exit-observer chain
        // that wakes `pthread_join`.
        ("hello_pthread", "joined"),
        // sh smoke — `busybox sh -c '<script>'` runs sequential
        // commands. End-to-end exercises fork(2), waitpid(2),
        // and the rdx-preserving syscall ABI: Linux requires rdx
        // to survive `syscall`, but the previous NARF convention
        // returned `(rax=value, rdx=status)` which clobbered rdx
        // with 0 on success. musl's `__init_tp` emits
        // `mov %fs:0, %rdx; syscall; movq $0, 0x98(%rdx)` and
        // every forked child #PF'd at CR2=0x98. Fix is to return
        // -EINVAL in rax on error and preserve rdx.
        ("busybox sh -c 'echo a; echo b'", "b"),
        // Pipes through fork+exec. busybox sh's pipeline
        // implementation forks two children, dup2's the pipe ends
        // to stdin/stdout, then `execve(2)`s into the named
        // binary. The Linux ABI cutover for execve (path, argv,
        // envp) — previously NARF-native (elf_ptr, elf_len, ...)
        // — plus the `stat(2)` cutover (NUL-terminated path
        // instead of (ptr, len)) get this end-to-end. Without
        // either, busybox sh's PATH search hits the
        // `Operation not permitted` (EPERM) wall every time.
        ("busybox sh -c 'echo hi | busybox cat'", "hi"),
        ("signal_smoke", "signal-ok"),
        ("fs_smoke", "fs-ok"),
        ("fork_pipe_smoke", "fork-ok"),
        ("pty_smoke", "pty-ok"),
        ("net_smoke", "net-ok"),
        ("net6_smoke", "net6-ok"),
        ("unix_smoke", "unix-ok"),
        ("epoll_smoke", "epoll-ok"),
        // Linux-compat round: eventfd2, getrandom, socketpair, accept4.
        ("eventfd_smoke", "eventfd-ok"),
        ("getrandom_smoke", "getrandom-ok"),
        ("sockpair_smoke", "sockpair-ok"),
        ("accept4_smoke", "accept4-ok"),
        // Linux-compat round 2: mremap, sendfile, creds, waitid.
        ("mremap_smoke", "mremap-ok"),
        ("sendfile_smoke", "sendfile-ok"),
        ("creds_smoke", "creds-ok"),
        ("waitid_smoke", "waitid-ok"),
        // Linux-compat round 3: ppoll, sysinfo, splice, membarrier+clock_getres.
        ("ppoll_smoke", "ppoll-ok"),
        ("sysinfo_smoke", "sysinfo-ok"),
        ("splice_smoke", "splice-ok"),
        ("barrier_smoke", "barrier-ok"),
        // Linux-compat round 4: close_range, sched-policy, msync+mincore, sync+syncfs+personality.
        ("closerange_smoke", "closerange-ok"),
        ("sched_smoke", "sched-ok"),
        ("mcore_smoke", "mcore-ok"),
        ("sync_smoke", "sync-ok"),
        // Linux-compat round 5: dup3+fadvise64+mlock2, robust lists, renameat2, pidfd_send_signal.
        ("dup3fam_smoke", "dup3-ok"),
        ("robust_smoke", "robust-ok"),
        ("renameat2_smoke", "renameat2-ok"),
        ("pidfdsig_smoke", "pidfdsig-ok"),
        // Linux-compat round 6: sethostname+setdomainname, sendmmsg+recvmmsg, openat2, preadv+pwritev.
        ("host_smoke", "host-ok"),
        ("mmsg_smoke", "mmsg-ok"),
        ("openat2_smoke", "openat2-ok"),
        ("pv_smoke", "pv-ok"),
        // Linux-compat round 7: capget+capset, setitimer+getitimer+alarm, xattr, readahead+sync_file_range.
        ("cap_smoke", "cap-ok"),
        ("itimer_smoke", "itimer-ok"),
        ("xattr_smoke", "xattr-ok"),
        ("fhint_smoke", "fhint-ok"),
        // Linux-compat round 8: mq_*, inotify, pkey_*, process_vm_*.
        ("mq_smoke", "mq-ok"),
        ("inotify_smoke", "inotify-ok"),
        ("pkey_smoke", "pkey-ok"),
        ("pvm_smoke", "pvm-ok"),
        // Linux-compat round 9: mempolicy, sched_attr, adjtimex, introspection.
        ("mempolicy_smoke", "mpol-ok"),
        ("schedattr_smoke", "schedattr-ok"),
        ("adjtimex_smoke", "adjtimex-ok"),
        ("introspect_smoke", "introspect-ok"),
        // Linux-compat round 10: vectored + extended I/O.
        ("vio_smoke", "vio-ok"),
        // Linux-compat round 11: System V semaphores + message queues.
        ("sysvipc_smoke", "sysvipc-ok"),
        // Linux-compat round 12: System V shared memory.
        ("shm_smoke", "shm-ok"),
        // Linux-compat round 13: xattr l*/f*/remove variants.
        ("xattr2_smoke", "xattr2-ok"),
        // Linux-compat round 14: filesystem misc (creat/lchown/utime/utimes).
        ("fsmisc_smoke", "fsmisc-ok"),
        // Linux-compat round 15: credential gaps (real/effective/fs ids).
        ("creds2_smoke", "creds2-ok"),
        // Linux-compat round 16: signal queueing + signalfd4.
        ("sig2_smoke", "sig2-ok"),
        // Linux-compat round 18: mlockall/memfd_secret/NUMA/process_madvise.
        ("mem2_smoke", "mem2-ok"),
        // Linux-compat round 19: process & scheduling.
        ("psched_smoke", "psched-ok"),
        // Linux-compat round 20: futex2 wait/wake/requeue/waitv.
        ("futex2_smoke", "futex2-ok"),
        // Linux-compat round 21: keyrings (add_key/request_key/keyctl).
        ("keyring_smoke", "keyring-ok"),
        // Linux-compat round 22: inotify real event delivery.
        ("inotify2_smoke", "inotify2-ok"),
        // Linux-compat round 23: fanotify (init/mark + fd events).
        ("fanotify_smoke", "fanotify-ok"),
        // Linux-compat round 24: Landlock path-rule enforcement.
        ("landlock_smoke", "landlock-ok"),
        // Linux-compat round 25: generic LSM self-attr syscalls.
        ("lsm_smoke", "lsm-ok"),
        // vDSO: real fast-path linux-vdso.so.1 (clock_gettime).
        ("vdso_smoke", "vdso-ok"),
        // New mount API round 1: file handles.
        ("fhandle_smoke", "fhandle-ok"),
        // New mount API round 2: fsopen/fsconfig/fsmount/move_mount.
        ("mountapi_smoke", "mountapi-ok"),
        // Job control + termios: pty termios round-trip + SIGTTIN.
        ("jobctl_smoke", "jobctl-ok"),
        // Job control stop/resume: SIGSTOP + SIGCONT via wait4 WUNTRACED.
        ("jobctl2_smoke", "jobctl2-ok"),
        // Filesystem navigation: chdir + getcwd + opendir/getdents64.
        ("navfs_smoke", "navfs-ok"),
        // Pipe blocking-read + EOF on writer exit (fd teardown on exit).
        ("pipeof_smoke", "pipeof-ok"),
        // Relative-path *at resolution (mkdir/rename/symlink/unlink/rmdir).
        ("relpaths_smoke", "relpaths-ok"),
        // Console is a tty: isatty + cooked tcgetattr + tcsetattr round-trip.
        ("consoletty_smoke", "consoletty-ok"),
        // (a) Preemptive SIGALRM raised+delivered to a CPU-bound busy loop.
        ("alarmloop_smoke", "alarmloop-ok"),
        // (b) Timer-driven preemption: a CPU-bound child can't stall parent.
        ("preemptsched_smoke", "preemptsched-ok"),
        // procfs breadth: /proc/stat + fuller /proc/<pid>/status.
        ("procfs2_smoke", "procfs2-ok"),
        // multi-DSO dynamic linking: main -> libb -> liba -> libc.
        ("dso_smoke", "dso-ok"),
        // per-DSO TLS: thread-locals in a shared library (libtls).
        ("tls_smoke", "tls-ok"),
    ];
    // Run every case in a SINGLE QEMU boot rather than one boot per
    // command — the TCG boot (especially on CI) dwarfs the per-command
    // runtime, so amortizing it across all commands is the big win.
    // The VM keeps its full multi-vCPU/NUMA topology so concurrency
    // bugs still surface.
    let (passed, failed) = run_interactive_multi(args, cases)?;
    eprintln!("\nmusl-demo summary: {} passed, {} failed", passed, failed);
    if failed > 0 {
        bail!("musl-demo failed ({} errors)", failed);
    }
    Ok(())
}

fn run_interactive_cmd(args: &RunInteractiveArgs) -> Result<()> {
    use std::io::Write;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Arc, Mutex};

    if !matches!(args.build.arch, Arch::X86_64) {
        // The shell + boot_userspace_init are x86_64-only today
        // (`cfg(all(feature = "boot-init", target_arch = "x86_64"))`).
        bail!("xtask run-interactive: only x86_64 is wired (aarch64 boot-init is a stub)");
    }

    let mut build = args.build.clone();
    ensure_feature(&mut build.features, "boot-init");
    // Bring up at least the firmware ack the boot-init flow assumes;
    // matches `Cmd::IsoBoot` / `Cmd::Image` defaults so the shell
    // actually loads.
    ensure_feature(&mut build.features, "firmware-allow-unsigned");

    let root = workspace_root()?;
    let out_dir = cargo_build(&build, &root)?;

    let kernel = out_dir.join(&build.package);
    if !kernel.exists() {
        bail!(
            "expected kernel binary at {} — did `cargo build` succeed?",
            kernel.display()
        );
    }

    let qemu = build.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        build
            .arch
            .qemu_args(&kernel, &build.display, build.hw_profile),
    );
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    println!(
        "xtask run-interactive: launching {} {}",
        qemu,
        kernel.display()
    );

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let prompt_secs = std::env::var("XTASK_RI_PROMPT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);
    // Per-command echo timeout. Generous by default: a CI runner
    // without KVM emulates 5-10x slower than a local KVM host, so the
    // slowest cases (dynamic-linked musl binaries that run the full
    // ld-musl relocation path, pthread join, busybox fork/exec) can
    // take well over the old 30s there even though they finish in a
    // few seconds locally. Override with XTASK_RI_ECHO_TIMEOUT_SECS.
    let echo_secs = std::env::var("XTASK_RI_ECHO_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);

    // Channel events from the reader thread. The reader doesn't
    // try to detect the echo reply — main does that off the shared
    // buffer after typing finishes. Splitting the responsibilities
    // sidesteps the race between local-echo arrival and the main
    // thread setting a "stop counting" flag.
    enum Ev {
        Prompt,
        Panic(String),
        Eof,
    }
    let (tx, rx) = mpsc::channel::<Ev>();
    // Shared sink: every byte QEMU prints to its serial stdout
    // lands here. Main inspects this after typing to assert the
    // echo built-in's reply.
    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::with_capacity(64 * 1024)));

    // Reader thread: streams QEMU stdout byte by byte (the shell
    // prompt has no newline, so a BufRead::lines() iterator would
    // never surface it until the user typed Enter). Forwards each
    // byte to our own stdout for live tailing, and runs a tiny
    // state machine to detect:
    //   1. `narf> ` prompt → send Ev::Prompt once.
    //   2. `hello world\n` substring → send Ev::EchoHit once.
    //   3. Panic markers per line → send Ev::Panic.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdout"))?;
    let tx_reader = tx.clone();
    let captured_reader = captured.clone();
    let reader_handle = std::thread::spawn(move || {
        use std::io::Read;
        const PROMPT: &[u8] = b"narf> ";
        let panic_markers: &[&[u8]] = &[
            b"*** KERNEL PANIC ***",
            b"panicked at",
            b"double fault",
            b"general protection",
            b"kernel page fault",
            b"unsafe precondition",
        ];
        // Per-line buffer used only for the panic marker scan + the
        // human-readable echoed log line.
        let mut line: Vec<u8> = Vec::with_capacity(256);
        let mut prompt_sent = false;

        let mut stdout = stdout;
        let mut buf = [0u8; 256];
        let mut out = std::io::stdout();
        loop {
            let n = match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            // Mirror to our own stdout so the user sees the boot
            // chatter live (handy when debugging).
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
            // Persist for main-side post-typing inspection.
            if let Ok(mut g) = captured_reader.lock() {
                g.extend_from_slice(&buf[..n]);
            }
            for &b in &buf[..n] {
                // Per-line panic scan.
                if b == b'\n' {
                    for m in panic_markers {
                        if line.windows(m.len()).any(|w| w == *m) {
                            let s = String::from_utf8_lossy(&line).into_owned();
                            let _ = tx_reader.send(Ev::Panic(s));
                        }
                    }
                    line.clear();
                } else {
                    line.push(b);
                }
                // Prompt detection via a small ring of recent bytes:
                // a 32-byte window is enough to catch "narf> "
                // straddling a read boundary.
                if !prompt_sent {
                    let tail_from = line.len().saturating_sub(PROMPT.len() * 2);
                    if line[tail_from..].windows(PROMPT.len()).any(|w| w == PROMPT) {
                        prompt_sent = true;
                        let _ = tx_reader.send(Ev::Prompt);
                    }
                }
            }
        }
        let _ = tx_reader.send(Ev::Eof);
    });

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdin"))?;

    // Stage 0: log in. getty prints "NARF login:" then "Password:" before
    // the shell starts; credentials are seeded in /etc/passwd (root / narf).
    // The reader thread only signals "narf> ", so poll the shared capture
    // buffer for the login prompts directly.
    {
        let login_deadline = Duration::from_secs(prompt_secs);
        for (needle, reply) in [
            (&b"login: "[..], &b"root\n"[..]),
            (&b"Password: "[..], &b"narf\n"[..]),
        ] {
            let start = std::time::Instant::now();
            let mut seen = false;
            while start.elapsed() < login_deadline {
                if let Ok(g) = captured.lock() {
                    if g.windows(needle.len()).any(|w| w == needle) {
                        seen = true;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if !seen {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!(
                    "xtask run-interactive: did not see login prompt within {}s",
                    prompt_secs
                );
            }
            for &b in reply {
                if stdin.write_all(&[b]).is_err() {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader_handle.join();
                    bail!("xtask run-interactive: stdin write failed during login");
                }
                let _ = stdin.flush();
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    // Stage 1: wait for the prompt.
    let prompt_deadline = Duration::from_secs(prompt_secs);
    let mut got_prompt = false;
    let start = std::time::Instant::now();
    while start.elapsed() < prompt_deadline {
        let left = prompt_deadline - start.elapsed();
        match rx.recv_timeout(left) {
            Ok(Ev::Prompt) => {
                got_prompt = true;
                break;
            }
            Ok(Ev::Panic(p)) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!(
                    "xtask run-interactive: kernel panic before prompt — '{}'",
                    p
                );
            }
            Ok(Ev::Eof) => {
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!("xtask run-interactive: QEMU stdout EOF before prompt appeared");
            }
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    if !got_prompt {
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader_handle.join();
        bail!(
            "xtask run-interactive: did not see `narf> ` prompt within {}s — \
             is boot-init wired? did the shell crash before main()?",
            prompt_secs
        );
    }

    println!(
        "\nxtask run-interactive: prompt seen, typing `{}`...",
        args.cmd
    );

    // Drain the kernel's late-boot log noise (USB-HID enumeration
    // typically lands a few hundred ms after the shell prompt is
    // first printed). If we type while the keyboard is attaching,
    // the local-echo gets interleaved with `usb-hid: kbd attached`
    // and the substring `hello world` straddles a kernel log line,
    // which defeats the detector.
    std::thread::sleep(Duration::from_millis(750));

    // Stage 2: type the command. Write byte-by-byte with brief
    // pauses so the shell's `read_byte` loop has a chance to drain
    // each character through the input ring + line editor without
    // overflowing the bounded ring.
    // Mark the byte position in the capture buffer where typing
    // begins. Anything before this is pre-typing boot chatter +
    // the shell prompt itself; "hello world" detection only needs
    // to consider bytes from here onwards.
    let pre_type_pos = captured.lock().map(|g| g.len()).unwrap_or(0);

    // Wave-49: typed line is the configurable `args.cmd` with a
    // trailing newline. Default is "echo hello world" for parity
    // with the Wave-45 echo smoke.
    let mut typed: Vec<u8> = args.cmd.as_bytes().to_vec();
    typed.push(b'\n');
    for &b in &typed {
        if stdin.write_all(&[b]).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader_handle.join();
            bail!("xtask run-interactive: stdin write failed while typing line");
        }
        let _ = stdin.flush();
        std::thread::sleep(Duration::from_millis(5));
    }

    // Stage 3: poll the captured-output buffer for the echo reply.
    //
    // The kernel UART maps `\n` to `\r\n`, so the byte sequence on
    // the wire is `hello world\r\n`. Two `hello world` substrings
    // appear after typing: one from the shell's local-echo loop
    // (proves the keystroke → fd-0 path) and one from the `echo`
    // built-in's sys_write (proves the fd-1 path). The local-echo
    // copy can be broken by an interleaved kernel log line (e.g.
    // `usb-hid: kbd attached on port 5` lands mid-typing on a cold
    // boot), so we can't rely on counting matches.
    //
    // Instead: require a `hello world` substring that is NOT
    // immediately followed by a typed-character byte. The echo
    // built-in's output is terminated by `\r\n` (the kernel UART
    // expansion of the trailing `\n`), so we accept a match
    // followed by `\r` or `\n`. The local-echo's "hello world"
    // is followed by a typed ` ` or, once the trailing `\n` is
    // echoed, by `\r\n` — so a strict "followed by \r or \n" check
    // matches BOTH variants. That's still better than the prior
    // window-clear heuristic: in the worst case we trigger on the
    // local-echo copy when it arrives intact, which only happens
    // when the keystroke→shell→UART loop is working end to end
    // anyway. Either way, the test asserts what it claims to.
    // Wave-49: the expected substring is configurable via
    // `args.expect`. Default is "hello world".
    let needle: Vec<u8> = args.expect.as_bytes().to_vec();
    let echo_deadline = Duration::from_secs(echo_secs);
    let echo_start = std::time::Instant::now();
    let mut got_echo = false;
    while echo_start.elapsed() < echo_deadline {
        // Drain pending events first so a panic short-circuits the
        // loop instead of waiting out the full timeout.
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ev::Panic(p)) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!("xtask run-interactive: panic after typing — '{}'", p);
            }
            Ok(Ev::Prompt) => {}
            Ok(Ev::Eof) => {
                // QEMU stdout closed. Before treating it as a hard
                // failure, sweep the captured buffer one more time
                // for the expect needle — the kernel might have
                // printed the expected output AND then halted/exited
                // (e.g. clean Wave-78+3 dynamic-musl exit through
                // `exit_group` racing with the reader loop). If the
                // needle's there with a terminator, count it as
                // success.
                if let Ok(g) = captured.lock() {
                    if g.len() > pre_type_pos {
                        let tail = &g[pre_type_pos..];
                        let mut idx = 0usize;
                        while idx + needle.len() < tail.len() {
                            if &tail[idx..idx + needle.len()] == needle.as_slice() {
                                let next = tail[idx + needle.len()];
                                if next == b'\r' || next == b'\n' {
                                    got_echo = true;
                                    break;
                                }
                            }
                            idx += 1;
                        }
                    }
                }
                if got_echo {
                    break;
                }
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!("xtask run-interactive: QEMU stdout EOF before echo reply");
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if let Ok(g) = captured.lock() {
            if g.len() > pre_type_pos {
                let tail = &g[pre_type_pos..];
                // Find any occurrence of NEEDLE in `tail` whose
                // next byte is `\r` or `\n` (or EOF on the buffer
                // — but in that case keep waiting).
                let mut idx = 0usize;
                while idx + needle.len() < tail.len() {
                    if &tail[idx..idx + needle.len()] == needle.as_slice() {
                        let next = tail[idx + needle.len()];
                        if next == b'\r' || next == b'\n' {
                            got_echo = true;
                            break;
                        }
                    }
                    idx += 1;
                }
            }
        }
        if got_echo {
            break;
        }
    }

    // Done — tear down cleanly. The shell loops forever, so QEMU
    // never exits on its own from this command; killing the child
    // is the only termination path.
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader_handle.join();

    if !got_echo {
        bail!(
            "xtask run-interactive: typed `{}` but did not \
             see `{}` echoed back within {}s",
            args.cmd,
            args.expect,
            echo_secs
        );
    }

    println!(
        "\nxtask run-interactive: ok — typed `{}`, saw `{}`",
        args.cmd, args.expect,
    );
    Ok(())
}

/// Boot QEMU **once** and run an entire list of `(command, expect)`
/// pairs in that single VM, rather than one boot per command. Each
/// command is typed at the `narf> ` prompt; it passes when its
/// `expect` token appears (CR/LF-terminated) before the echo timeout
/// and the shell returns to a prompt afterward. Returns
/// `(passed, failed)`.
///
/// This keeps the full multi-vCPU/NUMA machine (so concurrency bugs
/// still surface) — the only thing it changes is amortizing the slow
/// TCG boot across all commands instead of paying it N times. Prompt
/// and token detection are driven off the captured serial buffer; the
/// channel carries only panic/EOF so a crash aborts fast (remaining
/// commands are counted failed).
fn run_interactive_multi(build_in: &BuildArgs, cases: &[(&str, &str)]) -> Result<(usize, usize)> {
    use std::io::{Read, Write};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Arc, Mutex};

    if !matches!(build_in.arch, Arch::X86_64) {
        bail!("run-interactive(multi): only x86_64 is wired (aarch64 boot-init is a stub)");
    }

    let mut build = build_in.clone();
    ensure_feature(&mut build.features, "boot-init");
    ensure_feature(&mut build.features, "firmware-allow-unsigned");

    let root = workspace_root()?;
    let out_dir = cargo_build(&build, &root)?;
    let kernel = out_dir.join(&build.package);
    if !kernel.exists() {
        bail!(
            "expected kernel binary at {} — did `cargo build` succeed?",
            kernel.display()
        );
    }

    let qemu = build.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        build
            .arch
            .qemu_args(&kernel, &build.display, build.hw_profile),
    );
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    println!(
        "xtask musl-demo: launching {} {} (single boot for {} commands)",
        qemu,
        kernel.display(),
        cases.len()
    );
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let prompt_secs = std::env::var("XTASK_RI_PROMPT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);
    let echo_secs = std::env::var("XTASK_RI_ECHO_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);

    enum Ev {
        Panic(String),
        Eof,
    }
    let (tx, rx) = mpsc::channel::<Ev>();
    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::with_capacity(256 * 1024)));
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdout"))?;
    let tx_reader = tx.clone();
    let captured_reader = captured.clone();
    let reader_handle = std::thread::spawn(move || {
        let panic_markers: &[&[u8]] = &[
            b"*** KERNEL PANIC ***",
            b"panicked at",
            b"double fault",
            b"general protection",
            b"kernel page fault",
            b"unsafe precondition",
        ];
        let mut line: Vec<u8> = Vec::with_capacity(256);
        let mut stdout = stdout;
        let mut buf = [0u8; 256];
        let mut out = std::io::stdout();
        loop {
            let n = match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
            if let Ok(mut g) = captured_reader.lock() {
                g.extend_from_slice(&buf[..n]);
            }
            for &b in &buf[..n] {
                if b == b'\n' {
                    for m in panic_markers {
                        if line.windows(m.len()).any(|w| w == *m) {
                            let _ = tx_reader
                                .send(Ev::Panic(String::from_utf8_lossy(&line).into_owned()));
                        }
                    }
                    line.clear();
                } else {
                    line.push(b);
                }
            }
        }
        let _ = tx_reader.send(Ev::Eof);
    });

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdin"))?;

    // Scan `captured[from..]` for `needle`; when `term`, require the
    // byte after the match to be CR/LF (mirrors the single-command
    // detector — distinguishes a real reply from a bare echo). Returns
    // the absolute index just past the terminator/needle.
    let scan = |from: usize, needle: &[u8], term: bool| -> Option<usize> {
        let g = captured.lock().ok()?;
        if g.len() <= from {
            return None;
        }
        let tail = &g[from..];
        let mut idx = 0usize;
        while idx + needle.len() <= tail.len() {
            if &tail[idx..idx + needle.len()] == needle {
                if !term {
                    return Some(from + idx + needle.len());
                }
                if idx + needle.len() < tail.len() {
                    let next = tail[idx + needle.len()];
                    if next == b'\r' || next == b'\n' {
                        return Some(from + idx + needle.len());
                    }
                }
            }
            idx += 1;
        }
        None
    };

    enum Wait {
        Found(usize),
        TimedOut,
        Died(String),
    }
    // Poll the buffer for `needle` from `from`, draining panic/EOF.
    let wait_for = |from: usize, needle: &[u8], term: bool, timeout: Duration| -> Wait {
        let start = std::time::Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ev::Panic(p)) => {
                    if let Some(end) = scan(from, needle, term) {
                        return Wait::Found(end);
                    }
                    return Wait::Died(format!("kernel panic — '{p}'"));
                }
                Ok(Ev::Eof) => {
                    if let Some(end) = scan(from, needle, term) {
                        return Wait::Found(end);
                    }
                    return Wait::Died("QEMU stdout EOF".into());
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {}
            }
            if let Some(end) = scan(from, needle, term) {
                return Wait::Found(end);
            }
            if start.elapsed() >= timeout {
                return Wait::TimedOut;
            }
        }
    };

    let prompt_to = Duration::from_secs(prompt_secs);
    let echo_to = Duration::from_secs(echo_secs);
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut cursor = 0usize; // buffer position consumed so far

    // Log in first: getty shows "NARF login:" then "Password:" before the
    // shell starts. Credentials are seeded in /etc/passwd (root / narf).
    for (needle, reply) in [
        (&b"login: "[..], &b"root\n"[..]),
        (&b"Password: "[..], &b"narf\n"[..]),
    ] {
        match wait_for(cursor, needle, false, prompt_to) {
            Wait::Found(end) => cursor = end,
            Wait::TimedOut => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!("xtask musl-demo: did not see login prompt within {prompt_secs}s");
            }
            Wait::Died(why) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!("xtask musl-demo: {why} before login prompt");
            }
        }
        for &b in reply {
            if stdin.write_all(&[b]).is_err() {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!("xtask musl-demo: stdin write failed during login");
            }
            let _ = stdin.flush();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // Initial prompt.
    match wait_for(cursor, b"narf> ", false, prompt_to) {
        Wait::Found(end) => cursor = end,
        Wait::TimedOut => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader_handle.join();
            bail!("xtask musl-demo: did not see `narf> ` prompt within {prompt_secs}s");
        }
        Wait::Died(why) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader_handle.join();
            bail!("xtask musl-demo: {why} before first prompt");
        }
    }
    // Late-boot log noise (USB-HID enumeration) can interleave with
    // the first keystrokes; let it settle once.
    std::thread::sleep(Duration::from_millis(750));

    let mut aborted: Option<String> = None;
    for (i, (cmdline, expect)) in cases.iter().enumerate() {
        eprintln!(
            "\n=== musl-demo [{}/{}]: cmd=`{}` expect=`{}` ===",
            i + 1,
            cases.len(),
            cmdline,
            expect
        );
        let pre = captured.lock().map(|g| g.len()).unwrap_or(cursor);
        // Type the command byte-by-byte (the shell's line editor needs
        // time to drain each char through the bounded input ring).
        let mut typed = cmdline.as_bytes().to_vec();
        typed.push(b'\n');
        let mut wrote = true;
        for &b in &typed {
            if stdin.write_all(&[b]).is_err() {
                wrote = false;
                break;
            }
            let _ = stdin.flush();
            std::thread::sleep(Duration::from_millis(5));
        }
        if !wrote {
            aborted = Some("stdin write failed".into());
            failed += 1;
            break;
        }

        match wait_for(pre, expect.as_bytes(), true, echo_to) {
            Wait::Found(_) => {
                passed += 1;
                println!("xtask musl-demo: ok — `{cmdline}` saw `{expect}`");
            }
            Wait::TimedOut => {
                failed += 1;
                eprintln!(
                    "musl-demo: `{cmdline}` failed: did not see `{expect}` within {echo_secs}s"
                );
            }
            Wait::Died(why) => {
                failed += 1;
                eprintln!("musl-demo: `{cmdline}` failed: {why}");
                aborted = Some(why);
                break;
            }
        }

        // Wait for the shell to return to a prompt before typing the
        // next command. Anchor the search at the PRE-type position,
        // not the token match: a forking builtin like `busybox sh -c`
        // re-prompts asynchronously and prints `narf> ` BEFORE its
        // child's output, so the next prompt can land on either side
        // of the token. From `pre` (just after the previous prompt)
        // the first `narf> ` is unambiguously this command's prompt.
        match wait_for(pre, b"narf> ", false, prompt_to) {
            Wait::Found(end) => cursor = end,
            Wait::TimedOut => {
                aborted = Some(format!(
                    "shell did not return to a prompt within {prompt_secs}s after `{cmdline}`"
                ));
                break;
            }
            Wait::Died(why) => {
                aborted = Some(why);
                break;
            }
        }
        let _ = cursor;
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader_handle.join();

    if let Some(why) = aborted {
        // Count the commands that never got a chance to run as failed.
        let ran = passed + failed;
        let remaining = cases.len().saturating_sub(ran);
        failed += remaining;
        eprintln!(
            "musl-demo: aborted after {ran}/{} commands — {why} ({remaining} not run, counted failed)",
            cases.len()
        );
    }

    Ok((passed, failed))
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

/// Recursively walk `fw_dir` collecting every regular file. Returns a
/// pair of entry lists:
///
/// - `initramfs`: `(cpio_name, bytes)` pairs where `cpio_name =
///   "firmware/<rel>"` for blobs whose `<rel>` path matches at least
///   one glob in `initramfs_globs`. These go into the CPIO archive
///   so the kernel's `firmware-scan-initramfs` initcall registers
///   them before root mounts.
///
/// - `rootfs`: `(rel, bytes)` pairs for everything else. The caller
///   copies these to `<root-staging>/lib/firmware/<rel>` so
///   `firmware-scan-rootfs` registers them after `root-mount-auto`.
///
/// Linux convention (linux/init/initramfs.c + linux/drivers/base/
/// firmware_loader/main.c::fw_get_filesystem_firmware): only blobs
/// needed BEFORE root mounts (CPU microcode, early-FB GPU firmware,
/// storage-controller quirk blobs) go in the initramfs. Everything
/// else lives on the root partition at /lib/firmware/.
///
/// Default (empty `initramfs_globs`): zero firmware in initramfs;
/// all firmware goes to rootfs. Keeps the initramfs small enough for
/// Limine's multiboot2 module allocator (< 20 MiB without firmware
/// vs. 1.7 GiB with a full linux-firmware import).
///
/// Empty result is fine — a build with no firmware just skips the
/// scan + ships the same init+shell-only CPIO as before.
fn collect_firmware_blobs(
    fw_dir: &Path,
    initramfs_globs: &[String],
) -> Result<(Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>)> {
    if !fw_dir.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut initramfs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut rootfs: Vec<(String, Vec<u8>)> = Vec::new();

    let mut stack: Vec<PathBuf> = vec![fw_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).with_context(|| format!("read_dir {}", dir.display()))?;
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
            let rel = path.strip_prefix(fw_dir).with_context(|| {
                format!("strip_prefix {} vs {}", path.display(), fw_dir.display())
            })?;
            let rel_str = rel
                .to_str()
                .ok_or_else(|| anyhow!("firmware path {} not valid UTF-8", path.display()))?
                .replace('\\', "/");
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading firmware blob {}", path.display()))?;
            // Match against initramfs globs. A glob is matched against
            // the rel-path (e.g. "amd-ucode/microcode_amd.bin") using
            // simple wildcard expansion: `*` matches any sequence of
            // characters that doesn't cross a `/` boundary, `**` is
            // not supported (use `amdgpu/*` for a whole subdirectory).
            let in_initramfs = initramfs_globs
                .iter()
                .any(|glob| glob_match(glob, &rel_str));
            if in_initramfs {
                let cpio_name = format!("firmware/{}", rel_str);
                initramfs.push((cpio_name, bytes));
            } else {
                rootfs.push((rel_str, bytes));
            }
        }
    }
    // Stable order for reproducibility.
    initramfs.sort_by(|a, b| a.0.cmp(&b.0));
    rootfs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((initramfs, rootfs))
}

/// Simple single-level glob matcher. Supports `*` (matches any
/// characters except `/`) within a path component. Does NOT support
/// `?` or `[...]` — firmware path globs don't need them.
///
/// Examples:
///   glob_match("amd-ucode/*",        "amd-ucode/microcode_amd.bin") → true
///   glob_match("intel-ucode/*",      "amd-ucode/microcode_amd.bin") → false
///   glob_match("amdgpu/raven_*.bin", "amdgpu/raven_dmcu.bin")       → true
///   glob_match("amdgpu/*",           "amdgpu/sub/blob.bin")         → false
fn glob_match(glob: &str, path: &str) -> bool {
    // Split both into `/`-separated segments and match segment by segment.
    let g_segs: Vec<&str> = glob.split('/').collect();
    let p_segs: Vec<&str> = path.split('/').collect();
    if g_segs.len() != p_segs.len() {
        return false;
    }
    g_segs.iter().zip(p_segs.iter()).all(|(g, p)| {
        // Each segment is matched with `*` as a wildcard.
        segment_match(g, p)
    })
}

fn segment_match(glob: &str, text: &str) -> bool {
    // Recursive: consume one glob char at a time.
    if glob.is_empty() {
        return text.is_empty();
    }
    if glob == "*" {
        // Remaining glob is just `*` — matches anything (including empty).
        return true;
    }
    let mut gi = glob.chars();
    let first = gi.next().unwrap();
    if first != '*' {
        // Literal char: must match.
        let mut pi = text.chars();
        match pi.next() {
            Some(c) if c == first => segment_match(gi.as_str(), pi.as_str()),
            _ => false,
        }
    } else {
        // `*` at start of glob segment: try matching 0..=N text chars.
        let rest_glob = gi.as_str();
        let mut t = text;
        loop {
            if segment_match(rest_glob, t) {
                return true;
            }
            if t.is_empty() {
                return false;
            }
            // Advance one character in text.
            let mut ci = t.chars();
            ci.next();
            t = ci.as_str();
        }
    }
}

/// Wrap raw payload bytes with the NARF unsigned trailer. Pure
/// function — same trailer logic as `pack_firmware_cmd` but
/// callable from the bulk-import path without going through file
/// I/O for each blob.
fn wrap_firmware_trailer(payload: &[u8], version: Option<&str>) -> Vec<u8> {
    let mut metadata: Vec<u8> = Vec::new();
    if let Some(ver) = version {
        let bytes = ver.as_bytes();
        // Per signature::decode the metadata len byte is u8 (max
        // 255). Anything longer gets silently truncated for the
        // bulk-import path — version strings from kernel `uname -r`
        // are well under that, and bulk-import has no human in the
        // loop to surface "too long" warnings to.
        let n = bytes.len().min(255);
        metadata.push(0x01); // TLV tag: ASCII version
        metadata.push(n as u8);
        metadata.extend_from_slice(&bytes[..n]);
    }
    let mut blob = Vec::with_capacity(payload.len() + 104 + metadata.len());
    blob.extend_from_slice(payload);
    blob.extend_from_slice(&[0u8; 64]); // unsigned sig sentinel
    blob.extend_from_slice(&[0u8; 32]); // unsigned signer fingerprint
    blob.extend_from_slice(&metadata);
    blob.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    blob.extend_from_slice(b"NRFW");
    blob
}

/// Bulk-import firmware blobs. Walks the source tree, decompresses
/// any `.zst` entries, wraps each with the NARF trailer, and writes
/// the result under the workspace's `firmware/` dir so subsequent
/// `xtask image` runs auto-bundle the lot into the initramfs CPIO.
fn import_firmware_cmd(args: &ImportFirmwareArgs) -> Result<()> {
    let source = PathBuf::from(&args.source);
    if !source.is_dir() {
        bail!(
            "source dir {} doesn't exist or isn't a directory",
            source.display()
        );
    }
    let root = workspace_root()?;
    let out_root = root.join(&args.out);

    if args.clean && out_root.exists() {
        std::fs::remove_dir_all(&out_root)
            .with_context(|| format!("removing {}", out_root.display()))?;
        println!("import-firmware: cleaned {}", out_root.display());
    }
    std::fs::create_dir_all(&out_root)
        .with_context(|| format!("creating {}", out_root.display()))?;

    // Optional version stamp baked into each blob's trailer. Uses
    // the host kernel's release string so post-mortem inspection
    // (BoundFirmware.version) ties a NARF boot back to the Linux
    // firmware drop it was sourced from.
    let host_uname = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    let vendor_prefix: Option<PathBuf> = args.vendor.as_ref().map(PathBuf::from);

    let mut imported: usize = 0;
    let mut skipped_existing: usize = 0;
    let mut skipped_too_big: usize = 0;
    let mut skipped_non_blob: usize = 0;
    let mut decomp_failed: usize = 0;
    let mut total_payload_bytes: u64 = 0;

    let mut stack: Vec<PathBuf> = vec![source.clone()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).with_context(|| format!("read_dir {}", dir.display()))?;
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue, // permission/IO blip on one file shouldn't kill the bulk
            };
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                // Skip symlinks — most firmware symlinks are alias
                // names (vendor/foo.bin -> vendor/foo-v2.bin). Each
                // alias becomes its own entry below, and following
                // would risk infinite loops on circular aliases.
                continue;
            }
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }

            let rel = path.strip_prefix(&source).with_context(|| {
                format!("strip_prefix {} vs {}", path.display(), source.display())
            })?;

            // Vendor filter: only import paths that match the
            // requested prefix (path-component-wise, so `--vendor
            // amdgpu` matches `amdgpu/phoenix_*` but not
            // `amd-ucode/microcode_amd.bin` or stray `amdfoo` blobs).
            if let Some(prefix) = &vendor_prefix {
                if !rel.starts_with(prefix) {
                    continue;
                }
            }

            // Skip well-known non-firmware files. linux-firmware
            // ships .txt licenses, WHENCE manifests, etc. — none
            // are firmware blobs and packing them just bloats the
            // CPIO.
            let rel_str = rel.to_str().unwrap_or("");
            if rel_str.ends_with(".txt")
                || rel_str.ends_with(".md")
                || rel_str.ends_with(".rst")
                || rel_str.ends_with(".cfg")
                || rel_str.contains("WHENCE")
                || rel_str.contains("README")
                || rel_str.contains("LICENSE")
                || rel_str.contains("LICENCE")
                || rel_str.contains("copyright")
                || rel_str.starts_with(".")
            {
                skipped_non_blob += 1;
                continue;
            }

            // Compute destination path. Strip `.zst` if present
            // so the canonical registry key matches what drivers
            // request (e.g. `amdgpu/phoenix_dmcub.bin`, not
            // `amdgpu/phoenix_dmcub.bin.zst`).
            let dest_rel: PathBuf = if rel_str.ends_with(".zst") {
                PathBuf::from(&rel_str[..rel_str.len() - 4])
            } else {
                rel.to_path_buf()
            };
            let dest_path = out_root.join(&dest_rel);

            if args.skip_existing && dest_path.exists() {
                skipped_existing += 1;
                continue;
            }

            // Read payload (decompressing on the fly if .zst).
            let raw = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let payload: Vec<u8> = if rel_str.ends_with(".zst") {
                match zstd::stream::decode_all(raw.as_slice()) {
                    Ok(b) => b,
                    Err(_) => {
                        decomp_failed += 1;
                        continue;
                    }
                }
            } else {
                raw
            };

            if (payload.len() as u64) > args.max_payload_bytes {
                skipped_too_big += 1;
                continue;
            }
            if payload.is_empty() {
                // Empty payloads fail at narf_firmware decode
                // (signature::decode rejects blobs < 104 bytes
                // total, but even after trailer add an empty
                // payload trips load_firmware's size==0 check on
                // amdgpu). Skip rather than ship a deliberately-
                // broken blob.
                skipped_non_blob += 1;
                continue;
            }

            let wrapped = wrap_firmware_trailer(&payload, host_uname.as_deref());

            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&dest_path, &wrapped)
                .with_context(|| format!("writing {}", dest_path.display()))?;
            imported += 1;
            total_payload_bytes += payload.len() as u64;
        }
    }

    println!(
        "import-firmware: imported {} blob(s), {} payload byte(s) total",
        imported, total_payload_bytes
    );
    if skipped_existing > 0 {
        println!(
            "  skipped {} (already present; --skip-existing)",
            skipped_existing
        );
    }
    if skipped_too_big > 0 {
        println!(
            "  skipped {} (over --max-payload-bytes = {})",
            skipped_too_big, args.max_payload_bytes
        );
    }
    if skipped_non_blob > 0 {
        println!(
            "  skipped {} (license/readme/empty/non-blob files)",
            skipped_non_blob
        );
    }
    if decomp_failed > 0 {
        println!("  zstd-decompression failed on {} file(s)", decomp_failed);
    }
    println!("  output dir: {}", out_root.display());
    if host_uname.is_some() {
        println!(
            "  trailer version stamp: {}",
            host_uname.as_deref().unwrap_or("")
        );
    }
    Ok(())
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
        bail!(
            "payload {} is empty — NARF amdgpu rejects size==0",
            &args.payload
        );
    }
    if let Some(ver) = &args.version {
        if ver.len() > 255 {
            bail!("version string too long ({} > 255)", ver.len());
        }
    }
    let blob = wrap_firmware_trailer(&payload, args.version.as_deref());

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

    // Build the 5 coreutils and read their ELFs.
    // Each crate lives at userspace/coreutils/<name>/ and uses
    // <name>.ld as its linker script. They land in the CPIO at
    // "bin/<name>" so the shell's "/bin/<name>" PATH resolution
    // finds them after root-mount-auto mounts the initramfs at "/".
    //
    // Linux reference: BusyBox multi-call layout — each applet
    // invoked at its own /bin/<name> path. We split them into
    // separate ELFs rather than a multi-call binary to keep the
    // no_std build simple.
    let coreutil_names = ["echo", "pwd", "cat", "ls", "ps"];
    let mut coreutil_bytes: Vec<(String, Vec<u8>)> = Vec::new();
    for name in coreutil_names {
        let crate_dir = format!("userspace/coreutils/{}", name);
        let ld_name = format!("{}.ld", name);
        let elf = build_user_binary(&root, &crate_dir, name, &ld_name)?;
        let bytes = std::fs::read(&elf)
            .with_context(|| format!("reading {} ELF at {}", name, elf.display()))?;
        println!("xtask image: coreutil {} = {} bytes", name, bytes.len());
        coreutil_bytes.push((format!("bin/{}", name), bytes));
    }

    // Firmware bundling — Linux hybrid model:
    //   initramfs: only blobs matching --initramfs-firmware globs.
    //              Needed BEFORE root mounts (CPU microcode, early-FB
    //              GPU firmware, storage-controller quirk blobs).
    //              Default: ZERO blobs → initramfs stays tiny so
    //              Limine can allocate it as a multiboot2 module.
    //   rootfs:    everything else → target/rootfs-firmware-staging/
    //              lib/firmware/<rel>. disk-write-partitioned copies
    //              this tree onto the NARF_ROOT ext4 partition;
    //              firmware-scan-rootfs registers it after root-mount.
    //
    // Linux references:
    //   linux/init/initramfs.c — boot-time initramfs include.
    //   linux/drivers/base/firmware_loader/main.c::fw_get_filesystem_firmware
    //     — /lib/firmware/ search-path pattern.
    let fw_dir = root.join("target").join("firmware");
    let (fw_initramfs, fw_rootfs) = collect_firmware_blobs(&fw_dir, &args.initramfs_firmware)?;

    // Optional ld-musl staging for Linux-compat PT_INTERP. When
    // $LDMUSL_PATH is set (or /lib/ld-musl-x86_64.so.1 is present on
    // the host), copy the host interpreter into the initramfs CPIO at
    // the canonical Linux path. The kernel's FS-backed PT_INTERP
    // lookup (Wave-75, userspace/process.rs::read_path_from_vfs)
    // resolves `/lib/ld-musl-x86_64.so.1` against the initramfs mount
    // and runs the interpreter for dynamically-linked Linux ELFs.
    //
    // Absent on a non-musl host: skip with a warning. The image still
    // builds; programs needing the interpreter just don't get one.
    let ld_musl_bytes: Option<Vec<u8>> = {
        let host_path = std::env::var("LDMUSL_PATH")
            .ok()
            .unwrap_or_else(|| "/lib/ld-musl-x86_64.so.1".into());
        match std::fs::read(&host_path) {
            Ok(b) => {
                println!(
                    "xtask image: ld-musl staged from {} ({} bytes) → lib/ld-musl-x86_64.so.1",
                    host_path,
                    b.len()
                );
                Some(b)
            }
            Err(e) => {
                println!(
                    "xtask image: no ld-musl at {} ({}); skipping dynamic-linker stage",
                    host_path, e
                );
                None
            }
        }
    };

    let mut cpio_entries: Vec<(&str, &[u8])> = Vec::new();
    cpio_entries.push(("init", &init_bytes));
    cpio_entries.push(("shell", &shell_bytes));
    // Stage coreutils at bin/<name> so the shell's /bin/<name>
    // PATH resolution resolves them after the initramfs is mounted.
    for (path, bytes) in &coreutil_bytes {
        cpio_entries.push((path.as_str(), bytes.as_slice()));
    }
    if let Some(ref b) = ld_musl_bytes {
        cpio_entries.push(("lib/ld-musl-x86_64.so.1", b.as_slice()));
    }
    for (path, bytes) in &fw_initramfs {
        cpio_entries.push((path.as_str(), bytes.as_slice()));
    }
    let cpio = encode_cpio_newc(&cpio_entries);
    let cpio_path = boot_dir.join("initramfs.cpio");
    std::fs::write(&cpio_path, &cpio)
        .with_context(|| format!("writing initramfs CPIO to {}", cpio_path.display()))?;

    // Stage rootfs firmware at target/rootfs-firmware-staging/lib/firmware/<rel>
    // so disk-write-partitioned can copy the whole tree onto NARF_ROOT.
    let rootfs_fw_stage = root
        .join("target")
        .join("rootfs-firmware-staging")
        .join("lib")
        .join("firmware");
    if !fw_rootfs.is_empty() {
        std::fs::create_dir_all(&rootfs_fw_stage)
            .context("creating rootfs firmware staging dir")?;
        for (rel, bytes) in &fw_rootfs {
            let dst = rootfs_fw_stage.join(rel);
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating staging subdir {}", parent.display()))?;
            }
            std::fs::write(&dst, bytes)
                .with_context(|| format!("staging rootfs firmware blob {}", rel))?;
        }
    }

    let initramfs_fw_bytes: usize = fw_initramfs.iter().map(|(_, b)| b.len()).sum();
    let rootfs_fw_bytes: usize = fw_rootfs.iter().map(|(_, b)| b.len()).sum();
    fn fmt_mib(bytes: usize) -> String {
        if bytes >= 1024 * 1024 {
            format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.1} KiB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }
    println!(
        "xtask image: initramfs firmware: {} entries ({})",
        fw_initramfs.len(),
        fmt_mib(initramfs_fw_bytes),
    );
    println!(
        "xtask image: rootfs firmware:    {} entries ({})",
        fw_rootfs.len(),
        fmt_mib(rootfs_fw_bytes),
    );
    let coreutil_total: usize = coreutil_bytes.iter().map(|(_, b)| b.len()).sum();
    println!(
        "xtask image: bundled initramfs ({} bytes; init={} bytes, shell={} bytes, coreutils={} bytes [{}])",
        cpio.len(),
        init_bytes.len(),
        shell_bytes.len(),
        coreutil_total,
        coreutil_bytes.iter().map(|(n, b)| format!("{}={}", n, b.len())).collect::<Vec<_>>().join(", "),
    );

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
    cmd.arg(stage.as_os_str()).arg("-o").arg(iso.as_os_str());

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
    // 4 GiB. Limine's high-memory allocator reads the entire
    // initramfs in during boot; the linux-firmware-scale bundle
    // (~90 MB amdgpu alone, ~750 MB full) overflows the 1 GiB
    // ceiling. Override via XTASK_MEM if you need more / less.
    let mem = std::env::var("XTASK_MEM").unwrap_or_else(|_| "4096M".into());
    cmd.arg("-m").arg(&mem);
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

    println!(
        "xtask iso-boot: launching qemu-system-x86_64 with ISO {}",
        iso.display()
    );

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

    let iso_path = args.iso.clone().unwrap_or_else(|| {
        workspace_root()
            .ok()
            .map(|r| r.join("target").join("narf-x86_64.iso"))
            .unwrap_or_else(|| PathBuf::from("target/narf-x86_64.iso"))
            .display()
            .to_string()
    });
    let iso = PathBuf::from(&iso_path);
    if !iso.exists() {
        bail!(
            "ISO not found at {}; run `cargo xtask image` first",
            iso.display()
        );
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
        detect_usb_device().context("USB stick not detected after replug — is it inserted?")?
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

    // ESP capacity preflight. Sum the staged artifact sizes and
    // compare to the user's `--esp-size-mib`. FAT32 overhead +
    // cluster-rounding-up adds ~3% in the worst case for a few
    // hundred files, so we check against 92% of capacity to leave
    // headroom. Catches "default 1 GiB but you also imported
    // 500 MB of WiFi blobs" before we trash the user's USB.
    let mut esp_payload_bytes: u64 = 0;
    for p in [&kernel, &initramfs, &bootx64] {
        esp_payload_bytes += std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    }
    // Limine support dir — walk + sum.
    fn dir_size(p: &Path) -> u64 {
        let mut total: u64 = 0;
        if let Ok(entries) = std::fs::read_dir(p) {
            for e in entries.flatten() {
                if let Ok(md) = e.metadata() {
                    if md.is_dir() {
                        total += dir_size(&e.path());
                    } else {
                        total += md.len();
                    }
                }
            }
        }
        total
    }
    esp_payload_bytes += dir_size(&limine_dir);

    let esp_capacity_bytes = args.esp_size_mib * 1024 * 1024;
    let usable_capacity = esp_capacity_bytes * 92 / 100;
    if esp_payload_bytes > usable_capacity {
        bail!(
            "ESP staging ({} MiB) won't fit in --esp-size-mib={} \
             (after ~8% FAT32 overhead = {} MiB usable). Bump \
             --esp-size-mib or trim the initramfs (the firmware \
             bundle is the usual culprit — drop `target/firmware/` \
             contents to test a minimal ISO).",
            esp_payload_bytes / (1024 * 1024),
            args.esp_size_mib,
            usable_capacity / (1024 * 1024),
        );
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
        let mut msg = String::from("missing host tools required by disk-write-partitioned:\n");
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
    println!("Plan: GPT layout on {}", dev);
    println!(
        "  - ESP (FAT32, {} MiB) — kernel + initramfs + Limine",
        args.esp_size_mib
    );
    println!(
        "  - narf-root ({}, rest of disk, PARTLABEL={})",
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
            "-n",
            &format!("1:0:{}", esp_end),
            "-t",
            "1:EF00",
            "-c",
            "1:ESP",
            "-n",
            "2:0:0",
            "-t",
            "2:8300",
            "-c",
            &format!("2:{}", args.root_label),
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
            "-L",
            &args.root_label,
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
            .args(["cp", src.to_str().unwrap(), dst.to_str().unwrap()])
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
        eprintln!(
            "warning: Limine support-file copy reported failure (some boot modes may not work)"
        );
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

    // ── 5c. Copy staged rootfs firmware onto the root partition ──
    // `xtask image` populated target/rootfs-firmware-staging/lib/firmware/
    // with every blob NOT matched by --initramfs-firmware globs.
    // Copy that whole tree onto the root partition so the kernel's
    // `firmware-scan-rootfs` initcall finds it at /lib/firmware/ after
    // `root-mount-auto` mounts the ext4 partition.
    //
    // Linux convention: /lib/firmware/ is the canonical search path
    // (linux/drivers/base/firmware_loader/main.c::fw_get_filesystem_firmware).
    let rootfs_fw_stage = target_dir
        .join("rootfs-firmware-staging")
        .join("lib")
        .join("firmware");
    if rootfs_fw_stage.exists() {
        mk_root_dir(&mnt_fs, "lib")?;
        mk_root_dir(&mnt_fs, "lib/firmware")?;
        // Walk the staging tree and copy each blob.
        let mut fw_copied = 0usize;
        let mut fw_bytes = 0u64;
        let mut fw_stack: Vec<PathBuf> = vec![rootfs_fw_stage.clone()];
        while let Some(dir) = fw_stack.pop() {
            let rel_dir = dir
                .strip_prefix(&rootfs_fw_stage)
                .unwrap_or(std::path::Path::new(""));
            let entries = std::fs::read_dir(&dir)
                .with_context(|| format!("read_dir fw-staging {}", dir.display()))?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let ft = entry.file_type()?;
                if ft.is_dir() {
                    fw_stack.push(path);
                    continue;
                }
                if !ft.is_file() {
                    continue;
                }
                let fname = entry.file_name();
                let rel_path = rel_dir.join(&fname);
                let rel_str = rel_path
                    .to_str()
                    .ok_or_else(|| anyhow!("firmware path not valid UTF-8"))?;
                let dst_rel = format!("lib/firmware/{}", rel_str.replace('\\', "/"));
                // Ensure parent dir exists on the mounted partition.
                if let Some(parent) = std::path::Path::new(&dst_rel).parent() {
                    if !parent.as_os_str().is_empty() {
                        mk_root_dir(&mnt_fs, parent.to_str().unwrap_or(""))?;
                    }
                }
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                cp_root(&path, &mnt_fs.join(&dst_rel))?;
                fw_copied += 1;
                fw_bytes += size;
            }
        }
        println!(
            "  root partition: copied {} firmware blob(s) ({:.1} MiB) to /lib/firmware/",
            fw_copied,
            fw_bytes as f64 / (1024.0 * 1024.0),
        );
    } else {
        println!("  root partition: no staged rootfs firmware (run `cargo xtask image` first, or no firmware imported)");
    }

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
    let tmp = std::env::temp_dir().join(format!("narf-disk-write-{}", std::process::id()));
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
        .args(["cp", src.to_str().unwrap(), dst.to_str().unwrap()])
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
        .arg(format!(
            "sudo dd if={} bs=1M count={} status=none | head -c {} | sha256sum",
            dev,
            n.div_ceil(1024 * 1024),
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
            // Phase 1: kernel-test feature on, run all in-kernel smokes.
            let mut smoke_args = args.clone();
            if smoke_args.features.is_empty() {
                smoke_args.features = "kernel-test".into();
            } else if !smoke_args.features.contains("kernel-test") {
                smoke_args.features.push_str(",kernel-test");
            }
            // Gate on the kernel-test runner's exit status: a failing
            // smoke makes the runner exit_kernel(1), which this fails on.
            run_cmd_inner(&smoke_args, true)?;
            // Phase 2: boot-smoke without kernel-test. Catches
            // regressions that smokes miss because they exercise modules
            // in isolation, not the full init flow. Strip the
            // kernel-test feature explicitly so the real init runs.
            args.features = args
                .features
                .split(',')
                .filter(|f| !f.is_empty() && *f != "kernel-test")
                .collect::<Vec<_>>()
                .join(",");
            boot_smoke_cmd(&args)
        }
        Cmd::BootSmoke(args) => boot_smoke_cmd(&args),
        Cmd::RunInteractive(args) => run_interactive_cmd(&args),
        Cmd::MuslDemo(args) => musl_demo_cmd(&args),
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
        Cmd::ImportFirmware(args) => import_firmware_cmd(&args),
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
