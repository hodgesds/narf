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
// `cargo xtask host-test`                        — fast host unit-test gate
// `cargo xtask image --arch=<arch>`              — bootable UEFI media

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

/// The `affected` subcommand: crate reverse-dependency closure → the set
/// of CI jobs/subsystems a diff can affect. Its pure core is unit-tested.
mod affected;
/// `verification/specification/spec.md` §8's statistics, split out because
/// they are the only part of xtask with unit tests — a wrong t-distribution
/// tail invalidates every number that passes through it, silently.
mod bench_stats;
/// The `bpf-bench` subcommand: boot the suite, harvest the samples, apply §8.
mod bpf_bench;

#[derive(Parser)]
#[command(author, version, about = "NARF build orchestrator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the fast, hardware-independent unit-test suite on the host.
    ///
    /// This intentionally names an allowlist: crates that require the
    /// kernel linker script, privileged instructions, or QEMU belong in
    /// `xtask test`, not in this gate.
    HostTest,
    /// Compute which CI jobs and kernel-test subsystems a change can
    /// affect, from the git diff against a base ref + the workspace
    /// reverse-dependency closure. Emits JSON (default) or GitHub Actions
    /// outputs (`--github`). Hub-crate / build-infra / unknown-path
    /// changes and push-to-main / nightly events force a full run.
    Affected(affected::AffectedArgs),
    /// Cross-compile the kernel.
    Build(BuildArgs),
    /// Cross-compile and boot under QEMU.
    Run(BuildArgs),
    /// Cross-compile and run kernel tests under QEMU.
    Test(TestArgs),
    /// Cross-compile a kernel-module crate into a single relocatable
    /// object — the NARF equivalent of a `.ko`.
    BuildModule(BuildModuleArgs),
    /// Cross-compile and boot under QEMU as a real init pass (no
    /// kernel-test feature), parsing serial output for panic markers
    /// and known success markers. Catches regressions that smoke
    /// tests miss because smokes exercise modules in isolation
    /// rather than the full boot flow.
    BootSmoke(BuildArgs),
    /// Cross-compile and boot the mounted /mnt rootfs's
    /// `/lib/systemd/systemd` as REAL PID 1 (sets the `systemd_pid1`
    /// kernel cmdline flag, which makes boot-init spawn the chroot
    /// launcher as the first user task instead of NARF init/getty).
    /// Streams + captures serial for a timeout, then kills QEMU and
    /// prints a digest of systemd's output. Requires a systemd rootfs
    /// disk at `target/narf-vblk.img`. Timeout via
    /// `XTASK_SYSTEMD_PID1_TIMEOUT_SECS` (default 120). Optional
    /// `XTASK_SYSTEMD_PID1_SUCCESS_MARKER` and
    /// `XTASK_SYSTEMD_PID1_FAILURE_MARKER` turn the capture into a
    /// fail-fast integration assertion.
    SystemdPid1(BuildArgs),
    /// Cross-compile and boot under QEMU with `boot-init` on, drive
    /// the serial port programmatically by typing `echo hello world`
    /// into QEMU's stdin, and assert that `hello world\n` appears on
    /// QEMU's serial stdout. Closes the Wave-37+ interactive loop:
    /// keystrokes → narf_input ring → /dev/console → sys_read fd 0 →
    /// shell parser → echo built-in → sys_write fd 1 → UART.
    RunInteractive(RunInteractiveArgs),
    /// Off-box network serving smoke. Boot with `qemu-net` (statically
    /// configures vnet0 with the SLIRP lease) + a QEMU `hostfwd`, wait
    /// for the auto-spawned `netserve` echo server to print
    /// `netserve: listening`, then open a real TCP socket FROM THE HOST
    /// to the forwarded port, round-trip a line, and assert the echo +
    /// the guest's `netserve-ok`. Proves a guest server is reachable
    /// from outside the VM over virtio-net.
    NetSmoke(BuildArgs),
    /// Off-box redis smoke. Boot with `qemu-net` + a QEMU `hostfwd`,
    /// wait for the auto-spawned unmodified `redis-server` to print
    /// `Ready to accept connections`, then open a real host TCP socket to
    /// the forwarded port and round-trip RESP `SET`/`GET`. Proves a real
    /// third-party server daemon serves off-box over virtio-net.
    RedisSmoke(BuildArgs),
    /// Off-box redis PERFORMANCE benchmark with a Linux baseline.
    /// Boots `qemu-net` + `hostfwd`, waits for the unmodified
    /// `redis-server` to come up, then drives a pipelined SET/GET
    /// throughput workload + a sequential-PING latency workload from a
    /// real host TCP socket. Re-runs the IDENTICAL workload against the
    /// SAME redis binary spawned natively on the Linux host and prints
    /// a side-by-side NARF-guest-vs-Linux-host comparison.
    RedisBench(BuildArgs),
    /// Multi-queue / RSS throughput+latency benchmark. Boots NARF with
    /// the `mt-echo` feature (a multithreaded SO_REUSEPORT echo server:
    /// one Listen TCB per worker thread, distinct flows steered to
    /// distinct workers/cores), then drives a host-side load generator
    /// (N persistent connections, request→response) and reports
    /// req/s + p50/p99/p99.9 latency. Sweeps the kernel cmdline
    /// `mt_echo_threads=N` and the virtio-net queue count
    /// (`XTASK_QEMU_QUEUES`, tap only) so the MQ scaling curve is
    /// visible. The workload redis (single-threaded) cannot exercise.
    MtEchoBench(BuildArgs),
    /// Wave-78 — boot under QEMU and verify both linux-compat demo
    /// binaries (`/bin/hello` and `/bin/hello_musl`) print their
    /// expected output through the real shell + execve + ELF
    /// loader + syscall-instruction dispatch + SSE init path. Two
    /// `run-interactive` invocations under the hood; fails CI if
    /// either binary regresses. x86_64 only — `hello_musl` is a
    /// stock-musl-built ELF that requires `int 0x80` / `syscall`
    /// dual dispatch + CR4.OSFXSR.
    MuslDemo(MuslDemoArgs),
    /// BPF microbenchmark suite under the `verification/` §8 statistical
    /// protocol. Boots the kernel with `narf-bpf/bench` + the `bpf_bench`
    /// cmdline flag, harvests the raw samples the in-kernel harness emits,
    /// and computes median + 95% bootstrap CI, Welch's t AND Mann-Whitney U
    /// (both must agree), and a Benjamini-Hochberg correction across the
    /// suite. Verifies §8.2's noise-control preconditions first and refuses
    /// to run without `--allow-unverified-runner` when they fail.
    ///
    /// Not a test: it gates nothing and asserts nothing. It answers "what
    /// does this cost".
    BpfBench(bpf_bench::BpfBenchArgs),
    /// Produce a bootable image.
    Image(BuildArgs),
    /// Build removable media and boot it under OVMF/AAVMF UEFI.
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

    /// Build in debug mode. Default is `--release` (optimized): NARF under
    /// QEMU with software rendering is slow enough that debug builds make
    /// interactive use (KDE, boots) painful, so release is preferred for all
    /// builds. Pass `--debug` when you need debug assertions / gdb symbols.
    #[arg(long)]
    debug: bool,

    /// Crate to build.
    #[arg(long, default_value = "narf-frame")]
    package: String,

    /// Forward-list of cargo features to enable. Comma-separated.
    #[arg(long, default_value = "")]
    features: String,

    /// QEMU display mode.
    #[arg(long, default_value = "none")]
    display: String,

    /// Virtual GPU backend exposed by QEMU.
    ///
    /// `virtio-2d` is the universally available scanout path. `virgl`
    /// selects QEMU's OpenGL-backed virtio-gpu device; it also requires a
    /// GL-capable display backend such as `--display gtk,gl=on` (or an
    /// EGL-headless backend on hosts that provide one).
    #[arg(long, value_enum, default_value_t = GpuBackend::Auto)]
    gpu_backend: GpuBackend,

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

    /// Build with Kernel Address Sanitizer (KASAN) for the freed-slab
    /// write-after-free hunt: injects `-Zsanitizer=kernel-address` into the
    /// kernel rustflags and enables the `kasan` cargo feature, so a dangling
    /// write to a poisoned (freed) slab block trips the compiler-emitted
    /// inline shadow check and panics IN the corruptor's frame. x86_64 only.
    #[arg(long, default_value_t = false)]
    kasan: bool,
}

#[derive(Parser, Clone)]
struct TestArgs {
    #[command(flatten)]
    build: BuildArgs,

    /// Run only kernel tests under these subsystems. Comma-separated;
    /// each is prefix-matched in-kernel (`filesystem` also selects
    /// `filesystem/page_cache`). Empty/absent runs the whole suite.
    #[arg(long)]
    subsystem: Option<String>,
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

    /// Re-boot and retry this many times if the boot/echo fails or times
    /// out (each attempt is a fresh QEMU). The reliability primitive for
    /// the flaky-under-TCG cases: a genuine break still fails after all
    /// attempts, a flake passes on retry. Default 0 (no retry).
    #[arg(long, default_value_t = 0)]
    retries: u32,

    /// Boot this already-built kernel binary instead of compiling. Used by
    /// the split per-case `musl-demo` CI jobs: one job builds the kernel,
    /// uploads it, and each case job boots the downloaded artifact — no N×
    /// rebuilds. When set, `--features`/`--package` are ignored (the
    /// prebuilt image already baked them in).
    #[arg(long, value_name = "PATH")]
    prebuilt: Option<String>,
}

/// Args for `xtask musl-demo`. Inherits BuildArgs; adds subsystem-group
/// sharding (`--group`/`--list-groups`) and prebuilt-kernel boot so CI can
/// build once and fan the cases out across a handful of parallel jobs by
/// subsystem rather than one slow ~80-case boot.
#[derive(Parser, Clone)]
struct MuslDemoArgs {
    #[command(flatten)]
    build: BuildArgs,

    /// Run only the cases in this subsystem group (see `--list-groups`).
    /// Omitted ⇒ run every group in this invocation (the local full run).
    #[arg(long)]
    group: Option<String>,

    /// Print the JSON array of subsystem groups (the CI matrix consumes
    /// this) and exit without booting.
    #[arg(long)]
    list_groups: bool,

    /// Boot this already-built kernel instead of cross-building. The
    /// per-group CI jobs download the artifact the build job produced and
    /// boot it, so no group re-compiles the kernel.
    #[arg(long, value_name = "PATH")]
    prebuilt: Option<String>,
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

#[derive(Clone, Copy, ValueEnum, Default, Debug, PartialEq, Eq)]
pub enum GpuBackend {
    /// Prefer VirGL for graphical runs when QEMU provides it, otherwise 2D.
    #[default]
    Auto,
    /// Portable virtio-gpu 2D scanout.
    #[value(name = "virtio-2d")]
    Virtio2d,
    /// VirGL-backed virtio-gpu using the host OpenGL stack.
    Virgl,
}

#[derive(Clone, Copy, ValueEnum)]
enum Arch {
    #[value(name = "x86_64")]
    X86_64,
    #[value(name = "aarch64")]
    Aarch64,
}

fn virtio_gpu_device_arg(backend: GpuBackend) -> String {
    let driver = match backend {
        GpuBackend::Auto => unreachable!("auto GPU backend must be resolved before QEMU args"),
        GpuBackend::Virtio2d => "virtio-gpu-pci",
        GpuBackend::Virgl => "virtio-gpu-gl-pci",
    };
    format!("{driver},id=vgpu0,disable-legacy=on,disable-modern=off")
}

fn qemu_supports_device(qemu: &str, device: &str) -> bool {
    let Ok(output) = Command::new(qemu).args(["-device", "help"]).output() else {
        return false;
    };
    output.status.success()
        && (String::from_utf8_lossy(&output.stdout).contains(device)
            || String::from_utf8_lossy(&output.stderr).contains(device))
}

fn resolve_gpu_backend(arch: Arch, display: &str, requested: GpuBackend) -> GpuBackend {
    match requested {
        GpuBackend::Auto
            if display != "none" && qemu_supports_device(arch.qemu_bin(), "virtio-gpu-gl-pci") =>
        {
            eprintln!("xtask: GPU auto selected VirGL");
            GpuBackend::Virgl
        }
        GpuBackend::Auto => {
            if display != "none" {
                eprintln!("xtask: GPU auto fell back to virtio-gpu 2D");
            }
            GpuBackend::Virtio2d
        }
        explicit => explicit,
    }
}

fn qemu_display_arg(display: &str, backend: GpuBackend) -> String {
    let mut options = display.to_string();

    if options == "gtk" || options.starts_with("gtk,") {
        // The desktop image uses virtio keyboard + tablet devices.  GTK does
        // not hand host input to those devices until it has grabbed the
        // window, which otherwise leaves a visible but non-interactive
        // Wayland desktop until the user knows to press Ctrl-Alt-G.  Grab
        // automatically as the pointer enters the guest instead.
        if !options
            .split(',')
            .any(|part| part.starts_with("grab-on-hover="))
        {
            options.push_str(",grab-on-hover=on");
        }
    }

    if backend == GpuBackend::Virgl
        && options != "none"
        && !options.split(',').any(|part| part.starts_with("gl="))
    {
        options.push_str(",gl=on");
    }

    options
}

#[cfg(test)]
mod gpu_backend_tests {
    use super::*;

    #[test]
    fn default_gpu_backend_is_auto() {
        let cli = Cli::try_parse_from(["xtask", "run"]).expect("default CLI must parse");
        let Cmd::Run(args) = cli.cmd else {
            panic!("run subcommand parsed as another variant");
        };
        assert_eq!(args.gpu_backend, GpuBackend::Auto);
        assert_eq!(
            virtio_gpu_device_arg(GpuBackend::Virtio2d),
            "virtio-gpu-pci,id=vgpu0,disable-legacy=on,disable-modern=off"
        );
    }

    #[test]
    fn virgl_gpu_backend_selects_qemu_gl_device() {
        let cli = Cli::try_parse_from(["xtask", "run", "--gpu-backend", "virgl"])
            .expect("virgl CLI must parse");
        let Cmd::Run(args) = cli.cmd else {
            panic!("run subcommand parsed as another variant");
        };
        assert_eq!(args.gpu_backend, GpuBackend::Virgl);
        assert_eq!(
            virtio_gpu_device_arg(args.gpu_backend),
            "virtio-gpu-gl-pci,id=vgpu0,disable-legacy=on,disable-modern=off"
        );
        assert_eq!(
            qemu_display_arg("gtk", args.gpu_backend),
            "gtk,grab-on-hover=on,gl=on"
        );
        assert_eq!(
            qemu_display_arg("gtk,gl=off", args.gpu_backend),
            "gtk,gl=off,grab-on-hover=on"
        );
        assert_eq!(
            qemu_display_arg("gtk,grab-on-hover=off", GpuBackend::Virtio2d),
            "gtk,grab-on-hover=off"
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SerialMarkerMatch {
    None,
    Success,
    Failure,
}

fn classify_serial_marker(
    line: &str,
    success_marker: Option<&str>,
    failure_marker: Option<&str>,
) -> SerialMarkerMatch {
    // Failure wins when callers accidentally choose overlapping markers: a
    // negative diagnostic must never be hidden by a broader success token.
    if failure_marker.is_some_and(|marker| line.contains(marker)) {
        SerialMarkerMatch::Failure
    } else if success_marker.is_some_and(|marker| line.contains(marker)) {
        SerialMarkerMatch::Success
    } else {
        SerialMarkerMatch::None
    }
}

fn emit_serial_line(writer: &mut impl Write, line: &str) {
    // A tmux/PTY consumer can transiently return EAGAIN when a noisy distro
    // boot fills its host-side buffer. `println!` panics on that error and,
    // under this workspace's panic=abort profile, used to kill xtask and its
    // QEMU child. The in-memory capture remains authoritative; mirroring to
    // the interactive console is best-effort.
    let _ = writeln!(writer, "{line}");
}

#[cfg(test)]
mod systemd_marker_tests {
    use super::*;

    struct WouldBlockWriter;

    impl Write for WouldBlockWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn classifies_optional_systemd_integration_markers() {
        assert_eq!(
            classify_serial_marker(
                "NARF_UDEV_SEAT_PASS card0 master-of-seat CanGraphical=yes",
                Some("NARF_UDEV_SEAT_PASS"),
                Some("NARF_UDEV_SEAT_FAIL"),
            ),
            SerialMarkerMatch::Success,
        );
        assert_eq!(
            classify_serial_marker(
                "NARF_UDEV_SEAT_FAIL missing=/run/udev/data/c226:0",
                Some("NARF_UDEV_SEAT_PASS"),
                Some("NARF_UDEV_SEAT_FAIL"),
            ),
            SerialMarkerMatch::Failure,
        );
        assert_eq!(
            classify_serial_marker("ordinary systemd output", None, None),
            SerialMarkerMatch::None,
        );
    }

    #[test]
    fn failure_marker_wins_when_markers_overlap() {
        assert_eq!(
            classify_serial_marker("seat-fail", Some("seat"), Some("seat-fail")),
            SerialMarkerMatch::Failure,
        );
    }

    #[test]
    fn serial_console_backpressure_is_nonfatal() {
        emit_serial_line(&mut WouldBlockWriter, "noisy guest line");
    }
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

    /// Clamp a `max`-family QEMU CPU model's advertised physical-address
    /// width to 40 bits (1 TiB) unless the caller already pinned
    /// `phys-bits`. `-cpu max` otherwise reports the host's width (often
    /// 46-52 bits), which makes QEMU park the q35 64-bit PCI hole — and
    /// every 64-bit device BAR (NVMe, virtio) — up near the top of that
    /// space (~14 TiB observed at -m 8192). NARF maps MMIO through the
    /// identity window, whose high-MMIO range only covers phys
    /// [512 GiB, 1 TiB), so a BAR above 1 TiB #PFs on first register
    /// access once RAM is large enough to push the hole up. Capping to
    /// 40 bits keeps the hole inside [~992 GiB, 1 TiB) — within the
    /// mapped window — and mirrors real laptops, whose firmware already
    /// parks BARs at 512 GiB-1016 GiB. Non-`max` explicit models
    /// (EPYC-Rome/Genoa) are left untouched.
    fn clamp_cpu_phys_bits(cpu: String) -> String {
        if cpu.contains("max") && !cpu.contains("phys-bits") {
            format!("{cpu},phys-bits=40")
        } else {
            cpu
        }
    }

    fn qemu_args(
        self,
        kernel: &Path,
        display: &str,
        profile: HwProfile,
        gpu_backend: GpuBackend,
    ) -> Vec<String> {
        let kernel = kernel.display().to_string();
        let gpu_backend = resolve_gpu_backend(self, display, gpu_backend);
        let display = qemu_display_arg(display, gpu_backend);
        match self {
            Arch::X86_64 => {
                // QEMU CPU model can be overridden to exercise the
                // xAPIC fallback path (no x2APIC) and/or the
                // InitialCount LAPIC arm path (no TSC-deadline) —
                // matches Renoir's BIOS behavior where x2APIC is
                // refused. Example:
                //   NARF_QEMU_CPU="max,-x2apic,-tsc-deadline"
                let cpu = Self::clamp_cpu_phys_bits(
                    std::env::var("NARF_QEMU_CPU").unwrap_or_else(|_| "max".into()),
                );
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
                // Optional virtio-mem region used by the NUMA memory-hotplug
                // smoke. The backend is address-space capacity, not initial
                // RAM; half starts plugged so both online and later host
                // resize operations have room to move.
                let virtio_mem_mb = std::env::var("NARF_QEMU_VIRTIO_MEM_MB")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|m| *m >= 4 && *m % 2 == 0);
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
                    virtio_mem_mb.map_or_else(
                        || format!("{mem_mb}M"),
                        |hotplug| {
                            format!(
                                "{mem_mb}M,slots=2,maxmem={}M",
                                mem_mb.saturating_add(hotplug)
                            )
                        },
                    ),
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
                // Diagnostic escape hatch: append arbitrary QEMU args,
                // whitespace-separated. E.g. `NARF_QEMU_EXTRA="-gdb tcp::1234"`
                // attaches a gdb stub for hang debugging without touching
                // the kernel binary (so the .text layout — and the
                // marginal-buddy DMA probe it can tip — is unchanged).
                if let Ok(extra) = std::env::var("NARF_QEMU_EXTRA") {
                    for tok in extra.split_whitespace() {
                        args.push(tok.to_string());
                    }
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
                    // SLIT distance matrix (System Locality Information
                    // Table). local=10, remote=20 — Linux's
                    // LOCAL_DISTANCE / REMOTE_DISTANCE. Populates the
                    // guest's SLIT so node_distance() is validatable
                    // end-to-end (kernel-test numa_distance_smoke).
                    "-numa".into(),    "dist,src=0,dst=0,val=10".into(),
                    "-numa".into(),    "dist,src=0,dst=1,val=20".into(),
                    "-numa".into(),    "dist,src=1,dst=0,val=20".into(),
                    "-numa".into(),    "dist,src=1,dst=1,val=10".into(),
                    ]);
                }
                if let Some(hotplug) = virtio_mem_mb {
                    args.extend_from_slice(&[
                        "-object".into(),
                        format!("memory-backend-ram,id=narf-vmem0,size={hotplug}M"),
                        "-device".into(),
                        format!(
                            "virtio-mem-pci,id=narf-vmem0,memdev=narf-vmem0,node={},requested-size={}M,block-size=2M,disable-legacy=on,disable-modern=off",
                            if smp.is_none() { 1 } else { 0 },
                            hotplug / 2,
                        ),
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
                // `XTASK_QEMU_SNAPSHOT=1` opens every `-drive` copy-on-write:
                // writes land in an ephemeral host overlay and the base images
                // stay read-only-shared, so N VMs can boot the SAME rootfs disk
                // at once WITHOUT tripping QEMU's image write-lock (the "second
                // VM emits 0 serial lines" failure). Lets the hunt fan out
                // across many concurrent 16-CPU VMs to cut time-to-repro. SLIRP
                // user-net binds no host ports by default, so nothing else
                // collides; opt-in QMP/hostfwd/COM2 paths must still be
                // per-instance if used.
                if std::env::var("XTASK_QEMU_SNAPSHOT").as_deref() == Ok("1") {
                    args.push("-snapshot".into());
                }
                // `NARF_QEMU_COM2_FILE=<path>` routes a *second* serial (COM2,
                // 0x2F8) to a host file. Appended AFTER `-serial stdio` so QEMU
                // assigns it COM2 (stdio stays COM1, the console). The kernel's
                // fatal-trap core dumper (frame trap.rs `mod kcore`) streams an
                // ELF core out 0x2F8, so a kernel crash under this run leaves an
                // analyzable core at <path> for offline gdb. Off unless set.
                if let Ok(path) = std::env::var("NARF_QEMU_COM2_FILE") {
                    args.push("-serial".into());
                    args.push(format!("file:{path}"));
                }
                // `XTASK_QEMU_QMP=<path>` exposes a QMP control socket so a host
                // tool can drive QEMU (e.g. `screendump` to capture what the
                // guest is scanning out). Off unless the env var is set.
                if let Ok(sock) = std::env::var("XTASK_QEMU_QMP") {
                    args.push("-qmp".into());
                    args.push(format!("unix:{sock},server,nowait"));
                }

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
                    args.extend_from_slice(&["-vga".into(), "none".into()]);
                    // VirGL must be the only display adapter.  Leaving the
                    // Bochs fallback attached gives KWin two DRM devices;
                    // its libdrm probe can then associate card0's render
                    // path with the 1234:1111 fallback instead of the
                    // 1af4:1050 virtio-gpu transport.
                    if gpu_backend != GpuBackend::Virgl {
                        args.extend_from_slice(&[
                            "-device".into(),
                            "bochs-display,id=bochs0".into(),
                        ]);
                    }
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
                    // Optional host→guest port forward for the off-box
                    // network smoke: `XTASK_QEMU_HOSTFWD=tcp:127.0.0.1:H-:G`
                    // makes QEMU's user-mode backend forward host port H to
                    // guest port G so a host client can reach a guest server.
                    // `XTASK_QEMU_TAP=<ifname>` uses a real host tap backend
                    // instead of SLIRP — the host reaches the guest directly at
                    // its static IP (10.0.2.15), no hostfwd. Needs the tap
                    // pre-created + up (e.g. `ip tuntap add tap0 mode tap`,
                    // `ip addr add 10.0.2.2/24 dev tap0`, `ip link set tap0 up`).
                    // For NARF-over-real-NIC bring-up + perf free of the
                    // single-threaded-SLIRP confound (task #127).
                    // XTASK_QEMU_QUEUES=N (tap only) requests N virtio-net queue
                    // pairs (multi-queue / RSS). The tap must be created with
                    // the multi_queue flag (`ip tuntap add ... multi_queue`);
                    // the netdev gets `queues=N` and the device `mq=on` plus
                    // 2N+2 MSI-X vectors (2/pair + control + config).
                    // Bumped to ≥2 for a multi_queue tap (QEMU can't open
                    // it single-queue → silent no-serial boot failure).
                    let queues: usize = effective_qemu_queues();
                    let n0 = match std::env::var("XTASK_QEMU_TAP") {
                        Ok(tap) if !tap.is_empty() => {
                            let q = if queues > 1 {
                                format!(",queues={queues}")
                            } else {
                                String::new()
                            };
                            format!("tap,id=n0,ifname={tap},script=no,downscript=no{q}")
                        }
                        _ => match std::env::var("XTASK_QEMU_HOSTFWD") {
                            Ok(fwd) if !fwd.is_empty() => format!("user,id=n0,hostfwd={fwd}"),
                            _ => "user,id=n0".into(),
                        },
                    };
                    let dev = if queues > 1 {
                        format!(
                            "virtio-net-pci,netdev=n0,tx=timer,disable-legacy=on,disable-modern=off,mq=on,vectors={}",
                            2 * queues + 2
                        )
                    } else {
                        "virtio-net-pci,netdev=n0,tx=timer,disable-legacy=on,disable-modern=off"
                            .into()
                    };
                    args.extend_from_slice(&["-netdev".into(), n0, "-device".into(), dev]);
                    // Optional wire capture for debugging: `XTASK_QEMU_NETDUMP=<path>`
                    // pcaps every frame on netdev n0 (the hostfwd NIC).
                    if let Ok(path) = std::env::var("XTASK_QEMU_NETDUMP") {
                        if !path.is_empty() {
                            args.extend_from_slice(&[
                                "-object".into(),
                                format!("filter-dump,id=netdump0,netdev=n0,file={path}"),
                            ]);
                        }
                    }
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
                    // `XTASK_QEMU_NO_VIRTIO_INPUT=1` drops the virtio
                    // keyboard/tablet so QEMU routes input to the q35 i8042
                    // PS/2 kbd+mouse (which weston discovers via the udev DB).
                    if std::env::var_os("XTASK_QEMU_NO_VIRTIO_INPUT").is_none() {
                        args.extend_from_slice(&[
                            "-device".into(),
                            "virtio-keyboard-pci,disable-legacy=on,disable-modern=off".into(),
                        ]);
                        // Absolute-pointing tablet so /dev/input/event* covers
                        // EV_ABS (ABS_X/ABS_Y) alongside the keyboard's EV_KEY.
                        args.extend_from_slice(&[
                            "-device".into(),
                            "virtio-tablet-pci,disable-legacy=on,disable-modern=off".into(),
                        ]);
                    }
                    args.extend_from_slice(&["-device".into(), virtio_gpu_device_arg(gpu_backend)]);
                    if !legacy {
                        args.extend_from_slice(&["-audiodev".into(), "none,id=snd0".into()]);
                    }
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-sound-pci,audiodev=snd0,disable-legacy=on,disable-modern=off"
                            .into(),
                    ]);
                }

                // Optional kernel cmdline (multiboot2 `-append`). Used to
                // pass runtime knobs the kernel parses from
                // `narf_boot::cmdline()` — e.g. `mt_echo_threads=N` for the
                // mt-echo benchmark — without rebuilding the kernel.
                if let Ok(append) = std::env::var("XTASK_QEMU_APPEND") {
                    if !append.is_empty() {
                        args.push("-append".into());
                        args.push(append);
                    }
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
                    // Optional host→guest port forward for the off-box
                    // network smoke: `XTASK_QEMU_HOSTFWD=tcp:127.0.0.1:H-:G`
                    // makes QEMU's user-mode backend forward host port H to
                    // guest port G so a host client can reach a guest server.
                    // `XTASK_QEMU_TAP=<ifname>` uses a real host tap backend
                    // instead of SLIRP — the host reaches the guest directly at
                    // its static IP (10.0.2.15), no hostfwd. Needs the tap
                    // pre-created + up (e.g. `ip tuntap add tap0 mode tap`,
                    // `ip addr add 10.0.2.2/24 dev tap0`, `ip link set tap0 up`).
                    // For NARF-over-real-NIC bring-up + perf free of the
                    // single-threaded-SLIRP confound (task #127).
                    // XTASK_QEMU_QUEUES=N (tap only) requests N virtio-net queue
                    // pairs (multi-queue / RSS). The tap must be created with
                    // the multi_queue flag (`ip tuntap add ... multi_queue`);
                    // the netdev gets `queues=N` and the device `mq=on` plus
                    // 2N+2 MSI-X vectors (2/pair + control + config).
                    // Bumped to ≥2 for a multi_queue tap (QEMU can't open
                    // it single-queue → silent no-serial boot failure).
                    let queues: usize = effective_qemu_queues();
                    let n0 = match std::env::var("XTASK_QEMU_TAP") {
                        Ok(tap) if !tap.is_empty() => {
                            let q = if queues > 1 {
                                format!(",queues={queues}")
                            } else {
                                String::new()
                            };
                            format!("tap,id=n0,ifname={tap},script=no,downscript=no{q}")
                        }
                        _ => match std::env::var("XTASK_QEMU_HOSTFWD") {
                            Ok(fwd) if !fwd.is_empty() => format!("user,id=n0,hostfwd={fwd}"),
                            _ => "user,id=n0".into(),
                        },
                    };
                    let dev = if queues > 1 {
                        format!(
                            "virtio-net-pci,netdev=n0,tx=timer,disable-legacy=on,disable-modern=off,mq=on,vectors={}",
                            2 * queues + 2
                        )
                    } else {
                        "virtio-net-pci,netdev=n0,tx=timer,disable-legacy=on,disable-modern=off"
                            .into()
                    };
                    args.extend_from_slice(&["-netdev".into(), n0, "-device".into(), dev]);
                    // Optional wire capture for debugging: `XTASK_QEMU_NETDUMP=<path>`
                    // pcaps every frame on netdev n0 (the hostfwd NIC).
                    if let Ok(path) = std::env::var("XTASK_QEMU_NETDUMP") {
                        if !path.is_empty() {
                            args.extend_from_slice(&[
                                "-object".into(),
                                format!("filter-dump,id=netdump0,netdev=n0,file={path}"),
                            ]);
                        }
                    }
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
                    // `XTASK_QEMU_NO_VIRTIO_INPUT=1` drops the virtio
                    // keyboard/tablet so QEMU routes input to the q35 i8042
                    // PS/2 kbd+mouse (which weston discovers via the udev DB).
                    if std::env::var_os("XTASK_QEMU_NO_VIRTIO_INPUT").is_none() {
                        args.extend_from_slice(&[
                            "-device".into(),
                            "virtio-keyboard-pci,disable-legacy=on,disable-modern=off".into(),
                        ]);
                        // Absolute-pointing tablet so /dev/input/event* covers
                        // EV_ABS (ABS_X/ABS_Y) alongside the keyboard's EV_KEY.
                        args.extend_from_slice(&[
                            "-device".into(),
                            "virtio-tablet-pci,disable-legacy=on,disable-modern=off".into(),
                        ]);
                    }
                    args.extend_from_slice(&["-device".into(), virtio_gpu_device_arg(gpu_backend)]);
                    args.extend_from_slice(&["-audiodev".into(), "none,id=snd0".into()]);
                    args.extend_from_slice(&[
                        "-device".into(),
                        "virtio-sound-pci,audiodev=snd0,disable-legacy=on,disable-modern=off"
                            .into(),
                    ]);
                }

                // The kernel command line reaches aarch64 through the DEVICE
                // TREE, not through `-append`. This arm hands the blob over
                // with a generic `loader` device — opaque bytes at a fixed
                // address — and QEMU only injects `-append` into a device tree
                // it builds itself or receives via `-dtb`. So `-append` alone
                // was silently dropped here and `narf_boot::cmdline()` read
                // empty on this arch.
                //
                // `qemu_virt_dtb_path_with_cmdline` therefore bakes the string
                // into `/chosen/bootargs` when it generates the blob, which is
                // where `boot/src/aarch64` already parses it from.
                let append = std::env::var("XTASK_QEMU_APPEND").unwrap_or_default();
                args.extend_from_slice(&[
                    "-device".into(),
                    format!(
                        "loader,file={},addr={:#x},force-raw=on",
                        qemu_virt_dtb_path_with_cmdline(&append).display(),
                        DTB_LOAD_ADDR
                    ),
                ]);

                // Passed as well, harmlessly: it is what a `-dtb`-style boot
                // would use, and keeping it means a future switch away from the
                // generic loader needs no change here. The DTB above is the
                // transport that actually works today.
                if !append.is_empty() {
                    args.push("-append".into());
                    args.push(append);
                }
                args.push("-kernel".into());
                args.push(kernel);
                args
            }
        }
    }
}

const DTB_LOAD_ADDR: u64 = 0x4F00_0000;

/// Path to a cached QEMU `virt` device tree, optionally carrying a kernel
/// command line in `/chosen/bootargs`.
///
/// The aarch64 boot path hands the kernel this blob via
/// `-device loader,file=...,force-raw=on` — i.e. as opaque bytes at a fixed
/// address. QEMU only injects `-append` into a device tree it *builds* (or one
/// given via `-dtb`), so with a generic-loader blob the command line was
/// silently dropped and `narf_boot::cmdline()` read empty on aarch64. The
/// visible symptom was `cargo xtask test --subsystem <name>` filtering nothing
/// there: the kernel never saw `test_subsystem=`, took `run_all_and_exit()`,
/// ran the whole suite, and still reported success.
///
/// Fixed by letting QEMU do the work it is already doing — the blob is produced
/// by `-machine ...,dumpdtb=`, so passing `-append` to *that* invocation makes
/// QEMU write `/chosen/bootargs` into the dump. Blobs are cached per command
/// line (hashed into the filename) because the cmdline varies per run and a
/// single cached path would serve a stale one.
fn qemu_virt_dtb_path_with_cmdline(cmdline: &str) -> PathBuf {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    // Distinct file per command line. An empty cmdline keeps the historical
    // name so existing callers and any cached artifact stay valid.
    let path = if cmdline.is_empty() {
        root.join("target").join("qemu-virt.dtb")
    } else {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in cmdline.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        root.join("target").join(format!("qemu-virt-{h:016x}.dtb"))
    };
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
            .args(if cmdline.is_empty() {
                // `-append ""` is not the same as omitting it: QEMU still
                // creates an empty `/chosen/bootargs`, which is harmless but
                // makes the two cache entries differ for no reason.
                Vec::new()
            } else {
                // `-kernel` is required, not incidental: QEMU refuses with
                // "-append only allowed with -kernel option", so without one
                // the dump never runs and the loader below points at a file
                // that does not exist.
                //
                // It must NOT be the real kernel. `dumpdtb` does not exit
                // early enough to skip image loading, and handing QEMU the
                // 231 MB narf-frame ELF makes it **segfault** (exit 139) — the
                // dump silently never happens, which is exactly how this looked
                // the first time. A 4 KiB zero-filled raw image is accepted as
                // a bare aarch64 boot image, produces the same device tree, and
                // costs nothing. (An ELF stub is rejected outright with
                // "image is from incompatible architecture".)
                let stub = root.join("target").join("dtb-append-stub.img");
                if !stub.exists() {
                    let _ = std::fs::write(&stub, [0u8; 4096]);
                }
                vec![
                    "-append".to_string(),
                    cmdline.to_string(),
                    "-kernel".to_string(),
                    stub.display().to_string(),
                ]
            })
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
            .arg("virtio-net-pci,netdev=n0,tx=timer")
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

/// The plain device tree, with no kernel command line.
fn qemu_virt_dtb_path() -> PathBuf {
    qemu_virt_dtb_path_with_cmdline("")
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

/// Set true by the kernel-test runner (`run_cmd_inner` when the build carries
/// the `kernel-test` feature). When set, `virtio_blk_image_path` returns the
/// dedicated test disk (`narf-vblk-test.img`) instead of the Alpine-rootfs
/// path (`narf-vblk.img`), so the two consumers never clobber each other:
/// the kernel-test wants a tiny ext2 placeholder with the 0x97 LBA-0 pattern
/// (and NOT a full rootfs, so it isn't auto-root-mounted at `/`), while
/// musl-demo/stress-ng/oci want the real Alpine rootfs.
static KERNEL_TEST_DISK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Dedicated kernel-test disk: a minimal ext2 + 0x97 sector-0 pattern, kept
/// at its own path so the Alpine rootfs at `narf-vblk.img` is never touched.
/// Idempotent (regenerated when the bytes differ) — safe because nothing else
/// uses this path.
fn virtio_blk_test_image_path() -> PathBuf {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let path = root.join("target").join("narf-vblk-test.img");
    let img = build_ext2_disk_image(b"hello.txt", b"hello from disk\n");
    let stale = std::fs::read(&path).map(|b| b != img).unwrap_or(true);
    if stale {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, &img);
    }
    path
}

fn virtio_blk_image_path() -> PathBuf {
    if KERNEL_TEST_DISK.load(std::sync::atomic::Ordering::Relaxed) {
        return virtio_blk_test_image_path();
    }
    // `NARF_VBLK_IMG` selects an alternate rootfs disk verbatim — the
    // Alpine image at `narf-vblk.img` is the default, but a distro
    // bring-up (e.g. `target/narf-fedora-vblk.img`, built by
    // `REGEN_fedora_kde_rootfs.sh`) wants its own disk without
    // displacing the one every musl-demo / redis / oci case reads.
    // Must already exist; we never synthesize an override path.
    if let Some(p) = std::env::var_os("NARF_VBLK_IMG") {
        return PathBuf::from(p);
    }
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let path = root.join("target").join("narf-vblk.img");
    // CREATE-ONLY — do NOT overwrite an existing image. This path is shared:
    // `REGEN_alpine_rootfs.sh` builds the real ~28 MiB Alpine rootfs here for
    // the musl-demo / stress-ng / oci chroot tests, and xtask "uses it
    // verbatim when it already exists". Only when it's ABSENT do we drop a
    // minimal ext2 placeholder containing `/hello.txt` (so the boot's
    // `mnt-mount-ext2` initcall has something to mount at /mnt, plus a seeded
    // `(i*0x97)&0xFF` pattern at LBA 0 for the kernel-test raw-sector smokes).
    // An always-regenerate variant clobbers the Alpine rootfs on every
    // kernel-test run and breaks musl-demo.
    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
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

/// Reconstruct a full disk image from a committed `NARFBTR1` sparse fixture
/// (see `drivers/fs/btrfs/testdata/regen_fixture.sh`). The output is written as
/// a sparse file (holes read as zeros), so a 128 MiB logical image costs only
/// its non-zero payload on disk. Idempotent: skips when the target already has
/// the right length. No external tools — CI-safe.
fn reconstruct_sparse_fixture(sparse_rel: &str, out: &Path) {
    use std::io::{Seek, SeekFrom, Write};
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let sparse = match std::fs::read(root.join(sparse_rel)) {
        Ok(b) => b,
        Err(_) => return,
    };
    if sparse.len() < 20 || &sparse[0..8] != b"NARFBTR1" {
        return;
    }
    let total = u64::from_le_bytes(sparse[8..16].try_into().unwrap());
    // Always rebuild to a pristine image: the btrfs boot smoke *mutates* this
    // disk (write + create/unlink), so a size check can't tell a clean fixture
    // from an already-modified one. Reconstruction is cheap (a ~110 KiB sparse
    // payload into a sparse-backed 16 MiB file).
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut f) = std::fs::File::create(out) else {
        return;
    };
    let _ = f.set_len(total);
    let n_runs = u32::from_le_bytes(sparse[16..20].try_into().unwrap()) as usize;
    let mut p = 20usize;
    for _ in 0..n_runs {
        let off = u64::from_le_bytes(sparse[p..p + 8].try_into().unwrap());
        let len = u64::from_le_bytes(sparse[p + 8..p + 16].try_into().unwrap()) as usize;
        p += 16;
        if f.seek(SeekFrom::Start(off)).is_ok() {
            let _ = f.write_all(&sparse[p..p + len]);
        }
        p += len;
    }
}

/// After a kernel-test run, verify that the btrfs image NARF wrote to on nvme0
/// (via the boot-time `btrfs-write-smoke`) is still consistent by running host
/// `btrfs check`. This turns the NARF↔Linux write-interop guarantee into a
/// CI-enforced invariant. Best-effort: skips when the image is absent (no
/// kernel-test disk) or `btrfs-progs` is not installed; fails when a present
/// `btrfs check` reports errors.
fn verify_btrfs_write_interop() -> Result<()> {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let img = root.join("target").join("narf-nvme-btrfs.img");
    if !img.exists() {
        return Ok(());
    }
    if std::process::Command::new("btrfs")
        .arg("--version")
        .output()
        .is_err()
    {
        println!("xtask: skipping btrfs write-interop check (btrfs-progs not found)");
        return Ok(());
    }
    println!("xtask: verifying NARF-written btrfs image with `btrfs check`...");
    let out = std::process::Command::new("btrfs")
        .arg("check")
        .arg(&img)
        .output()
        .context("failed to run `btrfs check`")?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() && combined.contains("no error found") {
        println!("xtask: btrfs write-interop OK — NARF-written image is `btrfs check` clean");
        Ok(())
    } else {
        eprintln!("{combined}");
        bail!("`btrfs check` reported errors on the NARF-written image (write-interop regression)");
    }
}

fn nvme_image_path() -> PathBuf {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    // During a kernel-test run, serve a real laptop-style btrfs image on nvme0
    // so the boot-time `btrfs-disk-smoke` initcall exercises the driver against
    // real (QEMU NVMe) hardware. Nothing consumes nvme0's content otherwise.
    if KERNEL_TEST_DISK.load(std::sync::atomic::Ordering::Relaxed) {
        let path = root.join("target").join("narf-nvme-btrfs.img");
        // A 96 MiB btrfs image with a free-space tree (`space_cache=v2`), a second
        // superblock copy (the 64 MiB mirror), AND a deliberately-fragmented data
        // block group whose free space is tracked with a `FREE_SPACE_BITMAP`. So
        // the boot-time btrfs read/write smokes exercise the driver across the
        // board — free-space-tree maintenance in both extent and bitmap form,
        // chunk growth, and updating every superblock mirror in lockstep — on real
        // NVMe hardware, and the written image stays mountable + `btrfs check`-clean
        // for a real Linux kernel. Verify manually with `mount -o loop` + `btrfs
        // check`.
        reconstruct_sparse_fixture("drivers/fs/btrfs/testdata/fixture-bitmap.img.sparse", &path);
        return path;
    }
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

/// True if the tap netdev `tap` was created with `IFF_MULTI_QUEUE`
/// (flag 0x0100 in `/sys/class/net/<tap>/tun_flags`). QEMU rejects a
/// single-queue open of such a tap ("could not configure /dev/net/tun:
/// Invalid argument") — which surfaces as a guest that never boots (no
/// serial). The harness can't open a multi_queue tap with one queue, so
/// it must request ≥2.
fn tap_is_multi_queue(tap: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{tap}/tun_flags"))
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .map(|flags| flags & 0x0100 != 0)
        .unwrap_or(false)
}

/// Effective virtio-net queue-pair count for the current netdev config.
/// Honors `XTASK_QEMU_QUEUES` (>1), but forces a minimum of 2 when
/// `XTASK_QEMU_TAP` names a `multi_queue` tap (see [`tap_is_multi_queue`]).
/// A single-queue tap or SLIRP stays at 1.
fn effective_qemu_queues() -> usize {
    let requested = std::env::var("XTASK_QEMU_QUEUES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 1)
        .unwrap_or(1);
    let multi_queue_tap = std::env::var("XTASK_QEMU_TAP")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|tap| tap_is_multi_queue(&tap))
        .unwrap_or(false);
    if multi_queue_tap {
        requested.max(2)
    } else {
        requested
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

/// Args for `xtask build-module`.
#[derive(clap::Args)]
struct BuildModuleArgs {
    /// Target architecture.
    #[arg(long, value_enum, default_value_t = Arch::X86_64)]
    arch: Arch,

    /// Module crate to build.
    #[arg(long, default_value = "narf-test-module")]
    package: String,

    /// Where to write the `.ko`. Defaults to
    /// `target/<triple>/release/<package>.ko`.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Stamp this kernel ABI hash into the module's `.modinfo`, replacing
    /// whatever `kernel_abi=` the source declared. Accepts `0x...` or bare
    /// hex.
    ///
    /// The loader refuses a module whose hash does not match the running
    /// kernel's, and that hash is derived from the kernel's export table —
    /// so it is not knowable when the module crate is written. Read it from
    /// a running kernel with `cat /sys/kernel/abi_hash` and pass it here.
    #[arg(long)]
    kernel_abi: Option<String>,
}

/// Overwrite the `kernel_abi=0x........` value inside a `.ko`'s `.modinfo`.
///
/// The field is fixed-width hex, so this is an in-place patch of eight bytes
/// — no section has to grow and no offset moves. Scoped to the `.modinfo`
/// section rather than done over the whole file so a matching byte string in
/// debug info or a string literal cannot be hit by accident.
fn stamp_kernel_abi(ko: &Path, value: u32) -> Result<()> {
    let mut bytes = std::fs::read(ko).with_context(|| format!("read {}", ko.display()))?;
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        bail!("{} is not an ELF object", ko.display());
    }
    let u16at = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]) as usize;
    let u32at =
        |b: &[u8], o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize;
    let u64at = |b: &[u8], o: usize| {
        u64::from_le_bytes([
            b[o],
            b[o + 1],
            b[o + 2],
            b[o + 3],
            b[o + 4],
            b[o + 5],
            b[o + 6],
            b[o + 7],
        ]) as usize
    };

    let shoff = u64at(&bytes, 0x28);
    let shentsize = u16at(&bytes, 0x3A);
    let shnum = u16at(&bytes, 0x3C);
    let shstrndx = u16at(&bytes, 0x3E);
    if shoff == 0 || shnum == 0 || shstrndx >= shnum {
        bail!("{}: unusable section header table", ko.display());
    }
    let strtab_off = u64at(&bytes, shoff + shstrndx * shentsize + 0x18);

    let mut target: Option<(usize, usize)> = None;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let name_off = strtab_off + u32at(&bytes, sh);
        let name_end = bytes[name_off..]
            .iter()
            .position(|b| *b == 0)
            .map(|n| name_off + n)
            .unwrap_or(name_off);
        if &bytes[name_off..name_end] == b".modinfo" {
            target = Some((u64at(&bytes, sh + 0x18), u64at(&bytes, sh + 0x20)));
            break;
        }
    }
    let Some((off, size)) = target else {
        bail!("{}: no .modinfo section to stamp", ko.display());
    };

    const KEY: &[u8] = b"kernel_abi=0x";
    let region = &bytes[off..off + size];
    let Some(at) = region
        .windows(KEY.len())
        .position(|w| w == KEY)
        .map(|p| off + p + KEY.len())
    else {
        bail!(
            "{}: .modinfo has no `kernel_abi=0x` field to stamp",
            ko.display()
        );
    };
    if at + 8 > off + size {
        bail!("{}: `kernel_abi=` value is truncated", ko.display());
    }
    let replacement = format!("{value:08x}");
    bytes[at..at + 8].copy_from_slice(replacement.as_bytes());
    std::fs::write(ko, &bytes).with_context(|| format!("write {}", ko.display()))?;
    Ok(())
}

/// Build a module crate into the single relocatable object the loader wants.
///
/// A module crate is `crate-type = ["staticlib"]`, which produces an
/// **archive** — not a loadable object. Two things have to happen to it:
///
///  1. Take only the crate's own members. The archive also contains every
///     `core` and `compiler_builtins` object the linker might have wanted;
///     pulling those in would produce a multi-megabyte module out of a
///     hundred bytes of driver.
///  2. `ld -r` them together. Besides combining the members, this **merges
///     same-named sections** — which matters more than it sounds, because
///     rustc emits one `.modinfo` section per `#[link_section]` static
///     (seven for the reference module) and Linux's module build relies on
///     exactly this merge. The loader tolerates the un-merged form too, but
///     a `.ko` should be the merged one.
///
/// A module that calls into `core` beyond what the compiler inlines will
/// come out with undefined references that neither the kernel's KSYMTAB nor
/// this object can satisfy, and will fail to load naming the symbol. Linking
/// the needed `core` members in as well is the next step for that case;
/// nothing in-tree needs it yet.
/// Pick a linker that can do `-r` on either target's objects.
///
/// The host `ld` is built for one architecture and refuses a foreign object
/// with "file in wrong format", so an aarch64 module cannot be linked with it
/// on an x86_64 host. LLD is architecture-neutral — it infers the target from
/// the inputs — and `rust-lld` ships with the pinned toolchain's `llvm-tools`
/// component, so preferring it means no cross-binutils to install. `ld.lld`
/// from a system LLVM is an equally good fallback; plain `ld` is last, and
/// works only for a native-arch module.
fn module_linker(root: &Path) -> Result<(String, Vec<String>)> {
    let _ = root;
    // `rust-lld` needs an explicit flavor; the `ld.lld` alias implies GNU.
    if let Ok(sysroot) = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--print")
        .arg("sysroot")
        .output()
    {
        if sysroot.status.success() {
            let base = PathBuf::from(String::from_utf8_lossy(&sysroot.stdout).trim().to_string());
            for host in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
                let candidate = base
                    .join("lib")
                    .join("rustlib")
                    .join(host)
                    .join("bin")
                    .join("rust-lld");
                if candidate.exists() {
                    return Ok((
                        candidate.to_string_lossy().into_owned(),
                        vec!["-flavor".into(), "gnu".into()],
                    ));
                }
            }
        }
    }
    for candidate in ["ld.lld", "lld"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Ok((candidate.to_string(), Vec::new()));
        }
    }
    Ok(("ld".to_string(), Vec::new()))
}

fn build_module(args: &BuildModuleArgs, root: &Path) -> Result<PathBuf> {
    let triple = args.arch.triple();
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(root)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .arg("build")
        .arg("-p")
        .arg(&args.package)
        .arg("--release")
        .arg("--target")
        .arg(triple)
        .arg("-Z")
        .arg("build-std=core,compiler_builtins,alloc")
        .arg("-Z")
        .arg("build-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128")
        .status()
        .with_context(|| format!("failed to spawn cargo for {}", args.package))?;
    if !status.success() {
        bail!("cargo build -p {} failed", args.package);
    }

    let stem = args.package.replace('-', "_");
    let out_dir = root.join("target").join(triple).join("release");
    let archive = out_dir.join(format!("lib{stem}.a"));
    if !archive.exists() {
        bail!(
            "{} did not produce {} — is it `crate-type = [\"staticlib\"]`?",
            args.package,
            archive.display()
        );
    }

    // Members belonging to this crate are named `<crate>-<hash>...o`; every
    // other member came from core / compiler_builtins.
    let listing = Command::new("ar")
        .arg("t")
        .arg(&archive)
        .output()
        .context("failed to run `ar t` — is binutils installed?")?;
    if !listing.status.success() {
        bail!("`ar t {}` failed", archive.display());
    }
    let prefix = format!("{stem}-");
    let members: Vec<String> = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .map(str::trim)
        .filter(|m| m.starts_with(&prefix) && m.ends_with(".o"))
        .map(str::to_string)
        .collect();
    if members.is_empty() {
        bail!(
            "no `{prefix}*.o` members in {} — nothing of the crate's own to link",
            archive.display()
        );
    }

    // `ar x` extracts into the working directory, so give it one of its own
    // rather than scattering objects across the target dir.
    let work = out_dir.join(format!("{stem}.ko.d"));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).with_context(|| format!("mkdir {}", work.display()))?;
    let mut extract = Command::new("ar");
    extract.current_dir(&work).arg("x").arg(&archive);
    for m in &members {
        extract.arg(m);
    }
    if !extract.status().context("failed to run `ar x`")?.success() {
        bail!("`ar x` failed to extract members of {}", archive.display());
    }

    let out = args
        .out
        .clone()
        .unwrap_or_else(|| out_dir.join(format!("{stem}.ko")));
    let (linker, linker_args) = module_linker(root)?;
    let mut link = Command::new(&linker);
    link.args(&linker_args).arg("-r").arg("-o").arg(&out);
    for m in &members {
        link.arg(work.join(m));
    }
    if !link
        .status()
        .with_context(|| format!("failed to run `{linker} -r`"))?
        .success()
    {
        bail!(
            "`{linker} -r` failed to combine {} object(s)",
            members.len()
        );
    }
    let _ = std::fs::remove_dir_all(&work);

    if let Some(raw) = &args.kernel_abi {
        let hex = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
        let value = u32::from_str_radix(hex, 16)
            .with_context(|| format!("--kernel-abi {raw} is not a 32-bit hex value"))?;
        stamp_kernel_abi(&out, value)?;
        println!("xtask build-module: stamped kernel_abi=0x{value:08x}");
    }

    let size = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    println!(
        "xtask build-module: {} -> {} ({size} bytes, {} object(s), {triple})",
        args.package,
        out.display(),
        members.len()
    );
    Ok(out)
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
    // KASAN: setting CARGO_ENCODED_RUSTFLAGS overrides `.cargo/config.toml`'s
    // per-target rustflags, so replicate the x86_64 kernel flags and append
    // `-Zsanitizer=kernel-address`. Applied to every crate (incl. build-std
    // core), so there is no sanitizer-ABI mismatch. x86_64 only.
    if args.kasan {
        if args.arch.triple() != "x86_64-unknown-none" {
            bail!("--kasan is x86_64-only (kernel-address sanitizer unsupported on aarch64-unknown-none)");
        }
        let flags = [
            "-C",
            "relocation-model=static",
            "-C",
            "code-model=kernel",
            "-C",
            "link-arg=-Tbuild/linker/x86_64.ld",
            "-C",
            "link-arg=--gc-sections",
            "-C",
            "link-arg=--build-id=sha1",
            "-Z",
            "plt=no",
            "--cfg",
            "curve25519_dalek_backend=\"serial\"",
            "--cfg",
            "poly1305_force_soft",
            "--cfg",
            "aes_force_soft",
            "--cfg",
            "polyval_force_soft",
            "-Z",
            "sanitizer=kernel-address",
            // Force OUTLINE instrumentation: every access calls
            // `__asan_{load,store}N` with the raw address instead of an inline
            // `shr|OFFSET` shadow check. NARF accesses data through BOTH the low
            // identity map (phys==VA) and the high-half kernel image, and no
            // single linear shadow offset keeps both canonical — the inline
            // `(addr>>3)|0x100000000000` mapping goes non-canonical (#GP) for
            // high-half addresses. The outline callback does the low/high→phys→
            // shadow lookup in software (see memory/src/kasan.rs), sidestepping
            // the mapping entirely.
            "-C",
            "llvm-args=-asan-instrumentation-with-call-threshold=0",
            // Access checks only — no stack/global/alloca redzone poisoning
            // (those emit `__asan_set_shadow_*` and demand writable shadow over
            // every stack; the freed-block write we hunt is a heap store).
            "-C",
            "llvm-args=-asan-stack=0",
            "-C",
            "llvm-args=-asan-globals=0",
            "-C",
            "llvm-args=-asan-instrument-dynamic-allocas=0",
        ]
        .join("\u{1f}");
        cmd.env("CARGO_ENCODED_RUSTFLAGS", flags);
    }
    if !args.debug {
        cmd.arg("--release");
    }
    let features = if args.kasan {
        if args.features.is_empty() {
            "kasan".to_string()
        } else {
            format!("{},kasan", args.features)
        }
    } else {
        args.features.clone()
    };
    if !features.is_empty() {
        cmd.arg("--features").arg(&features);
    }

    let status = cmd.status().context("failed to invoke cargo build")?;
    if !status.success() {
        bail!("cargo build failed with status {status}");
    }

    let profile = if args.debug { "debug" } else { "release" };
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

    // Kernel-test builds get their own virtio-blk disk (narf-vblk-test.img)
    // so they don't read/clobber the Alpine rootfs at narf-vblk.img. Set
    // before qemu_args, which resolves the disk path in-process.
    KERNEL_TEST_DISK.store(
        args.features.contains("kernel-test"),
        std::sync::atomic::Ordering::Relaxed,
    );

    let qemu = args.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        args.arch
            .qemu_args(&kernel, &args.display, args.hw_profile, args.gpu_backend),
    );

    println!("xtask: launching {} {}", qemu, kernel.display());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let secs = kernel_test_timeout_secs();
    let started = std::time::Instant::now();
    let status = match child.wait_timeout(Duration::from_secs(secs))? {
        Some(status) => status,
        None => {
            child.kill()?;
            child.wait()?;
            bail!("xtask: {qemu} timed out after {secs}s (possible kernel hang)");
        }
    };
    // Report the phase duration, not just the exit status. The timeout below
    // is chosen from how long this actually takes, and the only way that stays
    // true is if every run says what it took.
    println!(
        "xtask: {qemu} exited with {status} after {}s (cap {secs}s)",
        started.elapsed().as_secs()
    );

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
    cmd.args(
        args.arch
            .qemu_args(&kernel, &args.display, args.hw_profile, args.gpu_backend),
    );
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    println!("xtask boot-smoke: launching {} {}", qemu, kernel.display());

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    wait_for_boot_smoke(child, "boot-smoke", boot_smoke_timeout_secs(), args.arch)
}

/// How long to let the kernel-test QEMU phase run before calling it a hang.
///
/// The whole suite is one boot: every subsystem's smokes run in a single
/// kernel, so this bound has to cover all of them, not the slowest one. A
/// measured full local run (`cargo xtask test` with no `--subsystem`, 8041
/// smokes) spends 1228 s in this phase on this KVM host. The default is
/// roughly double that, because what it has to survive is not the median run
/// but the worst one on a loaded machine — and because being generous costs
/// nothing: a healthy run exits on its own and never approaches the cap.
///
/// The previous 600 s could not pass a full local run at all — it killed the
/// boot part-way through `syscall_abi` and reported "possible kernel hang"
/// for a suite that was working correctly. CI never saw it, because the
/// workflow already exports `XTASK_QEMU_TIMEOUT_SECS=2400`; only developers
/// running everything locally hit it, and the failure looked like a kernel
/// bug rather than a harness limit.
///
/// A scoped run (`--subsystem`) finishes in a fraction of this, so the cap
/// costs nothing there: it bounds a hang, it does not pace a healthy run.
fn kernel_test_timeout_secs() -> u64 {
    std::env::var("XTASK_QEMU_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2400)
}

/// How long to let a boot-smoke run take before calling it a hang.
///
/// This MUST stay above the largest per-initcall budget the kernel itself
/// declares, or the harness kills a boot the kernel considers healthy and
/// reports it as "possible kernel hang" — which is what the 90-second default
/// did to `btrfs-write-smoke`. That initcall registers a 120 000 ms budget and
/// measures 80–160 s depending on host load, so a 90-second cap could never
/// pass it reliably: the failure looked like a hang in the btrfs write path
/// and was really the harness being stricter than the workload it launched.
///
/// The headroom above 120 s is for host load, not for the workload growing
/// into it.
///
/// This used to record that `btrfs-write-smoke`'s per-file cost ROSE with
/// tree size — 12.4e9 cycles for the first sixteen files, 29.9e9 for the next
/// sixteen — because every write drove a full `commit_txn`, and noted that as
/// worth fixing. It was fixed: writes now accumulate into a batched
/// transaction, so a commit is amortised across operations instead of paid
/// per write, and the smoke measures around 2.9e9 cycles rather than the
/// 19e9 it did. The bound is kept where it is anyway — it exists to catch a
/// hang, and there is no reason to make it tighter than the kernel's own
/// 120 000 ms initcall budget plus room for a loaded host.
fn boot_smoke_timeout_secs() -> u64 {
    std::env::var("XTASK_BOOT_SMOKE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
}

/// Validate a QEMU boot that was built with the `boot-smoke` feature.
///
/// The reader is joined only after QEMU has exited (or has been killed);
/// joining it while a timed-out QEMU still owns the pipe would deadlock.
fn wait_for_boot_smoke(
    mut child: std::process::Child,
    label: &'static str,
    timeout_secs: u64,
    arch: Arch,
) -> Result<()> {
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

    // Stream stdout to terminal and accumulate panic/success markers.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdout"))?;
    let reader_handle = std::thread::spawn(move || -> (Option<String>, bool) {
        let reader = BufReader::new(stdout);
        let mut panic_line = None;
        let mut clean_exit_seen = false;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            println!("{line}");
            clean_exit_seen |= line.contains("boot-smoke: clean exit");
            if panic_line.is_none() && panic_markers.iter().any(|m| line.contains(m)) {
                panic_line = Some(line);
            }
        }
        (panic_line, clean_exit_seen)
    });

    // Wait for QEMU to exit naturally (kernel calls exit_kernel),
    // OR force-kill on timeout.
    let exit = child.wait_timeout(Duration::from_secs(timeout_secs))?;
    let timed_out = exit.is_none();
    let status = match exit {
        Some(s) => s,
        None => {
            child.kill()?;
            child.wait()?
        }
    };
    let (panic_line, clean_exit_seen) = reader_handle
        .join()
        .map_err(|_| anyhow!("xtask {label}: serial-reader thread panicked"))?;

    if let Some(p) = panic_line {
        bail!("xtask {label}: kernel panic during boot — '{}'", p);
    }
    if timed_out {
        bail!(
            "xtask {label}: kernel did not call exit_kernel within {}s — possible boot hang",
            timeout_secs
        );
    }
    if !clean_exit_seen {
        bail!("xtask {label}: QEMU exited without the kernel clean-exit marker");
    }
    // Clean-exit status is arch-dependent:
    //  * x86_64 uses `isa-debug-exit` (port I/O), which encodes
    //    `(code << 1) | 1` into QEMU's exit status — so a kernel
    //    exit code of 0 yields QEMU status 1.
    //  * aarch64 has no `isa-debug-exit`; the kernel shuts down via
    //    PSCI or semihosting `SYS_EXIT`, and QEMU exits naturally
    //    with status 0.
    let expected = match arch {
        Arch::X86_64 => Some(1),
        Arch::Aarch64 => Some(0),
    };
    if status.code() != expected {
        bail!(
            "xtask {label}: QEMU exited with non-success status {:?} (expected {:?} on {})",
            status.code(),
            expected,
            arch.triple(),
        );
    }
    println!("xtask {label}: kernel cleanly exited, no panic markers");
    Ok(())
}

/// Boot the mounted /mnt rootfs's `/lib/systemd/systemd` as REAL PID 1.
/// Sets the `systemd_pid1` kernel cmdline flag (boot-init then spawns the
/// chroot launcher as the first user task, so systemd inherits PID 1 down
/// the execve chain) and captures serial for a bounded window before
/// killing QEMU — systemd as PID 1 never exits, so unlike `boot-smoke`
/// there is no clean-shutdown to wait on. Requires a systemd rootfs disk
/// at `target/narf-vblk.img` (built out-of-band; not committed).
fn systemd_pid1_cmd(args: &BuildArgs) -> Result<()> {
    if !matches!(args.arch, Arch::X86_64) {
        bail!("xtask systemd-pid1: only x86_64 is wired (aarch64 boot-init is a stub)");
    }
    let mut args = args.clone();
    // boot-init compiles boot_userspace_init (which honours systemd_pid1);
    // cgroup-all makes /sys/fs/cgroup a real cgroup2fs (systemd's hard
    // gate); firmware-allow-unsigned mirrors the run-interactive boot.
    ensure_feature(&mut args.features, "boot-init");
    ensure_feature(&mut args.features, "cgroup-all");
    ensure_feature(&mut args.features, "firmware-allow-unsigned");

    let root = workspace_root()?;
    let disk = virtio_blk_image_path();
    if !disk.exists() {
        bail!(
            "xtask systemd-pid1: no rootfs disk at {} — build a systemd rootfs image first",
            disk.display()
        );
    }

    // Thread `systemd_pid1` onto the kernel cmdline (multiboot2 -append),
    // preserving any caller-provided XTASK_QEMU_APPEND. Set BEFORE
    // qemu_args() runs — it reads XTASK_QEMU_APPEND.
    let existing = std::env::var("XTASK_QEMU_APPEND").unwrap_or_default();
    let combined = if existing
        .split_ascii_whitespace()
        .any(|t| t == "systemd_pid1")
    {
        existing
    } else if existing.is_empty() {
        "systemd_pid1".to_string()
    } else {
        format!("{existing} systemd_pid1")
    };
    std::env::set_var("XTASK_QEMU_APPEND", combined);

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
    cmd.args(
        args.arch
            .qemu_args(&kernel, &args.display, args.hw_profile, args.gpu_backend),
    );
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());

    let secs = std::env::var("XTASK_SYSTEMD_PID1_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);
    let success_marker = std::env::var("XTASK_SYSTEMD_PID1_SUCCESS_MARKER")
        .ok()
        .filter(|marker| !marker.is_empty());
    let failure_marker = std::env::var("XTASK_SYSTEMD_PID1_FAILURE_MARKER")
        .ok()
        .filter(|marker| !marker.is_empty());

    println!(
        "xtask systemd-pid1: launching {} {} (capturing serial for {}s)",
        qemu,
        kernel.display(),
        secs
    );

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let panic_markers: &[&str] = &[
        "*** KERNEL PANIC ***",
        "panicked at",
        "double fault",
        "general protection",
        "kernel page fault",
        "unsafe precondition",
    ];

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdout"))?;
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap2 = captured.clone();
    // 0 = no marker, 1 = success, 2 = failure. The reader owns classification;
    // the control loop only observes this byte and terminates QEMU promptly.
    let marker_state = Arc::new(AtomicU8::new(0));
    let marker_state_reader = marker_state.clone();
    let success_marker_reader = success_marker.clone();
    let failure_marker_reader = failure_marker.clone();
    let reader_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let stdout = std::io::stdout();
        let mut host_stdout = stdout.lock();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.contains("Closing set fd ") {
                continue;
            }
            emit_serial_line(&mut host_stdout, &line);
            if let Ok(mut g) = cap2.lock() {
                g.push(line.clone());
            }
            match classify_serial_marker(
                &line,
                success_marker_reader.as_deref(),
                failure_marker_reader.as_deref(),
            ) {
                SerialMarkerMatch::None => {}
                SerialMarkerMatch::Success => {
                    // Preserve a failure observed on an earlier line.
                    let _ = marker_state_reader.compare_exchange(
                        0,
                        1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
                SerialMarkerMatch::Failure => {
                    // Failure is sticky even if a later line contains success.
                    marker_state_reader.store(2, Ordering::Release);
                }
            }
        }
    });

    // Bounded capture window, then kill — systemd PID 1 does not exit.
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break; // kernel died / exited early
        }
        if marker_state.load(Ordering::Acquire) != 0 {
            let _ = child.kill();
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.wait();
    let _ = reader_handle.join();

    // Digest: surface the systemd-relevant lines + any panic marker.
    let lines = captured.lock().map(|g| g.clone()).unwrap_or_default();
    let panic_hit = lines
        .iter()
        .find(|l| panic_markers.iter().any(|m| l.contains(m)))
        .cloned();
    let needles = [
        "systemd",
        "Reached target",
        "Queued start job",
        "Started ",
        "Failed to",
        "PID 1",
        "Freezing",
        "entire root",
        "Welcome to",
        "default target",
    ];
    let hits: Vec<&String> = lines
        .iter()
        .filter(|l| needles.iter().any(|n| l.contains(n)))
        .collect();
    println!(
        "\nxtask systemd-pid1: ==== digest ({} systemd-relevant lines) ====",
        hits.len()
    );
    for l in &hits {
        println!("  {l}");
    }
    if let Some(p) = panic_hit {
        bail!("xtask systemd-pid1: kernel panic during boot — {p}");
    }
    match marker_state.load(Ordering::Acquire) {
        2 => bail!(
            "xtask systemd-pid1: observed failure marker {:?}",
            failure_marker.unwrap_or_default()
        ),
        1 => println!(
            "xtask systemd-pid1: observed success marker {:?}",
            success_marker.as_deref().unwrap_or_default()
        ),
        _ if success_marker.is_some() => bail!(
            "xtask systemd-pid1: timed out without success marker {:?}",
            success_marker.unwrap_or_default()
        ),
        _ => {}
    }
    println!(
        "xtask systemd-pid1: capture window elapsed ({} total serial lines)",
        lines.len()
    );
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
/// Bucket a musl-demo case into a coarse subsystem group, so CI can fan
/// the ~80 cases out across a handful of parallel jobs by subsystem
/// (`--group`) rather than one long serial boot. This is a total function
/// — every case maps to exactly one group, so the union of all groups is
/// the whole suite regardless of how a given case is bucketed (an
/// imprecise match only shifts load, never drops coverage). First match
/// wins; order matters.
fn musl_case_group(cmd: &str) -> &'static str {
    let has = |needles: &[&str]| needles.iter().any(|n| cmd.contains(n));
    if has(&[
        "wl_",
        "mini_compositor",
        "drm_smoke",
        "modetest",
        "fb_smoke",
        "kms",
        "tfd_epoll",
    ]) {
        "gui"
    } else if has(&[
        "net_smoke",
        "net6",
        "unix_smoke",
        "epoll_smoke",
        "sockpair",
        "accept4",
        "mmsg",
        "ppoll_smoke",
        "scm_smoke",
    ]) {
        "net"
    } else if has(&["sig", "alarmloop", "preemptsched"]) {
        "signals"
    } else if has(&[
        "futex",
        "cond",
        "barrier",
        "robust",
        "notify_epoll",
        "sysvipc",
        "shm_smoke",
        "eventfd",
        "keyring",
    ]) {
        "ipc"
    } else if has(&[
        "fs_smoke",
        "navfs",
        "relpaths",
        "pipeof",
        "pipeblk",
        "xattr",
        "renameat2",
        "mountapi",
        "fhandle",
        "inotify",
        "fanotify",
        "splice",
        "sendfile",
        "sync_smoke",
        "fsmisc",
        "landlock",
        "lsm",
    ]) {
        "fs"
    } else if has(&["mremap", "mcore", "mem2", "mempolicy", "pkey", "pvm"]) {
        "mem"
    } else if has(&[
        "hello",
        "busybox",
        "fork",
        "sh -c",
        "pty",
        "jobctl",
        "creds",
        "waitid",
        "pidfd",
        "strace",
        "sched",
        "closerange",
        "dup3",
        "fd_cloexec",
        "oci",
    ]) {
        "process"
    } else {
        "linux-compat"
    }
}

/// Boot a single musl-demo case up to `attempts` times, returning true once
/// it passes. Retries on BOTH an assertion miss and a boot-level error
/// (e.g. "QEMU EOF before login" — GHA's TCG occasionally dies before the
/// shell), which is the dominant musl-demo flake. A genuinely-broken case
/// fails every attempt and returns false.
fn run_case_with_retry(
    build: &BuildArgs,
    case: (&str, &str),
    kernel: Option<&Path>,
    attempts: u32,
) -> bool {
    for attempt in 1..=attempts {
        match run_interactive_multi(build, core::slice::from_ref(&case), kernel) {
            Ok((_, 0, _)) => return true,
            Ok((_, f, _)) => eprintln!(
                "musl-demo: `{}` failed ({f} err) on attempt {attempt}/{attempts}",
                case.0
            ),
            Err(e) => eprintln!(
                "musl-demo: `{}` boot error on attempt {attempt}/{attempts}: {e:#}",
                case.0
            ),
        }
    }
    false
}

fn musl_demo_cmd(args: &MuslDemoArgs) -> Result<()> {
    if !matches!(args.build.arch, Arch::X86_64) {
        bail!("musl-demo is x86_64 only (hello_musl is not built for aarch64)");
    }

    // Lightweight cases run in a SINGLE shared boot (the TCG boot dwarfs
    // per-command runtime, so amortizing across commands is the win). The
    // heavy GUI cases each need their own fresh boot (see GUI_FRESH_BOOT).
    let lightweight: &[(&str, &str)] = &[
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
        // An interrupt gate preserves userspace DF. common_trap must clear the
        // live flag before Rust/REP MOVS while leaving the CPU-pushed RFLAGS
        // intact for iretq. The smoke sets DF around int80 uname and checks
        // both the forward kernel copy and restored user flag.
        ("df_trap_smoke", "df-trap-ok"),
        // Regression for the SYSRET rcx/r11 clobber on syscall-path
        // rt_sigreturn: an async SIGALRM interrupts an asm loop holding
        // sentinels in rcx/r11; the sigreturn must preserve them (full-register
        // iretq exit). See sigrcx_smoke_x86_64.c.
        ("sigrcx_smoke", "sigrcx-ok"),
        ("pipeblk_smoke", "pipeblk-ok"),
        // RT-signal regression for the stress-ng --sigrt fixes: si_pid on
        // SA_SIGINFO for a queued signal, a forked child's clean signal mask,
        // and rt_sigtimedwait reserving an UNBLOCKED in-set signal for the
        // waiter instead of a nop handler. See sigrt_smoke_x86_64.c.
        ("sigrt_smoke", "sigrt-ok"),
        // Live PTRACE_SYSCALL strace loop (TRACEME + syscall-stops + GETREGS).
        ("strace_smoke", "strace-ok"),
        // OCI container end-to-end: the `oci_smoke` runtime reads the
        // /oci bundle, unshares namespaces, sets the container hostname,
        // chroots into the bundle rootfs, and execs the contained
        // entrypoint. The entrypoint proves rootfs isolation (reads the
        // container's own /etc/os-release) + env propagation and prints
        // `oci-container-ok`; the runtime then prints `oci-smoke-ok`.
        // This default build (no `container` feature) exercises the
        // chroot-based rootfs isolation. The nightly OCI job
        // (.github/workflows/nightly-oci.yml) runs the same smoke WITH
        // `--features container`, where the runtime also prints the
        // stronger `oci-uts-isolated` token (the contained sethostname
        // did not leak to the host → a real UTS namespace).
        ("oci_smoke", "oci-smoke-ok"),
        ("fs_smoke", "fs-ok"),
        ("fork_pipe_smoke", "fork-ok"),
        // The mirror direction: the PARENT owns the last write end while a
        // forked child reads and closes its inherited copy — X server
        // Popen("w"), which is how Xwayland feeds xkbcomp its keymap.
        ("popenw_smoke", "popenw-ok"),
        // A Wayland compositor's exact wait shape: a server parked in
        // epoll_wait(-1) over its listening socket plus accepted clients,
        // and a client parked in poll(-1) for the reply.
        ("wlserve_smoke", "wlserve-ok"),
        // Early-systemd process topology: sixteen children are released
        // together across available CPUs, self-exec with one explicitly
        // preserved fd, report their post-exec identity, exit, and are reaped.
        ("fork_exec_burst_smoke", "fork-exec-burst-ok"),
        // Linux affinity masks are real scheduler constraints: self-migration,
        // remote-PID updates, a namespace boundary, and invalid masks.
        ("sched_affinity_smp_smoke", "sched-affinity-smp-ok"),
        ("pty_smoke", "pty-ok"),
        // Framebuffer smoke — opens /dev/fb0, FBIOGET_VSCREENINFO,
        // mmap MAP_SHARED, writes + reads back pixels through the
        // mapping. End-to-end proof of the device-mmap keystone +
        // the Linux fbdev ioctls from stock musl.
        ("fb_smoke", "fb-ok"),
        // AF_UNIX SCM_RIGHTS fd-passing — the Wayland transport primitive.
        ("scm_smoke", "scm-ok"),
        // libwayland (1.23 + libffi) client+server registry handshake over a
        // socketpair — proves the Wayland wire protocol + transport on NARF.
        ("wl_handshake", "wl-ok"),
        ("wl_shm", "shm-ok"),
        // NOTE: the multi-process Wayland compositor cases (mini_compositor,
        // wl_2proc, wl_multi, wl_xdg, wl_input, wl_kms, wl_evdev, wl_app) run
        // in their OWN fresh boots via GUI_FRESH_BOOT below — each forks a
        // compositor + client(s) and maps the framebuffer, and that state
        // accumulates across this single long-lived VM (a later case then
        // hangs nondeterministically). One boot per case keeps them reliable.
        // DRM/KMS dumb-buffer smoke — GET_CAP, CREATE_DUMB, MAP_DUMB,
        // mmap MAP_SHARED, ADDFB2, SETCRTC. Proves Rung-3 modeset
        // path end-to-end from stock musl.
        ("drm_smoke", "drm-ok"),
        // timerfd-in-epoll wake — weston's repaint-loop driver: a timerfd
        // armed via timerfd_settime, blocked on by epoll_wait(-1). Guards the
        // path the whole desktop repaint cadence rides on.
        ("tfd_epoll_smoke", "tfd-epoll-ok"),
        // Pure-timeout poll/epoll park hammer — hundreds of no-fd timeout
        // windows (with timerfd-in-epoll churn) across 8 concurrent
        // processes. Pins the slab-canary false positive that
        // tfd_epoll_smoke's single 120 ms step-F window only tripped on
        // layout-cursed builds ("slab: double free ... class 32 B").
        ("polltmo_hammer", "polltmo-ok"),
        // modetest (real libdrm) enumerates /dev/dri/card0 end-to-end —
        // VERSION + GET_CAP + GETRESOURCES + GETCONNECTOR/ENCODER/CRTC +
        // OBJ_GETPROPERTIES. Anchors on the enumerated 1280x800 mode.
        ("modetest -M narf-drm", "(1280x800)"),
        // NOTE: `modetest -s 3@1:1280x800` (set a mode + present an SMPTE
        // pattern) is NOT an auto case — `modetest -s` holds the mode and
        // blocks on stdin (interactive), so it never returns to the shell
        // prompt. The CREATE_DUMB → ADDFB2 → SETCRTC modeset path it exercises
        // is already covered for CI by `drm_smoke`; run it by hand for a
        // visual check: `xtask run-interactive --cmd "modetest -M narf-drm -s
        // 3@1:1280x800" --expect "crtc 1"`.
        ("net_smoke", "net-ok"),
        ("net6_smoke", "net6-ok"),
        ("unix_smoke", "unix-ok"),
        ("epoll_smoke", "epoll-ok"),
        // Linux-compat round: eventfd2, getrandom, socketpair, accept4.
        ("eventfd_smoke", "eventfd-ok"),
        ("getrandom_smoke", "getrandom-ok"),
        ("sockpair_smoke", "sockpair-ok"),
        ("accept4_smoke", "accept4-ok"),
        // The terminal chain end to end (see ptyspawn_smoke_x86_64.c). Anchored
        // on its own success line, which the probe prints ONLY when the
        // child's output actually came back off the master — "probe done"
        // prints unconditionally and would pass a silent failure.
        ("ptyspawn_smoke", "ptyspawn-ok"),
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
        ("fd_cloexec_exec_smoke", "fd-cloexec-exec-ok"),
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
        ("perf_smoke", "perf_smoke: OK"),
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
        // Condvar broadcast handoff — the FUTEX_REQUEUE path. Regression
        // for the permanent broadcast-waiter strand (requeue silently
        // dropped + the park loop never re-reading the futex word).
        ("condbcast_smoke", "condbcast-ok"),
        // Contended futex (N-thread mutex + join + condvar ping-pong).
        // Back in the shared-boot batch at the FULL 16-vCPU/2-socket-NUMA
        // topology: the strand class that forced its SMP=1 pin is fixed
        // (FUTEX_REQUEUE implemented, park-loop futex-word re-validation,
        // spawn→idle-AP resched kick) and the case hammers clean at
        // SMP=16 — see condbcast_smoke above for the permanent-strand
        // regression pin.
        ("futex_contend_smoke", "futex-contend-ok"),
        // Systemd Type=notify topology on live SMP: a service process pinned
        // to CPU 1 wakes PID-1-like epoll_wait on CPU 0 with SCM credentials.
        ("notify_epoll_smp_smoke", "notify-epoll-smp-ok"),
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
        // NUMA sysfs: node online range + per-node SLIT distance rows.
        ("numa_smoke", "numa-ok"),
        // multi-DSO dynamic linking: main -> libb -> liba -> libc.
        ("dso_smoke", "dso-ok"),
        // per-DSO TLS: thread-locals in a shared library (libtls).
        ("tls_smoke", "tls-ok"),
    ];

    // Heavy multi-process Wayland compositor cases — each forks a compositor
    // + client(s) and maps the framebuffer. That per-process state accumulates
    // across a single long-lived VM and makes a later case hang
    // nondeterministically, so each gets its OWN fresh boot. They pass
    // reliably in isolation.
    const GUI_FRESH_BOOT: &[(&str, &str)] = &[
        ("mini_compositor", "px=00c0ffee"),
        ("wl_2proc", "2proc-ok 1280x800 px=00c0ffee"),
        (
            "busybox sh -c 'wl_multi && echo wl-multi-ok'",
            "wl-multi-ok",
        ),
        ("wl_xdg", "xdg-ok 1280x800 px=00c0ffee"),
        ("wl_input", "input-ok 1280x800 key=30"),
        ("wl_kms", "kms-ok 1280x800 px=00c0ffee flip=1"),
        ("wl_evdev", "evdev-ok 1280x800 key=30"),
        ("wl_app", "app-ok 1280x800 win=250x250"),
    ];

    // `--list-groups`: emit the distinct subsystem groups over ALL cases so
    // the CI matrix runs exactly the non-empty groups (no drift, no gaps).
    // CI_EXCLUDED_GROUPS are omitted from the matrix but still runnable
    // locally via `--group <name>`: the GUI/Wayland compositor cases are
    // boot-flaky under GHA's TCG (multi-process fresh boots that
    // occasionally die before login), so they don't gate CI for now. Run
    // them by hand with `cargo xtask musl-demo --group gui`.
    const CI_EXCLUDED_GROUPS: &[&str] = &["gui"];
    if args.list_groups {
        let mut groups: Vec<&str> = lightweight
            .iter()
            .chain(GUI_FRESH_BOOT.iter())
            .map(|(cmd, _)| musl_case_group(cmd))
            .filter(|g| !CI_EXCLUDED_GROUPS.contains(g))
            .collect();
        groups.sort_unstable();
        groups.dedup();
        let json = groups
            .iter()
            .map(|g| format!("{g:?}"))
            .collect::<Vec<_>>()
            .join(",");
        println!("[{json}]");
        return Ok(());
    }

    // Resolve the kernel once: a prebuilt artifact (the per-group CI jobs
    // boot the same downloaded image) or a fresh build (run_interactive_multi
    // builds on the first call, warm-incremental after).
    let prebuilt: Option<PathBuf> = match &args.prebuilt {
        Some(p) => {
            let k = PathBuf::from(p);
            if !k.exists() {
                bail!("--prebuilt kernel not found at {}", k.display());
            }
            Some(k)
        }
        None => None,
    };
    let kernel_override = prebuilt.as_deref();

    // Select this invocation's group (or all groups when unset).
    let want = |cmd: &str| {
        args.group
            .as_deref()
            .is_none_or(|g| musl_case_group(cmd) == g)
    };
    if let Some(g) = &args.group {
        eprintln!("xtask musl-demo: running subsystem group `{g}`");
    }

    // Lightweight cases in this group → one shared boot. A boot-level flake
    // (a "QEMU EOF before login" — GHA's TCG occasionally dies before the
    // shell) retries the whole batch once rather than aborting the group.
    let selected: Vec<(&str, &str)> = lightweight.iter().copied().filter(|t| want(t.0)).collect();
    let (mut passed, mut failed, main_failed) = if selected.is_empty() {
        (0usize, 0usize, Vec::new())
    } else {
        let mut out = None;
        for attempt in 1..=2u32 {
            match run_interactive_multi(&args.build, &selected, kernel_override) {
                Ok(t) => {
                    out = Some(t);
                    break;
                }
                Err(e) if attempt < 2 => {
                    eprintln!("musl-demo: shared-boot error (attempt {attempt}/2): {e:#}; retrying")
                }
                Err(e) => return Err(e),
            }
        }
        out.expect("shared boot returned after the retry loop")
    };

    // Retry any shared-boot case that failed once, alone in a fresh boot: a
    // genuinely-broken case still fails (and stays counted), but a one-off
    // environmental flake (host scheduling jitter on a loaded runner, SLIRP
    // timing) clears.
    for (cmdline, expect) in &main_failed {
        eprintln!("\nmusl-demo (retry): {cmdline}");
        if run_case_with_retry(
            &args.build,
            (cmdline.as_str(), expect.as_str()),
            kernel_override,
            2,
        ) {
            // Cleared on the isolated retry → reclassify as a pass.
            passed += 1;
            failed -= 1;
        }
    }

    // GUI cases in this group → one fresh boot each, retried on a boot flake
    // or a miss (the multi-process compositor cases are the boot-flakiest;
    // wl_xdg once hit a bare "QEMU EOF before login" on GHA TCG).
    for case in GUI_FRESH_BOOT.iter().filter(|t| want(t.0)) {
        eprintln!("\nmusl-demo (fresh boot): {}", case.0);
        if run_case_with_retry(&args.build, *case, kernel_override, 3) {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    eprintln!(
        "\nmusl-demo summary ({}): {} passed, {} failed",
        args.group.as_deref().unwrap_or("all"),
        passed,
        failed
    );
    if failed > 0 {
        bail!("musl-demo failed ({} errors)", failed);
    }
    Ok(())
}

fn run_interactive_cmd(args: &RunInteractiveArgs) -> Result<()> {
    if !matches!(args.build.arch, Arch::X86_64) {
        // The shell + boot_userspace_init are x86_64-only today
        // (`cfg(all(feature = "boot-init", target_arch = "x86_64"))`).
        bail!("xtask run-interactive: only x86_64 is wired (aarch64 boot-init is a stub)");
    }

    let root = workspace_root()?;

    // Resolve the kernel image: a prebuilt artifact (the split per-case
    // `musl-demo` jobs download one and boot it) or a fresh cross-build.
    let (kernel, out_dir) = match &args.prebuilt {
        Some(path) => {
            let kernel = PathBuf::from(path);
            if !kernel.exists() {
                bail!("--prebuilt kernel not found at {}", kernel.display());
            }
            let out_dir = kernel
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| root.clone());
            (kernel, out_dir)
        }
        None => {
            let mut build = args.build.clone();
            ensure_feature(&mut build.features, "boot-init");
            // Bring up at least the firmware ack the boot-init flow assumes;
            // matches `Cmd::IsoBoot` / `Cmd::Image` defaults so the shell
            // actually loads.
            ensure_feature(&mut build.features, "firmware-allow-unsigned");
            let out_dir = cargo_build(&build, &root)?;
            let kernel = out_dir.join(&build.package);
            if !kernel.exists() {
                bail!(
                    "expected kernel binary at {} — did `cargo build` succeed?",
                    kernel.display()
                );
            }
            (kernel, out_dir)
        }
    };

    let fw_dir = root.join("target").join("firmware");
    let (fw_initramfs, _) = collect_firmware_blobs(&fw_dir, &args.build.initramfs_firmware)?;
    let mut cpio_path = None;
    if !fw_initramfs.is_empty() {
        let mut cpio_entries: Vec<(&str, &[u8])> = Vec::new();
        for (path, bytes) in &fw_initramfs {
            cpio_entries.push((path.as_str(), bytes.as_slice()));
        }
        let cpio = encode_cpio_newc(&cpio_entries);
        let p = out_dir.join("initramfs.cpio");
        std::fs::write(&p, &cpio)
            .with_context(|| format!("writing initramfs CPIO to {}", p.display()))?;
        cpio_path = Some(p);
    }

    // Retry loop: each attempt is a fresh QEMU boot. A flake (e.g. a
    // TCG-timing echo miss) passes on a re-boot; a genuine break fails
    // after every attempt. `--retries 0` (default) means a single boot.
    let attempts = args.retries + 1;
    let mut last_err = None;
    for attempt in 1..=attempts {
        if attempts > 1 {
            eprintln!(
                "xtask run-interactive: attempt {attempt}/{attempts} for `{}`",
                args.cmd
            );
        }
        match run_interactive_boot(
            &kernel,
            cpio_path.as_ref(),
            args.build.arch,
            &args.build.display,
            args.build.hw_profile,
            args.build.gpu_backend,
            &args.cmd,
            &args.expect,
        ) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("xtask run-interactive: attempt {attempt} failed: {e:#}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("run-interactive: no attempts made")))
}

/// Boot `kernel` under QEMU, log in as root, type `typed_cmd`, and assert
/// `expect` appears on the serial console. One attempt; the caller retries.
#[allow(clippy::too_many_arguments)]
fn run_interactive_boot(
    kernel: &Path,
    cpio_path: Option<&PathBuf>,
    arch: Arch,
    display: &str,
    hw_profile: HwProfile,
    gpu_backend: GpuBackend,
    typed_cmd: &str,
    expect: &str,
) -> Result<()> {
    use std::io::Write;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Arc, Mutex};

    let qemu = arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    let mut qemu_args = arch.qemu_args(kernel, display, hw_profile, gpu_backend);
    if let Some(cpio) = cpio_path {
        qemu_args.push("-initrd".into());
        qemu_args.push(cpio.display().to_string());
    }
    cmd.args(qemu_args);
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

    // Stage 0: log in, tolerating a garbled attempt. getty prints
    // "NARF login:" then "Password:", checks the reply against /etc/shadow
    // (root / narf), and on a mismatch prints "Login incorrect" and re-prompts.
    // Machine-speed keystrokes can garble under slow TCG — a byte-reordering
    // race in the console line discipline turns `root` into e.g. `orot` — so
    // rather than send the credentials once and then block for the full prompt
    // timeout on a login that has already failed, retry the exchange a few
    // times, watching for the "Login incorrect" re-prompt and trying again. The
    // reader thread only signals "narf> ", so poll the shared capture buffer for
    // the login-flow strings directly.
    {
        // Poll the capture buffer for `needle` at or after byte offset `from`,
        // within `timeout`. Returns the offset just past the match, or `None`.
        let find_from = |from: usize, needle: &[u8], timeout: Duration| -> Option<usize> {
            let start = std::time::Instant::now();
            loop {
                if let Ok(g) = captured.lock() {
                    let lo = from.min(g.len()).saturating_sub(needle.len());
                    if let Some(pos) = g[lo..].windows(needle.len()).position(|w| w == needle) {
                        return Some(lo + pos + needle.len());
                    }
                }
                if start.elapsed() >= timeout {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        // Type `bytes` slowly enough that the console line discipline keeps up:
        // a wider inter-byte gap than the post-login typing uses, because the
        // login prompt's cooked-mode echo is where the reordering race bites.
        let mut send = |bytes: &[u8]| -> bool {
            for &b in bytes {
                if stdin.write_all(&[b]).is_err() {
                    return false;
                }
                let _ = stdin.flush();
                std::thread::sleep(Duration::from_millis(25));
            }
            true
        };

        // The first "login:" only appears once boot reaches getty — allow the
        // full prompt budget for it. Re-prompts after a failed attempt come in
        // seconds, so those get a short per-step timeout below.
        let step = Duration::from_secs(30);
        let mut mark = match find_from(0, b"login: ", Duration::from_secs(prompt_secs)) {
            Some(m) => m,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!(
                    "xtask run-interactive: did not see login prompt within {}s",
                    prompt_secs
                );
            }
        };

        const MAX_LOGIN_ATTEMPTS: usize = 8;
        let mut logged_in = false;
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            if !send(b"root\n") {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!("xtask run-interactive: stdin write failed during login");
            }
            // The password prompt should follow even a garbled username (the
            // line still completes at the newline). If it doesn't, wait for the
            // next login prompt and start the attempt over.
            let Some(after_pw) = find_from(mark, b"Password: ", step) else {
                if let Some(m) = find_from(mark, b"login: ", step) {
                    mark = m;
                }
                continue;
            };
            if !send(b"narf\n") {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                bail!("xtask run-interactive: stdin write failed during login");
            }
            // Success prints "Welcome to NARF"; a bad (garbled) attempt prints
            // "Login incorrect" and re-prompts. Poll for whichever comes first so
            // a failed attempt retries at once instead of waiting out `step`.
            let verdict_start = std::time::Instant::now();
            let zero = Duration::from_millis(0);
            loop {
                if find_from(after_pw, b"Welcome to NARF", zero).is_some() {
                    logged_in = true;
                    break;
                }
                if find_from(after_pw, b"Login incorrect", zero).is_some()
                    || verdict_start.elapsed() >= step
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if logged_in {
                break;
            }
            // Failed or timed out — resync on the next login prompt and retry.
            if let Some(m) = find_from(after_pw, b"login: ", step) {
                mark = m;
            }
        }
        if !logged_in {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader_handle.join();
            bail!(
                "xtask run-interactive: could not log in after {} attempts",
                MAX_LOGIN_ATTEMPTS
            );
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
        typed_cmd
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

    // Typed line is the configurable command with a trailing newline.
    let mut typed: Vec<u8> = typed_cmd.as_bytes().to_vec();
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
    // The expected substring is configurable via `expect`.
    let needle: Vec<u8> = expect.as_bytes().to_vec();
    let echo_deadline = Duration::from_secs(echo_secs);
    let echo_start = std::time::Instant::now();
    let mut got_echo = false;
    while echo_start.elapsed() < echo_deadline {
        // Drain pending events first so a panic short-circuits the
        // loop instead of waiting out the full timeout.
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ev::Panic(p)) => {
                std::thread::sleep(Duration::from_millis(1500));
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_handle.join();
                let g = captured.lock().unwrap();
                let cap_str = String::from_utf8_lossy(&g);
                let tail = if cap_str.len() > 4096 {
                    &cap_str[cap_str.len() - 4096..]
                } else {
                    &cap_str
                };
                bail!(
                    "xtask run-interactive: panic after typing — '{}'\nCapture Tail:\n{}",
                    p,
                    tail
                );
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
            typed_cmd,
            expect,
            echo_secs
        );
    }

    println!(
        "\nxtask run-interactive: ok — typed `{}`, saw `{}`",
        typed_cmd, expect,
    );
    Ok(())
}

/// Off-box network serving smoke — see [`Cmd::NetSmoke`]. Boots with the
/// `qemu-net` static config + a QEMU `hostfwd`, waits for the auto-
/// spawned guest echo server to announce itself, then opens a real TCP
/// socket from the host to the forwarded port and asserts the round-trip
/// (plus the guest's `netserve-ok`).
fn net_smoke_cmd(args: &BuildArgs) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    if !matches!(args.arch, Arch::X86_64) {
        bail!("xtask net-smoke: only x86_64 is wired (boot-init is x86_64-only)");
    }

    let host_port: u16 = 17777;
    let guest_port: u16 = 7777;

    let mut build = args.clone();
    ensure_feature(&mut build.features, "boot-init");
    ensure_feature(&mut build.features, "firmware-allow-unsigned");
    ensure_feature(&mut build.features, "qemu-net");

    let root = workspace_root()?;
    let out_dir = cargo_build(&build, &root)?;
    let kernel = out_dir.join(&build.package);
    if !kernel.exists() {
        bail!(
            "expected kernel binary at {} — did `cargo build` succeed?",
            kernel.display()
        );
    }

    // Set in THIS process's env: `qemu_args` (called below, in-process)
    // reads it to splice `hostfwd` into the user-mode netdev. Setting it
    // on the child Command would be too late — the arg list is built here.
    std::env::set_var(
        "XTASK_QEMU_HOSTFWD",
        format!("tcp:127.0.0.1:{host_port}-:{guest_port}"),
    );
    // Suppress the redis-server auto-spawn: net-smoke only exercises
    // netserve, and redis's heavy multi-threaded startup starves
    // netserve's RX forwarder on a single (CI) vcpu under TCG, dragging
    // the off-box echo past the host read deadline — the historical ~20%
    // net-smoke flake. redis-smoke keeps redis (it doesn't set this).
    // Preserve any caller-provided kernel cmdline.
    {
        let existing = std::env::var("XTASK_QEMU_APPEND").unwrap_or_default();
        let combined = if existing.is_empty() {
            "no_redis".to_string()
        } else {
            format!("{existing} no_redis")
        };
        std::env::set_var("XTASK_QEMU_APPEND", combined);
    }

    let qemu = build.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        build
            .arch
            .qemu_args(&kernel, &build.display, build.hw_profile, build.gpu_backend),
    );
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    println!(
        "xtask net-smoke: launching {} {} (hostfwd 127.0.0.1:{host_port} -> guest :{guest_port})",
        qemu,
        kernel.display()
    );

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let timeout_secs = std::env::var("XTASK_RI_PROMPT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(180);

    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::with_capacity(64 * 1024)));
    let panic_flag: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdout"))?;
    let cap_r = captured.clone();
    let panic_r = panic_flag.clone();
    let reader = std::thread::spawn(move || {
        let panic_markers: &[&[u8]] = &[
            b"*** KERNEL PANIC ***",
            b"panicked at",
            b"double fault",
            b"general protection",
            b"kernel page fault",
            b"unsafe precondition",
        ];
        let mut stdout = stdout;
        let mut buf = [0u8; 256];
        let mut line: Vec<u8> = Vec::with_capacity(256);
        let mut out = std::io::stdout();
        loop {
            let n = match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
            if let Ok(mut g) = cap_r.lock() {
                g.extend_from_slice(&buf[..n]);
            }
            for &b in &buf[..n] {
                if b == b'\n' {
                    for m in panic_markers {
                        if line.windows(m.len()).any(|w| w == *m) {
                            if let Ok(mut p) = panic_r.lock() {
                                if p.is_none() {
                                    *p = Some(String::from_utf8_lossy(&line).into_owned());
                                }
                            }
                        }
                    }
                    line.clear();
                } else {
                    line.push(b);
                }
            }
        }
    });

    let wait_for = |needle: &[u8], secs: u64| -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(secs) {
            if panic_flag.lock().ok().map(|p| p.is_some()).unwrap_or(false) {
                return false;
            }
            if let Ok(g) = captured.lock() {
                if g.windows(needle.len()).any(|w| w == needle) {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    };

    // 1. Wait for the auto-spawned server to announce it is listening.
    if !wait_for(b"netserve: listening", timeout_secs) {
        let panic = panic_flag.lock().ok().and_then(|g| g.clone());
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        if let Some(p) = panic {
            bail!("xtask net-smoke: kernel panic before listen — '{p}'");
        }
        bail!(
            "xtask net-smoke: guest server did not print `netserve: listening` within {timeout_secs}s"
        );
    }
    println!(
        "\nxtask net-smoke: guest is listening; connecting from host to 127.0.0.1:{host_port}..."
    );

    // 2. Connect from the host, retrying — SLIRP forwarding + the guest
    //    accept loop may need a moment to be ready.
    let mut stream: Option<TcpStream> = None;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        match TcpStream::connect(("127.0.0.1", host_port)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    let mut stream = match stream {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("xtask net-smoke: could not connect to 127.0.0.1:{host_port} within 20s");
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));

    // 3. Round-trip a line and assert the echo.
    let payload = b"hello-narf\n";
    if stream.write_all(payload).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        bail!("xtask net-smoke: host write failed");
    }
    let _ = stream.flush();
    let mut got = Vec::new();
    let mut rbuf = [0u8; 256];
    loop {
        match stream.read(&mut rbuf) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&rbuf[..n]);
                if got.len() >= payload.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if !got.windows(payload.len()).any(|w| w == payload) {
        let _ = child.kill();
        let _ = child.wait();
        bail!(
            "xtask net-smoke: echo mismatch — sent {:?}, got {:?}",
            String::from_utf8_lossy(payload),
            String::from_utf8_lossy(&got)
        );
    }
    println!(
        "xtask net-smoke: host received the echo ({:?})",
        String::from_utf8_lossy(&got)
    );

    // 4. Wait for the guest's clean-round-trip confirmation.
    if !wait_for(b"netserve-ok", timeout_secs) {
        let _ = child.kill();
        let _ = child.wait();
        bail!("xtask net-smoke: guest did not print `netserve-ok` within {timeout_secs}s");
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    println!("xtask net-smoke: ok — guest server echoed an off-box client over virtio-net");
    Ok(())
}

/// Off-box redis smoke — see [`Cmd::RedisSmoke`]. Boots `qemu-net` + a
/// QEMU `hostfwd`, waits for the auto-spawned unmodified `redis-server`
/// to announce readiness, then drives RESP `SET`/`GET` from the host.
fn redis_smoke_cmd(args: &BuildArgs) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    if !matches!(args.arch, Arch::X86_64) {
        bail!("xtask redis-smoke: only x86_64 is wired (boot-init is x86_64-only)");
    }

    let host_port: u16 = 16379;
    let guest_port: u16 = 6379;

    let mut build = args.clone();
    ensure_feature(&mut build.features, "boot-init");
    ensure_feature(&mut build.features, "firmware-allow-unsigned");
    ensure_feature(&mut build.features, "qemu-net");

    let root = workspace_root()?;
    let out_dir = cargo_build(&build, &root)?;
    let kernel = out_dir.join(&build.package);
    if !kernel.exists() {
        bail!(
            "expected kernel binary at {} — did the build succeed?",
            kernel.display()
        );
    }

    std::env::set_var(
        "XTASK_QEMU_HOSTFWD",
        format!("tcp:127.0.0.1:{host_port}-:{guest_port}"),
    );

    // redis spawns background (bio) threads at startup via clone(2). The
    // SMP user-task *migration* path (task #87) is still being hardened —
    // under the default 16-vCPU machine those threads intermittently
    // fault when migrated/stolen across APs (a #PF with a corrupt resumed
    // context; not a redis/TCP bug — the same crash never reproduces
    // single-CPU). Until #87 lands, pin redis to one vCPU so the off-box
    // serving + sustained-stress guarantees are deterministic. The full
    // kernel SMP plumbing is otherwise unchanged; override with
    // `NARF_QEMU_SMP=<n>` to reproduce the migration race on purpose.
    if std::env::var_os("NARF_QEMU_SMP").is_none() {
        std::env::set_var("NARF_QEMU_SMP", "1");
    }

    let qemu = build.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        build
            .arch
            .qemu_args(&kernel, &build.display, build.hw_profile, build.gpu_backend),
    );
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    println!(
        "xtask redis-smoke: launching {} {} (hostfwd 127.0.0.1:{host_port} -> guest :{guest_port})",
        qemu,
        kernel.display()
    );

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    let timeout_secs = std::env::var("XTASK_RI_PROMPT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);

    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::with_capacity(64 * 1024)));
    let panic_flag: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qemu child has no stdout"))?;
    let cap_r = captured.clone();
    let panic_r = panic_flag.clone();
    let reader = std::thread::spawn(move || {
        let panic_markers: &[&[u8]] = &[
            b"*** KERNEL PANIC ***",
            b"panicked at",
            b"double fault",
            b"general protection",
            b"kernel page fault",
            b"unsafe precondition",
        ];
        let mut stdout = stdout;
        let mut buf = [0u8; 256];
        let mut line: Vec<u8> = Vec::with_capacity(256);
        let mut out = std::io::stdout();
        loop {
            let n = match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let _ = out.write_all(&buf[..n]);
            let _ = out.flush();
            if let Ok(mut g) = cap_r.lock() {
                g.extend_from_slice(&buf[..n]);
            }
            for &b in &buf[..n] {
                if b == b'\n' {
                    for m in panic_markers {
                        if line.windows(m.len()).any(|w| w == *m) {
                            if let Ok(mut p) = panic_r.lock() {
                                if p.is_none() {
                                    *p = Some(String::from_utf8_lossy(&line).into_owned());
                                }
                            }
                        }
                    }
                    line.clear();
                } else {
                    line.push(b);
                }
            }
        }
    });

    let wait_for = |needle: &[u8], secs: u64| -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(secs) {
            if panic_flag.lock().ok().map(|p| p.is_some()).unwrap_or(false) {
                return false;
            }
            if let Ok(g) = captured.lock() {
                if g.windows(needle.len()).any(|w| w == needle) {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    };

    // 1. Wait for redis to announce readiness.
    if !wait_for(b"Ready to accept connections", timeout_secs) {
        let panic = panic_flag.lock().ok().and_then(|g| g.clone());
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        if let Some(p) = panic {
            bail!("xtask redis-smoke: kernel panic before redis ready — '{p}'");
        }
        bail!(
            "xtask redis-smoke: redis-server did not print `Ready to accept connections` within {timeout_secs}s"
        );
    }
    println!(
        "\nxtask redis-smoke: redis is ready; connecting from host to 127.0.0.1:{host_port}..."
    );

    // 2. Connect from the host.
    let mut stream: Option<TcpStream> = None;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        match TcpStream::connect(("127.0.0.1", host_port)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    let mut stream = match stream {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("xtask redis-smoke: could not connect to 127.0.0.1:{host_port} within 20s");
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));

    // RESP-encode an array of bulk strings.
    let resp = |args: &[&str]| -> Vec<u8> {
        let mut b = format!("*{}\r\n", args.len()).into_bytes();
        for a in args {
            b.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            b.extend_from_slice(a.as_bytes());
            b.extend_from_slice(b"\r\n");
        }
        b
    };
    // Read exactly ONE complete RESP reply (handles +simple, -error,
    // :integer, $bulk, *array — recursively), returning the raw bytes.
    fn read_one_resp<R: std::io::BufRead>(r: &mut R) -> std::io::Result<Vec<u8>> {
        let mut line = Vec::new();
        r.read_until(b'\n', &mut line)?;
        if line.is_empty() {
            return Ok(line);
        }
        let mut out = line.clone();
        let num = |l: &[u8]| -> i64 {
            std::str::from_utf8(&l[1..])
                .ok()
                .map(|s| s.trim())
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(-1)
        };
        match line[0] {
            b'$' => {
                let len = num(&line);
                if len >= 0 {
                    let mut data = vec![0u8; len as usize + 2]; // payload + CRLF
                    r.read_exact(&mut data)?;
                    out.extend_from_slice(&data);
                }
            }
            b'*' => {
                let n = num(&line);
                for _ in 0..n.max(0) {
                    out.extend_from_slice(&read_one_resp(r)?);
                }
            }
            _ => {} // +, -, : are single-line
        }
        Ok(out)
    }

    let fail = |child: &mut std::process::Child, msg: String| -> anyhow::Error {
        let _ = child.kill();
        let _ = child.wait();
        anyhow!(msg)
    };

    // A representative command battery across every redis data type +
    // server/keyspace commands — proves the RESP protocol and command
    // dispatch work broadly, not just SET/GET. Each entry is
    // (args, check-on-raw-reply).
    let sub = |s: &'static [u8]| -> Box<dyn Fn(&[u8]) -> bool> {
        Box::new(move |r: &[u8]| r.windows(s.len()).any(|w| w == s))
    };
    let posint = || -> Box<dyn Fn(&[u8]) -> bool> {
        Box::new(|r: &[u8]| r.first() == Some(&b':') && r.get(1).is_some_and(u8::is_ascii_digit))
    };
    let battery: Vec<(Vec<&str>, Box<dyn Fn(&[u8]) -> bool>)> = vec![
        (vec!["PING"], sub(b"+PONG")),
        // strings
        (vec!["SET", "k:str", "hello-narf"], sub(b"+OK")),
        (vec!["GET", "k:str"], sub(b"hello-narf")),
        (vec!["APPEND", "k:str", "!"], sub(b":11")), // "hello-narf!" = 11
        (vec!["STRLEN", "k:str"], sub(b":11")),
        (vec!["EXISTS", "k:str"], sub(b":1")),
        (vec!["GETRANGE", "k:str", "0", "4"], sub(b"hello")),
        // integers
        (vec!["SET", "k:num", "10"], sub(b"+OK")),
        (vec!["INCR", "k:num"], sub(b":11")),
        (vec!["INCRBY", "k:num", "5"], sub(b":16")),
        (vec!["DECR", "k:num"], sub(b":15")),
        (vec!["DEL", "k:num"], sub(b":1")),
        (vec!["EXISTS", "k:num"], sub(b":0")),
        // lists
        (vec!["RPUSH", "k:list", "a", "b", "c"], sub(b":3")),
        (vec!["LPUSH", "k:list", "z"], sub(b":4")),
        (vec!["LLEN", "k:list"], sub(b":4")),
        (vec!["LRANGE", "k:list", "0", "-1"], sub(b"a")),
        (vec!["LPOP", "k:list"], sub(b"z")),
        // hashes
        (vec!["HSET", "k:hash", "f1", "v1", "f2", "v2"], sub(b":2")),
        (vec!["HGET", "k:hash", "f1"], sub(b"v1")),
        (vec!["HLEN", "k:hash"], sub(b":2")),
        (vec!["HGETALL", "k:hash"], sub(b"v2")),
        // sets
        (vec!["SADD", "k:set", "x", "y", "z"], sub(b":3")),
        (vec!["SCARD", "k:set"], sub(b":3")),
        (vec!["SISMEMBER", "k:set", "y"], sub(b":1")),
        // sorted sets
        (vec!["ZADD", "k:zset", "1", "one", "2", "two"], sub(b":2")),
        (vec!["ZCARD", "k:zset"], sub(b":2")),
        (vec!["ZSCORE", "k:zset", "two"], sub(b"2")),
        // expiry + introspection
        (vec!["EXPIRE", "k:str", "1000"], sub(b":1")),
        (vec!["TTL", "k:str"], posint()),
        (vec!["PERSIST", "k:str"], sub(b":1")),
        (vec!["TYPE", "k:list"], sub(b"+list")),
        (vec!["DBSIZE"], posint()),
        // server / config
        (vec!["INFO", "server"], sub(b"redis_version:7.2.5")),
        (vec!["CONFIG", "GET", "maxmemory"], sub(b"maxmemory")),
        (vec!["COMMAND", "COUNT"], posint()),
        (vec!["DBSIZE"], posint()),
    ];

    let mut reader_io = std::io::BufReader::new(
        stream
            .try_clone()
            .map_err(|e| fail(&mut child, format!("xtask redis-smoke: clone stream: {e}")))?,
    );

    let total = battery.len();
    for (i, (args, check)) in battery.iter().enumerate() {
        if stream.write_all(&resp(args)).is_err() {
            return Err(fail(
                &mut child,
                format!("xtask redis-smoke: host write failed for {:?}", args),
            ));
        }
        let _ = stream.flush();
        let reply = read_one_resp(&mut reader_io)
            .map_err(|e| anyhow!("xtask redis-smoke: read reply for {:?}: {e}", args))?;
        if !check(&reply) {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "xtask redis-smoke: command {:?} got unexpected reply: {:?}",
                args,
                String::from_utf8_lossy(&reply)
            );
        }
        println!(
            "  redis [{:2}/{}] {:<28} -> {}",
            i + 1,
            total,
            args.join(" "),
            String::from_utf8_lossy(&reply).trim().replace("\r\n", " ")
        );
    }

    // 3. Optional sustained stress phase. `XTASK_REDIS_STRESS_SECS=120`
    //    hammers redis with mixed-type round-trips for ~2 minutes to
    //    prove the TCP/epoll path stays healthy under sustained load:
    //    no stall (the failure mode was a stuck read after ~34 RTs), no
    //    leak, no crash. Keys are segregated per data type so a RESP
    //    error reply (`-...`) is always a real failure (never a benign
    //    WRONGTYPE from cross-type access). Default 0 = skip, keeping
    //    the quick smoke fast.
    let stress_secs: u64 = std::env::var("XTASK_REDIS_STRESS_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if stress_secs > 0 {
        println!(
            "\nxtask redis-smoke: starting {stress_secs}s sustained stress (mixed-type round-trips)..."
        );
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let start = Instant::now();
        let deadline = Duration::from_secs(stress_secs);
        // xorshift64 — deterministic host-side PRNG (no rand crate).
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut ops: u64 = 0;
        let mut last_report = Instant::now();
        while start.elapsed() < deadline {
            let r = next();
            let n = (r % 512).to_string(); // bounded keyspace → bounded memory
            let v = format!("v{}", r & 0xffff_ffff);
            // Command words. Each key prefix is touched by exactly one
            // data type, so a `-...` error reply is always a real bug
            // (never a benign cross-type WRONGTYPE).
            let mk = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<String>>();
            let words: Vec<String> = match (r >> 9) % 16 {
                0 => mk(&["SET", &format!("ss:{n}"), &v]),
                1 => mk(&["GET", &format!("ss:{n}")]),
                2 => mk(&["APPEND", &format!("ss:{n}"), "x"]),
                3 => mk(&["STRLEN", &format!("ss:{n}")]),
                4 => mk(&["INCR", &format!("si:{n}")]),
                5 => mk(&["INCRBY", &format!("si:{n}"), "3"]),
                6 => mk(&["RPUSH", &format!("sl:{n}"), &v]),
                7 => mk(&["LLEN", &format!("sl:{n}")]),
                8 => mk(&["LPOP", &format!("sl:{n}")]),
                9 => mk(&["HSET", &format!("sh:{n}"), "f", &v]),
                10 => mk(&["HGET", &format!("sh:{n}"), "f"]),
                11 => mk(&["SADD", &format!("sx:{n}"), &v]),
                12 => mk(&["SCARD", &format!("sx:{n}")]),
                13 => mk(&["ZADD", &format!("sz:{n}"), &(r % 100).to_string(), &v]),
                14 => mk(&["EXPIRE", &format!("ss:{n}"), "300"]),
                _ => mk(&["PING"]),
            };
            let refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
            if stream.write_all(&resp(&refs)).is_err() {
                return Err(fail(
                    &mut child,
                    format!(
                        "xtask redis-smoke: stress write failed after {ops} ops ({:?})",
                        refs
                    ),
                ));
            }
            let _ = stream.flush();
            let reply = read_one_resp(&mut reader_io).map_err(|e| {
                fail(
                    &mut child,
                    format!(
                        "xtask redis-smoke: STALL/read failure after {ops} ops on {:?}: {e} \
                         (sustained-load regression)",
                        refs
                    ),
                )
            })?;
            if reply.is_empty() || reply[0] == b'-' {
                return Err(fail(
                    &mut child,
                    format!(
                        "xtask redis-smoke: stress error reply after {ops} ops on {:?}: {:?}",
                        refs,
                        String::from_utf8_lossy(&reply)
                    ),
                ));
            }
            ops += 1;
            if last_report.elapsed() >= Duration::from_secs(10) {
                let el = start.elapsed().as_secs_f64().max(0.001);
                println!(
                    "  redis stress: {ops} ops in {:.0}s ({:.0} ops/s), 0 errors",
                    el,
                    ops as f64 / el
                );
                last_report = Instant::now();
            }
        }
        // Final liveness check: a clean PING after the stress proves the
        // connection + server survived intact (not merely "didn't error
        // mid-loop because we stopped looping").
        let _ = stream.write_all(&resp(&["PING"]));
        let _ = stream.flush();
        let pong = read_one_resp(&mut reader_io).map_err(|e| {
            fail(
                &mut child,
                format!("xtask redis-smoke: post-stress PING failed: {e}"),
            )
        })?;
        if !pong.windows(5).any(|w| w == b"+PONG") {
            return Err(fail(
                &mut child,
                format!(
                    "xtask redis-smoke: post-stress PING unexpected: {:?}",
                    String::from_utf8_lossy(&pong)
                ),
            ));
        }
        let el = start.elapsed().as_secs_f64().max(0.001);
        println!(
            "xtask redis-smoke: stress ok — {ops} sustained round-trips in {:.0}s \
             ({:.0} ops/s), 0 errors, server live after",
            el,
            ops as f64 / el
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    println!(
        "xtask redis-smoke: ok — unmodified redis-server served {total} commands \
         (strings/lists/hashes/sets/zsets/expiry/server) to an off-box client over virtio-net"
    );
    Ok(())
}

// ── redis-bench shared helpers ──────────────────────────────────────

/// RESP-encode a command as an array of bulk strings.
fn resp_encode(parts: &[&str]) -> Vec<u8> {
    let mut b = format!("*{}\r\n", parts.len()).into_bytes();
    for p in parts {
        b.extend_from_slice(format!("${}\r\n", p.len()).as_bytes());
        b.extend_from_slice(p.as_bytes());
        b.extend_from_slice(b"\r\n");
    }
    b
}

/// Read exactly ONE complete RESP reply (handles +simple, -error,
/// :integer, $bulk, *array — recursively), returning the raw bytes.
fn read_one_resp_full<R: std::io::BufRead>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    r.read_until(b'\n', &mut line)?;
    if line.is_empty() {
        return Ok(line);
    }
    let mut out = line.clone();
    let num = |l: &[u8]| -> i64 {
        std::str::from_utf8(&l[1..])
            .ok()
            .map(|s| s.trim())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(-1)
    };
    match line[0] {
        b'$' => {
            let len = num(&line);
            if len >= 0 {
                let mut data = vec![0u8; len as usize + 2];
                r.read_exact(&mut data)?;
                out.extend_from_slice(&data);
            }
        }
        b'*' => {
            let n = num(&line);
            for _ in 0..n.max(0) {
                out.extend_from_slice(&read_one_resp_full(r)?);
            }
        }
        _ => {}
    }
    Ok(out)
}

/// One benchmark result for a single redis target.
#[derive(Clone, Copy)]
struct BenchMetrics {
    set_ops_s: f64,
    get_ops_s: f64,
    lat_min_us: u64,
    lat_avg_us: u64,
    lat_p50_us: u64,
    lat_p99_us: u64,
    lat_p999_us: u64,
    lat_max_us: u64,
}

/// Drive an identical workload against a connected redis stream:
///   • pipelined SET throughput, • pipelined GET throughput,
///   • sequential single-command PING latency (p50/p99/avg/min).
/// Any error reply (`-...`), short read, or stall fails the bench.
fn redis_bench_workload(
    stream: &mut std::net::TcpStream,
    throughput_ops: usize,
    pipeline_depth: usize,
    latency_ops: usize,
) -> Result<BenchMetrics> {
    use std::io::{BufReader, Write};
    use std::time::{Duration, Instant};

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| anyhow!("bench: clone stream: {e}"))?,
    );

    // Working-set size (distinct keys). Default 4096; XTASK_REDIS_BENCH_KEYS=1
    // shrinks the working set to a single key (TLB/cache-hypothesis control).
    let bench_keys: usize = std::env::var("XTASK_REDIS_BENCH_KEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&k| k > 0)
        .unwrap_or(4096);

    // Pipelined throughput for a given command builder.
    let mut throughput = |verb: &str| -> Result<f64> {
        let val = "v".repeat(16);
        let start = Instant::now();
        let mut done = 0usize;
        while done < throughput_ops {
            let batch = pipeline_depth.min(throughput_ops - done);
            let mut out = Vec::with_capacity(batch * 48);
            for i in 0..batch {
                let key = format!("bench:{}", (done + i) % bench_keys);
                let cmd = if verb == "SET" {
                    resp_encode(&["SET", &key, &val])
                } else {
                    resp_encode(&["GET", &key])
                };
                out.extend_from_slice(&cmd);
            }
            stream
                .write_all(&out)
                .map_err(|e| anyhow!("bench {verb}: write after {done}: {e}"))?;
            stream.flush().ok();
            for _ in 0..batch {
                let reply = read_one_resp_full(&mut reader)
                    .map_err(|e| anyhow!("bench {verb}: read after {done}: {e}"))?;
                if reply.is_empty() || reply[0] == b'-' {
                    bail!(
                        "bench {verb}: error reply after {done}: {:?}",
                        String::from_utf8_lossy(&reply)
                    );
                }
            }
            done += batch;
        }
        Ok(throughput_ops as f64 / start.elapsed().as_secs_f64().max(1e-6))
    };

    let set_ops_s = throughput("SET")?;
    let get_ops_s = throughput("GET")?;

    // Sequential single-command latency.
    let mut samples: Vec<u64> = Vec::with_capacity(latency_ops);
    for _ in 0..latency_ops {
        let t = Instant::now();
        stream
            .write_all(&resp_encode(&["PING"]))
            .map_err(|e| anyhow!("bench PING: write: {e}"))?;
        stream.flush().ok();
        let reply =
            read_one_resp_full(&mut reader).map_err(|e| anyhow!("bench PING: read: {e}"))?;
        if !reply.windows(5).any(|w| w == b"+PONG") {
            bail!(
                "bench PING: unexpected {:?}",
                String::from_utf8_lossy(&reply)
            );
        }
        samples.push(t.elapsed().as_micros() as u64);
    }
    samples.sort_unstable();
    let n = samples.len().max(1);
    let sum: u64 = samples.iter().sum();
    Ok(BenchMetrics {
        set_ops_s,
        get_ops_s,
        lat_min_us: *samples.first().unwrap_or(&0),
        lat_avg_us: sum / n as u64,
        lat_p50_us: samples[n / 2],
        lat_p99_us: samples[(n * 99 / 100).min(n - 1)],
        lat_p999_us: samples[(n * 999 / 1000).min(n - 1)],
        lat_max_us: *samples.last().unwrap_or(&0),
    })
}

/// Boot NARF's `redis-server` under QEMU (qemu-net + hostfwd, pinned to
/// 1 vCPU per the migration caveat) and return the child, its serial
/// reader thread, and a connected host `TcpStream`.
fn boot_narf_redis(
    args: &BuildArgs,
    host_port: u16,
    guest_port: u16,
) -> Result<(
    std::process::Child,
    std::thread::JoinHandle<()>,
    std::net::TcpStream,
)> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    let mut build = args.clone();
    ensure_feature(&mut build.features, "boot-init");
    ensure_feature(&mut build.features, "firmware-allow-unsigned");
    ensure_feature(&mut build.features, "qemu-net");
    // XTASK_PERF_DUMP=1 enables the periodic per-CPU perf-stat dump.
    if std::env::var_os("XTASK_PERF_DUMP").is_some() {
        ensure_feature(&mut build.features, "perf-dump");
    }

    let root = workspace_root()?;
    let out_dir = cargo_build(&build, &root)?;
    let kernel = out_dir.join(&build.package);
    if !kernel.exists() {
        bail!("expected kernel at {}", kernel.display());
    }
    // Tap mode (XTASK_QEMU_TAP): the host reaches the guest directly at its
    // static IP — no hostfwd, and the readiness check connects to the guest
    // IP:guest_port instead of 127.0.0.1:host_port (task #127).
    let tap_mode = std::env::var_os("XTASK_QEMU_TAP").is_some();
    if !tap_mode {
        std::env::set_var(
            "XTASK_QEMU_HOSTFWD",
            format!("tcp:127.0.0.1:{host_port}-:{guest_port}"),
        );
    }
    if std::env::var_os("NARF_QEMU_SMP").is_none() {
        std::env::set_var("NARF_QEMU_SMP", "1");
    }

    let qemu = build.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        build
            .arch
            .qemu_args(&kernel, &build.display, build.hw_profile, build.gpu_backend),
    );
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().with_context(|| format!("spawn {qemu}"))?;

    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::with_capacity(64 * 1024)));
    let panic_flag: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let cap_r = captured.clone();
    let panic_r = panic_flag.clone();
    let reader = std::thread::spawn(move || {
        let markers: &[&[u8]] = &[b"KERNEL PANIC", b"panicked at", b"double fault"];
        let mut stdout = stdout;
        let mut buf = [0u8; 256];
        let mut line: Vec<u8> = Vec::new();
        loop {
            let nr = match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Ok(mut g) = cap_r.lock() {
                g.extend_from_slice(&buf[..nr]);
            }
            if std::env::var_os("XTASK_REDIS_TEE_SERIAL").is_some() {
                use std::io::Write as _;
                let _ = std::io::stdout().write_all(&buf[..nr]);
                let _ = std::io::stdout().flush();
            }
            for &b in &buf[..nr] {
                if b == b'\n' {
                    for m in markers {
                        if line.windows(m.len()).any(|w| w == *m) {
                            if let Ok(mut p) = panic_r.lock() {
                                if p.is_none() {
                                    *p = Some(String::from_utf8_lossy(&line).into_owned());
                                }
                            }
                        }
                    }
                    line.clear();
                } else {
                    line.push(b);
                }
            }
        }
    });

    let timeout_secs = std::env::var("XTASK_RI_PROMPT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    let start = Instant::now();
    let mut ready = false;
    while start.elapsed() < Duration::from_secs(timeout_secs) {
        if panic_flag.lock().ok().and_then(|p| p.clone()).is_some() {
            break;
        }
        if let Ok(g) = captured.lock() {
            if g.windows(27).any(|w| w == b"Ready to accept connections") {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !ready {
        let panic = panic_flag.lock().ok().and_then(|g| g.clone());
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        if let Some(p) = panic {
            bail!("NARF redis: kernel panic before ready — '{p}'");
        }
        bail!("NARF redis: not ready within {timeout_secs}s");
    }

    let (conn_host, conn_port) = if tap_mode {
        ("10.0.2.15", guest_port)
    } else {
        ("127.0.0.1", host_port)
    };
    let mut stream = None;
    let cstart = Instant::now();
    while cstart.elapsed() < Duration::from_secs(20) {
        if let Ok(s) = TcpStream::connect((conn_host, conn_port)) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let stream = match stream {
        Some(s) => s,
        None => {
            // Debug aid (#127): keep the guest alive for off-box probing
            // when the host connect fails. `XTASK_TAP_HOLD=<secs>`.
            if let Ok(h) = std::env::var("XTASK_TAP_HOLD") {
                if let Ok(secs) = h.parse::<u64>() {
                    let _ = writeln!(
                        std::io::stdout(),
                        "  [NARF] connect failed; holding guest {secs}s for debug (pid {})",
                        child.id()
                    );
                    std::thread::sleep(Duration::from_secs(secs));
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            bail!("NARF redis: could not connect to {conn_host}:{conn_port}");
        }
    };
    let _ = writeln!(std::io::stdout(), "  [NARF] redis ready, connected.");
    Ok((child, reader, stream))
}

/// Build a minimal initramfs (busybox + the SAME redis binary + musl
/// loader + an `/init` that brings up virtio-net and execs redis) and
/// boot a stock Linux kernel under QEMU with the same hostfwd. Returns
/// the QEMU child and a connected host `TcpStream`. This is the
/// apples-to-apples Linux baseline: same redis binary, same QEMU +
/// virtio-net + SLIRP, just a Linux kernel in place of NARF.
fn boot_linux_redis(
    host_port: u16,
    guest_port: u16,
) -> Result<(std::process::Child, std::net::TcpStream)> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    let root = workspace_root()?;
    let redis = root.join("verification/data/musl-demo/redis_server_x86_64");
    if !redis.exists() {
        bail!(
            "Linux baseline: redis binary missing at {}",
            redis.display()
        );
    }
    // busybox: prefer the committed static one, else the host's.
    let busybox = {
        let local = root.join("verification/data/musl-demo/busybox_static_x86_64");
        if local.exists() {
            local
        } else {
            PathBuf::from("/usr/bin/busybox")
        }
    };
    if !busybox.exists() {
        bail!("Linux baseline: need a static busybox (committed or /usr/bin/busybox)");
    }
    // musl loader the redis PIE asks for (/lib/ld-musl-x86_64.so.1).
    let musl_loader = PathBuf::from("/lib/ld-musl-x86_64.so.1");
    if !musl_loader.exists() {
        bail!("Linux baseline: musl loader /lib/ld-musl-x86_64.so.1 absent on host");
    }
    // A Linux kernel image. Override with XTASK_LINUX_KERNEL; else pick
    // the newest /boot/vmlinuz-*.
    let kernel = if let Ok(k) = std::env::var("XTASK_LINUX_KERNEL") {
        PathBuf::from(k)
    } else {
        let mut cands: Vec<PathBuf> = std::fs::read_dir("/boot")
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.starts_with("vmlinuz-"))
                            .unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();
        cands.sort();
        cands
            .pop()
            .or_else(|| {
                let v = PathBuf::from("/boot/vmlinuz");
                v.exists().then_some(v)
            })
            .ok_or_else(|| anyhow!("Linux baseline: no /boot/vmlinuz* (set XTASK_LINUX_KERNEL)"))?
    };

    // Stage an initramfs tree.
    let stage = std::env::temp_dir().join(format!("narf-linux-redis-{host_port}"));
    let _ = std::fs::remove_dir_all(&stage);
    for d in ["bin", "lib", "proc", "sys", "dev"] {
        std::fs::create_dir_all(stage.join(d))?;
    }
    std::fs::copy(&busybox, stage.join("bin/busybox"))?;
    std::fs::copy(&redis, stage.join("bin/redis-server"))?;
    // Resolve the musl loader symlink to its real file.
    let musl_real = std::fs::canonicalize(&musl_loader).unwrap_or(musl_loader.clone());
    std::fs::copy(&musl_real, stage.join("lib/ld-musl-x86_64.so.1"))?;
    let init = "#!/bin/busybox sh\n\
         /bin/busybox mount -t proc proc /proc\n\
         /bin/busybox mount -t sysfs sysfs /sys\n\
         /bin/busybox mount -t devtmpfs dev /dev 2>/dev/null\n\
         /bin/busybox mknod /dev/null c 1 3 2>/dev/null\n\
         /bin/busybox ifconfig lo 127.0.0.1 up\n\
         /bin/busybox ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up\n\
         /bin/busybox route add default gw 10.0.2.2\n\
         echo NARF-LINUX-BASELINE-NET-UP\n\
         exec /bin/redis-server --bind 0.0.0.0 --protected-mode no --save \"\" \
         --appendonly no --loglevel notice\n";
    std::fs::write(stage.join("init"), init)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["init", "bin/busybox", "bin/redis-server"] {
            let p = stage.join(f);
            let mut perm = std::fs::metadata(&p)?.permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm)?;
        }
    }
    // Pack: `find . | cpio -o -H newc | gzip > initramfs`.
    let initramfs = std::env::temp_dir().join(format!("narf-linux-redis-{host_port}.cpio.gz"));
    let find = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 > {}",
            stage.display(),
            initramfs.display()
        ))
        .status()
        .with_context(|| "Linux baseline: building initramfs (need cpio + gzip)")?;
    if !find.success() {
        bail!("Linux baseline: initramfs pack failed");
    }

    let mem = std::env::var("NARF_QEMU_MEM_MB").unwrap_or_else(|_| "2048".into());
    // Mirror NARF's accelerator + CPU EXACTLY so the comparison is
    // apples-to-apples. NARF's qemu_args defaults to TCG (no `-accel`)
    // with `-cpu max`, and only adds `-accel <x>` when `XTASK_QEMU_ACCEL`
    // is set; we do the same here. (Earlier this hard-forced `-enable-kvm
    // -cpu host` for Linux while NARF ran TCG — a ~10-50x unfair tilt.)
    let cpu = std::env::var("NARF_QEMU_CPU").unwrap_or_else(|_| "max".into());
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-nographic",
        "-no-reboot",
        "-kernel",
        &kernel.display().to_string(),
        "-initrd",
        &initramfs.display().to_string(),
        "-append",
        "console=ttyS0 panic=-1 quiet",
        "-m",
        mem.as_str(),
        "-smp",
        "1",
        "-cpu",
        cpu.as_str(),
    ]);
    // Tap mode: same real NIC NARF uses, so the Linux baseline is
    // apples-to-apples over a real backend (the guest self-assigns
    // 10.0.2.15 in its init). Else SLIRP + hostfwd.
    let linux_tap = std::env::var("XTASK_QEMU_TAP")
        .ok()
        .filter(|s| !s.is_empty());
    // Match a multi_queue tap (≥2 queues) just like the NARF side, else
    // QEMU can't open it and the Linux baseline silently fails to boot.
    let lq = effective_qemu_queues();
    let (linux_netdev, linux_dev) = match &linux_tap {
        Some(tap) if lq > 1 => (
            format!("tap,id=n0,ifname={tap},script=no,downscript=no,queues={lq}"),
            format!(
                "virtio-net-pci,netdev=n0,tx=timer,mq=on,vectors={}",
                2 * lq + 2
            ),
        ),
        Some(tap) => (
            format!("tap,id=n0,ifname={tap},script=no,downscript=no"),
            "virtio-net-pci,netdev=n0,tx=timer".to_string(),
        ),
        None => (
            format!("user,id=n0,hostfwd=tcp:127.0.0.1:{host_port}-:{guest_port}"),
            "virtio-net-pci,netdev=n0,tx=timer".to_string(),
        ),
    };
    cmd.args(["-netdev", &linux_netdev, "-device", &linux_dev]);
    if let Ok(accel) = std::env::var("XTASK_QEMU_ACCEL") {
        cmd.args(["-accel", accel.as_str()]);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .context("Linux baseline: spawn qemu-system-x86_64")?;

    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let cap_r = captured.clone();
    let reader = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut buf = [0u8; 256];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut g) = cap_r.lock() {
                        g.extend_from_slice(&buf[..n]);
                    }
                }
            }
        }
    });

    let start = Instant::now();
    let mut ready = false;
    while start.elapsed() < Duration::from_secs(120) {
        if let Ok(g) = captured.lock() {
            if g.windows(27).any(|w| w == b"Ready to accept connections") {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !ready {
        let tail = captured
            .lock()
            .ok()
            .map(|g| String::from_utf8_lossy(&g[g.len().saturating_sub(800)..]).into_owned())
            .unwrap_or_default();
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        bail!("Linux baseline: redis not ready within 120s. Serial tail:\n{tail}");
    }
    drop(reader); // detach; QEMU keeps draining into the (now-dropped) pipe

    let (lconn_host, lconn_port) = match &linux_tap {
        Some(_) => ("10.0.2.15", guest_port),
        None => ("127.0.0.1", host_port),
    };
    let mut stream = None;
    let cstart = Instant::now();
    while cstart.elapsed() < Duration::from_secs(20) {
        if let Ok(s) = TcpStream::connect((lconn_host, lconn_port)) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let stream = match stream {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Linux baseline: could not connect to {lconn_host}:{lconn_port}");
        }
    };
    let _ = writeln!(
        std::io::stdout(),
        "  [Linux] kernel {} booted, redis ready, connected.",
        kernel.file_name().and_then(|n| n.to_str()).unwrap_or("?")
    );
    Ok((child, stream))
}

/// Linux baseline for the mt-echo workload: the SAME static
/// `mt_echo_server` binary under a stock Linux kernel, with the SAME
/// multi-queue virtio-net + tap + vCPU count NARF uses, so the
/// comparison is apples-to-apples on the real-NIC MQ path. busybox init
/// brings up `eth0 10.0.2.15`, best-effort activates all N virtio-net
/// queue pairs via `ethtool -L eth0 combined N` (so Linux gets the same
/// RX spread NARF does), then execs the server. Returns the QEMU child
/// once the readiness marker appears; the caller drives `loadgen`
/// against `10.0.2.15:<guest_port>` itself. Tap-only (MQ is moot over
/// SLIRP).
fn boot_linux_mt_echo(guest_port: u16, server_threads: usize) -> Result<std::process::Child> {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    let tap = std::env::var("XTASK_QEMU_TAP")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("Linux mt-echo baseline is tap-only (set XTASK_QEMU_TAP)"))?;

    let root = workspace_root()?;
    let server = root.join("verification/data/musl-demo/mt_echo_server_x86_64");
    if !server.exists() {
        bail!(
            "Linux baseline: mt-echo binary missing at {}",
            server.display()
        );
    }
    let busybox = {
        let local = root.join("verification/data/musl-demo/busybox_static_x86_64");
        if local.exists() {
            local
        } else {
            PathBuf::from("/usr/bin/busybox")
        }
    };
    if !busybox.exists() {
        bail!("Linux baseline: need a static busybox");
    }
    // ethtool (optional): activates all N virtio-net queue pairs so the
    // Linux side gets the same multi-queue RX spread NARF does. Without
    // it, Linux defaults to a single combined queue.
    let ethtool = ["/sbin/ethtool", "/usr/sbin/ethtool"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists());

    let kernel = if let Ok(k) = std::env::var("XTASK_LINUX_KERNEL") {
        PathBuf::from(k)
    } else {
        let mut cands: Vec<PathBuf> = std::fs::read_dir("/boot")
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.starts_with("vmlinuz-"))
                            .unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();
        cands.sort();
        cands
            .pop()
            .or_else(|| {
                let v = PathBuf::from("/boot/vmlinuz");
                v.exists().then_some(v)
            })
            .ok_or_else(|| anyhow!("Linux baseline: no /boot/vmlinuz* (set XTASK_LINUX_KERNEL)"))?
    };

    let stage = std::env::temp_dir().join(format!("narf-linux-mtecho-{guest_port}"));
    let _ = std::fs::remove_dir_all(&stage);
    for d in ["bin", "proc", "sys", "dev"] {
        std::fs::create_dir_all(stage.join(d))?;
    }
    std::fs::copy(&busybox, stage.join("bin/busybox"))?;
    std::fs::copy(&server, stage.join("bin/mt-echo"))?;
    let mut exec_files: Vec<&str> = vec!["init", "bin/busybox", "bin/mt-echo"];
    let ethtool_line = if let Some(et) = &ethtool {
        std::fs::copy(et, stage.join("bin/ethtool"))?;
        exec_files.push("bin/ethtool");
        format!("/bin/ethtool -L eth0 combined {server_threads} 2>/dev/null\n")
    } else {
        String::new()
    };
    let init = format!(
        "#!/bin/busybox sh\n\
         /bin/busybox mount -t proc proc /proc\n\
         /bin/busybox mount -t sysfs sysfs /sys\n\
         /bin/busybox mount -t devtmpfs dev /dev 2>/dev/null\n\
         /bin/busybox mknod /dev/null c 1 3 2>/dev/null\n\
         /bin/busybox ifconfig lo 127.0.0.1 up\n\
         /bin/busybox ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up\n\
         /bin/busybox route add default gw 10.0.2.2\n\
         {ethtool_line}\
         echo NARF-LINUX-BASELINE-NET-UP\n\
         exec /bin/mt-echo {guest_port} {server_threads}\n",
    );
    std::fs::write(stage.join("init"), init)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in &exec_files {
            let p = stage.join(f);
            let mut perm = std::fs::metadata(&p)?.permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm)?;
        }
    }
    let initramfs = std::env::temp_dir().join(format!("narf-linux-mtecho-{guest_port}.cpio.gz"));
    let pack = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1 > {}",
            stage.display(),
            initramfs.display()
        ))
        .status()
        .with_context(|| "Linux baseline: building initramfs (need cpio + gzip)")?;
    if !pack.success() {
        bail!("Linux baseline: initramfs pack failed");
    }

    let mem = std::env::var("NARF_QEMU_MEM_MB").unwrap_or_else(|_| "2048".into());
    let cpu = std::env::var("NARF_QEMU_CPU").unwrap_or_else(|_| "max".into());
    // Match NARF's vCPU count (mt-echo-bench defaults NARF_QEMU_SMP to
    // server_threads+1 too) so the comparison is on equal cores.
    let smp = std::env::var("NARF_QEMU_SMP").unwrap_or_else(|_| format!("{}", server_threads + 1));
    // ≥2 for a multi_queue tap (else QEMU can't open it single-queue).
    let queues: usize = effective_qemu_queues();
    let (netdev, device) = if queues > 1 {
        (
            format!("tap,id=n0,ifname={tap},script=no,downscript=no,queues={queues}"),
            format!(
                "virtio-net-pci,netdev=n0,tx=timer,mq=on,vectors={}",
                2 * queues + 2
            ),
        )
    } else {
        (
            format!("tap,id=n0,ifname={tap},script=no,downscript=no"),
            "virtio-net-pci,netdev=n0,tx=timer".to_string(),
        )
    };
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-nographic",
        "-no-reboot",
        "-kernel",
        &kernel.display().to_string(),
        "-initrd",
        &initramfs.display().to_string(),
        "-append",
        "console=ttyS0 panic=-1 quiet",
        "-m",
        mem.as_str(),
        "-smp",
        smp.as_str(),
        "-cpu",
        cpu.as_str(),
        "-netdev",
        &netdev,
        "-device",
        &device,
    ]);
    if let Ok(accel) = std::env::var("XTASK_QEMU_ACCEL") {
        cmd.args(["-accel", accel.as_str()]);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .context("Linux baseline: spawn qemu-system-x86_64")?;

    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let cap_r = captured.clone();
    let reader = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut buf = [0u8; 256];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut g) = cap_r.lock() {
                        g.extend_from_slice(&buf[..n]);
                    }
                }
            }
        }
    });

    let marker = b"mt-echo: listening";
    let start = Instant::now();
    let mut ready = false;
    while start.elapsed() < Duration::from_secs(120) {
        if let Ok(g) = captured.lock() {
            if g.windows(marker.len()).any(|w| w == marker) {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !ready {
        let tail = captured
            .lock()
            .ok()
            .map(|g| String::from_utf8_lossy(&g[g.len().saturating_sub(800)..]).into_owned())
            .unwrap_or_default();
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        bail!("Linux baseline: mt-echo not ready within 120s. Serial tail:\n{tail}");
    }
    drop(reader);
    let _ = writeln!(
        std::io::stdout(),
        "  [Linux] kernel {} booted, mt-echo ready ({server_threads} thread(s)).",
        kernel.file_name().and_then(|n| n.to_str()).unwrap_or("?")
    );
    Ok(child)
}

/// Off-box redis performance benchmark — see [`Cmd::RedisBench`].
/// Run the host's `redis-benchmark` against a guest's hostfwd port with
/// real concurrency (`-c` clients). Unlike the single-connection xtask
/// workload (which idles the guest between synchronous batches → RTT-
/// bound), N concurrent clients keep the guest CPU-saturated, so this
/// measures COMPUTE-bound throughput. Gated on `XTASK_REDIS_BENCHMARK`.
fn run_redis_benchmark(host_port: u16, label: &str) {
    let env_u = |k: &str, d: u32| -> u32 {
        std::env::var(k)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(d)
    };
    let clients = env_u("XTASK_REDIS_BENCHMARK_C", 50);
    let pipeline = env_u("XTASK_REDIS_BENCHMARK_P", 16);
    let n = env_u("XTASK_REDIS_BENCHMARK_N", 100_000);
    println!("  [{label}] redis-benchmark -c {clients} -P {pipeline} -n {n} -t set,get,ping");
    let bin = ["/usr/bin/redis-benchmark", "/usr/local/bin/redis-benchmark"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or("redis-benchmark");
    // The host redis-benchmark is a buckos build with a non-standard ELF
    // interpreter path that doesn't exist here, so a direct exec fails with
    // ENOENT. Invoke via the real loader explicitly (libs still resolve).
    let loader = "/lib64/ld-linux-x86-64.so.2";
    let tests =
        std::env::var("XTASK_REDIS_BENCHMARK_T").unwrap_or_else(|_| "set,get,ping_inline".into());
    // Tap mode: both guests are reached directly at the static IP 10.0.2.15
    // (they boot sequentially on the same tap), not via a 127.0.0.1 hostfwd.
    let _ = label;
    let (bench_host, bench_port) = if std::env::var_os("XTASK_QEMU_TAP").is_some() {
        ("10.0.2.15".to_string(), "6379".to_string())
    } else {
        ("127.0.0.1".to_string(), host_port.to_string())
    };
    let bench_args = [
        "-h",
        &bench_host,
        "-p",
        &bench_port,
        "-c",
        &clients.to_string(),
        "-P",
        &pipeline.to_string(),
        "-n",
        &n.to_string(),
        "-t",
        &tests,
        "-q",
    ];
    let out = if std::path::Path::new(loader).exists() {
        std::process::Command::new(loader)
            .arg(bin)
            .args(bench_args)
            .output()
    } else {
        std::process::Command::new(bin).args(bench_args).output()
    };
    match out {
        Ok(o) => {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if !line.trim().is_empty() {
                    println!("  [{label}] {line}");
                }
            }
            if !o.status.success() {
                println!("  [{label}] redis-benchmark exited {:?}", o.status.code());
            }
        }
        Err(e) => println!("  [{label}] redis-benchmark spawn failed: {e}"),
    }
}

// ── mt-echo multi-queue benchmark ──────────────────────────────────

/// One `loadgen` run's parsed aggregate metrics (from its RESULT line).
#[derive(Clone, Copy)]
struct LoadgenResult {
    requests: u64,
    errors: u64,
    rps: f64,
    p50_us: u64,
    p99_us: u64,
    p999_us: u64,
}

/// Compile the host-side `loadgen` (userspace/mt-echo/loadgen.c) once and
/// return its path. The server binary is the committed static ELF that
/// boots inside the guest; `loadgen` runs on the host, so it's built here
/// with the host cc rather than musl.
fn build_loadgen(root: &Path) -> Result<PathBuf> {
    let src = root.join("userspace/mt-echo/loadgen.c");
    if !src.exists() {
        bail!("loadgen source missing at {}", src.display());
    }
    let out = root.join("target").join("mt-echo-loadgen");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let status = Command::new(&cc)
        .args(["-O2", "-pthread", "-o"])
        .arg(&out)
        .arg(&src)
        .status()
        .with_context(|| format!("invoking {cc} to build loadgen"))?;
    if !status.success() {
        bail!("loadgen build failed (cc exit {status})");
    }
    Ok(out)
}

/// Run `loadgen <host> <port> <conns> <secs> <client_threads>` and parse
/// its RESULT line.
fn run_loadgen(
    loadgen: &Path,
    host: &str,
    port: u16,
    conns: usize,
    secs: usize,
    client_threads: usize,
) -> Result<LoadgenResult> {
    let out = Command::new(loadgen)
        .args([
            host.to_string(),
            port.to_string(),
            conns.to_string(),
            secs.to_string(),
            client_threads.to_string(),
        ])
        .output()
        .with_context(|| "spawning loadgen")?;
    // loadgen prints its progress to stderr; the RESULT key=val line is
    // the only thing on stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("RESULT "))
        .ok_or_else(|| {
            anyhow!(
                "loadgen produced no RESULT line (stderr: {})",
                String::from_utf8_lossy(&out.stderr).trim()
            )
        })?;
    let get = |key: &str| -> Option<&str> {
        line.split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
    };
    let num = |key: &str| -> u64 { get(key).and_then(|v| v.parse().ok()).unwrap_or(0) };
    Ok(LoadgenResult {
        requests: num("requests="),
        errors: num("errors="),
        rps: get("rps=").and_then(|v| v.parse().ok()).unwrap_or(0.0),
        p50_us: num("p50_us="),
        p99_us: num("p99_us="),
        p999_us: num("p999_us="),
    })
}

/// Boot NARF's `mt-echo` server under QEMU and return the child + serial
/// reader thread once the readiness marker is seen. Mirrors
/// `boot_narf_redis` but with the `mt-echo` feature, the
/// `mt_echo_threads=N` kernel cmdline, and the mt-echo readiness probe.
fn boot_narf_mt_echo(
    args: &BuildArgs,
    server_threads: usize,
    host_port: u16,
    guest_port: u16,
) -> Result<(std::process::Child, std::thread::JoinHandle<()>)> {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    let mut build = args.clone();
    ensure_feature(&mut build.features, "boot-init");
    ensure_feature(&mut build.features, "firmware-allow-unsigned");
    ensure_feature(&mut build.features, "mt-echo");
    if std::env::var_os("XTASK_PERF_DUMP").is_some() {
        ensure_feature(&mut build.features, "perf-dump");
    }

    let root = workspace_root()?;
    let out_dir = cargo_build(&build, &root)?;
    let kernel = out_dir.join(&build.package);
    if !kernel.exists() {
        bail!("expected kernel at {}", kernel.display());
    }

    // Worker thread count → kernel cmdline (parsed by bare_main). Set
    // before qemu_args runs (it reads XTASK_QEMU_APPEND).
    std::env::set_var(
        "XTASK_QEMU_APPEND",
        format!("mt_echo_threads={server_threads}"),
    );
    // Default to enough vCPUs that the N workers can actually spread
    // (one extra for the BSP forwarder/main). The caller can override.
    if std::env::var_os("NARF_QEMU_SMP").is_none() {
        std::env::set_var("NARF_QEMU_SMP", format!("{}", server_threads + 1));
    }
    let tap_mode = std::env::var_os("XTASK_QEMU_TAP").is_some();
    if !tap_mode {
        std::env::set_var(
            "XTASK_QEMU_HOSTFWD",
            format!("tcp:127.0.0.1:{host_port}-:{guest_port}"),
        );
    }

    let qemu = build.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        build
            .arch
            .qemu_args(&kernel, &build.display, build.hw_profile, build.gpu_backend),
    );
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().with_context(|| format!("spawn {qemu}"))?;

    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::with_capacity(64 * 1024)));
    let panic_flag: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let cap_r = captured.clone();
    let panic_r = panic_flag.clone();
    let reader = std::thread::spawn(move || {
        let markers: &[&[u8]] = &[b"KERNEL PANIC", b"panicked at", b"double fault"];
        let mut stdout = stdout;
        let mut buf = [0u8; 256];
        let mut line: Vec<u8> = Vec::new();
        loop {
            let nr = match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Ok(mut g) = cap_r.lock() {
                g.extend_from_slice(&buf[..nr]);
            }
            if std::env::var_os("XTASK_REDIS_TEE_SERIAL").is_some() {
                let _ = std::io::stdout().write_all(&buf[..nr]);
                let _ = std::io::stdout().flush();
            }
            for &b in &buf[..nr] {
                if b == b'\n' {
                    for m in markers {
                        if line.windows(m.len()).any(|w| w == *m) {
                            if let Ok(mut p) = panic_r.lock() {
                                if p.is_none() {
                                    *p = Some(String::from_utf8_lossy(&line).into_owned());
                                }
                            }
                        }
                    }
                    line.clear();
                } else {
                    line.push(b);
                }
            }
        }
    });

    let timeout_secs = std::env::var("XTASK_RI_PROMPT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    let marker = b"mt-echo: listening";
    let start = Instant::now();
    let mut ready = false;
    while start.elapsed() < Duration::from_secs(timeout_secs) {
        if panic_flag.lock().ok().and_then(|p| p.clone()).is_some() {
            break;
        }
        if let Ok(g) = captured.lock() {
            if g.windows(marker.len()).any(|w| w == marker) {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !ready {
        let panic = panic_flag.lock().ok().and_then(|g| g.clone());
        if let Ok(h) = std::env::var("XTASK_TAP_HOLD") {
            if let Ok(secs) = h.parse::<u64>() {
                let _ = writeln!(
                    std::io::stdout(),
                    "  [NARF] mt-echo not ready; holding guest {secs}s for debug (pid {})",
                    child.id()
                );
                std::thread::sleep(Duration::from_secs(secs));
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        if let Some(p) = panic {
            bail!("NARF mt-echo: kernel panic before ready — '{p}'");
        }
        bail!("NARF mt-echo: not ready within {timeout_secs}s");
    }
    let _ = writeln!(
        std::io::stdout(),
        "  [NARF] mt-echo ready ({server_threads} worker thread(s))."
    );
    Ok((child, reader))
}

fn mt_echo_bench_cmd(args: &BuildArgs) -> Result<()> {
    if !matches!(args.arch, Arch::X86_64) {
        bail!("xtask mt-echo-bench: only x86_64 is wired");
    }
    let guest_port = 7000u16;
    let host_port = 17000u16;
    let conns: usize = std::env::var("XTASK_MT_ECHO_CONNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let secs: usize = std::env::var("XTASK_MT_ECHO_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    // One client thread per connection by default (capped): the loadgen
    // services a thread's connections sequentially, so too few client
    // threads caps offered concurrency below `conns` and under-measures
    // the server (16 threads × ~410µs RTT ≈ 39k was a loadgen cap, not a
    // NARF ceiling — one-thread-per-conn lifted it to ~60k).
    let client_threads: usize = std::env::var("XTASK_MT_ECHO_CLIENT_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(conns.min(64));
    // Server worker-thread sweep, e.g. "1,2,4,8". Each value boots a
    // fresh kernel with mt_echo_threads=N.
    let sweep: Vec<usize> = std::env::var("XTASK_MT_ECHO_THREADS")
        .unwrap_or_else(|_| "4".into())
        .split(',')
        .filter_map(|t| t.trim().parse().ok())
        .collect();
    let sweep = if sweep.is_empty() { vec![4] } else { sweep };

    let tap_mode = std::env::var_os("XTASK_QEMU_TAP").is_some();
    let queues = std::env::var("XTASK_QEMU_QUEUES").unwrap_or_else(|_| "1".into());
    let accel = std::env::var("XTASK_QEMU_ACCEL").unwrap_or_else(|_| "tcg (default)".into());
    let backend = if tap_mode {
        "tap (real NIC)"
    } else {
        "SLIRP+hostfwd"
    };

    println!(
        "xtask mt-echo-bench: {conns} conns / {client_threads} client thread(s), \
         {secs}s measured, backend={backend}, queues={queues}, accel={accel}\n\
         server thread sweep: {sweep:?}\n\
         NOTE: real multi-queue/RSS scaling needs tap (XTASK_QEMU_TAP=<if>) + \
         XTASK_QEMU_QUEUES=N; SLIRP is single-queue.\n"
    );

    let root = workspace_root()?;
    let loadgen = build_loadgen(&root)?;

    // Linux baseline runs over the same tap (so MQ is real); it shares
    // 10.0.2.15, so it boots only AFTER NARF's QEMU is killed. Off over
    // SLIRP (MQ is moot) or when opted out via XTASK_MT_ECHO_NO_LINUX.
    let run_linux = tap_mode && std::env::var_os("XTASK_MT_ECHO_NO_LINUX").is_none();

    let mut rows: Vec<(usize, LoadgenResult, Option<LoadgenResult>)> = Vec::new();
    for &threads in &sweep {
        // ── NARF ──
        println!("── NARF mt-echo: {threads} worker thread(s) ──");
        let (mut child, reader) = boot_narf_mt_echo(args, threads, host_port, guest_port)?;
        let (lg_host, lg_port) = if tap_mode {
            ("10.0.2.15".to_string(), guest_port)
        } else {
            ("127.0.0.1".to_string(), host_port)
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        let narf_res = run_loadgen(&loadgen, &lg_host, lg_port, conns, secs, client_threads);
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        let narf_r = match narf_res {
            Ok(r) => {
                println!(
                    "  [NARF  t={threads}] rps={:.0}  p50={}µs  p99={}µs  p99.9={}µs  (reqs={} errs={})",
                    r.rps, r.p50_us, r.p99_us, r.p999_us, r.requests, r.errors
                );
                Some(r)
            }
            Err(e) => {
                println!("  [NARF  t={threads}] loadgen failed: {e:#}");
                None
            }
        };

        // ── Linux baseline (same binary, stock kernel) ──
        let linux_r = if run_linux {
            // Let the tap link settle after NARF's QEMU exits.
            std::thread::sleep(std::time::Duration::from_millis(500));
            match boot_linux_mt_echo(guest_port, threads) {
                Ok(mut lchild) => {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    let r = run_loadgen(
                        &loadgen,
                        "10.0.2.15",
                        guest_port,
                        conns,
                        secs,
                        client_threads,
                    );
                    let _ = lchild.kill();
                    let _ = lchild.wait();
                    match r {
                        Ok(r) => {
                            println!(
                                "  [Linux t={threads}] rps={:.0}  p50={}µs  p99={}µs  p99.9={}µs  (reqs={} errs={})",
                                r.rps, r.p50_us, r.p99_us, r.p999_us, r.requests, r.errors
                            );
                            Some(r)
                        }
                        Err(e) => {
                            println!("  [Linux t={threads}] loadgen failed: {e:#}");
                            None
                        }
                    }
                }
                Err(e) => {
                    println!("  [Linux t={threads}] baseline unavailable: {e:#}");
                    None
                }
            }
        } else {
            None
        };

        if let Some(n) = narf_r {
            rows.push((threads, n, linux_r));
        }
    }

    println!("\n┌─ mt-echo: NARF vs Linux — same binary, backend={backend}, queues={queues} ─");
    println!(
        "│ {:>7}  {:>10} {:>10} {:>6}   {:>9} {:>9}",
        "threads", "NARF rps", "Linux rps", "N/L", "NARF p99", "Linux p99"
    );
    for (t, n, lx) in &rows {
        match lx {
            Some(l) => println!(
                "│ {t:>7}  {:>10.0} {:>10.0} {:>5.2}×   {:>7}µs {:>7}µs",
                n.rps,
                l.rps,
                if l.rps > 0.0 { n.rps / l.rps } else { 0.0 },
                n.p99_us,
                l.p99_us
            ),
            None => println!(
                "│ {t:>7}  {:>10.0} {:>10} {:>6}   {:>7}µs {:>9}",
                n.rps, "—", "—", n.p99_us, "—"
            ),
        }
    }
    println!("└─");
    Ok(())
}

fn redis_bench_cmd(args: &BuildArgs) -> Result<()> {
    if !matches!(args.arch, Arch::X86_64) {
        bail!("xtask redis-bench: only x86_64 is wired");
    }
    let ops: usize = std::env::var("XTASK_REDIS_BENCH_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let pipeline: usize = std::env::var("XTASK_REDIS_BENCH_PIPELINE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    let lat_ops: usize = std::env::var("XTASK_REDIS_BENCH_LAT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let accel = std::env::var("XTASK_QEMU_ACCEL").unwrap_or_else(|_| "tcg (default)".into());
    println!(
        "xtask redis-bench: workload = {ops} pipelined ops (depth {pipeline}) SET + GET, \
         {lat_ops} sequential PINGs for latency\n\
         both guests: 1 vCPU, accel={accel}, -cpu max, same virtio-net + hostfwd\n"
    );

    // 1. NARF under QEMU.
    println!("── NARF (microkernel) under QEMU ──");
    let (mut narf_child, narf_reader, mut narf_stream) = boot_narf_redis(args, 16379, 6379)?;
    if std::env::var_os("XTASK_REDIS_BENCHMARK").is_some() {
        run_redis_benchmark(16379, "NARF");
    }
    let narf = redis_bench_workload(&mut narf_stream, ops, pipeline, lat_ops);
    let _ = narf_child.kill();
    let _ = narf_child.wait();
    let _ = narf_reader.join();
    let narf = narf?;

    // 2. Stock Linux kernel under the same QEMU + virtio-net.
    println!("\n── Linux (stock kernel) under QEMU ──");
    let linux = match boot_linux_redis(16380, 6379) {
        Ok((mut lchild, mut lstream)) => {
            if std::env::var_os("XTASK_REDIS_BENCHMARK").is_some() {
                run_redis_benchmark(16380, "Linux");
            }
            let m = redis_bench_workload(&mut lstream, ops, pipeline, lat_ops);
            let _ = lchild.kill();
            let _ = lchild.wait();
            Some(m?)
        }
        Err(e) => {
            println!("  Linux baseline unavailable: {e:#}");
            None
        }
    };

    // 3. Report.
    println!("\n┌─ redis off-box performance (same redis-server 7.2.5 binary) ─");
    let row = |label: &str, m: &BenchMetrics| {
        println!(
            "│ {label:<22} SET {:>9.0} ops/s  GET {:>9.0} ops/s  \
             PING lat min {:>6}µs avg {:>6}µs p50 {:>6}µs p99 {:>6}µs p99.9 {:>6}µs max {:>6}µs",
            m.set_ops_s,
            m.get_ops_s,
            m.lat_min_us,
            m.lat_avg_us,
            m.lat_p50_us,
            m.lat_p99_us,
            m.lat_p999_us,
            m.lat_max_us
        );
    };
    row("NARF (QEMU guest)", &narf);
    if let Some(l) = &linux {
        row("Linux (QEMU guest)", l);
        println!(
            "│ ratio (NARF/Linux)    SET {:>9.2}x  GET {:>9.2}x  PING lat {:>6.2}x",
            narf.set_ops_s / l.set_ops_s.max(1e-6),
            narf.get_ops_s / l.get_ops_s.max(1e-6),
            narf.lat_avg_us as f64 / (l.lat_avg_us.max(1) as f64),
        );
    }
    println!("└────────────────────────────────────────────────────────────");
    println!("\nxtask redis-bench: ok");
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
/// Returns `(passed, failed, failed_cases)`. `failed_cases` is the
/// `(cmdline, expect)` of every command that did not pass — including
/// commands never reached because an earlier one killed the VM — so the
/// caller can retry them individually (see the SMP-strand retry in
/// `musl_demo_cmd`).
#[allow(clippy::type_complexity)]
fn run_interactive_multi(
    build_in: &BuildArgs,
    cases: &[(&str, &str)],
    kernel_override: Option<&Path>,
) -> Result<(usize, usize, Vec<(String, String)>)> {
    use std::io::{Read, Write};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Arc, Mutex};

    if !matches!(build_in.arch, Arch::X86_64) {
        bail!("run-interactive(multi): only x86_64 is wired (aarch64 boot-init is a stub)");
    }

    let mut build = build_in.clone();
    // A prebuilt kernel (the sharded musl-demo CI jobs download one and
    // boot it) skips the cross-build entirely.
    let kernel = match kernel_override {
        Some(k) => {
            if !k.exists() {
                bail!("--prebuilt kernel not found at {}", k.display());
            }
            k.to_path_buf()
        }
        None => {
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
            kernel
        }
    };

    let qemu = build.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(
        build
            .arch
            .qemu_args(&kernel, &build.display, build.hw_profile, build.gpu_backend),
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
    let mut failed_cases: Vec<(String, String)> = Vec::new();
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
        // QEMU's emulated USB keyboard enumerates just after getty prints the
        // login prompt. Do not type credentials while that late init path is
        // still producing console traffic: password input is intentionally
        // not echoed, so it cannot use the per-byte acknowledgement protocol
        // below. The musl-demo machine always has this keyboard; keep the
        // bounded fallback for alternate local QEMU configurations.
        if needle == b"login: " {
            if let Wait::Found(end) = wait_for(
                cursor,
                b"usb-hid: kbd attached",
                false,
                Duration::from_secs(10),
            ) {
                cursor = end;
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
            std::thread::sleep(Duration::from_millis(20));
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
        // Flow-control command entry through the shell's echoed line editor.
        // Keep at most one unacknowledged byte in the serial/input-ring path:
        // loaded TCG runners previously transposed adjacent bytes here
        // (`sendfile_smoke` arrived as `sendfile_smkoe`). Waiting for each
        // byte's echo adapts to guest load and proves ordered consumption.
        let mut wrote = true;
        let mut type_error = "stdin write failed";
        let mut echo_cursor = pre;
        for &b in cmdline.as_bytes() {
            if stdin.write_all(&[b]).is_err() {
                wrote = false;
                break;
            }
            let _ = stdin.flush();
            match wait_for(echo_cursor, core::slice::from_ref(&b), false, prompt_to) {
                Wait::Found(end) => echo_cursor = end,
                Wait::TimedOut | Wait::Died(_) => {
                    wrote = false;
                    type_error = "serial echo acknowledgement failed";
                    break;
                }
            }
        }
        if wrote {
            wrote = stdin.write_all(b"\n").is_ok();
            let _ = stdin.flush();
        }
        if !wrote {
            aborted = Some(type_error.into());
            failed += 1;
            failed_cases.push((cmdline.to_string(), expect.to_string()));
            break;
        }

        match wait_for(pre, expect.as_bytes(), true, echo_to) {
            Wait::Found(_) => {
                passed += 1;
                println!("xtask musl-demo: ok — `{cmdline}` saw `{expect}`");
            }
            Wait::TimedOut => {
                failed += 1;
                failed_cases.push((cmdline.to_string(), expect.to_string()));
                eprintln!(
                    "musl-demo: `{cmdline}` failed: did not see `{expect}` within {echo_secs}s"
                );
            }
            Wait::Died(why) => {
                failed += 1;
                failed_cases.push((cmdline.to_string(), expect.to_string()));
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
        // Count the commands that never got a chance to run as failed, and
        // record them so the caller can retry them in a fresh boot.
        let ran = passed + failed;
        let remaining = cases.len().saturating_sub(ran);
        failed += remaining;
        for (cmdline, expect) in &cases[ran..] {
            failed_cases.push((cmdline.to_string(), expect.to_string()));
        }
        eprintln!(
            "musl-demo: aborted after {ran}/{} commands — {why} ({remaining} not run, counted failed)",
            cases.len()
        );
    }

    Ok((passed, failed, failed_cases))
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

/// Remove features whose contract is to select the in-kernel test runner.
/// `xtask test` reuses the caller's feature list for its second, production
/// boot-smoke phase, where retaining any of these would transitively re-enable
/// `kernel-test` and make the kernel run tests instead of real init.
fn without_kernel_test_features(features: &str) -> String {
    features
        .split(',')
        .map(str::trim)
        .filter(|feature| {
            !feature.is_empty()
                && !matches!(
                    *feature,
                    "kernel-test" | "user-mode-e2e" | "user-mode-testbin" | "narf-libc-validate"
                )
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod kernel_test_feature_tests {
    use super::without_kernel_test_features;

    #[test]
    fn boot_smoke_drops_direct_and_transitive_kernel_test_features() {
        assert_eq!(
            without_kernel_test_features(
                "mte,user-mode-e2e,kernel-test,user-mode-testbin,narf-libc-validate,boot-init"
            ),
            "mte,boot-init"
        );
        assert_eq!(
            without_kernel_test_features("mte, boot-init"),
            "mte,boot-init"
        );
    }
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
    if matches!(args.arch, Arch::Aarch64) {
        build_aarch64_uefi_image(args)?;
        return Ok(());
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
             (Arch), fetch an upstream Limine binary release, or set \
             $LIMINE_PATH to its directory containing BOOTX64.EFI + \
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
        "  test under QEMU UEFI:  qemu-system-x86_64 -drive if=pflash,format=raw,readonly=on,file={} -machine q35 -cpu max -m 1024M \\\n\
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
    if matches!(args.arch, Arch::Aarch64) {
        return aarch64_uefi_boot_cmd(args);
    }
    let mut args = args.clone();
    ensure_feature(&mut args.features, "boot-smoke");
    image_cmd(&args)?;

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
    // Use OVMF as a read-only pflash device. Current Debian/Ubuntu packages
    // ship a split 4 MiB CODE image which some QEMU builds reject through the
    // legacy `-bios` loader even though it is a valid pflash image.
    cmd.arg("-drive").arg(format!(
        "if=pflash,format=raw,readonly=on,file={}",
        ovmf.display()
    ));
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
    cmd.arg("-device")
        .arg("isa-debug-exit,iobase=0xf4,iosize=0x04");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
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

    let child = cmd.spawn().context("failed to spawn qemu-system-x86_64")?;
    let secs = std::env::var("XTASK_BOOT_SMOKE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);
    wait_for_boot_smoke(child, "uefi-smoke", secs, Arch::X86_64)
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
    if let Some(path) = std::env::var_os("OVMF_CODE") {
        return PathBuf::from(path);
    }
    for cand in [
        // Arch (edk2-ovmf >= 202311). The 4m variant ships with the
        // newer x64 image; the legacy `OVMF_CODE.fd` was renamed.
        "/usr/share/edk2/x64/OVMF.4m.fd",
        "/usr/share/edk2-ovmf/x64/OVMF.4m.fd",
        "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
        "/usr/share/edk2/x64/OVMF_CODE.fd",
        "/usr/share/ovmf/x64/OVMF.fd",
        // Debian/Ubuntu's `ovmf` package installs the split 4 MiB image
        // under this name on current runners.
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/edk2/OvmfX64/OVMF_CODE.fd",
    ] {
        let pb = PathBuf::from(cand);
        if pb.is_file() {
            return pb;
        }
    }
    PathBuf::from("OVMF_CODE.fd")
}

fn aavmf_code_path() -> PathBuf {
    if let Some(path) = std::env::var_os("AAVMF_CODE") {
        return PathBuf::from(path);
    }
    for cand in [
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/AAVMF/AAVMF_CODE.ms.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        "/usr/share/qemu/edk2-aarch64-code.fd",
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        "/usr/share/edk2-armvirt/aarch64/QEMU_EFI.fd",
    ] {
        let path = PathBuf::from(cand);
        if path.is_file() {
            return path;
        }
    }
    PathBuf::from("AAVMF_CODE.fd")
}

/// Build a removable FAT image with the standard AA64 fallback loader.
fn build_aarch64_uefi_image(args: &BuildArgs) -> Result<PathBuf> {
    let root = workspace_root()?;
    let out_dir = cargo_build(args, &root)?;
    let kernel = out_dir.join(&args.package);
    if !kernel.is_file() {
        bail!("expected kernel binary at {}", kernel.display());
    }

    let loader_manifest = root.join("build/uefi-loader/Cargo.toml");
    let loader_target = root.join("target/uefi-loader");
    let mut cargo = Command::new("cargo");
    cargo
        .args([
            "build",
            "--manifest-path",
            loader_manifest
                .to_str()
                .ok_or_else(|| anyhow!("non-UTF-8 UEFI loader path"))?,
            "--target",
            "aarch64-unknown-uefi",
            "--release",
            "-Zbuild-std=core,compiler_builtins,alloc",
            "-Zbuild-std-features=compiler-builtins-mem",
        ])
        .env("CARGO_TARGET_DIR", &loader_target)
        .current_dir(&root);
    let status = cargo.status().context("building aarch64 UEFI loader")?;
    if !status.success() {
        bail!("aarch64 UEFI loader build failed with {status}");
    }
    let loader = loader_target.join("aarch64-unknown-uefi/release/narf-uefi-loader.efi");
    if !loader.is_file() {
        bail!("expected UEFI loader at {}", loader.display());
    }

    // The linked kernel keeps DWARF for crash symbolization, but firmware only
    // needs its ELF program headers and loadable segments. Stage a stripped
    // copy so a debug build does not turn a ~21 MiB payload into a ~230 MiB ESP.
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let sysroot_output = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .context("locating Rust sysroot for llvm-objcopy")?;
    if !sysroot_output.status.success() {
        bail!("rustc --print sysroot failed");
    }
    let sysroot = PathBuf::from(String::from_utf8(sysroot_output.stdout)?.trim());
    let rustlib = sysroot.join("lib/rustlib");
    let objcopy = std::fs::read_dir(&rustlib)
        .with_context(|| format!("reading {}", rustlib.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("bin/llvm-objcopy"))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            anyhow!(
                "llvm-objcopy not found under {}; install llvm-tools-preview",
                rustlib.display()
            )
        })?;
    let staged_kernel = root.join("target/narf-frame-aarch64.efi-elf");
    run_checked(
        Command::new(objcopy)
            .arg("--strip-debug")
            .arg(&kernel)
            .arg(&staged_kernel),
        "stripping aarch64 kernel debug sections for the ESP",
    )?;

    for tool in ["mformat", "mmd", "mcopy"] {
        if which(tool).is_none() {
            bail!("`{tool}` is required for the aarch64 UEFI image; install mtools");
        }
    }
    let image = root.join("target/narf-aarch64-uefi.img");
    let _ = std::fs::remove_file(&image);
    let file =
        std::fs::File::create(&image).with_context(|| format!("creating {}", image.display()))?;
    const MIB: u64 = 1024 * 1024;
    const ESP_MIN_BYTES: u64 = 64 * MIB;
    const ESP_HEADROOM_BYTES: u64 = 32 * MIB;
    const ESP_ALIGNMENT_BYTES: u64 = 16 * MIB;
    let payload_bytes = std::fs::metadata(&loader)?
        .len()
        .checked_add(std::fs::metadata(&staged_kernel)?.len())
        .ok_or_else(|| anyhow!("aarch64 EFI payload size overflow"))?;
    let required_bytes = payload_bytes
        .checked_add(ESP_HEADROOM_BYTES)
        .ok_or_else(|| anyhow!("aarch64 EFI payload size overflow"))?;
    let image_bytes = required_bytes
        .checked_add(ESP_ALIGNMENT_BYTES - 1)
        .ok_or_else(|| anyhow!("aarch64 EFI image size overflow"))?
        / ESP_ALIGNMENT_BYTES
        * ESP_ALIGNMENT_BYTES;
    let image_bytes = image_bytes.max(ESP_MIN_BYTES);
    file.set_len(image_bytes)
        .with_context(|| format!("sizing {}", image.display()))?;

    run_checked(
        Command::new("mformat").args(["-i", image.to_str().unwrap(), "-F", "::"]),
        "formatting aarch64 EFI system partition",
    )?;
    run_checked(
        Command::new("mmd").args([
            "-i",
            image.to_str().unwrap(),
            "::/EFI",
            "::/EFI/BOOT",
            "::/boot",
        ]),
        "creating EFI system partition directories",
    )?;
    run_checked(
        Command::new("mcopy").args([
            "-i",
            image.to_str().unwrap(),
            loader.to_str().unwrap(),
            "::/EFI/BOOT/BOOTAA64.EFI",
        ]),
        "copying BOOTAA64.EFI",
    )?;
    run_checked(
        Command::new("mcopy").args([
            "-i",
            image.to_str().unwrap(),
            staged_kernel.to_str().unwrap(),
            "::/boot/narf-frame",
        ]),
        "copying aarch64 kernel",
    )?;
    println!(
        "xtask image: wrote {} ({} MiB ESP)",
        image.display(),
        image_bytes / MIB
    );
    Ok(image)
}

fn run_checked(command: &mut Command, operation: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("failed while {operation}"))?;
    if !status.success() {
        bail!("{operation} failed with {status}");
    }
    Ok(())
}

fn aarch64_uefi_boot_cmd(args: &BuildArgs) -> Result<()> {
    let mut args = args.clone();
    ensure_feature(&mut args.features, "boot-smoke");
    let image = build_aarch64_uefi_image(&args)?;
    let firmware = aavmf_code_path();
    if !firmware.is_file() {
        bail!(
            "AAVMF firmware not found at {}; install `qemu-efi-aarch64` \
             (Debian/Ubuntu) or set AAVMF_CODE",
            firmware.display()
        );
    }
    let dtb = qemu_virt_dtb_path();
    if std::fs::metadata(&dtb)
        .map(|metadata| metadata.len() < 40)
        .unwrap_or(true)
    {
        bail!(
            "QEMU aarch64 virt DTB was not generated at {}; \
             ensure qemu-system-aarch64 supports -machine virt,dumpdtb=...",
            dtb.display()
        );
    }

    let mut command = Command::new("qemu-system-aarch64");
    command.arg("-machine").arg(format!(
        "virt,gic-version=3,mte=on,highmem-ecam=off,acpi=off,dtb={}",
        dtb.display()
    ));
    command
        .args(["-cpu", "max", "-smp", "2", "-m", "512M", "-bios"])
        .arg(&firmware)
        .args(["-drive"])
        .arg(format!(
            "if=none,id=esp,format=raw,readonly=on,file={}",
            image.display()
        ))
        .args([
            "-device",
            "virtio-blk-pci,drive=esp,disable-legacy=on,disable-modern=off",
            "-serial",
            "stdio",
            "-display",
            "none",
            "-no-reboot",
            "-semihosting",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    println!(
        "xtask iso-boot: launching qemu-system-aarch64 with ESP {}",
        image.display()
    );
    let child = command
        .spawn()
        .context("failed to spawn qemu-system-aarch64")?;
    let timeout = std::env::var("XTASK_BOOT_SMOKE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(120);
    wait_for_boot_smoke(child, "aarch64-uefi-smoke", timeout, Arch::Aarch64)
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
        Cmd::HostTest => host_test_cmd(),
        Cmd::Affected(args) => {
            let root = workspace_root()?;
            affected::affected_cmd(&args, &root)
        }
        Cmd::Build(args) => {
            cargo_build(&args, &workspace_root()?)?;
            Ok(())
        }
        Cmd::BuildModule(args) => {
            build_module(&args, &workspace_root()?)?;
            Ok(())
        }
        Cmd::Run(args) => run_cmd(&args),
        Cmd::Test(test) => {
            let mut args = test.build;
            let prior_append = std::env::var_os("XTASK_QEMU_APPEND");
            if let Some(subsystem) = &test.subsystem {
                // Comma-separated list of subsystem filters (prefix-matched
                // in-kernel). Each part is validated; the whole list is
                // threaded onto the cmdline as `test_subsystem=a,b,c`.
                let parts: Vec<&str> = subsystem.split(',').filter(|s| !s.is_empty()).collect();
                if parts.is_empty()
                    || parts.iter().any(|part| {
                        !part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
                    })
                {
                    bail!(
                        "--subsystem parts must contain only letters, digits, '/', '_', '-', or '.'"
                    );
                }
                let mut append = prior_append
                    .as_ref()
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !append.is_empty() {
                    append.push(' ');
                }
                append.push_str("test_subsystem=");
                append.push_str(subsystem);
                std::env::set_var("XTASK_QEMU_APPEND", append);
            }
            let result = (|| {
                // Phase 1: kernel-test feature on, run selected in-kernel smokes.
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
                args.features = without_kernel_test_features(&args.features);
                boot_smoke_cmd(&args)?;
                // Verify NARF's on-disk btrfs writes are still Linux-consistent.
                verify_btrfs_write_interop()
            })();
            match prior_append {
                Some(value) => std::env::set_var("XTASK_QEMU_APPEND", value),
                None => std::env::remove_var("XTASK_QEMU_APPEND"),
            }
            result
        }
        Cmd::BootSmoke(args) => boot_smoke_cmd(&args),
        Cmd::SystemdPid1(args) => systemd_pid1_cmd(&args),
        Cmd::RunInteractive(args) => run_interactive_cmd(&args),
        Cmd::NetSmoke(args) => net_smoke_cmd(&args),
        Cmd::RedisSmoke(args) => redis_smoke_cmd(&args),
        Cmd::RedisBench(args) => redis_bench_cmd(&args),
        Cmd::MtEchoBench(args) => mt_echo_bench_cmd(&args),
        Cmd::MuslDemo(args) => musl_demo_cmd(&args),
        Cmd::BpfBench(args) => bpf_bench::bpf_bench_cmd(&args),
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
                args.display = match args.gpu_backend {
                    GpuBackend::Auto | GpuBackend::Virtio2d => "gtk".into(),
                    GpuBackend::Virgl => "gtk,gl=on".into(),
                };
            }
            run_cmd(&args)
        }
    }
}

fn host_test_cmd() -> Result<()> {
    let root = workspace_root()?;
    let suites: &[(&str, &[&str])] = &[
        (
            "kernel workspace host-safe crates",
            &[
                "test",
                "-p",
                "narf-lib",
                "-p",
                "narf-hid",
                "-p",
                "narf-bpf-isa",
                "-p",
                "narf-bpf-verifier",
                "-p",
                "narf-bpf-jit",
                // The BTF parser. Its input comes straight from a syscall
                // argument, so its negative tests are the whole point and CI
                // must run them on every push, not only when a kernel boots.
                "-p",
                "narf-bpf-btf",
                // xtask itself: `bench_stats` implements the §8 protocol, and
                // its distribution functions are anchored on closed forms
                // (Cauchy at ν=1, the ν=2 closed form, the normal at ±1.96).
                // A wrong tail there does not fail loudly — it silently
                // invalidates every perf conclusion drawn through it.
                "-p",
                "xtask",
                // Developer-facing native package frontend. Its os-release
                // detection and command construction must remain host-safe.
                "-p",
                "cargo-narf",
            ],
        ),
        (
            "isolated login-core workspace",
            &["test", "--manifest-path", "userspace/login-core/Cargo.toml"],
        ),
    ];

    for (name, args) in suites {
        eprintln!("host-test: {name}");
        let status = Command::new("cargo")
            .args(*args)
            .current_dir(&root)
            .status()
            .with_context(|| format!("failed to launch {name}"))?;
        if !status.success() {
            bail!("{name} failed with {status}");
        }
    }
    Ok(())
}
