// NARF xtask orchestrator.
// Spec: build/specification/spec.md §3.
//
// `cargo xtask run   --arch=x86_64 [--release]`  — cross-build + QEMU boot
// `cargo xtask test  --arch=aarch64`             — boot + run kernel tests
// `cargo xtask image --arch=x86_64 --bootloader=limine` — bootable ISO
//
// Stage 1 lands `run` and `build` with the QEMU command line per arch.
// `test` defers until `verification/` has its `#[kernel_test]` macro;
// `image` defers until `boot/` is wired.

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
    /// Cross-compile and run kernel tests under QEMU. (Stage 1: stub.)
    Test(BuildArgs),
    /// Produce a bootable image. (Stage 1: stub.)
    Image(BuildArgs),
}

#[derive(Parser, Clone)]
struct BuildArgs {
    /// Target architecture.
    #[arg(long, value_enum, default_value_t = Arch::X86_64)]
    arch: Arch,

    /// Build with `--release`.
    #[arg(long)]
    release: bool,

    /// Crate to build. `narf-frame` is the kernel bin; `narf-lib` is a rlib
    /// used for cross-target sanity checks.
    #[arg(long, default_value = "narf-frame")]
    package: String,

    /// Forward-list of cargo features to enable. Comma-separated.
    /// Example: `--features idt-selftest`.
    #[arg(long, default_value = "")]
    features: String,
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
            // `aarch64-unknown-none-softfloat` trips a future-incompat
            // warning in stdlib's NEON intrinsics (issue #134375 —
            // `target_feature(enable = "neon")` on softfloat is
            // unsound). `aarch64-unknown-none` is the plain variant
            // that kernel ports conventionally target; we keep
            // floating-point disabled by runtime convention
            // (CPACR_EL1.FPEN left at its reset state).
            Arch::Aarch64 => "aarch64-unknown-none",
        }
    }

    fn qemu_bin(self) -> &'static str {
        match self {
            Arch::X86_64  => "qemu-system-x86_64",
            Arch::Aarch64 => "qemu-system-aarch64",
        }
    }

    fn qemu_args(self, kernel: &Path) -> Vec<String> {
        let kernel = kernel.display().to_string();
        match self {
            // x86_64 via PVH direct-kernel load. `isa-debug-exit` lets the
            // guest exit QEMU by writing to I/O port 0xF4 (status = value<<1 | 1).
            // `-no-reboot` stops QEMU on triple-fault instead of infinite resets.
            //
            // NVMe attachment: an `nvme` device backed by a small raw
            // image gives the kernel a real PCIe controller to drive
            // (vendor 0x1b36, device 0x0010 — QEMU's standard NVMe
            // ID). The image is created lazily by `nvme_image_path`
            // before launch; a 1 MiB blank file is plenty for the
            // admin-queue bring-up test and any future single-LBA
            // round-trip smoke.
            Arch::X86_64 => {
                let img = nvme_image_path()
                    .display().to_string();
                vec![
                    "-machine".into(), "q35".into(),
                    "-cpu".into(),     "max".into(),
                    "-m".into(),       "256M".into(),
                    "-serial".into(),  "stdio".into(),
                    "-display".into(), "none".into(),
                    "-no-reboot".into(),
                    "-device".into(),  "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
                    "-drive".into(),
                    format!("if=none,id=nvm0,format=raw,file={img}"),
                    "-device".into(),  "nvme,drive=nvm0,serial=narf".into(),
                    "-kernel".into(),  kernel,
                ]
            },
            // aarch64 virt machine with GICv3 (system-register interface
            // at ICC_*_EL1). Default QEMU virt is GICv2 (MMIO); forcing
            // GICv3 gives us parity with x86_64's x2APIC programming
            // model (MSRs).
            // `-semihosting` enables the SYS_EXIT path.
            Arch::Aarch64 => vec![
                // `mte=on` enables full MTE (level 2+): tag storage,
                // accessible GCR_EL1/TFSR_EL1, SCTLR_EL1.ATA/TCF gates.
                // Without this QEMU exposes only MTE level 1 (instruction
                // support but no in-memory tag check).
                // `highmem-ecam=off` forces the PCIe ECAM into the
                // 0x3F00_0000 lowmem window. QEMU's default for newer
                // virt machines is highmem (4 TiB+), which is outside
                // the 1 GiB identity map our boot stub installs;
                // forcing low keeps PCIe walks reachable until ioremap
                // for >4 GiB lands.
                "-machine".into(),  "virt,gic-version=3,mte=on,highmem-ecam=off".into(),
                "-cpu".into(),      "max".into(),
                "-m".into(),        "256M".into(),
                "-serial".into(),   "stdio".into(),
                "-display".into(),  "none".into(),
                "-no-reboot".into(),
                "-semihosting".into(),
                // Attach an NVMe device on aarch64 too — same image as
                // x86_64. Once DTB-driven PCIe walking finds it, the
                // existing NVMe smokes naturally extend to aarch64.
                "-drive".into(),
                format!("if=none,id=nvm0,format=raw,file={}",
                        nvme_image_path().display()),
                "-device".into(),   "nvme,drive=nvm0,serial=narf".into(),
                // QEMU's `-kernel <elf>` path on aarch64 does not
                // load a `-dtb` blob into RAM (the DTB-loading code
                // path is gated on `is_linux=1`). Instead we
                // force-load the dumped DTB at a fixed physical
                // address (`DTB_LOAD_ADDR`) via `-device loader`,
                // and the boot stub picks it up there.
                "-device".into(),
                format!("loader,file={},addr={:#x},force-raw=on",
                        qemu_virt_dtb_path().display(), DTB_LOAD_ADDR),
                "-kernel".into(),   kernel,
            ],
        }
    }
}

/// Path to the NVMe-backing raw image that x86_64 QEMU attaches to
/// the emulated NVMe controller. Created on demand at 1 MiB. Stored
/// in `target/` so a `cargo clean` removes it; persists across runs
/// to skip the write on subsequent boots.
/// Physical address at which xtask force-loads the dumped DTB on
/// aarch64. Must match the address `boot/aarch64/parse_raw` searches
/// for the FDT magic. Picked to be high enough to be past the kernel
/// image (kernel is loaded at 0x4008_0000 on virt; 0x4f00_0000 leaves
/// ~240 MiB of head room). Must stay inside the `lo_L1[1]` 1 GiB
/// Normal-mapped block (0x4000_0000..0x8000_0000).
const DTB_LOAD_ADDR: u64 = 0x4F00_0000;

/// Path to the cached QEMU `virt` DTB. Lazily generated by invoking
/// `qemu-system-aarch64 -machine ...,dumpdtb=PATH` if missing. The
/// machine line must mirror the `-machine` we pass at run time so
/// the DTB describes the same hardware.
fn qemu_virt_dtb_path() -> PathBuf {
    let root = workspace_root().unwrap_or_else(|_| PathBuf::from("."));
    let path = root.join("target").join("qemu-virt.dtb");
    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // dumpdtb writes the DTB and exits without running. Mirror
        // the machine line below so the dumped DTB matches the
        // run-time topology.
        let _ = Command::new("qemu-system-aarch64")
            .arg("-machine")
            .arg(format!(
                "virt,gic-version=3,mte=on,highmem-ecam=off,dumpdtb={}",
                path.display()))
            .arg("-cpu").arg("max")
            .arg("-m").arg("256M")
            .arg("-display").arg("none")
            .arg("-no-reboot")
            .arg("-drive").arg(format!(
                "if=none,id=nvm0,format=raw,file={}",
                nvme_image_path().display()))
            .arg("-device").arg("nvme,drive=nvm0,serial=narf")
            .status();
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
        // 1 MiB of zeros — small enough that the file isn't a
        // commit-noise risk and large enough that QEMU NVMe accepts
        // it as a non-empty namespace.
        let _ = std::fs::write(&path, vec![0u8; 1024 * 1024]);
    }
    path
}

fn workspace_root() -> Result<PathBuf> {
    // CARGO_MANIFEST_DIR points at build/xtask; parent().parent() is the workspace.
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
        // build-std scoped to the cross targets only. See .cargo/config.toml.
        // `no-f16-f128` keeps compiler_builtins from pulling soft-float f128
        // lowering paths that LLVM can't soften under `code-model=kernel`.
        // `alloc` comes along because narf-frame registers a
        // #[global_allocator] and uses `alloc::boxed::Box` for tasks.
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

    // The artefact path convention — kernel crates produce a library; once
    // `frame/` lands with a `[[bin]]` target, this function switches to
    // returning the bin path.
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
    cmd.args(args.arch.qemu_args(&kernel));
    
    println!("xtask: launching {} {}", qemu, kernel.display());
    
    let mut child = cmd.spawn()
        .with_context(|| format!("failed to spawn {qemu}"))?;

    // Wait for up to 240 seconds. e2e suite + new syscall additions
    // push total runtime higher; healthy runs still finish well
    // under this.
    match child.wait_timeout(Duration::from_secs(240))? {
        Some(status) => {
            println!("xtask: {qemu} exited with {status}");
        }
        None => {
            child.kill()?;
            child.wait()?;
            bail!("xtask: {qemu} timed out after 240s (possible kernel hang)");
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
            // Run the verification/ harness: build with `kernel-test`
            // feature on, boot under QEMU, map isa-debug-exit status
            // to cargo test's "passed" / "failed" convention.
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
    }
}
