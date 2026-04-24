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
            Arch::X86_64 => vec![
                "-machine".into(), "q35".into(),
                "-cpu".into(),     "max".into(),
                "-m".into(),       "256M".into(),
                "-serial".into(),  "stdio".into(),
                "-display".into(), "none".into(),
                "-no-reboot".into(),
                "-device".into(),  "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
                "-kernel".into(),  kernel,
            ],
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
                "-machine".into(),  "virt,gic-version=3,mte=on".into(),
                "-cpu".into(),      "max".into(),
                "-m".into(),        "256M".into(),
                "-serial".into(),   "stdio".into(),
                "-display".into(),  "none".into(),
                "-no-reboot".into(),
                "-semihosting".into(),
                "-kernel".into(),   kernel,
            ],
        }
    }
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

    // Wait for up to 15 seconds. If the kernel hasn't finished the
    // exit-gate demo by then, it's likely hung.
    match child.wait_timeout(Duration::from_secs(15))? {
        Some(status) => {
            println!("xtask: {qemu} exited with {status}");
        }
        None => {
            child.kill()?;
            child.wait()?;
            bail!("xtask: {qemu} timed out after 15s (possible kernel hang)");
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
