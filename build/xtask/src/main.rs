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

    /// Crate to build (defaults to the first kernel crate — Stage 1 only has `narf-lib`).
    #[arg(long, default_value = "narf-lib")]
    package: String,
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
            Arch::Aarch64 => "aarch64-unknown-none-softfloat",
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
            // Minimal x86_64 QEMU harness — no multiboot yet; -kernel will not
            // actually boot a bare ELF without a bootloader, but this shape is
            // where boot/ integration plugs in at Wave 1.
            Arch::X86_64 => vec![
                "-machine".into(), "q35".into(),
                "-cpu".into(),     "max".into(),
                "-m".into(),       "256M".into(),
                "-serial".into(),  "stdio".into(),
                "-display".into(), "none".into(),
                "-no-reboot".into(), "-no-shutdown".into(),
                "-kernel".into(),  kernel,
            ],
            // aarch64 virt machine — Limine / U-Boot / EFI handoff wires in at boot/.
            Arch::Aarch64 => vec![
                "-machine".into(),  "virt".into(),
                "-cpu".into(),      "max".into(),
                "-m".into(),        "256M".into(),
                "-serial".into(),   "stdio".into(),
                "-display".into(),  "none".into(),
                "-no-reboot".into(), "-no-shutdown".into(),
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
        .arg("-Z").arg("build-std=core,compiler_builtins")
        .arg("-Z").arg("build-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128");
    if args.release { cmd.arg("--release"); }

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

fn run_cmd(args: &BuildArgs) -> Result<()> {
    let root = workspace_root()?;
    let out_dir = cargo_build(args, &root)?;

    // Stage 1: `narf-lib` is the only crate and it's a library — nothing to
    // run yet. `frame/`'s `_start` binary lands in Wave 2; this branch is
    // the harness shape so that wiring is a one-line change then.
    let kernel = out_dir.join(format!("{}.elf", args.package));
    if !kernel.exists() {
        println!("Stage 1: no bootable kernel yet (only `narf-lib` exists).");
        println!("         `frame/` will produce `{}` at Wave 2.", kernel.display());
        return Ok(());
    }

    let qemu = args.arch.qemu_bin();
    let mut cmd = Command::new(qemu);
    cmd.args(args.arch.qemu_args(&kernel));
    let status = cmd.status()
        .with_context(|| format!("failed to invoke {qemu} — is it installed?"))?;
    if !status.success() {
        bail!("{qemu} exited with status {status}");
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build(args) => { cargo_build(&args, &workspace_root()?)?; Ok(()) }
        Cmd::Run(args)   => run_cmd(&args),
        Cmd::Test(args)  => {
            // TODO(stage-1-wave-3): integrate `verification/` kernel_test harness.
            eprintln!("xtask test: stub (arch={:?}); wires in with verification/ Wave 3.",
                args.arch.triple());
            Ok(())
        }
        Cmd::Image(args) => {
            eprintln!("xtask image: stub (arch={:?}); wires in with boot/ at Stage 1 Wave 1.",
                args.arch.triple());
            Ok(())
        }
    }
}
