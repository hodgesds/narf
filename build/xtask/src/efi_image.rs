// SPDX-License-Identifier: GPL-2.0-or-later
//! Native, self-contained EFI images. Existing Limine image commands retain
//! their established layout while this path gains hardware acceptance.

use super::*;
use narf_boot_protocol::{ElfImage, CMDLINE_CAP};

#[derive(clap::Args)]
pub struct Args {
    /// Target architecture (native single-file images currently support x86_64).
    #[arg(long, value_enum, default_value_t = Arch::X86_64)]
    arch: Arch,
    /// Retain debug assertions and symbols in the canonical kernel ELF.
    #[arg(long)]
    debug: bool,
    /// Comma-separated kernel Cargo features.
    #[arg(long, default_value = "")]
    features: String,
    /// External kernel composition manifest.
    #[arg(long, value_name = "FILE")]
    composition: Option<PathBuf>,
    /// External crate linked into the kernel; repeatable.
    #[arg(long = "builtin-crate", value_name = "MANIFEST")]
    builtin_crates: Vec<PathBuf>,
    /// External module included in the generated archive; repeatable.
    #[arg(long = "module-crate", value_name = "MANIFEST")]
    module_crates: Vec<PathBuf>,
    /// Permit unsigned modules selected by the external composition.
    #[arg(long)]
    allow_unsigned_modules: bool,
    /// QEMU display backend; serial is always available.
    #[arg(long, default_value = "none")]
    display: String,
    /// Include matching target/firmware/ blobs in the generated archive;
    /// repeatable. Unselected firmware is not installed anywhere.
    #[arg(long, value_name = "GLOB")]
    initramfs_firmware: Vec<String>,
    /// Build with the existing kernel address-sanitizer configuration.
    #[arg(long)]
    kasan: bool,
    /// Use this exact kernel ELF instead of rebuilding it.
    #[arg(long, value_name = "ELF")]
    prebuilt: Option<PathBuf>,
    /// Embed this uncompressed CPIO newc archive instead of generating one.
    #[arg(long, value_name = "CPIO")]
    initramfs: Option<PathBuf>,
    /// Embedded kernel command line. EFI load options cannot override it.
    #[arg(long, default_value = "narf.disks=boot-only")]
    cmdline: String,
    /// Destination EFI file (default: target/narf-x86_64[-smoke].efi).
    #[arg(long, value_name = "EFI")]
    output: Option<PathBuf>,
    /// Attach a regular raw root-disk image to QEMU using a disposable snapshot.
    #[arg(long, value_name = "RAW")]
    root_image: Option<PathBuf>,
    /// Boot the image interactively under OVMF after building it.
    #[arg(long, conflicts_with = "smoke")]
    run: bool,
    /// Build with boot-smoke, boot under OVMF, and require a clean shutdown.
    #[arg(long, conflicts_with = "run")]
    smoke: bool,
}

impl Args {
    fn build_args(&self) -> BuildArgs {
        BuildArgs {
            arch: self.arch,
            debug: self.debug,
            package: "narf-frame".into(),
            features: self.features.clone(),
            composition: self.composition.clone(),
            builtin_crates: self.builtin_crates.clone(),
            module_crates: self.module_crates.clone(),
            allow_unsigned_modules: self.allow_unsigned_modules,
            display: self.display.clone(),
            gpu_backend: GpuBackend::Auto,
            hw_profile: HwProfile::Minimal,
            passthrough_devices: Vec::new(),
            initramfs_firmware: self.initramfs_firmware.clone(),
            kasan: self.kasan,
        }
    }
}

pub fn run(args: &Args) -> Result<()> {
    if let Some(path) = &args.root_image {
        if (!args.run && !args.smoke) || !path.is_file() || path.to_string_lossy().contains(',') {
            bail!("--root-image requires --run/--smoke and a regular raw file whose path contains no comma");
        }
    }
    if args.arch != Arch::X86_64 {
        bail!("efi-image currently supports x86_64; aarch64 uses cargo xtask image --arch=aarch64");
    }
    let root = workspace_root()?;
    let mut build = args.build_args();
    if args.smoke {
        build.features = without_kernel_test_features(&build.features);
    }
    ensure_feature(&mut build.features, "boot-init");
    if args.smoke {
        ensure_feature(&mut build.features, "boot-smoke");
    }
    let plan = composition_plan(&build, &root)?;
    let extra = composition::boot_arguments(&plan).join(" ");
    let cmdline = if extra.is_empty() {
        args.cmdline.clone()
    } else {
        format!("{} {extra}", args.cmdline)
    };
    if cmdline.len() >= CMDLINE_CAP || cmdline.as_bytes().contains(&0) {
        bail!(
            "embedded command line must fit {} bytes including its terminating NUL",
            CMDLINE_CAP
        );
    }
    if args.prebuilt.is_some() && plan.modules().next().is_some() {
        bail!("--prebuilt cannot build composed modules; build the composition without --prebuilt");
    }
    let kernel = if let Some(path) = &args.prebuilt {
        path.canonicalize()
            .with_context(|| format!("locating selected kernel {}", path.display()))?
    } else {
        cargo_build(&build, &root)?.join(&build.package)
    };
    let stage = root.join(if args.smoke {
        "target/native-uefi-x86_64-smoke"
    } else {
        "target/native-uefi-x86_64"
    });
    std::fs::create_dir_all(&stage)?;
    // Remove all non-loadable ELF sections, keeping the canonical ELF intact
    // for GDB. This greatly reduces EFI's own resident image allocation.
    let staged_kernel = stage.join("kernel.elf");
    run_checked(
        Command::new(llvm_objcopy()?)
            .arg("--strip-all")
            .arg(&kernel)
            .arg(&staged_kernel),
        "stripping EFI kernel payload",
    )?;
    let bytes = std::fs::read(&staged_kernel)?;
    let elf = ElfImage::parse(&bytes).map_err(|error| anyhow!("EFI kernel rejected: {error:?}"))?;
    println!(
        "xtask efi-image: kernel {} (SHA256 {})",
        kernel.display(),
        sha256_file(&kernel)?
    );
    println!(
        "xtask efi-image: physical load {:#x}..{:#x}",
        elf.load_start, elf.load_end
    );

    let cpio = if let Some(path) = &args.initramfs {
        if !build.initramfs_firmware.is_empty() || plan.modules().next().is_some() {
            bail!("--initramfs supplies the complete archive; firmware globs and composed modules cannot be added to it");
        }
        std::fs::read(path).with_context(|| format!("reading initramfs {}", path.display()))?
    } else {
        default_initramfs(&build, &root, &plan)?
    };
    if cpio.len() < 110 || !cpio.starts_with(b"070701") {
        bail!("initramfs must be an uncompressed CPIO newc archive (070701)");
    }
    let initramfs = stage.join("initramfs.cpio");
    std::fs::write(&initramfs, &cpio)?;
    let target = root.join("target/uefi-loader");
    run_checked(
        Command::new("cargo")
            .args([
                "build",
                "--release",
                "--target",
                "x86_64-unknown-uefi",
                "-Zbuild-std=core,compiler_builtins,alloc",
                "-Zbuild-std-features=compiler-builtins-mem",
            ])
            .arg("--manifest-path")
            .arg(root.join("build/uefi-loader/Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env("NARF_EFI_KERNEL", &staged_kernel)
            .env("NARF_EFI_INITRAMFS", &initramfs)
            .env("NARF_EFI_CMDLINE", &cmdline)
            .current_dir(&root),
        "building native EFI application",
    )?;
    let output = args.output.clone().unwrap_or_else(|| {
        root.join(if args.smoke {
            "target/narf-x86_64-smoke.efi"
        } else {
            "target/narf-x86_64.efi"
        })
    });
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(
        target.join("x86_64-unknown-uefi/release/narf-uefi-loader.efi"),
        &output,
    )?;
    let esp = stage.join("esp");
    let efi_directory = esp.join("EFI/BOOT");
    std::fs::create_dir_all(&efi_directory)?;
    std::fs::copy(&output, efi_directory.join("BOOTX64.EFI"))?;
    println!(
        "xtask efi-image: wrote {} ({} bytes; initramfs {} bytes)",
        output.display(),
        std::fs::metadata(&output)?.len(),
        cpio.len()
    );
    println!("xtask efi-image: embedded cmdline: {cmdline}");
    if args.run || args.smoke {
        boot(args, &esp)?;
    }
    Ok(())
}

fn llvm_objcopy() -> Result<PathBuf> {
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .context("locating Rust sysroot")?;
    if !sysroot.status.success() {
        bail!("rustc --print sysroot failed");
    }
    let rustlib = PathBuf::from(String::from_utf8(sysroot.stdout)?.trim()).join("lib/rustlib");
    std::fs::read_dir(&rustlib)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("bin/llvm-objcopy"))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            anyhow!("llvm-objcopy missing; install the pinned toolchain's llvm-tools component")
        })
}

fn default_initramfs(build: &BuildArgs, root: &Path, plan: &composition::Plan) -> Result<Vec<u8>> {
    let mut files = Vec::new();
    for (directory, binary, linker, guest) in [
        ("userspace/init", "init", "init.ld", "init"),
        ("userspace/shell", "shell", "shell.ld", "shell"),
        ("userspace/coreutils/echo", "echo", "echo.ld", "bin/echo"),
        ("userspace/coreutils/pwd", "pwd", "pwd.ld", "bin/pwd"),
        ("userspace/coreutils/cat", "cat", "cat.ld", "bin/cat"),
        ("userspace/coreutils/ls", "ls", "ls.ld", "bin/ls"),
        ("userspace/coreutils/ps", "ps", "ps.ld", "bin/ps"),
    ] {
        let elf = build_user_binary(root, directory, binary, linker)?;
        files.push((guest.to_string(), std::fs::read(elf)?));
    }
    files.extend(initramfs_firmware_entries(build, root)?);
    for component in plan.modules() {
        let path = composition::module_output_path(root, plan, build.arch.triple(), component);
        files.push((
            composition::module_guest_path(component),
            std::fs::read(path)?,
        ));
    }
    let entries: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    Ok(encode_cpio_newc(&entries))
}

fn boot(args: &Args, esp: &Path) -> Result<()> {
    let firmware = ovmf_code_path();
    if !firmware.is_file() {
        bail!(
            "OVMF firmware not found at {}; install OVMF or set OVMF_CODE",
            firmware.display()
        );
    }
    let mut command = Command::new("qemu-system-x86_64");
    command
        .args(["-machine", "q35", "-cpu"])
        .arg(std::env::var("XTASK_CPU").unwrap_or_else(|_| "max".into()))
        .arg("-m")
        .arg(std::env::var("XTASK_MEM").unwrap_or_else(|_| "4096M".into()))
        .arg("-smp")
        .arg(std::env::var("XTASK_SMP").unwrap_or_else(|_| "2".into()))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            firmware.display()
        ))
        // The isolated ESP contains only BOOTX64.EFI. QEMU's read-only FAT
        // backend avoids image tools and proves no sidecar is needed to boot.
        .arg("-drive")
        .arg(format!(
            "if=virtio,format=raw,readonly=on,file=fat:{}",
            esp.display()
        ))
        .args(["-serial", "stdio", "-display"])
        .arg(&args.display)
        .args([
            "-monitor",
            "none",
            "-no-reboot",
            "-nic",
            "none",
            "-device",
            "qemu-xhci,id=xhci0",
            "-device",
            "usb-kbd,bus=xhci0.0",
            "-device",
            "usb-tablet,bus=xhci0.0",
        ]);
    if let Ok(accel) = std::env::var("XTASK_QEMU_ACCEL") {
        command.args(["-accel", &accel]);
    }
    if let Some(path) = &args.root_image {
        let temporary = esp.parent().unwrap_or(esp).join("qemu-tmp");
        std::fs::create_dir_all(&temporary)?;
        command.env("TMPDIR", &temporary);
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=narf-root,format=raw,snapshot=on,file={}",
                path.display()
            ))
            .args([
                "-device",
                "virtio-blk-pci,drive=narf-root,disable-legacy=on,disable-modern=off",
            ]);
    }
    println!("xtask efi-image: booting {} through OVMF", esp.display());
    if args.smoke {
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let secs = std::env::var("XTASK_BOOT_SMOKE_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(180);
        wait_for_boot_smoke(child, "native-efi", secs, Arch::X86_64)
    } else {
        run_checked(&mut command, "running native EFI image")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn efi_cli_is_opt_in_and_has_distinct_run_and_smoke_modes() {
        let cli = Cli::try_parse_from([
            "xtask",
            "efi-image",
            "--cmdline",
            "root=UUID=123 narf.disks=root-ro",
            "--smoke",
        ])
        .unwrap();
        let Cmd::EfiImage(args) = cli.cmd else {
            panic!("wrong command")
        };
        assert!(args.smoke);
        assert!(!args.run);
        assert_eq!(args.cmdline, "root=UUID=123 narf.disks=root-ro");
        assert!(Cli::try_parse_from(["xtask", "efi-image", "--run", "--smoke"]).is_err());
    }
}
