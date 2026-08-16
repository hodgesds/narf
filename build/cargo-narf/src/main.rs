// SPDX-License-Identifier: GPL-2.0-or-later

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "cargo narf",
    bin_name = "cargo narf",
    about = "Build and install NARF through native distribution packages"
)]
struct Cli {
    /// NARF source checkout. Defaults to the current directory or an ancestor.
    #[arg(long, global = true)]
    repo: Option<PathBuf>,

    #[command(subcommand)]
    command: NarfCommand,
}

#[derive(Debug, Subcommand)]
enum NarfCommand {
    /// Build one or more native distribution packages.
    Package(PackageArgs),
    /// Build a native package and install it through the host package manager.
    Install(InstallArgs),
    /// Print the native package format detected from os-release.
    Detect(DetectArgs),
}

#[derive(Debug, Args)]
struct PackageArgs {
    /// Semantic NARF release version, without a leading `v`.
    #[arg(long)]
    version: String,

    /// Comma-separated formats: auto, all, deb, rpm, arch, gentoo, or tar.
    #[arg(long, default_value = "auto")]
    formats: String,

    /// Release artifact directory.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Package an already-built canonical kernel artifact.
    #[arg(long)]
    skip_build: bool,

    /// Reproducible build timestamp.
    #[arg(long)]
    source_date_epoch: Option<u64>,
}

#[derive(Debug, Args)]
struct InstallArgs {
    /// Semantic NARF release version, without a leading `v`.
    #[arg(long)]
    version: String,

    /// Native package format. `auto` reads os-release.
    #[arg(long, value_enum, default_value_t = PackageFormat::Auto)]
    format: PackageFormat,

    /// Release artifact directory.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Package an already-built canonical kernel artifact.
    #[arg(long)]
    skip_build: bool,

    /// Reproducible build timestamp.
    #[arg(long)]
    source_date_epoch: Option<u64>,

    /// Pass the native package manager's non-interactive confirmation flag.
    #[arg(long)]
    yes: bool,

    /// Build the package and print, but do not execute, the install command.
    #[arg(long)]
    dry_run: bool,

    /// os-release file used for automatic format detection.
    #[arg(long, default_value = "/etc/os-release")]
    os_release: PathBuf,
}

#[derive(Debug, Args)]
struct DetectArgs {
    /// os-release file to inspect.
    #[arg(long, default_value = "/etc/os-release")]
    os_release: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PackageFormat {
    Auto,
    Deb,
    Rpm,
    Arch,
    Gentoo,
    Tar,
}

impl PackageFormat {
    const fn as_script_name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Arch => "arch",
            Self::Gentoo => "gentoo",
            Self::Tar => "tar",
        }
    }

    const fn installable(self) -> bool {
        matches!(self, Self::Deb | Self::Rpm | Self::Arch)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct InstallCommand {
    program: OsString,
    args: Vec<OsString>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cargo narf: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse_from(normalized_args());
    match cli.command {
        NarfCommand::Package(args) => {
            let root = find_repo(cli.repo.as_deref())?;
            let formats = resolve_formats(&args.formats, Path::new("/etc/os-release"))?;
            run_packager(
                &root,
                &args.version,
                &formats,
                args.output.as_deref(),
                args.skip_build,
                args.source_date_epoch,
            )
        }
        NarfCommand::Install(args) => {
            let root = find_repo(cli.repo.as_deref())?;
            let format = resolve_format(args.format, &args.os_release)?;
            if !format.installable() {
                bail!(
                    "{} packages are generation-only; install supports deb, rpm, and arch",
                    format.as_script_name()
                );
            }
            let output = absolute_output(&root, args.output.as_deref(), &args.version);
            run_packager(
                &root,
                &args.version,
                format.as_script_name(),
                Some(&output),
                args.skip_build,
                args.source_date_epoch,
            )?;
            let artifact = find_artifact(&output, format, &args.version)?;
            let command = native_install_command(format, &artifact, args.yes)?;
            let command = elevate_if_needed(command)?;
            if args.dry_run {
                println!("{}", display_command(&command));
                return Ok(());
            }
            let status = Command::new(&command.program)
                .args(&command.args)
                .status()
                .with_context(|| format!("launching {}", command.program.to_string_lossy()))?;
            if !status.success() {
                bail!("native package installation failed with {status}");
            }
            Ok(())
        }
        NarfCommand::Detect(args) => {
            let format = detect_format(&args.os_release)?;
            println!("{}", format.as_script_name());
            Ok(())
        }
    }
}

/// Cargo may pass the external subcommand name as argv[1]. Accept both
/// `cargo narf package` and direct `cargo-narf package` invocation shapes.
fn normalized_args() -> Vec<OsString> {
    let mut args: Vec<OsString> = env::args_os().collect();
    if args.get(1).is_some_and(|arg| arg == "narf") {
        args.remove(1);
    }
    args
}

fn find_repo(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return validate_repo(path);
    }
    let current = env::current_dir().context("reading current directory")?;
    for candidate in current.ancestors() {
        if is_repo(candidate) {
            return Ok(candidate.to_path_buf());
        }
    }
    bail!("not inside a NARF checkout; pass --repo PATH")
}

fn validate_repo(path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("resolving repository path {}", path.display()))?;
    if !is_repo(&path) {
        bail!(
            "{} is not a NARF checkout (missing packaging/build-release.sh)",
            path.display()
        );
    }
    Ok(path)
}

fn is_repo(path: &Path) -> bool {
    path.join("Cargo.toml").is_file() && path.join("packaging/build-release.sh").is_file()
}

fn resolve_formats(value: &str, os_release: &Path) -> Result<String> {
    if value == "auto" {
        return Ok(detect_format(os_release)?.as_script_name().to_string());
    }
    Ok(value.to_string())
}

fn resolve_format(value: PackageFormat, os_release: &Path) -> Result<PackageFormat> {
    if value == PackageFormat::Auto {
        detect_format(os_release)
    } else {
        Ok(value)
    }
}

fn detect_format(path: &Path) -> Result<PackageFormat> {
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    classify_os_release(&contents).ok_or_else(|| {
        anyhow!(
            "unsupported distribution in {}; pass --format explicitly",
            path.display()
        )
    })
}

fn classify_os_release(contents: &str) -> Option<PackageFormat> {
    let mut identities = Vec::new();
    for line in contents.lines() {
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        if key != "ID" && key != "ID_LIKE" {
            continue;
        }
        let value = raw_value.trim().trim_matches(['\'', '"']);
        identities.extend(value.split_ascii_whitespace().map(str::to_ascii_lowercase));
    }
    if identities
        .iter()
        .any(|id| matches!(id.as_str(), "debian" | "ubuntu" | "linuxmint" | "pop"))
    {
        Some(PackageFormat::Deb)
    } else if identities.iter().any(|id| {
        matches!(
            id.as_str(),
            "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "suse" | "opensuse"
        )
    }) {
        Some(PackageFormat::Rpm)
    } else if identities
        .iter()
        .any(|id| matches!(id.as_str(), "arch" | "manjaro" | "endeavouros"))
    {
        Some(PackageFormat::Arch)
    } else if identities.iter().any(|id| id == "gentoo") {
        Some(PackageFormat::Gentoo)
    } else {
        None
    }
}

fn run_packager(
    root: &Path,
    version: &str,
    formats: &str,
    output: Option<&Path>,
    skip_build: bool,
    source_date_epoch: Option<u64>,
) -> Result<()> {
    let mut command = Command::new(root.join("packaging/build-release.sh"));
    command
        .current_dir(root)
        .args(["--version", version, "--formats", formats]);
    if let Some(output) = output {
        command.arg("--output").arg(output);
    }
    if skip_build {
        command.arg("--skip-build");
    }
    if let Some(epoch) = source_date_epoch {
        command.arg("--source-date-epoch").arg(epoch.to_string());
    }
    let status = command.status().context("launching native package build")?;
    if !status.success() {
        bail!("native package build failed with {status}");
    }
    Ok(())
}

fn absolute_output(root: &Path, output: Option<&Path>, version: &str) -> PathBuf {
    match output {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => root.join(path),
        None => root.join("target/release-assets").join(version),
    }
}

fn find_artifact(output: &Path, format: PackageFormat, version: &str) -> Result<PathBuf> {
    let exact = match format {
        PackageFormat::Deb => Some(output.join(format!("narf-kernel_{version}_amd64.deb"))),
        _ => None,
    };
    if let Some(path) = exact.filter(|path| path.is_file()) {
        return Ok(path);
    }

    let mut matches = Vec::new();
    for entry in std::fs::read_dir(output)
        .with_context(|| format!("reading package output {}", output.display()))?
    {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        let is_match = match format {
            PackageFormat::Rpm => name.ends_with(".rpm") && !name.ends_with(".src.rpm"),
            PackageFormat::Arch => name.contains(".pkg.tar."),
            _ => false,
        };
        if is_match {
            matches.push(path);
        }
    }
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => bail!(
            "no {} package found in {}",
            format.as_script_name(),
            output.display()
        ),
        _ => bail!(
            "multiple {} packages found in {}; select a clean output directory",
            format.as_script_name(),
            output.display()
        ),
    }
}

fn native_install_command(
    format: PackageFormat,
    artifact: &Path,
    yes: bool,
) -> Result<InstallCommand> {
    native_install_command_with(format, artifact, yes, command_exists)
}

fn native_install_command_with(
    format: PackageFormat,
    artifact: &Path,
    yes: bool,
    mut exists: impl FnMut(&str) -> bool,
) -> Result<InstallCommand> {
    let artifact = artifact.as_os_str().to_owned();
    let (program, mut args): (&str, Vec<OsString>) = match format {
        PackageFormat::Deb if exists("apt-get") => ("apt-get", vec!["install".into()]),
        PackageFormat::Deb if exists("dpkg") => ("dpkg", vec!["-i".into()]),
        PackageFormat::Rpm if exists("dnf") => ("dnf", vec!["install".into()]),
        PackageFormat::Rpm if exists("rpm") => ("rpm", vec!["-Uvh".into()]),
        PackageFormat::Arch if exists("pacman") => ("pacman", vec!["-U".into()]),
        _ => bail!(
            "no supported native package manager found for {}",
            format.as_script_name()
        ),
    };
    if yes {
        match program {
            "apt-get" | "dnf" => args.push("-y".into()),
            "pacman" => args.push("--noconfirm".into()),
            _ => {}
        }
    }
    args.push(artifact);
    Ok(InstallCommand {
        program: program.into(),
        args,
    })
}

fn elevate_if_needed(command: InstallCommand) -> Result<InstallCommand> {
    if effective_uid_is_root()? {
        return Ok(command);
    }
    if !command_exists("sudo") {
        bail!("installation requires root; install sudo or run cargo narf as root");
    }
    let mut args = Vec::with_capacity(command.args.len() + 1);
    args.push(command.program);
    args.extend(command.args);
    Ok(InstallCommand {
        program: "sudo".into(),
        args,
    })
}

fn effective_uid_is_root() -> Result<bool> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("running id -u")?;
    if !output.status.success() {
        bail!("id -u failed with {}", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "0")
}

fn command_exists(program: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|directory| directory.join(program).is_file())
}

fn display_command(command: &InstallCommand) -> String {
    std::iter::once(&command.program)
        .chain(&command.args)
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_.,:=+@%-".contains(&byte))
    {
        value.into_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_debian_family() {
        assert_eq!(
            classify_os_release("ID=ubuntu\nID_LIKE=debian\n"),
            Some(PackageFormat::Deb)
        );
    }

    #[test]
    fn classifies_rpm_family_with_quoted_id_like() {
        assert_eq!(
            classify_os_release("ID=ultramarine\nID_LIKE=\"fedora rhel\"\n"),
            Some(PackageFormat::Rpm)
        );
    }

    #[test]
    fn classifies_arch_and_gentoo() {
        assert_eq!(
            classify_os_release("ID=endeavouros\nID_LIKE=arch\n"),
            Some(PackageFormat::Arch)
        );
        assert_eq!(
            classify_os_release("ID=gentoo\n"),
            Some(PackageFormat::Gentoo)
        );
    }

    #[test]
    fn rejects_unknown_distribution() {
        assert_eq!(classify_os_release("ID=unknown\n"), None);
    }

    #[test]
    fn quotes_display_only_when_needed() {
        assert_eq!(shell_quote(OsStr::new("/tmp/narf.deb")), "/tmp/narf.deb");
        assert_eq!(
            shell_quote(OsStr::new("/tmp/narf package.deb")),
            "'/tmp/narf package.deb'"
        );
        assert_eq!(shell_quote(OsStr::new("it's")), "'it'\\''s'");
    }

    #[test]
    fn resolves_relative_output_under_checkout() {
        assert_eq!(
            absolute_output(Path::new("/src/narf"), Some(Path::new("out")), "1.2.3"),
            Path::new("/src/narf/out")
        );
        assert_eq!(
            absolute_output(Path::new("/src/narf"), None, "1.2.3"),
            Path::new("/src/narf/target/release-assets/1.2.3")
        );
    }

    #[test]
    fn native_install_commands_preserve_package_ownership() {
        let artifact = Path::new("/tmp/narf.deb");
        let apt = native_install_command_with(PackageFormat::Deb, artifact, true, |program| {
            program == "apt-get"
        })
        .unwrap();
        assert_eq!(apt.program, "apt-get");
        assert_eq!(
            apt.args,
            ["install", "-y", "/tmp/narf.deb"].map(OsString::from)
        );

        let rpm = native_install_command_with(PackageFormat::Rpm, artifact, false, |program| {
            program == "rpm"
        })
        .unwrap();
        assert_eq!(rpm.program, "rpm");
        assert_eq!(rpm.args, ["-Uvh", "/tmp/narf.deb"].map(OsString::from));

        let pacman = native_install_command_with(PackageFormat::Arch, artifact, true, |program| {
            program == "pacman"
        })
        .unwrap();
        assert_eq!(pacman.program, "pacman");
        assert_eq!(
            pacman.args,
            ["-U", "--noconfirm", "/tmp/narf.deb"].map(OsString::from)
        );
    }
}
