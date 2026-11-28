//! Independent crates.io version preparation.
//!
//! A package opts into release management by declaring an explicit
//! `[package].version`; packages inheriting `workspace.package.version` stay
//! out of automation. This keeps a point release local to one crate while the
//! rest of the kernel workspace continues to use its development version.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use semver::{Version, VersionReq};
use serde::Deserialize;
use toml_edit::{value, DocumentMut, Item, Table, Value};

#[derive(ClapArgs, Debug)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List crates that have opted into independent release management.
    List,
    /// Prepare independent version changes without committing or publishing.
    Bump(BumpArgs),
    /// Validate and package selected release-managed crates without uploading.
    Check(CheckArgs),
}

#[derive(ClapArgs, Debug)]
struct BumpArgs {
    /// Increment this crate's patch component. Repeat for multiple crates.
    #[arg(long = "package")]
    packages: Vec<String>,

    /// Set an exact version as NAME=VERSION. Repeat for multiple crates.
    #[arg(long = "set", value_parser = parse_assignment)]
    exact: Vec<VersionAssignment>,

    /// Patch-bump every independently versioned, publishable crate.
    #[arg(long, conflicts_with = "changed_since_tags")]
    all: bool,

    /// Patch-bump crates changed since `crate/NAME/vCURRENT`.
    /// Crates without a matching publication tag are reported and skipped.
    #[arg(long, conflicts_with = "all")]
    changed_since_tags: bool,

    /// Write the selected package names, one per line, for CI consumers.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(ClapArgs, Debug)]
struct CheckArgs {
    /// Validate only this crate. Repeat for multiple crates.
    #[arg(long = "package")]
    packages: Vec<String>,

    /// Validate every independently versioned, publishable crate.
    #[arg(long)]
    all: bool,
}

#[derive(Clone, Debug)]
struct VersionAssignment {
    name: String,
    version: Version,
}

fn parse_assignment(raw: &str) -> std::result::Result<VersionAssignment, String> {
    let (name, version) = raw
        .split_once('=')
        .ok_or_else(|| "expected NAME=VERSION".to_string())?;
    if name.is_empty() {
        return Err("crate name must not be empty".into());
    }
    let version = Version::parse(version).map_err(|error| error.to_string())?;
    Ok(VersionAssignment {
        name: name.into(),
        version,
    })
}

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
    target_directory: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
struct Package {
    id: String,
    name: String,
    version: Version,
    manifest_path: PathBuf,
    publish: Option<Vec<String>>,
    dependencies: Vec<Dependency>,
}

#[derive(Clone, Debug, Deserialize)]
struct Dependency {
    name: String,
    req: VersionReq,
    path: Option<PathBuf>,
}

impl Package {
    fn publishable(&self) -> bool {
        self.publish
            .as_ref()
            .is_none_or(|registries| !registries.is_empty())
    }

    fn directory(&self) -> Result<&Path> {
        self.manifest_path
            .parent()
            .ok_or_else(|| anyhow!("{} has no manifest parent", self.name))
    }
}

pub fn run(args: &Args, root: &Path) -> Result<()> {
    match &args.command {
        Command::List => list(root),
        Command::Bump(args) => bump(root, args),
        Command::Check(args) => check(root, args),
    }
}

fn cargo_metadata(root: &Path) -> Result<Metadata> {
    let output = ProcessCommand::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .context("running cargo metadata for crate releases")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing cargo metadata for crate releases")
}

fn workspace_packages(metadata: &Metadata) -> Vec<&Package> {
    let members: HashSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    metadata
        .packages
        .iter()
        .filter(|package| members.contains(package.id.as_str()))
        .collect()
}

fn manifest_document(path: &Path) -> Result<DocumentMut> {
    fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?
        .parse::<DocumentMut>()
        .with_context(|| format!("parsing {}", path.display()))
}

fn release_managed(path: &Path) -> Result<bool> {
    let document = manifest_document(path)?;
    Ok(document["package"]["version"].as_str().is_some()
        && document["package"]["metadata"]["narf"]["release-managed"].as_bool() == Some(true))
}

fn managed_packages(metadata: &Metadata) -> Result<BTreeMap<String, &Package>> {
    let mut managed = BTreeMap::new();
    for package in workspace_packages(metadata) {
        if package.publishable() && release_managed(&package.manifest_path)? {
            managed.insert(package.name.clone(), package);
        }
    }
    Ok(managed)
}

fn list(root: &Path) -> Result<()> {
    let metadata = cargo_metadata(root)?;
    for (name, package) in managed_packages(&metadata)? {
        println!(
            "{name}\t{}\tcrate/{name}/v{}",
            package.version, package.version
        );
    }
    Ok(())
}

fn patch_version(current: &Version) -> Version {
    Version::new(current.major, current.minor, current.patch + 1)
}

fn select_changed_since_tags(
    root: &Path,
    managed: &BTreeMap<String, &Package>,
    all_packages: &[&Package],
) -> Result<BTreeSet<String>> {
    let package_roots: Vec<PathBuf> = all_packages
        .iter()
        .filter_map(|package| package.directory().ok())
        .filter_map(|path| path.strip_prefix(root).ok())
        .map(Path::to_path_buf)
        .collect();
    let mut selected = BTreeSet::new();

    for (name, package) in managed {
        let tag = format!("crate/{name}/v{}", package.version);
        let exists = ProcessCommand::new("git")
            .args([
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("refs/tags/{tag}"),
            ])
            .current_dir(root)
            .status()
            .with_context(|| format!("checking publication tag {tag}"))?
            .success();
        if !exists {
            eprintln!("crate-release: skip {name}: publication tag {tag} is absent");
            continue;
        }

        let output = ProcessCommand::new("git")
            .args(["diff", "--name-only", &format!("{tag}..HEAD"), "--"])
            .current_dir(root)
            .output()
            .with_context(|| format!("finding changes since {tag}"))?;
        if !output.status.success() {
            bail!(
                "git diff from {tag} failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let package_root = package.directory()?.strip_prefix(root).with_context(|| {
            format!(
                "{} is outside {}",
                package.manifest_path.display(),
                root.display()
            )
        })?;
        let changed = String::from_utf8(output.stdout)
            .context("git emitted a non-UTF-8 path while selecting crate releases")?
            .lines()
            .map(Path::new)
            .any(|path| path_owned_by(path, package_root, &package_roots));
        if changed {
            selected.insert(name.clone());
        }
    }
    Ok(selected)
}

fn path_owned_by(path: &Path, owner: &Path, package_roots: &[PathBuf]) -> bool {
    if !path.starts_with(owner) {
        return false;
    }
    !package_roots
        .iter()
        .any(|other| other != owner && other.starts_with(owner) && path.starts_with(other))
}

fn bump(root: &Path, args: &BumpArgs) -> Result<()> {
    let metadata = cargo_metadata(root)?;
    let all_packages = workspace_packages(&metadata);
    let managed = managed_packages(&metadata)?;
    let mut desired = BTreeMap::<String, Version>::new();

    if args.all {
        for (name, package) in &managed {
            desired.insert(name.clone(), patch_version(&package.version));
        }
    }
    if args.changed_since_tags {
        for name in select_changed_since_tags(root, &managed, &all_packages)? {
            let package = managed[&name];
            desired.insert(name, patch_version(&package.version));
        }
    }
    for name in &args.packages {
        let package = managed.get(name).ok_or_else(|| unmanaged_error(name))?;
        if desired
            .insert(name.clone(), patch_version(&package.version))
            .is_some()
        {
            bail!("crate {name} was selected more than once");
        }
    }
    for assignment in &args.exact {
        let package = managed
            .get(&assignment.name)
            .ok_or_else(|| unmanaged_error(&assignment.name))?;
        if assignment.version <= package.version {
            bail!(
                "{} must advance from {} (requested {})",
                assignment.name,
                package.version,
                assignment.version
            );
        }
        if desired
            .insert(assignment.name.clone(), assignment.version.clone())
            .is_some()
        {
            bail!("crate {} was selected more than once", assignment.name);
        }
    }

    if !args.all && !args.changed_since_tags && args.packages.is_empty() && args.exact.is_empty() {
        bail!("select at least one --package/--set, --all, or --changed-since-tags");
    }

    if desired.is_empty() {
        eprintln!("crate-release: no independently versioned crates need a bump");
        write_selection(args.output.as_deref(), desired.keys())?;
        return Ok(());
    }

    expand_incompatible_dependents(&all_packages, &managed, &mut desired)?;
    let packages_by_manifest = packages_by_manifest(&all_packages)?;
    let versions: HashMap<PathBuf, Version> = all_packages
        .iter()
        .map(|package| {
            let path = canonical_manifest(&package.manifest_path)?;
            let version = desired
                .get(&package.name)
                .cloned()
                .unwrap_or_else(|| package.version.clone());
            Ok((path, version))
        })
        .collect::<Result<_>>()?;

    let mut updates = Vec::new();
    for (name, new_version) in &desired {
        let package = managed
            .get(name)
            .ok_or_else(|| anyhow!("dependent {name} is not release-managed"))?;
        let mut document = manifest_document(&package.manifest_path)?;
        document["package"]["version"] = value(new_version.to_string());
        add_internal_dependency_versions(
            &mut document,
            &package.manifest_path,
            &packages_by_manifest,
            &versions,
        )?;
        updates.push((package.manifest_path.clone(), document.to_string()));
    }

    for (path, contents) in updates {
        fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
    }
    write_selection(args.output.as_deref(), desired.keys())?;

    for (name, new_version) in &desired {
        println!(
            "crate-release: {name} {} -> {new_version}",
            managed[name].version
        );
    }
    println!(
        "crate-release: prepared {} crate(s); no commit or publication was performed",
        desired.len()
    );
    Ok(())
}

fn unmanaged_error(name: &str) -> anyhow::Error {
    anyhow!(
        "{name} is not release-managed; give it an explicit [package].version, set package.metadata.narf.release-managed=true, and ensure publish is not false"
    )
}

fn expand_incompatible_dependents(
    packages: &[&Package],
    managed: &BTreeMap<String, &Package>,
    desired: &mut BTreeMap<String, Version>,
) -> Result<()> {
    loop {
        let mut additions = Vec::new();
        for package in packages {
            if desired.contains_key(&package.name) {
                continue;
            }
            for dependency in package.dependencies.iter().filter(|dep| dep.path.is_some()) {
                let Some(new_version) = desired.get(&dependency.name) else {
                    continue;
                };
                // A missing registry requirement is represented by `*` and
                // does not constrain local Cargo builds. It is repaired when
                // this package itself is selected for publication.
                if dependency.req == VersionReq::STAR || dependency.req.matches(new_version) {
                    continue;
                }
                let Some(managed_package) = managed.get(&package.name) else {
                    bail!(
                        "{} requires {} {}, which excludes {}; make the dependent release-managed and select it too",
                        package.name,
                        dependency.name,
                        dependency.req,
                        new_version
                    );
                };
                additions.push((
                    package.name.clone(),
                    patch_version(&managed_package.version),
                ));
            }
        }
        if additions.is_empty() {
            return Ok(());
        }
        for (name, version) in additions {
            desired.entry(name).or_insert(version);
        }
    }
}

fn canonical_manifest(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("canonicalizing {}", path.display()))
}

fn packages_by_manifest(packages: &[&Package]) -> Result<HashMap<PathBuf, Package>> {
    packages
        .iter()
        .map(|package| {
            Ok((
                canonical_manifest(&package.manifest_path)?,
                (*package).clone(),
            ))
        })
        .collect()
}

fn add_internal_dependency_versions(
    document: &mut DocumentMut,
    manifest_path: &Path,
    packages: &HashMap<PathBuf, Package>,
    versions: &HashMap<PathBuf, Version>,
) -> Result<()> {
    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", manifest_path.display()))?;
    visit_dependency_tables(document, |alias, item| {
        let Some(path) = dependency_path(item) else {
            return Ok(());
        };
        let dependency_manifest = canonical_manifest(&manifest_dir.join(path).join("Cargo.toml"))?;
        let dependency = packages.get(&dependency_manifest).ok_or_else(|| {
            anyhow!(
                "{alias} in {} points outside the release workspace ({})",
                manifest_path.display(),
                dependency_manifest.display()
            )
        })?;
        if !dependency.publishable() {
            bail!(
                "{} cannot be packaged because path dependency {} is private",
                manifest_path.display(),
                dependency.name
            );
        }
        let version = versions
            .get(&dependency_manifest)
            .ok_or_else(|| anyhow!("no release version for {}", dependency.name))?;
        set_dependency_requirement(item, version)?;
        Ok(())
    })
}

fn visit_dependency_tables(
    document: &mut DocumentMut,
    mut visitor: impl FnMut(&str, &mut Item) -> Result<()>,
) -> Result<()> {
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    for kind in KINDS {
        if let Some(table) = document.get_mut(kind).and_then(Item::as_table_mut) {
            visit_dependency_table(table, &mut visitor)?;
        }
    }
    if let Some(targets) = document.get_mut("target").and_then(Item::as_table_mut) {
        for (_, target) in targets.iter_mut() {
            let Some(target) = target.as_table_mut() else {
                continue;
            };
            for kind in KINDS {
                if let Some(table) = target.get_mut(kind).and_then(Item::as_table_mut) {
                    visit_dependency_table(table, &mut visitor)?;
                }
            }
        }
    }
    Ok(())
}

fn visit_dependency_table(
    table: &mut Table,
    visitor: &mut impl FnMut(&str, &mut Item) -> Result<()>,
) -> Result<()> {
    for (name, item) in table.iter_mut() {
        visitor(name.get(), item)?;
    }
    Ok(())
}

fn dependency_path(item: &Item) -> Option<&str> {
    if let Some(inline) = item.as_value().and_then(Value::as_inline_table) {
        return inline.get("path").and_then(Value::as_str);
    }
    item.as_table()?.get("path")?.as_value()?.as_str()
}

fn set_dependency_requirement(item: &mut Item, version: &Version) -> Result<()> {
    if dependency_requirement(item)
        .and_then(|requirement| VersionReq::parse(requirement).ok())
        .is_some_and(|requirement| requirement.matches(version))
    {
        return Ok(());
    }
    let requirement = format!("^{version}");
    if let Some(inline) = item.as_value_mut().and_then(Value::as_inline_table_mut) {
        inline.insert("version", Value::from(requirement));
        inline.fmt();
        return Ok(());
    }
    if let Some(table) = item.as_table_mut() {
        table["version"] = value(requirement);
        return Ok(());
    }
    bail!("path dependency is neither an inline table nor a table")
}

fn dependency_requirement(item: &Item) -> Option<&str> {
    if let Some(inline) = item.as_value().and_then(Value::as_inline_table) {
        return inline.get("version").and_then(Value::as_str);
    }
    item.as_table()?.get("version")?.as_value()?.as_str()
}

fn write_selection<'a>(path: Option<&Path>, names: impl Iterator<Item = &'a String>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating selection directory {}", parent.display()))?;
    }
    let mut output = names.cloned().collect::<Vec<_>>().join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    fs::write(path, output).with_context(|| format!("writing {}", path.display()))
}

fn check(root: &Path, args: &CheckArgs) -> Result<()> {
    let metadata = cargo_metadata(root)?;
    let all_packages = workspace_packages(&metadata);
    let managed = managed_packages(&metadata)?;
    let selected: BTreeSet<String> = if args.all || args.packages.is_empty() {
        managed.keys().cloned().collect()
    } else {
        args.packages.iter().cloned().collect()
    };
    if selected.is_empty() {
        bail!("no independently versioned crates are available to check");
    }
    let by_directory: HashMap<PathBuf, &Package> = all_packages
        .iter()
        .map(|package| Ok((fs::canonicalize(package.directory()?)?, *package)))
        .collect::<Result<_>>()?;

    for name in &selected {
        let package = managed.get(name).ok_or_else(|| unmanaged_error(name))?;
        for dependency in package.dependencies.iter().filter(|dep| dep.path.is_some()) {
            let path = fs::canonicalize(dependency.path.as_ref().expect("filtered path"))?;
            let target = by_directory.get(&path).ok_or_else(|| {
                anyhow!(
                    "{} path dependency {} is outside the workspace",
                    name,
                    dependency.name
                )
            })?;
            if !target.publishable() {
                bail!("{name} depends on private crate {}", target.name);
            }
            if dependency.req == VersionReq::STAR {
                bail!(
                    "{name} -> {} has no registry version; run crate-release bump for {name}",
                    target.name
                );
            }
            if !dependency.req.matches(&target.version) {
                bail!(
                    "{name} -> {} requires {}, but the local crate is {}",
                    target.name,
                    dependency.req,
                    target.version
                );
            }
        }

        eprintln!("crate-release: package-checking {name} {}", package.version);
        let mut command = ProcessCommand::new("cargo");
        command
            .args(["package", "--package", name, "--allow-dirty", "--no-verify"])
            .current_dir(root);
        // Before NARF's first crates.io publication, Cargo cannot resolve the
        // registry fallbacks we just validated. Patch the selected crate's
        // internal dependencies back to this checkout for archive construction only. Cargo
        // still normalizes the packaged manifest to registry requirements;
        // none of these local paths appear in the resulting `.crate` file.
        let internal_dependencies = package
            .dependencies
            .iter()
            .filter_map(|dependency| dependency.path.as_ref())
            .map(fs::canonicalize)
            .collect::<std::io::Result<BTreeSet<_>>>()?;
        for dependency_path in internal_dependencies {
            let internal = by_directory.get(&dependency_path).ok_or_else(|| {
                anyhow!(
                    "{} has an internal dependency outside the workspace: {}",
                    name,
                    dependency_path.display()
                )
            })?;
            let path = internal.directory()?.to_string_lossy();
            let path_value = Value::from(path.as_ref()).to_string();
            command.arg("--config").arg(format!(
                "patch.crates-io.{}.path={path_value}",
                internal.name
            ));
        }
        let status = command
            .status()
            .with_context(|| format!("running cargo package for {name}"))?;
        if !status.success() {
            bail!("cargo package failed for {name}");
        }
        let archive = metadata
            .target_directory
            .join("package")
            .join(format!("{name}-{}.crate", package.version));
        let bytes = fs::metadata(&archive)
            .with_context(|| format!("reading package archive {}", archive.display()))?
            .len();
        if bytes > 10_000_000 {
            bail!(
                "{} is {} bytes; crates.io's archive limit is 10000000",
                archive.display(),
                bytes
            );
        }
    }
    println!(
        "crate-release: publication preflight passed for {} crate(s); nothing was uploaded",
        selected.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_requires_name_and_semver() {
        let parsed = parse_assignment("narf-demo=1.2.3").unwrap();
        assert_eq!(parsed.name, "narf-demo");
        assert_eq!(parsed.version, Version::new(1, 2, 3));
        assert!(parse_assignment("narf-demo").is_err());
        assert!(parse_assignment("=1.2.3").is_err());
        assert!(parse_assignment("narf-demo=latest").is_err());
    }

    #[test]
    fn explicit_version_is_distinct_from_workspace_inheritance() {
        let explicit = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[package.metadata.narf]\nrelease-managed = true\n"
            .parse::<DocumentMut>()
            .unwrap();
        let inherited = "[package]\nname = \"demo\"\nversion.workspace = true\n"
            .parse::<DocumentMut>()
            .unwrap();
        assert_eq!(explicit["package"]["version"].as_str(), Some("0.1.0"));
        assert!(inherited["package"]["version"].as_str().is_none());
        assert_eq!(
            explicit["package"]["metadata"]["narf"]["release-managed"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn adds_or_replaces_inline_dependency_version() {
        let mut document = "[dependencies]\nfoo = { path = \"../foo\", features = [\"x\"] }\n"
            .parse::<DocumentMut>()
            .unwrap();
        let item = document["dependencies"].as_table_mut().unwrap()["foo"].as_value_mut();
        assert!(item.is_some());
        set_dependency_requirement(
            document["dependencies"]
                .as_table_mut()
                .unwrap()
                .get_mut("foo")
                .unwrap(),
            &Version::new(0, 4, 2),
        )
        .unwrap();
        let rendered = document.to_string();
        assert!(rendered.contains("path = \"../foo\""));
        assert!(rendered.contains("features = [\"x\"]"));
        assert!(rendered.contains("version = \"^0.4.2\""));
    }

    #[test]
    fn preserves_a_compatible_dependency_requirement() {
        let mut item = "{ path = \"../foo\", version = \">=0.4, <1\" }"
            .parse::<Value>()
            .map(Item::Value)
            .unwrap();
        set_dependency_requirement(&mut item, &Version::new(0, 5, 1)).unwrap();
        assert_eq!(dependency_requirement(&item), Some(">=0.4, <1"));
    }

    #[test]
    fn nested_package_owns_its_files() {
        let roots = vec![
            PathBuf::from("drivers/net"),
            PathBuf::from("drivers/net/e1000"),
        ];
        assert!(path_owned_by(
            Path::new("drivers/net/src/lib.rs"),
            Path::new("drivers/net"),
            &roots
        ));
        assert!(!path_owned_by(
            Path::new("drivers/net/e1000/src/lib.rs"),
            Path::new("drivers/net"),
            &roots
        ));
        assert!(path_owned_by(
            Path::new("drivers/net/e1000/src/lib.rs"),
            Path::new("drivers/net/e1000"),
            &roots
        ));
    }
}
