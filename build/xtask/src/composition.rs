//! External kernel-crate composition.
//!
//! A composition is deliberately an input beside the NARF checkout, not a
//! patch to it.  Built-in crates are added to a generated copy of the frame
//! manifest under `target/narf-compositions/`; loadable crates are built as
//! ordinary `.ko` images and staged by the caller.  Keeping every built-in in
//! the frame's one Cargo graph is load-bearing: separately compiling an rlib
//! can select a different feature set (and therefore different Rust symbol
//! hashes) for kernel crates.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ComponentMode {
    Builtin,
    Module,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompositionFile {
    version: u32,
    #[serde(default)]
    allow_unsigned_modules: bool,
    #[serde(default, rename = "component")]
    components: Vec<ComponentInput>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentInput {
    manifest: PathBuf,
    package: Option<String>,
    mode: ComponentMode,
    features: Option<Vec<String>>,
    default_features: Option<bool>,
    entry: Option<String>,
    stage: Option<String>,
    domain: Option<String>,
    autoload: Option<bool>,
    #[serde(default)]
    compress: bool,
    signature: Option<PathBuf>,
    public_key: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct Component {
    pub manifest: PathBuf,
    pub package: String,
    pub mode: ComponentMode,
    pub features: Vec<String>,
    pub default_features: bool,
    pub entry: String,
    pub stage: String,
    pub domain: Option<String>,
    pub autoload: bool,
    pub compress: bool,
    pub signature: Option<PathBuf>,
    pub public_key: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub allow_unsigned_modules: bool,
    pub components: Vec<Component>,
}

impl Plan {
    pub fn builtins(&self) -> impl Iterator<Item = &Component> {
        self.components
            .iter()
            .filter(|component| component.mode == ComponentMode::Builtin)
    }

    pub fn modules(&self) -> impl Iterator<Item = &Component> {
        self.components
            .iter()
            .filter(|component| component.mode == ComponentMode::Module)
    }
}

#[derive(Clone, Debug)]
pub struct PackageInfo {
    pub name: String,
    pub lib_name: String,
    pub manifest: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Overlay {
    pub manifest: PathBuf,
    pub registrar: PathBuf,
}

fn manifest_path(path: &Path, base: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let candidate = if joined.is_dir() {
        joined.join("Cargo.toml")
    } else {
        joined
    };
    candidate
        .canonicalize()
        .with_context(|| format!("resolving component manifest {}", candidate.display()))
}

fn optional_path(path: Option<PathBuf>, base: &Path, label: &str) -> Result<Option<PathBuf>> {
    path.map(|path| {
        let path = if path.is_absolute() {
            path
        } else {
            base.join(path)
        };
        path.canonicalize()
            .with_context(|| format!("resolving {label} {}", path.display()))
    })
    .transpose()
}

/// Resolve a package and its actual Cargo target directory from any manifest,
/// including a package outside the NARF workspace.
pub fn resolve_package(manifest: &Path, requested: Option<&str>) -> Result<PackageInfo> {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .with_context(|| format!("running cargo metadata for {}", manifest.display()))?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed for {}:\n{}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parsing cargo metadata for {}", manifest.display()))?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("cargo metadata omitted packages"))?;
    let canonical_requested_manifest = manifest.canonicalize().unwrap_or_else(|_| manifest.into());

    let select = |package: &&serde_json::Value| -> bool {
        if let Some(requested) = requested {
            return package.get("name").and_then(serde_json::Value::as_str) == Some(requested);
        }
        package
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .and_then(|path| path.canonicalize().ok())
            .is_some_and(|path| path == canonical_requested_manifest)
    };
    let package = packages
        .iter()
        .find(select)
        .or_else(|| (requested.is_none() && packages.len() == 1).then(|| &packages[0]))
        .ok_or_else(|| {
            let available = packages
                .iter()
                .filter_map(|package| package.get("name")?.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow!(
                "{} does not identify one package{}; available packages: {}",
                manifest.display(),
                requested
                    .map(|name| format!(" named `{name}`"))
                    .unwrap_or_default(),
                available
            )
        })?;
    let name = package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("selected cargo package has no name"))?
        .to_string();
    let manifest = package
        .get("manifest_path")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("selected cargo package has no manifest_path"))?;
    let lib_name = package
        .get("targets")
        .and_then(serde_json::Value::as_array)
        .and_then(|targets| {
            targets.iter().find(|target| {
                target
                    .get("kind")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|kinds| {
                        kinds
                            .iter()
                            .any(|kind| matches!(kind.as_str(), Some("lib" | "rlib" | "staticlib")))
                    })
            })
        })
        .and_then(|target| target.get("name"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("selected cargo package {name} has no library target"))?
        .to_string();
    Ok(PackageInfo {
        name,
        lib_name,
        manifest,
    })
}

fn valid_rust_path(path: &str) -> bool {
    !path.is_empty()
        && path.split("::").all(|segment| {
            !segment.is_empty()
                && segment.chars().enumerate().all(|(index, ch)| {
                    ch == '_' || ch.is_ascii_alphanumeric() && (index != 0 || !ch.is_ascii_digit())
                })
        })
}

fn valid_stage(stage: &str) -> bool {
    matches!(
        stage,
        "early" | "core" | "postcore" | "arch" | "subsys" | "fs" | "device" | "late"
    )
}

fn valid_domain(domain: &str) -> bool {
    matches!(
        domain,
        "frame"
            | "caps"
            | "memory_mgr"
            | "sched"
            | "ipc"
            | "tracer"
            | "keys"
            | "observe"
            | "userspace_k"
            | "driver0"
            | "driver1"
            | "driver2"
            | "driver3"
            | "driver4"
            | "bpf"
            | "scratch"
            | "net"
            | "block"
            | "graphics"
            | "input"
            | "crypto"
    )
}

fn builtin_domain_id(domain: &str) -> Option<u8> {
    Some(match domain {
        "frame" => 0,
        "caps" => 1,
        "memory_mgr" => 2,
        "sched" => 3,
        "ipc" => 4,
        "tracer" => 5,
        "keys" => 6,
        "observe" => 7,
        "userspace_k" => 8,
        "driver0" | "net" => 9,
        "driver1" | "block" => 10,
        "driver2" | "graphics" => 11,
        "driver3" | "input" => 12,
        "driver4" | "crypto" => 13,
        "bpf" => 14,
        "scratch" => 15,
        _ => return None,
    })
}

fn resolve_component(input: ComponentInput, base: &Path) -> Result<Component> {
    if input.mode == ComponentMode::Builtin && input.autoload.is_some() {
        bail!("a built-in component cannot set autoload");
    }
    if input.mode == ComponentMode::Module && (input.entry.is_some() || input.stage.is_some()) {
        bail!("a module component cannot set entry or stage");
    }
    let requested_manifest = manifest_path(&input.manifest, base)?;
    let package = resolve_package(&requested_manifest, input.package.as_deref())?;
    let features = input.features.unwrap_or_else(|| match input.mode {
        ComponentMode::Builtin => Vec::new(),
        ComponentMode::Module => vec!["module".into()],
    });
    let default_features = input
        .default_features
        .unwrap_or(input.mode == ComponentMode::Builtin);
    let entry = input.entry.unwrap_or_else(|| "register".into());
    let stage = input.stage.unwrap_or_else(|| "subsys".into());
    if !valid_rust_path(&entry) {
        bail!(
            "component {} has invalid Rust entry path `{entry}`",
            package.name
        );
    }
    if !valid_stage(&stage) {
        bail!(
            "component {} has invalid init stage `{stage}`",
            package.name
        );
    }
    if let Some(domain) = input.domain.as_deref() {
        if !valid_domain(domain) {
            bail!("component {} has unknown domain `{domain}`", package.name);
        }
        if input.mode == ComponentMode::Module && domain == "frame" {
            bail!(
                "runtime module {} cannot select the FRAME domain",
                package.name
            );
        }
    }
    let signature = optional_path(input.signature, base, "module signature")?;
    let public_key = optional_path(input.public_key, base, "module public key")?;
    if signature.is_some() != public_key.is_some() {
        bail!(
            "component {} must set signature and public_key together",
            package.name
        );
    }
    if input.mode == ComponentMode::Builtin
        && (input.compress || signature.is_some() || public_key.is_some())
    {
        bail!(
            "built-in component {} cannot use module compression/signature options",
            package.name
        );
    }
    Ok(Component {
        manifest: package.manifest,
        package: package.name,
        mode: input.mode,
        features,
        default_features,
        entry,
        stage,
        domain: input.domain,
        autoload: input
            .autoload
            .unwrap_or(input.mode == ComponentMode::Module),
        compress: input.compress,
        signature,
        public_key,
    })
}

/// Load a persistent composition and merge repeatable one-off crate flags.
pub fn load(
    root: &Path,
    file: Option<&Path>,
    builtin_crates: &[PathBuf],
    module_crates: &[PathBuf],
    allow_unsigned_modules: bool,
) -> Result<Plan> {
    let (mut inputs, file_unsigned) = if let Some(file) = file {
        let file = manifest_path(file, root)?;
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading composition {}", file.display()))?;
        let parsed: CompositionFile = toml::from_str(&text)
            .with_context(|| format!("parsing composition {}", file.display()))?;
        if parsed.version != FORMAT_VERSION {
            bail!(
                "composition {} uses version {}; supported version is {}",
                file.display(),
                parsed.version,
                FORMAT_VERSION
            );
        }
        let base = file.parent().unwrap_or(root).to_path_buf();
        (
            parsed
                .components
                .into_iter()
                .map(|component| (component, base.clone()))
                .collect::<Vec<_>>(),
            parsed.allow_unsigned_modules,
        )
    } else {
        (Vec::new(), false)
    };

    for manifest in builtin_crates {
        inputs.push((
            ComponentInput {
                manifest: manifest.clone(),
                package: None,
                mode: ComponentMode::Builtin,
                features: None,
                default_features: None,
                entry: None,
                stage: None,
                domain: None,
                autoload: None,
                compress: false,
                signature: None,
                public_key: None,
            },
            root.to_path_buf(),
        ));
    }
    for manifest in module_crates {
        inputs.push((
            ComponentInput {
                manifest: manifest.clone(),
                package: None,
                mode: ComponentMode::Module,
                features: None,
                default_features: None,
                entry: None,
                stage: None,
                domain: None,
                autoload: None,
                compress: false,
                signature: None,
                public_key: None,
            },
            root.to_path_buf(),
        ));
    }

    let mut components = Vec::with_capacity(inputs.len());
    let mut identities = BTreeSet::new();
    let mut module_paths = BTreeSet::new();
    for (input, base) in inputs {
        let component = resolve_component(input, &base)?;
        let identity = (component.package.clone(), component.mode as u8);
        if !identities.insert(identity) {
            bail!(
                "component {} is selected more than once in {:?} mode",
                component.package,
                component.mode
            );
        }
        if component.mode == ComponentMode::Module {
            let path = module_guest_path(&component);
            if !module_paths.insert(path.clone()) {
                bail!("multiple module components map to guest path {path}");
            }
        }
        components.push(component);
    }
    let allow_unsigned_modules = allow_unsigned_modules || file_unsigned;
    if !allow_unsigned_modules {
        for component in components
            .iter()
            .filter(|component| component.mode == ComponentMode::Module)
        {
            if component.signature.is_none() {
                bail!(
                    "module component {} is unsigned; provide signature/public_key or explicitly enable allow_unsigned_modules",
                    component.package
                );
            }
        }
    }
    Ok(Plan {
        allow_unsigned_modules,
        components,
    })
}

fn rewrite_dependency_paths(value: &mut toml::Value, base: &Path) {
    let Some(table) = value.as_table_mut() else {
        return;
    };
    for (_, dependency) in table.iter_mut() {
        let Some(spec) = dependency.as_table_mut() else {
            continue;
        };
        let Some(path) = spec.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        let absolute = base
            .join(path)
            .canonicalize()
            .unwrap_or_else(|_| base.join(path));
        spec.insert(
            "path".into(),
            toml::Value::String(absolute.display().to_string()),
        );
    }
}

fn composition_key(plan: &Plan) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&FORMAT_VERSION.to_le_bytes());
    hasher.update(&[u8::from(plan.allow_unsigned_modules)]);
    for component in &plan.components {
        hasher.update(component.manifest.as_os_str().as_encoded_bytes());
        hasher.update(component.package.as_bytes());
        hasher.update(&[component.mode as u8, u8::from(component.default_features)]);
        for feature in &component.features {
            hasher.update(feature.as_bytes());
            hasher.update(&[0]);
        }
        hasher.update(component.entry.as_bytes());
        hasher.update(component.stage.as_bytes());
        if let Some(domain) = &component.domain {
            hasher.update(domain.as_bytes());
        }
        hasher.update(&[u8::from(component.autoload), u8::from(component.compress)]);
        if let Some(signature) = &component.signature {
            hasher.update(signature.as_os_str().as_encoded_bytes());
        }
        if let Some(public_key) = &component.public_key {
            hasher.update(public_key.as_os_str().as_encoded_bytes());
        }
    }
    hasher.finalize().to_hex()[..16].to_string()
}

pub fn output_dir(root: &Path, plan: &Plan) -> PathBuf {
    root.join("target")
        .join("narf-compositions")
        .join(composition_key(plan))
}

fn raw_public_key_hex(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading module public key {}", path.display()))?;
    let key: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "module public key {} must contain exactly 32 raw bytes, got {}",
            path.display(),
            bytes.len()
        )
    })?;
    if key == [0; 32] {
        bail!("module public key {} cannot be all zero", path.display());
    }
    Ok(key.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Materialise the trust store selected by signed module entries.
///
/// An operator-provided `NARF_MODULE_TRUSTED_KEYS` file is copied into the
/// generated store first, so a composition augments rather than replaces an
/// existing distribution trust policy. `modules/build.rs` remains the final
/// parser and enforces its duplicate/key-count bounds.
pub fn prepare_trusted_keys(root: &Path, plan: &Plan) -> Result<Option<PathBuf>> {
    let public_keys = plan
        .modules()
        .filter_map(|component| component.public_key.as_deref())
        .collect::<Vec<_>>();
    if public_keys.is_empty() {
        return Ok(None);
    }

    let mut contents = String::new();
    if let Some(existing) = std::env::var_os("NARF_MODULE_TRUSTED_KEYS") {
        let existing = PathBuf::from(existing);
        if !existing.is_absolute() {
            bail!("NARF_MODULE_TRUSTED_KEYS must be an absolute path");
        }
        contents.push_str(&std::fs::read_to_string(&existing).with_context(|| {
            format!(
                "reading existing trusted module keys {}",
                existing.display()
            )
        })?);
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
    }
    contents.push_str("# Public keys selected by the external composition.\n");
    for public_key in public_keys {
        writeln!(contents, "{}", raw_public_key_hex(public_key)?)?;
    }

    let path = output_dir(root, plan).join("trusted-module-keys.hex");
    write_if_changed(&path, contents.as_bytes())?;
    Ok(Some(path))
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(contents) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

fn stage_expr(stage: &str) -> &'static str {
    match stage {
        "early" => "narf_init::Stage::Early",
        "core" => "narf_init::Stage::Core",
        "postcore" => "narf_init::Stage::PostCore",
        "arch" => "narf_init::Stage::Arch",
        "subsys" => "narf_init::Stage::Subsys",
        "fs" => "narf_init::Stage::Fs",
        "device" => "narf_init::Stage::Device",
        "late" => "narf_init::Stage::Late",
        _ => unreachable!("stage validated while resolving composition"),
    }
}

/// Materialise the standalone frame manifest and generated registration calls
/// for all built-ins.  Returns `None` for a module-only composition.
pub fn prepare_overlay(root: &Path, plan: &Plan) -> Result<Option<Overlay>> {
    let builtins = plan.builtins().collect::<Vec<_>>();
    if builtins.is_empty() {
        return Ok(None);
    }
    let frame_dir = root.join("frame");
    let frame_manifest = frame_dir.join("Cargo.toml");
    let mut manifest: toml::Value = std::fs::read_to_string(&frame_manifest)
        .with_context(|| format!("reading {}", frame_manifest.display()))?
        .parse()
        .with_context(|| format!("parsing {}", frame_manifest.display()))?;
    let workspace: toml::Value = std::fs::read_to_string(root.join("Cargo.toml"))
        .context("reading workspace Cargo.toml")?
        .parse()
        .context("parsing workspace Cargo.toml")?;

    let inherited = workspace
        .get("workspace")
        .and_then(|value| value.get("package"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("workspace Cargo.toml has no workspace.package table"))?;
    let package = manifest
        .get_mut("package")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("frame Cargo.toml has no package table"))?;
    for field in [
        "version",
        "edition",
        "rust-version",
        "license",
        "repository",
    ] {
        if package
            .get(field)
            .and_then(toml::Value::as_table)
            .and_then(|value| value.get("workspace"))
            .and_then(toml::Value::as_bool)
            == Some(true)
        {
            let value = inherited
                .get(field)
                .cloned()
                .ok_or_else(|| anyhow!("workspace.package.{field} is missing"))?;
            package.insert(field.into(), value);
        }
    }
    manifest
        .as_table_mut()
        .ok_or_else(|| anyhow!("frame manifest root is not a table"))?
        .remove("lints");
    for key in ["dependencies", "build-dependencies", "dev-dependencies"] {
        if let Some(value) = manifest.get_mut(key) {
            rewrite_dependency_paths(value, &frame_dir);
        }
    }
    if let Some(bins) = manifest.get_mut("bin").and_then(toml::Value::as_array_mut) {
        for bin in bins {
            if let Some(table) = bin.as_table_mut() {
                if let Some(path) = table.get("path").and_then(toml::Value::as_str) {
                    table.insert(
                        "path".into(),
                        toml::Value::String(frame_dir.join(path).display().to_string()),
                    );
                }
            }
        }
    }
    let features = manifest
        .get_mut("features")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("frame Cargo.toml has no features table"))?;
    features.insert(
        "external-composition".into(),
        toml::Value::Array(Vec::new()),
    );

    let dependencies = manifest
        .get_mut("dependencies")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("frame Cargo.toml has no dependencies table"))?;
    for (index, component) in builtins.iter().enumerate() {
        let alias = format!("narf_composed_{index}");
        let mut spec = toml::map::Map::new();
        spec.insert(
            "package".into(),
            toml::Value::String(component.package.clone()),
        );
        spec.insert(
            "path".into(),
            toml::Value::String(
                component
                    .manifest
                    .parent()
                    .ok_or_else(|| anyhow!("component manifest has no parent"))?
                    .display()
                    .to_string(),
            ),
        );
        spec.insert(
            "default-features".into(),
            toml::Value::Boolean(component.default_features),
        );
        if !component.features.is_empty() {
            spec.insert(
                "features".into(),
                toml::Value::Array(
                    component
                        .features
                        .iter()
                        .cloned()
                        .map(toml::Value::String)
                        .collect(),
                ),
            );
        }
        dependencies.insert(alias, toml::Value::Table(spec));
    }

    let root_table = manifest
        .as_table_mut()
        .ok_or_else(|| anyhow!("frame manifest root is not a table"))?;
    let mut overlay_workspace = toml::map::Map::new();
    overlay_workspace.insert("resolver".into(), toml::Value::String("2".into()));
    root_table.insert("workspace".into(), toml::Value::Table(overlay_workspace));
    if let Some(profile) = workspace.get("profile") {
        root_table.insert("profile".into(), profile.clone());
    }

    let dir = output_dir(root, plan).join("overlay");
    let overlay_manifest = dir.join("Cargo.toml");
    write_if_changed(
        &overlay_manifest,
        toml::to_string_pretty(&manifest)?.as_bytes(),
    )?;

    let mut registrar = String::from(
        "// Generated by `cargo xtask`; do not edit.\n\
         pub(crate) fn register_initcalls() {\n",
    );
    for (index, component) in builtins.iter().enumerate() {
        let label = format!("external/{}", component.package);
        let alias = format!("narf_composed_{index}");
        writeln!(
            registrar,
            "    narf_init::register({}, {:?}, || {{",
            stage_expr(&component.stage),
            label
        )?;
        if let Some(domain) = component.domain.as_deref() {
            let id = builtin_domain_id(domain).expect("validated domain has a numeric id");
            writeln!(
                registrar,
                "        {alias}::{}(narf_lib::id::DomainId::new({id}));",
                component.entry
            )?;
        } else {
            writeln!(registrar, "        {alias}::{}();", component.entry)?;
        }
        registrar.push_str("        narf_init::InitResult::Ok\n    });\n");
    }
    registrar.push_str("}\n");
    let registrar_path = dir.join("registrar.rs");
    write_if_changed(&registrar_path, registrar.as_bytes())?;
    Ok(Some(Overlay {
        manifest: overlay_manifest,
        registrar: registrar_path,
    }))
}

pub fn module_output_path(
    root: &Path,
    plan: &Plan,
    target: &str,
    component: &Component,
) -> PathBuf {
    let stem = component.package.replace('-', "_");
    let suffix = if component.compress { ".ko.lz4" } else { ".ko" };
    output_dir(root, plan)
        .join("modules")
        .join(target)
        .join(format!("{stem}{suffix}"))
}

pub fn module_guest_path(component: &Component) -> String {
    let stem = component.package.replace('-', "_");
    let suffix = if component.compress { ".ko.lz4" } else { ".ko" };
    format!("lib/modules/{stem}{suffix}")
}

pub fn boot_arguments(plan: &Plan) -> Vec<String> {
    let autoload = plan
        .modules()
        .filter(|component| component.autoload)
        .collect::<Vec<_>>();
    if autoload.is_empty() {
        return Vec::new();
    }
    let paths = autoload
        .iter()
        .map(|component| module_guest_path(component))
        .collect::<Vec<_>>();
    let mut args = vec![format!("modules_load={}", paths.join(","))];
    let domains = autoload
        .iter()
        .filter_map(|component| {
            component
                .domain
                .as_ref()
                .map(|domain| format!("{}={domain}", module_guest_path(component)))
        })
        .collect::<Vec<_>>();
    if !domains.is_empty() {
        args.push(format!("modules_domains={}", domains.join(",")));
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_schema_rejects_unknown_fields() {
        let text = r#"
version = 1
surprise = true
"#;
        assert!(toml::from_str::<CompositionFile>(text).is_err());
    }

    #[test]
    fn builtin_domains_follow_the_owned_namespace() {
        assert_eq!(builtin_domain_id("frame"), Some(0));
        assert_eq!(builtin_domain_id("net"), Some(9));
        assert_eq!(builtin_domain_id("graphics"), Some(11));
        assert_eq!(builtin_domain_id("bpf"), Some(14));
        assert_eq!(builtin_domain_id("scratch"), Some(15));
        assert_eq!(builtin_domain_id("unknown"), None);
    }

    #[test]
    fn rust_entry_paths_are_bounded_to_identifiers() {
        assert!(valid_rust_path("register"));
        assert!(valid_rust_path("component::register"));
        assert!(!valid_rust_path("component::"));
        assert!(!valid_rust_path("register(); panic!()"));
        assert!(!valid_rust_path("9register"));
    }

    #[test]
    fn raw_public_keys_use_the_trust_store_format() {
        let path = std::env::temp_dir().join(format!(
            "narf-composition-public-key-{}",
            std::process::id()
        ));
        std::fs::write(&path, [0x5a; 32]).unwrap();
        let encoded = raw_public_key_hex(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(encoded, "5a".repeat(32));
    }

    #[test]
    fn boot_plan_keeps_per_module_domains() {
        let component = |package: &str, domain: Option<&str>| Component {
            manifest: PathBuf::from("Cargo.toml"),
            package: package.into(),
            mode: ComponentMode::Module,
            features: vec!["module".into()],
            default_features: false,
            entry: "register".into(),
            stage: "subsys".into(),
            domain: domain.map(str::to_string),
            autoload: true,
            compress: false,
            signature: None,
            public_key: None,
        };
        let plan = Plan {
            allow_unsigned_modules: true,
            components: vec![
                component("acme-net", Some("driver2")),
                component("trace", None),
            ],
        };
        assert_eq!(
            boot_arguments(&plan),
            [
                "modules_load=lib/modules/acme_net.ko,lib/modules/trace.ko",
                "modules_domains=lib/modules/acme_net.ko=driver2",
            ]
        );
        assert_ne!(
            module_output_path(
                Path::new("/repo"),
                &plan,
                "x86_64-unknown-none",
                &plan.components[0],
            ),
            module_output_path(
                Path::new("/repo"),
                &plan,
                "aarch64-unknown-none",
                &plan.components[0],
            ),
        );
    }
}
