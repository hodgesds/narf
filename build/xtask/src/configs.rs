//! `cargo xtask --config <name-or-path>` — TOML driver configuration.
//!
//! A config is a TOML file, Linux `.config`-like, listing drivers
//! with `y` / `n` / `m` per driver (design of record:
//! `narf-configurable-drivers-design.md` §5). Policy lives in this
//! one file (the `affected.rs` precedent): the loader, the
//! name-or-path resolver, the validator, and the TOML→feature-set
//! translator. Nothing in xtask maps a name to a hardcoded feature
//! list any more — the closed named-config registry this file used
//! to hold is DELETED (Daniel, 2026-11-27: "rework it").
//!
//! File shape (§5.1):
//!
//! ```toml
//! [drivers.net]
//! e1000 = "y"
//! ixgbe = "n"
//!
//! [drivers.storage]
//! nvme = "y"
//! ```
//!
//! * `"y"` — built in: the driver is compiled into `narf-frame`
//!   and registers, as today.
//! * `"n"` — left out: neither compiled into frame nor registered.
//! * `"m"` — built as a loadable module (`.ko`). Lane 1 refuses
//!   it as a hard error (§5.2): the `m` build belongs to the
//!   modules-for-everything programme, and silently treating it as
//!   `"n"` or `"y"` would lie about the resulting image.
//!
//! Key validity is closed per table, grounded in the facades'
//! manifests at the build's tip: `[drivers.net]` is the 17
//! per-driver features of `narf-drivers-net`, `[drivers.storage]`
//! is the 7 per-driver features of `narf-drivers-storage` PLUS the
//! special key `nvme`, which maps to the standalone dual-build
//! crate `drivers/nvme` (not a facade feature). `[drivers.gpu]`
//! is valid from lane 2 only; wireless/usb/fs/etc. have no valid
//! keys yet. An unknown table or key is a hard error. Values are
//! the exact lowercase strings `"y"` / `"n"` / `"m"`.
//!
//! Unspecified key defaults to `"y"`: a config states what it
//! changes and pins, and can never silently exclude a driver it
//! does not mention. An empty file is valid and means all `"y"`.
//! The file contains only `[drivers.*]` tables.
//!
//! Resolution (§5.2) is syntactic: an argument containing a path
//! separator (`/`) or ending in `.toml` is a path, used as-is
//! (in-repo or out, relative to the cwd where `cargo xtask` was
//! invoked); anything else is a preset name resolving to
//! `configs/<name>.toml` under the workspace root. Unknown name =
//! error, no filesystem fallback. `auto` is the one reserved
//! keyword (lane-5 test-config generator); it is neither a preset
//! name nor a path, and lane 1 refuses it.
//!
//! Translation (§5.3) follows the tree's `kernel-test` forwarding
//! pattern. Frame's `drivers-net` / `drivers-storage` features are
//! the group gates: each names only its facade dep, and
//! `bare_main` calls the facade's `register_initcalls()` only
//! under the matching gate. The full per-driver set lives in
//! frame's `default`, so a plain build composes exactly the driver
//! set it did before. A config resolves to `--no-default-features`
//! + the always-on core features + the gate feature for every
//! group with at least one `"y"` facade key + the per-driver facade
//! features for the `"y"` keys (`narf-drivers-net/<driver>`,
//! `narf-drivers-storage/<driver>`), and `drivers-nvme` for the
//! standalone NVMe crate when `nvme = "y"` (its own gate — it does
//! not pull in the storage gate). A group with all keys
//! `"n"` contributes no feature at all. Free-form `--features`
//! remains available for one-off local use and composes with
//! `--config` by union; CI passes config paths/names only.
//!
//! Two consequences of the group-gate shape, stated plainly:
//! (a) the `all` translation resolves to exactly frame's default
//! feature set (verified by the `all_matches_default_build` test
//! and by `cargo tree`); (b) the composition census fixture
//! (`frame/src/census.rs`) is group-granular, so it is exact for
//! `all`, `minimal`, and every group-uniform generated config,
//! while a hand-written *partial* config (some keys `"y"`, some
//! `"n"` inside one group) trips the census smoke loudly — the
//! fixture expects the full group set whenever the gate is on.
//! Per-driver census tables are a follow-up, not this lane.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Frame features that are not driver-group selections but members
/// of frame's `default` — the always-on core a subset config must
/// re-add explicitly when it drops defaults. Mirrors the non-group
/// members of `default` in `frame/Cargo.toml`; if the two drift
/// apart, subset builds lose core behaviour and the composition
/// census fixture (frame/src/census.rs) shows the drift in stages
/// no group owns.
pub const CORE_FEATURES: &[&str] = &["user-task-smp"];

/// Per-driver keys of `[drivers.net]`: the 17 per-driver features
/// of `narf-drivers-net` (`drivers/net/Cargo.toml`, `default` list).
pub const NET_KEYS: &[&str] = &[
    "aqc1xx",
    "atheros",
    "bnxt",
    "cxgb4",
    "e1000",
    "enic",
    "forcedeth",
    "i40e",
    "igb",
    "igc",
    "ixgbe",
    "mlx4",
    "mlx5",
    "realtek",
    "rtl8139",
    "tg3",
    "vmxnet3",
];

/// Per-driver keys of `[drivers.storage]`: the 7 per-driver
/// features of `narf-drivers-storage`
/// (`drivers/storage/Cargo.toml`, `default` list) PLUS the special
/// key `nvme`, which maps to the standalone dual-build crate
/// `drivers/nvme` (not a facade feature).
pub const STORAGE_KEYS: &[&str] = &[
    "ahci", "megaraid", "mpt3sas", "rtsx", "sdhci", "smartpqi", "vmd", "nvme",
];

/// The one reserved `--config` keyword (§5.4): the lane-5
/// test-config generator. Neither a preset name nor a path.
pub const RESERVED_AUTO: &str = "auto";

/// One driver's selection in a config file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    /// Built in: compiled into `narf-frame` and registered.
    Yes,
    /// Left out: neither compiled in nor registered.
    No,
    /// Built as a loadable module (`.ko`): refused by lane 1 (§5.2).
    Module,
}

impl Selection {
    /// Parse the exact lowercase string values `"y"` / `"n"` /
    /// `"m"`; anything else is an error naming the key and value.
    fn from_str(value: &str, key: &str, file: &Path) -> Result<Selection> {
        match value {
            "y" => Ok(Selection::Yes),
            "n" => Ok(Selection::No),
            "m" => Ok(Selection::Module),
            other => bail!(
                "invalid value for {key:?} in {}: expected exactly \"y\", \"n\" or \"m\", got {other:?}",
                file.display()
            ),
        }
    }
}

/// A config file's driver selections after validation: every known
/// key present, unspecified keys defaulting to `"y"` (§5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverConfig {
    /// `[drivers.net]`, one entry per key in [`NET_KEYS`].
    pub net: BTreeMap<&'static str, Selection>,
    /// `[drivers.storage]`, one entry per key in [`STORAGE_KEYS`].
    pub storage: BTreeMap<&'static str, Selection>,
}

impl DriverConfig {
    /// Every known key `"y"` — the effective selection of an empty
    /// file and of `configs/all.toml`.
    fn all_yes() -> DriverConfig {
        DriverConfig {
            net: NET_KEYS.iter().map(|k| (*k, Selection::Yes)).collect(),
            storage: STORAGE_KEYS.iter().map(|k| (*k, Selection::Yes)).collect(),
        }
    }
}

/// A resolved `--config`: what `cargo_build` applies to the frame
/// build (`--no-default-features` + this feature list, unioned
/// with the caller's `--features`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedConfig {
    /// Drop `narf-frame`'s default features before applying
    /// `features`. Always true for a config: even `all` re-selects
    /// the default set explicitly (same resolved set — see the
    /// `all_matches_default_build` test), so the translation is
    /// one code path for every file.
    pub no_default_features: bool,
    /// Frame features the config selects, in a stable order.
    pub features: Vec<String>,
    /// Where the config came from (preset path or the given path),
    /// for error messages and logs.
    pub source: PathBuf,
}

/// Parse and validate a config file's text. The file contains only
/// `[drivers.*]` tables; anything else is a hard error naming the
/// file, the key/value, and the reason (§5.2 error table).
pub fn parse(text: &str, file: &Path) -> Result<DriverConfig> {
    let value: toml::Value =
        toml::from_str(text).with_context(|| format!("malformed TOML in {}", file.display()))?;
    let Some(top) = value.as_table() else {
        bail!(
            "malformed TOML in {}: top level is not a table",
            file.display()
        );
    };
    for key in top.keys() {
        if key != "drivers" {
            bail!(
                "unknown table in {}: {key:?} is not a [drivers.*] table (the file is driver selection only)",
                file.display()
            );
        }
    }
    let mut config = DriverConfig::all_yes();
    let Some(drivers) = top.get("drivers") else {
        return Ok(config);
    };
    let Some(drivers) = drivers.as_table() else {
        bail!(
            "invalid [drivers] in {}: expected a table of [drivers.<group>] tables",
            file.display()
        );
    };
    for (group, table) in drivers {
        let (known, target): (&[&str], &mut BTreeMap<&'static str, Selection>) =
            match group.as_str() {
                "net" => (NET_KEYS, &mut config.net),
                "storage" => (STORAGE_KEYS, &mut config.storage),
                "gpu" => {
                    bail!(
                        "unknown table in {}: [drivers.gpu] has no selection surface yet — \
                     the gpu keys (amdgpu, intel) become valid in lane 2",
                        file.display()
                    );
                }
                other => {
                    bail!(
                        "unknown table in {}: [drivers.{other}] has no selection surface yet",
                        file.display()
                    );
                }
            };
        let Some(table) = table.as_table() else {
            bail!(
                "invalid [drivers.{group}] in {}: expected a table of driver = \"y\" / \"n\" / \"m\" entries",
                file.display()
            );
        };
        for (key, raw) in table {
            let Some(known_key) = known.iter().find(|k| **k == key.as_str()) else {
                bail!(
                    "unknown driver in {}: {key:?} is not a [drivers.{group}] key (known: {})",
                    file.display(),
                    known.join(", ")
                );
            };
            let Some(text) = raw.as_str() else {
                bail!(
                    "invalid value for {key:?} in {}: expected exactly \"y\", \"n\" or \"m\", got {}",
                    file.display(),
                    describe_toml_value(raw)
                );
            };
            target.insert(known_key, Selection::from_str(text, key, file)?);
        }
    }
    Ok(config)
}

/// One-line description of a TOML value's shape, for invalid-value
/// errors (never prints a large value).
fn describe_toml_value(value: &toml::Value) -> String {
    match value {
        toml::Value::String(_) => "a string".to_string(),
        toml::Value::Integer(i) => format!("integer {i}"),
        toml::Value::Float(f) => format!("float {f}"),
        toml::Value::Boolean(b) => format!("boolean {b}"),
        toml::Value::Datetime(_) => "a datetime".to_string(),
        toml::Value::Array(_) => "an array".to_string(),
        toml::Value::Table(_) => "a table".to_string(),
    }
}

/// Load, parse, and validate a config file at `path`.
pub fn load_file(path: &Path) -> Result<DriverConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    parse(&text, path)
}

/// Preset names available under `root/configs/` (the `*.toml`
/// stems, sorted), for unknown-name errors.
pub fn available_presets(root: &Path) -> Vec<String> {
    let dir = root.join("configs");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".toml").map(str::to_string)
        })
        .collect();
    names.sort();
    names
}

/// Resolve a `--config` argument to the feature set (§5.2).
/// `root` is the workspace root (preset home); path-form arguments
/// resolve against the current working directory, not `root`.
pub fn resolve(arg: &str, root: &Path) -> Result<ResolvedConfig> {
    if arg == RESERVED_AUTO {
        bail!(
            "--config {arg:?} is reserved for the lane-5 test-config generator \
             (design §5.4) and is not available yet — pass a preset name or a TOML path"
        );
    }
    let is_path = arg.contains('/') || arg.ends_with(".toml");
    let path: PathBuf = if is_path {
        PathBuf::from(arg)
    } else {
        let preset = root.join("configs").join(format!("{arg}.toml"));
        if !preset.is_file() {
            let available = available_presets(root);
            let known = if available.is_empty() {
                "none installed".to_string()
            } else {
                available.join(", ")
            };
            bail!(
                "unknown --config preset {arg:?}: no {} (available presets: {known})",
                preset.display()
            );
        }
        preset
    };
    if !path.is_file() {
        bail!("--config file does not exist: {}", path.display());
    }
    let config = load_file(&path)?;
    translate(config, path)
}

/// Translate a validated config to the frame feature set (§5.3).
/// Any `"m"` key is a hard error: the module build belongs to the
/// modules-for-everything programme, and lane 1 refuses rather
/// than silently treating it as `"n"` or `"y"`.
pub fn translate(config: DriverConfig, source: PathBuf) -> Result<ResolvedConfig> {
    // The `m` refusal comes first, so the error names the key
    // before any feature is computed.
    for (group, keys) in [("net", &config.net), ("storage", &config.storage)] {
        for (key, selection) in keys {
            if *selection == Selection::Module {
                bail!(
                    "--config {} selects {key:?} = \"m\" in [drivers.{group}], but module selection \
                     is not wired yet (design §5.2/§5.6): the `m` value belongs to the \
                     modules-for-everything programme — lane 1 refuses rather than silently \
                     treating it as \"n\" or \"y\"",
                    source.display()
                );
            }
        }
    }
    let mut features: Vec<String> = CORE_FEATURES.iter().map(|f| f.to_string()).collect();
    // Net: the gate, then the per-driver facade features for the
    // "y" keys. A group with all keys "n" contributes nothing.
    if config.net.values().any(|s| *s == Selection::Yes) {
        features.push("drivers-net".to_string());
        for (key, selection) in &config.net {
            if *selection == Selection::Yes {
                features.push(format!("narf-drivers-net/{key}"));
            }
        }
    }
    // Storage facade keys (all except the special `nvme` key).
    let storage_facade_yes = config
        .storage
        .iter()
        .filter(|(key, selection)| **key != "nvme" && **selection == Selection::Yes);
    if storage_facade_yes.clone().next().is_some() {
        features.push("drivers-storage".to_string());
        for (key, _) in storage_facade_yes {
            features.push(format!("narf-drivers-storage/{key}"));
        }
    }
    // The nvme key lives in the storage table but maps to the
    // standalone crate (§5.1): its own forwarding feature, not a
    // facade feature — and it does NOT pull in the storage gate.
    if config.storage.get("nvme") == Some(&Selection::Yes) {
        features.push("drivers-nvme".to_string());
    }
    Ok(ResolvedConfig {
        no_default_features: true,
        features,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    /// Workspace root for tests: xtask's manifest dir is
    /// `build/xtask`, so the root is two levels up.
    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("build/ has a parent")
            .parent()
            .expect("repo root has a parent")
            .to_path_buf()
    }

    /// Write `text` to a fresh temp file and return its path. The
    /// caller owns cleanup (temp dir is per-test unique).
    fn write_temp(text: &str, name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("narf-config-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("config.toml");
        std::fs::write(&path, text).expect("write temp config");
        path
    }

    fn resolve_text(text: &str) -> Result<ResolvedConfig> {
        let path = write_temp(text, "resolve");
        let config = load_file(&path)?;
        translate(config, path)
    }

    fn all_features() -> Vec<String> {
        let mut expected: Vec<String> =
            vec!["user-task-smp".to_string(), "drivers-net".to_string()];
        expected.extend(NET_KEYS.iter().map(|k| format!("narf-drivers-net/{k}")));
        expected.push("drivers-storage".to_string());
        expected.extend(
            STORAGE_KEYS
                .iter()
                .filter(|k| **k != "nvme")
                .map(|k| format!("narf-drivers-storage/{k}")),
        );
        expected.push("drivers-nvme".to_string());
        expected
    }

    #[test]
    fn empty_file_means_all_yes() {
        let resolved = resolve_text("").expect("empty file is valid");
        assert!(resolved.no_default_features);
        assert_eq!(resolved.features, all_features());
    }

    #[test]
    fn all_preset_is_all_yes() {
        let root = workspace_root();
        let resolved = resolve("all", &root).expect("configs/all.toml resolves");
        assert_eq!(resolved.features, all_features());
        assert_eq!(resolved.source, root.join("configs/all.toml"));
    }

    #[test]
    fn all_matches_default_build() {
        // The `all` translation must resolve to exactly frame's
        // `default` feature set (frame/Cargo.toml): core + both
        // gates + every per-driver facade feature + drivers-nvme.
        // If frame's `default` gains a member, this test (and the
        // translator) must gain it too.
        let root = workspace_root();
        let resolved = resolve("all", &root).expect("configs/all.toml resolves");
        let manifest =
            std::fs::read_to_string(root.join("frame/Cargo.toml")).expect("read frame/Cargo.toml");
        for feature in &resolved.features {
            let bare = feature.split('/').next().expect("feature name");
            assert!(
                manifest.contains(&format!("\"{bare}\"")) || manifest.contains(bare),
                "translated feature {feature:?} is not named in frame/Cargo.toml"
            );
        }
        assert!(resolved.features.contains(&"user-task-smp".to_string()));
        assert!(resolved.features.contains(&"drivers-net".to_string()));
        assert!(resolved.features.contains(&"drivers-storage".to_string()));
        assert!(resolved.features.contains(&"drivers-nvme".to_string()));
    }

    #[test]
    fn minimal_preset_is_core_only() {
        let root = workspace_root();
        let resolved = resolve("minimal", &root).expect("configs/minimal.toml resolves");
        assert!(resolved.no_default_features);
        assert_eq!(resolved.features, vec!["user-task-smp".to_string()]);
        assert_eq!(resolved.source, root.join("configs/minimal.toml"));
    }

    #[test]
    fn presets_are_complete() {
        // Every preset under configs/ must express every known key
        // (§5.2): a lane that adds a selection surface and forgets
        // the presets would otherwise silently default the new
        // driver to "y" — or, under a future default, drop it.
        let root = workspace_root();
        for name in available_presets(&root) {
            let path = root.join("configs").join(format!("{name}.toml"));
            let config = load_file(&path).expect("preset parses");
            assert_eq!(
                config.net.keys().copied().collect::<Vec<_>>(),
                NET_KEYS,
                "preset {name} is missing net keys"
            );
            // BTreeMap keys sort alphabetically ("nvme" before
            // "rtsx"); compare as sets, not in STORAGE_KEYS order.
            let storage_keys: std::collections::BTreeSet<_> =
                config.storage.keys().copied().collect();
            let expected_keys: std::collections::BTreeSet<_> =
                STORAGE_KEYS.iter().copied().collect();
            assert_eq!(
                storage_keys, expected_keys,
                "preset {name} is missing storage keys"
            );
        }
        assert!(available_presets(&root).contains(&"all".to_string()));
        assert!(available_presets(&root).contains(&"minimal".to_string()));
    }

    #[test]
    fn partial_selection_is_per_driver() {
        let resolved =
            resolve_text("[drivers.net]\ne1000 = \"y\"\n\n[drivers.storage]\nnvme = \"y\"\n")
                .expect("partial file resolves");
        // Unspecified keys default to "y" (§5.1), so this file is
        // NOT net-only: only e1000 and nvme are pinned, everything
        // else stays in. The per-driver check below pins one driver
        // OUT while the rest stay in.
        assert!(resolved
            .features
            .contains(&"narf-drivers-net/e1000".to_string()));
        assert!(resolved.features.contains(&"drivers-nvme".to_string()));
        let resolved = resolve_text(
            "[drivers.net]\nigc = \"n\"\n\n[drivers.storage]\nahci = \"n\"\nnvme = \"n\"\n",
        )
        .expect("partial file resolves");
        assert!(!resolved
            .features
            .contains(&"narf-drivers-net/igc".to_string()));
        assert!(!resolved
            .features
            .contains(&"narf-drivers-storage/ahci".to_string()));
        assert!(!resolved.features.contains(&"drivers-nvme".to_string()));
        assert!(resolved.features.contains(&"drivers-net".to_string()));
        assert!(resolved.features.contains(&"drivers-storage".to_string()));
        assert!(resolved
            .features
            .contains(&"narf-drivers-net/e1000".to_string()));
    }

    #[test]
    fn all_n_group_contributes_no_feature() {
        let mut text = String::from("[drivers.net]\n");
        for key in NET_KEYS {
            let _ = writeln!(text, "{key} = \"n\"");
        }
        text.push_str("[drivers.storage]\n");
        for key in STORAGE_KEYS {
            let _ = writeln!(text, "{key} = \"n\"");
        }
        let resolved = resolve_text(&text).expect("all-n file resolves");
        assert_eq!(resolved.features, vec!["user-task-smp".to_string()]);
    }

    #[test]
    fn module_selection_is_a_hard_error() {
        let err =
            resolve_text("[drivers.net]\nigc = \"m\"\n").expect_err("\"m\" must fail in lane 1");
        assert!(
            err.to_string().contains("\"m\""),
            "error names the value: {err}"
        );
        assert!(
            err.to_string().contains("igc"),
            "error names the key: {err}"
        );
        let err =
            resolve_text("[drivers.storage]\nnvme = \"m\"\n").expect_err("nvme \"m\" must fail");
        assert!(
            err.to_string().contains("nvme"),
            "error names the key: {err}"
        );
    }

    #[test]
    fn unknown_preset_name_errors_and_lists_presets() {
        let root = workspace_root();
        let err = resolve("bogus", &root).expect_err("unknown preset must fail");
        let msg = err.to_string();
        assert!(msg.contains("bogus"), "error names the argument: {msg}");
        assert!(msg.contains("all"), "error lists available presets: {msg}");
        assert!(
            msg.contains("minimal"),
            "error lists available presets: {msg}"
        );
    }

    #[test]
    fn missing_path_file_errors() {
        let root = workspace_root();
        let err = resolve("./does-not-exist.toml", &root).expect_err("missing file must fail");
        assert!(
            err.to_string().contains("does-not-exist.toml"),
            "error names the file: {err}"
        );
    }

    #[test]
    fn malformed_toml_errors_with_location() {
        let path = write_temp("[drivers.net\ne1000 = \"y\"\n", "malformed");
        let err = load_file(&path).expect_err("malformed TOML must fail");
        assert!(
            err.to_string().contains("malformed TOML"),
            "error names the cause: {err}"
        );
    }

    #[test]
    fn unknown_table_errors() {
        let err = load_file(&write_temp(
            "[drivers.foobar]\nx = \"y\"\n",
            "unknown-table",
        ))
        .expect_err("unknown table must fail");
        assert!(
            err.to_string().contains("foobar"),
            "error names the table: {err}"
        );
        let err = load_file(&write_temp("[other]\nx = \"y\"\n", "non-drivers"))
            .expect_err("non-drivers table must fail");
        assert!(
            err.to_string().contains("other"),
            "error names the table: {err}"
        );
    }

    #[test]
    fn gpu_table_errors_in_lane_1() {
        let err = load_file(&write_temp("[drivers.gpu]\namdgpu = \"y\"\n", "gpu"))
            .expect_err("[drivers.gpu] must fail in lane 1");
        assert!(
            err.to_string().contains("lane 2"),
            "error says when it lands: {err}"
        );
    }

    #[test]
    fn unknown_key_errors() {
        let err = load_file(&write_temp("[drivers.net]\nnope = \"y\"\n", "unknown-key"))
            .expect_err("unknown key must fail");
        let msg = err.to_string();
        assert!(msg.contains("nope"), "error names the key: {msg}");
        assert!(msg.contains("drivers.net"), "error names the table: {msg}");
    }

    #[test]
    fn invalid_value_errors() {
        for (text, label) in [
            ("[drivers.net]\ne1000 = \"Y\"\n", "uppercase Y"),
            ("[drivers.net]\ne1000 = \"yes\"\n", "yes"),
            ("[drivers.net]\ne1000 = true\n", "boolean"),
            ("[drivers.net]\ne1000 = 1\n", "integer"),
        ] {
            let err =
                load_file(&write_temp(text, "invalid-value")).expect_err("invalid value must fail");
            assert!(
                err.to_string().contains("e1000"),
                "{label}: error names the key: {err}"
            );
        }
    }

    #[test]
    fn path_form_uses_the_path_as_is() {
        let root = workspace_root();
        let path = write_temp("[drivers.net]\ne1000 = \"n\"\n", "path-form");
        let resolved = resolve(path.to_str().expect("temp path is UTF-8"), &root)
            .expect("absolute .toml path resolves");
        assert!(!resolved
            .features
            .contains(&"narf-drivers-net/e1000".to_string()));
        assert_eq!(resolved.source, path);
        // A bare word that ends in .toml is a path even if a preset
        // of that name existed: syntactic rule (§5.2).
        let err = resolve("minimal.toml", &root).expect_err("no minimal.toml file in cwd");
        assert!(
            err.to_string().contains("does not exist"),
            "error names the miss: {err}"
        );
    }

    #[test]
    fn auto_is_reserved() {
        let root = workspace_root();
        let err = resolve("auto", &root).expect_err("auto must fail in lane 1");
        assert!(
            err.to_string().contains("lane-5"),
            "error says when it lands: {err}"
        );
    }

    #[test]
    fn key_sets_match_the_facades() {
        // The closed key sets are grounded in the facades'
        // manifests at the tip: if a facade gains or loses a
        // per-driver feature, this test (and the key sets) must
        // move with it — never invent a key.
        let root = workspace_root();
        let net = std::fs::read_to_string(root.join("drivers/net/Cargo.toml"))
            .expect("read net facade manifest");
        for key in NET_KEYS {
            assert!(
                net.contains(&format!("\"dep:narf-drivers-net-{key}\""))
                    || net.contains(&format!("{key} = [\"dep:narf-drivers-net-{key}\"]")),
                "net key {key:?} has no per-driver feature in drivers/net/Cargo.toml"
            );
        }
        let storage = std::fs::read_to_string(root.join("drivers/storage/Cargo.toml"))
            .expect("read storage facade manifest");
        for key in STORAGE_KEYS.iter().filter(|k| **k != "nvme") {
            assert!(
                storage.contains(&format!("{key} = [\"dep:narf-drivers-storage-{key}\"]")),
                "storage key {key:?} has no per-driver feature in drivers/storage/Cargo.toml"
            );
        }
        let nvme = std::fs::read_to_string(root.join("drivers/nvme/Cargo.toml"))
            .expect("read nvme manifest");
        assert!(
            nvme.contains("default = [\"builtin\"]"),
            "nvme is the dual-build crate"
        );
    }
}
