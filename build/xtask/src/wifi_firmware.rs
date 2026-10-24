//! Host payload inventory. This does not authorize firmware or qualify boards.
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CATALOG: &str = include_str!("../../../verification/data/wifi-firmware/profiles.json");
const MAX_PAYLOAD: u64 = 16 * 1024 * 1024;

#[derive(clap::Args)]
pub struct Args {
    /// Installed raw or zstd-compressed vendor firmware tree (never modified).
    #[arg(long, default_value = "/lib/firmware")]
    source: PathBuf,
    /// Audit only these exact catalog profile IDs; repeat or separate by comma.
    #[arg(long, value_delimiter = ',')]
    profile: Vec<String>,
    /// Create a new JSON inventory outside the source tree, including payload hashes.
    #[arg(long)]
    report: Option<PathBuf>,
    /// Fail if any selected profile lacks a required fixed-name payload.
    /// Board selection, signed policy and conditional PNVM remain manual gates.
    #[arg(long)]
    require_assets: bool,
    #[arg(long, default_value_t = MAX_PAYLOAD)]
    max_payload_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema_version: u32,
    profiles: Vec<Profile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    id: String,
    family: String,
    assets: Vec<Asset>,
    requirements: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    role: String,
    required: bool,
    /// Ordered canonical registry keys. Existing invalid input stops fallback.
    candidates: Vec<String>,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    source: PathBuf,
    scope: &'static str,
    profiles: Vec<ProfileReport>,
}

#[derive(Serialize)]
struct ProfileReport {
    id: String,
    family: String,
    assets: Vec<AssetReport>,
    external_requirements: Vec<String>,
}

#[derive(Serialize)]
struct AssetReport {
    role: String,
    required: bool,
    candidates: Vec<String>,
    payload: Option<Payload>,
}

#[derive(Serialize)]
struct Payload {
    registry_key: String,
    source_alias: String,
    bytes: usize,
    sha256: String,
}

fn safe_key(key: &str) -> bool {
    !key.is_empty()
        && !key.contains('\\')
        && key
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && Path::new(key)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

fn catalog() -> Result<Catalog> {
    let catalog: Catalog = serde_json::from_str(CATALOG)?;
    if catalog.schema_version != 1 || catalog.profiles.is_empty() {
        bail!("unsupported or empty Wi-Fi firmware catalog");
    }
    let mut ids = BTreeSet::new();
    for profile in &catalog.profiles {
        if profile.id.is_empty() || !ids.insert(&profile.id) || profile.requirements.is_empty() {
            bail!("invalid profile {}", profile.id);
        }
        for asset in &profile.assets {
            if asset.candidates.is_empty() || !asset.candidates.iter().all(|key| safe_key(key)) {
                bail!("invalid firmware keys in {}", profile.id);
            }
        }
    }
    Ok(catalog)
}

fn resolve(source: &Path, asset: &Asset, max_bytes: u64) -> Result<Option<Payload>> {
    for key in &asset.candidates {
        if !safe_key(key) {
            bail!("unsafe firmware key {key:?}");
        }
        for relative in super::firmware_source_candidates(Path::new(key)) {
            let relative = relative.to_str().context("firmware key is not UTF-8")?;
            let path = source.join(relative);
            // A dangling link or an unreadable existing candidate is an
            // input error, never permission to choose an older image.
            match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
                Ok(_) => {}
            }
            let resolved = path
                .canonicalize()
                .with_context(|| format!("resolving {relative}"))?;
            if !resolved.starts_with(source) || !resolved.is_file() {
                bail!("firmware alias {relative} is not a regular file inside the source tree");
            }
            let bytes = super::read_firmware_payload(&resolved, max_bytes)
                .with_context(|| format!("invalid candidate {relative}; fallback stopped"))?;
            return Ok(Some(Payload {
                registry_key: key.clone(),
                source_alias: relative.to_owned(),
                bytes: bytes.len(),
                sha256: format!("{:x}", Sha256::digest(&bytes)),
            }));
        }
    }
    Ok(None)
}

fn audit(source: &Path, selected: &[String], max_bytes: u64) -> Result<Report> {
    if max_bytes == 0 || max_bytes > MAX_PAYLOAD {
        bail!("--max-payload-bytes must be in 1..={MAX_PAYLOAD}");
    }
    let source = source
        .canonicalize()
        .context("resolving firmware source directory")?;
    if !source.is_dir() {
        bail!("firmware source is not a directory");
    }
    let catalog = catalog()?;
    for id in selected {
        if !catalog.profiles.iter().any(|p| &p.id == id) {
            bail!("unknown Wi-Fi firmware profile {id:?}");
        }
    }
    let mut profiles = Vec::new();
    for profile in catalog.profiles {
        if !selected.is_empty() && !selected.contains(&profile.id) {
            continue;
        }
        let mut assets = Vec::new();
        for asset in profile.assets {
            let payload = resolve(&source, &asset, max_bytes)?;
            assets.push(AssetReport {
                role: asset.role,
                required: asset.required,
                candidates: asset.candidates,
                payload,
            });
        }
        profiles.push(ProfileReport {
            id: profile.id,
            family: profile.family,
            assets,
            external_requirements: profile.requirements,
        });
    }
    Ok(Report {
        schema_version: 1,
        source,
        scope: "Payload availability only; no signature, parser, board or hardware qualification",
        profiles,
    })
}

pub fn run(args: Args) -> Result<()> {
    let report = audit(&args.source, &args.profile, args.max_payload_bytes)?;
    println!("wifi-firmware: {}", report.scope);
    let mut missing = 0;
    for profile in &report.profiles {
        println!("{} ({})", profile.id, profile.family);
        for asset in &profile.assets {
            if let Some(payload) = &asset.payload {
                println!(
                    "  {}: {} ({} bytes; SHA256 {})",
                    asset.role, payload.registry_key, payload.bytes, payload.sha256
                );
            } else {
                missing += usize::from(asset.required);
                println!(
                    "  {}: MISSING{} ({})",
                    asset.role,
                    if asset.required {
                        ""
                    } else {
                        " conditional asset"
                    },
                    asset.candidates.join(", ")
                );
            }
        }
        for requirement in &profile.external_requirements {
            println!("  manual gate: {requirement}");
        }
    }
    if let Some(path) = args.report {
        write_report(&report, &path)?;
    }
    if args.require_assets && missing != 0 {
        bail!("{missing} required payload(s) missing; inventory is not hardware qualification");
    }
    Ok(())
}

fn write_report(report: &Report, path: &Path) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let resolved = parent
        .canonicalize()?
        .join(path.file_name().context("report needs a filename")?);
    if resolved.starts_with(&report.source) {
        bail!("report must be outside the firmware source tree");
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&resolved)
        .with_context(|| format!("creating inventory {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Tree(PathBuf);
    impl Tree {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "narf-wifi-audit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
        fn write(&self, name: &str, bytes: &[u8]) {
            let path = self.0.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn asset(names: &[&str]) -> Asset {
        Asset {
            role: "test".into(),
            required: true,
            candidates: names.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn catalog_covers_all_eleven_families_and_distinct_mtk_pairs() {
        let catalog = catalog().unwrap();
        let families: BTreeSet<_> = catalog.profiles.iter().map(|p| p.family.as_str()).collect();
        assert_eq!(
            families,
            BTreeSet::from([
                "ath9k", "ath10k", "ath11k", "brcmfmac", "cyw43439", "iwlwifi", "mt7921",
                "rtl8xxxu", "rtlwifi", "rtw88", "rtw89"
            ])
        );
        let mt20 = catalog.profiles.iter().find(|p| p.id == "mt7920").unwrap();
        assert!(mt20
            .assets
            .iter()
            .any(|a| a.candidates == ["mediatek/WIFI_RAM_CODE_MT7961_1a.bin"]));
        let ee = catalog
            .profiles
            .iter()
            .find(|p| p.id == "rtl8188ee")
            .unwrap();
        assert_eq!(ee.assets[0].candidates, ["rtlwifi/rtl8188efw.bin"]);
        // Cross-check the retained driver tables, including less common
        // Qualcomm revisions that may be absent from the local installation.
        for (family, source, prefix) in [
            (
                "ath10k",
                include_str!("../../../drivers/wireless/src/ath10k/profile.rs"),
                "",
            ),
            (
                "ath11k",
                include_str!("../../../drivers/wireless/src/ath11k/hw.rs"),
                "ath11k/",
            ),
        ] {
            for directory in source
                .split('"')
                .filter(|s| s.contains("/hw") && !s.contains('\n'))
            {
                let key = format!("{prefix}{directory}/");
                assert!(
                    catalog
                        .profiles
                        .iter()
                        .filter(|p| p.family == family)
                        .flat_map(|p| &p.assets)
                        .flat_map(|a| &a.candidates)
                        .any(|name| name.starts_with(&key)),
                    "uncatalogued profile: {key}"
                );
            }
        }
    }

    #[test]
    fn flat_compressed_intel_alias_has_canonical_key_and_raw_digest() {
        let tree = Tree::new();
        tree.write(
            "iwlwifi-ty-a0-gf-a0-89.ucode.zst",
            &zstd::stream::encode_all(&b"abc"[..], 1).unwrap(),
        );
        let payload = resolve(
            &tree.0,
            &asset(&["iwlwifi/iwlwifi-ty-a0-gf-a0-89.ucode"]),
            3,
        )
        .unwrap()
        .unwrap();
        assert_eq!(payload.registry_key, "iwlwifi/iwlwifi-ty-a0-gf-a0-89.ucode");
        assert_eq!(payload.source_alias, "iwlwifi-ty-a0-gf-a0-89.ucode.zst");
        assert_eq!(payload.bytes, 3);
        assert_eq!(
            payload.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn canonical_intel_source_precedes_a_differing_flat_alias() {
        let tree = Tree::new();
        let key = "iwlwifi/iwlwifi-ty-a0-gf-a0-89.ucode";
        tree.write("iwlwifi-ty-a0-gf-a0-89.ucode", b"flat");
        tree.write(key, b"canonical");
        let payload = resolve(&tree.0, &asset(&[key]), 16).unwrap().unwrap();
        assert_eq!(payload.source_alias, key);
        assert_eq!(payload.bytes, 9);
        tree.write(key, b"");
        assert!(resolve(&tree.0, &asset(&[key]), 16).is_err());
    }

    #[test]
    fn fallback_only_on_absence_not_invalid_existing_input() {
        let tree = Tree::new();
        let candidates = asset(&["new.bin", "old.bin"]);
        tree.write("old.bin", b"old");
        assert_eq!(
            resolve(&tree.0, &candidates, 3)
                .unwrap()
                .unwrap()
                .registry_key,
            "old.bin"
        );
        tree.write("new.bin.zst", b"corrupt");
        assert!(resolve(&tree.0, &candidates, 3).is_err());
        tree.write("new.bin", b"oversized");
        assert!(resolve(&tree.0, &candidates, 3).is_err());
        tree.write("new.bin", b"");
        assert!(resolve(&tree.0, &candidates, 3).is_err());
    }

    #[test]
    fn missing_assets_and_manual_gates_are_preserved() {
        let tree = Tree::new();
        let report = audit(&tree.0, &["cyw43439".into(), "ath9k".into()], MAX_PAYLOAD).unwrap();
        assert_eq!(report.profiles.len(), 2);
        assert!(report
            .profiles
            .iter()
            .all(|p| !p.external_requirements.is_empty()));
        assert!(report
            .profiles
            .iter()
            .flat_map(|p| &p.assets)
            .all(|a| a.payload.is_none()));
        assert!(audit(&tree.0, &["typo".into()], MAX_PAYLOAD).is_err());
        assert!(audit(&tree.0, &[], 0).is_err());
        assert!(audit(&tree.0, &[], MAX_PAYLOAD + 1).is_err());
        for key in [
            "",
            "/absolute",
            "../escape",
            "foo/../bar",
            "foo//bar",
            "./foo",
            "foo\\bar",
        ] {
            assert!(resolve(&tree.0, &asset(&[key]), 3).is_err());
        }
    }

    #[test]
    fn reports_cannot_overwrite_existing_files_or_modify_source_tree() {
        let tree = Tree::new();
        let output = Tree::new();
        let report = audit(&tree.0, &["ath9k".into()], MAX_PAYLOAD).unwrap();
        assert!(write_report(&report, &tree.0.join("report.json")).is_err());
        let path = output.0.join("report.json");
        write_report(&report, &path).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(write_report(&report, &path).is_err());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn aliases_can_select_inside_files_but_cannot_escape_source_tree() {
        use std::os::unix::fs::symlink;
        let tree = Tree::new();
        let outside = Tree::new();
        tree.write("actual.bin", b"abc");
        outside.write("actual.bin", b"abc");
        symlink("actual.bin", tree.0.join("inside.bin")).unwrap();
        symlink(outside.0.join("actual.bin"), tree.0.join("escape.bin")).unwrap();
        symlink("absent.bin", tree.0.join("dangling.bin")).unwrap();
        assert!(resolve(&tree.0, &asset(&["inside.bin"]), 3)
            .unwrap()
            .is_some());
        assert!(resolve(&tree.0, &asset(&["escape.bin", "inside.bin"]), 3).is_err());
        assert!(resolve(&tree.0, &asset(&["dangling.bin", "inside.bin"]), 3).is_err());
    }
}
