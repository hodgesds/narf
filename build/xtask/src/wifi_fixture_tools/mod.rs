//! Native host metadata tools. Structural replays never grant firmware/board authority.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

mod board;
mod formats;
mod realtek;
mod render;
#[cfg(test)]
mod tests;

const MAX: u64 = 32 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 16384;
const MAX_METADATA: usize = 8 * 1024 * 1024;

#[derive(clap::Args)]
pub(crate) struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(clap::Subcommand)]
enum Command {
    /// Verify pinned local raw sources, factual JSON, metadata and Rust fixture tables.
    Check(FixtureArgs),
    /// Recreate fixture artifacts from the same explicit source pins; never update pins.
    Write(FixtureArgs),
    /// Extract one explicitly identified raw file into a new output directory.
    Extract(ExtractArgs),
    /// Encode explicit deployment JSON as unsigned NBSP v1 (sign separately).
    BoardManifest(board::Args),
}
#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
enum Vendor {
    Intel,
    Mediatek,
    Qualcomm,
    Broadcom,
    Realtek,
}
impl Vendor {
    fn name(self) -> &'static str {
        match self {
            Self::Intel => "intel",
            Self::Mediatek => "mediatek",
            Self::Qualcomm => "qualcomm",
            Self::Broadcom => "broadcom",
            Self::Realtek => "realtek",
        }
    }
}
#[derive(clap::Args)]
struct FixtureArgs {
    #[arg(long, value_enum, value_delimiter = ',')]
    vendor: Vec<Vendor>,
    /// Local raw/zstd firmware tree, never modified.
    #[arg(long, default_value = "/lib/firmware")]
    source: PathBuf,
    /// Explicit fixture/provenance tree; defaults to the repository fixture directory.
    #[arg(long)]
    fixtures: Option<PathBuf>,
}
#[derive(clap::Args)]
struct ExtractArgs {
    #[arg(long, value_enum)]
    vendor: Vendor,
    /// Structural format key, e.g. cc_77, mt7921_patch or qca6174_board2.
    #[arg(long)]
    key: String,
    /// Canonical vendor source name recorded in provenance.
    #[arg(long)]
    name: String,
    #[arg(long)]
    input: PathBuf,
    /// Complete decompressed source SHA256, supplied explicitly.
    #[arg(long)]
    sha256: String,
    /// New directory for metadata.bin and facts.json; must not already exist.
    #[arg(long)]
    output: PathBuf,
}
pub(crate) fn run(args: Args, root: &Path) -> Result<()> {
    match args.command {
        Command::Check(args) => fixtures(args, root, false),
        Command::Write(args) => fixtures(args, root, true),
        Command::BoardManifest(args) => board::run(args),
        Command::Extract(args) => {
            safe_name(&args.name)?;
            safe_name(&args.key)?;
            ensure!(!args.key.contains('/'), "key must be a filename component");
            ensure!(!args.output.exists(), "output directory already exists");
            let raw = super::read_firmware_payload(&args.input, MAX)?;
            ensure!(
                hex(&Sha256::digest(&raw)) == args.sha256,
                "source SHA256 differs from explicit pin"
            );
            let extracted = extract(args.vendor, &args.key, &args.name, &raw)?;
            let facts = json!({"source":args.name,"source_sha256":args.sha256,
                "vendor":args.vendor.name(),"key":args.key,
                "source_size":raw.len(),"metadata_sha256":hex(&Sha256::digest(&extracted.metadata)),
                "metadata_size":extracted.metadata.len(),"fragments":extracted.fragments,"facts":extracted.facts,
                "scope":"structural metadata only; never load into hardware"});
            fs::create_dir(&args.output)?;
            fs::write(args.output.join("metadata.bin"), extracted.metadata)?;
            fs::write(args.output.join("facts.json"), json_bytes(&facts)?)?;
            Ok(())
        }
    }
}

struct Extracted {
    metadata: Vec<u8>,
    fragments: Vec<(usize, usize, usize)>,
    facts: Value,
}
fn extract(vendor: Vendor, key: &str, name: &str, raw: &[u8]) -> Result<Extracted> {
    match vendor {
        Vendor::Intel => formats::intel(raw),
        Vendor::Mediatek => formats::mediatek(raw, key.ends_with("patch")),
        Vendor::Qualcomm => formats::qualcomm(raw, key),
        Vendor::Broadcom => formats::broadcom(raw),
        Vendor::Realtek => {
            let facts = realtek::extract(raw, name)?;
            let mut ranges = Vec::new();
            for part in array(&facts, "fragments")? {
                ranges.push((uint(part, "offset")?, unhex(string(part, "hex")?)?));
            }
            let mut metadata = Vec::new();
            let mut fragments = Vec::new();
            for (offset, bytes) in ranges {
                fragments.push((offset, metadata.len(), bytes.len()));
                metadata.extend(bytes);
            }
            Ok(Extracted {
                metadata,
                fragments,
                facts,
            })
        }
    }
}

fn fixtures(args: FixtureArgs, root: &Path, write: bool) -> Result<()> {
    let directory = args
        .fixtures
        .unwrap_or_else(|| root.join("verification/data/wifi-firmware"))
        .canonicalize()
        .context("resolving fixture tree")?;
    let source_root = args
        .source
        .canonicalize()
        .context("resolving source tree")?;
    let vendors = if args.vendor.is_empty() {
        vec![
            Vendor::Intel,
            Vendor::Mediatek,
            Vendor::Qualcomm,
            Vendor::Broadcom,
            Vendor::Realtek,
        ]
    } else {
        args.vendor
    };
    // Validate every selected source/product before any write. Optional vendor
    // files and existing untracked metadata are never removed or staged.
    let mut products = BTreeMap::new();
    let mut metadata_total = 0usize;
    for vendor in vendors {
        let target = directory
            .join(vendor.name())
            .canonicalize()
            .context("resolving vendor fixture directory")?;
        ensure!(
            target.starts_with(&directory) && target.is_dir(),
            "vendor fixture directory escapes fixture tree"
        );
        let manifest_name = if vendor == Vendor::Realtek {
            "manifest.json"
        } else {
            "provenance.json"
        };
        let manifest_path = target.join(manifest_name);
        validate_output(&directory, &source_root, &manifest_path, write)?;
        let mut manifest: Value =
            serde_json::from_slice(&super::read_firmware_payload(&manifest_path, MAX)?)?;
        let images = if vendor == Vendor::Broadcom {
            vec![manifest.clone()]
        } else {
            array(
                &manifest,
                if vendor == Vendor::Realtek {
                    "sources"
                } else {
                    "images"
                },
            )?
            .clone()
        };
        ensure!(
            !images.is_empty() && images.len() <= 16,
            "invalid source inventory count"
        );
        let mut seen = std::collections::BTreeSet::new();
        let mut updated = Vec::new();
        let mut extracted = Vec::new();
        for mut image in images {
            let (name, pin, size) = if vendor == Vendor::Realtek {
                (
                    string(&image, "name")?,
                    string(&image, "sha256")?,
                    uint(&image, "length")?,
                )
            } else {
                (
                    string(&image, "source")?,
                    string(&image, "source_sha256")?,
                    uint(&image, "source_size")?,
                )
            };
            let key = key(vendor, name)?.to_owned();
            ensure!(seen.insert(key.clone()), "duplicate pinned source/key");
            let raw = read_source(&args.source, name)?;
            ensure!(
                raw.len() == size && hex(&Sha256::digest(&raw)) == pin,
                "unpinned input: {name}"
            );
            let value =
                extract(vendor, &key, name, &raw).with_context(|| format!("decoding {name}"))?;
            metadata_total = metadata_total
                .checked_add(value.metadata.len())
                .context("aggregate metadata overflow")?;
            ensure!(
                metadata_total <= 2 * MAX_METADATA,
                "aggregate metadata exceeds fixture-tool budget"
            );
            if vendor == Vendor::Realtek {
                ensure!(
                    write || value.facts == image,
                    "Realtek metadata differs: {name}"
                );
                image = value.facts.clone();
            } else {
                let digest = hex(&Sha256::digest(&value.metadata));
                ensure!(
                    write
                        || (image["facts"] == value.facts
                            && image["metadata_size"] == json!(value.metadata.len())
                            && image["metadata_sha256"] == digest),
                    "metadata facts/hash differ: {name}"
                );
                image["facts"] = value.facts.clone();
                image["metadata_size"] = json!(value.metadata.len());
                image["metadata_sha256"] = json!(digest);
                products.insert(
                    target.join(format!("{key}.metadata.bin")),
                    value.metadata.clone(),
                );
            }
            extracted.push((key, image.clone(), value));
            updated.push(image);
        }
        // Preserve optional/unavailable input inventories. Their appearance is
        // not a reason to delete files or synthesize unqualified new profiles.
        if let Some(aliases) = manifest.get("aliases").and_then(Value::as_object) {
            for (alias, canonical) in aliases {
                let canonical = canonical.as_str().context("invalid alias target")?;
                ensure!(
                    read_source(&args.source, alias)? == read_source(&args.source, canonical)?,
                    "alias differs: {alias}"
                );
            }
        }
        if vendor == Vendor::Broadcom {
            manifest = updated.remove(0);
        } else {
            manifest[if vendor == Vendor::Realtek {
                "sources"
            } else {
                "images"
            }] = json!(updated);
        }
        for (name, body) in render::products(vendor, &extracted)? {
            products.insert(target.join(name), body.into_bytes());
        }
        if write {
            if vendor != Vendor::Realtek {
                manifest["decoder"] = json!("independent native Rust Wi-Fi metadata decoder");
            }
            products.insert(target.join(manifest_name), json_bytes(&manifest)?);
        }
    }
    for (path, bytes) in &products {
        validate_output(&directory, &source_root, path, write)?;
        if !write {
            let old = super::read_firmware_payload(path, MAX)
                .with_context(|| format!("missing fixture {}", path.display()))?;
            let equal = if path.extension().is_some_and(|x| x == "rs") {
                rust_body(&old)? == rust_body(bytes)?
            } else {
                old == *bytes
            };
            ensure!(equal, "stale fixture {}", path.display());
        }
    }
    if write {
        for (path, bytes) in &products {
            write_product(path, bytes)?;
        }
    }
    println!(
        "{} {} Wi-Fi fixture artifacts",
        if write { "wrote" } else { "verified" },
        products.len()
    );
    Ok(())
}

fn validate_output(directory: &Path, source: &Path, path: &Path, write: bool) -> Result<()> {
    let parent = path
        .parent()
        .context("fixture output has no parent")?
        .canonicalize()?;
    ensure!(
        parent.starts_with(directory),
        "fixture output escapes selected tree"
    );
    ensure!(
        !write || !parent.starts_with(source),
        "fixture output would modify the raw source tree"
    );
    match path.symlink_metadata() {
        Ok(metadata) => ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "fixture product must be a regular non-symlink file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
fn write_product(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{
        io::Write,
        sync::atomic::{AtomicUsize, Ordering},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let temp = path.with_file_name(format!(
        ".narf-wifi-fixture-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_source(root: &Path, name: &str) -> Result<Vec<u8>> {
    safe_name(name)?;
    let root = root
        .canonicalize()
        .context("resolving firmware source tree")?;
    let mut names = vec![name.to_owned()];
    if !name.contains('/') {
        names.push(format!("intel/iwlwifi/{name}"));
        names.push(format!("iwlwifi/{name}"));
    }
    for name in names {
        for suffix in ["", ".zst"] {
            let path = root.join(format!("{name}{suffix}"));
            if path.symlink_metadata().is_ok() {
                let path = super::firmware_import_source(&root, &path)?;
                return super::read_firmware_payload(&path, MAX);
            }
        }
    }
    bail!("required pinned source unavailable: {name}")
}
fn key(vendor: Vendor, name: &str) -> Result<&str> {
    if vendor == Vendor::Realtek {
        return Ok(name);
    }
    ensure!(
        match vendor {
            Vendor::Intel => name.starts_with("iwlwifi-") && !name.contains('/'),
            Vendor::Mediatek => name.starts_with("mediatek/"),
            Vendor::Qualcomm => name.starts_with("ath10k/") || name.starts_with("ath11k/"),
            Vendor::Broadcom => name == "brcm/brcmfmac43602-pcie.bin",
            Vendor::Realtek => unreachable!(),
        },
        "source belongs to a different fixture family"
    );
    let pairs = &[
        ("iwlwifi-cc-a0-77.ucode", "cc_77"),
        ("iwlwifi-ty-a0-gf-a0-89.ucode", "ty_89"),
        ("iwlwifi-so-a0-gf-a0-89.ucode", "so_gf_89"),
        ("iwlwifi-so-a0-gf4-a0-89.ucode", "so_gf4_89"),
        ("iwlwifi-bz-b0-gf-a0-100.ucode", "bz_100"),
        ("iwlwifi-sc-a0-wh-b0-c103.ucode", "sc_103"),
        ("iwlwifi-sc-a0-fm-c0-c103.ucode", "sc_fm_103"),
        (
            "mediatek/WIFI_MT7961_patch_mcu_1a_2_hdr.bin",
            "mt7920_patch",
        ),
        ("mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin", "mt7921_patch"),
        ("mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin", "mt7922_patch"),
        ("mediatek/WIFI_RAM_CODE_MT7961_1a.bin", "mt7920_ram"),
        ("mediatek/WIFI_RAM_CODE_MT7961_1.bin", "mt7921_ram"),
        ("mediatek/WIFI_RAM_CODE_MT7922_1.bin", "mt7922_ram"),
        ("ath10k/QCA988X/hw2.0/firmware-5.bin", "qca988x_api5"),
        ("ath10k/QCA6174/hw3.0/firmware-6.bin", "qca6174_api6"),
        ("ath10k/QCA6174/hw3.0/board-2.bin", "qca6174_board2"),
        ("ath11k/QCA6390/hw2.0/board-2.bin", "qca6390_board2"),
        ("ath11k/WCN6855/hw2.0/board-2.bin", "wcn6855_board2"),
        ("ath11k/QCA6390/hw2.0/amss.bin", "qca6390_amss"),
        ("ath11k/QCA6390/hw2.0/m3.bin", "qca6390_m3"),
        ("ath11k/WCN6855/hw2.0/amss.bin", "wcn6855_amss"),
        ("ath11k/WCN6855/hw2.0/m3.bin", "wcn6855_m3"),
        ("brcm/brcmfmac43602-pcie.bin", "bcm43602"),
    ];
    pairs
        .iter()
        .find_map(|(source, key)| (*source == name).then_some(*key))
        .context("unrecognized fixture source; use explicit extract --key")
}
fn safe_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|x| x.is_ascii_alphanumeric() || b"/_.-".contains(&x))
            && !name.contains('\\')
            && Path::new(name)
                .components()
                .all(|x| matches!(x, Component::Normal(_)))
            && name
                .split('/')
                .all(|x| !x.is_empty() && x != "." && x != ".."),
        "invalid relative source/key"
    );
    Ok(())
}
fn rust_body(bytes: &[u8]) -> Result<String> {
    // Parse real Rust tokens: preserve token boundaries and literal bytes,
    // including char/raw strings. Ordinary comments/formatting carry no data.
    let text = std::str::from_utf8(bytes).context("fixture Rust is not UTF-8")?;
    let tokens = text
        .parse::<proc_macro2::TokenStream>()
        .map_err(|error| anyhow::anyhow!("invalid fixture Rust tokens: {error}"))?;
    Ok(tokens.to_string())
}
fn json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    ensure!(value.len() % 2 == 0 && value.is_ascii(), "invalid hex");
    (0..value.len())
        .step_by(2)
        .map(|x| u8::from_str_radix(&value[x..x + 2], 16).context("invalid hex"))
        .collect()
}
fn uint(value: &Value, key: &str) -> Result<usize> {
    usize::try_from(
        value[key]
            .as_u64()
            .with_context(|| format!("missing integer {key}"))?,
    )
    .context("integer too large")
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("missing string {key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .with_context(|| format!("missing array {key}"))
}
fn bytes(raw: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    raw.get(at..at.checked_add(len).context("extent overflow")?)
        .context("truncated metadata field")
}
fn u16le(raw: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(raw, at, 2)?.try_into()?))
}
fn u32le(raw: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(raw, at, 4)?.try_into()?))
}
fn u32be(raw: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(bytes(raw, at, 4)?.try_into()?))
}
fn packed(raw: &[u8], ranges: &[(usize, usize)], facts: Value) -> Result<Extracted> {
    ensure!(ranges.len() <= MAX_FRAGMENTS, "too many metadata fragments");
    let mut metadata = Vec::new();
    let mut fragments = Vec::new();
    let mut end = 0;
    for &(at, len) in ranges {
        ensure!(at >= end, "overlapping metadata ranges");
        if len == 0 {
            continue;
        }
        ensure!(
            len <= MAX_METADATA - metadata.len(),
            "metadata exceeds fixture-tool budget"
        );
        fragments.push((at, metadata.len(), len));
        metadata.extend_from_slice(bytes(raw, at, len)?);
        end = at + len;
    }
    Ok(Extracted {
        metadata,
        fragments,
        facts,
    })
}
