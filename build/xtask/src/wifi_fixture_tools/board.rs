//! NBSP v1 encoding of explicit facts. This creates no calibration or signature.
use super::*;
use serde::Deserialize;
use std::io::Write;
#[derive(clap::Args)]
pub(super) struct Args {
    /// Explicit deployment records (JSON array); asset paths are relative to this file.
    #[arg(
        long,
        required_unless_present = "synthetic_fixture",
        conflicts_with = "synthetic_fixture"
    )]
    input: Option<PathBuf>,
    /// Only the existing deliberately synthetic nondeployment regression identities.
    #[arg(long)]
    synthetic_fixture: bool,
    /// Emit Rust literal fixture bytes rather than an unsigned raw NBSP payload.
    #[arg(long)]
    rust: bool,
    /// New output file. Sign raw deployment output with pack-firmware separately.
    #[arg(long)]
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    family: String,
    board: String,
    revisions: Value,
    host: Host,
    #[serde(default)]
    card: Option<[Value; 3]>,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    kind: String,
    address: Value,
    vendor: Value,
    device: Value,
    subsystem_vendor: Value,
    subsystem_device: Value,
    class: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    key: String,
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    fixture: Option<Vec<u8>>,
    #[serde(default)]
    wrapped: bool,
    #[serde(default)]
    signed: Option<bool>,
}

pub(super) fn run(args: Args) -> Result<()> {
    let (records, base) = if let Some(input) = args.input {
        (
            serde_json::from_slice::<Vec<Record>>(&super::super::read_firmware_payload(
                &input,
                1024 * 1024,
            )?)?,
            input.parent().unwrap_or(Path::new(".")).to_path_buf(),
        )
    } else {
        (synthetic()?, PathBuf::from("."))
    };
    let data = encode(&records, &base, args.synthetic_fixture)?;
    let output = if args.rust {
        literal(&data).into_bytes()
    } else {
        data
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .with_context(|| format!("creating {}", args.output.display()))?;
    file.write_all(&output)?;
    println!(
        "wrote {} bytes; NBSP output is not signed or hardware qualification",
        output.len()
    );
    Ok(())
}
fn number(value: &Value, max: u64) -> Result<u64> {
    let number = if let Some(value) = value.as_u64() {
        value
    } else if let Some(value) = value.as_str() {
        if let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)?
        } else {
            value.parse()?
        }
    } else {
        bail!("expected unsigned integer or decimal/hex string")
    };
    ensure!(number <= max, "numeric field exceeds wire bounds");
    Ok(number)
}
fn text(value: &str, len: usize, key: bool) -> Result<Vec<u8>> {
    ensure!(
        !value.is_empty()
            && value.len() < len
            && value
                .bytes()
                .all(|x| x.is_ascii_alphanumeric() || b"_.-".contains(&x) || (key && x == b'/')),
        "invalid board name or asset key"
    );
    if key {
        safe_name(value)?;
    }
    let mut data = vec![0; len];
    data[..value.len()].copy_from_slice(value.as_bytes());
    Ok(data)
}
fn payload(asset: &Asset, base: &Path, fixtures: bool) -> Result<Vec<u8>> {
    let mut data = match (&asset.path, &asset.fixture) {
        (Some(path), None) => {
            super::super::read_firmware_payload(&base.join(path), 16 * 1024 * 1024 + 4096)?
        }
        (None, Some(bytes)) if fixtures && !asset.wrapped => bytes.clone(),
        _ => bail!("supply exactly one raw asset path; inline bytes are synthetic-only"),
    };
    if asset.wrapped {
        ensure!(
            data.len() >= 104 && &data[data.len() - 4..] == b"NRFW",
            "not an NRFW envelope"
        );
        let version = u32le(&data, data.len() - 8)? as usize;
        let end = data
            .len()
            .checked_sub(104)
            .and_then(|x| x.checked_sub(version))
            .context("invalid NRFW extent")?;
        ensure!(end > 0, "empty NRFW payload");
        data.truncate(end);
    }
    Ok(data)
}
fn put16(raw: &mut [u8], at: usize, value: u64) {
    raw[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
}
fn put32(raw: &mut [u8], at: usize, value: u64) {
    raw[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}
fn encode(records: &[Record], base: &Path, fixtures: bool) -> Result<Vec<u8>> {
    ensure!(
        (1..=16).contains(&records.len()),
        "NBSP record count must be 1..16"
    );
    let mut output = vec![0; 16 + 616 * records.len()];
    output[..4].copy_from_slice(b"NBSP");
    put16(&mut output, 4, 1);
    put16(&mut output, 6, 16);
    let length = output.len();
    put32(&mut output, 8, length as u64);
    put16(&mut output, 12, records.len() as u64);
    put16(&mut output, 14, 616);
    let mut selectors = std::collections::BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        let family = match record.family.as_str() {
            "pcie43602" => 1,
            "sdio43439" => 2,
            _ => bail!("unsupported NBSP family"),
        };
        let revisions = number(&record.revisions, u16::MAX.into())?;
        ensure!(revisions != 0, "empty revision mask");
        let card = if let Some(card) = &record.card {
            [
                number(&card[0], 255)?,
                number(&card[1], 65535)?,
                number(&card[2], 65535)?,
            ]
        } else {
            [0; 3]
        };
        let host = &record.host;
        let (kind, address) = match host.kind.as_str() {
            "pci" => {
                let address = host
                    .address
                    .as_array()
                    .context("PCI address must be [segment,bus,device,function]")?;
                ensure!(address.len() == 4, "PCI address length");
                (
                    1,
                    (number(&address[0], 65535)? << 24)
                        | (number(&address[1], 255)? << 16)
                        | (number(&address[2], 31)? << 8)
                        | number(&address[3], 7)?,
                )
            }
            "mmio" if family == 2 => {
                let address = number(&host.address, u64::MAX)?;
                ensure!(address != 0 && address % 4 == 0, "invalid MMIO address");
                (2, address)
            }
            _ => bail!("unsupported host kind/family"),
        };
        let ids = [
            number(&host.vendor, 65535)?,
            number(&host.device, 65535)?,
            number(&host.subsystem_vendor, 65535)?,
            number(&host.subsystem_device, 65535)?,
        ];
        let class = number(&host.class, u32::MAX.into())?;
        if family == 1 {
            ensure!(
                ids[0] == 0x14e4 && (0x43ba..=0x43bc).contains(&ids[1]) && card == [0; 3],
                "invalid BCM43602 selector"
            );
        } else {
            ensure!(
                matches!(card, [1, 0x2d0, 0xa9af] | [1, 0x4b4, 0xbd3d])
                    && (kind != 1 || matches!(class, 0x080500 | 0x080501)),
                "invalid CYW43439 selector"
            );
        }
        ensure!(
            selectors.insert((family, kind, address, ids, class, card)),
            "ambiguous duplicate selector"
        );
        let row = &mut output[16 + index * 616..16 + (index + 1) * 616];
        row[0] = family;
        row[1] = card[0] as u8;
        put16(row, 2, if family == 1 { 43602 } else { 43439 });
        put16(row, 4, revisions);
        row[6] = kind;
        row[8..16].copy_from_slice(&address.to_le_bytes());
        for (index, id) in ids.into_iter().enumerate() {
            put16(row, 16 + index * 2, id);
        }
        put32(row, 24, class);
        put16(row, 28, card[1]);
        put16(row, 30, card[2]);
        row[32..96].copy_from_slice(&text(&record.board, 64, false)?);
        ensure!(
            record.assets.len() == if family == 1 { 2 } else { 3 },
            "incorrect asset count"
        );
        let mut keys = std::collections::BTreeSet::new();
        for (index, asset) in record.assets.iter().enumerate() {
            let role = index + 1;
            let signed = asset.signed.unwrap_or(role != 1);
            ensure!(
                role == 1 || signed,
                "NVRAM/CLM must require verified signer"
            );
            let data = payload(asset, base, fixtures)?;
            ensure!(
                !data.is_empty() && data.len() <= if role == 2 { 64000 } else { 16 * 1024 * 1024 },
                "invalid asset extent"
            );
            if role == 1 {
                ensure!(
                    if family == 1 {
                        data.len() >= 4
                    } else {
                        data.len() <= 4 * 1024 * 1024
                    },
                    "invalid executable extent"
                );
            }
            ensure!(keys.insert(&asset.key), "duplicate asset key");
            let at = 112 + index * 168;
            row[at] = role as u8;
            row[at + 1] = u8::from(signed);
            put32(row, at + 4, data.len() as u64);
            row[at + 8..at + 40].copy_from_slice(&Sha256::digest(&data));
            row[at + 40..at + 168].copy_from_slice(&text(&asset.key, 128, true)?);
        }
    }
    Ok(output)
}
fn synthetic() -> Result<Vec<Record>> {
    Ok(serde_json::from_value(json!([
        {"family":"pcie43602","board":"synthetic-not-a-board","revisions":8,
         "host":{"kind":"pci","address":[65534,250,29,3],"vendor":5348,"device":17338,"subsystem_vendor":4203,"subsystem_device":307,"class":163840},
         "assets":[{"key":"narf-test/brcm/fw","fixture":[68,51,34,17,9,8,7,6]},{"key":"narf-test/brcm/nv","fixture":[98,111,97,114,100,114,101,118,61,49,10]}]},
        {"family":"sdio43439","board":"synthetic-not-a-board","revisions":1,"card":[1,720,43439],
         "host":{"kind":"pci","address":[65534,250,28,2],"vendor":6844,"device":4660,"subsystem_vendor":4660,"subsystem_device":22136,"class":525568},
         "assets":[{"key":"narf-test/brcm/fw","fixture":[68,51,34,17,9,8,7,6]},{"key":"narf-test/brcm/nv","fixture":[98,111,97,114,100,114,101,118,61,49,10]},{"key":"narf-test/brcm/clm","fixture":[105,110,101,114,116,45,99,108,109]}]}
    ]))?)
}
fn literal(data: &[u8]) -> String {
    let mut out=format!("// Native Rust NBSP v1 encoder; synthetic identities are never deployment qualification.\nconst MANIFEST_BYTES: [u8; {}] = [\n",data.len());
    for chunk in data.chunks(16) {
        out.push_str(
            &chunk
                .iter()
                .map(|x| format!("0x{x:02x}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str(",\n");
    }
    out.push_str("];\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_independently_captured_nbsp_fixture() {
        let records = synthetic().unwrap();
        let encoded = encode(&records, Path::new("."), true).unwrap();
        let text = include_str!("../../../../drivers/wireless/src/brcmfmac/provision/golden.rs");
        let expected = text
            .split("= [")
            .nth(1)
            .unwrap()
            .split(']')
            .next()
            .unwrap()
            .split(',')
            .filter_map(|x| x.trim().strip_prefix("0x"))
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(encoded, expected);
        assert!(encode(&records, Path::new("."), false).is_err());
    }
    #[test]
    fn rejects_ambiguous_selectors_unsigned_calibration_and_bounds() {
        let mut records = synthetic().unwrap();
        records[1] = synthetic().unwrap().remove(0);
        assert!(encode(&records, Path::new("."), true).is_err());
        let mut records = synthetic().unwrap();
        records[0].assets[1].signed = Some(false);
        assert!(encode(&records, Path::new("."), true).is_err());
        for field in [json!(-1), json!(65536), json!(1.5), json!("0x10000")] {
            assert!(number(&field, 65535).is_err());
        }
        for name in ["", "../x", "x//y", "/x", "x/./y", "x\\y"] {
            assert!(text(name, 128, true).is_err());
        }
        assert!(encode(&[], Path::new("."), true).is_err());
        assert!(text(&"a".repeat(64), 64, false).is_err());
    }
    #[test]
    fn wrapped_assets_have_checked_envelopes_and_selector_widths() {
        let temp = super::super::tests::Temp::new();
        let path = temp.0.join("wrapped.bin");
        let mut wrapped = b"ABCD".to_vec();
        wrapped.extend_from_slice(&[0; 100]);
        wrapped.extend_from_slice(b"NRFW");
        fs::write(&path, &wrapped).unwrap();
        let asset = Asset {
            key: "brcm/test.bin".into(),
            path: Some(path.clone()),
            fixture: None,
            wrapped: true,
            signed: Some(true),
        };
        assert_eq!(payload(&asset, Path::new("."), false).unwrap(), b"ABCD");
        let at = wrapped.len() - 8;
        wrapped[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(path, &wrapped).unwrap();
        assert!(payload(&asset, Path::new("."), false).is_err());
        for address in [
            json!([65536, 0, 0, 0]),
            json!([0, 256, 0, 0]),
            json!([0, 0, 32, 0]),
            json!([0, 0, 0, 8]),
        ] {
            let mut records = synthetic().unwrap();
            records[0].host.address = address;
            assert!(encode(&records, Path::new("."), true).is_err());
        }
        let mut records = synthetic().unwrap();
        records[1].host.kind = "mmio".into();
        records[1].host.address = json!(3);
        assert!(encode(&records, Path::new("."), true).is_err());
        records[1].host.address = json!(4096);
        assert!(encode(&records, Path::new("."), true).is_ok());
        records[1].assets[1].fixture = Some(vec![0; 64001]);
        assert!(encode(&records, Path::new("."), true).is_err());
    }
}
