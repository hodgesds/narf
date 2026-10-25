use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
pub(super) struct Temp(pub PathBuf);
impl Temp {
    pub(super) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "narf-wifi-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn malformed_vendor_inputs_are_errors_without_panics() {
    for vendor in [
        Vendor::Intel,
        Vendor::Mediatek,
        Vendor::Qualcomm,
        Vendor::Broadcom,
        Vendor::Realtek,
    ] {
        for size in 0..128 {
            let raw = vec![0; size];
            let key = if vendor == Vendor::Mediatek {
                "mt7921_patch"
            } else {
                "qca6174_api6"
            };
            let result = extract(vendor, key, "rtw89/test.bin", &raw);
            if vendor != Vendor::Broadcom || size < 116 {
                assert!(result.is_err(), "{vendor:?}, {size}");
            }
        }
    }
}
#[test]
fn intel_tlv_alignment_truncation_and_non_executable_ranges() {
    let mut raw = vec![0; 104];
    raw[..8].copy_from_slice(b"\0\0\0\0IWL\n");
    raw[88..92].copy_from_slice(&19u32.to_le_bytes());
    raw[92..96].copy_from_slice(&5u32.to_le_bytes());
    raw[96..100].copy_from_slice(&0x123456u32.to_le_bytes());
    raw[100] = 0xaa;
    let result = formats::intel(&raw).unwrap();
    assert_eq!(result.fragments, [(0, 0, 88), (88, 88, 8), (96, 96, 4)]);
    assert_eq!(result.metadata.len(), 100);
    assert_eq!(result.facts["sections"], json!([[19, 0x123456, 1]]));
    raw.truncate(103);
    assert!(formats::intel(&raw).is_err());
    raw.resize(104, 0);
    raw[92..96].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(formats::intel(&raw).is_err());
}
#[test]
fn intel_fixed_scalar_tags_cannot_smuggle_opaque_payloads() {
    for (tag, len) in [
        (23u32, 8u32),
        (27, 8),
        (36, 16),
        (62, 8),
        (22, 16),
        (29, 12),
    ] {
        let mut raw = vec![0; 96 + len as usize];
        raw[..8].copy_from_slice(b"\0\0\0\0IWL\n");
        raw[88..92].copy_from_slice(&tag.to_le_bytes());
        raw[92..96].copy_from_slice(&len.to_le_bytes());
        assert!(formats::intel(&raw).is_err());
    }
}
#[test]
fn mediatek_tables_cannot_escape_or_overlap_payloads() {
    let mut patch = vec![0; 164];
    patch[44..48].copy_from_slice(&1u32.to_be_bytes());
    patch[96..100].copy_from_slice(&2u32.to_be_bytes());
    patch[100..104].copy_from_slice(&160u32.to_be_bytes());
    patch[112..116].copy_from_slice(&4u32.to_be_bytes());
    assert_eq!(formats::mediatek(&patch, true).unwrap().metadata.len(), 160);
    patch[100..104].copy_from_slice(&159u32.to_be_bytes());
    assert!(formats::mediatek(&patch, true).is_err());
    let mut ram = vec![0; 80];
    ram[46] = 1;
    ram[24..28].copy_from_slice(&5u32.to_le_bytes());
    assert!(formats::mediatek(&ram, false).is_err());
}
#[test]
fn qualcomm_nested_ie_padding_and_bounds_are_checked() {
    let mut raw = b"QCA-ATH10K-BOARD\0".to_vec();
    raw.resize(36, 0);
    raw[20..24].copy_from_slice(&0u32.to_le_bytes());
    raw[24..28].copy_from_slice(&8u32.to_le_bytes());
    raw[28..32].copy_from_slice(&0u32.to_le_bytes());
    raw[32..36].copy_from_slice(&4u32.to_le_bytes());
    assert!(formats::qualcomm(&raw, "qca6174_board2").is_err());
    let mut raw = b"QCA-ATH10K\0\0".to_vec();
    raw.extend_from_slice(&[5, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]);
    let result = formats::qualcomm(&raw, "qca6174_api6").unwrap();
    assert_eq!(result.facts["wmi"], 1);
    raw.pop();
    assert!(formats::qualcomm(&raw, "qca6174_api6").is_err());
}
#[test]
fn realtek_declared_sections_and_signature_pools_remain_bounded() {
    let mut raw = vec![0; 96];
    raw[0] = 255;
    raw[1] = 1;
    raw[17] = 1;
    raw[20..24].copy_from_slice(&32u32.to_le_bytes());
    raw[24..28].copy_from_slice(&64u32.to_le_bytes());
    raw[57] = 1;
    raw[68..72].copy_from_slice(&16u32.to_le_bytes());
    let decoded = realtek::extract(&raw, "rtw89/test.bin").unwrap();
    assert_eq!(decoded["images"][0]["sections"][0]["length"], 16);
    assert_eq!(decoded["fragments"].as_array().unwrap().len(), 2);
    raw[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(realtek::extract(&raw, "rtw89/test.bin").is_err());
}

#[test]
fn extraction_requires_explicit_hash_and_new_destination() {
    let temp = Temp::new();
    let input = temp.0.join("source.bin");
    let output = temp.0.join("new");
    let raw = vec![0; 116];
    fs::write(&input, &raw).unwrap();
    let args = |sha256: String| Args {
        command: Command::Extract(ExtractArgs {
            vendor: Vendor::Broadcom,
            key: "synthetic".into(),
            name: "brcm/synthetic.bin".into(),
            input: input.clone(),
            sha256,
            output: output.clone(),
        }),
    };
    assert!(run(args("ff".repeat(32)), &temp.0).is_err());
    assert!(!output.exists());
    run(args(hex(&Sha256::digest(&raw))), &temp.0).unwrap();
    assert_eq!(fs::read(output.join("metadata.bin")).unwrap(), [0; 12]);
    let facts: Value =
        serde_json::from_slice(&fs::read(output.join("facts.json")).unwrap()).unwrap();
    assert_eq!(facts["fragments"], json!([[0, 0, 4], [108, 4, 8]]));
    assert_eq!(facts["facts"]["embedded_ramsize"], Value::Null);
    assert!(run(args(hex(&Sha256::digest(&raw))), &temp.0).is_err());
}

#[test]
fn source_aliases_stay_contained_and_inputs_are_not_modified() {
    let temp = Temp::new();
    fs::write(temp.0.join("raw.bin"), [1, 2, 3]).unwrap();
    assert_eq!(read_source(&temp.0, "raw.bin").unwrap(), [1, 2, 3]);
    for name in ["../raw.bin", "./raw.bin", "/raw.bin", "sub//raw.bin"] {
        assert!(read_source(&temp.0, name).is_err());
    }
    #[cfg(unix)]
    {
        let outside = Temp::new();
        fs::write(outside.0.join("raw.bin"), [9]).unwrap();
        std::os::unix::fs::symlink(outside.0.join("raw.bin"), temp.0.join("escape.bin")).unwrap();
        assert!(read_source(&temp.0, "escape.bin").is_err());
        assert_eq!(fs::read(outside.0.join("raw.bin")).unwrap(), [9]);
    }
    assert_eq!(fs::read(temp.0.join("raw.bin")).unwrap(), [1, 2, 3]);
}

#[test]
fn cli_modes_require_explicit_inputs_and_boundaries() {
    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        args: Args,
    }
    use clap::Parser;
    for args in [
        vec!["tool", "check"],
        vec!["tool", "check", "--vendor", "intel,realtek"],
        vec![
            "tool",
            "board-manifest",
            "--synthetic-fixture",
            "--output",
            "new.rs",
            "--rust",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
    for args in [
        vec!["tool", "extract"],
        vec!["tool", "board-manifest", "--output", "new.bin"],
        vec![
            "tool",
            "board-manifest",
            "--input",
            "x.json",
            "--synthetic-fixture",
            "--output",
            "new.bin",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn rust_table_comparison_preserves_token_and_literal_boundaries() {
    let canonical = b"const SOURCE: usize = 635449;";
    assert_eq!(
        rust_body(canonical).unwrap(),
        rust_body(b"// comment\n const SOURCE : usize=635449 ;").unwrap()
    );
    for corrupted in [
        &b"constSOURCE: usize = 635449;"[..],
        &b"const SOURCE: usize = 6 35449;"[..],
    ] {
        assert_ne!(rust_body(canonical).unwrap(), rust_body(corrupted).unwrap());
    }
    assert_ne!(
        rust_body(br##"const S: &str = r#"a b"#;"##).unwrap(),
        rust_body(br##"const S: &str = r#"ab"#;"##).unwrap()
    );
    assert!(rust_body(b"const S: &str = \"unterminated").is_err());
}

#[test]
fn ax_membership_uses_decoded_source_identity_without_order_assumptions() {
    let mut raw = vec![0; 96];
    raw[0] = 255;
    raw[1] = 1;
    raw[17] = 1;
    raw[20..24].copy_from_slice(&32u32.to_le_bytes());
    raw[24..28].copy_from_slice(&64u32.to_le_bytes());
    raw[57] = 1;
    raw[68..72].copy_from_slice(&16u32.to_le_bytes());
    let ax = extract(Vendor::Realtek, "ax", "rtw89/test.bin", &raw).unwrap();
    let mut legacy = vec![0; 32];
    legacy[..2].copy_from_slice(&0x88e1u16.to_le_bytes());
    let legacy = extract(Vendor::Realtek, "legacy", "rtlwifi/test.bin", &legacy).unwrap();
    let items = vec![
        ("ax".into(), Value::Null, ax),
        ("legacy".into(), Value::Null, legacy),
    ];
    let products = render::products(Vendor::Realtek, &items).unwrap();
    assert!(products["metadata.rs"].ends_with("pub const AX: &[Source] = &[\n    SOURCE_0,\n];\n"));
}

#[cfg(unix)]
#[test]
fn fixture_writes_reject_symlink_escape_before_any_product_changes() {
    let fixtures = Temp::new();
    let source = Temp::new();
    let outside = Temp::new();
    fs::create_dir(source.0.join("brcm")).unwrap();
    fs::create_dir(fixtures.0.join("broadcom")).unwrap();
    let raw = vec![0; 116];
    fs::write(source.0.join("brcm/brcmfmac43602-pcie.bin"), &raw).unwrap();
    let manifest = json!({"source":"brcm/brcmfmac43602-pcie.bin","source_sha256":hex(&Sha256::digest(&raw)),"source_size":116});
    let target = fixtures.0.join("broadcom");
    let manifest_bytes = json_bytes(&manifest).unwrap();
    fs::write(target.join("provenance.json"), &manifest_bytes).unwrap();
    let outside_file = outside.0.join("preserve.bin");
    fs::write(&outside_file, b"outside").unwrap();
    let args = || FixtureArgs {
        vendor: vec![Vendor::Broadcom],
        source: source.0.clone(),
        fixtures: Some(fixtures.0.clone()),
    };
    for name in ["bcm43602.metadata.bin", "goldens.rs"] {
        std::os::unix::fs::symlink(&outside_file, target.join(name)).unwrap();
        assert!(super::fixtures(args(), Path::new("."), true).is_err());
        assert_eq!(fs::read(&outside_file).unwrap(), b"outside");
        assert_eq!(
            fs::read(target.join("provenance.json")).unwrap(),
            manifest_bytes
        );
        fs::remove_file(target.join(name)).unwrap();
    }
    fs::remove_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(&outside.0, &target).unwrap();
    assert!(super::fixtures(args(), Path::new("."), true).is_err());
    assert_eq!(fs::read(&outside_file).unwrap(), b"outside");
    assert!(validate_output(&source.0, &source.0, &source.0.join("product.bin"), true).is_err());
    // Atomic replacement must not mutate another link to the prior inode.
    let linked = fixtures.0.join("linked.bin");
    fs::hard_link(&outside_file, &linked).unwrap();
    write_product(&linked, b"new").unwrap();
    assert_eq!(fs::read(&outside_file).unwrap(), b"outside");
}

#[test]
fn write_check_roundtrip_rejects_corruption_and_validates_all_pins_first() {
    let tree = Temp::new();
    let source = Temp::new();
    let target = tree.0.join("broadcom");
    fs::create_dir(&target).unwrap();
    fs::create_dir(source.0.join("brcm")).unwrap();
    let raw = vec![0; 116];
    let source_path = source.0.join("brcm/brcmfmac43602-pcie.bin");
    fs::write(&source_path, &raw).unwrap();
    let manifest = json!({"source":"brcm/brcmfmac43602-pcie.bin","source_sha256":hex(&Sha256::digest(&raw)),"source_size":116,"unknown_provenance":"retain"});
    let original = json_bytes(&manifest).unwrap();
    fs::write(target.join("provenance.json"), &original).unwrap();
    fs::write(target.join("optional.vendor.bin"), b"preserve").unwrap();
    let args = |vendor| FixtureArgs {
        vendor,
        source: source.0.clone(),
        fixtures: Some(tree.0.clone()),
    };
    // A later selected family is invalid. Earlier validated products must not
    // appear and their explicit provenance must remain byte-for-byte intact.
    assert!(fixtures(
        args(vec![Vendor::Broadcom, Vendor::Intel]),
        Path::new("."),
        true
    )
    .is_err());
    assert!(!target.join("bcm43602.metadata.bin").exists());
    assert_eq!(fs::read(target.join("provenance.json")).unwrap(), original);
    fixtures(args(vec![Vendor::Broadcom]), Path::new("."), true).unwrap();
    fixtures(args(vec![Vendor::Broadcom]), Path::new("."), false).unwrap();
    assert_eq!(
        fs::read(target.join("bcm43602.metadata.bin")).unwrap(),
        [0; 12]
    );
    assert_eq!(fs::read(&source_path).unwrap(), raw);
    assert_eq!(
        fs::read(target.join("optional.vendor.bin")).unwrap(),
        b"preserve"
    );
    let checked_manifest = fs::read(target.join("provenance.json")).unwrap();
    let facts: Value = serde_json::from_slice(&checked_manifest).unwrap();
    assert_eq!(facts["unknown_provenance"], "retain");
    let golden = fs::read_to_string(target.join("goldens.rs")).unwrap();
    for corruption in [
        golden.replace("const SOURCE:", "constSOURCE:"),
        golden.replace("usize = 116", "usize = 1 16"),
    ] {
        fs::write(target.join("goldens.rs"), corruption).unwrap();
        assert!(fixtures(args(vec![Vendor::Broadcom]), Path::new("."), false).is_err());
    }
    fs::write(target.join("goldens.rs"), &golden).unwrap();
    let mut modified = raw;
    modified[0] = 1;
    fs::write(&source_path, modified).unwrap();
    assert!(fixtures(args(vec![Vendor::Broadcom]), Path::new("."), true).is_err());
    assert_eq!(
        fs::read_to_string(target.join("goldens.rs")).unwrap(),
        golden
    );
    assert_eq!(
        fs::read(target.join("provenance.json")).unwrap(),
        checked_manifest
    );
}
