// SPDX-License-Identifier: GPL-2.0-or-later
//! Detect the extracted Wi-Fi firmware golden fixtures at build time.
//!
//! The golden replay tests under `verification/data/wifi-firmware/`
//! embed `*.metadata.bin` extracts via `include_bytes!`. Those extracts
//! are produced by the native Rust `cargo xtask wifi-fixtures` command from SHA256-pinned vendor
//! originals under `/lib/firmware`, which are not part of this repo.
//! All metadata extracts are committed. The Qualcomm and Broadcom extracts
//! previously omitted by the root `*.bin` gitignore rule (issue #739) are
//! included too; a clean checkout needs no vendor originals to run these tests.
//!
//! For each vendor whose extracts are all present, emit a cfg
//! (`narf_wifi_goldens_qualcomm` / `narf_wifi_goldens_broadcom`) that
//! enables the real replay test modules. When a vendor's extracts are
//! absent, emit no cfg — the declarations in the driver sources then
//! select stub modules that register the same tests as
//! `TestResult::Skip` — and print a warning naming the regeneration
//! command, so the absence is loud in build output instead of a
//! compile error (`include_bytes!` on a missing file) or a silent pass.

use std::env;
use std::path::PathBuf;

/// `(fixture dir, cfg name, vendor label, extract file names)`.
const VENDORS: &[(&str, &str, &str, &[&str])] = &[
    (
        "qualcomm",
        "narf_wifi_goldens_qualcomm",
        "Qualcomm",
        &[
            "qca988x_api5.metadata.bin",
            "qca6174_api6.metadata.bin",
            "qca6174_board2.metadata.bin",
            "qca6390_board2.metadata.bin",
            "wcn6855_board2.metadata.bin",
            "qca6390_amss.metadata.bin",
            "qca6390_m3.metadata.bin",
            "wcn6855_amss.metadata.bin",
            "wcn6855_m3.metadata.bin",
        ],
    ),
    (
        "broadcom",
        "narf_wifi_goldens_broadcom",
        "Broadcom",
        &["bcm43602.metadata.bin"],
    ),
];

fn main() {
    for (_, cfg, _, _) in VENDORS {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
    }
    let fixtures = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../../verification/data/wifi-firmware");
    for (dir_name, cfg, label, files) in VENDORS {
        let dir = fixtures.join(dir_name);
        let mut present = true;
        for file in *files {
            let path = dir.join(file);
            // Rerun when an extract appears (or changes) so a checkout
            // that gains the real files picks the real tests up without
            // a manual clean.
            println!("cargo:rerun-if-changed={}", path.display());
            present &= path.is_file();
        }
        if present {
            println!("cargo:rustc-cfg={cfg}");
        } else {
            println!(
                "cargo:warning=narf-drivers-wireless: {label} Wi-Fi golden fixtures absent \
                 (verification/data/wifi-firmware/{dir_name}/*.metadata.bin) — the {label} \
                 golden replay tests will report Skip. Regenerate with: cargo xtask wifi-fixtures write --vendor {dir_name} \
                 (requires the SHA256-pinned vendor originals under /lib/firmware)"
            );
        }
    }
}
