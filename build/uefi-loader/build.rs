// SPDX-License-Identifier: GPL-2.0-or-later
use narf_boot_protocol::{BootBundle, BUNDLE_HEADER_SIZE, BUNDLE_MAGIC};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() {
    for name in ["NARF_EFI_KERNEL", "NARF_EFI_INITRAMFS", "NARF_EFI_CMDLINE"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("uefi")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut parts = Vec::new();
    for (name, _destination) in [
        ("NARF_EFI_KERNEL", "kernel.elf"),
        ("NARF_EFI_INITRAMFS", "initramfs.cpio"),
    ] {
        let path = PathBuf::from(
            env::var_os(name)
                .unwrap_or_else(|| panic!("{name} is required; build with cargo xtask efi-image")),
        );
        println!("cargo:rerun-if-changed={}", path.display());
        let size = fs::metadata(&path).expect("EFI input metadata").len();
        assert!(
            size > 0 && size <= 1024 * 1024 * 1024,
            "EFI payload must be nonempty and at most 1 GiB"
        );
        parts.push(fs::read(&path).expect("reading EFI payload"));
    }
    let cmdline = env::var("NARF_EFI_CMDLINE").unwrap_or_default();
    assert!(
        cmdline.len() < 2048 && !cmdline.as_bytes().contains(&0),
        "EFI command line exceeds kernel capacity or contains NUL"
    );
    parts.push(cmdline.into_bytes());
    let mut bundle = vec![0u8; BUNDLE_HEADER_SIZE];
    bundle[..16].copy_from_slice(BUNDLE_MAGIC);
    bundle[16..20].copy_from_slice(&1u32.to_le_bytes());
    bundle[20..24].copy_from_slice(&(BUNDLE_HEADER_SIZE as u32).to_le_bytes());
    for (i, part) in parts.iter().enumerate() {
        let offset = bundle.len();
        bundle[32 + i * 16..40 + i * 16].copy_from_slice(&(offset as u64).to_le_bytes());
        bundle[40 + i * 16..48 + i * 16].copy_from_slice(&(part.len() as u64).to_le_bytes());
        bundle[80 + i * 32..112 + i * 32].copy_from_slice(&Sha256::digest(part));
        bundle.extend_from_slice(part);
        bundle.resize(bundle.len().div_ceil(8) * 8, 0);
    }
    let total = bundle.len() as u64;
    bundle[24..32].copy_from_slice(&total.to_le_bytes());
    BootBundle::parse(&bundle).expect("validating EFI bundle");
    fs::write(out.join("bundle.bin"), bundle).expect("writing EFI bundle");
}
