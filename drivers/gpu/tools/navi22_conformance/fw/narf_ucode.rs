//! Host runner for NARF's own Navi22 firmware parsers, printing the record
//! format of `linux_ucode.c` so the two can be diffed. The parser sources are
//! compiled unmodified via `#[path]`; they depend only on `core`.
//!
//! rustc --edition 2021 -O narf_ucode.rs -o narf_ucode && ./narf_ucode <fw-dir>
#![allow(dead_code)]

#[path = "../../../src/amdgpu_dmub_firmware.rs"]
mod amdgpu_dmub_firmware;
#[path = "../../../src/amdgpu_gfx_firmware.rs"]
mod amdgpu_gfx_firmware;
#[path = "../../../src/amdgpu_psp_firmware.rs"]
mod amdgpu_psp_firmware;
#[path = "../../../src/amdgpu_rdna2.rs"]
mod amdgpu_rdna2;
#[path = "../../../src/amdgpu_smc_firmware.rs"]
mod amdgpu_smc_firmware;

use amdgpu_gfx_firmware::{Image as Gfx, Source};
use amdgpu_psp_firmware::{Component, Image as Sos};
use std::path::Path;

/// Strip the NARF trailer (firmware/src/signature.rs): payload | signature (64)
/// | signer (32) | metadata | metadata length (4, LE) | "NRFW".
fn load(dir: &Path, name: &str) -> Vec<u8> {
    let path = dir.join(format!("navy_flounder_{name}.bin"));
    let mut bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("missing {}: {e}", path.display());
        std::process::exit(2)
    });
    let n = bytes.len();
    if n >= 104 && bytes[n - 4..] == *b"NRFW" {
        let mlen = u32::from_le_bytes(bytes[n - 8..n - 4].try_into().unwrap()) as usize;
        bytes.truncate(n - 8 - mlen - 96);
    }
    bytes
}

fn off(base: &[u8], part: &[u8]) -> usize {
    part.as_ptr() as usize - base.as_ptr() as usize
}

fn sos(dir: &Path) {
    let b = load(dir, "sos");
    let major = u16::from_le_bytes([b[8], b[9]]);
    let minor = u16::from_le_bytes([b[10], b[11]]);
    println!("sos header {major}.{minor} size {}", b.len());
    let image = match Sos::parse(&b) {
        Ok(i) => i,
        Err(e) => return println!("sos parse error {e:?}"),
    };
    println!("sos version 0x{:08x}", image.version());
    for (component, part) in image.components() {
        let name = match component {
            Component::KeyDatabase => "KDB",
            Component::Spl => "SPL",
            Component::SystemDriver => "SYS_DRV",
            Component::SecureOs => "SOS",
            Component::SocDriver => "SOC_DRV",
            Component::InterfaceDriver => "INTF_DRV",
            Component::HardwareDebugDriver => "DBG_DRV",
            Component::RasDriver => "RAS_DRV",
            Component::IpKeyManager => "IPKEYMGR_DRV",
        };
        println!(
            "sos load {name} cmd 0x{:08x} off 0x{:x} size 0x{:x}",
            component.command(),
            off(&b, part),
            part.len()
        );
    }
    match image.toc() {
        Some(toc) => println!("sos toc off 0x{:x} size 0x{:x}", off(&b, toc), toc.len()),
        None => println!("sos toc none"),
    }
}

fn smc(dir: &Path, profile: &amdgpu_rdna2::Profile) {
    let b = load(dir, "smc");
    let major = u16::from_le_bytes([b[8], b[9]]);
    let minor = u16::from_le_bytes([b[10], b[11]]);
    println!("smc header {major}.{minor} size {}", b.len());
    let image = match amdgpu_smc_firmware::Image::parse(&b) {
        Ok(i) => i,
        Err(e) => return println!("smc parse error {e:?}"),
    };
    let mut tables: Vec<_> = image
        .powerplay_ids()
        .map(|id| image.powerplay_for(id).unwrap())
        .collect();
    if let Some(table) = image.powerplay() {
        tables.push(table);
    }
    for t in tables {
        let layout = profile
            .power_table_layout(t.len().checked_sub(802).expect("PowerPlay driver header"))
            .expect("unknown PowerPlay SKU layout");
        let word = |at: usize| u16::from_le_bytes(t[at..at + 2].try_into().unwrap());
        assert_eq!(word(0) as usize, t.len());
        assert_eq!(word(5), 802);
        assert_eq!(t[2..5], [layout.format_revision, 0, 2]);
        assert_eq!(word(15), layout.format_id);
        assert_eq!(layout.board_end - layout.board_start, 292);
    }
    println!("smc version 0x{:08x}", image.version());
    // amdgpu_psp_ring.rs::load_smc sends the payload as type 18.
    let p = image.payload();
    println!(
        "smc upload type 18 off 0x{:x} size 0x{:x}",
        off(&b, p),
        p.len()
    );
    match image.powerplay() {
        Some(t) => println!("smc pptable off 0x{:x} size 0x{:x}", off(&b, t), t.len()),
        None => println!("smc pptable none"),
    }
}

fn file_name(source: Source) -> &'static str {
    match source {
        Source::Sdma => "sdma",
        Source::Ce => "ce",
        Source::Pfp => "pfp",
        Source::Me => "me",
        Source::Mec => "mec",
        Source::Mec2 => "mec2",
        Source::Rlc => "rlc",
        Source::Vcn => "vcn",
        Source::Dmcub => "dmcub",
    }
}

fn gfx(dir: &Path, vcn_mask: u8) {
    // Same sequence as amdgpu_gfx_navi22.rs::Firmware::images and
    // amdgpu_psp_ring.rs::load_gfx_inner (Source::ORDER, payloads in order).
    let files: Vec<(Source, Vec<u8>)> = Source::ORDER
        .iter()
        .map(|&s| (s, load(dir, file_name(s))))
        .collect();
    let mut uploads = Vec::new();
    for (source, bytes) in &files {
        let mut image = match Gfx::parse(*source, bytes) {
            Ok(i) => i,
            Err(e) => {
                println!("{} parse error {e:?}", file_name(*source));
                continue;
            }
        };
        if *source == Source::Vcn {
            image = image.for_vcn_instances(vcn_mask).expect("vcn mask");
        }
        match source {
            Source::Rlc => {
                let major = u16::from_le_bytes([bytes[8], bytes[9]]);
                let minor = u16::from_le_bytes([bytes[10], bytes[11]]);
                println!(
                    "rlc header {major}.{minor} version 0x{:08x}",
                    image.version()
                );
            }
            Source::Dmcub => {}
            s => println!("{} version 0x{:08x}", file_name(*s), image.version()),
        }
        for p in image.payloads() {
            uploads.push(format!(
                "gfx upload type {} file {} off 0x{:x} size 0x{:x}",
                p.firmware_type(),
                file_name(*source),
                off(bytes, p.bytes()),
                p.bytes().len()
            ));
        }
    }
    println!("gfx vcn_mask {vcn_mask}");
    for u in uploads {
        println!("{u}");
    }
}

fn dmcub(dir: &Path) {
    let b = load(dir, "dmcub");
    let h16 = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let image = match amdgpu_dmub_firmware::Image::parse(&b) {
        Ok(i) => i,
        Err(e) => return println!("dmcub parse error {e:?}"),
    };
    println!(
        "dmcub header {}.{} ip {}.{} version 0x{:08x}",
        h16(8),
        h16(10),
        h16(12),
        h16(14),
        image.version()
    );
    let s = image.signed_instructions();
    println!(
        "dmcub signed off 0x{:x} size 0x{:x}",
        image.signed_offset(),
        s.len()
    );
    let i = image.instructions();
    println!("dmcub inst off 0x{:x} size 0x{:x}", off(&b, i), i.len());
    let d = image.bss_data();
    println!("dmcub bss off 0x{:x} size 0x{:x}", off(&b, d), d.len());
    let m = image.metadata();
    println!(
        "dmcub meta fw_region 0x{:x} trace 0x{:x} version 0x{:08x} dal 1 shared 0x{:x} features {} bits 0x{:x}",
        m.state_size, m.trace_size, m.version, m.shared_state_size, m.shared_state_features, m.feature_bits
    );
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: narf_ucode <fw-dir>");
        std::process::exit(2)
    });
    let dir = Path::new(&dir);
    sos(dir);
    let asic = std::env::args().nth(2).unwrap_or_else(|| "navi22".into());
    let profile = amdgpu_rdna2::PROFILES
        .iter()
        .find(|p| p.asic == asic)
        .expect("unknown ASIC");
    smc(dir, profile);
    gfx(dir, 1);
    gfx(dir, 3);
    dmcub(dir);
}
