//! Subsystem smokes for `narf-firmware-fdt`. All FDT smoke tests
//! live here so the crate is self-contained.

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{self as fdt, Reservation};

extern crate alloc;
use alloc::vec::Vec;

/// Build a minimal FDT blob for tests.
///
/// Produces a header + struct block + strings block. Optional
/// reservations can be supplied; an all-zeros terminator is added.
fn build_blob(
    boot_cpuid: u32,
    reservations: &[(u64, u64)],
    nodes: &[(&str, &[(&str, &[u8])])],
) -> Vec<u8> {
    // 1) Build the strings block: NUL-terminated property names,
    //    deduped via a linear scan.
    let mut strings: Vec<u8> = Vec::new();
    let intern = |strings: &mut Vec<u8>, name: &str| -> u32 {
        // search for an existing identical run.
        let target = name.as_bytes();
        let mut i = 0;
        while i + target.len() < strings.len() {
            if &strings[i..i + target.len()] == target && strings[i + target.len()] == 0 {
                return i as u32;
            }
            i += 1;
        }
        let off = strings.len() as u32;
        strings.extend_from_slice(target);
        strings.push(0);
        off
    };

    // 2) Build the struct block.
    let mut s: Vec<u8> = Vec::new();

    // Root open: BEGIN_NODE + empty name + 4-byte alignment.
    s.extend_from_slice(&fdt::FDT_BEGIN_NODE.to_be_bytes());
    s.push(0); s.push(0); s.push(0); s.push(0);    // empty name (NUL + 3 pad)

    for (node_name, props) in nodes {
        s.extend_from_slice(&fdt::FDT_BEGIN_NODE.to_be_bytes());
        s.extend_from_slice(node_name.as_bytes());
        s.push(0);
        // pad to 4
        while s.len() % 4 != 0 { s.push(0); }

        for (pname, pval) in *props {
            let off = intern(&mut strings, pname);
            s.extend_from_slice(&fdt::FDT_PROP.to_be_bytes());
            s.extend_from_slice(&(pval.len() as u32).to_be_bytes());
            s.extend_from_slice(&off.to_be_bytes());
            s.extend_from_slice(pval);
            while s.len() % 4 != 0 { s.push(0); }
        }

        s.extend_from_slice(&fdt::FDT_END_NODE.to_be_bytes());
    }

    s.extend_from_slice(&fdt::FDT_END_NODE.to_be_bytes());   // close root
    s.extend_from_slice(&fdt::FDT_END.to_be_bytes());

    let struct_size = s.len() as u32;
    let strings_size = strings.len() as u32;

    // 3) Memory reserve map.
    let mut rsv: Vec<u8> = Vec::new();
    for (addr, size) in reservations {
        rsv.extend_from_slice(&addr.to_be_bytes());
        rsv.extend_from_slice(&size.to_be_bytes());
    }
    rsv.extend_from_slice(&0u64.to_be_bytes());
    rsv.extend_from_slice(&0u64.to_be_bytes());

    // 4) Layout.
    //   header (40) + rsvmap + struct + strings
    let off_rsvmap  = 40u32;
    let off_struct  = off_rsvmap + rsv.len() as u32;
    let off_strings = off_struct + struct_size;
    let totalsize   = off_strings + strings_size;

    let mut out: Vec<u8> = Vec::with_capacity(totalsize as usize);
    out.extend_from_slice(&fdt::FDT_MAGIC.to_be_bytes());
    out.extend_from_slice(&totalsize.to_be_bytes());
    out.extend_from_slice(&off_struct.to_be_bytes());
    out.extend_from_slice(&off_strings.to_be_bytes());
    out.extend_from_slice(&off_rsvmap.to_be_bytes());
    out.extend_from_slice(&17u32.to_be_bytes());           // version
    out.extend_from_slice(&16u32.to_be_bytes());           // last_comp_version
    out.extend_from_slice(&boot_cpuid.to_be_bytes());
    out.extend_from_slice(&strings_size.to_be_bytes());
    out.extend_from_slice(&struct_size.to_be_bytes());
    out.extend_from_slice(&rsv);
    out.extend_from_slice(&s);
    out.extend_from_slice(&strings);
    out
}

fn smoke_fdt_header_round_trip() -> TestResult {
    let blob = build_blob(0, &[], &[]);
    let hdr = fdt::parse_header(&blob).expect("header");
    if hdr.magic != fdt::FDT_MAGIC { return TestResult::Fail("magic"); }
    if hdr.version != 17 { return TestResult::Fail("version"); }
    if hdr.boot_cpuid_phys != 0 { return TestResult::Fail("boot cpu"); }
    if hdr.totalsize as usize != blob.len() { return TestResult::Fail("totalsize"); }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_header_round_trip);

fn smoke_fdt_walk_minimal() -> TestResult {
    let nodes = &[
        ("memory@0", &[("device_type", b"memory\0" as &[u8])][..]),
    ];
    let blob = build_blob(0, &[], nodes);
    let mut saw = false;
    let mut prop_count = 0u32;
    fdt::walk_nodes(&blob, |path, props| {
        if path.matches(&["memory@0"]) {
            saw = true;
            for (name, _value) in props {
                if name == "device_type" { prop_count += 1; }
            }
        }
    });
    if !saw { return TestResult::Fail("memory@0 not visited"); }
    if prop_count != 1 { return TestResult::Fail("device_type prop missing"); }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_walk_minimal);

fn smoke_fdt_chosen_bootargs() -> TestResult {
    let nodes = &[
        ("chosen", &[("bootargs", b"console=ttyAMA0\0" as &[u8])][..]),
    ];
    let blob = build_blob(0, &[], nodes);
    let bargs = fdt::chosen_bootargs(&blob).expect("bootargs");
    if bargs.as_str() != "console=ttyAMA0" {
        return TestResult::Fail("bootargs mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_chosen_bootargs);

fn smoke_fdt_memory_ranges() -> TestResult {
    // /memory@40000000 reg = <0x0 0x40000000 0x0 0x10000000>
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x4000_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x1000_0000u64.to_be_bytes());
    let nodes = &[
        ("memory@40000000",
         &[("device_type", b"memory\0" as &[u8]),
           ("reg", reg.as_slice())][..]),
    ];
    let blob = build_blob(0, &[], nodes);
    let mut out = [Reservation::default(); 4];
    let n = fdt::copy_memory_ranges(&blob, &mut out);
    if n != 1
        || out[0].addr != 0x4000_0000
        || out[0].size != 0x1000_0000
    {
        return TestResult::Fail("memory range mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_memory_ranges);

fn smoke_fdt_reservations() -> TestResult {
    let blob = build_blob(0, &[(0xC000_0000, 0x10_0000), (0xD000_0000, 0x40_0000)], &[]);
    let mut out = [Reservation::default(); 4];
    let n = fdt::copy_reservations(&blob, &mut out);
    if n != 2
        || out[0] != (Reservation { addr: 0xC000_0000, size: 0x10_0000 })
        || out[1] != (Reservation { addr: 0xD000_0000, size: 0x40_0000 })
    {
        return TestResult::Fail("reserve map mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_reservations);
