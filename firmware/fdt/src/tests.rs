//! Subsystem smokes for `narf-firmware-fdt`. All FDT smoke tests
//! live here so the crate is self-contained.

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{self as fdt, Reservation};

extern crate alloc;
use alloc::vec::Vec;

/// A node's name paired with its list of `(property name, property value)` pairs.
type NodeSpec<'a> = (&'a str, &'a [(&'a str, &'a [u8])]);

/// Build a minimal FDT blob for tests.
///
/// Produces a header + struct block + strings block. Optional
/// reservations can be supplied; an all-zeros terminator is added.
fn build_blob(
    boot_cpuid: u32,
    reservations: &[(u64, u64)],
    root_props: &[(&str, &[u8])],
    nodes: &[NodeSpec],
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
    s.push(0);
    s.push(0);
    s.push(0);
    s.push(0); // empty name (NUL + 3 pad)

    for (pname, pval) in root_props {
        let off = intern(&mut strings, pname);
        s.extend_from_slice(&fdt::FDT_PROP.to_be_bytes());
        s.extend_from_slice(&(pval.len() as u32).to_be_bytes());
        s.extend_from_slice(&off.to_be_bytes());
        s.extend_from_slice(pval);
        while s.len() % 4 != 0 {
            s.push(0);
        }
    }

    for (node_name, props) in nodes {
        s.extend_from_slice(&fdt::FDT_BEGIN_NODE.to_be_bytes());
        s.extend_from_slice(node_name.as_bytes());
        s.push(0);
        // pad to 4
        while s.len() % 4 != 0 {
            s.push(0);
        }

        for (pname, pval) in *props {
            let off = intern(&mut strings, pname);
            s.extend_from_slice(&fdt::FDT_PROP.to_be_bytes());
            s.extend_from_slice(&(pval.len() as u32).to_be_bytes());
            s.extend_from_slice(&off.to_be_bytes());
            s.extend_from_slice(pval);
            while s.len() % 4 != 0 {
                s.push(0);
            }
        }

        s.extend_from_slice(&fdt::FDT_END_NODE.to_be_bytes());
    }

    s.extend_from_slice(&fdt::FDT_END_NODE.to_be_bytes()); // close root
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
    let off_rsvmap = 40u32;
    let off_struct = off_rsvmap + rsv.len() as u32;
    let off_strings = off_struct + struct_size;
    let totalsize = off_strings + strings_size;

    let mut out: Vec<u8> = Vec::with_capacity(totalsize as usize);
    out.extend_from_slice(&fdt::FDT_MAGIC.to_be_bytes());
    out.extend_from_slice(&totalsize.to_be_bytes());
    out.extend_from_slice(&off_struct.to_be_bytes());
    out.extend_from_slice(&off_strings.to_be_bytes());
    out.extend_from_slice(&off_rsvmap.to_be_bytes());
    out.extend_from_slice(&17u32.to_be_bytes()); // version
    out.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version
    out.extend_from_slice(&boot_cpuid.to_be_bytes());
    out.extend_from_slice(&strings_size.to_be_bytes());
    out.extend_from_slice(&struct_size.to_be_bytes());
    out.extend_from_slice(&rsv);
    out.extend_from_slice(&s);
    out.extend_from_slice(&strings);
    out
}

fn smoke_fdt_header_round_trip() -> TestResult {
    let blob = build_blob(0, &[], &[], &[]);
    let hdr = fdt::parse_header(&blob).expect("header");
    if hdr.magic != fdt::FDT_MAGIC {
        return TestResult::Fail("magic");
    }
    if hdr.version != 17 {
        return TestResult::Fail("version");
    }
    if hdr.boot_cpuid_phys != 0 {
        return TestResult::Fail("boot cpu");
    }
    if hdr.totalsize as usize != blob.len() {
        return TestResult::Fail("totalsize");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_header_round_trip);

fn smoke_fdt_walk_minimal() -> TestResult {
    let nodes = &[("memory@0", &[("device_type", b"memory\0" as &[u8])][..])];
    let blob = build_blob(0, &[], &[], nodes);
    let mut saw = false;
    let mut prop_count = 0u32;
    fdt::walk_nodes(&blob, |path, props| {
        if path.matches(&["memory@0"]) {
            saw = true;
            for (name, _value) in props {
                if name == "device_type" {
                    prop_count += 1;
                }
            }
        }
    });
    if !saw {
        return TestResult::Fail("memory@0 not visited");
    }
    if prop_count != 1 {
        return TestResult::Fail("device_type prop missing");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_walk_minimal);

fn smoke_fdt_chosen_bootargs() -> TestResult {
    let nodes = &[("chosen", &[("bootargs", b"console=ttyAMA0\0" as &[u8])][..])];
    let blob = build_blob(0, &[], &[], nodes);
    let bargs = fdt::chosen_bootargs(&blob).expect("bootargs");
    if bargs.as_str() != "console=ttyAMA0" {
        return TestResult::Fail("bootargs mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_chosen_bootargs);

fn smoke_fdt_memory_ranges() -> TestResult {
    // DTSpec 2.3.5: root-default cells are <2> (8-byte addr) and <1> (4-byte size).
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x4000_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x1000_0000u32.to_be_bytes());
    let nodes = &[(
        "memory@40000000",
        &[
            ("device_type", b"memory\0" as &[u8]),
            ("reg", reg.as_slice()),
        ][..],
    )];
    let blob = build_blob(0, &[], &[], nodes);
    let mut out = [Reservation::default(); 4];
    let n = fdt::copy_memory_ranges(&blob, &mut out);
    if n != 1 || out[0].addr != 0x4000_0000 || out[0].size != 0x1000_0000 {
        return TestResult::Fail("memory range mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_memory_ranges);

fn smoke_fdt_reservations() -> TestResult {
    let blob = build_blob(
        0,
        &[(0xC000_0000, 0x10_0000), (0xD000_0000, 0x40_0000)],
        &[],
        &[],
    );
    let mut out = [Reservation::default(); 4];
    let n = fdt::copy_reservations(&blob, &mut out);
    if n != 2
        || out[0]
            != (Reservation {
                addr: 0xC000_0000,
                size: 0x10_0000,
            })
        || out[1]
            != (Reservation {
                addr: 0xD000_0000,
                size: 0x40_0000,
            })
    {
        return TestResult::Fail("reserve map mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_reservations);

fn smoke_fdt_cells_inheritance() -> TestResult {
    // Explicitly set 2/2 in root.
    let addr_cells = 2u32.to_be_bytes();
    let size_cells = 2u32.to_be_bytes();
    let root_props = &[
        ("#address-cells", &addr_cells[..]),
        ("#size-cells", &size_cells[..]),
    ];

    let mut reg = Vec::new();
    reg.extend_from_slice(&0x4000_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x1000_0000u64.to_be_bytes());

    let nodes = &[(
        "memory@40000000",
        &[
            ("device_type", b"memory\0" as &[u8]),
            ("reg", reg.as_slice()),
        ][..],
    )];
    let blob = build_blob(0, &[], root_props, nodes);
    let mut out = [Reservation::default(); 2];
    let n = fdt::copy_memory_ranges(&blob, &mut out);
    if n != 1 || out[0].addr != 0x4000_0000 || out[0].size != 0x1000_0000 {
        return TestResult::Fail("explicit 2/2 cells decoding");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_cells_inheritance);

fn smoke_fdt_compatible_match() -> TestResult {
    let zero_reg = 0u128.to_be_bytes();
    let nodes = &[
        (
            "uart@9000000",
            &[
                ("compatible", b"arm,pl011\0arm,primecell\0" as &[u8]),
                ("reg", &zero_reg[..]),
            ][..],
        ),
        (
            "eth@a003000",
            &[("compatible", b"virtio,mmio\0" as &[u8])][..],
        ),
    ];
    let blob = build_blob(0, &[], &[], nodes);
    let mut hits = 0u32;
    fdt::for_each_compatible(&blob, "arm,pl011", |path, _props, _cells| {
        if path.last_segment() == "uart@9000000" {
            hits += 1;
        }
    });
    if hits != 1 {
        return TestResult::Fail("expected exactly 1 pl011 match");
    }
    let mut other = 0u32;
    fdt::for_each_compatible(&blob, "nonexistent,bogus", |_p, _pr, _c| other += 1);
    if other != 0 {
        return TestResult::Fail("bogus compat matched");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_compatible_match);

fn smoke_fdt_phandle_lookup() -> TestResult {
    let phandle_buf = 7u32.to_be_bytes();
    let icells_buf = 3u32.to_be_bytes();
    let nodes = &[(
        "intc@8000000",
        &[
            ("phandle", &phandle_buf[..]),
            ("#interrupt-cells", &icells_buf[..]),
        ][..],
    )];
    let blob = build_blob(0, &[], &[], nodes);
    if fdt::interrupt_cells_for(&blob, 7) != Some(3) {
        return TestResult::Fail("interrupt-cells via phandle 7");
    }
    if fdt::interrupt_cells_for(&blob, 99).is_some() {
        return TestResult::Fail("missing phandle returned Some");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_phandle_lookup);

fn smoke_fdt_aliases_and_stdout() -> TestResult {
    let nodes = &[
        ("aliases", &[("serial0", b"/uart@9000000\0" as &[u8])][..]),
        (
            "chosen",
            &[
                ("stdout-path", b"/uart@9000000:115200\0" as &[u8]),
                ("bootargs", b"console=ttyAMA0\0" as &[u8]),
            ][..],
        ),
    ];
    let blob = build_blob(0, &[], &[], nodes);
    let mut alias = [0u8; 32];
    let n = fdt::alias_path(&blob, "serial0", &mut alias);
    if n == 0 || &alias[..n] != b"/uart@9000000" {
        return TestResult::Fail("alias serial0 lookup");
    }
    let mut stdout = [0u8; 32];
    let m = fdt::chosen_stdout_path(&blob, &mut stdout);
    if m == 0 || &stdout[..m] != b"/uart@9000000:115200" {
        return TestResult::Fail("chosen stdout-path lookup");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_aliases_and_stdout);

fn smoke_fdt_status_filter() -> TestResult {
    let nodes = &[
        ("eth@1", &[("status", b"disabled\0" as &[u8])][..]),
        ("eth@2", &[("status", b"okay\0" as &[u8])][..]),
        ("eth@3", &[][..]),
    ];
    let blob = build_blob(0, &[], &[], nodes);
    let mut counts = [0u32; 3];
    fdt::walk_nodes(&blob, |path, props| {
        let st = fdt::node_status(props);
        let idx = match path.last_segment() {
            "eth@1" => 0,
            "eth@2" => 1,
            "eth@3" => 2,
            _ => return,
        };
        match st {
            fdt::Status::Disabled if idx == 0 => counts[0] += 1,
            fdt::Status::Okay if idx == 1 => counts[1] += 1,
            // No status property defaults to Okay.
            fdt::Status::Okay if idx == 2 => counts[2] += 1,
            _ => {}
        }
    });
    if counts != [1, 1, 1] {
        return TestResult::Fail("status decoder mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_status_filter);

fn smoke_fdt_typed_props() -> TestResult {
    let mut u32_buf = Vec::new();
    u32_buf.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    let mut u64_buf = Vec::new();
    u64_buf.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
    let nodes = &[(
        "dev",
        &[
            ("freq", u32_buf.as_slice()),
            ("size", u64_buf.as_slice()),
            ("name", b"hello\0" as &[u8]),
            ("compatible", b"a,one\0a,two\0a,three\0" as &[u8]),
        ][..],
    )];
    let blob = build_blob(0, &[], &[], nodes);
    let mut saw_u32 = None;
    let mut saw_u64 = None;
    let mut saw_str = None;
    let mut compat_hits = 0u32;
    fdt::walk_nodes(&blob, |path, props| {
        if path.last_segment() != "dev" {
            return;
        }
        saw_u32 = fdt::prop_u32(props, "freq");
        saw_u64 = fdt::prop_u64(props, "size");
        saw_str = fdt::prop_str(props, "name").map(|s| {
            // copy into a stack-buf so we can compare across the
            // closure boundary without lifetimes.
            let mut owned = [0u8; 16];
            let n = s.len().min(owned.len());
            owned[..n].copy_from_slice(&s.as_bytes()[..n]);
            (owned, n)
        });
        fdt::prop_string_list(props, "compatible", |_s| compat_hits += 1);
    });
    if saw_u32 != Some(0xDEAD_BEEF) {
        return TestResult::Fail("prop_u32");
    }
    if saw_u64 != Some(0x1122_3344_5566_7788) {
        return TestResult::Fail("prop_u64");
    }
    let (buf, n) = saw_str.expect("prop_str");
    if &buf[..n] != b"hello" {
        return TestResult::Fail("prop_str payload");
    }
    if compat_hits != 3 {
        return TestResult::Fail("compat string-list count");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_typed_props);

fn smoke_fdt_discover_round_trip() -> TestResult {
    // Build a blob, take a raw pointer, hand it to `discover`, get a
    // 'static slice back, parse the header again — round-trip check.
    let blob = build_blob(0, &[], &[], &[]);
    let phys = blob.as_ptr() as usize;
    let max = blob.len();
    // SAFETY: blob outlives this call; pointer is to a Vec we own.
    let recovered = unsafe { fdt::discover(phys, max) }.expect("discover");
    if recovered.len() != blob.len() || recovered.as_ptr() != blob.as_ptr() {
        return TestResult::Fail("discover did not return the same slice");
    }
    if fdt::parse_header(recovered).is_none() {
        return TestResult::Fail("recovered header invalid");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_discover_round_trip);
