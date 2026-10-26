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

    for (node_path, props) in nodes {
        let mut opened = 0;
        for node_name in node_path.split('/') {
            s.extend_from_slice(&fdt::FDT_BEGIN_NODE.to_be_bytes());
            s.extend_from_slice(node_name.as_bytes());
            s.push(0);
            while s.len() % 4 != 0 {
                s.push(0);
            }
            opened += 1;
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

        for _ in 0..opened {
            s.extend_from_slice(&fdt::FDT_END_NODE.to_be_bytes());
        }
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

fn smoke_fdt_header_rejects_incompatible_or_oob_layout() -> TestResult {
    let blob = build_blob(0, &[], &[], &[]);
    let mut old = blob.clone();
    old[20..24].copy_from_slice(&16u32.to_be_bytes());
    if fdt::parse_header(&old).is_some() {
        return TestResult::Fail("accepted pre-v17 blob");
    }
    let mut oob = blob;
    let beyond = (oob.len() as u32 + 4).to_be_bytes();
    oob[36..40].copy_from_slice(&beyond);
    if fdt::parse_header(&oob).is_some() {
        return TestResult::Fail("accepted out-of-bounds structure block");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt",
    smoke_fdt_header_rejects_incompatible_or_oob_layout
);

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

/// The guest cmdline xtask builds on an affected-filter test run
/// (#960): a ~430-byte `test_subsystem=` include list followed by the
/// `test_subsystem_exclude=` token. The exclude token starts past
/// byte 440, so the old 256-byte `chosen_bootargs` cap silently
/// dropped it (and the last wanted subsystems) on the FDT path.
fn affected_filter_append() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"test_subsystem=");
    v.extend_from_slice(b"aarch64,audio,bluetooth,drivers/gpu,drivers/graphics,drivers/input,drivers/sound,drivers/usb,drivers/virtio,drivers/wireless/ath10k,drivers/wireless/ath11k,drivers/wireless/ath9k,drivers/wireless/brcmfmac,drivers/wireless/cyw43439,drivers/wireless/e2e,drivers/wireless/iwlwifi,drivers/wireless/qualcomm,drivers/wireless/rtl8xxxu,drivers/wireless/rtlwifi,drivers/wireless/rtw88,drivers/wireless/rtw89,fb,frame,verification,wireless");
    v.extend_from_slice(b" test_subsystem_exclude=drivers/gpu");
    v
}

fn smoke_fdt_chosen_bootargs_long_append_survives() -> TestResult {
    let append = affected_filter_append();
    // Shape sanity: the append must actually exercise the old cap —
    // the exclude token has to start past byte 255.
    let exclude_len = b"test_subsystem_exclude=drivers/gpu".len();
    if append.len() <= 256 || append.len() - exclude_len <= 255 {
        return TestResult::Fail("fixture append does not cross the old 256-byte cap");
    }
    let mut value = append.clone();
    value.push(0);
    let nodes = &[("chosen", &[("bootargs", value.as_slice())][..])];
    let blob = build_blob(0, &[], &[], nodes);
    let bargs = fdt::chosen_bootargs(&blob).expect("bootargs");
    if bargs.len() != append.len() {
        return TestResult::Fail("long bootargs truncated at the FDT layer");
    }
    if bargs.as_bytes() != append.as_slice() {
        return TestResult::Fail("long bootargs content mismatch");
    }
    if !bargs
        .as_str()
        .ends_with("test_subsystem_exclude=drivers/gpu")
    {
        return TestResult::Fail("trailing exclude token lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt",
    smoke_fdt_chosen_bootargs_long_append_survives
);

fn smoke_fdt_chosen_bootargs_oversized_clips_at_cap() -> TestResult {
    // A bootargs past BOOTARGS_CAP is clipped to exactly the cap.
    // That exact-width result is the signal the boot store's
    // truncation warning relies on (its keep-limit is one byte below
    // the cap, so a clipped value can never fit silently).
    let mut value = Vec::new();
    value.resize(fdt::BOOTARGS_CAP + 64, b'a');
    value.push(0);
    let nodes = &[("chosen", &[("bootargs", value.as_slice())][..])];
    let blob = build_blob(0, &[], &[], nodes);
    let bargs = fdt::chosen_bootargs(&blob).expect("bootargs");
    if bargs.len() != fdt::BOOTARGS_CAP {
        return TestResult::Fail("oversized bootargs not clipped at BOOTARGS_CAP");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt",
    smoke_fdt_chosen_bootargs_oversized_clips_at_cap
);

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

fn smoke_fdt_reserved_memory_static_ranges() -> TestResult {
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x7800_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x0080_0000u32.to_be_bytes());
    let nodes = &[(
        "reserved-memory/framebuffer@78000000",
        &[
            ("reg", reg.as_slice()),
            ("no-map", &[] as &[u8]),
            ("compatible", b"shared-dma-pool\0" as &[u8]),
        ][..],
    )];
    let blob = build_blob(0, &[], &[], nodes);
    let mut out = [fdt::ReservedRegion::default(); 2];
    let n = fdt::copy_reserved_memory_ranges(&blob, &mut out);
    if n != 1
        || out[0].addr != 0x7800_0000
        || out[0].size != 0x0080_0000
        || !out[0].no_map
        || out[0].reusable
    {
        return TestResult::Fail("reserved-memory static range mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_reserved_memory_static_ranges);

fn smoke_fdt_reserved_memory_rejects_conflicting_flags() -> TestResult {
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x7900_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x0010_0000u32.to_be_bytes());
    let nodes = &[(
        "reserved-memory/bad@79000000",
        &[
            ("reg", reg.as_slice()),
            ("no-map", &[] as &[u8]),
            ("reusable", &[] as &[u8]),
        ][..],
    )];
    let blob = build_blob(0, &[], &[], nodes);
    let mut out = [fdt::ReservedRegion::default(); 1];
    if fdt::copy_reserved_memory_ranges(&blob, &mut out) != 0 {
        return TestResult::Fail("accepted no-map plus reusable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt",
    smoke_fdt_reserved_memory_rejects_conflicting_flags
);

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

fn smoke_fdt_interrupts_extended_multiple_domains() -> TestResult {
    let phandle_a = 7u32.to_be_bytes();
    let cells_a = 2u32.to_be_bytes();
    let phandle_b = 9u32.to_be_bytes();
    let cells_b = 1u32.to_be_bytes();
    let mut extended = Vec::new();
    for cell in [7u32, 10, 8, 9, 218] {
        extended.extend_from_slice(&cell.to_be_bytes());
    }
    let nodes = &[
        (
            "pic@1000",
            &[
                ("phandle", &phandle_a[..]),
                ("#interrupt-cells", &cells_a[..]),
                ("interrupt-controller", &[] as &[u8]),
            ][..],
        ),
        (
            "gic@2000",
            &[
                ("phandle", &phandle_b[..]),
                ("#interrupt-cells", &cells_b[..]),
                ("interrupt-controller", &[] as &[u8]),
            ][..],
        ),
        (
            "device@3000",
            &[("interrupts-extended", extended.as_slice())][..],
        ),
    ];
    let blob = build_blob(0, &[], &[], nodes);
    let mut hits = 0;
    fdt::walk_nodes(&blob, |path, props| {
        if path.last_segment() != "device@3000" {
            return;
        }
        fdt::for_each_interrupt(&blob, props, None, |parent, cells| {
            match hits {
                0 if parent == 7 && cells == [10, 8] => {}
                1 if parent == 9 && cells == [218] => {}
                _ => hits = 99,
            }
            hits += 1;
        });
    });
    if hits != 2 {
        return TestResult::Fail("interrupts-extended decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt",
    smoke_fdt_interrupts_extended_multiple_domains
);

fn smoke_fdt_interrupts_extended_precedes_legacy() -> TestResult {
    let phandle = 3u32.to_be_bytes();
    let cells = 1u32.to_be_bytes();
    let mut extended = Vec::new();
    extended.extend_from_slice(&3u32.to_be_bytes());
    extended.extend_from_slice(&55u32.to_be_bytes());
    let legacy = 99u32.to_be_bytes();
    let nodes = &[
        (
            "intc",
            &[("phandle", &phandle[..]), ("#interrupt-cells", &cells[..])][..],
        ),
        (
            "device",
            &[
                ("interrupts-extended", extended.as_slice()),
                ("interrupts", &legacy[..]),
                ("interrupt-parent", &phandle[..]),
            ][..],
        ),
    ];
    let blob = build_blob(0, &[], &[], nodes);
    let mut value = 0;
    fdt::walk_nodes(&blob, |path, props| {
        if path.last_segment() == "device" {
            fdt::for_each_interrupt(&blob, props, None, |_parent, spec| value = spec[0]);
        }
    });
    if value != 55 {
        return TestResult::Fail("legacy interrupts overrode extended");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt",
    smoke_fdt_interrupts_extended_precedes_legacy
);

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

// ───────────────────────────────────────────────────────────────────
// Real-blob fixture smokes.
//
// The smokes above build synthetic blobs in code, which risks
// mirroring the parser's own assumptions. The smokes below pin the
// parser against a real DTB emitted by QEMU for its `virt` machine
// (`tests/fixtures/qemu-virt.dtb`; see that directory's README for
// provenance): GICv3 interrupt specifiers, a two-bank CFI flash
// `reg`, root `#size-cells = 2`, a 32-slot virtio-mmio fleet, and a
// `/chosen` with `stdout-path` but no `bootargs`.
// ───────────────────────────────────────────────────────────────────

const QEMU_VIRT_DTB: &[u8] = include_bytes!("../tests/fixtures/qemu-virt.dtb");

/// Phandle of QEMU virt's GICv3 (`/intc@8000000`), also the root's
/// `interrupt-parent`.
const QEMU_VIRT_GIC_PHANDLE: u32 = 0x8005;

fn smoke_fdt_real_qemu_virt_header() -> TestResult {
    let hdr = match fdt::parse_header(QEMU_VIRT_DTB) {
        Some(h) => h,
        None => return TestResult::Fail("QEMU virt DTB did not validate"),
    };
    if hdr.magic != fdt::FDT_MAGIC {
        return TestResult::Fail("magic");
    }
    if hdr.totalsize as usize != QEMU_VIRT_DTB.len() {
        return TestResult::Fail("totalsize != fixture length");
    }
    if hdr.version != 17 || hdr.last_comp_version != 16 {
        return TestResult::Fail("version");
    }
    if hdr.boot_cpuid_phys != 0 {
        return TestResult::Fail("boot cpu");
    }
    if hdr.off_mem_rsvmap != 48 || hdr.off_dt_struct != 64 {
        return TestResult::Fail("block offsets");
    }
    if hdr.size_dt_struct != 7464 || hdr.off_dt_strings != 7528 || hdr.size_dt_strings != 495 {
        return TestResult::Fail("block sizes");
    }
    // The reserve map is a lone terminator pair in this blob.
    let mut rsv = [Reservation::default(); 4];
    if fdt::copy_reservations(QEMU_VIRT_DTB, &mut rsv) != 0 {
        return TestResult::Fail("reserve map not empty");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_header);

fn smoke_fdt_real_qemu_virt_census() -> TestResult {
    let mut count = 0usize;
    let mut max_depth = 0u8;
    fdt::walk_nodes(QEMU_VIRT_DTB, |path, _props| {
        count += 1;
        if path.depth() > max_depth {
            max_depth = path.depth();
        }
    });
    // 62 nodes total; the walker does not call back for the root.
    if count != 61 {
        return TestResult::Fail("node census != 61");
    }
    // /cpus/cpu-map/socket0/cluster0/coreN is the deepest chain.
    if max_depth != 5 {
        return TestResult::Fail("max depth != 5");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_census);

fn smoke_fdt_real_qemu_virt_memory() -> TestResult {
    let mut out = [Reservation::default(); 4];
    let n = fdt::copy_memory_ranges(QEMU_VIRT_DTB, &mut out);
    if n != 1 {
        return TestResult::Fail("memory range count != 1");
    }
    // -m 1024: 1 GiB at 0x4000_0000. Decoding this requires the
    // root's #address-cells = 2 / #size-cells = 2.
    if out[0].addr != 0x4000_0000 || out[0].size != 0x4000_0000 {
        return TestResult::Fail("memory range mismatch");
    }
    // No /reserved-memory node in this blob.
    let mut reserved = [fdt::ReservedRegion::default(); 4];
    if fdt::copy_reserved_memory_ranges(QEMU_VIRT_DTB, &mut reserved) != 0 {
        return TestResult::Fail("reserved-memory not empty");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_memory);

fn smoke_fdt_real_qemu_virt_chosen() -> TestResult {
    let mut stdout = [0u8; 64];
    let n = fdt::chosen_stdout_path(QEMU_VIRT_DTB, &mut stdout);
    if &stdout[..n] != b"/pl011@9000000" {
        return TestResult::Fail("stdout-path mismatch");
    }
    // The blob carries no bootargs and no initrd properties.
    if fdt::chosen_bootargs(QEMU_VIRT_DTB).is_some() {
        return TestResult::Fail("unexpected bootargs");
    }
    if fdt::chosen_initrd_range(QEMU_VIRT_DTB).is_some() {
        return TestResult::Fail("unexpected initrd range");
    }
    // No /aliases node in this blob.
    let mut alias = [0u8; 64];
    if fdt::alias_path(QEMU_VIRT_DTB, "serial0", &mut alias) != 0 {
        return TestResult::Fail("unexpected alias");
    }
    // stdout-path resolves to the PL011's reg window.
    if fdt::chosen_stdout_reg(QEMU_VIRT_DTB) != Some((0x0900_0000, 0x1000)) {
        return TestResult::Fail("stdout-path did not resolve to the PL011 reg");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_chosen);

fn smoke_fdt_chosen_stdout_reg_forms() -> TestResult {
    // Root cells 1/1 so the fixture UARTs' `reg` decodes as
    // (addr, size) u32 pairs.
    let root_props: &[(&str, &[u8])] = &[
        ("#address-cells", &[0, 0, 0, 1]),
        ("#size-cells", &[0, 0, 0, 1]),
    ];
    // Alias label + ":params" suffix form.
    let alias_form = &[
        ("aliases", &[("serial0", b"/uart@1000\0" as &[u8])][..]),
        (
            "chosen",
            &[("stdout-path", b"serial0:115200n8\0" as &[u8])][..],
        ),
        (
            "uart@1000",
            &[("reg", &[0u8, 0, 0x10, 0x00, 0, 0, 0x01, 0x00] as &[u8])][..],
        ),
    ];
    let blob = build_blob(0, &[], root_props, alias_form);
    if fdt::chosen_stdout_reg(&blob) != Some((0x1000, 0x100)) {
        return TestResult::Fail("alias+params stdout-path did not resolve");
    }
    // Bare full-path form.
    let path_form = &[
        ("chosen", &[("stdout-path", b"/uart@2000\0" as &[u8])][..]),
        (
            "uart@2000",
            &[("reg", &[0u8, 0, 0x20, 0x00, 0, 0, 0x00, 0x80] as &[u8])][..],
        ),
    ];
    let blob = build_blob(0, &[], root_props, path_form);
    if fdt::chosen_stdout_reg(&blob) != Some((0x2000, 0x80)) {
        return TestResult::Fail("full-path stdout-path did not resolve");
    }
    // No /chosen at all.
    let blob = build_blob(0, &[], root_props, &[]);
    if fdt::chosen_stdout_reg(&blob).is_some() {
        return TestResult::Fail("stdout reg without /chosen");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_chosen_stdout_reg_forms);

fn smoke_fdt_real_qemu_virt_pl011() -> TestResult {
    let mut hits = 0usize;
    let mut failure: Option<&'static str> = None;
    fdt::for_each_compatible(QEMU_VIRT_DTB, "arm,pl011", |path, props, parent_cells| {
        hits += 1;
        if path.last_segment() != "pl011@9000000" {
            failure = Some("pl011 path");
            return;
        }
        if fdt::node_status(props) != fdt::Status::Okay {
            failure = Some("pl011 status");
            return;
        }
        let mut reg = None;
        for (name, value) in props {
            if name == "reg" {
                reg = parent_cells.read_one_reg(value, 0);
            }
        }
        if reg != Some((0x0900_0000, 0x1000)) {
            failure = Some("pl011 reg");
            return;
        }
        // Legacy `interrupts`: parent inherited from the root's
        // interrupt-parent; GIC 3-cell specifier (SPI, IRQ 1,
        // level-high).
        let mut n_specs = 0usize;
        let mut spec: (u32, [u32; 3]) = (0, [0; 3]);
        fdt::for_each_interrupt(
            QEMU_VIRT_DTB,
            props,
            Some(QEMU_VIRT_GIC_PHANDLE),
            |parent, cells| {
                n_specs += 1;
                if cells.len() == 3 {
                    spec.0 = parent;
                    spec.1.copy_from_slice(cells);
                }
            },
        );
        if n_specs != 1 || spec != (QEMU_VIRT_GIC_PHANDLE, [0, 1, 4]) {
            failure = Some("pl011 interrupt spec");
        }
    });
    if let Some(why) = failure {
        return TestResult::Fail(why);
    }
    if hits != 1 {
        return TestResult::Fail("pl011 hit count != 1");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_pl011);

fn smoke_fdt_real_qemu_virt_gic() -> TestResult {
    let mut hits = 0usize;
    let mut failure: Option<&'static str> = None;
    fdt::for_phandle(
        QEMU_VIRT_DTB,
        QEMU_VIRT_GIC_PHANDLE,
        |_path, props, _cells| {
            hits += 1;
            let mut gic_v3 = false;
            for (name, value) in props {
                if name == "compatible" {
                    gic_v3 = fdt::compatible_matches(value, "arm,gic-v3");
                }
            }
            if !gic_v3 {
                failure = Some("phandle node is not the GICv3");
                return;
            }
            if fdt::prop_interrupt_cells(props) != Some(3) {
                failure = Some("gic #interrupt-cells != 3");
            }
        },
    );
    if let Some(why) = failure {
        return TestResult::Fail(why);
    }
    if hits != 1 {
        return TestResult::Fail("gic hit count != 1");
    }
    if fdt::interrupt_cells_for(QEMU_VIRT_DTB, QEMU_VIRT_GIC_PHANDLE) != Some(3) {
        return TestResult::Fail("interrupt_cells_for != 3");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_gic);

fn smoke_fdt_real_qemu_virt_virtio_fleet() -> TestResult {
    let mut count = 0usize;
    let mut first = None;
    let mut last = None;
    fdt::for_each_compatible(
        QEMU_VIRT_DTB,
        "virtio,mmio",
        |_path, props, parent_cells| {
            count += 1;
            for (name, value) in props {
                if name == "reg" {
                    let decoded = parent_cells.read_one_reg(value, 0);
                    if first.is_none() {
                        first = decoded;
                    }
                    last = decoded;
                }
            }
        },
    );
    if count != 32 {
        return TestResult::Fail("virtio-mmio count != 32");
    }
    if first != Some((0x0a00_0000, 0x200)) {
        return TestResult::Fail("first virtio-mmio reg");
    }
    if last != Some((0x0a00_3e00, 0x200)) {
        return TestResult::Fail("last virtio-mmio reg");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_virtio_fleet);

fn smoke_fdt_real_qemu_virt_cpus_psci() -> TestResult {
    let mut cpus = 0usize;
    let mut failure: Option<&'static str> = None;
    fdt::walk_with_cells(QEMU_VIRT_DTB, |path, props, parent_cells| {
        if path.depth() != 2 || path.segment(0) != Some("cpus") {
            return;
        }
        let name = path.last_segment();
        if !name.starts_with("cpu@") {
            return;
        }
        cpus += 1;
        if name == "cpu@0" {
            if fdt::prop_str(props, "enable-method") != Some("psci") {
                failure = Some("cpu@0 enable-method != psci");
                return;
            }
            // /cpus declares #address-cells = 1, #size-cells = 0.
            let mut reg = None;
            for (pname, value) in props {
                if pname == "reg" {
                    reg = parent_cells.read_one_reg(value, 0);
                }
            }
            if reg != Some((0, 0)) {
                failure = Some("cpu@0 reg != (0, 0)");
            }
        }
    });
    if let Some(why) = failure {
        return TestResult::Fail(why);
    }
    if cpus != 4 {
        return TestResult::Fail("cpu count != 4");
    }
    let mut psci = 0usize;
    fdt::for_each_compatible(QEMU_VIRT_DTB, "arm,psci-1.0", |_path, props, _cells| {
        psci += 1;
        if fdt::prop_str(props, "method") != Some("hvc") {
            failure = Some("psci method != hvc");
        }
    });
    if let Some(why) = failure {
        return TestResult::Fail(why);
    }
    if psci != 1 {
        return TestResult::Fail("psci hit count != 1");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_cpus_psci);

fn smoke_fdt_real_qemu_virt_flash() -> TestResult {
    let mut hits = 0usize;
    let mut failure: Option<&'static str> = None;
    fdt::for_each_compatible(QEMU_VIRT_DTB, "cfi-flash", |_path, props, parent_cells| {
        hits += 1;
        let mut banks: [(u64, u64); 4] = [(0, 0); 4];
        let mut n_banks = 0usize;
        for (name, value) in props {
            if name == "reg" {
                let stride = parent_cells.entry_bytes();
                let mut off = 0;
                while off + stride <= value.len() && n_banks < banks.len() {
                    match parent_cells.read_one_reg(value, off) {
                        Some(entry) => {
                            banks[n_banks] = entry;
                            n_banks += 1;
                        }
                        None => {
                            failure = Some("flash reg entry undecodable");
                            return;
                        }
                    }
                    off += stride;
                }
            }
        }
        if n_banks != 2 || banks[0] != (0x0, 0x400_0000) || banks[1] != (0x400_0000, 0x400_0000) {
            failure = Some("flash banks mismatch");
        }
    });
    if let Some(why) = failure {
        return TestResult::Fail(why);
    }
    if hits != 1 {
        return TestResult::Fail("flash hit count != 1");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_flash);

fn smoke_fdt_real_qemu_virt_rejects_corruption() -> TestResult {
    // Truncated: totalsize (8023) exceeds the slice.
    let truncated = &QEMU_VIRT_DTB[..100];
    if fdt::parse_header(truncated).is_some() {
        return TestResult::Fail("truncated blob accepted");
    }
    let mut ranges = [Reservation::default(); 2];
    if fdt::copy_memory_ranges(truncated, &mut ranges) != 0 {
        return TestResult::Fail("truncated blob yielded ranges");
    }
    // Bad magic.
    let mut corrupt: Vec<u8> = Vec::new();
    corrupt.extend_from_slice(QEMU_VIRT_DTB);
    corrupt[0] ^= 0xff;
    if fdt::parse_header(&corrupt).is_some() {
        return TestResult::Fail("bad-magic blob accepted");
    }
    let mut count = 0usize;
    fdt::walk_nodes(&corrupt, |_path, _props| count += 1);
    if count != 0 {
        return TestResult::Fail("bad-magic blob yielded nodes");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_real_qemu_virt_rejects_corruption);
