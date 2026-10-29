//! `pci_set_of_node` association and reserved-memory smokes.
extern crate alloc;
use crate as fdt;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A nested test tree node.
struct TreeNode<'a> {
    name: &'a str,
    props: &'a [(&'a str, &'a [u8])],
    children: &'a [TreeNode<'a>],
}

fn emit(s: &mut Vec<u8>, strings: &mut Vec<u8>, node: &TreeNode<'_>) {
    s.extend_from_slice(&fdt::FDT_BEGIN_NODE.to_be_bytes());
    s.extend_from_slice(node.name.as_bytes());
    s.push(0);
    while s.len() % 4 != 0 {
        s.push(0);
    }
    for (name, value) in node.props {
        let off = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        s.extend_from_slice(&fdt::FDT_PROP.to_be_bytes());
        s.extend_from_slice(&(value.len() as u32).to_be_bytes());
        s.extend_from_slice(&off.to_be_bytes());
        s.extend_from_slice(value);
        while s.len() % 4 != 0 {
            s.push(0);
        }
    }
    for child in node.children {
        emit(s, strings, child);
    }
    s.extend_from_slice(&fdt::FDT_END_NODE.to_be_bytes());
}

fn build_tree(root: &[TreeNode<'_>]) -> Vec<u8> {
    let mut s = Vec::new();
    let mut strings = Vec::new();
    let top = TreeNode {
        name: "",
        props: &[],
        children: root,
    };
    emit(&mut s, &mut strings, &top);
    s.extend_from_slice(&fdt::FDT_END.to_be_bytes());
    let off_struct = 40u32 + 16;
    let off_strings = off_struct + s.len() as u32;
    let total = off_strings + strings.len() as u32;
    let mut out = Vec::new();
    for v in [
        fdt::FDT_MAGIC,
        total,
        off_struct,
        off_strings,
        40,
        17,
        16,
        0,
        strings.len() as u32,
        s.len() as u32,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&s);
    out.extend_from_slice(&strings);
    out
}

const PCI: &[u8] = b"pci\0";
const REG0: &[u8] = &[0; 20];

/// Host bridge → root port (devfn 0) → endpoint (devfn 0), the endpoint's
/// calibration-variant and `memory-region`, the domain/ambiguity rules and
/// `/reserved-memory` resolution.
fn smoke_fdt_pci_function_node_and_reserved_memory() -> TestResult {
    let endpoint = [TreeNode {
        name: "wifi@0",
        props: &[
            ("reg", REG0),
            ("qcom,calibration-variant", b"LE_X13S\0"),
            ("memory-region", &[0, 0, 0, 7]),
        ],
        children: &[],
    }];
    let root_port = [TreeNode {
        name: "pcie@0",
        props: &[("device_type", PCI), ("reg", REG0)],
        children: &endpoint,
    }];
    let reserved = [TreeNode {
        name: "wlan@8c400000",
        props: &[
            (
                "reg",
                &[0, 0, 0, 0, 0x8c, 0x40, 0, 0, 0, 0, 0, 0, 0, 0x30, 0, 0],
            ),
            ("phandle", &[0, 0, 0, 7]),
            ("no-map", &[]),
        ],
        children: &[],
    }];
    let tree = [
        TreeNode {
            name: "reserved-memory",
            props: &[
                ("#address-cells", &[0, 0, 0, 2]),
                ("#size-cells", &[0, 0, 0, 2]),
            ],
            children: &reserved,
        },
        TreeNode {
            name: "pcie@1c08000",
            props: &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 4])],
            children: &root_port,
        },
    ];
    let blob = build_tree(&tree);
    let mut variant = None;
    let mut region = None;
    let found = fdt::for_pci_function(&blob, 4, &[0, 0], |path, props, _| {
        if path.last_segment() == "wifi@0" {
            variant = fdt::prop_str(props, "qcom,calibration-variant").map(|s| s.len());
            region = fdt::memory_region_phandle(props, 0);
        }
    });
    if !found || variant != Some(7) || region != Some(7) {
        return TestResult::Fail("endpoint node not associated");
    }
    if fdt::reserved_memory_region(&blob, 7) != Some((0x8c40_0000, 0x30_0000))
        || fdt::reserved_memory_region(&blob, 8).is_some()
    {
        return TestResult::Fail("reserved-memory phandle resolution");
    }
    if fdt::for_pci_function(&blob, 3, &[0, 0], |_, _, _| {})
        || fdt::for_pci_function(&blob, 4, &[0, 8], |_, _, _| {})
        || fdt::for_pci_function(&blob, 4, &[], |_, _, _| {})
    {
        return TestResult::Fail("wrong domain / devfn / empty path matched");
    }
    let untagged = [TreeNode {
        name: "pcie@1",
        props: &[("device_type", PCI)],
        children: &root_port,
    }];
    if !fdt::for_pci_function(&build_tree(&untagged), 0, &[0, 0], |_, _, _| {}) {
        return TestResult::Fail("single untagged host bridge refused");
    }
    let two = [
        TreeNode {
            name: "pcie@1",
            props: &[("device_type", PCI)],
            children: &root_port,
        },
        TreeNode {
            name: "pcie@2",
            props: &[("device_type", PCI)],
            children: &root_port,
        },
    ];
    if fdt::for_pci_function(&build_tree(&two), 0, &[0, 0], |_, _, _| {}) {
        return TestResult::Fail("ambiguous host bridges matched");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt",
    smoke_fdt_pci_function_node_and_reserved_memory
);

fn be(cells: &[u32]) -> Vec<u8> {
    cells.iter().flat_map(|c| c.to_be_bytes()).collect()
}
/// QEMU virt `create_pcie_irq_map`: slot s, pin p (1-based) -> SPI
/// 3 + (s + p - 1) % 4, level-high, through `&intc` (2 address cells).
fn virt_irq_map(parent: u32, controller_flags: u32) -> Vec<u32> {
    let mut map = Vec::new();
    for slot in 0..4u32 {
        for pin in 1..=4u32 {
            map.extend_from_slice(&[slot << 11, 0, 0, pin, parent, 0, 0]);
            map.extend_from_slice(&[0, 3 + (slot + pin - 1) % 4, controller_flags]);
        }
    }
    map
}
fn smoke_fdt_pci_intx_interrupt_map_matches_linux() -> TestResult {
    let map = be(&virt_irq_map(0x8003, 4));
    let mask = be(&[0x1800, 0, 0, 7]);
    let gic = TreeNode {
        name: "intc@8000000",
        props: &[
            ("phandle", &[0, 0, 0x80, 3]),
            ("#address-cells", &[0, 0, 0, 2]),
            ("#interrupt-cells", &[0, 0, 0, 3]),
            ("interrupt-controller", &[]),
        ],
        children: &[],
    };
    let pcie = TreeNode {
        name: "pcie@10000000",
        props: &[
            ("device_type", b"pci\0"),
            ("#address-cells", &[0, 0, 0, 3]),
            ("#interrupt-cells", &[0, 0, 0, 1]),
            ("linux,pci-domain", &[0, 0, 0, 0]),
            ("interrupt-map-mask", &mask),
            ("interrupt-map", &map),
        ],
        children: &[],
    };
    let blob = build_tree(&[gic, pcie]);
    // Slot 2 function 1, INTB: SPI 3 + (2 + 1) % 4 = 6 -> INTID 38, level.
    let devfn = (2 << 3) | 1;
    let Some(route) = fdt::pci::intx_route(&blob, 0, 0, devfn, 2) else {
        return TestResult::Fail("virt interrupt-map entry not resolved");
    };
    if route.parent != 0x8003
        || route.cells != 3
        || route.specifier[..3] != [0, 6, 4]
        || fdt::pci::gic_spi(&route) != Some((38, true))
    {
        return TestResult::Fail("interrupt-map specifier/GIC INTID differs from of_irq_parse_raw");
    }
    for (slot, pin, spi) in [(0u8, 1u8, 3u32), (1, 4, 3), (3, 3, 4)] {
        let route = fdt::pci::intx_route(&blob, 0, 0, slot << 3, pin);
        if route.and_then(|r| fdt::pci::gic_spi(&r)) != Some((32 + spi, true)) {
            return TestResult::Fail("interrupt-map rotation differs from QEMU virt");
        }
    }
    if fdt::pci::intx_route(&blob, 0, 0, 0, 0).is_some()
        || fdt::pci::intx_route(&blob, 1, 0, 0, 1).is_some()
    {
        return TestResult::Fail("pin 0 or a foreign domain resolved");
    }
    // The mask keeps two slot bits, so slot 4 wraps to slot 0 as in Linux.
    if fdt::pci::intx_route(&blob, 0, 0, 4 << 3, 1).and_then(|r| fdt::pci::gic_spi(&r))
        != Some((35, true))
    {
        return TestResult::Fail("interrupt-map-mask not applied to the slot bits");
    }
    // Unsupported sense (level-low) is refused by the GIC translation.
    let low = fdt::pci::IntxRoute {
        parent: 0x8003,
        specifier: [0, 3, 8, 0],
        cells: 3,
    };
    if fdt::pci::gic_spi(&low).is_some() {
        return TestResult::Fail("level-low SPI accepted");
    }
    // A parent that is not an interrupt controller (nested nexus) is refused.
    let nexus = TreeNode {
        name: "nexus",
        props: &[
            ("phandle", &[0, 0, 0x80, 3]),
            ("#address-cells", &[0, 0, 0, 2]),
            ("#interrupt-cells", &[0, 0, 0, 3]),
        ],
        children: &[],
    };
    let pcie = TreeNode {
        name: "pcie@10000000",
        props: &[
            ("device_type", b"pci\0"),
            ("#address-cells", &[0, 0, 0, 3]),
            ("#interrupt-cells", &[0, 0, 0, 1]),
            ("interrupt-map-mask", &mask),
            ("interrupt-map", &map),
        ],
        children: &[],
    };
    let blob = build_tree(&[nexus, pcie]);
    if fdt::pci::intx_route(&blob, 0, 0, 0, 1).is_some() {
        return TestResult::Fail("nested interrupt nexus resolved as a controller");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt/pci",
    smoke_fdt_pci_intx_interrupt_map_matches_linux
);
