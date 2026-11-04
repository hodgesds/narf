//! `of_dma_is_coherent` inheritance and `shared-dma-pool` smokes.
extern crate alloc;
use crate as fdt;
use crate::pci::tests::{build_tree, TreeNode};
use alloc::vec::Vec;
use fdt::DmaCoherenceProp as C;
use narf_kernel_test::{kernel_test_in, TestResult};

const PCI: &[u8] = b"pci\0";
const REG0: &[u8] = &[0; 20];

fn be(cells: &[u32]) -> Vec<u8> {
    cells.iter().flat_map(|c| c.to_be_bytes()).collect()
}

/// Nearest marked node wins, `dma-coherent` beats `dma-noncoherent` on one
/// node, unmarked chains report the arch default and a `dma-mem`
/// interconnect parent is unresolved.
fn smoke_fdt_dma_coherent_inheritance() -> TestResult {
    let grandchild = [TreeNode {
        name: "child@0",
        props: &[],
        children: &[],
    }];
    let soc_children = [
        TreeNode {
            name: "dev@1",
            props: &[],
            children: &[],
        },
        TreeNode {
            name: "nc@2",
            props: &[("dma-noncoherent", &[])],
            children: &grandchild,
        },
        TreeNode {
            name: "both@3",
            props: &[("dma-noncoherent", &[]), ("dma-coherent", &[])],
            children: &[],
        },
        TreeNode {
            name: "ic@4",
            props: &[("interconnect-names", b"cpu\0dma-mem\0")],
            children: &[],
        },
    ];
    let tree = [
        TreeNode {
            name: "soc",
            props: &[("dma-coherent", &[])],
            children: &soc_children,
        },
        TreeNode {
            name: "plain@5",
            props: &[],
            children: &grandchild,
        },
    ];
    let blob = build_tree(&tree);
    let got = |path: &[&str]| fdt::node_dma_coherence(&blob, path);
    let checks = [
        (got(&["soc"]), Some(C::Coherent)),
        (got(&["soc", "dev@1"]), Some(C::Coherent)),
        (got(&["soc", "nc@2"]), Some(C::NonCoherent)),
        (got(&["soc", "nc@2", "child@0"]), Some(C::NonCoherent)),
        (got(&["soc", "both@3"]), Some(C::Coherent)),
        (got(&["soc", "ic@4"]), Some(C::Unresolved)),
        (got(&["plain@5", "child@0"]), Some(C::Default)),
        (got(&["missing"]), None),
    ];
    if checks.iter().all(|(a, b)| a == b) {
        TestResult::Pass
    } else {
        TestResult::Fail("of_dma_is_coherent inheritance mismatch")
    }
}
kernel_test_in!("firmware/fdt", smoke_fdt_dma_coherent_inheritance);

/// A PCI function inherits its host bridge node's coherence
/// (`pci_dma_configure` → `of_dma_configure(bridge->parent->of_node)`).
fn smoke_fdt_pci_host_bridge_dma_coherence() -> TestResult {
    let endpoint = [TreeNode {
        name: "wifi@0",
        props: &[("reg", REG0), ("dma-noncoherent", &[])],
        children: &[],
    }];
    let bridges = [
        TreeNode {
            name: "pcie@1",
            props: &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 0])],
            children: &endpoint,
        },
        TreeNode {
            name: "pcie@2",
            props: &[
                ("device_type", PCI),
                ("linux,pci-domain", &[0, 0, 0, 1]),
                ("dma-noncoherent", &[]),
            ],
            children: &[],
        },
    ];
    let tree = [TreeNode {
        name: "soc",
        props: &[("dma-coherent", &[])],
        children: &bridges,
    }];
    let blob = build_tree(&tree);
    // The endpoint's own property is not consulted: Linux configures PCI
    // DMA from the host bridge node.
    if fdt::pci_host_bridge_dma_coherence(&blob, 0) != Some(C::Coherent)
        || fdt::pci_host_bridge_dma_coherence(&blob, 1) != Some(C::NonCoherent)
        || fdt::pci_host_bridge_dma_coherence(&blob, 2).is_some()
    {
        return TestResult::Fail("host bridge coherence not inherited");
    }
    let untagged = [TreeNode {
        name: "pcie@3",
        props: &[("device_type", PCI)],
        children: &endpoint,
    }];
    if fdt::pci_host_bridge_dma_coherence(&build_tree(&untagged), 7) != Some(C::Default) {
        return TestResult::Fail("single untagged bridge default");
    }
    let two = [
        TreeNode {
            name: "pcie@3",
            props: &[("device_type", PCI), ("dma-coherent", &[])],
            children: &[],
        },
        TreeNode {
            name: "pcie@4",
            props: &[("device_type", PCI), ("dma-coherent", &[])],
            children: &[],
        },
    ];
    if fdt::pci_host_bridge_dma_coherence(&build_tree(&two), 0).is_some() {
        return TestResult::Fail("ambiguous untagged bridges resolved");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_pci_host_bridge_dma_coherence);

/// `shared-dma-pool` acceptance (`no-map`, static, enabled, not
/// `reusable`), `linux,dma-default` (last wins) and a PCI function's
/// `memory-region` pool.
fn smoke_fdt_shared_dma_pool_and_memory_region() -> TestResult {
    let reg = |base: u32| be(&[0, base, 0, 0x10_0000]);
    let (ra, rb, rc, rd, re, rf, rg) = (
        reg(0x9000_0000),
        reg(0x9010_0000),
        reg(0x9020_0000),
        reg(0x9030_0000),
        reg(0x9040_0000),
        reg(0x9050_0000),
        reg(0x9060_0000),
    );
    const POOL: &[u8] = b"shared-dma-pool\0";
    let pools = [
        TreeNode {
            name: "pool@90000000",
            props: &[
                ("compatible", POOL),
                ("reg", &ra),
                ("no-map", &[]),
                ("phandle", &[0, 0, 0, 5]),
            ],
            children: &[],
        },
        TreeNode {
            name: "pool@90100000",
            props: &[
                ("compatible", POOL),
                ("reg", &rb),
                ("no-map", &[]),
                ("linux,dma-default", &[]),
                ("phandle", &[0, 0, 0, 6]),
            ],
            children: &[],
        },
        TreeNode {
            name: "mapped@90200000",
            props: &[
                ("compatible", POOL),
                ("reg", &rc),
                ("phandle", &[0, 0, 0, 7]),
            ],
            children: &[],
        },
        TreeNode {
            name: "cma@90300000",
            props: &[
                ("compatible", POOL),
                ("reg", &rd),
                ("reusable", &[]),
                ("phandle", &[0, 0, 0, 8]),
            ],
            children: &[],
        },
        TreeNode {
            name: "off@90400000",
            props: &[
                ("compatible", POOL),
                ("reg", &re),
                ("no-map", &[]),
                ("status", b"disabled\0"),
                ("phandle", &[0, 0, 0, 9]),
            ],
            children: &[],
        },
        TreeNode {
            name: "fw@90500000",
            props: &[
                ("compatible", b"vendor,fw\0"),
                ("reg", &rf),
                ("no-map", &[]),
                ("phandle", &[0, 0, 0, 10]),
            ],
            children: &[],
        },
        TreeNode {
            name: "pool@90600000",
            props: &[
                ("compatible", b"vendor,dma\0shared-dma-pool\0"),
                ("reg", &rg),
                ("no-map", &[]),
                ("linux,dma-default", &[]),
            ],
            children: &[],
        },
    ];
    let endpoint = [TreeNode {
        name: "wifi@0",
        props: &[("reg", REG0), ("memory-region", &[0, 0, 0, 5])],
        children: &[],
    }];
    let other = [TreeNode {
        name: "wifi@0",
        props: &[("reg", REG0), ("memory-region", &[0, 0, 0, 7])],
        children: &[],
    }];
    let tree = [
        TreeNode {
            name: "reserved-memory",
            props: &[
                ("#address-cells", &[0, 0, 0, 2]),
                ("#size-cells", &[0, 0, 0, 2]),
            ],
            children: &pools,
        },
        TreeNode {
            name: "pcie@1",
            props: &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 0])],
            children: &endpoint,
        },
        TreeNode {
            name: "pcie@2",
            props: &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 1])],
            children: &other,
        },
    ];
    let blob = build_tree(&tree);
    let a = fdt::SharedDmaPool {
        addr: 0x9000_0000,
        size: 0x10_0000,
        phandle: Some(5),
        default: false,
    };
    if fdt::shared_dma_pool(&blob, 5) != Some(a)
        || fdt::shared_dma_pool(&blob, 6).map(|p| p.default) != Some(true)
    {
        return TestResult::Fail("valid shared-dma-pool not resolved");
    }
    if (7..=10).any(|ph| fdt::shared_dma_pool(&blob, ph).is_some()) {
        return TestResult::Fail("mapped / reusable / disabled / foreign pool accepted");
    }
    if fdt::default_shared_dma_pool(&blob).map(|p| p.addr) != Some(0x9060_0000) {
        return TestResult::Fail("linux,dma-default redefinition not last-wins");
    }
    if fdt::pci_function_dma_pool(&blob, 0, &[0]) != Some(a)
        || fdt::pci_function_dma_pool(&blob, 1, &[0]).is_some()
        || fdt::pci_function_dma_pool(&blob, 0, &[8]).is_some()
    {
        return TestResult::Fail("PCI function memory-region pool");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_shared_dma_pool_and_memory_region);
