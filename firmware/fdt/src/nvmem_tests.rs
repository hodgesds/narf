//! `of_nvmem_cell_get` over `nvmem-rmem` fixed-layout smokes.
extern crate alloc;
use crate as fdt;
use crate::pci::tests::{build_tree, TreeNode};
use alloc::vec::Vec;
use fdt::{NvmemError as E, RmemCell};
use narf_kernel_test::{kernel_test_in, TestResult};

fn be(cells: &[u32]) -> Vec<u8> {
    cells.iter().flat_map(|c| c.to_be_bytes()).collect()
}

/// Resolve `id` against a consumer node `/consumer` in `blob`.
fn lookup(blob: &[u8], id: &str) -> Option<Result<RmemCell, E>> {
    let mut out = None;
    fdt::walk_nodes(blob, |path, props| {
        if path.matches(&["consumer"]) {
            out = Some(fdt::rmem_cell(blob, props, id));
        }
    });
    out
}

/// Builds `/reserved-memory/eeprom@50000000` (`nvmem-rmem`, 64 KiB) with an
/// `nvmem-layout` holding `extra` plus `cal@1000` (phandle 5) and
/// `precal@0` (phandle 6, `#nvmem-cell-cells = <1>`), a legacy direct
/// child (phandle 7) and a `/soc/efuse` cell (phandle 8, no provider).
fn tree(
    rmem_props: &[(&str, &[u8])],
    layout_compat: &[u8],
    extra: &[TreeNode<'_>],
    consumer: &[(&str, &[u8])],
) -> Vec<u8> {
    let cal_reg = be(&[0x1000, 0x844]);
    let pre_reg = be(&[0, 0x3000]);
    let bits = be(&[4, 8]);
    let cal_props: [(&str, &[u8]); 2] = [("reg", &cal_reg), ("phandle", &[0, 0, 0, 5])];
    let pre_props: [(&str, &[u8]); 4] = [
        ("reg", &pre_reg),
        ("phandle", &[0, 0, 0, 6]),
        ("#nvmem-cell-cells", &[0, 0, 0, 1]),
        ("bits", &bits),
    ];
    let mut cells = Vec::new();
    cells.push(TreeNode {
        name: "cal@1000",
        props: &cal_props,
        children: &[],
    });
    cells.push(TreeNode {
        name: "precal@0",
        props: &pre_props,
        children: &[],
    });
    for node in extra {
        cells.push(TreeNode {
            name: node.name,
            props: node.props,
            children: &[],
        });
    }
    let layout_props: &[(&str, &[u8])] = &[
        ("compatible", layout_compat),
        ("#address-cells", &[0, 0, 0, 1]),
        ("#size-cells", &[0, 0, 0, 1]),
    ];
    let legacy_reg = be(&[0x4000, 4]);
    let rmem_children = [
        TreeNode {
            name: "nvmem-layout",
            props: layout_props,
            children: &cells,
        },
        TreeNode {
            name: "legacy@4000",
            props: &[("reg", &legacy_reg), ("phandle", &[0, 0, 0, 7])],
            children: &[],
        },
    ];
    let rmem = [TreeNode {
        name: "eeprom@50000000",
        props: rmem_props,
        children: &rmem_children,
    }];
    let efuse_cell = [TreeNode {
        name: "cal@0",
        props: &[("reg", &cal_reg), ("phandle", &[0, 0, 0, 8])],
        children: &[],
    }];
    let efuse = [TreeNode {
        name: "efuse@1000",
        props: &[("compatible", b"qcom,qfprom\0")],
        children: &efuse_cell,
    }];
    build_tree(&[
        TreeNode {
            name: "reserved-memory",
            props: &[
                ("#address-cells", &[0, 0, 0, 2]),
                ("#size-cells", &[0, 0, 0, 2]),
            ],
            children: &rmem,
        },
        TreeNode {
            name: "soc",
            props: &[],
            children: &efuse,
        },
        TreeNode {
            name: "consumer",
            props: consumer,
            children: &[],
        },
    ])
}

const RMEM_REG: &[u8] = &[0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0];

/// Named lookup through `#nvmem-cell-cells`, fixed-layout cell `reg`/`bits`,
/// the rmem static region, and Linux's ENOENT / EINVAL / EPROBE_DEFER
/// classification for missing names, extra args, legacy cells, foreign
/// providers, disabled/dynamic regions, other layouts and broken siblings.
fn smoke_fdt_nvmem_rmem_fixed_layout_cells() -> TestResult {
    let rmem: &[(&str, &[u8])] = &[("compatible", b"nvmem-rmem\0"), ("reg", RMEM_REG)];
    let cells = be(&[6, 0, 5, 7, 8]);
    let consumer: &[(&str, &[u8])] = &[
        ("nvmem-cells", &cells),
        (
            "nvmem-cell-names",
            b"pre-calibration\0calibration\0legacy\0efuse\0",
        ),
    ];
    let blob = tree(rmem, b"fixed-layout\0", &[], consumer);
    if lookup(&blob, "calibration")
        != Some(Ok(RmemCell {
            base: 0x5000_0000,
            size: 0x1_0000,
            offset: 0x1000,
            bytes: 0x844,
            bits: None,
        }))
    {
        return TestResult::Fail("named fixed-layout cell after an argument cell");
    }
    if lookup(&blob, "pre-calibration")
        != Some(Ok(RmemCell {
            base: 0x5000_0000,
            size: 0x1_0000,
            offset: 0,
            bytes: 0x3000,
            bits: Some((4, 8)),
        }))
    {
        return TestResult::Fail("argument cell / bits");
    }
    if lookup(&blob, "missing") != Some(Err(E::NotFound))
        || lookup(&blob, "legacy") != Some(Err(E::NotFound))
        || lookup(&blob, "efuse") != Some(Err(E::ProviderUnavailable))
    {
        return TestResult::Fail("ENOENT / legacy / foreign provider");
    }
    let truncated = be(&[6]);
    let short = tree(
        rmem,
        b"fixed-layout\0",
        &[],
        &[
            ("nvmem-cells", &truncated),
            ("nvmem-cell-names", b"pre-calibration\0"),
        ],
    );
    if lookup(&short, "pre-calibration") != Some(Err(E::NotFound)) {
        return TestResult::Fail("truncated phandle args resolved");
    }
    let disabled: &[(&str, &[u8])] = &[
        ("compatible", b"nvmem-rmem\0"),
        ("reg", RMEM_REG),
        ("status", b"disabled\0"),
    ];
    let dynamic: &[(&str, &[u8])] = &[
        ("compatible", b"nvmem-rmem\0"),
        ("size", &[0, 0, 0, 0, 0, 1, 0, 0]),
    ];
    for props in [disabled, dynamic] {
        if lookup(
            &tree(props, b"fixed-layout\0", &[], consumer),
            "calibration",
        ) != Some(Err(E::ProviderUnavailable))
        {
            return TestResult::Fail("disabled / dynamic rmem registered");
        }
    }
    if lookup(
        &tree(rmem, b"onie,tlv-layout\0", &[], consumer),
        "calibration",
    ) != Some(Err(E::ProviderUnavailable))
    {
        return TestResult::Fail("non-fixed layout resolved");
    }
    let bad_reg = be(&[0x2000]);
    let broken = [TreeNode {
        name: "bad@2000",
        props: &[("reg", &bad_reg)],
        children: &[],
    }];
    if lookup(
        &tree(rmem, b"fixed-layout\0", &broken, consumer),
        "calibration",
    ) != Some(Err(E::ProviderUnavailable))
    {
        return TestResult::Fail("malformed sibling did not fail the layout");
    }
    let bad_bits = be(&[0x3000, 1]);
    let bad_bits_range = be(&[7, 2]);
    let bits = [TreeNode {
        name: "bits@3000",
        props: &[("reg", &bad_bits), ("bits", &bad_bits_range)],
        children: &[],
    }];
    if lookup(
        &tree(rmem, b"fixed-layout\0", &bits, consumer),
        "calibration",
    ) != Some(Err(E::ProviderUnavailable))
    {
        return TestResult::Fail("out-of-range bits did not fail the layout");
    }
    TestResult::Pass
}
kernel_test_in!("firmware/fdt", smoke_fdt_nvmem_rmem_fixed_layout_cells);

/// A cell node whose `#nvmem-cell-cells` is two is `-EINVAL`.
fn smoke_fdt_nvmem_cell_with_two_arguments_is_invalid() -> TestResult {
    let reg = be(&[0, 4]);
    let cell = [TreeNode {
        name: "cal@0",
        props: &[
            ("reg", &reg),
            ("phandle", &[0, 0, 0, 9]),
            ("#nvmem-cell-cells", &[0, 0, 0, 2]),
        ],
        children: &[],
    }];
    let layout = [TreeNode {
        name: "nvmem-layout",
        props: &[("compatible", b"fixed-layout\0")],
        children: &cell,
    }];
    let rmem = [TreeNode {
        name: "eeprom@50000000",
        props: &[("compatible", b"nvmem-rmem\0"), ("reg", RMEM_REG)],
        children: &layout,
    }];
    let cells = be(&[9, 0, 0]);
    let blob = build_tree(&[
        TreeNode {
            name: "reserved-memory",
            props: &[
                ("#address-cells", &[0, 0, 0, 2]),
                ("#size-cells", &[0, 0, 0, 2]),
            ],
            children: &rmem,
        },
        TreeNode {
            name: "consumer",
            props: &[
                ("nvmem-cells", &cells),
                ("nvmem-cell-names", b"calibration\0"),
            ],
            children: &[],
        },
    ]);
    if lookup(&blob, "calibration") != Some(Err(E::Invalid)) {
        return TestResult::Fail("two-argument nvmem cell accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware/fdt",
    smoke_fdt_nvmem_cell_with_two_arguments_is_invalid
);
