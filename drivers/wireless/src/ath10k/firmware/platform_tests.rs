// SPDX-License-Identifier: GPL-2.0-or-later
//! DT/NVMEM calibration sources over synthetic Devicetree blobs.
use super::super::calibration::{select, Mode, Origin};
use super::super::{Error, Files};
use super::*;
use crate::ath10k::profile::Profile;
use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use narf_bus::PcieAddr;
use narf_firmware_fdt::pci::tests::{build_tree, TreeNode};
use narf_kernel_test::{kernel_test_in, TestResult};

fn be(cells: &[u32]) -> Vec<u8> {
    cells.iter().flat_map(|c| c.to_be_bytes()).collect()
}

const PCI: &[u8] = b"pci\0";
const REG0: &[u8] = &[0; 20];
/// QCA9887 `cal_data_len`.
const CAL: usize = 2116;

fn profile() -> Profile {
    Profile::select(0x50, 0x4100016d).unwrap()
}

/// `/reserved-memory/eeprom@50000000` (`nvmem-rmem`, 64 KiB) with fixed
/// cells `precal@0` (phandle 5) and `cal@1000` (phandle 6, `cal_len`
/// bytes), plus a host bridge → root port → `wifi@0` endpoint whose
/// properties are `endpoint`.
fn blob(endpoint: &[(&str, &[u8])], cal_len: u32) -> Vec<u8> {
    let pre_reg = be(&[0, CAL as u32]);
    let cal_reg = be(&[0x1000, cal_len]);
    let cells = [
        TreeNode {
            name: "precal@0",
            props: &[("reg", &pre_reg), ("phandle", &[0, 0, 0, 5])],
            children: &[],
        },
        TreeNode {
            name: "cal@1000",
            props: &[("reg", &cal_reg), ("phandle", &[0, 0, 0, 6])],
            children: &[],
        },
    ];
    let layout = [TreeNode {
        name: "nvmem-layout",
        props: &[
            ("compatible", b"fixed-layout\0"),
            ("#address-cells", &[0, 0, 0, 1]),
            ("#size-cells", &[0, 0, 0, 1]),
        ],
        children: &cells,
    }];
    let rmem = [TreeNode {
        name: "eeprom@50000000",
        props: &[
            ("compatible", b"nvmem-rmem\0"),
            ("reg", &[0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]),
        ],
        children: &layout,
    }];
    let wifi = [TreeNode {
        name: "wifi@0",
        props: endpoint,
        children: &[],
    }];
    let port = [TreeNode {
        name: "pcie@0",
        props: &[("device_type", PCI), ("reg", REG0)],
        children: &wifi,
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
            name: "pcie@40000000",
            props: &[("device_type", PCI), ("linux,pci-domain", &[0, 0, 0, 2])],
            children: &port,
        },
    ])
}

/// Synthetic reserved region: each byte is the low byte of its offset
/// plus one, so a wrong cell offset changes the bytes.
fn region(cell: &RmemCell, reads: &mut Vec<(u64, u32, u32)>) -> Result<Vec<u8>, Error> {
    reads.push((cell.base, cell.offset, cell.bytes));
    Ok((cell.offset..cell.offset + cell.bytes)
        .map(|at| (at as u8).wrapping_add(1))
        .collect())
}

fn expected(offset: u32) -> Vec<u8> {
    (offset..offset + CAL as u32)
        .map(|at| (at as u8).wrapping_add(1))
        .collect()
}

#[derive(Default)]
struct Store {
    blobs: BTreeMap<String, Vec<u8>>,
    lookups: Vec<String>,
}
impl Files for Store {
    fn load(&mut self, name: &str) -> Result<Vec<u8>, Error> {
        self.lookups.push(name.into());
        self.blobs.get(name).cloned().ok_or(Error::Missing)
    }
}

const PRE: &str = "ath10k/pre-cal-pci-0002:00:00.0.bin";
const FINAL: &str = "ath10k/cal-pci-0002:00:00.0.bin";

fn address() -> Option<PcieAddr> {
    Some(PcieAddr::new(2, 0, 0, 0))
}

/// The endpoint's NVMEM cells, primary DT properties and variant reach
/// `Platform`; the node is the PCI function's own (wrong domain or devfn is
/// an absent `of_node`).
fn smoke_ath10k_dt_nvmem_sources_follow_pci_function_node() -> TestResult {
    let cells = be(&[5, 6]);
    let pre_dt = vec![0x31; CAL];
    let dt = vec![0x32; CAL];
    let legacy = vec![0x33; CAL];
    let endpoint: &[(&str, &[u8])] = &[
        ("reg", REG0),
        ("nvmem-cells", &cells),
        ("nvmem-cell-names", b"pre-calibration\0calibration\0"),
        ("qcom,pre-calibration-data", &pre_dt),
        ("qcom,ath10k-calibration-data", &legacy),
        ("qcom,calibration-data", &dt),
        ("qcom,ath10k-calibration-variant", b"LEGACY\0"),
        (
            "qcom,calibration-variant",
            b"RB_0123456789abcdef0123456789abcdef\0",
        ),
    ];
    let tree = blob(endpoint, CAL as u32);
    let mut reads = Vec::new();
    let sources = Platform::in_blob(&tree, 2, &[0, 0], |cell| region(cell, &mut reads));
    if reads
        != [
            (0x5000_0000, 0, CAL as u32),
            (0x5000_0000, 0x1000, CAL as u32),
        ]
        || sources.pre_nvmem != Source::Present(expected(0))
        || sources.nvmem != Source::Present(expected(0x1000))
        || sources.pre_dt != Source::Present(pre_dt.clone())
        || sources.dt != Source::Present(dt.clone())
        || sources.variant.as_deref() != Some(&b"RB_0123456789abcdef0123456789ab"[..])
    {
        return TestResult::Fail("function node sources / primary names / strscpy");
    }
    for (domain, devfns) in [(3u16, &[0u8, 0][..]), (2, &[0, 8][..])] {
        let mut called = false;
        if Platform::in_blob(&tree, domain, devfns, |_| {
            called = true;
            Err(Error::Address)
        }) != Platform::default()
            || called
        {
            return TestResult::Fail("another function's node supplied calibration");
        }
    }
    // Legacy names only when the primary property is absent.
    let legacy_only: &[(&str, &[u8])] = &[
        ("reg", REG0),
        ("qcom,ath10k-pre-calibration-data", &pre_dt),
        ("qcom,ath10k-calibration-data", &legacy),
        ("qcom,ath10k-calibration-variant", b"LEGACY\0"),
    ];
    let sources = Platform::in_blob(&blob(legacy_only, CAL as u32), 2, &[0, 0], |_| {
        Err(Error::Address)
    });
    if sources.pre_dt != Source::Present(pre_dt)
        || sources.dt != Source::Present(legacy)
        || sources.pre_nvmem != Source::Absent
        || sources.nvmem != Source::Absent
        || sources.variant.as_deref() != Some(&b"LEGACY"[..])
    {
        return TestResult::Fail("legacy DT names");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_dt_nvmem_sources_follow_pci_function_node
);

/// Out-of-region cells, a cell outside any registered provider, an
/// unterminated variant and a failing read are refused, not absent.
fn smoke_ath10k_nvmem_cell_failures_are_terminal_sources() -> TestResult {
    let cells = be(&[6]);
    let endpoint: &[(&str, &[u8])] = &[
        ("reg", REG0),
        ("nvmem-cells", &cells),
        ("nvmem-cell-names", b"calibration\0"),
        ("qcom,calibration-variant", b"UNTERMINATED"),
    ];
    // 0x1000 + 0xf001 runs one byte past the 64 KiB region (`-EIO`).
    let sources = Platform::in_blob(&blob(endpoint, 0xf001), 2, &[0, 0], |_| Err(Error::Address));
    if sources.nvmem != Source::Refused(Error::Calibration) || sources.variant.is_some() {
        return TestResult::Fail("out-of-region cell / unterminated variant");
    }
    let sources = Platform::in_blob(&blob(endpoint, CAL as u32), 2, &[0, 0], |_| {
        Err(Error::NoMemory)
    });
    if sources.nvmem != Source::Refused(Error::NoMemory) {
        return TestResult::Fail("failed rmem read became absent");
    }
    let foreign = be(&[9]);
    let efuse_reg = be(&[0, CAL as u32]);
    let efuse_cell = [TreeNode {
        name: "cal@0",
        props: &[("reg", &efuse_reg), ("phandle", &[0, 0, 0, 9])],
        children: &[],
    }];
    let efuse = [TreeNode {
        name: "efuse@1000",
        props: &[("compatible", b"qcom,qfprom\0")],
        children: &efuse_cell,
    }];
    let wifi = [TreeNode {
        name: "wifi@0",
        props: &[
            ("reg", REG0),
            ("nvmem-cells", &foreign),
            ("nvmem-cell-names", b"calibration\0"),
        ],
        children: &[],
    }];
    let port = [TreeNode {
        name: "pcie@0",
        props: &[("device_type", PCI), ("reg", REG0)],
        children: &wifi,
    }];
    let tree = build_tree(&[
        TreeNode {
            name: "soc",
            props: &[],
            children: &efuse,
        },
        TreeNode {
            name: "pcie@40000000",
            props: &[("device_type", PCI)],
            children: &port,
        },
    ]);
    if Platform::in_blob(&tree, 0, &[0, 0], |_| Err(Error::Address)).nvmem
        != Source::Refused(Error::Unsupported)
    {
        return TestResult::Fail("unregistered NVMEM provider became absent");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_nvmem_cell_failures_are_terminal_sources
);

/// `ath10k_core_pre_cal_download` / `ath10k_download_cal_data` precedence:
/// NVMEM, file, DT for pre-cal, then the same for cal; geometry and refusal
/// stay terminal for every origin.
fn smoke_ath10k_calibration_source_precedence_matches_linux() -> TestResult {
    let p = profile();
    let all = || Platform {
        pre_nvmem: Source::Present(vec![1; CAL]),
        pre_dt: Source::Present(vec![2; CAL]),
        nvmem: Source::Present(vec![3; CAL]),
        dt: Source::Present(vec![4; CAL]),
        variant: None,
    };
    let mut files = Store::default();
    files.blobs.insert(PRE.into(), vec![5; CAL]);
    files.blobs.insert(FINAL.into(), vec![6; CAL]);
    let mut sources = all();
    let expect = |sources: &Platform,
                  files: &mut Store,
                  mode: Mode,
                  origin: Origin,
                  byte: u8,
                  lookups: &[&str]|
     -> Result<(), &'static str> {
        files.lookups.clear();
        let cal = select(files, address(), p, sources)
            .map_err(|_| "select failed")?
            .ok_or("no source")?;
        if cal.mode != mode || cal.origin != origin || cal.bytes != vec![byte; CAL] {
            return Err("wrong source selected");
        }
        if files.lookups != lookups {
            return Err("file lookups out of Linux order");
        }
        Ok(())
    };
    let steps: [(Mode, Origin, u8, &[&str]); 6] = [
        (Mode::Pre, Origin::Nvmem, 1, &[]),
        (Mode::Pre, Origin::File, 5, &[PRE]),
        (Mode::Pre, Origin::Dt, 2, &[PRE]),
        (Mode::Final, Origin::Nvmem, 3, &[PRE]),
        (Mode::Final, Origin::File, 6, &[PRE, FINAL]),
        (Mode::Final, Origin::Dt, 4, &[PRE, FINAL]),
    ];
    for (index, (mode, origin, byte, lookups)) in steps.into_iter().enumerate() {
        if let Err(why) = expect(&sources, &mut files, mode, origin, byte, lookups) {
            return TestResult::Fail(why);
        }
        // Remove the winning source so the next one is selected.
        match index {
            0 => sources.pre_nvmem = Source::Absent,
            1 => {
                files.blobs.remove(PRE);
            }
            2 => sources.pre_dt = Source::Absent,
            3 => sources.nvmem = Source::Absent,
            4 => {
                files.blobs.remove(FINAL);
            }
            _ => sources.dt = Source::Absent,
        }
    }
    files.lookups.clear();
    if !matches!(select(&mut files, address(), p, &sources), Ok(None))
        || files.lookups != [PRE, FINAL]
    {
        return TestResult::Fail("no source did not fall through to EEPROM/OTP");
    }
    // A present malformed or refused source never selects a later one.
    let mut short = all();
    short.pre_nvmem = Source::Present(vec![1; CAL - 4]);
    let mut refused = all();
    refused.pre_dt = Source::Absent;
    refused.pre_nvmem = Source::Absent;
    refused.nvmem = Source::Refused(Error::Unsupported);
    files.lookups.clear();
    if select(&mut files, address(), p, &short).err() != Some(Error::Calibration)
        || select(&mut files, address(), p, &refused).err() != Some(Error::Unsupported)
        || files.lookups != [PRE]
    {
        return TestResult::Fail("malformed / refused platform source fell back");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_calibration_source_precedence_matches_linux
);
