//! Devicetree platform devices.
//!
//! Linux binds Qualcomm SoC blocks (the WCSS remoteproc, the ath11k
//! `wifi@` node, SMP2P edges, the GCC) as `platform_device`s and reads
//! their resources with `platform_get_resource_byname`,
//! `platform_get_irq_byname`, `of_parse_phandle_with_args` and
//! `of_reserved_mem_lookup`. [`PlatformDevice`] is that view, built from
//! the boot FDT with `narf_firmware_fdt` (the same walker
//! `narf_bus::boot_dtb` consumers use):
//!
//! - `reg` + `reg-names`, decoded with the parent's `#address-cells` /
//!   `#size-cells`. Only identity (or absent) `ranges` are supported, the
//!   layout of every IPQ8074/IPQ6018/IPQ5018/SC7280 `soc@0` bus; a node
//!   under a translating bus is refused with [`DtError::Ranges`].
//! - `interrupts` / `interrupts-extended` + `interrupt-names`, with the
//!   `interrupt-parent` inherited from the nearest ancestor (root
//!   included).
//! - `memory-region` phandles resolved to static `/reserved-memory`
//!   ranges.
//! - Any `<&provider args...>` list (`resets`, `clocks`,
//!   `qcom,smem-states`, `hwlocks`, `mboxes`) decoded with the provider's
//!   `#<x>-cells`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use narf_firmware_fdt as fdt;

/// Resource lookup failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DtError {
    /// No node with that compatible / phandle.
    NotFound,
    /// A named resource is missing (`reg-names`, `interrupt-names`, ...).
    MissingResource(&'static str),
    /// A property is malformed (short cells, unknown provider cell count).
    Malformed(&'static str),
    /// The node sits under a non-identity `ranges` translation.
    Ranges,
}

/// One interrupt specifier: the controller's phandle plus its raw cells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrqSpec {
    pub parent: u32,
    pub cells: Vec<u32>,
}

impl IrqSpec {
    /// For a GIC 3-cell specifier `<type num flags>`: the Linux virq-less
    /// hardware number (`SPI n` → `n + 32`, `PPI n` → `n + 16`).
    pub fn gic_hwirq(&self) -> Option<u32> {
        match self.cells.as_slice() {
            [0, n, _] => Some(n + 32),
            [1, n, _] => Some(n + 16),
            _ => None,
        }
    }
}

/// One `<&provider arg...>` entry of a phandle-list property.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhandleArgs {
    pub phandle: u32,
    pub args: Vec<u32>,
}

/// A devicetree node viewed as a Linux `platform_device`.
#[derive(Clone, Debug, Default)]
pub struct PlatformDevice {
    /// Full path, e.g. `/soc@0/remoteproc@cd00000`.
    pub path: String,
    pub compatible: Vec<String>,
    pub phandle: Option<u32>,
    /// `status` is absent, `okay` or `ok`.
    pub enabled: bool,
    /// Decoded `reg` tuples (base, size).
    pub regs: Vec<(u64, u64)>,
    pub reg_names: Vec<String>,
    pub irqs: Vec<IrqSpec>,
    pub irq_names: Vec<String>,
    /// Static `/reserved-memory` ranges behind `memory-region`, in order;
    /// `None` for an entry that does not resolve.
    pub memory_regions: Vec<Option<(u64, u64)>>,
    /// Every property, raw (name, big-endian payload).
    props: Vec<(String, Vec<u8>)>,
    ranges_ok: bool,
}

impl PlatformDevice {
    /// Raw property payload.
    pub fn prop(&self, name: &str) -> Option<&[u8]> {
        self.props
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// The property as big-endian `u32` cells.
    pub fn prop_u32s(&self, name: &str) -> Option<Vec<u32>> {
        let v = self.prop(name)?;
        if v.len() % 4 != 0 {
            return None;
        }
        Some(
            v.chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect(),
        )
    }

    /// First cell of a `u32` property.
    pub fn prop_u32(&self, name: &str) -> Option<u32> {
        self.prop_u32s(name)?.first().copied()
    }

    /// NUL-separated string-list property.
    pub fn prop_strings(&self, name: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(v) = self.prop(name) {
            fdt::for_each_compatible_string(v, |s| out.push(s.to_string()));
        }
        out
    }

    /// `true` iff `compatible` lists `compat`.
    pub fn is_compatible(&self, compat: &str) -> bool {
        self.compatible.iter().any(|c| c == compat)
    }

    /// `platform_get_resource(pdev, IORESOURCE_MEM, index)`.
    pub fn reg(&self, index: usize) -> Result<(u64, u64), DtError> {
        if !self.ranges_ok {
            return Err(DtError::Ranges);
        }
        self.regs
            .get(index)
            .copied()
            .ok_or(DtError::MissingResource("reg"))
    }

    /// `platform_get_resource_byname(pdev, IORESOURCE_MEM, name)`.
    pub fn reg_by_name(&self, name: &'static str) -> Result<(u64, u64), DtError> {
        let i = self
            .reg_names
            .iter()
            .position(|n| n == name)
            .ok_or(DtError::MissingResource(name))?;
        self.reg(i).map_err(|e| match e {
            DtError::MissingResource(_) => DtError::MissingResource(name),
            e => e,
        })
    }

    /// `platform_get_irq_byname`.
    pub fn irq_by_name(&self, name: &'static str) -> Result<&IrqSpec, DtError> {
        let i = self
            .irq_names
            .iter()
            .position(|n| n == name)
            .ok_or(DtError::MissingResource(name))?;
        self.irqs.get(i).ok_or(DtError::MissingResource(name))
    }

    /// `of_reserved_mem_lookup(of_parse_phandle(np, "memory-region", i))`.
    pub fn memory_region(&self, index: usize) -> Result<(u64, u64), DtError> {
        self.memory_regions
            .get(index)
            .copied()
            .flatten()
            .ok_or(DtError::MissingResource("memory-region"))
    }

    /// Decode a `<&provider args...>` list (`resets`, `clocks`, ...). The
    /// arg count of each entry is the provider node's `cells_prop`
    /// (`#reset-cells`, `#clock-cells`, ...).
    pub fn phandle_args(
        &self,
        blob: &[u8],
        list_prop: &str,
        cells_prop: &str,
    ) -> Result<Vec<PhandleArgs>, DtError> {
        let Some(cells) = self.prop_u32s(list_prop) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut i = 0;
        while i < cells.len() {
            let phandle = cells[i];
            i += 1;
            let n = provider_cells(blob, phandle, cells_prop)
                .ok_or(DtError::Malformed("provider cells"))? as usize;
            if i + n > cells.len() {
                return Err(DtError::Malformed("phandle args"));
            }
            out.push(PhandleArgs {
                phandle,
                args: cells[i..i + n].to_vec(),
            });
            i += n;
        }
        Ok(out)
    }

    /// The entry of `list_prop` whose position matches `name` in
    /// `names_prop` (`reset-names`, `clock-names`, ...).
    pub fn phandle_args_by_name(
        &self,
        blob: &[u8],
        list_prop: &str,
        cells_prop: &str,
        names_prop: &str,
        name: &'static str,
    ) -> Result<PhandleArgs, DtError> {
        let names = self.prop_strings(names_prop);
        let i = names
            .iter()
            .position(|n| n == name)
            .ok_or(DtError::MissingResource(name))?;
        self.phandle_args(blob, list_prop, cells_prop)?
            .into_iter()
            .nth(i)
            .ok_or(DtError::MissingResource(name))
    }
}

/// A provider's `#<x>-cells`, e.g. `#reset-cells`.
pub fn provider_cells(blob: &[u8], phandle: u32, cells_prop: &str) -> Option<u32> {
    let mut out = None;
    fdt::for_phandle(blob, phandle, |_, props, _| {
        out = fdt::prop_u32(props, cells_prop);
    });
    out
}

/// Root-node `interrupt-parent`: the struct block's first node is the
/// root, which `walk_with_cells` does not report.
fn root_interrupt_parent(blob: &[u8]) -> Option<u32> {
    let hdr = fdt::parse_header(blob)?;
    let be = |o: usize| -> Option<u32> {
        let b = blob.get(o..o + 4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    let strings = hdr.off_dt_strings as usize;
    let mut cur = hdr.off_dt_struct as usize;
    if be(cur)? != fdt::FDT_BEGIN_NODE {
        return None;
    }
    cur += 4;
    // Root name is "" → one NUL, padded to 4.
    let nul = blob.get(cur..)?.iter().position(|&b| b == 0)?;
    cur += (nul + 1 + 3) & !3;
    loop {
        match be(cur)? {
            fdt::FDT_NOP => cur += 4,
            fdt::FDT_PROP => {
                let len = be(cur + 4)? as usize;
                let nameoff = be(cur + 8)? as usize;
                let data = cur + 12;
                let name_start = strings + nameoff;
                let name_end = name_start + blob.get(name_start..)?.iter().position(|&b| b == 0)?;
                if &blob[name_start..name_end] == b"interrupt-parent" && len >= 4 {
                    return be(data);
                }
                cur = (data + len + 3) & !3;
            }
            _ => return None,
        }
    }
}

/// Build every enabled-or-not node matching `pred`.
fn collect(blob: &[u8], mut pred: impl FnMut(&[(String, Vec<u8>)]) -> bool) -> Vec<PlatformDevice> {
    let root_parent = root_interrupt_parent(blob);
    // Per-depth inherited interrupt-parent and ranges-identity flag.
    let mut parent_at: [Option<u32>; fdt::MAX_PATH_DEPTH + 1] = [None; fdt::MAX_PATH_DEPTH + 1];
    let mut ranges_ok_at = [true; fdt::MAX_PATH_DEPTH + 1];
    parent_at[0] = root_parent;
    let mut out = Vec::new();
    fdt::walk_with_cells(blob, |path, props, cells| {
        let depth = path.depth() as usize;
        if depth == 0 || depth > fdt::MAX_PATH_DEPTH {
            return;
        }
        let raw: Vec<(String, Vec<u8>)> = props.map(|(n, v)| (n.to_string(), v.to_vec())).collect();
        let own_parent = raw
            .iter()
            .find(|(n, v)| n == "interrupt-parent" && v.len() >= 4)
            .map(|(_, v)| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
        let inherited = parent_at[depth - 1];
        parent_at[depth] = own_parent.or(inherited);
        // `ranges` on this node governs its children.
        let identity = match raw.iter().find(|(n, _)| n == "ranges") {
            None => true,
            Some((_, v)) => ranges_identity(v),
        };
        ranges_ok_at[depth] = ranges_ok_at[depth - 1] && identity;
        if !pred(&raw) {
            return;
        }
        let mut dev = PlatformDevice {
            ranges_ok: ranges_ok_at[depth - 1],
            ..Default::default()
        };
        let mut p = String::new();
        for i in 0..depth {
            p.push('/');
            p.push_str(path.segment(i).unwrap_or(""));
        }
        dev.path = p;
        dev.phandle = fdt::prop_phandle(props);
        dev.enabled = !matches!(
            fdt::node_status(props),
            fdt::Status::Disabled | fdt::Status::Fail | fdt::Status::Reserved
        );
        for (name, value) in props {
            match name {
                "compatible" => {
                    fdt::for_each_compatible_string(value, |s| dev.compatible.push(s.to_string()))
                }
                "reg" => {
                    let mut off = 0;
                    while let Some(r) = cells.read_one_reg(value, off) {
                        dev.regs.push(r);
                        off += cells.entry_bytes();
                    }
                }
                "reg-names" => {
                    fdt::for_each_compatible_string(value, |s| dev.reg_names.push(s.to_string()))
                }
                "interrupt-names" => {
                    fdt::for_each_compatible_string(value, |s| dev.irq_names.push(s.to_string()))
                }
                _ => {}
            }
        }
        fdt::for_each_interrupt(blob, props, inherited.or(own_parent), |parent, c| {
            dev.irqs.push(IrqSpec {
                parent,
                cells: c.to_vec(),
            });
        });
        if let Some((_, v)) = raw.iter().find(|(n, _)| n == "memory-region") {
            for c in v.chunks_exact(4) {
                let ph = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                dev.memory_regions
                    .push(fdt::reserved_memory_region(blob, ph));
            }
        }
        dev.props = raw;
        out.push(dev);
    });
    out
}

/// A `ranges` payload is identity when empty, or when every
/// (child, parent) address pair is equal. Each entry is decoded with the
/// IPQ/SC7280 `soc@0` layout (2 child, 2 parent, 2 size cells), the only
/// one the supported SoCs use.
fn ranges_identity(v: &[u8]) -> bool {
    if v.is_empty() {
        return true;
    }
    let cells: Vec<u32> = v
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    if cells.len() % 6 != 0 {
        return false;
    }
    cells.chunks_exact(6).all(|e| e[0] == e[2] && e[1] == e[3])
}

/// Every node whose `compatible` lists `compat` (enabled or not; check
/// [`PlatformDevice::enabled`]).
pub fn find_compatible(blob: &[u8], compat: &str) -> Vec<PlatformDevice> {
    collect(blob, |raw| {
        raw.iter()
            .any(|(n, v)| n == "compatible" && fdt::compatible_matches(v, compat))
    })
}

/// The node carrying `phandle`.
pub fn find_phandle(blob: &[u8], phandle: u32) -> Result<PlatformDevice, DtError> {
    collect(blob, |raw| {
        raw.iter().any(|(n, v)| {
            (n == "phandle" || n == "linux,phandle")
                && v.len() >= 4
                && u32::from_be_bytes([v[0], v[1], v[2], v[3]]) == phandle
        })
    })
    .into_iter()
    .next()
    .ok_or(DtError::NotFound)
}

/// Child nodes of `parent_path` (one level down), e.g. the
/// `master-kernel` / `slave-kernel` entries of an SMP2P edge.
pub fn children(blob: &[u8], parent_path: &str) -> Vec<PlatformDevice> {
    let depth = parent_path.matches('/').count() + 1;
    collect(blob, |_| true)
        .into_iter()
        .filter(|d| {
            d.path.matches('/').count() == depth
                && d.path.starts_with(parent_path)
                && d.path.as_bytes().get(parent_path.len()) == Some(&b'/')
        })
        .collect()
}
