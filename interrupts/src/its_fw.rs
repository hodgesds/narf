//! Firmware description of the GICv3 ITS, redistributors and PCI MSI
//! DeviceID mappings.
//!
//! Byte-slice parsers (no MMIO, arch-neutral) for:
//! - the flattened devicetree: `arm,gic-v3` (`reg`, `#redistributor-regions`,
//!   `redistributor-stride`), its `arm,gic-v3-its` children (`reg`,
//!   `phandle`), and PCI host bridges' `msi-map` / `msi-map-mask` /
//!   `linux,pci-domain` (Linux `of_map_id`);
//! - the ACPI MADT: GICC (per-CPU GICR base + MPIDR), GICR (redistributor
//!   discovery ranges) and GIC ITS (translation ID + base) structures
//!   (Linux `gic_acpi_parse_madt_*`, `its_acpi_probe`);
//! - the ACPI IORT: root-complex ID mappings, chained through SMMUv3
//!   nodes to an ITS group (Linux `iort_node_map_id` / `iort_id_map`).

use alloc::vec::Vec;

/// Where the layout came from.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Source {
    #[default]
    None,
    Devicetree,
    Acpi,
}

/// One described ITS.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ItsNode {
    pub base: u64,
    /// DT phandle, or the ACPI GIC ITS translation ID.
    pub id: u32,
}

/// One `msi-map` entry: `<rid-base msi-controller msi-base length>`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MsiMap {
    pub rid_base: u32,
    pub controller: u32,
    pub out_base: u32,
    pub len: u32,
}

/// One PCI host bridge's MSI description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DtPciHost {
    pub segment: u16,
    pub mask: u32,
    /// Empty with `has_msi_map == false` ⇒ identity (msi-parent or none).
    pub maps: Vec<MsiMap>,
    pub has_msi_map: bool,
}

/// Everything discovery found.
#[derive(Clone, Debug, Default)]
pub struct GicFirmware {
    pub source: Source,
    pub its: Vec<ItsNode>,
    /// Redistributor regions `(base, len)`, walked frame by frame.
    pub rd_regions: Vec<(u64, u64)>,
    /// Explicit frame stride (DT `redistributor-stride`).
    pub rd_stride: Option<u64>,
    /// ACPI GICC per-CPU redistributor frames `(mpidr_aff, base)`, used when
    /// the MADT has no GICR structures.
    pub gicc_rd: Vec<(u32, u64)>,
    pub pci_hosts: Vec<DtPciHost>,
    /// Copy of the IORT, when ACPI provided one.
    pub iort: Option<Vec<u8>>,
}

/// Pack an MPIDR the way `GICR_TYPER[63:32]` and `narf_arch`'s
/// `mpidr_aff()` do: Aff3.Aff2.Aff1.Aff0.
pub const fn mpidr_to_aff(mpidr: u64) -> u32 {
    (((mpidr >> 32) & 0xFF) << 24 | (mpidr & 0xFF_FFFF)) as u32
}

impl GicFirmware {
    pub fn primary_its(&self) -> Option<ItsNode> {
        self.its.first().copied()
    }

    /// PCI requester ID → ITS DeviceID (Linux `its_pci_msi_prepare`:
    /// `pci_msi_domain_get_msi_rid` → `iort_msi_map_id` / `of_map_id`).
    /// Identity when firmware describes no mapping for the bridge; `None`
    /// when a DT `msi-map` exists but does not cover the RID (Linux
    /// refuses the device then).
    pub fn pci_device_id(&self, segment: u16, rid: u16) -> Option<u32> {
        if let Some(iort) = &self.iort {
            return Some(iort_map_rid(iort, segment as u32, rid as u32).unwrap_or(rid as u32));
        }
        let its_id = self.primary_its().map(|i| i.id);
        let host = self
            .pci_hosts
            .iter()
            .find(|h| h.segment == segment)
            .or_else(|| (self.pci_hosts.len() == 1).then(|| &self.pci_hosts[0]));
        match host {
            Some(h) if h.has_msi_map => dt_map_id(h, rid as u32, its_id),
            _ => Some(rid as u32),
        }
    }
}

/// Linux `of_map_id`: apply `msi-map-mask`, then the first range that
/// contains the masked ID and targets our ITS (any target when the ITS
/// phandle is unknown).
pub fn dt_map_id(host: &DtPciHost, rid: u32, its: Option<u32>) -> Option<u32> {
    let id = rid & host.mask;
    host.maps
        .iter()
        .filter(|m| its.is_none_or(|p| p == 0 || m.controller == p))
        .find(|m| id >= m.rid_base && id - m.rid_base < m.len)
        .map(|m| id - m.rid_base + m.out_base)
}

// ── little helpers ──────────────────────────────────────────────────

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}
fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

// ── ACPI MADT ───────────────────────────────────────────────────────

const SDT_HEADER: usize = 36;
const MADT_GICC: u8 = 0x0B;
const MADT_GICR: u8 = 0x0E;
const MADT_ITS: u8 = 0x0F;

/// Parse an aarch64 MADT (whole table, header included) into `fw`.
/// Returns the number of GIC structures consumed.
pub fn parse_madt(table: &[u8], fw: &mut GicFirmware) -> usize {
    if table.get(..4) != Some(b"APIC") {
        return 0;
    }
    let len = le32(table, 4).map_or(0, |l| l as usize).min(table.len());
    let mut at = SDT_HEADER + 8;
    let mut n = 0;
    while at + 2 <= len {
        let kind = table[at];
        let elen = table[at + 1] as usize;
        if elen < 2 || at + elen > len {
            break;
        }
        let e = &table[at..at + elen];
        match kind {
            // GICC: Flags @12 (bit 0 Enabled), GICR base @60, MPIDR @68.
            MADT_GICC if elen >= 76 => {
                let enabled = le32(e, 12).is_some_and(|f| f & 1 != 0);
                let rd = le64(e, 60).unwrap_or(0);
                let mpidr = le64(e, 68).unwrap_or(0);
                if enabled && rd != 0 {
                    fw.gicc_rd.push((mpidr_to_aff(mpidr), rd));
                }
                n += 1;
            }
            // GICR: discovery range base @4, length @12.
            MADT_GICR if elen >= 16 => {
                if let (Some(base), Some(l)) = (le64(e, 4), le32(e, 12)) {
                    if base != 0 && l != 0 {
                        fw.rd_regions.push((base, l as u64));
                    }
                }
                n += 1;
            }
            // GIC ITS: translation ID @4, base @8.
            MADT_ITS if elen >= 16 => {
                if let (Some(id), Some(base)) = (le32(e, 4), le64(e, 8)) {
                    fw.its.push(ItsNode { base, id });
                }
                n += 1;
            }
            _ => {}
        }
        at += elen;
    }
    if n > 0 {
        fw.source = Source::Acpi;
    }
    n
}

// ── ACPI IORT ───────────────────────────────────────────────────────

const IORT_ITS_GROUP: u8 = 0;
const IORT_ROOT_COMPLEX: u8 = 2;
const IORT_SMMU_V3: u8 = 4;
const IORT_SINGLE_MAPPING: u32 = 1;
const IORT_MAX_DEPTH: usize = 8;

/// Linux `iort_node_map_id` for a PCI requester: find the root complex
/// for `segment`, translate through its ID mappings, follow output
/// references (via SMMUv3 nodes) until an ITS group is reached. `None` on
/// any break in the chain — the caller falls back to the input ID, as
/// Linux's `iort_msi_map_id` does.
pub fn iort_map_rid(iort: &[u8], segment: u32, rid: u32) -> Option<u32> {
    if iort.get(..4) != Some(b"IORT") {
        return None;
    }
    let len = (le32(iort, 4)? as usize).min(iort.len());
    let iort = &iort[..len];
    let count = le32(iort, SDT_HEADER)? as usize;
    let first = le32(iort, SDT_HEADER + 4)? as usize;

    // Find the root-complex node for this segment.
    let mut at = first;
    let mut node = None;
    for _ in 0..count {
        let kind = *iort.get(at)?;
        let nlen = le16(iort, at + 1)? as usize;
        if nlen < 16 || at + nlen > iort.len() {
            return None;
        }
        // Root complex: PCI segment number @28 (node data starts @16).
        if kind == IORT_ROOT_COMPLEX && le32(iort, at + 28) == Some(segment) {
            node = Some(at);
            break;
        }
        at += nlen;
    }
    let mut node = node?;
    let mut id = rid;
    for _ in 0..IORT_MAX_DEPTH {
        let kind = *iort.get(node)?;
        if kind == IORT_ITS_GROUP {
            return Some(id);
        }
        let n_maps = le32(iort, node + 8)? as usize;
        let maps = le32(iort, node + 12)? as usize;
        if n_maps == 0 || maps == 0 {
            return None;
        }
        let skip = smmu_id_mapping_index(iort, node, n_maps);
        let mut hit = None;
        let mut edge = None;
        for i in 0..n_maps {
            if Some(i) == skip {
                continue;
            }
            let m = node + maps + i * 20;
            let in_base = le32(iort, m)?;
            let id_count = le32(iort, m + 4)?;
            let out_base = le32(iort, m + 8)?;
            let out_ref = le32(iort, m + 12)? as usize;
            let flags = le32(iort, m + 16)?;
            if out_ref == 0 {
                return None;
            }
            if flags & IORT_SINGLE_MAPPING != 0 {
                if kind == IORT_ROOT_COMPLEX {
                    hit = Some((out_base, out_ref));
                    break;
                }
                continue;
            }
            // `id_count` is "number of IDs minus one". A RID equal to the
            // inclusive end is accepted only when no range starts there
            // (Linux's -EAGAIN overlap rule).
            if id >= in_base && id - in_base < id_count {
                hit = Some((out_base + (id - in_base), out_ref));
                break;
            }
            if id >= in_base && id - in_base == id_count && edge.is_none() {
                edge = Some((out_base + id_count, out_ref));
            }
        }
        let (out, next) = hit.or(edge)?;
        id = out;
        node = next;
    }
    None
}

/// SMMUv3 nodes reserve one mapping for the SMMU's own MSIs
/// (`iort_get_id_mapping_index`); it is skipped while translating.
fn smmu_id_mapping_index(iort: &[u8], node: usize, n_maps: usize) -> Option<usize> {
    if iort[node] != IORT_SMMU_V3 || iort[node + 3] < 1 {
        return None;
    }
    let rev = iort[node + 3];
    let gsivs = [44usize, 48, 52, 56].map(|o| le32(iort, node + o).unwrap_or(0));
    if rev < 5 {
        if gsivs.iter().all(|g| *g != 0) {
            return None;
        }
    } else if le32(iort, node + 24)? & (1 << 4) == 0 {
        // ACPI_IORT_SMMU_V3_DEVICEID_VALID
        return None;
    }
    let idx = le32(iort, node + 64)? as usize;
    (idx < n_maps).then_some(idx)
}

// ── Flattened devicetree ────────────────────────────────────────────

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const MAX_DEPTH: usize = 16;

#[derive(Copy, Clone, Default)]
struct NodeState {
    addr_cells: u32,
    size_cells: u32,
    gic_v3: bool,
    its: bool,
    pci: bool,
    phandle: u32,
    reg: Option<(usize, usize)>,
    msi_map: Option<(usize, usize)>,
    msi_map_mask: Option<u32>,
    pci_domain: Option<u32>,
    rd_regions: Option<u32>,
    rd_stride: Option<u64>,
}

/// Total size of a DTB from its header, if the magic matches.
pub fn fdt_total_size(header: &[u8]) -> Option<usize> {
    if be32(header, 0)? != FDT_MAGIC {
        return None;
    }
    Some(be32(header, 4)? as usize)
}

fn cells(b: &[u8], at: usize, n: u32) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..n as usize {
        v = (v << 32) | be32(b, at + i * 4)? as u64;
    }
    Some(v)
}

/// Decode `reg` into `(addr, size)` pairs with the parent's cell sizes.
fn reg_entries(b: &[u8], range: (usize, usize), ac: u32, sc: u32) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let stride = ((ac + sc) * 4) as usize;
    if stride == 0 || ac > 2 || sc > 2 {
        return out;
    }
    let (start, len) = range;
    let mut at = start;
    while at + stride <= start + len {
        if let (Some(a), Some(s)) = (cells(b, at, ac), cells(b, at + ac as usize * 4, sc)) {
            out.push((a, s));
        }
        at += stride;
    }
    out
}

/// Parse a DTB blob into `fw`. Returns false on a malformed blob.
pub fn parse_fdt(blob: &[u8], fw: &mut GicFirmware) -> bool {
    let Some(total) = fdt_total_size(blob) else {
        return false;
    };
    let blob = &blob[..total.min(blob.len())];
    let (Some(off_struct), Some(off_strings), Some(size_strings), Some(size_struct)) = (
        be32(blob, 8),
        be32(blob, 12),
        be32(blob, 32),
        be32(blob, 36),
    ) else {
        return false;
    };
    let (off_struct, size_struct) = (off_struct as usize, size_struct as usize);
    let (off_strings, size_strings) = (off_strings as usize, size_strings as usize);
    if off_struct + size_struct > blob.len() || off_strings + size_strings > blob.len() {
        return false;
    }
    let strings = &blob[off_strings..off_strings + size_strings];
    let name_of = |off: usize| -> &[u8] {
        let s = strings.get(off..).unwrap_or(&[]);
        let end = s.iter().position(|c| *c == 0).unwrap_or(s.len());
        &s[..end]
    };

    let mut stack = [NodeState::default(); MAX_DEPTH + 1];
    // Root's parent defaults per DT spec §2.3.5: 2 address, 1 size cells.
    stack[0].addr_cells = 2;
    stack[0].size_cells = 1;
    let mut depth = 0usize;
    let mut gic_its_found = Vec::new();
    let mut cur = off_struct;
    let end = off_struct + size_struct;
    let mut pci_index = 0u16;
    while cur + 4 <= end {
        let Some(tok) = be32(blob, cur) else {
            return false;
        };
        cur += 4;
        match tok {
            FDT_BEGIN_NODE => {
                let name_end = match blob[cur..end].iter().position(|c| *c == 0) {
                    Some(p) => cur + p,
                    None => return false,
                };
                cur = (name_end + 1 + 3) & !3;
                if depth >= MAX_DEPTH {
                    return false;
                }
                depth += 1;
                stack[depth] = NodeState {
                    addr_cells: 2,
                    size_cells: 1,
                    ..NodeState::default()
                };
            }
            FDT_PROP => {
                let (Some(plen), Some(nameoff)) = (be32(blob, cur), be32(blob, cur + 4)) else {
                    return false;
                };
                cur += 8;
                let plen = plen as usize;
                if cur + plen > end || depth == 0 {
                    return false;
                }
                let data = &blob[cur..cur + plen];
                let range = (cur, plen);
                cur = (cur + plen + 3) & !3;
                let n = &mut stack[depth];
                match name_of(nameoff as usize) {
                    b"compatible" => {
                        for c in data.split(|b| *b == 0) {
                            match c {
                                b"arm,gic-v3" => n.gic_v3 = true,
                                b"arm,gic-v3-its" => n.its = true,
                                b"pci-host-ecam-generic" | b"pci-host-cam-generic" => n.pci = true,
                                _ => {}
                            }
                        }
                    }
                    b"device_type" if data.starts_with(b"pci\0") => n.pci = true,
                    b"#address-cells" => n.addr_cells = be32(data, 0).unwrap_or(2),
                    b"#size-cells" => n.size_cells = be32(data, 0).unwrap_or(1),
                    b"phandle" | b"linux,phandle" => n.phandle = be32(data, 0).unwrap_or(0),
                    b"reg" => n.reg = Some(range),
                    b"msi-map" => n.msi_map = Some(range),
                    b"msi-map-mask" => n.msi_map_mask = be32(data, 0),
                    b"linux,pci-domain" => n.pci_domain = be32(data, 0),
                    b"#redistributor-regions" => n.rd_regions = be32(data, 0),
                    b"redistributor-stride" => {
                        n.rd_stride = match plen {
                            8 => cells(data, 0, 2),
                            4 => be32(data, 0).map(u64::from),
                            _ => None,
                        }
                    }
                    _ => {}
                }
            }
            FDT_END_NODE => {
                if depth == 0 {
                    return false;
                }
                let n = stack[depth];
                let parent = stack[depth - 1];
                let regs = n
                    .reg
                    .map(|r| reg_entries(blob, r, parent.addr_cells, parent.size_cells))
                    .unwrap_or_default();
                if n.its {
                    if let Some(&(base, _)) = regs.first() {
                        gic_its_found.push(ItsNode {
                            base,
                            id: n.phandle,
                        });
                    }
                }
                if n.gic_v3 {
                    let nr = n.rd_regions.unwrap_or(1).max(1) as usize;
                    fw.rd_regions
                        .extend(regs.iter().skip(1).take(nr).filter(|r| r.1 != 0));
                    fw.rd_stride = n.rd_stride.filter(|s| *s != 0);
                }
                // Only host bridges; PCI-PCI bridge nodes nest under them.
                if n.pci && !parent.pci {
                    let mut maps = Vec::new();
                    if let Some((at, len)) = n.msi_map {
                        let mut p = at;
                        while p + 16 <= at + len {
                            if let (Some(rid_base), Some(controller), Some(out_base), Some(l)) = (
                                be32(blob, p),
                                be32(blob, p + 4),
                                be32(blob, p + 8),
                                be32(blob, p + 12),
                            ) {
                                maps.push(MsiMap {
                                    rid_base,
                                    controller,
                                    out_base,
                                    len: l,
                                });
                            }
                            p += 16;
                        }
                    }
                    let segment = n.pci_domain.map_or(pci_index, |d| d as u16);
                    pci_index = pci_index.wrapping_add(1);
                    fw.pci_hosts.push(DtPciHost {
                        segment,
                        mask: n.msi_map_mask.unwrap_or(u32::MAX),
                        has_msi_map: n.msi_map.is_some(),
                        maps,
                    });
                }
                depth -= 1;
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => return false,
        }
    }
    fw.its.extend(gic_its_found);
    if !fw.its.is_empty() || !fw.rd_regions.is_empty() {
        fw.source = Source::Devicetree;
    }
    true
}

/// Choose the stride for the redistributor frame whose `GICR_TYPER` is
/// `typer` (Linux `gic_iterate_rdists`): explicit `redistributor-stride`
/// wins, else 128 KiB plus 128 KiB more for GICv4 VLPI frames.
pub fn rd_frame_stride(explicit: Option<u64>, typer: u64) -> u64 {
    use crate::its_core::{reg, GICR_TYPER_VLPIS};
    explicit.unwrap_or(if typer & GICR_TYPER_VLPIS != 0 {
        reg::GICR_STRIDE_V4
    } else {
        reg::GICR_STRIDE_V3
    })
}

/// Walk one redistributor region for the frame whose `GICR_TYPER`
/// affinity (bits [63:32]) equals `aff`. `read_typer(pa)` reads that
/// frame's `GICR_TYPER`. Stops at `GICR_TYPER.Last` or the region end.
pub fn find_rd_frame(
    region: (u64, u64),
    stride: Option<u64>,
    aff: u32,
    mut read_typer: impl FnMut(u64) -> Option<u64>,
) -> Option<(u64, u64)> {
    let (base, len) = region;
    let mut pa = base;
    while pa + crate::its_core::reg::GICR_RD_FRAME <= base + len {
        let typer = read_typer(pa)?;
        if (typer >> 32) as u32 == aff {
            return Some((pa, typer));
        }
        if typer & crate::its_core::GICR_TYPER_LAST != 0 {
            return None;
        }
        pa += rd_frame_stride(stride, typer);
    }
    None
}
