//! PCI function ↔ Devicetree node association and reserved-memory lookup.
//!
//! Mirrors Linux `drivers/pci/of.c` (`pci_set_of_node`,
//! `of_pci_find_child_device`, `of_pci_get_devfn`) and
//! `drivers/of/of_reserved_mem.c` (`of_reserved_mem_region_to_resource`)
//! for the subset drivers need: a PCI function's node is found by
//! descending from the host bridge (a `device_type = "pci"` node with no
//! PCI ancestor, matching `linux,pci-domain` when present) through one
//! child per hop whose `reg` phys.hi cell encodes the hop's devfn
//! (bits 8..15, PCI Bus Binding to IEEE 1275 §2.2.1.1).

use crate::{prop_phandle, walk_with_cells, Cells, Path, PropIter, MAX_PATH_DEPTH};

/// `of_pci_get_devfn`: `(reg[0] >> 8) & 0xff`.
fn reg_devfn(props: PropIter<'_>) -> Option<u8> {
    for (name, value) in props {
        if name == "reg" && value.len() >= 4 {
            return Some(value[2]);
        }
    }
    None
}

fn is_pci(props: PropIter<'_>) -> bool {
    props.into_iter().any(|(name, value)| {
        name == "device_type" && value.split(|b| *b == 0).next() == Some(b"pci")
    })
}

fn pci_domain(props: PropIter<'_>) -> Option<u32> {
    crate::prop_u32(props, "linux,pci-domain")
}

/// Walk the tree, calling `hit` for every node that is the PCI function
/// reached by `devfns` under a host bridge of `domain`. Host bridges that
/// carry `linux,pci-domain` must match it; a bridge without the property
/// is accepted only when `untagged_ok` (the caller has proven it is the
/// only host bridge).
fn walk_matches<F>(blob: &[u8], domain: u16, devfns: &[u8], untagged_ok: bool, mut hit: F)
where
    F: FnMut(&Path<'_>, PropIter<'_>, Cells),
{
    // level[d]: the node at depth d matched hop `level - 1` (0 = host
    // bridge). pci_anc[d]: the node or an ancestor is a PCI bridge node.
    let mut level: [Option<usize>; MAX_PATH_DEPTH + 1] = [None; MAX_PATH_DEPTH + 1];
    let mut pci_anc = [false; MAX_PATH_DEPTH + 1];
    walk_with_cells(blob, |path, props, cells| {
        let depth = usize::from(path.depth());
        if depth == 0 || depth > MAX_PATH_DEPTH {
            return;
        }
        let pci = is_pci(props);
        level[depth] = match level[depth - 1] {
            Some(k) if k < devfns.len() && reg_devfn(props) == Some(devfns[k]) => Some(k + 1),
            _ if pci && !pci_anc[depth - 1] => {
                let ok = match pci_domain(props) {
                    Some(d) => d == u32::from(domain),
                    None => untagged_ok,
                };
                ok.then_some(0)
            }
            _ => None,
        };
        pci_anc[depth] = pci_anc[depth - 1] || pci;
        if !devfns.is_empty() && level[depth] == Some(devfns.len()) {
            hit(path, props, cells);
        }
    });
}

/// Count host bridges (PCI nodes without a PCI ancestor).
fn host_bridges(blob: &[u8]) -> usize {
    let mut pci_anc = [false; MAX_PATH_DEPTH + 1];
    let mut count = 0;
    crate::walk_nodes(blob, |path, props| {
        let depth = usize::from(path.depth());
        if depth == 0 || depth > MAX_PATH_DEPTH {
            return;
        }
        let pci = is_pci(props);
        if pci && !pci_anc[depth - 1] {
            count += 1;
        }
        pci_anc[depth] = pci_anc[depth - 1] || pci;
    });
    count
}

/// Linux `pci_set_of_node` for one function: call `f` with the unique node
/// reached from the host bridge of PCI `domain` through `devfns` (root-bus
/// hop first, see `narf_bus::pci::devfn_path`). Returns false — and does
/// not call `f` — when no node or more than one node matches; an untagged
/// host bridge is only trusted when it is the only one.
pub fn for_pci_function<F>(blob: &[u8], domain: u16, devfns: &[u8], mut f: F) -> bool
where
    F: FnMut(&Path<'_>, PropIter<'_>, Cells),
{
    let untagged_ok = host_bridges(blob) == 1;
    let mut matches = 0usize;
    walk_matches(blob, domain, devfns, untagged_ok, |_, _, _| matches += 1);
    if matches != 1 {
        return false;
    }
    walk_matches(blob, domain, devfns, untagged_ok, |path, props, cells| {
        f(path, props, cells)
    });
    true
}

/// The `index`th phandle of a node's `memory-region` property.
pub fn memory_region_phandle(props: PropIter<'_>, index: usize) -> Option<u32> {
    for (name, value) in props {
        if name == "memory-region" {
            let at = index * 4;
            let cell = value.get(at..at + 4)?;
            return Some(u32::from_be_bytes([cell[0], cell[1], cell[2], cell[3]]));
        }
    }
    None
}

/// `of_reserved_mem_region_to_resource`: the static `reg` (base, size) of
/// the `/reserved-memory` child whose phandle is `phandle`. Dynamic
/// (`size`-only) and out-of-tree targets are refused.
pub fn reserved_memory_region(blob: &[u8], phandle: u32) -> Option<(u64, u64)> {
    let mut out = None;
    walk_with_cells(blob, |path, props, cells| {
        if out.is_some()
            || path.depth() != 2
            || path.segment(0) != Some("reserved-memory")
            || prop_phandle(props) != Some(phandle)
        {
            return;
        }
        for (name, value) in props {
            if name == "reg" {
                out = cells.read_one_reg(value, 0).filter(|(_, size)| *size != 0);
            }
        }
    });
    out
}

#[path = "pci_tests.rs"]
mod tests;
