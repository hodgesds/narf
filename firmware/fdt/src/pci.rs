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

/// A PCI function's legacy INTx resolved through its host bridge's
/// `interrupt-map`: the interrupt controller's phandle and its specifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntxRoute {
    pub parent: u32,
    pub specifier: [u32; 4],
    pub cells: usize,
}

fn cells_of(value: &[u8]) -> impl Iterator<Item = u32> + '_ {
    value
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
}
fn cell(value: &[u8], index: usize) -> Option<u32> {
    let c = value.get(index * 4..index * 4 + 4)?;
    Some(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
}

/// `(#address-cells, #interrupt-cells, is interrupt-controller)` of the node
/// with `phandle`. `of_irq_parse_raw` treats an absent `#address-cells` on
/// the interrupt parent as 0.
fn parent_cells(blob: &[u8], phandle: u32) -> Option<(usize, usize, bool)> {
    let mut found = None;
    crate::for_phandle(blob, phandle, |_, props, _| {
        let address = crate::prop_u32(props, "#address-cells").unwrap_or(0);
        let interrupt = crate::prop_u32(props, "#interrupt-cells");
        let controller = props
            .into_iter()
            .any(|(name, _)| name == "interrupt-controller");
        found = interrupt.map(|i| (address as usize, i as usize, controller));
    });
    found
}

/// Linux `of_irq_parse_raw` for a function on the root bus of PCI `domain`
/// (`bus` is the host bridge's bus number): the child unit address
/// `<bus << 16 | devfn << 8, 0, 0>` and INTx `pin` (1..=4) are masked with
/// `interrupt-map-mask` and matched against `interrupt-map`. Only a single
/// nexus hop to an `interrupt-controller` is resolved (no nested maps);
/// functions behind bridges need the caller's swizzle to the root port.
pub fn intx_route(blob: &[u8], domain: u16, bus: u8, devfn: u8, pin: u8) -> Option<IntxRoute> {
    if !(1..=4).contains(&pin) {
        return None;
    }
    let untagged_ok = host_bridges(blob) == 1;
    let mut bridges = 0;
    let mut pci_anc = [false; MAX_PATH_DEPTH + 1];
    // (offset, length) of `interrupt-map` within `blob`.
    let mut found: Option<(usize, usize)> = None;
    let mut mask = [u32::MAX; 4];
    let mut mask_len = 0;
    let mut address_cells = 3usize;
    let mut interrupt_cells = 1usize;
    crate::walk_nodes(blob, |path, props| {
        let depth = usize::from(path.depth());
        if depth == 0 || depth > MAX_PATH_DEPTH {
            return;
        }
        let pci = is_pci(props);
        if pci && !pci_anc[depth - 1] {
            let ok = match pci_domain(props) {
                Some(d) => d == u32::from(domain),
                None => untagged_ok,
            };
            if ok {
                bridges += 1;
                address_cells = crate::prop_u32(props, "#address-cells").unwrap_or(3) as usize;
                interrupt_cells = crate::prop_u32(props, "#interrupt-cells").unwrap_or(1) as usize;
                for (name, value) in props {
                    if name == "interrupt-map" {
                        let offset = (value.as_ptr() as usize).wrapping_sub(blob.as_ptr() as usize);
                        found = Some((offset, value.len()));
                    } else if name == "interrupt-map-mask" {
                        mask_len = 0;
                        for (i, cell) in cells_of(value).enumerate().take(4) {
                            mask[i] = cell;
                            mask_len = i + 1;
                        }
                    }
                }
            }
        }
        pci_anc[depth] = pci_anc[depth - 1] || pci;
    });
    if bridges != 1 || address_cells != 3 || interrupt_cells != 1 {
        return None;
    }
    let (offset, length) = found?;
    let raw = blob.get(offset..offset.checked_add(length)?)?;
    let count = raw.len() / 4;
    let child = [
        u32::from(bus) << 16 | u32::from(devfn) << 8,
        0,
        0,
        u32::from(pin),
    ];
    let masked: [u32; 4] = core::array::from_fn(|i| {
        let m = if mask_len == 4 { mask[i] } else { u32::MAX };
        child[i] & m
    });
    let mut at = 0;
    while at + 5 <= count {
        let entry: [u32; 4] = core::array::from_fn(|i| cell(raw, at + i).unwrap_or(0));
        let parent = cell(raw, at + 4)?;
        let (parent_address, parent_interrupt, controller) = parent_cells(blob, parent)?;
        let specifier_at = at + 5 + parent_address;
        let end = specifier_at + parent_interrupt;
        if end > count || parent_interrupt > 4 {
            return None;
        }
        if entry == masked {
            if !controller {
                return None;
            }
            let mut specifier = [0; 4];
            for (i, slot) in specifier.iter_mut().take(parent_interrupt).enumerate() {
                *slot = cell(raw, specifier_at + i)?;
            }
            return Some(IntxRoute {
                parent,
                specifier,
                cells: parent_interrupt,
            });
        }
        at = end;
    }
    None
}

/// GIC `#interrupt-cells = <3>` specifier → `(INTID, level)`: SPI only
/// (type 0, INTID 32 + number); flags 1 = edge rising, 4 = level high (the
/// GIC distributor supports no other SPI sense).
pub fn gic_spi(route: &IntxRoute) -> Option<(u32, bool)> {
    if route.cells != 3 || route.specifier[0] != 0 || route.specifier[1] > 987 {
        return None;
    }
    let intid = 32 + route.specifier[1];
    match route.specifier[2] & 0xf {
        1 => Some((intid, false)),
        4 => Some((intid, true)),
        _ => None,
    }
}
