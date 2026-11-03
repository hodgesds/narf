//! DMA coherence (`dma-coherent` / `dma-noncoherent`) and `shared-dma-pool`
//! reserved memory.
//!
//! Mirrors Linux `drivers/of/address.c::of_dma_is_coherent` (nearest node
//! on the DMA-parent chain carrying either property wins, else the arch
//! `dma_default_coherent`), `drivers/pci/of.c` + `drivers/of/device.c`
//! (`of_dma_configure` on a PCI device uses the host bridge's node), and
//! `kernel/dma/coherent.c::rmem_dma_setup` (`shared-dma-pool`: never
//! `reusable`; `linux,dma-default` names the global pool, a later
//! definition replacing an earlier one).

use crate::{
    compatible_matches, node_status, pci, prop_phandle, walk_nodes, walk_with_cells, Cells,
    PropIter, Status, MAX_PATH_DEPTH,
};

/// What the Devicetree says about a node's DMA coherence, before the
/// architecture default (`dma_default_coherent`) is applied.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaCoherenceProp {
    /// `dma-coherent` on the node or its nearest marked ancestor.
    Coherent,
    /// `dma-noncoherent` on the node or its nearest marked ancestor.
    NonCoherent,
    /// Neither property anywhere on the chain: the arch default applies.
    Default,
    /// The chain leaves the tree through an `interconnects` "dma-mem" DMA
    /// parent (Linux `__of_get_dma_parent`), which this parser does not
    /// follow. Callers must treat this as non-coherent (the safe direction).
    Unresolved,
}

/// The node's own contribution: `dma-coherent` is tested before
/// `dma-noncoherent`, as `of_dma_is_coherent` does.
fn own_coherence(props: PropIter<'_>) -> Option<DmaCoherenceProp> {
    let (mut coherent, mut noncoherent, mut dma_mem) = (false, false, false);
    for (name, value) in props {
        match name {
            "dma-coherent" => coherent = true,
            "dma-noncoherent" => noncoherent = true,
            "interconnect-names" => {
                dma_mem = value.split(|b| *b == 0).any(|s| s == b"dma-mem");
            }
            _ => {}
        }
    }
    if coherent {
        Some(DmaCoherenceProp::Coherent)
    } else if noncoherent {
        Some(DmaCoherenceProp::NonCoherent)
    } else if dma_mem {
        Some(DmaCoherenceProp::Unresolved)
    } else {
        None
    }
}

/// Walk every node with its `of_dma_is_coherent` answer.
fn walk_coherence<F>(blob: &[u8], mut f: F)
where
    F: FnMut(&crate::Path<'_>, PropIter<'_>, DmaCoherenceProp),
{
    let mut state = [DmaCoherenceProp::Default; MAX_PATH_DEPTH + 1];
    walk_nodes(blob, |path, props| {
        let depth = usize::from(path.depth());
        if depth > MAX_PATH_DEPTH {
            return;
        }
        let inherited = if depth == 0 {
            DmaCoherenceProp::Default
        } else {
            state[depth - 1]
        };
        state[depth] = own_coherence(props).unwrap_or(inherited);
        f(path, props, state[depth]);
    });
}

/// `of_dma_is_coherent` for the node at `path` (segments below the root,
/// e.g. `["soc", "dma@1000"]`). `None` when no such node exists.
pub fn node_dma_coherence(blob: &[u8], path: &[&str]) -> Option<DmaCoherenceProp> {
    let mut out = None;
    walk_coherence(blob, |node, _, coherence| {
        if node.matches(path) {
            out = Some(coherence);
        }
    });
    out
}

/// `of_dma_is_coherent` for the host bridge of PCI `domain` — the node every
/// function below it inherits through `of_dma_configure` (Linux
/// `pci_dma_configure`). Host bridges are matched like
/// [`crate::for_pci_function`]; `None` without a unique one.
pub fn pci_host_bridge_dma_coherence(blob: &[u8], domain: u16) -> Option<DmaCoherenceProp> {
    let untagged_ok = pci::host_bridges(blob) == 1;
    let mut pci_anc = [false; MAX_PATH_DEPTH + 1];
    let mut found = None;
    let mut matches = 0usize;
    walk_coherence(blob, |path, props, coherence| {
        let depth = usize::from(path.depth());
        if depth == 0 {
            return;
        }
        let is_pci = pci::is_pci(props);
        if is_pci && !pci_anc[depth - 1] {
            let ok = match crate::prop_u32(props, "linux,pci-domain") {
                Some(d) => d == u32::from(domain),
                None => untagged_ok,
            };
            if ok {
                matches += 1;
                found = Some(coherence);
            }
        }
        pci_anc[depth] = pci_anc[depth - 1] || is_pci;
    });
    (matches == 1).then_some(found).flatten()
}

/// One `/reserved-memory` child usable as a Linux `shared-dma-pool`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SharedDmaPool {
    /// Static base (first `reg` entry).
    pub addr: u64,
    pub size: u64,
    pub phandle: Option<u32>,
    /// `linux,dma-default`: the global pool for non-coherent devices.
    pub default: bool,
}

/// A `shared-dma-pool` NARF can map non-cacheable: enabled, statically
/// placed, `no-map` (so absent from System RAM — `rmem_dma_setup`'s
/// `CONFIG_ARM` rule, applied everywhere here) and not `reusable`.
fn pool_of(props: PropIter<'_>, cells: Cells) -> Option<SharedDmaPool> {
    if node_status(props) != Status::Okay {
        return None;
    }
    let (mut compatible, mut no_map, mut reusable, mut default) = (false, false, false, false);
    let mut reg = None;
    for (name, value) in props {
        match name {
            "compatible" => compatible = compatible_matches(value, "shared-dma-pool"),
            "no-map" => no_map = true,
            "reusable" => reusable = true,
            "linux,dma-default" => default = true,
            "reg" => reg = cells.read_one_reg(value, 0),
            _ => {}
        }
    }
    let (addr, size) = reg?;
    (compatible && no_map && !reusable && size != 0).then_some(SharedDmaPool {
        addr,
        size,
        phandle: prop_phandle(props),
        default,
    })
}

fn for_each_pool<F: FnMut(SharedDmaPool)>(blob: &[u8], mut f: F) {
    walk_with_cells(blob, |path, props, cells| {
        if path.depth() == 2 && path.segment(0) == Some("reserved-memory") {
            if let Some(pool) = pool_of(props, cells) {
                f(pool);
            }
        }
    });
}

/// The `shared-dma-pool` with `phandle` (a device's `memory-region` target).
pub fn shared_dma_pool(blob: &[u8], phandle: u32) -> Option<SharedDmaPool> {
    let mut out = None;
    for_each_pool(blob, |pool| {
        if pool.phandle == Some(phandle) {
            out = Some(pool);
        }
    });
    out
}

/// The `linux,dma-default` pool. Linux warns on a redefinition and keeps the
/// last one; so does this.
pub fn default_shared_dma_pool(blob: &[u8]) -> Option<SharedDmaPool> {
    let mut out = None;
    for_each_pool(blob, |pool| {
        if pool.default {
            out = Some(pool);
        }
    });
    out
}

/// Linux `of_reserved_mem_device_init(dev)` for a PCI function: the
/// `shared-dma-pool` named by `memory-region[0]` of the function's own node
/// (`for_pci_function`). `None` without a unique node, without the property
/// or when the target is not a usable `shared-dma-pool`.
pub fn pci_function_dma_pool(blob: &[u8], domain: u16, devfns: &[u8]) -> Option<SharedDmaPool> {
    let mut phandle = None;
    if !crate::for_pci_function(blob, domain, devfns, |_, props, _| {
        phandle = crate::memory_region_phandle(props, 0);
    }) {
        return None;
    }
    shared_dma_pool(blob, phandle?)
}

#[path = "dma_tests.rs"]
mod tests;
