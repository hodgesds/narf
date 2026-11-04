//! NVMEM consumer cell resolution for reserved-memory providers.
//!
//! Mirrors Linux `drivers/nvmem/core.c` (`of_nvmem_cell_get`,
//! `nvmem_add_cells_from_dt`, `nvmem_device_match`),
//! `drivers/nvmem/layouts/fixed-layout.c` and `drivers/nvmem/rmem.c` for the
//! one provider that can be read without a bus driver: an enabled
//! `/reserved-memory` child compatible `nvmem-rmem` with a static `reg`,
//! whose cells live in its `nvmem-layout` (`fixed-layout`) container.
//! `rmem_probe` sets no `add_legacy_fixed_of_cells`, so a cell that is a
//! direct child of the rmem node is not registered. Every other provider
//! (MTD, I2C EEPROM, QFPROM, …) has no in-tree NVMEM driver and resolves to
//! [`NvmemError::ProviderUnavailable`], Linux's `-EPROBE_DEFER`.

use crate::{for_phandle, prop_phandle, prop_u32, walk_with_cells, PropIter, MAX_PATH_DEPTH};

/// Linux error a consumer sees from `of_nvmem_cell_get`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvmemError {
    /// `-ENOENT`: no such name in `nvmem-cell-names`, no resolvable
    /// `nvmem-cells` entry, or no registered cell for the node.
    NotFound,
    /// `-EINVAL`: more than one cell argument, or a cell node without a parent.
    Invalid,
    /// `-EPROBE_DEFER`: the provider is not registered by this kernel
    /// (unsupported provider/layout, disabled or dynamic region, or a
    /// fixed layout whose `nvmem_add_cells_from_dt` fails).
    ProviderUnavailable,
}

/// One registered `nvmem-rmem` fixed-layout cell: the provider's static
/// reserved region and the cell's `reg = <offset bytes>`. `bits` is
/// `Some((bit_offset, nbits))` for a valid bit-field cell, whose read needs
/// `nvmem_shift_read_buffer_in_place` post-processing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RmemCell {
    pub base: u64,
    pub size: u64,
    pub offset: u32,
    pub bytes: u32,
    pub bits: Option<(u32, u32)>,
}

fn be32(value: &[u8], at: usize) -> Option<u32> {
    value
        .get(at..at + 4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
}

fn prop<'a>(props: PropIter<'a>, want: &str) -> Option<&'a [u8]> {
    props
        .into_iter()
        .find_map(|(name, value)| (name == want).then_some(value))
}

/// `of_property_match_string(np, "nvmem-cell-names", id)`.
fn name_index(consumer: PropIter<'_>, id: &str) -> Option<usize> {
    let mut index = None;
    let mut at = 0usize;
    crate::prop_string_list(consumer, "nvmem-cell-names", |name| {
        if index.is_none() && name == id {
            index = Some(at);
        }
        at += 1;
    });
    index
}

/// `#nvmem-cell-cells` of the node `phandle` (absent = 0). `None` when no
/// node carries the phandle.
fn cell_cells(blob: &[u8], phandle: u32) -> Option<u32> {
    let mut out = None;
    for_phandle(blob, phandle, |_, props, _| {
        out = Some(prop_u32(props, "#nvmem-cell-cells").unwrap_or(0));
    });
    out
}

/// `of_parse_phandle_with_optional_args(np, "nvmem-cells",
/// "#nvmem-cell-cells", index)`: the target phandle and its argument count.
fn cell_phandle(blob: &[u8], value: &[u8], index: usize) -> Result<(u32, u32), NvmemError> {
    let mut at = 0usize;
    for i in 0..=index {
        let phandle = be32(value, at).ok_or(NvmemError::NotFound)?;
        if phandle == 0 {
            return Err(NvmemError::NotFound);
        }
        let count = cell_cells(blob, phandle).ok_or(NvmemError::NotFound)?;
        let next = (count as usize)
            .checked_add(1)
            .and_then(|cells| cells.checked_mul(4))
            .and_then(|bytes| at.checked_add(bytes))
            .filter(|next| *next <= value.len())
            .ok_or(NvmemError::NotFound)?;
        if i == index {
            return Ok((phandle, count));
        }
        at = next;
    }
    Err(NvmemError::NotFound)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Provider {
    /// Not a node this kernel registers as an NVMEM device.
    None,
    Rmem {
        base: u64,
        size: u64,
    },
}

/// A cell's `(offset, bytes, bits)`.
type CellReg = (u32, u32, Option<(u32, u32)>);
/// Pass-1 result: the layout container's serial, provider and cell.
type Hit = Result<(usize, Provider, Option<CellReg>), NvmemError>;

/// `nvmem_add_cells_from_dt` per-child parse: `Ok(None)` for a child
/// without `reg` (skipped), `Err` for one that fails the whole layout.
fn parse_cell(props: PropIter<'_>) -> Result<Option<CellReg>, ()> {
    let Some(reg) = prop(props, "reg") else {
        return Ok(None);
    };
    if reg.len() < 8 {
        return Err(());
    }
    let (offset, bytes) = (be32(reg, 0).ok_or(())?, be32(reg, 4).ok_or(())?);
    let bits = match prop(props, "bits") {
        Some(value) if value.len() == 8 => {
            let (bit_offset, nbits) = (be32(value, 0).ok_or(())?, be32(value, 4).ok_or(())?);
            let total = u64::from(bytes) * 8;
            if u64::from(bit_offset) >= total
                || nbits < 1
                || u64::from(bit_offset) + u64::from(nbits) > total
            {
                return Err(());
            }
            Some((bit_offset, nbits))
        }
        _ => None,
    };
    Ok(Some((offset, bytes, bits)))
}

/// Linux `of_nvmem_cell_get(np, id)` for a consumer node's properties,
/// restricted to `nvmem-rmem` fixed-layout cells (see the module docs).
pub fn rmem_cell(blob: &[u8], consumer: PropIter<'_>, id: &str) -> Result<RmemCell, NvmemError> {
    let index = name_index(consumer, id).ok_or(NvmemError::NotFound)?;
    let cells = prop(consumer, "nvmem-cells").ok_or(NvmemError::NotFound)?;
    let (target, args) = cell_phandle(blob, cells, index)?;
    if args > 1 {
        return Err(NvmemError::Invalid);
    }

    // Pass 1: locate the cell node and classify its ancestors. Node serials
    // are the deterministic visit order, reused by pass 2.
    let mut serial = [0usize; MAX_PATH_DEPTH + 1];
    let mut provider = [Provider::None; MAX_PATH_DEPTH + 1];
    let mut layout = [false; MAX_PATH_DEPTH + 1];
    let mut fixed = [false; MAX_PATH_DEPTH + 1];
    let mut next = 0usize;
    let mut hit: Option<Hit> = None;
    walk_with_cells(blob, |path, props, cells| {
        let depth = usize::from(path.depth());
        next += 1;
        if depth == 0 || depth > MAX_PATH_DEPTH {
            return;
        }
        serial[depth] = next;
        let name = path.last_segment();
        let base = name.split('@').next().unwrap_or("");
        layout[depth] = base == "nvmem-layout";
        fixed[depth] = prop(props, "compatible")
            .is_some_and(|value| crate::compatible_matches(value, "fixed-layout"));
        provider[depth] = Provider::None;
        if depth == 2
            && path.segment(0) == Some("reserved-memory")
            && prop(props, "compatible")
                .is_some_and(|value| crate::compatible_matches(value, "nvmem-rmem"))
            && crate::node_status(props) == crate::Status::Okay
        {
            // `of_reserved_mem_lookup`: the first static `reg` entry.
            if let Some((base, size)) = prop(props, "reg")
                .and_then(|reg| cells.read_one_reg(reg, 0))
                .filter(|(_, size)| *size != 0)
            {
                provider[depth] = Provider::Rmem { base, size };
            }
        }
        if hit.is_some() || prop_phandle(props) != Some(target) {
            return;
        }
        // `of_get_parent`, then one more hop out of an `nvmem-layout`.
        hit = Some(if depth < 2 {
            Err(NvmemError::ProviderUnavailable)
        } else if layout[depth - 1] {
            if depth < 3 || provider[depth - 2] == Provider::None {
                Err(NvmemError::ProviderUnavailable)
            } else if !fixed[depth - 1] {
                // No in-tree driver for any other layout compatible.
                Err(NvmemError::ProviderUnavailable)
            } else {
                parse_cell(props)
                    .map(|cell| (serial[depth - 1], provider[depth - 2], cell))
                    .map_err(|()| NvmemError::ProviderUnavailable)
            }
        } else if provider[depth - 1] == Provider::None {
            Err(NvmemError::ProviderUnavailable)
        } else {
            // rmem registers no legacy cells and this provider has no layout
            // claiming the node.
            Err(NvmemError::NotFound)
        });
    });
    let (layout_serial, provider, cell) = hit.ok_or(NvmemError::NotFound)??;
    let Provider::Rmem { base, size } = provider else {
        return Err(NvmemError::ProviderUnavailable);
    };

    // Pass 2: `fixed_layout_add_cells` fails the whole provider registration
    // when any sibling cell is malformed, so the target is then unregistered.
    let mut parent = [0usize; MAX_PATH_DEPTH + 1];
    let mut next = 0usize;
    let mut broken = false;
    walk_with_cells(blob, |path, props, _| {
        let depth = usize::from(path.depth());
        next += 1;
        if depth == 0 || depth > MAX_PATH_DEPTH {
            return;
        }
        parent[depth] = next;
        if parent[depth - 1] == layout_serial && parse_cell(props).is_err() {
            broken = true;
        }
    });
    if broken {
        return Err(NvmemError::ProviderUnavailable);
    }
    // A child without `reg` is never registered: the layout exists, so
    // `of_nvmem_cell_get` reports `-EPROBE_DEFER`.
    let (offset, bytes, bits) = cell.ok_or(NvmemError::ProviderUnavailable)?;
    Ok(RmemCell {
        base,
        size,
        offset,
        bytes,
        bits,
    })
}

#[path = "nvmem_tests.rs"]
mod tests;
