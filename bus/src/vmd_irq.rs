//! VMD MSI remapping — child interrupts steered through the VMD
//! bridge (issue #933 item 4).
//!
//! Children behind a VMD bridge cannot receive MSI directly: the
//! bridge intercepts every child message and re-issues it through
//! one of *its own* MSI-X table entries. Linux `vmd.c` models this
//! as an IRQ domain whose `compose_msg` writes, into the child's
//! MSI/MSI-X slot,
//!
//! - address = the standard x86 MSI base with the **bridge MSI-X
//!   entry index** in the destination-ID field, and
//! - data = 0,
//!
//! and whose demux handler walks the fired entry's list of child
//! IRQs. NARF reproduces exactly that shape here, in `bus`, so child
//! drivers need no VMD awareness: [`crate::msix::MsixTable::
//! program_vector`] and [`crate::msi::program_msi`] check whether
//! the device lives on a registered VMD segment (see
//! [`crate::vmd_domain`]) and, if so, substitute the remapped
//! message and record the (child vector → bridge entry) mapping the
//! demux dispatches on.
//!
//! Entry-assignment policy (Linux `vmd_next_irq`): storage-class
//! children (PCI class `0x0108xx`, i.e. NVMe) get the least-loaded
//! entry at or above `first_vec + 1` — their own fast vector — while
//! every other class shares the `first_vec` entry. The assignment is
//! idempotent per (device, vector index): reprogramming a child
//! vector returns the entry it already owns.
//!
//! Spec: `bus/specification/spec.md` §3.7.

use alloc::vec::Vec;

use narf_interrupts::dispatch::{self, IrqStatus};
use narf_lib::sync::IrqSafeSpinLock;

use crate::BusAddr;

/// One child MSI/MSI-X vector bound to a bridge entry.
struct ChildVector {
    device: BusAddr,
    /// The child's own vector index (MSI-X table index; 0 for
    /// legacy MSI, whose messages all collapse onto one entry).
    index: u16,
    /// Host IRQ vector the child driver installed its handler on.
    vector: u8,
}

/// One bridge MSI-X entry: the host vector it fires plus every
/// child vector remapped onto it.
struct BridgeEntry {
    bridge_vector: u8,
    children: Vec<ChildVector>,
}

/// Remap state for one VMD bridge.
struct IrqDomain {
    segment: u16,
    first_vec: u16,
    entries: Vec<BridgeEntry>,
}

static IRQ_DOMAINS: IrqSafeSpinLock<Vec<IrqDomain>> = IrqSafeSpinLock::new(Vec::new());

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmdIrqError {
    /// A remap domain is already registered for this segment.
    DuplicateSegment,
    /// No bridge vectors were supplied.
    NoEntries,
}

/// Register the remap domain for a bridge whose MSI-X table the VMD
/// driver has already programmed: `bridge_vectors[i]` is the host
/// IRQ vector entry `i` delivers on. Installs the demux handler on
/// every vector. Ownership of the vectors transfers to the domain —
/// [`unregister_bridge_domain`] frees them.
pub fn register_bridge_domain(
    segment: u16,
    first_vec: u16,
    bridge_vectors: &[u8],
) -> Result<(), VmdIrqError> {
    if bridge_vectors.is_empty() {
        return Err(VmdIrqError::NoEntries);
    }
    {
        let mut g = IRQ_DOMAINS.lock();
        if g.iter().any(|d| d.segment == segment) {
            return Err(VmdIrqError::DuplicateSegment);
        }
        g.push(IrqDomain {
            segment,
            first_vec,
            entries: bridge_vectors
                .iter()
                .map(|&v| BridgeEntry {
                    bridge_vector: v,
                    children: Vec::new(),
                })
                .collect(),
        });
    }
    for (i, &v) in bridge_vectors.iter().enumerate() {
        dispatch::install_handler_named(v, "vmd-demux", demux_cookie(segment, i as u16), demux);
    }
    Ok(())
}

/// Tear down a bridge's remap domain: drop every child mapping,
/// remove the demux handlers, and free the bridge vectors.
pub fn unregister_bridge_domain(segment: u16) -> bool {
    let domain = {
        let mut g = IRQ_DOMAINS.lock();
        let Some(pos) = g.iter().position(|d| d.segment == segment) else {
            return false;
        };
        g.remove(pos)
    };
    for e in &domain.entries {
        dispatch::clear_handler(e.bridge_vector);
        let _ = narf_interrupts::vector::free(e.bridge_vector);
    }
    true
}

/// Assign (or re-confirm) the bridge entry for one child vector,
/// recording the mapping the demux dispatches on. Returns the entry
/// index, or `None` when no remap domain covers `segment`.
///
/// Policy mirrors Linux `vmd_next_irq`: NVMe-class children
/// (`class >> 8 == 0x0108`) spread over the least-loaded entries at
/// or above `first_vec + 1`; all other classes share `first_vec`.
pub fn assign_child_vector(
    segment: u16,
    class: u32,
    device: BusAddr,
    index: u16,
    vector: u8,
) -> Option<u16> {
    let mut g = IRQ_DOMAINS.lock();
    let d = g.iter_mut().find(|d| d.segment == segment)?;
    // Idempotent reprogramming: the child already owns an entry.
    for (i, e) in d.entries.iter_mut().enumerate() {
        if let Some(c) = e
            .children
            .iter_mut()
            .find(|c| c.device == device && c.index == index)
        {
            c.vector = vector;
            return Some(i as u16);
        }
    }
    let n = d.entries.len() as u16;
    if n == 0 {
        return None;
    }
    let first = d.first_vec.min(n - 1);
    let storage = (class >> 8) == 0x0108;
    let entry = if storage && first + 1 < n {
        // Least-loaded entry in [first + 1, n); ties go to the
        // lowest index so behaviour is deterministic.
        let mut best = first + 1;
        let mut best_load = usize::MAX;
        for i in (first + 1)..n {
            let load = d.entries[i as usize].children.len();
            if load < best_load {
                best_load = load;
                best = i;
            }
        }
        best
    } else {
        first
    };
    d.entries[entry as usize].children.push(ChildVector {
        device,
        index,
        vector,
    });
    Some(entry)
}

/// The bridge entry a child vector is currently assigned to.
pub fn entry_for_child(segment: u16, device: BusAddr, index: u16) -> Option<u16> {
    let g = IRQ_DOMAINS.lock();
    let d = g.iter().find(|d| d.segment == segment)?;
    d.entries
        .iter()
        .position(|e| {
            e.children
                .iter()
                .any(|c| c.device == device && c.index == index)
        })
        .map(|i| i as u16)
}

/// The host vector a bridge entry fires on (demux target).
pub fn bridge_vector(segment: u16, entry: u16) -> Option<u8> {
    let g = IRQ_DOMAINS.lock();
    let d = g.iter().find(|d| d.segment == segment)?;
    d.entries.get(entry as usize).map(|e| e.bridge_vector)
}

/// Drop every child mapping owned by `device`, across all domains.
/// Called from the bus detach path (spec §9.7): a detached child's
/// vectors must never be dispatched to again.
pub fn release_device(device: BusAddr) {
    let mut g = IRQ_DOMAINS.lock();
    for d in g.iter_mut() {
        for e in d.entries.iter_mut() {
            e.children.retain(|c| c.device != device);
        }
    }
}

/// The MSI message a VMD child is programmed with so its interrupt
/// lands on bridge `entry` (Linux `vmd_compose_msi_msg`): on x86_64
/// the standard LAPIC message base with the entry index in the
/// destination-ID field and a zero data word — the bridge, not the
/// child, decides what the CPU sees. The 8-bit destination field
/// caps usable entries at 256, which the host vector space already
/// guarantees. On aarch64 the message is the ITS doorbell with the
/// entry index as EventID; the bridge's own ITS translations are
/// programmed when its table entries are set up.
pub fn remap_message(entry: u16) -> (u64, u32) {
    #[cfg(target_arch = "x86_64")]
    {
        (0xFEE0_0000u64 | (((entry as u64) & 0xFF) << 12), 0)
    }
    #[cfg(target_arch = "aarch64")]
    {
        (narf_interrupts::aarch64::its::doorbell_pa(), entry as u32)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = entry;
        (0, 0)
    }
}

/// The remap message as an MSI-X table-entry word quad
/// `[addr_lo, addr_hi, data, vector_control]` (unmasked).
pub fn remap_entry_words(entry: u16) -> [u32; 4] {
    let (addr, data) = remap_message(entry);
    [addr as u32, (addr >> 32) as u32, data, 0]
}

fn demux_cookie(segment: u16, entry: u16) -> u64 {
    ((segment as u64) << 16) | (entry as u64)
}

/// Demux handler installed on every bridge vector. Snapshots the
/// fired entry's child vectors under the registry lock, drops the
/// lock, then re-dispatches each through the normal IRQ path so the
/// child driver's own handler runs with its usual bookkeeping.
/// Returns `None` (spurious) when the entry has no children — the
/// honest signal that a bridge interrupt arrived with nobody
/// behind it.
fn demux(cookie: u64) -> IrqStatus {
    let segment = (cookie >> 16) as u16;
    let entry = (cookie & 0xFFFF) as u16;
    let vectors: Vec<u8> = {
        let g = IRQ_DOMAINS.lock();
        match g
            .iter()
            .find(|d| d.segment == segment)
            .and_then(|d| d.entries.get(entry as usize))
        {
            Some(e) => e.children.iter().map(|c| c.vector).collect(),
            None => return IrqStatus::None,
        }
    };
    if vectors.is_empty() {
        return IrqStatus::None;
    }
    for v in vectors {
        dispatch::on_irq(v);
    }
    IrqStatus::Handled
}

#[doc(hidden)]
/// Test-only: tear down every remap domain between smokes.
pub fn __reset_for_test() {
    let segments: Vec<u16> = IRQ_DOMAINS.lock().iter().map(|d| d.segment).collect();
    for s in segments {
        unregister_bridge_domain(s);
    }
}
