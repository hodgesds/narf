//! Devicetree enumeration — the single-walker DT path.
//!
//! Spec: `bus/` §3.2, §5 aarch64; design: embedded audit R1
//! `boot-enumeration.md` §5. Everything here consumes
//! `narf_firmware_fdt` — the tree's one FDT parser. (The private
//! hand-rolled walker this module replaces lived in
//! `bus/src/aarch64/mod.rs` and knew only `virtio_mmio@*` /
//! `pcie@*` node *names*; matching is by `compatible` now, per the
//! devicetree specification.)
//!
//! Two layers:
//! - [`decode_devices`] — pure decode of a blob into device-shaped
//!   records: `compatible`, `reg` windows translated through
//!   ancestor `ranges`, interrupts resolved to architectural
//!   INTIDs against their (inherited) interrupt parent. No
//!   hardware access; pinned against the real QEMU `virt` DTB
//!   fixture by the census smoke.
//! - [`enumerate_dt`] (aarch64) — turns decoded records into
//!   registry devices: platform records as-is, virtio-mmio slots
//!   probed for a populated device-id (the legacy behaviour), the
//!   PCIe host bridge's ECAM walked through the shared PCIe
//!   enumerator under the legacy low-4-GiB guard.
//!
//! Emission rule (audit §5.3, tightened where noted): a node
//! becomes a device when it has `status` absent-or-okay (`fail` /
//! `reserved` nodes describe broken or held-off hardware and are
//! NOT probed — the tightening), a `compatible`, and at least one
//! translatable `reg` window. The `/cpus` subtree is excluded:
//! CPU nodes are SMP bring-up's input, not bus devices.

use alloc::vec::Vec;

use narf_firmware_fdt as fdt;
use narf_memory::PhysAddr;

use crate::addr::BusAddr;
use crate::device::{BusDevice, BusKind, DeviceId, DtIrq, PlatformDevice, RegWindow};

/// Upper bound on the DTB size the enumerator will map — the same
/// bound `boot/` applies (`MAX_DTB_SIZE`).
pub(crate) const MAX_DTB_BYTES: usize = 2 * 1024 * 1024;

/// Platform devices have no PCI identity.
const ZERO_ID: DeviceId = DeviceId {
    vendor: 0,
    device: 0,
    class: 0,
    subsystem_vendor: 0,
    subsystem_id: 0,
};

/// One DT node decoded into device-shaped data (uncapped — the
/// [`PlatformDevice`] record applies its inline caps when the
/// registry record is built).
#[derive(Debug)]
pub struct DtDevice {
    /// Raw `compatible` value (NUL-separated, most-specific first).
    pub compatible: Vec<u8>,
    /// Decoded `reg` windows, translated through ancestor `ranges`.
    pub regs: Vec<(u64, u64)>,
    /// The interrupt parent the node's specifiers were resolved
    /// against (phandle; 0 = none declared or inherited).
    pub irq_parent: u32,
    /// Interrupts resolved to `(INTID, flags)` — GIC-parented
    /// specifiers only; empty when the parent is another
    /// controller (its phandle stays on `irq_parent`).
    pub irqs: Vec<(u32, u32)>,
    /// The node's own `phandle` (0 = none declared).
    pub phandle: u32,
}

impl DtDevice {
    /// `true` iff the node's `compatible` list contains `needle`.
    pub fn compatible_contains(&self, needle: &str) -> bool {
        fdt::compatible_matches(&self.compatible, needle)
    }

    /// Build the registry record for this device. The record's
    /// `BusAddr` keys on the first `reg` window's base.
    pub fn to_bus_device(&self) -> BusDevice {
        let mut rec = PlatformDevice::new();
        rec.set_compatible(&self.compatible);
        for &(base, len) in &self.regs {
            let _ = rec.push_reg(RegWindow {
                base: PhysAddr::new(base),
                len,
            });
        }
        for &(intid, flags) in &self.irqs {
            let _ = rec.push_irq(DtIrq { intid, flags });
        }
        rec.irq_parent = self.irq_parent;
        rec.phandle = self.phandle;
        BusDevice {
            addr: BusAddr::Mmio(PhysAddr::new(self.regs.first().map(|r| r.0).unwrap_or(0))),
            id: ZERO_ID,
            kind: BusKind::Platform(rec),
        }
    }
}

/// Ancestor state the single walk maintains per depth: what a
/// node's children need from it (`ranges` for address translation,
/// the effective interrupt parent for specifier resolution).
struct AncestorFrame {
    /// Raw `ranges` value (None = absent or empty; an empty
    /// `ranges` is the identity map per DTSpec §2.3.8).
    ranges: Option<Vec<u8>>,
    /// This node's own `#address-cells` / `#size-cells` (declared
    /// or the DTSpec defaults — not inherited, mirroring the
    /// walker). Governs this node's ranges child side.
    own_cells: fdt::Cells,
    /// The cells governing this node's own `reg` (its parent's
    /// cells, as the walker reports them). Governs this node's
    /// ranges parent side.
    parent_cells: fdt::Cells,
    /// Effective interrupt parent in force at this node.
    irq_parent: u32,
}

fn raw_prop<'a>(props: fdt::PropIter<'a>, name: &str) -> Option<&'a [u8]> {
    for (n, v) in props {
        if n == name {
            return Some(v);
        }
    }
    None
}

fn read_cells(value: &[u8], off: usize, cells: usize) -> Option<u64> {
    let mut out = 0u64;
    for i in 0..cells {
        let b = value.get(off + i * 4..off + i * 4 + 4)?;
        out = (out << 32) | u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
    }
    Some(out)
}

/// Translate `addr` through one node's `ranges`: entries are
/// (child addr, parent addr, length) triples decoded with the
/// node's own cells (child side + length) and its parent's cells
/// (parent side). `None` when no entry covers `addr` — the window
/// is then untranslatable and dropped by the caller rather than
/// emitted at a wrong address.
fn translate_ranges(ranges: &[u8], frame: &AncestorFrame, addr: u64) -> Option<u64> {
    let child_cells = frame.own_cells.address as usize;
    let parent_cells = frame.parent_cells.address as usize;
    let size_cells = frame.own_cells.size as usize;
    let entry_bytes = (child_cells + parent_cells + size_cells) * 4;
    if entry_bytes == 0 {
        return None;
    }
    let mut off = 0usize;
    while off + entry_bytes <= ranges.len() {
        let child = read_cells(ranges, off, child_cells)?;
        let parent = read_cells(ranges, off + child_cells * 4, parent_cells)?;
        let len = read_cells(ranges, off + (child_cells + parent_cells) * 4, size_cells)?;
        if addr >= child && addr - child < len {
            return Some(parent + (addr - child));
        }
        off += entry_bytes;
    }
    None
}

/// `true` iff `phandle` names an interrupt controller with a GIC
/// binding (3-cell specifier: type, number, flags). Cached per
/// enumeration — resolving a parent walks the tree.
fn is_gic_parent(blob: &[u8], phandle: u32, cache: &mut Vec<(u32, bool)>) -> bool {
    if let Some(&(_, gic)) = cache.iter().find(|(p, _)| *p == phandle) {
        return gic;
    }
    const GIC_BINDINGS: [&str; 6] = [
        "arm,gic-v3",
        "arm,gic-400",
        "arm,gic-v2",
        "arm,cortex-a15-gic",
        "arm,cortex-a9-gic",
        "arm,pl390",
    ];
    let mut gic = false;
    fdt::for_phandle(blob, phandle, |_path, props, _cells| {
        if fdt::prop_interrupt_cells(props) != Some(3) {
            return;
        }
        for (name, value) in props {
            if name == "compatible" {
                for binding in GIC_BINDINGS {
                    if fdt::compatible_matches(value, binding) {
                        gic = true;
                    }
                }
            }
        }
    });
    cache.push((phandle, gic));
    gic
}

/// Decode every device-shaped node in `blob`. Pure: no hardware
/// access, deterministic in the blob. See the module docs for the
/// emission rule.
pub fn decode_devices(blob: &[u8]) -> Vec<DtDevice> {
    let mut out: Vec<DtDevice> = Vec::new();
    // ancestors[d] describes the node at depth d; [0] is the root,
    // whose own frame the walk never reports — seed it from the
    // root's declarations (its interrupt-parent is the tree-wide
    // default; root has no usable ranges).
    let mut ancestors: Vec<AncestorFrame> = alloc::vec![AncestorFrame {
        ranges: None,
        own_cells: fdt::Cells::DEFAULT,
        parent_cells: fdt::Cells::DEFAULT,
        irq_parent: fdt::root_prop_u32(blob, "interrupt-parent").unwrap_or(0),
    }];
    let mut gic_cache: Vec<(u32, bool)> = Vec::new();

    fdt::walk_with_cells(blob, |path, props, parent_cells| {
        let depth = path.depth() as usize;
        if depth == 0 {
            return; // the walk never reports the root; stay total
        }
        // The chain above this node is its ancestor chain; drop
        // whatever a previous subtree left at this depth and below.
        ancestors.truncate(depth);
        if ancestors.len() < depth {
            return; // unreachable on a well-formed walk; stay total
        }
        let inherited_parent = ancestors[depth - 1].irq_parent;
        let effective_parent = fdt::prop_interrupt_parent(props).or(if inherited_parent != 0 {
            Some(inherited_parent)
        } else {
            None
        });
        let own_cells = fdt::Cells {
            address: fdt::prop_u32(props, "#address-cells").unwrap_or(2),
            size: fdt::prop_u32(props, "#size-cells").unwrap_or(1),
        };
        let ranges = match raw_prop(props, "ranges") {
            Some(v) if !v.is_empty() => Some(v.to_vec()),
            _ => None,
        };
        ancestors.push(AncestorFrame {
            ranges,
            own_cells,
            parent_cells,
            irq_parent: effective_parent.unwrap_or(0),
        });

        // ── Emission filter ──────────────────────────────────
        if fdt::node_status(props) != fdt::Status::Okay {
            return;
        }
        if path.segment(0) == Some("cpus") {
            return;
        }
        let Some(compatible) = raw_prop(props, "compatible") else {
            return;
        };
        let Some(reg_raw) = raw_prop(props, "reg") else {
            return;
        };
        let entry_bytes = parent_cells.entry_bytes();
        if entry_bytes == 0 {
            return;
        }
        let mut regs: Vec<(u64, u64)> = Vec::new();
        let mut off = 0usize;
        while off + entry_bytes <= reg_raw.len() {
            let Some((raw_addr, size)) = parent_cells.read_one_reg(reg_raw, off) else {
                break;
            };
            off += entry_bytes;
            // Lift the address from the parent bus's space to CPU
            // space through each ancestor bus's `ranges`, nearest
            // first. An address no entry covers is dropped, not
            // emitted untranslated.
            let mut addr = raw_addr;
            let mut translated = true;
            for k in (1..depth).rev() {
                if let Some(ranges) = &ancestors[k].ranges {
                    match translate_ranges(ranges, &ancestors[k], addr) {
                        Some(a) => addr = a,
                        None => {
                            translated = false;
                            break;
                        }
                    }
                }
            }
            if translated {
                regs.push((addr, size));
            }
        }
        if regs.is_empty() {
            return;
        }

        // ── Interrupts ───────────────────────────────────────
        let mut irqs: Vec<(u32, u32)> = Vec::new();
        let mut spec_parent = 0u32;
        fdt::for_each_interrupt(blob, props, effective_parent, |parent, cells| {
            spec_parent = parent;
            if cells.len() == 3 && is_gic_parent(blob, parent, &mut gic_cache) {
                let intid = match cells[0] {
                    0 => 32 + cells[1], // SPI
                    1 => 16 + cells[1], // PPI
                    _ => return,
                };
                irqs.push((intid, cells[2]));
            }
        });

        out.push(DtDevice {
            compatible: compatible.to_vec(),
            regs,
            irq_parent: if spec_parent != 0 {
                spec_parent
            } else {
                effective_parent.unwrap_or(0)
            },
            irqs,
            phandle: fdt::prop_phandle(props).unwrap_or(0),
        });
    });
    out
}

// ── Hardware-facing enumeration (aarch64) ───────────────────────

/// Magic value at offset 0x00 of every virtio-mmio transport.
/// ASCII "virt" little-endian = 0x7472_6976. Spec §4.2.2.
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

/// Offset of the DeviceID register.
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x0008;

/// Probe a virtio-mmio transport: check the magic, read the
/// device-id register, and build a `BusDevice` iff the slot is
/// populated. Moved verbatim from the legacy aarch64 walker.
///
/// The descriptor records the *physical* base, which is what a bus
/// descriptor should carry and what `VirtioMmioDevice::probe` maps
/// later; the registers are read here through a mapping of our own.
///
/// # Safety
/// `base_addr` must name a real virtio-mmio transport window at
/// least `len` bytes long.
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn probe_virtio_mmio(base_addr: u64, len: u64) -> Option<BusDevice> {
    use core::sync::atomic::{compiler_fence, Ordering};
    // A transport slot is 0x200 bytes; `ioremap` rounds sub-page
    // requests up and caches by range, so the 32 slots sharing a
    // page share one mapping.
    // SAFETY: a virtio-mmio window the machine describes; ours
    // while mapped.
    let mapping = unsafe {
        narf_memory::ioremap::ioremap(base_addr, len, narf_memory::ioremap::MmioAttrs::Device)
    }
    .ok()?;
    let regs = mapping.va();
    let base_ptr = regs as *const u32;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted MMIO window.
    let magic = unsafe { core::ptr::read_volatile(base_ptr) };
    compiler_fence(Ordering::SeqCst);
    if magic != VIRTIO_MMIO_MAGIC {
        return None;
    }

    compiler_fence(Ordering::SeqCst);
    let device_id =
        // SAFETY: same region, +0x08 is still inside the 0x200-byte window.
        unsafe { core::ptr::read_volatile((regs + VIRTIO_MMIO_DEVICE_ID) as *const u32) };
    compiler_fence(Ordering::SeqCst);
    if device_id == 0 {
        return None;
    } // empty slot

    let phys = PhysAddr::new(base_addr);
    Some(BusDevice {
        addr: BusAddr::Mmio(phys),
        id: DeviceId {
            // virtio-mmio doesn't expose PCI-style vendor/device; we
            // synthesise a recognisable pair so drivers can filter:
            // vendor = 'V' + 'I' = 0x5649 (Virtio spec reserves 0x1AF4
            // for the PCI transport, but MMIO is transport-distinct).
            vendor: 0x1AF4, // Red Hat / virtio — matches the PCI transport
            device: device_id as u16,
            class: 0,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::VirtioMmio {
            base: phys,
            len,
            device_id,
        },
    })
}

/// Full DT enumeration over a validated blob: platform records for
/// device-shaped nodes, populated virtio-mmio slots as
/// `VirtioMmio` devices, and the PCIe host bridge's children via
/// the shared ECAM enumerator.
///
/// # Safety
/// The blob must describe the machine this runs on: enumeration
/// probes the DT-described virtio-mmio windows and, when the host
/// bridge's ECAM window falls in the low 4 GiB, walks it — the
/// same contract the legacy name-based walker ran under.
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn enumerate_dt(blob: &[u8]) -> Vec<BusDevice> {
    let mut out = Vec::new();
    for dev in decode_devices(blob) {
        if dev.compatible_contains("virtio,mmio") {
            if let Some(&(base, len)) = dev.regs.first() {
                // SAFETY: DT-described virtio-mmio window on this
                // machine (see the fn-level contract).
                if let Some(d) = unsafe { probe_virtio_mmio(base, len) } {
                    out.push(d);
                }
            }
            continue;
        }
        let bridge = dev.compatible_contains("pci-host-ecam-generic");
        let first_window = dev.regs.first().copied();
        out.push(dev.to_bus_device());
        if bridge {
            if let Some((ecam_base, ecam_size)) = first_window {
                // Legacy guard, preserved verbatim: with QEMU
                // virt's default highmem ECAM at 0x4010_0000_0000
                // the window sits outside the identity map and
                // bare reads would abort, so only a low-4-GiB ECAM
                // is walked.
                if ecam_base < 0x1_0000_0000 && ecam_size > 0 {
                    // 1 MiB per bus per ECAM convention.
                    let n_buses = (ecam_size / 0x10_0000).min(crate::pcie::MAX_BUSES as u64) as u16;
                    // SAFETY: DTB asserts the ECAM region is mapped
                    // Device memory by the firmware / boot stub for
                    // low-4-GiB addresses; the walker only does
                    // aligned 4-byte reads and skips unpopulated
                    // slots.
                    let pcie =
                        unsafe { crate::pcie::enumerate_n(PhysAddr::new(ecam_base), n_buses) };
                    out.extend(pcie);
                }
            }
        }
    }
    out
}
