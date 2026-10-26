//! Device descriptor.
//!
//! Spec: `bus/` §3.1 `DeviceInfo`. Simplified for Stage 2/3-side-track:
//! the canonical registry entry is a `BusDevice` that names the
//! device, its location, and enough identification for drivers to
//! decide whether they care (vendor/device/class for PCIe; compatible
//! string + optional magic for MMIO). BAR sizing, MSI-X capability
//! layout, IOMMU group, and NUMA node are future work.

use core::fmt;

use crate::addr::{BusAddr, PcieAddr};
use narf_memory::PhysAddr;

/// Identification fields common across transports. PCIe populates all
/// five; MMIO virtio populates `vendor`/`device` from the transport's
/// own registers (magic + device id) with `class` left at 0 and
/// `subsystem_vendor`/`subsystem_id` left at 0.
///
/// Subsystem IDs come from the PCI type-0 header at offsets 0x2C
/// (Subsystem Vendor ID) and 0x2E (Subsystem ID) per PCI 3.0 §6.2.4.
/// Linux reads them in `drivers/pci/probe.c::pci_read_bases` (called
/// by `pci_setup_device`) and stores as `dev->subsystem_vendor` /
/// `dev->subsystem_device`.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct DeviceId {
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    /// PCI Subsystem Vendor ID (cfg offset 0x2C). 0 for non-PCIe transports.
    pub subsystem_vendor: u16,
    /// PCI Subsystem ID (cfg offset 0x2E). 0 for non-PCIe transports.
    pub subsystem_id: u16,
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeviceId({:04x}:{:04x}, class={:06x}, subsys={:04x}:{:04x})",
            self.vendor, self.device, self.class, self.subsystem_vendor, self.subsystem_id
        )
    }
}

/// Inline capacity of a [`PlatformDevice`]'s `compatible` list (the
/// raw NUL-separated property value, most-specific string first).
/// 128 bytes covers realistic lists (QEMU `virt`'s longest is the
/// 24-byte `arm,pl011\0arm,primecell`); a longer list is truncated
/// at a string boundary — the most-specific strings, which matching
/// prefers, are the ones kept.
pub const PLATFORM_COMPATIBLE_CAP: usize = 128;

/// Maximum `reg` windows a [`PlatformDevice`] record carries.
/// Windows past the cap are dropped at enumeration (the first
/// window — the one `BusAddr` keys on — is always kept).
pub const PLATFORM_MAX_REGS: usize = 4;

/// Maximum interrupts a [`PlatformDevice`] record carries.
pub const PLATFORM_MAX_IRQS: usize = 4;

/// One decoded `reg` window of a platform device: physical base +
/// length, already translated through any ancestor `ranges`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RegWindow {
    pub base: PhysAddr,
    pub len: u64,
}

/// One interrupt of a platform device, decoded from its DT
/// specifier and resolved to the architectural interrupt id the
/// `interrupts` crate routes. Resolution happens at enumeration
/// time against the interrupt parent's binding; only GIC bindings
/// (the 3-cell `arm,gic-*` form: type, number, flags) are resolved
/// today — a device whose parent is another controller keeps its
/// `irq_parent` phandle on the record but carries no resolved
/// entries.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DtIrq {
    /// Architectural INTID (SPI: `32 + number`, PPI: `16 + number`).
    pub intid: u32,
    /// The DT specifier's flags cell (trigger type / polarity),
    /// passed through uninterpreted.
    pub flags: u32,
}

/// A devicetree-described platform device: the DT analogue of the
/// PCIe descriptor. Carries the node's identity (`compatible` list,
/// most-specific first), its decoded `reg` windows (translated
/// through ancestor `ranges` at enumeration), its interrupts
/// resolved against the interrupt parent (in practice the GIC),
/// and the phandles the framework layer binds at probe time.
///
/// Fixed-size and `Copy` like the rest of `BusDevice`: the registry
/// hands devices out by value, so no part of the record may point
/// into the (potentially unmapped-after-boot) DTB.
#[derive(Copy, Clone)]
pub struct PlatformDevice {
    /// Raw `compatible` value: NUL-separated strings, possibly
    /// truncated at a string boundary to
    /// [`PLATFORM_COMPATIBLE_CAP`]. Length is `compatible_len`.
    pub compatible: [u8; PLATFORM_COMPATIBLE_CAP],
    pub compatible_len: u8,
    /// Decoded `reg` windows; the first `reg_count` entries are
    /// valid. Window 0's base is the device's `BusAddr`.
    pub regs: [RegWindow; PLATFORM_MAX_REGS],
    pub reg_count: u8,
    /// Resolved interrupts; the first `irq_count` entries are
    /// valid.
    pub irqs: [DtIrq; PLATFORM_MAX_IRQS],
    pub irq_count: u8,
    /// Phandle of the node's interrupt parent (0 = none declared or
    /// inherited).
    pub irq_parent: u32,
    /// This node's own `phandle` (0 = none declared).
    pub phandle: u32,
}

impl PlatformDevice {
    /// An empty record; fill via [`PlatformDevice::set_compatible`],
    /// [`PlatformDevice::push_reg`], [`PlatformDevice::push_irq`].
    pub const fn new() -> Self {
        Self {
            compatible: [0; PLATFORM_COMPATIBLE_CAP],
            compatible_len: 0,
            regs: [RegWindow {
                base: PhysAddr::new(0),
                len: 0,
            }; PLATFORM_MAX_REGS],
            reg_count: 0,
            irqs: [DtIrq { intid: 0, flags: 0 }; PLATFORM_MAX_IRQS],
            irq_count: 0,
            irq_parent: 0,
            phandle: 0,
        }
    }

    /// Copy a raw `compatible` property value (NUL-separated
    /// strings) into the record, truncating at a string boundary
    /// when the value exceeds the inline capacity: whole strings
    /// are kept in order, the first string that does not fit ends
    /// the copy.
    pub fn set_compatible(&mut self, value: &[u8]) {
        let mut out = 0usize;
        let mut start = 0usize;
        while start < value.len() {
            let end = value[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| start + p)
                .unwrap_or(value.len());
            let entry_len = end - start + 1; // include the NUL
            if out + entry_len > PLATFORM_COMPATIBLE_CAP {
                break;
            }
            self.compatible[out..out + entry_len - 1].copy_from_slice(&value[start..end]);
            self.compatible[out + entry_len - 1] = 0;
            out += entry_len;
            start = end + 1;
        }
        self.compatible_len = out as u8;
    }

    /// Append a `reg` window. Returns `false` (window dropped)
    /// when the record is already at [`PLATFORM_MAX_REGS`].
    pub fn push_reg(&mut self, window: RegWindow) -> bool {
        let i = self.reg_count as usize;
        if i >= PLATFORM_MAX_REGS {
            return false;
        }
        self.regs[i] = window;
        self.reg_count += 1;
        true
    }

    /// Append a resolved interrupt. Returns `false` (interrupt
    /// dropped) when the record is already at [`PLATFORM_MAX_IRQS`].
    pub fn push_irq(&mut self, irq: DtIrq) -> bool {
        let i = self.irq_count as usize;
        if i >= PLATFORM_MAX_IRQS {
            return false;
        }
        self.irqs[i] = irq;
        self.irq_count += 1;
        true
    }

    /// The stored `compatible` value (NUL-separated, no trailing
    /// padding).
    pub fn compatible_bytes(&self) -> &[u8] {
        &self.compatible[..self.compatible_len as usize]
    }

    /// Position of `needle` in the `compatible` list — 0 is the
    /// most-specific string. `None` when absent. This is the DT
    /// matcher's specificity measure: a match against an earlier
    /// (more specific) string outranks one against a later
    /// (fallback) string.
    pub fn compatible_position(&self, needle: &str) -> Option<usize> {
        let mut pos = 0usize;
        for entry in self.compatible_bytes().split(|&b| b == 0) {
            if entry == needle.as_bytes() {
                return Some(pos);
            }
            if !entry.is_empty() {
                pos += 1;
            }
        }
        None
    }

    /// `true` iff the `compatible` list contains `needle`.
    pub fn compatible_contains(&self, needle: &str) -> bool {
        self.compatible_position(needle).is_some()
    }

    /// The most-specific compatible string ("" when the list is
    /// empty). For diagnostics.
    pub fn first_compatible(&self) -> &str {
        let bytes = self.compatible_bytes();
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        core::str::from_utf8(&bytes[..end]).unwrap_or("")
    }

    /// The decoded `reg` windows (valid prefix only).
    pub fn reg_windows(&self) -> &[RegWindow] {
        &self.regs[..self.reg_count as usize]
    }

    /// The resolved interrupts (valid prefix only).
    pub fn irq_list(&self) -> &[DtIrq] {
        &self.irqs[..self.irq_count as usize]
    }
}

impl Default for PlatformDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PlatformDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlatformDevice")
            .field("compatible", &self.first_compatible())
            .field("regs", &self.reg_windows())
            .field("irqs", &self.irq_list())
            .field("irq_parent", &self.irq_parent)
            .field("phandle", &self.phandle)
            .finish()
    }
}

/// Transport-specific extras. Kept small — a driver that needs the
/// full BAR layout asks the registry for its `BusDeviceHandle` and
/// pulls it out there (Wave 2 cap work).
#[derive(Copy, Clone)]
pub enum BusKind {
    /// PCIe function. ECAM window base lets drivers build their own
    /// cfg-space accessor after `claim()` — the bus crate holds the
    /// only mapping today and simply exposes its base.
    Pcie {
        addr: PcieAddr,
        /// Physical address of this function's 4-KiB cfg window.
        cfg_phys: PhysAddr,
    },
    /// Memory-mapped virtio transport. `device_id` mirrors the value
    /// pulled from the VIRTIO_MMIO_DEVICE_ID register (0 = invalid /
    /// empty slot, reported here only when non-zero).
    VirtioMmio {
        base: PhysAddr,
        /// Size of the VIRTIO_MMIO register window (typically 0x200).
        len: u64,
        /// VIRTIO_MMIO device ID (DeviceId register, offset 0x08).
        device_id: u32,
    },
    /// Devicetree-described platform device. The record carries the
    /// compatible identity, decoded `reg` windows, and GIC-resolved
    /// interrupts; `DeviceId` is all-zero (no PCI identity exists).
    Platform(PlatformDevice),
}

impl fmt::Debug for BusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusKind::Pcie { addr, cfg_phys } => f
                .debug_struct("Pcie")
                .field("addr", addr)
                .field("cfg_phys", cfg_phys)
                .finish(),
            BusKind::VirtioMmio {
                base,
                len,
                device_id,
            } => f
                .debug_struct("VirtioMmio")
                .field("base", base)
                .field("len", len)
                .field("device_id", device_id)
                .finish(),
            BusKind::Platform(dev) => f.debug_tuple("Platform").field(dev).finish(),
        }
    }
}

/// A discovered device. Immutable post-enumeration.
#[derive(Copy, Clone)]
pub struct BusDevice {
    pub addr: BusAddr,
    pub id: DeviceId,
    pub kind: BusKind,
}

impl fmt::Debug for BusDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusDevice")
            .field("addr", &self.addr)
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}
