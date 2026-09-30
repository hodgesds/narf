//! PCI NHI discovery. Modern USB4 controllers use class 0x0c0340;
//! older Intel PCI identities remain explicit matches. Native ownership and
//! DMA enablement are deferred to the Late-stage connection manager.

use core::sync::atomic::{AtomicU32, Ordering};

use narf_bus::{
    map_bar, register_pci_driver, BusDevice, BusDeviceCap, MatchKind, MmioRegion, PciMatch,
    ProbeError,
};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// Intel PCI vendor ID.
pub const INTEL_VENDOR: u16 = 0x8086;

/// `REG_CAPS` — last 11 bits hold the hop (adapter port) count for
/// the NHI port, bits 23:16 hold the NHI silicon version. Linux
/// `drivers/thunderbolt/nhi_regs.h` line 113. Stable across every
/// NHI revision since Falcon Ridge.
pub const REG_CAPS: u64 = 0x39640;
/// Mask covering the silicon-version byte of `REG_CAPS`.
pub const REG_CAPS_VERSION_MASK: u32 = 0x00FF_0000;
/// Right-shift applied to extract the version byte.
pub const REG_CAPS_VERSION_SHIFT: u32 = 16;
/// Mask covering the hop (adapter-port) count in the low 11 bits.
pub const REG_CAPS_HOP_COUNT_MASK: u32 = 0x0000_07FF;
/// Sentinel version-byte value Linux uses for the NHI rev-2 silicon
/// (Falcon Ridge / Alpine Ridge onward). Stage-0 just records what
/// the silicon reports; nothing branches on this yet.
pub const REG_CAPS_VERSION_2: u32 = 0x40;

/// BAR index for the NHI MMIO register block. Linux NHI binds BAR0
/// (`pci_iomap(pdev, 0, 0)` in `nhi.c::nhi_probe`).
pub const NHI_BAR: u8 = 0;

/// NHI / Thunderbolt PCI device-ID table.
///
/// Sourced from `nhi_ids[]` in Linux `drivers/thunderbolt/pci.c`
/// (register identities; controller behavior follows the USB4 class).
/// Coverage spans:
/// - Tiger Lake (Maple Ridge controllers + on-die)
/// - Alder Lake (Goshen Ridge external + Alder Lake-P on-die)
/// - Raptor Lake-P / -H
/// - Meteor Lake (M / P)
/// - Lunar Lake
/// - Wildcat Lake
/// - Barlow Ridge discrete (USB4 80G / 40G accessory hubs)
///
/// We *do not* register the older Alpine / Titan Ridge IDs at
/// Stage-0. The user's bring-up targets (Zen2 + Phoenix HawkPoint1)
/// don't ship them, and Linux carries a separate `icm` driver
/// (`icm.c`) for the legacy ICM-mode controllers; the NHI registers
/// here all assume the modern USB4 CM firmware shape. Pre-USB4 SKUs
/// are a follow-up.
pub const TB_DEVICE_IDS: &[(u16, &str)] = &[
    // Tiger Lake — Linux `PCI_DEVICE_ID_INTEL_TGL_NHI{0,1}`.
    // 0x9A1B is the user-cited "Tiger Lake (Maple Ridge)" entry.
    (0x9A1B, "tgl-nhi0"),
    (0x9A1D, "tgl-nhi1"),
    (0x9A1F, "tgl-h-nhi0"),
    (0x9A21, "tgl-h-nhi1"),
    // Alder Lake — Linux `PCI_DEVICE_ID_INTEL_ADL_NHI{0,1}`.
    (0x463E, "adl-nhi0"),
    (0x466D, "adl-nhi1"),
    // Raptor Lake — Linux `PCI_DEVICE_ID_INTEL_RPL_NHI{0,1}`.
    (0xA73E, "rpl-nhi0"),
    (0xA76D, "rpl-nhi1"),
    (0x7EB2, "mtl-m-nhi0"),
    (0x7EC2, "mtl-p-nhi0"),
    (0x7EC3, "mtl-p-nhi1"),
    // Lunar Lake — Linux `PCI_DEVICE_ID_INTEL_LNL_NHI{0,1}`.
    (0xA833, "lnl-nhi0"),
    (0xA834, "lnl-nhi1"),
    // Panther Lake — Linux `PCI_DEVICE_ID_INTEL_PTL_{M,P}_NHI{0,1}`.
    (0xE333, "ptl-m-nhi0"),
    (0xE334, "ptl-m-nhi1"),
    (0xE433, "ptl-p-nhi0"),
    (0xE434, "ptl-p-nhi1"),
    // Wildcat Lake — Linux `PCI_DEVICE_ID_INTEL_WCL_NHI0`.
    (0x4D33, "wcl-nhi0"),
    // Discrete USB4 accessory: Barlow Ridge 80G / 40G NHI.
    // 0x5781 is the user-cited "Meteor Lake / Lunar Lake" SKU —
    // it's actually the Barlow Ridge 80G host NHI Intel ships
    // beside MTL / LNL boards.
    (0x5781, "barlow-ridge-80g"),
    (0x5784, "barlow-ridge-40g"),
];

/// Counter of detected Thunderbolt / USB4 NHI controllers. Used by
/// the smokes to confirm whether the probe path ran on the current
/// run, without needing to plumb a typed return out of probe.
static TB_INSTANCE_COUNT: AtomicU32 = AtomicU32::new(0);
/// Most recently observed NHI version byte (`REG_CAPS` bits 23:16).
/// Test-observable; on real-HW Maple Ridge / Goshen Ridge the silicon
/// reports `REG_CAPS_VERSION_2` (0x40).
static TB_LAST_NHI_VERSION: AtomicU32 = AtomicU32::new(0);
/// Most recently observed hop / adapter-port count (low 11 bits of
/// `REG_CAPS`). Test-observable.
static TB_LAST_HOP_COUNT: AtomicU32 = AtomicU32::new(0);

/// Errors from NHI Stage-0 bring-up. Every variant folds to
/// `ProbeError::BadDevice` in `probe`; the typed surface keeps the
/// smokes' assertions readable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TbError {
    /// BAR0 wasn't mappable (rare — usually means a firmware bug in
    /// resource assignment, since the NHI cfg-space header is
    /// otherwise standard PCIe Type 0).
    BarMapFailed,
    /// BAR0 was too small to contain `REG_CAPS`. The smallest NHI
    /// register block we expect is ~256 KiB; anything smaller is
    /// either a stub device or a misprogrammed BAR.
    BarTooSmall,
}

/// One discovered NHI controller — just enough state to satisfy the
/// Stage-0 announce + test introspection.
#[derive(Copy, Clone, Debug)]
pub struct Nhi {
    /// PCI device-ID of the controller.
    pub device_id: u16,
    /// Human-readable SKU tag — entry's `.1` from `TB_DEVICE_IDS`.
    pub sku: &'static str,
    /// BAR0 mapping (NHI MMIO).
    pub bar0: MmioRegion,
    /// `REG_CAPS[23:16]` — NHI silicon version byte.
    pub nhi_version: u8,
    /// `REG_CAPS[10:0]` — hop / adapter-port count.
    pub hop_count: u16,
}

impl Nhi {
    /// Bring up the NHI in-place: map BAR0, read identity registers.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 exclusively. `map_bar` performs
    /// the standard PCIe sizing dance which writes briefly to cfg
    /// space.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, TbError> {
        // SAFETY: forwarded — caller owns BAR0.
        let bar0 = unsafe { map_bar(device, NHI_BAR) }.map_err(|_| TbError::BarMapFailed)?;

        // `REG_CAPS` lives at 0x39640. If the BAR doesn't even cover
        // that offset we're either talking to a stub or BAR0 wasn't
        // resized; either way Stage-0 can't proceed.
        if bar0.len < REG_CAPS + 4 {
            return Err(TbError::BarTooSmall);
        }

        // SAFETY: bar0 is identity-mapped MMIO; REG_CAPS verified in
        // range above; the NHI cfg block tolerates a 32-bit read at
        // every register documented in `nhi_regs.h`.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let caps = unsafe { bar0.read32(REG_CAPS) };

        let nhi_version = ((caps & REG_CAPS_VERSION_MASK) >> REG_CAPS_VERSION_SHIFT) as u8;
        let hop_count = (caps & REG_CAPS_HOP_COUNT_MASK) as u16;

        Ok(Self {
            device_id: device.id.device,
            sku: if device.id.vendor == INTEL_VENDOR {
                sku_name(device.id.device).unwrap_or("intel-usb4")
            } else if device.id.vendor == 0x1022 {
                "amd-usb4"
            } else {
                "usb4-nhi"
            },
            bar0,
            nhi_version,
            hop_count,
        })
    }
}

/// Look up the human-readable SKU tag for a Thunderbolt device ID.
pub fn sku_name(device_id: u16) -> Option<&'static str> {
    TB_DEVICE_IDS
        .iter()
        .find(|(did, _)| *did == device_id)
        .map(|(_, name)| *name)
}

/// Per-driver `probe` invoked by the bus driver-match dispatcher
/// once a matching device is discovered.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError> {
    // Keep the probe guard consistent with explicit IDs and the USB4 class.
    if !matches_controller(device.id.vendor, device.id.device, device.id.class) {
        return Err(ProbeError::NotForThisDriver);
    }
    cap.invoke(PowerOn(&device))
        .map_err(|_| ProbeError::BadDevice)??;

    // Decode registers now. Native ownership, ring setup and bus-master
    // enablement belong to the connection manager's Late-stage worker.
    narf_bus::pci::set_command(&cap, &device, narf_bus::pci::cmd::MEM_SPACE)
        .map_err(|_| ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let nhi = match unsafe { Nhi::bring_up(&device, &cap) } {
        Ok(n) => n,
        Err(_) => return Err(ProbeError::BadDevice),
    };

    TB_INSTANCE_COUNT.fetch_add(1, Ordering::AcqRel);
    TB_LAST_NHI_VERSION.store(nhi.nhi_version as u32, Ordering::Release);
    TB_LAST_HOP_COUNT.store(nhi.hop_count as u32, Ordering::Release);
    crate::runtime::retain(device, cap, nhi);

    // Stage-0 announce. Shape mirrors `i915` / `nvme` / `vmd`
    // probe-announce lines so the boot transcript is grep-friendly.
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "thunderbolt: detected {} BAR0={:#018x}, NHI version={:#04x}, {} adapter ports",
            nhi.sku,
            nhi.bar0.phys.raw(),
            nhi.nhi_version,
            nhi.hop_count,
        );
    }

    // NHI is a USB4 host bridge — not a Block / Net / etc. consumer.
    // Use the `UsbHost` bucket; USB4 is a superset of USB and the
    // CM eventually surfaces a host-controller-equivalent interface
    // for downstream peripherals. A dedicated `Usb4Host` variant
    // can land once the CM driver is in tree.
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("usb4-nhi"),
        kind: narf_drivers::BoundKind::UsbHost,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::UsbHost.default_domain(),
    });

    Ok(())
}

/// Register the Thunderbolt / USB4 NHI driver with the bus-level
/// match table. Trusted in-tree drivers call this from a
/// Stage::Device initcall (see `lib.rs::register_initcalls`).
///
/// Every device ID lands as `MatchKind::VendorDevice` so the bus
/// tie-breaker picks us at full specificity over any later class
/// backstop that may match the USB4-host class triple.
pub fn register_pci_driver_thunderbolt() {
    register_pci_driver(PciMatch {
        name: "usb4-nhi",
        kind: MatchKind::ClassFull {
            class: 0x0c,
            subclass: 3,
            prog_if: 0x40,
        },
        probe,
    });
    for (did, name) in TB_DEVICE_IDS.iter().copied() {
        register_pci_driver(PciMatch {
            name,
            kind: MatchKind::VendorDevice {
                vendor: INTEL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Linux pci.c binds USB4 NHIs by full class, including AMD Pink Sardine.
/// PCIe tunnel bridges (0604xx) and xHCI (0c0330) remain separate drivers.
pub fn matches_controller(vendor: u16, device: u16, class: u32) -> bool {
    class == 0x0c0340 || (vendor == INTEL_VENDOR && sku_name(device).is_some())
}

struct PowerOn<'a>(&'a BusDevice);
impl CapOp<BusDeviceCap, Write> for PowerOn<'_> {
    type Output = Result<(), ProbeError>;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let narf_bus::BusKind::Pcie { cfg_phys, .. } = self.0.kind else {
                return Err(ProbeError::NotForThisDriver);
            };
            // SAFETY: probe owns the PCI function; access is gated by invoke.
            let offset = match unsafe { narf_bus::pci_cap::find_cap(self.0, 1) } {
                Ok(Some(v)) => v,
                Ok(None) | Err(narf_bus::pci_cap::CapError::NoCapList) => return Ok(()),
                Err(_) => return Err(ProbeError::BadDevice),
            };
            let pointer = narf_bus::ecam::ptr_for(cfg_phys, offset + 4)
                .ok_or(ProbeError::BadDevice)?
                .cast::<u16>();
            // SAFETY: mapped and aligned PMCSR of the owned PCI function.
            let state = unsafe { pointer.read_volatile() };
            if state == u16::MAX {
                return Err(ProbeError::BadDevice);
            }
            if state & 3 != 0 {
                // SAFETY: D0 request, preserving RW bits and excluding W1C PME.
                unsafe { pointer.write_volatile(state & !(3 | 0x8000)) };
                narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(10));
                // SAFETY: same PMCSR, after the mandatory D3hot settle interval.
                if unsafe { pointer.read_volatile() } & 3 != 0 {
                    return Err(ProbeError::BadDevice);
                }
            }
            Ok(())
        })())
    }
}

/// Number of Thunderbolt / USB4 NHI controllers probed so far.
/// Diagnostic + test-observable.
pub fn instance_count() -> u32 {
    TB_INSTANCE_COUNT.load(Ordering::Acquire)
}

/// Last-observed NHI silicon-version byte (`REG_CAPS[23:16]`).
pub fn last_nhi_version() -> u8 {
    TB_LAST_NHI_VERSION.load(Ordering::Acquire) as u8
}

/// Last-observed hop (adapter-port) count (`REG_CAPS[10:0]`).
pub fn last_hop_count() -> u16 {
    TB_LAST_HOP_COUNT.load(Ordering::Acquire) as u16
}

#[doc(hidden)]
/// Test-only: reset counters between smokes. Boot path never calls
/// this — the smokes pile up otherwise.
pub fn __reset_for_test() {
    TB_INSTANCE_COUNT.store(0, Ordering::Release);
    TB_LAST_NHI_VERSION.store(0, Ordering::Release);
    TB_LAST_HOP_COUNT.store(0, Ordering::Release);
}

#[cfg(feature = "kernel-test")]
mod matching_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn usb4_amd_class_excludes_xhci_and_pcie_bridges() -> TestResult {
        // The supplied lspci names do not give numeric NHI IDs. Match the
        // architectural class instead of inventing a Pink Sardine ID table.
        if !matches_controller(0x1022, 0xffff, 0x0c0340)
            || matches_controller(0x1022, 0x15c1, 0x0c0330)
            || matches_controller(0x1022, 0x1453, 0x060400)
            || matches_controller(0x8086, 0x463f, 0x060400)
            || matches_controller(0x8086, 0x7eb3, 0x060400)
        {
            return TestResult::Fail("NHI binding confused with xHCI or a tunnel bridge");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/nhi",
        usb4_amd_class_excludes_xhci_and_pcie_bridges
    );
}
