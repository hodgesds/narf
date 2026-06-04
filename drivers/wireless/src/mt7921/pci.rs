//! MT7921 PCI probe.
//!
//! Stage-0: register the PCI match table, map BAR0, read
//! `MT_HW_CHIPID` / `MT_HW_REV`, and apply the MT7920 re-tagging that
//! Linux's `mt7921/pci.c` does at probe time (line ~358 in v6.6).
//!
//! Stage-1 power-on (driver-own latch, EFUSE MCU stub) lives in
//! `mac.rs`. The probe entry orchestrates both stages and degrades
//! gracefully when firmware blobs aren't installed — the chip will
//! be recorded as bound + the MAC field will be the EFUSE-derived
//! value if available, else the all-zero sentinel.
//!
//! References (all GPL-2.0; NARF is GPL-2.0-or-later since 2026-05-20):
//!
//! - `drivers/net/wireless/mediatek/mt76/mt7921/pci.c` —
//!   `mt7921_pci_probe`, `mt7921_pci_device_table`,
//!   the `chipid == 0x7961 && BIT(7)` re-tag at ~L358.
//! - `drivers/net/wireless/mediatek/mt76/mt792x_regs.h` —
//!   `MT_HW_CHIPID`, `MT_HW_REV`, `MT_HW_BOUND`.

#![allow(dead_code)]

use core::fmt::Write as _;

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::mac;
use super::mcu;
use super::regs::*;

/// One bound MT7921 controller — what the driver retains after probe.
///
/// Single-instance per the baseline: laptops ship at most one PCIe
/// MT7921/MT7922 radio. Multi-radio support is a non-goal here.
pub struct Mt7921Device {
    pub mmio_bar0: MmioRegion,
    /// PCI device id we matched on (post-re-tagging — 0x7961 may have
    /// been folded to 0x7920 if MT_HW_BOUND[7] was set).
    pub effective_did: u16,
    /// Raw chip-id read from `MT_HW_CHIPID`.
    pub chip_id: u32,
    /// Chip revision byte (low 8 bits of `MT_HW_REV`).
    pub chip_rev: u8,
    /// True once `mac::take_driver_own` succeeded.
    pub driver_owned: bool,
    /// EFUSE-derived MAC. All-zero if EFUSE read hasn't run / failed
    /// (firmware not loaded or MCU not alive).
    pub mac: [u8; MAC_ADDR_LEN],
}

impl core::fmt::Debug for Mt7921Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mt7921Device")
            .field(
                "effective_did",
                &format_args!("{:#06x}", self.effective_did),
            )
            .field("chip_id", &format_args!("{:#010x}", self.chip_id))
            .field("chip_rev", &format_args!("{:#04x}", self.chip_rev))
            .field("driver_owned", &self.driver_owned)
            .field("mac", &self.mac)
            .finish()
    }
}

/// Errors raised by the Stage-0/Stage-1 probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed. Most likely the BAR isn't
    /// implemented (wrong PCI ID matched) or another driver claimed it.
    Bar0MapFailed,
    /// BAR0 reads returned the all-FF sentinel that means "device
    /// gone" — link down or surprise-remove.
    DeviceGone,
    /// Driver-own handshake timed out after `DRV_OWN_RETRY_COUNT`
    /// retries. Either the firmware never released ownership (cold
    /// power-up with no PCIE_BUS_PWR), or the chip is wedged.
    DriverOwnTimeout,
    /// EFUSE MAC read failed. Not fatal — probe records the device
    /// bound with the all-zero MAC sentinel and the iface comes up
    /// with a derived MAC instead.
    EfuseRead,
    /// MCU patch / RAM-code firmware load hit `NotImplemented`. The
    /// firmware-loader path needs the blob to be registered via the
    /// initramfs scan path; absent that, probe still records the
    /// device as bound.
    NotImplemented,
}

/// Single-instance live device. Probe drops a new entry into this
/// slot. The kernel-test smokes reset it via `__reset_for_test`.
static CONTROLLER: IrqSafeSpinLock<Option<Mt7921Device>> = IrqSafeSpinLock::new(None);

/// Register the PCI match table. One entry per supported device id —
/// names must be unique (the bus match registry is keyed by `name`)
/// so we use the `mt7921-<did>` shape. Sync with `name_for`.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: MTK_VENDOR,
                device: did,
            },
            probe,
        });
    }
    // Also register the ITTIM-vendor MT7922 SKU. Linux's table
    // includes `{ PCI_DEVICE(PCI_VENDOR_ID_ITTIM, 0x7922), ... }` at
    // line 21 of `mt7921_pci_device_table`.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "mt7921-ittim-7922",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: ITTIM_VENDOR,
            device: MTK_DEV_MT7922,
        },
        probe,
    });
}

/// PCI probe entry. Called by the bus dispatch layer when one of our
/// registered (vendor, device) pairs is enumerated.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // Skip if we already bound a device. Single-instance baseline;
    // a second probe is an enumeration race.
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    // Enable MEM_SPACE + BUS_MASTER. BAR reads need MEM_SPACE; future
    // DMA ring posting needs BUS_MASTER. Mirrors the `e1000` /
    // `rtw88` shape so the test harness's mocked-cfg writes route
    // through the same code path.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: bus dispatch hands us exclusive BusDeviceCap authority
    // for this device's cfg + BARs for the duration of probe.
    let result = unsafe { bring_up(&device) };
    let dev = match result {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  mt7921: bring-up failed ({:04x}:{:04x}): {:?}",
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    let _ = writeln!(
        narf_console::Writer,
        "  mt7921: probed {} ({:04x}:{:04x}) chip={:04x} rev={:#04x} owned={} mac={:02x?}",
        name_for(dev.effective_did),
        device.id.vendor,
        device.id.device,
        (dev.chip_id & 0xffff) as u16,
        dev.chip_rev,
        dev.driver_owned,
        dev.mac,
    );

    let did = dev.effective_did;
    let mac = dev.mac;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Register the iface stub so the kernel-side TCP stack can see
    // the MAC. send_frame returns Err until the DMA-ring path lands.
    narf_net::iface::register("wlan0", mac, send_frame_unimpl);
    Ok(())
}

/// Stage-0 + Stage-1: BAR0 map, chip-ID read, driver-own latch,
/// firmware-load stub, EFUSE read.
///
/// # Safety
/// Caller owns the device's BARs exclusively for the duration of the
/// call.
pub unsafe fn bring_up(device: &BusDevice) -> Result<Mt7921Device, ProbeError> {
    // ── Stage 0: BAR0 mapping ───────────────────────────────────
    //
    // SAFETY: caller-asserted BAR exclusivity.
    let mmio_bar0 = unsafe { map_bar(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    // Presence test: a fresh BAR window on absent silicon returns
    // all-FF on every 32-bit read. `MT_HW_CHIPID` is the lowest
    // 32-bit register guaranteed to exist regardless of PMU state.
    //
    // We have to remap the absolute 32-bit address into a BAR0
    // offset. CONNAC2 maps the lower 16 MiB of the chip address
    // space directly into BAR0, so absolute addresses < 0x100_0000
    // are direct offsets. `MT_HW_CHIPID = 0x70010200` lives outside
    // that window; Linux's `mt7921_l1_rr` uses a remap table. For
    // the baseline we use a presence test that hits a known register
    // *inside* the direct window, namely `MT_PCIE_MAC_INT_ENABLE`
    // (0x10188), and fall back to the chip-id read via the remap.
    // SAFETY: identity-mapped MMIO; offset within mapped BAR len.
    let presence = unsafe { mmio_bar0.read32(MT_PCIE_MAC_INT_ENABLE as u64) };
    if presence == 0xFFFF_FFFF {
        return Err(ProbeError::DeviceGone);
    }

    // Chip-ID + rev read via the L1 remap helper. Linux's
    // `mt7921_l1_rr(dev, MT_HW_CHIPID)` does the same thing — it
    // walks an internal table that maps the absolute address to a
    // BAR-relative offset. Our `chip_id_read` is the minimal version
    // of that for the two registers we actually need.
    //
    // SAFETY: BAR0 mapped, presence test passed.
    let chip_id = unsafe { chip_id_read(&mmio_bar0) };
    // SAFETY: same.
    let hw_rev = unsafe { hw_rev_read(&mmio_bar0) };
    // SAFETY: same.
    let bound = unsafe { hw_bound_read(&mmio_bar0) };

    // MT7920 re-tagging — `mt7921/pci.c:358`:
    //   if (chipid == 0x7961 && (mt7921_l1_rr(dev, MT_HW_BOUND) & BIT(7)))
    //       chipid = 0x7920;
    let raw_chip = (chip_id & 0xffff) as u16;
    let effective_did = if raw_chip == MTK_DEV_MT7961 && (bound & MT_HW_BOUND_DBDC) != 0 {
        MTK_DEV_MT7920
    } else {
        raw_chip
    };

    // ── Stage 1: driver-own + firmware-load stub + EFUSE ─────────
    //
    // SAFETY: BAR0 mapped + owned.
    let driver_owned = match unsafe { mac::take_driver_own(&mmio_bar0) } {
        Ok(()) => true,
        Err(mac::PowerError::Timeout) => return Err(ProbeError::DriverOwnTimeout),
        Err(mac::PowerError::DeviceGone) => return Err(ProbeError::DeviceGone),
    };

    // Firmware-load stub. Stage-1 deliberately stops at the firmware
    // boundary — the patch + RAM-code blobs aren't typically
    // installed in narf-firmware's registry yet, and even when they
    // are, the patch-apply MCU sequence requires the DMA rings from
    // Stage-2. We resolve the blob names (so a future installer
    // knows what to ship) and call the MCU patch-load helper, which
    // currently returns `Err(NotImplemented)` past the resolve step.
    let mut mac_bytes = [0u8; MAC_ADDR_LEN];
    let firmware_outcome = unsafe { mcu::load_firmware_stub(&mmio_bar0, effective_did) };
    if let Err(mcu::McuError::NotImplemented) = firmware_outcome {
        // Expected baseline path — note it but keep the device bound.
        let _ = writeln!(
            narf_console::Writer,
            "  mt7921: firmware-load deferred (Stage-2 DMA rings needed)"
        );
    }

    // EFUSE read is gated on firmware being live. If the firmware
    // load returned `NotImplemented`, we leave `mac_bytes` zeroed
    // and surface "no EFUSE" via the all-zero sentinel.
    if firmware_outcome.is_ok() {
        if let Ok(m) = unsafe { mcu::read_efuse_mac(&mmio_bar0) } {
            mac_bytes = m;
        }
    }

    // Stage-4..13 bring-up orchestrator. On real silicon this would
    // allocate the WFDMA0 ring set, program the rings, download the
    // patch + WM + WA firmware, run the MCU init sequence, set up
    // the vif, switch channel, and arm the data path. On QEMU /
    // missing-firmware it returns `NotImplemented` at the FW dispatch
    // step, which we treat as "ring set allocated successfully, real
    // bring-up needs live MCU".
    //
    // The orchestrator is invoked with a default config primed with
    // the EFUSE-derived MAC; the result is dropped because the ring
    // set lives in the orchestrator's stack frame — when the real
    // dispatch path lands, we'll thread the result into `Mt7921Device`.
    use super::bringup::{full_bring_up, BringUpConfig};
    let cfg = BringUpConfig {
        effective_did,
        own_mac: mac_bytes,
        ..BringUpConfig::default()
    };
    // SAFETY: BAR0 mapped + owned per `# Safety`.
    let bringup_outcome = unsafe { full_bring_up(&mmio_bar0, cfg) };
    let _ = bringup_outcome;

    Ok(Mt7921Device {
        mmio_bar0,
        effective_did,
        chip_id,
        chip_rev: (hw_rev & 0xff) as u8,
        driver_owned,
        mac: mac_bytes,
    })
}

/// Read `MT_HW_CHIPID` (chip absolute address `0x70010200`) via the
/// minimal L1 remap. CONNAC2 maps the upper-address registers into
/// BAR0 starting at a fixed remap offset of `0xb000_0000`; the
/// in-tree Linux helper `mt7921_l1_rr` walks a table for this but
/// the two registers we read in Stage-0 (CHIPID + REV + BOUND) all
/// live in the same 0x7001_xxxx page which Linux's remap drops at
/// BAR0 offset `0xb_0200`.
///
/// # Safety
/// `mmio` is the live BAR0 region and the chip is in a state that
/// tolerates reads (post-presence-test).
unsafe fn chip_id_read(mmio: &MmioRegion) -> u32 {
    // SAFETY: forwarded.
    unsafe { l1_read32(mmio, MT_HW_CHIPID) }
}

/// Read `MT_HW_REV`. See `chip_id_read`.
///
/// # Safety
/// As `chip_id_read`.
unsafe fn hw_rev_read(mmio: &MmioRegion) -> u32 {
    // SAFETY: forwarded.
    unsafe { l1_read32(mmio, MT_HW_REV) }
}

/// Read `MT_HW_BOUND`. See `chip_id_read`.
///
/// # Safety
/// As `chip_id_read`.
unsafe fn hw_bound_read(mmio: &MmioRegion) -> u32 {
    // SAFETY: forwarded.
    unsafe { l1_read32(mmio, MT_HW_BOUND) }
}

/// L1 remap helper. Translates an absolute 32-bit on-chip address
/// into a BAR0-relative offset.
///
/// The CONNAC2 BAR0 window is 16 MiB. Direct-mapped addresses live
/// in `0x0000_0000..0x00ff_ffff`; the higher pages (`0x18xx_xxxx`,
/// `0x7xxx_xxxx`, etc.) come through a remap of the upper 12 bits.
/// Linux's `mt7921_l1_rr` keeps a table for this; the baseline
/// reduces it to two cases:
///
///   - Address < `0x100_0000` → direct (BAR0 offset = address).
///   - Otherwise → fold the upper bits into the high half of the
///     BAR0 window (`0x80_0000 + (address & 0x7f_ffff)`).
///
/// This is intentionally conservative: it lands the read on the
/// upper 8 MiB of BAR0 where the remap window sits, then masks the
/// address to a 23-bit offset. The mapped reads return 0 / 0xFF on
/// absent silicon but never wedge the bus.
///
/// # Safety
/// `mmio.len` covers the resulting offset (Stage-0 maps BAR0 with a
/// 16 MiB length); chip tolerates the read.
unsafe fn l1_read32(mmio: &MmioRegion, abs: u32) -> u32 {
    let offset = l1_remap(abs);
    // SAFETY: caller-asserted.
    unsafe { mmio.read32(offset as u64) }
}

/// Translate an absolute on-chip address to a BAR0-relative offset.
/// See `l1_read32` for the policy.
pub fn l1_remap(abs: u32) -> u32 {
    if abs < 0x0100_0000 {
        abs
    } else {
        0x0080_0000 | (abs & 0x007f_ffff)
    }
}

/// SendFn registered with `narf_net::iface` at probe. Stage-2 lights
/// up real TX once the DMA ring path lands; until then we return Err
/// so the kernel-side TCP stack surfaces the unimplemented-ness
/// without crashing.
pub fn send_frame_unimpl(_frame: &[u8]) -> Result<(), ()> {
    Err(())
}

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        MTK_DEV_MT7961 => "mt7921-7961",
        MTK_DEV_MT7922 => "mt7921-7922",
        MTK_DEV_MT7921 => "mt7921-0608",
        MTK_DEV_MT7921_ALT => "mt7921-0616",
        MTK_DEV_MT7920 => "mt7921-7920",
        _ => "mt7921",
    }
}

/// Resolve the firmware-blob names this chip wants. Returns
/// `(patch_name, ram_code_name)`. Used by the firmware-load stub.
pub fn firmware_blobs_for(did: u16) -> (&'static str, &'static str) {
    match did {
        MTK_DEV_MT7922 => (MT7922_ROM_PATCH, MT7922_FIRMWARE_WM),
        MTK_DEV_MT7920 => (MT7920_ROM_PATCH, MT7961_FIRMWARE_WM),
        // MT7921 + MT7961 share the 7961 patch and RAM code.
        _ => (MT7961_ROM_PATCH, MT7961_FIRMWARE_WM),
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Mt7921Device) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot. Gated under `kernel-test` so it
/// drops out of production binaries.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
