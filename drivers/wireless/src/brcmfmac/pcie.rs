//! `brcmfmac` PCIe transport — match table + BAR0 map + soft-reset.
//!
//! This is the Stage-0 floor:
//!   - PCI device match (vendor `0x14E4`, the BCM43602 / 4350 / 4356 /
//!     4358 / 4365 / 4366 / 4371 / 4378 / 4387 family + the Apple-only
//!     `0x4488` (BCM4387) sub-variant the kernel ships under the same
//!     driver).
//!   - BAR0 (32 KiB register window) map. Linux pcie.c uses
//!     `BRCMF_PCIE_REG_MAP_SIZE = 32 * 1024`. BAR2 (TCM window) isn't
//!     touched at this stage — it's gated on the boot loader / shared
//!     memory protocol handshake which lands in Stage-2+.
//!   - Read `BRCMF_PCIE_PCIE2REG_INTMASK` to confirm the BAR window is
//!     live (an all-FF return on the PCIe2 mailbox-mask register is the
//!     standard "device gone" sentinel — same idiom Linux uses in
//!     `brcmf_pcie_intr_disable`).
//!   - Soft-reset via the PCIe-bus interface: clear the mailbox-int
//!     register, then mask everything. This is the minimum cross-chip
//!     "park the device" sequence Linux runs at `brcmf_pcie_release`
//!     and at probe-time before chip-id discovery.
//!
//! Reference: Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/pcie.c`
//! (~L117 .. L210 for the register map, ~L2700 .. L2780 for the
//! `brcmf_pcie_devices` PCI ID table; v6.6).

#![allow(dead_code)]

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── Hardware identification ────────────────────────────────────────
//
// Per Linux `include/brcm_hw_ids.h`. All entries on the PCIe bus share
// the Broadcom vendor id `0x14E4` (`PCI_VENDOR_ID_BROADCOM`).

/// Broadcom Inc. PCI vendor id.
pub const BROADCOM_VENDOR: u16 = 0x14E4;

// Per Linux `include/brcm_hw_ids.h` (lines ~75..101) — copied verbatim.
pub const BRCM_PCIE_4350_DEVICE_ID: u16 = 0x43A3;
pub const BRCM_PCIE_4354_DEVICE_ID: u16 = 0x43DF;
pub const BRCM_PCIE_4354_RAW_DEVICE_ID: u16 = 0x4354;
pub const BRCM_PCIE_4355_DEVICE_ID: u16 = 0x43DC;
pub const BRCM_PCIE_4356_DEVICE_ID: u16 = 0x43EC;
pub const BRCM_PCIE_43567_DEVICE_ID: u16 = 0x43D3;
pub const BRCM_PCIE_43570_DEVICE_ID: u16 = 0x43D9;
pub const BRCM_PCIE_43570_RAW_DEVICE_ID: u16 = 0xAA31;
pub const BRCM_PCIE_4358_DEVICE_ID: u16 = 0x43E9;
pub const BRCM_PCIE_4359_DEVICE_ID: u16 = 0x43EF;
pub const BRCM_PCIE_43602_DEVICE_ID: u16 = 0x43BA;
pub const BRCM_PCIE_43602_2G_DEVICE_ID: u16 = 0x43BB;
pub const BRCM_PCIE_43602_5G_DEVICE_ID: u16 = 0x43BC;
pub const BRCM_PCIE_4364_DEVICE_ID: u16 = 0x4464;
pub const BRCM_PCIE_4365_DEVICE_ID: u16 = 0x43CA;
pub const BRCM_PCIE_4365_2G_DEVICE_ID: u16 = 0x43CB;
pub const BRCM_PCIE_4365_5G_DEVICE_ID: u16 = 0x43CC;
pub const BRCM_PCIE_4366_DEVICE_ID: u16 = 0x43C3;
pub const BRCM_PCIE_4366_2G_DEVICE_ID: u16 = 0x43C4;
pub const BRCM_PCIE_4366_5G_DEVICE_ID: u16 = 0x43C5;
pub const BRCM_PCIE_4371_DEVICE_ID: u16 = 0x440D;
pub const BRCM_PCIE_43596_DEVICE_ID: u16 = 0x4415;
pub const BRCM_PCIE_43752_DEVICE_ID: u16 = 0x449D;
pub const BRCM_PCIE_4377_DEVICE_ID: u16 = 0x4488;
pub const BRCM_PCIE_4378_DEVICE_ID: u16 = 0x4425;
pub const BRCM_PCIE_4387_DEVICE_ID: u16 = 0x4433;

/// All PCI device ids in the match table. Order matches the Linux
/// `brcmf_pcie_devices` array in `pcie.c` (~L2724..L2754) and is purely
/// cosmetic — the dispatcher matches by `(vendor, device)` pair.
pub const ALL_DEV_IDS: &[u16] = &[
    BRCM_PCIE_4350_DEVICE_ID,
    BRCM_PCIE_4354_DEVICE_ID,
    BRCM_PCIE_4354_RAW_DEVICE_ID,
    BRCM_PCIE_4355_DEVICE_ID,
    BRCM_PCIE_4356_DEVICE_ID,
    BRCM_PCIE_43567_DEVICE_ID,
    BRCM_PCIE_43570_DEVICE_ID,
    BRCM_PCIE_43570_RAW_DEVICE_ID,
    BRCM_PCIE_4358_DEVICE_ID,
    BRCM_PCIE_4359_DEVICE_ID,
    BRCM_PCIE_43602_DEVICE_ID,
    BRCM_PCIE_43602_2G_DEVICE_ID,
    BRCM_PCIE_43602_5G_DEVICE_ID,
    BRCM_PCIE_4364_DEVICE_ID,
    BRCM_PCIE_4365_DEVICE_ID,
    BRCM_PCIE_4365_2G_DEVICE_ID,
    BRCM_PCIE_4365_5G_DEVICE_ID,
    BRCM_PCIE_4366_DEVICE_ID,
    BRCM_PCIE_4366_2G_DEVICE_ID,
    BRCM_PCIE_4366_5G_DEVICE_ID,
    BRCM_PCIE_4371_DEVICE_ID,
    BRCM_PCIE_43596_DEVICE_ID,
    BRCM_PCIE_43752_DEVICE_ID,
    BRCM_PCIE_4377_DEVICE_ID,
    BRCM_PCIE_4378_DEVICE_ID,
    BRCM_PCIE_4387_DEVICE_ID,
];

// ── BAR0 register map ──────────────────────────────────────────────
//
// Per Linux `pcie.c` (lines ~119..150). The BAR0 window is 32 KiB and
// is split into two halves:
//   - The first 0x1000 holds the legacy "PCIE1" registers
//     (BAR0_WINDOW, BAR0_WRAPPERBASE, INTSTATUS, INTMASK, SBMBX,
//     LINK_STATUS_CTRL).
//   - The second 0x1000 holds the "PCIE2" register block — used by
//     newer parts for the mailbox / doorbell / configaddr/data dance.
//     `BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET = 0x2000` is the start of the
//     PCIe2 block.
//
// The "64-bit" register set (BRCMF_PCIE_64_PCIE2REG_*) is at higher
// offsets and only relevant for the v7 shared-memory protocol; the
// stage-0 path doesn't care.

/// BAR0 window size — `BRCMF_PCIE_REG_MAP_SIZE`. Linux `pcie.c` ~L119.
pub const BRCMF_PCIE_REG_MAP_SIZE: u64 = 32 * 1024;

/// BAR0 sliding-window register that selects the backplane address the
/// next BAR0 read targets. `BRCMF_PCIE_BAR0_WINDOW`. Linux `pcie.c`
/// ~L122.
pub const BRCMF_PCIE_BAR0_WINDOW: u64 = 0x80;

/// Offset of the "PCIE2 enum" register block inside BAR0.
/// `BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET`. Linux `pcie.c` ~L127.
pub const BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET: u64 = 0x2000;

/// PCIE2 register block: mailbox-mask register. Reads of this register
/// are the standard probe-time presence test — an all-FF return is the
/// "device gone" sentinel.
/// `BRCMF_PCIE_PCIE2REG_INTMASK`. Linux `pcie.c` ~L138.
pub const BRCMF_PCIE_PCIE2REG_INTMASK: u64 = 0x24;

/// PCIE2 register block: mailbox-int (RW1C status). Cleared as the
/// first step of the soft-reset prologue.
/// `BRCMF_PCIE_PCIE2REG_MAILBOXINT`. Linux `pcie.c` ~L139.
pub const BRCMF_PCIE_PCIE2REG_MAILBOXINT: u64 = 0x48;

/// PCIE2 register block: mailbox-mask. Linux writes 0 here to disable
/// all mailbox sources during release / probe.
/// `BRCMF_PCIE_PCIE2REG_MAILBOXMASK`. Linux `pcie.c` ~L140.
pub const BRCMF_PCIE_PCIE2REG_MAILBOXMASK: u64 = 0x4C;

/// PCIE2 register block: configuration-address. Used by the chip-id
/// discovery + BAR2 retarget flows in Linux `pcie.c` (~L720).
pub const BRCMF_PCIE_PCIE2REG_CONFIGADDR: u64 = 0x120;

/// PCIE2 register block: configuration-data. Companion to
/// `CONFIGADDR` — write the backplane offset to ADDR, read/write DATA.
pub const BRCMF_PCIE_PCIE2REG_CONFIGDATA: u64 = 0x124;

/// Sentinel a stale / absent BAR window returns on a 32-bit read.
const READ_GONE_U32: u32 = 0xFFFF_FFFF;

// ── Driver state ───────────────────────────────────────────────────

/// One bound `brcmfmac` PCIe device. Holds the BAR0 mapping + the
/// 32-bit chip-id sample we took at probe time. The full shared-memory
/// protocol (BAR2 TCM window + firmware push + ring DMA) gets attached
/// to this struct in Stage-2/3.
pub struct BrcmfmacDevice {
    pub mmio_bar0: MmioRegion,
    /// Best-effort chip-id sample. Real chip-id discovery on Broadcom
    /// parts walks the ChipCommon backplane via `BAR0_WINDOW`; the
    /// stage-0 path only reads `PCIE2REG_INTMASK` as a presence test,
    /// so this is the raw 32-bit value of that register (0 when the
    /// device is parked, non-FF when alive).
    pub chip_id_probe: u32,
    pub device_id: u16,
}

impl core::fmt::Debug for BrcmfmacDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmfmacDevice")
            .field("device_id", &format_args!("{:#06x}", self.device_id))
            .field("chip_id_probe", &format_args!("{:#x}", self.chip_id_probe))
            .finish_non_exhaustive()
    }
}

/// Errors raised by the Stage-0 probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed.
    Bar0MapFailed,
    /// BAR0 window came back as all-FF on the PCIE2 mailbox-mask
    /// register — the device dropped off the link before we could
    /// drive it.
    DeviceGone,
}

/// Single-instance live device. Multi-radio support comes with the
/// data-path follow-up.
static CONTROLLER: IrqSafeSpinLock<Option<BrcmfmacDevice>> = IrqSafeSpinLock::new(None);

/// PCI driver match registration. Mirrors the Linux `brcmf_pcie_devices`
/// array (~L2724..L2754 in `pcie.c`).
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: BROADCOM_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Probe entry — called by `narf-bus::driver_match` when a Broadcom
/// vendor/device pair we registered for surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    // Enable MEM_SPACE + BUS_MASTER. BAR0 maps need MEM_SPACE; the
    // msgbuf data path needs BUS_MASTER for the firmware-initiated
    // DMA reads (stage-2+).
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller hands us exclusive BusDeviceCap authority for
    // this device's cfg + BARs.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = match unsafe { bring_up(&device) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    let did = dev.device_id;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    Ok(())
}

/// Bring the chip up: map BAR0, sample the chip-id probe register,
/// run the soft-reset prologue.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(device: &BusDevice) -> Result<BrcmfmacDevice, ProbeError> {
    // SAFETY: caller-asserted BAR exclusivity.
    let mmio_bar0 = unsafe { map_bar(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    // Presence test on the PCIE2REG_INTMASK register. An all-FF read
    // is the device-gone sentinel Linux uses everywhere.
    let intmask_off = BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET + BRCMF_PCIE_PCIE2REG_INTMASK;
    // SAFETY: BAR0 mapped, 32-bit aligned.
    let chip_id_probe = unsafe { mmio_bar0.read32(intmask_off) };
    if chip_id_probe == READ_GONE_U32 {
        return Err(ProbeError::DeviceGone);
    }

    // Soft-reset prologue: clear MAILBOXINT (RW1C), mask everything in
    // MAILBOXMASK. This is the minimum cross-chip "park the device"
    // sequence Linux runs at `brcmf_pcie_release_*`.
    // SAFETY: BAR0 mapped + 32-bit aligned offsets.
    unsafe {
        let mailboxint_off = BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET + BRCMF_PCIE_PCIE2REG_MAILBOXINT;
        let mailboxmask_off = BRCMF_PCIE_BARO_PCIE_ENUM_OFFSET + BRCMF_PCIE_PCIE2REG_MAILBOXMASK;
        // RW1C — write a sticky-clear pattern of all-1s.
        mmio_bar0.write32(mailboxint_off, 0xFFFF_FFFF);
        // Mask everything until the data-path follow-up lights the
        // doorbells back up.
        mmio_bar0.write32(mailboxmask_off, 0x0000_0000);
    }

    Ok(BrcmfmacDevice {
        mmio_bar0,
        chip_id_probe,
        device_id: device.id.device,
    })
}

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value. Each entry is
/// unique per device id — the bus's match-table registration is
/// idempotent on `name`, so collapsing variants (e.g. the
/// 43602/43602_2G/43602_5G triplet) to a single name would
/// silently overwrite all but the last entry. Sub-chip variants are
/// disambiguated via a per-id suffix instead.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        BRCM_PCIE_4350_DEVICE_ID => "brcmfmac-4350",
        BRCM_PCIE_4354_DEVICE_ID => "brcmfmac-4354",
        BRCM_PCIE_4354_RAW_DEVICE_ID => "brcmfmac-4354-raw",
        BRCM_PCIE_4355_DEVICE_ID => "brcmfmac-4355",
        BRCM_PCIE_4356_DEVICE_ID => "brcmfmac-4356",
        BRCM_PCIE_43567_DEVICE_ID => "brcmfmac-43567",
        BRCM_PCIE_43570_DEVICE_ID => "brcmfmac-43570",
        BRCM_PCIE_43570_RAW_DEVICE_ID => "brcmfmac-43570-raw",
        BRCM_PCIE_4358_DEVICE_ID => "brcmfmac-4358",
        BRCM_PCIE_4359_DEVICE_ID => "brcmfmac-4359",
        BRCM_PCIE_43602_DEVICE_ID => "brcmfmac-43602",
        BRCM_PCIE_43602_2G_DEVICE_ID => "brcmfmac-43602-2g",
        BRCM_PCIE_43602_5G_DEVICE_ID => "brcmfmac-43602-5g",
        BRCM_PCIE_4364_DEVICE_ID => "brcmfmac-4364",
        BRCM_PCIE_4365_DEVICE_ID => "brcmfmac-4365",
        BRCM_PCIE_4365_2G_DEVICE_ID => "brcmfmac-4365-2g",
        BRCM_PCIE_4365_5G_DEVICE_ID => "brcmfmac-4365-5g",
        BRCM_PCIE_4366_DEVICE_ID => "brcmfmac-4366",
        BRCM_PCIE_4366_2G_DEVICE_ID => "brcmfmac-4366-2g",
        BRCM_PCIE_4366_5G_DEVICE_ID => "brcmfmac-4366-5g",
        BRCM_PCIE_4371_DEVICE_ID => "brcmfmac-4371",
        BRCM_PCIE_43596_DEVICE_ID => "brcmfmac-43596",
        BRCM_PCIE_43752_DEVICE_ID => "brcmfmac-43752",
        BRCM_PCIE_4377_DEVICE_ID => "brcmfmac-4377",
        BRCM_PCIE_4378_DEVICE_ID => "brcmfmac-4378",
        BRCM_PCIE_4387_DEVICE_ID => "brcmfmac-4387",
        _ => "brcmfmac",
    }
}

/// Best-guess firmware-blob filename for a known device id. Format
/// matches the Linux `linux-firmware` tree's `brcm/brcmfmacXXXX-pcie.bin`
/// naming. Returns `None` for ids we don't have a registered candidate
/// for — the firmware-load path can still try the generic
/// `brcmfmac-pcie.bin` fallback.
pub const fn firmware_filename(did: u16) -> Option<&'static str> {
    match did {
        BRCM_PCIE_4350_DEVICE_ID => Some("/firmware/brcm/brcmfmac4350-pcie.bin"),
        BRCM_PCIE_4356_DEVICE_ID => Some("/firmware/brcm/brcmfmac4356-pcie.bin"),
        BRCM_PCIE_4358_DEVICE_ID => Some("/firmware/brcm/brcmfmac4358-pcie.bin"),
        BRCM_PCIE_43602_DEVICE_ID | BRCM_PCIE_43602_2G_DEVICE_ID | BRCM_PCIE_43602_5G_DEVICE_ID => {
            Some("/firmware/brcm/brcmfmac43602-pcie.bin")
        }
        BRCM_PCIE_4365_DEVICE_ID | BRCM_PCIE_4365_2G_DEVICE_ID | BRCM_PCIE_4365_5G_DEVICE_ID => {
            Some("/firmware/brcm/brcmfmac4366c-pcie.bin")
        }
        BRCM_PCIE_4366_DEVICE_ID | BRCM_PCIE_4366_2G_DEVICE_ID | BRCM_PCIE_4366_5G_DEVICE_ID => {
            Some("/firmware/brcm/brcmfmac4366c-pcie.bin")
        }
        BRCM_PCIE_4371_DEVICE_ID => Some("/firmware/brcm/brcmfmac4371-pcie.bin"),
        BRCM_PCIE_4378_DEVICE_ID => Some("/firmware/brcm/brcmfmac4378b1-pcie.bin"),
        BRCM_PCIE_4377_DEVICE_ID => Some("/firmware/brcm/brcmfmac4377b3-pcie.bin"),
        BRCM_PCIE_4387_DEVICE_ID => Some("/firmware/brcm/brcmfmac4387c2-pcie.bin"),
        _ => None,
    }
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller.
pub fn with_controller<R>(f: impl FnOnce(&BrcmfmacDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
