//! PCIe ownership, bounded BAR0 window access, AI core discovery, and
//! interrupt parking. DMA remains disabled until an owned firmware/ring
//! lifecycle exists. Parking mailbox interrupts is not a chip reset.
//! Reference: Linux `brcmfmac/pcie.c` and `brcmfmac/chip.c`.

#![allow(dead_code)]

use narf_bus::{map_bar_control, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::chip::{self, Backplane, Chip};

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
// The revision >=64 PCIe core uses different interrupt offsets. The
// discovery path selects those from the core revision, not firmware ABI.

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

/// A parked PCIe device, retaining exclusive config-space authority.
/// No network interface is published by this ownership/discovery stage.
pub struct BrcmfmacDevice {
    backplane: PcieBackplane,
    pub chip: Chip,
    pub device_id: u16,
}

/// The BAR0 sliding window is mutable device state. Keeping it and the
/// authority private prevents independent MMIO handles from racing a
/// select/access pair. Future async firmware work must own this value or
/// put it behind an async mutex, never await under CONTROLLER's IRQ lock.
struct PcieBackplane {
    bar0: MmioRegion,
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
}

impl PcieBackplane {
    fn select(&mut self, address: u32) -> Result<u64, chip::Error> {
        if !chip::valid_address(address) {
            return Err(chip::Error::Address);
        }
        let window = address & !0xfff;
        // Retry the posted PCI configuration write once, as Linux's
        // brcmf_pcie_select_core does. This is a fixed transaction bound,
        // not a register wait loop. Every operation checks live authority.
        for _ in 0..2 {
            narf_bus::pci::write_config32(
                &self.cap,
                &self.device,
                BRCMF_PCIE_BAR0_WINDOW as u16,
                window,
            )
            .map_err(|_| chip::Error::Access)?;
            let selected = narf_bus::pci::read_config32(
                &self.cap,
                &self.device,
                BRCMF_PCIE_BAR0_WINDOW as u16,
            )
            .map_err(|_| chip::Error::Access)?;
            if selected == window {
                return Ok(u64::from(address & 0xfff));
            }
            if selected == u32::MAX {
                return Err(chip::Error::Gone);
            }
        }
        Err(chip::Error::Access)
    }
}

impl Backplane for PcieBackplane {
    fn read32(&mut self, address: u32) -> Result<u32, chip::Error> {
        let offset = self.select(address)?;
        // SAFETY: BAR0 has at least 4 KiB; select validates dword
        // alignment and returns an offset <=4092. The owning &mut self
        // serializes window selection with the device register access.
        Ok(unsafe { self.bar0.read32(offset) })
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), chip::Error> {
        let offset = self.select(address)?;
        // SAFETY: same checked window and exclusive ownership as read32.
        unsafe { self.bar0.write32(offset, value) };
        Ok(())
    }
}

impl core::fmt::Debug for BrcmfmacDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmfmacDevice")
            .field("device_id", &format_args!("{:#06x}", self.device_id))
            .field("chip", &self.chip)
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
    Bar0TooSmall,
    PciAccess,
    Discovery(chip::Error),
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

    // SAFETY: caller hands us exclusive BusDeviceCap authority for
    // this device's cfg + BARs.
    let dev = match unsafe { bring_up(device, cap) } {
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

/// Claim a parked device: first revoke inherited bus mastering, then
/// map registers, discover actual cores, and mask the matching PCIe
/// interrupt registers. This does not start firmware or publish a NIC.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<BrcmfmacDevice, ProbeError> {
    // Firmware inherited from a previous owner must not DMA into memory
    // before this driver has established rings, mappings, and ownership.
    narf_bus::pci::clear_command(&cap, &device, narf_bus::pci::cmd::BUS_MASTER)
        .map_err(|_| ProbeError::PciAccess)?;
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| ProbeError::PciAccess)?;
    let command = narf_bus::pci::read_command(&cap, &device).map_err(|_| ProbeError::PciAccess)?;
    if command & narf_bus::pci::cmd::BUS_MASTER != 0 {
        return Err(ProbeError::PciAccess);
    }
    // SAFETY: caller-asserted BAR exclusivity.
    let bar0 = unsafe { map_bar_control(&device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;
    if bar0.len < 4096 {
        return Err(ProbeError::Bar0TooSmall);
    }
    let mut backplane = PcieBackplane { bar0, device, cap };
    let chip = Chip::discover(&mut backplane).map_err(ProbeError::Discovery)?;
    chip.park_pcie(&mut backplane)
        .map_err(ProbeError::Discovery)?;
    Ok(BrcmfmacDevice {
        backplane,
        chip,
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
