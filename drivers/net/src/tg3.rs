//! Broadcom Tigon3 (`tg3`) Gigabit Ethernet driver — BCM57xx family.
//!
//! NARF Stage-4 cut. Targets the wired NetXtreme controllers shipped
//! on Dell / HP / Lenovo desktop and laptop boards (BCM5700 .. 5764M
//! roughly 2002-2012). The chip line carried into the NetXtreme II
//! (BCM57710) and the on-die NICs used by Sun / IBM / Apple Macs of
//! the same era.
//!
//! ## Reference
//!
//! Adapted from Linux `drivers/net/ethernet/broadcom/tg3.c` and
//! `tg3.h` (GPL-2.0-or-later). NARF is GPL-2.0-or-later as of
//! 2026-05-20 so direct register-layout citations are kept inline.
//!
//! The BCM57xx PCIe surface is laid out across one 64-bit MMIO BAR
//! (BAR0); registers are byte-addressable. The driver only touches
//! the standard "low" register window (offsets 0x0000..0x6FFF):
//!
//! | offset  | name              | description                       |
//! |---------|-------------------|-----------------------------------|
//! | 0x0068  | MISC_HOST_CTRL    | Endian, INDIR access toggles      |
//! | 0x0410  | MAC_ADDR_0_HIGH   | MAC[0..1] (upper 16 bits)         |
//! | 0x0414  | MAC_ADDR_0_LOW    | MAC[2..5] (lower 32 bits)         |
//! | 0x044c  | MAC_MI_COM        | MII (PHY) command/data            |
//! | 0x0450  | MAC_MI_STAT       | MII status                        |
//! | 0x0454  | MAC_MI_MODE       | MII clock divider                 |
//! | 0x6800  | GRC_MODE          | Global cfg — endian / stackup     |
//! | 0x6804  | GRC_MISC_CFG      | Core-clock reset (self-clearing)  |
//!
//! Stage 0 scope: PCI probe, BAR0 mapping, MAC address read. The
//! data-path (`receive`/`transmit`) returns `Err(NotImplemented)`
//! until later stages plug in the BD rings.

extern crate alloc;

use core::fmt::Write as _;

use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: Broadcom Corporation.
pub const BCM_VENDOR: u16 = 0x14E4;

// BCM57xx NetXtreme device ids we recognise. List intentionally
// covers the 6-8 most-deployed variants:
//
//   - 5700  / 5701  : original NetXtreme (PCI-X).
//   - 5705x        : value SKU, shipped on Sun / IBM blades.
//   - 5714  / 5715 : single + dual-port PCIe.
//   - 5751  / 5752 : popular Dell / HP desktop LOM.
//   - 5754  / 5755 : business desktop / SFF.
//   - 5764M        : Lenovo / HP laptop docking-station LOM.
//   - 5780  / 5781 : NetXtreme refresh.

pub const BCM_5700: u16 = 0x1644;
pub const BCM_5701: u16 = 0x1645;
pub const BCM_5705: u16 = 0x1653;
pub const BCM_5705_2: u16 = 0x1654;
pub const BCM_5705M: u16 = 0x165D;
pub const BCM_5705M_2: u16 = 0x165E;
pub const BCM_5714: u16 = 0x1668;
pub const BCM_5715: u16 = 0x1678;
pub const BCM_5721: u16 = 0x1659;
pub const BCM_5751: u16 = 0x1677;
pub const BCM_5751M: u16 = 0x167D;
pub const BCM_5752: u16 = 0x1600;
pub const BCM_5752M: u16 = 0x1601;
pub const BCM_5754: u16 = 0x167A;
pub const BCM_5754M: u16 = 0x1672;
pub const BCM_5755: u16 = 0x167B;
pub const BCM_5755M: u16 = 0x1673;
pub const BCM_5764M: u16 = 0x1684;
pub const BCM_5780: u16 = 0x166A;
pub const BCM_5781: u16 = 0x166E;
pub const BCM_5782: u16 = 0x1696;

/// Every Broadcom device id this driver claims. Maintained as a
/// single `const` so the registration loop and the match-table
/// smoke test see the same list.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    BCM_5700, BCM_5701, BCM_5705, BCM_5705_2, BCM_5705M, BCM_5705M_2, BCM_5714, BCM_5715, BCM_5721,
    BCM_5751, BCM_5751M, BCM_5752, BCM_5752M, BCM_5754, BCM_5754M, BCM_5755, BCM_5755M, BCM_5764M,
    BCM_5780, BCM_5781, BCM_5782,
];

// ── Register offsets ────────────────────────────────────────────────
//
// Names mirror Linux `tg3.h` so future-Claude can cross-reference
// driver-side adjustments cleanly. Only the registers the Stage 0
// path touches are declared here; rings / IRQ status / MI-mode
// constants land in later stages.

const REG_MISC_HOST_CTRL: u64 = 0x0068;
const REG_MAC_ADDR_0_HIGH: u64 = 0x0410;
const REG_MAC_ADDR_0_LOW: u64 = 0x0414;
const REG_GRC_MODE: u64 = 0x6800;
#[allow(dead_code)] // Stage 1 — core-clock reset
const REG_GRC_MISC_CFG: u64 = 0x6804;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    /// MAC reads back as either all-zero or all-FFs — suggests the
    /// device is half-dead or the BAR isn't actually mapped.
    BadMac,
    /// Data path not implemented yet (Stage 0 placeholder).
    NotImplemented,
}

// ── Driver state ────────────────────────────────────────────────────

/// A live BCM57xx NetXtreme controller. Stage 0 holds only the MMIO
/// mapping + the MAC read at bring-up; later stages add the BD
/// rings + IRQ binding.
pub struct Tg3Nic {
    #[allow(dead_code)] // used in later stages
    mmio: MmioRegion,
    /// MAC address read from MAC_ADDR_0_HIGH/LOW at bring-up.
    pub mac: [u8; 6],
    /// Cached PCI device id — useful for chip-rev-specific quirks
    /// landed in later stages.
    pub device_id: u16,
}

impl core::fmt::Debug for Tg3Nic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tg3Nic")
            .field("device_id", &self.device_id)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

impl Tg3Nic {
    /// Bring up the controller: map BAR0, read MAC. Stage 0 only —
    /// no chip reset, no ring init, no link evaluation.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively for
    /// the duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NicError> {
        // BCM57xx places its register block on BAR0 (memory-type, 64
        // bit on PCIe parts, 32 bit on legacy PCI-X parts). Linux's
        // `tg3_init_one` calls `pci_iomap(pdev, BAR_0, ...)` first
        // thing.
        // SAFETY: caller-asserted exclusive ownership.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| NicError::BarMapFailed)?;

        // Read MAC from MAC_ADDR_0_HIGH/LOW. Per `tg3.h`:
        //   - HIGH at 0x0410 carries the upper 2 bytes in bits[15:0].
        //   - LOW  at 0x0414 carries the lower 4 bytes in bits[31:0].
        // Some boards mirror MAC into the standard register window
        // even before the chip reset completes; others gate it
        // behind reset-clear. Stage 0 reads it as-is — Stage 1 will
        // re-read post-reset if the initial read looks invalid.
        // SAFETY: identity-mapped MMIO; reads are pure observations.
        let mac_hi = unsafe { mmio.read32(REG_MAC_ADDR_0_HIGH) };
        // SAFETY: same.
        let mac_lo = unsafe { mmio.read32(REG_MAC_ADDR_0_LOW) };
        let mac = [
            ((mac_hi >> 8) & 0xFF) as u8,
            (mac_hi & 0xFF) as u8,
            ((mac_lo >> 24) & 0xFF) as u8,
            ((mac_lo >> 16) & 0xFF) as u8,
            ((mac_lo >> 8) & 0xFF) as u8,
            (mac_lo & 0xFF) as u8,
        ];

        let _ = writeln!(
            narf_console::Writer,
            "  tg3: BCM{:04X} BAR0={:#018x}+{:#x} MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            device.id.device,
            mmio.phys.raw(),
            mmio.len,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
        );

        // Sanity-check: all-zero or all-FFs MAC means the BAR isn't
        // mapped or the device is half-dead. Don't fail probe (the
        // bus layer treats `BadDevice` as "driver doesn't claim
        // this one"), but log loudly so the boot trace shows it.
        let all_zero = mac.iter().all(|b| *b == 0);
        let all_ff = mac.iter().all(|b| *b == 0xFF);
        if all_zero || all_ff {
            let _ = writeln!(
                narf_console::Writer,
                "  tg3: MAC reads as {} — BAR likely unmapped or chip in reset",
                if all_zero { "all-zero" } else { "all-FF" }
            );
            return Err(NicError::BadMac);
        }

        // Read MISC_HOST_CTRL + GRC_MODE so we can fingerprint what
        // the chip thinks its endian/stackup config is. Stage 1 will
        // overwrite these; Stage 0 just logs them.
        // SAFETY: identity-mapped MMIO.
        let misc_host_ctrl = unsafe { mmio.read32(REG_MISC_HOST_CTRL) };
        // SAFETY: same.
        let grc_mode = unsafe { mmio.read32(REG_GRC_MODE) };
        let chip_rev = (misc_host_ctrl >> 16) & 0xFFFF;
        let _ = writeln!(
            narf_console::Writer,
            "  tg3: MISC_HOST_CTRL={:#010x} (chiprev={:#06x}) GRC_MODE={:#010x}",
            misc_host_ctrl, chip_rev, grc_mode,
        );

        Ok(Self {
            mmio,
            mac,
            device_id: device.id.device,
        })
    }

    /// Stage 0 placeholder. Returns `NotImplemented` until Stage 2
    /// wires the BD ring + RX drain.
    pub fn receive(&self) -> Result<alloc::vec::Vec<u8>, NicError> {
        Err(NicError::NotImplemented)
    }

    /// Stage 0 placeholder. Returns `NotImplemented` until Stage 2
    /// wires the BD ring + TX path.
    pub fn transmit(&self, _frame: &[u8]) -> Result<(), NicError> {
        Err(NicError::NotImplemented)
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Tg3Nic>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`. Idempotent:
/// returns `Ok(())` when the controller is already brought up.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER are required: the chip DMAs the BD
    // rings + frame buffers, and we map BAR0 as MMIO. Leave INTx
    // open here — Stage 2 flips INTX_DISABLE on once MSI/MSI-X is
    // brought up.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller-authority over the device.
    let dev = match unsafe { Tg3Nic::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("tg3"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

/// Register the driver against every Broadcom device id we recognise.
/// One match per id pair so the entries are independently maintainable
/// and the smoke test can spot-check coverage.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "tg3",
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: BCM_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once `probe` has installed a controller.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Test-side accessor: run `f` against the probed controller.
pub fn with_controller<R>(f: impl FnOnce(&Tg3Nic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
