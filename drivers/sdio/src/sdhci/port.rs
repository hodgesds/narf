// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux MMC host front-ends that are SDHCI-compatible variants: their
//! identity tables, quirk sets and register-access ops, applied as one
//! `Registers` adapter in front of the owned aperture.
//!
//! Every profile mirrors one Linux fixes/slot/data object exactly:
//! - `sdhci-pci-core.c` `sdhci_intel_byt_sdio` (BYT/BSW/SPT/BXT/BXTM/APL/GLK
//!   SDIO PCI functions) with `sdhci_intel_byt_ops`;
//! - `sdhci-acpi.c` `sdhci_acpi_slot_int_sdio` (`sdhci_acpi_uids`/`ids`);
//! - `sdhci-iproc.c` `bcm2835_data`, `bcm2711_data`, `iproc_cygnus_data`,
//!   `iproc_data`, `bcm7211a0_data` (`sdhci_iproc_of_match`).
//!
//! Quirks with no effect on this crate's 3.3-V legacy/high-speed SDIO host
//! are carried as Linux bits for identity and documented in the spec
//! (`drivers/sdio/specification/spec.md` "Host front-end ports"); only the
//! ones that change register traffic act here. The generic profile is an
//! exact passthrough, so the standard PCI SDHCI host is byte-identical.

use crate::pio::Registers;
use crate::sdhci::regs::*;
use crate::sdio::function::PmFlags;
use narf_time::Deadline;

// Linux `drivers/mmc/host/sdhci.h` quirk bits (exact values).
pub const QUIRK_BROKEN_DMA: u32 = 1 << 5;
pub const QUIRK_BROKEN_ADMA: u32 = 1 << 6;
pub const QUIRK_BROKEN_TIMEOUT_VAL: u32 = 1 << 12;
pub const QUIRK_BROKEN_CARD_DETECTION: u32 = 1 << 15;
pub const QUIRK_NO_LED: u32 = 1 << 19;
pub const QUIRK_DATA_TIMEOUT_USES_SDCLK: u32 = 1 << 24;
pub const QUIRK_NO_ENDATTR_IN_NOPDESC: u32 = 1 << 26;
pub const QUIRK_MULTIBLOCK_READ_ACMD12: u32 = 1 << 28;
pub const QUIRK_NO_HISPD_BIT: u32 = 1 << 29;
pub const QUIRK2_HOST_OFF_CARD_ON: u32 = 1 << 0;
pub const QUIRK2_PRESET_VALUE_BROKEN: u32 = 1 << 3;
pub const QUIRK2_ACMD23_BROKEN: u32 = 1 << 14;
// `sdhci.h` CAPABILITIES_1 driver-type bits used by the iproc overrides.
pub const CAPS1_DRIVER_TYPE_A: u32 = 0x0000_0010;
pub const CAPS1_DRIVER_TYPE_C: u32 = 0x0000_0020;
pub const CAPS1_DRIVER_TYPE_D: u32 = 0x0000_0040;
const CAPS_CAN_DO_SUSPEND: u32 = 0x0080_0000;
const CAPS_TIMEOUT_CLK_SHIFT: u32 = 0;

/// Register access discipline of the front-end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    /// Exact-width SDHCI accessors.
    Native,
    /// `sdhci_iproc_32only_ops` / `sdhci_iproc_bcm2711_ops`: 32-bit-only
    /// bus, 16/8-bit accesses synthesized with TRANSFER_MODE and
    /// BLOCK_SIZE/COUNT shadowed until COMMAND, and a four-SD-clock delay
    /// after each write at or below 400 kHz.
    Iproc32,
}

/// One Linux host front-end profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    /// Linux fixes/slot/data object this profile mirrors.
    pub name: &'static str,
    pub quirks: u32,
    pub quirks2: u32,
    /// `__sdhci_read_caps(host, NULL, &caps, &caps1)` override
    /// (`sdhci_iproc_data.missing_caps`): CAPABILITIES/_1 read as these.
    pub caps: Option<(u32, u32)>,
    /// `MMC_CAP_NONREMOVABLE` or `SDHCI_QUIRK_BROKEN_CARD_DETECTION`:
    /// Linux `sdhci_get_cd` reports present without reading the line.
    pub non_removable: bool,
    pub access: Access,
    /// `sdhci_intel_byt_ops`: `sdhci_intel_set_clock`,
    /// `sdhci_intel_set_power`, `sdhci_intel_set_uhs_signaling`.
    pub intel_ops: bool,
    /// Platform `mmc->pm_caps` the slot itself grants (sdhci-acpi slot
    /// `pm_caps`). PCI keeps its own `sdhci_pci_probe_slot` derivation.
    pub pm_caps: PmFlags,
    /// `ops->get_min_clock` (`sdhci_iproc_bcm2711_get_min_clock`).
    pub min_clock_hz: Option<u32>,
    /// The base clock comes from the platform clock (`get_max_clock` =
    /// `sdhci_pltfm_clk_get_max_clock`) when CAPABILITIES has none.
    pub platform_clock: bool,
}

impl Profile {
    /// Standard SDHCI: every access passes through unchanged.
    pub const GENERIC: Self = Self {
        name: "sdhci",
        quirks: 0,
        quirks2: 0,
        caps: None,
        non_removable: false,
        access: Access::Native,
        intel_ops: false,
        pm_caps: PmFlags::NONE,
        min_clock_hz: None,
        platform_clock: false,
    };
    pub fn is_generic(&self) -> bool {
        *self == Self::GENERIC
    }
}

/// `sdhci-pci-core.c` `sdhci_intel_byt_sdio` + `byt_sdio_probe_slot`
/// (`MMC_CAP_POWER_OFF_CARD | MMC_CAP_NONREMOVABLE | MMC_CAP_WAIT_WHILE_BUSY`).
pub const PCI_INTEL_BYT_SDIO: Profile = Profile {
    name: "sdhci_intel_byt_sdio",
    quirks: QUIRK_NO_ENDATTR_IN_NOPDESC | QUIRK_NO_LED,
    quirks2: QUIRK2_HOST_OFF_CARD_ON | QUIRK2_PRESET_VALUE_BROKEN,
    caps: None,
    non_removable: true,
    access: Access::Native,
    intel_ops: true,
    pm_caps: PmFlags::NONE,
    min_clock_hz: None,
    platform_clock: false,
};

/// `sdhci-acpi.c` `sdhci_acpi_slot_int_sdio` (no `.chip`: default ops).
pub const ACPI_INT_SDIO: Profile = Profile {
    name: "sdhci_acpi_slot_int_sdio",
    quirks: QUIRK_BROKEN_CARD_DETECTION | QUIRK_NO_LED | QUIRK_NO_ENDATTR_IN_NOPDESC,
    quirks2: QUIRK2_HOST_OFF_CARD_ON,
    caps: None,
    non_removable: true,
    access: Access::Native,
    intel_ops: false,
    pm_caps: PmFlags::KEEP_POWER,
    min_clock_hz: None,
    platform_clock: false,
};

const IPROC_CAPS: u32 = ((0x1 << CAPS_MAX_BLOCK_SHIFT) & CAPS_MAX_BLOCK_MASK)
    | CAPS_CAN_VDD_330
    | CAPS_CAN_VDD_180
    | CAPS_CAN_DO_SUSPEND
    | CAPS_CAN_DO_HISPD
    | CAPS_CAN_DO_ADMA2
    | CAPS_CAN_DO_SDMA;
const IPROC_CAPS1: u32 = CAPS1_DRIVER_TYPE_C | CAPS1_DRIVER_TYPE_D | CAPS1_SUPPORT_DDR50;

/// `sdhci-iproc.c` `bcm2835_data` (Raspberry Pi Wi-Fi `sdhci`/mmcnr node).
pub const IPROC_BCM2835: Profile = Profile {
    name: "bcm2835_data",
    quirks: QUIRK_BROKEN_CARD_DETECTION | QUIRK_DATA_TIMEOUT_USES_SDCLK | QUIRK_NO_HISPD_BIT,
    quirks2: QUIRK2_PRESET_VALUE_BROKEN,
    caps: Some((
        ((0x1 << CAPS_MAX_BLOCK_SHIFT) & CAPS_MAX_BLOCK_MASK)
            | CAPS_CAN_VDD_330
            | CAPS_CAN_DO_HISPD,
        CAPS1_DRIVER_TYPE_A | CAPS1_DRIVER_TYPE_C,
    )),
    non_removable: true,
    access: Access::Iproc32,
    intel_ops: false,
    pm_caps: PmFlags::NONE,
    min_clock_hz: None,
    platform_clock: true,
};
/// `sdhci-iproc.c` `bcm2711_data` (`sdhci_iproc_bcm2711_ops`).
pub const IPROC_BCM2711: Profile = Profile {
    name: "bcm2711_data",
    quirks: QUIRK_MULTIBLOCK_READ_ACMD12,
    quirks2: 0,
    caps: None,
    non_removable: false,
    access: Access::Iproc32,
    intel_ops: false,
    pm_caps: PmFlags::NONE,
    min_clock_hz: Some(200_000),
    platform_clock: true,
};
/// `sdhci-iproc.c` `iproc_cygnus_data` (`missing_caps` false: the caps
/// fields are unused by `sdhci_iproc_probe`).
pub const IPROC_CYGNUS: Profile = Profile {
    name: "iproc_cygnus_data",
    quirks: QUIRK_DATA_TIMEOUT_USES_SDCLK | QUIRK_NO_HISPD_BIT,
    quirks2: QUIRK2_ACMD23_BROKEN | QUIRK2_HOST_OFF_CARD_ON,
    caps: None,
    non_removable: false,
    access: Access::Iproc32,
    intel_ops: false,
    pm_caps: PmFlags::NONE,
    min_clock_hz: None,
    platform_clock: true,
};
/// `sdhci-iproc.c` `iproc_data` (`sdhci_iproc_ops`: native widths).
pub const IPROC: Profile = Profile {
    name: "iproc_data",
    quirks: QUIRK_DATA_TIMEOUT_USES_SDCLK | QUIRK_MULTIBLOCK_READ_ACMD12 | QUIRK_NO_HISPD_BIT,
    quirks2: QUIRK2_ACMD23_BROKEN,
    caps: None,
    non_removable: false,
    access: Access::Native,
    intel_ops: false,
    pm_caps: PmFlags::NONE,
    min_clock_hz: None,
    platform_clock: true,
};
const BCM7211A0_BASE_CLK_MHZ: u32 = 100;
/// `sdhci-iproc.c` `bcm7211a0_data`.
pub const IPROC_BCM7211A0: Profile = Profile {
    name: "bcm7211a0_data",
    quirks: QUIRK_BROKEN_TIMEOUT_VAL | QUIRK_BROKEN_DMA | QUIRK_BROKEN_ADMA,
    quirks2: 0,
    caps: Some((
        ((BCM7211A0_BASE_CLK_MHZ / 2) << CAPS_TIMEOUT_CLK_SHIFT)
            | (BCM7211A0_BASE_CLK_MHZ << CAPS_CLOCK_BASE_SHIFT)
            | ((0x2 << CAPS_MAX_BLOCK_SHIFT) & CAPS_MAX_BLOCK_MASK)
            | CAPS_CAN_VDD_330
            | CAPS_CAN_VDD_180
            | CAPS_CAN_DO_SUSPEND
            | CAPS_CAN_DO_HISPD,
        CAPS1_DRIVER_TYPE_C | CAPS1_DRIVER_TYPE_D,
    )),
    non_removable: false,
    access: Access::Native,
    intel_ops: false,
    pm_caps: PmFlags::NONE,
    min_clock_hz: None,
    platform_clock: true,
};
// Linux keeps the iproc_data caps tables for these two but never applies
// them (`missing_caps` false); referenced so the tables stay exact.
const _: (u32, u32) = (IPROC_CAPS, IPROC_CAPS1);

const INTEL: u16 = 0x8086;
const NI: u16 = 0x1093;
const NI_7884: u16 = 0x7884;
/// `sdhci-pci.h` Intel SDIO device IDs bound to `intel_byt_sdio`.
pub const PCI_INTEL_SDIO: [u16; 7] = [0x0f15, 0x2295, 0x9d2c, 0x0ad0, 0x1ad0, 0x5ad0, 0x31d0];

/// PCI match: `sdhci_pci_ids` order. `SDHCI_PCI_SUBDEVICE(INTEL, BYT_SDIO,
/// NI, 7884, ni_byt_sdio)` precedes the plain BYT entry; that NI fixes
/// object additionally needs `ni_set_max_freq` (ACPI `MXFQ` on the PCI
/// companion), which is not ported, so it stays on the generic profile.
pub fn pci(vendor: u16, device: u16, subsystem_vendor: u16, subsystem_id: u16) -> Option<Profile> {
    if vendor != INTEL || !PCI_INTEL_SDIO.contains(&device) {
        return None;
    }
    if device == 0x0f15 && subsystem_vendor == NI && subsystem_id == NI_7884 {
        return None;
    }
    Some(PCI_INTEL_BYT_SDIO)
}

/// `sdhci_acpi_uids` rows that select `sdhci_acpi_slot_int_sdio`, matched
/// as `sdhci_acpi_get_slot` does (`acpi_dev_hid_uid_match`: a `None` UID
/// row matches any UID). First match wins in table order.
pub const ACPI_INT_SDIO_IDS: [(&str, Option<&str>); 6] = [
    ("80865AD0", None),
    ("80860F14", Some("2")),
    ("INT33BB", Some("2")),
    ("INT33C6", None),
    ("INT3436", None),
    ("INT344D", None),
];
/// `sdhci_acpi_uids` rows for the same HIDs that select a non-SDIO slot
/// (eMMC/SD); those are storage hosts, not this stack's.
const ACPI_OTHER_SLOTS: [(&str, &str); 4] = [
    ("80860F14", "1"),
    ("80860F14", "3"),
    ("INT33BB", "3"),
    ("PNP0FFF", "3"),
];

pub fn acpi(hid: &str, uid: Option<&str>) -> Option<Profile> {
    // Table order: an eMMC/SD row for the same HID+UID precedes nothing
    // here, but keep the exact first-match semantics explicit.
    if ACPI_OTHER_SLOTS
        .iter()
        .any(|(h, u)| *h == hid && uid == Some(*u))
    {
        return None;
    }
    ACPI_INT_SDIO_IDS
        .iter()
        .find(|(h, u)| *h == hid && (u.is_none() || *u == uid))
        .map(|_| ACPI_INT_SDIO)
}

/// `sdhci_iproc_of_match` in table order.
pub const OF_IPROC: [(&str, Profile); 5] = [
    ("brcm,bcm2835-sdhci", IPROC_BCM2835),
    ("brcm,bcm2711-emmc2", IPROC_BCM2711),
    ("brcm,sdhci-iproc-cygnus", IPROC_CYGNUS),
    ("brcm,sdhci-iproc", IPROC),
    ("brcm,bcm7211a0-sdhci", IPROC_BCM7211A0),
];
pub fn of(compatible: &str) -> Option<Profile> {
    OF_IPROC
        .iter()
        .find(|(c, _)| *c == compatible)
        .map(|(_, p)| *p)
}

/// Register adapter applying one front-end profile to an owned aperture.
#[derive(Debug)]
pub struct Ported<R> {
    inner: R,
    profile: Profile,
    /// Platform clock rate (`clk_get_rate`) when the profile needs one.
    clock: Option<u32>,
    /// Linux `host->clock`: last requested SD clock (0 until set).
    sd_clock: u32,
    shadow_cmd: u32,
    shadow_blk: u32,
    cmd_shadowed: bool,
    blk_shadowed: bool,
}

impl<R: Registers> Ported<R> {
    pub fn new(inner: R, profile: Profile, clock: Option<u32>) -> Self {
        Self {
            inner,
            profile,
            clock,
            sd_clock: 0,
            shadow_cmd: 0,
            shadow_blk: 0,
            cmd_shadowed: false,
            blk_shadowed: false,
        }
    }
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    pub fn inner(&self) -> &R {
        &self.inner
    }
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    fn delay_us(us: u64) {
        let _ = narf_scheduler::responsive_spin_until(|| false, Deadline::after_us(us));
    }
    fn iproc(&self) -> bool {
        self.profile.access == Access::Iproc32
    }
    /// `REG_OFFSET_IN_BITS`.
    const fn shift(reg: u32) -> u32 {
        (reg << 3) & 0x18
    }
    /// `sdhci_iproc_readl` (caps override applied above it).
    fn readl(&mut self, reg: u32) -> u32 {
        self.inner.read32(reg)
    }
    /// `sdhci_iproc_writel`.
    fn writel(&mut self, value: u32, reg: u32) {
        self.inner.write32(reg, value);
        if self.sd_clock <= 400_000 {
            // "Round up to micro-second four SD clock delay".
            if self.sd_clock != 0 {
                // `(4 * 1000000 + host->clock - 1) / host->clock`.
                Self::delay_us(u64::from(4_000_000u32.div_ceil(self.sd_clock)));
            } else {
                Self::delay_us(10);
            }
        }
    }
    fn caps_override(&self, reg: u32) -> Option<u32> {
        let (caps, caps1) = self.profile.caps?;
        match reg {
            CAPABILITIES => Some(caps),
            CAPABILITIES_1 => Some(caps1),
            _ => None,
        }
    }
    fn raw_read16(&mut self, reg: u32) -> u16 {
        if !self.iproc() {
            return self.inner.read16(reg);
        }
        // `sdhci_iproc_readw`.
        let value = if reg == TRANSFER_MODE && self.cmd_shadowed {
            self.shadow_cmd
        } else if (reg == BLOCK_SIZE || reg == BLOCK_COUNT) && self.blk_shadowed {
            self.shadow_blk
        } else {
            self.readl(reg & !3)
        };
        (value >> Self::shift(reg)) as u16
    }
    fn raw_write16(&mut self, reg: u32, value: u16) {
        if !self.iproc() {
            return self.inner.write16(reg, value);
        }
        // `sdhci_iproc_writew`.
        let word_shift = Self::shift(reg);
        let mask = 0xffffu32 << word_shift;
        let old = if reg == COMMAND {
            if self.blk_shadowed {
                let blk = self.shadow_blk;
                self.writel(blk, BLOCK_SIZE);
                self.blk_shadowed = false;
            }
            self.cmd_shadowed = false;
            self.shadow_cmd
        } else if (reg == BLOCK_SIZE || reg == BLOCK_COUNT) && self.blk_shadowed {
            self.shadow_blk
        } else {
            self.readl(reg & !3)
        };
        let new = (old & !mask) | (u32::from(value) << word_shift);
        if reg == TRANSFER_MODE {
            self.shadow_cmd = new;
            self.cmd_shadowed = true;
        } else if reg == BLOCK_SIZE || reg == BLOCK_COUNT {
            self.shadow_blk = new;
            self.blk_shadowed = true;
        } else {
            self.writel(new, reg & !3);
        }
    }
    fn raw_read8(&mut self, reg: u32) -> u8 {
        if !self.iproc() {
            return self.inner.read8(reg);
        }
        // `sdhci_iproc_readb`.
        (self.readl(reg & !3) >> Self::shift(reg)) as u8
    }
    fn raw_write8(&mut self, reg: u32, value: u8) {
        if !self.iproc() {
            return self.inner.write8(reg, value);
        }
        // `sdhci_iproc_writeb`.
        let old = self.readl(reg & !3);
        let shift = Self::shift(reg);
        let new = (old & !(0xff << shift)) | (u32::from(value) << shift);
        self.writel(new, reg & !3);
    }
    /// `sdhci_intel_set_power` after `sdhci_set_power` turned bus power on:
    /// "Bus power might not enable after D3 -> D0 transition ... Retry for
    /// up to 2ms" (`SDHCI_INTEL_PWR_TIMEOUT_CNT` 20 x 100 us).
    fn intel_power_retry(&mut self) {
        for _ in 0..20 {
            let mut reg = self.raw_read8(POWER_CONTROL);
            if reg & POWER_ON != 0 {
                break;
            }
            Self::delay_us(100);
            reg |= POWER_ON;
            self.raw_write8(POWER_CONTROL, reg);
        }
    }
    /// `sdhci_set_ios` (v3+, preset values off) around
    /// `sdhci_intel_set_uhs_signaling`: SD high speed selects UHS SDR25,
    /// with the card clock gated across the mode change.
    fn intel_high_speed(&mut self) {
        if (self.raw_read16(HOST_VERSION) & SPEC_VER_MASK) < SPEC_300 {
            return;
        }
        let clk = self.raw_read16(CLOCK_CONTROL);
        self.raw_write16(CLOCK_CONTROL, clk & !CLK_CARD_EN);
        let ctrl2 = self.raw_read16(HOST_CONTROL2);
        self.raw_write16(HOST_CONTROL2, (ctrl2 & !CTRL2_UHS_MASK) | CTRL2_UHS_SDR25);
        self.raw_write16(CLOCK_CONTROL, clk);
    }
}

impl<R: Registers> Registers for Ported<R> {
    fn host_identity(&self) -> Option<crate::pio::HostIdentity> {
        self.inner.host_identity()
    }
    fn source(&self) -> Option<crate::source::Source> {
        self.inner.source()
    }
    fn enable_intx(&mut self) -> bool {
        self.inner.enable_intx()
    }
    fn pm_caps(&mut self) -> PmFlags {
        self.inner.pm_caps().union(self.profile.pm_caps)
    }
    fn enable_dma(&mut self) -> Option<narf_io::DmaDevice> {
        // `SDHCI_QUIRK_BROKEN_DMA | BROKEN_ADMA` (bcm7211a0): PIO.
        if self.profile.quirks & (QUIRK_BROKEN_DMA | QUIRK_BROKEN_ADMA)
            == QUIRK_BROKEN_DMA | QUIRK_BROKEN_ADMA
        {
            return None;
        }
        self.inner.enable_dma()
    }
    fn disable_dma(&mut self) -> bool {
        self.inner.disable_dma()
    }
    fn base_clock_hz(&mut self) -> Option<u32> {
        if self.profile.platform_clock {
            self.clock
        } else {
            self.inner.base_clock_hz()
        }
    }
    fn clock_changed(&mut self, hz: u32) {
        self.sd_clock = hz;
        self.inner.clock_changed(hz);
    }
    fn read8(&mut self, offset: u32) -> u8 {
        self.raw_read8(offset)
    }
    fn read16(&mut self, offset: u32) -> u16 {
        self.raw_read16(offset)
    }
    fn read32(&mut self, offset: u32) -> u32 {
        if let Some(value) = self.caps_override(offset) {
            return value;
        }
        if self.iproc() {
            self.readl(offset)
        } else {
            self.inner.read32(offset)
        }
    }
    fn write8(&mut self, offset: u32, value: u8) {
        let mut value = value;
        if offset == HOST_CONTROL && self.profile.quirks & QUIRK_NO_HISPD_BIT != 0 {
            // `sdhci_set_ios`: the HISPD bit is never set on this host.
            value &= !CTRL_HISPD;
        }
        let rising_hispd = self.profile.intel_ops
            && offset == HOST_CONTROL
            && value & CTRL_HISPD != 0
            && self.raw_read8(HOST_CONTROL) & CTRL_HISPD == 0;
        self.raw_write8(offset, value);
        if self.profile.intel_ops && offset == POWER_CONTROL && value & POWER_ON != 0 {
            self.intel_power_retry();
        }
        if rising_hispd {
            self.intel_high_speed();
        }
    }
    fn write16(&mut self, offset: u32, value: u16) {
        if self.profile.intel_ops && offset == CLOCK_CONTROL {
            // `sdhci_intel_set_clock`: "Stop card clock separately to
            // avoid glitches on clock line".
            let clk = self.raw_read16(CLOCK_CONTROL);
            if clk & CLK_CARD_EN != 0 && value & CLK_CARD_EN == 0 {
                self.raw_write16(CLOCK_CONTROL, clk & !CLK_CARD_EN);
            }
        }
        self.raw_write16(offset, value);
    }
    fn write32(&mut self, offset: u32, value: u32) {
        if self.iproc() {
            self.writel(value, offset);
        } else {
            self.inner.write32(offset, value);
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "port_tests.rs"]
mod tests;
