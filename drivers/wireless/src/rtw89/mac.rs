//! RTW89 MAC subsystem — power-on sequence, chip-ID detection,
//! register definitions.
//!
//! This file plays the role of `rtw88/{power.rs, regs.rs}` for the
//! Wi-Fi-6 silicon. The register block layout is similar — both
//! families speak the same "SYS / PMU / EFUSE" idiom — but the
//! AX-generation 8852/8851/8922 parts moved nearly every interesting
//! bit to a different offset. We pin the Linux source for each
//! constant so the diff is auditable.
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `drivers/net/wireless/realtek/rtw89/reg.h` (v6.6) — `R_AX_*`
//!   offsets, lines 1..~250 cover the SYS/PMU/EFUSE block this stage
//!   touches.
//! - Linux `drivers/net/wireless/realtek/rtw89/mac.c` (v6.6) —
//!   `rtw89_mac_power_switch` (~L1510), `rtw89_mac_pwr_on` (~L1575),
//!   `rtw89_mac_pwr_seq` (~L1302).
//! - Linux `drivers/net/wireless/realtek/rtw89/core.h` (v6.6) —
//!   `enum rtw89_core_chip_id` (~L163) gives the chip-id namespace
//!   we mirror.

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

// ── SYS / power-control registers (BAR2 + offset) ──────────────────
//
// Per `rtw89/reg.h`. The SYS block sits in the lower 0x100 bytes and
// is what `rtw89_mac_power_switch` walks before the MAC / DMA paths
// come alive.

/// `R_AX_SYS_ISO_CTRL` — isolation control. Linux `reg.h:11`.
pub const R_AX_SYS_ISO_CTRL: u64 = 0x0000;
/// `B_AX_PWC_EV2EF_B14` — EV→EF power-coupling, bit 14. `reg.h:14`.
pub const B_AX_PWC_EV2EF_B14: u16 = 1 << 14;
/// `B_AX_PWC_EV2EF_B15` — EV→EF power-coupling, bit 15. `reg.h:13`.
pub const B_AX_PWC_EV2EF_B15: u16 = 1 << 15;
/// `B_AX_ISO_EB2CORE` — EFUSE-block to core isolation. `reg.h:15`.
pub const B_AX_ISO_EB2CORE: u16 = 1 << 8;

/// `R_AX_SYS_FUNC_EN` — system function enable. `reg.h:17`.
pub const R_AX_SYS_FUNC_EN: u64 = 0x0002;
/// `B_AX_FEN_BB_GLB_RSTN` — BB global reset. `reg.h:18`.
pub const B_AX_FEN_BB_GLB_RSTN: u16 = 1 << 1;
/// `B_AX_FEN_BBRSTB` — BB reset. `reg.h:19`.
pub const B_AX_FEN_BBRSTB: u16 = 1 << 0;

/// `R_AX_SYS_PW_CTRL` — system power control. `reg.h:21`.
pub const R_AX_SYS_PW_CTRL: u64 = 0x0004;
/// `B_AX_PSUS_OFF_CAPC_EN` — power-suspend cap-EN. `reg.h:30`.
pub const B_AX_PSUS_OFF_CAPC_EN: u32 = 1 << 14;
/// `B_AX_RDY_SYSPWR` — SYS power-ready bit. `reg.h:27`.
pub const B_AX_RDY_SYSPWR: u32 = 1 << 17;
/// `B_AX_EN_WLON` — enable WLAN-on. `reg.h:28`.
pub const B_AX_EN_WLON: u32 = 1 << 16;
/// `B_AX_APFM_OFFMAC` — auto power-down "off MAC" trigger. `reg.h:34`.
pub const B_AX_APFM_OFFMAC: u32 = 1 << 9;
/// `B_AX_APFN_ONMAC` — auto power-up "on MAC" trigger. `reg.h:35`.
pub const B_AX_APFN_ONMAC: u32 = 1 << 8;

/// `R_AX_SYS_CLK_CTRL` — system clock control. `reg.h:37`.
pub const R_AX_SYS_CLK_CTRL: u64 = 0x0008;
/// `B_AX_CPU_CLK_EN` — bit 14. `reg.h:38`.
pub const B_AX_CPU_CLK_EN: u16 = 1 << 14;

/// `R_AX_SYS_WL_EFUSE_CTRL` — WL-EFUSE auto-load status. `reg.h:8`.
pub const R_AX_SYS_WL_EFUSE_CTRL: u64 = 0x000A;
/// `B_AX_AUTOLOAD_SUS` — auto-load-sustained, bit 5. `reg.h:9`.
pub const B_AX_AUTOLOAD_SUS: u16 = 1 << 5;

/// `R_AX_RSV_CTRL` — reserved-control gate. `reg.h:47`.
pub const R_AX_RSV_CTRL: u64 = 0x001C;
/// `B_AX_R_DIS_PRST` — disable PCIe-reset, bit 6. `reg.h:48`.
pub const B_AX_R_DIS_PRST: u8 = 1 << 6;

/// `R_AX_EFUSE_CTRL` — EFUSE control + 16-bit data window. `reg.h:63`.
pub const R_AX_EFUSE_CTRL: u64 = 0x0030;
/// EFUSE address mask — `GENMASK(26, 16)`. `reg.h:67`.
pub const B_AX_EF_ADDR_MASK: u32 = 0x07FF_0000;
/// EFUSE address-field shift (low bit of `B_AX_EF_ADDR_MASK`).
pub const B_AX_EF_ADDR_SHIFT: u32 = 16;
/// EFUSE data mask — `GENMASK(15, 0)`. `reg.h:68`.
pub const B_AX_EF_DATA_MASK: u32 = 0x0000_FFFF;
/// EFUSE ready bit — `BIT(29)`. `reg.h:65`. Writes clear it; the
/// hardware sets it once the read result is in `B_AX_EF_DATA_MASK`.
pub const B_AX_EF_RDY: u32 = 1 << 29;
/// EFUSE mode-select mask — `GENMASK(31, 30)`. `reg.h:64`. Bit 31 is
/// the "burst read" flag; bit 30 selects DAV (digital analog VR)
/// versus DDV (digital).
pub const B_AX_EF_MODE_SEL_MASK: u32 = 0xC000_0000;

/// `R_AX_EFUSE_CTRL_1` — EFUSE control (CV0 family). `reg.h:54`.
pub const R_AX_EFUSE_CTRL_1: u64 = 0x0038;
/// `R_AX_EFUSE_CTRL_1_V1` — EFUSE control (CV1 family — 8852C). Same
/// physical offset, different bit layout. `reg.h:70`.
pub const R_AX_EFUSE_CTRL_1_V1: u64 = 0x0038;
/// `B_AX_EF_ENT` — EFUSE-entry enable, bit 31. `reg.h:71`.
pub const B_AX_EF_ENT: u32 = 1 << 31;
/// `B_AX_EF_BURST` — burst-read mode, bit 19. `reg.h:72`.
pub const B_AX_EF_BURST: u32 = 1 << 19;

/// `R_AX_SYS_SDIO_CTRL` — HCI-side ctrl. `reg.h:120`.
pub const R_AX_SYS_SDIO_CTRL: u64 = 0x0070;
/// `B_AX_PCIE_FORCE_PWR_NGAT` — bit 13. `reg.h:123`. Set during PCI
/// HCI bring-up so the PMU keeps the L2/L3 gates open.
pub const B_AX_PCIE_FORCE_PWR_NGAT: u32 = 1 << 13;

/// `R_AX_PLATFORM_ENABLE` — top-level enable for the wifi platform.
/// `reg.h:143`.
pub const R_AX_PLATFORM_ENABLE: u64 = 0x0088;
/// `B_AX_AXIDMA_EN` — AXI-DMA enable, bit 3. `reg.h:144`.
pub const B_AX_AXIDMA_EN: u8 = 1 << 3;
/// `B_AX_APB_WRAP_EN` — APB wrap enable, bit 2. `reg.h:145`.
pub const B_AX_APB_WRAP_EN: u8 = 1 << 2;
/// `B_AX_WCPU_EN` — WLAN-CPU enable, bit 1. `reg.h:146`.
pub const B_AX_WCPU_EN: u8 = 1 << 1;
/// `B_AX_PLATFORM_EN` — top-level platform enable, bit 0. `reg.h:147`.
pub const B_AX_PLATFORM_EN: u8 = 1 << 0;

/// `R_AX_SYS_CFG1` — system-cfg-1 (read-only chip-version reg).
/// `reg.h:182`.
pub const R_AX_SYS_CFG1: u64 = 0x00F0;
/// `B_AX_CHIP_VER_MASK` — `GENMASK(15, 12)`. `reg.h:183`.
pub const B_AX_CHIP_VER_MASK: u32 = 0x0000_F000;
/// Shift to align `B_AX_CHIP_VER_MASK` to a u8.
pub const B_AX_CHIP_VER_SHIFT: u32 = 12;

// ── Chip-version enumeration ───────────────────────────────────────
//
// Linux `core.h` (~L163) groups the parts into `enum rtw89_core_chip_id`.
// We mirror that exactly so a future cross-file branch (`match chip.id`)
// looks identical to the kernel original.

/// One of the supported Realtek 802.11ax/be chips.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipId {
    /// RTL8852A. AX, CV0.
    Rtl8852A,
    /// RTL8852B / 8852BT. AX, CV0.
    Rtl8852B,
    /// RTL8852C. AX, CV1.
    Rtl8852C,
    /// RTL8851B. AX, CV0.
    Rtl8851B,
    /// RTL8922A. BE (Wi-Fi 7) generation.
    Rtl8922A,
}

impl ChipId {
    /// Map a PCI device id → known chip family. Returns `None` for
    /// devices we don't know yet (the probe path can still bind, but
    /// per-chip quirks won't fire).
    pub const fn from_pci_did(did: u16) -> Option<Self> {
        match did {
            0x8852 | 0xA85A => Some(ChipId::Rtl8852A),
            0xB852 | 0xB85B => Some(ChipId::Rtl8852B),
            0xC852 => Some(ChipId::Rtl8852C),
            0xB851 => Some(ChipId::Rtl8851B),
            0x8922 | 0x892B => Some(ChipId::Rtl8922A),
            _ => None,
        }
    }

    /// Which MAC/PHY generation this chip belongs to. Determines the
    /// `mac.c` vs `mac_be.c` codepath in Linux; here it gates the
    /// per-chip Stage-2 ring layout.
    pub const fn generation(&self) -> ChipGeneration {
        match self {
            ChipId::Rtl8852A | ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B => {
                ChipGeneration::Ax
            }
            ChipId::Rtl8922A => ChipGeneration::Be,
        }
    }
}

/// AX (802.11ax, Wi-Fi 6) vs BE (802.11be, Wi-Fi 7) MAC generation.
/// Each takes a different EFUSE map shape and DMA-ring layout. Linux
/// `core.h` defines `enum rtw89_chip_gen { RTW89_CHIP_AX, RTW89_CHIP_BE }`
/// — we use the same names.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipGeneration {
    /// 802.11ax MAC (`mac.c`, `efuse.c`, `pci.c`).
    Ax,
    /// 802.11be MAC (`mac_be.c`, `efuse_be.c`, `pci_be.c`).
    Be,
}

/// Errors raised by the MAC bring-up path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MacError {
    /// `R_AX_SYS_FUNC_EN` returned the all-FF "device gone" sentinel.
    /// Either silicon-absent or the BAR window isn't routed.
    DeviceGone,
    /// Power-on prologue never saw `B_AX_RDY_SYSPWR` go high within
    /// the wall-clock budget. Either the part needs the full per-chip
    /// PWR-seq table (which this stage doesn't ship) or the BIOS
    /// already powered the part down to D3-cold.
    Timeout,
}

/// Sentinel returned by an absent / unrouted PCIe BAR.
const READ_GONE_U16: u16 = 0xFFFF;

/// Detect the chip-version field from `R_AX_SYS_CFG1`. Linux uses
/// this for per-cut quirks (e.g. `_rtw8852b_pwr_seq_a` only runs on
/// CV0). Returns the raw 4-bit field — we don't pin a per-chip
/// enum at Stage 0 because the value depends on the silicon revision
/// and the table mapping it lives per-chip in
/// `rtw89/rtw8852a_table.c`/etc.
///
/// # Safety
/// Caller owns the BAR2 MMIO exclusively.
pub unsafe fn read_chip_version(mmio: &MmioRegion) -> u8 {
    // SAFETY: identity-mapped MMIO; caller asserts BAR2 ownership.
    let cfg = unsafe { mmio.read32(R_AX_SYS_CFG1) };
    ((cfg & B_AX_CHIP_VER_MASK) >> B_AX_CHIP_VER_SHIFT) as u8
}

/// Baseline power-on prologue. Runs the chip-agnostic minimum from
/// `rtw89_mac_power_switch(on=true)` — full per-chip PWR-seq table
/// is deferred.
///
/// The sequence here mirrors `rtw89_mac_power_switch`:
///
/// 1. Presence check via `R_AX_SYS_FUNC_EN`.
/// 2. Unlock the RSV-CTRL register so PMU writes land.
/// 3. Clear `B_AX_AFSM_PCIE_SUS_EN` / friends in `R_AX_SYS_PW_CTRL`
///    so the part exits PCIe-suspend.
/// 4. Strobe `B_AX_APFN_ONMAC` to kick the PMU's "power-on" state
///    machine. Linux's per-chip table does this via a polled WRITE +
///    POLL pair (`cur_cfg->cmd == PWR_CMD_POLL`); we approximate with
///    a deadline-spin on the ready bit.
/// 5. Wait for `B_AX_RDY_SYSPWR` to assert.
/// 6. Set `B_AX_PLATFORM_EN | B_AX_APB_WRAP_EN | B_AX_AXIDMA_EN` in
///    `R_AX_PLATFORM_ENABLE` so the AXI-DMA + APB are live for EFUSE.
///
/// # Safety
/// Caller owns the BAR2 MMIO exclusively for the duration of the
/// call.
pub unsafe fn baseline_power_on(mmio: &MmioRegion) -> Result<(), MacError> {
    // SAFETY: identity-mapped MMIO.
    let presence = unsafe { mmio.read16(R_AX_SYS_FUNC_EN) };
    if presence == READ_GONE_U16 {
        return Err(MacError::DeviceGone);
    }

    // Step 1: unlock RSV_CTRL so PMU writes land. Per Linux
    // `rtw89_mac_power_switch_boot_mode` (~L1483) the equivalent
    // `B_AX_R_DIS_PRST` clear is the first action.
    // SAFETY: same.
    unsafe {
        let v = mmio.read8(R_AX_RSV_CTRL);
        mmio.write8(R_AX_RSV_CTRL, v & !B_AX_R_DIS_PRST);
    }

    // Step 2: clear power-suspend gates in SYS_PW_CTRL so the PMU
    // moves out of PCIe-suspend. Linux `rtw89_mac_power_switch`
    // does the equivalent via `rtw89_write32_clr(rtwdev,
    // R_AX_SYS_PW_CTRL, B_AX_PSUS_OFF_CAPC_EN)` at ~L2706.
    // SAFETY: same.
    unsafe {
        let v = mmio.read32(R_AX_SYS_PW_CTRL);
        mmio.write32(R_AX_SYS_PW_CTRL, v & !B_AX_PSUS_OFF_CAPC_EN);
    }

    // Step 3: kick PMU power-on state machine via APFN_ONMAC and
    // enable WLON. Per the AX pwr_on table (look at
    // `rtw89_pwr_on_seq_8852a` referenced in `rtw89_mac_pwr_seq`),
    // these two bits asserted together drive the PMU into the
    // "ready" state.
    // SAFETY: same.
    unsafe {
        let v = mmio.read32(R_AX_SYS_PW_CTRL);
        mmio.write32(R_AX_SYS_PW_CTRL, v | B_AX_EN_WLON | B_AX_APFN_ONMAC);
    }

    // Step 4: wait for B_AX_RDY_SYSPWR. Linux's per-chip PWR-seq
    // table encodes this as a POLL slot with a 5..50 ms budget; we
    // pick the upper end so a slow-cut 8852C settling doesn't time
    // out spuriously.
    let mut last: u32 = 0;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            last = unsafe { mmio.read32(R_AX_SYS_PW_CTRL) };
            last & B_AX_RDY_SYSPWR != 0
        },
        Deadline::after_ms(50),
    );
    if !done {
        // Don't leave APFN_ONMAC pulsed on the failure path — Linux
        // calls `rtw89_mac_power_switch(false)` to clean up; we do
        // the equivalent inline.
        // SAFETY: same.
        unsafe {
            let v = mmio.read32(R_AX_SYS_PW_CTRL);
            mmio.write32(R_AX_SYS_PW_CTRL, v & !B_AX_APFN_ONMAC);
        }
        return Err(MacError::Timeout);
    }

    // Step 5: enable platform clocks so AXI-DMA / APB are live. EFUSE
    // reads need APB up; the full DMA-ring bring-up will need the
    // AXIDMA + WCPU bits too, so we set them now even though Stage 0
    // doesn't use them.
    // SAFETY: same.
    unsafe {
        let v = mmio.read8(R_AX_PLATFORM_ENABLE);
        mmio.write8(
            R_AX_PLATFORM_ENABLE,
            v | B_AX_PLATFORM_EN | B_AX_APB_WRAP_EN | B_AX_AXIDMA_EN,
        );
    }

    Ok(())
}
