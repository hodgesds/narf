//! Intel iwlwifi — CSR (Control / Status Register) layout.
//!
//! Adapted from Linux `drivers/net/wireless/intel/iwlwifi/iwl-csr.h`
//! (kernel ≥ 6.10) — GPL-2.0-or-later. NARF was relicensed to
//! GPL-2.0-or-later on 2026-05-20, so direct adaptation is allowed.
//!
//! These offsets live at the bottom of BAR0 and are directly
//! readable/writable through ordinary `MmioRegion::read32` /
//! `write32`. Unlike the PRPH window (see `prph.rs`), the MAC
//! does *not* need to be powered up to access CSRs — they live on
//! a side channel that stays alive as long as the device has
//! platform power.

#![allow(dead_code)]

// ── Direct-CSR offsets (BAR0 + off) ───────────────────────────────

/// Hardware interface configuration. Encodes platform power-saving
/// + bus-arbitration model. Driver writes `HAP_WAKE` in `apm_init`.
pub const CSR_HW_IF_CONFIG_REG: u32 = 0x000;
/// Interrupt coalescing — `(reads & writes) / 32 µs` threshold.
pub const CSR_INT_COALESCING: u32 = 0x004;
/// Pending interrupt status. Read-and-clear by writing the bits
/// back to it. Driver's MSI handler reads this first.
pub const CSR_INT: u32 = 0x008;
/// Interrupt-mask register. Bit set = enabled.
pub const CSR_INT_MASK: u32 = 0x00C;
/// Flow-handler interrupt status. Read on every IRQ to find which
/// DMA channel completed.
pub const CSR_FH_INT_STATUS: u32 = 0x010;
/// GPIO input register — reads platform-wired switches (HW RF-kill
/// switch lives here as `GP_CNTRL[27]` on newer parts).
pub const CSR_GPIO_IN: u32 = 0x018;
/// Reset. Setting `SW_RESET` (bit 7) on pre-Bz parts holds the
/// device in reset until the bit clears. On Bz+ the equivalent
/// lives in `CSR_GP_CNTRL`.
pub const CSR_RESET: u32 = 0x020;
/// General-purpose control. Carries the MAC wake-up handshake and
/// `INIT_DONE`/`MAC_CLOCK_READY` bits.
pub const CSR_GP_CNTRL: u32 = 0x024;
/// Function-scratch — driver-private 32-bit scratch the device
/// preserves across resets.
pub const CSR_FUNC_SCRATCH: u32 = 0x02C;
/// Hardware revision. Bit `15:4` = device type, `3:2` = step,
/// `1:0` = dash. Read by the probe path to print the SKU.
pub const CSR_HW_REV: u32 = 0x028;
/// EEPROM / OTP register window. Co-located with `FUNC_SCRATCH`
/// in older parts; the EEPROM path is the one that uses it.
pub const CSR_EEPROM_REG: u32 = 0x02C;
/// EEPROM general-purpose status.
pub const CSR_EEPROM_GP: u32 = 0x030;
/// OTP (one-time-programmable memory) general purpose.
pub const CSR_OTP_GP_REG: u32 = 0x034;
/// GIO control. Driver clears `L0S` here in `apm_config`.
pub const CSR_GIO_REG: u32 = 0x03C;
/// RF chip identity (per AX2xx family). Layout differs between
/// gen1/gen2.
pub const CSR_HW_RF_ID: u32 = 0x09C;
/// uCode general-purpose register (legacy mailbox).
pub const CSR_GP_UCODE_REG: u32 = 0x048;
/// Driver-private "GP driver" — radio-SKU select bits.
pub const CSR_GP_DRIVER_REG: u32 = 0x050;
/// uCode driver GP1 — driver→firmware mailbox.
pub const CSR_UCODE_DRV_GP1: u32 = 0x054;
/// uCode driver GP1 set-bit alias (write 1 = set, 0 = no-op).
pub const CSR_UCODE_DRV_GP1_SET: u32 = 0x058;
/// uCode driver GP1 clear-bit alias (write 1 = clear).
pub const CSR_UCODE_DRV_GP1_CLR: u32 = 0x05C;
/// uCode driver GP2 — firmware→driver mailbox.
pub const CSR_UCODE_DRV_GP2: u32 = 0x060;

/// Doorbell-style "OS alive" mailbox bit register.
pub const CSR_MBOX_SET_REG: u32 = 0x088;

/// LED control.
pub const CSR_LED_REG: u32 = 0x094;
/// DRAM int-tbl base.
pub const CSR_DRAM_INT_TBL_REG: u32 = 0x0A0;
/// Shadow-reg control 1 (6000+).
pub const CSR_MAC_SHADOW_REG_CTRL: u32 = 0x0A8;
/// Shadow-reg control 2 (6000+).
pub const CSR_MAC_SHADOW_REG_CTL2: u32 = 0x0AC;

/// LTR (Latency Tolerance Reporting) long-value AD register.
pub const CSR_LTR_LONG_VAL_AD: u32 = 0x0D4;
/// Last LTR message reported.
pub const CSR_LTR_LAST_MSG: u32 = 0x0DC;

/// `HEEP_CTRL_WRD_PCIEX_CTRL` — control register for the SHR
/// (shared-block) indirect-access window. Bits 15..0 = SHR address;
/// bits 29..28 = 2 (read) / 3 (write).
pub const HEEP_CTRL_WRD_PCIEX_CTRL_REG: u32 = 0x0EC;
/// `HEEP_CTRL_WRD_PCIEX_DATA` — paired data register for SHR
/// indirect access.
pub const HEEP_CTRL_WRD_PCIEX_DATA_REG: u32 = 0x0F4;

/// GIO chicken-bits (PCIe link power-management workarounds).
/// Driver sets `BIT_L1A_NO_L0S_RX` in `apm_init`.
pub const CSR_GIO_CHICKEN_BITS: u32 = 0x100;

/// IPC state — Bz+ reset / handshake state machine.
pub const CSR_IPC_STATE: u32 = 0x110;
/// IPC sleep control.
pub const CSR_IPC_SLEEP_CONTROL: u32 = 0x114;
/// Doorbell vector — Bz+ uses this to drive `UREG_DOORBELL_TO_ISR6`.
pub const CSR_DOORBELL_VECTOR: u32 = 0x130;
/// Host chicken-bits — power-management debug knobs.
pub const CSR_HOST_CHICKEN: u32 = 0x204;
/// Analog PLL config — driver sets `0x00880300` on parts with
/// `pll_cfg = true`.
pub const CSR_ANA_PLL_CFG: u32 = 0x20C;
/// Hardware monitor config — XTAL resources.
pub const CSR_MONITOR_CFG_REG: u32 = 0x214;
/// Hardware monitor status.
pub const CSR_MONITOR_STATUS_REG: u32 = 0x228;
/// Hardware-revision workaround register.
pub const CSR_HW_REV_WA_REG: u32 = 0x22C;
/// HPET memory debug register.
pub const CSR_DBG_HPET_MEM_REG: u32 = 0x240;
/// Link power-management debug register.
pub const CSR_DBG_LINK_PWR_MGMT_REG: u32 = 0x250;

// ── HBUS (host-bus indirect access) ───────────────────────────────
//
// HBUS registers sit at `HBUS_BASE = 0x400` from the start of BAR0
// and provide indirect access to device-internal memory + the
// peripheral (PRPH) register window. The MAC must be "awake" (see
// `apm_init`) before these are usable.

/// HBUS register-window base.
pub const HBUS_BASE: u32 = 0x400;

/// Address register for indirect SRAM reads.
pub const HBUS_TARG_MEM_RADDR: u32 = HBUS_BASE + 0x00C;
/// Address register for indirect SRAM writes.
pub const HBUS_TARG_MEM_WADDR: u32 = HBUS_BASE + 0x010;
/// Data register for indirect SRAM writes.
pub const HBUS_TARG_MEM_WDAT: u32 = HBUS_BASE + 0x018;
/// Data register for indirect SRAM reads.
pub const HBUS_TARG_MEM_RDAT: u32 = HBUS_BASE + 0x01C;

/// Mailbox-C — alternate command-blocked signal for RF-kill flow.
pub const HBUS_TARG_MBX_C: u32 = HBUS_BASE + 0x030;

/// PRPH write-address register.
pub const HBUS_TARG_PRPH_WADDR: u32 = HBUS_BASE + 0x044;
/// PRPH read-address register.
pub const HBUS_TARG_PRPH_RADDR: u32 = HBUS_BASE + 0x048;
/// PRPH write-data register.
pub const HBUS_TARG_PRPH_WDAT: u32 = HBUS_BASE + 0x04C;
/// PRPH read-data register.
pub const HBUS_TARG_PRPH_RDAT: u32 = HBUS_BASE + 0x050;

/// Per-Tx-queue write-pointer index.
pub const HBUS_TARG_WRPTR: u32 = HBUS_BASE + 0x060;

// ── MSI-X register window (AX-class parts) ─────────────────────────

/// MSI-X register base.
pub const CSR_MSIX_BASE: u32 = 0x2000;
/// MSI-X FH interrupt-cause aggregate.
pub const CSR_MSIX_FH_INT_CAUSES_AD: u32 = CSR_MSIX_BASE + 0x800;
/// MSI-X FH interrupt mask.
pub const CSR_MSIX_FH_INT_MASK_AD: u32 = CSR_MSIX_BASE + 0x804;
/// MSI-X HW interrupt-cause aggregate.
pub const CSR_MSIX_HW_INT_CAUSES_AD: u32 = CSR_MSIX_BASE + 0x808;
/// MSI-X HW interrupt mask.
pub const CSR_MSIX_HW_INT_MASK_AD: u32 = CSR_MSIX_BASE + 0x80C;

// ── CSR_RESET bits (CSR + 0x020) ──────────────────────────────────

/// "NEVO reset" — historical name for the legacy SW reset.
pub const CSR_RESET_REG_FLAG_NEVO_RESET: u32 = 0x0000_0001;
/// Force NMI — watchdog uses this to dump error logs.
pub const CSR_RESET_REG_FLAG_FORCE_NMI: u32 = 0x0000_0002;
/// Software-controlled reset. Sticky until cleared.
pub const CSR_RESET_REG_FLAG_SW_RESET: u32 = 0x0000_0080;
/// Master disable — asserted while reprogramming the flow handler.
pub const CSR_RESET_REG_FLAG_MASTER_DISABLED: u32 = 0x0000_0100;
/// Stop the device — set when the driver is unbinding.
pub const CSR_RESET_REG_FLAG_STOP_MASTER: u32 = 0x0000_0200;
/// Disable link power-management while resetting.
pub const CSR_RESET_LINK_PWR_MGMT_DISABLED: u32 = 0x8000_0000;

// ── CSR_GP_CNTRL bits ─────────────────────────────────────────────

/// MAC clock is up — device has acknowledged the wake request.
pub const CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY: u32 = 0x0000_0001;
/// Host has put the device into D0A (fully operational).
pub const CSR_GP_CNTRL_REG_FLAG_INIT_DONE: u32 = 0x0000_0004;
/// Host requests + maintains MAC wakeup for indirect access.
pub const CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ: u32 = 0x0000_0008;
/// MAC entering power-saving sleep — don't poke device.
pub const CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP: u32 = 0x0000_0010;
/// Force XTAL on (low-power-XTAL workaround).
pub const CSR_GP_CNTRL_REG_FLAG_XTAL_ON: u32 = 0x0000_0400;
/// HW RF-kill switch state (read-only) — set if killed.
pub const CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW: u32 = 0x0800_0000;

// Bz+ replacements — different bit layout for the init/reset flow.
pub const CSR_GP_CNTRL_REG_FLAG_MAC_INIT: u32 = 1 << 6;
pub const CSR_GP_CNTRL_REG_FLAG_ROM_START: u32 = 1 << 7;
pub const CSR_GP_CNTRL_REG_FLAG_MAC_STATUS: u32 = 1 << 20;
pub const CSR_GP_CNTRL_REG_FLAG_BZ_MAC_ACCESS_REQ: u32 = 1 << 21;
pub const CSR_GP_CNTRL_REG_FLAG_BUS_MASTER_DISABLE_REQ: u32 = 1 << 29;
pub const CSR_GP_CNTRL_REG_FLAG_SW_RESET: u32 = 1 << 31;

// ── CSR_HW_IF_CONFIG_REG bits ─────────────────────────────────────

/// Step-and-dash mask within `HW_IF_CONFIG`.
pub const CSR_HW_IF_CONFIG_REG_MSK_MAC_STEP_DASH: u32 = 0x0000_000F;
/// HAP-INTA wake — drives the PCIe link out of L1a → L0s.
pub const CSR_HW_IF_CONFIG_REG_HAP_WAKE: u32 = 0x0008_0000;
/// EEPROM-ownership semaphore (legacy).
pub const CSR_HW_IF_CONFIG_REG_EEPROM_OWN_SEM: u32 = 0x0020_0000;
/// PCI owns the device.
pub const CSR_HW_IF_CONFIG_REG_PCI_OWN_SET: u32 = 0x0040_0000;
/// iAMT is owning the device — driver must back off.
pub const CSR_HW_IF_CONFIG_REG_IAMT_UP: u32 = 0x0100_0000;
/// ME (Management Engine) owns the device.
pub const CSR_HW_IF_CONFIG_REG_ME_OWN: u32 = 0x0200_0000;
/// Wake-ME signal.
pub const CSR_HW_IF_CONFIG_REG_WAKE_ME: u32 = 0x0800_0000;
/// Persistence bit — retain state across SHRD_HW_RST in S3.
pub const CSR_HW_IF_CONFIG_REG_PERSISTENCE: u32 = 0x4000_0000;

// ── CSR_GIO bits ──────────────────────────────────────────────────

/// Disable L0s in the PCIe link control (workaround). Set always
/// on parts that need it.
pub const CSR_GIO_REG_VAL_L0S_DISABLED: u32 = 0x0000_0002;

// ── CSR_GIO_CHICKEN_BITS bits ─────────────────────────────────────

/// Disable L0s exit timer — pre-8000 workaround.
pub const CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER: u32 = 0x2000_0000;
/// Disable L1A → L0s on the RX path (ICH workaround).
pub const CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX: u32 = 0x0080_0000;

// ── CSR_INT bits (host-interrupt status / set / clear) ───────────

pub const CSR_INT_BIT_FH_RX: u32 = 1 << 31; // Rx DMA / cmd responses
pub const CSR_INT_BIT_HW_ERR: u32 = 1 << 29; // DMA hardware error
pub const CSR_INT_BIT_RX_PERIODIC: u32 = 1 << 28;
pub const CSR_INT_BIT_FH_TX: u32 = 1 << 27; // Tx DMA
pub const CSR_INT_BIT_SCD: u32 = 1 << 26; // TXQ pointer advanced
pub const CSR_INT_BIT_SW_ERR: u32 = 1 << 25; // uCode error
pub const CSR_INT_BIT_RF_KILL: u32 = 1 << 7;
pub const CSR_INT_BIT_CT_KILL: u32 = 1 << 6; // Critical temperature
pub const CSR_INT_BIT_SW_RX: u32 = 1 << 3; // Rx / cmd responses
pub const CSR_INT_BIT_RESET_DONE: u32 = 1 << 2;
pub const CSR_INT_BIT_WAKEUP: u32 = 1 << 1;
pub const CSR_INT_BIT_ALIVE: u32 = 1 << 0;

/// Composite of every CSR_INT bit driver should default-enable
/// after `apm_init`. Mirrors Linux `CSR_INI_SET_MASK`.
pub const CSR_INI_SET_MASK: u32 = CSR_INT_BIT_FH_RX
    | CSR_INT_BIT_HW_ERR
    | CSR_INT_BIT_FH_TX
    | CSR_INT_BIT_SW_ERR
    | CSR_INT_BIT_RF_KILL
    | CSR_INT_BIT_SW_RX
    | CSR_INT_BIT_WAKEUP
    | CSR_INT_BIT_RESET_DONE
    | CSR_INT_BIT_ALIVE
    | CSR_INT_BIT_RX_PERIODIC;

// ── HW REV decode (CSR_HW_REV) ────────────────────────────────────

/// Extract the device-type field (`bits 19..4`) from `HW_REV`.
/// Mirrors Linux `CSR_HW_REV_TYPE`: `((_val) & 0x000FFF0) >> 4`.
#[inline]
pub const fn csr_hw_rev_type(val: u32) -> u32 {
    (val & 0x000F_FFF0) >> 4
}

/// Extract the step+dash field (`bits 3..0`) from `HW_REV`.
#[inline]
pub const fn csr_hw_rev_step_dash(val: u32) -> u32 {
    val & CSR_HW_IF_CONFIG_REG_MSK_MAC_STEP_DASH
}

// HW REV device-type values (subset; AX-class)
pub const CSR_HW_REV_TYPE_QU_B0: u32 = 0x331;
pub const CSR_HW_REV_TYPE_QU_C0: u32 = 0x332;
pub const CSR_HW_REV_TYPE_QUZ: u32 = 0x351;
pub const CSR_HW_REV_TYPE_SO: u32 = 0x370;
pub const CSR_HW_REV_TYPE_TY: u32 = 0x420;
