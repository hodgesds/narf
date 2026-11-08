//! Realtek RTL8152/RTL8153 USB Ethernet driver — register-level.
//!
//! Full driver for the RTL8152 (USB 2.0, 10/100) and RTL8153 /
//! RTL8155 / RTL8156 / RTL8157 (USB 3.x, GbE / 2.5 GbE) family —
//! the chip inside most USB-C docks and USB Ethernet dongles.
//!
//! ## Register / wire model
//!
//! Register facts (addresses, bit definitions, descriptor formats)
//! are the chip's publicly documented programming model, as
//! mirrored by the public references for this family:
//! - Linux `drivers/net/usb/r8152.c` (cited by the original stub).
//! - FreeBSD `sys/dev/usb/net/if_ure.c` register header.
//!
//! The MAC's register file is reached through the **OCP vendor
//! control protocol**: a vendor device request (`bRequest = 0x05`
//! for both directions; `bmRequestType` 0xC0 read / 0x40 write)
//! where `wValue` is the register address and `wIndex` packs the
//! MCU window (`0x0100` = PLA, `0x0000` = USB) OR'd with a byte
//! enable (`0xFF` dword / `0x33` word / `0x11` byte, shifted to the
//! accessed byte lanes). Reads and writes move in ≤ 64-byte chunks
//! at 4-byte-aligned addresses.
//!
//! Datapath formats:
//! - **RX**: bulk-IN transfers carry an aggregation buffer of
//!   back-to-back segments; each segment is a 24-byte `rx_desc`
//!   (`opts1..opts6`, `opts1 & 0x7FFF` = frame length INCLUDING
//!   the trailing 4-byte FCS, which the walk strips) followed by
//!   the frame + FCS, zero-padded so the next descriptor starts
//!   at the next 8-byte boundary (Linux `rx_bottom` /
//!   `rx_agg_align`, `RX_ALIGN` = 8). `opts2` carries the
//!   checksum report bits (`RD_IPV4_CS` / `RD_IPV6_CS` /
//!   `RD_TCP_CS` / `RD_UDP_CS`) and `opts3` the fail bits
//!   (`RX_IPF` / `RX_UDPF` / `RX_TCPF`); the pump decodes them
//!   (`rx_csum_result`) and drops device-verified corrupt frames
//!   (`rx_segment_deliverable`), with an IPv4/UDP zero-checksum
//!   exception. The v1 layout is used for every generation
//!   except the RTL8157 (VER_16), which uses the 16-byte v2
//!   descriptor (`rx_desc_v2`, Linux `r8157_desc_init`):
//!   the length moves to `opts1` bits 17..31 and counts the
//!   trailing FCS, the VLAN tag moves to `opts1` bit 3 (TCI in
//!   the high half of `opts2`), all checksum report/fail bits
//!   move into `opts3`, and segments align to 16 bytes
//!   (`parse_rx_aggregate_v2`, `rx_csum_result_v2`).
//! - **TX**: each bulk-OUT transfer is one 8-byte `tx_desc`
//!   (`opts1 = len | TX_FS | TX_LS`, plus GTSENDV4/V6 +
//!   transport-offset for hardware TSO) followed by the frame,
//!   zero-padded to a 4-byte multiple (`TX_ALIGN`). `opts2`
//!   carries the offloads the stack requested via `TxMeta`:
//!   VLAN insert, IPv4/IPv6 + TCP/UDP checksum generation, or
//!   the TSO MSS — plain frames still encode `opts2 = 0`. The
//!   RTL8157 uses the 16-byte v2 TX descriptor instead
//!   (`tx_desc_v2`: same `opts1`/`opts2`, plus
//!   `opts3 = len << 4` and `opts4 = TX_SIG`, padded to 16),
//!   with a tighter transport-offset cap (`TCPHO_MAX_2` =
//!   0x3FF, `build_tx_segment_meta_v2`).
//!
//! The MAC address is **read from the device** (`PLA_IDR`, or
//! `PLA_BACKUP` on the GbE generations, with the other as fallback)
//! and validated; a device that reports no valid address fails the
//! bind — no address is ever invented. Carrier / speed / duplex
//! come from `PLA_PHYSTATUS`, sampled by the RX pump and published
//! through `narf_net::iface::set_link_metadata`.
//!
//! Publication: each bound device registers as `usb-rtl{N}` via
//! `narf_net::iface::register_with_context` with the device-record
//! index as the send cookie, so TX always routes to the bound
//! device (the queue-22 shared PCIe publish helper is a future
//! dedup for this, not a dependency).
//!
//! ## Scope limits (honest)
//!
//! The version-switched PHY init layer covers every known chip
//! version (Linux's `r8152b_hw_phy_cfg`, `r8153_hw_phy_cfg`,
//! `r8153b_hw_phy_cfg`, `r8153c_hw_phy_cfg`, `r8156_hw_phy_cfg`,
//! `r8156b_hw_phy_cfg`, `r8157_hw_phy_cfg` — see the §881 section
//! in the code), and the firmware-blob step
//! (`rtl8152_apply_firmware`) is implemented over the
//! `narf_firmware` registry: the per-version blob is fetched by
//! its Linux file name and validated (SHA-256 header checksum +
//! per-block rules) before any block is applied. NARF ships no
//! firmware blobs itself — a version whose blob is absent from
//! the registry runs its table without the firmware step, like
//! Linux's failed `request_firmware` (warn and continue).
//! TEST_01 and unknown versions keep reset defaults. Still open:
//! the USB/LPM init layers for the other families (Linux's
//! `r8152b_init` / `r8153b_init` / `r8156_init`, the counterpart
//! of the VER_03–VER_06 `r8153_init` layer already ported) —
//! tracked as follow-up issues.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::class_registry::{
    register_class_driver_with_unbind, SuspendOutcome, UsbClassMatch, UsbProbeError,
};
use crate::device::USBDevice;
use crate::xhci::{EndpointConfig, EndpointKind};

// ── OCP vendor-request protocol ──────────────────────────────────

/// MCU window selector for `wIndex` (high byte).
pub const MCU_TYPE_PLA: u16 = 0x0100;
pub const MCU_TYPE_USB: u16 = 0x0000;

/// `bmRequestType` for register reads (device-to-host, vendor).
pub const REQT_READ: u8 = 0xC0;
/// `bmRequestType` for register writes (host-to-device, vendor).
pub const REQT_WRITE: u8 = 0x40;
/// `bRequest` for register reads.
pub const REQ_GET_REGS: u8 = 0x05;
/// `bRequest` for register writes.
pub const REQ_SET_REGS: u8 = 0x05;

/// Byte-enable patterns packed into `wIndex` (low byte), shifted
/// left by the accessed byte-lane offset before use.
pub const BYTE_EN_DWORD: u16 = 0xFF;
pub const BYTE_EN_WORD: u16 = 0x33;
pub const BYTE_EN_BYTE: u16 = 0x11;

/// Largest single OCP read chunk (the reference model caps reads
/// at 64 bytes per control transfer).
pub const OCP_READ_CHUNK: usize = 64;

// ── PLA register map (subset the datapath needs) ─────────────────

/// Permanent station address (6 bytes used of an 8-byte read).
pub const PLA_IDR: u16 = 0xC000;
/// Receive Configuration Register (accept-filter bits).
pub const PLA_RCR: u16 = 0xC010;
/// Receive Maximum Size (bytes).
pub const PLA_RMS: u16 = 0xC016;
/// Multicast Address Registers (8 bytes; all-ones = accept all
/// multicast groups the RCR filter admits).
pub const PLA_MAR: u16 = 0xCD00;
/// Backup station address — the live MAC on GbE generations.
pub const PLA_BACKUP: u16 = 0xD000;
/// Transmit Configuration Register 1 (chip-version bits).
pub const PLA_TCR1: u16 = 0xE612;
/// Chip command byte register (reset / RX enable / TX enable).
pub const PLA_CR: u16 = 0xE813;
/// PHY link-status byte (speed / duplex / link).
pub const PLA_PHYSTATUS: u16 = 0xE908;

/// `PLA_TCR1` version field mask.
pub const TCR1_VERSION_MASK: u16 = 0x7CF0;

/// OCP PHY-register window base register (Linux `PLA_OCP_GPHY_BASE`).
pub const PLA_OCP_GPHY_BASE: u16 = 0xE86C;
/// PHY power register (Linux `PLA_PHY_PWR`).
pub const PLA_PHY_PWR: u16 = 0xE84C;
/// EEE control register (Linux `PLA_EEE_CR`).
pub const PLA_EEE_CR: u16 = 0xE040;
/// Poll register for ALDPS-disable completion (Linux reads PLA
/// `0xe000` bit `0x0100` after clearing `EN_ALDPS`).
pub const PLA_ALDPS_POLL: u16 = 0xE000;
pub const ALDPS_POLL_DONE: u16 = 0x0100;

/// OCP PHY registers (Linux `OCP_*`, reached through the
/// `PLA_OCP_GPHY_BASE` window).
pub const OCP_POWER_CFG: u16 = 0xA430;
pub const OCP_EEE_CFG: u16 = 0xA432;
pub const OCP_SRAM_ADDR: u16 = 0xA436;
pub const OCP_SRAM_DATA: u16 = 0xA438;
pub const OCP_DOWN_SPEED: u16 = 0xA442;
pub const OCP_BASE_MII: u16 = 0xA400;
pub const OCP_EEE_ADV: u16 = 0xA5D0;

/// `OCP_POWER_CFG` bits.
pub const POWER_CFG_EN_ALDPS: u16 = 0x0004;
pub const POWER_CFG_EEE_CLKDIV_EN: u16 = 0x8000;
pub const POWER_CFG_EN_10M_PLLOFF: u16 = 0x0001;
/// `OCP_EEE_CFG` bits.
pub const EEE_CFG_EEE10_EN: u16 = 0x0010;
pub const EEE_CFG_CTAP_SHORT_EN: u16 = 0x0040;
/// `OCP_DOWN_SPEED` bits.
pub const DOWN_SPEED_EN_10M_BGOFF: u16 = 0x0080;
/// `PLA_PHY_PWR` bits.
pub const PHY_PWR_PFM_PWM_SWITCH: u16 = 0x0040;
/// `PLA_EEE_CR` bits.
pub const EEE_CR_RX_EN: u16 = 0x0001;
pub const EEE_CR_TX_EN: u16 = 0x0002;
/// USB-window U2P3 control (Linux `USB_U2P3_CTRL`).
pub const USB_U2P3_CTRL: u16 = 0xB460;
pub const U2P3_ENABLE: u16 = 0x0001;

// ── r8153 USB/LPM init layer (Linux `r8153_init`) ────────────────────
// Register addresses/bits of the original RTL8153 family's USB/LPM
// init sequence. These are the vendor programming model's facts as
// mirrored by the public Linux register header; the sequence that
// uses them is re-derived below in `r8153_init_ops`, not copied.

/// `PLA_BOOT_CTRL` + autoload-done poll bit.
pub const PLA_BOOT_CTRL: u16 = 0xE004;
pub const AUTOLOAD_DONE: u16 = 0x0002;

/// OCP PHY status register + accept values (Linux `OCP_PHY_STATUS`,
/// `PHY_STAT_*`). Read through the GPHY window (`ocp_reg_read`).
pub const OCP_PHY_STATUS: u16 = 0xA420;
pub const PHY_STAT_MASK: u16 = 0x0007;
pub const PHY_STAT_LAN_ON: u16 = 3;
pub const PHY_STAT_PWRDN: u16 = 5;
pub const PHY_STAT_EXT_INIT: u16 = 2;

/// PHY ADC configuration (Linux `OCP_ADC_CFG`): VER_03/04/05 only.
/// Value = `CKADSEL_L | ADC_EN | EN_EMI_L` = `0x0100 | 0x0080 | 0x0040`.
pub const OCP_ADC_CFG: u16 = 0xBC06;
pub const ADC_CFG_8153: u16 = 0x01C0;

/// U1/U2 tolerance array (Linux `USB_TOLERANCE`): 8 bytes of 0xFF
/// enable U1/U2, 8 bytes of 0x00 disable them. Written here as two
/// dword writes to the same byte lanes (same final state as one
/// 8-byte OCP transfer).
pub const USB_TOLERANCE: u16 = 0xD490;

/// USB power-cut + misc registers (Linux `USB_POWER_CUT`,
/// `USB_MISC_0`).
pub const USB_POWER_CUT: u16 = 0xD80A;
pub const PWR_EN: u16 = 0x0001;
pub const PHASE2_EN: u16 = 0x0008;
pub const USB_MISC_0: u16 = 0xD81A;
pub const PCUT_STATUS: u16 = 0x0001;

/// MAC clock speed-down (Linux `PLA_MAC_PWR_CTRL2`).
pub const PLA_MAC_PWR_CTRL2: u16 = 0xE0CA;
pub const MAC_CLK_SPDWN_EN: u16 = 0x8000;

/// VER_04 SuperSpeed PHY link tuning (Linux `USB_SSPHYLINK2`,
/// `pwd_dn_scale`): mask `0x3FFE`, value `96 << 1`.
pub const USB_SSPHYLINK2: u16 = 0xB428;
pub const SSPHYLINK2_PWD_DN_SCALE_MASK: u16 = 0x3FFE;
pub const SSPHYLINK2_PWD_DN_SCALE_96: u16 = 0x00C0;

/// VER_04 USB2 PHY L1/suspend bits (Linux `USB_USB2PHY`).
pub const USB_USB2PHY: u16 = 0xB41E;
pub const USB2PHY_L1: u8 = 0x02;
pub const USB2PHY_SUSPEND: u8 = 0x01;

/// Burst-size / dummy control (Linux `USB_BURST_SIZE`,
/// `USB_CSR_DUMMY1/2`).
pub const USB_BURST_SIZE: u16 = 0xCFC0;
pub const USB_CSR_DUMMY1: u16 = 0xB464;
pub const DYNAMIC_BURST: u8 = 0x01;
pub const USB_CSR_DUMMY2: u16 = 0xB466;
pub const EP4_FULL_FC: u8 = 0x01;

/// Watchdog timer 11 (Linux `USB_WDT11_CTRL`).
pub const USB_WDT11_CTRL: u16 = 0xE43C;
pub const TIMER11_EN: u16 = 0x0001;

/// LED mode mask (Linux `PLA_LED_FEATURE`).
pub const PLA_LED_FEATURE: u16 = 0xDD92;
pub const LED_MODE_MASK: u16 = 0x0700;

/// LPM control byte (Linux `USB_LPM_CTRL`): FIFO threshold +
/// ROK-exit + timer. 500 ms only for VER_04 below SuperSpeed,
/// 500 us otherwise.
pub const USB_LPM_CTRL: u16 = 0xD41A;
pub const LPM_CTRL_FIFO_EMPTY_1FB: u8 = 0x30;
pub const LPM_CTRL_ROK_EXIT_LPM: u8 = 0x02;
pub const LPM_CTRL_TIMER_500MS: u8 = 0x04;
pub const LPM_CTRL_TIMER_500US: u8 = 0x0C;

/// AFE sensitivity (Linux `USB_AFE_CTRL2`).
pub const USB_AFE_CTRL2: u16 = 0xD824;
pub const AFE_SEN_VAL_MASK: u16 = 0xF800;
pub const AFE_SEN_VAL_NORMAL: u16 = 0xA000;
pub const AFE_SEL_RXIDLE: u16 = 0x0100;

/// USB connect timer (Linux `USB_CONNECT_TIMER`).
pub const USB_CONNECT_TIMER: u16 = 0xCBF8;

/// Wake-on-LAN config registers (Linux `PLA_CONFIG6`,
/// `PLA_LWAKE_CTRL_REG`).
pub const PLA_CONFIG6: u16 = 0xE90A;
pub const CONFIG6_LANWAKE_CLR_EN: u8 = 0x01;
pub const PLA_LWAKE_CTRL_REG: u16 = 0xE007;
pub const LWAKE_LANWAKE_PIN: u8 = 0x80;

/// RX aggregation control (Linux `USB_USB_CTRL`).
pub const USB_USB_CTRL: u16 = 0xD406;
pub const USB_CTRL_RX_AGG_DISABLE: u16 = 0x0010;
pub const USB_CTRL_RX_ZERO_EN: u16 = 0x0080;

/// Tally-counter reset (Linux `PLA_RSTTALLY`).
pub const PLA_RSTTALLY: u16 = 0xE800;
pub const TALLY_RESET: u16 = 0x0001;

/// RX early timeout, programmed from the coalesce value at enable
/// time (Linux `USB_RX_EARLY_TIMEOUT`, `r8153_set_rx_early_timeout`).
pub const USB_RX_EARLY_TIMEOUT: u16 = 0xD42C;

/// VER_06 runtime-wake indication (Linux `PLA_INDICATE_FALG` —
/// Linux's spelling — `PLA_SUSPEND_FLAG`, `PLA_EXTRA_STATUS`).
pub const PLA_INDICATE_FALG: u16 = 0xD38C;
pub const INDICATE_UPCOMING_RUNTIME_D3: u8 = 0x01;
pub const PLA_SUSPEND_FLAG: u16 = 0xD38A;
pub const SUSPEND_LINK_CHG_EVENT: u8 = 0x01;
pub const PLA_EXTRA_STATUS: u16 = 0xD398;
pub const EXTRA_STATUS_LINK_CHANGE_FLAG: u16 = 0x0100;
pub const EXTRA_STATUS_CUR_LINK_OK: u16 = 0x8000;
pub const EXTRA_STATUS_POLL_LINK_CHG: u16 = 0x0001;

/// VER_05 ALDPS dummy bit (Linux `PLA_DMY_REG0`, `ECM_ALDPS`).
pub const PLA_DMY_REG0: u16 = 0xC0B0;
pub const DMY_ECM_ALDPS: u8 = 0x02;

/// Link-off-wake bit cleared by the init layer's
/// runtime-suspend-disable step (Linux `LINK_OFF_WAKE_EN`).
pub const CONFIG34_LINK_OFF_WAKE_EN: u16 = 0x0008;

/// BMCR power-down bit cleared by the init layer (IEEE 802.3
/// clause 22: BMCR is MII register 0, power-down is bit 11).
pub const MII_BMCR: u16 = 0;
pub const BMCR_PDOWN: u16 = 0x0800;

/// RX coalesce timeout in us by negotiated USB speed (Linux
/// `COALESCE_*`, selected in `r8153_init`).
pub const COALESCE_SUPER: u32 = 85_000;
pub const COALESCE_HIGH: u32 = 250_000;
pub const COALESCE_SLOW: u32 = 524_280;

/// PHY SRAM tuning cells (Linux `SRAM_*`).
pub const SRAM_LPF_CFG: u16 = 0x8012;
pub const SRAM_10M_AMP1: u16 = 0x8080;
pub const SRAM_10M_AMP2: u16 = 0x8082;
pub const SRAM_IMPEDANCE: u16 = 0x8084;

/// MII advertisement register + pause bits (IEEE 802.3 clause 22).
pub const MII_ADVERTISE: u16 = 4;
pub const ADVERTISE_PAUSE_CAP: u16 = 0x0400;
pub const ADVERTISE_PAUSE_ASYM: u16 = 0x0800;

/// EEE advertisement for the original RTL8153 (Linux `eee_adv` =
/// `MDIO_EEE_1000T | MDIO_EEE_100TX` = `0x0004 | 0x0002`).
pub const EEE_ADV_8153: u16 = 0x0006;

// ── Per-family PHY-init registers (Linux `r8152.c` register header) ──
// Addresses/bits for the RTL8152 (VER_01/02/07), RTL8153B
// (VER_08/09), RTL8156 (VER_10/11), RTL8156B (VER_12/13/15), RTL8153C
// (VER_14) and RTL8157 (VER_16/17) PHY-init sequences. Same sourcing
// as the VER_03–VER_06 constants above: the Linux register header.

/// Second PHY SRAM bank (Linux `OCP_SRAM2_ADDR` / `OCP_SRAM2_DATA`).
pub const OCP_SRAM2_ADDR: u16 = 0xB87C;
pub const OCP_SRAM2_DATA: u16 = 0xB87E;
/// PHY control config (Linux `OCP_NCTL_CFG`).
pub const OCP_NCTL_CFG: u16 = 0xA42C;
/// System-clock divider config (Linux `OCP_SYSCLK_CFG`).
pub const OCP_SYSCLK_CFG: u16 = 0xC416;
/// 10GBASE-T control (Linux `OCP_10GBT_CTRL`).
pub const OCP_10GBT_CTRL: u16 = 0xA5D4;
/// Interrupt enable (Linux `OCP_INTR_EN`).
pub const OCP_INTR_EN: u16 = 0xA424;
/// EEE configuration registers for the FE family (Linux
/// `OCP_EEE_CONFIG1/2/3`, `OCP_EEE_AR`, `OCP_EEE_DATA`).
pub const OCP_EEE_CONFIG1: u16 = 0x2080;
pub const OCP_EEE_CONFIG2: u16 = 0x2092;
pub const OCP_EEE_CONFIG3: u16 = 0x2094;
pub const OCP_EEE_AR: u16 = 0xA41A;
pub const OCP_EEE_DATA: u16 = 0xA41C;
/// Second EEE advertisement register, 2.5G/5G families (Linux
/// `OCP_EEE_ADV2`).
pub const OCP_EEE_ADV2: u16 = 0xA6D4;
/// ALDPS configuration register, FE family (Linux
/// `OCP_ALDPS_CONFIG`).
pub const OCP_ALDPS_CONFIG: u16 = 0x2010;
/// PHY patch request/status + lock (Linux `OCP_PHY_PATCH_CMD`,
/// `OCP_PHY_PATCH_STAT`, `OCP_PHY_LOCK`).
pub const OCP_PHY_PATCH_CMD: u16 = 0xB820;
pub const OCP_PHY_PATCH_STAT: u16 = 0xB800;
pub const OCP_PHY_LOCK: u16 = 0xB82E;
/// ADC bias offset register (Linux `OCP_ADC_IOFFSET`).
pub const OCP_ADC_IOFFSET: u16 = 0xBCFC;

/// `OCP_NCTL_CFG` bits.
pub const NCTL_CFG_PGA_RETURN_EN: u16 = 0x0002;
/// `OCP_DOWN_SPEED` bits (2.5G/5G families).
pub const DOWN_SPEED_EN_EEE_CMODE: u16 = 0x4000;
pub const DOWN_SPEED_EN_EEE_1000: u16 = 0x2000;
pub const DOWN_SPEED_EN_EEE_100: u16 = 0x1000;
pub const DOWN_SPEED_EN_10M_CLKDIV: u16 = 0x0800;
/// `OCP_PHY_PATCH_CMD` / `OCP_PHY_PATCH_STAT` bits.
pub const PATCH_REQUEST: u16 = 0x0010;
pub const PATCH_READY: u16 = 0x0040;
/// `OCP_PHY_LOCK` bit.
pub const PHY_LOCK_PATCH_LOCK: u16 = 0x0001;
/// SRAM green-config bits (Linux `SRAM_GREEN_CFG`, `GREEN_ETH_EN`,
/// `R_TUNE_EN`).
pub const SRAM_GREEN_CFG: u16 = 0x8011;
pub const GREEN_ETH_EN: u16 = 0x8000;
pub const GREEN_CFG_R_TUNE_EN: u16 = 0x0800;
/// `OCP_INTR_EN` bits.
pub const INTR_EN_SPEED_FORCE: u16 = 0x0008;
/// `OCP_10GBT_CTRL` bits.
pub const CTRL_10GBT_ADV2_5G_F_R: u16 = 0x0020;
/// Clock-divider encodings (Linux `clk_div_expo(5)` /
/// `sysclk_div_expo(5)`).
pub const CLK_DIV_EXPO_5: u16 = 0x0050;
pub const SYSCLK_DIV_EXPO_5: u16 = 0x0500;
/// `OCP_ALDPS_CONFIG` bits (FE family).
pub const ALDPS_CFG_ENPWRSAVE: u16 = 0x8000;
pub const ALDPS_CFG_ENPDNPS: u16 = 0x0200;
pub const ALDPS_CFG_LINKENA: u16 = 0x0100;
pub const ALDPS_CFG_DIS_SDSAVE: u16 = 0x0010;
/// `OCP_ALDPS_CONFIG` full values (Linux `r8152_aldps_en`).
pub const ALDPS_CFG_8152_ENABLE: u16 = 0x8310;
pub const ALDPS_CFG_8152_DISABLE: u16 = 0x0310;
/// FE-family EEE config bits (Linux `r8152_eee_en`).
pub const EEE_10_CAP: u16 = 0x2000;
pub const EEE_NWAY_EN: u16 = 0x1000;
pub const EEE_TX_QUIET_EN: u16 = 0x0200;
pub const EEE_RX_QUIET_EN: u16 = 0x0100;
pub const EEE_RG_DACQUIET_EN: u16 = 0x0400;
pub const EEE_RG_LDVQUIET_EN: u16 = 0x0200;
/// `OCP_EEE_CONFIG1` sd-rise-time mask / values
/// (Linux `sd_rise_time_mask`, `sd_rise_time(1)` / `(7)`).
pub const EEE_SD_RISE_TIME_MASK: u16 = 0x0070;
pub const EEE_SD_RISE_TIME_1: u16 = 0x0010;
pub const EEE_SD_RISE_TIME_7: u16 = 0x0070;
/// `OCP_EEE_CONFIG3` fast-SNR mask / values
/// (Linux `fast_snr_mask`, `fast_snr(42)` / `(511)`).
pub const EEE_FAST_SNR_MASK: u16 = 0xFF80;
pub const EEE_FAST_SNR_42: u16 = 0x1500;
pub const EEE_FAST_SNR_511: u16 = 0xFF80;
/// MMD indirect-access function codes (Linux `FUN_ADDR` /
/// `FUN_DATA`) and the AN MMD (Linux `MDIO_MMD_AN`,
/// `MDIO_AN_EEE_ADV`).
pub const MMD_FUN_ADDR: u16 = 0x0000;
pub const MMD_FUN_DATA: u16 = 0x4000;
pub const MDIO_MMD_AN: u16 = 7;
pub const MDIO_AN_EEE_ADV: u16 = 60;
/// MDIO EEE advertisement bits (Linux `include/uapi/linux/mdio.h`).
pub const MDIO_EEE_100TX: u16 = 0x0002;
pub const MDIO_EEE_1000T: u16 = 0x0004;
pub const MDIO_EEE_10GT: u16 = 0x0008;
pub const MDIO_EEE_2_5GT: u16 = 0x0001;
pub const MDIO_EEE_5GT: u16 = 0x0002;
/// `eee_adv` per family (Linux `rtl_ops_init`).
pub const EEE_ADV_8152: u16 = 0x0002;
pub const EEE_ADV_8157: u16 = 0x000E;

/// MAC power control 4 (Linux `PLA_MAC_PWR_CTRL4`) + speed-down bit.
pub const PLA_MAC_PWR_CTRL4: u16 = 0xE0CE;
pub const MAC_PWR_CTRL4_EEE_SPDWN_EN: u16 = 0x0001;
/// 2.5G EEE TX wake timer (Linux `PLA_EEE_TXTWSYS_2P5G`).
pub const PLA_EEE_TXTWSYS_2P5G: u16 = 0xE058;
/// USB configuration (Linux `PLA_USB_CFG`) + link-IP bits.
pub const PLA_USB_CFG: u16 = 0xE952;
pub const USB_CFG_EN_XG_LIP: u16 = 0x0002;
pub const USB_CFG_EN_G_LIP: u16 = 0x0004;
/// EFUSE command/data (Linux `PLA_EFUSE_CMD`, `PLA_EFUSE_DATA`).
pub const PLA_EFUSE_CMD: u16 = 0xDD02;
pub const PLA_EFUSE_DATA: u16 = 0xDD00;
pub const EFUSE_READ_CMD: u16 = 0x8000;
pub const EFUSE_DATA_BIT16: u16 = 0x0080;
/// UPHY timer (Linux `PLA_UPHY_TIMER`).
pub const PLA_UPHY_TIMER: u16 = 0xD388;
/// Breakpoint registers (Linux `PLA_BP_0`, `PLA_BP_BA`,
/// `PLA_BP_EN`).
pub const PLA_BP_0: u16 = 0xFC28;
pub const PLA_BP_BA: u16 = 0xFC26;
pub const PLA_BP_EN: u16 = 0xFC38;
/// MAC debug pre/post (Linux `PLA_MACDBG_PRE` / `PLA_MACDBG_POST`,
/// VER_04 only; `PLA_MACDBG_PRE` shares its address with
/// `PLA_INDICATE_FALG`).
pub const PLA_MACDBG_PRE: u16 = 0xD38C;
pub const PLA_MACDBG_POST: u16 = 0xD38E;
pub const MACDBG_DEBUG_OE: u16 = 0x0001;
pub const MACDBG_DEBUG_LTSSM: u16 = 0x0082;
/// PHY patch GPIO control (Linux `PLA_POL_GPIO_CTRL`).
pub const PLA_POL_GPIO_CTRL: u16 = 0xDC6A;
pub const POL_GPIO_GPHY_PATCH: u16 = 0x0010;
/// GPHY control (Linux `PLA_GPHY_CTRL`).
pub const PLA_GPHY_CTRL: u16 = 0xD3AE;
pub const GPHY_CTRL_FLASH: u16 = 0x0002;
/// PHY firmware version SRAM cell (Linux `SRAM_GPHY_FW_VER`).
pub const SRAM_GPHY_FW_VER: u16 = 0x801E;

/// U1/U2 idle timer (Linux `USB_U1U2_TIMER`).
pub const USB_U1U2_TIMER: u16 = 0xD4DA;
/// UPS configuration (Linux `USB_UPS_CFG`) + saw-count mask.
pub const USB_UPS_CFG: u16 = 0xD842;
pub const UPS_CFG_SAW_CNT_1MS_MASK: u16 = 0x0FFF;
pub const UPS_CFG_MID_REVERSE: u16 = 0x0020;
/// Flow-control timer (Linux `USB_FC_TIMER`).
pub const USB_FC_TIMER: u16 = 0xD340;
pub const FC_TIMER_CTRL_EN: u16 = 0x8000;
/// Misc 1 (Linux `USB_MISC_1`) + BND mask.
pub const USB_MISC_1: u16 = 0xD81F;
pub const MISC_1_BND_MASK: u16 = 0x0004;
/// Firmware control/task (Linux `USB_FW_CTRL`, `USB_FW_TASK`).
pub const USB_FW_CTRL: u16 = 0xD334;
pub const FW_CTRL_FLOW_CTRL_PATCH_OPT: u16 = 0x0002;
pub const FW_CTRL_FLOW_CTRL_PATCH_2: u16 = 0x0100;
pub const USB_FW_TASK: u16 = 0xD4E8;
pub const FW_TASK_FC_PATCH: u16 = 0x0002;
/// Firmware fix enables (Linux `USB_FW_FIX_EN0/1`).
pub const USB_FW_FIX_EN0: u16 = 0xCFCA;
pub const USB_FW_FIX_EN1: u16 = 0xCFCC;
pub const FW_FIX_SUSPEND: u16 = 0x4000;
pub const FW_FIX_IP_RESET_EN: u16 = 0x0200;
/// Watchdog-1 control (Linux `USB_WDT1_CTRL`).
pub const USB_WDT1_CTRL: u16 = 0xE404;
pub const WDT1_EN: u16 = 0x0001;
/// CSTMR (Linux `USB_CSTMR`) + force-SuperSpeed bit.
pub const USB_CSTMR: u16 = 0xCFEF;
pub const CSTMR_FORCE_SUPER: u16 = 0x0001;
/// Breakpoint 4 (Linux `USB_BP_4` = `PLA_BP_4`) + SuperSpeed-only value.
pub const USB_BP_4: u16 = 0xFC30;
pub const BP4_SUPER_ONLY: u16 = 0x1578;
/// GPHY control, USB window (Linux `USB_GPHY_CTRL`) + bits.
pub const USB_GPHY_CTRL: u16 = 0xD284;
pub const GPHY_CTRL_BYPASS_FLASH: u16 = 0x0020;
pub const GPHY_CTRL_PATCH_DONE: u16 = 0x0004;
pub const GPHY_CTRL_BACKUP_RESTRORE: u16 = 0x0040;
/// UPHY3 MDCM DIO (Linux `USB_UPHY3_MDCMDIO`).
pub const USB_UPHY3_MDCMDIO: u16 = 0xD480;
/// Second breakpoint-enable register (Linux `USB_BP2_EN`).
pub const USB_BP2_EN: u16 = 0xFC48;
/// U3P3 check enable (Linux `U3P3_CHECK_EN`, VER_05 only).
pub const EXTRA_STATUS_U3P3_CHECK_EN: u16 = 0x0080;

// `PLA_CR` bits.
pub const CR_RST: u8 = 0x10;
pub const CR_RE: u8 = 0x08;
pub const CR_TE: u8 = 0x04;

// `PLA_RCR` accept-filter bits.
pub const RCR_AAP: u32 = 1 << 0; // accept all (promiscuous)
pub const RCR_APM: u32 = 1 << 1; // accept physical match (unicast to us)
pub const RCR_AM: u32 = 1 << 2; // accept multicast
pub const RCR_AB: u32 = 1 << 3; // accept broadcast

// `PLA_PHYSTATUS` bits.
pub const PHYSTAT_1000M: u8 = 0x10;
pub const PHYSTAT_100M: u8 = 0x08;
pub const PHYSTAT_10M: u8 = 0x04;
pub const PHYSTAT_LINK: u8 = 0x02;
pub const PHYSTAT_FULL_DUP: u8 = 0x01;

/// VLAN receive-enable registers (Linux `rtl_rx_vlan_en`):
/// VER_01–VER_09 and VER_14 use `PLA_CPCR`, newer versions use
/// `PLA_RCR1` (Linux's default arm covers TEST_01 too).
pub const PLA_CPCR: u16 = 0xE854;
pub const CPCR_RX_VLAN: u16 = 0x0040;
pub const PLA_RCR1: u16 = 0xC012;
pub const RCR1_OUTER_VLAN: u16 = 0x0080;
pub const RCR1_INNER_VLAN: u16 = 0x0040;

/// Wake-on-LAN registers (Linux `__rtl_get_wol` /
/// `__rtl_set_wol`).
pub const PLA_CFG_WOL: u16 = 0xC0B6;
pub const WOL_MAGIC_EN: u16 = 0x0001;
pub const PLA_CONFIG34: u16 = 0xE820;
pub const CONFIG34_LINK_ON_WAKE_EN: u16 = 0x0010;
pub const PLA_CONFIG5: u16 = 0xE822;
pub const CONFIG5_UWF_EN: u16 = 0x0010;
pub const CONFIG5_BWF_EN: u16 = 0x0040;
pub const CONFIG5_MWF_EN: u16 = 0x0020;
pub const PLA_CRWECR: u16 = 0xE81C;
pub const CRWECR_CONFIG: u8 = 0xC0;
pub const CRWECR_NORMAL: u8 = 0x00;

// `tx_desc.opts1` offload bits (Linux v1 descriptor).
pub const TX_GTSENDV4: u32 = 1 << 28;
pub const TX_GTSENDV6: u32 = 1 << 27;
pub const TX_GTTCPHO_SHIFT: u32 = 18;
pub const TX_GTTCPHO_MAX: u32 = 0x7F;
// `tx_desc.opts2` offload bits.
pub const TX_UDP_CS: u32 = 1 << 31;
pub const TX_TCP_CS: u32 = 1 << 30;
pub const TX_IPV4_CS: u32 = 1 << 29;
pub const TX_IPV6_CS: u32 = 1 << 28;
pub const TX_MSS_SHIFT: u32 = 17;
pub const TX_MSS_MAX: u32 = 0x7FF;
pub const TX_TCPHO_SHIFT: u32 = 17;
pub const TX_TCPHO_MAX: u32 = 0x7FF;
pub const TX_VLAN_TAG_BIT: u32 = 1 << 16;
// `rx_desc.opts2` VLAN bit (Linux `RX_VLAN_TAG`).
pub const RX_VLAN_TAG_BIT: u32 = 1 << 16;
// `rx_desc.opts2` RX checksum report bits (Linux `RD_*_CS`, v1
// descriptor): which checksums the chip examined on this frame.
pub const RD_IPV4_CS: u32 = 1 << 19;
pub const RD_IPV6_CS: u32 = 1 << 20;
pub const RD_TCP_CS: u32 = 1 << 22;
pub const RD_UDP_CS: u32 = 1 << 23;
// `rx_desc.opts3` RX checksum fail bits (Linux `IPF` / `UDPF` /
// `TCPF`, v1 descriptor): the examined checksum was wrong.
pub const RX_IPF: u32 = 1 << 23;
pub const RX_UDPF: u32 = 1 << 22;
pub const RX_TCPF: u32 = 1 << 21;

// ── RTL8157 v2 descriptor formats (Linux `rx_desc_v2` /
// `tx_desc_v2`, `r8157_desc_init`) ──────────────────────────
//
// RTL8157 (VER_16, `PLA_TCR1` 0x1030) uses a different packet
// descriptor format from every earlier generation (upstream
// Linux `drivers/net/usb/r8152.c`, RTL8157 series merged
// 2026-03, based on Realtek's out-of-tree driver): both
// descriptors shrink to 16 bytes (4 × u32), the RX length
// moves to the top of `opts1` and counts the trailing FCS,
// and every checksum bit moves into RX `opts3`.

/// RX aggregation segment header length for v2 (`rx_desc_v2`,
/// 4 × u32).
pub const RX_DESC_V2_LEN: usize = 16;
/// RX aggregation alignment for v2 (Linux `r8157_desc_init`:
/// `rx_desc.align = 16` — the next segment starts at the next
/// 16-byte boundary after frame + FCS).
pub const RX_DESC_V2_ALIGN: usize = 16;
/// `rx_desc_v2.opts1` frame-length mask / shift (Linux
/// `RX_LEN_MASK_2` / `rx_v2_get_len`): bits 17..31 hold the
/// frame length INCLUDING the trailing FCS (`RX_FCS_LEN`).
pub const RX_V2_LEN_MASK: u32 = 0xFFFE_0000;
pub const RX_V2_LEN_SHIFT: u32 = 17;
/// `rx_desc_v2.opts1` VLAN-tag-present bit (Linux
/// `RX_VLAN_TAG_2`); the TCI itself lives in the high half of
/// `opts2` (see [`rx_vlan_tag_v2`]).
pub const RX_V2_VLAN_TAG_BIT: u32 = 1 << 3;
/// `rx_desc_v2.opts1` descriptor-version field mask (Linux
/// `RX_VER_MASK`). Linux's walk does not validate it, and
/// neither does this parser — it is defined here so a reader
/// of a raw descriptor can name the low two bits.
pub const RX_V2_VER_MASK: u32 = 0x3;
/// `rx_desc_v2.opts3` RX checksum report bits (Linux
/// `RD_*_CS_2`): which checksums the chip examined on this
/// frame. Unlike v1, report and fail bits share `opts3`.
pub const RD_IPV4_CS_V2: u32 = 1 << 14;
pub const RD_IPV6_CS_V2: u32 = 1 << 15;
pub const RD_TCP_CS_V2: u32 = 1 << 10;
pub const RD_UDP_CS_V2: u32 = 1 << 11;
/// `rx_desc_v2.opts3` RX checksum fail bits (Linux `IPF_2` /
/// `UDPF_2` / `TCPF_2`): the examined checksum was wrong.
pub const RX_IPF_V2: u32 = 1 << 26;
pub const RX_UDPF_V2: u32 = 1 << 25;
pub const RX_TCPF_V2: u32 = 1 << 24;
/// TX descriptor length / aggregation alignment for v2
/// (Linux `tx_desc_v2`, `r8157_desc_init`: `tx_desc.size` =
/// 16, `tx_desc.align` = 16).
pub const TX_DESC_V2_LEN: usize = 16;
pub const TX_DESC_V2_ALIGN: usize = 16;
/// `tx_desc_v2.opts3` length encoding (Linux `tx_v2_set_len`:
/// `len << 4`).
pub const TX_V2_LEN_SHIFT: u32 = 4;
/// `tx_desc_v2.opts4` signature (Linux `TX_SIG`: `0x15 << 27`).
pub const TX_V2_SIG: u32 = 0x15 << 27;
/// TX transport-offset cap for v2 (Linux `TCPHO_MAX_2`: 0x3FF,
/// vs `TX_TCPHO_MAX` 0x7FF for v1). The TSO cap is unchanged
/// (`TX_GTTCPHO_MAX`): Linux's `r8157_tx_csum` tightens only
/// the non-GSO checksum path and delegates TSO to the shared
/// `r8152_tx_csum`.
pub const TX_TCPHO_MAX_V2: u32 = 0x3FF;

// ── Datapath descriptor formats ──────────────────────────────────

/// RX aggregation segment header length (`rx_desc`, 6 × u32).
pub const RX_DESC_LEN: usize = 24;
/// RX aggregation segment alignment (Linux `RX_ALIGN`:
/// `rx_agg_align` rounds the end of frame + FCS up to the
/// next 8-byte boundary, where the next `rx_desc` starts).
pub const RX_DESC_ALIGN: usize = 8;
/// FCS bytes trailing each RX frame inside the descriptor's
/// length field (Linux `ETH_FCS_LEN`); the walk strips them,
/// so `RxSegment.len` stays "delivered frame bytes".
pub const RX_FCS_LEN: usize = 4;
/// `rx_desc.opts1` frame-length mask.
pub const RX_LEN_MASK: u32 = 0x7FFF;
/// Minimum Ethernet frame the chip hands up (`ETH_ZLEN`); a
/// shorter length field means the aggregation stream is corrupt
/// or exhausted — stop the walk.
pub const RX_MIN_FRAME: u32 = 60;

/// `tx_desc.opts1` first-segment bit.
pub const TX_FS: u32 = 1 << 31;
/// `tx_desc.opts1` last-segment bit.
pub const TX_LS: u32 = 1 << 30;
/// `tx_desc.opts1` length mask / maximum.
pub const TX_LEN_MASK: u32 = 0x3FFFF;

/// RX aggregation buffer posted on bulk IN. Covers the RTL8153
/// 9 KiB max frame plus aggregation slack; the FE generation's
/// frames are ≤ 1522 bytes so several aggregate per transfer.
pub const RX_BUF_LEN: usize = 16 * 1024;

// ── Pure SETUP-packet packing (fixture-pinned) ───────────────────

/// SETUP fields for an OCP register read:
/// `(bmRequestType, bRequest, wValue, wIndex)`.
pub fn ocp_read_setup(mcu: u16, addr: u16) -> (u8, u8, u16, u16) {
    (REQT_READ, REQ_GET_REGS, addr, mcu)
}

/// SETUP fields + data-stage bytes for an OCP dword write:
/// `(bmRequestType, bRequest, wValue, wIndex, data)`. `wValue` is
/// the (already 4-aligned) register address; `wIndex` is the MCU
/// window OR'd with the dword byte-enable.
pub fn ocp_write_dword_pack(mcu: u16, addr: u16, value: u32) -> (u8, u8, u16, u16, [u8; 4]) {
    (
        REQT_WRITE,
        REQ_SET_REGS,
        addr,
        mcu | BYTE_EN_DWORD,
        value.to_le_bytes(),
    )
}

/// SETUP fields + data-stage bytes for an OCP word write. The
/// address is aligned down to a dword; the value is placed in its
/// byte lanes and the word byte-enable is shifted to match.
pub fn ocp_write_word_pack(mcu: u16, addr: u16, value: u16) -> (u8, u8, u16, u16, [u8; 4]) {
    let shift = addr & 2;
    let packed = (value as u32) << (shift * 8);
    (
        REQT_WRITE,
        REQ_SET_REGS,
        addr & !3,
        mcu | (BYTE_EN_WORD << shift),
        packed.to_le_bytes(),
    )
}

/// SETUP fields + data-stage bytes for an OCP byte write.
pub fn ocp_write_byte_pack(mcu: u16, addr: u16, value: u8) -> (u8, u8, u16, u16, [u8; 4]) {
    let shift = addr & 3;
    let packed = (value as u32) << (shift * 8);
    (
        REQT_WRITE,
        REQ_SET_REGS,
        addr & !3,
        mcu | (BYTE_EN_BYTE << shift),
        packed.to_le_bytes(),
    )
}

// ── OCP accessors over the USB core device handle ────────────────

/// Read `out.len()` bytes (multiple of 4) at 4-aligned `addr` from
/// the `mcu` window, in ≤ 64-byte control transfers.
async fn ocp_read(dev: &USBDevice, mcu: u16, addr: u16, out: &mut [u8]) -> Result<(), ()> {
    if addr & 3 != 0 || out.len() % 4 != 0 || out.is_empty() {
        return Err(());
    }
    let (rt, req, _, _) = ocp_read_setup(mcu, addr);
    let mut off = 0usize;
    while off < out.len() {
        let chunk = core::cmp::min(OCP_READ_CHUNK, out.len() - off);
        let wvalue = addr.wrapping_add(off as u16);
        dev.control_in(rt, req, wvalue, mcu, &mut out[off..off + chunk])
            .await
            .map_err(|_| ())?;
        off += chunk;
    }
    Ok(())
}

async fn ocp_read_dword(dev: &USBDevice, mcu: u16, addr: u16) -> Result<u32, ()> {
    let mut buf = [0u8; 4];
    ocp_read(dev, mcu, addr, &mut buf).await?;
    Ok(u32::from_le_bytes(buf))
}

/// Word read: plain dword fetch, word extracted locally (the
/// reference model passes no byte-enable for reads — byte-enables
/// appear only in write `wIndex` values).
async fn ocp_read_word(dev: &USBDevice, mcu: u16, addr: u16) -> Result<u16, ()> {
    let shift = addr & 2;
    let (rt, req, _, _) = ocp_read_setup(mcu, addr);
    let mut buf = [0u8; 4];
    dev.control_in(rt, req, addr & !3, mcu, &mut buf)
        .await
        .map_err(|_| ())?;
    Ok((u32::from_le_bytes(buf) >> (shift * 8)) as u16)
}

/// Byte read: plain dword fetch, byte extracted locally (the
/// reference model passes no byte-enable for byte reads).
async fn ocp_read_byte(dev: &USBDevice, mcu: u16, addr: u16) -> Result<u8, ()> {
    let shift = addr & 3;
    let (rt, req, _, _) = ocp_read_setup(mcu, addr);
    let mut buf = [0u8; 4];
    dev.control_in(rt, req, addr & !3, mcu, &mut buf)
        .await
        .map_err(|_| ())?;
    Ok((u32::from_le_bytes(buf) >> (shift * 8)) as u8)
}

async fn ocp_write_dword(dev: &USBDevice, mcu: u16, addr: u16, value: u32) -> Result<(), ()> {
    let (rt, req, wvalue, windex, data) = ocp_write_dword_pack(mcu, addr, value);
    dev.control_out(rt, req, wvalue, windex, &data)
        .await
        .map_err(|_| ())?;
    Ok(())
}

async fn ocp_write_word(dev: &USBDevice, mcu: u16, addr: u16, value: u16) -> Result<(), ()> {
    let (rt, req, wvalue, windex, data) = ocp_write_word_pack(mcu, addr, value);
    dev.control_out(rt, req, wvalue, windex, &data)
        .await
        .map_err(|_| ())?;
    Ok(())
}

async fn ocp_write_byte(dev: &USBDevice, mcu: u16, addr: u16, value: u8) -> Result<(), ()> {
    let (rt, req, wvalue, windex, data) = ocp_write_byte_pack(mcu, addr, value);
    dev.control_out(rt, req, wvalue, windex, &data)
        .await
        .map_err(|_| ())?;
    Ok(())
}

// ── Per-chip-version PHY init (issue #881) ───────────────────────
//
// Linux `drivers/net/usb/r8152.c` switches its PHY/firmware init on
// the `PLA_TCR1` version field (the high half of the `PLA_TCR0`
// dword Linux reads). The datapath runs on reset defaults without
// this layer; the tables below reproduce Linux's per-family
// `*_hw_phy_cfg` sequences for every known version —
// `r8152b_hw_phy_cfg` (VER_01/02/07), `r8153_hw_phy_cfg`
// (VER_03–VER_06), `r8153b_hw_phy_cfg` (VER_08/09),
// `r8153c_hw_phy_cfg` (VER_14, which is `r8153b_hw_phy_cfg` plus a
// driver-internal flag with no wire effect), `r8156_hw_phy_cfg`
// (VER_10/11), `r8156b_hw_phy_cfg` (VER_12/13/15) and
// `r8157_hw_phy_cfg` (VER_16/17) — in Linux's order, with the
// firmware-blob step (`rtl8152_apply_firmware`) as an
// [`PhyInitOp::ApplyFirmware`] step at Linux's position in each
// sequence (see the firmware section below). TEST_01 and unknown
// versions keep reset defaults. Every table entry is grounded in
// the Linux source; no chip version is on hand in this VM, so
// only the silicon itself remains untested (fixture-validated
// end-to-end, per #1255's symptom-led rule).

/// Chip version, decoded from the `PLA_TCR1` version field.
/// Names follow Linux's `rtl_version` enum.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RtlVersion {
    Unknown,
    Ver01,
    Ver02,
    Ver03,
    Ver04,
    Ver05,
    Ver06,
    Ver07,
    Ver08,
    Ver09,
    Test01,
    Ver10,
    Ver11,
    Ver12,
    Ver13,
    Ver14,
    Ver15,
    Ver16,
    Ver17,
}

/// Decode a raw `PLA_TCR1` word into its chip version (the
/// version-field mask is applied here, so callers pass the raw
/// register word). The code table is Linux's
/// `__rtl_get_hw_ver` switch, verbatim.
pub fn version_from_tcr1(raw: u16) -> RtlVersion {
    match raw & TCR1_VERSION_MASK {
        0x4C00 => RtlVersion::Ver01,
        0x4C10 => RtlVersion::Ver02,
        0x5C00 => RtlVersion::Ver03,
        0x5C10 => RtlVersion::Ver04,
        0x5C20 => RtlVersion::Ver05,
        0x5C30 => RtlVersion::Ver06,
        0x4800 => RtlVersion::Ver07,
        0x6000 => RtlVersion::Ver08,
        0x6010 => RtlVersion::Ver09,
        0x7010 => RtlVersion::Test01,
        0x7020 => RtlVersion::Ver10,
        0x7030 => RtlVersion::Ver11,
        0x7400 => RtlVersion::Ver12,
        0x7410 => RtlVersion::Ver13,
        0x6400 => RtlVersion::Ver14,
        0x7420 => RtlVersion::Ver15,
        0x1030 => RtlVersion::Ver16,
        0x2020 => RtlVersion::Ver17,
        _ => RtlVersion::Unknown,
    }
}

/// How the firmware step decides `power_cut` (Linux
/// `rtl8152_apply_firmware(tp, power_cut)`), per family. The
/// status-gated modes read `OCP_PHY_STATUS` at the step, exactly
/// where Linux's `r8153_phy_status(tp, 0)` call sits in each
/// `*_hw_phy_cfg`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FirmwarePowerCut {
    /// Always `power_cut = false` (Linux `r8152b_hw_phy_cfg` and
    /// `r8153_hw_phy_cfg`).
    Never,
    /// `power_cut = true` when the PHY status is PWRDN or
    /// EXT_INIT (Linux `r8153b_hw_phy_cfg` / `r8153c_hw_phy_cfg`);
    /// after a power-cut application the BMCR power-down bit is
    /// cleared.
    OnPwrdnOrExtInit,
    /// `power_cut = true` only when the PHY status is EXT_INIT
    /// (Linux `r8156_hw_phy_cfg`, `r8156b_hw_phy_cfg`,
    /// `r8157_hw_phy_cfg`); after a power-cut application the
    /// `0xa468` bits 3|1 are cleared, plus `0xa466` bit 0 when
    /// `clear_a466` is set (`r8156b` / `r8157` only).
    OnExtInit { clear_a466: bool },
}

/// One step of a version-switched PHY init sequence, in the order
/// Linux executes it. The executor below interprets each step
/// through the existing OCP accessors; the table itself is pure
/// data, so fixtures can pin the whole register conversation
/// without hardware.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyInitOp {
    /// OCP PHY-register set-bits (read-modify-write via the
    /// `PLA_OCP_GPHY_BASE` window).
    OcpRegSetBits { addr: u16, bits: u16 },
    /// OCP PHY-register clear-bits.
    OcpRegClrBits { addr: u16, bits: u16 },
    /// OCP PHY-register plain write.
    OcpRegWrite { addr: u16, value: u16 },
    /// SRAM write: `OCP_SRAM_ADDR := addr`, then
    /// `OCP_SRAM_DATA := value`.
    SramWrite { addr: u16, value: u16 },
    /// PLA word set-bits (read-modify-write).
    PlaWordSetBits { addr: u16, bits: u16 },
    /// PLA word clear-bits.
    PlaWordClrBits { addr: u16, bits: u16 },
    /// PLA word plain write.
    PlaWordWrite { addr: u16, value: u16 },
    /// USB-window word set-bits.
    UsbWordSetBits { addr: u16, bits: u16 },
    /// MDIO set-bits via `OCP_BASE_MII + reg * 2`.
    MdioSetBits { reg: u16, bits: u16 },
    /// USB-window word clear-bits.
    UsbWordClrBits { addr: u16, bits: u16 },
    /// USB-window word plain write.
    UsbWordWrite { addr: u16, value: u16 },
    /// USB-window byte set-bits.
    UsbByteSetBits { addr: u16, bits: u8 },
    /// USB-window byte clear-bits.
    UsbByteClrBits { addr: u16, bits: u8 },
    /// USB-window byte plain write.
    UsbByteWrite { addr: u16, value: u8 },
    /// USB-window dword plain write.
    UsbDwordWrite { addr: u16, value: u32 },
    /// PLA byte set-bits.
    PlaByteSetBits { addr: u16, bits: u8 },
    /// PLA byte clear-bits.
    PlaByteClrBits { addr: u16, bits: u8 },
    /// PLA byte plain write.
    PlaByteWrite { addr: u16, value: u8 },
    /// MDIO clear-bits via `OCP_BASE_MII + reg * 2`.
    MdioClrBits { reg: u16, bits: u16 },
    /// Autoload poll: `PLA_BOOT_CTRL` for `AUTOLOAD_DONE`
    /// (proceeds even if the poll never completes, like the
    /// reset poll in bind).
    AutoloadPoll,
    /// PHY-status poll accepting LAN_ON / PWRDN / EXT_INIT
    /// (Linux `r8153_phy_status(tp, 0)`).
    PhyStatusPollAny,
    /// PHY-status poll accepting exactly LAN_ON
    /// (Linux `r8153_phy_status(tp, PHY_STAT_LAN_ON)`).
    PhyStatusPollLanOn,
    /// ALDPS disable: `OCP_POWER_CFG` clear `EN_ALDPS`, then poll
    /// `PLA_ALDPS_POLL` for `ALDPS_POLL_DONE` (proceeds even if
    /// the poll never completes, like the reset poll in bind).
    AldpsDisable,
    /// OCP PHY-register clear-then-set (Linux `ocp_reg_w0w1`):
    /// read, `(cur & !clear) | set`, write.
    OcpRegW0W1 { addr: u16, clear: u16, set: u16 },
    /// SRAM read-modify-write (Linux `sram_write_w0w1`): read the
    /// cell, `(cur & !clear) | set`, write the data register.
    SramW0W1 { addr: u16, clear: u16, set: u16 },
    /// Second SRAM bank read-modify-write (Linux
    /// `sram2_write_w0w1`).
    Sram2W0W1 { addr: u16, clear: u16, set: u16 },
    /// Second SRAM bank write: `OCP_SRAM2_ADDR := addr`, then
    /// `OCP_SRAM2_DATA := value` (Linux `sram2_write`).
    Sram2Write { addr: u16, value: u16 },
    /// SRAM address register alone (Linux `ocp_reg_write(tp,
    /// OCP_SRAM_ADDR, addr)`): starts a burst of data writes.
    SramAddrWrite { addr: u16 },
    /// SRAM data register alone (Linux `ocp_reg_write(tp,
    /// OCP_SRAM_DATA, value)`): one burst word, address already
    /// set (auto-increments on the chip).
    SramDataWrite { value: u16 },
    /// Second SRAM bank address register alone (Linux
    /// `ocp_reg_write(tp, OCP_SRAM2_ADDR, addr)`).
    Sram2AddrWrite { addr: u16 },
    /// Second SRAM bank data register alone (Linux
    /// `ocp_reg_write(tp, OCP_SRAM2_DATA, value)`).
    Sram2DataWrite { value: u16 },
    /// USB-window word test-and-clear (Linux
    /// `ocp_word_test_and_clr_bits`): read, write back cleared
    /// only when any of `bits` is set.
    UsbWordTestAndClrBits { addr: u16, bits: u16 },
    /// MDIO test-and-clear via `OCP_BASE_MII + reg * 2` (Linux
    /// `r8152_mdio_test_and_clr_bit`).
    MdioTestAndClrBits { reg: u16, bits: u16 },
    /// MMD indirect write (Linux `r8152_mmd_write`): select the
    /// device/register through `OCP_EEE_AR` / `OCP_EEE_DATA`,
    /// write the value, deselect.
    MmdWrite { dev: u16, reg: u16, value: u16 },
    /// Firmware-blob step (Linux `rtl8152_apply_firmware`) at
    /// this position in the sequence, with the family's
    /// `power_cut` rule. A missing blob is a no-op (Linux's
    /// failed `request_firmware`: warn and continue); a blob
    /// that fails validation is logged and skipped, never a
    /// bind failure.
    ApplyFirmware { mode: FirmwarePowerCut },
    /// PHY patch request/release (Linux
    /// `rtl_phy_patch_request`): set (or clear) `PATCH_REQUEST`
    /// in `OCP_PHY_PATCH_CMD` and wait for `PATCH_READY` to
    /// set (or clear). A failed *request* aborts the rest of
    /// the sequence — Linux returns from `*_hw_phy_cfg` on it —
    /// so the executor marks the run aborted and later steps
    /// become no-ops.
    PhyPatchRequest { request: bool },
    /// Flash-load wait (Linux `r8156b_wait_loading_flash`):
    /// when `PLA_GPHY_CTRL` says the PHY boots from flash and
    /// `USB_GPHY_CTRL` does not bypass it, poll for
    /// `GPHY_PATCH_DONE` (best-effort).
    WaitLoadingFlash,
    /// ADC bias calibration from efuse (Linux
    /// `r8153b_hw_phy_cfg`): read efuse offset `0x7d`, drop the
    /// dummy bit, write the rebuilt value to `OCP_ADC_IOFFSET`
    /// unless it is `0xffff`.
    AdcBiasFromEfuse,
    /// UPS-mode TX link-pulse timing (Linux
    /// `r8153b_hw_phy_cfg`): read the sawtooth count at OCP
    /// `0xc426`, derive the 1 ms counter and program
    /// `USB_UPS_CFG` — skipped when the count reads zero.
    UpsTimingFromSawCnt,
    /// MDI pair swap when the board is reversed (Linux
    /// `r8156_hw_phy_cfg` VER_11): when `USB_UPS_CFG` reports
    /// `MID_REVERSE` and OCP `0xd068` bit 1 is set, swap the
    /// p0/p3 and p1/p2 lanes plus the `0xbd5a`/`0xbd5c` and
    /// `0xbc18`/`0xbc1a` pairs.
    MdiSwapIfReversed,
}

/// EEE-disable steps shared by the VER_03–VER_06 / VER_08 / VER_09 /
/// VER_14 sequences (Linux `r8153_eee_en(tp, false)` plus the
/// `OCP_EEE_ADV := 0` write in `rtl_eee_enable`).
fn eee_disable_ops_8153() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    vec![
        PlaWordClrBits {
            addr: PLA_EEE_CR,
            bits: EEE_CR_RX_EN | EEE_CR_TX_EN,
        },
        OcpRegClrBits {
            addr: OCP_EEE_CFG,
            bits: EEE_CFG_EEE10_EN,
        },
        OcpRegWrite {
            addr: OCP_EEE_ADV,
            value: 0,
        },
    ]
}

/// EEE-enable steps shared by the VER_03–VER_06 / VER_08 / VER_09 /
/// VER_14 sequences (Linux `r8153_eee_en(tp, true)` plus the
/// `OCP_EEE_ADV := eee_adv` write). `adv` is the family's
/// `eee_adv` (Linux `rtl_ops_init`).
fn eee_enable_ops_8153(adv: u16) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    vec![
        PlaWordSetBits {
            addr: PLA_EEE_CR,
            bits: EEE_CR_RX_EN | EEE_CR_TX_EN,
        },
        OcpRegSetBits {
            addr: OCP_EEE_CFG,
            bits: EEE_CFG_EEE10_EN,
        },
        OcpRegWrite {
            addr: OCP_EEE_ADV,
            value: adv,
        },
    ]
}

/// EEE-disable steps shared by the VER_10–VER_13 / VER_15–VER_17
/// sequences (Linux `r8156_eee_en(tp, false)` plus the
/// `OCP_EEE_ADV := 0` write).
fn eee_disable_ops_8156() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = eee_disable_ops_8153();
    ops.push(OcpRegW0W1 {
        addr: OCP_EEE_ADV2,
        clear: MDIO_EEE_2_5GT | MDIO_EEE_5GT,
        set: 0,
    });
    ops
}

/// EEE-enable steps shared by the VER_10–VER_13 / VER_15–VER_17
/// sequences (Linux `r8156_eee_en(tp, true)` plus the
/// `OCP_EEE_ADV := eee_adv` write). `adv` is the family's
/// `eee_adv`, `adv2` its `eee_adv2` (Linux `rtl_ops_init`).
fn eee_enable_ops_8156(adv: u16, adv2: u16) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = eee_enable_ops_8153(adv);
    ops.push(OcpRegW0W1 {
        addr: OCP_EEE_ADV2,
        clear: (MDIO_EEE_2_5GT | MDIO_EEE_5GT) & !adv2,
        set: adv2,
    });
    ops
}

/// Flow-control advertisement (Linux `r8152b_enable_fc`).
fn enable_fc_op() -> PhyInitOp {
    PhyInitOp::MdioSetBits {
        reg: MII_ADVERTISE,
        bits: ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM,
    }
}

/// ALDPS re-enable (Linux `r8153_aldps_en(tp, true)`).
fn aldps_enable_op() -> PhyInitOp {
    PhyInitOp::OcpRegSetBits {
        addr: OCP_POWER_CFG,
        bits: POWER_CFG_EN_ALDPS,
    }
}

/// The `r8152b_hw_phy_cfg` sequence for the RTL8152 family
/// (VER_01/02/07), in Linux's order: firmware first (no file
/// exists for these versions, so the step is a no-op in Linux),
/// then EEE enable (`r8152_eee_en` + MMD advertisement),
/// ALDPS enable (`r8152_aldps_en`) and flow control.
fn phy_init_ops_8152b() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    vec![
        ApplyFirmware {
            mode: FirmwarePowerCut::Never,
        },
        // EEE enable (Linux: eee_en is true for VER_01/02/07).
        PlaWordSetBits {
            addr: PLA_EEE_CR,
            bits: EEE_CR_RX_EN | EEE_CR_TX_EN,
        },
        OcpRegW0W1 {
            addr: OCP_EEE_CONFIG1,
            clear: EEE_SD_RISE_TIME_MASK,
            set: EEE_10_CAP | EEE_NWAY_EN | EEE_TX_QUIET_EN | EEE_RX_QUIET_EN | EEE_SD_RISE_TIME_1,
        },
        OcpRegSetBits {
            addr: OCP_EEE_CONFIG2,
            bits: EEE_RG_DACQUIET_EN | EEE_RG_LDVQUIET_EN,
        },
        OcpRegW0W1 {
            addr: OCP_EEE_CONFIG3,
            clear: EEE_FAST_SNR_MASK,
            set: EEE_FAST_SNR_42,
        },
        MmdWrite {
            dev: MDIO_MMD_AN,
            reg: MDIO_AN_EEE_ADV,
            value: EEE_ADV_8152,
        },
        // ALDPS enable (r8152_aldps_en writes the whole config word).
        OcpRegWrite {
            addr: OCP_ALDPS_CONFIG,
            value: ALDPS_CFG_8152_ENABLE,
        },
        enable_fc_op(),
    ]
}

/// The `r8153_hw_phy_cfg` sequence for the original RTL8153
/// family, in Linux's order. Version gates inside the sequence:
/// `CTAP_SHORT_EN` clears only on VER_03; the U2P3 enable lands
/// only on VER_05/VER_06 (Linux enables it for VER_05/VER_06/
/// default and skips VER_03/VER_04).
fn phy_init_ops_8153(version: RtlVersion) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        // Disable ALDPS before updating the PHY parameters.
        AldpsDisable,
    ];
    ops.extend(eee_disable_ops_8153());
    ops.push(ApplyFirmware {
        mode: FirmwarePowerCut::Never,
    });
    ops.extend([
        OcpRegSetBits {
            addr: OCP_POWER_CFG,
            bits: POWER_CFG_EEE_CLKDIV_EN,
        },
        OcpRegSetBits {
            addr: OCP_DOWN_SPEED,
            bits: DOWN_SPEED_EN_10M_BGOFF,
        },
        OcpRegSetBits {
            addr: OCP_POWER_CFG,
            bits: POWER_CFG_EN_10M_PLLOFF,
        },
        SramWrite {
            addr: SRAM_IMPEDANCE,
            value: 0x0B13,
        },
        PlaWordSetBits {
            addr: PLA_PHY_PWR,
            bits: PHY_PWR_PFM_PWM_SWITCH,
        },
        // Enable LPF corner auto tune.
        SramWrite {
            addr: SRAM_LPF_CFG,
            value: 0xF70F,
        },
        // Adjust 10M amplitude.
        SramWrite {
            addr: SRAM_10M_AMP1,
            value: 0x00AF,
        },
        SramWrite {
            addr: SRAM_10M_AMP2,
            value: 0x0208,
        },
    ]);
    // Re-enable EEE (Linux: eee_en is true for VER_03–VER_06).
    ops.extend(eee_enable_ops_8153(EEE_ADV_8153));
    ops.push(aldps_enable_op());
    ops.push(enable_fc_op());
    if version == RtlVersion::Ver03 {
        // VER_03 only: clear CTAP_SHORT_EN, immediately after the
        // firmware step (Linux's position in the sequence).
        ops.insert(
            5,
            OcpRegClrBits {
                addr: OCP_EEE_CFG,
                bits: EEE_CFG_CTAP_SHORT_EN,
            },
        );
    }
    if version == RtlVersion::Ver05 || version == RtlVersion::Ver06 {
        ops.push(UsbWordSetBits {
            addr: USB_U2P3_CTRL,
            bits: U2P3_ENABLE,
        });
    }
    ops
}

/// The `r8153b_hw_phy_cfg` sequence for the RTL8153B family
/// (VER_08/09) and, through `r8153c_hw_phy_cfg`, VER_14 — the
/// latter only sets a driver-internal flag (`ups_info.r_tune`)
/// after calling this sequence, which has no wire effect, so
/// both share this table. In Linux's order.
fn phy_init_ops_8153b() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        UsbWordTestAndClrBits {
            addr: USB_MISC_0,
            bits: PCUT_STATUS,
        },
        // Disable ALDPS before updating the PHY parameters.
        AldpsDisable,
    ];
    ops.extend(eee_disable_ops_8153());
    ops.extend([
        // U1/U2/L1 idle timer. 500 us.
        UsbWordWrite {
            addr: USB_U1U2_TIMER,
            value: 500,
        },
        ApplyFirmware {
            mode: FirmwarePowerCut::OnPwrdnOrExtInit,
        },
    ]);
    // Green ethernet (Linux: GREEN_ETHERNET is set in
    // r8153b_init / r8153c_init, so always enabled here).
    ops.extend([
        SramWrite {
            addr: 0x8045,
            value: 0,
        },
        SramWrite {
            addr: 0x804D,
            value: 0x1222,
        },
        SramWrite {
            addr: 0x805D,
            value: 0x0022,
        },
        SramW0W1 {
            addr: SRAM_GREEN_CFG,
            clear: 0,
            set: GREEN_ETH_EN,
        },
        SramW0W1 {
            addr: SRAM_GREEN_CFG,
            clear: 0,
            set: GREEN_CFG_R_TUNE_EN,
        },
        OcpRegSetBits {
            addr: OCP_NCTL_CFG,
            bits: NCTL_CFG_PGA_RETURN_EN,
        },
        AdcBiasFromEfuse,
        UpsTimingFromSawCnt,
        PlaWordSetBits {
            addr: PLA_PHY_PWR,
            bits: PHY_PWR_PFM_PWM_SWITCH,
        },
        // Advance EEE, gated on the PHY patch request.
        PhyPatchRequest { request: true },
        OcpRegSetBits {
            addr: OCP_POWER_CFG,
            bits: POWER_CFG_EEE_CLKDIV_EN,
        },
        OcpRegSetBits {
            addr: OCP_DOWN_SPEED,
            bits: DOWN_SPEED_EN_EEE_CMODE | DOWN_SPEED_EN_EEE_1000 | DOWN_SPEED_EN_10M_CLKDIV,
        },
        OcpRegWrite {
            addr: OCP_SYSCLK_CFG,
            value: 0,
        },
        OcpRegWrite {
            addr: OCP_SYSCLK_CFG,
            value: CLK_DIV_EXPO_5,
        },
        PhyPatchRequest { request: false },
    ]);
    // Re-enable EEE (Linux: eee_en is true for VER_08/09/14).
    ops.extend(eee_enable_ops_8153(EEE_ADV_8153));
    ops.push(aldps_enable_op());
    ops.push(enable_fc_op());
    ops
}

/// Shared prefix of `r8156_hw_phy_cfg` (VER_10/11): power-cut
/// clear, firmware step, ALDPS/EEE disable, LAN_ON poll, PHY
/// power switch.
fn phy_init_ops_8156_prefix() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        UsbWordTestAndClrBits {
            addr: USB_MISC_0,
            bits: PCUT_STATUS,
        },
        ApplyFirmware {
            mode: FirmwarePowerCut::OnExtInit { clear_a466: false },
        },
        // Disable ALDPS before updating the PHY parameters.
        AldpsDisable,
    ];
    ops.extend(eee_disable_ops_8156());
    ops.extend([
        PhyStatusPollLanOn,
        PlaWordSetBits {
            addr: PLA_PHY_PWR,
            bits: PHY_PWR_PFM_PWM_SWITCH,
        },
    ]);
    ops
}

/// Shared tail of `r8156_hw_phy_cfg` (VER_10/11): green mode,
/// lite-mode clears, EEE re-enable (only when `eee_en` — true
/// for VER_11, false for VER_10), ALDPS, flow control, U2P3.
fn phy_init_ops_8156_tail(eee_en: bool, adv: u16, adv2: u16) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        SramW0W1 {
            addr: SRAM_GREEN_CFG,
            clear: 0,
            set: GREEN_ETH_EN,
        },
        OcpRegClrBits {
            addr: 0xA428,
            bits: 0x0200,
        },
        OcpRegClrBits {
            addr: 0xA5EA,
            bits: 0x0001,
        },
    ];
    if eee_en {
        ops.extend(eee_enable_ops_8156(adv, adv2));
    }
    ops.push(aldps_enable_op());
    ops.push(enable_fc_op());
    ops.push(UsbWordSetBits {
        addr: USB_U2P3_CTRL,
        bits: U2P3_ENABLE,
    });
    ops
}

/// The `r8156_hw_phy_cfg` sequence for the RTL8156 family
/// (VER_10/11), in Linux's order.
fn phy_init_ops_8156(version: RtlVersion) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = phy_init_ops_8156_prefix();
    match version {
        RtlVersion::Ver10 => {
            ops.extend([
                OcpRegW0W1 {
                    addr: 0xAD40,
                    clear: 0x03FF,
                    set: 0x0084,
                },
                OcpRegSetBits {
                    addr: 0xAD4E,
                    bits: 0x0010,
                },
                OcpRegW0W1 {
                    addr: 0xAD16,
                    clear: 0x03FF,
                    set: 0x0006,
                },
                OcpRegW0W1 {
                    addr: 0xAD32,
                    clear: 0x003F,
                    set: 0x0006,
                },
                OcpRegClrBits {
                    addr: 0xAC08,
                    bits: 0x1100,
                },
                OcpRegW0W1 {
                    addr: 0xAC8A,
                    clear: 0x8000,
                    set: 0x7000,
                },
                OcpRegSetBits {
                    addr: 0xAD18,
                    bits: 0x0400,
                },
                OcpRegSetBits {
                    addr: 0xAD1A,
                    bits: 0x03FF,
                },
                OcpRegSetBits {
                    addr: 0xAD1C,
                    bits: 0x03FF,
                },
                SramW0W1 {
                    addr: 0x80EA,
                    clear: 0xFF00,
                    set: 0xC400,
                },
                SramW0W1 {
                    addr: 0x80EB,
                    clear: 0x0700,
                    set: 0x0300,
                },
                SramW0W1 {
                    addr: 0x80F8,
                    clear: 0xFF00,
                    set: 0x1C00,
                },
                SramW0W1 {
                    addr: 0x80F1,
                    clear: 0xFF00,
                    set: 0x3000,
                },
                SramW0W1 {
                    addr: 0x80FE,
                    clear: 0xFF00,
                    set: 0xA500,
                },
                SramW0W1 {
                    addr: 0x8102,
                    clear: 0xFF00,
                    set: 0x5000,
                },
                SramW0W1 {
                    addr: 0x8015,
                    clear: 0xFF00,
                    set: 0x3300,
                },
                SramW0W1 {
                    addr: 0x8100,
                    clear: 0xFF00,
                    set: 0x7000,
                },
                SramW0W1 {
                    addr: 0x8014,
                    clear: 0xFF00,
                    set: 0xF000,
                },
                SramW0W1 {
                    addr: 0x8016,
                    clear: 0xFF00,
                    set: 0x6500,
                },
                SramW0W1 {
                    addr: 0x80DC,
                    clear: 0xFF00,
                    set: 0xED00,
                },
                SramW0W1 {
                    addr: 0x80DF,
                    clear: 0,
                    set: 0x0100,
                },
                SramW0W1 {
                    addr: 0x80E1,
                    clear: 0x0100,
                    set: 0,
                },
                OcpRegW0W1 {
                    addr: 0xBF06,
                    clear: 0x003F,
                    set: 0x0038,
                },
                SramWrite {
                    addr: 0x819F,
                    value: 0xDDB6,
                },
                OcpRegWrite {
                    addr: 0xBC34,
                    value: 0x5555,
                },
                OcpRegW0W1 {
                    addr: 0xBF0A,
                    clear: 0x0E00,
                    set: 0x0A00,
                },
                OcpRegClrBits {
                    addr: 0xBD2C,
                    bits: 0x2000,
                },
            ]);
        }
        RtlVersion::Ver11 => {
            ops.extend([
                OcpRegSetBits {
                    addr: 0xAD16,
                    bits: 0x03FF,
                },
                OcpRegW0W1 {
                    addr: 0xAD32,
                    clear: 0x003F,
                    set: 0x0006,
                },
                OcpRegClrBits {
                    addr: 0xAC08,
                    bits: 0x1100,
                },
                OcpRegW0W1 {
                    addr: 0xACC0,
                    clear: 0x0003,
                    set: 0x0002,
                },
                OcpRegW0W1 {
                    addr: 0xAD40,
                    clear: 0x00E7,
                    set: 0x0044,
                },
                OcpRegClrBits {
                    addr: 0xAC14,
                    bits: 0x0080,
                },
                OcpRegClrBits {
                    addr: 0xAC80,
                    bits: 0x0300,
                },
                OcpRegW0W1 {
                    addr: 0xAC5E,
                    clear: 0x0007,
                    set: 0x0002,
                },
                OcpRegWrite {
                    addr: 0xAD4C,
                    value: 0x00A8,
                },
                OcpRegWrite {
                    addr: 0xAC5C,
                    value: 0x01FF,
                },
                OcpRegW0W1 {
                    addr: 0xAC8A,
                    clear: 0x00F0,
                    set: 0x0030,
                },
                Sram2W0W1 {
                    addr: 0x8157,
                    clear: 0xFF00,
                    set: 0x0500,
                },
                Sram2W0W1 {
                    addr: 0x8159,
                    clear: 0xFF00,
                    set: 0x0700,
                },
                // AAGC.
                Sram2Write {
                    addr: 0x80A2,
                    value: 0x0153,
                },
                Sram2Write {
                    addr: 0x809C,
                    value: 0x0153,
                },
                // EEE parameter.
                PlaWordWrite {
                    addr: PLA_EEE_TXTWSYS_2P5G,
                    value: 0x0056,
                },
                PlaWordSetBits {
                    addr: PLA_USB_CFG,
                    bits: USB_CFG_EN_XG_LIP | USB_CFG_EN_G_LIP,
                },
                // XG PLL.
                SramWrite {
                    addr: 0x8257,
                    value: 0x020F,
                },
                // GIGA Master.
                SramWrite {
                    addr: 0x80EA,
                    value: 0x7843,
                },
                // Advance EEE, gated on the PHY patch request.
                PhyPatchRequest { request: true },
                PlaWordSetBits {
                    addr: PLA_MAC_PWR_CTRL4,
                    bits: MAC_PWR_CTRL4_EEE_SPDWN_EN,
                },
                OcpRegW0W1 {
                    addr: OCP_DOWN_SPEED,
                    clear: DOWN_SPEED_EN_EEE_100 | DOWN_SPEED_EN_EEE_1000,
                    set: DOWN_SPEED_EN_10M_CLKDIV,
                },
                OcpRegClrBits {
                    addr: OCP_POWER_CFG,
                    bits: POWER_CFG_EEE_CLKDIV_EN,
                },
                OcpRegWrite {
                    addr: OCP_SYSCLK_CFG,
                    value: 0,
                },
                OcpRegWrite {
                    addr: OCP_SYSCLK_CFG,
                    value: SYSCLK_DIV_EXPO_5,
                },
                PhyPatchRequest { request: false },
                // Enable ADC Ibias Cal.
                OcpRegSetBits {
                    addr: 0xD068,
                    bits: 0x2000,
                },
                // Enable Thermal Sensor.
                SramW0W1 {
                    addr: 0x81A2,
                    clear: 0x0100,
                    set: 0,
                },
                OcpRegW0W1 {
                    addr: 0xB54C,
                    clear: 0xFF00,
                    set: 0xDB00,
                },
                // Nway 2.5G Lite.
                OcpRegClrBits {
                    addr: 0xA454,
                    bits: 0x0001,
                },
                // CS DSP solution.
                OcpRegSetBits {
                    addr: OCP_10GBT_CTRL,
                    bits: CTRL_10GBT_ADV2_5G_F_R,
                },
                OcpRegClrBits {
                    addr: 0xAD4E,
                    bits: 0x0010,
                },
                OcpRegClrBits {
                    addr: 0xA86A,
                    bits: 0x0001,
                },
                MdiSwapIfReversed,
                // Notify the MAC when the speed is changed to force mode.
                OcpRegSetBits {
                    addr: OCP_INTR_EN,
                    bits: INTR_EN_SPEED_FORCE,
                },
            ]);
        }
        _ => {}
    }
    // VER_10: eee_en is false in Linux (zero-initialised);
    // VER_11: eee_en is true, eee_adv 0x0006, eee_adv2 2.5GT.
    let (eee_en, adv, adv2) = match version {
        RtlVersion::Ver11 => (true, EEE_ADV_8153, MDIO_EEE_2_5GT),
        _ => (false, EEE_ADV_8153, 0),
    };
    ops.extend(phy_init_ops_8156_tail(eee_en, adv, adv2));
    ops
}

/// Shared prefix of `r8156b_hw_phy_cfg` (VER_12/13/15) and
/// `r8157_hw_phy_cfg` (VER_16/17): power-cut clear, firmware
/// step, BMCR power-down test-and-clear, ALDPS/EEE disable,
/// LAN_ON poll, PHY power switch. `set_pfm_pwm` selects the
/// switch direction: the 8156B family sets it (PFM/PWM mode),
/// the 8157 family clears it (PFM mode).
fn phy_init_ops_8156b_prefix(clear_a466: bool, set_pfm_pwm: bool) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        UsbWordTestAndClrBits {
            addr: USB_MISC_0,
            bits: PCUT_STATUS,
        },
        ApplyFirmware {
            mode: FirmwarePowerCut::OnExtInit { clear_a466 },
        },
        MdioTestAndClrBits {
            reg: MII_BMCR,
            bits: BMCR_PDOWN,
        },
        // Disable ALDPS before updating the PHY parameters.
        AldpsDisable,
    ];
    ops.extend(eee_disable_ops_8156());
    ops.extend([
        PhyStatusPollLanOn,
        if set_pfm_pwm {
            PlaWordSetBits {
                addr: PLA_PHY_PWR,
                bits: PHY_PWR_PFM_PWM_SWITCH,
            }
        } else {
            PlaWordClrBits {
                addr: PLA_PHY_PWR,
                bits: PHY_PWR_PFM_PWM_SWITCH,
            }
        },
    ]);
    ops
}

/// Shared tail of `r8156b_hw_phy_cfg` (VER_12/13/15): force-mode
/// interrupt, patch-gated Advance EEE, green mode, lite-mode
/// clears, EEE re-enable, ALDPS, flow control, U2P3.
fn phy_init_ops_8156b_tail() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        // Notify the MAC when the speed is changed to force mode.
        OcpRegSetBits {
            addr: OCP_INTR_EN,
            bits: INTR_EN_SPEED_FORCE,
        },
        // Advance EEE, gated on the PHY patch request.
        PhyPatchRequest { request: true },
        PlaWordSetBits {
            addr: PLA_MAC_PWR_CTRL4,
            bits: MAC_PWR_CTRL4_EEE_SPDWN_EN,
        },
        OcpRegW0W1 {
            addr: OCP_DOWN_SPEED,
            clear: DOWN_SPEED_EN_EEE_100 | DOWN_SPEED_EN_EEE_1000,
            set: DOWN_SPEED_EN_10M_CLKDIV,
        },
        OcpRegClrBits {
            addr: OCP_POWER_CFG,
            bits: POWER_CFG_EEE_CLKDIV_EN,
        },
        PhyPatchRequest { request: false },
        SramW0W1 {
            addr: SRAM_GREEN_CFG,
            clear: 0,
            set: GREEN_ETH_EN,
        },
        OcpRegClrBits {
            addr: 0xA428,
            bits: 0x0200,
        },
        OcpRegClrBits {
            addr: 0xA5EA,
            bits: 0x0001,
        },
    ];
    // EEE re-enable (Linux: eee_en is true for VER_12/13/15).
    ops.extend(eee_enable_ops_8156(EEE_ADV_8153, MDIO_EEE_2_5GT));
    ops.push(aldps_enable_op());
    ops.push(enable_fc_op());
    ops.push(UsbWordSetBits {
        addr: USB_U2P3_CTRL,
        bits: U2P3_ENABLE,
    });
    ops
}

/// The `r8156b_hw_phy_cfg` sequence for the RTL8156B family
/// (VER_12/13/15), in Linux's order.
fn phy_init_ops_8156b(version: RtlVersion) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = Vec::new();
    match version {
        RtlVersion::Ver12 => {
            ops.extend([
                OcpRegWrite {
                    addr: 0xBF86,
                    value: 0x9000,
                },
                OcpRegSetBits {
                    addr: 0xC402,
                    bits: 0x0400,
                },
                OcpRegClrBits {
                    addr: 0xC402,
                    bits: 0x0400,
                },
                OcpRegWrite {
                    addr: 0xBD86,
                    value: 0x1010,
                },
                OcpRegWrite {
                    addr: 0xBD88,
                    value: 0x1010,
                },
                OcpRegW0W1 {
                    addr: 0xBD4E,
                    clear: 0x0C00,
                    set: 0x0800,
                },
                OcpRegW0W1 {
                    addr: 0xBF46,
                    clear: 0x0F00,
                    set: 0x0700,
                },
            ]);
        }
        RtlVersion::Ver13 | RtlVersion::Ver15 => {
            ops.push(WaitLoadingFlash);
        }
        _ => {}
    }
    ops.extend(phy_init_ops_8156b_prefix(true, true));
    match version {
        RtlVersion::Ver12 => {
            ops.extend([
                OcpRegSetBits {
                    addr: 0xBC08,
                    bits: 0x000C,
                },
                SramW0W1 {
                    addr: 0x8FFF,
                    clear: 0xFF00,
                    set: 0x0400,
                },
                OcpRegSetBits {
                    addr: 0xACDA,
                    bits: 0xFF00,
                },
                OcpRegSetBits {
                    addr: 0xACDE,
                    bits: 0xF000,
                },
                OcpRegWrite {
                    addr: 0xAC8C,
                    value: 0x0FFC,
                },
                OcpRegWrite {
                    addr: 0xAC46,
                    value: 0xB7B4,
                },
                OcpRegWrite {
                    addr: 0xAC50,
                    value: 0x0FBC,
                },
                OcpRegWrite {
                    addr: 0xAC3C,
                    value: 0x9240,
                },
                OcpRegWrite {
                    addr: 0xAC4E,
                    value: 0x0DB4,
                },
                OcpRegWrite {
                    addr: 0xACC6,
                    value: 0x0707,
                },
                OcpRegWrite {
                    addr: 0xACC8,
                    value: 0xA0D3,
                },
                OcpRegWrite {
                    addr: 0xAD08,
                    value: 0x0007,
                },
                Sram2Write {
                    addr: 0x8560,
                    value: 0x19CC,
                },
                Sram2Write {
                    addr: 0x8562,
                    value: 0x19CC,
                },
                Sram2Write {
                    addr: 0x8564,
                    value: 0x19CC,
                },
                Sram2Write {
                    addr: 0x8566,
                    value: 0x147D,
                },
                Sram2Write {
                    addr: 0x8568,
                    value: 0x147D,
                },
                Sram2Write {
                    addr: 0x856A,
                    value: 0x147D,
                },
                Sram2Write {
                    addr: 0x8FFE,
                    value: 0x0907,
                },
                Sram2Write {
                    addr: 0x80D6,
                    value: 0x2801,
                },
                Sram2Write {
                    addr: 0x80F2,
                    value: 0x2801,
                },
                Sram2Write {
                    addr: 0x80F4,
                    value: 0x6077,
                },
                OcpRegWrite {
                    addr: 0xB506,
                    value: 0x01E7,
                },
                Sram2Write {
                    addr: 0x8013,
                    value: 0x0700,
                },
                Sram2Write {
                    addr: 0x8FB9,
                    value: 0x2801,
                },
                Sram2Write {
                    addr: 0x8FBA,
                    value: 0x0100,
                },
                Sram2Write {
                    addr: 0x8FBC,
                    value: 0x1900,
                },
                Sram2Write {
                    addr: 0x8FBE,
                    value: 0xE100,
                },
                Sram2Write {
                    addr: 0x8FC0,
                    value: 0x0800,
                },
                Sram2Write {
                    addr: 0x8FC2,
                    value: 0xE500,
                },
                Sram2Write {
                    addr: 0x8FC4,
                    value: 0x0F00,
                },
                Sram2Write {
                    addr: 0x8FC6,
                    value: 0xF100,
                },
                Sram2Write {
                    addr: 0x8FC8,
                    value: 0x0400,
                },
                Sram2Write {
                    addr: 0x8FCA,
                    value: 0xF300,
                },
                Sram2Write {
                    addr: 0x8FCC,
                    value: 0xFD00,
                },
                Sram2Write {
                    addr: 0x8FCE,
                    value: 0xFF00,
                },
                Sram2Write {
                    addr: 0x8FD0,
                    value: 0xFB00,
                },
                Sram2Write {
                    addr: 0x8FD2,
                    value: 0x0100,
                },
                Sram2Write {
                    addr: 0x8FD4,
                    value: 0xF400,
                },
                Sram2Write {
                    addr: 0x8FD6,
                    value: 0xFF00,
                },
                Sram2Write {
                    addr: 0x8FD8,
                    value: 0xF600,
                },
                PlaByteSetBits {
                    addr: PLA_USB_CFG,
                    bits: (USB_CFG_EN_XG_LIP | USB_CFG_EN_G_LIP) as u8,
                },
                Sram2Write {
                    addr: 0x813D,
                    value: 0x390E,
                },
                Sram2Write {
                    addr: 0x814F,
                    value: 0x790E,
                },
                Sram2Write {
                    addr: 0x80B0,
                    value: 0x0F31,
                },
                OcpRegSetBits {
                    addr: 0xBF4C,
                    bits: 0x0002,
                },
                OcpRegSetBits {
                    addr: 0xBCCA,
                    bits: 0x0300,
                },
                Sram2Write {
                    addr: 0x8141,
                    value: 0x320E,
                },
                Sram2Write {
                    addr: 0x8153,
                    value: 0x720E,
                },
                Sram2Write {
                    addr: 0x8529,
                    value: 0x050E,
                },
                OcpRegClrBits {
                    addr: OCP_EEE_CFG,
                    bits: EEE_CFG_CTAP_SHORT_EN,
                },
                SramWrite {
                    addr: 0x816C,
                    value: 0xC4A0,
                },
                SramWrite {
                    addr: 0x8170,
                    value: 0xC4A0,
                },
                SramWrite {
                    addr: 0x8174,
                    value: 0x04A0,
                },
                SramWrite {
                    addr: 0x8178,
                    value: 0x04A0,
                },
                SramWrite {
                    addr: 0x817C,
                    value: 0x0719,
                },
                SramWrite {
                    addr: 0x8FF4,
                    value: 0x0400,
                },
                SramWrite {
                    addr: 0x8FF1,
                    value: 0x0404,
                },
                OcpRegWrite {
                    addr: 0xBF4A,
                    value: 0x001B,
                },
                Sram2Write {
                    addr: 0x8033,
                    value: 0x7C13,
                },
                Sram2Write {
                    addr: 0x8037,
                    value: 0x7C13,
                },
                Sram2Write {
                    addr: 0x803B,
                    value: 0xFC32,
                },
                Sram2Write {
                    addr: 0x803F,
                    value: 0x7C13,
                },
                Sram2Write {
                    addr: 0x8043,
                    value: 0x7C13,
                },
                Sram2Write {
                    addr: 0x8047,
                    value: 0x7C13,
                },
                Sram2Write {
                    addr: 0x8145,
                    value: 0x370E,
                },
                Sram2Write {
                    addr: 0x8157,
                    value: 0x770E,
                },
                Sram2Write {
                    addr: 0x8169,
                    value: 0x0D0A,
                },
                Sram2Write {
                    addr: 0x817B,
                    value: 0x1D0A,
                },
                SramW0W1 {
                    addr: 0x8217,
                    clear: 0xFF00,
                    set: 0x5000,
                },
                SramW0W1 {
                    addr: 0x821A,
                    clear: 0xFF00,
                    set: 0x5000,
                },
                SramWrite {
                    addr: 0x80DA,
                    value: 0x0403,
                },
                SramW0W1 {
                    addr: 0x80DC,
                    clear: 0xFF00,
                    set: 0x1000,
                },
                SramWrite {
                    addr: 0x80B3,
                    value: 0x0384,
                },
                SramWrite {
                    addr: 0x80B7,
                    value: 0x2007,
                },
                SramW0W1 {
                    addr: 0x80BA,
                    clear: 0xFF00,
                    set: 0x6C00,
                },
                SramWrite {
                    addr: 0x80B5,
                    value: 0xF009,
                },
                SramW0W1 {
                    addr: 0x80BD,
                    clear: 0xFF00,
                    set: 0x9F00,
                },
                SramWrite {
                    addr: 0x80C7,
                    value: 0xF083,
                },
                SramWrite {
                    addr: 0x80DD,
                    value: 0x03F0,
                },
                SramW0W1 {
                    addr: 0x80DF,
                    clear: 0xFF00,
                    set: 0x1000,
                },
                SramWrite {
                    addr: 0x80CB,
                    value: 0x2007,
                },
                SramW0W1 {
                    addr: 0x80CE,
                    clear: 0xFF00,
                    set: 0x6C00,
                },
                SramWrite {
                    addr: 0x80C9,
                    value: 0x8009,
                },
                SramW0W1 {
                    addr: 0x80D1,
                    clear: 0xFF00,
                    set: 0x8000,
                },
                SramWrite {
                    addr: 0x80A3,
                    value: 0x200A,
                },
                SramWrite {
                    addr: 0x80A5,
                    value: 0xF0AD,
                },
                SramWrite {
                    addr: 0x809F,
                    value: 0x6073,
                },
                SramWrite {
                    addr: 0x80A1,
                    value: 0x000B,
                },
                SramW0W1 {
                    addr: 0x80A9,
                    clear: 0xFF00,
                    set: 0xC000,
                },
                // Patch-gated register block (Linux returns from
                // hw_phy_cfg when the request fails).
                PhyPatchRequest { request: true },
                OcpRegClrBits {
                    addr: 0xB896,
                    bits: 0x0001,
                },
                OcpRegClrBits {
                    addr: 0xB892,
                    bits: 0xFF00,
                },
                OcpRegWrite {
                    addr: 0xB88E,
                    value: 0xC23E,
                },
                OcpRegWrite {
                    addr: 0xB890,
                    value: 0x0000,
                },
                OcpRegWrite {
                    addr: 0xB88E,
                    value: 0xC240,
                },
                OcpRegWrite {
                    addr: 0xB890,
                    value: 0x0103,
                },
                OcpRegWrite {
                    addr: 0xB88E,
                    value: 0xC242,
                },
                OcpRegWrite {
                    addr: 0xB890,
                    value: 0x0507,
                },
                OcpRegWrite {
                    addr: 0xB88E,
                    value: 0xC244,
                },
                OcpRegWrite {
                    addr: 0xB890,
                    value: 0x090B,
                },
                OcpRegWrite {
                    addr: 0xB88E,
                    value: 0xC246,
                },
                OcpRegWrite {
                    addr: 0xB890,
                    value: 0x0C0E,
                },
                OcpRegWrite {
                    addr: 0xB88E,
                    value: 0xC248,
                },
                OcpRegWrite {
                    addr: 0xB890,
                    value: 0x1012,
                },
                OcpRegWrite {
                    addr: 0xB88E,
                    value: 0xC24A,
                },
                OcpRegWrite {
                    addr: 0xB890,
                    value: 0x1416,
                },
                OcpRegSetBits {
                    addr: 0xB896,
                    bits: 0x0001,
                },
                PhyPatchRequest { request: false },
                OcpRegSetBits {
                    addr: 0xA86A,
                    bits: 0x0001,
                },
                OcpRegSetBits {
                    addr: 0xA6F0,
                    bits: 0x0001,
                },
                OcpRegWrite {
                    addr: 0xBFA0,
                    value: 0xD70D,
                },
                OcpRegWrite {
                    addr: 0xBFA2,
                    value: 0x4100,
                },
                OcpRegWrite {
                    addr: 0xBFA4,
                    value: 0xE868,
                },
                OcpRegWrite {
                    addr: 0xBFA6,
                    value: 0xDC59,
                },
                OcpRegWrite {
                    addr: 0xB54C,
                    value: 0x3C18,
                },
                OcpRegClrBits {
                    addr: 0xBFA4,
                    bits: 0x0020,
                },
                SramW0W1 {
                    addr: 0x817D,
                    clear: 0,
                    set: 0x1000,
                },
            ]);
        }
        RtlVersion::Ver13 => {
            // 2.5G INRX, then fall through to the VER_15 arm.
            ops.extend([
                OcpRegW0W1 {
                    addr: 0xAC46,
                    clear: 0x00F0,
                    set: 0x0090,
                },
                OcpRegW0W1 {
                    addr: 0xAD30,
                    clear: 0x0003,
                    set: 0x0001,
                },
            ]);
            ops.extend(phy_init_ops_8156b_1315());
        }
        RtlVersion::Ver15 => {
            ops.extend(phy_init_ops_8156b_1315());
        }
        _ => {}
    }
    ops.extend(phy_init_ops_8156b_tail());
    ops
}

/// The VER_13/VER_15 shared arm of `r8156b_hw_phy_cfg` (Linux's
/// `case RTL_VER_15` fall-through target).
fn phy_init_ops_8156b_1315() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        // EEE parameter.
        Sram2Write {
            addr: 0x80F5,
            value: 0x760E,
        },
        Sram2Write {
            addr: 0x8107,
            value: 0x360E,
        },
        Sram2W0W1 {
            addr: 0x8551,
            clear: 0xFF00,
            set: 0x0800,
        },
        // ADC_PGA parameter.
        OcpRegW0W1 {
            addr: 0xBF00,
            clear: 0xE000,
            set: 0xA000,
        },
        OcpRegW0W1 {
            addr: 0xBF46,
            clear: 0x0F00,
            set: 0x0300,
        },
    ];
    // Green Table-PGA, 1G full viterbi.
    for addr in [
        0x8044u16, 0x804A, 0x8050, 0x8056, 0x805C, 0x8062, 0x8068, 0x806E, 0x8074, 0x807A,
    ] {
        ops.push(SramWrite {
            addr,
            value: 0x2417,
        });
    }
    ops.push(OcpRegW0W1 {
        addr: 0xBF84,
        clear: 0xE000,
        set: 0xA000,
    });
    ops
}

/// Shared tail of `r8157_hw_phy_cfg` (VER_16/17): patch-gated
/// Advance EEE, green mode, lite-mode clears, EEE re-enable,
/// ALDPS, flow control. Unlike the other families there is no
/// U2P3 enable here (Linux uses the separate `r8157_u2p3en`
/// path).
fn phy_init_ops_8157_tail(adv: u16, adv2: u16) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        // Advance EEE, gated on the PHY patch request.
        PhyPatchRequest { request: true },
        PlaWordSetBits {
            addr: PLA_MAC_PWR_CTRL4,
            bits: MAC_PWR_CTRL4_EEE_SPDWN_EN,
        },
        OcpRegW0W1 {
            addr: OCP_DOWN_SPEED,
            clear: DOWN_SPEED_EN_EEE_100 | DOWN_SPEED_EN_EEE_1000,
            set: DOWN_SPEED_EN_10M_CLKDIV,
        },
        OcpRegSetBits {
            addr: OCP_POWER_CFG,
            bits: POWER_CFG_EEE_CLKDIV_EN,
        },
        PhyPatchRequest { request: false },
        SramW0W1 {
            addr: SRAM_GREEN_CFG,
            clear: 0,
            set: GREEN_ETH_EN,
        },
        OcpRegClrBits {
            addr: 0xA428,
            bits: 0x0200,
        },
        OcpRegClrBits {
            addr: 0xA5EA,
            bits: 0x0003,
        },
    ];
    // EEE re-enable (Linux: eee_en is true for VER_16/17).
    ops.extend(eee_enable_ops_8156(adv, adv2));
    ops.push(aldps_enable_op());
    ops.push(enable_fc_op());
    ops
}

/// The `r8157_hw_phy_cfg` sequence for the RTL8157 family
/// (VER_16/17), in Linux's order.
fn phy_init_ops_8157(version: RtlVersion) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![WaitLoadingFlash];
    ops.extend(phy_init_ops_8156b_prefix(true, false));
    // r8157 clears the PFM/PWM switch (PFM mode) where the other
    // families set it — handled by the `set_pfm_pwm` argument
    // above. First version-specific act in Linux:
    ops.extend([
        // Advanced Power Saving parameter.
        OcpRegSetBits {
            addr: OCP_POWER_CFG,
            bits: 0x0003,
        },
        // Disable ALDPS force mode.
        OcpRegClrBits {
            addr: 0xA44A,
            bits: 0x0004,
        },
    ]);
    match version {
        RtlVersion::Ver16 => {
            ops.extend(phy_init_ops_8157_ver16());
        }
        RtlVersion::Ver17 => {
            ops.extend(phy_init_ops_8157_ver17());
        }
        _ => {}
    }
    // VER_16: eee_adv 0x0006, eee_adv2 2.5GT|5GT; VER_17:
    // eee_adv 0x000E, eee_adv2 2.5GT|5GT.
    let adv = match version {
        RtlVersion::Ver17 => EEE_ADV_8157,
        _ => EEE_ADV_8153,
    };
    ops.extend(phy_init_ops_8157_tail(adv, MDIO_EEE_2_5GT | MDIO_EEE_5GT));
    ops
}

/// The VER_16 arm of `r8157_hw_phy_cfg`.
fn phy_init_ops_8157_ver16() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let mut ops = vec![
        // XG_INRX parameter.
        SramW0W1 {
            addr: 0x8183,
            clear: 0xFF00,
            set: 0x5900,
        },
        OcpRegSetBits {
            addr: 0xA654,
            bits: 0x0800,
        },
        OcpRegSetBits {
            addr: 0xB648,
            bits: 0x4000,
        },
        OcpRegClrBits {
            addr: 0xAD2C,
            bits: 0x8000,
        },
        OcpRegSetBits {
            addr: 0xAD94,
            bits: 0x0020,
        },
        OcpRegSetBits {
            addr: 0xADA0,
            bits: 0x0002,
        },
        OcpRegW0W1 {
            addr: 0xAE06,
            clear: 0xFC00,
            set: 0x7C00,
        },
        Sram2W0W1 {
            addr: 0x8647,
            clear: 0xFF00,
            set: 0xE600,
        },
        Sram2W0W1 {
            addr: 0x8036,
            clear: 0xFF00,
            set: 0x3000,
        },
        Sram2W0W1 {
            addr: 0x8078,
            clear: 0xFF00,
            set: 0x3000,
        },
        // Green mode.
        Sram2W0W1 {
            addr: 0x89E9,
            clear: 0xFF00,
            set: 0,
        },
        Sram2W0W1 {
            addr: 0x8FFD,
            clear: 0xFF00,
            set: 0x0100,
        },
        Sram2W0W1 {
            addr: 0x8FFE,
            clear: 0xFF00,
            set: 0x0200,
        },
        Sram2W0W1 {
            addr: 0x8FFF,
            clear: 0xFF00,
            set: 0x0400,
        },
        // Recognize AQC/Bcom function.
        SramW0W1 {
            addr: 0x8018,
            clear: 0xFF00,
            set: 0x7700,
        },
        SramAddrWrite { addr: 0x8F9C },
        SramDataWrite { value: 0x0005 },
        SramDataWrite { value: 0x0000 },
        SramDataWrite { value: 0x00ED },
        SramDataWrite { value: 0x0502 },
        SramDataWrite { value: 0x0B00 },
        SramDataWrite { value: 0xD401 },
        SramW0W1 {
            addr: 0x8FA8,
            clear: 0xFF00,
            set: 0x2900,
        },
        // RFI_corr_thd 5g.
        Sram2W0W1 {
            addr: 0x814B,
            clear: 0xFF00,
            set: 0x1100,
        },
        Sram2W0W1 {
            addr: 0x814D,
            clear: 0xFF00,
            set: 0x1100,
        },
        Sram2W0W1 {
            addr: 0x814F,
            clear: 0xFF00,
            set: 0x0B00,
        },
        Sram2W0W1 {
            addr: 0x8142,
            clear: 0xFF00,
            set: 0x0100,
        },
        Sram2W0W1 {
            addr: 0x8144,
            clear: 0xFF00,
            set: 0x0100,
        },
        Sram2W0W1 {
            addr: 0x8150,
            clear: 0xFF00,
            set: 0x0100,
        },
        // RFI_corr_thd 2p5g.
        Sram2W0W1 {
            addr: 0x8118,
            clear: 0xFF00,
            set: 0x0700,
        },
        Sram2W0W1 {
            addr: 0x811A,
            clear: 0xFF00,
            set: 0x0700,
        },
        Sram2W0W1 {
            addr: 0x811C,
            clear: 0xFF00,
            set: 0x0500,
        },
        Sram2W0W1 {
            addr: 0x810F,
            clear: 0xFF00,
            set: 0x0100,
        },
        Sram2W0W1 {
            addr: 0x8111,
            clear: 0xFF00,
            set: 0x0100,
        },
        Sram2W0W1 {
            addr: 0x811D,
            clear: 0xFF00,
            set: 0x0100,
        },
        // RFI parameter.
        OcpRegClrBits {
            addr: 0xAD1C,
            bits: 0x0100,
        },
        OcpRegW0W1 {
            addr: 0xADE8,
            clear: 0xFFC0,
            set: 0x1400,
        },
        Sram2W0W1 {
            addr: 0x864B,
            clear: 0xFF00,
            set: 0x9D00,
        },
        Sram2W0W1 {
            addr: 0x862C,
            clear: 0xFF00,
            set: 0x1200,
        },
        SramAddrWrite { addr: 0x8566 },
        SramDataWrite { value: 0x003F },
        SramDataWrite { value: 0x3F02 },
        SramDataWrite { value: 0x023C },
        SramDataWrite { value: 0x3B0A },
        SramDataWrite { value: 0x1C00 },
        SramDataWrite { value: 0x0000 },
        SramDataWrite { value: 0x0000 },
        SramDataWrite { value: 0x0000 },
        SramDataWrite { value: 0x0000 },
        // RFI-color noise gen parameter 5g.
        OcpRegSetBits {
            addr: 0xAD9C,
            bits: 0x0020,
        },
        Sram2W0W1 {
            addr: 0x8122,
            clear: 0xFF00,
            set: 0x0C00,
        },
        Sram2AddrWrite { addr: 0x82C8 },
    ];
    for value in [
        0x03EDu16, 0x03FF, 0x0009, 0x03FE, 0x000B, 0x0021, 0x03F7, 0x03B8, 0x03E0, 0x0049, 0x0049,
        0x03E0, 0x03B8, 0x03F7, 0x0021, 0x000B, 0x03FE, 0x0009, 0x03FF, 0x03ED,
    ] {
        ops.push(Sram2DataWrite { value });
    }
    ops.extend([
        // RFI-color noise gen parameter 2p5g.
        Sram2W0W1 {
            addr: 0x80EF,
            clear: 0xFF00,
            set: 0x0C00,
        },
        Sram2AddrWrite { addr: 0x82A0 },
    ]);
    for value in [
        0x000Eu16, 0x03FE, 0x03ED, 0x0006, 0x001A, 0x03F1, 0x03D8, 0x0023, 0x0054, 0x0322, 0x00DD,
        0x03AB, 0x03DC, 0x0027, 0x000E, 0x03E5, 0x03F9, 0x0012, 0x0001, 0x03F1,
    ] {
        ops.push(Sram2DataWrite { value });
    }
    ops.extend([
        // Modify thermal speed down threshold.
        OcpRegW0W1 {
            addr: 0xB54C,
            clear: 0xFFC0,
            set: 0x3700,
        },
        // XG compatibility modification.
        OcpRegSetBits {
            addr: 0xB648,
            bits: 0x0040,
        },
        Sram2W0W1 {
            addr: 0x8082,
            clear: 0xFF00,
            set: 0x5D00,
        },
        Sram2W0W1 {
            addr: 0x807C,
            clear: 0xFF00,
            set: 0x5000,
        },
        Sram2W0W1 {
            addr: 0x809D,
            clear: 0xFF00,
            set: 0x5000,
        },
    ]);
    ops
}

/// The VER_17 arm of `r8157_hw_phy_cfg`.
fn phy_init_ops_8157_ver17() -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    let ops = vec![
        // Disable bypass turn off clk in ALDPS.
        PlaByteClrBits {
            addr: 0xD3C8,
            bits: 0x01,
        },
        // Power level tuning: test mode power level.
        SramW0W1 {
            addr: 0x8415,
            clear: 0xFF00,
            set: 0x9300,
        },
        // Normal link power level 10G, 5G, 2.5G.
        SramW0W1 {
            addr: 0x81A3,
            clear: 0xFF00,
            set: 0x0F00,
        },
        SramW0W1 {
            addr: 0x81AE,
            clear: 0xFF00,
            set: 0x0F00,
        },
        SramW0W1 {
            addr: 0x81B9,
            clear: 0xFF00,
            set: 0xB900,
        },
        // Normal link TX filter.
        Sram2W0W1 {
            addr: 0x83B0,
            clear: 0x0E00,
            set: 0,
        },
        Sram2W0W1 {
            addr: 0x83C5,
            clear: 0x0E00,
            set: 0,
        },
        Sram2W0W1 {
            addr: 0x83DA,
            clear: 0x0E00,
            set: 0,
        },
        Sram2W0W1 {
            addr: 0x83EF,
            clear: 0x0E00,
            set: 0,
        },
        // AFE power saving for 2.5G & 5G.
        SramWrite {
            addr: 0x8173,
            value: 0x8620,
        },
        SramWrite {
            addr: 0x8175,
            value: 0x8671,
        },
        SramW0W1 {
            addr: 0x817C,
            clear: 0,
            set: 0x2000,
        },
        SramW0W1 {
            addr: 0x8187,
            clear: 0,
            set: 0x2000,
        },
        SramW0W1 {
            addr: 0x8192,
            clear: 0,
            set: 0x2000,
        },
        SramW0W1 {
            addr: 0x819D,
            clear: 0,
            set: 0x2000,
        },
        SramW0W1 {
            addr: 0x81A8,
            clear: 0x2000,
            set: 0,
        },
        SramW0W1 {
            addr: 0x81B3,
            clear: 0x2000,
            set: 0,
        },
        SramW0W1 {
            addr: 0x81BE,
            clear: 0,
            set: 0x2000,
        },
        SramW0W1 {
            addr: 0x817D,
            clear: 0xFF00,
            set: 0xA600,
        },
        SramW0W1 {
            addr: 0x8188,
            clear: 0xFF00,
            set: 0xA600,
        },
        SramW0W1 {
            addr: 0x8193,
            clear: 0xFF00,
            set: 0xA600,
        },
        SramW0W1 {
            addr: 0x819E,
            clear: 0xFF00,
            set: 0xA600,
        },
        SramW0W1 {
            addr: 0x81A9,
            clear: 0xFF00,
            set: 0x1400,
        },
        SramW0W1 {
            addr: 0x81B4,
            clear: 0xFF00,
            set: 0x1400,
        },
        SramW0W1 {
            addr: 0x81BF,
            clear: 0xFF00,
            set: 0xA600,
        },
        // RFI parameter: disable preset FBE.
        OcpRegClrBits {
            addr: 0xAEAA,
            bits: 0x0028,
        },
        // Modify PGA for 5G&10G.
        Sram2Write {
            addr: 0x84F0,
            value: 0x201C,
        },
        Sram2Write {
            addr: 0x84F2,
            value: 0x3117,
        },
        // RFI parameter.
        OcpRegWrite {
            addr: 0xAEC6,
            value: 0x0000,
        },
        OcpRegWrite {
            addr: 0xAE20,
            value: 0xFFFF,
        },
        OcpRegWrite {
            addr: 0xAECE,
            value: 0xFFFF,
        },
        OcpRegWrite {
            addr: 0xAED2,
            value: 0xFFFF,
        },
        OcpRegWrite {
            addr: 0xAEC8,
            value: 0x0000,
        },
        OcpRegClrBits {
            addr: 0xAED0,
            bits: 0x0001,
        },
        OcpRegWrite {
            addr: 0xADB8,
            value: 0x0150,
        },
        Sram2W0W1 {
            addr: 0x8197,
            clear: 0xFF00,
            set: 0x5000,
        },
        Sram2W0W1 {
            addr: 0x8231,
            clear: 0xFF00,
            set: 0x5000,
        },
        Sram2W0W1 {
            addr: 0x82CB,
            clear: 0xFF00,
            set: 0x5000,
        },
        Sram2W0W1 {
            addr: 0x82CD,
            clear: 0xFF00,
            set: 0x5700,
        },
        Sram2W0W1 {
            addr: 0x8233,
            clear: 0xFF00,
            set: 0x5700,
        },
        Sram2W0W1 {
            addr: 0x8199,
            clear: 0xFF00,
            set: 0x5700,
        },
        Sram2Write {
            addr: 0x815A,
            value: 0x0150,
        },
        Sram2Write {
            addr: 0x81F4,
            value: 0x0150,
        },
        Sram2Write {
            addr: 0x828E,
            value: 0x0150,
        },
        Sram2Write {
            addr: 0x81B1,
            value: 0x0000,
        },
        Sram2Write {
            addr: 0x824B,
            value: 0x0000,
        },
        Sram2Write {
            addr: 0x82E5,
            value: 0x0000,
        },
        Sram2W0W1 {
            addr: 0x84F7,
            clear: 0xFF00,
            set: 0x2800,
        },
        OcpRegSetBits {
            addr: 0xAEC2,
            bits: 0x1000,
        },
        Sram2W0W1 {
            addr: 0x81B3,
            clear: 0xFF00,
            set: 0xAD00,
        },
        Sram2W0W1 {
            addr: 0x824D,
            clear: 0xFF00,
            set: 0xAD00,
        },
        Sram2W0W1 {
            addr: 0x82E7,
            clear: 0xFF00,
            set: 0xAD00,
        },
        OcpRegW0W1 {
            addr: 0xAE4E,
            clear: 0x000F,
            set: 0x0001,
        },
        Sram2W0W1 {
            addr: 0x82CE,
            clear: 0xF000,
            set: 0x4000,
        },
        // 5G shift sel, default = '04'; 10G shift sel, default = '03'.
        Sram2W0W1 {
            addr: 0x83A5,
            clear: 0xFF00,
            set: 0x0400,
        },
        Sram2W0W1 {
            addr: 0x83A6,
            clear: 0xFF00,
            set: 0x0400,
        },
        Sram2W0W1 {
            addr: 0x83A7,
            clear: 0xFF00,
            set: 0x0400,
        },
        Sram2W0W1 {
            addr: 0x83A8,
            clear: 0xFF00,
            set: 0x0400,
        },
        // XG INRX parameters: RC coefficients.
        Sram2Write {
            addr: 0x84AC,
            value: 0x0000,
        },
        Sram2Write {
            addr: 0x84AE,
            value: 0x0000,
        },
        Sram2Write {
            addr: 0x84B0,
            value: 0xF818,
        },
        Sram2W0W1 {
            addr: 0x84B2,
            clear: 0xFF00,
            set: 0x6000,
        },
        // Training AAGC PAR (with uc2 patch).
        Sram2Write {
            addr: 0x8FFC,
            value: 0x6008,
        },
        Sram2Write {
            addr: 0x8FFE,
            value: 0xF450,
        },
        // DAC BGK.
        Sram2W0W1 {
            addr: 0x8015,
            clear: 0,
            set: 0x0200,
        },
        Sram2W0W1 {
            addr: 0x8016,
            clear: 0,
            set: 0x0800,
        },
        Sram2W0W1 {
            addr: 0x8FE6,
            clear: 0xFF00,
            set: 0x0800,
        },
        Sram2Write {
            addr: 0x8FE4,
            value: 0x2114,
        },
        // 10G PBO table.
        Sram2Write {
            addr: 0x8647,
            value: 0xA7B1,
        },
        Sram2Write {
            addr: 0x8649,
            value: 0xBBCA,
        },
        Sram2W0W1 {
            addr: 0x864B,
            clear: 0xFF00,
            set: 0xDC00,
        },
        // 2.5G ado power window size.
        Sram2W0W1 {
            addr: 0x8154,
            clear: 0xC000,
            set: 0x4000,
        },
        Sram2W0W1 {
            addr: 0x8158,
            clear: 0xC000,
            set: 0,
        },
        // 10G lock far.
        Sram2Write {
            addr: 0x826C,
            value: 0xFFFF,
        },
        Sram2Write {
            addr: 0x826E,
            value: 0xFFFF,
        },
        // XG INRX parameter.
        Sram2W0W1 {
            addr: 0x8872,
            clear: 0xFF00,
            set: 0x0E00,
        },
        SramW0W1 {
            addr: 0x8012,
            clear: 0,
            set: 0x0800,
        },
        SramW0W1 {
            addr: 0x8012,
            clear: 0,
            set: 0x4000,
        },
        OcpRegSetBits {
            addr: 0xB576,
            bits: 0x0001,
        },
        SramW0W1 {
            addr: 0x834A,
            clear: 0xFF00,
            set: 0x0700,
        },
        Sram2W0W1 {
            addr: 0x8217,
            clear: 0x3F00,
            set: 0x2A00,
        },
        SramW0W1 {
            addr: 0x81B1,
            clear: 0xFF00,
            set: 0x0B00,
        },
        Sram2W0W1 {
            addr: 0x8FED,
            clear: 0xFF00,
            set: 0x4E00,
        },
        // Slave about EC mu of datamode AAGC and DAC BG.
        Sram2W0W1 {
            addr: 0x88AC,
            clear: 0xFF00,
            set: 0x2300,
        },
        // Improve UBE.
        OcpRegSetBits {
            addr: 0xBF0C,
            bits: 0x3800,
        },
        // Close Sparse NEC, improve connect 5EUU cable performance.
        Sram2W0W1 {
            addr: 0x88DE,
            clear: 0xFF00,
            set: 0,
        },
        // 5G slave compatibility issue.
        Sram2Write {
            addr: 0x80B4,
            value: 0x5195,
        },
        // XG Test Mode: xgtstm_map_tbl for mdi_cap_sel.
        SramWrite {
            addr: 0x8370,
            value: 0x8671,
        },
        SramWrite {
            addr: 0x8372,
            value: 0x86C8,
        },
        // xgtstm_amp_map_tbl for REG_IBX_UP_SHIFT_L.
        SramWrite {
            addr: 0x8401,
            value: 0x86C8,
        },
        SramWrite {
            addr: 0x8403,
            value: 0x86DA,
        },
        SramW0W1 {
            addr: 0x8406,
            clear: 0x1800,
            set: 0x1000,
        },
        SramW0W1 {
            addr: 0x8408,
            clear: 0x1800,
            set: 0x1000,
        },
        SramW0W1 {
            addr: 0x840A,
            clear: 0x1800,
            set: 0x1000,
        },
        SramW0W1 {
            addr: 0x840C,
            clear: 0x1800,
            set: 0x1000,
        },
        SramW0W1 {
            addr: 0x840E,
            clear: 0x1800,
            set: 0x1000,
        },
        SramW0W1 {
            addr: 0x8410,
            clear: 0x1800,
            set: 0x1000,
        },
        SramW0W1 {
            addr: 0x8412,
            clear: 0x1800,
            set: 0x1000,
        },
        SramW0W1 {
            addr: 0x8414,
            clear: 0x1800,
            set: 0x1000,
        },
        SramW0W1 {
            addr: 0x8416,
            clear: 0x1800,
            set: 0x1000,
        },
        // Cable Test Patch.
        SramWrite {
            addr: 0x82BD,
            value: 0x1F40,
        },
        // Thermal sensor parameters.
        OcpRegW0W1 {
            addr: 0xBFB4,
            clear: 0x07FF,
            set: 0x0328,
        },
        OcpRegWrite {
            addr: 0xBFB6,
            value: 0x3E14,
        },
        // spdchg_gtx_shape_100M.
        SramAddrWrite { addr: 0x81C4 },
        SramDataWrite { value: 0x003B },
        SramDataWrite { value: 0x0086 },
        SramDataWrite { value: 0x00B7 },
        SramDataWrite { value: 0x00DB },
        SramDataWrite { value: 0x00FE },
        SramDataWrite { value: 0x00FE },
        SramDataWrite { value: 0x00FE },
        SramDataWrite { value: 0x00FE },
        SramDataWrite { value: 0x00C3 },
        SramDataWrite { value: 0x0078 },
        SramDataWrite { value: 0x0047 },
        SramDataWrite { value: 0x0023 },
        // lsbmsk_parameters (RL6961_lsbmsk_parameter_250207).
        Sram2Write {
            addr: 0x88D7,
            value: 0x01A0,
        },
        Sram2Write {
            addr: 0x88D9,
            value: 0x01A0,
        },
        Sram2Write {
            addr: 0x8FFA,
            value: 0x002A,
        },
        Sram2Write {
            addr: 0x8FEE,
            value: 0xFFDF,
        },
        Sram2Write {
            addr: 0x8FF0,
            value: 0xFFFF,
        },
        Sram2Write {
            addr: 0x8FF2,
            value: 0x0A4A,
        },
        Sram2Write {
            addr: 0x8FF4,
            value: 0xAA5A,
        },
        Sram2Write {
            addr: 0x8FF6,
            value: 0x0A4A,
        },
        Sram2Write {
            addr: 0x8FF8,
            value: 0xAA5A,
        },
        Sram2W0W1 {
            addr: 0x88D5,
            clear: 0xFF00,
            set: 0x0200,
        },
    ];
    ops
}

/// The version-switched PHY init sequence for `version`, in
/// Linux's order (see the per-family builders above). Returns an
/// empty sequence for TEST_01 and unknown versions — those keep
/// reset defaults, never a bind failure.
pub fn phy_init_ops(version: RtlVersion) -> Vec<PhyInitOp> {
    match version {
        RtlVersion::Ver01 | RtlVersion::Ver02 | RtlVersion::Ver07 => phy_init_ops_8152b(),
        RtlVersion::Ver03 | RtlVersion::Ver04 | RtlVersion::Ver05 | RtlVersion::Ver06 => {
            phy_init_ops_8153(version)
        }
        RtlVersion::Ver08 | RtlVersion::Ver09 | RtlVersion::Ver14 => phy_init_ops_8153b(),
        RtlVersion::Ver10 | RtlVersion::Ver11 => phy_init_ops_8156(version),
        RtlVersion::Ver12 | RtlVersion::Ver13 | RtlVersion::Ver15 => phy_init_ops_8156b(version),
        RtlVersion::Ver16 | RtlVersion::Ver17 => phy_init_ops_8157(version),
        _ => Vec::new(),
    }
}

/// Backwards-compatible name for the original RTL8153-family
/// builder: the VER_03–VER_06 sequence.
pub fn r8153_phy_init_ops(version: RtlVersion) -> Vec<PhyInitOp> {
    match version {
        RtlVersion::Ver03 | RtlVersion::Ver04 | RtlVersion::Ver05 | RtlVersion::Ver06 => {
            phy_init_ops_8153(version)
        }
        _ => Vec::new(),
    }
}

/// Derive the OCP window access for a PHY register address:
/// `(base, index)` where the base goes to `PLA_OCP_GPHY_BASE`
/// and the index is the PLA word access (Linux `ocp_reg_read` /
/// `ocp_reg_write`).
pub fn ocp_reg_window(addr: u16) -> (u16, u16) {
    (addr & 0xF000, (addr & 0x0FFF) | 0xB000)
}

async fn ocp_reg_read(dev: &USBDevice, addr: u16) -> Result<u16, ()> {
    let (base, index) = ocp_reg_window(addr);
    ocp_write_word(dev, MCU_TYPE_PLA, PLA_OCP_GPHY_BASE, base).await?;
    ocp_read_word(dev, MCU_TYPE_PLA, index).await
}

async fn ocp_reg_write(dev: &USBDevice, addr: u16, value: u16) -> Result<(), ()> {
    let (base, index) = ocp_reg_window(addr);
    ocp_write_word(dev, MCU_TYPE_PLA, PLA_OCP_GPHY_BASE, base).await?;
    ocp_write_word(dev, MCU_TYPE_PLA, index, value).await
}

async fn ocp_reg_set_bits(dev: &USBDevice, addr: u16, bits: u16) -> Result<(), ()> {
    let cur = ocp_reg_read(dev, addr).await?;
    ocp_reg_write(dev, addr, cur | bits).await
}

async fn ocp_reg_clr_bits(dev: &USBDevice, addr: u16, bits: u16) -> Result<(), ()> {
    let cur = ocp_reg_read(dev, addr).await?;
    ocp_reg_write(dev, addr, cur & !bits).await
}

async fn pla_word_set_bits(dev: &USBDevice, addr: u16, bits: u16) -> Result<(), ()> {
    let cur = ocp_read_word(dev, MCU_TYPE_PLA, addr).await?;
    ocp_write_word(dev, MCU_TYPE_PLA, addr, cur | bits).await
}

async fn pla_word_clr_bits(dev: &USBDevice, addr: u16, bits: u16) -> Result<(), ()> {
    let cur = ocp_read_word(dev, MCU_TYPE_PLA, addr).await?;
    ocp_write_word(dev, MCU_TYPE_PLA, addr, cur & !bits).await
}

/// SRAM cell write: `OCP_SRAM_ADDR := addr`, then
/// `OCP_SRAM_DATA := value` (Linux `sram_write`).
async fn sram_write(dev: &USBDevice, addr: u16, value: u16) -> Result<(), ()> {
    ocp_reg_write(dev, OCP_SRAM_ADDR, addr).await?;
    ocp_reg_write(dev, OCP_SRAM_DATA, value).await
}

/// SRAM cell read: `OCP_SRAM_ADDR := addr`, then read
/// `OCP_SRAM_DATA` (Linux `sram_read`).
async fn sram_read(dev: &USBDevice, addr: u16) -> Result<u16, ()> {
    ocp_reg_write(dev, OCP_SRAM_ADDR, addr).await?;
    ocp_reg_read(dev, OCP_SRAM_DATA).await
}

/// Second SRAM bank cell read (Linux `sram2_read`).
async fn sram2_read(dev: &USBDevice, addr: u16) -> Result<u16, ()> {
    ocp_reg_write(dev, OCP_SRAM2_ADDR, addr).await?;
    ocp_reg_read(dev, OCP_SRAM2_DATA).await
}

/// Second SRAM bank write: `OCP_SRAM2_ADDR := addr`, then
/// `OCP_SRAM2_DATA := value` (Linux `sram2_write`).
async fn sram2_write(dev: &USBDevice, addr: u16, value: u16) -> Result<(), ()> {
    ocp_reg_write(dev, OCP_SRAM2_ADDR, addr).await?;
    ocp_reg_write(dev, OCP_SRAM2_DATA, value).await
}

/// Poll `OCP_PHY_STATUS` for any of LAN_ON / PWRDN / EXT_INIT
/// (Linux `r8153_phy_status(tp, 0)`), returning the status value
/// seen — the last read when the poll never completes, like the
/// reset poll in bind. Cooperative yields between reads, never a
/// busy spin on a hardware register.
async fn poll_phy_status_any(dev: &USBDevice) -> Result<u16, ()> {
    let mut status = 0u16;
    for _ in 0..500 {
        status = ocp_reg_read(dev, OCP_PHY_STATUS).await? & PHY_STAT_MASK;
        if status == PHY_STAT_LAN_ON || status == PHY_STAT_PWRDN || status == PHY_STAT_EXT_INIT {
            break;
        }
        narf_scheduler::yield_now().await;
    }
    Ok(status)
}

/// PHY patch request/release (Linux `rtl_phy_patch_request(tp,
/// request, wait)`): set (or clear) `PATCH_REQUEST` in
/// `OCP_PHY_PATCH_CMD` and, when `wait` is set, wait for
/// `PATCH_READY` to set (or clear), 1 ms between polls, up to
/// 5000 iterations. Returns `Ok(true)` when the patch state
/// reached the requested value (or when `wait` is false — Linux
/// sets the bit and returns immediately), `Ok(false)` when a
/// *request* timed out — Linux logs the failure, releases the
/// request without waiting, and returns `-ETIME` (the caller
/// then returns from `*_hw_phy_cfg`). The release path never
/// returns `Ok(false)`. The table-level `PhyPatchRequest` steps
/// always pass `wait = true`; the firmware-internal calls pass
/// `!power_cut`, as in Linux.
async fn phy_patch_request(dev: &USBDevice, request: bool, wait: bool) -> Result<bool, ()> {
    let check = if request {
        ocp_reg_set_bits(dev, OCP_PHY_PATCH_CMD, PATCH_REQUEST).await?;
        0
    } else {
        ocp_reg_clr_bits(dev, OCP_PHY_PATCH_CMD, PATCH_REQUEST).await?;
        PATCH_READY
    };
    if !wait {
        return Ok(true);
    }
    for _ in 0..5000 {
        narf_time::sleep_ms(1).await;
        let stat = ocp_reg_read(dev, OCP_PHY_PATCH_STAT).await?;
        if (stat & PATCH_READY) ^ check != 0 {
            break;
        }
    }
    if request {
        let stat = ocp_reg_read(dev, OCP_PHY_PATCH_STAT).await?;
        if stat & PATCH_READY == 0 {
            // Release without waiting, as Linux does on failure.
            ocp_reg_clr_bits(dev, OCP_PHY_PATCH_CMD, PATCH_REQUEST).await?;
            return Ok(false);
        }
    }
    Ok(true)
}

/// Efuse word read (Linux `r8152_efuse_read`): issue the read
/// command, then assemble the 17-bit value from the command
/// register's bit 16 and the data register.
async fn efuse_read(dev: &USBDevice, addr: u8) -> Result<u32, ()> {
    ocp_write_word(
        dev,
        MCU_TYPE_PLA,
        PLA_EFUSE_CMD,
        EFUSE_READ_CMD | addr as u16,
    )
    .await?;
    let cmd = ocp_read_word(dev, MCU_TYPE_PLA, PLA_EFUSE_CMD).await?;
    let data = ocp_read_word(dev, MCU_TYPE_PLA, PLA_EFUSE_DATA).await?;
    Ok(((u32::from(cmd) & u32::from(EFUSE_DATA_BIT16)) << 9) | u32::from(data))
}

/// MDI pair swap when the board is reversed (Linux
/// `r8156_hw_phy_cfg` VER_11): when `USB_UPS_CFG` reports
/// `MID_REVERSE` and OCP `0xd068` bit 1 is set, swap the p0/p3
/// and p1/p2 lanes through the `0xd068` selector / `0xd06a` data
/// pair, then the `0xbd5a`/`0xbd5c` and `0xbc18`/`0xbc1a` pairs.
async fn mdi_swap_if_reversed(dev: &USBDevice) -> Result<(), ()> {
    let ups = ocp_read_word(dev, MCU_TYPE_USB, USB_UPS_CFG).await?;
    let sel = ocp_reg_read(dev, 0xD068).await?;
    if ups & UPS_CFG_MID_REVERSE == 0 || sel & 0x0002 == 0 {
        return Ok(());
    }
    let mut data = ocp_reg_read(dev, 0xD068).await?;
    data &= !0x001F;
    data |= 0x0001; // p0
    ocp_reg_write(dev, 0xD068, data).await?;
    let swap_a = ocp_reg_read(dev, 0xD06A).await?;
    data &= !0x0018;
    data |= 0x0018; // p3
    ocp_reg_write(dev, 0xD068, data).await?;
    let swap_b = ocp_reg_read(dev, 0xD06A).await?;
    data &= !0x0018; // p0
    ocp_reg_write(dev, 0xD068, data).await?;
    ocp_reg_write(dev, 0xD06A, (swap_a & !0x07FF) | (swap_b & 0x07FF)).await?;
    data |= 0x0018; // p3
    ocp_reg_write(dev, 0xD068, data).await?;
    ocp_reg_write(dev, 0xD06A, (swap_b & !0x07FF) | (swap_a & 0x07FF)).await?;
    data &= !0x0018;
    data |= 0x0008; // p1
    ocp_reg_write(dev, 0xD068, data).await?;
    let swap_a = ocp_reg_read(dev, 0xD06A).await?;
    data &= !0x0018;
    data |= 0x0010; // p2
    ocp_reg_write(dev, 0xD068, data).await?;
    let swap_b = ocp_reg_read(dev, 0xD06A).await?;
    data &= !0x0018;
    data |= 0x0008; // p1
    ocp_reg_write(dev, 0xD068, data).await?;
    ocp_reg_write(dev, 0xD06A, (swap_a & !0x07FF) | (swap_b & 0x07FF)).await?;
    data &= !0x0018;
    data |= 0x0010; // p2
    ocp_reg_write(dev, 0xD068, data).await?;
    ocp_reg_write(dev, 0xD06A, (swap_b & !0x07FF) | (swap_a & 0x07FF)).await?;
    let swap_a = ocp_reg_read(dev, 0xBD5A).await?;
    let swap_b = ocp_reg_read(dev, 0xBD5C).await?;
    ocp_reg_write(
        dev,
        0xBD5A,
        (swap_a & !0x1F1F) | ((swap_b & 0x001F) << 8) | ((swap_b >> 8) & 0x001F),
    )
    .await?;
    ocp_reg_write(
        dev,
        0xBD5C,
        (swap_b & !0x1F1F) | ((swap_a & 0x001F) << 8) | ((swap_a >> 8) & 0x001F),
    )
    .await?;
    let swap_a = ocp_reg_read(dev, 0xBC18).await?;
    let swap_b = ocp_reg_read(dev, 0xBC1A).await?;
    ocp_reg_write(
        dev,
        0xBC18,
        (swap_a & !0x1F1F) | ((swap_b & 0x001F) << 8) | ((swap_b >> 8) & 0x001F),
    )
    .await?;
    ocp_reg_write(
        dev,
        0xBC1A,
        (swap_b & !0x1F1F) | ((swap_a & 0x001F) << 8) | ((swap_a >> 8) & 0x001F),
    )
    .await?;
    Ok(())
}

/// Execution context threaded through one `phy_init_ops` run:
/// the chip version, the firmware blob (if the registry has one
/// for it), and whether a failed PHY patch request aborted the
/// run — Linux returns from `*_hw_phy_cfg` on it, so later steps
/// become no-ops, including the patch release.
#[derive(Debug)]
pub struct PhyInitCtx<'a> {
    version: RtlVersion,
    fw: Option<&'a [u8]>,
    patch_aborted: bool,
}

impl<'a> PhyInitCtx<'a> {
    fn new(version: RtlVersion, fw: Option<&'a [u8]>) -> Self {
        Self {
            version,
            fw,
            patch_aborted: false,
        }
    }
}

/// Execute one [`PhyInitOp`] against the device.
async fn apply_phy_init_op(
    dev: &USBDevice,
    ctx: &mut PhyInitCtx<'_>,
    op: PhyInitOp,
) -> Result<(), ()> {
    use PhyInitOp::*;
    // A failed patch request aborts the rest of the sequence
    // (Linux returns from `*_hw_phy_cfg` on it).
    if ctx.patch_aborted {
        return Ok(());
    }
    match op {
        OcpRegSetBits { addr, bits } => ocp_reg_set_bits(dev, addr, bits).await,
        OcpRegClrBits { addr, bits } => ocp_reg_clr_bits(dev, addr, bits).await,
        OcpRegWrite { addr, value } => ocp_reg_write(dev, addr, value).await,
        OcpRegW0W1 { addr, clear, set } => {
            let cur = ocp_reg_read(dev, addr).await?;
            ocp_reg_write(dev, addr, (cur & !clear) | set).await
        }
        SramWrite { addr, value } => sram_write(dev, addr, value).await,
        SramW0W1 { addr, clear, set } => {
            let cur = sram_read(dev, addr).await?;
            ocp_reg_write(dev, OCP_SRAM_DATA, (cur & !clear) | set).await
        }
        Sram2W0W1 { addr, clear, set } => {
            let cur = sram2_read(dev, addr).await?;
            ocp_reg_write(dev, OCP_SRAM2_DATA, (cur & !clear) | set).await
        }
        Sram2Write { addr, value } => sram2_write(dev, addr, value).await,
        SramAddrWrite { addr } => ocp_reg_write(dev, OCP_SRAM_ADDR, addr).await,
        SramDataWrite { value } => ocp_reg_write(dev, OCP_SRAM_DATA, value).await,
        Sram2AddrWrite { addr } => ocp_reg_write(dev, OCP_SRAM2_ADDR, addr).await,
        Sram2DataWrite { value } => ocp_reg_write(dev, OCP_SRAM2_DATA, value).await,
        PlaWordSetBits { addr, bits } => pla_word_set_bits(dev, addr, bits).await,
        PlaWordClrBits { addr, bits } => pla_word_clr_bits(dev, addr, bits).await,
        PlaWordWrite { addr, value } => ocp_write_word(dev, MCU_TYPE_PLA, addr, value).await,
        UsbWordSetBits { addr, bits } => {
            let cur = ocp_read_word(dev, MCU_TYPE_USB, addr).await?;
            ocp_write_word(dev, MCU_TYPE_USB, addr, cur | bits).await
        }
        MdioSetBits { reg, bits } => {
            let addr = OCP_BASE_MII + reg * 2;
            ocp_reg_set_bits(dev, addr, bits).await
        }
        UsbWordClrBits { addr, bits } => {
            let cur = ocp_read_word(dev, MCU_TYPE_USB, addr).await?;
            ocp_write_word(dev, MCU_TYPE_USB, addr, cur & !bits).await
        }
        UsbWordWrite { addr, value } => ocp_write_word(dev, MCU_TYPE_USB, addr, value).await,
        UsbWordTestAndClrBits { addr, bits } => {
            let cur = ocp_read_word(dev, MCU_TYPE_USB, addr).await?;
            if cur & bits != 0 {
                ocp_write_word(dev, MCU_TYPE_USB, addr, cur & !bits).await
            } else {
                Ok(())
            }
        }
        MdioTestAndClrBits { reg, bits } => {
            let addr = OCP_BASE_MII + reg * 2;
            let cur = ocp_reg_read(dev, addr).await?;
            if cur & bits != 0 {
                ocp_reg_write(dev, addr, cur & !bits).await
            } else {
                Ok(())
            }
        }
        MmdWrite {
            dev: mmd_dev,
            reg,
            value,
        } => {
            // Linux `r8152_mmd_write`: select the device/register
            // through `OCP_EEE_AR` / `OCP_EEE_DATA`, write the
            // value, deselect.
            ocp_reg_write(dev, OCP_EEE_AR, MMD_FUN_ADDR | mmd_dev).await?;
            ocp_reg_write(dev, OCP_EEE_DATA, reg).await?;
            ocp_reg_write(dev, OCP_EEE_AR, MMD_FUN_DATA | mmd_dev).await?;
            ocp_reg_write(dev, OCP_EEE_DATA, value).await?;
            ocp_reg_write(dev, OCP_EEE_AR, 0).await
        }
        UsbByteSetBits { addr, bits } => {
            let cur = ocp_read_byte(dev, MCU_TYPE_USB, addr).await?;
            ocp_write_byte(dev, MCU_TYPE_USB, addr, cur | bits).await
        }
        UsbByteClrBits { addr, bits } => {
            let cur = ocp_read_byte(dev, MCU_TYPE_USB, addr).await?;
            ocp_write_byte(dev, MCU_TYPE_USB, addr, cur & !bits).await
        }
        UsbByteWrite { addr, value } => ocp_write_byte(dev, MCU_TYPE_USB, addr, value).await,
        UsbDwordWrite { addr, value } => ocp_write_dword(dev, MCU_TYPE_USB, addr, value).await,
        PlaByteSetBits { addr, bits } => {
            let cur = ocp_read_byte(dev, MCU_TYPE_PLA, addr).await?;
            ocp_write_byte(dev, MCU_TYPE_PLA, addr, cur | bits).await
        }
        PlaByteClrBits { addr, bits } => {
            let cur = ocp_read_byte(dev, MCU_TYPE_PLA, addr).await?;
            ocp_write_byte(dev, MCU_TYPE_PLA, addr, cur & !bits).await
        }
        PlaByteWrite { addr, value } => ocp_write_byte(dev, MCU_TYPE_PLA, addr, value).await,
        MdioClrBits { reg, bits } => {
            let addr = OCP_BASE_MII + reg * 2;
            ocp_reg_clr_bits(dev, addr, bits).await
        }
        AutoloadPoll => {
            for _ in 0..500 {
                let boot = ocp_read_word(dev, MCU_TYPE_PLA, PLA_BOOT_CTRL).await?;
                if boot & AUTOLOAD_DONE != 0 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
            Ok(())
        }
        PhyStatusPollAny => {
            poll_phy_status_any(dev).await?;
            Ok(())
        }
        PhyStatusPollLanOn => {
            for _ in 0..500 {
                let status = ocp_reg_read(dev, OCP_PHY_STATUS).await? & PHY_STAT_MASK;
                if status == PHY_STAT_LAN_ON {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
            Ok(())
        }
        AldpsDisable => {
            ocp_reg_clr_bits(dev, OCP_POWER_CFG, POWER_CFG_EN_ALDPS).await?;
            for _ in 0..20 {
                let poll = ocp_read_word(dev, MCU_TYPE_PLA, PLA_ALDPS_POLL).await?;
                if poll & ALDPS_POLL_DONE != 0 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
            Ok(())
        }
        ApplyFirmware { mode } => {
            // Resolve `power_cut` from the PHY status, exactly
            // where Linux's `r8153_phy_status(tp, 0)` call sits
            // in each `*_hw_phy_cfg`.
            let (power_cut, clear_a466) = match mode {
                FirmwarePowerCut::Never => (false, false),
                FirmwarePowerCut::OnPwrdnOrExtInit => {
                    let status = poll_phy_status_any(dev).await?;
                    (
                        status == PHY_STAT_PWRDN || status == PHY_STAT_EXT_INIT,
                        false,
                    )
                }
                FirmwarePowerCut::OnExtInit { clear_a466 } => {
                    let status = poll_phy_status_any(dev).await?;
                    (status == PHY_STAT_EXT_INIT, clear_a466)
                }
            };
            if let Some(fw) = ctx.fw {
                match apply_firmware(dev, ctx.version, fw, power_cut).await {
                    Ok(()) => {}
                    // A failed validation is skipped, never a bind
                    // failure (Linux warn-and-continue; this crate
                    // has no logging sink, so the skip is silent
                    // here — the validation itself is covered by
                    // the pure `check_firmware` tests).
                    Err(FwError::Transfer) => return Err(()),
                    Err(_) => {}
                }
            }
            if power_cut {
                match mode {
                    FirmwarePowerCut::OnPwrdnOrExtInit => {
                        let addr = OCP_BASE_MII + MII_BMCR * 2;
                        ocp_reg_clr_bits(dev, addr, BMCR_PDOWN).await?;
                    }
                    FirmwarePowerCut::OnExtInit { .. } => {
                        if clear_a466 {
                            ocp_reg_clr_bits(dev, 0xA466, 0x0001).await?;
                        }
                        ocp_reg_clr_bits(dev, 0xA468, 0x0008 | 0x0002).await?;
                    }
                    FirmwarePowerCut::Never => {}
                }
            }
            Ok(())
        }
        PhyPatchRequest { request } => {
            if !phy_patch_request(dev, request, true).await? {
                // Request timed out: abort the rest of the
                // sequence (Linux returns from `*_hw_phy_cfg`).
                ctx.patch_aborted = true;
            }
            Ok(())
        }
        WaitLoadingFlash => {
            // Linux `r8156b_wait_loading_flash`: when the PHY
            // boots from flash and the bypass is off, poll for
            // `GPHY_PATCH_DONE` (best-effort, 100 × 1 ms).
            let gphy = ocp_read_word(dev, MCU_TYPE_PLA, PLA_GPHY_CTRL).await?;
            let usb_gphy = ocp_read_word(dev, MCU_TYPE_USB, USB_GPHY_CTRL).await?;
            if gphy & GPHY_CTRL_FLASH != 0 && usb_gphy & GPHY_CTRL_BYPASS_FLASH == 0 {
                for _ in 0..100 {
                    let cur = ocp_read_word(dev, MCU_TYPE_USB, USB_GPHY_CTRL).await?;
                    if cur & GPHY_CTRL_PATCH_DONE != 0 {
                        break;
                    }
                    narf_time::sleep_ms(1).await;
                }
            }
            Ok(())
        }
        AdcBiasFromEfuse => {
            // Linux `r8153b_hw_phy_cfg`: read efuse offset 0x7d
            // to get a 17-bit value, drop the dummy bit (bit 3)
            // to rebuild the real 16-bit value, write it to the
            // ADC ioffset unless it is 0xffff.
            let ocp_data = efuse_read(dev, 0x7D).await?;
            let data = (((ocp_data & 0x1FFF0) >> 1) | (ocp_data & 0x7)) as u16;
            if data != 0xFFFF {
                ocp_reg_write(dev, OCP_ADC_IOFFSET, data).await?;
            }
            Ok(())
        }
        UpsTimingFromSawCnt => {
            // Linux `r8153b_hw_phy_cfg`: rg_saw_cnt = OCP reg
            // 0xC426 bits [13:0]; swr_cnt_1ms_ini = 16000000 /
            // rg_saw_cnt, programmed into `USB_UPS_CFG` — skipped
            // when the count reads zero.
            let saw = ocp_reg_read(dev, 0xC426).await? & 0x3FFF;
            if saw != 0 {
                let swr = ((16_000_000u32 / u32::from(saw)) as u16) & UPS_CFG_SAW_CNT_1MS_MASK;
                let cur = ocp_read_word(dev, MCU_TYPE_USB, USB_UPS_CFG).await?;
                ocp_write_word(
                    dev,
                    MCU_TYPE_USB,
                    USB_UPS_CFG,
                    (cur & !UPS_CFG_SAW_CNT_1MS_MASK) | swr,
                )
                .await?;
            }
            Ok(())
        }
        MdiSwapIfReversed => mdi_swap_if_reversed(dev).await,
    }
}

/// Run the version-switched PHY init sequence for `version`
/// before CR RE/TE enable, applying the firmware blob `fw` at
/// Linux's position in the sequence (`None` when the registry
/// has no blob for the version — Linux's failed
/// `request_firmware`: warn and continue). Unknown and
/// not-yet-ported versions are a no-op (reset defaults), never a
/// bind failure.
pub async fn apply_phy_init(
    dev: &USBDevice,
    version: RtlVersion,
    fw: Option<&[u8]>,
) -> Result<(), ()> {
    let mut ctx = PhyInitCtx::new(version, fw);
    for op in phy_init_ops(version) {
        apply_phy_init_op(dev, &mut ctx, op).await?;
    }
    Ok(())
}

// ── Firmware loading (issue #1255) ───────────────────────────────
//
// Linux `drivers/net/usb/r8152.c` loads one firmware file per
// chip version (`rtl_fw_init`): the file is a 64-byte header (a
// 32-byte SHA-256 checksum over the version field to the end of
// the file, then a 32-byte version string) followed by blocks;
// each block is an 8-byte header (`type`, `length`) plus a
// type-specific body. `check_firmware` validates the whole file
// before `rtl8152_apply_firmware` walks it. The blobs
// themselves are NOT shipped in-tree: bind fetches the file for
// the version from the `narf_firmware` registry (see
// `firmware_name_for`) and the loader below consumes its bytes.
// No blob byte is embedded here or in any fixture — test images
// are built in-test from these layouts with checksums computed
// by the same SHA-256 implementation, and the real files were
// validated structurally off-line (see the PR body).
//
// Two deliberate deviations from Linux, both fail-closed:
//  - Linux's block walk would loop forever on a zero-length
//    block and reads block fields without bounds checks.
//    `check_firmware` rejects a zero-length block and every
//    field read below is bounds-checked against the block.
//  - Linux's apply helpers are `void` and swallow transfer
//    errors. NARF propagates them (`FwError::Transfer`) like
//    the table ops, so a dead device fails bind instead of
//    limping on with half-applied firmware — except the two
//    `generic_ocp_write` calls in `fw_mac_apply`, where Linux
//    explicitly returns from the block on failure and the loop
//    continues with the next block.

/// Firmware block types (Linux `rtl_fw_type`).
pub const RTL_FW_END: u32 = 0;
pub const RTL_FW_PLA: u32 = 1;
pub const RTL_FW_USB: u32 = 2;
pub const RTL_FW_PHY_START: u32 = 3;
pub const RTL_FW_PHY_STOP: u32 = 4;
pub const RTL_FW_PHY_NC: u32 = 5;
pub const RTL_FW_PHY_FIXUP: u32 = 6;
pub const RTL_FW_PHY_UNION_NC: u32 = 7;
pub const RTL_FW_PHY_UNION_NC1: u32 = 8;
pub const RTL_FW_PHY_UNION_NC2: u32 = 9;
pub const RTL_FW_PHY_UNION_UC2: u32 = 10;
pub const RTL_FW_PHY_UNION_UC: u32 = 11;
pub const RTL_FW_PHY_UNION_MISC: u32 = 12;
pub const RTL_FW_PHY_SPEED_UP: u32 = 13;
pub const RTL_FW_PHY_VER: u32 = 14;

/// Firmware file header size: 32-byte checksum + 32-byte
/// version string (Linux `struct fw_header`, `RTL_VER_SIZE` 32).
pub const FW_HEADER_LEN: usize = 64;
/// Firmware block header size: `type` + `length`
/// (Linux `struct fw_block`).
pub const FW_BLOCK_HDR_LEN: usize = 8;
/// `struct fw_mac` size (Linux, `__packed`).
pub const FW_MAC_LEN: usize = 63;
/// `struct fw_phy_nc` size (Linux, `__packed`).
pub const FW_PHY_NC_LEN: usize = 40;
/// `struct fw_phy_union` size (Linux, `__packed`).
pub const FW_PHY_UNION_LEN: usize = 58;
/// `struct fw_phy_fixup` / `struct fw_phy_ver` /
/// `struct fw_phy_patch_key` / `struct fw_phy_speed_up` size
/// (Linux, `__packed` — all four are 16 bytes).
pub const FW_PHY_SMALL_LEN: usize = 16;

/// Firmware file name for `version` (Linux `rtl_fw_init`),
/// or `None` when Linux loads no file for the version
/// (VER_01/02/03/07/08/10/12 — `apply_firmware` is a no-op
/// there). The names are the `MODULE_FIRMWARE` paths under
/// `rtl_nic/`; the registry holds the blob under the same name.
pub fn firmware_name_for(version: RtlVersion) -> Option<&'static str> {
    match version {
        RtlVersion::Ver04 => Some("rtl_nic/rtl8153a-2.fw"),
        RtlVersion::Ver05 => Some("rtl_nic/rtl8153a-3.fw"),
        RtlVersion::Ver06 => Some("rtl_nic/rtl8153a-4.fw"),
        RtlVersion::Ver09 => Some("rtl_nic/rtl8153b-2.fw"),
        RtlVersion::Ver11 => Some("rtl_nic/rtl8156a-2.fw"),
        RtlVersion::Ver13 | RtlVersion::Ver15 => Some("rtl_nic/rtl8156b-2.fw"),
        RtlVersion::Ver14 => Some("rtl_nic/rtl8153c-1.fw"),
        RtlVersion::Ver16 => Some("rtl_nic/rtl8157-1.fw"),
        RtlVersion::Ver17 => Some("rtl_nic/rtl8159-1.fw"),
        _ => None,
    }
}

/// Version string from a firmware image's header (the 32-byte
/// version field, up to the first NUL), or `""` when the image
/// is too small or the field is not valid UTF-8. Logging only —
/// never used to select behaviour.
pub fn firmware_version(fw: &[u8]) -> &str {
    if fw.len() < FW_HEADER_LEN {
        return "";
    }
    let raw = &fw[32..FW_HEADER_LEN];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    core::str::from_utf8(&raw[..end]).unwrap_or("")
}

/// Why a firmware image failed validation (or application).
/// `Transfer` is the only variant that fails bind — a dead
/// device mid-apply; every validation variant is skipped by
/// the executor, never a bind failure (Linux warn-and-continue).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// Image smaller than the 64-byte header.
    TooSmall,
    /// SHA-256 over `fw[32..]` does not match `fw[0..32]`.
    BadChecksum,
    /// A block header runs past the end of the image, or a
    /// block's length runs past it.
    Truncated,
    /// A zero-length block (Linux would loop forever here).
    ZeroLength,
    /// A block length that violates its type's rule (END not 8,
    /// PHY_START not 16, PHY_STOP not 8, FIXUP/VER not 16).
    BadLength,
    /// A block type seen twice where Linux allows it once
    /// (PLA, USB, PHY_NC/UNION_*, SPEED_UP, VER).
    Duplicate,
    /// A block in an order Linux forbids (START after any PHY
    /// block, STOP without START, a UNION/NC/VER after STOP or
    /// before START, …).
    OutOfOrder,
    /// START seen without a matching STOP by the end of the file.
    UnpairedStart,
    /// A block whose fields violate its type's per-version rule
    /// (`is_fw_mac_ok` / `is_fw_phy_nc_ok` /
    /// `is_fw_phy_union_ok` / `is_fw_phy_fixup_ok` /
    /// `is_fw_phy_speed_up_ok` / `is_fw_phy_ver_ok`).
    InvalidBlock,
    /// A USB transfer failed while applying the image.
    Transfer,
}

/// Little-endian readers over a block slice; `None` on a short
/// read (fail-closed — the caller treats it as invalid).
fn fw_le_u16(block: &[u8], off: usize) -> Option<u16> {
    block
        .get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn fw_le_u32(block: &[u8], off: usize) -> Option<u32> {
    block
        .get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// SHA-256 of `fw[32..]` against `fw[0..32]` (Linux
/// `rtl8152_fw_verify_checksum`).
pub fn fw_checksum_ok(fw: &[u8]) -> bool {
    if fw.len() < FW_HEADER_LEN {
        return false;
    }
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(&fw[32..]);
    h.finalize() == fw[..32]
}

/// Per-version `fw_mac` expectations (Linux
/// `rtl8152_is_fw_mac_ok`): `(fw_reg, bp_ba_addr, bp_en_addr,
/// bp_start, max_bp)`. `None` when the block type is invalid
/// for the version — PLA is invalid for VER_10/16/17, USB is
/// invalid for VER_01/02/07/10/16/17. Note VER_01/02/07 PLA
/// has `bp_en_addr = 0` (no enable register).
fn fw_mac_expect(version: RtlVersion, is_pla: bool) -> Option<(u16, u16, u16, u16, u16)> {
    if is_pla {
        match version {
            RtlVersion::Ver01 | RtlVersion::Ver02 | RtlVersion::Ver07 => {
                Some((0xF800, PLA_BP_BA, 0, PLA_BP_0, 8))
            }
            RtlVersion::Ver03
            | RtlVersion::Ver04
            | RtlVersion::Ver05
            | RtlVersion::Ver06
            | RtlVersion::Ver08
            | RtlVersion::Ver09
            | RtlVersion::Ver11
            | RtlVersion::Ver12
            | RtlVersion::Ver13
            | RtlVersion::Ver15 => Some((0xF800, PLA_BP_BA, PLA_BP_EN, PLA_BP_0, 8)),
            RtlVersion::Ver14 => Some((0xF800, PLA_BP_BA, USB_BP2_EN, PLA_BP_0, 16)),
            _ => None,
        }
    } else {
        match version {
            RtlVersion::Ver03 | RtlVersion::Ver04 | RtlVersion::Ver05 | RtlVersion::Ver06 => {
                Some((0xF800, PLA_BP_BA, PLA_BP_EN, PLA_BP_0, 8))
            }
            RtlVersion::Ver08
            | RtlVersion::Ver09
            | RtlVersion::Ver11
            | RtlVersion::Ver12
            | RtlVersion::Ver13
            | RtlVersion::Ver14
            | RtlVersion::Ver15 => Some((0xE600, PLA_BP_BA, USB_BP2_EN, PLA_BP_0, 16)),
            _ => None,
        }
    }
}

/// Linux `rtl8152_is_fw_mac_ok` over a block slice.
fn is_fw_mac_ok(version: RtlVersion, is_pla: bool, block: &[u8]) -> bool {
    let Some((fw_reg, bp_ba, bp_en, bp_start, max_bp)) = fw_mac_expect(version, is_pla) else {
        return false;
    };
    let Some(fw_offset) = fw_le_u16(block, 8) else {
        return false;
    };
    if (fw_offset as usize) < FW_MAC_LEN {
        return false;
    }
    let Some(length) = fw_le_u32(block, 4) else {
        return false;
    };
    if (length as usize) < fw_offset as usize {
        return false;
    }
    let data_len = length as usize - fw_offset as usize;
    if data_len < 4 || data_len & 3 != 0 {
        return false;
    }
    if fw_le_u16(block, 10) != Some(fw_reg)
        || fw_le_u16(block, 12) != Some(bp_ba)
        || fw_le_u16(block, 16) != Some(bp_en)
        || fw_le_u16(block, 20) != Some(bp_start)
    {
        return false;
    }
    let Some(bp_num) = fw_le_u16(block, 22) else {
        return false;
    };
    if bp_num > max_bp {
        return false;
    }
    for i in bp_num..max_bp {
        if fw_le_u16(block, 24 + 2 * i as usize) != Some(0) {
            return false;
        }
    }
    true
}

/// Linux `rtl8152_is_fw_phy_nc_ok` over a block slice (VER_04–
/// VER_06 only: `fw_reg` 0xa014, `ba_reg` 0xa012, `patch_en`
/// 0xa01a, `mode_reg` 0xb820, `bp_start` 0xa000, `bp_num` ≤ 4).
fn is_fw_phy_nc_ok(version: RtlVersion, block: &[u8]) -> bool {
    if !matches!(
        version,
        RtlVersion::Ver04 | RtlVersion::Ver05 | RtlVersion::Ver06
    ) {
        return false;
    }
    let Some(fw_offset) = fw_le_u16(block, 8) else {
        return false;
    };
    if (fw_offset as usize) < FW_PHY_NC_LEN {
        return false;
    }
    let Some(length) = fw_le_u32(block, 4) else {
        return false;
    };
    if (length as usize) < fw_offset as usize {
        return false;
    }
    let data_len = length as usize - fw_offset as usize;
    if data_len == 0 || data_len & 1 != 0 {
        return false;
    }
    if fw_le_u16(block, 10) != Some(0xA014)
        || fw_le_u16(block, 12) != Some(0xA012)
        || fw_le_u16(block, 16) != Some(0xA01A)
        || fw_le_u16(block, 20) != Some(0xB820)
        || fw_le_u16(block, 28) != Some(0xA000)
    {
        return false;
    }
    match fw_le_u16(block, 30) {
        Some(bp_num) => bp_num <= 4,
        None => false,
    }
}

/// Linux `rtl8152_is_fw_phy_union_ok` over a block slice
/// (VER_10/11/12/13/15 only: `fw_offset` ≥ 58, data length
/// even, `pre_num` ≤ 2, `bp_num` ≤ 8).
fn is_fw_phy_union_ok(version: RtlVersion, block: &[u8]) -> bool {
    if !matches!(
        version,
        RtlVersion::Ver10
            | RtlVersion::Ver11
            | RtlVersion::Ver12
            | RtlVersion::Ver13
            | RtlVersion::Ver15
    ) {
        return false;
    }
    let Some(fw_offset) = fw_le_u16(block, 8) else {
        return false;
    };
    if (fw_offset as usize) < FW_PHY_UNION_LEN {
        return false;
    }
    let Some(length) = fw_le_u32(block, 4) else {
        return false;
    };
    if (length as usize) <= fw_offset as usize {
        return false;
    }
    if (length as usize - fw_offset as usize) & 1 != 0 {
        return false;
    }
    match (block.get(56), block.get(57)) {
        (Some(&pre_num), Some(&bp_num)) => pre_num <= 2 && bp_num <= 8,
        _ => false,
    }
}

/// Linux `rtl8152_is_fw_phy_fixup_ok` over a block slice
/// (VER_10/11/12/13/15 only: length 16, `setting.addr` is
/// `OCP_PHY_PATCH_CMD`, `setting.data` is bit 7).
fn is_fw_phy_fixup_ok(version: RtlVersion, block: &[u8]) -> bool {
    if !matches!(
        version,
        RtlVersion::Ver10
            | RtlVersion::Ver11
            | RtlVersion::Ver12
            | RtlVersion::Ver13
            | RtlVersion::Ver15
    ) {
        return false;
    }
    if fw_le_u32(block, 4) != Some(FW_PHY_SMALL_LEN as u32) {
        return false;
    }
    fw_le_u16(block, 8) == Some(OCP_PHY_PATCH_CMD) && fw_le_u16(block, 10) == Some(0x0080)
}

/// Linux `rtl8152_is_fw_phy_speed_up_ok` over a block slice
/// (VER_13/15/16/17 only: `fw_offset` ≥ 16, data length a
/// multiple of 4, `fw_reg` 0x9A00).
fn is_fw_phy_speed_up_ok(version: RtlVersion, block: &[u8]) -> bool {
    if !matches!(
        version,
        RtlVersion::Ver13 | RtlVersion::Ver15 | RtlVersion::Ver16 | RtlVersion::Ver17
    ) {
        return false;
    }
    let Some(fw_offset) = fw_le_u16(block, 8) else {
        return false;
    };
    if (fw_offset as usize) < FW_PHY_SMALL_LEN {
        return false;
    }
    let Some(length) = fw_le_u32(block, 4) else {
        return false;
    };
    if (length as usize) <= fw_offset as usize {
        return false;
    }
    if (length as usize - fw_offset as usize) & 3 != 0 {
        return false;
    }
    fw_le_u16(block, 12) == Some(0x9A00)
}

/// Linux `rtl8152_is_fw_phy_ver_ok` over a block slice
/// (VER_10/11/12/13/15 only: length 16, `ver.addr` is
/// `SRAM_GPHY_FW_VER`).
fn is_fw_phy_ver_ok(version: RtlVersion, block: &[u8]) -> bool {
    if !matches!(
        version,
        RtlVersion::Ver10
            | RtlVersion::Ver11
            | RtlVersion::Ver12
            | RtlVersion::Ver13
            | RtlVersion::Ver15
    ) {
        return false;
    }
    if fw_le_u32(block, 4) != Some(FW_PHY_SMALL_LEN as u32) {
        return false;
    }
    fw_le_u16(block, 8) == Some(SRAM_GPHY_FW_VER)
}

/// Block-walk state for `check_firmware` (Linux's `fw_flags`
/// bitmask, as named fields).
#[derive(Default)]
struct FwWalk {
    pla: bool,
    usb: bool,
    start: bool,
    stop: bool,
    nc: bool,
    nc1: bool,
    nc2: bool,
    uc2: bool,
    uc: bool,
    speed_up: bool,
    ver: bool,
}

/// Validate a whole firmware image for `version` (Linux
/// `rtl8152_check_firmware`): header size, SHA-256 checksum,
/// then the block walk from offset 64, advancing
/// `i += ALIGN(length, 8)`. Unknown block types are warned and
/// skipped in Linux — here they are skipped silently (this
/// crate has no logging sink). A file with no END block is
/// accepted when START/STOP pair up, as in Linux.
pub fn check_firmware(version: RtlVersion, fw: &[u8]) -> Result<(), FwError> {
    if fw.len() < FW_HEADER_LEN {
        return Err(FwError::TooSmall);
    }
    if !fw_checksum_ok(fw) {
        return Err(FwError::BadChecksum);
    }
    let mut flags = FwWalk::default();
    let mut i = FW_HEADER_LEN;
    while i < fw.len() {
        if i + FW_BLOCK_HDR_LEN > fw.len() {
            return Err(FwError::Truncated);
        }
        let ty = fw_le_u32(fw, i).unwrap_or(u32::MAX);
        let len = fw_le_u32(fw, i + 4).unwrap_or(0) as usize;
        if len == 0 {
            return Err(FwError::ZeroLength);
        }
        if i + len > fw.len() {
            return Err(FwError::Truncated);
        }
        let block = &fw[i..i + len];
        match ty {
            RTL_FW_END => {
                if len != FW_BLOCK_HDR_LEN {
                    return Err(FwError::BadLength);
                }
                if flags.start && !flags.stop {
                    return Err(FwError::UnpairedStart);
                }
                return Ok(());
            }
            RTL_FW_PLA => {
                if flags.pla {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_mac_ok(version, true, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.pla = true;
            }
            RTL_FW_USB => {
                if flags.usb {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_mac_ok(version, false, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.usb = true;
            }
            RTL_FW_PHY_START => {
                if flags.start
                    || flags.nc
                    || flags.nc1
                    || flags.nc2
                    || flags.uc2
                    || flags.uc
                    || flags.stop
                {
                    return Err(FwError::OutOfOrder);
                }
                if len != FW_PHY_SMALL_LEN {
                    return Err(FwError::BadLength);
                }
                flags.start = true;
            }
            RTL_FW_PHY_STOP => {
                if flags.stop || !flags.start {
                    return Err(FwError::OutOfOrder);
                }
                if len != FW_BLOCK_HDR_LEN {
                    return Err(FwError::BadLength);
                }
                flags.stop = true;
            }
            RTL_FW_PHY_NC => {
                if !flags.start || flags.stop {
                    return Err(FwError::OutOfOrder);
                }
                if flags.nc {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_phy_nc_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.nc = true;
            }
            RTL_FW_PHY_UNION_NC => {
                if !flags.start || flags.nc1 || flags.nc2 || flags.uc2 || flags.uc || flags.stop {
                    return Err(FwError::OutOfOrder);
                }
                if flags.nc {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_phy_union_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.nc = true;
            }
            RTL_FW_PHY_UNION_NC1 => {
                if !flags.start || flags.nc2 || flags.uc2 || flags.uc || flags.stop {
                    return Err(FwError::OutOfOrder);
                }
                if flags.nc1 {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_phy_union_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.nc1 = true;
            }
            RTL_FW_PHY_UNION_NC2 => {
                if !flags.start || flags.uc2 || flags.uc || flags.stop {
                    return Err(FwError::OutOfOrder);
                }
                if flags.nc2 {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_phy_union_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.nc2 = true;
            }
            RTL_FW_PHY_UNION_UC2 => {
                if !flags.start || flags.uc || flags.stop {
                    return Err(FwError::OutOfOrder);
                }
                if flags.uc2 {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_phy_union_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.uc2 = true;
            }
            RTL_FW_PHY_UNION_UC => {
                if !flags.start || flags.stop {
                    return Err(FwError::OutOfOrder);
                }
                if flags.uc {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_phy_union_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.uc = true;
            }
            RTL_FW_PHY_UNION_MISC => {
                if !is_fw_phy_union_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
            }
            RTL_FW_PHY_FIXUP => {
                if !is_fw_phy_fixup_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
            }
            RTL_FW_PHY_SPEED_UP => {
                if flags.speed_up {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_phy_speed_up_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.speed_up = true;
            }
            RTL_FW_PHY_VER => {
                if flags.start
                    || flags.nc
                    || flags.nc1
                    || flags.nc2
                    || flags.uc2
                    || flags.uc
                    || flags.stop
                {
                    return Err(FwError::OutOfOrder);
                }
                if flags.ver {
                    return Err(FwError::Duplicate);
                }
                if !is_fw_phy_ver_ok(version, block) {
                    return Err(FwError::InvalidBlock);
                }
                flags.ver = true;
            }
            _ => {
                // Unknown type: warned and skipped in Linux.
            }
        }
        // Next block (Linux `i += ALIGN(length, 8)`).
        i += (len + 7) & !7;
    }
    if flags.start && !flags.stop {
        return Err(FwError::UnpairedStart);
    }
    Ok(())
}

/// Firmware-path chunked OCP write (Linux `generic_ocp_write`
/// with byteen 0xff, the only value the firmware path ever
/// uses, so no start/end byte-enable splitting): `size` and
/// `index` must be 4-aligned, `size` nonzero,
/// `index + size ≤ 0xffff`; data goes out in ≤ 512-byte control
/// transfers with `wIndex = mcu | BYTE_EN_DWORD`.
async fn generic_ocp_write(dev: &USBDevice, index: u16, data: &[u8], mcu: u16) -> Result<(), ()> {
    if data.is_empty() || data.len() & 3 != 0 || index & 3 != 0 {
        return Err(());
    }
    if u32::from(index) + data.len() as u32 > 0xFFFF {
        return Err(());
    }
    let mut off = 0usize;
    while off < data.len() {
        let n = core::cmp::min(512, data.len() - off);
        let wvalue = index.wrapping_add(off as u16);
        dev.control_out(
            REQT_WRITE,
            REQ_SET_REGS,
            wvalue,
            mcu | BYTE_EN_DWORD,
            &data[off..off + n],
        )
        .await
        .map_err(|_| ())?;
        off += n;
    }
    Ok(())
}

/// Clear the break points for one window (Linux
/// `rtl_clear_bp`): disable the enable register for the
/// version/window, burst zeros over the break-point registers,
/// wait 3 ms for the firmware to stop, then clear the base
/// address register.
async fn clear_bp(dev: &USBDevice, version: RtlVersion, mcu: u16) -> Result<(), ()> {
    let bp_num: usize = match version {
        RtlVersion::Ver08
        | RtlVersion::Ver09
        | RtlVersion::Ver10
        | RtlVersion::Ver11
        | RtlVersion::Ver12
        | RtlVersion::Ver13
        | RtlVersion::Ver15 => {
            if mcu == MCU_TYPE_USB {
                ocp_write_word(dev, MCU_TYPE_USB, USB_BP2_EN, 0).await?;
                16
            } else {
                ocp_write_byte(dev, mcu, PLA_BP_EN, 0).await?;
                8
            }
        }
        RtlVersion::Ver03 | RtlVersion::Ver04 | RtlVersion::Ver05 | RtlVersion::Ver06 => {
            ocp_write_byte(dev, mcu, PLA_BP_EN, 0).await?;
            8
        }
        RtlVersion::Ver01 | RtlVersion::Ver02 | RtlVersion::Ver07 => 8,
        _ => {
            ocp_write_word(dev, mcu, USB_BP2_EN, 0).await?;
            16
        }
    };
    // Return value ignored in Linux.
    let zeros = [0u8; 32];
    let _ = generic_ocp_write(dev, PLA_BP_0, &zeros[..bp_num * 2], mcu).await;
    // Wait 3 ms to make sure the firmware is stopped.
    narf_time::sleep_ms(3).await;
    ocp_write_word(dev, mcu, PLA_BP_BA, 0).await
}

/// Apply one PLA/USB firmware block (Linux
/// `rtl8152_fw_mac_apply`): skip when the stored version byte
/// (read from the USB window) is already at least the block's
/// version; otherwise clear the break points, apply the data,
/// program the break-point base/array/enable, and store the
/// version byte. A failed `generic_ocp_write` returns from the
/// block early (Linux's explicit check) while the loop
/// continues with the next block; other transfer errors
/// propagate.
async fn fw_mac_apply(
    dev: &USBDevice,
    version: RtlVersion,
    block: &[u8],
    is_pla: bool,
) -> Result<(), ()> {
    let mcu = if is_pla { MCU_TYPE_PLA } else { MCU_TYPE_USB };
    let fw_ver_reg = fw_le_u16(block, 60).unwrap_or(0);
    let fw_ver_data = block.get(62).copied().unwrap_or(0);
    if fw_ver_reg != 0 {
        let cur = ocp_read_byte(dev, MCU_TYPE_USB, fw_ver_reg).await?;
        if cur >= fw_ver_data {
            return Ok(());
        }
    }
    clear_bp(dev, version, mcu).await?;
    // Enable backup/restore of MACDBG. Required after clearing
    // PLA break points and before applying the PLA firmware.
    if version == RtlVersion::Ver04 && is_pla {
        let post = ocp_read_word(dev, MCU_TYPE_PLA, PLA_MACDBG_POST).await?;
        if post & MACDBG_DEBUG_OE == 0 {
            ocp_write_word(dev, MCU_TYPE_PLA, PLA_MACDBG_PRE, MACDBG_DEBUG_LTSSM).await?;
            ocp_write_word(dev, MCU_TYPE_PLA, PLA_MACDBG_POST, MACDBG_DEBUG_LTSSM).await?;
        }
    }
    let fw_offset = fw_le_u16(block, 8).unwrap_or(0) as usize;
    let fw_reg = fw_le_u16(block, 10).unwrap_or(0);
    let length = fw_le_u32(block, 4).unwrap_or(0) as usize;
    let data_len = length.saturating_sub(fw_offset);
    let data = block.get(fw_offset..fw_offset + data_len).unwrap_or(&[]);
    if generic_ocp_write(dev, fw_reg, data, mcu).await.is_err() {
        return Ok(());
    }
    let bp_ba_addr = fw_le_u16(block, 12).unwrap_or(0);
    let bp_ba_value = fw_le_u16(block, 14).unwrap_or(0);
    ocp_write_word(dev, mcu, bp_ba_addr, bp_ba_value).await?;
    let bp_start = fw_le_u16(block, 20).unwrap_or(0);
    let bp_num = fw_le_u16(block, 22).unwrap_or(0) as usize;
    let bp_len = (bp_num * 2).next_multiple_of(4);
    let bp_bytes = block.get(24..24 + bp_len).unwrap_or(&[]);
    if generic_ocp_write(dev, bp_start, bp_bytes, mcu)
        .await
        .is_err()
    {
        return Ok(());
    }
    let bp_en_addr = fw_le_u16(block, 16).unwrap_or(0);
    if bp_en_addr != 0 {
        let bp_en_value = fw_le_u16(block, 18).unwrap_or(0);
        ocp_write_word(dev, mcu, bp_en_addr, bp_en_value).await?;
    }
    if fw_ver_reg != 0 {
        ocp_write_byte(dev, MCU_TYPE_USB, fw_ver_reg, fw_ver_data).await?;
    }
    Ok(())
}

/// Apply one PHY_NC block (Linux `rtl8152_fw_phy_nc_apply`):
/// mode-pre, base address, burst the data through the SRAM
/// window, patch-enable, break points, mode-post.
async fn fw_phy_nc_apply(dev: &USBDevice, block: &[u8]) -> Result<(), ()> {
    let mode_reg = fw_le_u16(block, 20).unwrap_or(0);
    let mode_pre = fw_le_u16(block, 22).unwrap_or(0);
    let mode_post = fw_le_u16(block, 24).unwrap_or(0);
    let ba_reg = fw_le_u16(block, 12).unwrap_or(0);
    let ba_data = fw_le_u16(block, 14).unwrap_or(0);
    let patch_en_addr = fw_le_u16(block, 16).unwrap_or(0);
    let patch_en_value = fw_le_u16(block, 18).unwrap_or(0);
    let fw_reg = fw_le_u16(block, 10).unwrap_or(0);
    let bp_start = fw_le_u16(block, 28).unwrap_or(0);
    let bp_num = fw_le_u16(block, 30).unwrap_or(0) as usize;
    let fw_offset = fw_le_u16(block, 8).unwrap_or(0) as usize;
    let length = fw_le_u32(block, 4).unwrap_or(0) as usize;
    sram_write(dev, mode_reg, mode_pre).await?;
    sram_write(dev, ba_reg, ba_data).await?;
    let num = length.saturating_sub(fw_offset) / 2;
    ocp_reg_write(dev, OCP_SRAM_ADDR, fw_reg).await?;
    for k in 0..num {
        let v = fw_le_u16(block, fw_offset + 2 * k).unwrap_or(0);
        ocp_reg_write(dev, OCP_SRAM_DATA, v).await?;
    }
    sram_write(dev, patch_en_addr, patch_en_value).await?;
    let mut bp_index = bp_start;
    for k in 0..bp_num {
        let v = fw_le_u16(block, 32 + 2 * k).unwrap_or(0);
        sram_write(dev, bp_index, v).await?;
        bp_index += 2;
    }
    sram_write(dev, mode_reg, mode_post).await?;
    Ok(())
}

/// Apply one PHY union block (Linux
/// `rtl8152_fw_phy_union_apply`): pre-sets, burst the data
/// through the SRAM window, break points, break-point enable.
async fn fw_phy_union_apply(dev: &USBDevice, block: &[u8]) -> Result<(), ()> {
    let fw_offset = fw_le_u16(block, 8).unwrap_or(0) as usize;
    let fw_reg = fw_le_u16(block, 10).unwrap_or(0);
    let length = fw_le_u32(block, 4).unwrap_or(0) as usize;
    let pre_num = block.get(56).copied().unwrap_or(0) as usize;
    for k in 0..pre_num {
        let addr = fw_le_u16(block, 12 + 4 * k).unwrap_or(0);
        let data = fw_le_u16(block, 14 + 4 * k).unwrap_or(0);
        sram_write(dev, addr, data).await?;
    }
    let num = length.saturating_sub(fw_offset) / 2;
    ocp_reg_write(dev, OCP_SRAM_ADDR, fw_reg).await?;
    for k in 0..num {
        let v = fw_le_u16(block, fw_offset + 2 * k).unwrap_or(0);
        ocp_reg_write(dev, OCP_SRAM_DATA, v).await?;
    }
    let bp_num = block.get(57).copied().unwrap_or(0) as usize;
    for k in 0..bp_num {
        let addr = fw_le_u16(block, 20 + 4 * k).unwrap_or(0);
        let data = fw_le_u16(block, 22 + 4 * k).unwrap_or(0);
        sram_write(dev, addr, data).await?;
    }
    if bp_num != 0 {
        let bp_en_addr = fw_le_u16(block, 52).unwrap_or(0);
        if bp_en_addr != 0 {
            let bp_en_data = fw_le_u16(block, 54).unwrap_or(0);
            sram_write(dev, bp_en_addr, bp_en_data).await?;
        }
    }
    Ok(())
}

/// Apply one PHY fixup block (Linux `rtl8152_fw_phy_fixup`):
/// read-modify-write one OCP register per `bit_cmd`
/// (AND/OR/NOT/XOR). An unknown command applies nothing.
async fn fw_phy_fixup(dev: &USBDevice, block: &[u8]) -> Result<(), ()> {
    let addr = fw_le_u16(block, 8).unwrap_or(0);
    let setting = fw_le_u16(block, 10).unwrap_or(0);
    let bit_cmd = fw_le_u16(block, 12).unwrap_or(0);
    let cur = ocp_reg_read(dev, addr).await?;
    let new = match bit_cmd {
        0 => cur & setting,
        1 => cur | setting,
        2 => cur & !setting,
        3 => cur ^ setting,
        _ => return Ok(()),
    };
    ocp_reg_write(dev, addr, new).await
}

/// Apply one PHY version block (Linux `rtl8152_fw_phy_ver`):
/// when the stored version at `ver.addr` is already at least
/// the block's version, return 0 (patching is skipped for the
/// rest of the file); otherwise store the version and return
/// it (nonzero — patching continues).
async fn fw_phy_ver(dev: &USBDevice, block: &[u8]) -> Result<u16, ()> {
    let ver_addr = fw_le_u16(block, 8).unwrap_or(0);
    let ver = fw_le_u16(block, 10).unwrap_or(0);
    if sram_read(dev, ver_addr).await? >= ver {
        return Ok(0);
    }
    sram_write(dev, ver_addr, ver).await?;
    Ok(ver)
}

/// Set (or clear) the PHY patch key (Linux
/// `rtl_patch_key_set`): with a key, write it and lock the
/// SRAM; without one, unlock and clear the key register.
/// Linux's `PATCH_LOCK` is bit 0 — the same bit as
/// `PHY_PATCH_LOCK`.
async fn patch_key_set(dev: &USBDevice, key_addr: u16, patch_key: u16) -> Result<(), ()> {
    if patch_key != 0 && key_addr != 0 {
        sram_write(dev, key_addr, patch_key).await?;
        sram_write(dev, OCP_PHY_LOCK, PHY_LOCK_PATCH_LOCK).await?;
    } else if key_addr != 0 {
        sram_write(dev, 0x0000, 0x0000).await?;
        ocp_reg_clr_bits(dev, OCP_PHY_LOCK, PHY_LOCK_PATCH_LOCK).await?;
        sram_write(dev, key_addr, 0x0000).await?;
    }
    // key_addr == 0: Linux WARN_ON_ONCEs; nothing to do here.
    Ok(())
}

/// PHY_START step (Linux `rtl_pre_ram_code`): request the patch
/// and set the key. Returns `false` when the request timed
/// out — the caller ignores the result, as in Linux.
async fn pre_ram_code(
    dev: &USBDevice,
    key_addr: u16,
    patch_key: u16,
    wait: bool,
) -> Result<bool, ()> {
    if !phy_patch_request(dev, true, wait).await? {
        return Ok(false);
    }
    patch_key_set(dev, key_addr, patch_key).await?;
    Ok(true)
}

/// PHY_STOP step (Linux `rtl_post_ram_code`): clear the key and
/// release the patch.
async fn post_ram_code(dev: &USBDevice, key_addr: u16, wait: bool) -> Result<(), ()> {
    patch_key_set(dev, key_addr, 0).await?;
    let _ = phy_patch_request(dev, false, wait).await;
    Ok(())
}

/// Apply one SPEED_UP block (Linux `rtl_ram_code_speed_up`):
/// skip when the stored PHY firmware version is already at
/// least the block's; otherwise patch-request, stream the data
/// in 2048-byte chunks through the USB window, and release.
/// The `POL_GPHY_PATCH` poll yields between reads (the file's
/// no-busy-spin convention) where Linux does 1000 back-to-back
/// reads; a timed-out chunk stops the stream, as in Linux.
async fn ram_code_speed_up(dev: &USBDevice, block: &[u8], wait: bool) -> Result<(), ()> {
    let version = fw_le_u16(block, 10).unwrap_or(0);
    let fw_reg = fw_le_u16(block, 12).unwrap_or(0);
    let fw_offset = fw_le_u16(block, 8).unwrap_or(0) as usize;
    let length = fw_le_u32(block, 4).unwrap_or(0) as usize;
    if sram_read(dev, SRAM_GPHY_FW_VER).await? >= version {
        return Ok(());
    }
    let mut len = length.saturating_sub(fw_offset);
    let mut off = fw_offset;
    if !phy_patch_request(dev, true, wait).await? {
        return Ok(());
    }
    while len > 0 {
        let size = core::cmp::min(len, 2048);
        let cur = ocp_read_word(dev, MCU_TYPE_USB, USB_GPHY_CTRL).await?;
        ocp_write_word(
            dev,
            MCU_TYPE_USB,
            USB_GPHY_CTRL,
            cur | GPHY_CTRL_PATCH_DONE | GPHY_CTRL_BACKUP_RESTRORE,
        )
        .await?;
        // Return value ignored in Linux.
        let data = block.get(off..off + size).unwrap_or(&[]);
        let _ = generic_ocp_write(dev, fw_reg, data, MCU_TYPE_USB).await;
        off += size;
        len -= size;
        let cur = ocp_read_word(dev, MCU_TYPE_PLA, PLA_POL_GPIO_CTRL).await?;
        ocp_write_word(
            dev,
            MCU_TYPE_PLA,
            PLA_POL_GPIO_CTRL,
            cur | POL_GPIO_GPHY_PATCH,
        )
        .await?;
        let mut i = 0;
        loop {
            let cur = ocp_read_word(dev, MCU_TYPE_PLA, PLA_POL_GPIO_CTRL).await?;
            if cur & POL_GPIO_GPHY_PATCH == 0 || i >= 1000 {
                break;
            }
            narf_scheduler::yield_now().await;
            i += 1;
        }
        if i >= 1000 {
            break;
        }
    }
    let _ = phy_patch_request(dev, false, wait).await;
    Ok(())
}

/// Wait for the watchdog timer to be ready (Linux
/// `r8153_pre_firmware_1`): poll `USB_WDT1_CTRL` for `WTD1_EN`
/// clear, up to 104 × 1 ms.
async fn wait_wdt1_ready(dev: &USBDevice) -> Result<(), ()> {
    for _ in 0..104 {
        let v = ocp_read_byte(dev, MCU_TYPE_USB, USB_WDT1_CTRL).await?;
        if v & (WDT1_EN as u8) == 0 {
            break;
        }
        narf_time::sleep_ms(1).await;
    }
    Ok(())
}

/// USB-window word set-bits helper (read-modify-write).
async fn usb_word_set_bits(dev: &USBDevice, addr: u16, bits: u16) -> Result<(), ()> {
    let cur = ocp_read_word(dev, MCU_TYPE_USB, addr).await?;
    ocp_write_word(dev, MCU_TYPE_USB, addr, cur | bits).await
}

/// USB-window word clear-bits helper (read-modify-write).
async fn usb_word_clr_bits(dev: &USBDevice, addr: u16, bits: u16) -> Result<(), ()> {
    let cur = ocp_read_word(dev, MCU_TYPE_USB, addr).await?;
    ocp_write_word(dev, MCU_TYPE_USB, addr, cur & !bits).await
}

/// USB-window byte set-bits helper (read-modify-write).
async fn usb_byte_set_bits(dev: &USBDevice, addr: u16, bits: u8) -> Result<(), ()> {
    let cur = ocp_read_byte(dev, MCU_TYPE_USB, addr).await?;
    ocp_write_byte(dev, MCU_TYPE_USB, addr, cur | bits).await
}

/// Pre-firmware hook for `version` (Linux `rtl_fw_init`'s
/// `pre_fw`): VER_04 waits for the watchdog timer, VER_05
/// does that plus clearing `FW_FIX_SUSPEND`, VER_09/VER_14
/// enable the flow-control timer at 1 s. Other versions have
/// no pre hook.
async fn apply_pre_fw(dev: &USBDevice, version: RtlVersion) -> Result<(), ()> {
    match version {
        RtlVersion::Ver04 => wait_wdt1_ready(dev).await,
        RtlVersion::Ver05 => {
            wait_wdt1_ready(dev).await?;
            usb_word_clr_bits(dev, USB_FW_FIX_EN0, FW_FIX_SUSPEND).await
        }
        RtlVersion::Ver09 | RtlVersion::Ver14 => {
            ocp_write_word(
                dev,
                MCU_TYPE_USB,
                USB_FC_TIMER,
                FC_TIMER_CTRL_EN | (1000 / 8),
            )
            .await
        }
        _ => Ok(()),
    }
}

/// Post-firmware hook for `version` (Linux `rtl_fw_init`'s
/// `post_fw`): VER_04 sets the super-only break point when
/// forced-super and resets the UPHY timer to 36 ms; VER_05
/// adds the U3P3 check, `FW_FIX_SUSPEND` and USB2-PHY
/// L1/suspend; VER_06 sets USB2-PHY L1/suspend plus
/// `FW_IP_RESET_EN`; VER_09 enables the BND break point, the
/// flow-control patch and `FW_IP_RESET_EN`; VER_11 sets
/// `FW_IP_RESET_EN` and writes the U3-PHY MDCMDIO pair; VER_14
/// sets the flow-control patch 2. Other versions have no post
/// hook.
async fn apply_post_fw(dev: &USBDevice, version: RtlVersion) -> Result<(), ()> {
    match version {
        RtlVersion::Ver04 => {
            if ocp_read_byte(dev, MCU_TYPE_USB, USB_CSTMR).await? & (CSTMR_FORCE_SUPER as u8) != 0 {
                ocp_write_word(dev, MCU_TYPE_USB, USB_BP_4, BP4_SUPER_ONLY).await?;
            }
            ocp_write_word(dev, MCU_TYPE_PLA, PLA_UPHY_TIMER, 36000 / 16).await
        }
        RtlVersion::Ver05 => {
            if ocp_read_byte(dev, MCU_TYPE_USB, USB_CSTMR).await? & (CSTMR_FORCE_SUPER as u8) != 0 {
                pla_word_set_bits(dev, PLA_BP_EN, 0x0001).await?;
            }
            ocp_write_word(dev, MCU_TYPE_PLA, PLA_UPHY_TIMER, 36000 / 16).await?;
            ocp_write_word(
                dev,
                MCU_TYPE_PLA,
                PLA_EXTRA_STATUS,
                EXTRA_STATUS_U3P3_CHECK_EN | 4,
            )
            .await?;
            usb_word_set_bits(dev, USB_FW_FIX_EN0, FW_FIX_SUSPEND).await?;
            usb_byte_set_bits(dev, USB_USB2PHY, USB2PHY_L1 | USB2PHY_SUSPEND).await
        }
        RtlVersion::Ver06 => {
            usb_byte_set_bits(dev, USB_USB2PHY, USB2PHY_L1 | USB2PHY_SUSPEND).await?;
            usb_word_set_bits(dev, USB_FW_FIX_EN1, FW_FIX_IP_RESET_EN).await
        }
        RtlVersion::Ver09 => {
            if ocp_read_byte(dev, MCU_TYPE_USB, USB_MISC_1).await? & (MISC_1_BND_MASK as u8) != 0 {
                pla_word_set_bits(dev, PLA_BP_EN, 0x0001).await?;
            }
            usb_word_set_bits(dev, USB_FW_CTRL, FW_CTRL_FLOW_CTRL_PATCH_OPT).await?;
            usb_word_set_bits(dev, USB_FW_TASK, FW_TASK_FC_PATCH).await?;
            usb_word_set_bits(dev, USB_FW_FIX_EN1, FW_FIX_IP_RESET_EN).await
        }
        RtlVersion::Ver11 => {
            usb_word_set_bits(dev, USB_FW_FIX_EN1, FW_FIX_IP_RESET_EN).await?;
            ocp_write_dword(dev, MCU_TYPE_USB, USB_UPHY3_MDCMDIO, 0x4026_840E).await?;
            ocp_write_dword(dev, MCU_TYPE_USB, USB_UPHY3_MDCMDIO, 0x4001_ACC9).await
        }
        RtlVersion::Ver14 => {
            usb_word_set_bits(dev, USB_FW_CTRL, FW_CTRL_FLOW_CTRL_PATCH_2).await?;
            usb_word_set_bits(dev, USB_FW_TASK, FW_TASK_FC_PATCH).await
        }
        _ => Ok(()),
    }
}

/// Apply a validated firmware image for `version` (Linux
/// `rtl8152_apply_firmware`): pre hook, then the block walk
/// from offset 64 advancing `i += ALIGN(length, 8)` — END
/// stops the walk, unknown types are skipped — then the post
/// hook. `patch_phy` starts set and is cleared by a PHY_VER
/// block whose version is already stored (later patch blocks
/// are then skipped); PHY_NC applies regardless. Validation
/// failures surface as `FwError` (never a bind failure — the
/// executor records and skips them); transfer errors surface
/// as `FwError::Transfer`.
pub async fn apply_firmware(
    dev: &USBDevice,
    version: RtlVersion,
    fw: &[u8],
    power_cut: bool,
) -> Result<(), FwError> {
    check_firmware(version, fw)?;
    // `rtl_reset_ocp_base` is a no-op in NARF (no ocp_base
    // cache; the OCP accessors always write the base first).
    apply_pre_fw(dev, version)
        .await
        .map_err(|_| FwError::Transfer)?;
    let mut patch_phy = true;
    let mut key_addr = 0u16;
    let mut i = FW_HEADER_LEN;
    while i < fw.len() {
        let ty = fw_le_u32(fw, i).unwrap_or(RTL_FW_END);
        let len = fw_le_u32(fw, i + 4).unwrap_or(0) as usize;
        if len == 0 {
            break;
        }
        let block = &fw[i..core::cmp::min(i + len, fw.len())];
        match ty {
            RTL_FW_END => break,
            RTL_FW_PLA => {
                fw_mac_apply(dev, version, block, true)
                    .await
                    .map_err(|_| FwError::Transfer)?;
            }
            RTL_FW_USB => {
                fw_mac_apply(dev, version, block, false)
                    .await
                    .map_err(|_| FwError::Transfer)?;
            }
            RTL_FW_PHY_START => {
                if patch_phy {
                    let key_reg = fw_le_u16(block, 8).unwrap_or(0);
                    let key_data = fw_le_u16(block, 10).unwrap_or(0);
                    key_addr = key_reg;
                    let _ = pre_ram_code(dev, key_addr, key_data, !power_cut).await;
                }
            }
            RTL_FW_PHY_STOP => {
                if patch_phy {
                    let _ = post_ram_code(dev, key_addr, !power_cut).await;
                }
            }
            RTL_FW_PHY_NC => {
                fw_phy_nc_apply(dev, block)
                    .await
                    .map_err(|_| FwError::Transfer)?;
            }
            RTL_FW_PHY_VER => {
                patch_phy = fw_phy_ver(dev, block)
                    .await
                    .map_err(|_| FwError::Transfer)?
                    != 0;
            }
            RTL_FW_PHY_UNION_NC
            | RTL_FW_PHY_UNION_NC1
            | RTL_FW_PHY_UNION_NC2
            | RTL_FW_PHY_UNION_UC2
            | RTL_FW_PHY_UNION_UC
            | RTL_FW_PHY_UNION_MISC => {
                if patch_phy {
                    fw_phy_union_apply(dev, block)
                        .await
                        .map_err(|_| FwError::Transfer)?;
                }
            }
            RTL_FW_PHY_FIXUP => {
                if patch_phy {
                    fw_phy_fixup(dev, block)
                        .await
                        .map_err(|_| FwError::Transfer)?;
                }
            }
            RTL_FW_PHY_SPEED_UP => {
                ram_code_speed_up(dev, block, !power_cut)
                    .await
                    .map_err(|_| FwError::Transfer)?;
            }
            _ => {}
        }
        i += (len + 7) & !7;
    }
    apply_post_fw(dev, version)
        .await
        .map_err(|_| FwError::Transfer)?;
    Ok(())
}

/// RX coalesce timeout in us for a negotiated USB speed (Linux
/// `r8153_init`'s speed switch: Super/SuperPlus → `COALESCE_SUPER`,
/// High → `COALESCE_HIGH`, anything slower → `COALESCE_SLOW`).
pub fn coalesce_for_speed(speed: crate::xhci::PortSpeed) -> u32 {
    use crate::xhci::PortSpeed;
    match speed {
        PortSpeed::Super | PortSpeed::SuperPlus => COALESCE_SUPER,
        PortSpeed::High => COALESCE_HIGH,
        _ => COALESCE_SLOW,
    }
}

/// The `r8153_init` USB/LPM init sequence for the original RTL8153
/// family, in Linux's order, as pure [`PhyInitOp`] data. `speed` is
/// the negotiated USB speed, `burst_size` the pre-read
/// `USB_BURST_SIZE` word, and `link_ok` the pre-read
/// `PLA_PHYSTATUS` link bit — all three are sampled by bind before
/// the sequence runs (none of the earlier steps changes them), so
/// the builder stays pure and fixtures can pin the whole
/// conversation without hardware. Returns an empty sequence for
/// every other version — those families keep reset defaults until
/// their own init layers are ported.
///
/// Deliberately NOT modelled here (see bind): the host-side
/// `usb_enable_lpm` call (NARF's xHCI stack has no LPM enable yet;
/// the device-side `USB_LPM_CTRL` byte below is still programmed)
/// and the Dell TB16 RX-aggregation quirk (Linux keys it on
/// bcdDevice 0x3011 + dock serial strings, which bind does not
/// read — the normal branch runs instead).
pub fn r8153_init_ops(
    version: RtlVersion,
    speed: crate::xhci::PortSpeed,
    burst_size: u16,
    link_ok: bool,
) -> Vec<PhyInitOp> {
    use crate::xhci::PortSpeed;
    use PhyInitOp::*;
    match version {
        RtlVersion::Ver03 | RtlVersion::Ver04 | RtlVersion::Ver05 | RtlVersion::Ver06 => {}
        _ => return Vec::new(),
    }
    let mut ops = vec![
        // U1/U2 off while the device initialises.
        UsbDwordWrite {
            addr: USB_TOLERANCE,
            value: 0,
        },
        UsbDwordWrite {
            addr: USB_TOLERANCE + 4,
            value: 0,
        },
        // Wait for the firmware autoload to finish (best-effort).
        AutoloadPoll,
        // PHY up to a stable state (any of LAN_ON / PWRDN /
        // EXT_INIT).
        PhyStatusPollAny,
    ];
    // ADC tuning, VER_03/04/05 only.
    if matches!(
        version,
        RtlVersion::Ver03 | RtlVersion::Ver04 | RtlVersion::Ver05
    ) {
        ops.push(OcpRegWrite {
            addr: OCP_ADC_CFG,
            value: ADC_CFG_8153,
        });
    }
    ops.extend([
        // Clear the PHY power-down bit, then wait for LAN_ON.
        MdioClrBits {
            reg: MII_BMCR,
            bits: BMCR_PDOWN,
        },
        PhyStatusPollLanOn,
        // U3 off while the version branches run.
        UsbWordClrBits {
            addr: USB_U2P3_CTRL,
            bits: U2P3_ENABLE,
        },
    ]);
    match version {
        RtlVersion::Ver04 => {
            // `w0w1(mask, value)` as a clear-then-set pair.
            ops.extend([
                UsbWordClrBits {
                    addr: USB_SSPHYLINK2,
                    bits: SSPHYLINK2_PWD_DN_SCALE_MASK,
                },
                UsbWordSetBits {
                    addr: USB_SSPHYLINK2,
                    bits: SSPHYLINK2_PWD_DN_SCALE_96,
                },
                UsbByteSetBits {
                    addr: USB_USB2PHY,
                    bits: USB2PHY_L1 | USB2PHY_SUSPEND,
                },
            ]);
        }
        RtlVersion::Ver05 => {
            ops.push(PlaByteClrBits {
                addr: PLA_DMY_REG0,
                bits: DMY_ECM_ALDPS,
            });
            ops.push(if burst_size == 0 {
                UsbByteClrBits {
                    addr: USB_CSR_DUMMY1,
                    bits: DYNAMIC_BURST,
                }
            } else {
                UsbByteSetBits {
                    addr: USB_CSR_DUMMY1,
                    bits: DYNAMIC_BURST,
                }
            });
        }
        RtlVersion::Ver06 => {
            ops.push(if burst_size == 0 {
                UsbByteClrBits {
                    addr: USB_CSR_DUMMY1,
                    bits: DYNAMIC_BURST,
                }
            } else {
                UsbByteSetBits {
                    addr: USB_CSR_DUMMY1,
                    bits: DYNAMIC_BURST,
                }
            });
            // Queue-wake off, then the link-status bits.
            ops.extend([
                PlaByteClrBits {
                    addr: PLA_INDICATE_FALG,
                    bits: INDICATE_UPCOMING_RUNTIME_D3,
                },
                PlaByteClrBits {
                    addr: PLA_SUSPEND_FLAG,
                    bits: SUSPEND_LINK_CHG_EVENT,
                },
                PlaWordClrBits {
                    addr: PLA_EXTRA_STATUS,
                    bits: EXTRA_STATUS_LINK_CHANGE_FLAG,
                },
            ]);
            if link_ok {
                ops.push(PlaWordSetBits {
                    addr: PLA_EXTRA_STATUS,
                    bits: EXTRA_STATUS_CUR_LINK_OK | EXTRA_STATUS_POLL_LINK_CHG,
                });
            } else {
                // `w0w1(clear CUR_LINK_OK, set POLL_LINK_CHG)`.
                ops.extend([
                    PlaWordClrBits {
                        addr: PLA_EXTRA_STATUS,
                        bits: EXTRA_STATUS_CUR_LINK_OK,
                    },
                    PlaWordSetBits {
                        addr: PLA_EXTRA_STATUS,
                        bits: EXTRA_STATUS_POLL_LINK_CHG,
                    },
                ]);
            }
        }
        _ => {}
    }
    // LPM timer: 500 ms only for VER_04 below SuperSpeed.
    let lpm_timer = if matches!(version, RtlVersion::Ver04)
        && !matches!(speed, PortSpeed::Super | PortSpeed::SuperPlus)
    {
        LPM_CTRL_TIMER_500MS
    } else {
        LPM_CTRL_TIMER_500US
    };
    ops.extend([
        // Endpoint-4 full flow control, watchdog-11 off, LED mode
        // bits cleared.
        UsbByteSetBits {
            addr: USB_CSR_DUMMY2,
            bits: EP4_FULL_FC,
        },
        UsbWordClrBits {
            addr: USB_WDT11_CTRL,
            bits: TIMER11_EN,
        },
        PlaWordClrBits {
            addr: PLA_LED_FEATURE,
            bits: LED_MODE_MASK,
        },
        // LPM control byte.
        UsbByteWrite {
            addr: USB_LPM_CTRL,
            value: LPM_CTRL_FIFO_EMPTY_1FB | LPM_CTRL_ROK_EXIT_LPM | lpm_timer,
        },
        // AFE sensitivity: normal value + RX-idle select.
        UsbWordClrBits {
            addr: USB_AFE_CTRL2,
            bits: AFE_SEN_VAL_MASK,
        },
        UsbWordSetBits {
            addr: USB_AFE_CTRL2,
            bits: AFE_SEN_VAL_NORMAL | AFE_SEL_RXIDLE,
        },
        // Connect timer to its minimum.
        UsbWordWrite {
            addr: USB_CONNECT_TIMER,
            value: 0x0001,
        },
        // Power-cut off.
        UsbWordClrBits {
            addr: USB_POWER_CUT,
            bits: PWR_EN | PHASE2_EN,
        },
        UsbWordClrBits {
            addr: USB_MISC_0,
            bits: PCUT_STATUS,
        },
        // Runtime-suspend disable: restoring saved WoL is a no-op
        // at bind (nothing changed WoL yet); link-off-wake off
        // behind the CRWECR dance.
        PlaByteWrite {
            addr: PLA_CRWECR,
            value: CRWECR_CONFIG,
        },
        PlaWordClrBits {
            addr: PLA_CONFIG34,
            bits: CONFIG34_LINK_OFF_WAKE_EN,
        },
        PlaByteWrite {
            addr: PLA_CRWECR,
            value: CRWECR_NORMAL,
        },
        // MAC clock speed-down off.
        PlaWordClrBits {
            addr: PLA_MAC_PWR_CTRL2,
            bits: MAC_CLK_SPDWN_EN,
        },
        // U1/U2 back on (host-side LPM enable is a stack gap —
        // see the doc comment above).
        UsbDwordWrite {
            addr: USB_TOLERANCE,
            value: 0xFFFF_FFFF,
        },
        UsbDwordWrite {
            addr: USB_TOLERANCE + 4,
            value: 0xFFFF_FFFF,
        },
        // LAN-wake clear enable, LAN-wake pin off.
        PlaByteSetBits {
            addr: PLA_CONFIG6,
            bits: CONFIG6_LANWAKE_CLR_EN,
        },
        PlaByteClrBits {
            addr: PLA_LWAKE_CTRL_REG,
            bits: LWAKE_LANWAKE_PIN,
        },
        // RX aggregation on (normal branch — the Dell TB16 quirk
        // is not modelled; see the doc comment above).
        UsbWordClrBits {
            addr: USB_USB_CTRL,
            bits: USB_CTRL_RX_AGG_DISABLE | USB_CTRL_RX_ZERO_EN,
        },
        // Tally counters reset.
        PlaWordSetBits {
            addr: PLA_RSTTALLY,
            bits: TALLY_RESET,
        },
    ]);
    ops
}

/// Run the version-switched USB/LPM init sequence for `version`
/// before the PHY init sequence. Unknown and not-yet-ported
/// versions are a no-op (reset defaults), never a bind failure.
pub async fn apply_usb_init(
    dev: &USBDevice,
    version: RtlVersion,
    speed: crate::xhci::PortSpeed,
    burst_size: u16,
    link_ok: bool,
) -> Result<(), ()> {
    // The USB/LPM layer never contains the firmware or patch
    // steps, so the context carries no blob.
    let mut ctx = PhyInitCtx::new(version, None);
    for op in r8153_init_ops(version, speed, burst_size, link_ok) {
        apply_phy_init_op(dev, &mut ctx, op).await?;
    }
    Ok(())
}

// ── Pure datapath helpers (fixture-pinned) ───────────────────────

/// Extract and validate the station address from an 8-byte
/// station-address register read (IDR or BACKUP). Returns `None`
/// for the unprogrammed patterns (all-zero, all-ones) and for
/// multicast addresses — the caller falls back to the other
/// register, then fails the bind.
pub fn mac_from_station_bytes(raw: &[u8; 8]) -> Option<[u8; 6]> {
    let mac: [u8; 6] = raw[..6].try_into().ok()?;
    if mac.iter().all(|&b| b == 0) || mac.iter().all(|&b| b == 0xFF) {
        return None;
    }
    if mac[0] & 1 != 0 {
        return None; // multicast bit set — not a station address
    }
    Some(mac)
}

/// The `PLA_RCR` value for normal operation: keep the device's
/// other configuration bits, drop promiscuous, accept unicast to
/// us + multicast + broadcast.
pub fn rcr_with_accept_filters(old: u32) -> u32 {
    (old & !RCR_AAP) | RCR_APM | RCR_AM | RCR_AB
}

/// Decode a `PLA_PHYSTATUS` byte into
/// `(carrier, speed_mbps, duplex)` for `iface::set_link_metadata`.
pub fn decode_link_status(byte: u8) -> (bool, Option<u32>, Option<narf_net::iface::LinkDuplex>) {
    if byte & PHYSTAT_LINK == 0 {
        return (false, None, None);
    }
    let speed = if byte & PHYSTAT_1000M != 0 {
        Some(1000)
    } else if byte & PHYSTAT_100M != 0 {
        Some(100)
    } else if byte & PHYSTAT_10M != 0 {
        Some(10)
    } else {
        None
    };
    let duplex = if byte & PHYSTAT_FULL_DUP != 0 {
        Some(narf_net::iface::LinkDuplex::Full)
    } else {
        Some(narf_net::iface::LinkDuplex::Half)
    };
    (true, speed, duplex)
}

/// One frame located inside an RX aggregation buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxSegment {
    /// Byte offset of the frame within the aggregation buffer.
    pub offset: usize,
    /// Delivered frame length in bytes (descriptor excluded,
    /// and the trailing FCS stripped — see
    /// [`parse_rx_aggregate`]).
    pub len: usize,
    /// 802.1Q tag the chip stripped and reported in `rx_desc`
    /// `opts2` (`RX_VLAN_TAG_BIT`), or `None` when the segment
    /// carries no VLAN tag. The pump splices a reported tag
    /// back into the delivered frame (see `insert_vlan_tag`).
    pub vlan_tag: Option<u16>,
    /// RX checksum verdict decoded from the `rx_desc` `opts2` /
    /// `opts3` report bits (see [`rx_csum_result`]). The pump
    /// drops `Bad` segments per [`rx_segment_deliverable`].
    pub csum: RxCsumResult,
}

/// Extract the VLAN tag (TCI) from an `rx_desc` `opts2` word:
/// bit 16 marks a tag, the low 16 bits carry it byte-swapped
/// (Linux `r8152_rx_vlan_tag` applies `swab16` to recover the
/// TCI).
pub fn rx_vlan_tag_from_opts2(opts2: u32) -> Option<u16> {
    if opts2 & RX_VLAN_TAG_BIT != 0 {
        Some(((opts2 & 0xFFFF) as u16).swap_bytes())
    } else {
        None
    }
}

/// What the device concluded about a received frame's checksums,
/// decoded from the v1 `rx_desc` report bits (Linux
/// `r8152_rx_csum`). The RTL8157 v2 descriptor carries the same
/// verdict in different bit positions — see
/// [`rx_csum_result_v2`] (Linux `r8157_rx_csum`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    /// The device did not examine L3/L4 (non-IP frame, or no
    /// checked protocol). Delivered as before; the stack does
    /// not verify RX checksums, so nothing changes for these.
    NotChecked,
    /// Checked and correct.
    Good,
    /// Checked and wrong: `ip` = IP header checksum failed,
    /// `l4` = transport checksum failed.
    Bad { ip: bool, l4: bool },
}

/// Decode the RX checksum verdict from a v1 `rx_desc` `opts2` /
/// `opts3` pair, mirroring Linux `r8152_rx_csum` with one
/// fail-closed deviation: Linux's final `CHECKSUM_NONE` branch
/// conflates "checked and failed" with "not checked" (both go to
/// the stack, which re-verifies in software). NARF's stack has
/// no RX software-verification consumer, so this function must
/// distinguish them — any checked protocol failed means `Bad`,
/// even on a contradictory descriptor (Linux would
/// optimistically return `CHECKSUM_UNNECESSARY` if a later L4
/// branch hits; a corrupt descriptor must not pass here).
/// Fail bits for protocols the device did not mark checked are
/// ignored, as in Linux.
pub fn rx_csum_result(opts2: u32, opts3: u32) -> RxCsumResult {
    if opts2 & (RD_IPV4_CS | RD_IPV6_CS) == 0 {
        return RxCsumResult::NotChecked;
    }
    let ip_fail = opts2 & RD_IPV4_CS != 0 && opts3 & RX_IPF != 0;
    let l4_fail = (opts2 & RD_UDP_CS != 0 && opts3 & RX_UDPF != 0)
        || (opts2 & RD_TCP_CS != 0 && opts3 & RX_TCPF != 0);
    if ip_fail || l4_fail {
        return RxCsumResult::Bad {
            ip: ip_fail,
            l4: l4_fail,
        };
    }
    let l4_ok = (opts2 & RD_UDP_CS != 0 && opts3 & RX_UDPF == 0)
        || (opts2 & RD_TCP_CS != 0 && opts3 & RX_TCPF == 0);
    if l4_ok {
        RxCsumResult::Good
    } else {
        RxCsumResult::NotChecked
    }
}

/// Whether a chip version uses the v2 packet descriptor format
/// (Linux `rtl_ops_init`: only `RTL_VER_16` — the RTL8157 —
/// selects `r8157_desc_init`; every other version selects
/// `r8152_desc_init`). The RTL8159 is documented in the same
/// upstream series as sharing the v2 format, but Linux master
/// carries no version id for it, so it is not selected here
/// until its `PLA_TCR1` id is known.
pub fn uses_rx_desc_v2(version: RtlVersion) -> bool {
    matches!(version, RtlVersion::Ver16)
}

/// Decode the raw frame length from a v2 `rx_desc_v2` `opts1`
/// word (Linux `r8157_rx_len` / `rx_v2_get_len`): bits 17..31.
/// The value INCLUDES the trailing FCS (`RX_FCS_LEN`); the
/// walk strips it before reporting the segment length.
pub fn rx_len_v2(opts1: u32) -> u32 {
    (opts1 & RX_V2_LEN_MASK) >> RX_V2_LEN_SHIFT
}

/// Extract the VLAN tag (TCI) from a v2 `rx_desc_v2` word pair:
/// `opts1` bit 3 marks a tag (Linux `RX_VLAN_TAG_2`) and the
/// TCI sits in the HIGH half of `opts2`, byte-swapped (Linux
/// `r8157_rx_vlan_tag` applies `swab16` to `(opts2 >> 16) &
/// 0xffff`). Note the two moves from v1: the present-bit left
/// `opts2` for `opts1`, and the TCI moved from the low half of
/// `opts2` to the high half.
pub fn rx_vlan_tag_v2(opts1: u32, opts2: u32) -> Option<u16> {
    if opts1 & RX_V2_VLAN_TAG_BIT != 0 {
        Some((((opts2 >> 16) & 0xFFFF) as u16).swap_bytes())
    } else {
        None
    }
}

/// Decode the RX checksum verdict from a v2 `rx_desc_v2`
/// `opts3` word, mirroring Linux `r8157_rx_csum` with the same
/// fail-closed deviation as [`rx_csum_result`]: Linux's
/// `CHECKSUM_NONE` conflates "checked and failed" with "not
/// checked" (both go to the stack, which re-verifies in
/// software). NARF's stack has no RX software-verification
/// consumer, so this function must distinguish them — any
/// checked protocol failed means `Bad`, even when Linux's
/// first branch (IPv4 examined + IP fail) would return `NONE`
/// before looking at a passing L4 result. All report and fail
/// bits live in `opts3` here (v1 splits them across `opts2` /
/// `opts3`); fail bits for protocols the device did not mark
/// checked are ignored, as in Linux.
pub fn rx_csum_result_v2(opts3: u32) -> RxCsumResult {
    if opts3 & (RD_IPV4_CS_V2 | RD_IPV6_CS_V2) == 0 {
        return RxCsumResult::NotChecked;
    }
    let ip_fail = opts3 & RD_IPV4_CS_V2 != 0 && opts3 & RX_IPF_V2 != 0;
    let l4_fail = (opts3 & RD_UDP_CS_V2 != 0 && opts3 & RX_UDPF_V2 != 0)
        || (opts3 & RD_TCP_CS_V2 != 0 && opts3 & RX_TCPF_V2 != 0);
    if ip_fail || l4_fail {
        return RxCsumResult::Bad {
            ip: ip_fail,
            l4: l4_fail,
        };
    }
    let l4_ok = (opts3 & RD_UDP_CS_V2 != 0 && opts3 & RX_UDPF_V2 == 0)
        || (opts3 & RD_TCP_CS_V2 != 0 && opts3 & RX_TCPF_V2 == 0);
    if l4_ok {
        RxCsumResult::Good
    } else {
        RxCsumResult::NotChecked
    }
}

/// Walk an RTL8157 (v2) RX aggregation buffer into its frames,
/// mirroring Linux's `rx_bottom` walk with `r8157_desc_init`'s
/// geometry: 16-byte descriptors, the length field counting
/// frame + FCS (stripped here, so `RxSegment.len` stays
/// "delivered frame bytes"), and the next descriptor at the
/// next 16-byte boundary. Stops at the first segment whose
/// length field is implausible (< `RX_MIN_FRAME` including the
/// FCS, or running past the buffer) — the stream cannot be
/// resynced past a bad descriptor.
///
/// This walk deliberately does NOT share the v1 walk's
/// frame-bytes-only convention: the v1 walk treats the length
/// field as delivered bytes with no FCS strip and no
/// inter-segment alignment, which is a pre-existing divergence
/// from Linux's walk (see the remainder in the PR body). The
/// v2 walk follows the evidence — a v2 fixture built the v1
/// way would agree with a wrong walk and pass while real
/// silicon would fail.
pub fn parse_rx_aggregate_v2(buf: &[u8]) -> Vec<RxSegment> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + RX_DESC_V2_LEN <= buf.len() {
        let opts1 = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let opts2 = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let opts3 = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        let pkt_len = rx_len_v2(opts1) as usize;
        if pkt_len < RX_MIN_FRAME as usize || off + RX_DESC_V2_LEN + pkt_len > buf.len() {
            break;
        }
        out.push(RxSegment {
            offset: off + RX_DESC_V2_LEN,
            len: pkt_len - RX_FCS_LEN,
            vlan_tag: rx_vlan_tag_v2(opts1, opts2),
            csum: rx_csum_result_v2(opts3),
        });
        off = (off + RX_DESC_V2_LEN + pkt_len + RX_DESC_V2_ALIGN - 1) & !(RX_DESC_V2_ALIGN - 1);
    }
    out
}

/// Whether an IPv4/UDP frame carries a zero UDP checksum field,
/// i.e. RFC 768 "no checksum" — a legal frame even if the device
/// flagged UDPF. Only the IPv4 case qualifies (IPv6 UDP checksums
/// are mandatory). Parses the Ethernet header plus one optional
/// VLAN tag, then the IPv4 header (IHL-aware); any parse failure
/// or short frame returns `false` (fail closed).
pub fn ipv4_udp_zero_checksum(frame: &[u8]) -> bool {
    let read_u16 = |off: usize| -> Option<u16> {
        frame
            .get(off..off + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    };
    let mut et_off = 12usize;
    let Some(mut ethertype) = read_u16(et_off) else {
        return false;
    };
    if ethertype == 0x8100 || ethertype == 0x88A8 {
        et_off = 16;
        let Some(inner) = read_u16(et_off) else {
            return false;
        };
        ethertype = inner;
    }
    if ethertype != 0x0800 {
        return false;
    }
    let l3 = et_off + 2;
    let Some(&vihl) = frame.get(l3) else {
        return false;
    };
    if vihl >> 4 != 4 {
        return false;
    }
    let ihl = (vihl & 0x0F) as usize * 4;
    if ihl < 20 || frame.len() < l3 + ihl + 8 {
        return false;
    }
    if frame[l3 + 9] != 17 {
        return false;
    }
    let csum_off = l3 + ihl + 6;
    frame[csum_off] == 0 && frame[csum_off + 1] == 0
}

/// Whether a parsed RX segment reaches the stack — the delivery
/// half of the RX checksum channel (the stack has no RX metadata
/// consumer, so a device-verified corrupt frame is dropped here
/// rather than marked: that is the outcome the stack's software
/// verification would produce).
/// - `Good` / `NotChecked` → deliver.
/// - `Bad` with an IP failure → drop (a corrupt IP header's
///   fields cannot be trusted for any exception).
/// - `Bad` L4-only → drop, except an IPv4/UDP frame with a zero
///   checksum field (legal "no checksum", see
///   [`ipv4_udp_zero_checksum`]).
pub fn rx_segment_deliverable(csum: RxCsumResult, frame: &[u8]) -> bool {
    match csum {
        RxCsumResult::Good | RxCsumResult::NotChecked => true,
        RxCsumResult::Bad { ip: true, .. } => false,
        RxCsumResult::Bad {
            ip: false,
            l4: true,
        } => ipv4_udp_zero_checksum(frame),
        RxCsumResult::Bad { .. } => false,
    }
}

/// Walk an RX aggregation buffer into its frames, mirroring
/// Linux's `rx_bottom` walk: the `opts1` length field counts
/// frame + FCS, so the walk bounds-checks the raw length
/// (`< ETH_ZLEN`, i.e. `RX_MIN_FRAME`, or running past the
/// buffer, stops the walk — the stream cannot be resynced past
/// a bad descriptor), delivers `pkt_len - ETH_FCS_LEN` bytes,
/// and places the next descriptor at the next 8-byte boundary
/// (`rx_agg_align`). The raw-length check runs BEFORE the
/// strip, exactly as in Linux: a raw length of 60 delivers a
/// 56-byte frame.
pub fn parse_rx_aggregate(buf: &[u8]) -> Vec<RxSegment> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + RX_DESC_LEN <= buf.len() {
        let opts1 = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let opts2 = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let opts3 = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        let pkt_len = (opts1 & RX_LEN_MASK) as usize;
        if pkt_len < RX_MIN_FRAME as usize || off + RX_DESC_LEN + pkt_len > buf.len() {
            break;
        }
        out.push(RxSegment {
            offset: off + RX_DESC_LEN,
            len: pkt_len - RX_FCS_LEN,
            vlan_tag: rx_vlan_tag_from_opts2(opts2),
            csum: rx_csum_result(opts2, opts3),
        });
        off = (off + RX_DESC_LEN + pkt_len + RX_DESC_ALIGN - 1) & !(RX_DESC_ALIGN - 1);
    }
    out
}

/// Splice an 802.1Q tag (TCI) back into a frame the chip
/// stripped: destination + source MAC, then `0x8100` + the TCI
/// in wire (big-endian) order, then the original ethertype +
/// payload. Returns `None` for frames shorter than an Ethernet
/// header.
pub fn insert_vlan_tag(frame: &[u8], tag: u16) -> Option<Vec<u8>> {
    if frame.len() < 14 {
        return None;
    }
    let mut out = Vec::with_capacity(frame.len() + 4);
    out.extend_from_slice(&frame[..12]);
    out.extend_from_slice(&[0x81, 0x00]);
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&frame[12..]);
    Some(out)
}

/// Append one TX segment (`tx_desc` + frame, padded to TX_ALIGN =
/// 4 bytes) for `frame` to `out`.
pub fn build_tx_segment(frame: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    if frame.len() > TX_LEN_MASK as usize {
        return Err(());
    }
    let opts1 = (frame.len() as u32 & TX_LEN_MASK) | TX_FS | TX_LS;
    out.extend_from_slice(&opts1.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // opts2: no csum offload
    out.extend_from_slice(frame);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    Ok(())
}

/// Append one v2 TX segment (`tx_desc_v2` + frame, padded to a
/// 16-byte multiple) for `frame` to `out` — the RTL8157 form
/// (Linux `r8157_tx_len` + `r8152_tx_csum`): `opts1`/`opts2`
/// are laid out exactly as in v1 (length + FS/LS, no offload),
/// then `opts3 = len << 4` and `opts4 = TX_SIG`. A `plain`
/// meta produces exactly `build_tx_segment_meta_v2`'s bytes.
pub fn build_tx_segment_v2(frame: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    if frame.len() > TX_LEN_MASK as usize {
        return Err(());
    }
    let opts1 = (frame.len() as u32 & TX_LEN_MASK) | TX_FS | TX_LS;
    out.extend_from_slice(&opts1.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // opts2: no csum offload
    out.extend_from_slice(&((frame.len() as u32) << TX_V2_LEN_SHIFT).to_le_bytes()); // opts3
    out.extend_from_slice(&TX_V2_SIG.to_le_bytes()); // opts4
    out.extend_from_slice(frame);
    while out.len() % TX_DESC_V2_ALIGN != 0 {
        out.push(0);
    }
    Ok(())
}

/// What the TX offload encoder needs from a frame's headers:
/// IP version, L4 protocol, and the transport-header offset
/// (the value the descriptor's TCPHO/GTTCPHO fields carry).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxL3Info {
    pub is_ipv4: bool,
    pub protocol: u8,
    pub transport_offset: usize,
}

/// Locate the transport header of an Ethernet/IPv4 or
/// Ethernet/IPv6 frame. Handles one inline 802.1Q tag (the
/// transport base moves past it). Returns `None` for short
/// frames, non-IP ethertypes, IPv4 options the header cannot
/// express, and IPv6 extension headers (the transport offset
/// is not walkable without them) — callers reject those
/// offload requests rather than emitting a partial checksum
/// (the `TxMeta` contract).
pub fn tx_l3_info(frame: &[u8]) -> Option<TxL3Info> {
    if frame.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut base = 14usize;
    if ethertype == 0x8100 {
        if frame.len() < 18 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        base = 18;
    }
    match ethertype {
        0x0800 => {
            if frame.len() < base + 20 {
                return None;
            }
            let ihl = (frame[base] & 0x0F) as usize * 4;
            if ihl < 20 || frame.len() < base + ihl {
                return None;
            }
            Some(TxL3Info {
                is_ipv4: true,
                protocol: frame[base + 9],
                transport_offset: base + ihl,
            })
        }
        0x86DD => {
            if frame.len() < base + 40 {
                return None;
            }
            let nexthdr = frame[base + 6];
            if nexthdr != 6 && nexthdr != 17 {
                return None;
            }
            Some(TxL3Info {
                is_ipv4: false,
                protocol: nexthdr,
                transport_offset: base + 40,
            })
        }
        _ => None,
    }
}

/// Compute the shared `opts1` / `opts2` pair for one TX
/// segment from `meta` (Linux `r8152_tx_csum`): the `opts1` /
/// `opts2` layout is identical in the v1 and v2 descriptors
/// (same offsets, same bits — Linux's v2 path delegates to the
/// shared `r8152_tx_csum` for these words). Only the
/// non-GSO checksum transport-offset cap differs per
/// generation: v1 `TX_TCPHO_MAX`, v2 `TX_TCPHO_MAX_V2`
/// (Linux `r8157_tx_csum` enforces the tighter cap before
/// delegating); the TSO cap (`TX_GTTCPHO_MAX`) is the same for
/// both. Rejection rules match [`build_tx_segment_meta`]:
/// SCTP, protocol/frame mismatches, and unparseable frames are
/// rejected — never silently sent with a partial checksum.
fn tx_desc_opts(frame: &[u8], meta: narf_net::TxMeta, tcpho_max: u32) -> Result<(u32, u32), ()> {
    if frame.len() > TX_LEN_MASK as usize {
        return Err(());
    }
    let mut opts1 = (frame.len() as u32 & TX_LEN_MASK) | TX_FS | TX_LS;
    let mut opts2 = 0u32;
    if let Some(tag) = meta.vlan_tag {
        opts2 |= TX_VLAN_TAG_BIT | tag.swap_bytes() as u32;
    }
    if let Some(mss) = meta.tso_mss {
        let info = tx_l3_info(frame).ok_or(())?;
        if info.protocol != 6 || info.transport_offset as u32 > TX_GTTCPHO_MAX {
            return Err(());
        }
        opts1 |= if info.is_ipv4 {
            TX_GTSENDV4
        } else {
            TX_GTSENDV6
        } | ((info.transport_offset as u32) << TX_GTTCPHO_SHIFT);
        opts2 |= (core::cmp::min(mss as u32, TX_MSS_MAX)) << TX_MSS_SHIFT;
    } else if let Some(kind) = meta.csum_l4 {
        let want = match kind {
            narf_net::L4CsumKind::Tcp => 6,
            narf_net::L4CsumKind::Udp => 17,
            narf_net::L4CsumKind::Sctp => return Err(()),
        };
        let info = tx_l3_info(frame).ok_or(())?;
        if info.protocol != want || info.transport_offset as u32 > tcpho_max {
            return Err(());
        }
        opts2 |= if info.is_ipv4 { TX_IPV4_CS } else { TX_IPV6_CS }
            | if want == 6 { TX_TCP_CS } else { TX_UDP_CS }
            | ((info.transport_offset as u32) << TX_TCPHO_SHIFT);
    }
    Ok((opts1, opts2))
}

/// Append one TX segment honouring `meta` (Linux `r8152_tx_csum`
/// + `r8152_tx_vlan_tag` for the v1 descriptor):
/// - `vlan_tag`: `opts2 = TX_VLAN_TAG | swab16(tag)`.
/// - `csum_l4` (no TSO): IPV4/IPV6_CS + TCP/UDP_CS +
///   `transport_offset << TCPHO_SHIFT`. SCTP is rejected
///   (the chip has no SCTP offload); a csum request whose
///   protocol does not match the frame, or whose frame is
///   unparseable, is rejected — never silently sent with a
///   partial checksum.
/// - `tso_mss`: GTSENDV4/GTSENDV6 + `transport_offset <<
///   GTTCPHO_SHIFT` + `min(mss, MSS_MAX) << MSS_SHIFT`
///   (Linux clamps the MSS). Non-TCP frames are rejected;
///   frames the hardware cannot encode (transport offset
///   past `GTTCPHO_MAX`, or longer than `TX_LEN_MASK`) are
///   rejected here — the send path falls back to software GSO
///   for TCP frames it cannot encode.
///
/// A `plain` meta produces exactly `build_tx_segment`'s bytes.
pub fn build_tx_segment_meta(
    frame: &[u8],
    meta: narf_net::TxMeta,
    out: &mut Vec<u8>,
) -> Result<(), ()> {
    let (opts1, opts2) = tx_desc_opts(frame, meta, TX_TCPHO_MAX)?;
    out.extend_from_slice(&opts1.to_le_bytes());
    out.extend_from_slice(&opts2.to_le_bytes());
    out.extend_from_slice(frame);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    Ok(())
}

/// Append one v2 TX segment honouring `meta` — the RTL8157 form
/// (Linux `r8157_tx_csum` + `r8157_tx_len`): `opts1`/`opts2`
/// are exactly the v1 words from [`tx_desc_opts`] (same offload
/// bits, same VLAN encoding), then `opts3 = len << 4` and
/// `opts4 = TX_SIG`, and the segment pads to a 16-byte
/// multiple. The one behavioural difference from v1 is the
/// tighter non-GSO checksum transport-offset cap
/// (`TX_TCPHO_MAX_V2` = 0x3FF); the TSO cap is unchanged.
///
/// A `plain` meta produces exactly `build_tx_segment_v2`'s bytes.
pub fn build_tx_segment_meta_v2(
    frame: &[u8],
    meta: narf_net::TxMeta,
    out: &mut Vec<u8>,
) -> Result<(), ()> {
    let (opts1, opts2) = tx_desc_opts(frame, meta, TX_TCPHO_MAX_V2)?;
    out.extend_from_slice(&opts1.to_le_bytes());
    out.extend_from_slice(&opts2.to_le_bytes());
    out.extend_from_slice(&((frame.len() as u32) << TX_V2_LEN_SHIFT).to_le_bytes());
    out.extend_from_slice(&TX_V2_SIG.to_le_bytes());
    out.extend_from_slice(frame);
    while out.len() % TX_DESC_V2_ALIGN != 0 {
        out.push(0);
    }
    Ok(())
}

/// Offloads this driver honours, advertised to the stack at bind
/// via `iface::set_offloads` so `TxMeta` requests arrive at all.
/// `max_tso_bytes` is the descriptor's hard length cap
/// (`TX_LEN_MASK`). RX checksum is advertised because the RX path
/// now decodes the descriptor's fail bits (`rx_csum_result`) and
/// drops device-verified corrupt frames in the pump
/// (`rx_segment_deliverable`); the stack has no RX metadata
/// consumer, so the drop — not a mark — is the delivery channel.
pub fn r8152_offloads() -> narf_net::OffloadCapabilities {
    narf_net::OffloadCapabilities {
        tx_checksum: true,
        rx_checksum: true,
        max_tso_bytes: TX_LEN_MASK,
        vlan_insert: true,
    }
}

// ── Wake-on-LAN (Linux `__rtl_get_wol` / `__rtl_set_wol`) ────────

/// Wake-on-LAN options, one flag per Linux `WAKE_*` bit. Bind
/// records the device's current options (Linux's
/// `saved_wolopts` initialised from `__rtl_get_wol` at probe);
/// `apply_wol` programs a new set. Programming is only the
/// register state — actually waking from suspend waits on the
/// per-NIC suspend path, which does not exist yet.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WolOpts {
    /// Wake on link change (`WAKE_PHY`).
    pub phy: bool,
    /// Wake on directed packet (`WAKE_UCAST`).
    pub unicast: bool,
    /// Wake on broadcast (`WAKE_BCAST`).
    pub broadcast: bool,
    /// Wake on multicast (`WAKE_MCAST`).
    pub multicast: bool,
    /// Wake on magic packet (`WAKE_MAGIC`).
    pub magic: bool,
}

/// Decode the current WoL options from the three register words
/// Linux reads (`PLA_CONFIG34`, `PLA_CONFIG5`, `PLA_CFG_WOL`).
pub fn wol_opts_from_regs(config34: u16, config5: u16, cfg_wol: u16) -> WolOpts {
    WolOpts {
        phy: config34 & CONFIG34_LINK_ON_WAKE_EN != 0,
        unicast: config5 & CONFIG5_UWF_EN != 0,
        broadcast: config5 & CONFIG5_BWF_EN != 0,
        multicast: config5 & CONFIG5_MWF_EN != 0,
        magic: cfg_wol & WOL_MAGIC_EN != 0,
    }
}

/// One step of the WoL programming sequence (Linux
/// `__rtl_set_wol`, in order). `PLA_CONFIG34`/`PLA_CONFIG5`
/// are write-protected unless `PLA_CRWECR` holds `CONFIG`
/// first — hence the bracketing byte writes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WolOp {
    /// Byte write to `PLA_CRWECR` (`CONFIG` to open,
    /// `NORMAL` to close).
    CrwecrWrite(u8),
    /// `PLA_CONFIG34` set/clear `LINK_ON_WAKE_EN`.
    Config34Set(bool),
    /// `PLA_CONFIG5` write-0-write-1 over the UWF/BWF/MWF
    /// mask with the given set bits.
    Config5W0W1(u16),
    /// `PLA_CFG_WOL` set/clear `MAGIC_EN`.
    CfgWolSet(bool),
}

/// The exact `__rtl_set_wol` step sequence for `opts`.
pub fn wol_ops(opts: WolOpts) -> [WolOp; 5] {
    let mut filter = 0u16;
    if opts.unicast {
        filter |= CONFIG5_UWF_EN;
    }
    if opts.broadcast {
        filter |= CONFIG5_BWF_EN;
    }
    if opts.multicast {
        filter |= CONFIG5_MWF_EN;
    }
    [
        WolOp::CrwecrWrite(CRWECR_CONFIG),
        WolOp::Config34Set(opts.phy),
        WolOp::Config5W0W1(filter),
        WolOp::CrwecrWrite(CRWECR_NORMAL),
        WolOp::CfgWolSet(opts.magic),
    ]
}

/// Execute one [`WolOp`] against the device.
async fn apply_wol_op(dev: &USBDevice, op: WolOp) -> Result<(), ()> {
    match op {
        WolOp::CrwecrWrite(v) => ocp_write_byte(dev, MCU_TYPE_PLA, PLA_CRWECR, v).await,
        WolOp::Config34Set(on) => {
            if on {
                pla_word_set_bits(dev, PLA_CONFIG34, CONFIG34_LINK_ON_WAKE_EN).await
            } else {
                pla_word_clr_bits(dev, PLA_CONFIG34, CONFIG34_LINK_ON_WAKE_EN).await
            }
        }
        WolOp::Config5W0W1(set) => {
            let cur = ocp_read_word(dev, MCU_TYPE_PLA, PLA_CONFIG5).await?;
            let mask = CONFIG5_UWF_EN | CONFIG5_BWF_EN | CONFIG5_MWF_EN;
            ocp_write_word(dev, MCU_TYPE_PLA, PLA_CONFIG5, (cur & !mask) | set).await
        }
        WolOp::CfgWolSet(on) => {
            if on {
                pla_word_set_bits(dev, PLA_CFG_WOL, WOL_MAGIC_EN).await
            } else {
                pla_word_clr_bits(dev, PLA_CFG_WOL, WOL_MAGIC_EN).await
            }
        }
    }
}

/// Program `opts` into the chip (Linux `__rtl_set_wol`). The
/// USB remote-wakeup arming (`device_set_wakeup_enable` in
/// Linux) has no NARF equivalent yet — it rides with the
/// per-NIC suspend work, not this register programming.
pub async fn apply_wol(dev: &USBDevice, opts: WolOpts) -> Result<(), ()> {
    for op in wol_ops(opts) {
        apply_wol_op(dev, op).await?;
    }
    Ok(())
}

/// Read the device's current WoL options (best-effort: a read
/// failure yields all-disabled rather than failing the bind —
/// the snapshot is advisory until a setter runs).
pub async fn read_wol_opts(dev: &USBDevice) -> WolOpts {
    let Ok(config34) = ocp_read_word(dev, MCU_TYPE_PLA, PLA_CONFIG34).await else {
        return WolOpts::default();
    };
    let Ok(config5) = ocp_read_word(dev, MCU_TYPE_PLA, PLA_CONFIG5).await else {
        return WolOpts::default();
    };
    let Ok(cfg_wol) = ocp_read_word(dev, MCU_TYPE_PLA, PLA_CFG_WOL).await else {
        return WolOpts::default();
    };
    wol_opts_from_regs(config34, config5, cfg_wol)
}

/// The RX VLAN enable for `version` (Linux `rtl_rx_vlan_en`):
/// `PLA_CPCR`'s `CPCR_RX_VLAN` bit for VER_01–VER_09 and
/// VER_14, `PLA_RCR1`'s outer+inner VLAN bits otherwise
/// (Linux's default arm, which also covers TEST_01 and
/// unknown versions). Returns the `(address, bits)` to set.
pub fn rx_vlan_enable(version: RtlVersion) -> (u16, u16) {
    match version {
        RtlVersion::Ver01
        | RtlVersion::Ver02
        | RtlVersion::Ver03
        | RtlVersion::Ver04
        | RtlVersion::Ver05
        | RtlVersion::Ver06
        | RtlVersion::Ver07
        | RtlVersion::Ver08
        | RtlVersion::Ver09
        | RtlVersion::Ver14 => (PLA_CPCR, CPCR_RX_VLAN),
        _ => (PLA_RCR1, RCR1_OUTER_VLAN | RCR1_INNER_VLAN),
    }
}

/// Walk the vendor-specific (class 0xFF) interface's endpoints
/// in a configuration-descriptor blob. Returns
/// `(bulk_in, bulk_out, interrupt_in)` as xHCI endpoint configs
/// (each `None` when absent; last descriptor wins per slot).
/// The interrupt entry carries the descriptor's own `bInterval`
/// (byte 6) — the device's designed polling rate, not an
/// invented one. Bulk entries keep interval 0 (irrelevant for
/// bulk). One walk feeds both accessors below, so the bulk-pair
/// result cannot drift from the interrupt result.
fn walk_rtl_endpoints(
    cfg: &[u8],
) -> (
    Option<EndpointConfig>,
    Option<EndpointConfig>,
    Option<EndpointConfig>,
) {
    let mut i = 0usize;
    let mut in_vendor_iface = false;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    let mut interrupt_in: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            // INTERFACE: class is byte 5.
            in_vendor_iface = cfg[i + 5] == 0xFF;
        } else if desc_type == 0x05 && in_vendor_iface && len >= 7 {
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF;
            let is_in = ep_addr & 0x80 != 0;
            match attrs & 0x03 {
                2 => {
                    // Bulk endpoint.
                    let ep = EndpointConfig {
                        ep_addr,
                        max_packet,
                        kind: if is_in {
                            EndpointKind::BulkIn
                        } else {
                            EndpointKind::BulkOut
                        },
                        interval: 0,
                    };
                    if is_in {
                        bulk_in = Some(ep);
                    } else {
                        bulk_out = Some(ep);
                    }
                }
                3 if is_in => {
                    // Interrupt-IN endpoint (AX88179 link-status
                    // channel; r8152 ignores it).
                    interrupt_in = Some(EndpointConfig {
                        ep_addr,
                        max_packet,
                        kind: EndpointKind::InterruptIn,
                        interval: cfg[i + 6],
                    });
                }
                _ => {}
            }
        }
        i += len;
    }
    (bulk_in, bulk_out, interrupt_in)
}

/// Find the vendor-specific (class 0xFF) interface's bulk pair in
/// a configuration-descriptor blob. Returns
/// `(bulk_in_ep, bulk_out_ep)` as xHCI endpoint configs.
pub fn find_rtl_endpoints(cfg: &[u8]) -> Option<(EndpointConfig, EndpointConfig)> {
    match walk_rtl_endpoints(cfg) {
        (Some(i), Some(o), _) => Some((i, o)),
        _ => None,
    }
}

/// Find the vendor-specific (class 0xFF) interface's
/// interrupt-IN endpoint in a configuration-descriptor blob, if
/// any. Same walk as [`find_rtl_endpoints`] — not a second
/// finder — so a blob yielding a bulk pair yields its
/// interrupt endpoint from the same pass.
pub fn find_rtl_interrupt_endpoint(cfg: &[u8]) -> Option<EndpointConfig> {
    walk_rtl_endpoints(cfg).2
}

// ── Device table + publication ───────────────────────────────────

/// Chip generation, from the product id. Selects the station
/// address source order and the receive-size programming; the
/// datapath formats are identical across generations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RtlGen {
    /// RTL8152 — USB 2.0, 10/100.
    Fe,
    /// RTL8153 / 8155 / 8156 / 8157 and the dock re-badges.
    GbE,
}

pub fn generation_for_pid(pid: u16) -> RtlGen {
    if pid == 0x8152 {
        RtlGen::Fe
    } else {
        RtlGen::GbE
    }
}

/// Largest frame the generation accepts (programmed into
/// `PLA_RMS`): 1522 (1518 + FCS) for FE, 9216 jumbo-capable for
/// GbE.
pub fn rx_max_size(gen: RtlGen) -> u16 {
    match gen {
        RtlGen::Fe => 1522,
        RtlGen::GbE => 9216,
    }
}

/// MTU → `PLA_RMS` programming (Linux `mtu_to_size`, r8152.c):
/// receive-max-size = MTU + `VLAN_ETH_HLEN` (18) + `ETH_FCS_LEN`
/// (4).
pub fn mtu_to_rms(mtu: u32) -> u32 {
    mtu + 22
}

/// Linux `ndo_change_mtu` bounds (r8152.c probe switch):
/// `ETH_MIN_MTU` (68) ..= max, where max is 1500 for VER_01/02/07
/// and unknown/test versions, 9194 (9 KiB − 22) for
/// VER_03/04/05/06/08/09/14, 15338 (15 KiB − 22) for VER_10/11, and
/// 16362 (16 KiB − 22) for VER_12/13/15/16/17.
pub fn max_mtu_for(version: RtlVersion) -> u32 {
    match version {
        RtlVersion::Ver03
        | RtlVersion::Ver04
        | RtlVersion::Ver05
        | RtlVersion::Ver06
        | RtlVersion::Ver08
        | RtlVersion::Ver09
        | RtlVersion::Ver14 => 9194,
        RtlVersion::Ver10 | RtlVersion::Ver11 => 15338,
        RtlVersion::Ver12
        | RtlVersion::Ver13
        | RtlVersion::Ver15
        | RtlVersion::Ver16
        | RtlVersion::Ver17 => 16362,
        _ => 1500,
    }
}

/// Validate a requested MTU against the chip version:
/// `Err(22)` outside 68..=max.
pub fn validate_mtu(version: RtlVersion, mtu: u32) -> Result<(), i32> {
    if (68..=max_mtu_for(version)).contains(&mtu) {
        Ok(())
    } else {
        Err(22)
    }
}

/// `PLA_RMS` reprogram needed for an MTU change, if any. Linux
/// leaves `PLA_RMS` untouched for VER_01/02/07 (FE: fixed 1522
/// bound, max MTU 1500) and for versions with no `change_mtu` op;
/// GbE versions with an op write `PLA_RMS` = MTU + 22. `None`
/// when the MTU is unchanged.
pub fn mtu_reprogram(version: RtlVersion, current: u32, desired: u32) -> Option<u16> {
    if current == desired {
        return None;
    }
    match version {
        RtlVersion::Ver03
        | RtlVersion::Ver04
        | RtlVersion::Ver05
        | RtlVersion::Ver06
        | RtlVersion::Ver08
        | RtlVersion::Ver09
        | RtlVersion::Ver10
        | RtlVersion::Ver11
        | RtlVersion::Ver12
        | RtlVersion::Ver13
        | RtlVersion::Ver14
        | RtlVersion::Ver15
        | RtlVersion::Ver16
        | RtlVersion::Ver17 => Some(mtu_to_rms(desired) as u16),
        _ => None,
    }
}

/// Pure MTU-change transition for a bound record, returning
/// `(new_mtu, new_pending)`. `Err(19)` when the record is not
/// live (detached or pump stopped); `Err(22)` when the MTU is out
/// of range. A pending write survives an unchanged MTU; a changed
/// GbE MTU overwrites it with the new bound.
pub fn mtu_transition(
    version: RtlVersion,
    current: u32,
    pending: Option<u16>,
    desired: u32,
    live: bool,
) -> Result<(u32, Option<u16>), i32> {
    if !live {
        return Err(19);
    }
    validate_mtu(version, desired)?;
    let next_pending = mtu_reprogram(version, current, desired).or(pending);
    Ok((desired, next_pending))
}

/// One bound RTL device.
#[derive(Clone, Debug)]
pub struct RtlDevice {
    pub slot_id: u8,
    pub generation: RtlGen,
    /// Chip version decoded from `PLA_TCR1` at bind (drives the
    /// version-switched PHY init and later version-gated
    /// programming such as RX VLAN enable).
    pub version: RtlVersion,
    /// Wake-on-LAN options snapshotted at bind (the device's
    /// current register state); reprogrammed via `apply_wol`
    /// by the suspend path (#1256).
    pub wol_opts: WolOpts,
    pub mac: [u8; 6],
    pub bulk_in_dci: u8,
    pub bulk_out_dci: u8,
    /// Assigned `narf_net::iface` name (`usb-rtl{N}`).
    pub iface_name: String,
    pub pump_running: bool,
    /// Last `PLA_PHYSTATUS` byte sampled (0xFF = never sampled).
    pub link_byte: u8,
    /// Registry MTU the record tracks. Fresh registrations start
    /// at 1500; rebinds restore the retired entry's MTU, synced
    /// from the registry after registration.
    pub mtu: u32,
    /// `PLA_RMS` value awaiting application by the RX pump
    /// (MTU-change path; `None` when hardware matches `mtu`).
    pub pending_rms: Option<u16>,
    /// Detach tombstone: set by `detach_r8152_slot`. The pump
    /// exits when `pump_running` clears; TX resolves to `None`.
    /// Records are never removed, because net-registry TX
    /// cookies are record indices — removing a record would
    /// retarget every later device's cookie at the wrong
    /// device (the ECM/NCM rule).
    pub detached: bool,
    /// Index of the xHCI controller the device is on
    /// ([`crate::xhci::Xhci::id`]); `slot_id` is only unique within it.
    pub controller: u8,
    /// Hub context recorded at bind: `Some((parent hub slot id,
    /// downstream port))` when the device sits behind a hub,
    /// `None` on a root port. Root-port devices never become
    /// idle-suspend candidates (no hub to gate them); hub-port
    /// devices use this to park/resume their own port (#1256).
    pub hub_port: Option<(u8, u8)>,
    /// Port speed recorded at bind, so the suspend hook can
    /// build a transient `USBDevice` for the WoL register
    /// programming without retaining a device Arc.
    pub speed: crate::xhci::PortSpeed,
    /// Park flag: set by the class suspend hook, cleared by
    /// resume. Distinct from the `detached` tombstone (detach
    /// dominates: a parked pump exits on detach) and from
    /// `pump_running` (the pump task stays alive while parked).
    pub suspended: bool,
    /// Whether DEVICE_REMOTE_WAKEUP arming succeeded at the
    /// last park. `false` after a park whose arming transfer
    /// stalled: the datapath still parks (TX-demand resume
    /// works), but the device cannot signal a wake.
    pub wakeup_armed: bool,
}

/// System-wide registry of bound RTL devices (records carry their
/// controller; indices are the net-registry TX cookies).
pub static RTL_DEVICES: IrqSafeSpinLock<Vec<RtlDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Driver control hook installed on each bound r8152 iface
/// (issue #1258). `configure` is synchronous while USB control
/// transfers are async, so it validates and records only: the RX
/// pump applies a pending `PLA_RMS` write on its next turn.
/// Registry metadata therefore commits after validation, with
/// hardware following within one pump turn — a transient window,
/// never a permanent divergence — and a failed pump write stays
/// pending for the next turn. Non-MTU fields are deliberately
/// untouched here: MAC / promiscuity / address changes keep
/// their existing registry-only behavior.
#[derive(Debug)]
pub struct RtlControl {
    idx: usize,
}

impl narf_net::iface::DeviceControl for RtlControl {
    fn configure(&self, desired: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        let mut g = RTL_DEVICES.lock();
        let Some(rec) = g.get_mut(self.idx) else {
            return Err(19);
        };
        let live = !rec.detached && rec.pump_running;
        let (mtu, pending) =
            mtu_transition(rec.version, rec.mtu, rec.pending_rms, desired.mtu, live)?;
        rec.mtu = mtu;
        rec.pending_rms = pending;
        Ok(())
    }
}

/// Take a pending `PLA_RMS` reprogram for the RX pump to apply.
fn take_pending_rms(idx: usize) -> Option<u16> {
    RTL_DEVICES
        .lock()
        .get_mut(idx)
        .and_then(|rec| rec.pending_rms.take())
}

/// Restore a `PLA_RMS` reprogram the pump failed to apply, so
/// the next turn retries it.
fn restore_pending_rms(idx: usize, rms: u16) {
    if let Some(rec) = RTL_DEVICES.lock().get_mut(idx) {
        rec.pending_rms = Some(rms);
    }
}

/// Resolve a device-record index to its TX target
/// `(slot_id, bulk_out_dci)`. The send trampoline routes through
/// this — and only this — so a frame can never be emitted on a
/// different device's endpoint.
pub fn tx_target(idx: usize) -> Option<(u8, u8)> {
    let g = RTL_DEVICES.lock();
    g.get(idx)
        .filter(|d| !d.detached)
        .map(|d| (d.slot_id, d.bulk_out_dci))
}

/// Ship one built TX segment on the device's bulk-OUT endpoint.
/// The net stack's send hook is sync; bridge to the async
/// bulk_out via block_on (called from TX paths that are not
/// inside an executor poll — same contract as CDC-NCM's send).
fn rtl_send_segment(controller: u8, slot_id: u8, bulk_out_dci: u8, seg: &[u8]) -> Result<(), ()> {
    let c = crate::xhci::controller_by_id(controller).ok_or(())?;
    narf_scheduler::block_on(async move { c.bulk_out(slot_id, bulk_out_dci, seg).await })
        .map_err(|_| ())?;
    Ok(())
}

/// Send one frame for the device record at `idx`, honouring
/// `meta` (VLAN insert, checksum offload, hardware TSO). A TCP
/// frame the hardware cannot encode (over the descriptor's
/// length cap) falls back to the stack's software GSO splitter
/// — the same oracle hardware TSO is validated against — with
/// each segment sent plainly (VLAN tag preserved); a non-TCP
/// TSO request, or an unparseable csum request, is rejected
/// rather than sent with a partial offload. Driver-local only:
/// no shared TX-path code is touched.
fn rtl_send_frame(idx: usize, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    // TX-demand resume (#1256): a parked device's port is
    // gated, so a bulk-OUT would fail. Resume first; on
    // failure fail fast rather than sending into a gated port.
    // Root-port devices never park (hub_port None), so this
    // is a no-op for them. The record lock is never held
    // across the resume await: read, release, resume,
    // re-resolve via tx_target.
    let resume_needed = {
        let g = RTL_DEVICES.lock();
        g.get(idx).and_then(|d| {
            if d.detached {
                None
            } else {
                d.hub_port
                    .filter(|_| d.suspended)
                    .map(|hp| (hp, d.controller))
            }
        })
    };
    if let Some(((hub_slot, port), controller)) = resume_needed {
        let Some(c) = crate::xhci::controller_by_id(controller) else {
            return Err(());
        };
        let resumed = narf_scheduler::block_on(resume_r8152_port(&c, hub_slot, port));
        if !resumed {
            return Err(());
        }
        // Waking for TX opens a fresh idle window, so a TX
        // burst does not flap the port straight back into
        // suspend (the pump's RX marking alone would let a
        // TX-only flow idle-expire).
        crate::attach::mark_port_activity(controller, hub_slot, port);
    }
    let (slot_id, bulk_out_dci) = tx_target(idx).ok_or(())?;
    let controller = RTL_DEVICES.lock().get(idx).ok_or(())?.controller;
    // RTL8157 (VER_16) speaks the v2 TX descriptor format;
    // every other version speaks v1. The builders differ in
    // descriptor length, the opts3/opts4 tail, padding, and
    // the checksum transport-offset cap.
    let v2 = RTL_DEVICES
        .lock()
        .get(idx)
        .map(|d| uses_rx_desc_v2(d.version))
        .unwrap_or(false);
    let build = |frame: &[u8], meta: narf_net::TxMeta, seg: &mut Vec<u8>| -> Result<(), ()> {
        if v2 {
            build_tx_segment_meta_v2(frame, meta, seg)
        } else {
            build_tx_segment_meta(frame, meta, seg)
        }
    };
    let mut seg = Vec::new();
    if build(frame, meta, &mut seg).is_ok() {
        return rtl_send_segment(controller, slot_id, bulk_out_dci, &seg);
    }
    // Hardware encode failed. Only TCP super-frames get the
    // software fallback; anything else is a rejected request.
    let info = tx_l3_info(frame).ok_or(())?;
    if info.protocol != 6 || meta.tso_mss.is_none() {
        return Err(());
    }
    let mss = meta.tso_mss.unwrap_or(0) as usize;
    let segments = if info.is_ipv4 {
        narf_net::gso::segment_ipv4_tcp(frame, mss)
    } else {
        narf_net::gso::segment_ipv6_tcp(frame, mss)
    }
    .ok_or(())?;
    let seg_meta = narf_net::TxMeta {
        vlan_tag: meta.vlan_tag,
        ..narf_net::TxMeta::plain()
    };
    for s in &segments {
        let mut seg = Vec::new();
        build(s, seg_meta, &mut seg)?;
        rtl_send_segment(controller, slot_id, bulk_out_dci, &seg)?;
    }
    Ok(())
}

/// `SendCtxFn` trampoline: the cookie is the device-record index
/// assigned at registration time.
fn rtl_send_ctx(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    rtl_send_frame(cookie as usize, frame, meta)
}

// ── Bind ─────────────────────────────────────────────────────────

/// Read the station address: FE parts keep it in `PLA_IDR`, GbE
/// parts in `PLA_BACKUP`; each generation tries the other as a
/// fallback. Fails when neither holds a valid address.
async fn read_station_address(dev: &USBDevice, gen: RtlGen) -> Result<[u8; 6], ()> {
    let order = match gen {
        RtlGen::Fe => [PLA_IDR, PLA_BACKUP],
        RtlGen::GbE => [PLA_BACKUP, PLA_IDR],
    };
    for base in order {
        let mut raw = [0u8; 8];
        ocp_read(dev, MCU_TYPE_PLA, base, &mut raw).await?;
        if let Some(mac) = mac_from_station_bytes(&raw) {
            return Ok(mac);
        }
    }
    Err(())
}

/// `PLA_CR` value with receiver + transmitter enabled (reset and
/// all other bits preserved from the read-back value).
pub fn cr_with_datapath_enabled(old: u8) -> u8 {
    (old & !CR_RST) | CR_RE | CR_TE
}

/// Full bind for an addressed RTL8152/8153 device: configuration,
/// endpoint setup, MAC-level bring-up, station-address read,
/// netdev publication, RX pump. Returns the device-record index.
async fn bind(device: Arc<USBDevice>, hub_port: Option<(u8, u8)>) -> Result<usize, ()> {
    use core::fmt::Write;
    // Fetch the configuration descriptor (two-step like xpad:
    // 9-byte header for wTotalLength, then the full blob).
    let mut hdr = [0u8; 9];
    device
        .get_config_descriptor(0, &mut hdr)
        .await
        .map_err(|_| ())?;
    let total = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
    if !(9..=4096).contains(&total) {
        return Err(());
    }
    let mut cfg = vec![0u8; total];
    device
        .get_config_descriptor(0, &mut cfg)
        .await
        .map_err(|_| ())?;
    let cfg_value = cfg[5];
    let (in_ep, out_ep) = find_rtl_endpoints(&cfg).ok_or(())?;
    device
        .control_out(
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .map_err(|_| ())?;
    device
        .configure_endpoints(&[in_ep, out_ep])
        .await
        .map_err(|_| ())?;
    let bulk_in_dci = ((in_ep.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = (out_ep.ep_addr & 0x0F) * 2;

    // ── MAC-level bring-up over the OCP protocol ──
    // Soft reset; CR_RST is self-clearing. Poll cooperatively
    // (scheduler yield between reads — never a busy spin on a
    // hardware register) and proceed even if it never clears:
    // the datapath enable below is the real gate.
    ocp_write_byte(&device, MCU_TYPE_PLA, PLA_CR, CR_RST).await?;
    for _ in 0..200 {
        let cr = ocp_read_byte(&device, MCU_TYPE_PLA, PLA_CR).await?;
        if cr & CR_RST == 0 {
            break;
        }
        narf_scheduler::yield_now().await;
    }
    // Chip version: drives the version-switched PHY init below
    // (issue #881); the generation comes from the PID.
    let version_raw = ocp_read_word(&device, MCU_TYPE_PLA, PLA_TCR1).await?;
    let version = version_from_tcr1(version_raw);
    let gen = generation_for_pid(device.product_id());
    // USB/LPM init layer for the chip version (Linux `r8153_init`,
    // probe-time in Linux, so it runs before the PHY init
    // sequence here). The burst-size word and link bit are
    // sampled first — none of the init steps changes them — and
    // both reads are best-effort with the safe defaults (burst 0,
    // link down) so the init layer adds no new bind failure mode.
    // Unknown / not-yet-ported versions are a no-op here (reset
    // defaults).
    let burst_size = ocp_read_word(&device, MCU_TYPE_USB, USB_BURST_SIZE)
        .await
        .unwrap_or(0);
    let link_ok = ocp_read_byte(&device, MCU_TYPE_PLA, PLA_PHYSTATUS)
        .await
        .map(|b| b & PHYSTAT_LINK != 0)
        .unwrap_or(false);
    apply_usb_init(&device, version, device.speed(), burst_size, link_ok).await?;
    let coalesce_us = coalesce_for_speed(device.speed());
    // Firmware blob for the chip version, from the registry
    // (Linux `rtl8152_request_firmware`, probe-time in Linux).
    // The cap is held alive across the init sequence so the blob
    // view stays valid; a missing blob is Linux's failed
    // `request_firmware` — warn and continue, never a bind
    // failure (this crate has no logging sink, so the absence is
    // silent here and visible only as the skipped step).
    let fw_cap = firmware_name_for(version).and_then(crate::btusb::firmware_cap);
    let fw_view = match &fw_cap {
        Some(cap) => narf_firmware::view_of(cap).ok(),
        None => None,
    };
    let fw = fw_view.as_ref().map(|v| v.bytes);
    // PHY/firmware init for the chip version, before CR RE/TE
    // enable. Unknown versions are a no-op here (reset
    // defaults); every known version runs its `*_hw_phy_cfg`.
    apply_phy_init(&device, version, fw).await?;
    // Station address from the device itself — never invented.
    let mac = read_station_address(&device, gen).await?;
    // Multicast table wide open (RCR_AM does the policy), then the
    // accept filters, then the receive-size bound.
    ocp_write_dword(&device, MCU_TYPE_PLA, PLA_MAR, 0xFFFF_FFFF).await?;
    ocp_write_dword(&device, MCU_TYPE_PLA, PLA_MAR + 4, 0xFFFF_FFFF).await?;
    let rcr = ocp_read_dword(&device, MCU_TYPE_PLA, PLA_RCR).await?;
    ocp_write_dword(&device, MCU_TYPE_PLA, PLA_RCR, rcr_with_accept_filters(rcr)).await?;
    ocp_write_word(&device, MCU_TYPE_PLA, PLA_RMS, rx_max_size(gen)).await?;
    // RX VLAN tag reporting (Linux rtl_rx_vlan_en, always on
    // here: untagged traffic is unaffected — the tag bit is
    // simply never set — and tagged traffic needs the tag in
    // opts2 for the pump splice below).
    let (vlan_addr, vlan_bits) = rx_vlan_enable(version);
    pla_word_set_bits(&device, vlan_addr, vlan_bits).await?;
    // Snapshot the device's current WoL options (best-effort).
    let wol_opts = read_wol_opts(&device).await;
    // RX early timeout from the coalesce value (Linux
    // `r8153_set_rx_early_timeout` at enable time): coalesce us
    // / 8 fits u16 for every speed (max 524280 / 8 = 65535).
    // VER_03–VER_06 only — other families use a different
    // aggregation timer.
    if matches!(
        version,
        RtlVersion::Ver03 | RtlVersion::Ver04 | RtlVersion::Ver05 | RtlVersion::Ver06
    ) {
        ocp_write_word(
            &device,
            MCU_TYPE_USB,
            USB_RX_EARLY_TIMEOUT,
            (coalesce_us / 8) as u16,
        )
        .await?;
    }
    // Enable receiver + transmitter.
    let cr = ocp_read_byte(&device, MCU_TYPE_PLA, PLA_CR).await?;
    ocp_write_byte(&device, MCU_TYPE_PLA, PLA_CR, cr_with_datapath_enabled(cr)).await?;

    // ── Record + publication ──
    let idx = {
        let mut g = RTL_DEVICES.lock();
        let idx = g.len();
        g.push(RtlDevice {
            slot_id: device.slot_id(),
            generation: gen,
            version,
            wol_opts,
            mac,
            bulk_in_dci,
            bulk_out_dci,
            iface_name: format!("usb-rtl{}", idx),
            pump_running: false,
            link_byte: 0xFF,
            mtu: 1500,
            pending_rms: None,
            detached: false,
            controller: device.controller().id(),
            hub_port,
            speed: device.speed(),
            suspended: false,
            wakeup_armed: false,
        });
        idx
    };
    let requested = {
        let g = RTL_DEVICES.lock();
        g[idx].iface_name.clone()
    };
    let assigned =
        narf_net::iface::register_with_context(&requested, mac, idx as u64, rtl_send_ctx);
    // Advertise the TX offloads the send path honours, so the
    // stack actually requests them via TxMeta.
    narf_net::iface::set_offloads(&assigned, r8152_offloads());
    {
        let mut g = RTL_DEVICES.lock();
        g[idx].iface_name = assigned.clone();
        g[idx].pump_running = true;
    }
    // Sync the record's MTU from the registry (a rebind restores
    // the retired entry's MTU, which need not be 1500), then
    // install the control hook so registry MTU changes validate
    // against the chip and reprogram `PLA_RMS` (issue #1258).
    {
        let mut g = RTL_DEVICES.lock();
        if let Some(rec) = g.get_mut(idx) {
            rec.mtu = narf_net::iface::lookup(&assigned)
                .map(|s| s.mtu)
                .unwrap_or(1500);
        }
    }
    narf_net::iface::set_device_control(&assigned, Arc::new(RtlControl { idx }));
    let _ = writeln!(
        narf_console::Writer,
        "  net: r8152 bound slot {} as {} (gen {:?}, tcr1 version {:#06x} {:?}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        device.slot_id(),
        assigned,
        gen,
        version_raw,
        version,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    // Initial link sample, then the RX pump owns the device.
    sample_link(&device, idx).await;
    let pump_dev = device.clone();
    narf_scheduler::spawn(async move {
        rx_pump(pump_dev, idx).await;
    });
    Ok(idx)
}

/// Sample `PLA_PHYSTATUS` and republish link metadata on change.
async fn sample_link(device: &USBDevice, idx: usize) {
    let Ok(byte) = ocp_read_byte(device, MCU_TYPE_PLA, PLA_PHYSTATUS).await else {
        return;
    };
    let name = {
        let mut g = RTL_DEVICES.lock();
        let Some(rec) = g.get_mut(idx) else {
            return;
        };
        if rec.link_byte == byte {
            return;
        }
        rec.link_byte = byte;
        rec.iface_name.clone()
    };
    let (carrier, speed, duplex) = decode_link_status(byte);
    narf_net::iface::set_link_metadata(&name, carrier, speed, duplex);
}

/// RX pump-stop predicate: the pump runs until its record's flag
/// clears (device removal — the detach follow-on — clears it) or
/// the record vanishes.
fn pump_should_continue(idx: usize) -> bool {
    let g = RTL_DEVICES.lock();
    g.get(idx).map(|d| d.pump_running).unwrap_or(false)
}

/// Supervised RX pump: post bulk-IN reads, walk each aggregation
/// buffer, hand every frame to the stack. Stops after a bounded
/// run of consecutive transfer errors (a removed device surfaces
/// as persistent errors) or when the record's flag clears.
async fn rx_pump(device: Arc<USBDevice>, idx: usize) {
    let bulk_in_dci = {
        let g = RTL_DEVICES.lock();
        let Some(rec) = g.get(idx) else {
            return;
        };
        rec.bulk_in_dci
    };
    let mut buf = vec![0u8; RX_BUF_LEN];
    let mut errors = 0u32;
    let mut turns = 0u32;
    while pump_should_continue(idx) {
        // Park decision (#1256): a parked pump yields without
        // issuing transfers — a gated port would fail them and
        // the 16-error bound would kill the pump — and without
        // counting errors or sampling link (the device is
        // gated). Detach dominates: it clears `pump_running`,
        // so the loop condition exits. The yield loop matches
        // the pump's existing empty-poll arm; a timer-based
        // park sleep is follow-up polish, not correctness.
        let action = {
            let g = RTL_DEVICES.lock();
            g.get(idx)
                .map(|d| crate::attach::nic_pump_action(d.detached, d.suspended, d.pump_running))
                .unwrap_or(crate::attach::NicPumpAction::Exit)
        };
        match action {
            crate::attach::NicPumpAction::Exit => break,
            crate::attach::NicPumpAction::Park => {
                narf_scheduler::yield_now().await;
                continue;
            }
            crate::attach::NicPumpAction::Transfer => {}
        }
        // MTU-change path (issue #1258): apply a pending
        // `PLA_RMS` reprogram before posting reads, so the
        // receive bound tracks the registry MTU. A failed write
        // stays pending for the next turn.
        if let Some(rms) = take_pending_rms(idx) {
            if ocp_write_word(&device, MCU_TYPE_PLA, PLA_RMS, rms)
                .await
                .is_err()
            {
                restore_pending_rms(idx, rms);
            }
        }
        match device.bulk_in(bulk_in_dci, &mut buf).await {
            Ok(n) if n > 0 => {
                errors = 0;
                let dev = {
                    let g = RTL_DEVICES.lock();
                    g.get(idx)
                        .map(|d| (d.iface_name.clone(), d.hub_port, d.version))
                };
                if let Some((name, hub_port, version)) = dev {
                    let mut delivered = 0usize;
                    // RTL8157 (VER_16) speaks the v2 descriptor
                    // format; every other version speaks v1. The
                    // two walks differ in stride, length
                    // semantics, and checksum bit positions, so
                    // the wrong parser desyncs the stream.
                    let segs = if uses_rx_desc_v2(version) {
                        parse_rx_aggregate_v2(&buf[..n])
                    } else {
                        parse_rx_aggregate(&buf[..n])
                    };
                    for seg in segs {
                        let raw = &buf[seg.offset..seg.offset + seg.len];
                        // With CPCR_RX_VLAN / RCR1 VLAN enabled
                        // at bind, the chip strips a VLAN tag
                        // and reports it in opts2 (the Linux
                        // hwaccel contract) — splice it back so
                        // the stack sees the wire frame. This
                        // splice is the one silicon assumption
                        // in this lane: if hardware shows the
                        // tag inline after all, drop the splice.
                        let mut frame = match seg.vlan_tag {
                            Some(tag) => insert_vlan_tag(raw, tag).unwrap_or_else(|| raw.to_vec()),
                            None => raw.to_vec(),
                        };
                        // RX checksum channel: a device-verified
                        // corrupt frame is dropped here (the
                        // stack has no RX metadata consumer, so a
                        // mark would be dead data — the drop is
                        // the outcome software verification
                        // would produce). See
                        // `rx_segment_deliverable`.
                        if !rx_segment_deliverable(seg.csum, &frame) {
                            continue;
                        }
                        narf_net::iface::on_rx_frame_from(&name, &mut frame);
                        delivered += 1;
                    }
                    // Real traffic keeps the port's idle clock
                    // fresh (#1256): only delivered frames mark
                    // activity, never empty bulk-IN polls, so an
                    // idle NIC still becomes a suspend candidate
                    // after the 30 s window.
                    if delivered > 0 {
                        if let Some((hub_slot, port)) = hub_port {
                            crate::attach::mark_port_activity(
                                device.controller().id(),
                                hub_slot,
                                port,
                            );
                        }
                    }
                }
            }
            Ok(_) => narf_scheduler::yield_now().await,
            Err(_) => {
                errors += 1;
                if errors >= 16 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
        }
        turns = turns.wrapping_add(1);
        if turns % 32 == 0 {
            sample_link(&device, idx).await;
        }
    }
    let mut g = RTL_DEVICES.lock();
    if let Some(rec) = g.get_mut(idx) {
        rec.pump_running = false;
    }
}

// ── Suspend / resume (#1256) ─────────────────────────────────────
//
// Shape: the supervisor's idle-suspend pass calls the class
// suspend hook BEFORE gating the port (a gated port blocks all
// transfers, including the arming transfer). The hook parks the
// datapath (the pump's park branch) and arms wakeup in two
// steps: (1) reprogram the chip's wake filter from the
// bind-time snapshot via apply_wol — a failed filter program
// is ParkFailed, because gating without the wake filter would
// leave the device unable to wake on magic packet; (2)
// SET_FEATURE(DEVICE_REMOTE_WAKEUP) — a stall here only
// clears `wakeup_armed` and the park still proceeds (the
// device cannot signal, but TX-demand resume still works;
// same as HID's "nothing enables remote wakeup" state).
// Resume re-opens the port and clears the park flag; link
// state restores via the pump's existing 32-turn sampling,
// which resumes with the pump — no separate re-probe. The
// wake-watch step resumes a port only on an observed
// remote-wakeup edge, so idle ports stay suspended (an
// unconditional resume would defeat autosuspend + WoL).
// Arming MUST precede gating; the pass guarantees the order.

/// Class suspend hook for one hub port. Self-filters on the
/// record's hub context; idempotent (an already-parked device
/// returns `Parked` without re-arming). Never holds the record
/// lock across an await: lock to find, release, transfer, lock
/// to set flags.
async fn suspend_r8152_port(hub_slot: u8, port: u8) -> SuspendOutcome {
    // Read what arming needs, then release before any await.
    let target = {
        let g = RTL_DEVICES.lock();
        g.iter().find_map(|d| {
            if !d.detached && d.hub_port == Some((hub_slot, port)) {
                if d.suspended {
                    Some(None)
                } else {
                    Some(Some((d.slot_id, d.speed, d.wol_opts, d.controller)))
                }
            } else {
                None
            }
        })
    };
    let Some(target) = target else {
        return SuspendOutcome::NotMine;
    };
    let Some((slot_id, speed, wol_opts, controller)) = target else {
        // Already parked: idempotent re-park, no re-arm.
        return SuspendOutcome::Parked;
    };
    let Some(c) = crate::xhci::controller_by_id(controller) else {
        return SuspendOutcome::ParkFailed;
    };
    // Transient device handle for the OCP register path
    // (apply_wol takes &USBDevice). The hub-port number IS
    // the device's downstream port; the slot id and speed
    // come from the record.
    let dev = USBDevice::new(c.clone(), slot_id, port, speed);
    if apply_wol(&dev, wol_opts).await.is_err() {
        return SuspendOutcome::ParkFailed;
    }
    let setup = crate::control::set_feature_device_remote_wakeup();
    let armed = c
        .control_out(
            slot_id,
            setup.bm_request_type,
            setup.b_request,
            setup.w_value,
            setup.w_index,
            &[],
        )
        .await
        .is_ok();
    // Set the park flag only if the record is still live
    // (a detach in between wins; the pass's gating of a
    // device-less port is harmless).
    let mut g = RTL_DEVICES.lock();
    match g
        .iter_mut()
        .find(|d| !d.detached && d.hub_port == Some((hub_slot, port)) && d.slot_id == slot_id)
    {
        Some(rec) => {
            rec.suspended = true;
            rec.wakeup_armed = armed;
            SuspendOutcome::Parked
        }
        None => SuspendOutcome::NotMine,
    }
}

/// Resume one parked r8152 port: re-open the hub port, then
/// clear the park flag. Returns `true` iff the port is awake
/// and the flag cleared. Idempotent in the sense that a
/// non-parked port returns `false` (nothing was resumed) —
/// callers that need "awake" semantics re-check the flag.
/// Never holds the record lock across the resume await.
pub async fn resume_r8152_port(xhci_dev: &crate::xhci::Xhci, hub_slot: u8, port: u8) -> bool {
    let idx = {
        let g = RTL_DEVICES.lock();
        g.iter()
            .position(|d| !d.detached && d.suspended && d.hub_port == Some((hub_slot, port)))
    };
    let Some(idx) = idx else {
        return false;
    };
    crate::attach::resume_port(xhci_dev, hub_slot, port).await;
    if crate::attach::hub_port_is_suspended(xhci_dev.id(), hub_slot, port) {
        return false;
    }
    let mut g = RTL_DEVICES.lock();
    match g.get_mut(idx) {
        Some(rec) if !rec.detached && rec.suspended => {
            rec.suspended = false;
            true
        }
        _ => false,
    }
}

/// Hub ports holding a parked (suspended, non-detached) r8152
/// record. Mirrors `hid::hub_ports`, filtered to parked
/// devices: the wake-watch step's candidate list.
pub fn suspended_hub_ports() -> Vec<(u8, u8)> {
    let g = RTL_DEVICES.lock();
    g.iter()
        .filter(|d| !d.detached && d.suspended)
        .filter_map(|d| d.hub_port)
        .collect()
}

/// Wake-watch step: for each parked r8152 port, read the hub
/// port status; on an observed remote-wakeup edge (the
/// `C_PORT_SUSPEND` change bit) resume the port. `port_resume`
/// acks the change bit, so no double-resume. Ports with no
/// edge stay suspended.
pub async fn wake_suspended_ports(xhci_dev: &crate::xhci::Xhci) {
    for (hub_slot, port) in suspended_hub_ports() {
        if crate::attach::hub_port_suspend_change(xhci_dev, hub_slot, port).await == Some(true) {
            let _ = resume_r8152_port(xhci_dev, hub_slot, port).await;
        }
    }
}

// ── Class-registry probe ─────────────────────────────────────────

const MATCHES: &[UsbClassMatch] = &[
    // Realtek
    UsbClassMatch::vid_pid(0x0BDA, 0x8050),
    UsbClassMatch::vid_pid(0x0BDA, 0x8053),
    UsbClassMatch::vid_pid(0x0BDA, 0x8152),
    UsbClassMatch::vid_pid(0x0BDA, 0x8153),
    UsbClassMatch::vid_pid(0x0BDA, 0x8155),
    UsbClassMatch::vid_pid(0x0BDA, 0x8156),
    UsbClassMatch::vid_pid(0x0BDA, 0x8157),
    // Microsoft
    UsbClassMatch::vid_pid(0x045E, 0x07ab),
    UsbClassMatch::vid_pid(0x045E, 0x07c6),
    UsbClassMatch::vid_pid(0x045E, 0x0927),
    UsbClassMatch::vid_pid(0x045E, 0x0c5e),
    // Samsung
    UsbClassMatch::vid_pid(0x04E8, 0xa101),
    // Lenovo
    UsbClassMatch::vid_pid(0x17EF, 0x304f),
    UsbClassMatch::vid_pid(0x17EF, 0x3054),
    UsbClassMatch::vid_pid(0x17EF, 0x3062),
    UsbClassMatch::vid_pid(0x17EF, 0x3069),
    // TP-Link (UE300 family)
    UsbClassMatch::vid_pid(0x2357, 0x0601),
    // Linksys (USB3GIG)
    UsbClassMatch::vid_pid(0x13B1, 0x0041),
    // NVIDIA (Shield controller dock NIC)
    UsbClassMatch::vid_pid(0x0955, 0x09ff),
];

fn probe(device: Arc<USBDevice>, hub_port: Option<(u8, u8)>) -> Result<(), UsbProbeError> {
    // The registry probe is synchronous, but bind needs async
    // control transfers — spawn it (xpad precedent). The hub
    // context rides into bind so the record can participate in
    // hub idle-suspend (#1256).
    narf_scheduler::spawn_stackful(async move {
        use core::fmt::Write;
        if bind(device, hub_port).await.is_err() {
            let _ = writeln!(
                narf_console::Writer,
                "  net: r8152 bind failed (no valid station address or config error)"
            );
        }
    });
    Ok(())
}

/// Detach hook for a slot: tombstone every RTL record bound to
/// it and unregister its net iface. The pump exits at its next
/// `pump_should_continue` check once `pump_running` clears;
/// TX resolves to `None` instead of retargeting a later device
/// (records are never removed — the ECM/NCM rule: net-registry
/// TX cookies are record indices). Unknown slots no-op; repeat
/// detach is a silent no-op (unregister is idempotent).
///
/// RX-mirror obligation (#789, from the #872-review note):
/// RESOLVED as not owed here — same verdict as ECM/NCM:
/// this family's pump delivers via
/// `narf_net::iface::on_rx_frame_from` directly and never calls
/// `publish::note_rx_mirror_attached`, and its `usb-rtl{N}`
/// names cannot collide with the `eth%d` keys the mirror
/// registry can ever hold. No clear call is owed; if this
/// family ever dual-publishes, its detach paths must call
/// `publish::clear_rx_mirror_attached` alongside unregister.
///
/// Panic-free and idempotent by the #893 hook contract: no
/// indexing and no fallible unwraps on any path. Tombstones
/// are set under the registry lock and iface names collected
/// there, but the net unregister runs after the lock is
/// released — the net registry lock must never be taken while
/// the RTL registry lock is held (UVC collect-then-unregister
/// pattern). A TX already past `tx_target` when detach lands
/// may still hit the wire; every later TX fail-closes.
///
/// Infallible bookkeeping, adapted to the [`UsbUnbindFn`]
/// contract with an unconditional `Ok(())` (#893: a hook
/// reports failure with `Err(())`, never by panicking).
pub fn detach_r8152_slot(controller: u8, slot_id: u8) -> Result<(), ()> {
    let ifaces: Vec<String> = {
        let mut g = RTL_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g
            .iter_mut()
            .filter(|d| d.controller == controller && d.slot_id == slot_id && !d.detached)
        {
            dev.detached = true;
            dev.pump_running = false;
            names.push(dev.iface_name.clone());
        }
        names
    };
    for name in ifaces {
        let _ = narf_net::iface::unregister(&name);
    }
    Ok(())
}

/// Wholesale variant of [`detach_r8152_slot`] for controller
/// recovery (`attach::detach_all_bindings`): tombstone every
/// RTL binding on `controller` and unregister its net iface,
/// regardless of slot. Infallible and idempotent, same pump-exit and
/// never-remove reasoning as [`detach_r8152_slot`], and the
/// same #789 mirror verdict (no clear call owed).
pub fn detach_all_r8152(controller: u8) {
    let ifaces: Vec<String> = {
        let mut g = RTL_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g
            .iter_mut()
            .filter(|d| d.controller == controller && !d.detached)
        {
            dev.detached = true;
            dev.pump_running = false;
            names.push(dev.iface_name.clone());
        }
        names
    };
    for name in ifaces {
        let _ = narf_net::iface::unregister(&name);
    }
}

/// Register the r8152 USB class driver, together with its
/// detach hook. The probe spawns the async bind (xpad
/// precedent); the unbind hook adapts infallible
/// `detach_r8152_slot` to the fallible `UsbUnbindFn` contract
/// with an unconditional `Ok(())` (#893: a hook reports
/// failure with `Err(())`, never by panicking).
pub fn register() {
    let _ = register_class_driver_with_unbind("r8152", MATCHES, probe, detach_r8152_slot);
    let _ = crate::class_registry::register_suspend_hook("r8152", |slot, port| {
        alloc::boxed::Box::pin(suspend_r8152_port(slot, port))
    });
}

// ── Fixtures ─────────────────────────────────────────────────────
//
// Modelled-device fixtures in the crate's kernel-test style: the
// register conversation is pinned at the level the production
// code composes it — SETUP-packet packing for each access class,
// the bind's pure decision functions run against modelled
// register contents, and the RX/TX wire formats as byte fixtures.

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_r8152_ocp_setup_packing() -> TestResult {
        // Dword read of PLA_IDR: vendor IN, req 0x05, wValue =
        // address, wIndex = PLA window alone (dword reads pass no
        // byte-enable).
        let (rt, rq, wv, wi) = ocp_read_setup(MCU_TYPE_PLA, PLA_IDR);
        if (rt, rq, wv, wi) != (0xC0, 0x05, 0xC000, 0x0100) {
            return TestResult::Fail("OCP read setup packing wrong");
        }
        // Dword write: wIndex gains the dword byte-enable.
        let (rt, rq, wv, wi, data) = ocp_write_dword_pack(MCU_TYPE_PLA, PLA_RCR, 0x0000_000E);
        if (rt, rq, wv, wi) != (0x40, 0x05, 0xC010, 0x01FF) || data != [0x0E, 0, 0, 0] {
            return TestResult::Fail("OCP dword write packing wrong");
        }
        // Word write at PLA_RMS (0xC016): aligned down to 0xC014,
        // byte-enable 0x33 << 2 in wIndex, value in the high lanes.
        let (_, _, wv, wi, data) = ocp_write_word_pack(MCU_TYPE_PLA, PLA_RMS, 1522);
        if wv != 0xC014 || wi != 0x01CC || data != [0, 0, 0xF2, 0x05] {
            return TestResult::Fail("OCP word write packing wrong");
        }
        // Byte write at PLA_CR (0xE813): aligned to 0xE810, enable
        // 0x11 << 3, value in lane 3.
        let (_, _, wv, wi, data) = ocp_write_byte_pack(MCU_TYPE_PLA, PLA_CR, CR_RST);
        if wv != 0xE810 || wi != 0x0188 || data != [0, 0, 0, CR_RST] {
            return TestResult::Fail("OCP byte write packing wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_ocp_setup_packing);

    fn smoke_r8152_station_address_validation() -> TestResult {
        let good: [u8; 8] = [0x00, 0xE0, 0x4C, 0x36, 0x0A, 0xBC, 0, 0];
        if mac_from_station_bytes(&good) != Some([0x00, 0xE0, 0x4C, 0x36, 0x0A, 0xBC]) {
            return TestResult::Fail("valid station address rejected");
        }
        if mac_from_station_bytes(&[0u8; 8]).is_some() {
            return TestResult::Fail("all-zero address accepted");
        }
        if mac_from_station_bytes(&[0xFFu8; 8]).is_some() {
            return TestResult::Fail("all-ones address accepted");
        }
        let multicast: [u8; 8] = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01, 0, 0];
        if mac_from_station_bytes(&multicast).is_some() {
            return TestResult::Fail("multicast address accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_station_address_validation);

    fn smoke_r8152_rcr_and_cr_updates() -> TestResult {
        // Start from a modelled RCR with unrelated high bits set
        // and promiscuous on: filters land, AAP clears, rest kept.
        let old = 0xDEAD_0000 | RCR_AAP;
        let new = rcr_with_accept_filters(old);
        if new & RCR_AAP != 0 || new & (RCR_APM | RCR_AM | RCR_AB) != RCR_APM | RCR_AM | RCR_AB {
            return TestResult::Fail("RCR accept-filter update wrong");
        }
        if new & 0xFFFF_0000 != 0xDEAD_0000 {
            return TestResult::Fail("RCR unrelated bits clobbered");
        }
        // CR: RE|TE set, RST clear, other bits preserved.
        let cr = cr_with_datapath_enabled(0x02);
        if cr != 0x02 | CR_RE | CR_TE {
            return TestResult::Fail("CR datapath-enable update wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rcr_and_cr_updates);

    fn smoke_r8152_link_status_decode() -> TestResult {
        let (carrier, speed, duplex) = decode_link_status(0);
        if carrier || speed.is_some() || duplex.is_some() {
            return TestResult::Fail("link-down byte decoded as up");
        }
        let (carrier, speed, duplex) =
            decode_link_status(PHYSTAT_LINK | PHYSTAT_1000M | PHYSTAT_FULL_DUP);
        if !carrier || speed != Some(1000) || duplex != Some(narf_net::iface::LinkDuplex::Full) {
            return TestResult::Fail("gigabit full-duplex link decoded wrong");
        }
        let (carrier, speed, duplex) = decode_link_status(PHYSTAT_LINK | PHYSTAT_100M);
        if !carrier || speed != Some(100) || duplex != Some(narf_net::iface::LinkDuplex::Half) {
            return TestResult::Fail("100M half-duplex link decoded wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_link_status_decode);

    fn datagram_frame(len: usize, fill: u8) -> Vec<u8> {
        let mut f = alloc::vec::Vec::new();
        f.resize(len, fill);
        f
    }

    fn smoke_r8152_rx_aggregate_walk() -> TestResult {
        // Three valid frames then a runt descriptor: the walk
        // must yield exactly the three frames and stop at the
        // runt. Segments are built from the Linux `rx_desc`
        // layout (never from the parser under test): `opts1`
        // counts frame + FCS, the 4 FCS bytes follow the frame,
        // and the next descriptor starts at the next 8-byte
        // boundary. The 61-byte frame forces the alignment
        // step (its segment ends at offset 177, the next
        // descriptor sits at 184); a walk without the alignment
        // would read the pad as a descriptor and stop after
        // two frames.
        let f1 = datagram_frame(60, 0xA5);
        let f2 = datagram_frame(61, 0x3C);
        let f3 = datagram_frame(100, 0x77);
        let mut buf = alloc::vec::Vec::new();
        let push_seg = |buf: &mut Vec<u8>, frame: &[u8]| {
            buf.extend_from_slice(&((frame.len() + RX_FCS_LEN) as u32).to_le_bytes()); // opts1
            buf.extend_from_slice(&[0u8; 20]); // opts2..opts6
            buf.extend_from_slice(frame);
            buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // FCS marker
            while buf.len() % RX_DESC_ALIGN != 0 {
                buf.push(0);
            }
        };
        push_seg(&mut buf, &f1);
        push_seg(&mut buf, &f2);
        push_seg(&mut buf, &f3);
        buf.extend_from_slice(&10u32.to_le_bytes()); // runt opts1
        buf.extend_from_slice(&[0u8; 20]);
        buf.extend_from_slice(&[0u8; 10]);
        let segs = parse_rx_aggregate(&buf);
        if segs.len() != 3 {
            return TestResult::Fail("aggregate walk yielded wrong frame count");
        }
        // seg0: desc [0..24), frame [24..84), FCS [84..88).
        // seg1: desc [88..112), frame [112..173), FCS
        // [173..177), pad [177..184). seg2: desc [184..208),
        // frame [208..308), FCS [308..312).
        if segs[0]
            != (RxSegment {
                offset: RX_DESC_LEN,
                len: 60,
                vlan_tag: None,
                csum: RxCsumResult::NotChecked,
            })
        {
            return TestResult::Fail("first segment location wrong");
        }
        if segs[1]
            != (RxSegment {
                offset: 112,
                len: 61,
                vlan_tag: None,
                csum: RxCsumResult::NotChecked,
            })
        {
            return TestResult::Fail("second segment location wrong");
        }
        if segs[2]
            != (RxSegment {
                offset: 208,
                len: 100,
                vlan_tag: None,
                csum: RxCsumResult::NotChecked,
            })
        {
            return TestResult::Fail("third segment location wrong");
        }
        // Delivered bytes are the frames only — the FCS marker
        // is stripped, never handed to the stack.
        if &buf[segs[0].offset..segs[0].offset + segs[0].len] != f1.as_slice()
            || &buf[segs[1].offset..segs[1].offset + segs[1].len] != f2.as_slice()
            || &buf[segs[2].offset..segs[2].offset + segs[2].len] != f3.as_slice()
        {
            return TestResult::Fail("segment payload bytes wrong");
        }
        for seg in &segs {
            if buf[seg.offset + seg.len..seg.offset + seg.len + RX_FCS_LEN]
                != [0xDE, 0xAD, 0xBE, 0xEF]
            {
                return TestResult::Fail("FCS marker not where the length says");
            }
        }
        // Truncated tail: length field runs past the buffer → stop.
        let mut bad = datagram_frame(60, 0x11);
        bad[0..4].copy_from_slice(&500u32.to_le_bytes());
        let mut agg = alloc::vec::Vec::new();
        agg.extend_from_slice(&bad[0..4]);
        agg.extend_from_slice(&[0u8; 20]);
        agg.extend_from_slice(&bad[4..]);
        if !parse_rx_aggregate(&agg).is_empty() {
            return TestResult::Fail("over-long segment not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_aggregate_walk);

    /// Minimal IPv4 frame carrying a TCP or UDP header, for the
    /// RX checksum deliverability tests. The IPv4 header checksum
    /// field is left zero: the parser under test reads only the
    /// protocol byte and the UDP checksum field, never the IP
    /// checksum. `vlan_tag` inserts an inline 802.1Q tag (the
    /// post-splice shape the pump hands the deliverability check).
    fn ipv4_l4_frame(proto: u8, l4_checksum: u16, vlan_tag: Option<u16>) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        if let Some(tag) = vlan_tag {
            f.extend_from_slice(&[0x81, 0x00]);
            f.extend_from_slice(&tag.to_be_bytes());
        }
        f.extend_from_slice(&[0x08, 0x00]);
        let l4_len = if proto == 17 { 8 } else { 20 };
        let total = (20 + l4_len + 4) as u16;
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]);
        f.push(64);
        f.push(proto);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1]);
        f.extend_from_slice(&[10, 0, 0, 2]);
        if proto == 17 {
            f.extend_from_slice(&1234u16.to_be_bytes());
            f.extend_from_slice(&5678u16.to_be_bytes());
            f.extend_from_slice(&12u16.to_be_bytes());
            f.extend_from_slice(&l4_checksum.to_be_bytes());
        } else {
            f.extend_from_slice(&1234u16.to_be_bytes());
            f.extend_from_slice(&5678u16.to_be_bytes());
            f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
            f.extend_from_slice(&[0x50, 0, 0, 0]);
            f.extend_from_slice(&l4_checksum.to_be_bytes());
            f.extend_from_slice(&[0, 0]);
        }
        f.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        f
    }

    fn smoke_r8152_rx_csum_verdict() -> TestResult {
        let cases: &[(u32, u32, RxCsumResult)] = &[
            (0, 0, RxCsumResult::NotChecked),
            (RD_IPV4_CS | RD_TCP_CS, 0, RxCsumResult::Good),
            (RD_IPV4_CS | RD_UDP_CS, 0, RxCsumResult::Good),
            (RD_IPV6_CS | RD_UDP_CS, 0, RxCsumResult::Good),
            (RD_IPV6_CS | RD_TCP_CS, 0, RxCsumResult::Good),
            (
                RD_IPV4_CS,
                RX_IPF,
                RxCsumResult::Bad {
                    ip: true,
                    l4: false,
                },
            ),
            (
                RD_IPV4_CS | RD_TCP_CS,
                RX_TCPF,
                RxCsumResult::Bad {
                    ip: false,
                    l4: true,
                },
            ),
            (
                RD_IPV4_CS | RD_UDP_CS,
                RX_UDPF,
                RxCsumResult::Bad {
                    ip: false,
                    l4: true,
                },
            ),
            // Checked IP only (e.g. ICMP): no L4 verdict either way.
            (RD_IPV4_CS, 0, RxCsumResult::NotChecked),
            // Fail bits for protocols the device did not mark
            // checked are ignored.
            (0, RX_IPF | RX_UDPF | RX_TCPF, RxCsumResult::NotChecked),
            // Stray IPF on an IPv6 frame: IPF only applies to IPv4.
            (RD_IPV6_CS | RD_TCP_CS, RX_IPF, RxCsumResult::Good),
            // Contradictory descriptor (UDP failed, TCP passed):
            // fail-closed Bad, where Linux would optimistically
            // return CHECKSUM_UNNECESSARY via the TCP branch.
            (
                RD_IPV4_CS | RD_UDP_CS | RD_TCP_CS,
                RX_UDPF,
                RxCsumResult::Bad {
                    ip: false,
                    l4: true,
                },
            ),
        ];
        for (opts2, opts3, want) in cases {
            let got = rx_csum_result(*opts2, *opts3);
            if got != *want {
                return TestResult::Fail("rx_csum_result verdict wrong");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_csum_verdict);

    fn smoke_r8152_rx_segment_deliverable() -> TestResult {
        let udp_zero = ipv4_l4_frame(17, 0, None);
        let udp_nonzero = ipv4_l4_frame(17, 0x1234, None);
        let tcp = ipv4_l4_frame(6, 0x1234, None);
        let udp_zero_vlan = ipv4_l4_frame(17, 0, Some(0x0007));
        let short = alloc::vec![0u8; 10];
        // IPv6/UDP with a zero checksum field: no exception (the
        // IPv6 UDP checksum is mandatory), so a Bad verdict drops.
        let mut udp6_zero = Vec::new();
        udp6_zero.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        udp6_zero.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        udp6_zero.extend_from_slice(&[0x86, 0xDD]);
        udp6_zero.extend_from_slice(&[0x60, 0, 0, 0, 0, 12, 17, 64]);
        udp6_zero.extend_from_slice(&[0u8; 32]);
        udp6_zero.extend_from_slice(&1234u16.to_be_bytes());
        udp6_zero.extend_from_slice(&5678u16.to_be_bytes());
        udp6_zero.extend_from_slice(&12u16.to_be_bytes());
        udp6_zero.extend_from_slice(&[0, 0]);
        udp6_zero.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let bad_l4 = RxCsumResult::Bad {
            ip: false,
            l4: true,
        };
        let bad_ip = RxCsumResult::Bad {
            ip: true,
            l4: false,
        };
        let cases: &[(RxCsumResult, &[u8], bool)] = &[
            (RxCsumResult::Good, &udp_zero, true),
            (RxCsumResult::NotChecked, &udp_zero, true),
            // IP failure wins over the UDP-zero exception: the
            // header's fields cannot be trusted.
            (bad_ip, &udp_zero, false),
            // IPv4/UDP zero checksum is legal "no checksum".
            (bad_l4, &udp_zero, true),
            (bad_l4, &udp_nonzero, false),
            (bad_l4, &tcp, false),
            (bad_l4, &udp_zero_vlan, true),
            (bad_l4, &short, false),
            (bad_l4, &udp6_zero, false),
            (
                RxCsumResult::Bad {
                    ip: false,
                    l4: false,
                },
                &udp_zero,
                false,
            ),
        ];
        for (csum, frame, want) in cases {
            if rx_segment_deliverable(*csum, frame) != *want {
                return TestResult::Fail("rx_segment_deliverable wrong");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_segment_deliverable);

    fn smoke_r8152_rx_aggregate_csum_carriage() -> TestResult {
        // One Good and one Bad segment: the walk must carry each
        // segment's verdict, not just its location.
        let mut f_good = ipv4_l4_frame(6, 0x1234, None);
        f_good.resize(60, 0);
        let mut f_bad = ipv4_l4_frame(6, 0x1234, None);
        f_bad.resize(60, 0);
        let mut buf = Vec::new();
        let push_seg = |buf: &mut Vec<u8>, frame: &[u8], opts2: u32, opts3: u32| {
            // Linux layout: opts1 counts frame + FCS, FCS
            // bytes follow the frame, next descriptor at the
            // next 8-byte boundary (88 is already aligned).
            buf.extend_from_slice(&((frame.len() + RX_FCS_LEN) as u32).to_le_bytes());
            buf.extend_from_slice(&opts2.to_le_bytes());
            buf.extend_from_slice(&opts3.to_le_bytes());
            buf.extend_from_slice(&[0u8; 12]);
            buf.extend_from_slice(frame);
            buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // FCS marker
            while buf.len() % RX_DESC_ALIGN != 0 {
                buf.push(0);
            }
        };
        push_seg(&mut buf, &f_good, RD_IPV4_CS | RD_TCP_CS, 0);
        push_seg(&mut buf, &f_bad, RD_IPV4_CS | RD_TCP_CS, RX_TCPF);
        let segs = parse_rx_aggregate(&buf);
        if segs.len() != 2 {
            return TestResult::Fail("aggregate csum walk frame count wrong");
        }
        if segs[0].csum != RxCsumResult::Good {
            return TestResult::Fail("good segment verdict lost");
        }
        if segs[1].csum
            != (RxCsumResult::Bad {
                ip: false,
                l4: true,
            })
        {
            return TestResult::Fail("bad segment verdict lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_aggregate_csum_carriage);

    /// One v2 RX segment, built from the Linux `rx_desc_v2`
    /// format (never from the parser under test): 16-byte
    /// descriptor, length in `opts1` bits 17..31 counting
    /// frame + FCS, VLAN present-bit in `opts1` with the TCI
    /// in the high half of `opts2`, checksum report/fail bits
    /// in `opts3`; frame bytes, then a 4-byte FCS marker, then
    /// zero pad to the next 16-byte boundary.
    fn push_v2_seg(buf: &mut Vec<u8>, frame: &[u8], opts1_extra: u32, opts2: u32, opts3: u32) {
        let pkt_len = frame.len() + RX_FCS_LEN;
        let opts1 = ((pkt_len as u32) << RX_V2_LEN_SHIFT) | opts1_extra;
        buf.extend_from_slice(&opts1.to_le_bytes());
        buf.extend_from_slice(&opts2.to_le_bytes());
        buf.extend_from_slice(&opts3.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]); // opts4
        buf.extend_from_slice(frame);
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // FCS marker
        while buf.len() % RX_DESC_V2_ALIGN != 0 {
            buf.push(0);
        }
    }

    fn smoke_r8152_rx_v2_decode() -> TestResult {
        // Length: bits 17..31, low bits ignored.
        if rx_len_v2((104u32 << RX_V2_LEN_SHIFT) | 0x2) != 104 {
            return TestResult::Fail("v2 length decode wrong");
        }
        // VLAN: present-bit in opts1, TCI in the HIGH half of
        // opts2, byte-swapped (0x0064 <-> 0x6400).
        if rx_vlan_tag_v2(RX_V2_VLAN_TAG_BIT, 0x6400_0000) != Some(0x0064) {
            return TestResult::Fail("v2 VLAN tag decode wrong");
        }
        if rx_vlan_tag_v2(0, 0x6400_0000).is_some() {
            return TestResult::Fail("v2 tag bit clear must mean no tag");
        }
        // A v1-shaped VLAN word must NOT decode as v2: v1 puts
        // the present-bit in opts2 bit 16 and the TCI in the
        // low half — both are the wrong places for v2.
        if rx_vlan_tag_v2(0, RX_VLAN_TAG_BIT | 0x6400).is_some() {
            return TestResult::Fail("v1 VLAN word must not decode as v2");
        }
        // Checksum verdicts, all bits in opts3.
        if rx_csum_result_v2(0) != RxCsumResult::NotChecked
            || rx_csum_result_v2(RD_IPV4_CS_V2 | RD_TCP_CS_V2) != RxCsumResult::Good
            || rx_csum_result_v2(RD_IPV6_CS_V2 | RD_UDP_CS_V2) != RxCsumResult::Good
            || rx_csum_result_v2(RD_IPV4_CS_V2) != RxCsumResult::NotChecked
            || rx_csum_result_v2(RX_TCPF_V2) != RxCsumResult::NotChecked
        {
            return TestResult::Fail("v2 csum good/unchecked verdicts wrong");
        }
        if rx_csum_result_v2(RD_IPV4_CS_V2 | RD_TCP_CS_V2 | RX_TCPF_V2)
            != (RxCsumResult::Bad {
                ip: false,
                l4: true,
            })
            || rx_csum_result_v2(RD_IPV6_CS_V2 | RD_UDP_CS_V2 | RX_UDPF_V2)
                != (RxCsumResult::Bad {
                    ip: false,
                    l4: true,
                })
            || rx_csum_result_v2(RD_IPV4_CS_V2 | RX_IPF_V2)
                != (RxCsumResult::Bad {
                    ip: true,
                    l4: false,
                })
        {
            return TestResult::Fail("v2 csum bad verdicts wrong");
        }
        // Fail-closed deviation from Linux: IPv4 + IP fail is
        // Bad even when an L4 check passed (Linux's first
        // branch returns NONE before looking at L4).
        if rx_csum_result_v2(RD_IPV4_CS_V2 | RX_IPF_V2 | RD_TCP_CS_V2)
            != (RxCsumResult::Bad {
                ip: true,
                l4: false,
            })
        {
            return TestResult::Fail("v2 IP-fail must dominate a passing L4");
        }
        // Version selection: only VER_16 (RTL8157) speaks v2.
        if !uses_rx_desc_v2(RtlVersion::Ver16)
            || uses_rx_desc_v2(RtlVersion::Ver15)
            || uses_rx_desc_v2(RtlVersion::Ver10)
            || uses_rx_desc_v2(RtlVersion::Unknown)
            || version_from_tcr1(0x1030) != RtlVersion::Ver16
        {
            return TestResult::Fail("v2 version selection wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_v2_decode);

    fn smoke_r8152_rx_aggregate_walk_v2() -> TestResult {
        // Three frames, then a runt descriptor. The 100-byte
        // frame forces the 16-byte alignment step (its segment
        // ends at offset 200, the next descriptor sits at 208);
        // a walk without the alignment would read the pad as a
        // descriptor and stop after two frames.
        let f1 = datagram_frame(60, 0xA5);
        let f2 = datagram_frame(100, 0x3C);
        let f3 = datagram_frame(61, 0x77);
        let mut buf = alloc::vec::Vec::new();
        push_v2_seg(
            &mut buf,
            &f1,
            RX_V2_VLAN_TAG_BIT,
            0x6400_0000,
            RD_IPV4_CS_V2 | RD_TCP_CS_V2,
        );
        push_v2_seg(&mut buf, &f2, 0, 0, 0);
        push_v2_seg(&mut buf, &f3, 0, 0, 0);
        // Runt descriptor: length 10 < ETH_ZLEN.
        buf.extend_from_slice(&((10u32) << RX_V2_LEN_SHIFT).to_le_bytes());
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(&[0u8; 10]);
        let segs = parse_rx_aggregate_v2(&buf);
        if segs.len() != 3 {
            return TestResult::Fail("v2 aggregate walk yielded wrong frame count");
        }
        // seg0: desc [0..16), frame [16..76), FCS [76..80).
        // seg1: desc [80..96), frame [96..196), FCS [196..200),
        // pad [200..208). seg2: desc [208..224), frame
        // [224..285), FCS [285..289).
        if segs[0]
            != (RxSegment {
                offset: RX_DESC_V2_LEN,
                len: 60,
                vlan_tag: Some(0x0064),
                csum: RxCsumResult::Good,
            })
        {
            return TestResult::Fail("v2 first segment location/verdict wrong");
        }
        if segs[1]
            != (RxSegment {
                offset: 96,
                len: 100,
                vlan_tag: None,
                csum: RxCsumResult::NotChecked,
            })
        {
            return TestResult::Fail("v2 second segment location wrong");
        }
        if segs[2]
            != (RxSegment {
                offset: 224,
                len: 61,
                vlan_tag: None,
                csum: RxCsumResult::NotChecked,
            })
        {
            return TestResult::Fail("v2 third segment location wrong");
        }
        // Delivered bytes are the frames only — the FCS marker
        // is stripped, never handed to the stack.
        if &buf[segs[0].offset..segs[0].offset + segs[0].len] != f1.as_slice()
            || &buf[segs[1].offset..segs[1].offset + segs[1].len] != f2.as_slice()
            || &buf[segs[2].offset..segs[2].offset + segs[2].len] != f3.as_slice()
        {
            return TestResult::Fail("v2 segment payload bytes wrong");
        }
        if buf[segs[0].offset + segs[0].len..segs[0].offset + segs[0].len + 4]
            != [0xDE, 0xAD, 0xBE, 0xEF]
        {
            return TestResult::Fail("v2 FCS marker not where the length says");
        }
        // The v1 parser on the same buffer must NOT reproduce
        // these segments: v2 opts1 low bits read as length 0,
        // so it stops immediately. This pins that the layouts
        // actually differ — the finding this issue verifies.
        if !parse_rx_aggregate(&buf).is_empty() {
            return TestResult::Fail("v1 parser must not walk a v2 buffer");
        }
        // Truncated tail: length field runs past the buffer.
        let mut bad = alloc::vec::Vec::new();
        bad.extend_from_slice(&((500u32) << RX_V2_LEN_SHIFT).to_le_bytes());
        bad.extend_from_slice(&[0u8; 12]);
        bad.extend_from_slice(&[0u8; 60]);
        if !parse_rx_aggregate_v2(&bad).is_empty() {
            return TestResult::Fail("v2 over-long segment not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_aggregate_walk_v2);

    fn smoke_r8152_tx_segment_v2() -> TestResult {
        let frame = datagram_frame(61, 0x5A);
        let mut out = Vec::new();
        if build_tx_segment_v2(&frame, &mut out).is_err() {
            return TestResult::Fail("clean v2 frame rejected");
        }
        // 16-byte desc + 61-byte frame = 77, padded to 80.
        if out.len() != 80 {
            return TestResult::Fail("v2 TX segment padding wrong");
        }
        let opts1 = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let opts2 = u32::from_le_bytes(out[4..8].try_into().unwrap());
        let opts3 = u32::from_le_bytes(out[8..12].try_into().unwrap());
        let opts4 = u32::from_le_bytes(out[12..16].try_into().unwrap());
        if opts1 != 61 | TX_FS | TX_LS {
            return TestResult::Fail("v2 TX opts1 wrong");
        }
        if opts2 != 0 {
            return TestResult::Fail("v2 TX opts2 not zero");
        }
        if opts3 != 61 << TX_V2_LEN_SHIFT {
            return TestResult::Fail("v2 TX opts3 length wrong");
        }
        if opts4 != TX_V2_SIG {
            return TestResult::Fail("v2 TX opts4 signature wrong");
        }
        if out[16..77] != frame[..] || out[77..] != [0, 0, 0] {
            return TestResult::Fail("v2 TX payload/padding bytes wrong");
        }
        // Oversize frame (> TX_LEN_MASK) refused.
        let big = datagram_frame(TX_LEN_MASK as usize + 1, 0);
        if build_tx_segment_v2(&big, &mut Vec::new()).is_ok() {
            return TestResult::Fail("v2 oversize frame accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_tx_segment_v2);

    fn smoke_r8152_tx_segment_meta_v2() -> TestResult {
        let frame = ipv4_tcp_frame(10);
        // Plain meta reproduces build_tx_segment_v2 byte for byte.
        let mut plain_meta = Vec::new();
        let mut plain = Vec::new();
        if build_tx_segment_meta_v2(&frame, narf_net::TxMeta::plain(), &mut plain_meta).is_err()
            || build_tx_segment_v2(&frame, &mut plain).is_err()
            || plain_meta != plain
        {
            return TestResult::Fail("v2 plain meta must match the plain builder");
        }
        // VLAN insert: opts2 = TAG_BIT | swab16(0x1234), with
        // the v2 opts3/opts4 tail.
        let mut out = Vec::new();
        let meta = narf_net::TxMeta {
            vlan_tag: Some(0x1234),
            ..narf_net::TxMeta::plain()
        };
        if build_tx_segment_meta_v2(&frame, meta, &mut out).is_err() {
            return TestResult::Fail("v2 VLAN frame rejected");
        }
        let opts2 = u32::from_le_bytes(out[4..8].try_into().unwrap());
        let opts3 = u32::from_le_bytes(out[8..12].try_into().unwrap());
        let opts4 = u32::from_le_bytes(out[12..16].try_into().unwrap());
        if opts2 != TX_VLAN_TAG_BIT | 0x3412 {
            return TestResult::Fail("v2 VLAN opts2 wrong");
        }
        if opts3 != (frame.len() as u32) << TX_V2_LEN_SHIFT || opts4 != TX_V2_SIG {
            return TestResult::Fail("v2 VLAN tail wrong");
        }
        // IPv4/TCP checksum offload: IPV4_CS | TCP_CS | 34<<17.
        let mut out = Vec::new();
        let meta = narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Tcp);
        if build_tx_segment_meta_v2(&frame, meta, &mut out).is_err() {
            return TestResult::Fail("v2 csum frame rejected");
        }
        let opts2 = u32::from_le_bytes(out[4..8].try_into().unwrap());
        if opts2 != TX_IPV4_CS | TX_TCP_CS | (34 << TX_TCPHO_SHIFT) {
            return TestResult::Fail("v2 csum opts2 wrong");
        }
        // Hardware TSO: GTSENDV4 + 34<<18 in opts1, 1460<<17
        // in opts2 — the TSO cap is unchanged from v1.
        let mut out = Vec::new();
        let meta = narf_net::TxMeta::with_tso(1460);
        if build_tx_segment_meta_v2(&frame, meta, &mut out).is_err() {
            return TestResult::Fail("v2 TSO frame rejected");
        }
        let opts1 = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let opts2 = u32::from_le_bytes(out[4..8].try_into().unwrap());
        let len = frame.len() as u32;
        if opts1 != len | TX_FS | TX_LS | TX_GTSENDV4 | (34 << TX_GTTCPHO_SHIFT) {
            return TestResult::Fail("v2 TSO opts1 wrong");
        }
        if opts2 != 1460 << TX_MSS_SHIFT {
            return TestResult::Fail("v2 TSO opts2 wrong");
        }
        // The v2 checksum transport-offset cap is tighter than
        // v1's (0x3FF vs 0x7FF); the constant pins the Linux
        // `TCPHO_MAX_2` value the encoder enforces.
        if TX_TCPHO_MAX_V2 != 0x3FF || TX_TCPHO_MAX_V2 >= TX_TCPHO_MAX {
            return TestResult::Fail("v2 TCPHO cap wrong");
        }
        // Rejection: SCTP csum is rejected, as in v1.
        if build_tx_segment_meta_v2(
            &frame,
            narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Sctp),
            &mut Vec::new(),
        )
        .is_ok()
        {
            return TestResult::Fail("v2 SCTP offload must be rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_tx_segment_meta_v2);

    fn smoke_r8152_tx_segment_build() -> TestResult {
        let frame = datagram_frame(61, 0x5A);
        let mut out = Vec::new();
        if build_tx_segment(&frame, &mut out).is_err() {
            return TestResult::Fail("clean frame rejected");
        }
        // 8-byte desc + 61-byte frame = 69, padded to 72.
        if out.len() != 72 {
            return TestResult::Fail("TX segment padding wrong");
        }
        let opts1 = u32::from_le_bytes(out[0..4].try_into().unwrap());
        if opts1 != 61 | TX_FS | TX_LS {
            return TestResult::Fail("TX opts1 wrong");
        }
        if out[4..8] != [0, 0, 0, 0] {
            return TestResult::Fail("TX opts2 not zero");
        }
        if out[8..69] != frame[..] || out[69..] != [0, 0, 0] {
            return TestResult::Fail("TX payload/padding bytes wrong");
        }
        // Oversize frame (> TX_LEN_MASK) refused.
        let big = datagram_frame(TX_LEN_MASK as usize + 1, 0);
        if build_tx_segment(&big, &mut Vec::new()).is_ok() {
            return TestResult::Fail("oversize frame accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_tx_segment_build);

    fn smoke_r8152_endpoint_finder() -> TestResult {
        // Modelled RTL8153 configuration: config header, a vendor
        // interface (class 0xFF) with bulk IN 0x81 / OUT 0x02 and
        // an interrupt endpoint that must be ignored.
        #[rustfmt::skip]
        let cfg: &[u8] = &[
            9, 2, 32, 0, 1, 1, 0, 0x80, 0x32, // config
            9, 4, 0, 0, 3, 0xFF, 0, 0, 0,    // vendor interface
            7, 5, 0x81, 2, 0x00, 0x04, 0,    // bulk IN, 1024
            7, 5, 0x02, 2, 0x00, 0x04, 0,    // bulk OUT, 1024
            7, 5, 0x83, 3, 16, 0, 8,         // interrupt IN
        ];
        let (i, o) = match find_rtl_endpoints(cfg) {
            Some(t) => t,
            None => return TestResult::Fail("modelled endpoints not found"),
        };
        if i.ep_addr != 0x81 || o.ep_addr != 0x02 || i.max_packet != 1024 {
            return TestResult::Fail("modelled endpoints decoded wrong");
        }
        // A CDC-class config has no vendor interface → no match.
        #[rustfmt::skip]
        let cdc: &[u8] = &[
            9, 2, 25, 0, 1, 1, 0, 0x80, 0x32,
            9, 4, 0, 0, 2, 0x0A, 0, 0, 0,
            7, 5, 0x81, 2, 64, 0, 0,
            7, 5, 0x02, 2, 64, 0, 0,
        ];
        if find_rtl_endpoints(cdc).is_some() {
            return TestResult::Fail("CDC config falsely claimed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_endpoint_finder);

    fn smoke_r8152_modelled_bind_conversation() -> TestResult {
        // Walk the bind's register conversation against a modelled
        // register file: the modelled device answers the IDR read
        // with its programmed station address, and the writes the
        // bind would issue are checked field by field.
        // 1. Read station address from PLA_IDR.
        let (rt, rq, wv, wi) = ocp_read_setup(MCU_TYPE_PLA, PLA_IDR);
        if (rt, rq, wv, wi) != (0xC0, 0x05, PLA_IDR, MCU_TYPE_PLA) {
            return TestResult::Fail("conversation: IDR read setup wrong");
        }
        let modelled_idr: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0, 0];
        let mac = match mac_from_station_bytes(&modelled_idr) {
            Some(m) => m,
            None => return TestResult::Fail("conversation: modelled MAC rejected"),
        };
        if mac != [0x10, 0x20, 0x30, 0x40, 0x50, 0x60] {
            return TestResult::Fail("conversation: MAC bytes wrong");
        }
        // 2. Multicast table: two dword writes of all-ones at
        //    PLA_MAR / PLA_MAR+4.
        for addr in [PLA_MAR, PLA_MAR + 4] {
            let (_, _, wv, wi, data) = ocp_write_dword_pack(MCU_TYPE_PLA, addr, 0xFFFF_FFFF);
            if wv != addr || wi != MCU_TYPE_PLA | BYTE_EN_DWORD || data != [0xFF; 4] {
                return TestResult::Fail("conversation: MAR write wrong");
            }
        }
        // 3. RCR write carries the accept-filter update of the
        //    modelled reset value 0.
        let (_, _, wv, _, data) =
            ocp_write_dword_pack(MCU_TYPE_PLA, PLA_RCR, rcr_with_accept_filters(0));
        if wv != PLA_RCR || data != (RCR_APM | RCR_AM | RCR_AB).to_le_bytes() {
            return TestResult::Fail("conversation: RCR write wrong");
        }
        // 4. CR byte write enables RE|TE at PLA_CR.
        let (_, _, wv, wi, data) =
            ocp_write_byte_pack(MCU_TYPE_PLA, PLA_CR, cr_with_datapath_enabled(0));
        if wv != PLA_CR & !3 || wi != 0x0188 || data != [0, 0, 0, CR_RE | CR_TE] {
            return TestResult::Fail("conversation: CR enable write wrong");
        }
        // 5. Generation/RMS pairing the bind programs.
        if generation_for_pid(0x8152) != RtlGen::Fe || rx_max_size(RtlGen::Fe) != 1522 {
            return TestResult::Fail("conversation: FE generation mapping wrong");
        }
        if generation_for_pid(0x8153) != RtlGen::GbE || rx_max_size(RtlGen::GbE) != 9216 {
            return TestResult::Fail("conversation: GbE generation mapping wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_modelled_bind_conversation);

    fn smoke_r8152_tx_routing_two_devices() -> TestResult {
        // Two modelled devices in the table: tx_target must
        // resolve each record index to ITS OWN slot/endpoint —
        // the per-device routing the send trampoline relies on.
        RTL_DEVICES.lock().clear();
        let mk = |slot_id: u8, out_dci: u8| RtlDevice {
            slot_id,
            generation: RtlGen::GbE,
            version: RtlVersion::Ver03,
            wol_opts: WolOpts::default(),
            mac: [0x02, 0, 0, 0, 0, slot_id],
            bulk_in_dci: 3,
            bulk_out_dci: out_dci,
            iface_name: alloc::format!("usb-rtl-model-{}", slot_id),
            pump_running: false,
            link_byte: 0xFF,
            mtu: 1500,
            pending_rms: None,
            detached: false,
            controller: 0,
            hub_port: None,
            speed: crate::xhci::PortSpeed::High,
            suspended: false,
            wakeup_armed: false,
        };
        {
            let mut g = RTL_DEVICES.lock();
            g.push(mk(7, 4));
            g.push(mk(9, 6));
        }
        let t0 = tx_target(0);
        let t1 = tx_target(1);
        RTL_DEVICES.lock().clear();
        if t0 != Some((7, 4)) || t1 != Some((9, 6)) {
            return TestResult::Fail("tx_target mis-routed between devices");
        }
        if tx_target(0).is_some() {
            return TestResult::Fail("tx_target resolved a removed device");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_tx_routing_two_devices);

    /// Two modelled RTL devices bind; detaching the first
    /// tombstones exactly its record (TX fail-closes, net iface
    /// unregisters, survivor untouched), detach is idempotent
    /// and a no-op for unknown slots, wholesale detach clears
    /// the rest, and a re-push of the same slot publishes under
    /// a fresh index — never a duplicate iface, never a
    /// retargeted TX cookie. Masking-defeating case: the
    /// detached record's pump had already exited
    /// (`pump_running` false before detach) yet detach still
    /// tombstones + unregisters.
    fn smoke_r8152_detach_tombstones_and_unregisters() -> TestResult {
        RTL_DEVICES.lock().clear();
        let mk = |slot_id: u8, out_dci: u8| RtlDevice {
            slot_id,
            generation: RtlGen::GbE,
            version: RtlVersion::Ver03,
            wol_opts: WolOpts::default(),
            mac: [0x02, 0, 0, 0, 0, slot_id],
            bulk_in_dci: 3,
            bulk_out_dci: out_dci,
            iface_name: alloc::format!("usb-rtl-detach{}", slot_id),
            pump_running: true,
            link_byte: 0xFF,
            mtu: 1500,
            pending_rms: None,
            detached: false,
            controller: 0,
            hub_port: None,
            speed: crate::xhci::PortSpeed::High,
            suspended: false,
            wakeup_armed: false,
        };
        {
            let mut g = RTL_DEVICES.lock();
            g.push(mk(7, 4));
            g.push(mk(9, 6));
        }
        // Register the net ifaces for real, capturing the
        // assigned names, so the unregister half is asserted
        // against the net registry, not trusted. Names follow
        // the production rule (`usb-rtl{record index}`).
        let (name7, name9) = {
            let mut g = RTL_DEVICES.lock();
            let n7 = narf_net::iface::register_with_context(
                "usb-rtl0",
                [0x02, 0, 0, 0, 0, 7],
                0,
                rtl_send_ctx,
            );
            let n9 = narf_net::iface::register_with_context(
                "usb-rtl1",
                [0x02, 0, 0, 0, 0, 9],
                1,
                rtl_send_ctx,
            );
            g[0].iface_name = n7.clone();
            g[1].iface_name = n9.clone();
            (n7, n9)
        };
        if narf_net::iface::lookup(&name7).is_none() || narf_net::iface::lookup(&name9).is_none() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("net ifaces must resolve before detach");
        }
        // Simulate the first pump having already exited.
        {
            let mut g = RTL_DEVICES.lock();
            g[0].pump_running = false;
        }
        if detach_r8152_slot(0, 7).is_err() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("detach must be infallible");
        }
        let ok = tx_target(0).is_none()
            && narf_net::iface::lookup(&name7).is_none()
            && tx_target(1) == Some((9, 6))
            && narf_net::iface::lookup(&name9).is_some();
        if !ok {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("detach must tombstone exactly one binding");
        }
        // Idempotent, and unknown slots are a silent no-op.
        let _ = detach_r8152_slot(0, 7);
        let _ = detach_r8152_slot(0, 99);
        if tx_target(1) != Some((9, 6)) {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("repeat/unknown detach must not change the registry");
        }
        detach_all_r8152(0);
        if tx_target(1).is_some() || narf_net::iface::lookup(&name9).is_some() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("wholesale detach must clear every binding");
        }
        // Re-push the same slot: records are never removed, so
        // the new record lands at a fresh index with a fresh
        // iface name — never a duplicate, never a recycled
        // cookie. The re-bound name follows the production
        // rule (`usb-rtl{record index}`), exactly as bind
        // assigns it.
        let idx = {
            let mut g = RTL_DEVICES.lock();
            let idx = g.len();
            g.push(mk(7, 4));
            g[idx].iface_name = alloc::format!("usb-rtl{}", idx);
            idx
        };
        if idx != 2 {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("re-bind must not reuse a tombstoned index");
        }
        let fresh = {
            let g = RTL_DEVICES.lock();
            g[idx].iface_name.clone()
        };
        if fresh == name7 {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("re-bind must not recycle the detached iface name");
        }
        let _ = detach_r8152_slot(0, 7);
        if tx_target(idx).is_some() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("cleanup detach must leave no live binding");
        }
        RTL_DEVICES.lock().clear();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/r8152",
        smoke_r8152_detach_tombstones_and_unregisters
    );

    /// The class-registry unbind hook installed by
    /// `r8152::register` must reach `detach_r8152_slot`
    /// through the supervisor's `dispatch_unbind` path — the
    /// wiring the hub-detach path actually uses, not just the
    /// detach function in isolation.
    fn smoke_r8152_dispatch_unbind_reaches_detach() -> TestResult {
        RTL_DEVICES.lock().clear();
        {
            let mut g = RTL_DEVICES.lock();
            g.push(RtlDevice {
                slot_id: 7,
                generation: RtlGen::GbE,
                version: RtlVersion::Ver03,
                wol_opts: WolOpts::default(),
                mac: [0x02, 0, 0, 0, 0, 7],
                bulk_in_dci: 3,
                bulk_out_dci: 4,
                iface_name: alloc::format!("usb-rtl-detach{}", 7),
                pump_running: true,
                link_byte: 0xFF,
                mtu: 1500,
                pending_rms: None,
                detached: false,
                controller: 0,
                hub_port: None,
                speed: crate::xhci::PortSpeed::High,
                suspended: false,
                wakeup_armed: false,
            });
        }
        register();
        let report = crate::class_registry::dispatch_unbind(0, 7);
        let live = tx_target(0);
        RTL_DEVICES.lock().clear();
        if report.invoked == 0 {
            return TestResult::Fail("dispatch_unbind invoked no hooks");
        }
        if live.is_some() {
            return TestResult::Fail("unbind hook must tombstone the slot 7 binding");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/r8152",
        smoke_r8152_dispatch_unbind_reaches_detach
    );

    /// #789 remainder (a): rebind-on-redock proof. Two modelled
    /// RTL devices bind with real net ifaces; the supervisor's
    /// `dispatch_unbind` path detaches the first; a re-push of
    /// the same slot — the shape bind takes on replug, after
    /// the supervisor cleared the port claim — lands at a fresh
    /// index with a fresh iface name, TX resolves to the NEW
    /// device, and the old cookie fail-closes.
    fn smoke_r8152_redock_rebind_via_dispatch() -> TestResult {
        RTL_DEVICES.lock().clear();
        let mk = |slot_id: u8, out_dci: u8| RtlDevice {
            slot_id,
            generation: RtlGen::GbE,
            version: RtlVersion::Ver03,
            wol_opts: WolOpts::default(),
            mac: [0x02, 0, 0, 0, 0, slot_id],
            bulk_in_dci: 3,
            bulk_out_dci: out_dci,
            iface_name: alloc::format!("usb-rtl-detach{}", slot_id),
            pump_running: true,
            link_byte: 0xFF,
            mtu: 1500,
            pending_rms: None,
            detached: false,
            controller: 0,
            hub_port: None,
            speed: crate::xhci::PortSpeed::High,
            suspended: false,
            wakeup_armed: false,
        };
        {
            let mut g = RTL_DEVICES.lock();
            g.push(mk(7, 4));
            g.push(mk(9, 6));
        }
        let (name7, name9) = {
            let mut g = RTL_DEVICES.lock();
            let n7 = narf_net::iface::register_with_context(
                "usb-rtl0",
                [0x02, 0, 0, 0, 0, 7],
                0,
                rtl_send_ctx,
            );
            let n9 = narf_net::iface::register_with_context(
                "usb-rtl1",
                [0x02, 0, 0, 0, 0, 9],
                1,
                rtl_send_ctx,
            );
            g[0].iface_name = n7.clone();
            g[1].iface_name = n9.clone();
            (n7, n9)
        };
        if narf_net::iface::lookup(&name7).is_none() || narf_net::iface::lookup(&name9).is_none() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("net ifaces must resolve before detach");
        }
        register();
        let report = crate::class_registry::dispatch_unbind(0, 7);
        if report.invoked == 0 {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("dispatch_unbind invoked no hooks");
        }
        if tx_target(0).is_some()
            || narf_net::iface::lookup(&name7).is_some()
            || tx_target(1) != Some((9, 6))
        {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("dispatch detach must tombstone exactly one binding");
        }
        // Re-plug: fresh record, published under the production
        // name rule with a real net iface — never a recycled
        // cookie or name.
        let idx = {
            let mut g = RTL_DEVICES.lock();
            let idx = g.len();
            g.push(mk(7, 4));
            let requested = alloc::format!("usb-rtl{}", idx);
            let assigned = narf_net::iface::register_with_context(
                &requested,
                [0x02, 0, 0, 0, 0, 7],
                idx as u64,
                rtl_send_ctx,
            );
            g[idx].iface_name = assigned;
            idx
        };
        if idx != 2 {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("re-bind must not reuse a tombstoned index");
        }
        let fresh = {
            let g = RTL_DEVICES.lock();
            g[idx].iface_name.clone()
        };
        if fresh == name7
            || tx_target(idx) != Some((7, 4))
            || tx_target(0).is_some()
            || narf_net::iface::lookup(&fresh).is_none()
        {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("re-bind must publish fresh and keep the old cookie dead");
        }
        let _ = detach_r8152_slot(0, 7);
        RTL_DEVICES.lock().clear();
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_redock_rebind_via_dispatch);

    fn smoke_r8152_version_decode() -> TestResult {
        // Linux's __rtl_get_hw_ver switch, code for code; low
        // bits outside the version mask must not change the
        // verdict (the mask is applied inside the decoder).
        let cases: &[(u16, RtlVersion)] = &[
            (0x4C00, RtlVersion::Ver01),
            (0x4C10, RtlVersion::Ver02),
            (0x5C00, RtlVersion::Ver03),
            (0x5C0F, RtlVersion::Ver03),
            (0x5C10, RtlVersion::Ver04),
            (0x5C20, RtlVersion::Ver05),
            (0x5C30, RtlVersion::Ver06),
            (0x4800, RtlVersion::Ver07),
            (0x6000, RtlVersion::Ver08),
            (0x6010, RtlVersion::Ver09),
            (0x7010, RtlVersion::Test01),
            (0x7020, RtlVersion::Ver10),
            (0x7030, RtlVersion::Ver11),
            (0x7400, RtlVersion::Ver12),
            (0x7410, RtlVersion::Ver13),
            (0x6400, RtlVersion::Ver14),
            (0x7420, RtlVersion::Ver15),
            (0x1030, RtlVersion::Ver16),
            (0x2020, RtlVersion::Ver17),
            (0x0000, RtlVersion::Unknown),
            (0x7FFF, RtlVersion::Unknown),
        ];
        for (raw, want) in cases {
            if version_from_tcr1(*raw) != *want {
                return TestResult::Fail("TCR1 version decode wrong");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_version_decode);

    fn smoke_r8152_ocp_reg_window() -> TestResult {
        // OCP window derivation (Linux ocp_reg_read/write): the
        // high nibble selects the base, the low 12 bits OR'd
        // with 0xb000 select the index.
        if ocp_reg_window(OCP_POWER_CFG) != (0xA000, 0xB430) {
            return TestResult::Fail("OCP_POWER_CFG window wrong");
        }
        if ocp_reg_window(OCP_EEE_ADV) != (0xA000, 0xB5D0) {
            return TestResult::Fail("OCP_EEE_ADV window wrong");
        }
        if ocp_reg_window(OCP_SRAM_ADDR) != (0xA000, 0xB436) {
            return TestResult::Fail("OCP_SRAM_ADDR window wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_ocp_reg_window);

    fn smoke_r8152_phy_init_table_shape() -> TestResult {
        // Every known version gets a sequence; TEST_01 and
        // unknown versions keep reset defaults (empty table,
        // never a bind failure).
        for version in [
            RtlVersion::Ver01,
            RtlVersion::Ver02,
            RtlVersion::Ver03,
            RtlVersion::Ver04,
            RtlVersion::Ver05,
            RtlVersion::Ver06,
            RtlVersion::Ver07,
            RtlVersion::Ver08,
            RtlVersion::Ver09,
            RtlVersion::Ver10,
            RtlVersion::Ver11,
            RtlVersion::Ver12,
            RtlVersion::Ver13,
            RtlVersion::Ver14,
            RtlVersion::Ver15,
            RtlVersion::Ver16,
            RtlVersion::Ver17,
        ] {
            if phy_init_ops(version).is_empty() {
                return TestResult::Fail("known version must have a PHY table");
            }
        }
        if !phy_init_ops(RtlVersion::Test01).is_empty()
            || !phy_init_ops(RtlVersion::Unknown).is_empty()
        {
            return TestResult::Fail("unported version must have an empty PHY table");
        }
        let v03 = phy_init_ops(RtlVersion::Ver03);
        let v04 = phy_init_ops(RtlVersion::Ver04);
        let v05 = phy_init_ops(RtlVersion::Ver05);
        let v06 = phy_init_ops(RtlVersion::Ver06);
        // VER_03 carries exactly one more step than VER_04: the
        // CTAP_SHORT_EN clear at position 5 (right after the
        // firmware step).
        if v03.len() != v04.len() + 1 {
            return TestResult::Fail("VER_03 table must exceed VER_04 by the CTAP step");
        }
        if v03[5]
            != (PhyInitOp::OcpRegClrBits {
                addr: OCP_EEE_CFG,
                bits: EEE_CFG_CTAP_SHORT_EN,
            })
        {
            return TestResult::Fail("VER_03 table must clear CTAP_SHORT_EN fifth");
        }
        if v04.iter().any(|op| {
            *op == (PhyInitOp::OcpRegClrBits {
                addr: OCP_EEE_CFG,
                bits: EEE_CFG_CTAP_SHORT_EN,
            })
        }) {
            return TestResult::Fail("VER_04 table must not clear CTAP_SHORT_EN");
        }
        // VER_05/VER_06 end with the U2P3 enable; VER_03/VER_04
        // end with the flow-control advertisement.
        let u2p3 = PhyInitOp::UsbWordSetBits {
            addr: USB_U2P3_CTRL,
            bits: U2P3_ENABLE,
        };
        if v05.last() != Some(&u2p3) || v06.last() != Some(&u2p3) {
            return TestResult::Fail("VER_05/VER_06 tables must end with U2P3 enable");
        }
        let fc = PhyInitOp::MdioSetBits {
            reg: MII_ADVERTISE,
            bits: ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM,
        };
        if v03.last() != Some(&fc) || v04.last() != Some(&fc) {
            return TestResult::Fail("VER_03/VER_04 tables must end with flow control");
        }
        // The sequence opens with ALDPS disable and EEE disable,
        // in Linux's order.
        if v03[0] != PhyInitOp::AldpsDisable {
            return TestResult::Fail("PHY table must open with ALDPS disable");
        }
        if v03[1]
            != (PhyInitOp::PlaWordClrBits {
                addr: PLA_EEE_CR,
                bits: EEE_CR_RX_EN | EEE_CR_TX_EN,
            })
        {
            return TestResult::Fail("PHY table must disable EEE second");
        }
        // Every known version carries exactly one firmware step,
        // at Linux's position in its sequence.
        for version in [
            RtlVersion::Ver01,
            RtlVersion::Ver02,
            RtlVersion::Ver03,
            RtlVersion::Ver04,
            RtlVersion::Ver05,
            RtlVersion::Ver06,
            RtlVersion::Ver07,
            RtlVersion::Ver08,
            RtlVersion::Ver09,
            RtlVersion::Ver10,
            RtlVersion::Ver11,
            RtlVersion::Ver12,
            RtlVersion::Ver13,
            RtlVersion::Ver14,
            RtlVersion::Ver15,
            RtlVersion::Ver16,
            RtlVersion::Ver17,
        ] {
            let ops = phy_init_ops(version);
            if ops
                .iter()
                .filter(|op| matches!(op, PhyInitOp::ApplyFirmware { .. }))
                .count()
                != 1
            {
                return TestResult::Fail("each PHY table must carry exactly one firmware step");
            }
        }
        // VER_14 reuses the VER_08/VER_09 table (Linux's
        // `r8153c_hw_phy_cfg` is `r8153b_hw_phy_cfg` plus a
        // driver-internal flag with no wire effect); VER_01/02/07
        // share one table too.
        if phy_init_ops(RtlVersion::Ver14) != phy_init_ops(RtlVersion::Ver08)
            || phy_init_ops(RtlVersion::Ver14) != phy_init_ops(RtlVersion::Ver09)
        {
            return TestResult::Fail("VER_14 table must equal the VER_08/VER_09 table");
        }
        if phy_init_ops(RtlVersion::Ver01) != phy_init_ops(RtlVersion::Ver02)
            || phy_init_ops(RtlVersion::Ver01) != phy_init_ops(RtlVersion::Ver07)
        {
            return TestResult::Fail("VER_01/02/07 tables must be identical");
        }
        // VER_10 is the only version with EEE disabled at the end
        // (Linux's `eee_en` is false there); VER_11 re-enables it.
        let eee_enable = PhyInitOp::PlaWordSetBits {
            addr: PLA_EEE_CR,
            bits: EEE_CR_RX_EN | EEE_CR_TX_EN,
        };
        if phy_init_ops(RtlVersion::Ver10).contains(&eee_enable) {
            return TestResult::Fail("VER_10 table must not re-enable EEE");
        }
        if !phy_init_ops(RtlVersion::Ver11).contains(&eee_enable) {
            return TestResult::Fail("VER_11 table must re-enable EEE");
        }
        // The 8157 family has no U2P3 enable in its table (Linux
        // uses the separate `r8157_u2p3en` path); the 8156B family
        // ends with it.
        if phy_init_ops(RtlVersion::Ver16).contains(&u2p3)
            || phy_init_ops(RtlVersion::Ver17).contains(&u2p3)
        {
            return TestResult::Fail("VER_16/17 tables must not enable U2P3");
        }
        if phy_init_ops(RtlVersion::Ver12).last() != Some(&u2p3)
            || phy_init_ops(RtlVersion::Ver13).last() != Some(&u2p3)
            || phy_init_ops(RtlVersion::Ver15).last() != Some(&u2p3)
        {
            return TestResult::Fail("VER_12/13/15 tables must end with U2P3 enable");
        }
        // The legacy builder still serves VER_03–VER_06 only.
        if r8153_phy_init_ops(RtlVersion::Ver03) != v03
            || !r8153_phy_init_ops(RtlVersion::Ver08).is_empty()
        {
            return TestResult::Fail("legacy r8153 builder must stay VER_03–VER_06 only");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_table_shape);

    fn smoke_r8152_usb_init_ops() -> TestResult {
        use crate::xhci::PortSpeed;
        // Only VER_03–VER_06 get a sequence; everything else is
        // reset defaults (empty sequence, never a bind failure).
        if !r8153_init_ops(RtlVersion::Ver01, PortSpeed::Super, 0, false).is_empty()
            || !r8153_init_ops(RtlVersion::Ver08, PortSpeed::Super, 0, false).is_empty()
            || !r8153_init_ops(RtlVersion::Ver16, PortSpeed::Super, 0, false).is_empty()
            || !r8153_init_ops(RtlVersion::Unknown, PortSpeed::Super, 0, false).is_empty()
        {
            return TestResult::Fail("unported version must have an empty init sequence");
        }
        let v03 = r8153_init_ops(RtlVersion::Ver03, PortSpeed::Super, 0, false);
        // Opening: U1/U2 off, autoload poll, PHY-status poll.
        if v03[0]
            != (PhyInitOp::UsbDwordWrite {
                addr: USB_TOLERANCE,
                value: 0,
            })
            || v03[1]
                != (PhyInitOp::UsbDwordWrite {
                    addr: USB_TOLERANCE + 4,
                    value: 0,
                })
            || v03[2] != PhyInitOp::AutoloadPoll
            || v03[3] != PhyInitOp::PhyStatusPollAny
        {
            return TestResult::Fail("VER_03 init must open with U1/U2-off + polls");
        }
        // VER_03 carries the ADC step; VER_03 has no VER_04 branch.
        if !v03.contains(&PhyInitOp::OcpRegWrite {
            addr: OCP_ADC_CFG,
            value: ADC_CFG_8153,
        }) {
            return TestResult::Fail("VER_03 init must carry the ADC_CFG step");
        }
        if v03.iter().any(
            |op| matches!(op, PhyInitOp::UsbWordSetBits { addr, .. } if *addr == USB_SSPHYLINK2),
        ) {
            return TestResult::Fail("VER_03 init must not carry the VER_04 SSPHYLINK2 step");
        }
        // MDIO power-down clear + LAN_ON poll + U3 off, in order.
        let mdio_pos = v03
            .iter()
            .position(|op| {
                *op == (PhyInitOp::MdioClrBits {
                    reg: MII_BMCR,
                    bits: BMCR_PDOWN,
                })
            })
            .unwrap_or(usize::MAX);
        if mdio_pos == usize::MAX
            || v03[mdio_pos + 1] != PhyInitOp::PhyStatusPollLanOn
            || v03[mdio_pos + 2]
                != (PhyInitOp::UsbWordClrBits {
                    addr: USB_U2P3_CTRL,
                    bits: U2P3_ENABLE,
                })
        {
            return TestResult::Fail("VER_03 init MDIO/U3 order wrong");
        }
        // LPM byte at SuperSpeed: FIFO + ROK-exit + 500 us timer.
        if !v03.contains(&PhyInitOp::UsbByteWrite {
            addr: USB_LPM_CTRL,
            value: LPM_CTRL_FIFO_EMPTY_1FB | LPM_CTRL_ROK_EXIT_LPM | LPM_CTRL_TIMER_500US,
        }) {
            return TestResult::Fail("VER_03 SuperSpeed LPM byte wrong");
        }
        // VER_04 below SuperSpeed gets the 500 ms timer instead.
        let v04_high = r8153_init_ops(RtlVersion::Ver04, PortSpeed::High, 0, false);
        if !v04_high.contains(&PhyInitOp::UsbByteWrite {
            addr: USB_LPM_CTRL,
            value: LPM_CTRL_FIFO_EMPTY_1FB | LPM_CTRL_ROK_EXIT_LPM | LPM_CTRL_TIMER_500MS,
        }) {
            return TestResult::Fail("VER_04 HighSpeed LPM byte must use the 500 ms timer");
        }
        let v04_super = r8153_init_ops(RtlVersion::Ver04, PortSpeed::Super, 0, false);
        if !v04_super.contains(&PhyInitOp::UsbByteWrite {
            addr: USB_LPM_CTRL,
            value: LPM_CTRL_FIFO_EMPTY_1FB | LPM_CTRL_ROK_EXIT_LPM | LPM_CTRL_TIMER_500US,
        }) {
            return TestResult::Fail("VER_04 SuperSpeed LPM byte must use the 500 us timer");
        }
        // VER_04 carries SSPHYLINK2 + USB2PHY; VER_03 does not.
        if !v04_super.contains(&PhyInitOp::UsbWordClrBits {
            addr: USB_SSPHYLINK2,
            bits: SSPHYLINK2_PWD_DN_SCALE_MASK,
        }) || !v04_super.contains(&PhyInitOp::UsbWordSetBits {
            addr: USB_SSPHYLINK2,
            bits: SSPHYLINK2_PWD_DN_SCALE_96,
        }) || !v04_super.contains(&PhyInitOp::UsbByteSetBits {
            addr: USB_USB2PHY,
            bits: USB2PHY_L1 | USB2PHY_SUSPEND,
        }) {
            return TestResult::Fail("VER_04 init must carry the SSPHYLINK2/USB2PHY steps");
        }
        // VER_05: ALDPS dummy clear + burst-size branch.
        let v05_zero = r8153_init_ops(RtlVersion::Ver05, PortSpeed::Super, 0, false);
        let v05_nz = r8153_init_ops(RtlVersion::Ver05, PortSpeed::Super, 0x40, false);
        if !v05_zero.contains(&PhyInitOp::PlaByteClrBits {
            addr: PLA_DMY_REG0,
            bits: DMY_ECM_ALDPS,
        }) {
            return TestResult::Fail("VER_05 init must clear the ALDPS dummy bit");
        }
        if !v05_zero.contains(&PhyInitOp::UsbByteClrBits {
            addr: USB_CSR_DUMMY1,
            bits: DYNAMIC_BURST,
        }) || !v05_nz.contains(&PhyInitOp::UsbByteSetBits {
            addr: USB_CSR_DUMMY1,
            bits: DYNAMIC_BURST,
        }) {
            return TestResult::Fail("VER_05 burst-size branch inverted");
        }
        // VER_06: queue-wake off + link-status branch.
        let v06_link = r8153_init_ops(RtlVersion::Ver06, PortSpeed::Super, 0, true);
        let v06_nolink = r8153_init_ops(RtlVersion::Ver06, PortSpeed::Super, 0, false);
        if !v06_link.contains(&PhyInitOp::PlaByteClrBits {
            addr: PLA_INDICATE_FALG,
            bits: INDICATE_UPCOMING_RUNTIME_D3,
        }) || !v06_link.contains(&PhyInitOp::PlaWordClrBits {
            addr: PLA_EXTRA_STATUS,
            bits: EXTRA_STATUS_LINK_CHANGE_FLAG,
        }) {
            return TestResult::Fail("VER_06 init must carry the queue-wake steps");
        }
        if !v06_link.contains(&PhyInitOp::PlaWordSetBits {
            addr: PLA_EXTRA_STATUS,
            bits: EXTRA_STATUS_CUR_LINK_OK | EXTRA_STATUS_POLL_LINK_CHG,
        }) {
            return TestResult::Fail("VER_06 link-up must set CUR_LINK_OK + POLL_LINK_CHG");
        }
        if !v06_nolink.contains(&PhyInitOp::PlaWordClrBits {
            addr: PLA_EXTRA_STATUS,
            bits: EXTRA_STATUS_CUR_LINK_OK,
        }) || !v06_nolink.contains(&PhyInitOp::PlaWordSetBits {
            addr: PLA_EXTRA_STATUS,
            bits: EXTRA_STATUS_POLL_LINK_CHG,
        }) {
            return TestResult::Fail("VER_06 link-down must clear CUR_LINK_OK, set POLL_LINK_CHG");
        }
        // Every family sequence closes with the tally reset.
        if v03[v03.len() - 1]
            != (PhyInitOp::PlaWordSetBits {
                addr: PLA_RSTTALLY,
                bits: TALLY_RESET,
            })
        {
            return TestResult::Fail("init sequence must close with the tally reset");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_usb_init_ops);

    fn smoke_r8152_coalesce_for_speed() -> TestResult {
        use crate::xhci::PortSpeed;
        if coalesce_for_speed(PortSpeed::Super) != 85_000
            || coalesce_for_speed(PortSpeed::SuperPlus) != 85_000
            || coalesce_for_speed(PortSpeed::High) != 250_000
            || coalesce_for_speed(PortSpeed::Full) != 524_280
            || coalesce_for_speed(PortSpeed::Low) != 524_280
        {
            return TestResult::Fail("coalesce_for_speed mapping wrong");
        }
        // Early-timeout division fits u16 for every speed.
        for speed in [
            PortSpeed::Super,
            PortSpeed::SuperPlus,
            PortSpeed::High,
            PortSpeed::Full,
            PortSpeed::Low,
        ] {
            if coalesce_for_speed(speed) / 8 > u16::MAX as u32 {
                return TestResult::Fail("coalesce / 8 overflows the timeout word");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_coalesce_for_speed);

    /// Modelled register file for the PHY-init conversation: PLA
    /// words, OCP PHY registers, SRAM cells (both banks), USB-window
    /// words and MDIO registers as small association lists. The
    /// executor mirrors the production op semantics
    /// (read-modify-write for set/clr-bits, two-step SRAM writes,
    /// auto-incrementing burst pointers after an address write);
    /// the ALDPS poll is modelled as satisfied. All polls are
    /// modelled the same way. Byte ops touch the low byte of the
    /// word at `addr` (all byte-op addresses in the sequences are
    /// even, so this is exact there); a dword write splits
    /// low@`addr`, high@`addr + 1`. The firmware step is modelled
    /// as a counted no-op (`fw_steps`) — the blob walk itself is
    /// covered by the pure `check_firmware` tests — and the patch
    /// request always succeeds, so `patch_aborted` never sets in
    /// the model (the abort path is a thin flag in the executor).
    /// `efuse_7d` is the preloaded 17-bit efuse value the ADC
    /// calibration reads.
    struct ModelRegs {
        pla: Vec<(u16, u16)>,
        ocp: Vec<(u16, u16)>,
        sram: Vec<(u16, u16)>,
        sram2: Vec<(u16, u16)>,
        usb: Vec<(u16, u16)>,
        mdio: Vec<(u16, u16)>,
        sram_ptr: u16,
        sram2_ptr: u16,
        fw_steps: usize,
        patch_aborted: bool,
        efuse_7d: u32,
    }

    impl ModelRegs {
        fn new() -> Self {
            Self {
                pla: Vec::new(),
                ocp: Vec::new(),
                sram: Vec::new(),
                sram2: Vec::new(),
                usb: Vec::new(),
                mdio: Vec::new(),
                sram_ptr: 0,
                sram2_ptr: 0,
                fw_steps: 0,
                patch_aborted: false,
                efuse_7d: 0,
            }
        }
        fn get(map: &[(u16, u16)], addr: u16) -> u16 {
            map.iter()
                .find(|(a, _)| *a == addr)
                .map(|(_, v)| *v)
                .unwrap_or(0)
        }
        fn set(map: &mut Vec<(u16, u16)>, addr: u16, value: u16) {
            if let Some(slot) = map.iter_mut().find(|(a, _)| *a == addr) {
                slot.1 = value;
            } else {
                map.push((addr, value));
            }
        }
        fn apply(&mut self, op: PhyInitOp) {
            use PhyInitOp::*;
            // A failed patch request aborts the rest of the
            // sequence; the model never fails one, so this only
            // guards the flag's plumbing.
            if self.patch_aborted {
                return;
            }
            match op {
                OcpRegSetBits { addr, bits } => {
                    let cur = Self::get(&self.ocp, addr);
                    Self::set(&mut self.ocp, addr, cur | bits);
                }
                OcpRegClrBits { addr, bits } => {
                    let cur = Self::get(&self.ocp, addr);
                    Self::set(&mut self.ocp, addr, cur & !bits);
                }
                OcpRegWrite { addr, value } => Self::set(&mut self.ocp, addr, value),
                OcpRegW0W1 { addr, clear, set } => {
                    let cur = Self::get(&self.ocp, addr);
                    Self::set(&mut self.ocp, addr, (cur & !clear) | set);
                }
                SramWrite { addr, value } => Self::set(&mut self.sram, addr, value),
                SramW0W1 { addr, clear, set } => {
                    let cur = Self::get(&self.sram, addr);
                    Self::set(&mut self.sram, addr, (cur & !clear) | set);
                }
                Sram2W0W1 { addr, clear, set } => {
                    let cur = Self::get(&self.sram2, addr);
                    Self::set(&mut self.sram2, addr, (cur & !clear) | set);
                }
                Sram2Write { addr, value } => Self::set(&mut self.sram2, addr, value),
                SramAddrWrite { addr } => self.sram_ptr = addr,
                SramDataWrite { value } => {
                    let ptr = self.sram_ptr;
                    Self::set(&mut self.sram, ptr, value);
                    self.sram_ptr = ptr.wrapping_add(2);
                }
                Sram2AddrWrite { addr } => self.sram2_ptr = addr,
                Sram2DataWrite { value } => {
                    let ptr = self.sram2_ptr;
                    Self::set(&mut self.sram2, ptr, value);
                    self.sram2_ptr = ptr.wrapping_add(2);
                }
                PlaWordSetBits { addr, bits } => {
                    let cur = Self::get(&self.pla, addr);
                    Self::set(&mut self.pla, addr, cur | bits);
                }
                PlaWordClrBits { addr, bits } => {
                    let cur = Self::get(&self.pla, addr);
                    Self::set(&mut self.pla, addr, cur & !bits);
                }
                PlaWordWrite { addr, value } => Self::set(&mut self.pla, addr, value),
                UsbWordSetBits { addr, bits } => {
                    let cur = Self::get(&self.usb, addr);
                    Self::set(&mut self.usb, addr, cur | bits);
                }
                MdioSetBits { reg, bits } => {
                    let addr = OCP_BASE_MII + reg * 2;
                    let cur = Self::get(&self.mdio, addr);
                    Self::set(&mut self.mdio, addr, cur | bits);
                }
                UsbWordClrBits { addr, bits } => {
                    let cur = Self::get(&self.usb, addr);
                    Self::set(&mut self.usb, addr, cur & !bits);
                }
                UsbWordWrite { addr, value } => Self::set(&mut self.usb, addr, value),
                UsbWordTestAndClrBits { addr, bits } => {
                    let cur = Self::get(&self.usb, addr);
                    if cur & bits != 0 {
                        Self::set(&mut self.usb, addr, cur & !bits);
                    }
                }
                MdioTestAndClrBits { reg, bits } => {
                    let addr = OCP_BASE_MII + reg * 2;
                    let cur = Self::get(&self.mdio, addr);
                    if cur & bits != 0 {
                        Self::set(&mut self.mdio, addr, cur & !bits);
                    }
                }
                MmdWrite { dev, reg, value } => {
                    // Linux `r8152_mmd_write`: select, write,
                    // deselect — only the final state is modelled.
                    Self::set(&mut self.ocp, OCP_EEE_AR, MMD_FUN_ADDR | dev);
                    Self::set(&mut self.ocp, OCP_EEE_DATA, reg);
                    Self::set(&mut self.ocp, OCP_EEE_AR, MMD_FUN_DATA | dev);
                    Self::set(&mut self.ocp, OCP_EEE_DATA, value);
                    Self::set(&mut self.ocp, OCP_EEE_AR, 0);
                }
                ApplyFirmware { .. } => {
                    self.fw_steps += 1;
                }
                PhyPatchRequest { .. } => {
                    // Modelled as success: the request bit sets
                    // and PATCH_READY is already set.
                }
                WaitLoadingFlash => {}
                AdcBiasFromEfuse => {
                    // Rebuild the 16-bit value from the preloaded
                    // 17-bit efuse word, as in Linux.
                    let raw = self.efuse_7d;
                    let data = (((raw & 0x1FFF0) >> 1) | (raw & 0x7)) as u16;
                    if data != 0xFFFF {
                        Self::set(&mut self.ocp, OCP_ADC_IOFFSET, data);
                    }
                }
                UpsTimingFromSawCnt => {
                    let saw = Self::get(&self.ocp, 0xC426) & 0x3FFF;
                    if saw != 0 {
                        let swr =
                            ((16_000_000u32 / u32::from(saw)) as u16) & UPS_CFG_SAW_CNT_1MS_MASK;
                        let cur = Self::get(&self.usb, USB_UPS_CFG);
                        Self::set(
                            &mut self.usb,
                            USB_UPS_CFG,
                            (cur & !UPS_CFG_SAW_CNT_1MS_MASK) | swr,
                        );
                    }
                }
                MdiSwapIfReversed => {
                    let ups = Self::get(&self.usb, USB_UPS_CFG);
                    let sel = Self::get(&self.ocp, 0xD068);
                    if ups & UPS_CFG_MID_REVERSE == 0 || sel & 0x0002 == 0 {
                        return;
                    }
                    let mut data = Self::get(&self.ocp, 0xD068);
                    data &= !0x001F;
                    data |= 0x0001; // p0
                    Self::set(&mut self.ocp, 0xD068, data);
                    let swap_a = Self::get(&self.ocp, 0xD06A);
                    data &= !0x0018;
                    data |= 0x0018; // p3
                    Self::set(&mut self.ocp, 0xD068, data);
                    let swap_b = Self::get(&self.ocp, 0xD06A);
                    data &= !0x0018; // p0
                    Self::set(&mut self.ocp, 0xD068, data);
                    Self::set(
                        &mut self.ocp,
                        0xD06A,
                        (swap_a & !0x07FF) | (swap_b & 0x07FF),
                    );
                    data |= 0x0018; // p3
                    Self::set(&mut self.ocp, 0xD068, data);
                    Self::set(
                        &mut self.ocp,
                        0xD06A,
                        (swap_b & !0x07FF) | (swap_a & 0x07FF),
                    );
                    data &= !0x0018;
                    data |= 0x0008; // p1
                    Self::set(&mut self.ocp, 0xD068, data);
                    let swap_a = Self::get(&self.ocp, 0xD06A);
                    data &= !0x0018;
                    data |= 0x0010; // p2
                    Self::set(&mut self.ocp, 0xD068, data);
                    let swap_b = Self::get(&self.ocp, 0xD06A);
                    data &= !0x0018;
                    data |= 0x0008; // p1
                    Self::set(&mut self.ocp, 0xD068, data);
                    Self::set(
                        &mut self.ocp,
                        0xD06A,
                        (swap_a & !0x07FF) | (swap_b & 0x07FF),
                    );
                    data &= !0x0018;
                    data |= 0x0010; // p2
                    Self::set(&mut self.ocp, 0xD068, data);
                    Self::set(
                        &mut self.ocp,
                        0xD06A,
                        (swap_b & !0x07FF) | (swap_a & 0x07FF),
                    );
                    let swap_a = Self::get(&self.ocp, 0xBD5A);
                    let swap_b = Self::get(&self.ocp, 0xBD5C);
                    Self::set(
                        &mut self.ocp,
                        0xBD5A,
                        (swap_a & !0x1F1F) | ((swap_b & 0x001F) << 8) | ((swap_b >> 8) & 0x001F),
                    );
                    Self::set(
                        &mut self.ocp,
                        0xBD5C,
                        (swap_b & !0x1F1F) | ((swap_a & 0x001F) << 8) | ((swap_a >> 8) & 0x001F),
                    );
                    let swap_a = Self::get(&self.ocp, 0xBC18);
                    let swap_b = Self::get(&self.ocp, 0xBC1A);
                    Self::set(
                        &mut self.ocp,
                        0xBC18,
                        (swap_a & !0x1F1F) | ((swap_b & 0x001F) << 8) | ((swap_b >> 8) & 0x001F),
                    );
                    Self::set(
                        &mut self.ocp,
                        0xBC1A,
                        (swap_b & !0x1F1F) | ((swap_a & 0x001F) << 8) | ((swap_a >> 8) & 0x001F),
                    );
                }
                UsbByteSetBits { addr, bits } => {
                    let cur = Self::get(&self.usb, addr);
                    let lo = (cur as u8 | bits) as u16;
                    Self::set(&mut self.usb, addr, (cur & 0xFF00) | lo);
                }
                UsbByteClrBits { addr, bits } => {
                    let cur = Self::get(&self.usb, addr);
                    let lo = (cur as u8 & !bits) as u16;
                    Self::set(&mut self.usb, addr, (cur & 0xFF00) | lo);
                }
                UsbByteWrite { addr, value } => {
                    let cur = Self::get(&self.usb, addr);
                    Self::set(&mut self.usb, addr, (cur & 0xFF00) | value as u16);
                }
                UsbDwordWrite { addr, value } => {
                    Self::set(&mut self.usb, addr, value as u16);
                    Self::set(&mut self.usb, addr + 1, (value >> 16) as u16);
                }
                PlaByteSetBits { addr, bits } => {
                    let cur = Self::get(&self.pla, addr);
                    let lo = (cur as u8 | bits) as u16;
                    Self::set(&mut self.pla, addr, (cur & 0xFF00) | lo);
                }
                PlaByteClrBits { addr, bits } => {
                    let cur = Self::get(&self.pla, addr);
                    let lo = (cur as u8 & !bits) as u16;
                    Self::set(&mut self.pla, addr, (cur & 0xFF00) | lo);
                }
                PlaByteWrite { addr, value } => {
                    let cur = Self::get(&self.pla, addr);
                    Self::set(&mut self.pla, addr, (cur & 0xFF00) | value as u16);
                }
                MdioClrBits { reg, bits } => {
                    let addr = OCP_BASE_MII + reg * 2;
                    let cur = Self::get(&self.mdio, addr);
                    Self::set(&mut self.mdio, addr, cur & !bits);
                }
                // Polls write nothing and always complete, so the
                // model treats them as satisfied (as with ALDPS).
                AutoloadPoll | PhyStatusPollAny | PhyStatusPollLanOn => {}
                AldpsDisable => {
                    let cur = Self::get(&self.ocp, OCP_POWER_CFG);
                    Self::set(&mut self.ocp, OCP_POWER_CFG, cur & !POWER_CFG_EN_ALDPS);
                }
            }
        }
    }

    fn smoke_r8152_phy_init_modelled_conversation() -> TestResult {
        // VER_03 against a modelled register file preloaded with
        // ALDPS on and CTAP_SHORT_EN set: the conversation must
        // end with ALDPS re-enabled, EEE on with the 8153
        // advertisement, the SRAM tuning cells programmed, and
        // the VER_03-only CTAP clear applied.
        let mut m = ModelRegs::new();
        ModelRegs::set(&mut m.ocp, OCP_POWER_CFG, POWER_CFG_EN_ALDPS);
        ModelRegs::set(&mut m.ocp, OCP_EEE_CFG, EEE_CFG_CTAP_SHORT_EN);
        for op in phy_init_ops(RtlVersion::Ver03) {
            m.apply(op);
        }
        let power = ModelRegs::get(&m.ocp, OCP_POWER_CFG);
        if power != POWER_CFG_EN_ALDPS | POWER_CFG_EEE_CLKDIV_EN | POWER_CFG_EN_10M_PLLOFF {
            return TestResult::Fail("modelled POWER_CFG end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_DOWN_SPEED) != DOWN_SPEED_EN_10M_BGOFF {
            return TestResult::Fail("modelled DOWN_SPEED end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_EEE_CFG) != EEE_CFG_EEE10_EN {
            return TestResult::Fail("modelled EEE_CFG end state wrong (CTAP must clear)");
        }
        if ModelRegs::get(&m.ocp, OCP_EEE_ADV) != EEE_ADV_8153 {
            return TestResult::Fail("modelled EEE_ADV end state wrong");
        }
        if ModelRegs::get(&m.pla, PLA_EEE_CR) != EEE_CR_RX_EN | EEE_CR_TX_EN {
            return TestResult::Fail("modelled PLA_EEE_CR end state wrong");
        }
        if ModelRegs::get(&m.pla, PLA_PHY_PWR) != PHY_PWR_PFM_PWM_SWITCH {
            return TestResult::Fail("modelled PLA_PHY_PWR end state wrong");
        }
        if ModelRegs::get(&m.sram, SRAM_IMPEDANCE) != 0x0B13
            || ModelRegs::get(&m.sram, SRAM_LPF_CFG) != 0xF70F
            || ModelRegs::get(&m.sram, SRAM_10M_AMP1) != 0x00AF
            || ModelRegs::get(&m.sram, SRAM_10M_AMP2) != 0x0208
        {
            return TestResult::Fail("modelled SRAM tuning end state wrong");
        }
        if ModelRegs::get(&m.mdio, OCP_BASE_MII + MII_ADVERTISE * 2)
            != ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM
        {
            return TestResult::Fail("modelled MDIO flow-control end state wrong");
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_03 conversation must carry exactly one firmware step");
        }
        // VER_04 from the same preload: CTAP_SHORT_EN survives
        // (no clear step), everything else matches.
        let mut m4 = ModelRegs::new();
        ModelRegs::set(&mut m4.ocp, OCP_POWER_CFG, POWER_CFG_EN_ALDPS);
        ModelRegs::set(&mut m4.ocp, OCP_EEE_CFG, EEE_CFG_CTAP_SHORT_EN);
        for op in phy_init_ops(RtlVersion::Ver04) {
            m4.apply(op);
        }
        if ModelRegs::get(&m4.ocp, OCP_EEE_CFG) != EEE_CFG_EEE10_EN | EEE_CFG_CTAP_SHORT_EN {
            return TestResult::Fail("VER_04 must preserve CTAP_SHORT_EN");
        }
        // VER_05: U2P3 enabled, CTAP untouched.
        let mut m5 = ModelRegs::new();
        for op in phy_init_ops(RtlVersion::Ver05) {
            m5.apply(op);
        }
        if ModelRegs::get(&m5.usb, USB_U2P3_CTRL) != U2P3_ENABLE {
            return TestResult::Fail("VER_05 must enable U2P3");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/r8152",
        smoke_r8152_phy_init_modelled_conversation
    );

    fn smoke_r8152_phy_init_ver01_conversation() -> TestResult {
        // VER_01 (RTL8152): firmware step first, then the 8152
        // EEE enable (CONFIG1/2/3 + MMD advertisement), ALDPS
        // enable as a whole-word write, flow control.
        let mut m = ModelRegs::new();
        for op in phy_init_ops(RtlVersion::Ver01) {
            m.apply(op);
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_01 conversation must carry one firmware step");
        }
        if ModelRegs::get(&m.pla, PLA_EEE_CR) != EEE_CR_RX_EN | EEE_CR_TX_EN {
            return TestResult::Fail("VER_01 PLA_EEE_CR end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_EEE_CONFIG1) != 0x3310 {
            return TestResult::Fail("VER_01 EEE_CONFIG1 end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_EEE_CONFIG2) != 0x0600 {
            return TestResult::Fail("VER_01 EEE_CONFIG2 end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_EEE_CONFIG3) != 0x1500 {
            return TestResult::Fail("VER_01 EEE_CONFIG3 end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_EEE_AR) != 0
            || ModelRegs::get(&m.ocp, OCP_EEE_DATA) != EEE_ADV_8152
        {
            return TestResult::Fail("VER_01 MMD advertisement end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_ALDPS_CONFIG) != ALDPS_CFG_8152_ENABLE {
            return TestResult::Fail("VER_01 ALDPS config end state wrong");
        }
        if ModelRegs::get(&m.mdio, OCP_BASE_MII + MII_ADVERTISE * 2)
            != ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM
        {
            return TestResult::Fail("VER_01 MDIO flow-control end state wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_ver01_conversation);

    fn smoke_r8152_phy_init_ver08_conversation() -> TestResult {
        // VER_08 (RTL8153B): power-cut clear, U1/U2 timer, green
        // mode, ADC efuse calibration, UPS timing, patch-gated
        // Advance EEE, EEE re-enable.
        let mut m = ModelRegs::new();
        ModelRegs::set(&mut m.usb, USB_MISC_0, PCUT_STATUS);
        ModelRegs::set(&mut m.ocp, 0xC426, 0x1000);
        m.efuse_7d = 0x1234;
        for op in phy_init_ops(RtlVersion::Ver08) {
            m.apply(op);
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_08 conversation must carry one firmware step");
        }
        if ModelRegs::get(&m.usb, USB_MISC_0) != 0 {
            return TestResult::Fail("VER_08 must clear the power-cut status");
        }
        if ModelRegs::get(&m.usb, USB_U1U2_TIMER) != 500 {
            return TestResult::Fail("VER_08 U1/U2 timer wrong");
        }
        if ModelRegs::get(&m.sram, 0x8045) != 0
            || ModelRegs::get(&m.sram, 0x804D) != 0x1222
            || ModelRegs::get(&m.sram, 0x805D) != 0x0022
            || ModelRegs::get(&m.sram, SRAM_GREEN_CFG) != GREEN_ETH_EN | GREEN_CFG_R_TUNE_EN
        {
            return TestResult::Fail("VER_08 green-mode end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_NCTL_CFG) != NCTL_CFG_PGA_RETURN_EN {
            return TestResult::Fail("VER_08 NCTL_CFG end state wrong");
        }
        // efuse 0x1234 -> ((0x1230) >> 1) | 0x4 = 0x091C.
        if ModelRegs::get(&m.ocp, OCP_ADC_IOFFSET) != 0x091C {
            return TestResult::Fail("VER_08 ADC ioffset end state wrong");
        }
        // saw 0x1000 -> 16000000 / 4096 = 3906 (0xF42).
        if ModelRegs::get(&m.usb, USB_UPS_CFG) != 0x0F42 {
            return TestResult::Fail("VER_08 UPS timing end state wrong");
        }
        if ModelRegs::get(&m.pla, PLA_PHY_PWR) != PHY_PWR_PFM_PWM_SWITCH {
            return TestResult::Fail("VER_08 PLA_PHY_PWR end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_DOWN_SPEED)
            != DOWN_SPEED_EN_EEE_CMODE | DOWN_SPEED_EN_EEE_1000 | DOWN_SPEED_EN_10M_CLKDIV
        {
            return TestResult::Fail("VER_08 DOWN_SPEED end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_SYSCLK_CFG) != CLK_DIV_EXPO_5 {
            return TestResult::Fail("VER_08 SYSCLK_CFG end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_POWER_CFG) != POWER_CFG_EEE_CLKDIV_EN | POWER_CFG_EN_ALDPS {
            return TestResult::Fail("VER_08 POWER_CFG end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_EEE_ADV) != EEE_ADV_8153 {
            return TestResult::Fail("VER_08 EEE_ADV end state wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_ver08_conversation);

    fn smoke_r8152_phy_init_ver10_conversation() -> TestResult {
        // VER_10 (RTL8156): EEE stays disabled at the end
        // (eee_en is false), green mode on, lite-mode clears
        // applied, U2P3 enabled.
        let mut m = ModelRegs::new();
        ModelRegs::set(&mut m.ocp, 0xA428, 0x0200);
        ModelRegs::set(&mut m.ocp, 0xA5EA, 0x0001);
        for op in phy_init_ops(RtlVersion::Ver10) {
            m.apply(op);
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_10 conversation must carry one firmware step");
        }
        if ModelRegs::get(&m.pla, PLA_EEE_CR) != 0
            || ModelRegs::get(&m.ocp, OCP_EEE_CFG) != 0
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV) != 0
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV2) != 0
        {
            return TestResult::Fail("VER_10 must leave EEE disabled");
        }
        if ModelRegs::get(&m.sram, SRAM_GREEN_CFG) != GREEN_ETH_EN {
            return TestResult::Fail("VER_10 green-mode end state wrong");
        }
        if ModelRegs::get(&m.ocp, 0xA428) != 0 || ModelRegs::get(&m.ocp, 0xA5EA) != 0 {
            return TestResult::Fail("VER_10 lite-mode clears wrong");
        }
        if ModelRegs::get(&m.sram, 0x819F) != 0xDDB6 || ModelRegs::get(&m.ocp, 0xBC34) != 0x5555 {
            return TestResult::Fail("VER_10 arm end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_POWER_CFG) != POWER_CFG_EN_ALDPS {
            return TestResult::Fail("VER_10 POWER_CFG end state wrong");
        }
        if ModelRegs::get(&m.usb, USB_U2P3_CTRL) != U2P3_ENABLE {
            return TestResult::Fail("VER_10 must enable U2P3");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_ver10_conversation);

    fn smoke_r8152_phy_init_ver11_conversation() -> TestResult {
        // VER_11 (RTL8156): EEE re-enabled with the 2.5G
        // advertisement, ADC Ibias cal, thermal sensor, 2.5G
        // force-mode interrupt. The MDI swap is skipped here
        // (no MID_REVERSE reported); the swap itself is covered
        // by the dedicated test below.
        let mut m = ModelRegs::new();
        ModelRegs::set(&mut m.ocp, 0xA428, 0x0200);
        ModelRegs::set(&mut m.ocp, 0xA5EA, 0x0001);
        for op in phy_init_ops(RtlVersion::Ver11) {
            m.apply(op);
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_11 conversation must carry one firmware step");
        }
        if ModelRegs::get(&m.pla, PLA_EEE_CR) != EEE_CR_RX_EN | EEE_CR_TX_EN
            || ModelRegs::get(&m.ocp, OCP_EEE_CFG) != EEE_CFG_EEE10_EN
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV) != EEE_ADV_8153
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV2) != MDIO_EEE_2_5GT
        {
            return TestResult::Fail("VER_11 EEE end state wrong");
        }
        if ModelRegs::get(&m.ocp, 0xD068) != 0x2000 {
            return TestResult::Fail("VER_11 ADC Ibias cal end state wrong");
        }
        if ModelRegs::get(&m.sram, 0x81A2) != 0
            || ModelRegs::get(&m.ocp, 0xB54C) != 0xDB00
            || ModelRegs::get(&m.ocp, 0xA454) != 0
            || ModelRegs::get(&m.ocp, OCP_10GBT_CTRL) != CTRL_10GBT_ADV2_5G_F_R
            || ModelRegs::get(&m.ocp, OCP_INTR_EN) != INTR_EN_SPEED_FORCE
        {
            return TestResult::Fail("VER_11 arm end state wrong");
        }
        if ModelRegs::get(&m.pla, PLA_EEE_TXTWSYS_2P5G) != 0x0056 {
            return TestResult::Fail("VER_11 EEE TX window end state wrong");
        }
        if ModelRegs::get(&m.pla, PLA_USB_CFG) != USB_CFG_EN_XG_LIP | USB_CFG_EN_G_LIP {
            return TestResult::Fail("VER_11 USB_CFG end state wrong");
        }
        if ModelRegs::get(&m.sram2, 0x80A2) != 0x0153 || ModelRegs::get(&m.sram2, 0x809C) != 0x0153
        {
            return TestResult::Fail("VER_11 AAGC end state wrong");
        }
        if ModelRegs::get(&m.usb, USB_U2P3_CTRL) != U2P3_ENABLE {
            return TestResult::Fail("VER_11 must enable U2P3");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_ver11_conversation);

    fn smoke_r8152_phy_init_mdi_swap() -> TestResult {
        // The MDI swap alone, with reversed lanes reported and
        // distinct break-point pairs preloaded: the 0xbd5a/0xbd5c
        // and 0xbc18/0xbc1a pairs must exchange their low halves.
        let mut m = ModelRegs::new();
        ModelRegs::set(&mut m.usb, USB_UPS_CFG, UPS_CFG_MID_REVERSE);
        ModelRegs::set(&mut m.ocp, 0xD068, 0x0002);
        ModelRegs::set(&mut m.ocp, 0xBD5A, 0x1111);
        ModelRegs::set(&mut m.ocp, 0xBD5C, 0x2222);
        ModelRegs::set(&mut m.ocp, 0xBC18, 0x3333);
        ModelRegs::set(&mut m.ocp, 0xBC1A, 0x4444);
        m.apply(PhyInitOp::MdiSwapIfReversed);
        if ModelRegs::get(&m.ocp, 0xBD5A) != 0x0202 || ModelRegs::get(&m.ocp, 0xBD5C) != 0x3131 {
            return TestResult::Fail("MDI swap 0xbd5a/0xbd5c pair wrong");
        }
        if ModelRegs::get(&m.ocp, 0xBC18) != 0x2424 || ModelRegs::get(&m.ocp, 0xBC1A) != 0x5353 {
            return TestResult::Fail("MDI swap 0xbc18/0xbc1a pair wrong");
        }
        // Without MID_REVERSE the swap is a no-op.
        let mut m2 = ModelRegs::new();
        ModelRegs::set(&mut m2.ocp, 0xD068, 0x0002);
        ModelRegs::set(&mut m2.ocp, 0xBD5A, 0x1111);
        ModelRegs::set(&mut m2.ocp, 0xBD5C, 0x2222);
        m2.apply(PhyInitOp::MdiSwapIfReversed);
        if ModelRegs::get(&m2.ocp, 0xBD5A) != 0x1111 || ModelRegs::get(&m2.ocp, 0xBD5C) != 0x2222 {
            return TestResult::Fail("MDI swap must not run without MID_REVERSE");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_mdi_swap);

    fn smoke_r8152_phy_init_ver12_conversation() -> TestResult {
        // VER_12 (RTL8156B): version pre-switch, green
        // table/PGA arm, patch-gated register block, EEE
        // re-enable with 2.5G, U2P3.
        let mut m = ModelRegs::new();
        for op in phy_init_ops(RtlVersion::Ver12) {
            m.apply(op);
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_12 conversation must carry one firmware step");
        }
        if ModelRegs::get(&m.ocp, 0xBF86) != 0x9000
            || ModelRegs::get(&m.ocp, 0xC402) != 0
            || ModelRegs::get(&m.ocp, 0xBD86) != 0x1010
            || ModelRegs::get(&m.ocp, 0xBD88) != 0x1010
            || ModelRegs::get(&m.ocp, 0xBD4E) != 0x0800
            || ModelRegs::get(&m.ocp, 0xBF46) != 0x0700
        {
            return TestResult::Fail("VER_12 pre-switch end state wrong");
        }
        if ModelRegs::get(&m.sram2, 0x8560) != 0x19CC
            || ModelRegs::get(&m.sram2, 0x80D6) != 0x2801
            || ModelRegs::get(&m.sram2, 0x80F4) != 0x6077
            || ModelRegs::get(&m.sram, 0x816C) != 0xC4A0
            || ModelRegs::get(&m.sram, 0x817C) != 0x0719
        {
            return TestResult::Fail("VER_12 arm end state wrong");
        }
        if ModelRegs::get(&m.ocp, 0xBFA0) != 0xD70D
            || ModelRegs::get(&m.ocp, 0xBFA2) != 0x4100
            || ModelRegs::get(&m.ocp, 0xBFA4) != 0xE848
            || ModelRegs::get(&m.ocp, 0xBFA6) != 0xDC59
            || ModelRegs::get(&m.ocp, 0xB54C) != 0x3C18
            || ModelRegs::get(&m.sram, 0x817D) != 0x1000
        {
            return TestResult::Fail("VER_12 patch-block end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_INTR_EN) != INTR_EN_SPEED_FORCE
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV) != EEE_ADV_8153
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV2) != MDIO_EEE_2_5GT
            || ModelRegs::get(&m.ocp, OCP_POWER_CFG) != POWER_CFG_EN_ALDPS
        {
            return TestResult::Fail("VER_12 tail end state wrong");
        }
        if ModelRegs::get(&m.usb, USB_U2P3_CTRL) != U2P3_ENABLE {
            return TestResult::Fail("VER_12 must enable U2P3");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_ver12_conversation);

    fn smoke_r8152_phy_init_ver13_conversation() -> TestResult {
        // VER_13 (RTL8156B): the 2.5G INRX arm on top of the
        // VER_15 arm, flash wait first.
        let mut m = ModelRegs::new();
        for op in phy_init_ops(RtlVersion::Ver13) {
            m.apply(op);
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_13 conversation must carry one firmware step");
        }
        if !phy_init_ops(RtlVersion::Ver13).contains(&PhyInitOp::WaitLoadingFlash) {
            return TestResult::Fail("VER_13 table must wait for flash load");
        }
        if ModelRegs::get(&m.ocp, 0xAC46) != 0x0090 || ModelRegs::get(&m.ocp, 0xAD30) != 0x0001 {
            return TestResult::Fail("VER_13 INRX arm end state wrong");
        }
        if ModelRegs::get(&m.sram2, 0x80F5) != 0x760E
            || ModelRegs::get(&m.sram2, 0x8107) != 0x360E
            || ModelRegs::get(&m.ocp, 0xBF00) != 0xA000
            || ModelRegs::get(&m.sram, 0x8044) != 0x2417
            || ModelRegs::get(&m.sram, 0x807A) != 0x2417
            || ModelRegs::get(&m.ocp, 0xBF84) != 0xA000
        {
            return TestResult::Fail("VER_13 shared arm end state wrong");
        }
        if ModelRegs::get(&m.usb, USB_U2P3_CTRL) != U2P3_ENABLE {
            return TestResult::Fail("VER_13 must enable U2P3");
        }
        // VER_15 is VER_13 without the two INRX steps.
        if phy_init_ops(RtlVersion::Ver15).len() != phy_init_ops(RtlVersion::Ver13).len() - 2 {
            return TestResult::Fail("VER_15 table must be VER_13 minus the INRX steps");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_ver13_conversation);

    fn smoke_r8152_phy_init_ver16_conversation() -> TestResult {
        // VER_16 (RTL8157): flash wait, BMCR power-down
        // test-and-clear, PFM mode (PHY_PWR switch cleared),
        // burst tables, patch-gated Advance EEE, no U2P3.
        let mut m = ModelRegs::new();
        ModelRegs::set(&mut m.pla, PLA_PHY_PWR, PHY_PWR_PFM_PWM_SWITCH);
        ModelRegs::set(&mut m.mdio, OCP_BASE_MII + MII_BMCR * 2, BMCR_PDOWN);
        ModelRegs::set(&mut m.ocp, 0xA44A, 0x0004);
        for op in phy_init_ops(RtlVersion::Ver16) {
            m.apply(op);
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_16 conversation must carry one firmware step");
        }
        if !phy_init_ops(RtlVersion::Ver16).contains(&PhyInitOp::WaitLoadingFlash) {
            return TestResult::Fail("VER_16 table must wait for flash load");
        }
        if ModelRegs::get(&m.mdio, OCP_BASE_MII + MII_BMCR * 2) != 0 {
            return TestResult::Fail("VER_16 must clear BMCR power-down");
        }
        if ModelRegs::get(&m.pla, PLA_PHY_PWR) != 0 {
            return TestResult::Fail("VER_16 must clear the PFM/PWM switch (PFM mode)");
        }
        if ModelRegs::get(&m.ocp, OCP_POWER_CFG)
            != 0x0003 | POWER_CFG_EEE_CLKDIV_EN | POWER_CFG_EN_ALDPS
        {
            return TestResult::Fail("VER_16 POWER_CFG end state wrong");
        }
        if ModelRegs::get(&m.ocp, 0xA44A) != 0 {
            return TestResult::Fail("VER_16 must clear the ALDPS force-mode bit");
        }
        if ModelRegs::get(&m.sram, 0x8183) != 0x5900
            || ModelRegs::get(&m.ocp, 0xA654) != 0x0800
            || ModelRegs::get(&m.ocp, 0xB648) != 0x4040
            || ModelRegs::get(&m.sram2, 0x8647) != 0xE600
        {
            return TestResult::Fail("VER_16 arm end state wrong");
        }
        // Burst tables: the 6-word block at 0x8f9c, the 9-word
        // block at 0x8566, the 20-word RFI blocks at 0x82c8 and
        // 0x82a0.
        if ModelRegs::get(&m.sram, 0x8F9C) != 0x0005
            || ModelRegs::get(&m.sram, 0x8FA0) != 0x00ED
            || ModelRegs::get(&m.sram, 0x8FA6) != 0xD401
            || ModelRegs::get(&m.sram, 0x8566) != 0x003F
            || ModelRegs::get(&m.sram, 0x8568) != 0x3F02
            || ModelRegs::get(&m.sram, 0x856E) != 0x1C00
        {
            return TestResult::Fail("VER_16 SRAM burst end state wrong");
        }
        if ModelRegs::get(&m.sram2, 0x82C8) != 0x03ED
            || ModelRegs::get(&m.sram2, 0x82CE) != 0x03FE
            || ModelRegs::get(&m.sram2, 0x82D2) != 0x0021
            || ModelRegs::get(&m.sram2, 0x82EE) != 0x03ED
            || ModelRegs::get(&m.sram2, 0x82A0) != 0x000E
            || ModelRegs::get(&m.sram2, 0x82AA) != 0x03F1
            || ModelRegs::get(&m.sram2, 0x82C6) != 0x03F1
        {
            return TestResult::Fail("VER_16 SRAM2 burst end state wrong");
        }
        if ModelRegs::get(&m.ocp, OCP_DOWN_SPEED) != DOWN_SPEED_EN_10M_CLKDIV
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV) != EEE_ADV_8153
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV2) != MDIO_EEE_2_5GT | MDIO_EEE_5GT
            || ModelRegs::get(&m.sram, SRAM_GREEN_CFG) != GREEN_ETH_EN
        {
            return TestResult::Fail("VER_16 tail end state wrong");
        }
        if ModelRegs::get(&m.usb, USB_U2P3_CTRL) != 0 {
            return TestResult::Fail("VER_16 must not enable U2P3");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_ver16_conversation);

    fn smoke_r8152_phy_init_ver17_conversation() -> TestResult {
        // VER_17 (RTL8157): 10G advertisement, PBO table,
        // thermal sensor, cable-test patch, no U2P3.
        let mut m = ModelRegs::new();
        ModelRegs::set(&mut m.pla, 0xD3C8, 0x0001);
        for op in phy_init_ops(RtlVersion::Ver17) {
            m.apply(op);
        }
        if m.fw_steps != 1 {
            return TestResult::Fail("VER_17 conversation must carry one firmware step");
        }
        if ModelRegs::get(&m.pla, 0xD3C8) != 0 {
            return TestResult::Fail("VER_17 must clear the ALDPS clock-bypass bit");
        }
        if ModelRegs::get(&m.sram, 0x8415) != 0x9300
            || ModelRegs::get(&m.sram, 0x81A3) != 0x0F00
            || ModelRegs::get(&m.sram, 0x81B9) != 0xB900
            || ModelRegs::get(&m.sram, 0x8173) != 0x8620
        {
            return TestResult::Fail("VER_17 power-level end state wrong");
        }
        if ModelRegs::get(&m.ocp, 0xAE20) != 0xFFFF
            || ModelRegs::get(&m.ocp, 0xAEC6) != 0
            || ModelRegs::get(&m.ocp, 0xADB8) != 0x0150
        {
            return TestResult::Fail("VER_17 RFI end state wrong");
        }
        if ModelRegs::get(&m.sram2, 0x8647) != 0xA7B1
            || ModelRegs::get(&m.sram2, 0x8649) != 0xBBCA
            || ModelRegs::get(&m.sram2, 0x826C) != 0xFFFF
            || ModelRegs::get(&m.sram2, 0x826E) != 0xFFFF
        {
            return TestResult::Fail("VER_17 PBO end state wrong");
        }
        if ModelRegs::get(&m.sram, 0x81C4) != 0x003B
            || ModelRegs::get(&m.sram, 0x81C6) != 0x0086
            || ModelRegs::get(&m.sram, 0x81DA) != 0x0023
        {
            return TestResult::Fail("VER_17 shape-table burst end state wrong");
        }
        if ModelRegs::get(&m.ocp, 0xBFB4) != 0x0328
            || ModelRegs::get(&m.ocp, 0xBFB6) != 0x3E14
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV) != EEE_ADV_8157
            || ModelRegs::get(&m.ocp, OCP_EEE_ADV2) != MDIO_EEE_2_5GT | MDIO_EEE_5GT
        {
            return TestResult::Fail("VER_17 tail end state wrong");
        }
        if ModelRegs::get(&m.usb, USB_U2P3_CTRL) != 0 {
            return TestResult::Fail("VER_17 must not enable U2P3");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_phy_init_ver17_conversation);

    /// Minimal firmware-image builder for the `check_firmware`
    /// tests. Images are built from the Linux struct layouts
    /// with literal field values from `r8152.c` — never the
    /// implementation's constants, so a wrong constant cannot
    /// make code and fixture agree — and the SHA-256 header
    /// checksum is computed by the same implementation the
    /// loader uses. Each block is padded to an 8-byte boundary,
    /// as the loader's `ALIGN(length, 8)` advance requires.
    struct FwTestImage {
        bytes: Vec<u8>,
    }

    impl FwTestImage {
        fn new(version: &str) -> Self {
            let mut bytes = alloc::vec![0u8; 64];
            let v = version.as_bytes();
            let n = core::cmp::min(v.len(), 31);
            bytes[32..32 + n].copy_from_slice(&v[..n]);
            Self { bytes }
        }
        /// Append a block: `type` + `length` header, `body`
        /// bytes, zero padding to an 8-byte boundary.
        fn block(&mut self, ty: u32, body: &[u8]) {
            let len = 8 + body.len();
            self.bytes.extend_from_slice(&ty.to_le_bytes());
            self.bytes.extend_from_slice(&(len as u32).to_le_bytes());
            self.bytes.extend_from_slice(body);
            while self.bytes.len() % 8 != 0 {
                self.bytes.push(0);
            }
        }
        /// Append a block with an explicit (possibly lying)
        /// length field, for invalid-image tests.
        fn block_with_len(&mut self, ty: u32, len: u32, body: &[u8]) {
            self.bytes.extend_from_slice(&ty.to_le_bytes());
            self.bytes.extend_from_slice(&len.to_le_bytes());
            self.bytes.extend_from_slice(body);
            while self.bytes.len() % 8 != 0 {
                self.bytes.push(0);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            let mut h = narf_crypto::sha256::Sha256::new();
            h.update(&self.bytes[32..]);
            let sum = h.finalize();
            self.bytes[..32].copy_from_slice(&sum);
            self.bytes
        }
    }

    /// Recompute the header checksum of a mutated test image
    /// in place, so a mutation trips its own check rather than
    /// `BadChecksum`.
    fn resign_fw(img: &mut [u8]) {
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(&img[32..]);
        let sum = h.finalize();
        img[..32].copy_from_slice(&sum);
    }

    fn put_u16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    /// `fw_mac` body (55 bytes after the block header):
    /// fw_offset, fw_reg, bp_ba_addr, bp_ba_value, bp_en_addr,
    /// bp_en_value, bp_start, bp_num, bp[16], reserved,
    /// fw_ver_reg, fw_ver_data — then `data_len` bytes of
    /// firmware data.
    fn fw_mac_body(
        fw_offset: u16,
        fw_reg: u16,
        bp_ba: u16,
        bp_en: u16,
        bp_start: u16,
        bp_num: u16,
        data_len: usize,
    ) -> Vec<u8> {
        let mut b = alloc::vec![0u8; 55 + data_len];
        put_u16(&mut b, 0, fw_offset);
        put_u16(&mut b, 2, fw_reg);
        put_u16(&mut b, 4, bp_ba);
        put_u16(&mut b, 8, bp_en);
        put_u16(&mut b, 12, bp_start);
        put_u16(&mut b, 14, bp_num);
        b
    }

    /// `fw_phy_nc` body (32 bytes after the block header):
    /// fw_offset, fw_reg, ba_reg, ba_data, patch_en_addr,
    /// patch_en_value, mode_reg, mode_pre, mode_post, reserved,
    /// bp_start, bp_num, bp[4] — then `data_len` bytes.
    fn fw_phy_nc_body(data_len: usize) -> Vec<u8> {
        let mut b = alloc::vec![0u8; 32 + data_len];
        put_u16(&mut b, 0, 40); // fw_offset
        put_u16(&mut b, 2, 0xA014); // fw_reg
        put_u16(&mut b, 4, 0xA012); // ba_reg
        put_u16(&mut b, 8, 0xA01A); // patch_en_addr
        put_u16(&mut b, 12, 0xB820); // mode_reg
        put_u16(&mut b, 20, 0xA000); // bp_start
        b
    }

    /// `fw_phy_union` body (50 bytes after the block header):
    /// fw_offset, fw_reg, pre_set[2], bp[8], bp_en, pre_num,
    /// bp_num — then `data_len` bytes.
    fn fw_phy_union_body(data_len: usize) -> Vec<u8> {
        let mut b = alloc::vec![0u8; 50 + data_len];
        put_u16(&mut b, 0, 58); // fw_offset
                                // pre_num (byte 48) and bp_num (byte 49) stay zero.
        b
    }

    /// Valid VER_04 image (mirrors the real rtl8153a-2.fw block
    /// order): PHY_START, PHY_NC, PHY_STOP, USB, PLA, END.
    /// Layout: header 0..64; PHY_START 64..80; PHY_NC 80..180
    /// (len 100, padded to 184); PHY_STOP 184..192; USB
    /// 192..259 (len 67, padded to 264); PLA 264..331 (len 67,
    /// padded to 336); END 336..344.
    fn valid_ver04_image() -> Vec<u8> {
        let mut img = FwTestImage::new("rtl8153a-2 v1 10/23/19");
        img.block(3, &[0u8; 8]); // PHY_START (patch key)
        img.block(5, &fw_phy_nc_body(60)); // PHY_NC
        img.block(4, &[]); // PHY_STOP
        img.block(2, &fw_mac_body(63, 0xF800, 0xFC26, 0xFC38, 0xFC28, 0, 4)); // USB
        img.block(1, &fw_mac_body(63, 0xF800, 0xFC26, 0xFC38, 0xFC28, 0, 4)); // PLA
        img.block(0, &[]); // END
        img.finish()
    }

    /// Valid VER_11 image (mirrors the real rtl8156a-2.fw block
    /// order, subset): USB, PLA, PHY_VER, PHY_START, UNION_NC,
    /// PHY_STOP, END.
    fn valid_ver11_image() -> Vec<u8> {
        let mut img = FwTestImage::new("rtl8156a-2 v2 04/27/23");
        img.block(2, &fw_mac_body(63, 0xE600, 0xFC26, 0xFC48, 0xFC28, 0, 4)); // USB
        img.block(1, &fw_mac_body(63, 0xF800, 0xFC26, 0xFC38, 0xFC28, 0, 4)); // PLA
        let mut ver = [0u8; 8];
        put_u16(&mut ver, 0, 0x801E); // ver.addr = SRAM_GPHY_FW_VER
        put_u16(&mut ver, 2, 0x0102); // ver.data
        img.block(14, &ver); // PHY_VER
        img.block(3, &[0u8; 8]); // PHY_START
        img.block(7, &fw_phy_union_body(2)); // UNION_NC
        img.block(4, &[]); // PHY_STOP
        img.block(0, &[]); // END
        img.finish()
    }

    fn smoke_r8152_firmware_name_for() -> TestResult {
        let cases = [
            (RtlVersion::Ver04, Some("rtl_nic/rtl8153a-2.fw")),
            (RtlVersion::Ver05, Some("rtl_nic/rtl8153a-3.fw")),
            (RtlVersion::Ver06, Some("rtl_nic/rtl8153a-4.fw")),
            (RtlVersion::Ver09, Some("rtl_nic/rtl8153b-2.fw")),
            (RtlVersion::Ver11, Some("rtl_nic/rtl8156a-2.fw")),
            (RtlVersion::Ver13, Some("rtl_nic/rtl8156b-2.fw")),
            (RtlVersion::Ver15, Some("rtl_nic/rtl8156b-2.fw")),
            (RtlVersion::Ver14, Some("rtl_nic/rtl8153c-1.fw")),
            (RtlVersion::Ver16, Some("rtl_nic/rtl8157-1.fw")),
            (RtlVersion::Ver17, Some("rtl_nic/rtl8159-1.fw")),
        ];
        for (version, want) in cases {
            if firmware_name_for(version) != want {
                return TestResult::Fail("firmware_name_for mapping wrong");
            }
        }
        for version in [
            RtlVersion::Ver01,
            RtlVersion::Ver02,
            RtlVersion::Ver03,
            RtlVersion::Ver07,
            RtlVersion::Ver08,
            RtlVersion::Ver10,
            RtlVersion::Ver12,
            RtlVersion::Test01,
            RtlVersion::Unknown,
        ] {
            if firmware_name_for(version).is_some() {
                return TestResult::Fail("version without a file must map to None");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_firmware_name_for);

    fn smoke_r8152_firmware_checksum() -> TestResult {
        let img = valid_ver04_image();
        if !fw_checksum_ok(&img) {
            return TestResult::Fail("valid image must pass the checksum");
        }
        if firmware_version(&img) != "rtl8153a-2 v1 10/23/19" {
            return TestResult::Fail("firmware_version must return the header string");
        }
        // Corrupt one version byte: checksum fails.
        let mut bad = img.clone();
        bad[40] ^= 0xFF;
        if fw_checksum_ok(&bad) {
            return TestResult::Fail("corrupted version field must fail the checksum");
        }
        // Corrupt one firmware byte: checksum fails.
        let mut bad = img.clone();
        bad[100] ^= 0xFF;
        if fw_checksum_ok(&bad) {
            return TestResult::Fail("corrupted firmware byte must fail the checksum");
        }
        if fw_checksum_ok(&[]) || fw_checksum_ok(&img[..63]) {
            return TestResult::Fail("short image must fail the checksum");
        }
        if !firmware_version(&[]).is_empty() || !firmware_version(&img[..63]).is_empty() {
            return TestResult::Fail("short image must have no version string");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_firmware_checksum);

    fn smoke_r8152_firmware_check_valid() -> TestResult {
        if check_firmware(RtlVersion::Ver04, &valid_ver04_image()) != Ok(()) {
            return TestResult::Fail("valid VER_04 image rejected");
        }
        if check_firmware(RtlVersion::Ver11, &valid_ver11_image()) != Ok(()) {
            return TestResult::Fail("valid VER_11 image rejected");
        }
        // VER_16: SPEED_UP only, then END.
        let mut img = FwTestImage::new("rtl8157-1 v1 01/01/25");
        let mut speed = [0u8; 8];
        put_u16(&mut speed, 0, 16); // fw_offset
        put_u16(&mut speed, 2, 1); // version
        put_u16(&mut speed, 4, 0x9A00); // fw_reg
        let mut body = speed.to_vec();
        body.extend_from_slice(&[0u8; 4]);
        img.block(13, &body); // SPEED_UP, len 20
        img.block(0, &[]); // END
        if check_firmware(RtlVersion::Ver16, &img.finish()) != Ok(()) {
            return TestResult::Fail("valid VER_16 SPEED_UP image rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_firmware_check_valid);

    fn smoke_r8152_firmware_check_invalid() -> TestResult {
        // Too small.
        if check_firmware(RtlVersion::Ver04, &valid_ver04_image()[..63]) != Err(FwError::TooSmall) {
            return TestResult::Fail("short image must be TooSmall");
        }
        // Bad checksum.
        let mut img = valid_ver04_image();
        img[40] ^= 0xFF;
        if check_firmware(RtlVersion::Ver04, &img) != Err(FwError::BadChecksum) {
            return TestResult::Fail("corrupted image must be BadChecksum");
        }
        // Zero-length block (Linux would loop forever here).
        let mut img = FwTestImage::new("test");
        img.block_with_len(1, 0, &[]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Err(FwError::ZeroLength) {
            return TestResult::Fail("zero-length block must be ZeroLength");
        }
        // Truncated block: length runs past the end.
        let mut img = FwTestImage::new("test");
        img.block_with_len(1, 1000, &[0u8; 8]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Err(FwError::Truncated) {
            return TestResult::Fail("overlong block must be Truncated");
        }
        // END with length != 8.
        let mut img = FwTestImage::new("test");
        img.block_with_len(0, 9, &[0u8; 1]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Err(FwError::BadLength) {
            return TestResult::Fail("END length != 8 must be BadLength");
        }
        // Duplicate PLA.
        let mut img = FwTestImage::new("test");
        img.block(1, &fw_mac_body(63, 0xF800, 0xFC26, 0xFC38, 0xFC28, 0, 4));
        img.block(1, &fw_mac_body(63, 0xF800, 0xFC26, 0xFC38, 0xFC28, 0, 4));
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Err(FwError::Duplicate) {
            return TestResult::Fail("duplicate PLA must be Duplicate");
        }
        // STOP without START.
        let mut img = FwTestImage::new("test");
        img.block(4, &[]);
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Err(FwError::OutOfOrder) {
            return TestResult::Fail("STOP without START must be OutOfOrder");
        }
        // START without STOP.
        let mut img = FwTestImage::new("test");
        img.block(3, &[0u8; 8]);
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Err(FwError::UnpairedStart) {
            return TestResult::Fail("START without STOP must be UnpairedStart");
        }
        // USB block with the wrong fw_reg.
        let mut img = valid_ver04_image();
        put_u16(&mut img, 202, 0x0000);
        resign_fw(&mut img);
        if check_firmware(RtlVersion::Ver04, &img) != Err(FwError::InvalidBlock) {
            return TestResult::Fail("USB block with wrong fw_reg must be InvalidBlock");
        }
        // PHY_NC block with the wrong fw_reg.
        let mut img = valid_ver04_image();
        put_u16(&mut img, 90, 0x0000);
        resign_fw(&mut img);
        if check_firmware(RtlVersion::Ver04, &img) != Err(FwError::InvalidBlock) {
            return TestResult::Fail("PHY_NC block with wrong fw_reg must be InvalidBlock");
        }
        // UNION_NC is not valid for VER_04.
        let mut img = FwTestImage::new("test");
        img.block(3, &[0u8; 8]);
        img.block(7, &fw_phy_union_body(2));
        img.block(4, &[]);
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Err(FwError::InvalidBlock) {
            return TestResult::Fail("UNION_NC on VER_04 must be InvalidBlock");
        }
        // SPEED_UP is not valid for VER_04.
        let mut img = FwTestImage::new("test");
        let mut speed = [0u8; 8];
        put_u16(&mut speed, 0, 16);
        put_u16(&mut speed, 2, 1);
        put_u16(&mut speed, 4, 0x9A00);
        let mut body = speed.to_vec();
        body.extend_from_slice(&[0u8; 4]);
        img.block(13, &body);
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Err(FwError::InvalidBlock) {
            return TestResult::Fail("SPEED_UP on VER_04 must be InvalidBlock");
        }
        // PHY_VER with the wrong address.
        let mut img = FwTestImage::new("test");
        let mut ver = [0u8; 8];
        put_u16(&mut ver, 0, 0x0000);
        put_u16(&mut ver, 2, 0x0102);
        img.block(14, &ver);
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver11, &img.finish()) != Err(FwError::InvalidBlock) {
            return TestResult::Fail("PHY_VER with wrong addr must be InvalidBlock");
        }
        // PHY_VER after START is out of order.
        let mut img = FwTestImage::new("test");
        img.block(3, &[0u8; 8]);
        let mut ver = [0u8; 8];
        put_u16(&mut ver, 0, 0x801E);
        put_u16(&mut ver, 2, 0x0102);
        img.block(14, &ver);
        img.block(4, &[]);
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver11, &img.finish()) != Err(FwError::OutOfOrder) {
            return TestResult::Fail("PHY_VER after START must be OutOfOrder");
        }
        // FIXUP with the wrong setting address.
        let mut img = FwTestImage::new("test");
        let mut fix = [0u8; 8];
        put_u16(&mut fix, 0, 0x0000);
        put_u16(&mut fix, 2, 0x0080);
        img.block(6, &fix);
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver11, &img.finish()) != Err(FwError::InvalidBlock) {
            return TestResult::Fail("FIXUP with wrong addr must be InvalidBlock");
        }
        // PLA block is not valid for VER_16.
        let mut img = FwTestImage::new("test");
        img.block(1, &fw_mac_body(63, 0xF800, 0xFC26, 0xFC38, 0xFC28, 0, 4));
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver16, &img.finish()) != Err(FwError::InvalidBlock) {
            return TestResult::Fail("PLA block on VER_16 must be InvalidBlock");
        }
        // Unknown block type is skipped.
        let mut img = FwTestImage::new("test");
        img.block(99, &[]);
        img.block(0, &[]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Ok(()) {
            return TestResult::Fail("unknown block type must be skipped");
        }
        // No END block at all, but START/STOP pair up: accepted,
        // as in Linux.
        let mut img = FwTestImage::new("test");
        img.block(3, &[0u8; 8]);
        img.block(4, &[]);
        if check_firmware(RtlVersion::Ver04, &img.finish()) != Ok(()) {
            return TestResult::Fail("missing END with paired START/STOP must be accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_firmware_check_invalid);

    fn ipv4_tcp_frame(payload_len: usize) -> Vec<u8> {
        let mut f = alloc::vec![0u8; 14 + 20 + 20 + payload_len];
        f[12] = 0x08;
        f[13] = 0x00;
        f[14] = 0x45;
        f[14 + 9] = 6;
        f[14 + 20 + 12] = 0x50;
        f
    }

    fn ipv4_udp_frame() -> Vec<u8> {
        let mut f = ipv4_tcp_frame(10);
        f[14 + 9] = 17;
        f
    }

    fn ipv6_tcp_frame(payload_len: usize) -> Vec<u8> {
        let mut f = alloc::vec![0u8; 14 + 40 + 20 + payload_len];
        f[12] = 0x86;
        f[13] = 0xDD;
        f[14] = 0x60;
        f[14 + 6] = 6;
        f[14 + 40 + 12] = 0x50;
        f
    }

    fn smoke_r8152_tx_l3_info() -> TestResult {
        let v4 = ipv4_tcp_frame(10);
        match tx_l3_info(&v4) {
            Some(i) if i.is_ipv4 && i.protocol == 6 && i.transport_offset == 34 => {}
            _ => return TestResult::Fail("IPv4/TCP transport offset wrong"),
        }
        let udp = ipv4_udp_frame();
        match tx_l3_info(&udp) {
            Some(i) if i.is_ipv4 && i.protocol == 17 && i.transport_offset == 34 => {}
            _ => return TestResult::Fail("IPv4/UDP transport offset wrong"),
        }
        let v6 = ipv6_tcp_frame(10);
        match tx_l3_info(&v6) {
            Some(i) if !i.is_ipv4 && i.protocol == 6 && i.transport_offset == 54 => {}
            _ => return TestResult::Fail("IPv6/TCP transport offset wrong"),
        }
        // One inline 802.1Q tag moves the transport base by 4.
        let mut tagged = ipv4_tcp_frame(10);
        tagged.splice(12..12, [0x81, 0x00, 0x00, 0x64]);
        tagged[16] = 0x08;
        tagged[17] = 0x00;
        match tx_l3_info(&tagged) {
            Some(i) if i.transport_offset == 38 => {}
            _ => return TestResult::Fail("tagged IPv4 transport offset wrong"),
        }
        // IPv6 extension headers: transport offset unknowable.
        let mut ext = ipv6_tcp_frame(10);
        ext[14 + 6] = 0;
        if tx_l3_info(&ext).is_some() {
            return TestResult::Fail("IPv6 extension headers must not parse");
        }
        // Non-IP ethertype and short frames do not parse.
        let mut arp = ipv4_tcp_frame(10);
        arp[12] = 0x08;
        arp[13] = 0x06;
        if tx_l3_info(&arp).is_some() || tx_l3_info(&[0u8; 10]).is_some() {
            return TestResult::Fail("non-IP/short frames must not parse");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_tx_l3_info);

    fn smoke_r8152_tx_segment_meta() -> TestResult {
        let frame = ipv4_tcp_frame(10);
        // Plain meta reproduces build_tx_segment byte for byte.
        let mut plain_meta = Vec::new();
        let mut plain = Vec::new();
        if build_tx_segment_meta(&frame, narf_net::TxMeta::plain(), &mut plain_meta).is_err()
            || build_tx_segment(&frame, &mut plain).is_err()
            || plain_meta != plain
        {
            return TestResult::Fail("plain meta must match the plain builder");
        }
        // VLAN insert: opts2 = TAG_BIT | swab16(0x1234).
        let mut out = Vec::new();
        let meta = narf_net::TxMeta {
            vlan_tag: Some(0x1234),
            ..narf_net::TxMeta::plain()
        };
        if build_tx_segment_meta(&frame, meta, &mut out).is_err() {
            return TestResult::Fail("VLAN frame rejected");
        }
        let opts2 = u32::from_le_bytes(out[4..8].try_into().unwrap());
        if opts2 != TX_VLAN_TAG_BIT | 0x3412 {
            return TestResult::Fail("VLAN opts2 wrong");
        }
        // IPv4/TCP checksum offload: IPV4_CS | TCP_CS | 34<<17.
        let mut out = Vec::new();
        let meta = narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Tcp);
        if build_tx_segment_meta(&frame, meta, &mut out).is_err() {
            return TestResult::Fail("csum frame rejected");
        }
        let opts2 = u32::from_le_bytes(out[4..8].try_into().unwrap());
        if opts2 != TX_IPV4_CS | TX_TCP_CS | (34 << TX_TCPHO_SHIFT) {
            return TestResult::Fail("csum opts2 wrong");
        }
        // Hardware TSO: GTSENDV4 + 34<<18 in opts1, 1460<<17
        // in opts2.
        let mut out = Vec::new();
        let meta = narf_net::TxMeta::with_tso(1460);
        if build_tx_segment_meta(&frame, meta, &mut out).is_err() {
            return TestResult::Fail("TSO frame rejected");
        }
        let opts1 = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let opts2 = u32::from_le_bytes(out[4..8].try_into().unwrap());
        let len = frame.len() as u32;
        if opts1 != len | TX_FS | TX_LS | TX_GTSENDV4 | (34 << TX_GTTCPHO_SHIFT) {
            return TestResult::Fail("TSO opts1 wrong");
        }
        if opts2 != 1460 << TX_MSS_SHIFT {
            return TestResult::Fail("TSO opts2 wrong");
        }
        // MSS clamps to MSS_MAX like Linux (min(mss, MSS_MAX)).
        let mut out = Vec::new();
        if build_tx_segment_meta(&frame, narf_net::TxMeta::with_tso(9000), &mut out).is_err() {
            return TestResult::Fail("clamped-MSS frame rejected");
        }
        let opts2 = u32::from_le_bytes(out[4..8].try_into().unwrap());
        if opts2 != TX_MSS_MAX << TX_MSS_SHIFT {
            return TestResult::Fail("MSS clamp wrong");
        }
        // Rejections: SCTP csum, TCP csum on a UDP frame, TSO
        // on a UDP frame, TSO on a non-IP frame.
        let udp = ipv4_udp_frame();
        if build_tx_segment_meta(
            &frame,
            narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Sctp),
            &mut Vec::new(),
        )
        .is_ok()
            || build_tx_segment_meta(
                &udp,
                narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Tcp),
                &mut Vec::new(),
            )
            .is_ok()
            || build_tx_segment_meta(&udp, narf_net::TxMeta::with_tso(1460), &mut Vec::new())
                .is_ok()
            || build_tx_segment_meta(
                &arp_frame(),
                narf_net::TxMeta::with_tso(1460),
                &mut Vec::new(),
            )
            .is_ok()
        {
            return TestResult::Fail("unsupported offload request must be rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_tx_segment_meta);

    fn arp_frame() -> Vec<u8> {
        let mut f = alloc::vec![0u8; 60];
        f[12] = 0x08;
        f[13] = 0x06;
        f
    }

    fn smoke_r8152_rx_vlan_and_splice() -> TestResult {
        // Descriptor opts2 for TCI 0x0064: TAG_BIT set, low 16
        // bits byte-swapped (0x6400) — decode recovers 0x0064.
        if rx_vlan_tag_from_opts2(RX_VLAN_TAG_BIT | 0x6400) != Some(0x0064) {
            return TestResult::Fail("RX VLAN tag decode wrong");
        }
        if rx_vlan_tag_from_opts2(0x6400).is_some() {
            return TestResult::Fail("tag bit clear must mean no tag");
        }
        // Splice: 60-byte frame -> 64 bytes, 0x8100 + TCI after
        // the MACs, original ethertype preserved after the tag.
        let mut frame = alloc::vec![0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x00;
        let tagged = match insert_vlan_tag(&frame, 0x0064) {
            Some(t) => t,
            None => return TestResult::Fail("splice rejected a full frame"),
        };
        if tagged.len() != 64
            || tagged[12..16] != [0x81, 0x00, 0x00, 0x64]
            || tagged[16..18] != [0x08, 0x00]
            || tagged[18..] != frame[14..]
        {
            return TestResult::Fail("splice bytes wrong");
        }
        if insert_vlan_tag(&[0u8; 10], 0x0064).is_some() {
            return TestResult::Fail("short frame must not splice");
        }
        // Aggregate walk reports the tag on the segment.
        // Linux layout: opts1 counts frame + FCS (60 + 4),
        // FCS bytes follow the frame.
        let mut agg = alloc::vec::Vec::new();
        agg.extend_from_slice(&((frame.len() + RX_FCS_LEN) as u32).to_le_bytes()); // opts1: len
        agg.extend_from_slice(&(RX_VLAN_TAG_BIT | 0x6400).to_le_bytes()); // opts2
        agg.extend_from_slice(&[0u8; 16]); // opts3..opts6
        agg.extend_from_slice(&frame);
        agg.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // FCS marker
        let segs = parse_rx_aggregate(&agg);
        if segs.len() != 1 || segs[0].vlan_tag != Some(0x0064) || segs[0].len != 60 {
            return TestResult::Fail("aggregate walk must report the VLAN tag");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_vlan_and_splice);

    fn smoke_r8152_rx_vlan_enable_switch() -> TestResult {
        if rx_vlan_enable(RtlVersion::Ver03) != (PLA_CPCR, CPCR_RX_VLAN)
            || rx_vlan_enable(RtlVersion::Ver14) != (PLA_CPCR, CPCR_RX_VLAN)
            || rx_vlan_enable(RtlVersion::Ver10) != (PLA_RCR1, RCR1_OUTER_VLAN | RCR1_INNER_VLAN)
            || rx_vlan_enable(RtlVersion::Unknown) != (PLA_RCR1, RCR1_OUTER_VLAN | RCR1_INNER_VLAN)
        {
            return TestResult::Fail("RX VLAN enable register switch wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_vlan_enable_switch);

    fn smoke_r8152_wol_decode_and_ops() -> TestResult {
        // Decode: LINK bit -> phy, UWF+BWF -> unicast+broadcast,
        // MAGIC bit -> magic, MWF clear -> no multicast.
        let opts = wol_opts_from_regs(0x0010, 0x0050, 0x0001);
        if opts
            != (WolOpts {
                phy: true,
                unicast: true,
                broadcast: true,
                multicast: false,
                magic: true,
            })
        {
            return TestResult::Fail("WoL decode wrong");
        }
        // Magic-only op sequence, in __rtl_set_wol order.
        let magic_only = WolOpts {
            magic: true,
            ..WolOpts::default()
        };
        if wol_ops(magic_only)
            != [
                WolOp::CrwecrWrite(CRWECR_CONFIG),
                WolOp::Config34Set(false),
                WolOp::Config5W0W1(0),
                WolOp::CrwecrWrite(CRWECR_NORMAL),
                WolOp::CfgWolSet(true),
            ]
        {
            return TestResult::Fail("magic-only WoL ops wrong");
        }
        // All-options sequence: filter mask UWF|BWF|MWF.
        let all = WolOpts {
            phy: true,
            unicast: true,
            broadcast: true,
            multicast: true,
            magic: true,
        };
        let ops = wol_ops(all);
        if ops[1] != WolOp::Config34Set(true)
            || ops[2] != WolOp::Config5W0W1(CONFIG5_UWF_EN | CONFIG5_BWF_EN | CONFIG5_MWF_EN)
            || ops[4] != WolOp::CfgWolSet(true)
        {
            return TestResult::Fail("all-options WoL ops wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_wol_decode_and_ops);

    fn smoke_r8152_mtu_policy() -> TestResult {
        // Linux max-MTU classes (r8152.c probe switch).
        if max_mtu_for(RtlVersion::Ver01) != 1500
            || max_mtu_for(RtlVersion::Ver02) != 1500
            || max_mtu_for(RtlVersion::Ver07) != 1500
            || max_mtu_for(RtlVersion::Unknown) != 1500
            || max_mtu_for(RtlVersion::Test01) != 1500
        {
            return TestResult::Fail("FE/unknown max MTU is not 1500");
        }
        if max_mtu_for(RtlVersion::Ver03) != 9194 || max_mtu_for(RtlVersion::Ver14) != 9194 {
            return TestResult::Fail("9 KiB class max MTU is not 9194");
        }
        if max_mtu_for(RtlVersion::Ver10) != 15338 {
            return TestResult::Fail("15 KiB class max MTU is not 15338");
        }
        if max_mtu_for(RtlVersion::Ver12) != 16362 || max_mtu_for(RtlVersion::Ver17) != 16362 {
            return TestResult::Fail("16 KiB class max MTU is not 16362");
        }
        // Bounds: 68 accepted, 67 rejected, max accepted, max+1
        // rejected, per class.
        if validate_mtu(RtlVersion::Ver03, 68).is_err()
            || validate_mtu(RtlVersion::Ver03, 67).is_ok()
            || validate_mtu(RtlVersion::Ver03, 9194).is_err()
            || validate_mtu(RtlVersion::Ver03, 9195).is_ok()
            || validate_mtu(RtlVersion::Ver01, 1500).is_err()
            || validate_mtu(RtlVersion::Ver01, 1501).is_ok()
        {
            return TestResult::Fail("MTU validation bounds wrong");
        }
        // RMS values: MTU + 22 (VLAN header + FCS).
        if mtu_to_rms(1500) != 1522 || mtu_to_rms(9000) != 9022 {
            return TestResult::Fail("MTU to RMS conversion wrong");
        }
        // Reprogram decisions: FE never reprograms (Linux leaves
        // PLA_RMS untouched for VER_01/02/07); GbE reprograms on
        // change; nothing reprograms when unchanged.
        if mtu_reprogram(RtlVersion::Ver01, 1500, 1400).is_some()
            || mtu_reprogram(RtlVersion::Ver03, 1500, 1500).is_some()
            || mtu_reprogram(RtlVersion::Ver03, 1500, 9000) != Some(9022)
        {
            return TestResult::Fail("MTU reprogram decision wrong");
        }
        // Transition: not-live rejects with ENODEV; out-of-range
        // rejects with EINVAL and leaves state untouched; a
        // pending write survives an unchanged MTU; a changed GbE
        // MTU overwrites it with the new bound.
        if mtu_transition(RtlVersion::Ver03, 1500, Some(1522), 9000, false) != Err(19) {
            return TestResult::Fail("MTU transition on dead record is not ENODEV");
        }
        if mtu_transition(RtlVersion::Ver03, 1500, None, 9195, true) != Err(22) {
            return TestResult::Fail("MTU transition out of range is not EINVAL");
        }
        if mtu_transition(RtlVersion::Ver03, 1500, Some(1522), 1500, true) != Ok((1500, Some(1522)))
        {
            return TestResult::Fail("unchanged MTU dropped a pending write");
        }
        if mtu_transition(RtlVersion::Ver03, 1500, Some(1522), 9000, true) != Ok((9000, Some(9022)))
        {
            return TestResult::Fail("changed GbE MTU did not overwrite pending bound");
        }
        if mtu_transition(RtlVersion::Ver01, 1500, None, 1400, true) != Ok((1400, None)) {
            return TestResult::Fail("FE MTU change queued a reprogram");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_mtu_policy);

    fn smoke_r8152_mtu_rms_packing() -> TestResult {
        // MTU 9000 programs PLA_RMS 9022 (0x233E): word write at
        // 0xC016 aligns down to 0xC014, byte-enable 0x33 << 2 in
        // wIndex, value in the high lanes — same packing the
        // bind-time 1522 case pins.
        let (_, _, wv, wi, data) = ocp_write_word_pack(MCU_TYPE_PLA, PLA_RMS, 9022);
        if wv != 0xC014 || wi != 0x01CC || data != [0, 0, 0x3E, 0x23] {
            return TestResult::Fail("MTU RMS word write packing wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_mtu_rms_packing);

    // Suspend/resume fixture tests (#1256). The transfer-level
    // behavior (park -> gate -> wake -> traffic) needs a hub +
    // device and is CI/silicon-only — no fake xhci exists. What
    // fixtures CAN pin: the pump decision precedence, the
    // remote-wakeup SETUP bytes, and the parked-port selection
    // + flag cycle the hook and resume manipulate.
    fn smoke_r8152_pump_action_precedence() -> TestResult {
        use crate::attach::{nic_pump_action, NicPumpAction};
        // Detach dominates suspend; a stopped pump exits.
        if nic_pump_action(true, true, true) != NicPumpAction::Exit
            || nic_pump_action(true, false, true) != NicPumpAction::Exit
            || nic_pump_action(false, true, false) != NicPumpAction::Exit
            || nic_pump_action(false, false, false) != NicPumpAction::Exit
        {
            return TestResult::Fail("pump_action did not exit on detach/stop");
        }
        // Suspended + running parks without transfers.
        if nic_pump_action(false, true, true) != NicPumpAction::Park {
            return TestResult::Fail("pump_action did not park a suspended pump");
        }
        // Live + running transfers.
        if nic_pump_action(false, false, true) != NicPumpAction::Transfer {
            return TestResult::Fail("pump_action did not transfer for a live pump");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_pump_action_precedence);

    fn smoke_r8152_remote_wakeup_setup() -> TestResult {
        // USB 2.0 §9.4.2 + Table 9-6: host-to-device, standard,
        // device recipient; SET_FEATURE (3); selector 1
        // (DEVICE_REMOTE_WAKEUP); wIndex 0; no Data Stage.
        let setup = crate::control::set_feature_device_remote_wakeup();
        if setup.to_bytes() != [0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00] {
            return TestResult::Fail("remote-wakeup SETUP packet mis-encoded");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_remote_wakeup_setup);

    fn smoke_r8152_suspended_hub_ports() -> TestResult {
        let mk =
            |slot_id: u8, hub_port: Option<(u8, u8)>, suspended: bool, detached: bool| RtlDevice {
                slot_id,
                generation: RtlGen::GbE,
                version: RtlVersion::Ver03,
                wol_opts: WolOpts::default(),
                mac: [0x02, 0, 0, 0, 0, slot_id],
                bulk_in_dci: 3,
                bulk_out_dci: 4,
                iface_name: alloc::format!("usb-rtl-susp{}", slot_id),
                pump_running: true,
                link_byte: 0xFF,
                mtu: 1500,
                pending_rms: None,
                detached,
                controller: 0,
                hub_port,
                speed: crate::xhci::PortSpeed::High,
                suspended,
                wakeup_armed: suspended,
            };
        {
            let mut g = RTL_DEVICES.lock();
            g.push(mk(7, Some((2, 3)), true, false));
            g.push(mk(8, Some((2, 4)), false, false));
            g.push(mk(9, None, true, false));
            g.push(mk(10, Some((2, 5)), true, true));
        }
        let ports = suspended_hub_ports();
        RTL_DEVICES.lock().clear();
        // Only the live parked hub-port device selects; the
        // running hub-port device, the parked root-port device
        // (no hub to gate), and the detached record do not.
        if ports != alloc::vec![(2, 3)] {
            return TestResult::Fail("suspended_hub_ports selected the wrong ports");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_suspended_hub_ports);
}
