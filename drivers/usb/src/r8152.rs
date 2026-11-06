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
//!   exception. The v1 layout is used for all generations; the
//!   RTL8157 v2 descriptor layout is not decoded.
//! - **TX**: each bulk-OUT transfer is one 8-byte `tx_desc`
//!   (`opts1 = len | TX_FS | TX_LS`, plus GTSENDV4/V6 +
//!   transport-offset for hardware TSO) followed by the frame,
//!   zero-padded to a 4-byte multiple (`TX_ALIGN`). `opts2`
//!   carries the offloads the stack requested via `TxMeta`:
//!   VLAN insert, IPv4/IPv6 + TCP/UDP checksum generation, or
//!   the TSO MSS — plain frames still encode `opts2 = 0`.
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
//! The version-switched PHY init layer is implemented for the
//! original RTL8153 family only (VER_03–VER_06, Linux's
//! `r8153_hw_phy_cfg` — see the §881 section in the code); every
//! other chip version keeps reset defaults until its sequence is
//! ported, and the firmware-blob step
//! (`rtl8152_apply_firmware`) is not reproduced for any version
//! (it loads per-version firmware files NARF does not ship).
//! Tracked as follow-up issues.

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
// this layer; the table below reproduces Linux's
// `r8153_hw_phy_cfg` for the original RTL8153 family
// (VER_03–VER_06 — the chip in most USB-C docks and GbE dongles,
// the most common version, implemented here because no chip
// version is on hand in this VM and no symptom has been observed
// to drive a symptom-led port per #881's scoping instruction).
// Every other version keeps reset defaults until its sequence is
// ported (see the remainder issue); the firmware-blob step
// (`rtl8152_apply_firmware`) is deliberately NOT reproduced — it
// loads per-version firmware files NARF does not ship, so the
// sequence runs around that step in Linux's order otherwise.

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
}

/// The `r8153_hw_phy_cfg` sequence for the original RTL8153
/// family, in Linux's order, with the firmware-blob step omitted
/// (see the section header). Returns an empty sequence for every
/// other version — those keep reset defaults until ported.
/// Version gates inside the sequence: `CTAP_SHORT_EN` clears only
/// on VER_03; the U2P3 enable lands only on VER_05/VER_06 (Linux
/// enables it for VER_05/VER_06/default and skips VER_03/VER_04).
pub fn r8153_phy_init_ops(version: RtlVersion) -> Vec<PhyInitOp> {
    use PhyInitOp::*;
    match version {
        RtlVersion::Ver03 | RtlVersion::Ver04 | RtlVersion::Ver05 | RtlVersion::Ver06 => {}
        _ => return Vec::new(),
    }
    let mut ops = vec![
        // Disable ALDPS before updating the PHY parameters.
        AldpsDisable,
        // Disable EEE before updating the PHY parameters.
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
        // [rtl8152_apply_firmware skipped: no firmware blobs.]
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
        // Re-enable EEE (Linux: eee_en is true for VER_03–VER_06).
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
            value: EEE_ADV_8153,
        },
        // Re-enable ALDPS.
        OcpRegSetBits {
            addr: OCP_POWER_CFG,
            bits: POWER_CFG_EN_ALDPS,
        },
        // Flow-control advertisement (r8152b_enable_fc).
        MdioSetBits {
            reg: MII_ADVERTISE,
            bits: ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM,
        },
    ];
    if version == RtlVersion::Ver03 {
        // VER_03 only: clear CTAP_SHORT_EN, immediately after the
        // EEE disable (Linux's position in the sequence).
        ops.insert(
            4,
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

/// Execute one [`PhyInitOp`] against the device.
async fn apply_phy_init_op(dev: &USBDevice, op: PhyInitOp) -> Result<(), ()> {
    use PhyInitOp::*;
    match op {
        OcpRegSetBits { addr, bits } => ocp_reg_set_bits(dev, addr, bits).await,
        OcpRegClrBits { addr, bits } => ocp_reg_clr_bits(dev, addr, bits).await,
        OcpRegWrite { addr, value } => ocp_reg_write(dev, addr, value).await,
        SramWrite { addr, value } => {
            ocp_reg_write(dev, OCP_SRAM_ADDR, addr).await?;
            ocp_reg_write(dev, OCP_SRAM_DATA, value).await
        }
        PlaWordSetBits { addr, bits } => pla_word_set_bits(dev, addr, bits).await,
        PlaWordClrBits { addr, bits } => pla_word_clr_bits(dev, addr, bits).await,
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
            for _ in 0..500 {
                let status = ocp_reg_read(dev, OCP_PHY_STATUS).await? & PHY_STAT_MASK;
                if status == PHY_STAT_LAN_ON
                    || status == PHY_STAT_PWRDN
                    || status == PHY_STAT_EXT_INIT
                {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
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
    }
}

/// Run the version-switched PHY init sequence for `version`
/// before CR RE/TE enable. Unknown and not-yet-ported versions
/// are a no-op (reset defaults), never a bind failure.
pub async fn apply_phy_init(dev: &USBDevice, version: RtlVersion) -> Result<(), ()> {
    for op in r8153_phy_init_ops(version) {
        apply_phy_init_op(dev, op).await?;
    }
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
    for op in r8153_init_ops(version, speed, burst_size, link_ok) {
        apply_phy_init_op(dev, op).await?;
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
/// `r8152_rx_csum`). Follows the in-tree v1 descriptor layout
/// used for all generations; the RTL8157 v2 descriptor layout
/// (Linux `r8157_rx_csum`) is not decoded here.
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
        if info.protocol != want || info.transport_offset as u32 > TX_TCPHO_MAX {
            return Err(());
        }
        opts2 |= if info.is_ipv4 { TX_IPV4_CS } else { TX_IPV6_CS }
            | if want == 6 { TX_TCP_CS } else { TX_UDP_CS }
            | ((info.transport_offset as u32) << TX_TCPHO_SHIFT);
    }
    out.extend_from_slice(&opts1.to_le_bytes());
    out.extend_from_slice(&opts2.to_le_bytes());
    out.extend_from_slice(frame);
    while out.len() % 4 != 0 {
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
    let mut seg = Vec::new();
    if build_tx_segment_meta(frame, meta, &mut seg).is_ok() {
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
        build_tx_segment_meta(s, seg_meta, &mut seg)?;
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
    // PHY/firmware init for the chip version, before CR RE/TE
    // enable. Unknown / not-yet-ported versions are a no-op here
    // (reset defaults); VER_03–VER_06 run r8153_hw_phy_cfg.
    apply_phy_init(&device, version).await?;
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
                    g.get(idx).map(|d| (d.iface_name.clone(), d.hub_port))
                };
                if let Some((name, hub_port)) = dev {
                    let mut delivered = 0usize;
                    for seg in parse_rx_aggregate(&buf[..n]) {
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
        // Only VER_03–VER_06 get a sequence; everything else is
        // reset defaults (empty table, never a bind failure).
        if !r8153_phy_init_ops(RtlVersion::Ver01).is_empty()
            || !r8153_phy_init_ops(RtlVersion::Ver08).is_empty()
            || !r8153_phy_init_ops(RtlVersion::Ver16).is_empty()
            || !r8153_phy_init_ops(RtlVersion::Unknown).is_empty()
        {
            return TestResult::Fail("unported version must have an empty PHY table");
        }
        let v03 = r8153_phy_init_ops(RtlVersion::Ver03);
        let v04 = r8153_phy_init_ops(RtlVersion::Ver04);
        let v05 = r8153_phy_init_ops(RtlVersion::Ver05);
        let v06 = r8153_phy_init_ops(RtlVersion::Ver06);
        // VER_03 carries exactly one more step than VER_04: the
        // CTAP_SHORT_EN clear at position 4 (right after the EEE
        // disable).
        if v03.len() != v04.len() + 1 {
            return TestResult::Fail("VER_03 table must exceed VER_04 by the CTAP step");
        }
        if v03[4]
            != (PhyInitOp::OcpRegClrBits {
                addr: OCP_EEE_CFG,
                bits: EEE_CFG_CTAP_SHORT_EN,
            })
        {
            return TestResult::Fail("VER_03 table must clear CTAP_SHORT_EN fourth");
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
    /// words, OCP PHY registers, SRAM cells, USB-window words and
    /// MDIO registers as small association lists. The executor
    /// mirrors the production op semantics (read-modify-write
    /// for set/clr-bits, two-step SRAM writes); the ALDPS poll
    /// is modelled as satisfied.
    /// All polls are modelled the same way. Byte ops touch
    /// the low byte of the word at `addr` (all byte-op addresses
    /// in the sequences are even, so this is exact there); a
    /// dword write splits low@`addr`, high@`addr + 1`.
    struct ModelRegs {
        pla: Vec<(u16, u16)>,
        ocp: Vec<(u16, u16)>,
        sram: Vec<(u16, u16)>,
        usb: Vec<(u16, u16)>,
        mdio: Vec<(u16, u16)>,
    }

    impl ModelRegs {
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
                SramWrite { addr, value } => Self::set(&mut self.sram, addr, value),
                PlaWordSetBits { addr, bits } => {
                    let cur = Self::get(&self.pla, addr);
                    Self::set(&mut self.pla, addr, cur | bits);
                }
                PlaWordClrBits { addr, bits } => {
                    let cur = Self::get(&self.pla, addr);
                    Self::set(&mut self.pla, addr, cur & !bits);
                }
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
        let mut m = ModelRegs {
            pla: Vec::new(),
            ocp: Vec::new(),
            sram: Vec::new(),
            usb: Vec::new(),
            mdio: Vec::new(),
        };
        ModelRegs::set(&mut m.ocp, OCP_POWER_CFG, POWER_CFG_EN_ALDPS);
        ModelRegs::set(&mut m.ocp, OCP_EEE_CFG, EEE_CFG_CTAP_SHORT_EN);
        for op in r8153_phy_init_ops(RtlVersion::Ver03) {
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
        // VER_04 from the same preload: CTAP_SHORT_EN survives
        // (no clear step), everything else matches.
        let mut m4 = ModelRegs {
            pla: Vec::new(),
            ocp: Vec::new(),
            sram: Vec::new(),
            usb: Vec::new(),
            mdio: Vec::new(),
        };
        ModelRegs::set(&mut m4.ocp, OCP_POWER_CFG, POWER_CFG_EN_ALDPS);
        ModelRegs::set(&mut m4.ocp, OCP_EEE_CFG, EEE_CFG_CTAP_SHORT_EN);
        for op in r8153_phy_init_ops(RtlVersion::Ver04) {
            m4.apply(op);
        }
        if ModelRegs::get(&m4.ocp, OCP_EEE_CFG) != EEE_CFG_EEE10_EN | EEE_CFG_CTAP_SHORT_EN {
            return TestResult::Fail("VER_04 must preserve CTAP_SHORT_EN");
        }
        // VER_05: U2P3 enabled, CTAP untouched.
        let mut m5 = ModelRegs {
            pla: Vec::new(),
            ocp: Vec::new(),
            sram: Vec::new(),
            usb: Vec::new(),
            mdio: Vec::new(),
        };
        for op in r8153_phy_init_ops(RtlVersion::Ver05) {
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
