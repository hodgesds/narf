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
//!   (`opts1..opts6`, `opts1 & 0x7FFF` = frame length, frame bytes
//!   only) followed immediately by the frame.
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

use crate::class_registry::{register_class_driver_with_unbind, UsbClassMatch, UsbProbeError};
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

// ── Datapath descriptor formats ──────────────────────────────────

/// RX aggregation segment header length (`rx_desc`, 6 × u32).
pub const RX_DESC_LEN: usize = 24;
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
    /// Frame length in bytes (descriptor excluded).
    pub len: usize,
    /// 802.1Q tag the chip stripped and reported in `rx_desc`
    /// `opts2` (`RX_VLAN_TAG_BIT`), or `None` when the segment
    /// carries no VLAN tag. The pump splices a reported tag
    /// back into the delivered frame (see `insert_vlan_tag`).
    pub vlan_tag: Option<u16>,
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

/// Walk an RX aggregation buffer into its frames. Stops at the
/// first segment whose length field is implausible (< ETH_ZLEN,
/// or running past the buffer) — the stream cannot be resynced
/// past a bad descriptor.
pub fn parse_rx_aggregate(buf: &[u8]) -> Vec<RxSegment> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + RX_DESC_LEN <= buf.len() {
        let opts1 = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let opts2 = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let len = (opts1 & RX_LEN_MASK) as usize;
        if (len as u32) < RX_MIN_FRAME || off + RX_DESC_LEN + len > buf.len() {
            break;
        }
        out.push(RxSegment {
            offset: off + RX_DESC_LEN,
            len,
            vlan_tag: rx_vlan_tag_from_opts2(opts2),
        });
        off += RX_DESC_LEN + len;
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

/// Offloads this driver's send path honours, advertised to the
/// stack at bind via `iface::set_offloads` so `TxMeta` requests
/// arrive at all. `max_tso_bytes` is the descriptor's hard
/// length cap (`TX_LEN_MASK`); RX checksum metadata is not
/// advertised — the RX descriptor's fail bits have no delivery
/// channel in `on_rx_frame_from`.
pub fn r8152_offloads() -> narf_net::OffloadCapabilities {
    narf_net::OffloadCapabilities {
        tx_checksum: true,
        rx_checksum: false,
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

/// Find the vendor-specific (class 0xFF) interface's bulk pair in
/// a configuration-descriptor blob. Returns
/// `(bulk_in_ep, bulk_out_ep)` as xHCI endpoint configs.
pub fn find_rtl_endpoints(cfg: &[u8]) -> Option<(EndpointConfig, EndpointConfig)> {
    let mut i = 0usize;
    let mut in_vendor_iface = false;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
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
            if attrs & 0x03 == 2 {
                // Bulk endpoint.
                let is_in = ep_addr & 0x80 != 0;
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
        }
        i += len;
    }
    match (bulk_in, bulk_out) {
        (Some(i), Some(o)) => Some((i, o)),
        _ => None,
    }
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
    /// by the future suspend path.
    pub wol_opts: WolOpts,
    pub mac: [u8; 6],
    pub bulk_in_dci: u8,
    pub bulk_out_dci: u8,
    /// Assigned `narf_net::iface` name (`usb-rtl{N}`).
    pub iface_name: String,
    pub pump_running: bool,
    /// Last `PLA_PHYSTATUS` byte sampled (0xFF = never sampled).
    pub link_byte: u8,
    /// Detach tombstone: set by `detach_r8152_slot`. The pump
    /// exits when `pump_running` clears; TX resolves to `None`.
    /// Records are never removed, because net-registry TX
    /// cookies are record indices — removing a record would
    /// retarget every later device's cookie at the wrong
    /// device (the ECM/NCM rule).
    pub detached: bool,
}

/// System-wide registry of bound RTL devices.
pub static RTL_DEVICES: IrqSafeSpinLock<Vec<RtlDevice>> = IrqSafeSpinLock::new(Vec::new());

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
fn rtl_send_segment(slot_id: u8, bulk_out_dci: u8, seg: &[u8]) -> Result<(), ()> {
    let c = crate::xhci::controller().ok_or(())?;
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
    let (slot_id, bulk_out_dci) = tx_target(idx).ok_or(())?;
    let mut seg = Vec::new();
    if build_tx_segment_meta(frame, meta, &mut seg).is_ok() {
        return rtl_send_segment(slot_id, bulk_out_dci, &seg);
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
        rtl_send_segment(slot_id, bulk_out_dci, &seg)?;
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
async fn bind(device: Arc<USBDevice>) -> Result<usize, ()> {
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
            detached: false,
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
        match device.bulk_in(bulk_in_dci, &mut buf).await {
            Ok(n) if n > 0 => {
                errors = 0;
                let name = {
                    let g = RTL_DEVICES.lock();
                    g.get(idx).map(|d| d.iface_name.clone())
                };
                if let Some(name) = name {
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
                        narf_net::iface::on_rx_frame_from(&name, &mut frame);
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

fn probe(device: Arc<USBDevice>) -> Result<(), UsbProbeError> {
    // The registry probe is synchronous, but bind needs async
    // control transfers — spawn it (xpad precedent).
    narf_scheduler::spawn_stackful(async move {
        use core::fmt::Write;
        if bind(device).await.is_err() {
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
pub fn detach_r8152_slot(slot_id: u8) -> Result<(), ()> {
    let ifaces: Vec<String> = {
        let mut g = RTL_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g.iter_mut().filter(|d| d.slot_id == slot_id && !d.detached) {
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
/// RTL binding and unregister every net iface, regardless of
/// slot. Infallible and idempotent, same pump-exit and
/// never-remove reasoning as [`detach_r8152_slot`], and the
/// same #789 mirror verdict (no clear call owed).
pub fn detach_all_r8152() {
    let ifaces: Vec<String> = {
        let mut g = RTL_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g.iter_mut().filter(|d| !d.detached) {
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
        // Two valid frames then a runt descriptor: the walk must
        // yield exactly the two frames and stop at the runt.
        let f1 = datagram_frame(60, 0xA5);
        let f2 = datagram_frame(100, 0x3C);
        let mut buf = alloc::vec::Vec::new();
        let push_seg = |buf: &mut Vec<u8>, frame: &[u8]| {
            buf.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // opts1
            buf.extend_from_slice(&[0u8; 20]); // opts2..opts6
            buf.extend_from_slice(frame);
        };
        push_seg(&mut buf, &f1);
        push_seg(&mut buf, &f2);
        buf.extend_from_slice(&10u32.to_le_bytes()); // runt opts1
        buf.extend_from_slice(&[0u8; 20]);
        buf.extend_from_slice(&[0u8; 10]);
        let segs = parse_rx_aggregate(&buf);
        if segs.len() != 2 {
            return TestResult::Fail("aggregate walk yielded wrong frame count");
        }
        if segs[0]
            != (RxSegment {
                offset: RX_DESC_LEN,
                len: 60,
                vlan_tag: None,
            })
        {
            return TestResult::Fail("first segment location wrong");
        }
        if segs[1]
            != (RxSegment {
                offset: RX_DESC_LEN + 60 + RX_DESC_LEN,
                len: 100,
                vlan_tag: None,
            })
        {
            return TestResult::Fail("second segment location wrong");
        }
        if &buf[segs[0].offset..segs[0].offset + segs[0].len] != f1.as_slice()
            || &buf[segs[1].offset..segs[1].offset + segs[1].len] != f2.as_slice()
        {
            return TestResult::Fail("segment payload bytes wrong");
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
            detached: false,
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
            detached: false,
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
        if detach_r8152_slot(7).is_err() {
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
        let _ = detach_r8152_slot(7);
        let _ = detach_r8152_slot(99);
        if tx_target(1) != Some((9, 6)) {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("repeat/unknown detach must not change the registry");
        }
        detach_all_r8152();
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
        let _ = detach_r8152_slot(7);
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
                detached: false,
            });
        }
        register();
        let report = crate::class_registry::dispatch_unbind(7);
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
            detached: false,
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
        let report = crate::class_registry::dispatch_unbind(7);
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
        let _ = detach_r8152_slot(7);
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

    /// Modelled register file for the PHY-init conversation: PLA
    /// words, OCP PHY registers, SRAM cells, USB-window words and
    /// MDIO registers as small association lists. The executor
    /// mirrors the production op semantics (read-modify-write
    /// for set/clr-bits, two-step SRAM writes); the ALDPS poll
    /// is modelled as satisfied.
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
        let mut agg = alloc::vec::Vec::new();
        agg.extend_from_slice(&60u32.to_le_bytes()); // opts1: len
        agg.extend_from_slice(&(RX_VLAN_TAG_BIT | 0x6400).to_le_bytes()); // opts2
        agg.extend_from_slice(&[0u8; 16]); // opts3..opts6
        agg.extend_from_slice(&frame);
        let segs = parse_rx_aggregate(&agg);
        if segs.len() != 1 || segs[0].vlan_tag != Some(0x0064) {
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
}
