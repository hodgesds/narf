//! SMSC/Microchip LAN95xx USB 2.0 10/100 Ethernet driver — register-level.
//!
//! Core driver for the LAN9500 / LAN9500A / LAN9512 / LAN9514 /
//! LAN9530 / LAN9730 / LAN89530 family (issue #788, ASIX audit
//! item 3): probe + vendor control transport + lite reset + PHY
//! autoneg + EEPROM station address + TX/RX pumps + publication
//! as `usb-lan95xx{N}` + detach. 10/100 only, USB 2.0 — not gigabit.
//!
//! Issue #1552 (this lane's follow-up, now delivered): the
//! interrupt-endpoint link-change task republishes link metadata
//! when the cable state changes after bind, and multicast
//! programming (hash filter + `MAC_CR` receive-mode bits) is
//! wired to the stack's `DeviceControl` hook.
//!
//! ## Grounding (read before trusting a constant)
//!
//! Every register address, bit definition, and wire format below is
//! transcribed from Linux `drivers/net/usb/smsc95xx.c` / `smsc95xx.h`
//! @ cbbddb6 as a **driver-observed** value: no public LAN95xx
//! datasheet copy exists in this workspace, so no value here is
//! datasheet-verified. The audit's §5 GPL note is honoured by
//! re-deriving the framing as NARF's own data model (never copying
//! Linux function bodies) and by marking every Linux-observed
//! tunable as such. Two audit §6 items are RESOLVED by the Linux
//! source itself, not guessed:
//!
//! - Control-setup packing: `usbnet_read_cmd` / `usbnet_write_cmd`
//!   pass `wValue = 0`, `wIndex = register index`, 4-byte LE data
//!   (`smsc95xx.c:97` / `:131`). The audit's "ungrounded" packing
//!   question has this answer.
//! - `990x` device-ID mapping: the Linux device table comments map
//!   every `990x` PID to its chip (SAL10 / HAL / alternate-ID
//!   variants of 9500 / 9500A / 9512-9514). All bind to the same
//!   driver with no PID branching, so the full 0424 table is
//!   admitted. The two non-0424 PIDs (`0878:1400` SYSTEC T1L,
//!   `184F:0051` T1S EVB) are NOT admitted: their PHYs are not the
//!   internal 10/100 PHY this lane drives.
//!
//! ## Control transport
//!
//! Vendor device requests: `READ_REGISTER 0xA1` / `WRITE_REGISTER
//! 0xA0`, `wValue = 0`, `wIndex = register`, 4-byte little-endian
//! data stage, via `control::submit`.
//!
//! ## Datapath formats
//!
//! - **TX**: each bulk-OUT transfer is one 8-byte header (`tx_cmd_a`
//!   = length | `FIRST_SEG` | `LAST_SEG`, `tx_cmd_b` = length |
//!   optional `CSUM_ENABLE`) followed by the frame. With TX checksum
//!   offload the chip needs a 4-byte preamble between header and
//!   frame: `(csum_start + csum_offset) << 16 | csum_start`, and
//!   both command lengths grow by 4. The chip appends the FCS.
//!   `FLAG_SEND_ZLP` semantics (Linux `smsc95xx_info.flags`):
//!   a segment whose length is an exact multiple of the bulk-OUT
//!   maxpacket is followed by a zero-length transfer.
//! - **RX**: bulk-IN buffers carry back-to-back frames; each frame
//!   is a 4-byte status header (`RX_STS_FL_` length bits 16–29,
//!   `RX_STS_ES_` error summary) + 2-byte IP-alignment pad +
//!   frame bytes INCLUDING the FCS + padding to a 4-byte boundary
//!   (`(4 - ((size + 2) % 4)) % 4`). The pump strips the FCS and
//!   delivers the bare frame. `HW_CFG` RX data offset is programmed
//!   to 2 at reset (Linux: `NET_IP_ALIGN << 9`).
//!
//! ## Link-change + multicast (#1552, delivered)
//!
//! - The interrupt endpoint is armed at bind (4-byte status
//!   word, Linux `smsc95xx_status`: exactly 4 bytes, LE32,
//!   `INT_ENP_PHY_INT_` = bit 15). A PHY-interrupt event makes
//!   the status task re-read the PHY (BMSR twice, latched-low,
//!   then `PHY_SPECIAL`) and republish link metadata on change
//!   only — including a renegotiation that changes speed/duplex
//!   without dropping carrier. Non-PHY events and short
//!   transfers are ignored, exactly like the reference.
//! - The PHY interrupt sources are armed in reset via
//!   `PHY_INT_MASK` = `PHY_INT_MASK_DEFAULT` (autoneg-complete
//!   \+ link-down, Linux `smsc95xx.h`); without it the endpoint
//!   would never fire on real silicon. The handler acknowledges
//!   the PHY interrupt by reading `PHY_INT_SRC` (best-effort).
//! - Multicast is programmed through the stack's
//!   `DeviceControl` hook (Linux `smsc95xx_set_multicast`,
//!   `ndo_set_rx_mode`): promiscuous → `PRMS`, all-multicast
//!   → `MCPAS`, a non-empty list → hash table + `HPFILT`,
//!   empty → receive-own only. The `MAC_CR` shadow in the
//!   device record is the single tracked value both the
//!   multicast hook and the link-change path start from, so
//!   neither clobbers the other's bits (last writer wins on
//!   the shadow; a link event arriving mid-configure
//!   reconciles on the next event — the AX88179 pattern).
//! - Constant correction found by re-deriving against
//!   `smsc95xx.h` @ cbbddb6: the old `MAC_CR_HPFILT_` value
//!   `0x8000` is actually `MAC_CR_HFILT_` (hash-only
//!   filtering); the real `HPFILT` (hash/perfect filtering,
//!   the bit `smsc95xx_set_multicast` sets) is `0x2000`.
//!   The reset-time receive-own clear previously cleared the
//!   wrong bit; it now clears the right one.
//!
//! ## Scope limits (honest)
//!
//! - Station address comes from EEPROM only (offset `0x01`, 6
//!   bytes). A device reporting no valid address fails the bind —
//!   no address is ever invented (USB-Ethernet contract). The
//!   EEPROM-less MAC fallback is audit item 4, not this lane.
//! - External PHY (`HW_CFG_PSEL_` set) fails the bind: only the
//!   internal PHY (id 1) is driven.
//! - RX checksum offload is NOT enabled: NARF's USB RX path
//!   (`on_rx_frame_from` takes bare bytes) has no verdict channel,
//!   so `rx_checksum: false` is the honest advertisement and
//!   csum-error frames keep being delivered for stack revalidation
//!   (same position as r8152 / AX88179). TX checksum IS honoured:
//!   the preamble is computed from the parsed frame, and a csum
//!   request the hardware cannot encode is rejected, never sent
//!   with a partial offload.
//! - No TSO, no VLAN insert/strip (both rejected on the TX path).
//! - No suspend/WoL (audit item 5, matches the r8152 remainders
//!   pattern). No hub-combo verification yet: LAN9512/9514's
//!   Ethernet function sits behind its internal hub, and while
//!   class matching by VID/PID is depth-independent, real-hardware
//!   enumeration through the internal hub is audit item 4.
//! - `BURST_CAP` / `BULK_IN_DLY` tunables are Linux-observed
//!   values (audit §5 flags them as empirically derived); they
//!   are transcribed, not re-derived, and marked as such.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::class_registry::{register_class_driver_with_unbind, UsbClassMatch, UsbProbeError};
use crate::control;
use crate::device::USBDevice;
use crate::xhci::{EndpointConfig, EndpointKind, PortSpeed};

// ── Register map (Linux smsc95xx.h @ cbbddb6, driver-observed) ──

/// Device ID and revision.
pub const ID_REV: u16 = 0x00;
/// Interrupt status.
pub const INT_STS: u16 = 0x08;
/// Receive configuration (FIFO flush).
pub const RX_CFG: u16 = 0x0C;
/// Transmit configuration.
pub const TX_CFG: u16 = 0x10;
/// Hardware configuration.
pub const HW_CFG: u16 = 0x14;
/// Receive FIFO information (unused here, kept for the map).
pub const RX_FIFO_INF: u16 = 0x18;
/// Transmit FIFO information (unused here, kept for the map).
pub const TX_FIFO_INF: u16 = 0x1C;
/// Power management control (unused here, kept for the map).
pub const PM_CTRL: u16 = 0x20;
/// LED / GPIO configuration.
pub const LED_GPIO_CFG: u16 = 0x24;
/// EEPROM command.
pub const E2P_CMD: u16 = 0x30;
/// EEPROM data.
pub const E2P_DATA: u16 = 0x34;
/// Burst cap.
pub const BURST_CAP: u16 = 0x38;
/// Configuration straps status (unused here, kept for the map).
pub const STRAP_STATUS: u16 = 0x3C;
/// Interrupt endpoint control.
pub const INT_EP_CTL: u16 = 0x68;
/// Bulk-IN delay.
pub const BULK_IN_DLY: u16 = 0x6C;
/// MAC control.
pub const MAC_CR: u16 = 0x100;
/// MAC address high.
pub const ADDRH: u16 = 0x104;
/// MAC address low.
pub const ADDRL: u16 = 0x108;
/// Multicast hash table high.
pub const HASHH: u16 = 0x10C;
/// Multicast hash table low.
pub const HASHL: u16 = 0x110;
/// MII access.
pub const MII_ADDR: u16 = 0x114;
/// MII data.
pub const MII_DATA: u16 = 0x118;
/// Flow control.
pub const FLOW: u16 = 0x11C;
/// VLAN1 tag.
pub const VLAN1: u16 = 0x120;
/// Checksum offload engine control.
pub const COE_CR: u16 = 0x130;

// HW_CFG bits.
pub const HW_CFG_LRST_: u32 = 0x0000_0008;
pub const HW_CFG_PSEL_: u32 = 0x0000_0004;
pub const HW_CFG_BCE_: u32 = 0x0000_0002;
pub const HW_CFG_MEF_: u32 = 0x0000_0020;
pub const HW_CFG_BIR_: u32 = 0x0000_1000;
/// RX data offset field (bits 10:9); programmed to 2 (IP align).
pub const HW_CFG_RXDOFF_: u32 = 0x0000_0600;

// INT_STS bits.
pub const INT_STS_CLEAR_ALL_: u32 = 0xFFFF_FFFF;

// LED_GPIO_CFG bits.
pub const LED_GPIO_CFG_SPD_LED: u32 = 0x0100_0000;
pub const LED_GPIO_CFG_LNK_LED: u32 = 0x0010_0000;
pub const LED_GPIO_CFG_FDX_LED: u32 = 0x0001_0000;

// E2P_CMD bits.
pub const E2P_CMD_BUSY_: u32 = 0x8000_0000;
pub const E2P_CMD_READ_: u32 = 0x0000_0000;
pub const E2P_CMD_TIMEOUT_: u32 = 0x0000_0400;
pub const E2P_CMD_ADDR_: u32 = 0x0000_01FF;
/// EEPROM byte offset of the station address (Linux `EEPROM_MAC_OFFSET`).
pub const EEPROM_MAC_OFFSET: u32 = 0x01;

// INT_EP_CTL bits.
pub const INT_EP_CTL_PHY_INT_: u32 = 0x0000_8000;

/// PHY-interrupt bit in the interrupt-endpoint status word
/// (Linux `INT_ENP_PHY_INT_`, `BIT(15)` — the same value as
/// `INT_STS_PHY_INT_` / `INT_EP_CTL_PHY_INT_`).
pub const INT_ENP_PHY_INT_: u32 = 0x0000_8000;

/// Interrupt-endpoint transfer length (Linux
/// `smsc95xx_status`: any length other than 4 bytes is
/// unexpected and ignored).
pub const INT_STATUS_LEN: usize = 4;

// TX_CFG bits.
pub const TX_CFG_ON_: u32 = 0x0000_0004;

// MAC_CR bits.
pub const MAC_CR_PRMS_: u32 = 0x0004_0000;
pub const MAC_CR_MCPAS_: u32 = 0x0008_0000;
/// Hash/perfect filtering mode (Linux `MAC_CR_HPFILT_`,
/// `0x2000` — the bit `smsc95xx_set_multicast` sets for a
/// filtered list). NOTE: an earlier revision of this file had
/// `0x8000` here; that value is `MAC_CR_HFILT_` (hash-only
/// filtering), not `HPFILT` — corrected against `smsc95xx.h`
/// @ cbbddb6 in #1552.
pub const MAC_CR_HPFILT_: u32 = 0x0000_2000;
/// Hash-only filtering mode (Linux `MAC_CR_HFILT_`).
pub const MAC_CR_HFILT_: u32 = 0x0000_8000;
/// Receive-own control (Linux `MAC_CR_RCVOWN_`): set in
/// half duplex, clear in full duplex
/// (`smsc95xx_mac_update_fullduplex`).
pub const MAC_CR_RCVOWN_: u32 = 0x0080_0000;
pub const MAC_CR_FDPX_: u32 = 0x0010_0000;
pub const MAC_CR_TXEN_: u32 = 0x0000_0008;
pub const MAC_CR_RXEN_: u32 = 0x0000_0004;

// COE_CR bits.
pub const COE_TX_EN_: u32 = 0x0001_0000;
pub const COE_RX_EN_: u32 = 0x0000_0001;

// MII access bits.
pub const MII_WRITE_: u32 = 0x02;
pub const MII_BUSY_: u32 = 0x01;

/// Auto flow-control configuration register.
pub const AFC_CFG: u16 = 0x2C;
// AFC_CFG default (Linux `AFC_CFG_DEFAULT`; flow-control watermarks
// + "apply FC on any frame" — a Linux-observed tunable).
pub const AFC_CFG_DEFAULT: u32 = 0x00F8_30A1;

// Vendor requests.
pub const USB_VENDOR_REQUEST_WRITE_REGISTER: u8 = 0xA0;
pub const USB_VENDOR_REQUEST_READ_REGISTER: u8 = 0xA1;

// TX command words.
pub const TX_CMD_A_FIRST_SEG_: u32 = 0x0000_2000;
pub const TX_CMD_A_LAST_SEG_: u32 = 0x0000_1000;
pub const TX_CMD_B_CSUM_ENABLE: u32 = 0x0000_4000;

// RX status word.
pub const RX_STS_FL_: u32 = 0x3FFF_0000;
pub const RX_STS_ES_: u32 = 0x0000_8000;

// PHY (Clause 22) registers + bits.
pub const PHY_BMCR: u16 = 0;
pub const PHY_BMSR: u16 = 1;
pub const PHY_ANAR: u16 = 4;
pub const PHY_SPECIAL: u16 = 31;
/// Internal PHY id (Linux `SMSC95XX_INTERNAL_PHY_ID`).
pub const INTERNAL_PHY_ID: u16 = 1;
pub const BMCR_ANEN: u16 = 0x1000;
pub const BMCR_RSTAN: u16 = 0x0200;
pub const BMSR_AN_COMP: u16 = 0x0020;
pub const BMSR_LINK: u16 = 0x0004;
/// 10/100 half/full + 802.3 selector, plus symmetric + asymmetric
/// pause (Linux binds with pause_tx/pause_rx/asym-pause on).
pub const ANAR_ADVERTISE: u16 = 0x0DE1;
pub const PHY_SPECIAL_SPD_: u16 = 0x001C;
pub const PHY_SPECIAL_SPD_10HALF: u16 = 0x0004;
pub const PHY_SPECIAL_SPD_10FULL: u16 = 0x0014;
pub const PHY_SPECIAL_SPD_100HALF: u16 = 0x0008;
pub const PHY_SPECIAL_SPD_100FULL: u16 = 0x0018;

// PHY interrupt source / mask registers (Linux `smsc95xx.h`).
/// Interrupt source (read to acknowledge the PHY interrupt).
pub const PHY_INT_SRC: u16 = 29;
/// Interrupt mask.
pub const PHY_INT_MASK: u16 = 30;
pub const PHY_INT_MASK_ENERGY_ON_: u16 = 0x0080;
pub const PHY_INT_MASK_ANEG_COMP_: u16 = 0x0040;
pub const PHY_INT_MASK_REMOTE_FAULT_: u16 = 0x0020;
pub const PHY_INT_MASK_LINK_DOWN_: u16 = 0x0010;
/// Mask programmed at reset so the PHY raises an interrupt on
/// autoneg completion and on link-down (Linux
/// `PHY_INT_MASK_DEFAULT_`).
pub const PHY_INT_MASK_DEFAULT: u16 = PHY_INT_MASK_ANEG_COMP_ | PHY_INT_MASK_LINK_DOWN_;

// Burst / bulk-IN tuning (Linux-observed tunables, see module docs).
/// High-speed burst cap in USB packets: (16 KiB + 5*512) / 512.
pub const HS_BURST_CAP: u32 = 37;
/// Full-speed burst cap in USB packets: (6 KiB + 33*64) / 64.
pub const FS_BURST_CAP: u32 = 129;
/// High-speed RX buffer: 16 KiB + 5*512.
pub const HS_RX_BUF_LEN: usize = 16 * 1024 + 5 * 512;
/// Full-speed RX buffer: 6 KiB + 33*64.
pub const FS_RX_BUF_LEN: usize = 6 * 1024 + 33 * 64;
/// Bulk-IN delay (Linux `DEFAULT_BULK_IN_DELAY`).
pub const BULK_IN_DELAY: u32 = 0x0000_2000;

// Poll bounds (cooperative yields, never busy spins).
/// Lite-reset poll iterations (mirrors Linux's 100 x 10 ms).
pub const LRST_POLL_ITERS: usize = 100;
/// EEPROM / MII busy-poll iterations (Linux waits up to ~1 s).
pub const BUSY_POLL_ITERS: usize = 1000;
/// Autoneg-complete poll iterations.
pub const ANEG_POLL_ITERS: usize = 200;

/// Largest frame the TX path accepts (standard max frame; the chip
/// appends the FCS). Jumbo frames are a remainder, not silently
/// truncated.
pub const MAX_TX_FRAME_LEN: usize = 1518;
/// Largest RX status length accepted with COE off (1518 + FCS).
/// A larger length field is bogus: parsing stops (fail-closed).
pub const MAX_RX_STATUS_LEN: usize = 1522;
/// RX data offset: status header (4) + IP-alignment pad (2).
pub const RX_HEADER_LEN: usize = 6;

/// Chip identity from `ID_REV` bits 31:16 (Linux `ID_REV_CHIP_ID_*`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipId {
    Lan9500,
    Lan9500A,
    Lan9512,
    Lan9530,
    Lan89530,
    Lan9730,
    Unknown(u16),
}

pub fn chip_id_from_id_rev(id_rev: u32) -> ChipId {
    match (id_rev >> 16) as u16 {
        0x9500 => ChipId::Lan9500,
        0x9E00 => ChipId::Lan9500A,
        0xEC00 => ChipId::Lan9512,
        0x9530 => ChipId::Lan9530,
        0x9E08 => ChipId::Lan89530,
        0x9730 => ChipId::Lan9730,
        other => ChipId::Unknown(other),
    }
}

// ── Pure helpers (fixture-pinned) ─────────────────────────────────

/// SETUP packing for a register read: vendor IN `0xA1`,
/// `wValue = 0`, `wIndex = register` (resolved audit §6 item).
pub fn read_reg_setup(reg: u16) -> (u8, u8, u16, u16) {
    (0xC0, USB_VENDOR_REQUEST_READ_REGISTER, 0, reg)
}

/// SETUP packing for a register write: vendor OUT `0xA0`,
/// `wValue = 0`, `wIndex = register`.
pub fn write_reg_setup(reg: u16) -> (u8, u8, u16, u16) {
    (0x40, USB_VENDOR_REQUEST_WRITE_REGISTER, 0, reg)
}

/// MII access-register command word (Linux `mii_address_cmd`):
/// phy id bits 15:11, register bits 10:6, write bit 1. The BUSY bit
/// is OR'd by the caller at the access itself.
pub fn mii_address_cmd(phy_id: u16, idx: u16, write: bool) -> u32 {
    ((phy_id & 0x1F) as u32) << 11 | ((idx & 0x1F) as u32) << 6 | if write { MII_WRITE_ } else { 0 }
}

/// Ethernet CRC used by the multicast hash: `bitrev32(crc32_le(~0,
/// addr))` (Linux `ether_crc`). Bitwise implementation — no table
/// to mistranscribe. Pinned by the Linux-documented example:
/// `01:00:5E:00:00:01` hashes to bit 31.
pub fn ether_crc(addr: &[u8; 6]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in addr.iter() {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc.reverse_bits()
}

/// Multicast hash bit number (Linux `smsc95xx_hash`).
pub fn multicast_hash(addr: &[u8; 6]) -> u32 {
    (ether_crc(addr) >> 26) & 0x3F
}

/// Split a set of multicast addresses into the `(HASHH, HASHL)`
/// words (Linux `smsc95xx_set_multicast`): bit >= 32 goes to the
/// high word at `bit - 32`, else to the low word.
pub fn hash_words(addrs: &[[u8; 6]]) -> (u32, u32) {
    let mut hi = 0u32;
    let mut lo = 0u32;
    for addr in addrs {
        let bit = multicast_hash(addr);
        if bit & 0x20 != 0 {
            hi |= 1 << (bit & 0x1F);
        } else {
            lo |= 1 << (bit & 0x1F);
        }
    }
    (hi, lo)
}

// ── Link-change pure helpers (#1552) ────────────────────────────

/// Published link state: carrier + negotiated mode (`None`
/// speed/duplex = carrier known, mode unknown — e.g. the PHY
/// reports link but `PHY_SPECIAL` decodes to nothing).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinkState {
    pub up: bool,
    pub speed: Option<u32>,
    pub duplex: Option<narf_net::iface::LinkDuplex>,
}

/// Decode one interrupt-endpoint transfer (Linux
/// `smsc95xx_status`): the event is exactly one 4-byte
/// little-endian status word; `true` iff its PHY-interrupt bit
/// is set. Short transfers, long transfers, and words without
/// the PHY bit are not link events — the reference warns and
/// ignores them, and so does this.
pub fn lan95xx_interrupt_phy(buf: &[u8]) -> bool {
    if buf.len() != INT_STATUS_LEN {
        return false;
    }
    let intdata = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    intdata & INT_ENP_PHY_INT_ != 0
}

/// Link-change decision from a fresh PHY sample: carrier plus
/// the decoded speed/duplex (`phy_link_status` already applied
/// the latched-low BMSR double-read and the `PHY_SPECIAL`
/// decode). Returns the new [`LinkState`] iff it differs from
/// the last published state, else `None` (no republish). A
/// renegotiation that changes speed/duplex without dropping
/// carrier is a change; a duplicate interrupt for an unchanged
/// state is not. A down state never carries a mode, even if
/// the caller passes one.
pub fn link_change_decision(
    prev: &LinkState,
    up: bool,
    speed: Option<u32>,
    duplex: Option<narf_net::iface::LinkDuplex>,
) -> Option<LinkState> {
    let next = LinkState {
        up,
        speed: if up { speed } else { None },
        duplex: if up { duplex } else { None },
    };
    if next == *prev {
        None
    } else {
        Some(next)
    }
}

/// MAC control for a negotiated duplex (Linux
/// `smsc95xx_mac_update_fullduplex`): full duplex sets `FDPX`
/// and clears `RCVOWN`; half duplex clears `FDPX` and sets
/// `RCVOWN`. Every other bit — including the multicast
/// receive-mode bits — is preserved, so the link-change path
/// and the multicast hook never clobber each other.
pub fn mac_cr_for_duplex(mac_cr: u32, duplex: narf_net::iface::LinkDuplex) -> u32 {
    use narf_net::iface::LinkDuplex;
    match duplex {
        LinkDuplex::Full => (mac_cr | MAC_CR_FDPX_) & !MAC_CR_RCVOWN_,
        LinkDuplex::Half => (mac_cr & !MAC_CR_FDPX_) | MAC_CR_RCVOWN_,
    }
}

// ── Multicast pure helper (#1552) ───────────────────────────────

/// Result of programming the multicast filter: the `MAC_CR`
/// value to write plus the `(HASHH, HASHL)` words.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MulticastProgram {
    pub mac_cr: u32,
    pub hash_hi: u32,
    pub hash_lo: u32,
}

/// Multicast programming (Linux `smsc95xx_set_multicast`,
/// exact branch order — promiscuous wins over all-multicast,
/// which wins over a filtered list): promiscuous sets `PRMS`
/// and clears `MCPAS`/`HPFILT`; all-multicast sets `MCPAS`
/// and clears `PRMS`/`HPFILT`; a non-empty list sets
/// `HPFILT`, clears `PRMS`/`MCPAS`, and fills the hash table
/// from the addresses; an empty list clears all three and
/// leaves the hash table empty (receive-own only). The hash
/// table is zeroed in every branch — Linux writes `HASHH` /
/// `HASHL` unconditionally. All other `MAC_CR` bits
/// (`FDPX`/`RCVOWN`/`TXEN`/`RXEN`) are preserved.
pub fn lan95xx_multicast_program(
    mac_cr: u32,
    promiscuous: bool,
    all_multicast: bool,
    addrs: &[[u8; 6]],
) -> MulticastProgram {
    if promiscuous {
        MulticastProgram {
            mac_cr: (mac_cr | MAC_CR_PRMS_) & !(MAC_CR_MCPAS_ | MAC_CR_HPFILT_),
            hash_hi: 0,
            hash_lo: 0,
        }
    } else if all_multicast {
        MulticastProgram {
            mac_cr: (mac_cr | MAC_CR_MCPAS_) & !(MAC_CR_PRMS_ | MAC_CR_HPFILT_),
            hash_hi: 0,
            hash_lo: 0,
        }
    } else if !addrs.is_empty() {
        let (hash_hi, hash_lo) = hash_words(addrs);
        MulticastProgram {
            mac_cr: (mac_cr | MAC_CR_HPFILT_) & !(MAC_CR_PRMS_ | MAC_CR_MCPAS_),
            hash_hi,
            hash_lo,
        }
    } else {
        MulticastProgram {
            mac_cr: mac_cr & !(MAC_CR_PRMS_ | MAC_CR_MCPAS_ | MAC_CR_HPFILT_),
            hash_hi: 0,
            hash_lo: 0,
        }
    }
}

/// Station-address validity (USB-Ethernet contract): non-zero,
/// non-broadcast, unicast (multicast bit clear).
pub fn mac_valid(mac: &[u8; 6]) -> bool {
    if mac.iter().all(|&b| b == 0) || mac.iter().all(|&b| b == 0xFF) {
        return false;
    }
    mac[0] & 1 == 0
}

/// Decode a `PHY_SPECIAL` value into `(speed_mbps, duplex)`.
/// Unknown encodings yield `(None, None)` — never a guessed speed.
pub fn decode_phy_special(v: u16) -> (Option<u32>, Option<narf_net::iface::LinkDuplex>) {
    use narf_net::iface::LinkDuplex;
    match v & PHY_SPECIAL_SPD_ {
        PHY_SPECIAL_SPD_10HALF => (Some(10), Some(LinkDuplex::Half)),
        PHY_SPECIAL_SPD_10FULL => (Some(10), Some(LinkDuplex::Full)),
        PHY_SPECIAL_SPD_100HALF => (Some(100), Some(LinkDuplex::Half)),
        PHY_SPECIAL_SPD_100FULL => (Some(100), Some(LinkDuplex::Full)),
        _ => (None, None),
    }
}

/// Locate the L4 checksum field in an Ethernet frame for TX
/// checksum offload. Returns `(csum_start, csum_offset)` — the
/// transport-header offset and the checksum field's offset within
/// it (TCP 16, UDP 6). IPv4 (IHL-parsed) and IPv6 without extension
/// headers only; anything else is rejected, never approximated.
pub fn l4_csum_location(frame: &[u8], proto: u8) -> Result<(u16, u16), ()> {
    if frame.len() < 14 {
        return Err(());
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let (l4_start, csum_off) = match ethertype {
        0x0800 => {
            // IPv4: IHL in 32-bit words.
            if frame.len() < 34 {
                return Err(());
            }
            let ihl = ((frame[14] & 0x0F) as usize) * 4;
            if ihl < 20 || frame.len() < 14 + ihl + 8 {
                return Err(());
            }
            if frame[14 + 9] != proto {
                return Err(());
            }
            (14 + ihl, if proto == 6 { 16 } else { 6 })
        }
        0x86DD => {
            // IPv6, no extension headers: next-header must be the
            // transport protocol directly.
            if frame.len() < 54 {
                return Err(());
            }
            if frame[14 + 6] != proto {
                return Err(());
            }
            (14 + 40, if proto == 6 { 16 } else { 6 })
        }
        _ => return Err(()),
    };
    let csum_start = l4_start as u16;
    let csum_offset = csum_off as u16;
    if l4_start + csum_off as usize + 2 > frame.len() {
        return Err(());
    }
    Ok((csum_start, csum_offset))
}

/// Linux `smsc95xx_can_tx_checksum`: the hardware TX checksum
/// does not work properly with extremely small packets.
pub fn can_tx_checksum(frame_len: usize, csum_start: usize, csum_offset: usize) -> bool {
    if frame_len <= 45 {
        return false;
    }
    let Some(len) = frame_len.checked_sub(csum_start) else {
        return false;
    };
    csum_offset < len.saturating_sub(5)
}

/// TX checksum preamble (Linux `smsc95xx_calc_csum_preamble`).
pub fn csum_preamble(csum_start: u16, csum_offset: u16) -> u32 {
    (((csum_start + csum_offset) as u32) << 16) | csum_start as u32
}

/// Build the TX command words for a frame. `csum` carries
/// `(csum_start, csum_offset)` when TX checksum offload applies;
/// the lengths then include the 4-byte preamble.
pub fn tx_cmd_words(frame_len: usize, csum: Option<(u16, u16)>) -> (u32, u32) {
    let extra = if csum.is_some() { 4 } else { 0 };
    let len = (frame_len + extra) as u32;
    let a = len | TX_CMD_A_FIRST_SEG_ | TX_CMD_A_LAST_SEG_;
    let b = if csum.is_some() {
        len | TX_CMD_B_CSUM_ENABLE
    } else {
        len
    };
    (a, b)
}

/// Build one TX segment: 8-byte header + optional 4-byte checksum
/// preamble + frame. Rejects TSO, VLAN insert, SCTP checksums, and
/// any csum request the hardware cannot encode (unparseable frame
/// or the small-packet gate) — never sent with a partial offload.
pub fn build_tx_segment(frame: &[u8], meta: narf_net::TxMeta) -> Result<Vec<u8>, ()> {
    if meta.tso_mss.is_some() || meta.vlan_tag.is_some() {
        return Err(());
    }
    if frame.len() > MAX_TX_FRAME_LEN {
        return Err(());
    }
    let csum = match meta.csum_l4 {
        None => None,
        Some(narf_net::L4CsumKind::Tcp) => {
            let (start, off) = l4_csum_location(frame, 6)?;
            if !can_tx_checksum(frame.len(), start as usize, off as usize) {
                return Err(());
            }
            Some((start, off))
        }
        Some(narf_net::L4CsumKind::Udp) => {
            let (start, off) = l4_csum_location(frame, 17)?;
            if !can_tx_checksum(frame.len(), start as usize, off as usize) {
                return Err(());
            }
            Some((start, off))
        }
        Some(narf_net::L4CsumKind::Sctp) => return Err(()),
    };
    let (a, b) = tx_cmd_words(frame.len(), csum);
    let mut seg = Vec::new();
    seg.extend_from_slice(&a.to_le_bytes());
    seg.extend_from_slice(&b.to_le_bytes());
    if let Some((start, off)) = csum {
        seg.extend_from_slice(&csum_preamble(start, off).to_le_bytes());
    }
    seg.extend_from_slice(frame);
    Ok(seg)
}

/// Whether a TX segment needs a trailing zero-length transfer
/// (Linux `FLAG_SEND_ZLP`): exactly when its length is a multiple
/// of the bulk-OUT maxpacket.
pub fn needs_zlp(seg_len: usize, out_max_packet: u16) -> bool {
    let mp = out_max_packet as usize;
    mp != 0 && seg_len % mp == 0
}

/// One good frame found by the RX aggregate walk: byte range
/// `[offset, offset + len)` in the bulk buffer, FCS already
/// excluded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxFrame {
    pub offset: usize,
    pub len: usize,
}

/// Result of walking one bulk-IN aggregation buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RxWalk {
    pub frames: Vec<RxFrame>,
    pub dropped: usize,
}

/// Walk a bulk-IN aggregation buffer (Linux `smsc95xx_rx_fixup`
/// shape): per frame, 4-byte status header + 2-byte pad + frame
/// bytes including FCS + padding to a 4-byte boundary. Error-
/// summary frames are counted and skipped; a bogus length field
/// or a truncated tail stops the walk (fail-closed: the rest of
/// the buffer cannot be resynchronised). The last frame in the
/// buffer carries no trailing padding.
pub fn parse_rx_aggregate(buf: &[u8]) -> RxWalk {
    let mut walk = RxWalk::default();
    let mut i = 0usize;
    while i + RX_HEADER_LEN <= buf.len() {
        let header = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let size = ((header & RX_STS_FL_) >> 16) as usize;
        let align = (4 - ((size + 2) % 4)) % 4;
        let rest = buf.len() - i - RX_HEADER_LEN;
        // size includes the 4-byte FCS and must fit the remainder.
        if !(4..=MAX_RX_STATUS_LEN).contains(&size) || size > rest {
            break;
        }
        if header & RX_STS_ES_ != 0 {
            walk.dropped += 1;
        } else {
            walk.frames.push(RxFrame {
                offset: i + RX_HEADER_LEN,
                len: size - 4,
            });
        }
        i += RX_HEADER_LEN + size;
        if rest == size {
            break; // Last frame: no trailing padding.
        }
        i += align;
    }
    walk
}

/// Find the bulk pair in a configuration-descriptor blob: the
/// first interface that yields both a bulk-IN and a bulk-OUT
/// endpoint. Class filtering is deliberately NOT applied: the
/// VID/PID match already identifies the device, and the smsc
/// config carries a single vendor interface, so a class gate
/// adds no safety and could only brick the bind.
pub fn find_smsc_endpoints(cfg: &[u8]) -> Option<(EndpointConfig, EndpointConfig)> {
    let mut i = 0usize;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x05 && len >= 7 {
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF;
            if attrs & 0x03 == 2 {
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

/// Find the interrupt-IN endpoint in a configuration-descriptor
/// blob: the interrupt endpoint the link-change status task
/// arms (4-byte status word, `INT_ENP_PHY_INT_`). Same
/// descriptor walk as [`find_smsc_endpoints`] — a separate
/// finder, not a second walk shape — and the same no-class-gate
/// rule: the VID/PID match already identifies the device.
/// `None` when the device exposes no interrupt endpoint; the
/// device still binds, it just gets no status task (the
/// AX88179 shape).
pub fn find_smsc_interrupt_endpoint(cfg: &[u8]) -> Option<EndpointConfig> {
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x05 && len >= 7 {
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF;
            if attrs & 0x03 == 3 && ep_addr & 0x80 != 0 {
                return Some(EndpointConfig {
                    ep_addr,
                    max_packet,
                    kind: EndpointKind::InterruptIn,
                    interval: cfg[i + 6],
                });
            }
        }
        i += len;
    }
    None
}

// ── Async device operations ─────────────────────────────────────

/// Read a 32-bit register: vendor IN `0xA1`, `wValue = 0`,
/// `wIndex = register`, 4-byte LE data stage.
async fn reg_read(dev: &USBDevice, reg: u16) -> Result<u32, ()> {
    let setup = control::vendor_read(USB_VENDOR_REQUEST_READ_REGISTER, 0, reg, 4);
    let mut buf = [0u8; 4];
    let n = control::submit(dev, setup, &mut buf)
        .await
        .map_err(|_| ())?;
    if n != 4 {
        return Err(());
    }
    Ok(u32::from_le_bytes(buf))
}

/// Write a 32-bit register: vendor OUT `0xA0`, `wValue = 0`,
/// `wIndex = register`, 4-byte LE data stage.
async fn reg_write(dev: &USBDevice, reg: u16, val: u32) -> Result<(), ()> {
    let setup = control::vendor_write(USB_VENDOR_REQUEST_WRITE_REGISTER, 0, reg, 4);
    let mut buf = val.to_le_bytes();
    control::submit(dev, setup, &mut buf)
        .await
        .map_err(|_| ())?;
    Ok(())
}

/// Poll a register until `mask` clears (or `iters` yields pass).
/// Returns the last value read; the caller decides whether the
/// outcome is acceptable.
async fn poll_reg_clear(dev: &USBDevice, reg: u16, mask: u32, iters: usize) -> Result<u32, ()> {
    let mut val = 0u32;
    for _ in 0..iters {
        val = reg_read(dev, reg).await?;
        if val & mask == 0 {
            break;
        }
        narf_scheduler::yield_now().await;
    }
    Ok(val)
}

/// Confirm the EEPROM controller is not busy (Linux
/// `smsc95xx_eeprom_confirm_not_busy`).
async fn eeprom_confirm_not_busy(dev: &USBDevice) -> Result<(), ()> {
    let val = poll_reg_clear(dev, E2P_CMD, E2P_CMD_BUSY_, BUSY_POLL_ITERS).await?;
    if val & E2P_CMD_BUSY_ != 0 {
        return Err(());
    }
    Ok(())
}

/// Wait for an EEPROM operation to complete (Linux
/// `smsc95xx_wait_eeprom`): busy clear, or the timeout bit set
/// (which is itself a failure).
async fn wait_eeprom(dev: &USBDevice) -> Result<(), ()> {
    let mut val = 0u32;
    for _ in 0..BUSY_POLL_ITERS {
        val = reg_read(dev, E2P_CMD).await?;
        if val & E2P_CMD_BUSY_ == 0 || val & E2P_CMD_TIMEOUT_ != 0 {
            break;
        }
        narf_scheduler::yield_now().await;
    }
    if val & (E2P_CMD_TIMEOUT_ | E2P_CMD_BUSY_) != 0 {
        return Err(());
    }
    Ok(())
}

/// Read `len` EEPROM bytes starting at `offset` (Linux
/// `smsc95xx_read_eeprom`): one BUSY|READ command per byte, then
/// the low byte of `E2P_DATA`.
async fn read_eeprom(dev: &USBDevice, offset: u32, out: &mut [u8]) -> Result<(), ()> {
    eeprom_confirm_not_busy(dev).await?;
    let mut addr = offset;
    for slot in out.iter_mut() {
        let cmd = E2P_CMD_BUSY_ | E2P_CMD_READ_ | (addr & E2P_CMD_ADDR_);
        reg_write(dev, E2P_CMD, cmd).await?;
        wait_eeprom(dev).await?;
        let val = reg_read(dev, E2P_DATA).await?;
        *slot = (val & 0xFF) as u8;
        addr += 1;
    }
    Ok(())
}

/// Read the station address from EEPROM (offset `0x01`, 6 bytes)
/// and validate it. Failure here fails the bind: no address is
/// ever invented, and the EEPROM-less fallback is audit item 4.
async fn read_station_address(dev: &USBDevice) -> Result<[u8; 6], ()> {
    let mut mac = [0u8; 6];
    read_eeprom(dev, EEPROM_MAC_OFFSET, &mut mac).await?;
    if !mac_valid(&mac) {
        return Err(());
    }
    Ok(mac)
}

/// Wait until the MII access register reports not-busy (Linux
/// `smsc95xx_phy_wait_not_busy`).
async fn phy_wait_not_busy(dev: &USBDevice) -> Result<(), ()> {
    let val = poll_reg_clear(dev, MII_ADDR, MII_BUSY_, BUSY_POLL_ITERS).await?;
    if val & MII_BUSY_ != 0 {
        return Err(());
    }
    Ok(())
}

/// Clause-22 MDIO read via `MII_ADDR` / `MII_DATA` (Linux
/// `smsc95xx_mdio_read`).
async fn mdio_read(dev: &USBDevice, phy_id: u16, idx: u16) -> Result<u16, ()> {
    phy_wait_not_busy(dev).await?;
    let addr = mii_address_cmd(phy_id, idx, false) | MII_BUSY_;
    reg_write(dev, MII_ADDR, addr).await?;
    phy_wait_not_busy(dev).await?;
    let val = reg_read(dev, MII_DATA).await?;
    Ok((val & 0xFFFF) as u16)
}

/// Clause-22 MDIO write via `MII_ADDR` / `MII_DATA` (Linux
/// `smsc95xx_mdio_write`).
async fn mdio_write(dev: &USBDevice, phy_id: u16, idx: u16, val: u16) -> Result<(), ()> {
    phy_wait_not_busy(dev).await?;
    reg_write(dev, MII_DATA, val as u32).await?;
    let addr = mii_address_cmd(phy_id, idx, true) | MII_BUSY_;
    reg_write(dev, MII_ADDR, addr).await?;
    phy_wait_not_busy(dev).await?;
    Ok(())
}

/// Current PHY link state without touching autoneg: read the
/// (latched-low) BMSR link bit twice and decode `PHY_SPECIAL`
/// for speed/duplex (Linux `smsc95xx_link_ok` shape). The
/// link-change task calls this on every PHY interrupt; the
/// bind-time `phy_link` calls it after autoneg completes.
/// A down link yields `(false, None, None)`; an up link with
/// an undecodable `PHY_SPECIAL` yields `(true, None, None)`
/// — carrier known, mode unknown.
async fn phy_link_status(
    dev: &USBDevice,
) -> Result<(bool, Option<u32>, Option<narf_net::iface::LinkDuplex>), ()> {
    // BMSR link bit is latched-low: the second read is the truth.
    let _ = mdio_read(dev, INTERNAL_PHY_ID, PHY_BMSR).await?;
    let bmsr = mdio_read(dev, INTERNAL_PHY_ID, PHY_BMSR).await?;
    if bmsr & BMSR_LINK == 0 {
        return Ok((false, None, None));
    }
    let special = mdio_read(dev, INTERNAL_PHY_ID, PHY_SPECIAL).await?;
    let (speed, duplex) = decode_phy_special(special);
    Ok((true, speed, duplex))
}

/// Bring the internal PHY to autoneg and read the link state:
/// advertise 10/100 + pause, restart autoneg, poll for completion,
/// then read the link state via [`phy_link_status`]. A timeout
/// or a down link yields `(false, None, None)` — the iface
/// still publishes, with carrier down, exactly as a link-down
/// netdev.
async fn phy_link(
    dev: &USBDevice,
) -> Result<(bool, Option<u32>, Option<narf_net::iface::LinkDuplex>), ()> {
    mdio_write(dev, INTERNAL_PHY_ID, PHY_ANAR, ANAR_ADVERTISE).await?;
    mdio_write(dev, INTERNAL_PHY_ID, PHY_BMCR, BMCR_ANEN | BMCR_RSTAN).await?;
    let mut done = false;
    for _ in 0..ANEG_POLL_ITERS {
        let bmsr = mdio_read(dev, INTERNAL_PHY_ID, PHY_BMSR).await?;
        if bmsr & BMSR_AN_COMP != 0 {
            done = true;
            break;
        }
        narf_scheduler::yield_now().await;
    }
    if !done {
        return Ok((false, None, None));
    }
    phy_link_status(dev).await
}

/// Burst-cap + RX-buffer pair for the device's USB speed (Linux
/// `smsc95xx_reset` turbo path; NARF has no turbo_mode knob, so
/// the turbo values are the policy). Anything but High/Full
/// fails: this is a USB 2.0 10/100 part.
fn burst_for_speed(speed: PortSpeed) -> Result<(u32, usize), ()> {
    match speed {
        PortSpeed::High => Ok((HS_BURST_CAP, HS_RX_BUF_LEN)),
        PortSpeed::Full => Ok((FS_BURST_CAP, FS_RX_BUF_LEN)),
        _ => Err(()),
    }
}

/// Full reset in Linux's order (`smsc95xx_reset`): lite reset,
/// EEPROM station address, `HW_CFG` tuning, interrupt clear,
/// LED + flow + AFC + VLAN + COE programming, receive-own
/// multicast default, PHY-interrupt enable, TX then RX enable.
/// Returns `(station address, MAC_CR shadow, chip id)`.
async fn reset(dev: &USBDevice, burst_cap: u32) -> Result<([u8; 6], u32, ChipId), ()> {
    // Lite reset; LRST is self-clearing.
    reg_write(dev, HW_CFG, HW_CFG_LRST_).await?;
    let hw = poll_reg_clear(dev, HW_CFG, HW_CFG_LRST_, LRST_POLL_ITERS).await?;
    if hw & HW_CFG_LRST_ != 0 {
        return Err(());
    }
    // Station address from EEPROM, programmed to ADDRL/ADDRH
    // (Linux `smsc95xx_set_mac_address`: low word = bytes 0..4
    // little-endian, high word = bytes 4..6).
    let mac = read_station_address(dev).await?;
    let addr_lo = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
    let addr_hi = u32::from_le_bytes([mac[4], mac[5], 0, 0]);
    reg_write(dev, ADDRL, addr_lo).await?;
    reg_write(dev, ADDRH, addr_hi).await?;
    // Bulk-IN empty response.
    let mut hw = reg_read(dev, HW_CFG).await?;
    hw |= HW_CFG_BIR_;
    reg_write(dev, HW_CFG, hw).await?;
    // Burst cap + bulk-IN delay (Linux-observed tunables).
    reg_write(dev, BURST_CAP, burst_cap).await?;
    reg_write(dev, BULK_IN_DLY, BULK_IN_DELAY).await?;
    // Multi-frame + burst-cap enable, RX data offset = 2.
    hw = reg_read(dev, HW_CFG).await?;
    hw |= HW_CFG_MEF_ | HW_CFG_BCE_;
    hw &= !HW_CFG_RXDOFF_;
    hw |= 2 << 9;
    reg_write(dev, HW_CFG, hw).await?;
    // Clear all pending interrupts.
    reg_write(dev, INT_STS, INT_STS_CLEAR_ALL_).await?;
    // Chip identity (diagnostics + record).
    let id_rev = reg_read(dev, ID_REV).await?;
    let chip = chip_id_from_id_rev(id_rev);
    // GPIO pins as LED outputs.
    let mut led = reg_read(dev, LED_GPIO_CFG).await?;
    led |= LED_GPIO_CFG_SPD_LED | LED_GPIO_CFG_LNK_LED | LED_GPIO_CFG_FDX_LED;
    reg_write(dev, LED_GPIO_CFG, led).await?;
    // TX path setup: no flow-control pause time, AFC defaults.
    reg_write(dev, FLOW, 0).await?;
    reg_write(dev, AFC_CFG, AFC_CFG_DEFAULT).await?;
    // MAC shadow, VLAN tag recognition, checksum engines.
    let mut mac_cr = reg_read(dev, MAC_CR).await?;
    reg_write(dev, VLAN1, 0x8100).await?;
    let mut coe = reg_read(dev, COE_CR).await?;
    coe |= COE_TX_EN_;
    coe &= !COE_RX_EN_; // No RX verdict channel: RX COE stays off.
    reg_write(dev, COE_CR, coe).await?;
    // Multicast default: receive-own only (hash table empty),
    // via the same program the `DeviceControl` hook uses.
    let prog = lan95xx_multicast_program(mac_cr, false, false, &[]);
    reg_write(dev, HASHH, prog.hash_hi).await?;
    reg_write(dev, HASHL, prog.hash_lo).await?;
    mac_cr = prog.mac_cr;
    reg_write(dev, MAC_CR, mac_cr).await?;
    // Enable PHY interrupts at the endpoint (consumed by the
    // link-change status task) and arm the PHY interrupt
    // sources that raise them: without the mask the endpoint
    // would never fire on real silicon.
    let mut ep_ctl = reg_read(dev, INT_EP_CTL).await?;
    ep_ctl |= INT_EP_CTL_PHY_INT_;
    reg_write(dev, INT_EP_CTL, ep_ctl).await?;
    mdio_write(dev, INTERNAL_PHY_ID, PHY_INT_MASK, PHY_INT_MASK_DEFAULT).await?;
    // Start TX, then RX (Linux `smsc95xx_start_tx_path` /
    // `smsc95xx_start_rx_path`).
    mac_cr |= MAC_CR_TXEN_;
    reg_write(dev, MAC_CR, mac_cr).await?;
    reg_write(dev, TX_CFG, TX_CFG_ON_).await?;
    mac_cr |= MAC_CR_RXEN_;
    reg_write(dev, MAC_CR, mac_cr).await?;
    Ok((mac, mac_cr, chip))
}

// ── Device records + publication ────────────────────────────────

#[derive(Debug)]
pub struct Lan95xxDevice {
    pub slot_id: u8,
    /// Owning xHCI controller id ([`Xhci::id`]): slot ids are only
    /// unique within one controller, so TX and detach resolve the
    /// controller through this field, never a global accessor.
    pub controller: u8,
    pub chip: ChipId,
    pub mac: [u8; 6],
    pub bulk_in_dci: u8,
    pub bulk_out_dci: u8,
    /// Interrupt-IN endpoint DCI, when the device exposes one
    /// (`None` = no status task; bind-time link state stands).
    pub int_dci: Option<u8>,
    pub out_max_packet: u16,
    pub rx_buf_len: usize,
    /// Tracked `MAC_CR` shadow: the single value both the
    /// multicast hook and the link-change path start from.
    /// Read under the lock, never held across an await
    /// (AGENTS.md lock rule).
    pub mac_cr: u32,
    /// Last published link state (bind-time sample, then the
    /// status task's republishes). The link-change decision
    /// compares against this triple, so only real changes
    /// republish.
    pub link_up: bool,
    pub link_speed: Option<u32>,
    pub link_duplex: Option<narf_net::iface::LinkDuplex>,
    pub iface_name: String,
    pub pump_running: bool,
    pub detached: bool,
}

pub static LAN95XX_DEVICES: IrqSafeSpinLock<Vec<Lan95xxDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Resolve a device-record index to its TX target
/// `(slot_id, bulk_out_dci, out_max_packet)`. The send trampoline
/// routes through this — and only this — so a frame can never be
/// emitted on a different device's endpoint.
pub fn tx_target(idx: usize) -> Option<(u8, u8, u16)> {
    let g = LAN95XX_DEVICES.lock();
    g.get(idx)
        .filter(|d| !d.detached)
        .map(|d| (d.slot_id, d.bulk_out_dci, d.out_max_packet))
}

/// Ship one built TX segment on the device's bulk-OUT endpoint.
/// The net stack's send hook is sync; bridge to the async
/// bulk_out via block_on (called from TX paths that are not
/// inside an executor poll — same contract as r8152's send).
fn lan95xx_send_segment(
    controller: u8,
    slot_id: u8,
    bulk_out_dci: u8,
    seg: &[u8],
) -> Result<(), ()> {
    let c = crate::xhci::controller_by_id(controller).ok_or(())?;
    let n = narf_scheduler::block_on(async move { c.bulk_out(slot_id, bulk_out_dci, seg).await })
        .map_err(|_| ())?;
    if n != seg.len() {
        return Err(());
    }
    Ok(())
}

/// Send one frame for the device record at `idx`, honouring
/// `meta`. TSO, VLAN insert, SCTP checksums, and any csum request
/// the hardware cannot encode are rejected rather than sent with
/// a partial offload.
fn lan95xx_send_frame(idx: usize, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let (slot_id, bulk_out_dci, out_max_packet) = tx_target(idx).ok_or(())?;
    let controller = LAN95XX_DEVICES.lock().get(idx).ok_or(())?.controller;
    let seg = build_tx_segment(frame, meta)?;
    lan95xx_send_segment(controller, slot_id, bulk_out_dci, &seg)?;
    // FLAG_SEND_ZLP: a segment exactly filling maxpacket frames
    // needs a zero-length terminator.
    if needs_zlp(seg.len(), out_max_packet) {
        let c = crate::xhci::controller_by_id(controller).ok_or(())?;
        narf_scheduler::block_on(async move { c.bulk_out(slot_id, bulk_out_dci, &[]).await })
            .map_err(|_| ())?;
    }
    Ok(())
}

/// `SendCtxFn` trampoline: the cookie is the device-record index
/// assigned at registration time.
fn lan95xx_send_ctx(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    lan95xx_send_frame(cookie as usize, frame, meta)
}

/// Offloads the send path honours, so the stack actually requests
/// them via TxMeta. TX checksum only: no RX verdict channel, no
/// TSO, no VLAN insert.
pub fn lan95xx_offloads() -> narf_net::OffloadCapabilities {
    narf_net::OffloadCapabilities {
        tx_checksum: true,
        rx_checksum: false,
        max_tso_bytes: 0,
        vlan_insert: false,
    }
}

// ── Multicast `DeviceControl` (#1552) ───────────────────────────

/// `DeviceControl` for one bound LAN95xx record: programs the
/// multicast hash filter + `MAC_CR` receive-mode bits from the
/// stack's `DeviceConfig` (Linux `smsc95xx_set_multicast`).
/// The trait is sync while the hardware path is async, so
/// `configure` bridges via `block_on` (same contract as the
/// send path: the caller is not inside an executor poll, and
/// no lock is held across the `block_on` — AGENTS.md lock
/// rule). The record's tracked `mac_cr` is updated only after
/// all three writes succeed; a failed write leaves hardware
/// partly programmed and the record unchanged, and the stack
/// keeps its old metadata on `Err` (per the `DeviceConfig`
/// contract: "an error leaves metadata unchanged").
pub struct Lan95xxDeviceControl {
    device: Arc<USBDevice>,
    idx: usize,
}

// Manual `Debug` (`USBDevice` is `Clone`-only, so a derived impl
// would fail): slot + record index identify the binding.
impl core::fmt::Debug for Lan95xxDeviceControl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Lan95xxDeviceControl")
            .field("slot_id", &self.device.slot_id())
            .field("idx", &self.idx)
            .finish()
    }
}

impl narf_net::iface::DeviceControl for Lan95xxDeviceControl {
    fn configure(&self, config: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        // Stack errno convention (positive, Linux numbers — see
        // `configure_device`): ENODEV when the record is gone,
        // EIO when a hardware write fails.
        const ENODEV: i32 = 19;
        const EIO: i32 = 5;
        // Filter members are multicast addresses only: unicast
        // entries are the station address, not filter members.
        let mc: Vec<[u8; 6]> = config
            .addresses
            .iter()
            .filter(|a| !a.unicast)
            .map(|a| a.addr)
            .collect();
        // Tracked `MAC_CR` shadow, read before any await (no
        // lock across awaits). A link-change landing mid-path
        // may restore a newer shadow afterwards; the next link
        // event reconciles — last writer wins, same as the two
        // publishers in the AX88179 lane.
        let mac_cr = {
            let g = LAN95XX_DEVICES.lock();
            match g.get(self.idx) {
                Some(rec) if !rec.detached => rec.mac_cr,
                _ => return Err(ENODEV),
            }
        };
        let prog = lan95xx_multicast_program(mac_cr, config.promiscuous, config.all_multicast, &mc);
        let device = self.device.clone();
        let ok = narf_scheduler::block_on(async move {
            // Linux's order: HASHH, HASHL, then MAC_CR.
            reg_write(&device, HASHH, prog.hash_hi).await?;
            reg_write(&device, HASHL, prog.hash_lo).await?;
            reg_write(&device, MAC_CR, prog.mac_cr).await
        })
        .is_ok();
        if !ok {
            return Err(EIO);
        }
        let mut g = LAN95XX_DEVICES.lock();
        let Some(rec) = g.get_mut(self.idx) else {
            return Err(ENODEV);
        };
        if rec.detached {
            return Err(ENODEV);
        }
        rec.mac_cr = prog.mac_cr;
        Ok(())
    }
}

// ── Bind ────────────────────────────────────────────────────────

/// Full bind for an addressed LAN95xx device: configuration,
/// endpoint setup, reset, PHY link, netdev publication, RX pump,
/// link-change status task. Returns the device-record index.
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
    // Bulk pair + optional interrupt endpoint (#1552): a device
    // without an interrupt endpoint still binds — the bind-time
    // link state stands and no status task spawns (the AX88179
    // shape).
    let (in_ep, out_ep) = find_smsc_endpoints(&cfg).ok_or(())?;
    let int_ep = find_smsc_interrupt_endpoint(&cfg);
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
    match int_ep {
        Some(ie) => {
            device
                .configure_endpoints(&[in_ep, out_ep, ie])
                .await
                .map_err(|_| ())?;
        }
        None => {
            device
                .configure_endpoints(&[in_ep, out_ep])
                .await
                .map_err(|_| ())?;
        }
    }
    let bulk_in_dci = crate::bulk::dci_for(in_ep.ep_addr);
    let bulk_out_dci = crate::bulk::dci_for(out_ep.ep_addr);
    let int_dci = int_ep.map(|e| crate::bulk::dci_for(e.ep_addr));
    let (burst_cap, rx_buf_len) = burst_for_speed(device.speed())?;

    // Reset in Linux's order (station address from EEPROM inside).
    let (mac, mut mac_cr, chip) = reset(&device, burst_cap).await?;

    // External PHY: not driven by this lane (fail-closed).
    let hw = reg_read(&device, HW_CFG).await?;
    if hw & HW_CFG_PSEL_ != 0 {
        return Err(());
    }

    // PHY autoneg + link state; duplex feeds MAC_CR FDPX/RCVOWN
    // (Linux `smsc95xx_mac_update_fullduplex` steady state).
    let (carrier, speed, duplex) = phy_link(&device).await?;
    if let Some(duplex) = duplex {
        mac_cr = mac_cr_for_duplex(mac_cr, duplex);
        reg_write(&device, MAC_CR, mac_cr).await?;
    }

    // ── Record + publication ──
    let idx = {
        let mut g = LAN95XX_DEVICES.lock();
        let idx = g.len();
        g.push(Lan95xxDevice {
            slot_id: device.slot_id(),
            controller: device.controller().id(),
            chip,
            mac,
            bulk_in_dci,
            bulk_out_dci,
            int_dci,
            out_max_packet: out_ep.max_packet,
            rx_buf_len,
            mac_cr,
            link_up: carrier,
            link_speed: speed,
            link_duplex: duplex,
            iface_name: format!("usb-lan95xx{}", idx),
            pump_running: false,
            detached: false,
        });
        idx
    };
    let requested = {
        let g = LAN95XX_DEVICES.lock();
        g[idx].iface_name.clone()
    };
    let assigned =
        narf_net::iface::register_with_context(&requested, mac, idx as u64, lan95xx_send_ctx);
    // Advertise the TX offloads the send path honours.
    narf_net::iface::set_offloads(&assigned, lan95xx_offloads());
    // Multicast control hook (#1552). Best-effort: a `false`
    // return (iface gone) leaves the stack's registry-only
    // behavior, which is still correct — just without
    // driver-side filter programming.
    let _ = narf_net::iface::set_device_control(
        &assigned,
        Arc::new(Lan95xxDeviceControl {
            device: device.clone(),
            idx,
        }),
    );
    narf_net::iface::set_link_metadata(&assigned, carrier, speed, duplex);
    {
        let mut g = LAN95XX_DEVICES.lock();
        g[idx].iface_name = assigned.clone();
        g[idx].pump_running = true;
    }
    let _ = writeln!(
        narf_console::Writer,
        "  net: lan95xx bound slot {} as {} (chip {:?}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        device.slot_id(),
        assigned,
        chip,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    let pump_dev = device.clone();
    narf_scheduler::spawn(async move {
        rx_pump(pump_dev, idx).await;
    });
    if int_dci.is_some() {
        let status_dev = device.clone();
        narf_scheduler::spawn(async move {
            status_task(status_dev, idx).await;
        });
    }
    Ok(idx)
}

/// RX pump-stop predicate: the pump runs until its record's flag
/// clears (device removal clears it) or the record vanishes.
fn pump_should_continue(idx: usize) -> bool {
    let g = LAN95XX_DEVICES.lock();
    g.get(idx).map(|d| d.pump_running).unwrap_or(false)
}

/// Supervised RX pump: post bulk-IN reads, walk each aggregation
/// buffer, hand every good frame to the stack. Stops after a
/// bounded run of consecutive transfer errors (a removed device
/// surfaces as persistent errors) or when the record's flag
/// clears.
async fn rx_pump(device: Arc<USBDevice>, idx: usize) {
    let (bulk_in_dci, rx_buf_len) = {
        let g = LAN95XX_DEVICES.lock();
        let Some(rec) = g.get(idx) else {
            return;
        };
        (rec.bulk_in_dci, rec.rx_buf_len)
    };
    let mut buf = vec![0u8; rx_buf_len];
    let mut errors = 0u32;
    while pump_should_continue(idx) {
        match device.bulk_in(bulk_in_dci, &mut buf).await {
            Ok(n) if n > 0 => {
                errors = 0;
                let name = {
                    let g = LAN95XX_DEVICES.lock();
                    g.get(idx).map(|d| d.iface_name.clone())
                };
                if let Some(name) = name {
                    let walk = parse_rx_aggregate(&buf[..n]);
                    for frame in walk.frames {
                        let mut owned = buf[frame.offset..frame.offset + frame.len].to_vec();
                        narf_net::iface::on_rx_frame_from(&name, &mut owned);
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
    }
    let mut g = LAN95XX_DEVICES.lock();
    if let Some(rec) = g.get_mut(idx) {
        rec.pump_running = false;
    }
}

// ── Link-change status task (#1552) ─────────────────────────────

/// Handle one PHY interrupt (Linux `smsc95xx_status` →
/// PHY IRQ → `smsc95xx_handle_link_change`): acknowledge the
/// PHY interrupt, re-read the PHY, and republish link metadata
/// only when the state actually changed. On link-up the
/// carrier verdict stands even when the mode is unknown
/// (no `MAC_CR` duplex write then); on link-down the stack
/// clears speed/duplex and the `MAC_CR` duplex bits keep
/// their last value (Linux leaves them — `FDPX`/`RCVOWN`
/// are only rewritten for a negotiated duplex).
async fn handle_link_event(dev: &USBDevice, idx: usize) {
    // Acknowledge the PHY interrupt (best-effort: a failed
    // ack must not block the republish).
    let _ = mdio_read(dev, INTERNAL_PHY_ID, PHY_INT_SRC).await;
    let Ok((up, speed, duplex)) = phy_link_status(dev).await else {
        return;
    };
    let prev = {
        let g = LAN95XX_DEVICES.lock();
        match g.get(idx) {
            Some(rec) if !rec.detached => LinkState {
                up: rec.link_up,
                speed: rec.link_speed,
                duplex: rec.link_duplex,
            },
            _ => return,
        }
    };
    let Some(next) = link_change_decision(&prev, up, speed, duplex) else {
        return;
    };
    let name = {
        let mut g = LAN95XX_DEVICES.lock();
        let Some(rec) = g.get_mut(idx) else {
            return;
        };
        if rec.detached {
            return;
        }
        rec.link_up = next.up;
        rec.link_speed = next.speed;
        rec.link_duplex = next.duplex;
        rec.iface_name.clone()
    };
    // Duplex write from the freshest `MAC_CR` shadow (read
    // after the PHY sample, immediately before the write, so
    // a multicast configure landing mid-path is not clobbered).
    if next.up {
        if let Some(duplex) = next.duplex {
            let shadow = {
                let g = LAN95XX_DEVICES.lock();
                g.get(idx).map(|d| d.mac_cr)
            };
            if let Some(shadow) = shadow {
                let new_cr = mac_cr_for_duplex(shadow, duplex);
                if reg_write(dev, MAC_CR, new_cr).await.is_ok() {
                    let mut g = LAN95XX_DEVICES.lock();
                    if let Some(rec) = g.get_mut(idx) {
                        if !rec.detached {
                            rec.mac_cr = new_cr;
                        }
                    }
                }
            }
        }
        narf_net::iface::set_link_metadata(&name, true, next.speed, next.duplex);
    } else {
        narf_net::iface::set_link_metadata(&name, false, None, None);
    }
}

/// Interrupt-IN status task (Linux `smsc95xx_status`): arm
/// once with a 4-byte buffer, then poll — `poll_interrupt_in`
/// re-arms after every completion, so exactly one transfer
/// stays outstanding. Only PHY-interrupt events reach the
/// handler; short transfers and non-PHY words are ignored.
/// Exits on detach or a bounded run of consecutive transfer
/// errors (a removed device surfaces as persistent errors,
/// same bound as the RX pump).
async fn status_task(device: Arc<USBDevice>, idx: usize) {
    let int_dci = {
        let g = LAN95XX_DEVICES.lock();
        match g.get(idx).and_then(|d| d.int_dci) {
            Some(d) => d,
            None => return,
        }
    };
    if device
        .arm_interrupt_in(int_dci, INT_STATUS_LEN as u32)
        .is_err()
    {
        return;
    }
    let mut buf = [0u8; INT_STATUS_LEN];
    let mut errors = 0u32;
    loop {
        let detached = {
            let g = LAN95XX_DEVICES.lock();
            g.get(idx).map(|d| d.detached).unwrap_or(true)
        };
        if detached {
            break;
        }
        match device.poll_interrupt_in(int_dci, &mut buf) {
            Ok(Some(n)) => {
                errors = 0;
                if lan95xx_interrupt_phy(&buf[..n]) {
                    handle_link_event(&device, idx).await;
                }
            }
            Ok(None) => narf_scheduler::yield_now().await,
            Err(_) => {
                errors += 1;
                if errors >= 16 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
        }
    }
}

// ── Class-registry probe ────────────────────────────────────────

const MATCHES: &[UsbClassMatch] = &[
    // SMSC9500 USB Ethernet Device
    UsbClassMatch::vid_pid(0x0424, 0x9500),
    // SMSC9505 USB Ethernet Device
    UsbClassMatch::vid_pid(0x0424, 0x9505),
    // SMSC9500A USB Ethernet Device
    UsbClassMatch::vid_pid(0x0424, 0x9E00),
    // SMSC9505A USB Ethernet Device
    UsbClassMatch::vid_pid(0x0424, 0x9E01),
    // SMSC9512/9514 USB Hub & Ethernet Device
    UsbClassMatch::vid_pid(0x0424, 0xEC00),
    // SMSC9500 USB Ethernet Device (SAL10)
    UsbClassMatch::vid_pid(0x0424, 0x9900),
    // SMSC9505 USB Ethernet Device (SAL10)
    UsbClassMatch::vid_pid(0x0424, 0x9901),
    // SMSC9500A USB Ethernet Device (SAL10)
    UsbClassMatch::vid_pid(0x0424, 0x9902),
    // SMSC9505A USB Ethernet Device (SAL10)
    UsbClassMatch::vid_pid(0x0424, 0x9903),
    // SMSC9512/9514 USB Hub & Ethernet Device (SAL10)
    UsbClassMatch::vid_pid(0x0424, 0x9904),
    // SMSC9500A USB Ethernet Device (HAL)
    UsbClassMatch::vid_pid(0x0424, 0x9905),
    // SMSC9505A USB Ethernet Device (HAL)
    UsbClassMatch::vid_pid(0x0424, 0x9906),
    // SMSC9500 USB Ethernet Device (Alternate ID)
    UsbClassMatch::vid_pid(0x0424, 0x9907),
    // SMSC9500A USB Ethernet Device (Alternate ID)
    UsbClassMatch::vid_pid(0x0424, 0x9908),
    // SMSC9512/9514 USB Hub & Ethernet Device (Alternate ID)
    UsbClassMatch::vid_pid(0x0424, 0x9909),
    // SMSC LAN9530 USB Ethernet Device
    UsbClassMatch::vid_pid(0x0424, 0x9530),
    // SMSC LAN9730 USB Ethernet Device
    UsbClassMatch::vid_pid(0x0424, 0x9730),
    // SMSC LAN89530 USB Ethernet Device
    UsbClassMatch::vid_pid(0x0424, 0x9E08),
    // Deliberately NOT admitted: 0878:1400 (SYSTEC 10BASE-T1L)
    // and 184F:0051 (Microchip 10BASE-T1S EVB) bind to the same
    // Linux driver but carry different PHY families, not the
    // internal 10/100 PHY this lane drives.
];

fn probe(device: Arc<USBDevice>, _hub_port: Option<(u8, u8)>) -> Result<(), UsbProbeError> {
    // The registry probe is synchronous, but bind needs async
    // control transfers — spawn it (xpad precedent).
    narf_scheduler::spawn_stackful(async move {
        use core::fmt::Write;
        if bind(device).await.is_err() {
            let _ = writeln!(
                narf_console::Writer,
                "  net: lan95xx bind failed (no valid station address or config error)"
            );
        }
    });
    Ok(())
}

/// Detach hook for a slot: tombstone every LAN95xx record bound
/// to it and unregister its net iface. The pump exits at its next
/// `pump_should_continue` check once `pump_running` clears; the
/// link-change status task exits at its next loop check once
/// `detached` is set.
/// TX resolves to `None` instead of retargeting a later device
/// (records are never removed — the ECM/NCM rule: net-registry
/// TX cookies are record indices). Unknown slots no-op; repeat
/// detach is a silent no-op (unregister is idempotent).
///
/// Panic-free and idempotent by the #893 hook contract: no
/// indexing and no fallible unwraps on any path. Tombstones
/// are set under the registry lock and iface names collected
/// there, but the net unregister runs after the lock is
/// released — the net registry lock must never be taken while
/// the LAN95xx registry lock is held (UVC collect-then-unregister
/// pattern). A TX already past `tx_target` when detach lands
/// may still hit the wire; every later TX fail-closes.
///
/// RX-mirror obligation (#789): NOT owed here — same verdict as
/// r8152/ECM/NCM: this family's pump delivers via
/// `narf_net::iface::on_rx_frame_from` directly and never calls
/// `publish::note_rx_mirror_attached`, and its `usb-lan95xx{N}`
/// names cannot collide with the `eth%d` keys the mirror
/// registry can ever hold.
pub fn detach_lan95xx_slot(controller: u8, slot_id: u8) -> Result<(), ()> {
    let ifaces: Vec<String> = {
        let mut g = LAN95XX_DEVICES.lock();
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

/// Wholesale variant of [`detach_lan95xx_slot`] for controller
/// recovery (`attach::detach_all_bindings`): tombstone every
/// LAN95xx binding and unregister every net iface, regardless of
/// slot. Infallible and idempotent, same pump-exit and
/// never-remove reasoning as [`detach_lan95xx_slot`].
pub fn detach_all_lan95xx() {
    let ifaces: Vec<String> = {
        let mut g = LAN95XX_DEVICES.lock();
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

/// Register the lan95xx USB class driver, together with its
/// detach hook. The probe spawns the async bind (xpad
/// precedent); the unbind hook adapts infallible
/// `detach_lan95xx_slot` to the fallible `UsbUnbindFn` contract
/// with an unconditional `Ok(())` (#893: a hook reports
/// failure with `Err(())`, never by panicking).
pub fn register() {
    let _ = register_class_driver_with_unbind("lan95xx", MATCHES, probe, detach_lan95xx_slot);
}

// ── Fixtures ────────────────────────────────────────────────────
//
// Modelled-device fixtures in the crate's kernel-test style: the
// register conversation is pinned at the level the production
// code composes it — SETUP-packet packing for each access class,
// the pure TX/RX wire formats as byte fixtures, and the
// decision functions (hash, PHY decode, MAC validity) against
// independently computed literals.

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_lan95xx_setup_packing() -> TestResult {
        // Register read of HW_CFG: vendor IN, req 0xA1,
        // wValue = 0, wIndex = register.
        let (rt, rq, wv, wi) = read_reg_setup(HW_CFG);
        if (rt, rq, wv, wi) != (0xC0, 0xA1, 0, 0x14) {
            return TestResult::Fail("read setup packing wrong");
        }
        // Register write of FLOW: vendor OUT, req 0xA0,
        // wValue = 0, wIndex = register.
        let (rt, rq, wv, wi) = write_reg_setup(FLOW);
        if (rt, rq, wv, wi) != (0x40, 0xA0, 0, 0x11C) {
            return TestResult::Fail("write setup packing wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_mii_address_cmd() -> TestResult {
        // PHY 1, reg 0, read: (1 << 11) | (0 << 6) | 0.
        if mii_address_cmd(1, 0, false) != 0x0800 {
            return TestResult::Fail("mii read cmd wrong");
        }
        // PHY 1, reg 31, write: 0x0800 | (31 << 6) | 0x02.
        if mii_address_cmd(1, 31, true) != 0x0FC2 {
            return TestResult::Fail("mii write cmd wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_multicast_hash() -> TestResult {
        // Linux-documented example: 01:00:5E:00:00:01 -> bit 31
        // (independently re-computed with a Python crc32_le +
        // bitrev32 oracle before this fixture was written).
        if multicast_hash(&[0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]) != 31 {
            return TestResult::Fail("hash example bit wrong");
        }
        // High-word split: 01:00:5E:7F:FF:FA -> bit 43, so
        // HASHH bit 11; combined with the bit-31 address.
        let (hi, lo) = hash_words(&[
            [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01],
            [0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA],
        ]);
        if (hi, lo) != (0x0000_0800, 0x8000_0000) {
            return TestResult::Fail("hash word split wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_mac_validity() -> TestResult {
        if mac_valid(&[0, 0, 0, 0, 0, 0]) {
            return TestResult::Fail("all-zero accepted");
        }
        if mac_valid(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) {
            return TestResult::Fail("broadcast accepted");
        }
        if mac_valid(&[0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]) {
            return TestResult::Fail("multicast accepted");
        }
        if !mac_valid(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]) {
            return TestResult::Fail("valid unicast rejected");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_phy_special_decode() -> TestResult {
        use narf_net::iface::LinkDuplex;
        if decode_phy_special(0x0018) != (Some(100), Some(LinkDuplex::Full)) {
            return TestResult::Fail("100FULL decode wrong");
        }
        if decode_phy_special(0x0004) != (Some(10), Some(LinkDuplex::Half)) {
            return TestResult::Fail("10HALF decode wrong");
        }
        // Unrelated low bits must not affect the masked decode.
        if decode_phy_special(0x0019) != (Some(100), Some(LinkDuplex::Full)) {
            return TestResult::Fail("masked decode wrong");
        }
        if decode_phy_special(0x001C) != (None, None) {
            return TestResult::Fail("unknown SPD accepted");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_chip_id_decode() -> TestResult {
        if chip_id_from_id_rev(0x9500_0000) != ChipId::Lan9500 {
            return TestResult::Fail("9500 decode wrong");
        }
        if chip_id_from_id_rev(0xEC00_1234) != ChipId::Lan9512 {
            return TestResult::Fail("9512 decode wrong");
        }
        if chip_id_from_id_rev(0x1234_0000) != ChipId::Unknown(0x1234) {
            return TestResult::Fail("unknown chip decode wrong");
        }
        TestResult::Pass
    }

    fn ipv4_tcp_frame(total_len: usize) -> Vec<u8> {
        // Ethernet (14) + IPv4 (20, IHL 5, proto TCP) + TCP (20)
        // + payload to total_len. csum_start = 34, TCP offset 16.
        let mut f = vec![0u8; total_len];
        f[12] = 0x08;
        f[13] = 0x00;
        f[14] = 0x45;
        f[14 + 9] = 6;
        f
    }

    fn smoke_lan95xx_tx_segment_plain() -> TestResult {
        let frame = ipv4_tcp_frame(60);
        let seg = match build_tx_segment(&frame, narf_net::TxMeta::plain()) {
            Ok(s) => s,
            Err(()) => return TestResult::Fail("plain build rejected"),
        };
        // tx_cmd_a = 60 | FIRST | LAST = 0x303C, tx_cmd_b = 60.
        if seg.len() != 68 {
            return TestResult::Fail("plain segment length wrong");
        }
        if seg[0..8] != [0x3C, 0x30, 0, 0, 0x3C, 0, 0, 0] {
            return TestResult::Fail("plain command words wrong");
        }
        if seg[8..] != frame[..] {
            return TestResult::Fail("plain frame bytes wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_tx_segment_csum() -> TestResult {
        let frame = ipv4_tcp_frame(100);
        let meta = narf_net::TxMeta {
            csum_l4: Some(narf_net::L4CsumKind::Tcp),
            ..narf_net::TxMeta::plain()
        };
        let seg = match build_tx_segment(&frame, meta) {
            Ok(s) => s,
            Err(()) => return TestResult::Fail("csum build rejected"),
        };
        // Lengths grow by the 4-byte preamble: 104.
        // tx_cmd_a = 104 | FIRST | LAST = 0x3068,
        // tx_cmd_b = 104 | CSUM_ENABLE = 0x4068,
        // preamble = ((34 + 16) << 16) | 34 = 0x0032_0022.
        if seg.len() != 112 {
            return TestResult::Fail("csum segment length wrong");
        }
        if seg[0..12] != [0x68, 0x30, 0, 0, 0x68, 0x40, 0, 0, 0x22, 0x00, 0x32, 0x00] {
            return TestResult::Fail("csum header words wrong");
        }
        if seg[12..] != frame[..] {
            return TestResult::Fail("csum frame bytes wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_tx_segment_rejects() -> TestResult {
        let frame = ipv4_tcp_frame(100);
        // SCTP: no chip support.
        let meta = narf_net::TxMeta {
            csum_l4: Some(narf_net::L4CsumKind::Sctp),
            ..narf_net::TxMeta::plain()
        };
        if build_tx_segment(&frame, meta).is_ok() {
            return TestResult::Fail("SCTP accepted");
        }
        // TSO: not implemented.
        let meta = narf_net::TxMeta {
            tso_mss: Some(1460),
            ..narf_net::TxMeta::plain()
        };
        if build_tx_segment(&frame, meta).is_ok() {
            return TestResult::Fail("TSO accepted");
        }
        // VLAN insert: not implemented.
        let meta = narf_net::TxMeta {
            vlan_tag: Some(0x001),
            ..narf_net::TxMeta::plain()
        };
        if build_tx_segment(&frame, meta).is_ok() {
            return TestResult::Fail("VLAN accepted");
        }
        // Small packet: the hardware csum gate (len <= 45). A UDP
        // frame carries its checksum field at 34 + 6 + 2 = 42, so
        // a 44-byte UDP frame parses but trips the gate (a TCP
        // frame cannot be <= 45 bytes and still contain its
        // checksum field, so TCP cannot exercise this branch).
        let mut small = vec![0u8; 44];
        small[12] = 0x08;
        small[13] = 0x00;
        small[14] = 0x45;
        small[14 + 9] = 17;
        let meta = narf_net::TxMeta {
            csum_l4: Some(narf_net::L4CsumKind::Udp),
            ..narf_net::TxMeta::plain()
        };
        if build_tx_segment(&small, meta).is_ok() {
            return TestResult::Fail("small-packet csum accepted");
        }
        // Oversize: jumbo is a remainder, never truncated.
        let big = ipv4_tcp_frame(1519);
        if build_tx_segment(&big, narf_net::TxMeta::plain()).is_ok() {
            return TestResult::Fail("oversize accepted");
        }
        // Unparseable csum request (non-IP EtherType).
        let mut bad = ipv4_tcp_frame(100);
        bad[12] = 0x88;
        bad[13] = 0x47;
        let meta = narf_net::TxMeta {
            csum_l4: Some(narf_net::L4CsumKind::Tcp),
            ..narf_net::TxMeta::plain()
        };
        if build_tx_segment(&bad, meta).is_ok() {
            return TestResult::Fail("non-IP csum accepted");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_csum_gate_edges() -> TestResult {
        // (frame_len, csum_start, csum_offset): 16 < len-5 gate.
        if !can_tx_checksum(100, 34, 16) {
            return TestResult::Fail("100-byte gate wrong");
        }
        if can_tx_checksum(45, 34, 16) {
            return TestResult::Fail("45-byte gate wrong");
        }
        // 56 - 34 = 22; 16 < 22 - 5 = 17: pass.
        if !can_tx_checksum(56, 34, 16) {
            return TestResult::Fail("56-byte gate wrong");
        }
        // 55 - 34 = 21; 16 < 21 - 5 = 16: fail (strict).
        if can_tx_checksum(55, 34, 16) {
            return TestResult::Fail("55-byte gate wrong");
        }
        if csum_preamble(34, 16) != 0x0032_0022 {
            return TestResult::Fail("preamble wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_rx_aggregate_walk() -> TestResult {
        // Frame 1: good, size 64 (60 delivered). Frame 2: ES-set,
        // size 60 (dropped). Frame 3: good last, size 68 (64).
        let mut buf = Vec::new();
        // Frame 1: header + pad + 64 bytes + 2 align.
        buf.extend_from_slice(&((64u32) << 16).to_le_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0xAA; 64]);
        buf.extend_from_slice(&[0, 0]);
        // Frame 2: ES header + pad + 60 bytes + 2 align.
        buf.extend_from_slice(&(((60u32) << 16) | RX_STS_ES_).to_le_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0xBB; 60]);
        buf.extend_from_slice(&[0, 0]);
        // Frame 3: header + pad + 68 bytes, no trailing pad.
        buf.extend_from_slice(&((68u32) << 16).to_le_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0xCC; 68]);
        let walk = parse_rx_aggregate(&buf);
        if walk.frames.len() != 2 || walk.dropped != 1 {
            return TestResult::Fail("walk frame/drop counts wrong");
        }
        if walk.frames[0] != (RxFrame { offset: 6, len: 60 }) {
            return TestResult::Fail("frame 1 range wrong");
        }
        if walk.frames[1]
            != (RxFrame {
                offset: 146,
                len: 64,
            })
        {
            return TestResult::Fail("frame 3 range wrong");
        }
        // Delivered bytes are the frame bytes, FCS excluded.
        if buf[walk.frames[0].offset] != 0xAA || buf[walk.frames[1].offset] != 0xCC {
            return TestResult::Fail("delivered bytes wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_rx_aggregate_truncation() -> TestResult {
        // Truncated tail: claimed size exceeds the buffer — the
        // walk stops, keeping the good frame before it.
        let mut buf = Vec::new();
        buf.extend_from_slice(&((64u32) << 16).to_le_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0xAA; 64]);
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&((100u32) << 16).to_le_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0xBB; 50]);
        let walk = parse_rx_aggregate(&buf);
        if walk.frames.len() != 1 || walk.dropped != 0 {
            return TestResult::Fail("truncation walk wrong");
        }
        // Oversize length field: stop immediately, no frames.
        let mut buf = Vec::new();
        buf.extend_from_slice(&((2000u32) << 16).to_le_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0xAA; 64]);
        let walk = parse_rx_aggregate(&buf);
        if !walk.frames.is_empty() {
            return TestResult::Fail("oversize not stopped");
        }
        // Empty buffer: no frames, no panic.
        if !parse_rx_aggregate(&[]).frames.is_empty() {
            return TestResult::Fail("empty buffer walk wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_endpoint_finder() -> TestResult {
        // Config (9) + interface (9, class 0xFF) + bulk OUT ep 2
        // + bulk IN ep 0x81, maxpacket 512 each.
        let mut cfg = Vec::new();
        cfg.extend_from_slice(&[9, 0x02, 0x20, 0x00, 1, 1, 0, 0x80, 250]);
        cfg.extend_from_slice(&[9, 0x04, 0, 0, 2, 0xFF, 0, 0, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x00, 0x02, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x81, 0x02, 0x00, 0x02, 0]);
        let Some((in_ep, out_ep)) = find_smsc_endpoints(&cfg) else {
            return TestResult::Fail("bulk pair not found");
        };
        if in_ep.ep_addr != 0x81 || out_ep.ep_addr != 0x02 {
            return TestResult::Fail("endpoint addresses wrong");
        }
        if in_ep.max_packet != 512 || out_ep.max_packet != 512 {
            return TestResult::Fail("maxpacket wrong");
        }
        // Interrupt-only config: no bulk pair.
        let mut cfg = Vec::new();
        cfg.extend_from_slice(&[9, 0x02, 0x10, 0x00, 1, 1, 0, 0x80, 250]);
        cfg.extend_from_slice(&[9, 0x04, 0, 0, 1, 0xFF, 0, 0, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x83, 0x03, 0x08, 0x00, 10]);
        if find_smsc_endpoints(&cfg).is_some() {
            return TestResult::Fail("interrupt-only accepted");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_zlp_rule() -> TestResult {
        if !needs_zlp(512, 512) {
            return TestResult::Fail("exact multiple needs ZLP");
        }
        if !needs_zlp(1024, 512) {
            return TestResult::Fail("double multiple needs ZLP");
        }
        if needs_zlp(513, 512) {
            return TestResult::Fail("non-multiple flagged");
        }
        if needs_zlp(100, 0) {
            return TestResult::Fail("zero maxpacket flagged");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_interrupt_decode() -> TestResult {
        // Exactly 4 bytes, LE32, PHY-interrupt bit 15 set.
        if !lan95xx_interrupt_phy(&[0x00, 0x80, 0x00, 0x00]) {
            return TestResult::Fail("PHY interrupt word not recognised");
        }
        // All bits set still carries the PHY interrupt.
        if !lan95xx_interrupt_phy(&[0xFF, 0xFF, 0xFF, 0xFF]) {
            return TestResult::Fail("all-bits word not recognised");
        }
        // No PHY bit: TX-error word (bit 14) is not a link event.
        if lan95xx_interrupt_phy(&[0x00, 0x40, 0x00, 0x00]) {
            return TestResult::Fail("non-PHY word treated as link event");
        }
        // All-zero word: no event.
        if lan95xx_interrupt_phy(&[0x00, 0x00, 0x00, 0x00]) {
            return TestResult::Fail("zero word treated as link event");
        }
        // Linux requires exactly 4 bytes: short, empty, and long
        // transfers are ignored even with the PHY bit set.
        if lan95xx_interrupt_phy(&[0x00, 0x80, 0x00]) {
            return TestResult::Fail("short transfer treated as link event");
        }
        if lan95xx_interrupt_phy(&[]) {
            return TestResult::Fail("empty transfer treated as link event");
        }
        if lan95xx_interrupt_phy(&[0x00, 0x80, 0x00, 0x00, 0x00]) {
            return TestResult::Fail("long transfer treated as link event");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_link_change_decision() -> TestResult {
        use narf_net::iface::LinkDuplex;
        let down = LinkState {
            up: false,
            speed: None,
            duplex: None,
        };
        // Fake link-change interrupt, cable plugged in after
        // bind: down -> 100/full republishes.
        let up100 = match link_change_decision(&down, true, Some(100), Some(LinkDuplex::Full)) {
            Some(s) => s,
            None => return TestResult::Fail("link-up change missed"),
        };
        if up100
            != (LinkState {
                up: true,
                speed: Some(100),
                duplex: Some(LinkDuplex::Full),
            })
        {
            return TestResult::Fail("link-up state wrong");
        }
        // Duplicate interrupt, same state: no republish.
        if link_change_decision(&up100, true, Some(100), Some(LinkDuplex::Full)).is_some() {
            return TestResult::Fail("unchanged state republished");
        }
        // Renegotiation without carrier drop: 100/full ->
        // 10/half republishes.
        let up10 = match link_change_decision(&up100, true, Some(10), Some(LinkDuplex::Half)) {
            Some(s) => s,
            None => return TestResult::Fail("renegotiation change missed"),
        };
        if up10.speed != Some(10) || up10.duplex != Some(LinkDuplex::Half) {
            return TestResult::Fail("renegotiation state wrong");
        }
        // Cable unplugged: link-down republishes with no mode.
        let back_down = match link_change_decision(&up10, false, None, None) {
            Some(s) => s,
            None => return TestResult::Fail("link-down change missed"),
        };
        if back_down != down {
            return TestResult::Fail("link-down state wrong");
        }
        // No interrupt (still down): no republish.
        if link_change_decision(&down, false, None, None).is_some() {
            return TestResult::Fail("steady down state republished");
        }
        // Link-up with unknown mode still publishes carrier.
        let unknown = match link_change_decision(&down, true, None, None) {
            Some(s) => s,
            None => return TestResult::Fail("unknown-mode link-up missed"),
        };
        if !unknown.up || unknown.speed.is_some() || unknown.duplex.is_some() {
            return TestResult::Fail("unknown-mode state wrong");
        }
        // A down state never carries a mode, even if the
        // caller passes one.
        let forced = match link_change_decision(&up10, false, Some(100), Some(LinkDuplex::Full)) {
            Some(s) => s,
            None => return TestResult::Fail("forced-down change missed"),
        };
        if forced.speed.is_some() || forced.duplex.is_some() {
            return TestResult::Fail("down state carries a mode");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_mac_cr_duplex() -> TestResult {
        use narf_net::iface::LinkDuplex;
        // Base: TXEN | RXEN | HPFILT (bind-time steady state).
        let base = MAC_CR_TXEN_ | MAC_CR_RXEN_ | MAC_CR_HPFILT_;
        let full = mac_cr_for_duplex(base, LinkDuplex::Full);
        if full & MAC_CR_FDPX_ == 0 || full & MAC_CR_RCVOWN_ != 0 {
            return TestResult::Fail("full-duplex bits wrong");
        }
        if full & MAC_CR_HPFILT_ == 0 || full & (MAC_CR_TXEN_ | MAC_CR_RXEN_) == 0 {
            return TestResult::Fail("full-duplex clobbered other bits");
        }
        let half = mac_cr_for_duplex(base, LinkDuplex::Half);
        if half & MAC_CR_FDPX_ != 0 || half & MAC_CR_RCVOWN_ == 0 {
            return TestResult::Fail("half-duplex bits wrong");
        }
        if half & MAC_CR_HPFILT_ == 0 || half & (MAC_CR_TXEN_ | MAC_CR_RXEN_) == 0 {
            return TestResult::Fail("half-duplex clobbered other bits");
        }
        // From zero: exactly one bit each.
        if mac_cr_for_duplex(0, LinkDuplex::Full) != MAC_CR_FDPX_ {
            return TestResult::Fail("full-duplex from zero wrong");
        }
        if mac_cr_for_duplex(0, LinkDuplex::Half) != MAC_CR_RCVOWN_ {
            return TestResult::Fail("half-duplex from zero wrong");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_multicast_program() -> TestResult {
        // Bind-time steady state as the base: TXEN | RXEN.
        let base = MAC_CR_TXEN_ | MAC_CR_RXEN_;
        // Filtered set, three addresses (hash bits 31, 43, 15 —
        // each independently re-computed with a Python
        // crc32_le + bitrev32 oracle): HASHL bits 31 + 15,
        // HASHH bit 11.
        let prog = lan95xx_multicast_program(
            base,
            false,
            false,
            &[
                [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01],
                [0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA],
                [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB],
            ],
        );
        if (prog.hash_hi, prog.hash_lo) != (0x0000_0800, 0x8000_8000) {
            return TestResult::Fail("filtered hash words wrong");
        }
        // The corrected HPFILT bit (0x2000) is set; the old
        // wrong value (0x8000, HFILT) is not.
        if prog.mac_cr & MAC_CR_HPFILT_ == 0 {
            return TestResult::Fail("filtered program lacks HPFILT");
        }
        if prog.mac_cr & MAC_CR_HFILT_ != 0 {
            return TestResult::Fail("filtered program sets HFILT");
        }
        if prog.mac_cr & (MAC_CR_PRMS_ | MAC_CR_MCPAS_) != 0 {
            return TestResult::Fail("filtered program sets PRMS/MCPAS");
        }
        if prog.mac_cr & (MAC_CR_TXEN_ | MAC_CR_RXEN_) == 0 {
            return TestResult::Fail("filtered program clobbered TXEN/RXEN");
        }
        // Promiscuous wins over all-multicast + a list.
        let prog =
            lan95xx_multicast_program(base, true, true, &[[0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]]);
        if prog.mac_cr & MAC_CR_PRMS_ == 0
            || prog.mac_cr & (MAC_CR_MCPAS_ | MAC_CR_HPFILT_) != 0
            || (prog.hash_hi, prog.hash_lo) != (0, 0)
        {
            return TestResult::Fail("promiscuous program wrong");
        }
        // All-multicast: MCPAS, no filter, empty hash table.
        let prog =
            lan95xx_multicast_program(base, false, true, &[[0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]]);
        if prog.mac_cr & MAC_CR_MCPAS_ == 0
            || prog.mac_cr & (MAC_CR_PRMS_ | MAC_CR_HPFILT_) != 0
            || (prog.hash_hi, prog.hash_lo) != (0, 0)
        {
            return TestResult::Fail("all-multicast program wrong");
        }
        // Empty list: receive-own only, empty hash table.
        let prog = lan95xx_multicast_program(base, false, false, &[]);
        if prog.mac_cr & (MAC_CR_PRMS_ | MAC_CR_MCPAS_ | MAC_CR_HPFILT_) != 0
            || (prog.hash_hi, prog.hash_lo) != (0, 0)
        {
            return TestResult::Fail("empty multicast program wrong");
        }
        if prog.mac_cr != base {
            return TestResult::Fail("empty program changed base bits");
        }
        TestResult::Pass
    }

    fn smoke_lan95xx_interrupt_endpoint_finder() -> TestResult {
        // Config (9) + interface (9, class 0xFF) + bulk OUT ep 2
        // + bulk IN ep 0x81, maxpacket 512 each + interrupt IN
        // ep 0x83, maxpacket 8, interval 10.
        let mut cfg = Vec::new();
        cfg.extend_from_slice(&[9, 0x02, 0x27, 0x00, 1, 1, 0, 0x80, 250]);
        cfg.extend_from_slice(&[9, 0x04, 0, 0, 3, 0xFF, 0, 0, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x00, 0x02, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x81, 0x02, 0x00, 0x02, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x83, 0x03, 0x08, 0x00, 10]);
        // The bulk finder still finds its pair with the
        // interrupt endpoint present.
        let Some((in_ep, out_ep)) = find_smsc_endpoints(&cfg) else {
            return TestResult::Fail("bulk pair lost with interrupt ep");
        };
        if in_ep.ep_addr != 0x81 || out_ep.ep_addr != 0x02 {
            return TestResult::Fail("bulk addresses wrong");
        }
        let Some(ie) = find_smsc_interrupt_endpoint(&cfg) else {
            return TestResult::Fail("interrupt endpoint not found");
        };
        if ie.ep_addr != 0x83 || ie.max_packet != 8 || ie.interval != 10 {
            return TestResult::Fail("interrupt endpoint fields wrong");
        }
        if !matches!(ie.kind, EndpointKind::InterruptIn) {
            return TestResult::Fail("interrupt endpoint kind wrong");
        }
        // No interrupt endpoint: None (bulk pair unaffected).
        let mut cfg = Vec::new();
        cfg.extend_from_slice(&[9, 0x02, 0x20, 0x00, 1, 1, 0, 0x80, 250]);
        cfg.extend_from_slice(&[9, 0x04, 0, 0, 2, 0xFF, 0, 0, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x02, 0x02, 0x00, 0x02, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x81, 0x02, 0x00, 0x02, 0]);
        if find_smsc_interrupt_endpoint(&cfg).is_some() {
            return TestResult::Fail("interrupt endpoint invented");
        }
        // Interrupt-only config: finder finds it, bulk pair None.
        let mut cfg = Vec::new();
        cfg.extend_from_slice(&[9, 0x02, 0x10, 0x00, 1, 1, 0, 0x80, 250]);
        cfg.extend_from_slice(&[9, 0x04, 0, 0, 1, 0xFF, 0, 0, 0]);
        cfg.extend_from_slice(&[7, 0x05, 0x83, 0x03, 0x08, 0x00, 10]);
        if find_smsc_interrupt_endpoint(&cfg).is_none() {
            return TestResult::Fail("interrupt-only endpoint missed");
        }
        if find_smsc_endpoints(&cfg).is_some() {
            return TestResult::Fail("interrupt-only accepted as bulk");
        }
        TestResult::Pass
    }

    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_setup_packing);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_mii_address_cmd);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_multicast_hash);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_mac_validity);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_phy_special_decode);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_chip_id_decode);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_tx_segment_plain);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_tx_segment_csum);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_tx_segment_rejects);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_csum_gate_edges);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_rx_aggregate_walk);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_rx_aggregate_truncation);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_endpoint_finder);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_zlp_rule);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_interrupt_decode);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_link_change_decision);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_mac_cr_duplex);
    kernel_test_in!("drivers/usb/lan95xx", smoke_lan95xx_multicast_program);
    kernel_test_in!(
        "drivers/usb/lan95xx",
        smoke_lan95xx_interrupt_endpoint_finder
    );
}
