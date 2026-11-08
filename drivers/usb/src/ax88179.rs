//! ASIX AX88179 USB 3.0 to 10/100/1000M Gigabit Ethernet driver — core
//! + audit item 2.
//!
//! Implements issue #788 part 1 (audit §7 item 1): probe, vendor control
//! transport, reset, Clause 22 PHY, MAC read, TX/RX framing, publication
//! as `usb-ax{N}`, and tombstone detach; plus audit item 2: the
//! link-status interrupt path (interrupt endpoint, PHYSR/medium/
//! bulkin link-change, speed + duplex reporting), TX/RX offload
//! advertisement (TX checksum accepted, RX checksum deliberately
//! unadvertised — no verdict channel in `on_rx_frame_from`, the
//! r8152 limitation), and multicast filter programming via the
//! stack's `DeviceControl` hook. LAN95xx is item 3 (separate lane);
//! VLAN handling and jumbo frames are UNGROUNDED per audit §6 and
//! are not included.
//!
//! ## Grounding (read before touching a constant)
//!
//! Register map and framing come from the #788 audit
//! (`~/workspace/queue/ethernet-asix-audit.md`, 2026-11-04), cross-checked
//! against Linux `drivers/net/usb/ax88179_178a.c` @ cbbddb6 (behavioral
//! cross-check only — nothing is transcribed verbatim, per the repo
//! no-GPL rule). The full ASIX datasheet (`AX88179/V1.31/04/11/16`) could
//! NOT be retrieved in-session (only marketing product briefs are
//! publicly fetchable), so every value below that rests on driver
//! sources rather than the datasheet is marked driver-observed in its
//! comment. Two consequences, both deliberate:
//!
//! - The long proprietary PHY-init write sequences and the EEPROM/EFUSE
//!   handling order the audit flagged as highest GPL risk are NOT in
//!   this lane: PHY bring-up is standard IEEE 802.3 Clause 22 autoneg
//!   only, and the MAC is read from the chip's own `AX_NODE_ID`
//!   register (the chip resolves EEPROM/EFUSE internally), so no
//!   EEPROM/EFUSE selection logic is needed.
//! - The audit's §3 sentence "`wValue` = register, `wIndex` = PHY id
//!   for PHY access" is BACKWARDS against the shipped driver's wire
//!   behavior and is corrected here: Linux `usbnet_read_cmd` passes
//!   `value` → `wValue`, `index` → `wIndex` verbatim, and the MDIO
//!   path calls it with `value = phy_id`, `index = register`
//!   (`ax88179_mdio_read`). So PHY access packs `wValue = 0x03`,
//!   `wIndex = register`. MAC access packs `wValue = register`,
//!   `wIndex = byte count`. Both packings are pinned by fixtures.
//!
//! ## Wire model
//!
//! Vendor control transfers (`bmRequestType` 0xC0 read / 0x40 write,
//! device recipient, vendor type). `bRequest` is the access class.
//! TX: one 8-byte header (`tx_hdr1` = frame length LE, `tx_hdr2` = 0
//! in v1 — no TSO — plus the `0x80008000` padding flag when
//! `(len + 8) % maxpacket == 0`) followed by the frame. RX: bulk-IN
//! buffers of concatenated frames; each frame carries a 2-byte
//! IP-alignment pseudo-header inside its length, frames are padded
//! to 8-byte boundaries, a trailing 32-bit `rx_hdr` gives `pkt_cnt`
//! (low half) and `hdr_off` (high half) for the per-packet metadata
//! array, and dummy headers (`pkt_len = 0` + `DROP_ERR`) are skipped.
//! The published station address is read from the device at bind
//! (never synthesised); a device reporting no valid address fails
//! the bind, per the USB-Ethernet contract in `spec.md`.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::class_registry::{register_class_driver_with_unbind, UsbClassMatch, UsbProbeError};
use crate::device::USBDevice;
use crate::r8152::{find_rtl_endpoints, find_rtl_interrupt_endpoint};

// ── Vendor control transport ───────────────────────────────────────

/// `bRequest` access classes (audit §3; Linux `ax88179_178a.c:30–34`).
pub const AX_ACCESS_MAC: u8 = 0x01;
pub const AX_ACCESS_PHY: u8 = 0x02;
pub const AX_ACCESS_EEPROM: u8 = 0x04;
pub const AX_ACCESS_EFUS: u8 = 0x05;
pub const AX_RELOAD_EEPROM_EFUSE: u8 = 0x06;

/// `bmRequestType` for vendor reads/writes (device recipient).
pub const AX_REQT_READ: u8 = 0xC0;
pub const AX_REQT_WRITE: u8 = 0x40;

// ── MAC register map (driver-observed; see module docs) ────────────

/// RX control (Linux `:54`; bits `:55–63`).
pub const AX_RX_CTL: u16 = 0x0B;
pub const AX_RX_CTL_DROPCRCERR: u16 = 0x0100;
pub const AX_RX_CTL_IPE: u16 = 0x0200;
pub const AX_RX_CTL_START: u16 = 0x0080;
pub const AX_RX_CTL_AP: u16 = 0x0020;
pub const AX_RX_CTL_AM: u16 = 0x0010;
pub const AX_RX_CTL_AMALL: u16 = 0x0002;
pub const AX_RX_CTL_AB: u16 = 0x0008;
pub const AX_RX_CTL_PRO: u16 = 0x0001;
pub const AX_RX_CTL_STOP: u16 = 0x0000;

/// RX control programmed by the reset sequence (Linux `ax88179_reset`):
/// the single source of truth for the record's tracked `rxctl` — the
/// link-change path restores exactly this value, and the multicast
/// hook replaces it with its own computed value.
pub const AX_RX_CTL_RESET: u16 = AX_RX_CTL_DROPCRCERR
    | AX_RX_CTL_IPE
    | AX_RX_CTL_START
    | AX_RX_CTL_AP
    | AX_RX_CTL_AMALL
    | AX_RX_CTL_AB;

/// Station address, 6 bytes, read via MAC access (Linux `:65`).
pub const AX_NODE_ID: u16 = 0x10;
/// Medium status / mode (Linux `:68`; bits `:69–76`).
pub const AX_MEDIUM_STATUS_MODE: u16 = 0x22;
pub const AX_MEDIUM_GIGAMODE: u16 = 0x01;
pub const AX_MEDIUM_FULL_DUPLEX: u16 = 0x02;
pub const AX_MEDIUM_RXFLOW_CTRLEN: u16 = 0x10;
pub const AX_MEDIUM_TXFLOW_CTRLEN: u16 = 0x20;
pub const AX_MEDIUM_RECEIVE_EN: u16 = 0x0100;
/// Monitor mode (Linux `:78`; bits `:79–82`).
pub const AX_MONITOR_MOD: u16 = 0x24;
pub const AX_MONITOR_MODE_RWMP: u8 = 0x04;
pub const AX_MONITOR_MODE_PMEPOL: u8 = 0x20;
pub const AX_MONITOR_MODE_PMETYPE: u8 = 0x40;
/// PHY power / reset control (Linux `:89`; bits `:90–92`).
pub const AX_PHYPWR_RSTCTL: u16 = 0x26;
pub const AX_PHYPWR_RSTCTL_IPRL: u16 = 0x0020;
pub const AX_PHYPWR_RSTCTL_AT: u16 = 0x1000;
/// RX bulk-IN queue control (Linux `:94`).
pub const AX_RX_BULKIN_QCTRL: u16 = 0x2E;
/// Clock select (Linux `:95`; bits `:96–98`).
pub const AX_CLK_SELECT: u16 = 0x33;
pub const AX_CLK_SELECT_BCS: u8 = 0x01;
pub const AX_CLK_SELECT_ACS: u8 = 0x02;
pub const AX_CLK_SELECT_ULR: u8 = 0x08;
/// Pause watermarks: register addresses (Linux `:35–36`).
pub const AX_PAUSE_WATERLVL_LOW: u16 = 0x54;
pub const AX_PAUSE_WATERLVL_HIGH: u16 = 0x55;
/// Checksum offload controls (Linux `:100–112`). Written by the
/// reset sequence (mirroring Linux reset) but NOT advertised via
/// `set_offloads` in v1 — advertisement is audit item 2.
pub const AX_RXCOE_CTL: u16 = 0x34;
pub const AX_TXCOE_CTL: u16 = 0x35;
pub const AX_COE_IP: u8 = 0x01;
pub const AX_COE_TCP: u8 = 0x02;
pub const AX_COE_UDP: u8 = 0x04;
pub const AX_COE_TCPV6: u8 = 0x20;
pub const AX_COE_UDPV6: u8 = 0x40;

// ── Link-status interrupt + link-change (audit item 2) ───────────

/// Link bit in the interrupt event's first word (Linux `:22`,
/// `ax88179_status`: `link = (intdata1 & AX_INT_PPLS_LINK) >> 16`).
pub const AX_INT_PPLS_LINK: u32 = 1 << 16;

/// USB link-status byte (Linux `:38–40`).
pub const AX_PHYSICAL_LINK_STATUS: u16 = 0x02;
pub const AX_USB_SS: u8 = 0x04;
pub const AX_USB_HS: u8 = 0x02;

/// PHY status page (Linux `:116–121`).
pub const GMII_PHY_PHYSR: u16 = 0x11;
pub const GMII_PHY_PHYSR_SMASK: u16 = 0xC000;
pub const GMII_PHY_PHYSR_GIGA: u16 = 0x8000;
pub const GMII_PHY_PHYSR_100: u16 = 0x4000;
pub const GMII_PHY_PHYSR_FULL: u16 = 0x2000;
pub const GMII_PHY_PHYSR_LINK: u16 = 0x0400;

/// Medium-mode bits used only by the link-change path (Linux
/// `:69–76`); the reset-programmed bits live above.
pub const AX_MEDIUM_EN_125MHZ: u16 = 0x08;
pub const AX_MEDIUM_PS: u16 = 0x200;

/// Bulk-IN queue table, indexed by link speed + USB speed
/// (Linux `AX88179_BULKIN_SIZE`: [0] SS giga, [1] HS giga,
/// [2] SS/HS 100M, [3] everything else). Entry [0] is also the
/// reset-programmed value (see `RESET_POST`).
pub const AX_RX_BULKIN_SIZE: &[[u8; 5]] = &[
    [0x07, 0x4F, 0x00, 0x12, 0xFF],
    [0x07, 0x20, 0x03, 0x16, 0xFF],
    [0x07, 0xAE, 0x07, 0x18, 0xFF],
    [0x07, 0xCC, 0x4C, 0x18, 0x08],
];

/// TX FIFO quiesce poll (Linux `ax88179_link_reset`): a vendor IN
/// request (`bRequest` 0x81, `wValue` 0x8c, 4 bytes) whose bit
/// 0x40000000 reports TX FIFO busy. The register meaning is
/// driver-observed, not datasheet-verified — only the wire
/// behavior (request, bit, 100 ms budget) is pinned.
pub const AX_TX_FIFO_STATUS_REQ: u8 = 0x81;
pub const AX_TX_FIFO_STATUS_VALUE: u16 = 0x8C;
pub const AX_TX_FIFO_BUSY: u32 = 0x4000_0000;

/// Multicast filter (Linux `:20–21`, `:66`, `:867–905`).
pub const AX_MULFLTARY: u16 = 0x16;
pub const AX_MCAST_FLTSIZE: usize = 8;
pub const AX_MAX_MCAST: usize = 64;

// ── PHY (IEEE 802.3 Clause 22 standard registers) ──────────────────

/// Internal GbE PHY id (audit §3; Linux `:17`).
pub const AX_PHY_ID: u16 = 0x03;
/// Standard Clause 22 registers (IEEE 802.3, not ASIX-proprietary).
pub const MII_BMCR: u16 = 0x00;
pub const MII_BMSR: u16 = 0x01;
pub const BMCR_ANENABLE: u16 = 0x1000;
pub const BMCR_ANRESTART: u16 = 0x0200;
/// BMSR link-status bit (latched-low: read twice for current state).
pub const BMSR_LSTATUS: u16 = 0x0004;

// ── RX metadata bits (Linux `:23–29`) ───────────────────────────────

pub const AX_RXHDR_L3CSUM_ERR: u32 = 2;
pub const AX_RXHDR_L4CSUM_ERR: u32 = 1;
pub const AX_RXHDR_CRC_ERR: u32 = 1 << 29;
pub const AX_RXHDR_DROP_ERR: u32 = 1 << 31;

/// RX bulk buffer size (Linux reset: `rx_urb_size = 1024 * 20`).
pub const AX_RX_BUF_LEN: usize = 20 * 1024;

/// Ethernet header length (destination + source + ethertype).
const ETH_HLEN: usize = 14;

// ── SETUP packing (pure; fixture-pinned) ────────────────────────────

/// MAC access: `wValue` = register, `wIndex` = byte count. The count
/// rule is the shipped driver's observed packing (e.g. a 2-byte
/// `AX_PHYPWR_RSTCTL` write carries `wIndex = 2`, a 6-byte
/// `AX_NODE_ID` read carries `wIndex = 6`).
pub fn ax_mac_setup(read: bool, reg: u16, len: u16) -> (u8, u8, u16, u16) {
    (
        if read { AX_REQT_READ } else { AX_REQT_WRITE },
        AX_ACCESS_MAC,
        reg,
        len,
    )
}

/// PHY access: `wValue` = PHY id, `wIndex` = register. This CORRECTS
/// audit §3 (see module docs): the MDIO path passes
/// `value = phy_id, index = loc` into `usbnet_read_cmd`, which maps
/// them verbatim to `wValue`/`wIndex`.
pub fn ax_phy_setup(read: bool, reg: u16) -> (u8, u8, u16, u16) {
    (
        if read { AX_REQT_READ } else { AX_REQT_WRITE },
        AX_ACCESS_PHY,
        AX_PHY_ID,
        reg,
    )
}

/// EEPROM access for the auto-detach probe: `wValue` = word address,
/// `wIndex` = 1 as observed in the shipped driver's auto-detach read
/// (`0x43`, `1`, 2 bytes). The `wIndex` semantics here are
/// driver-observed, not datasheet-verified.
pub fn ax_eeprom_setup(read: bool, word: u16) -> (u8, u8, u16, u16) {
    (
        if read { AX_REQT_READ } else { AX_REQT_WRITE },
        AX_ACCESS_EEPROM,
        word,
        1,
    )
}

// ── Pure datapath functions (fixture-pinned) ────────────────────────

/// Linux `is_valid_ether_addr` equivalent: unicast (bit 0 of byte 0
/// clear), not all-zero. Broadcast is multicast, so it fails here.
pub fn mac_is_valid(mac: &[u8; 6]) -> bool {
    mac[0] & 0x01 == 0 && mac.iter().any(|b| *b != 0)
}

/// TX segment: 8-byte header (`tx_hdr1` = frame length LE,
/// `tx_hdr2` = 0 in v1 — no TSO — plus the `0x80008000` padding flag
/// when `(len + 8) % maxpacket == 0`) followed by the frame.
/// A zero `max_packet` (broken descriptor; bind rejects it) disables
/// the padding flag rather than dividing by zero.
pub fn build_tx_segment(frame: &[u8], max_packet: u16) -> Vec<u8> {
    let mut seg = Vec::with_capacity(frame.len() + 8);
    let hdr1 = frame.len() as u32;
    let mut hdr2: u32 = 0;
    if max_packet > 0 && (frame.len() + 8) % (max_packet as usize) == 0 {
        hdr2 |= 0x8000_8000;
    }
    seg.extend_from_slice(&hdr1.to_le_bytes());
    seg.extend_from_slice(&hdr2.to_le_bytes());
    seg.extend_from_slice(frame);
    seg
}

/// Outcome of parsing one RX aggregation buffer.
#[derive(Debug)]
pub struct AxRxOutcome {
    /// Frames extracted (pseudo-header stripped), in wire order.
    pub frames: Vec<Vec<u8>>,
    /// Entries skipped: CRC/DROP errors, runts, and the stop-on-
    /// truncation count (the truncated entry itself, if any).
    pub dropped: usize,
}

/// Parse an AX88179 RX aggregation buffer (Linux `ax88179_rx_fixup`
/// algorithm, adapted to return owned frames instead of mutating an
/// skb chain):
/// - trailing 32-bit `rx_hdr` = `pkt_cnt` (low half) + `hdr_off`
///   (high half) for the per-packet metadata array;
/// - per-packet metadata word: `pkt_len` = bits 16–28 (`& 0x1fff`),
///   `CRC_ERR` bit 29, `DROP_ERR` bit 31; `pkt_len` includes the
///   2-byte IP-alignment pseudo-header, frames are padded to
///   8-byte boundaries;
/// - dummy headers (`pkt_len == 0`) are skipped — current firmware
///   emits 2 metadata entries per packet (entry + dummy);
/// - a metadata array running past the buffer, a zero `pkt_cnt`,
///   or a short buffer yields no frames (fail-closed);
/// - a packet whose padded length overruns the data region stops
///   the parse, keeping already-extracted frames.
pub fn parse_rx_aggregate(buf: &[u8]) -> AxRxOutcome {
    let mut out = AxRxOutcome {
        frames: Vec::new(),
        dropped: 0,
    };
    if buf.len() < 4 {
        return out;
    }
    let body_len = buf.len() - 4;
    let rx_hdr = u32::from_le_bytes([
        buf[body_len],
        buf[body_len + 1],
        buf[body_len + 2],
        buf[body_len + 3],
    ]);
    let pkt_cnt = (rx_hdr & 0xFFFF) as usize;
    let hdr_off = (rx_hdr >> 16) as usize;
    if pkt_cnt == 0 {
        return out;
    }
    let meta_len = match pkt_cnt.checked_mul(4) {
        Some(m) => m,
        None => return out,
    };
    if meta_len + hdr_off > body_len {
        // Truncated metadata array: drop the whole buffer.
        return out;
    }
    let mut cursor = 0usize;
    for i in 0..pkt_cnt {
        let woff = hdr_off + i * 4;
        let word_bytes = match buf.get(woff..woff + 4) {
            Some(b) => b,
            None => break,
        };
        let word = u32::from_le_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        let pkt_len = ((word >> 16) & 0x1FFF) as usize;
        if pkt_len == 0 {
            // Dummy header: metadata-only, consumes no data bytes.
            continue;
        }
        let pkt_len_plus_padd = (pkt_len + 7) & !7;
        let remaining = hdr_off - cursor;
        if pkt_len_plus_padd > remaining {
            // Truncated packet data: stop, keep prior frames.
            out.dropped += 1;
            break;
        }
        if word & (AX_RXHDR_CRC_ERR | AX_RXHDR_DROP_ERR) != 0 || pkt_len < 2 + ETH_HLEN {
            out.dropped += 1;
            cursor += pkt_len_plus_padd;
            continue;
        }
        out.frames.push(buf[cursor + 2..cursor + pkt_len].to_vec());
        cursor += pkt_len_plus_padd;
    }
    out
}

// ── Item-2 pure functions (fixture-pinned) ────────────────────────

/// Decode one interrupt-IN transfer (Linux `ax88179_status`):
/// the event is two little-endian words; link state is bit 16
/// of the first. Transfers shorter than 8 bytes carry no event
/// and are ignored, exactly like the reference.
pub fn ax_interrupt_link(buf: &[u8]) -> Option<bool> {
    if buf.len() < 8 {
        return None;
    }
    let intdata1 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Some(intdata1 & AX_INT_PPLS_LINK != 0)
}

/// Link-change computation (Linux `ax88179_link_reset`, minus the
/// EEE check and the jumbo branch — neither is in this lane):
/// from the USB link-status byte and the PHY status page, the
/// medium-mode word, the bulk-IN queue entry, the negotiated
/// speed in Mbps, and the duplex. `None` when the PHY reports
/// no link. The caller programs bulkin + medium mode and
/// publishes speed + duplex; it must NOT publish a mode on
/// `None` (the interrupt's carrier verdict still stands —
/// Linux leaves carrier up when `link_reset` finds no PHY link).
pub fn ax_link_mode(
    link_sts: u8,
    physr: u16,
) -> Option<(u16, [u8; 5], u32, narf_net::iface::LinkDuplex)> {
    if physr & GMII_PHY_PHYSR_LINK == 0 {
        return None;
    }
    let mut mode = AX_MEDIUM_RECEIVE_EN | AX_MEDIUM_TXFLOW_CTRLEN | AX_MEDIUM_RXFLOW_CTRLEN;
    let (bulkin, speed) = match physr & GMII_PHY_PHYSR_SMASK {
        GMII_PHY_PHYSR_GIGA => {
            mode |= AX_MEDIUM_GIGAMODE | AX_MEDIUM_EN_125MHZ;
            let b = if link_sts & AX_USB_SS != 0 {
                AX_RX_BULKIN_SIZE[0]
            } else if link_sts & AX_USB_HS != 0 {
                AX_RX_BULKIN_SIZE[1]
            } else {
                AX_RX_BULKIN_SIZE[3]
            };
            (b, 1000)
        }
        GMII_PHY_PHYSR_100 => {
            mode |= AX_MEDIUM_PS;
            let b = if link_sts & (AX_USB_SS | AX_USB_HS) != 0 {
                AX_RX_BULKIN_SIZE[2]
            } else {
                AX_RX_BULKIN_SIZE[3]
            };
            (b, 100)
        }
        _ => (AX_RX_BULKIN_SIZE[3], 10),
    };
    let duplex = if physr & GMII_PHY_PHYSR_FULL != 0 {
        mode |= AX_MEDIUM_FULL_DUPLEX;
        narf_net::iface::LinkDuplex::Full
    } else {
        narf_net::iface::LinkDuplex::Half
    };
    Some((mode, bulkin, speed, duplex))
}

/// Ethernet CRC for the multicast filter (Linux `ether_crc`:
/// `bitrev32(crc32_le(~0, addr, 6))`, `include/linux/crc32.h`).
/// Bitwise reflected CRC-32 (polynomial 0xEDB88320), seeded
/// all-ones, with NO final inversion (that is the `crc32_le`
/// semantic — the final xor belongs to zlib-style callers, not
/// here); the 32-bit reversal is `u32::reverse_bits`.
pub fn ax_ether_crc(addr: &[u8; 6]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in addr.iter() {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc.reverse_bits()
}

/// Multicast programming (Linux `ax88179_set_multicast`, exact):
/// from (promiscuous, all-multicast, multicast addresses) to
/// (RX control, filter). The filter is `Some` only for a
/// non-empty filtered list; promiscuous wins over all-multicast
/// (the Linux if/else-if chain); more than `AX_MAX_MCAST`
/// addresses fall back to accept-all-multicast. Note the base
/// drops `DROPCRCERR` and `AP` relative to `AX_RX_CTL_RESET` —
/// Linux recomputes from the same base on every call, and
/// directed delivery is unaffected (CRC-error frames are still
/// dropped by the RX parse; `AP` is never the directed gate,
/// since Linux filtering works without it).
pub fn ax_multicast_program(
    promiscuous: bool,
    all_multicast: bool,
    addrs: &[[u8; 6]],
) -> (u16, Option<[u8; AX_MCAST_FLTSIZE]>) {
    let base = AX_RX_CTL_START | AX_RX_CTL_AB | AX_RX_CTL_IPE;
    if promiscuous {
        (base | AX_RX_CTL_PRO, None)
    } else if all_multicast || addrs.len() > AX_MAX_MCAST {
        (base | AX_RX_CTL_AMALL, None)
    } else if addrs.is_empty() {
        (base, None)
    } else {
        let mut filter = [0u8; AX_MCAST_FLTSIZE];
        for addr in addrs {
            let bits = ax_ether_crc(addr) >> 26;
            filter[(bits >> 3) as usize] |= 1 << (bits & 7);
        }
        (base | AX_RX_CTL_AM, Some(filter))
    }
}

/// Offload capabilities advertised at bind (mirrors
/// `r8152_offloads`): TX checksum generation is real — the chip
/// computes TCP/UDP checksums whenever TXCOE is programmed
/// (bind), and Linux `tx_fixup` sets no per-frame checksum bit
/// (only GSO size + the padding flag). RX checksum metadata is
/// NOT advertised: the RX metadata's L3/L4 error bits have no
/// delivery channel in `on_rx_frame_from` (same limitation as
/// r8152), so csum-error frames keep being delivered and the
/// stack revalidates (pinned by `rx_runt_and_csum_bits`).
/// TSO and VLAN insertion are not advertised: no GSO size is
/// ever programmed (`tx_hdr2` stays 0) and VLAN handling is
/// UNGROUNDED per audit §6.
pub fn ax88179_offloads() -> narf_net::OffloadCapabilities {
    narf_net::OffloadCapabilities {
        tx_checksum: true,
        rx_checksum: false,
        max_tso_bytes: 0,
        vlan_insert: false,
    }
}

/// TX offload acceptance for `ax_send_frame`: TCP/UDP checksum
/// requests are accepted (chip-computed, see `ax88179_offloads`);
/// SCTP is rejected (no TXCOE bit covers it — same rule as
/// r8152); TSO and VLAN insertion are rejected (unprogrammed).
pub fn ax_tx_meta_accepted(meta: narf_net::TxMeta) -> bool {
    !matches!(meta.csum_l4, Some(narf_net::L4CsumKind::Sctp))
        && meta.tso_mss.is_none()
        && meta.vlan_tag.is_none()
}

// ── Reset program (ordered MAC writes; fixture-pinned) ─────────────

/// One fixed reset write: register + payload. The executor derives
/// `wIndex` = payload length (the MAC packing rule), so the table
/// cannot drift out of sync with the wire format.
#[derive(Debug)]
pub struct AxMacWrite {
    pub reg: u16,
    pub data: &'static [u8],
}

/// Reset writes before the clock-select step (Linux reset order):
/// power up the PHY (`0`), then set IPRL. A 500 ms sleep follows.
pub const RESET_PRE: &[AxMacWrite] = &[
    AxMacWrite {
        reg: AX_PHYPWR_RSTCTL,
        data: &[0x00, 0x00],
    },
    AxMacWrite {
        reg: AX_PHYPWR_RSTCTL,
        data: &[0x20, 0x00],
    },
];

/// Clock-select write (ACS | BCS). A 200 ms sleep follows.
pub const RESET_CLK: AxMacWrite = AxMacWrite {
    reg: AX_CLK_SELECT,
    data: &[AX_CLK_SELECT_ACS | AX_CLK_SELECT_BCS],
};

/// Reset writes after the MAC read (Linux reset order): bulk-IN
/// queue config (`BULKIN_SIZE[0]`, the SuperSpeed/giga entry —
/// entries [1]–[3] are link-speed variants for the link-change
/// path, audit item 2), pause watermarks, checksum offload
/// controls (advertised by item 2 via `set_offloads`), RX control
/// (`AX_RX_CTL_RESET`), monitor mode, medium mode (giga +
/// full-duplex + flow control + receive enable).
pub const RESET_POST: &[AxMacWrite] = &[
    AxMacWrite {
        reg: AX_RX_BULKIN_QCTRL,
        data: &[0x07, 0x4F, 0x00, 0x12, 0xFF],
    },
    AxMacWrite {
        reg: AX_PAUSE_WATERLVL_HIGH,
        data: &[0x34],
    },
    AxMacWrite {
        reg: AX_PAUSE_WATERLVL_LOW,
        data: &[0x52],
    },
    AxMacWrite {
        reg: AX_RXCOE_CTL,
        data: &[AX_COE_IP | AX_COE_TCP | AX_COE_UDP | AX_COE_TCPV6 | AX_COE_UDPV6],
    },
    AxMacWrite {
        reg: AX_TXCOE_CTL,
        data: &[AX_COE_IP | AX_COE_TCP | AX_COE_UDP | AX_COE_TCPV6 | AX_COE_UDPV6],
    },
    AxMacWrite {
        reg: AX_RX_CTL,
        data: &[(AX_RX_CTL_RESET as u8), ((AX_RX_CTL_RESET >> 8) as u8)],
    },
    AxMacWrite {
        reg: AX_MONITOR_MOD,
        data: &[AX_MONITOR_MODE_PMETYPE | AX_MONITOR_MODE_PMEPOL | AX_MONITOR_MODE_RWMP],
    },
    AxMacWrite {
        reg: AX_MEDIUM_STATUS_MODE,
        data: &[
            (AX_MEDIUM_RECEIVE_EN
                | AX_MEDIUM_TXFLOW_CTRLEN
                | AX_MEDIUM_RXFLOW_CTRLEN
                | AX_MEDIUM_FULL_DUPLEX
                | AX_MEDIUM_GIGAMODE) as u8,
            ((AX_MEDIUM_RECEIVE_EN
                | AX_MEDIUM_TXFLOW_CTRLEN
                | AX_MEDIUM_RXFLOW_CTRLEN
                | AX_MEDIUM_FULL_DUPLEX
                | AX_MEDIUM_GIGAMODE)
                >> 8) as u8,
        ],
    },
];

// ── Async control helpers ──────────────────────────────────────────

/// Raw vendor read: `bRequest` = access class, `wValue`/`wIndex` as
/// packed by the `ax_*_setup` helpers. Fails on short transfers.
async fn ax_read(
    dev: &USBDevice,
    access: u8,
    value: u16,
    index: u16,
    out: &mut [u8],
) -> Result<(), ()> {
    let n = dev
        .control_in(AX_REQT_READ, access, value, index, out)
        .await
        .map_err(|_| ())?;
    if n != out.len() {
        return Err(());
    }
    Ok(())
}

/// Raw vendor write. Fails on short transfers.
async fn ax_write(
    dev: &USBDevice,
    access: u8,
    value: u16,
    index: u16,
    data: &[u8],
) -> Result<(), ()> {
    let n = dev
        .control_out(AX_REQT_WRITE, access, value, index, data)
        .await
        .map_err(|_| ())?;
    if n != data.len() {
        return Err(());
    }
    Ok(())
}

/// Execute one fixed reset write (MAC access, `wIndex` = length).
async fn ax_write_mac(dev: &USBDevice, w: &AxMacWrite) -> Result<(), ()> {
    let (_, _, value, index) = ax_mac_setup(false, w.reg, w.data.len() as u16);
    ax_write(dev, AX_ACCESS_MAC, value, index, w.data).await
}

async fn ax_read_u8(dev: &USBDevice, access: u8, value: u16, index: u16) -> Result<u8, ()> {
    let mut buf = [0u8; 1];
    ax_read(dev, access, value, index, &mut buf).await?;
    Ok(buf[0])
}

async fn ax_read_u16(dev: &USBDevice, access: u8, value: u16, index: u16) -> Result<u16, ()> {
    let mut buf = [0u8; 2];
    ax_read(dev, access, value, index, &mut buf).await?;
    Ok(u16::from_le_bytes(buf))
}

async fn ax_write_u8(dev: &USBDevice, access: u8, value: u16, index: u16, v: u8) -> Result<(), ()> {
    ax_write(dev, access, value, index, &[v]).await
}

async fn ax_write_u16(
    dev: &USBDevice,
    access: u8,
    value: u16,
    index: u16,
    v: u16,
) -> Result<(), ()> {
    ax_write(dev, access, value, index, &v.to_le_bytes()).await
}

/// Clause 22 PHY read via `AX_ACCESS_PHY` (packing per `ax_phy_setup`).
async fn phy_read(dev: &USBDevice, reg: u16) -> Result<u16, ()> {
    let (_, _, value, index) = ax_phy_setup(true, reg);
    ax_read_u16(dev, AX_ACCESS_PHY, value, index).await
}

/// Clause 22 PHY write via `AX_ACCESS_PHY`.
async fn phy_write(dev: &USBDevice, reg: u16, v: u16) -> Result<(), ()> {
    let (_, _, value, index) = ax_phy_setup(false, reg);
    ax_write_u16(dev, AX_ACCESS_PHY, value, index, v).await
}

/// Read the station address from `AX_NODE_ID` (6 bytes, MAC access).
async fn read_station_address(dev: &USBDevice) -> Result<[u8; 6], ()> {
    let (_, _, value, index) = ax_mac_setup(true, AX_NODE_ID, 6);
    let mut mac = [0u8; 6];
    ax_read(dev, AX_ACCESS_MAC, value, index, &mut mac).await?;
    if !mac_is_valid(&mac) {
        return Err(());
    }
    Ok(mac)
}

/// Best-effort "Ethernet PHY Auto Detach" (Linux `ax88179_auto_detach`):
/// if the EEPROM word at `0x43` is present and has bit `0x0100` set,
/// set `AX_CLK_SELECT_ULR` and `AX_PHYPWR_RSTCTL_AT`. Any failure
/// (including a failed EEPROM read) skips the step silently — the
/// reset proceeds regardless, exactly like the reference.
async fn auto_detach_best_effort(dev: &USBDevice) {
    let (_, _, value, index) = ax_eeprom_setup(true, 0x43);
    let Ok(word) = ax_read_u16(dev, AX_ACCESS_EEPROM, value, index).await else {
        return;
    };
    if word == 0xFFFF || word & 0x0100 == 0 {
        return;
    }
    let Ok(clk) = ax_read_u8(dev, AX_ACCESS_MAC, AX_CLK_SELECT, 1).await else {
        return;
    };
    if ax_write_u8(
        dev,
        AX_ACCESS_MAC,
        AX_CLK_SELECT,
        1,
        clk | AX_CLK_SELECT_ULR,
    )
    .await
    .is_err()
    {
        return;
    }
    let Ok(rst) = ax_read_u16(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2).await else {
        return;
    };
    let _ = ax_write_u16(
        dev,
        AX_ACCESS_MAC,
        AX_PHYPWR_RSTCTL,
        2,
        rst | AX_PHYPWR_RSTCTL_AT,
    )
    .await;
}

// ── Device table + publication ─────────────────────────────────────

/// Bound AX88179 device record (mirrors the r8152 record shape).
#[derive(Debug)]
pub struct AxDevice {
    /// Owning xHCI controller id ([`Xhci::id`]): slot ids are only
    /// unique within one controller, so TX and detach resolve the
    /// controller through this field, never a global accessor.
    pub controller: u8,
    pub slot_id: u8,
    pub mac: [u8; 6],
    pub bulk_in_dci: u8,
    pub bulk_out_dci: u8,
    /// Bulk-OUT endpoint max packet (TX padding-flag divisor).
    pub out_max_packet: u16,
    /// Interrupt-IN endpoint DCI, when the device exposes one
    /// (`None` = BMSR polling is the only carrier source).
    pub int_dci: Option<u8>,
    /// Currently programmed RX control. Bind sets
    /// `AX_RX_CTL_RESET`; the multicast hook and the link-change
    /// path keep it in sync with hardware. Read under the lock,
    /// never held across an await (AGENTS.md lock rule).
    pub rxctl: u16,
    /// Assigned `narf_net::iface` name (`usb-ax{N}`).
    pub iface_name: String,
    pub pump_running: bool,
    /// Last published carrier state (interrupt event or BMSR
    /// sample, whichever changed it most recently).
    pub link_up: bool,
    /// Detach tombstone: set by `detach_ax_slot`. The pump exits
    /// when `pump_running` clears; TX resolves to `None`.
    /// Records are never removed, because net-registry TX
    /// cookies are record indices — removing a record would
    /// retarget every later device's cookie at the wrong
    /// device (the ECM/NCM rule).
    pub detached: bool,
}

/// System-wide registry of bound AX88179 devices.
pub static AX_DEVICES: IrqSafeSpinLock<Vec<AxDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Resolve a device-record index to its TX target
/// `(controller, slot_id, bulk_out_dci, out_max_packet)`. The send trampoline
/// routes through this — and only this — so a frame can never be
/// emitted on a different device's endpoint.
pub fn tx_target(idx: usize) -> Option<(u8, u8, u8, u16)> {
    let g = AX_DEVICES.lock();
    g.get(idx)
        .filter(|d| !d.detached)
        .map(|d| (d.controller, d.slot_id, d.bulk_out_dci, d.out_max_packet))
}

/// Ship one built TX segment on the device's bulk-OUT endpoint.
/// The net stack's send hook is sync; bridge to the async bulk_out
/// via block_on (called from TX paths that are not inside an
/// executor poll — same contract as r8152's send). No lock is held
/// across the block_on (the lock rule in `AGENTS.md`).
fn ax_send_segment(controller: u8, slot_id: u8, bulk_out_dci: u8, seg: &[u8]) -> Result<(), ()> {
    let c = crate::xhci::controller_by_id(controller).ok_or(())?;
    narf_scheduler::block_on(async move { c.bulk_out(slot_id, bulk_out_dci, seg).await })
        .map_err(|_| ())?;
    Ok(())
}

/// Send one frame for the device record at `idx`. Offload
/// requests the chip cannot honour (SCTP checksum, TSO, VLAN
/// insert — see `ax_tx_meta_accepted`) are rejected rather than
/// sent with a partial offload; a request here is a
/// stack/driver mismatch, not a normal path, because the
/// advertised caps (`ax88179_offloads`) never promise them.
fn ax_send_frame(idx: usize, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    if !ax_tx_meta_accepted(meta) {
        return Err(());
    }
    let (controller, slot_id, bulk_out_dci, out_max_packet) = tx_target(idx).ok_or(())?;
    let seg = build_tx_segment(frame, out_max_packet);
    ax_send_segment(controller, slot_id, bulk_out_dci, &seg)
}

/// `SendCtxFn` trampoline: the cookie is the device-record index
/// assigned at registration time.
fn ax_send_ctx(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    ax_send_frame(cookie as usize, frame, meta)
}

/// Sample carrier state from the PHY BMSR link bit. The bit is
/// latched-low per IEEE 802.3, so it is read twice and the second
/// read is used (the first read clears a latched-down state).
/// Carrier only — speed/duplex come from the interrupt
/// link-change path (item 2); this poll stays as the fallback
/// carrier source when no interrupt endpoint exists, and as a
/// reconciler when an interrupt event is missed. Publishes on
/// change only, so it never overwrites the interrupt path's
/// speed/duplex for an unchanged carrier state.
async fn sample_link(dev: &USBDevice, idx: usize) {
    let Ok(_) = phy_read(dev, MII_BMSR).await else {
        return;
    };
    let Ok(bmsr) = phy_read(dev, MII_BMSR).await else {
        return;
    };
    let up = bmsr & BMSR_LSTATUS != 0;
    let name = {
        let mut g = AX_DEVICES.lock();
        let Some(rec) = g.get_mut(idx) else {
            return;
        };
        if rec.link_up == up {
            return;
        }
        rec.link_up = up;
        rec.iface_name.clone()
    };
    narf_net::iface::set_link_metadata(&name, up, None, None);
}

// ── Item-2 runtime paths ───────────────────────────────────────────

/// `DeviceControl` for one bound AX88179 record: programs the
/// multicast filter + RX control from the stack's `DeviceConfig`
/// (Linux `ax88179_set_multicast`). This is the first in-tree
/// `DeviceControl` implementation; the trait is sync while the
/// hardware path is async, so `configure` bridges via `block_on`
/// (same contract as `ax_send_segment`: the caller is not inside
/// an executor poll, and no lock is held across the `block_on` —
/// AGENTS.md lock rule). The record's tracked `rxctl` is updated
/// only after both writes succeed; a failed write leaves
/// hardware and record unchanged, and the stack keeps its old
/// metadata on `Err` (per the `DeviceConfig` contract: "an error
/// leaves metadata unchanged").
pub struct AxDeviceControl {
    device: Arc<USBDevice>,
    idx: usize,
}

// Manual `Debug` (`USBDevice` is `Clone`-only, so a derived impl
// would fail): slot + record index identify the binding.
impl core::fmt::Debug for AxDeviceControl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AxDeviceControl")
            .field("slot_id", &self.device.slot_id())
            .field("idx", &self.idx)
            .finish()
    }
}

impl narf_net::iface::DeviceControl for AxDeviceControl {
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
        let (rxctl, filter) = ax_multicast_program(config.promiscuous, config.all_multicast, &mc);
        // Detach check before touching hardware (re-checked
        // under the lock after the writes, before updating).
        {
            let g = AX_DEVICES.lock();
            if g.get(self.idx).map(|d| d.detached).unwrap_or(true) {
                return Err(ENODEV);
            }
        }
        let device = self.device.clone();
        let ok = narf_scheduler::block_on(async move {
            if let Some(f) = filter {
                ax_write(
                    &device,
                    AX_ACCESS_MAC,
                    AX_MULFLTARY,
                    AX_MCAST_FLTSIZE as u16,
                    &f,
                )
                .await?;
            }
            ax_write_u16(&device, AX_ACCESS_MAC, AX_RX_CTL, 2, rxctl).await
        })
        .is_ok();
        if !ok {
            return Err(EIO);
        }
        let mut g = AX_DEVICES.lock();
        let Some(rec) = g.get_mut(self.idx) else {
            return Err(ENODEV);
        };
        if rec.detached {
            return Err(ENODEV);
        }
        rec.rxctl = rxctl;
        Ok(())
    }
}

/// Link-change path (Linux `ax88179_link_reset`, minus the EEE
/// check and the jumbo branch — neither is in this lane).
/// Quiesces TX (STOP/restore + FIFO poll, 100 ms budget: 100
/// iterations of up to 1 ms), reads link status + PHYSR,
/// programs bulkin + medium mode. Returns the negotiated
/// (speed Mbps, duplex) on success, `None` when the PHY
/// reports no link or any transfer fails. On FIFO-poll
/// timeout the receiver is left running on the old medium
/// config (rxctl restored, no reprogramming) — the same
/// early return Linux makes — and the caller still publishes
/// the interrupt's carrier verdict with unknown mode.
async fn ax_link_change(dev: &USBDevice, idx: usize) -> Option<(u32, narf_net::iface::LinkDuplex)> {
    // Tracked rxctl, read before any await (no lock across
    // awaits). A multicast configure landing mid-path may
    // restore a newer rxctl afterwards; the next link event
    // reconciles — last writer wins, same as the two carrier
    // publishers.
    let rxctl = {
        let g = AX_DEVICES.lock();
        g.get(idx).map(|d| d.rxctl).unwrap_or(AX_RX_CTL_RESET)
    };
    let mut drained = false;
    for _ in 0..100 {
        if ax_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, AX_RX_CTL_STOP)
            .await
            .is_err()
        {
            break;
        }
        if ax_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, rxctl)
            .await
            .is_err()
        {
            break;
        }
        let mut sts = [0u8; 4];
        // A failed read counts as still-busy: the budget
        // expires safely instead of programming blind.
        if let Ok(4) = dev
            .control_in(
                AX_REQT_READ,
                AX_TX_FIFO_STATUS_REQ,
                AX_TX_FIFO_STATUS_VALUE,
                0,
                &mut sts,
            )
            .await
        {
            if u32::from_le_bytes(sts) & AX_TX_FIFO_BUSY == 0 {
                drained = true;
                break;
            }
        }
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
    }
    if !drained {
        let _ = ax_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, rxctl).await;
        return None;
    }
    let Ok(link_sts) = ax_read_u8(dev, AX_ACCESS_MAC, AX_PHYSICAL_LINK_STATUS, 1).await else {
        return None;
    };
    let Ok(physr) = phy_read(dev, GMII_PHY_PHYSR).await else {
        return None;
    };
    let (mode, bulkin, speed, duplex) = ax_link_mode(link_sts, physr)?;
    if ax_write(dev, AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, &bulkin)
        .await
        .is_err()
    {
        return None;
    }
    if ax_write_u16(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE, 2, mode)
        .await
        .is_err()
    {
        return None;
    }
    Some((speed, duplex))
}

/// Handle one decoded interrupt event (Linux `ax88179_status`
/// → `usbnet_link_change` → `link_reset`): publish + run the
/// link-change path on carrier change only. On link-up the
/// carrier verdict comes from the interrupt even when the
/// link-change path fails (unknown mode); on link-down the
/// stack clears speed/duplex (see `update_link_metadata`).
async fn handle_status_event(dev: &USBDevice, idx: usize, up: bool) {
    let name = {
        let mut g = AX_DEVICES.lock();
        let Some(rec) = g.get_mut(idx) else {
            return;
        };
        if rec.detached || rec.link_up == up {
            return;
        }
        rec.link_up = up;
        rec.iface_name.clone()
    };
    if !up {
        narf_net::iface::set_link_metadata(&name, false, None, None);
        return;
    }
    match ax_link_change(dev, idx).await {
        Some((speed, duplex)) => {
            narf_net::iface::set_link_metadata(&name, true, Some(speed), Some(duplex));
        }
        None => {
            narf_net::iface::set_link_metadata(&name, true, None, None);
        }
    }
}

/// Interrupt-IN status task (Linux `ax88179_status`): arm once,
/// then poll — `poll_interrupt_in` re-arms after every
/// completion (btusb pattern), so exactly one transfer stays
/// outstanding. Short transfers are ignored; only carrier
/// changes publish. Exits on detach or a bounded run of
/// consecutive transfer errors (a removed device surfaces as
/// persistent errors, same bound as the RX pump).
async fn status_task(device: Arc<USBDevice>, idx: usize) {
    let int_dci = {
        let g = AX_DEVICES.lock();
        match g.get(idx).and_then(|d| d.int_dci) {
            Some(d) => d,
            None => return,
        }
    };
    if device.arm_interrupt_in(int_dci, 8).is_err() {
        return;
    }
    let mut buf = [0u8; 8];
    let mut errors = 0u32;
    loop {
        let detached = {
            let g = AX_DEVICES.lock();
            g.get(idx).map(|d| d.detached).unwrap_or(true)
        };
        if detached {
            break;
        }
        match device.poll_interrupt_in(int_dci, &mut buf) {
            Ok(Some(n)) => {
                errors = 0;
                if let Some(up) = ax_interrupt_link(&buf[..n]) {
                    handle_status_event(&device, idx, up).await;
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

// ── Bind ───────────────────────────────────────────────────────────

/// Full bind for an addressed AX88179 device: configuration,
/// endpoint setup, reset sequence, station-address read, netdev
/// publication, RX pump. Returns the device-record index.
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
    // Bulk pair + optional interrupt endpoint in the vendor
    // (0xFF) interface: the r8152 finder shape, extended for
    // the interrupt endpoint (audit item 2) without changing
    // the bulk-pair result. A device without an interrupt
    // endpoint still binds — BMSR polling remains the carrier
    // source — but gets no status task and no link-change path.
    let (in_ep, out_ep) = find_rtl_endpoints(&cfg).ok_or(())?;
    let int_ep = find_rtl_interrupt_endpoint(&cfg);
    if in_ep.max_packet == 0 || out_ep.max_packet == 0 {
        return Err(());
    }
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
    let bulk_in_dci = ((in_ep.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = (out_ep.ep_addr & 0x0F) * 2;
    let int_dci = int_ep.map(|e| ((e.ep_addr & 0x0F) * 2) + 1);

    // ── Reset sequence (Linux `ax88179_reset` order, minus LED /
    // EEE-disable / WoL-check, which are cosmetic) ──
    // Power up the PHY, then set IPRL; the 500 ms wait follows.
    for w in RESET_PRE {
        ax_write_mac(&device, w).await?;
    }
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
    // Clock select (ACS | BCS); the 200 ms wait follows.
    ax_write_mac(&device, &RESET_CLK).await?;
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(200_000_000)).await;
    // Ethernet PHY auto-detach: best-effort, never fails bind.
    auto_detach_best_effort(&device).await;
    // Station address from the device itself — never invented.
    let mac = read_station_address(&device).await?;
    // Bulk-IN config, pause watermarks, offload controls, RX
    // control, monitor mode, medium mode (giga).
    for w in RESET_POST {
        ax_write_mac(&device, w).await?;
    }
    // Restart autoneg (read-modify-write: keep negotiated bits,
    // set ANENABLE | ANRESTART).
    let bmcr = phy_read(&device, MII_BMCR).await?;
    phy_write(&device, MII_BMCR, bmcr | BMCR_ANENABLE | BMCR_ANRESTART).await?;

    // ── Record + publication ──
    let idx = {
        let mut g = AX_DEVICES.lock();
        let idx = g.len();
        g.push(AxDevice {
            controller: device.controller().id(),
            slot_id: device.slot_id(),
            mac,
            bulk_in_dci,
            bulk_out_dci,
            out_max_packet: out_ep.max_packet,
            int_dci,
            rxctl: AX_RX_CTL_RESET,
            iface_name: format!("usb-ax{}", idx),
            pump_running: false,
            link_up: false,
            detached: false,
        });
        idx
    };
    let requested = {
        let g = AX_DEVICES.lock();
        g[idx].iface_name.clone()
    };
    let assigned = narf_net::iface::register_with_context(&requested, mac, idx as u64, ax_send_ctx);
    // Offload advertisement (audit item 2) + the multicast
    // control hook. The control install is best-effort: a
    // `false` return (iface gone) leaves the stack's
    // registry-only behavior, which is still correct — just
    // without driver-side filter programming.
    narf_net::iface::set_offloads(&assigned, ax88179_offloads());
    let _ = narf_net::iface::set_device_control(
        &assigned,
        Arc::new(AxDeviceControl {
            device: device.clone(),
            idx,
        }),
    );
    {
        let mut g = AX_DEVICES.lock();
        g[idx].iface_name = assigned.clone();
        g[idx].pump_running = true;
    }
    let _ = writeln!(
        narf_console::Writer,
        "  net: ax88179 bound slot {} as {} (mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        device.slot_id(),
        assigned,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    // Initial link sample, then the RX pump owns the device and
    // the status task owns the interrupt endpoint (when one
    // exists — otherwise the BMSR poll is the carrier source).
    sample_link(&device, idx).await;
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
/// clears (device removal — the detach follow-on — clears it) or
/// the record vanishes.
fn pump_should_continue(idx: usize) -> bool {
    let g = AX_DEVICES.lock();
    g.get(idx).map(|d| d.pump_running).unwrap_or(false)
}

/// Supervised RX pump: post bulk-IN reads, walk each aggregation
/// buffer, hand every frame to the stack. Stops after a bounded
/// run of consecutive transfer errors (a removed device surfaces
/// as persistent errors) or when the record's flag clears.
async fn rx_pump(device: Arc<USBDevice>, idx: usize) {
    let bulk_in_dci = {
        let g = AX_DEVICES.lock();
        let Some(rec) = g.get(idx) else {
            return;
        };
        rec.bulk_in_dci
    };
    let mut buf = vec![0u8; AX_RX_BUF_LEN];
    let mut errors = 0u32;
    let mut turns = 0u32;
    while pump_should_continue(idx) {
        match device.bulk_in(bulk_in_dci, &mut buf).await {
            Ok(n) if n > 0 => {
                errors = 0;
                let name = {
                    let g = AX_DEVICES.lock();
                    g.get(idx).map(|d| d.iface_name.clone())
                };
                if let Some(name) = name {
                    let outcome = parse_rx_aggregate(&buf[..n]);
                    for mut frame in outcome.frames {
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
    let mut g = AX_DEVICES.lock();
    if let Some(rec) = g.get_mut(idx) {
        rec.pump_running = false;
    }
}

// ── Class-registry probe ───────────────────────────────────────────

/// v1 admits the ASIX reference PID only. The audit's table lists
/// further PIDs as the same driver path; extending `MATCHES` is a
/// one-line follow-up once 1790 is proven on silicon.
const MATCHES: &[UsbClassMatch] = &[UsbClassMatch::vid_pid(0x0B95, 0x1790)];

fn probe(device: Arc<USBDevice>, _hub_port: Option<(u8, u8)>) -> Result<(), UsbProbeError> {
    // The registry probe is synchronous, but bind needs async
    // control transfers — spawn it (xpad precedent, same as r8152).
    narf_scheduler::spawn_stackful(async move {
        use core::fmt::Write;
        if bind(device).await.is_err() {
            let _ = writeln!(
                narf_console::Writer,
                "  net: ax88179 bind failed (no valid station address or config error)"
            );
        }
    });
    Ok(())
}

/// Detach hook for a slot: tombstone every AX88179 record bound to
/// it and unregister its net iface. The pump exits at its next
/// `pump_should_continue` check once `pump_running` clears, and
/// the status task exits at its next detached check;
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
/// the AX registry lock is held (UVC collect-then-unregister
/// pattern). A TX already past `tx_target` when detach lands
/// may still hit the wire; every later TX fail-closes.
///
/// Infallible bookkeeping, adapted to the [`UsbUnbindFn`]
/// contract with an unconditional `Ok(())` (#893: a hook
/// reports failure with `Err(())`, never by panicking).
pub fn detach_ax_slot(controller: u8, slot_id: u8) -> Result<(), ()> {
    let ifaces: Vec<String> = {
        let mut g = AX_DEVICES.lock();
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

/// Wholesale variant of [`detach_ax_slot`] for controller
/// recovery (`attach::detach_all_bindings`): tombstone every
/// AX88179 binding on `controller` and unregister its net iface,
/// regardless of slot. Infallible and idempotent, same pump-exit and
/// never-remove reasoning as [`detach_ax_slot`].
pub fn detach_all_ax(controller: u8) {
    let ifaces: Vec<String> = {
        let mut g = AX_DEVICES.lock();
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

/// Register the ax88179 USB class driver, together with its
/// detach hook. The probe spawns the async bind (xpad
/// precedent); the unbind hook adapts infallible
/// `detach_ax_slot` to the fallible `UsbUnbindFn` contract
/// with an unconditional `Ok(())` (#893: a hook reports
/// failure with `Err(())`, never by panicking).
pub fn register() {
    let _ = register_class_driver_with_unbind("ax88179", MATCHES, probe, detach_ax_slot);
}

// ── Fixtures ─────────────────────────────────────────────────────
//
// Modelled-device fixtures in the crate's kernel-test style: the
// register conversation is pinned at the level the production
// code composes it — SETUP-packet packing for each access class,
// the reset-write tables in full, MAC validation, and the RX/TX
// wire formats as byte fixtures, including the masking-defeating
// RX cases from audit §3 (drop-err, CRC-err, truncated metadata
// array, zero pkt_cnt, truncated packet data, runts).

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_ax88179_setup_packing() -> TestResult {
        // MAC write of AX_PHYPWR_RSTCTL (2 bytes): vendor OUT,
        // access MAC, wValue = register, wIndex = byte count.
        if ax_mac_setup(false, AX_PHYPWR_RSTCTL, 2) != (0x40, 0x01, 0x26, 2) {
            return TestResult::Fail("MAC write setup packing wrong");
        }
        // MAC read of AX_NODE_ID (6 bytes): vendor IN.
        if ax_mac_setup(true, AX_NODE_ID, 6) != (0xC0, 0x01, 0x10, 6) {
            return TestResult::Fail("MAC read setup packing wrong");
        }
        // PHY write of BMCR: wValue = PHY id, wIndex = register
        // (the audit §3 correction — NOT register/id swapped).
        if ax_phy_setup(false, MII_BMCR) != (0x40, 0x02, 0x03, 0x00) {
            return TestResult::Fail("PHY setup packing wrong");
        }
        // PHY read of BMSR.
        if ax_phy_setup(true, MII_BMSR) != (0xC0, 0x02, 0x03, 0x01) {
            return TestResult::Fail("PHY read setup packing wrong");
        }
        // EEPROM auto-detach probe read (word 0x43, wIndex 1).
        if ax_eeprom_setup(true, 0x43) != (0xC0, 0x04, 0x43, 1) {
            return TestResult::Fail("EEPROM setup packing wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_setup_packing);

    fn smoke_ax88179_reset_tables() -> TestResult {
        // Pre-clock table: power-up then IPRL, in order.
        if RESET_PRE.len() != 2
            || RESET_PRE[0].reg != AX_PHYPWR_RSTCTL
            || RESET_PRE[0].data != [0x00, 0x00]
            || RESET_PRE[1].reg != AX_PHYPWR_RSTCTL
            || RESET_PRE[1].data != [0x20, 0x00]
        {
            return TestResult::Fail("RESET_PRE table wrong");
        }
        // Clock select: ACS | BCS.
        if RESET_CLK.reg != AX_CLK_SELECT || RESET_CLK.data != [0x03] {
            return TestResult::Fail("RESET_CLK table wrong");
        }
        // Post table: register order + payloads, in bind order.
        let regs: Vec<u16> = RESET_POST.iter().map(|w| w.reg).collect();
        if regs
            != [
                AX_RX_BULKIN_QCTRL,
                AX_PAUSE_WATERLVL_HIGH,
                AX_PAUSE_WATERLVL_LOW,
                AX_RXCOE_CTL,
                AX_TXCOE_CTL,
                AX_RX_CTL,
                AX_MONITOR_MOD,
                AX_MEDIUM_STATUS_MODE,
            ]
        {
            return TestResult::Fail("RESET_POST register order wrong");
        }
        if RESET_POST[0].data != [0x07, 0x4F, 0x00, 0x12, 0xFF]
            || RESET_POST[1].data != [0x34]
            || RESET_POST[2].data != [0x52]
            || RESET_POST[3].data != [0x67]
            || RESET_POST[4].data != [0x67]
            || RESET_POST[5].data != [0xAA, 0x03]
            || RESET_POST[6].data != [0x64]
            || RESET_POST[7].data != [0x33, 0x01]
        {
            return TestResult::Fail("RESET_POST payloads wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_reset_tables);

    fn smoke_ax88179_mac_valid() -> TestResult {
        if !mac_is_valid(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) {
            return TestResult::Fail("valid unicast rejected");
        }
        // Locally-administered unicast is valid.
        if !mac_is_valid(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]) {
            return TestResult::Fail("local unicast rejected");
        }
        if mac_is_valid(&[0, 0, 0, 0, 0, 0]) {
            return TestResult::Fail("zero address accepted");
        }
        if mac_is_valid(&[0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]) {
            return TestResult::Fail("multicast accepted");
        }
        if mac_is_valid(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) {
            return TestResult::Fail("broadcast accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_mac_valid);

    fn smoke_ax88179_tx_segment() -> TestResult {
        // Plain frame: 8-byte header (len LE, hdr2 0) + frame.
        let frame = [0xAAu8; 60];
        let seg = build_tx_segment(&frame, 1024);
        if seg.len() != 68
            || seg[0..4] != [60, 0, 0, 0]
            || seg[4..8] != [0, 0, 0, 0]
            || seg[8..] != frame
        {
            return TestResult::Fail("plain TX segment wrong");
        }
        // Padding flag: (1016 + 8) % 1024 == 0.
        let frame = [0xBBu8; 1016];
        let seg = build_tx_segment(&frame, 1024);
        if seg[4..8] != [0x00, 0x80, 0x00, 0x80] {
            return TestResult::Fail("TX padding flag missing");
        }
        // The same frame flags at 512 too: 1024 is a multiple of
        // 512 as well, and the modulus is the endpoint maxpacket,
        // not a hardcoded 1024.
        let seg = build_tx_segment(&frame, 512);
        if seg[4..8] != [0x00, 0x80, 0x00, 0x80] {
            return TestResult::Fail("TX padding flag missing at 512");
        }
        // No flag when not aligned: (1015 + 8) = 1023 is not a
        // multiple of 512 — the 1016-byte frame above *is*
        // (1024 % 512 == 0), so it must still flag at 512, per
        // Linux `ax88179_tx_fixup` (`(len + 8) % maxpacket`).
        let short = [0xBBu8; 1015];
        let seg = build_tx_segment(&short, 512);
        if seg[4..8] != [0, 0, 0, 0] {
            return TestResult::Fail("TX padding flag spurious");
        }
        // No panic on max_packet 0.
        let seg = build_tx_segment(&frame, 0);
        if seg[4..8] != [0, 0, 0, 0] {
            return TestResult::Fail("TX zero-maxpacket flag spurious");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_tx_segment);

    /// Metadata word: pkt_len in bits 16–28, flags in low/other bits.
    fn meta_word(pkt_len: u16, flags: u32) -> [u8; 4] {
        (((pkt_len as u32) << 16) | flags).to_le_bytes()
    }

    /// Trailing rx_hdr: pkt_cnt low, hdr_off high.
    fn rx_hdr(pkt_cnt: u16, hdr_off: u16) -> [u8; 4] {
        (((hdr_off as u32) << 16) | (pkt_cnt as u32)).to_le_bytes()
    }

    /// One packet's data-region bytes: 2-byte pseudo-header +
    /// frame, padded to an 8-byte boundary.
    fn packet_bytes(frame: &[u8]) -> Vec<u8> {
        let pkt_len = frame.len() + 2;
        let padded = (pkt_len + 7) & !7;
        let mut out = vec![0x00, 0x00];
        out.extend_from_slice(frame);
        out.resize(padded, 0);
        out
    }

    fn smoke_ax88179_rx_two_packets_with_dummies() -> TestResult {
        // Two frames with the firmware's entry+dummy metadata
        // pattern: entry, dummy, entry, dummy.
        let frame1 = [0x11u8; 34];
        let frame2 = [0x22u8; 24];
        let mut buf = Vec::new();
        buf.extend_from_slice(&packet_bytes(&frame1));
        buf.extend_from_slice(&packet_bytes(&frame2));
        let hdr_off = buf.len() as u16; // 40 + 32 = 72
        buf.extend_from_slice(&meta_word(36, 0));
        buf.extend_from_slice(&meta_word(0, AX_RXHDR_DROP_ERR));
        buf.extend_from_slice(&meta_word(26, 0));
        buf.extend_from_slice(&meta_word(0, AX_RXHDR_DROP_ERR));
        buf.extend_from_slice(&rx_hdr(4, hdr_off));
        let out = parse_rx_aggregate(&buf);
        if out.frames.len() != 2 || out.dropped != 0 {
            return TestResult::Fail("two-packet parse wrong");
        }
        if out.frames[0] != frame1 || out.frames[1] != frame2 {
            return TestResult::Fail("two-packet frames wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ax88179",
        smoke_ax88179_rx_two_packets_with_dummies
    );

    fn smoke_ax88179_rx_error_entries_dropped() -> TestResult {
        // DROP_ERR entry, CRC_ERR entry, then a good frame.
        let frame = [0x33u8; 30];
        let mut buf = Vec::new();
        buf.extend_from_slice(&packet_bytes(&[0xAAu8; 30]));
        buf.extend_from_slice(&packet_bytes(&[0xBBu8; 30]));
        buf.extend_from_slice(&packet_bytes(&frame));
        let hdr_off = buf.len() as u16;
        buf.extend_from_slice(&meta_word(32, AX_RXHDR_DROP_ERR));
        buf.extend_from_slice(&meta_word(32, AX_RXHDR_CRC_ERR));
        buf.extend_from_slice(&meta_word(32, 0));
        buf.extend_from_slice(&rx_hdr(3, hdr_off));
        let out = parse_rx_aggregate(&buf);
        if out.frames.len() != 1 || out.dropped != 2 || out.frames[0] != frame {
            return TestResult::Fail("error entries not dropped");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ax88179",
        smoke_ax88179_rx_error_entries_dropped
    );

    fn smoke_ax88179_rx_truncated_metadata() -> TestResult {
        // pkt_cnt claims 3 entries but only 2 fit before rx_hdr.
        let mut buf = Vec::new();
        buf.extend_from_slice(&packet_bytes(&[0x44u8; 30]));
        let hdr_off = buf.len() as u16;
        buf.extend_from_slice(&meta_word(32, 0));
        buf.extend_from_slice(&meta_word(32, 0));
        buf.extend_from_slice(&rx_hdr(3, hdr_off));
        let out = parse_rx_aggregate(&buf);
        if !out.frames.is_empty() {
            return TestResult::Fail("truncated metadata array yielded frames");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_rx_truncated_metadata);

    fn smoke_ax88179_rx_zero_pkt_cnt() -> TestResult {
        let mut buf = Vec::new();
        buf.extend_from_slice(&packet_bytes(&[0x55u8; 30]));
        buf.extend_from_slice(&rx_hdr(0, 40));
        let out = parse_rx_aggregate(&buf);
        if !out.frames.is_empty() {
            return TestResult::Fail("zero pkt_cnt yielded frames");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_rx_zero_pkt_cnt);

    fn smoke_ax88179_rx_truncated_packet_keeps_prior() -> TestResult {
        // Good first packet, then an entry whose padded length
        // overruns the data region: first frame kept, stop.
        let frame1 = [0x66u8; 30];
        let mut buf = Vec::new();
        buf.extend_from_slice(&packet_bytes(&frame1));
        let hdr_off = buf.len() as u16;
        buf.extend_from_slice(&meta_word(32, 0));
        buf.extend_from_slice(&meta_word(100, 0));
        buf.extend_from_slice(&rx_hdr(2, hdr_off));
        let out = parse_rx_aggregate(&buf);
        if out.frames.len() != 1 || out.frames[0] != frame1 || out.dropped != 1 {
            return TestResult::Fail("truncated packet handling wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ax88179",
        smoke_ax88179_rx_truncated_packet_keeps_prior
    );

    fn smoke_ax88179_rx_runt_and_csum_bits() -> TestResult {
        // Runt (pkt_len 12 < 2 + 14) drops; L3/L4 csum-err bits do
        // NOT drop (v1 delivers; the stack revalidates).
        let frame = [0x77u8; 30];
        let mut buf = Vec::new();
        buf.extend_from_slice(&packet_bytes(&[0x88u8; 10]));
        buf.extend_from_slice(&packet_bytes(&frame));
        let hdr_off = buf.len() as u16;
        buf.extend_from_slice(&meta_word(12, 0));
        buf.extend_from_slice(&meta_word(32, AX_RXHDR_L3CSUM_ERR | AX_RXHDR_L4CSUM_ERR));
        buf.extend_from_slice(&rx_hdr(2, hdr_off));
        let out = parse_rx_aggregate(&buf);
        if out.frames.len() != 1 || out.dropped != 1 || out.frames[0] != frame {
            return TestResult::Fail("runt/csum handling wrong");
        }
        // Short buffer: no frames, no panic.
        if !parse_rx_aggregate(&[0x00, 0x01, 0x02]).frames.is_empty() {
            return TestResult::Fail("short buffer yielded frames");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_rx_runt_and_csum_bits);

    fn smoke_ax88179_interrupt_decode() -> TestResult {
        // intdata1 bit 16 set → link up; intdata2 is ignored.
        let up = [0x00, 0x00, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        if ax_interrupt_link(&up) != Some(true) {
            return TestResult::Fail("interrupt link-up decode wrong");
        }
        // intdata1 clear, intdata2 all set → still down: only
        // the first word carries the link bit.
        let down = [0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        if ax_interrupt_link(&down) != Some(false) {
            return TestResult::Fail("interrupt link-down decode wrong");
        }
        // Short transfer (< 8 bytes): no event, not a verdict.
        if ax_interrupt_link(&up[..7]).is_some() {
            return TestResult::Fail("short interrupt transfer yielded a verdict");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_interrupt_decode);

    fn smoke_ax88179_link_mode() -> TestResult {
        use narf_net::iface::LinkDuplex;
        // Giga + SuperSpeed + full: base + GIGAMODE + 125MHz + FULL.
        let m = ax_link_mode(AX_USB_SS, 0xA400);
        if m != Some((0x013B, AX_RX_BULKIN_SIZE[0], 1000, LinkDuplex::Full)) {
            return TestResult::Fail("giga/SS/full link mode wrong");
        }
        // Giga + HighSpeed + half: bulkin[1], no FULL bit.
        let m = ax_link_mode(AX_USB_HS, 0x8400);
        if m != Some((0x0139, AX_RX_BULKIN_SIZE[1], 1000, LinkDuplex::Half)) {
            return TestResult::Fail("giga/HS/half link mode wrong");
        }
        // Giga + neither speed: bulkin[3] (the else branch).
        let m = ax_link_mode(0x00, 0x8400);
        if m != Some((0x0139, AX_RX_BULKIN_SIZE[3], 1000, LinkDuplex::Half)) {
            return TestResult::Fail("giga/other link mode wrong");
        }
        // 100M + SuperSpeed + full: PS bit, bulkin[2].
        let m = ax_link_mode(AX_USB_SS, 0x6400);
        if m != Some((0x0332, AX_RX_BULKIN_SIZE[2], 100, LinkDuplex::Full)) {
            return TestResult::Fail("100M/SS/full link mode wrong");
        }
        // 100M + neither + half: bulkin[3].
        let m = ax_link_mode(0x00, 0x4400);
        if m != Some((0x0330, AX_RX_BULKIN_SIZE[3], 100, LinkDuplex::Half)) {
            return TestResult::Fail("100M/other link mode wrong");
        }
        // 10M: no speed bits, bulkin[3], USB speed irrelevant.
        let m = ax_link_mode(AX_USB_SS, 0x0400);
        if m != Some((0x0130, AX_RX_BULKIN_SIZE[3], 10, LinkDuplex::Half)) {
            return TestResult::Fail("10M link mode wrong");
        }
        // No PHY link bit → None, even with GIGA set.
        if ax_link_mode(AX_USB_SS, 0x8000).is_some() {
            return TestResult::Fail("no-link PHYSR yielded a mode");
        }
        if ax_link_mode(AX_USB_SS, 0x0000).is_some() {
            return TestResult::Fail("zero PHYSR yielded a mode");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_link_mode);

    fn smoke_ax88179_ether_crc() -> TestResult {
        // Linux ether_crc vectors, computed independently via
        // zlib CRC-32 + bitrev32 (see ax_ether_crc docs).
        if ax_ether_crc(&[0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]) != 0x7FA3_2D9B {
            return TestResult::Fail("ether_crc 01:00:5e:00:00:01 wrong");
        }
        if ax_ether_crc(&[0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]) != 0x3F7B_3B21 {
            return TestResult::Fail("ether_crc 01:00:5e:00:00:fb wrong");
        }
        if ax_ether_crc(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]) != 0xF99B_AABA {
            return TestResult::Fail("ether_crc 33:33:00:00:00:01 wrong");
        }
        if ax_ether_crc(&[0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]) != 0x67D8_C317 {
            return TestResult::Fail("ether_crc 01:80:c2:00:00:00 wrong");
        }
        if ax_ether_crc(&[0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA]) != 0xAE3C_4AFC {
            return TestResult::Fail("ether_crc 01:00:5e:7f:ff:fa wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_ether_crc);

    fn smoke_ax88179_multicast_program() -> TestResult {
        // Base = START | AB | IPE = 0x0288.
        // Promiscuous: + PRO, no filter (and promisc wins over
        // all-multicast + a non-empty list — Linux if/else-if).
        let (rxctl, filter) =
            ax_multicast_program(true, true, &[[0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]]);
        if rxctl != 0x0289 || filter.is_some() {
            return TestResult::Fail("promiscuous program wrong");
        }
        // Promiscuous with an empty list: still PRO, no filter.
        let (rxctl, filter) = ax_multicast_program(true, false, &[]);
        if rxctl != 0x0289 || filter.is_some() {
            return TestResult::Fail("promiscuous (no list) program wrong");
        }
        // All-multicast: + AMALL, no filter.
        let (rxctl, filter) = ax_multicast_program(false, true, &[]);
        if rxctl != 0x028A || filter.is_some() {
            return TestResult::Fail("all-multicast program wrong");
        }
        // Overflow past 64 addresses falls back to AMALL.
        let many: Vec<[u8; 6]> = (0..65)
            .map(|i| [0x01, 0x00, 0x5E, 0x00, 0x00, i as u8])
            .collect();
        let (rxctl, filter) = ax_multicast_program(false, false, &many);
        if rxctl != 0x028A || filter.is_some() {
            return TestResult::Fail("multicast overflow program wrong");
        }
        // Empty list: base only ("just broadcast and directed").
        let (rxctl, filter) = ax_multicast_program(false, false, &[]);
        if rxctl != 0x0288 || filter.is_some() {
            return TestResult::Fail("empty multicast program wrong");
        }
        // Filtered list: + AM, filter bits from ether_crc
        // (bits 31 → byte 3 bit 7; bits 62 → byte 7 bit 6).
        let (rxctl, filter) = ax_multicast_program(
            false,
            false,
            &[
                [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01],
                [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            ],
        );
        if rxctl != 0x0298 || filter != Some([0, 0, 0, 0x80, 0, 0, 0, 0x40]) {
            return TestResult::Fail("filtered multicast program wrong");
        }
        // Two addresses in one filter byte OR their bits
        // (bits 31 → bit 7, bits 25 → bit 1, both byte 3).
        let (rxctl, filter) = ax_multicast_program(
            false,
            false,
            &[
                [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01],
                [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00],
            ],
        );
        if rxctl != 0x0298 || filter != Some([0, 0, 0, 0x82, 0, 0, 0, 0]) {
            return TestResult::Fail("multicast filter OR-accumulation wrong");
        }
        // Single address: bits 15 → byte 1 bit 7.
        let (rxctl, filter) =
            ax_multicast_program(false, false, &[[0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]]);
        if rxctl != 0x0298 || filter != Some([0, 0x80, 0, 0, 0, 0, 0, 0]) {
            return TestResult::Fail("single multicast program wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_multicast_program);

    fn smoke_ax88179_offloads_and_tx_meta() -> TestResult {
        let caps = ax88179_offloads();
        if !caps.tx_checksum || caps.rx_checksum || caps.max_tso_bytes != 0 || caps.vlan_insert {
            return TestResult::Fail("advertised offloads wrong");
        }
        let plain = narf_net::TxMeta {
            csum_l4: None,
            tso_mss: None,
            vlan_tag: None,
            more: false,
        };
        if !ax_tx_meta_accepted(plain) {
            return TestResult::Fail("plain TX rejected");
        }
        let tcp = narf_net::TxMeta {
            csum_l4: Some(narf_net::L4CsumKind::Tcp),
            ..plain
        };
        if !ax_tx_meta_accepted(tcp) {
            return TestResult::Fail("TCP csum TX rejected");
        }
        let udp = narf_net::TxMeta {
            csum_l4: Some(narf_net::L4CsumKind::Udp),
            ..plain
        };
        if !ax_tx_meta_accepted(udp) {
            return TestResult::Fail("UDP csum TX rejected");
        }
        let sctp = narf_net::TxMeta {
            csum_l4: Some(narf_net::L4CsumKind::Sctp),
            ..plain
        };
        if ax_tx_meta_accepted(sctp) {
            return TestResult::Fail("SCTP csum TX accepted");
        }
        let tso = narf_net::TxMeta {
            tso_mss: Some(1460),
            ..plain
        };
        if ax_tx_meta_accepted(tso) {
            return TestResult::Fail("TSO TX accepted");
        }
        let vlan = narf_net::TxMeta {
            vlan_tag: Some(7),
            ..plain
        };
        if ax_tx_meta_accepted(vlan) {
            return TestResult::Fail("VLAN TX accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ax88179", smoke_ax88179_offloads_and_tx_meta);
}
