//! RTL8XXXU EFUSE read via USB control transfers.
//!
//! Realtek USB WiFi chips expose their EFUSE through the same register
//! interface as PCIe parts, but the register bus is the USB control
//! transfer path (vendor class, `REALTEK_USB_CMD_REQ`).
//!
//! The read algorithm matches `core.c::rtl8xxxu_read_efuse8` (L1746)
//! plus the `read_efuse` preamble (L1780):
//!
//! **Preamble (once per chip):**
//! 1. Write `EFUSE_ACCESS_ENABLE (0x69)` to `REG_EFUSE_ACCESS (0x00CF)`.
//! 2. Assert `SYS_ISO_PWC_EV12V` in `REG_SYS_ISO_CTRL` (1.2V power).
//! 3. Assert `SYS_FUNC_ELDR` in `REG_SYS_FUNC` (EFUSE loader clock).
//! 4. Assert `SYS_CLK_LOADER_ENABLE | SYS_CLK_ANA8M` in `REG_SYS_CLKR`.
//!
//! **Per-byte read:**
//! 1. Write `addr & 0xFF` to `REG_EFUSE_CTRL + 1`.
//! 2. Read `REG_EFUSE_CTRL + 2`, clear bits[1:0], set `addr >> 8` in
//!    bits[1:0], write back.
//! 3. Read `REG_EFUSE_CTRL + 3`, clear bit 7, write back (arms trigger).
//! 4. Poll 32-bit `REG_EFUSE_CTRL` until bit 31 is set (data ready).
//! 5. Read the data byte from `REG_EFUSE_CTRL` bits[7:0].
//!
//! **Post:** Write `EFUSE_ACCESS_DISABLE (0x00)` to `REG_EFUSE_ACCESS`.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c`
//!   `rtl8xxxu_read_efuse8` (~L1746) and `rtl8xxxu_read_efuse` (~L1780).

#![allow(dead_code)]

use super::regs::*;
use super::usb::UsbControlSetup;

// ── EFUSE byte address type ─────────────────────────────────────────

/// A 10-bit EFUSE byte address (0 .. EFUSE_REAL_CONTENT_LEN).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EfuseAddr(pub u16);

impl EfuseAddr {
    /// Construct; saturates at `EFUSE_REAL_CONTENT_LEN`.
    pub fn new(addr: u16) -> Self {
        Self(addr.min(EFUSE_REAL_CONTENT_LEN as u16 - 1))
    }
}

// ── Control-transfer setups for EFUSE access ────────────────────────

/// Encode the three USB control-transfer setup packets needed to write
/// the EFUSE byte-address and arm the read trigger for `addr`.
///
/// Returns `(step1, step2_mask, step3)` where:
/// - `step1` — write `addr & 0xFF` to `REG_EFUSE_CTRL + 1`.
/// - `step2_mask` — `(upper_2_bits, addr_hi_bits)` for the
///   read-modify-write of `REG_EFUSE_CTRL + 2`.
/// - `step3` — write setup for clearing bit 7 of `REG_EFUSE_CTRL + 3`.
///
/// Source: `core.c::rtl8xxxu_read_efuse8` ~L1752..L1762.
pub fn efuse_addr_setups(addr: EfuseAddr) -> EfuseAddrSetups {
    let lo = (addr.0 & 0xFF) as u8;
    let hi = ((addr.0 >> 8) & 0x03) as u8;
    EfuseAddrSetups { addr_lo: lo, addr_hi_bits: hi }
}

/// The two data fields extracted by `efuse_addr_setups`.
#[derive(Copy, Clone, Debug)]
pub struct EfuseAddrSetups {
    /// Low byte of the EFUSE address → written to `REG_EFUSE_CTRL + 1`.
    pub addr_lo: u8,
    /// Bits[1:0] of the high address nibble → OR'd into
    /// `REG_EFUSE_CTRL + 2` after clearing the existing bits[1:0].
    pub addr_hi_bits: u8,
}

impl EfuseAddrSetups {
    /// Build the USB write setup for `REG_EFUSE_CTRL + 1 ← addr_lo`.
    pub fn write_ctrl1_setup(&self) -> UsbControlSetup {
        UsbControlSetup::write(REG_EFUSE_CTRL + 1, 1)
    }

    /// Build the USB write setup for `REG_EFUSE_CTRL + 2`.
    /// Caller is expected to read the current byte, apply the mask, then
    /// write back. This returns the setup packet for the write back.
    pub fn write_ctrl2_setup(&self) -> UsbControlSetup {
        UsbControlSetup::write(REG_EFUSE_CTRL + 2, 1)
    }

    /// Apply this object's `addr_hi_bits` to the existing value of
    /// `REG_EFUSE_CTRL + 2`, clearing old bits[1:0] first.
    /// Returns the byte to write back.
    pub fn apply_ctrl2(&self, existing: u8) -> u8 {
        (existing & 0xFC) | (self.addr_hi_bits & 0x03)
    }

    /// Build the USB write setup for `REG_EFUSE_CTRL + 3` (arm trigger).
    /// The caller reads the current value, clears bit 7, and writes back.
    pub fn write_ctrl3_setup(&self) -> UsbControlSetup {
        UsbControlSetup::write(REG_EFUSE_CTRL + 3, 1)
    }

    /// Clear the read-trigger bit (bit 7) from the `REG_EFUSE_CTRL + 3`
    /// byte. Pass the read-back value of that byte.
    pub fn apply_ctrl3_clear_trigger(val: u8) -> u8 {
        val & !(1 << 7)
    }
}

/// Build the USB read setup for polling `REG_EFUSE_CTRL` (32-bit).
pub fn efuse_ctrl_read_setup() -> UsbControlSetup {
    UsbControlSetup::read(REG_EFUSE_CTRL, 4)
}

// ── EFUSE logical map walker ────────────────────────────────────────

/// Decode the compact "PG header" EFUSE wire format into a flat
/// 512-byte logical map.
///
/// The EFUSE physical stream is a sequence of variable-length records:
///
/// ```text
/// [header byte]          — offset (bits [7:4] = section, bits [3:0] = word_mask)
/// [optional extheader]   — if header[4:0] == 0x0F (extended record)
/// [data bytes]           — words for enabled bits in word_mask
/// ```
///
/// Section 0..N each contains 8 bytes (4 × 16-bit words). The
/// `word_mask` nibble selects which of the 4 words are present
/// (0 = present, 1 = skip). The section index × 8 gives the byte
/// offset in the 512-byte logical map.
///
/// Source: `core.c::rtl8xxxu_read_efuse` ~L1830..L1887.
///
/// # Parameters
/// - `raw`: raw EFUSE physical stream bytes (up to 512).
/// - `map_out`: caller-provided 512-byte buffer; initialised to 0xFF.
pub fn decode_efuse_map(raw: &[u8], map_out: &mut [u8; EFUSE_MAP_LEN]) {
    map_out.fill(EFUSE_UNDEFINED);

    let mut pos = 0usize;
    while pos < raw.len() {
        let header = raw[pos];
        if header == EFUSE_UNDEFINED {
            break; // end sentinel
        }
        pos += 1;

        let (offset, word_mask) = if (header & 0x1F) == 0x0F {
            // Extended header: next byte encodes upper offset bits + word_mask.
            if pos >= raw.len() {
                break;
            }
            let extheader = raw[pos];
            pos += 1;
            if (extheader & 0x0F) == 0x0F {
                continue; // all words disabled
            }
            let off = ((header & 0xE0) >> 5) | ((extheader & 0xF0) >> 1);
            let wm = extheader & 0x0F;
            (off as u16, wm)
        } else {
            let off = (header >> 4) & 0x0F;
            let wm = header & 0x0F;
            (off as u16, wm)
        };

        let mut map_addr = offset as usize * 8;
        for i in 0..EFUSE_MAX_WORD_UNIT {
            if word_mask & (1 << i) != 0 {
                // Word is masked out (skip).
                map_addr += 2;
                continue;
            }
            // Two data bytes per word.
            if pos + 1 >= raw.len() {
                break;
            }
            if map_addr + 1 < EFUSE_MAP_LEN {
                map_out[map_addr] = raw[pos];
                map_out[map_addr + 1] = raw[pos + 1];
            }
            pos += 2;
            map_addr += 2;
        }
    }
}

// ── Convenience: extract MAC from decoded map ───────────────────────

/// MAC address logical-map offset for RTL8188EU / RTL8192EU / RTL8723BU.
///
/// Linux locates the factory MAC in the efuse_wifi map at this offset.
/// Value derived from `8188e.c::rtl8188eu_parse_efuse` which reads
/// `map.efuse.mac_addr[0..6]` at struct offset corresponding to
/// `EFUSE_WIFI_MAC_OFFSET_8188E`.
pub const EFUSE_WIFI_MAC_OFFSET: usize = 0x0007 * 2; // word 7 = byte 14

/// Extract the 6-byte MAC address from the decoded EFUSE logical map.
///
/// Returns `None` if the MAC reads as all-zero or all-0xFF.
pub fn extract_mac(map: &[u8; EFUSE_MAP_LEN]) -> Option<[u8; 6]> {
    let off = EFUSE_WIFI_MAC_OFFSET;
    if off + 6 > EFUSE_MAP_LEN {
        return None;
    }
    let mac: [u8; 6] = map[off..off + 6].try_into().ok()?;
    if mac == [0u8; 6] || mac == [0xFFu8; 6] {
        None
    } else {
        Some(mac)
    }
}

/// `true` if a 6-byte MAC is neither all-zero nor all-0xFF.
pub fn mac_is_valid(mac: [u8; 6]) -> bool {
    mac != [0u8; 6] && mac != [0xFFu8; 6]
}
