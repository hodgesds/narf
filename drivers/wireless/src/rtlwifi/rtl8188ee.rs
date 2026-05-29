//! RTL8188EE per-chip constants.
//!
//! RTL8188EE is a 1T1R 802.11n 2.4 GHz PCIe NIC shipped from ~2012 in
//! budget laptops.  The register layout is the same as the RTL8192CE family
//! (`rtlwifi/rtl8188ee/reg.h` and `def.h` share most definitions with the
//! `rtl8192ce` subdirectory).
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8188ee/reg.h`
//! - `rtlwifi/rtl8188ee/def.h`
//! - `rtlwifi/rtl8188ee/trx.h`  — `struct tx_desc_88e`, `struct rx_desc_88e`

#![allow(dead_code)]

/// PCI device ID.
pub const DEV_ID: u16 = super::regs::RTL_DEV_8188EE;

// ── Per-chip register bank ────────────────────────────────────────────────

/// Size of the mapped IO range (16 KiB).
/// `rtlwifi/pci.h::RTL_MEM_MAPPED_IO_RANGE_8192CE` — same range used for 8188EE.
pub const MMIO_SIZE: usize = 0x4000;

/// EFUSE physical size (256 bytes raw).
/// Source: `rtl8188ee/hw.c` — `EFUSE_MAP_SIZE` is 256 for 88E.
pub const EFUSE_MAP_SIZE: usize = 256;

// ── Chip version identifiers ──────────────────────────────────────────────
//
// Source: `rtl8188ee/def.h::enum version_8188e`.

/// Test chip version.
pub const VERSION_TEST: u8 = 0x00;
/// Normal production chip version.
pub const VERSION_NORMAL: u8 = 0x01;

// ── TX descriptor layout (dword offsets) ─────────────────────────────────
//
// The `tx_desc_88e` struct in `trx.h` maps to 16 × u32 = 64 bytes.
// Key field positions for the baseline BE/MGNT/HI queue path:
//
//  DW0[15:0]   pktsize        — MPDU length
//  DW0[23:16]  offset         — header offset (usually 0)
//  DW0[31]     own            — 1=HW owns, 0=driver owns
//  DW1[12:8]   queuesel       — queue select (QSLT_*)
//  DW1[5:0]    macid          — MAC-id
//  DW5[5:0]    txrate         — Tx rate index

/// TX descriptor size (bytes).
pub const TX_DESC_SIZE: usize = super::regs::TX_DESC_SIZE;

/// Bit mask for the OWN bit in TX descriptor DW0.
pub const TX_OWN_BIT: u32 = 1 << 31;

/// Bit mask for FIRST_SEG in TX descriptor DW0.
pub const TX_FIRST_SEG: u32 = 1 << 27;

/// Bit mask for LAST_SEG in TX descriptor DW0.
pub const TX_LAST_SEG: u32 = 1 << 26;

// ── RX descriptor layout ─────────────────────────────────────────────────
//
// `rx_desc_88e` in `trx.h` maps to 8 × u32 = 32 bytes.
//
//  DW0[13:0]   length         — received MPDU length
//  DW0[14]     crc32          — CRC error
//  DW0[15]     icverror       — ICV error
//  DW0[31]     own            — 1=HW owns, 0=driver owns
//  DW6[31:0]   bufferaddress  — DMA buffer physical address

/// RX descriptor size (bytes).
pub const RX_DESC_SIZE: usize = super::regs::RX_DESC_SIZE;

/// Bit mask for the OWN bit in RX descriptor DW0.
pub const RX_OWN_BIT: u32 = 1 << 31;

/// Bit mask for EOR (end of ring) in RX descriptor DW0.
pub const RX_EOR_BIT: u32 = 1 << 30;

/// Mask for the received packet length in RX descriptor DW0.
pub const RX_PKT_LEN_MASK: u32 = 0x3FFF;

// ── TX descriptor helpers ─────────────────────────────────────────────────

/// 16-dword TX descriptor ring entry.  The `dwords` array maps exactly to
/// the `tx_desc_88e` layout in `trx.h`.  Individual fields are written
/// through the named helpers below so call-sites don't hard-code dword indices.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TxDesc {
    pub dwords: [u32; 16],
}

impl TxDesc {
    /// Set packet length (bits[15:0] of DW0).
    #[inline]
    pub fn set_pkt_size(&mut self, len: u16) {
        self.dwords[0] = (self.dwords[0] & !0xFFFF) | (len as u32);
    }

    /// Set/clear the HW-own bit (bit 31 of DW0).
    #[inline]
    pub fn set_own(&mut self, own: bool) {
        if own {
            self.dwords[0] |= TX_OWN_BIT;
        } else {
            self.dwords[0] &= !TX_OWN_BIT;
        }
    }

    /// Set FIRST_SEG + LAST_SEG (non-fragmented single-MPDU path).
    #[inline]
    pub fn set_single_mpdu(&mut self) {
        self.dwords[0] |= TX_FIRST_SEG | TX_LAST_SEG;
    }

    /// Set queue-select field (bits[12:8] of DW1).
    #[inline]
    pub fn set_queuesel(&mut self, qs: u8) {
        self.dwords[1] = (self.dwords[1] & !(0x1F << 8)) | ((qs as u32 & 0x1F) << 8);
    }

    /// Set DMA buffer address (DW8 = TX buffer address).
    #[inline]
    pub fn set_buf_addr(&mut self, addr: u32) {
        self.dwords[8] = addr;
    }

    /// Set TX buffer size (bits[15:0] of DW7).
    #[inline]
    pub fn set_buf_size(&mut self, sz: u16) {
        self.dwords[7] = (self.dwords[7] & !0xFFFF) | (sz as u32);
    }
}

/// 8-dword RX descriptor ring entry.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RxDesc {
    pub dwords: [u32; 8],
}

impl RxDesc {
    /// True if the descriptor is owned by hardware.
    #[inline]
    pub fn is_hw_owned(&self) -> bool {
        self.dwords[0] & RX_OWN_BIT != 0
    }

    /// Received packet length.
    #[inline]
    pub fn pkt_len(&self) -> u16 {
        (self.dwords[0] & RX_PKT_LEN_MASK) as u16
    }

    /// CRC error flag.
    #[inline]
    pub fn crc_err(&self) -> bool {
        self.dwords[0] & (1 << 14) != 0
    }

    /// Reclaim by writing DMA buffer address and setting OWN.
    #[inline]
    pub fn reclaim(&mut self, buf_addr: u32) {
        self.dwords[6] = buf_addr;
        self.dwords[0] = (self.dwords[0] & !RX_PKT_LEN_MASK) | RX_OWN_BIT;
    }
}
