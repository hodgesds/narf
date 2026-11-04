//! ixgbe Wake-on-LAN — WUFC / WUC / WUS / IPAV (+ IP4AT/IP6AT).
//!
//! Grounding: Intel 82599 Datasheet rev. 2.0 §8.2.3.24.1 (WUC at
//! 0x05800: PME_En bit 1, PME_Status bit 2 write-1-to-clear),
//! §8.2.3.24.2 (WUFC at 0x05808: LNKC 0, MAG 1, EX 2, MC 3, BC 4,
//! ARP 5, IPV4 6, IPV6 7, NoTCO 15, FLX0..5 16..21), §8.2.3.24.3
//! (WUS at 0x05810, RW1C, same bits + MNG 8), §8.2.3.24.5
//! (IP4AT at 0x05840 + 8*n, n = 0..3), §8.2.3.24.6 (IP6AT at
//! 0x05880 + 4*n, 4 words per address). No Linux ixgbe source
//! consulted for those values.
//!
//! IPAV (resolved by #1267): Datasheet rev. 2.0 §8.2.3.24.4,
//! printed as 0x5838 in the PDF text — the leading zero is
//! dropped in extraction, as with the neighbouring 0x058xx
//! registers. Linux normalizes it to 0x05838 (ixgbe_type.h:508;
//! e1000_hw.h:990 and igb e1000_regs.h:304 agree, "IP Address
//! Valid - RW"). Bits: V40..V43 = IPv4 slots 0..3 valid (bits
//! 0..3), V60 = IPv6 address 0 valid (bit 16); V40 init comes
//! from EEPROM. Linux never writes IPAV (it appears only in
//! ethtool register dumps); NARF programs it per the datasheet
//! because the valid bits are what make a table entry count
//! for wake matching.
//!
//! IPAV programming: `program_ipv4` sets the slot's valid bit
//! (V40..V43) alongside the table write, `program_ipv6` sets
//! V60, and `invalidate_ipv4` / `invalidate_ipv6` clear them.
//! `arm` / `disarm` do not touch IPAV: validity is per-entry
//! state, and with WUFC = 0 no filter can fire regardless of
//! the valid bits.
//!
//! Per-part support:
//! * 82599EB — supported: the 82599 datasheet's §8.2.3.24 + power
//!   management chapter describe the full WoL filter set.
//! * X540-AT2 / X550 / X550EM_x — grounded in Linux, NOT in a
//!   datasheet (the X540/X550 datasheets were not consulted in this
//!   stream): Linux programs the same WUFC/WUC block for these
//!   parts on its shared shutdown path, and gates arming on a
//!   board capability record (see `WolBoardCap`). Nothing arms by
//!   default: without a permitting record, X540+ stays unarmed.
//! * X550 LOM/board gating IS the record: Linux's
//!   `ixgbe_wol_supported` has no separate LOM concept for X550 —
//!   the board's EEPROM DEVICE_CAPS word is the opt-in, and a
//!   board that does not opt in never wakes. The driver therefore
//!   never arms X550 WoL on its own.
//!
use super::queues::RegBank;

/// Wake-up registers (datasheet §8.2.3.24).
pub const REG_WUC: u64 = 0x05800;
pub const REG_WUFC: u64 = 0x05808;
pub const REG_WUS: u64 = 0x05810;
pub const REG_IPAV: u64 = 0x05838;
pub const REG_IP4AT_BASE: u64 = 0x05840;
pub const REG_IP6AT_BASE: u64 = 0x05880;

/// IPAV valid bits (datasheet §8.2.3.24.4).
pub const IPAV_V40: u32 = 1 << 0;
pub const IPAV_V41: u32 = 1 << 1;
pub const IPAV_V42: u32 = 1 << 2;
pub const IPAV_V43: u32 = 1 << 3;
pub const IPAV_V60: u32 = 1 << 16;

/// WUC bits.
pub const WUC_PME_EN: u32 = 1 << 1;
pub const WUC_PME_STATUS: u32 = 1 << 2;

/// WUFC/WUS filter bits (shared layout).
pub const WUFC_LNKC: u32 = 1 << 0;
pub const WUFC_MAG: u32 = 1 << 1;
pub const WUFC_EX: u32 = 1 << 2;
pub const WUFC_MC: u32 = 1 << 3;
pub const WUFC_BC: u32 = 1 << 4;
pub const WUFC_ARP: u32 = 1 << 5;
pub const WUFC_IPV4: u32 = 1 << 6;
pub const WUFC_IPV6: u32 = 1 << 7;
pub const WUFC_NOTCO: u32 = 1 << 15;
pub const WUFC_MNG: u32 = 1 << 8; // WUS only (status bit)

/// Which wake-up filters to arm. Each flag maps 1:1 to a WUFC bit.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WolConfig {
    /// Wake on link-status change.
    pub link_change: bool,
    /// Wake on magic packet (directed to this MAC).
    pub magic: bool,
    /// Wake on directed exact-match packet.
    pub exact: bool,
    /// Wake on directed multicast packet.
    pub multicast: bool,
    /// Wake on broadcast packet.
    pub broadcast: bool,
    /// Wake on ARP / IPv4 request packet.
    pub arp: bool,
    /// Wake on directed IPv4 packet (needs an IP4AT entry).
    pub ipv4: bool,
    /// Wake on directed IPv6 packet (needs an IP6AT entry).
    pub ipv6: bool,
}

impl WolConfig {
    /// Magic-packet-only: the conservative default for suspend.
    pub const fn magic_only() -> Self {
        Self {
            link_change: false,
            magic: true,
            exact: false,
            multicast: false,
            broadcast: false,
            arp: false,
            ipv4: false,
            ipv6: false,
        }
    }

    /// Pack the filter bits into a WUFC word.
    pub const fn wufc_word(&self) -> u32 {
        let mut w = 0u32;
        if self.link_change {
            w |= WUFC_LNKC;
        }
        if self.magic {
            w |= WUFC_MAG;
        }
        if self.exact {
            w |= WUFC_EX;
        }
        if self.multicast {
            w |= WUFC_MC;
        }
        if self.broadcast {
            w |= WUFC_BC;
        }
        if self.arp {
            w |= WUFC_ARP;
        }
        if self.ipv4 {
            w |= WUFC_IPV4;
        }
        if self.ipv6 {
            w |= WUFC_IPV6;
        }
        w
    }

    /// Arm WoL: clear stale status (RW1C — write 1s to the latched
    /// bits), program WUFC, then set WUC.PME_En. The PMCSR PME_En
    /// bit (PCI config space, owned by the platform PM layer)
    /// further gates the wake; setting WUC.PME_En also sets it
    /// per §8.2.3.24.1's note.
    pub fn arm(&self, bank: &mut impl RegBank) {
        bank.write32(REG_WUS, 0xFFFF_FFFF);
        bank.write32(REG_WUFC, self.wufc_word());
        bank.set_bits(REG_WUC, WUC_PME_EN);
    }

    /// Disarm WoL: clear the filter set and PME_En, and clear any
    /// latched status.
    pub fn disarm(bank: &mut impl RegBank) {
        bank.write32(REG_WUFC, 0);
        bank.clear_bits(REG_WUC, WUC_PME_EN);
        bank.write32(REG_WUS, 0xFFFF_FFFF);
    }
}

/// Decode a WUS word into the filters that fired.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WakeStatus {
    pub raw: u32,
}

impl WakeStatus {
    pub const fn link_change(&self) -> bool {
        self.raw & WUFC_LNKC != 0
    }
    pub const fn magic(&self) -> bool {
        self.raw & WUFC_MAG != 0
    }
    pub const fn exact(&self) -> bool {
        self.raw & WUFC_EX != 0
    }
    pub const fn multicast(&self) -> bool {
        self.raw & WUFC_MC != 0
    }
    pub const fn broadcast(&self) -> bool {
        self.raw & WUFC_BC != 0
    }
    pub const fn arp(&self) -> bool {
        self.raw & WUFC_ARP != 0
    }
    pub const fn ipv4(&self) -> bool {
        self.raw & WUFC_IPV4 != 0
    }
    pub const fn ipv6(&self) -> bool {
        self.raw & WUFC_IPV6 != 0
    }
    pub const fn manageability(&self) -> bool {
        self.raw & WUFC_MNG != 0
    }
}

/// Per-part WoL support with no board record (see the module header
/// for the reasoning). `device_id` is the PCI device id from the
/// driver's match table.
pub fn wol_supported(device_id: u16) -> bool {
    // 82599EB only. X540-and-newer parts need a permitting board
    // record (`wol_allowed`); they are never armed by default.
    device_id == super::IXGBE_DEV_82599EB
}

/// Linux EEPROM DEVICE_CAPS WoL bits (ixgbe_type.h:2179-2181).
/// The word is read from EEPROM/NVM offset 0x2c at probe
/// (ixgbe_main.c:11913); only the 0xC mask matters here.
pub const WOL_CAP_PORT0_1: u16 = 0x4; // WoL supported on ports 0 & 1
pub const WOL_CAP_PORT0: u16 = 0x8; // WoL supported on port 0
pub const WOL_CAP_MASK: u16 = 0xC;

/// Board capability record gating WoL on X540-and-newer parts.
///
/// Linux determines X540+ WoL from the EEPROM DEVICE_CAPS word, not
/// from the device ID (ixgbe_main.c `ixgbe_wol_supported`, X540+ arm):
/// the board (via its EEPROM image) opts in, and the driver never
/// arms blindly. NARF has an EERD reader but no DEVICE_CAPS consumer
/// yet, so the record is supplied explicitly by the board/platform
/// layer through `Ixgbe::set_wol_board_cap`; the default record opts
/// nothing in. A future lane can populate it from EEPROM word 0x2c
/// via the existing EERD helper instead of board configuration.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WolBoardCap {
    /// Raw DEVICE_CAPS word bits (only the 0xC mask is consulted).
    pub cap_bits: u16,
    /// PCI function number of this device. A PORT0-only cap permits
    /// function 0 only (Linux's `hw->bus.func == 0` clause).
    pub func: u8,
}

impl WolBoardCap {
    /// The Linux-literal X540+ rule (ixgbe_main.c `ixgbe_wol_supported`):
    /// masked cap 0x4 permits any function; masked cap 0x8 permits
    /// function 0 only; anything else — including 0xC, both bits set,
    /// which Linux's equality comparisons reject — permits nothing.
    pub const fn allows(&self) -> bool {
        let cap = self.cap_bits & WOL_CAP_MASK;
        if cap == WOL_CAP_PORT0_1 {
            return true;
        }
        if cap == WOL_CAP_PORT0 && self.func == 0 {
            return true;
        }
        false
    }
}

/// X540-and-newer parts in this driver's match table (mac.type >=
/// ixgbe_mac_X540 in Linux's enum, ixgbe_type.h:3218-3220).
pub fn is_x540_or_newer(device_id: u16) -> bool {
    device_id == super::IXGBE_DEV_X540
        || device_id == super::IXGBE_DEV_X550
        || device_id == super::IXGBE_DEV_X550EM_X
}

/// WoL allowed for this device under the board record: 82599EB by
/// its datasheet rule (`wol_supported`), X540-and-newer only when
/// the board record permits (Linux EEPROM-cap rule), everything
/// else never. With the default (empty) record, X540+ stays
/// unarmed — the opt-in is explicit, never a default.
pub fn wol_allowed(device_id: u16, board: WolBoardCap) -> bool {
    if wol_supported(device_id) {
        return true;
    }
    if is_x540_or_newer(device_id) {
        return board.allows();
    }
    false
}

/// Program one directed-IPv4 wake address (IP4AT[n], n = 0..3).
/// The address is stored as a single little-endian word, and the
/// slot's IPAV valid bit (V40..V43) is set alongside the write:
/// without the valid bit the entry does not count for wake.
/// Out-of-range slots are rejected and touch nothing.
pub fn program_ipv4(bank: &mut impl RegBank, slot: usize, addr: [u8; 4]) -> bool {
    if slot >= 4 {
        return false;
    }
    bank.write32(REG_IP4AT_BASE + 8 * slot as u64, u32::from_le_bytes(addr));
    bank.set_bits(REG_IPAV, 1 << slot);
    true
}

/// Program the directed-IPv6 wake address (IP6AT, 4 words, LS byte
/// of word 0 first on the wire) and set the IPAV V60 valid bit.
pub fn program_ipv6(bank: &mut impl RegBank, addr: [u8; 16]) {
    for n in 0..4 {
        bank.write32(
            REG_IP6AT_BASE + 4 * n as u64,
            u32::from_le_bytes([
                addr[4 * n],
                addr[4 * n + 1],
                addr[4 * n + 2],
                addr[4 * n + 3],
            ]),
        );
    }
    bank.set_bits(REG_IPAV, IPAV_V60);
}

/// Clear one IPv4 slot's IPAV valid bit. The table entry stays
/// programmed but no longer counts for wake. Out-of-range slots
/// are rejected and touch nothing.
pub fn invalidate_ipv4(bank: &mut impl RegBank, slot: usize) -> bool {
    if slot >= 4 {
        return false;
    }
    bank.clear_bits(REG_IPAV, 1 << slot);
    true
}

/// Clear the IPv6 IPAV valid bit (V60).
pub fn invalidate_ipv6(bank: &mut impl RegBank) {
    bank.clear_bits(REG_IPAV, IPAV_V60);
}
