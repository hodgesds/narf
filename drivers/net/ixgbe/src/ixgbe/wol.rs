//! ixgbe Wake-on-LAN — WUFC / WUC / WUS (+ IP4AT/IP6AT).
//!
//! Grounding: Intel 82599 Datasheet rev. 2.0 §8.2.3.24.1 (WUC at
//! 0x05800: PME_En bit 1, PME_Status bit 2 write-1-to-clear),
//! §8.2.3.24.2 (WUFC at 0x05808: LNKC 0, MAG 1, EX 2, MC 3, BC 4,
//! ARP 5, IPV4 6, IPV6 7, NoTCO 15, FLX0..5 16..21), §8.2.3.24.3
//! (WUS at 0x05810, RW1C, same bits + MNG 8), §8.2.3.24.5
//! (IP4AT at 0x05840 + 8*n, n = 0..3), §8.2.3.24.6 (IP6AT at
//! 0x05880 + 4*n, 4 words per address). No Linux ixgbe source
//! consulted.
//!
//! Per-part support (the lane brief's datasheet check):
//! * 82599EB — supported: the 82599 datasheet's §8.2.3.24 + power
//!   management chapter describe the full WoL filter set.
//! * X540-AT2 / X550EM_x — NOT enabled: the X540 datasheet was not
//!   consulted in this stream, so no claim is made either way.
//! * X550 — controller-level WoL exists but is LOM/board-gated
//!   (Intel's own adapter guidance: most 10 GbE adapters do not
//!   support WoL; the X550 controller supports it as a LAN on
//!   Motherboard when the board enables it). The driver therefore
//!   does not arm X550 WoL on its own; a board that wires it must
//!   opt in explicitly (follow-up issue, see spec §14).
//!
//! Deliberately NOT programmed: IPAV. The datasheet text extracted
//! as "0x5838", which is one hex digit short of the neighbouring
//! 0x058xx registers (expected 0x05838); that ambiguity is a
//! remainder, not a value to guess — directed-IP wake-up works
//! without it on the 82599 path the driver enables (magic packet
//! + link change), and IP4AT/IP6AT programming below is provided
//!   for the caller that supplies the addresses.

use super::queues::RegBank;

/// Wake-up registers (datasheet §8.2.3.24).
pub const REG_WUC: u64 = 0x05800;
pub const REG_WUFC: u64 = 0x05808;
pub const REG_WUS: u64 = 0x05810;
pub const REG_IP4AT_BASE: u64 = 0x05840;
pub const REG_IP6AT_BASE: u64 = 0x05880;

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

/// Per-part WoL support (see the module header for the reasoning).
/// `device_id` is the PCI device id from the driver's match table.
pub fn wol_supported(device_id: u16) -> bool {
    // 82599EB only. X540/X550EM_x are ungrounded in this stream;
    // X550 is LOM/board-gated and must not be armed blindly.
    device_id == super::IXGBE_DEV_82599EB
}

/// Program one directed-IPv4 wake address (IP4AT[n], n = 0..3).
/// The address is stored as a single little-endian word.
pub fn program_ipv4(bank: &mut impl RegBank, slot: usize, addr: [u8; 4]) -> bool {
    if slot >= 4 {
        return false;
    }
    bank.write32(REG_IP4AT_BASE + 8 * slot as u64, u32::from_le_bytes(addr));
    true
}

/// Program the directed-IPv6 wake address (IP6AT, 4 words, LS byte
/// of word 0 first on the wire).
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
}
