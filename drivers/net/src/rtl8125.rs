//! Realtek RTL8125 / RTL8125B 2.5 Gigabit Ethernet driver — Stage-4
//! cut. Stage 1 lands the PCI match table and the BAR0 register
//! decoder; subsequent stages add MAC reset / MAC read and TX
//! descriptor packing.
//!
//! Clean-room: register layout sourced from Realtek's public
//! "RTL8125 Series 2.5 Gigabit Ethernet Controller — Registers
//! Datasheet" (Rev. 1.0). No GPL Linux `r8169_main.c` / `r8125`
//! sources consulted.
//!
//! Per the datasheet §2 the RTL8125 keeps the legacy RTL8169/8168
//! register-layout floor (IDR0..5, CR, IMR/ISR, TCR, RCR at the same
//! offsets) and extends it with 2.5 Gbps-specific blocks at offsets
//! ≥ 0x100. Stage 1 only consumes the floor.

#![allow(dead_code)]

mod tests;

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: Realtek Semiconductor Corp.
pub const RTL_VENDOR: u16 = 0x10EC;
/// RTL8125 — original 2.5 GbE silicon.
pub const RTL_DEV_8125: u16 = 0x8125;
/// RTL8125B — refreshed 2.5 GbE silicon. Same register layout as
/// RTL8125, only differs in PHY-side feature negotiation.
pub const RTL_DEV_8125B: u16 = 0x3000;

const ALL_DEV_IDS: &[u16] = &[RTL_DEV_8125, RTL_DEV_8125B];

/// Human-readable name for a known device id; `"rtl8125"` falls back
/// for anything not on the match table.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8125  => "rtl8125",
        RTL_DEV_8125B => "rtl8125b",
        _             => "rtl8125",
    }
}

// ── Register offsets (BAR0, MMIO) ───────────────────────────────────
// Datasheet §2 "MAC Configuration Registers". Offsets shared with
// RTL8168 are noted; RTL8125-specific extensions live ≥ 0x100.

/// IDR0..5 — MAC address (byte-readable). §2.1.
pub(crate) const REG_IDR0:    u64 = 0x00;
/// MAR0..7 — multicast hash filter (8 bytes). §2.2.
pub(crate) const REG_MAR0:    u64 = 0x08;
/// TNPDS — TX normal-priority descriptor base (64-bit). §2.3.
pub(crate) const REG_TNPDS:   u64 = 0x20;
/// CR — Command (RST/RE/TE). §2.4.
pub(crate) const REG_CR:      u64 = 0x37;
/// TPPoll — TX priority polling doorbell. §2.5.
pub(crate) const REG_TPPOLL:  u64 = 0x38;
/// IMR — interrupt mask (16-bit legacy alias; RTL8125 also exposes a
/// 32-bit mirror at 0xF0). §2.6.
pub(crate) const REG_IMR:     u64 = 0x3C;
/// ISR — interrupt status (write-1-clear, 16-bit legacy alias). §2.6.
pub(crate) const REG_ISR:     u64 = 0x3E;
/// TCR — TX configuration. §2.7.
pub(crate) const REG_TCR:     u64 = 0x40;
/// RCR — RX configuration. §2.8.
pub(crate) const REG_RCR:     u64 = 0x44;
/// 9346CR — config-register write-lock latch. §2.9.
pub(crate) const REG_9346CR:  u64 = 0x50;
/// PHYStatus — PHY status (LinkSts at bit 1). §2.10.
pub(crate) const REG_PHYSTAT: u64 = 0x6C;
/// RMS — RX max packet size (14-bit). §2.11.
pub(crate) const REG_RMS:     u64 = 0xDA;
/// C+CR — VLAN/csum offload toggles. §2.12.
pub(crate) const REG_CPLUSCR: u64 = 0xE0;
/// RDSAR — RX descriptor base (64-bit, 256-byte aligned). §2.13.
pub(crate) const REG_RDSAR:   u64 = 0xE4;
/// MTPS — Max TX packet size (units of 128 bytes). §2.14.
pub(crate) const REG_MTPS:    u64 = 0xEC;

// CR bits (§2.4).
pub(crate) const CR_TE:  u8 = 1 << 2;
pub(crate) const CR_RE:  u8 = 1 << 3;
pub(crate) const CR_RST: u8 = 1 << 4;

// TPPoll bits (§2.5).
pub(crate) const TPPOLL_NPQ: u8 = 1 << 6;

// 9346CR (config-write lock). Bits 7:6 = EEM. 00=normal, 11=write-en.
pub(crate) const EEM_NORMAL:       u8 = 0x00;
pub(crate) const EEM_CONFIG_WRITE: u8 = 0xC0;

// RCR bits (§2.8).
pub(crate) const RCR_AAP:             u32 = 1 << 0;
pub(crate) const RCR_APM:             u32 = 1 << 1;
pub(crate) const RCR_AM:              u32 = 1 << 2;
pub(crate) const RCR_AB:              u32 = 1 << 3;
pub(crate) const RCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;
pub(crate) const RCR_RXFTH_NONE:      u32 = 0b111 << 13;

// TCR bits (§2.7).
pub(crate) const TCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;
pub(crate) const TCR_IFG_STD:         u32 = 0b11  << 24;

// ISR / IMR (16-bit alias) bits (§2.6).
pub(crate) const INT_ROK:     u16 = 1 << 0;
pub(crate) const INT_TOK:     u16 = 1 << 2;
pub(crate) const INT_RDU:     u16 = 1 << 4;
pub(crate) const INT_LINKCHG: u16 = 1 << 5;
pub(crate) const INT_TDU:     u16 = 1 << 7;

// PHYStatus bits (§2.10).
pub(crate) const PHYSTAT_LINKSTS: u8 = 1 << 1;

// ── MAC reset / MAC-address decode ──────────────────────────────────
// Stage 2: pure-data helpers. The live `bring_up` path lands later;
// these routines isolate the parts a unit test can exercise without
// touching MMIO.

/// Maximum number of polling iterations to spend waiting for CR.RST
/// to self-clear. RTL8125 datasheet §2.4 notes the reset typically
/// completes in << 1 ms; the cap is a watchdog on hung silicon.
pub const RESET_POLL_LIMIT: u32 = 1_000_000;

/// Decode a 6-byte MAC from the IDR0..5 register window. The
/// datasheet §2.1 specifies IDR is byte-readable and 4-byte writable;
/// the on-wire byte order is `IDR0` = first MAC octet, `IDR5` = last.
/// `bytes` must be a slice of length ≥ 6 starting at the IDR0 offset.
pub fn decode_mac(bytes: &[u8]) -> Option<[u8; 6]> {
    if bytes.len() < 6 { return None; }
    Some([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
}

/// `true` iff the MAC reads as either all-zero (no EEPROM image) or
/// all-FF (controller floor / disconnected). Used as a sanity gate
/// after `decode_mac`.
pub const fn mac_is_invalid(mac: [u8; 6]) -> bool {
    let mut all_zero = true;
    let mut all_ff   = true;
    let mut i = 0;
    while i < 6 {
        if mac[i] != 0x00 { all_zero = false; }
        if mac[i] != 0xFF { all_ff   = false; }
        i += 1;
    }
    all_zero || all_ff
}

/// Build the byte to write to CR (§2.4) to kick a software reset.
/// Provided as a helper so the test suite can assert the bit pattern
/// without poking MMIO. RST is self-clearing once the chip has
/// re-initialised the FIFOs + descriptor pointers.
pub const fn cr_reset_value() -> u8 { CR_RST }

// ── Driver-match registration ────────────────────────────────────────

/// Probe entry — Stage 1 returns `Ok(())` without touching hardware.
/// Subsequent stages will plumb `bring_up` here.
pub fn probe(
    _device: narf_bus::BusDevice,
    _cap:    narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    // Stage 1 is structural only — no live IO. Stage 2+ will bring
    // up the controller here.
    Ok(())
}

/// Register a PCI match-table entry per supported device id. Realtek
/// keeps the IDs distinct between RTL8125 and RTL8125B even though
/// the register layouts are identical; we register both.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: RTL_VENDOR, device: did,
            },
            probe,
        });
    }
}
