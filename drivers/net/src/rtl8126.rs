//! Realtek RTL8126 / RTL8126A 5 Gigabit Ethernet driver — Stage-1
//! cut: probe + reset + TX/RX rings + one MSI-X vector. No PHY-config
//! tables yet (PHY-config is a follow-up matching the rtl8125 pattern).
//!
//! ## Reference
//!
//! - Linux **`drivers/net/ethernet/realtek/r8169_main.c`** (GPL-2.0;
//!   NARF is GPL-2.0-or-later since 2026-05-20 so adaptation is
//!   permitted): `rtl_chip_infos[]` lines 109–110 (XID 0x649/0x64a →
//!   `RTL_GIGA_MAC_VER_70`), `rtl_hw_start_8126a` at line 3970,
//!   `rtl_init_rxcfg` at line 2608 (`RX_FETCH_DFLT_8125 | RX_DMA_BURST
//!   | RX_PAUSE_SLOT_ON`).
//! - Linux **`drivers/net/ethernet/realtek/r8169_phy_config.c`**:
//!   `rtl8126a_hw_phy_config` at line 1123 (deferred — PHY-config
//!   follow-up matching the rtl8125 stage).
//!
//! ## Relationship to RTL8125
//!
//! The RTL8126 is the 5 Gbps successor to the RTL8125 (2.5 Gbps).
//! The two chips share the same register floor (same MMIO map, same
//! TX/RX descriptor format, same interrupt register layout) — Linux's
//! r8169 driver dispatches both through `rtl_hw_start_8125_common`.
//! The NARF RTL8126 driver reuses every abstraction from
//! [`crate::rtl8125`]:
//!
//! - `TxDesc` / `build_tx_desc` / `build_rx_desc` — identical 16-byte
//!   descriptor format (new-descriptor-format is disabled in
//!   `rtl_hw_start_8125_common`, same as for 8125).
//! - `REG_IMR_8125` / `REG_ISR_8125` / `REG_TPPOLL_8125` — same
//!   offsets (0x38 / 0x3C / 0x90).
//! - `RING_LEN` / `RX_BUF_LEN` — same ring geometry.
//!
//! Key RTL8126-specific differences:
//!
//! 1. **PCI device IDs** — 0x8126 (RTL8126) and 0x5000 (variant).
//! 2. **MAC version XIDs** — 0x649 and 0x64a both decode to
//!    `MacVer70` (RTL_GIGA_MAC_VER_70 in Linux). There is no VER_71
//!    in current Linux upstream.
//! 3. **RxConfig** uses `RX_PAUSE_SLOT_ON` (bit 11) in addition to
//!    `RX_FETCH_DFLT_8125` — per `rtl_init_rxcfg` VER_63..LAST path.
//! 4. **5 Gbps link** — PHYStatus byte carries no dedicated 5G speed
//!    bit. Linux delegates 5G link-rate to the PHY subsystem. This
//!    driver reads the standard PHYStatus byte (same as rtl8125):
//!    `_1000bpsF | LinkStatus` indicates a ≥1G link; the real 5G
//!    speed requires a PHYAR register read (follow-up commit).

#![allow(dead_code)]

mod tests;

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: Realtek Semiconductor Corp.
pub const RTL_VENDOR: u16 = 0x10EC;
/// RTL8126 / RTL8126A — primary 5 GbE device id.
/// Linux r8169_main.c line 242: `{ PCI_VDEVICE(REALTEK, 0x8126) }`.
pub const RTL_DEV_8126: u16 = 0x8126;
/// RTL8126 variant device id (subsystem / OEM SKU).
/// Linux r8169_main.c line 245: `{ PCI_VDEVICE(REALTEK, 0x5000) }`.
pub const RTL_DEV_8126_VAR: u16 = 0x5000;

const ALL_DEV_IDS: &[u16] = &[RTL_DEV_8126, RTL_DEV_8126_VAR];

/// Human-readable name for a known device id.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8126 => "rtl8126",
        RTL_DEV_8126_VAR => "rtl8126-var",
        _ => "rtl8126",
    }
}

// ── Register offsets (BAR2, MMIO) ───────────────────────────────────
// RTL8126 inherits the full RTL8125 register floor unchanged.
// Re-declared here so the module is self-contained; values are
// identical to those in `crate::rtl8125`.

pub(crate) const REG_IDR0: u64 = 0x00;
pub(crate) const REG_MAR0: u64 = 0x08;
pub(crate) const REG_TNPDS: u64 = 0x20;
pub(crate) const REG_CR: u64 = 0x37;
pub(crate) const REG_INT_CFG0_8125: u64 = 0x34;
pub(crate) const REG_IMR_8125: u64 = 0x38;
pub(crate) const REG_ISR_8125: u64 = 0x3C;
pub(crate) const REG_TCR: u64 = 0x40;
pub(crate) const REG_RCR: u64 = 0x44;
pub(crate) const REG_9346CR: u64 = 0x50;
pub(crate) const REG_PHYSTAT: u64 = 0x6C;
pub(crate) const REG_INT_CFG1_8125: u64 = 0x7A;
pub(crate) const REG_TPPOLL_8125: u64 = 0x90;
pub(crate) const REG_RMS: u64 = 0xDA;
pub(crate) const REG_CPLUSCR: u64 = 0xE0;
pub(crate) const REG_RDSAR: u64 = 0xE4;
pub(crate) const REG_MTPS: u64 = 0xEC;

// CR bits.
pub(crate) const CR_TE: u8 = 1 << 2;
pub(crate) const CR_RE: u8 = 1 << 3;
pub(crate) const CR_RST: u8 = 1 << 4;

// 9346CR lock.
pub(crate) const EEM_NORMAL: u8 = 0x00;
pub(crate) const EEM_CONFIG_WRITE: u8 = 0xC0;

// TPPoll doorbell.
pub(crate) const TPPOLL_NPQ: u8 = 1 << 6;

// TCR bits.
pub(crate) const TCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;
pub(crate) const TCR_IFG_STD: u32 = 0b11 << 24;

// RCR bits (shared with rtl8125).
pub(crate) const RCR_APM: u32 = 1 << 1;
pub(crate) const RCR_AM: u32 = 1 << 2;
pub(crate) const RCR_AB: u32 = 1 << 3;
pub(crate) const RCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;

/// `RX_FETCH_DFLT_8125 = 8 << 27` — shared DMA-prefetch threshold.
pub(crate) const RX_FETCH_DFLT_8125: u32 = 8 << 27;

/// `RX_PAUSE_SLOT_ON` (bit 11) — enabled on RTL8125B and later
/// (VER_63..LAST). RTL8126 (VER_70) falls in this range.
/// Linux `r8169_main.c` line 282: `#define RX_PAUSE_SLOT_ON (1 << 11)`.
pub(crate) const RX_PAUSE_SLOT_ON: u32 = 1 << 11;

// INT_CFG0 bits.
pub(crate) const INT_CFG0_ENABLE_8125: u8 = 1 << 0;
pub(crate) const INT_CFG0_CLKREQEN: u8 = 1 << 3;

// 32-bit IMR/ISR bits (same layout as rtl8125).
pub(crate) const INT32_ROK: u32 = 1 << 0;
pub(crate) const INT32_RXERR: u32 = 1 << 1;
pub(crate) const INT32_TOK: u32 = 1 << 2;
pub(crate) const INT32_TXERR: u32 = 1 << 3;
pub(crate) const INT32_RDU: u32 = 1 << 4;
pub(crate) const INT32_LINKCHG: u32 = 1 << 5;
pub(crate) const INT32_RX_FIFO_OVER: u32 = 1 << 6;
pub(crate) const INT32_TDU: u32 = 1 << 7;
pub(crate) const INT32_SYS_ERR: u32 = 1 << 15;

// PHYStatus bits (shared with rtl8125; no dedicated 5G bit in this
// byte — 5G speed requires PHYAR access, deferred to PHY-config stage).
pub(crate) const PHYSTAT_LINKSTS: u8 = 1 << 1;
pub(crate) const PHYSTAT_FULLDUP: u8 = 1 << 0;
pub(crate) const PHYSTAT_10BPS: u8 = 1 << 2;
pub(crate) const PHYSTAT_100BPS: u8 = 1 << 3;
pub(crate) const PHYSTAT_1000BPSF: u8 = 1 << 4;
pub(crate) const PHYSTAT_RXFLOWCTRL: u8 = 1 << 5;
pub(crate) const PHYSTAT_TXFLOWCTRL: u8 = 1 << 6;
/// `TBI_Enable` bit in PHYStatus (bit 7). On legacy chips this signals
/// TBI mode; on the RTL8126 it is set when the link is negotiated at
/// 5 Gbps. Linux defers 5G speed decoding entirely to the PHY
/// subsystem via `phy_print_status`; the NARF PHY-config stage will do
/// likewise via PHYAR access.
pub(crate) const PHYSTAT_TBI_OR_5G: u8 = 1 << 7;

/// Decoded PHYStatus register for the RTL8126. Adds `speed_5g` which
/// is set when `TBI_Enable` (bit 7) reads 1 — the only in-band
/// indicator of a 5 Gbps link that is visible without PHYAR access.
/// The definitive 5G confirmation requires reading the PHY speed
/// negotiation register (deferred; same pattern as 2.5G on rtl8125).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PhyStatus {
    pub link_up: bool,
    pub full_duplex: bool,
    /// True when PHYStatus reports a ≥1 Gbps (or 5 Gbps) link.
    pub speed_1000m_or_above: bool,
    pub speed_100m: bool,
    pub speed_10m: bool,
    /// True when `TBI_Enable` (bit 7) is set. On RTL8126 this
    /// indicates 5 Gbps negotiation; exact confirmation requires
    /// a PHY register read.
    pub speed_5g: bool,
    pub rx_flow_control: bool,
    pub tx_flow_control: bool,
}

impl PhyStatus {
    /// Decode the PHYStatus byte returned by `mmio.read8(REG_PHYSTAT)`.
    pub const fn parse(byte: u8) -> Self {
        Self {
            link_up: byte & PHYSTAT_LINKSTS != 0,
            full_duplex: byte & PHYSTAT_FULLDUP != 0,
            speed_10m: byte & PHYSTAT_10BPS != 0,
            speed_100m: byte & PHYSTAT_100BPS != 0,
            speed_1000m_or_above: byte & PHYSTAT_1000BPSF != 0,
            speed_5g: byte & PHYSTAT_TBI_OR_5G != 0,
            rx_flow_control: byte & PHYSTAT_RXFLOWCTRL != 0,
            tx_flow_control: byte & PHYSTAT_TXFLOWCTRL != 0,
        }
    }

    /// Best-guess link speed string. "5G" is indicated by the
    /// `TBI_Enable` / 5G flag (bit 7); a definitive reading requires
    /// a follow-up PHYAR register access (PHY-config stage).
    pub const fn speed_label(&self) -> &'static str {
        if self.speed_5g {
            "5G"
        } else if self.speed_1000m_or_above {
            "1000M-or-2.5G"
        } else if self.speed_100m {
            "100M"
        } else if self.speed_10m {
            "10M"
        } else {
            "down"
        }
    }
}

// ── MAC version (XID) decode ────────────────────────────────────────
// Linux's r8169_main.c lines 109–110:
//   { 0x7cf, 0x64a, RTL_GIGA_MAC_VER_70, "RTL8126A", FIRMWARE_8126A_3 },
//   { 0x7cf, 0x649, RTL_GIGA_MAC_VER_70, "RTL8126A", FIRMWARE_8126A_2 },
// Both XIDs map to the same MAC version. There is no VER_71 in
// current Linux upstream (VER_LAST = VER_80 for the RTL8127A family).

/// MAC-version classification for the RTL8126 family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MacVersion {
    /// XIDs 0x649 / 0x64a — RTL8126A (RTL_GIGA_MAC_VER_70).
    Ver70,
    /// XID not in the RTL8126 match table; bring-up is still
    /// attempted on the common 8125-compatible path.
    Unknown(u32),
}

/// Extract the 12-bit chip XID from TxConfig (0x40).
/// Same formula as rtl8125: `(txconfig >> 20) & 0xfcf`.
pub const fn decode_xid(txconfig: u32) -> u32 {
    (txconfig >> 20) & 0xfcf
}

/// Classify an XID into `MacVersion`. Only the two RTL8126A XIDs
/// are named; everything else is `Unknown`.
pub const fn mac_version_from_xid(xid: u32) -> MacVersion {
    match xid {
        0x649 | 0x64a => MacVersion::Ver70,
        other => MacVersion::Unknown(other),
    }
}

// ── Descriptor ring geometry ─────────────────────────────────────────
// Reused from rtl8125: 256-slot 16-byte-descriptor rings (same
// `rtl_hw_start_8125_common` disables the new-descriptor-format).

/// Descriptor count per ring.
pub const RING_LEN: usize = 256;
/// Total bytes for one descriptor ring.
pub const RING_BYTES: usize = RING_LEN * 16;

// TX descriptor word0 flags.
pub(crate) const TXD_OWN: u32 = 1 << 31;
pub(crate) const TXD_EOR: u32 = 1 << 30;
pub(crate) const TXD_FS: u32 = 1 << 29;
pub(crate) const TXD_LS: u32 = 1 << 28;
pub(crate) const TXD_LEN_MASK: u32 = 0xFFFF;

// RX descriptor word0 flags.
pub(crate) const RXD_OWN: u32 = 1 << 31;
pub(crate) const RXD_EOR: u32 = 1 << 30;
pub(crate) const RXD_LS: u32 = 1 << 28;
pub(crate) const RXD_LEN_MASK: u32 = 0x3FFF;

/// RX buffer size — 2 KiB, identical to rtl8125 Stage-1.
pub const RX_BUF_LEN: usize = 2048;

const MTPS_DEFAULT: u8 = 0x3B;
const RMS_DEFAULT: u16 = 1536;

/// In-memory TX (and RX) descriptor — 16-byte `repr(C)` layout shared
/// with rtl8125. The RTL8126 hardware DMAs the same on-wire format.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxDesc {
    pub flags_len: u32,
    pub vlan: u32,
    pub addr_lo: u32,
    pub addr_hi: u32,
}
const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);
const _: () = assert!(core::mem::align_of::<TxDesc>() == 16);

/// Build a single-buffer TX descriptor. Identical logic to rtl8125.
pub const fn build_tx_desc(slot: usize, phys: u64, len: u32) -> TxDesc {
    let mut flags = TXD_OWN | TXD_FS | TXD_LS | (len & TXD_LEN_MASK);
    if slot == RING_LEN - 1 {
        flags |= TXD_EOR;
    }
    TxDesc {
        flags_len: flags,
        vlan: 0,
        addr_lo: phys as u32,
        addr_hi: (phys >> 32) as u32,
    }
}

/// Build an RX descriptor for slot `slot`. OWN=1 (NIC-owned); EOR on
/// the wrap slot. Identical layout to rtl8125.
pub const fn build_rx_desc(slot: usize, phys: u64, buf_size: u32) -> TxDesc {
    let mut flags = RXD_OWN | (buf_size & RXD_LEN_MASK);
    if slot == RING_LEN - 1 {
        flags |= RXD_EOR;
    }
    TxDesc {
        flags_len: flags,
        vlan: 0,
        addr_lo: phys as u32,
        addr_hi: (phys >> 32) as u32,
    }
}

// ── TX offload descriptor helpers ───────────────────────────────────
// Same TD1 offload-bit layout as RTL8125 (TxDesc.vlan / word1).
// Linux r8169_main.c `rtl8169_tso_csum_v2` (same path for VER_70).
// RTL8126 uses the v2 offload path identically to RTL8125.

/// TSO: enable giant-send IPv4. Combine with `TD1_IPv4_CS | TD1_TCP_CS`
/// and MSS in `[28:18]`. Linux `r8169_main.c` TD_RSOB_TX.
pub const TD1_GTSENV4: u32 = 1 << 26;
/// MSS field shift for TSO (bits `[28:18]` in `TxDesc.vlan`).
pub const TD1_MSS_SHIFT: u32 = 18;
/// IPv4 header checksum offload. Linux `r8169_main.c` `TD1_IPv4_CS`.
#[allow(non_upper_case_globals)] // TODO(narf): mirrors the datasheet register/bit name
pub const TD1_IPv4_CS: u32 = 1 << 29;
/// TCP checksum offload. Linux `r8169_main.c` `TD1_TCP_CS`.
pub const TD1_TCP_CS: u32 = 1 << 30;

// RX descriptor csum status bits (word0 after chip writes back).
// Same layout as RTL8125 (Linux r8169_main.c csum check path).
pub(crate) const RX_IPOK: u32 = 1 << 5;
pub(crate) const RX_TCPOK: u32 = 1 << 6;
pub(crate) const RX_UDPOK: u32 = 1 << 7;
pub(crate) const RX_IPFAIL: u32 = 1 << 16;
pub(crate) const RX_TCPFAIL: u32 = 1 << 14;
pub(crate) const RX_UDPFAIL: u32 = 1 << 15;

/// Result of hardware checksum verification on a received frame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    /// Hardware did not perform checksum verification (e.g. non-IP).
    None,
    /// Hardware verified the checksum and it passed.
    Ok,
    /// Hardware verified the checksum and it failed.
    Fail,
}

impl TxDesc {
    /// Build a TX descriptor with IPv4 + TCP checksum offload only.
    /// Sets `TD1_IPv4_CS | TD1_TCP_CS` in the vlan word; no TSO.
    /// Mirrors `rtl8125::TxDesc::with_csum`.
    pub const fn with_csum(addr_lo: u32, addr_hi: u32, len: u16) -> Self {
        TxDesc {
            flags_len: TXD_OWN | TXD_FS | TXD_LS | (len as u32 & TXD_LEN_MASK),
            vlan: TD1_IPv4_CS | TD1_TCP_CS,
            addr_lo,
            addr_hi,
        }
    }

    /// Build a TX descriptor with TSO + IPv4 + TCP checksum offload.
    /// Sets `TD1_GTSENV4 | TD1_IPv4_CS | TD1_TCP_CS` and encodes `mss`
    /// in bits `[28:18]` of the vlan word.
    /// Mirrors `rtl8125::TxDesc::with_tso`.
    pub const fn with_tso(addr_lo: u32, addr_hi: u32, len: u16, mss: u16) -> Self {
        TxDesc {
            flags_len: TXD_OWN | TXD_FS | TXD_LS | (len as u32 & TXD_LEN_MASK),
            vlan: TD1_GTSENV4 | TD1_IPv4_CS | TD1_TCP_CS | ((mss as u32) << TD1_MSS_SHIFT),
            addr_lo,
            addr_hi,
        }
    }

    /// Decode the RX checksum result from a chip-writeback descriptor.
    pub const fn rx_csum_result(&self) -> RxCsumResult {
        let done = self.flags_len & (RX_IPOK | RX_TCPOK | RX_UDPOK) != 0;
        if !done {
            return RxCsumResult::None;
        }
        if self.flags_len & (RX_IPFAIL | RX_TCPFAIL | RX_UDPFAIL) != 0 {
            RxCsumResult::Fail
        } else {
            RxCsumResult::Ok
        }
    }
}

// ── Firmware names ───────────────────────────────────────────────────
// Linux r8169_main.c lines 64–65 / 109–110.

/// Firmware for XID 0x64a (RTL8126A, the more-common rev).
/// Linux `FIRMWARE_8126A_3` = `"rtl_nic/rtl8126a-3.fw"`.
pub const FIRMWARE_8126A_3: &str = "rtl_nic/rtl8126a-3.fw";

/// Firmware for XID 0x649.
/// Linux `FIRMWARE_8126A_2` = `"rtl_nic/rtl8126a-2.fw"`.
pub const FIRMWARE_8126A_2: &str = "rtl_nic/rtl8126a-2.fw";

/// Return the firmware name for a given XID.
/// Linux r8169_main.c lines 109–110.
pub const fn firmware_name_for_xid(xid: u32) -> &'static str {
    match xid {
        0x64a => FIRMWARE_8126A_3,
        0x649 => FIRMWARE_8126A_2,
        _ => FIRMWARE_8126A_3,
    }
}

// ── PHY paged-register access types ─────────────────────────────────
// The RTL8126A uses the same paged-MDIO scheme as RTL8125 / RTL8168G.
// "Page" = value written to MII reg 0x1F; the helpers here model the
// Linux `phy_modify_paged` / `phy_write_paged` / `r8168g_phy_param` /
// `rtl8125_phy_param` helpers from r8169_phy_config.c.

/// One entry in the static PHY configuration table.
/// Encodes a `phy_modify_paged` or `phy_write_paged` operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhyConfigEntry {
    /// PHY page (value written to MII reg 0x1F).
    pub page: u16,
    /// MII register within that page.
    pub reg: u8,
    /// Bits to clear (ANDed inverted with current value).
    pub mask: u16,
    /// Bits to set (ORed after masking).
    pub val: u16,
    /// Entry kind.
    pub kind: PhyConfigKind,
}

/// Which PHY-access flavour this entry uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhyConfigKind {
    /// `phy_modify_paged(page, reg, mask, val)` — page via MII reg 0x1F.
    /// Linux r8169_phy_config.c `phy_modify_paged` callers.
    ModifyPaged,
    /// `phy_write_paged(page, reg, val)` — full 16-bit write.
    /// Equivalent to `ModifyPaged` with `mask = 0xFFFF`.
    WritePaged,
    /// `r8168g_phy_param(parm, mask, val)` — page 0x0a43, reg 0x13
    /// = parm, modify reg 0x14.
    /// Linux r8169_phy_config.c lines 42–51.
    R8168gParam,
    /// `rtl8125_phy_param(parm, mask, val)` — MMD VEND2 registers
    /// 0xb87c / 0xb87e.
    /// Linux r8169_phy_config.c lines 53–60.
    Rtl8125Param,
}

// ── Full rtl8126a_hw_phy_config table ───────────────────────────────
//
// Rust translation of `rtl8126a_hw_phy_config` in Linux
// `drivers/net/ethernet/realtek/r8169_phy_config.c` lines 1123–1131.
//
// After firmware load the function applies:
//
//   rtl8168g_enable_gphy_10m  (line 1127):
//     phy_modify_paged(0x0a44, 0x11, 0, BIT(11))
//
//   rtl8125_legacy_force_mode (line 1128):
//     phy_modify_paged(0xa5b, 0x12, BIT(15), 0)
//
//   rtl8168g_disable_aldps    (line 1129):
//     phy_modify_paged(0x0a43, 0x10, BIT(2), 0)
//
//   rtl8125_common_config_eee_phy (line 1130, 3 entries):
//     phy_modify_paged(0xa6d, 0x14, 0x0010, 0x0000)
//     phy_modify_paged(0xa42, 0x14, 0x0080, 0x0000)
//     phy_modify_paged(0xa4a, 0x11, 0x0200, 0x0000)
//
// Total: 6 ModifyPaged entries. Firmware load is handled separately
// by the NARF firmware subsystem before this table is applied.

/// Static PHY configuration table for RTL8126A (VER_70).
///
/// Linux ref: `r8169_phy_config.c` `rtl8126a_hw_phy_config` lines
/// 1123–1131 plus helper expansions at lines 720–728, 993–996,
/// 101–106.
pub const PHY_CONFIG_TABLE: &[PhyConfigEntry] = &[
    // rtl8168g_enable_gphy_10m: phy_modify_paged(0x0a44, 0x11, 0, BIT(11))
    PhyConfigEntry {
        page: 0x0a44,
        reg: 0x11,
        mask: 0x0000,
        val: 1 << 11,
        kind: PhyConfigKind::ModifyPaged,
    },
    // rtl8125_legacy_force_mode: phy_modify_paged(0xa5b, 0x12, BIT(15), 0)
    PhyConfigEntry {
        page: 0x0a5b,
        reg: 0x12,
        mask: 1 << 15,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    // rtl8168g_disable_aldps: phy_modify_paged(0x0a43, 0x10, BIT(2), 0)
    PhyConfigEntry {
        page: 0x0a43,
        reg: 0x10,
        mask: 1 << 2,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    // rtl8125_common_config_eee_phy entry 1: phy_modify_paged(0xa6d, 0x14, 0x0010, 0x0000)
    PhyConfigEntry {
        page: 0x0a6d,
        reg: 0x14,
        mask: 0x0010,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    // rtl8125_common_config_eee_phy entry 2: phy_modify_paged(0xa42, 0x14, 0x0080, 0x0000)
    PhyConfigEntry {
        page: 0x0a42,
        reg: 0x14,
        mask: 0x0080,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    // rtl8125_common_config_eee_phy entry 3: phy_modify_paged(0xa4a, 0x11, 0x0200, 0x0000)
    PhyConfigEntry {
        page: 0x0a4a,
        reg: 0x11,
        mask: 0x0200,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
];

/// Number of entries in `PHY_CONFIG_TABLE`.
pub const PHY_CONFIG_TABLE_LEN: usize = PHY_CONFIG_TABLE.len();

/// Distinct PHY pages touched by `PHY_CONFIG_TABLE` (for smoke tests).
pub const PHY_CONFIG_PAGES: &[u16] = &[0x0a44, 0x0a5b, 0x0a43, 0x0a6d, 0x0a42, 0x0a4a];

// ── Link partner capability negotiation ─────────────────────────────

/// Link speeds, descending preference order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LinkSpeed {
    Down = 0,
    Speed10M = 1,
    Speed100M = 2,
    Speed1G = 3,
    Speed2_5G = 4,
    Speed5G = 5,
}

impl LinkSpeed {
    /// Highest speed mutually supported by `local` and `partner`.
    /// Implements the 5G → 2.5G → 1G → 100M → 10M fallback ladder.
    ///
    /// When local is 5G-capable but partner only advertises ≥1G
    /// (no TBI_Enable in partner), we conservatively report `Speed2_5G`
    /// because the partner could be a 2.5G-only device — the definitive
    /// speed requires a PHYAR read.
    pub const fn negotiate(local: &PhyStatus, partner: &PhyStatus) -> Self {
        if local.speed_5g && partner.speed_5g {
            Self::Speed5G
        } else if local.speed_1000m_or_above && partner.speed_1000m_or_above {
            if local.speed_5g {
                Self::Speed2_5G // partner ≥1G but not 5G; upper bound
            } else {
                Self::Speed1G
            }
        } else if local.speed_100m && partner.speed_100m {
            Self::Speed100M
        } else if local.speed_10m && partner.speed_10m {
            Self::Speed10M
        } else {
            Self::Down
        }
    }
}

// ── MAC helpers ──────────────────────────────────────────────────────

/// Maximum polling iterations for CR.RST self-clear.
pub const RESET_POLL_LIMIT: u32 = 1_000_000;

/// Decode 6-byte MAC from IDR0..5 bytes (identical to rtl8125).
pub fn decode_mac(bytes: &[u8]) -> Option<[u8; 6]> {
    if bytes.len() < 6 {
        return None;
    }
    Some([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
}

/// `true` iff MAC is all-zero or all-FF (invalid sentinels).
pub const fn mac_is_invalid(mac: [u8; 6]) -> bool {
    let mut all_zero = true;
    let mut all_ff = true;
    let mut i = 0;
    while i < 6 {
        if mac[i] != 0x00 {
            all_zero = false;
        }
        if mac[i] != 0xFF {
            all_ff = false;
        }
        i += 1;
    }
    all_zero || all_ff
}

/// Value to write to CR for a software reset.
pub const fn cr_reset_value() -> u8 {
    CR_RST
}

// ── Live driver state ────────────────────────────────────────────────

use core::sync::atomic::{compiler_fence, Ordering};

use alloc::sync::Arc;
use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write,
};
use narf_ipc::{channel, Consumer, Producer};
use narf_net::{Frame, RX_RING_N, TX_RING_N};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    FrameTooLong,
    TxRingFull,
    TxTimeout,
    MsixSetup,
    Other(&'static str),
}

/// A live RTL8126 / RTL8126A 5 GbE controller.
pub struct Rtl8126Nic {
    mmio: MmioRegion,
    tx_ring: DmaBuffer,
    tx_pool: alloc::vec::Vec<DmaBuffer>,
    tx_head: IrqSafeSpinLock<u32>,
    rx_ring: DmaBuffer,
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address read from IDR0..5 at bring-up.
    pub mac: [u8; 6],
    /// MAC version detected from TxConfig.XID at bring-up.
    pub mac_version: MacVersion,
    /// True when PHYStatus.LinkSts read 1 at bring-up.
    pub link_up: bool,
    /// IDT vector wired to MSI-X entry 0, when MSI-X is enabled.
    pub irq_vector: Option<u8>,
    msix: Option<narf_bus::MsixTable>,

    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: all interior-mutable state (`tx_head`, `rx_head`, the IPC
// rings) is guarded by `IrqSafeSpinLock`, and the remaining fields are
// either plain data or DMA/MMIO handles that describe identity-mapped
// physical regions owned exclusively by this NIC instance. There are no
// non-Send raw thread-local handles, so the device can be moved to and
// shared across CPUs.
unsafe impl Send for Rtl8126Nic {}
// SAFETY: every path that mutates shared state goes through the
// `IrqSafeSpinLock` fields above, so concurrent `&Rtl8126Nic` access
// from multiple CPUs is serialized; the bare data fields are read-only
// after bring-up.
unsafe impl Sync for Rtl8126Nic {}

impl core::fmt::Debug for Rtl8126Nic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8126Nic")
            .field("mac", &self.mac)
            .field("mac_version", &self.mac_version)
            .field("link_up", &self.link_up)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

impl Rtl8126Nic {
    /// Bring up the controller: reset, read MAC, detect XID, install
    /// TX + RX rings, enable receive + transmit, observe link state.
    ///
    /// The bring-up sequence mirrors `rtl8125::RtlNic::bring_up` —
    /// both chips use `rtl_hw_start_8125_common` in Linux. The key
    /// RTL8126-specific difference is `RX_PAUSE_SLOT_ON` (bit 11) in
    /// the RxConfig write (per `rtl_init_rxcfg` VER_63..LAST path).
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NicError> {
        // RTL8126 uses the same BAR layout as RTL8125: MMIO in BAR2.
        // SAFETY: caller-asserted exclusive ownership.
        let mmio = unsafe { map_bar(device, 2) }.map_err(|_| NicError::BarMapFailed)?;

        // 1. Software reset.
        // SAFETY: identity-mapped MMIO.
        unsafe { mmio.write8(REG_CR, CR_RST) };
        narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read8(REG_CR) } & CR_RST == 0,
            narf_time::Deadline::after_ms(100),
        );

        // 2. Read MAC from IDR0..5.
        // SAFETY: identity-mapped MMIO.
        let mac = unsafe {
            [
                mmio.read8(REG_IDR0),
                mmio.read8(REG_IDR0 + 1),
                mmio.read8(REG_IDR0 + 2),
                mmio.read8(REG_IDR0 + 3),
                mmio.read8(REG_IDR0 + 4),
                mmio.read8(REG_IDR0 + 5),
            ]
        };

        // 3. Detect MAC version from TxConfig XID.
        // SAFETY: identity-mapped MMIO.
        let txcfg = unsafe { mmio.read32(REG_TCR) };
        let mac_version = mac_version_from_xid(decode_xid(txcfg));

        // 4. Allocate descriptor rings + per-slot buffers.
        let tx_ring =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let rx_ring =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            rx_pool.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }
        let mut tx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            tx_pool.push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?);
        }

        // 5. C+CR: disable VLAN-detag + RX checksum offload (Stage 1).
        // SAFETY: identity-mapped MMIO.
        unsafe { mmio.write16(REG_CPLUSCR, 0) };

        // 6. Enable TX + RX.
        // SAFETY: same.
        unsafe { mmio.write8(REG_CR, CR_TE | CR_RE) };

        // 6a. TX descriptor ring base + TCR.
        let tx_phys = tx_ring.dma_addr().raw();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_TNPDS, tx_phys as u32);
            mmio.write32(REG_TNPDS + 4, (tx_phys >> 32) as u32);
            mmio.write32(REG_TCR, TCR_MXDMA_UNLIMITED | TCR_IFG_STD);
            mmio.write8(REG_MTPS, MTPS_DEFAULT);
        }

        // 6b. Pre-fill RX descriptors.
        let rx_ring_phys = rx_ring.dma_addr().raw();
        for (i, buf) in rx_pool.iter().enumerate() {
            let buf_phys = buf.dma_addr().raw();
            let mut flags = RXD_OWN | (RX_BUF_LEN as u32 & RXD_LEN_MASK);
            if i == RING_LEN - 1 {
                flags |= RXD_EOR;
            }
            let d = TxDesc {
                flags_len: flags,
                vlan: 0,
                addr_lo: buf_phys as u32,
                addr_hi: (buf_phys >> 32) as u32,
            };
            // SAFETY: identity-mapped DMA ring page; i < RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rx_ring_phys + (i * 16) as u64)
                        .kernel_mut_ptr::<TxDesc>(),
                    d,
                );
            }
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_RDSAR, rx_ring_phys as u32);
            mmio.write32(REG_RDSAR + 4, (rx_ring_phys >> 32) as u32);
            mmio.write16(REG_RMS, RMS_DEFAULT);
        }

        // 6c. RxConfig — RTL8126 (VER_70) uses the VER_63..LAST path:
        //     `RX_FETCH_DFLT_8125 | RX_DMA_BURST | RX_PAUSE_SLOT_ON`.
        //     `RX_DMA_BURST` = `RCR_MXDMA_UNLIMITED` (7 << 8) in this
        //     driver's notation; `RX_PAUSE_SLOT_ON` = bit 11 (extra
        //     vs RTL8125A's VER_61 path).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(
                REG_RCR,
                RX_FETCH_DFLT_8125
                    | RCR_APM
                    | RCR_AM
                    | RCR_AB
                    | RCR_MXDMA_UNLIMITED
                    | RX_PAUSE_SLOT_ON,
            );
        }

        // 7. Disable interrupt aggregation (same as rtl8125 Stage 1).
        // SAFETY: identity-mapped MMIO.
        unsafe { mmio.write8(REG_INT_CFG0_8125, 0) };

        // 8. Mask all interrupts; clear any latched status.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_IMR_8125, 0);
            mmio.write32(REG_ISR_8125, 0xFFFF_FFFF);
        }

        // 9. PHYStatus snapshot. RTL8126 PHYStatus byte: bits 0..6
        //    same as rtl8125; bit 7 (`TBI_Enable`) set at 5 Gbps.
        // SAFETY: same.
        let phystat = unsafe { mmio.read8(REG_PHYSTAT) };
        let link_up = phystat & PHYSTAT_LINKSTS != 0;

        // 10. Re-lock config registers.
        // SAFETY: same.
        unsafe { mmio.write8(REG_9346CR, EEM_NORMAL) };

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let nic = Arc::new(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_head: IrqSafeSpinLock::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            mac_version,
            link_up,
            irq_vector: None,
            msix: None,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        spawn_pumps(nic.clone(), rx_prod, tx_cons);

        Arc::try_unwrap(nic).map_err(|_| NicError::NoMemory)
    }

    /// Bring up MSI-X with a single vector wired to entry 0.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, NicError> {
        let mut table = narf_bus::enable_msix(cap, device).map_err(|_| NicError::MsixSetup)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| NicError::MsixSetup)?;
        let _ = table.alloc_vector().ok_or(NicError::MsixSetup)?;
        // SAFETY: x2APIC is online by Stage-4 boot.
        let target_apic = unsafe { narf_interrupts::current_cpu_target_id() };
        // SAFETY: caller-authority.
        unsafe { table.program_vector(0, target_apic, v) }.map_err(|_| NicError::MsixSetup)?;
        // SAFETY: same.
        unsafe { table.enable() }.map_err(|_| NicError::MsixSetup)?;

        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(
                REG_IMR_8125,
                INT32_ROK | INT32_TOK | INT32_LINKCHG | INT32_RDU | INT32_TDU,
            );
        }

        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// Transmit a single Ethernet frame (polled completion).
    pub fn transmit(&self, frame: &[u8]) -> Result<(), NicError> {
        if frame.is_empty() || frame.len() > 1518 {
            return Err(NicError::FrameTooLong);
        }
        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let phys = self.tx_pool[slot].dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(self.tx_pool[slot].cpu_mut_ptr_at::<u8>(i as u64), *b);
            }
        }
        let ring_phys = self.tx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // SAFETY: identity-mapped DMA ring.
        let cur_flags = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
        };
        if cur_flags & TXD_OWN != 0 {
            return Err(NicError::TxRingFull);
        }

        let mut flags = TXD_OWN | TXD_FS | TXD_LS | (frame.len() as u32 & TXD_LEN_MASK);
        if slot == RING_LEN - 1 {
            flags |= TXD_EOR;
        }
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                0u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 8).kernel_mut_ptr::<u32>(),
                phys as u32,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 12).kernel_mut_ptr::<u32>(),
                (phys >> 32) as u32,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<u32>(),
                flags,
            )
        };
        compiler_fence(Ordering::SeqCst);

        // Ring the TX doorbell at TxPoll_8125 (0x90).
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.write8(REG_TPPOLL_8125, TPPOLL_NPQ) };

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        drop(head_g);

        let owned = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA ring.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>()) } & TXD_OWN == 0,
            narf_time::Deadline::after_ms(250),
        );
        if !owned {
            return Err(NicError::TxTimeout);
        }
        Ok(())
    }

    /// Pop one received frame off the RX ring.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        let mut head_g = self.rx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let ring_phys = self.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // SAFETY: identity-mapped DMA ring.
        let flags_len = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
        };
        if flags_len & RXD_OWN != 0 {
            return None;
        }

        let len = (flags_len & RXD_LEN_MASK) as usize;
        let buf_phys = self.rx_pool[slot].dma_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(len.min(RX_BUF_LEN));
        if flags_len & RXD_LS != 0 {
            let copy_len = len.min(RX_BUF_LEN);
            for i in 0..copy_len {
                // SAFETY: `buf_phys` is the identity-mapped physical base
                // of this slot's RX DMA buffer (RX_BUF_LEN bytes); `i <
                // copy_len <= RX_BUF_LEN`, so the byte read is in bounds.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                out.push(unsafe {
                    core::ptr::read_volatile(self.rx_pool[slot].cpu_ptr_at::<u8>(i as u64))
                });
            }
        }

        // Rearm the descriptor.
        let mut new_flags = RXD_OWN | (RX_BUF_LEN as u32 & RXD_LEN_MASK);
        if slot == RING_LEN - 1 {
            new_flags |= RXD_EOR;
        }
        let d = TxDesc {
            flags_len: new_flags,
            vlan: 0,
            addr_lo: buf_phys as u32,
            addr_hi: (buf_phys >> 32) as u32,
        };
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<TxDesc>(),
                d,
            )
        };
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        Some(out)
    }

    /// Read the PHY-status register.
    pub fn phy_status(&self) -> u8 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read8(REG_PHYSTAT) }
    }

    /// Read + write-1-clear the 32-bit ISR.
    pub fn ack_isr(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        let s = unsafe { self.mmio.read32(REG_ISR_8125) };
        // SAFETY: same.
        unsafe { self.mmio.write32(REG_ISR_8125, s) };
        s
    }

    /// Re-evaluate link state from PHYStatus.
    pub fn refresh_link_state(&mut self) -> bool {
        // SAFETY: identity-mapped MMIO.
        let phystat = unsafe { self.mmio.read8(REG_PHYSTAT) };
        let up = phystat & PHYSTAT_LINKSTS != 0;
        self.link_up = up;
        up
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<Rtl8126Nic>>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

    // SAFETY: caller-authority over the device.
    let dev = match unsafe { Rtl8126Nic::bring_up(&device, &cap) } {
        Ok(d) => Arc::new(d),
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    {
        // SAFETY: `dev` was just created here and has not been published
        // (CONTROLLER is set below, no clones exist yet), so its Arc
        // refcount is 1 and this is the only reference — forming a unique
        // `&mut Rtl8126Nic` from the as_ptr pointer does not alias.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let d = unsafe { &mut *(Arc::as_ptr(&dev) as *mut Rtl8126Nic) };
        *d.rx_ipc_ring.lock() = Some(rx_cons);
        *d.tx_ipc_ring.lock() = Some(tx_prod);
    }

    *CONTROLLER.lock() = Some(dev.clone());

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("rtl8126"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Rtl8126NicIface);
    }

    spawn_pumps(dev, rx_prod, tx_cons);

    Ok(())
}

fn spawn_pumps(
    device: Arc<Rtl8126Nic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        rtl8126_rx_pump(d1, rx_prod).await;
    });
    let d2 = device;
    narf_scheduler::spawn(async move {
        rtl8126_tx_pump(d2, tx_cons).await;
    });
}

async fn rtl8126_rx_pump(device: Arc<Rtl8126Nic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    loop {
        if let Some(pkt) = device.receive() {
            let dma_buf =
                alloc_coherent(pkt.len(), DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, pkt.len() as u32);
            frame.payload_mut().copy_from_slice(&pkt);
            let _ = rx_prod.send(frame).await;
        }
        narf_scheduler::yield_now().await;
    }
}

async fn rtl8126_tx_pump(device: Arc<Rtl8126Nic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload());
    }
}

/// Register a PCI match-table entry per supported device id.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: RTL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once `probe` has installed a controller.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Test-side accessor.
pub fn with_controller<R>(f: impl FnOnce(&Rtl8126Nic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

/// Mutable accessor for tests.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut Rtl8126Nic) -> R) -> Option<R> {
    CONTROLLER
        .lock()
        .as_mut()
        .map(|a| f(Arc::get_mut(a).expect("Rtl8126Nic static has multiple owners")))
}

/// `narf_net::Interface` implementation.
#[derive(Debug)]
pub struct Rtl8126NicIface;

impl narf_net::Interface for Rtl8126NicIface {
    fn name(&self) -> &str {
        "rtl8126"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up).unwrap_or(false)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.rx_ipc_ring.lock().take();
            }
        });
        &RING
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.tx_ipc_ring.lock().take();
            }
        });
        &RING
    }
}

impl crate::HwNic for Rtl8126NicIface {
    fn name(&self) -> &'static str {
        "rtl8126"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up).unwrap_or(false)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::RealtekRtl8168
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        RING_LEN
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as narf_net::Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as narf_net::Interface>::tx_ring(self)
    }
}
