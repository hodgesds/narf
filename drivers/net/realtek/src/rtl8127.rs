//! Realtek RTL8127 / RTL8127A 10 Gigabit Ethernet driver — Stage-1
//! cut, extended with the Linux compared feature set: probe +
//! reset + TX/RX rings + one MSI-X vector, plus TX checksum
//! (TCP/UDP, v4/v6) and TSO (v2 layout — VER_80 is csum-v2),
//! VLAN tag insertion on TX, RX checksum decode, jumbo-sized
//! rings / RMS / MTPS, WoL register programming (including the
//! 8125-family MAC-OCP steps), the EEE TX LPI idle timer, and
//! the RSS register programming model as a dormant
//! [`Rtl8127Nic::configure_rss`] method (see below). Deliberate
//! asymmetries: RX VLAN stripping stays OFF, the interface MTU
//! stays 1500 with offloads advertised, and RSS is NOT enabled
//! at bring-up — steering registers are programmed only on an
//! explicit `configure_rss` call, and enabling steering in
//! production additionally needs a multi-ring datapath
//! (per-queue descriptor bases, RSS descriptor format,
//! per-queue pumps, 30 MSI-X vectors) that the current
//! single-consumer `Interface` cannot express. Bring-up keeps
//! Linux's single-queue behavior (`RSS_CTRL` = 0).
//!
//! ## RSS, precisely
//!
//! Linux enables RSS only on VER_80 (`rtl_hw_support_rss`), and
//! this is the only chip in the family with that gap. The
//! register programming (key / indirection / control /
//! queue-count / descriptor-type) is implemented in
//! `crate::features` and wired here as `configure_rss`, but the
//! datapath that would consume steered queues does not exist
//! yet and QEMU does not emulate an 8127, so it would be
//! untestable locally. The multi-ring datapath is a follow-up;
//! until then `configure_rss` is dormant, exercised only by the
//! shared feature fixtures.
//!
//! ## Reference
//!
//! - Linux **`drivers/net/ethernet/realtek/r8169_main.c`** (GPL-2.0;
//!   NARF is GPL-2.0-or-later so adaptation is permitted):
//!   `rtl_chip_infos[]` entry `{ 0x7cf, 0x6c9, RTL_GIGA_MAC_VER_80,
//!   "RTL8127A", FIRMWARE_8127A_1 }`, `rtl_hw_start_8127a`, and
//!   `rtl_init_rxcfg`'s `VER_63 … VER_80` arm
//!   (`RX_FETCH_DFLT_8125 | RX_DMA_BURST | RX_PAUSE_SLOT_ON`).
//! - Linux **`drivers/net/ethernet/realtek/r8169_phy_config.c`**:
//!   `rtl8127a_hw_phy_config`.
//!
//! ## Hardware this targets
//!
//! Verified against the Minisforum **MS-03** (Panther Lake-H), which
//! carries an RTL8127 at PCI `58:00.0` reporting
//! `10ec:8127 (rev 05)`, subsystem `10ec:0123`.
//!
//! ## Relationship to RTL8125 / RTL8126
//!
//! The RTL8127 is the 10 Gbps member of the same family. All three
//! chips share the register floor Linux drives through
//! `rtl_hw_start_8125_common`: the same MMIO map in BAR2, the same
//! 16-byte TX/RX descriptor format (the new-descriptor format stays
//! disabled), and the same 32-bit IMR/ISR at 0x38 / 0x3C with the
//! TxPoll doorbell at 0x90. This module re-declares those offsets so
//! it is self-contained, exactly as [`crate::rtl8126`] does.
//!
//! RTL8127-specific deltas:
//!
//! 1. **PCI device ID** — `0x8127`.
//! 2. **MAC version XID** — `0x6c9` decodes to `RTL_GIGA_MAC_VER_80`
//!    (`MacVersion::Ver80` here); it is the newest entry in Linux's
//!    chip table.
//! 3. **Firmware** — `rtl_nic/rtl8127a-1.fw`.
//! 4. **10 Gbps link** — the PHYStatus byte at 0x6C has no 10G speed
//!    bit. As with 2.5G on RTL8125 and 5G on RTL8126, Linux delegates
//!    the rate entirely to phylib. Stage-1 therefore reports link
//!    up/down and the coarse `≥1G` class from PHYStatus; the exact
//!    negotiated rate needs an MDIO read and lands with the PHY-config
//!    stage.
//! 5. **Jumbo frames** — Linux's `rtl_jumbo_max` gives VER_80 the
//!    16K class (16362-byte MTU); rings, RMS and MTPS are sized
//!    to that family bound, matching the rest of the family.
//!
//! ## PHY bring-up
//!
//! [`PHY_CONFIG_TABLE`] is a complete, in-order transcription of
//! `rtl8127a_1_hw_phy_config`, and [`phy`] applies it: the firmware
//! patch first when `rtl_nic/rtl8127a-1.fw` is available, then the
//! table. See that module for why there is no MDIO bus involved —
//! every access is an address computation onto one OCP window.
//!
//! ## Scope
//!
//! What this still does not do:
//!
//! - **EPHY / ASPM entry latency.** Linux's `rtl_hw_start_8127a`
//!   calls `rtl_set_def_aspm_entry_latency` before the common path;
//!   this leaves the firmware's ASPM programming alone.
//! - **SFP mode.** `rtl_sfp_init` runs only when `tp->sfp_mode` is
//!   set. The MS-03's RTL8127 is an RJ45 copper port, so the
//!   `r8127_sfp_init_10g` SerDes sequence is out of scope here.
//! - **Link-speed reporting above 1G.** Unchanged: the PHYStatus
//!   byte has no 10G bit, so the rate still needs an MDIO read even
//!   now that one is available.

#![allow(dead_code)]

/// The shared PHY-access module, re-exported under its historic
/// path so `rtl8127::phy::PhyAccess` and the tests' `super::phy::…`
/// imports keep resolving.
pub use crate::phy_access as phy;
/// Shared PHY-config entry types (see `crate::phy_access`).
pub use crate::phy_access::{PhyConfigEntry, PhyConfigKind};

mod tests;

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: Realtek Semiconductor Corp.
pub const RTL_VENDOR: u16 = 0x10EC;
/// RTL8127 / RTL8127A — 10 GbE device id.
/// Linux `r8169_main.c`: `{ PCI_VDEVICE(REALTEK, 0x8127) }`.
pub const RTL_DEV_8127: u16 = 0x8127;

const ALL_DEV_IDS: &[u16] = &[RTL_DEV_8127];

/// Human-readable name for a known device id.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8127 => "rtl8127",
        _ => "rtl8127",
    }
}

// ── Register offsets (BAR2, MMIO) ───────────────────────────────────
// Inherited unchanged from the RTL8125 register floor.

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

// RCR bits.
pub(crate) const RCR_APM: u32 = 1 << 1;
pub(crate) const RCR_AM: u32 = 1 << 2;
pub(crate) const RCR_AB: u32 = 1 << 3;
pub(crate) const RCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;

/// `RX_FETCH_DFLT_8125 = 8 << 27` — shared DMA-prefetch threshold.
pub(crate) const RX_FETCH_DFLT_8125: u32 = 8 << 27;
/// `RX_PAUSE_SLOT_ON` (bit 11) — set on VER_63 … VER_80, which
/// includes the RTL8127A (VER_80).
pub(crate) const RX_PAUSE_SLOT_ON: u32 = 1 << 11;

// INT_CFG0 bits.
pub(crate) const INT_CFG0_ENABLE_8125: u8 = 1 << 0;
/// `INT_CFG0_CLKREQEN` — on VER_70 / VER_80 the ASPM ClkReq enable
/// moved from Config2 into INT_CFG0 bit 3.
pub(crate) const INT_CFG0_CLKREQEN: u8 = 1 << 3;

/// First register of the per-vector interrupt-coalescing block that
/// `rtl_hw_start_8125_common` zeroes.
pub(crate) const COALESCE_BLOCK_START: u64 = 0xa00;
/// One past the last coalescing register on VER_80. VER_63 / VER_70
/// stop at 0xa80; the RTL8127A block is twice as wide.
pub(crate) const COALESCE_BLOCK_END_8127: u64 = 0xb00;

// 32-bit IMR/ISR bits.
pub(crate) const INT32_ROK: u32 = 1 << 0;
pub(crate) const INT32_RXERR: u32 = 1 << 1;
pub(crate) const INT32_TOK: u32 = 1 << 2;
pub(crate) const INT32_TXERR: u32 = 1 << 3;
pub(crate) const INT32_RDU: u32 = 1 << 4;
pub(crate) const INT32_LINKCHG: u32 = 1 << 5;
pub(crate) const INT32_RX_FIFO_OVER: u32 = 1 << 6;
pub(crate) const INT32_TDU: u32 = 1 << 7;
pub(crate) const INT32_SYS_ERR: u32 = 1 << 15;

// PHYStatus bits.
pub const PHYSTAT_LINKSTS: u8 = 1 << 1;
pub const PHYSTAT_FULLDUP: u8 = 1 << 0;
pub(crate) const PHYSTAT_10BPS: u8 = 1 << 2;
pub const PHYSTAT_100BPS: u8 = 1 << 3;
pub const PHYSTAT_1000BPSF: u8 = 1 << 4;
pub(crate) const PHYSTAT_RXFLOWCTRL: u8 = 1 << 5;
pub(crate) const PHYSTAT_TXFLOWCTRL: u8 = 1 << 6;

/// Decoded PHYStatus register.
///
/// The byte carries no multi-gig speed bit on this family — 2.5G on
/// RTL8125, 5G on RTL8126 and 10G here all require an MDIO read.
/// `speed_1000m_or_above` is therefore exactly what the register can
/// tell us in band, and `speed_label` says so rather than inventing a
/// rate.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PhyStatus {
    pub link_up: bool,
    pub full_duplex: bool,
    /// True when PHYStatus reports a ≥1 Gbps link. On the RTL8127
    /// this covers 1G / 2.5G / 5G / 10G alike.
    pub speed_1000m_or_above: bool,
    pub speed_100m: bool,
    pub speed_10m: bool,
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
            rx_flow_control: byte & PHYSTAT_RXFLOWCTRL != 0,
            tx_flow_control: byte & PHYSTAT_TXFLOWCTRL != 0,
        }
    }

    /// In-band link-speed class. Never claims a specific multi-gig
    /// rate — `">=1G"` is the honest upper bound until MDIO lands.
    pub const fn speed_label(&self) -> &'static str {
        if !self.link_up {
            "down"
        } else if self.speed_1000m_or_above {
            ">=1G"
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
// Linux `rtl_chip_infos[]`:
//   { 0x7cf, 0x6c9, RTL_GIGA_MAC_VER_80, "RTL8127A", FIRMWARE_8127A_1 }

/// MAC-version classification for the RTL8127 family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MacVersion {
    /// XID 0x6c9 — RTL8127A (`RTL_GIGA_MAC_VER_80`).
    Ver80,
    /// XID not in the RTL8127 match table; bring-up is still
    /// attempted on the common 8125-compatible path.
    Unknown(u32),
}

/// Extract the 12-bit chip XID from TxConfig (0x40).
/// Same formula as the rest of the family: `(txconfig >> 20) & 0xfcf`.
pub const fn decode_xid(txconfig: u32) -> u32 {
    (txconfig >> 20) & 0xfcf
}

/// Classify an XID into [`MacVersion`].
pub const fn mac_version_from_xid(xid: u32) -> MacVersion {
    match xid {
        0x6c9 => MacVersion::Ver80,
        other => MacVersion::Unknown(other),
    }
}

// ── Descriptor ring geometry ─────────────────────────────────────────

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

/// RX buffer size. Linux sizes every RX buffer on this family to
/// `R8169_RX_BUF_SIZE` (16 KiB − 1) and programs RMS to the
/// buffer bound, independent of MTU.
pub const RX_BUF_LEN: usize = 16383;

/// TX slot buffer size: one slot must hold the largest frame this
/// driver will transmit — the family jumbo tagged frame
/// (16384 bytes).
pub const TX_BUF_LEN: usize = 16384;

/// In-memory TX (and RX) descriptor — 16-byte `repr(C)` layout shared
/// with rtl8125 / rtl8126.
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

/// Build a single-buffer TX descriptor.
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

/// Build an RX descriptor for `slot`. OWN=1 (NIC-owned); EOR on the
/// wrap slot.
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
// Canonical definitions live in `crate::features` (corrected
// placement: v2 GTSENV/GTTCPHO in word0, MSS/csum bits/TCPHO in
// word1). The previous in-tree comments placed the v2 bits in
// word1, which was wrong and would have corrupted the MSS field.
// Linux drives all three 8125-family chips through
// `rtl8169_tso_csum_v2`.
/// Historic spelling of [`TD1_IPV4_CS`].
pub use crate::features::TD1_IPV4_CS as TD1_IPv4_CS;
pub use crate::features::{
    TD1_GTSENV4, TD1_GTSENV6, TD1_IPV4_CS, TD1_IPV6_CS, TD1_MSS_SHIFT, TD1_TCP_CS, TD1_UDP_CS,
};

// RX descriptor csum status bits — see
// `crate::features::rx_csum_decode`. The previous in-tree "OK"
// bits (RX_IPOK / RX_TCPOK / RX_UDPOK, bits 5/6/7) were
// frame-length bits, not protocol bits, and are deleted.
pub use crate::features::{
    RX_FAIL_IP as RX_IPFAIL, RX_FAIL_TCP as RX_TCPFAIL, RX_FAIL_UDP as RX_UDPFAIL,
};
pub use crate::features::{RX_PID_TCP, RX_PID_UDP};

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
    /// Build a TX descriptor from pre-computed offload words (see
    /// `crate::features::v2_csum_words` / `v2_tso_words`).
    pub fn with_offload(
        addr_lo: u32,
        addr_hi: u32,
        len: u16,
        words: crate::features::OffloadWords,
    ) -> Self {
        TxDesc {
            flags_len: TXD_OWN | TXD_FS | TXD_LS | (len as u32 & TXD_LEN_MASK) | words.word0,
            vlan: words.word1,
            addr_lo,
            addr_hi,
        }
    }

    /// Decode the RX checksum result from a chip-writeback
    /// descriptor, using the Linux PID/fail rule.
    pub fn rx_csum_result(&self) -> RxCsumResult {
        let decoded = crate::features::rx_csum_decode(self.flags_len);
        if decoded.l4_ok {
            RxCsumResult::Ok
        } else if self.flags_len & (RX_IPFAIL | RX_TCPFAIL | RX_UDPFAIL) != 0 {
            RxCsumResult::Fail
        } else {
            RxCsumResult::None
        }
    }
}

// ── Firmware ─────────────────────────────────────────────────────────

/// Firmware for XID 0x6c9 (RTL8127A).
/// Linux `FIRMWARE_8127A_1` = `"rtl_nic/rtl8127a-1.fw"`.
pub const FIRMWARE_8127A_1: &str = "rtl_nic/rtl8127a-1.fw";

/// Return the firmware name for a given XID.
pub const fn firmware_name_for_xid(_xid: u32) -> &'static str {
    // Only one RTL8127 revision exists in Linux's chip table today, so
    // every XID that reaches this driver maps to the same blob.
    FIRMWARE_8127A_1
}

/// Static PHY configuration table for RTL8127A (`RTL_GIGA_MAC_VER_80`).
///
/// A one-for-one transcription of `rtl8127a_1_hw_phy_config` in Linux
/// `drivers/net/ethernet/realtek/r8169_phy_config.c` (v7.3-rc4, lines
/// 1158-1321), in source order, with the three helper calls it makes
/// expanded inline:
///
/// - `rtl8168g_enable_gphy_10m`      -> `phy_modify_paged(0x0a44, 0x11, 0, BIT(11))`
/// - `rtl8168g_disable_aldps`        -> `phy_modify_paged(0x0a43, 0x10, BIT(2), 0)`
/// - `rtl8125_common_config_eee_phy` -> three EEE clears
///
/// `r8169_apply_firmware(tp)` — the first statement of the Linux
/// function — is *not* an entry here: the firmware blob
/// ([`FIRMWARE_8127A_1`]) is loaded by the NARF firmware subsystem
/// before this table is walked, matching Linux's ordering.
pub const PHY_CONFIG_TABLE: &[PhyConfigEntry] = &[
    // r8169_apply_firmware(tp) — handled by the NARF firmware
    // subsystem before this table is applied.
    // rtl8168g_enable_gphy_10m()
    PhyConfigEntry {
        page: 0x0a44,
        reg: 0x0011,
        mask: 0x0000,
        val: 0x0800,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x8415,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x9300,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81a3,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x0f00,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81ae,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x0f00,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81b9,
        reg: 0x0014,
        mask: 0xff00,
        val: 0xb900,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x83b0,
        reg: 0xb87e,
        mask: 0x0e00,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x83c5,
        reg: 0xb87e,
        mask: 0x0e00,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x83da,
        reg: 0xb87e,
        mask: 0x0e00,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x83ef,
        reg: 0xb87e,
        mask: 0x0e00,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x0bf3,
        reg: 0x0014,
        mask: 0x01f0,
        val: 0x0160,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0bf3,
        reg: 0x0015,
        mask: 0x001f,
        val: 0x0014,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0bf2,
        reg: 0x0014,
        mask: 0x6000,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0bf2,
        reg: 0x0016,
        mask: 0xc000,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0bf2,
        reg: 0x0014,
        mask: 0x1fff,
        val: 0x0187,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0bf2,
        reg: 0x0015,
        mask: 0x003f,
        val: 0x0003,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x8173,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x8620,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8175,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x8671,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x817c,
        reg: 0x0014,
        mask: 0x0000,
        val: 0x2000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8187,
        reg: 0x0014,
        mask: 0x0000,
        val: 0x2000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8192,
        reg: 0x0014,
        mask: 0x0000,
        val: 0x2000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x819d,
        reg: 0x0014,
        mask: 0x0000,
        val: 0x2000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81a8,
        reg: 0x0014,
        mask: 0x2000,
        val: 0x0000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81b3,
        reg: 0x0014,
        mask: 0x2000,
        val: 0x0000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81be,
        reg: 0x0014,
        mask: 0x0000,
        val: 0x2000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x817d,
        reg: 0x0014,
        mask: 0xff00,
        val: 0xa600,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8188,
        reg: 0x0014,
        mask: 0xff00,
        val: 0xa600,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8193,
        reg: 0x0014,
        mask: 0xff00,
        val: 0xa600,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x819e,
        reg: 0x0014,
        mask: 0xff00,
        val: 0xa600,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81a9,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x1400,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81b4,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x1400,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81bf,
        reg: 0x0014,
        mask: 0xff00,
        val: 0xa600,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x0aea,
        reg: 0x0015,
        mask: 0x0028,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x84f0,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x201c,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x84f2,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x3117,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x0aec,
        reg: 0x0013,
        mask: 0xffff,
        val: 0x0000,
        kind: PhyConfigKind::WritePaged,
    },
    PhyConfigEntry {
        page: 0x0ae2,
        reg: 0x0010,
        mask: 0xffff,
        val: 0xffff,
        kind: PhyConfigKind::WritePaged,
    },
    PhyConfigEntry {
        page: 0x0aec,
        reg: 0x0017,
        mask: 0xffff,
        val: 0xffff,
        kind: PhyConfigKind::WritePaged,
    },
    PhyConfigEntry {
        page: 0x0aed,
        reg: 0x0011,
        mask: 0xffff,
        val: 0xffff,
        kind: PhyConfigKind::WritePaged,
    },
    PhyConfigEntry {
        page: 0x0aec,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x0000,
        kind: PhyConfigKind::WritePaged,
    },
    PhyConfigEntry {
        page: 0x0aed,
        reg: 0x0010,
        mask: 0x0001,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0adb,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x0150,
        kind: PhyConfigKind::WritePaged,
    },
    PhyConfigEntry {
        page: 0x8197,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x5000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8231,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x5000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x82cb,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x5000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x82cd,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x5700,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8233,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x5700,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8199,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x5700,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x815a,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0150,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x81f4,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0150,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x828e,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0150,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x81b1,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x824b,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x82e5,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x84f7,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x2800,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x0aec,
        reg: 0x0011,
        mask: 0x0000,
        val: 0x1000,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x81b3,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0xad00,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x824d,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0xad00,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x82e7,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0xad00,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x0ae4,
        reg: 0x0017,
        mask: 0x000f,
        val: 0x0001,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x82ce,
        reg: 0xb87e,
        mask: 0xf000,
        val: 0x4000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x84ac,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x84ae,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x84b0,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xf818,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x84b2,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x6000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8ffc,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x6008,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8ffe,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xf450,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8015,
        reg: 0xb87e,
        mask: 0x0000,
        val: 0x0200,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8016,
        reg: 0xb87e,
        mask: 0x0800,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8fe6,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x0800,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8fe4,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x2114,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8647,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xa7b1,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8649,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xbbca,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x864b,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0xdc00,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8154,
        reg: 0xb87e,
        mask: 0xc000,
        val: 0x4000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8158,
        reg: 0xb87e,
        mask: 0xc000,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x826c,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xffff,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x826e,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xffff,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8872,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x0e00,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8012,
        reg: 0x0014,
        mask: 0x0000,
        val: 0x0800,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8012,
        reg: 0x0014,
        mask: 0x0000,
        val: 0x4000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x0b57,
        reg: 0x0013,
        mask: 0x0000,
        val: 0x0001,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x834a,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x0700,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8217,
        reg: 0xb87e,
        mask: 0x3f00,
        val: 0x2a00,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x81b1,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x0b00,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8fed,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x4e00,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x88ac,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x2300,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x0bf0,
        reg: 0x0016,
        mask: 0x0000,
        val: 0x3800,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x88de,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x0000,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x80b4,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x5195,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8370,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x8671,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8372,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x86c8,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8401,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x86c8,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8403,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x86da,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8406,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8408,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x840a,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x840c,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x840e,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8410,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8412,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8414,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x8416,
        reg: 0x0014,
        mask: 0x1800,
        val: 0x1000,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x82bd,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x1f40,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x0bfb,
        reg: 0x0012,
        mask: 0x07ff,
        val: 0x0328,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0bfb,
        reg: 0x0013,
        mask: 0xffff,
        val: 0x3e14,
        kind: PhyConfigKind::WritePaged,
    },
    PhyConfigEntry {
        page: 0x81c4,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x003b,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81c6,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x0086,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81c8,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x00b7,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81ca,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x00db,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81cc,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x00fe,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81ce,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x00fe,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81d0,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x00fe,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81d2,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x00fe,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81d4,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x00c3,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81d6,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x0078,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81d8,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x0047,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x81da,
        reg: 0x0014,
        mask: 0xffff,
        val: 0x0023,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x88d7,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x01a0,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x88d9,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x01a0,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8ffa,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x002a,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8fee,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xffdf,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8ff0,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xffff,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8ff2,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0a4a,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8ff4,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xaa5a,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8ff6,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0x0a4a,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x8ff8,
        reg: 0xb87e,
        mask: 0xffff,
        val: 0xaa5a,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x88d5,
        reg: 0xb87e,
        mask: 0xff00,
        val: 0x0200,
        kind: PhyConfigKind::Rtl8125Param,
    },
    PhyConfigEntry {
        page: 0x84bb,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x0a00,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x84c0,
        reg: 0x0014,
        mask: 0xff00,
        val: 0x1600,
        kind: PhyConfigKind::R8168gParam,
    },
    PhyConfigEntry {
        page: 0x0a43,
        reg: 0x0010,
        mask: 0x0000,
        val: 0x0003,
        kind: PhyConfigKind::ModifyPaged,
    },
    // rtl8168g_disable_aldps()
    PhyConfigEntry {
        page: 0x0a43,
        reg: 0x0010,
        mask: 0x0004,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    // rtl8125_common_config_eee_phy()
    PhyConfigEntry {
        page: 0x0a6d,
        reg: 0x0014,
        mask: 0x0010,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0a42,
        reg: 0x0014,
        mask: 0x0080,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
    PhyConfigEntry {
        page: 0x0a4a,
        reg: 0x0011,
        mask: 0x0200,
        val: 0x0000,
        kind: PhyConfigKind::ModifyPaged,
    },
];

/// Number of entries in [`PHY_CONFIG_TABLE`].
pub const PHY_CONFIG_TABLE_LEN: usize = PHY_CONFIG_TABLE.len();

/// `true` iff every entry in [`PHY_CONFIG_TABLE`] uses the register
/// each [`PhyConfigKind`] pins for it. A cheap structural invariant
/// the smokes assert, so a hand-edit of the table cannot silently
/// encode a `*Param` entry against the wrong register.
pub const fn phy_config_table_is_well_formed() -> bool {
    let mut i = 0;
    while i < PHY_CONFIG_TABLE.len() {
        let e = PHY_CONFIG_TABLE[i];
        let ok = match e.kind {
            PhyConfigKind::R8168gParam => e.reg == 0x14,
            PhyConfigKind::Rtl8125Param => e.reg == 0xb87e,
            PhyConfigKind::WritePaged => e.mask == 0xFFFF,
            PhyConfigKind::ModifyPaged => true,
        };
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

// ── MAC helpers ──────────────────────────────────────────────────────

/// Maximum polling iterations for CR.RST self-clear.
pub const RESET_POLL_LIMIT: u32 = 1_000_000;

/// Decode a 6-byte MAC from IDR0..5 bytes.
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
use narf_net::{Frame, TxMeta, RX_RING_N, TX_RING_N};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    FrameTooLong,
    TxRingFull,
    TxTimeout,
    MsixSetup,
    /// The requested TX offload cannot be programmed for this
    /// frame (unparseable transport header, SCTP, MSS/offset
    /// overflow, or an invalid RSS queue count).
    UnsupportedOffload,
    Other(&'static str),
}

/// A live RTL8127 / RTL8127A 10 GbE controller.
pub struct Rtl8127Nic {
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
    /// Last WoL option set programmed via [`Rtl8127Nic::set_wol_opts`].
    wol_opts: IrqSafeSpinLock<crate::features::WolOpts>,
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
// either plain data or DMA/MMIO handles describing identity-mapped
// physical regions owned exclusively by this NIC instance.
unsafe impl Send for Rtl8127Nic {}
// SAFETY: every path that mutates shared state goes through the
// `IrqSafeSpinLock` fields above; the bare data fields are read-only
// after bring-up.
unsafe impl Sync for Rtl8127Nic {}

impl core::fmt::Debug for Rtl8127Nic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8127Nic")
            .field("mac", &self.mac)
            .field("mac_version", &self.mac_version)
            .field("link_up", &self.link_up)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

impl Rtl8127Nic {
    /// Bring up the controller: reset, read MAC, detect XID, install
    /// TX + RX rings, enable receive + transmit, observe link state.
    ///
    /// Mirrors `rtl_hw_start_8125_common`, with the VER_63…VER_80
    /// RxConfig (`RX_PAUSE_SLOT_ON` set).
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NicError> {
        // Same BAR layout as the rest of the family: MMIO in BAR2.
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
            tx_pool.push(
                alloc_coherent(TX_BUF_LEN, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }

        // 5. C+CR: enable RX checksum offload (the RX pump decodes
        //    it into `Frame::rx_meta`) and keep RX VLAN stripping
        //    OFF (no VLAN-tag field in `Frame::rx_meta`). Then
        //    program the EEE TX LPI idle timer (Linux's
        //    `rtl_set_eee_txidle_timer` VER_61..LAST arm covers
        //    VER_80), and make the single-queue RSS state explicit
        //    (Linux's single-ring write: `RSS_CTRL` = 0).
        // SAFETY: bring_up owns the BAR exclusively.
        unsafe {
            let mut regs = crate::features::MmioRegs(&mmio);
            crate::features::apply_cplus(&mut regs, false, true);
            crate::features::apply_eee_txidle(&mut regs, 1500);
            crate::features::apply_rss_single_queue(&mut regs);
        }

        // 6. Enable TX + RX.
        // SAFETY: same.
        unsafe { mmio.write8(REG_CR, CR_TE | CR_RE) };

        // 6a. TX descriptor ring base + TCR.
        let tx_phys = tx_ring.dma_addr().raw();
        // MTPS from the family jumbo tagged frame (16384 bytes →
        // 128 units). VER_80 needs no jumbo Config writes (Linux's
        // `rtl_jumbo_config` default arm).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_TNPDS, tx_phys as u32);
            mmio.write32(REG_TNPDS + 4, (tx_phys >> 32) as u32);
            mmio.write32(REG_TCR, TCR_MXDMA_UNLIMITED | TCR_IFG_STD);
            mmio.write8(REG_MTPS, crate::features::mtps_for_frame(TX_BUF_LEN as u32));
        }

        // 6b. Pre-fill RX descriptors.
        let rx_ring_phys = rx_ring.dma_addr().raw();
        for (i, buf) in rx_pool.iter().enumerate() {
            let buf_phys = buf.dma_addr().raw();
            let d = build_rx_desc(i, buf_phys, RX_BUF_LEN as u32);
            // SAFETY: identity-mapped DMA ring page; i < RING_LEN so the
            // 16-byte descriptor slot lies inside the RING_BYTES alloc.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rx_ring_phys + (i * 16) as u64)
                        .kernel_mut_ptr::<TxDesc>(),
                    d,
                );
            }
        }
        // RMS is the buffer bound (16383), not the MTU bound —
        // Linux's `rtl_set_rx_max_size` shape.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_RDSAR, rx_ring_phys as u32);
            mmio.write32(REG_RDSAR + 4, (rx_ring_phys >> 32) as u32);
            mmio.write16(REG_RMS, RX_BUF_LEN as u16);
        }

        // 6c. RxConfig — RTL8127A is VER_80, inside `rtl_init_rxcfg`'s
        //     VER_63…VER_80 arm:
        //     `RX_FETCH_DFLT_8125 | RX_DMA_BURST | RX_PAUSE_SLOT_ON`.
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

        // 7. Disable interrupt aggregation.
        //
        // `rtl_hw_start_8125_common` writes INT_CFG0 = 0, then zeroes
        // the per-vector coalescing block. The window is MAC-version
        // dependent: VER_63 / VER_70 clear 0xa00..0xa80, while VER_80
        // (this chip) clears the full 0xa00..0xb00 and *also* zeroes
        // the 16-bit INT_CFG1 at 0x7a.
        // SAFETY: identity-mapped MMIO; every offset below is inside
        // BAR2's register window.
        unsafe {
            mmio.write8(REG_INT_CFG0_8125, 0);
            let mut off = COALESCE_BLOCK_START;
            while off < COALESCE_BLOCK_END_8127 {
                mmio.write32(off, 0);
                off += 4;
            }
            mmio.write16(REG_INT_CFG1_8125, 0);
        }

        // 8. Mask all interrupts; clear any latched status.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_IMR_8125, 0);
            mmio.write32(REG_ISR_8125, 0xFFFF_FFFF);
        }

        // 9. PHYStatus snapshot.
        // SAFETY: same.
        let phystat = unsafe { mmio.read8(REG_PHYSTAT) };
        let link_up = phystat & PHYSTAT_LINKSTS != 0;

        // 10. Re-lock config registers.
        // SAFETY: same.
        unsafe { mmio.write8(REG_9346CR, EEM_NORMAL) };

        // 11. PHY configuration is deliberately NOT done here. See
        //     `configure_phy_late`: the firmware patch has to run
        //     before the config table, and the firmware registry is
        //     not populated until `Stage::Late` — probe is
        //     `Stage::Device`. Linux has the same split, running the
        //     whole sequence from `rtl8169_up()` rather than from
        //     probe.

        Ok(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_head: IrqSafeSpinLock::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            mac_version,
            wol_opts: IrqSafeSpinLock::new(crate::features::WolOpts::NONE),
            link_up,
            irq_vector: None,
            msix: None,
            rx_ipc_ring: IrqSafeSpinLock::new(None),
            tx_ipc_ring: IrqSafeSpinLock::new(None),
        })
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
    pub fn transmit(&self, frame: &[u8], meta: &TxMeta) -> Result<(), NicError> {
        if frame.is_empty() || frame.len() > TX_BUF_LEN {
            return Err(NicError::FrameTooLong);
        }
        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let phys = self.tx_pool[slot].dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer, 4 KiB per slot and
        // `frame.len() <= 1518`.
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

        // Descriptor format from the offload request. VER_80 is
        // csum-v2, so only the v2 builders are used. Offload words
        // are computed driver-locally; no shared TX-path code is
        // touched. An offload the chip cannot take for this frame
        // is `UnsupportedOffload`, never a descriptor with a
        // guessed offset. Plain frames still get VLAN insertion.
        let mut d = if let Some(mss) = meta.tso_mss {
            if mss == 0 || mss > crate::features::MSS_MAX {
                return Err(NicError::UnsupportedOffload);
            }
            let info =
                crate::features::parse_transport(frame).ok_or(NicError::UnsupportedOffload)?;
            let words = crate::features::v2_tso_words(info.ip, mss, info.offset, meta.vlan_tag)
                .ok_or(NicError::UnsupportedOffload)?;
            TxDesc::with_offload(phys as u32, (phys >> 32) as u32, frame.len() as u16, words)
        } else if let Some(kind) = meta.csum_l4 {
            let info =
                crate::features::parse_transport(frame).ok_or(NicError::UnsupportedOffload)?;
            let words = crate::features::v2_csum_words(kind, info.ip, info.offset, meta.vlan_tag)
                .ok_or(NicError::UnsupportedOffload)?;
            TxDesc::with_offload(phys as u32, (phys >> 32) as u32, frame.len() as u16, words)
        } else {
            TxDesc {
                flags_len: TXD_OWN | TXD_FS | TXD_LS | (frame.len() as u32 & TXD_LEN_MASK),
                vlan: crate::features::tx_vlan_word(meta.vlan_tag),
                addr_lo: phys as u32,
                addr_hi: (phys >> 32) as u32,
            }
        };
        if slot == RING_LEN - 1 {
            d.flags_len |= TXD_EOR;
        }
        // SAFETY: identity-mapped DMA ring; the three writes below fill
        // the vlan + address words before OWN is published.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                d.vlan,
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
                d.flags_len,
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
        self.receive_with_meta().map(|(buf, _)| buf)
    }

    /// Like [`Rtl8127Nic::receive`], plus the chip's RX checksum
    /// verification result decoded from the returned descriptor.
    pub fn receive_with_meta(&self) -> Option<(alloc::vec::Vec<u8>, RxCsumResult)> {
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

        // Decode the RX checksum result now, before rearming
        // overwrites the descriptor.
        let csum = TxDesc {
            flags_len,
            vlan: 0,
            addr_lo: 0,
            addr_hi: 0,
        }
        .rx_csum_result();

        let len = (flags_len & RXD_LEN_MASK) as usize;
        let buf_phys = self.rx_pool[slot].dma_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(len.min(RX_BUF_LEN));
        if flags_len & RXD_LS != 0 {
            let copy_len = len.min(RX_BUF_LEN);
            for i in 0..copy_len {
                // SAFETY: this slot's RX DMA buffer is RX_BUF_LEN bytes
                // and `i < copy_len <= RX_BUF_LEN`.
                out.push(unsafe {
                    core::ptr::read_volatile(self.rx_pool[slot].cpu_ptr_at::<u8>(i as u64))
                });
            }
        }

        // Rearm the descriptor.
        let d = build_rx_desc(slot, buf_phys, RX_BUF_LEN as u32);
        // SAFETY: identity-mapped DMA ring; slot < RING_LEN.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<TxDesc>(),
                d,
            )
        };
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        Some((out, csum))
    }

    /// Largest frame this driver will transmit: the family jumbo
    /// tagged frame, which is also the TX slot buffer size.
    pub fn max_frame(&self) -> u32 {
        TX_BUF_LEN as u32
    }

    /// EEE LPI capabilities for VER_80 (Linux's
    /// `rtl8169_get_lpi_caps` shape: 100/1000/2500/5000/10000FD —
    /// the only version that advertises 10G LPI).
    pub fn eee_caps(&self) -> crate::features::EeeCaps {
        crate::features::eee_lpi_caps(80)
    }

    /// Program the RSS steering registers for `queues` RX queues
    /// (key / indirection / control / queue-count / descriptor
    /// type, via `crate::features::apply_rss`).
    ///
    /// DORMANT: not called from bring-up. Enabling steering in
    /// production additionally needs the multi-ring datapath
    /// (per-queue descriptor bases, RSS descriptor format,
    /// per-queue pumps, 30 MSI-X vectors) — see the module header.
    /// Calling this on a live single-ring controller would steer
    /// frames to queues nobody drains.
    pub fn configure_rss(&self, queues: usize) -> Result<(), NicError> {
        let config = narf_net::rss::RssConfig::standard(queues, crate::features::RSS_INDIR_ENTRIES);
        // SAFETY: bring_up owns the BAR; `configure_rss` is called
        // only on the live controller, whose MMIO is exclusively
        // owned by this instance.
        unsafe {
            let mut regs = crate::features::MmioRegs(&self.mmio);
            if !crate::features::apply_rss(&mut regs, queues, &config.key, &config.indirection) {
                return Err(NicError::UnsupportedOffload);
            }
        }
        Ok(())
    }

    /// Program Wake-on-LAN options (Linux's `__rtl8169_set_wol`
    /// 8125-family shape, as in the 8125 driver: Config registers
    /// via `apply_wol` with the MAC-OCP magic, then the 0xe0c6
    /// LinkUp step and the 0xc0b6 magic step through the shared
    /// OCP accessor). Nothing is left pending.
    pub fn set_wol_opts(&self, opts: crate::features::WolOpts) -> Result<(), NicError> {
        if !opts.is_valid() {
            return Err(NicError::UnsupportedOffload);
        }
        // SAFETY: bring_up owns the BAR; `set_wol_opts` is called
        // only on the live controller, whose MMIO is exclusively
        // owned by this instance.
        unsafe {
            self.mmio.write8(REG_9346CR, EEM_CONFIG_WRITE);
            let mut regs = crate::features::MmioRegs(&self.mmio);
            let pending = crate::features::apply_wol(
                &mut regs,
                opts,
                crate::features::WolMagic::MacOcpC0b6,
                crate::features::WolPmeReg::Config2,
            );
            self.mmio.write8(REG_9346CR, EEM_NORMAL);
            *self.wol_opts.lock() = opts;
            let access = crate::phy_access::PhyAccess::new(&self.mmio);
            let linkup_val: u16 = if opts.contains(crate::features::WolOpts::PHY) {
                0x13
            } else {
                0
            };
            let cur_e0c6 = access
                .mac_ocp_read(0xe0c6)
                .map_err(|_| NicError::Other("OCP read failed"))?;
            access
                .mac_ocp_write(0xe0c6, (cur_e0c6 & !0x3f) | linkup_val)
                .map_err(|_| NicError::Other("OCP write failed"))?;
            if let crate::features::WolPendingMagic::MacOcpC0b6(magic_on) = pending {
                let cur_c0b6 = access
                    .mac_ocp_read(0xc0b6)
                    .map_err(|_| NicError::Other("OCP read failed"))?;
                let new_c0b6 = if magic_on {
                    cur_c0b6 | 0x0001
                } else {
                    cur_c0b6 & !0x0001
                };
                access
                    .mac_ocp_write(0xc0b6, new_c0b6)
                    .map_err(|_| NicError::Other("OCP write failed"))?;
            }
            Ok(())
        }
    }

    /// Last WoL option set programmed via [`Rtl8127Nic::set_wol_opts`].
    pub fn wol_opts(&self) -> crate::features::WolOpts {
        *self.wol_opts.lock()
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

/// Load the PHY firmware patch if it is present, then apply
/// [`PHY_CONFIG_TABLE`].
///
/// Ordering matches Linux's `rtl8127a_1_hw_phy_config`, whose first
/// statement is `r8169_apply_firmware`: the blob is a PHY-MCU patch
/// and several table entries target registers it installs. Without
/// it the table still programs everything it names, which is why a
/// missing blob is a log line rather than an error.
fn configure_phy(mmio: &MmioRegion) {
    use core::fmt::Write as _;

    let mut access = phy::PhyAccess::new(mmio);

    match load_phy_firmware() {
        Some(code) => match access.run_firmware(&code) {
            Ok(()) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8127: applied {} ({} opcodes)",
                    FIRMWARE_8127A_1,
                    code.len(),
                );
            }
            Err(e) => {
                // The blob is a sequence of register writes; a
                // failure partway leaves the PHY in an unknown state,
                // so say so rather than silently continuing to the
                // table on top of it.
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8127: firmware aborted at an opcode: {:?}; PHY may be partly patched",
                    e,
                );
            }
        },
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  rtl8127: {} not present; applying PHY config without it",
                FIRMWARE_8127A_1,
            );
        }
    }

    if let Err(e) = access.apply_config_table(PHY_CONFIG_TABLE) {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8127: PHY config table aborted: {:?}",
            e
        );
    }
}

/// Run the PHY bring-up sequence once the firmware registry exists.
///
/// Split out of `bring_up` because of an ordering constraint that
/// cannot be satisfied at probe time. `rtl8127a_1_hw_phy_config`
/// calls `r8169_apply_firmware` as its *first* statement and then
/// writes the config table on top of the patched PHY, so the two
/// cannot be reordered. But the firmware registry is only populated
/// by the `Stage::Late` initramfs and rootfs scans, and the PCI probe
/// pass is `Stage::Device` — so at probe there is never a blob to
/// apply, and the table would go down on an unpatched PHY.
///
/// Linux does not do this at probe either: the sequence runs from
/// `rtl8169_up()`, when the interface is brought up. NARF has no
/// interface-up hook yet, so this runs from a `Stage::Late` initcall
/// registered after the firmware scans.
pub fn configure_phy_late() {
    // Take an `Arc` clone and drop the registry lock before touching
    // the PHY: a firmware delay opcode can spin for up to
    // `MAX_FIRMWARE_DELAY_MS`, and holding an IrqSafeSpinLock across
    // that would stall every other controller user.
    let controller = CONTROLLER.lock().clone();
    let Some(controller) = controller else {
        return;
    };
    configure_phy(&controller.mmio);
}

/// Fetch and parse `rtl_nic/rtl8127a-1.fw`, if the firmware registry
/// has it.
fn load_phy_firmware() -> Option<alloc::vec::Vec<u32>> {
    use core::fmt::Write as _;

    let auth = narf_firmware::trusted_loader_authority()?.derive().ok()?;
    let cap = narf_firmware::open(FIRMWARE_8127A_1, &auth).ok()?;
    let view = narf_firmware::view_of(&cap).ok()?;

    let code = match phy::parse_firmware(view.bytes) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  rtl8127: {} failed its format check: {:?}",
                FIRMWARE_8127A_1,
                e,
            );
            return None;
        }
    };
    // Bounds-check every jump before touching a register, so a
    // corrupt blob cannot run off the end mid-program.
    if let Err(e) = phy::validate_firmware(&code) {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8127: {} rejected: {:?}",
            FIRMWARE_8127A_1,
            e,
        );
        return None;
    }
    Some(code)
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<Rtl8127Nic>>> = IrqSafeSpinLock::new(None);

/// The interface name `iface::register` gave this NIC (`eth%d`, Linux
/// `dev_alloc_name`). Set once at probe; the device lives as long as
/// the kernel, so the name is leaked into a `&'static str`.
static RTL8127_IFNAME: crate::publish::IfName = crate::publish::IfName::new();

/// This NIC's interface name; empty until it has registered.
pub fn rtl8127_ifname() -> &'static str {
    RTL8127_IFNAME.get()
}

/// SendFn registered with `narf_net::iface` at probe time. Routes the
/// kernel-side TCP stack's outbound frames through
/// `Rtl8127Nic::transmit`. The Arc is cloned out rather than holding
/// the IRQ-masking CONTROLLER lock across `transmit` (same reasoning
/// as e1000's send path).
fn rtl8127_send_frame(frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = CONTROLLER.lock().clone().ok_or(())?;
    ctrl.transmit(frame, &meta).map_err(|_| ())
}

/// Decode a PHYStatus byte into a publication sample via the family's
/// existing `PhyStatus::parse`. The ≥1G bit covers 1G/2.5G/5G/10G
/// alike on this part, so 1000 is published as the in-band lower
/// bound; exact negotiated-rate decode is PHY work (issue #790).
fn rtl8127_link_sample(status: u8) -> crate::publish::LinkSample {
    let s = PhyStatus::parse(status);
    if !s.link_up {
        return crate::publish::LinkSample::DOWN;
    }
    let speed_mbps = if s.speed_1000m_or_above {
        Some(1000)
    } else if s.speed_100m {
        Some(100)
    } else if s.speed_10m {
        Some(10)
    } else {
        None
    };
    crate::publish::LinkSample {
        carrier: true,
        speed_mbps,
        duplex: Some(if s.full_duplex {
            narf_net::iface::LinkDuplex::Full
        } else {
            narf_net::iface::LinkDuplex::Half
        }),
    }
}

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
    let mut dev = match unsafe { Rtl8127Nic::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    // The rings are installed before the device is published, so the
    // exclusive `&mut` here needs no Arc-aliasing argument.
    *dev.rx_ipc_ring.lock() = Some(rx_cons);
    *dev.tx_ipc_ring.lock() = Some(tx_prod);

    // Best-effort MSI-X. A failure leaves the NIC on the polled path
    // the pumps already drive, so it is not fatal to the probe.
    // SAFETY: caller-authority over the device's cfg space.
    if unsafe { dev.enable_msix(&cap, &device) }.is_err() {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8127: MSI-X setup failed; continuing on the polled path"
        );
    }

    let dev = Arc::new(dev);
    *CONTROLLER.lock() = Some(dev.clone());

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8127: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ver={:?} link={}",
            dev.mac[0],
            dev.mac[1],
            dev.mac[2],
            dev.mac[3],
            dev.mac[4],
            dev.mac[5],
            dev.mac_version,
            PhyStatus::parse(dev.phy_status()).speed_label(),
        );
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("rtl8127"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Publish to the kernel-side stack (issue #784): a dynamic `eth%d`
    // name + carrier metadata via the shared helper. The frame-ring
    // registration below stays.
    let mac = with_controller(|c| c.mac).unwrap_or([0; 6]);
    let status = with_controller(|c| c.phy_status()).unwrap_or(0);
    let name = crate::publish::publish_netdev(mac, rtl8127_send_frame, rtl8127_link_sample(status));
    RTL8127_IFNAME.set(name);

    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Rtl8127NicIface);
    }

    spawn_pumps(dev, rx_prod, tx_cons);

    Ok(())
}

fn spawn_pumps(
    device: Arc<Rtl8127Nic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        rtl8127_rx_pump(d1, rx_prod).await;
    });
    let d2 = device;
    narf_scheduler::spawn(async move {
        rtl8127_tx_pump(d2, tx_cons).await;
    });
}

async fn rtl8127_rx_pump(device: Arc<Rtl8127Nic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    // Carrier refresh (issue #791): the production datapath is polled
    // (probe never enables MSI-X, so the LinkChg bit in the ISR has no
    // consumer), which makes this pump the family's link observer.
    // `phy_status()` is an `&self` MMIO read — unlike
    // `refresh_link_state(&mut self)`, it is safe to call while pumps
    // hold Arc clones. A transition republishes the iface metadata;
    // the cached `Interface::link_up` snapshot is left as-is.
    let mut last_sample = rtl8127_link_sample(device.phy_status());
    loop {
        let sample = rtl8127_link_sample(device.phy_status());
        if sample != last_sample {
            last_sample = sample;
            crate::publish::publish_link(rtl8127_ifname(), sample);
        }
        if let Some((pkt, csum)) = device.receive_with_meta() {
            let dma_buf =
                alloc_coherent(pkt.len(), DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, pkt.len() as u32);
            frame.payload_mut().copy_from_slice(&pkt);
            // RX checksum verification from the descriptor: only
            // `Ok` marks the checksums verified; `Fail` and `None`
            // both leave the flags clear so the stack re-checks.
            let mut rx_meta = narf_net::RxMeta::default();
            if csum == RxCsumResult::Ok {
                rx_meta.csum_l3 = true;
                rx_meta.csum_l4 = true;
            }
            frame.set_rx_meta(rx_meta);
            // RX fan-out (issue #784), e1000's `dispatch_rx_frame`
            // shape via the shared helper: an attached ring consumer
            // gets a pristine pre-dispatch copy; the original goes to
            // the kernel stack in place. The mirror is non-blocking —
            // a full/closed ring drops its copy, never the stack's
            // packet.
            let name = rtl8127_ifname();
            crate::publish::dispatch_rx(
                name,
                &mut frame,
                crate::publish::rx_mirror_attached(name),
                |mirror| {
                    let _ = rx_prod.try_send(mirror);
                },
            );
        }
        narf_scheduler::yield_now().await;
    }
}

async fn rtl8127_tx_pump(device: Arc<Rtl8127Nic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload(), &TxMeta::plain());
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
pub fn with_controller<R>(f: impl FnOnce(&Rtl8127Nic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

/// Mutable accessor for tests.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut Rtl8127Nic) -> R) -> Option<R> {
    CONTROLLER
        .lock()
        .as_mut()
        .map(|a| f(Arc::get_mut(a).expect("Rtl8127Nic static has multiple owners")))
}

/// `narf_net::Interface` implementation.
#[derive(Debug)]
pub struct Rtl8127NicIface;

impl narf_net::Interface for Rtl8127NicIface {
    fn name(&self) -> &str {
        // The dynamic `eth%d` name once published (issue #784); the
        // family name before probe gets that far.
        let n = rtl8127_ifname();
        if n.is_empty() {
            "rtl8127"
        } else {
            n
        }
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
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        // The TSO byte cap is the TX slot buffer: a TSO packet is
        // one frame copied into one slot. RSS is deliberately not
        // advertised: the steering registers are dormant until
        // the multi-ring datapath lands.
        narf_net::OffloadCapabilities {
            tx_checksum: true,
            rx_checksum: true,
            max_tso_bytes: TX_BUF_LEN as u32,
            vlan_insert: true,
        }
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.rx_ipc_ring.lock().take();
                if r.is_some() {
                    // Ring consumer attached: enable the RX mirror
                    // (e1000's `rx_mirror_enabled` moment).
                    crate::publish::note_rx_mirror_attached(rtl8127_ifname());
                }
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

impl crate::HwNic for Rtl8127NicIface {
    fn name(&self) -> &'static str {
        let n = rtl8127_ifname();
        if n.is_empty() {
            "rtl8127"
        } else {
            n
        }
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
        // RSS is deliberately NOT advertised: the steering
        // registers are dormant until the multi-ring datapath
        // lands (see the module header).
        crate::NicCaps::TX_CSUM
            | crate::NicCaps::RX_CSUM
            | crate::NicCaps::TSO
            | crate::NicCaps::VLAN_TAGGING
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
