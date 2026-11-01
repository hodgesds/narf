//! Realtek RTL8125 family 2.5 Gigabit Ethernet driver — Stage-2 cut,
//! extended with the Linux compared feature set: probe + reset +
//! TX/RX rings + one MSI-X vector, plus TX checksum (TCP/UDP,
//! v4/v6) and TSO
//! (v2 layout — every 8125-family chip is csum-v2), VLAN tag
//! insertion on TX, RX checksum decode, jumbo-sized rings / RMS /
//! MTPS, WoL register programming (including the 8125-family
//! MAC-OCP steps), the EEE TX LPI idle timer, and per-variant
//! PHY-config tables applied from a `Stage::Late` hook (firmware
//! first, except 8125A where Linux runs firmware mid-table —
//! see [`phy_table_for`]). Deliberate asymmetries, shared with
//! the r8169 driver: RX VLAN stripping stays OFF (no VLAN-tag
//! field in `Frame::rx_meta`), the interface MTU stays 1500
//! with offloads advertised (Linux's `rtl8169_fix_features`
//! disables CSUM + TSO when MTU > 1500 on MAC > VER_06), and
//! RSS stays off (Linux enables RSS only on VER_80). Still
//! missing: EEE PHY advertisement (Clause 45 MMD through the
//! OCP window) and GMII auto-negotiation tuning.
//!
//! ## Reference
//!
//! - Realtek **"RTL8125 Series 2.5 Gigabit Ethernet Controller —
//!   Registers Datasheet"** Rev. 1.0 (public). Defines the legacy
//!   RTL8169/8168 register floor (IDR0..5, CR, TCR, RCR, RDSAR,
//!   TNPDS at the same offsets) plus the 2.5 Gbps additions:
//!   IntrMask_8125 (32-bit) @ 0x38, IntrStatus_8125 (32-bit) @ 0x3c,
//!   TxPoll_8125 @ 0x90, INT_CFG0_8125 @ 0x34.
//! - Linux **`drivers/net/ethernet/realtek/r8169_main.c`** (GPL-2.0;
//!   NARF is GPL-2.0-or-later since 2026-05-20 so adaptation is
//!   permitted): `enum rtl8125_registers`, `rtl_hw_start_8125_common`,
//!   `rtl_init_rxcfg` for `RX_FETCH_DFLT_8125`, descriptor `opts1`
//!   layout (identical to RTL8169 — `struct TxDesc`/`struct RxDesc`
//!   remain 16 bytes with `opts1`/`opts2`/`__le64 addr`).
//!
//! Like the RTL8169 driver in [`crate::r8169`], the on-wire descriptor
//! is 16 bytes — `RxDescV3`/`TxDescV3` exist only in the Linux source
//! for a different chip (RTL8125-side "new descriptor format" is
//! *disabled* by default and stays disabled here per the comment in
//! `rtl_hw_start_8125_common` line 3877 of r8169_main.c).
//!
//! ## Differences from RTL8169 / r8169 driver
//!
//! 1. `IntrMask` / `IntrStatus` widen to 32 bits and move from 0x3C
//!    / 0x3E to 0x38 / 0x3C respectively. The legacy 16-bit aliases
//!    at 0x3C/0x3E continue to function on the 8125 silicon but
//!    Realtek's own driver targets the 32-bit ports — we do too so
//!    we get the new high-half interrupt sources (8125-specific
//!    `RxRWT`/`RxRES`/`RxRUNT` in the RxStatusDesc bits).
//! 2. `TxPoll` doorbell moves from CR-adjacent 0x38 to 0x90 to free
//!    up the 32-bit IntrMask slot.
//! 3. `RxConfig` (0x44) uses `RX_FETCH_DFLT_8125 = 8 << 27` for the
//!    DMA prefetch threshold instead of the 8169's `RX128_INT_EN`
//!    block.
//! 4. `INT_CFG0_8125` (0x34) controls the new interrupt-aggregation
//!    enable bit + CLKREQ gate; we leave both off, matching the 8169
//!    no-coalescing default.
//! 5. The MAC chip XID lives at `(TxConfig >> 20) & 0xfcf` per
//!    `r8169_main.c:5647`; we expose `decode_xid` so a future stage
//!    can branch on RTL8125A / RTL8125B / RTL8125D for chip-specific
//!    PHY-config tables.

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
        RTL_DEV_8125 => "rtl8125",
        RTL_DEV_8125B => "rtl8125b",
        _ => "rtl8125",
    }
}

// ── Register offsets (BAR0, MMIO) ───────────────────────────────────
// Datasheet §2 "MAC Configuration Registers". Offsets shared with
// RTL8168 are noted; RTL8125-specific extensions live ≥ 0x100.

/// IDR0..5 — MAC address (byte-readable). §2.1.
pub(crate) const REG_IDR0: u64 = 0x00;
/// MAR0..7 — multicast hash filter (8 bytes). §2.2.
pub(crate) const REG_MAR0: u64 = 0x08;
/// TNPDS — TX normal-priority descriptor base (64-bit). §2.3.
pub(crate) const REG_TNPDS: u64 = 0x20;
/// CR — Command (RST/RE/TE). §2.4.
pub(crate) const REG_CR: u64 = 0x37;
/// TPPoll — TX priority polling doorbell. §2.5.
pub(crate) const REG_TPPOLL: u64 = 0x38;
/// IMR — interrupt mask (16-bit legacy alias). §2.6.
///
/// Kept for documentation: the RTL8125's interrupt block is at the
/// 32-bit [`REG_IMR_8125`] (0x38) / [`REG_ISR_8125`] (0x3C) ports.
/// The legacy 16-bit alias at 0x3C/0x3E overlaps the low half of
/// the 32-bit ISR — writing it from a Stage-2 driver would clobber
/// the high-half status bits. Stage 2 uses the 32-bit ports
/// exclusively.
pub(crate) const REG_IMR: u64 = 0x3C;
/// ISR — interrupt status (write-1-clear, 16-bit legacy alias). §2.6.
/// See [`REG_ISR_8125`] for the 32-bit 8125 register (same offset,
/// different width).
pub(crate) const REG_ISR: u64 = 0x3E;
/// TCR — TX configuration. §2.7.
pub(crate) const REG_TCR: u64 = 0x40;
/// RCR — RX configuration. §2.8.
pub(crate) const REG_RCR: u64 = 0x44;
/// 9346CR — config-register write-lock latch. §2.9.
pub(crate) const REG_9346CR: u64 = 0x50;
/// PHYStatus — PHY status (LinkSts at bit 1). §2.10.
pub(crate) const REG_PHYSTAT: u64 = 0x6C;
/// RMS — RX max packet size (14-bit). §2.11.
pub(crate) const REG_RMS: u64 = 0xDA;
/// C+CR — VLAN/csum offload toggles. §2.12.
pub(crate) const REG_CPLUSCR: u64 = 0xE0;
/// RDSAR — RX descriptor base (64-bit, 256-byte aligned). §2.13.
pub(crate) const REG_RDSAR: u64 = 0xE4;
/// MTPS — Max TX packet size (units of 128 bytes). §2.14.
pub(crate) const REG_MTPS: u64 = 0xEC;

// ── RTL8125-specific register extensions ────────────────────────────
// Sourced from `enum rtl8125_registers` in Linux's r8169_main.c
// (GPL-2.0-or-later, lines 427–443). The legacy 8169 register floor
// continues to alias the old offsets; we target the new offsets
// because Realtek's reference driver does — that keeps us in step
// with their per-revision quirks.

/// INT_CFG0_8125 — interrupt-aggregation enable + CLKREQ gate. We
/// hold this at 0x00 to disable both: aggregation hides individual
/// TX completions behind a timer, and CLKREQEN is owned by the
/// ASPM path which Stage 2 doesn't enter.
pub(crate) const REG_INT_CFG0_8125: u64 = 0x34;
/// `INT_CFG0_ENABLE_8125` — aggregation enable. Off in Stage 2.
pub(crate) const INT_CFG0_ENABLE_8125: u8 = 1 << 0;
/// `INT_CFG0_CLKREQEN` — let the chip raise CLKREQ during IRQ
/// service. Off in Stage 2 (ASPM stays disabled).
pub(crate) const INT_CFG0_CLKREQEN: u8 = 1 << 3;

/// `IntrMask_8125` — 32-bit interrupt mask. Replaces the 16-bit IMR
/// at 0x3C for RTL8125 silicon.
pub(crate) const REG_IMR_8125: u64 = 0x38;
/// `IntrStatus_8125` — 32-bit interrupt status (write-1-clear).
pub(crate) const REG_ISR_8125: u64 = 0x3C;

/// INT_CFG1_8125 — secondary interrupt configuration. Reserved for
/// future MSI-X queue mapping; Stage 2 leaves the reset value.
pub(crate) const REG_INT_CFG1_8125: u64 = 0x7A;

/// TxPoll_8125 — new TX doorbell. Moves from 0x38 (now IMR_8125)
/// to 0x90 on the 8125. `TPPOLL_NPQ` bit (1 << 6) is unchanged.
pub(crate) const REG_TPPOLL_8125: u64 = 0x90;

/// RSS_CTRL_8125 — receive-side scaling control. Held at 0 in
/// Stage 2 (single-queue).
pub(crate) const REG_RSS_CTRL_8125: u64 = 0x4500;

/// Q_NUM_CTRL_8125 — queue count selector. Held at 0 = single-queue.
pub(crate) const REG_Q_NUM_CTRL_8125: u64 = 0x4800;

// CR bits (§2.4).
pub(crate) const CR_TE: u8 = 1 << 2;
pub(crate) const CR_RE: u8 = 1 << 3;
pub(crate) const CR_RST: u8 = 1 << 4;

// TPPoll bits (§2.5). Same NPQ bit on both the legacy 0x38 doorbell
// and the 8125-relocated 0x90 doorbell.
pub(crate) const TPPOLL_NPQ: u8 = 1 << 6;

// 9346CR (config-write lock). Bits 7:6 = EEM. 00=normal, 11=write-en.
pub(crate) const EEM_NORMAL: u8 = 0x00;
pub(crate) const EEM_CONFIG_WRITE: u8 = 0xC0;

// RCR bits (§2.8).
pub(crate) const RCR_AAP: u32 = 1 << 0;
pub(crate) const RCR_APM: u32 = 1 << 1;
pub(crate) const RCR_AM: u32 = 1 << 2;
pub(crate) const RCR_AB: u32 = 1 << 3;
pub(crate) const RCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;
pub(crate) const RCR_RXFTH_NONE: u32 = 0b111 << 13;

// TCR bits (§2.7).
pub(crate) const TCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;
pub(crate) const TCR_IFG_STD: u32 = 0b11 << 24;

// ISR / IMR (16-bit alias) bits (§2.6).
pub(crate) const INT_ROK: u16 = 1 << 0;
pub(crate) const INT_TOK: u16 = 1 << 2;
pub(crate) const INT_RDU: u16 = 1 << 4;
pub(crate) const INT_LINKCHG: u16 = 1 << 5;
pub(crate) const INT_TDU: u16 = 1 << 7;

// RTL8125 32-bit IMR/ISR bit layout (REG_IMR_8125 / REG_ISR_8125).
// The low 8 bits match the 16-bit alias; higher bits are 8125-only
// (per `enum rtl_register_content` in Linux r8169_main.c lines 453–
// 466 — same bit numbers, just promoted to 32-bit). The widened port
// also exposes 8125-specific descriptor-status bits (RxRWT, RxRES,
// RxRUNT, RxCRC at bits 22..19) that the legacy 16-bit ISR window
// can't see.
pub(crate) const INT32_ROK: u32 = 1 << 0;
pub(crate) const INT32_RXERR: u32 = 1 << 1;
pub(crate) const INT32_TOK: u32 = 1 << 2;
pub(crate) const INT32_TXERR: u32 = 1 << 3;
pub(crate) const INT32_RDU: u32 = 1 << 4;
pub(crate) const INT32_LINKCHG: u32 = 1 << 5;
pub(crate) const INT32_RX_FIFO_OVER: u32 = 1 << 6;
pub(crate) const INT32_TDU: u32 = 1 << 7;
pub(crate) const INT32_SWINT: u32 = 1 << 8;
pub(crate) const INT32_PCS_TIMEOUT: u32 = 1 << 14;
pub(crate) const INT32_SYS_ERR: u32 = 1 << 15;

/// `RX_FETCH_DFLT_8125 = 8 << 27` — Linux's default RX-DMA prefetch
/// threshold for the 8125 RxConfig register. See
/// `rtl_init_rxcfg(RTL_GIGA_MAC_VER_61)` in r8169_main.c:2604–2605.
pub(crate) const RX_FETCH_DFLT_8125: u32 = 8 << 27;

// PHYStatus bits (§2.10).
// Bit layout per Linux `enum rtl_register_content` lines 557–565:
//   bit 7  TBI_Enable
//   bit 6  TxFlowCtrl
//   bit 5  RxFlowCtrl
//   bit 4  _1000bpsF
//   bit 3  _100bps
//   bit 2  _10bps
//   bit 1  LinkStatus
//   bit 0  FullDup
// RTL8125 negotiates 2.5 Gbps via PHY registers; the PHYStatus
// register only surfaces up to gigabit. A 2.5G link reads as
// "_1000bpsF | LinkStatus" here — the driver consults the PHY
// (via PHYAR) to learn the real speed once the link is up.
pub const PHYSTAT_LINKSTS: u8 = 1 << 1;
pub const PHYSTAT_FULLDUP: u8 = 1 << 0;
pub(crate) const PHYSTAT_10BPS: u8 = 1 << 2;
pub const PHYSTAT_100BPS: u8 = 1 << 3;
pub const PHYSTAT_1000BPSF: u8 = 1 << 4;
pub(crate) const PHYSTAT_RXFLOWCTRL: u8 = 1 << 5;
pub(crate) const PHYSTAT_TXFLOWCTRL: u8 = 1 << 6;

/// Decoded PHYStatus register. The RTL8125 PHYStatus mirrors the
/// 8169 layout — 2.5 Gbps negotiations surface as 1000bpsF here,
/// with the real speed available via PHY-register access. Stage 2
/// captures the byte-level info; speed-decoding lives in a future
/// PHY-config commit.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PhyStatus {
    pub link_up: bool,
    pub full_duplex: bool,
    pub speed_1000m: bool,
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
            speed_1000m: byte & PHYSTAT_1000BPSF != 0,
            rx_flow_control: byte & PHYSTAT_RXFLOWCTRL != 0,
            tx_flow_control: byte & PHYSTAT_TXFLOWCTRL != 0,
        }
    }

    /// Best-guess link speed string. "2.5G" requires a separate
    /// PHY-register read (a 2.5 Gbps link surfaces as "1000Mbps" in
    /// PHYStatus); the driver caller is expected to upgrade the
    /// label after talking to the PHY directly.
    pub const fn speed_label(&self) -> &'static str {
        if self.speed_1000m {
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
    if bytes.len() < 6 {
        return None;
    }
    Some([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
}

/// `true` iff the MAC reads as either all-zero (no EEPROM image) or
/// all-FF (controller floor / disconnected). Used as a sanity gate
/// after `decode_mac`.
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

/// Build the byte to write to CR (§2.4) to kick a software reset.
/// Provided as a helper so the test suite can assert the bit pattern
/// without poking MMIO. RST is self-clearing once the chip has
/// re-initialised the FIFOs + descriptor pointers.
pub const fn cr_reset_value() -> u8 {
    CR_RST
}

// ── MAC version (XID) decode ────────────────────────────────────────
// Linux's r8169_main.c extracts the chip XID from TxConfig:
//   xid = (RTL_R32(tp, TxConfig) >> 20) & 0xfcf   // line 5647
// and matches it against `rtl_chip_infos[]`. For the 8125 family the
// XIDs are:
//   0x609 → RTL8125A (MAC_VER_61)
//   0x641 → RTL8125B (MAC_VER_63)
//   0x688 → RTL8125D
//   0x689 → RTL8125D
//   0x68a → RTL8125K
//   0x68b → RTL9151A
//   0x681 → RTL8125BP (MAC_VER_66)
// We only need to distinguish 8125A vs 8125B vs everything-else for
// Stage 2 because the bring-up steps are 99% identical; later stages
// branch the PHY-config table here.

/// Sub-family classification. Drives the PHY-config table and
/// firmware-blob pick in [`phy_table_for`] / [`firmware_name_for`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipKind {
    /// 0x609 / MAC_VER_61. Original RTL8125 silicon.
    Rtl8125A,
    /// 0x641 / MAC_VER_63. Refreshed RTL8125B silicon (most common
    /// laptop variant as of 2024).
    Rtl8125B,
    /// 0x688/0x689 / MAC_VER_64. RTL8125D.
    Rtl8125D,
    /// 0x68a / MAC_VER_64. RTL8125K (same PHY function as D,
    /// different blob).
    Rtl8125K,
    /// 0x68b / MAC_VER_64. RTL9151A (same PHY function as D,
    /// different blob).
    Rtl9151A,
    /// 0x708 / MAC_VER_65. RTL8125CP.
    Rtl8125Cp,
    /// 0x681 / MAC_VER_66. RTL8125BP.
    Rtl8125Bp,
    /// XID didn't match any known 8125. Bring-up still attempts —
    /// the common path doesn't depend on the sub-rev — but no
    /// PHY table or firmware blob is known for it.
    Unknown(u32),
}

/// Extract the 12-bit chip XID from the 32-bit TxConfig (0x40) value.
/// The mask `0xfcf` mirrors Linux's `(txconfig >> 20) & 0xfcf`.
pub const fn decode_xid(txconfig: u32) -> u32 {
    (txconfig >> 20) & 0xfcf
}

/// Classify an XID into `ChipKind`.
pub const fn chip_kind_from_xid(xid: u32) -> ChipKind {
    match xid {
        0x609 => ChipKind::Rtl8125A,
        0x641 => ChipKind::Rtl8125B,
        0x688 | 0x689 => ChipKind::Rtl8125D,
        0x68a => ChipKind::Rtl8125K,
        0x68b => ChipKind::Rtl9151A,
        0x708 => ChipKind::Rtl8125Cp,
        0x681 => ChipKind::Rtl8125Bp,
        other => ChipKind::Unknown(other),
    }
}

// ── TX descriptor ring layout (Stage 3) ────────────────────────────
// Datasheet §3.1.1 "Transmit Descriptor Format" — RTL8125 inherits
// the 16-byte descriptor of the RTL8169/8168 family unchanged on the
// normal-priority queue. Each descriptor is four little-endian 32-bit
// words:
//
//   word0:  flags (OWN/EOR/FS/LS/...) | frame_length[15:0]
//   word1:  VLAN tag bits             (Stage 3: always 0)
//   word2:  buffer phys addr  low  32 bits
//   word3:  buffer phys addr  high 32 bits

/// Descriptor count per ring. Datasheet §3.1 caps each ring at 1024
/// descriptors; 256 fills one 4 KiB page (256 × 16 = 4096) which is
/// the same Stage-4 ring sizing the r8169 driver uses.
pub const RING_LEN: usize = 256;
/// Total bytes occupied by one descriptor ring.
pub const RING_BYTES: usize = RING_LEN * 16;

// TX descriptor word0 flag bits (§3.1.1 Table 3-1).
pub(crate) const TXD_OWN: u32 = 1 << 31;
pub(crate) const TXD_EOR: u32 = 1 << 30;
pub(crate) const TXD_FS: u32 = 1 << 29;
pub(crate) const TXD_LS: u32 = 1 << 28;
/// word0 frame-length field mask (16 bits, §3.1.1).
pub(crate) const TXD_LEN_MASK: u32 = 0xFFFF;

/// In-memory shape of a single TX descriptor. `repr(C, align(16))`
/// matches the on-wire layout the chip DMAs from. `Default::default()`
/// produces a host-owned (OWN=0) descriptor, which is what
/// `alloc_coherent`-zeroed pages give us.
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

/// Build a single-buffer TX descriptor for a frame of `len` bytes
/// living at physical address `phys`. `slot` is the descriptor's
/// position within the ring; the EOR bit is set on slot
/// `RING_LEN - 1` so the controller's internal pointer wraps to slot
/// 0 instead of running off the end. FS+LS are always set since the
/// Stage-3 driver only emits single-segment packets.
///
/// `len` is masked to 16 bits per §3.1.1; values > 0xFFFF are silently
/// truncated (caller is expected to enforce ≤ 1518 / MTU).
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

// ── RX descriptor (§3.1.2 — same 16-byte shape) ─────────────────────

/// RX descriptor word0 flag bits — re-exported from `rtl_phy` for
/// driver-local use. The 8125's RX descriptor is identical to the
/// 8169's at the bit level (the "new descriptor format" that adds
/// 8 bytes is held disabled in `rtl_hw_start_8125_common`).
pub(crate) const RXD_OWN_LOCAL: u32 = 1 << 31;
pub(crate) const RXD_EOR_LOCAL: u32 = 1 << 30;
pub(crate) const RXD_LS_LOCAL: u32 = 1 << 28;
/// word0 length field mask — 14 bits per §3.1.2.
pub(crate) const RXD_LEN_MASK_LOCAL: u32 = 0x3FFF;

/// RX buffer size. Linux sizes every RX buffer on this family to
/// `R8169_RX_BUF_SIZE` (16 KiB − 1) and programs RMS to the
/// buffer bound, independent of MTU; jumbo frames are therefore
/// receivable even while the interface MTU stays 1500.
pub const RX_BUF_LEN: usize = 16383;

/// TX slot buffer size: one slot must hold the largest frame this
/// driver will transmit — the 8125-family jumbo tagged frame
/// (16384 bytes), which is also the family buffer bound.
pub const TX_BUF_LEN: usize = 16384;

/// Build the 14-bit-length RX descriptor for slot `slot` pointing at
/// `phys` with buffer size `buf_size`. OWN is set so the chip owns it;
/// EOR is set on the wrap slot. Mirrors `prepare_rx_desc` in
/// `rtl_phy.rs` so we don't import the whole module just for this
/// const helper.
pub const fn build_rx_desc(slot: usize, phys: u64, buf_size: u32) -> TxDesc {
    let mut flags = RXD_OWN_LOCAL | (buf_size & RXD_LEN_MASK_LOCAL);
    if slot == RING_LEN - 1 {
        flags |= RXD_EOR_LOCAL;
    }
    // TxDesc and RxDesc share the same on-wire shape — both are
    // `repr(C, align(16))` 4-word structs. Reusing `TxDesc` here
    // saves a separate type but produces correct DMA layout.
    TxDesc {
        flags_len: flags,
        vlan: 0,
        addr_lo: phys as u32,
        addr_hi: (phys >> 32) as u32,
    }
}

// TX offload bits — canonical definitions live in
// `crate::features` (corrected placement: v2 GTSENV/GTTCPHO in
// word0, MSS/csum bits/TCPHO in word1). The previous in-tree
// comments placed the v2 bits in word1, which was wrong and
// would have corrupted the MSS field. Re-exported so existing
// users of these names keep compiling.
/// Historic spelling of [`TD1_IPV4_CS`].
pub use crate::features::TD1_IPV4_CS as TD1_IPv4_CS;
pub use crate::features::{
    TD1_GTSENV4, TD1_GTSENV6, TD1_IPV4_CS, TD1_IPV6_CS, TD1_MSS_SHIFT, TD1_TCP_CS, TD1_UDP_CS,
};

// RX status bits — see `crate::features::rx_csum_decode`. The
// previous in-tree "OK" bits (RX_IPOK / RX_TCPOK / RX_UDPOK,
// bits 5/6/7) were frame-length bits, not protocol bits, and are
// deleted; decode through [`TxDesc::rx_csum_result`].
pub use crate::features::{
    RX_FAIL_IP as RX_IPFAIL, RX_FAIL_TCP as RX_TCPFAIL, RX_FAIL_UDP as RX_UDPFAIL,
};
pub use crate::features::{RX_PID_TCP, RX_PID_UDP};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    None,
    Ok,
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

    /// Decode the RX checksum result from a chip-returned
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

// ── Live driver state ───────────────────────────────────────────────
// Stage 2b: descriptor rings, MMIO-backed bring_up, polled TX/RX path.

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
    /// Frame outside [1, chip max frame].
    FrameTooLong,
    /// `transmit` couldn't find a free TX descriptor.
    TxRingFull,
    /// `transmit` polled too long for OWN to clear.
    TxTimeout,
    /// MSI-X table couldn't be brought up.
    MsixSetup,
    /// The requested TX offload cannot be programmed for this
    /// frame (unparseable transport header, SCTP, MSS/offset
    /// overflow).
    UnsupportedOffload,
    /// Catch-all.
    Other(&'static str),
}

/// A live RTL8125 / RTL8125B 2.5 GbE controller. Holds the MMIO
/// mapping, the descriptor rings, and the RX/TX buffer pools.
///
/// On-wire layout matches the r8169 driver: per-direction 256-slot
/// 16-byte-descriptor rings, one DMA buffer per slot for RX, one DMA
/// buffer per slot for TX (persistent — see audit #4 in the r8169
/// driver for why this matters).
pub struct RtlNic {
    mmio: MmioRegion,
    /// TX descriptor ring (`RING_LEN * 16` bytes).
    tx_ring: DmaBuffer,
    /// Persistent per-slot TX frame buffers; indexed by slot.
    tx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side TX producer cursor (next slot to fill).
    tx_head: IrqSafeSpinLock<u32>,
    /// RX descriptor ring (`RING_LEN * 16` bytes).
    rx_ring: DmaBuffer,
    /// One DMA buffer per RX descriptor. Kept alive for driver's
    /// lifetime — descriptor `i` always points at `rx_pool[i]`.
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side RX consumer cursor.
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address read from IDR0..5 at bring-up.
    pub mac: [u8; 6],
    /// Raw chip XID from TxConfig at bring-up (drives the
    /// firmware-blob pick for the D variants).
    pub xid: u32,
    /// Sub-family detected from TxConfig.XID at bring-up. Drives
    /// the PHY-config table pick in [`phy_table_for`].
    pub chip_kind: ChipKind,
    /// Last WoL option set programmed via [`RtlNic::set_wol_opts`].
    wol_opts: IrqSafeSpinLock<crate::features::WolOpts>,
    /// True when PHYStatus.LinkSts read 1 at bring-up. We don't yet
    /// re-poll on LinkChg interrupts.
    pub link_up: bool,
    /// IDT vector wired to MSI-X entry 0, when MSI-X is enabled.
    pub irq_vector: Option<u8>,
    /// Live MSI-X table — kept alive so the device's MSI-X enable
    /// stays sticky.
    msix: Option<narf_bus::MsixTable>,

    // IPC integration
    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: `RtlNic` only owns an `MmioRegion` (identity-mapped BAR2 device
// window) and `DmaBuffer`s (identity-mapped DMA pages). Those raw pointers are
// the sole reason auto `Send` is not derived; the underlying device window is
// not thread-affine, so the struct may be moved between cores.
unsafe impl Send for RtlNic {}
// SAFETY: every interior-mutable field (`tx_head`, `rx_head`, the IPC rings) is
// guarded by `IrqSafeSpinLock`, so concurrent `&RtlNic` access is serialised.
// The MMIO/DMA windows are device registers/buffers safe for shared volatile
// access from multiple cores.
unsafe impl Sync for RtlNic {}

impl core::fmt::Debug for RtlNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtlNic")
            .field("mac", &self.mac)
            .field("chip_kind", &self.chip_kind)
            .field("link_up", &self.link_up)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

impl RtlNic {
    /// Bring up the controller: reset, read MAC, detect XID, install
    /// TX + RX rings, enable receive + transmit, observe link state.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively for
    /// the duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NicError> {
        // RTL8125 ships its operational registers in BAR2 (MMIO).
        // BAR0/1 are the legacy I/O alias path we don't use.
        // SAFETY: caller-asserted exclusive ownership.
        let mmio = unsafe { map_bar(device, 2) }.map_err(|_| NicError::BarMapFailed)?;

        // 1. Software reset. CR.RST self-clears once the chip has
        //    finished re-initialising the FIFOs + descriptor pointers
        //    (datasheet §2.4 + Linux `rtl_hw_reset`).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write8(REG_CR, CR_RST);
        }
        // 100 ms wedge threshold matches Linux's
        // `rtl_loop_wait_low(tp, &rtl_chipcmd_cond, 100, 100)` at
        // r8169_main.c:2675 (100 µs per poll × 100 polls = 10 ms
        // typical; bumped to 100 ms wall-clock for safety here).
        narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read8(REG_CR) } & CR_RST == 0,
            narf_time::Deadline::after_ms(100),
        );

        // 2. Read MAC from IDR0..5 (datasheet §2.1). Byte-readable
        //    despite the 4-byte write constraint.
        // SAFETY: identity-mapped.
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

        // 3. Detect sub-family from TxConfig XID. Read BEFORE step
        //    6a overwrites TCR: the reset-default TCR carries the
        //    chip's XID in bits 29:20 (Linux `rtl_read_mac_version`
        //    reads the same register at probe).
        // SAFETY: identity-mapped MMIO.
        let txcfg = unsafe { mmio.read32(REG_TCR) };
        let xid = decode_xid(txcfg);
        let chip_kind = chip_kind_from_xid(xid);

        // 4. Allocate descriptor rings + per-slot buffers. zeroed
        //    pages give us "host-owned (OWN=0)" descriptors, which
        //    is the correct initial state for TX; RX gets explicitly
        //    rearmed to NIC-owned in step 6.
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

        // 5. C+CR first per the Linux bring-up order. Enable RX
        //    checksum offload (the RX pump decodes it into
        //    `Frame::rx_meta`) and keep RX VLAN stripping OFF:
        //    NARF's `Frame::rx_meta` has no VLAN-tag field, so
        //    stripping would discard tags the stack needs. TX
        //    VLAN insertion is independent of this bit. Then
        //    program the EEE TX LPI idle timer (Linux's
        //    `rtl_set_eee_txidle_timer` VER_61..LAST arm: the whole
        //    8125 family takes the 0x6048 register).
        // SAFETY: bring_up owns the BAR exclusively.
        unsafe {
            let mut regs = crate::features::MmioRegs(&mmio);
            crate::features::apply_cplus(&mut regs, false, true);
            crate::features::apply_eee_txidle(&mut regs, 1500);
        }

        // 6. CR enables both TE + RE. Datasheet §2.7 + §2.8 require
        //    TE / RE be set before TCR / RCR are programmed; same
        //    idiom as r8169.
        // SAFETY: same.
        unsafe {
            mmio.write8(REG_CR, CR_TE | CR_RE);
        }

        // 6a. Program TX descriptor ring base + TCR. Splits the
        //     64-bit phys as low-32@offset+0, high-32@offset+4 per
        //     datasheet §2.3. EOR set lazily on the last slot at
        //     first `transmit`.
        let tx_phys = tx_ring.dma_addr().raw();
        // MTPS from the family jumbo tagged frame (16384 bytes →
        // 128 units of 128 bytes). The whole 8125 family needs no
        // jumbo Config-register writes (Linux's `rtl_jumbo_config`
        // default arm), so MTPS is the only jumbo sizing here.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_TNPDS, tx_phys as u32);
            mmio.write32(REG_TNPDS + 4, (tx_phys >> 32) as u32);
            mmio.write32(REG_TCR, TCR_MXDMA_UNLIMITED | TCR_IFG_STD);
            mmio.write8(REG_MTPS, crate::features::mtps_for_frame(TX_BUF_LEN as u32));
        }

        // 6b. Pre-fill RX descriptors: each points at its pooled
        //     buffer + has BufferSize=RX_BUF_LEN + OWN=1 so the NIC
        //     can DMA into it. Slot RING_LEN-1 carries EOR.
        let rx_ring_phys = rx_ring.dma_addr().raw();
        for (i, buf) in rx_pool.iter().enumerate().take(RING_LEN) {
            let buf_phys = buf.dma_addr().raw();
            let mut flags = RXD_OWN_LOCAL | (RX_BUF_LEN as u32 & RXD_LEN_MASK_LOCAL);
            if i == RING_LEN - 1 {
                flags |= RXD_EOR_LOCAL;
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
        // RMS is the buffer bound (16383), not the MTU bound —
        // Linux's `rtl_set_rx_max_size` shape.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_RDSAR, rx_ring_phys as u32);
            mmio.write32(REG_RDSAR + 4, (rx_ring_phys >> 32) as u32);
            mmio.write16(REG_RMS, RX_BUF_LEN as u16);
        }

        // 6c. RCR — 8125 variant uses `RX_FETCH_DFLT_8125 = 8 << 27`
        //     for the DMA-prefetch threshold (Linux
        //     `rtl_init_rxcfg(RTL_GIGA_MAC_VER_61)`; the 8169-era
        //     RX128_INT_EN / RX_EARLY_OFF bits are absent on 8125).
        //     We OR in the accept-mask (physical-match, multicast,
        //     broadcast) + MXDMA-unlimited so the chip can DMA
        //     without throttling on the 2.5 G PHY's burst rate.
        // SAFETY: same.
        unsafe {
            mmio.write32(
                REG_RCR,
                RX_FETCH_DFLT_8125 | RCR_APM | RCR_AM | RCR_AB | RCR_MXDMA_UNLIMITED,
            );
        }

        // 7. Disable RTL8125's interrupt-aggregation block. Off in
        //    Stage 2 — aggregation hides individual TX completions
        //    behind a timer that complicates the polled / IRQ-driven
        //    paths in transmit / receive.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write8(REG_INT_CFG0_8125, 0);
        }

        // 8. Mask all interrupts at IMR for now. MSI-X bring-up
        //    enables the bits we care about (ROK|TOK|LinkChg). We
        //    write-1-clear any latched ISR bits so a stale event
        //    from before reset can't fire on first IRQ unmask.
        //    Use the 32-bit ports — the 8125 has them at 0x38/0x3C
        //    and Realtek's reference driver targets these.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_IMR_8125, 0);
            mmio.write32(REG_ISR_8125, 0xFFFF_FFFF);
        }

        // 9. PHYStatus snapshot. The PHY runs auto-neg in the
        //    background; on a live cabled link LinkSts reads 1
        //    within ~3 seconds of reset. Stage 2 captures the
        //    current state — a later stage wires LinkChg-driven
        //    re-evaluation.
        // SAFETY: same.
        let phystat = unsafe { mmio.read8(REG_PHYSTAT) };
        let link_up = phystat & PHYSTAT_LINKSTS != 0;

        // 10. Lock the config registers back per datasheet §2.9.
        // SAFETY: same.
        unsafe {
            mmio.write8(REG_9346CR, EEM_NORMAL);
        }

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let rtl = Arc::new(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_head: IrqSafeSpinLock::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            xid,
            chip_kind,
            wol_opts: IrqSafeSpinLock::new(crate::features::WolOpts::NONE),
            link_up,
            irq_vector: None,
            msix: None,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn the device's only pump pair — probe spawns none, so the
        // pair fed here is the pair whose halves occupy the ring slots.
        spawn_pumps(rtl.clone(), rx_prod, tx_cons);

        Arc::try_unwrap(rtl).map_err(|_| NicError::NoMemory)
    }

    /// Bring up MSI-X with a single vector wired to MSI-X table
    /// entry 0. After this call, `wait_for_irq(self.irq_vector
    /// .unwrap()).await` resolves on every TX completion / RX
    /// arrival / link change.
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
        // SAFETY: caller-authority over the device.
        unsafe { table.program_vector(0, target_apic, v) }.map_err(|_| NicError::MsixSetup)?;
        // SAFETY: same.
        unsafe { table.enable() }.map_err(|_| NicError::MsixSetup)?;

        // Unmask ROK | TOK | LinkChg | RDU | TDU on the 32-bit
        // IMR_8125 port. Bits 0/2/5/4/7 — same numbering as the
        // legacy 16-bit alias (the 8125 promoted them to u32 to
        // make room for the new high-half ones at bits 14/15).
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

    /// Transmit a single Ethernet frame. Polled completion: spins on
    /// the slot's OWN bit until the NIC clears it. Frames up to the
    /// family jumbo tagged frame (16384 bytes) are accepted; the
    /// chip pads frames < 64 bytes itself.
    pub fn transmit(&self, frame: &[u8], meta: &TxMeta) -> Result<(), NicError> {
        if frame.is_empty() || frame.len() > TX_BUF_LEN {
            return Err(NicError::FrameTooLong);
        }
        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let phys = self.tx_pool[slot].dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(self.tx_pool[slot].cpu_mut_ptr_at::<u8>(i as u64), *b);
            }
        }
        let ring_phys = self.tx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // SAFETY: identity-mapped DMA ring; slot < RING_LEN.
        let cur_flags = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
        };
        if cur_flags & TXD_OWN != 0 {
            return Err(NicError::TxRingFull);
        }

        // Select descriptor format based on offload request.
        // Every 8125-family chip is csum-v2, so only the v2
        // builders are used. Offload words are computed
        // driver-locally (frame parsing + `crate::features`
        // builders); no shared TX-path code is touched. An offload
        // the chip cannot take for this frame is
        // `UnsupportedOffload`, never a descriptor with a guessed
        // offset. Plain frames still get VLAN insertion.
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
        // The NIC sees OWN=1 once we publish word0; the addr / vlan
        // / length-without-OWN fields must already be visible. Write
        // them first, fence, then publish OWN.
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                d.vlan,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 8).kernel_mut_ptr::<u32>(),
                d.addr_lo,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 12).kernel_mut_ptr::<u32>(),
                d.addr_hi,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<u32>(),
                d.flags_len,
            );
        }
        compiler_fence(Ordering::SeqCst);

        // Ring the TX doorbell at TxPoll_8125 (0x90 on 8125, not
        // 0x38). NPQ bit (1 << 6) is unchanged from the legacy
        // doorbell.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write8(REG_TPPOLL_8125, TPPOLL_NPQ);
        }

        let next_head = (*head_g + 1) % (RING_LEN as u32);
        *head_g = next_head;
        drop(head_g);

        // Poll for OWN → 0. 250 ms wall-clock budget covers worst-
        // case Tx congestion. responsive_spin_until ticks sleep_pumps
        // so the FB cursor / serial drain stay alive.
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

    /// Pop one received frame off the RX ring. Returns `Some(buf)`
    /// when a descriptor's OWN bit reads 0 (NIC handed it back) and
    /// `None` when the ring head is still NIC-owned.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        self.receive_with_meta().map(|(buf, _)| buf)
    }

    /// Like [`RtlNic::receive`], plus the chip's RX checksum
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
        if flags_len & RXD_OWN_LOCAL != 0 {
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

        // Status layout per §3.1.2: bits[13:0] = received frame
        // length (incl. CRC unless RCR.SECRC strips it; Stage 2
        // leaves SECRC off so CRC is preserved — caller strips if
        // they care). LS must be set; multi-segment fragments get
        // their non-LS prefixes dropped.
        let len = (flags_len & RXD_LEN_MASK_LOCAL) as usize;
        let buf_phys = self.rx_pool[slot].dma_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(len.min(RX_BUF_LEN));
        if flags_len & RXD_LS_LOCAL != 0 {
            let copy_len = len.min(RX_BUF_LEN);
            // SAFETY: identity-mapped DMA buffer.
            for i in 0..copy_len {
                // SAFETY: `buf_phys` is the identity-mapped DMA buffer the NIC
                // just filled for this slot; `i < copy_len <= RX_BUF_LEN`, so
                // `buf_phys + i` stays inside the buffer.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                out.push(unsafe {
                    core::ptr::read_volatile(self.rx_pool[slot].cpu_ptr_at::<u8>(i as u64))
                });
            }
        }

        // Rearm the descriptor: OWN=1, BufferSize=RX_BUF_LEN, EOR
        // preserved on the wrap slot.
        let mut new_flags = RXD_OWN_LOCAL | (RX_BUF_LEN as u32 & RXD_LEN_MASK_LOCAL);
        if slot == RING_LEN - 1 {
            new_flags |= RXD_EOR_LOCAL;
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
            );
        }
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        Some((out, csum))
    }

    /// Largest frame this driver will transmit: the family jumbo
    /// tagged frame, which is also the TX slot buffer size.
    pub fn max_frame(&self) -> u32 {
        TX_BUF_LEN as u32
    }

    /// EEE LPI capabilities for this chip's MAC version (Linux's
    /// `rtl8169_get_lpi_caps` shape; 8125A gets 100/1000 only,
    /// later variants add 2500FD).
    pub fn eee_caps(&self) -> crate::features::EeeCaps {
        crate::features::eee_lpi_caps(match self.chip_kind {
            ChipKind::Rtl8125A => 61,
            ChipKind::Rtl8125B => 63,
            ChipKind::Rtl8125D | ChipKind::Rtl8125K | ChipKind::Rtl9151A => 64,
            ChipKind::Rtl8125Cp => 65,
            ChipKind::Rtl8125Bp => 66,
            ChipKind::Unknown(_) => 0,
        })
    }

    /// Program Wake-on-LAN options (Linux's `__rtl8169_set_wol`
    /// 8125-family shape). Config registers are unlocked for the
    /// sequence and re-locked after. Unlike the r8169 driver,
    /// nothing is left pending: the 8125 magic step (MAC-OCP
    /// 0xc0b6 bit 0) and the LinkUp step (MAC-OCP 0xe0c6, mask
    /// 0x3f, value 0x13 when PHY wake is on, else 0) are both
    /// performed here through the shared OCP accessor.
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
            // Consume the pending 8125-family steps. The OCP
            // window is not a config register, so it stays usable
            // after the lock.
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

    /// Last WoL option set programmed via [`RtlNic::set_wol_opts`].
    pub fn wol_opts(&self) -> crate::features::WolOpts {
        *self.wol_opts.lock()
    }

    /// Read the PHY-status register. Useful for tests; bit 1 = link.
    pub fn phy_status(&self) -> u8 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read8(REG_PHYSTAT) }
    }

    /// Read + write-1-clear the ISR_8125 (32-bit port). The IRQ
    /// handler / async waiter path uses this to drain pending events
    /// before re-arming.
    pub fn ack_isr(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        let s = unsafe { self.mmio.read32(REG_ISR_8125) };
        // 8125 ISR: write 1 to clear.
        // SAFETY: same.
        unsafe {
            self.mmio.write32(REG_ISR_8125, s);
        }
        s
    }

    /// Re-evaluate the link state from PHYStatus. Returns the new
    /// `link_up` value and stamps it into `self.link_up`.
    pub fn refresh_link_state(&mut self) -> bool {
        // SAFETY: identity-mapped MMIO.
        let phystat = unsafe { self.mmio.read8(REG_PHYSTAT) };
        let up = phystat & PHYSTAT_LINKSTS != 0;
        self.link_up = up;
        up
    }
}

// ── PHY-config tables ────────────────────────────────────────────────
// Transcriptions of the `rtl8125*_hw_phy_config` functions in
// Linux `drivers/net/ethernet/realtek/r8169_phy_config.c`, in
// source order, with the helper calls expanded inline. Entry
// constructors: `mp` = `phy_modify_paged`, `wp` =
// `phy_write_paged`, `gp` = `r8168g_phy_param`, `rp` =
// `rtl8125_phy_param` (see `crate::phy_access` for the exact
// register each form touches).

use crate::phy_access::{PhyConfigEntry, PhyConfigKind};

const fn mp(page: u16, reg: u16, mask: u16, val: u16) -> PhyConfigEntry {
    PhyConfigEntry {
        page,
        reg,
        mask,
        val,
        kind: PhyConfigKind::ModifyPaged,
    }
}

const fn wp(page: u16, reg: u16, val: u16) -> PhyConfigEntry {
    PhyConfigEntry {
        page,
        reg,
        mask: 0xFFFF,
        val,
        kind: PhyConfigKind::WritePaged,
    }
}

const fn gp(parm: u16, mask: u16, val: u16) -> PhyConfigEntry {
    PhyConfigEntry {
        page: parm,
        reg: 0x14,
        mask,
        val,
        kind: PhyConfigKind::R8168gParam,
    }
}

const fn rp(parm: u16, mask: u16, val: u16) -> PhyConfigEntry {
    PhyConfigEntry {
        page: parm,
        reg: 0xb87e,
        mask,
        val,
        kind: PhyConfigKind::Rtl8125Param,
    }
}

/// `rtl8168g_enable_gphy_10m`: `phy_modify_paged(0x0a44, 0x11,
/// 0, BIT(11))`.
const fn enable_gphy_10m() -> PhyConfigEntry {
    mp(0x0a44, 0x11, 0x0000, 0x0800)
}

/// `rtl8125_legacy_force_mode`: `phy_modify_paged(0xa5b, 0x12,
/// BIT(15), 0)`.
const fn legacy_force_mode() -> PhyConfigEntry {
    mp(0xa5b, 0x12, 0x8000, 0x0000)
}

/// `rtl8168g_disable_aldps`: `phy_modify_paged(0x0a43, 0x10,
/// BIT(2), 0)`.
const fn disable_aldps() -> PhyConfigEntry {
    mp(0x0a43, 0x10, 0x0004, 0x0000)
}

/// RTL8125A (VER_61) table, part 1: everything Linux's
/// `rtl8125a_2_hw_phy_config` writes BEFORE `r8169_apply_firmware`
/// — including the 0x0a43 burst (selector 0x81B3, then 15 values,
/// then 25 zeroes) and the page-0 restore. The burst's trailing
/// `phy_write(0x1f, 0x0000)` is encoded as `wp(0, 0x1f, 0)`:
/// selecting page 0 and then writing the page-select register
/// itself to 0 leaves page 0 selected, which is the same state.
const PHY_TABLE_A_PRE: &[PhyConfigEntry] = &[
    mp(0xad4, 0x17, 0x0000, 0x0010),
    mp(0xad1, 0x13, 0x03ff, 0x03ff),
    mp(0xad3, 0x11, 0x003f, 0x0006),
    mp(0xac0, 0x14, 0x1100, 0x0000),
    mp(0xacc, 0x10, 0x0003, 0x0002),
    mp(0xad4, 0x10, 0x00e7, 0x0044),
    mp(0xac1, 0x12, 0x0080, 0x0000),
    mp(0xac8, 0x10, 0x0300, 0x0000),
    mp(0xac5, 0x17, 0x0007, 0x0002),
    wp(0xad4, 0x16, 0x00a8),
    wp(0xac5, 0x16, 0x01ff),
    mp(0xac8, 0x15, 0x00f0, 0x0030),
    rp(0x80a2, 0xffff, 0x0153),
    rp(0x809c, 0xffff, 0x0153),
    wp(0x0a43, 0x13, 0x81b3),
    wp(0x0a43, 0x14, 0x0043),
    wp(0x0a43, 0x14, 0x00a7),
    wp(0x0a43, 0x14, 0x00d6),
    wp(0x0a43, 0x14, 0x00ec),
    wp(0x0a43, 0x14, 0x00f6),
    wp(0x0a43, 0x14, 0x00fb),
    wp(0x0a43, 0x14, 0x00fd),
    wp(0x0a43, 0x14, 0x00ff),
    wp(0x0a43, 0x14, 0x00bb),
    wp(0x0a43, 0x14, 0x0058),
    wp(0x0a43, 0x14, 0x0029),
    wp(0x0a43, 0x14, 0x0013),
    wp(0x0a43, 0x14, 0x0009),
    wp(0x0a43, 0x14, 0x0004),
    wp(0x0a43, 0x14, 0x0002),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0x0a43, 0x14, 0x0000),
    wp(0, 0x1f, 0x0000),
    gp(0x8257, 0xffff, 0x020f),
    gp(0x80ea, 0xffff, 0x7843),
];

/// RTL8125A (VER_61) table, part 2: everything Linux writes AFTER
/// `r8169_apply_firmware`, in order, ending with the helper calls.
const PHY_TABLE_A_POST: &[PhyConfigEntry] = &[
    mp(0xd06, 0x14, 0x0000, 0x2000),
    gp(0x81a2, 0x0000, 0x0100),
    mp(0xb54, 0x16, 0xff00, 0xdb00),
    mp(0xa45, 0x12, 0x0001, 0x0000),
    mp(0xa5d, 0x12, 0x0000, 0x0020),
    mp(0xad4, 0x17, 0x0010, 0x0000),
    mp(0xa86, 0x15, 0x0001, 0x0000),
    enable_gphy_10m(),
    disable_aldps(),
    // `rtl8125_config_eee_phy` = g-config + common clears.
    mp(0x0a43, 0x11, 0x0000, 0x0010),
    mp(0xa6d, 0x14, 0x0010, 0x0000),
    mp(0xa42, 0x14, 0x0080, 0x0000),
    mp(0xa4a, 0x11, 0x0200, 0x0000),
];

/// RTL8125B (VER_63) table: firmware runs first in Linux, so the
/// whole table is the post-firmware part.
const PHY_TABLE_B: &[PhyConfigEntry] = &[
    enable_gphy_10m(),
    mp(0xac4, 0x13, 0x00f0, 0x0090),
    mp(0xad3, 0x10, 0x0003, 0x0001),
    rp(0x80f5, 0xffff, 0x760e),
    rp(0x8107, 0xffff, 0x360e),
    rp(0x8551, 0xff00, 0x0800),
    mp(0xbf0, 0x10, 0xe000, 0xa000),
    mp(0xbf4, 0x13, 0x0f00, 0x0300),
    gp(0x8044, 0xffff, 0x2417),
    gp(0x804a, 0xffff, 0x2417),
    gp(0x8050, 0xffff, 0x2417),
    gp(0x8056, 0xffff, 0x2417),
    gp(0x805c, 0xffff, 0x2417),
    gp(0x8062, 0xffff, 0x2417),
    gp(0x8068, 0xffff, 0x2417),
    gp(0x806e, 0xffff, 0x2417),
    gp(0x8074, 0xffff, 0x2417),
    gp(0x807a, 0xffff, 0x2417),
    mp(0xa4c, 0x15, 0x0000, 0x0040),
    mp(0xbf8, 0x12, 0xe000, 0xa000),
    legacy_force_mode(),
    disable_aldps(),
    mp(0x0a43, 0x11, 0x0000, 0x0010),
    mp(0xa6d, 0x14, 0x0010, 0x0000),
    mp(0xa42, 0x14, 0x0080, 0x0000),
    mp(0xa4a, 0x11, 0x0200, 0x0000),
];

/// RTL8125D / RTL8125K / RTL9151A (VER_64) table: firmware first,
/// then four helper calls only — Linux's `rtl8125d_hw_phy_config`
/// has no other register writes.
const PHY_TABLE_D: &[PhyConfigEntry] = &[
    enable_gphy_10m(),
    legacy_force_mode(),
    disable_aldps(),
    mp(0x0a43, 0x11, 0x0000, 0x0010),
    mp(0xa6d, 0x14, 0x0010, 0x0000),
    mp(0xa42, 0x14, 0x0080, 0x0000),
    mp(0xa4a, 0x11, 0x0200, 0x0000),
];

/// RTL8125CP (VER_65) table: firmware first. `LINK_SPEED_10M_PLL_OFF
/// | ALDPS_PLL_OFF` = BIT(0) | BIT(1) = 0x0003 (Linux
/// `r8169_phy_config.c` lines 17–18).
const PHY_TABLE_CP: &[PhyConfigEntry] = &[
    enable_gphy_10m(),
    mp(0xad0, 0x17, 0x007f, 0x000b),
    mp(0xad7, 0x14, 0x0000, 0x0010),
    rp(0x807f, 0xff00, 0x5300),
    gp(0x81b8, 0xffff, 0x00b4),
    gp(0x81ba, 0xffff, 0x00e4),
    gp(0x81c5, 0xffff, 0x0104),
    gp(0x81d0, 0xffff, 0x054d),
    mp(0x0a43, 0x10, 0x0000, 0x0003),
    mp(0x0a44, 0x11, 0x0000, 0x0080),
    legacy_force_mode(),
    disable_aldps(),
    mp(0x0a43, 0x11, 0x0000, 0x0010),
    mp(0xa6d, 0x14, 0x0010, 0x0000),
    mp(0xa42, 0x14, 0x0080, 0x0000),
    mp(0xa4a, 0x11, 0x0200, 0x0000),
];

/// RTL8125BP (VER_66) table: firmware first.
const PHY_TABLE_BP: &[PhyConfigEntry] = &[
    enable_gphy_10m(),
    gp(0x8010, 0x0800, 0x0000),
    rp(0x8088, 0xff00, 0x9000),
    rp(0x808f, 0xff00, 0x9000),
    gp(0x8174, 0x2000, 0x1800),
    legacy_force_mode(),
    disable_aldps(),
    mp(0x0a43, 0x11, 0x0000, 0x0010),
    mp(0xa6d, 0x14, 0x0010, 0x0000),
    mp(0xa42, 0x14, 0x0080, 0x0000),
    mp(0xa4a, 0x11, 0x0200, 0x0000),
];

/// Firmware blob name for a chip XID, from Linux's
/// `rtl_firmware` table (`rtl8125a-3.fw`, `rtl8125b-2.fw`,
/// `rtl8125d-1.fw` / `rtl8125d-2.fw`, `rtl8125k-1.fw`,
/// `rtl9151a-1.fw`, `rtl8125cp-1.fw`, `rtl8125bp-2.fw`).
/// `None` for an XID with no known blob.
pub fn firmware_name_for(xid: u32) -> Option<&'static str> {
    Some(match xid {
        0x609 => "rtl_nic/rtl8125a-3.fw",
        0x641 => "rtl_nic/rtl8125b-2.fw",
        0x688 => "rtl_nic/rtl8125d-1.fw",
        0x689 => "rtl_nic/rtl8125d-2.fw",
        0x68a => "rtl_nic/rtl8125k-1.fw",
        0x68b => "rtl_nic/rtl9151a-1.fw",
        0x708 => "rtl_nic/rtl8125cp-1.fw",
        0x681 => "rtl_nic/rtl8125bp-2.fw",
        _ => return None,
    })
}

/// PHY-config tables for a chip kind, as `(pre_firmware,
/// post_firmware)` slices. Only 8125A splits: Linux runs its
/// firmware mid-table, so the pre part must land first. Every
/// other variant runs firmware first, so its pre part is empty.
/// Unknown kinds get no tables at all.
pub fn phy_table_for(kind: ChipKind) -> (&'static [PhyConfigEntry], &'static [PhyConfigEntry]) {
    match kind {
        ChipKind::Rtl8125A => (PHY_TABLE_A_PRE, PHY_TABLE_A_POST),
        ChipKind::Rtl8125B => (&[], PHY_TABLE_B),
        ChipKind::Rtl8125D | ChipKind::Rtl8125K | ChipKind::Rtl9151A => (&[], PHY_TABLE_D),
        ChipKind::Rtl8125Cp => (&[], PHY_TABLE_CP),
        ChipKind::Rtl8125Bp => (&[], PHY_TABLE_BP),
        ChipKind::Unknown(_) => (&[], &[]),
    }
}

/// Run the PHY bring-up sequence once the firmware registry exists.
/// Mirrors the 8127 late hook: take an `Arc` clone and drop the
/// registry lock before touching the PHY (a firmware delay opcode
/// can spin for up to `MAX_FIRMWARE_DELAY_MS`). A missing blob is
/// a log line, not an error — the tables still program the
/// registers they name. A blob that fails mid-stream is logged
/// and the tables still run (same shape as the 8127 hook).
pub fn configure_phy_late() {
    let controller = CONTROLLER.lock().clone();
    let Some(controller) = controller else {
        return;
    };
    configure_phy(&controller.mmio, controller.xid, controller.chip_kind);
}

fn configure_phy(mmio: &MmioRegion, xid: u32, kind: ChipKind) {
    use core::fmt::Write as _;

    let (pre, post) = phy_table_for(kind);
    let mut access = crate::phy_access::PhyAccess::new(mmio);

    if let Err(e) = access.apply_config_table(pre) {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8125: pre-firmware PHY table aborted: {:?}",
            e
        );
        return;
    }

    match load_phy_firmware(xid) {
        Some(code) => match access.run_firmware(&code) {
            Ok(()) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8125: applied firmware ({} opcodes)",
                    code.len(),
                );
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8125: firmware aborted at an opcode: {:?}; PHY may be partly patched",
                    e,
                );
            }
        },
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  rtl8125: no firmware blob for XID {:#x}; applying PHY config without it",
                xid,
            );
        }
    }

    if let Err(e) = access.apply_config_table(post) {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8125: PHY config table aborted: {:?}",
            e
        );
    }
}

/// Fetch and parse this chip's firmware blob, if the firmware
/// registry has it.
fn load_phy_firmware(xid: u32) -> Option<alloc::vec::Vec<u32>> {
    use core::fmt::Write as _;

    let name = firmware_name_for(xid)?;
    let auth = narf_firmware::trusted_loader_authority()?.derive().ok()?;
    let cap = narf_firmware::open(name, &auth).ok()?;
    let view = narf_firmware::view_of(&cap).ok()?;

    let code = match crate::phy_access::parse_firmware(view.bytes) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  rtl8125: {} failed its format check: {:?}",
                name,
                e,
            );
            return None;
        }
    };
    if let Err(e) = crate::phy_access::validate_firmware(&code) {
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8125: {} rejected: {:?}",
            name,
            e,
        );
        return None;
    }
    Some(code)
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<RtlNic>>> = IrqSafeSpinLock::new(None);

/// The interface name `iface::register` gave this NIC (`eth%d`, Linux
/// `dev_alloc_name`). Set once at probe; the device lives as long as
/// the kernel, so the name is leaked into a `&'static str`.
static RTL8125_IFNAME: crate::publish::IfName = crate::publish::IfName::new();

/// This NIC's interface name; empty until it has registered.
pub fn rtl8125_ifname() -> &'static str {
    RTL8125_IFNAME.get()
}

/// SendFn registered with `narf_net::iface` at probe time. Routes the
/// kernel-side TCP stack's outbound frames through `RtlNic::transmit`.
/// The Arc is cloned out rather than holding the IRQ-masking
/// CONTROLLER lock across `transmit` (same reasoning as e1000).
fn rtl8125_send_frame(frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = CONTROLLER.lock().clone().ok_or(())?;
    ctrl.transmit(frame, &meta).map_err(|_| ())
}

/// Decode a PHYStatus byte into a publication sample via the family's
/// existing `PhyStatus::parse`. The 1000M bit is in-band state: a
/// 2.5 GbE link also raises it, so 1000 is published as the in-band
/// lower bound; exact negotiated-rate decode is PHY work (#790).
fn rtl8125_link_sample(status: u8) -> crate::publish::LinkSample {
    let s = PhyStatus::parse(status);
    if !s.link_up {
        return crate::publish::LinkSample::DOWN;
    }
    let speed_mbps = if s.speed_1000m {
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

/// Probe entry — installed via `bus::register_pci_driver`. Idempotent:
/// returns `Ok(())` when the controller is already brought up.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER are both required: the chip DMAs the
    // descriptor rings + frame buffers, and we map BAR2 as MMIO.
    // INTX_DISABLE silences the legacy line so MSI-X can take over
    // cleanly later.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe holds exclusive authority over `device` and its cfg `cap`
    // for the duration of `bring_up`, satisfying its `# Safety` contract.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = match unsafe { RtlNic::bring_up(&device, &cap) } {
        Ok(d) => Arc::new(d),
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    *CONTROLLER.lock() = Some(dev.clone());

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("rtl8125"),
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
    let name = crate::publish::publish_netdev(mac, rtl8125_send_frame, rtl8125_link_sample(status));
    RTL8125_IFNAME.set(name);

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Rtl8125Nic);
    }

    // No pump spawn here: `bring_up` spawned the device's single RX/TX
    // pump pair, fed by the channel pair whose halves occupy the
    // `rx_ipc_ring`/`tx_ipc_ring` slots (igc's discipline). A second
    // pair spawned from probe would drain the same descriptor ring
    // while its mirror sink's consumer is overwritten away — silently
    // losing frames an attached ring consumer must see.

    Ok(())
}

fn spawn_pumps(
    device: Arc<RtlNic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        rtl8125_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        rtl8125_tx_pump(d2, tx_cons).await;
    });
}

async fn rtl8125_rx_pump(device: Arc<RtlNic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    // Carrier refresh (issue #791): the production datapath is polled
    // (probe never enables MSI-X, so the LinkChg bit in the ISR has no
    // consumer), which makes this pump the family's link observer.
    // `phy_status()` is an `&self` MMIO read — unlike
    // `refresh_link_state(&mut self)`, it is safe to call while pumps
    // hold Arc clones. A transition republishes the iface metadata;
    // the cached `Interface::link_up` snapshot is left as-is.
    let mut last_sample = rtl8125_link_sample(device.phy_status());
    loop {
        let sample = rtl8125_link_sample(device.phy_status());
        if sample != last_sample {
            last_sample = sample;
            crate::publish::publish_link(rtl8125_ifname(), sample);
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
            let name = rtl8125_ifname();
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

async fn rtl8125_tx_pump(device: Arc<RtlNic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload(), &TxMeta::plain());
    }
}

/// Register a PCI match-table entry per supported device id. Realtek
/// keeps the IDs distinct between RTL8125 and RTL8125B even though
/// the register layouts are identical; we register both.
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
#[derive(Debug)]
pub struct Rtl8125Nic;

impl narf_net::Interface for Rtl8125Nic {
    fn name(&self) -> &str {
        // The dynamic `eth%d` name once published (issue #784); the
        // family name before probe gets that far.
        let n = rtl8125_ifname();
        if n.is_empty() {
            "rtl8125"
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
        // one frame copied into one slot.
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
                    crate::publish::note_rx_mirror_attached(rtl8125_ifname());
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

impl crate::HwNic for Rtl8125Nic {
    fn name(&self) -> &'static str {
        let n = rtl8125_ifname();
        if n.is_empty() {
            "rtl8125"
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

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Test-side accessor: run `f` against the probed controller.
pub fn with_controller<R>(f: impl FnOnce(&RtlNic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

/// Mutable accessor — used by tests that want to switch on MSI-X
/// after probe.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut RtlNic) -> R) -> Option<R> {
    CONTROLLER
        .lock()
        .as_mut()
        .map(|a| f(Arc::get_mut(a).expect("RtlNic static has multiple owners")))
}
