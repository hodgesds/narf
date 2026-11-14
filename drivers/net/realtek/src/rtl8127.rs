//! Realtek RTL8127 / RTL8127A 10 Gigabit Ethernet driver — Stage-1
//! cut, extended with the Linux compared feature set: probe +
//! reset + TX/RX rings + one MSI-X vector, plus TX checksum
//! (TCP/UDP, v4/v6) and TSO (v2 layout — VER_80 is csum-v2),
//! VLAN tag insertion on TX, RX checksum decode, jumbo-sized
//! rings / RMS / MTPS, WoL register programming (including the
//! 8125-family MAC-OCP steps), the EEE TX LPI idle timer, and
//! the RSS register programming model (`features::apply_rss`)
//! plus the multi-ring datapath that consumes it (see below).
//! The runtime MTU switch (#1276, via [`Rtl8127MtuControl`])
//! reprograms the EEE timer per MTU and follows Linux's
//! `fix_features` offload rules.
//! Deliberate asymmetries: RX VLAN stripping stays OFF, and on a
//! 1-CPU boot bring-up keeps Linux's single-queue behavior
//! (`RSS_CTRL` = 0).
//!
//! ## RSS, precisely
//!
//! Linux enables RSS only on VER_80 (`rtl_hw_support_rss`), and
//! this is the only chip in the family with that gap. Bring-up
//! selects the RX queue count by Linux's rule —
//! `rounddown_pow2(min(cpu_count, 8))`, minimum 1 — and, when
//! it is ≥ 2, programs the steering registers via
//! `features::apply_rss` (key, indirection, control, queue
//! count, descriptor type), allocates one RX descriptor ring
//! and buffer pool per queue (queue 0 at `REG_RDSAR`, queues
//! 1..N at `REG_RDSAR_Q1_LOW + (q-1)*8`), switches every queue
//! to the RSS descriptor format, spawns one RX pump per queue,
//! and attempts up to 30 MSI-X vectors (Linux's
//! `R8127_MIN_NUM_IRQVEC`) with a single-vector fallback.
//! `Interface` then reports the live queue count, the active
//! `RssConfig`, and per-queue affinity, and `caps` gains
//! `NicCaps::RSS`. The pumps are still polled, so per-queue
//! vectors are programmed as device configuration for future
//! IRQ use and do not demux the polled pumps; likewise the
//! affinity core is the intended pump placement (spawns are
//! currently unpinned). Live multi-queue datapath validation
//! is silicon-only: QEMU does not emulate an 8127.
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
/// RX descriptor ring base for queue 1 (lo/hi pair). Queue q ≥ 1
/// lives at `REG_RDSAR_Q1_LOW + (q-1)*8`: each queue's base is a
/// 64-bit lo+hi pair, so the stride is 8. Linux programs these
/// from `rtl_set_rx_tx_desc_registers` (`RDSAR_Q1_LOW` 0x4000).
pub(crate) const REG_RDSAR_Q1_LOW: u64 = 0x4000;
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

impl MacVersion {
    /// Linux `RTL_GIGA_MAC_VER_*` number for MTU validation
    /// (`None` for an unknown XID — fail-closed: unknown
    /// versions are treated as modern by `mtu_transition`).
    pub const fn version_number(&self) -> Option<u32> {
        match self {
            MacVersion::Ver80 => Some(80),
            MacVersion::Unknown(_) => None,
        }
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

// ── RSS multi-ring helpers ────────────────────────────────────────
// Linux's `RxDesc` union: in RSS mode (descriptor type
// `DESC_TYPE_RSS`, set by `apply_rss`) a descriptor is NOT the
// default opts1/opts2/addr layout. It is rss_addr (64-bit, words
// 0–1), rss_opts2 (word 2), rss_opts1 (word 3). The status word
// the RX path reads is rss_opts1, whose bit positions Linux
// treats as the shared opts1 layout (its `rtl8169_rx_desc_opts1`
// returns rss_opts1 verbatim for the RSS type, and the RX loop
// then applies the common OWN / error / length decode) — so
// OWN/EOR/LS/LEN keep the positions in the `RXD_*` consts
// above. The checksum bits DO differ: the RSS branch decodes
// TCPT/UDPT/TCPF/UDPF from rss_opts1 instead of the
// default format's PID/fail bits.

// RSS-format checksum bits in rss_opts1 (Linux's
// `RX_TCPT_DESC_RSS` / `RX_UDPT_DESC_RSS` /
// `RX_TCPFAIL_DESC_RSS` / `RX_UDPFAIL_DESC_RSS`).
pub(crate) const RSS_RX_TCPT: u32 = 1 << 18;
pub(crate) const RSS_RX_UDPT: u32 = 1 << 19;
pub(crate) const RSS_RX_TCPFAIL: u32 = 1 << 15;
pub(crate) const RSS_RX_UDPFAIL: u32 = 1 << 16;

/// Linux's RSS queue-count rule (`rtl8169_set_rx_ring_num`):
/// `rounddown_pow2(min(cpu_count, RSS_MAX_QUEUES))`, minimum 1.
/// `RSS_MAX_QUEUES` is 8 (the in-tree `features::RSS_MAX_QUEUES`
/// bound, and the hardware queue-count field's width). A 0-CPU
/// reading (no SMP info) yields 1 — the single-queue case.
pub(crate) const fn select_rss_queues(cpus: u32) -> usize {
    if cpus <= 1 {
        return 1;
    }
    let n = if cpus > 8 { 8 } else { cpus };
    let mut q = 1;
    while q * 2 <= n {
        q *= 2;
    }
    q as usize
}

/// MMIO register offset holding queue `q`'s RX descriptor base
/// (lo word; hi word is +4). Queue 0 is `REG_RDSAR`; queues 1..N
/// are `REG_RDSAR_Q1_LOW + (q-1)*8`.
pub(crate) const fn rx_queue_base_reg(queue: usize) -> u64 {
    if queue == 0 {
        REG_RDSAR
    } else {
        REG_RDSAR_Q1_LOW + ((queue - 1) as u64) * 8
    }
}

/// MSI-X vectors to request for a table of `table_size` entries,
/// given a `want` from Linux's vector policy. The table size
/// bounds the request; 0 means "no MSI-X capability". The
/// caller falls back to 1 vector when allocation itself fails
/// (Linux's `rtl_alloc_irq` min-vector fallback).
pub(crate) const fn select_msix_count(table_size: u16, want: u16) -> u16 {
    if table_size == 0 {
        0
    } else if want > table_size {
        table_size
    } else {
        want
    }
}

/// Decode the RSS-format checksum result from an rss_opts1
/// status word. Linux's RSS branch marks the checksum OK iff
/// (TCPT and not TCPF) or (UDPT and not UDPF), and failed iff
/// TCPF or UDPF is set; otherwise the hardware did not verify
/// (e.g. non-TCP/UDP). There is no separate IP-fail bit in the
/// RSS branch — an IP-only failure surfaces as "not verified"
/// here, matching Linux. OK takes precedence over Fail when
/// both an OK bit and an unrelated Fail bit are set (a TCP
/// checksum cannot fail while a UDP checksum succeeds on the
/// same packet; the OK protocol's verdict wins, mirroring the
/// default-format decode's Ok-first shape).
pub(crate) const fn rss_rx_csum(opts1: u32) -> RxCsumResult {
    let tcp_ok = opts1 & RSS_RX_TCPT != 0 && opts1 & RSS_RX_TCPFAIL == 0;
    let udp_ok = opts1 & RSS_RX_UDPT != 0 && opts1 & RSS_RX_UDPFAIL == 0;
    if tcp_ok || udp_ok {
        RxCsumResult::Ok
    } else if opts1 & (RSS_RX_TCPFAIL | RSS_RX_UDPFAIL) != 0 {
        RxCsumResult::Fail
    } else {
        RxCsumResult::None
    }
}

/// RSS-format initial-fill status word for `slot`: OWN + buffer
/// size + EOR on the wrap slot (same shape as `build_rx_desc`,
/// written to word 3 instead of word 0).
pub(crate) const fn rss_fill_opts1(slot: usize) -> u32 {
    let mut flags = RXD_OWN | (RX_BUF_LEN as u32 & RXD_LEN_MASK);
    if slot == RING_LEN - 1 {
        flags |= RXD_EOR;
    }
    flags
}

/// RSS-format rearm status word, mirroring Linux's `mark_to_asic`
/// RSS branch: rss_opts2 = 0, then (after a fence) rss_opts1 =
/// DescOwn | eor | R8169_RX_BUF_SIZE, where eor is preserved
/// from the descriptor being rearmed. The caller writes the
/// address words + rss_opts2 = 0 first, fences, then publishes
/// this word last.
pub(crate) const fn rss_rearm_opts1(cur_opts1: u32) -> u32 {
    RXD_OWN | (cur_opts1 & RXD_EOR) | (RX_BUF_LEN as u32 & RXD_LEN_MASK)
}

/// One RX queue: its descriptor ring, its buffer pool, and its
/// head. Each queue's pump owns its head; heads are independent
/// (no cross-queue lock), and all pumps fan into the single
/// mirror producer on the NIC.
pub(crate) struct RxQueue {
    ring: DmaBuffer,
    pool: alloc::vec::Vec<DmaBuffer>,
    head: IrqSafeSpinLock<u32>,
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

use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

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
    /// The device is suspended for system suspend (issue #793):
    /// the datapath gates refuse TX and RX while suspended.
    Suspended,
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
    /// RX queues: one descriptor ring + buffer pool + head per
    /// queue. Length 1 in the single-queue case; N in RSS mode.
    rx_queues: alloc::vec::Vec<RxQueue>,
    /// Active RSS steering configuration (`None` when the
    /// controller runs a single queue).
    rss_config: Option<narf_net::rss::RssConfig>,
    /// MAC address read from IDR0..5 at bring-up.
    pub mac: [u8; 6],
    /// MAC version detected from TxConfig.XID at bring-up.
    pub mac_version: MacVersion,
    /// Programmed interface MTU, the source of truth for
    /// `Interface::mtu` / `HwNic::mtu` and the offload
    /// advertisement. The [`Rtl8127MtuControl`] hook is the only
    /// writer after bring-up.
    mtu: IrqSafeSpinLock<u32>,
    /// Last WoL option set programmed via [`Rtl8127Nic::set_wol_opts`].
    wol_opts: IrqSafeSpinLock<crate::features::WolOpts>,
    /// True when PHYStatus.LinkSts read 1 at bring-up.
    pub link_up: bool,
    /// Set by `suspend`, cleared by `resume`: the datapath gates
    /// refuse TX and RX while this is set (issue #793).
    suspended: AtomicBool,
    /// IDT vector wired to MSI-X entry 0, when MSI-X is enabled.
    pub irq_vector: Option<u8>,
    /// IDT vector per MSI-X entry (entry q → vector), when MSI-X
    /// is enabled. Empty when MSI-X is off; `irq_vector` is
    /// always the first entry of this list.
    irq_vectors: alloc::vec::Vec<u8>,
    msix: Option<narf_bus::MsixTable>,
    /// PCI address of the function this instance drives. Probe
    /// refuses a second bind of the same address (issue #1631): two
    /// `Rtl8127Nic`s for one chip would drive one set of rings.
    pub addr: narf_bus::BusAddr,
    /// Interface name `publish_netdev_with_context` assigned this
    /// instance (`eth%d`). Per-instance (i40e/igc pattern): the old
    /// module-level `RTL8127_IFNAME` static could only name one NIC.
    ifname: crate::publish::IfName,

    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
    /// Mirror producer shared by all RX pumps. Installed by
    /// `probe` before the pumps spawn; each pump locks it only
    /// for the non-blocking `try_send` of its mirror.
    rx_mirror: IrqSafeSpinLock<Option<Producer<Frame, RX_RING_N>>>,
}

// SAFETY: all interior-mutable state (`tx_head`, the per-queue
// heads, the IPC rings, the mirror producer) is guarded by
// `IrqSafeSpinLock`, and the remaining fields are either plain
// data or DMA/MMIO handles describing identity-mapped physical
// regions owned exclusively by this NIC instance.
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
    /// RxConfig (`RX_PAUSE_SLOT_ON` set). The RX queue count
    /// follows Linux's rule (`select_rss_queues(cpu_count)`).
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NicError> {
        // SAFETY: same contract as `bring_up_queues`.
        unsafe { Self::bring_up_queues(device, cap, select_rss_queues(narf_lib::smp::cpu_count())) }
    }

    /// Bring up with an explicit RX queue count (1 = Linux's
    /// single-queue behavior exactly; ≥ 2 = RSS multi-ring
    /// datapath). `bring_up` selects the count from the CPU
    /// count; tests and future callers can pin it here.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn bring_up_queues(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
        queues: usize,
    ) -> Result<Self, NicError> {
        let queues = queues.max(1);
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

        // 4. Allocate descriptor rings + per-slot buffers: one RX
        //    ring + pool per queue (each queue costs a full ring
        //    of 16 KiB buffers — the same shape Linux allocates
        //    per ring; the queue count is capped at 8 above).
        let tx_ring =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let mut rx_queues: alloc::vec::Vec<RxQueue> = alloc::vec::Vec::with_capacity(queues);
        for _ in 0..queues {
            let ring =
                alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
            let mut pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
            for _ in 0..RING_LEN {
                pool.push(
                    alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0)
                        .map_err(|_| NicError::NoMemory)?,
                );
            }
            rx_queues.push(RxQueue {
                ring,
                pool,
                head: IrqSafeSpinLock::new(0),
            });
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
        //    VER_80).
        // SAFETY: bring_up owns the BAR exclusively.
        unsafe {
            let mut regs = crate::features::MmioRegs(&mmio);
            crate::features::apply_cplus(&mut regs, false, true);
            crate::features::apply_eee_txidle(&mut regs, 1500);
        }
        // RSS state: a single queue keeps Linux's single-ring
        // write (`RSS_CTRL` = 0); ≥ 2 queues program key /
        // indirection / control / queue-count / descriptor-type
        // via `apply_rss`, and the config is kept for
        // `Interface::rss`.
        // SAFETY: bring_up owns the BAR exclusively.
        let rss_config = if queues >= 2 {
            let config =
                narf_net::rss::RssConfig::standard(queues, crate::features::RSS_INDIR_ENTRIES);
            // SAFETY: bring_up owns the register window exclusively
            // (single probe path; apply_rss requires exclusive ownership).
            let ok = unsafe {
                let mut regs = crate::features::MmioRegs(&mmio);
                crate::features::apply_rss(&mut regs, queues, &config.key, &config.indirection)
            };
            if !ok {
                return Err(NicError::UnsupportedOffload);
            }
            Some(config)
        } else {
            // SAFETY: bring_up owns the register window exclusively
            // (single probe path; apply_rss_single_queue requires it).
            unsafe {
                let mut regs = crate::features::MmioRegs(&mmio);
                crate::features::apply_rss_single_queue(&mut regs);
            }
            None
        };

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

        // 6b. Pre-fill RX descriptors and program each queue's
        //     base. A single queue keeps the legacy format and
        //     base (`REG_RDSAR`); ≥ 2 queues switch EVERY queue
        //     — queue 0 included — to the RSS format (Linux's
        //     descriptor-type switch is per-controller, not
        //     per-ring: `init_rx_desc_type` is one global) and
        //     program queues 1..N at `RDSAR_Q1_LOW + (q-1)*8`.
        //     Ordering note: RX is already enabled (step 6)
        //     before the bases land, exactly as in the shipped
        //     single-queue path (where RE precedes RDSAR), so
        //     steering is live for a bring-up window in which
        //     only queue 0's base is programmed. Queue 0's base
        //     is programmed first to shrink it.
        for (q, rxq) in rx_queues.iter().enumerate() {
            let ring_phys = rxq.ring.dma_addr().raw();
            for (i, buf) in rxq.pool.iter().enumerate() {
                let buf_phys = buf.dma_addr().raw();
                let desc_addr = ring_phys + (i * 16) as u64;
                if queues >= 2 {
                    // RSS format: rss_addr (words 0–1),
                    // rss_opts2 = 0 (word 2), rss_opts1 (word 3).
                    // The address words + rss_opts2 land before
                    // OWN is published in word 3.
                    // SAFETY: identity-mapped DMA ring page;
                    // i < RING_LEN so the 16-byte slot lies
                    // inside the RING_BYTES alloc.
                    unsafe {
                        core::ptr::write_volatile(
                            narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<u32>(),
                            buf_phys as u32,
                        );
                        core::ptr::write_volatile(
                            narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                            (buf_phys >> 32) as u32,
                        );
                        core::ptr::write_volatile(
                            narf_memory::PhysAddr::new(desc_addr + 8).kernel_mut_ptr::<u32>(),
                            0,
                        );
                    }
                    compiler_fence(Ordering::SeqCst);
                    // SAFETY: same.
                    unsafe {
                        core::ptr::write_volatile(
                            narf_memory::PhysAddr::new(desc_addr + 12).kernel_mut_ptr::<u32>(),
                            rss_fill_opts1(i),
                        );
                    }
                    compiler_fence(Ordering::SeqCst);
                } else {
                    let d = build_rx_desc(i, buf_phys, RX_BUF_LEN as u32);
                    // SAFETY: identity-mapped DMA ring page; i <
                    // RING_LEN so the 16-byte descriptor slot lies
                    // inside the RING_BYTES alloc.
                    unsafe {
                        core::ptr::write_volatile(
                            narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<TxDesc>(),
                            d,
                        );
                    }
                }
            }
            // SAFETY: identity-mapped MMIO.
            let base_reg = rx_queue_base_reg(q);
            // SAFETY: identity-mapped MMIO; q indexes rx_queues, so
            // base_reg is a valid per-queue RX base register, and
            // ring_phys is that queue's DMA ring base address.
            unsafe {
                mmio.write32(base_reg, ring_phys as u32);
                mmio.write32(base_reg + 4, (ring_phys >> 32) as u32);
            }
        }
        // RMS is the buffer bound (16383), not the MTU bound —
        // Linux's `rtl_set_rx_max_size` shape.
        // SAFETY: identity-mapped MMIO.
        unsafe {
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
            rx_queues,
            rss_config,
            mac,
            mac_version,
            mtu: IrqSafeSpinLock::new(1500),
            wol_opts: IrqSafeSpinLock::new(crate::features::WolOpts::NONE),
            link_up,
            suspended: AtomicBool::new(false),
            irq_vector: None,
            irq_vectors: alloc::vec::Vec::new(),
            msix: None,
            addr: device.addr,
            ifname: crate::publish::IfName::new(),
            rx_ipc_ring: IrqSafeSpinLock::new(None),
            tx_ipc_ring: IrqSafeSpinLock::new(None),
            rx_mirror: IrqSafeSpinLock::new(None),
        })
    }

    /// Bring up MSI-X with `want` vectors (entry i → IDT vector
    /// `vectors[i]`), returning the IDT vectors in entry order.
    /// The request is bounded by the device's own table size
    /// (`select_msix_count`); a request of 0 (no table) is
    /// `MsixSetup`. IDT vectors are allocated BEFORE any table
    /// entry is programmed, so a vector-allocation failure
    /// leaves the table untouched, and the table is enabled
    /// only after every entry programs. The IMR bits are the
    /// chip-global set (the 8127's IMR is not per-queue),
    /// identical to the single-vector path. A program failure
    /// mid-loop is unreachable for i < count ≤ size (only
    /// VectorOutOfRange or a BAR-mapping failure can fail it);
    /// on any error the table is left unenabled and dropped.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn enable_msix_vectors(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
        want: u16,
    ) -> Result<alloc::vec::Vec<u8>, NicError> {
        let mut table = narf_bus::enable_msix(cap, device).map_err(|_| NicError::MsixSetup)?;
        let count = select_msix_count(table.size(), want);
        if count == 0 {
            return Err(NicError::MsixSetup);
        }
        table.alloc_block(count).map_err(|_| NicError::MsixSetup)?;
        let mut vectors = alloc::vec::Vec::with_capacity(count as usize);
        for _ in 0..count {
            vectors.push(narf_interrupts::vector::alloc().map_err(|_| NicError::MsixSetup)?);
        }
        // SAFETY: x2APIC is online by Stage-4 boot.
        let target_apic = unsafe { narf_interrupts::current_cpu_target_id() };
        for (i, v) in vectors.iter().enumerate() {
            // SAFETY: caller-authority; entry i < count ≤ table
            // size, allocated above; the table is not enabled
            // yet, so a failure here leaves it inert.
            unsafe { table.program_vector(i as u16, target_apic, *v) }
                .map_err(|_| NicError::MsixSetup)?;
        }
        // SAFETY: same.
        unsafe { table.enable() }.map_err(|_| NicError::MsixSetup)?;

        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(
                REG_IMR_8125,
                INT32_ROK | INT32_TOK | INT32_LINKCHG | INT32_RDU | INT32_TDU,
            );
        }

        self.irq_vector = vectors.first().copied();
        self.irq_vectors = vectors.clone();
        self.msix = Some(table);
        Ok(vectors)
    }

    /// Transmit a single Ethernet frame (polled completion).
    pub fn transmit(&self, frame: &[u8], meta: &TxMeta) -> Result<(), NicError> {
        if self.suspended.load(Ordering::Acquire) {
            return Err(NicError::Suspended);
        }
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
    /// Queue 0 in the current format (legacy when single-queue,
    /// RSS format when multi-queue).
    pub fn receive_with_meta(&self) -> Option<(alloc::vec::Vec<u8>, RxCsumResult)> {
        if self.suspended.load(Ordering::Acquire) {
            return None;
        }
        self.receive_on_queue(0).map(|(buf, csum, _)| (buf, csum))
    }

    /// Pop one received frame off RX queue `q`, plus the chip's
    /// RX checksum verification result and — in RSS mode — the
    /// hardware Toeplitz hash (`rss_result`) that steered the
    /// frame to this queue (`None` in the single-queue case,
    /// where no hash exists). The hash has already done its
    /// steering work by the time the pump sees the frame (the
    /// queue identity IS the steering outcome), so pumps do not
    /// forward it; it is returned for diagnostics and future
    /// stack use. Out-of-range `q` yields `None`.
    pub fn receive_on_queue(
        &self,
        q: usize,
    ) -> Option<(alloc::vec::Vec<u8>, RxCsumResult, Option<u32>)> {
        let rxq = self.rx_queues.get(q)?;
        let rss = self.rx_queues.len() > 1;
        let mut head_g = rxq.head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let ring_phys = rxq.ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // Status word: word 0 in the legacy format, word 3
        // (rss_opts1) in the RSS format. Bit positions are
        // shared (see the RSS-format comment above).
        // SAFETY: identity-mapped DMA ring.
        let flags_len = unsafe {
            core::ptr::read_volatile(
                narf_memory::PhysAddr::new(if rss { desc_addr + 12 } else { desc_addr })
                    .kernel_ptr::<u32>(),
            )
        };
        if flags_len & RXD_OWN != 0 {
            return None;
        }

        // Decode the RX checksum result now, before rearming
        // overwrites the descriptor. The RSS format uses its
        // own TCPT/UDPT/TCPF/UDPF bits (see `rss_rx_csum`).
        let csum = if rss {
            rss_rx_csum(flags_len)
        } else {
            TxDesc {
                flags_len,
                vlan: 0,
                addr_lo: 0,
                addr_hi: 0,
            }
            .rx_csum_result()
        };

        // RSS hash: rss_result is word 1 of the RSS descriptor.
        // SAFETY: identity-mapped DMA ring.
        let hash = if rss {
            // SAFETY: identity-mapped DMA ring; slot is head mod
            // RING_LEN, so desc_addr + 4 is word 1 of a valid
            // 16-byte descriptor, and rss selects the RSS layout
            // whose word 1 is the steering hash.
            Some(unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 4).kernel_ptr::<u32>(),
                )
            })
        } else {
            None
        };

        let len = (flags_len & RXD_LEN_MASK) as usize;
        let buf_phys = rxq.pool[slot].dma_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(len.min(RX_BUF_LEN));
        if flags_len & RXD_LS != 0 {
            let copy_len = len.min(RX_BUF_LEN);
            for i in 0..copy_len {
                // SAFETY: this slot's RX DMA buffer is RX_BUF_LEN bytes
                // and `i < copy_len <= RX_BUF_LEN`.
                out.push(unsafe {
                    core::ptr::read_volatile(rxq.pool[slot].cpu_ptr_at::<u8>(i as u64))
                });
            }
        }

        // Rearm the descriptor.
        if rss {
            // RSS rearm, mirroring `mark_to_asic`: address words
            // + rss_opts2 = 0, fence, then rss_opts1 last (EOR
            // preserved from the descriptor being rearmed).
            // SAFETY: identity-mapped DMA ring; slot < RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<u32>(),
                    buf_phys as u32,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                    (buf_phys >> 32) as u32,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 8).kernel_mut_ptr::<u32>(),
                    0,
                );
            }
            compiler_fence(Ordering::SeqCst);
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 12).kernel_mut_ptr::<u32>(),
                    rss_rearm_opts1(flags_len),
                );
            }
        } else {
            let d = build_rx_desc(slot, buf_phys, RX_BUF_LEN as u32);
            // SAFETY: identity-mapped DMA ring; slot < RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<TxDesc>(),
                    d,
                )
            };
        }
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        Some((out, csum, hash))
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

    /// MAC version for MTU validation, via
    /// [`MacVersion::version_number`].
    fn mac_version_opt(&self) -> Option<u32> {
        self.mac_version.version_number()
    }

    /// Program a validated MTU switch on live hardware (Linux
    /// `rtl8169_change_mtu` shape for the 8125 family): the
    /// jumbo Config bits via `apply_jumbo_config` under the
    /// 9346CR unlock — a no-op for VER_61..80, where Linux's
    /// `rtl_jumbo_config` takes the default arm — and the EEE
    /// TX LPI idle timer via `apply_eee_txidle` (Linux's
    /// `rtl_set_eee_txidle_timer` VER_61..LAST arm writes
    /// `EEE_TXIDLE_TIMER_8125` = mtu + ETH_HLEN + 0x20; the
    /// only live register write in `change_mtu` for this
    /// family). RMS is NOT touched: it stays at the 16383
    /// buffer bound, which covers every MTU up to the version
    /// max, and Linux's change_mtu does not touch it either
    /// (`rtl_set_rx_max_size` runs at hw-start only). MTPS is
    /// NOT touched: the bring-up jumbo-max value already covers
    /// any MTU up to the version max, and Linux's change_mtu
    /// writes it only for VER_31..33. Rings are NOT resized:
    /// RX buffers (16383) and TX slots (16384) already cover
    /// the version max. Pause capabilities need phylink, which
    /// NARF does not have; PCIe read-request size is never
    /// programmed in-tree.
    fn program_mtu(&self, program: crate::features::MtuProgram) {
        // SAFETY: probe-time controller owns the BAR exclusively;
        // the hook runs on that same controller.
        unsafe {
            self.mmio.write8(REG_9346CR, EEM_CONFIG_WRITE);
            let mut regs = crate::features::MmioRegs(&self.mmio);
            crate::features::apply_jumbo_config(
                &mut regs,
                self.mac_version_opt().unwrap_or(0),
                program.jumbo,
            );
            crate::features::apply_eee_txidle(&mut regs, program.mtu);
            self.mmio.write8(REG_9346CR, EEM_NORMAL);
        }
    }

    /// Program the RSS steering registers for `queues` RX queues
    /// (key / indirection / control / queue-count / descriptor
    /// type, via `crate::features::apply_rss`).
    ///
    /// Bring-up already programs steering for multi-queue
    /// controllers (via `apply_rss` directly); this method
    /// re-programs steering on a live controller. It refuses
    /// to steer to queues that do not exist: `queues` above
    /// the live RX queue count is `UnsupportedOffload`, since
    /// those queues have no ring and no pump to drain them.
    pub fn configure_rss(&self, queues: usize) -> Result<(), NicError> {
        if queues > self.rx_queues.len() {
            return Err(NicError::UnsupportedOffload);
        }
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

    /// Suspend the device for system suspend (issue #793): mask
    /// interrupts, acknowledge pending causes, stop the TX/RX DMA
    /// engines via the shared `pm` plan, and publish link down. A
    /// second suspend is a no-op success. The PHY stays powered
    /// (its autoneg advertisement persists), and the descriptor
    /// rings persist — only the CR EN bits gate DMA.
    pub fn suspend(&self) -> Result<(), NicError> {
        if self.suspended.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        crate::pm::suspend_plan(&crate::pm::MmioBank::new(&self.mmio), crate::pm::IMR_WIDE);
        crate::publish::publish_link(self.ifname(), crate::publish::LinkSample::DOWN);
        Ok(())
    }

    /// Resume a suspended device (issue #793): re-kick the PHY so
    /// the link re-negotiates after the DMA stop, restore the DMA
    /// engines + interrupt mask via the shared `pm` plan, and
    /// republish link from live PHYStatus. Resuming a running
    /// device is a no-op success. The PHY re-kick is best-effort:
    /// a failed MDIO read leaves the advertisement as it was, and
    /// the link still comes back on its own.
    pub fn resume(&self) -> Result<(), NicError> {
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let phy = crate::phy_access::PhyAccess::new(&self.mmio);
        if let Ok(bmcr) = phy.phyar_read(crate::phy_access::MII_BMCR_REG) {
            if let Some(word) = crate::phy_access::bmcr_restart_value(bmcr) {
                let _ = phy.phyar_write(crate::phy_access::MII_BMCR_REG, word);
            }
        }
        crate::pm::resume_plan(
            &crate::pm::MmioBank::new(&self.mmio),
            crate::pm::IMR_WIDE,
            INT32_ROK | INT32_TOK | INT32_LINKCHG | INT32_RDU | INT32_TDU,
            self.irq_vector.is_some(),
        );
        self.suspended.store(false, Ordering::Release);
        crate::publish::publish_link(self.ifname(), rtl8127_link_sample(self.phy_status()));
        Ok(())
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

    // EEE PHY advertisement (#794; same shape as rtl8125): program
    // the emulated AN MMD advertisement registers for this chip's
    // LPI caps (MAC version 80 — the same value `eee_caps`
    // reports), then restart auto-negotiation iff the
    // advertisement changed so the link partner negotiates EEE
    // on the next exchange. This runs last so the advertisement
    // is the final PHY-page programming before the link is used.
    // A failure here is logged, not fatal: the interface still
    // works, just without EEE advertisement.
    let caps = crate::features::eee_lpi_caps(80);
    match access.advertise_eee(caps) {
        Ok(true) => match access.restart_aneg() {
            Ok(true) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8127: EEE advertisement programmed; autonegotiation restarted",
                );
            }
            Ok(false) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8127: EEE advertisement programmed; autonegotiation disabled, \
                     takes effect at the next autonegotiation",
                );
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  rtl8127: EEE advertisement programmed but autonegotiation restart \
                     failed: {:?}",
                    e
                );
            }
        },
        Ok(false) => {}
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  rtl8127: EEE advertisement failed: {:?}; link partner will not negotiate EEE",
                e
            );
        }
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
    // Every probed controller gets its PHY sequence, not just the
    // first: the hook runs once from a `Stage::Late` initcall and
    // each instance owns its own PHY. Take the `Arc`s and drop the
    // registry lock before touching any PHY: a firmware delay
    // opcode can spin for up to `MAX_FIRMWARE_DELAY_MS`, and
    // holding an IrqSafeSpinLock across that would stall every
    // other controller user.
    let controllers = CONTROLLERS.lock().clone();
    for controller in controllers {
        configure_phy(&controller.mmio);
    }
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

impl Rtl8127Nic {
    /// This instance's published interface name (`eth%d`), or `""`
    /// before probe publishes it. Per-instance state (i40e/igc
    /// pattern); the pumps and the registry adapter read the name
    /// off the device they serve, never a module-level static.
    pub fn ifname(&self) -> &'static str {
        self.ifname.get()
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Every probed controller, by probe order. The index is the cookie
/// the kernel-side stack's send path resolves through
/// [`rtl8127_send_frame`] — the i40e `CONTROLLERS` pattern, so a
/// second RTL8127 on the same machine probes, binds, and carries
/// traffic instead of being dropped by a singleton slot (issue
/// #1631). The vec never shrinks, so a live controller's cookie
/// stays valid for the kernel lifetime.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<Rtl8127Nic>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// `SendCtxFn` registered with `narf_net::iface` at probe time. Routes
/// the kernel-side TCP stack's outbound frames through
/// `Rtl8127Nic::transmit`; the cookie is the controller's index in
/// `CONTROLLERS`. The `Arc` is cloned out rather than holding the
/// IRQ-masking `CONTROLLERS` lock across `transmit` (same reasoning
/// as e1000's send path).
fn rtl8127_send_frame(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = controller(cookie as usize).ok_or(())?;
    ctrl.transmit(frame, &meta).map_err(|_| ())
}

/// Decode a PHYStatus byte into a publication sample via the family's
/// existing `PhyStatus::parse`. The ≥1G bit covers 1G/2.5G/5G/10G
/// alike on this part, so 1000 is published as the in-band lower
/// bound; exact negotiated-rate decode is
/// [`rtl8127_link_sample_with_phy`] (PHY work, issue #790).
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
        // PHYStatus reports no media state (link/speed/duplex/
        // flow-control only); no PHY-type code is read here
        // (issue #791).
        media_available: None,
        phy_type: None,
        phy_type_name: None,
    }
}

/// Resolve the exact negotiated rate via the shared PHY trait
/// (issue #790) when the in-band PHYStatus byte only proves
/// "≥1G" — on this part that covers 1G/2.5G/5G/10G alike.
/// 10/100 come straight from the byte — they are exact there —
/// and a down link never touches the PHY. The PHY read is the
/// `rtlgen` algorithm (`crate::phy::Phy` implemented by
/// `PhyAccess`): Clause-22 resolution plus the page 0xa43
/// register 0x12 speed word, merged over the in-band lower
/// bound so any PHY error (or an undecodable speed word) keeps
/// the byte's rate instead of inventing or dropping one. (The
/// RTL8127-internal PHY is the RTL8261C 10G PHY; it follows
/// the same `rtlgen` path as the 8125/8126 internal PHYs.)
///
/// A fresh `PhyAccess` per call is stateless (the trait impl
/// never touches the latched `ocp_base`), so this cannot divert
/// the config-table or firmware paths. Callers gate on the
/// PHYStatus byte changing (see queue 0's pump): the PHY read
/// runs on link transitions only, never on the per-pass hot path.
fn rtl8127_link_sample_with_phy(device: &Rtl8127Nic, status: u8) -> crate::publish::LinkSample {
    use crate::phy::Phy;
    let base = rtl8127_link_sample(status);
    if !base.carrier || !PhyStatus::parse(status).speed_1000m_or_above {
        return base;
    }
    let access = crate::phy_access::PhyAccess::new(&device.mmio);
    match access.read_status() {
        Ok(link) => crate::phy::merge_phy_sample(base, link),
        Err(_) => base,
    }
}

impl narf_power::device_pm::DevicePmOps for Rtl8127Nic {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.suspend()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.resume()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
}

/// Probe entry — installed via `bus::register_pci_driver`. A second
/// probe of the SAME function is a no-op success (the old idempotent
/// behaviour): the bus re-walks devices, and rebuilding a second
/// `Rtl8127Nic` for the same silicon would let two instances drive
/// one chip's rings. A second FUNCTION binds as a new instance
/// instead of being dropped (issue #1631).
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLERS.lock().iter().any(|c| c.addr == device.addr) {
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
    // exclusive `&mut` here needs no Arc-aliasing argument. The
    // mirror producer moves onto the NIC so every RX pump can
    // share it (the single-owner `Producer` cannot be cloned
    // into N pumps).
    *dev.rx_ipc_ring.lock() = Some(rx_cons);
    *dev.tx_ipc_ring.lock() = Some(tx_prod);
    *dev.rx_mirror.lock() = Some(rx_prod);

    // Best-effort MSI-X. A failure leaves the NIC on the polled path
    // the pumps already drive, so it is not fatal to the probe.
    // Multi-queue controllers attempt Linux's minimum vector
    // count (30) with a single-vector fallback; single-queue
    // controllers request one vector, as before.
    // SAFETY: caller-authority over the device's cfg space.
    let msix_want: u16 = if dev.rx_queues.len() > 1 { 30 } else { 1 };
    // SAFETY: probe owns the device's BAR + cfg windows
    // exclusively (enable_msix_vectors requires it); cap is the
    // MSI-X capability found during probe.
    let msix_ok = match unsafe { dev.enable_msix_vectors(&cap, &device, msix_want) } {
        Ok(_) => true,
        // SAFETY: same BAR + cfg exclusivity as the primary
        // attempt; single-vector fallback after it failed.
        Err(_) if msix_want > 1 => unsafe { dev.enable_msix_vectors(&cap, &device, 1) }.is_ok(),
        Err(_) => false,
    };
    if !msix_ok {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  rtl8127: MSI-X setup failed; continuing on the polled path"
        );
    }

    let dev = Arc::new(dev);

    // Retain before any ring DMA address reaches the device; the
    // index is this instance's send-path cookie (see `CONTROLLERS`).
    let index = {
        let mut g = CONTROLLERS.lock();
        g.push(dev.clone());
        g.len() - 1
    };

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

    // name + carrier metadata via the shared helper, keyed by the
    // `CONTROLLERS` index so each port's send path resolves to its
    // own NIC (i40e pattern). The frame-ring registration below stays.
    // The link sample is the PHY-exact decode (issue #790): the
    // in-band PHYStatus byte only proves "≥1G".
    let mac = dev.mac;
    let status = dev.phy_status();
    let name = crate::publish::publish_netdev_with_context(
        mac,
        index as u64,
        rtl8127_send_frame,
        rtl8127_link_sample_with_phy(&dev, status),
    );
    dev.ifname.set(name);

    // Device-PM registration (#793): system suspend fans out
    // through `suspend` / `resume` via the `DevicePmOps` impl
    // above. The registry is idempotent on the interface name.
    // There is no detach path to withdraw the entry from yet —
    // the CONTROLLER slot is never drained either, so the entry
    // lives as long as the device does.
    narf_power::device_pm::register_device_pm_ops(dev.ifname(), dev.clone());

    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(
            &auth,
            Rtl8127NicIface {
                nic: dev.clone(),
                name: "rtl8127",
            },
        );
    }

    // Runtime MTU switch (#1276): install the DeviceControl hook
    // so `try_set_mtu` validates + programs the switch instead
    // of only changing registry metadata, and publish the
    // initial (MTU 1500) offload advertisement. The stack reads
    // entry.offloads, and this driver never published one
    // before, so the stack ran software offload even at MTU
    // 1500 despite the driver's claimed Interface::offloads —
    // bind now publishes what the driver already claimed.
    if let Some(ctrl) = controller(index) {
        let name = ctrl.ifname();
        let _ = narf_net::iface::set_device_control(
            name,
            Arc::new(Rtl8127MtuControl {
                controller: ctrl.clone(),
                name,
            }),
        );
        let initial = crate::features::mtu_transition(ctrl.mac_version_opt(), 1500)
            .map(offloads_for_program)
            .unwrap_or(narf_net::OffloadCapabilities {
                tx_checksum: true,
                rx_checksum: true,
                max_tso_bytes: TX_BUF_LEN as u32,
                vlan_insert: true,
            });
        narf_net::iface::set_offloads(name, initial);
    }

    spawn_pumps(dev, tx_cons);

    Ok(())
}

fn spawn_pumps(device: Arc<Rtl8127Nic>, tx_cons: Consumer<Frame, TX_RING_N>) {
    // One RX pump per queue; every pump fans into the single
    // mirror producer installed on the NIC by `probe`. Queue 0
    // keeps the link-sample duty; the other pumps drain only.
    for q in 0..device.rx_queues.len() {
        let d = device.clone();
        narf_scheduler::spawn(async move {
            rtl8127_rx_pump(d, q).await;
        });
    }
    let d2 = device;
    narf_scheduler::spawn(async move {
        rtl8127_tx_pump(d2, tx_cons).await;
    });
}

async fn rtl8127_rx_pump(device: Arc<Rtl8127Nic>, queue: usize) {
    // Carrier refresh (issue #791): the production datapath is polled
    // (the pumps are polled, so the LinkChg bit in the ISR has no
    // consumer), which makes queue 0's pump the family's link
    // observer. Other queues' pumps drain only.
    // `phy_status()` is an `&self` MMIO read — unlike
    // `refresh_link_state(&mut self)`, it is safe to call while pumps
    // hold Arc clones. A transition republishes the iface metadata;
    // the cached `Interface::link_up` snapshot is left as-is.
    // The PHYStatus byte gates the PHY read (see
    // `rtl8127_link_sample_with_phy`): the exact-rate decode
    // runs only when the byte changes, so the per-pass hot path
    // stays one MMIO byte read, as before.
    let mut last_status = device.phy_status();
    let mut last_sample = rtl8127_link_sample_with_phy(&device, last_status);
    loop {
        if queue == 0 {
            let status = device.phy_status();
            if status != last_status {
                last_status = status;
                let sample = rtl8127_link_sample_with_phy(&device, status);
                if sample != last_sample {
                    last_sample = sample;
                    crate::publish::publish_link(device.ifname(), sample);
                }
            }
        }
        if let Some((pkt, csum, _hash)) = device.receive_on_queue(queue) {
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
            let name = device.ifname();
            crate::publish::dispatch_rx(
                name,
                &mut frame,
                crate::publish::rx_mirror_attached(name),
                |mirror| {
                    let mut g = device.rx_mirror.lock();
                    if let Some(p) = g.as_mut() {
                        let _ = p.try_send(mirror);
                    }
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

/// Number of probed controllers (issue #1631).
pub fn instance_count() -> usize {
    CONTROLLERS.lock().len()
}

/// `true` once at least one controller has been probed.
pub fn is_probed() -> bool {
    !CONTROLLERS.lock().is_empty()
}

/// The probed controller at `index`, if it exists. The index is the
/// cookie probe assigned (see `CONTROLLERS`); it is stable for the
/// kernel lifetime because the vec never shrinks.
pub fn controller(index: usize) -> Option<Arc<Rtl8127Nic>> {
    CONTROLLERS.lock().get(index).cloned()
}

/// Test-side accessor: run `f` against the probed controller at
/// `index` (i40e shape).
pub fn with_controller<R>(index: usize, f: impl FnOnce(&Rtl8127Nic) -> R) -> Option<R> {
    CONTROLLERS.lock().get(index).map(|a| f(a))
}

/// Mutable accessor for tests.
pub fn with_controller_mut<R>(index: usize, f: impl FnOnce(&mut Rtl8127Nic) -> R) -> Option<R> {
    CONTROLLERS
        .lock()
        .get_mut(index)
        .map(|a| f(Arc::get_mut(a).expect("Rtl8127Nic static has multiple owners")))
}

/// One probed port, as the net stack sees it.
///
/// This owns its `Arc<Rtl8127Nic>` rather than looking the controller
/// up in a module-level static. That is what makes multiple ports
/// work: `Interface::rx_ring` / `tx_ring` return references borrowed
/// from `&self`, so an interface with no storage of its own has to
/// hand back a `static` — and every instance would then share one
/// pair of rings, with the second port's frames landing in the first
/// port's queue (i40e's `I40eNicIface` pattern).
#[derive(Debug)]
pub struct Rtl8127NicIface {
    /// This port's controller; the rings are borrowed out of it.
    nic: Arc<Rtl8127Nic>,
    /// Pre-publish fallback name, used by [`narf_net::Interface::name`]
    /// before probe publishes the dynamic `eth%d` name.
    name: &'static str,
}

/// `OffloadCapabilities` matching a validated MTU program: TX
/// checksum + TSO follow the program; RX checksum and VLAN
/// insertion are never touched by Linux's `fix_features` rules
/// and stay advertised.
fn offloads_for_program(program: crate::features::MtuProgram) -> narf_net::OffloadCapabilities {
    narf_net::OffloadCapabilities {
        tx_checksum: program.tx_checksum,
        rx_checksum: true,
        max_tso_bytes: if program.tso { TX_BUF_LEN as u32 } else { 0 },
        vlan_insert: true,
    }
}

/// Current (TX checksum, TSO) advertisement for `nic`, derived from
/// its programmed MTU (Linux `rtl8169_fix_features` rules, via
/// `features::mtu_transition`). A stored MTU that somehow fails
/// validation withdraws TX offload (fail-closed — unreachable, since
/// the hook only stores validated values).
fn current_tx_offloads(nic: &Rtl8127Nic) -> (bool, bool) {
    let mtu = *nic.mtu.lock();
    crate::features::mtu_transition(nic.mac_version_opt(), mtu)
        .map(|p| (p.tx_checksum, p.tso))
        .unwrap_or((false, false))
}

/// Linux `EINVAL` for a rejected MTU (see `netlink_route.rs`).
const EINVAL: i32 = 22;

/// `iface::DeviceControl` for the RTL8127 family: a proposed MTU
/// change validates against the version range, programs the
/// hardware switch, and republishes the offload advertisement
/// so it always matches the programmed hardware. Any other
/// metadata change passes through untouched (same MTU ⇒
/// no-op Ok), and a rejected MTU leaves registry metadata
/// unchanged (the `configure_device` contract: the hook runs
/// before commit). The hook compares against the controller's
/// programmed MTU, not the registry's, so a commit that lost a
/// race to a rebind self-heals on the next `try_set_mtu` to
/// the same value.
#[derive(Debug)]
pub struct Rtl8127MtuControl {
    controller: Arc<Rtl8127Nic>,
    name: &'static str,
}

impl narf_net::iface::DeviceControl for Rtl8127MtuControl {
    fn configure(&self, config: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        if config.mtu == *self.controller.mtu.lock() {
            return Ok(());
        }
        let program =
            crate::features::mtu_transition(self.controller.mac_version_opt(), config.mtu)
                .map_err(|_| EINVAL)?;
        self.controller.program_mtu(program);
        *self.controller.mtu.lock() = program.mtu;
        narf_net::iface::set_offloads(self.name, offloads_for_program(program));
        Ok(())
    }
}

impl narf_net::Interface for Rtl8127NicIface {
    fn name(&self) -> &str {
        // The dynamic `eth%d` name once published (issue #784); the
        // family name before probe gets that far.
        let n = self.nic.ifname();
        if n.is_empty() {
            self.name
        } else {
            n
        }
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        *self.nic.mtu.lock()
    }
    fn link_up(&self) -> bool {
        self.nic.link_up
    }
    fn num_rx_queues(&self) -> u16 {
        self.nic.rx_queues.len() as u16
    }
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        self.nic.rss_config.clone()
    }
    fn queue_affinity(&self, q: u16) -> narf_net::rss::QueueAffinity {
        // Intended pump placement: queue q on core q, on its
        // MSI-X vector when one was programmed for it. Spawns
        // are currently unpinned and the pumps are polled, so
        // this is advisory until IRQ-driven pumps land. The
        // default (boot CPU, no vector) covers the single-queue
        // case and the no-controller-yet case.
        narf_net::rss::QueueAffinity {
            core: q as u32,
            irq: self.nic.irq_vectors.get(q as usize).copied(),
        }
    }
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        // The TSO byte cap is the TX slot buffer: a TSO packet is
        // one frame copied into one slot. RSS has no offload
        // field (`OffloadCapabilities` carries checksum / TSO /
        // VLAN only); it is advertised via `NicCaps::RSS` in
        // `caps` and the live config in `rss` above. TX offload
        // follows the programmed MTU (#1276); RX checksum + VLAN
        // insertion are never withdrawn by the fix_features rules.
        let mtu = *self.nic.mtu.lock();
        crate::features::mtu_transition(self.nic.mac_version_opt(), mtu)
            .map(offloads_for_program)
            .unwrap_or(narf_net::OffloadCapabilities {
                tx_checksum: false,
                rx_checksum: true,
                max_tso_bytes: 0,
                vlan_insert: true,
            })
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        // Ring consumer attached: enable the RX mirror (e1000's
        // `rx_mirror_enabled` moment), keyed by this port's own
        // published name.
        crate::publish::note_rx_mirror_attached(self.nic.ifname());
        &self.nic.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.nic.tx_ipc_ring
    }
}

impl crate::HwNic for Rtl8127NicIface {
    fn name(&self) -> &'static str {
        let n = self.nic.ifname();
        if n.is_empty() {
            self.name
        } else {
            n
        }
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        *self.nic.mtu.lock()
    }
    fn link_up(&self) -> bool {
        self.nic.link_up
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::RealtekRtl8168
    }
    fn caps(&self) -> crate::NicCaps {
        let (tx_checksum, tso) = current_tx_offloads(&self.nic);
        let mut caps = crate::NicCaps::RX_CSUM | crate::NicCaps::VLAN_TAGGING;
        if tx_checksum {
            caps = caps | crate::NicCaps::TX_CSUM;
        }
        if tso {
            caps = caps | crate::NicCaps::TSO;
        }
        // RSS only when the live controller actually runs
        // multiple RX queues; a single-queue controller (or no
        // controller yet) does not advertise it.
        if self.nic.rx_queues.len() > 1 {
            caps = caps | crate::NicCaps::RSS;
        }
        caps
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
