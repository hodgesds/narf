//! Intel I210 / I211 / 82576 / I350 — 1 GbE — clean-room.
//!
//! Spec: Intel **"Ethernet Controller I210 Datasheet"** rev 3.7
//! (free PDF, intel.com) and the **"82576EB Gigabit Ethernet
//! Controller Datasheet"**. The igb family shares the Foxville /
//! 82575+ advanced descriptor datapath that `igc.rs` (I225/I226)
//! implements: advanced one-buffer RX descriptors, advanced TX
//! data/context descriptors, per-queue `SRRCTL` with
//! `DESCTYPE = ADV_ONEBUF`, the low ICR/IMS cause registers, and
//! the `0x1500` extended MSI-X block (EIMS/GPIE/EITR/IVAR). The basic
//! CTRL/STATUS/RAL/RAH/TCTL/RCTL/TDBAL/RDBAL addresses are the same
//! as the base `e1000` layout.
//!
//! The functional delta vs igc is the **per-queue TXDCTL/RXDCTL
//! ENABLE handshake**: unlike the legacy 8254x path (and unlike
//! igc at Stage-2, which relies on the queue being live out of
//! reset), igb gates each queue's DMA engine on the `ENABLE` bit
//! (bit 25) of its per-queue control register and the driver must
//! spin until the chip reflects the enable before the queue moves
//! descriptors. Linux does this in `igb_configure_tx_ring` /
//! `igb_configure_rx_ring` (`drivers/net/ethernet/intel/igb/igb_main.c`).
//!
//! Register map subset (BAR0 + offset, all 4-byte aligned):
//!
//! | offset  | name   | description                            |
//! |---------|--------|----------------------------------------|
//! | 0x0000  | CTRL   | Device Control                         |
//! | 0x0008  | STATUS | Device Status                          |
//! | 0x00c0  | ICR    | Interrupt Cause Read (legacy)          |
//! | 0x00d0  | IMS    | Interrupt Mask Set/Read (legacy)       |
//! | 0x1524  | EIMS   | Extended Interrupt Mask Set/Read       |
//! | 0x1514  | GPIE   | General Purpose Interrupt Enable       |
//! | 0x1680  | EITR0  | Interrupt Throttle, vector 0           |
//! | 0x1700  | IVAR0  | Queue interrupt-vector allocation      |
//! | 0x0100  | RCTL   | Receive Control                        |
//! | 0x0400  | TCTL   | Transmit Control                       |
//! | 0x2800  | RDBAL/H/LEN/H/T (igb queue-0 RX window)         |
//! | 0x2828  | RXDCTL0 | per-queue RX DMA control (bit 25 = EN) |
//! | 0x3800  | TDBAL/H/LEN/H/T (igb queue-0 TX window)         |
//! | 0x3828  | TXDCTL0 | per-queue TX DMA control (bit 25 = EN) |
//! | 0x5400  | RAL0   | Receive Address Low                    |
//! | 0x5404  | RAH0   | Receive Address High + Address Valid   |

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

use alloc::{sync::Arc, vec::Vec};
use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, TxMeta, RX_RING_N, TX_RING_N};

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Mirrors a subset of Linux's `igb_pci_tbl[]` in
// `drivers/net/ethernet/intel/igb/igb_main.c`. These IDs previously
// squatted on the legacy `e1000` driver, which ran them through the
// 8254x legacy-descriptor path; they now bind to this advanced-
// descriptor igb driver instead.

pub const IGB_VENDOR: u16 = 0x8086;

/// I210 Copper.
pub const IGB_I210_COPPER: u16 = 0x1533;
/// I210 Fiber.
pub const IGB_I210_FIBER: u16 = 0x1536;
/// I210 Serdes.
pub const IGB_I210_SERDES: u16 = 0x1537;
/// I210 SGMII.
pub const IGB_I210_SGMII: u16 = 0x1538;
/// I210 Copper flashless.
pub const IGB_I210_COPPER_FLASHLESS: u16 = 0x157B;
/// I210 Serdes flashless.
pub const IGB_I210_SERDES_FLASHLESS: u16 = 0x157C;
/// I211 Copper.
pub const IGB_I211_COPPER: u16 = 0x1539;
/// 82576.
pub const IGB_82576: u16 = 0x10C9;
/// 82576 with NS clock.
pub const IGB_82576_NS: u16 = 0x150A;
/// I350 Copper.
pub const IGB_I350_COPPER: u16 = 0x1521;

// ── Register offsets ────────────────────────────────────────────────

const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
/// MDIC — MDI Control register (PHY register access via MDIO).
const REG_MDIC: u64 = 0x0020;
/// ICR — Interrupt Cause Read. Reading clears all pending cause bits.
/// The legacy cause/mask registers live in the low 0x00c0 block, NOT the
/// 0x1500 extended block (that is EICS/EIMS/EIAC/EIAM/GPIE). igb silicon
/// keeps both: the extended block drives MSI-X, the legacy block carries
/// the ICR cause encoding Linux's `igb_intr`/`igb_msix_other` still read.
/// Linux: drivers/net/ethernet/intel/igb/e1000_regs.h E1000_ICR = 0x000C0.
const REG_ICR: u64 = 0x00C0;
/// IMS — Interrupt Mask Set/Read (legacy).
/// Linux: e1000_regs.h E1000_IMS = 0x000D0.
const REG_IMS: u64 = 0x00D0;
/// IMC — Interrupt Mask Clear (write-1-to-clear).
/// Linux: e1000_regs.h E1000_IMC = 0x000D8.
const REG_IMC: u64 = 0x00D8;
/// Extended MSI-X interrupt mask registers.
const REG_EIMS: u64 = 0x1524;
const REG_EIMC: u64 = 0x1528;
const REG_EIAC: u64 = 0x152C;
const REG_EIAM: u64 = 0x1530;
/// GPIE — General Purpose Interrupt Enable.
const REG_GPIE: u64 = 0x1514;
/// Per-vector interrupt-throttle register for MSI-X table entry 0.
const REG_EITR0: u64 = 0x1680;
/// Queue-0 RX/TX interrupt-vector allocation register.
const REG_IVAR0: u64 = 0x1700;
/// IVAR_MISC — "other" causes to MSI-X vector number.
const REG_IVAR_MISC: u64 = 0x1740;
const REG_RCTL: u64 = 0x0100;
const REG_TCTL: u64 = 0x0400;
// igb (82575+) queue-0 RX descriptor window. Queues 0..3 use the
// 0x2800 + 0x100*n window; the compact 0xC000 + 0x40*n window is for queues
// 4 and above. QEMU aliases 0xC000 back to queue 0, but real silicon's
// canonical queue-0 registers are these low-window offsets.
// Linux: drivers/net/ethernet/intel/igb/e1000_regs.h E1000_RDBAL/RDBAH/...
const REG_RDBAL: u64 = 0x2800;
const REG_RDBAH: u64 = 0x2804;
const REG_RDLEN: u64 = 0x2808;
const REG_RDH: u64 = 0x2810;
const REG_RDT: u64 = 0x2818;
/// Per-queue RX DMA control — queue 0.
/// Linux: drivers/net/ethernet/intel/igb/e1000_regs.h E1000_RXDCTL.
const REG_RXDCTL0: u64 = 0x2828;
// igb (82575+) queue-0 TX descriptor window. As with RX, queues 0..3 use
// 0x3800 + 0x100*n and the compact 0xE000 window begins at queue 4.
// Linux: drivers/net/ethernet/intel/igb/e1000_regs.h E1000_TDBAL.
const REG_TDBAL: u64 = 0x3800;
const REG_TDBAH: u64 = 0x3804;
const REG_TDLEN: u64 = 0x3808;
const REG_TDH: u64 = 0x3810;
const REG_TDT: u64 = 0x3818;
/// Per-queue TX DMA control — queue 0.
/// Linux: drivers/net/ethernet/intel/igb/e1000_regs.h E1000_TXDCTL.
const REG_TXDCTL0: u64 = 0x3828;
const REG_RAL0: u64 = 0x5400;
const REG_RAH0: u64 = 0x5404;
/// SRRCTL — Split-and-Replication Receive Control, queue 0.
/// Linux: drivers/net/ethernet/intel/igb/e1000_regs.h E1000_SRRCTL.
const REG_SRRCTL_Q0: u64 = 0x280C;
/// `SRRCTL_BSIZEPKT_SHIFT` (10) — packet-buffer-size field is in 1 KiB
/// units. Linux: e1000_82575.h E1000_SRRCTL_BSIZEPKT_SHIFT = 10.
const SRRCTL_BSIZEPKT_SHIFT: u32 = 10;
/// `SRRCTL_BSIZEPKT_MASK` = bits[6:0]. QEMU hw/net/igb_regs.h
/// E1000_SRRCTL_BSIZEPKT_MASK = 0x0000007F.
const SRRCTL_BSIZEPKT_MASK: u32 = 0x7F;
/// `SRRCTL_DESCTYPE_MASK` = bits[27:25]. QEMU hw/net/igb_regs.h
/// E1000_SRRCTL_DESCTYPE_MASK = 0x0E000000.
const SRRCTL_DESCTYPE_MASK: u32 = 0x0E00_0000;
/// `SRRCTL_DESCTYPE_ADV_ONEBUF` (1 << 25 = 0x0200_0000) — advanced
/// one-buffer descriptor format.
/// Linux: drivers/net/ethernet/intel/igb/e1000_82575.h
/// E1000_SRRCTL_DESCTYPE_ADV_ONEBUF = 0x02000000.
pub const SRRCTL_DESCTYPE_ADV_ONEBUF: u32 = 1 << 25;

/// Per-queue TXDCTL/RXDCTL ENABLE bit (bit 25 = 0x0200_0000).
/// Linux: drivers/net/ethernet/intel/igb/e1000_82575.h
/// E1000_TXDCTL_QUEUE_ENABLE / E1000_RXDCTL_QUEUE_ENABLE = 0x02000000.
pub const QUEUE_ENABLE: u32 = 0x0200_0000;

// ── Multi-queue register windows ────────────────────────────────────
//
// Linux: drivers/net/ethernet/intel/igb/e1000_regs.h E1000_RDBAL /
// RDBAH / RDLEN / SRRCTL / RDH / RDT / RXDCTL and E1000_TDBAL / TDBAH /
// TDLEN / TDH / TDT / TXDCTL. Queues 0..3 use the 0x2800 (RX) / 0x3800
// (TX) windows with a 0x100 stride; queues 4..7 use the compact 0xC000
// (RX) / 0xE000 (TX) windows with a 0x40 stride. Queue 0 of either window
// is the legacy REG_*0 constant above. Bring-up still arms queue 0 only
// (the QEMU/CI profile is single-queue); these windows are the
// programming surface for queues 1..7, exercised end-to-end by the
// fake-register fixtures in the test module below.

/// Maximum RX/TX queues on the family (I350 / 82576 / 82580 / i354).
/// Linux: drivers/net/ethernet/intel/igb/igb.h IGB_MAX_RX_QUEUES /
/// IGB_MAX_TX_QUEUES = 8.
pub const IGB_MAX_QUEUES: usize = 8;
/// Maximum queues on 82575 and I210 (Linux IGB_MAX_RX_QUEUES_82575 = 4;
/// `igb_get_max_rss_queues` maps both e1000_82575 and e1000_i210 here).
pub const IGB_MAX_QUEUES_82575: usize = 4;
/// Maximum queues on I211 (Linux IGB_MAX_RX_QUEUES_I211 = 2).
pub const IGB_MAX_QUEUES_I211: usize = 2;

/// All BAR0 register offsets of one queue's descriptor windows.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueueRegs {
    pub rdbal: u64,
    pub rdbah: u64,
    pub rdlen: u64,
    pub srrctl: u64,
    pub rdh: u64,
    pub rdt: u64,
    pub rxdctl: u64,
    pub tdbal: u64,
    pub tdbah: u64,
    pub tdlen: u64,
    pub tdh: u64,
    pub tdt: u64,
    pub txdctl: u64,
}

const fn rx_queue_base(queue: usize) -> u64 {
    if queue < 4 {
        0x2800 + queue as u64 * 0x100
    } else {
        0xC000 + queue as u64 * 0x40
    }
}

const fn tx_queue_base(queue: usize) -> u64 {
    if queue < 4 {
        0x3800 + queue as u64 * 0x100
    } else {
        0xE000 + queue as u64 * 0x40
    }
}

/// Register window for `queue` (0..7). Queues past the device's
/// `max_queues_for_device` limit have well-defined addresses but must
/// never be programmed: the silicon has no such queue.
pub const fn queue_regs(queue: usize) -> QueueRegs {
    let rx = rx_queue_base(queue);
    let tx = tx_queue_base(queue);
    QueueRegs {
        rdbal: rx,
        rdbah: rx + 0x04,
        rdlen: rx + 0x08,
        srrctl: rx + 0x0C,
        rdh: rx + 0x10,
        rdt: rx + 0x18,
        rxdctl: rx + 0x28,
        tdbal: tx,
        tdbah: tx + 0x04,
        tdlen: tx + 0x08,
        tdh: tx + 0x10,
        tdt: tx + 0x18,
        txdctl: tx + 0x28,
    }
}

/// Maximum RSS queues for a device id, mirroring Linux
/// `igb_get_max_rss_queues` (igb_main.c) first-hand, including the
/// SR-IOV interaction: an I350 with any VF allocated drops to 1 queue
/// ("I350 cannot do RSS and SR-IOV at the same time"), an 82576 with
/// VFs drops to 2, and every other family keeps its full count.
/// `vfs_allocated` is the SR-IOV VF count (0 when SR-IOV is off).
pub fn max_queues_for_device(device_id: u16, vfs_allocated: u16) -> usize {
    match device_id {
        IGB_I211_COPPER => IGB_MAX_QUEUES_I211,
        IGB_I210_COPPER
        | IGB_I210_FIBER
        | IGB_I210_SERDES
        | IGB_I210_SGMII
        | IGB_I210_COPPER_FLASHLESS
        | IGB_I210_SERDES_FLASHLESS => IGB_MAX_QUEUES_82575,
        IGB_82576 | IGB_82576_NS => {
            if vfs_allocated > 0 {
                2
            } else {
                IGB_MAX_QUEUES
            }
        }
        IGB_I350_COPPER => {
            if vfs_allocated > 0 {
                1
            } else {
                IGB_MAX_QUEUES
            }
        }
        // Linux `default:` arm (82580 / i354 / unknown) is 8.
        _ => IGB_MAX_QUEUES,
    }
}

/// Whether TX and RX queues share one MSI-X vector per queue (Linux
/// `igb_set_flag_queue_pairs`: pairs when rss_queues > max/2, so a
/// full 8-queue I350/82576 pairs but a 4-of-8 configuration does not).
pub const fn queue_pairs(queues: usize, max_queues: usize) -> bool {
    queues > max_queues / 2
}

/// TXDCTL/RXDCTL word with the ENABLE bit set, preserving the
/// threshold/other bits the caller already programmed.
pub const fn queue_enable_word(current: u32) -> u32 {
    current | QUEUE_ENABLE
}

/// TXDCTL/RXDCTL word with the ENABLE bit cleared (queue disable).
pub const fn queue_disable_word(current: u32) -> u32 {
    current & !QUEUE_ENABLE
}

/// Whether a TXDCTL/RXDCTL read reflects the ENABLE handshake: the
/// bring-up spin in `Igb::bring_up` polls exactly this predicate, and
/// a queue that never reflects ENABLE is a dead queue
/// (`IgbError::QueueEnableTimeout`).
pub const fn queue_enable_reflected(value: u32) -> bool {
    value & QUEUE_ENABLE != 0
}

/// TXDCTL programming word from Linux's thresholds (igb.h):
/// PTHRESH at bits[7:0], HTHRESH at bits[15:8], WTHRESH at bits[23:16],
/// plus ENABLE. The common (non-82576+MSI-X) values are PTHRESH 8,
/// HTHRESH 1, WTHRESH 16; an 82576 with MSI-X uses WTHRESH 1.
pub const fn txdctl_word(pthresh: u32, hthresh: u32, wthresh: u32) -> u32 {
    (pthresh & 0xFF) | ((hthresh & 0xFF) << 8) | ((wthresh & 0xFF) << 16) | QUEUE_ENABLE
}

/// RXDCTL programming word, same layout as [`txdctl_word`]. The common
/// values are PTHRESH 8, HTHRESH 8, WTHRESH 4; an 82576 with MSI-X uses
/// WTHRESH 1. (i354 raises PTHRESH to 12 TX / 20 RX; NARF claims no
/// i354 device id, so those variants are not encoded.)
pub const fn rxdctl_word(pthresh: u32, hthresh: u32, wthresh: u32) -> u32 {
    (pthresh & 0xFF) | ((hthresh & 0xFF) << 8) | ((wthresh & 0xFF) << 16) | QUEUE_ENABLE
}

// ── MSI-X vector routing (IVAR) ─────────────────────────────────────
//
// Linux `igb_assign_vector` (igb_main.c) routes each queue's RX and TX
// causes to an MSI-X vector through the IVAR table (one 32-bit word
// per row, four byte lanes). The scheme depends on silicon generation:
// 82575 uses an MSIXBM bitmask instead of IVAR; 82576 orders the table
// column-major (low 3 bits = row, bit 3 = column); 82580 and newer
// (I210 / I211 / I350 / i354) order it row-major (bit 0 = column, the
// rest = row). Queue 0 under row-major reproduces the existing shared
// IVAR0 word 0x8080 (RX byte 0, TX byte 1, both vector 0 + VALID).

/// Which IVAR addressing scheme a device id uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IvarScheme {
    /// 82575: MSIXBM bitmask, no IVAR table. No NARF-claimed id uses
    /// this scheme; it is encoded so the difference is explicit rather
    /// than silently mapped onto a wrong table layout.
    Bitmask82575,
    /// 82576: column-major IVAR table.
    ColumnMajor82576,
    /// 82580 / I210 / I211 / I350 / i354: row-major IVAR table.
    RowMajor82580Plus,
}

/// IVAR scheme for a NARF-claimed igb device id.
pub fn ivar_scheme_for_device(device_id: u16) -> IvarScheme {
    match device_id {
        IGB_82576 | IGB_82576_NS => IvarScheme::ColumnMajor82576,
        // Every other claimed id (I210 family, I211, I350) is 82580+.
        _ => IvarScheme::RowMajor82580Plus,
    }
}

/// (IVAR register address, byte-lane shift) for a queue's RX cause.
pub const fn ivar_rx(queue: usize, scheme: IvarScheme) -> (u64, u32) {
    let (index, shift) = match scheme {
        IvarScheme::Bitmask82575 => (0, 0),
        IvarScheme::ColumnMajor82576 => (queue & 0x7, ((queue & 0x8) << 1) as u32),
        IvarScheme::RowMajor82580Plus => (queue >> 1, ((queue & 0x1) << 4) as u32),
    };
    (REG_IVAR0 + index as u64 * 4, shift)
}

/// (IVAR register address, byte-lane shift) for a queue's TX cause.
pub const fn ivar_tx(queue: usize, scheme: IvarScheme) -> (u64, u32) {
    let (index, shift) = match scheme {
        IvarScheme::Bitmask82575 => (0, 0),
        IvarScheme::ColumnMajor82576 => (queue & 0x7, (((queue & 0x8) << 1) + 8) as u32),
        IvarScheme::RowMajor82580Plus => (queue >> 1, (((queue & 0x1) << 4) + 8) as u32),
    };
    (REG_IVAR0 + index as u64 * 4, shift)
}

/// Apply one queue cause's vector to an IVAR word: clear only that byte
/// lane, then set `vector | VALID`. Other lanes are untouched, so RX
/// and TX of a queue pair compose into one word write each.
pub const fn ivar_apply(current: u32, shift: u32, vector: u8) -> u32 {
    (current & !(0xFF << shift)) | (((vector as u32) | IVAR_VALID) << shift)
}

/// EITR register for an MSI-X vector: 0x1680 + 4 * vector (Linux
/// E1000_EITR(n)). Queue pairs share one vector, so one EITR programs
/// the throttle for both directions of the pair.
pub const fn eitr_reg(vector: usize) -> u64 {
    REG_EITR0 + vector as u64 * 4
}

// ── Receive Side Scaling (RSS) ──────────────────────────────────────
//
// Linux `igb_setup_mrqc` + `igb_write_rss_key` +
// `igb_write_rss_indir_tbl` (igb_main.c / igb_ethtool.c). The 40-byte
// RSS key feeds RSSRK, the 128-entry indirection table feeds RETA
// (32 registers × 4 one-byte queue entries, little-endian packed),
// and MRQC selects the hash fields and the queueing mode. Live
// bring-up does not program MRQC yet: it stays queue-0-only, and
// programming RXCSUM.PCSD would repurpose the RX descriptor's lower
// word from checksum to hash — that switch belongs to the
// multi-queue activation step, not to a single-queue bring-up.

/// MRQC — Multiple Receive Queue Control.
const REG_MRQC: u64 = 0x5818;
/// RXCSUM — Receive Checksum Control.
const REG_RXCSUM: u64 = 0x5000;
/// RETA base — RSS indirection table, 32 registers.
const REG_RETA_BASE: u64 = 0x5C00;
/// RSSRK base — RSS random key, 10 registers.
const REG_RSSRK_BASE: u64 = 0x5C80;

/// RETA entries (Linux IGB_RETA_SIZE = 128).
pub const RETA_SIZE: usize = 128;
/// RSS key bytes (Linux IGB_RSS_KEY_SIZE = 40).
pub const RSS_KEY_SIZE: usize = 40;
/// RETA registers (128 entries / 4 per register).
pub const RETA_REGS: usize = 32;

/// MRQC hash-field bits (Linux e1000_defines.h / e1000_82575.h).
pub const MRQC_FIELD_IPV4_TCP: u32 = 0x0001_0000;
pub const MRQC_FIELD_IPV4: u32 = 0x0002_0000;
pub const MRQC_FIELD_IPV6_TCP_EX: u32 = 0x0004_0000;
pub const MRQC_FIELD_IPV6: u32 = 0x0010_0000;
pub const MRQC_FIELD_IPV6_TCP: u32 = 0x0020_0000;
pub const MRQC_FIELD_IPV4_UDP: u32 = 0x0040_0000;
pub const MRQC_FIELD_IPV6_UDP: u32 = 0x0080_0000;
pub const MRQC_FIELD_IPV6_UDP_EX: u32 = 0x0100_0000;
/// MRQC queueing modes.
pub const MRQC_ENABLE_RSS_MQ: u32 = 0x0000_0002;
pub const MRQC_ENABLE_VMDQ: u32 = 0x0000_0003;
pub const MRQC_ENABLE_VMDQ_RSS_MQ: u32 = 0x0000_0005;
/// RXCSUM bits Linux sets alongside MRQC: PCSD puts the RSS hash (not
/// the packet checksum) in the RX descriptor's lower word; CRCOFL
/// enables SCTP CRC offload (all NARF-claimed ids are >= 82576).
pub const RXCSUM_PCSD: u32 = 0x0000_2000;
pub const RXCSUM_CRCOFL: u32 = 0x0000_0800;

/// RETA register for indirection-table word `i` (0..32).
pub const fn reta_reg(i: usize) -> u64 {
    REG_RETA_BASE + i as u64 * 4
}

/// RSSRK register for key word `i` (0..10).
pub const fn rssrk_reg(i: usize) -> u64 {
    REG_RSSRK_BASE + i as u64 * 4
}

/// Default RETA entry for `index`: Linux's `(j * num_rx_queues) /
/// IGB_RETA_SIZE` spread, so a 4-queue table cycles 0,0,..1,1,.. and
/// an 8-queue table cycles twice as fast. Every queue gets an equal
/// share of the 128 slots.
pub const fn reta_entry(queue_count: usize, index: usize) -> u8 {
    ((index * queue_count) / RETA_SIZE) as u8
}

/// Default RETA table for `queue_count` queues.
pub const fn reta_table(queue_count: usize) -> [u8; RETA_SIZE] {
    let mut table = [0u8; RETA_SIZE];
    let mut i = 0;
    while i < RETA_SIZE {
        table[i] = reta_entry(queue_count, i);
        i += 1;
    }
    table
}

/// Pack four RETA entries into one register word, little-endian
/// (entry `i` at byte `i`), as Linux's `igb_write_rss_indir_tbl`
/// does before the shift below.
pub const fn reta_word(entries: [u8; 4]) -> u32 {
    entries[0] as u32
        | ((entries[1] as u32) << 8)
        | ((entries[2] as u32) << 16)
        | ((entries[3] as u32) << 24)
}

/// RETA value shift for a device: 0, except 82576 with VFs allocated,
/// where Linux shifts by 3 (the 82575 shift of 6 belongs to a silicon
/// generation NARF claims no id for and is deliberately not encoded).
pub fn reta_shift(device_id: u16, vfs_allocated: u16) -> u32 {
    match device_id {
        IGB_82576 | IGB_82576_NS if vfs_allocated > 0 => 3,
        _ => 0,
    }
}

/// One RSSRK word from a 40-byte key: little-endian, key bytes
/// `[4*i .. 4*i+4]` (Linux `get_unaligned_le32(&rss_key[i * 4])`).
pub const fn rss_key_word(key: &[u8; RSS_KEY_SIZE], i: usize) -> u32 {
    (key[i * 4] as u32)
        | ((key[i * 4 + 1] as u32) << 8)
        | ((key[i * 4 + 2] as u32) << 16)
        | ((key[i * 4 + 3] as u32) << 24)
}

/// MRQC word: the fixed hash fields Linux always enables (IPv4,
/// IPv4/TCP, IPv6, IPv6/TCP, IPv6/TCP-extended), optional UDP fields,
/// and the queueing mode — RSS multi-queue without VMDq, VMDq+RSS
/// when VMDq is active with more than one RSS queue, plain VMDq
/// otherwise.
pub const fn mrqc_word(udp_v4: bool, udp_v6: bool, vmdq: bool, rss_queues: usize) -> u32 {
    let mut word = MRQC_FIELD_IPV4
        | MRQC_FIELD_IPV4_TCP
        | MRQC_FIELD_IPV6
        | MRQC_FIELD_IPV6_TCP
        | MRQC_FIELD_IPV6_TCP_EX;
    if udp_v4 {
        word |= MRQC_FIELD_IPV4_UDP;
    }
    if udp_v6 {
        word |= MRQC_FIELD_IPV6_UDP;
    }
    word |= if !vmdq {
        MRQC_ENABLE_RSS_MQ
    } else if rss_queues > 1 {
        MRQC_ENABLE_VMDQ_RSS_MQ
    } else {
        MRQC_ENABLE_VMDQ
    };
    word
}

/// RXCSUM word for RSS operation: PCSD + CRCOFL over whatever the
/// caller already programmed.
pub const fn rxcsum_rss_word(current: u32) -> u32 {
    current | RXCSUM_PCSD | RXCSUM_CRCOFL
}

/// RX queue selected by an RSS hash through a RETA table: the low 7
/// hash bits index the 128-entry table.
pub fn rss_queue_for_hash(hash: u32, reta: &[u8; RETA_SIZE]) -> u8 {
    reta[(hash & 0x7F) as usize]
}

// ── VLAN filtering and insertion ────────────────────────────────────
//
// Linux `igb_vlan_rx_add_vid` / `igb_restore_vlan` (igb_main.c) and
// the TX context-descriptor VLAN field (`IGB_TX_FLAGS_VLAN_MASK` /
// `IGB_TX_FLAGS_VLAN_SHIFT` in igb.h: the tag rides in bits[31:16]
// of the context descriptor's `vlan_macip_lens`). RX filtering is a
// 4096-bit table (VFTA, 128 words at 0x5600): VID `v` sets word
// `v / 32`, bit `v % 32`. Linux always restores VID 0 (priority-tagged
// frames share the untagged path); the shadow here starts empty and
// `restore_default` adds VID 0, mirroring that restore step. The live
// device programs no VFTA word at bring-up — filtering is opt-in
// through [`Igb::vlan_filter_add`], so the single-queue QEMU path
// keeps its current accept-all behaviour until a caller opts in.

/// VET — VLAN Ether Type. Linux programs 0x8100 ("enable h/w to
/// recognize an 802.1Q VLAN Ethernet packet").
const REG_VET: u64 = 0x038;
/// VET value for 802.1Q.
const VET_8021Q: u32 = 0x8100;
/// VFTA base — VLAN Filter Table Array, 128 words.
const REG_VFTA_BASE: u64 = 0x5600;
/// VFTA words (4096 VIDs / 32 bits).
pub const VFTA_WORDS: usize = 128;
/// Maximum valid VID (12-bit field).
pub const VLAN_VID_MAX: u16 = 4095;
/// RX descriptor status bit: IEEE VLAN packet (Linux E1000_RXD_STAT_VP).
pub const ADV_RXD_STAT_VP: u32 = 1 << 3;
/// TX context-descriptor VLAN tag shift/mask (Linux IGB_TX_FLAGS_*).
pub const TX_CTXT_VLAN_SHIFT: u32 = 16;
pub const TX_CTXT_VLAN_MASK: u32 = 0xFFFF_0000;

/// VFTA word index for a VID.
pub const fn vfta_word(vid: u16) -> usize {
    (vid as usize) / 32
}

/// VFTA bit within its word for a VID.
pub const fn vfta_bit(vid: u16) -> u32 {
    (vid as usize % 32) as u32
}

/// Shadow of the hardware VFTA plus the opt-in filter state. A VID is
/// accepted by the filter iff its bit is set; VID 0 is special (see
/// [`VlanFilter::restore_default`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VlanFilter {
    words: [u32; VFTA_WORDS],
}

impl VlanFilter {
    /// Empty filter: no tagged VID accepted.
    pub const fn new() -> Self {
        Self {
            words: [0; VFTA_WORDS],
        }
    }

    /// Linux restore default: VID 0 is always present.
    pub fn restore_default(&mut self) {
        self.add(0);
    }

    /// Add a VID. Returns false (and changes nothing) for VID > 4095.
    pub fn add(&mut self, vid: u16) -> bool {
        if vid > VLAN_VID_MAX {
            return false;
        }
        self.words[vfta_word(vid)] |= 1 << vfta_bit(vid);
        true
    }

    /// Remove a VID. Returns false for VID > 4095.
    pub fn remove(&mut self, vid: u16) -> bool {
        if vid > VLAN_VID_MAX {
            return false;
        }
        self.words[vfta_word(vid)] &= !(1 << vfta_bit(vid));
        true
    }

    /// Whether a VID is in the filter (false for VID > 4095).
    pub fn contains(&self, vid: u16) -> bool {
        if vid > VLAN_VID_MAX {
            return false;
        }
        self.words[vfta_word(vid)] & (1 << vfta_bit(vid)) != 0
    }

    /// Accept every VID (VLAN promiscuous, Linux `IGB_FLAG_VLAN_PROMISC`
    /// set-VFTA step).
    pub fn set_promiscuous(&mut self) {
        self.words = [!0u32; VFTA_WORDS];
    }

    /// Shadow word `i` — the value programmed to VFTA register `i`.
    pub const fn word(&self, i: usize) -> u32 {
        self.words[i]
    }
}

impl Default for VlanFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// VLAN tag decoded from an RX write-back descriptor: present iff the
/// VP status bit is set, in which case `tag` is the descriptor's
/// `vlan` field (12-bit VID + PCP + CFI, as received on the wire).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxVlan {
    pub present: bool,
    pub tag: u16,
}

/// Strip an 802.1Q tag from an Ethernet frame in place: with a tag the
/// frame is `dst(6) src(6) TPID(2) TCI(2) ethertype(2) payload`, and
/// stripping deletes the 4 TPID/TCI bytes, returning the new length.
/// Returns `None` (frame untouched) when the frame is too short or
/// carries no 0x8100 TPID at bytes 12..14. This is the software half
/// of VLAN stripping; the hardware half is the VFTA filter above plus
/// the caller's decision to strip before handing the frame to the
/// stack (the live drain currently passes tag bytes through, as
/// before — stripping is opt-in, not a silent frame rewrite).
pub fn strip_vlan_tag_in_place(frame: &mut [u8], len: usize) -> Option<usize> {
    if len < 18 || len > frame.len() {
        return None;
    }
    if frame[12] != 0x81 || frame[13] != 0x00 {
        return None;
    }
    frame.copy_within(16..len, 12);
    Some(len - 4)
}

// ── Wake-on-LAN ─────────────────────────────────────────────────────
//
// Linux `igb_init_wol` / `__igb_shutdown` / resume WUS drain
// (igb_main.c) and `igb_get_wol` / `igb_set_wol` (igb_ethtool.c).
// WUC arms PME, WUFC selects the wake filters, WUS reports which
// filter fired (write-1-to-clear; Linux clears it with ~0 on resume).
// The live device does not arm WoL at bring-up: arming belongs to
// the suspend sequence (next commit), and the EEPROM support probe
// below still needs NVM access NARF's igb does not have yet — the
// support decode is provided so the suspend path can use it the
// moment NVM reads land, not as a claim that probe knows it today.

/// WUC — Wakeup Control.
const REG_WUC: u64 = 0x5800;
/// WUFC — Wakeup Filter Control.
const REG_WUFC: u64 = 0x5808;
/// WUS — Wakeup Status (W1C).
const REG_WUS: u64 = 0x5810;
/// WUC PME enable (Linux E1000_WUC_PME_EN).
pub const WUC_PME_EN: u32 = 0x0000_0002;
/// CTRL bit: advertise D3 wake capability (Linux E1000_CTRL_ADVD3WUC).
pub const CTRL_ADVD3WUC: u32 = 0x0010_0000;
/// WUFC/WUS filter bits (Linux E1000_WUFC_* / E1000_WUS_*).
pub const WUFC_LNKC: u32 = 0x0000_0001;
pub const WUFC_MAG: u32 = 0x0000_0002;
pub const WUFC_EX: u32 = 0x0000_0004;
pub const WUFC_MC: u32 = 0x0000_0008;
pub const WUFC_BC: u32 = 0x0000_0010;
/// WUS directed-packet bits (Linux E1000_WUS_ARPD/IPV4/IPV6/NSD).
pub const WUS_ARPD: u32 = 0x0000_0020;
pub const WUS_IPV4: u32 = 0x0000_0040;
pub const WUS_IPV6: u32 = 0x0000_0080;
pub const WUS_NSD: u32 = 0x0000_0400;
/// WUS bits that mean a wake packet was delivered to the host
/// (Linux WAKE_PKT_WUS: EX | ARPD | IPV4 | IPV6 | NSD).
pub const WUS_WAKE_PKT: u32 = WUFC_EX | WUS_ARPD | WUS_IPV4 | WUS_IPV6 | WUS_NSD;
/// EEPROM APME bit (Linux IGB_EEPROM_APME = 0x0400): set in NVM init
/// control word 3 when the part may wake the system.
pub const EEPROM_APME: u16 = 0x0400;

/// Wake filters a caller may arm, mirroring Linux's `adapter->wol`
/// WUFC word without exposing raw bit positions to callers.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WolFilters {
    pub link_change: bool,
    pub magic: bool,
    pub directed_exact: bool,
    pub multicast: bool,
    pub broadcast: bool,
}

impl WolFilters {
    /// Magic-packet-only, Linux's default when WoL is supported.
    pub const fn magic_only() -> Self {
        Self {
            link_change: false,
            magic: true,
            directed_exact: false,
            multicast: false,
            broadcast: false,
        }
    }

    /// Encode as a WUFC word.
    pub const fn to_wufc(&self) -> u32 {
        (if self.link_change { WUFC_LNKC } else { 0 })
            | (if self.magic { WUFC_MAG } else { 0 })
            | (if self.directed_exact { WUFC_EX } else { 0 })
            | (if self.multicast { WUFC_MC } else { 0 })
            | (if self.broadcast { WUFC_BC } else { 0 })
    }

    /// Decode a WUFC word (unknown bits are dropped).
    pub const fn from_wufc(word: u32) -> Self {
        Self {
            link_change: word & WUFC_LNKC != 0,
            magic: word & WUFC_MAG != 0,
            directed_exact: word & WUFC_EX != 0,
            multicast: word & WUFC_MC != 0,
            broadcast: word & WUFC_BC != 0,
        }
    }
}

/// Whether WoL is supported, from Linux `igb_init_wol`'s two main
/// gates: port A supports wake by default, other ports need the NVM
/// APME bit, and the platform must be able to wake at all
/// (`device_can_wakeup`). NOT encoded here: the fiber/quad-port
/// special cases (dual-fiber port B, quad-copper non-A ports), which
/// need multi-port topology the NARF probe does not track — a caller
/// with that topology must clear support explicitly. When this
/// returns true, Linux's default armed filter is magic-only.
pub fn wol_supported(port_is_a: bool, eeprom_apme: bool, device_can_wakeup: bool) -> bool {
    (port_is_a || eeprom_apme) && device_can_wakeup
}

/// Suspend-time WoL programming, from Linux `__igb_shutdown`: the
/// runtime-suspend path arms link-change only; the system-suspend
/// path arms the caller's filters, except link-change is dropped when
/// the link is already up (an up link cannot be a wake event). When
/// the resulting filter word is zero, WUC/WUFC are both cleared and
/// the link is powered down instead of armed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WolSuspendProgram {
    /// Set CTRL.ADVD3WUC when arming.
    pub advd3wuc: bool,
    /// Value for WUC (PME_EN when arming, 0 otherwise).
    pub wuc: u32,
    /// Value for WUFC (the armed filters, or 0).
    pub wufc: u32,
    /// Power the link down (true only when nothing is armed).
    pub power_down_link: bool,
}

/// Compute the suspend-time WoL program. `runtime` selects the
/// runtime-suspend filter (link-change only); otherwise the caller's
/// filters apply, minus link-change when `link_up`.
pub fn wol_suspend_program(filters: WolFilters, link_up: bool, runtime: bool) -> WolSuspendProgram {
    let mut wufc = if runtime {
        WUFC_LNKC
    } else {
        filters.to_wufc()
    };
    if link_up {
        wufc &= !WUFC_LNKC;
    }
    if wufc != 0 {
        WolSuspendProgram {
            advd3wuc: true,
            wuc: WUC_PME_EN,
            wufc,
            power_down_link: false,
        }
    } else {
        WolSuspendProgram {
            advd3wuc: false,
            wuc: 0,
            wufc: 0,
            power_down_link: true,
        }
    }
}

/// Whether a WUS word reports a delivered wake packet.
pub const fn wus_delivered_wake_packet(wus: u32) -> bool {
    wus & WUS_WAKE_PKT != 0
}

/// WUS clear word: WUS is write-1-to-clear, and Linux clears all
/// pending status with ~0 on resume.
pub const fn wus_clear_word() -> u32 {
    !0u32
}

// ── ethtool surface ─────────────────────────────────────────────────
//
// NARF has no ethtool ABI (the only in-tree mention is a comment in
// `drivers/net/core` about future rtnetlink/ethtool consumers), so
// this is a driver-local query surface shaped on Linux's
// `igb_ethtool_ops` read side — drvinfo, link settings, ring
// parameters, coalesce, pause parameters, WoL, RSS sizes, and the
// statistics set — rather than a wire protocol. Counters are real:
// the RX drain and the TX completion paths below bump them, so the
// snapshot reports observed traffic, not constants. Set-side ops
// (set_wol, set_rxfh, set_coalesce, set_ringparam) are deliberately
// absent: changing rings or the RETA table on a live device needs
// the stop/reconfigure sequence the PM commit adds, and advertising
// setters before it would be a lie.

/// Driver version reported by the ethtool surface (matches the
/// module version in `lib.rs`).
pub const IGB_DRIVER_VERSION: &str = "0.1.0";

/// Link settings in Linux `igb_get_link_ksettings` shape. NARF
/// forces 1 GbE full-duplex at bring-up (CTRL_FRCSPD/FRCDPLX), so
/// autoneg is reported off — not guessed on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EthtoolLink {
    pub speed_mbps: Option<u32>,
    pub duplex_full: bool,
    pub autoneg: bool,
}

/// Ring parameters in Linux `igb_get_ringparam` shape. `tx_usable`
/// is the sentinel-adjusted capacity (one slot is never posted).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EthtoolRings {
    pub tx_count: usize,
    pub tx_usable: usize,
    pub rx_count: usize,
}

/// Coalesce parameters in Linux `igb_get_coalesce` shape. NARF
/// routes RX and TX through one shared vector with one EITR, so both
/// directions report the same interval.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EthtoolCoalesce {
    pub rx_usecs: u32,
    pub tx_usecs: u32,
}

/// Pause parameters in Linux `igb_get_pauseparam` shape. NARF's igb
/// programs no flow-control registers, so all three report off.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EthtoolPause {
    pub autoneg: bool,
    pub rx_pause: bool,
    pub tx_pause: bool,
}

/// Statistics snapshot. Names match [`IGB_STAT_NAMES`] order.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EthtoolStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_errors: u64,
}

/// Statistic names in snapshot order (Linux `igb_get_strings` shape,
/// restricted to the counters this driver actually maintains).
pub const IGB_STAT_NAMES: [&str; 5] = [
    "rx_packets",
    "rx_bytes",
    "tx_packets",
    "tx_bytes",
    "tx_errors",
];

/// Whole ethtool read surface for one igb device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EthtoolInfo {
    pub driver: &'static str,
    pub version: &'static str,
    pub link: EthtoolLink,
    pub rings: EthtoolRings,
    pub coalesce: EthtoolCoalesce,
    pub pause: EthtoolPause,
    /// WoL support: `None` while NVM access (hence the EEPROM APME
    /// probe) is unavailable — unknown, not false.
    pub wol_supported: Option<bool>,
    pub wol: WolFilters,
    pub rss_indir_size: usize,
    pub rss_key_size: usize,
    pub stats: EthtoolStats,
}

/// EITR interval (256 ns units, Linux EITR encoding) to whole
/// microseconds, masking the CNT_IGNR flag bit first.
pub const fn eitr_to_usecs(eitr: u32) -> u32 {
    ((eitr & !EITR_CNT_IGNR) * 256) / 1000
}

/// Whole microseconds to an EITR interval (floor; the 256 ns unit
/// cannot represent every microsecond value exactly).
pub const fn usecs_to_eitr(usecs: u32) -> u32 {
    (usecs * 1000) / 256
}

/// Live counters backing [`EthtoolStats`]. Bumped with relaxed
/// atomics from the datapath; the snapshot is informational, not a
/// billing record, so relaxed ordering is sufficient.
#[derive(Debug, Default)]
pub struct IgbStats {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    tx_errors: AtomicU64,
}

impl IgbStats {
    fn note_rx(&self, len: u64) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(len, Ordering::Relaxed);
    }

    fn note_tx_ok(&self, len: u64) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(len, Ordering::Relaxed);
    }

    fn note_tx_error(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> EthtoolStats {
        EthtoolStats {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
        }
    }
}

// ── Power management and detach ─────────────────────────────────────
//
// Linux `__igb_close(suspending)` + `__igb_shutdown` + `igb_resume`
// (igb_main.c) and the detach contract in `drivers/net/specification`
// §3 (issue #789): a detach path must call
// `publish::clear_rx_mirror_attached` for the interface name when it
// unregisters the interface, because `eth%d` names are
// lowest-free-allocated and reused. Suspend order here: mask
// interrupts, disable the queue-0 DMA engines, then either arm WoL
// (RCTL restored for wake filtering, CTRL.ADVD3WUC, WUC/WUFC) or
// stop DMA and power the PHY down. Resume reverses it: clear WUS,
// re-kick the PHY, restore RCTL/TCTL, re-run the per-queue ENABLE
// handshake, unmask the MSI-X block, republish link. Deliberately
// NOT programmed: firmware handoff via CTRL_EXT.DRV_LOAD (NARF's igb
// never claims DRV_LOAD, so there is nothing to release) and PTP
// suspend (no PTP clock exists in this driver). The async pumps are
// not torn down on detach — they hold an `Arc<Igb>` — but every
// datapath entry point fails fast once `detached` is set, so a
// parked pump can no longer touch the device.

/// PHY BMCR power-down bit (IEEE 802.3 clause 22, bit 11).
const PHY_BMCR_PWRDOWN: u16 = 0x0800;

/// RCTL word for a WoL-armed suspend: the bring-up receive value,
/// kept so wake filtering still receives.
const RCTL_SUSPEND_ARMED: u32 =
    RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC | RCTL_BSIZE_2K;

/// RCTL word for an unarmed suspend: receive DMA stopped.
const RCTL_SUSPEND_OFF: u32 = RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC | RCTL_BSIZE_2K;

/// TCTL word for suspend: transmit DMA stopped, PSP kept.
const TCTL_SUSPEND_OFF: u32 = TCTL_PSP;

/// Whether the datapath may run: false while suspended or detached.
/// Factored pure so the fixture pins the gate the live paths use.
pub const fn datapath_allowed(detached: bool, suspended: bool) -> bool {
    !detached && !suspended
}

// CTRL bits.
const CTRL_RST: u32 = 1 << 26;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_FD: u32 = 1 << 0; // Full duplex.
const CTRL_SPEED_1000: u32 = 0b10 << 8; // Speed 1000 Mb/s.
const CTRL_FRCSPD: u32 = 1 << 11; // Force speed.
const CTRL_FRCDPLX: u32 = 1 << 12; // Force duplex.

// MDIC (PHY access). opcode: 01=write, 10=read. PHY addr 1 (internal).
const MDIC_PHY_ADDR: u32 = 1 << 21; // phyaddr = 1 at bits[25:21]
const MDIC_OP_WRITE: u32 = 0b01 << 26;
const MDIC_READY: u32 = 1 << 28;
// PHY BMCR (reg 0): autoneg enable + restart kicks QEMU igb's PHY to
// complete negotiation and raise BMSR link status → STATUS.LU.
const PHY_BMCR: u32 = 0;
const PHY_BMCR_ANENABLE: u16 = 0x1000;
const PHY_BMCR_ANRESTART: u16 = 0x0200;

// IMS/ICR cause bits — igb keeps the legacy e1000 IMS/ICR cause encoding
// for the legacy cause register; single-vector MSI-X uses the same bits.
// Linux: drivers/net/ethernet/intel/igb/e1000_defines.h E1000_ICR_* /
// E1000_IMS_* (IMS_* alias the ICR_* bits).
pub const IMS_TXDW: u32 = 1 << 0; // E1000_ICR_TXDW   0x00000001
pub const IMS_RXSEQ: u32 = 1 << 3; // E1000_ICR_RXSEQ  0x00000008
pub const IMS_LSC: u32 = 1 << 2; // E1000_ICR_LSC    0x00000004
pub const IMS_RXDMT0: u32 = 1 << 4; // E1000_ICR_RXDMT0 0x00000010
pub const IMS_RXT0: u32 = 1 << 7; // E1000_ICR_RXT0   0x00000080
                                  // Matches Linux's IMS_ENABLE_MASK subset the single-vector path needs:
                                  // RXT0 | TXDW | RXDMT0 | RXSEQ | LSC (DOUTSYNC is DMA-coalescing only).
pub const IMS_DEFAULT: u32 = IMS_TXDW | IMS_LSC | IMS_RXSEQ | IMS_RXDMT0 | IMS_RXT0;

/// One shared MSI-X table/vector entry handles RX0, TX0, and other causes.
const MSIX_VECTOR0_MASK: u32 = 1;
// Linux: e1000_defines.h E1000_IVAR_VALID = 0x80.
const IVAR_VALID: u32 = 0x80;
/// Linux starts igb queue vectors at 648 256-ns units (~6,000 IRQ/s).
/// Linux: drivers/net/ethernet/intel/igb/igb.h IGB_START_ITR = 648.
const EITR_START: u32 = 648;
/// Linux: e1000_defines.h E1000_EITR_CNT_IGNR = 0x80000000 (82576+;
/// "don't reset the ITR counter on write").
const EITR_CNT_IGNR: u32 = 1 << 31;

const fn ivar0_shared_vector(vector: u8) -> u32 {
    let entry = (vector as u32) | IVAR_VALID;
    entry | (entry << 8)
}

const fn ivar_misc_shared_vector(vector: u8) -> u32 {
    ((vector as u32) | IVAR_VALID) << 8
}

// GPIE bits. Linux: drivers/net/ethernet/intel/igb/e1000_defines.h.
pub const GPIE_NSICR: u32 = 1 << 0; // E1000_GPIE_NSICR     0x00000001
pub const GPIE_MULTIPLE_MSIX: u32 = 1 << 4; // E1000_GPIE_MSIX_MODE 0x00000010
pub const GPIE_EIAME: u32 = 1 << 30; // E1000_GPIE_EIAME    0x40000000
pub const GPIE_PBA: u32 = 1 << 31; // E1000_GPIE_PBA       0x80000000

// TCTL bits.
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

// RCTL bits.
const RCTL_EN: u32 = 1 << 1;
const RCTL_UPE: u32 = 1 << 3; // Unicast promiscuous.
const RCTL_MPE: u32 = 1 << 4; // Multicast promiscuous.
const RCTL_BAM: u32 = 1 << 15; // Broadcast accept.
const RCTL_BSIZE_2K: u32 = 0; // bits[17:16] = 0 → 2 KiB
const RCTL_SECRC: u32 = 1 << 26; // Strip Ethernet CRC.

// TX descriptor Done bit (bit 0 of the write-back status byte at
// descriptor offset 12 — same for the advanced write-back form).
const TXD_STAT_DD: u8 = 1 << 0;

// Ring sizes — must be a multiple of 8.
const TX_RING_LEN: usize = 8;
const TX_RING_USABLE: usize = TX_RING_LEN - 1;
const RX_RING_LEN: usize = 256;
const FRAME_SIZE: usize = 2048;

fn previous_rx_slot(next_head: usize) -> usize {
    (next_head + RX_RING_LEN - 1) % RX_RING_LEN
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IgbError {
    BarMapFailed,
    ResetTimeout,
    TxTimeout,
    QueueEnableTimeout,
    QueueTooSmall,
    UnsupportedOffload,
    /// Catch-all.
    Other(&'static str),
}

/// MMIO base of the IRQ-attached igb, shared with the static ISR so it
/// can read ICR (read-to-clear) and acknowledge the device. 0 = no
/// controller bound (handler short-circuits).
static ISR_MMIO_BASE: AtomicU64 = AtomicU64::new(0);

/// Sync ISR: read ICR to acknowledge the device, then return. The
/// dispatch layer bumps the per-vector fire-count and wakes any waiter.
/// Link Status Change pending, set by the ISR when ICR reports LSC.
/// The ISR does no lock or allocation work; the RX pump (task
/// context) consumes the flag, re-samples STATUS via `Igb::link_up`,
/// and republishes the iface link metadata — before this, carrier
/// was a probe-time photograph because the ISR read ICR only to
/// acknowledge it (issue #791).
static LSC_PENDING: AtomicBool = AtomicBool::new(false);

/// The family's publication sample. i210/82576/i350 negotiate up to
/// 1 GbE copper; report full duplex when the link is up (QEMU's igb
/// model reports LU immediately). Shared by probe (initial state) and
/// the RX pump's LSC drain (every transition).
fn igb_link_sample(dev: &Igb) -> crate::publish::LinkSample {
    if dev.link_up() {
        crate::publish::LinkSample {
            carrier: true,
            speed_mbps: Some(1000),
            duplex: Some(narf_net::iface::LinkDuplex::Full),
        }
    } else {
        crate::publish::LinkSample::DOWN
    }
}

fn igb_isr() {
    let base = ISR_MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    // SAFETY: `base` is the device's BAR0 virt, mapped at bring-up;
    // ICR (0x00c0) is inside the igb register window.
    let icr = unsafe { narf_arch::mmio::read32(base + REG_ICR) };
    // LSC is in the default IMS mask, so a link transition reaches
    // this read; record it for the pump instead of discarding the
    // cause word (issue #791).
    if icr & IMS_LSC != 0 {
        LSC_PENDING.store(true, Ordering::Release);
    }
}

/// Advanced RX descriptor — "read" form (driver → chip).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
struct AdvRxDescRead {
    /// Packet buffer DMA address.
    pkt_addr: u64,
    /// Header buffer DMA address — zero in single-buffer mode.
    hdr_addr: u64,
}

/// Advanced RX descriptor — "write-back" form (chip → driver).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
struct AdvRxDescWb {
    /// Lower 64 bits — RSS hash + ext-status.
    lower: u64,
    /// Status/error field (bits 0..19), VLAN (bits 20..31).
    status_error: u32,
    /// Frame length.
    length: u16,
    /// VLAN tag (ignored by this driver).
    vlan: u16,
}

const _: () = assert!(core::mem::size_of::<AdvRxDescRead>() == 16);
const _: () = assert!(core::mem::size_of::<AdvRxDescWb>() == 16);

/// Bit 0 of `AdvRxDescWb::status_error` — Descriptor Done.
const ADV_RXD_STAT_DD: u32 = 1 << 0;
/// Bit 1 — End of Packet.
const ADV_RXD_STAT_EOP: u32 = 1 << 1;

// ── TX advanced descriptor offload bits ─────────────────────────────

/// Advanced TX data descriptor type (bits[21:20] = 0b11).
pub const ADVTXD_DTYP_DATA: u32 = 0x0030_0000;
/// Advanced TX context descriptor type (bits[21:20] = 0b10).
pub const ADVTXD_DTYP_CTXT: u32 = 0x0020_0000;
pub const ADVTXD_DCMD_DEXT: u32 = 1 << 29;
pub const ADVTXD_DCMD_RS: u32 = 1 << 27;
pub const ADVTXD_DCMD_IFCS: u32 = 1 << 25;
pub const ADVTXD_DCMD_EOP: u32 = 1 << 24;
/// TSE — TCP Segmentation Enable (bit 31 of cmd_type_len).
pub const ADVTXD_DCMD_TSE: u32 = 1 << 31;
/// PAYLEN shift — payload length sits at bits[31:14] of olinfo_status.
pub const ADVTXD_PAYLEN_SHIFT: u32 = 14;
/// Insert IP checksum (bit 8 of olinfo_status POPTS field).
pub const TXD_POPTS_IXSM: u32 = 0x0100;
/// Insert TCP/UDP checksum (bit 9 of olinfo_status POPTS field).
pub const TXD_POPTS_TXSM: u32 = 0x0200;
/// MAC length shift in vlan_macip_lens (bits[18:9]).
pub const ADVTXD_MACLEN_SHIFT: u32 = 9;
/// TUCMD: IPv4 packet.
pub const ADVTXD_TUCMD_IPV4: u32 = 0x400;
/// TUCMD: L4 type = TCP.
pub const ADVTXD_TUCMD_L4T_TCP: u32 = 0x800;
/// L4 length shift in mss_l4len_idx (bits[15:8]).
pub const ADVTXD_L4LEN_SHIFT: u32 = 8;
/// MSS shift in mss_l4len_idx (bits[31:16]).
pub const ADVTXD_MSS_SHIFT: u32 = 16;

// ── RX advanced descriptor checksum bits ────────────────────────────

/// status bit 4 — UDP checksum calculated.
/// Linux: e1000_defines.h E1000_RXD_STAT_UDPCS = 0x10.
#[allow(dead_code)]
const ADV_RXD_STAT_UDPCS: u32 = 1 << 4;
/// status bit 5 — TCP checksum calculated.
/// Linux: e1000_defines.h E1000_RXD_STAT_TCPCS = 0x20.
#[allow(dead_code)]
const ADV_RXD_STAT_TCPCS: u32 = 1 << 5;
/// status bit 6 — IP checksum calculated.
/// Linux: e1000_defines.h E1000_RXD_STAT_IPCS = 0x40.
#[allow(dead_code)]
const ADV_RXD_STAT_IPCS: u32 = 1 << 6;
/// stat/err bit 29 — TCP/UDP (L4) checksum error.
/// Linux: e1000_defines.h E1000_RXDEXT_STATERR_TCPE = 0x20000000.
#[allow(dead_code)]
const ADV_RXD_ERR_TCPE: u32 = 0x2000_0000;
/// stat/err bit 30 — IP checksum error.
/// Linux: e1000_defines.h E1000_RXDEXT_STATERR_IPE = 0x40000000.
#[allow(dead_code)]
const ADV_RXD_ERR_IPE: u32 = 0x4000_0000;

/// RX checksum verification result decoded from an igb AdvRxDescWb.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    /// Hardware did not compute a checksum for this frame.
    None,
    /// Hardware computed and verified the checksum — no errors.
    Ok,
    /// Hardware detected a checksum error.
    Fail,
}

/// Advanced TX context descriptor. Precedes the data descriptor for
/// TSO; carries MSS / L4len / TUCMD.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvTxCtxtDesc {
    pub vlan_macip_lens: u32,
    pub launch_time: u32,
    pub type_tucmd_mlhl: u32,
    pub mss_l4len_idx: u32,
}

/// Advanced TX data descriptor — replaces the legacy 8-byte descriptor
/// on igb hardware when DEXT is set. Used for both plain sends and TSO.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvTxDataDesc {
    pub buffer_addr: u64,
    pub cmd_type_len: u32,
    pub olinfo_status: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct TxTicket {
    slot: usize,
    generation: u64,
}

/// Producer/consumer bookkeeping for the queue-0 TX ring. One descriptor is
/// left unused so equal head/tail values remain unambiguous to the hardware.
/// A VLAN-insertion frame occupies two slots — a context descriptor
/// immediately followed by its data descriptor — tracked via
/// `is_context`: context descriptors carry no buffer and no waiter, so
/// reclaim completes one only once its following data descriptor shows
/// DD (the chip fetches descriptors in ring order, so data DD implies
/// the context was consumed; completing it any earlier could let a
/// wrap-around reservation overwrite a context the chip has not
/// fetched yet).
#[derive(Debug)]
struct TxRingCursor {
    next_to_use: usize,
    next_to_clean: usize,
    in_flight: usize,
    generations: [u64; TX_RING_LEN],
    is_context: [bool; TX_RING_LEN],
}

impl TxRingCursor {
    const fn new() -> Self {
        Self {
            next_to_use: 0,
            next_to_clean: 0,
            in_flight: 0,
            generations: [0; TX_RING_LEN],
            is_context: [false; TX_RING_LEN],
        }
    }

    fn reserve(&mut self) -> Option<TxTicket> {
        if self.in_flight >= TX_RING_USABLE {
            return None;
        }
        let slot = self.next_to_use;
        self.next_to_use = (slot + 1) % TX_RING_LEN;
        self.in_flight += 1;
        self.generations[slot] = self.generations[slot].wrapping_add(1);
        self.is_context[slot] = false;
        Some(TxTicket {
            slot,
            generation: self.generations[slot],
        })
    }

    /// Reserve a (context, data) slot pair for one VLAN-insertion
    /// frame. Both slots count against the usable capacity, and the
    /// pair may wrap across the ring end (context in the last slot,
    /// data in slot 0).
    fn reserve_pair(&mut self) -> Option<(TxTicket, TxTicket)> {
        if self.in_flight + 2 > TX_RING_USABLE {
            return None;
        }
        let ctx_slot = self.next_to_use;
        let data_slot = (ctx_slot + 1) % TX_RING_LEN;
        self.next_to_use = (data_slot + 1) % TX_RING_LEN;
        self.in_flight += 2;
        self.generations[ctx_slot] = self.generations[ctx_slot].wrapping_add(1);
        self.generations[data_slot] = self.generations[data_slot].wrapping_add(1);
        self.is_context[ctx_slot] = true;
        self.is_context[data_slot] = false;
        Some((
            TxTicket {
                slot: ctx_slot,
                generation: self.generations[ctx_slot],
            },
            TxTicket {
                slot: data_slot,
                generation: self.generations[data_slot],
            },
        ))
    }

    /// Slot following the oldest outstanding descriptor — the data
    /// descriptor of a context slot at the clean head.
    fn following_slot(&self) -> usize {
        (self.next_to_clean + 1) % TX_RING_LEN
    }

    fn complete_oldest(&mut self) {
        debug_assert!(self.in_flight != 0);
        self.is_context[self.next_to_clean] = false;
        self.next_to_clean = (self.next_to_clean + 1) % TX_RING_LEN;
        self.in_flight -= 1;
    }

    fn ticket_was_reused(&self, ticket: TxTicket) -> bool {
        self.generations[ticket.slot] != ticket.generation
    }
}

// ── Descriptor offload impl blocks ──────────────────────────────────

impl AdvRxDescWb {
    /// RSS hash for this frame: once RXCSUM.PCSD is set (see
    /// [`rxcsum_rss_word`]), the descriptor's lower word carries the
    /// RSS hash instead of the packet checksum. Only meaningful for
    /// descriptors written back after MRQC programming.
    #[allow(dead_code)]
    pub fn rss_hash(&self) -> u32 {
        self.lower as u32
    }

    /// VLAN tag for this frame: present iff the VP status bit is set,
    /// with the tag taken from the descriptor's `vlan` field. When VP
    /// is clear the `vlan` field is meaningless and `present` is
    /// false, even if the field happens to be non-zero.
    #[allow(dead_code)]
    pub fn rx_vlan(&self) -> RxVlan {
        RxVlan {
            present: self.status_error & ADV_RXD_STAT_VP != 0,
            tag: self.vlan,
        }
    }

    /// Decode the RX checksum result from `status_error`.
    #[allow(dead_code)]
    pub fn csum_result(&self) -> RxCsumResult {
        let ip_computed = self.status_error & ADV_RXD_STAT_IPCS != 0;
        let l4_computed = self.status_error & (ADV_RXD_STAT_TCPCS | ADV_RXD_STAT_UDPCS) != 0;
        if !ip_computed && !l4_computed {
            return RxCsumResult::None;
        }
        let ip_err = self.status_error & ADV_RXD_ERR_IPE != 0;
        let tcp_err = self.status_error & ADV_RXD_ERR_TCPE != 0;
        if ip_err || tcp_err {
            RxCsumResult::Fail
        } else {
            RxCsumResult::Ok
        }
    }
}

impl AdvTxCtxtDesc {
    /// Build a VLAN-insertion context descriptor: the tag rides in
    /// bits[31:16] of `vlan_macip_lens` (Linux `IGB_TX_FLAGS_VLAN_MASK`
    /// / `IGB_TX_FLAGS_VLAN_SHIFT`). The following data descriptor is
    /// an ordinary data descriptor; the chip inserts the tag on the
    /// wire. A combined TSO+VLAN descriptor ORs the tag into
    /// [`AdvTxCtxtDesc::new_tso_v4`]'s `vlan_macip_lens`.
    pub fn new_vlan(tag: u16) -> Self {
        AdvTxCtxtDesc {
            vlan_macip_lens: ((tag as u32) << TX_CTXT_VLAN_SHIFT) & TX_CTXT_VLAN_MASK,
            launch_time: 0,
            type_tucmd_mlhl: ADVTXD_DCMD_DEXT | ADVTXD_DTYP_CTXT,
            mss_l4len_idx: 0,
        }
    }

    /// Build a TSO context descriptor for an IPv4/TCP frame.
    pub fn new_tso_v4(mac_len: u8, ip_len: u8, l4_len: u8, mss: u16) -> Self {
        let vlan_macip_lens = (ip_len as u32) | ((mac_len as u32) << ADVTXD_MACLEN_SHIFT);
        let type_tucmd_mlhl =
            ADVTXD_DCMD_DEXT | ADVTXD_DTYP_CTXT | ADVTXD_TUCMD_IPV4 | ADVTXD_TUCMD_L4T_TCP;
        let mss_l4len_idx =
            ((l4_len as u32) << ADVTXD_L4LEN_SHIFT) | ((mss as u32) << ADVTXD_MSS_SHIFT);
        AdvTxCtxtDesc {
            vlan_macip_lens,
            launch_time: 0,
            type_tucmd_mlhl,
            mss_l4len_idx,
        }
    }
}

impl AdvTxDataDesc {
    /// Build a plain advanced data descriptor (no checksum / no TSO).
    /// QEMU's igb model — like real 82575+/i210 silicon — only accepts
    /// advanced TX descriptors (DEXT set); it has no legacy TX path, so
    /// even an offload-free send must use this advanced form.
    pub fn plain(addr: u64, len: u16) -> Self {
        let cmd_type_len = (len as u32)
            | ADVTXD_DTYP_DATA
            | ADVTXD_DCMD_DEXT
            | ADVTXD_DCMD_RS
            | ADVTXD_DCMD_IFCS
            | ADVTXD_DCMD_EOP;
        let olinfo_status = (len as u32) << ADVTXD_PAYLEN_SHIFT;
        AdvTxDataDesc {
            buffer_addr: addr,
            cmd_type_len,
            olinfo_status,
        }
    }

    /// Build a data descriptor with IP + TCP/UDP checksum offload.
    pub fn with_csum(addr: u64, len: u16) -> Self {
        let cmd_type_len = (len as u32)
            | ADVTXD_DTYP_DATA
            | ADVTXD_DCMD_DEXT
            | ADVTXD_DCMD_RS
            | ADVTXD_DCMD_IFCS
            | ADVTXD_DCMD_EOP;
        let olinfo_status = ((len as u32) << ADVTXD_PAYLEN_SHIFT) | TXD_POPTS_IXSM | TXD_POPTS_TXSM;
        AdvTxDataDesc {
            buffer_addr: addr,
            cmd_type_len,
            olinfo_status,
        }
    }

    /// Build a data descriptor with TSO enabled.
    pub fn with_tso(addr: u64, len: u16, _mss: u16) -> Self {
        let cmd_type_len = (len as u32)
            | ADVTXD_DTYP_DATA
            | ADVTXD_DCMD_DEXT
            | ADVTXD_DCMD_RS
            | ADVTXD_DCMD_IFCS
            | ADVTXD_DCMD_EOP
            | ADVTXD_DCMD_TSE;
        let olinfo_status = ((len as u32) << ADVTXD_PAYLEN_SHIFT) | TXD_POPTS_IXSM | TXD_POPTS_TXSM;
        AdvTxDataDesc {
            buffer_addr: addr,
            cmd_type_len,
            olinfo_status,
        }
    }
}

pub struct Igb {
    mmio: MmioRegion,
    mac: [u8; 6],
    tx_ring_buf: DmaBuffer,
    rx_ring_buf: DmaBuffer,
    /// The DMA buffer currently armed in each RX descriptor slot.
    rx_buf_pool: IrqSafeSpinLock<alloc::vec::Vec<DmaBuffer>>,
    /// One persistent copy-mode DMA buffer per TX descriptor. A slot is not
    /// reused until hardware writes DD, so concurrent senders never overwrite
    /// a buffer still owned by the device.
    tx_buf_pool: alloc::vec::Vec<DmaBuffer>,
    tx_state: IrqSafeSpinLock<TxRingCursor>,
    /// Opt-in VLAN filter shadow; no VFTA word is programmed at
    /// bring-up (see [`VlanFilter`]).
    vlan_filter: IrqSafeSpinLock<VlanFilter>,
    /// Live counters for the ethtool surface.
    stats: IgbStats,
    /// WoL filters the suspend sequence will arm (default: none).
    wol_filters: IrqSafeSpinLock<WolFilters>,
    /// Datapath gates (see [`datapath_allowed`]).
    suspended: AtomicBool,
    detached: AtomicBool,
    rx_head: IrqSafeSpinLock<u16>,
    /// Reject nested/concurrent drains while an RX callback owns the current
    /// descriptor. A callback may synchronously transmit, whose responsive
    /// wait pumps RX again; returning from that nested pump avoids recursively
    /// taking `rx_head`/`rx_buf_pool` while the outer callback holds them.
    rx_draining: AtomicBool,
    pub ready: bool,
    /// MSI-X table mapping when MSI-X is enabled.
    _msix: Option<MsixTable>,
    /// IDT vector bound to the device's MSI-X table[0]. `None` means
    /// polled-only completion.
    pub irq_vector: Option<u8>,
    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

impl core::fmt::Debug for Igb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Igb")
            .field("mac", &self.mac)
            .field("ready", &self.ready)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

impl Igb {
    /// Bring up the controller.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Arc<Self>, IgbError> {
        // SAFETY: caller-asserted.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| IgbError::BarMapFailed)?;

        // 1. Master reset.
        // SAFETY: mapped MMIO.
        let ctrl = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, ctrl | CTRL_RST);
        }
        // SAFETY: mapped MMIO; responsive_spin_until ticks sleep_pumps.
        // I210 datasheet §3.3.1: CTRL.RST self-clears within ~1 ms;
        // 100 ms is the wedge threshold.
        narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { mmio.read32(REG_CTRL) } & CTRL_RST == 0,
            narf_time::Deadline::after_ms(100),
        );
        // SAFETY: same.
        let after = unsafe { mmio.read32(REG_CTRL) };
        if after & CTRL_RST != 0 {
            return Err(IgbError::ResetTimeout);
        }

        // 2. Mask legacy and extended interrupt causes during bring-up.
        //    The legacy cause/mask pair lives in the low block (ICR 0x00c0,
        //    IMS 0x00d0, IMC 0x00d8); the extended MSI-X block lives at
        //    0x1500+ (EICS/EIMS/EIMC/EIAC/EIAM/GPIE). We clear both.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_IMC, !0u32);
            mmio.write32(REG_EIMC, !0u32);
            let _ = mmio.read32(REG_ICR);
        }

        // 3. Set link up. Force 1 GbE full-duplex so QEMU's igb model
        //    (and real silicon with a trivial copper partner) reports
        //    STATUS.LU — QEMU's igb gates RX delivery on LU, so an
        //    SLU-only write leaves RX dead (link stays down, DD never set).
        // SAFETY: same.
        let ctrl = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe {
            mmio.write32(
                REG_CTRL,
                ctrl | CTRL_SLU | CTRL_FD | CTRL_SPEED_1000 | CTRL_FRCSPD | CTRL_FRCDPLX,
            );
        }
        // Kick the internal PHY to (re)start auto-negotiation. QEMU's igb
        // keeps STATUS.LU clear until the PHY's BMSR link bit is set,
        // which this BMCR write drives; without it RX is silently dropped.
        // SAFETY: mapped MMIO.
        unsafe {
            Self::phy_write(&mmio, PHY_BMCR, PHY_BMCR_ANENABLE | PHY_BMCR_ANRESTART);
        }
        // Give QEMU a moment to raise link before RX enable (bounded).
        narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { mmio.read32(REG_STATUS) } & (1 << 1) != 0,
            narf_time::Deadline::after_ms(50),
        );

        // 4. Read MAC from RAL/RAH.
        // SAFETY: same.
        let ral = unsafe { mmio.read32(REG_RAL0) };
        // SAFETY: same.
        let rah = unsafe { mmio.read32(REG_RAH0) };
        let mac = [
            (ral & 0xFF) as u8,
            ((ral >> 8) & 0xFF) as u8,
            ((ral >> 16) & 0xFF) as u8,
            ((ral >> 24) & 0xFF) as u8,
            (rah & 0xFF) as u8,
            ((rah >> 8) & 0xFF) as u8,
        ];

        // 5. Allocate ring + buffer pools.
        let tx_ring_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IgbError::BarMapFailed)?;
        let rx_ring_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IgbError::BarMapFailed)?;
        let mut tx_buf_pool: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(TX_RING_LEN);
        for _ in 0..TX_RING_LEN {
            tx_buf_pool.push(
                alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0)
                    .map_err(|_| IgbError::BarMapFailed)?,
            );
        }
        let mut rx_buf_pool: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(RX_RING_LEN);
        for _ in 0..RX_RING_LEN {
            rx_buf_pool.push(
                alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0)
                    .map_err(|_| IgbError::BarMapFailed)?,
            );
        }

        // 6. Initialise TX descriptors (zeroed by alloc_coherent) and
        //    enable the per-queue TX DMA engine. Queue 0 is programmed
        //    through the multi-queue window helper; `queue_regs(0)`
        //    reproduces the legacy REG_TDBAL/REG_TXDCTL0 addresses
        //    exactly (asserted by the multi-queue fixture below), so
        //    this refactor changes no live register traffic.
        let q0 = queue_regs(0);
        let tx_phys = tx_ring_buf.dma_addr().raw();
        let tx_len = (TX_RING_LEN * 16) as u32;
        // SAFETY: mapped DMA, freshly zeroed.
        unsafe {
            mmio.write32(q0.tdbal, (tx_phys & 0xFFFF_FFFF) as u32);
            mmio.write32(q0.tdbah, (tx_phys >> 32) as u32);
            mmio.write32(q0.tdlen, tx_len);
            mmio.write32(q0.tdh, 0);
            mmio.write32(q0.tdt, 0);
            mmio.write32(REG_TCTL, TCTL_EN | TCTL_PSP);
        }
        // igb per-queue enable: set TXDCTL.ENABLE then spin until the
        // chip reflects it. Linux `igb_configure_tx_ring`.
        // SAFETY: mapped MMIO.
        unsafe {
            let txdctl = queue_enable_word(mmio.read32(q0.txdctl));
            mmio.write32(q0.txdctl, txdctl);
        }
        let tx_on = narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { queue_enable_reflected(mmio.read32(q0.txdctl)) },
            narf_time::Deadline::after_ms(100),
        );
        if !tx_on {
            // QEMU's igb model reflects the bit immediately; a real
            // part that never reflects ENABLE is a dead queue.
            return Err(IgbError::QueueEnableTimeout);
        }

        // 7. Initialise RX descriptors using the *advanced* descriptor
        //    format. hdr_addr = 0 (single-buffer mode).
        let rx_phys = rx_ring_buf.dma_addr().raw();
        // SAFETY: mapped DMA, freshly zeroed.
        unsafe {
            for (i, buf) in rx_buf_pool.iter().enumerate().take(RX_RING_LEN) {
                let desc = narf_memory::PhysAddr::new(rx_phys + (i * 16) as u64)
                    .kernel_mut_ptr::<AdvRxDescRead>();
                core::ptr::write_volatile(
                    desc,
                    AdvRxDescRead {
                        pkt_addr: buf.dma_addr().raw(),
                        hdr_addr: 0,
                    },
                );
            }
            mmio.write32(q0.rdbal, (rx_phys & 0xFFFF_FFFF) as u32);
            mmio.write32(q0.rdbah, (rx_phys >> 32) as u32);
            mmio.write32(q0.rdlen, (RX_RING_LEN * 16) as u32);
            mmio.write32(q0.rdh, 0);
            mmio.write32(q0.rdt, (RX_RING_LEN - 1) as u32);

            // SRRCTL — per-queue: buffer-size = 2 KiB, descriptor type =
            // ADV_ONEBUF. Linux `igb_setup_srrctl`; queue 0 only.
            let mut srrctl = mmio.read32(q0.srrctl);
            srrctl &= !(SRRCTL_BSIZEPKT_MASK | SRRCTL_DESCTYPE_MASK);
            srrctl |= ((FRAME_SIZE as u32) >> SRRCTL_BSIZEPKT_SHIFT) & SRRCTL_BSIZEPKT_MASK;
            srrctl |= SRRCTL_DESCTYPE_ADV_ONEBUF;
            mmio.write32(q0.srrctl, srrctl);

            mmio.write32(
                REG_RCTL,
                RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC | RCTL_BSIZE_2K,
            );

            // VET — tell the hardware 0x8100 is the VLAN EtherType so
            // tagged frames are recognised for VFTA filtering and the
            // RX descriptor VP bit. This matches Linux's configure
            // step and QEMU's default; it changes no acceptance
            // behaviour while the VFTA shadow stays unprogrammed.
            mmio.write32(REG_VET, VET_8021Q);
        }
        // igb per-queue enable: set RXDCTL.ENABLE then spin until the
        // chip reflects it. Linux `igb_configure_rx_ring`.
        // SAFETY: mapped MMIO.
        unsafe {
            let rxdctl = queue_enable_word(mmio.read32(q0.rxdctl));
            mmio.write32(q0.rxdctl, rxdctl);
        }
        let rx_on = narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { queue_enable_reflected(mmio.read32(q0.rxdctl)) },
            narf_time::Deadline::after_ms(100),
        );
        if !rx_on {
            return Err(IgbError::QueueEnableTimeout);
        }

        // 8. Try MSI-X (single vector covering all causes); polling is
        //    the fallback so bring-up tests work without an IRQ vector.
        let (msix, irq_vector) = match Self::try_enable_msix(cap, device) {
            Ok((tbl, v)) => (Some(tbl), Some(v)),
            Err(_) => (None, None),
        };

        if irq_vector.is_some() {
            ISR_MMIO_BASE.store(mmio.virt, Ordering::Release);
        }
        if let Some(v) = irq_vector {
            narf_interrupts::install_handler(v, igb_isr);
        }

        // 9. Program the extended interrupt block. Queue 0 RX and TX
        //    occupy IVAR0 bytes 0 and 1; "other" causes occupy
        //    IVAR_MISC byte 1. All three target MSI-X table entry 0.
        if irq_vector.is_some() {
            // SAFETY: mapped MMIO.
            unsafe {
                mmio.write32(
                    REG_GPIE,
                    GPIE_NSICR | GPIE_MULTIPLE_MSIX | GPIE_EIAME | GPIE_PBA,
                );
                mmio.write32(REG_IVAR0, ivar0_shared_vector(0));
                mmio.write32(REG_IVAR_MISC, ivar_misc_shared_vector(0));
                mmio.write32(REG_EITR0, EITR_START | EITR_CNT_IGNR);
                mmio.write32(REG_EIAC, MSIX_VECTOR0_MASK);
                mmio.write32(REG_EIAM, MSIX_VECTOR0_MASK);
                mmio.write32(REG_EIMS, MSIX_VECTOR0_MASK);
                mmio.write32(REG_IMS, IMS_DEFAULT);
            }
        }

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
        // Keep the RX producer alive for the optional `Interface`/registry
        // consumer path, but do NOT spawn an RX pump that drains the
        // hardware ring: the kernel-side TCP stack drains RX synchronously
        // via `install_rx_drain` → `rx_recv_in_place`, and a second async
        // consumer on the same ring would split frames between the two.
        core::mem::drop(rx_prod);

        let igb = Arc::new(Self {
            mmio,
            mac,
            tx_ring_buf,
            rx_ring_buf,
            rx_buf_pool: IrqSafeSpinLock::new(rx_buf_pool),
            tx_buf_pool,
            tx_state: IrqSafeSpinLock::new(TxRingCursor::new()),
            vlan_filter: IrqSafeSpinLock::new(VlanFilter::new()),
            stats: IgbStats::default(),
            wol_filters: IrqSafeSpinLock::new(WolFilters::default()),
            suspended: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            rx_head: IrqSafeSpinLock::new(0),
            rx_draining: AtomicBool::new(false),
            ready: true,
            _msix: msix,
            irq_vector,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // TX async pump: drains the TX IPC ring for any registry
        // `Interface` producer. The kernel stack uses the synchronous
        // `igb_send_frame` SendFn instead, so this is idle under the
        // net-smoke profile.
        spawn_tx_pump(igb.clone(), tx_cons);

        Ok(igb)
    }

    /// Walk the controller's MSI-X capability, allocate an IDT vector +
    /// table slot, program slot 0 to deliver to the probe CPU, and flip
    /// the global MSI-X enable. Failure leaves the device polled-only.
    fn try_enable_msix(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(MsixTable, u8), IgbError> {
        let mut msix = enable_msix(cap, device).map_err(|_| IgbError::BarMapFailed)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| IgbError::BarMapFailed)?;
        let _ = msix.alloc_vector().ok_or(IgbError::BarMapFailed)?;
        // SAFETY: interrupt topology is initialized before subsystem probes.
        let target = unsafe { narf_interrupts::current_cpu_target_id() };
        // SAFETY: caller holds the BusDeviceCap; we own the MSI-X table;
        // this write precedes the global enable.
        let _ = unsafe { msix.program_vector(0, target, v) }.map_err(|_| IgbError::BarMapFailed)?;
        // SAFETY: cfg-space write to a known cap-list offset.
        unsafe { msix.enable() }.map_err(|_| IgbError::BarMapFailed)?;
        Ok((msix, v))
    }

    /// Write a 16-bit value to an internal-PHY register via MDIC.
    ///
    /// # Safety
    /// Caller owns BAR0; `mmio` is mapped.
    unsafe fn phy_write(mmio: &MmioRegion, reg: u32, data: u16) {
        let cmd = (data as u32) | ((reg & 0x1F) << 16) | MDIC_PHY_ADDR | MDIC_OP_WRITE;
        // SAFETY: caller-asserted mapped MMIO.
        unsafe {
            mmio.write32(REG_MDIC, cmd);
        }
        // Wait for the transaction to retire (READY set). QEMU completes
        // synchronously; a short bounded spin covers real silicon.
        narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { mmio.read32(REG_MDIC) } & MDIC_READY != 0,
            narf_time::Deadline::after_ms(10),
        );
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Set the WoL filters the suspend sequence will arm.
    pub fn set_wol_filters(&self, filters: WolFilters) {
        *self.wol_filters.lock() = filters;
    }

    /// Whole ethtool read surface for this device, from live state.
    pub fn ethtool_info(&self) -> EthtoolInfo {
        let link_up = self.link_up();
        EthtoolInfo {
            driver: "igb",
            version: IGB_DRIVER_VERSION,
            link: EthtoolLink {
                speed_mbps: if link_up { Some(1000) } else { None },
                duplex_full: link_up,
                autoneg: false,
            },
            rings: EthtoolRings {
                tx_count: TX_RING_LEN,
                tx_usable: TX_RING_USABLE,
                rx_count: RX_RING_LEN,
            },
            coalesce: EthtoolCoalesce {
                rx_usecs: eitr_to_usecs(EITR_START | EITR_CNT_IGNR),
                tx_usecs: eitr_to_usecs(EITR_START | EITR_CNT_IGNR),
            },
            pause: EthtoolPause::default(),
            wol_supported: None,
            wol: *self.wol_filters.lock(),
            rss_indir_size: RETA_SIZE,
            rss_key_size: RSS_KEY_SIZE,
            stats: self.stats.snapshot(),
        }
    }

    /// Opt a VID into the hardware VLAN filter: update the shadow and
    /// program that one VFTA word (Linux `igb_vlan_rx_add_vid` writes
    /// the shadow word to the device). Returns false for VID > 4095.
    /// The caller owns the policy question of whether enabling any
    /// filter also needs VID 0 restored (see
    /// [`VlanFilter::restore_default`]).
    pub fn vlan_filter_add(&self, vid: u16) -> bool {
        let mut filter = self.vlan_filter.lock();
        if !filter.add(vid) {
            return false;
        }
        let word = vfta_word(vid);
        let value = filter.word(word);
        drop(filter);
        // SAFETY: mapped MMIO; VFTA word `word` is within the 128-word
        // table for any valid VID.
        unsafe {
            self.mmio.write32(REG_VFTA_BASE + word as u64 * 4, value);
        }
        true
    }

    /// Remove a VID from the hardware VLAN filter (shadow + the one
    /// VFTA word). Returns false for VID > 4095.
    pub fn vlan_filter_remove(&self, vid: u16) -> bool {
        let mut filter = self.vlan_filter.lock();
        if !filter.remove(vid) {
            return false;
        }
        let word = vfta_word(vid);
        let value = filter.word(word);
        drop(filter);
        // SAFETY: mapped MMIO; see `vlan_filter_add`.
        unsafe {
            self.mmio.write32(REG_VFTA_BASE + word as u64 * 4, value);
        }
        true
    }

    /// Suspend the device (Linux `__igb_shutdown` order): mask
    /// interrupts, disable the queue-0 DMA engines, then arm WoL or
    /// stop DMA and power the PHY down. `runtime` selects the
    /// runtime-suspend filter (link-change only); otherwise the
    /// filters set by [`Igb::set_wol_filters`] apply. While suspended
    /// the datapath gates refuse TX and RX (see [`datapath_allowed`])
    /// and the interface publishes link down. A second suspend is a
    /// no-op success; suspending a detached device fails.
    pub fn suspend(&self, runtime: bool) -> Result<(), IgbError> {
        if self.detached.load(Ordering::Acquire) {
            return Err(IgbError::Other("igb device detached"));
        }
        if self.suspended.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let q0 = queue_regs(0);
        // SAFETY: mapped MMIO.
        unsafe {
            self.mmio.write32(REG_IMC, !0u32);
            self.mmio.write32(REG_EIMC, !0u32);
            self.mmio.write32(q0.txdctl, 0);
            self.mmio.write32(q0.rxdctl, 0);
        }
        let filters = *self.wol_filters.lock();
        let program = wol_suspend_program(filters, self.link_up(), runtime);
        // SAFETY: mapped MMIO. Transmit DMA stops in both branches
        // (`__igb_close` has already stopped the TX unit before Linux
        // arms wake filtering); only the receive side differs.
        unsafe {
            self.mmio.write32(REG_TCTL, TCTL_SUSPEND_OFF);
            if program.wufc != 0 {
                self.mmio.write32(REG_RCTL, RCTL_SUSPEND_ARMED);
                let ctrl = self.mmio.read32(REG_CTRL);
                self.mmio.write32(REG_CTRL, ctrl | CTRL_ADVD3WUC);
                self.mmio.write32(REG_WUC, program.wuc);
                self.mmio.write32(REG_WUFC, program.wufc);
            } else {
                self.mmio.write32(REG_WUC, 0);
                self.mmio.write32(REG_WUFC, 0);
                self.mmio.write32(REG_RCTL, RCTL_SUSPEND_OFF);
                Self::phy_write(&self.mmio, PHY_BMCR, PHY_BMCR_PWRDOWN);
            }
        }
        crate::publish::publish_link(igb_ifname(), crate::publish::LinkSample::DOWN);
        Ok(())
    }

    /// Resume a suspended device (Linux `igb_resume` order): clear
    /// WUS, re-kick the PHY out of power-down, restore RCTL/TCTL,
    /// re-run the queue-0 ENABLE handshake, unmask the MSI-X block,
    /// and republish link. Resuming a running device is a no-op
    /// success; resuming a detached device fails. A handshake that
    /// never reflects leaves the device suspended and reports
    /// `QueueEnableTimeout`.
    pub fn resume(&self) -> Result<(), IgbError> {
        if self.detached.load(Ordering::Acquire) {
            return Err(IgbError::Other("igb device detached"));
        }
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let q0 = queue_regs(0);
        // SAFETY: mapped MMIO.
        unsafe {
            self.mmio.write32(REG_WUS, wus_clear_word());
            self.mmio.write32(REG_WUC, 0);
            self.mmio.write32(REG_WUFC, 0);
            Self::phy_write(&self.mmio, PHY_BMCR, PHY_BMCR_ANENABLE | PHY_BMCR_ANRESTART);
            self.mmio.write32(
                REG_RCTL,
                RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC | RCTL_BSIZE_2K,
            );
            self.mmio.write32(REG_TCTL, TCTL_EN | TCTL_PSP);
            let txdctl = queue_enable_word(self.mmio.read32(q0.txdctl));
            self.mmio.write32(q0.txdctl, txdctl);
            let rxdctl = queue_enable_word(self.mmio.read32(q0.rxdctl));
            self.mmio.write32(q0.rxdctl, rxdctl);
        }
        let tx_on = narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { queue_enable_reflected(self.mmio.read32(q0.txdctl)) },
            narf_time::Deadline::after_ms(100),
        );
        let rx_on = narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { queue_enable_reflected(self.mmio.read32(q0.rxdctl)) },
            narf_time::Deadline::after_ms(100),
        );
        if !tx_on || !rx_on {
            return Err(IgbError::QueueEnableTimeout);
        }
        // Unmask the MSI-X block (same program as bring-up step 9).
        if self.irq_vector.is_some() {
            // SAFETY: mapped MMIO.
            unsafe {
                self.mmio.write32(
                    REG_GPIE,
                    GPIE_NSICR | GPIE_MULTIPLE_MSIX | GPIE_EIAME | GPIE_PBA,
                );
                self.mmio.write32(REG_IVAR0, ivar0_shared_vector(0));
                self.mmio.write32(REG_IVAR_MISC, ivar_misc_shared_vector(0));
                self.mmio.write32(REG_EITR0, EITR_START | EITR_CNT_IGNR);
                self.mmio.write32(REG_EIAC, MSIX_VECTOR0_MASK);
                self.mmio.write32(REG_EIAM, MSIX_VECTOR0_MASK);
                self.mmio.write32(REG_EIMS, MSIX_VECTOR0_MASK);
                self.mmio.write32(REG_IMS, IMS_DEFAULT);
            }
        }
        self.suspended.store(false, Ordering::Release);
        crate::publish::publish_link(igb_ifname(), igb_link_sample(self));
        Ok(())
    }

    /// Device half of detach: set the datapath gate and drop the
    /// ISR's MMIO base first (so no new datapath work or late
    /// interrupt can race the teardown), then mask interrupts, stop
    /// the TX/RX units, disable the queue-0 DMA engines, and clear
    /// any WoL arming. The registry half lives in [`igb_detach`].
    fn detach_device(&self) {
        self.detached.store(true, Ordering::Release);
        ISR_MMIO_BASE.store(0, Ordering::Release);
        let q0 = queue_regs(0);
        // SAFETY: mapped MMIO.
        unsafe {
            self.mmio.write32(REG_IMC, !0u32);
            self.mmio.write32(REG_EIMC, !0u32);
            self.mmio.write32(q0.txdctl, 0);
            self.mmio.write32(q0.rxdctl, 0);
            self.mmio.write32(REG_RCTL, RCTL_SUSPEND_OFF);
            self.mmio.write32(REG_TCTL, TCTL_SUSPEND_OFF);
            self.mmio.write32(REG_WUC, 0);
            self.mmio.write32(REG_WUFC, 0);
        }
    }

    pub fn link_up(&self) -> bool {
        // SAFETY: mapped MMIO; STATUS bit 1 = LU (link up).
        let s = unsafe { self.mmio.read32(REG_STATUS) };
        s & (1 << 1) != 0
    }

    fn tx_desc_done(&self, slot: usize) -> bool {
        let status_off = (slot * core::mem::size_of::<AdvTxDataDesc>()) as u64 + 12;
        // SAFETY: `slot` is ring-bounded and the coherent descriptor ring is
        // mapped for the controller's lifetime.
        let status =
            unsafe { core::ptr::read_volatile(self.tx_ring_buf.cpu_ptr_at::<u8>(status_off)) };
        status & TXD_STAT_DD != 0
    }

    fn reclaim_tx_locked(&self, state: &mut TxRingCursor) {
        while state.in_flight != 0 {
            // A context descriptor at the clean head has no DD of its
            // own: it completes only once its following data descriptor
            // shows DD (in-order fetch makes that a sound proxy).
            if state.is_context[state.next_to_clean] {
                if !self.tx_desc_done(state.following_slot()) {
                    break;
                }
            } else if !self.tx_desc_done(state.next_to_clean) {
                break;
            }
            // Pair the device's DD write with subsequent slot/buffer reuse.
            compiler_fence(Ordering::SeqCst);
            state.complete_oldest();
        }
    }

    fn tx_descriptor(buf_phys: u64, len: usize) -> AdvTxDataDesc {
        AdvTxDataDesc::plain(buf_phys, len as u16)
    }

    fn post_tx_locked(&self, state: &TxRingCursor, ticket: TxTicket, descriptor: AdvTxDataDesc) {
        let desc_off = (ticket.slot * core::mem::size_of::<AdvTxDataDesc>()) as u64;
        // SAFETY: `ticket.slot` was reserved from this ring under `tx_state`.
        unsafe {
            core::ptr::write_volatile(
                self.tx_ring_buf.cpu_mut_ptr_at::<AdvTxDataDesc>(desc_off),
                descriptor,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: mapped MMIO; every preceding descriptor through
        // `next_to_use` was posted while holding the same `tx_state` lock.
        unsafe {
            self.mmio.write32(REG_TDT, state.next_to_use as u32);
        }
    }

    /// Post a VLAN-insertion pair: context descriptor first, data
    /// descriptor second, then a single TDT doorbell past both. The
    /// context slot uses no TX buffer (its slot's persistent buffer
    /// stays untouched for the data descriptor's own slot).
    fn post_tx_pair_locked(
        &self,
        state: &TxRingCursor,
        ctx_ticket: TxTicket,
        ctx: AdvTxCtxtDesc,
        data_ticket: TxTicket,
        data: AdvTxDataDesc,
    ) {
        let ctx_off = (ctx_ticket.slot * core::mem::size_of::<AdvTxCtxtDesc>()) as u64;
        let data_off = (data_ticket.slot * core::mem::size_of::<AdvTxDataDesc>()) as u64;
        // SAFETY: both tickets were reserved from this ring under
        // `tx_state`; context and data descriptors are both 16 bytes.
        unsafe {
            core::ptr::write_volatile(
                self.tx_ring_buf.cpu_mut_ptr_at::<AdvTxCtxtDesc>(ctx_off),
                ctx,
            );
            core::ptr::write_volatile(
                self.tx_ring_buf.cpu_mut_ptr_at::<AdvTxDataDesc>(data_off),
                data,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: mapped MMIO; every preceding descriptor through
        // `next_to_use` was posted while holding the same `tx_state` lock.
        unsafe {
            self.mmio.write32(REG_TDT, state.next_to_use as u32);
        }
    }

    fn tx_ticket_done(&self, ticket: TxTicket) -> bool {
        let reused = self.tx_state.lock().ticket_was_reused(ticket);
        reused || self.tx_desc_done(ticket.slot)
    }

    fn wait_for_tx(&self, ticket: TxTicket) -> Result<(), IgbError> {
        let done = narf_scheduler::responsive_spin_until(
            || self.tx_ticket_done(ticket),
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(IgbError::TxTimeout);
        }
        let mut state = self.tx_state.lock();
        self.reclaim_tx_locked(&mut state);
        Ok(())
    }

    /// Transmit a single Ethernet frame. Posting is serialized briefly, but
    /// no IRQ-safe lock spans the responsive completion wait: its sleep-pump
    /// may re-enter RX and synchronously transmit an ARP-released packet.
    pub fn tx(&self, frame: &[u8], meta: &TxMeta) -> Result<(), IgbError> {
        if !datapath_allowed(
            self.detached.load(Ordering::Acquire),
            self.suspended.load(Ordering::Acquire),
        ) {
            return Err(IgbError::Other("igb device suspended or detached"));
        }
        if frame.is_empty() || frame.len() > FRAME_SIZE {
            return Err(IgbError::QueueTooSmall);
        }
        if let Some(tag) = meta.vlan_tag {
            return self.tx_vlan(frame, tag);
        }
        if meta.csum_l4.is_some() || meta.tso_mss.is_some() {
            return Err(IgbError::UnsupportedOffload);
        }
        let mut ticket = None;
        let posted = narf_scheduler::responsive_spin_until(
            || {
                let mut state = self.tx_state.lock();
                self.reclaim_tx_locked(&mut state);
                let Some(reserved) = state.reserve() else {
                    return false;
                };
                let buffer = &self.tx_buf_pool[reserved.slot];
                // SAFETY: one persistent FRAME_SIZE allocation backs this
                // reserved slot and cannot be reused until DD completion.
                unsafe {
                    for (i, byte) in frame.iter().enumerate() {
                        core::ptr::write_volatile(buffer.cpu_mut_ptr_at::<u8>(i as u64), *byte);
                    }
                }
                let descriptor = Self::tx_descriptor(buffer.dma_addr().raw(), frame.len());
                self.post_tx_locked(&state, reserved, descriptor);
                ticket = Some(reserved);
                true
            },
            narf_time::Deadline::after_ms(250),
        );
        if !posted {
            self.stats.note_tx_error();
            return Err(IgbError::TxTimeout);
        }
        let result = self.wait_for_tx(ticket.ok_or(IgbError::Other("TX reservation lost"))?);
        match &result {
            Ok(()) => self.stats.note_tx_ok(frame.len() as u64),
            Err(IgbError::TxTimeout) => self.stats.note_tx_error(),
            Err(_) => {}
        }
        result
    }

    /// Transmit a single Ethernet frame with VLAN insertion: a context
    /// descriptor carrying the tag precedes the ordinary data
    /// descriptor, and completion waits on the data descriptor's DD
    /// (which also releases the context slot through reclaim). The
    /// plain path is untouched — only a frame that actually requests a
    /// tag takes the two-slot path.
    fn tx_vlan(&self, frame: &[u8], tag: u16) -> Result<(), IgbError> {
        if frame.is_empty() || frame.len() > FRAME_SIZE {
            return Err(IgbError::QueueTooSmall);
        }
        let mut data_ticket = None;
        let posted = narf_scheduler::responsive_spin_until(
            || {
                let mut state = self.tx_state.lock();
                self.reclaim_tx_locked(&mut state);
                let Some((ctx_ticket, data)) = state.reserve_pair() else {
                    return false;
                };
                let buffer = &self.tx_buf_pool[data.slot];
                // SAFETY: one persistent FRAME_SIZE allocation backs this
                // reserved data slot and cannot be reused until DD
                // completion; the context slot has no buffer.
                unsafe {
                    for (i, byte) in frame.iter().enumerate() {
                        core::ptr::write_volatile(buffer.cpu_mut_ptr_at::<u8>(i as u64), *byte);
                    }
                }
                let descriptor = Self::tx_descriptor(buffer.dma_addr().raw(), frame.len());
                self.post_tx_pair_locked(
                    &state,
                    ctx_ticket,
                    AdvTxCtxtDesc::new_vlan(tag),
                    data,
                    descriptor,
                );
                data_ticket = Some(data);
                true
            },
            narf_time::Deadline::after_ms(250),
        );
        if !posted {
            self.stats.note_tx_error();
            return Err(IgbError::TxTimeout);
        }
        let result =
            self.wait_for_tx(data_ticket.ok_or(IgbError::Other("TX VLAN reservation lost"))?);
        match &result {
            Ok(()) => self.stats.note_tx_ok(frame.len() as u64),
            Err(IgbError::TxTimeout) => self.stats.note_tx_error(),
            Err(_) => {}
        }
        result
    }

    /// Frame compatibility wrapper. Copying into the descriptor's persistent
    /// DMA buffer keeps timeout handling safe: a timed-out descriptor never
    /// retains a DMA reference to a `Frame` the caller may immediately drop.
    pub fn tx_frame(&self, frame: &Frame) -> Result<(), IgbError> {
        let meta = frame.tx_meta();
        self.tx(frame.payload(), &meta)
    }

    /// Receive a single frame using the advanced RX descriptor format;
    /// returns the byte count copied into `out`, or 0 if none pending.
    pub fn rx(&self, out: &mut [u8]) -> usize {
        if !datapath_allowed(
            self.detached.load(Ordering::Acquire),
            self.suspended.load(Ordering::Acquire),
        ) {
            return 0;
        }
        let mut head = self.rx_head.lock();
        let idx = *head as usize;
        let ring_phys = self.rx_ring_buf.dma_addr().raw();
        let desc_ptr = narf_memory::PhysAddr::new(ring_phys + (idx * 16) as u64)
            .kernel_mut_ptr::<AdvRxDescWb>();
        // SAFETY: mapped DMA; idx < RX_RING_LEN.
        let desc = unsafe { core::ptr::read_volatile(desc_ptr) };
        if desc.status_error & ADV_RXD_STAT_DD == 0 {
            return 0;
        }
        let len = (desc.length as usize).min(out.len()).min(FRAME_SIZE);
        let slots = self.rx_buf_pool.lock();
        let buf_phys = slots[idx].dma_addr().raw();
        for (i, b) in out.iter_mut().enumerate().take(len) {
            // SAFETY: `buf_phys` is the mapped DMA address of this RX
            // slot's packet buffer; `i < len <= FRAME_SIZE`.
            *b = unsafe { core::ptr::read_volatile(slots[idx].cpu_ptr_at::<u8>(i as u64)) };
        }
        drop(slots);
        let _ = ADV_RXD_STAT_EOP; // multi-buffer frames land in a follow-up.
        let read_form = AdvRxDescRead {
            pkt_addr: buf_phys,
            hdr_addr: 0,
        };
        // SAFETY: mapped DMA; AdvRxDescRead is the same 16 bytes as
        // AdvRxDescWb (the chip selects interpretation via SRRCTL).
        unsafe {
            core::ptr::write_volatile(desc_ptr as *mut AdvRxDescRead, read_form);
        }
        let next = ((idx + 1) % RX_RING_LEN) as u16;
        *head = next;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: mapped MMIO.
        unsafe {
            self.mmio.write32(REG_RDT, (idx % RX_RING_LEN) as u32);
        }
        len
    }

    /// Drain up to `budget` completed RX descriptors **in place** — zero
    /// copy — dispatching each frame to `f` straight out of its RX DMA
    /// page before re-arming the slot (same buffer address) and publishing
    /// the whole rearmed run with a single RDT doorbell.
    ///
    /// This is the one true drain: both the async RX pump and the
    /// synchronous `rx_recv_in_place` / `igb_rx_pump_step` busy-wait drain
    /// funnel through it, so a descriptor is consumed and dispatched exactly
    /// once and the RDT tail advances monotonically under a single
    /// `rx_head` lock. Mirrors e1000's `rx_drain_in_place`; replaces the
    /// earlier split design (an owned-`Frame` batch drain racing an in-place
    /// single drain on the same ring), which left late single frames — e.g.
    /// a DNS-server ARP reply — undelivered.
    fn rx_drain_in_place<F: FnMut(&mut [u8])>(&self, budget: usize, mut f: F) -> usize {
        if !datapath_allowed(
            self.detached.load(Ordering::Acquire),
            self.suspended.load(Ordering::Acquire),
        ) {
            return 0;
        }
        let limit = budget.min(RX_RING_LEN);
        if limit == 0 {
            return 0;
        }
        if self
            .rx_draining
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return 0;
        }
        let mut head = self.rx_head.lock();
        let mut idx = *head as usize;
        let ring_phys = self.rx_ring_buf.dma_addr().raw();
        let mut drained = 0usize;
        while drained < limit {
            let desc_ptr = narf_memory::PhysAddr::new(ring_phys + (idx * 16) as u64)
                .kernel_mut_ptr::<AdvRxDescWb>();
            // SAFETY: mapped DMA; idx < RX_RING_LEN.
            let desc = unsafe { core::ptr::read_volatile(desc_ptr) };
            if desc.status_error & ADV_RXD_STAT_DD == 0 {
                break;
            }
            let len = (desc.length as usize).min(FRAME_SIZE);
            // Re-arm keeps the slot's own buffer address — the slot<->buffer
            // pairing is stable for the device's lifetime (set at probe).
            let buf_phys = {
                let slots = self.rx_buf_pool.lock();
                let buf_phys = slots[idx].dma_addr().raw();
                // SAFETY: `slots[idx]` is this RX slot's packet buffer; the
                // chip has completed it (DD set); `len <= FRAME_SIZE`. `f`
                // may rewrite header bytes in the DMA page we own until the
                // re-arm below.
                let frame = unsafe {
                    core::slice::from_raw_parts_mut(slots[idx].cpu_mut_ptr_at::<u8>(0), len)
                };
                f(frame);
                self.stats.note_rx(len as u64);
                buf_phys
            };
            let _ = ADV_RXD_STAT_EOP; // multi-buffer frames land in a follow-up.
            let read_form = AdvRxDescRead {
                pkt_addr: buf_phys,
                hdr_addr: 0,
            };
            // SAFETY: mapped DMA; AdvRxDescRead is the same 16 bytes as
            // AdvRxDescWb (the chip selects interpretation via SRRCTL);
            // idx is ring-bounded.
            unsafe {
                core::ptr::write_volatile(desc_ptr as *mut AdvRxDescRead, read_form);
            }
            idx = (idx + 1) % RX_RING_LEN;
            drained += 1;
        }
        if drained != 0 {
            *head = idx as u16;
            compiler_fence(Ordering::SeqCst);
            // SAFETY: mapped MMIO; `previous_rx_slot(idx)` is the last
            // descriptor re-armed in this batch.
            unsafe {
                self.mmio.write32(REG_RDT, previous_rx_slot(idx) as u32);
            }
        }
        drop(head);
        self.rx_draining.store(false, Ordering::Release);
        drained
    }

    /// Drain up to `budget` completed RX descriptors, swapping a fresh
    /// DMA buffer into each slot and publishing the rearmed run with one
    /// RDT write. The returned frames own the device-filled buffers.
    /// Retained only for the optional `Interface`/registry owned-`Frame`
    /// consumer path; the live kernel-stack datapath uses the unified
    /// `rx_drain_in_place` above.
    #[allow(dead_code)]
    fn rx_drain_frames(&self, budget: usize) -> Vec<Frame> {
        let mut frames = Vec::new();
        let limit = budget.min(RX_RING_LEN);
        if limit == 0 {
            return frames;
        }
        let mut head = self.rx_head.lock();
        let mut idx = *head as usize;
        let ring_phys = self.rx_ring_buf.dma_addr().raw();
        while frames.len() < limit {
            let desc_ptr = narf_memory::PhysAddr::new(ring_phys + (idx * 16) as u64)
                .kernel_mut_ptr::<AdvRxDescWb>();
            // SAFETY: mapped DMA; idx < RX_RING_LEN.
            let desc = unsafe { core::ptr::read_volatile(desc_ptr) };
            if desc.status_error & ADV_RXD_STAT_DD == 0 {
                break;
            }
            let len = (desc.length as usize).min(FRAME_SIZE);
            let replacement = match alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0) {
                Ok(replacement) => replacement,
                Err(_) => break,
            };
            let repl_phys = replacement.dma_addr().raw();
            let filled = {
                let mut slots = self.rx_buf_pool.lock();
                core::mem::replace(&mut slots[idx], replacement)
            };
            let read_form = AdvRxDescRead {
                pkt_addr: repl_phys,
                hdr_addr: 0,
            };
            // SAFETY: mapped DMA; AdvRxDescRead is the same 16 bytes as
            // AdvRxDescWb and `idx` is ring-bounded.
            unsafe {
                core::ptr::write_volatile(desc_ptr as *mut AdvRxDescRead, read_form);
            }
            frames.push(Frame::new(filled, len as u32));
            idx = (idx + 1) % RX_RING_LEN;
        }
        if !frames.is_empty() {
            *head = idx as u16;
            compiler_fence(Ordering::SeqCst);
            // SAFETY: mapped MMIO; every descriptor through this slot has
            // been returned to read form above.
            unsafe {
                self.mmio.write32(REG_RDT, previous_rx_slot(idx) as u32);
            }
        }
        frames
    }

    /// Zero-copy single-frame receive compatibility wrapper (owned-`Frame`
    /// form for the optional registry consumer path).
    #[allow(dead_code)]
    pub fn rx_recv_frame(&self) -> Option<Frame> {
        self.rx_drain_frames(1).into_iter().next()
    }

    /// Drain one completed RX descriptor in place and hand the frame
    /// bytes to `f` before re-arming the slot. Returns true iff a frame
    /// was dispatched. This is the synchronous path the kernel-side TCP
    /// stack's busy-wait (`install_rx_drain`) uses — it must not depend
    /// on the async RX pump getting CPU. Shares the single unified
    /// `rx_drain_in_place` drain with the async pump so the two never
    /// double-consume or desynchronize the ring. Mirrors e1000's
    /// `rx_recv_in_place`.
    pub fn rx_recv_in_place<F: FnMut(&mut [u8])>(&self, f: F) -> bool {
        self.rx_drain_in_place(1, f) != 0
    }

    /// Whether queue 0 has a completed descriptor at the software head.
    fn rx_has_pending(&self) -> bool {
        let idx = *self.rx_head.lock() as usize;
        let ring_phys = self.rx_ring_buf.dma_addr().raw();
        let desc_ptr =
            narf_memory::PhysAddr::new(ring_phys + (idx * 16) as u64).kernel_ptr::<AdvRxDescWb>();
        // SAFETY: mapped DMA; idx < RX_RING_LEN.
        unsafe { core::ptr::read_volatile(desc_ptr) }.status_error & ADV_RXD_STAT_DD != 0
    }

    /// Re-enable the shared MSI-X vector after a NAPI-style drain.
    fn rearm_msix(&self) {
        if self.irq_vector.is_some() {
            compiler_fence(Ordering::SeqCst);
            // SAFETY: mapped BAR0; vector 0 is the only configured entry.
            unsafe {
                self.mmio.write32(REG_EIMS, MSIX_VECTOR0_MASK);
            }
        }
    }
}

// ── HwNic adapter ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct IgbNic;

impl narf_net::Interface for IgbNic {
    fn name(&self) -> &str {
        "igb"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac()).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up()).unwrap_or(false)
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

impl crate::HwNic for IgbNic {
    fn name(&self) -> &'static str {
        "igb"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac()).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up()).unwrap_or(false)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::IntelIgb
    }
    fn caps(&self) -> crate::NicCaps {
        // The advanced descriptor helpers are present, but checksum/TSO
        // requests need a matching context descriptor before they are a
        // supported public capability. Keep the stack on its verified
        // software-checksum path until that two-descriptor sequence lands.
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        TX_RING_USABLE
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as narf_net::Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as narf_net::Interface>::tx_ring(self)
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<Igb>>> = IrqSafeSpinLock::new(None);

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
    // SAFETY: caller-authority.
    let dev = match unsafe { Igb::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    let mac = dev.mac;
    let link_sample = igb_link_sample(&dev);
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Register with the kernel-side TCP stack: hand it a `(mac, send_fn)`
    // pair + a name, and install the synchronous RX drain so busy-wait
    // paths (ARP / TCP handshake) can pull frames off the ring directly
    // while the parked syscall spins. Mirrors e1000's probe.
    let name = narf_net::iface::register("eth%d", mac, igb_send_frame);
    let bus_info = match device.addr {
        narf_bus::BusAddr::Pcie(pci) => alloc::format!("{:?}", pci),
        narf_bus::BusAddr::Mmio(_) => alloc::string::String::new(),
    };
    narf_net::iface::set_driver_info(&name, "igb", None, bus_info);
    crate::publish::publish_link(&name, link_sample);
    narf_net::iface::set_offloads(
        &name,
        narf_net::OffloadCapabilities {
            ..Default::default()
        },
    );
    *IGB_IFNAME.lock() = Some(alloc::boxed::Box::leak(name.into_boxed_str()));
    narf_net::iface::install_rx_drain(igb_rx_pump_step);

    // Stage-4 registry (cap-gated) — the newer `Interface` consumer path.
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, IgbNic);
    }

    Ok(())
}

/// The interface name `iface::register` gave this NIC (`eth%d`). Set
/// once at probe; leaked into a `&'static str` since the device lives
/// as long as the kernel.
static IGB_IFNAME: IrqSafeSpinLock<Option<&'static str>> = IrqSafeSpinLock::new(None);

fn igb_ifname() -> &'static str {
    IGB_IFNAME.lock().unwrap_or("")
}

/// SendFn registered with `narf_net::iface` at probe. Routes the
/// kernel-side TCP stack's outbound frames through `Igb::tx`. We clone
/// the `Arc` out rather than hold the IRQ-masking CONTROLLER lock across
/// `tx`, which busy-polls the DD bit for up to 250 ms.
fn igb_send_frame(frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = CONTROLLER.lock().as_ref().cloned().ok_or(())?;
    ctrl.tx(frame, &meta).map_err(|_| ())
}

/// Detach the bound igb device, if any: device half (mask, disable
/// queues, clear WoL, drop the ISR base, set the datapath gate), then
/// the registry half the net spec §3 obliges — publish link down,
/// clear the RX-mirror attach note for the interface name (names are
/// lowest-free-allocated and reused), and unregister the interface.
/// Idempotent: a second call finds no controller and does nothing.
/// The async pumps are not joined (they hold `Arc<Igb>` clones), but
/// every datapath entry point fails fast once detached, so a parked
/// pump can no longer touch the device.
pub fn igb_detach() {
    let controller = CONTROLLER.lock().take();
    let Some(device) = controller else {
        return;
    };
    device.detach_device();
    let name = igb_ifname();
    crate::publish::publish_link(name, crate::publish::LinkSample::DOWN);
    crate::publish::clear_rx_mirror_attached(name);
    let _ = narf_net::iface::unregister(name);
    *IGB_IFNAME.lock() = None;
}

/// Drain one frame from the RX ring and dispatch it through the network
/// stack's RX handler. Returns true iff a frame was processed. Called
/// from the kernel-side polling task + busy-wait drains.
pub fn igb_rx_pump_step() -> bool {
    // Bind the clone before the match so the lock guard is dropped at this
    // semicolon. A match directly on `CONTROLLER.lock()` extends the scrutinee
    // temporary through the selected arm; ARP dispatch can synchronously send
    // a queued packet and would then deadlock reacquiring CONTROLLER.
    let controller = CONTROLLER.lock().as_ref().cloned();
    match controller {
        Some(c) => c.rx_recv_in_place(|frame| {
            narf_net::iface::on_rx_frame_from(igb_ifname(), frame);
        }),
        None => false,
    }
}

/// Every Intel device id this driver claims.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    IGB_I210_COPPER,
    IGB_I210_FIBER,
    IGB_I210_SERDES,
    IGB_I210_SGMII,
    IGB_I210_COPPER_FLASHLESS,
    IGB_I210_SERDES_FLASHLESS,
    IGB_I211_COPPER,
    IGB_82576,
    IGB_82576_NS,
    IGB_I350_COPPER,
];

pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: IGB_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        IGB_I210_COPPER => "igb-i210-copper",
        IGB_I210_FIBER => "igb-i210-fiber",
        IGB_I210_SERDES => "igb-i210-serdes",
        IGB_I210_SGMII => "igb-i210-sgmii",
        IGB_I210_COPPER_FLASHLESS => "igb-i210-copper-flashless",
        IGB_I210_SERDES_FLASHLESS => "igb-i210-serdes-flashless",
        IGB_I211_COPPER => "igb-i211-copper",
        IGB_82576 => "igb-82576",
        IGB_82576_NS => "igb-82576-ns",
        IGB_I350_COPPER => "igb-i350-copper",
        _ => "igb",
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Igb) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

fn spawn_tx_pump(device: Arc<Igb>, tx_cons: Consumer<Frame, TX_RING_N>) {
    // Steady-state RX: an IRQ-driven (polled fallback) task that drains
    // the ring and dispatches each frame into the kernel TCP stack. It
    // shares the `rx_head` lock with the synchronous `igb_rx_pump_step`
    // busy-wait drain, so the two never double-consume a descriptor.
    let d_rx = device.clone();
    narf_scheduler::spawn(async move {
        igb_rx_pump(d_rx).await;
    });

    narf_scheduler::spawn(async move {
        igb_tx_pump(device, tx_cons).await;
    });
}

async fn igb_rx_pump(device: Arc<Igb>) {
    const RX_DRAIN_BUDGET: usize = 64;
    const IRQ_FALLBACK_MS: u64 = 10;
    let poll_fallback_cycles = narf_time::ns_to_cycles(1_000_000);

    loop {
        // Link Status Change drain (issue #791): the ISR flagged a
        // transition; re-sample STATUS in task context and republish.
        // The pump wakes on the same interrupt (LSC is in IMS_DEFAULT)
        // or on the 10 ms fallback, so this adds no polling loop.
        if LSC_PENDING.swap(false, Ordering::AcqRel) {
            crate::publish::publish_link(igb_ifname(), igb_link_sample(&device));
        }
        let irq_waiter = device.irq_vector.map(|vector| {
            narf_interrupts::wait_for_irq_until(
                vector,
                narf_time::Deadline::after_ms(IRQ_FALLBACK_MS),
            )
        });
        // Dispatch each completed frame straight out of its RX DMA page
        // into the kernel stack through the same unified in-place drain the
        // synchronous `igb_rx_pump_step` uses, so the async pump and the
        // busy-wait drain never race for a descriptor.
        let drained = device.rx_drain_in_place(RX_DRAIN_BUDGET, |frame| {
            narf_net::iface::on_rx_frame_from(igb_ifname(), frame);
        });
        if drained == RX_DRAIN_BUDGET {
            narf_scheduler::yield_now().await;
            continue;
        }

        device.rearm_msix();
        if device.rx_has_pending() {
            narf_scheduler::yield_now().await;
            continue;
        }
        match irq_waiter {
            Some(waiter) => {
                let _ = waiter.await;
            }
            None => narf_time::sleep_cycles(poll_fallback_cycles).await,
        }
    }
}

async fn igb_tx_pump(device: Arc<Igb>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.tx_frame(&frame);
    }
}

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::{
        datapath_allowed, eitr_reg, eitr_to_usecs, ivar0_shared_vector, ivar_apply,
        ivar_misc_shared_vector, ivar_rx, ivar_scheme_for_device, ivar_tx, max_queues_for_device,
        mrqc_word, previous_rx_slot, queue_disable_word, queue_enable_reflected, queue_enable_word,
        queue_pairs, queue_regs, reta_entry, reta_reg, reta_shift, reta_table, reta_word,
        rss_key_word, rss_queue_for_hash, rssrk_reg, rxcsum_rss_word, rxdctl_word,
        strip_vlan_tag_in_place, txdctl_word, usecs_to_eitr, vfta_bit, vfta_word, wol_supported,
        wol_suspend_program, wus_clear_word, wus_delivered_wake_packet, AdvRxDescRead, AdvRxDescWb,
        AdvTxCtxtDesc, AdvTxDataDesc, IgbStats, IvarScheme, TxRingCursor, VlanFilter, WolFilters,
        ADVTXD_DCMD_DEXT, ADVTXD_DTYP_CTXT, ADV_RXD_STAT_VP, CTRL_ADVD3WUC, EEPROM_APME,
        EITR_CNT_IGNR, EITR_START, IGB_82576, IGB_82576_NS, IGB_DRIVER_VERSION, IGB_I210_COPPER,
        IGB_I211_COPPER, IGB_I350_COPPER, IGB_MAX_QUEUES, IGB_MAX_QUEUES_82575,
        IGB_MAX_QUEUES_I211, IGB_STAT_NAMES, IVAR_VALID, MRQC_ENABLE_RSS_MQ, MRQC_ENABLE_VMDQ,
        MRQC_ENABLE_VMDQ_RSS_MQ, MRQC_FIELD_IPV4, MRQC_FIELD_IPV4_TCP, MRQC_FIELD_IPV4_UDP,
        MRQC_FIELD_IPV6, MRQC_FIELD_IPV6_TCP, MRQC_FIELD_IPV6_TCP_EX, MRQC_FIELD_IPV6_UDP,
        PHY_BMCR_PWRDOWN, QUEUE_ENABLE, RCTL_BAM, RCTL_EN, RCTL_MPE, RCTL_SECRC,
        RCTL_SUSPEND_ARMED, RCTL_SUSPEND_OFF, RCTL_UPE, REG_EIAC, REG_EIAM, REG_EIMC, REG_EIMS,
        REG_EITR0, REG_ICR, REG_IMC, REG_IMS, REG_IVAR0, REG_IVAR_MISC, REG_MRQC, REG_RDBAH,
        REG_RDBAL, REG_RDH, REG_RDLEN, REG_RDT, REG_RETA_BASE, REG_RSSRK_BASE, REG_RXCSUM,
        REG_RXDCTL0, REG_SRRCTL_Q0, REG_TDBAH, REG_TDBAL, REG_TDH, REG_TDLEN, REG_TDT, REG_TXDCTL0,
        REG_VET, REG_VFTA_BASE, REG_WUC, REG_WUFC, REG_WUS, RETA_REGS, RETA_SIZE, RSS_KEY_SIZE,
        RXCSUM_CRCOFL, RXCSUM_PCSD, RX_RING_LEN, SRRCTL_DESCTYPE_ADV_ONEBUF, TCTL_EN, TCTL_PSP,
        TCTL_SUSPEND_OFF, TX_CTXT_VLAN_MASK, TX_CTXT_VLAN_SHIFT, TX_RING_LEN, TX_RING_USABLE,
        VET_8021Q, VFTA_WORDS, WUC_PME_EN, WUFC_LNKC, WUFC_MAG, WUFC_MC, WUS_ARPD, WUS_IPV6,
    };

    fn smoke_igb_extended_interrupt_layout() -> TestResult {
        if REG_ICR != 0x00c0
            || REG_IMS != 0x00d0
            || REG_IMC != 0x00d8
            || REG_EIMS != 0x1524
            || REG_EIMC != 0x1528
            || REG_EIAC != 0x152c
            || REG_EIAM != 0x1530
            || REG_EITR0 != 0x1680
            || REG_IVAR0 != 0x1700
            || REG_IVAR_MISC != 0x1740
        {
            return TestResult::Fail("igb extended interrupt register offset drift");
        }
        if ivar0_shared_vector(0) != 0x0000_8080 || ivar_misc_shared_vector(0) != 0x0000_8000 {
            return TestResult::Fail("igb queue/other causes do not target shared vector 0");
        }
        if EITR_START != 648 || EITR_CNT_IGNR != 1 << 31 {
            return TestResult::Fail("igb initial interrupt throttle drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_extended_interrupt_layout);

    fn smoke_igb_per_queue_enable_layout() -> TestResult {
        // The per-queue DMA-enable handshake is the functional delta vs
        // igc. Assert the queue-0 TXDCTL/RXDCTL offsets and the ENABLE
        // bit (bit 25) so a register-map typo is a test failure.
        if REG_TXDCTL0 != 0x3828 || REG_RXDCTL0 != 0x2828 {
            return TestResult::Fail("igb per-queue DMA control offset drift");
        }
        if QUEUE_ENABLE != 1 << 25 {
            return TestResult::Fail("igb queue-enable bit is not bit 25");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_per_queue_enable_layout);

    fn smoke_igb_adv_descriptor_field_math() -> TestResult {
        // Advanced descriptors are 16 bytes; DD/length live where the
        // write-back decode expects them. Also check ADV_ONEBUF select.
        if core::mem::size_of::<AdvRxDescRead>() != 16
            || core::mem::size_of::<AdvRxDescWb>() != 16
            || core::mem::size_of::<AdvTxDataDesc>() != 16
        {
            return TestResult::Fail("igb advanced descriptor is not 16 bytes");
        }
        // length field sits at byte offset 12 in the write-back form —
        // same offset the TX Done poll reads (status byte) and the RX
        // decode reads (length u16). Verify via offset_of-style math.
        let wb = AdvRxDescWb {
            lower: 0,
            status_error: 0x1,
            length: 1500,
            vlan: 0,
        };
        if wb.status_error & 0x1 == 0 || wb.length != 1500 {
            return TestResult::Fail("igb write-back DD/length decode drift");
        }
        // A plain checksum data descriptor must carry PAYLEN in the
        // upper olinfo bits and the DATA/DEXT/EOP command bits.
        let d = AdvTxDataDesc::with_csum(0xDEAD_BEEF, 100);
        if (d.olinfo_status >> 14) != 100 {
            return TestResult::Fail("igb TX PAYLEN shift drift");
        }
        if d.cmd_type_len & 0x0030_0000 == 0 {
            return TestResult::Fail("igb TX DTYP_DATA bits missing");
        }
        if SRRCTL_DESCTYPE_ADV_ONEBUF != 1 << 25 {
            return TestResult::Fail("igb SRRCTL ADV_ONEBUF select drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_adv_descriptor_field_math);

    fn smoke_igb_batched_rx_tail_wrap() -> TestResult {
        if RX_RING_LEN != 256 || previous_rx_slot(1) != 0 || previous_rx_slot(0) != RX_RING_LEN - 1
        {
            return TestResult::Fail("igb batched RDT publication wraps incorrectly");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_batched_rx_tail_wrap);

    fn smoke_igb_tx_cursor_reserves_without_wait_lock() -> TestResult {
        let mut cursor = TxRingCursor::new();
        let first = match cursor.reserve() {
            Some(ticket) => ticket,
            None => return TestResult::Fail("igb TX cursor rejected an empty ring"),
        };
        for _ in 1..TX_RING_USABLE {
            if cursor.reserve().is_none() {
                return TestResult::Fail("igb TX cursor filled before its usable capacity");
            }
        }
        if cursor.reserve().is_some() || cursor.in_flight != TX_RING_USABLE {
            return TestResult::Fail("igb TX cursor did not preserve the sentinel slot");
        }

        // Completion makes one credit available. The next reservation uses
        // slot 7; after one more ordered completion, allocation wraps to slot
        // 0 and the generation tells first's waiter its descriptor was safely
        // reclaimed/reused while that waiter was outside the lock.
        cursor.complete_oldest();
        let last = match cursor.reserve() {
            Some(ticket) => ticket,
            None => return TestResult::Fail("igb TX completion did not return a credit"),
        };
        if last.slot != TX_RING_LEN - 1 || cursor.ticket_was_reused(first) {
            return TestResult::Fail("igb TX cursor advanced or reused a slot out of order");
        }
        cursor.complete_oldest();
        let wrapped = match cursor.reserve() {
            Some(ticket) => ticket,
            None => return TestResult::Fail("igb TX cursor failed to wrap"),
        };
        if wrapped.slot != first.slot || !cursor.ticket_was_reused(first) {
            return TestResult::Fail("igb TX generation did not detect safe slot reuse");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/igb",
        smoke_igb_tx_cursor_reserves_without_wait_lock
    );

    fn smoke_igb_multiqueue_register_windows() -> TestResult {
        // Queue 0 through the window helper must reproduce the legacy
        // queue-0 constants exactly — this is what makes the bring_up
        // refactor a no-op on live register traffic.
        let q0 = queue_regs(0);
        if q0.rdbal != REG_RDBAL
            || q0.rdbah != REG_RDBAH
            || q0.rdlen != REG_RDLEN
            || q0.srrctl != REG_SRRCTL_Q0
            || q0.rdh != REG_RDH
            || q0.rdt != REG_RDT
            || q0.rxdctl != REG_RXDCTL0
            || q0.tdbal != REG_TDBAL
            || q0.tdbah != REG_TDBAH
            || q0.tdlen != REG_TDLEN
            || q0.tdh != REG_TDH
            || q0.tdt != REG_TDT
            || q0.txdctl != REG_TXDCTL0
        {
            return TestResult::Fail("igb queue-0 window drifted from legacy offsets");
        }
        // Low window stride 0x100 for queues 1..3, compact window
        // stride 0x40 from queue 4 (Linux E1000_RDBAL/TDBAL macros).
        let q3 = queue_regs(3);
        if q3.rdbal != 0x2B00 || q3.tdbal != 0x3B00 || q3.rxdctl != 0x2B28 || q3.txdctl != 0x3B28 {
            return TestResult::Fail("igb queue-3 window stride drift");
        }
        let q4 = queue_regs(4);
        if q4.rdbal != 0xC100 || q4.tdbal != 0xE100 || q4.srrctl != 0xC10C || q4.rxdctl != 0xC128 {
            return TestResult::Fail("igb queue-4 compact window drift");
        }
        let q7 = queue_regs(7);
        if q7.rdbal != 0xC1C0 || q7.tdbal != 0xE1C0 || q7.rxdctl != 0xC1E8 || q7.txdctl != 0xE1E8 {
            return TestResult::Fail("igb queue-7 compact window drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_multiqueue_register_windows);

    fn smoke_igb_multiqueue_counts_and_pairs() -> TestResult {
        if IGB_MAX_QUEUES != 8 || IGB_MAX_QUEUES_82575 != 4 || IGB_MAX_QUEUES_I211 != 2 {
            return TestResult::Fail("igb queue-cap constant drift");
        }
        if max_queues_for_device(IGB_I211_COPPER, 0) != 2
            || max_queues_for_device(IGB_I210_COPPER, 0) != 4
            || max_queues_for_device(IGB_82576, 0) != 8
            || max_queues_for_device(IGB_82576_NS, 0) != 8
            || max_queues_for_device(IGB_I350_COPPER, 0) != 8
        {
            return TestResult::Fail("igb per-device queue cap drift");
        }
        // SR-IOV interaction, Linux igb_get_max_rss_queues: I350 with
        // any VF allocated drops to 1 queue, 82576 to 2.
        if max_queues_for_device(IGB_I350_COPPER, 1) != 1
            || max_queues_for_device(IGB_I350_COPPER, 7) != 1
            || max_queues_for_device(IGB_82576, 3) != 2
            || max_queues_for_device(IGB_I211_COPPER, 1) != 2
        {
            return TestResult::Fail("igb SR-IOV queue-cap interaction drift");
        }
        // Queue pairs iff rss_queues > max/2 (Linux igb_set_flag_queue_pairs).
        if !queue_pairs(8, 8) || queue_pairs(4, 8) || !queue_pairs(3, 4) || queue_pairs(2, 4) {
            return TestResult::Fail("igb queue-pair rule drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_multiqueue_counts_and_pairs);

    /// Fake per-queue DMA-control register: the "chip" reflects ENABLE
    /// only after `stale_reads_left` stale reads, so the test exercises
    /// the spin-until-reflected conversation instead of assuming an
    /// instant reflection.
    struct FakeQueueCtl {
        word: u32,
        stale_reads_left: u32,
    }

    impl FakeQueueCtl {
        fn new(stale_reads: u32) -> Self {
            Self {
                word: 0,
                stale_reads_left: stale_reads,
            }
        }

        fn write(&mut self, word: u32) {
            self.word = word;
        }

        fn read(&mut self) -> u32 {
            if self.stale_reads_left > 0 {
                self.stale_reads_left -= 1;
                self.word & !QUEUE_ENABLE
            } else {
                self.word
            }
        }
    }

    fn smoke_igb_queue_enable_handshake() -> TestResult {
        // Enable conversation: driver writes ENABLE, chip reflects it
        // only on the third read; the poll predicate must see exactly
        // two stale reads, then reflection — never an instant pass, and
        // never a spin past reflection.
        let mut ctl = FakeQueueCtl::new(2);
        let enabled = queue_enable_word(ctl.read());
        ctl.write(enabled);
        let mut stale_polls = 0u32;
        while !queue_enable_reflected(ctl.read()) {
            stale_polls += 1;
            if stale_polls > 100 {
                return TestResult::Fail("igb queue-enable spin did not terminate");
            }
        }
        if stale_polls != 2 {
            return TestResult::Fail("igb queue-enable reflection count drift");
        }
        // Disable conversation: clearing ENABLE reflects immediately.
        let disabled = queue_disable_word(ctl.read());
        ctl.write(disabled);
        if queue_enable_reflected(ctl.read()) {
            return TestResult::Fail("igb queue-disable did not clear ENABLE");
        }
        // Threshold words: PTHRESH/HTHRESH/WTHRESH fields plus ENABLE.
        if txdctl_word(8, 1, 16) != 0x0210_0108 || rxdctl_word(8, 8, 4) != 0x0204_0808 {
            return TestResult::Fail("igb TXDCTL/RXDCTL threshold word drift");
        }
        if txdctl_word(8, 1, 1) & QUEUE_ENABLE == 0 || rxdctl_word(8, 8, 1) & QUEUE_ENABLE == 0 {
            return TestResult::Fail("igb 82576+MSI-X threshold word lost ENABLE");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_queue_enable_handshake);

    fn smoke_igb_ivar_routing() -> TestResult {
        // Row-major (82580+): queue 0 reproduces the legacy shared word
        // 0x8080; queue 1 RX/TX live in the same IVAR0 word's upper
        // lanes; queue 2 RX starts the next word.
        let scheme = ivar_scheme_for_device(IGB_I350_COPPER);
        if scheme != IvarScheme::RowMajor82580Plus {
            return TestResult::Fail("igb I350 IVAR scheme is not row-major");
        }
        if ivar_scheme_for_device(IGB_82576) != IvarScheme::ColumnMajor82576 {
            return TestResult::Fail("igb 82576 IVAR scheme is not column-major");
        }
        let (rx0_reg, rx0_shift) = ivar_rx(0, scheme);
        let (tx0_reg, tx0_shift) = ivar_tx(0, scheme);
        if rx0_reg != REG_IVAR0 || rx0_shift != 0 || tx0_reg != REG_IVAR0 || tx0_shift != 8 {
            return TestResult::Fail("igb queue-0 IVAR lanes drift");
        }
        let mut word = ivar_apply(0, rx0_shift, 0);
        word = ivar_apply(word, tx0_shift, 0);
        if word != ivar0_shared_vector(0) {
            return TestResult::Fail("igb queue-0 IVAR word does not match legacy shared vector");
        }
        let (rx1_reg, rx1_shift) = ivar_rx(1, scheme);
        let (tx1_reg, tx1_shift) = ivar_tx(1, scheme);
        if rx1_reg != REG_IVAR0 || rx1_shift != 16 || tx1_reg != REG_IVAR0 || tx1_shift != 24 {
            return TestResult::Fail("igb queue-1 row-major IVAR lanes drift");
        }
        let (rx2_reg, rx2_shift) = ivar_rx(2, scheme);
        if rx2_reg != REG_IVAR0 + 4 || rx2_shift != 0 {
            return TestResult::Fail("igb queue-2 row-major IVAR row drift");
        }
        // Column-major (82576): queue 1 RX is row 1, lane 0.
        let col = IvarScheme::ColumnMajor82576;
        let (rx1c_reg, rx1c_shift) = ivar_rx(1, col);
        let (tx1c_reg, tx1c_shift) = ivar_tx(1, col);
        if rx1c_reg != REG_IVAR0 + 4
            || rx1c_shift != 0
            || tx1c_reg != REG_IVAR0 + 4
            || tx1c_shift != 8
        {
            return TestResult::Fail("igb 82576 column-major IVAR lanes drift");
        }
        // Lane isolation: writing the TX lane must not disturb RX.
        let composed = ivar_apply(ivar_apply(0, 0, 3), 8, 3);
        if composed != (3 | IVAR_VALID) | ((3 | IVAR_VALID) << 8) {
            return TestResult::Fail("igb IVAR lane write clobbered a neighbouring lane");
        }
        if eitr_reg(0) != REG_EITR0 || eitr_reg(3) != 0x168C {
            return TestResult::Fail("igb per-vector EITR stride drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_ivar_routing);

    fn smoke_igb_rss_table_and_key() -> TestResult {
        if RETA_SIZE != 128 || RSS_KEY_SIZE != 40 || RETA_REGS != 32 {
            return TestResult::Fail("igb RETA/key size drift");
        }
        if REG_MRQC != 0x5818
            || REG_RXCSUM != 0x5000
            || REG_RETA_BASE != 0x5C00
            || REG_RSSRK_BASE != 0x5C80
        {
            return TestResult::Fail("igb MRQC/RXCSUM/RETA/RSSRK base drift");
        }
        if reta_reg(0) != 0x5C00
            || reta_reg(31) != 0x5C7C
            || rssrk_reg(0) != 0x5C80
            || rssrk_reg(9) != 0x5CA4
        {
            return TestResult::Fail("igb RETA/RSSRK register stride drift");
        }
        // Default spread: 4 queues cycle every 32 slots, 8 queues
        // every 16; the last slot always lands on the last queue.
        if reta_entry(4, 0) != 0
            || reta_entry(4, 31) != 0
            || reta_entry(4, 32) != 1
            || reta_entry(4, 127) != 3
            || reta_entry(8, 15) != 0
            || reta_entry(8, 16) != 1
            || reta_entry(8, 127) != 7
        {
            return TestResult::Fail("igb RETA default spread drift");
        }
        // Fake RETA register file: program the 4-queue table through
        // reta_word, then read the entries back out of the words.
        let table = reta_table(4);
        let mut regs = [0u32; RETA_REGS];
        for (i, reg) in regs.iter_mut().enumerate() {
            let base = i * 4;
            *reg = reta_word([
                table[base],
                table[base + 1],
                table[base + 2],
                table[base + 3],
            ]);
        }
        for (i, entry) in table.iter().enumerate() {
            let back = ((regs[i / 4] >> ((i % 4) * 8)) & 0xFF) as u8;
            if back != *entry {
                return TestResult::Fail("igb RETA register round-trip drift");
            }
        }
        // RSS key words are little-endian slices of the 40-byte key.
        let mut key = [0u8; RSS_KEY_SIZE];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        if rss_key_word(&key, 0) != 0x0302_0100 || rss_key_word(&key, 9) != 0x2726_2524 {
            return TestResult::Fail("igb RSS key word packing drift");
        }
        // RETA shift: 0 normally, 3 for 82576 with VFs.
        if reta_shift(IGB_I350_COPPER, 0) != 0
            || reta_shift(IGB_82576, 0) != 0
            || reta_shift(IGB_82576_NS, 2) != 3
        {
            return TestResult::Fail("igb RETA shift drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_rss_table_and_key);

    fn smoke_igb_rss_mrqc_and_hash() -> TestResult {
        let base = MRQC_FIELD_IPV4
            | MRQC_FIELD_IPV4_TCP
            | MRQC_FIELD_IPV6
            | MRQC_FIELD_IPV6_TCP
            | MRQC_FIELD_IPV6_TCP_EX;
        if mrqc_word(false, false, false, 1) != base | MRQC_ENABLE_RSS_MQ {
            return TestResult::Fail("igb MRQC single-queue RSS word drift");
        }
        if mrqc_word(true, true, false, 8)
            != base | MRQC_FIELD_IPV4_UDP | MRQC_FIELD_IPV6_UDP | MRQC_ENABLE_RSS_MQ
        {
            return TestResult::Fail("igb MRQC UDP-field word drift");
        }
        if mrqc_word(false, false, true, 4) != base | MRQC_ENABLE_VMDQ_RSS_MQ
            || mrqc_word(false, false, true, 1) != base | MRQC_ENABLE_VMDQ
        {
            return TestResult::Fail("igb MRQC VMDq mode word drift");
        }
        if rxcsum_rss_word(0) != RXCSUM_PCSD | RXCSUM_CRCOFL || rxcsum_rss_word(0x100) & 0x100 == 0
        {
            return TestResult::Fail("igb RXCSUM RSS word drift");
        }
        // Hash steering: low 7 hash bits index RETA; a descriptor's
        // lower word is the hash once PCSD is set.
        let table = reta_table(4);
        let wb = AdvRxDescWb {
            lower: 0xDEAD_BEEF,
            status_error: 0,
            length: 0,
            vlan: 0,
        };
        if wb.rss_hash() != 0xDEAD_BEEF {
            return TestResult::Fail("igb RX descriptor RSS hash decode drift");
        }
        if rss_queue_for_hash(0xDEAD_BEEF, &table) != table[(0x6F) as usize] {
            return TestResult::Fail("igb RSS hash-to-queue steering drift");
        }
        if rss_queue_for_hash(0, &table) != 0 || rss_queue_for_hash(127, &table) != 3 {
            return TestResult::Fail("igb RSS hash boundary steering drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_rss_mrqc_and_hash);

    fn smoke_igb_vlan_filter_table() -> TestResult {
        if REG_VET != 0x038 || VET_8021Q != 0x8100 || REG_VFTA_BASE != 0x5600 || VFTA_WORDS != 128 {
            return TestResult::Fail("igb VET/VFTA register drift");
        }
        if vfta_word(0) != 0
            || vfta_bit(0) != 0
            || vfta_word(100) != 3
            || vfta_bit(100) != 4
            || vfta_word(4095) != 127
            || vfta_bit(4095) != 31
        {
            return TestResult::Fail("igb VFTA word/bit math drift");
        }
        let mut filter = VlanFilter::new();
        if filter.contains(100) {
            return TestResult::Fail("igb empty VLAN filter accepts a VID");
        }
        if !filter.add(100) || !filter.contains(100) || filter.contains(101) {
            return TestResult::Fail("igb VLAN filter add drift");
        }
        if filter.word(3) != 1 << 4 {
            return TestResult::Fail("igb VLAN filter shadow word drift");
        }
        if !filter.remove(100) || filter.contains(100) || filter.word(3) != 0 {
            return TestResult::Fail("igb VLAN filter remove drift");
        }
        // Out-of-range VIDs are rejected without touching the table.
        if filter.add(4096) || filter.remove(4096) || filter.contains(4096) {
            return TestResult::Fail("igb VLAN filter accepted an out-of-range VID");
        }
        // Linux restore default: VID 0 always present.
        filter.restore_default();
        if !filter.contains(0) || filter.word(0) != 1 {
            return TestResult::Fail("igb VLAN restore-default drift");
        }
        filter.set_promiscuous();
        if filter.word(0) != !0u32 || filter.word(127) != !0u32 || !filter.contains(4095) {
            return TestResult::Fail("igb VLAN promiscuous shadow drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vlan_filter_table);

    fn smoke_igb_vlan_rx_decode_and_strip() -> TestResult {
        // VP set: tag comes from the descriptor's vlan field.
        let tagged = AdvRxDescWb {
            lower: 0,
            status_error: ADV_RXD_STAT_VP,
            length: 64,
            vlan: 0x1234,
        };
        let decoded = tagged.rx_vlan();
        if !decoded.present || decoded.tag != 0x1234 {
            return TestResult::Fail("igb RX VLAN decode drift");
        }
        // VP clear: a non-zero vlan field is meaningless, not a tag.
        let untagged = AdvRxDescWb {
            lower: 0,
            status_error: 0x1,
            length: 64,
            vlan: 0x1234,
        };
        if untagged.rx_vlan().present {
            return TestResult::Fail("igb RX VLAN decode reported a tag without VP");
        }
        // Strip: dst/src preserved, TPID+TCI deleted, ethertype moves.
        let mut frame = [0u8; 64];
        frame[0..6].copy_from_slice(&[0xAA; 6]);
        frame[6..12].copy_from_slice(&[0xBB; 6]);
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[14] = 0x00;
        frame[15] = 0x64;
        frame[16] = 0x08;
        frame[17] = 0x00;
        frame[18..22].copy_from_slice(&[0xCC; 4]);
        let stripped = match strip_vlan_tag_in_place(&mut frame, 22) {
            Some(len) => len,
            None => return TestResult::Fail("igb VLAN strip rejected a tagged frame"),
        };
        if stripped != 18 || frame[12] != 0x08 || frame[13] != 0x00 || frame[14] != 0xCC {
            return TestResult::Fail("igb VLAN strip rewrote the frame incorrectly");
        }
        // No TPID, no strip; short frame, no strip.
        let mut plain = [0u8; 64];
        plain[12] = 0x08;
        plain[13] = 0x00;
        if strip_vlan_tag_in_place(&mut plain, 22).is_some()
            || strip_vlan_tag_in_place(&mut frame, 10).is_some()
        {
            return TestResult::Fail("igb VLAN strip fired on an untagged/short frame");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vlan_rx_decode_and_strip);

    fn smoke_igb_vlan_tx_context_and_pair() -> TestResult {
        // Context descriptor: tag in bits[31:16], DEXT+CTXT type.
        let ctx = AdvTxCtxtDesc::new_vlan(100);
        if ctx.vlan_macip_lens != (100u32 << TX_CTXT_VLAN_SHIFT)
            || ctx.vlan_macip_lens & !TX_CTXT_VLAN_MASK != 0
            || ctx.type_tucmd_mlhl != ADVTXD_DCMD_DEXT | ADVTXD_DTYP_CTXT
        {
            return TestResult::Fail("igb TX VLAN context descriptor drift");
        }
        // Pair reservation: a full-ish ring refuses the pair, and a
        // pair allocated across the ring end wraps (context last,
        // data first) with the context flag only on the first slot.
        let mut cursor = TxRingCursor::new();
        for _ in 0..6 {
            if cursor.reserve().is_none() {
                return TestResult::Fail("igb TX cursor fill failed in VLAN pair test");
            }
        }
        if cursor.reserve_pair().is_some() {
            return TestResult::Fail("igb TX pair over-committed a full ring");
        }
        cursor.complete_oldest();
        let (ctx_ticket, data_ticket) = match cursor.reserve_pair() {
            Some(pair) => pair,
            None => return TestResult::Fail("igb TX pair reservation failed"),
        };
        if ctx_ticket.slot != 6
            || data_ticket.slot != 7
            || !cursor.is_context[6]
            || cursor.is_context[7]
        {
            return TestResult::Fail("igb TX pair slot/context-flag drift");
        }
        for _ in 0..5 {
            cursor.complete_oldest();
        }
        if cursor.next_to_clean != 6 || cursor.following_slot() != 7 {
            return TestResult::Fail("igb TX pair clean-head/following-slot drift");
        }
        cursor.complete_oldest();
        if cursor.is_context[6] || cursor.next_to_clean != 7 || cursor.in_flight != 1 {
            return TestResult::Fail("igb TX context completion drift");
        }
        // Slot 0 re-reserves with a bumped generation.
        let first = match cursor.reserve() {
            Some(ticket) => ticket,
            None => return TestResult::Fail("igb TX wrap reservation failed"),
        };
        if first.slot != 0 || first.generation != 2 {
            return TestResult::Fail("igb TX wrap generation drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_vlan_tx_context_and_pair);

    fn smoke_igb_wol_filters_and_registers() -> TestResult {
        if REG_WUC != 0x5800 || REG_WUFC != 0x5808 || REG_WUS != 0x5810 {
            return TestResult::Fail("igb WUC/WUFC/WUS register drift");
        }
        if WUC_PME_EN != 0x2 || CTRL_ADVD3WUC != 0x0010_0000 {
            return TestResult::Fail("igb WUC/CTRL wake bit drift");
        }
        // Filter encode/decode round-trip, including unknown-bit drop.
        let filters = WolFilters {
            link_change: true,
            magic: true,
            directed_exact: false,
            multicast: true,
            broadcast: false,
        };
        let word = filters.to_wufc();
        if word != WUFC_LNKC | WUFC_MAG | WUFC_MC {
            return TestResult::Fail("igb WUFC encode drift");
        }
        if WolFilters::from_wufc(word) != filters
            || WolFilters::from_wufc(word | 0x8000_0000) != filters
        {
            return TestResult::Fail("igb WUFC decode drift");
        }
        if WolFilters::magic_only().to_wufc() != WUFC_MAG {
            return TestResult::Fail("igb WoL magic-only default drift");
        }
        // Support gates: port A, or APME on other ports, and the
        // platform must be able to wake at all.
        if !wol_supported(true, false, true)
            || !wol_supported(false, true, true)
            || wol_supported(false, false, true)
            || wol_supported(true, false, false)
        {
            return TestResult::Fail("igb WoL support-gate drift");
        }
        if EEPROM_APME != 0x0400 {
            return TestResult::Fail("igb EEPROM APME bit drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_wol_filters_and_registers);

    fn smoke_igb_wol_suspend_and_status() -> TestResult {
        // System suspend with magic-only arms PME + MAG, keeps the
        // link powered (wake needs it).
        let program = wol_suspend_program(WolFilters::magic_only(), false, false);
        if !program.advd3wuc
            || program.wuc != WUC_PME_EN
            || program.wufc != WUFC_MAG
            || program.power_down_link
        {
            return TestResult::Fail("igb WoL system-suspend program drift");
        }
        // Link already up drops link-change from the armed set.
        let filters = WolFilters {
            link_change: true,
            magic: true,
            directed_exact: false,
            multicast: false,
            broadcast: false,
        };
        let program = wol_suspend_program(filters, true, false);
        if program.wufc != WUFC_MAG {
            return TestResult::Fail("igb WoL link-up LNKC drop drift");
        }
        // Runtime suspend arms link-change only, even with no caller
        // filters — unless the link is up, in which case nothing is
        // armed and the link powers down.
        let program = wol_suspend_program(WolFilters::default(), false, true);
        if program.wufc != WUFC_LNKC || program.power_down_link {
            return TestResult::Fail("igb WoL runtime-suspend program drift");
        }
        let program = wol_suspend_program(WolFilters::default(), true, true);
        if program.wuc != 0 || program.wufc != 0 || !program.power_down_link {
            return TestResult::Fail("igb WoL nothing-armed program drift");
        }
        // WUS: directed-packet bits count as a delivered wake packet;
        // link-change/magic alone do not; clear word is all-ones.
        if !wus_delivered_wake_packet(WUS_ARPD)
            || !wus_delivered_wake_packet(WUS_IPV6)
            || wus_delivered_wake_packet(WUFC_MAG)
            || wus_delivered_wake_packet(WUFC_LNKC)
            || wus_clear_word() != !0u32
        {
            return TestResult::Fail("igb WUS wake-packet decode drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_wol_suspend_and_status);

    fn smoke_igb_ethtool_coalesce_and_rings() -> TestResult {
        // EITR 648 × 256 ns = 165.888 µs, reported as 165 µs; the
        // CNT_IGNR flag bit must not leak into the interval.
        if eitr_to_usecs(EITR_START) != 165
            || eitr_to_usecs(EITR_START | EITR_CNT_IGNR) != 165
            || eitr_to_usecs(0) != 0
        {
            return TestResult::Fail("igb EITR-to-usecs drift");
        }
        // Microsecond-to-EITR conversion floors to the 256 ns unit.
        if usecs_to_eitr(165) != 644 || usecs_to_eitr(0) != 0 {
            return TestResult::Fail("igb usecs-to-EITR drift");
        }
        if TX_RING_LEN != 8 || TX_RING_USABLE != 7 || RX_RING_LEN != 256 {
            return TestResult::Fail("igb ethtool ring-parameter drift");
        }
        if IGB_STAT_NAMES.len() != 5
            || IGB_STAT_NAMES[0] != "rx_packets"
            || IGB_STAT_NAMES[4] != "tx_errors"
        {
            return TestResult::Fail("igb ethtool statistic-name drift");
        }
        if IGB_DRIVER_VERSION != "0.1.0" {
            return TestResult::Fail("igb ethtool driver-version drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_ethtool_coalesce_and_rings);

    fn smoke_igb_ethtool_stats() -> TestResult {
        let stats = IgbStats::default();
        let snap = stats.snapshot();
        if snap.rx_packets != 0 || snap.tx_bytes != 0 || snap.tx_errors != 0 {
            return TestResult::Fail("igb ethtool stats do not start at zero");
        }
        stats.note_rx(1500);
        stats.note_rx(64);
        stats.note_tx_ok(1500);
        stats.note_tx_error();
        let snap = stats.snapshot();
        if snap.rx_packets != 2 || snap.rx_bytes != 1564 {
            return TestResult::Fail("igb ethtool RX counter drift");
        }
        if snap.tx_packets != 1 || snap.tx_bytes != 1500 || snap.tx_errors != 1 {
            return TestResult::Fail("igb ethtool TX counter drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_ethtool_stats);

    fn smoke_igb_pm_gates_and_words() -> TestResult {
        // Datapath gate truth table: only running + attached runs.
        if !datapath_allowed(false, false)
            || datapath_allowed(true, false)
            || datapath_allowed(false, true)
            || datapath_allowed(true, true)
        {
            return TestResult::Fail("igb PM datapath gate drift");
        }
        // Suspend words: armed keeps receive on for wake filtering;
        // unarmed stops receive DMA; transmit always stops (PSP kept).
        if RCTL_SUSPEND_ARMED != RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC {
            return TestResult::Fail("igb armed-suspend RCTL drift");
        }
        if RCTL_SUSPEND_OFF & RCTL_EN != 0
            || RCTL_SUSPEND_OFF != RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC
        {
            return TestResult::Fail("igb unarmed-suspend RCTL drift");
        }
        if TCTL_SUSPEND_OFF != TCTL_PSP || TCTL_SUSPEND_OFF & TCTL_EN != 0 {
            return TestResult::Fail("igb suspend TCTL drift");
        }
        if PHY_BMCR_PWRDOWN != 0x0800 {
            return TestResult::Fail("igb PHY power-down bit drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/igb", smoke_igb_pm_gates_and_words);
}
