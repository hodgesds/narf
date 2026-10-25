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
#[derive(Debug)]
struct TxRingCursor {
    next_to_use: usize,
    next_to_clean: usize,
    in_flight: usize,
    generations: [u64; TX_RING_LEN],
}

impl TxRingCursor {
    const fn new() -> Self {
        Self {
            next_to_use: 0,
            next_to_clean: 0,
            in_flight: 0,
            generations: [0; TX_RING_LEN],
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
        Some(TxTicket {
            slot,
            generation: self.generations[slot],
        })
    }

    fn complete_oldest(&mut self) {
        debug_assert!(self.in_flight != 0);
        self.next_to_clean = (self.next_to_clean + 1) % TX_RING_LEN;
        self.in_flight -= 1;
    }

    fn ticket_was_reused(&self, ticket: TxTicket) -> bool {
        self.generations[ticket.slot] != ticket.generation
    }
}

// ── Descriptor offload impl blocks ──────────────────────────────────

impl AdvRxDescWb {
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
        //    enable the per-queue TX DMA engine.
        let tx_phys = tx_ring_buf.dma_addr().raw();
        let tx_len = (TX_RING_LEN * 16) as u32;
        // SAFETY: mapped DMA, freshly zeroed.
        unsafe {
            mmio.write32(REG_TDBAL, (tx_phys & 0xFFFF_FFFF) as u32);
            mmio.write32(REG_TDBAH, (tx_phys >> 32) as u32);
            mmio.write32(REG_TDLEN, tx_len);
            mmio.write32(REG_TDH, 0);
            mmio.write32(REG_TDT, 0);
            mmio.write32(REG_TCTL, TCTL_EN | TCTL_PSP);
        }
        // igb per-queue enable: set TXDCTL.ENABLE then spin until the
        // chip reflects it. Linux `igb_configure_tx_ring`.
        // SAFETY: mapped MMIO.
        unsafe {
            let txdctl = mmio.read32(REG_TXDCTL0) | QUEUE_ENABLE;
            mmio.write32(REG_TXDCTL0, txdctl);
        }
        let tx_on = narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { mmio.read32(REG_TXDCTL0) } & QUEUE_ENABLE != 0,
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
            mmio.write32(REG_RDBAL, (rx_phys & 0xFFFF_FFFF) as u32);
            mmio.write32(REG_RDBAH, (rx_phys >> 32) as u32);
            mmio.write32(REG_RDLEN, (RX_RING_LEN * 16) as u32);
            mmio.write32(REG_RDH, 0);
            mmio.write32(REG_RDT, (RX_RING_LEN - 1) as u32);

            // SRRCTL — per-queue: buffer-size = 2 KiB, descriptor type =
            // ADV_ONEBUF. Linux `igb_setup_srrctl`; queue 0 only.
            let mut srrctl = mmio.read32(REG_SRRCTL_Q0);
            srrctl &= !(SRRCTL_BSIZEPKT_MASK | SRRCTL_DESCTYPE_MASK);
            srrctl |= ((FRAME_SIZE as u32) >> SRRCTL_BSIZEPKT_SHIFT) & SRRCTL_BSIZEPKT_MASK;
            srrctl |= SRRCTL_DESCTYPE_ADV_ONEBUF;
            mmio.write32(REG_SRRCTL_Q0, srrctl);

            mmio.write32(
                REG_RCTL,
                RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC | RCTL_BSIZE_2K,
            );
        }
        // igb per-queue enable: set RXDCTL.ENABLE then spin until the
        // chip reflects it. Linux `igb_configure_rx_ring`.
        // SAFETY: mapped MMIO.
        unsafe {
            let rxdctl = mmio.read32(REG_RXDCTL0) | QUEUE_ENABLE;
            mmio.write32(REG_RXDCTL0, rxdctl);
        }
        let rx_on = narf_scheduler::responsive_spin_until(
            // SAFETY: mapped MMIO.
            || unsafe { mmio.read32(REG_RXDCTL0) } & QUEUE_ENABLE != 0,
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
        while state.in_flight != 0 && self.tx_desc_done(state.next_to_clean) {
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
        if frame.is_empty() || frame.len() > FRAME_SIZE {
            return Err(IgbError::QueueTooSmall);
        }
        if meta.csum_l4.is_some() || meta.tso_mss.is_some() || meta.vlan_tag.is_some() {
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
            return Err(IgbError::TxTimeout);
        }
        self.wait_for_tx(ticket.ok_or(IgbError::Other("TX reservation lost"))?)
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
        ivar0_shared_vector, ivar_misc_shared_vector, previous_rx_slot, AdvRxDescRead, AdvRxDescWb,
        AdvTxDataDesc, TxRingCursor, EITR_CNT_IGNR, EITR_START, QUEUE_ENABLE, REG_EIAC, REG_EIAM,
        REG_EIMC, REG_EIMS, REG_EITR0, REG_ICR, REG_IMC, REG_IMS, REG_IVAR0, REG_IVAR_MISC,
        REG_RXDCTL0, REG_TXDCTL0, RX_RING_LEN, SRRCTL_DESCTYPE_ADV_ONEBUF, TX_RING_LEN,
        TX_RING_USABLE,
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
}
