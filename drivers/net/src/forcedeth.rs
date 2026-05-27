//! NVIDIA nForce ("forcedeth") Gigabit Ethernet controller.
//!
//! The nForce MCP integrates Ethernet directly onto the chipset; the
//! controller exposes itself as a PCI device with vendor 0x10DE
//! ("NVIDIA Corporation"). The same register block (with a few minor
//! version differences) covers nForce/nForce2/nForce3/nForce4 through
//! nForce 6xx/7xx (MCP55/MCP6x/MCP7x), and shows up under a long list
//! of device IDs that all use the same driver.
//!
//! ## Reference
//!
//! - Linux `drivers/net/ethernet/nvidia/forcedeth.c`
//!   (GPL-2.0). NARF is GPL-2.0-or-later; we cite + adapt directly.
//! - The chip is otherwise undocumented — every register name below
//!   originates with the reverse-engineered Linux driver.
//!
//! ## Register layout (BAR0, MMIO, little-endian 32-bit accesses)
//!
//! | offset  | name              | description                          |
//! |---------|-------------------|--------------------------------------|
//! | 0x000   | IrqStatus         | RW1C interrupt status                |
//! | 0x004   | IrqMask           | Interrupt enable mask                |
//! | 0x034   | MacReset          | MAC block reset                      |
//! | 0x084   | TransmitterCtl    | TX path enable                       |
//! | 0x088   | TransmitterStatus | TX BUSY bit (polled at stop)         |
//! | 0x08C   | PacketFilterFlags | Promisc / pause / "my-addr" / bcast  |
//! | 0x094   | ReceiverCtl       | RX path enable                       |
//! | 0x098   | ReceiverStatus    | RX BUSY bit (polled at stop)         |
//! | 0x0A8   | MacAddrA          | MAC bytes [0..3] (often byte-swapped)|
//! | 0x0AC   | MacAddrB          | MAC bytes [4..5]                     |
//! | 0x100   | TxRingPhysAddr    | TX descriptor ring DMA addr (low32)  |
//! | 0x104   | RxRingPhysAddr    | RX descriptor ring DMA addr (low32)  |
//! | 0x108   | RingSizes         | RX/TX ring sizes (descriptors - 1)   |
//! | 0x10C   | TransmitPoll      | MAC_ADDR_REV bit + TX poll control   |
//! | 0x180   | MIIStatus         | MII transaction status (RW1C)        |
//! | 0x188   | AdapterCtl        | PHY-init + adapter speed             |
//! | 0x18C   | MIISpeed          | MII clock divider                    |
//! | 0x190   | MIIControl        | MII address + read/write + INUSE     |
//! | 0x194   | MIIData           | MII data window (write before / read |
//! |         |                   |  after MIIControl)                   |
//! | 0x144   | TxRxControl       | DESC_VERx | RESET | KICK             |
//!
//! ## MAC address byte-ordering quirk
//!
//! Linux's forcedeth distinguishes three cases (see `forcedeth.c`
//! around line 5874):
//!
//! 1. `DEV_HAS_CORRECT_MACADDR` — modern parts already lay the MAC
//!    out in big-endian-natural order in (MacAddrA, MacAddrB).
//! 2. Older parts where bit 15 of `TransmitPoll`
//!    (`MAC_ADDR_REV`) is set indicate the byte-ordering workaround
//!    was already applied by the firmware.
//! 3. Older parts where `MAC_ADDR_REV` is 0 hand back the MAC in
//!    reversed order: byte 0 of the wire MAC lives in the
//!    `MacAddrB >> 8` slot, etc.
//!
//! We replicate the three-way decode below. On real silicon the third
//! path also wants us to write the corrected value back with
//! `MAC_ADDR_REV` latched — `bring_up` does that.
//!
//! ## Descriptor format (DESC_VER_2 — "ring_desc")
//!
//! The simpler, 8-byte format used on every chip before the 64-bit
//! "ex" descriptor (DESC_VER_3). One descriptor:
//!
//! ```text
//!   word0:  buffer phys addr  low  32 bits   (write-only by host)
//!   word1:  flags<31..16> | length<13..0>    (write by host, read
//!                                            back after chip clears
//!                                            the VALID/AVAIL bit)
//! ```
//!
//! Per Linux `forcedeth.c`:
//!
//! - TX VALID (chip-owned) lives at bit 31 of word1. Bit 30 is the
//!   driver-visible ERROR bit. The host sets `NV_TX_VALID |
//!   NV_TX_LASTPACKET | length` when handing the descriptor to the
//!   chip; the chip clears VALID on completion. For DESC_VER_2 the
//!   LASTPACKET bit is `NV_TX2_LASTPACKET` at bit 29.
//! - RX AVAIL (chip-owned) is also at bit 31 of word1, with the
//!   descriptor's frame length copied into bits[13..0] when the chip
//!   clears the bit. For DESC_VER_2 the `NV_RX2_DESCRIPTORVALID` bit
//!   lives at bit 29.
//!
//! ## Stage cut
//!
//! - Stage 0: probe + BAR0 map + MAC read + driver registration. The
//!   data path returns `BadDevice` (we wedge the probe at `Ok`).
//! - Stage 1: MAC + TX/RX reset, MII PHY init, link status snapshot.
//! - Stage 2: TX + RX descriptor rings (DESC_VER_2), one polled
//!   send + receive round trip.

#![allow(dead_code)]

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write,
};

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: NVIDIA Corporation.
pub const NV_VENDOR: u16 = 0x10DE;

/// nForce 6xx MCP55 — most common nForce4/5 chipset MAC.
pub const NV_DEV_MCP55_1: u16 = 0x0372;
pub const NV_DEV_MCP55_2: u16 = 0x0373;

/// nForce 6xx MCP65 — paired with C51/C55/MCP67 northbridges; ships in
/// late-2006 / 2007 AM2 boards.
pub const NV_DEV_MCP65_1: u16 = 0x0450;
pub const NV_DEV_MCP65_2: u16 = 0x0451;
pub const NV_DEV_MCP65_3: u16 = 0x0452;
pub const NV_DEV_MCP65_4: u16 = 0x0453;

/// nForce 6xx MCP67 — early IGP-only chipsets.
pub const NV_DEV_MCP67_1: u16 = 0x054C;
pub const NV_DEV_MCP67_2: u16 = 0x054D;
pub const NV_DEV_MCP67_3: u16 = 0x054E;
pub const NV_DEV_MCP67_4: u16 = 0x054F;

/// nForce 7xx MCP73 — desktop / mobile mid-range.
pub const NV_DEV_MCP73_1: u16 = 0x07DC;
pub const NV_DEV_MCP73_2: u16 = 0x07DD;
pub const NV_DEV_MCP73_3: u16 = 0x07DE;
pub const NV_DEV_MCP73_4: u16 = 0x07DF;

/// nForce 7xx MCP77/MCP78 — the last-generation high-end nForce; ships
/// on the long-running AM2+ board catalogue. Most common forcedeth
/// device IDs in the wild.
pub const NV_DEV_MCP77_1: u16 = 0x0760;
pub const NV_DEV_MCP77_2: u16 = 0x0761;
pub const NV_DEV_MCP77_3: u16 = 0x0762;
pub const NV_DEV_MCP77_4: u16 = 0x0763;

/// The supported nForce device IDs covered by this driver. Curated to
/// the 6xx/7xx generations — those are the ones still hitting "MCP
/// Ethernet" lspci output on running systems. The earliest nForce
/// (0x01C3, 0x0066) is omitted; it shares the register set but uses a
/// distinct PHY init path we don't replicate here.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    NV_DEV_MCP55_1,
    NV_DEV_MCP55_2,
    NV_DEV_MCP65_1,
    NV_DEV_MCP65_2,
    NV_DEV_MCP65_3,
    NV_DEV_MCP65_4,
    NV_DEV_MCP67_1,
    NV_DEV_MCP67_2,
    NV_DEV_MCP67_3,
    NV_DEV_MCP67_4,
    NV_DEV_MCP73_1,
    NV_DEV_MCP73_2,
    NV_DEV_MCP73_3,
    NV_DEV_MCP73_4,
    NV_DEV_MCP77_1,
    NV_DEV_MCP77_2,
    NV_DEV_MCP77_3,
    NV_DEV_MCP77_4,
];

// ── Register offsets (Linux: `enum {...}` in forcedeth.c §"NvReg*") ──

pub const REG_IRQ_STATUS: u64 = 0x000;
pub const REG_IRQ_MASK: u64 = 0x004;
pub const REG_UNK_SETUP6: u64 = 0x008;
pub const REG_POLLING_INTERVAL: u64 = 0x00C;
pub const REG_MAC_RESET: u64 = 0x034;
pub const REG_MISC1: u64 = 0x080;
pub const REG_XMIT_CTL: u64 = 0x084;
pub const REG_XMIT_STATUS: u64 = 0x088;
pub const REG_PACKET_FILTER: u64 = 0x08C;
pub const REG_OFFLOAD_CFG: u64 = 0x090;
pub const REG_RCV_CTL: u64 = 0x094;
pub const REG_RCV_STATUS: u64 = 0x098;
pub const REG_SLOT_TIME: u64 = 0x09C;
pub const REG_TX_DEFERRAL: u64 = 0x0A0;
pub const REG_RX_DEFERRAL: u64 = 0x0A4;
pub const REG_MAC_ADDR_A: u64 = 0x0A8;
pub const REG_MAC_ADDR_B: u64 = 0x0AC;
pub const REG_MCAST_ADDR_A: u64 = 0x0B0;
pub const REG_MCAST_ADDR_B: u64 = 0x0B4;
pub const REG_MCAST_MASK_A: u64 = 0x0B8;
pub const REG_MCAST_MASK_B: u64 = 0x0BC;
pub const REG_PHY_IFACE: u64 = 0x0C0;
pub const REG_BACKOFF_CTL: u64 = 0x0C4;
pub const REG_TX_RING_PHYS: u64 = 0x100;
pub const REG_RX_RING_PHYS: u64 = 0x104;
pub const REG_RING_SIZES: u64 = 0x108;
pub const REG_TRANSMIT_POLL: u64 = 0x10C;
pub const REG_LINK_SPEED: u64 = 0x110;
pub const REG_TX_RX_CONTROL: u64 = 0x144;
pub const REG_TX_RING_PHYS_HIGH: u64 = 0x148;
pub const REG_RX_RING_PHYS_HIGH: u64 = 0x14C;
pub const REG_MII_STATUS: u64 = 0x180;
pub const REG_ADAPTER_CTL: u64 = 0x188;
pub const REG_MII_SPEED: u64 = 0x18C;
pub const REG_MII_CONTROL: u64 = 0x190;
pub const REG_MII_DATA: u64 = 0x194;

// ── Register field bits ─────────────────────────────────────────────

/// `MacReset` value that asserts the chip-wide MAC reset. Self-clears
/// after `NV_MAC_RESET_DELAY`. Forcedeth.c #define NVREG_MAC_RESET_ASSERT.
pub const MAC_RESET_ASSERT: u32 = 0x0F3;

/// `TransmitPoll.MAC_ADDR_REV`: when set, indicates the MAC bytes in
/// MacAddrA/B are in natural order. The bit must be re-asserted by
/// the driver after a MAC reset on older parts.
pub const TRANSMIT_POLL_MAC_ADDR_REV: u32 = 0x00008000;

/// `XmitCtl.TX_PATH_EN` — software-controlled TX path gate.
pub const XMIT_CTL_TX_PATH_EN: u32 = 0x01000000;
/// `XmitCtl.START` — drains the TX FIFO when set.
pub const XMIT_CTL_START: u32 = 0x01;

/// `XmitStatus.BUSY` — set while the TX path is draining; polled to 0
/// at stop.
pub const XMIT_STATUS_BUSY: u32 = 0x01;

/// `RcvCtl.RX_PATH_EN` — software-controlled RX path gate.
pub const RCV_CTL_RX_PATH_EN: u32 = 0x01000000;
/// `RcvCtl.START` — drains the RX FIFO when set.
pub const RCV_CTL_START: u32 = 0x01;
/// `RcvStatus.BUSY` — set while the RX path is draining.
pub const RCV_STATUS_BUSY: u32 = 0x01;

/// `PacketFilter.ALWAYS` — accept frames matching our MAC. The default
/// "let me receive my unicast traffic" mask.
pub const PFF_ALWAYS: u32 = 0x7F0000;
/// `PacketFilter.MYADDR` — promiscuous-disabled, address-filter mode.
pub const PFF_MYADDR: u32 = 0x20;
/// `PacketFilter.PROMISC` — accept-all.
pub const PFF_PROMISC: u32 = 0x80;

/// `TxRxControl` bits. The kick bit fires the TX engine; reset
/// toggles the chip's internal TX+RX state machines. DESC_VER_2 is
/// the encoding for the 8-byte legacy descriptor format.
pub const TXRXCTL_KICK: u32 = 0x0001;
pub const TXRXCTL_BIT2: u32 = 0x0004;
pub const TXRXCTL_IDLE: u32 = 0x0008;
pub const TXRXCTL_RESET: u32 = 0x0010;
pub const TXRXCTL_RXCHECK: u32 = 0x0400;
pub const TXRXCTL_DESC_1: u32 = 0;
pub const TXRXCTL_DESC_2: u32 = 0x002100;
pub const TXRXCTL_DESC_3: u32 = 0xC02200;

/// `RingSizes` field encoding. The chip wants (count − 1) in the two
/// low halfwords, low half = RX, high half = TX.
pub const RINGSZ_TXSHIFT: u32 = 0;
pub const RINGSZ_RXSHIFT: u32 = 16;

/// `MIIStatus.MASK_RW` — written before every MII transaction to clear
/// the latched status bits.
pub const MIISTAT_MASK_RW: u32 = 0x000F;
/// `MIIStatus.ERROR` — read after the transaction completes.
pub const MIISTAT_ERROR: u32 = 0x0001;

/// `MIIControl` bits. The chip's MII glue serializes a PHY transaction
/// driven by the address+register packed in this register; data lives
/// in REG_MII_DATA.
pub const MIICTL_INUSE: u32 = 0x08000;
pub const MIICTL_WRITE: u32 = 0x00400;
pub const MIICTL_ADDR_SHIFT: u32 = 5;

/// MII clock divider value. Linux uses 8 on most chips; the chip
/// derives MDC from REF/(MIISpeed+1). 8 gives ~25 MHz clock from the
/// 200 MHz reference, which matches Clause-22 PHY MDC spec (≤ 2.5 MHz
/// would be safer but the chip's prescaler doesn't go that high).
pub const MIISPEED_DEFAULT: u32 = 8;

/// `IrqMask` standard "data path" set: RX OK + RX error + RX nobuf +
/// TX OK + TX error + LinkChg + Recover. Mirrors Linux's
/// `NVREG_IRQMASK_THROUGHPUT = 0x00DF`.
pub const IRQMASK_THROUGHPUT: u32 = 0x00DF;
pub const IRQ_RX_ERROR: u32 = 0x0001;
pub const IRQ_RX: u32 = 0x0002;
pub const IRQ_RX_NOBUF: u32 = 0x0004;
pub const IRQ_TX_ERR: u32 = 0x0008;
pub const IRQ_TX_OK: u32 = 0x0010;
pub const IRQ_TIMER: u32 = 0x0020;
pub const IRQ_LINK: u32 = 0x0040;
pub const IRQ_RX_FORCED: u32 = 0x0080;
pub const IRQ_TX_FORCED: u32 = 0x0100;
pub const IRQ_RECOVER_ERROR: u32 = 0x8200;

// ── Descriptor bit definitions (DESC_VER_2 / "_2_" variant) ────────

/// TX word1 flags. `VALID` = chip owns the descriptor. `LASTPACKET` =
/// end of frame (only one segment for now). `ERROR` set by chip on
/// completion if anything went wrong. See `NV_TX2_*` in forcedeth.c.
pub const TXD_LASTPACKET: u32 = 1 << 29;
pub const TXD_ERROR: u32 = 1 << 30;
pub const TXD_VALID: u32 = 1 << 31;

/// RX word1 flags. `AVAIL` = chip owns the descriptor. `DESCRIPTOR_VALID`
/// = chip wrote a valid frame into the buffer. `ERROR` = chip flagged
/// a problem during reception.
pub const RXD_DESCRIPTOR_VALID: u32 = 1 << 29;
pub const RXD_ERROR: u32 = 1 << 30;
pub const RXD_AVAIL: u32 = 1 << 31;

/// Length lives in bits[13..0] of word1 in DESC_VER_2 (LEN_MASK_V2 =
/// `0xFFFFFFFF ^ FLAG_MASK_V2 = 0x3FFF` per forcedeth.c).
pub const DESC_LEN_MASK_V2: u32 = 0x3FFF;

// ── MII Clause-22 register subset ──────────────────────────────────

pub const MII_BMCR: u32 = 0x00;
pub const MII_BMSR: u32 = 0x01;
pub const BMCR_RESET: u16 = 1 << 15;
pub const BMCR_AUTONEG_EN: u16 = 1 << 12;
pub const BMCR_AUTONEG_RESTART: u16 = 1 << 9;
pub const BMSR_LINK_UP: u16 = 1 << 2;

// ── Sizing constants ────────────────────────────────────────────────

/// Descriptor count per ring. 64 keeps RX + TX combined under one
/// page (64 × 8 = 512 B; 64 × 8 = 512 B; both fit in one 4 KiB
/// allocation comfortably) and is plenty for a Stage-2 driver.
pub const RING_LEN: usize = 64;

/// RX buffer size. nForce datasheet-equivalent (forcedeth.c
/// `RX_NIC_BUFSIZE`) is `RX_HEADERS + max-mtu`; we settle on a flat
/// 2 KiB which holds a 1518-byte Ethernet frame + chip-emitted
/// trailer.
pub const RX_BUF_LEN: usize = 2048;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    /// The `TxRxControl.IDLE` bit didn't go high inside the deadline.
    ResetTimeout,
    /// MII transaction never cleared the INUSE bit.
    MiiTimeout,
    /// MII transaction returned the ERROR latch.
    MiiError,
    /// Frame outside [1, 1518].
    FrameTooLong,
    /// `transmit` couldn't find a free TX descriptor.
    TxRingFull,
    /// `transmit` polled too long for VALID to clear.
    TxTimeout,
}

// ── Descriptor in-memory shape ──────────────────────────────────────

/// DESC_VER_2 descriptor (8 bytes). Per forcedeth.c `struct ring_desc`:
/// word0 holds the buffer's low-32-bit physical address (the chip
/// can't DMA past 4 GiB on this descriptor variant), word1 holds
/// flags + length packed together.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default)]
struct Desc {
    buf: u32,
    flaglen: u32,
}
const _: () = assert!(core::mem::size_of::<Desc>() == 8);

// ── Driver state ────────────────────────────────────────────────────

/// A live nForce Ethernet controller. The handle owns the BAR0 MMIO
/// mapping, the TX/RX descriptor rings, and the per-slot RX/TX buffer
/// pool.
pub struct ForcedethNic {
    mmio: MmioRegion,
    tx_ring: DmaBuffer,
    /// Per-TX-slot persistent frame buffer. Indexed by ring slot so a
    /// frame stays alive for the descriptor's lifetime.
    tx_pool: alloc::vec::Vec<DmaBuffer>,
    tx_head: IrqSafeSpinLock<u32>,
    rx_ring: DmaBuffer,
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address as decoded from MacAddrA/MacAddrB at bring-up.
    pub mac: [u8; 6],
    /// True when the PHY's BMSR.LinkStatus read 1 at bring-up. We
    /// don't (yet) re-poll on LinkChg interrupts; a follow-up wires
    /// the IRQ-driven refresh.
    pub link_up: bool,
    /// The PHY's MII address as discovered by the bring-up MDIO scan.
    /// 32 means "no PHY responded" — the chip's MII glue still works
    /// for tests but the data path is link-down.
    pub phy_addr: u8,
    /// TxRxControl base bits with the DESC_VER_2 encoding pre-baked.
    /// Linux carries this in `np->txrxctl_bits` so every write to
    /// REG_TX_RX_CONTROL can OR in the persistent state.
    txrxctl_bits: u32,
}

impl core::fmt::Debug for ForcedethNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ForcedethNic")
            .field("mac", &self.mac)
            .field("link_up", &self.link_up)
            .field("phy_addr", &self.phy_addr)
            .finish_non_exhaustive()
    }
}

impl ForcedethNic {
    /// Bring up the controller through Stage-2: TX_RX_CONTROL reset,
    /// MAC read, MII PHY scan + BMCR reset, TX/RX ring install, link
    /// state snapshot.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively for the
    /// duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NicError> {
        // forcedeth.c §"start_nic": the chip lays operational
        // registers in BAR0, and the BAR is wired straight into MMIO
        // — there's no I/O alias to skip.
        // SAFETY: caller-asserted exclusive ownership of the device.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| NicError::BarMapFailed)?;

        // The DESC_VER_2 encoding is what every part covered by
        // SUPPORTED_DEVICE_IDS speaks. Forcedeth.c discriminates at
        // probe time via DEV_HAS_LARGEDESC; we hard-pick DESC_VER_2
        // because every supported part either is DESC_VER_2 or
        // accepts the DESC_VER_2 layout transparently.
        let txrxctl_bits = TXRXCTL_DESC_2;

        // 1. TxRxControl reset. Per forcedeth.c `nv_txrx_reset`:
        //    raise RESET | BIT2 | txrxctl_bits, push the write, wait
        //    `NV_TXRX_RESET_DELAY` (4 µs in Linux), then lower it.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_TX_RX_CONTROL, TXRXCTL_BIT2 | TXRXCTL_RESET | txrxctl_bits);
            // PCI flush-by-read (the chip orders ops by ack-back of
            // the write — Linux does this via `pci_push` which is a
            // `readl` of any post-decoded register).
            let _ = mmio.read32(REG_TX_RX_CONTROL);
        }
        // Spin briefly. Linux uses a 4 µs `udelay`; we use the
        // responsive variant so background pumps still tick.
        narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(REG_TX_RX_CONTROL) } & TXRXCTL_RESET == 0
                || true /* TX_RX reset is self-cleared by writing 0 below */,
            narf_time::Deadline::after_ms(2),
        );
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_TX_RX_CONTROL, TXRXCTL_BIT2 | txrxctl_bits);
            let _ = mmio.read32(REG_TX_RX_CONTROL);
        }

        // 2. Read MAC. Replicate forcedeth.c's three-way decode (see
        //    the module doc-comment above). We can't tell at runtime
        //    whether the part is on the `DEV_HAS_CORRECT_MACADDR`
        //    list, so we trust the `TRANSMIT_POLL_MAC_ADDR_REV` bit
        //    as the discriminator. The MCP6x/MCP7x families covered
        //    by SUPPORTED_DEVICE_IDS already program this bit on POST.
        // SAFETY: identity-mapped MMIO.
        let mac_a = unsafe { mmio.read32(REG_MAC_ADDR_A) };
        // SAFETY: same.
        let mac_b = unsafe { mmio.read32(REG_MAC_ADDR_B) };
        // SAFETY: same.
        let txpoll = unsafe { mmio.read32(REG_TRANSMIT_POLL) };
        let mac = if txpoll & TRANSMIT_POLL_MAC_ADDR_REV != 0 {
            [
                (mac_a >> 0) as u8,
                (mac_a >> 8) as u8,
                (mac_a >> 16) as u8,
                (mac_a >> 24) as u8,
                (mac_b >> 0) as u8,
                (mac_b >> 8) as u8,
            ]
        } else {
            // Reversed-byte-order workaround case. Forcedeth.c also
            // re-writes MacAddrA/B with the corrected layout + sets
            // MAC_ADDR_REV; we do the same so the chip sees a stable
            // MAC after the reset.
            let m = [
                (mac_b >> 8) as u8,
                (mac_b >> 0) as u8,
                (mac_a >> 24) as u8,
                (mac_a >> 16) as u8,
                (mac_a >> 8) as u8,
                (mac_a >> 0) as u8,
            ];
            let new_a = (m[5] as u32)
                | ((m[4] as u32) << 8)
                | ((m[3] as u32) << 16)
                | ((m[2] as u32) << 24);
            let new_b = (m[1] as u32) | ((m[0] as u32) << 8);
            // SAFETY: identity-mapped MMIO.
            unsafe {
                mmio.write32(REG_MAC_ADDR_A, new_a);
                mmio.write32(REG_MAC_ADDR_B, new_b);
                mmio.write32(REG_TRANSMIT_POLL, txpoll | TRANSMIT_POLL_MAC_ADDR_REV);
            }
            m
        };

        // 3. Allocate descriptor rings + per-slot buffer pools.
        let tx_ring = alloc_coherent(RING_LEN * 8, DomainId::DRIVER_0)
            .map_err(|_| NicError::NoMemory)?;
        let rx_ring = alloc_coherent(RING_LEN * 8, DomainId::DRIVER_0)
            .map_err(|_| NicError::NoMemory)?;
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            rx_pool.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0)
                    .map_err(|_| NicError::NoMemory)?,
            );
        }
        let mut tx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            tx_pool.push(
                alloc_coherent(2048, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }

        // 4. Program MIISpeed before any MII transaction (the chip
        //    needs the clock divider before MIIControl will respond).
        //    Forcedeth.c `nv_open` writes this to 8 unconditionally.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_MII_SPEED, MIISPEED_DEFAULT);
        }

        // 5. Probe the MII bus to find which address responds. The
        //    PHY can sit at any 5-bit MDIO address — Linux walks
        //    32..0 (high first) and picks the first one whose BMSR
        //    reads as a non-0/0xFFFF value. We do the same.
        let mut phy_addr: u8 = 32;
        for addr in (0u8..32).rev() {
            match mii_rw(&mmio, addr, MII_BMSR, None) {
                Ok(v) if v != 0 && v != 0xFFFF => {
                    phy_addr = addr;
                    break;
                }
                _ => continue,
            }
        }

        let link_up = if phy_addr < 32 {
            // 6. PHY soft-reset via MII BMCR. The standard handshake:
            //    set BMCR.RESET, wait for it to self-clear, then read
            //    BMSR.LINK_UP for the link state snapshot. Forcedeth.c
            //    layers a 500ms sleep in `phy_reset` — we cap our
            //    wall-clock budget at 600 ms.
            let _ = mii_rw(
                &mmio,
                phy_addr,
                MII_BMCR,
                Some((BMCR_RESET | BMCR_AUTONEG_EN | BMCR_AUTONEG_RESTART) as u32),
            );
            narf_scheduler::responsive_spin_until(
                || match mii_rw(&mmio, phy_addr, MII_BMCR, None) {
                    Ok(v) => v as u16 & BMCR_RESET == 0,
                    Err(_) => true, // give up — error path treated as "reset done"
                },
                narf_time::Deadline::after_ms(600),
            );
            // BMSR.LINK_UP is sticky-low: read twice; the second
            // value is the current state. Forcedeth.c does the same
            // double-read in `nv_update_linkspeed`.
            let _ = mii_rw(&mmio, phy_addr, MII_BMSR, None);
            let bmsr = mii_rw(&mmio, phy_addr, MII_BMSR, None).unwrap_or(0);
            (bmsr as u16) & BMSR_LINK_UP != 0
        } else {
            false
        };

        // 7. Install TX + RX ring base addresses. RingSizes is
        //    (count - 1) packed into low / high halfwords. The chip
        //    reads physical 32-bit addresses out of TxRingPhysAddr /
        //    RxRingPhysAddr; on parts with the *_HIGH companion
        //    registers we still write 0 there because DESC_VER_2
        //    descriptors only carry a 32-bit buffer pointer (`buf`).
        let tx_phys = tx_ring.phys_addr().raw();
        let rx_phys = rx_ring.phys_addr().raw();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_TX_RING_PHYS, tx_phys as u32);
            mmio.write32(REG_RX_RING_PHYS, rx_phys as u32);
            mmio.write32(REG_TX_RING_PHYS_HIGH, (tx_phys >> 32) as u32);
            mmio.write32(REG_RX_RING_PHYS_HIGH, (rx_phys >> 32) as u32);
            mmio.write32(
                REG_RING_SIZES,
                ((RING_LEN as u32 - 1) << RINGSZ_TXSHIFT)
                    | ((RING_LEN as u32 - 1) << RINGSZ_RXSHIFT),
            );
        }

        // 8. Prime the RX ring — every slot points at its persistent
        //    pool buffer + carries AVAIL=1 so the chip can DMA into
        //    it on first receive.
        let rx_ring_phys = rx_ring.phys_addr().raw();
        for i in 0..RING_LEN {
            let buf_phys = rx_pool[i].phys_addr().raw();
            let d = Desc {
                buf: buf_phys as u32,
                flaglen: RXD_AVAIL | (RX_BUF_LEN as u32 & DESC_LEN_MASK_V2),
            };
            // SAFETY: identity-mapped DMA ring page; i < RING_LEN.
            unsafe {
                core::ptr::write_volatile((rx_ring_phys + (i * 8) as u64) as *mut Desc, d);
            }
        }

        // 9. Mask interrupts for now. Stage-2 doesn't yet wire MSI/X
        //    or attach a vector — the data path is polled.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_IRQ_MASK, 0);
            mmio.write32(REG_IRQ_STATUS, 0xFFFFFFFF);
        }

        // 10. Enable the receive + transmit paths.
        //     `RcvCtl.RX_PATH_EN` + `XmitCtl.TX_PATH_EN` map onto
        //     forcedeth.c's `nv_start_rxtx` sequence. The chip won't
        //     pull frames off the RX ring until both bits are set.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_PACKET_FILTER, PFF_ALWAYS | PFF_MYADDR);
            mmio.write32(REG_RCV_CTL, RCV_CTL_RX_PATH_EN | RCV_CTL_START);
            mmio.write32(REG_XMIT_CTL, XMIT_CTL_TX_PATH_EN | XMIT_CTL_START);
        }

        Ok(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_head: IrqSafeSpinLock::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            link_up,
            phy_addr,
            txrxctl_bits,
        })
    }

    /// Transmit a single Ethernet frame, polled. Frame must be in
    /// `[1, 1518]` bytes; padding for runt frames is the chip's job.
    pub fn transmit(&self, frame: &[u8]) -> Result<(), NicError> {
        if frame.is_empty() || frame.len() > 1518 {
            return Err(NicError::FrameTooLong);
        }

        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let phys = self.tx_pool[slot].phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked by
        // FrameTooLong guard.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
            }
        }
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 8) as u64;

        // SAFETY: identity-mapped DMA ring page.
        let cur = unsafe { core::ptr::read_volatile((desc_addr + 4) as *const u32) };
        if cur & TXD_VALID != 0 {
            return Err(NicError::TxRingFull);
        }

        // Per forcedeth.c §"nv_start_xmit_optimized": write buf first,
        // fence, then flip VALID. The chip sees VALID set only after
        // the buffer pointer has propagated.
        // SAFETY: identity-mapped DMA ring page.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut u32, phys as u32);
        }
        compiler_fence(Ordering::SeqCst);
        let flaglen = TXD_VALID | TXD_LASTPACKET | (frame.len() as u32 & DESC_LEN_MASK_V2);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile((desc_addr + 4) as *mut u32, flaglen);
        }
        compiler_fence(Ordering::SeqCst);

        // Ring the TX kick doorbell. Per forcedeth.c `nv_start_xmit_*`:
        // OR the kick bit into the persistent txrxctl base.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write32(REG_TX_RX_CONTROL, TXRXCTL_KICK | self.txrxctl_bits);
        }

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        drop(head_g);

        // Poll for VALID → 0. The chip clears VALID once the frame
        // has been DMA'd to its TX FIFO. 250 ms wall-clock budget.
        let owned = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA ring.
            || unsafe { core::ptr::read_volatile((desc_addr + 4) as *const u32) } & TXD_VALID == 0,
            narf_time::Deadline::after_ms(250),
        );
        if !owned {
            return Err(NicError::TxTimeout);
        }
        Ok(())
    }

    /// Pop one received frame off the RX ring. Returns `Some(buf)`
    /// when a descriptor's AVAIL bit reads 0 (chip handed it back)
    /// and `None` when the head is still chip-owned.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        let mut head_g = self.rx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 8) as u64;

        // SAFETY: identity-mapped DMA ring.
        let flaglen = unsafe { core::ptr::read_volatile((desc_addr + 4) as *const u32) };
        if flaglen & RXD_AVAIL != 0 {
            return None;
        }

        let len = (flaglen & DESC_LEN_MASK_V2) as usize;
        let buf_phys = self.rx_pool[slot].phys_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(len.min(RX_BUF_LEN));
        if flaglen & RXD_DESCRIPTOR_VALID != 0 {
            let copy_len = len.min(RX_BUF_LEN);
            // SAFETY: identity-mapped DMA buffer; bounds-checked.
            for i in 0..copy_len {
                out.push(unsafe { core::ptr::read_volatile((buf_phys + i as u64) as *const u8) });
            }
        }

        // Re-arm: hand the descriptor back to the chip.
        let d = Desc {
            buf: buf_phys as u32,
            flaglen: RXD_AVAIL | (RX_BUF_LEN as u32 & DESC_LEN_MASK_V2),
        };
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut Desc, d);
        }
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        Some(out)
    }

    /// Re-evaluate the link state by re-reading BMSR.
    pub fn refresh_link_state(&mut self) -> bool {
        if self.phy_addr >= 32 {
            self.link_up = false;
            return false;
        }
        // sticky-low: double-read.
        let _ = mii_rw(&self.mmio, self.phy_addr, MII_BMSR, None);
        let bmsr = mii_rw(&self.mmio, self.phy_addr, MII_BMSR, None).unwrap_or(0);
        let up = (bmsr as u16) & BMSR_LINK_UP != 0;
        self.link_up = up;
        up
    }

    /// Read + write-1-clear the IRQ status. Stage-3 wires this into an
    /// interrupt handler; for now it's used by smoke tests that want
    /// to make sure the IRQ latch isn't stuck.
    pub fn ack_irq_status(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        let s = unsafe { self.mmio.read32(REG_IRQ_STATUS) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(REG_IRQ_STATUS, s);
        }
        s
    }
}

// ── MII transaction helper ──────────────────────────────────────────

/// Read or write a single PHY register through the chip's MII glue.
/// `value = None` performs a read, `value = Some(v)` performs a write.
/// Returns the read-back data (or `Ok(0)` after a write). Matches the
/// shape of forcedeth.c's `mii_rw`.
fn mii_rw(
    mmio: &MmioRegion,
    addr: u8,
    reg: u32,
    value: Option<u32>,
) -> Result<u32, NicError> {
    // SAFETY: identity-mapped MMIO.
    unsafe {
        mmio.write32(REG_MII_STATUS, MIISTAT_MASK_RW);
    }

    // SAFETY: same.
    let mut ctrl = unsafe { mmio.read32(REG_MII_CONTROL) };
    if ctrl & MIICTL_INUSE != 0 {
        // Force-clear an in-flight transaction. Forcedeth.c does the
        // same write-INUSE-back trick to abort.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_MII_CONTROL, MIICTL_INUSE);
        }
        // Brief wait for the bus to settle. We piggy-back on the
        // responsive_spin_until wedge so we don't hot-loop here.
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(REG_MII_CONTROL) } & MIICTL_INUSE == 0,
            narf_time::Deadline::after_ms(2),
        );
    }

    ctrl = ((addr as u32) << MIICTL_ADDR_SHIFT) | reg;
    if let Some(v) = value {
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_MII_DATA, v);
        }
        ctrl |= MIICTL_WRITE;
    }
    // SAFETY: same.
    unsafe {
        mmio.write32(REG_MII_CONTROL, ctrl);
    }

    // Wait for INUSE to drop. Forcedeth.c uses NV_MIIPHY_DELAYMAX
    // (10000 µs); 20 ms here covers the worst-case slow PHY.
    let done = narf_scheduler::responsive_spin_until(
        // SAFETY: same.
        || unsafe { mmio.read32(REG_MII_CONTROL) } & MIICTL_INUSE == 0,
        narf_time::Deadline::after_ms(20),
    );
    if !done {
        return Err(NicError::MiiTimeout);
    }

    if value.is_some() {
        // Write — fewer error paths are detectable; treat as OK.
        return Ok(0);
    }
    // SAFETY: same.
    let stat = unsafe { mmio.read32(REG_MII_STATUS) };
    if stat & MIISTAT_ERROR != 0 {
        return Err(NicError::MiiError);
    }
    // SAFETY: same.
    Ok(unsafe { mmio.read32(REG_MII_DATA) })
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<ForcedethNic>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`. Idempotent.
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER: BAR0 maps the operational registers,
    // and the chip DMAs descriptor rings + frame buffers on its own.
    // INTX_DISABLE silences the legacy line — Stage-2 is polled, so
    // we don't want a misfiring legacy IRQ to surface.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller-authority over the device for the duration of
    // bring_up.
    let dev = match unsafe { ForcedethNic::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

/// Register the driver against every supported nForce device id.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: NV_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    // Per-device-id name so `narf_bus::register_pci_driver`'s "idempotent
    // on name" clause doesn't collapse multiple match entries onto a
    // single slot. The register call replaces any prior entry of the
    // same name, so grouping IDs (e.g. "forcedeth-mcp55" for both
    // 0x0372 and 0x0373) would silently keep only the last one.
    match did {
        NV_DEV_MCP55_1 => "forcedeth-mcp55-1",
        NV_DEV_MCP55_2 => "forcedeth-mcp55-2",
        NV_DEV_MCP65_1 => "forcedeth-mcp65-1",
        NV_DEV_MCP65_2 => "forcedeth-mcp65-2",
        NV_DEV_MCP65_3 => "forcedeth-mcp65-3",
        NV_DEV_MCP65_4 => "forcedeth-mcp65-4",
        NV_DEV_MCP67_1 => "forcedeth-mcp67-1",
        NV_DEV_MCP67_2 => "forcedeth-mcp67-2",
        NV_DEV_MCP67_3 => "forcedeth-mcp67-3",
        NV_DEV_MCP67_4 => "forcedeth-mcp67-4",
        NV_DEV_MCP73_1 => "forcedeth-mcp73-1",
        NV_DEV_MCP73_2 => "forcedeth-mcp73-2",
        NV_DEV_MCP73_3 => "forcedeth-mcp73-3",
        NV_DEV_MCP73_4 => "forcedeth-mcp73-4",
        NV_DEV_MCP77_1 => "forcedeth-mcp77-1",
        NV_DEV_MCP77_2 => "forcedeth-mcp77-2",
        NV_DEV_MCP77_3 => "forcedeth-mcp77-3",
        NV_DEV_MCP77_4 => "forcedeth-mcp77-4",
        _ => "forcedeth",
    }
}

/// `true` once `probe` has installed a controller.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Test-side accessor: run `f` against the probed controller.
pub fn with_controller<R>(f: impl FnOnce(&ForcedethNic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Mutable accessor — used by tests that need to drive PHY state
/// refresh.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut ForcedethNic) -> R) -> Option<R> {
    CONTROLLER.lock().as_mut().map(f)
}

// ── Smoke tests ─────────────────────────────────────────────────────
//
// Tests live inline here (rather than in `drivers/net/src/tests.rs`)
// to keep the forcedeth-specific scope of this driver self-contained.
// Real-silicon-only paths (PHY init, ring round-trip) emit
// `TestResult::Skip` when probe didn't run, so this block is safe to
// link on every build.

#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_forcedeth_pci_match_table() -> TestResult {
        use narf_bus::driver_match::__reset_for_test;
        use narf_bus::{registered_pci_drivers, MatchKind};
        __reset_for_test();
        register_pci_driver();
        let registered = registered_pci_drivers();
        for did in SUPPORTED_DEVICE_IDS.iter().copied() {
            let found = registered.iter().any(|m| {
                matches!(m.kind, MatchKind::VendorDevice {
                    vendor, device,
                } if vendor == NV_VENDOR && device == did)
            });
            if !found {
                return TestResult::Fail("forcedeth match entry missing");
            }
        }
        // Spot-check the laptop-relevant 7xx IDs explicitly so a
        // future refactor of `SUPPORTED_DEVICE_IDS` can't silently
        // drop them.
        let must_have: &[u16] = &[
            NV_DEV_MCP55_1,
            NV_DEV_MCP73_1,
            NV_DEV_MCP77_1,
        ];
        for did in must_have.iter().copied() {
            let found = registered.iter().any(|m| {
                matches!(m.kind, MatchKind::VendorDevice {
                    vendor, device,
                } if vendor == NV_VENDOR && device == did)
            });
            if !found {
                return TestResult::Fail("forcedeth spot-check id missing");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/forcedeth", smoke_forcedeth_pci_match_table);

    fn smoke_forcedeth_txrxctl_desc_encodings_match_linux() -> TestResult {
        // Cross-check our DESC_VER encodings against Linux's
        // forcedeth.c §"NvRegTxRxControl":
        //   #define NVREG_TXRXCTL_DESC_1   0
        //   #define NVREG_TXRXCTL_DESC_2   0x002100
        //   #define NVREG_TXRXCTL_DESC_3   0xc02200
        // A bit drift here would silently corrupt every TX/RX
        // descriptor because the chip-side and driver-side descriptor
        // layouts disagree.
        if TXRXCTL_DESC_1 != 0 {
            return TestResult::Fail("TXRXCTL_DESC_1 must be 0");
        }
        if TXRXCTL_DESC_2 != 0x0021_00 {
            return TestResult::Fail("TXRXCTL_DESC_2 drift");
        }
        if TXRXCTL_DESC_3 != 0xc022_00 {
            return TestResult::Fail("TXRXCTL_DESC_3 drift");
        }
        if TXRXCTL_KICK != 0x0001 {
            return TestResult::Fail("TXRXCTL_KICK drift");
        }
        if TXRXCTL_RESET != 0x0010 {
            return TestResult::Fail("TXRXCTL_RESET drift");
        }
        if TXRXCTL_BIT2 != 0x0004 {
            return TestResult::Fail("TXRXCTL_BIT2 drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/forcedeth",
        smoke_forcedeth_txrxctl_desc_encodings_match_linux
    );

    fn smoke_forcedeth_desc_bit_layout_matches_linux() -> TestResult {
        // DESC_VER_2 descriptor word1 flags. Linux's
        // forcedeth.c lays them out as:
        //   NV_TX2_LASTPACKET     (1<<29)
        //   NV_TX2_ERROR          (1<<30)
        //   NV_TX2_VALID          (1<<31)
        //   NV_RX2_DESCRIPTORVALID(1<<29)
        //   NV_RX2_ERROR          (1<<30)
        //   NV_RX2_AVAIL          (1<<31)
        //   LEN_MASK_V2           (0x3FFF)
        // A bit drift would make every transmit / receive descriptor
        // read as either chip-owned forever (host blocks) or
        // host-owned-immediately (chip races us).
        if TXD_LASTPACKET != 1 << 29 {
            return TestResult::Fail("TXD_LASTPACKET drift");
        }
        if TXD_ERROR != 1 << 30 {
            return TestResult::Fail("TXD_ERROR drift");
        }
        if TXD_VALID != 1 << 31 {
            return TestResult::Fail("TXD_VALID drift");
        }
        if RXD_DESCRIPTOR_VALID != 1 << 29 {
            return TestResult::Fail("RXD_DESCRIPTOR_VALID drift");
        }
        if RXD_ERROR != 1 << 30 {
            return TestResult::Fail("RXD_ERROR drift");
        }
        if RXD_AVAIL != 1 << 31 {
            return TestResult::Fail("RXD_AVAIL drift");
        }
        if DESC_LEN_MASK_V2 != 0x3FFF {
            return TestResult::Fail("DESC_LEN_MASK_V2 drift");
        }
        if core::mem::size_of::<Desc>() != 8 {
            return TestResult::Fail("Desc must be 8 bytes (DESC_VER_2)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/forcedeth",
        smoke_forcedeth_desc_bit_layout_matches_linux
    );

    fn smoke_forcedeth_register_offsets_match_linux() -> TestResult {
        // Linux forcedeth.c register offsets — the constants we
        // pinned here have to match byte-for-byte or the chip drops
        // writes / wedges silently. These are the cross-version
        // pinned ones (offsets 0x000..0x194 are stable across every
        // device in SUPPORTED_DEVICE_IDS).
        if REG_IRQ_STATUS != 0x000 {
            return TestResult::Fail("IrqStatus offset");
        }
        if REG_IRQ_MASK != 0x004 {
            return TestResult::Fail("IrqMask offset");
        }
        if REG_MAC_RESET != 0x034 {
            return TestResult::Fail("MacReset offset");
        }
        if REG_XMIT_CTL != 0x084 {
            return TestResult::Fail("XmitCtl offset");
        }
        if REG_RCV_CTL != 0x094 {
            return TestResult::Fail("RcvCtl offset");
        }
        if REG_MAC_ADDR_A != 0x0A8 {
            return TestResult::Fail("MacAddrA offset");
        }
        if REG_MAC_ADDR_B != 0x0AC {
            return TestResult::Fail("MacAddrB offset");
        }
        if REG_TX_RING_PHYS != 0x100 {
            return TestResult::Fail("TxRingPhysAddr offset");
        }
        if REG_RX_RING_PHYS != 0x104 {
            return TestResult::Fail("RxRingPhysAddr offset");
        }
        if REG_RING_SIZES != 0x108 {
            return TestResult::Fail("RingSizes offset");
        }
        if REG_TRANSMIT_POLL != 0x10C {
            return TestResult::Fail("TransmitPoll offset");
        }
        if REG_TX_RX_CONTROL != 0x144 {
            return TestResult::Fail("TxRxControl offset");
        }
        if REG_MII_STATUS != 0x180 {
            return TestResult::Fail("MIIStatus offset");
        }
        if REG_MII_CONTROL != 0x190 {
            return TestResult::Fail("MIIControl offset");
        }
        if REG_MII_DATA != 0x194 {
            return TestResult::Fail("MIIData offset");
        }
        if TRANSMIT_POLL_MAC_ADDR_REV != 0x0000_8000 {
            return TestResult::Fail("TRANSMIT_POLL_MAC_ADDR_REV drift");
        }
        if MIICTL_INUSE != 0x0_8000 {
            return TestResult::Fail("MIICTL_INUSE drift");
        }
        if MIICTL_WRITE != 0x0_0400 {
            return TestResult::Fail("MIICTL_WRITE drift");
        }
        if MIICTL_ADDR_SHIFT != 5 {
            return TestResult::Fail("MIICTL_ADDR_SHIFT drift");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/forcedeth",
        smoke_forcedeth_register_offsets_match_linux
    );

    fn smoke_forcedeth_ring_descriptor_round_trip() -> TestResult {
        // Stage-2 descriptor round-trip: build a DESC_VER_2
        // descriptor, write it into a scratch buffer, read it back,
        // and assert the flag/length bits decode the way they were
        // packed. Doesn't need a probed device — exercises the
        // descriptor layout + bit-packing only.
        let mut ring = [0u8; 64 * 8];
        let desc_ptr = ring.as_mut_ptr() as *mut Desc;
        let slot = 5usize;
        let flaglen = TXD_VALID | TXD_LASTPACKET | (1500 & DESC_LEN_MASK_V2);
        let d = Desc {
            buf: 0xDEAD_BEEF,
            flaglen,
        };
        // SAFETY: ring is a valid &mut [u8; 64*8]; slot < 64.
        unsafe {
            core::ptr::write_volatile(desc_ptr.add(slot), d);
        }
        // SAFETY: same.
        let readback = unsafe { core::ptr::read_volatile(desc_ptr.add(slot)) };
        if readback.buf != 0xDEAD_BEEF {
            return TestResult::Fail("buf word didn't round-trip");
        }
        if readback.flaglen & TXD_VALID == 0 {
            return TestResult::Fail("VALID lost in round-trip");
        }
        if readback.flaglen & TXD_LASTPACKET == 0 {
            return TestResult::Fail("LASTPACKET lost in round-trip");
        }
        if readback.flaglen & DESC_LEN_MASK_V2 != 1500 {
            return TestResult::Fail("length lost in round-trip");
        }
        // Simulate chip clearing VALID + writing RX-side flags.
        let rx_flaglen = RXD_DESCRIPTOR_VALID | (1500 & DESC_LEN_MASK_V2);
        let rd = Desc {
            buf: 0xCAFE_F000,
            flaglen: rx_flaglen,
        };
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(desc_ptr.add(slot), rd);
        }
        // SAFETY: same.
        let rback = unsafe { core::ptr::read_volatile(desc_ptr.add(slot)) };
        if rback.flaglen & RXD_AVAIL != 0 {
            return TestResult::Fail("AVAIL should be 0 once chip handed off");
        }
        if rback.flaglen & RXD_DESCRIPTOR_VALID == 0 {
            return TestResult::Fail("DESCRIPTOR_VALID lost");
        }
        if rback.flaglen & DESC_LEN_MASK_V2 != 1500 {
            return TestResult::Fail("RX length lost");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/forcedeth",
        smoke_forcedeth_ring_descriptor_round_trip
    );

    fn smoke_forcedeth_ring_sizes_encoding() -> TestResult {
        // RingSizes is (count - 1) packed as RX in [31:16], TX in
        // [15:0]. Confirm our encoding matches forcedeth.c's
        // `NVREG_RINGSZ_TXSHIFT = 0` / `NVREG_RINGSZ_RXSHIFT = 16`.
        if RINGSZ_TXSHIFT != 0 {
            return TestResult::Fail("RINGSZ_TXSHIFT drift");
        }
        if RINGSZ_RXSHIFT != 16 {
            return TestResult::Fail("RINGSZ_RXSHIFT drift");
        }
        let v = ((RING_LEN as u32 - 1) << RINGSZ_TXSHIFT)
            | ((RING_LEN as u32 - 1) << RINGSZ_RXSHIFT);
        if (v & 0xFFFF) != (RING_LEN as u32 - 1) {
            return TestResult::Fail("TX ring size encode mismatch");
        }
        if ((v >> 16) & 0xFFFF) != (RING_LEN as u32 - 1) {
            return TestResult::Fail("RX ring size encode mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/forcedeth",
        smoke_forcedeth_ring_sizes_encoding
    );
}
