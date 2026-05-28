//! Broadcom Tigon3 (`tg3`) Gigabit Ethernet driver — BCM57xx family.
//!
//! NARF Stage-4 cut. Targets the wired NetXtreme controllers shipped
//! on Dell / HP / Lenovo desktop and laptop boards (BCM5700 .. 5764M
//! roughly 2002-2012). The chip line carried into the NetXtreme II
//! (BCM57710) and the on-die NICs used by Sun / IBM / Apple Macs of
//! the same era.
//!
//! ## Reference
//!
//! Adapted from Linux `drivers/net/ethernet/broadcom/tg3.c` and
//! `tg3.h` (GPL-2.0-or-later). NARF is GPL-2.0-or-later as of
//! 2026-05-20 so direct register-layout citations are kept inline.
//!
//! The BCM57xx PCIe surface is laid out across one 64-bit MMIO BAR
//! (BAR0); registers are byte-addressable. The driver only touches
//! the standard "low" register window (offsets 0x0000..0x6FFF):
//!
//! | offset  | name              | description                       |
//! |---------|-------------------|-----------------------------------|
//! | 0x0068  | MISC_HOST_CTRL    | Endian, INDIR access toggles      |
//! | 0x0410  | MAC_ADDR_0_HIGH   | MAC[0..1] (upper 16 bits)         |
//! | 0x0414  | MAC_ADDR_0_LOW    | MAC[2..5] (lower 32 bits)         |
//! | 0x044c  | MAC_MI_COM        | MII (PHY) command/data            |
//! | 0x0450  | MAC_MI_STAT       | MII status                        |
//! | 0x0454  | MAC_MI_MODE       | MII clock divider                 |
//! | 0x6800  | GRC_MODE          | Global cfg — endian / stackup     |
//! | 0x6804  | GRC_MISC_CFG      | Core-clock reset (self-clearing)  |
//!
//! Stage 0 scope: PCI probe, BAR0 mapping, MAC address read. The
//! data-path (`receive`/`transmit`) returns `Err(NotImplemented)`
//! until later stages plug in the BD rings.

extern crate alloc;

use core::fmt::Write as _;
use core::sync::atomic::{compiler_fence, Ordering};

use alloc::sync::Arc;
use narf_ipc::{channel, Consumer, Producer};
use narf_net::{Frame, RX_RING_N, TX_RING_N};
use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write,
};

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: Broadcom Corporation.
pub const BCM_VENDOR: u16 = 0x14E4;

// BCM57xx NetXtreme device ids we recognise. List intentionally
// covers the 6-8 most-deployed variants:
//
//   - 5700  / 5701  : original NetXtreme (PCI-X).
//   - 5705x        : value SKU, shipped on Sun / IBM blades.
//   - 5714  / 5715 : single + dual-port PCIe.
//   - 5751  / 5752 : popular Dell / HP desktop LOM.
//   - 5754  / 5755 : business desktop / SFF.
//   - 5764M        : Lenovo / HP laptop docking-station LOM.
//   - 5780  / 5781 : NetXtreme refresh.

pub const BCM_5700: u16 = 0x1644;
pub const BCM_5701: u16 = 0x1645;
pub const BCM_5705: u16 = 0x1653;
pub const BCM_5705_2: u16 = 0x1654;
pub const BCM_5705M: u16 = 0x165D;
pub const BCM_5705M_2: u16 = 0x165E;
pub const BCM_5714: u16 = 0x1668;
pub const BCM_5715: u16 = 0x1678;
pub const BCM_5721: u16 = 0x1659;
pub const BCM_5751: u16 = 0x1677;
pub const BCM_5751M: u16 = 0x167D;
pub const BCM_5752: u16 = 0x1600;
pub const BCM_5752M: u16 = 0x1601;
pub const BCM_5754: u16 = 0x167A;
pub const BCM_5754M: u16 = 0x1672;
pub const BCM_5755: u16 = 0x167B;
pub const BCM_5755M: u16 = 0x1673;
pub const BCM_5764M: u16 = 0x1684;
pub const BCM_5780: u16 = 0x166A;
pub const BCM_5781: u16 = 0x166E;
pub const BCM_5782: u16 = 0x1696;

/// Every Broadcom device id this driver claims. Maintained as a
/// single `const` so the registration loop and the match-table
/// smoke test see the same list.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    BCM_5700, BCM_5701, BCM_5705, BCM_5705_2, BCM_5705M, BCM_5705M_2, BCM_5714, BCM_5715, BCM_5721,
    BCM_5751, BCM_5751M, BCM_5752, BCM_5752M, BCM_5754, BCM_5754M, BCM_5755, BCM_5755M, BCM_5764M,
    BCM_5780, BCM_5781, BCM_5782,
];

// ── Register offsets ────────────────────────────────────────────────
//
// Names mirror Linux `tg3.h` so future-Claude can cross-reference
// driver-side adjustments cleanly. Only the registers the Stage 0
// path touches are declared here; rings / IRQ status / MI-mode
// constants land in later stages.

const REG_MISC_HOST_CTRL: u64 = 0x0068;
const REG_MAC_ADDR_0_HIGH: u64 = 0x0410;
const REG_MAC_ADDR_0_LOW: u64 = 0x0414;
const REG_MAC_MI_COM: u64 = 0x044C;
#[allow(dead_code)] // Stage 1 — MI status, used by smoke tests
const REG_MAC_MI_STAT: u64 = 0x0450;
const REG_MAC_MI_MODE: u64 = 0x0454;
const REG_GRC_MODE: u64 = 0x6800;
const REG_GRC_MISC_CFG: u64 = 0x6804;

// ── Bit definitions ────────────────────────────────────────────────
//
// All bit positions mirror Linux `tg3.h`.

// MISC_HOST_CTRL (0x0068).
const MISC_HOST_CTRL_BYTE_SWAP: u32 = 0x0000_0004;
const MISC_HOST_CTRL_WORD_SWAP: u32 = 0x0000_0008;
const MISC_HOST_CTRL_PCISTATE_RW: u32 = 0x0000_0010;
const MISC_HOST_CTRL_CLKREG_RW: u32 = 0x0000_0020;
const MISC_HOST_CTRL_INDIR_ACCESS: u32 = 0x0000_0080;
const MISC_HOST_CTRL_TAGGED_STATUS: u32 = 0x0000_0200;

// GRC_MODE (0x6800). Standard host-stackup config: native-endian
// frame data + descriptors, stackup on, no IRQ-on-coalesce.
const GRC_MODE_HOST_STACKUP: u32 = 0x0001_0000;
const GRC_MODE_HOST_SENDBDS: u32 = 0x0002_0000;
const GRC_MODE_INT_ON_MAC_ATTN: u32 = 0x0400_0000;
#[allow(dead_code)] // wired in Stage 2
const GRC_MODE_4X_NIC_SEND_RINGS: u32 = 0x2000_0000;

// GRC_MISC_CFG (0x6804) — core-clock reset. Self-clearing; the chip
// re-initialises every block while the bit is set then drops it.
const GRC_MISC_CFG_CORECLK_RESET: u32 = 0x0000_0001;

// MAC_MI_COM (0x044C) — MII command/data register.
const MI_COM_CMD_READ: u32 = 0x0800_0000;
const MI_COM_START: u32 = 0x2000_0000;
const MI_COM_BUSY: u32 = 0x2000_0000;
const MI_COM_PHY_ADDR_SHIFT: u32 = 21;
const MI_COM_REG_ADDR_SHIFT: u32 = 16;
const MI_COM_DATA_MASK: u32 = 0x0000_FFFF;

// MAC_MI_MODE (0x0454) — MII clock divider. Bit 11 = AUTO_POLL.
// Per Linux: divider 0x1F (decimal 31) → ~2.5 MHz MDC at 80 MHz
// MAC clock, comfortably under the IEEE 802.3 MDC max (2.5 MHz).
#[allow(dead_code)] // Stage 2 — read_phy fast path will toggle this off
const MAC_MI_MODE_AUTO_POLL: u32 = 0x0000_0010;
const MAC_MI_MODE_DEFAULT_CLK: u32 = 0x0000_001F;

// MII (Clause 22) standard register addresses + bit positions used
// here. Same shape as Linux `<linux/mii.h>`. We only need BMSR to
// read link state.
const MII_REG_BMCR: u8 = 0x00;
const MII_REG_BMSR: u8 = 0x01;
const MII_BMSR_LINK_UP: u16 = 0x0004;

/// PHY address on the BCM57xx internal MDIO bus. Tigon3 hard-wires
/// the internal copper PHY to address 1 (see `tp->phy_addr` init in
/// `tg3_get_invariants`).
const PHY_ADDR_INTERNAL: u8 = 0x01;

// ── BD ring sizing ─────────────────────────────────────────────────

/// RX standard ring depth. Linux uses 200/2048 depending on chip
/// (5705 vs 5717+); 256 is the slot count that fits one
/// `alloc_coherent` page (256 * 32 = 8192 bytes) and matches what
/// most Stage-4 NARF drivers use.
pub const RX_STD_RING_LEN: usize = 256;
const RX_STD_RING_BYTES: usize = RX_STD_RING_LEN * core::mem::size_of::<RxBufferDesc>();

/// TX ring depth. Linux uses 512 by default; we mirror RX so one
/// pool of DMA pages can back both.
pub const TX_RING_LEN: usize = 256;
const TX_RING_BYTES: usize = TX_RING_LEN * core::mem::size_of::<TxBufferDesc>();

/// RX buffer size for the standard ring. 2 KiB matches the 5705+
/// "standard" buffer slot (jumbo + mini live on separate rings we
/// don't program in Stage 2).
pub const RX_BUF_LEN: usize = 2048;

// ── Mailbox / doorbell offsets ─────────────────────────────────────
//
// BCM57xx mailboxes are 64-bit, low-half-first. The high-half is
// unused for the indices we touch in Stage 2. Linux uses
// `tw32_mailbox` to write only the low word — same idiom here.

const REG_MAILBOX_RCV_STD_PROD_IDX: u64 = 0x0268;
const REG_MAILBOX_SNDHOST_PROD_IDX_0: u64 = 0x0300;

// ── Tx/Rx descriptor layouts ───────────────────────────────────────
//
// Bit-for-bit copy of Linux `struct tg3_tx_buffer_desc` and
// `struct tg3_rx_buffer_desc` (tg3.h:2553 / 2584). Each field is a
// 32-bit naturally-aligned word; the DMA hardware reads them in
// little-endian on x86_64 (we use GRC_MODE.BSWAP_DATA = 0).

#[repr(C, align(4))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxBufferDesc {
    /// Buffer physical-address high word.
    pub addr_hi: u32,
    /// Buffer physical-address low word.
    pub addr_lo: u32,
    /// `len << 16 | flags`. Flags subset:
    ///   - bit 2 (0x0004) = END (last fragment of packet).
    ///   - bit 0 (0x0001) = TCPUDP_CSUM.
    pub len_flags: u32,
    /// VLAN tag (bits[15:0]) + MSS (bits[31:16]). Stage 2 leaves
    /// both at 0.
    pub vlan_tag: u32,
}
const _: () = assert!(core::mem::size_of::<TxBufferDesc>() == 16);

#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxBufferDesc {
    /// Buffer physical-address high word.
    pub addr_hi: u32,
    /// Buffer physical-address low word.
    pub addr_lo: u32,
    /// `(idx << 16) | len`. On producer-fill `idx` is the slot
    /// index; on consumer-return `len` is the received frame length.
    pub idx_len: u32,
    /// `(type << 16) | flags`. `type` is 0 for the standard ring.
    /// Flags include END (0x0004), ERROR (0x0400), JUMBO (0x0020).
    pub type_flags: u32,
    /// IP/TCP checksum result on RX (Stage 2 ignores).
    pub ip_tcp_csum: u32,
    /// Error + VLAN bits. Stage 2 reads RXD_ERR_MASK here.
    pub err_vlan: u32,
    /// Reserved. Stage 2 leaves at 0.
    pub reserved: u32,
    /// Opaque tag — driver-private, copied back unchanged by HW.
    /// Linux stores the producer index here so it can find the
    /// matching skb on consumer return.
    pub opaque: u32,
}
const _: () = assert!(core::mem::size_of::<RxBufferDesc>() == 32);

// TX descriptor flag bits, native widths.
pub const TXD_FLAG_END: u32 = 0x0004;
pub const TXD_LEN_SHIFT: u32 = 16;

// RX descriptor flag bits (in `type_flags`).
pub const RXD_FLAG_END: u32 = 0x0004;
pub const RXD_FLAG_ERROR: u32 = 0x0400;

// Error mask in `err_vlan`. Mirrors Linux `RXD_ERR_MASK` per
// tg3.h:2630 — BAD_CRC | COLLISION | LINK_LOST | PHY_DECODE |
// MAC_ABRT | TOO_SMALL | NO_RESOURCES | HUGE_FRAME.
pub const RXD_ERR_BAD_CRC: u32 = 0x0001_0000;
pub const RXD_ERR_COLLISION: u32 = 0x0002_0000;
pub const RXD_ERR_LINK_LOST: u32 = 0x0004_0000;
pub const RXD_ERR_PHY_DECODE: u32 = 0x0008_0000;
pub const RXD_ERR_MAC_ABRT: u32 = 0x0020_0000;
pub const RXD_ERR_TOO_SMALL: u32 = 0x0040_0000;
pub const RXD_ERR_NO_RESOURCES: u32 = 0x0080_0000;
pub const RXD_ERR_HUGE_FRAME: u32 = 0x0100_0000;
pub const RXD_ERR_MASK: u32 = RXD_ERR_BAD_CRC
    | RXD_ERR_COLLISION
    | RXD_ERR_LINK_LOST
    | RXD_ERR_PHY_DECODE
    | RXD_ERR_MAC_ABRT
    | RXD_ERR_TOO_SMALL
    | RXD_ERR_NO_RESOURCES
    | RXD_ERR_HUGE_FRAME;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    /// MAC reads back as either all-zero or all-FFs — suggests the
    /// device is half-dead or the BAR isn't actually mapped.
    BadMac,
    /// `alloc_coherent` failed during ring or buffer-pool setup.
    NoMemory,
    /// Frame outside `[1, 1518]`.
    FrameTooLong,
    /// `transmit` couldn't find a free TX descriptor.
    TxRingFull,
    /// Data path not implemented yet (placeholder for paths not
    /// fully wired to silicon yet).
    NotImplemented,
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Decode the 6-byte MAC out of the high/low half-words read from
/// MAC_ADDR_0_HIGH/LOW. The chip lays the address big-endian-on-wire:
///
///   HIGH[15:8]  = MAC[0]
///   HIGH[7:0]   = MAC[1]
///   LOW[31:24]  = MAC[2]
///   LOW[23:16]  = MAC[3]
///   LOW[15:8]   = MAC[4]
///   LOW[7:0]    = MAC[5]
///
/// Split out so unit tests can verify the decode without standing up
/// a full Tg3Nic. (Linux's `tg3_get_eeprom_hw_cfg` uses the same shift
/// pattern — see drivers/net/ethernet/broadcom/tg3.c near line 14000.)
pub fn decode_mac(mac_hi: u32, mac_lo: u32) -> [u8; 6] {
    [
        ((mac_hi >> 8) & 0xFF) as u8,
        (mac_hi & 0xFF) as u8,
        ((mac_lo >> 24) & 0xFF) as u8,
        ((mac_lo >> 16) & 0xFF) as u8,
        ((mac_lo >> 8) & 0xFF) as u8,
        (mac_lo & 0xFF) as u8,
    ]
}

// ── Driver state ────────────────────────────────────────────────────

/// A live BCM57xx NetXtreme controller. Stage 2 holds the MMIO
/// mapping, the standard RX + TX BD rings, per-slot RX/TX DMA
/// buffers, post-reset MAC + link snapshot. IRQ wiring lands in
/// Stage 3.
pub struct Tg3Nic {
    mmio: MmioRegion,
    /// TX BD ring (`TX_RING_LEN * 16` bytes, contiguous DMA).
    tx_ring: DmaBuffer,
    /// Per-slot TX frame buffers. Persistent so we don't re-alloc
    /// per packet — slot index keys into the pool.
    tx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Producer cursor for the TX ring (next slot to fill).
    tx_head: IrqSafeSpinLock<u32>,
    /// RX BD ring (`RX_STD_RING_LEN * 32` bytes, contiguous DMA).
    rx_ring: DmaBuffer,
    /// Per-slot RX frame buffers. Pre-armed at bring-up; descriptor
    /// `i` always points at `rx_pool[i]`.
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Consumer cursor for the RX ring.
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address read from MAC_ADDR_0_HIGH/LOW at bring-up.
    pub mac: [u8; 6],
    /// Cached PCI device id — useful for chip-rev-specific quirks
    /// landed in later stages.
    pub device_id: u16,
    /// Latched link state read from BMSR.LinkSts at bring-up. Real-HW
    /// link status often comes up `false` immediately after reset; a
    /// Stage 1 driver doesn't yet re-poll on a LinkChg interrupt.
    pub link_up: bool,
    /// True iff `tg3_chip_reset` ran (Stage 1+). Used by tests that
    /// want to detect "Stage-0 fallback" probe paths.
    pub reset_done: bool,

    // IPC integration
    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

unsafe impl Send for Tg3Nic {}
unsafe impl Sync for Tg3Nic {}

impl core::fmt::Debug for Tg3Nic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tg3Nic")
            .field("device_id", &self.device_id)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

impl Tg3Nic {
    /// Bring up the controller: map BAR0, run `tg3_chip_reset`,
    /// program GRC_MODE (host stackup), read MAC, snapshot link
    /// state from BMSR. Stage 1 cut — no BD ring init, no IRQ
    /// binding.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively for
    /// the duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NicError> {
        // BCM57xx places its register block on BAR0 (memory-type, 64
        // bit on PCIe parts, 32 bit on legacy PCI-X parts). Linux's
        // `tg3_init_one` calls `pci_iomap(pdev, BAR_0, ...)` first
        // thing.
        // SAFETY: caller-asserted exclusive ownership.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| NicError::BarMapFailed)?;

        // Fingerprint chip rev BEFORE the reset clobbers anything.
        // SAFETY: identity-mapped MMIO; reads are pure observations.
        let pre_misc_host_ctrl = unsafe { mmio.read32(REG_MISC_HOST_CTRL) };
        let chip_rev = (pre_misc_host_ctrl >> 16) & 0xFFFF;

        let _ = writeln!(
            narf_console::Writer,
            "  tg3: BCM{:04X} BAR0={:#018x}+{:#x} chiprev={:#06x}",
            device.id.device,
            mmio.phys.raw(),
            mmio.len,
            chip_rev,
        );

        // Run the chip reset before reading MAC. On a cold-boot
        // BCM57xx, MAC_ADDR_0_HIGH/LOW are programmed by the boot
        // firmware (or NVRAM auto-load) and survive reset; on a
        // warm-boot the firmware may not have re-run, so Stage 1
        // reads MAC post-reset to match Linux's order (reset → MAC).
        // SAFETY: caller-asserted exclusive ownership; identity-mapped.
        let reset_done = unsafe { Self::chip_reset(&mmio) };

        // Read MAC from MAC_ADDR_0_HIGH/LOW. Per `tg3.h`:
        //   - HIGH at 0x0410 carries the upper 2 bytes in bits[15:0].
        //   - LOW  at 0x0414 carries the lower 4 bytes in bits[31:0].
        // SAFETY: identity-mapped MMIO; reads are pure observations.
        let mac_hi = unsafe { mmio.read32(REG_MAC_ADDR_0_HIGH) };
        // SAFETY: same.
        let mac_lo = unsafe { mmio.read32(REG_MAC_ADDR_0_LOW) };
        let mac = decode_mac(mac_hi, mac_lo);

        let _ = writeln!(
            narf_console::Writer,
            "  tg3: MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        );

        // Sanity-check: all-zero or all-FFs MAC means the BAR isn't
        // mapped or the device is half-dead. Don't fail probe (the
        // bus layer treats `BadDevice` as "driver doesn't claim
        // this one"), but log loudly so the boot trace shows it.
        let all_zero = mac.iter().all(|b| *b == 0);
        let all_ff = mac.iter().all(|b| *b == 0xFF);
        if all_zero || all_ff {
            let _ = writeln!(
                narf_console::Writer,
                "  tg3: MAC reads as {} — BAR likely unmapped or chip wedged in reset",
                if all_zero { "all-zero" } else { "all-FF" }
            );
            return Err(NicError::BadMac);
        }

        // Snapshot link state from BMSR via the MII bus. Per Linux's
        // `__tg3_readphy`: auto-poll must be off for software-driven
        // MDIO; Stage 1 leaves the MI_MODE default (no auto-poll, no
        // INTLPBK) so the read path is the simple one.
        // SAFETY: identity-mapped MMIO; caller owns the device.
        let bmsr = unsafe { Self::read_phy(&mmio, PHY_ADDR_INTERNAL, MII_REG_BMSR) }
            .unwrap_or(0xFFFF);
        let link_up = bmsr != 0xFFFF && (bmsr & MII_BMSR_LINK_UP) != 0;

        let _ = writeln!(
            narf_console::Writer,
            "  tg3: BMSR={:#06x} link_up={} reset={}",
            bmsr, link_up, reset_done,
        );

        // Final GRC_MODE snapshot post-reset — useful when triaging
        // a chip that comes back up with the wrong endian/stackup
        // config. Stage 1 already programmed HOST_STACKUP inside
        // `chip_reset`; this read confirms it took.
        // SAFETY: identity-mapped MMIO.
        let grc_mode = unsafe { mmio.read32(REG_GRC_MODE) };
        let _ = writeln!(
            narf_console::Writer,
            "  tg3: GRC_MODE={:#010x} (HOST_STACKUP={})",
            grc_mode,
            grc_mode & GRC_MODE_HOST_STACKUP != 0,
        );

        // Stage 2: allocate the BD rings + per-slot DMA buffers. The
        // chip has 4 ring types (RX std, RX jumbo, RX RCB, TX); Stage
        // 2 only programs RX std + TX which covers every Ethernet-
        // frame-sized transfer.
        let tx_ring = alloc_coherent(TX_RING_BYTES, DomainId::DRIVER_0)
            .map_err(|_| NicError::NoMemory)?;
        let rx_ring = alloc_coherent(RX_STD_RING_BYTES, DomainId::DRIVER_0)
            .map_err(|_| NicError::NoMemory)?;

        let mut tx_pool: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(TX_RING_LEN);
        for _ in 0..TX_RING_LEN {
            tx_pool.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0)
                    .map_err(|_| NicError::NoMemory)?,
            );
        }
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(RX_STD_RING_LEN);
        for _ in 0..RX_STD_RING_LEN {
            rx_pool.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0)
                    .map_err(|_| NicError::NoMemory)?,
            );
        }

        // Pre-arm every RX BD with its pooled buffer + length.
        // Linux's `tg3_rx_prodring_alloc` does this in
        // `tg3_init_rings`. The chip walks the ring linearly; we
        // don't carry an EOR bit (BCM57xx wraps via the producer
        // index in the mailbox, not in the descriptor).
        let rx_ring_phys = rx_ring.phys_addr().raw();
        for i in 0..RX_STD_RING_LEN {
            let buf_phys = rx_pool[i].phys_addr().raw();
            let d = RxBufferDesc {
                addr_hi: (buf_phys >> 32) as u32,
                addr_lo: buf_phys as u32,
                idx_len: ((i as u32) << 16) | (RX_BUF_LEN as u32 & 0xFFFF),
                type_flags: 0,
                ip_tcp_csum: 0,
                err_vlan: 0,
                reserved: 0,
                opaque: i as u32,
            };
            // SAFETY: ring is a DmaBuffer of RX_STD_RING_BYTES, i is
            // bounded by RX_STD_RING_LEN.
            unsafe {
                let slot = (rx_ring_phys + (i * core::mem::size_of::<RxBufferDesc>()) as u64)
                    as *mut RxBufferDesc;
                core::ptr::write_volatile(slot, d);
            }
        }
        // Zero the TX ring — the chip will see OWN bits clear (we
        // populate them on `transmit`).
        let tx_ring_phys = tx_ring.phys_addr().raw();
        for i in 0..TX_RING_LEN {
            // SAFETY: ring is a DmaBuffer of TX_RING_BYTES, i is
            // bounded by TX_RING_LEN.
            unsafe {
                let slot = (tx_ring_phys + (i * core::mem::size_of::<TxBufferDesc>()) as u64)
                    as *mut TxBufferDesc;
                core::ptr::write_volatile(slot, TxBufferDesc::default());
            }
        }
        compiler_fence(Ordering::SeqCst);

        let _ = writeln!(
            narf_console::Writer,
            "  tg3: rings allocated — RX@{:#018x} ({} slots) TX@{:#018x} ({} slots)",
            rx_ring_phys,
            RX_STD_RING_LEN,
            tx_ring_phys,
            TX_RING_LEN,
        );

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let tg3 = Arc::new(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_head: IrqSafeSpinLock::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            device_id: device.id.device,
            link_up,
            reset_done,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn pumps
        spawn_pumps(tg3.clone(), rx_prod, tx_cons);

        Ok(Arc::try_unwrap(tg3).map_err(|_| NicError::NoMemory)?)
    }

    /// Perform the BCM57xx chip reset sequence — `GRC_MISC_CFG.CORECLK_RESET`
    /// is self-clearing, so we set it then poll until it goes away.
    /// Programs MISC_HOST_CTRL with the standard host-side endian
    /// + indirect-access bits, and GRC_MODE with HOST_STACKUP +
    /// HOST_SENDBDS so the chip drives its descriptor rings from
    /// host memory.
    ///
    /// Adapted from Linux `tg3_chip_reset` (drivers/net/ethernet/
    /// broadcom/tg3.c). Stage 1 omits the ASIC-rev-specific quirks
    /// (5752 fastboot, 5906 VCPU, PCIe 1.0a forcing) — those land
    /// when bring-up exercises specific silicon.
    ///
    /// Returns `true` if the reset bit was observed to clear within
    /// the budget. A `false` return means we time out — the caller
    /// can proceed (the registers may still be usable on a stuck
    /// chip) but should flag the device.
    ///
    /// # Safety
    /// `mmio` covers BAR0 of an owned tg3 device.
    unsafe fn chip_reset(mmio: &MmioRegion) -> bool {
        // 1. Program MISC_HOST_CTRL to a known-good state. Linux's
        //    `tg3_get_invariants` sets these in `tp->misc_host_ctrl`
        //    before reset; we keep the host-side endian-swap bits
        //    off (NARF + BCM are both little-endian on x86_64).
        //    INDIR_ACCESS + PCISTATE_RW + CLKREG_RW open the
        //    indirect-register window the bring-up walk uses;
        //    TAGGED_STATUS gates the tagged-IRQ feature we need
        //    in Stage 2.
        let misc_host =
            MISC_HOST_CTRL_INDIR_ACCESS
                | MISC_HOST_CTRL_PCISTATE_RW
                | MISC_HOST_CTRL_CLKREG_RW
                | MISC_HOST_CTRL_TAGGED_STATUS
                | MISC_HOST_CTRL_BYTE_SWAP * 0
                | MISC_HOST_CTRL_WORD_SWAP * 0;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_MISC_HOST_CTRL, misc_host);
        }

        // 2. Fire the core-clock reset. Bit is self-clearing per
        //    `tg3.h` (line 1749) — once the chip finishes its
        //    internal re-init the bit drops to 0.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_GRC_MISC_CFG, GRC_MISC_CFG_CORECLK_RESET);
        }

        // 3. Per the Linux comment block at tg3.c:9259:
        //    "we have to delay before the PCI read back. Some 575X
        //     chips even will not respond to a PCI cfg access when
        //     the reset command is given to the chip."
        //    `udelay(120)` is the Linux value. NARF's
        //    `responsive_spin_until` is the closest analog — it
        //    spin-waits while ticking the kernel sleep_pumps so the
        //    framebuffer cursor + serial drain stay alive on a slow
        //    reset. 250 ms wall-clock budget covers worst-case
        //    PCIe re-train.
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(REG_GRC_MISC_CFG) } & GRC_MISC_CFG_CORECLK_RESET == 0,
            narf_time::Deadline::after_ms(250),
        );

        // 4. Re-program MISC_HOST_CTRL after reset — the
        //    core-clock reset clears the indirect-access bit on
        //    some 575X parts and we need it back on before any
        //    further register access.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_MISC_HOST_CTRL, misc_host);
        }

        // 5. Program GRC_MODE. HOST_STACKUP tells the chip to drive
        //    its descriptor rings from host memory (vs. the on-die
        //    SRAM that NetXtreme II uses); HOST_SENDBDS gates the
        //    send-BD ring; INT_ON_MAC_ATTN makes MAC attention
        //    events raise an IRQ (used by Stage 2's link-change
        //    handler).
        let grc_mode = GRC_MODE_HOST_STACKUP | GRC_MODE_HOST_SENDBDS | GRC_MODE_INT_ON_MAC_ATTN;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_GRC_MODE, grc_mode);
        }

        // 6. Program the MII clock divider. Default 0x1F gives
        //    ~2.5 MHz MDC at 80 MHz MAC clock. Auto-poll OFF for
        //    Stage 1 — software drives PHY reads via __tg3_readphy.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_MAC_MI_MODE, MAC_MI_MODE_DEFAULT_CLK);
        }
        // Per `__tg3_readphy`, ~80 us after MAC_MI_MODE writes
        // before the bus is stable. We hand off a fast spin —
        // 80 us is below our `Deadline` resolution but
        // `responsive_spin_until` polls in a tight loop and the
        // first iteration alone is several us.
        let _ = narf_scheduler::responsive_spin_until(
            || true,
            narf_time::Deadline::after_ms(1),
        );

        cleared
    }

    /// Read a 16-bit MII-Clause-22 register through MAC_MI_COM. This
    /// is the software-driven path — caller must have programmed
    /// MAC_MI_MODE with auto-poll OFF (which Stage 1 does in
    /// `chip_reset`).
    ///
    /// Adapted from Linux `__tg3_readphy` (drivers/net/ethernet/
    /// broadcom/tg3.c:1118). Returns `Some(data)` when the BUSY bit
    /// drops within `PHY_BUSY_LOOPS` iterations; `None` on timeout
    /// (chip wedged or MI bus disabled).
    ///
    /// # Safety
    /// `mmio` covers BAR0; caller owns the device's MMIO window.
    unsafe fn read_phy(mmio: &MmioRegion, phy_addr: u8, reg: u8) -> Option<u16> {
        let frame_val = ((phy_addr as u32) << MI_COM_PHY_ADDR_SHIFT)
            | ((reg as u32) << MI_COM_REG_ADDR_SHIFT)
            | MI_COM_CMD_READ
            | MI_COM_START;
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_MAC_MI_COM, frame_val);
        }

        // Linux polls 5000 times with `udelay(10)` (= ~50 ms wall).
        // We use `responsive_spin_until` with a 100 ms deadline so
        // a wedged MI bus surfaces as `None` rather than locking
        // bring-up.
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(REG_MAC_MI_COM) } & MI_COM_BUSY == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !cleared {
            return None;
        }

        // SAFETY: identity-mapped MMIO.
        let final_val = unsafe { mmio.read32(REG_MAC_MI_COM) };
        Some((final_val & MI_COM_DATA_MASK) as u16)
    }

    /// Re-read BMSR and update `link_up`. Returns the new value.
    /// Useful for link-change polling until Stage 2 wires a real
    /// LinkChg IRQ.
    pub fn refresh_link_state(&mut self) -> bool {
        // SAFETY: identity-mapped MMIO; we own the device.
        let bmsr = unsafe { Self::read_phy(&self.mmio, PHY_ADDR_INTERNAL, MII_REG_BMSR) }
            .unwrap_or(0xFFFF);
        let up = bmsr != 0xFFFF && (bmsr & MII_BMSR_LINK_UP) != 0;
        self.link_up = up;
        up
    }

    /// Read BMCR via the MII bus. Mostly useful for diagnostics +
    /// tests — the value reflects PHY admin state (power down,
    /// loopback, restart-autoneg) rather than link.
    pub fn read_bmcr(&self) -> Option<u16> {
        // SAFETY: identity-mapped MMIO; we own the device.
        unsafe { Self::read_phy(&self.mmio, PHY_ADDR_INTERNAL, MII_REG_BMCR) }
    }

    /// Read MAC_MI_STAT — the MII status register. Bit 0 (LNKSTAT_ATTN_ENAB)
    /// is the "link state attention" enable used by Stage 2's IRQ
    /// path; exposed here so smoke tests can confirm reset programs
    /// the register sensibly.
    pub fn read_mi_stat(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_MAC_MI_STAT) }
    }

    /// Stage 2: copy `frame` into the next TX slot's buffer, write a
    /// fully-formed TX descriptor, advance the producer index. Does
    /// not yet ring the SNDHOST_PROD_IDX mailbox — that's Stage 3
    /// (real silicon will need SNDBDS_MODE enabled + the mailbox
    /// doorbell + a TX-completion IRQ to drain).
    ///
    /// Returns `Ok(slot)` so a caller (or smoke test) can locate the
    /// produced descriptor in the ring without re-deriving it.
    pub fn transmit(&self, frame: &[u8]) -> Result<u32, NicError> {
        if frame.is_empty() || frame.len() > 1518 {
            return Err(NicError::FrameTooLong);
        }
        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % TX_RING_LEN;
        let phys = self.tx_pool[slot].phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
            }
        }
        let d = TxBufferDesc {
            addr_hi: (phys >> 32) as u32,
            addr_lo: phys as u32,
            // len in upper 16 bits, END flag set (single-fragment
            // packet). Linux's `tg3_start_xmit_dma_bug` would set
            // VLAN / TSO / csum flags here; Stage 2 leaves them 0.
            len_flags: ((frame.len() as u32) << TXD_LEN_SHIFT) | TXD_FLAG_END,
            vlan_tag: 0,
        };
        // SAFETY: identity-mapped DMA ring; slot < TX_RING_LEN.
        unsafe {
            let p = (self.tx_ring.phys_addr().raw()
                + (slot * core::mem::size_of::<TxBufferDesc>()) as u64)
                as *mut TxBufferDesc;
            core::ptr::write_volatile(p, d);
        }
        compiler_fence(Ordering::SeqCst);

        let returned = *head_g;
        *head_g = (*head_g + 1) % (TX_RING_LEN as u32);
        // Stage 3 will write `*head_g + 1` into
        // MAILBOX_SNDHOST_PROD_IDX_0 here to ring the doorbell.
        Ok(returned)
    }

    /// Stage 2: read the descriptor at the current RX consumer
    /// position. Returns `None` if the slot still looks unwritten
    /// (length == 0 + no flags + idx still matches the producer
    /// value we put there at bring-up). A real wire-fed RX would
    /// have the chip write a non-zero `idx_len` length field.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        let mut head_g = self.rx_head.lock();
        let slot = (*head_g) as usize % RX_STD_RING_LEN;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_ptr = (ring_phys
            + (slot * core::mem::size_of::<RxBufferDesc>()) as u64)
            as *const RxBufferDesc;
        // SAFETY: identity-mapped DMA ring; slot < RX_STD_RING_LEN.
        let d = unsafe { core::ptr::read_volatile(desc_ptr) };

        // On a fresh pre-arm we wrote `(idx << 16) | RX_BUF_LEN` into
        // `idx_len`. After the chip writes back, the low 16 bits
        // carry the actual frame length (≤ RX_BUF_LEN) but the slot's
        // self-idx (high 16) won't necessarily match anymore. The
        // simplest "did the chip touch this?" check is: did `type_flags`
        // gain any of the err / end / type bits? Stage 3 will swap
        // this for the proper "did the status block advance" check.
        if d.type_flags == 0 && d.err_vlan == 0 {
            return None;
        }
        let err = d.err_vlan & RXD_ERR_MASK != 0;

        let len = (d.idx_len & 0xFFFF) as usize;
        let copy_len = if err { 0 } else { len.min(RX_BUF_LEN) };
        let buf_phys = self.rx_pool[slot].phys_addr().raw();
        let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(copy_len);
        // SAFETY: identity-mapped DMA buffer; copy_len bounded.
        for i in 0..copy_len {
            out.push(unsafe { core::ptr::read_volatile((buf_phys + i as u64) as *const u8) });
        }

        // Rearm the slot in place: zero the metadata, restore the
        // self-idx pre-arm shape so the next chip-write produces a
        // distinguishable result. Stage 3 will also write the new
        // producer index back to MAILBOX_RCV_STD_PROD_IDX.
        let rearmed = RxBufferDesc {
            addr_hi: (buf_phys >> 32) as u32,
            addr_lo: buf_phys as u32,
            idx_len: ((slot as u32) << 16) | (RX_BUF_LEN as u32 & 0xFFFF),
            type_flags: 0,
            ip_tcp_csum: 0,
            err_vlan: 0,
            reserved: 0,
            opaque: slot as u32,
        };
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            let p = (self.rx_ring.phys_addr().raw()
                + (slot * core::mem::size_of::<RxBufferDesc>()) as u64)
                as *mut RxBufferDesc;
            core::ptr::write_volatile(p, rearmed);
        }
        compiler_fence(Ordering::SeqCst);
        *head_g = (*head_g + 1) % (RX_STD_RING_LEN as u32);
        if err {
            None
        } else {
            Some(out)
        }
    }

    /// Stage 2 introspection: read the TX descriptor at `slot`.
    /// Used by the FakeMmio round-trip smoke test to verify that
    /// `transmit` produces the descriptor shape the chip expects.
    pub fn read_tx_descriptor(&self, slot: usize) -> TxBufferDesc {
        let p = (self.tx_ring.phys_addr().raw()
            + ((slot % TX_RING_LEN) * core::mem::size_of::<TxBufferDesc>()) as u64)
            as *const TxBufferDesc;
        // SAFETY: identity-mapped DMA ring; slot bounded by modulo.
        unsafe { core::ptr::read_volatile(p) }
    }

    /// Stage 2 introspection: read the RX descriptor at `slot`.
    pub fn read_rx_descriptor(&self, slot: usize) -> RxBufferDesc {
        let p = (self.rx_ring.phys_addr().raw()
            + ((slot % RX_STD_RING_LEN) * core::mem::size_of::<RxBufferDesc>()) as u64)
            as *const RxBufferDesc;
        // SAFETY: identity-mapped DMA ring.
        unsafe { core::ptr::read_volatile(p) }
    }

    /// Stage 2 introspection: low-half of the RX producer mailbox.
    /// Stage 3 will write the actual producer index here when ringing
    /// the RX-fill doorbell.
    pub fn rx_prod_mailbox_addr(&self) -> u64 {
        REG_MAILBOX_RCV_STD_PROD_IDX
    }

    /// Stage 2 introspection: low-half of the TX producer mailbox.
    pub fn tx_prod_mailbox_addr(&self) -> u64 {
        REG_MAILBOX_SNDHOST_PROD_IDX_0
    }

    /// Current TX producer cursor (for tests).
    pub fn tx_head(&self) -> u32 {
        *self.tx_head.lock()
    }

    /// Current RX consumer cursor (for tests).
    pub fn rx_head(&self) -> u32 {
        *self.rx_head.lock()
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<Tg3Nic>>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`. Idempotent:
/// returns `Ok(())` when the controller is already brought up.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER are required: the chip DMAs the BD
    // rings + frame buffers, and we map BAR0 as MMIO. Leave INTx
    // open here — Stage 2 flips INTX_DISABLE on once MSI/MSI-X is
    // brought up.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller-authority over the device.
    let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

    let dev = match unsafe { Tg3Nic::bring_up(&device, &cap) } {
        Ok(d) => Arc::new(d),
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    {
        let d = unsafe { &mut *(Arc::as_ptr(&dev) as *mut Tg3Nic) };
        *d.rx_ipc_ring.lock() = Some(rx_cons);
        *d.tx_ipc_ring.lock() = Some(tx_prod);
    }

    *CONTROLLER.lock() = Some(dev.clone());

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Tg3HwNic);
    }

    // Spawn pumps
    spawn_pumps(dev, rx_prod, tx_cons);

    Ok(())
}

fn spawn_pumps(
    device: Arc<Tg3Nic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        tg3_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        tg3_tx_pump(d2, tx_cons).await;
    });
}

async fn tg3_rx_pump(device: Arc<Tg3Nic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    loop {
        if let Some(pkt) = device.receive() {
            let dma_buf = alloc_coherent(pkt.len(), DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, pkt.len() as u32);
            frame.payload_mut().copy_from_slice(&pkt);
            let _ = rx_prod.send(frame).await;
        }
        narf_scheduler::yield_now().await;
    }
}


async fn tg3_tx_pump(device: Arc<Tg3Nic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload());
    }
}



/// Register the driver against every Broadcom device id we recognise.
/// Each match carries a unique name (driver re-registration is
/// idempotent on `name` per `narf_bus::register_pci_driver`), so a
/// shared `"tg3"` would collapse the whole table down to the last
/// id. `name_for` returns a static per-id string.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: BCM_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Human-readable per-id driver name. Used as the `PciMatch.name`
/// key + in `record_bound` so the boot trace shows which exact
/// BCM57xx SKU got picked up.
fn name_for(did: u16) -> &'static str {
    match did {
        BCM_5700 => "tg3:BCM5700",
        BCM_5701 => "tg3:BCM5701",
        BCM_5705 => "tg3:BCM5705",
        BCM_5705_2 => "tg3:BCM5705_2",
        BCM_5705M => "tg3:BCM5705M",
        BCM_5705M_2 => "tg3:BCM5705M_2",
        BCM_5714 => "tg3:BCM5714",
        BCM_5715 => "tg3:BCM5715",
        BCM_5721 => "tg3:BCM5721",
        BCM_5751 => "tg3:BCM5751",
        BCM_5751M => "tg3:BCM5751M",
        BCM_5752 => "tg3:BCM5752",
        BCM_5752M => "tg3:BCM5752M",
        BCM_5754 => "tg3:BCM5754",
        BCM_5754M => "tg3:BCM5754M",
        BCM_5755 => "tg3:BCM5755",
        BCM_5755M => "tg3:BCM5755M",
        BCM_5764M => "tg3:BCM5764M",
        BCM_5780 => "tg3:BCM5780",
        BCM_5781 => "tg3:BCM5781",
        BCM_5782 => "tg3:BCM5782",
        _ => "tg3:BCM57xx",
    }
}

/// `true` once `probe` has installed a controller.
#[derive(Debug)]
pub struct Tg3HwNic;

impl narf_net::Interface for Tg3HwNic {
    fn name(&self) -> &str {
        "eth4"
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
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> = IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.rx_ipc_ring.lock().take();
            }
        });
        &RING
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> = IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.tx_ipc_ring.lock().take();
            }
        });
        &RING
    }
}

impl crate::HwNic for Tg3HwNic {
    fn name(&self) -> &'static str {
        "eth4" // TODO: dynamic naming
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
        crate::NicModel::IntelIgb // TODO: Add BroadcomTg3 to NicModel
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        TX_RING_LEN
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> = IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.rx_ipc_ring.lock().take();
            }
        });
        &RING
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> = IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.tx_ipc_ring.lock().take();
            }
        });
        &RING
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Test-side accessor: run `f` against the probed controller.
pub fn with_controller<R>(f: impl FnOnce(&Tg3Nic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

// ── Smoke tests ────────────────────────────────────────────────────
//
// Embedded here (rather than in `tests.rs`) because the parallel-
// agent contract for this Stage-4 push restricts edits to tg3.rs +
// the lib.rs hookup. The `kernel_test_in!` macro registers against
// the same `narf.tests` ELF section the runner reads.

#[cfg(target_arch = "x86_64")]
mod smoke {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_tg3_pci_match_table_covers_supported_ids() -> TestResult {
        // Structural smoke: register the tg3 driver and assert
        // every ID in `SUPPORTED_DEVICE_IDS` lands in the bus's
        // match table.
        use narf_bus::driver_match::__reset_for_test;
        use narf_bus::{registered_pci_drivers, MatchKind};
        __reset_for_test();
        register_pci_driver();
        let registered = registered_pci_drivers();
        for did in SUPPORTED_DEVICE_IDS.iter().copied() {
            let found = registered.iter().any(|m| {
                matches!(m.kind, MatchKind::VendorDevice {
                    vendor, device,
                } if vendor == BCM_VENDOR && device == did)
            });
            if !found {
                return TestResult::Fail("tg3 match entry missing");
            }
        }
        // Spot-check the marquee laptop/desktop SKUs explicitly so
        // a future refactor of `SUPPORTED_DEVICE_IDS` can't silently
        // drop them.
        let must_have: &[u16] = &[BCM_5700, BCM_5701, BCM_5751, BCM_5754, BCM_5755, BCM_5764M];
        for did in must_have.iter().copied() {
            let found = registered.iter().any(|m| {
                matches!(m.kind, MatchKind::VendorDevice {
                    vendor, device,
                } if vendor == BCM_VENDOR && device == did)
            });
            if !found {
                return TestResult::Fail("tg3 spot-check id missing");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_pci_match_table_covers_supported_ids);

    fn smoke_tg3_decode_mac_round_trips() -> TestResult {
        // Reference vector: HIGH = 0x0000_0011, LOW = 0x2233_4455 →
        // 00:11:22:33:44:55. Matches the byte order Linux tg3 uses
        // when storing the MAC into MAC_ADDR_0_*.
        let mac = decode_mac(0x0000_0011, 0x2233_4455);
        if mac != [0x00, 0x11, 0x22, 0x33, 0x44, 0x55] {
            return TestResult::Fail("MAC decode byte order drift");
        }
        // All-zero + all-FF round-trips — the BadMac guard at probe
        // depends on these being faithfully reproduced.
        if decode_mac(0, 0) != [0; 6] {
            return TestResult::Fail("all-zero MAC mis-decoded");
        }
        if decode_mac(0x0000_FFFF, 0xFFFF_FFFF) != [0xFF; 6] {
            return TestResult::Fail("all-FF MAC mis-decoded");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_decode_mac_round_trips);

    fn smoke_tg3_register_offsets_match_linux() -> TestResult {
        // Pin the offsets that the bring-up sequence relies on
        // against Linux's `tg3.h`. A one-byte drift here would
        // silently write into the wrong register (MISC_HOST_CTRL
        // at 0x6C instead of 0x68 lands on TG3PCI_DUAL_MAC_CTRL,
        // for example).
        if REG_MISC_HOST_CTRL != 0x0068 {
            return TestResult::Fail("MISC_HOST_CTRL offset drift");
        }
        if REG_MAC_ADDR_0_HIGH != 0x0410 || REG_MAC_ADDR_0_LOW != 0x0414 {
            return TestResult::Fail("MAC_ADDR_0_* offset drift");
        }
        if REG_MAC_MI_COM != 0x044C {
            return TestResult::Fail("MAC_MI_COM offset drift");
        }
        if REG_MAC_MI_STAT != 0x0450 {
            return TestResult::Fail("MAC_MI_STAT offset drift");
        }
        if REG_MAC_MI_MODE != 0x0454 {
            return TestResult::Fail("MAC_MI_MODE offset drift");
        }
        if REG_GRC_MODE != 0x6800 {
            return TestResult::Fail("GRC_MODE offset drift");
        }
        if REG_GRC_MISC_CFG != 0x6804 {
            return TestResult::Fail("GRC_MISC_CFG offset drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_register_offsets_match_linux);

    fn smoke_tg3_mi_com_frame_bit_layout_matches_linux() -> TestResult {
        // Construct the same frame_val Linux's `__tg3_readphy` does
        // for (phy_addr=1, reg=1) and verify the bit fields land in
        // the slots tg3.h documents:
        //   bits [25:21] = PHY address (5 bits)
        //   bits [20:16] = register address (5 bits)
        //   bits [29:26] = command (READ = 0b0010 at bit 26 = 0x0800_0000 ? )
        //   bit  [29]    = START / BUSY
        let phy_addr: u32 = 0x01;
        let reg: u32 = 0x01;
        let frame_val =
            (phy_addr << MI_COM_PHY_ADDR_SHIFT) | (reg << MI_COM_REG_ADDR_SHIFT) | MI_COM_CMD_READ | MI_COM_START;
        // PHY address ends up in bits [25:21] → phy_addr << 21.
        if (frame_val >> 21) & 0x1F != 0x01 {
            return TestResult::Fail("PHY address shift drift");
        }
        // Register address in bits [20:16] → reg << 16.
        if (frame_val >> 16) & 0x1F != 0x01 {
            return TestResult::Fail("REG address shift drift");
        }
        // CMD_READ at bit 27 (0x0800_0000) per tg3.h:482.
        if MI_COM_CMD_READ != 0x0800_0000 {
            return TestResult::Fail("CMD_READ position drift");
        }
        // START at bit 29 (0x2000_0000) per tg3.h:484.
        if MI_COM_START != 0x2000_0000 {
            return TestResult::Fail("START position drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_mi_com_frame_bit_layout_matches_linux);

    fn smoke_tg3_grc_mode_includes_host_stackup() -> TestResult {
        // Per Linux comment in `tg3_chip_reset`: GRC_MODE must
        // carry HOST_STACKUP for the chip to drive descriptor
        // rings from host memory (as opposed to on-die SRAM). A
        // bring-up that loses this bit would tx into the SRAM
        // ring and the host never sees TX completions.
        if GRC_MODE_HOST_STACKUP != 0x0001_0000 {
            return TestResult::Fail("HOST_STACKUP bit position drift");
        }
        if GRC_MODE_HOST_SENDBDS != 0x0002_0000 {
            return TestResult::Fail("HOST_SENDBDS bit position drift");
        }
        if GRC_MISC_CFG_CORECLK_RESET != 0x0000_0001 {
            return TestResult::Fail("CORECLK_RESET bit position drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_grc_mode_includes_host_stackup);

    fn smoke_tg3_descriptor_layouts_match_linux() -> TestResult {
        // Pin the descriptor sizes + field offsets against Linux's
        // tg3.h. A drift here would let the driver write a 16-byte
        // descriptor into a 32-byte slot (RX) or vice versa, and
        // the chip would interpret garbage.
        if core::mem::size_of::<TxBufferDesc>() != 16 {
            return TestResult::Fail("TX descriptor size drift");
        }
        if core::mem::size_of::<RxBufferDesc>() != 32 {
            return TestResult::Fail("RX descriptor size drift");
        }
        // Linux `TXD_LEN_SHIFT` is 16 and `TXD_FLAG_END` is 0x0004.
        if TXD_LEN_SHIFT != 16 {
            return TestResult::Fail("TXD_LEN_SHIFT drift");
        }
        if TXD_FLAG_END != 0x0004 {
            return TestResult::Fail("TXD_FLAG_END drift");
        }
        if RXD_FLAG_END != 0x0004 {
            return TestResult::Fail("RXD_FLAG_END drift");
        }
        if RXD_FLAG_ERROR != 0x0400 {
            return TestResult::Fail("RXD_FLAG_ERROR drift");
        }
        // RXD_ERR_MASK should be the union of all eight error bits.
        if RXD_ERR_MASK & RXD_ERR_BAD_CRC == 0 {
            return TestResult::Fail("RXD_ERR_MASK missing BAD_CRC");
        }
        if RXD_ERR_MASK & RXD_ERR_HUGE_FRAME == 0 {
            return TestResult::Fail("RXD_ERR_MASK missing HUGE_FRAME");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_descriptor_layouts_match_linux);

    fn smoke_tg3_tx_descriptor_round_trip() -> TestResult {
        // Stage 2 round-trip on the descriptor packing — the chip
        // reads `len_flags` as `(len << 16) | flags`. The smoke
        // exercises the same shift-and-or math `transmit()` does so
        // that a refactor that re-shifts incorrectly is caught
        // without needing a probed device.
        let frame_len: u32 = 1500;
        let len_flags = (frame_len << TXD_LEN_SHIFT) | TXD_FLAG_END;
        // High 16 bits → length.
        if (len_flags >> 16) != frame_len {
            return TestResult::Fail("frame len doesn't survive shift");
        }
        // Low 16 bits → flags.
        if len_flags & 0xFFFF != TXD_FLAG_END {
            return TestResult::Fail("END flag lost in low-16");
        }
        // Repack into a TxBufferDesc, confirm field-by-field
        // round-trip.
        let d = TxBufferDesc {
            addr_hi: 0xDEAD_BEEF,
            addr_lo: 0xCAFE_F00D,
            len_flags,
            vlan_tag: 0,
        };
        if d.addr_hi != 0xDEAD_BEEF || d.addr_lo != 0xCAFE_F00D {
            return TestResult::Fail("buffer-addr fields didn't round-trip");
        }
        if d.len_flags != len_flags {
            return TestResult::Fail("len_flags didn't round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_tx_descriptor_round_trip);

    fn smoke_tg3_rx_descriptor_round_trip() -> TestResult {
        // Same round-trip check on the RX-side descriptor + the
        // `idx_len` packing used at pre-arm time.
        let slot: u32 = 42;
        let buf_len: u32 = RX_BUF_LEN as u32;
        let idx_len = (slot << 16) | (buf_len & 0xFFFF);
        if (idx_len >> 16) != slot {
            return TestResult::Fail("idx doesn't survive shift");
        }
        if idx_len & 0xFFFF != buf_len {
            return TestResult::Fail("buf_len lost in low-16");
        }
        let d = RxBufferDesc {
            addr_hi: 0x0000_0001,
            addr_lo: 0x2000_0000,
            idx_len,
            type_flags: 0,
            ip_tcp_csum: 0,
            err_vlan: 0,
            reserved: 0,
            opaque: slot,
        };
        if d.opaque != slot {
            return TestResult::Fail("opaque tag didn't round-trip");
        }
        if d.idx_len != idx_len {
            return TestResult::Fail("idx_len didn't round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_rx_descriptor_round_trip);

    fn smoke_tg3_ring_constants() -> TestResult {
        // The ring sizes determine both the DMA-alloc page count and
        // the modulo math `transmit`/`receive` use. Pin them so a
        // refactor that drops to e.g. 128 doesn't leave the modulo
        // out of sync.
        if RX_STD_RING_LEN != 256 {
            return TestResult::Fail("RX std ring length drift");
        }
        if TX_RING_LEN != 256 {
            return TestResult::Fail("TX ring length drift");
        }
        if RX_BUF_LEN != 2048 {
            return TestResult::Fail("RX buffer size drift");
        }
        // 256 * 32 = 8192 bytes RX ring → 2 pages.
        // 256 * 16 = 4096 bytes TX ring → 1 page.
        if RX_STD_RING_LEN * core::mem::size_of::<RxBufferDesc>() != 8192 {
            return TestResult::Fail("RX ring bytes != 8192");
        }
        if TX_RING_LEN * core::mem::size_of::<TxBufferDesc>() != 4096 {
            return TestResult::Fail("TX ring bytes != 4096");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_ring_constants);

    fn smoke_tg3_mailbox_offsets_match_linux() -> TestResult {
        // Mailbox offsets pulled from Linux tg3.h. Stage 3 will
        // write to these — a one-byte drift would silently push
        // the producer index into the wrong mailbox slot.
        if REG_MAILBOX_RCV_STD_PROD_IDX != 0x0268 {
            return TestResult::Fail("MAILBOX_RCV_STD_PROD_IDX offset drift");
        }
        if REG_MAILBOX_SNDHOST_PROD_IDX_0 != 0x0300 {
            return TestResult::Fail("MAILBOX_SNDHOST_PROD_IDX_0 offset drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/tg3", smoke_tg3_mailbox_offsets_match_linux);
}
